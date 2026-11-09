using System;
using System.IO;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Recto.Shared.Protocol.V04;
using Recto.Shared.Services;
using Xunit;

namespace Recto.Shared.Tests.Services;

/// <summary>
/// The software key service exists only in DEBUG builds of the desktop targets
/// (Windows, Mac Catalyst). A release build of those targets registers
/// <see cref="NoHardwareKeyService"/>, which refuses every key act by name, so it
/// cannot pair as an authority device.
/// </summary>
public class DesktopReleaseKeyServiceTests
{
    [Fact]
    public async Task NoHardwareKeyService_RefusesEveryKeyActByName()
    {
        var keys = new NoHardwareKeyService();
        var ct = CancellationToken.None;

        var gen = await keys.GenerateAsync("recto.phone.identity", ct);
        var device = await keys.GenerateDeviceKeyAsync("recto.phone.poll", ct);
        var pub = await keys.GetPublicKeyAsync("recto.phone.identity", ct);
        var sig = await keys.SignAsync("recto.phone.identity", new byte[] { 1, 2, 3 }, ct);

        foreach (var error in new[] { gen.Error, device.Error, pub.Error, sig.Error })
        {
            Assert.Equal(NoHardwareKeyService.RefusalCode, error.Method);
            Assert.Contains("no hardware key store", error.Message);
        }
        Assert.True(gen.IsFailure && device.IsFailure && pub.IsFailure && sig.IsFailure);
        var exists = await keys.KeyExistsAsync("recto.phone.identity", ct);
        Assert.True(exists.IsSuccess);
        Assert.False(exists.Value);
    }

    [Fact]
    public void NoHardwareKeyService_NamesNoAlgorithmTheBootloaderEnrolls()
    {
        var keys = new NoHardwareKeyService();
        Assert.NotEqual(V04Protocol.AlgorithmEd25519, keys.Algorithm);
        Assert.NotEqual(V04Protocol.AlgorithmEcdsaP256, keys.Algorithm);
    }

    private static string PhoneFile(params string[] parts)
    {
        var dir = new DirectoryInfo(System.AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "Recto", "MauiProgram.cs")))
        {
            dir = dir.Parent;
        }
        Assert.NotNull(dir);
        return File.ReadAllText(Path.Combine(dir!.FullName, Path.Combine(parts)));
    }

    [Fact]
    public void TheSoftwareKeyService_CompilesForDebugDesktopBuildsOnly()
    {
        var source = PhoneFile("Recto", "Services", "SoftwareEnclaveKeyService.cs");
        var firstIf = Regex.Match(source, @"^#if .*$", RegexOptions.Multiline);
        Assert.True(firstIf.Success);
        Assert.Equal("#if DEBUG && !IOS && !ANDROID", firstIf.Value.TrimEnd('\r'));
        // The guard opens before the class and closes after it.
        Assert.True(firstIf.Index < source.IndexOf("class SoftwareEnclaveKeyService", StringComparison.Ordinal));
        Assert.EndsWith("#endif", source.TrimEnd());
    }

    [Fact]
    public void ThePairFlow_RefusesBeforeItContactsTheBootloader()
    {
        var page = Recto.Shared.Tests.Capability.ProfileSigningInputTests.HomePage();
        var pair = Recto.Shared.Tests.Capability.ProfileSigningInputTests.MethodBody(page, "HandlePairClick");

        var refusal = pair.IndexOf("if (EnclaveKeys is NoHardwareKeyService)", StringComparison.Ordinal);
        Assert.True(refusal >= 0);
        Assert.Contains("_errorMessage = NoHardwareKeyService.Refusal.Message;", pair);
        foreach (var later in new[] { "IsDemoPairAttempt", "GetOrCreatePhoneIdAsync(", "GetRegistrationChallengeAsync(", "EnclaveKeys.GenerateAsync(" })
        {
            var at = pair.IndexOf(later, StringComparison.Ordinal);
            Assert.True(at > refusal, $"{later} runs before the no-hardware refusal");
        }
    }

    [Fact]
    public void AReleaseDesktopBuild_RegistersTheRefusingKeyService()
    {
        var program = PhoneFile("Recto", "MauiProgram.cs");

        // The software key service is registered once, in the DEBUG branch.
        Assert.Single(Regex.Matches(program, @"SoftwareEnclaveKeyService>"));
        Assert.Matches(
            @"#elif DEBUG\r?\n(?:[ \t]*//[^\n]*\n)*[ \t]*builder\.Services\.AddSingleton<IEnclaveKeyService, SoftwareEnclaveKeyService>\(\);",
            program);
        // The release branch registers the refusing service.
        Assert.Matches(
            @"#else\r?\n(?:[ \t]*//[^\n]*\n)*[ \t]*builder\.Services\.AddSingleton<IEnclaveKeyService, NoHardwareKeyService>\(\);",
            program);
    }
}
