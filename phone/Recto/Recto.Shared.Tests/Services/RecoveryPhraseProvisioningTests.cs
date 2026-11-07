using System;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using Recto.Shared.Tests.Capability;
using Xunit;

namespace Recto.Shared.Tests.Services;

/// <summary>
/// The recovery phrase is created only by an act that asks for one: pairing a
/// service (Home.razor's pair-service flow) or a restore in Settings. A sign
/// path, an address shown on a card, or a revoke reads the phrase and, when the
/// read comes back empty, refuses by name - it never writes a new phrase in
/// place of one it could not read. The four signers share one phrase, so this
/// is checked across all of them.
/// </summary>
public class RecoveryPhraseProvisioningTests
{
    private static string PhoneRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "Recto.Shared", "Pages", "Home.razor")))
        {
            dir = dir.Parent;
        }
        Assert.NotNull(dir);
        return dir!.FullName;
    }

    [Theory]
    [InlineData("MauiEthSignService.cs", 4)]
    [InlineData("MauiBtcSignService.cs", 1)]
    [InlineData("MauiEd25519ChainSignService.cs", 1)]
    [InlineData("MauiTronSignService.cs", 1)]
    public void NoSignPath_CreatesARecoveryPhrase(string file, int signMethods)
    {
        var source = File.ReadAllText(Path.Combine(PhoneRoot(), "Recto", "Services", file));
        var names = Regex.Matches(source, @"public async Task<Result<[\w\[\]]+>> (Sign\w*Async)\(")
            .Select(m => m.Groups[1].Value).ToArray();
        Assert.Equal(signMethods, names.Length);
        foreach (var name in names)
        {
            var body = ProfileSigningInputTests.MethodBody(source, name);
            Assert.DoesNotContain("EnsureMnemonicAsync(", body);
            Assert.DoesNotContain("GenerateMnemonic(", body);
            Assert.DoesNotContain("SetAsync(", body);
        }
    }

    [Theory]
    [InlineData("PopulateEthAddressesAsync")]
    [InlineData("PopulateBtcAddressesAsync")]
    [InlineData("PopulateEdAddressesAsync")]
    [InlineData("PopulateTronAddressesAsync")]
    [InlineData("RevokeConsumerBindingAsync")]
    public void TheCardsAndTheRevoke_ReadThePhraseOnly(string method)
    {
        var body = ProfileSigningInputTests.MethodBody(ProfileSigningInputTests.HomePage(), method);
        Assert.DoesNotContain("EnsureMnemonicAsync(", body);
    }

    [Fact]
    public void PairingAService_IsTheOnePagePathThatCreatesAPhrase()
    {
        var page = ProfileSigningInputTests.HomePage();
        Assert.Equal(1, Regex.Matches(page, @"\.EnsureMnemonicAsync\(").Count);
    }
}
