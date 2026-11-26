using System.Text.RegularExpressions;
using Recto.Shared.Tests.Capability;
using Xunit;

namespace Recto.Shared.Tests.Services;

/// <summary>
/// The recovery phrase's key signs only after the identity key has (hard rule 14.9): its biometric comes first, once, in
/// every act of the pages that signs with the phrase or shows it. The phrase's own store asks for no biometric.
/// </summary>
public sealed class PhraseGateTests
{
    private static readonly Regex PhraseAct = new(
        @"\b(?:Eth|Btc|Ed|Tron)Signer\s*\.\s*(?:Sign\w*|Export\w*)\(", RegexOptions.CultureInvariant);

    private static readonly Regex Biometric = new(
        @"EnclaveKeys\s*\.\s*SignAsync\(", RegexOptions.CultureInvariant);

    private static readonly string[] Acts =
    [
        "ApproveBtcSignAsync", "ApproveEdSignAsync", "ApproveEthSignAsync", "ApproveTronSignAsync",
        "ApproveCapabilityRequestAsync", "ApproveProfileCreateAsync", "ApproveProfileAddDeviceAsync",
        "ApproveProfileRevokeDeviceAsync", "HandlePairServiceClick", "RevokeConsumerBindingAsync",
    ];

    public static TheoryData<string> ActNames() => [.. Acts];

    [Theory]
    [MemberData(nameof(ActNames))]
    public void ThePhraseSignsOnlyAfterTheBiometric(string method)
    {
        var body = ProfileSigningInputTests.MethodBody(ProfileSigningInputTests.HomePage(), method);
        var gates = Biometric.Matches(body);
        Assert.Single(gates);
        var phrase = PhraseAct.Matches(body);
        Assert.NotEmpty(phrase);
        Assert.All(phrase, call => Assert.True(gates[0].Index < call.Index, $"{method}: {call.Value} comes before the biometric"));
        // A declined prompt ends the act: what is between the two returns on it.
        var between = body[gates[0].Index..phrase[0].Index];
        Assert.Matches(@"(?s)(?:\.IsFailure\)).{0,160}?return", between);
    }

    [Fact]
    public void NoOtherPageActSignsWithThePhrase()
    {
        var page = ProfileSigningInputTests.HomePage();
        var listed = Acts.Sum(m => PhraseAct.Matches(ProfileSigningInputTests.MethodBody(page, m)).Count);
        var dir = Path.GetDirectoryName(HomePath())!;
        var all = Directory.EnumerateFiles(Path.GetDirectoryName(dir)!, "*.*", SearchOption.AllDirectories)
            .Where(f => (f.EndsWith(".razor", StringComparison.Ordinal) || f.EndsWith(".cs", StringComparison.Ordinal))
                && !f.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}")
                && !f.Contains($"{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}"))
            .ToDictionary(f => f, f => PhraseAct.Matches(File.ReadAllText(f)).Count);
        Assert.Equal(listed, all[HomePath()]);
        var others = all.Where(f => f.Value > 0 && f.Key != HomePath()).Select(f => Path.GetFileName(f.Key));
        Assert.Equal(["Settings.razor"], others);
    }

    [Fact]
    public void ThePhraseIsShownOnlyAfterTheBiometric()
    {
        var settings = File.ReadAllText(Path.Combine(Path.GetDirectoryName(HomePath())!, "Settings.razor"));
        var phrase = Assert.Single(PhraseAct.Matches(settings));
        var body = ProfileSigningInputTests.MethodBody(settings, "BeginBackupAsync");
        var gate = Assert.Single(Biometric.Matches(body));
        Assert.Equal("EthSigner.ExportMnemonicAsync(", phrase.Value);
        Assert.Matches(@"(?s)gate\.IsFailure\).*?return;.*?ExportMnemonicAsync\(", body[gate.Index..]);
    }

    [Fact]
    public void APairingSendsWhatTheIdentityKeySigned()
    {
        Assert.Equal("recto-pair-v1|rb1|pk_1|abc",
            System.Text.Encoding.ASCII.GetString(Recto.Shared.Protocol.V04.DevicesPairRequest.IdentityPayload("rb1", "pk_1", "abc")));
        var body = ProfileSigningInputTests.MethodBody(ProfileSigningInputTests.HomePage(), "HandlePairServiceClick");
        Assert.Contains("DevicesPairRequest.IdentityPayload(_paired!.BootloaderId, _paired!.PhoneId, Base64UrlEncode(digest))", body);
        Assert.Contains("IdentitySignatureB64u: Base64UrlEncode(identity.Value)", body);
        Assert.Contains("PhoneId: _paired!.PhoneId", body);
        var record = new Recto.Shared.Protocol.V04.DevicesPairRecord("b", "s", "p", "c", 1);
        var json = System.Text.Json.JsonSerializer.Serialize(new Recto.Shared.Protocol.V04.DevicesPairRequest("c", record, "j", PhoneId: "p1", IdentitySignatureB64u: "s1"));
        Assert.Contains("\"phone_id\":\"p1\"", json);
        Assert.Contains("\"identity_signature_b64u\":\"s1\"", json);
        Assert.DoesNotContain("phone_id", System.Text.Json.JsonSerializer.Serialize(new Recto.Shared.Protocol.V04.DevicesPairRequest("c", record, "j")));
    }

    [Fact]
    public void AnUnpairingSendsWhatTheIdentityKeySigned()
    {
        Assert.Equal("recto-unpair-v1|rb1|pk_1|abc",
            System.Text.Encoding.ASCII.GetString(Recto.Shared.Protocol.V04.DevicesUnpairRequest.IdentityPayload("rb1", "pk_1", "abc")));
        var body = ProfileSigningInputTests.MethodBody(ProfileSigningInputTests.HomePage(), "RevokeConsumerBindingAsync");
        Assert.Contains("DevicesUnpairRequest.IdentityPayload(_paired!.BootloaderId, _paired!.PhoneId, Base64UrlEncode(digest))", body);
        Assert.Contains("IdentitySignatureB64u: Base64UrlEncode(identity.Value)", body);
        Assert.Contains("PhoneId: _paired!.PhoneId", body);
        var json = System.Text.Json.JsonSerializer.Serialize(new Recto.Shared.Protocol.V04.DevicesUnpairRequest("c", "k", "j", "p", "s"));
        Assert.Contains("\"phone_id\":\"p\"", json);
        Assert.Contains("\"identity_signature_b64u\":\"s\"", json);
        Assert.DoesNotContain("phone_id", System.Text.Json.JsonSerializer.Serialize(new Recto.Shared.Protocol.V04.DevicesUnpairRequest("c", "k", "j")));
    }

    private static string HomePath()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "Recto.Shared", "Pages", "Home.razor"))) dir = dir.Parent;
        Assert.NotNull(dir);
        return Path.Combine(dir!.FullName, "Recto.Shared", "Pages", "Home.razor");
    }
}
