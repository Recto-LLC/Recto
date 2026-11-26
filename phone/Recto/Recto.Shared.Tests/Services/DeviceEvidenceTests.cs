using System;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging.Abstractions;
using Recto.Shared.Capability;
using Recto.Shared.Common;
using Recto.Shared.Protocol.V04;
using Recto.Shared.Services;
using Recto.Shared.Tests.Capability;
using Xunit;

namespace Recto.Shared.Tests.Services;

/// <summary>Hard rule 14.8, the phone's half: what a registration shows, and when an identity key may be made again.</summary>
public class DeviceEvidenceTests
{
    // Pinned against recto.bootloader.device_evidence, which computes both the same way.
    [Fact]
    public void TheTwoBindings_AreTheBootloadersOwn()
    {
        Assert.Equal("684bce7e8a4c74fe98cdce3bc057b8aa7f44bbcbbce892f9166aa25f6012b8c1",
            Convert.ToHexStringLower(DeviceEvidence.AndroidChallenge("abc")));
        Assert.Equal("8e5afd22aed664b9dc387cecc610e3fa7873db0ca177f1c0f8190c0d444f7387",
            Convert.ToHexStringLower(DeviceEvidence.IosClientDataHash("abc", "id", "poll")));
    }

    private static RegistrationRequest Request(DeviceEvidence? evidence = null, string? code = null) => new(
        "phone", "label", "pub", new[] { "ecdsa-p256" }, 1, new RegistrationProof("c", "s"),
        DeviceEvidence: evidence, TestDeviceCode: code);

    [Fact]
    public void ARegistrationWithNothingToShow_IsTheOneOlderBootloadersRead()
    {
        var json = JsonSerializer.Serialize(Request());
        Assert.DoesNotContain("device_evidence", json);
        Assert.DoesNotContain("test_device_code", json);
    }

    [Fact]
    public void TheWireShape_IsWhatTheBootloaderReads()
    {
        var android = JsonSerializer.Serialize(Request(DeviceEvidence.Android(new[] { "leaf", "root" }), "ABCDE-FGH10"));
        Assert.Contains("\"device_evidence\":{\"platform\":\"android\",\"chain\":[\"leaf\",\"root\"]}", android);
        Assert.Contains("\"test_device_code\":\"ABCDE-FGH10\"", android);
        var ios = JsonSerializer.Serialize(Request(DeviceEvidence.Ios("k", "o")));
        Assert.Contains("\"device_evidence\":{\"platform\":\"ios\",\"key_id\":\"k\",\"attestation\":\"o\"}", ios);
    }

    private sealed class Handler(Func<HttpResponseMessage> answer) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage r, CancellationToken ct)
            => Task.FromResult(answer());
    }

    private static async Task<Error> Answer(Func<HttpResponseMessage> answer)
    {
        var client = new BootloaderClient(new HttpClient(new Handler(answer)), NullLogger<BootloaderClient>.Instance);
        return (await client.RegisterAsync("https://b.example", Request(), CancellationToken.None)).Error;
    }

    private static Func<HttpResponseMessage> Says(HttpStatusCode status, string body) => () => new HttpResponseMessage(status)
    {
        Content = new StringContent(body, Encoding.UTF8, "application/json"),
    };

    [Theory]
    [InlineData("device_evidence_required", true)]
    [InlineData("device_evidence_invalid", true)]
    [InlineData("test_device_code_invalid", true)]
    [InlineData("owner_approval_required", false)]
    [InlineData("member_phone_bound_elsewhere", false)]
    public async Task ARefusalOfWhatThePhoneShowed_IsReadFromTheBootloadersName(string code, bool refusal)
    {
        var error = await Answer(Says(HttpStatusCode.Forbidden, $"{{\"error\":\"{code}\",\"detail\":\"device_evidence_invalid\"}}"));
        Assert.Equal(refusal, DeviceEvidence.IsRefusal(error));
        Assert.True(DeviceEvidence.WasAnswered(error));
    }

    [Fact]
    public async Task AnAnswerIsAnAnswer_AndSilenceIsNot()
    {
        Assert.True(DeviceEvidence.WasAnswered(await Answer(Says(HttpStatusCode.NotFound, "{\"error\":\"x\"}"))));
        Assert.True(DeviceEvidence.WasAnswered(await Answer(Says(HttpStatusCode.BadGateway, "<html>"))));
        var silent = await Answer(() => throw new HttpRequestException("device_evidence_invalid"));
        Assert.False(DeviceEvidence.WasAnswered(silent));
        Assert.False(DeviceEvidence.IsRefusal(silent));
    }

    private static readonly Error Refused = Error.Failure("HTTP 403: device_evidence_invalid: x");
    private static readonly Error Waiting = Error.Failure("HTTP 403: owner_approval_required: x");
    private static readonly Error Silent = Error.Failure("The bootloader did not answer in time.");

    [Fact]
    public void AKeyNoBootloaderWasSent_MayBeMadeAgain_AndNoOther()
    {
        Assert.True(IdentityKeyJournal.MayReplace(IdentityKeyJournal.New));
        Assert.False(IdentityKeyJournal.MayReplace(null));
        Assert.False(IdentityKeyJournal.MayReplace(IdentityKeyJournal.Sent("b.example")));
    }

    [Fact]
    public void TheJournal_LetsGoOfAKeyOnlyWhenTheSameBootloaderSaysItDoesNotHoldIt()
    {
        var sent = IdentityKeyJournal.Sent("b.example");
        Assert.Equal(IdentityKeyJournal.New, IdentityKeyJournal.After(sent, "b.example", Refused));
        Assert.Null(IdentityKeyJournal.After(sent, "b.example", null));
        Assert.Null(IdentityKeyJournal.After(sent, "b.example", Waiting));
        Assert.Equal(sent, IdentityKeyJournal.After(sent, "b.example", Silent));
        // Another bootloader's refusal says nothing about the one whose answer never came.
        Assert.Null(IdentityKeyJournal.After(sent, "other.example", Refused));
        // A key some bootloader may hold stays, whatever any bootloader answers.
        Assert.Null(IdentityKeyJournal.After(null, "b.example", Refused));
    }

    // --- nothing of it is kept ----------------------------------------------

    private static string PhoneRoot()
    {
        var dir = new System.IO.DirectoryInfo(System.AppContext.BaseDirectory);
        while (dir is not null && !System.IO.File.Exists(System.IO.Path.Combine(dir.FullName, "Recto", "MauiProgram.cs"))) dir = dir.Parent;
        Assert.NotNull(dir);
        return dir!.FullName;
    }

    private static System.Collections.Generic.IEnumerable<(string Name, string Text)> PhoneSource()
    {
        var root = PhoneRoot();
        foreach (var project in new[] { "Recto", "Recto.Shared" })
        {
            foreach (var file in System.IO.Directory.EnumerateFiles(System.IO.Path.Combine(root, project), "*", System.IO.SearchOption.AllDirectories))
            {
                var parts = file.Split(System.IO.Path.DirectorySeparatorChar);
                if (Array.IndexOf(parts, "bin") >= 0 || Array.IndexOf(parts, "obj") >= 0) continue;
                if (file.EndsWith(".cs", StringComparison.Ordinal) || file.EndsWith(".razor", StringComparison.Ordinal))
                    yield return (file, System.IO.File.ReadAllText(file));
            }
        }
    }

    [Fact]
    public void ThePhone_NeverAsksForADeviceIdentifier()
    {
        var forbidden = new System.Text.RegularExpressions.Regex(
            @"DevicePropertiesAttestation|DeviceIdAttestation|AttestationIds|AttestDeviceIds|AttestationId(Serial|Imei|Meid)"
            + @"|UniqueIdIncluded|GenerateAttestationKeyPair|EnrollmentSpecificId"
            + @"|Build\.(Serial|GetSerial)|GetSerial\(|GetImei|GetMeid|\.DeviceId\b|Secure\.AndroidId|IdentifierForVendor|AdvertisingIdentifier",
            System.Text.RegularExpressions.RegexOptions.IgnoreCase);
        var read = 0;
        foreach (var (name, text) in PhoneSource())
        {
            read++;
            Assert.False(forbidden.IsMatch(text), $"{name}: {forbidden.Match(text).Value}");
        }
        Assert.True(read > 50);
    }

    [Fact]
    public void TheProof_IsReadInThreePlaces_AndReachesOnlyTheRequest()
    {
        // The two platform services that read it, the interface, the type, the request, the pair flow - and the sender
        // of assertions, which knows the type's one code for a key that is gone.
        var readers = new System.Collections.Generic.SortedSet<string>(StringComparer.Ordinal);
        foreach (var (name, text) in PhoneSource())
        {
            if (System.Text.RegularExpressions.Regex.IsMatch(text, @"DeviceEvidence|GetCertificateChain|DCAppAttest"))
                readers.Add(System.IO.Path.GetFileName(name));
        }
        Assert.Equal(new[]
        {
            "ActAsserter.cs", "AndroidStrongBoxKeyService.cs", "DeviceEvidence.cs", "Home.razor", "IEnclaveKeyService.cs",
            "IosSecureEnclaveKeyService.cs", "RegistrationRequest.cs",
        }, readers);

        // In the page the proof is a local of the pair flow: awaited once, into the request.
        var page = ProfileSigningInputTests.HomePage();
        Assert.Equal(2, System.Text.RegularExpressions.Regex.Matches(page, @"\bevidenceTask\b").Count);
        Assert.Contains("DeviceEvidence: await evidenceTask,", page);
        var read = Method("DeviceEvidenceAsync");
        Assert.Contains("return evidence.IsSuccess ? evidence.Value : null;", read);
        foreach (var sink in new[] { "_errorMessage", "Log", "Debug.", "Console.", "Storage", "Preferences" }) Assert.DoesNotContain(sink, read);
    }

    [Fact]
    public void AProofThatIsPrinted_PrintsItsPlatform()
    {
        var chain = DeviceEvidence.Android(new[] { "CANARYcertificate" });
        Assert.Equal("DeviceEvidence(android)", chain.ToString());
        Assert.DoesNotContain("CANARY", Request(chain).ToString());
        var ios = DeviceEvidence.Ios("CANARYkeyid", "CANARYobject");
        Assert.DoesNotContain("CANARY", $"{ios} {Request(ios)}");
    }

    [Fact]
    public async Task AProofThatIsSent_IsInNoLogLine_AndInNoErrorTheAppShows()
    {
        var log = new Lines();
        var sent = string.Empty;
        foreach (var answer in new Func<HttpResponseMessage>[]
                 {
                     Says(HttpStatusCode.Forbidden, "{\"error\":\"device_evidence_invalid\",\"detail\":\"x\"}"),
                     Says(HttpStatusCode.OK, "not json"),
                     Says(HttpStatusCode.BadGateway, "<html>"),
                     () => throw new HttpRequestException("gone"),
                     () => throw new InvalidOperationException("gone"),
                 })
        {
            var client = new BootloaderClient(new HttpClient(new Handler(answer)), log);
            var result = await client.RegisterAsync("https://b.example",
                Request(DeviceEvidence.Android(new[] { "CANARYcertificate" }), "ABCDE-FGH10"), CancellationToken.None);
            sent += result.IsFailure ? result.Error.ToString() : string.Empty;
        }
        Assert.NotEmpty(log.Text.ToString());
        Assert.DoesNotContain("CANARY", log.Text + sent);
        Assert.DoesNotContain("FGH10", log.Text + sent);
    }

    private sealed class Lines : Microsoft.Extensions.Logging.ILogger<BootloaderClient>
    {
        public readonly StringBuilder Text = new();
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(Microsoft.Extensions.Logging.LogLevel level) => true;
        public void Log<TState>(Microsoft.Extensions.Logging.LogLevel level, Microsoft.Extensions.Logging.EventId id, TState state,
            Exception? exception, Func<TState, Exception?, string> formatter)
            => Text.AppendLine(formatter(state, exception)).AppendLine(exception?.ToString());
    }

    // --- the pair flow ------------------------------------------------------

    private static string Method(string name)
        => ProfileSigningInputTests.MethodBody(ProfileSigningInputTests.HomePage(), name).Replace("\r\n", "\n");

    [Fact]
    public void ThePairFlow_RemakesOnlyAKeyTheJournalReleases()
    {
        var pair = Method("HandlePairClick");
        Assert.Contains("var remake = EnclaveKeys.AttestsAtCreation\n                && IdentityKeyJournal.MayReplace(", pair);
        Assert.Contains("if (existsResult.IsSuccess && existsResult.Value && !remake)", pair);
        Assert.DoesNotContain("EnclaveKeys.DeleteAsync", pair);
        Assert.Contains("DeviceEvidence.AndroidChallenge(challenge.ChallengeB64u)", pair);
        // Every registration goes through the one sender that keeps the journal.
        Assert.DoesNotContain("BootloaderClient.RegisterAsync", pair);
        var page = ProfileSigningInputTests.HomePage();
        Assert.True(page.IndexOf("IdentityKeyJournal.Sent(host)", StringComparison.Ordinal)
            < page.IndexOf("BootloaderClient.RegisterAsync", StringComparison.Ordinal));
        Assert.Equal(page.IndexOf("BootloaderClient.RegisterAsync", StringComparison.Ordinal),
            page.LastIndexOf("BootloaderClient.RegisterAsync", StringComparison.Ordinal));
    }

    [Fact]
    public void TheOldKey_IsRemovedOnlyOnASecondTap_AndThroughTheGuard()
    {
        var click = Method("HandleNewIdentityKeyClick");
        var confirm = click.IndexOf("if (!_confirmNewIdentityKey)", StringComparison.Ordinal);
        Assert.True(confirm >= 0 && confirm < click.IndexOf("Unpair.RemoveIdentityKeyAsync(", StringComparison.Ordinal));
        Assert.Contains("_offerNewIdentityKey = _confirmNewIdentityKey = false;", Method("HandlePairClick"));
    }

    // --- the approval card's validity line ----------------------------------

    [Fact]
    public void TheValidityLine_CountsWhileTheCardIsOpen()
    {
        var now = DateTimeOffset.FromUnixTimeSeconds(1_715_000_020);
        Assert.Equal(("20s ago", "40s left"), CapabilityAuditView.ValidityAt(1_715_000_000, 1_715_000_060, now));
        Assert.Equal(("21s ago", "39s left"), CapabilityAuditView.ValidityAt(1_715_000_000, 1_715_000_060, now.AddSeconds(1)));
        Assert.Equal("expired", CapabilityAuditView.ValidityAt(1_715_000_000, 1_715_000_060, now.AddSeconds(40)).TimeLeft);

        var page = ProfileSigningInputTests.HomePage();
        Assert.Contains("<CardValidity Iat=\"capDecoded.Iat\" Exp=\"capDecoded.Exp\" />", page);
        Assert.DoesNotContain("@capDecoded.TimeLeft", page);
    }

    [Fact]
    public async Task TheValidityLine_DrawsItselfAgainEachSecond_AndStopsWithItsCard()
    {
        using var line = new Probe();
        line.Start();
        for (var i = 0; i < 50 && line.Drawn < 2; i++) await Task.Delay(100);
        Assert.True(line.Drawn >= 2);
        line.Dispose();
        await Task.Delay(200);
        var stopped = line.Drawn;
        await Task.Delay(1500);
        Assert.Equal(stopped, line.Drawn);
    }

    private sealed class Probe : Recto.Shared.Pages.CardValidity
    {
        public int Drawn;
        public void Start() => OnInitialized();
        protected override void OnTick() => Interlocked.Increment(ref Drawn);
    }
}
