using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Recto.Shared.Services;
using Xunit;

namespace Recto.Shared.Tests.Services;

/// <summary>
/// The pairing screen's two codes: six digits, and an owner reset's sixteen
/// characters. The reset code is read by the same rules as the bootloader
/// reads it, sent canonical, and never logged or stored.
/// </summary>
public class PairingCodeShapeTests
{
    private const string Canonical = "ABCDEFGHJKMNPQRS";

    // --- the shape ----------------------------------------------------------

    [Fact]
    public void SixDigits_IsAnOwnerCode_AndNotAResetCode()
    {
        Assert.True(PairingCodeShape.IsOwnerCode("314159"));
        Assert.False(PairingCodeShape.IsResetCode("314159"));
        Assert.Equal("314159", PairingCodeShape.Canonical("314159"));
        Assert.Equal("314159", PairingCodeShape.Display("314159"));
    }

    [Theory]
    [InlineData("ABCDEFGHJKMNPQRS")]
    [InlineData("ABCD-EFGH-JKMN-PQRS")]
    [InlineData("abcdefghjkmnpqrs")]
    [InlineData("abcd efgh jkmn pqrs")]
    [InlineData(" abcd-efgh - jkmn-pqrs ")]
    public void AResetCode_HoweverTyped_IsOneCanonicalString(string typed)
    {
        Assert.True(PairingCodeShape.IsResetCode(typed));
        Assert.False(PairingCodeShape.IsOwnerCode(typed));
        Assert.Equal(Canonical, PairingCodeShape.NormalizeResetCode(typed));
        Assert.Equal(Canonical, PairingCodeShape.Canonical(typed));
        Assert.Equal("ABCD-EFGH-JKMN-PQRS", PairingCodeShape.Display(typed));
    }

    [Fact]
    public void TheLettersThatLookLikeDigits_AreReadAsDigits()
    {
        Assert.Equal("1100123456789ABC", PairingCodeShape.NormalizeResetCode("ILO0-1234-5678-9abc"));
        Assert.Equal("1100123456789ABC", PairingCodeShape.NormalizeResetCode("ilo0123456789ABC"));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("ABCDEFGHJKMNPQR")]         // 15
    [InlineData("ABCDEFGHJKMNPQRST")]       // 17
    [InlineData("ABCDEFGHJKMNPQRU")]        // U is not in the alphabet
    [InlineData("ABCD_EFGH_JKMN_PQRS")]     // only dashes and spaces are forgiven
    [InlineData("ABCDEFGHJKMNPQRS\t")]
    [InlineData("ABCDEFGHJKMNPQRı")]   // a dotless i is not an I
    [InlineData("ABCDEFGHJKMNPQR٣")]   // a digit of another script
    public void AnythingElse_IsNotAResetCode(string? typed)
    {
        Assert.False(PairingCodeShape.IsResetCode(typed));
        Assert.Null(PairingCodeShape.NormalizeResetCode(typed));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("12345")]
    [InlineData("1234567")]
    [InlineData("12345A")]
    [InlineData(" 123456")]
    [InlineData("12-34-56")]
    [InlineData("１２３４５６")]   // six full-width digits
    [InlineData("12345٣")]
    public void AnOwnerCode_IsSixAsciiDigitsAndNothingElse(string? typed)
    {
        Assert.False(PairingCodeShape.IsOwnerCode(typed));
        Assert.Null(PairingCodeShape.Canonical(typed));
    }

    [Fact]
    public void TheAlphabet_IsCrockfords()
    {
        Assert.Equal(32, PairingCodeShape.ResetAlphabet.Length);
        Assert.Equal(32, PairingCodeShape.ResetAlphabet.Distinct().Count());
        Assert.DoesNotContain(PairingCodeShape.ResetAlphabet, c => "ILOU".Contains(c));
        Assert.Equal(19, PairingCodeShape.ResetCodeTypedMaxLength);
    }

    // --- which field is sent -------------------------------------------------

    [Fact]
    public void TheResetCode_WinsOverThePairingCode()
    {
        Assert.Equal(Canonical, PairingCodeShape.CodeToSend("314159", "abcd-efgh-jkmn-pqrs"));
        Assert.Equal(Canonical, PairingCodeShape.CodeToSend("", "abcd-efgh-jkmn-pqrs"));
    }

    [Fact]
    public void AnEmptyResetField_SendsTheSixDigits()
    {
        Assert.Equal("314159", PairingCodeShape.CodeToSend("314159", ""));
        Assert.Equal("314159", PairingCodeShape.CodeToSend("314159", "   "));
        Assert.Equal("314159", PairingCodeShape.CodeToSend("314159", null));
    }

    [Fact]
    public void AHalfTypedResetCode_SendsNothing_NotTheOtherField()
    {
        Assert.Null(PairingCodeShape.CodeToSend("314159", "ABCD-EFGH"));
        Assert.Null(PairingCodeShape.CodeToSend("31415", ""));
        Assert.Null(PairingCodeShape.CodeToSend(null, null));
    }

    // --- one vector file, read by the bootloader's tests too -------------------

    public static IEnumerable<object?[]> SharedVectors()
    {
        using var doc = JsonDocument.Parse(File.ReadAllText(Path.Combine(RepoRoot(), "tests", "reset_code_vectors.json")));
        foreach (var v in doc.RootElement.GetProperty("vectors").EnumerateArray())
        {
            yield return new object?[]
            {
                v.GetProperty("input").GetString(),
                v.GetProperty("form").GetString(),
                v.GetProperty("canonical").GetString(),
                v.GetProperty("display").GetString(),
            };
        }
    }

    [Theory]
    [MemberData(nameof(SharedVectors))]
    public void ThePhoneReadsACode_AsTheBootloaderDoes(string? input, string? form, string? canonical, string? display)
    {
        Assert.Equal(form == "long", PairingCodeShape.IsResetCode(input));
        Assert.Equal(form == "digits", PairingCodeShape.IsOwnerCode(input));
        Assert.Equal(canonical, PairingCodeShape.Canonical(input));
        if (display is not null) Assert.Equal(display, PairingCodeShape.Display(input!));
    }

    [Fact]
    public void TheVectorFile_NamesThePhonesAlphabet()
    {
        using var doc = JsonDocument.Parse(File.ReadAllText(Path.Combine(RepoRoot(), "tests", "reset_code_vectors.json")));
        Assert.Equal(PairingCodeShape.ResetAlphabet, doc.RootElement.GetProperty("alphabet").GetString());
        Assert.True(doc.RootElement.GetProperty("vectors").GetArrayLength() >= 20);
    }

    // --- the deep link ---------------------------------------------------------

    [Theory]
    [InlineData("ABCDEFGHJKMNPQRS")]
    [InlineData("ABCD-EFGH-JKMN-PQRS")]
    [InlineData("abcdefghjkmnpqrs")]
    public void ABootloaderLink_CarriesAResetCode_Canonical(string inLink)
    {
        var parsed = PairDeepLinkParser.TryParse(
            $"recto://pair?code={inLink}&bootloader=https%3A%2F%2Fbootloader.example.com&kind=bootloader");

        Assert.NotNull(parsed);
        Assert.Equal(PairDeepLinkKind.Bootloader, parsed!.Kind);
        Assert.Equal(Canonical, parsed.Code);
        Assert.Equal("https://bootloader.example.com", parsed.BootloaderUrl);
    }

    [Fact]
    public void ABootloaderLink_StillCarriesSixDigits()
    {
        var parsed = PairDeepLinkParser.TryParse(
            "recto://pair?code=314159&bootloader=https%3A%2F%2Fbootloader.example.com&kind=bootloader");
        Assert.Equal("314159", parsed!.Code);
    }

    [Theory]
    [InlineData("recto://pair?code=ABCDEFGHJKMNPQRS&kind=bootloader")]                                  // no bootloader
    [InlineData("recto://pair?code=ABCDEFGHJKMNPQR&bootloader=https%3A%2F%2Fb.example.com&kind=bootloader")]   // 15
    [InlineData("recto://pair?code=ABCDEFGHJKMNPQRST&bootloader=https%3A%2F%2Fb.example.com&kind=bootloader")] // 17
    [InlineData("recto://pair?code=ABCDEFGHJKMNPQRU&bootloader=https%3A%2F%2Fb.example.com&kind=bootloader")]  // a U
    [InlineData("recto://pair?code=1234567&bootloader=https%3A%2F%2Fb.example.com&kind=bootloader")]           // 7 digits
    [InlineData("recto://pair?code=ABCDEFGHJKMNPQRS&bootloader=https%3A%2F%2Fb.example.com")]                  // a service link
    public void AnyOtherShape_IsRefused(string url)
    {
        Assert.Null(PairDeepLinkParser.TryParse(url));
    }

    [Fact]
    public void AServiceLinksBootstrapCode_StaysSixDigits()
    {
        // A consumer's link never carries an owner reset: the long shape is dropped there, as any other was.
        var parsed = PairDeepLinkParser.TryParse(
            "recto://pair?code=ABCD1234&bootstrap_bootloader=https%3A%2F%2Fb.example.com&bootstrap_pair_code=ABCDEFGHJKMNPQRS");
        Assert.NotNull(parsed);
        Assert.Null(parsed!.BootstrapPairCode);

        var six = PairDeepLinkParser.TryParse(
            "recto://pair?code=ABCD1234&bootstrap_bootloader=https%3A%2F%2Fb.example.com&bootstrap_pair_code=314159");
        Assert.Equal("314159", six!.BootstrapPairCode);
    }

    [Fact]
    public void TheEmitter_RoundTripsAResetCode_WithTheBytesTheHostEmits()
    {
        var url = PairDeepLinkEmitter.BuildBootloaderPairUrl(Canonical, "https://bootloader.example.com");

        // Byte for byte what recto/qr/pair.py builds (tests/test_owner_reset_code.py pins the same string).
        Assert.Equal(
            "recto://pair?code=ABCDEFGHJKMNPQRS&bootloader=https%3A%2F%2Fbootloader.example.com&kind=bootloader", url);
        var parsed = PairDeepLinkParser.TryParse(url);
        Assert.Equal(Canonical, parsed!.Code);
    }

    [Theory]
    [InlineData("ABCD-EFGH-JKMN-PQRS")]    // the link carries the canonical form only
    [InlineData("abcdefghjkmnpqrs")]
    [InlineData("ABCDEFGHJKMNPQRU")]
    [InlineData("ABCDEFGHJKMNPQR")]
    [InlineData("1234567")]
    public void TheEmitter_RefusesAnyOtherShape_WithoutRepeatingIt(string code)
    {
        var ex = Assert.Throws<ArgumentException>(
            () => PairDeepLinkEmitter.BuildBootloaderPairUrl(code, "https://bootloader.example.com"));
        Assert.DoesNotContain(code, ex.Message);
    }

    // --- the wire, and what is never kept ---------------------------------------

    private sealed class Capture : HttpMessageHandler
    {
        public List<Uri> Uris { get; } = new();

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            Uris.Add(request.RequestUri!);
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.Forbidden)
            {
                Content = new StringContent(
                    "{\"error\":\"registration_expired\",\"detail\":\"pairing code expired or invalid\"}",
                    System.Text.Encoding.UTF8, "application/json"),
            });
        }
    }

    private sealed class Lines : ILogger<BootloaderClient>
    {
        public List<string> Written { get; } = new();
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            Written.Add(formatter(state, exception));
            if (state is IEnumerable<KeyValuePair<string, object?>> pairs)
            {
                foreach (var pair in pairs) Written.Add($"{pair.Key}={pair.Value}");
            }
            if (exception is not null) Written.Add(exception.ToString());
        }
    }

    [Fact]
    public async Task TheCanonicalCode_IsSentInTheCodeParameter_AndNeverLoggedOrReturned()
    {
        var handler = new Capture();
        var log = new Lines();
        var sut = new BootloaderClient(new HttpClient(handler), log);

        var sent = PairingCodeShape.CodeToSend("", "abcd-efgh-jkmn-pqrs")!;
        var result = await sut.GetRegistrationChallengeAsync("https://bootloader.example.com", sent, CancellationToken.None);

        Assert.Equal(
            "https://bootloader.example.com/v0.4/registration_challenge?code=ABCDEFGHJKMNPQRS",
            Assert.Single(handler.Uris).AbsoluteUri);
        // A refusal: the log has its lines, and neither they nor the error shown to the person hold the code.
        Assert.True(result.IsFailure);
        Assert.NotEmpty(log.Written);
        foreach (var line in log.Written.Append(result.Error.Message))
        {
            Assert.DoesNotContain(Canonical, line, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("ABCD-EFGH", line, StringComparison.OrdinalIgnoreCase);
        }
    }

    [Fact]
    public void ThePairingScreen_NeverStoresOrLogsTheResetCode()
    {
        var home = File.ReadAllText(Path.Combine(PhoneRoot(), "Recto.Shared", "Pages", "Home.razor"));

        // Every line of the page that names the field, but for the ones that only read its shape or clear it.
        var uses = home.Split('\n').Select(l => l.Trim()).Where(l => l.Contains("_resetCode")).ToList();
        Assert.True(uses.Count >= 8, "the field is declared, bound, read for its shape, sent and cleared");
        var forbidden = new Regex(
            @"SecureStorage|Preferences|RecentErrors|Debug\.|Console\.|_log\b|Log(Information|Warning|Error|Debug)|"
            + @"_errorMessage\s*=.*_resetCode|localStorage|sessionStorage|Pairing\.Save|File\.");
        foreach (var line in uses)
        {
            Assert.False(forbidden.IsMatch(line), $"the reset code reaches something that keeps it: {line}");
        }

        // It is cleared when a pairing completes and wherever the pairing code is.
        Assert.True(Regex.Matches(home, @"_resetCode = string\.Empty;").Count >= 4);
        // It is sent only through the one shape function, in its canonical form.
        Assert.Contains("PairingCodeShape.CodeToSend(_pairingCode, _resetCode)", home);
        Assert.Contains("_bootloaderUrl, codeToSend, CancellationToken.None", home);
        Assert.DoesNotContain("codeToSend}", home);     // never interpolated into a message
    }

    [Fact]
    public void ThePairingScreen_KeepsTheNumericKeypad_AndHasASeparateResetField()
    {
        var home = File.ReadAllText(Path.Combine(PhoneRoot(), "Recto.Shared", "Pages", "Home.razor"));
        var pairing = Regex.Match(home, "<input id=\"pairing-code\"[^>]*>").Value;
        Assert.Contains("inputmode=\"numeric\"", pairing);
        Assert.Contains("maxlength=\"6\"", pairing);

        var reset = Regex.Match(home, "<input id=\"owner-reset-code\"[^>]*>").Value;
        Assert.Contains("type=\"text\"", reset);
        Assert.Contains("autocomplete=\"off\"", reset);
        Assert.Contains("autocapitalize=\"characters\"", reset);
        Assert.Contains("@bind=\"_resetCode\"", reset);
        Assert.DoesNotContain("inputmode=\"numeric\"", reset);
        Assert.Contains("<summary class=\"small text-muted\">Owner reset</summary>", home);
    }

    private static string PhoneRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "Recto", "MauiProgram.cs"))) dir = dir.Parent;
        Assert.NotNull(dir);
        return dir!.FullName;
    }

    private static string RepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "tests", "reset_code_vectors.json"))) dir = dir.Parent;
        Assert.NotNull(dir);
        return dir!.FullName;
    }
}
