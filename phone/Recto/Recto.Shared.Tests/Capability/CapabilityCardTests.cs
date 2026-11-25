using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Recto.Shared.Capability;
using Recto.Shared.Protocol.V04;
using Xunit;

namespace Recto.Shared.Tests.Capability;

/// <summary>
/// A capability card shows everything it signs (hard rule 15.x): the whole
/// purpose before Approve is offered, every signed term, every hidden
/// character written out, and no Approve at all for a card that cannot be
/// shown whole or whose payload changed under its id.
/// </summary>
public class CapabilityCardTests
{
    private static readonly DateTimeOffset Now = DateTimeOffset.FromUnixTimeSeconds(1_715_000_020);

    // Printed by recto.capability.jwt.build_signing_input over a claims set
    // that carries every field the Python types sign.
    private const string GoldenHeader = "eyJhbGciOiJFUzI1NksiLCJ0eXAiOiJKV1QifQ";
    private const string GoldenPayload =
        "eyJhdWQiOlsiY29uc3VtZXItYXBwIl0sImNhcCI6eyJhbGxvd19hY3Rpb25zIjpbImE6b25lIl0sImRlbnlfYWN0aW9ucyI6WyJhOnR3byJd"
        + "LCJncm91cHMiOlsiZzpvbmUiXSwibGltaXRzIjp7InBlcl9kYXkiOnsiYTpvbmUiOjl9LCJwZXJfaG91ciI6eyJhOm9uZSI6M30sInBlcl9z"
        + "ZXNzaW9uIjp7ImE6b25lIjoyfX0sInJlZ2lzdHJ5X3ZlcnNpb24iOiJ2MSIsInNjb3BlIjp7ImNoYXRfcm9vbV9pZCI6InJvb20tMSIsImNy"
        + "ZWF0ZV9mb3Jfb3duZXIiOiJvd25lci0xIiwiZW52IjpbInN0YWdpbmciXSwicGFpcmluZ19jb2RlIjoiQUIxMkNEMzQiLCJwYXlsb2FkX3No"
        + "YTI1NiI6ImFiIiwicmVwb3MiOlsiciJdLCJzZXJ2aWNlcyI6WyJ3ZWIiXSwidGFyZ2V0X3VzZXJfaWQiOiJ1c2VyLTEifSwidGllciI6MX0s"
        + "ImV4cCI6MTcxNTAwMDYwMCwiaWF0IjoxNzE1MDAwMDAwLCJpc3MiOiJwaG9uZTpvd25lcjplbmNsYXZlIiwianRpIjoiY2FwX2FsbF9maWVs"
        + "ZHMiLCJtYXhfdXNlcyI6NSwibmJmIjoxNzE1MDAwMDAwLCJwYXJlbnRfY2FwIjoiY2FwX3BhcmVudCIsInBhcmVudF9wcm9maWxlIjoicHJv"
        + "Zi0xIiwicHVycG9zZSI6ImV2ZXJ5IGZpZWxkIiwic3ViIjoiYWdlbnQ6YWxwaGFAdXNlcjpiZXRhIn0";

    private static CapabilityClaims Claims(string purpose = "Run one act", long? maxUses = 1, string jti = "cap_card_test")
        => new("phone:operator:enclave", "agent:alpha", new[] { "consumer-app" }, 1_715_000_000, 1_715_000_000,
            1_715_000_600, jti, CapabilityClause.Create(1, "v1", allowActions: new[] { "example:act" }), purpose,
            MaxUses: maxUses);

    private static PendingRequest Card(CapabilityClaims claims, string id = "req-1")
    {
        var (digest, header, payload) = CapabilityJws.BuildSigningInput(claims);
        return Card(header, payload, id, CapabilityJws.Base64UrlEncode(digest));
    }

    private static PendingRequest Card(string header, string payload, string id = "req-1", string hash = "aGFzaA")
        => new(id, PendingRequestKind.CapabilityRequest, "recto", "capability",
            new PendingRequestContext(0, "(external-agent)", 1_715_000_000, "a description", PayloadHashB64u: hash,
                CapHeaderB64: header, CapPayloadB64: payload, CapAgentId: "agent-one"));

    private static PendingRequest CardOf(string payloadJson)
        => Card(GoldenHeader, CapabilityJws.Base64UrlEncode(Encoding.UTF8.GetBytes(payloadJson)));

    private static CapabilityCardDesk Desk(params PendingRequest[] queue) => DeskOn(new SeenPayloads(), queue);

    private static CapabilityCardDesk DeskOn(SeenPayloads seen, params PendingRequest[] queue)
    {
        var desk = new CapabilityCardDesk(seen, new Unhurried());
        desk.Load(queue, Now);
        return desk;
    }

    /// <summary>An hour between any two looks at the clock: no card is ever new.</summary>
    internal sealed class Unhurried : TimeProvider
    {
        private long _at;
        public override long TimestampFrequency => 1;
        public override long GetTimestamp() => _at += 3600;
    }

    private static string GoldenJson => Encoding.UTF8.GetString(CapabilityJws.Base64UrlDecode(GoldenPayload));

    // ---- a short card is unchanged ------------------------------------------------------------------------

    [Fact]
    public void AShortCard_HasOnePart_NoExtraTerm_AndTakesApproveAtOnce()
    {
        var req = Card(Claims());
        var desk = Desk(req);
        var view = desk.ViewOf(req.RequestId)!;
        Assert.Equal("Run one act", desk.PurposeShown(req.RequestId));
        Assert.Single(view.PurposeParts);
        Assert.Empty(view.Terms);
        Assert.Equal(0, desk.PartsLeft(req.RequestId));
        Assert.Equal(CardBlock.None, desk.Judge(req).Block);
    }

    [Fact]
    public void APurposeOfExactlyTheGlance_IsStillOnePart()
    {
        var req = Card(Claims(new string('x', 240)));
        var desk = Desk(req);
        Assert.Equal(new string('x', 240), desk.PurposeShown(req.RequestId));
        Assert.Equal(CardBlock.None, desk.Judge(req).Block);
    }

    [Fact]
    public void ACardThatSignsNoUseCount_SaysAnyNumber()
    {
        var req = Card(Claims(maxUses: null));
        Assert.Equal(new SignedTerm("Uses", "any number until it ends"), Assert.Single(Desk(req).ViewOf(req.RequestId)!.Terms));
    }

    [Fact]
    public void AScopeThatLimitsNothing_SaysAny_AndAValueStandsOnItsOwn()
    {
        SignedList[] Rows(CapabilityScope scope)
            => CapabilityAuditView.From(Claims() with { Cap = Claims().Cap with { Scope = scope } }, Now).ScopeRows.ToArray();

        var any = Assert.Single(Rows(new CapabilityScope([], [], [])));
        Assert.Equal("Scope", any.Label);
        Assert.Empty(any.Values);

        var rows = Rows(new CapabilityScope(["staging"], [], ["one, two", "any", ""]));
        Assert.Equal(new[] { "Services", "Repos", "Environments" }, rows.Select(r => r.Label));
        Assert.Empty(rows[0].Values);
        Assert.Equal(new[] { "one, two", "any", "(empty)" }, rows[1].Values);
        Assert.Equal(new[] { "staging" }, rows[2].Values);
    }

    [Fact]
    public void UpToThreeActions_AreShownAtAGlance()
    {
        CapabilityAuditView View(params string[] actions)
            => CapabilityAuditView.From(Claims() with { Cap = Claims().Cap with { AllowActions = actions } }, Now);

        Assert.Empty(View().GlanceActions);
        Assert.Equal(new[] { "a:one" }, View("a:one").GlanceActions);
        Assert.Equal(new[] { "a:one", "a:two", "a:three" }, View("a:one", "a:two", "a:three", "a:four").GlanceActions);
        Assert.Contains("U+202E", View("a:" + (char)0x202E + "one").GlanceActions[0]);
    }

    // ---- the whole purpose, before Approve -----------------------------------------------------------------

    [Fact]
    public void ALongPurpose_IsReadAPartAtATime_AndApproveWaitsForTheLast()
    {
        var purpose = new string('a', 240) + new string('b', 240) + "the tail";
        var req = Card(Claims(purpose));
        var desk = Desk(req);

        Assert.Equal(new string('a', 240) + "...", desk.PurposeShown(req.RequestId));
        Assert.Equal(2, desk.PartsLeft(req.RequestId));
        Assert.Equal((CardBlock.Unread, CapabilityCardDesk.UnreadText), desk.Judge(req));

        Assert.Equal("1 of 3 parts shown. " + CapabilityCardDesk.UnreadText, desk.ProgressOf(req.RequestId));

        desk.ReadOn(req.RequestId);
        Assert.Equal(CardBlock.Unread, desk.Judge(req).Block);
        Assert.EndsWith("...", desk.PurposeShown(req.RequestId));

        desk.ReadOn(req.RequestId);
        Assert.Equal("The whole request is shown (3 of 3 parts).", desk.ProgressOf(req.RequestId));
        Assert.Equal(purpose, desk.PurposeShown(req.RequestId));
        Assert.Equal(CardBlock.None, desk.Judge(req).Block);

        desk.ReadOn(req.RequestId);   // nothing left to show
        Assert.Equal(3, desk.PartsShown(req.RequestId));
    }

    [Fact]
    public void ReadingProgress_SurvivesAReloadOfTheSameCard_AndNotItsLeavingTheQueue()
    {
        var req = Card(Claims(new string('a', 300)));
        var desk = Desk(req);
        desk.ReadOn(req.RequestId);
        desk.Load(new[] { req, Card(Claims(jti: "other"), "req-2") }, Now);
        Assert.Equal(CardBlock.None, desk.Judge(req).Block);

        desk.Load(Array.Empty<PendingRequest>(), Now);
        desk.Load(new[] { req }, Now);
        Assert.Equal(CardBlock.Unread, desk.Judge(req).Block);
    }

    [Fact]
    public void APart_NeverSplitsASurrogatePair()
    {
        var globe = char.ConvertFromUtf32(0x1F30D);
        var purpose = new string('a', 239) + globe + "end";
        var view = Desk(Card(Claims(purpose))).ViewOf("req-1")!;
        Assert.Equal(new string('a', 239), view.PurposeParts[0]);
        Assert.Equal(purpose, string.Concat(view.PurposeParts));
    }

    // ---- every signed term ---------------------------------------------------------------------------------

    [Fact]
    public void EveryFieldTheBootloaderSigns_IsReadAndShown()
    {
        var req = Card(GoldenHeader, GoldenPayload);
        var desk = Desk(req);
        Assert.Null(desk.RefusalOf(req.RequestId));
        Assert.Equal(CardBlock.None, desk.Judge(req).Block);
        var view = desk.ViewOf(req.RequestId)!;
        Assert.Equal(new[]
        {
            new SignedTerm("Uses", "5"),
            new SignedTerm("Limit per hour", "a:one: 3"),
            new SignedTerm("Limit per day", "a:one: 9"),
            new SignedTerm("Limit per session", "a:one: 2"),
            new SignedTerm("Child of grant", "cap_parent"),
            new SignedTerm("Signs as profile", "prof-1"),
            new SignedTerm("Creates for owner", "owner-1"),
            new SignedTerm("Chat room", "room-1"),
            new SignedTerm("Target user", "user-1"),
            new SignedTerm("Pairing code", "AB12CD34"),
        }, view.Terms);
    }

    [Fact]
    public void TheClaimsModel_CarriesEveryFieldTheBootloaderSigns()
    {
        var claims = CapabilityCardPayload.TryRead(GoldenHeader, GoldenPayload, out var refusal);
        Assert.Null(refusal);
        var (_, header, payload) = CapabilityJws.BuildSigningInput(claims!);
        Assert.Equal(GoldenHeader, header);
        Assert.Equal(GoldenPayload, payload);
    }

    [Theory]
    [InlineData(1_715_000_020 + 121, true)]
    [InlineData(1_715_000_020 + 120, false)]
    [InlineData(1_715_000_000, false)]
    public void ALaterStart_IsShown_PastTheClockSkew(long nbf, bool shown)
    {
        var view = CapabilityAuditView.From(Claims() with { Nbf = nbf }, Now);
        Assert.Equal(shown, view.Terms.Any(t => t.Label == "Not valid before"));
    }

    [Fact]
    public void ACardDatedAhead_SaysSo()
        => Assert.Equal("dated 1h 0m ahead",
            CapabilityAuditView.From(Claims() with { Iat = 1_715_000_020 + 3600 }, Now).RequestedAgo);

    // ---- a card that cannot be shown whole is not signed ----------------------------------------------------

    [Theory]
    [InlineData("\"cap_extra\":1,\"exp\"", "cap_extra")]
    [InlineData("\"max_uses\":5,\"exp\"", "max_uses")]
    public void AnUnknownOrRepeatedField_RefusesTheCard(string instead, string named)
    {
        var req = CardOf(GoldenJson.Replace("\"exp\"", instead));
        var desk = Desk(req);
        Assert.Null(desk.ViewOf(req.RequestId));
        var (block, text) = desk.Judge(req);
        Assert.Equal(CardBlock.Refused, block);
        Assert.StartsWith(CapabilityCardDesk.RefusedPrefix, text);
        Assert.Contains(named, text);
    }

    [Theory]
    [InlineData("\"tier\":1", "\"tier\":1,\"weight\":2", "cap.weight")]
    [InlineData("\"services\":[\"web\"]", "\"services\":[\"web\"],\"path_prefix\":\"/\"", "cap.scope.path_prefix")]
    [InlineData("\"per_day\":{\"a:one\":9}", "\"per_day\":{\"a:one\":9},\"per_year\":{}", "cap.limits.per_year")]
    [InlineData("\"max_uses\":5", "\"max_uses\":\"5\"", "max_uses")]
    [InlineData("\"payload_sha256\":\"ab\"", "\"payload_sha256\":7", "cap.scope.payload_sha256")]
    [InlineData("\"aud\":[\"consumer-app\"]", "\"aud\":[\"consumer-app\",null]", "aud")]
    [InlineData("\"a:one\":9", "\"a:one\":\"9\"", "cap.limits.per_day")]
    [InlineData("\"parent_cap\":\"cap_parent\"", "\"parent_cap\":null", "parent_cap")]
    public void AFieldTheCardCannotShow_RefusesTheCard(string from, string to, string named)
    {
        Assert.Contains(from, GoldenJson);
        var req = CardOf(GoldenJson.Replace(from, to));
        var (block, text) = Desk(req).Judge(req);
        Assert.Equal(CardBlock.Refused, block);
        Assert.Contains(named, text);
    }

    [Theory]
    [InlineData("{\"alg\":\"none\",\"typ\":\"JWT\"}")]
    [InlineData("{\"alg\":\"ES256K\",\"typ\":\"JWT\",\"kid\":\"k\"}")]
    [InlineData("{\"typ\":\"JWT\"}")]
    [InlineData("[]")]
    public void AHeaderOfAnotherShape_RefusesTheCard(string header)
    {
        var req = Card(CapabilityJws.Base64UrlEncode(Encoding.UTF8.GetBytes(header)), GoldenPayload);
        Assert.Equal(CardBlock.Refused, Desk(req).Judge(req).Block);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("not base64url!")]
    [InlineData("e30=")]
    [InlineData("e30 ")]
    [InlineData("e31")]
    public void ASegmentInAnotherSpelling_RefusesTheCard(string? payload)
    {
        var req = Card(GoldenHeader, payload!);
        Assert.Equal(CardBlock.Refused, Desk(req).Judge(req).Block);
    }

    [Fact]
    public void ATimeTheCardCannotShow_RefusesTheCard()
    {
        var req = CardOf(GoldenJson.Replace("\"exp\":1715000600", "\"exp\":9223372036854775807"));
        Assert.Equal(CardBlock.Refused, Desk(req).Judge(req).Block);
    }

    // ---- hidden characters -----------------------------------------------------------------------------------

    [Fact]
    public void AHiddenCharacter_IsWrittenOut_WhereverItIsSigned()
    {
        var rlo = ((char)0x202E).ToString();
        var claims = Claims("Rename " + rlo + "it") with
        {
            Aud = new[] { "consumer" + (char)0x200B },
            Sub = "agent:al" + (char)0x2066 + "pha",
        };
        var view = Desk(Card(claims)).ViewOf("req-1")!;
        Assert.Equal("Rename " + (char)0x27E8 + "U+202E" + (char)0x27E9 + "it", view.PurposeShort);
        Assert.Contains("U+200B", view.Audience[0]);
        Assert.Contains("U+2066", view.ActingAgent);
    }

    [Theory]
    [InlineData(0x202A)]
    [InlineData(0x202E)]
    [InlineData(0x2066)]
    [InlineData(0x2069)]
    [InlineData(0x200E)]
    [InlineData(0x061C)]
    [InlineData(0x200B)]
    [InlineData(0x200D)]
    [InlineData(0xFEFF)]
    [InlineData(0x00AD)]
    [InlineData(0x2028)]
    [InlineData(0x0007)]
    [InlineData(0x0085)]
    [InlineData(0xE0041)]
    [InlineData(0xE000)]
    [InlineData(0x3164)]
    [InlineData(0x2800)]
    [InlineData(0x200C)]
    [InlineData(0xFE0E)]
    [InlineData(0xFE0F)]
    [InlineData(0xFFFC)]
    [InlineData(0xFFFE)]
    [InlineData(0xFDD0)]
    [InlineData(0x10FFFF)]
    [InlineData(0x0378)]
    [InlineData(0x16FE4)]
    [InlineData(0x1D159)]
    [InlineData(0x1107F)]
    [InlineData(0x0335)]
    [InlineData(0x0336)]
    [InlineData(0x0338)]
    [InlineData(0x20D2)]
    [InlineData(0x20E0)]
    [InlineData(0x20E3)]
    [InlineData(0x0489)]
    [InlineData(0x1AB0 + 0xE)]
    public void EachHiddenCharacter_IsNamedByItsCodePoint(int codePoint)
    {
        var text = "a" + char.ConvertFromUtf32(codePoint) + "b";
        Assert.Contains($"U+{codePoint:X4}", VisibleText.Of(text));
        Assert.Equal("ab", VisibleText.WithoutHidden(text));
    }

    [Fact]
    public void OrdinaryText_ComesBackAsItWas()
    {
        foreach (var text in new[] { "plain", "caf" + (char)0xE9, "line\nbreak\ttab", "heart " + (char)0x2764 + (char)0xFE0F,
                                     "globe " + char.ConvertFromUtf32(0x1F30D), string.Empty })
        {
            Assert.Same(text, VisibleText.Of(text));
        }
        Assert.Equal((char)0x27E8 + "U+D800" + (char)0x27E9 + "x", VisibleText.Of((char)0xD800 + "x"));
    }

    private static string Text(params int[] codePoints) => string.Concat(codePoints.Select(char.ConvertFromUtf32));

    public static IEnumerable<object[]> SpelledWithAJoiner() => new[]
    {
        Text(0x0645, 0x06CC, 0x200C, 0x062E, 0x0648, 0x0627, 0x0647, 0x0645),              // Persian, a non-joiner inside a word
        Text(0x0643, 0x0651, 0x200D, 0x0627),                                              // Arabic, a mark before the joiner
        Text(0x0915, 0x094D, 0x200D, 0x0937), Text(0x0915, 0x094D, 0x200C, 0x0937),        // Devanagari, after the virama
        Text(0x0DC1, 0x0DCA, 0x200D, 0x0DBB, 0x0DD3),                                      // Sinhala
        Text(0x1F468, 0x200D, 0x1F469, 0x200D, 0x1F467),                                   // a family
        Text(0x2764, 0xFE0F, 0x200D, 0x1F525), Text(0x1F469, 0x1F3FD, 0x200D, 0x1F4BB),    // a heart on fire, a skin tone
        Text(0x1F3F3, 0xFE0F, 0x200D, 0x1F308), Text(0x31, 0xFE0F, 0x20E3), Text(0x23, 0x20E3),
        Text(0x1F1F5, 0x1F1F1), Text(0x2764, 0xFE0F), Text(0x00A9, 0xFE0F),
        Text(0x05E9, 0x05DC, 0x05D5, 0x05DD), Text(0x0633, 0x0644, 0x0627, 0x0645),        // Hebrew, Arabic
        Text(0x0065, 0x0301), Text(0x0E01, 0x0E34, 0x0E48),                                // a decomposed accent, Thai
    }.Select(t => new object[] { t });

    [Theory]
    [MemberData(nameof(SpelledWithAJoiner))]
    public void TextSpelledWithAJoiner_ComesBackAsItWas(string text)
    {
        Assert.Same(text, VisibleText.Of(text));
        Assert.False(VisibleText.HasHidden(text));
    }

    public static IEnumerable<object[]> JoinersOutOfPlace() => new[]
    {
        Text(0x61, 0x200C, 0x62), Text(0x61, 0x200D, 0x62),                  // Latin is not written joined
        Text(0x0645, 0x200C), Text(0x200C, 0x0645),                          // nothing on one side
        Text(0x0645, 0x200C, 0x200C, 0x0645),                                // two in a row
        Text(0x0645, 0x200C, 0x61), Text(0x61, 0x200D, 0x0645),              // another script on one side
        Text(0x0645, 0x200C, 0x0915), Text(0x0645, 0x200D, 0x20, 0x0645),
        Text(0x1F468, 0x200D, 0x61), Text(0x61, 0x200D, 0x1F468), Text(0x1F468, 0x200C, 0x1F469),
        Text(0x61, 0xFE0F), Text(0x31, 0xFE0F), Text(0x31, 0xFE0F, 0x30), Text(0x61, 0x20E3),
        Text(0x1F3F4, 0xE0067, 0xE007F),
    }.Select(t => new object[] { t });

    [Theory]
    [MemberData(nameof(JoinersOutOfPlace))]
    public void AJoinerOutOfPlace_IsWrittenOut(string text)
    {
        Assert.NotEqual(text, VisibleText.Of(text));
        Assert.True(VisibleText.HasHidden(text));
    }

    [Fact]
    public void ALongRequestInAJoinedScript_IsNoLongerThanItWas()
    {
        var word = Text(0x0645, 0x06CC, 0x200C, 0x062E, 0x0648, 0x0627, 0x0647, 0x0645) + " ";
        var view = CapabilityAuditView.From(Claims(string.Concat(Enumerable.Repeat(word, 23))), Now);
        Assert.Single(view.PurposeParts);
    }

    [Fact]
    public void AnActorsName_ShowsItsHiddenCharacters()
    {
        var verdict = ActorContextCheck.Of("agent:alpha", new ActorContext("agent:alpha", "Al" + (char)0x202E + "ice", null));
        Assert.True(verdict.Show);
        Assert.Contains("U+202E", verdict.Name);
        var other = ActorContextCheck.Of("agent:alpha", new ActorContext("agent:al" + (char)0x202E + "pha", "Alice", null));
        Assert.Contains("U+202E", other.Warning);
    }

    // ---- the cross-check ---------------------------------------------------------------------------------------

    private const string Foreign = "00000000-0000-0000-0000-000000000000";

    public static IEnumerable<object[]> Decoys() => new (string, Func<CapabilityClaims, CapabilityClaims>)[]
    {
        ("a scope service", c => c with { Cap = c.Cap with { Scope = new CapabilityScope([], [Foreign], []) } }),
        ("a scope repo", c => c with { Cap = c.Cap with { Scope = new CapabilityScope([], [], [Foreign]) } }),
        ("a scope env", c => c with { Cap = c.Cap with { Scope = new CapabilityScope([Foreign], [], []) } }),
        ("a group", c => c with { Cap = c.Cap with { Groups = [Foreign] } }),
        ("a denied action", c => c with { Cap = c.Cap with { DenyActions = [Foreign] } }),
        ("the audience", c => c with { Aud = [Foreign] }),
        ("the request id", c => c with { Jti = Foreign }),
        ("the target user", c => c with { Cap = c.Cap with { Scope = new CapabilityScope([], [], [], TargetUserId: Foreign) } }),
    }.Select(d => new object[] { d.Item1, d.Item2 });

    [Theory]
    [MemberData(nameof(Decoys))]
    public void AUuidCarriedElsewhere_NeverQuietsTheCheck(string carrier, Func<CapabilityClaims, CapabilityClaims> decoy)
    {
        var claims = decoy(Claims($"Approve access for agent {Foreign}"));
        var warning = Assert.Single(CapabilityAuditView.From(claims, Now).Warnings);
        Assert.Contains(Foreign, warning);
        Assert.Contains(carrier, warning);
        Assert.Contains("agent:alpha", warning);
    }

    [Fact]
    public void AHiddenCharacterInsideAUuid_DoesNotHideItFromTheCheck()
    {
        var claims = Claims("Approve access for agent 00000000-0000-" + (char)0x200B + "0000-0000-000000000000");
        Assert.Single(CapabilityAuditView.From(claims, Now).Warnings);
    }

    private const string Uuid = "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0";

    public static IEnumerable<object[]> OtherSpellings() => new[]
    {
        Uuid.Replace('-', (char)0x2010), Uuid.Replace('-', (char)0x2011), Uuid.Replace('-', (char)0x2212),
        Uuid.Replace('-', (char)0x2014), Uuid.Replace('-', (char)0xFF0D), Uuid.Replace('-', (char)0x2500),
        Uuid.Replace('a', (char)0x0430).Replace('e', (char)0x0435).Replace('c', (char)0x0441),
        Uuid.Replace('d', (char)0x0501).Replace('0', (char)0x041E), Uuid.Replace('0', 'O').Replace('1', 'l'),
        Uuid.Replace('b', (char)0x0299).Replace('f', (char)0xA730),
        Uuid.Replace('1', (char)0x0661).Replace('2', (char)0x06F2).Replace('3', (char)0xFF13),
        Uuid.Replace("4", Text(0x1D7D2)).Replace("a", Text(0x1D41A)), Uuid.ToUpperInvariant(),
        Uuid.Insert(9, "\n"), Uuid.Insert(9, " "), Uuid.Insert(4, Text(0x00A0)), Uuid.Insert(4, Text(0x3000)),
        Uuid.Insert(4, Text(0xFE0F)), Uuid.Insert(4, Text(0x0301)), Uuid.Insert(4, Text(0x0335)), Uuid.Insert(4, Text(0x20DD)),
        Uuid.Replace("-", " - "),
        Uuid.Replace('-', (char)0x06D4), Uuid.Replace('-', (char)0x2574), Uuid.Replace('-', (char)0x31D0),
        Uuid.Replace('-', (char)0x3127), Uuid.Replace('-', (char)0x1428), Uuid.Replace('-', (char)0xA7F7),
        Uuid.Replace('-', (char)0x02C9), Uuid.Replace('-', (char)0x2CBB), Uuid.Replace("-", Text(0x10191)),
        Uuid.Replace('2', (char)0x01A7), Uuid.Replace('2', (char)0xA644), Uuid.Replace('9', (char)0xA76E),
        Iso(Uuid), Uuid[..4] + Iso(Uuid[4..]),
    }.Select(u => new object[] { u });

    [Theory]
    [MemberData(nameof(OtherSpellings))]
    public void AUuidInAnotherSpelling_IsTheSameUuidToTheCheck(string spelled)
    {
        var warning = Assert.Single(CapabilityAuditView.From(Claims($"Act for {spelled} today"), Now).Warnings);
        Assert.Contains(Uuid, warning, StringComparison.OrdinalIgnoreCase);
        // and the signed subject's own, however it is spelled, warns of nothing
        Assert.Empty(CapabilityAuditView.From(
            Claims($"Act for {spelled} today") with { Sub = "agent:alpha@user:" + Uuid }, Now).Warnings);
    }

    [Fact]
    public void AnOrdinaryPurpose_WarnsOfNothing()
    {
        foreach (var purpose in new[]
                 {
                     "Deploy 2026-11-24 - fix the deadbeef-cafe decode - 12 files, 1-2 hours",
                     "Vault SET: ServiceA/example-key = sha256:818e58a60e89... on rb1-0123456789abcdef0123456789abcdef - until 2026-10-15 07:40Z",
                     "Roll back owner/repo: running 01234567 back to 89abcdef",
                     Text(0x0645, 0x06CC, 0x200C, 0x062E, 0x0648, 0x0627, 0x0647, 0x0645),
                 })
        {
            Assert.Empty(CapabilityAuditView.From(Claims(purpose), Now).Warnings);
        }
    }

    // ---- a payload that changes under its id ---------------------------------------------------------------------

    [Fact]
    public void AChangedPayload_IsRefused_AndSaysSo_EvenWhenItChangesBack()
    {
        var first = Card(Claims("Rename the world"));
        var swapped = Card(Claims("Delete the world"));
        var desk = Desk(first);
        Assert.Equal(CardBlock.None, desk.Judge(first).Block);

        desk.Load(new[] { swapped }, Now);
        Assert.Equal((CardBlock.Refused, CapabilityCardDesk.ChangedText), desk.Judge(swapped));
        Assert.Equal(CardBlock.Refused, desk.Judge(first).Block);   // a tap on the card as it was first rendered

        desk.Load(new[] { first }, Now);
        Assert.Equal(CardBlock.Refused, desk.Judge(first).Block);
    }

    [Fact]
    public void AChangedPayload_IsRememberedByTheApp_NotByThePage()
    {
        var seen = new SeenPayloads();
        DeskOn(seen, Card(Claims("Rename the world")));
        var swapped = Card(Claims("Delete the world"));
        Assert.Equal(CardBlock.Refused, DeskOn(seen, swapped).Judge(swapped).Block);
    }

    [Fact]
    public void AnIdThatLeftTheQueue_IsStillRemembered()
    {
        var seen = new SeenPayloads();
        var desk = DeskOn(seen, Card(Claims("Rename the world")));
        desk.Load(Array.Empty<PendingRequest>(), Now);
        var swapped = Card(Claims("Delete the world"));
        desk.Load(new[] { swapped }, Now);
        Assert.Equal(CardBlock.Refused, desk.Judge(swapped).Block);
    }

    [Fact]
    public void AnotherKindsPayload_IsHeldToItsFirstToo_AndAnUnsignedDetailIsNot()
    {
        static PendingRequest Sign(string hash, string text, long at) => new("req-9", PendingRequestKind.SingleSign,
            "recto", "top-plane:x", new PendingRequestContext(0, "(bootloader)", at, text, PayloadHashB64u: hash));
        var desk = Desk(Sign("aGFzaA", "one", 1));
        // A card the bootloader puts back after a restart carries its id, its hash and a new queue time.
        Assert.Equal(CardBlock.None, desk.Judge(Sign("aGFzaA", "one", 2)).Block);
        Assert.Equal(CardBlock.Refused, desk.Judge(Sign("b3RoZXI", "one", 1)).Block);
    }

    [Fact]
    public void AMessageThatChangesUnderItsId_IsRefused_WhateverItsHashSays()
    {
        static PendingRequest Sign(string text) => new("req-10", PendingRequestKind.EthSign, "svc", "eth",
            new PendingRequestContext(0, "a", 1, "sign", PayloadHashB64u: "aGFzaA",
                EthMessageKind: EthMessageKind.PersonalSign, EthMessageText: text));
        var desk = Desk(Sign("send one"));
        Assert.Equal(CardBlock.None, desk.Judge(Sign("send one")).Block);
        Assert.Equal(CardBlock.Refused, desk.Judge(Sign("send ten")).Block);
    }

    [Fact]
    public void ACardThatLeftTheQueue_IsNotSaidToHaveChanged()
    {
        var req = Card(Claims());
        var desk = Desk(req);
        desk.Load(Array.Empty<PendingRequest>(), Now);
        Assert.Equal((CardBlock.Refused, CapabilityCardDesk.GoneText), desk.Judge(req));
    }

    [Fact]
    public void AListOfValues_IsNeverDigestedAsAnother()
    {
        static PendingRequest Session(params string[]? scope) => new("req-11", PendingRequestKind.SessionIssuance, "s", "k",
            new PendingRequestContext(0, "x", 1, "d", SessionBearer: "b", SessionScope: scope));
        var digests = new[] { Session("a b"), Session("a", "b"), Session("a", "b", ""), Session("a:b"), Session(), Session(null) }
            .Select(CapabilityCardDesk.DigestOf).ToList();
        Assert.Equal(digests.Count, digests.Distinct().Count());
    }

    [Fact]
    public void ACardTheDeskNeverLoaded_IsNotApprovable_AndOneItDoesNotOwnIs()
    {
        var desk = new CapabilityCardDesk(new SeenPayloads());
        Assert.Equal((CardBlock.Refused, CapabilityCardDesk.GoneText), desk.Judge(Card(Claims())));
        var sign = new PendingRequest("demo", PendingRequestKind.SingleSign, "demo-service", "demo-secret",
            new PendingRequestContext(0, "demo", 1, "demo", PayloadHashB64u: "aGFzaA"));
        Assert.Equal(CardBlock.None, desk.Judge(sign).Block);
    }

    [Fact]
    public void ForgettingIsOldestFirst_AndNeverAnIdOnTheQueue()
    {
        var seen = new SeenPayloads();
        for (var i = 0; i <= SeenPayloads.Capacity + 1; i++) seen.Unchanged("id-" + i, "d");
        seen.Trim(new HashSet<string> { "id-0" });
        Assert.False(seen.Unchanged("id-0", "other"));   // still held
        Assert.True(seen.Unchanged("id-1", "other"));    // forgotten: seen as new
    }

    // ---- the page -------------------------------------------------------------------------------------------------

    [Fact]
    public void ThePage_JudgesTheCardBeforeTheEnclaveIsAsked()
    {
        var approve = ProfileSigningInputTests.MethodBody(ProfileSigningInputTests.HomePage(), "HandleApproveAsync");
        var judged = approve.IndexOf("Cards.Judge(req)", StringComparison.Ordinal);
        var signed = approve.IndexOf("await ApproveCapabilityRequestAsync(req);", StringComparison.Ordinal);
        Assert.True(judged > 0 && signed > judged);
    }

    [Fact]
    public void ThePage_RendersThePurposeFromTheDesk_AndOffersNoApproveWhileBlocked()
    {
        var page = ProfileSigningInputTests.HomePage().Replace("\r\n", "\n");
        Assert.Contains("<bdi dir=\"auto\">@(Cards.PurposeShown(req.RequestId))</bdi>", page);
        Assert.DoesNotContain("PurposeShort", page);
        Assert.Contains("Cards.ReadOn(req.RequestId)", page);
        Assert.Contains("foreach (var term in capDecoded.Terms)", page);
        var blocked = page.IndexOf("else if (Cards.Judge(req) is { Block: Recto.Shared.Capability.CardBlock.Refused } judged)",
            StringComparison.Ordinal);
        var offered = page.IndexOf("@onclick=\"() => HandleApproveAsync(req)\"", StringComparison.Ordinal);
        Assert.True(blocked > 0 && offered > blocked);
        Assert.Equal(offered, page.LastIndexOf("@onclick=\"() => HandleApproveAsync(req)\"", StringComparison.Ordinal));
        Assert.Contains("disabled=\"@(!string.IsNullOrEmpty(_processingRequestId) || Cards.Judge(req).Block != "
            + "Recto.Shared.Capability.CardBlock.None)\"", page[blocked..offered]);
    }

    [Fact]
    public void ReadOn_StandsBesideApprove_AndStaysThere()
    {
        var page = ProfileSigningInputTests.HomePage().Replace("\r\n", "\n");
        var row = page.IndexOf("<div class=\"rec-btn-row\" style=\"flex-wrap: wrap;\">", StringComparison.Ordinal);
        var approve = page.IndexOf("@onclick=\"() => HandleApproveAsync(req)\"", StringComparison.Ordinal);
        var readOn = page.IndexOf("@onclick=\"() => ReadOn(req)\"", StringComparison.Ordinal);
        Assert.True(row > 0 && readOn > row && approve > readOn);
        // One row holds both; the button is drawn while there is more than one part, read or not.
        Assert.DoesNotContain("</div>", page[row..approve]);
        Assert.Contains("@if (parts > 1)", page[row..readOn]);
        Assert.Contains("aria-disabled=\"@(unread ? \"false\" : \"true\")\"", page[row..approve]);
        Assert.Contains("aria-describedby=\"@(parts > 1 ? readOnId + \" \" + progressId : null)\"", page[readOn..approve]);
    }

    [Fact]
    public void HowFarACardIsRead_IsSaidPolitely_AndOnlyARefusalIsAnAlert()
    {
        var page = ProfileSigningInputTests.HomePage().Replace("\r\n", "\n");
        Assert.Contains("role=\"status\" aria-live=\"polite\">@Cards.ProgressOf(req.RequestId)</p>", page);
        Assert.Single(System.Text.RegularExpressions.Regex.Matches(page, "role=\"alert\">@judged\\.Text"));
        Assert.DoesNotContain("UnreadText", page);
    }

    [Fact]
    public void ACard_KeepsItsOwnStateWhereverItMoves_AndItsFailureIsItsOwn()
    {
        var page = ProfileSigningInputTests.HomePage().Replace("\r\n", "\n");
        foreach (var section in new[] { "identityReqs", "tokenReqs" })
        {
            Assert.Contains($"CapabilityCardDesk.Keyed({section}))\n                                {{\n"
                + "                                    <CardBoundary @key=\"card.Key\">", page);
        }
        Assert.Equal(2, page.Split("<ErrorContent>@renderRefused(card.Request)</ErrorContent>").Length - 1);
        Assert.DoesNotContain("@foreach (var req in identityReqs)", page);
    }

    [Fact]
    public void AHeldTap_IsLetGo_AndTheUserVaultCardIsHeldToo()
    {
        var page = ProfileSigningInputTests.HomePage();
        var approve = ProfileSigningInputTests.MethodBody(page, "HandleApproveAsync");
        Assert.Contains("if (judged.Block == Recto.Shared.Capability.CardBlock.Held) return;", approve);
        Assert.Contains("Held=\"@Cards.IsHeld(req.RequestId)\"", page);
        // A panel above the cards comes or goes: asked as the page is drawn, before any card is.
        var panels = ProfileSigningInputTests.MethodBody(page, "HoldAsPanelsMove");
        // What each says, not only whether it is there: words that grow in place move the cards too.
        foreach (var said in new[] { "{_lastTotpAlias}/{_lastTotpCode}/{_totpCopied}", "{_identityErrorTitle}/{_reverifying}",
                                     "Said(_identityError),", "{polling}/{_retrying}" })
            Assert.Contains(said, panels);
        Assert.Contains("Cards.HoldFrom();", panels);
        Assert.Contains("_ = RenderWhenHoldEndsAsync();", panels);
        var asked = page.IndexOf("HoldAsPanelsMove(totpFresh);", StringComparison.Ordinal);
        Assert.True(asked > 0 && asked < page.IndexOf("@if (totpFresh)", StringComparison.Ordinal)
            && asked < page.IndexOf("RenderFragment<PendingRequest> renderCard", StringComparison.Ordinal));
        var view = System.IO.File.ReadAllText(PagePath("UserVaultCardView.razor"));
        Assert.Contains("disabled=\"@Held\" @onclick=\"ApproveAsync\"", view);
        Assert.Contains("if (_model is null || Held) return;", view);
    }

    [Fact]
    public void ADenial_GoesToTheQueueTheCardWaitsOn()
    {
        var page = ProfileSigningInputTests.HomePage();
        Assert.Contains("await SendDenialAsync(req)", ProfileSigningInputTests.MethodBody(page, "HandleDenyAsync"));
        var send = ProfileSigningInputTests.MethodBody(page, "SendDenialAsync");
        Assert.Contains("req.Kind == PendingRequestKind.Unreadable ? req.NamedKind : req.Kind", send);
        var other = send.IndexOf("BootloaderClient.RespondAsync(", StringComparison.Ordinal);
        Assert.True(send.IndexOf("IsUserVaultKind(kind)", StringComparison.Ordinal) < other);
        Assert.True(send.IndexOf("BootloaderClient.DenyUserVaultGrantRequestAsync(", StringComparison.Ordinal) > other);
    }

    [Fact]
    public void AFaultBesideTheCards_NeverLeavesThemUndrawn()
    {
        var refresh = ProfileSigningInputTests.MethodBody(ProfileSigningInputTests.HomePage(), "RefreshPendingCoreAsync");
        var listed = refresh.IndexOf("await Registry.GetAllAsync(ct);", StringComparison.Ordinal);
        Assert.EndsWith("try", refresh[..listed].Split('{')[^2].Trim());
        Assert.Contains("catch (Exception) when (!ct.IsCancellationRequested)",
            refresh[listed..refresh.IndexOf("Cards.Load(arrived", StringComparison.Ordinal)]);
        Assert.DoesNotContain("when (ex is not OperationCanceledException)", refresh);
    }

    private static string Iso(string inner) => (char)0x2068 + inner + (char)0x2069;

    public static IEnumerable<object[]> BalancedIsolates() => new[]
    {
        Iso("title"), "a " + Iso("b") + " c " + Iso("d"), Iso("a " + Iso("b")),
        "say " + Iso(Text(0x05E9, 0x05DC, 0x05D5, 0x05DD)) + " now",
    }.Select(t => new object[] { t });

    [Theory]
    [MemberData(nameof(BalancedIsolates))]
    public void ABalancedIsolateAroundARun_PassesInProse_AndNeverInAnIdOrAName(string text)
    {
        Assert.Same(text, VisibleText.OfProse(text));
        Assert.Contains("U+2068", VisibleText.Of(text));
        Assert.Equal(text, CapabilityAuditView.From(Claims(text), Now).PurposeParts[0]);
        Assert.Contains("U+2068", CapabilityAuditView.From(Claims() with { Sub = "agent:" + text }, Now).ActingAgent);
    }

    [Theory]
    [InlineData(new[] { 0x2068, 0x61 }, "U+2068")]                      // not closed
    [InlineData(new[] { 0x61, 0x2069 }, "U+2069")]                      // not opened
    [InlineData(new[] { 0x2069, 0x61, 0x2068 }, "U+2069")]
    [InlineData(new[] { 0x61, 0x2068, 0x2069 }, "U+2068")]              // around nothing
    [InlineData(new[] { 0x2068, 0x20, 0x200B, 0x2069 }, "U+2069")]      // around nothing drawn
    [InlineData(new[] { 0x2068, 0x61, 0x0A, 0x62, 0x2069 }, "U+2068")]  // over a line's end
    [InlineData(new[] { 0x2066, 0x61, 0x2069 }, "U+2069")]              // another isolate's
    [InlineData(new[] { 0x2067, 0x61, 0x2069 }, "U+2067")]
    [InlineData(new[] { 0x2068, 0x202E, 0x61, 0x2069 }, "U+202E")]      // what it holds is judged as ever
    [InlineData(new[] { 0x2068, 0x2068, 0x61, 0x2069 }, "U+2068")]
    public void AnyOtherIsolate_IsWrittenOut(int[] codePoints, string named)
        => Assert.Contains(named, VisibleText.OfProse(Text(codePoints)));

    [Fact]
    public void HoweverDeepIsolatesNest_ReadingThemTakesOnePass()
    {
        const int depth = 100_000;
        var text = new string((char)0x2068, depth) + "a" + new string((char)0x2069, depth);
        var clock = System.Diagnostics.Stopwatch.StartNew();
        Assert.Same(text, VisibleText.OfProse(text));
        Assert.Contains("U+2068", VisibleText.OfProse(new string((char)0x2068, depth) + new string((char)0x2069, depth)));
        Assert.True(clock.Elapsed < TimeSpan.FromSeconds(3), $"{clock.Elapsed}");
    }

    private static string PagePath(string name)
    {
        var dir = new System.IO.DirectoryInfo(System.AppContext.BaseDirectory);
        while (dir is not null && !System.IO.File.Exists(System.IO.Path.Combine(dir.FullName, "Recto.Shared", "Pages", name)))
            dir = dir.Parent;
        return System.IO.Path.Combine(dir!.FullName, "Recto.Shared", "Pages", name);
    }

    [Fact]
    public void NothingOnACard_IsCutOff()
    {
        var css = System.IO.File.ReadAllText(PagePath("Home.razor.css")).Replace("\r\n", "\n");
        var body = css[css.IndexOf(".rec-pending-card-body {", StringComparison.Ordinal)..];
        Assert.Contains("overflow-wrap: anywhere;", body[..body.IndexOf('}')]);
        var page = ProfileSigningInputTests.HomePage();
        Assert.Contains("<div style=\"overflow-wrap: anywhere;\"><code dir=\"auto\">@glance</code></div>", page);
        Assert.Contains("@foreach (var scopeRow in capDecoded.ScopeRows)", page);
        Assert.DoesNotContain("string.Join(\", \", capDecoded", page);
        Assert.DoesNotContain("string.Join(\", \", s)", page);
    }

    [Fact]
    public void WhatACardWasSent_IsShownThroughCardText()
    {
        var page = ProfileSigningInputTests.HomePage();
        var card = page[page.IndexOf("RenderFragment<PendingRequest> renderCard", StringComparison.Ordinal)
            ..page.IndexOf("var identityReqs = ", StringComparison.Ordinal)];
        card = System.Text.RegularExpressions.Regex.Replace(card, @"@\*.*?\*@", string.Empty,
            System.Text.RegularExpressions.RegexOptions.Singleline);
        // Numbers alone are drawn as they are.
        var raw = System.Text.RegularExpressions.Regex.Matches(card,
            @"(?<![=""(])@\(?(?:req\.(?:Service|Secret|Kind|Context\.(?!ChildPid|TotpPeriodSeconds|TotpDigits|SessionLifetimeSeconds"
            + @"|SessionMaxUses|CandidateDerivation|AppContext|UserVaultGrant|CapPayload))|td\.|tx\.|appCtx\.App(?:Name|Desc|Url|Version))[^\n]*")
            .Select(m => m.Value);
        Assert.Empty(raw);
        foreach (var shown in new[] { "req.Service", "req.Secret", "req.Kind", "req.Context.SessionBearer ?? \"?\"", "req.Context.TotpAlias",
                                      "req.Context.ChildArgv0", "req.Context.CandidateDisplayName", "tx.To", "td.PrimaryType" })
        {
            Assert.Contains($"<CardText Value=\"@({shown})\" />", card);
        }
    }

    [Theory]
    [InlineData("BtcMessageText")]
    [InlineData("EdMessageText")]
    [InlineData("EthMessageText")]
    [InlineData("TronMessageText")]
    public void ThePage_ShowsASignedMessagesHiddenCharacters(string field)
    {
        var page = ProfileSigningInputTests.HomePage();
        Assert.Contains($"<strong>Message:</strong> <CardText Value=\"@req.Context.{field}\" />", page);
    }

    [Fact]
    public void TheQueue_IsReadBeforeItIsRendered()
    {
        var refresh = ProfileSigningInputTests.MethodBody(ProfileSigningInputTests.HomePage(), "RefreshPendingCoreAsync");
        var read = refresh.IndexOf("Cards.Load(arrived, DateTimeOffset.UtcNow);", StringComparison.Ordinal);
        var shown = refresh.IndexOf("_pending = arrived;", StringComparison.Ordinal);
        Assert.True(read > 0 && shown > read);
        // A queue is remembered as acted on only once it was read: one that was not is read again at the next poll.
        var remembered = refresh.IndexOf("_lastPendingFingerprint = wireFingerprint;", StringComparison.Ordinal);
        Assert.True(remembered > shown);
        // Nothing is awaited between the read and the drawing: a card's hold begins as a person first sees it.
        Assert.DoesNotContain("await ", refresh[read..refresh.IndexOf("else", remembered, StringComparison.Ordinal)]);
        Assert.Contains("OrderBy(r => IsTokenSigningKind(r.Kind))", refresh);
    }

    // ---- the pairing fingerprint --------------------------------------------------------------------------------------

    [Fact]
    public void TheFingerprint_IsTheFormTheOtherScreenShows()
    {
        // SHA-256 over the raw 64 bytes, first eight bytes, four groups of upper-case hex.
        var key = Enumerable.Range(0, 64).Select(i => (byte)i).ToArray();
        Assert.Equal("FDEA-B9AC-F371-0362", KeyFingerprint.Of(key));
        Assert.Throws<ArgumentException>(() => KeyFingerprint.Of(new byte[65]));
    }

    [Fact]
    public void ThePairing_ShowsTheFingerprintBeforeItSends_AndAfter()
    {
        var pair = ProfileSigningInputTests.MethodBody(ProfileSigningInputTests.HomePage(), "HandlePairServiceClick");
        var shown = pair.IndexOf("_pairServiceFingerprint = Recto.Shared.Capability.KeyFingerprint.Of(pubkeyResult.Value);",
            StringComparison.Ordinal);
        var sent = pair.IndexOf("BootloaderClient.PairDeviceAsync(", StringComparison.Ordinal);
        Assert.True(shown > 0 && sent > shown);
        Assert.Equal(1, pair.Split("_pairServiceFingerprint = null").Length - 1);   // cleared at the start only
        Assert.Equal(2, ProfileSigningInputTests.HomePage().Split("<code>@_pairServiceFingerprint</code>").Length - 1);
    }
}
