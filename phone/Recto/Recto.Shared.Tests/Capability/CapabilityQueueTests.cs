using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Rendering;
using Microsoft.AspNetCore.Components.Web;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Recto.Shared.Capability;
using Recto.Shared.Pages;
using Recto.Shared.Protocol.V04;
using Xunit;

namespace Recto.Shared.Tests.Capability;

/// <summary>
/// The queue on the phone: a card that cannot be read is one refused card with
/// its Deny, and the cards beside it stand; a card that was drawn or moved a
/// moment ago takes no Approve yet.
/// </summary>
public class CapabilityQueueTests
{
    private static readonly DateTimeOffset Now = DateTimeOffset.FromUnixTimeSeconds(1_715_000_020);

    private const string Header = "{\"alg\":\"ES256K\",\"typ\":\"JWT\"}";

    // Every field the bootloader signs, and every one the wire carries beside them.
    private const string Payload =
        "{\"aud\":[\"consumer-app\"],\"cap\":{\"allow_actions\":[\"a:one\"],\"deny_actions\":[\"a:two\"],\"groups\":[\"g:one\"],"
        + "\"limits\":{\"per_day\":{\"a:one\":9},\"per_hour\":{\"a:one\":3},\"per_session\":{\"a:one\":2}},\"registry_version\":\"v1\","
        + "\"scope\":{\"chat_room_id\":\"room-1\",\"create_for_owner\":\"owner-1\",\"env\":[\"staging\"],\"pairing_code\":\"AB12CD34\","
        + "\"payload_sha256\":\"ab\",\"repos\":[\"r\"],\"services\":[\"web\"],\"target_user_id\":\"user-1\"},\"tier\":1},"
        + "\"exp\":1715000600,\"iat\":1715000000,\"iss\":\"phone:owner:enclave\",\"jti\":\"cap_all_fields\",\"max_uses\":5,"
        + "\"nbf\":1715000000,\"parent_cap\":\"cap_parent\",\"parent_profile\":\"prof-1\",\"purpose\":\"every field\","
        + "\"sub\":\"agent:alpha@user:beta\"}";

    private static readonly JsonSerializerOptions Wire = new(JsonSerializerDefaults.Web);

    private static string B64(string text) => CapabilityJws.Base64UrlEncode(Encoding.UTF8.GetBytes(text));

    private static JsonObject Card(string id, string header = Header, string payload = Payload) => new()
    {
        ["request_id"] = id,
        ["kind"] = PendingRequestKind.CapabilityRequest,
        ["service"] = "recto",
        ["secret"] = "capability",
        ["context"] = new JsonObject
        {
            ["child_pid"] = 0,
            ["child_argv0"] = "(external-agent)",
            ["requested_at_unix"] = 1_715_000_000,
            ["operation_description"] = "a description",
            ["payload_hash_b64u"] = "aGFzaA",
            ["cap_header_b64"] = B64(header),
            ["cap_payload_b64"] = B64(payload),
            ["cap_agent_id"] = "agent-one",
            ["app_context"] = new JsonObject
            {
                ["app_id"] = "one", ["app_name"] = "App One", ["app_description"] = "An app", ["app_url"] = "https://app.example",
                ["app_icon_url"] = "https://app.example/icon.png", ["app_version"] = "1",
            },
            ["actor_context"] = new JsonObject
            {
                ["actor_id"] = "agent:alpha", ["actor_name"] = "Alpha", ["actor_icon_url"] = "https://app.example/alpha.png",
            },
        },
    };

    private static IReadOnlyList<PendingRequest> Parse(string middle)
        => JsonSerializer.Deserialize<PendingRequestsResponse>(
            $"{{\"requests\":[{Card("good-1").ToJsonString()},{middle},{Card("good-2").ToJsonString()}]}}", Wire)!.Requests;

    // The queue a card stands in: the good cards on both sides are read and may be approved, and the card between them is
    // there, under its id, with a Deny.
    private static (CardBlock Block, string? Text) Between(string middle, string expectedId = "bad")
    {
        var queue = Parse(middle);
        Assert.Equal(3, queue.Count);
        var desk = new CapabilityCardDesk(new SeenPayloads(), new CapabilityCardTests.Unhurried());
        desk.Load(queue, Now);
        foreach (var (at, id) in new[] { (0, "good-1"), (2, "good-2") })
        {
            Assert.Equal(id, queue[at].RequestId);
            Assert.NotNull(desk.ViewOf(id));
            Assert.Equal(CardBlock.None, desk.Judge(queue[at]).Block);
        }
        Assert.Equal(expectedId, queue[1].RequestId);
        Assert.Equal(expectedId.Length > 0, CapabilityCardDesk.CanDeny(queue[1]));
        var judged = desk.Judge(queue[1]);
        if (judged.Block == CardBlock.Refused)
        {
            Assert.False(string.IsNullOrEmpty(judged.Text));
            Assert.Null(desk.ViewOf(expectedId));
        }
        return judged;
    }

    // ---- every field, dropped and null ------------------------------------------------------------------------------------

    private static IEnumerable<string> Paths(JsonNode node, string at = "")
    {
        switch (node)
        {
            case JsonObject o:
                foreach (var (name, value) in o)
                {
                    var path = at.Length == 0 ? name : $"{at}/{name}";
                    yield return path;
                    if (value is not null) foreach (var inner in Paths(value, path)) yield return inner;
                }
                break;
            case JsonArray a:
                for (var i = 0; i < a.Count; i++) yield return $"{at}/{i}";
                break;
        }
    }

    private static string Without(string json, string path, bool asNull)
    {
        var root = JsonNode.Parse(json)!;
        var names = path.Split('/');
        var node = root;
        foreach (var name in names[..^1]) node = node is JsonArray a ? a[int.Parse(name)]! : node[name]!;
        if (node is JsonArray list)
        {
            if (asNull) list[int.Parse(names[^1])] = null;
            else list.RemoveAt(int.Parse(names[^1]));
        }
        else if (asNull) node[names[^1]] = null;
        else ((JsonObject)node).Remove(names[^1]);
        return root.ToJsonString();
    }

    private static readonly HashSet<string> NeededOnTheWire = ["kind", "context", "context/cap_header_b64", "context/cap_payload_b64"];

    private static readonly HashSet<string> NeededInThePayload =
        ["iss", "sub", "aud", "iat", "nbf", "exp", "jti", "cap", "purpose", "cap/tier", "cap/registry_version"];

    public static IEnumerable<object[]> EveryField()
    {
        foreach (var asNull in new[] { false, true })
        {
            foreach (var path in Paths(Card("bad"))) yield return ["wire", path, asNull];
            foreach (var path in Paths(JsonNode.Parse(Header)!)) yield return ["header", path, asNull];
            foreach (var path in Paths(JsonNode.Parse(Payload)!)) yield return ["payload", path, asNull];
        }
    }

    [Fact]
    public void EveryFieldTheCardReads_IsTriedBelow()
    {
        var payload = Paths(JsonNode.Parse(Payload)!).ToList();
        foreach (var field in new[] { "max_uses", "parent_cap", "parent_profile", "cap/limits/per_session", "cap/scope/pairing_code" }
                     .Concat(NeededInThePayload))
        {
            Assert.Contains(field, payload);
        }
        Assert.Equal(12, JsonNode.Parse(Payload)!.AsObject().Count);
        Assert.Equal(8, JsonNode.Parse(Payload)!["cap"]!["scope"]!.AsObject().Count);
    }

    [Theory]
    [MemberData(nameof(EveryField))]
    public void AFieldThatIsMissing_IsThatCardsOwn(string where, string path, bool asNull)
    {
        var middle = where switch
        {
            "wire" => Without(Card("bad").ToJsonString(), path, asNull),
            "header" => Card("bad", header: Without(Header, path, asNull)).ToJsonString(),
            _ => Card("bad", payload: Without(Payload, path, asNull)).ToJsonString(),
        };
        var (block, _) = Between(middle, where == "wire" && path == "request_id" ? string.Empty : "bad");
        if (where == "wire" ? NeededOnTheWire.Contains(path) : where == "payload" ? NeededInThePayload.Contains(path) : path == "alg")
            Assert.Equal(CardBlock.Refused, block);
        // Null is not a value any signed field holds.
        if (where != "wire" && asNull) Assert.Equal(CardBlock.Refused, block);
    }

    // ---- what is not a card, and what is not text ----------------------------------------------------------------------------

    [Theory]
    [InlineData("null", "")]
    [InlineData("7", "")]
    [InlineData("\"text\"", "")]
    [InlineData("[]", "")]
    [InlineData("{}", "")]
    [InlineData("{\"request_id\":7}", "")]
    [InlineData("{\"request_id\":\"bad\"}", "bad")]
    [InlineData("{\"request_id\":\"bad\",\"kind\":\"single_sign\",\"context\":null}", "bad")]
    [InlineData("{\"request_id\":\"bad\",\"kind\":{},\"context\":{}}", "bad")]
    [InlineData("{\"request_id\":\"\\ud800\",\"kind\":\"single_sign\"}", "")]
    public void WhatIsNotACard_IsOneUnreadableCard(string middle, string id)
    {
        var (block, text) = Between(middle, id);
        Assert.Equal((CardBlock.Refused, CapabilityCardDesk.UnreadableText), (block, text));
        Assert.Equal(PendingRequestKind.Unreadable, Parse(middle)[1].Kind);
    }

    public static IEnumerable<object[]> NotText()
    {
        foreach (var path in new[]
                 {
                     "service", "secret", "context/operation_description", "context/child_argv0", "context/cap_agent_id",
                     "context/app_context", "context/app_context/app_name", "context/actor_context",
                     "context/actor_context/actor_name", "context/child_pid", "context/requested_at_unix",
                     "context/payload_hash_b64u", "context/cap_header_b64", "context/cap_payload_b64",
                 })
        {
            foreach (var value in new[] { "{\"a\":1}", "[1]", "true", "\"\\ud800\"", "1e400", "99999999999999999999" })
                yield return [path, value];
        }
    }

    [Theory]
    [MemberData(nameof(NotText))]
    public void AFieldOfAnotherKind_IsThatCardsOwn(string path, string value)
    {
        const string mark = "@@value@@";
        var root = Card("bad");
        JsonNode node = root;
        var names = path.Split('/');
        foreach (var name in names[..^1]) node = node[name]!;
        node[names[^1]] = mark;
        Between(root.ToJsonString().Replace($"\"{mark}\"", value));
    }

    [Theory]
    [InlineData("\"user_vault_revoke\"", "user_vault_revoke")]
    [InlineData("\"single_sign\"", "single_sign")]
    [InlineData("{}", "")]
    public void AnUnreadableCard_KeepsTheKindItNamed(string kind, string named)
    {
        var card = Parse("{\"request_id\":\"bad\",\"kind\":" + kind + ",\"service\":7,\"context\":{}}")[1];
        Assert.Equal((PendingRequestKind.Unreadable, named), (card.Kind, card.NamedKind));
    }

    [Theory]
    [InlineData("{\"requests\":null}")]
    [InlineData("{\"requests\":{}}")]
    [InlineData("{\"requests\":\"none\"}")]
    public void AQueueThatIsNotAList_IsNotReadAsAnEmptyOne(string body)
        => Assert.ThrowsAny<JsonException>(() => JsonSerializer.Deserialize<PendingRequestsResponse>(body, Wire));

    [Fact]
    public void TheQueueReadsAndWritesAsItDid()
    {
        var parsed = new PendingRequestsResponse(Parse(Card("between").ToJsonString()), "a.b.c");
        var again = JsonSerializer.Deserialize<PendingRequestsResponse>(JsonSerializer.Serialize(parsed, Wire), Wire)!;
        Assert.Equal(parsed.Requests.Select(r => r.RequestId), again.Requests.Select(r => r.RequestId));
        Assert.Equal(parsed.Requests[1].Context.CapPayloadB64, again.Requests[1].Context.CapPayloadB64);
        Assert.Equal("a.b.c", again.PendingJws);
    }

    [Fact]
    public void ACardWithNothingInIt_IsNotTheDesksToDropAQueueOver()
    {
        // What the list reader never hands it, the desk still refuses alone.
        var desk = new CapabilityCardDesk(new SeenPayloads(), new CapabilityCardTests.Unhurried());
        var good = Parse(Card("between").ToJsonString())[0];
        var empty = new PendingRequest(null!, PendingRequestKind.SingleSign, null!, null!, null!);
        var capability = new PendingRequest("no-context", PendingRequestKind.CapabilityRequest, "s", "k", null!);
        desk.Load([empty, good, capability], Now);
        Assert.Equal(CardBlock.None, desk.Judge(good).Block);
        Assert.Equal(CardBlock.Refused, desk.Judge(empty).Block);
        Assert.Equal(CardBlock.Refused, desk.Judge(capability).Block);
    }

    [Fact]
    public void CardsAreNamedApart_EvenWhenAQueueRepeatsAnId()
    {
        var twin = Parse(Card("good-1").ToJsonString());
        Assert.Equal(new[] { ("good-1", 1), ("good-1", 2), ("good-2", 1) }, CapabilityCardDesk.Keyed(twin).Select(c => c.Key));
        Assert.Equal(new[] { ("good-2", 1), ("good-1", 1) }, CapabilityCardDesk.Keyed(new[] { twin[2], twin[0] }).Select(c => c.Key));
        // An id that reads like another's second is no one's name but its own.
        foreach (var ids in new[] { new[] { "x", "x", "x#2" }, new[] { "", "", "#2" }, new[] { "x#2", "x", "x" } })
            Assert.Equal(3, CapabilityCardDesk.Keyed(ids.Select(id => PendingRequest.Unreadable(id))).Select(c => c.Key).Distinct().Count());
    }

    // ---- drawn or moved a moment ago ------------------------------------------------------------------------------------------

    private sealed class Clock : TimeProvider
    {
        private long _ticks;
        public override long TimestampFrequency => TimeSpan.TicksPerSecond;
        public override long GetTimestamp() => _ticks;
        public void Pass(int milliseconds) => _ticks += milliseconds * TimeSpan.TicksPerMillisecond;
    }

    private static (CapabilityCardDesk Desk, Clock Clock, PendingRequest A, PendingRequest B) Two()
    {
        var clock = new Clock();
        var cards = Parse(Card("between").ToJsonString());
        return (new CapabilityCardDesk(new SeenPayloads(), clock), clock, cards[0], cards[1]);
    }

    [Fact]
    public void ACardJustDrawn_TakesNoApproveForASecond()
    {
        var (desk, clock, a, _) = Two();
        desk.Load([a], Now);
        Assert.Equal((CardBlock.Held, null), desk.Judge(a));
        clock.Pass(CapabilityCardDesk.HoldMilliseconds - 1);
        Assert.Equal(CardBlock.Held, desk.Judge(a).Block);
        clock.Pass(1);
        Assert.Equal(CardBlock.None, desk.Judge(a).Block);
    }

    [Fact]
    public void ACardThatKeepsItsPlace_IsNotHeldAgain_AndOneThatMovesIs()
    {
        var (desk, clock, a, b) = Two();
        desk.Load([a], Now);
        clock.Pass(1000);
        desk.Load([a, b], Now);
        Assert.Equal(CardBlock.None, desk.Judge(a).Block);
        Assert.Equal(CardBlock.Held, desk.Judge(b).Block);
        clock.Pass(1000);
        Assert.Equal(CardBlock.None, desk.Judge(b).Block);

        desk.Load([b], Now);   // the card above it left: it came up under the finger
        Assert.Equal(CardBlock.Held, desk.Judge(b).Block);
        clock.Pass(1000);
        Assert.Equal(CardBlock.None, desk.Judge(b).Block);
    }

    [Fact]
    public void ANewCardInAnOldPlace_IsHeld()
    {
        var (desk, clock, a, b) = Two();
        desk.Load([a], Now);
        clock.Pass(5000);
        desk.Load([b], Now);
        Assert.Equal(CardBlock.Held, desk.Judge(b).Block);
    }

    [Fact]
    public void ReadingOn_HoldsTheCardAndTheOnesBelowIt()
    {
        var clock = new Clock();
        var longPurpose = Payload.Replace("every field", new string('a', 300));
        var queue = Parse(Card("long", payload: longPurpose).ToJsonString());
        var desk = new CapabilityCardDesk(new SeenPayloads(), clock);
        desk.Load(queue, Now);
        clock.Pass(1000);
        Assert.Equal(CardBlock.Unread, desk.Judge(queue[1]).Block);
        desk.ReadOn("long");
        Assert.Equal(CardBlock.None, desk.Judge(queue[0]).Block);
        Assert.Equal(CardBlock.Held, desk.Judge(queue[1]).Block);
        Assert.Equal(CardBlock.Held, desk.Judge(queue[2]).Block);
        clock.Pass(1000);
        Assert.Equal(CardBlock.None, desk.Judge(queue[1]).Block);

        desk.ReadOn("long");   // nothing was added: nothing moved
        Assert.Equal(CardBlock.None, desk.Judge(queue[2]).Block);
        desk.HoldFrom();       // something above them all came or went
        Assert.All(queue, r => Assert.Equal(CardBlock.Held, desk.Judge(r).Block));
    }

    [Fact]
    public void EveryKindOfCard_IsHeld()
    {
        foreach (var kind in new[] { PendingRequestKind.SingleSign, PendingRequestKind.TotpProvision, PendingRequestKind.EthSign,
                                     PendingRequestKind.UserVaultGrant, PendingRequestKind.UserVaultRevoke })
        {
            var clock = new Clock();
            var desk = new CapabilityCardDesk(new SeenPayloads(), clock);
            var req = new PendingRequest("r", kind, "s", "k", new PendingRequestContext(0, "x", 1, "d", PayloadHashB64u: "aGFzaA"));
            desk.Load([req], Now);
            Assert.Equal(CardBlock.Held, desk.Judge(req).Block);
            clock.Pass(1000);
            Assert.Equal(CardBlock.None, desk.Judge(req).Block);
        }
    }

    // ---- drawn ------------------------------------------------------------------------------------------------------------------

    private static async Task<string> Draw<T>(IDictionary<string, object?> parameters) where T : IComponent
    {
        await using var services = new ServiceCollection().BuildServiceProvider();
        await using var renderer = new HtmlRenderer(services, NullLoggerFactory.Instance);
        return await renderer.Dispatcher.InvokeAsync(async () =>
            (await renderer.RenderComponentAsync<T>(ParameterView.FromDictionary(parameters))).ToHtmlString());
    }

    [Fact]
    public async Task TextACardWasSent_IsDrawnVisible_InItsOwnDirection_AndKeptToItself()
    {
        Assert.Equal("<bdi dir=\"auto\">plain</bdi>", (await Draw<CardText>(new Dictionary<string, object?> { ["Value"] = "plain" })).Trim());
        var drawn = await Draw<CardText>(new Dictionary<string, object?> { ["Value"] = "a" + (char)0x202E + "b" });
        Assert.Contains("U+202E", System.Net.WebUtility.HtmlDecode(drawn));
        Assert.Equal("<bdi dir=\"auto\"></bdi>", (await Draw<CardText>(new Dictionary<string, object?> { ["Value"] = null })).Trim());
    }

    [Fact]
    public async Task ABalancedIsolate_IsDrawnAsOne_InProseAlone()
    {
        var text = "publish " + (char)0x2068 + "title" + (char)0x2069 + " now";
        var prose = System.Net.WebUtility.HtmlDecode(await Draw<CardText>(new Dictionary<string, object?> { ["Value"] = text, ["Prose"] = true }));
        Assert.Contains(text, prose);
        var value = System.Net.WebUtility.HtmlDecode(await Draw<CardText>(new Dictionary<string, object?> { ["Value"] = text }));
        Assert.Contains("U+2068", value);
    }

    [Fact]
    public async Task ACardThatCannotBeDrawn_IsRefusedAlone()
    {
        var html = await Draw<Three>(new Dictionary<string, object?>());
        Assert.Equal("onerefusedthree", html);
    }

    private sealed class Three : ComponentBase
    {
        protected override void BuildRenderTree(RenderTreeBuilder builder)
        {
            foreach (var (name, n) in new[] { "one", "two", "three" }.Select((name, n) => (name, n)))
            {
                builder.OpenComponent<CardBoundary>(n);
                builder.AddComponentParameter(1, "ChildContent", (RenderFragment)(b =>
                    b.AddContent(0, name == "two" ? throw new InvalidOperationException("made up") : name)));
                builder.AddComponentParameter(2, "ErrorContent", (RenderFragment<Exception>)(_ => b => b.AddContent(0, "refused")));
                builder.CloseComponent();
            }
        }
    }
}
