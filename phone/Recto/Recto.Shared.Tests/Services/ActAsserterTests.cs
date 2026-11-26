using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging.Abstractions;
using Recto.Shared.Common;
using Recto.Shared.Models;
using Recto.Shared.Protocol.V04;
using Recto.Shared.Services;
using Recto.Shared.Tests.Capability;
using Xunit;

namespace Recto.Shared.Tests.Services;

/// <summary>Hard rule 14.8, after admission: the assertion a phone with a kept App Attest key adds to its signed acts.</summary>
public class ActAsserterTests
{
    private const string Url = "https://b.example";

    private sealed class Pairing : IPairingStateService
    {
        public string? Kept = "kid";
        public bool Paired = true;
        public Task<Result<PairingState?>> GetCurrentAsync(CancellationToken ct) => Task.FromResult(Result.Success<PairingState?>(
            Paired ? new PairingState("pk_me", "boot-1", Url, Array.Empty<ManagedSecretRef>(), DateTimeOffset.UnixEpoch) : null));
        public Task<Result> SaveAsync(PairingState state, CancellationToken ct) => throw new NotSupportedException();
        public Task<Result> ClearAsync(CancellationToken ct) => throw new NotSupportedException();
        public Task<Result<string>> GetOrCreatePhoneIdAsync(CancellationToken ct) => throw new NotSupportedException();
        public Task<string?> GetAppAttestKeyIdAsync(string bootloaderId, CancellationToken ct)
            => Task.FromResult(bootloaderId == "boot-1" ? Kept : null);
        public Task SetAppAttestKeyIdAsync(string bootloaderId, string? keyId, CancellationToken ct)
        {
            Kept = keyId;
            return Task.CompletedTask;
        }
    }

    private sealed class Keys : IEnclaveKeyService
    {
        public Func<string, byte[], CancellationToken, Task<Result<string?>>> Make = (k, h, _)
            => Task.FromResult(Result.Success<string?>($"{k}:{Convert.ToHexStringLower(h)}"));
        public int Asked;
        public string Algorithm => "ecdsa-p256";
        public Task<Result<string?>> GetDeviceAssertionAsync(string appAttestKeyId, byte[] clientDataHash, CancellationToken ct)
        {
            Interlocked.Increment(ref Asked);
            return Make(appAttestKeyId, clientDataHash, ct);
        }
        // Nothing here prompts: the identity key is never reached.
        public Task<Result<EnclavePublicKey>> GenerateAsync(string a, CancellationToken ct) => throw new InvalidOperationException("prompt");
        public Task<Result<bool>> KeyExistsAsync(string a, CancellationToken ct) => throw new InvalidOperationException("prompt");
        public Task<Result<EnclavePublicKey>> GetPublicKeyAsync(string a, CancellationToken ct) => throw new InvalidOperationException("prompt");
        public Task<Result<byte[]>> SignAsync(string a, byte[] m, CancellationToken ct) => throw new InvalidOperationException("prompt");
        public Task<Result> DeleteAsync(string a, CancellationToken ct) => throw new InvalidOperationException("prompt");
    }

    private sealed class ReadSigner : IReadSigner
    {
        public Task<PollSignatureHeaders?> SignReadAsync(string phoneId, string path, CancellationToken ct)
            => Task.FromResult<PollSignatureHeaders?>(new PollSignatureHeaders("sig", 1700000000));
    }

    private sealed class Wire(Func<HttpRequestMessage, string, HttpResponseMessage> answer) : HttpMessageHandler
    {
        public readonly List<(string Path, JsonElement Body)> Sent = new();
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage r, CancellationToken ct)
        {
            var body = r.Content is null ? "{}" : await r.Content.ReadAsStringAsync(ct);
            lock (Sent) Sent.Add((r.RequestUri!.AbsolutePath, JsonDocument.Parse(body).RootElement.Clone()));
            return answer(r, body);
        }
    }

    private static HttpResponseMessage Json(string body, HttpStatusCode status = HttpStatusCode.OK)
        => new(status) { Content = new StringContent(body, Encoding.UTF8, "application/json") };

    private const string Queue = "{\"requests\":[{\"request_id\":\"r1\",\"kind\":\"single_sign\",\"service\":\"s\",\"secret\":\"k\","
        + "\"context\":{\"child_pid\":1,\"child_argv0\":\"x\",\"requested_at_unix\":1700000123,\"operation_description\":\"d\",\"payload_hash_b64u\":\"cHBw\"}}]}";

    private static (BootloaderClient Client, Wire Wire, Pairing Pairing, Keys Keys, ActAsserter Acts) Build(
        Func<HttpRequestMessage, string, HttpResponseMessage>? answer = null, TimeSpan? limit = null)
    {
        var wire = new Wire(answer ?? ((r, _) => Json(r.RequestUri!.AbsolutePath == "/v0.4/pending" ? Queue : "{\"resolved\":true}")));
        var (pairing, keys) = (new Pairing(), new Keys());
        var acts = new ActAsserter(pairing, keys, limit ?? TimeSpan.FromSeconds(3));
        return (new BootloaderClient(new HttpClient(wire), NullLogger<BootloaderClient>.Instance, new ReadSigner(), acts), wire, pairing, keys, acts);
    }

    private static RespondRequest Approve(string decision = "approved") => new("pk_me", decision, SignatureB64u: "sig");

    private static string? Assertion((string Path, JsonElement Body) sent)
        => sent.Body.TryGetProperty("device_assertion", out var a) ? a.GetString() : null;

    private static string Over(string act, string ident, byte[] payload, string fresh)
        => "kid:" + Convert.ToHexStringLower(ActAsserter.ClientDataHash(act, ident, payload, fresh));

    // Pinned against recto.bootloader.device_evidence.assertion_client_data_hash("approve", "r1", b"ppp", "1700000123").
    [Fact]
    public void TheBinding_IsTheBootloadersOwn()
        => Assert.Equal("3c3dfc4d2ea9a1e0b9289f4ab58ab388eac7ac9b6abe266688cf63193e3a216b",
            Convert.ToHexStringLower(ActAsserter.ClientDataHash("approve", "r1", Encoding.ASCII.GetBytes("ppp"), "1700000123")));

    [Theory]
    [InlineData("approved", "approve")]
    [InlineData("denied", "deny")]
    public async Task AnAnswer_IsBoundToItsDecision_ItsCard_AndWhatTheCardNames(string decision, string act)
    {
        var (client, wire, _, _, _) = Build();
        await client.GetPendingAsync(Url, "pk_me", CancellationToken.None);
        await client.RespondAsync(Url, "r1", Approve(decision), CancellationToken.None);
        Assert.Equal(Over(act, "r1", Encoding.ASCII.GetBytes("ppp"), "1700000123"), Assertion(wire.Sent[^1]));
    }

    [Fact]
    public async Task TheOtherActs_CarryTheirs()
    {
        var (client, wire, _, _, _) = Build((r, _) => Json("{}"));
        await client.RevokePhoneAsync(Url, new RevokeRequest("pk_me", "pk_x", "chal", "sig"), CancellationToken.None);
        Assert.Equal(Over("revoke", "chal", Encoding.ASCII.GetBytes("chal:pk_x"), "chal"), Assertion(wire.Sent[^1]));
        await client.UpdatePushTokenAsync(Url, new PushTokenUpdateRequest("pk_me", "tok", "apns"), CancellationToken.None);
        Assert.Equal(Over("push-token", "pk_me", Encoding.UTF8.GetBytes("tok|apns"), "1700000000"), Assertion(wire.Sent[^1]));
        var record = new UserVaultSignedRecord(new Dictionary<string, object?>(), "SIG");
        await client.PostUserVaultGrantAsync(Url, record, CancellationToken.None);
        Assert.Equal(Over("vault-grant", "pk_me", Encoding.UTF8.GetBytes("SIG"), ""), Assertion(wire.Sent[^1]));
        await client.PostUserVaultRevokeAsync(Url, record, CancellationToken.None);
        Assert.Equal(Over("vault-revoke", "pk_me", Encoding.UTF8.GetBytes("SIG"), ""), Assertion(wire.Sent[^1]));
        await client.PostUserVaultRevokeKeyAsync(Url, record, CancellationToken.None);
        Assert.Equal(Over("vault-revoke-key", "pk_me", Encoding.UTF8.GetBytes("SIG"), ""), Assertion(wire.Sent[^1]));
        await client.DenyUserVaultGrantRequestAsync(Url, "pk_me", "r9", CancellationToken.None);
        Assert.Equal(Over("vault-deny", "r9", Array.Empty<byte>(), "1700000000"), Assertion(wire.Sent[^1]));
        var pair = new DevicesPairRequest("https://c.example", new DevicesPairRecord("boot-1", "sub", "pub", "CODE", 99), "jws");
        await client.PairDeviceAsync(Url, pair, CancellationToken.None);
        Assert.Equal(Over("pair", "CODE", Encoding.UTF8.GetBytes("jws"), "99"), Assertion(wire.Sent[^1]));
    }

    [Fact]
    public async Task AReadIsNeverAsserted()
    {
        var (client, wire, _, keys, _) = Build();
        await client.GetPendingAsync(Url, "pk_me", CancellationToken.None);
        await client.ListRegisteredPhonesAsync(Url, "pk_me", CancellationToken.None);
        Assert.Equal(0, keys.Asked);
        Assert.All(wire.Sent, s => Assert.Null(Assertion(s)));
    }

    [Theory]
    [InlineData("no kept key")]
    [InlineData("not paired")]
    [InlineData("a card never read")]
    [InlineData("the platform fails")]
    [InlineData("the platform throws")]
    [InlineData("no App Attest here")]
    public async Task AnActGoes_WithoutOne_WhenThereIsNoneToMake(string why)
    {
        var (client, wire, pairing, keys, _) = Build();
        if (why != "a card never read") await client.GetPendingAsync(Url, "pk_me", CancellationToken.None);
        if (why == "no kept key") pairing.Kept = null;
        if (why == "not paired") pairing.Paired = false;
        if (why == "the platform fails") keys.Make = (_, _, _) => Task.FromResult(Result.Failure<string?>(Error.Failure("x")));
        if (why == "the platform throws") keys.Make = (_, _, _) => throw new InvalidOperationException("x");
        if (why == "no App Attest here") keys.Make = (_, _, _) => Task.FromResult(Result.Success<string?>(null));
        var result = await client.RespondAsync(Url, "r1", Approve(), CancellationToken.None);
        Assert.True(result.IsSuccess);
        Assert.False(wire.Sent[^1].Body.TryGetProperty("device_assertion", out _));
        Assert.Equal(why == "no kept key" ? null : "kid", pairing.Kept);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task AnAssertionThatTakesTooLong_IsLeftBehind(bool deaf)
    {
        var (client, wire, _, keys, _) = Build(limit: TimeSpan.FromMilliseconds(200));
        await client.GetPendingAsync(Url, "pk_me", CancellationToken.None);
        keys.Make = async (_, _, ct) =>
        {
            await Task.Delay(30_000, deaf ? CancellationToken.None : ct);
            return Result.Success<string?>("late");
        };
        var started = DateTime.UtcNow;
        Assert.True((await client.RespondAsync(Url, "r1", Approve(), CancellationToken.None)).IsSuccess);
        Assert.True(DateTime.UtcNow - started < TimeSpan.FromSeconds(5));
        Assert.Null(Assertion(wire.Sent[^1]));
        Assert.Equal(TimeSpan.FromSeconds(3), ActAsserter.Limit);
    }

    [Fact]
    public async Task ActsAreSentOneAtATime_SoTheirCountsArriveInOrder()
    {
        var order = new List<string>();
        var (client, _, _, keys, acts) = Build();
        var counter = 0;
        keys.Make = (_, _, _) => Task.FromResult(Result.Success<string?>($"{Interlocked.Increment(ref counter)}"));
        await Task.WhenAll(Enumerable.Range(0, 12).Select(i => Task.Run(() => acts.SendAsync(new byte[32], async a =>
        {
            await Task.Delay(5);
            lock (order) order.Add(a!);
            return true;
        }))));
        Assert.Equal(Enumerable.Range(1, 12).Select(i => i.ToString()), order);
        Assert.NotNull(client);
    }

    [Fact]
    public async Task AKeyThePlatformLost_IsNotAskedForAgain()
    {
        var (client, wire, pairing, keys, _) = Build();
        await client.GetPendingAsync(Url, "pk_me", CancellationToken.None);
        keys.Make = (_, _, _) => Task.FromResult(Result.Failure<string?>(new Error(DeviceEvidence.KeyGoneCode, "gone", "")));
        Assert.True((await client.RespondAsync(Url, "r1", Approve(), CancellationToken.None)).IsSuccess);
        Assert.Null(pairing.Kept);
        Assert.Null(Assertion(wire.Sent[^1]));
        await client.RespondAsync(Url, "r1", Approve(), CancellationToken.None);
        Assert.Equal(1, keys.Asked);
    }

    [Fact]
    public async Task AKeyTheBootloaderNoLongerKeeps_IsLetGoAfterThreeRefusals_AndACountIsNot()
    {
        var reason = "assertion_signature";
        var (client, _, pairing, _, _) = Build((r, _) => r.RequestUri!.AbsolutePath == "/v0.4/pending" ? Json(Queue)
            : Json($"{{\"error\":\"approval_evidence_invalid\",\"reason\":\"{reason}\",\"detail\":\"this phone's assertion does not verify ({reason}); x\"}}", HttpStatusCode.Forbidden));
        await client.GetPendingAsync(Url, "pk_me", CancellationToken.None);
        reason = "counter";
        for (var i = 0; i < 5; i++) await client.RespondAsync(Url, "r1", Approve(), CancellationToken.None);
        Assert.Equal("kid", pairing.Kept);
        reason = "assertion_signature";
        for (var i = 0; i < 2; i++) await client.RespondAsync(Url, "r1", Approve(), CancellationToken.None);
        Assert.Equal("kid", pairing.Kept);
        await client.RespondAsync(Url, "r1", Approve(), CancellationToken.None);
        Assert.Null(pairing.Kept);
    }

    [Fact]
    public void ThePhoneKeepsTheKey_ExactlyWhenTheRegistryDoes_AndBeforeThePairingIsSaved()
    {
        var pair = ProfileSigningInputTests.MethodBody(ProfileSigningInputTests.HomePage(), "HandlePairClick");
        var kept = pair.IndexOf("if (registration.AppAttestKept && request.DeviceEvidence?.KeyId is { } appAttestKeyId)", StringComparison.Ordinal);
        Assert.True(kept > 0 && kept < pair.IndexOf("Pairing.SaveAsync(pairedState", StringComparison.Ordinal));
        Assert.Single(System.Text.RegularExpressions.Regex.Matches(pair, "SetAppAttestKeyIdAsync"));
        var answer = JsonSerializer.Deserialize<RegistrationResponse>(
            "{\"registered\":true,\"phone_id\":\"p\",\"bootloader_id\":\"b\",\"managed_secrets\":[]}")!;
        Assert.False(answer.AppAttestKept, "an older bootloader keeps none");
    }
}
