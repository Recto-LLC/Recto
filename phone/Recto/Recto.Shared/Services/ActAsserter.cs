using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Recto.Shared.Common;
using Recto.Shared.Protocol.V04;

namespace Recto.Shared.Services;

/// <summary>
/// The App Attest assertion an iPhone adds to the acts it signs (hard rule 14.8), when the bootloader it is paired with
/// keeps its App Attest key. It is an addition: made after the person has approved, it never prompts, and an act whose
/// assertion could not be made in <see cref="Limit"/> goes without one. Whether the platform asks its vendor over the
/// network to make one is not stated by the vendor, so nothing here assumes it does or does not.
/// </summary>
public sealed class ActAsserter
{
    public const string Prefix = "recto-assert-v1";

    /// <summary>How long one act waits for its turn and its assertion together.</summary>
    public static readonly TimeSpan Limit = TimeSpan.FromSeconds(3);

    private readonly IPairingStateService _pairing;
    private readonly IEnclaveKeyService _keys;
    private readonly TimeSpan _limit;

    // The bootloader takes a counter only once and only upward, so the acts of this phone are made and sent one at a time.
    private readonly SemaphoreSlim _turn = new(1, 1);
    private readonly ConcurrentDictionary<string, (string PayloadHash, long IssuedAt)> _cards = new(StringComparer.Ordinal);

    public ActAsserter(IPairingStateService pairing, IEnclaveKeyService keys, TimeSpan? limit = null)
        => (_pairing, _keys, _limit) = (pairing, keys, limit ?? Limit);

    /// <summary>What an assertion is over; the bootloader computes the same (device_evidence.assertion_client_data_hash).</summary>
    public static byte[] ClientDataHash(string act, string ident, byte[] payload, string fresh)
        => SHA256.HashData(Encoding.UTF8.GetBytes($"{Prefix}|{act}|{ident}|{B64u(SHA256.HashData(payload))}|{fresh}"));

    /// <summary>Keeps what each card on the queue names, and only those: an answer is bound to its card's own words.</summary>
    public void SawQueue(IReadOnlyList<PendingRequest> cards)
    {
        var now = new HashSet<string>(StringComparer.Ordinal);
        foreach (var card in cards)
        {
            if (card?.RequestId is not { } id || card.Context is not { } context) continue;
            now.Add(id);
            _cards[id] = (context.PayloadHashB64u ?? string.Empty, context.RequestedAtUnix);
        }
        foreach (var id in _cards.Keys)
        {
            if (!now.Contains(id)) _cards.TryRemove(id, out _);
        }
    }

    /// <summary>The client data of a card's answer, or null for a card this phone has not read.</summary>
    public byte[]? ForCard(string requestId, string decision)
        => _cards.TryGetValue(requestId, out var card)
            ? ClientDataHash(
                string.Equals(decision, RespondDecision.Approved, StringComparison.Ordinal) ? "approve" : "deny",
                requestId, FromB64u(card.PayloadHash), card.IssuedAt.ToString(CultureInfo.InvariantCulture))
            : null;

    private int _strangers;

    /// <summary>
    /// What a bootloader answered an asserted act. One that says, three times running, that the assertion is not its kept
    /// key's holds another key or none (an answer this phone never got): the key is let go here, so the next act carries
    /// none instead of a wrong one. A count behind its own is a race, and lets nothing go.
    /// </summary>
    public async Task HeardAsync(string? assertion, Error? error)
    {
        if (assertion is null) return;
        if (error is null || !error.Message.StartsWith("HTTP 403: approval_evidence_invalid", StringComparison.Ordinal)
            || !error.Message.Contains("(assertion_signature)", StringComparison.Ordinal))
        {
            Interlocked.Exchange(ref _strangers, 0);
            return;
        }
        if (Interlocked.Increment(ref _strangers) < 3) return;
        Interlocked.Exchange(ref _strangers, 0);
        if (await BootloaderIdAsync().ConfigureAwait(false) is { } id)
            await _pairing.SetAppAttestKeyIdAsync(id, null, CancellationToken.None).ConfigureAwait(false);
    }

    /// <summary>Sends one act, with its assertion when there is a kept key and one could be made in time.</summary>
    public async Task<T> SendAsync<T>(byte[]? clientDataHash, Func<string?, Task<T>> send)
    {
        var keyId = clientDataHash is null ? null : await KeptKeyAsync().ConfigureAwait(false);
        if (keyId is null) return await send(null).ConfigureAwait(false);

        using var limit = new CancellationTokenSource(_limit);
        var mine = false;
        try
        {
            string? assertion = null;
            try
            {
                await _turn.WaitAsync(limit.Token).ConfigureAwait(false);
                mine = true;
                assertion = await AssertAsync(keyId, clientDataHash!, limit.Token).ConfigureAwait(false);
            }
            catch (Exception)
            {
                // Not made in time, or not at all: the act goes without it, and the bootloader's policy answers.
            }
            return await send(assertion).ConfigureAwait(false);
        }
        finally
        {
            if (mine) _turn.Release();
        }
    }

    private async Task<string?> AssertAsync(string keyId, byte[] clientDataHash, CancellationToken ct)
    {
        var made = await Task.Run(() => _keys.GetDeviceAssertionAsync(keyId, clientDataHash, ct), ct)
            .WaitAsync(ct).ConfigureAwait(false);
        if (made.IsSuccess) return made.Value;
        // The platform says the key is gone (a reinstall, a restore): it is not asked for again.
        if (made.Error.Method == DeviceEvidence.KeyGoneCode && await BootloaderIdAsync().ConfigureAwait(false) is { } id)
            await _pairing.SetAppAttestKeyIdAsync(id, null, CancellationToken.None).ConfigureAwait(false);
        return null;
    }

    private async Task<string?> KeptKeyAsync()
        => await BootloaderIdAsync().ConfigureAwait(false) is { } id
            ? await _pairing.GetAppAttestKeyIdAsync(id, CancellationToken.None).ConfigureAwait(false)
            : null;

    /// <summary>The id this phone's pairing has at its bootloader, or null.</summary>
    public async Task<string?> PhoneIdAsync() => (await PairingAsync().ConfigureAwait(false))?.PhoneId;

    private async Task<string?> BootloaderIdAsync() => (await PairingAsync().ConfigureAwait(false))?.BootloaderId;

    private async Task<Recto.Shared.Models.PairingState?> PairingAsync()
    {
        try
        {
            var current = await _pairing.GetCurrentAsync(CancellationToken.None).ConfigureAwait(false);
            return current.IsSuccess ? current.Value : null;
        }
        catch (Exception)
        {
            return null;
        }
    }

    private static string B64u(byte[] raw) => Convert.ToBase64String(raw).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static byte[] FromB64u(string text)
    {
        try
        {
            var s = text.Replace('-', '+').Replace('_', '/');
            return Convert.FromBase64String(s + new string('=', (4 - s.Length % 4) % 4));
        }
        catch (FormatException)
        {
            return Array.Empty<byte>();
        }
    }
}
