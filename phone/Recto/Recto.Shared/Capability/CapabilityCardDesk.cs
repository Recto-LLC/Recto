using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Recto.Shared.Protocol.V04;

namespace Recto.Shared.Capability;

/// <summary>
/// The signed payload each request id was first shown with, for as long as
/// the app runs. Digests only, in memory only (hard rule 15.y).
/// </summary>
public sealed class SeenPayloads
{
    /// <summary>Ids no longer on the queue are forgotten, oldest first, past this many.</summary>
    public const int Capacity = 4096;

    private sealed class Entry
    {
        public required string Digest { get; init; }
        public bool Changed { get; set; }
    }

    private readonly object _gate = new();
    private readonly Dictionary<string, Entry> _byId = new(StringComparer.Ordinal);
    private readonly Queue<string> _order = new();

    /// <summary>
    /// Records <paramref name="digest"/> for an id seen for the first time.
    /// True when it is what the id was first shown with and the id never
    /// carried another; an id that did stays changed.
    /// </summary>
    public bool Unchanged(string requestId, string digest)
    {
        lock (_gate)
        {
            if (!_byId.TryGetValue(requestId, out var entry))
            {
                _byId[requestId] = new Entry { Digest = digest };
                _order.Enqueue(requestId);
                return true;
            }
            if (entry.Digest != digest) entry.Changed = true;
            return !entry.Changed;
        }
    }

    /// <summary>Forgets the oldest ids past <see cref="Capacity"/>, never one that is on the queue now.</summary>
    public void Trim(IReadOnlySet<string> onTheQueue)
    {
        lock (_gate)
        {
            for (var left = _order.Count; left > 0 && _byId.Count > Capacity; left--)
            {
                var id = _order.Dequeue();
                if (onTheQueue.Contains(id)) _order.Enqueue(id);
                else _byId.Remove(id);
            }
        }
    }
}

/// <summary>Why a card takes no Approve now.</summary>
public enum CardBlock
{
    None,

    /// <summary>The card was drawn, or moved to another place, a moment ago.</summary>
    Held,

    /// <summary>Part of the signed purpose has not been brought into view yet.</summary>
    Unread,

    /// <summary>The card cannot be shown whole, or its payload changed under its id.</summary>
    Refused,
}

/// <summary>
/// What the phone holds about the cards on its queue: each capability card's
/// view, how much of its purpose has been shown, when it came to where it
/// stands, and whether it may be approved. The page renders from it and asks
/// it again at the tap. A card it cannot read is one refused card, never a
/// queue that cannot be read.
/// </summary>
public sealed class CapabilityCardDesk
{
    /// <summary>How long a card that was drawn or moved takes no Approve: a tap meant for what stood there is not one for it.</summary>
    public const int HoldMilliseconds = 1000;

    public const string ChangedText =
        "This request changed after it was first shown, so it cannot be approved. Nothing was signed. "
        + "Deny it, and ask for it again.";

    public const string GoneText = "This request is no longer waiting for an answer. Nothing was signed.";

    public const string UnreadText = "Read the whole request to approve it.";

    public const string UnreadableText = "This request cannot be read by this app, so it cannot be approved.";

    public const string RefusedPrefix = "This card cannot be shown whole, so it cannot be approved: ";

    private sealed record Card(string? Digest, CapabilityAuditView? View, string? Refusal);

    private readonly record struct Place(int Index, long Since);

    private readonly SeenPayloads _seen;
    private readonly TimeProvider _time;
    private readonly object _gate = new();
    private readonly Dictionary<string, Card> _cards = new(StringComparer.Ordinal);
    private readonly Dictionary<string, int> _partsShown = new(StringComparer.Ordinal);
    private readonly Dictionary<string, Place> _places = new(StringComparer.Ordinal);

    public CapabilityCardDesk(SeenPayloads seen, TimeProvider? time = null)
    {
        _seen = seen;
        _time = time ?? TimeProvider.System;
    }

    /// <summary>
    /// Reads the queue as it stands, in the order it is drawn. Reading
    /// progress survives a reload of the same payload and nothing else; a
    /// card that keeps its place keeps its time there.
    /// </summary>
    public void Load(IReadOnlyCollection<PendingRequest> pending, DateTimeOffset now)
    {
        lock (_gate)
        {
            var before = new Dictionary<string, Card>(_cards, StringComparer.Ordinal);
            var stood = new Dictionary<string, Place>(_places, StringComparer.Ordinal);
            _cards.Clear();
            _places.Clear();
            var index = 0;
            foreach (var req in pending)
            {
                var id = IdOf(req);
                _places[id] = stood.TryGetValue(id, out var place) && place.Index == index
                    ? place
                    : new Place(index, _time.GetTimestamp());
                index++;
                var card = Read(req, now);
                if (card.Digest is not null) _seen.Unchanged(id, card.Digest);
                if (req?.Kind != PendingRequestKind.CapabilityRequest) continue;
                _cards[id] = card;
                if (!before.TryGetValue(id, out var old) || old.Digest != card.Digest) _partsShown[id] = 1;
            }
            foreach (var id in _partsShown.Keys.Except(_cards.Keys).ToList()) _partsShown.Remove(id);
        }
        _seen.Trim(pending.Select(IdOf).ToHashSet(StringComparer.Ordinal));
    }

    // Whatever is wrong with one card is that card's refusal.
    private static Card Read(PendingRequest req, DateTimeOffset now)
    {
        var digest = TryDigest(req);
        if (digest is null || req.Kind != PendingRequestKind.CapabilityRequest) return new Card(digest, null, null);
        try
        {
            var claims = CapabilityCardPayload.TryRead(req.Context.CapHeaderB64, req.Context.CapPayloadB64, out var refusal);
            return claims is null
                ? new Card(digest, null, RefusedPrefix + refusal)
                : new Card(digest, CapabilityAuditView.From(claims, now), null);
        }
        catch (Exception ex) when (ex is ArgumentOutOfRangeException or OverflowException)
        {
            return new Card(digest, null, RefusedPrefix + "it names a time this app cannot show.");
        }
        catch (Exception ex)
        {
            return new Card(digest, null, RefusedPrefix + $"it could not be read ({ex.GetType().Name}).");
        }
    }

    private static string IdOf(PendingRequest? req) => req?.RequestId ?? string.Empty;

    private static string? TryDigest(PendingRequest? req)
    {
        try
        {
            return req is null ? null : DigestOf(req);
        }
        catch (Exception)
        {
            return null;
        }
    }

    /// <summary>
    /// The cards with a name for each that no other card on the page has, so
    /// what a person opened or began on one card stays that card's wherever it
    /// moves. The name is the request id and which card of that id it is, two
    /// values and never one text, so no id a queue carries is another's name.
    /// </summary>
    public static IReadOnlyList<(PendingRequest Request, (string Id, int Nth) Key)> Keyed(IEnumerable<PendingRequest> cards)
    {
        var count = new Dictionary<string, int>(StringComparer.Ordinal);
        return cards.Select(req =>
        {
            var id = IdOf(req);
            return (req, (id, count[id] = count.GetValueOrDefault(id) + 1));
        }).ToList();
    }

    /// <summary>Whether a denial can name this request: it can unless the request carries no id.</summary>
    public static bool CanDeny(PendingRequest req) => IdOf(req).Length > 0;

    public CapabilityAuditView? ViewOf(string requestId)
    {
        lock (_gate) return _cards.GetValueOrDefault(requestId)?.View;
    }

    /// <summary>The reason a capability card cannot be shown whole, or null.</summary>
    public string? RefusalOf(string requestId)
    {
        lock (_gate) return _cards.GetValueOrDefault(requestId)?.Refusal;
    }

    /// <summary>The purpose as far as it has been brought into view, with an ellipsis while some is left.</summary>
    public string PurposeShown(string requestId)
        => ViewOf(requestId)?.PurposeUpTo(PartsShown(requestId)) ?? string.Empty;

    /// <summary>How many parts the purpose is read in: 1 when it fits the card at a glance.</summary>
    public int PartsOf(string requestId) => ViewOf(requestId)?.PurposeParts.Count ?? 1;

    public int PartsShown(string requestId)
    {
        lock (_gate) return _partsShown.GetValueOrDefault(requestId, 1);
    }

    public int PartsLeft(string requestId) => Math.Max(0, PartsOf(requestId) - PartsShown(requestId));

    /// <summary>How far the purpose has been read, in words.</summary>
    public string ProgressOf(string requestId)
    {
        var parts = PartsOf(requestId);
        return PartsLeft(requestId) == 0
            ? $"The whole request is shown ({parts} of {parts} parts)."
            : $"{PartsShown(requestId)} of {parts} parts shown. {UnreadText}";
    }

    /// <summary>Brings the next part of the purpose into view. The card grows, so it and the ones below it are held again.</summary>
    public void ReadOn(string requestId)
    {
        if (PartsLeft(requestId) == 0) return;
        lock (_gate) _partsShown[requestId] = _partsShown.GetValueOrDefault(requestId, 1) + 1;
        HoldFrom(requestId);
    }

    /// <summary>Holds a card and every card below it, as moved; with no id, every card.</summary>
    public void HoldFrom(string? requestId = null)
    {
        lock (_gate)
        {
            var from = requestId is not null && _places.TryGetValue(requestId, out var place) ? place.Index : 0;
            foreach (var (id, held) in _places.Where(p => p.Value.Index >= from).ToList())
                _places[id] = held with { Since = _time.GetTimestamp() };
        }
    }

    /// <summary>Whether a card was drawn, or came to where it stands, less than <see cref="HoldMilliseconds"/> ago.</summary>
    public bool IsHeld(string requestId)
    {
        lock (_gate)
        {
            return _places.TryGetValue(requestId, out var place)
                && _time.GetElapsedTime(place.Since) < TimeSpan.FromMilliseconds(HoldMilliseconds);
        }
    }

    /// <summary>
    /// Whether <paramref name="req"/> - this one, as it was rendered - may be
    /// approved now, with the words for when it may not. The user-vault kinds
    /// own their card and its rules; the hold is theirs too.
    /// </summary>
    public (CardBlock Block, string? Text) Judge(PendingRequest req)
    {
        if (req.Kind == PendingRequestKind.Unreadable) return (CardBlock.Refused, UnreadableText);
        if (!UserVaultCardModel.IsUserVaultKind(req.Kind))
        {
            if (TryDigest(req) is not { } digest) return (CardBlock.Refused, UnreadableText);
            if (!_seen.Unchanged(IdOf(req), digest)) return (CardBlock.Refused, ChangedText);
            if (req.Kind == PendingRequestKind.CapabilityRequest)
            {
                Card? card;
                lock (_gate) card = _cards.GetValueOrDefault(IdOf(req));
                if (card is null) return (CardBlock.Refused, GoneText);
                if (card.Digest != digest) return (CardBlock.Refused, ChangedText);
                if (card.Refusal is not null) return (CardBlock.Refused, card.Refusal);
                if (PartsLeft(IdOf(req)) > 0) return (CardBlock.Unread, UnreadText);
            }
        }
        return (IsHeld(IdOf(req)) ? CardBlock.Held : CardBlock.None, null);
    }

    /// <summary>
    /// The digest of what a card's approval acts on, whatever its kind: the
    /// payload hash, the capability segments, and each chain's message, path
    /// and network. Not its description, its app or its queue time, which
    /// nothing signs.
    /// </summary>
    public static string DigestOf(PendingRequest req)
    {
        var c = req.Context;
        var sb = new StringBuilder();
        // Each value with its length and each list with its count, so no two sets of values read alike.
        void Add(string? value) => sb.Append(value?.Length ?? -1).Append(':').Append(value);
        void AddAll(params string?[] values)
        {
            foreach (var value in values) Add(value);
        }

        AddAll(req.Kind, req.Service, req.Secret, c.PayloadHashB64u, c.CapHeaderB64, c.CapPayloadB64,
            c.TotpAlias, c.TotpSecretB32, c.TotpAlgorithm, $"{c.TotpPeriodSeconds}", $"{c.TotpDigits}",
            c.SessionBearer, $"{c.SessionScope?.Count ?? -1}");
        foreach (var scope in c.SessionScope ?? []) Add(scope);
        AddAll($"{c.SessionLifetimeSeconds}", $"{c.SessionMaxUses}", c.SessionBootloaderId,
            c.WebAuthnRpId, c.WebAuthnOrigin, c.WebAuthnChallengeB64u, c.WebAuthnUserHandleB64u,
            c.PgpOperation, c.PgpKeyLabel,
            $"{c.EthChainId}", c.EthMessageKind, c.EthDerivationPath, c.EthMessageText, c.EthTypedDataJson,
            c.EthTransactionJson,
            c.BtcNetwork, c.BtcCoin, c.BtcMessageKind, c.BtcDerivationPath, c.BtcMessageText, c.BtcPsbtBase64,
            c.EdChain, c.EdMessageKind, c.EdDerivationPath, c.EdMessageText, c.EdPayloadHex,
            c.TronNetwork, c.TronMessageKind, c.TronDerivationPath, c.TronMessageText, c.TronPayloadHex);
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(sb.ToString())));
    }
}
