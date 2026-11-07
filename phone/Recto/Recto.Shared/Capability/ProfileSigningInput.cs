using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text.Json;
using Recto.Shared.Protocol.V04;

namespace Recto.Shared.Capability;

/// <summary>
/// The master key signs a profile card only over bytes the phone has read back
/// against the card it shows. A profile card (<c>profile_create</c>,
/// <c>profile_add_device</c>, <c>profile_revoke_device</c>) carries its signing
/// input in <c>cap_payload_b64</c>; before the master key (m/44'/60'/0'/0/0)
/// signs, the input must be:
/// <list type="bullet">
/// <item>the canonical JSON (<see cref="CanonicalJson"/>, byte-for-byte what the
/// bootloader's <c>_canonical_json</c> writes) of exactly the key set the
/// bootloader builds for that card's kind - no key more, none less, none twice;</item>
/// <item>naming the card's own action, ids and request id, and a time within
/// <see cref="ClockSlackSeconds"/> of the card's;</item>
/// <item>naming this phone's own master key;</item>
/// <item>the bytes whose SHA-256 is the card's <c>payload_hash_b64u</c>, the hash
/// the paired-phone envelope signs.</item>
/// </list>
/// Anything else is refused by name and nothing is signed (hard rule 15.x: a
/// card that cannot render a signed field refuses to sign).
///
/// <para>Lives here, not in the page, so the rule is unit-tested without a render
/// harness; Home.razor's three profile approvals consume it thin.</para>
/// </summary>
public static class ProfileSigningInput
{
    /// <summary>Either the 32-byte digest the master key signs, or why nothing is signed.</summary>
    public sealed record Verdict(byte[]? Digest, string? Refusal)
    {
        public bool Ok => Refusal is null && Digest is not null;
    }

    /// <summary>The card's time and the time in its signing input are stamped by the
    /// bootloader in one request; they may differ by this much and no more.</summary>
    public const long ClockSlackSeconds = 300;

    private static readonly string[] AddDeviceKeys =
        ["action", "added_at_unix", "master_pubkey_hex", "new_phone_id", "profile_id", "request_id"];

    private static readonly string[] RevokeDeviceKeys =
        ["action", "master_pubkey_hex", "phone_id_to_revoke", "profile_id", "request_id", "revoked_at_unix"];

    private static readonly string[] ProfileCreateKeys =
        ["candidate_profile_id", "derivation_coin_type", "derivation_index", "derivation_purpose",
         "display_name", "kind", "master_pubkey_hex", "scim_provider", "theme_hint"];

    public static Verdict AddDevice(PendingRequest req, string ownMasterPubkeyHex)
    {
        if (req.Kind != PendingRequestKind.ProfileAddDevice)
        {
            return Refuse("this is not an add-device card");
        }
        var ctx = req.Context;
        var (fields, bytes, refusal) = Read(ctx, AddDeviceKeys);
        if (refusal is not null) return Refuse(refusal);
        refusal = Text(fields!, "action", PendingRequestKind.ProfileAddDevice)
            ?? Text(fields!, "profile_id", ctx.AddevProfileId)
            ?? Text(fields!, "new_phone_id", ctx.AddevNewPhoneId)
            ?? Text(fields!, "request_id", req.RequestId)
            ?? Stamp(fields!, "added_at_unix", ctx.RequestedAtUnix)
            ?? OwnMaster(fields!, ownMasterPubkeyHex);
        return refusal is null ? new Verdict(SHA256.HashData(bytes!), null) : Refuse(refusal);
    }

    public static Verdict RevokeDevice(PendingRequest req, string ownMasterPubkeyHex)
    {
        if (req.Kind != PendingRequestKind.ProfileRevokeDevice)
        {
            return Refuse("this is not a revoke-device card");
        }
        var ctx = req.Context;
        var (fields, bytes, refusal) = Read(ctx, RevokeDeviceKeys);
        if (refusal is not null) return Refuse(refusal);
        refusal = Text(fields!, "action", PendingRequestKind.ProfileRevokeDevice)
            ?? Text(fields!, "profile_id", ctx.RevdevProfileId)
            ?? Text(fields!, "phone_id_to_revoke", ctx.RevdevPhoneIdToRevoke)
            ?? Text(fields!, "request_id", req.RequestId)
            ?? Stamp(fields!, "revoked_at_unix", ctx.RequestedAtUnix)
            ?? OwnMaster(fields!, ownMasterPubkeyHex);
        return refusal is null ? new Verdict(SHA256.HashData(bytes!), null) : Refuse(refusal);
    }

    /// <summary>The queue-time input is PARTIAL (the bootloader cannot know the child
    /// key): it is checked against the card, then the phone's own derived child key is
    /// added and the whole re-encoded, and that is what the master signs.</summary>
    public static Verdict ProfileCreate(PendingRequest req, string ownMasterPubkeyHex, string childPubkeyHex)
    {
        if (req.Kind != PendingRequestKind.ProfileCreate)
        {
            return Refuse("this is not a create-profile card");
        }
        if (!IsPubkeyHex(childPubkeyHex))
        {
            return Refuse("the derived child key is not a 64-byte public key");
        }
        var ctx = req.Context;
        var (fields, _, refusal) = Read(ctx, ProfileCreateKeys);
        if (refusal is not null) return Refuse(refusal);
        refusal = Text(fields!, "candidate_profile_id", ctx.CandidateProfileId)
            ?? Text(fields!, "kind", ctx.CandidateKind)
            ?? Text(fields!, "display_name", ctx.CandidateDisplayName)
            ?? Number(fields!, "derivation_purpose", ctx.CandidateDerivationPurpose)
            ?? Number(fields!, "derivation_coin_type", ctx.CandidateDerivationCoinType)
            ?? Number(fields!, "derivation_index", ctx.CandidateDerivationIndex)
            ?? Optional(fields!, "theme_hint", ctx.CandidateThemeHint)
            ?? Optional(fields!, "scim_provider", ctx.CandidateScimProvider)
            ?? OwnMaster(fields!, ownMasterPubkeyHex);
        if (refusal is not null) return Refuse(refusal);
        var full = new Dictionary<string, object?>(fields!, StringComparer.Ordinal)
        {
            ["child_pubkey_hex"] = childPubkeyHex,
        };
        return new Verdict(SHA256.HashData(CanonicalJson.Encode(full)), null);
    }

    // ---------------------------------------------------------------------

    private static Verdict Refuse(string why) =>
        new(null, $"Not signed: {why}. The card's signing input does not match the card.");

    /// <summary>Decode, hash-check, parse and canonical-check the card's signing input.</summary>
    private static (Dictionary<string, object?>? Fields, byte[]? Bytes, string? Refusal) Read(
        PendingRequestContext ctx, string[] keys)
    {
        if (string.IsNullOrEmpty(ctx.CapPayloadB64) || string.IsNullOrEmpty(ctx.PayloadHashB64u))
        {
            return (null, null, "the card carries no signing input");
        }
        byte[] bytes, envelopeHash;
        try
        {
            bytes = Base64UrlDecode(ctx.CapPayloadB64);
            envelopeHash = Base64UrlDecode(ctx.PayloadHashB64u);
        }
        catch (FormatException)
        {
            return (null, null, "the signing input is not base64url");
        }
        if (!CryptographicOperations.FixedTimeEquals(SHA256.HashData(bytes), envelopeHash))
        {
            return (null, null, "the signing input is not the bytes the card's hash names");
        }
        var fields = new Dictionary<string, object?>(StringComparer.Ordinal);
        try
        {
            using var doc = JsonDocument.Parse(bytes);
            if (doc.RootElement.ValueKind != JsonValueKind.Object)
            {
                return (null, null, "the signing input is not a JSON object");
            }
            foreach (var prop in doc.RootElement.EnumerateObject())
            {
                if (!fields.TryAdd(prop.Name, Scalar(prop.Value)))
                {
                    return (null, null, $"the signing input names {prop.Name} twice");
                }
            }
        }
        catch (Exception ex) when (ex is JsonException or InvalidOperationException)
        {
            return (null, null, "the signing input is not canonical JSON");
        }
        if (fields.Count != keys.Length || !keys.All(fields.ContainsKey))
        {
            return (null, null, "the signing input does not carry exactly this card's fields");
        }
        if (!bytes.AsSpan().SequenceEqual(CanonicalJson.Encode(fields)))
        {
            return (null, null, "the signing input is not canonically encoded");
        }
        return (fields, bytes, null);
    }

    private static object? Scalar(JsonElement e) => e.ValueKind switch
    {
        JsonValueKind.Null => null,
        JsonValueKind.True => true,
        JsonValueKind.False => false,
        JsonValueKind.String => e.GetString(),
        JsonValueKind.Number when e.TryGetInt64(out var n) => n,
        _ => throw new InvalidOperationException("not a canonical scalar"),
    };

    private static string? Text(Dictionary<string, object?> f, string key, string? card) =>
        !string.IsNullOrEmpty(card) && f[key] is string s && string.Equals(s, card, StringComparison.Ordinal)
            ? null
            : $"its {key} is not the card's";

    private static string? Optional(Dictionary<string, object?> f, string key, string? card) =>
        (f[key] is null && card is null) || (f[key] is string s && string.Equals(s, card, StringComparison.Ordinal))
            ? null
            : $"its {key} is not the card's";

    private static string? Number(Dictionary<string, object?> f, string key, long? card) =>
        card is not null && f[key] is long n && n == card ? null : $"its {key} is not the card's";

    private static string? Stamp(Dictionary<string, object?> f, string key, long cardAt) =>
        f[key] is long at && at >= 0 && Math.Abs(at - cardAt) <= ClockSlackSeconds
            ? null
            : $"its {key} is not the card's time";

    private static string? OwnMaster(Dictionary<string, object?> f, string own) =>
        IsPubkeyHex(own) && f["master_pubkey_hex"] is string named && IsPubkeyHex(named)
            && string.Equals(named, own, StringComparison.OrdinalIgnoreCase)
            ? null
            : "it names another master key";

    private static bool IsPubkeyHex(string? s) => s is { Length: 128 } && s.All(Uri.IsHexDigit);

    private static byte[] Base64UrlDecode(string s)
    {
        var b64 = s.Replace('-', '+').Replace('_', '/');
        b64 += (b64.Length % 4) switch { 2 => "==", 3 => "=", 0 => "", _ => throw new FormatException() };
        return Convert.FromBase64String(b64);
    }
}
