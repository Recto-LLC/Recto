using System;
using System.Collections.Generic;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Recto.Shared.Capability;

/// <summary>
/// Reads a capability card's two signed segments whole, or refuses them
/// (hard rule 15.x: a card that cannot render a signed field refuses to
/// sign). Every field of the header and the payload must be one the card
/// shows, named once, with the type it is shown as. The set is the one
/// <c>recto/capability/types.py</c> signs.
/// </summary>
public static class CapabilityCardPayload
{
    private delegate string? FieldCheck(JsonElement value, string where);

    private static readonly Regex Segment = new("^[A-Za-z0-9_-]+$", RegexOptions.CultureInvariant);

    private static readonly IReadOnlyDictionary<string, FieldCheck> HeaderFields =
        new Dictionary<string, FieldCheck>(StringComparer.Ordinal)
        {
            ["alg"] = (v, w) => Exactly(v, w, "ES256K"),
            ["typ"] = (v, w) => Exactly(v, w, "JWT"),
        };

    private static readonly IReadOnlyDictionary<string, FieldCheck> ScopeFields =
        new Dictionary<string, FieldCheck>(StringComparer.Ordinal)
        {
            ["env"] = TextList,
            ["services"] = TextList,
            ["repos"] = TextList,
            ["create_for_owner"] = Text,
            ["chat_room_id"] = Text,
            ["target_user_id"] = Text,
            ["pairing_code"] = Text,
            ["payload_sha256"] = Text,
        };

    private static readonly IReadOnlyDictionary<string, FieldCheck> LimitFields =
        new Dictionary<string, FieldCheck>(StringComparer.Ordinal)
        {
            ["per_hour"] = WholeNumbers,
            ["per_day"] = WholeNumbers,
            ["per_session"] = WholeNumbers,
        };

    private static readonly IReadOnlyDictionary<string, FieldCheck> CapFields =
        new Dictionary<string, FieldCheck>(StringComparer.Ordinal)
        {
            ["tier"] = WholeNumber,
            ["registry_version"] = Text,
            ["groups"] = TextList,
            ["allow_actions"] = TextList,
            ["deny_actions"] = TextList,
            ["scope"] = (v, w) => Fields(v, w, ScopeFields),
            ["limits"] = (v, w) => Fields(v, w, LimitFields),
        };

    private static readonly IReadOnlyDictionary<string, FieldCheck> PayloadFields =
        new Dictionary<string, FieldCheck>(StringComparer.Ordinal)
        {
            ["iss"] = Text,
            ["sub"] = Text,
            ["aud"] = TextList,
            ["iat"] = WholeNumber,
            ["nbf"] = WholeNumber,
            ["exp"] = WholeNumber,
            ["jti"] = Text,
            ["cap"] = (v, w) => Fields(v, w, CapFields),
            ["purpose"] = Text,
            ["parent_cap"] = Text,
            ["max_uses"] = WholeNumber,
            ["parent_profile"] = Text,
        };

    /// <summary>The claims, or null with the reason the card cannot be shown whole.</summary>
    public static CapabilityClaims? TryRead(string? headerB64, string? payloadB64, out string? refusal)
    {
        refusal = null;
        try
        {
            if (string.IsNullOrEmpty(headerB64) || string.IsNullOrEmpty(payloadB64))
            {
                refusal = "it carries no signed claims.";
                return null;
            }
            using var header = JsonDocument.Parse(Decode(headerB64));
            using var payload = JsonDocument.Parse(Decode(payloadB64));
            refusal = Fields(header.RootElement, "header", HeaderFields)
                ?? (header.RootElement.TryGetProperty("alg", out _) ? null : "its header names no algorithm.")
                ?? Fields(payload.RootElement, string.Empty, PayloadFields);
            return refusal is null ? CapabilityJws.PayloadToClaims(payload.RootElement) : null;
        }
        catch (Exception ex)
        {
            // Whatever a card carries, the worst it does is refuse itself.
            refusal = $"it could not be read ({ex.GetType().Name}).";
            return null;
        }
    }

    // One spelling per segment: the unpadded base64url of its own bytes.
    private static byte[] Decode(string segment)
    {
        if (!Segment.IsMatch(segment)) throw new FormatException("not base64url");
        var bytes = CapabilityJws.Base64UrlDecode(segment);
        return CapabilityJws.Base64UrlEncode(bytes) == segment ? bytes : throw new FormatException("not canonical base64url");
    }

    private static string? Fields(JsonElement value, string where, IReadOnlyDictionary<string, FieldCheck> known)
    {
        if (value.ValueKind != JsonValueKind.Object) return Wrong(where.Length == 0 ? "the payload" : where);
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var property in value.EnumerateObject())
        {
            var name = where.Length == 0 ? property.Name : where + "." + property.Name;
            if (!seen.Add(property.Name)) return $"it signs {Named(name)} twice.";
            if (!known.TryGetValue(property.Name, out var check))
                return $"it signs {Named(name)}, a field this app does not show.";
            if (check(property.Value, name) is { } why) return why;
        }
        return null;
    }

    private static string? Text(JsonElement value, string where)
        => value.ValueKind == JsonValueKind.String && value.GetString() is not null ? null : Wrong(where);

    private static string? Exactly(JsonElement value, string where, string expected)
        => value.ValueKind == JsonValueKind.String && value.GetString() == expected ? null : Wrong(where);

    private static string? WholeNumber(JsonElement value, string where)
        => value.ValueKind == JsonValueKind.Number && value.TryGetInt64(out _) ? null : Wrong(where);

    private static string? TextList(JsonElement value, string where)
    {
        if (value.ValueKind != JsonValueKind.Array) return Wrong(where);
        foreach (var item in value.EnumerateArray())
        {
            if (Text(item, where) is { } why) return why;
        }
        return null;
    }

    private static string? WholeNumbers(JsonElement value, string where)
    {
        if (value.ValueKind != JsonValueKind.Object) return Wrong(where);
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var property in value.EnumerateObject())
        {
            if (!seen.Add(property.Name)) return $"it signs {Named(where + "." + property.Name)} twice.";
            if (WholeNumber(property.Value, where) is { } why) return why;
        }
        return null;
    }

    private static string Wrong(string where) => $"{Named(where)} is not a value this app can show.";

    private static string Named(string name)
    {
        var visible = VisibleText.Of(name);
        return visible.Length <= 80 ? visible : visible[..80] + "...";
    }
}
