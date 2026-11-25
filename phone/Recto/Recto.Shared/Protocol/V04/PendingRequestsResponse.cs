using System;
using System.Collections.Generic;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Recto.Shared.Protocol.V04;

/// <summary>
/// Bootloader response to <c>GET /v0.4/pending?phone_id=...</c> &mdash;
/// the list of sign requests waiting for operator approval on this phone.
/// Empty list when nothing is pending; the phone polls or wakes from
/// push.
/// </summary>
public sealed record PendingRequestsResponse(
    [property: JsonPropertyName("requests")]
    [property: JsonConverter(typeof(PendingRequestListConverter))] IReadOnlyList<PendingRequest> Requests,
    // 2026-09-16 SERVER-SIGNED CARDS: an ES256K JWS by the bootloader's pair key
    // whose cap.scope.payload_sha256 is the SHA-256 of the exact `requests` text
    // on the wire, sub = phone:<this phone>. Null from bootloaders that hold no
    // key. A paired phone that pinned the key renders NO card without it (see
    // Services.BootloaderAttestation.VerifyPendingEnvelope).
    [property: JsonPropertyName("pending_jws")] string? PendingJws = null)
{
    /// <summary>
    /// The `requests` element exactly as received (JsonElement.GetRawText()),
    /// set by the client after parsing; never serialized. This is what the
    /// envelope's digest is over -- re-encoding the typed records would not
    /// reproduce the server's bytes.
    /// </summary>
    [JsonIgnore]
    public string? RequestsRawJson { get; init; }
}

/// <summary>
/// Reads the queue one card at a time: a card that cannot be read is one
/// unreadable card under its id, and the others are read as they are. What
/// the envelope signs is the raw text, which this does not touch.
/// </summary>
public sealed class PendingRequestListConverter : JsonConverter<IReadOnlyList<PendingRequest>>
{
    public override bool HandleNull => true;

    public override IReadOnlyList<PendingRequest> Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        using var list = JsonDocument.ParseValue(ref reader);
        if (list.RootElement.ValueKind != JsonValueKind.Array) throw new JsonException("requests is not a list");
        var cards = new List<PendingRequest>(list.RootElement.GetArrayLength());
        foreach (var element in list.RootElement.EnumerateArray()) cards.Add(ReadCard(element, options));
        return cards;
    }

    public override void Write(Utf8JsonWriter writer, IReadOnlyList<PendingRequest> value, JsonSerializerOptions options)
        => JsonSerializer.Serialize(writer, value, options);

    private static PendingRequest ReadCard(JsonElement element, JsonSerializerOptions options)
    {
        try
        {
            var card = element.Deserialize<PendingRequest>(options);
            if (card is { Context: not null } && !string.IsNullOrEmpty(card.RequestId) && !string.IsNullOrEmpty(card.Kind))
            {
                return card with
                {
                    Service = card.Service ?? string.Empty,
                    Secret = card.Secret ?? string.Empty,
                    Context = card.Context with
                    {
                        ChildArgv0 = card.Context.ChildArgv0 ?? string.Empty,
                        OperationDescription = card.Context.OperationDescription ?? string.Empty,
                    },
                };
            }
        }
        catch (Exception)
        {
            // Whatever is wrong with one card, the others are still the person's to answer.
        }
        return PendingRequest.Unreadable(TextOf(element, "request_id"), TextOf(element, "kind"));
    }

    private static string TextOf(JsonElement element, string name)
    {
        try
        {
            return element.ValueKind == JsonValueKind.Object && element.TryGetProperty(name, out var text)
                && text.ValueKind == JsonValueKind.String ? text.GetString() ?? string.Empty : string.Empty;
        }
        catch (Exception)
        {
            return string.Empty;
        }
    }
}
