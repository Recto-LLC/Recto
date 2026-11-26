using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Serialization;
using Recto.Shared.Common;

namespace Recto.Shared.Services;

/// <summary>
/// What a registration sends to show where its identity key lives (hard rule 14.8). The wire shape of
/// <c>device_evidence</c>: an Android key's certificate chain (base64 DER, leaf first), or an iOS App Attest key id and
/// object. A bootloader that does not read the field ignores it. Read for the one registration and kept nowhere; of an App Attest object the
/// phone keeps the key's id, and only when the bootloader says it keeps the key.
/// </summary>
public sealed record DeviceEvidence(
    [property: JsonPropertyName("platform")] string Platform,
    [property: JsonPropertyName("chain"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    IReadOnlyList<string>? Chain = null,
    [property: JsonPropertyName("key_id"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    string? KeyId = null,
    [property: JsonPropertyName("attestation"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    string? Attestation = null)
{
    /// <summary>What a key service answers when the platform no longer holds an App Attest key.</summary>
    public const string KeyGoneCode = "AppAttestKeyGone";

    public const string AndroidChallengePrefix = "recto-key-attest-v1";
    public const string IosClientDataPrefix = "recto-attest-v1";

    /// <summary>The platform alone: a record that is printed prints its members, and this one's are never printed.</summary>
    public override string ToString() => $"DeviceEvidence({Platform})";

    public static DeviceEvidence Android(IReadOnlyList<string> chain) => new("android", Chain: chain);

    public static DeviceEvidence Ios(string keyId, string attestation)
        => new("ios", KeyId: keyId, Attestation: attestation);

    /// <summary>What an Android identity key is generated with (setAttestationChallenge).</summary>
    public static byte[] AndroidChallenge(string registrationChallenge)
        => SHA256.HashData(Encoding.ASCII.GetBytes($"{AndroidChallengePrefix}|{registrationChallenge}"));

    /// <summary>What App Attest signs over: this registration's challenge and the two keys it registers.</summary>
    public static byte[] IosClientDataHash(string registrationChallenge, string identityKeyB64u, string pollKeyB64u)
        => SHA256.HashData(Encoding.ASCII.GetBytes(
            $"{IosClientDataPrefix}|{registrationChallenge}|{identityKeyB64u}|{pollKeyB64u}"));

    /// <summary>The bootloader refused the registration for what this phone showed. Such an answer also says the
    /// bootloader does not hold this key: a key it holds is never asked.</summary>
    public static bool IsRefusal(Error error)
        => error.Message.StartsWith("HTTP 403: device_evidence_", StringComparison.Ordinal)
            || error.Message.StartsWith("HTTP 403: test_device_code_invalid", StringComparison.Ordinal);

    /// <summary>The bootloader answered, whatever it said (as against a request whose answer never came).</summary>
    public static bool WasAnswered(Error error)
        => error.Message.StartsWith("HTTP ", StringComparison.Ordinal)
            || error.Message.StartsWith("Not found: ", StringComparison.Ordinal)
            || error.Message.StartsWith("Bootloader returned HTTP ", StringComparison.Ordinal);
}

/// <summary>
/// Whether the identity key on this phone may be made again for a new registration. A key whose platform attests it at
/// creation carries one registration's challenge for ever, so a try that ended before the bootloader had the key needs a
/// new one; a key any bootloader may hold is never replaced without being asked.
/// </summary>
public static class IdentityKeyJournal
{
    /// <summary>Made here, and no bootloader was ever sent it.</summary>
    public const string New = "new";

    private const string SentPrefix = "sent|";

    /// <summary>Sent to <paramref name="host"/>; what became of it there is not known yet.</summary>
    public static string Sent(string host) => SentPrefix + host;

    public static bool MayReplace(string? journal) => journal == New;

    /// <summary>What to keep after a register call to <paramref name="host"/>. Null means a bootloader may hold the key.</summary>
    public static string? After(string? journal, string host, Error? error)
    {
        if (journal is null) return null;
        if (error is null) return null;
        if (journal == Sent(host) && DeviceEvidence.IsRefusal(error)) return New;
        return DeviceEvidence.WasAnswered(error) ? null : journal;
    }
}
