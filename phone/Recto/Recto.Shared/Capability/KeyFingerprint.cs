using System;
using System.Security.Cryptography;

namespace Recto.Shared.Capability;

/// <summary>
/// The short form of a public key a person compares between two screens:
/// SHA-256 over the raw 64-byte key (X || Y), its first eight bytes as four
/// hyphenated groups of upper-case hex, e.g. <c>3F2A-9C01-77D4-B812</c>.
/// For reading only; the key itself is the identity (hard rule 14).
/// </summary>
public static class KeyFingerprint
{
    public static string Of(byte[] rawPublicKey)
    {
        ArgumentNullException.ThrowIfNull(rawPublicKey);
        if (rawPublicKey.Length != 64)
            throw new ArgumentException("A public key is 64 raw bytes (X || Y).", nameof(rawPublicKey));
        var hex = Convert.ToHexString(SHA256.HashData(rawPublicKey), 0, 8);
        return $"{hex[..4]}-{hex[4..8]}-{hex[8..12]}-{hex[12..16]}";
    }
}
