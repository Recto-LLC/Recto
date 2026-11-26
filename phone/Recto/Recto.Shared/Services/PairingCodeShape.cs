using System;

namespace Recto.Shared.Services;

/// <summary>
/// The two codes the pairing screen sends in the <c>code</c> parameter of
/// <c>GET /v0.4/registration_challenge</c>, told apart by shape alone.
/// <list type="bullet">
/// <item>A pairing code: exactly six ASCII digits, sent as typed.</item>
/// <item>An owner reset's code, from the bootloader's own host: sixteen
/// characters of Crockford base32 (no I, L, O or U), shown as
/// <c>XXXX-XXXX-XXXX-XXXX</c>. Lower case, dashes and spaces are forgiven and
/// I, L and O are read as 1, 1 and 0; it is sent upper case with no
/// separators.</item>
/// </list>
/// The bootloader reads a code by the same rules
/// (<c>recto.bootloader.top_plane.normalize_reset_code</c>); both sides run
/// <c>tests/reset_code_vectors.json</c>. Pure: nothing here stores, logs or
/// sends a code.
/// </summary>
public static class PairingCodeShape
{
    public const int OwnerCodeLength = 6;
    public const int ResetCodeLength = 16;

    /// <summary>What a person may type for a reset code: 16 characters and 3 dashes.</summary>
    public const int ResetCodeTypedMaxLength = 19;

    /// <summary>Crockford base32, byte-for-byte the bootloader's alphabet.</summary>
    public const string ResetAlphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

    /// <summary>Exactly six ASCII digits. <c>char.IsDigit</c> is not used: it takes digits of other scripts.</summary>
    public static bool IsOwnerCode(string? code)
    {
        if (code is null || code.Length != OwnerCodeLength) return false;
        foreach (var c in code)
        {
            if (c < '0' || c > '9') return false;
        }
        return true;
    }

    /// <summary>True when the text reads as a reset code.</summary>
    public static bool IsResetCode(string? code) => NormalizeResetCode(code) is not null;

    /// <summary>
    /// The sixteen canonical characters of a reset code, or null when the text
    /// is not one. Only ASCII is read: a letter or digit of another script
    /// never passes for one of the alphabet.
    /// </summary>
    public static string? NormalizeResetCode(string? code)
    {
        if (code is null) return null;
        Span<char> canonical = stackalloc char[ResetCodeLength];
        var n = 0;
        foreach (var raw in code)
        {
            if (raw == '-' || raw == ' ') continue;
            if (raw > 0x7F) return null;
            var c = raw >= 'a' && raw <= 'z' ? (char)(raw - 32) : raw;
            if (c == 'I' || c == 'L') c = '1';
            else if (c == 'O') c = '0';
            if (ResetAlphabet.IndexOf(c) < 0) return null;
            if (n == ResetCodeLength) return null;
            canonical[n++] = c;
        }
        return n == ResetCodeLength ? new string(canonical) : null;
    }

    /// <summary>
    /// What goes on the wire: six digits as typed, a reset code in its
    /// canonical form, or null when the text is neither.
    /// </summary>
    public static string? Canonical(string? code)
        => IsOwnerCode(code) ? code : NormalizeResetCode(code);

    /// <summary>A reset code in four groups of four; anything else unchanged.</summary>
    public static string Display(string code)
    {
        var canonical = NormalizeResetCode(code);
        if (canonical is null) return code;
        return $"{canonical[..4]}-{canonical[4..8]}-{canonical[8..12]}-{canonical[12..]}";
    }

    /// <summary>
    /// The code the Pair button sends, from the pairing screen's two fields.
    /// A reset code that reads as one wins over the six digits; with the reset
    /// field holding anything else, the screen does not pair (a half-typed
    /// reset code never falls back to the other field).
    /// </summary>
    public static string? CodeToSend(string? pairingCode, string? resetCode)
    {
        if (!string.IsNullOrWhiteSpace(resetCode)) return NormalizeResetCode(resetCode);
        return IsOwnerCode(pairingCode) ? pairingCode : null;
    }
}
