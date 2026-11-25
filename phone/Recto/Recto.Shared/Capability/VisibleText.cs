using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;

namespace Recto.Shared.Capability;

/// <summary>
/// Text as a card shows it: a character that draws nothing, that strikes out
/// another, or that changes the order the rest is read in, is written out as
/// its code point. Text with none of those comes back as it was, the same
/// string. The two joiners pass where a script or an emoji is spelled with
/// them.
/// </summary>
public static class VisibleText
{
    private const char Open = (char)0x27E8;   // mathematical left angle bracket
    private const char Close = (char)0x27E9;

    private const int NonJoiner = 0x200C;
    private const int Joiner = 0x200D;
    private const int TextPresentation = 0xFE0E;
    private const int EmojiPresentation = 0xFE0F;
    private const int Keycap = 0x20E3;
    private const int IsolateFirst = 0x2066;        // left to right, right to left,
    private const int FirstStrongIsolate = 0x2068;  // first strong
    private const int PopIsolate = 0x2069;

    /// <summary>An id, a name or a value, where two spellings that look alike are two values: no isolate passes.</summary>
    public static string Of(string? text) => Of(text, isolates: false);

    /// <summary>
    /// Sentences, where a title in another direction may be quoted inside a
    /// first-strong isolate: a balanced pair around something on one line
    /// passes, and the page draws it as the isolation it is. Any other
    /// isolate is written out.
    /// </summary>
    public static string OfProse(string? text) => Of(text, isolates: true);

    private static string Of(string? text, bool isolates)
    {
        if (string.IsNullOrEmpty(text) || IsPlain(text)) return text ?? string.Empty;
        var pieces = Pieces(text);
        var shown = Enumerable.Range(0, pieces.Count).Select(i => IsHiddenAt(pieces, i)).ToArray();
        if (isolates) foreach (var at in BalancedIsolates(pieces, shown)) shown[at] = false;
        if (!shown.Contains(true)) return text;
        var sb = new StringBuilder(text.Length + 16);
        for (var i = 0; i < pieces.Count; i++)
        {
            if (!shown[i]) sb.Append(pieces[i].Raw);
            else sb.Append(Open).Append("U+").Append(pieces[i].CodePoint.ToString("X4", CultureInfo.InvariantCulture)).Append(Close);
        }
        return sb.ToString();
    }

    /// <summary>The text without those characters - for a comparison that must not be thrown off by one.</summary>
    public static string WithoutHidden(string? text)
    {
        if (string.IsNullOrEmpty(text) || IsPlain(text)) return text ?? string.Empty;
        var pieces = Pieces(text);
        return string.Concat(pieces.Where((_, i) => !IsHiddenAt(pieces, i)).Select(p => p.Raw));
    }

    public static bool HasHidden(string? text)
    {
        if (string.IsNullOrEmpty(text) || IsPlain(text)) return false;
        var pieces = Pieces(text);
        return Enumerable.Range(0, pieces.Count).Any(i => IsHiddenAt(pieces, i));
    }

    /// <summary>
    /// The text as a reader takes it, for matching: every dash one dash, every
    /// digit its ASCII digit, a letter that looks like another that other
    /// letter, and no marks, hidden characters or white space. Two spellings
    /// that look alike come out the same. Never shown.
    /// </summary>
    public static string FoldedForMatch(string? text)
    {
        if (string.IsNullOrEmpty(text)) return string.Empty;
        var visible = WithoutHidden(text);
        string decomposed;
        try
        {
            decomposed = visible.Normalize(NormalizationForm.FormKD);
        }
        catch (Exception ex) when (ex is ArgumentException or PlatformNotSupportedException)
        {
            decomposed = visible;
        }
        var sb = new StringBuilder(decomposed.Length);
        foreach (var rune in decomposed.EnumerateRunes())
        {
            var category = Rune.GetUnicodeCategory(rune);
            if (Rune.IsWhiteSpace(rune) || category is UnicodeCategory.NonSpacingMark or UnicodeCategory.SpacingCombiningMark
                    or UnicodeCategory.EnclosingMark or UnicodeCategory.Format or UnicodeCategory.Control)
                continue;
            if (category == UnicodeCategory.DashPunctuation || OtherDashes.Contains(rune.Value)) sb.Append('-');
            else if (category == UnicodeCategory.DecimalDigitNumber) sb.Append((char)('0' + (int)Rune.GetNumericValue(rune)));
            else if (LooksLike.TryGetValue(rune.Value, out var letter)) sb.Append(letter);
            else sb.Append(rune.ToString());
        }
        return sb.ToString();
    }

    /// <summary>
    /// Control and format characters (the bidirectional controls and the
    /// zero-width ones are format characters), line and paragraph separators,
    /// private-use and unassigned code points, marks that enclose or strike
    /// out, and the few characters of other categories that draw as nothing.
    /// A tab or a line break is ordinary white space.
    /// </summary>
    public static bool IsHidden(Rune rune)
    {
        var v = rune.Value;
        if (v is '\t' or '\n' or '\r') return false;
        return Rune.GetUnicodeCategory(rune) switch
        {
            UnicodeCategory.Control => true,
            UnicodeCategory.Format => true,
            UnicodeCategory.LineSeparator => true,
            UnicodeCategory.ParagraphSeparator => true,
            UnicodeCategory.PrivateUse => true,
            UnicodeCategory.Surrogate => true,
            UnicodeCategory.OtherNotAssigned => true,
            UnicodeCategory.EnclosingMark => true,
            _ => v is 0x034F or 0x115F or 0x1160 or 0x17B4 or 0x17B5 or 0x2065 or 0x2800 or 0x3164 or 0xFFA0
                or 0xFFFC or 0x16FE4 or 0x1107F or 0x1D159
                or (>= 0x180B and <= 0x180F) or (>= 0xFE00 and <= 0xFE0F) or (>= 0xFFF0 and <= 0xFFF8)
                or (>= 0xE0000 and <= 0xE0FFF)
                // Marks drawn across the letter before them.
                or (>= 0x0334 and <= 0x0338) or 0x20D2 or 0x20D3 or (>= 0x20D8 and <= 0x20DA) or 0x20E5 or 0x20E6
                or 0x20EA or 0x20EB or (>= 0x1D167 and <= 0x1D169),
        };
    }

    // A code point with the characters it was written in; a null rune is half of a surrogate pair on its own.
    private readonly record struct Piece(Rune? Rune, string Raw)
    {
        public int CodePoint => Rune?.Value ?? Raw[0];
    }

    private static List<Piece> Pieces(string text)
    {
        var pieces = new List<Piece>(text.Length);
        for (var i = 0; i < text.Length;)
        {
            var status = Rune.DecodeFromUtf16(text.AsSpan(i), out var rune, out var used);
            var done = status == System.Buffers.OperationStatus.Done;
            pieces.Add(new Piece(done ? rune : null, text.Substring(i, done ? used : 1)));
            i += done ? used : 1;
        }
        return pieces;
    }

    // The places of each first-strong isolate and of the pop that closes it, with something drawn between them on one
    // line (a line's end ends an isolate).
    private static List<int> BalancedIsolates(List<Piece> pieces, bool[] hidden)
    {
        var passes = new List<int>();
        var open = new Stack<(int At, int Drawn)>();   // where it opened, and how much was drawn before it
        var drawn = 0;
        for (var i = 0; i < pieces.Count; i++)
        {
            var v = pieces[i].CodePoint;
            if (!hidden[i] && !Rune.IsWhiteSpace(pieces[i].Rune!.Value)) drawn++;
            if (v is '\n' or '\r' or 0x0085 or 0x2029 or (>= 0x1C and <= 0x1E)) open.Clear();
            else if (v is >= IsolateFirst and <= FirstStrongIsolate) open.Push((i, drawn));
            else if (v == PopIsolate && open.TryPop(out var from) && pieces[from.At].CodePoint == FirstStrongIsolate
                     && drawn > from.Drawn)
            {
                passes.Add(from.At);
                passes.Add(i);
            }
        }
        return passes;
    }

    private static bool IsPlain(string text)
        => text.All(c => c is (>= ' ' and <= '~') or '\t' or '\n' or '\r');

    private static bool IsHiddenAt(List<Piece> pieces, int at)
    {
        if (pieces[at].Rune is not { } rune) return true;
        return rune.Value switch
        {
            NonJoiner => !BetweenJoiningLetters(pieces, at),
            Joiner => !BetweenJoiningLetters(pieces, at) && !BetweenEmoji(pieces, at),
            TextPresentation or EmojiPresentation => !(at > 0 && IsEmoji(pieces[at - 1].Rune))
                && !(IsKeycapBase(pieces, at - 1) && at + 1 < pieces.Count && pieces[at + 1].CodePoint == Keycap),
            Keycap => !IsKeycapBase(pieces, at - 1)
                && !(at > 0 && pieces[at - 1].CodePoint == EmojiPresentation && IsKeycapBase(pieces, at - 2)),
            _ => IsHidden(rune),
        };
    }

    // One joiner between two letters (a letter's own marks between them) of one script that is written joined.
    private static bool BetweenJoiningLetters(List<Piece> pieces, int at)
    {
        var before = at - 1;
        while (before >= 0 && IsMark(pieces[before].Rune)) before--;
        if (before < 0 || at + 1 >= pieces.Count) return false;
        var script = JoiningScript(pieces[before].Rune);
        return script != 0 && Rune.IsLetter(pieces[before].Rune!.Value) && JoiningScript(pieces[at + 1].Rune) == script
            && (Rune.IsLetter(pieces[at + 1].Rune!.Value) || IsMark(pieces[at + 1].Rune));
    }

    private static bool BetweenEmoji(List<Piece> pieces, int at)
    {
        var before = at - 1;
        if (before >= 0 && pieces[before].CodePoint == EmojiPresentation) before--;
        return before >= 0 && at + 1 < pieces.Count && IsEmoji(pieces[before].Rune) && IsEmoji(pieces[at + 1].Rune);
    }

    private static bool IsMark(Rune? rune)
        => rune is { } r && Rune.GetUnicodeCategory(r) is UnicodeCategory.NonSpacingMark or UnicodeCategory.SpacingCombiningMark
            && !IsHidden(r);

    private static bool IsKeycapBase(List<Piece> pieces, int at)
        => at >= 0 && pieces[at].CodePoint is (>= '0' and <= '9') or '#' or '*';

    private static bool IsEmoji(Rune? rune)
        => rune is { } r && Rune.GetUnicodeCategory(r) != UnicodeCategory.OtherNotAssigned
            && r.Value is 0x00A9 or 0x00AE or 0x203C or 0x2049 or 0x2122 or 0x2139 or (>= 0x2194 and <= 0x21AA)
                or (>= 0x231A and <= 0x23FF) or 0x24C2 or (>= 0x25AA and <= 0x27BF) or 0x2934 or 0x2935
                or (>= 0x2B05 and <= 0x2B55) or 0x3030 or 0x303D or 0x3297 or 0x3299 or (>= 0x1F000 and <= 0x1FAFF);

    // 0 for a script that is not written joined; the same number for two letters of one script.
    private static int JoiningScript(Rune? rune) => rune?.Value switch
    {
        (>= 0x0600 and <= 0x06FF) or (>= 0x0750 and <= 0x077F) or (>= 0x0870 and <= 0x08FF)
            or (>= 0xFB50 and <= 0xFDFF) or (>= 0xFE70 and <= 0xFEFE) => 1,   // Arabic
        (>= 0x0700 and <= 0x074F) or (>= 0x0860 and <= 0x086F) => 2,          // Syriac
        >= 0x07C0 and <= 0x07FF => 3,                                         // N'Ko
        >= 0x0840 and <= 0x085F => 4,                                         // Mandaic
        >= 0x1800 and <= 0x18AF => 5,                                         // Mongolian
        >= 0x1780 and <= 0x17FF => 6,                                         // Khmer
        >= 0x10D00 and <= 0x10D3F => 7,                                       // Hanifi Rohingya
        >= 0x1E900 and <= 0x1E95F => 8,                                       // Adlam
        { } v and >= 0x0900 and <= 0x0DFF => 0x100 + (v >> 7),                // the Indic blocks, 128 code points each
        _ => 0,
    };

    // Characters of other categories that are drawn as a dash.
    private static readonly HashSet<int> OtherDashes =
    [
        0x02D7, 0x2043, 0x207B, 0x208B, 0x2212, 0x23AF, 0x2500, 0x2501, 0x2796, 0x30FC, 0x3161, 0x4E00, 0xFF70, 0x1173,
        0x02C9, 0x06D4, 0x1428, 0x2574, 0x2CBA, 0x2CBB, 0x3127, 0x31D0, 0xA7F7, 0x10191,
    ];

    // Letters that are drawn like a hexadecimal digit, or like the letters often read as one. Compatibility forms
    // (full width, mathematical, circled) and accented letters reach here already decomposed.
    private static readonly IReadOnlyDictionary<int, char> LooksLike = Alike(
        ('a', [0x0430, 0x0410, 0x03B1, 0x0391, 0x0251, 0x1D00, 0x13AA, 0xA4EE, 0x237A]),
        ('b', [0x0432, 0x0412, 0x042C, 0x044C, 0x03B2, 0x0392, 0x0299, 0x13CF, 0x13F4, 0x0184, 0x0185, 0xA4D0, 0x1472]),
        ('c', [0x0441, 0x0421, 0x03F2, 0x03F9, 0x1D04, 0x13DF, 0xA4DA, 0x2CA4, 0x2CA5]),
        ('d', [0x0501, 0x0500, 0x1D05, 0x0257, 0x13A0, 0x13E7, 0xA4D2, 0xA4D3, 0x146F]),
        ('e', [0x0435, 0x0415, 0x04BD, 0x03B5, 0x0395, 0x1D07, 0x212E, 0x13AC, 0xA4F0, 0x0454]),
        ('f', [0x03DC, 0x03DD, 0xA730, 0xA4DD, 0x0584, 0x0192, 0xA798, 0xA799]),
        ('0', ['o', 'O', 0x043E, 0x041E, 0x03BF, 0x039F, 0x1D0F, 0x0585, 0x0555, 0x2C9E, 0x2C9F, 0xA4F3, 0x3007, 0x12D0]),
        ('1', ['l', 'I', 'i', 0x0456, 0x0406, 0x04CF, 0x04C0, 0x03B9, 0x0399, 0x0131, 0x01C0, 0x2223, 0x2C92, 0x2C93, 0xA4F2, 0x16C1]),
        ('2', [0x01A7, 0x01A8, 0xA644, 0xA645]),
        ('3', [0x0437, 0x0417, 0x01B7, 0x0292, 0x025C, 0x021C, 0x021D, 0xA7AB]),
        ('4', [0x13CE]),
        ('5', [0x01BC, 0x01BD]),
        ('6', [0x0431, 0x13EE]),
        ('8', [0x0222, 0x0223]),
        ('9', [0xA76E, 0xA76F]));

    private static Dictionary<int, char> Alike(params (char Letter, int[] From)[] rows)
        => rows.SelectMany(row => row.From.Select(from => (from, row.Letter))).ToDictionary(p => p.from, p => p.Letter);
}
