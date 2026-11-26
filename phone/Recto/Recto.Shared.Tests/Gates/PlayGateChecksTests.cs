using System.IO.Compression;
using System.Text;
using Recto.Build;
using Xunit;

namespace Recto.Shared.Tests.Gates;

/// <summary>
/// The Play gates the Android Release build runs on its own package
/// (<c>phone/gates/PlayGates.cs</c>, compiled into this project without its
/// build task): the DEX sum, and each native library's loadable-segment
/// alignment. The packages and ELF files here are made in memory.
/// </summary>
public class PlayGateChecksTests
{
    private const long Limit = PlayGateChecks.DefaultDexByteLimit;

    // --- the ELF reader ---

    [Theory]
    [InlineData(0x4000L)]
    [InlineData(0x10000L)]
    public void Elf64_AlignedTo16KbOrMore_Passes(long alignment)
    {
        var reading = PlayGateChecks.ReadElf("lib/arm64-v8a/libgood.so", Elf(is64: true, alignment, alignment));

        Assert.True(reading.Readable);
        Assert.True(reading.Is64Bit);
        Assert.Equal(2, reading.LoadSegments);
        Assert.Equal(alignment, reading.MinLoadAlignment);
        Assert.True(PlayGateChecks.PassesPageSize(reading));
    }

    [Fact]
    public void Elf64_WithOne4KbSegmentAmong16Kb_Fails_AndReportsTheSmallest()
    {
        var reading = PlayGateChecks.ReadElf("lib/arm64-v8a/libold.so", Elf(is64: true, 0x4000, 0x1000, 0x4000));

        Assert.True(reading.Readable);
        Assert.Equal(3, reading.LoadSegments);
        Assert.Equal(0x1000, reading.MinLoadAlignment);
        Assert.False(PlayGateChecks.PassesPageSize(reading));
    }

    [Fact]
    public void Elf64_SegmentsThatAreNotLoadable_AreNotJudged()
    {
        // A 4 KB alignment on a non-loadable header (PT_NOTE here) does not count.
        var bytes = Elf(is64: true, new[] { (Type: 4u, Align: 0x4L), (Type: 1u, Align: 0x4000L) });

        var reading = PlayGateChecks.ReadElf("lib/arm64-v8a/libnote.so", bytes);

        Assert.Equal(1, reading.LoadSegments);
        Assert.Equal(0x4000, reading.MinLoadAlignment);
        Assert.True(PlayGateChecks.PassesPageSize(reading));
    }

    [Fact]
    public void Elf32_At4Kb_IsListedAndNotFailed()
    {
        var reading = PlayGateChecks.ReadElf("lib/armeabi-v7a/lib32.so", Elf(is64: false, 0x1000));

        Assert.True(reading.Readable);
        Assert.False(reading.Is64Bit);
        Assert.Equal(0x1000, reading.MinLoadAlignment);
        Assert.True(PlayGateChecks.PassesPageSize(reading));
    }

    [Fact]
    public void NotAnElfFile_IsUnreadable_AndFails()
    {
        var reading = PlayGateChecks.ReadElf("lib/arm64-v8a/libtext.so", Encoding.ASCII.GetBytes(new string('x', 200)));

        Assert.False(reading.Readable);
        Assert.Equal("not an ELF file", reading.Problem);
        Assert.False(PlayGateChecks.PassesPageSize(reading));
    }

    [Fact]
    public void AnEmptyOrShortFile_IsUnreadable_AndDoesNotThrow()
    {
        Assert.False(PlayGateChecks.ReadElf("a.so", Array.Empty<byte>()).Readable);
        Assert.False(PlayGateChecks.ReadElf("b.so", new byte[] { 0x7F, (byte)'E', (byte)'L', (byte)'F' }).Readable);
    }

    [Fact]
    public void AProgramHeaderTableOutsideTheFile_IsUnreadable()
    {
        var bytes = Elf(is64: true, 0x4000, 0x4000);
        var cut = bytes.AsSpan(0, bytes.Length - 10).ToArray();

        var reading = PlayGateChecks.ReadElf("lib/arm64-v8a/libcut.so", cut);

        Assert.False(reading.Readable);
        Assert.Equal("a program header table outside the file", reading.Problem);
    }

    [Theory]
    [InlineData(true, ulong.MaxValue)]
    [InlineData(true, 0x7FFFFFFFFFFFFFFFUL)]
    [InlineData(true, 0x7FFFFFFFFFFFFFF0UL)]
    [InlineData(true, 0x8000000000000000UL)]
    [InlineData(false, 0xFFFFFFFFUL)]
    [InlineData(false, 0x7FFFFFFFUL)]
    public void ACraftedProgramHeaderOffset_NearTheTopOfTheRange_IsUnreadable_AndDoesNotThrow(bool is64, ulong offset)
    {
        // An offset this large wrapped the old check's addition to a small or negative sum, which passed
        // as "inside the file" and read far outside it.
        var bytes = Elf(is64, 0x4000, 0x4000);
        if (is64)
        {
            BitConverter.TryWriteBytes(bytes.AsSpan(0x20), offset);
        }
        else
        {
            BitConverter.TryWriteBytes(bytes.AsSpan(0x1C), (uint)offset);
        }

        var reading = PlayGateChecks.ReadElf("lib/x/libcrafted.so", bytes);

        Assert.False(reading.Readable);
        Assert.Equal("a program header table outside the file", reading.Problem);
        Assert.False(PlayGateChecks.PassesPageSize(reading));
    }

    [Theory]
    [InlineData(true, ulong.MaxValue)]
    [InlineData(true, 0x7FFFFFFFFFFFFFFFUL)]
    [InlineData(true, 0x7FFFFFFFFFFFFFF0UL)]
    [InlineData(false, 0xFFFFFFFFUL)]
    public void ACraftedSectionHeaderOffset_ReadsAsNoSymbolTable_AndDoesNotThrow(bool is64, ulong offset)
    {
        var bytes = Elf(is64, symbolTable: true, 0x4000);
        if (is64)
        {
            BitConverter.TryWriteBytes(bytes.AsSpan(0x28), offset);
        }
        else
        {
            BitConverter.TryWriteBytes(bytes.AsSpan(0x20), (uint)offset);
        }

        var reading = PlayGateChecks.ReadElf("lib/x/libcrafted.so", bytes);

        // The alignment is still read; the symbol table simply is not there.
        Assert.True(reading.Readable);
        Assert.False(reading.HasSymbolTable);
    }

    [Fact]
    public void AProgramHeaderTableThatEndsExactlyAtTheFilesEnd_IsRead()
    {
        // The boundary the subtraction must keep: the last header ends on the last byte.
        var reading = PlayGateChecks.ReadElf("lib/arm64-v8a/libexact.so", Elf(is64: true, 0x4000, 0x4000));

        Assert.True(reading.Readable);
        Assert.Equal(2, reading.LoadSegments);
    }

    [Fact]
    public void APackageOlderThanWhatTheBuildCompiled_IsRefused_AndOneAsNewOrNewer_IsNot()
    {
        var compiled = new DateTime(2026, 11, 21, 12, 0, 0, DateTimeKind.Utc);

        var stale = PlayGateChecks.StaleFailure("app.aab", compiled.AddSeconds(-1), "App.dll", compiled);
        Assert.Contains("app.aab was written 2026-11-21 11:59:59Z, before App.dll (2026-11-21 12:00:00Z)", stale);
        Assert.Contains("it is not the package this build made", stale);

        Assert.Equal(string.Empty, PlayGateChecks.StaleFailure("app.aab", compiled, "App.dll", compiled));
        Assert.Equal(string.Empty, PlayGateChecks.StaleFailure("app.aab", compiled.AddMinutes(2), "App.dll", compiled));
    }

    [Fact]
    public void AnElfWithNoLoadableSegment_IsUnreadable()
    {
        var reading = PlayGateChecks.ReadElf("lib/arm64-v8a/libnoload.so", Elf(is64: true, new[] { (Type: 4u, Align: 0x4L) }));

        Assert.False(reading.Readable);
        Assert.Equal("no loadable segment", reading.Problem);
    }

    [Fact]
    public void ABigEndianElf_IsUnreadable()
    {
        var bytes = Elf(is64: true, 0x4000);
        bytes[5] = 2;

        Assert.Equal("not little-endian", PlayGateChecks.ReadElf("lib/x/libbe.so", bytes).Problem);
    }

    // --- the package reader and the verdict ---

    [Fact]
    public void ABundle_UnderTheDexLimit_WithAlignedLibraries_Passes()
    {
        using var package = Package(
            ("base/dex/classes.dex", new byte[6_000_000]),
            ("base/dex/classes2.dex", new byte[3_999_999]),
            ("base/lib/arm64-v8a/libgood.so", Elf(is64: true, 0x4000, 0x4000)),
            ("base/lib/x86_64/libgood.so", Elf(is64: true, 0x4000)),
            ("base/manifest/AndroidManifest.xml", new byte[10]));

        var reading = PlayGateChecks.ReadPackage("app.aab", package);

        Assert.Equal(9_999_999, reading.DexBytes);
        Assert.Equal(2, reading.DexFiles.Count);
        Assert.Equal(2, reading.Libraries.Count);
        Assert.Empty(PlayGateChecks.Failures(reading, Limit));
    }

    [Fact]
    public void TheDexSum_AtTheLimit_Fails_TheLimitIsUnder()
    {
        using var package = Package(
            ("base/dex/classes.dex", new byte[6_000_000]),
            ("base/dex/classes2.dex", new byte[4_000_000]));

        var failure = Assert.Single(PlayGateChecks.Failures(PlayGateChecks.ReadPackage("app.aab", package), Limit));

        Assert.Contains("the DEX sum is 10,000,000 bytes", failure);
    }

    [Fact]
    public void AnApk_IsReadTheSameWay()
    {
        using var package = Package(
            ("classes.dex", new byte[100]),
            ("lib/arm64-v8a/libold.so", Elf(is64: true, 0x1000)));

        var reading = PlayGateChecks.ReadPackage("app.apk", package);
        var failure = Assert.Single(PlayGateChecks.Failures(reading, Limit));

        Assert.Equal(100, reading.DexBytes);
        Assert.Contains("lib/arm64-v8a/libold.so is 64-bit with a loadable segment aligned to 4,096 bytes", failure);
    }

    [Fact]
    public void EveryMiss_IsNamed_NotOnlyTheFirst()
    {
        using var package = Package(
            ("base/dex/classes.dex", new byte[10_000_001]),
            ("base/lib/arm64-v8a/libold.so", Elf(is64: true, 0x1000)),
            ("base/lib/arm64-v8a/libtext.so", new byte[80]),
            ("base/lib/armeabi-v7a/lib32.so", Elf(is64: false, 0x1000)),
            ("base/lib/arm64-v8a/libgood.so", Elf(is64: true, 0x4000)));

        var failures = PlayGateChecks.Failures(PlayGateChecks.ReadPackage("app.aab", package), Limit);

        Assert.Equal(3, failures.Count);
        Assert.Contains(failures, f => f.Contains("the DEX sum is 10,000,001 bytes"));
        Assert.Contains(failures, f => f.Contains("libold.so is 64-bit"));
        Assert.Contains(failures, f => f.Contains("libtext.so could not be read (not an ELF file)"));
    }

    [Fact]
    public void APackageWithNoDex_Fails_AGateThatCheckedNothingHasNotPassed()
    {
        using var package = Package(("base/lib/arm64-v8a/libgood.so", Elf(is64: true, 0x4000)));

        var failure = Assert.Single(PlayGateChecks.Failures(PlayGateChecks.ReadPackage("app.aab", package), Limit));

        Assert.Contains("no .dex file was found", failure);
    }

    [Fact]
    public void Describe_ListsTheDexSumAndEveryLibraryWithItsAlignment()
    {
        using var package = Package(
            ("base/dex/classes.dex", new byte[1234]),
            ("base/lib/arm64-v8a/libgood.so", Elf(is64: true, 0x4000)),
            ("base/lib/arm64-v8a/libold.so", Elf(is64: true, 0x1000)),
            ("base/lib/armeabi-v7a/lib32.so", Elf(is64: false, 0x1000)));

        var lines = PlayGateChecks.Describe(PlayGateChecks.ReadPackage("app.aab", package), Limit);

        Assert.Equal(5, lines.Count);
        Assert.Contains("DEX sum 1,234 bytes in 1 file(s), limit under 10,000,000", lines[0]);
        Assert.Contains("no R8 mapping carried", lines[1]);
        Assert.Contains("libgood.so: 64-bit, 1 loadable segment(s), smallest alignment 16,384 (16 KB: yes)", lines[2]);
        Assert.Contains("libold.so: 64-bit, 1 loadable segment(s), smallest alignment 4,096 (16 KB: NO)", lines[3]);
        Assert.Contains("lib32.so: 32-bit, 1 loadable segment(s), smallest alignment 4,096 (not judged)", lines[4]);
    }

    // --- the upload files: the R8 mapping and the native symbols ---

    [Fact]
    public void ABundleWithItsR8Mapping_Passes_AndOneWithout_FailsWhenTheMappingIsRequired()
    {
        using var with = Package(
            ("base/dex/classes.dex", new byte[100]),
            (PlayGateChecks.ProguardMapEntry, new byte[2048]));
        using var without = Package(("base/dex/classes.dex", new byte[100]));
        using var empty = Package(
            ("base/dex/classes.dex", new byte[100]),
            (PlayGateChecks.ProguardMapEntry, Array.Empty<byte>()));

        var carried = PlayGateChecks.ReadPackage("app.aab", with);
        Assert.Equal(2048, carried.ProguardMapBytes);
        Assert.Empty(PlayGateChecks.Failures(carried, Limit, requireProguardMap: true));
        Assert.Contains("R8 mapping carried for Play, 2,048 bytes", PlayGateChecks.Describe(carried, Limit)[1]);

        var missing = PlayGateChecks.ReadPackage("app.aab", without);
        Assert.Equal(-1, missing.ProguardMapBytes);
        Assert.Contains("carries no R8 mapping", Assert.Single(PlayGateChecks.Failures(missing, Limit, requireProguardMap: true)));
        // An .apk carries none by design, so the build asks for it of a bundle only.
        Assert.Empty(PlayGateChecks.Failures(missing, Limit));

        Assert.Single(PlayGateChecks.Failures(PlayGateChecks.ReadPackage("app.aab", empty), Limit, requireProguardMap: true));
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void TheElfReader_SeesASymbolTable_OnlyWhereThereIsOne(bool is64)
    {
        Assert.True(PlayGateChecks.ReadElf("a.so", Elf(is64, symbolTable: true, 0x4000)).HasSymbolTable);
        Assert.False(PlayGateChecks.ReadElf("b.so", Elf(is64, 0x4000)).HasSymbolTable);
    }

    [Fact]
    public void TheSymbolsZip_HoldsOnlyTheLibrariesThatCarryASymbolTable_ByAbi()
    {
        var folder = Directory.CreateTempSubdirectory("recto-play-gates-").FullName;
        try
        {
            var packagePath = Path.Combine(folder, "app.aab");
            var zipPath = Path.Combine(folder, "native-debug-symbols.zip");
            var withSymbols = Elf(is64: true, symbolTable: true, 0x4000);
            using (var package = Package(
                ("base/dex/classes.dex", new byte[100]),
                ("base/lib/arm64-v8a/libsym.so", withSymbols),
                ("base/lib/x86_64/libsym.so", withSymbols),
                ("base/lib/arm64-v8a/libstripped.so", Elf(is64: true, 0x4000)),
                ("base/lib/arm64-v8a/libtext.so", new byte[80])))
            {
                File.WriteAllBytes(packagePath, package.ToArray());
            }

            var written = PlayGateChecks.WriteNativeSymbols(packagePath, zipPath);

            Assert.Equal(new[] { "arm64-v8a/libsym.so", "x86_64/libsym.so" }, written);
            using var zip = ZipFile.OpenRead(zipPath);
            Assert.Equal(written, zip.Entries.Select(e => e.FullName).ToArray());
            using var copy = new MemoryStream();
            using (var opened = zip.Entries[0].Open())
            {
                opened.CopyTo(copy);
            }
            Assert.Equal(withSymbols, copy.ToArray());
        }
        finally
        {
            Directory.Delete(folder, recursive: true);
        }
    }

    [Fact]
    public void WithNoSymbolTableAnywhere_NoZipIsWritten_AndAnOldOneIsRemoved()
    {
        var folder = Directory.CreateTempSubdirectory("recto-play-gates-").FullName;
        try
        {
            var packagePath = Path.Combine(folder, "app.aab");
            var zipPath = Path.Combine(folder, "native-debug-symbols.zip");
            File.WriteAllText(zipPath, "an older build's zip");
            using (var package = Package(("base/lib/arm64-v8a/libstripped.so", Elf(is64: true, 0x4000))))
            {
                File.WriteAllBytes(packagePath, package.ToArray());
            }

            Assert.Empty(PlayGateChecks.WriteNativeSymbols(packagePath, zipPath));
            Assert.False(File.Exists(zipPath));
        }
        finally
        {
            Directory.Delete(folder, recursive: true);
        }
    }

    // --- the NDK floor: a library built by an old NDK is named, even when it is aligned ---

    [Theory]
    [InlineData("r20", 20)]
    [InlineData("r27", 27)]
    [InlineData("r27c", 27)]
    [InlineData("r28b", 28)]
    [InlineData("r9", 9)]
    [InlineData("", 0)]
    [InlineData("27", 0)]
    [InlineData("rc1", 0)]
    [InlineData("unnamed", 0)]
    public void TheNdkNumber_IsReadFromItsName(string version, int major)
    {
        Assert.Equal(major, PlayGateChecks.NdkMajorOf(version));
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void TheElfReader_ReadsTheNdkFromTheAndroidNote(bool is64)
    {
        var library = PlayGateChecks.ReadElf("libold.so", ElfWithNote(is64, AndroidNote(21, "r20", "5594570")));

        Assert.True(library.Readable, library.Problem);
        Assert.Equal("r20", library.NdkVersion);
        Assert.Equal(20, library.NdkMajor);
        Assert.Equal(1, library.LoadSegments);
        Assert.Equal(0x4000, library.MinLoadAlignment);
    }

    [Fact]
    public void ALibraryWithNoAndroidNote_NamesNoNdk()
    {
        Assert.Equal(string.Empty, PlayGateChecks.ReadElf("a.so", Elf(is64: true, 0x4000)).NdkVersion);
        // Another vendor's note in the segment is not Android's.
        var other = PlayGateChecks.ReadElf("b.so", ElfWithNote(true, Note("GNU", 3, new byte[20])));
        Assert.True(other.Readable);
        Assert.Equal(string.Empty, other.NdkVersion);
        // The Android note after another note is still found.
        var second = PlayGateChecks.ReadElf(
            "c.so", ElfWithNote(true, Note("GNU", 3, new byte[20]).Concat(AndroidNote(24, "r27", "12077973")).ToArray()));
        Assert.Equal("r27", second.NdkVersion);
    }

    [Fact]
    public void AnAndroidNoteTooShortToNameAnNdk_ReadsAsUnnamed_AndIsBelowEveryFloor()
    {
        var library = PlayGateChecks.ReadElf("libancient.so", ElfWithNote(true, Note("Android", 1, new byte[4])));

        Assert.Equal(PlayGateChecks.UnnamedNdk, library.NdkVersion);
        Assert.False(PlayGateChecks.PassesNdkFloor(library, 27));
        Assert.True(PlayGateChecks.PassesNdkFloor(library, 0));
    }

    [Fact]
    public void AnOldNdkLibrary_FailsUnderTheFloor_ByNameAndNdk()
    {
        using var package = Package(
            ("base/dex/classes.dex", new byte[100]),
            ("base/lib/arm64-v8a/libold.so", ElfWithNote(true, AndroidNote(21, "r20", "5594570"))));

        var failure = Assert.Single(PlayGateChecks.Failures(
            PlayGateChecks.ReadPackage("app.aab", package), Limit, minNdkMajor: PlayGateChecks.DefaultMinNdkMajor));

        Assert.Contains("base/lib/arm64-v8a/libold.so", failure);
        Assert.Contains("NDK r20", failure);
        Assert.Contains("r27 or newer", failure);
        Assert.Equal(27, PlayGateChecks.DefaultMinNdkMajor);
    }

    [Theory]
    [InlineData("r27")]
    [InlineData("r27c")]
    [InlineData("r28")]
    [InlineData("r30b")]
    public void ACurrentNdkLibrary_Passes(string ndk)
    {
        using var package = Package(
            ("base/dex/classes.dex", new byte[100]),
            ("base/lib/arm64-v8a/libnew.so", ElfWithNote(true, AndroidNote(24, ndk, "12077973"))));

        Assert.Empty(PlayGateChecks.Failures(PlayGateChecks.ReadPackage("app.aab", package), Limit, minNdkMajor: 27));
    }

    [Fact]
    public void ALibraryWithNoNote_IsListed_AndPasses()
    {
        using var package = Package(
            ("base/dex/classes.dex", new byte[100]),
            ("base/lib/arm64-v8a/libruntime.so", Elf(is64: true, 0x4000)));
        var reading = PlayGateChecks.ReadPackage("app.aab", package);

        Assert.Empty(PlayGateChecks.Failures(reading, Limit, minNdkMajor: 27));
        Assert.Contains("libruntime.so: 64-bit, 1 loadable segment(s), smallest alignment 16,384 (16 KB: yes), no NDK note.",
            PlayGateChecks.Describe(reading, Limit)[2]);
    }

    [Fact]
    public void OneOldLibraryAmongGoodOnes_IsExactlyOneFailure_AndEveryLibraryIsListedWithItsNdk()
    {
        using var package = Package(
            ("base/dex/classes.dex", new byte[100]),
            ("base/lib/arm64-v8a/libnew.so", ElfWithNote(true, AndroidNote(24, "r27", "12077973"))),
            ("base/lib/arm64-v8a/libold.so", ElfWithNote(true, AndroidNote(21, "r20", "5594570"))),
            ("base/lib/arm64-v8a/libruntime.so", Elf(is64: true, 0x4000)),
            ("base/lib/armeabi-v7a/libold32.so", ElfWithNote(false, AndroidNote(21, "r20", "5594570"))));
        var reading = PlayGateChecks.ReadPackage("app.aab", package);

        var failure = Assert.Single(PlayGateChecks.Failures(reading, Limit, minNdkMajor: 27));
        Assert.Contains("libold.so", failure);
        var lines = PlayGateChecks.Describe(reading, Limit);
        Assert.Contains("libnew.so", lines[2]);
        Assert.EndsWith("NDK r27.", lines[2]);
        Assert.EndsWith("NDK r20.", lines[3]);
        Assert.EndsWith("no NDK note.", lines[4]);
        // A 32-bit library is listed with its NDK and never failed, as for the page size.
        Assert.EndsWith("NDK r20.", lines[5]);
    }

    [Fact]
    public void AFloorOfZero_JudgesNoNdk_AndTheOtherGatesStillFail()
    {
        using var package = Package(
            ("base/dex/classes.dex", new byte[100]),
            ("base/lib/arm64-v8a/libold.so", ElfWithNote(true, AndroidNote(21, "r20", "5594570"))),
            ("base/lib/arm64-v8a/libunaligned.so", Elf(is64: true, 0x1000)));
        var reading = PlayGateChecks.ReadPackage("app.aab", package);

        var failure = Assert.Single(PlayGateChecks.Failures(reading, Limit, minNdkMajor: 0));
        Assert.Contains("libunaligned.so", failure);
        Assert.Contains("NDK r20", PlayGateChecks.Describe(reading, Limit)[2]);
    }

    [Fact]
    public void AnOldNdkLibraryThatIsAlsoUnaligned_FailsBothGates()
    {
        var bytes = ElfWithNote(true, AndroidNote(21, "r20", "5594570"), loadAlignment: 0x1000);
        using var package = Package(("base/dex/classes.dex", new byte[100]), ("base/lib/arm64-v8a/libboth.so", bytes));

        var failures = PlayGateChecks.Failures(PlayGateChecks.ReadPackage("app.aab", package), Limit, minNdkMajor: 27);

        Assert.Equal(2, failures.Count);
        Assert.Contains("16 KB pages need", failures[0]);
        Assert.Contains("NDK r20", failures[1]);
    }

    [Theory]
    [InlineData(true, ulong.MaxValue - 4, 8ul)]        // an offset that would wrap an addition
    [InlineData(true, 0x1000ul, 8ul)]                  // an offset past the end
    [InlineData(true, 0x40ul, 0x100000ul)]             // a size past the end
    [InlineData(true, 0ul, ulong.MaxValue)]
    [InlineData(false, 0xFFFFFFF0ul, 0x20ul)]
    [InlineData(false, 0x34ul, 0xFFFFFFFFul)]
    public void ANoteSegmentOutsideTheFile_IsUnreadable_AndFailsWithoutThrowing(bool is64, ulong offset, ulong size)
    {
        var bytes = ElfWithNote(is64, AndroidNote(24, "r27", "12077973"));
        var noteHeader = (is64 ? 0x40 : 0x34) + (is64 ? 0x38 : 0x20);
        if (is64)
        {
            BitConverter.TryWriteBytes(bytes.AsSpan(noteHeader + 0x08), offset);
            BitConverter.TryWriteBytes(bytes.AsSpan(noteHeader + 0x20), size);
        }
        else
        {
            BitConverter.TryWriteBytes(bytes.AsSpan(noteHeader + 0x04), (uint)offset);
            BitConverter.TryWriteBytes(bytes.AsSpan(noteHeader + 0x10), (uint)size);
        }

        var library = PlayGateChecks.ReadElf("libbad.so", bytes);

        Assert.False(library.Readable);
        Assert.Equal("a note segment outside the file", library.Problem);
        using var package = Package(("base/dex/classes.dex", new byte[100]), ("base/lib/arm64-v8a/libbad.so", bytes));
        Assert.Contains("could not be read", Assert.Single(
            PlayGateChecks.Failures(PlayGateChecks.ReadPackage("app.aab", package), Limit, minNdkMajor: 27)));
    }

    [Theory]
    [InlineData(0xFFFFFFFFu, 4u)]      // a name that runs past the segment
    [InlineData(8u, 0xFFFFFFFFu)]      // a description that runs past the segment
    [InlineData(0xFFFFFFFCu, 0xFFFFFFFCu)]
    [InlineData(0u, 0u)]
    public void ANoteWhoseSizesRunPastItsSegment_EndsTheWalk_WithoutThrowing(uint nameSize, uint descSize)
    {
        var note = AndroidNote(24, "r27", "12077973");
        BitConverter.TryWriteBytes(note.AsSpan(0), nameSize);
        BitConverter.TryWriteBytes(note.AsSpan(4), descSize);

        var library = PlayGateChecks.ReadElf("libodd.so", ElfWithNote(true, note));

        Assert.True(library.Readable);
        Assert.Equal(string.Empty, library.NdkVersion);
    }

    [Fact]
    public void AnNdkNameThatIsNotText_IsShownAsQuestionMarks_AndIsBelowTheFloor()
    {
        var note = AndroidNote(24, "r27", "1");
        // The first two bytes of the version: a control character and a byte above ASCII.
        var versionAt = 12 + 8 + 4;
        note[versionAt] = 0x1B;
        note[versionAt + 1] = 0xC3;

        var library = PlayGateChecks.ReadElf("libodd.so", ElfWithNote(true, note));

        Assert.Equal("??7", library.NdkVersion);
        Assert.Equal(0, library.NdkMajor);
        Assert.False(PlayGateChecks.PassesNdkFloor(library, 27));
    }

    [Fact]
    public void TheBuild_HandsTheGateItsNdkFloor_AndThePinnedLibraryIsTheRebuiltOne()
    {
        var project = File.ReadAllText(PhonePath("Recto", "Recto.csproj"));
        Assert.Contains("<RectoPlayMinNdkMajor Condition=\"'$(RectoPlayMinNdkMajor)' == ''\">27</RectoPlayMinNdkMajor>", project);
        Assert.Contains("MinNdkMajor=\"$(RectoPlayMinNdkMajor)\"", project);

        var task = File.ReadAllText(PhonePath("..", "gates", "PlayGates.cs"));
        Assert.Contains("public int MinNdkMajor { get; set; } = PlayGateChecks.DefaultMinNdkMajor;", task);
        Assert.Contains("minNdkMajor: MinNdkMajor", task);

        // DataStore and its siblings move together, at the first version whose library was rebuilt.
        var props = File.ReadAllText(PhonePath("..", "Directory.Packages.props"));
        var family = System.Text.RegularExpressions.Regex.Matches(
            props, "<PackageVersion Include=\"Xamarin\\.AndroidX\\.DataStore[A-Za-z.]*\" Version=\"([^\"]+)\" />");
        Assert.Equal(13, family.Count);
        Assert.All(family, m => Assert.Equal("1.3.0", m.Groups[1].Value));
        foreach (System.Text.RegularExpressions.Match m in System.Text.RegularExpressions.Regex.Matches(
                     props, "<PackageVersion Include=\"(Xamarin\\.AndroidX\\.(DataStore|Collection)[A-Za-z.]*)\""))
        {
            Assert.Contains("<PackageReference Include=\"" + m.Groups[1].Value + "\" />", project);
        }
    }

    // --- the build wiring, pinned from the project's text ---

    [Fact]
    public void TheAndroidReleaseBuild_RunsTheGatesOnItsPackage_AndWritesTheUploadFiles()
    {
        var project = File.ReadAllText(PhonePath("Recto", "Recto.csproj"));

        // The task is this file, compiled by the build; the target runs after the package is signed.
        Assert.Contains("TaskName=\"CheckPlayGates\"", project);
        Assert.Contains("Source=\"$(MSBuildThisFileDirectory)../../gates/PlayGates.cs\"", project);
        // Two hooks onto the one gate target: a command-line build signs the package inside Build, an IDE
        // build in SignAndroidPackage. Both are for the Android Release build only.
        const string release = "$(TargetFramework.Contains('-android')) AND '$(Configuration)' == 'Release'";
        Assert.Contains(
            "<Target Name=\"RectoPlayGatesAfterBuild\" AfterTargets=\"Build\" DependsOnTargets=\"RectoPlayGates\" "
            + "Condition=\"" + release + " AND '$(BuildingInsideVisualStudio)' != 'true'\" />",
            project);
        Assert.Contains(
            "<Target Name=\"RectoPlayGatesAfterSign\" AfterTargets=\"SignAndroidPackage\" DependsOnTargets=\"RectoPlayGates\" "
            + "Condition=\"" + release + "\" />",
            project);
        Assert.Contains("<Target Name=\"RectoPlayGates\">", project);
        Assert.Contains(
            "<CheckPlayGates Packages=\"@(RectoPlayPackage)\" DexByteLimit=\"$(RectoPlayDexByteLimit)\" "
            + "SymbolsZip=\"$(OutDir)native-debug-symbols.zip\" "
            + "NotOlderThan=\"@(IntermediateAssembly->'%(FullPath)')\" "
            + "MinNdkMajor=\"$(RectoPlayMinNdkMajor)\" />",
            project);
        // The package checked is this build's: the signed package in the build's format, and the universal
        // .apk only when the format is aab and the formats also name apk. Named outright - no Exists() lets a
        // missing one pass, no wildcard picks up a leftover - and refused when it is older than the assembly
        // this build compiled.
        Assert.Contains(
            "<RectoPlayPackage Include=\"$(OutDir)$(ApplicationId)-Signed.$(AndroidPackageFormat)\" />", project);
        Assert.Contains(
            "<RectoPlayPackage Include=\"$(OutDir)$(ApplicationId)-Signed.apk\" "
            + "Condition=\"'$(AndroidPackageFormat)' == 'aab' AND $(AndroidPackageFormats.Contains('apk'))\" />",
            project);
        Assert.Equal(3, project.Split("RectoPlayPackage").Length - 1);
        Assert.DoesNotContain("Exists(", project.Substring(project.IndexOf("<Target Name=\"RectoPlayGates\">", StringComparison.Ordinal)));
        Assert.DoesNotContain("*.aab", project);
        // A missing package, or a missing reference file, is refused by name before any time is compared.
        var task = File.ReadAllText(PhonePath("..", "gates", "PlayGates.cs"));
        var exists = task.IndexOf("if (!File.Exists(package.ItemSpec))", StringComparison.Ordinal);
        var reference = task.IndexOf("if (NotOlderThan.Length != 0 && !File.Exists(NotOlderThan))", StringComparison.Ordinal);
        var compared = task.IndexOf("File.GetLastWriteTimeUtc(package.ItemSpec)", StringComparison.Ordinal);
        Assert.True(exists > 0 && reference > exists && compared > reference);
        Assert.Contains("was not found: this build did not make the package it is set to make.", task);
        Assert.Contains("<AndroidCreateProguardMappingFile>true</AndroidCreateProguardMappingFile>", project);
        // DataStore's native library is this project's own reference, at a version the props file names.
        Assert.Contains("<PackageReference Include=\"Xamarin.AndroidX.DataStore.Core.Android\" />", project);
        Assert.Contains(
            "<PackageVersion Include=\"Xamarin.AndroidX.DataStore.Core.Android\" Version=\"",
            File.ReadAllText(PhonePath("..", "Directory.Packages.props")));
        Assert.Contains("<RectoPlayDexByteLimit Condition=\"'$(RectoPlayDexByteLimit)' == ''\">10000000</RectoPlayDexByteLimit>", project);
        // No switch turns the gates off.
        Assert.DoesNotContain("RectoSkipPlayGates", project);
        Assert.DoesNotContain("ContinueOnError", project);
        // The same source is what these tests compile.
        var tests = File.ReadAllText(PhonePath("Recto.Shared.Tests", "Recto.Shared.Tests.csproj"));
        Assert.Contains("gates\\PlayGates.cs", tests);
        Assert.Contains("PLAY_GATES_LOGIC_ONLY", tests);
    }

    // --- helpers ---

    private static byte[] Elf(bool is64, params long[] loadAlignments)
        => Elf(is64, loadAlignments.Select(a => (Type: 1u, Align: a)).ToArray());

    private static byte[] Elf(bool is64, bool symbolTable, params long[] loadAlignments)
        => Elf(is64, loadAlignments.Select(a => (Type: 1u, Align: a)).ToArray(), symbolTable);

    /// <summary>
    /// A minimal little-endian ELF: the header, then one program header per
    /// entry, then - when asked - a section header table of a null section
    /// and a symbol table.
    /// </summary>
    private static byte[] Elf(bool is64, (uint Type, long Align)[] headers, bool symbolTable = false)
    {
        var headerSize = is64 ? 0x40 : 0x34;
        var entrySize = is64 ? 0x38 : 0x20;
        var sectionSize = is64 ? 0x40 : 0x28;
        var sectionsAt = headerSize + (entrySize * headers.Length);
        var bytes = new byte[sectionsAt + (symbolTable ? sectionSize * 2 : 0)];
        if (symbolTable)
        {
            if (is64)
            {
                BitConverter.TryWriteBytes(bytes.AsSpan(0x28), (ulong)sectionsAt);
                BitConverter.TryWriteBytes(bytes.AsSpan(0x3A), (ushort)sectionSize);
                BitConverter.TryWriteBytes(bytes.AsSpan(0x3C), (ushort)2);
            }
            else
            {
                BitConverter.TryWriteBytes(bytes.AsSpan(0x20), (uint)sectionsAt);
                BitConverter.TryWriteBytes(bytes.AsSpan(0x2E), (ushort)sectionSize);
                BitConverter.TryWriteBytes(bytes.AsSpan(0x30), (ushort)2);
            }
            // The second section's type: a symbol table.
            BitConverter.TryWriteBytes(bytes.AsSpan(sectionsAt + sectionSize + 4), 2u);
        }
        bytes[0] = 0x7F; bytes[1] = (byte)'E'; bytes[2] = (byte)'L'; bytes[3] = (byte)'F';
        bytes[4] = (byte)(is64 ? 2 : 1);
        bytes[5] = 1;
        if (is64)
        {
            BitConverter.TryWriteBytes(bytes.AsSpan(0x20), (ulong)headerSize);
            BitConverter.TryWriteBytes(bytes.AsSpan(0x36), (ushort)entrySize);
            BitConverter.TryWriteBytes(bytes.AsSpan(0x38), (ushort)headers.Length);
        }
        else
        {
            BitConverter.TryWriteBytes(bytes.AsSpan(0x1C), (uint)headerSize);
            BitConverter.TryWriteBytes(bytes.AsSpan(0x2A), (ushort)entrySize);
            BitConverter.TryWriteBytes(bytes.AsSpan(0x2C), (ushort)headers.Length);
        }
        for (var i = 0; i < headers.Length; i++)
        {
            var at = headerSize + (entrySize * i);
            BitConverter.TryWriteBytes(bytes.AsSpan(at), headers[i].Type);
            if (is64)
            {
                BitConverter.TryWriteBytes(bytes.AsSpan(at + 0x30), (ulong)headers[i].Align);
            }
            else
            {
                BitConverter.TryWriteBytes(bytes.AsSpan(at + 0x1C), (uint)headers[i].Align);
            }
        }
        return bytes;
    }

    /// <summary>One ELF note: the three sizes, the name with its NUL, the description, each padded to four bytes.</summary>
    private static byte[] Note(string name, uint type, byte[] description)
    {
        var nameBytes = System.Text.Encoding.ASCII.GetBytes(name + "\0");
        var namePadded = (nameBytes.Length + 3) & ~3;
        var descPadded = (description.Length + 3) & ~3;
        var note = new byte[12 + namePadded + descPadded];
        BitConverter.TryWriteBytes(note.AsSpan(0), (uint)nameBytes.Length);
        BitConverter.TryWriteBytes(note.AsSpan(4), (uint)description.Length);
        BitConverter.TryWriteBytes(note.AsSpan(8), type);
        nameBytes.CopyTo(note, 12);
        description.CopyTo(note, 12 + namePadded);
        return note;
    }

    /// <summary>The note the NDK writes: the API level, then 64 bytes of NDK version, then 64 of build number.</summary>
    private static byte[] AndroidNote(uint api, string ndk, string build)
    {
        var description = new byte[4 + 64 + 64];
        BitConverter.TryWriteBytes(description.AsSpan(0), api);
        System.Text.Encoding.ASCII.GetBytes(ndk).CopyTo(description, 4);
        System.Text.Encoding.ASCII.GetBytes(build).CopyTo(description, 4 + 64);
        return Note("Android", 1, description);
    }

    /// <summary>A minimal ELF of one loadable segment and one note segment whose bytes follow the headers.</summary>
    private static byte[] ElfWithNote(bool is64, byte[] notes, long loadAlignment = 0x4000)
    {
        var headers = Elf(is64, new[] { (Type: 1u, Align: loadAlignment), (Type: 4u, Align: 4L) });
        var bytes = new byte[headers.Length + notes.Length];
        headers.CopyTo(bytes, 0);
        notes.CopyTo(bytes, headers.Length);
        var noteHeader = (is64 ? 0x40 : 0x34) + (is64 ? 0x38 : 0x20);
        if (is64)
        {
            BitConverter.TryWriteBytes(bytes.AsSpan(noteHeader + 0x08), (ulong)headers.Length);
            BitConverter.TryWriteBytes(bytes.AsSpan(noteHeader + 0x20), (ulong)notes.Length);
        }
        else
        {
            BitConverter.TryWriteBytes(bytes.AsSpan(noteHeader + 0x04), (uint)headers.Length);
            BitConverter.TryWriteBytes(bytes.AsSpan(noteHeader + 0x10), (uint)notes.Length);
        }
        return bytes;
    }

    private static MemoryStream Package(params (string Name, byte[] Bytes)[] entries)
    {
        var stream = new MemoryStream();
        using (var zip = new ZipArchive(stream, ZipArchiveMode.Create, leaveOpen: true))
        {
            foreach (var (name, bytes) in entries)
            {
                using var written = zip.CreateEntry(name, CompressionLevel.Fastest).Open();
                written.Write(bytes);
            }
        }
        stream.Position = 0;
        return stream;
    }

    private static string PhonePath(params string[] parts)
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "Recto", "MauiProgram.cs")))
        {
            dir = dir.Parent;
        }
        Assert.NotNull(dir);
        return Path.Combine(dir!.FullName, Path.Combine(parts));
    }
}
