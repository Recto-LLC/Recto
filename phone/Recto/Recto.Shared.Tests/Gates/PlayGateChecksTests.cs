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
            + "NotOlderThan=\"@(IntermediateAssembly->'%(FullPath)')\" />",
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
