#nullable enable
// The Play gates: what Google Play checks on an uploaded Android package,
// checked here on the package the build just made, so a miss fails the build
// and not the upload.
//
//   1. The DEX sum: the uncompressed bytes of every .dex in the package stay
//      under a limit (10,000,000 by default).
//   2. The 16 KB page size: every 64-bit native library's loadable segments
//      are aligned to at least 16,384 bytes. A 32-bit library is listed and
//      never failed: no 32-bit device runs 16 KB pages.
//   3. The upload files: an app bundle carries the R8 mapping Play reads to
//      de-obfuscate a Java stack, and the native libraries that still carry
//      a symbol table are written to a zip in the layout Google documents
//      for a hand-made symbols zip (one folder per ABI at the root, each
//      unstripped library under its own name). No upload has confirmed
//      that Play takes this zip.
//   4. The package is this build's: one older than the app assembly the
//      build compiled is refused, so a leftover from an earlier build is
//      never the one that passes.
//   5. The NDK floor: a 64-bit native library that says which Android NDK
//      built it (the .note.android.ident note) says r27 or newer. Play's
//      16 KB notice names a library built by an older NDK even when its
//      segments are aligned. A library with no such note (the .NET runtime's
//      own are linked without one) is listed and never failed for it.
//
// One file, two readers. Recto.csproj compiles it as an inline build task
// (RoslynCodeTaskFactory, which builds against netstandard2.0: no records, no
// spans). The test project compiles the same file with PLAY_GATES_LOGIC_ONLY
// defined, which leaves the build task out, and tests the checks directly.

using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.IO.Compression;

namespace Recto.Build
{
    /// <summary>One native library as the package carries it.</summary>
    public sealed class NativeLibraryReading
    {
        public NativeLibraryReading(
            string entry, bool readable, bool is64Bit, int loadSegments, long minLoadAlignment, bool hasSymbolTable, string problem,
            string ndkVersion = "", int ndkMajor = 0)
        {
            Entry = entry;
            Readable = readable;
            Is64Bit = is64Bit;
            LoadSegments = loadSegments;
            MinLoadAlignment = minLoadAlignment;
            HasSymbolTable = hasSymbolTable;
            Problem = problem;
            NdkVersion = ndkVersion;
            NdkMajor = ndkMajor;
        }

        /// <summary>
        /// The NDK the library's Android note names ("r27", "r28b"); empty
        /// when the file carries no Android note. A note too short to name an
        /// NDK reads as <see cref="PlayGateChecks.UnnamedNdk"/>.
        /// </summary>
        public string NdkVersion { get; }

        /// <summary>The number in <see cref="NdkVersion"/>; zero when there is no note, or its version is not rNN.</summary>
        public int NdkMajor { get; }

        /// <summary>The library's path inside the package.</summary>
        public string Entry { get; }

        /// <summary>False when the bytes are not an ELF file this reader understands.</summary>
        public bool Readable { get; }

        public bool Is64Bit { get; }

        /// <summary>How many loadable (PT_LOAD) segments the file declares.</summary>
        public int LoadSegments { get; }

        /// <summary>The smallest alignment any loadable segment declares; zero when there is none.</summary>
        public long MinLoadAlignment { get; }

        /// <summary>True when the file still carries a symbol table (a .symtab section): it was not stripped.</summary>
        public bool HasSymbolTable { get; }

        /// <summary>Why the file could not be read; empty when it could.</summary>
        public string Problem { get; }
    }

    /// <summary>What one package (.aab or .apk) carries, as the gates read it.</summary>
    public sealed class PlayPackageReading
    {
        public PlayPackageReading(string package)
        {
            Package = package;
        }

        public string Package { get; }

        /// <summary>Each .dex entry and its uncompressed length.</summary>
        public List<KeyValuePair<string, long>> DexFiles { get; } = new List<KeyValuePair<string, long>>();

        public List<NativeLibraryReading> Libraries { get; } = new List<NativeLibraryReading>();

        /// <summary>The length of the R8 mapping an app bundle carries for Play; -1 when it carries none.</summary>
        public long ProguardMapBytes { get; set; } = -1;

        public long DexBytes
        {
            get
            {
                long sum = 0;
                foreach (var dex in DexFiles) sum += dex.Value;
                return sum;
            }
        }
    }

    public static class PlayGateChecks
    {
        /// <summary>The DEX sum a package must stay under.</summary>
        public const long DefaultDexByteLimit = 10000000;

        /// <summary>16 KB: the alignment a 64-bit library's loadable segments need.</summary>
        public const long PageSize16Kb = 16384;

        /// <summary>Where an app bundle carries the R8 mapping Play reads.</summary>
        public const string ProguardMapEntry = "BUNDLE-METADATA/com.android.tools.build.obfuscation/proguard.map";

        /// <summary>The oldest NDK a 64-bit library's Android note may name.</summary>
        public const int DefaultMinNdkMajor = 27;

        /// <summary>What an Android note that names no NDK reads as: older than any floor.</summary>
        public const string UnnamedNdk = "unnamed";

        private const int PtLoad = 1;
        private const int PtNote = 4;
        private const int ShtSymtab = 2;

        /// <summary>Reads a package file from disk.</summary>
        public static PlayPackageReading ReadPackage(string path)
        {
            using (var stream = File.OpenRead(path))
            {
                return ReadPackage(Path.GetFileName(path), stream);
            }
        }

        /// <summary>Reads a package (a zip) from a stream: every .dex entry's length, every .so entry's ELF header.</summary>
        public static PlayPackageReading ReadPackage(string name, Stream package)
        {
            var reading = new PlayPackageReading(name);
            using (var zip = new ZipArchive(package, ZipArchiveMode.Read, leaveOpen: true))
            {
                foreach (var entry in zip.Entries)
                {
                    if (entry.FullName.EndsWith(".dex", StringComparison.OrdinalIgnoreCase))
                    {
                        reading.DexFiles.Add(new KeyValuePair<string, long>(entry.FullName, entry.Length));
                    }
                    else if (string.Equals(entry.FullName, ProguardMapEntry, StringComparison.Ordinal))
                    {
                        reading.ProguardMapBytes = entry.Length;
                    }
                    else if (entry.FullName.EndsWith(".so", StringComparison.OrdinalIgnoreCase))
                    {
                        using (var opened = entry.Open())
                        using (var copy = new MemoryStream())
                        {
                            opened.CopyTo(copy);
                            reading.Libraries.Add(ReadElf(entry.FullName, copy.ToArray()));
                        }
                    }
                }
            }
            return reading;
        }

        /// <summary>
        /// Reads an ELF file's program headers. Never throws on a malformed
        /// file: the reading says it was not readable, and why.
        /// </summary>
        public static NativeLibraryReading ReadElf(string entry, byte[] bytes)
        {
            if (bytes.Length < 0x34 || bytes[0] != 0x7F || bytes[1] != (byte)'E' || bytes[2] != (byte)'L' || bytes[3] != (byte)'F')
            {
                return Unreadable(entry, "not an ELF file");
            }
            var elfClass = bytes[4];
            if (elfClass != 1 && elfClass != 2)
            {
                return Unreadable(entry, "an ELF class that is neither 32-bit nor 64-bit");
            }
            if (bytes[5] != 1)
            {
                return Unreadable(entry, "not little-endian");
            }
            var is64 = elfClass == 2;
            if (is64 && bytes.Length < 0x40)
            {
                return Unreadable(entry, "a 64-bit ELF header cut short");
            }

            long tableOffset = is64 ? (long)ReadUInt64(bytes, 0x20) : ReadUInt32(bytes, 0x1C);
            int entrySize = ReadUInt16(bytes, is64 ? 0x36 : 0x2A);
            int entryCount = ReadUInt16(bytes, is64 ? 0x38 : 0x2C);
            var smallestEntry = is64 ? 0x38 : 0x20;
            if (entryCount == 0)
            {
                return Unreadable(entry, "no program headers");
            }
            // Compared by subtraction: an offset near the top of the range
            // would wrap an addition and pass. entrySize and entryCount are
            // 16-bit, so their product cannot overflow a long.
            long tableBytes = (long)entrySize * entryCount;
            if (entrySize < smallestEntry || tableOffset <= 0 || tableOffset > bytes.Length - tableBytes)
            {
                return Unreadable(entry, "a program header table outside the file");
            }

            var loads = 0;
            long min = long.MaxValue;
            var ndkVersion = string.Empty;
            for (var i = 0; i < entryCount; i++)
            {
                var at = (int)(tableOffset + ((long)entrySize * i));
                if (ReadUInt32(bytes, at) == PtNote)
                {
                    ulong noteOffset = is64 ? ReadUInt64(bytes, at + 0x08) : ReadUInt32(bytes, at + 0x04);
                    ulong noteSize = is64 ? ReadUInt64(bytes, at + 0x20) : ReadUInt32(bytes, at + 0x10);
                    // By subtraction, as for the tables: no addition to wrap.
                    if (noteSize > (ulong)bytes.Length || noteOffset > (ulong)bytes.Length - noteSize)
                    {
                        return Unreadable(entry, "a note segment outside the file");
                    }
                    var found = AndroidNdkNote(bytes, (int)noteOffset, (int)noteSize);
                    if (found.Length != 0)
                    {
                        ndkVersion = found;
                    }
                    continue;
                }
                if (ReadUInt32(bytes, at) != PtLoad)
                {
                    continue;
                }
                loads++;
                var declared = is64 ? ReadUInt64(bytes, at + 0x30) : ReadUInt32(bytes, at + 0x1C);
                var alignment = declared > long.MaxValue ? long.MaxValue : (long)declared;
                if (alignment < min)
                {
                    min = alignment;
                }
            }
            if (loads == 0)
            {
                return Unreadable(entry, "no loadable segment");
            }
            return new NativeLibraryReading(
                entry, true, is64, loads, min, HasSymbolTable(bytes, is64), string.Empty, ndkVersion, NdkMajorOf(ndkVersion));
        }

        /// <summary>
        /// The NDK version in a note segment's Android ident note (name
        /// "Android", type 1: a 4-byte API level, then 64 bytes of NDK
        /// version, then 64 of build number). Empty when the segment holds no
        /// such note; <see cref="UnnamedNdk"/> when the note is too short to
        /// name one. Reads only inside [start, start + size): a note whose
        /// sizes run past the segment ends the walk.
        /// </summary>
        private static string AndroidNdkNote(byte[] bytes, int start, int size)
        {
            long at = start;
            long end = (long)start + size;
            while (end - at >= 12)
            {
                long nameSize = ReadUInt32(bytes, (int)at);
                long descSize = ReadUInt32(bytes, (int)at + 4);
                var type = ReadUInt32(bytes, (int)at + 8);
                long nameAt = at + 12;
                long descAt = nameAt + ((nameSize + 3) & ~3L);
                long next = descAt + ((descSize + 3) & ~3L);
                if (nameSize > end - nameAt || descAt > end || descSize > end - descAt)
                {
                    break;
                }
                if (type == 1 && nameSize == 8 && bytes[nameAt] == (byte)'A' && bytes[nameAt + 1] == (byte)'n'
                    && bytes[nameAt + 2] == (byte)'d' && bytes[nameAt + 3] == (byte)'r' && bytes[nameAt + 4] == (byte)'o'
                    && bytes[nameAt + 5] == (byte)'i' && bytes[nameAt + 6] == (byte)'d' && bytes[nameAt + 7] == 0)
                {
                    if (descSize < 4 + 64)
                    {
                        return UnnamedNdk;
                    }
                    var text = new System.Text.StringBuilder();
                    for (var i = 0; i < 64; i++)
                    {
                        var c = bytes[descAt + 4 + i];
                        if (c == 0)
                        {
                            break;
                        }
                        // Printable ASCII only: the text goes into the build log.
                        text.Append(c >= 0x21 && c <= 0x7E ? (char)c : '?');
                    }
                    return text.Length == 0 ? UnnamedNdk : text.ToString();
                }
                if (next <= at)
                {
                    break;
                }
                at = next;
            }
            return string.Empty;
        }

        /// <summary>27 for "r27" or "r27c"; zero for anything that is not r followed by digits.</summary>
        public static int NdkMajorOf(string ndkVersion)
        {
            if (ndkVersion.Length < 2 || ndkVersion[0] != 'r')
            {
                return 0;
            }
            var major = 0;
            var digits = 0;
            for (var i = 1; i < ndkVersion.Length && ndkVersion[i] >= '0' && ndkVersion[i] <= '9' && digits < 4; i++, digits++)
            {
                major = (major * 10) + (ndkVersion[i] - '0');
            }
            return digits == 0 ? 0 : major;
        }

        /// <summary>
        /// True when the library meets the NDK floor: it is 32-bit, or it
        /// carries no Android note, or its note names an NDK at or above the
        /// floor. A note that names no readable NDK is below every floor. A
        /// floor of zero judges nothing.
        /// </summary>
        public static bool PassesNdkFloor(NativeLibraryReading library, int minNdkMajor)
            => minNdkMajor <= 0 || !library.Is64Bit || library.NdkVersion.Length == 0 || library.NdkMajor >= minNdkMajor;

        /// <summary>True when the section header table lists a symbol table. A table that cannot be read is "none".</summary>
        private static bool HasSymbolTable(byte[] bytes, bool is64)
        {
            long tableOffset = is64 ? (long)ReadUInt64(bytes, 0x28) : ReadUInt32(bytes, 0x20);
            int entrySize = ReadUInt16(bytes, is64 ? 0x3A : 0x2E);
            int entryCount = ReadUInt16(bytes, is64 ? 0x3C : 0x30);
            // By subtraction, as for the program headers: no addition to wrap.
            long tableBytes = (long)entrySize * entryCount;
            if (tableOffset <= 0 || entryCount == 0 || entrySize < 8 || tableOffset > bytes.Length - tableBytes)
            {
                return false;
            }
            for (var i = 0; i < entryCount; i++)
            {
                if (ReadUInt32(bytes, (int)(tableOffset + ((long)entrySize * i)) + 4) == ShtSymtab)
                {
                    return true;
                }
            }
            return false;
        }

        /// <summary>
        /// Writes the package's native libraries that still carry a symbol
        /// table to a zip in the layout Google documents for a symbols zip
        /// made by hand: one folder per ABI at the root, each unstripped
        /// library inside it under its own name (arm64-v8a/libname.so).
        /// Returns the entries written. When no library carries one, no zip
        /// is written and any old one at that path is removed.
        /// </summary>
        public static List<string> WriteNativeSymbols(string packagePath, string zipPath)
        {
            var written = new List<string>();
            if (File.Exists(zipPath))
            {
                File.Delete(zipPath);
            }
            using (var package = File.OpenRead(packagePath))
            using (var zip = new ZipArchive(package, ZipArchiveMode.Read))
            {
                ZipArchive? symbols = null;
                try
                {
                    foreach (var entry in zip.Entries)
                    {
                        if (!entry.FullName.EndsWith(".so", StringComparison.OrdinalIgnoreCase))
                        {
                            continue;
                        }
                        var parts = entry.FullName.Split('/');
                        if (parts.Length < 2)
                        {
                            continue;
                        }
                        byte[] bytes;
                        using (var opened = entry.Open())
                        using (var copy = new MemoryStream())
                        {
                            opened.CopyTo(copy);
                            bytes = copy.ToArray();
                        }
                        var library = ReadElf(entry.FullName, bytes);
                        if (!library.Readable || !library.HasSymbolTable)
                        {
                            continue;
                        }
                        if (symbols == null)
                        {
                            symbols = new ZipArchive(File.Create(zipPath), ZipArchiveMode.Create);
                        }
                        var name = parts[parts.Length - 2] + "/" + parts[parts.Length - 1];
                        using (var target = symbols.CreateEntry(name, CompressionLevel.Optimal).Open())
                        {
                            target.Write(bytes, 0, bytes.Length);
                        }
                        written.Add(name);
                    }
                }
                finally
                {
                    if (symbols != null)
                    {
                        symbols.Dispose();
                    }
                }
            }
            return written;
        }

        /// <summary>
        /// Empty when the package is at least as new as the reference file
        /// the build compiled; otherwise the sentence that refuses it. A
        /// package left over from an earlier build must not be the one the
        /// gates pass.
        /// </summary>
        public static string StaleFailure(string package, DateTime packageUtc, string reference, DateTime referenceUtc)
            => packageUtc >= referenceUtc
                ? string.Empty
                : string.Format(
                    CultureInfo.InvariantCulture,
                    "{0} was written {1:u}, before {2} ({3:u}): it is not the package this build made.",
                    package, packageUtc, reference, referenceUtc);

        /// <summary>True when the library meets the 16 KB gate: readable, and 32-bit or aligned to 16 KB.</summary>
        public static bool PassesPageSize(NativeLibraryReading library)
            => library.Readable && (!library.Is64Bit || library.MinLoadAlignment >= PageSize16Kb);

        /// <summary>Every way the package misses a gate, one sentence each; empty when it passes.</summary>
        public static List<string> Failures(
            PlayPackageReading reading, long dexByteLimit, bool requireProguardMap = false, int minNdkMajor = 0)
        {
            var failures = new List<string>();
            if (requireProguardMap && reading.ProguardMapBytes <= 0)
            {
                failures.Add(reading.Package + ": the bundle carries no R8 mapping (" + ProguardMapEntry + "), so Play could not de-obfuscate a stack.");
            }
            if (reading.DexFiles.Count == 0)
            {
                failures.Add(reading.Package + ": no .dex file was found, so the DEX sum was not checked.");
            }
            else if (reading.DexBytes >= dexByteLimit)
            {
                failures.Add(string.Format(
                    CultureInfo.InvariantCulture,
                    "{0}: the DEX sum is {1:N0} bytes; the limit is under {2:N0}.",
                    reading.Package, reading.DexBytes, dexByteLimit));
            }
            foreach (var library in reading.Libraries)
            {
                if (!library.Readable)
                {
                    failures.Add(reading.Package + ": " + library.Entry + " could not be read (" + library.Problem + "), so its alignment was not checked.");
                }
                else if (!PassesPageSize(library))
                {
                    failures.Add(string.Format(
                        CultureInfo.InvariantCulture,
                        "{0}: {1} is 64-bit with a loadable segment aligned to {2:N0} bytes; 16 KB pages need {3:N0}.",
                        reading.Package, library.Entry, library.MinLoadAlignment, PageSize16Kb));
                }
                if (library.Readable && !PassesNdkFloor(library, minNdkMajor))
                {
                    failures.Add(string.Format(
                        CultureInfo.InvariantCulture,
                        "{0}: {1} is 64-bit and was built with Android NDK {2}; Play's 16 KB check wants r{3} or newer. "
                        + "Raise the package that ships it to a version with a rebuilt library.",
                        reading.Package, library.Entry, library.NdkVersion, minNdkMajor));
                }
            }
            return failures;
        }

        /// <summary>The reading as lines for the build log: the DEX sum, then each library.</summary>
        public static List<string> Describe(PlayPackageReading reading, long dexByteLimit)
        {
            var lines = new List<string>();
            lines.Add(string.Format(
                CultureInfo.InvariantCulture,
                "Play gates: {0}: DEX sum {1:N0} bytes in {2} file(s), limit under {3:N0}.",
                reading.Package, reading.DexBytes, reading.DexFiles.Count, dexByteLimit));
            lines.Add(reading.ProguardMapBytes > 0
                ? string.Format(
                    CultureInfo.InvariantCulture,
                    "Play gates: {0}: R8 mapping carried for Play, {1:N0} bytes.", reading.Package, reading.ProguardMapBytes)
                : "Play gates: " + reading.Package + ": no R8 mapping carried.");
            foreach (var library in reading.Libraries)
            {
                lines.Add(library.Readable
                    ? string.Format(
                        CultureInfo.InvariantCulture,
                        "Play gates: {0}: {1}: {2}, {3} loadable segment(s), smallest alignment {4:N0}{5}, {6}.",
                        reading.Package, library.Entry, library.Is64Bit ? "64-bit" : "32-bit", library.LoadSegments,
                        library.MinLoadAlignment,
                        library.Is64Bit ? (PassesPageSize(library) ? " (16 KB: yes)" : " (16 KB: NO)") : " (not judged)",
                        library.NdkVersion.Length == 0 ? "no NDK note" : "NDK " + library.NdkVersion)
                    : "Play gates: " + reading.Package + ": " + library.Entry + ": unreadable (" + library.Problem + ").");
            }
            return lines;
        }

        private static NativeLibraryReading Unreadable(string entry, string problem)
            => new NativeLibraryReading(entry, false, false, 0, 0, false, problem);

        private static int ReadUInt16(byte[] bytes, int at)
            => bytes[at] | (bytes[at + 1] << 8);

        private static uint ReadUInt32(byte[] bytes, int at)
            => (uint)(bytes[at] | (bytes[at + 1] << 8) | (bytes[at + 2] << 16) | (bytes[at + 3] << 24));

        private static ulong ReadUInt64(byte[] bytes, int at)
            => ReadUInt32(bytes, at) | ((ulong)ReadUInt32(bytes, at + 4) << 32);
    }

#if !PLAY_GATES_LOGIC_ONLY
    /// <summary>
    /// The build task: reads each package, logs what it found, and fails the
    /// build on any miss. A build that hands it no package fails too: a gate
    /// that checked nothing has not passed. A 64-bit library whose Android
    /// note names an NDK older than <see cref="MinNdkMajor"/> is a miss. An app bundle must carry its R8
    /// mapping; when <see cref="NotOlderThan"/> is given, a package older
    /// than that file is refused; when <see cref="SymbolsZip"/> is given, the
    /// first package's unstripped native libraries are written there.
    /// </summary>
    public sealed class CheckPlayGates : Microsoft.Build.Utilities.Task
    {
        public Microsoft.Build.Framework.ITaskItem[] Packages { get; set; } = new Microsoft.Build.Framework.ITaskItem[0];

        public long DexByteLimit { get; set; } = PlayGateChecks.DefaultDexByteLimit;

        public string SymbolsZip { get; set; } = string.Empty;

        public string NotOlderThan { get; set; } = string.Empty;

        /// <summary>The oldest NDK a 64-bit library's Android note may name.</summary>
        public int MinNdkMajor { get; set; } = PlayGateChecks.DefaultMinNdkMajor;

        public override bool Execute()
        {
            if (Packages.Length == 0)
            {
                Log.LogError("Play gates: no package (.aab or .apk) was found to check.");
                return false;
            }
            foreach (var package in Packages)
            {
                // Asked by name first: a missing file has a last-write time
                // (the year 1601), and a comparison against it would answer
                // something.
                if (!File.Exists(package.ItemSpec))
                {
                    Log.LogError("Play gates: " + Path.GetFileName(package.ItemSpec) + " was not found: this build did not make the package it is set to make.");
                    continue;
                }
                if (NotOlderThan.Length != 0 && !File.Exists(NotOlderThan))
                {
                    Log.LogError("Play gates: " + Path.GetFileName(NotOlderThan) + " was not found, so " + Path.GetFileName(package.ItemSpec) + " could not be shown to be this build's.");
                    continue;
                }
                PlayPackageReading reading;
                try
                {
                    if (NotOlderThan.Length != 0)
                    {
                        var stale = PlayGateChecks.StaleFailure(
                            Path.GetFileName(package.ItemSpec), File.GetLastWriteTimeUtc(package.ItemSpec),
                            Path.GetFileName(NotOlderThan), File.GetLastWriteTimeUtc(NotOlderThan));
                        if (stale.Length != 0)
                        {
                            Log.LogError("Play gates: " + stale);
                            continue;
                        }
                    }
                    reading = PlayGateChecks.ReadPackage(package.ItemSpec);
                }
                catch (Exception ex)
                {
                    Log.LogError("Play gates: " + Path.GetFileName(package.ItemSpec) + " could not be opened (" + ex.GetType().Name + ").");
                    continue;
                }
                foreach (var line in PlayGateChecks.Describe(reading, DexByteLimit))
                {
                    Log.LogMessage(Microsoft.Build.Framework.MessageImportance.High, line);
                }
                var isBundle = package.ItemSpec.EndsWith(".aab", StringComparison.OrdinalIgnoreCase);
                foreach (var failure in PlayGateChecks.Failures(reading, DexByteLimit, requireProguardMap: isBundle, minNdkMajor: MinNdkMajor))
                {
                    Log.LogError("Play gates: " + failure);
                }
            }
            if (SymbolsZip.Length != 0 && !Log.HasLoggedErrors)
            {
                try
                {
                    var written = PlayGateChecks.WriteNativeSymbols(Packages[0].ItemSpec, SymbolsZip);
                    Log.LogMessage(
                        Microsoft.Build.Framework.MessageImportance.High,
                        written.Count == 0
                            ? "Play gates: no native library in the package carries a symbol table; no symbols zip was written."
                            : "Play gates: native symbols written: " + Path.GetFileName(SymbolsZip) + " (" + written.Count
                                + " libraries that carry a symbol table: " + string.Join(", ", written)
                                + "). The other libraries ship stripped and have no symbols to give.");
                }
                catch (Exception ex)
                {
                    Log.LogError("Play gates: the native symbols zip could not be written (" + ex.GetType().Name + ").");
                }
            }
            return !Log.HasLoggedErrors;
        }
    }
#endif
}
