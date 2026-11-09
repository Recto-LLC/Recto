using System;
using System.Collections.Generic;
using System.IO;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Recto.Shared.Services;
using Recto.Shared.Tests.Capability;
using Xunit;

namespace Recto.Shared.Tests.Services;

/// <summary>
/// A recovery phrase is created on an empty read only when none was ever provisioned
/// for the alias. After that an empty read (a secure store that dropped the value, a
/// restore that did not bring it) is refused by name, and only the person's explicit
/// choice of a new phrase creates one. The four signers share one phrase and one rule.
/// </summary>
public class RecoveryPhraseRuleTests
{
    /// <summary>The phone's store contract: a read that finds a phrase marks the alias,
    /// a write marks it, and the marker outlives the phrase.</summary>
    private sealed class MemoryStore : IRecoveryPhraseStore
    {
        private readonly Dictionary<string, string> _phrases = new();
        private readonly HashSet<string> _provisioned = new();
        public int Writes { get; private set; }

        public Task<string?> ReadAsync(string alias)
        {
            _phrases.TryGetValue(alias, out var phrase);
            if (!string.IsNullOrEmpty(phrase)) _provisioned.Add(alias);
            return Task.FromResult<string?>(phrase);
        }

        public Task WriteAsync(string alias, string phrase)
        {
            _phrases[alias] = phrase;
            _provisioned.Add(alias);
            Writes++;
            return Task.CompletedTask;
        }

        public bool WasProvisioned(string alias) => _provisioned.Contains(alias);

        /// <summary>The secure store loses the phrase; the marker stays.</summary>
        public void DropPhrase(string alias) => _phrases.Remove(alias);

        /// <summary>A phone provisioned before the marker existed: a phrase, no marker.</summary>
        public void SeedPhraseWithoutMarker(string alias, string phrase) => _phrases[alias] = phrase;

        public string? Phrase(string alias) => _phrases.TryGetValue(alias, out var p) ? p : null;
    }

    [Fact]
    public async Task FirstProvision_CreatesAPhrase()
    {
        var store = new MemoryStore();

        var result = await RecoveryPhraseProvisioning.EnsureAsync(store, "default", replaceUnreadable: false);

        Assert.True(result.IsSuccess);
        Assert.Equal(24, result.Value.Split(' ').Length);
        Assert.True(Bip39.ValidateMnemonic(result.Value));
        Assert.Equal(result.Value, store.Phrase("default"));
        Assert.Equal(1, store.Writes);
        Assert.True(store.WasProvisioned("default"));
    }

    [Fact]
    public async Task AReadablePhrase_IsNeverReplaced_EvenWhenANewOneIsAsked()
    {
        var store = new MemoryStore();
        var first = (await RecoveryPhraseProvisioning.EnsureAsync(store, "default", false)).Value;

        var again = await RecoveryPhraseProvisioning.EnsureAsync(store, "default", false);
        var asked = await RecoveryPhraseProvisioning.EnsureAsync(store, "default", replaceUnreadable: true);

        Assert.Equal(first, again.Value);
        Assert.Equal(first, asked.Value);
        Assert.Equal(1, store.Writes);
    }

    [Fact]
    public async Task AnEmptyReadAfterProvisioning_IsRefused_AndNothingIsWritten()
    {
        var store = new MemoryStore();
        await RecoveryPhraseProvisioning.EnsureAsync(store, "default", false);
        store.DropPhrase("default");

        var result = await RecoveryPhraseProvisioning.EnsureAsync(store, "default", replaceUnreadable: false);

        Assert.True(result.IsFailure);
        Assert.True(RecoveryPhraseProvisioning.IsUnreadable(result.Error));
        Assert.Equal(RecoveryPhraseProvisioning.UnreadableCode, result.Error.Method);
        Assert.Contains("Restore the phrase in Settings", result.Error.Message);
        Assert.Contains("create a new phrase", result.Error.Message);
        Assert.Null(store.Phrase("default"));
        Assert.Equal(1, store.Writes);
    }

    [Fact]
    public async Task ANewPhraseChosenAfterTheRefusal_IsCreated()
    {
        var store = new MemoryStore();
        var old = (await RecoveryPhraseProvisioning.EnsureAsync(store, "default", false)).Value;
        store.DropPhrase("default");
        Assert.True((await RecoveryPhraseProvisioning.EnsureAsync(store, "default", false)).IsFailure);

        var chosen = await RecoveryPhraseProvisioning.EnsureAsync(store, "default", replaceUnreadable: true);

        Assert.True(chosen.IsSuccess);
        Assert.True(Bip39.ValidateMnemonic(chosen.Value));
        Assert.NotEqual(old, chosen.Value);
        Assert.Equal(chosen.Value, store.Phrase("default"));
        // The new phrase is the alias's phrase from here on.
        Assert.Equal(chosen.Value, (await RecoveryPhraseProvisioning.EnsureAsync(store, "default", false)).Value);
    }

    [Fact]
    public async Task APhraseFoundByARead_IsCoveredFromThen()
    {
        // A phone provisioned before the marker existed: the phrase is there, the
        // marker is not, until the first read finds the phrase.
        var store = new MemoryStore();
        store.SeedPhraseWithoutMarker("default", Bip39.GenerateMnemonic(24));
        Assert.False(store.WasProvisioned("default"));

        await store.ReadAsync("default");
        Assert.True(store.WasProvisioned("default"));
        store.DropPhrase("default");
        var result = await RecoveryPhraseProvisioning.EnsureAsync(store, "default", false);

        Assert.True(RecoveryPhraseProvisioning.IsUnreadable(result.Error));
        Assert.Equal(0, store.Writes);
    }

    [Fact]
    public async Task APhraseLostBeforeAnyReadMarkedIt_LooksNeverProvisioned()
    {
        // The limit of the marker, pinned so it is not mistaken for coverage: a
        // phrase that was never read on a build that marks, and is lost, leaves no
        // trace, and the first pairing creates a phrase as it did before.
        var store = new MemoryStore();
        store.SeedPhraseWithoutMarker("default", Bip39.GenerateMnemonic(24));
        store.DropPhrase("default");

        var result = await RecoveryPhraseProvisioning.EnsureAsync(store, "default", false);

        Assert.True(result.IsSuccess);
        Assert.Equal(1, store.Writes);
    }

    [Fact]
    public async Task TheRuleIsPerAlias()
    {
        var store = new MemoryStore();
        await RecoveryPhraseProvisioning.EnsureAsync(store, "default", false);
        store.DropPhrase("default");

        var other = await RecoveryPhraseProvisioning.EnsureAsync(store, "second", false);

        Assert.True(other.IsSuccess);
        Assert.False(RecoveryPhraseProvisioning.IsUnreadable(null));
        Assert.False(RecoveryPhraseProvisioning.IsUnreadable(Recto.Shared.Common.Error.NotFound("x")));
    }

    // --- The phone's own code (source checks: the MAUI project is not referenced here) ---

    private static string PhoneRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "Recto.Shared", "Pages", "Home.razor")))
        {
            dir = dir.Parent;
        }
        Assert.NotNull(dir);
        return dir!.FullName;
    }

    private static string PhoneService(string file) =>
        File.ReadAllText(Path.Combine(PhoneRoot(), "Recto", "Services", file));

    [Theory]
    [InlineData("MauiEthSignService.cs")]
    [InlineData("MauiBtcSignService.cs")]
    [InlineData("MauiEd25519ChainSignService.cs")]
    [InlineData("MauiTronSignService.cs")]
    public void EverySigner_EnsuresThroughTheOneRule_AndReadsThroughTheStore(string file)
    {
        var source = PhoneService(file);
        var ensure = ProfileSigningInputTests.MethodBody(source, "EnsureMnemonicAsync");

        Assert.Contains("RecoveryPhraseProvisioning", ensure);
        Assert.Contains(".EnsureAsync(MauiRecoveryPhraseStore.Instance, alias, replaceUnreadablePhrase)", ensure);
        Assert.DoesNotContain("SetAsync(", ensure);
        // No signer makes a phrase itself, and no read bypasses the store that marks it.
        Assert.DoesNotContain("GenerateMnemonic(", source);
        Assert.DoesNotContain("GetAsync(MnemonicPrefix", source);
        Assert.DoesNotContain("SetAsync(MnemonicPrefix", source);
        Assert.Matches(@"bool replaceUnreadablePhrase,\s*CancellationToken ct\)", source);
    }

    [Fact]
    public void TheStore_KeepsTheMarkerOutsideTheSecureStore()
    {
        var source = PhoneService("MauiRecoveryPhraseStore.cs");

        Assert.Matches(@"public bool WasProvisioned\(string alias\) => Preferences\.Default\.ContainsKey\(ProvisionedPrefix \+ alias\);", source);
        Assert.Contains("MarkProvisioned(alias)", ProfileSigningInputTests.MethodBody(source, "ReadAsync"));
        // A write marks FIRST and strictly (no best-effort helper): a marker that
        // cannot be written stops the phrase from being written unmarked.
        var write = ProfileSigningInputTests.MethodBody(source, "WriteAsync");
        var markAt = write.IndexOf("Preferences.Default.Set(ProvisionedPrefix + alias, true);", StringComparison.Ordinal);
        var phraseAt = write.IndexOf("ResilientStorage.SetAsync(PhrasePrefix + alias, phrase)", StringComparison.Ordinal);
        Assert.True(markAt >= 0 && phraseAt > markAt);
        Assert.DoesNotContain("MarkProvisioned(", write);
        Assert.DoesNotContain("catch", write);
        var mark = ProfileSigningInputTests.MethodBody(source, "MarkProvisioned");
        Assert.Contains("Preferences.Default.Set(", mark);
        Assert.DoesNotContain("ResilientStorage", mark);
        Assert.DoesNotContain("SecureStorage", mark);
        Assert.Contains("public const string PhrasePrefix = \"recto.phone.eth.mnemonic.\";", source);
    }

    [Fact]
    public void ThePairFlow_ReplacesAnUnreadablePhraseOnlyOnThePersonsChoice()
    {
        var page = ProfileSigningInputTests.HomePage();
        var pair = ProfileSigningInputTests.MethodBody(page, "HandlePairServiceClick");

        Assert.Contains("replaceUnreadablePhrase: replacePhrase", pair);
        Assert.Contains("RecoveryPhraseProvisioning.IsUnreadable(ensureResult.Error)", pair);
        Assert.DoesNotContain("_pairServiceReplacePhrase = true", pair);
        Assert.Single(Regex.Matches(page, @"_pairServiceReplacePhrase = true"));
        var choose = ProfileSigningInputTests.MethodBody(page, "ChooseNewPhraseAndPair");
        Assert.Contains("_pairServiceReplacePhrase = true", choose);
        // The choice is cleared after the one attempt, however it ended.
        Assert.Matches(@"finally\s*\{[^}]*_pairServiceReplacePhrase = false;", choose);
        Assert.Contains("@onclick=\"ChooseNewPhraseAndPair\"", page);
        Assert.Contains("@onclick=\"RestorePhraseInSettings\"", page);
    }
}
