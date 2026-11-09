using System.Threading.Tasks;
using Recto.Shared.Common;

namespace Recto.Shared.Services;

/// <summary>
/// Where the recovery phrase and its provisioned marker live. The phone has one
/// phrase per alias, shared by every signer (ETH, BTC, the ed25519 chains, TRON).
/// </summary>
public interface IRecoveryPhraseStore
{
    /// <summary>The stored phrase, or null or empty when the read finds none. A read
    /// that finds a phrase also marks the alias provisioned, so a phone paired before
    /// the marker existed is covered from its first read.</summary>
    Task<string?> ReadAsync(string alias);

    /// <summary>Marks the alias provisioned, then writes the phrase. A marker that
    /// cannot be written fails the write before any phrase is stored.</summary>
    Task WriteAsync(string alias, string phrase);

    /// <summary>True once a phrase was created, restored or read for the alias on this
    /// phone. Kept apart from the phrase, so it outlives a phrase the platform's secure
    /// store dropped.</summary>
    bool WasProvisioned(string alias);
}

/// <summary>
/// The one rule for creating a recovery phrase. An empty read cannot tell "never
/// provisioned" from "the stored phrase became unreadable" (a secure store dropping a
/// value it can no longer decrypt, or a restore that brought the app's settings but
/// not its keychain). So a phrase is created on an empty read only when none was ever
/// provisioned for the alias. After that, an empty read is refused by name and the
/// person chooses: restore the phrase, or ask for a new one in so many words.
/// A readable phrase is never replaced here; a restore in Settings does that.
/// </summary>
public static class RecoveryPhraseProvisioning
{
    /// <summary>The <see cref="Error.Method"/> of the refusal, so a caller can tell it
    /// from other failures and offer the two choices.</summary>
    public const string UnreadableCode = "RecoveryPhrase.Unreadable";

    public static Error Unreadable(string alias) => new(
        UnreadableCode,
        $"A recovery phrase was set up on this phone at '{alias}' and it reads empty now (it was wiped, or can no longer be read), so no new one was made. "
        + "Restore the phrase in Settings to keep the same wallet, or create a new phrase: "
        + "the old wallet's addresses come back only with the old words.",
        string.Empty);

    public static bool IsUnreadable(Error? error) => error is not null && error.Method == UnreadableCode;

    /// <summary>
    /// Returns the alias's phrase. On an empty read it creates a 24-word BIP-39 phrase
    /// only when none was ever provisioned, or when <paramref name="replaceUnreadable"/>
    /// says the person chose a new phrase after the refusal; otherwise it fails with
    /// <see cref="Unreadable"/> and writes nothing.
    /// </summary>
    public static async Task<Result<string>> EnsureAsync(
        IRecoveryPhraseStore store, string alias, bool replaceUnreadable)
    {
        var phrase = await store.ReadAsync(alias).ConfigureAwait(false);
        if (!string.IsNullOrEmpty(phrase))
        {
            return Result.Success<string>(phrase);
        }
        if (store.WasProvisioned(alias) && !replaceUnreadable)
        {
            return Result.Failure<string>(Unreadable(alias));
        }
        phrase = Bip39.GenerateMnemonic(wordCount: 24);
        await store.WriteAsync(alias, phrase).ConfigureAwait(false);
        return Result.Success<string>(phrase);
    }
}
