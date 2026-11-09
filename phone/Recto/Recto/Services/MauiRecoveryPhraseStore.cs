using System;
using System.Threading.Tasks;
using Microsoft.Maui.Storage;
using Recto.Shared.Services;

namespace Recto.Services;

/// <summary>
/// The phone's recovery-phrase store. The phrase lives in <see cref="SecureStorage"/>
/// (through <see cref="ResilientStorage"/>) under the shared
/// <c>recto.phone.eth.mnemonic.{alias}</c> entry every signer reads. The provisioned
/// marker lives in <see cref="Preferences"/>, outside the secure store, because the
/// case it exists for is the secure store losing the phrase: a marker kept beside the
/// phrase would be lost with it. The marker holds no secret, only that a phrase was
/// provisioned for the alias.
/// </summary>
public sealed class MauiRecoveryPhraseStore : IRecoveryPhraseStore
{
    /// <summary>The shared phrase entry's prefix (the "eth" is historical: every
    /// signer reads it).</summary>
    public const string PhrasePrefix = "recto.phone.eth.mnemonic.";

    private const string ProvisionedPrefix = "recto.phone.recovery-phrase.provisioned.";

    public static readonly MauiRecoveryPhraseStore Instance = new();

    public async Task<string?> ReadAsync(string alias)
    {
        var phrase = await ResilientStorage.GetAsync(PhrasePrefix + alias).ConfigureAwait(false);
        if (!string.IsNullOrEmpty(phrase))
        {
            MarkProvisioned(alias);
        }
        return phrase;
    }

    // The marker is written FIRST and must succeed: if it cannot be written, no phrase
    // is written either, so a phrase never exists unmarked from a write. If the phrase
    // write then fails, the next attempt is refused by name and the person chooses.
    public async Task WriteAsync(string alias, string phrase)
    {
        Preferences.Default.Set(ProvisionedPrefix + alias, true);
        await ResilientStorage.SetAsync(PhrasePrefix + alias, phrase).ConfigureAwait(false);
    }

    public bool WasProvisioned(string alias) => Preferences.Default.ContainsKey(ProvisionedPrefix + alias);

    // Best effort, on a read only: a sign must not fail because the marker could not
    // be written, and the next read that finds the phrase writes it again.
    private static void MarkProvisioned(string alias)
    {
        try
        {
            if (!Preferences.Default.ContainsKey(ProvisionedPrefix + alias))
            {
                Preferences.Default.Set(ProvisionedPrefix + alias, true);
            }
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine(
                $"[Recto.MauiRecoveryPhraseStore] provisioned marker not written for '{alias}': {ex.GetType().Name}");
        }
    }
}
