using System;
using System.Threading;
using System.Threading.Tasks;
using Recto.Shared.Common;

namespace Recto.Shared.Services;

/// <summary>Outcome of a full-wipe attempt.</summary>
public enum UnpairAllStatus
{
    /// <summary>Wipe completed: pairing, TOTP secrets, and enclave key are gone.</summary>
    Completed,

    /// <summary>
    /// Refused: this phone is (or must be presumed) a genesis member, and
    /// the wipe would destroy a trust-root key. The message names the
    /// ceremony that is the legitimate route.
    /// </summary>
    RefusedGenesisMember,

    /// <summary>
    /// Refused: the phone holds a recovery phrase (or must be presumed to)
    /// and the caller did not say it may be erased. The message names the
    /// backup and the way on that keeps it.
    /// </summary>
    RefusedRecoveryPhrase,

    /// <summary>The wipe was attempted and a step failed.</summary>
    Failed
}

public sealed record UnpairAllResult(UnpairAllStatus Status, string? Message = null);

/// <summary>
/// The ONE full-wipe path. Every caller that intends to destroy the enclave
/// identity key routes through <see cref="UnpairAllAsync"/> — the guard
/// lives here, ahead of the first destructive call, so no UI surface can
/// reach the key deletion without passing it.
/// </summary>
public interface IUnpairService
{
    /// <summary>
    /// Wipes pairing state, TOTP secrets, and the enclave key under
    /// <paramref name="keyAlias"/> — unless this phone is a genesis member,
    /// in which case it refuses without touching anything. The TOTP wipe
    /// empties the app's secure storage, the recovery phrase with it, so a
    /// phone that holds a phrase is refused too, until a caller that asked
    /// the person passes <paramref name="eraseRecoveryPhrase"/>.
    /// </summary>
    Task<UnpairAllResult> UnpairAllAsync(string keyAlias, CancellationToken ct, bool eraseRecoveryPhrase = false);

    /// <summary>
    /// Removes the identity key under <paramref name="keyAlias"/> and the poll key it delegated, so the next pairing
    /// makes new ones; the pairing record, the TOTP secrets and the recovery phrase stay. The genesis guard stands
    /// ahead of it as it does of the wipe.
    /// </summary>
    Task<UnpairAllResult> RemoveIdentityKeyAsync(string keyAlias, CancellationToken ct);
}

public sealed class UnpairService : IUnpairService
{
    /// <summary>
    /// The refusal names the ceremony (the guard's contract): a refusal
    /// without a route gets worked around, not respected.
    /// </summary>
    public const string GenesisRefusalMessage =
        "This phone is a genesis member — its key helps constitute the trust root, " +
        "and \"Unpair all\" would destroy it unrecoverably. To retire this device, " +
        "run the recovery ceremony: restore from the recovery phrase, then re-enrol " +
        "the member set on the bootloader.";

    /// <summary>The one recovery phrase every signer on the phone derives from.</summary>
    public const string RecoveryPhraseAlias = "default";

    public const string RecoveryPhraseRefusalMessage =
        "This phone holds a recovery phrase, or was set up with one, and a full wipe erases it: the wallet it opens comes back " +
        "only with the words. Back the phrase up in Settings first. To leave this bootloader and keep the " +
        "phrase, use Settings → Unpair bootloader (keep vault).";

    public const string FailClosedPrefix =
        "Genesis membership could not be read; refusing the wipe (fail closed). ";

    private readonly IPairingStateService _pairing;
    private readonly ITotpService _totp;
    private readonly IEnclaveKeyService _enclaveKeys;
    private readonly IGenesisStateService _genesis;
    private readonly IRecoveryPhraseStore _phrases;

    public UnpairService(
        IPairingStateService pairing,
        ITotpService totp,
        IEnclaveKeyService enclaveKeys,
        IGenesisStateService genesis,
        IRecoveryPhraseStore phrases)
    {
        _pairing = pairing;
        _totp = totp;
        _enclaveKeys = enclaveKeys;
        _genesis = genesis;
        _phrases = phrases;
    }

    public async Task<UnpairAllResult> UnpairAllAsync(
        string keyAlias, CancellationToken ct, bool eraseRecoveryPhrase = false)
    {
        if (await RefuseGenesisMemberAsync(ct).ConfigureAwait(false) is { } refusal) return refusal;

        if (!eraseRecoveryPhrase && await HoldsPhraseAsync().ConfigureAwait(false))
        {
            return new UnpairAllResult(UnpairAllStatus.RefusedRecoveryPhrase, RecoveryPhraseRefusalMessage);
        }

        try
        {
            // Wipe order preserved verbatim from the pre-guard Settings
            // sequence: pairing FIRST so any in-flight poll loops see
            // "no longer paired" before their backing keys are torn down.
            // (SaveAsync(null) rather than ClearAsync is the historical
            // behavior of this path — kept identical; see the DIAG note in
            // MauiPairingStateService.)
            await _pairing.SaveAsync(null!, ct).ConfigureAwait(false);
            await _totp.ClearAllAsync(ct).ConfigureAwait(false);
            await _enclaveKeys.DeleteAsync(keyAlias, ct).ConfigureAwait(false);
            // Rule 14.2: the delegated poll key goes with the identity that
            // delegated it. No-op when none was ever minted.
            await _enclaveKeys.DeleteAsync(PollSigning.PollKeyAlias, ct).ConfigureAwait(false);
            return new UnpairAllResult(UnpairAllStatus.Completed);
        }
        catch (Exception ex)
        {
            return new UnpairAllResult(UnpairAllStatus.Failed, $"{ex.GetType().Name}: {ex.Message}");
        }
    }

    public async Task<UnpairAllResult> RemoveIdentityKeyAsync(string keyAlias, CancellationToken ct)
    {
        if (await RefuseGenesisMemberAsync(ct).ConfigureAwait(false) is { } refusal) return refusal;
        try
        {
            var deleted = await _enclaveKeys.DeleteAsync(keyAlias, ct).ConfigureAwait(false);
            if (deleted.IsFailure) return new UnpairAllResult(UnpairAllStatus.Failed, deleted.Error.Message);
            await _enclaveKeys.DeleteAsync(PollSigning.PollKeyAlias, ct).ConfigureAwait(false);
            return new UnpairAllResult(UnpairAllStatus.Completed);
        }
        catch (Exception ex)
        {
            return new UnpairAllResult(UnpairAllStatus.Failed, $"{ex.GetType().Name}: {ex.Message}");
        }
    }

    // THE GUARD — ahead of the first destructive call, fail-closed:
    // an unreadable marker is treated as membership, because the cost
    // of a wrong "no" is a retry and the cost of a wrong "yes" is a
    // destroyed trust-root member.
    private async Task<UnpairAllResult?> RefuseGenesisMemberAsync(CancellationToken ct)
    {
        var membership = await _genesis.IsGenesisMemberAsync(ct).ConfigureAwait(false);
        if (!membership.IsSuccess)
        {
            return new UnpairAllResult(
                UnpairAllStatus.RefusedGenesisMember,
                FailClosedPrefix + GenesisRefusalMessage);
        }

        return membership.Value
            ? new UnpairAllResult(UnpairAllStatus.RefusedGenesisMember, GenesisRefusalMessage)
            : null;
    }

    // Only whether there is one. A store that cannot be read is presumed to hold it, and so is one that reads empty
    // where a phrase was once set up (RecoveryPhraseProvisioning: it may be there and unreadable now): a wrong "yes"
    // is one more question, and a wrong "no" is a wallet.
    private async Task<bool> HoldsPhraseAsync()
    {
        try
        {
            return !string.IsNullOrEmpty(await _phrases.ReadAsync(RecoveryPhraseAlias).ConfigureAwait(false))
                || _phrases.WasProvisioned(RecoveryPhraseAlias);
        }
        catch (Exception)
        {
            return true;
        }
    }
}
