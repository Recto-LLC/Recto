using System.Threading;
using System.Threading.Tasks;
using Recto.Shared.Common;
using Recto.Shared.Models;

namespace Recto.Shared.Services;

/// <summary>
/// Persists pairing state across app launches. Backing store is platform-
/// specific (MAUI SecureStorage on the phone host); the abstraction lets
/// future surfaces (CLI helper, desktop pairing assistant) plug in their own.
/// </summary>
public interface IPairingStateService
{
    /// <summary>Returns the current pairing if any, or <c>null</c> when unpaired.</summary>
    Task<Result<PairingState?>> GetCurrentAsync(CancellationToken ct);

    /// <summary>Persists <paramref name="state"/> as the current pairing.</summary>
    Task<Result> SaveAsync(PairingState state, CancellationToken ct);

    /// <summary>Removes the current pairing record. Does not delete enclave keys.</summary>
    Task<Result> ClearAsync(CancellationToken ct);

    /// <summary>Gets the persistent phone identifier, minting a fresh uuid4 on first call.</summary>
    Task<Result<string>> GetOrCreatePhoneIdAsync(CancellationToken ct);

    /// <summary>The id of the App Attest key the bootloader <paramref name="bootloaderId"/> keeps for this phone, or null.
    /// It outlives an unpairing that keeps the identity key, as the bootloader's record does.</summary>
    Task<string?> GetAppAttestKeyIdAsync(string bootloaderId, CancellationToken ct) => Task.FromResult<string?>(null);

    /// <summary>Keeps <paramref name="keyId"/> for <paramref name="bootloaderId"/>; null removes it.</summary>
    Task SetAppAttestKeyIdAsync(string bootloaderId, string? keyId, CancellationToken ct) => Task.CompletedTask;

    /// <summary>The <see cref="IdentityKeyJournal"/> entry, or null when there is none or it cannot be read - which
    /// means the identity key is never replaced unasked.</summary>
    Task<string?> GetIdentityKeyJournalAsync(CancellationToken ct) => Task.FromResult<string?>(null);

    /// <summary>Keeps <paramref name="entry"/>; null removes it. A store that fails keeps none.</summary>
    Task SetIdentityKeyJournalAsync(string? entry, CancellationToken ct) => Task.CompletedTask;
}
