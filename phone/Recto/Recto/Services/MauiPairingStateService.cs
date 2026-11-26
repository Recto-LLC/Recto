using System;
using System.Diagnostics;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Recto.Services;
using Recto.Shared.Common;
using Recto.Shared.Models;
using Recto.Shared.Services;

namespace Recto.Services;

/// <summary>
/// MAUI-side persistence for the phone's pairing record + persistent phone id.
/// Routes through <see cref="ResilientStorage"/> which wraps SecureStorage on
/// real devices and falls back to file storage on iOS Simulator (where
/// Keychain Services returns errSecMissingEntitlement for unsigned simulator
/// builds — see ResilientStorage.cs comments for the full story).
/// <para>
/// The pairing JSON lives under <c>recto.phone.pairing</c>, the phone id
/// under <c>recto.phone.id</c>.
/// </para>
/// </summary>
public sealed class MauiPairingStateService : IPairingStateService
{
    private const string PhoneIdKey = "recto.phone.id";
    private const string PairingStateKey = "recto.phone.pairing";
    private const string IdentityKeyJournalKey = "recto.phone.identity.journal";

    public async Task<Result<PairingState?>> GetCurrentAsync(CancellationToken ct)
    {
        try
        {
            var json = await ResilientStorage.GetAsync(PairingStateKey).ConfigureAwait(false);
            if (string.IsNullOrEmpty(json))
            {
                return Result.Success<PairingState?>(null);
            }

            var state = JsonSerializer.Deserialize<PairingState>(json);
            return Result.Success(state);
        }
        catch (Exception ex)
        {
            return Result.Failure<PairingState?>(Error.Failure($"Failed to read pairing state: {ex.Message}"));
        }
    }

    public async Task<Result> SaveAsync(PairingState state, CancellationToken ct)
    {
        try
        {
            // DIAG-2026-04-30 (auto-unpair investigation): log who's saving
            // null pairing state. Manual UnpairAll button in Settings.razor
            // is the only known caller; if anything else trips this, the
            // stack trace tells us where.
            if (state is null)
            {
                Debug.WriteLine($"[Recto/DIAG] MauiPairingStateService.SaveAsync(null) called.{Environment.NewLine}" +
                                $"  Caller stack:{Environment.NewLine}{new StackTrace(true)}");
            }
            var json = JsonSerializer.Serialize(state);
            await ResilientStorage.SetAsync(PairingStateKey, json).ConfigureAwait(false);
            return Result.Success();
        }
        catch (Exception ex)
        {
            return Result.Failure(Error.Failure($"Failed to save pairing state: {ex.Message}"));
        }
    }

    public Task<Result> ClearAsync(CancellationToken ct)
    {
        try
        {
            // DIAG-2026-04-30 (auto-unpair investigation): log every caller.
            // HandleUnpairClick in Home.razor is the only known caller; any
            // other path that lands here means something is unpairing the
            // phone unexpectedly. Stack trace identifies the culprit.
            Debug.WriteLine($"[Recto/DIAG] MauiPairingStateService.ClearAsync called.{Environment.NewLine}" +
                            $"  Caller stack:{Environment.NewLine}{new StackTrace(true)}");
            ResilientStorage.Remove(PairingStateKey);
            return Task.FromResult(Result.Success());
        }
        catch (Exception ex)
        {
            return Task.FromResult(Result.Failure(Error.Failure($"Failed to clear pairing state: {ex.Message}")));
        }
    }

    private static string AppAttestKey(string bootloaderId)
        => "recto.phone.appattest." + Convert.ToHexStringLower(
            System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(bootloaderId)))[..16];

    public async Task<string?> GetAppAttestKeyIdAsync(string bootloaderId, CancellationToken ct)
    {
        try
        {
            return await ResilientStorage.GetAsync(AppAttestKey(bootloaderId)).ConfigureAwait(false);
        }
        catch (Exception)
        {
            return null;
        }
    }

    public async Task SetAppAttestKeyIdAsync(string bootloaderId, string? keyId, CancellationToken ct)
    {
        try
        {
            if (keyId is null) ResilientStorage.Remove(AppAttestKey(bootloaderId));
            else await ResilientStorage.SetAsync(AppAttestKey(bootloaderId), keyId).ConfigureAwait(false);
        }
        catch (Exception)
        {
            // A stale id would be a wrong assertion, which is refused; none is a missing one.
            try { ResilientStorage.Remove(AppAttestKey(bootloaderId)); } catch (Exception) { }
        }
    }

    public async Task<string?> GetIdentityKeyJournalAsync(CancellationToken ct)
    {
        try
        {
            return await ResilientStorage.GetAsync(IdentityKeyJournalKey).ConfigureAwait(false);
        }
        catch (Exception)
        {
            return null;
        }
    }

    public async Task SetIdentityKeyJournalAsync(string? entry, CancellationToken ct)
    {
        try
        {
            if (entry is null) ResilientStorage.Remove(IdentityKeyJournalKey);
            else await ResilientStorage.SetAsync(IdentityKeyJournalKey, entry).ConfigureAwait(false);
        }
        catch (Exception)
        {
            // An entry that may be stale must not outlive the write that failed.
            try { ResilientStorage.Remove(IdentityKeyJournalKey); } catch (Exception) { }
        }
    }

    public async Task<Result<string>> GetOrCreatePhoneIdAsync(CancellationToken ct)
    {
        try
        {
            var existing = await ResilientStorage.GetAsync(PhoneIdKey).ConfigureAwait(false);
            if (!string.IsNullOrEmpty(existing))
            {
                return Result.Success(existing);
            }

            var newId = Guid.NewGuid().ToString();
            await ResilientStorage.SetAsync(PhoneIdKey, newId).ConfigureAwait(false);
            return Result.Success(newId);
        }
        catch (Exception ex)
        {
            return Result.Failure<string>(Error.Failure($"Failed to get phone id: {ex.Message}"));
        }
    }
}
