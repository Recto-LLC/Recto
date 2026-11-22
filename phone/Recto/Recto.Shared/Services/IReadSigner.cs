using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Recto.Shared.Common;
using Recto.Shared.Models;

namespace Recto.Shared.Services;

/// <summary>
/// Signs the phone's READS to a bootloader (hard rule 14.2):
/// <c>GET /v0.4/pending</c>, <c>GET /v0.4/manage/phones</c>,
/// <c>POST /v0.4/manage/push_token</c>. Returns the header pair to attach,
/// or null when this pairing carries no poll key (demo mode only) -- the
/// read then goes bare and a real bootloader answers it with a verdict.
/// <para>
/// The seam exists so <see cref="BootloaderClient"/> attaches the headers at
/// the ONE place the URL path is known, and so tests can prove the headers
/// are attached without an enclave.
/// </para>
/// </summary>
public interface IReadSigner
{
    Task<PollSignatureHeaders?> SignReadAsync(string phoneId, string path, CancellationToken ct);
}

/// <summary>
/// Why a read left the phone without a signature. A fixed list: these are
/// the only words the signer's log lines and its Settings entry use for it.
/// </summary>
public static class UnsignedReadReason
{
    /// <summary>The pairing record could not be read.</summary>
    public const string PairingUnreadable = "pairing_unreadable";

    /// <summary>There is no pairing record. A normal state, not a fault.</summary>
    public const string NotPaired = "not_paired";

    /// <summary>
    /// The poll key reads as gated by user authentication, so signing with it
    /// would raise a prompt. It is refused, once, with no retry.
    /// </summary>
    public const string PollKeyGated = "poll_key_gated";

    /// <summary>The pairing recorded no poll key (a demo pairing, or one made before poll keys).</summary>
    public const string NoPollKey = "no_poll_key";

    /// <summary>
    /// The device is locked and its key store will not use the poll key until
    /// it is unlocked. A normal state, not a fault, and not retried.
    /// </summary>
    public const string DeviceLocked = "device_locked";

    /// <summary>The key store answered both attempts with a failure.</summary>
    public const string SignFailed = "sign_failed";

    /// <summary>The key store threw on the last attempt.</summary>
    public const string SignThrew = "sign_threw";
}

/// <summary>
/// The production <see cref="IReadSigner"/>: signs with the enclave key under
/// <see cref="PollSigning.PollKeyAlias"/> -- the non-gated device key -- when
/// the current pairing recorded one, and only then. A signing failure is
/// reported as "no signature" rather than thrown: a read that goes bare is
/// answered by the bootloader's mode with a verdict; a read that never leaves
/// the phone is silence.
/// <para>
/// A signing that fails is tried ONCE more, at once, with a new timestamp: a
/// key store that is briefly busy answers the second call. One failure is
/// never retried: a poll key that reads as gated by user authentication
/// (<see cref="DeviceKeyRefusal"/>). The key store refuses it without a
/// prompt, and a second call could only ask again. When a read still
/// goes unsigned the signer says why - one of <see cref="UnsignedReadReason"/>,
/// the route from the client's fixed list, and the kind of the failure (an
/// error's code or an exception's type name). It never logs a phone id, a
/// key, a signature, a payload or an exception's text. The reason is logged
/// when it changes, not on every poll, and is kept in
/// <see cref="RecentErrors"/> so Settings can show it; the first signed read
/// after that is logged too. A phone that is not paired, and a device that
/// is locked, are the exceptions: normal states, logged for information and
/// kept out of Settings. A bootloader can require signed reads only once
/// these lines stay quiet.
/// </para>
/// </summary>
public sealed class PollKeyReadSigner : IReadSigner
{
    /// <summary>One signing and one retry.</summary>
    public const int Attempts = 2;

    /// <summary>The phase the reason is kept under in <see cref="RecentErrors"/>.</summary>
    public const string RecentErrorsPhase = "poll/sign";

    private const string Signing = "";

    private readonly IEnclaveKeyService _enclave;
    private readonly IPairingStateService _pairing;
    private readonly ILogger<PollKeyReadSigner>? _log;

    // What was last reported: empty while reads are signed.
    private string _reported = Signing;

    public PollKeyReadSigner(
        IEnclaveKeyService enclave, IPairingStateService pairing, ILogger<PollKeyReadSigner>? log = null)
    {
        _enclave = enclave;
        _pairing = pairing;
        _log = log;
    }

    public async Task<PollSignatureHeaders?> SignReadAsync(string phoneId, string path, CancellationToken ct)
    {
        Result<PairingState?> current;
        try
        {
            current = await _pairing.GetCurrentAsync(ct).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            // The caller gave the read up; the send that follows sees the
            // same cancellation. Nothing to report, and nothing thrown.
            return null;
        }
        catch (Exception ex)
        {
            return Unsigned(path, UnsignedReadReason.PairingUnreadable, ex.GetType().Name, attempts: 0);
        }
        if (current.IsFailure)
        {
            return Unsigned(path, UnsignedReadReason.PairingUnreadable, current.Error.Method, attempts: 0);
        }
        if (current.Value is null)
        {
            return Unsigned(path, UnsignedReadReason.NotPaired, string.Empty, attempts: 0);
        }
        if (current.Value.PollPublicKeyB64u is null)
        {
            return Unsigned(path, UnsignedReadReason.NoPollKey, string.Empty, attempts: 0);
        }

        var reason = UnsignedReadReason.SignFailed;
        var kind = string.Empty;
        for (var attempt = 1; attempt <= Attempts; attempt++)
        {
            try
            {
                // Each attempt signs its own timestamp.
                var signed = await PollSigning
                    .SignPollAsync(_enclave, PollSigning.PollKeyAlias, phoneId, path, ct)
                    .ConfigureAwait(false);
                if (signed.IsSuccess)
                {
                    Signed(path, attempt);
                    return signed.Value;
                }
                if (DeviceKeyRefusal.IsGated(signed.Error))
                {
                    // Refused before any prompt. Asking again changes nothing.
                    return Unsigned(path, UnsignedReadReason.PollKeyGated, string.Empty, attempt);
                }
                if (DeviceKeyRefusal.IsLocked(signed.Error))
                {
                    // The key is there and is not gated; the device is
                    // locked. It will sign once unlocked, not a moment from now.
                    return Unsigned(path, UnsignedReadReason.DeviceLocked, string.Empty, attempt);
                }
                reason = UnsignedReadReason.SignFailed;
                kind = signed.Error.Method;
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                return null;
            }
            catch (Exception ex)
            {
                reason = UnsignedReadReason.SignThrew;
                kind = ex.GetType().Name;
            }
        }
        return Unsigned(path, reason, kind, Attempts);
    }

    /// <summary>Reports why this read goes bare, once per change of reason. Always answers null.</summary>
    private PollSignatureHeaders? Unsigned(string path, string reason, string kind, int attempts)
    {
        kind = LoggableKind(kind);
        var report = kind.Length == 0 ? reason : $"{reason} ({kind})";
        if (Interlocked.Exchange(ref _reported, report) == report)
        {
            return null;
        }
        // Not paired is where every phone starts and where an unpair leaves
        // it; a locked device is one in a pocket. Neither is a fault.
        var fault = reason != UnsignedReadReason.NotPaired && reason != UnsignedReadReason.DeviceLocked;
        _log?.Log(
            fault ? LogLevel.Warning : LogLevel.Information,
            "Read {Route} goes unsigned: {Reason} {Kind} after {Attempts} signing attempt(s)",
            BootloaderClient.LoggedRouteOfPath(path), reason, kind.Length == 0 ? "(no kind)" : kind, attempts);
        if (fault)
        {
            RecentErrors.Record(RecentErrorsPhase, $"This phone's reads are going unsigned: {report}.");
        }
        return null;
    }

    private void Signed(string path, int attempt)
    {
        if (attempt > 1)
        {
            _log?.LogInformation(
                "Read {Route} signed on attempt {Attempt}", BootloaderClient.LoggedRouteOfPath(path), attempt);
        }
        var before = Interlocked.Exchange(ref _reported, Signing);
        if (before.Length != 0)
        {
            _log?.LogInformation(
                "Read {Route} signed again after: {Reason}", BootloaderClient.LoggedRouteOfPath(path), before);
        }
    }

    /// <summary>
    /// A failure's kind as the log may show it: an error code or a type name,
    /// when it is shaped like one (letters, digits, <c>_ .</c>, at most 64).
    /// Anything else - a sentence, a path, a value - is not shown.
    /// </summary>
    private static string LoggableKind(string? kind)
    {
        if (string.IsNullOrEmpty(kind))
        {
            return string.Empty;
        }
        if (kind.Length > 64)
        {
            return "unnamed";
        }
        foreach (var c in kind)
        {
            if (c is not ((>= 'a' and <= 'z') or (>= 'A' and <= 'Z') or (>= '0' and <= '9') or '_' or '.'))
            {
                return "unnamed";
            }
        }
        return kind;
    }
}
