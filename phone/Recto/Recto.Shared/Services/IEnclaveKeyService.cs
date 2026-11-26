using System;
using System.Threading;
using System.Threading.Tasks;
using Recto.Shared.Common;
using Recto.Shared.Models;

namespace Recto.Shared.Services;

/// <summary>
/// Phone-side keypair management. The implementation backs onto the
/// platform's hardware enclave where possible:
/// <list type="bullet">
/// <item>iOS: Secure Enclave via <c>SecKey</c> with
/// <c>kSecAttrTokenIDSecureEnclave</c> + biometric ACL. P-256 only
/// (Ed25519 not natively supported by Secure Enclave as of iOS 18).</item>
/// <item>Android: StrongBox via <c>KeyPairGenerator</c> with
/// <c>setIsStrongBoxBacked(true)</c> + <c>setUserAuthenticationRequired(true)</c>.
/// Ed25519, API 31+.</item>
/// <item>Windows / Mac Catalyst dev: software-backed Ed25519 via BouncyCastle,
/// persisted in MAUI <c>SecureStorage</c>. No biometric gate.</item>
/// </list>
/// </summary>
public interface IEnclaveKeyService
{
    /// <summary>
    /// The signature algorithm this implementation produces. One of
    /// <see cref="Protocol.V04.V04Protocol.AlgorithmEd25519"/> or
    /// <see cref="Protocol.V04.V04Protocol.AlgorithmEcdsaP256"/>. Phone
    /// advertises this in its registration request's
    /// <c>supported_algorithms</c> field.
    /// </summary>
    string Algorithm { get; }

    /// <summary>Generates a new keypair under <paramref name="keyAlias"/>. Overwrites any existing.</summary>
    Task<Result<EnclavePublicKey>> GenerateAsync(string keyAlias, CancellationToken ct);

    /// <summary>
    /// Generates a DEVICE key under <paramref name="keyAlias"/>: enclave-resident
    /// where the platform has one, but with NO user-authentication ACL, so
    /// <see cref="SignAsync"/> on it never prompts. This is the poll key of hard
    /// rule 14.2 (2026-09-21): it authenticates the device on the
    /// phone's reads (poll, pending, manage) and is delegated once, at pairing,
    /// by an identity-key signature. It must never sign an approval. The
    /// default falls back to <see cref="GenerateAsync"/> for implementations
    /// that have no ACL to drop (software-backed dev paths, test fakes).
    /// </summary>
    Task<Result<EnclavePublicKey>> GenerateDeviceKeyAsync(string keyAlias, CancellationToken ct)
        => GenerateAsync(keyAlias, ct);

    /// <summary>
    /// True when the platform attests a key at its creation (Android), so a key carries the challenge of the
    /// registration it was made for and no later one.
    /// </summary>
    bool AttestsAtCreation => false;

    /// <summary>
    /// <see cref="GenerateAsync"/>, asking the platform to attest the new key over
    /// <paramref name="attestationChallenge"/> where it can. A device that cannot attest still makes the key.
    /// </summary>
    Task<Result<EnclavePublicKey>> GenerateAttestedAsync(
        string keyAlias, byte[] attestationChallenge, CancellationToken ct)
        => GenerateAsync(keyAlias, ct);

    /// <summary>
    /// What this device can show for <paramref name="keyAlias"/> in this registration, or null when it can show
    /// nothing. Never prompts.
    /// </summary>
    Task<Result<DeviceEvidence?>> GetDeviceEvidenceAsync(
        string keyAlias, string registrationChallenge, string identityKeyB64u, string pollKeyB64u, CancellationToken ct)
        => Task.FromResult(Result.Success<DeviceEvidence?>(null));

    /// <summary>
    /// An App Attest assertion by the key <paramref name="appAttestKeyId"/> (base64), or null where there is no App
    /// Attest. Never prompts. A key the platform no longer holds fails with <see cref="DeviceEvidence.KeyGoneCode"/>.
    /// </summary>
    Task<Result<string?>> GetDeviceAssertionAsync(string appAttestKeyId, byte[] clientDataHash, CancellationToken ct)
        => Task.FromResult(Result.Success<string?>(null));

    /// <summary>True if a keypair already exists under <paramref name="keyAlias"/>.</summary>
    Task<Result<bool>> KeyExistsAsync(string keyAlias, CancellationToken ct);

    /// <summary>Returns the public key for an existing alias, in the algorithm's wire encoding.</summary>
    Task<Result<EnclavePublicKey>> GetPublicKeyAsync(string keyAlias, CancellationToken ct);

    /// <summary>
    /// Signs <paramref name="message"/> with the private key under
    /// <paramref name="keyAlias"/>. Returns the raw 64-byte signature in the
    /// algorithm's wire encoding (Ed25519: 64-byte raw; ECDSA P-256: 64-byte
    /// raw R || S, big-endian, NOT DER). Triggers a biometric prompt on
    /// platforms that gate enclave operations behind one.
    /// </summary>
    Task<Result<byte[]>> SignAsync(string keyAlias, byte[] message, CancellationToken ct);

    /// <summary>
    /// Signs with a DEVICE key (<see cref="GenerateDeviceKeyAsync"/>) and
    /// never prompts. An implementation that can tell a key is gated by user
    /// authentication refuses it here with <see cref="DeviceKeyRefusal.Gated"/>
    /// before any prompt is raised: a read is signed on a timer, and a timer
    /// must never put a biometric prompt on the screen.
    /// <para>
    /// THE DEFAULT REFUSES (<see cref="DeviceKeyRefusal.NoEntry"/>). It does
    /// not fall back to <see cref="SignAsync"/>, which may prompt: a key
    /// service that gates keys and forgot this method would then prompt on
    /// the timer. Every implementation says for itself that its device-key
    /// signing cannot prompt.
    /// </para>
    /// </summary>
    Task<Result<byte[]>> SignWithDeviceKeyAsync(string keyAlias, byte[] message, CancellationToken ct)
        => Task.FromResult(Result.Failure<byte[]>(DeviceKeyRefusal.NoEntry()));

    /// <summary>Removes the keypair under <paramref name="keyAlias"/>. No-op if absent.</summary>
    Task<Result> DeleteAsync(string keyAlias, CancellationToken ct);
}

/// <summary>
/// What a key service answers a device-key signing it will not make. Each is
/// an error with its own code, so the read signer can name the reason
/// without reading a sentence.
/// </summary>
public static class DeviceKeyRefusal
{
    /// <summary>The key needs user authentication: signing would raise a prompt.</summary>
    public const string GatedCode = "DeviceKeyGated";

    /// <summary>The device is locked, and the key is not readable while it is.</summary>
    public const string LockedCode = "DeviceLocked";

    /// <summary>The key service has no device-key signing of its own.</summary>
    public const string NoEntryCode = "DeviceKeyNoEntry";

    public static Error Gated()
        => new(GatedCode, "This key needs user authentication, so it cannot sign as a device key.", string.Empty);

    public static Error Locked()
        => new(LockedCode, "The device is locked, so its device key cannot be used yet.", string.Empty);

    public static Error NoEntry()
        => new(NoEntryCode, "This key service has no device-key signing.", string.Empty);

    /// <summary>True when <paramref name="error"/> is the gated refusal.</summary>
    public static bool IsGated(Error error) => string.Equals(error.Method, GatedCode, StringComparison.Ordinal);

    /// <summary>True when <paramref name="error"/> is the locked-device refusal.</summary>
    public static bool IsLocked(Error error) => string.Equals(error.Method, LockedCode, StringComparison.Ordinal);
}
