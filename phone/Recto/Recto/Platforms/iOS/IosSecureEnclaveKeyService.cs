using System;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using Foundation;
using LocalAuthentication;
using ObjCRuntime;
using Recto.Shared.Common;
using Recto.Shared.Models;
using Recto.Shared.Protocol.V04;
using Recto.Shared.Services;
using Security;
using UIKit;

namespace Recto.Platforms.iOSImpl;

/// <summary>
/// iOS Secure Enclave-backed key service. Generates a P-256 keypair inside
/// the Secure Enclave with a biometric-gated access control; the private key
/// is non-exportable and every sign requires Face ID / Touch ID.
/// <para>
/// Why P-256 and not Ed25519: as of iOS 18 the Secure Enclave only supports
/// <c>kSecAttrKeyTypeECSECPrimeRandom</c> (P-256). The v0.4 protocol's
/// <c>supported_algorithms</c> field lets the phone advertise
/// <c>ecdsa-p256</c> instead of Ed25519 (the default elsewhere).
/// </para>
/// <para>
/// Wire format: <c>SecKeyCreateSignature</c> returns ECDSA signatures in DER
/// form; we convert to raw R || S (64 bytes, big-endian) per the protocol
/// RFC. Public keys are returned by SecKey as the X9.63 65-byte form
/// (0x04 || X || Y); we strip the 0x04 prefix to get the 64-byte raw form.
/// </para>
/// <para>
/// Constants note: the .NET MAUI iOS binding marks <c>SecAttributeKey</c>,
/// <c>SecClass</c>, and <c>SecKeyGenerationAttributeKeys</c> as internal
/// (they're meant to be consumed indirectly via the typed <see cref="SecRecord"/>
/// class). For SecKey generation we need the raw <c>kSec*</c> constants, so we
/// load them directly from the Security framework binary via <c>Dlfcn</c>.
/// </para>
/// </summary>
public sealed class IosSecureEnclaveKeyService : IEnclaveKeyService
{
    public string Algorithm => V04Protocol.AlgorithmEcdsaP256;

    private static NSData TagFor(string keyAlias) =>
        NSData.FromString($"com.recto.phone.enclave.{keyAlias}", NSStringEncoding.UTF8)!;

    public Task<Result<EnclavePublicKey>> GenerateAsync(string keyAlias, CancellationToken ct)
        => Generate(keyAlias, biometricGated: true);

    /// <summary>
    /// The poll key (hard rule 14.2): Secure Enclave-resident like the
    /// identity key, but its ACL is <c>PrivateKeyUsage</c> alone -- no biometry
    /// -- so signing a read never raises Face ID / Touch ID. On iOS the prompt
    /// IS the ACL, so <see cref="SignAsync"/> needs no branch: the enclave
    /// prompts for the identity key and not for this one. Delegated once by the
    /// identity key at pairing; never signs an approval.
    /// </summary>
    public Task<Result<EnclavePublicKey>> GenerateDeviceKeyAsync(string keyAlias, CancellationToken ct)
        => Generate(keyAlias, biometricGated: false);

    /// <summary>
    /// App Attest over this registration (hard rule 14.8): a fresh App Attest key, attested over the challenge and the
    /// two keys being registered. It vouches for this app on this device, and through the app for the identity key,
    /// which this class makes in the Secure Enclave and nowhere else. The App Attest key is used for this one act.
    /// Null where App Attest is not supported. Asks Apple over the network, and never prompts.
    /// </summary>
    public async Task<Result<DeviceEvidence?>> GetDeviceEvidenceAsync(
        string keyAlias, string registrationChallenge, string identityKeyB64u, string pollKeyB64u, CancellationToken ct)
    {
        try
        {
            var service = DeviceCheck.DCAppAttestService.SharedService;
            if (!service.Supported)
            {
                return Result.Success<DeviceEvidence?>(null);
            }
            using var clientDataHash = NSData.FromArray(
                DeviceEvidence.IosClientDataHash(registrationChallenge, identityKeyB64u, pollKeyB64u));
            var keyId = await service.GenerateKeyAsync().WaitAsync(ct).ConfigureAwait(false);
            using var attestation = await service.AttestKeyAsync(keyId, clientDataHash).WaitAsync(ct).ConfigureAwait(false);
            return Result.Success<DeviceEvidence?>(
                DeviceEvidence.Ios(keyId, Convert.ToBase64String(attestation.ToArray())));
        }
        catch (Exception ex)
        {
            return Result.Failure<DeviceEvidence?>(Error.Failure($"App Attest failed: {ex.GetType().Name}"));
        }
    }

    /// <summary>
    /// An assertion by the App Attest key this app was attested with (hard rule 14.8). No prompt. The caller bounds it.
    /// </summary>
    public async Task<Result<string?>> GetDeviceAssertionAsync(
        string appAttestKeyId, byte[] clientDataHash, CancellationToken ct)
    {
        try
        {
            var service = DeviceCheck.DCAppAttestService.SharedService;
            if (!service.Supported)
            {
                return Result.Success<string?>(null);
            }
            using var hash = NSData.FromArray(clientDataHash);
            using var assertion = await service.GenerateAssertionAsync(appAttestKeyId, hash).WaitAsync(ct).ConfigureAwait(false);
            return Result.Success<string?>(Convert.ToBase64String(assertion.ToArray()));
        }
        catch (NSErrorException ex) when (ex.Error.Code == (nint)(long)DeviceCheck.DCError.InvalidKey)
        {
            return Result.Failure<string?>(new Error(DeviceEvidence.KeyGoneCode, "The App Attest key is gone.", string.Empty));
        }
        catch (Exception ex)
        {
            return Result.Failure<string?>(Error.Failure($"App Attest assertion failed: {ex.GetType().Name}"));
        }
    }

    private Task<Result<EnclavePublicKey>> Generate(string keyAlias, bool biometricGated)
    {
        try
        {
            // Idempotent: clear any prior key under this alias.
            DeleteInternal(keyAlias);

            // Biometric ACL: every private-key operation requires Face ID / Touch ID.
            // .biometryCurrentSet invalidates the key if the user enrolls a new biometric
            // (so a stolen + jailbroken phone can't auto-approve via attacker-enrolled biometrics).
            // The poll key drops the biometry flag and keeps the device-only accessibility.
            var flags = biometricGated
                ? SecAccessControlCreateFlags.BiometryCurrentSet | SecAccessControlCreateFlags.PrivateKeyUsage
                : SecAccessControlCreateFlags.PrivateKeyUsage;
            using var accessControl = new SecAccessControl(
                SecAccessible.WhenUnlockedThisDeviceOnly, flags);

            // SecAccessControl derives from NativeObject (CFType-bridged), not
            // NSObject — the NSMutableDictionary indexer needs NSObject, so we
            // bridge via the shared handle. CFType <-> NSObject is toll-free,
            // so the wrapper holds the same underlying object.
            using var accessControlAsNSObject =
                Runtime.GetNSObject<NSObject>(accessControl.Handle)
                    ?? throw new InvalidOperationException("Could not bridge SecAccessControl to NSObject.");

            using var privateKeyAttrs = new NSMutableDictionary
            {
                [SecConstants.AttrIsPermanent] = NSNumber.FromBoolean(true),
                [SecConstants.AttrApplicationTag] = TagFor(keyAlias),
                [SecConstants.AttrAccessControl] = accessControlAsNSObject,
            };

            using var attrs = new NSMutableDictionary
            {
                [SecConstants.AttrKeyType] = SecConstants.AttrKeyTypeECSECPrimeRandom,
                [SecConstants.AttrKeySizeInBits] = NSNumber.FromInt32(256),
                [SecConstants.AttrTokenID] = SecConstants.AttrTokenIDSecureEnclave,
                [SecConstants.PrivateKeyAttrs] = privateKeyAttrs,
            };

            var privateKey = SecKey.CreateRandomKey(attrs, out var error);
            if (privateKey is null || error is not null)
            {
                // Surface the raw OSStatus (e.g. -25293 / errSecAuthFailed
                // when biometric isn't enrolled) verbatim here; the UI layer
                // runs it through EnclaveErrors.TranslateRectoEnclaveError,
                // which owns the actionable-copy mapping (single translation
                // point — do NOT pre-translate here or the helper loses the
                // "-25293" token it keys on).
                return Task.FromResult(Result.Failure<EnclavePublicKey>(
                    Error.Failure($"Secure Enclave keygen failed: {error?.LocalizedDescription ?? "unknown"}")));
            }

            using (privateKey)
            using (var publicKey = privateKey.GetPublicKey())
            {
                if (publicKey is null)
                {
                    return Task.FromResult(Result.Failure<EnclavePublicKey>(
                        Error.Failure("Failed to derive public key from Secure Enclave private key.")));
                }

                var pubBytes = ExtractRawP256PublicKey(publicKey);
                return Task.FromResult(Result.Success(new EnclavePublicKey(pubBytes, Algorithm)));
            }
        }
        catch (Exception ex)
        {
            return Task.FromResult(Result.Failure<EnclavePublicKey>(
                Error.Failure($"iOS enclave keygen exception: {ex.GetType().Name}: {ex.Message}")));
        }
    }

    public Task<Result<bool>> KeyExistsAsync(string keyAlias, CancellationToken ct)
    {
        try
        {
            using var key = LoadPrivateKey(keyAlias);
            return Task.FromResult(Result.Success(key is not null));
        }
        catch (Exception ex)
        {
            return Task.FromResult(Result.Failure<bool>(
                Error.Failure($"iOS enclave key-exists check failed: {ex.Message}")));
        }
    }

    public Task<Result<EnclavePublicKey>> GetPublicKeyAsync(string keyAlias, CancellationToken ct)
    {
        try
        {
            using var privateKey = LoadPrivateKey(keyAlias);
            if (privateKey is null)
            {
                return Task.FromResult(Result.Failure<EnclavePublicKey>(
                    Error.NotFound($"No iOS Secure Enclave key found for alias '{keyAlias}'.")));
            }

            using var publicKey = privateKey.GetPublicKey();
            if (publicKey is null)
            {
                return Task.FromResult(Result.Failure<EnclavePublicKey>(
                    Error.Failure("Failed to derive public key from Secure Enclave private key.")));
            }

            var pubBytes = ExtractRawP256PublicKey(publicKey);
            return Task.FromResult(Result.Success(new EnclavePublicKey(pubBytes, Algorithm)));
        }
        catch (Exception ex)
        {
            return Task.FromResult(Result.Failure<EnclavePublicKey>(
                Error.Failure($"iOS enclave public-key read failed: {ex.Message}")));
        }
    }

    public Task<Result<byte[]>> SignAsync(string keyAlias, byte[] message, CancellationToken ct)
    {
        try
        {
            using var privateKey = LoadPrivateKey(keyAlias);
            if (privateKey is null)
            {
                return Task.FromResult(Result.Failure<byte[]>(
                    Error.NotFound($"No iOS Secure Enclave key found for alias '{keyAlias}'.")));
            }

            // Triggers the biometric prompt; user approval gates the signature.
            // EcdsaSignatureMessageX962Sha256 = pre-hash with SHA-256, sign with ECDSA,
            // return DER-encoded signature (SEQUENCE { r INTEGER, s INTEGER }).
            using var data = NSData.FromArray(message);
            var derSignature = privateKey.CreateSignature(
                SecKeyAlgorithm.EcdsaSignatureMessageX962Sha256,
                data,
                out var error);

            if (derSignature is null || error is not null)
            {
                return Task.FromResult(Result.Failure<byte[]>(
                    Error.Failure($"Secure Enclave sign failed: {error?.LocalizedDescription ?? "unknown"}")));
            }

            var rawSignature = EcdsaSignatureFormat.DerToRaw(derSignature.ToArray());
            return Task.FromResult(Result.Success(rawSignature));
        }
        catch (Exception ex)
        {
            return Task.FromResult(Result.Failure<byte[]>(
                Error.Failure($"iOS enclave sign exception: {ex.GetType().Name}: {ex.Message}")));
        }
    }

    /// <summary>
    /// Signs with a device key and never prompts. On iOS the prompt is the
    /// key's access control, raised by the enclave when the key is used, so
    /// "never prompt" is said to the system: the key is loaded under an
    /// authentication context whose <c>InteractionNotAllowed</c> is true,
    /// and a use that would need Face ID / Touch ID then fails at once in
    /// place of asking. That failure is answered as
    /// <see cref="DeviceKeyRefusal.Gated"/>; nothing is signed. A device key
    /// (<see cref="GenerateDeviceKeyAsync"/>) has no biometric control and
    /// signs under the same context exactly as before. This is the read
    /// signer's entry, called on a timer.
    /// <para>
    /// "Interaction not allowed" has a second meaning, and it is the common
    /// one: the keys here are readable only while the device is unlocked, so
    /// on a LOCKED device the keychain answers the same status for a key
    /// that is not gated at all. The two are told apart, and a locked device
    /// is answered as <see cref="DeviceKeyRefusal.Locked"/>:
    /// the status when the key is LOADED is always the locked device (a
    /// load needs no authentication); at signing, LocalAuthentication's own
    /// "not interactive" is the gated key, and the keychain status is the
    /// gated key only while the device's protected data is available.
    /// </para>
    /// </summary>
    public Task<Result<byte[]>> SignWithDeviceKeyAsync(string keyAlias, byte[] message, CancellationToken ct)
    {
        try
        {
            using var noPrompt = new LAContext { InteractionNotAllowed = true };
            using var privateKey = LoadPrivateKey(keyAlias, noPrompt, out var status);
            if (status == SecStatusCode.InteractionNotAllowed)
            {
                // Loading a key reference asks for no authentication, so
                // this is the device being locked, never the key being gated.
                return Task.FromResult(Result.Failure<byte[]>(DeviceKeyRefusal.Locked()));
            }
            if (privateKey is null)
            {
                return Task.FromResult(Result.Failure<byte[]>(
                    Error.NotFound($"No iOS Secure Enclave key found for alias '{keyAlias}'.")));
            }

            using var data = NSData.FromArray(message);
            var derSignature = privateKey.CreateSignature(
                SecKeyAlgorithm.EcdsaSignatureMessageX962Sha256,
                data,
                out var error);

            if (derSignature is null || error is not null)
            {
                return Task.FromResult(Result.Failure<byte[]>(ReadInteractionFailure(error) switch
                {
                    InteractionFailure.Gated => DeviceKeyRefusal.Gated(),
                    InteractionFailure.Locked => DeviceKeyRefusal.Locked(),
                    _ => Error.Failure($"Secure Enclave sign failed: {error?.LocalizedDescription ?? "unknown"}"),
                }));
            }

            var rawSignature = EcdsaSignatureFormat.DerToRaw(derSignature.ToArray());
            return Task.FromResult(Result.Success(rawSignature));
        }
        catch (Exception ex)
        {
            return Task.FromResult(Result.Failure<byte[]>(
                Error.Failure($"iOS enclave sign exception: {ex.GetType().Name}: {ex.Message}")));
        }
    }

    // errSecInteractionNotAllowed, and LAError.notInteractive in the
    // LocalAuthentication error domain: the two shapes in which the system
    // reports "this needed the user and interaction was not allowed".
    private const long ErrSecInteractionNotAllowed = -25308;
    private const long LaErrorNotInteractive = -1004;
    private const string LaErrorDomain = "com.apple.LocalAuthentication";

    private enum InteractionFailure
    {
        /// <summary>Some other failure.</summary>
        None,

        /// <summary>The key needs the user, and interaction was not allowed.</summary>
        Gated,

        /// <summary>The device is locked.</summary>
        Locked,
    }

    /// <summary>
    /// Reads a signing failure, and the errors it wraps. LocalAuthentication
    /// saying "not interactive" is the key's own access control asking for
    /// the user: gated. The keychain saying "interaction not allowed" is the
    /// gated key only while the device's protected data is available;
    /// otherwise the device is locked.
    /// </summary>
    private static InteractionFailure ReadInteractionFailure(NSError? error)
    {
        for (var depth = 0; error is not null && depth < 4; depth++)
        {
            var code = (long)error.Code;
            if (code == LaErrorNotInteractive && error.Domain == LaErrorDomain)
            {
                return InteractionFailure.Gated;
            }
            if (code == ErrSecInteractionNotAllowed)
            {
                return ProtectedDataAvailable() ? InteractionFailure.Gated : InteractionFailure.Locked;
            }
            error = error.UserInfo?[NSError.UnderlyingErrorKey] as NSError;
        }
        return InteractionFailure.None;
    }

    /// <summary>
    /// True while the device is unlocked enough to read protected data. Read
    /// on the main thread, where the application object is read. When it
    /// cannot be read the answer is false: the failure is then reported as a
    /// locked device, an ordinary state, and never as a gated key.
    /// </summary>
    private static bool ProtectedDataAvailable()
    {
        try
        {
            var available = false;
            var application = UIApplication.SharedApplication;
            application.InvokeOnMainThread(() => available = application.ProtectedDataAvailable);
            return available;
        }
        catch
        {
            return false;
        }
    }

    public Task<Result> DeleteAsync(string keyAlias, CancellationToken ct)
    {
        try
        {
            DeleteInternal(keyAlias);
            return Task.FromResult(Result.Success());
        }
        catch (Exception ex)
        {
            return Task.FromResult(Result.Failure(
                Error.Failure($"iOS enclave delete failed: {ex.Message}")));
        }
    }

    // --- internals ---

    private static SecKey? LoadPrivateKey(string keyAlias)
        => LoadPrivateKey(keyAlias, context: null, out _);

    /// <summary>
    /// Loads the key, under <paramref name="context"/> when one is given:
    /// the key then carries that authentication context into every use.
    /// </summary>
    private static SecKey? LoadPrivateKey(string keyAlias, LAContext? context, out SecStatusCode status)
    {
        var query = new SecRecord(SecKind.Key)
        {
            KeyClass = SecKeyClass.Private,
            ApplicationTag = TagFor(keyAlias),
            KeyType = SecKeyType.EC,
        };
        if (context is not null)
        {
            query.AuthenticationContext = context;
        }

        var result = SecKeyChain.QueryAsConcreteType(query, out status);
        return status == SecStatusCode.Success ? result as SecKey : null;
    }

    private static void DeleteInternal(string keyAlias)
    {
        var query = new SecRecord(SecKind.Key)
        {
            KeyClass = SecKeyClass.Private,
            ApplicationTag = TagFor(keyAlias),
        };
        // SecItemDelete equivalent; ignore status — we don't care if the key didn't exist.
        SecKeyChain.Remove(query);
    }

    /// <summary>
    /// SecKey's external representation for a P-256 public key is the 65-byte
    /// uncompressed point (0x04 || X || Y per X9.63). The protocol RFC's
    /// <c>ecdsa-p256</c> wire format is the 64-byte raw concatenation
    /// (X || Y, big-endian), so we strip the 0x04 prefix.
    /// </summary>
    private static byte[] ExtractRawP256PublicKey(SecKey publicKey)
    {
        using var data = publicKey.GetExternalRepresentation();
        if (data is null)
        {
            throw new InvalidOperationException("SecKey.GetExternalRepresentation returned null.");
        }

        var bytes = data.ToArray();
        if (bytes.Length == 65 && bytes[0] == 0x04)
        {
            var raw = new byte[64];
            Buffer.BlockCopy(bytes, 1, raw, 0, 64);
            return raw;
        }
        if (bytes.Length == 64)
        {
            return bytes;
        }
        throw new InvalidOperationException(
            $"Unexpected P-256 public-key external representation length: {bytes.Length}");
    }

    /// <summary>
    /// kSec* NSString constants loaded directly from the Security framework
    /// binary at runtime. We can't use the <c>SecAttributeKey</c> /
    /// <c>SecKeyGenerationAttributeKeys</c> classes because the .NET MAUI iOS
    /// binding marks them as internal — they're meant to be accessed indirectly
    /// via <see cref="SecRecord"/>, but SecKey generation needs the raw
    /// dictionary form.
    /// </summary>
    private static class SecConstants
    {
        private const string SecurityLibrary =
            "/System/Library/Frameworks/Security.framework/Security";

        private static readonly IntPtr _handle = Dlfcn.dlopen(SecurityLibrary, 0);

        public static readonly NSString AttrKeyType = Load("kSecAttrKeyType");
        public static readonly NSString AttrKeyTypeECSECPrimeRandom = Load("kSecAttrKeyTypeECSECPrimeRandom");
        public static readonly NSString AttrTokenID = Load("kSecAttrTokenID");
        public static readonly NSString AttrTokenIDSecureEnclave = Load("kSecAttrTokenIDSecureEnclave");
        public static readonly NSString AttrIsPermanent = Load("kSecAttrIsPermanent");
        public static readonly NSString AttrApplicationTag = Load("kSecAttrApplicationTag");
        public static readonly NSString AttrAccessControl = Load("kSecAttrAccessControl");
        public static readonly NSString AttrKeySizeInBits = Load("kSecAttrKeySizeInBits");
        public static readonly NSString PrivateKeyAttrs = Load("kSecPrivateKeyAttrs");

        private static NSString Load(string symbol)
        {
            if (_handle == IntPtr.Zero)
            {
                throw new InvalidOperationException(
                    $"Failed to dlopen Security.framework while loading '{symbol}'.");
            }

            // dlsym gives us the address of the NSString* — i.e. a pointer to a
            // pointer. Dereference once to get the actual NSString instance.
            var symAddr = Dlfcn.dlsym(_handle, symbol);
            if (symAddr == IntPtr.Zero)
            {
                throw new InvalidOperationException(
                    $"Symbol '{symbol}' not found in Security.framework.");
            }

            var nsStringPtr = Marshal.ReadIntPtr(symAddr);
            if (nsStringPtr == IntPtr.Zero)
            {
                throw new InvalidOperationException(
                    $"Symbol '{symbol}' resolved but its NSString value is null.");
            }

            return Runtime.GetNSObject<NSString>(nsStringPtr)
                ?? throw new InvalidOperationException(
                    $"Could not wrap NSString for '{symbol}'.");
        }
    }
}
