using System.Threading;
using System.Threading.Tasks;
using Recto.Shared.Common;
using Recto.Shared.Models;

namespace Recto.Shared.Services;

/// <summary>
/// The key service of a release build for a target with no hardware key store
/// (Windows, Mac Catalyst). It holds no key material and refuses every key act by
/// name, so such a build cannot pair as an authority device. The software key
/// service exists only in DEBUG builds of those targets, for the dev loop.
/// </summary>
public sealed class NoHardwareKeyService : IEnclaveKeyService
{
    public const string RefusalCode = "Enclave.NoHardwareKeyStore";

    public static readonly Error Refusal = new(
        RefusalCode,
        "This build has no hardware key store, so it cannot pair or sign. "
        + "Recto pairs from an iPhone or an Android phone.",
        string.Empty);

    /// <summary>Names no algorithm: this build has none to offer.</summary>
    public string Algorithm => "none";

    public Task<Result<EnclavePublicKey>> GenerateAsync(string keyAlias, CancellationToken ct)
        => Task.FromResult(Result.Failure<EnclavePublicKey>(Refusal));

    public Task<Result<EnclavePublicKey>> GenerateDeviceKeyAsync(string keyAlias, CancellationToken ct)
        => Task.FromResult(Result.Failure<EnclavePublicKey>(Refusal));

    public Task<Result<bool>> KeyExistsAsync(string keyAlias, CancellationToken ct)
        => Task.FromResult(Result.Success(false));

    public Task<Result<EnclavePublicKey>> GetPublicKeyAsync(string keyAlias, CancellationToken ct)
        => Task.FromResult(Result.Failure<EnclavePublicKey>(Refusal));

    public Task<Result<byte[]>> SignAsync(string keyAlias, byte[] message, CancellationToken ct)
        => Task.FromResult(Result.Failure<byte[]>(Refusal));

    public Task<Result> DeleteAsync(string keyAlias, CancellationToken ct)
        => Task.FromResult(Result.Success());
}
