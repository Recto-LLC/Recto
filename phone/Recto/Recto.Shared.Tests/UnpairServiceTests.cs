using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Recto.Shared.Common;
using Recto.Shared.Models;
using Recto.Shared.Services;
using Xunit;

namespace Recto.Shared.Tests;

/// <summary>
/// The unpair-all guard's red-build suite: a genesis member's key must be
/// unreachable by the full wipe. Remove the guard from UnpairService and
/// the first three tests go red by construction — that is their job.
/// </summary>
public class UnpairServiceTests
{
    private const string Alias = "recto.phone.identity";

    // ── fakes ────────────────────────────────────────────────────────────

    private sealed class FakeGenesisState : IGenesisStateService
    {
        public bool? Member;              // null => the read FAILS
        public Task<Result<bool>> IsGenesisMemberAsync(CancellationToken ct)
            => Task.FromResult(Member is null
                ? Result.Failure<bool>(Error.Failure("storage unreadable"))
                : Result.Success(Member.Value));
        public Task<Result> MarkGenesisMemberAsync(string id, CancellationToken ct)
            => Task.FromResult(Result.Success());
        public Task<Result> ClearAsync(CancellationToken ct)
            => Task.FromResult(Result.Success());
    }

    private sealed class FakePairingState : IPairingStateService
    {
        public List<string> Calls = new();
        public Task<Result<PairingState?>> GetCurrentAsync(CancellationToken ct)
            => Task.FromResult(Result.Success<PairingState?>(null));
        public Task<Result> SaveAsync(PairingState state, CancellationToken ct)
        {
            Calls.Add(state is null ? "save(null)" : "save");
            return Task.FromResult(Result.Success());
        }
        public Task<Result> ClearAsync(CancellationToken ct)
        {
            Calls.Add("clear");
            return Task.FromResult(Result.Success());
        }
        public Task<Result<string>> GetOrCreatePhoneIdAsync(CancellationToken ct)
            => Task.FromResult(Result.Success("phone-id"));
    }

    private sealed class FakeTotp : ITotpService
    {
        public int ClearAllCalls;
        public Task<Result> ProvisionAsync(string a, string s, int p, int d, string alg, CancellationToken ct)
            => Task.FromResult(Result.Success());
        public Task<Result<bool>> ExistsAsync(string a, CancellationToken ct)
            => Task.FromResult(Result.Success(false));
        public Task<Result<string>> GenerateAsync(string a, CancellationToken ct)
            => Task.FromResult(Result.Success("000000"));
        public Task<Result> DeleteAsync(string a, CancellationToken ct)
            => Task.FromResult(Result.Success());
        public Task<Result> ClearAllAsync(CancellationToken ct)
        {
            ClearAllCalls++;
            return Task.FromResult(Result.Success());
        }
    }

    private sealed class FakeEnclaveKeys : IEnclaveKeyService
    {
        public List<string> Deleted = new();
        public string Algorithm => "ecdsa-p256";
        public Task<Result<EnclavePublicKey>> GenerateAsync(string keyAlias, CancellationToken ct)
            => throw new NotSupportedException();
        public Task<Result<bool>> KeyExistsAsync(string keyAlias, CancellationToken ct)
            => Task.FromResult(Result.Success(true));
        public Task<Result<EnclavePublicKey>> GetPublicKeyAsync(string keyAlias, CancellationToken ct)
            => throw new NotSupportedException();
        public Task<Result<byte[]>> SignAsync(string keyAlias, byte[] message, CancellationToken ct)
            => throw new NotSupportedException();
        public Task<Result> DeleteAsync(string keyAlias, CancellationToken ct)
        {
            Deleted.Add(keyAlias);
            return Task.FromResult(Result.Success());
        }
    }

    private sealed class FakePhrases : IRecoveryPhraseStore
    {
        public string? Phrase;
        public bool Throws;
        public bool? Provisioned = false;   // null: the marker cannot be read
        public Task<string?> ReadAsync(string alias)
            => Throws ? throw new InvalidOperationException("secure storage unavailable")
                : Task.FromResult(alias == UnpairService.RecoveryPhraseAlias ? Phrase : null);
        public Task WriteAsync(string alias, string phrase) => throw new NotSupportedException();
        public bool WasProvisioned(string alias)
            => alias == UnpairService.RecoveryPhraseAlias && (Provisioned ?? throw new InvalidOperationException("preferences unavailable"));
    }

    private static (UnpairService Sut, FakeGenesisState Genesis, FakePairingState Pairing, FakeTotp Totp, FakeEnclaveKeys Keys) Build(
        bool? member, FakePhrases? phrases = null)
    {
        var genesis = new FakeGenesisState { Member = member };
        var pairing = new FakePairingState();
        var totp = new FakeTotp();
        var keys = new FakeEnclaveKeys();
        return (new UnpairService(pairing, totp, keys, genesis, phrases ?? new FakePhrases()), genesis, pairing, totp, keys);
    }

    // ── the recovery phrase ──────────────────────────────────────────────

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task APhoneThatHoldsAPhrase_OrCannotSay_IsNotWipedUnasked(bool unreadable)
    {
        var (sut, _, pairing, totp, keys) = Build(member: false,
            new FakePhrases { Phrase = "made up words", Throws = unreadable });

        var result = await sut.UnpairAllAsync(Alias, CancellationToken.None);

        Assert.Equal(UnpairAllStatus.RefusedRecoveryPhrase, result.Status);
        Assert.Contains("Back the phrase up", result.Message);
        Assert.Contains("keep vault", result.Message);
        Assert.DoesNotContain("made up words", result.Message);
        Assert.Empty(keys.Deleted);
        Assert.Empty(pairing.Calls);
        Assert.Equal(0, totp.ClearAllCalls);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(null)]
    public async Task APhraseThatReadsEmptyWhereOneWasSetUp_IsNotWipedUnasked(bool? provisioned)
    {
        var (sut, _, pairing, totp, keys) = Build(member: false, new FakePhrases { Provisioned = provisioned });

        var result = await sut.UnpairAllAsync(Alias, CancellationToken.None);

        Assert.Equal(UnpairAllStatus.RefusedRecoveryPhrase, result.Status);
        Assert.Empty(keys.Deleted);
        Assert.Empty(pairing.Calls);
        Assert.Equal(0, totp.ClearAllCalls);

        Assert.Equal(UnpairAllStatus.Completed,
            (await sut.UnpairAllAsync(Alias, CancellationToken.None, eraseRecoveryPhrase: true)).Status);
    }

    [Fact]
    public async Task APhoneThatNeverHadAPhrase_IsWipedAsBefore()
    {
        var (sut, _, _, totp, _) = Build(member: false, new FakePhrases());

        Assert.Equal(UnpairAllStatus.Completed, (await sut.UnpairAllAsync(Alias, CancellationToken.None)).Status);
        Assert.Equal(1, totp.ClearAllCalls);
    }

    [Fact]
    public async Task ThePersonWhoSaidThePhraseMayGo_IsHeard()
    {
        var (sut, _, _, totp, keys) = Build(member: false, new FakePhrases { Phrase = "made up words" });

        var result = await sut.UnpairAllAsync(Alias, CancellationToken.None, eraseRecoveryPhrase: true);

        Assert.Equal(UnpairAllStatus.Completed, result.Status);
        Assert.Equal(1, totp.ClearAllCalls);
        Assert.Contains(Alias, keys.Deleted);
    }

    [Fact]
    public async Task AGenesisMember_IsRefusedWhateverWasSaidAboutThePhrase()
    {
        var (sut, _, _, totp, _) = Build(member: true, new FakePhrases { Phrase = "made up words" });

        var result = await sut.UnpairAllAsync(Alias, CancellationToken.None, eraseRecoveryPhrase: true);

        Assert.Equal(UnpairAllStatus.RefusedGenesisMember, result.Status);
        Assert.Equal(0, totp.ClearAllCalls);
    }

    [Fact]
    public void TheOneTapPath_NeverSaysThePhraseMayGo_AndShowsTheRefusal()
    {
        var page = Capability.ProfileSigningInputTests.HomePage();
        var fresh = Capability.ProfileSigningInputTests.MethodBody(page, "HandleStartFreshClick");
        Assert.DoesNotContain("eraseRecoveryPhrase", fresh);
        Assert.Contains("UnpairAllStatus.RefusedRecoveryPhrase", fresh);
        var button = page.IndexOf("@onclick=\"HandleStartFreshClick\">", StringComparison.Ordinal);
        Assert.True(button > 0);
        Assert.Contains("@_errorMessage", page.Substring(button, 420));
    }

    [Fact]
    public void TheHost_RegistersTheStoreTheGuardReads()
    {
        var dir = new System.IO.DirectoryInfo(System.AppContext.BaseDirectory);
        while (dir is not null && !System.IO.File.Exists(System.IO.Path.Combine(dir.FullName, "Recto", "MauiProgram.cs")))
        {
            dir = dir.Parent;
        }
        Assert.NotNull(dir);
        var program = System.IO.File.ReadAllText(System.IO.Path.Combine(dir!.FullName, "Recto", "MauiProgram.cs"));
        Assert.Contains("AddSingleton<IRecoveryPhraseStore>(MauiRecoveryPhraseStore.Instance)", program);
    }

    // ── the guard (red-builds the violation) ─────────────────────────────

    [Fact]
    public async Task GenesisMember_Refuses_AndTouchesNothing()
    {
        var (sut, _, pairing, totp, keys) = Build(member: true);

        var result = await sut.UnpairAllAsync(Alias, CancellationToken.None);

        Assert.Equal(UnpairAllStatus.RefusedGenesisMember, result.Status);
        Assert.Empty(keys.Deleted);          // the enclave key was NOT deleted
        Assert.Empty(pairing.Calls);         // pairing record untouched
        Assert.Equal(0, totp.ClearAllCalls); // secrets untouched
    }

    [Fact]
    public async Task GenesisMember_RefusalNamesTheRecoveryCeremony()
    {
        var (sut, _, _, _, _) = Build(member: true);

        var result = await sut.UnpairAllAsync(Alias, CancellationToken.None);

        // The refusal must NAME the ceremony: a refusal without a route
        // gets worked around, not respected.
        Assert.NotNull(result.Message);
        Assert.Contains("recovery ceremony", result.Message);
        Assert.Contains("recovery phrase", result.Message);
        Assert.Contains("re-enrol", result.Message);
    }

    [Fact]
    public async Task UnreadableMembership_FailsClosed_RefusesAndTouchesNothing()
    {
        var (sut, _, pairing, totp, keys) = Build(member: null); // read FAILS

        var result = await sut.UnpairAllAsync(Alias, CancellationToken.None);

        Assert.Equal(UnpairAllStatus.RefusedGenesisMember, result.Status);
        Assert.Empty(keys.Deleted);
        Assert.Empty(pairing.Calls);
        Assert.Equal(0, totp.ClearAllCalls);
    }

    // ── the pre-genesis path (today's behavior, preserved) ───────────────

    [Fact]
    public async Task NonMember_WipeCompletes_InTheHistoricalOrder()
    {
        var (sut, _, pairing, totp, keys) = Build(member: false);

        var result = await sut.UnpairAllAsync(Alias, CancellationToken.None);

        Assert.Equal(UnpairAllStatus.Completed, result.Status);
        // Order preserved from the pre-guard sequence: pairing cleared
        // FIRST (via the historical SaveAsync(null)), then TOTP, then the
        // enclave key — so in-flight poll loops see "no longer paired"
        // before their backing keys go.
        Assert.Equal(new[] { "save(null)" }, pairing.Calls);
        Assert.Equal(1, totp.ClearAllCalls);
        // Rule 14.2 (2026-09-21): the delegated poll key goes with the identity
        // that delegated it -- identity first, then the poll key.
        Assert.Equal(new[] { Alias, PollSigning.PollKeyAlias }, keys.Deleted);
    }

    [Fact]
    public async Task NonMember_KeyDeletionFailure_ReportsFailed()
    {
        var genesis = new FakeGenesisState { Member = false };
        var pairing = new FakePairingState();
        var totp = new FakeTotp();
        var keys = new ThrowingEnclaveKeys();
        var sut = new UnpairService(pairing, totp, keys, genesis, new FakePhrases());

        var result = await sut.UnpairAllAsync(Alias, CancellationToken.None);

        Assert.Equal(UnpairAllStatus.Failed, result.Status);
        Assert.NotNull(result.Message);
    }

    private sealed class ThrowingEnclaveKeys : IEnclaveKeyService
    {
        public string Algorithm => "ecdsa-p256";
        public Task<Result<EnclavePublicKey>> GenerateAsync(string keyAlias, CancellationToken ct)
            => throw new NotSupportedException();
        public Task<Result<bool>> KeyExistsAsync(string keyAlias, CancellationToken ct)
            => Task.FromResult(Result.Success(true));
        public Task<Result<EnclavePublicKey>> GetPublicKeyAsync(string keyAlias, CancellationToken ct)
            => throw new NotSupportedException();
        public Task<Result<byte[]>> SignAsync(string keyAlias, byte[] message, CancellationToken ct)
            => throw new NotSupportedException();
        public Task<Result> DeleteAsync(string keyAlias, CancellationToken ct)
            => throw new InvalidOperationException("enclave unavailable");
    }
}
