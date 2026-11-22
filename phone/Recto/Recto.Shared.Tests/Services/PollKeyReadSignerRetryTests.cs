using Microsoft.Extensions.Logging;
using Recto.Shared.Common;
using Recto.Shared.Models;
using Recto.Shared.Protocol.V04;
using Recto.Shared.Services;
using Xunit;

namespace Recto.Shared.Tests.Services;

/// <summary>
/// The read signer tries a failed signing once more, and says why a read
/// went unsigned: a reason from a fixed list, the route from the client's
/// fixed list and the failure's kind. It never logs the phone id, a request
/// id, a key, a signature or an exception's text, and it logs a reason when
/// it changes, not on every poll.
/// </summary>
public class PollKeyReadSignerRetryTests
{
    private const string PhoneId = "CANARY-PHONE-ID";
    private const string RequestId = "CANARY-REQUEST-ID";
    private const string ExceptionText = "CANARY-EXCEPTION-TEXT";
    private const string ErrorText = "CANARY-ERROR-TEXT";
    private const string PollKey = "CANARY-POLL-PUBLIC-KEY";

    private static readonly string[] Canaries = [PhoneId, RequestId, ExceptionText, ErrorText, PollKey];

    // --- the retry ---

    [Fact]
    public async Task AFirstSigningThatFails_IsTriedOnceMore_AndTheReadIsSigned()
    {
        var enclave = new ScriptedEnclave(Fail, Succeed);
        var log = new CapturingLogger();
        var signer = new PollKeyReadSigner(enclave, new FixedPairing(PollKey), log);

        var headers = await signer.SignReadAsync(PhoneId, "/v0.4/pending", CancellationToken.None);

        Assert.NotNull(headers);
        Assert.Equal(2, enclave.SignCalls);
        Assert.DoesNotContain(log.Lines, l => l.Level >= LogLevel.Warning);
        Assert.Contains(log.Lines, l => l.Text == "Read /v0.4/pending signed on attempt 2");
    }

    [Fact]
    public async Task AFirstSigningThatThrows_IsTriedOnceMore_AndTheReadIsSigned()
    {
        var enclave = new ScriptedEnclave(Throw, Succeed);
        var signer = new PollKeyReadSigner(enclave, new FixedPairing(PollKey), new CapturingLogger());

        Assert.NotNull(await signer.SignReadAsync(PhoneId, "/v0.4/pending", CancellationToken.None));
        Assert.Equal(2, enclave.SignCalls);
    }

    [Fact]
    public async Task EachAttempt_SignsThePollAliasOverThePollPayload()
    {
        var enclave = new ScriptedEnclave(Fail, Succeed);
        var signer = new PollKeyReadSigner(enclave, new FixedPairing(PollKey));

        await signer.SignReadAsync(PhoneId, "/v0.4/manage/phones", CancellationToken.None);

        Assert.All(enclave.Aliases, alias => Assert.Equal(PollSigning.PollKeyAlias, alias));
        Assert.All(enclave.Messages, message =>
        {
            Assert.StartsWith($"{PollSigning.Prefix}|{PhoneId}|", message);
            Assert.EndsWith("|/v0.4/manage/phones", message);
        });
    }

    [Fact]
    public async Task TwoFailures_AreNotTriedAThirdTime_AndTheReadGoesUnsignedWithItsReason()
    {
        var enclave = new ScriptedEnclave(Fail, Fail, Succeed);
        var log = new CapturingLogger();
        var signer = new PollKeyReadSigner(enclave, new FixedPairing(PollKey), log);

        var headers = await signer.SignReadAsync(PhoneId, "/v0.4/pending", CancellationToken.None);

        Assert.Null(headers);
        Assert.Equal(PollKeyReadSigner.Attempts, enclave.SignCalls);
        var warning = Assert.Single(log.Lines, l => l.Level == LogLevel.Warning);
        Assert.Equal(
            "Read /v0.4/pending goes unsigned: sign_failed FailureError after 2 signing attempt(s)", warning.Text);
    }

    [Fact]
    public async Task ASigningThatThrowsTwice_IsReportedByItsTypeName_NeverItsText()
    {
        var log = new CapturingLogger();
        var signer = new PollKeyReadSigner(new ScriptedEnclave(Throw, Throw), new FixedPairing(PollKey), log);

        var headers = await signer.SignReadAsync(PhoneId, "/v0.4/pending", CancellationToken.None);

        Assert.Null(headers);
        var warning = Assert.Single(log.Lines, l => l.Level == LogLevel.Warning);
        Assert.Equal(
            "Read /v0.4/pending goes unsigned: sign_threw InvalidOperationException after 2 signing attempt(s)",
            warning.Text);
        Assert.Null(warning.Exception);
    }

    // --- the reasons that need no signing ---

    [Fact]
    public async Task APairingWithNoPollKey_IsNotSigned_AndSaysSo()
    {
        var enclave = new ScriptedEnclave();
        var log = new CapturingLogger();
        var signer = new PollKeyReadSigner(enclave, new FixedPairing(pollKey: null), log);

        Assert.Null(await signer.SignReadAsync(PhoneId, "/v0.4/pending", CancellationToken.None));

        Assert.Equal(0, enclave.SignCalls);
        Assert.Equal(
            "Read /v0.4/pending goes unsigned: no_poll_key (no kind) after 0 signing attempt(s)",
            Assert.Single(log.Lines).Text);
    }

    [Fact]
    public async Task NoPairingRecord_IsANormalState_LoggedForInformation_AndKeptOutOfRecentErrors()
    {
        var before = RecentErrors.Snapshot().Count(e => e.Message.Contains("not_paired", StringComparison.Ordinal));
        var enclave = new ScriptedEnclave();
        var log = new CapturingLogger();
        var signer = new PollKeyReadSigner(enclave, new FixedPairing(Result.Success<PairingState?>(null)), log);

        for (var poll = 0; poll < 3; poll++)
        {
            Assert.Null(await signer.SignReadAsync(PhoneId, "/v0.4/pending", CancellationToken.None));
        }

        // Said once, for information; nothing is signed and nothing is a warning.
        var line = Assert.Single(log.Lines);
        Assert.Equal(LogLevel.Information, line.Level);
        Assert.Equal("Read /v0.4/pending goes unsigned: not_paired (no kind) after 0 signing attempt(s)", line.Text);
        Assert.Equal(0, enclave.SignCalls);
        // Settings' recent errors never hears of it.
        Assert.Equal(before, RecentErrors.Snapshot().Count(e => e.Message.Contains("not_paired", StringComparison.Ordinal)));
        Assert.DoesNotContain(RecentErrors.Snapshot(), e => e.Message.Contains("not_paired", StringComparison.Ordinal));
    }

    [Fact]
    public async Task EveryOtherReason_IsAWarning()
    {
        var endings = new (ScriptedEnclave Enclave, FixedPairing Pairing)[]
        {
            (new ScriptedEnclave(Fail, Fail), new FixedPairing(PollKey)),
            (new ScriptedEnclave(Throw, Throw), new FixedPairing(PollKey)),
            (new ScriptedEnclave(Gated), new FixedPairing(PollKey)),
            (new ScriptedEnclave(), new FixedPairing(pollKey: null)),
            (new ScriptedEnclave(), new FixedPairing(throws: true)),
        };
        foreach (var (enclave, pairing) in endings)
        {
            var log = new CapturingLogger();
            await new PollKeyReadSigner(enclave, pairing, log).SignReadAsync(PhoneId, "/v0.4/pending", CancellationToken.None);
            Assert.Equal(LogLevel.Warning, Assert.Single(log.Lines).Level);
        }
    }

    // --- a poll key that would raise a prompt ---

    [Fact]
    public async Task APollKeyRefusedAsGated_IsNotRetried_AndTheReadGoesUnsignedWithItsOwnReason()
    {
        // A second call could only ask the same key again; on a key store that prompts, it would be a second prompt.
        var enclave = new ScriptedEnclave(Gated, Succeed);
        var log = new CapturingLogger();
        var signer = new PollKeyReadSigner(enclave, new FixedPairing(PollKey), log);

        var headers = await signer.SignReadAsync(PhoneId, "/v0.4/pending", CancellationToken.None);

        Assert.Null(headers);
        Assert.Equal(1, enclave.SignCalls);
        Assert.Equal(1, enclave.DeviceKeyCalls);
        var warning = Assert.Single(log.Lines);
        Assert.Equal(LogLevel.Warning, warning.Level);
        Assert.Equal("Read /v0.4/pending goes unsigned: poll_key_gated (no kind) after 1 signing attempt(s)", warning.Text);
        Assert.Contains(RecentErrors.Snapshot(), e => e.Phase == PollKeyReadSigner.RecentErrorsPhase
            && e.Message == "This phone's reads are going unsigned: poll_key_gated.");
    }

    [Fact]
    public async Task AGatedPollKey_IsAskedOncePerRead_NeverTwice_OverManyPolls()
    {
        var enclave = new ScriptedEnclave(Gated, Gated, Gated, Gated, Gated);
        var log = new CapturingLogger();
        var signer = new PollKeyReadSigner(enclave, new FixedPairing(PollKey), log);

        for (var poll = 0; poll < 5; poll++)
        {
            Assert.Null(await signer.SignReadAsync(PhoneId, "/v0.4/pending", CancellationToken.None));
        }

        Assert.Equal(5, enclave.SignCalls);
        Assert.Single(log.Lines);
    }

    [Fact]
    public async Task AFailureFollowedByAGatedRefusal_StopsAtTheRefusal()
    {
        var enclave = new ScriptedEnclave(Fail, Gated, Succeed);
        var log = new CapturingLogger();
        var signer = new PollKeyReadSigner(enclave, new FixedPairing(PollKey), log);

        Assert.Null(await signer.SignReadAsync(PhoneId, "/v0.4/pending", CancellationToken.None));

        Assert.Equal(2, enclave.SignCalls);
        Assert.Contains("poll_key_gated (no kind) after 2 signing attempt(s)", Assert.Single(log.Lines).Text);
    }

    [Fact]
    public async Task AKeyStoreThatCouldNotDescribeTheKey_IsAnOrdinaryFailure_Retried_NeverCalledGated()
    {
        // What the Android key service answers a device-key signing when the keystore's own reading of the
        // key failed: a plain failure, not the gated refusal. A passing keystore error must not tell the
        // user to pair again.
        Task<Result<byte[]>> Unreadable() => Task.FromResult(Result.Failure<byte[]>(
            Error.Failure("Android keystore could not report whether the key needs user authentication.")));

        var recovers = new ScriptedEnclave(Unreadable, Succeed);
        var quiet = new CapturingLogger();
        Assert.NotNull(await new PollKeyReadSigner(recovers, new FixedPairing(PollKey), quiet)
            .SignReadAsync(PhoneId, "/v0.4/pending", CancellationToken.None));
        Assert.Equal(2, recovers.SignCalls);
        Assert.DoesNotContain(quiet.Lines, l => l.Level >= LogLevel.Warning);

        var persists = new ScriptedEnclave(Unreadable, Unreadable);
        var log = new CapturingLogger();
        Assert.Null(await new PollKeyReadSigner(persists, new FixedPairing(PollKey), log)
            .SignReadAsync(PhoneId, "/v0.4/pending", CancellationToken.None));
        Assert.Equal(2, persists.SignCalls);
        Assert.Equal(
            "Read /v0.4/pending goes unsigned: sign_failed FailureError after 2 signing attempt(s)",
            Assert.Single(log.Lines).Text);
        Assert.DoesNotContain("poll_key_gated", log.Lines[0].Text);
    }

    [Fact]
    public async Task EveryReadSigning_GoesThroughTheDeviceKeyEntry_WhichNeverPrompts()
    {
        var enclave = new ScriptedEnclave(Fail, Succeed, Succeed);
        var signer = new PollKeyReadSigner(enclave, new FixedPairing(PollKey));

        await signer.SignReadAsync(PhoneId, "/v0.4/pending", CancellationToken.None);
        await signer.SignReadAsync(PhoneId, "/v0.4/manage/phones", CancellationToken.None);

        Assert.Equal(3, enclave.DeviceKeyCalls);
        Assert.Equal(0, enclave.PromptingCalls);
    }

    [Fact]
    public async Task AKeyServiceWithNoDeviceKeyEntryOfItsOwn_IsRefused_AndItsPromptingEntryIsNeverCalled()
    {
        // The interface's default. It used to fall back to the signing that may prompt; a key service that
        // gates keys and left the method out would then have prompted on the timer.
        var plain = new PlainEnclave();

        var signed = await ((IEnclaveKeyService)plain).SignWithDeviceKeyAsync("alias", new byte[] { 1 }, CancellationToken.None);

        Assert.True(signed.IsFailure);
        Assert.Equal(DeviceKeyRefusal.NoEntryCode, signed.Error.Method);
        Assert.Equal(0, plain.SignCalls);
    }

    [Fact]
    public async Task ThatRefusal_ReachesTheLogAsAnOrdinaryFailure_NamedByItsCode()
    {
        var plain = new PlainEnclave();
        var log = new CapturingLogger();
        var signer = new PollKeyReadSigner(plain, new FixedPairing(PollKey), log);

        Assert.Null(await signer.SignReadAsync(PhoneId, "/v0.4/pending", CancellationToken.None));

        Assert.Equal(0, plain.SignCalls);
        Assert.Equal(
            "Read /v0.4/pending goes unsigned: sign_failed DeviceKeyNoEntry after 2 signing attempt(s)",
            Assert.Single(log.Lines).Text);
    }

    [Fact]
    public void TheRefusals_AreRecognisedByTheirCodes_AndNameNoKey()
    {
        var gated = DeviceKeyRefusal.Gated();
        var locked = DeviceKeyRefusal.Locked();
        var none = DeviceKeyRefusal.NoEntry();

        Assert.True(DeviceKeyRefusal.IsGated(gated));
        Assert.False(DeviceKeyRefusal.IsGated(locked));
        Assert.False(DeviceKeyRefusal.IsGated(none));
        Assert.True(DeviceKeyRefusal.IsLocked(locked));
        Assert.False(DeviceKeyRefusal.IsLocked(gated));
        Assert.Equal("DeviceKeyGated", gated.Method);
        Assert.Equal("DeviceLocked", locked.Method);
        Assert.Equal("DeviceKeyNoEntry", none.Method);
        // A sentence that happens to hold the code is not the refusal.
        Assert.False(DeviceKeyRefusal.IsGated(Error.Failure("DeviceKeyGated")));
        Assert.All(new[] { gated, locked, none }, e => Assert.DoesNotContain(PollSigning.PollKeyAlias, e.Message));
    }

    // --- a locked device ---

    [Fact]
    public async Task ALockedDevice_IsANormalState_NotRetried_LoggedForInformation_AndKeptOutOfRecentErrors()
    {
        // The key is there and is not gated; the key store will not use it until the device is unlocked.
        var enclave = new ScriptedEnclave(Locked, Locked, Locked);
        var log = new CapturingLogger();
        var signer = new PollKeyReadSigner(enclave, new FixedPairing(PollKey), log);

        for (var poll = 0; poll < 3; poll++)
        {
            Assert.Null(await signer.SignReadAsync(PhoneId, "/v0.4/pending", CancellationToken.None));
        }

        // One call a read, never a retry; said once, for information.
        Assert.Equal(3, enclave.SignCalls);
        var line = Assert.Single(log.Lines);
        Assert.Equal(LogLevel.Information, line.Level);
        Assert.Equal("Read /v0.4/pending goes unsigned: device_locked (no kind) after 1 signing attempt(s)", line.Text);
        Assert.DoesNotContain(RecentErrors.Snapshot(), e => e.Message.Contains("device_locked", StringComparison.Ordinal));
        // It is never mistaken for the gated key, whose answer is "pair again".
        Assert.DoesNotContain("poll_key_gated", line.Text);
    }

    [Fact]
    public async Task OnceTheDeviceIsUnlocked_ReadsAreSignedAgain_AndThatIsLogged()
    {
        var enclave = new ScriptedEnclave(Locked, Succeed);
        var log = new CapturingLogger();
        var signer = new PollKeyReadSigner(enclave, new FixedPairing(PollKey), log);

        Assert.Null(await signer.SignReadAsync(PhoneId, "/v0.4/pending", CancellationToken.None));
        Assert.NotNull(await signer.SignReadAsync(PhoneId, "/v0.4/pending", CancellationToken.None));

        Assert.Equal(2, log.Lines.Count);
        Assert.Equal("Read /v0.4/pending signed again after: device_locked", log.Lines[1].Text);
        Assert.DoesNotContain(log.Lines, l => l.Level >= LogLevel.Warning);
    }

    [Fact]
    public async Task APairingRecordThatCannotBeRead_IsReportedByItsErrorCode_NeverItsText()
    {
        var log = new CapturingLogger();
        var signer = new PollKeyReadSigner(
            new ScriptedEnclave(),
            new FixedPairing(Result.Failure<PairingState?>(Error.Database(ErrorText))),
            log);

        Assert.Null(await signer.SignReadAsync(PhoneId, "/v0.4/pending", CancellationToken.None));

        Assert.Contains("goes unsigned: pairing_unreadable DatabaseError", Assert.Single(log.Lines).Text);
    }

    [Fact]
    public async Task APairingReadThatThrows_DoesNotEscape_AndIsReportedByItsTypeName()
    {
        var log = new CapturingLogger();
        var signer = new PollKeyReadSigner(new ScriptedEnclave(), new FixedPairing(throws: true), log);

        Assert.Null(await signer.SignReadAsync(PhoneId, "/v0.4/pending", CancellationToken.None));

        Assert.Contains("goes unsigned: pairing_unreadable InvalidOperationException", Assert.Single(log.Lines).Text);
    }

    // --- said once per change, not once per poll ---

    [Fact]
    public async Task TheSameReason_IsLoggedOnce_AndTheRecoveryIsLogged_AndANewFailureIsLoggedAgain()
    {
        var enclave = new ScriptedEnclave(Fail, Fail, Fail, Fail, Fail, Fail, Succeed, Throw, Throw);
        var log = new CapturingLogger();
        var signer = new PollKeyReadSigner(enclave, new FixedPairing(PollKey), log);

        for (var poll = 0; poll < 3; poll++)
        {
            Assert.Null(await signer.SignReadAsync(PhoneId, "/v0.4/pending", CancellationToken.None));
        }
        Assert.Single(log.Lines);

        Assert.NotNull(await signer.SignReadAsync(PhoneId, "/v0.4/pending", CancellationToken.None));
        Assert.Equal(2, log.Lines.Count);
        Assert.Equal(LogLevel.Information, log.Lines[1].Level);
        Assert.Equal("Read /v0.4/pending signed again after: sign_failed (FailureError)", log.Lines[1].Text);

        Assert.Null(await signer.SignReadAsync(PhoneId, "/v0.4/pending", CancellationToken.None));
        Assert.Equal(3, log.Lines.Count);
        Assert.Contains("sign_threw InvalidOperationException", log.Lines[2].Text);
    }

    [Fact]
    public async Task TheReason_IsKeptForSettings_InTheSignersOwnWords()
    {
        var signer = new PollKeyReadSigner(new ScriptedEnclave(Fail, Fail), new FixedPairing(PollKey));

        await signer.SignReadAsync(PhoneId, "/v0.4/pending", CancellationToken.None);

        var kept = RecentErrors.Snapshot().Where(e => e.Phase == PollKeyReadSigner.RecentErrorsPhase).ToList();
        Assert.Contains(kept, e => e.Message == "This phone's reads are going unsigned: sign_failed (FailureError).");
        Assert.All(kept, e => Assert.All(Canaries, canary => Assert.DoesNotContain(canary, e.Message)));
    }

    // --- nothing but the fixed words reaches a log ---

    [Theory]
    [InlineData("/v0.4/respond/" + RequestId, "/v0.4/respond/{id}")]
    [InlineData("/v0.4/user-vault/grant-request/deny", "/v0.4/user-vault/grant-request/deny")]
    [InlineData("/v0.4/" + RequestId, "/v0.4/(unlisted)")]
    [InlineData("/" + RequestId, "/v0.4/(unlisted)")]
    public async Task TheRouteNamed_IsFromTheClientsFixedList(string path, string route)
    {
        var log = new CapturingLogger();
        var signer = new PollKeyReadSigner(new ScriptedEnclave(Fail, Fail), new FixedPairing(PollKey), log);

        await signer.SignReadAsync(PhoneId, path, CancellationToken.None);

        Assert.StartsWith($"Read {route} goes unsigned:", Assert.Single(log.Lines).Text);
    }

    [Fact]
    public async Task NoCanary_ReachesALogLineAStructuredValueOrALoggedException_OnAnyEnding()
    {
        var endings = new (ScriptedEnclave Enclave, FixedPairing Pairing)[]
        {
            (new ScriptedEnclave(Fail, Fail), new FixedPairing(PollKey)),
            (new ScriptedEnclave(Throw, Throw), new FixedPairing(PollKey)),
            (new ScriptedEnclave(Fail, Succeed), new FixedPairing(PollKey)),
            (new ScriptedEnclave(FailWithAnOddCode, FailWithAnOddCode), new FixedPairing(PollKey)),
            (new ScriptedEnclave(), new FixedPairing(pollKey: null)),
            (new ScriptedEnclave(), new FixedPairing(Result.Failure<PairingState?>(Error.Database(ErrorText)))),
            (new ScriptedEnclave(), new FixedPairing(throws: true)),
        };
        foreach (var (enclave, pairing) in endings)
        {
            var log = new CapturingLogger();
            var signer = new PollKeyReadSigner(enclave, pairing, log);

            await signer.SignReadAsync(PhoneId, "/v0.4/respond/" + RequestId, CancellationToken.None);
            // A second read, so the recovery line or the quiet repeat is covered too.
            await signer.SignReadAsync(PhoneId, "/v0.4/respond/" + RequestId, CancellationToken.None);

            Assert.NotEmpty(log.Lines);
            foreach (var line in log.Lines)
            {
                Assert.Null(line.Exception);
                foreach (var canary in Canaries)
                {
                    Assert.DoesNotContain(canary, line.Text);
                    Assert.All(line.Values, value => Assert.DoesNotContain(canary, value));
                }
            }
        }
    }

    [Fact]
    public async Task AnErrorCodeThatIsNotShapedLikeACode_IsNotShown()
    {
        var log = new CapturingLogger();
        var signer = new PollKeyReadSigner(
            new ScriptedEnclave(FailWithAnOddCode, FailWithAnOddCode), new FixedPairing(PollKey), log);

        await signer.SignReadAsync(PhoneId, "/v0.4/pending", CancellationToken.None);

        Assert.Equal(
            "Read /v0.4/pending goes unsigned: sign_failed unnamed after 2 signing attempt(s)",
            Assert.Single(log.Lines).Text);
    }

    // --- a read the caller gave up ---

    [Fact]
    public async Task ACancelledRead_AnswersNull_ThrowsNothing_AndReportsNothing()
    {
        using var cancelled = new CancellationTokenSource();
        cancelled.Cancel();
        var log = new CapturingLogger();
        var signer = new PollKeyReadSigner(new ScriptedEnclave(Cancel, Succeed), new FixedPairing(PollKey), log);

        Assert.Null(await signer.SignReadAsync(PhoneId, "/v0.4/pending", cancelled.Token));
        Assert.Empty(log.Lines);
    }

    // --- the registration hands the signer its logger ---

    [Fact]
    public void TheSigner_HasOneConstructor_WhoseLoggerIsOptional()
    {
        // One constructor, so the container never has to choose; an optional logger, so a test builds without one.
        var constructor = Assert.Single(typeof(PollKeyReadSigner).GetConstructors());
        var logger = constructor.GetParameters()[^1];
        Assert.Equal(typeof(ILogger<PollKeyReadSigner>), logger.ParameterType);
        Assert.True(logger.HasDefaultValue);
    }

    // --- helpers ---

    private static Task<Result<byte[]>> Succeed() => Task.FromResult(Result.Success(new byte[64]));

    private static Task<Result<byte[]>> Fail() => Task.FromResult(Result.Failure<byte[]>(Error.Failure(ErrorText)));

    private static Task<Result<byte[]>> FailWithAnOddCode()
        => Task.FromResult(Result.Failure<byte[]>(new Error("a code with " + ErrorText, ErrorText, string.Empty)));

    private static Task<Result<byte[]>> Throw() => throw new InvalidOperationException(ExceptionText);

    private static Task<Result<byte[]>> Gated() => Task.FromResult(Result.Failure<byte[]>(DeviceKeyRefusal.Gated()));

    private static Task<Result<byte[]>> Locked() => Task.FromResult(Result.Failure<byte[]>(DeviceKeyRefusal.Locked()));

    private static Task<Result<byte[]>> Cancel() => throw new OperationCanceledException();

    private sealed class ScriptedEnclave : IEnclaveKeyService
    {
        private readonly Queue<Func<Task<Result<byte[]>>>> _script;
        public int SignCalls;
        public List<string> Aliases { get; } = new();
        public List<string> Messages { get; } = new();

        public ScriptedEnclave(params Func<Task<Result<byte[]>>>[] script) => _script = new(script);

        public string Algorithm => V04Protocol.AlgorithmEcdsaP256;
        public Task<Result<EnclavePublicKey>> GenerateAsync(string keyAlias, CancellationToken ct) => throw new NotSupportedException();
        public Task<Result<bool>> KeyExistsAsync(string keyAlias, CancellationToken ct) => Task.FromResult(Result.Success(true));
        public Task<Result<EnclavePublicKey>> GetPublicKeyAsync(string keyAlias, CancellationToken ct) => throw new NotSupportedException();
        public Task<Result> DeleteAsync(string keyAlias, CancellationToken ct) => Task.FromResult(Result.Success());

        public int DeviceKeyCalls;
        public int PromptingCalls;

        // The entry that may prompt. The read signer must never call it.
        public Task<Result<byte[]>> SignAsync(string keyAlias, byte[] message, CancellationToken ct)
        {
            PromptingCalls++;
            throw new InvalidOperationException("the read signer called the entry that may prompt");
        }

        public Task<Result<byte[]>> SignWithDeviceKeyAsync(string keyAlias, byte[] message, CancellationToken ct)
        {
            SignCalls++;
            DeviceKeyCalls++;
            Aliases.Add(keyAlias);
            Messages.Add(System.Text.Encoding.ASCII.GetString(message));
            return _script.Dequeue()();
        }
    }

    private sealed class PlainEnclave : IEnclaveKeyService
    {
        public int SignCalls;
        public string Algorithm => V04Protocol.AlgorithmEcdsaP256;
        public Task<Result<EnclavePublicKey>> GenerateAsync(string keyAlias, CancellationToken ct) => throw new NotSupportedException();
        public Task<Result<bool>> KeyExistsAsync(string keyAlias, CancellationToken ct) => Task.FromResult(Result.Success(true));
        public Task<Result<EnclavePublicKey>> GetPublicKeyAsync(string keyAlias, CancellationToken ct) => throw new NotSupportedException();
        public Task<Result> DeleteAsync(string keyAlias, CancellationToken ct) => Task.FromResult(Result.Success());
        public Task<Result<byte[]>> SignAsync(string keyAlias, byte[] message, CancellationToken ct)
        {
            SignCalls++;
            return Task.FromResult(Result.Success(new byte[64]));
        }
    }

    private sealed class FixedPairing : IPairingStateService
    {
        private readonly Result<PairingState?>? _answer;

        public FixedPairing(string? pollKey)
            => _answer = Result.Success<PairingState?>(new PairingState(
                PhoneId, "b", "http://h", Array.Empty<ManagedSecretRef>(), DateTimeOffset.UnixEpoch,
                PollPublicKeyB64u: pollKey));

        public FixedPairing(Result<PairingState?> answer) => _answer = answer;

        public FixedPairing(bool throws) => _answer = throws ? null : Result.Success<PairingState?>(null);

        public Task<Result<PairingState?>> GetCurrentAsync(CancellationToken ct)
            => _answer is null ? throw new InvalidOperationException(ExceptionText) : Task.FromResult(_answer);
        public Task<Result> SaveAsync(PairingState state, CancellationToken ct) => Task.FromResult(Result.Success());
        public Task<Result> ClearAsync(CancellationToken ct) => Task.FromResult(Result.Success());
        public Task<Result<string>> GetOrCreatePhoneIdAsync(CancellationToken ct) => Task.FromResult(Result.Success(PhoneId));
    }

    private sealed record Line(LogLevel Level, string Text, IReadOnlyList<string> Values, Exception? Exception);

    private sealed class CapturingLogger : ILogger<PollKeyReadSigner>
    {
        public List<Line> Lines { get; } = new();

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(
            LogLevel logLevel, EventId eventId, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            var values = state is IEnumerable<KeyValuePair<string, object?>> pairs
                ? pairs.Select(pair => pair.Value?.ToString() ?? string.Empty).ToList()
                : new List<string>();
            Lines.Add(new Line(logLevel, formatter(state, exception), values, exception));
        }
    }
}
