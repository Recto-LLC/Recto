using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Android.Security.Keystore;
using AndroidX.Biometric;
using AndroidX.Core.Content;
using AndroidX.Fragment.App;
using Java.Security;
using Java.Security.Spec;
using Recto.Shared.Common;
using Recto.Shared.Models;
using Recto.Shared.Protocol.V04;
using Recto.Shared.Services;

namespace Recto.Platforms.AndroidImpl;

/// <summary>
/// Android StrongBox-backed key service. Generates an ECDSA P-256 keypair
/// inside the StrongBox HSM (Titan M / Pixel chip / Samsung Knox HSM,
/// depending on device). Every signing operation is gated by an explicit
/// <see cref="BiometricPrompt"/> with <see cref="BiometricPrompt.CryptoObject"/>
/// so the user authorizes each signature individually -- matches the
/// "operator approves every cryptographic operation" security model.
/// <para>
/// Why P-256 and not Ed25519: AndroidKeyStore's public
/// <c>KEY_ALGORITHM_*</c> constants list EC / RSA / AES / HMAC / XDH but
/// not Ed25519, even on Android 16 / API 35. The v0.4 protocol's
/// <c>supported_algorithms</c> field lets the phone advertise
/// <c>ecdsa-p256</c> -- same as iOS Secure Enclave.
/// </para>
/// <para>
/// Key authentication model: per-use (<c>setUserAuthenticationParameters(0,
/// BIOMETRIC_STRONG | DEVICE_CREDENTIAL)</c>) so every <c>Signature.sign()</c>
/// call requires a fresh <c>BiometricPrompt</c> authorization. The
/// <c>InitSign</c> call succeeds without prior auth (key is "armed"); the
/// actual signature operation requires the prompt to authorize the
/// <c>CryptoObject</c>.
/// </para>
/// </summary>
public sealed class AndroidStrongBoxKeyService : IEnclaveKeyService
{
    private const string AndroidKeyStoreProvider = "AndroidKeyStore";
    private const string SignatureAlgorithm = "SHA256withECDSA";
    private const string EcCurveName = "secp256r1";

    public string Algorithm => V04Protocol.AlgorithmEcdsaP256;

    public Task<Result<EnclavePublicKey>> GenerateAsync(string keyAlias, CancellationToken ct)
        => Generate(keyAlias, requireUserAuth: true);

    /// <summary>
    /// The poll key (hard rule 14.2): StrongBox/TEE-resident like the
    /// identity key, but with NO user-authentication requirement, so signing a
    /// read never raises a BiometricPrompt. Delegated once by the identity key
    /// at pairing; never signs an approval.
    /// </summary>
    public Task<Result<EnclavePublicKey>> GenerateDeviceKeyAsync(string keyAlias, CancellationToken ct)
        => Generate(keyAlias, requireUserAuth: false);

    private static Task<Result<EnclavePublicKey>> Generate(string keyAlias, bool requireUserAuth)
    {
        try
        {
            DeleteInternal(keyAlias);

            var generator = KeyPairGenerator.GetInstance(KeyProperties.KeyAlgorithmEc, AndroidKeyStoreProvider)
                ?? throw new InvalidOperationException("KeyPairGenerator.GetInstance returned null.");

            var spec = BuildSpec(keyAlias, strongBox: true, requireUserAuth);
            try
            {
                generator.Initialize(spec);
                using var pair = generator.GenerateKeyPair()
                    ?? throw new InvalidOperationException("GenerateKeyPair returned null.");
                return Task.FromResult(BuildPublicKeyResult(pair));
            }
            catch (StrongBoxUnavailableException)
            {
                spec = BuildSpec(keyAlias, strongBox: false, requireUserAuth);
                generator.Initialize(spec);
                using var pair = generator.GenerateKeyPair()
                    ?? throw new InvalidOperationException("GenerateKeyPair returned null.");
                return Task.FromResult(BuildPublicKeyResult(pair));
            }
        }
        catch (Exception ex)
        {
            return Task.FromResult(Result.Failure<EnclavePublicKey>(
                Error.Failure($"Android StrongBox keygen failed: {ex.GetType().Name}: {ex.Message}")));
        }
    }

    public Task<Result<bool>> KeyExistsAsync(string keyAlias, CancellationToken ct)
    {
        try
        {
            using var keyStore = KeyStore.GetInstance(AndroidKeyStoreProvider);
            keyStore!.Load(null);
            return Task.FromResult(Result.Success(keyStore.ContainsAlias(keyAlias)));
        }
        catch (Exception ex)
        {
            return Task.FromResult(Result.Failure<bool>(
                Error.Failure($"Android keystore check failed: {ex.Message}")));
        }
    }

    public Task<Result<EnclavePublicKey>> GetPublicKeyAsync(string keyAlias, CancellationToken ct)
    {
        try
        {
            using var keyStore = KeyStore.GetInstance(AndroidKeyStoreProvider);
            keyStore!.Load(null);

            using var entry = keyStore.GetEntry(keyAlias, null);
            if (entry is not KeyStore.PrivateKeyEntry pkEntry || pkEntry.Certificate is null)
            {
                return Task.FromResult(Result.Failure<EnclavePublicKey>(
                    Error.NotFound($"No Android keystore entry for alias '{keyAlias}'.")));
            }

            var publicKey = pkEntry.Certificate.PublicKey
                ?? throw new InvalidOperationException("Certificate has no public key.");
            var encoded = publicKey.GetEncoded()
                ?? throw new InvalidOperationException("PublicKey.GetEncoded returned null.");

            return Task.FromResult(Result.Success(new EnclavePublicKey(
                ExtractRawP256PublicKey(encoded), Algorithm)));
        }
        catch (Exception ex)
        {
            return Task.FromResult(Result.Failure<EnclavePublicKey>(
                Error.Failure($"Android keystore public-key read failed: {ex.Message}")));
        }
    }

    public Task<Result<byte[]>> SignAsync(string keyAlias, byte[] message, CancellationToken ct)
        => Sign(keyAlias, message, mayPrompt: true, ct);

    /// <summary>
    /// Signs with a device key and never prompts: a key the keystore reports
    /// as needing user authentication is refused by name before any prompt
    /// is made. This is the read signer's entry, called on a timer.
    /// </summary>
    public Task<Result<byte[]>> SignWithDeviceKeyAsync(string keyAlias, byte[] message, CancellationToken ct)
        => Sign(keyAlias, message, mayPrompt: false, ct);

    private static Task<Result<byte[]>> Sign(string keyAlias, byte[] message, bool mayPrompt, CancellationToken ct)
    {
        // Released in the finally below, after the answer is settled.
        KeyStore? keyStore = null;
        KeyStore.IEntry? entry = null;
        try
        {
            keyStore = KeyStore.GetInstance(AndroidKeyStoreProvider);
            keyStore!.Load(null);

            entry = keyStore.GetEntry(keyAlias, null);
            if (entry is not KeyStore.PrivateKeyEntry pkEntry)
            {
                return Task.FromResult(Result.Failure<byte[]>(
                    Error.NotFound($"No Android keystore entry for alias '{keyAlias}'.")));
            }

            // The key's handle is released when this method returns: the
            // Signature holds its own reference from InitSign on.
            var privateKey = pkEntry.PrivateKey;

            // InitSign succeeds without prior user auth on per-use keys (timeout=0).
            // The Signature is "armed" but cannot complete .sign() until the
            // BiometricPrompt authorizes the CryptoObject wrapping it.
            var signer = Signature.GetInstance(SignatureAlgorithm)
                ?? throw new InvalidOperationException("Signature.GetInstance returned null.");
            var signerHandedOn = false;
            try
            {
                signer.InitSign(privateKey);

                // The poll key (GenerateDeviceKeyAsync) carries no user-auth
                // requirement: the KEYSTORE says so, not the caller, so no alias
                // convention can route an approval past the prompt. It signs
                // directly; every other key goes through BiometricPrompt.
                var gate = ReadKeyGate(privateKey!);
                if (gate == KeyGate.Open)
                {
                    signer.Update(message);
                    var derSig = signer.Sign()
                        ?? throw new InvalidOperationException("Signature.Sign returned null.");
                    return Task.FromResult(Result.Success(EcdsaSignatureFormat.DerToRaw(derSig)));
                }

                // Asked to sign as a device key, and the key did not read as
                // open: no prompt is made and nothing is signed. A key the
                // keystore SAYS is gated is refused by that name. A key the
                // keystore could not describe just now is an ordinary
                // failure, which the caller may try again: a passing
                // keystore error must not be reported as a gated key.
                if (!mayPrompt)
                {
                    return Task.FromResult(Result.Failure<byte[]>(gate == KeyGate.Gated
                        ? DeviceKeyRefusal.Gated()
                        : Error.Failure(KeyGateUnreadableMessage)));
                }

                // From here the key is treated as gated, an unreadable one
                // included: it can only ever be over-prompted.

                // One prompt at a time, in the whole process. The prompt
                // library keeps one callback per activity and returns
                // without showing when a prompt is already up, so a second
                // signing started now would take the first one's callback:
                // the first caller would never be answered and the second
                // would be handed the first one's touch. The second is
                // refused here, by name; nothing is signed.
                // A pass whose activity is gone is taken back first
                // (SingleFlight.TryEnter asks the holder): its prompt's
                // ending will never be delivered.
                var flight = PromptFlight.TryEnter();
                if (flight is null)
                {
                    return Task.FromResult(Result.Failure<byte[]>(Error.Conflict(PromptBusyMessage)));
                }

                // The prompt signs later, on its callback. From here the
                // prompt flow owns the Signature and the flight, releases
                // both on each of its endings, a prompt that could not be
                // shown included, and answers on each of them.
                signerHandedOn = true;
                return AuthenticateAndSignAsync(signer, flight, message, keyAlias, ct);
            }
            finally
            {
                // A direct signature is complete here, so its Signature is
                // released now: this path runs on every signed read. A
                // release that fails changes nothing this method answers.
                if (!signerHandedOn)
                {
                    Release(signer);
                }
                Release(privateKey);
            }
        }
        catch (Exception ex)
        {
            return Task.FromResult(Result.Failure<byte[]>(
                Error.Failure($"Android sign exception: {ex.GetType().Name}: {ex.Message}")));
        }
        finally
        {
            Release(entry);
            Release(keyStore);
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
                Error.Failure($"Android keystore delete failed: {ex.Message}")));
        }
    }

    // --- BiometricPrompt + CryptoObject sign flow ---

    /// <summary>
    /// Held from the moment a gated signing is admitted until its prompt has
    /// ended. One for the process: there is one screen.
    /// </summary>
    private static readonly SingleFlight PromptFlight = new();

    /// <summary>What a signing answers when the prompt could not be put on screen.</summary>
    private const string PromptNotShownMessage =
        "The biometric prompt could not be shown because Recto is not on screen. Open Recto and try again.";

    /// <summary>What a signing answers when its activity went away under the prompt.</summary>
    private const string PromptLostMessage =
        "The biometric prompt was closed before it was answered. Nothing was signed. Try again.";

    /// <summary>What a device-key signing answers when the keystore could not describe the key.</summary>
    private const string KeyGateUnreadableMessage =
        "Android keystore could not report whether the key needs user authentication.";

    /// <summary>What a signing answers while another signing's prompt is up.</summary>
    private const string PromptBusyMessage =
        "Another approval is waiting for your biometric. Finish or cancel it, then try again.";

    /// <summary>
    /// The prompt library ignores a cancel for a moment after a prompt shows.
    /// A cancelled signing asks its prompt to close at once and once more
    /// after this long.
    /// </summary>
    private static readonly TimeSpan DismissRetryDelay = TimeSpan.FromMilliseconds(750);

    /// <summary>A success whose Signature is not the one this prompt was given. Names no key and no alias.</summary>
    private const string ForeignTouchMessage = "This approval's touch belonged to another prompt. Nothing was signed.";

    /// <summary>
    /// Wraps the armed <see cref="Signature"/> in a
    /// <see cref="BiometricPrompt.CryptoObject"/> and shows the system
    /// biometric prompt. On success the prompt's success callback runs
    /// <c>signer.update(message)</c> + <c>signer.sign()</c>, converts the
    /// DER-encoded signature to raw R || S, and resolves the
    /// <see cref="TaskCompletionSource{TResult}"/>. On user cancel / error
    /// the TCS resolves with a <see cref="Result.Failure"/>.
    /// <para>
    /// Every path out of here answers. The prompt library returns from
    /// <c>authenticate</c> without showing anything, and without calling
    /// back, when the activity has saved its state (the app left the
    /// screen); that case is refused here by name before the prompt is
    /// asked, so the caller is never left waiting on a callback that does
    /// not come.
    /// </para>
    /// <para>
    /// The flight is released when the prompt is down: at once when no
    /// prompt was shown, otherwise on the prompt's own ending. A cancelled
    /// signing is answered at once and its prompt is asked to close; the
    /// flight stays held until that prompt has ended, because a signing let
    /// in under a prompt that is still up is the fault the flight prevents.
    /// </para>
    /// <para>
    /// AN ENDING THAT NEVER COMES. The prompt library delivers an ending
    /// through its fragment, and only while that fragment is started; when
    /// the activity is destroyed under a prompt (reclaimed by the system,
    /// finished, "Don't keep activities") the ending is dropped and the
    /// process lives on. So the pass is tied to the activity, twice over:
    /// the activity's own destruction answers the caller and releases
    /// everything, and a later signing takes back a pass whose activity is
    /// destroyed, finishing or no longer the current one. "The activity" is
    /// the one the prompt belongs to now: a configuration change rebuilds
    /// the activity under a prompt that lives on, so the watch follows it
    /// to the new one and such a destroy never counts as gone.
    /// </para>
    /// <para>
    /// AND A LIFE. The app's activity does not restore the prompt's fragment
    /// across that rebuild, so even a prompt that is followed may never
    /// deliver its ending. Every prompt is given <see cref="PromptLife.Limit"/>
    /// from the moment it is asked; past it the caller is answered that the
    /// approval was not answered in time, everything is released and the
    /// prompt is asked to close. The phone is never held shut for longer.
    /// </para>
    /// </summary>
    private static async Task<Result<byte[]>> AuthenticateAndSignAsync(
        Signature signer, SingleFlight.Pass flight, byte[] message, string keyAlias, CancellationToken ct)
    {
        var tcs = new TaskCompletionSource<Result<byte[]>>(TaskCreationOptions.RunContinuationsAsynchronously);
        BiometricAuthCallback? callback = null;
        FragmentActivity activity;

        try
        {
            activity = Microsoft.Maui.ApplicationModel.Platform.CurrentActivity as FragmentActivity
                ?? throw new InvalidOperationException(
                    "Current activity is not a FragmentActivity; BiometricPrompt requires it.");

            if (!CanShowPrompt(activity))
            {
                // No prompt will show, so nothing else holds the Signature.
                Release(signer);
                Release(flight);
                return Result.Failure<byte[]>(Error.Failure(PromptNotShownMessage));
            }

            var executor = ContextCompat.GetMainExecutor(activity)
                ?? throw new InvalidOperationException("ContextCompat.GetMainExecutor returned null.");

            // Held first, so it is released last: the flight is free only
            // after everything made for the prompt has been let go.
            callback = new BiometricAuthCallback(tcs, message, signer);
            callback.Hold(flight);
            // The prompt's screen, followed across a rebuild: the activity
            // captured here is only where it starts.
            var host = new PromptHost<global::Android.App.Activity>(activity);
            var answering = callback;
            callback.Hold(ActivityWatch.Start(host, answering));
            var prompt = new BiometricPrompt(activity, executor, callback);
            callback.Show(prompt);

            var cryptoObject = new BiometricPrompt.CryptoObject(signer);
            callback.Hold(cryptoObject);

            // Not chained, so the builder is in hand to release.
            var builder = new BiometricPrompt.PromptInfo.Builder();
            callback.Hold(builder);
            builder.SetTitle("Recto");
            builder.SetSubtitle($"Authorize signing for {keyAlias}");
            builder.SetDescription(
                $"Your fingerprint approves this cryptographic operation. Approve within {PromptLife.Limit.TotalMinutes:0} minutes.");
            builder.SetNegativeButtonText("Cancel");
            var promptInfo = builder.Build();
            callback.Hold(promptInfo);

            // From here the pass can be taken back, and not before: until
            // the prompt is asked there is nothing whose ending could be
            // lost, and every way out above releases the pass itself.
            // The prompt's whole life is capped from here: past it the
            // caller is answered, everything is released and the prompt is
            // asked to close, whether or not its ending ever comes. The lapse
            // alone ends a prompt that ran out of time; the pass's watch
            // takes it back on time only as a late backstop, for a lapse that
            // never ran, and then answers in the lapse's own words.
            var lapseOn = activity;
            var life = new PromptLife(() => answering.Lapse(lapseOn));
            callback.Hold(life);
            flight.Watch(
                () => life.IsOverBy(PromptLife.Grace) || IsGone(host),
                () => answering.Abandon(life.WordsForAnEnding(PromptLostMessage)));
            prompt.Authenticate(promptInfo, cryptoObject);
        }
        catch (Exception ex)
        {
            // No prompt is showing, so nothing else holds the Signature, the
            // flight or the objects made for the prompt. The caller is
            // answered here: this method is awaited, so an exception left to
            // escape would reach it as a faulted task and not as a result.
            if (callback is null)
            {
                Release(signer);
                Release(flight);
            }
            else
            {
                callback.ReleaseAll();
            }
            return Result.Failure<byte[]>(
                Error.Failure($"Android sign exception: {ex.GetType().Name}: {ex.Message}"));
        }

        // Cancellation answers the caller at once and asks the prompt to
        // close. The Signature and the flight stay with the prompt until it
        // has ended: its callback releases them then.
        var shown = callback;
        var on = activity;
        using var registration = ct.Register(() =>
        {
            if (shown.Cancel())
            {
                RequestDismissal(on, shown);
            }
        });

        return await tcs.Task.ConfigureAwait(false);
    }

    /// <summary>
    /// Asks a cancelled signing's prompt to close, on the main thread, now
    /// and once more after <see cref="DismissRetryDelay"/>. Best-effort: when
    /// it cannot be asked the prompt stays up until the user ends it, and
    /// that ending releases what the prompt holds.
    /// </summary>
    private static void RequestDismissal(FragmentActivity activity, BiometricAuthCallback callback)
    {
        try
        {
            activity.RunOnUiThread(callback.Dismiss);
            _ = Task.Delay(DismissRetryDelay).ContinueWith(
                _ =>
                {
                    try
                    {
                        activity.RunOnUiThread(callback.Dismiss);
                    }
                    catch
                    {
                        // The prompt's own ending still comes.
                    }
                },
                TaskScheduler.Default);
        }
        catch
        {
            // The prompt's own ending still comes.
        }
    }

    /// <summary>
    /// True when the prompt's activity can no longer deliver the prompt's
    /// ending. The rule is <see cref="PromptHost{TScreen}.IsGone"/>, asked of
    /// the activity the host is watching NOW - never of the one the prompt
    /// was first shown on, which a configuration change destroys while the
    /// prompt lives on. The activity's own "changing configurations" is read
    /// first: Android sets it, and marks the activity destroyed, before the
    /// lifecycle watch hears of the destroy, and in that window the prompt is
    /// alive. An activity that cannot be read is gone: a flight
    /// held for ever would refuse every approval until the process died.
    /// </summary>
    private static bool IsGone(PromptHost<global::Android.App.Activity> host)
    {
        try
        {
            return host.IsGone(
                watched => watched.IsChangingConfigurations,
                watched => watched.IsDestroyed,
                watched => watched.IsFinishing,
                () => Microsoft.Maui.ApplicationModel.Platform.CurrentActivity);
        }
        catch
        {
            return true;
        }
    }

    /// <summary>
    /// Feeds the application's activity events to the prompt's host. An
    /// activity destroyed for a configuration change (language, font scale,
    /// layout direction, a keyboard) is rebuilt under the prompt, which
    /// survives it: the host notes the destroy and takes the next activity
    /// created as the prompt's own. An activity destroyed for good takes the
    /// prompt's ending with it: the signing is answered with a failure and
    /// everything it holds is released, the single-flight pass included.
    /// </summary>
    private sealed class ActivityWatch : Java.Lang.Object, global::Android.App.Application.IActivityLifecycleCallbacks
    {
        private readonly PromptHost<global::Android.App.Activity> _host;
        private readonly BiometricAuthCallback _callback;

        private ActivityWatch(PromptHost<global::Android.App.Activity> host, BiometricAuthCallback callback)
        {
            _host = host;
            _callback = callback;
        }

        /// <summary>
        /// Starts watching and answers the handle that stops it. Null when
        /// the activity has no application to register with; the pass's own
        /// watch still takes it back.
        /// </summary>
        public static IDisposable? Start(PromptHost<global::Android.App.Activity> host, BiometricAuthCallback callback)
        {
            var application = host.Watched.Application;
            if (application is null)
            {
                return null;
            }
            var watch = new ActivityWatch(host, callback);
            application.RegisterActivityLifecycleCallbacks(watch);
            return new Stop(application, watch);
        }

        public void OnActivityDestroyed(global::Android.App.Activity activity)
        {
            if (_host.Destroyed(activity, activity.IsChangingConfigurations))
            {
                _callback.Abandon(PromptLostMessage);
            }
        }

        public void OnActivityCreated(global::Android.App.Activity activity, global::Android.OS.Bundle? savedInstanceState)
            => _host.Created(activity);

        public void OnActivityPaused(global::Android.App.Activity activity) { }

        public void OnActivityResumed(global::Android.App.Activity activity) { }

        public void OnActivitySaveInstanceState(global::Android.App.Activity activity, global::Android.OS.Bundle outState) { }

        public void OnActivityStarted(global::Android.App.Activity activity) { }

        public void OnActivityStopped(global::Android.App.Activity activity) { }

        /// <summary>
        /// Stops the watch. The watch object itself is left to the
        /// collector: the application may be in the middle of calling it.
        /// </summary>
        private sealed class Stop : IDisposable
        {
            private readonly global::Android.App.Application _application;
            private readonly ActivityWatch _watch;

            public Stop(global::Android.App.Application application, ActivityWatch watch)
            {
                _application = application;
                _watch = watch;
            }

            public void Dispose() => _application.UnregisterActivityLifecycleCallbacks(_watch);
        }
    }

    /// <summary>
    /// False in the cases where the prompt library would return without
    /// showing a prompt and without calling back: an activity that is
    /// finishing or destroyed, or one whose fragment manager has saved its
    /// state. Fails CLOSED: a state that cannot be read is "cannot show".
    /// </summary>
    private static bool CanShowPrompt(FragmentActivity activity)
    {
        try
        {
            if (activity.IsFinishing || activity.IsDestroyed)
            {
                return false;
            }
            var fragments = activity.SupportFragmentManager;
            return fragments is not null && !fragments.IsStateSaved;
        }
        catch
        {
            return false;
        }
    }

    private sealed class BiometricAuthCallback : BiometricPrompt.AuthenticationCallback
    {
        private readonly TaskCompletionSource<Result<byte[]>> _tcs;
        private readonly byte[] _message;
        private Signature? _signer;
        private BiometricPrompt? _prompt;
        private List<IDisposable>? _held = new();
        private SingleFlight.Pass? _pass;

        // ONE outcome. Every ending claims it first - success, error,
        // abandon, lapse, cancel - and exactly one wins: a success that loses
        // never touches the Signature, an abandon or a lapse that loses does
        // nothing. A cancel answers the caller at once but leaves the release
        // to the prompt's own ending (or an abandon or a lapse), which then
        // takes the claim from it and releases without answering again.
        private const int Live = 0;
        private const int Cancelled = 1;
        private const int Ending = 2;
        private int _state = Live;

        public BiometricAuthCallback(TaskCompletionSource<Result<byte[]>> tcs, byte[] message, Signature signer)
        {
            _tcs = tcs;
            _message = message;
            _signer = signer;
        }

        /// <summary>The prompt this callback answers: held like the rest, and kept to close on a cancel.</summary>
        public void Show(BiometricPrompt prompt)
        {
            _prompt = prompt;
            Hold(prompt);
        }

        /// <summary>
        /// Asks the prompt to close. Called on the main thread when the
        /// signing was cancelled. Does nothing once this prompt has ended, so
        /// a late call can never close a later signing's prompt.
        /// </summary>
        public void Dismiss()
        {
            if (Volatile.Read(ref _held) is null)
            {
                return;
            }
            try
            {
                _prompt?.CancelAuthentication();
            }
            catch
            {
                // The prompt stays up; its own ending still comes.
            }
        }

        /// <summary>
        /// Ends a signing whose prompt can no longer answer: the activity it
        /// was shown on is gone, or its life ran out and the lapse never ran.
        /// The caller is answered with a failure in <paramref name="words"/>
        /// and nothing is signed. Does nothing when another ending has the outcome.
        /// </summary>
        public void Abandon(string words)
        {
            End(Result.Failure<byte[]>(Error.Failure(words)));
        }

        /// <summary>
        /// The caller gave the signing up. Answers it at once, when no other
        /// ending has claimed the outcome, and says whether the prompt should
        /// be asked to close. What the prompt holds is released by its own
        /// ending, which comes once it closes.
        /// </summary>
        public bool Cancel()
        {
            if (Interlocked.CompareExchange(ref _state, Cancelled, Live) != Live)
            {
                return false;
            }
            _tcs.TrySetResult(Result.Failure<byte[]>(Error.Failure("Operation cancelled.")));
            return true;
        }

        /// <summary>
        /// Claims the outcome for an ending, and answers what it took over:
        /// <see cref="Live"/>, or <see cref="Cancelled"/> when a cancel had
        /// answered the caller (this ending then only releases, and signs
        /// nothing). Null when another ending has the outcome.
        /// </summary>
        private int? Claim()
        {
            var was = Interlocked.CompareExchange(ref _state, Ending, Live);
            if (was == Live)
            {
                return Live;
            }
            if (was == Cancelled && Interlocked.CompareExchange(ref _state, Ending, Cancelled) == Cancelled)
            {
                return Cancelled;
            }
            return null;
        }

        /// <summary>
        /// Ends a signing whose prompt has stood past <see cref="PromptLife.Limit"/>.
        /// On the main thread the prompt is first asked to close and then the
        /// signing is ended, so the prompt is told before what it uses is
        /// released. When the main thread cannot be asked the signing is
        /// ended here. The outcome is claimed first, on the main thread: a lapse
        /// that loses it (the prompt answered, or was abandoned) does nothing.
        /// Nothing is signed.
        /// </summary>
        public void Lapse(global::Android.App.Activity on)
        {
            if (Volatile.Read(ref _state) == Ending)
            {
                return;
            }
            var lapsed = Result.Failure<byte[]>(Error.Failure(PromptLife.LapsedMessage));
            try
            {
                on.RunOnUiThread(() =>
                {
                    if (Claim() is null)
                    {
                        return;
                    }
                    Dismiss();
                    Linger();
                    Finish(lapsed);
                });
            }
            catch
            {
                if (Claim() is null)
                {
                    return;
                }
                Linger();
                Finish(lapsed);
            }
        }

        /// <summary>
        /// The single-flight pass, once released by a lapse, holds the flight
        /// <see cref="DismissRetryDelay"/> longer: the prompt just asked to
        /// close may still deliver its own late ending, and it must land on no
        /// one, never on the next signing's prompt.
        /// </summary>
        private void Linger() => _pass?.Linger(DismissRetryDelay);

        /// <summary>
        /// Every ending goes through here, in this order: release
        /// everything, the single-flight pass included, THEN answer. A
        /// caller that resumes on another thread and signs again at once
        /// must find the flight free.
        /// </summary>
        private void End(Result<byte[]> answer)
        {
            if (Claim() is null)
            {
                return;
            }
            Finish(answer);
        }

        /// <summary>
        /// The ending that claimed the outcome: release everything, the
        /// single-flight pass included, THEN answer (a no-op after a cancel,
        /// which answered already).
        /// </summary>
        private void Finish(Result<byte[]> answer)
        {
            ReleaseAll();
            _tcs.TrySetResult(answer);
        }

        /// <summary>
        /// Takes an object made for this one prompt - the single-flight
        /// pass, the activity watch, the prompt, its crypto object, its life, its info
        /// and the info's builder - to release when the prompt ends. Two objects are left to the collector on purpose:
        /// this callback, which the prompt's own state still references
        /// after it ends, and the main-thread executor, which is the
        /// process's one executor and not this prompt's.
        /// </summary>
        public void Hold(IDisposable? made)
        {
            if (made is null)
            {
                return;
            }
            var held = Volatile.Read(ref _held);
            if (held is null)
            {
                // Already ended: nothing will come back for it, so it is
                // released now and never dropped.
                Release(made);
                return;
            }
            held.Add(made);
            if (made is SingleFlight.Pass pass)
            {
                // Kept by name too, for the lapse's linger.
                _pass = pass;
            }
        }

        /// <summary>
        /// Releases the Signature the prompt was given and the objects made
        /// for the prompt. Called by whichever ending claimed the outcome -
        /// the prompt's own success or error, an abandon, a lapse - and by
        /// the prompt's ending (or an abandon or a lapse) after a cancel,
        /// which answers the caller but releases nothing itself; and when the
        /// prompt could not be started. Safe to call twice.
        /// </summary>
        public void ReleaseAll()
        {
            // Released is ended: no later ending claims the outcome, so a
            // stray success after a prompt that failed to start signs nothing.
            Volatile.Write(ref _state, Ending);
            Release(Interlocked.Exchange(ref _signer, null));
            var held = Interlocked.Exchange(ref _held, null);
            if (held is null)
            {
                return;
            }
            _prompt = null;
            // Newest first: the info before its builder, the crypto object
            // before the prompt, then the activity watch, and the
            // single-flight pass last of all.
            for (var i = held.Count - 1; i >= 0; i--)
            {
                Release(held[i]);
            }
        }

        public override void OnAuthenticationSucceeded(BiometricPrompt.AuthenticationResult result)
        {
            // Claimed first. Another ending won - the caller was told nothing
            // was signed (its activity went away, the prompt ran out of time
            // or failed to start): the Signature is not touched. A cancel had
            // answered the caller: this ending releases and signs nothing.
            var claimed = Claim();
            if (claimed is null)
            {
                return;
            }
            if (claimed == Cancelled)
            {
                Finish(Result.Failure<byte[]>(Error.Failure("Operation cancelled.")));
                return;
            }

            // The answer is computed while the Signature is still held, and
            // given only after everything is released.
            Result<byte[]> answer;
            try
            {
                var sig = result.CryptoObject?.Signature;
                var mine = Volatile.Read(ref _signer);
                if (sig is null)
                {
                    answer = Result.Failure<byte[]>(
                        Error.Failure("BiometricPrompt CryptoObject signature was null."));
                }
                else if (mine is null || !global::Android.Runtime.JNIEnv.IsSameObject(sig.Handle, mine.Handle))
                {
                    // The touch carries another prompt's Signature (an older
                    // prompt's late ending): never sign this message with it.
                    answer = Result.Failure<byte[]>(Error.Failure(ForeignTouchMessage));
                }
                else
                {
                    sig.Update(_message);
                    var derSig = sig.Sign()
                        ?? throw new InvalidOperationException("Signature.Sign returned null.");
                    answer = Result.Success(EcdsaSignatureFormat.DerToRaw(derSig));
                }
            }
            catch (Exception ex)
            {
                answer = Result.Failure<byte[]>(
                    Error.Failure($"Android sign post-auth exception: {ex.GetType().Name}: {ex.Message}"));
            }
            Finish(answer);
        }

        public override void OnAuthenticationError(int errorCode, Java.Lang.ICharSequence errString)
        {
            Result<byte[]> answer;
            try
            {
                answer = Result.Failure<byte[]>(
                    Error.Failure($"BiometricPrompt error {errorCode}: {errString}"));
            }
            catch (Exception ex)
            {
                answer = Result.Failure<byte[]>(
                    Error.Failure($"BiometricPrompt error {errorCode} ({ex.GetType().Name})"));
            }
            End(answer);
        }

        // OnAuthenticationFailed (single attempt didn't match) is intentionally
        // not overridden -- the system retries automatically and ultimately
        // surfaces failure via OnAuthenticationError(ERROR_LOCKOUT or similar).
    }

    // --- internals ---

    /// <summary>What the keystore says of a key's user-authentication requirement.</summary>
    private enum KeyGate
    {
        /// <summary>The keystore says the key needs no user authentication.</summary>
        Open,

        /// <summary>The keystore says the key needs user authentication.</summary>
        Gated,

        /// <summary>The keystore could not be asked, or gave no answer.</summary>
        Unreadable,
    }

    /// <summary>
    /// Asks the keystore whether <paramref name="privateKey"/> was generated with
    /// <c>setUserAuthenticationRequired(true)</c>. Three answers, because
    /// "could not be read" is neither of the other two: a signing that may
    /// prompt treats it as gated (an unreadable key can only ever be
    /// over-prompted, never under-prompted), and a device-key signing
    /// treats it as a failure to try again, never as a gated key. Only
    /// <see cref="KeyGate.Open"/> signs without a prompt.
    /// </summary>
    private static KeyGate ReadKeyGate(IPrivateKey privateKey)
    {
        // Both are read once and released: this check runs on every signed
        // read. The answer is settled before either release, and a release
        // that fails does not change it.
        KeyFactory? factory = null;
        IDisposable? spec = null;
        try
        {
            factory = KeyFactory.GetInstance(privateKey.Algorithm, AndroidKeyStoreProvider);
            spec = factory?.GetKeySpec(privateKey, Java.Lang.Class.FromType(typeof(KeyInfo)));
            if (spec is not KeyInfo info)
            {
                return KeyGate.Unreadable;
            }
            return info.IsUserAuthenticationRequired ? KeyGate.Gated : KeyGate.Open;
        }
        catch
        {
            return KeyGate.Unreadable;
        }
        finally
        {
            Release(spec);
            Release(factory);
        }
    }

    /// <summary>
    /// Releases a platform object's handle, best-effort: a release that
    /// throws is dropped, so it can never replace a result or an exception
    /// already in hand.
    /// </summary>
    private static void Release(IDisposable? handle)
    {
        try
        {
            handle?.Dispose();
        }
        catch
        {
            // The collector releases it later.
        }
    }

    private static KeyGenParameterSpec BuildSpec(string keyAlias, bool strongBox, bool requireUserAuth)
    {
        // Not chained: the binding types each Builder method as returning a
        // nullable Builder, so a fluent chain is a chain of possible-null
        // dereferences to the analyzer (CS8602). Same calls, one receiver.
        var builder = new KeyGenParameterSpec.Builder(keyAlias, KeyStorePurpose.Sign);
        builder.SetAlgorithmParameterSpec(new ECGenParameterSpec(EcCurveName));
        builder.SetDigests(KeyProperties.DigestSha256!);
        builder.SetUserAuthenticationRequired(requireUserAuth);

        if (requireUserAuth)
        {
            // Per-use authentication: every cryptographic operation requires a
            // fresh BiometricPrompt.authenticate(CryptoObject) call. This matches
            // the protocol's "operator approves every operation" model. The poll
            // key (requireUserAuth: false) is the one deliberate exception -- it
            // signs READS, never approvals. minSdk is 24; the per-use spelling
            // changed at API 30, so both are here, version-guarded (CA1416).
            if (OperatingSystem.IsAndroidVersionAtLeast(30))
            {
                builder.SetUserAuthenticationParameters(
                    timeout: 0,
                    type: (int)(KeyPropertiesAuthType.BiometricStrong | KeyPropertiesAuthType.DeviceCredential));
            }
            else
            {
                // API 24-29: -1 is "authenticate for every use" -- the same
                // per-use model, in the only spelling those releases have.
#pragma warning disable CA1422 // obsoleted at 30; this branch never runs there
                builder.SetUserAuthenticationValidityDurationSeconds(-1);
#pragma warning restore CA1422
            }
        }

        // StrongBox exists from API 28. Below it the request is simply not
        // made: the key lands in the TEE, which is what the caller's
        // StrongBoxUnavailableException fallback produces anyway.
        if (strongBox && OperatingSystem.IsAndroidVersionAtLeast(28))
        {
            builder.SetIsStrongBoxBacked(true);
        }

        return builder.Build();
    }

    private static Result<EnclavePublicKey> BuildPublicKeyResult(KeyPair pair)
    {
        var publicKey = pair.Public
            ?? throw new InvalidOperationException("KeyPair.Public was null.");
        var encoded = publicKey.GetEncoded()
            ?? throw new InvalidOperationException("PublicKey.GetEncoded returned null.");

        return Result.Success(new EnclavePublicKey(
            ExtractRawP256PublicKey(encoded), V04Protocol.AlgorithmEcdsaP256));
    }

    private static byte[] ExtractRawP256PublicKey(byte[] encoded)
    {
        if (encoded.Length != 91)
        {
            throw new InvalidOperationException(
                $"Unexpected EC P-256 SubjectPublicKeyInfo length: {encoded.Length}");
        }
        if (encoded[26] != 0x04)
        {
            throw new InvalidOperationException(
                "EC P-256 SubjectPublicKeyInfo missing 0x04 uncompressed-point prefix.");
        }
        var raw = new byte[64];
        Buffer.BlockCopy(encoded, 27, raw, 0, 64);
        return raw;
    }

    private static void DeleteInternal(string keyAlias)
    {
        try
        {
            using var keyStore = KeyStore.GetInstance(AndroidKeyStoreProvider);
            keyStore!.Load(null);
            if (keyStore.ContainsAlias(keyAlias))
            {
                keyStore.DeleteEntry(keyAlias);
            }
        }
        catch
        {
            // Swallow -- DeleteAsync is "no-op if absent" and we don't
            // want a stale-keystore error masking a fresh GenerateAsync.
        }
    }
}
