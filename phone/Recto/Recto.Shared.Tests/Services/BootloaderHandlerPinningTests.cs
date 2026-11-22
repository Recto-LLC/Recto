using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Recto.Shared.Extensions;
using Recto.Shared.Services;
using Xunit;

namespace Recto.Shared.Tests.Services;

/// <summary>
/// The bootloader client's handler chain, as <c>AddSharedServices</c> builds
/// it: the primary handler and its certificate callback are the registered
/// ones, the request-count collection handler sits in front of it and changes
/// no request, response or certificate decision.
/// <para>
/// These run on the test host, where the primary handler is the desktop one.
/// The handler Android substitutes for it is not loadable here; what is
/// pinned for Android is the registration's source text.
/// </para>
/// </summary>
public class BootloaderHandlerPinningTests
{
    private const string Host = "127.0.0.1";
    private const string WrongPin = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    // --- the request-count collection handler ---

    [Fact]
    public async Task CollectionHandler_CollectsAfterEveryNthRequest()
    {
        var collections = 0;
        using var invoker = InvokerFor(new RequestCountCollectionHandler(3, () => collections++, Inline), new StubHandler());

        for (var i = 1; i <= 7; i++)
        {
            using var response = await invoker.SendAsync(new HttpRequestMessage(HttpMethod.Get, "https://bootloader.example/"), default);
            Assert.Equal(i / 3, collections);
        }
    }

    [Fact]
    public async Task CollectionHandler_CountsAFailedRequest()
    {
        var collections = 0;
        using var invoker = InvokerFor(
            new RequestCountCollectionHandler(2, () => collections++, Inline),
            new StubHandler { Fail = true });

        for (var i = 0; i < 4; i++)
        {
            await Assert.ThrowsAsync<HttpRequestException>(() =>
                invoker.SendAsync(new HttpRequestMessage(HttpMethod.Get, "https://bootloader.example/"), default));
        }

        Assert.Equal(2, collections);
    }

    [Fact]
    public async Task CollectionHandler_WithZero_NeverCollects()
    {
        var collections = 0;
        using var invoker = InvokerFor(new RequestCountCollectionHandler(0, () => collections++, Inline), new StubHandler());

        for (var i = 0; i < 50; i++)
        {
            using var response = await invoker.SendAsync(new HttpRequestMessage(HttpMethod.Get, "https://bootloader.example/"), default);
        }

        Assert.Equal(0, collections);
    }

    [Fact]
    public void CollectionHandler_RefusesANegativeCount()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new RequestCountCollectionHandler(-1));
    }

    [Fact]
    public async Task CollectionHandler_PassesTheRequestAndTheResponseThroughUntouched()
    {
        var stub = new StubHandler();
        using var invoker = InvokerFor(new RequestCountCollectionHandler(1, () => { }, Inline), stub);
        using var request = new HttpRequestMessage(HttpMethod.Post, "https://bootloader.example/v0.4/respond/abc")
        {
            Content = new StringContent("{}"),
        };
        request.Headers.TryAddWithoutValidation("X-Test", "kept");

        using var response = await invoker.SendAsync(request, default);

        Assert.Same(request, stub.LastRequest);
        Assert.Same(stub.LastResponse, response);
        Assert.Equal("kept", Assert.Single(request.Headers.GetValues("X-Test")));
    }

    [Fact]
    public async Task CollectionHandler_ItsOwnCollection_RunsWithoutFaultingTheRequest()
    {
        using var invoker = InvokerFor(new RequestCountCollectionHandler(1), new StubHandler());

        for (var i = 0; i < 3; i++)
        {
            using var response = await invoker.SendAsync(new HttpRequestMessage(HttpMethod.Get, "https://bootloader.example/"), default);
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        }
    }

    [Fact]
    public async Task CollectionHandler_AQueueThatThrows_LeavesAGoodResponseStanding_AndTheNextCountQueuesAgain()
    {
        var queued = 0;
        var stub = new StubHandler();
        using var invoker = InvokerFor(
            new RequestCountCollectionHandler(1, () => { }, _ =>
            {
                queued++;
                throw new InvalidOperationException("the queue is closed");
            }),
            stub);

        for (var i = 1; i <= 3; i++)
        {
            using var response = await invoker.SendAsync(new HttpRequestMessage(HttpMethod.Get, "https://bootloader.example/"), default);
            Assert.Same(stub.LastResponse, response);
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            // A queueing that failed does not hold the one-at-a-time slot.
            Assert.Equal(i, queued);
        }
    }

    [Fact]
    public async Task CollectionHandler_AQueueThatThrows_LeavesTheRequestsOwnExceptionStanding()
    {
        using var invoker = InvokerFor(
            new RequestCountCollectionHandler(1, () => { }, _ => throw new InvalidOperationException("the queue is closed")),
            new StubHandler { Fail = true });

        var thrown = await Assert.ThrowsAsync<HttpRequestException>(() =>
            invoker.SendAsync(new HttpRequestMessage(HttpMethod.Get, "https://bootloader.example/"), default));

        Assert.Equal("refused", thrown.Message);
    }

    [Fact]
    public async Task CollectionHandler_ACollectionThatThrows_IsDropped_AndTheNextCountCollectsAgain()
    {
        var collections = 0;
        using var invoker = InvokerFor(
            new RequestCountCollectionHandler(1, () =>
            {
                collections++;
                throw new InvalidOperationException("the collection faulted");
            }, Inline),
            new StubHandler());

        for (var i = 1; i <= 3; i++)
        {
            using var response = await invoker.SendAsync(new HttpRequestMessage(HttpMethod.Get, "https://bootloader.example/"), default);
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal(i, collections);
        }
    }

    [Fact]
    public async Task CollectionHandler_ACollectionThatThrowsOnThePool_FaultsNeitherTheRequestNorTheNextOne()
    {
        var runs = 0;
        var ran = new SemaphoreSlim(0);
        using var invoker = InvokerFor(
            new RequestCountCollectionHandler(1, () =>
            {
                Interlocked.Increment(ref runs);
                ran.Release();
                throw new InvalidOperationException("the collection faulted");
            }),
            new StubHandler());

        using (var first = await invoker.SendAsync(new HttpRequestMessage(HttpMethod.Get, "https://bootloader.example/"), default))
        {
            Assert.Equal(HttpStatusCode.OK, first.StatusCode);
        }
        Assert.True(await ran.WaitAsync(TimeSpan.FromSeconds(10)));

        // The faulted collection gives its slot back, so a later request's count collects again.
        for (var i = 0; i < 500 && Volatile.Read(ref runs) < 2; i++)
        {
            using var response = await invoker.SendAsync(new HttpRequestMessage(HttpMethod.Get, "https://bootloader.example/"), default);
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            await Task.Delay(10);
        }

        Assert.True(Volatile.Read(ref runs) >= 2);
    }

    [Fact]
    public async Task CollectionHandler_QueuesAtMostOneCollectionAtATime()
    {
        var held = new List<Action>();
        var collections = 0;
        using var invoker = InvokerFor(
            new RequestCountCollectionHandler(2, () => collections++, held.Add),
            new StubHandler());

        // Five counts are reached while the first collection is still only queued: one is queued, four are skipped.
        await SendManyAsync(invoker, 10);
        Assert.Single(held);
        Assert.Equal(0, collections);

        // It runs; the next count queues the next one, and again only one.
        held[0]();
        Assert.Equal(1, collections);
        await SendManyAsync(invoker, 6);
        Assert.Equal(2, held.Count);
    }

    [Fact]
    public async Task CollectionHandler_ACollectionStillRunning_HoldsTheSlot()
    {
        using var running = new ManualResetEventSlim();
        using var release = new ManualResetEventSlim();
        var queued = 0;
        using var invoker = InvokerFor(
            new RequestCountCollectionHandler(
                1,
                () =>
                {
                    running.Set();
                    release.Wait(TimeSpan.FromSeconds(10));
                },
                work =>
                {
                    Interlocked.Increment(ref queued);
                    ThreadPool.QueueUserWorkItem(_ => work());
                }),
            new StubHandler());

        await SendManyAsync(invoker, 1);
        Assert.True(running.Wait(TimeSpan.FromSeconds(10)));
        await SendManyAsync(invoker, 5);

        Assert.Equal(1, Volatile.Read(ref queued));
        release.Set();
    }

    [Fact]
    public void CollectionHandler_DefaultCount_IsAboutOneAMinuteAtThePollInterval()
    {
        // The home page polls every three seconds.
        Assert.InRange(RequestCountCollectionHandler.DefaultRequestsPerCollection * 3, 30, 120);
    }

    // --- the chain AddSharedServices registers ---

    [Fact]
    public void RegisteredChain_HasTheCollectionHandlerInFrontOfThePrimaryHandlerWithItsCallback()
    {
        using var provider = SharedServices(new PinningService());
        var chain = HandlersOf(provider);

        var collector = Assert.Single(chain.OfType<RequestCountCollectionHandler>());
        var primary = Assert.IsType<HttpClientHandler>(chain[^1]);
        Assert.NotNull(primary.ServerCertificateCustomValidationCallback);
        Assert.True(chain.IndexOf(collector) < chain.Count - 1);
    }

    [Fact]
    public async Task RegisteredChain_WrongPin_IsRefused()
    {
        using var server = new LoopbackTlsServer();
        var pinning = new PinningService();
        pinning.SetPin(Host, WrongPin);
        using var provider = SharedServices(pinning);
        using var client = ClientOf(provider);

        await Assert.ThrowsAsync<HttpRequestException>(() => client.GetAsync(server.Url));

        Assert.Equal(0, server.RequestsServed);
        // The certificate the server showed is still recorded for the drift check.
        Assert.Equal(server.SpkiPin, pinning.GetObservedPin(Host));
        Assert.True(pinning.HasDrifted(Host));
    }

    [Fact]
    public async Task RegisteredChain_MatchingPin_IsAccepted()
    {
        using var server = new LoopbackTlsServer();
        var pinning = new PinningService();
        pinning.SetPin(Host, server.SpkiPin);
        using var provider = SharedServices(pinning);
        using var client = ClientOf(provider);

        using var response = await client.GetAsync(server.Url);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(1, server.RequestsServed);
    }

    [Fact]
    public async Task RegisteredChain_NoPin_OutsideAPairing_IsRefused()
    {
        using var server = new LoopbackTlsServer();
        using var provider = SharedServices(new PinningService());
        using var client = ClientOf(provider);

        await Assert.ThrowsAsync<HttpRequestException>(() => client.GetAsync(server.Url));

        Assert.Equal(0, server.RequestsServed);
    }

    [Fact]
    public async Task RegisteredChain_NoPin_InsideThePairingWindow_IsAcceptedForThatHostOnly()
    {
        using var server = new LoopbackTlsServer();
        var pinning = new PinningService();
        using var provider = SharedServices(pinning);
        using var client = ClientOf(provider);

        pinning.BeginPairing("other.example");
        await Assert.ThrowsAsync<HttpRequestException>(() => client.GetAsync(server.Url));

        pinning.BeginPairing(Host);
        using var response = await client.GetAsync(server.Url);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(server.SpkiPin, pinning.GetObservedPin(Host));
    }

    // --- source pins: what Android is given ---

    [Fact]
    public void Registration_KeepsThePlatformDefaultHandlerAndItsPerRequestCallback()
    {
        var compact = Compact(PhoneFile("Recto.Shared", "Extensions", "ServiceCollectionExtensions.cs"));

        // The primary handler is the platform default with the pin check as its callback, keyed by the request's host.
        Assert.Contains(
            "varhandler=newHttpClientHandler();"
            + "handler.ServerCertificateCustomValidationCallback=(req,cert,chain,errors)=>"
            + "{if(certisnull||req.RequestUriisnull){returnfalse;}"
            + "varhost=req.RequestUri.Host;"
            + "varactualSpki=CertPinHelpers.ComputeSpkiPin(cert);"
            + "returnpinning.Validate(host,actualSpki,errors==SslPolicyErrors.None);};"
            + "returnhandler;",
            compact);
        // No other handler type, and no connection pool setting, stands in for it on any platform.
        Assert.DoesNotContain("SocketsHttpHandler", compact);
        Assert.DoesNotContain("PooledConnection", compact);
        Assert.DoesNotContain("RemoteCertificateValidationCallback", compact);
        Assert.Equal(1, Count(compact, "ServerCertificateCustomValidationCallback="));
        Assert.Equal(1, Count(compact, "AddHttpClient"));
        // Nothing elsewhere swaps the handler under it: no project switch to the managed handler, and the app's
        // own start-up registers no client defaults, no second bootloader client and no handler of its own.
        var project = Compact(PhoneFile("Recto", "Recto.csproj"), xml: true);
        Assert.DoesNotContain("<UseNativeHttpHandler>false", project, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("UseNativeHttpHandler=false", project, StringComparison.OrdinalIgnoreCase);
        var startup = Compact(PhoneFile("Recto", "MauiProgram.cs"));
        Assert.DoesNotContain("ConfigureHttpClientDefaults", startup);
        Assert.DoesNotContain("AddHttpClient", startup);
        Assert.DoesNotContain("HttpMessageHandler", startup);
        Assert.DoesNotContain("HttpClientHandler", startup);
        // The collection handler counts requests on Android only.
        Assert.Contains(
            ".AddHttpMessageHandler(()=>newRequestCountCollectionHandler("
            + "OperatingSystem.IsAndroid()?RequestCountCollectionHandler.DefaultRequestsPerCollection:0));",
            compact);
    }

    [Fact]
    public void AndroidKeyService_ReleasesItsPlatformObjectsOnEveryEnding()
    {
        var compact = Compact(PhoneFile("Recto", "Platforms", "Android", "AndroidStrongBoxKeyService.cs"));

        // SignAsync: the key handle, and the Signature of a direct signature.
        Assert.Contains("finally{if(!signerHandedOn){Release(signer);}Release(privateKey);}", compact);
        // SignAsync: the key store and its entry, after the method's own catch, so neither can change its answer.
        var sign = compact.Substring(compact.IndexOf("Sign(stringkeyAlias,byte[]message,boolmayPrompt,CancellationTokenct){", StringComparison.Ordinal));
        sign = sign[..sign.IndexOf("publicTask<Result>DeleteAsync(", StringComparison.Ordinal)];
        Assert.DoesNotContain("usingvar", sign);
        Assert.EndsWith("{ex.Message}\")));}finally{Release(entry);Release(keyStore);}}", sign);
        // The key's authentication requirement: the answer is returned from the try, the releases follow.
        Assert.Contains(
            "if(specisnotKeyInfoinfo){returnKeyGate.Unreadable;}"
            + "returninfo.IsUserAuthenticationRequired?KeyGate.Gated:KeyGate.Open;}"
            + "catch{returnKeyGate.Unreadable;}finally{Release(spec);Release(factory);}",
            compact);
        // The prompt path: a prompt that could not be started, then the prompt's two endings. Each releases the
        // Signature and the objects made for the prompt - the prompt, its crypto object, its info and the builder.
        Assert.Contains(
            "catch(Exceptionex){if(callbackisnull){Release(signer);Release(flight);}else{callback.ReleaseAll();}"
            + "returnResult.Failure<byte[]>(Error.Failure($\"Androidsignexception:{ex.GetType().Name}:{ex.Message}\"));}",
            compact);
        Assert.Contains("newBiometricAuthCallback(tcs,message,signer)", compact);
        // ONE outcome: every ending claims it first, and exactly one wins. The claim moves Live -> Ending, or
        // takes over from a cancel (Cancelled -> Ending), which had answered the caller and left the release.
        Assert.Contains("privateconstintLive=0;privateconstintCancelled=1;privateconstintEnding=2;privateint_state=Live;", compact);
        Assert.Contains(
            "privateint?Claim(){varwas=Interlocked.CompareExchange(ref_state,Ending,Live);if(was==Live){returnLive;}"
            + "if(was==Cancelled&&Interlocked.CompareExchange(ref_state,Ending,Cancelled)==Cancelled){returnCancelled;}"
            + "returnnull;}",
            compact);
        // Every ending of the prompt claims, then Finish: everything is released, the single-flight pass
        // included, and only then is the caller answered. A cancel answers once, by its own claim.
        Assert.Contains("privatevoidEnd(Result<byte[]>answer){if(Claim()isnull){return;}Finish(answer);}", compact);
        Assert.Contains("privatevoidFinish(Result<byte[]>answer){ReleaseAll();_tcs.TrySetResult(answer);}", compact);
        Assert.Contains(
            "publicboolCancel(){if(Interlocked.CompareExchange(ref_state,Cancelled,Live)!=Live){returnfalse;}"
            + "_tcs.TrySetResult(Result.Failure<byte[]>(Error.Failure(\"Operationcancelled.\")));returntrue;}",
            compact);
        Assert.Equal(2, Count(compact, "_tcs.TrySetResult("));
        // Claim(): its declaration, End's, the success's, and the lapse's two (on the main thread, or at once
        // when the main thread cannot be asked).
        Assert.Equal(5, Count(compact, "Claim()"));
        // Its declaration, the error ending and the abandon.
        Assert.Equal(3, Count(compact, "End("));
        // Finish: its declaration, End's, the success's two (a sign, or a release after a cancel), the lapse's two.
        Assert.Equal(6, Count(compact, "Finish("));
        Assert.DoesNotContain("finally{ReleaseAll();}", compact);
        Assert.DoesNotContain("ReleaseSigner", compact);
        foreach (var made in new[] { "flight", "cryptoObject", "builder", "promptInfo", "life" })
        {
            Assert.Equal(1, Count(compact, $"callback.Hold({made});"));
        }
        Assert.Equal(1, Count(compact, "callback.Show(prompt);"));
        Assert.Contains("publicvoidShow(BiometricPromptprompt){_prompt=prompt;Hold(prompt);}", compact);
        Assert.Contains(
            "publicvoidReleaseAll(){Volatile.Write(ref_state,Ending);Release(Interlocked.Exchange(ref_signer,null));"
            + "varheld=Interlocked.Exchange(ref_held,null);if(heldisnull){return;}_prompt=null;"
            + "for(vari=held.Count-1;i>=0;i--){Release(held[i]);}}",
            compact);
        // Every release goes through the one best-effort helper: a release that throws is dropped there.
        Assert.Contains("privatestaticvoidRelease(IDisposable?handle){try{handle?.Dispose();}catch{}}", compact);
        // Two in the file: the helper's, and the activity watch's own stop, which is released through the helper.
        Assert.Equal(2, Count(compact, "Dispose()"));
        Assert.Contains("publicvoidDispose()=>_application.UnregisterActivityLifecycleCallbacks(_watch);", compact);
        // Cancellation answers the caller - when it wins the claim - and asks the prompt to close. It
        // releases nothing itself: the Signature and the single-flight pass stay with the prompt until the
        // prompt's own ending (or an abandon or a lapse), which takes the claim from it.
        Assert.Contains(
            "usingvarregistration=ct.Register(()=>{"
            + "if(shown.Cancel()){RequestDismissal(on,shown);}});"
            + "returnawaittcs.Task.ConfigureAwait(false);}",
            compact);
        var dismissal = compact.Substring(compact.IndexOf("privatestaticvoidRequestDismissal(", StringComparison.Ordinal));
        dismissal = dismissal[..dismissal.IndexOf("privatestaticboolIsGone(", StringComparison.Ordinal)];
        Assert.Equal(2, Count(dismissal, "activity.RunOnUiThread(callback.Dismiss);"));
        Assert.DoesNotContain("Release", dismissal);
        Assert.DoesNotContain("Dispose", dismissal);
        // A dismissal that arrives after this prompt has ended does nothing, so it cannot close a later one.
        Assert.Contains(
            "publicvoidDismiss(){if(Volatile.Read(ref_held)isnull){return;}"
            + "try{_prompt?.CancelAuthentication();}catch{}}",
            compact);
    }

    [Fact]
    public void AndroidKeyService_AdmitsOnePromptAtATime_AndRefusesTheSecondByName()
    {
        var compact = Compact(PhoneFile("Recto", "Platforms", "Android", "AndroidStrongBoxKeyService.cs"));
        var sign = compact.Substring(compact.IndexOf("Sign(stringkeyAlias,byte[]message,boolmayPrompt,CancellationTokenct){", StringComparison.Ordinal));
        sign = sign[..sign.IndexOf("publicTask<Result>DeleteAsync(", StringComparison.Ordinal)];

        // One gate for the whole process.
        Assert.Equal(1, Count(compact, "privatestaticreadonlySingleFlightPromptFlight=new();"));
        Assert.Equal(1, Count(compact, "PromptFlight.TryEnter()"));
        // The gated branch: the pass is taken, or the signing is refused by name, before the prompt flow is
        // handed the Signature. It is the only way into the prompt flow.
        Assert.Contains(
            "varflight=PromptFlight.TryEnter();"
            + "if(flightisnull){returnTask.FromResult(Result.Failure<byte[]>(Error.Conflict(PromptBusyMessage)));}"
            + "signerHandedOn=true;"
            + "returnAuthenticateAndSignAsync(signer,flight,message,keyAlias,ct);",
            sign);
        Assert.Equal(1, Count(compact, "AuthenticateAndSignAsync(signer,"));
        // A refused second signing releases its own Signature: it was never handed on.
        Assert.Contains("finally{if(!signerHandedOn){Release(signer);}Release(privateKey);}", sign);
        // The pass is released on every ending. No prompt shown: at once. A prompt that failed to start, or
        // one that ended: with everything else the callback holds, and it is the first thing held, so the
        // last thing released.
        Assert.Contains("if(!CanShowPrompt(activity)){Release(signer);Release(flight);", compact);
        Assert.Contains("if(callbackisnull){Release(signer);Release(flight);}else{callback.ReleaseAll();}", compact);
        Assert.Contains(
            "callback=newBiometricAuthCallback(tcs,message,signer);callback.Hold(flight);"
            + "varhost=newPromptHost<global::Android.App.Activity>(activity);varanswering=callback;"
            + "callback.Hold(ActivityWatch.Start(host,answering));"
            + "varprompt=newBiometricPrompt(activity,executor,callback);",
            compact);
        Assert.Equal(2, Count(compact, "Release(flight);"));
        // The words name no key and no alias.
        Assert.Contains(
            "PromptBusyMessage=\"Anotherapprovaliswaitingforyourbiometric.Finishorcancelit,thentryagain.\";",
            compact);
    }

    [Fact]
    public void AndroidKeyService_ThePassIsTiedToTheActivity_SoALostEndingCannotHoldItForEver()
    {
        var compact = Compact(PhoneFile("Recto", "Platforms", "Android", "AndroidStrongBoxKeyService.cs"));

        // The prompt library delivers an ending only while its fragment is started; an activity destroyed
        // under a prompt drops it. Two ways back, both pinned.
        // Both are asked of the prompt's host (PromptHost, tested on its own in PromptHostTests), which
        // follows the activity across a rebuild: a configuration change destroys the activity the prompt was
        // first shown on while the prompt lives, so nothing here reads that captured activity again.
        // 1. The activity's own destruction - the host says whether it was for good - ends the signing, and
        //    the next activity created is handed to the host.
        Assert.Contains(
            "publicvoidOnActivityDestroyed(global::Android.App.Activityactivity){"
            + "if(_host.Destroyed(activity,activity.IsChangingConfigurations)){_callback.Abandon(PromptLostMessage);}}",
            compact);
        Assert.Contains(
            "publicvoidOnActivityCreated(global::Android.App.Activityactivity,global::Android.OS.Bundle?savedInstanceState)"
            + "=>_host.Created(activity);",
            compact);
        Assert.Contains("application.RegisterActivityLifecycleCallbacks(watch);returnnewStop(application,watch);", compact);
        // 2. A later signing takes back a pass whose activity - the one the host watches now - is destroyed,
        //    finishing or no longer current. The reads are the activity's own, and its "changing
        //    configurations" comes first: Android sets it and marks the activity destroyed before the watch
        //    hears of the destroy, and a signing asked in that window must not take a live prompt's pass.
        Assert.Contains(
            "privatestaticboolIsGone(PromptHost<global::Android.App.Activity>host){try{"
            + "returnhost.IsGone(watched=>watched.IsChangingConfigurations,watched=>watched.IsDestroyed,"
            + "watched=>watched.IsFinishing,()=>Microsoft.Maui.ApplicationModel.Platform.CurrentActivity);}"
            + "catch{returntrue;}}",
            compact);
        Assert.DoesNotContain("shownOn", compact);
        // Once in the destroy event, once in the reclaim's read.
        Assert.Equal(2, Count(compact, "IsChangingConfigurations"));
        // The pass can be taken back only once the prompt is asked: the watch is set on the line before. The
        // prompt's whole life is capped (PromptLife, tested on its own): the LAPSE alone ends a prompt that
        // ran out of time, answering in its own words and closing the prompt. The watch reads the life only
        // as a late backstop, Grace past the limit, so a signing at the limit can never take the pass ahead
        // of the queued lapse; and its abandon answers in the lapse's words once the limit is reached.
        Assert.Contains(
            "varlapseOn=activity;varlife=newPromptLife(()=>answering.Lapse(lapseOn));callback.Hold(life);"
            + "flight.Watch(()=>life.IsOverBy(PromptLife.Grace)||IsGone(host),"
            + "()=>answering.Abandon(life.WordsForAnEnding(PromptLostMessage)));"
            + "prompt.Authenticate(promptInfo,cryptoObject);",
            compact);
        Assert.DoesNotContain("life.IsOver||", compact);
        Assert.Equal(1, Count(compact, "flight.Watch("));
        // A prompt past its life claims the outcome on the main thread, then is asked to close, then ended,
        // answering the life's own words; when the main thread cannot be asked it is ended at once. A lapse
        // that loses the claim does nothing.
        Assert.Contains(
            "publicvoidLapse(global::Android.App.Activityon){if(Volatile.Read(ref_state)==Ending){return;}"
            + "varlapsed=Result.Failure<byte[]>(Error.Failure(PromptLife.LapsedMessage));"
            + "try{on.RunOnUiThread(()=>{if(Claim()isnull){return;}Dismiss();Linger();Finish(lapsed);});}"
            + "catch{if(Claim()isnull){return;}Linger();Finish(lapsed);}}",
            compact);
        // After a lapse the pass holds the flight the dismissal's delay longer, so the old prompt's own late
        // ending lands on no one (SingleFlight.Pass.Linger, tested in PromptLifeTests). Only the lapse lingers.
        Assert.Contains("privatevoidLinger()=>_pass?.Linger(DismissRetryDelay);", compact);
        Assert.Equal(2, Count(compact, "Linger();"));
        Assert.Contains("privatestaticreadonlyTimeSpanDismissRetryDelay=TimeSpan.FromMilliseconds(750);", compact);
        Assert.Contains("if(madeisSingleFlight.Passpass){_pass=pass;}", compact);
        // A success whose Signature is not this prompt's own - an older prompt's late ending - signs nothing.
        Assert.Contains(
            "varsig=result.CryptoObject?.Signature;varmine=Volatile.Read(ref_signer);"
            + "if(sigisnull){answer=Result.Failure<byte[]>(Error.Failure(\"BiometricPromptCryptoObjectsignaturewasnull.\"));}"
            + "elseif(mineisnull||!global::Android.Runtime.JNIEnv.IsSameObject(sig.Handle,mine.Handle))"
            + "{answer=Result.Failure<byte[]>(Error.Failure(ForeignTouchMessage));}"
            + "else{sig.Update(_message);",
            compact);
        Assert.Contains(
            "privateconststringForeignTouchMessage=\"Thisapproval'stouchbelongedtoanotherprompt.Nothingwassigned.\";",
            compact);
        // The prompt says its limit.
        Assert.Contains(
            "builder.SetDescription($\"Yourfingerprintapprovesthiscryptographicoperation.Approvewithin{PromptLife.Limit.TotalMinutes:0}minutes.\");",
            compact);
        // An object handed to a callback that has already ended is released at once, never dropped.
        Assert.Contains(
            "publicvoidHold(IDisposable?made){if(madeisnull){return;}varheld=Volatile.Read(ref_held);"
            + "if(heldisnull){Release(made);return;}held.Add(made);if(madeisSingleFlight.Passpass){_pass=pass;}}",
            compact);
        // A success claims first. One that loses - the caller was told nothing was signed - never touches the
        // Signature; one that takes over from a cancel releases and signs nothing.
        Assert.Contains(
            "publicoverridevoidOnAuthenticationSucceeded(BiometricPrompt.AuthenticationResultresult){"
            + "varclaimed=Claim();if(claimedisnull){return;}"
            + "if(claimed==Cancelled){Finish(Result.Failure<byte[]>(Error.Failure(\"Operationcancelled.\")));return;}"
            + "Result<byte[]>answer;",
            compact);
        // Either way the caller is answered with a failure, after everything is released; a prompt that has
        // already ended is left alone.
        Assert.Contains(
            "publicvoidAbandon(stringwords){End(Result.Failure<byte[]>(Error.Failure(words)));}",
            compact);
        Assert.Contains(
            "PromptLostMessage=\"Thebiometricpromptwasclosedbeforeitwasanswered.Nothingwassigned.Tryagain.\";",
            compact);
        // Nothing is signed on that path: Abandon reaches no Signature call.
        var abandon = compact.Substring(compact.IndexOf("publicvoidAbandon(stringwords)", StringComparison.Ordinal));
        abandon = abandon[..abandon.IndexOf("publicvoidHold(", StringComparison.Ordinal)];
        Assert.DoesNotContain(".Sign(", abandon);
        Assert.DoesNotContain("Result.Success", abandon);
    }

    [Fact]
    public void IosKeyService_ADeviceKeySigning_IsMadeWithInteractionDisallowed()
    {
        var compact = Compact(PhoneFile("Recto", "Platforms", "iOS", "IosSecureEnclaveKeyService.cs"));
        var device = compact.Substring(compact.IndexOf("SignWithDeviceKeyAsync(stringkeyAlias,", StringComparison.Ordinal));
        device = device[..device.IndexOf("privateconstlongErrSecInteractionNotAllowed", StringComparison.Ordinal)];

        // The key is loaded under a context that forbids interaction, so the enclave fails in place of asking.
        Assert.Contains(
            "usingvarnoPrompt=newLAContext{InteractionNotAllowed=true};"
            + "usingvarprivateKey=LoadPrivateKey(keyAlias,noPrompt,outvarstatus);"
            + "if(status==SecStatusCode.InteractionNotAllowed){"
            + "returnTask.FromResult(Result.Failure<byte[]>(DeviceKeyRefusal.Locked()));}",
            device);
        Assert.Contains("if(contextisnotnull){query.AuthenticationContext=context;}", compact);
        // "Interaction not allowed" means two things. When the key is LOADED it is the locked device, never a
        // gated key. At signing, LocalAuthentication's "not interactive" is the gated key; the keychain's
        // status is the gated key only while protected data is available, and the locked device otherwise.
        Assert.Contains(
            "returnTask.FromResult(Result.Failure<byte[]>(ReadInteractionFailure(error)switch{"
            + "InteractionFailure.Gated=>DeviceKeyRefusal.Gated(),"
            + "InteractionFailure.Locked=>DeviceKeyRefusal.Locked(),",
            device);
        Assert.Contains(
            "if(code==LaErrorNotInteractive&&error.Domain==LaErrorDomain){returnInteractionFailure.Gated;}"
            + "if(code==ErrSecInteractionNotAllowed){"
            + "returnProtectedDataAvailable()?InteractionFailure.Gated:InteractionFailure.Locked;}",
            compact);
        // Protected data that cannot be read is "not available": the failure is then a locked device.
        Assert.Contains(
            "application.InvokeOnMainThread(()=>available=application.ProtectedDataAvailable);"
            + "returnavailable;}catch{returnfalse;}",
            compact);
        Assert.Equal(1, Count(compact, "DeviceKeyRefusal.Gated()"));
        Assert.Contains("ErrSecInteractionNotAllowed=-25308;", compact);
        Assert.Contains("LaErrorNotInteractive=-1004;", compact);
        // The entry that may prompt is unchanged: it loads the key under no context.
        var prompting = compact.Substring(compact.IndexOf("publicTask<Result<byte[]>>SignAsync(", StringComparison.Ordinal));
        prompting = prompting[..prompting.IndexOf("publicTask<Result<byte[]>>SignWithDeviceKeyAsync(", StringComparison.Ordinal)];
        Assert.Contains("usingvarprivateKey=LoadPrivateKey(keyAlias);", prompting);
        Assert.DoesNotContain("LAContext", prompting);
    }

    [Fact]
    public void EveryKeyService_SaysForItself_HowItSignsWithADeviceKey()
    {
        // The interface's default refuses and never calls the signing that may prompt, so a key service
        // that gates keys cannot prompt on the timer by leaving the method out.
        var contract = Compact(PhoneFile("Recto.Shared", "Services", "IEnclaveKeyService.cs"));
        Assert.Contains(
            "Task<Result<byte[]>>SignWithDeviceKeyAsync(stringkeyAlias,byte[]message,CancellationTokenct)"
            + "=>Task.FromResult(Result.Failure<byte[]>(DeviceKeyRefusal.NoEntry()));",
            contract);
        Assert.DoesNotContain("=>SignAsync(", contract);
        // Each shipped key service has its own.
        foreach (var file in new[]
        {
            new[] { "Recto", "Platforms", "Android", "AndroidStrongBoxKeyService.cs" },
            new[] { "Recto", "Platforms", "iOS", "IosSecureEnclaveKeyService.cs" },
            new[] { "Recto", "Services", "SoftwareEnclaveKeyService.cs" },
            new[] { "Recto.Shared", "Services", "NoHardwareKeyService.cs" },
        })
        {
            Assert.Equal(
                1,
                Count(Compact(PhoneFile(file)), "publicTask<Result<byte[]>>SignWithDeviceKeyAsync(stringkeyAlias,byte[]message,CancellationTokenct)"));
        }
        // No key service is left out: those four are every implementation in the app.
        var implementations = new[] { PhonePath("Recto"), PhonePath("Recto.Shared") }
            .SelectMany(root => Directory.EnumerateFiles(root, "*.cs", SearchOption.AllDirectories))
            .Where(path => !path.Contains(Path.DirectorySeparatorChar + "obj" + Path.DirectorySeparatorChar)
                && !path.Contains(Path.DirectorySeparatorChar + "bin" + Path.DirectorySeparatorChar))
            .Count(path => Compact(File.ReadAllText(path)).Contains(":IEnclaveKeyService{", StringComparison.Ordinal));
        Assert.Equal(4, implementations);
    }

    [Fact]
    public void AndroidKeyService_ADeviceKeySigning_NeverReachesThePrompt()
    {
        var compact = Compact(PhoneFile("Recto", "Platforms", "Android", "AndroidStrongBoxKeyService.cs"));
        var sign = compact.Substring(compact.IndexOf("Sign(stringkeyAlias,byte[]message,boolmayPrompt,CancellationTokenct){", StringComparison.Ordinal));
        sign = sign[..sign.IndexOf("publicTask<Result>DeleteAsync(", StringComparison.Ordinal)];

        // The two public entries differ in one word.
        Assert.Contains(
            "publicTask<Result<byte[]>>SignAsync(stringkeyAlias,byte[]message,CancellationTokenct)"
            + "=>Sign(keyAlias,message,mayPrompt:true,ct);",
            compact);
        Assert.Contains(
            "publicTask<Result<byte[]>>SignWithDeviceKeyAsync(stringkeyAlias,byte[]message,CancellationTokenct)"
            + "=>Sign(keyAlias,message,mayPrompt:false,ct);",
            compact);
        // A key the keystore reports as gated is refused before the gate and before the prompt.
        var direct = sign.IndexOf("vargate=ReadKeyGate(privateKey!);if(gate==KeyGate.Open){", StringComparison.Ordinal);
        // Three answers from the keystore. Only "open" signs directly. Asked as a device key, "gated" is the
        // named refusal and "unreadable" is an ordinary failure the read signer tries again - a passing
        // keystore error is never reported as a gated key.
        var refused = sign.IndexOf(
            "if(!mayPrompt){returnTask.FromResult(Result.Failure<byte[]>(gate==KeyGate.Gated"
            + "?DeviceKeyRefusal.Gated():Error.Failure(KeyGateUnreadableMessage)));}",
            StringComparison.Ordinal);
        Assert.Equal(1, Count(sign, "KeyGate.Open"));
        Assert.Equal(1, Count(compact, "DeviceKeyRefusal.Gated()"));
        var gate = sign.IndexOf("PromptFlight.TryEnter()", StringComparison.Ordinal);
        var prompt = sign.IndexOf("AuthenticateAndSignAsync(", StringComparison.Ordinal);
        Assert.True(direct > 0 && refused > direct && gate > refused && prompt > gate);
        // The read signer signs through the device-key entry and no other.
        var polls = Compact(PhoneFile("Recto.Shared", "Services", "PollSigning.cs"));
        Assert.Contains("awaitenclave.SignWithDeviceKeyAsync(keyAlias,payload,ct)", polls);
        Assert.DoesNotContain(".SignAsync(", polls);
        Assert.DoesNotContain(".SignAsync(", Compact(PhoneFile("Recto.Shared", "Services", "IReadSigner.cs")));
    }

    [Fact]
    public void AndroidKeyService_APromptThatCannotShow_IsAnsweredBeforeThePromptIsAsked()
    {
        var compact = Compact(PhoneFile("Recto", "Platforms", "Android", "AndroidStrongBoxKeyService.cs"));
        var prompt = compact.Substring(compact.IndexOf("AuthenticateAndSignAsync(Signaturesigner,", StringComparison.Ordinal));
        prompt = prompt[..prompt.IndexOf("privatesealedclassBiometricAuthCallback", StringComparison.Ordinal)];

        // The library returns from authenticate without showing, and without calling back, for an activity that is
        // finishing or destroyed or whose fragment manager has saved its state. Those are refused first, by name.
        var refusal = prompt.IndexOf(
            "if(!CanShowPrompt(activity)){Release(signer);Release(flight);"
            + "returnResult.Failure<byte[]>(Error.Failure(PromptNotShownMessage));}",
            StringComparison.Ordinal);
        var asked = prompt.IndexOf("prompt.Authenticate(promptInfo,cryptoObject);", StringComparison.Ordinal);
        Assert.True(refusal > 0);
        Assert.True(asked > refusal);
        Assert.Equal(1, Count(prompt, ".Authenticate("));
        Assert.Contains(
            "privatestaticboolCanShowPrompt(FragmentActivityactivity){try{"
            + "if(activity.IsFinishing||activity.IsDestroyed){returnfalse;}"
            + "varfragments=activity.SupportFragmentManager;"
            + "returnfragmentsisnotnull&&!fragments.IsStateSaved;}catch{returnfalse;}}",
            prompt);
        // Nothing escapes as an exception: the method is awaited, so every ending is a result.
        Assert.DoesNotContain("throw;", prompt);
        Assert.Equal(2, Count(prompt, "returnResult.Failure<byte[]>("));
        Assert.EndsWith("returnfalse;}}", prompt);
        // The words the caller is given name no key, no alias and no platform type.
        Assert.Contains(
            "PromptNotShownMessage=\"ThebiometricpromptcouldnotbeshownbecauseRectoisnotonscreen.OpenRectoandtryagain.\";",
            compact);
    }

    [Fact]
    public void SharedAssembly_OpensItsInternalsToNoOtherAssembly()
    {
        var root = Path.GetDirectoryName(PhonePath("Recto.Shared", "Recto.Shared.csproj"))!;
        foreach (var file in Directory.EnumerateFiles(root, "*.cs*", SearchOption.AllDirectories))
        {
            var relative = Path.GetRelativePath(root, file);
            if (relative.StartsWith("obj", StringComparison.Ordinal) || relative.StartsWith("bin", StringComparison.Ordinal))
            {
                continue;
            }
            Assert.DoesNotContain("InternalsVisibleTo", File.ReadAllText(file));
        }
    }

    // --- the pins' own reader ---

    [Theory]
    [InlineData("var u = \"https://bootloader.example\"; // gone", "varu=\"https://bootloader.example\";")]
    [InlineData("var c = '/'; var d = '\\''; // gone", "varc='/';vard='\\'';")]
    [InlineData("var v = @\"a \"\"//\"\" b\"; // gone", "varv=@\"a\"\"//\"\"b\";")]
    [InlineData("a /* gone // gone */ b // gone\nc", "abc")]
    [InlineData("var e = \"a\\\"//b\"; /* gone */ f", "vare=\"a\\\"//b\";f")]
    public void Compact_DropsCommentsAndKeepsAStringLiteralsSlashes(string source, string expected)
    {
        Assert.Equal(expected, Compact(source));
    }

    [Fact]
    public void Compact_Xml_DropsXmlCommentsOnly()
    {
        Assert.Equal("<a>http://x</a>", Compact("<a>http://x</a> <!-- <b>false</b> -->", xml: true));
    }

    // --- helpers ---

    /// <summary>
    /// The source with its comments and white space removed, so a pin can be met only by code. A comment marker
    /// inside a string or character literal is text, not a comment.
    /// </summary>
    private static string Compact(string source, bool xml = false)
    {
        var kept = new StringBuilder(source.Length);
        var i = 0;
        while (i < source.Length)
        {
            var c = source[i];
            if (xml)
            {
                if (string.CompareOrdinal(source, i, "<!--", 0, 4) == 0)
                {
                    var end = source.IndexOf("-->", i + 4, StringComparison.Ordinal);
                    i = end < 0 ? source.Length : end + 3;
                    continue;
                }
            }
            else if (c == '/' && i + 1 < source.Length && source[i + 1] == '/')
            {
                var end = source.IndexOf('\n', i);
                i = end < 0 ? source.Length : end;
                continue;
            }
            else if (c == '/' && i + 1 < source.Length && source[i + 1] == '*')
            {
                var end = source.IndexOf("*/", i + 2, StringComparison.Ordinal);
                i = end < 0 ? source.Length : end + 2;
                continue;
            }
            else if (c == '"' || c == '\'')
            {
                // A verbatim string doubles its quote; any other literal escapes it with a backslash.
                var verbatim = c == '"' && i > 0
                    && (source[i - 1] == '@' || (source[i - 1] == '$' && i > 1 && source[i - 2] == '@'));
                var at = i + 1;
                while (at < source.Length)
                {
                    if (source[at] == c)
                    {
                        if (verbatim && at + 1 < source.Length && source[at + 1] == c)
                        {
                            at += 2;
                            continue;
                        }
                        break;
                    }
                    if (!verbatim && source[at] == '\\')
                    {
                        at++;
                    }
                    at++;
                }
                var stop = Math.Min(at + 1, source.Length);
                foreach (var ch in source.AsSpan(i, stop - i))
                {
                    if (!char.IsWhiteSpace(ch))
                    {
                        kept.Append(ch);
                    }
                }
                i = stop;
                continue;
            }
            if (!char.IsWhiteSpace(c))
            {
                kept.Append(c);
            }
            i++;
        }
        return kept.ToString();
    }

    private static int Count(string text, string needle)
    {
        var n = 0;
        for (var at = text.IndexOf(needle, StringComparison.Ordinal); at >= 0;
             at = text.IndexOf(needle, at + needle.Length, StringComparison.Ordinal))
        {
            n++;
        }
        return n;
    }

    private static string PhoneFile(params string[] parts) => File.ReadAllText(PhonePath(parts));

    private static string PhonePath(params string[] parts)
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "Recto", "MauiProgram.cs")))
        {
            dir = dir.Parent;
        }
        Assert.NotNull(dir);
        return Path.Combine(dir!.FullName, Path.Combine(parts));
    }

    private static HttpMessageInvoker InvokerFor(RequestCountCollectionHandler handler, HttpMessageHandler inner)
    {
        handler.InnerHandler = inner;
        return new HttpMessageInvoker(handler, disposeHandler: true);
    }

    private static void Inline(Action work) => work();

    private static async Task SendManyAsync(HttpMessageInvoker invoker, int requests)
    {
        for (var i = 0; i < requests; i++)
        {
            using var response = await invoker.SendAsync(new HttpRequestMessage(HttpMethod.Get, "https://bootloader.example/"), default);
        }
    }

    private const string ClientName = nameof(IBootloaderClient);

    private static ServiceProvider SharedServices(IPinningService pinning)
    {
        var services = new ServiceCollection();
        services.AddSharedServices(new ConfigurationBuilder().Build());
        // Registered last, so it is the one the handler's callback resolves.
        services.AddSingleton(pinning);
        return services.BuildServiceProvider();
    }

    private static HttpClient ClientOf(ServiceProvider provider)
        => provider.GetRequiredService<IHttpClientFactory>().CreateClient(ClientName);

    private static List<HttpMessageHandler> HandlersOf(ServiceProvider provider)
    {
        var chain = new List<HttpMessageHandler>();
        HttpMessageHandler? at = provider.GetRequiredService<IHttpMessageHandlerFactory>().CreateHandler(ClientName);
        while (at is not null)
        {
            chain.Add(at);
            at = (at as DelegatingHandler)?.InnerHandler;
        }
        return chain;
    }

    private sealed class StubHandler : HttpMessageHandler
    {
        public bool Fail { get; init; }
        public HttpRequestMessage? LastRequest { get; private set; }
        public HttpResponseMessage? LastResponse { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            LastRequest = request;
            if (Fail)
            {
                throw new HttpRequestException("refused");
            }
            LastResponse = new HttpResponseMessage(HttpStatusCode.OK);
            return Task.FromResult(LastResponse);
        }
    }

    /// <summary>
    /// A TLS server on a loopback port with a self-signed certificate. It
    /// answers every request on a connection with an empty JSON object and
    /// keeps the connection open until the client closes it.
    /// </summary>
    private sealed class LoopbackTlsServer : IDisposable
    {
        private readonly TcpListener _listener;
        private readonly X509Certificate2 _certificate;
        private readonly CancellationTokenSource _stop = new();
        private int _requestsServed;

        public LoopbackTlsServer()
        {
            _certificate = NewSelfSigned();
            SpkiPin = CertPinHelpers.ComputeSpkiPin(_certificate);
            _listener = new TcpListener(IPAddress.Loopback, 0);
            _listener.Start();
            Url = $"https://{Host}:{((IPEndPoint)_listener.LocalEndpoint).Port}/v0.4/pending";
            _ = AcceptLoopAsync();
        }

        public string Url { get; }
        public string SpkiPin { get; }
        public int RequestsServed => Volatile.Read(ref _requestsServed);

        private static X509Certificate2 NewSelfSigned()
        {
            using var key = RSA.Create(2048);
            var request = new CertificateRequest("CN=loopback", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            var names = new SubjectAlternativeNameBuilder();
            names.AddIpAddress(IPAddress.Loopback);
            request.CertificateExtensions.Add(names.Build());
            using var ephemeral = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
            // Reloaded from PKCS#12 so the private key is usable by the platform's TLS on every OS.
            return X509CertificateLoader.LoadPkcs12(ephemeral.Export(X509ContentType.Pfx), password: null);
        }

        private async Task AcceptLoopAsync()
        {
            try
            {
                while (!_stop.IsCancellationRequested)
                {
                    var tcp = await _listener.AcceptTcpClientAsync(_stop.Token);
                    _ = ServeAsync(tcp);
                }
            }
            catch (OperationCanceledException) { }
            catch (ObjectDisposedException) { }
            catch (SocketException) { }
        }

        private async Task ServeAsync(TcpClient tcp)
        {
            using (tcp)
            {
                try
                {
                    await using var tls = new SslStream(tcp.GetStream(), leaveInnerStreamOpen: false);
                    await tls.AuthenticateAsServerAsync(new SslServerAuthenticationOptions
                    {
                        ServerCertificate = _certificate,
                        EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                    }, _stop.Token);

                    var buffer = new byte[4096];
                    var pending = new StringBuilder();
                    while (true)
                    {
                        var read = await tls.ReadAsync(buffer, _stop.Token);
                        if (read == 0) return;
                        pending.Append(Encoding.ASCII.GetString(buffer, 0, read));
                        while (pending.ToString().IndexOf("\r\n\r\n", StringComparison.Ordinal) is var end and >= 0)
                        {
                            pending.Remove(0, end + 4);
                            Interlocked.Increment(ref _requestsServed);
                            var reply = Encoding.ASCII.GetBytes(
                                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}");
                            await tls.WriteAsync(reply, _stop.Token);
                            await tls.FlushAsync(_stop.Token);
                        }
                    }
                }
                catch (Exception)
                {
                    // A refused handshake or a closed connection ends this connection only.
                }
            }
        }

        public void Dispose()
        {
            _stop.Cancel();
            _listener.Stop();
            _certificate.Dispose();
            _stop.Dispose();
        }
    }
}
