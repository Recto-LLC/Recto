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
        // The key's authentication requirement: the answer is returned from the try, the releases follow.
        Assert.Contains(
            "return(specasKeyInfo)?.IsUserAuthenticationRequired??true;}catch{returntrue;}finally{Release(spec);Release(factory);}",
            compact);
        // The prompt path: a prompt that could not be shown, then the prompt's two endings.
        Assert.Contains("catch{Release(signer);throw;}", compact);
        Assert.Contains("newBiometricAuthCallback(tcs,message,signer)", compact);
        Assert.Equal(2, Count(compact, "finally{ReleaseSigner();}"));
        Assert.Contains("Release(Interlocked.Exchange(ref_signer,null));", compact);
        // Every release goes through the one best-effort helper: a release that throws is dropped there.
        Assert.Contains("privatestaticvoidRelease(IDisposable?handle){try{handle?.Dispose();}catch{}}", compact);
        Assert.Equal(1, Count(compact, "Dispose()"));
        // Cancellation resolves the task and leaves the Signature with the prompt, which is still showing.
        var cancel = compact.IndexOf("ct.Register(()=>tcs.TrySetResult(", StringComparison.Ordinal);
        Assert.True(cancel > 0);
        Assert.DoesNotContain("Dispose", compact.Substring(cancel, 160));
        Assert.DoesNotContain("Release", compact.Substring(cancel, 160));
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

    private static string PhoneFile(params string[] parts)
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "Recto", "MauiProgram.cs")))
        {
            dir = dir.Parent;
        }
        Assert.NotNull(dir);
        return File.ReadAllText(Path.Combine(dir!.FullName, Path.Combine(parts)));
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
