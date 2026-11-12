using System;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Security;
using FluentValidation;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Recto.Shared.Common.Handlers;
using Recto.Shared.Services;
using Scrutor;

[assembly: System.Runtime.CompilerServices.InternalsVisibleTo("Recto.Shared.Tests")]

namespace Recto.Shared.Extensions;

public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Wires up the Recto.Shared service surface for the calling host.
    /// Today this registers the v0.4 bootloader client (with cert pinning),
    /// validators, and the handler-discovery scaffold. Concrete handlers
    /// + further services land as later sprints add them.
    /// </summary>
    public static IServiceCollection AddSharedServices(
        this IServiceCollection services,
        IConfiguration configuration,
        bool isClient = false)
    {
        _ = configuration;
        _ = isClient;

        // Cert pinning service (round 6). Singleton, in-memory; pins are
        // restored from PairingState at app-start by Home.razor.
        services.AddSingleton<IPinningService, PinningService>();

        // FluentValidation: discovers any AbstractValidator<T> in this assembly.
        services.AddValidatorsFromAssembly(typeof(ServiceCollectionExtensions).Assembly);

        // Scrutor: wires concrete IQueryHandler / ICommandHandler implementations.
        // No-op today (no handlers exist yet); auto-registers as we add them.
        services.Scan(scan => scan
            .FromAssemblies(typeof(ServiceCollectionExtensions).Assembly)
            .AddClasses(classes => classes.AssignableTo(typeof(IQueryHandler<,>)))
                .AsImplementedInterfaces()
                .WithScopedLifetime()
            .AddClasses(classes => classes.AssignableTo(typeof(ICommandHandler<>)))
                .AsImplementedInterfaces()
                .WithScopedLifetime()
            .AddClasses(classes => classes.AssignableTo(typeof(ICommandHandler<,>)))
                .AsImplementedInterfaces()
                .WithScopedLifetime());

        // v0.4 bootloader client. BaseAddress is set per-call (one client can talk
        // to whichever bootloader the operator points at). 15s timeout, no Polly
        // retry (pairing is user-initiated; on failure the user just clicks Pair
        // again). Cert validation goes through IPinningService (round 6) so
        // pinned hosts verify against the SPKI captured at pairing time, and
        // un-pinned hosts fall back to system trust.
        // Rule 14.2 (2026-09-21): the phone's reads are signed by the delegated
        // poll key. The typed-client factory picks the BootloaderClient ctor
        // that takes IReadSigner once it is registered.
        services.AddSingleton<IReadSigner, PollKeyReadSigner>();

        services.AddHttpClient<IBootloaderClient, BootloaderClient>(client =>
        {
            client.Timeout = TimeSpan.FromSeconds(15);
            client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        })
        .ConfigurePrimaryHttpMessageHandler(provider =>
        {
            var pinning = provider.GetRequiredService<IPinningService>();
            var handler = new HttpClientHandler();
            handler.ServerCertificateCustomValidationCallback = (req, cert, chain, errors) =>
            {
                if (cert is null || req.RequestUri is null)
                {
                    return false;
                }
                var host = req.RequestUri.Host;
                var actualSpki = CertPinHelpers.ComputeSpkiPin(cert);
                return pinning.Validate(host, actualSpki, errors == SslPolicyErrors.None);
            };
            return handler;
        })
        // Android's platform handler makes a new set of TLS objects for every
        // request once a validation callback is set, and leaves their release
        // to the collector. Those requests run every few seconds, so there the
        // collector is run on a count of requests. The handler above is the
        // same on every platform and judges every request.
        .AddHttpMessageHandler(() => new RequestCountCollectionHandler(
            OperatingSystem.IsAndroid() ? RequestCountCollectionHandler.DefaultRequestsPerCollection : 0));

        return services;
    }
}

/// <summary>
/// Runs a full garbage collection after every <c>requestsPerCollection</c>
/// requests that pass through it, whether they succeeded or failed. It never
/// touches a request or a response. With a count of zero it does nothing.
/// <para>
/// The collection is queued to a pool thread, never run on the caller's: a
/// request may complete on the UI thread. At most one collection is queued or
/// running at a time; a count reached while one is outstanding is skipped.
/// Nothing the collection or its queueing does reaches the request: a fault
/// there is dropped, and the request's own response or exception stands.
/// </para>
/// </summary>
internal sealed class RequestCountCollectionHandler : DelegatingHandler
{
    /// <summary>One collection a minute at one request every three seconds.</summary>
    internal const int DefaultRequestsPerCollection = 20;

    private readonly int _requestsPerCollection;
    private readonly Action _collect;
    private readonly Action<Action> _queue;
    private int _requests;
    private int _outstanding;

    /// <param name="requestsPerCollection">Requests between collections; zero for none.</param>
    /// <param name="collect">The collection itself; a full garbage collection when null.</param>
    /// <param name="queue">Runs the collection off the caller's thread; the thread pool when null.</param>
    internal RequestCountCollectionHandler(
        int requestsPerCollection, Action? collect = null, Action<Action>? queue = null)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(requestsPerCollection);
        _requestsPerCollection = requestsPerCollection;
        _collect = collect ?? CollectFully;
        _queue = queue ?? QueueToPool;
    }

    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request, CancellationToken cancellationToken)
    {
        try
        {
            return await base.SendAsync(request, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            CountRequest();
        }
    }

    /// <summary>Counts one request and, on the count, queues a collection. Never throws.</summary>
    private void CountRequest()
    {
        if (_requestsPerCollection == 0
            || Interlocked.Increment(ref _requests) % _requestsPerCollection != 0)
        {
            return;
        }
        // One at a time: taken here, given back when the queued collection ends.
        if (Interlocked.Exchange(ref _outstanding, 1) == 1)
        {
            return;
        }
        try
        {
            _queue(RunCollection);
        }
        catch
        {
            // Not queued, so nothing will give it back.
            Volatile.Write(ref _outstanding, 0);
        }
    }

    private void RunCollection()
    {
        try
        {
            _collect();
        }
        catch
        {
            // A collection that faults is dropped; the next count tries again.
        }
        finally
        {
            Volatile.Write(ref _outstanding, 0);
        }
    }

    private static void QueueToPool(Action work)
        => ThreadPool.QueueUserWorkItem(static state => ((Action)state!)(), work);

    private static void CollectFully()
    {
        // Twice around finalization: an object released by a finalizer is
        // collected by the second pass.
        GC.Collect();
        GC.WaitForPendingFinalizers();
        GC.Collect();
    }
}
