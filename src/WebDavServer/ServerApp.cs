using System.Net;
using System.Net.Security;
using System.Security.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Strongthium.WebDavServer.Admin;
using Strongthium.WebDavServer.Config;
using Strongthium.WebDavServer.Dav;
using Strongthium.WebDavServer.Network;
using Strongthium.WebDavServer.Nextcloud;
using Strongthium.WebDavServer.Security;

namespace Strongthium.WebDavServer;

/// <summary>The server, put together and listening.</summary>
public sealed class ServerApp : IAsyncDisposable
{
    private readonly WebApplication app;
    private readonly List<(ListenOptions Options, ListenerKind Kind, bool Tls)> listeners;
    private readonly CancellationTokenSource stopping = new();
    private readonly Task housekeeping;
    private readonly HttpClient http;

    public ServerState State { get; }
    public Guard Guard { get; }
    public ConnectionGate Gate { get; }
    public TlsCertificates DavCertificate { get; }
    public TlsCertificates AdminCertificate { get; }

    private ServerApp(WebApplication app, List<(ListenOptions, ListenerKind, bool)> listeners, ServerState state, Guard guard, ConnectionGate gate, TlsCertificates davCertificate, TlsCertificates adminCertificate, HttpClient http)
    {
        this.app = app;
        this.listeners = listeners;
        this.http = http;
        State = state;
        Guard = guard;
        Gate = gate;
        DavCertificate = davCertificate;
        AdminCertificate = adminCertificate;
        housekeeping = Task.Run(HousekeepingAsync);
    }

    /// <summary>The WebDAV addresses, with the ports they really got.</summary>
    public IReadOnlyList<string> DavAddresses => [.. listeners.Where(listener => listener.Kind == ListenerKind.Dav).Select(Address)];
    public string AdminAddress => listeners.Where(listener => listener.Kind == ListenerKind.Admin).Select(Address).First();

    private static string Address((ListenOptions Options, ListenerKind Kind, bool Tls) listener)
    {
        var endPoint = listener.Options.IPEndPoint!;
        var host = endPoint.Address.Equals(IPAddress.Any) || endPoint.Address.Equals(IPAddress.IPv6Any) ? "localhost" : endPoint.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 ? $"[{endPoint.Address}]" : endPoint.Address.ToString();
        return $"{(listener.Tls ? "https" : "http")}://{host}:{endPoint.Port}";
    }

    public static ServerApp Build(string dataFolder, ServerConfig config, Action<WebApplicationBuilder>? configure = null, TimeProvider? clock = null)
    {
        DataFolder.Prepare(dataFolder);
        var state = new ServerState(dataFolder, clock);
        var guard = new Guard(state);
        var gate = new ConnectionGate(state, guard);
        var authenticator = new Authenticator(state);
        var locks = new LockManager(state.Clock);
        var handler = new DavHandler(state, locks, guard);
        var nextcloud = new NextcloudEndpoint(state, handler);
        var endpoint = new DavEndpoint(state, guard, gate, authenticator, handler, nextcloud);
        var davCertificate = new TlsCertificates(config.CertificateFile, config.KeyFile, dataFolder, "webdav");
        var adminCertificate = new TlsCertificates("", "", dataFolder, "admin");
        state.Geo.Load();

        var builder = WebApplication.CreateSlimBuilder();
        builder.Logging.ClearProviders();
        builder.Logging.AddSimpleConsole(options => options.SingleLine = true);
        builder.Logging.SetMinimumLevel(LogLevel.Warning);
        builder.Logging.AddFilter("Microsoft.AspNetCore.Server.Kestrel", LogLevel.Error);
        builder.Logging.AddFilter("WebDavServer", LogLevel.Information);
        builder.WebHost.UseKestrelHttpsConfiguration();
        if (OperatingSystem.IsWindows()) builder.Host.UseWindowsService(options => options.ServiceName = "webdav-server");
        configure?.Invoke(builder);

        var listeners = new List<(ListenOptions, ListenerKind, bool)>();
        builder.WebHost.ConfigureKestrel(kestrel =>
        {
            kestrel.AddServerHeader = false;
            kestrel.AllowSynchronousIO = false;
            kestrel.Limits.MaxConcurrentConnections = config.MaxConnections;
            kestrel.Limits.MaxRequestBodySize = DavXml.MaxRequestBytes;
            kestrel.Limits.MaxRequestHeadersTotalSize = 32 * 1024;
            kestrel.Limits.MaxRequestLineSize = 16 * 1024;
            kestrel.Limits.RequestHeadersTimeout = TimeSpan.FromSeconds(20);
            kestrel.Limits.KeepAliveTimeout = TimeSpan.FromSeconds(120);
            kestrel.Limits.Http2.MaxStreamsPerConnection = 64;

            void Listen(ListenerConfig listener, ListenerKind kind, TlsCertificates? certificate)
            {
                void Configure(ListenOptions options)
                {
                    // Before TLS: the door costs nothing, and a handshake isn't paid for on behalf of someone who's banned.
                    options.Use(next => connection => gate.OnConnectionAsync(connection, kind, next));
                    options.Protocols = certificate is null ? HttpProtocols.Http1 : HttpProtocols.Http1AndHttp2;
                    if (certificate is not null)
                    {
                        options.UseHttps(new HttpsConnectionAdapterOptions
                        {
                            ServerCertificateSelector = (_, _) => certificate.Current(),
                            SslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                            HandshakeTimeout = TimeSpan.FromSeconds(10),
                            OnAuthenticate = (_, ssl) => { if (Ciphers is { } ciphers) ssl.CipherSuitesPolicy = ciphers; },
                        });
                    }
                    listeners.Add((options, kind, certificate is not null));
                }

                if (listener.Address is "*" or "") kestrel.ListenAnyIP(listener.Port, Configure);
                else if (listener.Address == "localhost") kestrel.ListenLocalhost(listener.Port, Configure);
                else kestrel.Listen(IPAddress.Parse(listener.Address), listener.Port, Configure);
            }

            foreach (var listener in config.Listen) Listen(listener, ListenerKind.Dav, listener.Tls ? davCertificate : null);
            Listen(config.Admin, ListenerKind.Admin, adminCertificate);
        });

        var application = builder.Build();
        var http = Updater.NewClient("webdav-server");
        ServerApp? self = null;
        var admin = new AdminApi(state, guard, gate, authenticator, endpoint, config, davCertificate,
            () => self?.DavAddresses ?? [], () => self?.AdminAddress ?? "",
            cancel => state.Geo.UpdateAsync(http, cancel), cancel => state.Cloudflare.UpdateAsync(http, cancel));

        // One program, two ports, and which one a request came in on decides everything: files are never served on the admin
        // port, and nothing of the admin's can be reached on the file ports.
        application.Run(context => gate.KindOf(context) switch
        {
            ListenerKind.Admin => admin.InvokeAsync(context),
            ListenerKind.Dav => endpoint.InvokeAsync(context),
            _ => Abort(context),
        });

        self = new ServerApp(application, listeners, state, guard, gate, davCertificate, adminCertificate, http);
        return self;
    }

    private static Task Abort(HttpContext context)
    {
        context.Abort();
        return Task.CompletedTask;
    }

    /// <summary>On systems where it can be chosen: the suites with forward secrecy and authenticated encryption, and no others.
    /// On Windows, it's the system's own TLS settings that decide.</summary>
    private static CipherSuitesPolicy? Ciphers { get; } = OperatingSystem.IsLinux()
        ? new CipherSuitesPolicy(
        [
            TlsCipherSuite.TLS_AES_256_GCM_SHA384,
            TlsCipherSuite.TLS_AES_128_GCM_SHA256,
            TlsCipherSuite.TLS_CHACHA20_POLY1305_SHA256,
            TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            TlsCipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
            TlsCipherSuite.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            TlsCipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        ])
        : null;

    public Task StartAsync(CancellationToken cancel = default) => app.StartAsync(cancel);

    /// <summary>Waits until the server is told to stop, by Ctrl+C, systemd or the Windows service manager, then stops it.</summary>
    public async Task WaitForShutdownAsync() => await app.WaitForShutdownAsync();

    /// <summary>What goes on in the background: forgetting what's expired, trimming the log, and, only when they're in use,
    /// keeping DB-IP's files and Cloudflare's addresses up to date.</summary>
    private async Task HousekeepingAsync()
    {
        var nextDaily = DateTimeOffset.MinValue;
        using var timer = new PeriodicTimer(TimeSpan.FromMinutes(5));
        try
        {
            do
            {
                try
                {
                    Guard.Sweep();
                    if (DateTimeOffset.UtcNow >= nextDaily)
                    {
                        nextDaily = DateTimeOffset.UtcNow.AddDays(1);
                        State.Database.TrimLog(DateTimeOffset.UtcNow.AddDays(-90));
                        await UpdateFromOutsideAsync();
                    }
                }
                catch (Exception exception) when (exception is not OperationCanceledException)
                {
                    State.LogLine?.Invoke($"warning Housekeeping failed: {exception.Message}");
                }
            }
            while (await timer.WaitForNextTickAsync(stopping.Token));
        }
        catch (OperationCanceledException)
        {
            // It's stopping.
        }
    }

    private async Task UpdateFromOutsideAsync()
    {
        var policy = State.Policy;
        var usesPlaces = policy.Whitelist.NeedsPlaces || policy.AdminWhitelist.NeedsPlaces || policy.Accounts.Values.Any(account => account.Whitelist.NeedsPlaces);
        if (usesPlaces && policy.Settings.GeoAutoUpdate)
        {
            try
            {
                await State.Geo.UpdateAsync(http, stopping.Token);
            }
            catch (Exception exception) when (exception is HttpRequestException or IOException or InvalidOperationException or TaskCanceledException)
            {
                State.Log("warning", null, "", "", $"DB-IP's files couldn't be downloaded: {exception.Message}");
            }
        }
        if (policy.Settings.TrustCloudflare)
        {
            try
            {
                await State.Cloudflare.UpdateAsync(http, stopping.Token);
            }
            catch (Exception exception) when (exception is HttpRequestException or IOException or InvalidDataException or TaskCanceledException)
            {
                State.Log("warning", null, "", "", $"Cloudflare's addresses couldn't be downloaded: {exception.Message}");
            }
        }
    }

    public async ValueTask DisposeAsync()
    {
        stopping.Cancel();
        await housekeeping;
        await app.StopAsync();
        await app.DisposeAsync();
        http.Dispose();
    }
}
