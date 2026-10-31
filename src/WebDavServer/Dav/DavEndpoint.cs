using System.Net;
using System.Xml;
using System.Xml.Linq;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Strongthium.WebDavServer.Network;
using Strongthium.WebDavServer.Nextcloud;
using Strongthium.WebDavServer.Security;
using Strongthium.WebDavServer.Storage;
using static Strongthium.WebDavServer.Dav.DavXml;

namespace Strongthium.WebDavServer.Dav;

/// <summary>What came of a login.</summary>
public enum LoginOutcome
{
    Accepted,
    Refused,
    Busy,

    /// <summary>The connection has been cut: there's nothing more to say to this client.</summary>
    Dropped,
}

/// <summary>
/// The way every WebDAV and Nextcloud request comes in, in the order that matters: who is this really, are they banned or
/// outside the whitelist, is the connection fit for a password, have they logged in, and only then, what do they want.
/// </summary>
public sealed class DavEndpoint(ServerState state, Guard guard, ConnectionGate gate, Authenticator authenticator, DavHandler handler, NextcloudEndpoint nextcloud)
{
    private const string Realm = "webdav-server";
    private readonly System.Collections.Concurrent.ConcurrentDictionary<(string, string), DateTimeOffset> noticed = new();
    private int warnedAboutProxy;

    /// <summary>A proxy seems to be in front of the server, but isn't trusted: every client looks like the proxy.</summary>
    public IPAddress? UntrustedProxySeen { get; private set; }

    public ClientInfo ClientOf(HttpContext context)
    {
        var policy = state.Policy;
        var peer = context.Connection.RemoteIpAddress ?? IPAddress.None;
        var cloudflare = policy.Settings.TrustCloudflare ? state.Cloudflare.Ranges : [];
        return ClientAddress.Resolve(peer, context.Request.IsHttps, context.Request.Headers, context.Request.Host.Value ?? "", policy.TrustedProxies, cloudflare, policy.Settings.ProxyUsesRealIp, policy.Settings.AllowClearFromProxies);
    }

    public async Task InvokeAsync(HttpContext context)
    {
        try
        {
            await RunAsync(context);
        }
        catch (XmlException)
        {
            Answer(context, StatusCodes.Status400BadRequest);
        }
        catch (DavHandler.QuotaExceededException)
        {
            Answer(context, StatusCodes.Status507InsufficientStorage);
        }
        catch (Exception exception) when (exception is FileNotFoundException or DirectoryNotFoundException)
        {
            Answer(context, StatusCodes.Status404NotFound);
        }
        catch (UnauthorizedAccessException)
        {
            Answer(context, StatusCodes.Status403Forbidden);
        }
        catch (IOException exception) when (IsDiskFull(exception))
        {
            Answer(context, StatusCodes.Status507InsufficientStorage);
        }
        catch (IOException) when (!context.RequestAborted.IsCancellationRequested && !context.Response.HasStarted)
        {
            // Mostly: something else has the file open, or it was changed under the request. Trying again is the right response.
            Answer(context, StatusCodes.Status409Conflict);
        }
        catch (OperationCanceledException)
        {
            context.Abort();
        }
    }

    private static void Answer(HttpContext context, int status)
    {
        if (context.Response.HasStarted) context.Abort();
        else context.Response.StatusCode = status;
    }

    private static bool IsDiskFull(IOException exception) => (exception.HResult & 0xFFFF) is 0x70 or 0x27 || exception.HResult == 28;

    private async Task RunAsync(HttpContext context)
    {
        var policy = state.Policy;
        var client = ClientOf(context);
        if (!client.ViaProxy) NoticeUntrustedProxy(context, client);

        // The door has looked at the socket, but a socket can stay open for a long time, and behind a proxy it says nothing
        // of the client. So: again, by the client's real address, for every request.
        if (guard.IsBanned(client.Address, Scopes.All))
        {
            gate.Drop(context, client.ViaProxy);
            return;
        }
        switch (policy.Whitelist.Check(client.Address, state.Geo))
        {
            case AccessVerdict.Denied:
                guard.Ban(client.Address, Scopes.All, WhitelistBan(policy), "Connected from outside the server's whitelist.");
                gate.Drop(context, client.ViaProxy);
                return;
            case AccessVerdict.CannotTell:
                gate.Drop(context, client.ViaProxy);
                return;
        }

        var segments = PathRules.DecodeTarget(context.Features.Get<IHttpRequestFeature>()?.RawTarget ?? "/");
        if (segments is null)
        {
            context.Response.StatusCode = StatusCodes.Status400BadRequest;
            return;
        }
        var prefix = client.PathBase.Split('/', StringSplitOptions.RemoveEmptyEntries);
        if (prefix.Length > 0 && segments.Length >= prefix.Length && segments.Take(prefix.Length).SequenceEqual(prefix)) segments = segments[prefix.Length..];

        var route = Router.Locate(policy, segments);
        if (guard.IsBanned(client.Address, route.Scope))
        {
            gate.Drop(context, client.ViaProxy);
            return;
        }

        SecurityHeaders(context, client);

        // Basic sends the password as good as in the clear, so nobody is asked for one unless the way here is encrypted.
        if (!client.Secure)
        {
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            context.Response.ContentType = "text/plain; charset=utf-8";
            await context.Response.WriteAsync("This server only takes logins over TLS.\n", context.RequestAborted);
            return;
        }

        if (HttpMethods.IsOptions(context.Request.Method) && route.Kind != RouteKind.Nextcloud)
        {
            // Clients ask this before logging in, to see whether this is WebDAV at all.
            Options(context);
            return;
        }

        if (route.Kind == RouteKind.Nextcloud && await nextcloud.TryAnswerWithoutLoginAsync(context, client, route, this)) return;

        var account = await AuthenticateAsync(context, client, route.Scope);
        if (account is null) return;

        switch (route.Kind)
        {
            case RouteKind.Nextcloud:
                if (HttpMethods.IsOptions(context.Request.Method))
                {
                    Options(context);
                    return;
                }
                await nextcloud.AnswerAsync(context, client, route, account, this);
                return;
            case RouteKind.Top:
                await TopAsync(context, client, account);
                return;
            case RouteKind.NotFound:
                context.Response.StatusCode = StatusCodes.Status404NotFound;
                return;
        }

        var (target, status) = Router.Resolve(state, account, segments);
        if (target is null)
        {
            context.Response.StatusCode = status;
            return;
        }
        await handler.HandleAsync(new DavRequest(context, client, account, target));
    }

    /// <summary>A ban from a path holds however the path is reached. Nextcloud's addresses at the top of the server count their
    /// failures there, but lead to an account's home, so once it's known where a request is going, this is asked again. True if
    /// the connection has been cut.</summary>
    public bool DropIfBanned(HttpContext context, ClientInfo client, MountInfo mount)
    {
        if (!guard.IsBanned(client.Address, mount.Path)) return false;
        gate.Drop(context, client.ViaProxy);
        return true;
    }

    /// <summary>Headers for every answer: nothing here is a web page, and nobody but its owner should see it or keep a copy.</summary>
    private static void SecurityHeaders(HttpContext context, ClientInfo client)
    {
        var headers = context.Response.Headers;
        headers.XContentTypeOptions = "nosniff";
        headers.XFrameOptions = "DENY";
        headers["Referrer-Policy"] = "no-referrer";
        headers["X-Robots-Tag"] = "none";
        headers.CacheControl = "private, no-cache";
        headers.ContentSecurityPolicy = "default-src 'none'; sandbox";
        if (client.Scheme == "https") headers.StrictTransportSecurity = "max-age=31536000";
    }

    private static void Options(HttpContext context)
    {
        var headers = context.Response.Headers;
        headers["DAV"] = "1, 2, 3";
        headers["MS-Author-Via"] = "DAV";
        headers.Allow = DavHandler.AllowedMethods;
        context.Response.ContentLength = 0;
    }

    private static TimeSpan WhitelistBan(Policy policy) => TimeSpan.FromMinutes(policy.Settings.WhitelistBanMinutes);

    /// <summary>Logs in from a request's <c>Authorization</c> header. Null if it didn't work, and the request has been answered.</summary>
    public async Task<Account?> AuthenticateAsync(HttpContext context, ClientInfo client, string scope)
    {
        var header = context.Request.Headers.Authorization.ToString();
        if (header.Length == 0)
        {
            Challenge(context);
            return null;
        }
        if (!BasicAuth.TryParse(header, out var name, out var password))
        {
            // Not a login that could ever work, and an attacker can send any number of them: it counts the same.
            if (guard.LoginFailed(client.Address, scope, ""))
            {
                gate.Drop(context, client.ViaProxy);
                return null;
            }
            Challenge(context);
            return null;
        }

        var (outcome, account) = await LoginAsync(context, client, scope, name, password);
        switch (outcome)
        {
            case LoginOutcome.Accepted:
                return account;
            case LoginOutcome.Refused:
                Challenge(context);
                return null;
            case LoginOutcome.Busy:
                context.Response.StatusCode = StatusCodes.Status503ServiceUnavailable;
                context.Response.Headers.RetryAfter = "5";
                return null;
            default:
                return null;
        }
    }

    /// <summary>
    /// Checks a login, in the order the rules want: an account's whitelist comes before its password, since a login from
    /// outside it fails whether or not the password is right, and it costs nothing to find out.
    /// </summary>
    public async Task<(LoginOutcome Outcome, Account? Account)> LoginAsync(HttpContext context, ClientInfo client, string scope, string name, string password)
    {
        var policy = state.Policy;
        if (policy.Accounts.TryGetValue(name, out var named))
        {
            switch (named.Whitelist.Check(client.Address, state.Geo))
            {
                case AccessVerdict.Denied:
                    guard.Ban(client.Address, Scopes.All, WhitelistBan(policy), $"Tried to log in as {named.Name} from outside the account's whitelist.", named.Name);
                    gate.Drop(context, client.ViaProxy);
                    return (LoginOutcome.Dropped, null);
                case AccessVerdict.CannotTell:
                    state.Log("refused", client.Address, named.Name, scope, "The account's whitelist needs DB-IP's database, which isn't there.");
                    gate.Drop(context, client.ViaProxy);
                    return (LoginOutcome.Dropped, null);
            }
        }

        var result = await authenticator.CheckAsync(name, password, context.RequestAborted);
        switch (result.Verdict)
        {
            case LoginVerdict.Busy:
                return (LoginOutcome.Busy, null);
            case LoginVerdict.Refused:
                if (guard.LoginFailed(client.Address, scope, name))
                {
                    gate.Drop(context, client.ViaProxy);
                    return (LoginOutcome.Dropped, null);
                }
                return (LoginOutcome.Refused, null);
        }
        // Many guesses can be running at once when one of them crosses the line: a ban made in the meantime holds for them too.
        if (guard.IsBanned(client.Address, scope) || guard.IsBanned(client.Address, Scopes.All))
        {
            gate.Drop(context, client.ViaProxy);
            return (LoginOutcome.Dropped, null);
        }
        Notice(client.Address, result.Account!.Name, scope);
        context.Items[AppPasswordKey] = result.AppPasswordId;
        return (LoginOutcome.Accepted, result.Account);
    }

    /// <summary>Under which key a request remembers the app password it logged in with, if it did.</summary>
    public const string AppPasswordKey = "webdav-server.app-password";

    /// <summary>A login goes in the log once an hour for each account and address: every request is a login, in WebDAV.</summary>
    private void Notice(IPAddress address, string account, string scope)
    {
        var key = (account, address.ToString());
        var now = state.Clock.GetUtcNow();
        if (noticed.TryGetValue(key, out var last) && now - last < TimeSpan.FromHours(1)) return;
        if (noticed.Count > 50_000) noticed.Clear();
        noticed[key] = now;
        state.Log("login", address, account, scope, "Logged in.");
    }

    private static void Challenge(HttpContext context)
    {
        context.Response.StatusCode = StatusCodes.Status401Unauthorized;
        context.Response.Headers.WWWAuthenticate = $"Basic realm=\"{Realm}\", charset=\"UTF-8\"";
    }

    /// <summary>The server's own address, with no path there: an account sees the paths it may use, and nothing else.</summary>
    private async Task TopAsync(HttpContext context, ClientInfo client, Account account)
    {
        var method = context.Request.Method.ToUpperInvariant();
        if (method is "GET" or "HEAD")
        {
            context.Response.ContentType = "text/plain; charset=utf-8";
            if (method == "GET") await context.Response.WriteAsync("This is a WebDAV server. Connect to one of its paths with a WebDAV or Nextcloud client.\n", context.RequestAborted);
            return;
        }
        if (method != "PROPFIND")
        {
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            return;
        }
        var depth = context.Request.Headers["Depth"].ToString();
        if (depth.Equals("infinity", StringComparison.OrdinalIgnoreCase))
        {
            await WriteErrorAsync(context, StatusCodes.Status403Forbidden, new XElement(D + "propfind-finite-depth"));
            return;
        }
        await ReadAsync(context);

        static XElement Folder(string href, string name) => new(D + "response",
            new XElement(D + "href", href),
            new XElement(D + "propstat",
                new XElement(D + "prop", new XElement(D + "displayname", name), new XElement(D + "resourcetype", new XElement(D + "collection"))),
                DavXml.Status(200)));

        var responses = new List<XElement> { Folder(client.PathBase + "/", "") };
        if (depth != "0")
        {
            var policy = state.Policy;
            foreach (var grant in account.Info.Grants.OrderBy(grant => grant.Mount, StringComparer.Ordinal))
            {
                if (policy.Mounts.TryGetValue(grant.Mount, out var mount) && mount.Enabled && mount.Path != "/")
                    responses.Add(Folder($"{client.PathBase}/{Uri.EscapeDataString(mount.Path[1..])}/", mount.Path[1..]));
            }
        }
        await WriteAsync(context, StatusCodes.Status207MultiStatus, Multistatus(responses));
    }

    /// <summary>Headers that say a proxy is in the way, from an address nobody has said to trust: all its clients would look
    /// like one, and one person's failed logins would ban them all. It's said once, and the admin window shows it.</summary>
    private void NoticeUntrustedProxy(HttpContext context, ClientInfo client)
    {
        if (!context.Request.Headers.ContainsKey("X-Forwarded-For") && !context.Request.Headers.ContainsKey("CF-Connecting-IP")) return;
        UntrustedProxySeen = client.Peer;
        if (Interlocked.Exchange(ref warnedAboutProxy, 1) == 0)
            state.Log("warning", client.Peer, "", "", "Proxy headers came from an address that isn't a trusted proxy, and were ignored. If this is your proxy, add it to the trusted proxies.");
    }
}
