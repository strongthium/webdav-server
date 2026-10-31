using System.Collections.Concurrent;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Xml.Linq;
using Microsoft.AspNetCore.Http;
using Strongthium.WebDavServer.Dav;
using Strongthium.WebDavServer.Network;
using Strongthium.WebDavServer.Security;
using Strongthium.WebDavServer.Storage;
using static Strongthium.WebDavServer.Dav.DavXml;

namespace Strongthium.WebDavServer.Nextcloud;

/// <summary>
/// What a Nextcloud client expects of a server, on top of WebDAV: <c>status.php</c>, the login flow that gives it an app
/// password, the OCS calls for the capabilities and the user, and chunked uploads. Files themselves go through
/// <see cref="DavHandler"/> like everyone else's, so they're the same files, with the same locks and tags.
/// </summary>
public sealed class NextcloudEndpoint(ServerState state, DavHandler handler)
{
    private const string ReportedVersion = "31.0.0";

    private sealed class Flow
    {
        public required string PollToken { get; init; }
        public required string LoginToken { get; init; }
        public required string Client { get; init; }
        public required DateTimeOffset Expires { get; init; }
        public required string Scope { get; init; }
        public required string Prefix { get; init; }
        public required IPAddress Address { get; init; }
        public string? LoginName { get; set; }
        public string? AppPassword { get; set; }
    }

    private static readonly TimeSpan FlowLifetime = TimeSpan.FromMinutes(20);
    private const int MaxFlows = 2000, MaxFlowsPerAddress = 16;
    private readonly ConcurrentDictionary<string, Flow> flowsByLogin = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, Flow> flowsByPoll = new(StringComparer.Ordinal);

    private DateTimeOffset Now => state.Clock.GetUtcNow();

    /// <summary>The address clients know this server by, for what's sent back to them to use later.</summary>
    private string BaseUrl(ClientInfo client, DavRoute route)
    {
        var configured = state.Policy.Settings.PublicUrl.TrimEnd('/');
        var root = configured.Length > 0 ? configured : $"{client.Scheme}://{client.Host}{client.PathBase}";
        return root + (route.Mount?.Path ?? "");
    }

    /// <summary>What's answered to anyone: true if this was one of those.</summary>
    public async Task<bool> TryAnswerWithoutLoginAsync(HttpContext context, ClientInfo client, DavRoute route, DavEndpoint endpoint)
    {
        var method = context.Request.Method.ToUpperInvariant();
        switch (route.Rest)
        {
            case ["status.php"] when method is "GET" or "HEAD":
                await JsonAsync(context, new JsonObject
                {
                    ["installed"] = true,
                    ["maintenance"] = false,
                    ["needsDbUpgrade"] = false,
                    ["version"] = ReportedVersion + ".0",
                    ["versionstring"] = ReportedVersion,
                    ["edition"] = "",
                    ["productname"] = "webdav-server",
                    ["extendedSupport"] = false,
                });
                return true;

            case ["index.php", "204"]:
                context.Response.StatusCode = StatusCodes.Status204NoContent;
                return true;

            case ["ocs", _, "cloud", "capabilities"] when method == "GET":
                await OcsAsync(context, route.Rest[1], Capabilities());
                return true;

            case ["index.php", "login", "v2"] when method == "POST":
                await StartFlowAsync(context, client, route);
                return true;

            case ["index.php", "login", "v2", "poll"] when method == "POST":
                await PollFlowAsync(context, client);
                return true;

            case ["index.php", "login", "v2", "flow", var token]:
                await LoginPageAsync(context, client, route, endpoint, token, legacy: false);
                return true;

            case ["index.php", "login", "flow"]:
                await LoginPageAsync(context, client, route, endpoint, null, legacy: true);
                return true;

            case ["ocs-provider", ..] or ["ocm-provider", ..]:
                context.Response.StatusCode = StatusCodes.Status404NotFound;
                return true;
        }
        return false;
    }

    public async Task AnswerAsync(HttpContext context, ClientInfo client, DavRoute route, Account account, DavEndpoint endpoint)
    {
        var method = context.Request.Method.ToUpperInvariant();
        switch (route.Rest)
        {
            case ["remote.php", "dav", "uploads", var user, .. var rest]:
                if (!user.Equals(account.Name, StringComparison.OrdinalIgnoreCase))
                {
                    context.Response.StatusCode = StatusCodes.Status403Forbidden;
                    return;
                }
                await UploadsAsync(context, client, route, account, rest, endpoint);
                return;

            case ["remote.php", "webdav", ..] or ["remote.php", "dav", "files", _, ..]:
                string[] segments = route.Mount is null ? route.Rest : [route.Mount.Path[1..], .. route.Rest];
                var (target, status) = Router.Resolve(state, account, segments);
                if (target is null)
                {
                    context.Response.StatusCode = status;
                    return;
                }
                if (endpoint.DropIfBanned(context, client, target.Mount)) return;
                await handler.HandleAsync(new DavRequest(context, client, account, target));
                return;

            case ["ocs", _, "cloud", "user"] when method == "GET":
            case ["ocs", _, "cloud", "users", _] when method == "GET":
                await OcsAsync(context, route.Rest[1], UserInfo(account, route));
                return;

            case ["ocs", _, "core", "getapppassword"] when method == "GET":
                await GetAppPasswordAsync(context, route, account);
                return;

            case ["ocs", _, "core", "apppassword"] when method == "DELETE":
                await DeleteAppPasswordAsync(context, route, account);
                return;

            case ["ocs", _, ..]:
                // Notifications, sharing, activity and the rest: not here. Clients ask, and carry on.
                await OcsAsync(context, route.Rest[1], null, statusCode: StatusCodes.Status404NotFound, ocsStatus: 998);
                return;
        }
        context.Response.StatusCode = StatusCodes.Status404NotFound;
    }

    // ---- JSON and OCS --------------------------------------------------------------------------------------------

    private static async Task JsonAsync(HttpContext context, JsonNode node, int status = StatusCodes.Status200OK)
    {
        context.Response.StatusCode = status;
        context.Response.ContentType = "application/json; charset=utf-8";
        if (!HttpMethods.IsHead(context.Request.Method)) await context.Response.WriteAsync(node.ToJsonString(), context.RequestAborted);
    }

    /// <summary>An OCS answer: the same content in JSON or XML, whichever was asked for. Version 1 reports 100 for success, 2
    /// reports 200, as Nextcloud does.</summary>
    private static async Task OcsAsync(HttpContext context, string versionFile, JsonNode? data, int statusCode = StatusCodes.Status200OK, int ocsStatus = 0)
    {
        var v1 = versionFile.StartsWith("v1", StringComparison.OrdinalIgnoreCase);
        var succeeded = statusCode < 300;
        var code = ocsStatus != 0 ? ocsStatus : succeeded ? (v1 ? 100 : 200) : statusCode;
        var document = new JsonObject
        {
            ["ocs"] = new JsonObject
            {
                ["meta"] = new JsonObject { ["status"] = succeeded ? "ok" : "failure", ["statuscode"] = code, ["message"] = succeeded ? "OK" : "" },
                ["data"] = data ?? new JsonArray(),
            },
        };
        var wantsJson = context.Request.Query["format"].ToString().Equals("json", StringComparison.OrdinalIgnoreCase)
            || context.Request.Headers.Accept.ToString().Contains("json", StringComparison.OrdinalIgnoreCase);
        // Version 1 always answers 200, with the real answer inside, as Nextcloud's does.
        context.Response.StatusCode = v1 ? StatusCodes.Status200OK : statusCode;
        if (wantsJson)
        {
            context.Response.ContentType = "application/json; charset=utf-8";
            await context.Response.WriteAsync(document.ToJsonString(), context.RequestAborted);
            return;
        }
        context.Response.ContentType = "text/xml; charset=utf-8";
        var bytes = ToBytes((XElement)ToXml("ocs", document["ocs"]));
        await context.Response.Body.WriteAsync(bytes, context.RequestAborted);
    }

    private static XObject ToXml(string name, JsonNode? node) => node switch
    {
        JsonObject o => new XElement(name, o.Select(pair => ToXml(pair.Key, pair.Value))),
        JsonArray a => new XElement(name, a.Select(item => ToXml("element", item))),
        JsonValue v => new XElement(name, v.ToString()),
        _ => new XElement(name),
    };

    private static JsonObject Capabilities() => new()
    {
        ["version"] = new JsonObject
        {
            ["major"] = 31,
            ["minor"] = 0,
            ["micro"] = 0,
            ["string"] = ReportedVersion,
            ["edition"] = "",
            ["extendedSupport"] = false,
        },
        ["capabilities"] = new JsonObject
        {
            ["core"] = new JsonObject { ["pollinterval"] = 60, ["webdav-root"] = "remote.php/webdav", ["reference-api"] = false },
            ["dav"] = new JsonObject { ["chunking"] = "1.0" },
            ["files"] = new JsonObject { ["bigfilechunking"] = true, ["undelete"] = false, ["versioning"] = false, ["comments"] = false },
            ["files_sharing"] = new JsonObject { ["api_enabled"] = false },
            ["user"] = new JsonObject { ["expire_date"] = new JsonObject { ["enabled"] = false } },
        },
    };

    private JsonObject UserInfo(Account account, DavRoute route)
    {
        var mount = route.Mount ?? state.Policy.HomeOf(account);
        long used = 0, free = 0, total = -3;
        if (mount is not null && account.GrantOn(mount.Path) is not null)
        {
            var space = state.SpaceFor(mount, account);
            used = state.Usage.Get(space);
            if (space.QuotaBytes > 0)
            {
                total = space.QuotaBytes;
                free = Math.Max(0, total - used);
            }
            else
            {
                try
                {
                    free = new DriveInfo(Path.GetPathRoot(space.Root)!).AvailableFreeSpace;
                }
                catch (Exception exception) when (exception is IOException or ArgumentException or UnauthorizedAccessException)
                {
                    free = 0;
                }
            }
        }
        var shown = account.Info.DisplayName.Length > 0 ? account.Info.DisplayName : account.Name;
        return new JsonObject
        {
            ["enabled"] = true,
            ["id"] = account.Name,
            ["display-name"] = shown,
            ["displayname"] = shown,
            ["email"] = null,
            ["lastLogin"] = 0,
            ["backend"] = "webdav-server",
            ["language"] = "en",
            ["locale"] = "",
            ["groups"] = new JsonArray(),
            ["subadmin"] = new JsonArray(),
            ["quota"] = new JsonObject
            {
                ["free"] = free,
                ["used"] = used,
                ["total"] = total > 0 ? total : used + free,
                ["relative"] = total > 0 ? Math.Round(used * 100.0 / total, 2) : 0,
                ["quota"] = total,
            },
            ["backendCapabilities"] = new JsonObject { ["setDisplayName"] = false, ["setPassword"] = false },
        };
    }

    // ---- App passwords -------------------------------------------------------------------------------------------

    /// <summary>Makes an app password for an account. Only its hash is kept.</summary>
    private string NewAppPassword(Account account, string name)
    {
        var password = Passwords.NewAppPassword();
        state.Database.AddAppPassword(account.Name, name.Length > 200 ? name[..200] : name, Passwords.HashAppPassword(password), Now);
        state.Reload();
        state.Log("app-password", null, account.Name, "", $"App password made for {name}.");
        return password;
    }

    private async Task GetAppPasswordAsync(HttpContext context, DavRoute route, Account account)
    {
        // An app password can't make another: if one leaks, it mustn't be able to outlive being revoked.
        if (context.Items[DavEndpoint.AppPasswordKey] is long)
        {
            await OcsAsync(context, route.Rest[1], null, StatusCodes.Status403Forbidden);
            return;
        }
        await OcsAsync(context, route.Rest[1], new JsonObject { ["apppassword"] = NewAppPassword(account, ClientName(context)) });
    }

    private async Task DeleteAppPasswordAsync(HttpContext context, DavRoute route, Account account)
    {
        if (context.Items[DavEndpoint.AppPasswordKey] is not long id)
        {
            await OcsAsync(context, route.Rest[1], null, StatusCodes.Status403Forbidden);
            return;
        }
        state.Database.DeleteAppPassword(account.Name, id);
        state.Reload();
        state.Log("app-password", null, account.Name, "", "A client logged out, and its app password went with it.");
        await OcsAsync(context, route.Rest[1], new JsonArray());
    }

    private static string ClientName(HttpContext context)
    {
        var agent = context.Request.Headers.UserAgent.ToString();
        var clean = new string([.. agent.Where(c => !char.IsControl(c))]);
        return clean.Length == 0 ? "Nextcloud client" : clean.Length > 120 ? clean[..120] : clean;
    }

    // ---- Login flow ----------------------------------------------------------------------------------------------

    private async Task StartFlowAsync(HttpContext context, ClientInfo client, DavRoute route)
    {
        SweepFlows();
        // Anyone can ask to start one without logging in, so nobody gets to take them all and keep everyone else from logging in.
        if (flowsByLogin.Count >= MaxFlows || flowsByLogin.Values.Count(flow => flow.Address.Equals(client.Address)) >= MaxFlowsPerAddress)
        {
            context.Response.StatusCode = StatusCodes.Status503ServiceUnavailable;
            return;
        }
        var flow = new Flow
        {
            PollToken = RandomToken(),
            LoginToken = RandomToken(),
            Client = ClientName(context),
            Expires = Now + FlowLifetime,
            Scope = route.Scope,
            Prefix = route.Mount?.Path ?? "",
            Address = client.Address,
        };
        flowsByLogin[flow.LoginToken] = flow;
        flowsByPoll[flow.PollToken] = flow;
        var root = BaseUrl(client, route);
        await JsonAsync(context, new JsonObject
        {
            ["poll"] = new JsonObject { ["token"] = flow.PollToken, ["endpoint"] = $"{root}/index.php/login/v2/poll" },
            ["login"] = $"{root}/index.php/login/v2/flow/{flow.LoginToken}",
        });
    }

    private async Task PollFlowAsync(HttpContext context, ClientInfo client)
    {
        var form = context.Request.HasFormContentType ? await context.Request.ReadFormAsync(context.RequestAborted) : null;
        var token = form?["token"].ToString() ?? "";
        if (!flowsByPoll.TryGetValue(token, out var flow) || flow.Expires <= Now || flow.AppPassword is null)
        {
            context.Response.StatusCode = StatusCodes.Status404NotFound;
            return;
        }
        // Handed over once, then forgotten.
        flowsByPoll.TryRemove(token, out _);
        flowsByLogin.TryRemove(flow.LoginToken, out _);
        var configured = state.Policy.Settings.PublicUrl.TrimEnd('/');
        var server = (configured.Length > 0 ? configured : $"{client.Scheme}://{client.Host}{client.PathBase}") + flow.Prefix;
        await JsonAsync(context, new JsonObject { ["server"] = server, ["loginName"] = flow.LoginName, ["appPassword"] = flow.AppPassword });
    }

    private void SweepFlows()
    {
        var now = Now;
        foreach (var (key, flow) in flowsByLogin)
        {
            if (flow.Expires > now) continue;
            flowsByLogin.TryRemove(key, out _);
            flowsByPoll.TryRemove(flow.PollToken, out _);
        }
    }

    private static string RandomToken() => Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(32));

    /// <summary>
    /// The page the client opens in a browser. It's the one place here where a browser is meant to come, so it's small, with
    /// nothing from elsewhere, and only what its own nonce allows may run or style it. What's given to the client is an app
    /// password, never the password typed here. It says plainly what's being given and to whom, because someone who sends you
    /// a link to this page is trying to get a password for your files.
    /// </summary>
    private async Task LoginPageAsync(HttpContext context, ClientInfo client, DavRoute route, DavEndpoint endpoint, string? token, bool legacy)
    {
        Flow? flow = null;
        if (!legacy && (token is null || !flowsByLogin.TryGetValue(token, out flow) || flow.Expires <= Now || flow.AppPassword is not null))
        {
            await PageAsync(context, "This login has expired", "<p>Start again from your client.</p>", StatusCodes.Status404NotFound);
            return;
        }
        var clientName = flow?.Client ?? ClientName(context);

        if (HttpMethods.IsPost(context.Request.Method))
        {
            // A web page anywhere can make a visitor's browser post here. It couldn't log in, but a failed login counts against
            // the visitor's address, so a page could get them banned. Browsers say where a post comes from, and pages can't change that.
            if (CameFromElsewhere(context, client))
            {
                await PageAsync(context, "This login has to be started from here", "<p>Start again from your client.</p>", StatusCodes.Status403Forbidden);
                return;
            }
            if (!context.Request.HasFormContentType)
            {
                context.Response.StatusCode = StatusCodes.Status415UnsupportedMediaType;
                return;
            }
            var form = await context.Request.ReadFormAsync(context.RequestAborted);
            var name = form["user"].ToString().Trim();
            var password = form["password"].ToString();
            if (name.Length is 0 or > 256 || password.Length is 0 or > 1024)
            {
                await LoginFormAsync(context, clientName, "Enter a name and a password.");
                return;
            }
            var (outcome, account) = await endpoint.LoginAsync(context, client, route.Scope, name, password);
            switch (outcome)
            {
                case LoginOutcome.Dropped:
                    return;
                case LoginOutcome.Busy:
                    await LoginFormAsync(context, clientName, "The server is busy. Try again in a moment.");
                    return;
                case LoginOutcome.Refused:
                    await LoginFormAsync(context, clientName, "That name or password isn't right.");
                    return;
            }

            // Logging in with an app password gets that same one back. If it made a new one, a leaked app password could outlive being taken away.
            var appPassword = context.Items[DavEndpoint.AppPasswordKey] is long ? password : NewAppPassword(account!, clientName);
            if (legacy)
            {
                var server = BaseUrl(client, route);
                context.Response.StatusCode = StatusCodes.Status303SeeOther;
                context.Response.Headers.Location = $"nc://login/server:{server}&user:{Uri.EscapeDataString(account!.Name)}&password:{appPassword}";
                return;
            }
            flow!.LoginName = account!.Name;
            flow.AppPassword = appPassword;
            await PageAsync(context, "Connected", "<p>You can close this window and go back to your client.</p>");
            return;
        }
        await LoginFormAsync(context, clientName, null);
    }

    private bool CameFromElsewhere(HttpContext context, ClientInfo client)
    {
        var site = context.Request.Headers["Sec-Fetch-Site"].ToString();
        if (site.Length > 0) return site is not ("same-origin" or "none");
        var origin = context.Request.Headers.Origin.ToString();
        if (origin.Length == 0) return false;
        if (!Uri.TryCreate(origin, UriKind.Absolute, out var from)) return true;
        var configured = Uri.TryCreate(state.Policy.Settings.PublicUrl, UriKind.Absolute, out var url) ? url.Host : "";
        var host = client.Host.StartsWith('[') ? client.Host[1..client.Host.IndexOf(']')] : client.Host.Split(':')[0];
        return !from.Host.Equals(host, StringComparison.OrdinalIgnoreCase) && !from.Host.Equals(configured, StringComparison.OrdinalIgnoreCase);
    }

    private static Task LoginFormAsync(HttpContext context, string clientName, string? error)
    {
        var body = new StringBuilder();
        if (error is not null) body.Append("<p class=\"error\" role=\"alert\">").Append(WebUtility.HtmlEncode(error)).Append("</p>");
        body.Append("<p>Connecting <b>").Append(WebUtility.HtmlEncode(clientName)).Append("</b> to your files. It will be able to read and change them until you take its password away.</p>");
        body.Append("<p class=\"warn\">Only go on if you started this yourself, in your own client. If someone sent you this link, close this page.</p>");
        body.Append("""
            <form method="post" autocomplete="on">
              <label for="user">Name</label>
              <input id="user" name="user" autocomplete="username" autocapitalize="none" autofocus required maxlength="256">
              <label for="password">Password</label>
              <input id="password" name="password" type="password" autocomplete="current-password" required maxlength="1024">
              <button type="submit">Connect</button>
            </form>
            """);
        return PageAsync(context, "Connect a client", body.ToString(), StatusCodes.Status200OK);
    }

    private static async Task PageAsync(HttpContext context, string title, string body, int status = StatusCodes.Status200OK)
    {
        var nonce = Convert.ToBase64String(RandomNumberGenerator.GetBytes(16));
        context.Response.StatusCode = status;
        context.Response.ContentType = "text/html; charset=utf-8";
        // form-action lets the older login flow go on to the app that asked; the rest allows nothing but this page's own style.
        context.Response.Headers.ContentSecurityPolicy = $"default-src 'none'; style-src 'nonce-{nonce}'; form-action 'self' nc:; base-uri 'none'; frame-ancestors 'none'";
        await context.Response.WriteAsync($$"""
            <!doctype html>
            <html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
            <meta name="robots" content="none"><title>{{WebUtility.HtmlEncode(title)}}</title>
            <style nonce="{{nonce}}">
            :root { color-scheme: light dark; --bg: #f4f5f7; --card: #fff; --text: #1b1d21; --muted: #5d6470; --line: #d5d9e0; --accent: #4f6bf5; --error: #b3261e; }
            @media (prefers-color-scheme: dark) { :root { --bg: #15171b; --card: #1f2228; --text: #eceef2; --muted: #a3aab5; --line: #363b44; --accent: #8199ff; --error: #f2b8b5; } }
            body { margin: 0; min-height: 100vh; display: grid; place-items: center; background: var(--bg); color: var(--text); font: 16px/1.5 system-ui, sans-serif; padding: 16px; box-sizing: border-box; }
            main { background: var(--card); border: 1px solid var(--line); border-radius: 8px; padding: 24px; width: 100%; max-width: 400px; box-sizing: border-box; }
            h1 { font-size: 22px; margin: 0 0 12px; } p { margin: 0 0 12px; } .warn { color: var(--muted); font-size: 14px; } .error { color: var(--error); font-weight: 600; }
            label { display: block; font-weight: 600; margin: 12px 0 4px; } input { width: 100%; box-sizing: border-box; padding: 9px 10px; font: inherit; color: inherit; background: transparent; border: 1px solid var(--line); border-radius: 6px; }
            button { margin-top: 16px; width: 100%; padding: 10px; font: inherit; font-weight: 600; color: var(--card); background: var(--accent); border: 0; border-radius: 6px; cursor: pointer; }
            </style></head><body><main><h1>{{WebUtility.HtmlEncode(title)}}</h1>{{body}}</main></body></html>
            """, context.RequestAborted);
    }

    // ---- Chunked uploads -----------------------------------------------------------------------------------------

    private static bool IsSafeUploadName(string name) =>
        name.Length is > 0 and <= 128 && name.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_' or '.') && PathRules.IsValidSegment(name);

    /// <summary>
    /// Nextcloud's chunked upload (version 2): a client makes a folder under <c>/remote.php/dav/uploads/&lt;user&gt;/</c>, puts
    /// numbered chunks in it, then moves <c>.file</c> to where the file is to go. It's what gets a big file past a proxy that
    /// limits the size of a request, which Cloudflare does. Chunks count against the quota from the start, and they're kept
    /// in the server's own folder in the space, out of every client's sight.
    /// </summary>
    private async Task UploadsAsync(HttpContext context, ClientInfo client, DavRoute route, Account account, string[] rest, DavEndpoint endpoint)
    {
        var method = context.Request.Method.ToUpperInvariant();
        var mount = route.Mount ?? state.Policy.HomeOf(account);
        if (mount is null || account.GrantOn(mount.Path) is not { ReadOnly: false })
        {
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            return;
        }
        if (endpoint.DropIfBanned(context, client, mount)) return;
        var space = state.SpaceFor(mount, account);
        var uploads = space.UploadsFolder(account.Name);
        if (rest.Length == 0)
        {
            context.Response.StatusCode = method == "PROPFIND" ? StatusCodes.Status207MultiStatus : StatusCodes.Status405MethodNotAllowed;
            if (method == "PROPFIND") await WriteAsync(context, StatusCodes.Status207MultiStatus, Multistatus([]));
            return;
        }
        if (rest.Length > 2 || !rest.All(IsSafeUploadName))
        {
            context.Response.StatusCode = StatusCodes.Status400BadRequest;
            return;
        }
        var folder = Path.Combine(uploads, rest[0]);
        switch (method, rest.Length)
        {
            case ("MKCOL", 1):
                if (Directory.Exists(folder))
                {
                    context.Response.StatusCode = StatusCodes.Status405MethodNotAllowed;
                    return;
                }
                Directory.CreateDirectory(folder);
                context.Response.StatusCode = StatusCodes.Status201Created;
                return;

            case ("PROPFIND", 1):
                await ListUploadAsync(context, client, route, account, folder, rest[0]);
                return;

            case ("DELETE", 1):
                if (Directory.Exists(folder)) Directory.Delete(folder, recursive: true);
                context.Response.StatusCode = StatusCodes.Status204NoContent;
                return;

            case ("PUT", 2):
                await PutChunkAsync(context, space, folder, rest[1]);
                return;

            case ("DELETE", 2):
                DavHandler.TryDelete(Path.Combine(folder, rest[1]));
                context.Response.StatusCode = StatusCodes.Status204NoContent;
                return;

            case ("MOVE", 2) when rest[1] == ".file":
                await FinishUploadAsync(context, client, account, folder, endpoint);
                return;
        }
        context.Response.StatusCode = StatusCodes.Status405MethodNotAllowed;
    }

    private async Task ListUploadAsync(HttpContext context, ClientInfo client, DavRoute route, Account account, string folder, string id)
    {
        await ReadAsync(context);
        if (!Directory.Exists(folder))
        {
            context.Response.StatusCode = StatusCodes.Status404NotFound;
            return;
        }
        var baseHref = $"{client.PathBase}{route.Mount?.Path}/remote.php/dav/uploads/{Uri.EscapeDataString(account.Name)}/{id}/";
        var responses = new List<XElement>
        {
            new(D + "response", new XElement(D + "href", baseHref),
                new XElement(D + "propstat", new XElement(D + "prop", new XElement(D + "resourcetype", new XElement(D + "collection"))), DavXml.Status(200))),
        };
        foreach (var chunk in new DirectoryInfo(folder).EnumerateFiles())
        {
            responses.Add(new XElement(D + "response", new XElement(D + "href", baseHref + Uri.EscapeDataString(chunk.Name)),
                new XElement(D + "propstat", new XElement(D + "prop", new XElement(D + "getcontentlength", chunk.Length), new XElement(D + "resourcetype")), DavXml.Status(200))));
        }
        await WriteAsync(context, StatusCodes.Status207MultiStatus, Multistatus(responses));
    }

    private async Task PutChunkAsync(HttpContext context, Space space, string folder, string name)
    {
        if (!Directory.Exists(folder))
        {
            context.Response.StatusCode = StatusCodes.Status404NotFound;
            return;
        }
        // What's waiting in every unfinished upload here is on the disk too: otherwise each new upload would get the whole quota again.
        var total = long.TryParse(context.Request.Headers["OC-Total-Length"], out var stated) ? stated : 0;
        var held = space.UploadsHeld();
        var room = Math.Min(handler.FreeOnDisk(space), space.QuotaBytes > 0 ? Math.Max(0, space.QuotaBytes - state.Usage.Get(space) - held) : long.MaxValue);
        var ownSoFar = UsageOf(folder);
        var limit = state.Policy.Settings.MaxUploadBytes;
        if (limit > 0 && (total > limit || ownSoFar + (context.Request.ContentLength ?? 0) > limit))
        {
            context.Response.StatusCode = StatusCodes.Status413PayloadTooLarge;
            return;
        }
        if ((total > 0 && total - ownSoFar > room) || context.Request.ContentLength > room)
        {
            await WriteErrorAsync(context, StatusCodes.Status507InsufficientStorage, new XElement(D + "quota-not-exceeded"));
            return;
        }
        AllowBody(context, null);
        var part = Path.Combine(folder, name + ".part");
        DavHandler.TryDelete(part);
        try
        {
            await handler.ReceiveAsync(context, part, room, null);
        }
        catch (DavHandler.QuotaExceededException)
        {
            await WriteErrorAsync(context, StatusCodes.Status507InsufficientStorage, new XElement(D + "quota-not-exceeded"));
            return;
        }
        catch (DavHandler.TooLargeException)
        {
            context.Response.StatusCode = StatusCodes.Status413PayloadTooLarge;
            return;
        }
        File.Move(part, Path.Combine(folder, name), overwrite: true);
        context.Response.StatusCode = StatusCodes.Status201Created;
    }

    private static long UsageOf(string folder) => new DirectoryInfo(folder).EnumerateFiles().Sum(file => file.Length);

    private async Task FinishUploadAsync(HttpContext context, ClientInfo client, Account account, string folder, DavEndpoint endpoint)
    {
        if (!Directory.Exists(folder))
        {
            context.Response.StatusCode = StatusCodes.Status404NotFound;
            return;
        }
        var destination = context.Request.Headers["Destination"].ToString();
        var address = destination.StartsWith('/') ? destination : Uri.TryCreate(destination, UriKind.Absolute, out var uri) ? uri.AbsolutePath : null;
        var segments = address is null ? null : PathRules.DecodeTarget(address);
        if (segments is null)
        {
            context.Response.StatusCode = StatusCodes.Status400BadRequest;
            return;
        }
        var prefix = client.PathBase.Split('/', StringSplitOptions.RemoveEmptyEntries);
        if (prefix.Length > 0 && segments.Length >= prefix.Length && segments.Take(prefix.Length).SequenceEqual(prefix)) segments = segments[prefix.Length..];

        var (target, status) = Router.Resolve(state, account, segments);
        if (target is null || target.ReadOnly || target.Path.IsRoot)
        {
            context.Response.StatusCode = target is null ? status : StatusCodes.Status403Forbidden;
            return;
        }
        if (endpoint.DropIfBanned(context, client, target.Mount)) return;
        var space = target.Space;
        var full = space.FullPath(target.Path);
        if (full is null || space.Stat(target.Path.Parent) is not { IsDirectory: true } || space.Stat(target.Path) is { IsDirectory: true })
        {
            context.Response.StatusCode = StatusCodes.Status409Conflict;
            return;
        }

        var request = new DavRequest(context, client, account, target);
        var answered = await handler.CheckWriteAsync(request);
        if (!answered) return;

        // Chunks go in order of their numbers: 2 comes before 10, so names can't simply be sorted.
        var chunks = new DirectoryInfo(folder).EnumerateFiles().Where(file => !file.Name.EndsWith(".part", StringComparison.Ordinal))
            .OrderBy(file => long.TryParse(file.Name, out var number) ? number : long.MaxValue).ThenBy(file => file.Name, StringComparer.Ordinal).ToList();
        var size = chunks.Sum(chunk => chunk.Length);
        if (long.TryParse(context.Request.Headers["OC-Total-Length"], out var stated) && stated != size)
        {
            context.Response.StatusCode = StatusCodes.Status400BadRequest;
            return;
        }
        if (state.Policy.Settings.MaxUploadBytes is > 0 and var largest && size > largest)
        {
            context.Response.StatusCode = StatusCodes.Status413PayloadTooLarge;
            return;
        }
        var existing = space.Stat(target.Path);
        if (space.QuotaBytes > 0 && size > space.QuotaBytes - state.Usage.Get(space) + (existing?.Size ?? 0))
        {
            await WriteErrorAsync(context, StatusCodes.Status507InsufficientStorage, new XElement(D + "quota-not-exceeded"));
            return;
        }

        var temp = space.NewTempFile();
        try
        {
            await using (var output = new FileStream(temp, new FileStreamOptions { Mode = FileMode.CreateNew, Access = FileAccess.Write, Options = FileOptions.Asynchronous | FileOptions.SequentialScan, BufferSize = 1 << 18, PreallocationSize = size }))
            {
                foreach (var chunk in chunks)
                {
                    await using var input = new FileStream(chunk.FullName, new FileStreamOptions { Mode = FileMode.Open, Access = FileAccess.Read, Options = FileOptions.Asynchronous | FileOptions.SequentialScan, BufferSize = 1 << 18 });
                    await input.CopyToAsync(output, context.RequestAborted);
                }
                await output.FlushAsync(context.RequestAborted);
                output.Flush(flushToDisk: true);
            }
        }
        catch
        {
            DavHandler.TryDelete(temp);
            throw;
        }

        var time = DavHandler.RequestedTime(context.Request);
        var (entry, node, created) = handler.Commit(space, target.Path, full, temp, size, existing?.Size ?? 0, existing is not null, time);
        Directory.Delete(folder, recursive: true);
        DavHandler.AnswerStored(context.Response, entry, node, time is not null);
        context.Response.StatusCode = created ? StatusCodes.Status201Created : StatusCodes.Status204NoContent;
    }
}
