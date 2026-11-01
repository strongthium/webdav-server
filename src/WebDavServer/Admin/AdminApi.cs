using System.Collections.Concurrent;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Strongthium.WebDavServer.Config;
using Strongthium.WebDavServer.Dav;
using Strongthium.WebDavServer.Network;
using Strongthium.WebDavServer.Security;
using Strongthium.WebDavServer.Storage;

namespace Strongthium.WebDavServer.Admin;

/// <summary>
/// What the admin window talks to, on a port of its own that never serves files. It takes a name and password once, and gives
/// back a token, kept only as a hash and only in memory, that dies with half an hour of silence. Until the default password is
/// changed, that token can do exactly one thing: change it.
/// </summary>
public sealed class AdminApi(ServerState state, Guard guard, ConnectionGate gate, Authenticator authenticator, DavEndpoint endpoint, ServerConfig config, TlsCertificates certificates, Func<IReadOnlyList<string>> davAddresses, Func<string> adminAddress, Func<CancellationToken, Task> updateGeo, Func<CancellationToken, Task> updateCloudflare)
{
    private sealed class Session
    {
        public required string Name { get; init; }
        public required long Generation { get; init; }
        public required DateTimeOffset Created { get; init; }
        public DateTimeOffset LastUsed { get; set; }
    }

    private static readonly TimeSpan IdleLimit = TimeSpan.FromMinutes(30);
    private static readonly TimeSpan AbsoluteLimit = TimeSpan.FromHours(8);
    private readonly ConcurrentDictionary<string, Session> sessions = new(StringComparer.Ordinal);

    private DateTimeOffset Now => state.Clock.GetUtcNow();

    public async Task InvokeAsync(HttpContext context)
    {
        try
        {
            await RunAsync(context);
        }
        catch (JsonException)
        {
            await ErrorAsync(context, StatusCodes.Status400BadRequest, "The request couldn't be read.");
        }
        catch (BadHttpRequestException exception)
        {
            await ErrorAsync(context, exception.StatusCode, "The request couldn't be read.");
        }
        catch (OperationCanceledException)
        {
            context.Abort();
        }
    }

    private async Task RunAsync(HttpContext context)
    {
        var address = Networks.Normal(context.Connection.RemoteIpAddress ?? IPAddress.None);
        var headers = context.Response.Headers;
        headers.XContentTypeOptions = "nosniff";
        headers.CacheControl = "no-store";
        headers.ContentSecurityPolicy = "default-src 'none'; sandbox";
        headers.StrictTransportSecurity = "max-age=31536000";

        // A socket can outlast a ban or a change of whitelist, so this is asked of every request too.
        if (guard.IsBanned(address, Scopes.Admin))
        {
            gate.Drop(context, viaProxy: false);
            return;
        }
        switch (state.Policy.AdminWhitelist.Check(address, state.Geo))
        {
            case AccessVerdict.Denied:
                guard.Ban(address, Scopes.Admin, TimeSpan.FromMinutes(state.Policy.Settings.WhitelistBanMinutes), "Connected from outside the admin whitelist.");
                gate.Drop(context, viaProxy: false);
                return;
            case AccessVerdict.CannotTell:
                gate.Drop(context, viaProxy: false);
                return;
        }

        var method = context.Request.Method.ToUpperInvariant();
        string[] path = (context.Request.Path.Value ?? "").Split('/', StringSplitOptions.RemoveEmptyEntries);
        if (method == "POST" && path is ["api", "login"])
        {
            await LoginAsync(context, address);
            return;
        }

        var session = Authenticate(context);
        if (session is null)
        {
            await ErrorAsync(context, StatusCodes.Status401Unauthorized, "Log in first.");
            return;
        }
        var admin = state.Database.LoadAdmin();
        if (admin is null || admin.Generation != session.Generation)
        {
            await ErrorAsync(context, StatusCodes.Status401Unauthorized, "Log in again.");
            return;
        }

        // The only other things allowed with the default password.
        if (admin.MustChange && !(method == "POST" && path is ["api", "password"] or ["api", "logout"]))
        {
            await ErrorAsync(context, StatusCodes.Status403Forbidden, "The default password has to be changed first.", Api.MustChangePasswordCode);
            return;
        }

        switch (method, path)
        {
            case ("POST", ["api", "logout"]):
                Logout(context);
                await OkAsync(context);
                return;
            case ("POST", ["api", "password"]):
                await ChangePasswordAsync(context, address, admin);
                return;
            case ("GET", ["api", "status"]):
                await JsonAsync(context, Status());
                return;
            case ("GET", ["api", "settings"]):
                await JsonAsync(context, state.Policy.Settings);
                return;
            case ("PUT", ["api", "settings"]):
                await SaveSettingsAsync(context, address);
                return;
            case ("GET", ["api", "accounts"]):
                await JsonAsync(context, Accounts());
                return;
            case ("PUT", ["api", "accounts"]):
                await SaveAccountAsync(context, address);
                return;
            case ("DELETE", ["api", "accounts"]):
                await DeleteAccountAsync(context, address);
                return;
            case ("POST", ["api", "app-passwords"]):
                await NewAppPasswordAsync(context, address);
                return;
            case ("DELETE", ["api", "app-passwords"]):
                await DeleteAppPasswordAsync(context, address);
                return;
            case ("GET", ["api", "mounts"]):
                await JsonAsync(context, state.Policy.Mounts.Values.OrderBy(mount => mount.Path, StringComparer.Ordinal));
                return;
            case ("PUT", ["api", "mounts"]):
                await SaveMountAsync(context, address);
                return;
            case ("DELETE", ["api", "mounts"]):
                await DeleteMountAsync(context, address);
                return;
            case ("GET", ["api", "bans"]):
                await JsonAsync(context, guard.Bans());
                return;
            case ("POST", ["api", "bans"]):
                await AddBanAsync(context, address);
                return;
            case ("DELETE", ["api", "bans"]):
                if (guard.RemoveBan(context.Request.Query["network"].ToString(), context.Request.Query["scope"].ToString())) await OkAsync(context);
                else await ErrorAsync(context, StatusCodes.Status404NotFound, "There's no such ban.");
                return;
            case ("GET", ["api", "log"]):
                var kind = context.Request.Query["kind"].ToString();
                await JsonAsync(context, state.Database.ReadLog(int.TryParse(context.Request.Query["limit"], out var limit) ? limit : 500, kind.Length > 0 ? kind : null));
                return;
            case ("POST", ["api", "geo", "update"]):
                await UpdateAsync(context, updateGeo, "DB-IP's files");
                return;
            case ("POST", ["api", "cloudflare", "update"]):
                await UpdateAsync(context, updateCloudflare, "Cloudflare's addresses");
                return;
        }
        await ErrorAsync(context, StatusCodes.Status404NotFound, "There's nothing there.");
    }

    // ---- Answers -------------------------------------------------------------------------------------------------

    private static Task JsonAsync<T>(HttpContext context, T value, int status = StatusCodes.Status200OK)
    {
        context.Response.StatusCode = status;
        context.Response.ContentType = "application/json; charset=utf-8";
        return JsonSerializer.SerializeAsync(context.Response.Body, value, Api.Json, context.RequestAborted);
    }

    private static Task OkAsync(HttpContext context)
    {
        context.Response.StatusCode = StatusCodes.Status204NoContent;
        return Task.CompletedTask;
    }

    private static Task ErrorAsync(HttpContext context, int status, string error, string code = "") =>
        context.Response.HasStarted ? Task.CompletedTask : JsonAsync(context, new ApiError { Error = error, Code = code }, status);

    private static async Task<T> ReadAsync<T>(HttpContext context) where T : class =>
        await JsonSerializer.DeserializeAsync<T>(context.Request.Body, Api.Json, context.RequestAborted) ?? throw new JsonException();

    // ---- Logging in ----------------------------------------------------------------------------------------------

    private static string TokenKey(string token) => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(token)));

    private Session? Authenticate(HttpContext context)
    {
        var header = context.Request.Headers.Authorization.ToString();
        if (!header.StartsWith("Bearer ", StringComparison.Ordinal)) return null;
        var key = TokenKey(header[7..].Trim());
        if (!sessions.TryGetValue(key, out var session)) return null;
        var now = Now;
        lock (session)
        {
            if (now - session.LastUsed > IdleLimit || now - session.Created > AbsoluteLimit)
            {
                sessions.TryRemove(key, out _);
                return null;
            }
            session.LastUsed = now;
        }
        return session;
    }

    private void Logout(HttpContext context)
    {
        var header = context.Request.Headers.Authorization.ToString();
        if (header.StartsWith("Bearer ", StringComparison.Ordinal)) sessions.TryRemove(TokenKey(header[7..].Trim()), out _);
    }

    private async Task LoginAsync(HttpContext context, IPAddress address)
    {
        var request = await ReadAsync<LoginRequest>(context);
        var admin = state.Database.LoadAdmin();
        var hash = admin?.PasswordHash ?? Passwords.Decoy.Value;
        var verdict = request.Password.Length is 0 or > 1024
            ? LoginVerdict.Refused
            : await authenticator.SlowVerifyAsync(request.Password, hash, context.RequestAborted);
        if (verdict == LoginVerdict.Busy)
        {
            await ErrorAsync(context, StatusCodes.Status503ServiceUnavailable, "The server is busy. Try again in a moment.");
            return;
        }

        var name = request.UserName.Trim();
        var accepted = verdict == LoginVerdict.Accepted && admin is not null && name.Equals(admin.Name, StringComparison.OrdinalIgnoreCase);
        if (!accepted)
        {
            if (guard.LoginFailed(address, Scopes.Admin, name.Length > 64 ? name[..64] : name))
            {
                gate.Drop(context, viaProxy: false);
                return;
            }
            await ErrorAsync(context, StatusCodes.Status401Unauthorized, "That name or password isn't right.");
            return;
        }

        // A server that has just been started has a password that everyone knows. If it can be reached from the internet,
        // the first stranger to try it would own the server, so it only works from nearby until it's been changed.
        if (admin!.MustChange && !Networks.IsPrivate(address) && !config.AllowDefaultAdminPasswordFromAnywhere)
        {
            state.Log("refused", address, admin.Name, Scopes.Admin, "The default admin password was tried from a public address.");
            await ErrorAsync(context, StatusCodes.Status403Forbidden,
                "The default password only works from the server itself or a private network. Connect through an SSH tunnel, or set a password on the server with: webdav-server --set-admin-password");
            return;
        }

        var token = Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(32));
        var now = Now;
        foreach (var (key, old) in sessions)
        {
            if (now - old.LastUsed > IdleLimit || now - old.Created > AbsoluteLimit) sessions.TryRemove(key, out _);
        }
        sessions[TokenKey(token)] = new Session { Name = admin.Name, Generation = admin.Generation, Created = now, LastUsed = now };
        state.Log("admin-login", address, admin.Name, Scopes.Admin, admin.MustChange ? "Logged in with the default password." : "Logged in.");
        await JsonAsync(context, new LoginResponse { Token = token, UserName = admin.Name, MustChangePassword = admin.MustChange });
    }

    private async Task ChangePasswordAsync(HttpContext context, IPAddress address, AdminRow admin)
    {
        var request = await ReadAsync<ChangePasswordRequest>(context);
        var verdict = request.CurrentPassword.Length is 0 or > 1024 ? LoginVerdict.Refused : await authenticator.SlowVerifyAsync(request.CurrentPassword, admin.PasswordHash, context.RequestAborted);
        if (verdict == LoginVerdict.Busy)
        {
            await ErrorAsync(context, StatusCodes.Status503ServiceUnavailable, "The server is busy. Try again in a moment.");
            return;
        }
        if (verdict != LoginVerdict.Accepted)
        {
            if (guard.LoginFailed(address, Scopes.Admin, admin.Name))
            {
                gate.Drop(context, viaProxy: false);
                return;
            }
            await ErrorAsync(context, StatusCodes.Status403Forbidden, "The current password isn't right.");
            return;
        }
        if (Api.PasswordProblem(request.NewPassword) is { } problem)
        {
            await ErrorAsync(context, StatusCodes.Status400BadRequest, problem);
            return;
        }
        if (request.NewPassword == request.CurrentPassword || request.NewPassword == ServerState.DefaultAdminPassword)
        {
            await ErrorAsync(context, StatusCodes.Status400BadRequest, "The new password has to be a different one.");
            return;
        }
        var name = request.NewUserName.Trim();
        if (name.Length == 0) name = admin.Name;
        if (Names.AccountProblem(name.ToLowerInvariant()) is not null)
        {
            await ErrorAsync(context, StatusCodes.Status400BadRequest, "A name is 1 to 64 letters, digits, dots, dashes or underscores.");
            return;
        }

        state.Database.SaveAdmin(name, Passwords.Hash(request.NewPassword), mustChange: false);
        // Everyone else who was logged in is out: their sessions are of the old generation.
        sessions.Clear();
        var fresh = state.Database.LoadAdmin()!;
        var token = Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(32));
        sessions[TokenKey(token)] = new Session { Name = fresh.Name, Generation = fresh.Generation, Created = Now, LastUsed = Now };
        state.Log("admin-password", address, fresh.Name, Scopes.Admin, "The admin password was changed.");
        await JsonAsync(context, new LoginResponse { Token = token, UserName = fresh.Name, MustChangePassword = false });
    }

    // ---- Status --------------------------------------------------------------------------------------------------

    private StatusInfo Status()
    {
        var policy = state.Policy;
        var warnings = new List<string>();
        if (endpoint.UntrustedProxySeen is { } proxy)
            warnings.Add($"Proxy headers have come from {proxy}, which isn't a trusted proxy, so they were ignored. If that's your proxy, add it on the Proxy page: until then every client looks like it, and one person's failed logins would ban them all.");
        var usesPlaces = policy.Whitelist.NeedsPlaces || policy.AdminWhitelist.NeedsPlaces || policy.Accounts.Values.Any(account => account.Whitelist.NeedsPlaces);
        if (usesPlaces && !state.Geo.Loaded)
            warnings.Add("A whitelist names countries or networks, but DB-IP's database isn't here yet, so nobody can be matched by them. They are kept out, and not banned. Download it on the Access page.");
        if (policy.Accounts.Count == 0) warnings.Add("There are no accounts yet, so nobody can log in.");
        if (policy.Accounts.Values.Any(account => account.Info.Grants.Count == 0)) warnings.Add("An account has no path it may use.");
        if (certificates.IsSelfSigned) warnings.Add("WebDAV is using a self-signed certificate. Most clients won't connect until they've been told to trust it. Give the server a real one, or put it behind nginx or Cloudflare.");
        var certificate = certificates.Current();
        return new StatusInfo
        {
            Version = Updater.RunningVersion.ToString(4),
            System = System.Runtime.InteropServices.RuntimeInformation.OSDescription,
            Started = state.Started,
            OpenConnections = gate.OpenConnections,
            ClosedAtTheDoor = gate.ClosedAtTheDoor,
            Accounts = policy.Accounts.Count,
            Mounts = policy.Mounts.Count,
            Bans = guard.BanCount,
            DavAddresses = [.. davAddresses()],
            AdminAddress = adminAddress(),
            CertificateFingerprint = TlsCertificates.Fingerprint(certificate),
            CertificateSubject = certificate.Subject,
            CertificateExpires = certificate.NotAfter.ToUniversalTime(),
            DataFolder = state.DataFolder,
            GeoMonth = state.Geo.Month,
            CloudflareRanges = state.Cloudflare.Ranges.Length,
            Warnings = warnings,
        };
    }

    // ---- Settings ------------------------------------------------------------------------------------------------

    private static string? ListProblem(IEnumerable<string> rules) => rules.Select(AccessList.Problem).FirstOrDefault(problem => problem is not null);

    private async Task SaveSettingsAsync(HttpContext context, IPAddress address)
    {
        var settings = await ReadAsync<ServerSettings>(context);
        var problem = ListProblem(settings.Whitelist) ?? ListProblem(settings.AdminWhitelist);
        foreach (var proxy in settings.TrustedProxies)
        {
            if (!Networks.TryParse(proxy, out _)) problem ??= $"\"{proxy}\" isn't an address or a network.";
        }
        if (settings.PublicUrl.Length > 0 && (!Uri.TryCreate(settings.PublicUrl, UriKind.Absolute, out var url) || url.Scheme is not ("https" or "http") || url.Query.Length > 0 || url.Fragment.Length > 0))
            problem ??= "The public address has to be a whole address, like https://files.example.com.";
        if (settings.BanPrefixV6 is < 32 or > 128) problem ??= "An IPv6 ban covers between /32 and /128.";
        if (settings.WhitelistBanMinutes < 1 || settings.BanMinutes < 1 || settings.AdminBanMinutes < 1) problem ??= "A ban lasts at least a minute.";
        if (settings.FailureWindowMinutes < 1 || settings.AdminFailureWindowMinutes < 1) problem ??= "Failures are counted over at least a minute.";
        if (settings.MaxFailuresAllPaths < 0) problem ??= "The number of failures can't be negative: 0 never bans.";
        if (settings.MaxFailures < 0 || settings.AdminMaxFailures < 1) problem ??= "The admin port has to ban after some number of failures.";
        if (settings.MaxUploadBytes < 0) problem ??= "The largest upload can't be negative.";
        if (problem is not null)
        {
            await ErrorAsync(context, StatusCodes.Status400BadRequest, problem);
            return;
        }

        // Nobody saves a whitelist that shuts out the place they're saving it from. There's a way back from the server's
        // own command line, but it's a long way to go when the server is far away.
        var newAdminList = AccessList.Parse(settings.AdminWhitelist);
        if (newAdminList.Check(address, state.Geo) != AccessVerdict.Allowed)
        {
            await ErrorAsync(context, StatusCodes.Status409Conflict, $"That admin whitelist doesn't include {address}, where you are now, so you'd be shut out and banned.");
            return;
        }

        var prefixChanged = settings.BanPrefixV6 != state.Policy.Settings.BanPrefixV6;
        state.Database.SaveSettings(settings);
        state.Reload();
        if (prefixChanged) guard.SettingsChanged();
        state.Log("settings", address, "", Scopes.Admin, "The server's settings were changed.");
        await OkAsync(context);
    }

    // ---- Accounts ------------------------------------------------------------------------------------------------

    private List<AccountInfo> Accounts()
    {
        var policy = state.Policy;
        return [.. policy.Accounts.Values.OrderBy(account => account.Name, StringComparer.Ordinal).Select(account => account.Info)];
    }

    private async Task SaveAccountAsync(HttpContext context, IPAddress address)
    {
        var write = await ReadAsync<AccountWrite>(context);
        var info = write.Account with { Name = write.Account.Name.Trim().ToLowerInvariant() };
        var policy = state.Policy;
        var isNew = !policy.Accounts.ContainsKey(info.Name);
        var problem = Names.AccountProblem(info.Name) ?? ListProblem(info.Whitelist);
        if (info.QuotaBytes < 0) problem ??= "A quota can't be negative.";
        foreach (var grant in info.Grants)
        {
            if (!policy.Mounts.ContainsKey(grant.Mount)) problem ??= $"There's no path {grant.Mount}.";
        }
        if (info.HomeMount.Length > 0 && info.Grants.All(grant => grant.Mount != info.HomeMount)) problem ??= "An account's home has to be one of the paths it may use.";
        if (write.Password is { } password) problem ??= Api.PasswordProblem(password);
        if (isNew && write.Password is null && !info.RequireAppPasswords) problem ??= "A new account needs a password, unless it's to log in only with app passwords.";
        if (problem is not null)
        {
            await ErrorAsync(context, StatusCodes.Status400BadRequest, problem);
            return;
        }
        var hash = write.Password is { } text ? Passwords.Hash(text) : null;
        state.Database.SaveAccount(info with { Grants = [.. info.Grants.Select(grant => grant with { Mount = policy.Mounts[grant.Mount].Path })] }, hash);
        state.Reload();
        authenticator.Forget(info.Name);
        state.Log("account", address, info.Name, Scopes.Admin, isNew ? "Account made." : write.Password is null ? "Account changed." : "Account changed, with a new password.");
        await JsonAsync(context, state.Policy.Accounts[info.Name].Info);
    }

    private async Task DeleteAccountAsync(HttpContext context, IPAddress address)
    {
        var name = context.Request.Query["name"].ToString().Trim().ToLowerInvariant();
        if (!state.Database.DeleteAccount(name))
        {
            await ErrorAsync(context, StatusCodes.Status404NotFound, "There's no such account.");
            return;
        }
        state.Reload();
        authenticator.Forget(name);
        state.Log("account", address, name, Scopes.Admin, "Account deleted. Its files are still on the server.");
        await OkAsync(context);
    }

    private async Task NewAppPasswordAsync(HttpContext context, IPAddress address)
    {
        var request = await ReadAsync<AppPasswordRequest>(context);
        if (!state.Policy.Accounts.TryGetValue(request.Account.Trim(), out var account))
        {
            await ErrorAsync(context, StatusCodes.Status404NotFound, "There's no such account.");
            return;
        }
        var name = request.Name.Trim();
        if (name.Length is 0 or > 200)
        {
            await ErrorAsync(context, StatusCodes.Status400BadRequest, "Give it a name, of what it's for.");
            return;
        }
        var password = Passwords.NewAppPassword();
        var created = Now;
        var id = state.Database.AddAppPassword(account.Name, name, Passwords.HashAppPassword(password), created);
        state.Reload();
        state.Log("app-password", address, account.Name, Scopes.Admin, $"App password made: {name}.");
        await JsonAsync(context, new AppPasswordCreated { Info = new AppPasswordInfo { Id = id, Name = name, Created = created }, Password = password });
    }

    private async Task DeleteAppPasswordAsync(HttpContext context, IPAddress address)
    {
        var account = context.Request.Query["account"].ToString().Trim().ToLowerInvariant();
        if (!long.TryParse(context.Request.Query["id"], out var id) || !state.Database.DeleteAppPassword(account, id))
        {
            await ErrorAsync(context, StatusCodes.Status404NotFound, "There's no such app password.");
            return;
        }
        state.Reload();
        state.Log("app-password", address, account, Scopes.Admin, "App password taken away.");
        await OkAsync(context);
    }

    // ---- Paths ---------------------------------------------------------------------------------------------------

    private async Task SaveMountAsync(HttpContext context, IPAddress address)
    {
        var mount = await ReadAsync<MountInfo>(context);
        var problem = Names.MountProblem(mount.Path);
        if (mount.MaxFailures < 0) problem ??= "The number of failures can't be negative: 0 never bans.";
        if (mount.FailureWindowMinutes < 1) problem ??= "Failures are counted over at least a minute.";
        if (mount.BanMinutes < 1) problem ??= "A ban lasts at least a minute.";
        if (mount.QuotaBytes < 0) problem ??= "A quota can't be negative.";
        if (mount.Root.Length > 0) problem ??= RootProblem(mount.Root);
        var clash = state.Policy.Mounts.GetValueOrDefault(mount.Path);
        if (clash is not null && !clash.Path.Equals(mount.Path, StringComparison.Ordinal)) problem ??= $"There's already a path {clash.Path}.";
        if (problem is not null)
        {
            await ErrorAsync(context, StatusCodes.Status400BadRequest, problem);
            return;
        }
        state.Database.SaveMount(mount);
        state.Reload();
        state.Log("path", address, "", mount.Path, clash is null ? "Path made." : "Path changed.");
        await OkAsync(context);
    }

    /// <summary>A path's folder can't be, hold, or be inside the server's own data, or hold its certificate's key: serving those
    /// would give away its password hashes and keys, and the <c>files</c> folder inside it holds everyone's files. Paths are
    /// compared as what they really are, with links and Windows' short names followed, since there are many ways to write one.</summary>
    private string? RootProblem(string root)
    {
        if (!Path.IsPathFullyQualified(root)) return "A path's folder has to be a whole path on the server.";
        // \\?\C:\..., \\localhost\C$\... and the like would each be another way of writing somewhere else.
        if (OperatingSystem.IsWindows() && root.StartsWith(@"\\", StringComparison.Ordinal)) return "A path's folder has to be on a drive of the server, not a network or device path.";
        var full = RealPath.Of(root);
        var separator = Path.DirectorySeparatorChar;
        bool Holds(string inner)
        {
            var other = RealPath.Of(inner);
            return full.Length == 0 || other.Equals(full, PathRules.Compare) || other.StartsWith(full + separator, PathRules.Compare);
        }
        if (Holds(state.DataFolder)) return "That folder holds the server's own data.";
        var data = RealPath.Of(state.DataFolder);
        if (full.StartsWith(data + separator, PathRules.Compare)) return "That folder is inside the server's own data.";
        foreach (var file in new[] { config.CertificateFile, config.KeyFile })
        {
            if (file.Length > 0 && Holds(file)) return "That folder holds the server's certificate.";
        }
        return null;
    }

    private async Task DeleteMountAsync(HttpContext context, IPAddress address)
    {
        var path = context.Request.Query["path"].ToString();
        if (state.Policy.Accounts.Values.FirstOrDefault(account => account.GrantOn(path) is not null) is { } user)
        {
            await ErrorAsync(context, StatusCodes.Status409Conflict, $"{user.Name} still uses {path}. Take it away from them first.");
            return;
        }
        if (!state.Database.DeleteMount(path))
        {
            await ErrorAsync(context, StatusCodes.Status404NotFound, "There's no such path.");
            return;
        }
        state.Reload();
        state.Log("path", address, "", path, "Path deleted. Its files are still on the server.");
        await OkAsync(context);
    }

    // ---- Bans and updates ----------------------------------------------------------------------------------------

    private async Task AddBanAsync(HttpContext context, IPAddress address)
    {
        var write = await ReadAsync<BanWrite>(context);
        if (!Networks.TryParse(write.Network, out var network))
        {
            await ErrorAsync(context, StatusCodes.Status400BadRequest, "That isn't an address or a network.");
            return;
        }
        if (write.Scope != Scopes.All && write.Scope != Scopes.Admin && write.Scope != Scopes.Root && !state.Policy.Mounts.ContainsKey(write.Scope))
        {
            await ErrorAsync(context, StatusCodes.Status400BadRequest, "A ban is from all of WebDAV (*), the admin port (admin) or a path.");
            return;
        }
        if (write.Scope == Scopes.Admin && network.Contains(address))
        {
            await ErrorAsync(context, StatusCodes.Status409Conflict, $"That would ban {address}, where you are now.");
            return;
        }
        var now = Now;
        guard.AddBan(new BanInfo { Network = Networks.Format(network), Scope = write.Scope, Reason = write.Reason.Trim(), Created = now, Until = write.Minutes > 0 ? now.AddMinutes(write.Minutes) : null });
        await OkAsync(context);
    }

    private static async Task UpdateAsync(HttpContext context, Func<CancellationToken, Task> update, string what)
    {
        try
        {
            await update(context.RequestAborted);
            await OkAsync(context);
        }
        catch (Exception exception) when (exception is HttpRequestException or IOException or InvalidDataException or InvalidOperationException or TaskCanceledException)
        {
            await ErrorAsync(context, StatusCodes.Status502BadGateway, $"{what} couldn't be downloaded: {exception.Message}");
        }
    }
}
