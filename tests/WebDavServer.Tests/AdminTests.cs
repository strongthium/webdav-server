using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using static Strongthium.WebDavServer.Tests.TestServer;

namespace Strongthium.WebDavServer.Tests;

/// <summary>The admin port, as the admin window uses it.</summary>
public sealed class AdminTests : IAsyncLifetime
{
    private const string NewPassword = "a much better password";

    private TestServer server = null!;
    private HttpClient admin = null!;

    public async ValueTask InitializeAsync()
    {
        server = await StartAsync();
        var handler = new SocketsHttpHandler { UseProxy = false };
        handler.SslOptions.RemoteCertificateValidationCallback = (_, _, _, _) => true;
        admin = new HttpClient(handler) { BaseAddress = new Uri(server.App.AdminAddress) };
    }

    public async ValueTask DisposeAsync()
    {
        admin.Dispose();
        await server.DisposeAsync();
    }

    private async Task<HttpResponseMessage> LoginAsync(string name = "admin", string password = "admin") =>
        await admin.PostAsJsonAsync("/api/login", new LoginRequest { UserName = name, Password = password }, Api.Json);

    /// <summary>Logs in with the default password and changes it, as the window makes one do.</summary>
    private async Task ReadyAsync()
    {
        using var login = await LoginAsync();
        var answer = await login.Content.ReadFromJsonAsync<LoginResponse>(Api.Json);
        admin.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", answer!.Token);
        using var changed = await admin.PostAsJsonAsync("/api/password", new ChangePasswordRequest { CurrentPassword = "admin", NewPassword = NewPassword }, Api.Json);
        Assert.Equal(HttpStatusCode.OK, changed.StatusCode);
        var fresh = await changed.Content.ReadFromJsonAsync<LoginResponse>(Api.Json);
        admin.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", fresh!.Token);
    }

    [Fact]
    public async Task TheDefaultPasswordCanDoOneThingOnly()
    {
        using var login = await LoginAsync();
        Assert.Equal(HttpStatusCode.OK, login.StatusCode);
        var answer = await login.Content.ReadFromJsonAsync<LoginResponse>(Api.Json);
        Assert.True(answer!.MustChangePassword);
        admin.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", answer.Token);

        foreach (var address in new[] { "/api/status", "/api/settings", "/api/accounts", "/api/mounts", "/api/bans", "/api/log" })
        {
            using var response = await admin.GetAsync(address);
            Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
            var error = await response.Content.ReadFromJsonAsync<ApiError>(Api.Json);
            Assert.Equal(Api.MustChangePasswordCode, error!.Code);
        }
        using (var write = await admin.PutAsJsonAsync("/api/accounts", new AccountWrite { Account = new AccountInfo { Name = "x" }, Password = NewPassword }, Api.Json))
        {
            Assert.Equal(HttpStatusCode.Forbidden, write.StatusCode);
        }
    }

    [Theory]
    [InlineData("short")]
    [InlineData("admin")]
    [InlineData("aaaaaaaaaaaaaaaaaaaa")]
    public async Task ThePasswordItsChangedToHasToBeBetter(string bad)
    {
        using var login = await LoginAsync();
        var answer = await login.Content.ReadFromJsonAsync<LoginResponse>(Api.Json);
        admin.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", answer!.Token);
        using var changed = await admin.PostAsJsonAsync("/api/password", new ChangePasswordRequest { CurrentPassword = "admin", NewPassword = bad }, Api.Json);
        Assert.Equal(HttpStatusCode.BadRequest, changed.StatusCode);
        using var still = await admin.GetAsync("/api/status");
        Assert.Equal(HttpStatusCode.Forbidden, still.StatusCode);
    }

    [Fact]
    public async Task ChangingItNeedsTheCurrentOne()
    {
        using var login = await LoginAsync();
        var answer = await login.Content.ReadFromJsonAsync<LoginResponse>(Api.Json);
        admin.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", answer!.Token);
        using var changed = await admin.PostAsJsonAsync("/api/password", new ChangePasswordRequest { CurrentPassword = "wrong", NewPassword = NewPassword }, Api.Json);
        Assert.Equal(HttpStatusCode.Forbidden, changed.StatusCode);
    }

    [Fact]
    public async Task OnceChangedTheDefaultIsGoneAndOthersAreLoggedOut()
    {
        using var other = await LoginAsync();
        var otherToken = (await other.Content.ReadFromJsonAsync<LoginResponse>(Api.Json))!.Token;
        await ReadyAsync();

        using (var status = await admin.GetAsync("/api/status"))
        {
            Assert.Equal(HttpStatusCode.OK, status.StatusCode);
            var info = await status.Content.ReadFromJsonAsync<StatusInfo>(Api.Json);
            Assert.False(string.IsNullOrEmpty(info!.Version));
        }
        using (var oldLogin = await LoginAsync()) Assert.Equal(HttpStatusCode.Unauthorized, oldLogin.StatusCode);
        using (var newLogin = await LoginAsync(password: NewPassword))
        {
            Assert.Equal(HttpStatusCode.OK, newLogin.StatusCode);
            Assert.False((await newLogin.Content.ReadFromJsonAsync<LoginResponse>(Api.Json))!.MustChangePassword);
        }
        using var request = new HttpRequestMessage(HttpMethod.Get, "/api/status");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", otherToken);
        using var stale = await admin.SendAsync(request);
        Assert.Equal(HttpStatusCode.Unauthorized, stale.StatusCode);
    }

    [Fact]
    public async Task TheNameCanChangeToo()
    {
        using var login = await LoginAsync();
        var answer = await login.Content.ReadFromJsonAsync<LoginResponse>(Api.Json);
        admin.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", answer!.Token);
        using (await admin.PostAsJsonAsync("/api/password", new ChangePasswordRequest { CurrentPassword = "admin", NewPassword = NewPassword, NewUserName = "boss" }, Api.Json)) { }
        using (var oldName = await LoginAsync("admin", NewPassword)) Assert.Equal(HttpStatusCode.Unauthorized, oldName.StatusCode);
        using var newName = await LoginAsync("boss", NewPassword);
        Assert.Equal(HttpStatusCode.OK, newName.StatusCode);
    }

    [Fact]
    public async Task TheDefaultPasswordOnlyWorksNearby()
    {
        // Loopback is near. What's near is the rule that keeps the first stranger from owning a new server.
        Assert.True(Networks.IsPrivate(IPAddress.Parse("127.0.0.1")));
        Assert.True(Networks.IsPrivate(IPAddress.Parse("::1")));
        Assert.True(Networks.IsPrivate(IPAddress.Parse("10.1.2.3")));
        Assert.True(Networks.IsPrivate(IPAddress.Parse("172.16.0.1")));
        Assert.True(Networks.IsPrivate(IPAddress.Parse("192.168.1.1")));
        Assert.True(Networks.IsPrivate(IPAddress.Parse("fd00::1")));
        Assert.True(Networks.IsPrivate(IPAddress.Parse("::ffff:192.168.1.1")));
        Assert.False(Networks.IsPrivate(IPAddress.Parse("203.0.113.1")));
        Assert.False(Networks.IsPrivate(IPAddress.Parse("172.32.0.1")));
        Assert.False(Networks.IsPrivate(IPAddress.Parse("2001:db8::1")));
        using var login = await LoginAsync();
        Assert.Equal(HttpStatusCode.OK, login.StatusCode);
    }

    [Fact]
    public async Task NothingWithoutAToken()
    {
        foreach (var address in new[] { "/api/status", "/api/settings", "/api/accounts", "/", "/dav/" })
        {
            using var response = await admin.GetAsync(address);
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        }
        admin.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", "made-up");
        using var madeUp = await admin.GetAsync("/api/status");
        Assert.Equal(HttpStatusCode.Unauthorized, madeUp.StatusCode);
    }

    [Fact]
    public async Task ATokenDiesWithSilence()
    {
        await ReadyAsync();
        using (var alive = await admin.GetAsync("/api/status")) Assert.Equal(HttpStatusCode.OK, alive.StatusCode);
        server.Clock.Now = server.Clock.Now.AddMinutes(31);
        using var dead = await admin.GetAsync("/api/status");
        Assert.Equal(HttpStatusCode.Unauthorized, dead.StatusCode);
    }

    [Fact]
    public async Task LoggingOutEndsTheToken()
    {
        await ReadyAsync();
        using (await admin.PostAsync("/api/logout", null)) { }
        using var after = await admin.GetAsync("/api/status");
        Assert.Equal(HttpStatusCode.Unauthorized, after.StatusCode);
    }

    [Fact]
    public async Task FailedLoginsBanFromTheAdminPortAlone()
    {
        for (var i = 0; i < 4; i++)
        {
            using var wrong = await LoginAsync(password: "wrong");
            Assert.Equal(HttpStatusCode.Unauthorized, wrong.StatusCode);
        }
        await Assert.ThrowsAsync<HttpRequestException>(() => LoginAsync(password: "wrong"));
        var ban = Assert.Single(server.App.Guard.Bans());
        Assert.Equal("admin", ban.Scope);
        await Assert.ThrowsAsync<HttpRequestException>(() => LoginAsync());

        // WebDAV doesn't mind.
        server.AddAccount("alice", new GrantInfo { Mount = "/dav" });
        using var dav = await server.SendAsync("PROPFIND", "/dav/", headers: ("Depth", "0"));
        Assert.Equal((HttpStatusCode)207, dav.StatusCode);
    }

    [Fact]
    public async Task ABanOnWebDavDoesntShutOutTheAdmin()
    {
        server.App.Guard.Ban(IPAddress.Loopback, Security.Scopes.All, TimeSpan.FromHours(1), "Test.");
        using var login = await LoginAsync();
        Assert.Equal(HttpStatusCode.OK, login.StatusCode);
    }

    [Fact]
    public async Task FilesArentServedOnTheAdminPortNorTheAdminOnTheFilePort()
    {
        await ReadyAsync();
        server.AddAccount("alice", new GrantInfo { Mount = "/dav" });
        await server.PutAsync("/dav/f.txt", "secret");
        using (var file = await admin.GetAsync("/dav/f.txt")) Assert.Equal(HttpStatusCode.NotFound, file.StatusCode);
        using (var nc = await admin.GetAsync("/status.php")) Assert.Equal(HttpStatusCode.NotFound, nc.StatusCode);

        var token = admin.DefaultRequestHeaders.Authorization!.Parameter;
        using var request = new HttpRequestMessage(HttpMethod.Get, server.Url + "/api/status");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        using var response = await server.Http.SendAsync(request);
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.DoesNotContain("version", await response.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task AnAccountMadeHereCanLogIn()
    {
        await ReadyAsync();
        using (var made = await admin.PutAsJsonAsync("/api/accounts", new AccountWrite { Account = new AccountInfo { Name = "Alice", Grants = [new GrantInfo { Mount = "/dav" }] }, Password = Password }, Api.Json))
        {
            Assert.Equal(HttpStatusCode.OK, made.StatusCode);
            var info = await made.Content.ReadFromJsonAsync<AccountInfo>(Api.Json);
            Assert.Equal("alice", info!.Name);
            Assert.True(info.HasPassword);
        }
        await server.PutAsync("/dav/f.txt", "x");

        var accounts = await admin.GetFromJsonAsync<List<AccountInfo>>("/api/accounts", Api.Json);
        Assert.Equal("alice", Assert.Single(accounts!).Name);
        var text = await admin.GetStringAsync("/api/accounts");
        Assert.DoesNotContain("argon2", text);
        Assert.DoesNotContain(Password, text);

        // Changing the account without a password keeps the one it has.
        using (await admin.PutAsJsonAsync("/api/accounts", new AccountWrite { Account = new AccountInfo { Name = "alice", DisplayName = "Alice A.", Grants = [new GrantInfo { Mount = "/dav" }] } }, Api.Json)) { }
        Assert.Equal("x", await server.ReadAsync("/dav/f.txt"));

        // A new password replaces it at once, even though the old one was remembered for speed.
        using (await admin.PutAsJsonAsync("/api/accounts", new AccountWrite { Account = new AccountInfo { Name = "alice", Grants = [new GrantInfo { Mount = "/dav" }] }, Password = NewPassword }, Api.Json)) { }
        using (var old = await server.SendAsync("GET", "/dav/f.txt")) Assert.Equal(HttpStatusCode.Unauthorized, old.StatusCode);

        // Taking the account away leaves its files.
        using (var deleted = await admin.DeleteAsync("/api/accounts?name=alice")) Assert.Equal(HttpStatusCode.NoContent, deleted.StatusCode);
        Assert.True(File.Exists(Path.Combine(server.Folder, "files", "users", "alice", "f.txt")));
    }

    [Theory]
    [InlineData("../evil", "correct horse battery")]
    [InlineData("alice", "short")]
    [InlineData("con", "correct horse battery")]
    public async Task BadAccountsAreRefused(string name, string password)
    {
        await ReadyAsync();
        using var made = await admin.PutAsJsonAsync("/api/accounts", new AccountWrite { Account = new AccountInfo { Name = name }, Password = password }, Api.Json);
        Assert.Equal(HttpStatusCode.BadRequest, made.StatusCode);
    }

    [Fact]
    public async Task BadWhitelistsAreRefused()
    {
        await ReadyAsync();
        using (var account = await admin.PutAsJsonAsync("/api/accounts", new AccountWrite { Account = new AccountInfo { Name = "alice", Whitelist = ["nonsense"] }, Password = Password }, Api.Json))
        {
            Assert.Equal(HttpStatusCode.BadRequest, account.StatusCode);
        }
        using var settings = await admin.PutAsJsonAsync("/api/settings", new ServerSettings { Whitelist = ["nonsense"] }, Api.Json);
        Assert.Equal(HttpStatusCode.BadRequest, settings.StatusCode);
    }

    [Fact]
    public async Task AccountsCanOnlyGoWhereThereArePaths()
    {
        await ReadyAsync();
        using var made = await admin.PutAsJsonAsync("/api/accounts", new AccountWrite { Account = new AccountInfo { Name = "alice", Grants = [new GrantInfo { Mount = "/nowhere" }] }, Password = Password }, Api.Json);
        Assert.Equal(HttpStatusCode.BadRequest, made.StatusCode);
    }

    [Fact]
    public async Task NobodySavesAWhitelistThatShutsThemOut()
    {
        await ReadyAsync();
        using (var shut = await admin.PutAsJsonAsync("/api/settings", new ServerSettings { AdminWhitelist = ["203.0.113.0/24"] }, Api.Json)) Assert.Equal(HttpStatusCode.Conflict, shut.StatusCode);
        using (var fine = await admin.PutAsJsonAsync("/api/settings", new ServerSettings { AdminWhitelist = ["127.0.0.1"] }, Api.Json)) Assert.Equal(HttpStatusCode.NoContent, fine.StatusCode);
        using (var status = await admin.GetAsync("/api/status")) Assert.Equal(HttpStatusCode.OK, status.StatusCode);
    }

    [Fact]
    public async Task OutsideTheAdminWhitelistTheSocketClosesAndABanFollows()
    {
        server.ChangeSettings(settings => settings with { AdminWhitelist = ["203.0.113.0/24"] });
        var port = new Uri(server.App.AdminAddress).Port;
        var (answer, closed) = await server.RawAsync("", port);
        Assert.Equal("", answer);
        Assert.True(closed);
        Assert.Equal("admin", Assert.Single(server.App.Guard.Bans()).Scope);
    }

    [Fact]
    public async Task NobodyBansThemselvesFromHere()
    {
        await ReadyAsync();
        using var ban = await admin.PostAsJsonAsync("/api/bans", new BanWrite { Network = "127.0.0.0/8", Scope = "admin" }, Api.Json);
        Assert.Equal(HttpStatusCode.Conflict, ban.StatusCode);
    }

    [Fact]
    public async Task Paths()
    {
        await ReadyAsync();
        using (var made = await admin.PutAsJsonAsync("/api/mounts", new MountInfo { Path = "/team", Layout = StorageLayout.Path, MaxFailures = 2 }, Api.Json)) Assert.Equal(HttpStatusCode.NoContent, made.StatusCode);
        var mounts = await admin.GetFromJsonAsync<List<MountInfo>>("/api/mounts", Api.Json);
        Assert.Contains(mounts!, mount => mount.Path == "/team" && mount.Layout == StorageLayout.Path && mount.MaxFailures == 2);

        foreach (var bad in new[] { "/remote.php", "/a/b", "team", "/ocs" })
        {
            using var refused = await admin.PutAsJsonAsync("/api/mounts", new MountInfo { Path = bad }, Api.Json);
            Assert.Equal(HttpStatusCode.BadRequest, refused.StatusCode);
        }

        using (await admin.PutAsJsonAsync("/api/accounts", new AccountWrite { Account = new AccountInfo { Name = "alice", Grants = [new GrantInfo { Mount = "/team" }] }, Password = Password }, Api.Json)) { }
        using (var inUse = await admin.DeleteAsync("/api/mounts?path=/team")) Assert.Equal(HttpStatusCode.Conflict, inUse.StatusCode);
        using (await admin.PutAsJsonAsync("/api/accounts", new AccountWrite { Account = new AccountInfo { Name = "alice" } }, Api.Json)) { }
        using (var deleted = await admin.DeleteAsync("/api/mounts?path=/team")) Assert.Equal(HttpStatusCode.NoContent, deleted.StatusCode);
    }

    [Fact]
    public async Task APathCantServeTheServersOwnData()
    {
        await ReadyAsync();
        foreach (var bad in new[] { server.Folder, Path.Combine(server.Folder, "tls"), Path.GetPathRoot(server.Folder)!, "relative/path", Path.GetDirectoryName(server.Folder)! })
        {
            using var refused = await admin.PutAsJsonAsync("/api/mounts", new MountInfo { Path = "/x", Root = bad }, Api.Json);
            Assert.Equal(HttpStatusCode.BadRequest, refused.StatusCode);
        }
        using var fine = await admin.PutAsJsonAsync("/api/mounts", new MountInfo { Path = "/x", Root = Path.Combine(server.Folder + "-elsewhere", "x") }, Api.Json);
        Assert.Equal(HttpStatusCode.NoContent, fine.StatusCode);
    }

    [Fact]
    public async Task Bans()
    {
        await ReadyAsync();
        using (var made = await admin.PostAsJsonAsync("/api/bans", new BanWrite { Network = "198.51.100.0/24", Scope = "*", Reason = "Scanning", Minutes = 60 }, Api.Json)) Assert.Equal(HttpStatusCode.NoContent, made.StatusCode);
        Assert.True(server.App.Guard.IsBanned(IPAddress.Parse("198.51.100.77"), "*"));
        var bans = await admin.GetFromJsonAsync<List<BanInfo>>("/api/bans", Api.Json);
        Assert.Equal("198.51.100.0/24", Assert.Single(bans!).Network);
        using (var lifted = await admin.DeleteAsync("/api/bans?network=198.51.100.0/24&scope=*")) Assert.Equal(HttpStatusCode.NoContent, lifted.StatusCode);
        Assert.False(server.App.Guard.IsBanned(IPAddress.Parse("198.51.100.77"), "*"));
    }

    [Fact]
    public async Task IPv6IsBannedByItsNetwork()
    {
        server.App.Guard.Ban(IPAddress.Parse("2001:db8:1:2:3:4:5:6"), "*", TimeSpan.FromHours(1), "Test.");
        Assert.True(server.App.Guard.IsBanned(IPAddress.Parse("2001:db8:1:2:ffff::1"), "*"));
        Assert.False(server.App.Guard.IsBanned(IPAddress.Parse("2001:db8:1:3::1"), "*"));
        await ReadyAsync();
        var bans = await admin.GetFromJsonAsync<List<BanInfo>>("/api/bans", Api.Json);
        Assert.Equal("2001:db8:1:2::/64", Assert.Single(bans!).Network);
    }

    [Fact]
    public async Task AppPasswordsFromTheWindow()
    {
        await ReadyAsync();
        server.AddAccount("alice", new GrantInfo { Mount = "/dav" });
        using var made = await admin.PostAsJsonAsync("/api/app-passwords", new AppPasswordRequest { Account = "alice", Name = "laptop" }, Api.Json);
        var created = await made.Content.ReadFromJsonAsync<AppPasswordCreated>(Api.Json);
        using (var used = await server.SendAsync("PROPFIND", "/dav/", password: created!.Password, headers: ("Depth", "0"))) Assert.Equal((HttpStatusCode)207, used.StatusCode);

        // It isn't given out again.
        Assert.DoesNotContain(created.Password, await admin.GetStringAsync("/api/accounts"));

        using (var taken = await admin.DeleteAsync($"/api/app-passwords?account=alice&id={created.Info.Id}")) Assert.Equal(HttpStatusCode.NoContent, taken.StatusCode);
        using var after = await server.SendAsync("PROPFIND", "/dav/", password: created.Password, headers: ("Depth", "0"));
        Assert.Equal(HttpStatusCode.Unauthorized, after.StatusCode);
    }

    [Fact]
    public async Task TheLogKeepsNoSecrets()
    {
        server.AddAccount("alice", new GrantInfo { Mount = "/dav" });
        using (await server.SendAsync("PROPFIND", "/dav/", password: "a wrong password", headers: ("Depth", "0"))) { }
        using (await server.SendAsync("PROPFIND", "/dav/", headers: ("Depth", "0"))) { }
        await ReadyAsync();
        var text = await admin.GetStringAsync("/api/log?limit=100");
        Assert.Contains("login-failed", text);
        Assert.DoesNotContain("a wrong password", text);
        Assert.DoesNotContain(Password, text);
        Assert.DoesNotContain(NewPassword, text);
    }

    [Fact]
    public async Task WarningsSayWhatsWrong()
    {
        await ReadyAsync();
        await server.RawAsync(RawGet("/dav/", null, "X-Forwarded-For: 203.0.113.5", "Connection: close"));
        using (await admin.PutAsJsonAsync("/api/settings", new ServerSettings { Whitelist = ["CA", "127.0.0.1"] }, Api.Json)) { }
        var status = await admin.GetFromJsonAsync<StatusInfo>("/api/status", Api.Json);
        Assert.Contains(status!.Warnings, warning => warning.Contains("trusted proxy"));
        Assert.Contains(status.Warnings, warning => warning.Contains("DB-IP"));
        Assert.Contains(status.Warnings, warning => warning.Contains("no accounts"));
    }

    [Fact]
    public async Task TheAdminPortIsAlwaysTls()
    {
        Assert.StartsWith("https://", server.App.AdminAddress);
        var port = new Uri(server.App.AdminAddress).Port;
        var (answer, _) = await server.RawAsync("GET /api/status HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n", port);
        Assert.DoesNotContain("version", answer);
        Assert.DoesNotContain("200 OK", answer);
    }

    [Fact]
    public async Task HeadersOnTheAdminPort()
    {
        using var response = await admin.GetAsync("/api/status");
        Assert.Equal("no-store", response.Headers.CacheControl?.ToString());
        Assert.False(response.Headers.Contains("Server"));
    }

    [Fact]
    public async Task ThePasswordsAreOnlyHashesInTheDatabase()
    {
        await ReadyAsync();
        server.AddAccount("alice", new GrantInfo { Mount = "/dav" });
        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
        var bytes = await File.ReadAllBytesAsync(Path.Combine(server.Folder, "webdav-server.db"));
        var text = System.Text.Encoding.Latin1.GetString(bytes);
        Assert.DoesNotContain(NewPassword, text);
        Assert.DoesNotContain(Password, text);
    }

    [Fact]
    public async Task ACertificateKeepsItsFingerprintAcrossARestart()
    {
        var before = Network.TlsCertificates.Fingerprint(server.App.AdminCertificate.Current());
        var again = new Network.TlsCertificates("", "", server.Folder, "admin");
        Assert.Equal(before, Network.TlsCertificates.Fingerprint(again.Current()));
        Assert.Equal(64, before.Length);
        await Task.CompletedTask;
    }

    [Fact]
    public async Task JsonThatCantBeReadIsSaidToBe()
    {
        await ReadyAsync();
        using var response = await admin.PutAsync("/api/settings", new StringContent("{nonsense", System.Text.Encoding.UTF8, "application/json"));
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Contains("couldn't be read", JsonDocument.Parse(await response.Content.ReadAsStringAsync()).RootElement.GetProperty("error").GetString());
    }
}
