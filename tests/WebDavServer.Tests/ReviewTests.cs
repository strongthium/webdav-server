using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using Strongthium.WebDavServer.Security;
using Strongthium.WebDavServer.Storage;
using static Strongthium.WebDavServer.Tests.TestServer;

namespace Strongthium.WebDavServer.Tests;

/// <summary>Attacks that an adversarial read of the code found, each kept here so that it stays fixed.</summary>
public sealed partial class ReviewTests : IAsyncLifetime
{
    private TestServer server = null!;

    public async ValueTask InitializeAsync()
    {
        server = await StartAsync();
        server.AddAccount("alice", new GrantInfo { Mount = "/dav" });
    }

    public ValueTask DisposeAsync() => server.DisposeAsync();

    private static FormUrlEncodedContent Form(params (string Name, string Value)[] fields) => new(fields.Select(field => new KeyValuePair<string, string>(field.Name, field.Value)));

    private async Task<HttpResponseMessage> PostLoginAsync(string path, string user, string password, params (string Name, string Value)[] headers)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, server.Url + path) { Content = Form(("user", user), ("password", password)) };
        foreach (var (name, value) in headers) request.Headers.TryAddWithoutValidation(name, value);
        return await server.Http.SendAsync(request);
    }

    // ---- A web page getting its visitors banned --------------------------------------------------------------------

    [Theory]
    [InlineData("Sec-Fetch-Site", "cross-site")]
    [InlineData("Sec-Fetch-Site", "same-site")]
    [InlineData("Origin", "https://evil.example")]
    [InlineData("Origin", "null")]
    public async Task APostFromAnotherSiteIsntALogin(string header, string value)
    {
        server.AddAccount(new AccountInfo { Name = "carol", Whitelist = ["203.0.113.0/24"], Grants = [new GrantInfo { Mount = "/dav" }] });
        for (var i = 0; i < 10; i++)
        {
            using var response = await PostLoginAsync("/index.php/login/flow", "carol", "x", (header, value));
            Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        }
        Assert.Empty(server.App.Guard.Bans());
        Assert.DoesNotContain(server.State.Database.ReadLog(100, null), entry => entry.Kind == "login-failed");
    }

    [Fact]
    public async Task APostFromAnotherSiteCantUseTheFlowsOwnAddressEither()
    {
        using var client = new HttpClient(new SocketsHttpHandler { UseProxy = false });
        using var started = await client.PostAsync(server.Url + "/index.php/login/v2", null);
        var login = JsonDocument.Parse(await started.Content.ReadAsStringAsync()).RootElement.GetProperty("login").GetString()!;
        using var response = await PostLoginAsync(new Uri(login).AbsolutePath, "alice", "x", ("Sec-Fetch-Site", "cross-site"));
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Theory]
    [InlineData("Sec-Fetch-Site", "same-origin")]
    [InlineData("Sec-Fetch-Site", "none")]
    public async Task APostFromTheLoginPageItselfIsFine(string header, string value)
    {
        using var response = await PostLoginAsync("/index.php/login/flow", "alice", Password, (header, value));
        Assert.Equal(HttpStatusCode.SeeOther, response.StatusCode);
    }

    [Fact]
    public async Task AnOriginOfThisServerIsFine()
    {
        using var response = await PostLoginAsync("/index.php/login/flow", "alice", Password, ("Origin", server.Url));
        Assert.Equal(HttpStatusCode.SeeOther, response.StatusCode);
    }

    // ---- An app password outliving being taken away ------------------------------------------------------------------

    [Fact]
    public async Task TheLoginPageDoesntMakeAnAppPasswordFromAnAppPassword()
    {
        var leaked = Passwords.NewAppPassword();
        server.State.Database.AddAppPassword("alice", "phone", Passwords.HashAppPassword(leaked), server.Clock.Now);
        server.State.Reload();

        using var response = await PostLoginAsync("/index.php/login/flow", "alice", leaked);
        Assert.Equal(HttpStatusCode.SeeOther, response.StatusCode);
        Assert.EndsWith($"password:{leaked}", response.Headers.Location!.OriginalString);
        Assert.Single(server.State.Policy.Accounts["alice"].Info.AppPasswords);
    }

    [Fact]
    public async Task TheLoginPageStillMakesOneFromThePassword()
    {
        using var response = await PostLoginAsync("/index.php/login/flow", "alice", Password);
        Assert.DoesNotContain(Password, response.Headers.Location!.OriginalString);
        Assert.Single(server.State.Policy.Accounts["alice"].Info.AppPasswords);
    }

    // ---- A ban goes by the path reached ------------------------------------------------------------------------------

    [Fact]
    public async Task ABanFromAPathHoldsThroughNextcloudsAddresses()
    {
        server.AddMount(new MountInfo { Path = "/team", Layout = StorageLayout.Path, MaxFailures = 2 });
        server.AddAccount(new AccountInfo { Name = "alice", HomeMount = "/team", Grants = [new GrantInfo { Mount = "/team" }, new GrantInfo { Mount = "/dav" }] });
        await server.PutAsync("/team/secret.txt", "x");
        await server.PutAsync("/dav/mine.txt", "y");

        using (await server.SendAsync("PROPFIND", "/team/", password: "wrong password here", headers: ("Depth", "0"))) { }
        await Assert.ThrowsAsync<HttpRequestException>(() => server.SendAsync("PROPFIND", "/team/", password: "wrong password here", headers: ("Depth", "0")));

        // The top of the server leads to the same files, and has to be just as shut.
        await Assert.ThrowsAsync<HttpRequestException>(() => server.SendAsync("GET", "/remote.php/webdav/secret.txt"));
        await Assert.ThrowsAsync<HttpRequestException>(() => server.SendAsync("GET", "/remote.php/dav/files/alice/secret.txt"));
        await Assert.ThrowsAsync<HttpRequestException>(() => server.SendAsync("MKCOL", "/remote.php/dav/uploads/alice/x"));

        // And it can't be copied into from a path that's still open.
        using var copied = await server.SendAsync("COPY", "/dav/mine.txt", headers: ("Destination", "/team/mine.txt"));
        Assert.Equal(HttpStatusCode.Forbidden, copied.StatusCode);
    }

    [Fact]
    public async Task FailuresAddUpAcrossPaths()
    {
        server.ChangeSettings(settings => settings with { MaxFailuresAllPaths = 6 });
        foreach (var path in new[] { "/a", "/b", "/c" })
        {
            server.AddMount(new MountInfo { Path = path, Layout = StorageLayout.Path, MaxFailures = 0 });
        }
        var tries = 0;
        try
        {
            for (; tries < 20; tries++)
            {
                using var response = await server.SendAsync("PROPFIND", new[] { "/a/", "/b/", "/c/" }[tries % 3], password: "wrong password here", headers: ("Depth", "0"));
            }
        }
        catch (HttpRequestException)
        {
            // Cut off.
        }
        Assert.Equal(5, tries);
        var ban = Assert.Single(server.App.Guard.Bans());
        Assert.Equal("*", ban.Scope);
        Assert.Contains("across all paths", ban.Reason);
    }

    [Fact]
    public async Task TheAdminPortIsntPartOfTheCountAcrossPaths()
    {
        server.ChangeSettings(settings => settings with { MaxFailuresAllPaths = 2 });
        Assert.False(server.App.Guard.LoginFailed(IPAddress.Parse("198.51.100.1"), Scopes.Admin, ""));
        Assert.False(server.App.Guard.LoginFailed(IPAddress.Parse("198.51.100.1"), Scopes.Admin, ""));
        Assert.False(server.App.Guard.IsBanned(IPAddress.Parse("198.51.100.1"), Scopes.All));
        await Task.CompletedTask;
    }

    [Fact]
    public async Task AHomeWithNextcloudOffIsntServedToNextcloudClients()
    {
        server.AddMount(new MountInfo { Path = "/plain", Layout = StorageLayout.Path, Nextcloud = false });
        server.AddAccount(new AccountInfo { Name = "alice", HomeMount = "/plain", Grants = [new GrantInfo { Mount = "/plain" }] });
        await server.PutAsync("/plain/f.txt", "x");
        using var response = await server.SendAsync("GET", "/remote.php/webdav/f.txt");
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    // ---- Unfinished uploads ------------------------------------------------------------------------------------------

    [Fact]
    public async Task AnUploadIsNobodyElsesOnASharedPath()
    {
        server.AddMount(new MountInfo { Path = "/team", Layout = StorageLayout.Path });
        server.AddAccount(new AccountInfo { Name = "alice", HomeMount = "/team", Grants = [new GrantInfo { Mount = "/team" }] });
        server.AddAccount(new AccountInfo { Name = "bob", HomeMount = "/team", Grants = [new GrantInfo { Mount = "/team" }] });

        using (var made = await server.SendAsync("MKCOL", "/remote.php/dav/uploads/alice/shared-id")) Assert.Equal(HttpStatusCode.Created, made.StatusCode);
        using (await server.SendAsync("PUT", "/remote.php/dav/uploads/alice/shared-id/1", body: "alice's")) { }

        // Bob, knowing the id, gets nothing of hers: his own folder of that name, or nothing.
        using (var put = await server.SendAsync("PUT", "/remote.php/dav/uploads/bob/shared-id/1", "bob", "bob's")) Assert.Equal(HttpStatusCode.NotFound, put.StatusCode);
        using (var delete = await server.SendAsync("DELETE", "/remote.php/dav/uploads/bob/shared-id", "bob")) Assert.Equal(HttpStatusCode.NoContent, delete.StatusCode);

        using var moved = await server.SendAsync("MOVE", "/remote.php/dav/uploads/alice/shared-id/.file", headers: ("Destination", "/remote.php/dav/files/alice/done.txt"));
        Assert.Equal(HttpStatusCode.Created, moved.StatusCode);
        Assert.Equal("alice's", await server.ReadAsync("/team/done.txt"));
    }

    [Fact]
    public async Task AnotherUploadDoesntGetTheWholeQuotaAgain()
    {
        const string uploads = "/remote.php/dav/uploads/alice";
        server.AddAccount(new AccountInfo { Name = "alice", QuotaBytes = 10, Grants = [new GrantInfo { Mount = "/dav" }] });
        using (await server.SendAsync("MKCOL", $"{uploads}/one")) { }
        using (await server.SendAsync("MKCOL", $"{uploads}/two")) { }
        using (var first = await server.SendAsync("PUT", $"{uploads}/one/1", body: "12345678")) Assert.Equal(HttpStatusCode.Created, first.StatusCode);
        using var second = await server.SendAsync("PUT", $"{uploads}/two/1", body: "12345678");
        Assert.Equal((HttpStatusCode)507, second.StatusCode);
    }

    [Fact]
    public async Task TheLargestUploadHoldsForChunksTogether()
    {
        const string uploads = "/remote.php/dav/uploads/alice";
        server.ChangeSettings(settings => settings with { MaxUploadBytes = 10 });
        using (await server.SendAsync("MKCOL", $"{uploads}/big")) { }
        using (var first = await server.SendAsync("PUT", $"{uploads}/big/1", body: "12345678")) Assert.Equal(HttpStatusCode.Created, first.StatusCode);
        using var second = await server.SendAsync("PUT", $"{uploads}/big/2", body: "12345678");
        Assert.Equal(HttpStatusCode.RequestEntityTooLarge, second.StatusCode);
    }

    [Theory]
    [InlineData("NUL")]
    [InlineData("com1")]
    public async Task UploadIdsCantBeDevices(string name)
    {
        if (!OperatingSystem.IsWindows()) Assert.Skip("Only Windows has device names.");
        using var response = await server.SendAsync("MKCOL", $"/remote.php/dav/uploads/alice/{name}");
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    // ---- Windows' short names ----------------------------------------------------------------------------------------

    [LibraryImport("kernel32.dll", StringMarshalling = StringMarshalling.Utf16)]
    private static partial uint GetShortPathNameW(string longPath, [Out] char[] shortPath, uint size);

    private static string? ShortNameOf(string path)
    {
        if (!OperatingSystem.IsWindows()) return null;
        var buffer = new char[1024];
        var length = GetShortPathNameW(path, buffer, (uint)buffer.Length);
        var name = Path.GetFileName(new string(buffer, 0, (int)length));
        return name.Contains('~') ? name : null;
    }

    [Fact]
    public async Task TheServersOwnFolderCantBeReachedByItsShortName()
    {
        await server.PutAsync("/dav/seed.txt", "x");
        using (await server.SendAsync("MKCOL", "/remote.php/dav/uploads/alice/hidden")) { }
        var hidden = Path.Combine(server.Folder, "files", "users", "alice", PathRules.Hidden);
        var alias = ShortNameOf(hidden);
        if (alias is null) Assert.Skip("This disk doesn't make short names.");

        using var listed = await server.SendAsync("PROPFIND", $"/dav/{alias}/", headers: ("Depth", "1"));
        Assert.Equal(HttpStatusCode.NotFound, listed.StatusCode);
        using var written = await server.SendAsync("PUT", $"/dav/{alias}/planted.txt", body: "x");
        Assert.NotEqual(HttpStatusCode.Created, written.StatusCode);
        Assert.False(File.Exists(Path.Combine(hidden, "planted.txt")));
    }

    [Fact]
    public async Task AFileCantBeReachedByItsShortNameToGetRoundALock()
    {
        await server.PutAsync("/dav/a%20long%20file%20name.document", "x");
        var alias = ShortNameOf(Path.Combine(server.Folder, "files", "users", "alice", "a long file name.document"));
        if (alias is null) Assert.Skip("This disk doesn't make short names.");
        using var response = await server.SendAsync("GET", $"/dav/{alias}");
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    [Fact]
    public async Task AnOrdinaryNameWithATildeIsFine()
    {
        await server.PutAsync("/dav/notes~1.txt", "x");
        await server.PutAsync("/dav/backup~", "y");
        Assert.Equal("x", await server.ReadAsync("/dav/notes~1.txt"));
        Assert.Equal("y", await server.ReadAsync("/dav/backup~"));
    }

    // ---- A path serving the server's own data -------------------------------------------------------------------------

    [Fact]
    public void RealPathsSeeThroughHowTheyreWritten()
    {
        Assert.Equal(RealPath.Of(server.Folder), RealPath.Of(Path.Combine(server.Folder, "tls", "..")));
        if (ShortNameOf(Path.GetDirectoryName(Path.Combine(server.Folder, "tls"))!) is { } alias)
            Assert.Equal(RealPath.Of(server.Folder), RealPath.Of(Path.Combine(Path.GetDirectoryName(server.Folder)!, alias)));
    }

    [Fact]
    public async Task APathCantServeTheServersDataHoweverItsWritten()
    {
        var handler = new SocketsHttpHandler { UseProxy = false };
        handler.SslOptions.RemoteCertificateValidationCallback = (_, _, _, _) => true;
        using var admin = new HttpClient(handler) { BaseAddress = new Uri(server.App.AdminAddress) };
        using (var login = await admin.PostAsJsonAsync("/api/login", new LoginRequest { UserName = "admin", Password = "admin" }, Api.Json))
        {
            admin.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", (await login.Content.ReadFromJsonAsync<LoginResponse>(Api.Json))!.Token);
        }
        using (var changed = await admin.PostAsJsonAsync("/api/password", new ChangePasswordRequest { CurrentPassword = "admin", NewPassword = "a much better password" }, Api.Json))
        {
            admin.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", (await changed.Content.ReadFromJsonAsync<LoginResponse>(Api.Json))!.Token);
        }

        var bad = new List<string>
        {
            Path.Combine(server.Folder, "files"),
            Path.Combine(server.Folder, "files", "users"),
        };
        if (OperatingSystem.IsWindows())
        {
            bad.Add(@"\\?\" + server.Folder);
            bad.Add(@"\\localhost\C$\" + server.Folder[3..]);
        }
        var link = server.Folder + "-link";
        try
        {
            try
            {
                Directory.CreateSymbolicLink(link, server.Folder);
                bad.Add(link);
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
            {
                // This account can't make links. Those that can are covered by the rest.
            }
            foreach (var root in bad)
            {
                using var refused = await admin.PutAsJsonAsync("/api/mounts", new MountInfo { Path = "/x", Layout = StorageLayout.Path, Root = root }, Api.Json);
                Assert.Equal(HttpStatusCode.BadRequest, refused.StatusCode);
            }
        }
        finally
        {
            if (Directory.Exists(link)) Directory.Delete(link);
        }
    }

    [Fact]
    public async Task PathsNamedRootDontShareWithTheTop()
    {
        server.AddMount(new MountInfo { Path = "/", Layout = StorageLayout.Path });
        server.AddMount(new MountInfo { Path = "/root", Layout = StorageLayout.Path });
        server.AddAccount("alice", new GrantInfo { Mount = "/" }, new GrantInfo { Mount = "/root" });
        await server.PutAsync("/at-the-top.txt", "x");
        using var response = await server.SendAsync("GET", "/root/at-the-top.txt");
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    // ---- Smaller things ----------------------------------------------------------------------------------------------

    [Fact]
    public async Task ALineBreakInANameDoesntWriteAFalseLineInTheLog()
    {
        var lines = new List<string>();
        server.State.LogLine = lines.Add;
        var header = "Basic " + Convert.ToBase64String(Encoding.UTF8.GetBytes("x\nban 1.2.3.4 forged:password"));
        var (answer, _) = await server.RawAsync($"GET /dav/ HTTP/1.1\r\nHost: test\r\nConnection: close\r\nAuthorization: {header}\r\n\r\n");
        Assert.StartsWith("HTTP/1.1 401", answer);
        Assert.DoesNotContain(lines, line => line.Contains('\n'));
        Assert.DoesNotContain(server.State.Database.ReadLog(100, null), entry => entry.Account.Contains('\n') || entry.Account.Contains("forged"));
    }

    [Fact]
    public void WhatsLoggedHasNoControlCharacters()
    {
        var lines = new List<string>();
        server.State.LogLine = lines.Add;
        server.State.Log("test", null, "a\nb", "", "c\r\nd");
        Assert.Equal("test  a?b  c??d", lines.Single());
    }

    [Fact]
    public async Task NoEndOfFailedLoginsFillsTheLog()
    {
        for (var i = 0; i < 200; i++) server.App.Guard.LoginFailed(IPAddress.Parse($"198.51.100.{i % 250}"), "/dav", "x");
        Assert.Equal(60, server.State.Database.ReadLog(1000, "login-failed").Count);
        server.Clock.Now = server.Clock.Now.AddMinutes(2);
        server.App.Guard.LoginFailed(IPAddress.Parse("198.51.100.1"), "/dav", "x");
        Assert.Equal(61, server.State.Database.ReadLog(1000, "login-failed").Count);
        await Task.CompletedTask;
    }

    [Fact]
    public async Task NobodyStartsAllTheLoginsThereAre()
    {
        using var client = new HttpClient(new SocketsHttpHandler { UseProxy = false });
        var statuses = new List<HttpStatusCode>();
        for (var i = 0; i < 20; i++)
        {
            using var response = await client.PostAsync(server.Url + "/index.php/login/v2", null);
            statuses.Add(response.StatusCode);
        }
        Assert.Equal(16, statuses.Count(status => status == HttpStatusCode.OK));
        Assert.Equal(4, statuses.Count(status => status == HttpStatusCode.ServiceUnavailable));
    }

    [Fact]
    public async Task AskingForVeryManyPropertiesIsRefused()
    {
        var props = string.Concat(Enumerable.Range(0, 300).Select(i => $"<d:p{i}/>"));
        using var response = await server.SendAsync("PROPFIND", "/dav/", body: $"""<d:propfind xmlns:d="DAV:"><d:prop>{props}</d:prop></d:propfind>""", headers: ("Depth", "0"));
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task AGuessThatTurnsOutRightAfterABanDoesntCount()
    {
        // Cached here, so it's fast, but it's what a slow one finding a ban made while it ran comes to as well.
        (await server.SendAsync("PROPFIND", "/dav/", headers: ("Depth", "0"))).Dispose();
        server.App.Guard.Ban(IPAddress.Loopback, "/dav", TimeSpan.FromHours(1), "Test.");
        await Assert.ThrowsAsync<HttpRequestException>(() => server.SendAsync("PROPFIND", "/dav/", headers: ("Depth", "0")));
    }
}
