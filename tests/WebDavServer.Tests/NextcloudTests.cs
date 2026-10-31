using System.Net;
using System.Text.Json;
using static Strongthium.WebDavServer.Tests.TestServer;

namespace Strongthium.WebDavServer.Tests;

/// <summary>What a Nextcloud client does, on the same address and files as WebDAV.</summary>
public sealed class NextcloudTests : IAsyncLifetime
{
    private TestServer server = null!;

    public async ValueTask InitializeAsync()
    {
        server = await StartAsync();
        server.AddAccount("alice", new GrantInfo { Mount = "/dav" });
    }

    public ValueTask DisposeAsync() => server.DisposeAsync();

    private async Task<JsonElement> Json(string path, string? user = "alice", params (string, string)[] headers)
    {
        using var response = await server.SendAsync("GET", path, user, headers: headers);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        return JsonDocument.Parse(await response.Content.ReadAsStringAsync()).RootElement.Clone();
    }

    [Fact]
    public async Task StatusSaysItsInstalled()
    {
        var status = await Json("/status.php", null);
        Assert.True(status.GetProperty("installed").GetBoolean());
        Assert.False(status.GetProperty("maintenance").GetBoolean());
        Assert.False(string.IsNullOrEmpty(status.GetProperty("version").GetString()));
    }

    [Fact]
    public async Task Capabilities()
    {
        var capabilities = await Json("/ocs/v1.php/cloud/capabilities?format=json", null);
        var ocs = capabilities.GetProperty("ocs");
        Assert.Equal(100, ocs.GetProperty("meta").GetProperty("statuscode").GetInt32());
        Assert.Equal("1.0", ocs.GetProperty("data").GetProperty("capabilities").GetProperty("dav").GetProperty("chunking").GetString());
        var v2 = await Json("/ocs/v2.php/cloud/capabilities?format=json", null);
        Assert.Equal(200, v2.GetProperty("ocs").GetProperty("meta").GetProperty("statuscode").GetInt32());
    }

    [Fact]
    public async Task OcsAnswersInXmlToo()
    {
        using var response = await server.SendAsync("GET", "/ocs/v1.php/cloud/capabilities", null);
        var text = await response.Content.ReadAsStringAsync();
        Assert.Contains("<statuscode>100</statuscode>", text);
        Assert.Contains("<chunking>1.0</chunking>", text);
    }

    [Fact]
    public async Task TheUser()
    {
        var user = await Json("/ocs/v2.php/cloud/user?format=json", "alice", ("OCS-APIRequest", "true"));
        Assert.Equal("alice", user.GetProperty("ocs").GetProperty("data").GetProperty("id").GetString());
        Assert.True(user.GetProperty("ocs").GetProperty("data").GetProperty("quota").TryGetProperty("used", out _));
        using var anonymous = await server.SendAsync("GET", "/ocs/v2.php/cloud/user?format=json", null);
        Assert.Equal(HttpStatusCode.Unauthorized, anonymous.StatusCode);
    }

    [Fact]
    public async Task WhatsNotHereIsSaidCalmly()
    {
        using var response = await server.SendAsync("GET", "/ocs/v2.php/apps/notifications/api/v2/notifications?format=json");
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal(998, body.RootElement.GetProperty("ocs").GetProperty("meta").GetProperty("statuscode").GetInt32());
    }

    [Theory]
    [InlineData("/remote.php/webdav")]
    [InlineData("/remote.php/dav/files/alice")]
    [InlineData("/dav/remote.php/webdav")]
    [InlineData("/dav/remote.php/dav/files/alice")]
    public async Task TheSameFilesEitherWay(string baseAddress)
    {
        await server.PutAsync("/dav/from-webdav.txt", "plain");
        Assert.Equal("plain", await server.ReadAsync($"{baseAddress}/from-webdav.txt"));
        await server.PutAsync($"{baseAddress}/from-nextcloud.txt", "nc");
        Assert.Equal("nc", await server.ReadAsync("/dav/from-nextcloud.txt"));

        // Listings write addresses back the way they were asked for.
        var listing = await server.PropfindAsync($"{baseAddress}/", "1");
        Assert.Contains(listing.Descendants(D + "href"), href => href.Value == $"{baseAddress}/from-webdav.txt");

        // A lock from one holds against the other.
        const string lockInfo = """<d:lockinfo xmlns:d="DAV:"><d:lockscope><d:exclusive/></d:lockscope><d:locktype><d:write/></d:locktype></d:lockinfo>""";
        using (var locked = await server.SendAsync("LOCK", "/dav/from-webdav.txt", body: lockInfo)) Assert.Equal(HttpStatusCode.OK, locked.StatusCode);
        using var blocked = await server.SendAsync("PUT", $"{baseAddress}/from-webdav.txt", body: "x");
        Assert.Equal((HttpStatusCode)423, blocked.StatusCode);
    }

    [Fact]
    public async Task OnlyYourOwnFiles()
    {
        server.AddAccount("bob", new GrantInfo { Mount = "/dav" });
        await server.PutAsync("/dav/mine.txt", "x");
        using var response = await server.SendAsync("GET", "/remote.php/dav/files/alice/mine.txt", "bob");
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task ThePropertiesClientsAskFor()
    {
        await server.PutAsync("/dav/f.txt", "12345");
        var answer = await server.PropfindAsync("/remote.php/dav/files/alice/f.txt", "0", "<d:getetag/><oc:fileid/><oc:id/><oc:permissions/><oc:size/><nc:has-preview/>");
        Assert.Matches("^[0-9]+$", Prop(answer, OC + "fileid"));
        Assert.Contains("ocwebdavserver", Prop(answer, OC + "id"));
        Assert.Equal("GDNVW", Prop(answer, OC + "permissions"));
        Assert.Equal("5", Prop(answer, OC + "size"));
    }

    [Fact]
    public async Task AFileKeepsItsIdWhenItMoves()
    {
        await server.PutAsync("/dav/before.txt", "x");
        var id = Prop(await server.PropfindAsync("/dav/before.txt", "0", "<oc:fileid/>"), OC + "fileid");
        using (await server.SendAsync("MOVE", "/remote.php/webdav/before.txt", headers: ("Destination", server.Url + "/remote.php/webdav/after.txt"))) { }
        Assert.Equal(id, Prop(await server.PropfindAsync("/dav/after.txt", "0", "<oc:fileid/>"), OC + "fileid"));
    }

    [Fact]
    public async Task MovingFromOneAddressStyleToTheOther()
    {
        await server.PutAsync("/dav/a.txt", "x");
        using var moved = await server.SendAsync("MOVE", "/dav/a.txt", headers: ("Destination", "/remote.php/dav/files/alice/b.txt"));
        Assert.Equal(HttpStatusCode.Created, moved.StatusCode);
        Assert.Equal("x", await server.ReadAsync("/dav/b.txt"));
    }

    [Fact]
    public async Task ReservedNamesAreNotFiles()
    {
        // The names Nextcloud clients use can't be files at the top of a path that also serves them, or a file could stand in for the server.
        using var put = await server.SendAsync("PUT", "/dav/status.php", body: "<?php evil();");
        Assert.NotEqual(HttpStatusCode.Created, put.StatusCode);
        var status = await Json("/dav/status.php", null);
        Assert.True(status.GetProperty("installed").GetBoolean());
    }

    [Fact]
    public async Task WithNextcloudOffAPathIsOnlyWebDav()
    {
        server.AddMount(new MountInfo { Path = "/plain", Layout = StorageLayout.Path, Nextcloud = false });
        server.AddAccount("alice", new GrantInfo { Mount = "/plain" });
        await server.PutAsync("/plain/status.php", "just a file");
        Assert.Equal("just a file", await server.ReadAsync("/plain/status.php"));
    }

    // ---- The login flow ------------------------------------------------------------------------------------------

    private static FormUrlEncodedContent Form(params (string Name, string Value)[] fields) => new(fields.Select(field => new KeyValuePair<string, string>(field.Name, field.Value)));

    [Fact]
    public async Task LoginFlow()
    {
        using var client = new HttpClient(new SocketsHttpHandler { UseProxy = false, AllowAutoRedirect = false });
        client.DefaultRequestHeaders.UserAgent.ParseAdd("TestClient/1.0");

        using var started = await client.PostAsync(server.Url + "/index.php/login/v2", null);
        Assert.Equal(HttpStatusCode.OK, started.StatusCode);
        var flow = JsonDocument.Parse(await started.Content.ReadAsStringAsync()).RootElement;
        var pollUrl = flow.GetProperty("poll").GetProperty("endpoint").GetString()!;
        var token = flow.GetProperty("poll").GetProperty("token").GetString()!;
        var login = flow.GetProperty("login").GetString()!;
        Assert.StartsWith(server.Url, pollUrl);
        Assert.StartsWith(server.Url, login);

        // Nothing yet.
        using (var early = await client.PostAsync(pollUrl, Form(("token", token)))) Assert.Equal(HttpStatusCode.NotFound, early.StatusCode);

        using (var page = await client.GetAsync(login))
        {
            var html = await page.Content.ReadAsStringAsync();
            Assert.Contains("TestClient", html);
            Assert.Contains("If someone sent you this link", html);
            Assert.Contains("frame-ancestors 'none'", page.Headers.GetValues("Content-Security-Policy").Single());
        }

        using (var wrong = await client.PostAsync(login, Form(("user", "alice"), ("password", "wrong password here"))))
        {
            Assert.Contains("That name or password isn&#39;t right", await wrong.Content.ReadAsStringAsync());
        }
        using (var right = await client.PostAsync(login, Form(("user", "alice"), ("password", Password))))
        {
            Assert.Contains("Connected", await right.Content.ReadAsStringAsync());
        }

        using var polled = await client.PostAsync(pollUrl, Form(("token", token)));
        Assert.Equal(HttpStatusCode.OK, polled.StatusCode);
        var answer = JsonDocument.Parse(await polled.Content.ReadAsStringAsync()).RootElement;
        Assert.Equal(server.Url, answer.GetProperty("server").GetString());
        Assert.Equal("alice", answer.GetProperty("loginName").GetString());
        var appPassword = answer.GetProperty("appPassword").GetString()!;
        Assert.NotEqual(Password, appPassword);

        // It's handed over once, and it works.
        using (var again = await client.PostAsync(pollUrl, Form(("token", token)))) Assert.Equal(HttpStatusCode.NotFound, again.StatusCode);
        using (var used = await server.SendAsync("PROPFIND", "/remote.php/dav/files/alice/", password: appPassword, headers: ("Depth", "0"))) Assert.Equal((HttpStatusCode)207, used.StatusCode);

        var account = server.State.Policy.Accounts["alice"];
        Assert.Contains(account.Info.AppPasswords, item => item.Name.Contains("TestClient"));

        // Logging out takes it away.
        using (var logout = await server.SendAsync("DELETE", "/ocs/v2.php/core/apppassword", password: appPassword)) Assert.Equal(HttpStatusCode.OK, logout.StatusCode);
        using var after = await server.SendAsync("PROPFIND", "/remote.php/dav/files/alice/", password: appPassword, headers: ("Depth", "0"));
        Assert.Equal(HttpStatusCode.Unauthorized, after.StatusCode);
    }

    [Fact]
    public async Task TheLoginPageCountsFailuresLikeAnythingElse()
    {
        server.ChangeSettings(settings => settings with { MaxFailures = 2 });
        using var client = new HttpClient(new SocketsHttpHandler { UseProxy = false });
        using var started = await client.PostAsync(server.Url + "/index.php/login/v2", null);
        var login = JsonDocument.Parse(await started.Content.ReadAsStringAsync()).RootElement.GetProperty("login").GetString()!;
        using (await client.PostAsync(login, Form(("user", "alice"), ("password", "wrong password here")))) { }
        await Assert.ThrowsAsync<HttpRequestException>(() => client.PostAsync(login, Form(("user", "alice"), ("password", "wrong password here"))));
        Assert.Equal("/", Assert.Single(server.App.Guard.Bans()).Scope);
    }

    [Fact]
    public async Task TheLoginPageHoldsToAnAccountsWhitelist()
    {
        server.AddAccount(new AccountInfo { Name = "carol", Whitelist = ["203.0.113.0/24"], Grants = [new GrantInfo { Mount = "/dav" }] });
        using var client = new HttpClient(new SocketsHttpHandler { UseProxy = false });
        using var started = await client.PostAsync(server.Url + "/index.php/login/v2", null);
        var login = JsonDocument.Parse(await started.Content.ReadAsStringAsync()).RootElement.GetProperty("login").GetString()!;
        await Assert.ThrowsAsync<HttpRequestException>(() => client.PostAsync(login, Form(("user", "carol"), ("password", Password))));
        Assert.Equal("*", Assert.Single(server.App.Guard.Bans()).Scope);
    }

    [Fact]
    public async Task AnExpiredOrMadeUpLoginGetsNowhere()
    {
        using var made = await server.SendAsync("GET", "/index.php/login/v2/flow/0000", null);
        Assert.Equal(HttpStatusCode.NotFound, made.StatusCode);
        using var client = new HttpClient(new SocketsHttpHandler { UseProxy = false });
        using var started = await client.PostAsync(server.Url + "/index.php/login/v2", null);
        var login = JsonDocument.Parse(await started.Content.ReadAsStringAsync()).RootElement.GetProperty("login").GetString()!;
        server.Clock.Now = server.Clock.Now.AddMinutes(21);
        using var late = await client.GetAsync(login);
        Assert.Equal(HttpStatusCode.NotFound, late.StatusCode);
    }

    [Fact]
    public async Task ThePublicAddressIsUsedWhenThereIsOne()
    {
        server.ChangeSettings(settings => settings with { PublicUrl = "https://files.example.com" });
        using var client = new HttpClient(new SocketsHttpHandler { UseProxy = false });
        using var started = await client.PostAsync(server.Url + "/index.php/login/v2", null);
        var flow = JsonDocument.Parse(await started.Content.ReadAsStringAsync()).RootElement;
        Assert.StartsWith("https://files.example.com/index.php/login/v2/poll", flow.GetProperty("poll").GetProperty("endpoint").GetString());
    }

    [Fact]
    public async Task AnAppPasswordCantMakeAnother()
    {
        using var first = await server.SendAsync("GET", "/ocs/v2.php/core/getapppassword?format=json", headers: ("OCS-APIRequest", "true"));
        Assert.Equal(HttpStatusCode.OK, first.StatusCode);
        var password = JsonDocument.Parse(await first.Content.ReadAsStringAsync()).RootElement.GetProperty("ocs").GetProperty("data").GetProperty("apppassword").GetString()!;
        using var second = await server.SendAsync("GET", "/ocs/v2.php/core/getapppassword?format=json", password: password, headers: ("OCS-APIRequest", "true"));
        Assert.Equal(HttpStatusCode.Forbidden, second.StatusCode);
    }

    // ---- Chunked uploads -----------------------------------------------------------------------------------------

    private const string Uploads = "/remote.php/dav/uploads/alice";

    [Fact]
    public async Task ChunkedUpload()
    {
        const string id = "web-file-upload-1234";
        using (var made = await server.SendAsync("MKCOL", $"{Uploads}/{id}")) Assert.Equal(HttpStatusCode.Created, made.StatusCode);
        // Numbers in the order of their value: 2 before 10.
        var chunks = new[] { (1, "one-"), (2, "two-"), (10, "ten") };
        foreach (var (number, content) in chunks)
        {
            using var put = await server.SendAsync("PUT", $"{Uploads}/{id}/{number}", body: content, headers: [("Destination", server.Url + "/remote.php/dav/files/alice/big.bin"), ("OC-Total-Length", "11")]);
            Assert.Equal(HttpStatusCode.Created, put.StatusCode);
        }

        var listing = await server.PropfindAsync($"{Uploads}/{id}/", "1");
        Assert.Equal(4, listing.Elements(D + "response").Count());

        using (var moved = await server.SendAsync("MOVE", $"{Uploads}/{id}/.file", headers: [("Destination", server.Url + "/remote.php/dav/files/alice/big.bin"), ("OC-Total-Length", "11"), ("X-OC-Mtime", "1000000000")]))
        {
            Assert.Equal(HttpStatusCode.Created, moved.StatusCode);
            Assert.NotNull(moved.Headers.ETag);
            Assert.True(moved.Headers.Contains("OC-FileId"));
            Assert.Equal("accepted", moved.Headers.GetValues("X-OC-MTime").Single());
        }
        Assert.Equal("one-two-ten", await server.ReadAsync("/dav/big.bin"));
        Assert.Contains("2001", Prop(await server.PropfindAsync("/dav/big.bin"), D + "getlastmodified"));

        // The chunks are gone, and were never in anyone's sight.
        Assert.Empty(Directory.GetFileSystemEntries(Path.Combine(server.Folder, "files", "users", "alice", ".webdav-server", "uploads-alice")));
        var top = await server.PropfindAsync("/dav/", "1");
        Assert.DoesNotContain(top.Descendants(D + "href"), href => href.Value.Contains("uploads"));
    }

    [Fact]
    public async Task ChunksMustAddUp()
    {
        using (await server.SendAsync("MKCOL", $"{Uploads}/x1")) { }
        using (await server.SendAsync("PUT", $"{Uploads}/x1/1", body: "short")) { }
        using var moved = await server.SendAsync("MOVE", $"{Uploads}/x1/.file", headers: [("Destination", "/remote.php/dav/files/alice/x.bin"), ("OC-Total-Length", "1000")]);
        Assert.Equal(HttpStatusCode.BadRequest, moved.StatusCode);
        using var gone = await server.SendAsync("GET", "/dav/x.bin");
        Assert.Equal(HttpStatusCode.NotFound, gone.StatusCode);
    }

    [Fact]
    public async Task ChunksCountAgainstTheQuota()
    {
        server.AddAccount(new AccountInfo { Name = "alice", QuotaBytes = 10, Grants = [new GrantInfo { Mount = "/dav" }] });
        using (await server.SendAsync("MKCOL", $"{Uploads}/q1")) { }
        using (var first = await server.SendAsync("PUT", $"{Uploads}/q1/1", body: "12345678")) Assert.Equal(HttpStatusCode.Created, first.StatusCode);
        using (var second = await server.SendAsync("PUT", $"{Uploads}/q1/2", body: "12345678")) Assert.Equal((HttpStatusCode)507, second.StatusCode);
    }

    [Fact]
    public async Task AChunkedUploadCanBeGivenUp()
    {
        using (await server.SendAsync("MKCOL", $"{Uploads}/gone")) { }
        using (await server.SendAsync("PUT", $"{Uploads}/gone/1", body: "x")) { }
        using (var deleted = await server.SendAsync("DELETE", $"{Uploads}/gone")) Assert.Equal(HttpStatusCode.NoContent, deleted.StatusCode);
        using var after = await server.SendAsync("PUT", $"{Uploads}/gone/2", body: "y");
        Assert.Equal(HttpStatusCode.NotFound, after.StatusCode);
    }

    [Theory]
    [InlineData("..")]
    [InlineData("..%2F..%2Fetc")]
    [InlineData("a%5Cb")]
    [InlineData("a%00b")]
    public async Task UploadNamesStayInTheirFolder(string name)
    {
        var (answer, _) = await server.RawAsync($"MKCOL {Uploads}/{name} HTTP/1.1\r\nHost: test\r\nConnection: close\r\nAuthorization: {Basic("alice")}\r\n\r\n");
        Assert.StartsWith("HTTP/1.1 4", answer);
    }

    [Fact]
    public async Task OnlyYourOwnUploads()
    {
        server.AddAccount("bob", new GrantInfo { Mount = "/dav" });
        using var response = await server.SendAsync("MKCOL", $"{Uploads}/x", "bob");
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task ReadOnlyAccountsCantUpload()
    {
        server.AddAccount("reader", new GrantInfo { Mount = "/dav", ReadOnly = true });
        using var response = await server.SendAsync("MKCOL", "/remote.php/dav/uploads/reader/x", "reader");
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }
}
