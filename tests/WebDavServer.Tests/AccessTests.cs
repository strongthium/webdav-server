using System.Net;
using static Strongthium.WebDavServer.Tests.TestServer;

namespace Strongthium.WebDavServer.Tests;

/// <summary>Who gets in, who gets banned, and that a socket really is closed: seen from a real one.</summary>
public sealed class AccessTests : IAsyncLifetime
{
    private TestServer server = null!;

    public async ValueTask InitializeAsync()
    {
        server = await StartAsync();
        server.AddMount(new MountInfo { Path = "/strict", Layout = StorageLayout.Path, MaxFailures = 3, FailureWindowMinutes = 10, BanMinutes = 30 });
        server.AddMount(new MountInfo { Path = "/lenient", Layout = StorageLayout.Path, MaxFailures = 0 });
        server.AddAccount("alice", new GrantInfo { Mount = "/dav" }, new GrantInfo { Mount = "/strict" }, new GrantInfo { Mount = "/lenient" });
    }

    public ValueTask DisposeAsync() => server.DisposeAsync();

    private Task<HttpResponseMessage> Wrong(string path, string? forwardedFor = null, string user = "alice") => forwardedFor is null
        ? server.SendAsync("PROPFIND", path, user, password: "wrong password here", headers: ("Depth", "0"))
        : server.SendAsync("PROPFIND", path, user, password: "wrong password here", headers: [("Depth", "0"), ("X-Forwarded-For", forwardedFor), ("X-Forwarded-Proto", "https")]);

    [Fact]
    public async Task FailuresBanFromThatPathAndNoOther()
    {
        for (var i = 0; i < 2; i++)
        {
            using var response = await Wrong("/strict/");
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        }
        // The third crosses the line: no answer at all, and the connection goes.
        await Assert.ThrowsAsync<HttpRequestException>(() => Wrong("/strict/"));

        var ban = Assert.Single(server.App.Guard.Bans());
        Assert.Equal("/strict", ban.Scope);
        Assert.Equal("127.0.0.1", ban.Network);

        // Even with the right password.
        await Assert.ThrowsAsync<HttpRequestException>(() => server.SendAsync("PROPFIND", "/strict/", headers: ("Depth", "0")));
        var (answer, closed) = await server.RawAsync(RawGet("/strict/", "alice"));
        Assert.Equal("", answer);
        Assert.True(closed);

        // Another path is another matter.
        using var other = await server.SendAsync("PROPFIND", "/dav/", headers: ("Depth", "0"));
        Assert.Equal((HttpStatusCode)207, other.StatusCode);
    }

    [Fact]
    public async Task BansEnd()
    {
        for (var i = 0; i < 2; i++) (await Wrong("/strict/")).Dispose();
        await Assert.ThrowsAsync<HttpRequestException>(() => Wrong("/strict/"));
        server.Clock.Now = server.Clock.Now.AddMinutes(29);
        await Assert.ThrowsAsync<HttpRequestException>(() => server.SendAsync("PROPFIND", "/strict/", headers: ("Depth", "0")));
        server.Clock.Now = server.Clock.Now.AddMinutes(2);
        using var response = await server.SendAsync("PROPFIND", "/strict/", headers: ("Depth", "0"));
        Assert.Equal((HttpStatusCode)207, response.StatusCode);
    }

    [Fact]
    public async Task FailuresOutsideTheWindowDontAddUp()
    {
        for (var i = 0; i < 2; i++) (await Wrong("/strict/")).Dispose();
        server.Clock.Now = server.Clock.Now.AddMinutes(11);
        for (var i = 0; i < 2; i++) (await Wrong("/strict/")).Dispose();
        Assert.Empty(server.App.Guard.Bans());
    }

    [Fact]
    public async Task ManyNamesFromOnePlaceCountTogether()
    {
        (await Wrong("/strict/", user: "a")).Dispose();
        (await Wrong("/strict/", user: "b")).Dispose();
        await Assert.ThrowsAsync<HttpRequestException>(() => Wrong("/strict/", user: "c"));
        Assert.Single(server.App.Guard.Bans());
    }

    [Fact]
    public async Task LoggingInDoesntClearFailures()
    {
        (await Wrong("/strict/")).Dispose();
        (await server.SendAsync("PROPFIND", "/strict/", headers: ("Depth", "0"))).Dispose();
        (await Wrong("/strict/")).Dispose();
        (await server.SendAsync("PROPFIND", "/strict/", headers: ("Depth", "0"))).Dispose();
        await Assert.ThrowsAsync<HttpRequestException>(() => Wrong("/strict/"));
    }

    [Fact]
    public async Task NoLoginAtAllIsNotAFailure()
    {
        for (var i = 0; i < 10; i++)
        {
            using var response = await server.SendAsync("PROPFIND", "/strict/", user: null, headers: ("Depth", "0"));
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        }
        Assert.Empty(server.App.Guard.Bans());
    }

    [Fact]
    public async Task GarbageLoginsCountToo()
    {
        for (var i = 0; i < 2; i++)
        {
            var (first, _) = await server.RawAsync("GET /strict/ HTTP/1.1\r\nHost: test\r\nConnection: close\r\nAuthorization: Basic !!!\r\n\r\n");
            Assert.StartsWith("HTTP/1.1 401", first);
        }
        var (answer, closed) = await server.RawAsync("GET /strict/ HTTP/1.1\r\nHost: test\r\nAuthorization: Basic !!!\r\n\r\n");
        Assert.Equal("", answer);
        Assert.True(closed);
    }

    [Fact]
    public async Task ZeroMeansNeverBan()
    {
        for (var i = 0; i < 10; i++) (await Wrong("/lenient/")).Dispose();
        Assert.Empty(server.App.Guard.Bans());
    }

    [Fact]
    public async Task ABanOutlastsARestart()
    {
        for (var i = 0; i < 2; i++) (await Wrong("/strict/")).Dispose();
        await Assert.ThrowsAsync<HttpRequestException>(() => Wrong("/strict/"));
        var again = new Security.Guard(server.State);
        Assert.True(again.IsBanned(IPAddress.Loopback, "/strict"));
        Assert.False(again.IsBanned(IPAddress.Loopback, "/dav"));
    }

    [Fact]
    public async Task AnAddressBannedFromEverythingIsTurnedAwayAtTheDoor()
    {
        server.App.Guard.Ban(IPAddress.Loopback, Security.Scopes.All, TimeSpan.FromHours(1), "Test.");
        var before = server.App.Gate.ClosedAtTheDoor;
        var (answer, closed) = await server.RawAsync("");
        Assert.Equal("", answer);
        Assert.True(closed);
        Assert.True(server.App.Gate.ClosedAtTheDoor > before);
    }

    [Fact]
    public async Task OutsideTheServersWhitelistTheSocketClosesAndABanFollows()
    {
        server.ChangeSettings(settings => settings with { Whitelist = ["203.0.113.0/24"] });
        var (answer, closed) = await server.RawAsync("");
        Assert.Equal("", answer);
        Assert.True(closed);

        var ban = Assert.Single(server.App.Guard.Bans());
        Assert.Equal("*", ban.Scope);
        Assert.Equal(server.Clock.Now.AddDays(7), ban.Until);

        // Taking the rule away leaves the ban.
        server.ChangeSettings(settings => settings with { Whitelist = [] });
        (answer, closed) = await server.RawAsync(RawGet("/dav/", "alice"));
        Assert.Equal("", answer);
        Assert.True(closed);
    }

    [Fact]
    public async Task HowLongAWhitelistBanLastsIsUpToTheAdmin()
    {
        server.ChangeSettings(settings => settings with { Whitelist = ["203.0.113.0/24"], WhitelistBanMinutes = 5 });
        await server.RawAsync("");
        Assert.Equal(server.Clock.Now.AddMinutes(5), Assert.Single(server.App.Guard.Bans()).Until);
    }

    [Fact]
    public async Task InsideTheServersWhitelist()
    {
        server.ChangeSettings(settings => settings with { Whitelist = ["127.0.0.0/8"] });
        using var response = await server.SendAsync("PROPFIND", "/dav/", headers: ("Depth", "0"));
        Assert.Equal((HttpStatusCode)207, response.StatusCode);
        Assert.Empty(server.App.Guard.Bans());
    }

    [Fact]
    public async Task AWhitelistOfPlacesWithoutADatabaseShutsOutButDoesntBan()
    {
        server.ChangeSettings(settings => settings with { Whitelist = ["CA"] });
        var (answer, closed) = await server.RawAsync("");
        Assert.Equal("", answer);
        Assert.True(closed);
        Assert.Empty(server.App.Guard.Bans());
    }

    [Fact]
    public async Task AWhitelistOfPlacesWithADatabase()
    {
        server.State.Geo.Use(new StringReader("127.0.0.0,127.255.255.255,CA\n"), new StringReader("127.0.0.0,127.255.255.255,64500,Test\n"), "2026-10");
        server.ChangeSettings(settings => settings with { Whitelist = ["AS64500"] });
        using (var response = await server.SendAsync("PROPFIND", "/dav/", headers: ("Depth", "0"))) Assert.Equal((HttpStatusCode)207, response.StatusCode);
        server.ChangeSettings(settings => settings with { Whitelist = ["CA"] });
        using (var response = await server.SendAsync("PROPFIND", "/dav/", headers: ("Depth", "0"))) Assert.Equal((HttpStatusCode)207, response.StatusCode);
        server.ChangeSettings(settings => settings with { Whitelist = ["US"] });
        var (_, closed) = await server.RawAsync("");
        Assert.True(closed);
        Assert.Single(server.App.Guard.Bans());
    }

    [Fact]
    public async Task OutsideAnAccountsWhitelistEvenTheRightPasswordEndsInABan()
    {
        server.AddAccount(new AccountInfo { Name = "carol", Whitelist = ["203.0.113.0/24"], Grants = [new GrantInfo { Mount = "/dav" }] });

        // Others carry on until then, and asking without a login tells nobody anything.
        using (var anonymous = await server.SendAsync("PROPFIND", "/dav/", user: null, headers: ("Depth", "0"))) Assert.Equal(HttpStatusCode.Unauthorized, anonymous.StatusCode);
        Assert.Empty(server.App.Guard.Bans());

        var (answer, closed) = await server.RawAsync(RawGet("/dav/", "carol"));
        Assert.Equal("", answer);
        Assert.True(closed);

        var ban = Assert.Single(server.App.Guard.Bans());
        Assert.Equal("*", ban.Scope);
        Assert.Contains("carol", ban.Reason);
        Assert.Equal(server.Clock.Now.AddDays(7), ban.Until);

        // That address is now shut out at the door, whoever it says it is.
        (answer, closed) = await server.RawAsync(RawGet("/dav/", "alice"));
        Assert.Equal("", answer);
        Assert.True(closed);
    }

    [Fact]
    public async Task InsideAnAccountsWhitelist()
    {
        server.AddAccount(new AccountInfo { Name = "carol", Whitelist = ["127.0.0.1"], Grants = [new GrantInfo { Mount = "/dav" }] });
        using var response = await server.SendAsync("PROPFIND", "/dav/", "carol", headers: ("Depth", "0"));
        Assert.Equal((HttpStatusCode)207, response.StatusCode);
    }

    [Fact]
    public async Task AWhitelistCutsAnOpenConnectionToo()
    {
        using var client = new HttpClient(new SocketsHttpHandler { UseProxy = false });
        client.DefaultRequestHeaders.Authorization = Basic("alice");
        using (var request = new HttpRequestMessage(new HttpMethod("PROPFIND"), server.Url + "/dav/"))
        using (var first = await client.SendAsync(request)) Assert.Equal((HttpStatusCode)207, first.StatusCode);
        server.ChangeSettings(settings => settings with { Whitelist = ["203.0.113.0/24"] });
        using var second = new HttpRequestMessage(new HttpMethod("PROPFIND"), server.Url + "/dav/");
        await Assert.ThrowsAsync<HttpRequestException>(() => client.SendAsync(second));
    }

    [Fact]
    public async Task ADisabledAccountOrAWrongPasswordIsTheSameFailure()
    {
        server.AddAccount(new AccountInfo { Name = "dave", Enabled = false, Grants = [new GrantInfo { Mount = "/dav" }] });
        using (var disabled = await server.SendAsync("PROPFIND", "/dav/", "dave", headers: ("Depth", "0"))) Assert.Equal(HttpStatusCode.Unauthorized, disabled.StatusCode);
        using (var unknown = await server.SendAsync("PROPFIND", "/dav/", "nobody", headers: ("Depth", "0"))) Assert.Equal(HttpStatusCode.Unauthorized, unknown.StatusCode);
    }

    [Fact]
    public async Task NamesArentCaseSensitive()
    {
        using var response = await server.SendAsync("PROPFIND", "/dav/", "ALICE", headers: ("Depth", "0"));
        Assert.Equal((HttpStatusCode)207, response.StatusCode);
    }

    [Fact]
    public async Task AChangedPasswordStopsWorkingAtOnce()
    {
        using (var before = await server.SendAsync("PROPFIND", "/dav/", headers: ("Depth", "0"))) Assert.Equal((HttpStatusCode)207, before.StatusCode);
        server.State.Database.SaveAccount(server.State.Policy.Accounts["alice"].Info, Security.Passwords.Hash("a different password"));
        server.State.Reload();
        using (var after = await server.SendAsync("PROPFIND", "/dav/", headers: ("Depth", "0"))) Assert.Equal(HttpStatusCode.Unauthorized, after.StatusCode);
    }

    // ---- App passwords -------------------------------------------------------------------------------------------

    [Fact]
    public async Task AppPasswordsLogInAndCanBeTakenAway()
    {
        var password = Security.Passwords.NewAppPassword();
        var id = server.State.Database.AddAppPassword("alice", "phone", Security.Passwords.HashAppPassword(password), server.Clock.Now);
        server.State.Reload();
        using (var response = await server.SendAsync("PROPFIND", "/dav/", password: password, headers: ("Depth", "0"))) Assert.Equal((HttpStatusCode)207, response.StatusCode);
        server.State.Database.DeleteAppPassword("alice", id);
        server.State.Reload();
        using (var response = await server.SendAsync("PROPFIND", "/dav/", password: password, headers: ("Depth", "0"))) Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task AccountsCanBeLimitedToAppPasswords()
    {
        var password = Security.Passwords.NewAppPassword();
        server.State.Database.SaveAccount(new AccountInfo { Name = "erin", RequireAppPasswords = true, Grants = [new GrantInfo { Mount = "/dav" }] }, Security.Passwords.Hash(Password));
        server.State.Database.AddAppPassword("erin", "laptop", Security.Passwords.HashAppPassword(password), server.Clock.Now);
        server.State.Reload();
        using (var real = await server.SendAsync("PROPFIND", "/dav/", "erin", headers: ("Depth", "0"))) Assert.Equal(HttpStatusCode.Unauthorized, real.StatusCode);
        using (var app = await server.SendAsync("PROPFIND", "/dav/", "erin", password: password, headers: ("Depth", "0"))) Assert.Equal((HttpStatusCode)207, app.StatusCode);
    }

    // ---- Through a proxy -----------------------------------------------------------------------------------------

    [Fact]
    public async Task HeadersArentBelievedFromAnUntrustedPeer()
    {
        // Loopback isn't a trusted proxy here, so this client can't pretend to be elsewhere.
        (await Wrong("/strict/", "203.0.113.5")).Dispose();
        (await Wrong("/strict/", "203.0.113.6")).Dispose();
        await Assert.ThrowsAsync<HttpRequestException>(() => Wrong("/strict/", "203.0.113.7"));
        Assert.Equal("127.0.0.1", Assert.Single(server.App.Guard.Bans()).Network);
    }

    [Fact]
    public async Task ASpoofedHeaderDoesntGetPastAWhitelist()
    {
        server.ChangeSettings(settings => settings with { Whitelist = ["203.0.113.0/24"] });
        var (answer, closed) = await server.RawAsync(RawGet("/dav/", "alice", "X-Forwarded-For: 203.0.113.5", "X-Real-IP: 203.0.113.5", "CF-Connecting-IP: 203.0.113.5"));
        Assert.Equal("", answer);
        Assert.True(closed);
    }

    [Fact]
    public async Task BehindAProxyEachClientIsBannedAloneAndTheProxyIsnt()
    {
        server.ChangeSettings(settings => settings with { TrustedProxies = ["127.0.0.1"] });
        (await Wrong("/strict/", "203.0.113.5")).Dispose();
        (await Wrong("/strict/", "203.0.113.5")).Dispose();
        await Assert.ThrowsAsync<HttpRequestException>(() => Wrong("/strict/", "203.0.113.5"));
        Assert.Equal("203.0.113.5", Assert.Single(server.App.Guard.Bans()).Network);

        using var neighbour = await server.SendAsync("PROPFIND", "/strict/", headers: [("Depth", "0"), ("X-Forwarded-For", "203.0.113.6"), ("X-Forwarded-Proto", "https")]);
        Assert.Equal((HttpStatusCode)207, neighbour.StatusCode);
        await Assert.ThrowsAsync<HttpRequestException>(() => server.SendAsync("PROPFIND", "/strict/", headers: [("Depth", "0"), ("X-Forwarded-For", "203.0.113.5"), ("X-Forwarded-Proto", "https")]));
    }

    [Fact]
    public async Task BehindAProxyAWhitelistGoesByTheClient()
    {
        server.ChangeSettings(settings => settings with { TrustedProxies = ["127.0.0.1"], Whitelist = ["203.0.113.0/24"] });
        using (var inside = await server.SendAsync("PROPFIND", "/dav/", headers: [("Depth", "0"), ("X-Forwarded-For", "203.0.113.5"), ("X-Forwarded-Proto", "https")])) Assert.Equal((HttpStatusCode)207, inside.StatusCode);
        await Assert.ThrowsAsync<HttpRequestException>(() => server.SendAsync("PROPFIND", "/dav/", headers: [("Depth", "0"), ("X-Forwarded-For", "198.51.100.5"), ("X-Forwarded-Proto", "https")]));
        Assert.Equal("198.51.100.5", Assert.Single(server.App.Guard.Bans()).Network);
    }

    [Fact]
    public async Task BehindAProxyWithoutTlsNoPasswordIsAsked()
    {
        server.ChangeSettings(settings => settings with { TrustedProxies = ["127.0.0.1"] });
        using var response = await server.SendAsync("PROPFIND", "/dav/", headers: [("Depth", "0"), ("X-Forwarded-For", "203.0.113.5"), ("X-Forwarded-Proto", "http")]);
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task AProxysPrefixIsPutBackInAddresses()
    {
        server.ChangeSettings(settings => settings with { TrustedProxies = ["127.0.0.1"] });
        await server.PutAsync("/dav/f.txt", "x");
        using var response = await server.SendAsync("PROPFIND", "/dav/", headers: [("Depth", "1"), ("X-Forwarded-For", "203.0.113.5"), ("X-Forwarded-Proto", "https"), ("X-Forwarded-Prefix", "/files")]);
        Assert.Contains("<d:href>/files/dav/f.txt</d:href>", await response.Content.ReadAsStringAsync());
        using var moved = await server.SendAsync("MOVE", "/dav/f.txt", headers: [("Destination", "https://public.example/files/dav/g.txt"), ("X-Forwarded-For", "203.0.113.5"), ("X-Forwarded-Proto", "https"), ("X-Forwarded-Prefix", "/files")]);
        Assert.Equal(HttpStatusCode.Created, moved.StatusCode);
        Assert.Equal("x", await server.ReadAsync("/dav/g.txt"));
    }

    [Fact]
    public async Task ConnectionsThatDontComeThroughTheProxyCanBeClosed()
    {
        // Loopback is always let through, so that a proxy on this machine can't be locked out: that's what makes this testable only by what it lets through.
        server.ChangeSettings(settings => settings with { RequireProxy = true });
        using var response = await server.SendAsync("PROPFIND", "/dav/", headers: ("Depth", "0"));
        Assert.Equal((HttpStatusCode)207, response.StatusCode);
    }

    [Fact]
    public async Task AnUntrustedProxyIsNoticed()
    {
        await server.RawAsync(RawGet("/dav/", null, "X-Forwarded-For: 203.0.113.5", "Connection: close"));
        Assert.Contains(server.State.Database.ReadLog(50, "warning"), entry => entry.Message.Contains("trusted proxies"));
    }

    // ---- TLS -----------------------------------------------------------------------------------------------------

    [Fact]
    public async Task OverTls()
    {
        await using var secure = await StartAsync(tls: true);
        secure.AddAccount("alice", new GrantInfo { Mount = "/dav" });
        using var handler = new SocketsHttpHandler { UseProxy = false };
        handler.SslOptions.RemoteCertificateValidationCallback = (_, _, _, _) => true;
        using var client = new HttpClient(handler);
        client.DefaultRequestHeaders.Authorization = Basic("alice");
        using var request = new HttpRequestMessage(new HttpMethod("PROPFIND"), secure.Url + "/dav/") { Version = HttpVersion.Version20 };
        using var response = await client.SendAsync(request);
        Assert.Equal((HttpStatusCode)207, response.StatusCode);
        Assert.Equal(new Version(2, 0), response.Version);
        Assert.Equal("max-age=31536000", response.Headers.GetValues("Strict-Transport-Security").Single());

        // Over HTTP/2 a request ends without taking the connection along, unless the connection itself is closed, which is what a ban has to do.
        secure.App.Guard.Ban(IPAddress.Loopback, Security.Scopes.All, TimeSpan.FromHours(1), "Test.");
        using var banned = new HttpRequestMessage(new HttpMethod("PROPFIND"), secure.Url + "/dav/") { Version = HttpVersion.Version20 };
        await Assert.ThrowsAsync<HttpRequestException>(() => client.SendAsync(banned));
        for (var i = 0; i < 50 && secure.App.Gate.OpenConnections > 0; i++) await Task.Delay(100);
        Assert.Equal(0, secure.App.Gate.OpenConnections);
    }

    [Theory]
    [InlineData(System.Security.Authentication.SslProtocols.Tls13)]
    [InlineData(System.Security.Authentication.SslProtocols.Tls12)]
    public async Task ModernTlsIsAccepted(System.Security.Authentication.SslProtocols protocol)
    {
        await using var secure = await StartAsync(tls: true);
        Assert.True(await Handshake(secure.Port, protocol));
    }

    private static async Task<bool> Handshake(int port, System.Security.Authentication.SslProtocols protocol)
    {
        using var tcp = new System.Net.Sockets.TcpClient();
        try
        {
            await tcp.ConnectAsync(IPAddress.Loopback, port);
        }
        catch (System.Net.Sockets.SocketException exception) when (exception.SocketErrorCode == System.Net.Sockets.SocketError.ConnectionReset)
        {
            // Closed at the door so quickly that Linux reports the reset before the connection is even made.
            return false;
        }
        await using var ssl = new System.Net.Security.SslStream(tcp.GetStream(), false, (_, _, _, _) => true);
        try
        {
            await ssl.AuthenticateAsClientAsync(new System.Net.Security.SslClientAuthenticationOptions { TargetHost = "localhost", EnabledSslProtocols = protocol });
            return true;
        }
        catch (Exception exception) when (exception is System.Security.Authentication.AuthenticationException or IOException)
        {
            return false;
        }
    }

    [Fact]
    public async Task BannedAddressesDontGetAHandshake()
    {
        await using var secure = await StartAsync(tls: true);
        secure.App.Guard.Ban(IPAddress.Loopback, Security.Scopes.All, TimeSpan.FromHours(1), "Test.");
        Assert.False(await Handshake(secure.Port, System.Security.Authentication.SslProtocols.Tls13));
    }
}
