using System.Net;
using System.Text;
using System.Xml.Linq;
using static Strongthium.WebDavServer.Tests.TestServer;

namespace Strongthium.WebDavServer.Tests;

/// <summary>WebDAV itself, from a client's side of a real connection. The default path, /dav, keeps files by account.</summary>
public sealed class DavTests : IAsyncLifetime
{
    private TestServer server = null!;

    public async ValueTask InitializeAsync()
    {
        server = await StartAsync();
        server.AddAccount("alice", new GrantInfo { Mount = "/dav" });
    }

    public ValueTask DisposeAsync() => server.DisposeAsync();

    [Fact]
    public async Task OptionsSaysWhatItIsBeforeLogin()
    {
        using var response = await server.SendAsync("OPTIONS", "/", user: null);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Contains("2", response.Headers.GetValues("DAV").Single());
        Assert.Equal("DAV", response.Headers.GetValues("MS-Author-Via").Single());
        Assert.False(response.Headers.Contains("Server"));
    }

    [Fact]
    public async Task NothingWithoutALogin()
    {
        foreach (var path in new[] { "/dav/", "/", "/nothing/here", "/dav/x" })
        {
            using var response = await server.SendAsync("PROPFIND", path, user: null);
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
            Assert.Contains("Basic", response.Headers.WwwAuthenticate.ToString());
        }
    }

    [Fact]
    public async Task PutGetDelete()
    {
        using (var created = await server.SendAsync("PUT", "/dav/a.txt", body: "hello"))
        {
            Assert.Equal(HttpStatusCode.Created, created.StatusCode);
            Assert.NotNull(created.Headers.ETag);
        }
        using (var replaced = await server.SendAsync("PUT", "/dav/a.txt", body: "hello again")) Assert.Equal(HttpStatusCode.NoContent, replaced.StatusCode);
        Assert.Equal("hello again", await server.ReadAsync("/dav/a.txt"));
        using (var deleted = await server.SendAsync("DELETE", "/dav/a.txt")) Assert.Equal(HttpStatusCode.NoContent, deleted.StatusCode);
        using (var gone = await server.SendAsync("GET", "/dav/a.txt")) Assert.Equal(HttpStatusCode.NotFound, gone.StatusCode);
        using (var goneAgain = await server.SendAsync("DELETE", "/dav/a.txt")) Assert.Equal(HttpStatusCode.NotFound, goneAgain.StatusCode);
    }

    [Fact]
    public async Task FilesAreServedOnlyAsDownloads()
    {
        await server.PutAsync("/dav/page.html", "<script>alert(1)</script>");
        using var response = await server.SendAsync("GET", "/dav/page.html");
        Assert.Equal("attachment", response.Content.Headers.ContentDisposition?.DispositionType);
        Assert.Equal("nosniff", response.Headers.GetValues("X-Content-Type-Options").Single());
        Assert.Contains("sandbox", response.Headers.GetValues("Content-Security-Policy").Single());
    }

    [Fact]
    public async Task HeadRangeAndConditions()
    {
        await server.PutAsync("/dav/r.txt", "0123456789");
        using (var head = await server.SendAsync("HEAD", "/dav/r.txt"))
        {
            Assert.Equal(10, head.Content.Headers.ContentLength);
            Assert.Equal("", await head.Content.ReadAsStringAsync());
        }
        string tag;
        using (var part = await server.SendAsync("GET", "/dav/r.txt", headers: ("Range", "bytes=2-4")))
        {
            Assert.Equal(HttpStatusCode.PartialContent, part.StatusCode);
            Assert.Equal("234", await part.Content.ReadAsStringAsync());
            Assert.Equal("bytes 2-4/10", part.Content.Headers.ContentRange?.ToString());
            tag = part.Headers.ETag!.ToString();
        }
        using (var tooFar = await server.SendAsync("GET", "/dav/r.txt", headers: ("Range", "bytes=50-"))) Assert.Equal(HttpStatusCode.RequestedRangeNotSatisfiable, tooFar.StatusCode);
        using (var same = await server.SendAsync("GET", "/dav/r.txt", headers: ("If-None-Match", tag))) Assert.Equal(HttpStatusCode.NotModified, same.StatusCode);
        using (var stale = await server.SendAsync("GET", "/dav/r.txt", headers: [("Range", "bytes=2-4"), ("If-Range", "\"other\"")]))
        {
            Assert.Equal(HttpStatusCode.OK, stale.StatusCode);
            Assert.Equal(10, stale.Content.Headers.ContentLength);
        }
        using (var wrong = await server.SendAsync("PUT", "/dav/r.txt", body: "x", headers: ("If-Match", "\"other\""))) Assert.Equal(HttpStatusCode.PreconditionFailed, wrong.StatusCode);
        Assert.Equal("0123456789", await server.ReadAsync("/dav/r.txt"));
        using (var right = await server.SendAsync("PUT", "/dav/r.txt", body: "x", headers: ("If-Match", tag))) Assert.Equal(HttpStatusCode.NoContent, right.StatusCode);
        using (var noOverwrite = await server.SendAsync("PUT", "/dav/r.txt", body: "y", headers: ("If-None-Match", "*"))) Assert.Equal(HttpStatusCode.PreconditionFailed, noOverwrite.StatusCode);
    }

    [Fact]
    public async Task Folders()
    {
        await server.MkcolAsync("/dav/f");
        using (var again = await server.SendAsync("MKCOL", "/dav/f")) Assert.Equal(HttpStatusCode.MethodNotAllowed, again.StatusCode);
        using (var noParent = await server.SendAsync("MKCOL", "/dav/x/y")) Assert.Equal(HttpStatusCode.Conflict, noParent.StatusCode);
        using (var withBody = await server.SendAsync("MKCOL", "/dav/g", body: "<x/>")) Assert.Equal(HttpStatusCode.UnsupportedMediaType, withBody.StatusCode);
        using (var putNoParent = await server.SendAsync("PUT", "/dav/x/y.txt", body: "z")) Assert.Equal(HttpStatusCode.Conflict, putNoParent.StatusCode);
        using (var putOnFolder = await server.SendAsync("PUT", "/dav/f", body: "z")) Assert.Equal(HttpStatusCode.MethodNotAllowed, putOnFolder.StatusCode);

        await server.PutAsync("/dav/f/one.txt", "1");
        await server.PutAsync("/dav/f/two%20words.txt", "22");
        var listing = await server.PropfindAsync("/dav/f/", "1");
        var hrefs = listing.Descendants(D + "href").Select(href => href.Value).ToList();
        Assert.Contains("/dav/f/", hrefs);
        Assert.Contains("/dav/f/one.txt", hrefs);
        Assert.Contains("/dav/f/two%20words.txt", hrefs);
        Assert.Equal(3, hrefs.Count);

        using (var deleted = await server.SendAsync("DELETE", "/dav/f")) Assert.Equal(HttpStatusCode.NoContent, deleted.StatusCode);
        using (var gone = await server.SendAsync("PROPFIND", "/dav/f", headers: ("Depth", "0"))) Assert.Equal(HttpStatusCode.NotFound, gone.StatusCode);
    }

    [Fact]
    public async Task ListingEverythingAtOnceIsRefused()
    {
        using var response = await server.SendAsync("PROPFIND", "/dav/", headers: ("Depth", "infinity"));
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Contains("propfind-finite-depth", await response.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task ThePropertiesOfAFile()
    {
        await server.PutAsync("/dav/p.txt", "12345");
        var answer = await server.PropfindAsync("/dav/p.txt");
        Assert.Equal("5", Prop(answer, D + "getcontentlength"));
        Assert.Equal("text/plain", Prop(answer, D + "getcontenttype"));
        Assert.Equal("p.txt", Prop(answer, D + "displayname"));
        Assert.NotNull(Prop(answer, D + "getetag"));
        Assert.NotNull(Prop(answer, D + "getlastmodified"));
        Assert.NotNull(answer.Descendants(D + "supportedlock").FirstOrDefault());

        var asked = await server.PropfindAsync("/dav/", "0", "<d:quota-used-bytes/><d:quota-available-bytes/><d:nosuch/>");
        var statuses = asked.Descendants(D + "propstat").ToDictionary(stat => stat.Element(D + "status")!.Value, stat => stat);
        Assert.NotNull(statuses["HTTP/1.1 200 OK"].Descendants(D + "quota-used-bytes").Single());
        Assert.NotNull(statuses["HTTP/1.1 404 Not Found"].Descendants(D + "nosuch").Single());
    }

    [Fact]
    public async Task PropertiesThatClientsSet()
    {
        await server.PutAsync("/dav/n.txt", "x");
        const string set = """<d:propertyupdate xmlns:d="DAV:" xmlns:z="urn:z"><d:set><d:prop><z:colour><z:deep lang="en">red</z:deep></z:colour></d:prop></d:set></d:propertyupdate>""";
        using (var response = await server.SendAsync("PROPPATCH", "/dav/n.txt", body: set)) Assert.Equal((HttpStatusCode)207, response.StatusCode);

        var answer = await server.PropfindAsync("/dav/n.txt", "0", """<z:colour xmlns:z="urn:z"/>""");
        XNamespace z = "urn:z";
        Assert.Equal("red", answer.Descendants(z + "deep").Single().Value);

        // The server's own can't be set, and the whole request then fails together.
        const string mixed = """<d:propertyupdate xmlns:d="DAV:" xmlns:z="urn:z"><d:set><d:prop><d:getetag>x</d:getetag><z:other>y</z:other></d:prop></d:set></d:propertyupdate>""";
        using (var response = await server.SendAsync("PROPPATCH", "/dav/n.txt", body: mixed))
        {
            var text = await response.Content.ReadAsStringAsync();
            Assert.Contains("403", text);
            Assert.Contains("424", text);
        }
        var after = await server.PropfindAsync("/dav/n.txt", "0", """<z:other xmlns:z="urn:z"/>""");
        Assert.Contains(after.Descendants(D + "status"), status => status.Value.Contains("404"));

        const string remove = """<d:propertyupdate xmlns:d="DAV:" xmlns:z="urn:z"><d:remove><d:prop><z:colour/></d:prop></d:remove></d:propertyupdate>""";
        using (await server.SendAsync("PROPPATCH", "/dav/n.txt", body: remove)) { }
        var removed = await server.PropfindAsync("/dav/n.txt", "0", """<z:colour xmlns:z="urn:z"/>""");
        Assert.Contains(removed.Descendants(D + "status"), status => status.Value.Contains("404"));
    }

    [Fact]
    public async Task CopyAndMoveKeepProperties()
    {
        await server.MkcolAsync("/dav/src");
        await server.PutAsync("/dav/src/a.txt", "a");
        const string set = """<d:propertyupdate xmlns:d="DAV:" xmlns:z="urn:z"><d:set><d:prop><z:p>v</z:p></d:prop></d:set></d:propertyupdate>""";
        using (await server.SendAsync("PROPPATCH", "/dav/src/a.txt", body: set)) { }

        using (var copied = await server.SendAsync("COPY", "/dav/src", headers: ("Destination", server.Url + "/dav/copy"))) Assert.Equal(HttpStatusCode.Created, copied.StatusCode);
        Assert.Equal("a", await server.ReadAsync("/dav/copy/a.txt"));
        Assert.Equal("a", await server.ReadAsync("/dav/src/a.txt"));
        XNamespace z = "urn:z";
        Assert.Equal("v", Prop(await server.PropfindAsync("/dav/copy/a.txt", "0", """<z:p xmlns:z="urn:z"/>"""), z + "p"));

        using (var noOverwrite = await server.SendAsync("COPY", "/dav/src", headers: [("Destination", "/dav/copy"), ("Overwrite", "F")])) Assert.Equal(HttpStatusCode.PreconditionFailed, noOverwrite.StatusCode);
        using (var overwrite = await server.SendAsync("COPY", "/dav/src", headers: ("Destination", "/dav/copy"))) Assert.Equal(HttpStatusCode.NoContent, overwrite.StatusCode);

        using (var moved = await server.SendAsync("MOVE", "/dav/src/a.txt", headers: ("Destination", "/dav/moved.txt"))) Assert.Equal(HttpStatusCode.Created, moved.StatusCode);
        Assert.Equal("v", Prop(await server.PropfindAsync("/dav/moved.txt", "0", """<z:p xmlns:z="urn:z"/>"""), z + "p"));
        using (var old = await server.SendAsync("GET", "/dav/src/a.txt")) Assert.Equal(HttpStatusCode.NotFound, old.StatusCode);
    }

    [Fact]
    public async Task CopiesAndMovesThatMakeNoSense()
    {
        await server.MkcolAsync("/dav/top");
        await server.MkcolAsync("/dav/top/inner");
        await server.PutAsync("/dav/top/inner/f.txt", "keep");
        using (var ontoItself = await server.SendAsync("MOVE", "/dav/top", headers: ("Destination", "/dav/top"))) Assert.Equal(HttpStatusCode.Forbidden, ontoItself.StatusCode);
        using (var intoItself = await server.SendAsync("MOVE", "/dav/top", headers: ("Destination", "/dav/top/inner/x"))) Assert.Equal(HttpStatusCode.Forbidden, intoItself.StatusCode);
        // Moving something over the folder it's in would delete it first.
        using (var overParent = await server.SendAsync("MOVE", "/dav/top/inner/f.txt", headers: ("Destination", "/dav/top"))) Assert.Equal(HttpStatusCode.Forbidden, overParent.StatusCode);
        Assert.Equal("keep", await server.ReadAsync("/dav/top/inner/f.txt"));
        using (var noParent = await server.SendAsync("COPY", "/dav/top", headers: ("Destination", "/dav/none/x"))) Assert.Equal(HttpStatusCode.Conflict, noParent.StatusCode);
        using (var noDestination = await server.SendAsync("COPY", "/dav/top")) Assert.Equal(HttpStatusCode.BadRequest, noDestination.StatusCode);
        using (var elsewhere = await server.SendAsync("COPY", "/dav/top", headers: ("Destination", "http://elsewhere.example/dav/x"))) Assert.Equal(HttpStatusCode.BadGateway, elsewhere.StatusCode);
        using (var topOfSpace = await server.SendAsync("DELETE", "/dav/")) Assert.Equal(HttpStatusCode.Forbidden, topOfSpace.StatusCode);
    }

    [Fact]
    public async Task LocksHoldOffOthersAndLetTheirOwnerIn()
    {
        server.AddAccount("bob", new GrantInfo { Mount = "/shared" });
        server.AddMount(new MountInfo { Path = "/shared", Layout = StorageLayout.Path });
        server.AddAccount(new AccountInfo { Name = "alice", Grants = [new GrantInfo { Mount = "/dav" }, new GrantInfo { Mount = "/shared" }] });
        await server.PutAsync("/shared/l.txt", "original");

        const string lockInfo = """<d:lockinfo xmlns:d="DAV:"><d:lockscope><d:exclusive/></d:lockscope><d:locktype><d:write/></d:locktype><d:owner>me</d:owner></d:lockinfo>""";
        string token;
        using (var taken = await server.SendAsync("LOCK", "/shared/l.txt", body: lockInfo, headers: ("Timeout", "Second-600")))
        {
            Assert.Equal(HttpStatusCode.OK, taken.StatusCode);
            token = taken.Headers.GetValues("Lock-Token").Single().Trim('<', '>');
            var text = await taken.Content.ReadAsStringAsync();
            Assert.Contains(token, text);
            Assert.Contains("Second-600", text);
        }

        using (var blocked = await server.SendAsync("PUT", "/shared/l.txt", body: "x")) Assert.Equal((HttpStatusCode)423, blocked.StatusCode);
        using (var blockedDelete = await server.SendAsync("DELETE", "/shared/l.txt")) Assert.Equal((HttpStatusCode)423, blockedDelete.StatusCode);
        using (var secondLock = await server.SendAsync("LOCK", "/shared/l.txt", user: "bob", body: lockInfo)) Assert.Equal((HttpStatusCode)423, secondLock.StatusCode);
        using (var wrongToken = await server.SendAsync("PUT", "/shared/l.txt", body: "x", headers: ("If", "(<urn:uuid:00000000-0000-0000-0000-000000000000>)"))) Assert.Equal(HttpStatusCode.PreconditionFailed, wrongToken.StatusCode);

        // Knowing the token isn't being its owner.
        using (var stolen = await server.SendAsync("PUT", "/shared/l.txt", user: "bob", body: "x", headers: ("If", $"(<{token}>)"))) Assert.Equal((HttpStatusCode)423, stolen.StatusCode);
        using (var stolenUnlock = await server.SendAsync("UNLOCK", "/shared/l.txt", user: "bob", headers: ("Lock-Token", $"<{token}>"))) Assert.Equal(HttpStatusCode.Forbidden, stolenUnlock.StatusCode);
        Assert.Equal("original", await server.ReadAsync("/shared/l.txt"));

        using (var mine = await server.SendAsync("PUT", "/shared/l.txt", body: "changed", headers: ("If", $"(<{token}>)"))) Assert.Equal(HttpStatusCode.NoContent, mine.StatusCode);
        using (var refreshed = await server.SendAsync("LOCK", "/shared/l.txt", headers: [("If", $"(<{token}>)"), ("Timeout", "Second-900")]))
        {
            Assert.Equal(HttpStatusCode.OK, refreshed.StatusCode);
            Assert.Contains("Second-900", await refreshed.Content.ReadAsStringAsync());
        }
        using (var discovered = await server.SendAsync("PROPFIND", "/shared/l.txt", headers: ("Depth", "0"))) Assert.Contains(token, await discovered.Content.ReadAsStringAsync());
        using (var unlocked = await server.SendAsync("UNLOCK", "/shared/l.txt", headers: ("Lock-Token", $"<{token}>"))) Assert.Equal(HttpStatusCode.NoContent, unlocked.StatusCode);
        using (var free = await server.SendAsync("PUT", "/shared/l.txt", user: "bob", body: "bob's")) Assert.Equal(HttpStatusCode.NoContent, free.StatusCode);
    }

    [Fact]
    public async Task LockingANameThatIsntThereMakesAFile()
    {
        const string lockInfo = """<d:lockinfo xmlns:d="DAV:"><d:lockscope><d:exclusive/></d:lockscope><d:locktype><d:write/></d:locktype></d:lockinfo>""";
        using var taken = await server.SendAsync("LOCK", "/dav/new.docx", body: lockInfo);
        Assert.Equal(HttpStatusCode.Created, taken.StatusCode);
        Assert.Equal("", await server.ReadAsync("/dav/new.docx"));
    }

    [Fact]
    public async Task ALockOnAFolderCoversWhatsInIt()
    {
        await server.MkcolAsync("/dav/locked");
        await server.PutAsync("/dav/locked/in.txt", "x");
        const string lockInfo = """<d:lockinfo xmlns:d="DAV:"><d:lockscope><d:exclusive/></d:lockscope><d:locktype><d:write/></d:locktype></d:lockinfo>""";
        string token;
        using (var taken = await server.SendAsync("LOCK", "/dav/locked", body: lockInfo, headers: ("Depth", "infinity"))) token = taken.Headers.GetValues("Lock-Token").Single().Trim('<', '>');
        using (var inner = await server.SendAsync("PUT", "/dav/locked/in.txt", body: "y")) Assert.Equal((HttpStatusCode)423, inner.StatusCode);
        using (var newFile = await server.SendAsync("PUT", "/dav/locked/new.txt", body: "y")) Assert.Equal((HttpStatusCode)423, newFile.StatusCode);
        using (var moveOut = await server.SendAsync("MOVE", "/dav/locked/in.txt", headers: ("Destination", "/dav/out.txt"))) Assert.Equal((HttpStatusCode)423, moveOut.StatusCode);
        using (var withToken = await server.SendAsync("PUT", "/dav/locked/in.txt", body: "y", headers: ("If", $"</dav/locked> (<{token}>)"))) Assert.Equal(HttpStatusCode.NoContent, withToken.StatusCode);
    }

    [Fact]
    public async Task LocksTimeOut()
    {
        await server.PutAsync("/dav/t.txt", "x");
        const string lockInfo = """<d:lockinfo xmlns:d="DAV:"><d:lockscope><d:exclusive/></d:lockscope><d:locktype><d:write/></d:locktype></d:lockinfo>""";
        using (await server.SendAsync("LOCK", "/dav/t.txt", body: lockInfo, headers: ("Timeout", "Second-60"))) { }
        using (var blocked = await server.SendAsync("PUT", "/dav/t.txt", body: "y")) Assert.Equal((HttpStatusCode)423, blocked.StatusCode);
        server.Clock.Now = server.Clock.Now.AddSeconds(61);
        using (var free = await server.SendAsync("PUT", "/dav/t.txt", body: "y")) Assert.Equal(HttpStatusCode.NoContent, free.StatusCode);
    }

    // ---- Staying inside ------------------------------------------------------------------------------------------

    [Theory]
    [InlineData("/dav/%2e%2e/%2e%2e/%2e%2e/webdav-server.db")]
    [InlineData("/dav/..%2f..%2f..%2fwebdav-server.db")]
    [InlineData("/dav/..%5c..%5c..%5cwebdav-server.db")]
    [InlineData("/dav/%2e%2e%2f%2e%2e%2fwebdav-server.db")]
    [InlineData("/dav/a%00.txt")]
    [InlineData("/dav/.webdav-server/tmp")]
    [InlineData("/dav/.WEBDAV-SERVER/tmp")]
    public async Task TryingToGetOutGetsNowhere(string path)
    {
        await server.PutAsync("/dav/seed.txt", "x");
        // Sent with a raw socket, so that nothing tidies the path on the way.
        var (answer, _) = await server.RawAsync($"GET {path} HTTP/1.1\r\nHost: test\r\nConnection: close\r\nAuthorization: {Basic("alice")}\r\n\r\n");
        Assert.StartsWith("HTTP/1.1 4", answer);
        Assert.DoesNotContain("SQLite", answer);
    }

    [Fact]
    public async Task TheServersOwnFolderIsntListed()
    {
        await server.PutAsync("/dav/seed.txt", "x");
        var listing = await server.PropfindAsync("/dav/", "1");
        Assert.DoesNotContain(listing.Descendants(D + "href"), href => href.Value.Contains("webdav-server", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task AnEncodedSlashIsntAWayIntoAFolder()
    {
        await server.MkcolAsync("/dav/f");
        await server.PutAsync("/dav/f/x.txt", "x");
        var (answer, _) = await server.RawAsync($"GET /dav/f%2Fx.txt HTTP/1.1\r\nHost: test\r\nConnection: close\r\nAuthorization: {Basic("alice")}\r\n\r\n");
        Assert.StartsWith("HTTP/1.1 400", answer);
    }

    [Fact]
    public async Task LinksArentFollowed()
    {
        var outside = Directory.CreateTempSubdirectory("webdav-outside-");
        File.WriteAllText(Path.Combine(outside.FullName, "secret.txt"), "secret");
        await server.PutAsync("/dav/seed.txt", "x");
        var home = Path.Combine(server.Folder, "files", "users", "alice");
        try
        {
            var fileLink = true;
            try
            {
                Directory.CreateSymbolicLink(Path.Combine(home, "link"), outside.FullName);
                File.CreateSymbolicLink(Path.Combine(home, "filelink.txt"), Path.Combine(outside.FullName, "secret.txt"));
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
            {
                // Windows only lets some accounts make symbolic links, but anyone can make a junction, which leads out just the same.
                if (!OperatingSystem.IsWindows()) throw;
                fileLink = false;
                using var mklink = System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo("cmd.exe", ["/c", "mklink", "/J", Path.Combine(home, "link"), outside.FullName]) { RedirectStandardOutput = true, UseShellExecute = false })!;
                await mklink.WaitForExitAsync();
                Assert.Equal(0, mklink.ExitCode);
            }
            using (var through = await server.SendAsync("GET", "/dav/link/secret.txt")) Assert.Equal(HttpStatusCode.NotFound, through.StatusCode);
            if (fileLink)
            {
                using var file = await server.SendAsync("GET", "/dav/filelink.txt");
                Assert.Equal(HttpStatusCode.NotFound, file.StatusCode);
            }
            using (var write = await server.SendAsync("PUT", "/dav/link/new.txt", body: "x")) Assert.NotEqual(HttpStatusCode.Created, write.StatusCode);
            Assert.False(File.Exists(Path.Combine(outside.FullName, "new.txt")));
            var listing = await server.PropfindAsync("/dav/", "1");
            Assert.DoesNotContain(listing.Descendants(D + "href"), href => href.Value.Contains("link"));
        }
        finally
        {
            outside.Delete(recursive: true);
        }
    }

    [Fact]
    public async Task XmlCantReachOutOrBlowUp()
    {
        var secret = Path.Combine(server.Folder, "outside.txt");
        File.WriteAllText(secret, "TOPSECRET");
        var external = $"""<?xml version="1.0"?><!DOCTYPE p [<!ENTITY x SYSTEM "file:///{secret.Replace('\\', '/')}">]><d:propfind xmlns:d="DAV:"><d:prop><d:x>&x;</d:x></d:prop></d:propfind>""";
        using (var response = await server.SendAsync("PROPFIND", "/dav/", body: external, headers: ("Depth", "0")))
        {
            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
            Assert.DoesNotContain("TOPSECRET", await response.Content.ReadAsStringAsync());
        }
        const string bomb = """<?xml version="1.0"?><!DOCTYPE b [<!ENTITY a "aaaaaaaa"><!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;">]><d:propfind xmlns:d="DAV:"><d:prop><d:x>&b;</d:x></d:prop></d:propfind>""";
        using (var response = await server.SendAsync("PROPFIND", "/dav/", body: bomb, headers: ("Depth", "0"))) Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        using (var broken = await server.SendAsync("PROPFIND", "/dav/", body: "<not xml", headers: ("Depth", "0"))) Assert.Equal(HttpStatusCode.BadRequest, broken.StatusCode);
    }

    [Fact]
    public async Task XmlBodiesHaveALimit()
    {
        var huge = "<d:propfind xmlns:d=\"DAV:\"><d:allprop/>" + new string(' ', 2 * 1024 * 1024) + "</d:propfind>";
        using var response = await server.SendAsync("PROPFIND", "/dav/", body: huge, headers: ("Depth", "0"));
        Assert.False(response.IsSuccessStatusCode);
    }

    [Fact]
    public async Task AFailedUploadLeavesTheOldFile()
    {
        await server.PutAsync("/dav/whole.txt", "whole");
        var (_, _) = await server.RawAsync($"PUT /dav/whole.txt HTTP/1.1\r\nHost: test\r\nAuthorization: {Basic("alice")}\r\nContent-Length: 100\r\nConnection: close\r\n\r\nonly part of it");
        Assert.Equal("whole", await server.ReadAsync("/dav/whole.txt"));
    }

    [Fact]
    public async Task ReadersGetAWholeFileWhileItsReplaced()
    {
        var big = new string('a', 1024 * 1024);
        await server.PutAsync("/dav/race.txt", big);
        var writes = Task.Run(async () =>
        {
            for (var i = 0; i < 5; i++) await server.PutAsync("/dav/race.txt", new string((char)('b' + i), 1024 * 1024));
        });
        for (var i = 0; i < 5; i++)
        {
            var text = await server.ReadAsync("/dav/race.txt");
            Assert.Equal(1024 * 1024, text.Length);
            Assert.All(text, c => Assert.Equal(text[0], c));
        }
        await writes;
    }

    [Fact]
    public async Task NamesInManyLanguages()
    {
        const string name = "日本語 ファイル.txt";
        await server.PutAsync("/dav/" + Uri.EscapeDataString(name), "x");
        var listing = await server.PropfindAsync("/dav/", "1");
        Assert.Contains(listing.Descendants(D + "href"), href => Uri.UnescapeDataString(href.Value).EndsWith(name, StringComparison.Ordinal));
        Assert.Equal("x", await server.ReadAsync("/dav/" + Uri.EscapeDataString(name)));
    }

    // ---- Who keeps what ------------------------------------------------------------------------------------------

    [Fact]
    public async Task LaidOutByUserFilesFollowTheAccountAcrossPaths()
    {
        server.AddMount(new MountInfo { Path = "/second", Layout = StorageLayout.User });
        server.AddAccount("alice", new GrantInfo { Mount = "/dav" }, new GrantInfo { Mount = "/second" });
        server.AddAccount("bob", new GrantInfo { Mount = "/dav" });
        await server.PutAsync("/dav/mine.txt", "alice's");
        Assert.Equal("alice's", await server.ReadAsync("/second/mine.txt"));
        using (var bobs = await server.SendAsync("GET", "/dav/mine.txt", "bob")) Assert.Equal(HttpStatusCode.NotFound, bobs.StatusCode);
        Assert.True(File.Exists(Path.Combine(server.Folder, "files", "users", "alice", "mine.txt")));
    }

    [Fact]
    public async Task LaidOutByPathEveryoneShares()
    {
        server.AddMount(new MountInfo { Path = "/team", Layout = StorageLayout.Path });
        server.AddAccount("alice", new GrantInfo { Mount = "/team" });
        server.AddAccount("bob", new GrantInfo { Mount = "/team" });
        await server.PutAsync("/team/shared.txt", "ours");
        Assert.Equal("ours", await server.ReadAsync("/team/shared.txt", "bob"));
        Assert.True(File.Exists(Path.Combine(server.Folder, "files", "paths", "team", "shared.txt")));
    }

    [Fact]
    public async Task LaidOutByBothEachHasTheirOwnOnEachPath()
    {
        server.AddMount(new MountInfo { Path = "/one", Layout = StorageLayout.UserAndPath });
        server.AddMount(new MountInfo { Path = "/two", Layout = StorageLayout.UserAndPath });
        server.AddAccount("alice", new GrantInfo { Mount = "/one" }, new GrantInfo { Mount = "/two" });
        server.AddAccount("bob", new GrantInfo { Mount = "/one" });
        await server.PutAsync("/one/f.txt", "one");
        using (var otherPath = await server.SendAsync("GET", "/two/f.txt")) Assert.Equal(HttpStatusCode.NotFound, otherPath.StatusCode);
        using (var otherUser = await server.SendAsync("GET", "/one/f.txt", "bob")) Assert.Equal(HttpStatusCode.NotFound, otherUser.StatusCode);
        Assert.True(File.Exists(Path.Combine(server.Folder, "files", "paths", "one", "alice", "f.txt")));
    }

    [Fact]
    public async Task APathInAFolderOfItsOwn()
    {
        var elsewhere = Path.Combine(server.Folder, "elsewhere");
        server.AddMount(new MountInfo { Path = "/ext", Layout = StorageLayout.Path, Root = elsewhere });
        server.AddAccount("alice", new GrantInfo { Mount = "/ext" });
        await server.PutAsync("/ext/f.txt", "x");
        Assert.True(File.Exists(Path.Combine(elsewhere, "f.txt")));
    }

    [Fact]
    public async Task APathAtTheServersOwnAddress()
    {
        server.AddMount(new MountInfo { Path = "/", Layout = StorageLayout.User });
        server.AddAccount("alice", new GrantInfo { Mount = "/" });
        await server.PutAsync("/at-the-top.txt", "x");
        var listing = await server.PropfindAsync("/", "1");
        Assert.Contains(listing.Descendants(D + "href"), href => href.Value == "/at-the-top.txt");
    }

    [Fact]
    public async Task WithNoPathThereTheTopListsThePathsYouMayUse()
    {
        server.AddMount(new MountInfo { Path = "/hidden", Layout = StorageLayout.Path });
        var listing = await server.PropfindAsync("/", "1");
        var hrefs = listing.Descendants(D + "href").Select(href => href.Value).ToList();
        Assert.Contains("/dav/", hrefs);
        Assert.DoesNotContain("/hidden/", hrefs);
    }

    [Fact]
    public async Task PathsWithoutAGrantAreClosed()
    {
        server.AddMount(new MountInfo { Path = "/private", Layout = StorageLayout.Path });
        using var response = await server.SendAsync("PROPFIND", "/private/", headers: ("Depth", "0"));
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        using var copied = await server.SendAsync("COPY", "/dav/", headers: ("Destination", "/private/x"));
        Assert.Equal(HttpStatusCode.Forbidden, copied.StatusCode);
    }

    [Fact]
    public async Task ADisabledPathIsntThere()
    {
        server.AddMount(new MountInfo { Path = "/off", Layout = StorageLayout.Path, Enabled = false });
        server.AddAccount("alice", new GrantInfo { Mount = "/off" });
        using var response = await server.SendAsync("PROPFIND", "/off/", headers: ("Depth", "0"));
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    [Fact]
    public async Task ReadOnlyMeansIt()
    {
        server.AddMount(new MountInfo { Path = "/ro", Layout = StorageLayout.Path });
        server.AddAccount("alice", new GrantInfo { Mount = "/ro" });
        server.AddAccount("bob", new GrantInfo { Mount = "/ro", ReadOnly = true }, new GrantInfo { Mount = "/dav" });
        await server.PutAsync("/ro/f.txt", "x");
        await server.PutAsync("/dav/b.txt", "b", "bob");
        Assert.Equal("x", await server.ReadAsync("/ro/f.txt", "bob"));
        foreach (var (method, path, headers) in new (string, string, (string, string)[])[]
        {
            ("PUT", "/ro/f.txt", []),
            ("DELETE", "/ro/f.txt", []),
            ("MKCOL", "/ro/d", []),
            ("MOVE", "/ro/f.txt", [("Destination", "/dav/x.txt")]),
        })
        {
            using var response = await server.SendAsync(method, path, "bob", method == "PUT" ? "y" : null, headers: headers);
            Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        }
        using (var copyIn = await server.SendAsync("COPY", "/dav/b.txt", "bob", headers: ("Destination", "/ro/b.txt"))) Assert.Equal(HttpStatusCode.Forbidden, copyIn.StatusCode);
        const string lockInfo = """<d:lockinfo xmlns:d="DAV:"><d:lockscope><d:exclusive/></d:lockscope><d:locktype><d:write/></d:locktype></d:lockinfo>""";
        using (var locked = await server.SendAsync("LOCK", "/ro/f.txt", "bob", lockInfo)) Assert.Equal(HttpStatusCode.Forbidden, locked.StatusCode);
        const string set = """<d:propertyupdate xmlns:d="DAV:" xmlns:z="urn:z"><d:set><d:prop><z:p>v</z:p></d:prop></d:set></d:propertyupdate>""";
        using (var patched = await server.SendAsync("PROPPATCH", "/ro/f.txt", "bob", set)) Assert.Equal(HttpStatusCode.Forbidden, patched.StatusCode);
        Assert.Equal("x", await server.ReadAsync("/ro/f.txt", "bob"));
    }

    [Fact]
    public async Task CopyAcrossPaths()
    {
        server.AddMount(new MountInfo { Path = "/team", Layout = StorageLayout.Path });
        server.AddAccount("alice", new GrantInfo { Mount = "/dav" }, new GrantInfo { Mount = "/team" });
        await server.PutAsync("/dav/f.txt", "x");
        using (var response = await server.SendAsync("MOVE", "/dav/f.txt", headers: ("Destination", "/team/f.txt"))) Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        Assert.Equal("x", await server.ReadAsync("/team/f.txt"));
    }

    // ---- Limits --------------------------------------------------------------------------------------------------

    [Fact]
    public async Task QuotaIsHeldTo()
    {
        server.AddAccount(new AccountInfo { Name = "alice", QuotaBytes = 100, Grants = [new GrantInfo { Mount = "/dav" }] });
        await server.PutAsync("/dav/a.bin", new string('a', 60));
        using (var over = await server.SendAsync("PUT", "/dav/b.bin", body: new string('b', 60))) Assert.Equal((HttpStatusCode)507, over.StatusCode);
        using (var gone = await server.SendAsync("GET", "/dav/b.bin")) Assert.Equal(HttpStatusCode.NotFound, gone.StatusCode);
        // Replacing a file counts what it replaces as gone.
        using (var replace = await server.SendAsync("PUT", "/dav/a.bin", body: new string('a', 90))) Assert.Equal(HttpStatusCode.NoContent, replace.StatusCode);
        using (var copy = await server.SendAsync("COPY", "/dav/a.bin", headers: ("Destination", "/dav/c.bin"))) Assert.Equal((HttpStatusCode)507, copy.StatusCode);
        using (await server.SendAsync("DELETE", "/dav/a.bin")) { }
        using (var fits = await server.SendAsync("PUT", "/dav/b.bin", body: new string('b', 60))) Assert.Equal(HttpStatusCode.Created, fits.StatusCode);

        var answer = await server.PropfindAsync("/dav/", "0", "<d:quota-used-bytes/><d:quota-available-bytes/>");
        Assert.Equal("60", Prop(answer, D + "quota-used-bytes"));
        Assert.Equal("40", Prop(answer, D + "quota-available-bytes"));
    }

    [Fact]
    public async Task QuotaHoldsWithoutADeclaredLength()
    {
        server.AddAccount(new AccountInfo { Name = "alice", QuotaBytes = 100, Grants = [new GrantInfo { Mount = "/dav" }] });
        var chunk = new string('x', 200);
        var (answer, _) = await server.RawAsync($"PUT /dav/chunked.bin HTTP/1.1\r\nHost: test\r\nAuthorization: {Basic("alice")}\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n{chunk.Length:x}\r\n{chunk}\r\n0\r\n\r\n");
        Assert.StartsWith("HTTP/1.1 507", answer);
        using var gone = await server.SendAsync("GET", "/dav/chunked.bin");
        Assert.Equal(HttpStatusCode.NotFound, gone.StatusCode);
    }

    [Fact]
    public async Task LargestUploadIsHeldTo()
    {
        server.ChangeSettings(settings => settings with { MaxUploadBytes = 10 });
        using var response = await server.SendAsync("PUT", "/dav/big.bin", body: new string('x', 11));
        Assert.Equal(HttpStatusCode.RequestEntityTooLarge, response.StatusCode);
    }

    [Fact]
    public async Task UploadsLargerThanTheXmlLimit()
    {
        var content = new string('x', 3 * 1024 * 1024);
        await server.PutAsync("/dav/large.bin", content);
        Assert.Equal(content.Length, (await server.ReadAsync("/dav/large.bin")).Length);
    }

    [Fact]
    public async Task ChecksumsAreHeldTo()
    {
        using (var wrong = await server.SendAsync("PUT", "/dav/c.txt", body: "hello", headers: ("OC-Checksum", "SHA256:0000")))
        {
            Assert.Equal(HttpStatusCode.BadRequest, wrong.StatusCode);
        }
        using (var gone = await server.SendAsync("GET", "/dav/c.txt")) Assert.Equal(HttpStatusCode.NotFound, gone.StatusCode);
        var right = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(Encoding.UTF8.GetBytes("hello")));
        using var good = await server.SendAsync("PUT", "/dav/c.txt", body: "hello", headers: ("OC-Checksum", $"SHA256:{right}"));
        Assert.Equal(HttpStatusCode.Created, good.StatusCode);
    }

    [Fact]
    public async Task TimesFromClientsAreKept()
    {
        using (var put = await server.SendAsync("PUT", "/dav/t.txt", body: "x", headers: ("X-OC-Mtime", "1000000000")))
        {
            Assert.Equal("accepted", put.Headers.GetValues("X-OC-MTime").Single());
        }
        var answer = await server.PropfindAsync("/dav/t.txt");
        Assert.Contains("2001", Prop(answer, D + "getlastmodified"));

        const string windows = """<d:propertyupdate xmlns:d="DAV:" xmlns:z="urn:schemas-microsoft-com:"><d:set><d:prop><z:Win32LastModifiedTime>Fri, 02 Jan 2015 03:04:05 GMT</z:Win32LastModifiedTime></d:prop></d:set></d:propertyupdate>""";
        using (await server.SendAsync("PROPPATCH", "/dav/t.txt", body: windows)) { }
        Assert.Contains("2015", Prop(await server.PropfindAsync("/dav/t.txt"), D + "getlastmodified"));
    }

    [Fact]
    public async Task EveryChangeShowsOnEveryFolderAbove()
    {
        await server.MkcolAsync("/dav/a");
        await server.MkcolAsync("/dav/a/b");
        async Task<string> Tag(string path) => Prop(await server.PropfindAsync(path, "0", "<d:getetag/>"), D + "getetag")!;
        var (top, a, b) = (await Tag("/dav/"), await Tag("/dav/a/"), await Tag("/dav/a/b/"));
        await server.PutAsync("/dav/a/b/f.txt", "x");
        Assert.NotEqual(top, await Tag("/dav/"));
        Assert.NotEqual(a, await Tag("/dav/a/"));
        Assert.NotEqual(b, await Tag("/dav/a/b/"));

        var before = await Tag("/dav/a/b/f.txt");
        await server.PutAsync("/dav/a/b/f.txt", "y");
        Assert.NotEqual(before, await Tag("/dav/a/b/f.txt"));
    }
}
