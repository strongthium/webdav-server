using System.Net;
using Microsoft.AspNetCore.Http;
using Strongthium.WebDavServer.Dav;
using Strongthium.WebDavServer.Network;
using Strongthium.WebDavServer.Security;
using Strongthium.WebDavServer.Storage;

namespace Strongthium.WebDavServer.Tests;

/// <summary>What can be judged from known input, with no server: names, addresses, whitelists, passwords and headers.</summary>
public sealed class RuleTests
{
    [Theory]
    [InlineData("..")]
    [InlineData(".")]
    [InlineData("")]
    [InlineData("a/b")]
    [InlineData("a\\b")]
    [InlineData("a\0b")]
    [InlineData("a\nb")]
    [InlineData(".webdav-server")]
    [InlineData(".WEBDAV-SERVER")]
    public void NamesThatAreNeverAllowed(string name)
    {
        Assert.False(PathRules.IsValidSegment(name, windows: false));
        Assert.False(PathRules.IsValidSegment(name, windows: true));
    }

    [Theory]
    [InlineData("file.txt:secret")]
    [InlineData("CON")]
    [InlineData("nul.txt")]
    [InlineData("COM1")]
    [InlineData("name.")]
    [InlineData("name ")]
    [InlineData("a*b")]
    [InlineData("a|b")]
    public void NamesThatMeanSomethingElseOnWindows(string name)
    {
        Assert.False(PathRules.IsValidSegment(name, windows: true));
        Assert.True(PathRules.IsValidSegment(name, windows: false));
    }

    [Theory]
    [InlineData("report (final).pdf")]
    [InlineData("日本語.txt")]
    [InlineData(".hidden")]
    [InlineData("😀.png")]
    public void OrdinaryNames(string name)
    {
        Assert.True(PathRules.IsValidSegment(name, windows: true));
        Assert.True(PathRules.IsValidSegment(name, windows: false));
    }

    [Fact]
    public void NameOfTooManyBytes() => Assert.False(PathRules.IsValidSegment(new string('日', 100), windows: false));

    [Fact]
    public void TargetsAreSplitBeforeTheyreDecoded()
    {
        // An encoded slash stays inside its segment, where the rules on names then refuse it.
        Assert.Equal(["a/b"], PathRules.DecodeTarget("/a%2Fb")!);
        Assert.Equal(["..", "..", "etc"], PathRules.DecodeTarget("/%2e%2e/%2E%2E/etc")!);
        Assert.Null(PathRules.Check(PathRules.DecodeTarget("/%2e%2e/%2E%2E/etc")!));
        Assert.Null(PathRules.Check(PathRules.DecodeTarget("/a%2Fb")!));
        Assert.Null(PathRules.Check(PathRules.DecodeTarget("/a%5Cb")!));
        Assert.Null(PathRules.Check(PathRules.DecodeTarget("/a%00b")!));
    }

    [Theory]
    [InlineData("/a%ZZ")]
    [InlineData("/a%")]
    [InlineData("/a%FF")]
    [InlineData("/%C0%AF")]
    public void BrokenEncodingIsRefused(string target) => Assert.Null(PathRules.DecodeTarget(target));

    [Fact]
    public void Targets()
    {
        Assert.Equal(["a b", "c"], PathRules.DecodeTarget("/a%20b/c/?x=1")!);
        Assert.Equal([], PathRules.DecodeTarget("*")!);
        Assert.Equal(["a"], PathRules.DecodeTarget("http://example.com/a")!);
    }

    [Theory]
    [InlineData("203.0.113.7", "203.0.113.7", true)]
    [InlineData("203.0.113.0/24", "203.0.113.200", true)]
    [InlineData("203.0.113.9/24", "203.0.113.200", true)]
    [InlineData("203.0.113.0/24", "203.0.114.1", false)]
    [InlineData("2001:db8::/32", "2001:db8:1::5", true)]
    [InlineData("2001:db8::/32", "2001:db9::5", false)]
    [InlineData("203.0.113.7", "::ffff:203.0.113.7", true)]
    public void WhitelistNetworks(string rule, string address, bool allowed)
    {
        var verdict = AccessList.Parse([rule]).Check(IPAddress.Parse(address), null);
        Assert.Equal(allowed ? AccessVerdict.Allowed : AccessVerdict.Denied, verdict);
    }

    private sealed class FakePlaces(bool loaded = true) : IPlaces
    {
        public bool Loaded => loaded;
        public (string Country, int Asn) Lookup(IPAddress address) => ("CA", 64500);
    }

    [Fact]
    public void WhitelistPlaces()
    {
        var anywhere = IPAddress.Parse("198.51.100.1");
        Assert.Equal(AccessVerdict.Allowed, AccessList.Parse(["CA"]).Check(anywhere, new FakePlaces()));
        Assert.Equal(AccessVerdict.Allowed, AccessList.Parse(["ca"]).Check(anywhere, new FakePlaces()));
        Assert.Equal(AccessVerdict.Allowed, AccessList.Parse(["AS64500"]).Check(anywhere, new FakePlaces()));
        Assert.Equal(AccessVerdict.Denied, AccessList.Parse(["US", "AS64501"]).Check(anywhere, new FakePlaces()));
    }

    [Fact]
    public void WithoutADatabaseWhitelistsCantTellAndDontPunish()
    {
        var address = IPAddress.Parse("198.51.100.1");
        Assert.Equal(AccessVerdict.CannotTell, AccessList.Parse(["CA"]).Check(address, new FakePlaces(loaded: false)));
        Assert.Equal(AccessVerdict.CannotTell, AccessList.Parse(["CA"]).Check(address, null));
        Assert.Equal(AccessVerdict.Allowed, AccessList.Parse(["CA", "198.51.100.1"]).Check(address, null));
        Assert.Equal(AccessVerdict.Denied, AccessList.Parse(["203.0.113.1"]).Check(address, null));
    }

    [Fact]
    public void AnEmptyWhitelistAllowsEveryoneButAnUnreadableOneDoesnt()
    {
        var address = IPAddress.Parse("198.51.100.1");
        Assert.Equal(AccessVerdict.Allowed, AccessList.Parse([]).Check(address, null));
        Assert.Equal(AccessVerdict.Denied, AccessList.Parse(["not a rule"]).Check(address, null));
    }

    [Theory]
    [InlineData("203.0.113.7", true)]
    [InlineData("203.0.113.0/24", true)]
    [InlineData("2001:db8::/32", true)]
    [InlineData("AS64500", true)]
    [InlineData("as64500", true)]
    [InlineData("CA", true)]
    [InlineData("Canada", false)]
    [InlineData("ASX", false)]
    [InlineData("203.0.113.0/33", false)]
    [InlineData("", false)]
    public void WhitelistRulesAreChecked(string rule, bool good) => Assert.Equal(good, AccessList.Problem(rule) is null);

    // ---- Who's really connecting ---------------------------------------------------------------------------------

    private static readonly IPNetwork[] Nginx = [IPNetwork.Parse("10.0.0.0/8")];
    private static readonly IPNetwork[] Cloudflare = [IPNetwork.Parse("198.51.100.0/24")];

    private static ClientInfo Resolve(string peer, bool tls, IPNetwork[] proxies, IPNetwork[] cloudflare, params (string Name, string Value)[] headers) => Resolve(peer, tls, proxies, cloudflare, false, false, headers);

    private static ClientInfo Resolve(string peer, bool tls, IPNetwork[] proxies, IPNetwork[] cloudflare, bool realIpOnly, bool allowClearHop, params (string Name, string Value)[] headers)
    {
        var dictionary = new HeaderDictionary();
        foreach (var (name, value) in headers) dictionary.Append(name, value);
        return ClientAddress.Resolve(IPAddress.Parse(peer), tls, dictionary, "direct.example", proxies, cloudflare, realIpOnly, allowClearHop);
    }

    [Fact]
    public void HeadersFromAStrangerAreIgnored()
    {
        var client = Resolve("203.0.113.9", true, Nginx, Cloudflare, ("X-Forwarded-For", "127.0.0.1"), ("X-Real-IP", "127.0.0.1"), ("CF-Connecting-IP", "127.0.0.1"), ("X-Forwarded-Proto", "http"), ("X-Forwarded-Host", "evil.example"));
        Assert.Equal("203.0.113.9", client.Address.ToString());
        Assert.False(client.ViaProxy);
        Assert.True(client.Secure);
        Assert.Equal("direct.example", client.Host);
    }

    [Fact]
    public void WhatAClientAddsToTheLeftOfForwardedForIsIgnored()
    {
        var client = Resolve("10.0.0.1", true, Nginx, [], ("X-Forwarded-For", "127.0.0.1, 192.0.2.50, 203.0.113.9"), ("X-Forwarded-Proto", "https"));
        Assert.Equal("203.0.113.9", client.Address.ToString());
        Assert.True(client.ViaProxy);
        Assert.True(client.Secure);
    }

    [Fact]
    public void ThroughTwoProxies()
    {
        var client = Resolve("10.0.0.1", false, Nginx, [], ("X-Forwarded-For", "203.0.113.9, 10.0.0.2"), ("X-Forwarded-Proto", "https"));
        Assert.Equal("203.0.113.9", client.Address.ToString());
    }

    [Fact]
    public void OneHeaderOrTheOtherNeverWhicheverTurnsUp()
    {
        // A proxy that sets X-Real-IP alone passes on whatever a client writes in X-Forwarded-For, and the other way round.
        var realIp = Resolve("10.0.0.1", true, Nginx, [], true, false, ("X-Real-IP", "203.0.113.9"), ("X-Forwarded-For", "192.0.2.1"));
        Assert.Equal("203.0.113.9", realIp.Address.ToString());
        var forwarded = Resolve("10.0.0.1", true, Nginx, [], ("X-Real-IP", "192.0.2.1"), ("X-Forwarded-For", "203.0.113.9"));
        Assert.Equal("203.0.113.9", forwarded.Address.ToString());
    }

    [Fact]
    public void WithNeitherHeaderTheProxyIsAllThatsKnown()
    {
        Assert.Equal("10.0.0.1", Resolve("10.0.0.1", true, Nginx, [], ("X-Real-IP", "192.0.2.1")).Address.ToString());
        Assert.Equal("10.0.0.1", Resolve("10.0.0.1", true, Nginx, [], true, false, ("X-Forwarded-For", "192.0.2.1")).Address.ToString());
    }

    [Fact]
    public void TheLastStretchFromAProxyHasToBeSafeToo()
    {
        (string, string)[] headers = [("X-Forwarded-For", "203.0.113.9"), ("X-Forwarded-Proto", "https")];
        Assert.False(Resolve("10.0.0.1", false, Nginx, [], headers).Secure);
        Assert.True(Resolve("10.0.0.1", true, Nginx, [], headers).Secure);
        Assert.True(Resolve("10.0.0.1", false, Nginx, [], false, true, headers).Secure);
        Assert.True(Resolve("127.0.0.1", false, [IPNetwork.Parse("127.0.0.0/8")], [], headers).Secure);
        // What the admin allows for a proxy they've named, they don't allow for Cloudflare, which comes over the internet.
        Assert.False(Resolve("198.51.100.7", false, [], Cloudflare, false, true, ("CF-Connecting-IP", "203.0.113.9"), ("X-Forwarded-Proto", "https")).Secure);
    }

    [Fact]
    public void CloudflareStraightToTheServer()
    {
        var client = Resolve("198.51.100.7", true, [], Cloudflare, ("CF-Connecting-IP", "203.0.113.9"), ("X-Forwarded-For", "6.6.6.6, 203.0.113.9"), ("X-Forwarded-Proto", "https"));
        Assert.Equal("203.0.113.9", client.Address.ToString());
        Assert.True(client.Secure);
    }

    [Fact]
    public void CloudflareThenNginx()
    {
        var client = Resolve("10.0.0.1", false, Nginx, Cloudflare, ("CF-Connecting-IP", "203.0.113.9"), ("X-Forwarded-For", "6.6.6.6, 203.0.113.9, 198.51.100.7"), ("X-Forwarded-Proto", "https"));
        Assert.Equal("203.0.113.9", client.Address.ToString());
    }

    [Fact]
    public void GoingStraightToNginxWithACloudflareHeaderGetsNowhere()
    {
        var client = Resolve("10.0.0.1", false, Nginx, Cloudflare, ("CF-Connecting-IP", "192.0.2.1"), ("X-Forwarded-For", "203.0.113.9"), ("X-Forwarded-Proto", "https"));
        Assert.Equal("203.0.113.9", client.Address.ToString());
    }

    [Fact]
    public void CloudflareHeaderNotBelievedWhenCloudflareIsntTrusted()
    {
        var client = Resolve("198.51.100.7", true, [], [], ("CF-Connecting-IP", "192.0.2.1"));
        Assert.Equal("198.51.100.7", client.Address.ToString());
        Assert.False(client.ViaProxy);
    }

    [Theory]
    [InlineData("http", false)]
    [InlineData("https", true)]
    [InlineData("https,http", false)]
    public void TlsMustReachAllTheWayToTheClient(string proto, bool secure) =>
        Assert.Equal(secure, Resolve("10.0.0.1", true, Nginx, [], ("X-Forwarded-For", "203.0.113.9"), ("X-Forwarded-Proto", proto)).Secure);

    [Fact]
    public void CloudflareFlexibleIsInTheClear()
    {
        // The last hop crosses the internet without TLS, whatever Cloudflare says about the first.
        var client = Resolve("198.51.100.7", false, [], Cloudflare, ("CF-Connecting-IP", "203.0.113.9"), ("X-Forwarded-Proto", "https"));
        Assert.False(client.Secure);
    }

    [Fact]
    public void PlainHttpFromAStrangerIsntSecureButFromThisMachineIs()
    {
        Assert.False(Resolve("203.0.113.9", false, [], []).Secure);
        Assert.True(Resolve("127.0.0.1", false, [], []).Secure);
    }

    [Fact]
    public void ForwardedHostAndPrefixFromAProxy()
    {
        var client = Resolve("10.0.0.1", true, Nginx, [], ("X-Forwarded-For", "203.0.113.9"), ("X-Forwarded-Proto", "https"), ("X-Forwarded-Host", "files.example"), ("X-Forwarded-Prefix", "/dav/"));
        Assert.Equal("files.example", client.Host);
        Assert.Equal("/dav", client.PathBase);
        Assert.Equal("https", client.Scheme);

        var bad = Resolve("10.0.0.1", false, Nginx, [], ("X-Forwarded-For", "203.0.113.9"), ("X-Forwarded-Host", "evil\"><script>"), ("X-Forwarded-Prefix", "/../x\""));
        Assert.Equal("direct.example", bad.Host);
        Assert.Equal("", bad.PathBase);
    }

    [Fact]
    public void CloudflareListIsOnlyBelievedIfItLooksRight()
    {
        Assert.Null(CloudflareRanges.Parse(["173.245.48.0/20"]));
        Assert.Null(CloudflareRanges.Parse([.. Enumerable.Repeat("173.245.48.0/20", 12), "<html>"]));
        Assert.Null(CloudflareRanges.Parse([.. Enumerable.Repeat("173.245.48.0/20", 12), "0.0.0.0/0"]));
        Assert.NotNull(CloudflareRanges.Parse(Enumerable.Repeat("173.245.48.0/20", 12)));
    }

    // ---- Passwords -----------------------------------------------------------------------------------------------

    [Fact]
    public void PasswordsAreHashedWithArgon2id()
    {
        var hash = Passwords.Hash("correct horse battery");
        Assert.StartsWith("$argon2id$v=19$m=65536,t=3,p=2$", hash);
        Assert.DoesNotContain("correct", hash);
        Assert.True(Passwords.Verify("correct horse battery", hash));
        Assert.False(Passwords.Verify("wrong horse battery", hash));
        Assert.NotEqual(hash, Passwords.Hash("correct horse battery"));
    }

    [Theory]
    [InlineData("")]
    [InlineData("$argon2id$v=19$m=999999999,t=3,p=2$AAAA$AAAA")]
    [InlineData("$argon2i$v=19$m=8,t=1,p=1$AAAA$AAAA")]
    [InlineData("$argon2id$v=19$m=8,t=1,p=1$!!!$AAAA")]
    public void DamagedHashesDontMatchOrCrash(string encoded) => Assert.False(Passwords.Verify("x", encoded));

    [Fact]
    public void AppPasswords()
    {
        var password = Passwords.NewAppPassword();
        Assert.True(Passwords.LooksLikeAppPassword(password));
        Assert.Equal(41, password.Length);
        Assert.NotEqual(password, Passwords.NewAppPassword());
        Assert.False(Passwords.LooksLikeAppPassword("correct horse battery"));
        Assert.False(Passwords.LooksLikeAppPassword(password.Replace('-', 'a')));
    }

    [Fact]
    public void PasswordRules()
    {
        Assert.NotNull(Api.PasswordProblem("short"));
        Assert.NotNull(Api.PasswordProblem("aaaaaaaaaaaaaaaa"));
        Assert.NotNull(Api.PasswordProblem(new string('x', 2000)));
        Assert.Null(Api.PasswordProblem("correct horse battery"));
    }

    [Theory]
    [InlineData("Basic YWxpY2U6c2VjcmV0", "alice", "secret")]
    [InlineData("basic YWxpY2U6c2VjOnJldA==", "alice", "sec:ret")]
    public void BasicHeaders(string header, string name, string password)
    {
        Assert.True(BasicAuth.TryParse(header, out var n, out var p));
        Assert.Equal(name, n);
        Assert.Equal(password, p);
    }

    [Theory]
    [InlineData("Bearer abc")]
    [InlineData("Basic !!!")]
    [InlineData("Basic YWxpY2U=")]
    [InlineData("Basic OnNlY3JldA==")]
    public void BadBasicHeaders(string header) => Assert.False(BasicAuth.TryParse(header, out _, out _));

    // ---- Names, headers ------------------------------------------------------------------------------------------

    [Theory]
    [InlineData("/team", true)]
    [InlineData("/", true)]
    [InlineData("team", false)]
    [InlineData("/a/b", false)]
    [InlineData("/remote.php", false)]
    [InlineData("/OCS", false)]
    [InlineData("/index.php", false)]
    [InlineData("/.well-known", false)]
    [InlineData("/..", false)]
    [InlineData("/nul", false)]
    public void Paths(string path, bool good) => Assert.Equal(good, Names.MountProblem(path) is null);

    [Theory]
    [InlineData("alice", true)]
    [InlineData("a.b-c_d", true)]
    [InlineData("Alice", false)]
    [InlineData("../x", false)]
    [InlineData(".hidden", false)]
    [InlineData("con", false)]
    [InlineData("name.", false)]
    [InlineData("", false)]
    public void AccountNames(string name, bool good) => Assert.Equal(good, Names.AccountProblem(name) is null);

    [Fact]
    public void IfHeaders()
    {
        var lists = IfHeader.Parse("<http://x/a> (<urn:uuid:1> [\"e\"]) (Not <DAV:no-lock>)");
        Assert.NotNull(lists);
        Assert.Equal(2, lists.Count);
        Assert.Equal("http://x/a", lists[0].Resource);
        Assert.Equal("urn:uuid:1", lists[0].Conditions[0].Token);
        Assert.Equal("\"e\"", lists[0].Conditions[1].ETag);
        Assert.True(lists[1].Conditions[0].Not);
        Assert.Null(IfHeader.Parse("nonsense"));
        Assert.Null(IfHeader.Parse("(<unclosed"));
        Assert.Null(IfHeader.Parse("()"));
    }

    [Theory]
    [InlineData("bytes=0-4", 10, 0, 5)]
    [InlineData("bytes=5-", 10, 5, 5)]
    [InlineData("bytes=-3", 10, 7, 3)]
    [InlineData("bytes=8-100", 10, 8, 2)]
    public void Ranges(string header, long length, long start, long count)
    {
        var range = DavHandler.ParseRange(header, length);
        Assert.NotNull(range);
        Assert.Equal(start, range.Value.Start);
        Assert.Equal(count, range.Value.Count);
        Assert.False(range.Value.Unsatisfiable);
    }

    [Fact]
    public void RangesThatCantBeMet()
    {
        Assert.True(DavHandler.ParseRange("bytes=10-", 10)!.Value.Unsatisfiable);
        Assert.Null(DavHandler.ParseRange("bytes=0-1,3-4", 10));
        Assert.Null(DavHandler.ParseRange("lines=0-1", 10));
        Assert.Null(DavHandler.ParseRange("bytes=5-2", 10));
    }
}
