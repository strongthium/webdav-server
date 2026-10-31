using System.Net;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Http;

namespace Strongthium.WebDavServer.Network;

/// <summary>Who's connecting, as far as can be trusted.</summary>
public sealed record ClientInfo
{
    /// <summary>The address bans and whitelists go by.</summary>
    public required IPAddress Address { get; init; }

    /// <summary>The other end of the socket: the client, or the proxy it came through.</summary>
    public required IPAddress Peer { get; init; }

    /// <summary>The socket belongs to a trusted proxy, and other people's requests may be on it too.</summary>
    public required bool ViaProxy { get; init; }

    /// <summary>Whether a password can be sent: the whole way from the client is TLS, or it's this machine.</summary>
    public required bool Secure { get; init; }
    public required string Scheme { get; init; }
    public required string Host { get; init; }

    /// <summary>The part of the address a proxy takes off before passing a request on.</summary>
    public required string PathBase { get; init; }
}

/// <summary>
/// Works out who a request is really from. The headers that say so are believed only from a socket whose other end is a proxy
/// the admin has named, or Cloudflare by its published ranges. From anyone else they're ignored: anybody can write
/// <c>X-Forwarded-For: 127.0.0.1</c>, and believing them would let an attacker slip past a whitelist, or ban someone else.
/// </summary>
public static partial class ClientAddress
{
    [GeneratedRegex(@"^[A-Za-z0-9.\-:\[\]]{1,255}$")]
    private static partial Regex HostPattern();

    [GeneratedRegex(@"^(/[A-Za-z0-9._~\-]+)+$")]
    private static partial Regex PrefixPattern();

    /// <summary>
    /// <c>X-Forwarded-For</c> is read from the right, since each proxy adds to its end and only what trusted proxies added
    /// can be believed: the first address that isn't one of them is the client, and anything further left is what the client
    /// wrote itself. <c>CF-Connecting-IP</c> counts only when the address that passed the request on is really Cloudflare's,
    /// so a request sent straight to nginx with that header in it gets nowhere.
    /// </summary>
    public static ClientInfo Resolve(IPAddress peer, bool isTls, IHeaderDictionary headers, string hostHeader, IPNetwork[] proxies, IPNetwork[] cloudflare, bool realIpOnly = false, bool allowClearHop = false)
    {
        peer = Networks.Normal(peer);
        var loopback = IPAddress.IsLoopback(peer);
        if (!IsIn(peer, proxies) && !IsIn(peer, cloudflare))
        {
            return new ClientInfo
            {
                Address = peer,
                Peer = peer,
                ViaProxy = false,
                Secure = isTls || loopback,
                Scheme = isTls ? "https" : "http",
                Host = hostHeader,
                PathBase = "",
            };
        }

        var cfHeader = ParseAddress(headers["CF-Connecting-IP"].ToString());
        // One header or the other, never whichever turns up: a proxy that sets one passes on what a client wrote in the other.
        List<IPAddress> chain = [];
        if (!realIpOnly) chain = ForwardedFor(headers);
        else if (ParseAddress(headers["X-Real-IP"].ToString()) is { } realIp) chain.Add(realIp);

        var client = peer;
        var hop = peer;
        var found = false;
        foreach (var address in chain)
        {
            if (cfHeader is not null && IsIn(hop, cloudflare))
            {
                client = cfHeader;
                found = true;
                break;
            }
            if (!IsIn(address, proxies) && !IsIn(address, cloudflare))
            {
                client = address;
                found = true;
                break;
            }
            hop = address;
        }
        if (!found) client = cfHeader is not null && IsIn(hop, cloudflare) ? cfHeader : hop;

        // Whether the password has been safe the whole way. The last stretch, from the proxy to here, has to be TLS or stay on
        // this machine: anything else crosses a network in the clear, whatever the proxy says about the first half. Cloudflare's
        // Flexible SSL is the plainest case of that, and the admin can only allow it for proxies they've named. Then the
        // client's own connection has to have been TLS, and every hop has to say so: "https,http" is a stretch in the clear.
        var protos = headers["X-Forwarded-Proto"].ToString().Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
        var lastStretchSafe = isTls || loopback || (allowClearHop && IsIn(peer, proxies));
        bool secure;
        if (!lastStretchSafe) secure = false;
        else if (protos.Length > 0) secure = protos.All(proto => proto.Equals("https", StringComparison.OrdinalIgnoreCase));
        else secure = isTls || loopback && client.Equals(peer);
        var scheme = protos.Length > 0 ? (secure ? "https" : "http") : (isTls ? "https" : "http");

        var forwardedHost = headers["X-Forwarded-Host"].ToString().Split(',', StringSplitOptions.TrimEntries)[0];
        var prefix = headers["X-Forwarded-Prefix"].ToString().Split(',', StringSplitOptions.TrimEntries)[0].TrimEnd('/');
        return new ClientInfo
        {
            Address = client,
            Peer = peer,
            ViaProxy = true,
            Secure = secure,
            Scheme = scheme,
            Host = HostPattern().IsMatch(forwardedHost) ? forwardedHost : hostHeader,
            PathBase = PrefixPattern().IsMatch(prefix) ? prefix : "",
        };
    }

    public static bool IsIn(IPAddress address, IPNetwork[] networks)
    {
        foreach (var network in networks)
        {
            if (network.Contains(address)) return true;
        }
        return false;
    }

    /// <summary>The addresses in <c>X-Forwarded-For</c>, rightmost first, up to the first that can't be read. Whatever is
    /// left of something unreadable came from no trusted proxy, so it isn't looked at.</summary>
    private static List<IPAddress> ForwardedFor(IHeaderDictionary headers)
    {
        var addresses = new List<IPAddress>();
        var values = headers["X-Forwarded-For"];
        for (var v = values.Count - 1; v >= 0; v--)
        {
            var parts = (values[v] ?? "").Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
            for (var i = parts.Length - 1; i >= 0; i--)
            {
                if (ParseAddress(parts[i]) is not { } address) return addresses;
                addresses.Add(address);
                if (addresses.Count >= 32) return addresses;
            }
        }
        return addresses;
    }

    /// <summary>An address, as proxies write them: <c>203.0.113.7</c>, <c>2001:db8::1</c>, with or without a port.</summary>
    public static IPAddress? ParseAddress(string text)
    {
        text = text.Trim();
        if (text.Length == 0) return null;
        if (IPAddress.TryParse(text, out var address)) return Networks.Normal(address);
        return IPEndPoint.TryParse(text, out var endPoint) ? Networks.Normal(endPoint.Address) : null;
    }
}
