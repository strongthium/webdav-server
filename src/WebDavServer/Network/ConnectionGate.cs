using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using Microsoft.AspNetCore.Connections;
using Microsoft.AspNetCore.Connections.Features;
using Microsoft.AspNetCore.Http;
using Strongthium.WebDavServer.Security;

namespace Strongthium.WebDavServer.Network;

public enum ListenerKind
{
    Dav,
    Admin,
}

/// <summary>
/// The door. Every new connection comes here first, before TLS and before a byte has been read, so that one that isn't wanted
/// costs almost nothing: no handshake, no buffers, no request. It's closed with a reset, which frees the socket at once instead
/// of leaving it waiting in TIME_WAIT.
/// </summary>
public sealed class ConnectionGate(ServerState state, Guard guard)
{
    private readonly ConcurrentDictionary<string, (ConnectionContext Connection, ListenerKind Kind)> open = new();
    private long closedAtTheDoor;

    public int OpenConnections => open.Count;
    public long ClosedAtTheDoor => Interlocked.Read(ref closedAtTheDoor);

    public async Task OnConnectionAsync(ConnectionContext connection, ListenerKind kind, ConnectionDelegate next)
    {
        var peer = connection.RemoteEndPoint is IPEndPoint endPoint ? Networks.Normal(endPoint.Address) : IPAddress.None;
        if (!Admit(peer, kind))
        {
            HardClose(connection);
            return;
        }
        open[connection.ConnectionId] = (connection, kind);
        try
        {
            await next(connection);
        }
        finally
        {
            open.TryRemove(connection.ConnectionId, out _);
        }
    }

    /// <summary>Which listener a request came in on.</summary>
    public ListenerKind? KindOf(HttpContext context) => open.TryGetValue(context.Connection.Id, out var entry) ? entry.Kind : null;

    private bool Admit(IPAddress peer, ListenerKind kind)
    {
        var policy = state.Policy;
        if (kind == ListenerKind.Admin)
        {
            if (guard.IsBanned(peer, Scopes.Admin)) return false;
            return CheckWhitelist(policy.AdminWhitelist, peer, Scopes.Admin, "the admin whitelist");
        }

        // The socket of a trusted proxy says nothing about who's behind it: that's for each request, once it's been read.
        var cloudflare = policy.Settings.TrustCloudflare ? state.Cloudflare.Ranges : [];
        if (ClientAddress.IsIn(peer, policy.TrustedProxies) || ClientAddress.IsIn(peer, cloudflare)) return true;
        if (policy.Settings.RequireProxy && !IPAddress.IsLoopback(peer)) return false;
        if (guard.IsBanned(peer, Scopes.All)) return false;
        return CheckWhitelist(policy.Whitelist, peer, Scopes.All, "the server's whitelist");
    }

    private bool CheckWhitelist(AccessList list, IPAddress address, string scope, string what)
    {
        switch (list.Check(address, state.Geo))
        {
            case AccessVerdict.Allowed:
                return true;
            case AccessVerdict.CannotTell:
                // Whitelists naming countries or networks, and no database yet: kept out, but it's not the client's doing.
                return false;
            default:
                guard.Ban(address, scope, TimeSpan.FromMinutes(state.Policy.Settings.WhitelistBanMinutes), $"Connected from outside {what}.");
                return false;
        }
    }

    /// <summary>
    /// Ends a request with no answer. On its own socket, the socket is closed, whatever the protocol. Through a proxy, the
    /// socket isn't the client's: with HTTP/2 to the proxy, other people's requests may be on it, so only this request ends,
    /// which over HTTP/1.1 closes the connection to the proxy too, and the proxy tells the client it got nothing.
    /// </summary>
    public void Drop(HttpContext context, bool viaProxy)
    {
        if (!viaProxy && open.TryGetValue(context.Connection.Id, out var entry)) HardClose(entry.Connection);
        context.Abort();
    }

    private void HardClose(ConnectionContext connection)
    {
        Interlocked.Increment(ref closedAtTheDoor);
        try
        {
            if (connection.Features.Get<IConnectionSocketFeature>()?.Socket is { } socket) socket.LingerState = new LingerOption(true, 0);
        }
        catch (Exception exception) when (exception is SocketException or ObjectDisposedException)
        {
            // It's gone already.
        }
        connection.Abort(new ConnectionAbortedException("Not wanted here."));
    }
}
