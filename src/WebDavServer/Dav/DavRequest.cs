using Microsoft.AspNetCore.Http;
using Strongthium.WebDavServer.Network;
using Strongthium.WebDavServer.Security;
using Strongthium.WebDavServer.Storage;

namespace Strongthium.WebDavServer.Dav;

/// <summary>Where a request's address leads, for an account: which path, which file, and how to write that file's address
/// back in the way the client asked for it.</summary>
public sealed record DavTarget(MountInfo Mount, Space Space, RelPath Path, string HrefBase, bool ReadOnly);

/// <summary>A request that has passed the door and logged in, with its address worked out.</summary>
public sealed record DavRequest(HttpContext Http, ClientInfo Client, Account Account, DavTarget Target)
{
    public Space Space => Target.Space;
    public RelPath Path => Target.Path;
    public bool ReadOnly => Target.ReadOnly;

    public string Href(RelPath path, bool folder) => Href(Client, Target.HrefBase, path, folder);

    public static string Href(ClientInfo client, string hrefBase, RelPath path, bool folder)
    {
        var encoded = PathRules.Encode(path.Segments);
        var href = client.PathBase + hrefBase + "/" + encoded;
        return folder && !href.EndsWith('/') ? href + "/" : href;
    }
}

/// <summary>What the first part of an address is.</summary>
public enum RouteKind
{
    /// <summary>A path, and what's after it.</summary>
    Mount,

    /// <summary>The server's own address, no path: the list of paths.</summary>
    Top,

    /// <summary>One of the addresses a Nextcloud client uses, at the server's address or under a path.</summary>
    Nextcloud,

    NotFound,
}

public sealed record DavRoute(RouteKind Kind, MountInfo? Mount, string[] Rest)
{
    /// <summary>What failed logins here count against.</summary>
    public string Scope => Mount?.Path ?? Scopes.Root;
}

/// <summary>
/// Sorts addresses out. Nextcloud clients use a handful of fixed names, like <c>/remote.php/dav/files/alice/</c>, at the
/// address they were given, and those names can't be files in a path's top folder or the names of paths. So one address
/// serves both: <c>/team/report.pdf</c> is plain WebDAV, <c>/team/remote.php/webdav/report.pdf</c> and
/// <c>/remote.php/webdav/report.pdf</c> are Nextcloud's, and all of them lead through <see cref="Resolve"/> to the same file.
/// </summary>
public static class Router
{
    private static readonly HashSet<string> NextcloudTop = new(StringComparer.OrdinalIgnoreCase) { "status.php", "remote.php", "ocs", "index.php", "ocs-provider", "ocm-provider" };

    public static DavRoute Locate(Policy policy, string[] segments)
    {
        MountInfo? mount = null;
        var rest = segments;
        if (segments.Length > 0 && policy.Mounts.TryGetValue("/" + segments[0], out var named) && named.Path != "/")
        {
            if (!named.Enabled) return new DavRoute(RouteKind.NotFound, null, segments);
            mount = named;
            rest = segments[1..];
        }
        else mount = policy.RootMount;

        if ((mount is null || mount.Nextcloud) && rest.Length > 0 && NextcloudTop.Contains(rest[0])) return new DavRoute(RouteKind.Nextcloud, mount?.Path == "/" ? null : mount, rest);
        if (mount is not null) return new DavRoute(RouteKind.Mount, mount, rest);
        return new DavRoute(rest.Length == 0 ? RouteKind.Top : RouteKind.NotFound, null, rest);
    }

    /// <summary>
    /// The file an address leads to, for an account: used for the request's own address, a <c>Destination</c> and the
    /// addresses in an <c>If</c> header. A status code if it leads nowhere it may go.
    /// </summary>
    public static (DavTarget? Target, int Status) Resolve(ServerState state, Account account, string[] segments)
    {
        var policy = state.Policy;
        var route = Locate(policy, segments);
        switch (route.Kind)
        {
            case RouteKind.Mount:
                return Target(state, account, route.Mount!, route.Rest, route.Mount!.Path == "/" ? "" : route.Mount.Path);

            case RouteKind.Nextcloud when route.Rest is ["remote.php", "webdav", .. var rest]:
                return NextcloudTarget(state, account, route, rest, "/remote.php/webdav");

            case RouteKind.Nextcloud when route.Rest is ["remote.php", "dav", "files", var user, .. var rest]:
                return user.Equals(account.Name, StringComparison.OrdinalIgnoreCase)
                    ? NextcloudTarget(state, account, route, rest, $"/remote.php/dav/files/{Uri.EscapeDataString(user)}")
                    : (null, StatusCodes.Status403Forbidden);

            default:
                return (null, StatusCodes.Status404NotFound);
        }
    }

    private static (DavTarget?, int) NextcloudTarget(ServerState state, Account account, DavRoute route, string[] rest, string suffix)
    {
        // HomeOf only ever gives a path that serves Nextcloud clients, and DavRoute only gets here for one that does.
        var mount = route.Mount ?? state.Policy.HomeOf(account);
        if (mount is null) return (null, StatusCodes.Status403Forbidden);
        var prefix = route.Mount is null ? "" : route.Mount.Path;
        return Target(state, account, mount, rest, prefix + suffix);
    }

    private static (DavTarget?, int) Target(ServerState state, Account account, MountInfo mount, string[] rest, string hrefBase)
    {
        if (account.GrantOn(mount.Path) is not { } grant) return (null, StatusCodes.Status403Forbidden);
        var path = PathRules.Check(rest);
        if (path is null) return (null, StatusCodes.Status400BadRequest);
        return (new DavTarget(mount, state.SpaceFor(mount, account), path, hrefBase, grant.ReadOnly), 0);
    }
}
