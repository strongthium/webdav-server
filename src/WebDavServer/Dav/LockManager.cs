using Strongthium.WebDavServer.Storage;

namespace Strongthium.WebDavServer.Dav;

public sealed record DavLock
{
    public required string Token { get; init; }
    public required string Space { get; init; }
    public required RelPath Path { get; init; }
    public required bool Infinite { get; init; }
    public required bool Exclusive { get; init; }
    public required string Account { get; init; }

    /// <summary>What the client said about who holds it, as XML, to be given back as it was.</summary>
    public required string? OwnerXml { get; init; }
    public DateTimeOffset Expires { get; set; }
    public int TimeoutSeconds { get; set; }
}

/// <summary>
/// WebDAV's locks (RFC 4918, class 2), which Windows and macOS want before they'll write. They're on files in a space, not on
/// addresses: a lock taken over WebDAV holds against a Nextcloud client too, and the other way round. They live in memory, and
/// a restart ends them, which clients take in their stride since locks time out anyway.
/// </summary>
public sealed class LockManager(TimeProvider clock)
{
    public const int DefaultTimeoutSeconds = 3600;
    public const int MaxTimeoutSeconds = 24 * 3600;
    private const int MaxLocksPerAccount = 4096;

    private readonly Lock gate = new();
    private readonly Dictionary<string, DavLock> byToken = new(StringComparer.Ordinal);

    private DateTimeOffset Now => clock.GetUtcNow();

    private void Purge()
    {
        var now = Now;
        foreach (var token in byToken.Where(entry => entry.Value.Expires <= now).Select(entry => entry.Key).ToList()) byToken.Remove(token);
    }

    /// <summary>The locks that apply to a path: on it, and on folders above it that lock all they hold. With
    /// <paramref name="below"/>, also those on anything under it.</summary>
    public List<DavLock> Covering(string space, RelPath path, bool below = false, bool directParent = false)
    {
        lock (gate)
        {
            Purge();
            var parent = path.Parent;
            return [.. byToken.Values.Where(item => string.Equals(item.Space, space, PathRules.Compare)
                && ((path.IsInsideOrSame(item.Path) && (item.Infinite || item.Path.Equals(path)))
                    || (below && item.Path.IsInsideOrSame(path))
                    || (directParent && !path.IsRoot && item.Path.Equals(parent))))];
        }
    }

    /// <summary>A new lock, unless one in the way says otherwise: then null, and those in the way.</summary>
    public (DavLock? Lock, List<DavLock> Conflicts) Take(string space, RelPath path, bool infinite, bool exclusive, string account, string? ownerXml, int timeoutSeconds)
    {
        lock (gate)
        {
            Purge();
            var conflicts = byToken.Values.Where(item => string.Equals(item.Space, space, PathRules.Compare)
                && (exclusive || item.Exclusive)
                && ((path.IsInsideOrSame(item.Path) && (item.Infinite || item.Path.Equals(path))) || (infinite && item.Path.IsInsideOrSame(path)))).ToList();
            if (conflicts.Count > 0) return (null, conflicts);
            if (byToken.Values.Count(item => item.Account == account) >= MaxLocksPerAccount) return (null, []);
            var created = new DavLock
            {
                Token = "urn:uuid:" + Guid.NewGuid().ToString("D"),
                Space = space,
                Path = path,
                Infinite = infinite,
                Exclusive = exclusive,
                Account = account,
                OwnerXml = ownerXml,
                TimeoutSeconds = timeoutSeconds,
                Expires = Now.AddSeconds(timeoutSeconds),
            };
            byToken[created.Token] = created;
            return (created, []);
        }
    }

    public DavLock? Find(string token)
    {
        lock (gate)
        {
            Purge();
            return byToken.GetValueOrDefault(token);
        }
    }

    public void Refresh(DavLock item, int timeoutSeconds)
    {
        lock (gate)
        {
            item.TimeoutSeconds = timeoutSeconds;
            item.Expires = Now.AddSeconds(timeoutSeconds);
        }
    }

    public bool Release(string token)
    {
        lock (gate) return byToken.Remove(token);
    }

    /// <summary>A file or folder has gone: so have the locks on it and on what it held.</summary>
    public void RemoveTree(string space, RelPath path)
    {
        lock (gate)
        {
            foreach (var token in byToken.Values.Where(item => string.Equals(item.Space, space, PathRules.Compare) && item.Path.IsInsideOrSame(path)).Select(item => item.Token).ToList())
                byToken.Remove(token);
        }
    }
}

/// <summary>A condition in an <c>If</c> header: a lock token or an entity tag, perhaps with <c>Not</c>.</summary>
public sealed record IfCondition(bool Not, string? Token, string? ETag);

/// <summary>One bracketed list, all of whose conditions must hold, and the address it's about, if not the request's own.</summary>
public sealed record IfList(string? Resource, IReadOnlyList<IfCondition> Conditions);

public static class IfHeader
{
    /// <summary>An <c>If</c> header (RFC 4918, 10.4) read into its lists. Null if it can't be read.</summary>
    public static List<IfList>? Parse(string header)
    {
        var lists = new List<IfList>();
        string? resource = null;
        var i = 0;
        while (true)
        {
            SkipSpace(header, ref i);
            if (i >= header.Length) break;
            if (header[i] == '<')
            {
                var end = header.IndexOf('>', i);
                if (end < 0) return null;
                resource = header[(i + 1)..end];
                i = end + 1;
                SkipSpace(header, ref i);
                if (i >= header.Length || header[i] != '(') return null;
            }
            if (header[i] != '(') return null;
            i++;
            var conditions = new List<IfCondition>();
            while (true)
            {
                SkipSpace(header, ref i);
                if (i >= header.Length) return null;
                if (header[i] == ')')
                {
                    i++;
                    break;
                }
                var not = false;
                if (string.CompareOrdinal(header, i, "Not", 0, 3) == 0)
                {
                    not = true;
                    i += 3;
                    SkipSpace(header, ref i);
                    if (i >= header.Length) return null;
                }
                if (header[i] == '<')
                {
                    var end = header.IndexOf('>', i);
                    if (end < 0) return null;
                    conditions.Add(new IfCondition(not, header[(i + 1)..end], null));
                    i = end + 1;
                }
                else if (header[i] == '[')
                {
                    var end = header.IndexOf(']', i);
                    if (end < 0) return null;
                    conditions.Add(new IfCondition(not, null, header[(i + 1)..end].Trim()));
                    i = end + 1;
                }
                else return null;
            }
            if (conditions.Count == 0) return null;
            lists.Add(new IfList(resource, conditions));
        }
        return lists.Count > 0 ? lists : null;
    }

    private static void SkipSpace(string text, ref int i)
    {
        while (i < text.Length && char.IsWhiteSpace(text[i])) i++;
    }
}
