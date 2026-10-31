using System.Globalization;
using System.Xml.Linq;
using Microsoft.AspNetCore.StaticFiles;
using Strongthium.WebDavServer.Storage;
using static Strongthium.WebDavServer.Dav.DavXml;

namespace Strongthium.WebDavServer.Dav;

/// <summary>What the server works out for itself about a file, as opposed to what clients store on it.</summary>
public static class Properties
{
    private static readonly FileExtensionContentTypeProvider Types = new();

    public static string ContentType(string name) => Types.TryGetContentType(name, out var type) ? type : "application/octet-stream";

    public static string ETag(Entry entry, Node node) =>
        $"\"{node.Id:x}-{node.Generation:x}-{entry.Modified.UtcTicks:x}-{entry.Size:x}\"";

    /// <summary>The instance part of a Nextcloud file id: clients treat the whole as a string that identifies a file.</summary>
    public static string NextcloudId(long id) => $"{id:D8}ocwebdavserver";

    public static string HttpDate(DateTimeOffset time) => time.ToUniversalTime().ToString("r", CultureInfo.InvariantCulture);

    /// <summary>What Nextcloud clients are told they may do: read, and for those with write access, the rest. The top of a
    /// space can be written in, but not moved or deleted.</summary>
    public static string Permissions(Entry entry, bool readOnly)
    {
        if (readOnly) return "G";
        if (entry.Path.IsRoot) return "GCK";
        return entry.IsDirectory ? "GDNVCK" : "GDNVW";
    }

    /// <summary>The properties <c>allprop</c> and <c>propname</c> show. Nextcloud's and the quota are only given when asked
    /// for, since they cost more and most clients have no use for them.</summary>
    public static IEnumerable<XName> Standard(Entry entry)
    {
        yield return D + "creationdate";
        yield return D + "displayname";
        yield return D + "getlastmodified";
        yield return D + "getetag";
        yield return D + "resourcetype";
        yield return D + "supportedlock";
        yield return D + "lockdiscovery";
        if (!entry.IsDirectory)
        {
            yield return D + "getcontentlength";
            yield return D + "getcontenttype";
        }
    }

    /// <summary>Whether a property is the server's, which clients can't set.</summary>
    public static bool IsLive(XName name) =>
        name == D + "creationdate" || name == D + "displayname" || name == D + "getlastmodified" || name == D + "getetag"
        || name == D + "resourcetype" || name == D + "supportedlock" || name == D + "lockdiscovery" || name == D + "getcontentlength"
        || name == D + "getcontenttype" || name == D + "quota-available-bytes" || name == D + "quota-used-bytes"
        || name.Namespace == OC || name.Namespace == NC;

    public sealed record Context(DavRequest Request, Entry Entry, Node Node, IReadOnlyList<DavLock> Locks, Func<long> Used, Func<long> Free);

    /// <summary>A property's element, or null if this one doesn't have it.</summary>
    public static XElement? Live(XName name, Context context)
    {
        var entry = context.Entry;
        if (name.Namespace == D)
        {
            return name.LocalName switch
            {
                "creationdate" => new XElement(name, entry.Created.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture)),
                "displayname" => new XElement(name, entry.Path.IsRoot ? context.Request.Target.Mount.Path.TrimStart('/') : entry.Path.Name),
                "getlastmodified" => new XElement(name, HttpDate(entry.Modified)),
                "getetag" => new XElement(name, ETag(entry, context.Node)),
                "resourcetype" => entry.IsDirectory ? new XElement(name, new XElement(D + "collection")) : new XElement(name),
                "getcontentlength" => entry.IsDirectory ? null : new XElement(name, entry.Size),
                "getcontenttype" => entry.IsDirectory ? null : new XElement(name, ContentType(entry.Path.Name)),
                "supportedlock" => SupportedLock(),
                "lockdiscovery" => LockDiscovery(context.Locks, context.Request),
                "quota-used-bytes" => entry.IsDirectory ? new XElement(name, context.Used()) : null,
                "quota-available-bytes" => entry.IsDirectory ? new XElement(name, context.Free()) : null,
                _ => null,
            };
        }
        if (name.Namespace == OC)
        {
            return name.LocalName switch
            {
                "id" => new XElement(name, NextcloudId(context.Node.Id)),
                "fileid" => new XElement(name, context.Node.Id),
                "permissions" => new XElement(name, Permissions(entry, context.Request.ReadOnly)),
                "size" => new XElement(name, entry.IsDirectory ? (entry.Path.IsRoot ? context.Used() : 0) : entry.Size),
                "owner-id" => new XElement(name, context.Request.Account.Name),
                "owner-display-name" => new XElement(name, context.Request.Account.Info.DisplayName is { Length: > 0 } shown ? shown : context.Request.Account.Name),
                "share-types" => new XElement(name),
                "favorite" => new XElement(name, 0),
                "downloadURL" or "dDC" or "data-fingerprint" => new XElement(name),
                _ => null,
            };
        }
        if (name.Namespace == NC)
        {
            return name.LocalName switch
            {
                "has-preview" => new XElement(name, "false"),
                "is-encrypted" => new XElement(name, 0),
                "mount-type" => new XElement(name),
                _ => null,
            };
        }
        return null;
    }

    private static XElement SupportedLock() => new(D + "supportedlock",
        new XElement(D + "lockentry", new XElement(D + "lockscope", new XElement(D + "exclusive")), new XElement(D + "locktype", new XElement(D + "write"))),
        new XElement(D + "lockentry", new XElement(D + "lockscope", new XElement(D + "shared")), new XElement(D + "locktype", new XElement(D + "write"))));

    public static XElement LockDiscovery(IEnumerable<DavLock> locks, DavRequest request) => new(D + "lockdiscovery", locks.Select(item => ActiveLock(item, request)));

    private static XElement ActiveLock(DavLock item, DavRequest request)
    {
        var active = new XElement(D + "activelock",
            new XElement(D + "locktype", new XElement(D + "write")),
            new XElement(D + "lockscope", new XElement(D + (item.Exclusive ? "exclusive" : "shared"))),
            new XElement(D + "depth", item.Infinite ? "infinity" : "0"));
        if (item.OwnerXml is not null)
        {
            try
            {
                active.Add(XElement.Parse(item.OwnerXml));
            }
            catch (System.Xml.XmlException)
            {
                // It was read as XML when it came in, so this can't really happen, and the lock matters more than this.
            }
        }
        active.Add(new XElement(D + "timeout", $"Second-{item.TimeoutSeconds}"));
        active.Add(new XElement(D + "locktoken", new XElement(D + "href", item.Token)));
        active.Add(new XElement(D + "lockroot", new XElement(D + "href", request.Href(item.Path, false))));
        return active;
    }
}
