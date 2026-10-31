using System.Collections.Concurrent;
using System.Globalization;
using System.Text;

namespace Strongthium.WebDavServer.Storage;

/// <summary>A path inside a space, each segment already checked by <see cref="PathRules"/>.</summary>
public sealed class RelPath : IEquatable<RelPath>
{
    public static readonly RelPath Root = new([]);

    public IReadOnlyList<string> Segments { get; }

    /// <summary>Segments joined by <c>/</c>, without a slash at either end; empty for the top of the space.</summary>
    public string Key { get; }

    internal RelPath(IReadOnlyList<string> segments)
    {
        Segments = segments;
        Key = string.Join('/', segments);
    }

    public bool IsRoot => Segments.Count == 0;
    public string Name => Segments.Count == 0 ? "" : Segments[^1];
    public RelPath Parent => Segments.Count == 0 ? this : new RelPath([.. Segments.Take(Segments.Count - 1)]);
    public RelPath Child(string name) => new([.. Segments, name]);

    public bool IsInsideOrSame(RelPath other)
    {
        if (Segments.Count < other.Segments.Count) return false;
        for (var i = 0; i < other.Segments.Count; i++)
        {
            if (!string.Equals(Segments[i], other.Segments[i], PathRules.Compare)) return false;
        }
        return true;
    }

    public bool Equals(RelPath? other) => other is not null && Segments.Count == other.Segments.Count && IsInsideOrSame(other);
    public override bool Equals(object? obj) => Equals(obj as RelPath);
    public override int GetHashCode() => PathRules.Comparer.GetHashCode(Key);
    public override string ToString() => Key;
}

/// <summary>
/// What may be a name in a path. Paths come from clients, percent-encoded, and every byte is untrusted: this and
/// <see cref="Space.FullPath"/> are what keep a client inside its own files.
/// </summary>
public static class PathRules
{
    /// <summary>The folder inside each space for the server's own use: never listed, and no client can reach it.</summary>
    public const string Hidden = ".webdav-server";

    public const int MaxDepth = 64;
    public const int MaxSegmentBytes = 255;
    public const int MaxPathChars = 4000;

    public static StringComparison Compare => OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
    public static StringComparer Comparer => OperatingSystem.IsWindows() ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal;

    private static readonly HashSet<string> WindowsDevices = new(StringComparer.OrdinalIgnoreCase)
    {
        "CON", "PRN", "AUX", "NUL", "COM0", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9", "COM¹", "COM²", "COM³",
        "LPT0", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9", "LPT¹", "LPT²", "LPT³", "CONIN$", "CONOUT$",
    };

    /// <summary>Whether a single name, already decoded, may be used. It has to be safe on both systems the server runs on
    /// or on the one it's running on: names that Windows would read as something else (streams, devices) aren't just
    /// unusual there, they reach things other than the file.</summary>
    public static bool IsValidSegment(string segment) => IsValidSegment(segment, OperatingSystem.IsWindows());

    public static bool IsValidSegment(string segment, bool windows)
    {
        if (segment.Length == 0 || segment is "." or ".." || segment.Length > MaxSegmentBytes) return false;
        if (segment.Equals(Hidden, StringComparison.OrdinalIgnoreCase)) return false;
        if (Encoding.UTF8.GetByteCount(segment) > MaxSegmentBytes) return false;
        for (var i = 0; i < segment.Length; i++)
        {
            var c = segment[i];
            if (c < 0x20 || c == 0x7F || c == '/' || c == '\\') return false;
            if (char.IsSurrogate(c) && !(char.IsHighSurrogate(c) && i + 1 < segment.Length && char.IsLowSurrogate(segment[i + 1]) || char.IsLowSurrogate(c) && i > 0 && char.IsHighSurrogate(segment[i - 1]))) return false;
            if (c is '￾' or '￿') return false;
        }
        if (!windows) return true;

        if (segment.AsSpan().IndexOfAny("<>:\"|?*") >= 0) return false;
        if (segment[^1] is '.' or ' ') return false;
        var stem = segment.Split('.', 2)[0].TrimEnd(' ');
        return !WindowsDevices.Contains(stem);
    }

    /// <summary>The path part of a request's target, as it was sent, split and decoded. Null if it can't be read.</summary>
    public static string[]? DecodeTarget(string rawTarget)
    {
        var path = rawTarget;
        if (path == "*") return [];
        if (!path.StartsWith('/'))
        {
            // The absolute form: http://host/path
            if (!Uri.TryCreate(path, UriKind.Absolute, out var uri)) return null;
            path = uri.GetComponents(UriComponents.Path | UriComponents.KeepDelimiter, UriFormat.UriEscaped);
            if (!path.StartsWith('/')) path = "/" + path;
        }
        var query = path.IndexOf('?');
        if (query >= 0) path = path[..query];
        if (path.Length > MaxPathChars * 3) return null;

        var parts = new List<string>();
        foreach (var raw in path.Split('/', StringSplitOptions.RemoveEmptyEntries))
        {
            var decoded = PercentDecode(raw);
            if (decoded is null) return null;
            parts.Add(decoded);
        }
        return parts.Count > MaxDepth + 8 ? null : [.. parts];
    }

    /// <summary>Percent-decoding that refuses anything but well-formed UTF-8, rather than guessing.</summary>
    public static string? PercentDecode(string text)
    {
        if (!text.Contains('%')) return text;
        var bytes = new byte[Encoding.UTF8.GetByteCount(text)];
        var length = 0;
        for (var i = 0; i < text.Length; i++)
        {
            if (text[i] != '%')
            {
                length += Encoding.UTF8.GetBytes(text.AsSpan(i, char.IsHighSurrogate(text[i]) && i + 1 < text.Length ? 2 : 1), bytes.AsSpan(length));
                if (char.IsHighSurrogate(text[i])) i++;
                continue;
            }
            if (i + 2 >= text.Length || !byte.TryParse(text.AsSpan(i + 1, 2), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out bytes[length])) return null;
            length++;
            i += 2;
        }
        try
        {
            return new UTF8Encoding(false, throwOnInvalidBytes: true).GetString(bytes, 0, length);
        }
        catch (DecoderFallbackException)
        {
            return null;
        }
    }

    /// <summary>A checked path from decoded segments; null if any segment may not be used.</summary>
    public static RelPath? Check(IReadOnlyList<string> segments)
    {
        if (segments.Count == 0) return RelPath.Root;
        if (segments.Count > MaxDepth) return null;
        var total = 0;
        foreach (var segment in segments)
        {
            if (!IsValidSegment(segment)) return null;
            total += segment.Length + 1;
        }
        return total > MaxPathChars ? null : new RelPath([.. segments]);
    }

    /// <summary>A path encoded for an href: each segment percent-encoded, joined by slashes.</summary>
    public static string Encode(IEnumerable<string> segments) => string.Join('/', segments.Select(Uri.EscapeDataString));
}

/// <summary>A file or folder that's there.</summary>
public sealed record Entry(RelPath Path, string FullPath, bool IsDirectory, long Size, DateTimeOffset Modified, DateTimeOffset Created);

/// <summary>
/// One set of files on disk: an account's, a path's, or an account's on a path. Both protocols come to the same files through
/// this. A space's folder is its identity: its locks and properties go with the folder, whichever address reached it.
/// </summary>
public sealed class Space
{
    private static readonly ConcurrentDictionary<string, long> Swept = new(PathRules.Comparer);
    private const string UploadsPrefix = "uploads-";

    public string Root { get; }
    public long QuotaBytes { get; }

    public Space(string root, long quotaBytes)
    {
        Root = Path.GetFullPath(root);
        QuotaBytes = quotaBytes;
    }

    public string Key => Root;

    /// <summary>
    /// The place on disk for a path. Null if a symbolic link or junction is anywhere on the way: a link inside a user's files
    /// could lead outside them, so they're not followed, whoever made them. It's also checked that what came out of joining
    /// the names is inside the space, though the rules on names have already made sure of that.
    /// </summary>
    public string? FullPath(RelPath path)
    {
        Directory.CreateDirectory(Root);
        var current = Root;
        foreach (var segment in path.Segments)
        {
            current = Path.Combine(current, segment);
            FileSystemInfo info = new FileInfo(current);
            if (!info.Exists)
            {
                var folder = new DirectoryInfo(current);
                if (!folder.Exists)
                {
                    // Neither a file nor a folder: nothing further along can exist. A dangling link looks like this too.
                    if (info.LinkTarget is not null) return null;
                    continue;
                }
                info = folder;
            }
            if (info.LinkTarget is not null) return null;
            if (OperatingSystem.IsWindows() && IsShortNameAlias(current, segment)) return null;
        }
        var full = Path.GetFullPath(current);
        var inside = Root.EndsWith(Path.DirectorySeparatorChar) ? Root : Root + Path.DirectorySeparatorChar;
        return full.Equals(Root, PathRules.Compare) || full.StartsWith(inside, PathRules.Compare) ? full : null;
    }

    /// <summary>
    /// Windows gives long names a second, short one: <c>.webdav-server</c> can also be reached as <c>WEBDAV~1</c>, which no rule on
    /// names would catch, and which would be another name for a file that a lock or a check only knows by its real one. What's
    /// there is listed under its long name alone, so a name that opens something but isn't in the listing is one of these.
    /// </summary>
    private static bool IsShortNameAlias(string full, string segment)
    {
        if (!segment.Contains('~')) return false;
        var options = new EnumerationOptions { MatchType = MatchType.Simple, MatchCasing = MatchCasing.CaseInsensitive, AttributesToSkip = 0, IgnoreInaccessible = false };
        return !Directory.EnumerateFileSystemEntries(Path.GetDirectoryName(full)!, segment, options).Any();
    }

    public Entry? Stat(RelPath path)
    {
        var full = FullPath(path);
        return full is null ? null : StatFull(path, full);
    }

    private static Entry? StatFull(RelPath path, string full)
    {
        var file = new FileInfo(full);
        if (file.Exists) return new Entry(path, full, false, file.Length, file.LastWriteTimeUtc, file.CreationTimeUtc);
        var folder = new DirectoryInfo(full);
        return folder.Exists ? new Entry(path, full, true, 0, folder.LastWriteTimeUtc, folder.CreationTimeUtc) : null;
    }

    /// <summary>What's in a folder: never links, the server's own folder, or names that couldn't be asked for.</summary>
    public IEnumerable<Entry> List(Entry folder)
    {
        foreach (var info in new DirectoryInfo(folder.FullPath).EnumerateFileSystemInfos())
        {
            if (info.LinkTarget is not null || !PathRules.IsValidSegment(info.Name)) continue;
            var path = folder.Path.Child(info.Name);
            if (info is FileInfo file) yield return new Entry(path, file.FullName, false, file.Length, file.LastWriteTimeUtc, file.CreationTimeUtc);
            else yield return new Entry(path, info.FullName, true, 0, info.LastWriteTimeUtc, info.CreationTimeUtc);
        }
    }

    /// <summary>The server's folder for things on their way in: in the space, so that the last step is an atomic rename.</summary>
    public string WorkFolder(string name)
    {
        var folder = Path.Combine(Root, PathRules.Hidden, name);
        Directory.CreateDirectory(folder);
        var now = DateTime.UtcNow.Ticks;
        if (now - Swept.GetValueOrDefault(folder) > TimeSpan.TicksPerHour)
        {
            Swept[folder] = now;
            SweepStale(folder);
        }
        return folder;
    }

    /// <summary>Where an account keeps its chunked uploads on the way in. Each account has its own, even on a shared path: an
    /// upload is nobody else's to add to, finish or delete.</summary>
    public string UploadsFolder(string account) => WorkFolder(UploadsPrefix + account.ToLowerInvariant());

    /// <summary>What everyone's unfinished uploads in this space hold. It counts against the quota: it's on the disk.</summary>
    public long UploadsHeld()
    {
        var hidden = Path.Combine(Root, PathRules.Hidden);
        if (!Directory.Exists(hidden)) return 0;
        return Directory.EnumerateDirectories(hidden, UploadsPrefix + "*").Sum(UsageTracker.Count);
    }

    public string NewTempFile() => Path.Combine(WorkFolder("tmp"), Guid.NewGuid().ToString("N"));

    /// <summary>What an upload cut off by a crash left behind.</summary>
    private static void SweepStale(string folder)
    {
        var old = DateTime.UtcNow.AddDays(-2);
        foreach (var info in new DirectoryInfo(folder).EnumerateFileSystemInfos())
        {
            try
            {
                if (info.LastWriteTimeUtc >= old) continue;
                if (info is DirectoryInfo d) d.Delete(true);
                else info.Delete();
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
            {
                // It's in use; the next start gets it.
            }
        }
    }
}

/// <summary>How much each space holds. It's counted once by walking the folder, then kept up to date, and counted again
/// every so often in case files were changed on the server directly.</summary>
public sealed class UsageTracker
{
    private sealed class Usage
    {
        public long Bytes;
        public long CountedAt;
    }

    private static readonly long Recount = TimeSpan.FromMinutes(15).Ticks;
    private readonly ConcurrentDictionary<string, Usage> usages = new(PathRules.Comparer);

    public long Get(Space space)
    {
        var usage = usages.GetOrAdd(space.Key, _ => new Usage());
        var now = DateTime.UtcNow.Ticks;
        if (now - Interlocked.Read(ref usage.CountedAt) > Recount)
        {
            lock (usage)
            {
                if (now - Interlocked.Read(ref usage.CountedAt) > Recount)
                {
                    Interlocked.Exchange(ref usage.Bytes, Count(space.Root));
                    Interlocked.Exchange(ref usage.CountedAt, now);
                }
            }
        }
        return Math.Max(0, Interlocked.Read(ref usage.Bytes));
    }

    public void Add(Space space, long delta)
    {
        if (usages.TryGetValue(space.Key, out var usage)) Interlocked.Add(ref usage.Bytes, delta);
    }

    /// <summary>How much a folder holds, not counting what's still on its way in or anything a link leads to.</summary>
    public static long Count(string folder)
    {
        if (!Directory.Exists(folder)) return 0;
        var options = new EnumerationOptions { RecurseSubdirectories = false, IgnoreInaccessible = true, AttributesToSkip = FileAttributes.ReparsePoint };
        long total = 0;
        var pending = new Stack<string>();
        pending.Push(folder);
        while (pending.TryPop(out var current))
        {
            foreach (var info in new DirectoryInfo(current).EnumerateFileSystemInfos("*", options))
            {
                if (info.LinkTarget is not null) continue;
                if (info is FileInfo file) total += file.Length;
                else if (!info.Name.Equals(PathRules.Hidden, StringComparison.OrdinalIgnoreCase)) pending.Push(info.FullName);
            }
        }
        return total;
    }
}
