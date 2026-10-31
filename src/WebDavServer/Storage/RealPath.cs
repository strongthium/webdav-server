using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace Strongthium.WebDavServer.Storage;

/// <summary>
/// What a path on disk really is: links followed at every step and, on Windows, short names (<c>PROGRA~2</c>) made long. Two ways
/// of writing the same folder come out the same. What doesn't exist yet stays as written, after whatever part of it does.
/// </summary>
public static partial class RealPath
{
    public static string Of(string path)
    {
        var full = Path.GetFullPath(path);
        if (OperatingSystem.IsWindows()) full = LongName(full);
        var root = Path.GetPathRoot(full) ?? "";
        var current = root;
        foreach (var segment in full[root.Length..].Split(Path.DirectorySeparatorChar, StringSplitOptions.RemoveEmptyEntries))
        {
            current = Path.Combine(current, segment);
            FileSystemInfo info = new DirectoryInfo(current);
            if (!info.Exists) info = new FileInfo(current);
            if (info.Exists && info.LinkTarget is not null && info.ResolveLinkTarget(returnFinalTarget: true) is { } target) current = Of(target.FullName);
        }
        return current.TrimEnd(Path.DirectorySeparatorChar);
    }

    [SupportedOSPlatform("windows")]
    private static string LongName(string full)
    {
        // Windows can only say of a path that exists, so the part that does goes first, and the rest is added back.
        var existing = full;
        var rest = "";
        while (existing.Length > 0 && !Directory.Exists(existing) && !File.Exists(existing))
        {
            var parent = Path.GetDirectoryName(existing);
            if (parent is null) return full;
            rest = Path.Combine(Path.GetFileName(existing), rest);
            existing = parent;
        }
        var buffer = new char[32768];
        var length = GetLongPathNameW(existing, buffer, (uint)buffer.Length);
        if (length == 0 || length >= buffer.Length) return full;
        return Path.Combine(new string(buffer, 0, (int)length), rest).TrimEnd(Path.DirectorySeparatorChar);
    }

    [LibraryImport("kernel32.dll", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    private static partial uint GetLongPathNameW(string shortPath, [Out] char[] longPath, uint size);
}
