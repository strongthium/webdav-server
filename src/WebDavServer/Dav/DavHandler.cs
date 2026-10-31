using System.Buffers;
using System.Globalization;
using System.Security.Cryptography;
using System.Xml;
using System.Xml.Linq;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Strongthium.WebDavServer.Security;
using Strongthium.WebDavServer.Storage;
using static Strongthium.WebDavServer.Dav.DavXml;

namespace Strongthium.WebDavServer.Dav;

/// <summary>
/// WebDAV itself (RFC 4918, class 1 and 2, with the quota properties of RFC 4331). Every protocol that reaches files comes
/// through here, so a file behaves the same however it was reached: same locks, same tags, same ids, same limits.
/// </summary>
public sealed class DavHandler(ServerState state, LockManager locks, Guard guard)
{
    public const string AllowedMethods = "OPTIONS, GET, HEAD, PUT, DELETE, MKCOL, COPY, MOVE, PROPFIND, PROPPATCH, LOCK, UNLOCK, REPORT";
    private const int BufferBytes = 256 * 1024;
    private const int MaxPropertiesAsked = 256;

    public LockManager Locks => locks;

    public Task HandleAsync(DavRequest request) => request.Http.Request.Method.ToUpperInvariant() switch
    {
        "GET" or "HEAD" => GetAsync(request),
        "PUT" => PutAsync(request),
        "DELETE" => DeleteAsync(request),
        "MKCOL" => MkcolAsync(request),
        "COPY" => CopyOrMoveAsync(request, move: false),
        "MOVE" => CopyOrMoveAsync(request, move: true),
        "PROPFIND" => PropfindAsync(request),
        "PROPPATCH" => ProppatchAsync(request),
        "LOCK" => LockAsync(request),
        "UNLOCK" => UnlockAsync(request),
        "REPORT" => ReportAsync(request),
        _ => Status(request.Http, StatusCodes.Status405MethodNotAllowed),
    };

    private static Task Status(HttpContext http, int status)
    {
        http.Response.StatusCode = status;
        return Task.CompletedTask;
    }

    // ---- Conditions ----------------------------------------------------------------------------------------------

    private Entry? Stat(Space space, RelPath path) => space.Stat(path);
    private Node NodeOf(Space space, RelPath path) => state.Nodes.Get(space.Key, path.Key);
    private string TagOf(Space space, Entry entry) => Properties.ETag(entry, NodeOf(space, entry.Path));

    /// <summary>What an <c>If</c> header comes to: whether it holds, and the lock tokens it offers.</summary>
    private (bool Readable, bool Holds, HashSet<string> Tokens) EvaluateIf(DavRequest request)
    {
        var tokens = new HashSet<string>(StringComparer.Ordinal);
        var header = request.Http.Request.Headers["If"].ToString();
        if (header.Length == 0) return (true, true, tokens);
        var lists = IfHeader.Parse(header);
        if (lists is null) return (false, false, tokens);

        var holds = false;
        foreach (var list in lists)
        {
            var target = list.Resource is null ? (request.Space, request.Path) : Locate(request, list.Resource);
            if (target is not var (space, path)) continue;
            var entry = Stat(space, path);
            var ok = true;
            foreach (var condition in list.Conditions)
            {
                bool met;
                if (condition.Token is { } token)
                {
                    met = locks.Find(token) is { } found && string.Equals(found.Space, space.Key, PathRules.Compare)
                        && path.IsInsideOrSame(found.Path) && (found.Infinite || found.Path.Equals(path));
                }
                else
                {
                    met = entry is not null && SameTag(TagOf(space, entry), condition.ETag!);
                }
                if (met == condition.Not)
                {
                    ok = false;
                    break;
                }
            }
            if (!ok) continue;
            holds = true;
            foreach (var condition in list.Conditions)
            {
                if (!condition.Not && condition.Token is { } token) tokens.Add(token);
            }
        }
        return (true, holds, tokens);
    }

    private (Space, RelPath)? Locate(DavRequest request, string address)
    {
        var segments = AddressSegments(request, address, out _);
        if (segments is null) return null;
        var (target, _) = Router.Resolve(state, request.Account, segments);
        return target is null ? null : (target.Space, target.Path);
    }

    /// <summary>An address in a header, which may be a whole URL or just a path, with the proxy's prefix taken off.</summary>
    private static string[]? AddressSegments(DavRequest request, string address, out string host)
    {
        host = "";
        var path = address;
        if (!address.StartsWith('/'))
        {
            if (!Uri.TryCreate(address, UriKind.Absolute, out var uri)) return null;
            host = uri.Host;
            path = uri.AbsolutePath;
        }
        var segments = PathRules.DecodeTarget(path);
        if (segments is null) return null;
        var prefix = request.Client.PathBase.Split('/', StringSplitOptions.RemoveEmptyEntries);
        if (prefix.Length > 0 && segments.Length >= prefix.Length && segments.Take(prefix.Length).SequenceEqual(prefix)) segments = segments[prefix.Length..];
        return segments;
    }

    private static bool SameTag(string current, string asked)
    {
        var a = asked.StartsWith("W/", StringComparison.Ordinal) ? asked[2..] : asked;
        return current == a.Trim();
    }

    /// <summary>
    /// Checks an <c>If</c> header and the locks in the way of changing a path. Null if all is well; otherwise the request has
    /// been answered. <paramref name="below"/> is for what touches a whole folder, <paramref name="membership"/> for what adds
    /// to or takes from the folder it's in, which a lock on that folder protects.
    /// </summary>
    private async Task<bool> CheckLocksAsync(DavRequest request, params (Space Space, RelPath Path, bool Below, bool Membership)[] paths)
    {
        var (readable, holds, tokens) = EvaluateIf(request);
        if (!readable)
        {
            request.Http.Response.StatusCode = StatusCodes.Status400BadRequest;
            return false;
        }
        if (!holds)
        {
            request.Http.Response.StatusCode = StatusCodes.Status412PreconditionFailed;
            return false;
        }
        foreach (var (space, path, below, membership) in paths)
        {
            var blocking = locks.Covering(space.Key, path, below, membership);
            if (blocking.Count == 0) continue;
            // A token only counts from the one who took the lock: knowing someone's token isn't being them.
            var mine = blocking.Where(item => tokens.Contains(item.Token) && item.Account.Equals(request.Account.Name, StringComparison.OrdinalIgnoreCase)).ToList();
            var satisfied = blocking.All(item => mine.Contains(item) || (!item.Exclusive && mine.Any(other => !other.Exclusive && other.Path.Equals(item.Path))));
            if (satisfied) continue;
            await WriteErrorAsync(request.Http, StatusCodes.Status423Locked, new XElement(D + "lock-token-submitted", blocking.Select(item => new XElement(D + "href", request.Href(item.Path, false)))));
            return false;
        }
        return true;
    }

    /// <summary>The checks on writing a file that a chunked upload has to pass on its last step, as a PUT does on its first:
    /// conditions on the file as it is now, and locks. False if the request has been answered.</summary>
    public async Task<bool> CheckWriteAsync(DavRequest request)
    {
        var existing = request.Space.Stat(request.Path);
        var precondition = Preconditions(request.Http.Request, existing is null ? null : TagOf(request.Space, existing), existing?.Modified, readMethod: false);
        if (precondition != 0)
        {
            request.Http.Response.StatusCode = precondition;
            return false;
        }
        return await CheckLocksAsync(request, (request.Space, request.Path, false, existing is null));
    }

    /// <summary>The conditional headers of RFC 9110. A status to answer with, or 0 to go on.</summary>
    private static int Preconditions(HttpRequest request, string? tag, DateTimeOffset? modified, bool readMethod)
    {
        var headers = request.Headers;
        var ifMatch = headers.IfMatch.ToString();
        if (ifMatch.Length > 0 && (tag is null || !TagInList(ifMatch, tag))) return StatusCodes.Status412PreconditionFailed;
        if (ifMatch.Length == 0 && modified is { } a && TryDate(headers.IfUnmodifiedSince.ToString(), out var unmodified) && Whole(a) > Whole(unmodified)) return StatusCodes.Status412PreconditionFailed;

        var ifNone = headers.IfNoneMatch.ToString();
        if (ifNone.Length > 0)
        {
            if (tag is not null && TagInList(ifNone, tag)) return readMethod ? StatusCodes.Status304NotModified : StatusCodes.Status412PreconditionFailed;
        }
        else if (readMethod && modified is { } b && TryDate(headers.IfModifiedSince.ToString(), out var since) && Whole(b) <= Whole(since))
        {
            return StatusCodes.Status304NotModified;
        }
        return 0;
    }

    private static DateTimeOffset Whole(DateTimeOffset time) => new(time.Ticks - time.Ticks % TimeSpan.TicksPerSecond, time.Offset);

    private static bool TagInList(string list, string tag)
    {
        if (list.Trim() == "*") return true;
        return list.Split(',', StringSplitOptions.TrimEntries).Any(item => SameTag(tag, item));
    }

    private static bool TryDate(string text, out DateTimeOffset date) =>
        DateTimeOffset.TryParse(text, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out date);

    // ---- Reading -------------------------------------------------------------------------------------------------

    private async Task GetAsync(DavRequest request)
    {
        var http = request.Http;
        var response = http.Response;
        var entry = Stat(request.Space, request.Path);
        if (entry is null)
        {
            response.StatusCode = StatusCodes.Status404NotFound;
            return;
        }
        if (entry.IsDirectory)
        {
            // There's no page of files: a browser that lands here has logged in and is told what this is.
            response.ContentType = "text/plain; charset=utf-8";
            if (!HttpMethods.IsHead(http.Request.Method)) await response.WriteAsync("This is a folder on a WebDAV server. Connect to it with a WebDAV or Nextcloud client.\n", http.RequestAborted);
            return;
        }

        var node = NodeOf(request.Space, entry.Path);
        var tag = Properties.ETag(entry, node);
        response.Headers.ETag = tag;
        response.Headers["OC-ETag"] = tag;
        response.Headers["OC-FileId"] = Properties.NextcloudId(node.Id);
        response.Headers.LastModified = Properties.HttpDate(entry.Modified);
        response.Headers.AcceptRanges = "bytes";
        var precondition = Preconditions(http.Request, tag, entry.Modified, readMethod: true);
        if (precondition != 0)
        {
            response.StatusCode = precondition;
            return;
        }

        // Nothing here should ever be run or shown as a page from this address: uploaded HTML is someone's file, not this
        // server's content, and a browser that's logged in would otherwise run its scripts.
        response.ContentType = Properties.ContentType(entry.Path.Name);
        response.Headers.ContentDisposition = new Microsoft.Net.Http.Headers.ContentDispositionHeaderValue("attachment") { FileNameStar = entry.Path.Name }.ToString();

        // Files can be replaced while being read: the reader gets what it opened, whole.
        await using var file = new FileStream(entry.FullPath, new FileStreamOptions
        {
            Mode = FileMode.Open,
            Access = FileAccess.Read,
            Share = FileShare.ReadWrite | FileShare.Delete,
            Options = FileOptions.Asynchronous | FileOptions.SequentialScan,
            BufferSize = 0,
        });
        var length = file.Length;
        var (start, count) = (0L, length);
        var rangeHeader = http.Request.Headers.Range.ToString();
        if (rangeHeader.Length > 0 && RangeApplies(http.Request, tag, entry.Modified))
        {
            var range = ParseRange(rangeHeader, length);
            if (range is { Unsatisfiable: true })
            {
                response.StatusCode = StatusCodes.Status416RangeNotSatisfiable;
                response.Headers.ContentRange = $"bytes */{length}";
                response.ContentType = null;
                return;
            }
            if (range is { Start: var from, Count: var size })
            {
                (start, count) = (from, size);
                response.StatusCode = StatusCodes.Status206PartialContent;
                response.Headers.ContentRange = $"bytes {from}-{from + size - 1}/{length}";
            }
        }
        response.ContentLength = count;
        if (HttpMethods.IsHead(http.Request.Method)) return;

        file.Position = start;
        var buffer = ArrayPool<byte>.Shared.Rent(BufferBytes);
        try
        {
            var left = count;
            while (left > 0)
            {
                var read = await file.ReadAsync(buffer.AsMemory(0, (int)Math.Min(left, buffer.Length)), http.RequestAborted);
                if (read == 0) break;
                await response.Body.WriteAsync(buffer.AsMemory(0, read), http.RequestAborted);
                left -= read;
            }
            // The file got shorter under a reader that was promised more: the connection is cut rather than a short file delivered as whole.
            if (left > 0) http.Abort();
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    private static bool RangeApplies(HttpRequest request, string tag, DateTimeOffset modified)
    {
        var ifRange = request.Headers.IfRange.ToString();
        if (ifRange.Length == 0) return true;
        if (ifRange.StartsWith('"') || ifRange.StartsWith("W/", StringComparison.Ordinal)) return ifRange == tag;
        return TryDate(ifRange, out var date) && Whole(modified) <= Whole(date);
    }

    public readonly record struct ByteRange(long Start, long Count, bool Unsatisfiable);

    /// <summary>One byte range, the only kind answered; several, or nonsense, get the whole file, as RFC 9110 allows.</summary>
    public static ByteRange? ParseRange(string header, long length)
    {
        if (!header.StartsWith("bytes=", StringComparison.OrdinalIgnoreCase)) return null;
        var spec = header[6..].Trim();
        if (spec.Contains(',')) return null;
        var dash = spec.IndexOf('-');
        if (dash < 0) return null;
        var first = spec[..dash].Trim();
        var last = spec[(dash + 1)..].Trim();
        if (first.Length == 0)
        {
            if (!long.TryParse(last, NumberStyles.None, CultureInfo.InvariantCulture, out var suffix)) return null;
            if (suffix == 0 || length == 0) return new ByteRange(0, 0, true);
            var count = Math.Min(suffix, length);
            return new ByteRange(length - count, count, false);
        }
        if (!long.TryParse(first, NumberStyles.None, CultureInfo.InvariantCulture, out var start)) return null;
        if (start >= length) return new ByteRange(0, 0, true);
        var end = length - 1;
        if (last.Length > 0)
        {
            if (!long.TryParse(last, NumberStyles.None, CultureInfo.InvariantCulture, out var stated) || stated < start) return null;
            end = Math.Min(stated, end);
        }
        return new ByteRange(start, end - start + 1, false);
    }

    // ---- Writing a file ------------------------------------------------------------------------------------------

    public sealed class QuotaExceededException : Exception;
    public sealed class TooLargeException : Exception;

    /// <summary>How much more can go in a space, counting what's replaced as gone.</summary>
    private long Room(Space space, long replacing)
    {
        if (space.QuotaBytes <= 0) return long.MaxValue;
        return Math.Max(0, space.QuotaBytes - state.Usage.Get(space) + replacing);
    }

    public long FreeOnDisk(Space space)
    {
        try
        {
            return new DriveInfo(Path.GetPathRoot(space.Root)!).AvailableFreeSpace;
        }
        catch (Exception exception) when (exception is IOException or ArgumentException or UnauthorizedAccessException)
        {
            return long.MaxValue;
        }
    }

    /// <summary>Takes a request's body into a file, stopping as soon as it's over the limits. The disk's copy is flushed
    /// before the file is put in place, so a crash can't leave a file that says it's whole and isn't.</summary>
    public async Task<long> ReceiveAsync(HttpContext http, string temp, long room, IncrementalHash? checksum)
    {
        var limit = state.Policy.Settings.MaxUploadBytes;
        var buffer = ArrayPool<byte>.Shared.Rent(BufferBytes);
        long total = 0;
        try
        {
            await using var file = new FileStream(temp, new FileStreamOptions
            {
                Mode = FileMode.CreateNew,
                Access = FileAccess.Write,
                Share = FileShare.None,
                Options = FileOptions.Asynchronous | FileOptions.SequentialScan,
                BufferSize = 0,
            });
            int read;
            while ((read = await http.Request.Body.ReadAsync(buffer, http.RequestAborted)) > 0)
            {
                total += read;
                if (total > room) throw new QuotaExceededException();
                if (limit > 0 && total > limit) throw new TooLargeException();
                checksum?.AppendData(buffer, 0, read);
                await file.WriteAsync(buffer.AsMemory(0, read), http.RequestAborted);
            }
            await file.FlushAsync(http.RequestAborted);
            file.Flush(flushToDisk: true);
        }
        catch
        {
            TryDelete(temp);
            throw;
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
        return total;
    }

    public static void TryDelete(string path)
    {
        try
        {
            File.Delete(path);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            // It's in the server's own folder, and goes in the next sweep.
        }
    }

    /// <summary>Puts a finished upload in place in one step. Someone reading the old file carries on reading it, and nobody
    /// ever sees half of the new one.</summary>
    public (Entry Entry, Node Node, bool Created) Commit(Space space, RelPath path, string full, string temp, long size, long oldSize, bool existed, DateTimeOffset? modified)
    {
        if (modified is { } time) File.SetLastWriteTimeUtc(temp, time.UtcDateTime);
        AtomicFile.Replace(temp, full);
        state.Usage.Add(space, size - oldSize);
        state.Nodes.Changed(space.Key, path.Key);
        var entry = space.Stat(path) ?? throw new FileNotFoundException();
        return (entry, NodeOf(space, path), !existed);
    }

    /// <summary>The time a client wants on a file: Nextcloud's headers, in seconds since 1970.</summary>
    public static DateTimeOffset? RequestedTime(HttpRequest request)
    {
        var text = request.Headers["X-OC-MTime"].ToString();
        if (text.Length == 0) text = request.Headers["OC-Mtime"].ToString();
        if (text.Length == 0 || !double.TryParse(text, NumberStyles.Float, CultureInfo.InvariantCulture, out var seconds)) return null;
        if (seconds < 0 || seconds > 32503680000) return null;
        return DateTimeOffset.FromUnixTimeSeconds((long)seconds);
    }

    public static void AnswerStored(HttpResponse response, Entry entry, Node node, bool timeSet)
    {
        var tag = Properties.ETag(entry, node);
        response.Headers.ETag = tag;
        response.Headers["OC-ETag"] = tag;
        response.Headers["OC-FileId"] = Properties.NextcloudId(node.Id);
        response.Headers.LastModified = Properties.HttpDate(entry.Modified);
        if (timeSet) response.Headers["X-OC-MTime"] = "accepted";
    }

    private async Task PutAsync(DavRequest request)
    {
        var http = request.Http;
        var response = http.Response;
        if (request.ReadOnly || request.Path.IsRoot)
        {
            response.StatusCode = request.Path.IsRoot ? StatusCodes.Status405MethodNotAllowed : StatusCodes.Status403Forbidden;
            return;
        }
        // A range on PUT asks for something else than what's being done: RFC 9110 says to refuse it, not to write a whole file.
        if (http.Request.Headers.ContentRange.Count > 0 || http.Request.Headers.ContentEncoding.Any(value => value is not null && !value.Equals("identity", StringComparison.OrdinalIgnoreCase)))
        {
            response.StatusCode = StatusCodes.Status400BadRequest;
            return;
        }

        var space = request.Space;
        var full = space.FullPath(request.Path);
        if (full is null)
        {
            response.StatusCode = StatusCodes.Status403Forbidden;
            return;
        }
        var existing = space.Stat(request.Path);
        if (existing is { IsDirectory: true })
        {
            response.StatusCode = StatusCodes.Status405MethodNotAllowed;
            return;
        }
        if (space.Stat(request.Path.Parent) is not { IsDirectory: true })
        {
            response.StatusCode = StatusCodes.Status409Conflict;
            return;
        }
        var precondition = Preconditions(http.Request, existing is null ? null : TagOf(space, existing), existing?.Modified, readMethod: false);
        if (precondition != 0)
        {
            response.StatusCode = precondition;
            return;
        }
        if (!await CheckLocksAsync(request, (space, request.Path, false, existing is null))) return;

        var oldSize = existing?.Size ?? 0;
        var room = Room(space, oldSize);
        var maxUpload = state.Policy.Settings.MaxUploadBytes;
        var declared = http.Request.ContentLength;
        if (declared is { } length)
        {
            if (maxUpload > 0 && length > maxUpload)
            {
                response.StatusCode = StatusCodes.Status413PayloadTooLarge;
                return;
            }
            if (length > room || length > FreeOnDisk(space))
            {
                await WriteErrorAsync(http, StatusCodes.Status507InsufficientStorage, new XElement(D + "quota-not-exceeded"));
                return;
            }
        }
        AllowBody(http, null);

        var checksum = ParseChecksum(http.Request, out var expected);
        var temp = space.NewTempFile();
        long received;
        try
        {
            using (checksum)
            {
                received = await ReceiveAsync(http, temp, room, checksum);
                if (checksum is not null && !Convert.ToHexString(checksum.GetHashAndReset()).Equals(expected, StringComparison.OrdinalIgnoreCase))
                {
                    TryDelete(temp);
                    response.StatusCode = StatusCodes.Status400BadRequest;
                    return;
                }
            }
        }
        catch (QuotaExceededException)
        {
            await WriteErrorAsync(http, StatusCodes.Status507InsufficientStorage, new XElement(D + "quota-not-exceeded"));
            return;
        }
        catch (TooLargeException)
        {
            response.StatusCode = StatusCodes.Status413PayloadTooLarge;
            return;
        }

        // The upload may have taken hours, so the checks that matter are made again now, right before it counts.
        if (Recheck(request) is { } changedStatus)
        {
            TryDelete(temp);
            response.StatusCode = changedStatus;
            return;
        }

        var time = RequestedTime(http.Request);
        var (entry, node, created) = Commit(space, request.Path, full, temp, received, oldSize, existing is not null, time);
        AnswerStored(response, entry, node, time is not null);
        response.StatusCode = created ? StatusCodes.Status201Created : StatusCodes.Status204NoContent;
    }

    /// <summary>The parent folder must still be there, and any condition on the file must still hold.</summary>
    private int? Recheck(DavRequest request)
    {
        if (request.Space.Stat(request.Path.Parent) is not { IsDirectory: true }) return StatusCodes.Status409Conflict;
        var now = request.Space.Stat(request.Path);
        if (now is { IsDirectory: true }) return StatusCodes.Status405MethodNotAllowed;
        var conditional = request.Http.Request.Headers.IfMatch.Count > 0 || request.Http.Request.Headers.IfNoneMatch.Count > 0;
        if (conditional)
        {
            var precondition = Preconditions(request.Http.Request, now is null ? null : TagOf(request.Space, now), now?.Modified, readMethod: false);
            if (precondition != 0) return precondition;
        }
        return null;
    }

    /// <summary>The checksum a Nextcloud client sends with a file (<c>OC-Checksum: SHA1:…</c>), which is held to on arrival.</summary>
    private static IncrementalHash? ParseChecksum(HttpRequest request, out string expected)
    {
        expected = "";
        var header = request.Headers["OC-Checksum"].ToString();
        var colon = header.IndexOf(':');
        if (colon <= 0) return null;
        HashAlgorithmName? algorithm = header[..colon].ToUpperInvariant() switch
        {
#pragma warning disable CA5350, CA5351 // Clients choose these to check for damage in transit, not for security.
            "SHA1" => HashAlgorithmName.SHA1,
            "MD5" => HashAlgorithmName.MD5,
#pragma warning restore CA5350, CA5351
            "SHA256" => HashAlgorithmName.SHA256,
            _ => null,
        };
        if (algorithm is null) return null;
        expected = header[(colon + 1)..].Trim();
        return IncrementalHash.CreateHash(algorithm.Value);
    }

    // ---- Deleting and making folders ----------------------------------------------------------------------------

    private async Task DeleteAsync(DavRequest request)
    {
        var http = request.Http;
        if (request.ReadOnly || request.Path.IsRoot)
        {
            http.Response.StatusCode = StatusCodes.Status403Forbidden;
            return;
        }
        var entry = Stat(request.Space, request.Path);
        if (entry is null)
        {
            http.Response.StatusCode = StatusCodes.Status404NotFound;
            return;
        }
        var depth = http.Request.Headers["Depth"].ToString();
        if (entry.IsDirectory && depth.Length > 0 && !depth.Equals("infinity", StringComparison.OrdinalIgnoreCase))
        {
            http.Response.StatusCode = StatusCodes.Status400BadRequest;
            return;
        }
        var precondition = Preconditions(http.Request, TagOf(request.Space, entry), entry.Modified, readMethod: false);
        if (precondition != 0)
        {
            http.Response.StatusCode = precondition;
            return;
        }
        if (!await CheckLocksAsync(request, (request.Space, request.Path, entry.IsDirectory, true))) return;
        Remove(request.Space, entry);
        http.Response.StatusCode = StatusCodes.Status204NoContent;
    }

    private void Remove(Space space, Entry entry)
    {
        var size = entry.IsDirectory ? UsageTracker.Count(entry.FullPath) : entry.Size;
        if (entry.IsDirectory) Directory.Delete(entry.FullPath, recursive: true);
        else File.Delete(entry.FullPath);
        state.Usage.Add(space, -size);
        state.Nodes.Deleted(space.Key, entry.Path.Key);
        locks.RemoveTree(space.Key, entry.Path);
    }

    private async Task MkcolAsync(DavRequest request)
    {
        var http = request.Http;
        var response = http.Response;
        if (http.Request.ContentLength > 0 || http.Request.Headers.TransferEncoding.Count > 0)
        {
            response.StatusCode = StatusCodes.Status415UnsupportedMediaType;
            return;
        }
        if (request.ReadOnly)
        {
            response.StatusCode = StatusCodes.Status403Forbidden;
            return;
        }
        if (Stat(request.Space, request.Path) is not null)
        {
            response.StatusCode = StatusCodes.Status405MethodNotAllowed;
            response.Headers.Allow = AllowedMethods;
            return;
        }
        if (Stat(request.Space, request.Path.Parent) is not { IsDirectory: true } || request.Space.FullPath(request.Path) is not { } full)
        {
            response.StatusCode = StatusCodes.Status409Conflict;
            return;
        }
        if (!await CheckLocksAsync(request, (request.Space, request.Path, false, true))) return;
        Directory.CreateDirectory(full);
        state.Nodes.Changed(request.Space.Key, request.Path.Key);
        var entry = Stat(request.Space, request.Path)!;
        AnswerStored(response, entry, NodeOf(request.Space, request.Path), timeSet: false);
        response.StatusCode = StatusCodes.Status201Created;
    }

    // ---- Copying and moving -------------------------------------------------------------------------------------

    private async Task CopyOrMoveAsync(DavRequest request, bool move)
    {
        var http = request.Http;
        var response = http.Response;
        var source = Stat(request.Space, request.Path);
        if (source is null)
        {
            response.StatusCode = StatusCodes.Status404NotFound;
            return;
        }
        if (move && (request.ReadOnly || request.Path.IsRoot))
        {
            response.StatusCode = StatusCodes.Status403Forbidden;
            return;
        }

        var depth = http.Request.Headers["Depth"].ToString();
        if (depth.Length > 0 && !depth.Equals("infinity", StringComparison.OrdinalIgnoreCase) && (move || depth != "0"))
        {
            response.StatusCode = StatusCodes.Status400BadRequest;
            return;
        }
        var recursive = !depth.Equals("0", StringComparison.Ordinal);

        var destinationHeader = http.Request.Headers["Destination"].ToString();
        if (destinationHeader.Length == 0)
        {
            response.StatusCode = StatusCodes.Status400BadRequest;
            return;
        }
        var segments = AddressSegments(request, destinationHeader, out var destinationHost);
        if (segments is null)
        {
            response.StatusCode = StatusCodes.Status400BadRequest;
            return;
        }
        // A proxy may well pass on another Host than the client used, so this can only be told on a direct connection.
        if (!request.Client.ViaProxy && destinationHost.Length > 0 && !destinationHost.Equals(HostName(request.Client.Host), StringComparison.OrdinalIgnoreCase))
        {
            response.StatusCode = StatusCodes.Status502BadGateway;
            return;
        }
        var (target, status) = Router.Resolve(state, request.Account, segments);
        if (target is null)
        {
            response.StatusCode = status == StatusCodes.Status400BadRequest ? StatusCodes.Status403Forbidden : status;
            return;
        }
        if (target.ReadOnly || target.Path.IsRoot || guard.IsBanned(request.Client.Address, target.Mount.Path))
        {
            response.StatusCode = StatusCodes.Status403Forbidden;
            return;
        }

        var sameSpace = string.Equals(request.Space.Key, target.Space.Key, PathRules.Compare);
        var sameExactly = sameSpace && request.Path.Key == target.Path.Key;
        var caseOnly = sameSpace && !sameExactly && request.Path.Equals(target.Path);
        // Into itself never ends, and over a folder it's inside would delete what's being moved before moving it.
        if (sameExactly || (sameSpace && !caseOnly && (target.Path.IsInsideOrSame(request.Path) || request.Path.IsInsideOrSame(target.Path))))
        {
            response.StatusCode = StatusCodes.Status403Forbidden;
            return;
        }

        var destinationFull = target.Space.FullPath(target.Path);
        if (destinationFull is null || target.Space.Stat(target.Path.Parent) is not { IsDirectory: true })
        {
            response.StatusCode = StatusCodes.Status409Conflict;
            return;
        }
        var existing = caseOnly ? null : target.Space.Stat(target.Path);
        var overwrite = !http.Request.Headers["Overwrite"].ToString().Equals("F", StringComparison.OrdinalIgnoreCase);
        if (existing is not null && !overwrite)
        {
            response.StatusCode = StatusCodes.Status412PreconditionFailed;
            return;
        }

        var paths = new List<(Space, RelPath, bool, bool)> { (target.Space, target.Path, true, existing is null) };
        if (move) paths.Add((request.Space, request.Path, true, true));
        if (!await CheckLocksAsync(request, [.. paths])) return;

        // Room for it, when it will take any: moving within a space takes none, and what's overwritten is counted as gone.
        var incoming = source.IsDirectory ? (recursive ? UsageTracker.Count(source.FullPath) : 0) : source.Size;
        if (!(move && sameSpace))
        {
            var replacing = existing is null ? 0 : existing.IsDirectory ? UsageTracker.Count(existing.FullPath) : existing.Size;
            if (incoming > Room(target.Space, replacing) || incoming > FreeOnDisk(target.Space))
            {
                await WriteErrorAsync(http, StatusCodes.Status507InsufficientStorage, new XElement(D + "quota-not-exceeded"));
                return;
            }
        }

        if (existing is not null) Remove(target.Space, existing);

        if (move)
        {
            MoveOnDisk(source, destinationFull);
            locks.RemoveTree(request.Space.Key, request.Path);
            if (!sameSpace)
            {
                state.Usage.Add(request.Space, -incoming);
                state.Usage.Add(target.Space, incoming);
            }
            if (caseOnly) state.Nodes.Changed(request.Space.Key, request.Path.Key);
            else state.Nodes.Moved(request.Space.Key, request.Path.Key, target.Space.Key, target.Path.Key);
        }
        else
        {
            CopyOnDisk(request.Space, source, destinationFull, recursive);
            state.Usage.Add(target.Space, incoming);
            state.Nodes.Copied(request.Space.Key, request.Path.Key, target.Space.Key, target.Path.Key);
        }

        var entry = target.Space.Stat(target.Path);
        if (entry is not null) AnswerStored(response, entry, NodeOf(target.Space, target.Path), timeSet: false);
        response.StatusCode = existing is null ? StatusCodes.Status201Created : StatusCodes.Status204NoContent;
    }

    private static string HostName(string hostHeader)
    {
        if (hostHeader.StartsWith('['))
        {
            var close = hostHeader.IndexOf(']');
            return close > 0 ? hostHeader[1..close] : hostHeader;
        }
        var colon = hostHeader.IndexOf(':');
        return colon > 0 ? hostHeader[..colon] : hostHeader;
    }

    private static void MoveOnDisk(Entry source, string destination)
    {
        if (!source.IsDirectory)
        {
            File.Move(source.FullPath, destination, overwrite: false);
            return;
        }
        try
        {
            Directory.Move(source.FullPath, destination);
        }
        catch (IOException) when (!string.Equals(Path.GetPathRoot(source.FullPath), Path.GetPathRoot(destination), PathRules.Compare) || !OperatingSystem.IsWindows())
        {
            // On another volume, a folder can't be renamed into place. Links aren't taken along, and aren't left behind on purpose.
            CopyFolder(source.FullPath, destination);
            Directory.Delete(source.FullPath, recursive: true);
        }
    }

    private static void CopyOnDisk(Space space, Entry source, string destination, bool recursive)
    {
        if (!source.IsDirectory)
        {
            File.Copy(source.FullPath, destination, overwrite: false);
            return;
        }
        Directory.CreateDirectory(destination);
        if (!recursive) return;
        foreach (var child in space.List(source)) CopyOnDisk(space, child, Path.Combine(destination, child.Path.Name), recursive: true);
    }

    private static void CopyFolder(string source, string destination)
    {
        Directory.CreateDirectory(destination);
        foreach (var info in new DirectoryInfo(source).EnumerateFileSystemInfos())
        {
            if (info.LinkTarget is not null) continue;
            var target = Path.Combine(destination, info.Name);
            if (info is FileInfo file) file.CopyTo(target);
            else CopyFolder(info.FullName, target);
        }
    }

    // ---- Properties ----------------------------------------------------------------------------------------------

    private enum PropMode
    {
        All,
        Names,
        Listed,
    }

    private async Task PropfindAsync(DavRequest request)
    {
        var http = request.Http;
        var depthHeader = http.Request.Headers["Depth"].ToString();
        // A listing of everything under a folder is a request a client can make cheaply and the server pays for: RFC 4918
        // lets a server refuse it, and clients walk down a level at a time anyway.
        if (depthHeader.Equals("infinity", StringComparison.OrdinalIgnoreCase))
        {
            await WriteErrorAsync(http, StatusCodes.Status403Forbidden, new XElement(D + "propfind-finite-depth"));
            return;
        }
        if (depthHeader.Length > 0 && depthHeader is not ("0" or "1"))
        {
            http.Response.StatusCode = StatusCodes.Status400BadRequest;
            return;
        }
        var depth = depthHeader == "0" ? 0 : 1;

        var document = await ReadAsync(http);
        var mode = PropMode.All;
        var asked = new List<XName>();
        if (document?.Root is { } root)
        {
            if (root.Name != D + "propfind")
            {
                http.Response.StatusCode = StatusCodes.Status400BadRequest;
                return;
            }
            if (root.Element(D + "propname") is not null) mode = PropMode.Names;
            else if (root.Element(D + "prop") is { } prop)
            {
                mode = PropMode.Listed;
                asked.AddRange(prop.Elements().Select(element => element.Name));
                // The answer is built in memory, so a small request mustn't be able to ask for a huge one.
                if (asked.Count > MaxPropertiesAsked)
                {
                    http.Response.StatusCode = StatusCodes.Status400BadRequest;
                    return;
                }
            }
            else if (root.Element(D + "allprop") is null)
            {
                http.Response.StatusCode = StatusCodes.Status400BadRequest;
                return;
            }
            else asked.AddRange(root.Element(D + "include")?.Elements().Select(element => element.Name) ?? []);
        }

        var entry = Stat(request.Space, request.Path);
        if (entry is null)
        {
            http.Response.StatusCode = StatusCodes.Status404NotFound;
            return;
        }
        var entries = new List<Entry> { entry };
        if (depth == 1 && entry.IsDirectory) entries.AddRange(request.Space.List(entry));

        var nodes = state.Nodes.GetMany(request.Space.Key, [.. entries.Select(item => item.Path.Key)]);
        var withProps = state.Nodes.WithProperties(nodes.Select(node => node.Id));
        var used = new Lazy<long>(() => state.Usage.Get(request.Space));
        var free = new Lazy<long>(() => request.Space.QuotaBytes > 0 ? Math.Max(0, request.Space.QuotaBytes - used.Value) : FreeOnDisk(request.Space));

        var responses = new List<XElement>(entries.Count);
        for (var i = 0; i < entries.Count; i++)
        {
            var dead = withProps.Contains(nodes[i].Id) ? state.Nodes.Properties(nodes[i].Id) : [];
            var context = new Properties.Context(request, entries[i], nodes[i], locks.Covering(request.Space.Key, entries[i].Path), () => used.Value, () => free.Value);
            responses.Add(Response(request, context, mode, asked, dead));
        }
        await WriteAsync(http, StatusCodes.Status207MultiStatus, Multistatus(responses));
    }

    private static XElement Response(DavRequest request, Properties.Context context, PropMode mode, List<XName> asked, List<(string Ns, string Name, string Xml)> dead)
    {
        var entry = context.Entry;
        var found = new List<XElement>();
        var missing = new List<XElement>();

        XElement? Dead(XName name)
        {
            foreach (var property in dead)
            {
                if (property.Ns == name.NamespaceName && property.Name == name.LocalName) return XElement.Parse(property.Xml);
            }
            return null;
        }

        if (mode == PropMode.Names)
        {
            foreach (var name in Properties.Standard(entry)) found.Add(new XElement(name));
            foreach (var property in dead) found.Add(new XElement(XNamespace.Get(property.Ns) + property.Name));
        }
        else
        {
            if (mode == PropMode.All)
            {
                foreach (var name in Properties.Standard(entry))
                {
                    if (Properties.Live(name, context) is { } element) found.Add(element);
                }
                foreach (var property in dead) found.Add(XElement.Parse(property.Xml));
            }
            foreach (var name in asked)
            {
                if (found.Any(element => element.Name == name)) continue;
                var element = Properties.Live(name, context) ?? Dead(name);
                if (element is not null) found.Add(element);
                else missing.Add(new XElement(name));
            }
        }

        var response = new XElement(D + "response", new XElement(D + "href", request.Href(entry.Path, entry.IsDirectory)));
        if (found.Count > 0) response.Add(new XElement(D + "propstat", new XElement(D + "prop", found), DavXml.Status(200)));
        if (missing.Count > 0) response.Add(new XElement(D + "propstat", new XElement(D + "prop", missing), DavXml.Status(404)));
        if (found.Count == 0 && missing.Count == 0) response.Add(new XElement(D + "propstat", new XElement(D + "prop"), DavXml.Status(200)));
        return response;
    }

    private async Task ProppatchAsync(DavRequest request)
    {
        var http = request.Http;
        var document = await ReadAsync(http);
        if (document?.Root is not { } root || root.Name != D + "propertyupdate")
        {
            http.Response.StatusCode = StatusCodes.Status400BadRequest;
            return;
        }
        if (request.ReadOnly)
        {
            http.Response.StatusCode = StatusCodes.Status403Forbidden;
            return;
        }
        var entry = Stat(request.Space, request.Path);
        if (entry is null)
        {
            http.Response.StatusCode = StatusCodes.Status404NotFound;
            return;
        }
        if (!await CheckLocksAsync(request, (request.Space, request.Path, false, false))) return;

        var results = new List<(XName Name, int Status)>();
        var changes = new List<(string, string, string?)>();
        DateTimeOffset? newTime = null;
        var failed = false;
        foreach (var operation in root.Elements())
        {
            var setting = operation.Name == D + "set";
            if (!setting && operation.Name != D + "remove") continue;
            foreach (var property in operation.Elements(D + "prop").Elements())
            {
                var name = property.Name;
                // The times clients are allowed to set: Windows' own, and the one Nextcloud clients send. The rest of what the
                // server works out is the server's to say.
                if (setting && IsTimeProperty(name) && TryPropertyTime(name, property.Value, out var time))
                {
                    newTime = time;
                    results.Add((name, 200));
                    if (name.Namespace == MS) changes.Add((name.NamespaceName, name.LocalName, property.ToString(SaveOptions.DisableFormatting)));
                    continue;
                }
                if (Properties.IsLive(name))
                {
                    results.Add((name, 403));
                    failed = true;
                    continue;
                }
                var xml = setting ? property.ToString(SaveOptions.DisableFormatting) : null;
                if (xml is not null && xml.Length > NodeStore.MaxPropertyBytes)
                {
                    results.Add((name, 507));
                    failed = true;
                    continue;
                }
                changes.Add((name.NamespaceName, name.LocalName, xml));
                results.Add((name, 200));
            }
        }

        var node = NodeOf(request.Space, request.Path);
        if (!failed && !state.Nodes.ChangeProperties(node.Id, changes))
        {
            failed = true;
            results = [.. results.Select(result => (result.Name, 507))];
        }
        if (failed)
        {
            // It's all or none, so what would have worked is reported as not done because of what didn't.
            results = [.. results.Select(result => (result.Name, result.Status == 200 ? 424 : result.Status))];
        }
        else
        {
            if (newTime is { } time)
            {
                if (entry.IsDirectory) Directory.SetLastWriteTimeUtc(entry.FullPath, time.UtcDateTime);
                else File.SetLastWriteTimeUtc(entry.FullPath, time.UtcDateTime);
            }
            if (newTime is not null || changes.Count > 0) state.Nodes.Changed(request.Space.Key, request.Path.Key);
        }

        var response = new XElement(D + "response", new XElement(D + "href", request.Href(request.Path, entry.IsDirectory)));
        foreach (var group in results.GroupBy(result => result.Status))
            response.Add(new XElement(D + "propstat", new XElement(D + "prop", group.Select(result => new XElement(result.Name))), DavXml.Status(group.Key)));
        await WriteAsync(http, StatusCodes.Status207MultiStatus, Multistatus([response]));
    }

    private static bool IsTimeProperty(XName name) => name == D + "lastmodified" || name == MS + "Win32LastModifiedTime";

    private static bool TryPropertyTime(XName name, string value, out DateTimeOffset time)
    {
        // Nextcloud's is seconds since 1970; Windows' is a date.
        if (name == D + "lastmodified" && long.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out var seconds) && seconds <= 32503680000)
        {
            time = DateTimeOffset.FromUnixTimeSeconds(seconds);
            return true;
        }
        return TryDate(value, out time);
    }

    private async Task ReportAsync(DavRequest request)
    {
        var document = await ReadAsync(request.Http);
        // Nextcloud clients ask for their favourites this way. There are none: asking for them isn't an error.
        if (document?.Root?.Name == OC + "filter-files")
        {
            await WriteAsync(request.Http, StatusCodes.Status207MultiStatus, Multistatus([]));
            return;
        }
        await WriteErrorAsync(request.Http, StatusCodes.Status403Forbidden, new XElement(D + "supported-report"));
    }

    // ---- Locks ---------------------------------------------------------------------------------------------------

    private static int TimeoutSeconds(HttpRequest request)
    {
        foreach (var part in request.Headers["Timeout"].ToString().Split(',', StringSplitOptions.TrimEntries))
        {
            if (part.Equals("Infinite", StringComparison.OrdinalIgnoreCase)) return LockManager.MaxTimeoutSeconds;
            if (part.StartsWith("Second-", StringComparison.OrdinalIgnoreCase) && int.TryParse(part.AsSpan(7), NumberStyles.None, CultureInfo.InvariantCulture, out var seconds) && seconds > 0)
                return Math.Min(seconds, LockManager.MaxTimeoutSeconds);
        }
        return LockManager.DefaultTimeoutSeconds;
    }

    private async Task LockAsync(DavRequest request)
    {
        var http = request.Http;
        var response = http.Response;
        if (request.ReadOnly || request.Path.IsRoot)
        {
            response.StatusCode = StatusCodes.Status403Forbidden;
            return;
        }
        var document = await ReadAsync(http);
        if (document?.Root is not { } root)
        {
            await RefreshLockAsync(request);
            return;
        }
        if (root.Name != D + "lockinfo")
        {
            response.StatusCode = StatusCodes.Status400BadRequest;
            return;
        }
        var exclusive = root.Element(D + "lockscope")?.Element(D + "exclusive") is not null;
        var shared = root.Element(D + "lockscope")?.Element(D + "shared") is not null;
        if (exclusive == shared || root.Element(D + "locktype")?.Element(D + "write") is null)
        {
            response.StatusCode = StatusCodes.Status400BadRequest;
            return;
        }
        var depth = http.Request.Headers["Depth"].ToString();
        if (depth.Length > 0 && depth != "0" && !depth.Equals("infinity", StringComparison.OrdinalIgnoreCase))
        {
            response.StatusCode = StatusCodes.Status400BadRequest;
            return;
        }
        var owner = root.Element(D + "owner")?.ToString(SaveOptions.DisableFormatting);
        if (owner is { Length: > 4096 })
        {
            response.StatusCode = StatusCodes.Status400BadRequest;
            return;
        }

        var (readable, holds, _) = EvaluateIf(request);
        if (!readable || !holds)
        {
            response.StatusCode = readable ? StatusCodes.Status412PreconditionFailed : StatusCodes.Status400BadRequest;
            return;
        }

        var entry = Stat(request.Space, request.Path);
        if (entry is null && (Stat(request.Space, request.Path.Parent) is not { IsDirectory: true } || request.Space.FullPath(request.Path) is null))
        {
            response.StatusCode = StatusCodes.Status409Conflict;
            return;
        }
        var (taken, conflicts) = locks.Take(request.Space.Key, request.Path, !depth.Equals("0", StringComparison.Ordinal), exclusive, request.Account.Name, owner, TimeoutSeconds(http.Request));
        if (taken is null)
        {
            await WriteErrorAsync(http, StatusCodes.Status423Locked, new XElement(D + "no-conflicting-lock", conflicts.Select(item => new XElement(D + "href", request.Href(item.Path, false)))));
            return;
        }

        // Locking a name that isn't there makes an empty file, as RFC 4918 has it: Windows and Office count on it.
        var created = false;
        if (entry is null)
        {
            await using (File.Create(request.Space.FullPath(request.Path)!)) { }
            state.Nodes.Changed(request.Space.Key, request.Path.Key);
            created = true;
        }
        response.Headers["Lock-Token"] = $"<{taken.Token}>";
        await AnswerLockAsync(request, created ? StatusCodes.Status201Created : StatusCodes.Status200OK, [taken]);
    }

    private async Task RefreshLockAsync(DavRequest request)
    {
        var (readable, holds, tokens) = EvaluateIf(request);
        if (!readable || request.Http.Request.Headers["If"].Count == 0)
        {
            request.Http.Response.StatusCode = StatusCodes.Status400BadRequest;
            return;
        }
        if (!holds)
        {
            request.Http.Response.StatusCode = StatusCodes.Status412PreconditionFailed;
            return;
        }
        var refreshed = tokens.Select(locks.Find).OfType<DavLock>().Where(item => item.Account.Equals(request.Account.Name, StringComparison.OrdinalIgnoreCase)).ToList();
        if (refreshed.Count == 0)
        {
            request.Http.Response.StatusCode = StatusCodes.Status412PreconditionFailed;
            return;
        }
        var timeout = TimeoutSeconds(request.Http.Request);
        foreach (var item in refreshed) locks.Refresh(item, timeout);
        await AnswerLockAsync(request, StatusCodes.Status200OK, refreshed);
    }

    private static Task AnswerLockAsync(DavRequest request, int status, IEnumerable<DavLock> shown) =>
        WriteAsync(request.Http, status, new XElement(D + "prop", new XAttribute(XNamespace.Xmlns + "d", D.NamespaceName), Properties.LockDiscovery(shown, request)));

    private Task UnlockAsync(DavRequest request)
    {
        var response = request.Http.Response;
        var header = request.Http.Request.Headers["Lock-Token"].ToString().Trim();
        if (header.Length < 2 || header[0] != '<' || header[^1] != '>')
        {
            response.StatusCode = StatusCodes.Status400BadRequest;
            return Task.CompletedTask;
        }
        var item = locks.Find(header[1..^1]);
        if (item is null || !string.Equals(item.Space, request.Space.Key, PathRules.Compare) || !request.Path.IsInsideOrSame(item.Path))
        {
            response.StatusCode = StatusCodes.Status409Conflict;
            return Task.CompletedTask;
        }
        if (!item.Account.Equals(request.Account.Name, StringComparison.OrdinalIgnoreCase))
        {
            response.StatusCode = StatusCodes.Status403Forbidden;
            return Task.CompletedTask;
        }
        locks.Release(item.Token);
        response.StatusCode = StatusCodes.Status204NoContent;
        return Task.CompletedTask;
    }
}
