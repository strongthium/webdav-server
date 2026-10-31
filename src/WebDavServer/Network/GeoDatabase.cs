using System.Buffers.Binary;
using System.Globalization;
using System.IO.Compression;
using System.Net;
using System.Net.Sockets;

namespace Strongthium.WebDavServer.Network;

/// <summary>
/// DB-IP's free databases, read into memory: <c>dbip-country-lite</c> and <c>dbip-asn-lite</c>, published monthly under CC BY
/// 4.0 as gzipped CSV of ranges. Nothing is looked up online: every lookup is a binary search here, and the only thing ever
/// asked of DB-IP is the files themselves, when a whitelist has come to need them or the admin asks.
/// </summary>
public sealed class GeoDatabase(string folder) : IPlaces
{
    private const string BaseUrl = "https://download.db-ip.com/free/";

    private volatile Tables? tables;

    public bool Loaded => tables is not null;
    public string Month => tables?.Month ?? "";

    public (string Country, int Asn) Lookup(IPAddress address)
    {
        var current = tables;
        if (current is null) return ("", 0);
        address = Networks.Normal(address);
        var key = ToNumber(address);
        var country = current.Countries.Find(key) is var c and >= 0 ? current.Codes[c] : "";
        var asn = current.Networks.Find(key) is var n and >= 0 ? n : 0;
        return (country == "ZZ" ? "" : country, asn);
    }

    /// <summary>Reads the latest files in the folder, if there are any.</summary>
    public void Load()
    {
        var month = LatestMonth(folder);
        if (month is null) return;
        using var country = OpenGzip(Path.Combine(folder, CountryFile(month)));
        using var asn = OpenGzip(Path.Combine(folder, AsnFile(month)));
        tables = Read(country, asn, month);
    }

    /// <summary>Loads databases from readers, for tests and for <see cref="Load"/>.</summary>
    public void Use(TextReader country, TextReader asn, string month) => tables = Read(country, asn, month);

    private sealed record Tables(RangeTable Countries, RangeTable Networks, List<string> Codes, string Month);

    private static Tables Read(TextReader country, TextReader asn, string month)
    {
        var countries = new RangeTable();
        var networks = new RangeTable();
        var codes = new List<string>();
        var codeIndex = new Dictionary<string, int>(StringComparer.Ordinal);
        string? line;
        while ((line = country.ReadLine()) is not null)
        {
            if (!TryRange(line, out var first, out var last, out var rest)) continue;
            var code = rest.Trim().ToString().ToUpperInvariant();
            if (!codeIndex.TryGetValue(code, out var index))
            {
                codeIndex[code] = index = codes.Count;
                codes.Add(code);
            }
            countries.Add(first, last, index);
        }
        while ((line = asn.ReadLine()) is not null)
        {
            if (!TryRange(line, out var first, out var last, out var rest)) continue;
            var comma = rest.IndexOf(',');
            if (int.TryParse(comma < 0 ? rest : rest[..comma], NumberStyles.None, CultureInfo.InvariantCulture, out var number)) networks.Add(first, last, number);
        }
        countries.Seal();
        networks.Seal();
        return new Tables(countries, networks, codes, month);
    }

    private static string? LatestMonth(string directory)
    {
        if (!Directory.Exists(directory)) return null;
        return Directory.EnumerateFiles(directory, "dbip-country-lite-*.csv.gz")
            .Select(file => Path.GetFileName(file)["dbip-country-lite-".Length..^".csv.gz".Length])
            .Where(month => File.Exists(Path.Combine(directory, AsnFile(month))))
            .OrderDescending(StringComparer.Ordinal)
            .FirstOrDefault();
    }

    private static string CountryFile(string month) => $"dbip-country-lite-{month}.csv.gz";
    private static string AsnFile(string month) => $"dbip-asn-lite-{month}.csv.gz";

    private static StreamReader OpenGzip(string file) =>
        new(new GZipStream(new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.Read, 1 << 16), CompressionMode.Decompress));

    private static bool TryRange(string line, out UInt128 first, out UInt128 last, out ReadOnlySpan<char> rest)
    {
        first = last = default;
        rest = default;
        var span = line.AsSpan();
        var a = span.IndexOf(',');
        if (a < 0) return false;
        var b = span[(a + 1)..].IndexOf(',');
        if (b < 0) return false;
        b += a + 1;
        if (!IPAddress.TryParse(span[..a], out var from) || !IPAddress.TryParse(span[(a + 1)..b], out var to)) return false;
        first = ToNumber(from);
        last = ToNumber(to);
        rest = span[(b + 1)..];
        return first <= last;
    }

    /// <summary>An address as a number, IPv4 ones mapped into IPv6, so that one table holds both.</summary>
    private static UInt128 ToNumber(IPAddress address)
    {
        Span<byte> bytes = stackalloc byte[16];
        (address.AddressFamily == AddressFamily.InterNetwork ? address.MapToIPv6() : address).TryWriteBytes(bytes, out _);
        return BinaryPrimitives.ReadUInt128BigEndian(bytes);
    }

    /// <summary>Downloads this month's two files (last month's, early in a month before the new ones are out), checks that
    /// they read, deletes older months, and starts using them. About 12 MB.</summary>
    public async Task UpdateAsync(HttpClient http, CancellationToken cancel)
    {
        Directory.CreateDirectory(folder);
        var now = DateTime.UtcNow;
        Exception? failed = null;
        foreach (var date in (DateTime[])[now, now.AddMonths(-1)])
        {
            var month = date.ToString("yyyy-MM", CultureInfo.InvariantCulture);
            if (LatestMonth(folder) == month)
            {
                if (!Loaded) await Task.Run(Load, cancel).ConfigureAwait(false);
                return;
            }
            try
            {
                await DownloadFileAsync(http, BaseUrl + CountryFile(month), Path.Combine(folder, CountryFile(month)), cancel).ConfigureAwait(false);
                await DownloadFileAsync(http, BaseUrl + AsnFile(month), Path.Combine(folder, AsnFile(month)), cancel).ConfigureAwait(false);
                await Task.Run(Load, cancel).ConfigureAwait(false);
                foreach (var old in Directory.EnumerateFiles(folder, "dbip-*-lite-*.csv.gz"))
                {
                    if (!Path.GetFileName(old).Contains(month, StringComparison.Ordinal)) File.Delete(old);
                }
                return;
            }
            catch (HttpRequestException exception) when (exception.StatusCode == HttpStatusCode.NotFound)
            {
                failed = exception;
            }
        }
        throw new InvalidOperationException("DB-IP has no files for this month or the last one.", failed);
    }

    private static async Task DownloadFileAsync(HttpClient http, string url, string file, CancellationToken cancel)
    {
        var part = file + ".part";
        using (var response = await http.GetAsync(url, HttpCompletionOption.ResponseHeadersRead, cancel).ConfigureAwait(false))
        {
            response.EnsureSuccessStatusCode();
            await using var output = File.Create(part);
            await response.Content.CopyToAsync(output, cancel).ConfigureAwait(false);
        }
        File.Move(part, file, overwrite: true);
    }

    /// <summary>Address ranges, each with a value, sorted for binary search.</summary>
    private sealed class RangeTable
    {
        private readonly List<(UInt128 First, UInt128 Last, int Value)> building = [];
        private UInt128[] firsts = [], lasts = [];
        private int[] values = [];

        public void Add(UInt128 first, UInt128 last, int value) => building.Add((first, last, value));

        public void Seal()
        {
            building.Sort((a, b) => a.First.CompareTo(b.First));
            firsts = [.. building.Select(range => range.First)];
            lasts = [.. building.Select(range => range.Last)];
            values = [.. building.Select(range => range.Value)];
            building.Clear();
            building.TrimExcess();
        }

        public int Find(UInt128 address)
        {
            var i = Array.BinarySearch(firsts, address);
            if (i < 0) i = ~i - 1;
            return i >= 0 && address <= lasts[i] ? values[i] : -1;
        }
    }
}
