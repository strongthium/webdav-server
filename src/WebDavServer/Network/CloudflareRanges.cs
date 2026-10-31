using System.Net;

namespace Strongthium.WebDavServer.Network;

/// <summary>
/// The addresses Cloudflare connects from: the list it publishes, which is built in, and kept up to date from
/// <c>www.cloudflare.com</c> while the server is set to be behind Cloudflare. Only then does it ever ask.
/// </summary>
public sealed class CloudflareRanges
{
    /// <summary>From https://www.cloudflare.com/ips/.</summary>
    private static readonly string[] BuiltIn =
    [
        "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22", "141.101.64.0/18", "108.162.192.0/18",
        "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
        "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
        "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32", "2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32",
    ];

    private readonly string file;
    private volatile IPNetwork[] ranges;

    public CloudflareRanges(string dataFolder)
    {
        file = Path.Combine(dataFolder, "cloudflare-ranges.txt");
        ranges = Parse(BuiltIn) ?? [];
        if (File.Exists(file) && Parse(File.ReadAllLines(file)) is { } saved) ranges = saved;
    }

    public IPNetwork[] Ranges => ranges;

    /// <summary>A list as published, if it looks like one: a list that's short or has anything else in it isn't believed,
    /// since being wrong about this is trusting strangers' headers.</summary>
    public static IPNetwork[]? Parse(IEnumerable<string> lines)
    {
        var networks = new List<IPNetwork>();
        foreach (var line in lines)
        {
            var text = line.Trim();
            if (text.Length == 0) continue;
            if (!Networks.TryParse(text, out var network) || network.PrefixLength < (network.BaseAddress.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork ? 8 : 16)) return null;
            networks.Add(network);
        }
        return networks.Count >= 10 ? [.. networks] : null;
    }

    public async Task UpdateAsync(HttpClient http, CancellationToken cancel)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancel);
        timeout.CancelAfter(TimeSpan.FromSeconds(30));
        var v4 = await http.GetStringAsync("https://www.cloudflare.com/ips-v4", timeout.Token).ConfigureAwait(false);
        var v6 = await http.GetStringAsync("https://www.cloudflare.com/ips-v6", timeout.Token).ConfigureAwait(false);
        var lines = (v4 + "\n" + v6).Split('\n', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
        var parsed = Parse(lines) ?? throw new InvalidDataException("Cloudflare's list of addresses didn't look as it should, so the one there is stays.");
        File.WriteAllLines(file, lines);
        ranges = parsed;
    }
}
