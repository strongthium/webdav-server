using System.Globalization;
using System.Net;
using System.Net.Sockets;

namespace Strongthium.WebDavServer;

/// <summary>Where an address is, for rules naming a country or a network.</summary>
public interface IPlaces
{
    /// <summary>Whether there's anything to look addresses up in.</summary>
    bool Loaded { get; }

    (string Country, int Asn) Lookup(IPAddress address);
}

public static class Networks
{
    /// <summary>The same address in one form: IPv4 that came in over a dual-stack socket as plain IPv4.</summary>
    public static IPAddress Normal(IPAddress address) => address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address;

    /// <summary>A network written as <c>203.0.113.0/24</c>, or one address. Bits beyond the prefix don't matter.</summary>
    public static bool TryParse(string text, out IPNetwork network)
    {
        network = default;
        text = text.Trim();
        var slash = text.IndexOf('/');
        var addressText = slash < 0 ? text : text[..slash];
        if (!IPAddress.TryParse(addressText, out var address)) return false;
        address = Normal(address);
        var most = address.AddressFamily == AddressFamily.InterNetwork ? 32 : 128;
        var bits = most;
        if (slash >= 0 && (!int.TryParse(text[(slash + 1)..], NumberStyles.None, CultureInfo.InvariantCulture, out bits) || bits > most)) return false;
        network = new IPNetwork(Masked(address, bits), bits);
        return true;
    }

    /// <summary>The network of the first <paramref name="bits"/> bits of an address.</summary>
    public static IPNetwork Around(IPAddress address, int bits) => new(Masked(address, bits), bits);

    public static string Format(IPNetwork network)
    {
        var whole = network.BaseAddress.AddressFamily == AddressFamily.InterNetwork ? 32 : 128;
        return network.PrefixLength == whole ? network.BaseAddress.ToString() : network.ToString();
    }

    private static IPAddress Masked(IPAddress address, int bits)
    {
        var bytes = address.GetAddressBytes();
        for (var i = 0; i < bytes.Length; i++)
        {
            var keep = Math.Clamp(bits - i * 8, 0, 8);
            bytes[i] &= (byte)(0xFF << (8 - keep));
        }
        return new IPAddress(bytes);
    }

    public static bool IsPrivate(IPAddress address)
    {
        address = Normal(address);
        if (IPAddress.IsLoopback(address)) return true;
        var bytes = address.GetAddressBytes();
        if (address.AddressFamily == AddressFamily.InterNetwork)
            return bytes[0] == 10 || (bytes[0] == 172 && bytes[1] is >= 16 and < 32) || (bytes[0] == 192 && bytes[1] == 168)
                || (bytes[0] == 169 && bytes[1] == 254) || (bytes[0] == 100 && bytes[1] is >= 64 and < 128);
        return address.IsIPv6LinkLocal || address.IsIPv6UniqueLocal;
    }
}

/// <summary>What a whitelist says of an address.</summary>
public enum AccessVerdict
{
    Allowed,
    Denied,

    /// <summary>Only a country or network rule could allow it, and there's no database to look it up in. It's kept out, but
    /// not punished: the fault is the server's.</summary>
    CannotTell,
}

/// <summary>
/// A whitelist: addresses and networks (<c>203.0.113.7</c>, <c>2001:db8::/32</c>), autonomous systems (<c>AS64500</c>) and
/// countries (<c>CA</c>). An address is allowed if any of them matches. An empty list allows everyone.
/// </summary>
public sealed class AccessList
{
    public static readonly AccessList Empty = new([], [], []);

    private readonly IPNetwork[] networks;
    private readonly HashSet<int> systems;
    private readonly HashSet<string> countries;

    private AccessList(IPNetwork[] networks, HashSet<int> systems, HashSet<string> countries)
    {
        this.networks = networks;
        this.systems = systems;
        this.countries = countries;
    }

    public bool IsEmpty => networks.Length == 0 && systems.Count == 0 && countries.Count == 0;

    /// <summary>Whether looking up a country or network could matter.</summary>
    public bool NeedsPlaces => systems.Count > 0 || countries.Count > 0;

    /// <summary>What's wrong with a rule, or null if it can be read.</summary>
    public static string? Problem(string rule)
    {
        rule = rule.Trim();
        if (rule.Length == 0) return "An empty rule.";
        if (Networks.TryParse(rule, out _) || IsAsn(rule, out _) || IsCountry(rule)) return null;
        return $"\"{rule}\" isn't an address, a network (203.0.113.0/24), an AS number (AS64500) or a two-letter country (CA).";
    }

    /// <summary>A list read from rules. Rules that can't be read are left out: <see cref="Problem"/> refuses them on the way
    /// in. If any were left out of a list that would then be empty, the list allows no one rather than everyone.</summary>
    public static AccessList Parse(IEnumerable<string> rules)
    {
        var nets = new List<IPNetwork>();
        var asns = new HashSet<int>();
        var codes = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var unread = false;
        foreach (var raw in rules)
        {
            var rule = raw.Trim();
            if (Networks.TryParse(rule, out var network)) nets.Add(network);
            else if (IsAsn(rule, out var asn)) asns.Add(asn);
            else if (IsCountry(rule)) codes.Add(rule);
            else unread = true;
        }
        if (unread && nets.Count == 0 && asns.Count == 0 && codes.Count == 0) nets.Add(new IPNetwork(IPAddress.Parse("192.0.2.255"), 32));
        return new AccessList([.. nets], asns, codes);
    }

    public AccessVerdict Check(IPAddress address, IPlaces? places)
    {
        if (IsEmpty) return AccessVerdict.Allowed;
        address = Networks.Normal(address);
        foreach (var network in networks)
        {
            if (network.Contains(address)) return AccessVerdict.Allowed;
        }
        if (!NeedsPlaces) return AccessVerdict.Denied;
        if (places is not { Loaded: true }) return AccessVerdict.CannotTell;
        var (country, asn) = places.Lookup(address);
        return countries.Contains(country) || systems.Contains(asn) ? AccessVerdict.Allowed : AccessVerdict.Denied;
    }

    private static bool IsAsn(string rule, out int asn)
    {
        asn = 0;
        return rule.StartsWith("AS", StringComparison.OrdinalIgnoreCase)
            && int.TryParse(rule.AsSpan(2), NumberStyles.None, CultureInfo.InvariantCulture, out asn) && asn > 0;
    }

    private static bool IsCountry(string rule) => rule.Length == 2 && rule.All(char.IsAsciiLetter);
}
