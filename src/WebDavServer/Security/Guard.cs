using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;

namespace Strongthium.WebDavServer.Security;

/// <summary>
/// Who's banned from where, and who's on the way to it. Bans are in the database, so they outlast a restart, and in memory, so
/// that checking one at a socket's door costs next to nothing, however many connections an attacker opens.
/// </summary>
public sealed class Guard
{
    private readonly ServerState state;
    private readonly ConcurrentDictionary<(string Network, string Scope), BanInfo> single = new();
    private volatile (IPNetwork Network, BanInfo Ban)[] wide = [];
    private readonly ConcurrentDictionary<(string Network, string Scope), Failures> failures = new();
    private readonly Lock logBudgetGate = new();
    private DateTimeOffset logBudgetSince = DateTimeOffset.MinValue;
    private int logBudget;

    private sealed class Failures
    {
        public int Count;
        public DateTimeOffset Since;
    }

    /// <summary>The most addresses whose failures are counted at once; past that, the oldest are let go.</summary>
    private const int MaxTracked = 100_000;

    public Guard(ServerState state)
    {
        this.state = state;
        Reload();
    }

    private DateTimeOffset Now => state.Clock.GetUtcNow();

    private void Reload()
    {
        single.Clear();
        var wider = new List<(IPNetwork, BanInfo)>();
        foreach (var ban in state.Database.LoadBans())
        {
            if (ban.Until is { } until && until <= Now) continue;
            Remember(ban, wider);
        }
        wide = [.. wider];
    }

    private void Remember(BanInfo ban, List<(IPNetwork, BanInfo)> wider)
    {
        if (!Networks.TryParse(ban.Network, out var network)) return;
        if (IsSingleKey(network)) single[(Networks.Format(network), ban.Scope)] = ban;
        else wider.Add((network, ban));
    }

    /// <summary>The bans a whole address covers are looked up directly: a v4 address or a v6 network of the size bans use.</summary>
    private bool IsSingleKey(IPNetwork network) =>
        network.BaseAddress.AddressFamily == AddressFamily.InterNetwork ? network.PrefixLength == 32 : network.PrefixLength == state.Policy.Settings.BanPrefixV6;

    /// <summary>The network a ban on an address covers: IPv4's one address, or IPv6's /64, which one machine can hold whole.</summary>
    public IPNetwork BanNetwork(IPAddress address)
    {
        address = Networks.Normal(address);
        return Networks.Around(address, address.AddressFamily == AddressFamily.InterNetwork ? 32 : Math.Clamp(state.Policy.Settings.BanPrefixV6, 32, 128));
    }

    public bool IsBanned(IPAddress address, string scope)
    {
        address = Networks.Normal(address);
        var now = Now;
        if (single.TryGetValue((Networks.Format(BanNetwork(address)), scope), out var ban) && (ban.Until is null || ban.Until > now)) return true;
        foreach (var (network, entry) in wide)
        {
            if (entry.Scope == scope && (entry.Until is null || entry.Until > now) && network.Contains(address)) return true;
        }
        return false;
    }

    /// <summary>Bans an address from a scope. A longer ban already in force isn't shortened.</summary>
    public void Ban(IPAddress address, string scope, TimeSpan duration, string reason, string account = "")
    {
        var network = BanNetwork(address);
        var key = Networks.Format(network);
        var until = Now + duration;
        if (single.TryGetValue((key, scope), out var existing) && (existing.Until is null || existing.Until >= until)) return;
        var ban = new BanInfo { Network = key, Scope = scope, Reason = reason, Created = Now, Until = until };
        state.Database.SaveBan(ban);
        single[(key, scope)] = ban;
        state.Log("ban", address, account, scope, $"{reason} Banned until {until:u}.");
    }

    /// <summary>A ban made by hand, which may cover any network, and may never end.</summary>
    public void AddBan(BanInfo ban)
    {
        state.Database.SaveBan(ban);
        Reload();
        state.Log("ban", null, "", ban.Scope, $"{ban.Network} banned by the admin. {ban.Reason}".Trim());
    }

    public bool RemoveBan(string network, string scope)
    {
        var removed = state.Database.DeleteBan(network, scope);
        Reload();
        foreach (var key in failures.Keys.Where(key => key.Network == network && key.Scope == scope).ToList()) failures.TryRemove(key, out _);
        if (removed) state.Log("unban", null, "", scope, $"{network} let back in by the admin.");
        return removed;
    }

    /// <summary>The bans in force.</summary>
    public List<BanInfo> Bans()
    {
        var now = Now;
        return [.. single.Values.Concat(wide.Select(entry => entry.Ban)).Where(ban => ban.Until is null || ban.Until > now).OrderByDescending(ban => ban.Created)];
    }

    public int BanCount => Bans().Count;

    /// <summary>
    /// A failed login. True if it's the one that crosses the line and the address is now banned from the scope. Failures are
    /// counted per address and per scope, not per account: someone trying many names from one place is exactly what this is
    /// for, and locking an account would let anyone lock its owner out. A failure counts until the window has passed since
    /// the first one, and logging in successfully doesn't clear it, or one good account would give an attacker endless tries.
    /// </summary>
    public bool LoginFailed(IPAddress address, string scope, string account)
    {
        var now = Now;
        if (failures.Count >= MaxTracked) LetGoOfOldest(now);
        var count = Count(address, scope, now);
        var (maxFailures, _, banFor) = state.Policy.FailureRule(scope);
        if (MayLog(now)) state.Log("login-failed", address, account, scope, $"Failed login {count}{(maxFailures > 0 ? $" of {maxFailures}" : "")}.");

        // All paths together as well, or each new path would be another set of guesses at every account.
        if (scope != Scopes.Admin)
        {
            var total = Count(address, Scopes.All, now);
            var (maxTotal, _, banTotalFor) = state.Policy.FailureRule(Scopes.All);
            if (maxTotal > 0 && total >= maxTotal)
            {
                failures.TryRemove((Networks.Format(BanNetwork(address)), Scopes.All), out _);
                Ban(address, Scopes.All, banTotalFor, $"{total} failed logins across all paths.", account);
                return true;
            }
        }

        if (maxFailures <= 0 || count < maxFailures) return false;
        failures.TryRemove((Networks.Format(BanNetwork(address)), scope), out _);
        Ban(address, scope, banFor, $"{count} failed logins.", account);
        return true;
    }

    private int Count(IPAddress address, string scope, DateTimeOffset now)
    {
        var (_, window, _) = state.Policy.FailureRule(scope);
        var entry = failures.GetOrAdd((Networks.Format(BanNetwork(address)), scope), _ => new Failures { Since = now });
        lock (entry)
        {
            if (now - entry.Since > window)
            {
                entry.Count = 0;
                entry.Since = now;
            }
            return ++entry.Count;
        }
    }

    /// <summary>Anyone can send failed logins without limit, from enough addresses, and each would be a row in the database. So
    /// this many go in the log in a minute: enough for a person to read, and the bans are always logged.</summary>
    private bool MayLog(DateTimeOffset now)
    {
        const int perMinute = 60;
        lock (logBudgetGate)
        {
            if (now - logBudgetSince >= TimeSpan.FromMinutes(1))
            {
                logBudgetSince = now;
                logBudget = perMinute;
            }
            return logBudget-- > 0;
        }
    }

    /// <summary>Someone with very many addresses could fill memory with failures. What's expired goes first, then the oldest
    /// half: an attacker that busy loses count of their own failures too, and bans already made aren't touched.</summary>
    private void LetGoOfOldest(DateTimeOffset now)
    {
        Sweep(now);
        if (failures.Count < MaxTracked) return;
        foreach (var (key, _) in failures.OrderBy(entry => entry.Value.Since).Take(failures.Count / 2).ToList()) failures.TryRemove(key, out _);
    }

    /// <summary>Drops what's expired. Runs every few minutes.</summary>
    public void Sweep(DateTimeOffset? at = null)
    {
        var now = at ?? Now;
        foreach (var (key, entry) in failures)
        {
            var (_, window, _) = state.Policy.FailureRule(key.Scope);
            if (now - entry.Since > window) failures.TryRemove(key, out _);
        }
        foreach (var (key, ban) in single)
        {
            if (ban.Until is { } until && until <= now) single.TryRemove(key, out _);
        }
        if (wide.Any(entry => entry.Ban.Until is { } until && until <= now)) wide = [.. wide.Where(entry => entry.Ban.Until is null || entry.Ban.Until > now)];
        state.Database.DeleteExpiredBans(now);
    }

    /// <summary>The bans are read again after the size of an IPv6 ban changes.</summary>
    public void SettingsChanged() => Reload();
}
