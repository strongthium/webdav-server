using System.Collections.Frozen;
using System.Net;
using System.Text.RegularExpressions;
using Strongthium.WebDavServer.Network;
using Strongthium.WebDavServer.Storage;

namespace Strongthium.WebDavServer.Security;

/// <summary>An account, ready to be checked against.</summary>
public sealed class Account
{
    public required AccountInfo Info { get; init; }
    public required string PasswordHash { get; init; }
    public required long Generation { get; init; }
    public required AccessList Whitelist { get; init; }

    /// <summary>App passwords' hashes, and which each one is.</summary>
    public required FrozenDictionary<string, long> AppPasswords { get; init; }
    public string Name => Info.Name;

    public GrantInfo? GrantOn(string mountPath) => Info.Grants.FirstOrDefault(grant => grant.Mount == mountPath);
}

/// <summary>Everything that decides who may do what, read from the database at one moment. It's replaced whole when the admin
/// changes something, so a request sees one consistent set, and reading it takes no lock.</summary>
public sealed class Policy
{
    public required ServerSettings Settings { get; init; }
    public required FrozenDictionary<string, MountInfo> Mounts { get; init; }
    public required FrozenDictionary<string, Account> Accounts { get; init; }
    public required AccessList Whitelist { get; init; }
    public required AccessList AdminWhitelist { get; init; }
    public required IPNetwork[] TrustedProxies { get; init; }

    public MountInfo? RootMount => Mounts.GetValueOrDefault("/") is { Enabled: true } root ? root : null;

    /// <summary>The rule on failed logins for a scope: a path's own, or the server's for its own address.</summary>
    public (int MaxFailures, TimeSpan Window, TimeSpan Ban) FailureRule(string scope)
    {
        if (scope == Scopes.All) return (Settings.MaxFailuresAllPaths, TimeSpan.FromHours(1), TimeSpan.FromMinutes(Settings.BanMinutes));
        if (scope == Scopes.Admin) return (Settings.AdminMaxFailures, TimeSpan.FromMinutes(Settings.AdminFailureWindowMinutes), TimeSpan.FromMinutes(Settings.AdminBanMinutes));
        if (Mounts.TryGetValue(scope, out var mount)) return (mount.MaxFailures, TimeSpan.FromMinutes(mount.FailureWindowMinutes), TimeSpan.FromMinutes(mount.BanMinutes));
        return (Settings.MaxFailures, TimeSpan.FromMinutes(Settings.FailureWindowMinutes), TimeSpan.FromMinutes(Settings.BanMinutes));
    }

    /// <summary>The path an account lands on when connecting to the server's own address as a Nextcloud client.</summary>
    public MountInfo? HomeOf(Account account)
    {
        if (account.Info.HomeMount.Length > 0 && Mounts.TryGetValue(account.Info.HomeMount, out var home) && home is { Enabled: true, Nextcloud: true } && account.GrantOn(home.Path) is not null) return home;
        if (RootMount is { Nextcloud: true } root && account.GrantOn(root.Path) is not null) return root;
        foreach (var grant in account.Info.Grants.OrderBy(grant => grant.Mount, StringComparer.Ordinal))
        {
            if (Mounts.TryGetValue(grant.Mount, out var mount) && mount is { Enabled: true, Nextcloud: true }) return mount;
        }
        return null;
    }
}

public static class Scopes
{
    /// <summary>All of WebDAV: what whitelists and server-wide bans cover.</summary>
    public const string All = "*";

    /// <summary>The admin port, which has bans of its own, so that a ban on WebDAV can't shut the admin out as well.</summary>
    public const string Admin = "admin";

    /// <summary>The server's own address, when it isn't a path: Nextcloud clients connecting there, and the list of paths.</summary>
    public const string Root = "/";
}

public static partial class Names
{
    [GeneratedRegex("^[a-z0-9][a-z0-9._-]{0,63}$")]
    private static partial Regex AccountPattern();

    [GeneratedRegex("^/[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")]
    private static partial Regex MountPattern();

    /// <summary>Names at the top of the address that Nextcloud clients use, which a path can't take.</summary>
    public static readonly FrozenSet<string> ReservedTop = new[]
    {
        "status.php", "remote.php", "index.php", "public.php", "cron.php", "ocs", "ocs-provider", "ocm-provider", ".well-known", "avatar", "login", "apps",
    }.ToFrozenSet(StringComparer.OrdinalIgnoreCase);

    /// <summary>What's wrong with an account's name, or null. Names become folder names, so they're kept simple.</summary>
    public static string? AccountProblem(string name)
    {
        if (!AccountPattern().IsMatch(name)) return "An account's name is 1 to 64 small letters, digits, dots, dashes or underscores, starting with a letter or digit.";
        if (name.EndsWith('.') || name == PathRules.Hidden || !PathRules.IsValidSegment(name, windows: true)) return $"\"{name}\" can't be used as a folder name on every system.";
        return null;
    }

    /// <summary>What's wrong with a path, or null. A path is <c>/</c> or one name: <c>/team</c>.</summary>
    public static string? MountProblem(string path)
    {
        if (path == "/") return null;
        if (!MountPattern().IsMatch(path)) return "A path is / or a single name: /team. It's up to 64 letters, digits, dots, dashes or underscores, starting with a letter or digit.";
        if (ReservedTop.Contains(path[1..])) return $"{path} is one of the addresses Nextcloud clients use.";
        if (path.EndsWith('.') || !PathRules.IsValidSegment(path[1..], windows: true)) return $"{path} can't be used as a folder name on every system.";
        return null;
    }

    /// <summary>A path's folder name in the data folder.</summary>
    public static string MountFolder(string path) => path == "/" ? "_root" : path[1..].ToLowerInvariant();
}

/// <summary>Holds the policy in force, and what depends on it from outside the database.</summary>
public sealed class ServerState
{
    private volatile Policy policy = null!;

    public Database Database { get; }
    public NodeStore Nodes { get; }
    public UsageTracker Usage { get; } = new();
    public string DataFolder { get; }
    public string FilesFolder => Path.Combine(DataFolder, "files");
    public CloudflareRanges Cloudflare { get; }
    public GeoDatabase Geo { get; }
    public DateTimeOffset Started { get; } = DateTimeOffset.UtcNow;

    public ServerState(string dataFolder, TimeProvider? clock = null)
    {
        DataFolder = dataFolder;
        Clock = clock ?? TimeProvider.System;
        Database = new Database(Path.Combine(dataFolder, "webdav-server.db"));
        Nodes = new NodeStore(Database);
        Cloudflare = new CloudflareRanges(dataFolder);
        Geo = new GeoDatabase(Path.Combine(dataFolder, "geo"));
        Seed();
        Reload();
    }

    public TimeProvider Clock { get; }
    public Policy Policy => policy;

    /// <summary>The first start: one path, so that an account has somewhere to go, and the admin with the default password,
    /// which has to be changed before anything else can be done with it.</summary>
    private void Seed()
    {
        if (Database.LoadAdmin() is null) Database.SaveAdmin(DefaultAdminName, Passwords.Hash(DefaultAdminPassword), mustChange: true);
        if (Database.LoadMounts().Count == 0) Database.SaveMount(new MountInfo { Path = "/dav" });
    }

    public const string DefaultAdminName = "admin";
    public const string DefaultAdminPassword = "admin";

    /// <summary>Reads everything again after a change.</summary>
    public void Reload()
    {
        var settings = Database.LoadSettings();
        var appPasswords = Database.LoadAppPasswords().ToLookup(row => row.Account);
        var accounts = Database.LoadAccounts().Select(row => new Account
        {
            Info = row.Info with
            {
                HasPassword = row.PasswordHash.Length > 0,
                AppPasswords = [.. appPasswords[row.Info.Name].Select(token => new AppPasswordInfo { Id = token.Id, Name = token.Name, Created = token.Created, LastUsed = token.LastUsed })],
            },
            PasswordHash = row.PasswordHash,
            Generation = row.CredentialGeneration,
            Whitelist = AccessList.Parse(row.Info.Whitelist),
            AppPasswords = appPasswords[row.Info.Name].ToFrozenDictionary(token => token.TokenHash, token => token.Id),
        });
        policy = new Policy
        {
            Settings = settings,
            Mounts = Database.LoadMounts().ToFrozenDictionary(mount => mount.Path, StringComparer.OrdinalIgnoreCase),
            Accounts = accounts.ToFrozenDictionary(account => account.Name, StringComparer.OrdinalIgnoreCase),
            Whitelist = AccessList.Parse(settings.Whitelist),
            AdminWhitelist = AccessList.Parse(settings.AdminWhitelist),
            TrustedProxies = [.. settings.TrustedProxies.Select(text => Networks.TryParse(text, out var network) ? (IPNetwork?)network : null).OfType<IPNetwork>()],
        };
    }

    /// <summary>Where an account's files are on a path.</summary>
    public Space SpaceFor(MountInfo mount, Account account)
    {
        var name = account.Name.ToLowerInvariant();
        var folder = Names.MountFolder(mount.Path);
        return mount.Layout switch
        {
            StorageLayout.User => new Space(mount.Root.Length > 0 ? Path.Combine(mount.Root, name) : Path.Combine(FilesFolder, "users", name), account.Info.QuotaBytes),
            StorageLayout.Path => new Space(mount.Root.Length > 0 ? mount.Root : Path.Combine(FilesFolder, "paths", folder), mount.QuotaBytes),
            _ => new Space(mount.Root.Length > 0 ? Path.Combine(mount.Root, name) : Path.Combine(FilesFolder, "paths", folder, name), account.Info.QuotaBytes),
        };
    }

    /// <summary>A line in the log, which the admin window shows. No password or token ever goes in one.</summary>
    public void Log(string kind, IPAddress? address, string account, string scope, string message)
    {
        // Names come from whoever is trying to log in. A line break in one would write a false line in the log.
        account = Clean(account);
        message = Clean(message);
        Database.AddLog(Clock.GetUtcNow(), kind, address?.ToString() ?? "", account, scope, message);
        LogLine?.Invoke($"{kind} {address} {account} {scope} {message}".Trim());
    }

    private static string Clean(string text) => text.Any(char.IsControl) ? new string([.. text.Select(c => char.IsControl(c) ? '?' : c)]) : text;

    /// <summary>Where log lines go besides the database: the console, and from there the system's journal.</summary>
    public Action<string>? LogLine { get; set; }
}
