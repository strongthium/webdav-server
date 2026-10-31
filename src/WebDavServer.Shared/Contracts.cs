using System.Text.Json;
using System.Text.Json.Serialization;

namespace Strongthium.WebDavServer;

/// <summary>Where a path keeps an account's files.</summary>
[JsonConverter(typeof(JsonStringEnumConverter<StorageLayout>))]
public enum StorageLayout
{
    /// <summary>By the account: the same files through every path laid out this way.</summary>
    User,

    /// <summary>By the path: everyone allowed on the path shares one set of files.</summary>
    Path,

    /// <summary>By both: each account has its own files on each path.</summary>
    UserAndPath,
}

/// <summary>A WebDAV path: <c>/team</c>, or <c>/</c> for the server's own address.</summary>
public sealed record MountInfo
{
    public string Path { get; init; } = "/dav";
    public StorageLayout Layout { get; init; } = StorageLayout.User;

    /// <summary>A folder on the server to keep the files in; empty keeps them in the data folder.</summary>
    public string Root { get; init; } = "";
    public bool Enabled { get; init; } = true;

    /// <summary>Whether Nextcloud clients may connect at this path as well as WebDAV clients.</summary>
    public bool Nextcloud { get; init; } = true;

    /// <summary>Failed logins from an address that ban it from this path; 0 never bans.</summary>
    public int MaxFailures { get; init; } = 5;
    public int FailureWindowMinutes { get; init; } = 15;
    public int BanMinutes { get; init; } = 1440;

    /// <summary>The most a path laid out by path may hold, in bytes; 0 has no limit.</summary>
    public long QuotaBytes { get; init; }
}

/// <summary>A path an account may use.</summary>
public sealed record GrantInfo
{
    public string Mount { get; init; } = "";
    public bool ReadOnly { get; init; }
}

/// <summary>A password for one device, which can be taken away without touching the others.</summary>
public sealed record AppPasswordInfo
{
    public long Id { get; init; }
    public string Name { get; init; } = "";
    public DateTimeOffset Created { get; init; }
    public DateTimeOffset? LastUsed { get; init; }
}

public sealed record AccountInfo
{
    public string Name { get; init; } = "";
    public string DisplayName { get; init; } = "";
    public bool Enabled { get; init; } = true;

    /// <summary>Refuses the account's password over WebDAV: only app passwords log in.</summary>
    public bool RequireAppPasswords { get; init; }

    /// <summary>The most this account may keep, in bytes; 0 has no limit.</summary>
    public long QuotaBytes { get; init; }

    /// <summary>The path a Nextcloud client connecting to the server's own address sees; empty is the first it may use.</summary>
    public string HomeMount { get; init; } = "";

    /// <summary>The only places this account may log in from; empty is anywhere.</summary>
    public List<string> Whitelist { get; init; } = [];
    public List<GrantInfo> Grants { get; init; } = [];

    /// <summary>Filled in by the server; what's sent to it is ignored.</summary>
    public List<AppPasswordInfo> AppPasswords { get; init; } = [];
    public bool HasPassword { get; init; }

    /// <summary>What's kept for this account now, in bytes; -1 until it has been counted. Filled in by the server.</summary>
    public long UsedBytes { get; init; } = -1;
}

/// <summary>An account to save, with a new password if it's to have one.</summary>
public sealed record AccountWrite
{
    public AccountInfo Account { get; init; } = new();
    public string? Password { get; init; }
}

public sealed record ServerSettings
{
    /// <summary>The only places anyone may connect to WebDAV from; empty is anywhere.</summary>
    public List<string> Whitelist { get; init; } = [];

    /// <summary>How long a login from outside a whitelist bans the address.</summary>
    public int WhitelistBanMinutes { get; init; } = 7 * 24 * 60;

    /// <summary>The only places the admin window may connect from; empty is anywhere.</summary>
    public List<string> AdminWhitelist { get; init; } = [];
    public int AdminMaxFailures { get; init; } = 5;
    public int AdminFailureWindowMinutes { get; init; } = 15;
    public int AdminBanMinutes { get; init; } = 60;

    /// <summary>The server's own address, when no path is there: Nextcloud clients connecting there, and the list of paths.</summary>
    public int MaxFailures { get; init; } = 5;
    public int FailureWindowMinutes { get; init; } = 15;
    public int BanMinutes { get; init; } = 1440;

    /// <summary>Failed logins from an address, on all paths together in an hour, that ban it from all of WebDAV; 0 never does.
    /// Each path counts its own too, but without this, more paths would mean more guesses.</summary>
    public int MaxFailuresAllPaths { get; init; } = 30;

    /// <summary>How much of an IPv6 address is banned: one machine can hold a whole /64.</summary>
    public int BanPrefixV6 { get; init; } = 64;

    /// <summary>Addresses of proxies (nginx and the like) whose word is taken for who's connecting.</summary>
    public List<string> TrustedProxies { get; init; } = [];
    public bool TrustCloudflare { get; init; }

    /// <summary>The proxy says who's connecting with <c>X-Real-IP</c> alone, and passes on whatever a client writes in
    /// <c>X-Forwarded-For</c>. Only one of them can be believed, or a client could write the other.</summary>
    public bool ProxyUsesRealIp { get; init; }

    /// <summary>Takes logins through a trusted proxy on another machine over plain HTTP, on a network that's trusted to carry
    /// passwords in the clear: between containers, say. Off, that last stretch has to be TLS too.</summary>
    public bool AllowClearFromProxies { get; init; }

    /// <summary>Closes any connection that doesn't come from a trusted proxy or from this machine.</summary>
    public bool RequireProxy { get; init; }

    /// <summary>The address clients use, like <c>https://files.example.com</c>; empty goes by what each request says.</summary>
    public string PublicUrl { get; init; } = "";

    /// <summary>The largest single upload, in bytes; 0 has no limit but the quota.</summary>
    public long MaxUploadBytes { get; init; }

    /// <summary>Keeps DB-IP's files up to date, once whitelists use countries or networks.</summary>
    public bool GeoAutoUpdate { get; init; } = true;
}

public sealed record BanInfo
{
    public string Network { get; init; } = "";

    /// <summary><c>*</c> for all of WebDAV, <c>admin</c> for the admin port, or a path.</summary>
    public string Scope { get; init; } = "*";
    public string Reason { get; init; } = "";
    public DateTimeOffset Created { get; init; }

    /// <summary>When it ends; null never does.</summary>
    public DateTimeOffset? Until { get; init; }
}

public sealed record BanWrite
{
    public string Network { get; init; } = "";
    public string Scope { get; init; } = "*";
    public string Reason { get; init; } = "";

    /// <summary>0 never ends.</summary>
    public int Minutes { get; init; }
}

public sealed record LogEntry
{
    public long Id { get; init; }
    public DateTimeOffset Time { get; init; }
    public string Kind { get; init; } = "";
    public string Address { get; init; } = "";
    public string Account { get; init; } = "";
    public string Scope { get; init; } = "";
    public string Message { get; init; } = "";
}

public sealed record StatusInfo
{
    public string Version { get; init; } = "";
    public string System { get; init; } = "";
    public DateTimeOffset Started { get; init; }
    public int OpenConnections { get; init; }
    public long ClosedAtTheDoor { get; init; }
    public int Accounts { get; init; }
    public int Mounts { get; init; }
    public int Bans { get; init; }
    public List<string> DavAddresses { get; init; } = [];
    public string AdminAddress { get; init; } = "";
    public string CertificateFingerprint { get; init; } = "";
    public string CertificateSubject { get; init; } = "";
    public DateTimeOffset? CertificateExpires { get; init; }
    public string DataFolder { get; init; } = "";
    public string GeoMonth { get; init; } = "";
    public int CloudflareRanges { get; init; }

    /// <summary>What the admin ought to look at.</summary>
    public List<string> Warnings { get; init; } = [];
}

public sealed record LoginRequest
{
    public string UserName { get; init; } = "";
    public string Password { get; init; } = "";
}

public sealed record LoginResponse
{
    public string Token { get; init; } = "";
    public string UserName { get; init; } = "";

    /// <summary>Nothing but changing the password is allowed until it's been changed.</summary>
    public bool MustChangePassword { get; init; }
}

public sealed record ChangePasswordRequest
{
    public string CurrentPassword { get; init; } = "";
    public string NewPassword { get; init; } = "";

    /// <summary>A new name to log in with; empty keeps the one there is.</summary>
    public string NewUserName { get; init; } = "";
}

public sealed record AppPasswordRequest
{
    public string Account { get; init; } = "";
    public string Name { get; init; } = "";
}

public sealed record AppPasswordCreated
{
    public AppPasswordInfo Info { get; init; } = new();

    /// <summary>The password. It's shown this once: only its hash is kept.</summary>
    public string Password { get; init; } = "";
}

public sealed record ApiError
{
    public string Error { get; init; } = "";
    public string Code { get; init; } = "";
}

public static class Api
{
    /// <summary>How the two sides write JSON to each other.</summary>
    public static JsonSerializerOptions Json { get; } = new(JsonSerializerDefaults.Web);

    public const string MustChangePasswordCode = "must_change_password";
    public const int MinimumPasswordLength = 12;

    /// <summary>What's wrong with a new password, or null if nothing is.</summary>
    public static string? PasswordProblem(string password)
    {
        if (password.Length < MinimumPasswordLength) return $"A password needs at least {MinimumPasswordLength} characters.";
        if (password.Length > 1024) return "A password can have at most 1024 characters.";
        return password.Distinct().Count() < 5 ? "That password repeats too few different characters." : null;
    }
}
