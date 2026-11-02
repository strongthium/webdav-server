using System.Text.Json;

namespace Strongthium.WebDavServer.Config;

/// <summary>One address to listen on.</summary>
public sealed record ListenerConfig
{
    public string Address { get; init; } = "*";
    public int Port { get; init; } = 8443;

    /// <summary>Plain HTTP is only for a proxy on the same machine: logins over it are refused otherwise.</summary>
    public bool Tls { get; init; } = true;
}

/// <summary>
/// What has to be known before the server can start, and needs a restart to change: <c>webdav-server.json</c> in the data
/// folder. Everything else (accounts, paths, whitelists, bans, proxies) is in the database and changes as the server runs.
/// </summary>
public sealed record ServerConfig
{
    public List<ListenerConfig> Listen { get; init; } = [new()];

    /// <summary>The admin window's address. It's always TLS, with a certificate of its own that the window pins.</summary>
    public ListenerConfig Admin { get; init; } = new() { Port = 9443 };

    /// <summary>A PEM certificate and key for WebDAV. They're read again when they change, so a renewal needs no restart.
    /// Empty uses a self-signed one, made the first time.</summary>
    public string CertificateFile { get; init; } = "";
    public string KeyFile { get; init; } = "";

    public int MaxConnections { get; init; } = 4096;

    /// <summary>Accepts the default admin password from anywhere, not only this machine and private networks.</summary>
    public bool AllowDefaultAdminPasswordFromAnywhere { get; init; }

    private static readonly JsonSerializerOptions Options = new(JsonSerializerDefaults.Web) { WriteIndented = true, ReadCommentHandling = JsonCommentHandling.Skip, AllowTrailingCommas = true };

    public const string FileName = "webdav-server.json";

    /// <summary>The configuration in a data folder, written there the first time with the defaults.</summary>
    public static ServerConfig LoadOrCreate(string dataFolder)
    {
        var path = Path.Combine(dataFolder, FileName);
        if (File.Exists(path))
            return JsonSerializer.Deserialize<ServerConfig>(File.ReadAllText(path), Options) ?? new ServerConfig();
        var config = new ServerConfig();
        config.Save(dataFolder);
        return config;
    }

    /// <summary>Writes the configuration to a data folder, readable only by the server.</summary>
    public void Save(string dataFolder)
    {
        var path = Path.Combine(dataFolder, FileName);
        File.WriteAllText(path, JsonSerializer.Serialize(this, Options));
        DataFolder.Protect(path);
    }
}

public static class DataFolder
{
    /// <summary>Where data goes unless <c>--data</c> says otherwise.</summary>
    public static string Default()
    {
        if (OperatingSystem.IsWindows())
            return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Strongthium", "webdav-server");
        const string service = "/var/lib/webdav-server";
        if (Environment.GetEnvironmentVariable("STATE_DIRECTORY") is { Length: > 0 } state) return state;
        if (Environment.UserName == "root" || Directory.Exists(service)) return service;
        return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".local", "share", "webdav-server");
    }

    /// <summary>Makes the data folder, readable only by the account the server runs as. It holds password hashes and keys.</summary>
    public static void Prepare(string folder)
    {
        Directory.CreateDirectory(folder);
        Protect(folder);
    }

    /// <summary>Takes a file or folder away from everyone but the account the server runs as, and administrators.</summary>
    public static void Protect(string path)
    {
        if (OperatingSystem.IsWindows()) ProtectOnWindows(path);
        else if (Directory.Exists(path)) File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        else File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
    }

    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private static void ProtectOnWindows(string path)
    {
        // ProgramData is readable by every user by default. Files within a folder inherit this.
        var me = System.Security.Principal.WindowsIdentity.GetCurrent().User!;
        var system = new System.Security.Principal.SecurityIdentifier(System.Security.Principal.WellKnownSidType.LocalSystemSid, null);
        var admins = new System.Security.Principal.SecurityIdentifier(System.Security.Principal.WellKnownSidType.BuiltinAdministratorsSid, null);
        const System.Security.AccessControl.FileSystemRights full = System.Security.AccessControl.FileSystemRights.FullControl;
        if (Directory.Exists(path))
        {
            const System.Security.AccessControl.InheritanceFlags inherit = System.Security.AccessControl.InheritanceFlags.ContainerInherit | System.Security.AccessControl.InheritanceFlags.ObjectInherit;
            var security = new System.Security.AccessControl.DirectorySecurity();
            security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
            foreach (var who in new[] { me, system, admins })
                security.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(who, full, inherit, System.Security.AccessControl.PropagationFlags.None, System.Security.AccessControl.AccessControlType.Allow));
            new DirectoryInfo(path).SetAccessControl(security);
        }
        else
        {
            var security = new System.Security.AccessControl.FileSecurity();
            security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
            foreach (var who in new[] { me, system, admins })
                security.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(who, full, System.Security.AccessControl.AccessControlType.Allow));
            new FileInfo(path).SetAccessControl(security);
        }
    }
}
