using Strongthium.WebDavServer;
using Strongthium.WebDavServer.Config;
using Strongthium.WebDavServer.Install;
using Strongthium.WebDavServer.Network;
using Strongthium.WebDavServer.Security;

return await Program.MainAsync(args);

/// <summary>The command line: with nothing on it, the server runs.</summary>
internal static partial class Program
{
    private const string Usage = """
        webdav-server [--data FOLDER]

        Runs the WebDAV server. It keeps everything in one folder (--data): its settings file webdav-server.json, the
        database, certificates, and by default the files. The accounts, paths, whitelists and bans are managed from the
        admin window, webdav-server-admin, on Windows. The default admin login is admin / admin, which has to be changed
        the first time, and only works from this machine or a private network until it is.

        --install [--yes]          sets the server up as a service that starts with the machine: systemd on Linux, the
                                   service manager on Windows. It finds free ports and asks about a certificate, then
                                   writes webdav-server.json. Run as root or from an administrator's prompt. --yes takes
                                   every suggestion without asking. Installing again keeps the settings that are there.
        --uninstall [--yes]        takes the service and the program away, and asks before it deletes the data folder

        On this machine, for when you can't get in, each with the server stopped:
          --set-admin-password     asks for a new admin password
          --reset-admin            back to the default login, with the admin whitelist and admin bans cleared
          --unban ADDRESS          lifts every ban on an address
          --fingerprint            shows the admin port's certificate, to compare with what the admin window shows

        --about                    who makes this, and whether there's a newer version
        --update [--yes]           installs the newer version: it asks first, unless --yes is given
        --version
        """;

    public static async Task<int> MainAsync(string[] args)
    {
        string? data = null;
        string? command = null;
        string? argument = null;
        var yes = false;
        for (var i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--data" when i + 1 < args.Length:
                    data = args[++i];
                    break;
                case "--unban" when i + 1 < args.Length:
                    command = args[i];
                    argument = args[++i];
                    break;
                case "--set-admin-password" or "--reset-admin" or "--fingerprint" or "--about" or "--update" or "--version" or "--install" or "--uninstall":
                    command = args[i];
                    break;
                case "--yes":
                    yes = true;
                    break;
                case "--help" or "-h" or "-?":
                    Console.WriteLine(Usage);
                    return 0;
                default:
                    Console.Error.WriteLine($"I don't know what {args[i]} means.\n\n{Usage}");
                    return 2;
            }
        }

        if (OperatingSystem.IsLinux() && !HasOpenSsl())
        {
            Console.Error.WriteLine("""
                This needs OpenSSL 3 (libssl.so.3), which .NET uses for TLS, and it isn't installed.
                Fedora 45 and later come with OpenSSL 4, which .NET can't use yet. Install OpenSSL 3 beside it:
                  sudo dnf install openssl3-libs
                Fedora's own ASP.NET Core (sudo dnf install aspnetcore-runtime-10.0) brings it with it.
                """);
            return 1;
        }

        switch (command)
        {
            case "--version":
                Console.WriteLine(Updater.RunningVersion.ToString(4));
                return 0;
            case "--about":
                return await AboutCommand.AboutAsync(yes);
            case "--update":
                return await AboutCommand.UpdateAsync(yes);
            case "--install":
                return Installer.Install(data, yes);
            case "--uninstall":
                return Installer.Uninstall(data, yes);
        }

        Updater.Tidy();
        var folder = data ?? DataFolder.Default();
        DataFolder.Prepare(folder);
        switch (command)
        {
            case "--fingerprint":
                var certificate = new TlsCertificates("", "", folder, "admin").Current();
                Console.WriteLine($"Admin port: SHA-256 {TlsCertificates.Fingerprint(certificate)}");
                return 0;
            case "--set-admin-password":
                return SetAdminPassword(folder);
            case "--reset-admin":
                return ResetAdmin(folder);
            case "--unban":
                return Unban(folder, argument!);
        }

        var config = ServerConfig.LoadOrCreate(folder);
        var app = ServerApp.Build(folder, config);
        app.State.LogLine = line => Console.WriteLine(line);
        await app.StartAsync();
        Console.WriteLine($"webdav-server {Updater.RunningVersion.ToString(4)}, data in {folder}");
        foreach (var address in app.DavAddresses) Console.WriteLine($"WebDAV and Nextcloud on {address}");
        Console.WriteLine($"Admin on {app.AdminAddress}, certificate SHA-256 {TlsCertificates.Fingerprint(app.AdminCertificate.Current())}");
        if (app.State.Database.LoadAdmin() is { MustChange: true })
            Console.WriteLine("The admin login is still the default, admin / admin. Connect with the admin window and change it now.");
        await app.WaitForShutdownAsync();
        await app.DisposeAsync();
        return 0;
    }

    private static int SetAdminPassword(string folder)
    {
        if (Console.IsInputRedirected)
        {
            Console.Error.WriteLine("This asks for the password, so it has to be run at a terminal.");
            return 1;
        }
        var state = new ServerState(folder);
        var first = ReadPassword("New admin password: ");
        if (Api.PasswordProblem(first) is { } problem)
        {
            Console.Error.WriteLine(problem);
            return 1;
        }
        if (first != ReadPassword("Again: "))
        {
            Console.Error.WriteLine("They weren't the same. Nothing was changed.");
            return 1;
        }
        var name = state.Database.LoadAdmin()?.Name ?? ServerState.DefaultAdminName;
        state.Database.SaveAdmin(name, Passwords.Hash(first), mustChange: false);
        state.Log("admin-password", null, name, Scopes.Admin, "The admin password was changed on the server.");
        Console.WriteLine($"Done. Log in as {name}.");
        return 0;
    }

    private static string ReadPassword(string prompt)
    {
        Console.Write(prompt);
        var password = new System.Text.StringBuilder();
        while (true)
        {
            var key = Console.ReadKey(intercept: true);
            if (key.Key == ConsoleKey.Enter) break;
            if (key.Key == ConsoleKey.Backspace)
            {
                if (password.Length > 0) password.Length--;
            }
            else if (!char.IsControl(key.KeyChar)) password.Append(key.KeyChar);
        }
        Console.WriteLine();
        return password.ToString();
    }

    private static int ResetAdmin(string folder)
    {
        var state = new ServerState(folder);
        state.Database.SaveAdmin(ServerState.DefaultAdminName, Passwords.Hash(ServerState.DefaultAdminPassword), mustChange: true);
        state.Database.SaveSettings(state.Database.LoadSettings() with { AdminWhitelist = [] });
        state.Database.DeleteBansOfScope(Scopes.Admin);
        state.Log("admin-password", null, ServerState.DefaultAdminName, Scopes.Admin, "The admin login was reset on the server.");
        Console.WriteLine("The admin login is back to admin / admin, and has to be changed the next time it's used. The admin whitelist and admin bans are gone.");
        return 0;
    }

    private static int Unban(string folder, string address)
    {
        if (!Networks.TryParse(address, out var network))
        {
            Console.Error.WriteLine($"{address} isn't an address or a network.");
            return 1;
        }
        var state = new ServerState(folder);
        var lifted = 0;
        foreach (var ban in state.Database.LoadBans())
        {
            if (Networks.TryParse(ban.Network, out var banned) && (banned.Contains(network.BaseAddress) || network.Contains(banned.BaseAddress)) && state.Database.DeleteBan(ban.Network, ban.Scope)) lifted++;
        }
        Console.WriteLine($"{lifted} ban{(lifted == 1 ? "" : "s")} lifted.");
        return 0;
    }

    /// <summary>Whether .NET will find an OpenSSL it can use. Without one, the first TLS connection or certificate doesn't
    /// throw: it stops the whole program, so this is asked before anything else.</summary>
    private static bool HasOpenSsl() =>
        Environment.GetEnvironmentVariable("CLR_OPENSSL_VERSION_OVERRIDE") is { Length: > 0 }
        || new[] { "libssl.so.3", "libssl.so.1.1" }.Any(name => System.Runtime.InteropServices.NativeLibrary.TryLoad(name, out _));
}
