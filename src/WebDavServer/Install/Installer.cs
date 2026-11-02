using System.ComponentModel;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;
using Strongthium.WebDavServer.Config;
using Strongthium.WebDavServer.Network;

namespace Strongthium.WebDavServer.Install;

/// <summary>
/// <c>--install</c> and <c>--uninstall</c>: the server as a service that starts with the machine, under systemd on Linux and
/// the service manager on Windows, with its settings file written from a few questions.
/// </summary>
public static partial class Installer
{
    public const string ServiceName = "webdav-server";
    private const string DisplayName = "Strongthium WebDAV Server";
    private const string AdminRuleName = DisplayName + " (admin)";

    private const string LinuxProgram = "/usr/local/bin/webdav-server";
    private const string LinuxUnit = "/etc/systemd/system/webdav-server.service";
    public const string LinuxDefaultData = "/var/lib/webdav-server";

    private static string WindowsFolder => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Strongthium", "webdav-server");
    private static string WindowsProgram => Path.Combine(WindowsFolder, "webdav-server.exe");

    /// <summary>The ports offered first: 443 is what clients expect, and the others are the ones the server has always used.</summary>
    private static readonly int[] DavPorts = [443, 8443];
    private static readonly int[] AdminPorts = [9443];

    /// <summary>Something that stops an install or uninstall, said in words.</summary>
    private sealed class Failed(string message) : Exception(message);

    public static int Install(string? data, bool yes)
    {
        if (Problem(install: true) is { } problem)
        {
            Console.Error.WriteLine(problem);
            return 1;
        }
        try
        {
            var ask = Asker(yes);
            if (OperatingSystem.IsWindows()) return InstallOnWindows(data, ask);
            if (OperatingSystem.IsLinux()) return InstallOnLinux(data, ask);
            return 1;
        }
        catch (Failed failed)
        {
            Console.Error.WriteLine(failed.Message);
            return 1;
        }
    }

    public static int Uninstall(string? data, bool yes)
    {
        if (Problem(install: false) is { } problem)
        {
            Console.Error.WriteLine(problem);
            return 1;
        }
        try
        {
            var ask = Asker(yes);
            if (OperatingSystem.IsWindows()) return UninstallOnWindows(data, ask);
            if (OperatingSystem.IsLinux()) return UninstallOnLinux(data, ask);
            return 1;
        }
        catch (Failed failed)
        {
            Console.Error.WriteLine(failed.Message);
            return 1;
        }
    }

    /// <summary>Why this can't be done from here, if it can't.</summary>
    private static string? Problem(bool install)
    {
        var what = install ? "--install" : "--uninstall";
        if (install && Path.GetFileNameWithoutExtension(Environment.ProcessPath) is null or "dotnet")
            return "--install copies the program that's running, so it has to be run from the downloaded program, not through dotnet.";
        if (!OperatingSystem.IsWindows() && !OperatingSystem.IsLinux()) return $"{what} is for Linux and Windows.";
        if (OperatingSystem.IsLinux() && !Directory.Exists("/run/systemd/system"))
            return $"{what} sets the server up as a systemd service, and this machine isn't running systemd. Use whatever starts services here instead, with deploy/webdav-server.service as a guide.";
        if (!Environment.IsPrivilegedProcess)
            return OperatingSystem.IsWindows() ? $"{what} has to be run from an administrator's prompt." : $"{what} has to be run as root: sudo webdav-server {what}";
        return null;
    }

    /// <summary>Asks at the terminal, or, with <c>--yes</c>, takes every suggestion without asking.</summary>
    private static Func<string, string?> Asker(bool yes) => question =>
    {
        Console.Write(question);
        if (yes)
        {
            Console.WriteLine();
            return null;
        }
        var answer = Console.ReadLine();
        if (answer is null) Console.WriteLine();
        return answer;
    };

    // ---- What's asked, the same on both systems ----

    /// <summary>The settings for a new install: a free port for WebDAV and one for the admin window, and a certificate, if
    /// there is one. An empty answer, or none at all, takes what's suggested. <paramref name="serviceCantRead"/> says why
    /// the service's account couldn't read a file, where it runs as an account of its own.</summary>
    public static ServerConfig Ask(Func<string, string?> ask, Action<string> say, Func<string, string?>? serviceCantRead = null)
    {
        var port = AskPort(ask, say, "Port for WebDAV and Nextcloud clients", FreePort(DavPorts), not: null);
        var adminPort = AskPort(ask, say, "Port for the admin window", FreePort(AdminPorts, not: port), not: port);

        say("");
        say("WebDAV needs a certificate, as PEM files, like Let's Encrypt's fullchain.pem and privkey.pem. Without one, a self-signed");
        say("one is made, and many clients won't connect to that, Windows Explorer among them. It can be added to webdav-server.json later.");
        while (true)
        {
            var certificate = Unquote(ask("Certificate file (Enter for a self-signed one): "));
            if (certificate.Length == 0)
                return new ServerConfig { Listen = [new ListenerConfig { Port = port }], Admin = new ListenerConfig { Port = adminPort } };
            certificate = Path.GetFullPath(certificate);
            var key = Unquote(ask("Its key file (Enter if the key is in the same file): "));
            if (key.Length > 0) key = Path.GetFullPath(key);

            var problem = CertificateProblem(certificate, key, out var described);
            foreach (var file in key.Length > 0 ? [certificate, key] : new[] { certificate })
                problem ??= serviceCantRead?.Invoke(file);
            if (problem is not null)
            {
                say(problem);
                continue;
            }
            say(described);
            return new ServerConfig { Listen = [new ListenerConfig { Port = port }], Admin = new ListenerConfig { Port = adminPort }, CertificateFile = certificate, KeyFile = key };
        }
    }

    private static int AskPort(Func<string, string?> ask, Action<string> say, string what, int suggested, int? not)
    {
        while (true)
        {
            var answer = ask($"{what} [{suggested}]: ")?.Trim();
            if (string.IsNullOrEmpty(answer)) return suggested;
            if (!int.TryParse(answer, out var port) || port is < 1 or > 65535) say("A port is a number from 1 to 65535.");
            else if (port == not) say("That's the WebDAV port. The admin window needs a port of its own.");
            else if (!IsFree(port)) say($"Something is already using port {port}.");
            else return port;
        }
    }

    private static bool Confirm(Func<string, string?> ask, string question, bool suggested)
    {
        var answer = ask($"{question} {(suggested ? "[Y/n]" : "[y/N]")} ")?.Trim();
        return string.IsNullOrEmpty(answer) ? suggested : answer.StartsWith('y') || answer.StartsWith('Y');
    }

    /// <summary>A path as typed or pasted: Windows' Copy as path puts quotes around it.</summary>
    private static string Unquote(string? answer) => (answer ?? "").Trim().Trim('"', '\'').Trim();

    /// <summary>The first of the ports that nothing is using, or failing those, the first free one after them.</summary>
    public static int FreePort(IReadOnlyList<int> preferred, int? not = null)
    {
        foreach (var port in preferred.Concat(Enumerable.Range(preferred[^1] + 1, 65535 - preferred[^1])))
            if (port != not && IsFree(port)) return port;
        throw new Failed("Every port is in use.");
    }

    /// <summary>Whether the server could listen on a port on every address, as it does unless told otherwise.</summary>
    public static bool IsFree(int port)
    {
        try
        {
            // IPv6 and IPv4 at once where there's IPv6, the way Kestrel listens.
            using var socket = new Socket(SocketType.Stream, ProtocolType.Tcp);
            // On Windows this also fails when something has the port on one address only.
            if (OperatingSystem.IsWindows()) socket.ExclusiveAddressUse = true;
            socket.Bind(new IPEndPoint(socket.AddressFamily == AddressFamily.InterNetworkV6 ? IPAddress.IPv6Any : IPAddress.Any, port));
            return true;
        }
        catch (SocketException)
        {
            return false;
        }
    }

    /// <summary>What's wrong with a certificate and key, or null, with what it is when nothing is.</summary>
    public static string? CertificateProblem(string certificate, string key, out string described)
    {
        described = "";
        if (!File.Exists(certificate)) return $"There's no file {certificate}.";
        if (key.Length > 0 && !File.Exists(key)) return $"There's no file {key}.";
        try
        {
            using var loaded = X509Certificate2.CreateFromPemFile(certificate, key.Length > 0 ? key : null);
            var name = loaded.GetNameInfo(X509NameType.DnsName, forIssuer: false);
            if (loaded.NotAfter < DateTime.Now) return $"That certificate, for {name}, ran out on {loaded.NotAfter:yyyy-MM-dd}.";
            described = $"That's a certificate for {name}, good until {loaded.NotAfter:yyyy-MM-dd}.";
            return null;
        }
        catch (Exception exception) when (exception is CryptographicException or ArgumentException)
        {
            // ArgumentException is a key that isn't the certificate's.
            return $"That isn't a PEM certificate with its key: {exception.Message}";
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return $"It can't be read: {exception.Message}";
        }
    }

    /// <summary>A data folder that can't be one: a whole drive would have its permissions taken away from everyone.</summary>
    private static void CheckDataFolder(string data)
    {
        if (Path.GetPathRoot(data) == data || Path.TrimEndingDirectorySeparator(Path.GetPathRoot(data) ?? "") == data)
            throw new Failed($"The data folder can't be {data} itself: it's made readable by the server alone. Give it a folder of its own.");
    }

    /// <summary>Waits for the admin port to answer, which it does once the server has started.</summary>
    private static bool Listening(ServerConfig config)
    {
        var address = config.Admin.Address is "*" or "" or "localhost" ? IPAddress.Loopback : IPAddress.Parse(config.Admin.Address);
        var until = DateTime.UtcNow.AddSeconds(20);
        while (DateTime.UtcNow < until)
        {
            try
            {
                using var client = new TcpClient(address.AddressFamily);
                client.ConnectAsync(address, config.Admin.Port).Wait(TimeSpan.FromSeconds(2));
                if (client.Connected) return true;
            }
            catch (AggregateException)
            {
                // Not yet.
            }
            Thread.Sleep(500);
        }
        return false;
    }

    private static void Done(string data, ServerConfig config, string fingerprint, string reach, string shutOut)
    {
        var host = Dns.GetHostName();
        var dav = config.Listen.Select(listener => $"{(listener.Tls ? "https" : "http")}://{host}{(listener.Port == 443 && listener.Tls ? "" : $":{listener.Port}")}");
        Console.WriteLine();
        Console.WriteLine("The server is installed and running, and starts with the machine.");
        Console.WriteLine($"  WebDAV and Nextcloud   {string.Join(", ", dav)}");
        Console.WriteLine($"  Admin window           {host}:{config.Admin.Port}");
        Console.WriteLine($"  Admin certificate      SHA-256 {fingerprint}");
        Console.WriteLine($"  Data and settings      {data}, with {ServerConfig.FileName}");
        Console.WriteLine();
        Console.WriteLine("Connect the admin window as admin / admin, check the certificate is the one above, and change the password. Until");
        Console.WriteLine("it's changed, that login only works from this machine and private networks.");
        Console.WriteLine(reach);
        Console.WriteLine(shutOut);
    }

    private static string AdminFingerprint(string data) => TlsCertificates.Fingerprint(new TlsCertificates("", "", data, "admin").Current());

    /// <summary>The settings already in the data folder, kept as they are, or new ones from asking.</summary>
    private static ServerConfig Settings(string data, Func<string, string?> ask, Func<string, string?>? serviceCantRead)
    {
        if (File.Exists(Path.Combine(data, ServerConfig.FileName)))
        {
            Console.WriteLine($"{data} already has a {ServerConfig.FileName}, which is kept as it is, with the accounts and files.");
            return ServerConfig.LoadOrCreate(data);
        }
        var config = Ask(ask, Console.WriteLine, serviceCantRead);
        config.Save(data);
        return config;
    }

    private static (int Code, string Output) Run(string file, params string[] arguments)
    {
        var start = new ProcessStartInfo(file) { RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false, CreateNoWindow = true };
        foreach (var argument in arguments) start.ArgumentList.Add(argument);
        return Run(start);
    }

    /// <summary>For Windows' own commands, which read their command line in ways of their own.</summary>
    private static (int Code, string Output) RunLine(string file, string arguments) =>
        Run(new ProcessStartInfo(file, arguments) { RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false, CreateNoWindow = true });

    private static (int Code, string Output) Run(ProcessStartInfo start)
    {
        try
        {
            using var process = Process.Start(start)!;
            var output = process.StandardOutput.ReadToEndAsync();
            var errors = process.StandardError.ReadToEndAsync();
            process.WaitForExit();
            return (process.ExitCode, (output.Result + errors.Result).Trim());
        }
        catch (Win32Exception exception)
        {
            return (-1, $"{start.FileName} couldn't be run: {exception.Message}");
        }
    }

    private static void Must((int Code, string Output) result, string what)
    {
        if (result.Code != 0) throw new Failed($"{what} failed: {result.Output}");
    }

    // ---- Linux, under systemd ----

    private const string Account = "webdav-server";

    /// <summary>The unit in deploy/webdav-server.service, as it is in the repository.</summary>
    public static string UnitTemplate()
    {
        using var stream = typeof(Installer).Assembly.GetManifestResourceStream("webdav-server.service")!;
        return new StreamReader(stream).ReadToEnd();
    }

    /// <summary>The unit to install: the one in deploy, for this data folder and these ports, keeping the folders and the
    /// low ports an admin had allowed in the one it replaces.</summary>
    public static string SystemdUnit(string template, string data, bool lowPort, string? dotnetRoot, IReadOnlyList<string> kept)
    {
        var defaultData = data == LinuxDefaultData;
        var lines = new List<string>
        {
            "# Written by webdav-server --install, and taken away by --uninstall. Installing again keeps the ReadWritePaths here.",
            "# To serve a folder outside the data folder, add it to ReadWritePaths, then: systemctl daemon-reload && systemctl restart webdav-server",
        };
        foreach (var line in template.ReplaceLineEndings("\n").TrimEnd().Split('\n').SkipWhile(line => line != "[Unit]"))
        {
            if (line.StartsWith("ExecStart=", StringComparison.Ordinal))
            {
                lines.Add(defaultData ? $"ExecStart={LinuxProgram}" : $"ExecStart={LinuxProgram} --data {data}");
                if (dotnetRoot is not null) lines.Add($"Environment=DOTNET_ROOT={dotnetRoot}");
            }
            else if (line.StartsWith("StateDirectory", StringComparison.Ordinal))
            {
                if (defaultData) lines.Add(line);
            }
            else if (line.StartsWith("WorkingDirectory=", StringComparison.Ordinal)) lines.Add($"WorkingDirectory={data}");
            else if (line.StartsWith("#AmbientCapabilities=", StringComparison.Ordinal))
                lines.Add(lowPort || kept.Any(old => old.StartsWith("AmbientCapabilities=", StringComparison.Ordinal)) ? line[1..] : line);
            else if (line.StartsWith("#ReadWritePaths=", StringComparison.Ordinal))
            {
                var paths = kept.Where(old => old.StartsWith("ReadWritePaths=", StringComparison.Ordinal)).ToList();
                if (!defaultData && !paths.Contains($"ReadWritePaths={data}")) paths.Insert(0, $"ReadWritePaths={data}");
                lines.AddRange(paths.Count > 0 ? paths : [line]);
            }
            else lines.Add(line);
        }
        return string.Join('\n', lines) + "\n";
    }

    /// <summary>Why the service couldn't use a path, if it couldn't: systemd hides home folders from it, and a unit file
    /// reads spaces, quotes and percent signs as something else.</summary>
    public static string? LinuxPathProblem(string path)
    {
        foreach (var hidden in new[] { "/home", "/root", "/run/user" })
            if (path == hidden || path.StartsWith(hidden + "/", StringComparison.Ordinal))
                return $"The service can't see {path}: home folders are hidden from it. Use a folder outside {hidden}.";
        if (path.Any(c => char.IsWhiteSpace(c) || c is '"' or '\'' or '\\' or '%'))
            return $"{path} has spaces, quotes or percent signs in it, which a systemd unit can't take. Use a path without them.";
        return null;
    }

    /// <summary>The .NET the server runs on, for the service to find the same one, whether or not it's where systemd looks.</summary>
    private static string? DotnetRoot()
    {
        // .../shared/Microsoft.NETCore.App/10.0.x/
        var root = Path.TrimEndingDirectorySeparator(Path.GetFullPath(Path.Combine(RuntimeEnvironment.GetRuntimeDirectory(), "..", "..", "..")));
        return Directory.Exists(Path.Combine(root, "host", "fxr")) ? root : null;
    }

    [SupportedOSPlatform("linux")]
    private static int InstallOnLinux(string? dataArgument, Func<string, string?> ask)
    {
        var data = Path.TrimEndingDirectorySeparator(Path.GetFullPath(dataArgument ?? LinuxDefaultData));
        CheckDataFolder(data);
        if (LinuxPathProblem(data) is { } dataProblem) throw new Failed(dataProblem);
        var dotnetRoot = DotnetRoot();
        if (dotnetRoot is not null && LinuxPathProblem(dotnetRoot) is not null)
            throw new Failed($".NET is in {dotnetRoot}, where the service can't reach it. Install the ASP.NET Core 10 Runtime for the whole machine first.");

        var kept = File.Exists(LinuxUnit)
            ? File.ReadAllLines(LinuxUnit).Where(line => line.StartsWith("ReadWritePaths=", StringComparison.Ordinal) || line.StartsWith("AmbientCapabilities=", StringComparison.Ordinal)).ToList()
            : [];
        if (File.Exists(LinuxUnit))
        {
            Console.WriteLine("Stopping the server that's installed already...");
            Run("systemctl", "stop", ServiceName);
        }

        if (Run("id", "-u", Account).Code != 0)
        {
            var shell = File.Exists("/usr/sbin/nologin") ? "/usr/sbin/nologin" : "/sbin/nologin";
            Must(Run("useradd", "--system", "--user-group", "--home-dir", data, "--shell", shell, Account), $"Making the account {Account}");
            Console.WriteLine($"Made the account {Account}, which the server runs as. It can touch nothing but its data.");
        }

        DataFolder.Prepare(data);
        var config = Settings(data, ask, ServiceCantRead);
        var fingerprint = AdminFingerprint(data);

        var running = Environment.ProcessPath!;
        if (running != LinuxProgram)
        {
            File.Copy(running, LinuxProgram + ".new", overwrite: true);
            File.SetUnixFileMode(LinuxProgram + ".new", UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute | UnixFileMode.GroupRead | UnixFileMode.GroupExecute | UnixFileMode.OtherRead | UnixFileMode.OtherExecute);
            File.Move(LinuxProgram + ".new", LinuxProgram, overwrite: true);
        }

        var lowPort = config.Listen.Any(listener => listener.Port < 1024) || config.Admin.Port < 1024;
        File.WriteAllText(LinuxUnit, SystemdUnit(UnitTemplate(), data, lowPort, dotnetRoot, kept));
        File.SetUnixFileMode(LinuxUnit, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead | UnixFileMode.OtherRead);
        Must(Run("chown", "-R", $"{Account}:{Account}", data), "Giving the data folder to the server's account");

        Must(Run("systemctl", "daemon-reload"), "systemctl daemon-reload");
        Must(Run("systemctl", "enable", ServiceName), "Setting the service to start with the machine");
        Must(Run("systemctl", "restart", ServiceName), "Starting the service");
        if (!Listening(config))
        {
            Console.Error.WriteLine("It's installed, but it didn't start. What it said:");
            Console.Error.WriteLine(Run("journalctl", "-u", ServiceName, "-n", "20", "--no-pager").Output);
            return 1;
        }

        var ports = config.Listen.Select(listener => listener.Port.ToString()).ToList();
        Done(data, config, fingerprint,
            $"If there's a firewall, open port {string.Join(", ", ports)}, and {config.Admin.Port} if the admin window is on another computer.",
            $"If you're ever shut out, stop the service and use the commands in webdav-server --help as its account: sudo -u {Account} -H webdav-server{(data == LinuxDefaultData ? "" : $" --data {data}")} --reset-admin");
        return 0;
    }

    /// <summary>Why the service's account can't read a file, if it can't.</summary>
    [SupportedOSPlatform("linux")]
    private static string? ServiceCantRead(string file)
    {
        if (LinuxPathProblem(file) is { } problem) return problem;
        // test says 1 for a file it can't read. Anything else is runuser itself, and not a reason to refuse the file.
        var (code, _) = Run("runuser", "-u", Account, "--", "test", "-r", file);
        return code != 1 ? null
            : $"The server runs as {Account}, which can't read {file}. Give it read access, or for Let's Encrypt, copy the files somewhere it can read in a deploy hook.";
    }

    [SupportedOSPlatform("linux")]
    private static int UninstallOnLinux(string? dataArgument, Func<string, string?> ask)
    {
        var installedData = File.Exists(LinuxUnit)
            ? File.ReadAllLines(LinuxUnit).Where(line => line.StartsWith("WorkingDirectory=", StringComparison.Ordinal)).Select(line => line["WorkingDirectory=".Length..]).FirstOrDefault()
            : null;
        var data = Path.TrimEndingDirectorySeparator(Path.GetFullPath(dataArgument ?? installedData ?? LinuxDefaultData));
        if (!File.Exists(LinuxUnit) && !File.Exists(LinuxProgram) && !Directory.Exists(data))
        {
            Console.WriteLine("It isn't installed.");
            return 0;
        }

        if (File.Exists(LinuxUnit))
        {
            Run("systemctl", "disable", "--now", ServiceName);
            File.Delete(LinuxUnit);
            Run("systemctl", "daemon-reload");
            Run("systemctl", "reset-failed", ServiceName);
            Console.WriteLine("Stopped the server, and took away its service.");
        }
        if (File.Exists(LinuxProgram))
        {
            File.Delete(LinuxProgram);
            Console.WriteLine($"Deleted {LinuxProgram}.");
        }

        if (DeleteData(data, ask) && Run("id", "-u", Account).Code == 0)
        {
            Must(Run("userdel", Account), $"Deleting the account {Account}");
            Console.WriteLine($"Deleted the account {Account}.");
        }
        else if (Directory.Exists(data)) Console.WriteLine($"The account {Account} is kept too, since it owns the data. Installing again picks both up as they are.");
        return 0;
    }

    /// <summary>Asks before deleting the data folder, and keeps it unless the answer is to delete it.</summary>
    private static bool DeleteData(string data, Func<string, string?> ask)
    {
        if (!Directory.Exists(data)) return false;
        Console.WriteLine();
        Console.WriteLine($"The data folder, {data}, is still there, with the settings, the accounts, the certificates and every file kept in it.");
        Console.WriteLine("Folders that paths keep elsewhere aren't in it, and aren't touched.");
        var answer = ask("Type delete to delete it as well, which can't be undone, or press Enter to keep it: ")?.Trim();
        if (answer != "delete")
        {
            Console.WriteLine($"Kept {data}.");
            return false;
        }
        Directory.Delete(data, recursive: true);
        Console.WriteLine($"Deleted {data}.");
        return true;
    }

    // ---- Windows, as a service ----

    [GeneratedRegex("--data \"([^\"]+)\"")]
    private static partial Regex DataInCommandLine();

    [SupportedOSPlatform("windows")]
    private static System.ServiceProcess.ServiceController? InstalledService() =>
        System.ServiceProcess.ServiceController.GetServices().FirstOrDefault(service => service.ServiceName.Equals(ServiceName, StringComparison.OrdinalIgnoreCase));

    [SupportedOSPlatform("windows")]
    private static void Stop(System.ServiceProcess.ServiceController service)
    {
        service.Refresh();
        if (service.Status == System.ServiceProcess.ServiceControllerStatus.Stopped) return;
        try
        {
            service.Stop();
            service.WaitForStatus(System.ServiceProcess.ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(30));
        }
        catch (Exception exception) when (exception is InvalidOperationException or System.ServiceProcess.TimeoutException)
        {
            throw new Failed($"The server that's installed wouldn't stop: {exception.Message}");
        }
    }

    [SupportedOSPlatform("windows")]
    private static int InstallOnWindows(string? dataArgument, Func<string, string?> ask)
    {
        var data = Path.TrimEndingDirectorySeparator(Path.GetFullPath(dataArgument ?? DataFolder.Default()));
        CheckDataFolder(data);
        var defaultData = data.Equals(DataFolder.Default(), StringComparison.OrdinalIgnoreCase);

        var existing = InstalledService();
        if (existing is not null)
        {
            Console.WriteLine("Stopping the server that's installed already...");
            Stop(existing);
        }

        DataFolder.Prepare(data);
        var config = Settings(data, ask, serviceCantRead: null);
        var fingerprint = AdminFingerprint(data);

        var running = Environment.ProcessPath!;
        if (!running.Equals(WindowsProgram, StringComparison.OrdinalIgnoreCase))
        {
            Directory.CreateDirectory(WindowsFolder);
            File.Copy(running, WindowsProgram, overwrite: true);
        }

        // sc.exe reads \" as a quote inside a quoted value, and the paths have no backslash at the end to get in the way.
        var commandLine = defaultData ? $"\"{WindowsProgram}\"" : $"\"{WindowsProgram}\" --data \"{data}\"";
        var verb = existing is null ? "create" : "config";
        Must(RunLine("sc.exe", $"{verb} {ServiceName} binPath= \"{commandLine.Replace("\"", "\\\"")}\" start= auto DisplayName= \"{DisplayName}\""), "Setting up the service");
        RunLine("sc.exe", $"description {ServiceName} \"WebDAV and Nextcloud file server. https://github.com/strongthium/webdav-server\"");
        RunLine("sc.exe", $"failure {ServiceName} reset= 86400 actions= restart/5000/restart/5000/restart/60000");

        var ports = string.Join(",", config.Listen.Select(listener => listener.Port));
        RunLine("netsh", $"advfirewall firewall delete rule name=\"{DisplayName}\"");
        RunLine("netsh", $"advfirewall firewall delete rule name=\"{AdminRuleName}\"");
        var reach = new List<string>();
        if (Confirm(ask, $"Let other computers reach WebDAV, on port {ports}, through Windows Firewall?", suggested: true))
            Must(RunLine("netsh", $"advfirewall firewall add rule name=\"{DisplayName}\" dir=in action=allow protocol=TCP localport={ports} program=\"{WindowsProgram}\" profile=any"), "Opening the WebDAV port");
        else reach.Add($"Windows Firewall wasn't asked to let other computers reach port {ports}.");
        if (Confirm(ask, $"And the admin port, {config.Admin.Port}, for the admin window on another computer?", suggested: false))
            Must(RunLine("netsh", $"advfirewall firewall add rule name=\"{AdminRuleName}\" dir=in action=allow protocol=TCP localport={config.Admin.Port} program=\"{WindowsProgram}\" profile=any"), "Opening the admin port");
        else reach.Add($"The admin port, {config.Admin.Port}, can only be reached from this computer, unless another firewall rule allows it.");

        using var service = InstalledService() ?? throw new Failed("The service was set up, but Windows doesn't list it.");
        try
        {
            service.Start();
            service.WaitForStatus(System.ServiceProcess.ServiceControllerStatus.Running, TimeSpan.FromSeconds(30));
        }
        catch (Exception exception) when (exception is InvalidOperationException or System.ServiceProcess.TimeoutException)
        {
            // Said below.
        }
        if (!Listening(config))
        {
            Console.Error.WriteLine("It's installed, but it didn't start. To see why, run it by hand, from an administrator's prompt:");
            Console.Error.WriteLine($"  sc.exe stop {ServiceName}");
            Console.Error.WriteLine($"  {commandLine}");
            return 1;
        }

        Done(data, config, fingerprint, string.Join(" ", reach),
            $"If you're ever shut out, stop the service (sc.exe stop {ServiceName}) and use the commands in --help, from an administrator's prompt: {commandLine} --reset-admin");
        return 0;
    }

    [SupportedOSPlatform("windows")]
    private static int UninstallOnWindows(string? dataArgument, Func<string, string?> ask)
    {
        using var service = InstalledService();
        string? installedData = null;
        if (service is not null)
        {
            using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey($@"SYSTEM\CurrentControlSet\Services\{ServiceName}");
            if (key?.GetValue("ImagePath") is string commandLine && DataInCommandLine().Match(commandLine) is { Success: true } match)
                installedData = match.Groups[1].Value;
        }
        var data = Path.TrimEndingDirectorySeparator(Path.GetFullPath(dataArgument ?? installedData ?? DataFolder.Default()));
        if (service is null && !Directory.Exists(WindowsFolder) && !Directory.Exists(data))
        {
            Console.WriteLine("It isn't installed.");
            return 0;
        }

        if (service is not null)
        {
            Stop(service);
            Must(RunLine("sc.exe", $"delete {ServiceName}"), "Taking away the service");
            Console.WriteLine("Stopped the server, and took away its service.");
        }
        // netsh says no when there's no rule of that name.
        var davRule = RunLine("netsh", $"advfirewall firewall delete rule name=\"{DisplayName}\"").Code == 0;
        var adminRule = RunLine("netsh", $"advfirewall firewall delete rule name=\"{AdminRuleName}\"").Code == 0;
        if (davRule || adminRule) Console.WriteLine("Took away its Windows Firewall rules.");

        if (Directory.Exists(WindowsFolder))
        {
            var parent = Path.GetDirectoryName(WindowsFolder)!;
            if (Path.GetDirectoryName(Environment.ProcessPath)!.Equals(WindowsFolder, StringComparison.OrdinalIgnoreCase))
            {
                // A running program can't be deleted, so a command that outlives it deletes the folder a few seconds after it quits.
                Process.Start(new ProcessStartInfo("cmd.exe", $"/c ping -n 4 127.0.0.1 >nul & rmdir /s /q \"{WindowsFolder}\" & rmdir \"{parent}\" 2>nul") { UseShellExecute = false, CreateNoWindow = true });
                Console.WriteLine($"{WindowsFolder} is deleted a few seconds after this has finished.");
            }
            else
            {
                Directory.Delete(WindowsFolder, recursive: true);
                DeleteIfEmpty(parent);
                Console.WriteLine($"Deleted {WindowsFolder}.");
            }
        }

        if (DeleteData(data, ask) && Path.GetDirectoryName(data) is { } dataParent && Path.GetFileName(dataParent) == "Strongthium") DeleteIfEmpty(dataParent);
        return 0;
    }

    private static void DeleteIfEmpty(string folder)
    {
        try
        {
            if (Directory.Exists(folder) && !Directory.EnumerateFileSystemEntries(folder).Any()) Directory.Delete(folder);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            // Something else is using it.
        }
    }
}
