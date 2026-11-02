using System.Diagnostics;
using System.Net;
using System.Text.RegularExpressions;
using Strongthium.WebDavServer.Config;
using Strongthium.WebDavServer.Security;

namespace Strongthium.WebDavServer.Tests;

/// <summary>The program itself, started the way a person or systemd starts it, rather than put together inside a test.</summary>
public sealed partial class ProgramTests : IDisposable
{
    private readonly string folder = Directory.CreateTempSubdirectory("webdav-server-program-").FullName;

    public void Dispose()
    {
        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
        for (var tries = 0; tries < 20; tries++)
        {
            try
            {
                Directory.Delete(folder, recursive: true);
                return;
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
            {
                Thread.Sleep(100);
            }
        }
    }

    private static ProcessStartInfo Start(params string[] arguments)
    {
        var start = new ProcessStartInfo("dotnet") { RedirectStandardOutput = true, RedirectStandardError = true, RedirectStandardInput = true, UseShellExecute = false };
        start.ArgumentList.Add(Path.Combine(AppContext.BaseDirectory, "webdav-server.dll"));
        foreach (var argument in arguments) start.ArgumentList.Add(argument);
        return start;
    }

    /// <summary>Runs a command to its end.</summary>
    private static async Task<(int Code, string Output)> RunAsync(params string[] arguments)
    {
        using var process = Process.Start(Start(arguments))!;
        process.StandardInput.Close();
        var output = process.StandardOutput.ReadToEndAsync();
        var errors = process.StandardError.ReadToEndAsync();
        await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(60));
        return (process.ExitCode, await output + await errors);
    }

    [GeneratedRegex(@"WebDAV and Nextcloud on (http://\S+)")]
    private static partial Regex DavLine();

    [Fact]
    public async Task ItStartsAndKeepsRunning()
    {
        File.WriteAllText(Path.Combine(folder, ServerConfig.FileName), """{ "listen": [{ "address": "127.0.0.1", "port": 0, "tls": false }], "admin": { "address": "127.0.0.1", "port": 0 } }""");
        using var process = Process.Start(Start("--data", folder))!;
        try
        {
            var lines = new List<string>();
            string? url = null;
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(60));
            while (!timeout.IsCancellationRequested)
            {
                var line = await process.StandardOutput.ReadLineAsync(timeout.Token);
                if (line is null) break;
                lines.Add(line);
                if (DavLine().Match(line) is { Success: true } match) url = match.Groups[1].Value;
                if (line.StartsWith("Admin on", StringComparison.Ordinal)) break;
            }
            Assert.NotNull(url);
            Assert.Contains(lines, line => line.Contains("certificate SHA-256"));

            // A while later it's still there: the program mustn't start, and then stop.
            await Task.Delay(1500);
            Assert.False(process.HasExited, "The server stopped by itself.");
            using var http = new HttpClient(new SocketsHttpHandler { UseProxy = false });
            using var status = await http.GetAsync(url + "/status.php");
            Assert.Equal(HttpStatusCode.OK, status.StatusCode);
        }
        finally
        {
            process.Kill(entireProcessTree: true);
            await process.WaitForExitAsync();
        }
    }

    [Fact]
    public async Task TheCommandsForWhenYouCantGetIn()
    {
        // The state a locked-out admin would be in: a changed password, a whitelist that shuts them out, and bans.
        {
            var state = new ServerState(folder);
            state.Database.SaveAdmin("boss", Passwords.Hash("a much better password"), mustChange: false);
            state.Database.SaveSettings(state.Database.LoadSettings() with { AdminWhitelist = ["203.0.113.1"] });
            var now = DateTimeOffset.UtcNow;
            state.Database.SaveBan(new BanInfo { Network = "198.51.100.1", Scope = "*", Reason = "x", Created = now, Until = now.AddDays(1) });
            state.Database.SaveBan(new BanInfo { Network = "198.51.100.1", Scope = "/dav", Reason = "x", Created = now, Until = now.AddDays(1) });
            state.Database.SaveBan(new BanInfo { Network = "198.51.100.2", Scope = "*", Reason = "x", Created = now, Until = now.AddDays(1) });
            state.Database.SaveBan(new BanInfo { Network = "198.51.100.3", Scope = "admin", Reason = "x", Created = now, Until = now.AddDays(1) });
        }

        var (code, output) = await RunAsync("--data", folder, "--unban", "198.51.100.1");
        Assert.Equal(0, code);
        Assert.Contains("2 bans lifted", output);

        (code, output) = await RunAsync("--data", folder, "--reset-admin");
        Assert.Equal(0, code);
        Assert.Contains("admin / admin", output);

        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
        var after = new ServerState(folder);
        var admin = after.Database.LoadAdmin()!;
        Assert.Equal("admin", admin.Name);
        Assert.True(admin.MustChange);
        Assert.True(Passwords.Verify("admin", admin.PasswordHash));
        Assert.Empty(after.Database.LoadSettings().AdminWhitelist);
        Assert.Equal("198.51.100.2", Assert.Single(after.Database.LoadBans()).Network);

        (code, output) = await RunAsync("--data", folder, "--fingerprint");
        Assert.Equal(0, code);
        Assert.Matches("SHA-256 [0-9A-F]{64}", output);

        (code, _) = await RunAsync("--data", folder, "--unban", "not an address");
        Assert.NotEqual(0, code);
    }

    [Fact]
    public async Task SettingAPasswordNeedsSomeoneThere()
    {
        var (code, output) = await RunAsync("--data", folder, "--set-admin-password");
        Assert.NotEqual(0, code);
        Assert.Contains("terminal", output);
    }

    [Fact]
    public async Task ItSaysWhatItWontDo()
    {
        var (code, output) = await RunAsync("--nonsense");
        Assert.Equal(2, code);
        Assert.Contains("--data", output);
        (code, output) = await RunAsync("--version");
        Assert.Equal(0, code);
        Assert.Matches(@"\d+\.\d+\.\d+", output);
    }

    [Fact]
    public async Task ItInstallsOnlyFromTheProgramItself()
    {
        // Run through dotnet, as here, there's no program of its own to copy, so it stops before it changes anything.
        var (code, output) = await RunAsync("--data", folder, "--install", "--yes");
        Assert.Equal(1, code);
        Assert.Contains("downloaded program", output);
        Assert.Empty(Directory.EnumerateFileSystemEntries(folder));
    }

    [Fact]
    public void TheDataFolderIsOnlyForTheServer()
    {
        var data = Path.Combine(folder, "data");
        DataFolder.Prepare(data);
        if (OperatingSystem.IsWindows())
        {
            var rules = new DirectoryInfo(data).GetAccessControl().GetAccessRules(true, true, typeof(System.Security.Principal.SecurityIdentifier));
            var users = new System.Security.Principal.SecurityIdentifier(System.Security.Principal.WellKnownSidType.BuiltinUsersSid, null);
            var everyone = new System.Security.Principal.SecurityIdentifier(System.Security.Principal.WellKnownSidType.WorldSid, null);
            foreach (System.Security.AccessControl.FileSystemAccessRule rule in rules)
            {
                Assert.NotEqual(users, rule.IdentityReference);
                Assert.NotEqual(everyone, rule.IdentityReference);
            }
        }
        else
        {
            Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute, File.GetUnixFileMode(data));
        }
    }
}
