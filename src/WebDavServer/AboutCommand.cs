namespace Strongthium.WebDavServer;

/// <summary><c>--about</c> and <c>--update</c>: Strongthium, this program, and whether there's a newer version of it.</summary>
internal static class AboutCommand
{
    private const string Text = """
        Strongthium Labs makes small, focused software that does one job well, for the people who keep
        machines running. Everyone else is centralizing and harvesting data. We make software that runs on
        your own machines instead: your data and your keys never pass through us, and everything it does is
        shown, with the reason why.

        More from Strongthium, each with a free edition and no time limit:

          Strongthium Guard    a firewall for Linux servers     https://strongthium.com/linux-server-firewall
          Strongthium Mail     a mail server of your own        https://strongthium.com/self-hosted-mail-server
          Strongthium Chat     live chat you host yourself      https://strongthium.com/self-hosted-live-chat
          Strongthium Remote   an SSH client for Windows        https://strongthium.com/windows-ssh-client

        Website   https://strongthium.com
        Our tools https://github.com/strongthium
        Security  https://github.com/strongthium/.github/blob/main/SECURITY.md
        """;

    private static Updater NewUpdater()
    {
        var system = OperatingSystem.IsWindows() ? "win" : "linux";
        return new Updater(Updater.NewClient("webdav-server"), "strongthium/webdav-server",
            version => $"webdav-server-{version}-{system}-x64-needs-dotnet.zip",
            OperatingSystem.IsWindows() ? "webdav-server.exe" : "webdav-server");
    }

    public static async Task<int> AboutAsync(bool yes)
    {
        Console.WriteLine($"Strongthium WebDAV Server {Updater.RunningVersion.ToString(4)}");
        Console.WriteLine("Free and open source, under the MIT license: https://github.com/strongthium/webdav-server");
        Console.WriteLine();
        Console.WriteLine(Text);
        Console.WriteLine();
        return await CheckAsync(install: false, yes);
    }

    public static Task<int> UpdateAsync(bool yes) => CheckAsync(install: true, yes);

    /// <summary>Says whether there's a newer version; offers to install it when someone is there to answer.</summary>
    private static async Task<int> CheckAsync(bool install, bool yes)
    {
        var updater = NewUpdater();
        var running = Environment.ProcessPath ?? "";
        try
        {
            Console.WriteLine("Asking GitHub for the latest version...");
            var release = await updater.LatestAsync();
            var latest = release.Version.ToString(4);
            if (release.Version <= Updater.RunningVersion)
            {
                Console.WriteLine(release.Version == Updater.RunningVersion ? "You have the latest version." : $"This is newer than the latest release, {latest}.");
                return 0;
            }

            Console.WriteLine($"Version {latest} is out. You have {Updater.RunningVersion.ToString(4)}. What's new: {release.Page}");
            if (!yes)
            {
                if (Console.IsInputRedirected)
                {
                    if (install) Console.Error.WriteLine("--update asks before it changes anything; pass --yes when nobody is there to answer.");
                    return install ? 1 : 0;
                }
                Console.Write($"Update to {latest} now? It's checked against the release's checksums first. [y/N] ");
                if (!(Console.ReadLine() ?? "").Trim().StartsWith('y')) return 0;
            }
            await updater.InstallAsync(release, running);
            Console.WriteLine($"Updated to {latest}. Restart the server to run it.");
            return 0;
        }
        catch (Exception exception) when (Updater.IsExpected(exception))
        {
            Console.Error.WriteLine(Updater.Explain(exception, running));
            Console.Error.WriteLine($"The releases are at {updater.ReleasesPage}");
            return 1;
        }
    }
}
