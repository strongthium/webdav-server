using System.Windows;

namespace Strongthium.WebDavServer.AdminApp;

/// <summary>The command line: <c>--theme light|dark</c> sets the look rather than following Windows, and
/// <c>--server host[:port]</c> fills in the server to connect to.</summary>
internal static class Program
{
    public static string? StartServer { get; private set; }

    [STAThread]
    private static int Main(string[] args)
    {
        string? theme = null;
        int? waitFor = null;
        for (var i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--theme" when i + 1 < args.Length: theme = args[++i]; break;
                case "--server" when i + 1 < args.Length: StartServer = args[++i]; break;
                case "--wait-for" when i + 1 < args.Length && int.TryParse(args[i + 1], out var process):
                    waitFor = process;
                    i++;
                    break;
            }
        }
        Updater.Tidy(waitFor);

        var app = new App();
        app.InitializeComponent();
#pragma warning disable WPF0001
        if (theme == "dark") app.ThemeMode = ThemeMode.Dark;
        else if (theme == "light") app.ThemeMode = ThemeMode.Light;
#pragma warning restore WPF0001
        return app.Run();
    }
}
