using System.Windows;
using System.Windows.Controls;
using System.Windows.Threading;

namespace Strongthium.WebDavServer.AdminApp;

/// <summary>How the server is: read again every few seconds for as long as the page is showing.</summary>
public sealed partial class StatusPage : UserControl
{
    private readonly DispatcherTimer timer = new() { Interval = TimeSpan.FromSeconds(5) };

    public StatusPage()
    {
        InitializeComponent();
        timer.Tick += async (_, _) => await RefreshAsync();
        Loaded += async (_, _) =>
        {
            await RefreshAsync();
            timer.Start();
        };
        Unloaded += (_, _) => timer.Stop();
    }

    private async Task RefreshAsync()
    {
        try
        {
            if (Session.Client is null) return;
            Show(await Session.Client.GetAsync<StatusInfo>("/api/status"));
            ProblemText.Visibility = Visibility.Collapsed;
        }
        catch (Exception exception) when (AdminClient.IsExpected(exception))
        {
            ProblemText.Text = AdminClient.Explain(exception);
            ProblemText.Visibility = Visibility.Visible;
        }
    }

    private void Show(StatusInfo status)
    {
        Warnings.ItemsSource = status.Warnings;
        ConnectionsText.Text = status.OpenConnections.ToString("N0");
        ClosedText.Text = status.ClosedAtTheDoor.ToString("N0");
        BansText.Text = status.Bans.ToString("N0");
        AccountsText.Text = status.Accounts.ToString("N0");
        AccountsCaption.Text = $"accounts, on {status.Mounts} path{(status.Mounts == 1 ? "" : "s")}";

        ServerGrid.Children.Clear();
        ServerGrid.RowDefinitions.Clear();
        void Row(string name, string value, bool mono = false)
        {
            if (value.Length == 0) return;
            var row = ServerGrid.RowDefinitions.Count;
            ServerGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            var label = new TextBlock { Text = name, Margin = new Thickness(0, 3, 12, 3), Style = (Style)FindResource("Muted") };
            var text = new TextBox { Text = value, IsReadOnly = true, BorderThickness = new Thickness(0), Background = System.Windows.Media.Brushes.Transparent, Padding = new Thickness(0), MinHeight = 0, Margin = new Thickness(0, 3, 0, 3), TextWrapping = TextWrapping.Wrap };
            if (mono) text.FontFamily = new System.Windows.Media.FontFamily("Cascadia Mono, Consolas");
            Grid.SetRow(label, row);
            Grid.SetRow(text, row);
            Grid.SetColumn(text, 1);
            ServerGrid.Children.Add(label);
            ServerGrid.Children.Add(text);
        }
        Row("Version", status.Version);
        Row("System", status.System);
        Row("Started", status.Started.ToLocalTime().ToString("g"));
        Row("WebDAV and Nextcloud", string.Join("\n", status.DavAddresses));
        Row("Admin port", status.AdminAddress);
        Row("Data folder", status.DataFolder);
        Row("WebDAV certificate", status.CertificateSubject + (status.CertificateExpires is { } expires ? $", until {expires.ToLocalTime():d}" : ""));
        Row("Its key (SHA-256)", string.Join(' ', status.CertificateFingerprint.Chunk(8).Select(group => new string(group))), mono: true);
        Row("Countries and networks", status.GeoMonth.Length > 0 ? $"DB-IP, {status.GeoMonth}" : "Not downloaded");
        Row("Cloudflare's addresses", $"{status.CloudflareRanges} networks");
    }

    private void ChangePassword_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new ChangePasswordDialog(Session.Client, null, forced: false) { Owner = Window.GetWindow(this) };
        if (dialog.ShowDialog() == true && dialog.Answer is { } answer) Session.UserName = answer.UserName;
    }
}
