using System.Windows;
using System.Windows.Controls;

namespace Strongthium.WebDavServer.AdminApp;

public sealed record LogRow(LogEntry Entry)
{
    public string When => Entry.Time.ToLocalTime().ToString("g");
    public string Kind => Entry.Kind;
    public string Address => Entry.Address;
    public string Account => Entry.Account;
    public string Scope => Entry.Scope;
    public string Message => Entry.Message;
}

public sealed partial class LogPage : UserControl
{
    private static readonly string[] Kinds = ["Everything", "login", "login-failed", "ban", "unban", "refused", "warning", "admin-login", "admin-password", "account", "app-password", "path", "settings"];
    private bool ready;

    public LogPage()
    {
        InitializeComponent();
        KindBox.ItemsSource = Kinds;
        KindBox.SelectedIndex = 0;
        ready = true;
        Loaded += async (_, _) => await RefreshAsync();
    }

    private async Task RefreshAsync()
    {
        try
        {
            var kind = KindBox.SelectedItem is string chosen && chosen != "Everything" ? $"&kind={AdminClient.Q(chosen)}" : "";
            var entries = await Session.Client.GetAsync<List<LogEntry>>($"/api/log?limit=1000{kind}");
            List.ItemsSource = entries.Select(entry => new LogRow(entry)).ToList();
            ProblemText.Visibility = Visibility.Collapsed;
        }
        catch (Exception exception) when (AdminClient.IsExpected(exception))
        {
            ProblemText.Text = AdminClient.Explain(exception);
            ProblemText.Visibility = Visibility.Visible;
        }
    }

    private async void Refresh_Click(object sender, RoutedEventArgs e) => await RefreshAsync();

    private async void Kind_Changed(object sender, SelectionChangedEventArgs e)
    {
        if (ready) await RefreshAsync();
    }
}
