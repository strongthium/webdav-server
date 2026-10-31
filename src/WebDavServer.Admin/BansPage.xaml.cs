using System.Windows;
using System.Windows.Controls;

namespace Strongthium.WebDavServer.AdminApp;

public sealed record BanRow(BanInfo Info)
{
    public string Network => Info.Network;
    public string Scope => BansPage.ShowScope(Info.Scope);
    public string Since => Info.Created.ToLocalTime().ToString("g");
    public string Until => Info.Until is { } until ? until.ToLocalTime().ToString("g") : "Never ends";
    public string Reason => Info.Reason;
}

public sealed partial class BansPage : UserControl
{
    public BansPage()
    {
        InitializeComponent();
        Loaded += async (_, _) => await RefreshAsync();
    }

    public static string ShowScope(string scope) => scope switch
    {
        "*" => "Everything",
        "admin" => "The admin port",
        "/" => "The server's address",
        _ => scope,
    };

    private void Problem(string text)
    {
        ProblemText.Text = text;
        ProblemText.Visibility = Visibility.Visible;
    }

    private async Task RefreshAsync()
    {
        try
        {
            var bans = await Session.Client.GetAsync<List<BanInfo>>("/api/bans");
            List.ItemsSource = bans.Select(ban => new BanRow(ban)).ToList();
            var mounts = await Session.Client.GetAsync<List<MountInfo>>("/api/mounts");
            var selected = ScopeBox.SelectedItem as string;
            ScopeBox.ItemsSource = new[] { "Everything", "The admin port" }.Concat(mounts.Select(mount => mount.Path)).ToList();
            ScopeBox.SelectedItem = selected ?? "Everything";
            ProblemText.Visibility = Visibility.Collapsed;
        }
        catch (Exception exception) when (AdminClient.IsExpected(exception))
        {
            Problem(AdminClient.Explain(exception));
        }
    }

    private async void Refresh_Click(object sender, RoutedEventArgs e) => await RefreshAsync();

    private async void Lift_Click(object sender, RoutedEventArgs e)
    {
        if (List.SelectedItem is not BanRow row) return;
        try
        {
            await Session.Client.DeleteAsync($"/api/bans?network={AdminClient.Q(row.Info.Network)}&scope={AdminClient.Q(row.Info.Scope)}");
            await RefreshAsync();
        }
        catch (Exception exception) when (AdminClient.IsExpected(exception))
        {
            Problem(AdminClient.Explain(exception));
        }
    }

    private async void Add_Click(object sender, RoutedEventArgs e)
    {
        ProblemText.Visibility = Visibility.Collapsed;
        var minutes = 0;
        if (MinutesBox.Text.Trim().Length > 0 && (!int.TryParse(MinutesBox.Text, out minutes) || minutes < 1))
        {
            Problem("The minutes have to be a whole number, or empty for a ban that never ends.");
            return;
        }
        var scope = (ScopeBox.SelectedItem as string) switch
        {
            "Everything" or null => "*",
            "The admin port" => "admin",
            var path => path,
        };
        try
        {
            await Session.Client.PostAsync("/api/bans", new BanWrite { Network = NetworkBox.Text.Trim(), Scope = scope, Minutes = minutes, Reason = ReasonBox.Text.Trim() });
            NetworkBox.Clear();
            ReasonBox.Clear();
            MinutesBox.Clear();
            await RefreshAsync();
        }
        catch (Exception exception) when (AdminClient.IsExpected(exception))
        {
            Problem(AdminClient.Explain(exception));
        }
    }
}
