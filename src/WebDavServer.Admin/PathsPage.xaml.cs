using System.Windows;
using System.Windows.Controls;

namespace Strongthium.WebDavServer.AdminApp;

public sealed record MountRow(MountInfo Info)
{
    public string Path => Info.Path;
    public string Layout => Layouts.Describe(Info.Layout);
    public string Folder => Info.Root.Length > 0 ? Info.Root : "The data folder";
    public string State => Info.Enabled ? "Enabled" : "Disabled";
    public string Nextcloud => Info.Nextcloud ? "Yes" : "No";
    public string Rule => Info.MaxFailures == 0 ? "Never bans" : $"{Info.MaxFailures} in {Durations.Show(Info.FailureWindowMinutes)}, for {Durations.Show(Info.BanMinutes)}";
}

public static class Durations
{
    /// <summary>A number of minutes as a person says it.</summary>
    public static string Show(int minutes)
    {
        if (minutes % (7 * 24 * 60) == 0) return Plural(minutes / (7 * 24 * 60), "week");
        if (minutes % (24 * 60) == 0) return Plural(minutes / (24 * 60), "day");
        if (minutes % 60 == 0) return Plural(minutes / 60, "hour");
        return Plural(minutes, "minute");
    }

    private static string Plural(int count, string unit) => count == 1 ? $"1 {unit}" : $"{count} {unit}s";
}

public sealed partial class PathsPage : UserControl
{
    public PathsPage()
    {
        InitializeComponent();
        Loaded += async (_, _) => await RefreshAsync();
    }

    private async Task RefreshAsync()
    {
        try
        {
            var mounts = await Session.Client.GetAsync<List<MountInfo>>("/api/mounts");
            List.ItemsSource = mounts.Select(mount => new MountRow(mount)).ToList();
            ProblemText.Visibility = Visibility.Collapsed;
        }
        catch (Exception exception) when (AdminClient.IsExpected(exception))
        {
            Show(exception);
        }
    }

    private void Show(Exception exception)
    {
        ProblemText.Text = AdminClient.Explain(exception);
        ProblemText.Visibility = Visibility.Visible;
    }

    private async void Add_Click(object sender, RoutedEventArgs e)
    {
        new MountDialog(null) { Owner = Window.GetWindow(this) }.ShowDialog();
        await RefreshAsync();
    }

    private async void Edit_Click(object sender, RoutedEventArgs e)
    {
        if (List.SelectedItem is not MountRow row) return;
        new MountDialog(row.Info) { Owner = Window.GetWindow(this) }.ShowDialog();
        await RefreshAsync();
    }

    private async void Delete_Click(object sender, RoutedEventArgs e)
    {
        if (List.SelectedItem is not MountRow row) return;
        if (MessageBox.Show(Window.GetWindow(this), $"Delete {row.Path}? Clients won't be able to connect to it any more. Its files stay on the server.",
                "Delete the path", MessageBoxButton.YesNo, MessageBoxImage.Warning, MessageBoxResult.No) != MessageBoxResult.Yes) return;
        try
        {
            await Session.Client.DeleteAsync($"/api/mounts?path={AdminClient.Q(row.Path)}");
            await RefreshAsync();
        }
        catch (Exception exception) when (AdminClient.IsExpected(exception))
        {
            Show(exception);
        }
    }
}
