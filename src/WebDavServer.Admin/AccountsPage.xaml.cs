using System.Windows;
using System.Windows.Controls;

namespace Strongthium.WebDavServer.AdminApp;

public sealed record AccountRow(AccountInfo Info)
{
    public string Name => Info.Name;
    public string DisplayName => Info.DisplayName;
    public string State => !Info.Enabled ? "Disabled" : Info.RequireAppPasswords ? "App passwords" : "Enabled";
    public string Paths => Info.Grants.Count == 0 ? "None" : string.Join(", ", Info.Grants.Select(grant => grant.Mount + (grant.ReadOnly ? " (read)" : "")));
    public string Whitelist => Info.Whitelist.Count == 0 ? "Anywhere" : string.Join(", ", Info.Whitelist);
    public string Quota => Sizes.Show(Info.QuotaBytes);
    public int AppPasswords => Info.AppPasswords.Count;
}

public static class Sizes
{
    /// <summary>Bytes as a person says them; 0 means no limit, everywhere here.</summary>
    public static string Show(long bytes)
    {
        if (bytes <= 0) return "None";
        string[] units = ["bytes", "KB", "MB", "GB", "TB", "PB"];
        double value = bytes;
        var unit = 0;
        while (value >= 1024 && unit < units.Length - 1)
        {
            value /= 1024;
            unit++;
        }
        return unit == 0 ? $"{bytes} bytes" : $"{value:0.##} {units[unit]}";
    }

    /// <summary>A number of gigabytes as typed, in bytes. Empty or 0 is no limit.</summary>
    public static bool TryParseGb(string text, out long bytes)
    {
        bytes = 0;
        text = text.Trim();
        if (text.Length == 0) return true;
        if (!double.TryParse(text, out var value) || value < 0 || value > 1e9) return false;
        bytes = (long)(value * 1024 * 1024 * 1024);
        return true;
    }

    public static string ToGb(long bytes) => bytes <= 0 ? "" : (bytes / (1024.0 * 1024 * 1024)).ToString("0.###");
}

public sealed partial class AccountsPage : UserControl
{
    public AccountsPage()
    {
        InitializeComponent();
        Loaded += async (_, _) => await RefreshAsync();
    }

    private async Task RefreshAsync()
    {
        try
        {
            var accounts = await Session.Client.GetAsync<List<AccountInfo>>("/api/accounts");
            List.ItemsSource = accounts.Select(account => new AccountRow(account)).ToList();
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

    private async Task EditAsync(AccountInfo? account)
    {
        try
        {
            var mounts = await Session.Client.GetAsync<List<MountInfo>>("/api/mounts");
            var dialog = new AccountDialog(account, mounts) { Owner = Window.GetWindow(this) };
            dialog.ShowDialog();
            await RefreshAsync();
        }
        catch (Exception exception) when (AdminClient.IsExpected(exception))
        {
            Show(exception);
        }
    }

    private async void Add_Click(object sender, RoutedEventArgs e) => await EditAsync(null);

    private async void Edit_Click(object sender, RoutedEventArgs e)
    {
        if (List.SelectedItem is AccountRow row) await EditAsync(row.Info);
    }

    private async void Delete_Click(object sender, RoutedEventArgs e)
    {
        if (List.SelectedItem is not AccountRow row) return;
        if (MessageBox.Show(Window.GetWindow(this), $"Delete {row.Name}? Nobody will be able to log in with it, and its app passwords go with it. Its files stay on the server.",
                "Delete the account", MessageBoxButton.YesNo, MessageBoxImage.Warning, MessageBoxResult.No) != MessageBoxResult.Yes) return;
        try
        {
            await Session.Client.DeleteAsync($"/api/accounts?name={AdminClient.Q(row.Name)}");
            await RefreshAsync();
        }
        catch (Exception exception) when (AdminClient.IsExpected(exception))
        {
            Show(exception);
        }
    }
}
