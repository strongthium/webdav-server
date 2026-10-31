using System.Windows;

namespace Strongthium.WebDavServer.AdminApp;

public sealed partial class MountDialog : Window
{
    public MountDialog(MountInfo? mount)
    {
        InitializeComponent();
        var shown = mount ?? new MountInfo { Path = "/" };
        Title = mount is null ? "Add a path" : $"Change {mount.Path}";
        PathBox.Text = shown.Path;
        PathBox.IsReadOnly = mount is not null;
        ByUser.IsChecked = shown.Layout == StorageLayout.User;
        ByPath.IsChecked = shown.Layout == StorageLayout.Path;
        ByBoth.IsChecked = shown.Layout == StorageLayout.UserAndPath;
        RootBox.Text = shown.Root;
        FailuresBox.Text = shown.MaxFailures.ToString();
        WindowBox.Text = shown.FailureWindowMinutes.ToString();
        BanBox.Text = shown.BanMinutes.ToString();
        QuotaBox.Text = Sizes.ToGb(shown.QuotaBytes);
        EnabledBox.IsChecked = shown.Enabled;
        NextcloudBox.IsChecked = shown.Nextcloud;
    }

    private void Problem(string text)
    {
        ProblemText.Text = text;
        ProblemText.Visibility = Visibility.Visible;
    }

    private async void Save_Click(object sender, RoutedEventArgs e)
    {
        ProblemText.Visibility = Visibility.Collapsed;
        if (!int.TryParse(FailuresBox.Text, out var failures) || !int.TryParse(WindowBox.Text, out var window) || !int.TryParse(BanBox.Text, out var ban))
        {
            Problem("The number of failures and the minutes have to be whole numbers.");
            return;
        }
        if (!Sizes.TryParseGb(QuotaBox.Text, out var quota))
        {
            Problem("The quota has to be a number of gigabytes, or empty.");
            return;
        }
        var mount = new MountInfo
        {
            Path = PathBox.Text.Trim(),
            Layout = ByPath.IsChecked == true ? StorageLayout.Path : ByBoth.IsChecked == true ? StorageLayout.UserAndPath : StorageLayout.User,
            Root = RootBox.Text.Trim(),
            Enabled = EnabledBox.IsChecked == true,
            Nextcloud = NextcloudBox.IsChecked == true,
            MaxFailures = failures,
            FailureWindowMinutes = window,
            BanMinutes = ban,
            QuotaBytes = quota,
        };
        SaveButton.IsEnabled = false;
        try
        {
            await Session.Client.PutAsync("/api/mounts", mount);
            DialogResult = true;
        }
        catch (Exception exception) when (AdminClient.IsExpected(exception))
        {
            Problem(AdminClient.Explain(exception));
        }
        finally
        {
            SaveButton.IsEnabled = true;
        }
    }
}
