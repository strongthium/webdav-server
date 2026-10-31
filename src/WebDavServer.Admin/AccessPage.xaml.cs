using System.Windows;
using System.Windows.Controls;

namespace Strongthium.WebDavServer.AdminApp;

public sealed partial class AccessPage : UserControl
{
    public AccessPage()
    {
        InitializeComponent();
        Loaded += async (_, _) => await RefreshAsync();
    }

    private void Problem(string text)
    {
        ProblemText.Text = text;
        ProblemText.Visibility = Visibility.Visible;
    }

    private async Task RefreshAsync()
    {
        try
        {
            var settings = await Session.Client.GetAsync<ServerSettings>("/api/settings");
            WhitelistBox.Text = string.Join(Environment.NewLine, settings.Whitelist);
            WhitelistBanBox.Text = settings.WhitelistBanMinutes.ToString();
            FailuresBox.Text = settings.MaxFailures.ToString();
            WindowBox.Text = settings.FailureWindowMinutes.ToString();
            BanBox.Text = settings.BanMinutes.ToString();
            AcrossBox.Text = settings.MaxFailuresAllPaths.ToString();
            PrefixBox.Text = settings.BanPrefixV6.ToString();
            UploadBox.Text = Sizes.ToGb(settings.MaxUploadBytes);
            AdminWhitelistBox.Text = string.Join(Environment.NewLine, settings.AdminWhitelist);
            AdminFailuresBox.Text = settings.AdminMaxFailures.ToString();
            AdminWindowBox.Text = settings.AdminFailureWindowMinutes.ToString();
            AdminBanBox.Text = settings.AdminBanMinutes.ToString();
            GeoAutoBox.IsChecked = settings.GeoAutoUpdate;
            await RefreshGeoAsync();
            ProblemText.Visibility = Visibility.Collapsed;
        }
        catch (Exception exception) when (AdminClient.IsExpected(exception))
        {
            Problem(AdminClient.Explain(exception));
        }
    }

    private async Task RefreshGeoAsync()
    {
        var status = await Session.Client.GetAsync<StatusInfo>("/api/status");
        GeoText.Text = status.GeoMonth.Length > 0 ? $"The server has DB-IP's files for {status.GeoMonth}." : "The server hasn't got DB-IP's files.";
    }

    private static List<string> Rules(TextBox box) => [.. box.Text.Split('\n', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries)];

    private async void Save_Click(object sender, RoutedEventArgs e)
    {
        ProblemText.Visibility = SavedText.Visibility = Visibility.Collapsed;
        var whitelist = Rules(WhitelistBox);
        var adminWhitelist = Rules(AdminWhitelistBox);
        if (whitelist.Concat(adminWhitelist).Select(AccessList.Problem).FirstOrDefault(problem => problem is not null) is { } ruleProblem)
        {
            Problem(ruleProblem);
            return;
        }
        if (!int.TryParse(WhitelistBanBox.Text, out var whitelistBan) || !int.TryParse(FailuresBox.Text, out var failures) || !int.TryParse(WindowBox.Text, out var window)
            || !int.TryParse(BanBox.Text, out var ban) || !int.TryParse(PrefixBox.Text, out var prefix) || !int.TryParse(AdminFailuresBox.Text, out var adminFailures)
            || !int.TryParse(AdminWindowBox.Text, out var adminWindow) || !int.TryParse(AdminBanBox.Text, out var adminBan) || !int.TryParse(AcrossBox.Text, out var across))
        {
            Problem("The numbers have to be whole numbers.");
            return;
        }
        if (!Sizes.TryParseGb(UploadBox.Text, out var upload))
        {
            Problem("The largest upload has to be a number of gigabytes, or empty.");
            return;
        }

        SaveButton.IsEnabled = false;
        try
        {
            // Read again first, so that what's on the Proxy page, or what another admin has just saved, stays.
            var settings = await Session.Client.GetAsync<ServerSettings>("/api/settings");
            await Session.Client.PutAsync("/api/settings", settings with
            {
                Whitelist = whitelist,
                WhitelistBanMinutes = whitelistBan,
                MaxFailures = failures,
                FailureWindowMinutes = window,
                BanMinutes = ban,
                MaxFailuresAllPaths = across,
                BanPrefixV6 = prefix,
                MaxUploadBytes = upload,
                AdminWhitelist = adminWhitelist,
                AdminMaxFailures = adminFailures,
                AdminFailureWindowMinutes = adminWindow,
                AdminBanMinutes = adminBan,
                GeoAutoUpdate = GeoAutoBox.IsChecked == true,
            });
            SavedText.Visibility = Visibility.Visible;
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

    private async void Geo_Click(object sender, RoutedEventArgs e)
    {
        ProblemText.Visibility = Visibility.Collapsed;
        GeoButton.IsEnabled = false;
        GeoBusy.Visibility = Visibility.Visible;
        try
        {
            await Session.Client.PostAsync("/api/geo/update");
            await RefreshGeoAsync();
        }
        catch (Exception exception) when (AdminClient.IsExpected(exception))
        {
            Problem(AdminClient.Explain(exception));
        }
        finally
        {
            GeoButton.IsEnabled = true;
            GeoBusy.Visibility = Visibility.Collapsed;
        }
    }
}
