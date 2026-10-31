using System.Windows;
using System.Windows.Controls;

namespace Strongthium.WebDavServer.AdminApp;

public sealed partial class ProxyPage : UserControl
{
    private const string Nginx = """
        location / {
            proxy_pass http://127.0.0.1:8080;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
            proxy_http_version 1.1;
            proxy_set_header Connection "";
            proxy_request_buffering off;
            proxy_buffering off;
            client_max_body_size 0;
            proxy_read_timeout 1h;
            proxy_send_timeout 1h;
        }
        """;

    public ProxyPage()
    {
        InitializeComponent();
        NginxBox.Text = Nginx;
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
            ProxiesBox.Text = string.Join(Environment.NewLine, settings.TrustedProxies);
            RealIpBox.IsChecked = settings.ProxyUsesRealIp;
            ClearBox.IsChecked = settings.AllowClearFromProxies;
            CloudflareBox.IsChecked = settings.TrustCloudflare;
            RequireBox.IsChecked = settings.RequireProxy;
            PublicUrlBox.Text = settings.PublicUrl;
            await RefreshCloudflareAsync();
            ProblemText.Visibility = Visibility.Collapsed;
        }
        catch (Exception exception) when (AdminClient.IsExpected(exception))
        {
            Problem(AdminClient.Explain(exception));
        }
    }

    private async Task RefreshCloudflareAsync()
    {
        var status = await Session.Client.GetAsync<StatusInfo>("/api/status");
        CloudflareText.Text = $"Believes Cloudflare's headers from its {status.CloudflareRanges} published networks, and from nowhere else. The server keeps the list up to date from cloudflare.com while this is on.";
    }

    private async void Save_Click(object sender, RoutedEventArgs e)
    {
        ProblemText.Visibility = SavedText.Visibility = Visibility.Collapsed;
        SaveButton.IsEnabled = false;
        try
        {
            // Read again first, so that what's on the Access page, or what another admin has just saved, stays.
            var settings = await Session.Client.GetAsync<ServerSettings>("/api/settings");
            await Session.Client.PutAsync("/api/settings", settings with
            {
                TrustedProxies = [.. ProxiesBox.Text.Split('\n', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries)],
                ProxyUsesRealIp = RealIpBox.IsChecked == true,
                AllowClearFromProxies = ClearBox.IsChecked == true,
                TrustCloudflare = CloudflareBox.IsChecked == true,
                RequireProxy = RequireBox.IsChecked == true,
                PublicUrl = PublicUrlBox.Text.Trim(),
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

    private async void Cloudflare_Click(object sender, RoutedEventArgs e)
    {
        ProblemText.Visibility = Visibility.Collapsed;
        CloudflareButton.IsEnabled = false;
        try
        {
            await Session.Client.PostAsync("/api/cloudflare/update");
            await RefreshCloudflareAsync();
        }
        catch (Exception exception) when (AdminClient.IsExpected(exception))
        {
            Problem(AdminClient.Explain(exception));
        }
        finally
        {
            CloudflareButton.IsEnabled = true;
        }
    }
}
