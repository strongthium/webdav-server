using System.Windows;
using System.Windows.Controls;
using System.Windows.Media.Imaging;

namespace Strongthium.WebDavServer.AdminApp;

public partial class MainWindow : Window
{
    private readonly Dictionary<RadioButton, UserControl> pages = [];

    public MainWindow()
    {
        InitializeComponent();
        var icon = new BitmapImage(new Uri("pack://application:,,,/Assets/webdav-server-admin.png"));
        Logo.Source = icon;
        Icon = icon;
        ShowConnect(null);
    }

    /// <summary>Back to the page that connects, with whatever was open forgotten: the token, every page and what's on it.</summary>
    public void ShowConnect(string? message)
    {
        Session.Client?.Dispose();
        Session.Client = null!;
        pages.Clear();
        Nav.IsEnabled = false;
        foreach (var item in Nav.Children.OfType<RadioButton>()) item.IsChecked = false;
        ConnectedTo.Text = "";
        DisconnectButton.Visibility = Visibility.Collapsed;
        var connect = new ConnectPage(message);
        connect.Connected += OnConnected;
        Page.Content = connect;
    }

    private void OnConnected()
    {
        Session.Client.SessionEnded += () => Dispatcher.BeginInvoke(() => ShowConnect("The login has timed out, so you've been logged out. Log in again."));
        Nav.IsEnabled = true;
        ConnectedTo.Text = $"{Session.UserName} on {Session.Profile}";
        ConnectedTo.ToolTip = Session.Client.Address;
        DisconnectButton.Visibility = Visibility.Visible;
        StatusNav.IsChecked = true;
    }

    private void Nav_Checked(object sender, RoutedEventArgs e)
    {
        var item = (RadioButton)sender;
        if (!pages.TryGetValue(item, out var page))
        {
            page = item.Name switch
            {
                nameof(StatusNav) => new StatusPage(),
                nameof(AccountsNav) => new AccountsPage(),
                nameof(PathsNav) => new PathsPage(),
                nameof(AccessNav) => new AccessPage(),
                nameof(ProxyNav) => new ProxyPage(),
                nameof(BansNav) => new BansPage(),
                nameof(LogNav) => new LogPage(),
                _ => new AboutPage(),
            };
            pages[item] = page;
        }
        Page.Content = page;
    }

    private async void Disconnect_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            await Session.Client.PostAsync("/api/logout");
        }
        catch (Exception exception) when (AdminClient.IsExpected(exception))
        {
            // The server is out of reach, which ends the session just as well. Its token times out by itself.
        }
        ShowConnect(null);
    }
}
