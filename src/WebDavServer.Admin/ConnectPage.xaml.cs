using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;

namespace Strongthium.WebDavServer.AdminApp;

/// <summary>Connects to a server, makes sure it's the right one, logs in, and if the password is still the default, doesn't let
/// anything else happen until it's changed.</summary>
public sealed partial class ConnectPage : UserControl
{
    public event Action? Connected;

    private readonly List<ServerProfile> profiles = Profiles.Load();

    public ConnectPage(string? message)
    {
        InitializeComponent();
        ServerBox.ItemsSource = profiles;
        if (Program.StartServer is { } start) ServerBox.Text = start;
        else if (profiles.Count > 0) ServerBox.SelectedIndex = 0;
        else
        {
            ServerBox.Text = "localhost";
            NameBox.Text = "admin";
        }
        if (message is not null) Show(message);
        Loaded += (_, _) => PasswordBox.Focus();
    }

    private void Show(string problem)
    {
        ProblemText.Text = problem;
        ProblemText.Visibility = problem.Length > 0 ? Visibility.Visible : Visibility.Collapsed;
    }

    private void Server_Changed(object sender, SelectionChangedEventArgs e)
    {
        if (ServerBox.SelectedItem is ServerProfile profile) NameBox.Text = profile.UserName;
    }

    private void Password_KeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Enter) Connect_Click(sender, e);
    }

    private static bool TryParseServer(string text, out string host, out int port)
    {
        text = text.Trim();
        host = text;
        port = 9443;
        if (text.Length == 0) return false;
        if (text.StartsWith('['))
        {
            var close = text.IndexOf(']');
            if (close < 0) return false;
            host = text[1..close];
            return close + 1 == text.Length || (text[close + 1] == ':' && int.TryParse(text.AsSpan(close + 2), out port));
        }
        if (text.Count(c => c == ':') == 1)
        {
            var colon = text.IndexOf(':');
            host = text[..colon];
            return int.TryParse(text.AsSpan(colon + 1), out port) && port is > 0 and < 65536;
        }
        return true;
    }

    private async void Connect_Click(object sender, RoutedEventArgs e)
    {
        Show("");
        if (!TryParseServer(ServerBox.Text, out var host, out var port))
        {
            Show("That isn't a server's name and port.");
            return;
        }
        var saved = profiles.FirstOrDefault(profile => profile.Host.Equals(host, StringComparison.OrdinalIgnoreCase) && profile.Port == port);
        var profile = new ServerProfile { Host = host, Port = port, UserName = NameBox.Text.Trim(), Fingerprint = saved?.Fingerprint };
        var password = PasswordBox.Password;

        ConnectButton.IsEnabled = false;
        Busy.Visibility = Visibility.Visible;
        try
        {
            while (true)
            {
                var client = new AdminClient(host, port, profile.Fingerprint);
                try
                {
                    var answer = await client.LoginAsync(profile.UserName, password);
                    if (answer.MustChangePassword)
                    {
                        var dialog = new ChangePasswordDialog(client, password, forced: true) { Owner = Window.GetWindow(this) };
                        if (dialog.ShowDialog() != true || dialog.Answer is null)
                        {
                            client.Dispose();
                            Show("The default password has to be changed before the server can be looked after.");
                            return;
                        }
                        answer = dialog.Answer;
                    }

                    PasswordBox.Clear();
                    profile = profile with { UserName = answer.UserName };
                    Profiles.Remember(profile);
                    Session.Client = client;
                    Session.UserName = answer.UserName;
                    Session.Profile = profile;
                    Connected?.Invoke();
                    return;
                }
                catch (UntrustedCertificateException certificate)
                {
                    client.Dispose();
                    if (!AskToTrust(profile, certificate)) return;
                    profile = profile with { Fingerprint = certificate.Presented };
                }
                catch (Exception exception) when (AdminClient.IsExpected(exception))
                {
                    client.Dispose();
                    Show(AdminClient.Explain(exception));
                    return;
                }
            }
        }
        finally
        {
            ConnectButton.IsEnabled = true;
            Busy.Visibility = Visibility.Collapsed;
        }
    }

    private bool AskToTrust(ServerProfile profile, UntrustedCertificateException certificate)
    {
        var shown = string.Join(' ', certificate.Presented.Chunk(8).Select(group => new string(group)));
        var owner = Window.GetWindow(this);
        if (certificate.Trusted is null)
        {
            return MessageBox.Show(owner,
                $"This is the first time you've connected to {profile}. To be sure it's your server and nobody in between, compare this with what the server shows when it starts, or with webdav-server --fingerprint on the server:\n\n{shown}\n\nDoes it match? Your password is only sent if you say yes.",
                "Is this your server?", MessageBoxButton.YesNo, MessageBoxImage.Question, MessageBoxResult.No) == MessageBoxResult.Yes;
        }
        return MessageBox.Show(owner,
            $"{profile} has a different certificate from the one you trusted. That happens if the server's data folder was replaced, and it also happens if someone is listening in between.\n\nTrusted before:\n{string.Join(' ', certificate.Trusted.Chunk(8).Select(group => new string(group)))}\n\nShown now:\n{shown}\n\nCompare with webdav-server --fingerprint on the server. Only trust it if you know why it changed.",
            "The server's certificate has changed", MessageBoxButton.YesNo, MessageBoxImage.Warning, MessageBoxResult.No) == MessageBoxResult.Yes;
    }
}
