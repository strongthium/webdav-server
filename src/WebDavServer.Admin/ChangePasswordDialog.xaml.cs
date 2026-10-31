using System.Windows;

namespace Strongthium.WebDavServer.AdminApp;

public sealed partial class ChangePasswordDialog : Window
{
    private readonly AdminClient client;
    private readonly string? current;

    public LoginResponse? Answer { get; private set; }

    /// <param name="client">The connection, logged in.</param>
    /// <param name="current">The password that was just typed, when this comes right after logging in.</param>
    /// <param name="forced">It's still the default, and nothing else is allowed until it's changed.</param>
    public ChangePasswordDialog(AdminClient client, string? current, bool forced)
    {
        InitializeComponent();
        this.client = client;
        this.current = current;
        if (current is not null) CurrentPanel.Visibility = Visibility.Collapsed;
        if (forced)
        {
            Title = HeadingText.Text = "Change the default password";
            WhyText.Visibility = Visibility.Visible;
        }
        Loaded += (_, _) => { if (current is null) CurrentBox.Focus(); else NewBox.Focus(); };
    }

    private async void Save_Click(object sender, RoutedEventArgs e)
    {
        ProblemText.Visibility = Visibility.Collapsed;
        void Problem(string text)
        {
            ProblemText.Text = text;
            ProblemText.Visibility = Visibility.Visible;
        }
        if (Api.PasswordProblem(NewBox.Password) is { } problem)
        {
            Problem(problem);
            return;
        }
        if (NewBox.Password != AgainBox.Password)
        {
            Problem("The two new passwords aren't the same.");
            return;
        }
        SaveButton.IsEnabled = false;
        try
        {
            Answer = await client.ChangePasswordAsync(current ?? CurrentBox.Password, NewBox.Password, NewNameBox.Text.Trim());
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
