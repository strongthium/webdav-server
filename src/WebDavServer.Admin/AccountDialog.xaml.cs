using System.Security.Cryptography;
using System.Windows;

namespace Strongthium.WebDavServer.AdminApp;

/// <summary>A path in the list of what an account may use.</summary>
public sealed class GrantChoice(string mount, string layout, bool granted, bool readOnly)
{
    public string Mount { get; } = mount;
    public string Label { get; } = $"{mount}  ({layout})";
    public bool Granted { get; set; } = granted;
    public bool ReadOnly { get; set; } = readOnly;
}

public sealed partial class AccountDialog : Window
{
    private readonly bool isNew;
    private readonly List<GrantChoice> grants;
    private string name;

    public AccountDialog(AccountInfo? account, List<MountInfo> mounts)
    {
        InitializeComponent();
        isNew = account is null;
        name = account?.Name ?? "";
        Title = isNew ? "Add an account" : $"Change {name}";

        grants = [.. mounts.Select(mount =>
        {
            var grant = account?.Grants.FirstOrDefault(item => item.Mount == mount.Path);
            return new GrantChoice(mount.Path, Layouts.Describe(mount.Layout), grant is not null, grant?.ReadOnly ?? false);
        })];
        GrantsList.ItemsSource = grants;
        HomeBox.ItemsSource = new[] { "The first it may use" }.Concat(mounts.Select(mount => mount.Path)).ToList();
        HomeBox.SelectedItem = account is { HomeMount.Length: > 0 } ? account.HomeMount : "The first it may use";

        NameBox.Text = name;
        NameBox.IsReadOnly = !isNew;
        DisplayBox.Text = account?.DisplayName ?? "";
        EnabledBox.IsChecked = account?.Enabled ?? true;
        AppOnlyBox.IsChecked = account?.RequireAppPasswords ?? false;
        QuotaBox.Text = Sizes.ToGb(account?.QuotaBytes ?? 0);
        WhitelistBox.Text = string.Join(Environment.NewLine, account?.Whitelist ?? []);
        if (!isNew)
        {
            PasswordLabel.Text = "New password";
            PasswordHint.Text = "Leave these empty to keep the one it has.";
            AppPasswordsPanel.Visibility = Visibility.Visible;
            AppPasswordsList.ItemsSource = account!.AppPasswords;
        }
        Loaded += (_, _) => { if (isNew) NameBox.Focus(); else DisplayBox.Focus(); };
    }

    private void Problem(string text)
    {
        ProblemText.Text = text;
        ProblemText.Visibility = text.Length > 0 ? Visibility.Visible : Visibility.Collapsed;
    }

    private void Generate_Click(object sender, RoutedEventArgs e)
    {
        // 24 characters from 56 that can't be mistaken for one another: 139 bits.
        const string alphabet = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789";
        var password = RandomNumberGenerator.GetString(alphabet, 24);
        PasswordBox1.Password = PasswordBox2.Password = password;
        GeneratedBox.Text = password;
        GeneratedBox.Visibility = Visibility.Visible;
        PasswordHint.Text = "Copy it now: once this window is closed it can't be read back from anywhere.";
    }

    private async void Save_Click(object sender, RoutedEventArgs e)
    {
        Problem("");
        if (!Sizes.TryParseGb(QuotaBox.Text, out var quota))
        {
            Problem("The quota has to be a number of gigabytes, or empty.");
            return;
        }
        var whitelist = WhitelistBox.Text.Split('\n', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries).ToList();
        if (whitelist.Select(AccessList.Problem).FirstOrDefault(problem => problem is not null) is { } ruleProblem)
        {
            Problem(ruleProblem);
            return;
        }
        var password = PasswordBox1.Password;
        if (password != PasswordBox2.Password)
        {
            Problem("The two passwords aren't the same.");
            return;
        }

        var chosen = grants.Where(grant => grant.Granted).Select(grant => new GrantInfo { Mount = grant.Mount, ReadOnly = grant.ReadOnly }).ToList();
        var home = HomeBox.SelectedItem as string ?? "";
        var info = new AccountInfo
        {
            Name = NameBox.Text.Trim(),
            DisplayName = DisplayBox.Text.Trim(),
            Enabled = EnabledBox.IsChecked == true,
            RequireAppPasswords = AppOnlyBox.IsChecked == true,
            QuotaBytes = quota,
            HomeMount = home.StartsWith('/') ? home : "",
            Whitelist = whitelist,
            Grants = chosen,
        };

        SaveButton.IsEnabled = false;
        try
        {
            await Session.Client.PutAsync("/api/accounts", new AccountWrite { Account = info, Password = password.Length > 0 ? password : null });
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

    private async void NewAppPassword_Click(object sender, RoutedEventArgs e)
    {
        Problem("");
        try
        {
            var created = await Session.Client.PostAsync<AppPasswordCreated>("/api/app-passwords", new AppPasswordRequest { Account = name, Name = AppNameBox.Text.Trim() });
            NewAppPasswordBox.Text = created.Password;
            NewAppPasswordBox.Visibility = NewAppPasswordHint.Visibility = Visibility.Visible;
            AppNameBox.Clear();
            await ReloadAppPasswordsAsync();
        }
        catch (Exception exception) when (AdminClient.IsExpected(exception))
        {
            Problem(AdminClient.Explain(exception));
        }
    }

    private async void RemoveAppPassword_Click(object sender, RoutedEventArgs e)
    {
        if (AppPasswordsList.SelectedItem is not AppPasswordInfo item) return;
        Problem("");
        try
        {
            await Session.Client.DeleteAsync($"/api/app-passwords?account={AdminClient.Q(name)}&id={item.Id}");
            await ReloadAppPasswordsAsync();
        }
        catch (Exception exception) when (AdminClient.IsExpected(exception))
        {
            Problem(AdminClient.Explain(exception));
        }
    }

    private async Task ReloadAppPasswordsAsync()
    {
        var accounts = await Session.Client.GetAsync<List<AccountInfo>>("/api/accounts");
        AppPasswordsList.ItemsSource = accounts.FirstOrDefault(account => account.Name == name)?.AppPasswords ?? [];
    }
}

public static class Layouts
{
    public static string Describe(StorageLayout layout) => layout switch
    {
        StorageLayout.User => "by account",
        StorageLayout.Path => "by path, shared",
        _ => "by account and path",
    };
}
