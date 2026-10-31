using System.Windows;
using System.Windows.Threading;

namespace Strongthium.WebDavServer.AdminApp;

public partial class App : Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        DispatcherUnhandledException += OnUnhandled;
        new MainWindow().Show();
    }

    private void OnUnhandled(object sender, DispatcherUnhandledExceptionEventArgs e)
    {
        // Something the program didn't expect is shown, rather than the program disappearing.
        MessageBox.Show(e.Exception.Message, "webdav-server-admin", MessageBoxButton.OK, MessageBoxImage.Warning);
        e.Handled = true;
    }
}
