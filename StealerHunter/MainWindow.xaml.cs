using System.ComponentModel;
using System.Windows;
using System.Windows.Forms;
using StealerHunter.Services;
using StealerHunter.ViewModels;

namespace StealerHunter;

public partial class MainWindow : Window
{
    private readonly SystemTrayService _trayService = new();
    private bool _isExplicitExit;

    public MainWindow()
    {
        InitializeComponent();

        if (DataContext is MainViewModel vm)
        {
            _trayService.Initialize(
                onOpenRequested: RestoreWindow,
                onQuickScanRequested: () => Dispatcher.Invoke(async () => await vm.RunScanAsync(false)),
                onDeepScanRequested: () => Dispatcher.Invoke(async () => await vm.RunScanAsync(true)),
                getRealtimeStatus: () => vm.RealtimeProtectionEnabled,
                onToggleRealtimeRequested: () => Dispatcher.Invoke(() => vm.RealtimeProtectionEnabled = !vm.RealtimeProtectionEnabled),
                onOpenQuarantineRequested: () => Dispatcher.Invoke(() => vm.OpenQuarantineFolderCommand.Execute(null)),
                onOpenLogsRequested: () => Dispatcher.Invoke(() => { vm.SelectedTabIndex = 2; RestoreWindow(); }),
                onExitRequested: ExitApplication
            );

            vm.NotificationRequested += (title, message) =>
            {
                _trayService.ShowNotification(title, message, ToolTipIcon.Warning);

                // If window was hidden in tray, restore and bring to user attention
                Dispatcher.Invoke(() =>
                {
                    if (!IsVisible || WindowState == WindowState.Minimized)
                    {
                        Show();
                        WindowState = WindowState.Normal;
                        ShowInTaskbar = true;
                        Activate();
                    }
                });
            };

            // Check if started with --silent flag (from Windows boot auto-start)
            var args = Environment.GetCommandLineArgs();
            if (args.Any(a => a.Equals("--silent", StringComparison.OrdinalIgnoreCase) ||
                              a.Equals("--minimized", StringComparison.OrdinalIgnoreCase)))
            {
                ShowInTaskbar = false;
                _trayService.ShowNotification(
                    "StealerHunter Active",
                    "Running in background. Your browser credentials are protected.",
                    ToolTipIcon.None
                );
            }
        }
    }

    protected override void OnClosing(CancelEventArgs e)
    {
        if (!_isExplicitExit && DataContext is MainViewModel vm && vm.StartMinimizedToTray)
        {
            e.Cancel = true;
            Hide();
            _trayService.ShowNotification(
                "StealerHunter Minimized",
                "StealerHunter is still protecting your system in the System Tray.",
                ToolTipIcon.None
            );
            return;
        }

        _trayService.Dispose();
        base.OnClosing(e);
    }

    public void RestoreWindow()
    {
        Dispatcher.Invoke(() =>
        {
            Show();
            if (WindowState == WindowState.Minimized)
            {
                WindowState = WindowState.Normal;
            }
            ShowInTaskbar = true;
            Activate();
            Topmost = true;
            Topmost = false;
            Focus();
        });
    }

    private void ExitApplication()
    {
        Dispatcher.Invoke(() =>
        {
            _isExplicitExit = true;
            _trayService.Dispose();
            System.Windows.Application.Current.Shutdown();
        });
    }
}