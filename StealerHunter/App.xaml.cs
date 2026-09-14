using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Windows;
using StealerHunter.Services;

namespace StealerHunter;

/// <summary>
/// Interaction logic for App.xaml
/// </summary>
public partial class App : System.Windows.Application
{
    public const string AppId = "StealerHunter";

    [DllImport("shell32.dll", SetLastError = true)]
    private static extern void SetCurrentProcessExplicitAppUserModelID([MarshalAs(UnmanagedType.LPWStr)] string AppID);

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        try
        {
            SetCurrentProcessExplicitAppUserModelID(AppId);

            var programs = Environment.GetFolderPath(Environment.SpecialFolder.Programs);
            var shortcutPath = Path.Combine(programs, "StealerHunter.lnk");
            var exePath = Environment.ProcessPath;

            if (!File.Exists(shortcutPath) && !string.IsNullOrEmpty(exePath) && File.Exists(exePath))
            {
                var icoPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Assets", "app.ico");
                if (!File.Exists(icoPath))
                {
                    icoPath = exePath;
                }
                ShellShortcutHelper.CreateShortcut(shortcutPath, exePath, icoPath, AppId);
            }
        }
        catch
        {
            // Non-critical if shortcut creation fails
        }
    }
}


