using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading;
using System.Windows;
using StealerHunter.Services;

namespace StealerHunter;

/// <summary>
/// Interaction logic for App.xaml
/// </summary>
public partial class App : System.Windows.Application
{
    public const string AppId = "StealerHunter";
    private const string MutexName = "Global\\StealerHunter_SingleInstance_Mutex_8F9A4E2B";
    private const string WakeEventName = "Global\\StealerHunter_WakeUp_Event_7B9A";

    private static Mutex? _singleInstanceMutex;
    private static EventWaitHandle? _wakeUpEvent;

    [DllImport("shell32.dll", SetLastError = true)]
    private static extern void SetCurrentProcessExplicitAppUserModelID([MarshalAs(UnmanagedType.LPWStr)] string AppID);

    protected override void OnStartup(StartupEventArgs e)
    {
        // 1. Enforce Single-Instance Application
        bool isFirstInstance;
        try
        {
            _singleInstanceMutex = new Mutex(true, MutexName, out isFirstInstance);
        }
        catch
        {
            isFirstInstance = true;
        }

        if (!isFirstInstance)
        {
            // Another instance is already running!
            // Signal the primary instance to restore and focus its window
            try
            {
                if (EventWaitHandle.TryOpenExisting(WakeEventName, out var existingEvent))
                {
                    existingEvent.Set();
                    existingEvent.Dispose();
                }
            }
            catch { }

            // Exit this duplicate process immediately
            Shutdown();
            return;
        }

        // Setup wake-up event listener for this primary instance
        try
        {
            _wakeUpEvent = new EventWaitHandle(false, EventResetMode.AutoReset, WakeEventName);
            ThreadPool.RegisterWaitForSingleObject(
                _wakeUpEvent,
                (state, timedOut) =>
                {
                    Dispatcher.Invoke(() =>
                    {
                        if (MainWindow is MainWindow mw)
                        {
                            mw.RestoreWindow();
                        }
                    });
                },
                null,
                -1,
                false);
        }
        catch { }

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

    protected override void OnExit(ExitEventArgs e)
    {
        try
        {
            _wakeUpEvent?.Dispose();
            if (_singleInstanceMutex != null)
            {
                _singleInstanceMutex.ReleaseMutex();
                _singleInstanceMutex.Dispose();
            }
        }
        catch { }

        base.OnExit(e);
    }
}


