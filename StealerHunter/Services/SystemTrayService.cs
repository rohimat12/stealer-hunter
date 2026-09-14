using System;
using System.Drawing;
using System.Windows.Forms;

namespace StealerHunter.Services;

public class SystemTrayService : IDisposable
{
    private NotifyIcon? _notifyIcon;

    public void Initialize(
        Action onOpenRequested,
        Action onQuickScanRequested,
        Action onDeepScanRequested,
        Func<bool> getRealtimeStatus,
        Action onToggleRealtimeRequested,
        Action onOpenQuarantineRequested,
        Action onOpenLogsRequested,
        Action onExitRequested)
    {
        var contextMenu = new ContextMenuStrip();
        contextMenu.ShowImageMargin = false;

        // 1. Open Dashboard
        var openItem = new ToolStripMenuItem("🛡️  Open Dashboard")
        {
            Font = new Font(contextMenu.Font, FontStyle.Bold)
        };
        openItem.Click += (s, e) => onOpenRequested?.Invoke();
        contextMenu.Items.Add(openItem);

        contextMenu.Items.Add(new ToolStripSeparator());

        // 2. Scan Actions
        var quickScanItem = new ToolStripMenuItem("⚡  Run Quick Scan");
        quickScanItem.Click += (s, e) => onQuickScanRequested?.Invoke();
        contextMenu.Items.Add(quickScanItem);

        var deepScanItem = new ToolStripMenuItem("🔍  Run Deep MFT Scan");
        deepScanItem.Click += (s, e) => onDeepScanRequested?.Invoke();
        contextMenu.Items.Add(deepScanItem);

        contextMenu.Items.Add(new ToolStripSeparator());

        // 3. Realtime Guard status toggle
        var realtimeItem = new ToolStripMenuItem("🛡️  Real-time Guard: Active");
        realtimeItem.Click += (s, e) =>
        {
            onToggleRealtimeRequested?.Invoke();
            bool active = getRealtimeStatus?.Invoke() ?? true;
            realtimeItem.Checked = active;
            realtimeItem.Text = active ? "🛡️  Real-time Guard: Active" : "🛡️  Real-time Guard: Disabled";
        };
        contextMenu.Items.Add(realtimeItem);

        // 4. Tools: Quarantine & Logs
        var quarantineItem = new ToolStripMenuItem("📁  Open Quarantine Folder");
        quarantineItem.Click += (s, e) => onOpenQuarantineRequested?.Invoke();
        contextMenu.Items.Add(quarantineItem);

        var logsItem = new ToolStripMenuItem("📜  View Live Telemetry Logs");
        logsItem.Click += (s, e) => onOpenLogsRequested?.Invoke();
        contextMenu.Items.Add(logsItem);

        contextMenu.Items.Add(new ToolStripSeparator());

        // 5. Exit
        var exitItem = new ToolStripMenuItem("❌  Exit");
        exitItem.Click += (s, e) => onExitRequested?.Invoke();
        contextMenu.Items.Add(exitItem);

        // Refresh state dynamically when context menu opens
        contextMenu.Opening += (s, e) =>
        {
            bool active = getRealtimeStatus?.Invoke() ?? true;
            realtimeItem.Checked = active;
            realtimeItem.Text = active ? "🛡️  Real-time Guard: Active" : "🛡️  Real-time Guard: Disabled";
        };

        Icon trayIcon = SystemIcons.Shield;
        try
        {
            var baseDir = AppDomain.CurrentDomain.BaseDirectory;
            var icoPath = System.IO.Path.Combine(baseDir, "Assets", "app.ico");
            if (System.IO.File.Exists(icoPath))
            {
                trayIcon = new Icon(icoPath);
            }
            else
            {
                var exePath = Environment.ProcessPath;
                if (!string.IsNullOrEmpty(exePath) && System.IO.File.Exists(exePath))
                {
                    trayIcon = Icon.ExtractAssociatedIcon(exePath) ?? SystemIcons.Shield;
                }
            }
        }
        catch
        {
            trayIcon = SystemIcons.Shield;
        }

        _notifyIcon = new NotifyIcon
        {
            Icon = trayIcon,
            Text = "StealerHunter - Anti-Infostealer Guard",
            Visible = true,
            ContextMenuStrip = contextMenu
        };

        _notifyIcon.DoubleClick += (s, e) => onOpenRequested?.Invoke();
    }

    public void ShowNotification(string title, string message, ToolTipIcon icon = ToolTipIcon.None)
    {
        if (_notifyIcon != null)
        {
            _notifyIcon.ShowBalloonTip(4000, title, message, icon);
        }
    }

    public void Dispose()
    {
        if (_notifyIcon != null)
        {
            _notifyIcon.Visible = false;
            _notifyIcon.Dispose();
            _notifyIcon = null;
        }
        GC.SuppressFinalize(this);
    }
}
