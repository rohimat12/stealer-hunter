using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.CompilerServices;
using System.Windows.Input;
using StealerHunter.Models;
using StealerHunter.Services;

namespace StealerHunter.ViewModels;

public class MainViewModel : INotifyPropertyChanged
{
    private readonly BrowserAuditService _browserService = new();
    private readonly ProcessHunterService _processService = new();
    private readonly PersistenceService _persistenceService = new();
    private readonly StagedDataHunter _stagedDataHunter = new();
    private readonly QuarantineService _quarantineService = new();
    private readonly RealtimeWatcherService _watcherService = new();
    private readonly MftDeepScanService _mftDeepScanService = new();
    private readonly ArchiveScannerService _archiveScanner = new();
    private readonly AppSettings _settings;

    private CancellationTokenSource? _scanCts;
    private bool _isScanning;
    private double _scanProgress;
    private string _statusTitle = "SYSTEM SHIELD READY";
    private string _statusSubtitle = "Browser credentials protected. Ready to scan.";
    private string _statusColor = "#00E676"; // Emerald green
    private string _scanStatusText = "Idle";
    private int _scannedItemsCount;
    private int _selectedTabIndex;
    private bool _runOnStartup;
    private bool _realtimeProtectionEnabled;
    private bool _startMinimizedToTray;
    private bool _soundAlertOnThreat;
    private bool _hasActiveThreatAlert;
    private string _activeAlertMessage = string.Empty;

    public MainViewModel()
    {
        _settings = AppSettings.Load();

        DetectedThreats = new ObservableCollection<ThreatItem>();
        DetectedBrowsers = new ObservableCollection<BrowserTarget>();
        ScanLogs = new ObservableCollection<ScanLogItem>();

        QuickScanCommand = new RelayCommand(async () => await RunScanAsync(isDeepScan: false), () => !IsScanning);
        DeepScanCommand = new RelayCommand(async () => await RunScanAsync(isDeepScan: true), () => !IsScanning);
        CancelScanCommand = new RelayCommand(CancelScan, () => IsScanning);
        NeutralizeAllCommand = new RelayCommand(NeutralizeAllThreats, () => DetectedThreats.Any(t => !t.IsResolved));
        NeutralizeThreatCommand = new RelayCommand(p => NeutralizeSingleThreat(p as ThreatItem));
        OpenQuarantineFolderCommand = new RelayCommand(OpenQuarantineFolder);
        ClearLogsCommand = new RelayCommand(() => ScanLogs.Clear());
        DismissAlertCommand = new RelayCommand(() => HasActiveThreatAlert = false);

        _runOnStartup = AutoStartupService.IsAutoStartEnabled();
        _realtimeProtectionEnabled = _settings.RealtimeProtectionEnabled;
        _startMinimizedToTray = _settings.StartMinimizedToTray;
        _soundAlertOnThreat = _settings.SoundAlertOnThreat;

        // Initialize Realtime watcher if enabled
        if (_realtimeProtectionEnabled)
        {
            _watcherService.SuspiciousActivityDetected += OnSuspiciousActivityDetected;
            _watcherService.Start();
        }

        // Initialize detected browsers
        RefreshBrowsers();

        AddLog("INFO", "StealerHunter initialized. Database signatures loaded.");
        AddLog("INFO", $"Auto-Start on Boot is currently {(_runOnStartup ? "ENABLED" : "DISABLED")}.");
        AddLog("INFO", $"Realtime Protection is {(_realtimeProtectionEnabled ? "ACTIVE" : "INACTIVE")}.");
    }

    public ObservableCollection<ThreatItem> DetectedThreats { get; }
    public ObservableCollection<BrowserTarget> DetectedBrowsers { get; }
    public ObservableCollection<ScanLogItem> ScanLogs { get; }

    public ICommand QuickScanCommand { get; }
    public ICommand DeepScanCommand { get; }
    public ICommand CancelScanCommand { get; }
    public ICommand NeutralizeAllCommand { get; }
    public ICommand NeutralizeThreatCommand { get; }
    public ICommand OpenQuarantineFolderCommand { get; }
    public ICommand ClearLogsCommand { get; }
    public ICommand DismissAlertCommand { get; }

    public event Action<string, string>? NotificationRequested;

    public bool IsScanning
    {
        get => _isScanning;
        set { _isScanning = value; OnPropertyChanged(); }
    }

    public double ScanProgress
    {
        get => _scanProgress;
        set { _scanProgress = value; OnPropertyChanged(); }
    }

    public string StatusTitle
    {
        get => _statusTitle;
        set { _statusTitle = value; OnPropertyChanged(); }
    }

    public string StatusSubtitle
    {
        get => _statusSubtitle;
        set { _statusSubtitle = value; OnPropertyChanged(); }
    }

    public string StatusColor
    {
        get => _statusColor;
        set { _statusColor = value; OnPropertyChanged(); }
    }

    public string ScanStatusText
    {
        get => _scanStatusText;
        set { _scanStatusText = value; OnPropertyChanged(); }
    }

    public int ScannedItemsCount
    {
        get => _scannedItemsCount;
        set { _scannedItemsCount = value; OnPropertyChanged(); }
    }

    public int ThreatsCount => DetectedThreats.Count(t => !t.IsResolved);
    public int ResolvedCount => DetectedThreats.Count(t => t.IsResolved);
    public int InstalledBrowsersCount => DetectedBrowsers.Count(b => b.IsInstalled);

    public int SelectedTabIndex
    {
        get => _selectedTabIndex;
        set { _selectedTabIndex = value; OnPropertyChanged(); }
    }

    public bool RunOnStartup
    {
        get => _runOnStartup;
        set
        {
            if (_runOnStartup != value)
            {
                _runOnStartup = value;
                OnPropertyChanged();
                AutoStartupService.SetAutoStart(value);
                _settings.RunOnStartup = value;
                _settings.Save();
                AddLog("INFO", $"Windows Startup registration updated: {(value ? "ENABLED" : "DISABLED")}");
            }
        }
    }

    public bool RealtimeProtectionEnabled
    {
        get => _realtimeProtectionEnabled;
        set
        {
            if (_realtimeProtectionEnabled != value)
            {
                _realtimeProtectionEnabled = value;
                OnPropertyChanged();
                if (value)
                {
                    _watcherService.Start();
                    AddLog("SUCCESS", "Realtime file and temp watcher activated.");
                }
                else
                {
                    _watcherService.Stop();
                    AddLog("WARN", "Realtime watcher deactivated by user.");
                }
                _settings.RealtimeProtectionEnabled = value;
                _settings.Save();
            }
        }
    }

    public bool StartMinimizedToTray
    {
        get => _startMinimizedToTray;
        set
        {
            if (_startMinimizedToTray != value)
            {
                _startMinimizedToTray = value;
                OnPropertyChanged();
                _settings.StartMinimizedToTray = value;
                _settings.Save();
            }
        }
    }

    public bool SoundAlertOnThreat
    {
        get => _soundAlertOnThreat;
        set
        {
            if (_soundAlertOnThreat != value)
            {
                _soundAlertOnThreat = value;
                OnPropertyChanged();
                _settings.SoundAlertOnThreat = value;
                _settings.Save();
            }
        }
    }

    public bool HasActiveThreatAlert
    {
        get => _hasActiveThreatAlert;
        set
        {
            _hasActiveThreatAlert = value;
            OnPropertyChanged();
        }
    }

    public string ActiveAlertMessage
    {
        get => _activeAlertMessage;
        set
        {
            _activeAlertMessage = value;
            OnPropertyChanged();
        }
    }

    public void TriggerThreatAlert(string threatName, string details)
    {
        System.Windows.Application.Current?.Dispatcher.Invoke(() =>
        {
            HasActiveThreatAlert = true;
            ActiveAlertMessage = $"{threatName} — {details}";

            if (SoundAlertOnThreat)
            {
                try
                {
                    System.Media.SystemSounds.Hand.Play();
                }
                catch
                {
                    // Ignore sound device error
                }
            }

            NotificationRequested?.Invoke("⚠️ Ancaman Infostealer Terdeteksi!", $"{threatName}: {details}");
        });
    }

    public void RefreshBrowsers()
    {
        var list = _browserService.DetectBrowsers();
        DetectedBrowsers.Clear();
        foreach (var b in list)
        {
            DetectedBrowsers.Add(b);
        }
        OnPropertyChanged(nameof(InstalledBrowsersCount));
    }

    public async Task RunScanAsync(bool isDeepScan)
    {
        if (IsScanning) return;

        IsScanning = true;
        ScanProgress = 5;
        ScannedItemsCount = 0;
        StatusTitle = isDeepScan ? "DEEP HEURISTIC SCANNING..." : "QUICK SCANNING IN PROGRESS...";
        StatusSubtitle = "Analyzing active memory, registry autoruns, and browser data files...";
        StatusColor = "#08D9D6"; // Neon cyan
        ScanStatusText = "Initializing scanner...";

        _scanCts = new CancellationTokenSource();
        var ct = _scanCts.Token;

        AddLog("INFO", $"=== Starting {(isDeepScan ? "Deep" : "Quick")} Infostealer Scan ===");

        try
        {
            await Task.Run(() =>
            {
                // 1. Audit Browser Credentials
                ct.ThrowIfCancellationRequested();
                UpdateScanStatus("Auditing browser credential files (Chrome, Edge, Brave, Firefox)...", 20);
                var browserThreats = _browserService.AuditBrowserIntegrity(DetectedBrowsers.ToList(), AddLog);
                AddThreats(browserThreats);

                // 2. Scan Running Processes
                ct.ThrowIfCancellationRequested();
                UpdateScanStatus("Inspecting running processes in Temp, AppData, and memory...", 45);
                var processThreats = _processService.ScanProcesses(AddLog);
                AddThreats(processThreats);

                // 3. Scan Persistence & Startup
                ct.ThrowIfCancellationRequested();
                UpdateScanStatus("Scanning Registry Run keys and Startup folder...", 70);
                var persistenceThreats = _persistenceService.ScanPersistence(AddLog);
                AddThreats(persistenceThreats);

                // 4. Staged Data Hunter (Exfiltration folders & zips)
                ct.ThrowIfCancellationRequested();
                UpdateScanStatus("Hunting for staged exfiltration archives in %TEMP%...", isDeepScan ? 60 : 90);
                var stagedThreats = _stagedDataHunter.ScanStagedData(AddLog);
                AddThreats(stagedThreats);

                // 5. NTFS MFT & USN Journal Deep Scan across all drives
                if (isDeepScan)
                {
                    ct.ThrowIfCancellationRequested();
                    UpdateScanStatus("Memindai Master File Table (MFT) & USN Journal pada semua drive...", 70);
                    var mftThreats = _mftDeepScanService.ScanAllDrivesDeepMft(
                        AddLog,
                        (msg, pct) => UpdateScanStatus(msg, pct),
                        ct);
                    AddThreats(mftThreats);

                    // 6. Archive Inspector (.zip, .rar, .7z in Downloads, Desktop, Temp)
                    ct.ThrowIfCancellationRequested();
                    UpdateScanStatus("Memeriksa konten file arsip (.zip, .rar, .7z) di Downloads & Temp...", 85);
                    var archiveThreats = _archiveScanner.ScanVulnerableArchiveLocations(
                        AddLog,
                        (msg, pct) => UpdateScanStatus(msg, pct),
                        ct);
                    AddThreats(archiveThreats);
                }

                UpdateScanStatus("Scan complete.", 100);
            }, ct);

            // Update final status
            int activeThreats = DetectedThreats.Count(t => !t.IsResolved);
            if (activeThreats > 0)
            {
                StatusTitle = $"{activeThreats} INFOSTEALER THREAT(S) DETECTED!";
                StatusSubtitle = "Action required: Neutralize threats immediately to protect your credentials.";
                StatusColor = "#FF2E63"; // Crimson Red
                AddLog("DANGER", $"[ALERT] Scan completed with {activeThreats} active threat(s) found!");
                NotificationRequested?.Invoke("StealerHunter Alert", $"{activeThreats} dangerous infostealer threat(s) detected! Click to inspect.");
            }
            else
            {
                StatusTitle = "SYSTEM CLEAN & PROTECTED";
                StatusSubtitle = "No active infostealers or compromised browser credential locks detected.";
                StatusColor = "#00E676"; // Emerald Green
                AddLog("SUCCESS", "Scan completed. No infostealer threats found.");
            }
        }
        catch (OperationCanceledException)
        {
            StatusTitle = "SCAN CANCELLED";
            StatusSubtitle = "Pemindaian dihentikan oleh pengguna.";
            StatusColor = "#F4CE14";
            AddLog("WARN", "Scan was cancelled by user.");
        }
        catch (Exception ex)
        {
            StatusTitle = "SCAN ERROR";
            StatusSubtitle = ex.Message;
            StatusColor = "#FF2E63";
            AddLog("DANGER", $"Error during scan: {ex.Message}");
        }
        finally
        {
            IsScanning = false;
            OnPropertyChanged(nameof(ThreatsCount));
            OnPropertyChanged(nameof(ResolvedCount));
        }
    }

    private void CancelScan()
    {
        _scanCts?.Cancel();
    }

    private void UpdateScanStatus(string text, double progress)
    {
        ScanStatusText = text;
        ScanProgress = progress;
    }

    private void AddThreats(List<ThreatItem> items)
    {
        if (items.Count == 0) return;

        System.Windows.Application.Current?.Dispatcher.Invoke(() =>
        {
            foreach (var item in items)
            {
                // Avoid duplicates by FilePath or ProcessId
                bool exists = DetectedThreats.Any(t =>
                    (!string.IsNullOrEmpty(item.FilePath) && t.FilePath.Equals(item.FilePath, StringComparison.OrdinalIgnoreCase)) ||
                    (item.ProcessId.HasValue && t.ProcessId == item.ProcessId)
                );

                if (!exists)
                {
                    DetectedThreats.Add(item);
                    TriggerThreatAlert(item.Name, item.Description);
                }
            }
            OnPropertyChanged(nameof(ThreatsCount));
        });
    }

    public void NeutralizeAllThreats()
    {
        AddLog("WARN", "Executing mass neutralization of all detected threats...");
        var unresolved = DetectedThreats.Where(t => !t.IsResolved).ToList();

        foreach (var threat in unresolved)
        {
            NeutralizeSingleThreat(threat);
        }

        OnPropertyChanged(nameof(ThreatsCount));
        OnPropertyChanged(nameof(ResolvedCount));

        if (DetectedThreats.All(t => t.IsResolved))
        {
            StatusTitle = "ALL THREATS NEUTRALIZED";
            StatusSubtitle = "Malware processes killed and rogue files quarantined successfully.";
            StatusColor = "#00E676";
            HasActiveThreatAlert = false;
        }
    }

    public void NeutralizeSingleThreat(ThreatItem? threat)
    {
        if (threat == null || threat.IsResolved) return;

        AddLog("INFO", $"Neutralizing threat: {threat.Name}...");
        bool success = _quarantineService.NeutralizeThreat(threat, out var msg);

        if (success)
        {
            AddLog("SUCCESS", $"[NEUTRALIZED] {threat.Name}: {msg}");
        }
        else
        {
            AddLog("DANGER", $"[FAILED] Could not fully neutralize {threat.Name}: {msg}");
        }

        OnPropertyChanged(nameof(ThreatsCount));
        OnPropertyChanged(nameof(ResolvedCount));
    }

    private void OpenQuarantineFolder()
    {
        var dir = QuarantineService.GetQuarantineDirectory();
        if (!Directory.Exists(dir))
        {
            Directory.CreateDirectory(dir);
        }

        Process.Start(new ProcessStartInfo
        {
            FileName = dir,
            UseShellExecute = true
        });
    }

    private void OnSuspiciousActivityDetected(string message, string path)
    {
        System.Windows.Application.Current?.Dispatcher.Invoke(() =>
        {
            AddLog("DANGER", $"[REALTIME ALERT] {message}");
            NotificationRequested?.Invoke("StealerHunter Realtime Guard", message);

            // Add as active threat item
            var threat = new ThreatItem
            {
                Name = "Realtime Intercepted Artifact",
                Category = ThreatCategory.StagedExfiltrationData,
                Severity = ThreatSeverity.Critical,
                Description = message,
                FilePath = path,
                TargetTarget = "Temp Filesystem Watcher"
            };

            DetectedThreats.Add(threat);
            OnPropertyChanged(nameof(ThreatsCount));

            StatusTitle = "REALTIME THREAT INTERCEPTED!";
            StatusSubtitle = message;
            StatusColor = "#FF2E63";

            TriggerThreatAlert("Realtime File Staging Alert", message);
        });
    }

    public void AddLog(string level, string message)
    {
        System.Windows.Application.Current?.Dispatcher.Invoke(() =>
        {
            ScanLogs.Insert(0, new ScanLogItem
            {
                Level = level,
                Message = message
            });

            // Keep max 300 logs in memory
            if (ScanLogs.Count > 300)
            {
                ScanLogs.RemoveAt(ScanLogs.Count - 1);
            }
        });
    }

    public event PropertyChangedEventHandler? PropertyChanged;
    protected void OnPropertyChanged([CallerMemberName] string? name = null)
    {
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
    }
}
