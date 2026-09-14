using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.CompilerServices;
using System.Windows;
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
    private readonly MalwareDatabaseService _malwareDbService = new();
    private readonly AppSettings _settings;

    private CancellationTokenSource? _scanCts;
    private bool _isScanning;
    private bool _isUpdatingDatabase;
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

    public MainViewModel() : this(isTestMode: false)
    {
    }

    public MainViewModel(bool isTestMode)
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
        RestoreThreatCommand = new RelayCommand(p => RestoreSingleThreat(p as ThreatItem));
        OpenQuarantineFolderCommand = new RelayCommand(OpenQuarantineFolder);
        RefreshQuarantineCommand = new RelayCommand(RefreshQuarantinedItems);
        RestoreVaultItemCommand = new RelayCommand(p => RestoreVaultItem(p as QuarantinedItem));
        DeleteVaultItemCommand = new RelayCommand(p => DeleteVaultItem(p as QuarantinedItem));
        EmptyVaultCommand = new RelayCommand(EmptyVault, () => QuarantinedItems.Any());
        ClearLogsCommand = new RelayCommand(() => ScanLogs.Clear());
        DismissAlertCommand = new RelayCommand(() => HasActiveThreatAlert = false);
        UpdateDatabaseCommand = new RelayCommand(async () => await UpdateDatabaseAsync(), () => !IsScanning && !IsUpdatingDatabase);

        if (!isTestMode)
        {
            RefreshQuarantinedItems();

            _runOnStartup = AutoStartupService.IsAutoStartEnabled();
            _realtimeProtectionEnabled = _settings.RealtimeProtectionEnabled;
            _startMinimizedToTray = _settings.StartMinimizedToTray;
            _soundAlertOnThreat = _settings.SoundAlertOnThreat;

            // Initialize Realtime watcher
            _watcherService.SuspiciousActivityDetected += OnSuspiciousActivityDetected;
            _watcherService.WatcherLog += (level, msg) => AddLog(level, msg);

            if (_realtimeProtectionEnabled)
            {
                _watcherService.Start();
            }

            // Initialize detected browsers
            RefreshBrowsers();

            AddLog("INFO", $"StealerHunter initialized. Loaded {_malwareDbService.TotalSignatures:N0} Abuse.ch/MalwareBazaar threat signatures.");
            AddLog("INFO", $"Auto-Start on Boot is currently {(_runOnStartup ? "ENABLED" : "DISABLED")}.");
            AddLog("INFO", $"Realtime Protection is {(_realtimeProtectionEnabled ? "ACTIVE" : "INACTIVE")}.");
        }
        else
        {
            _realtimeProtectionEnabled = false;
            _startMinimizedToTray = false;
            _soundAlertOnThreat = false;
            _runOnStartup = false;
        }
    }

    public ObservableCollection<ThreatItem> DetectedThreats { get; }
    public ObservableCollection<BrowserTarget> DetectedBrowsers { get; }
    public ObservableCollection<ScanLogItem> ScanLogs { get; }
    public ObservableCollection<QuarantinedItem> QuarantinedItems { get; } = new();

    public ICommand QuickScanCommand { get; }
    public ICommand DeepScanCommand { get; }
    public ICommand CancelScanCommand { get; }
    public ICommand NeutralizeAllCommand { get; }
    public ICommand NeutralizeThreatCommand { get; }
    public ICommand RestoreThreatCommand { get; }
    public ICommand OpenQuarantineFolderCommand { get; }
    public ICommand RefreshQuarantineCommand { get; }
    public ICommand RestoreVaultItemCommand { get; }
    public ICommand DeleteVaultItemCommand { get; }
    public ICommand EmptyVaultCommand { get; }
    public ICommand ClearLogsCommand { get; }
    public ICommand DismissAlertCommand { get; }
    public ICommand UpdateDatabaseCommand { get; }

    public int QuarantinedCount => QuarantinedItems.Count;

    public int MalwareDatabaseCount => _malwareDbService.TotalSignatures;
    public string DatabaseStatusText => $"{_malwareDbService.TotalSignatures:N0} Signatures (Abuse.ch / MalwareBazaar)";

    public bool IsUpdatingDatabase
    {
        get => _isUpdatingDatabase;
        set { _isUpdatingDatabase = value; OnPropertyChanged(); }
    }

    public event Action<string, string>? NotificationRequested;

    public bool CanStartScan => !IsScanning;

    public bool IsScanning
    {
        get => _isScanning;
        set
        {
            if (_isScanning != value)
            {
                _isScanning = value;
                OnPropertyChanged();
                OnPropertyChanged(nameof(CanStartScan));
                OnPropertyChanged(nameof(ScanProgressText));
                try
                {
                    System.Windows.Application.Current?.Dispatcher?.InvokeAsync(() =>
                    {
                        CommandManager.InvalidateRequerySuggested();
                    });
                }
                catch
                {
                    // Dispatcher might not be active in unit tests
                }
            }
        }
    }

    public double ScanProgress
    {
        get => _scanProgress;
        set
        {
            _scanProgress = Math.Clamp(value, 0, 100);
            OnPropertyChanged();
            OnPropertyChanged(nameof(ScanProgressText));
        }
    }

    public string ScanProgressText => (IsScanning || _scanProgress > 0) ? $"{Math.Round(_scanProgress):0}%" : string.Empty;

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
                OnPropertyChanged(nameof(RealtimeStatusText));
                OnPropertyChanged(nameof(RealtimeStatusColor));

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

    public string RealtimeStatusText => RealtimeProtectionEnabled ? "SHIELD ON" : "SHIELD OFF";
    public string RealtimeStatusColor => RealtimeProtectionEnabled ? "#00E676" : "#FF5252";

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

                // 2. Scan Running Processes & Memory Hash Matching
                ct.ThrowIfCancellationRequested();
                UpdateScanStatus("Inspecting running processes in Temp, AppData, and memory...", 35);
                var processThreats = _processService.ScanProcesses(AddLog, _malwareDbService);
                AddThreats(processThreats);

                // 2b. Scan Critical System Folders against MalwareBazaar Database
                ct.ThrowIfCancellationRequested();
                UpdateScanStatus($"Matching file hashes against {_malwareDbService.TotalSignatures:N0} MalwareBazaar signatures...", 50);
                var signatureThreats = _malwareDbService.ScanCriticalDirectories(AddLog, (msg, pct) => UpdateScanStatus(msg, pct), ct);
                AddThreats(signatureThreats);

                // 3. Scan Persistence & Startup
                ct.ThrowIfCancellationRequested();
                UpdateScanStatus("Scanning Registry Run keys and Startup folder...", 60);
                var persistenceThreats = _persistenceService.ScanPersistence(AddLog);
                AddThreats(persistenceThreats);

                // 4. Staged Data Hunter (Exfiltration folders & zips)
                ct.ThrowIfCancellationRequested();
                UpdateScanStatus("Hunting for staged exfiltration archives in %TEMP%...", isDeepScan ? 70 : 85);
                var stagedThreats = _stagedDataHunter.ScanStagedData(AddLog);
                AddThreats(stagedThreats);

                // 5. NTFS MFT & USN Journal Deep Scan across all drives
                if (isDeepScan)
                {
                    ct.ThrowIfCancellationRequested();
                    UpdateScanStatus("Memindai Master File Table (MFT) & USN Journal pada semua drive...", 80);
                    var mftThreats = _mftDeepScanService.ScanAllDrivesDeepMft(
                        AddLog,
                        (msg, pct) => UpdateScanStatus(msg, pct),
                        ct);
                    AddThreats(mftThreats);

                    // 6. Archive Inspector (.zip, .rar, .7z in Downloads, Desktop, Temp)
                    ct.ThrowIfCancellationRequested();
                    UpdateScanStatus("Memeriksa konten file arsip (.zip, .rar, .7z) di Downloads & Temp...", 90);
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
                if (!_malwareDbService.IsDatabaseHealthy)
                {
                    StatusTitle = "SIGNATURE DATABASE EMPTY";
                    StatusSubtitle = "No threats found via heuristics, but signature database is empty. Click 'Update DB'.";
                    StatusColor = "#F4CE14"; // Amber
                    AddLog("WARN", "Scan completed. Note: Threat database is empty or could not be loaded.");
                }
                else
                {
                    StatusTitle = "SYSTEM CLEAN & PROTECTED";
                    StatusSubtitle = "No active infostealers or compromised browser credential locks detected.";
                    StatusColor = "#00E676"; // Emerald Green
                    AddLog("SUCCESS", "Scan completed. No infostealer threats found.");
                }
            }
        }
        catch (OperationCanceledException)
        {
            UpdateScanStatus("Scan cancelled by user.", 0);
            AddLog("WARN", "Scan operation was cancelled.");
            StatusTitle = "SCAN CANCELLED";
            StatusSubtitle = "Threat scanning was aborted.";
            StatusColor = "#FFB300";
        }
        catch (Exception ex)
        {
            UpdateScanStatus("Scan failed.", 0);
            AddLog("DANGER", $"Scan error: {ex.Message}");
            StatusTitle = "SCAN ENCOUNTERED ERROR";
            StatusSubtitle = ex.Message;
            StatusColor = "#FF2E63";
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

    public void AddThreats(List<ThreatItem> items)
    {
        if (items.Count == 0) return;

        System.Windows.Application.Current?.Dispatcher.Invoke(() =>
        {
            var newlyAdded = new List<ThreatItem>();
            foreach (var item in items)
            {
                // Avoid duplicates by FilePath or ProcessId + ProcessName / StartTime
                bool exists = DetectedThreats.Any(t =>
                    (!string.IsNullOrEmpty(item.FilePath) && t.FilePath.Equals(item.FilePath, StringComparison.OrdinalIgnoreCase)) ||
                    (item.ProcessId.HasValue && t.ProcessId == item.ProcessId &&
                     (string.IsNullOrEmpty(item.ProcessName) || string.IsNullOrEmpty(t.ProcessName) || t.ProcessName.Equals(item.ProcessName, StringComparison.OrdinalIgnoreCase)) &&
                     (!item.ProcessStartTime.HasValue || !t.ProcessStartTime.HasValue || Math.Abs((t.ProcessStartTime.Value - item.ProcessStartTime.Value).TotalSeconds) < 2))
                );

                if (!exists)
                {
                    DetectedThreats.Add(item);
                    newlyAdded.Add(item);
                }
            }
            OnPropertyChanged(nameof(ThreatsCount));

            // Coalesce alert: Trigger a single consolidated alert rather than bombarding sounds
            if (newlyAdded.Count == 1)
            {
                TriggerThreatAlert(newlyAdded[0].Name, newlyAdded[0].Description);
            }
            else if (newlyAdded.Count > 1)
            {
                TriggerThreatAlert($"{newlyAdded.Count} Threats Intercepted",
                    $"{newlyAdded.Count} active security threats were detected and require attention.");
            }
        });
    }

    public async void NeutralizeAllThreats()
    {
        var unresolved = DetectedThreats.Where(t => !t.IsResolved).ToList();
        if (unresolved.Count == 0) return;

        var confirm = System.Windows.MessageBox.Show(
            $"StealerHunter is about to neutralize {unresolved.Count} detected threat(s).\n\n" +
            "This will terminate confirmed malware processes and isolate rogue files into the encrypted quarantine vault.\n\n" +
            "Do you want to proceed?",
            "Confirm Threat Remediation",
            System.Windows.MessageBoxButton.YesNo,
            System.Windows.MessageBoxImage.Warning);

        if (confirm != System.Windows.MessageBoxResult.Yes)
        {
            AddLog("INFO", "Mass neutralization cancelled by user.");
            return;
        }

        AddLog("WARN", $"Executing mass neutralization of {unresolved.Count} threats in background...");

        bool anyRebootRequired = false;
        await Task.Run(() =>
        {
            foreach (var threat in unresolved)
            {
                NeutralizeSingleThreatInternal(threat);
                if (threat.StatusMessage.Contains("REBOOT REQUIRED", StringComparison.OrdinalIgnoreCase))
                {
                    anyRebootRequired = true;
                }
            }
        });

        OnPropertyChanged(nameof(ThreatsCount));
        OnPropertyChanged(nameof(ResolvedCount));
        RefreshQuarantinedItems();

        if (DetectedThreats.All(t => t.IsResolved))
        {
            if (anyRebootRequired)
            {
                StatusTitle = "REBOOT REQUIRED TO FINALIZE";
                StatusSubtitle = "Locked malware files are queued for kernel deletion upon next system restart.";
                StatusColor = "#FFB300";
            }
            else
            {
                StatusTitle = "ALL THREATS NEUTRALIZED";
                StatusSubtitle = "Malware processes killed and rogue files quarantined successfully.";
                StatusColor = "#00E676";
            }
            HasActiveThreatAlert = false;
        }
    }

    public void NeutralizeSingleThreat(ThreatItem? threat)
    {
        if (threat == null || threat.IsResolved) return;

        var confirm = System.Windows.MessageBox.Show(
            $"Do you want to neutralize threat:\n\n'{threat.Name}'\nTarget: {threat.FilePath}?\n\n" +
            "This will terminate the process and isolate the file into the encrypted quarantine vault.",
            "Confirm Single Threat Remediation",
            System.Windows.MessageBoxButton.YesNo,
            System.Windows.MessageBoxImage.Question);

        if (confirm != System.Windows.MessageBoxResult.Yes) return;

        NeutralizeSingleThreatInternal(threat);
    }

    private void NeutralizeSingleThreatInternal(ThreatItem threat)
    {
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
        RefreshQuarantinedItems();
    }

    public async void RestoreSingleThreat(ThreatItem? threat)
    {
        if (threat == null || !threat.CanRestore || string.IsNullOrEmpty(threat.QuarantineBackupPath))
            return;

        if (!QuarantineService.IsPathInsideQuarantineDirectory(threat.QuarantineBackupPath))
        {
            AddLog("DANGER", $"[VAULT SECURITY] Blocked restore: file is outside quarantine: {threat.QuarantineBackupPath}");
            return;
        }

        var confirm = System.Windows.MessageBox.Show(
            $"Are you sure you want to restore this file from quarantine?\n\nFile: {threat.FilePath}\n\n" +
            "WARNING: If this file was a true malicious payload, restoring it will place the executable back onto your system!",
            "Confirm Quarantine Restoration",
            System.Windows.MessageBoxButton.YesNo,
            System.Windows.MessageBoxImage.Warning);

        if (confirm != System.Windows.MessageBoxResult.Yes) return;

        bool restored = false;
        string msg = string.Empty;
        string backupPath = threat.QuarantineBackupPath;
        string targetPath = threat.FilePath;

        await Task.Run(() =>
        {
            restored = QuarantineService.RestoreQuarantinedFile(backupPath, targetPath, out msg);
        });

        if (restored)
        {
            threat.IsResolved = false;
            threat.QuarantineBackupPath = null;
            threat.StatusMessage = "Restored from Quarantine";
            AddLog("SUCCESS", $"[RESTORED] {threat.Name}: {msg}");
        }
        else
        {
            AddLog("DANGER", $"[RESTORE FAILED] Could not restore {threat.Name}: {msg}");
        }

        OnPropertyChanged(nameof(ThreatsCount));
        OnPropertyChanged(nameof(ResolvedCount));
        RefreshQuarantinedItems();
    }

    public async void RefreshQuarantinedItems()
    {
        try
        {
            var items = await Task.Run(() => QuarantineService.GetQuarantinedItems());

            void UpdateCollection()
            {
                QuarantinedItems.Clear();
                foreach (var item in items)
                {
                    QuarantinedItems.Add(item);
                }
                OnPropertyChanged(nameof(QuarantinedCount));
                ((RelayCommand)EmptyVaultCommand)?.RaiseCanExecuteChanged();
            }

            if (System.Windows.Application.Current?.Dispatcher != null && !System.Windows.Application.Current.Dispatcher.CheckAccess())
            {
                System.Windows.Application.Current.Dispatcher.Invoke(UpdateCollection);
            }
            else
            {
                UpdateCollection();
            }
        }
        catch (Exception ex)
        {
            AddLog("WARN", $"Could not refresh quarantine vault: {ex.Message}");
        }
    }

    public async void RestoreVaultItem(QuarantinedItem? item)
    {
        if (item == null || !File.Exists(item.FullPath)) return;

        if (!QuarantineService.IsPathInsideQuarantineDirectory(item.FullPath))
        {
            AddLog("DANGER", $"[VAULT SECURITY] Blocked restore for unauthorized path: {item.FullPath}");
            System.Windows.MessageBox.Show("Cannot restore file: Target path is outside the secure quarantine directory.", "Security Restriction", System.Windows.MessageBoxButton.OK, System.Windows.MessageBoxImage.Error);
            return;
        }

        var confirm = System.Windows.MessageBox.Show(
            $"Are you sure you want to restore this file from quarantine?\n\n" +
            $"File: {item.OriginalFileName}\nSize: {item.FormattedSize}\nDate: {item.FormattedDate}\n\n" +
            "WARNING: If this file was a true malicious payload, restoring it will decrypt the executable back onto your system.",
            "Confirm Quarantine Restoration",
            System.Windows.MessageBoxButton.YesNo,
            System.Windows.MessageBoxImage.Warning);

        if (confirm != System.Windows.MessageBoxResult.Yes) return;

        var sfd = new Microsoft.Win32.SaveFileDialog
        {
            Title = "Select Destination for Restored File",
            FileName = item.OriginalFileName,
            InitialDirectory = Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            Filter = "All Files (*.*)|*.*"
        };

        if (sfd.ShowDialog() == true)
        {
            string destPath = sfd.FileName;
            string fullPath = item.FullPath;
            string originalFileName = item.OriginalFileName;

            bool success = false;
            string msg = string.Empty;

            await Task.Run(() =>
            {
                success = QuarantineService.RestoreQuarantinedFile(fullPath, destPath, out msg);
            });

            if (success)
            {
                AddLog("SUCCESS", $"[VAULT RESTORE] {originalFileName} restored to: {destPath}");
                var deleteQuarantine = System.Windows.MessageBox.Show(
                    $"File successfully restored to:\n{destPath}\n\nDo you want to delete the quarantined copy from the vault?",
                    "Restore Succeeded",
                    System.Windows.MessageBoxButton.YesNo,
                    System.Windows.MessageBoxImage.Question);

                if (deleteQuarantine == System.Windows.MessageBoxResult.Yes)
                {
                    await Task.Run(() =>
                    {
                        try
                        {
                            if (QuarantineService.IsPathInsideQuarantineDirectory(fullPath) && File.Exists(fullPath))
                            {
                                File.Delete(fullPath);
                            }
                        }
                        catch { }
                    });
                }
                RefreshQuarantinedItems();
            }
            else
            {
                System.Windows.MessageBox.Show($"Failed to restore file:\n{msg}", "Restore Error", System.Windows.MessageBoxButton.OK, System.Windows.MessageBoxImage.Error);
                AddLog("DANGER", $"[VAULT RESTORE FAILED] {msg}");
            }
        }
    }

    public async void DeleteVaultItem(QuarantinedItem? item)
    {
        if (item == null || !File.Exists(item.FullPath)) return;

        if (!QuarantineService.IsPathInsideQuarantineDirectory(item.FullPath))
        {
            AddLog("DANGER", $"[VAULT SECURITY] Blocked deletion for unauthorized path: {item.FullPath}");
            System.Windows.MessageBox.Show("Cannot delete file: Target path is outside the secure quarantine directory.", "Security Restriction", System.Windows.MessageBoxButton.OK, System.Windows.MessageBoxImage.Error);
            return;
        }

        var confirm = System.Windows.MessageBox.Show(
            $"Permanently delete this quarantined file?\n\n" +
            $"File: {item.OriginalFileName}\nSize: {item.FormattedSize}\n\n" +
            "This action cannot be undone.",
            "Confirm Permanent Deletion",
            System.Windows.MessageBoxButton.YesNo,
            System.Windows.MessageBoxImage.Warning);

        if (confirm == System.Windows.MessageBoxResult.Yes)
        {
            string fullPath = item.FullPath;
            string origName = item.OriginalFileName;

            try
            {
                await Task.Run(() =>
                {
                    if (QuarantineService.IsPathInsideQuarantineDirectory(fullPath) && File.Exists(fullPath))
                    {
                        File.Delete(fullPath);
                    }
                });

                AddLog("WARN", $"[VAULT DELETED] Permanently removed: {origName}");
                RefreshQuarantinedItems();
            }
            catch (Exception ex)
            {
                System.Windows.MessageBox.Show($"Failed to delete file: {ex.Message}", "Delete Error", System.Windows.MessageBoxButton.OK, System.Windows.MessageBoxImage.Error);
            }
        }
    }

    public async void EmptyVault()
    {
        if (!QuarantinedItems.Any()) return;

        var confirm = System.Windows.MessageBox.Show(
            $"Permanently delete ALL {QuarantinedItems.Count} quarantined files?\n\n" +
            "This will purge the entire quarantine vault. This action cannot be undone.",
            "Confirm Empty Quarantine Vault",
            System.Windows.MessageBoxButton.YesNo,
            System.Windows.MessageBoxImage.Warning);

        if (confirm == System.Windows.MessageBoxResult.Yes)
        {
            var itemsToDelete = QuarantinedItems.ToList();
            int count = 0;

            await Task.Run(() =>
            {
                foreach (var item in itemsToDelete)
                {
                    try
                    {
                        if (QuarantineService.IsPathInsideQuarantineDirectory(item.FullPath) && File.Exists(item.FullPath))
                        {
                            File.Delete(item.FullPath);
                            count++;
                        }
                    }
                    catch { }
                }
            });

            AddLog("WARN", $"[VAULT PURGED] Permanently deleted {count} quarantined files.");
            RefreshQuarantinedItems();
        }
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
        System.Windows.Application.Current?.Dispatcher.BeginInvoke(() =>
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
        System.Windows.Application.Current?.Dispatcher.BeginInvoke(() =>
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

    public async Task UpdateDatabaseAsync()
    {
        if (IsUpdatingDatabase) return;
        IsUpdatingDatabase = true;
        try
        {
            AddLog("INFO", "Connecting to Abuse.ch MalwareBazaar threat intelligence feed...");
            var (added, total) = await _malwareDbService.UpdateFromMalwareBazaarAsync(AddLog);
            OnPropertyChanged(nameof(MalwareDatabaseCount));
            OnPropertyChanged(nameof(DatabaseStatusText));
            NotificationRequested?.Invoke("Database Updated", $"Malware database updated! Added +{added:N0} signatures. Total active: {total:N0}.");
        }
        catch (Exception ex)
        {
            AddLog("WARN", $"Database update failed: {ex.Message}");
        }
        finally
        {
            IsUpdatingDatabase = false;
        }
    }

    public event PropertyChangedEventHandler? PropertyChanged;
    protected void OnPropertyChanged([CallerMemberName] string? name = null)
    {
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
    }
}
