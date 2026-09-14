using System.IO;

namespace StealerHunter.Services;

public class RealtimeWatcherService : IDisposable
{
    private FileSystemWatcher? _tempWatcher;
    public event Action<string, string>? SuspiciousActivityDetected;
    public event Action<string, string>? WatcherLog;
    public bool IsActive { get; private set; }

    public void Start()
    {
        if (IsActive) return;

        try
        {
            var tempPath = Path.GetTempPath();
            if (Directory.Exists(tempPath))
            {
                _tempWatcher = new FileSystemWatcher(tempPath)
                {
                    NotifyFilter = NotifyFilters.FileName | NotifyFilters.DirectoryName | NotifyFilters.LastWrite,
                    IncludeSubdirectories = true,
                    InternalBufferSize = 65536, // 64 KB maximum safe buffer to prevent InternalBufferOverflowException
                    EnableRaisingEvents = true
                };

                _tempWatcher.Created += OnTempItemCreated;
                _tempWatcher.Renamed += OnTempItemRenamed;
                _tempWatcher.Error += OnWatcherError;
            }

            IsActive = true;
        }
        catch
        {
            IsActive = false;
        }
    }

    public void Stop()
    {
        if (!IsActive) return;

        try
        {
            if (_tempWatcher != null)
            {
                _tempWatcher.EnableRaisingEvents = false;
                _tempWatcher.Created -= OnTempItemCreated;
                _tempWatcher.Renamed -= OnTempItemRenamed;
                _tempWatcher.Error -= OnWatcherError;
                _tempWatcher.Dispose();
                _tempWatcher = null;
            }
        }
        catch
        {
            // Ignore teardown errors
        }

        IsActive = false;
    }

    private void OnWatcherError(object sender, ErrorEventArgs e)
    {
        var ex = e.GetException();
        WatcherLog?.Invoke("WARN", $"Realtime %TEMP% watcher handled I/O surge: {ex?.Message ?? "Internal buffer surge recovered."}");

        // Auto-recover event monitoring on buffer surge
        try
        {
            if (_tempWatcher != null)
            {
                _tempWatcher.EnableRaisingEvents = false;
                _tempWatcher.EnableRaisingEvents = true;
            }
        }
        catch
        {
        }
    }

    private void OnTempItemCreated(object sender, FileSystemEventArgs e) =>
        InspectItem(e.FullPath, e.Name, "created");

    private void OnTempItemRenamed(object sender, RenamedEventArgs e) =>
        InspectItem(e.FullPath, e.Name, "renamed");

    private void InspectItem(string fullPath, string? rawName, string action)
    {
        try
        {
            var name = rawName?.ToLowerInvariant() ?? string.Empty;
            if (string.IsNullOrEmpty(name)) return;

            // Skip PyInstaller / Python runtime temporary extractions (e.g. _MEIxxxxx\base_library.zip)
            if (name.Contains("_mei") || name.Contains("base_library.zip"))
            {
                return;
            }

            // Trigger on stealer exfiltration artifacts
            bool isStealerText = name.Contains("passwords.txt") ||
                                 name.Contains("cookies.txt") ||
                                 name.Contains("wallets") ||
                                 name.Contains("grabbed") ||
                                 name.Contains("all_passwords");

            bool isStealerArchive = name.EndsWith(".zip") && (name.Contains("passwords") ||
                                                              name.Contains("cookies") ||
                                                              name.Contains("wallet") ||
                                                              name.Contains("stealer") ||
                                                              name.Contains("dump") ||
                                                              name.Contains("logs"));

            bool isExecutableScript = name.EndsWith(".scr") || name.EndsWith(".vbs");

            if (isStealerText || isStealerArchive || isExecutableScript)
            {
                SuspiciousActivityDetected?.Invoke(
                    $"Suspicious file {action} in Temp folder: '{rawName}'",
                    fullPath
                );
                return;
            }

            // High-entropy encrypted credential staging detection (Lumma, Stealc mutation)
            if (File.Exists(fullPath))
            {
                var ext = Path.GetExtension(name);
                if (ext is ".txt" or ".tmp" or ".dat" or ".log")
                {
                    if (EntropyHelper.IsSuspiciousHighEntropyStaging(fullPath, out var entropy))
                    {
                        SuspiciousActivityDetected?.Invoke(
                            $"Encrypted/Obfuscated Staging Dump: '{rawName}' (Shannon Entropy: {entropy:F2}/8.00)",
                            fullPath
                        );
                    }
                }
            }
        }
        catch
        {
            // Transient event errors
        }
    }

    public void Dispose()
    {
        Stop();
        GC.SuppressFinalize(this);
    }
}
