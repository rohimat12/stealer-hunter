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

            // Skip legitimate build tools, package managers, compilers, and runtime temporary extractions
            if (name.Contains("_mei") ||
                name.Contains("base_library.zip") ||
                name.StartsWith("cab", StringComparison.OrdinalIgnoreCase) ||
                name.StartsWith("wct", StringComparison.OrdinalIgnoreCase) ||
                name.StartsWith("msi", StringComparison.OrdinalIgnoreCase) ||
                name.StartsWith("cbs", StringComparison.OrdinalIgnoreCase) ||
                name.StartsWith("etilqs", StringComparison.OrdinalIgnoreCase) ||
                name.StartsWith("npm-", StringComparison.OrdinalIgnoreCase) ||
                name.StartsWith("pip-", StringComparison.OrdinalIgnoreCase) ||
                name.StartsWith("yarn-", StringComparison.OrdinalIgnoreCase) ||
                name.StartsWith("is-", StringComparison.OrdinalIgnoreCase) ||
                name.StartsWith("flutter", StringComparison.OrdinalIgnoreCase) ||
                name.StartsWith("dart", StringComparison.OrdinalIgnoreCase) ||
                name.StartsWith("gradle", StringComparison.OrdinalIgnoreCase) ||
                name.StartsWith("android", StringComparison.OrdinalIgnoreCase) ||
                name.StartsWith("ninja", StringComparison.OrdinalIgnoreCase) ||
                name.StartsWith("cmake", StringComparison.OrdinalIgnoreCase) ||
                name.Contains("nuget") ||
                name.Contains("hsperfdata") ||
                name.Contains("flutter_tools") ||
                System.Text.RegularExpressions.Regex.IsMatch(name, @"^cab[0-9a-f]+\.tmp$", System.Text.RegularExpressions.RegexOptions.IgnoreCase) ||
                System.Text.RegularExpressions.Regex.IsMatch(name, @"^[0-9a-f]{8}-[0-9]+-[0-9]+\.tmp$", System.Text.RegularExpressions.RegexOptions.IgnoreCase) ||
                System.Text.RegularExpressions.Regex.IsMatch(name, @"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", System.Text.RegularExpressions.RegexOptions.IgnoreCase))
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

            // Deep inspection of file content if it exists
            if (File.Exists(fullPath))
            {
                // 1. Plaintext credential dump inspection (catches dumps regardless of extension, e.g. .tmp, .dat, .log, .xyz)
                if (EntropyHelper.ContainsPlaintextCredentials(fullPath, out var credReason))
                {
                    SuspiciousActivityDetected?.Invoke(
                        $"Harvested Credential Dump: '{rawName}' ({credReason})",
                        fullPath
                    );
                    return;
                }

                // 2. High-entropy encrypted credential staging detection (only for disguised text/data extensions)
                var ext = Path.GetExtension(name);
                if (ext is ".txt" or ".log" or ".dat" or ".json" or ".csv" or ".ini")
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
