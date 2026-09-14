using System.IO;

namespace StealerHunter.Services;

public class RealtimeWatcherService : IDisposable
{
    private FileSystemWatcher? _tempWatcher;
    public event Action<string, string>? SuspiciousActivityDetected;
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
                    EnableRaisingEvents = true
                };

                _tempWatcher.Created += OnTempItemCreated;
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

    private void OnTempItemCreated(object sender, FileSystemEventArgs e)
    {
        try
        {
            var name = e.Name?.ToLowerInvariant() ?? string.Empty;
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
                    $"Suspicious file creation in Temp folder: '{e.Name}'",
                    e.FullPath
                );
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
