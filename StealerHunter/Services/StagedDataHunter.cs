using System.IO;
using System.IO.Compression;
using StealerHunter.Models;

namespace StealerHunter.Services;

public class StagedDataHunter
{
    private static readonly HashSet<string> StealerDumpKeywords = new(StringComparer.OrdinalIgnoreCase)
    {
        "passwords.txt", "cookies.txt", "autofill.txt", "wallets", "all_passwords.txt",
        "browser_passwords.txt", "userinfo.txt", "system_info.txt", "information.txt"
    };

    public List<ThreatItem> ScanStagedData(Action<string, string>? logCallback = null)
    {
        var threats = new List<ThreatItem>();
        var tempDir = Path.GetTempPath();
        var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);

        logCallback?.Invoke("INFO", "Hunting for staged stolen credential archives in temporary folders...");

        // 1. Scan Temp Directory for recently created stealer folders
        ScanDirectoryForStaging(tempDir, threats, logCallback);

        // 2. Scan AppData Directory for anomalous staging folders
        ScanDirectoryForStaging(appData, threats, logCallback, maxDepth: 1);

        return threats;
    }

    private static void ScanDirectoryForStaging(string rootDir, List<ThreatItem> threats, Action<string, string>? logCallback, int maxDepth = 2)
    {
        if (!Directory.Exists(rootDir)) return;

        try
        {
            var directories = Directory.GetDirectories(rootDir);
            foreach (var dir in directories)
            {
                var dirName = Path.GetFileName(dir);

                // Never scan StealerHunter's own app data or quarantine folder
                if (dirName.Equals("StealerHunter", StringComparison.OrdinalIgnoreCase) ||
                    dir.Contains(@"\StealerHunter\Quarantine", StringComparison.OrdinalIgnoreCase) ||
                    dir.Contains(@"\Quarantine", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                // Check directory name or contents
                if (IsStagingFolderName(dirName))
                {
                    var threat = new ThreatItem
                    {
                        Name = $"Staged Credential Dump Folder: {dirName}",
                        Category = ThreatCategory.StagedExfiltrationData,
                        Severity = ThreatSeverity.Critical,
                        Description = $"Folder contains naming patterns typical of Infostealer exfiltration dumps: '{dir}'",
                        FilePath = dir,
                        TargetTarget = "Staged Browser/Wallet Dumps"
                    };
                    threats.Add(threat);
                    logCallback?.Invoke("DANGER", $"[CRITICAL] Staged dump folder found: {dir}");
                    continue;
                }

                // Check inside directory for stealer keywords
                try
                {
                    var files = Directory.GetFiles(dir);
                    int matchCount = 0;
                    foreach (var file in files)
                    {
                        var fn = Path.GetFileName(file);
                        if (StealerDumpKeywords.Contains(fn)) matchCount++;
                    }

                    if (matchCount >= 2)
                    {
                        var threat = new ThreatItem
                        {
                            Name = $"Infostealer Staging Directory ({matchCount} dump files)",
                            Category = ThreatCategory.StagedExfiltrationData,
                            Severity = ThreatSeverity.Critical,
                            Description = $"Directory '{dir}' contains {matchCount} files typically dumped by infostealers (passwords, cookies, system info)!",
                            FilePath = dir,
                            TargetTarget = "Harvested Passwords & Cookies"
                        };
                        threats.Add(threat);
                        logCallback?.Invoke("DANGER", $"[CRITICAL] Harvested credential dump in {dir}");
                    }
                }
                catch
                {
                    // Access restricted
                }
            }

            // Also check for recent ZIP files in temp that contain passwords.txt or cookies.txt
            var zipFiles = Directory.GetFiles(rootDir, "*.zip");
            var now = DateTime.Now;
            foreach (var zip in zipFiles)
            {
                try
                {
                    var fi = new FileInfo(zip);
                    // Check if modified in the last 48 hours
                    if ((now - fi.LastWriteTime).TotalHours <= 48)
                    {
                        if (IsZipContainingCredentials(zip))
                        {
                            var threat = new ThreatItem
                            {
                                Name = $"Exfiltration Archive: {Path.GetFileName(zip)}",
                                Category = ThreatCategory.StagedExfiltrationData,
                                Severity = ThreatSeverity.Critical,
                                Description = $"Zip file in temp directory contains dumped passwords/cookies ready to be uploaded to C2 server: '{zip}'",
                                FilePath = zip,
                                TargetTarget = "Staged Zip Exfiltration Payload"
                            };
                            threats.Add(threat);
                            logCallback?.Invoke("DANGER", $"[CRITICAL] Stealer zip archive ready for exfiltration: {zip}");
                        }
                    }
                }
                catch
                {
                    // Ignore locked zips
                }
            }
        }
        catch
        {
            // Permission or directory enumeration error
        }
    }

    private static bool IsStagingFolderName(string name)
    {
        var lower = name.ToLowerInvariant();
        return lower is "wallets" or "passwords" or "cookies_dump" or "browser_dump" or "stolen_data" or "logs_stealer";
    }

    private static bool IsZipContainingCredentials(string zipPath)
    {
        try
        {
            using var archive = ZipFile.OpenRead(zipPath);
            int matchCount = 0;
            foreach (var entry in archive.Entries)
            {
                var entryName = Path.GetFileName(entry.FullName);
                if (StealerDumpKeywords.Contains(entryName))
                {
                    matchCount++;
                    if (matchCount >= 2) return true;
                }
            }
        }
        catch
        {
            // Corrupt or encrypted zip
        }

        return false;
    }
}
