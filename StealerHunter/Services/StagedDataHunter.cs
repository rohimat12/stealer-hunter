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

                // Check inside directory for stealer keywords or high-entropy staging
                try
                {
                    var files = Directory.GetFiles(dir);
                    int matchCount = 0;
                    bool hasHighEntropyDump = false;

                    foreach (var file in files)
                    {
                        var fn = Path.GetFileName(file);
                        if (StealerDumpKeywords.Contains(fn)) matchCount++;

                        if (EntropyHelper.ContainsPlaintextCredentials(file, out _))
                        {
                            matchCount++;
                        }

                        if (EntropyHelper.IsSuspiciousHighEntropyStaging(file, out _))
                        {
                            hasHighEntropyDump = true;
                        }
                    }

                    // Only flag if folder name matches AND contains at least 1 dump file, OR contains 2+ confirmed dump files
                    if ((IsStagingFolderName(dirName) && (matchCount >= 1 || hasHighEntropyDump)) || matchCount >= 2)
                    {
                        var threat = new ThreatItem
                        {
                            Name = $"Infostealer Staging Directory: {dirName}",
                            Category = ThreatCategory.StagedExfiltrationData,
                            Severity = ThreatSeverity.Critical,
                            Description = $"Directory '{dir}' contains confirmed stealer artifacts ({matchCount} dump files, encrypted payload: {hasHighEntropyDump})!",
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

            // Also check candidate files in temporary folders
            var candidateFiles = Directory.GetFiles(rootDir, "*.*");
            foreach (var candidate in candidateFiles)
            {
                try
                {
                    var fi = new FileInfo(candidate);
                    if (fi.Length is < 32 or > 15_000_000 || (now - fi.LastWriteTime).TotalDays > 7) continue;

                    // 1. Check for plaintext credential markers in ANY file (e.g. .tmp, .dat, .log, .txt, etc.)
                    if (EntropyHelper.ContainsPlaintextCredentials(candidate, out var credReason))
                    {
                        var threat = new ThreatItem
                        {
                            Name = $"Harvested Credential Dump: {Path.GetFileName(candidate)}",
                            Category = ThreatCategory.StagedExfiltrationData,
                            Severity = ThreatSeverity.Critical,
                            Description = $"Staged credential dump detected in temporary folder ({credReason}): '{candidate}'",
                            FilePath = candidate,
                            TargetTarget = "Staged Credential Dump"
                        };
                        threats.Add(threat);
                        logCallback?.Invoke("DANGER", $"[CRITICAL] Staged credential dump detected: {candidate} ({credReason})");
                        continue;
                    }

                    // 2. High-entropy encrypted credential dumps (only disguised text/data extensions)
                    var ext = Path.GetExtension(candidate).ToLowerInvariant();
                    if (ext is ".txt" or ".log" or ".dat" or ".json" or ".csv" or ".ini")
                    {
                        if (fi.Length is >= 512 and <= 6_000_000)
                        {
                            if (EntropyHelper.IsSuspiciousHighEntropyStaging(candidate, out var entropy))
                            {
                                var threat = new ThreatItem
                                {
                                    Name = $"Encrypted Staging Dump: {Path.GetFileName(candidate)}",
                                    Category = ThreatCategory.StagedExfiltrationData,
                                    Severity = ThreatSeverity.Critical,
                                    Description = $"High-entropy staging file detected (Shannon Entropy: {entropy:F2}/8.00). Infostealers (Lumma/Stealc) obfuscate dumped credentials in temp files prior to exfiltration: '{candidate}'",
                                    FilePath = candidate,
                                    TargetTarget = "Encrypted Exfiltration Dump"
                                };
                                threats.Add(threat);
                                logCallback?.Invoke("DANGER", $"[CRITICAL] High-entropy encrypted dump: {candidate} (Entropy: {entropy:F2})");
                            }
                        }
                    }
                }
                catch
                {
                    // Ignore locked or inaccessible files
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
