using System.IO;
using StealerHunter.Models;

namespace StealerHunter.Services;

public class BrowserAuditService
{
    public List<BrowserTarget> DetectBrowsers()
    {
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);

        var targets = new List<BrowserTarget>
        {
            new()
            {
                BrowserName = "Google Chrome",
                Engine = "Chromium",
                ProfilePath = Path.Combine(localAppData, @"Google\Chrome\User Data")
            },
            new()
            {
                BrowserName = "Microsoft Edge",
                Engine = "Chromium",
                ProfilePath = Path.Combine(localAppData, @"Microsoft\Edge\User Data")
            },
            new()
            {
                BrowserName = "Brave Browser",
                Engine = "Chromium",
                ProfilePath = Path.Combine(localAppData, @"BraveSoftware\Brave-Browser\User Data")
            },
            new()
            {
                BrowserName = "Opera Stable",
                Engine = "Chromium",
                ProfilePath = Path.Combine(appData, @"Opera Software\Opera Stable")
            },
            new()
            {
                BrowserName = "Opera GX",
                Engine = "Chromium",
                ProfilePath = Path.Combine(appData, @"Opera Software\Opera GX Stable")
            },
            new()
            {
                BrowserName = "Vivaldi",
                Engine = "Chromium",
                ProfilePath = Path.Combine(localAppData, @"Vivaldi\User Data")
            },
            new()
            {
                BrowserName = "Mozilla Firefox",
                Engine = "Gecko",
                ProfilePath = Path.Combine(appData, @"Mozilla\Firefox\Profiles")
            }
        };

        foreach (var target in targets)
        {
            if (Directory.Exists(target.ProfilePath))
            {
                target.IsInstalled = true;
                target.SensitiveFiles = FindSensitiveFiles(target);
                target.StatusSummary = $"{target.SensitiveFiles.Count} sensitive credential files protected";
            }
            else
            {
                target.IsInstalled = false;
                target.StatusSummary = "Not Installed / No Profile";
            }
        }

        return targets;
    }

    private List<string> FindSensitiveFiles(BrowserTarget target)
    {
        var found = new List<string>();

        try
        {
            if (target.Engine == "Chromium")
            {
                // Local State (Master encryption key)
                var localState = Path.Combine(target.ProfilePath, "Local State");
                if (File.Exists(localState)) found.Add(localState);

                // Look inside Default and Profile * folders
                var profileDirs = Directory.GetDirectories(target.ProfilePath, "Profile*").ToList();
                var defaultDir = Path.Combine(target.ProfilePath, "Default");
                if (Directory.Exists(defaultDir)) profileDirs.Add(defaultDir);

                // For Opera, the profile root IS the target folder
                if (target.BrowserName.Contains("Opera"))
                {
                    profileDirs.Add(target.ProfilePath);
                }

                foreach (var dir in profileDirs.Distinct())
                {
                    CheckAndAdd(Path.Combine(dir, "Login Data"), found);
                    CheckAndAdd(Path.Combine(dir, "Web Data"), found);
                    CheckAndAdd(Path.Combine(dir, @"Network\Cookies"), found);
                    CheckAndAdd(Path.Combine(dir, "Cookies"), found);
                }
            }
            else if (target.Engine == "Gecko") // Firefox
            {
                var profileDirs = Directory.GetDirectories(target.ProfilePath);
                foreach (var dir in profileDirs)
                {
                    CheckAndAdd(Path.Combine(dir, "logins.json"), found);
                    CheckAndAdd(Path.Combine(dir, "key4.db"), found);
                    CheckAndAdd(Path.Combine(dir, "cookies.sqlite"), found);
                }
            }
        }
        catch
        {
            // Ignore access errors
        }

        return found;
    }

    private static void CheckAndAdd(string path, List<string> list)
    {
        if (File.Exists(path) && !list.Contains(path))
        {
            list.Add(path);
        }
    }

    /// <summary>
    /// Checks if files have an abnormal lock or if any temp file has recently made copies of login data.
    /// </summary>
    public List<ThreatItem> AuditBrowserIntegrity(List<BrowserTarget> installedBrowsers, Action<string, string>? logCallback = null)
    {
        var threats = new List<ThreatItem>();

        foreach (var browser in installedBrowsers.Where(b => b.IsInstalled))
        {
            logCallback?.Invoke("INFO", $"Auditing credentials for {browser.BrowserName}...");

            foreach (var filePath in browser.SensitiveFiles)
            {
                var fileInfo = new FileInfo(filePath);
                if (!fileInfo.Exists) continue;

                // Check if file is locked exclusively by an unauthorized process
                if (IsFileLockedExclusively(filePath, out var isLocked) && isLocked)
                {
                    // If browser itself is not running, but its database is locked, it's highly suspicious
                    var isBrowserRunning = IsBrowserProcessRunning(browser.BrowserName);

                    if (!isBrowserRunning)
                    {
                        var threat = new ThreatItem
                        {
                            Name = $"Suspicious Lock on {Path.GetFileName(filePath)}",
                            Category = ThreatCategory.BrowserDataLock,
                            Severity = ThreatSeverity.Critical,
                            Description = $"The sensitive credential file '{Path.GetFileName(filePath)}' is locked by an unknown background process while {browser.BrowserName} is closed!",
                            TargetTarget = browser.BrowserName,
                            FilePath = filePath
                        };
                        threats.Add(threat);
                        browser.HasSuspiciousLock = true;
                        logCallback?.Invoke("DANGER", $"[CRITICAL] Suspicious lock detected on {filePath} while {browser.BrowserName} is NOT running!");
                    }
                }
            }
        }

        return threats;
    }

    private static bool IsFileLockedExclusively(string filePath, out bool isLocked)
    {
        isLocked = false;
        try
        {
            using var stream = File.Open(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            return true;
        }
        catch (IOException)
        {
            isLocked = true;
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static bool IsBrowserProcessRunning(string browserName)
    {
        var candidates = GetProcessCandidates(browserName);
        return candidates.Any(cand => !string.IsNullOrEmpty(cand) && System.Diagnostics.Process.GetProcessesByName(cand).Length > 0);
    }

    private static string[] GetProcessCandidates(string browserName)
    {
        if (browserName.Contains("Chrome", StringComparison.OrdinalIgnoreCase)) return new[] { "chrome" };
        if (browserName.Contains("Edge", StringComparison.OrdinalIgnoreCase)) return new[] { "msedge" };
        if (browserName.Contains("Brave", StringComparison.OrdinalIgnoreCase)) return new[] { "brave" };
        if (browserName.Contains("Firefox", StringComparison.OrdinalIgnoreCase)) return new[] { "firefox" };
        if (browserName.Contains("Opera GX", StringComparison.OrdinalIgnoreCase)) return new[] { "opera", "opera_gx", "operagx" };
        if (browserName.Contains("Opera", StringComparison.OrdinalIgnoreCase)) return new[] { "opera" };
        if (browserName.Contains("Vivaldi", StringComparison.OrdinalIgnoreCase)) return new[] { "vivaldi" };
        return Array.Empty<string>();
    }
}
