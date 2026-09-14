using Microsoft.Win32;
using System.IO;
using StealerHunter.Models;

namespace StealerHunter.Services;

public class PersistenceService
{
    private static readonly string[] RunKeys = new[]
    {
        @"Software\Microsoft\Windows\CurrentVersion\Run",
        @"Software\Microsoft\Windows\CurrentVersion\RunOnce",
        @"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"
    };

    private static readonly HashSet<string> CoreSystemNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "explorer.exe", "svchost.exe", "spoolsv.exe", "csrss.exe", "lsass.exe",
        "services.exe", "smss.exe", "wininit.exe", "winlogon.exe", "taskhostw.exe"
    };

    public List<ThreatItem> ScanPersistence(Action<string, string>? logCallback = null)
    {
        var threats = new List<ThreatItem>();
        logCallback?.Invoke("INFO", "Scanning 64-bit and 32-bit (WOW64) Registry Startup keys...");

        // 1. Scan HKCU and HKLM in both 64-bit and 32-bit registry views
        var registryTargets = new (RegistryHive Hive, RegistryView View, string Label)[]
        {
            (RegistryHive.CurrentUser, RegistryView.Registry64, "HKCU (64-bit)"),
            (RegistryHive.CurrentUser, RegistryView.Registry32, "HKCU (WOW6432)"),
            (RegistryHive.LocalMachine, RegistryView.Registry64, "HKLM (64-bit)"),
            (RegistryHive.LocalMachine, RegistryView.Registry32, "HKLM (WOW6432)")
        };

        foreach (var target in registryTargets)
        {
            foreach (var subKey in RunKeys)
            {
                ScanRegistryView(target.Hive, target.View, subKey, target.Label, threats, logCallback);
            }
        }

        // 2. Scan User Startup Folder
        var startupPath = Environment.GetFolderPath(Environment.SpecialFolder.Startup);
        if (Directory.Exists(startupPath))
        {
            try
            {
                var files = Directory.GetFiles(startupPath);
                foreach (var file in files)
                {
                    var ext = Path.GetExtension(file).ToLowerInvariant();
                    if (ext is ".exe" or ".vbs" or ".bat" or ".cmd" or ".ps1" or ".js")
                    {
                        var threat = new ThreatItem
                        {
                            Name = $"Rogue Startup File: {Path.GetFileName(file)}",
                            Category = ThreatCategory.PersistenceAutorun,
                            Severity = ThreatSeverity.High,
                            Description = $"Executable or script found directly inside Windows Startup folder: '{file}'",
                            FilePath = file,
                            TargetTarget = "Windows Auto-Startup Folder"
                        };
                        threats.Add(threat);
                        logCallback?.Invoke("WARN", $"[HIGH] Startup folder item detected: {file}");
                    }
                }
            }
            catch
            {
                // Access issues
            }
        }

        // 3. Scan Suspicious Windows Folders for Rogue Binaries (e.g. C:\Windows\Resources)
        ScanSuspiciousWindowsFolders(threats, logCallback);

        return threats;
    }

    private static void ScanRegistryView(RegistryHive hive, RegistryView view, string subKeyPath, string rootLabel, List<ThreatItem> threats, Action<string, string>? logCallback)
    {
        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(hive, view);
            using var key = baseKey.OpenSubKey(subKeyPath, false);
            if (key == null) return;

            var valueNames = key.GetValueNames();
            var tempDir = Path.GetTempPath().TrimEnd('\\');
            var winDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows).TrimEnd('\\');
            var sys32Dir = Environment.GetFolderPath(Environment.SpecialFolder.System).TrimEnd('\\');

            foreach (var valName in valueNames)
            {
                var rawValue = key.GetValue(valName)?.ToString() ?? string.Empty;
                if (string.IsNullOrWhiteSpace(rawValue)) continue;

                var lowerValue = rawValue.ToLowerInvariant();

                // Skip StealerHunter's own autostart entry
                if (valName.Equals("StealerHunter", StringComparison.OrdinalIgnoreCase)) continue;

                string cleanPath = ExtractFilePath(rawValue);
                string fileName = Path.GetFileName(cleanPath);

                // Check for suspicious traits
                bool pointsToTemp = lowerValue.Contains(tempDir.ToLowerInvariant()) || lowerValue.Contains(@"\appdata\local\temp");
                bool pointsToResources = lowerValue.Contains(@"\windows\resources") || lowerValue.Contains(@"\resources\themes");
                bool isHiddenScript = (lowerValue.Contains("powershell") && (lowerValue.Contains("-enc") || lowerValue.Contains("-w hidden"))) ||
                                      lowerValue.Contains("cmd.exe /c") ||
                                      lowerValue.Contains("wscript.exe") ||
                                      lowerValue.Contains("cscript.exe");
                bool hasScriptExt = lowerValue.EndsWith(".vbs") || lowerValue.EndsWith(".bat") || lowerValue.EndsWith(".js") || lowerValue.EndsWith(".ps1");

                // Masquerading check in autorun: e.g. "explorer.exe" or "svchost.exe" pointing outside official dirs
                bool isMasquerading = false;
                if (CoreSystemNames.Contains(fileName))
                {
                    if (fileName.Equals("explorer.exe", StringComparison.OrdinalIgnoreCase))
                    {
                        var dir = Path.GetDirectoryName(cleanPath) ?? "";
                        if (!string.IsNullOrEmpty(dir) && !dir.Equals(winDir, StringComparison.OrdinalIgnoreCase))
                        {
                            isMasquerading = true;
                        }
                    }
                    else
                    {
                        var dir = Path.GetDirectoryName(cleanPath) ?? "";
                        if (!string.IsNullOrEmpty(dir) && !dir.Equals(sys32Dir, StringComparison.OrdinalIgnoreCase))
                        {
                            isMasquerading = true;
                        }
                    }
                }

                if (pointsToTemp || pointsToResources || isMasquerading || isHiddenScript || hasScriptExt)
                {
                    string viewPrefix = view == RegistryView.Registry32 ? "WOW6432Node\\" : "";
                    string hiveName = hive == RegistryHive.CurrentUser ? "HKCU" : "HKLM";
                    string formattedKey = $"{hiveName}\\{viewPrefix}{subKeyPath} -> {valName}";

                    var threat = new ThreatItem
                    {
                        Name = isMasquerading ? $"Masquerading Autorun ({valName}): {fileName}" : $"Suspicious Autorun Key: {valName}",
                        Category = ThreatCategory.PersistenceAutorun,
                        Severity = (pointsToResources || isMasquerading || pointsToTemp || isHiddenScript) ? ThreatSeverity.Critical : ThreatSeverity.High,
                        Description = isMasquerading
                            ? $"Malicious autorun entry masquerading as system process '{fileName}' from untrusted path: '{rawValue}'"
                            : $"Registry autorun entry points to suspicious location or script: '{rawValue}'",
                        FilePath = formattedKey,
                        TargetTarget = "Windows Startup Registry"
                    };

                    threats.Add(threat);
                    logCallback?.Invoke("DANGER", $"[CRITICAL] Suspicious autorun: {formattedKey} => {rawValue}");
                }
            }
        }
        catch
        {
            // Access permission restricted
        }
    }

    private static void ScanSuspiciousWindowsFolders(List<ThreatItem> threats, Action<string, string>? logCallback)
    {
        try
        {
            var winDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            var resourcesDir = Path.Combine(winDir, "Resources");

            if (!Directory.Exists(resourcesDir)) return;

            var enumOptions = new EnumerationOptions
            {
                IgnoreInaccessible = true,
                RecurseSubdirectories = true,
                AttributesToSkip = FileAttributes.None // Do NOT skip Hidden or System files!
            };

            // Legitimate Windows theme directories never legitimately contain standalone .exe files
            var rogueExecutables = Directory.GetFiles(resourcesDir, "*.exe", enumOptions);
            foreach (var exeFile in rogueExecutables)
            {
                var fileName = Path.GetFileName(exeFile);
                var threat = new ThreatItem
                {
                    Name = $"Rogue System Masquerader: {fileName}",
                    Category = ThreatCategory.PersistenceAutorun,
                    Severity = ThreatSeverity.Critical,
                    Description = $"Malicious executable discovered in Windows Resources folder: '{exeFile}'. Legitimate themes do not place standalone binaries here.",
                    FilePath = exeFile,
                    TargetTarget = "Windows Resources Theme Directory"
                };

                threats.Add(threat);
                logCallback?.Invoke("DANGER", $"[CRITICAL] Rogue binary found in Resources: {exeFile}");
            }

            // Also check for known Mofksys configuration/worm artifacts (e.g. icsys.icn)
            var icnFiles = Directory.GetFiles(resourcesDir, "icsys.*", enumOptions);
            foreach (var icnFile in icnFiles)
            {
                if (threats.Any(t => t.FilePath.Equals(icnFile, StringComparison.OrdinalIgnoreCase))) continue;

                var threat = new ThreatItem
                {
                    Name = $"Mofksys Worm Artifact: {Path.GetFileName(icnFile)}",
                    Category = ThreatCategory.PersistenceAutorun,
                    Severity = ThreatSeverity.Critical,
                    Description = $"Associated Worm:Win32/Mofksys spyware artifact: '{icnFile}'",
                    FilePath = icnFile,
                    TargetTarget = "Mofksys Payload Files"
                };

                threats.Add(threat);
                logCallback?.Invoke("DANGER", $"[CRITICAL] Mofksys payload artifact: {icnFile}");
            }
        }
        catch
        {
            // Permission or directory lock
        }
    }

    public static string ExtractFilePath(string rawCommand)
    {
        if (string.IsNullOrWhiteSpace(rawCommand)) return string.Empty;

        string trimmed = rawCommand.Trim();
        if (trimmed.StartsWith("\""))
        {
            int nextQuote = trimmed.IndexOf('\"', 1);
            if (nextQuote > 1)
            {
                return trimmed.Substring(1, nextQuote - 1);
            }
        }

        int firstSpace = trimmed.IndexOf(' ');
        if (firstSpace > 0)
        {
            string candidate = trimmed.Substring(0, firstSpace);
            if (candidate.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) || candidate.Contains("\\"))
            {
                return candidate;
            }
        }

        return trimmed;
    }
}

