using System.Diagnostics;
using System.IO;
using System.Management;
using StealerHunter.Models;

namespace StealerHunter.Services;

public class ProcessHunterService
{
    private static readonly HashSet<string> SystemProcesses = new(StringComparer.OrdinalIgnoreCase)
    {
        "svchost.exe", "csrss.exe", "lsass.exe", "smss.exe", "wininit.exe",
        "winlogon.exe", "services.exe", "taskhostw.exe", "conhost.exe"
    };

    public List<ThreatItem> ScanProcesses(Action<string, string>? logCallback = null)
    {
        var threats = new List<ThreatItem>();
        var tempDir = Path.GetTempPath().TrimEnd('\\');
        var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var publicFolder = Environment.GetEnvironmentVariable("PUBLIC") ?? @"C:\Users\Public";
        var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var downloads = Path.Combine(userProfile, "Downloads");
        var system32 = Environment.GetFolderPath(Environment.SpecialFolder.System);
        var currentPid = Environment.ProcessId;

        logCallback?.Invoke("INFO", "Inspecting active processes and memory space...");

        // Retrieve process command lines via WMI
        var commandLines = GetProcessCommandLines();

        var runningProcesses = Process.GetProcesses();
        foreach (var proc in runningProcesses)
        {
            try
            {
                if (proc.Id == currentPid || proc.Id <= 4) continue;

                string? exePath = null;
                try
                {
                    exePath = proc.MainModule?.FileName;
                }
                catch
                {
                    // Access denied for protected system processes (normal)
                }

                var procName = proc.ProcessName;
                commandLines.TryGetValue(proc.Id, out var cmdLine);
                cmdLine ??= string.Empty;

                // 1. Check for Masquerading System Processes & Resources directory abuse
                if (!string.IsNullOrEmpty(exePath))
                {
                    var dir = Path.GetDirectoryName(exePath) ?? "";
                    var winDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
                    var resourcesDir = Path.Combine(winDir, "Resources");

                    // Immediate flag if running from Windows Resources (e.g. Themes)
                    if (exePath.StartsWith(resourcesDir, StringComparison.OrdinalIgnoreCase))
                    {
                        var threat = new ThreatItem
                        {
                            Name = $"Rogue Process from Resources: {procName}",
                            Category = ThreatCategory.SuspiciousProcess,
                            Severity = ThreatSeverity.Critical,
                            Description = $"Process is actively executing from Windows Resources folder, typical of Mofksys/Icsys stealer: '{exePath}'",
                            FilePath = exePath,
                            ProcessId = proc.Id,
                            TargetTarget = "Windows Themes Abuse / Active Stealer"
                        };
                        threats.Add(threat);
                        logCallback?.Invoke("DANGER", $"[CRITICAL] Rogue Resources process: {procName} (PID {proc.Id}) at {exePath}");
                        continue;
                    }

                    // Check explorer.exe
                    if (procName.Equals("explorer", StringComparison.OrdinalIgnoreCase))
                    {
                        if (!dir.Equals(winDir, StringComparison.OrdinalIgnoreCase))
                        {
                            var threat = new ThreatItem
                            {
                                Name = $"Masquerading Explorer Process: {procName}",
                                Category = ThreatCategory.SuspiciousProcess,
                                Severity = ThreatSeverity.Critical,
                                Description = $"Process is disguised as explorer.exe but running from unauthorized folder: '{exePath}'",
                                FilePath = exePath,
                                ProcessId = proc.Id,
                                TargetTarget = "Core System Masquerading"
                            };
                            threats.Add(threat);
                            logCallback?.Invoke("DANGER", $"[CRITICAL] Fake explorer.exe process: PID {proc.Id} at {exePath}");
                            continue;
                        }
                    }
                    // Check other core system processes
                    else if (SystemProcesses.Contains(procName + ".exe"))
                    {
                        if (!dir.Equals(system32, StringComparison.OrdinalIgnoreCase))
                        {
                            var threat = new ThreatItem
                            {
                                Name = $"Masquerading System Process: {procName}",
                                Category = ThreatCategory.SuspiciousProcess,
                                Severity = ThreatSeverity.Critical,
                                Description = $"Process is masquerading as a Windows core service but is running from an unauthorized path: '{exePath}'",
                                FilePath = exePath,
                                ProcessId = proc.Id,
                                TargetTarget = "System Integrity / Credential Memory"
                            };
                            threats.Add(threat);
                            logCallback?.Invoke("DANGER", $"[CRITICAL] Masquerading process: {procName} (PID {proc.Id}) at {exePath}");
                            continue;
                        }
                    }
                }

                // 2. Check for Process running from Temp, Downloads, or Public folders
                if (!string.IsNullOrEmpty(exePath))
                {
                    bool isSuspiciousLocation =
                        exePath.StartsWith(tempDir, StringComparison.OrdinalIgnoreCase) ||
                        exePath.StartsWith(Path.Combine(localAppData, "Temp"), StringComparison.OrdinalIgnoreCase) ||
                        exePath.StartsWith(publicFolder, StringComparison.OrdinalIgnoreCase) ||
                        exePath.StartsWith(downloads, StringComparison.OrdinalIgnoreCase);

                    // Check for executable with double extensions like .pdf.exe, .jpg.exe
                    var fileName = Path.GetFileName(exePath);
                    var hasDoubleExtension = HasDoubleExtension(fileName);

                    if (isSuspiciousLocation || hasDoubleExtension)
                    {
                        // Exclude known dev runners if present, but flag executable binaries
                        var threat = new ThreatItem
                        {
                            Name = hasDoubleExtension ? $"Fake File Extension Dropper: {fileName}" : $"Suspicious Executable from High-Risk Folder: {fileName}",
                            Category = ThreatCategory.SuspiciousProcess,
                            Severity = hasDoubleExtension ? ThreatSeverity.Critical : ThreatSeverity.High,
                            Description = $"Active process running from temporary/untrusted directory '{exePath}'. Infostealers (Lumma, Stealc) frequently execute from these locations.",
                            FilePath = exePath,
                            ProcessId = proc.Id,
                            TargetTarget = "Active System Memory"
                        };
                        threats.Add(threat);
                        logCallback?.Invoke("WARN", $"[HIGH] Process running from high-risk path: {procName} (PID {proc.Id}) at {exePath}");
                        continue;
                    }
                }

                // 3. Check for Suspicious PowerShell / Script execution
                if (procName.Equals("powershell", StringComparison.OrdinalIgnoreCase) ||
                    procName.Equals("pwsh", StringComparison.OrdinalIgnoreCase) ||
                    procName.Equals("mshta", StringComparison.OrdinalIgnoreCase) ||
                    procName.Equals("wscript", StringComparison.OrdinalIgnoreCase) ||
                    procName.Equals("cscript", StringComparison.OrdinalIgnoreCase))
                {
                    if (IsSuspiciousCommandLine(cmdLine))
                    {
                        var threat = new ThreatItem
                        {
                            Name = $"Malicious Script Execution ({procName})",
                            Category = ThreatCategory.MaliciousScript,
                            Severity = ThreatSeverity.Critical,
                            Description = $"Script runner detected with obfuscated/hidden arguments commonly used by infostealer droppers: '{cmdLine}'",
                            FilePath = exePath ?? procName,
                            ProcessId = proc.Id,
                            TargetTarget = "Stealer Dropper / PowerShell Payload"
                        };
                        threats.Add(threat);
                        logCallback?.Invoke("DANGER", $"[CRITICAL] Suspicious hidden script detected: PID {proc.Id} => {cmdLine}");
                    }
                }
            }
            catch
            {
                // Process may have exited during scan
            }
        }

        return threats;
    }

    private static bool HasDoubleExtension(string filename)
    {
        var parts = filename.Split('.');
        if (parts.Length >= 3)
        {
            var fakeExt = parts[^2].ToLowerInvariant();
            if (fakeExt is "pdf" or "jpg" or "png" or "docx" or "xlsx" or "mp4" or "zip" or "txt")
            {
                var realExt = parts[^1].ToLowerInvariant();
                if (realExt is "exe" or "scr" or "com" or "bat" or "vbs") return true;
            }
        }
        return false;
    }

    private static bool IsSuspiciousCommandLine(string cmdLine)
    {
        if (string.IsNullOrWhiteSpace(cmdLine)) return false;

        var lower = cmdLine.ToLowerInvariant();
        bool hasHidden = lower.Contains("-w hidden") || lower.Contains("-windowstyle hidden") || lower.Contains("/b /nologo");
        bool hasEncoded = lower.Contains("-enc") || lower.Contains("-encodedcommand");
        bool hasDownload = lower.Contains("downloadstring") || lower.Contains("iwr") || lower.Contains("invoke-webrequest");
        bool hasBypass = lower.Contains("bypass") || lower.Contains("unrestricted");

        return (hasHidden && (hasEncoded || hasDownload)) || (hasEncoded && hasBypass);
    }

    private static Dictionary<int, string> GetProcessCommandLines()
    {
        var result = new Dictionary<int, string>();
        try
        {
            using var searcher = new ManagementObjectSearcher("SELECT ProcessId, CommandLine FROM Win32_Process");
            using var objects = searcher.Get();

            foreach (var obj in objects)
            {
                if (obj["ProcessId"] is uint pid && obj["CommandLine"] is string cmd)
                {
                    result[(int)pid] = cmd;
                }
            }
        }
        catch
        {
            // WMI might be restricted or busy
        }

        return result;
    }
}
