using Microsoft.Win32;
using System.Diagnostics;
using System.IO;
using StealerHunter.Models;

namespace StealerHunter.Services;

public class QuarantineService
{
    private static readonly string QuarantineDir = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
        "StealerHunter",
        "Quarantine"
    );

    public static string GetQuarantineDirectory() => QuarantineDir;

    public bool NeutralizeThreat(ThreatItem threat, out string resultMessage)
    {
        bool success = true;
        var messages = new List<string>();

        // 1. If there's an active Process ID, terminate it first
        if (threat.ProcessId.HasValue && threat.ProcessId.Value > 0)
        {
            if (KillProcess(threat.ProcessId.Value, out var killMsg))
            {
                messages.Add(killMsg);
            }
            else
            {
                messages.Add(killMsg);
                success = false;
            }
        }

        // 2. If it's a Registry autorun entry
        if (threat.Category == ThreatCategory.PersistenceAutorun && threat.FilePath.Contains("->"))
        {
            if (RemoveRegistryAutorun(threat.FilePath, out var regMsg))
            {
                messages.Add(regMsg);
            }
            else
            {
                messages.Add(regMsg);
                success = false;
            }
        }
        // 3. If it's an executable file or staged dump file/folder on disk
        if (!string.IsNullOrEmpty(threat.FilePath) && !threat.FilePath.Contains("->"))
        {
            if (File.Exists(threat.FilePath))
            {
                if (QuarantineFile(threat.FilePath, out var qMsg))
                {
                    messages.Add(qMsg);
                }
                else
                {
                    messages.Add(qMsg);
                    success = false;
                }
            }
            else if (Directory.Exists(threat.FilePath))
            {
                if (QuarantineDirectory(threat.FilePath, out var qDirMsg))
                {
                    messages.Add(qDirMsg);
                }
                else
                {
                    messages.Add(qDirMsg);
                    success = false;
                }
            }
        }

        threat.IsResolved = success;
        threat.StatusMessage = string.Join("; ", messages);
        resultMessage = threat.StatusMessage;
        return success;
    }

    public static bool KillProcess(int pid, out string message)
    {
        try
        {
            var proc = Process.GetProcessById(pid);
            var procName = proc.ProcessName;
            proc.Kill(entireProcessTree: true);
            message = $"Terminated process '{procName}' (PID {pid})";
            return true;
        }
        catch (ArgumentException)
        {
            message = $"Process with PID {pid} was already terminated";
            return true;
        }
        catch (Exception ex)
        {
            message = $"Failed to terminate PID {pid}: {ex.Message}";
            return false;
        }
    }

    public static bool QuarantineFile(string filePath, out string message)
    {
        try
        {
            if (!Directory.Exists(QuarantineDir))
            {
                Directory.CreateDirectory(QuarantineDir);
            }

            if (!File.Exists(filePath))
            {
                message = $"Target file already removed or does not exist: {filePath}";
                return true;
            }

            // Strip ReadOnly, Hidden, System attributes so Windows won't block moving/deleting
            try
            {
                File.SetAttributes(filePath, FileAttributes.Normal);
            }
            catch
            {
                // Proceed anyway
            }

            var fileName = Path.GetFileName(filePath);
            var destPath = Path.Combine(QuarantineDir, $"{DateTime.Now:yyyyMMdd_HHmmss}_{fileName}.quarantined");

            try
            {
                File.Move(filePath, destPath, overwrite: true);
            }
            catch
            {
                // Fallback: Copy and delete
                File.Copy(filePath, destPath, overwrite: true);
                File.Delete(filePath);
            }

            message = $"File isolated to quarantine: {Path.GetFileName(destPath)}";
            return true;
        }
        catch (Exception ex)
        {
            message = $"Failed to quarantine file '{filePath}': {ex.Message}";
            return false;
        }
    }

    public static bool QuarantineDirectory(string dirPath, out string message)
    {
        try
        {
            if (!Directory.Exists(QuarantineDir))
            {
                Directory.CreateDirectory(QuarantineDir);
            }

            var dirName = Path.GetFileName(dirPath.TrimEnd('\\'));
            var destPath = Path.Combine(QuarantineDir, $"{DateTime.Now:yyyyMMdd_HHmmss}_{dirName}_dump");

            Directory.Move(dirPath, destPath);
            message = $"Dump directory isolated: {Path.GetFileName(destPath)}";
            return true;
        }
        catch (Exception ex)
        {
            message = $"Failed to quarantine directory: {ex.Message}";
            return false;
        }
    }

    public static bool RemoveRegistryAutorun(string formattedKey, out string message)
    {
        try
        {
            // Expected format: "HKCU\Software\... -> ValueName" or "HKLM\WOW6432Node\Software\... -> ValueName"
            var parts = formattedKey.Split("->");
            if (parts.Length != 2)
            {
                message = "Invalid registry format";
                return false;
            }

            var fullPath = parts[0].Trim();
            var valueName = parts[1].Trim();

            bool isCurrentUser = fullPath.StartsWith("HKCU", StringComparison.OrdinalIgnoreCase);
            var hive = isCurrentUser ? RegistryHive.CurrentUser : RegistryHive.LocalMachine;

            bool isWow64 = fullPath.Contains("WOW6432Node", StringComparison.OrdinalIgnoreCase);
            var view = isWow64 ? RegistryView.Registry32 : RegistryView.Registry64;

            // Extract the subkey relative to hive
            var subPath = fullPath.Substring(fullPath.IndexOf('\\') + 1);
            if (subPath.StartsWith("WOW6432Node\\", StringComparison.OrdinalIgnoreCase))
            {
                subPath = subPath.Substring("WOW6432Node\\".Length);
            }

            using var baseKey = RegistryKey.OpenBaseKey(hive, view);
            using var key = baseKey.OpenSubKey(subPath, true);
            if (key != null)
            {
                var rawVal = key.GetValue(valueName)?.ToString();
                key.DeleteValue(valueName, false);
                message = $"Removed autorun value '{valueName}' from {fullPath}";

                // Also quarantine the physical file pointed to by this autorun value
                if (!string.IsNullOrEmpty(rawVal))
                {
                    string targetFile = PersistenceService.ExtractFilePath(rawVal);
                    if (!string.IsNullOrEmpty(targetFile) && File.Exists(targetFile))
                    {
                        if (QuarantineFile(targetFile, out var fileMsg))
                        {
                            message += $" and {fileMsg}";
                        }
                    }
                }

                return true;
            }

            message = $"Registry subkey '{subPath}' not found";
            return false;
        }
        catch (Exception ex)
        {
            message = $"Failed to remove registry key: {ex.Message}";
            return false;
        }
    }
}
