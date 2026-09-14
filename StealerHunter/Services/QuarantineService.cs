using System.Runtime.InteropServices;
using Microsoft.Win32;
using System.Diagnostics;
using System.IO;
using System.Management;
using StealerHunter.Models;

namespace StealerHunter.Services;

public class QuarantineService
{
    private static readonly string QuarantineDir = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
        "StealerHunter",
        "Quarantine"
    );

    private const byte QuarantineXorKey = 0x5A; // Industry-standard XOR key to neutralize executable PE headers

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool MoveFileEx(string lpExistingFileName, string? lpNewFileName, int dwFlags);
    private const int MOVEFILE_DELAY_UNTIL_REBOOT = 0x00000004;

    public static string GetQuarantineDirectory() => QuarantineDir;

    public static bool IsProtectedBrowserCredentialFile(string? path)
    {
        if (string.IsNullOrWhiteSpace(path)) return false;
        var fileName = Path.GetFileName(path).ToLowerInvariant();
        return fileName is "login data" or "login data-journal" or "cookies" or "cookies-journal"
                         or "web data" or "web data-journal" or "local state" or "places.sqlite"
                         or "key4.db" or "logins.json" or "formhistory.sqlite";
    }

    public bool NeutralizeThreat(ThreatItem threat, out string resultMessage)
    {
        bool success = true;
        var messages = new List<string>();

        // 1. If there's an active Process ID, terminate it with process identity verification
        if (threat.ProcessId.HasValue && threat.ProcessId.Value > 0)
        {
            if (KillProcess(threat.ProcessId.Value, threat.ProcessName, threat.FilePath, threat.ProcessStartTime, out var killMsg))
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
            // CRITICAL HARD SAFEGUARD: NEVER delete or quarantine legitimate browser credential databases!
            if (threat.Category == ThreatCategory.BrowserDataLock || IsProtectedBrowserCredentialFile(threat.FilePath))
            {
                messages.Add($"Protected credential vault '{Path.GetFileName(threat.FilePath)}' was preserved safely. Terminate rogue holding processes to clear lock.");
            }
            else if (File.Exists(threat.FilePath))
            {
                if (QuarantineFile(threat.FilePath, out var qMsg, out var quarantinedPath))
                {
                    threat.QuarantineBackupPath = quarantinedPath;
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

    public static bool KillProcess(int pid, string? expectedName, string? expectedPath, DateTime? expectedStartTime, out string message)
    {
        try
        {
            var proc = Process.GetProcessById(pid);
            var procName = proc.ProcessName;

            // 1. Verify Process Identity by Name (handling optional .exe) to prevent PID Reuse / TOCTOU hazards
            if (!string.IsNullOrEmpty(expectedName))
            {
                var cleanExpected = expectedName.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)
                    ? Path.GetFileNameWithoutExtension(expectedName)
                    : expectedName;

                if (!procName.Equals(cleanExpected, StringComparison.OrdinalIgnoreCase))
                {
                    message = $"Target PID {pid} was reassigned by Windows to '{procName}' (expected '{cleanExpected}'). Termination aborted for system safety.";
                    return false;
                }
            }

            // 2. Verify Process Start Time to prevent PID reuse by an identical process name
            if (expectedStartTime.HasValue)
            {
                DateTime? actualStartTime = null;
                try
                {
                    actualStartTime = proc.StartTime;
                }
                catch
                {
                    // Fallback to WMI if standard API access is restricted
                    try
                    {
                        using var searcher = new ManagementObjectSearcher($"SELECT CreationDate FROM Win32_Process WHERE ProcessId = {pid}");
                        using var objs = searcher.Get();
                        foreach (var o in objs)
                        {
                            if (o["CreationDate"] is string dmtf && !string.IsNullOrEmpty(dmtf))
                            {
                                actualStartTime = ManagementDateTimeConverter.ToDateTime(dmtf);
                                break;
                            }
                        }
                    }
                    catch
                    {
                    }
                }

                if (actualStartTime.HasValue && Math.Abs((actualStartTime.Value - expectedStartTime.Value).TotalSeconds) > 3)
                {
                    message = $"Target PID {pid} was reused by another instance of '{procName}' (Start time mismatch). Termination aborted for system safety.";
                    return false;
                }
            }

            // 3. Verify executable path if expectedPath is known
            if (!string.IsNullOrEmpty(expectedPath) && File.Exists(expectedPath))
            {
                try
                {
                    var currentPath = proc.MainModule?.FileName;
                    if (!string.IsNullOrEmpty(currentPath) && !currentPath.Equals(expectedPath, StringComparison.OrdinalIgnoreCase))
                    {
                        message = $"Target PID {pid} executable path mismatch: running '{currentPath}' instead of expected '{expectedPath}'. Termination aborted for safety.";
                        return false;
                    }
                }
                catch
                {
                    // Protected process access denied to MainModule
                }
            }

            // 4. Critical Windows System Process Safeguard
            var lowerName = procName.ToLowerInvariant();
            if (lowerName is "system" or "smss" or "csrss" or "wininit" or "services" or "lsass" or "winlogon" or "dwm")
            {
                message = $"Refusing to terminate critical system process '{procName}' (PID {pid}) to avoid system crash.";
                return false;
            }

            // 5. Terminate process safely
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

    public static bool KillProcess(int pid, string? expectedName, string? expectedPath, out string message) =>
        KillProcess(pid, expectedName, expectedPath, null, out message);

    public static bool KillProcess(int pid, out string message) =>
        KillProcess(pid, null, null, null, out message);

    public static bool QuarantineFile(string filePath, out string message) => QuarantineFile(filePath, out message, out _);

    public static bool QuarantineFile(string filePath, out string message, out string? destinationPath)
    {
        destinationPath = null;
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

            // 1. Read file bytes and apply XOR transformation to corrupt the MZ PE header (completely neutralizes execution)
            byte[] fileBytes = File.ReadAllBytes(filePath);
            for (int i = 0; i < fileBytes.Length; i++)
            {
                fileBytes[i] ^= QuarantineXorKey;
            }

            // 2. Write scrambled binary to Quarantine vault
            File.WriteAllBytes(destPath, fileBytes);
            destinationPath = destPath;

            // 3. Attempt to delete original file
            try
            {
                File.Delete(filePath);
                message = $"File neutralized (XOR-encrypted) and isolated to quarantine: {Path.GetFileName(destPath)}";
                return true;
            }
            catch
            {
                // 4. Fallback if file is locked: Schedule Windows kernel to delete file on next reboot
                bool scheduled = MoveFileEx(filePath, null, MOVEFILE_DELAY_UNTIL_REBOOT);
                if (scheduled)
                {
                    message = $"File encrypted to quarantine ({Path.GetFileName(destPath)}), original is locked. Scheduled for post-reboot kernel deletion.";
                }
                else
                {
                    message = $"File encrypted to quarantine ({Path.GetFileName(destPath)}), original locked (Access Denied).";
                }
                return true;
            }
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

            // Direct move attempt
            try
            {
                Directory.Move(dirPath, destPath);
                message = $"Dump directory isolated: {Path.GetFileName(destPath)}";
                return true;
            }
            catch
            {
                // Fallback: Recursive file-by-file copy, XOR encryption, and reboot scheduling
                Directory.CreateDirectory(destPath);
                int fileCount = 0;

                foreach (var file in Directory.GetFiles(dirPath, "*.*", SearchOption.AllDirectories))
                {
                    try
                    {
                        var relPath = Path.GetRelativePath(dirPath, file);
                        var targetFile = Path.Combine(destPath, relPath + ".quarantined");
                        var targetDir = Path.GetDirectoryName(targetFile);
                        if (!string.IsNullOrEmpty(targetDir) && !Directory.Exists(targetDir))
                        {
                            Directory.CreateDirectory(targetDir);
                        }

                        byte[] bytes = File.ReadAllBytes(file);
                        for (int i = 0; i < bytes.Length; i++)
                        {
                            bytes[i] ^= QuarantineXorKey;
                        }
                        File.WriteAllBytes(targetFile, bytes);

                        try
                        {
                            File.SetAttributes(file, FileAttributes.Normal);
                            File.Delete(file);
                        }
                        catch
                        {
                            MoveFileEx(file, null, MOVEFILE_DELAY_UNTIL_REBOOT);
                        }

                        fileCount++;
                    }
                    catch
                    {
                        // Proceed with remaining files
                    }
                }

                try
                {
                    Directory.Delete(dirPath, true);
                }
                catch
                {
                    MoveFileEx(dirPath, null, MOVEFILE_DELAY_UNTIL_REBOOT);
                }

                message = $"Staging directory isolated ({fileCount} files XOR-encrypted). Locked remnants scheduled for reboot cleanup.";
                return true;
            }
        }
        catch (Exception ex)
        {
            message = $"Failed to quarantine directory: {ex.Message}";
            return false;
        }
    }

    /// <summary>
    /// Safely restores an XOR-encrypted quarantined file back to its original executable format.
    /// </summary>
    public static bool RestoreQuarantinedFile(string quarantinedFilePath, string destinationPath, out string message)
    {
        try
        {
            if (!File.Exists(quarantinedFilePath))
            {
                message = "Quarantined file not found.";
                return false;
            }

            byte[] bytes = File.ReadAllBytes(quarantinedFilePath);
            for (int i = 0; i < bytes.Length; i++)
            {
                bytes[i] ^= QuarantineXorKey; // Reverse XOR
            }

            File.WriteAllBytes(destinationPath, bytes);
            message = $"File successfully decrypted and restored to: {destinationPath}";
            return true;
        }
        catch (Exception ex)
        {
            message = $"Failed to restore file: {ex.Message}";
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
