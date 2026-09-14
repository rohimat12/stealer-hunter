using Microsoft.Win32;
using System;
using System.Diagnostics;
using System.IO;

namespace StealerHunter.Services;

public class AutoStartupService
{
    private const string RunRegistryKey = @"Software\Microsoft\Windows\CurrentVersion\Run";
    private const string AppName = "StealerHunter";
    private const string TaskName = "StealerHunter";

    public static bool IsAutoStartEnabled()
    {
        try
        {
            // 1. Check Windows Task Scheduler
            var psi = new ProcessStartInfo
            {
                FileName = "schtasks.exe",
                Arguments = $"/Query /TN \"{TaskName}\"",
                CreateNoWindow = true,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };
            using var proc = Process.Start(psi);
            proc?.WaitForExit(2000);
            if (proc != null && proc.ExitCode == 0)
            {
                return true;
            }

            // 2. Check Registry Run key
            using var key = Registry.CurrentUser.OpenSubKey(RunRegistryKey, false);
            return key?.GetValue(AppName) != null;
        }
        catch
        {
            return false;
        }
    }

    public static bool SetAutoStart(bool enable)
    {
        bool success = false;
        try
        {
            var exePath = Environment.ProcessPath;
            if (string.IsNullOrEmpty(exePath) || !File.Exists(exePath))
            {
                exePath = Process.GetCurrentProcess().MainModule?.FileName ?? string.Empty;
            }

            if (enable && !string.IsNullOrEmpty(exePath))
            {
                // 1. Create elevated Task Scheduler entry (Bypasses UAC block on logon)
                try
                {
                    var psi = new ProcessStartInfo
                    {
                        FileName = "schtasks.exe",
                        Arguments = $"/Create /TN \"{TaskName}\" /TR \"\\\"{exePath}\\\" --silent\" /SC ONLOGON /RL HIGHEST /F",
                        CreateNoWindow = true,
                        UseShellExecute = false
                    };
                    using var proc = Process.Start(psi);
                    proc?.WaitForExit(3000);
                    if (proc != null && proc.ExitCode == 0) success = true;
                }
                catch { }

                // 2. Fallback / supplementary Registry Run key
                try
                {
                    using var key = Registry.CurrentUser.OpenSubKey(RunRegistryKey, true);
                    if (key != null)
                    {
                        key.SetValue(AppName, $"\"{exePath}\" --silent");
                        success = true;
                    }
                }
                catch { }
            }
            else
            {
                // Remove from Task Scheduler
                try
                {
                    var psi = new ProcessStartInfo
                    {
                        FileName = "schtasks.exe",
                        Arguments = $"/Delete /TN \"{TaskName}\" /F",
                        CreateNoWindow = true,
                        UseShellExecute = false
                    };
                    using var proc = Process.Start(psi);
                    proc?.WaitForExit(3000);
                    success = true;
                }
                catch { }

                // Remove from Registry
                try
                {
                    using var key = Registry.CurrentUser.OpenSubKey(RunRegistryKey, true);
                    if (key?.GetValue(AppName) != null)
                    {
                        key.DeleteValue(AppName, false);
                        success = true;
                    }
                }
                catch { }
            }
        }
        catch
        {
            // Logging or permission handling
        }

        return success;
    }
}
