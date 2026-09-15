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
            var psi = new ProcessStartInfo("schtasks.exe")
            {
                CreateNoWindow = true,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };
            psi.ArgumentList.Add("/Query");
            psi.ArgumentList.Add("/TN");
            psi.ArgumentList.Add(TaskName);

            using var proc = Process.Start(psi);
            proc?.WaitForExit(2000);
            if (proc != null && proc.ExitCode == 0)
            {
                return true;
            }

            // 2. Check Registry Run keys (HKCU & HKLM)
            using (var hkcuKey = Registry.CurrentUser.OpenSubKey(RunRegistryKey, false))
            {
                if (hkcuKey?.GetValue(AppName) != null) return true;
            }

            using (var hklmKey = Registry.LocalMachine.OpenSubKey(RunRegistryKey, false))
            {
                if (hklmKey?.GetValue(AppName) != null) return true;
            }

            return false;
        }
        catch
        {
            return false;
        }
    }

    public static bool SetAutoStart(bool enable)
    {
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
                    var psi = new ProcessStartInfo("schtasks.exe")
                    {
                        CreateNoWindow = true,
                        UseShellExecute = false,
                        RedirectStandardOutput = true,
                        RedirectStandardError = true
                    };
                    psi.ArgumentList.Add("/Create");
                    psi.ArgumentList.Add("/TN");
                    psi.ArgumentList.Add(TaskName);
                    psi.ArgumentList.Add("/TR");
                    psi.ArgumentList.Add($"\"{exePath}\" --silent");
                    psi.ArgumentList.Add("/SC");
                    psi.ArgumentList.Add("ONLOGON");
                    psi.ArgumentList.Add("/RL");
                    psi.ArgumentList.Add("HIGHEST");
                    psi.ArgumentList.Add("/F");

                    using var proc = Process.Start(psi);
                    if (proc != null) proc.WaitForExit(3000);
                }
                catch { }

                // 2. Fallback / supplementary Registry Run key
                try
                {
                    using var key = Registry.CurrentUser.OpenSubKey(RunRegistryKey, true);
                    key?.SetValue(AppName, $"\"{exePath}\" --silent");
                }
                catch { }
            }
            else
            {
                // Remove from Task Scheduler
                try
                {
                    var psi = new ProcessStartInfo("schtasks.exe")
                    {
                        CreateNoWindow = true,
                        UseShellExecute = false,
                        RedirectStandardOutput = true,
                        RedirectStandardError = true
                    };
                    psi.ArgumentList.Add("/Delete");
                    psi.ArgumentList.Add("/TN");
                    psi.ArgumentList.Add(TaskName);
                    psi.ArgumentList.Add("/F");

                    using var proc = Process.Start(psi);
                    proc?.WaitForExit(3000);
                }
                catch { }

                // Remove from Registry (HKCU & HKLM)
                try
                {
                    using var key = Registry.CurrentUser.OpenSubKey(RunRegistryKey, true);
                    if (key?.GetValue(AppName) != null)
                    {
                        key.DeleteValue(AppName, false);
                    }
                }
                catch { }

                try
                {
                    using var key = Registry.LocalMachine.OpenSubKey(RunRegistryKey, true);
                    if (key?.GetValue(AppName) != null)
                    {
                        key.DeleteValue(AppName, false);
                    }
                }
                catch { }
            }
        }
        catch
        {
            // Logging or permission handling
        }

        // Final verification: ensure actual ground truth matches requested state
        bool isCurrentlyEnabled = IsAutoStartEnabled();
        return enable ? isCurrentlyEnabled : !isCurrentlyEnabled;
    }
}
