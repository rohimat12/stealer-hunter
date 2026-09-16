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
            if (proc != null && proc.ExitCode == 0) return true;

            // 2. Fallback check HKCU Run key
            using var hkcuKey = Registry.CurrentUser.OpenSubKey(RunRegistryKey, false);
            return hkcuKey?.GetValue(AppName) != null;
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

            // Always clean up legacy direct-exe registry Run keys (Windows blocks elevated exes directly in Run keys)
            CleanupLegacyDirectExeKeys();

            if (enable && !string.IsNullOrEmpty(exePath))
            {
                // 1. Create elevated Task Scheduler entry via XML (100% robust against spaces and arguments)
                bool created = CreateTaskSchedulerEntry(exePath);

                // Fallback attempt via command-line arguments if XML method didn't succeed
                if (!created)
                {
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
                        psi.ArgumentList.Add($"\"'{exePath}' --silent\"");
                        psi.ArgumentList.Add("/SC");
                        psi.ArgumentList.Add("ONLOGON");
                        psi.ArgumentList.Add("/RL");
                        psi.ArgumentList.Add("HIGHEST");
                        psi.ArgumentList.Add("/F");

                        using var proc = Process.Start(psi);
                        if (proc != null) proc.WaitForExit(3000);
                    }
                    catch { }
                }

                // 2. Register in HKCU Run to trigger the task and display StealerHunter in Task Manager "Startup apps" tab
                try
                {
                    using var hkcuKey = Registry.CurrentUser.OpenSubKey(RunRegistryKey, true);
                    if (hkcuKey != null)
                    {
                        var schtasksExe = Path.Combine(Environment.SystemDirectory, "schtasks.exe");
                        if (!File.Exists(schtasksExe)) schtasksExe = "schtasks.exe";
                        hkcuKey.SetValue(AppName, $"\"{schtasksExe}\" /run /tn \"{TaskName}\"", RegistryValueKind.String);
                    }
                }
                catch { }
            }
            else
            {
                // 1. Remove from Task Scheduler
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

                // 2. Remove from Registry Run
                CleanupAllRegistryKeys();
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

    private static bool CreateTaskSchedulerEntry(string exePath)
    {
        string tempXmlPath = Path.Combine(Path.GetTempPath(), $"StealerHunter_Task_{Guid.NewGuid():N}.xml");
        try
        {
            string xmlContent = $@"<?xml version=""1.0"" encoding=""UTF-16""?>
<Task version=""1.2"" xmlns=""http://schemas.microsoft.com/windows/2004/02/mit/task"">
  <RegistrationInfo>
    <Description>StealerHunter Anti-Infostealer Resident Background Guardian</Description>
    <Author>StealerHunter</Author>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
    </LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id=""Author"">
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>true</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context=""Author"">
    <Exec>
      <Command>{exePath}</Command>
      <Arguments>--silent</Arguments>
    </Exec>
  </Actions>
</Task>";

            File.WriteAllText(tempXmlPath, xmlContent, System.Text.Encoding.Unicode);

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
            psi.ArgumentList.Add("/XML");
            psi.ArgumentList.Add(tempXmlPath);
            psi.ArgumentList.Add("/F");

            using var proc = Process.Start(psi);
            proc?.WaitForExit(3000);
            return proc != null && proc.ExitCode == 0;
        }
        catch
        {
            return false;
        }
        finally
        {
            try
            {
                if (File.Exists(tempXmlPath)) File.Delete(tempXmlPath);
            }
            catch { }
        }
    }

    public static void CleanupLegacyDirectExeKeys()
    {
        try
        {
            // Remove from HKLM if present (HKLM requires admin and Windows blocks direct elevated exes anyway)
            using var hklmKey = Registry.LocalMachine.OpenSubKey(RunRegistryKey, true);
            if (hklmKey?.GetValue(AppName) != null)
            {
                hklmKey.DeleteValue(AppName, false);
            }
        }
        catch { }

        try
        {
            // Clean up HKCU only if it still points directly to .exe (instead of schtasks)
            using var hkcuKey = Registry.CurrentUser.OpenSubKey(RunRegistryKey, true);
            var val = hkcuKey?.GetValue(AppName)?.ToString();
            if (!string.IsNullOrEmpty(val) && !val.Contains("schtasks", StringComparison.OrdinalIgnoreCase))
            {
                hkcuKey?.DeleteValue(AppName, false);
            }
        }
        catch { }
    }

    public static void CleanupAllRegistryKeys()
    {
        try
        {
            using var hkcuKey = Registry.CurrentUser.OpenSubKey(RunRegistryKey, true);
            if (hkcuKey?.GetValue(AppName) != null)
            {
                hkcuKey.DeleteValue(AppName, false);
            }
        }
        catch { }

        try
        {
            using var hklmKey = Registry.LocalMachine.OpenSubKey(RunRegistryKey, true);
            if (hklmKey?.GetValue(AppName) != null)
            {
                hklmKey.DeleteValue(AppName, false);
            }
        }
        catch { }
    }

    public static void CleanupLegacyRegistryKeys() => CleanupAllRegistryKeys();
}
