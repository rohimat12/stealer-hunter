using System.IO;
using StealerHunter.Models;
using StealerHunter.Services;

namespace StealerHunter.Tests;

[TestClass]
public class SecurityServicesTests
{
    [TestMethod]
    public void TestBrowserDetection()
    {
        var service = new BrowserAuditService();
        var browsers = service.DetectBrowsers();

        Assert.IsNotNull(browsers);
        Assert.IsTrue(browsers.Count >= 5, "Should configure at least 5 standard browsers");

        // Chrome and Edge definitions should be present
        Assert.IsTrue(browsers.Any(b => b.BrowserName.Contains("Chrome")));
        Assert.IsTrue(browsers.Any(b => b.BrowserName.Contains("Edge")));
    }

    [TestMethod]
    public void TestProcessHunterExecution()
    {
        var service = new ProcessHunterService();
        var logs = new List<string>();

        var threats = service.ScanProcesses((lvl, msg) => logs.Add($"{lvl}: {msg}"));

        Assert.IsNotNull(threats);
        Assert.IsTrue(logs.Count > 0, "ScanProcesses should produce telemetry logs");
    }

    [TestMethod]
    public void TestPersistenceScanner()
    {
        var service = new PersistenceService();
        var logs = new List<string>();

        var threats = service.ScanPersistence((lvl, msg) => logs.Add($"{lvl}: {msg}"));

        Assert.IsNotNull(threats);
        Assert.IsTrue(logs.Count > 0, "Persistence scan should produce telemetry logs");
    }

    [TestMethod]
    public void TestStagedDataHunter()
    {
        var hunter = new StagedDataHunter();
        var logs = new List<string>();

        var threats = hunter.ScanStagedData((lvl, msg) => logs.Add($"{lvl}: {msg}"));

        Assert.IsNotNull(threats);
        Assert.IsTrue(logs.Count > 0, "Staged data hunter should produce telemetry logs");
    }

    [TestMethod]
    public void TestQuarantineFileIsolation()
    {
        // Create a temporary test dummy threat file
        var testFile = Path.Combine(Path.GetTempPath(), $"dummy_threat_{Guid.NewGuid():N}.txt");
        File.WriteAllText(testFile, "DUMMY TEST FOR STEALERHUNTER REMEDIATION");

        try
        {
            var success = QuarantineService.QuarantineFile(testFile, out var msg);
            if (!success) Console.WriteLine($"[TEST FAILED QuarantineFile] {msg}");
            Assert.IsTrue(success, $"QuarantineFile failed: {msg}");
            Assert.IsFalse(File.Exists(testFile), "Original test file should have been moved");
            Assert.IsTrue(msg.Contains("isolated to quarantine"), "Message should confirm isolation");
        }
        finally
        {
            if (File.Exists(testFile)) File.Delete(testFile);
        }
    }

    [TestMethod]
    public void TestAppSettingsSerialization()
    {
        var settings = new AppSettings
        {
            RunOnStartup = false,
            StartMinimizedToTray = true,
            RealtimeProtectionEnabled = true
        };

        settings.Save();
        var loaded = AppSettings.Load();

        Assert.IsNotNull(loaded);
        Assert.AreEqual(settings.StartMinimizedToTray, loaded.StartMinimizedToTray);
    }

    [TestMethod]
    public void TestAutoStartupRegistryQuery()
    {
        // Should not throw exceptions even when running non-elevated
        var isEnabled = AutoStartupService.IsAutoStartEnabled();
        Assert.IsNotNull(isEnabled);
    }

    [TestMethod]
    public void TestLiveLogsTabRenderingNoCrash()
    {
        Exception? threadException = null;
        var thread = new Thread(() =>
        {
            try
            {
                if (System.Windows.Application.Current == null)
                {
                    _ = new System.Windows.Application();
                }

                var window = new MainWindow();
                var vm = (StealerHunter.ViewModels.MainViewModel)window.DataContext;

                // Add sample logs of each level
                vm.AddLog("INFO", "Test info message");
                vm.AddLog("WARN", "Test warning message");
                vm.AddLog("DANGER", "Test danger message");
                vm.AddLog("SUCCESS", "Test success message");

                // Switch to Live Logs tab (index 2)
                vm.SelectedTabIndex = 2;
                window.Show();
                window.UpdateLayout();
                window.Close();
            }
            catch (Exception ex)
            {
                threadException = ex;
            }
        });
        thread.SetApartmentState(ApartmentState.STA);
        thread.Start();
        thread.Join();

        Assert.IsNull(threadException, $"Rendering Live Logs tab failed with exception: {threadException}");
    }

    [TestMethod]
    public void TestQuarantineServiceSafeIsolationAndRestore()
    {
        var quarantineService = new QuarantineService();
        var tempFolder = Path.Combine(Path.GetTempPath(), "StealerHunter_Test_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempFolder);

        try
        {
            // 1. Test Quarantine and XOR encryption on mock dummy file
            var dummyFile = Path.Combine(tempFolder, "dummy_malware.exe");
            byte[] mockBytes = { 0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00 }; // Standard MZ header
            File.WriteAllBytes(dummyFile, mockBytes);

            bool qResult = QuarantineService.QuarantineFile(dummyFile, out var qMsg, out var quarantinedPath);
            Assert.IsTrue(qResult, "QuarantineFile should succeed for mock file");
            Assert.IsFalse(File.Exists(dummyFile), "Original file should be deleted");
            Assert.IsNotNull(quarantinedPath);
            Assert.IsTrue(File.Exists(quarantinedPath), "Quarantined file should exist in vault");

            // Verify XOR encryption (0x4D ^ 0x5A = 0x17)
            byte[] encryptedBytes = File.ReadAllBytes(quarantinedPath);
            Assert.AreEqual((byte)(0x4D ^ 0x5A), encryptedBytes[0], "First byte must be XOR scrambled");

            // 2. Test Safe Restoration
            var restoredFile = Path.Combine(tempFolder, "restored_malware.exe");
            bool restoreResult = QuarantineService.RestoreQuarantinedFile(quarantinedPath, restoredFile, out var rMsg);
            Assert.IsTrue(restoreResult, "RestoreQuarantinedFile should succeed");
            Assert.IsTrue(File.Exists(restoredFile), "Restored file must exist");
            byte[] restoredBytes = File.ReadAllBytes(restoredFile);
            CollectionAssert.AreEqual(mockBytes, restoredBytes, "Restored bytes must match original");

            // 3. Test Browser Credential Safeguard (NEVER delete browser database)
            var browserThreat = new ThreatItem
            {
                Name = "Suspicious Lock on Login Data",
                Category = ThreatCategory.BrowserDataLock,
                FilePath = Path.Combine(tempFolder, "Login Data")
            };
            File.WriteAllText(browserThreat.FilePath, "SQLite format 3 test");

            bool neutralizeBrowser = quarantineService.NeutralizeThreat(browserThreat, out var bMsg);
            Assert.IsTrue(neutralizeBrowser);
            Assert.IsTrue(File.Exists(browserThreat.FilePath), "CRITICAL: Browser Login Data must NEVER be deleted or quarantined!");
        }
        finally
        {
            if (Directory.Exists(tempFolder))
            {
                try { Directory.Delete(tempFolder, true); } catch { }
            }
        }
    }

    [TestMethod]
    public void TestMftDeepScanServiceExecution()
    {
        var mftService = new MftDeepScanService();
        var logs = new List<string>();

        // 1. Test CanAccessUsnJournal query capability
        bool canAccessC = mftService.CanAccessUsnJournal("C:\\");
        // Result depends on execution privilege (admin vs non-admin), but must not throw unhandled exception
        Assert.IsNotNull(canAccessC);

        // 2. Test cancellation responsiveness
        using var cts = new CancellationTokenSource();
        cts.Cancel(); // Cancel immediately

        try
        {
            mftService.ScanAllDrivesDeepMft(
                (lvl, msg) => logs.Add($"[{lvl}] {msg}"),
                (status, pct) => { },
                cts.Token);
        }
        catch (OperationCanceledException)
        {
            // Expected clean cancellation
        }
    }

    [TestMethod]
    public void TestArchiveScannerServiceDetectsDeceptivePayload()
    {
        var scanner = new ArchiveScannerService();
        var tempZip = Path.Combine(Path.GetTempPath(), $"test_archive_{Guid.NewGuid():N}.zip");

        try
        {
            // Create a fake archive containing a double extension payload and a password dump
            using (var zipStream = new FileStream(tempZip, FileMode.Create))
            using (var archive = new System.IO.Compression.ZipArchive(zipStream, System.IO.Compression.ZipArchiveMode.Create))
            {
                var entry1 = archive.CreateEntry("passwords.txt");
                using (var writer = new StreamWriter(entry1.Open()))
                {
                    writer.WriteLine("dummy:pass");
                }

                var entry2 = archive.CreateEntry("cookies.txt");
                using (var writer = new StreamWriter(entry2.Open()))
                {
                    writer.WriteLine("dummy_cookie");
                }

                var entry3 = archive.CreateEntry("TFT_Schematic.pdf.exe");
                using (var writer = new StreamWriter(entry3.Open()))
                {
                    writer.WriteLine("DUMMY PE BYTES");
                }
            }

            // Test scan
            var threat = scanner.ScanSingleArchive(tempZip);
            Assert.IsNotNull(threat, "ArchiveScanner should detect suspicious payload inside zip");
            Assert.IsTrue(threat.Category == ThreatCategory.StagedExfiltrationData || threat.Category == ThreatCategory.SuspiciousProcess);
        }
        finally
        {
            if (File.Exists(tempZip)) File.Delete(tempZip);
        }
    }

    [TestMethod]
    public void TestScanRealSuspiciousInstallerArchive()
    {
        var scanner = new ArchiveScannerService();
        var sampleFile = @"C:\Users\rohim\Downloads\_Installer_dan_APK\SETUP_FILE_(PASS_KEY=2235).zip";

        if (File.Exists(sampleFile))
        {
            var threat = scanner.ScanSingleArchive(sampleFile);
            Assert.IsNotNull(threat, "Should flag SETUP_FILE_(PASS_KEY=2235).zip as a Phishing Dropper Package");
            Console.WriteLine($"[TEST DETECTED] {threat.Name}: {threat.Description}");
        }
    }

    [TestMethod]
    public void TestKillProcessRejectsMismatchedProcessName()
    {
        var current = System.Diagnostics.Process.GetCurrentProcess();
        bool killed = QuarantineService.KillProcess(current.Id, "completely_fake_evil_malware.exe", null, out var msg);

        Assert.IsFalse(killed, "KillProcess must refuse to kill a process if expectedName does not match actual process");
        Assert.IsTrue(msg.Contains("was reassigned by Windows") || msg.Contains("Termination aborted"), 
            $"Message should explain abort due to name mismatch: {msg}");
    }

    [TestMethod]
    public void TestKillProcessRejectsMismatchedStartTime()
    {
        var current = System.Diagnostics.Process.GetCurrentProcess();
        var fakeStartTime = DateTime.Now.AddHours(-10);

        bool killed = QuarantineService.KillProcess(current.Id, current.ProcessName, null, fakeStartTime, out var msg);

        Assert.IsFalse(killed, "KillProcess must refuse to kill a process if expectedStartTime does not match");
        Assert.IsTrue(msg.Contains("start time mismatch", StringComparison.OrdinalIgnoreCase) || msg.Contains("Termination aborted"),
            $"Message should explain abort due to start time mismatch: {msg}");
    }

    [TestMethod]
    public void TestSystemCriticalPathSafeguard()
    {
        var winDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        var sys32 = Environment.GetFolderPath(Environment.SpecialFolder.System);

        Assert.IsTrue(QuarantineService.IsSystemCriticalPath(Path.Combine(sys32, "svchost.exe")), "System32 must be critical");
        Assert.IsTrue(QuarantineService.IsSystemCriticalPath(Path.Combine(winDir, "explorer.exe")), "Windows root must be critical");
        Assert.IsFalse(QuarantineService.IsSystemCriticalPath(Path.Combine(Path.GetTempPath(), "evil.exe")), "Temp path must not be critical");
    }

    [TestMethod]
    public void TestProtectedBrowserCredentialFiles()
    {
        var chromeLoginData = @"C:\Users\test\AppData\Local\Google\Chrome\User Data\Default\Login Data";
        var edgeCookies = @"C:\Users\test\AppData\Local\Microsoft\Edge\User Data\Default\Network\Cookies";
        var randomFile = @"C:\Users\test\AppData\Local\Temp\random.txt";

        Assert.IsTrue(QuarantineService.IsProtectedBrowserCredentialFile(chromeLoginData), "Login Data must be immune");
        Assert.IsTrue(QuarantineService.IsProtectedBrowserCredentialFile(edgeCookies), "Cookies must be immune");
        Assert.IsFalse(QuarantineService.IsProtectedBrowserCredentialFile(randomFile), "Temp random file must not be immune");
    }

    [TestMethod]
    public void TestRestoreQuarantinedFileAvoidsBlindOverwrite()
    {
        var tempFolder = Path.Combine(Path.GetTempPath(), "SH_RestoreTest_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempFolder);

        try
        {
            var existingCleanFile = Path.Combine(tempFolder, "app.exe");
            File.WriteAllText(existingCleanFile, "CLEAN_LEGITIMATE_VERSION");

            var mockQuarantine = Path.Combine(tempFolder, "threat.quarantined");
            byte[] malwareBytes = { 0x11, 0x22, 0x33, 0x44 };
            byte[] xorBytes = malwareBytes.Select(b => (byte)(b ^ 0x5A)).ToArray();
            File.WriteAllBytes(mockQuarantine, xorBytes);

            bool success = QuarantineService.RestoreQuarantinedFile(mockQuarantine, existingCleanFile, out var msg);

            Assert.IsTrue(success);
            Assert.AreEqual("CLEAN_LEGITIMATE_VERSION", File.ReadAllText(existingCleanFile), "Clean file must never be overwritten");
            Assert.IsTrue(File.Exists(existingCleanFile + ".restored"), "Restored file must be saved as .restored");
            CollectionAssert.AreEqual(malwareBytes, File.ReadAllBytes(existingCleanFile + ".restored"));
        }
        finally
        {
            if (Directory.Exists(tempFolder)) Directory.Delete(tempFolder, true);
        }
    }

    [TestMethod]
    public void TestScanButtonStateManagement()
    {
        var vm = new StealerHunter.ViewModels.MainViewModel(isTestMode: true);

        // Initially idle
        Assert.IsFalse(vm.IsScanning, "IsScanning should be false initially");
        Assert.IsTrue(vm.CanStartScan, "CanStartScan should be true when idle");
        Assert.IsFalse(vm.CancelScanCommand.CanExecute(null), "Stop button should be disabled when idle");
        Assert.IsTrue(vm.QuickScanCommand.CanExecute(null), "Quick Scan should be enabled when idle");
        Assert.IsTrue(vm.DeepScanCommand.CanExecute(null), "Deep Scan should be enabled when idle");

        // Simulate scan started
        vm.IsScanning = true;
        Assert.IsTrue(vm.IsScanning);
        Assert.IsFalse(vm.CanStartScan, "CanStartScan should be false while scanning");
        Assert.IsTrue(vm.CancelScanCommand.CanExecute(null), "Stop button should be enabled while scanning");
        Assert.IsFalse(vm.QuickScanCommand.CanExecute(null), "Quick Scan should be disabled while scanning");
        Assert.IsFalse(vm.DeepScanCommand.CanExecute(null), "Deep Scan should be disabled while scanning");

        // Simulate scan finished / completed
        vm.IsScanning = false;
        Assert.IsFalse(vm.IsScanning);
        Assert.IsTrue(vm.CanStartScan, "CanStartScan should be restored when scan completes");
        Assert.IsFalse(vm.CancelScanCommand.CanExecute(null), "Stop button must be disabled when scan completes");
        Assert.IsTrue(vm.QuickScanCommand.CanExecute(null), "Quick Scan should be re-enabled");
        Assert.IsTrue(vm.DeepScanCommand.CanExecute(null), "Deep Scan should be re-enabled");
    }

    [TestMethod]
    public void TestScanProgressTextFormatting()
    {
        var vm = new StealerHunter.ViewModels.MainViewModel(isTestMode: true);

        vm.IsScanning = false;
        vm.ScanProgress = 0;
        Assert.AreEqual(string.Empty, vm.ScanProgressText, "Progress text should be empty when idle at 0%");

        vm.IsScanning = true;
        vm.ScanProgress = 5;
        Assert.AreEqual("5%", vm.ScanProgressText);

        vm.ScanProgress = 42.6;
        Assert.AreEqual("43%", vm.ScanProgressText);

        vm.ScanProgress = 100;
        Assert.AreEqual("100%", vm.ScanProgressText);

        vm.IsScanning = false;
        // When scan completes and progress is at 100%
        Assert.AreEqual("100%", vm.ScanProgressText, "Completed scan at 100% should show 100%");
    }

    [TestMethod]
    public void TestQuarantineVaultItemParsingAndListing()
    {
        // 1. Verify filename extraction patterns
        var pattern1 = "20260915_053000_a1b2c3d4_payload.exe.quarantined";
        Assert.AreEqual("payload.exe", QuarantineService.ExtractOriginalFileName(pattern1));

        var pattern2 = "malware.exe_20260915053000.quarantined";
        Assert.AreEqual("malware.exe", QuarantineService.ExtractOriginalFileName(pattern2));

        var pattern3 = "simple_virus.dll.quarantined";
        Assert.AreEqual("simple_virus.dll", QuarantineService.ExtractOriginalFileName(pattern3));

        // 2. Verify ViewModel integration (with isolated test mode)
        var vm = new StealerHunter.ViewModels.MainViewModel(isTestMode: true);
        Assert.IsNotNull(vm.QuarantinedItems);
        Assert.IsNotNull(vm.RefreshQuarantineCommand);
        Assert.IsNotNull(vm.RestoreVaultItemCommand);
        Assert.IsNotNull(vm.DeleteVaultItemCommand);
        Assert.IsNotNull(vm.EmptyVaultCommand);
    }

    [TestMethod]
    public void TestQuarantinePathTraversalSafeguard()
    {
        var tempQuarantine = Path.Combine(Path.GetTempPath(), "SH_Vault_Test_" + Guid.NewGuid().ToString("N"));

        try
        {
            Directory.CreateDirectory(tempQuarantine);

            var validQuarantineFile = Path.Combine(tempQuarantine, "20260915_053000_test_trojan.exe.quarantined");
            var nonQuarantineExtension = Path.Combine(tempQuarantine, "trojan.exe");
            var traversalEscape = Path.Combine(tempQuarantine, "..", "Windows", "System32", "calc.exe.quarantined");
            var systemFile = @"C:\Windows\System32\notepad.exe";

            // Valid file inside quarantine with .quarantined extension
            Assert.IsTrue(QuarantineService.IsPathInsideQuarantineDirectory(validQuarantineFile, tempQuarantine),
                "Valid .quarantined file inside quarantine directory must be accepted");

            // Extension is not .quarantined
            Assert.IsFalse(QuarantineService.IsPathInsideQuarantineDirectory(nonQuarantineExtension, tempQuarantine),
                "File without .quarantined extension must be rejected");

            // Path traversal attempt using .. to escape directory
            Assert.IsFalse(QuarantineService.IsPathInsideQuarantineDirectory(traversalEscape, tempQuarantine),
                "Directory traversal escaping quarantine root must be strictly rejected");

            // Arbitrary system file
            Assert.IsFalse(QuarantineService.IsPathInsideQuarantineDirectory(systemFile, tempQuarantine),
                "System file outside quarantine must be rejected");

            // Null or empty
            Assert.IsFalse(QuarantineService.IsPathInsideQuarantineDirectory(null, tempQuarantine));
            Assert.IsFalse(QuarantineService.IsPathInsideQuarantineDirectory(string.Empty, tempQuarantine));
        }
        finally
        {
            if (Directory.Exists(tempQuarantine))
            {
                try { Directory.Delete(tempQuarantine, true); } catch { }
            }
        }
    }
}