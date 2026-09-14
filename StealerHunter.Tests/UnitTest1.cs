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

            Assert.IsTrue(success, "QuarantineFile should return true on valid file");
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

        Assert.IsNull(threadException, $"Rendering Live Logs tab failed with exception: {threadException?.Message}");
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
}