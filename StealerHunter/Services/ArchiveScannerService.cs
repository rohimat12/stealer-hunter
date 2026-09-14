using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Threading;
using SharpCompress.Archives;
using StealerHunter.Models;

namespace StealerHunter.Services;

public class ArchiveScannerService
{
    private static readonly HashSet<string> ArchiveExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".zip", ".rar", ".7z", ".tar", ".gz"
    };

    private static readonly HashSet<string> StagedCredentialFiles = new(StringComparer.OrdinalIgnoreCase)
    {
        "passwords.txt", "cookies.txt", "autofill.txt", "all_passwords.txt",
        "browser_passwords.txt", "wallets.txt", "userinfo.txt", "system_info.txt",
        "wallet.dat", "credit_cards.txt", "discord_tokens.txt"
    };

    private static readonly HashSet<string> DangerousScriptExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".vbs", ".wsf", ".hta", ".scr", ".pif"
    };

    private static readonly HashSet<string> DeveloperProjectIndicators = new(StringComparer.OrdinalIgnoreCase)
    {
        "package.json", "pubspec.yaml", "composer.json", "pom.xml", "tsconfig.json",
        "requirements.txt", "cargo.toml", "gemfile", "go.mod", "readme.md", ".gitignore",
        "next.config.js", "vite.config.js", "angular.json", "webpack.config.js"
    };

    private static readonly HashSet<string> DeveloperSourceExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".js", ".ts", ".jsx", ".tsx", ".dart", ".py", ".php", ".cs", ".java", ".html", ".css", ".json", ".vue", ".yaml", ".yml", ".sql"
    };

    public bool IsArchiveFile(string filePath)
    {
        var ext = Path.GetExtension(filePath);
        return ArchiveExtensions.Contains(ext);
    }

    public ThreatItem? ScanSingleArchive(string archivePath)
    {
        if (!File.Exists(archivePath)) return null;

        var lower = archivePath.ToLowerInvariant();
        // Ignore quarantine files
        if (lower.Contains(@"\stealerhunter\quarantine\") ||
            lower.Contains(@"\quarantine\") ||
            lower.EndsWith(".quarantined"))
        {
            return null;
        }

        try
        {
            var entries = ReadArchiveEntries(archivePath);
            if (entries.Count == 0) return null;

            int credMatchCount = 0;
            string? dangerousPayload = null;
            string? doubleExtPayload = null;
            string? mofksysPayload = null;
            string? scriptPayload = null;
            bool hasPassKeyIndicator = false;
            bool hasNestedArchive = false;
            bool hasObfuscatedHomoglyphs = false;
            bool isDevProject = false;
            int devSourceCount = 0;

            foreach (var entry in entries)
            {
                var entryName = Path.GetFileName(entry).ToLowerInvariant();
                var entryExt = Path.GetExtension(entryName);

                // Developer project detection (Node.js, Flutter, Python, Web)
                if (DeveloperProjectIndicators.Contains(entryName))
                {
                    isDevProject = true;
                }
                if (DeveloperSourceExtensions.Contains(entryExt))
                {
                    devSourceCount++;
                }

                // 1. Staged credential checks
                if (StagedCredentialFiles.Contains(entryName))
                {
                    credMatchCount++;
                }

                // 2. Mofksys worm artifact
                if (entryName.StartsWith("icsys.", StringComparison.OrdinalIgnoreCase) ||
                    entryName.Equals("icsys", StringComparison.OrdinalIgnoreCase))
                {
                    mofksysPayload = entry;
                }

                // 3. Double extension trick (e.g. invoice.pdf.exe, photo.jpg.scr)
                var parts = entryName.Split('.');
                if (parts.Length >= 3)
                {
                    var fakeExt = parts[^2];
                    var realExt = parts[^1];
                    if (fakeExt is "pdf" or "jpg" or "png" or "docx" or "xlsx" or "mp4" or "zip" or "txt")
                    {
                        if (realExt is "exe" or "scr" or "com" or "bat" or "vbs" or "pif")
                        {
                            doubleExtPayload = entry;
                        }
                    }
                }

                // 4. Standalone legacy script payload in root (e.g. .vbs, .hta, .scr)
                if (DangerousScriptExtensions.Contains(entryExt) && !entry.Contains('/') && !entry.Contains('\\'))
                {
                    scriptPayload = entry;
                }

                // 5. Dropper pattern: ReleaseSetup_*.exe or Setup_*.exe in tools archives
                if (entryName.StartsWith("releasesetup_", StringComparison.OrdinalIgnoreCase) && entryName.EndsWith(".exe"))
                {
                    dangerousPayload = entry;
                }

                // 6. Phishing Trap: Archive contains "PASS KEY" image/text + nested archive
                if (entryName.Contains("pass key") || entryName.Contains("pass_key") || entryName.Contains("password"))
                {
                    hasPassKeyIndicator = true;
                }
                if (entryName.EndsWith(".zip") || entryName.EndsWith(".rar") || entryName.EndsWith(".7z"))
                {
                    hasNestedArchive = true;
                    // Check for unicode homoglyphs / math bold characters used by malware authors
                    if (entry.Any(c => c >= 0x2000))
                    {
                        hasObfuscatedHomoglyphs = true;
                    }
                }
            }

            // If it's a developer project archive, never treat scripts as droppers
            if (isDevProject || devSourceCount >= 2)
            {
                scriptPayload = null;
            }

            var archiveFileName = Path.GetFileName(archivePath);

            // Verdict 0: Phishing Malware Dropper Package (e.g. SETUP_FILE_PASS_KEY + Obfuscated Nested Zip)
            if ((hasPassKeyIndicator && hasNestedArchive) || hasObfuscatedHomoglyphs)
            {
                return new ThreatItem
                {
                    Name = $"Phishing Dropper Package: {archiveFileName}",
                    Category = ThreatCategory.SuspiciousProcess,
                    Severity = ThreatSeverity.Critical,
                    Description = $"Arsip '{archiveFileName}' menggunakan pola phishing dropper bertingkat (berisi instruksi Password/Pass Key dan arsip terselubung dengan karakter Unicode khusus) untuk mengelabui proteksi Antivirus.",
                    FilePath = archivePath,
                    TargetTarget = "Password-Protected Phishing Trap"
                };
            }

            // Verdict 1: Credential exfiltration archive
            if (credMatchCount >= 2)
            {
                return new ThreatItem
                {
                    Name = $"Credential Exfiltration Archive: {archiveFileName}",
                    Category = ThreatCategory.StagedExfiltrationData,
                    Severity = ThreatSeverity.Critical,
                    Description = $"File arsip '{archiveFileName}' berisi {credMatchCount} file kredensial hasil jarahan infostealer (passwords, cookies, userinfo)!",
                    FilePath = archivePath,
                    TargetTarget = "Staged Credential Dump Archive"
                };
            }

            // Verdict 2: Mofksys payload inside archive
            if (mofksysPayload != null)
            {
                return new ThreatItem
                {
                    Name = $"Mofksys Dropper Archive: {archiveFileName}",
                    Category = ThreatCategory.PersistenceAutorun,
                    Severity = ThreatSeverity.Critical,
                    Description = $"File arsip '{archiveFileName}' memuat komponen Worm:Win32/Mofksys berbahaya: '{mofksysPayload}'",
                    FilePath = archivePath,
                    TargetTarget = "Mofksys Worm Dropper"
                };
            }

            // Verdict 3: Double extension deception
            if (doubleExtPayload != null)
            {
                return new ThreatItem
                {
                    Name = $"Deceptive Archive (Double Extension): {archiveFileName}",
                    Category = ThreatCategory.SuspiciousProcess,
                    Severity = ThreatSeverity.Critical,
                    Description = $"File arsip '{archiveFileName}' memuat file executable jebakan dengan ekstensi ganda palsu: '{doubleExtPayload}'",
                    FilePath = archivePath,
                    TargetTarget = "Phishing Archive Dropper"
                };
            }

            // Verdict 4: Standalone script dropper
            if (scriptPayload != null)
            {
                return new ThreatItem
                {
                    Name = $"Script Dropper Archive: {archiveFileName}",
                    Category = ThreatCategory.SuspiciousProcess,
                    Severity = ThreatSeverity.High,
                    Description = $"File arsip '{archiveFileName}' memuat file script eksekusi berbahaya di root arsip: '{scriptPayload}'",
                    FilePath = archivePath,
                    TargetTarget = "Malicious Script Archive"
                };
            }

            // Verdict 5: Fake release dropper
            if (dangerousPayload != null)
            {
                return new ThreatItem
                {
                    Name = $"Malware Dropper Package: {archiveFileName}",
                    Category = ThreatCategory.SuspiciousProcess,
                    Severity = ThreatSeverity.Critical,
                    Description = $"File arsip '{archiveFileName}' memuat biner installer dropper mencurigakan: '{dangerousPayload}'",
                    FilePath = archivePath,
                    TargetTarget = "Fake Tool Dropper"
                };
            }
        }
        catch
        {
            // Password protected, corrupted, or unsupported archive
        }

        return null;
    }

    private static List<string> ReadArchiveEntries(string archivePath)
    {
        var entries = new List<string>();
        var ext = Path.GetExtension(archivePath).ToLowerInvariant();

        // Native Fast ZIP reading
        if (ext == ".zip")
        {
            try
            {
                using var zip = ZipFile.OpenRead(archivePath);
                foreach (var entry in zip.Entries)
                {
                    if (!string.IsNullOrWhiteSpace(entry.FullName))
                    {
                        entries.Add(entry.FullName);
                    }
                }
                return entries;
            }
            catch
            {
                // Fallback to SharpCompress
            }
        }

        // SharpCompress for RAR, 7Z, TAR, GZ, and non-standard ZIP
        try
        {
            using var archive = ArchiveFactory.OpenArchive(archivePath);
            foreach (var entry in archive.Entries)
            {
                if (!entry.IsDirectory && !string.IsNullOrWhiteSpace(entry.Key))
                {
                    entries.Add(entry.Key);
                }
            }
        }
        catch
        {
            // Archive read error or password protected
        }

        return entries;
    }

    public List<ThreatItem> ScanVulnerableArchiveLocations(
        Action<string, string>? logCallback = null,
        Action<string, double>? progressCallback = null,
        CancellationToken cancellationToken = default)
    {
        var threats = new List<ThreatItem>();
        var scanFolders = new List<string>();

        // 1. User Downloads & subfolders
        var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var downloads = Path.Combine(userProfile, "Downloads");
        if (Directory.Exists(downloads)) scanFolders.Add(downloads);

        // 2. Desktop
        var desktop = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
        if (Directory.Exists(desktop)) scanFolders.Add(desktop);

        // 3. User Temp
        var tempPath = Path.GetTempPath();
        if (Directory.Exists(tempPath)) scanFolders.Add(tempPath);

        logCallback?.Invoke("INFO", $"[ARCHIVE SCAN] Memindai file arsip (.zip, .rar, .7z) pada {scanFolders.Count} direktori berisiko tinggi...");

        int totalScanned = 0;
        var enumOptions = new EnumerationOptions
        {
            IgnoreInaccessible = true,
            RecurseSubdirectories = true,
            AttributesToSkip = FileAttributes.None
        };

        foreach (var folder in scanFolders)
        {
            cancellationToken.ThrowIfCancellationRequested();

            try
            {
                foreach (var file in Directory.EnumerateFiles(folder, "*.*", enumOptions))
                {
                    cancellationToken.ThrowIfCancellationRequested();

                    if (!IsArchiveFile(file)) continue;

                    totalScanned++;
                    if (totalScanned % 10 == 0)
                    {
                        progressCallback?.Invoke($"Memindai isi arsip: {Path.GetFileName(file)}...", 85);
                    }

                    var threat = ScanSingleArchive(file);
                    if (threat != null)
                    {
                        threats.Add(threat);
                        logCallback?.Invoke("DANGER", $"[ARCHIVE THREAT] {threat.Name} ditemukan di: {file}");
                    }
                }
            }
            catch (Exception ex)
            {
                logCallback?.Invoke("WARN", $"Gagal memindai arsip di {folder}: {ex.Message}");
            }
        }

        logCallback?.Invoke("SUCCESS", $"[ARCHIVE SCAN] Selesai memeriksa {totalScanned} file arsip terkompresi.");
        return threats;
    }
}
