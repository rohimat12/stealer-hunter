using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Win32.SafeHandles;
using StealerHunter.Models;

namespace StealerHunter.Services;

public class MftDeepScanService
{
    private const uint GENERIC_READ = 0x80000000;
    private const uint FILE_SHARE_READ = 0x00000001;
    private const uint FILE_SHARE_WRITE = 0x00000002;
    private const uint OPEN_EXISTING = 3;
    private const uint FSCTL_ENUM_USN_DATA = 0x000900b3;
    private const uint FSCTL_QUERY_USN_JOURNAL = 0x000900f4;

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    private static extern SafeFileHandle CreateFile(
        string lpFileName,
        uint dwDesiredAccess,
        uint dwShareMode,
        IntPtr lpSecurityAttributes,
        uint dwCreationDisposition,
        uint dwFlagsAndAttributes,
        IntPtr hTemplateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool DeviceIoControl(
        SafeFileHandle hDevice,
        uint dwIoControlCode,
        IntPtr lpInBuffer,
        int nInBufferSize,
        IntPtr lpOutBuffer,
        int nOutBufferSize,
        out int lpBytesReturned,
        IntPtr lpOverlapped);

    [StructLayout(LayoutKind.Sequential)]
    private struct MFT_ENUM_DATA_V0
    {
        public ulong StartFileReferenceNumber;
        public long LowUsn;
        public long HighUsn;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct USN_JOURNAL_DATA_V0
    {
        public ulong UsnJournalID;
        public long FirstUsn;
        public long NextUsn;
        public long LowestValidUsn;
        public long MaxUsn;
        public ulong MaximumSize;
        public ulong AllocationDelta;
    }

    private readonly struct RawMftRecord
    {
        public readonly ulong Frn;
        public readonly ulong ParentFrn;
        public readonly string Name;
        public readonly bool IsDirectory;
        public readonly DateTime LastModified;

        public RawMftRecord(ulong frn, ulong parentFrn, string name, bool isDirectory, DateTime lastModified)
        {
            Frn = frn;
            ParentFrn = parentFrn;
            Name = name;
            IsDirectory = isDirectory;
            LastModified = lastModified;
        }
    }

    private static readonly HashSet<string> CriticalSystemProcesses = new(StringComparer.OrdinalIgnoreCase)
    {
        "explorer.exe", "svchost.exe", "spoolsv.exe", "csrss.exe", "lsass.exe",
        "services.exe", "smss.exe", "wininit.exe", "winlogon.exe", "taskhostw.exe"
    };

    public bool CanAccessUsnJournal(string rootPath)
    {
        try
        {
            string driveLetter = (Path.GetPathRoot(rootPath) ?? "C:\\").TrimEnd('\\');
            string volumePath = @"\\.\" + driveLetter;
            using var handle = CreateFile(
                volumePath,
                GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                IntPtr.Zero,
                OPEN_EXISTING,
                0,
                IntPtr.Zero);

            if (handle.IsInvalid) return false;

            int journalDataSize = Marshal.SizeOf<USN_JOURNAL_DATA_V0>();
            IntPtr outBuffer = Marshal.AllocHGlobal(journalDataSize);
            try
            {
                return DeviceIoControl(
                    handle,
                    FSCTL_QUERY_USN_JOURNAL,
                    IntPtr.Zero,
                    0,
                    outBuffer,
                    journalDataSize,
                    out _,
                    IntPtr.Zero);
            }
            finally
            {
                Marshal.FreeHGlobal(outBuffer);
            }
        }
        catch
        {
            return false;
        }
    }

    public List<ThreatItem> ScanAllDrivesDeepMft(
        Action<string, string>? logCallback = null,
        Action<string, double>? progressCallback = null,
        CancellationToken cancellationToken = default)
    {
        var threats = new List<ThreatItem>();
        var drives = DriveInfo.GetDrives();

        logCallback?.Invoke("INFO", $"=== Memulai MFT/USN Journal Deep Scan pada {drives.Length} drive ===");

        int driveIndex = 0;
        foreach (var drive in drives)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (!drive.IsReady) continue;

            string driveRoot = drive.RootDirectory.FullName;
            double baseProgress = 70 + ((double)driveIndex / drives.Length) * 20;

            progressCallback?.Invoke($"Memindai Master File Table (MFT) Drive {driveRoot}...", baseProgress);

            if (drive.DriveFormat.Equals("NTFS", StringComparison.OrdinalIgnoreCase))
            {
                try
                {
                    logCallback?.Invoke("INFO", $"[MFT] Membaca NTFS USN Journal Volume {driveRoot}...");
                    var mftThreats = ScanVolumeMft(driveRoot, logCallback, cancellationToken);
                    threats.AddRange(mftThreats);
                }
                catch (Exception ex)
                {
                    logCallback?.Invoke("WARN", $"[MFT] Gagal membaca MFT langsung pada {driveRoot}: {ex.Message}. Beralih ke parallel folder crawler.");
                    var fallbackThreats = FallbackDriveCrawler(driveRoot, logCallback, cancellationToken);
                    threats.AddRange(fallbackThreats);
                }
            }
            else
            {
                logCallback?.Invoke("INFO", $"Drive {driveRoot} bertipe {drive.DriveFormat}, menggunakan fast directory scanner.");
                var fallbackThreats = FallbackDriveCrawler(driveRoot, logCallback, cancellationToken);
                threats.AddRange(fallbackThreats);
            }

            driveIndex++;
        }

        return threats;
    }

    private List<ThreatItem> ScanVolumeMft(string driveRoot, Action<string, string>? logCallback, CancellationToken cancellationToken)
    {
        var threats = new List<ThreatItem>();
        string driveLetter = driveRoot.TrimEnd('\\');
        string volumePath = @"\\.\" + driveLetter;

        using var handle = CreateFile(
            volumePath,
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            IntPtr.Zero,
            OPEN_EXISTING,
            0,
            IntPtr.Zero);

        if (handle.IsInvalid)
        {
            int err = Marshal.GetLastWin32Error();
            throw new UnauthorizedAccessException($"Gagal membuka volume {volumePath} (Win32 Error: {err}). Butuh hak akses Administrator.");
        }

        int journalDataSize = Marshal.SizeOf<USN_JOURNAL_DATA_V0>();
        IntPtr journalBuffer = Marshal.AllocHGlobal(journalDataSize);
        USN_JOURNAL_DATA_V0 journalData;
        try
        {
            if (!DeviceIoControl(handle, FSCTL_QUERY_USN_JOURNAL, IntPtr.Zero, 0, journalBuffer, journalDataSize, out _, IntPtr.Zero))
            {
                throw new InvalidOperationException($"Volume {volumePath} tidak mendukung atau USN Journal belum aktif.");
            }
            journalData = Marshal.PtrToStructure<USN_JOURNAL_DATA_V0>(journalBuffer);
        }
        finally
        {
            Marshal.FreeHGlobal(journalBuffer);
        }

        int bufferSize = 65536;
        IntPtr outBuffer = Marshal.AllocHGlobal(bufferSize);
        IntPtr inBuffer = Marshal.AllocHGlobal(Marshal.SizeOf<MFT_ENUM_DATA_V0>());

        var mftEnumData = new MFT_ENUM_DATA_V0
        {
            StartFileReferenceNumber = 0,
            LowUsn = 0,
            HighUsn = journalData.NextUsn
        };

        var directories = new Dictionary<ulong, (string Name, ulong ParentFrn)>();
        var suspiciousRecords = new List<RawMftRecord>();
        int totalRecords = 0;

        try
        {
            while (true)
            {
                cancellationToken.ThrowIfCancellationRequested();

                Marshal.StructureToPtr(mftEnumData, inBuffer, true);

                bool success = DeviceIoControl(
                    handle,
                    FSCTL_ENUM_USN_DATA,
                    inBuffer,
                    Marshal.SizeOf<MFT_ENUM_DATA_V0>(),
                    outBuffer,
                    bufferSize,
                    out int bytesReturned,
                    IntPtr.Zero);

                if (!success || bytesReturned <= 8) break;

                mftEnumData.StartFileReferenceNumber = (ulong)Marshal.ReadInt64(outBuffer);
                int offset = 8;

                while (offset < bytesReturned)
                {
                    IntPtr recordPtr = IntPtr.Add(outBuffer, offset);
                    int recordLength = Marshal.ReadInt32(recordPtr);
                    if (recordLength < 60 || offset + recordLength > bytesReturned) break;

                    short majorVersion = Marshal.ReadInt16(recordPtr, 4);
                    ulong frn;
                    ulong parentFrn;
                    long timestamp;
                    int fileAttributes;
                    short fileNameLength;
                    short fileNameOffset;

                    if (majorVersion == 2)
                    {
                        frn = (ulong)Marshal.ReadInt64(recordPtr, 8);
                        parentFrn = (ulong)Marshal.ReadInt64(recordPtr, 16);
                        timestamp = Marshal.ReadInt64(recordPtr, 32);
                        fileAttributes = Marshal.ReadInt32(recordPtr, 52);
                        fileNameLength = Marshal.ReadInt16(recordPtr, 56);
                        fileNameOffset = Marshal.ReadInt16(recordPtr, 58);
                    }
                    else if (majorVersion == 3)
                    {
                        frn = (ulong)Marshal.ReadInt64(recordPtr, 8);
                        parentFrn = (ulong)Marshal.ReadInt64(recordPtr, 24);
                        timestamp = Marshal.ReadInt64(recordPtr, 40);
                        fileAttributes = Marshal.ReadInt32(recordPtr, 60);
                        fileNameLength = Marshal.ReadInt16(recordPtr, 64);
                        fileNameOffset = Marshal.ReadInt16(recordPtr, 66);
                    }
                    else
                    {
                        offset += recordLength;
                        continue;
                    }

                    if (fileNameOffset < 56 || fileNameLength <= 0 || fileNameOffset + fileNameLength > recordLength)
                    {
                        offset += recordLength;
                        continue;
                    }

                    string fileName = Marshal.PtrToStringUni(IntPtr.Add(recordPtr, fileNameOffset), fileNameLength / 2);
                    bool isDir = (fileAttributes & 0x00000010) != 0;

                    totalRecords++;

                    if (isDir)
                    {
                        directories[frn] = (fileName, parentFrn);
                    }
                    else
                    {
                        // Filter interesting heuristic names immediately during MFT read
                        if (IsSuspiciousFileName(fileName))
                        {
                            DateTime lastMod;
                            try { lastMod = DateTime.FromFileTimeUtc(timestamp); }
                            catch { lastMod = DateTime.MinValue; }

                            suspiciousRecords.Add(new RawMftRecord(frn, parentFrn, fileName, false, lastMod));
                        }
                    }

                    offset += recordLength;
                }
            }
        }
        finally
        {
            Marshal.FreeHGlobal(outBuffer);
            Marshal.FreeHGlobal(inBuffer);
        }

        logCallback?.Invoke("SUCCESS", $"[MFT] Selesai memindai {totalRecords:N0} MFT records pada {driveRoot}. Menganalisis {suspiciousRecords.Count} file mencurigakan...");

        // Reconstruct full paths for suspicious records
        var pathCache = new Dictionary<ulong, string>();
        string GetDirectoryFullPath(ulong parentFrn)
        {
            if (pathCache.TryGetValue(parentFrn, out var cached)) return cached;

            var pathStack = new Stack<string>();
            ulong current = parentFrn;
            var visited = new HashSet<ulong>();

            while (directories.TryGetValue(current, out var dirInfo))
            {
                if (!visited.Add(current)) break;
                if (!string.IsNullOrEmpty(dirInfo.Name))
                {
                    pathStack.Push(dirInfo.Name);
                }
                current = dirInfo.ParentFrn;
            }

            string full = driveLetter + "\\" + string.Join("\\", pathStack);
            pathCache[parentFrn] = full;
            return full;
        }

        var winDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows).TrimEnd('\\');
        var sys32 = Environment.GetFolderPath(Environment.SpecialFolder.System).TrimEnd('\\');
        var resourcesDir = Path.Combine(winDir, "Resources");

        foreach (var rec in suspiciousRecords)
        {
            cancellationToken.ThrowIfCancellationRequested();

            string dirPath = GetDirectoryFullPath(rec.ParentFrn);
            string fullPath = Path.Combine(dirPath, rec.Name);

            // Skip legitimate Windows files
            if (IsLegitimatePath(rec.Name, fullPath, winDir, sys32)) continue;

            // Analyze file on disk if exists
            try
            {
                if (File.Exists(fullPath))
                {
                    var threat = ClassifySuspiciousFile(fullPath, rec.Name, resourcesDir);
                    if (threat != null)
                    {
                        threats.Add(threat);
                        logCallback?.Invoke("DANGER", $"[MFT CRITICAL] {threat.Name} ditemukan di: {fullPath}");
                    }
                }
            }
            catch
            {
                // File access locked
            }
        }

        return threats;
    }

    private static bool IsSuspiciousFileName(string fileName)
    {
        if (string.IsNullOrEmpty(fileName)) return false;

        // Skip quarantined files immediately
        if (fileName.EndsWith(".quarantined", StringComparison.OrdinalIgnoreCase)) return false;

        // Skip non-executable developer source code, markdown, cmake, and text files
        if (fileName.EndsWith(".java", StringComparison.OrdinalIgnoreCase) ||
            fileName.EndsWith(".cmake", StringComparison.OrdinalIgnoreCase) ||
            fileName.EndsWith(".cs", StringComparison.OrdinalIgnoreCase) ||
            fileName.EndsWith(".cpp", StringComparison.OrdinalIgnoreCase) ||
            fileName.EndsWith(".c", StringComparison.OrdinalIgnoreCase) ||
            fileName.EndsWith(".h", StringComparison.OrdinalIgnoreCase) ||
            fileName.EndsWith(".ps1", StringComparison.OrdinalIgnoreCase) ||
            fileName.EndsWith(".txt", StringComparison.OrdinalIgnoreCase) ||
            fileName.EndsWith(".md", StringComparison.OrdinalIgnoreCase) ||
            fileName.EndsWith(".xml", StringComparison.OrdinalIgnoreCase) ||
            fileName.EndsWith(".json", StringComparison.OrdinalIgnoreCase) ||
            fileName.EndsWith(".pf", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        // Known worm artifacts (strictly icsys.* or icsys, NOT words like DynamicSystem or GenericSystem)
        if (fileName.StartsWith("icsys.", StringComparison.OrdinalIgnoreCase) ||
            fileName.Equals("icsys", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        // Masquerading core names
        if (CriticalSystemProcesses.Contains(fileName)) return true;

        // Double extensions (e.g. .pdf.exe, .jpg.exe)
        var parts = fileName.Split('.');
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

    private static bool IsLegitimatePath(string fileName, string fullPath, string winDir, string sys32)
    {
        var lower = fullPath.ToLowerInvariant();

        // 1. Quarantined files are safely isolated in StealerHunter's quarantine folder or marked .quarantined
        if (lower.Contains(@"\stealerhunter\quarantine\") ||
            lower.Contains(@"\quarantine\") ||
            lower.EndsWith(".quarantined"))
        {
            return true;
        }

        // 2. Legitimate Windows system components, update stores, servicing, and prefetch cache
        if (lower.Contains(@"\windows\winsxs\") ||
            lower.Contains(@"\windows\softwaredistribution\") ||
            lower.Contains(@"\windows\servicing\") ||
            lower.Contains(@"\windows\systemapps\") ||
            lower.Contains(@"\windows\system32\driverstore\") ||
            lower.Contains(@"\windows\inf\") ||
            lower.Contains(@"\windows\installer\") ||
            lower.Contains(@"\windows\assembly\") ||
            lower.Contains(@"\windows\microsoft.net\") ||
            lower.Contains(@"\windows\prefetch\") ||
            lower.Contains(@"\$windows.~bt\") ||
            lower.Contains(@"\windows.old\"))
        {
            return true;
        }

        // 3. Explorer.exe is legitimate directly in C:\Windows or C:\Windows\SysWOW64
        if (fileName.Equals("explorer.exe", StringComparison.OrdinalIgnoreCase))
        {
            return fullPath.Equals(Path.Combine(winDir, "explorer.exe"), StringComparison.OrdinalIgnoreCase) ||
                   lower.Equals(Path.Combine(winDir, "syswow64", "explorer.exe").ToLowerInvariant());
        }

        // 4. Other critical system processes are legitimate in System32, SysWOW64, or SystemApps
        if (CriticalSystemProcesses.Contains(fileName))
        {
            return fullPath.StartsWith(sys32, StringComparison.OrdinalIgnoreCase) ||
                   lower.StartsWith(Path.Combine(winDir, "syswow64").ToLowerInvariant()) ||
                   lower.StartsWith(Path.Combine(winDir, "systemapps").ToLowerInvariant());
        }

        return false;
    }

    private static ThreatItem? ClassifySuspiciousFile(string fullPath, string fileName, string resourcesDir)
    {
        var lower = fullPath.ToLowerInvariant();

        // Double check: Never re-flag quarantined or safely isolated files
        if (lower.Contains(@"\stealerhunter\quarantine\") ||
            lower.Contains(@"\quarantine\") ||
            lower.EndsWith(".quarantined"))
        {
            return null;
        }

        var fi = new FileInfo(fullPath);

        // 1. Files in C:\Windows\Resources (like explorer.exe or icsys)
        if (fullPath.StartsWith(resourcesDir, StringComparison.OrdinalIgnoreCase))
        {
            return new ThreatItem
            {
                Name = $"Resources Masquerader: {fileName}",
                Category = ThreatCategory.PersistenceAutorun,
                Severity = ThreatSeverity.Critical,
                Description = $"File biner mencurigakan berada di dalam folder tema Windows: '{fullPath}'. Pola khas Trojan/Worm Mofksys.",
                FilePath = fullPath,
                TargetTarget = "Windows Resources Theme Directory"
            };
        }

        // 2. Mofksys worm artifact (strictly icsys.* or icsys)
        if (fileName.StartsWith("icsys.", StringComparison.OrdinalIgnoreCase) ||
            fileName.Equals("icsys", StringComparison.OrdinalIgnoreCase))
        {
            return new ThreatItem
            {
                Name = $"Mofksys Worm File: {fileName}",
                Category = ThreatCategory.PersistenceAutorun,
                Severity = ThreatSeverity.Critical,
                Description = $"Artefak worm pencuri password terdeteksi di drive: '{fullPath}'",
                FilePath = fullPath,
                TargetTarget = "Mofksys Stealer Payload"
            };
        }

        // 3. Masquerading system files in unauthorized places (e.g. TFTUnlock or D:\ or AppData)
        if (CriticalSystemProcesses.Contains(fileName))
        {
            // Check if PE metadata is mutated with TJprojMain (Mofksys infection)
            string desc = $"File menyamar sebagai layanan sistem Windows resmi '{fileName}' di lokasi tidak resmi: '{fullPath}'";
            try
            {
                var ver = System.Diagnostics.FileVersionInfo.GetVersionInfo(fullPath);
                if (ver.OriginalFilename != null && ver.OriginalFilename.Contains("TJprojMain", StringComparison.OrdinalIgnoreCase))
                {
                    desc += " [TERKONFIRMASI TERINFEKSI VIRUS MOFKSYS (TJprojMain.exe)]";
                }
            }
            catch { }

            return new ThreatItem
            {
                Name = $"Masquerading Core Process: {fileName}",
                Category = ThreatCategory.SuspiciousProcess,
                Severity = ThreatSeverity.Critical,
                Description = desc,
                FilePath = fullPath,
                TargetTarget = "System Integrity / Rogue Binary"
            };
        }

        // 4. Double extensions
        if (fileName.Contains(".pdf.exe", StringComparison.OrdinalIgnoreCase) ||
            fileName.Contains(".jpg.exe", StringComparison.OrdinalIgnoreCase) ||
            fileName.Contains(".zip.exe", StringComparison.OrdinalIgnoreCase))
        {
            return new ThreatItem
            {
                Name = $"Fake Extension Dropper: {fileName}",
                Category = ThreatCategory.SuspiciousProcess,
                Severity = ThreatSeverity.Critical,
                Description = $"File menggunakan ekstensi palsu untuk mengelabui pengguna agar mengklik executable berbahaya: '{fullPath}'",
                FilePath = fullPath,
                TargetTarget = "Phishing / Dropper Payload"
            };
        }

        return null;
    }

    private static List<ThreatItem> FallbackDriveCrawler(string driveRoot, Action<string, string>? logCallback, CancellationToken cancellationToken)
    {
        var threats = new List<ThreatItem>();
        var enumOptions = new EnumerationOptions
        {
            IgnoreInaccessible = true,
            RecurseSubdirectories = true,
            AttributesToSkip = FileAttributes.None
        };

        try
        {
            var winDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows).TrimEnd('\\');
            var sys32 = Environment.GetFolderPath(Environment.SpecialFolder.System).TrimEnd('\\');
            var resourcesDir = Path.Combine(winDir, "Resources");

            // Look for masqueraders & icsys files
            string[] searchPatterns = new[] { "icsys.*", "explorer.exe", "svchost.exe", "spoolsv.exe" };
            foreach (var pat in searchPatterns)
            {
                cancellationToken.ThrowIfCancellationRequested();
                try
                {
                    foreach (var file in Directory.EnumerateFiles(driveRoot, pat, enumOptions))
                    {
                        cancellationToken.ThrowIfCancellationRequested();
                        var fn = Path.GetFileName(file);
                        if (IsLegitimatePath(fn, file, winDir, sys32)) continue;

                        var threat = ClassifySuspiciousFile(file, fn, resourcesDir);
                        if (threat != null)
                        {
                            threats.Add(threat);
                            logCallback?.Invoke("DANGER", $"[FALLBACK SCAN] {threat.Name}: {file}");
                        }
                    }
                }
                catch (OperationCanceledException) { throw; }
                catch { }
            }
        }
        catch (Exception ex)
        {
            logCallback?.Invoke("WARN", $"Crawler error on {driveRoot}: {ex.Message}");
        }

        return threats;
    }
}
