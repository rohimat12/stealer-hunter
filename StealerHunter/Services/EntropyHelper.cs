using System.IO;

namespace StealerHunter.Services;

/// <summary>
/// Provides Shannon Entropy calculation to detect encrypted, packed, or obfuscated
/// credential exfiltration staging files in temporary directories.
/// </summary>
public static class EntropyHelper
{
    /// <summary>
    /// Computes the Shannon entropy of a byte array (0.0 to 8.0).
    /// Plain text files usually range from 3.0 to 5.0.
    /// Encrypted or compressed exfiltration payloads approach 7.2 to 8.0.
    /// </summary>
    public static double CalculateEntropy(byte[] data)
    {
        if (data == null || data.Length == 0) return 0.0;

        int[] frequency = new int[256];
        foreach (byte b in data)
        {
            frequency[b]++;
        }

        double entropy = 0.0;
        double total = data.Length;

        for (int i = 0; i < 256; i++)
        {
            if (frequency[i] == 0) continue;
            double p = frequency[i] / total;
            entropy -= p * Math.Log2(p);
        }

        return entropy;
    }

    /// <summary>
    /// Reads up to maxBytes from the given file and calculates its Shannon entropy.
    /// Returns 0.0 if file is too small (&lt; 256 bytes) or inaccessible.
    /// </summary>
    public static double CalculateFileEntropy(string filePath, int maxBytes = 65536)
    {
        try
        {
            if (!File.Exists(filePath)) return 0.0;

            var fileInfo = new FileInfo(filePath);
            if (fileInfo.Length < 256) return 0.0; // Too small for statistically reliable entropy

            using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            int bytesToRead = (int)Math.Min(fs.Length, maxBytes);
            byte[] buffer = new byte[bytesToRead];
            int read = fs.Read(buffer, 0, bytesToRead);

            if (read < 256) return 0.0;

            return CalculateEntropy(buffer.AsSpan(0, read).ToArray());
        }
        catch
        {
            return 0.0;
        }
    }

    public static bool IsLegitimateStandardFormat(byte[] header)
    {
        if (header == null || header.Length < 4) return false;

        // PNG Image
        if (header.Length >= 8 &&
            header[0] == 0x89 && header[1] == 0x50 && header[2] == 0x4E && header[3] == 0x47 &&
            header[4] == 0x0D && header[5] == 0x0A && header[6] == 0x1A && header[7] == 0x0A)
            return true;

        // JPEG Image
        if (header[0] == 0xFF && header[1] == 0xD8 && header[2] == 0xFF)
            return true;

        // GIF Image
        if (header[0] == 0x47 && header[1] == 0x49 && header[2] == 0x46 && header[3] == 0x38)
            return true;

        // RIFF (WEBP / WAV / AVI)
        if (header[0] == 0x52 && header[1] == 0x49 && header[2] == 0x46 && header[3] == 0x46)
            return true;

        // PDF Document
        if (header[0] == 0x25 && header[1] == 0x50 && header[2] == 0x44 && header[3] == 0x46)
            return true;

        // BMP Image
        if (header[0] == 0x42 && header[1] == 0x4D)
            return true;

        // ICO Icon
        if (header[0] == 0x00 && header[1] == 0x00 && header[2] == 0x01 && header[3] == 0x00)
            return true;

        // ZIP / Office XML / JAR / APK
        if (header[0] == 0x50 && header[1] == 0x4B &&
            (header[2] == 0x03 || header[2] == 0x05 || header[2] == 0x07) &&
            (header[3] == 0x04 || header[3] == 0x06 || header[3] == 0x08))
            return true;

        // 7z Archive
        if (header.Length >= 6 &&
            header[0] == 0x37 && header[1] == 0x7A && header[2] == 0xBC &&
            header[3] == 0xAF && header[4] == 0x27 && header[5] == 0x1C)
            return true;

        // RAR Archive
        if (header[0] == 0x52 && header[1] == 0x61 && header[2] == 0x72 && header[3] == 0x21)
            return true;

        // GZIP Archive
        if (header[0] == 0x1F && header[1] == 0x8B)
            return true;

        // SQLite Database
        if (header.Length >= 16 &&
            header[0] == 0x53 && header[1] == 0x51 && header[2] == 0x4C && header[3] == 0x69 &&
            header[4] == 0x74 && header[5] == 0x65 && header[6] == 0x20)
            return true;

        // OLE / MSI Compound File
        if (header.Length >= 8 &&
            header[0] == 0xD0 && header[1] == 0xCF && header[2] == 0x11 && header[3] == 0xE0 &&
            header[4] == 0xA1 && header[5] == 0xB1 && header[6] == 0x1A && header[7] == 0xE1)
            return true;

        // WebM / Matroska
        if (header[0] == 0x1A && header[1] == 0x45 && header[2] == 0xDF && header[3] == 0xA3)
            return true;

        // MP4 / MOV (ftyp at offset 4)
        if (header.Length >= 12 &&
            header[4] == 0x66 && header[5] == 0x74 && header[6] == 0x79 && header[7] == 0x70)
            return true;

        // ID3 / MP3 Audio
        if (header[0] == 0x49 && header[1] == 0x44 && header[2] == 0x33)
            return true;

        // Zero-padded structured binary headers (memory index tables, sparse headers)
        if (header.Length >= 8 && header[0] == 0 && header[1] == 0 && header[2] == 0 && header[3] == 0 &&
            header[4] == 0 && header[5] == 0 && header[6] == 0 && header[7] == 0)
            return true;

        // DirectX Shader Bytecode (DXBC)
        if (header[0] == 0x44 && header[1] == 0x58 && header[2] == 0x42 && header[3] == 0x43)
            return true;

        // V8 / Chromium Snapshot ("v8")
        if (header[0] == 0x76 && header[1] == 0x38)
            return true;

        // Windows Executable / DLL (MZ header - handled by PE/Process scanner, not staging dump)
        if (header[0] == 0x4D && header[1] == 0x5A)
            return true;

        // Java Bytecode / Class File (0xCAFEBABE)
        if (header.Length >= 4 && header[0] == 0xCA && header[1] == 0xFE && header[2] == 0xBA && header[3] == 0xBE)
            return true;

        // ELF Linux/Android Shared Object / Binary (0x7F 'E' 'L' 'F')
        if (header.Length >= 4 && header[0] == 0x7F && header[1] == 0x45 && header[2] == 0x4C && header[3] == 0x46)
            return true;

        // WebAssembly Binary (0x00 'a' 's' 'm')
        if (header.Length >= 4 && header[0] == 0x00 && header[1] == 0x61 && header[2] == 0x73 && header[3] == 0x6D)
            return true;

        return false;
    }

    /// <summary>
    /// Returns true if a text/staging file shows suspicious high entropy (&gt; 7.25)
    /// without matching standard media/archive magic headers, indicating encrypted
    /// or packed credential dumps disguised as normal files.
    /// </summary>
    public static bool IsSuspiciousHighEntropyStaging(string filePath, out double entropy)
    {
        entropy = 0.0;
        try
        {
            if (!File.Exists(filePath)) return false;

            var ext = Path.GetExtension(filePath).ToLowerInvariant();
            if (ext is not (".txt" or ".log" or ".csv" or ".json" or ".dat" or ".tmp" or ".bin"))
            {
                return false;
            }

            var fi = new FileInfo(filePath);
            // Credential dumps are strictly within 512 bytes to 6 MB.
            // Exclude large build streams, installer packages, video/audio temp caches.
            if (fi.Length < 512 || fi.Length > 6 * 1024 * 1024) return false;

            var fn = Path.GetFileName(filePath).ToLowerInvariant();
            // Whitelist known installer / build / package manager / developer compiler streaming temp patterns
            if (System.Text.RegularExpressions.Regex.IsMatch(fn, @"^[0-9a-f]{8}-[0-9]+-[0-9]+\.tmp$", System.Text.RegularExpressions.RegexOptions.IgnoreCase) ||
                System.Text.RegularExpressions.Regex.IsMatch(fn, @"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", System.Text.RegularExpressions.RegexOptions.IgnoreCase) ||
                fn.StartsWith("is-", StringComparison.OrdinalIgnoreCase) ||
                fn.StartsWith("npm-", StringComparison.OrdinalIgnoreCase) ||
                fn.StartsWith("pip-", StringComparison.OrdinalIgnoreCase) ||
                fn.StartsWith("yarn-", StringComparison.OrdinalIgnoreCase) ||
                fn.StartsWith("flutter_", StringComparison.OrdinalIgnoreCase) ||
                fn.StartsWith("dart_", StringComparison.OrdinalIgnoreCase) ||
                fn.StartsWith("gradle_", StringComparison.OrdinalIgnoreCase) ||
                fn.StartsWith("android_", StringComparison.OrdinalIgnoreCase) ||
                fn.StartsWith("ninja_", StringComparison.OrdinalIgnoreCase) ||
                fn.StartsWith("cmake_", StringComparison.OrdinalIgnoreCase) ||
                fn.StartsWith("tmp.", StringComparison.OrdinalIgnoreCase) ||
                fn.StartsWith("~", StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            // Read header bytes first
            byte[] header = new byte[32];
            using (var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
            {
                int read = fs.Read(header, 0, 32);
                if (read < 16) return false;
            }

            // If it matches a standard legitimate media/document/archive format, it's not an encrypted dump
            if (IsLegitimateStandardFormat(header))
            {
                return false;
            }

            entropy = CalculateFileEntropy(filePath);
            return entropy >= 7.25;
        }
        catch
        {
            return false;
        }
    }
}
