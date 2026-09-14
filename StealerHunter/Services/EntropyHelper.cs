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

    /// <summary>
    /// Returns true if a text/staging file shows suspicious high entropy (&gt; 7.20),
    /// indicating encrypted or packed credential dumps disguised as normal files.
    /// </summary>
    public static bool IsSuspiciousHighEntropyStaging(string filePath, out double entropy)
    {
        entropy = CalculateFileEntropy(filePath);

        // Files claiming to be text (.txt, .log, .json, .csv) should have entropy < 5.5
        var ext = Path.GetExtension(filePath).ToLowerInvariant();
        if (ext is ".txt" or ".log" or ".csv" or ".json" or ".dat" or ".tmp")
        {
            // Encrypted/XORed payloads almost always exceed 7.10
            return entropy >= 7.15;
        }

        return false;
    }
}
