using System.IO;
using System.Security.Cryptography.X509Certificates;

namespace StealerHunter.Services;

/// <summary>
/// Verifies digital Authenticode signatures of binaries to eliminate false positives
/// on legitimate system updaters (e.g. Google, Microsoft, Acer, NVIDIA) while isolating unsigned infostealers.
/// </summary>
public static class DigitalSignatureHelper
{
    private static readonly HashSet<string> TrustedPublishers = new(StringComparer.OrdinalIgnoreCase)
    {
        "Microsoft Corporation",
        "Microsoft Windows",
        "Google LLC",
        "Acer Incorporated",
        "ASUSTeK Computer Inc.",
        "Apple Inc.",
        "Mozilla Corporation",
        "Valve Corp.",
        "Discord Inc.",
        "NVIDIA Corporation",
        "Intel Corporation",
        "Adobe Inc."
    };

    /// <summary>
    /// Checks if a file has a valid digital certificate issued by a trusted root CA
    /// or known reputable enterprise software vendor.
    /// </summary>
    public static bool IsTrustedOrSigned(string? filePath, out string signerInfo)
    {
        signerInfo = "Unsigned";
        if (string.IsNullOrEmpty(filePath) || !File.Exists(filePath))
            return false;

        try
        {
            // Extract the Authenticode X509 certificate embedded in the PE header
            using var rawCert = X509Certificate.CreateFromSignedFile(filePath);
            using var cert2 = new X509Certificate2(rawCert);

            var simpleSubject = cert2.GetNameInfo(X509NameType.SimpleName, false);
            var simpleIssuer = cert2.GetNameInfo(X509NameType.SimpleName, true);
            signerInfo = $"Signed by: {simpleSubject} (CA: {simpleIssuer})";

            // 1. Verify certificate chain against the local Windows Trusted Root store
            if (cert2.Verify())
            {
                return true;
            }

            // 2. Secondary verification for trusted vendors (handles valid legacy/timestamped certificates)
            var fullSubject = cert2.Subject ?? string.Empty;
            foreach (var pub in TrustedPublishers)
            {
                if (fullSubject.Contains(pub, StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }

            // Signed, but failed chain verification and not in trusted vendor list (possible self-signed stealer)
            signerInfo = $"Untrusted/Self-Signed: {simpleSubject}";
            return false;
        }
        catch
        {
            // Throws CryptographicException if the executable has no digital signature
            signerInfo = "Unsigned";
            return false;
        }
    }
}
