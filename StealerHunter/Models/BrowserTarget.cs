namespace StealerHunter.Models;

public class BrowserTarget
{
    public string BrowserName { get; set; } = string.Empty;
    public string Engine { get; set; } = "Chromium"; // Chromium or Gecko
    public string ProfilePath { get; set; } = string.Empty;
    public List<string> SensitiveFiles { get; set; } = new();
    public bool IsInstalled { get; set; }
    public string StatusSummary { get; set; } = "Not Found";
    public bool HasSuspiciousLock { get; set; }
    public string BrowserIcon => BrowserName switch
    {
        var n when n.Contains("Chrome", StringComparison.OrdinalIgnoreCase) => "🟡",
        var n when n.Contains("Edge", StringComparison.OrdinalIgnoreCase) => "🔵",
        var n when n.Contains("Brave", StringComparison.OrdinalIgnoreCase) => "🦁",
        var n when n.Contains("Firefox", StringComparison.OrdinalIgnoreCase) => "🦊",
        var n when n.Contains("Opera", StringComparison.OrdinalIgnoreCase) => "🔴",
        _ => "🌐"
    };
}
