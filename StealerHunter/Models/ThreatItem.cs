namespace StealerHunter.Models;

public enum ThreatSeverity
{
    Low,
    Medium,
    High,
    Critical
}

public enum ThreatCategory
{
    BrowserDataLock,
    SuspiciousProcess,
    PersistenceAutorun,
    StagedExfiltrationData,
    MaliciousScript,
    KnownSignatureMatch
}

public class ThreatItem
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public string Name { get; set; } = string.Empty;
    public ThreatCategory Category { get; set; }
    public ThreatSeverity Severity { get; set; }
    public string Description { get; set; } = string.Empty;
    public string TargetTarget { get; set; } = string.Empty;
    public string FilePath { get; set; } = string.Empty;
    public int? ProcessId { get; set; }
    public DateTime DetectedAt { get; set; } = DateTime.Now;
    public bool IsResolved { get; set; }
    public string StatusMessage { get; set; } = "Active Threat";

    public string SeverityBadgeColor => Severity switch
    {
        ThreatSeverity.Critical => "#FF2E63", // Red
        ThreatSeverity.High => "#FF7B54",     // Coral / Orange
        ThreatSeverity.Medium => "#F4CE14",   // Amber
        _ => "#08D9D6"                        // Cyan
    };

    public string CategoryIcon => Category switch
    {
        ThreatCategory.BrowserDataLock => "🌐",
        ThreatCategory.SuspiciousProcess => "⚡",
        ThreatCategory.PersistenceAutorun => "🔄",
        ThreatCategory.StagedExfiltrationData => "📦",
        ThreatCategory.MaliciousScript => "📜",
        ThreatCategory.KnownSignatureMatch => "☣️",
        _ => "⚠️"
    };
}
