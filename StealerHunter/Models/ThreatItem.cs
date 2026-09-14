using System.ComponentModel;
using System.Runtime.CompilerServices;

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

public class ThreatItem : INotifyPropertyChanged
{
    private bool _isResolved;
    private string _statusMessage = "Active Threat";
    private string? _quarantineBackupPath;

    public Guid Id { get; set; } = Guid.NewGuid();
    public string Name { get; set; } = string.Empty;
    public ThreatCategory Category { get; set; }
    public ThreatSeverity Severity { get; set; }
    public string Description { get; set; } = string.Empty;
    public string TargetTarget { get; set; } = string.Empty;
    public string FilePath { get; set; } = string.Empty;
    public int? ProcessId { get; set; }
    public string? ProcessName { get; set; }
    public DateTime DetectedAt { get; set; } = DateTime.Now;

    public bool IsResolved
    {
        get => _isResolved;
        set
        {
            if (_isResolved != value)
            {
                _isResolved = value;
                OnPropertyChanged();
                OnPropertyChanged(nameof(CanRestore));
            }
        }
    }

    public string StatusMessage
    {
        get => _statusMessage;
        set
        {
            if (_statusMessage != value)
            {
                _statusMessage = value;
                OnPropertyChanged();
            }
        }
    }

    public string? QuarantineBackupPath
    {
        get => _quarantineBackupPath;
        set
        {
            if (_quarantineBackupPath != value)
            {
                _quarantineBackupPath = value;
                OnPropertyChanged();
                OnPropertyChanged(nameof(CanRestore));
            }
        }
    }

    public bool CanRestore => IsResolved && !string.IsNullOrEmpty(QuarantineBackupPath);

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

    public event PropertyChangedEventHandler? PropertyChanged;

    protected void OnPropertyChanged([CallerMemberName] string? propertyName = null)
    {
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }
}
