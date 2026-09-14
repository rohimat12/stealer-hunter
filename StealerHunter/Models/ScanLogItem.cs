namespace StealerHunter.Models;

public class ScanLogItem
{
    private DateTime _timestamp = DateTime.Now;

    public DateTime Timestamp
    {
        get => _timestamp;
        set
        {
            _timestamp = value;
            FormattedTime = _timestamp.ToString("HH:mm:ss");
        }
    }

    public string Level { get; set; } = "INFO"; // INFO, WARN, DANGER, SUCCESS
    public string Message { get; set; } = string.Empty;
    public string FormattedTime { get; set; } = DateTime.Now.ToString("HH:mm:ss");

    public string LogColor => Level switch
    {
        "DANGER" => "#FF2E63",
        "WARN" => "#F4CE14",
        "SUCCESS" => "#00E676",
        _ => "#08D9D6"
    };

    public string LogBg => Level switch
    {
        "DANGER" => "#2E1220",
        "WARN" => "#2E2410",
        "SUCCESS" => "#0E291C",
        _ => "#122338"
    };
}
