using System.IO;
using System.Text.Json;

namespace StealerHunter.Models;

public class AppSettings
{
    public bool RunOnStartup { get; set; } = true;
    public bool StartMinimizedToTray { get; set; } = true;
    public bool RealtimeProtectionEnabled { get; set; } = true;
    public bool SoundAlertOnThreat { get; set; } = true;

    private static readonly string SettingsDir = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
        "StealerHunter"
    );

    private static readonly string SettingsFilePath = Path.Combine(SettingsDir, "settings.json");

    public static AppSettings Load()
    {
        try
        {
            if (File.Exists(SettingsFilePath))
            {
                var json = File.ReadAllText(SettingsFilePath);
                var settings = JsonSerializer.Deserialize<AppSettings>(json);
                if (settings != null) return settings;
            }
        }
        catch
        {
            // fallback default
        }

        return new AppSettings();
    }

    public void Save()
    {
        try
        {
            if (!Directory.Exists(SettingsDir))
            {
                Directory.CreateDirectory(SettingsDir);
            }

            var json = JsonSerializer.Serialize(this, new JsonSerializerOptions { WriteIndented = true });
            File.WriteAllText(SettingsFilePath, json);
        }
        catch
        {
            // Ignore settings write errors
        }
    }
}
