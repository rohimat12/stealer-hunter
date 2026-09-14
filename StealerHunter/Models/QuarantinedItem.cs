using System.ComponentModel;
using System.Runtime.CompilerServices;

namespace StealerHunter.Models;

public class QuarantinedItem : INotifyPropertyChanged
{
    private string _originalFileName = string.Empty;
    private string _quarantinedFileName = string.Empty;
    private string _fullPath = string.Empty;
    private long _fileSizeBytes;
    private DateTime _quarantinedDate;

    public string OriginalFileName
    {
        get => _originalFileName;
        set { _originalFileName = value; OnPropertyChanged(); }
    }

    public string QuarantinedFileName
    {
        get => _quarantinedFileName;
        set { _quarantinedFileName = value; OnPropertyChanged(); }
    }

    public string FullPath
    {
        get => _fullPath;
        set { _fullPath = value; OnPropertyChanged(); }
    }

    public long FileSizeBytes
    {
        get => _fileSizeBytes;
        set
        {
            _fileSizeBytes = value;
            OnPropertyChanged();
            OnPropertyChanged(nameof(FormattedSize));
        }
    }

    public string FormattedSize => FileSizeBytes switch
    {
        < 1024 => $"{FileSizeBytes} B",
        < 1024 * 1024 => $"{FileSizeBytes / 1024.0:F1} KB",
        _ => $"{FileSizeBytes / (1024.0 * 1024.0):F2} MB"
    };

    public DateTime QuarantinedDate
    {
        get => _quarantinedDate;
        set
        {
            _quarantinedDate = value;
            OnPropertyChanged();
            OnPropertyChanged(nameof(FormattedDate));
        }
    }

    public string FormattedDate => QuarantinedDate.ToString("yyyy-MM-dd HH:mm:ss");

    public event PropertyChangedEventHandler? PropertyChanged;

    protected void OnPropertyChanged([CallerMemberName] string? propertyName = null)
    {
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }
}
