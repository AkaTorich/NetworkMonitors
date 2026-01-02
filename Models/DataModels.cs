using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.CompilerServices;

namespace NetworkMonitorWPF.Models
{
    /// <summary>
    /// Уровни важности сообщений в логе
    /// </summary>
    public enum LogLevel
    {
        Info,
        Warning,
        Error,
        Success,
        Network,
        Security,
        Debug
    }

    /// <summary>
    /// Модель попытки входа RDP с поддержкой INotifyPropertyChanged для WPF
    /// </summary>
    public class RDPFailedLogin : INotifyPropertyChanged
    {
        private DateTime _timeStamp;
        private string _username = string.Empty;
        private string _sourceIP = string.Empty;
        private string _computer = string.Empty;
        private int _eventId;
        private string _description = string.Empty;
        private string _status = string.Empty;
        private string _eventType = string.Empty;
        private string _logonType = string.Empty;

        public DateTime TimeStamp
        {
            get => _timeStamp;
            set { _timeStamp = value; OnPropertyChanged(); }
        }

        public string Username
        {
            get => _username;
            set { _username = value; OnPropertyChanged(); }
        }

        public string SourceIP
        {
            get => _sourceIP;
            set { _sourceIP = value; OnPropertyChanged(); }
        }

        public string Computer
        {
            get => _computer;
            set { _computer = value; OnPropertyChanged(); }
        }

        public int EventId
        {
            get => _eventId;
            set { _eventId = value; OnPropertyChanged(); }
        }

        public string Description
        {
            get => _description;
            set { _description = value; OnPropertyChanged(); }
        }

        public string Status
        {
            get => _status;
            set { _status = value; OnPropertyChanged(); }
        }

        public string EventType
        {
            get => _eventType;
            set { _eventType = value; OnPropertyChanged(); }
        }

        public string LogonType
        {
            get => _logonType;
            set { _logonType = value; OnPropertyChanged(); }
        }

        public event PropertyChangedEventHandler? PropertyChanged;

        protected virtual void OnPropertyChanged([CallerMemberName] string? propertyName = null)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }
    }

    /// <summary>
    /// Модель сетевого устройства с поддержкой INotifyPropertyChanged для WPF
    /// </summary>
    public class NetworkDevice : INotifyPropertyChanged
    {
        private string _ipAddress = string.Empty;
        private string _macAddress = string.Empty;
        private string _hostname = string.Empty;
        private string _vendor = string.Empty;
        private string _deviceType = string.Empty;
        private string _operatingSystem = string.Empty;
        private string _status = string.Empty;
        private DateTime _firstSeen;
        private DateTime _lastSeen;
        private bool _isNew;
        private List<int> _openPorts = new List<int>();
        private string _description = string.Empty;

        public string IPAddress
        {
            get => _ipAddress;
            set { _ipAddress = value; OnPropertyChanged(); }
        }

        public string MACAddress
        {
            get => _macAddress;
            set { _macAddress = value; OnPropertyChanged(); }
        }

        public string Hostname
        {
            get => _hostname;
            set { _hostname = value; OnPropertyChanged(); }
        }

        public string Vendor
        {
            get => _vendor;
            set { _vendor = value; OnPropertyChanged(); }
        }

        public string DeviceType
        {
            get => _deviceType;
            set { _deviceType = value; OnPropertyChanged(); }
        }

        public string OperatingSystem
        {
            get => _operatingSystem;
            set { _operatingSystem = value; OnPropertyChanged(); }
        }

        public string Status
        {
            get => _status;
            set { _status = value; OnPropertyChanged(); }
        }

        public DateTime FirstSeen
        {
            get => _firstSeen;
            set { _firstSeen = value; OnPropertyChanged(); }
        }

        public DateTime LastSeen
        {
            get => _lastSeen;
            set { _lastSeen = value; OnPropertyChanged(); }
        }

        public bool IsNew
        {
            get => _isNew;
            set { _isNew = value; OnPropertyChanged(); }
        }

        public List<int> OpenPorts
        {
            get => _openPorts;
            set { _openPorts = value; OnPropertyChanged(); }
        }

        public string Description
        {
            get => _description;
            set { _description = value; OnPropertyChanged(); }
        }

        public event PropertyChangedEventHandler? PropertyChanged;

        protected virtual void OnPropertyChanged([CallerMemberName] string? propertyName = null)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }
    }

    /// <summary>
    /// Модель сообщения лога
    /// </summary>
    public class LogMessage : INotifyPropertyChanged
    {
        private DateTime _timestamp;
        private string _message = string.Empty;
        private LogLevel _level;
        private string _color = "#FFFFFF";

        public DateTime Timestamp
        {
            get => _timestamp;
            set { _timestamp = value; OnPropertyChanged(); }
        }

        public string Message
        {
            get => _message;
            set { _message = value; OnPropertyChanged(); }
        }

        public LogLevel Level
        {
            get => _level;
            set
            {
                _level = value;
                OnPropertyChanged();
                UpdateColor();
            }
        }

        public string Color
        {
            get => _color;
            private set { _color = value; OnPropertyChanged(); }
        }

        private void UpdateColor()
        {
            Color = Level switch
            {
                LogLevel.Error => "#F44336",
                LogLevel.Warning => "#FF9800",
                LogLevel.Success => "#4CAF50",
                LogLevel.Network => "#2196F3",
                LogLevel.Security => "#9C27B0",
                LogLevel.Debug => "#9E9E9E",
                _ => "#FFFFFF"
            };
        }

        public event PropertyChangedEventHandler? PropertyChanged;

        protected virtual void OnPropertyChanged([CallerMemberName] string? propertyName = null)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }
    }
}
