using System;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Windows;
using System.Windows.Input;
using System.Windows.Threading;
using NetworkMonitorWPF.Models;
using NetworkMonitorWPF.Services;

namespace NetworkMonitorWPF.ViewModels
{
    public class MainViewModel : INotifyPropertyChanged
    {
        private static string LogFile = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            "NetworkMonitorWPF_Crash.log");

        private static void LogToFile(string message)
        {
            // Логирование в файл отключено
            // try
            // {
            //     var logMessage = $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss.fff}] {message}";
            //     File.AppendAllText(LogFile, logMessage + Environment.NewLine);
            // }
            // catch
            // {
            //     // Ignore logging errors
            // }
        }
        private readonly RDPMonitor _rdpMonitor;
        private readonly NetworkMonitor _networkMonitor;
        private readonly DispatcherTimer _statsTimer;
        private readonly DispatcherTimer _networkTimer;
        private readonly DispatcherTimer _autoScanTimer;
        private readonly Dispatcher _dispatcher;

        // Коллекции данных
        public ObservableCollection<RDPFailedLogin> LoginAttempts { get; }
        public ObservableCollection<NetworkDevice> NetworkDevices { get; }
        public ObservableCollection<LogMessage> LogMessages { get; }

        // Команды
        public ICommand StartMonitoringCommand { get; }
        public ICommand StopMonitoringCommand { get; }
        public ICommand ClearDataCommand { get; }
        public ICommand ScanNetworkCommand { get; }
        public ICommand DiagnosticCommand { get; }
        public ICommand TestRDPCommand { get; }

        // Свойства для привязки
        private bool _isMonitoring;
        public bool IsMonitoring
        {
            get => _isMonitoring;
            set
            {
                _isMonitoring = value;
                OnPropertyChanged();
                OnPropertyChanged(nameof(CanStart));
                OnPropertyChanged(nameof(CanStop));
            }
        }

        private int _maxFailedAttempts = 5;
        public int MaxFailedAttempts
        {
            get => _maxFailedAttempts;
            set
            {
                _maxFailedAttempts = value;
                OnPropertyChanged();
            }
        }

        private int _timeWindowMinutes = 15;
        public int TimeWindowMinutes
        {
            get => _timeWindowMinutes;
            set
            {
                _timeWindowMinutes = value;
                OnPropertyChanged();
            }
        }

        private bool _enableNetworkMonitoring = true;
        public bool EnableNetworkMonitoring
        {
            get => _enableNetworkMonitoring;
            set
            {
                _enableNetworkMonitoring = value;
                OnPropertyChanged();
            }
        }

        private bool _enableSoundNotifications = true;
        public bool EnableSoundNotifications
        {
            get => _enableSoundNotifications;
            set
            {
                _enableSoundNotifications = value;
                OnPropertyChanged();
            }
        }

        private bool _enableAutoScan = true;
        public bool EnableAutoScan
        {
            get => _enableAutoScan;
            set
            {
                _enableAutoScan = value;
                OnPropertyChanged();
            }
        }

        private int _autoScanIntervalMinutes = 5;
        public int AutoScanIntervalMinutes
        {
            get => _autoScanIntervalMinutes;
            set
            {
                _autoScanIntervalMinutes = value;
                OnPropertyChanged();
                // Обновляем интервал таймера если он уже запущен
                if (_autoScanTimer != null && _autoScanTimer.IsEnabled)
                {
                    _autoScanTimer.Interval = TimeSpan.FromMinutes(value);
                }
            }
        }

        // Статистика
        private int _totalAttempts;
        public int TotalAttempts
        {
            get => _totalAttempts;
            set
            {
                _totalAttempts = value;
                OnPropertyChanged();
            }
        }

        private int _failedAttempts;
        public int FailedAttempts
        {
            get => _failedAttempts;
            set
            {
                _failedAttempts = value;
                OnPropertyChanged();
            }
        }

        private int _networkDevicesCount;
        public int NetworkDevicesCount
        {
            get => _networkDevicesCount;
            set
            {
                _networkDevicesCount = value;
                OnPropertyChanged();
            }
        }

        private int _activeThreats;
        public int ActiveThreats
        {
            get => _activeThreats;
            set
            {
                _activeThreats = value;
                OnPropertyChanged();
            }
        }

        private string _statusMessage = "Готов к работе";
        public string StatusMessage
        {
            get => _statusMessage;
            set
            {
                _statusMessage = value;
                OnPropertyChanged();
            }
        }

        private bool _isScanning;
        public bool IsScanning
        {
            get => _isScanning;
            set
            {
                _isScanning = value;
                OnPropertyChanged();
            }
        }

        public bool CanStart => !IsMonitoring;
        public bool CanStop => IsMonitoring;

        public MainViewModel()
        {
            try
            {
                LogToFile("=== MainViewModel CONSTRUCTOR START ===");

                LogToFile("Getting dispatcher...");
                _dispatcher = Application.Current.Dispatcher;
                LogToFile("Dispatcher OK");

                // Инициализация коллекций
                LogToFile("Creating collections...");
                LoginAttempts = new ObservableCollection<RDPFailedLogin>();
                NetworkDevices = new ObservableCollection<NetworkDevice>();
                LogMessages = new ObservableCollection<LogMessage>();
                LogToFile("Collections OK");

                // Инициализация сервисов
                LogToFile("Creating RDPMonitor...");
                _rdpMonitor = new RDPMonitor
                {
                    MaxFailedAttempts = MaxFailedAttempts,
                    TimeWindow = TimeSpan.FromMinutes(TimeWindowMinutes)
                };
                LogToFile("RDPMonitor OK");

                LogToFile("Creating NetworkMonitor...");
                _networkMonitor = new NetworkMonitor();
                LogToFile("NetworkMonitor OK");

                // Подписка на события RDP Monitor
                LogToFile("Subscribing to RDP events...");
                _rdpMonitor.OnFailedLogin += RdpMonitor_OnFailedLogin;
                _rdpMonitor.OnSuspiciousActivity += RdpMonitor_OnSuspiciousActivity;
                _rdpMonitor.OnLogMessage += OnLogMessage;
                LogToFile("RDP events OK");

                // Подписка на события Network Monitor
                LogToFile("Subscribing to Network events...");
                _networkMonitor.OnNewDeviceDetected += NetworkMonitor_OnNewDeviceDetected;
                _networkMonitor.OnDeviceStatusChanged += NetworkMonitor_OnDeviceStatusChanged;
                _networkMonitor.OnLogMessage += OnLogMessage;
                LogToFile("Network events OK");

                // Инициализация команд
                LogToFile("Creating commands...");
                StartMonitoringCommand = new RelayCommand(_ => StartMonitoring(), _ => CanStart);
                StopMonitoringCommand = new RelayCommand(_ => StopMonitoring(), _ => CanStop);
                ClearDataCommand = new RelayCommand(_ => ClearData());
                ScanNetworkCommand = new RelayCommand(_ => ScanNetwork());
                DiagnosticCommand = new RelayCommand(_ => RunDiagnostic());
                TestRDPCommand = new RelayCommand(_ => TestRDP());
                LogToFile("Commands OK");

                // Таймеры
                LogToFile("Creating timers...");
                _statsTimer = new DispatcherTimer
                {
                    Interval = TimeSpan.FromSeconds(5)
                };
                _statsTimer.Tick += (s, e) => UpdateStatistics();

                _networkTimer = new DispatcherTimer
                {
                    Interval = TimeSpan.FromSeconds(10)
                };
                _networkTimer.Tick += (s, e) => _networkMonitor.UpdateDeviceStatuses();

                _autoScanTimer = new DispatcherTimer
                {
                    Interval = TimeSpan.FromMinutes(AutoScanIntervalMinutes)
                };
                _autoScanTimer.Tick += (s, e) => AutoScanNetwork();
                LogToFile("Timers OK");

                // Приветственное сообщение
                LogToFile("Adding welcome message...");
                AddLogMessage("RDP & Network Security Monitor готов к работе", LogLevel.Info);

                LogToFile("=== MainViewModel CONSTRUCTOR END ===");
            }
            catch (Exception ex)
            {
                var error = $"MAINVIEWMODEL CONSTRUCTOR FAILED:\n{ex.GetType().Name}\n{ex.Message}\n{ex.StackTrace}\n{ex.InnerException?.Message}";
                LogToFile(error);
                MessageBox.Show(error, "Ошибка инициализации", MessageBoxButton.OK, MessageBoxImage.Error);
                throw;
            }
        }

        private void StartMonitoring()
        {
            try
            {
                _rdpMonitor.MaxFailedAttempts = MaxFailedAttempts;
                _rdpMonitor.TimeWindow = TimeSpan.FromMinutes(TimeWindowMinutes);

                _rdpMonitor.StartMonitoring();

                if (EnableNetworkMonitoring)
                {
                    AddLogMessage("Запуск сетевого мониторинга...", LogLevel.Info);
                    _networkMonitor.StartMonitoring();
                    _networkTimer.Start();

                    // Запускаем автоматическое сканирование если включено
                    if (EnableAutoScan)
                    {
                        _autoScanTimer.Interval = TimeSpan.FromMinutes(AutoScanIntervalMinutes);
                        _autoScanTimer.Start();
                        AddLogMessage($"Автосканирование включено (каждые {AutoScanIntervalMinutes} мин)", LogLevel.Info);
                    }
                }

                IsMonitoring = true;
                StatusMessage = "Мониторинг активен";
                _statsTimer.Start();

                AddLogMessage("Система мониторинга запущена успешно", LogLevel.Success);
            }
            catch (Exception ex)
            {
                AddLogMessage($"Ошибка запуска: {ex.Message}", LogLevel.Error);
                MessageBox.Show($"Ошибка запуска мониторинга: {ex.Message}",
                    "Ошибка", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void StopMonitoring()
        {
            _rdpMonitor.StopMonitoring();
            _networkMonitor.StopMonitoring();

            IsMonitoring = false;
            StatusMessage = "Мониторинг остановлен";
            _statsTimer.Stop();
            _networkTimer.Stop();
            _autoScanTimer.Stop();

            AddLogMessage("Система мониторинга остановлена", LogLevel.Warning);
        }

        private void ClearData()
        {
            LoginAttempts.Clear();
            NetworkDevices.Clear();
            LogMessages.Clear();

            _networkMonitor.ClearKnownDevices();

            TotalAttempts = 0;
            FailedAttempts = 0;
            NetworkDevicesCount = 0;
            ActiveThreats = 0;

            AddLogMessage("Данные очищены", LogLevel.Info);
        }

        private async void ScanNetwork()
        {
            if (IsScanning) return;

            IsScanning = true;
            AddLogMessage("Начинаем принудительное сканирование сети...", LogLevel.Info);

            await System.Threading.Tasks.Task.Run(() =>
            {
                _networkMonitor.PerformNetworkScan();
            });

            IsScanning = false;
            AddLogMessage($"Сканирование завершено. Найдено устройств: {NetworkDevices.Count}", LogLevel.Success);
        }

        private async void AutoScanNetwork()
        {
            if (IsScanning || !EnableAutoScan) return;

            IsScanning = true;
            AddLogMessage($"Автоматическое сканирование сети (каждые {AutoScanIntervalMinutes} мин)...", LogLevel.Info);

            await System.Threading.Tasks.Task.Run(() =>
            {
                _networkMonitor.PerformNetworkScan();
            });

            IsScanning = false;
            AddLogMessage($"Автосканирование завершено. Найдено устройств: {NetworkDevices.Count}", LogLevel.Success);
        }

        private void RunDiagnostic()
        {
            AddLogMessage("Запуск системной диагностики...", LogLevel.Info);
            _rdpMonitor.TestEventLogAccess();
        }

        private void TestRDP()
        {
            AddLogMessage("RDP тест: Попробуйте подключиться через RDP к localhost", LogLevel.Info);
            MessageBox.Show(
                "ТЕСТИРОВАНИЕ RDP:\n\n" +
                "1. Откройте 'Подключение к удаленному рабочему столу' (mstsc)\n" +
                "2. Подключитесь к 127.0.0.1 или localhost\n" +
                "3. Попробуйте правильный и неправильный пароль\n" +
                "4. Смотрите результаты в логах\n\n" +
                "События будут отображаться в реальном времени.",
                "RDP Тест",
                MessageBoxButton.OK,
                MessageBoxImage.Information);
        }

        private void RdpMonitor_OnFailedLogin(RDPFailedLogin login)
        {
            _dispatcher.Invoke(() =>
            {
                LoginAttempts.Insert(0, login);

                // Ограничиваем количество записей
                while (LoginAttempts.Count > 1000)
                {
                    LoginAttempts.RemoveAt(LoginAttempts.Count - 1);
                }

                UpdateStatistics();
            });
        }

        private void RdpMonitor_OnSuspiciousActivity(string key, int attempts)
        {
            _dispatcher.Invoke(() =>
            {
                AddLogMessage($"ПОДОЗРИТЕЛЬНАЯ АКТИВНОСТЬ: {attempts} попыток для {key}", LogLevel.Security);

                if (EnableSoundNotifications)
                {
                    System.Media.SystemSounds.Hand.Play();
                }

                MessageBox.Show(
                    $"ОБНАРУЖЕНА ПОДОЗРИТЕЛЬНАЯ RDP АКТИВНОСТЬ!\n\n" +
                    $"Источник: {key}\n" +
                    $"Количество попыток: {attempts}\n" +
                    $"Время: {DateTime.Now:HH:mm:ss}",
                    "КРИТИЧЕСКОЕ ПРЕДУПРЕЖДЕНИЕ",
                    MessageBoxButton.OK,
                    MessageBoxImage.Warning);
            });
        }

        private void NetworkMonitor_OnNewDeviceDetected(NetworkDevice device)
        {
            _dispatcher.Invoke(() =>
            {
                var existing = NetworkDevices.FirstOrDefault(d => d.IPAddress == device.IPAddress);
                if (existing == null)
                {
                    NetworkDevices.Add(device);
                    AddLogMessage($"Новое устройство: {device.DeviceType} {device.IPAddress} ({device.Hostname})", LogLevel.Network);

                    if (EnableSoundNotifications)
                    {
                        System.Media.SystemSounds.Asterisk.Play();
                    }
                }

                UpdateStatistics();
            });
        }

        private void NetworkMonitor_OnDeviceStatusChanged(NetworkDevice device)
        {
            _dispatcher.Invoke(() =>
            {
                var existing = NetworkDevices.FirstOrDefault(d => d.IPAddress == device.IPAddress);
                if (existing != null)
                {
                    existing.Status = device.Status;
                    existing.LastSeen = device.LastSeen;
                }
            });
        }

        private void OnLogMessage(string message, LogLevel level)
        {
            _dispatcher.Invoke(() =>
            {
                AddLogMessage(message, level);
            });
        }

        private void AddLogMessage(string message, LogLevel level)
        {
            var logMessage = new LogMessage
            {
                Timestamp = DateTime.Now,
                Message = message,
                Level = level
            };

            LogMessages.Insert(0, logMessage);

            // Ограничиваем количество логов
            while (LogMessages.Count > 250)
            {
                LogMessages.RemoveAt(LogMessages.Count - 1);
            }
        }

        private void UpdateStatistics()
        {
            TotalAttempts = LoginAttempts.Count;
            FailedAttempts = LoginAttempts.Count(l => l.EventType == "Неудачный вход");
            NetworkDevicesCount = NetworkDevices.Count;

            var attempts = _rdpMonitor.GetCurrentFailedAttempts();
            ActiveThreats = attempts.Count(a => a.Value >= MaxFailedAttempts);
        }

        public event PropertyChangedEventHandler? PropertyChanged;

        protected virtual void OnPropertyChanged([CallerMemberName] string? propertyName = null)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }
    }
}
