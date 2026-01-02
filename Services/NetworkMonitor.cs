using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Threading.Tasks;
using System.Text.RegularExpressions;
using System.Linq;
using System.IO;
using System.Text;
using System.Threading;
using NetworkMonitorWPF.Models;

namespace NetworkMonitorWPF.Services
{
    public class NetworkMonitor
    {
        private readonly Dictionary<string, NetworkDevice> _knownDevices = new Dictionary<string, NetworkDevice>();
        private readonly object _lockObject = new object();
        private bool _isRunning = false;
        private readonly Dictionary<string, string> _vendorDatabase;
        private readonly string _macDatabasePath;
        // Новое: ограничение параллелизма для обновления статусов
        private readonly SemaphoreSlim _statusSemaphore = new SemaphoreSlim(20);
        // Новое: локальные подсети (несколько)
        private List<(IPAddress ip, IPAddress mask, string prefix)> _localSubnets = new List<(IPAddress, IPAddress, string)>();
        private IPAddress? _localIPv4Address; // Первый IP (сохраняем для обратной совместимости)
        private IPAddress? _localSubnetMask;  // Его маска

        // События для логирования
        public event Action<string, LogLevel>? OnLogMessage;

        public event Action<NetworkDevice>? OnNewDeviceDetected;
        public event Action<NetworkDevice>? OnDeviceStatusChanged;

        public NetworkMonitor(string macDatabasePath = "MAC.db")
        {
            _macDatabasePath = macDatabasePath;
            _vendorDatabase = LoadVendorDatabase();
        }

        /// <summary>
        /// Получает безопасную кодировку для вывода консоли (CP866 с fallback на UTF8)
        /// </summary>
        private Encoding GetSafeConsoleEncoding()
        {
            try
            {
                // Пытаемся получить CP866 (DOS Cyrillic)
                return Encoding.GetEncoding(866);
            }
            catch
            {
                // Если CP866 недоступна, используем UTF8
                return Encoding.UTF8;
            }
        }

        /// <summary>
        /// Логирование сообщений через событие
        /// </summary>
        private void WriteLog(string message, LogLevel level = LogLevel.Info)
        {
            OnLogMessage?.Invoke(message, level);
        }

        /// <summary>
        /// Загружает базу данных производителей из файла MAC.db
        /// </summary>
        private Dictionary<string, string> LoadVendorDatabase()
        {
            var database = new Dictionary<string, string>();

            try
            {
                // Поиск файла в разных местах
                string actualPath = _macDatabasePath;
                if (!File.Exists(actualPath))
                {
                    var possiblePaths = new[]
                    {
                        Path.Combine(Directory.GetCurrentDirectory(), "MAC.db"),
                        Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "MAC.db"),
                        Path.Combine(Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location) ?? AppDomain.CurrentDomain.BaseDirectory, "MAC.db"),
                        Path.Combine(Environment.CurrentDirectory, "MAC.db")
                    };

                    foreach (var path in possiblePaths)
                    {
                        if (File.Exists(path))
                        {
                            actualPath = path;
                            WriteLog($"Найден файл MAC.db: {path}", LogLevel.Success);
                            break;
                        }
                    }
                }

                if (!File.Exists(actualPath))
                {
                    WriteLog($"ОШИБКА: Файл базы данных MAC не найден!", LogLevel.Error);
                    WriteLog($"Искали в: {_macDatabasePath}", LogLevel.Error);
                    WriteLog($"Текущая директория: {Directory.GetCurrentDirectory()}", LogLevel.Debug);
                    return database;
                }

                WriteLog($"Загружаем базу данных MAC из файла: {actualPath}", LogLevel.Info);

                // Читаем файл с правильной кодировкой
                var lines = File.ReadAllLines(actualPath, Encoding.UTF8);
                int loadedCount = 0;
                int skippedCount = 0;

                foreach (var line in lines)
                {
                    // Пропускаем пустые строки
                    if (string.IsNullOrWhiteSpace(line))
                    {
                        skippedCount++;
                        continue;
                    }

                    // Проверяем наличие табуляции
                    if (!line.Contains('\t'))
                    {
                        skippedCount++;
                        continue;
                    }

                    // Разделяем по ПЕРВОЙ табуляции
                    var tabIndex = line.IndexOf('\t');
                    if (tabIndex < 0 || tabIndex >= line.Length - 1)
                    {
                        skippedCount++;
                        continue;
                    }

                    var macPrefix = line.Substring(0, tabIndex).Trim().ToUpper();
                    var vendor = line.Substring(tabIndex + 1).Trim();

                    // Проверяем корректность MAC префикса
                    if (IsValidMacPrefix(macPrefix))
                    {
                        database[macPrefix] = vendor;
                        loadedCount++;
                    }
                    else
                    {
                        skippedCount++;
                    }
                }

                WriteLog($"=== ИТОГИ ЗАГРУЗКИ БАЗЫ MAC ===", LogLevel.Success);
                WriteLog($"Загружено записей: {loadedCount}", LogLevel.Success);
                WriteLog($"Пропущено строк: {skippedCount}", LogLevel.Info);
                WriteLog($"Размер базы в памяти: {database.Count}", LogLevel.Success);

                // Проверяем наличие известных префиксов
                var testPrefixes = new[] { "FC253F", "FC019E", "FC01CD" };
                WriteLog("Проверка загрузки известных префиксов:", LogLevel.Info);
                foreach (var prefix in testPrefixes)
                {
                    if (database.ContainsKey(prefix))
                    {
                        WriteLog($"  ✓ {prefix} -> {database[prefix]}", LogLevel.Success);
                    }
                    else
                    {
                        WriteLog($"  ✗ {prefix} -> НЕ НАЙДЕН!", LogLevel.Warning);
                    }
                }
            }
            catch (Exception ex)
            {
                WriteLog($"КРИТИЧЕСКАЯ ОШИБКА загрузки базы данных MAC: {ex.Message}", LogLevel.Error);
            }

            return database;
        }

        /// <summary>
        /// Проверяет корректность MAC префикса
        /// </summary>
        private bool IsValidMacPrefix(string macPrefix)
        {
            if (string.IsNullOrEmpty(macPrefix)) return false;

            // Префикс должен быть 6 символов
            if (macPrefix.Length != 6) return false;

            // Проверяем что все символы - это hex
            foreach (char c in macPrefix)
            {
                if (!((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f')))
                {
                    return false;
                }
            }

            return true;
        }

        /// <summary>
        /// Перезагружает базу данных MAC из файла
        /// </summary>
        public void ReloadMacDatabase()
        {
            WriteLog("Перезагрузка базы данных MAC...", LogLevel.Info);
            var newDatabase = LoadVendorDatabase();
            lock (_lockObject)
            {
                _vendorDatabase.Clear();
                foreach (var kvp in newDatabase)
                {
                    _vendorDatabase[kvp.Key] = kvp.Value;
                }
            }
            WriteLog($"База данных MAC перезагружена. Записей: {_vendorDatabase.Count}", LogLevel.Success);
        }

        /// <summary>
        /// Очищает список известных устройств
        /// </summary>
        public void ClearKnownDevices()
        {
            lock (_lockObject)
            {
                _knownDevices.Clear();
                WriteLog("Список известных устройств очищен", LogLevel.Info);
            }
        }

        /// <summary>
        /// Получает все известные устройства (для восстановления после старта)
        /// </summary>
        public List<NetworkDevice> GetAllKnownDevices()
        {
            lock (_lockObject)
            {
                return _knownDevices.Values.ToList();
            }
        }

        public void StartMonitoring()
        {
            if (_isRunning) return;
            _isRunning = true;

            Task.Run(() => PerformNetworkScan());
        }

        public void StopMonitoring()
        {
            _isRunning = false;
        }

        public void PerformNetworkScan()
        {
            if (!_isRunning) return;

            try
            {
                // Обнаружение ВСЕХ локальных подсетей
                DiscoverLocalSubnets();
                if (_localSubnets.Count == 0)
                {
                    WriteLog("Не удалось определить локальные подсети", LogLevel.Error);
                    return;
                }

                foreach (var (ifaceIp, mask, prefix) in _localSubnets)
                {
                    WriteLog($"Найден локальный IP через NetworkInterface: {ifaceIp}", LogLevel.Debug);
                    WriteLog($"Начинаем сканирование с локального IP: {ifaceIp}", LogLevel.Info);
                    WriteLog($"Сканируем сеть: {prefix}.1-254", LogLevel.Info);

                    // 1. Сначала сканируем ARP таблицу для этой подсети
                    WriteLog("Этап 1: Сканирование ARP таблицы...", LogLevel.Info);
                    ScanARPTable(ifaceIp);

                    // 2. Параллельное пингование всего диапазона /24 для этой подсети
                    WriteLog("Этап 2: Пингование всего диапазона IP адресов...", LogLevel.Info);
                    var pingTasks = new List<Task>();
                    var semaphore = new SemaphoreSlim(50);
                    for (int i = 1; i <= 254; i++)
                    {
                        var ip = $"{prefix}.{i}";
                        pingTasks.Add(Task.Run(async () =>
                        {
                            await semaphore.WaitAsync();
                            try { await ScanDeviceAsync(ip); } finally { semaphore.Release(); }
                        }));
                    }
                    Task.WaitAll(pingTasks.ToArray(), TimeSpan.FromMinutes(3));

                    // 3. Обратный DNS в рамках подсети
                    WriteLog("Этап 3: Проверка DNS записей...", LogLevel.Info);
                    ScanViaReverseDNS(prefix);

                    // 4. Обновление ARP и повторное сканирование для подсети
                    WriteLog("Этап 4: Обновление ARP и повторное сканирование...", LogLevel.Info);
                    RefreshARPTable(prefix);
                    Thread.Sleep(2000);
                    ScanARPTable(ifaceIp);
                }

                WriteLog($"Сканирование завершено. Найдено устройств: {_knownDevices.Count}", LogLevel.Success);
                lock (_lockObject)
                {
                    var deviceTypes = _knownDevices.Values.ToList()
                        .GroupBy(d => d.DeviceType)
                        .Select(g => $"{g.Key}: {g.Count()}")
                        .ToList();
                    WriteLog("Найденные типы устройств:", LogLevel.Info);
                    foreach (var t in deviceTypes) WriteLog($"  {t}", LogLevel.Info);
                }
            }
            catch (Exception ex)
            {
                WriteLog($"Ошибка сканирования сети: {ex.Message}", LogLevel.Error);
            }
        }

        // Новый асинхронный метод сканирования устройства
        private async Task ScanDeviceAsync(string ipAddress)
        {
            try
            {
                using (var ping = new Ping())
                {
                    // Пробуем несколько раз с разными таймаутами
                    var timeouts = new[] { 1000, 2000, 3000 };
                    PingReply? reply = null;

                    foreach (var timeout in timeouts)
                    {
                        reply = await ping.SendPingAsync(ipAddress, timeout);
                        if (reply.Status == IPStatus.Success)
                        {
                            break;
                        }
                    }

                    if (reply != null && reply.Status == IPStatus.Success)
                    {
                        WriteLog($"Пинг успешен: {ipAddress} ({reply.RoundtripTime}ms)", LogLevel.Debug);

                        var device = new NetworkDevice
                        {
                            IPAddress = ipAddress,
                            MACAddress = GetMACAddress(ipAddress),
                            Hostname = GetHostname(ipAddress),
                            Status = "Активен",
                            LastSeen = DateTime.Now
                        };

                        // Если MAC неизвестен и это не multicast/broadcast — пропускаем
                        if (device.MACAddress == "Неизвестно" && !IsMulticastOrBroadcast(ipAddress))
                        {
                            WriteLog($"Пропуск {ipAddress}: MAC неизвестен", LogLevel.Debug);
                            return;
                        }

                        device.Vendor = GetVendorFromMAC(device.MACAddress);
                        device.DeviceType = DetermineDeviceType(device);
                        device.OperatingSystem = DetectOperatingSystem(device);
                        device.OpenPorts = ScanCommonPorts(ipAddress);
                        device.Description = GenerateDeviceDescription(device);

                        WriteLog($"Устройство {device.IPAddress}: MAC={device.MACAddress}, Vendor={device.Vendor}, Type={device.DeviceType}", LogLevel.Info);
                        ProcessDevice(device);
                    }
                }
            }
            catch (Exception ex)
            {
                WriteLog($"Ошибка сканирования {ipAddress}: {ex.Message}", LogLevel.Debug);
            }
        }

        // Новый метод: Обновление ARP таблицы принудительным пингованием
        private void RefreshARPTable(string networkPrefix)
        {
            try
            {
                WriteLog("Обновляем ARP таблицу быстрым пингованием...", LogLevel.Debug);

                // Быстрое пингование всей подсети для обновления ARP
                var refreshTasks = new List<Task>();

                for (int i = 1; i <= 254; i++)
                {
                    var ip = $"{networkPrefix}.{i}";
                    refreshTasks.Add(Task.Run(async () =>
                    {
                        try
                        {
                            using (var ping = new Ping())
                            {
                                // Короткий таймаут для быстрого обновления ARP
                                await ping.SendPingAsync(ip, 100);
                            }
                        }
                        catch { } // Игнорируем ошибки, нам важно только обновить ARP
                    }));
                }

                Task.WaitAll(refreshTasks.ToArray(), TimeSpan.FromSeconds(30));
                WriteLog("ARP таблица обновлена", LogLevel.Debug);
            }
            catch (Exception ex)
            {
                WriteLog($"Ошибка обновления ARP: {ex.Message}", LogLevel.Warning);
            }
        }

        // Новый метод: Сканирование через обратный DNS
        private void ScanViaReverseDNS(string networkPrefix)
        {
            try
            {
                WriteLog("Проверяем DNS записи для пропущенных устройств...", LogLevel.Debug);

                var dnsTasks = new List<Task>();
                var semaphore = new SemaphoreSlim(20); // Ограничиваем DNS запросы

                for (int i = 1; i <= 254; i++)
                {
                    var ip = $"{networkPrefix}.{i}";

                    // Пропускаем уже найденные устройства
                    lock (_lockObject)
                    {
                        if (_knownDevices.ContainsKey(ip))
                            continue;
                    }

                    dnsTasks.Add(Task.Run(async () =>
                    {
                        await semaphore.WaitAsync();
                        try
                        {
                            var hostEntry = await Dns.GetHostEntryAsync(ip);
                            if (!string.IsNullOrEmpty(hostEntry.HostName) && hostEntry.HostName != ip)
                            {
                                WriteLog($"DNS нашел устройство: {ip} = {hostEntry.HostName}", LogLevel.Info);

                                // Пробуем еще раз пропинговать
                                await ScanDeviceAsync(ip);
                            }
                        }
                        catch { } // Игнорируем ошибки DNS
                        finally
                        {
                            semaphore.Release();
                        }
                    }));
                }

                Task.WaitAll(dnsTasks.ToArray(), TimeSpan.FromSeconds(30));
            }
            catch (Exception ex)
            {
                WriteLog($"Ошибка DNS сканирования: {ex.Message}", LogLevel.Warning);
            }
        }

        /// <summary>
        /// Принудительно сканирует конкретный IP адрес
        /// </summary>
        public async Task<bool> ForceScanSpecificIP(string ipAddress)
        {
            try
            {
                WriteLog($"Принудительное сканирование {ipAddress}...", LogLevel.Info);

                // Сначала пробуем обновить ARP для этого IP
                using (var ping = new Ping())
                {
                    // Несколько быстрых пингов для обновления ARP
                    for (int i = 0; i < 3; i++)
                    {
                        await ping.SendPingAsync(ipAddress, 500);
                        await Task.Delay(100);
                    }
                }

                // Теперь полное сканирование
                await ScanDeviceAsync(ipAddress);

                // Проверяем, нашли ли устройство
                lock (_lockObject)
                {
                    if (_knownDevices.ContainsKey(ipAddress))
                    {
                        WriteLog($"✅ Устройство {ipAddress} успешно добавлено", LogLevel.Success);
                        return true;
                    }
                }

                // Если не нашли через пинг, пробуем добавить вручную
                WriteLog($"Устройство {ipAddress} не отвечает на пинг, добавляем вручную...", LogLevel.Warning);

                var device = new NetworkDevice
                {
                    IPAddress = ipAddress,
                    MACAddress = GetMACAddress(ipAddress),
                    Hostname = GetHostname(ipAddress),
                    Status = "Недоступен",
                    LastSeen = DateTime.Now,
                    FirstSeen = DateTime.Now,
                    DeviceType = "❓ Неизвестное устройство",
                    OperatingSystem = "Неизвестно",
                    Vendor = "Неизвестно",
                    Description = "Устройство добавлено вручную",
                    IsNew = true
                };

                // Если получили MAC, пробуем определить производителя
                if (device.MACAddress != "Неизвестно")
                {
                    device.Vendor = GetVendorFromMAC(device.MACAddress);
                    device.DeviceType = DetermineDeviceType(device);
                }

                ProcessDevice(device);
                return true;
            }
            catch (Exception ex)
            {
                WriteLog($"Ошибка принудительного сканирования {ipAddress}: {ex.Message}", LogLevel.Error);
                return false;
            }
        }

        /// <summary>
        /// Принудительно обновляет MAC адрес для устройства
        /// </summary>
        public async Task<string> ForceUpdateMacAddress(string ipAddress)
        {
            try
            {
                WriteLog($"Принудительное обновление MAC для {ipAddress}...", LogLevel.Info);

                // 1. Сначала пингуем несколько раз для обновления ARP
                using (var ping = new Ping())
                {
                    for (int i = 0; i < 5; i++)
                    {
                        try
                        {
                            var reply = await ping.SendPingAsync(ipAddress, 1000);
                            if (reply.Status == IPStatus.Success)
                            {
                                WriteLog($"Ping {i + 1}/5 успешен: {reply.RoundtripTime}ms", LogLevel.Debug);
                            }
                        }
                        catch { }
                        await Task.Delay(200);
                    }
                }

                // 2. Ждем обновления ARP кеша
                await Task.Delay(500);

                // 3. Пробуем все методы получения MAC
                var mac = GetMACAddress(ipAddress);

                // 4. Обновляем устройство если MAC найден
                if (!string.IsNullOrEmpty(mac) && mac != "Неизвестно")
                {
                    lock (_lockObject)
                    {
                        if (_knownDevices.ContainsKey(ipAddress))
                        {
                            var device = _knownDevices[ipAddress];
                            device.MACAddress = mac;

                            // Обновляем вендора и тип устройства
                            device.Vendor = GetVendorFromMAC(mac);
                            device.DeviceType = DetermineDeviceType(device);

                            OnDeviceStatusChanged?.Invoke(device);

                            WriteLog($"✅ MAC обновлен для {ipAddress}: {mac} ({device.Vendor})", LogLevel.Success);
                        }
                    }
                    return mac;
                }
                else
                {
                    WriteLog($"❌ Не удалось получить MAC для {ipAddress}", LogLevel.Error);
                    return "Неизвестно";
                }
            }
            catch (Exception ex)
            {
                WriteLog($"Ошибка обновления MAC: {ex.Message}", LogLevel.Error);
                return "Неизвестно";
            }
        }

        private void ScanARPTable()
        {
            try
            {
                // НЕ очищаем ARP кеш - просто читаем текущую таблицу

                var process = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = "arp",
                        Arguments = _localIPv4Address != null ? $"-a -N {_localIPv4Address}" : "-a",
                        UseShellExecute = false,
                        RedirectStandardOutput = true,
                        CreateNoWindow = true,
                        StandardOutputEncoding = GetSafeConsoleEncoding() // Безопасная кодировка с fallback
                    }
                };

                process.Start();
                var output = process.StandardOutput.ReadToEnd();
                process.WaitForExit();

                WriteLog($"ARP таблица получена, размер: {output.Length} символов", LogLevel.Debug);

                // Парсим ARP таблицу
                var lines = output.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
                int deviceCount = 0;
                int skippedCount = 0;

                foreach (var line in lines)
                {
                    // Пропускаем заголовки и пустые строки (регистронезависимо)
                    if (string.IsNullOrWhiteSpace(line))
                    {
                        skippedCount++;
                        continue;
                    }
                    var headerLower = line.Trim().ToLowerInvariant();
                    if (headerLower.Contains("interface") || headerLower.Contains("internet address") || headerLower.Contains("интерфейс") || headerLower.Contains("адрес"))
                    {
                        skippedCount++;
                        continue;
                    }

                    var trimmed = line.Trim();

                    // Паттерны для разных форматов вывода
                    var pIpMacTypeDash = @"^(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5})\s+(\S+)";
                    var pIpMacTypeColon = @"^(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})\s+(\S+)";
                    var pIpMacDash = @"^(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5})";
                    var pIpMacColon = @"^(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})";
                    var pIpTypeRu = @"^(\d+\.\d+\.\d+\.\d+)\s+(динамический|статический)"; // Русский вывод без MAC

                    string? ip = null;
                    string? macRaw = null;
                    string? type = null;

                    Match m;
                    if ((m = Regex.Match(trimmed, pIpMacTypeDash)).Success || (m = Regex.Match(trimmed, pIpMacTypeColon)).Success)
                    {
                        ip = m.Groups[1].Value;
                        macRaw = m.Groups[2].Value;
                        type = m.Groups[3].Value;
                    }
                    else if ((m = Regex.Match(trimmed, pIpMacDash)).Success || (m = Regex.Match(trimmed, pIpMacColon)).Success)
                    {
                        ip = m.Groups[1].Value;
                        macRaw = m.Groups[2].Value;
                    }
                    else if ((m = Regex.Match(trimmed, pIpTypeRu)).Success)
                    {
                        ip = m.Groups[1].Value;
                        type = m.Groups[2].Value; // MAC отсутствует в выводе
                    }

                    if (!string.IsNullOrEmpty(ip))
                    {
                        // Фильтруем только локальную подсеть и убираем спец-адреса
                        if (IsSpecialOrNonLocal(ip))
                        {
                            skippedCount++;
                            continue;
                        }
                        var mac = !string.IsNullOrEmpty(macRaw) ? NormalizeMacAddress(macRaw) : "Неизвестно";

                        // НЕ пропускаем multicast и broadcast - это тоже важная информация!

                        // Избегаем дубликатов внутри одного прохода по строкам
                        deviceCount++;
                        WriteLog($"ARP запись #{deviceCount}: IP={ip}, MAC={mac}", LogLevel.Debug);

                        // Создаем устройство из ARP записи
                        var device = new NetworkDevice
                        {
                            IPAddress = ip,
                            MACAddress = mac,
                            Hostname = GetHostname(ip),
                            Status = "Активен",
                            LastSeen = DateTime.Now
                        };

                        device.Vendor = GetVendorFromMAC(device.MACAddress);
                        device.DeviceType = DetermineDeviceType(device);
                        device.OperatingSystem = DetectOperatingSystem(device);

                        // Сканирование портов делаем опционально для ускорения
                        if (deviceCount <= 20) // Сканируем порты только для первых 20 устройств
                        {
                            device.OpenPorts = ScanCommonPorts(ip);
                        }
                        else
                        {
                            device.OpenPorts = new List<int>();
                        }

                        device.Description = GenerateDeviceDescription(device);

                        ProcessDevice(device);
                    }
                    else
                    {
                        WriteLog($"Не удалось распарсить строку: {line}", LogLevel.Debug);
                        skippedCount++;
                    }
                }

                WriteLog($"Обработано {deviceCount} записей из ARP таблицы, пропущено {skippedCount}", LogLevel.Info);
            }
            catch (Exception ex)
            {
                WriteLog($"Ошибка сканирования ARP: {ex.Message}", LogLevel.Error);
            }
        }

        // Перегрузка: ARP для конкретного интерфейса
        private void ScanARPTable(IPAddress ifaceIp)
        {
            try
            {
                var process = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = "arp",
                        Arguments = ifaceIp != null ? $"-a -N {ifaceIp}" : "-a",
                        UseShellExecute = false,
                        RedirectStandardOutput = true,
                        CreateNoWindow = true,
                        StandardOutputEncoding = GetSafeConsoleEncoding()
                    }
                };

                process.Start();
                var output = process.StandardOutput.ReadToEnd();
                process.WaitForExit();

                WriteLog($"ARP таблица получена, размер: {output.Length} символов", LogLevel.Debug);

                // Парсим
                var lines = output.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
                int deviceCount = 0;
                int skippedCount = 0;
                foreach (var line in lines)
                {
                    if (string.IsNullOrWhiteSpace(line)) { skippedCount++; continue; }
                    var headerLower = line.Trim().ToLowerInvariant();
                    if (headerLower.Contains("interface") || headerLower.Contains("internet address") || headerLower.Contains("интерфейс") || headerLower.Contains("адрес")) { skippedCount++; continue; }

                    var trimmed = line.Trim();
                    var pIpMacTypeDash = @"^(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5})\s+(\S+)";
                    var pIpMacTypeColon = @"^(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})\s+(\S+)";
                    var pIpMacDash = @"^(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5})";
                    var pIpMacColon = @"^(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})";
                    var pIpTypeRu = @"^(\d+\.\d+\.\d+\.\d+)\s+(динамический|статический)";

                    string? ip = null; string? macRaw = null; string? type = null;
                    Match m;
                    if ((m = Regex.Match(trimmed, pIpMacTypeDash)).Success || (m = Regex.Match(trimmed, pIpMacTypeColon)).Success) { ip = m.Groups[1].Value; macRaw = m.Groups[2].Value; type = m.Groups[3].Value; }
                    else if ((m = Regex.Match(trimmed, pIpMacDash)).Success || (m = Regex.Match(trimmed, pIpMacColon)).Success) { ip = m.Groups[1].Value; macRaw = m.Groups[2].Value; }
                    else if ((m = Regex.Match(trimmed, pIpTypeRu)).Success) { ip = m.Groups[1].Value; type = m.Groups[2].Value; }

                    if (!string.IsNullOrEmpty(ip))
                    {
                        if (IsSpecialOrNonLocal(ip)) { skippedCount++; continue; }
                        var mac = !string.IsNullOrEmpty(macRaw) ? NormalizeMacAddress(macRaw) : "Неизвестно";
                        if (mac == "Неизвестно" && !IsMulticastOrBroadcast(ip)) { skippedCount++; continue; }
                        deviceCount++;
                        WriteLog($"ARP запись #{deviceCount}: IP={ip}, MAC={mac}", LogLevel.Debug);
                        var device = new NetworkDevice { IPAddress = ip, MACAddress = mac, Hostname = GetHostname(ip), Status = "Активен", LastSeen = DateTime.Now };
                        device.Vendor = GetVendorFromMAC(device.MACAddress);
                        device.DeviceType = DetermineDeviceType(device);
                        device.OperatingSystem = DetectOperatingSystem(device);
                        device.OpenPorts = deviceCount <= 20 ? ScanCommonPorts(ip) : new List<int>();
                        device.Description = GenerateDeviceDescription(device);
                        ProcessDevice(device);
                    }
                    else { skippedCount++; }
                }
                WriteLog($"Обработано {deviceCount} записей из ARP таблицы, пропущено {skippedCount}", LogLevel.Info);
            }
            catch (Exception ex)
            {
                WriteLog($"Ошибка сканирования ARP: {ex.Message}", LogLevel.Error);
            }
        }

        private void ProcessDevice(NetworkDevice device)
        {
            // Фильтруем строго: обрабатываем только локальную подсеть
            if (device == null || IsSpecialOrNonLocal(device.IPAddress))
            {
                return;
            }
            lock (_lockObject)
            {
                var key = device.IPAddress;

                if (_knownDevices.ContainsKey(key))
                {
                    // Обновляем существующее устройство
                    var existingDevice = _knownDevices[key];
                    existingDevice.Status = device.Status;
                    existingDevice.LastSeen = device.LastSeen;

                    // Обновляем MAC если он был неизвестен или изменился
                    if ((existingDevice.MACAddress == "Неизвестно" || string.IsNullOrEmpty(existingDevice.MACAddress))
                        && device.MACAddress != "Неизвестно" && !string.IsNullOrEmpty(device.MACAddress))
                    {
                        existingDevice.MACAddress = device.MACAddress;
                        existingDevice.Vendor = device.Vendor;
                        existingDevice.DeviceType = device.DeviceType;
                        WriteLog($"Обновлен MAC для {device.IPAddress}: {device.MACAddress}", LogLevel.Success);
                    }

                    // Обновляем hostname если он изменился
                    if (!string.IsNullOrEmpty(device.Hostname) && device.Hostname != existingDevice.Hostname)
                    {
                        existingDevice.Hostname = device.Hostname;
                    }

                    OnDeviceStatusChanged?.Invoke(existingDevice);
                }
                else
                {
                    // Новое устройство
                    device.FirstSeen = DateTime.Now;
                    device.IsNew = true;
                    _knownDevices[key] = device;

                    OnNewDeviceDetected?.Invoke(device);
                }
            }
        }

        public void UpdateDeviceStatuses()
        {
            if (!_isRunning) return;

            var devicesToCheck = new List<NetworkDevice>();
            lock (_lockObject)
            {
                devicesToCheck.AddRange(_knownDevices.Values.ToList());
            }

            foreach (var device in devicesToCheck)
            {
                Task.Run(async () =>
                {
                    await _statusSemaphore.WaitAsync().ConfigureAwait(false);
                    try
                    {
                        using (var ping = new Ping())
                        {
                            var reply = ping.Send(device.IPAddress, 1000);
                            var newStatus = reply.Status == IPStatus.Success ? "Активен" : "Недоступен";

                            if (device.Status != newStatus)
                            {
                                device.Status = newStatus;
                                device.LastSeen = DateTime.Now;
                                OnDeviceStatusChanged?.Invoke(device);
                            }
                        }
                    }
                    catch (Exception)
                    {
                        device.Status = "Ошибка";
                        OnDeviceStatusChanged?.Invoke(device);
                    }
                    finally
                    {
                        _statusSemaphore.Release();
                    }
                });
            }
        }

        private string GetLocalIPAddress()
        {
            try
            {
                // Метод 1: Через NetworkInterface (более надежный)
                foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (ni.OperationalStatus == OperationalStatus.Up &&
                        ni.NetworkInterfaceType != NetworkInterfaceType.Loopback)
                    {
                        foreach (var addr in ni.GetIPProperties().UnicastAddresses)
                        {
                            if (addr.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                            {
                                var ip = addr.Address.ToString();
                                // Проверяем что это локальная сеть
                                if (ip.StartsWith("192.168.") || ip.StartsWith("10.") ||
                                    (ip.StartsWith("172.") && IsInRange172(ip)))
                                {
                                    WriteLog($"Найден локальный IP через NetworkInterface: {ip}", LogLevel.Debug);
                                    return ip;
                                }
                            }
                        }
                    }
                }

                // Метод 2: Через DNS (fallback) — с защитой от исключений
                try
                {
                    var host = System.Net.Dns.GetHostEntry(System.Net.Dns.GetHostName());
                    foreach (var ip in host.AddressList)
                    {
                        if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                        {
                            var ipStr = ip.ToString();
                            if (ipStr.StartsWith("192.168.") || ipStr.StartsWith("10.") ||
                                (ipStr.StartsWith("172.") && IsInRange172(ipStr)))
                            {
                                WriteLog($"Найден локальный IP через DNS: {ipStr}", LogLevel.Debug);
                                return ipStr;
                            }
                        }
                    }
                }
                catch (System.Net.Sockets.SocketException) { }
                catch { }

                // Метод 3: Подключение к внешнему адресу — оборачиваем в try/catch
                try
                {
                    using (var socket = new System.Net.Sockets.Socket(System.Net.Sockets.AddressFamily.InterNetwork,
                                                                         System.Net.Sockets.SocketType.Dgram, 0))
                    {
                        // Без реального подключения (UDP), с коротким таймаутом
                        socket.ReceiveTimeout = 500;
                        socket.SendTimeout = 500;
                        try { socket.Connect("8.8.8.8", 65530); } catch (System.Net.Sockets.SocketException) { }
                        var endPoint = socket.LocalEndPoint as System.Net.IPEndPoint;
                        if (endPoint != null)
                        {
                            WriteLog($"Найден локальный IP через socket: {endPoint.Address}", LogLevel.Debug);
                            return endPoint.Address.ToString();
                        }
                    }
                }
                catch (System.Net.Sockets.SocketException) { }
                catch { }
            }
            catch (Exception ex)
            {
                WriteLog($"Ошибка получения локального IP: {ex.Message}", LogLevel.Error);
            }

            WriteLog("Используем fallback IP: 192.168.1.100", LogLevel.Warning);
            return "192.168.1.100"; // Fallback
        }

        private bool IsInRange172(string ip)
        {
            try
            {
                var parts = ip.Split('.');
                if (parts.Length >= 2)
                {
                    var secondOctet = int.Parse(parts[1]);
                    return secondOctet >= 16 && secondOctet <= 31; // 172.16.0.0 - 172.31.255.255
                }
            }
            catch { }
            return false;
        }

        private string GetNetworkPrefix(string ipAddress)
        {
            var parts = ipAddress.Split('.');
            return $"{parts[0]}.{parts[1]}.{parts[2]}";
        }

        // Улучшенный метод получения MAC адреса с множественными методами
        private string GetMACAddress(string ipAddress)
        {
            try
            {
                WriteLog($"Получаем MAC для IP: {ipAddress}", LogLevel.Debug);

                // Метод 1: Прямой запрос ARP для конкретного IP
                var macViaArp = GetMacViaArpCommand(ipAddress);
                if (!string.IsNullOrEmpty(macViaArp) && macViaArp != "Неизвестно")
                {
                    WriteLog($"MAC получен через ARP: {macViaArp}", LogLevel.Debug);
                    return macViaArp;
                }

                // Метод 2: Поиск в полной ARP таблице
                var macViaTable = GetMacFromArpTable(ipAddress);
                if (!string.IsNullOrEmpty(macViaTable) && macViaTable != "Неизвестно")
                {
                    WriteLog($"MAC найден в ARP таблице: {macViaTable}", LogLevel.Debug);
                    return macViaTable;
                }

                // Метод 3: Через nbtstat для Windows устройств
                var macViaNbtstat = GetMacViaNbtstat(ipAddress);
                if (!string.IsNullOrEmpty(macViaNbtstat) && macViaNbtstat != "Неизвестно")
                {
                    WriteLog($"MAC получен через nbtstat: {macViaNbtstat}", LogLevel.Debug);
                    return macViaNbtstat;
                }

                // Метод 4: Через ping + arp (обновляем ARP кеш)
                var macAfterPing = GetMacAfterPing(ipAddress);
                if (!string.IsNullOrEmpty(macAfterPing) && macAfterPing != "Неизвестно")
                {
                    WriteLog($"MAC получен после ping: {macAfterPing}", LogLevel.Debug);
                    return macAfterPing;
                }

                // Метод 5: Для локального компьютера
                if (ipAddress == GetLocalIPAddress())
                {
                    var localMac = GetLocalMacAddress();
                    if (!string.IsNullOrEmpty(localMac))
                    {
                        WriteLog($"Локальный MAC: {localMac}", LogLevel.Debug);
                        return localMac;
                    }
                }

                WriteLog($"Не удалось получить MAC для {ipAddress}", LogLevel.Warning);
                return "Неизвестно";
            }
            catch (Exception ex)
            {
                WriteLog($"Ошибка получения MAC для {ipAddress}: {ex.Message}", LogLevel.Error);
                return "Неизвестно";
            }
        }

        // Метод 1: Прямой ARP запрос
        private string GetMacViaArpCommand(string ipAddress)
        {
            try
            {
                var process = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = "arp",
                        Arguments = $"-a {ipAddress}",
                        UseShellExecute = false,
                        RedirectStandardOutput = true,
                        CreateNoWindow = true,
                        StandardOutputEncoding = GetSafeConsoleEncoding() // Безопасная кодировка с fallback
                    }
                };

                process.Start();
                var output = process.StandardOutput.ReadToEnd();
                process.WaitForExit();

                // Ищем MAC в разных форматах
                var patterns = new[]
                {
                    @"([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})",
                    @"([0-9A-Fa-f]{2}\s){5}([0-9A-Fa-f]{2})",
                    @"([0-9A-Fa-f]{4}\.){2}([0-9A-Fa-f]{4})" // Cisco формат
                };

                foreach (var pattern in patterns)
                {
                    var match = Regex.Match(output, pattern);
                    if (match.Success)
                    {
                        var mac = match.Value.ToUpper();
                        // Нормализуем формат
                        mac = NormalizeMacAddress(mac);
                        return mac;
                    }
                }

                return "Неизвестно";
            }
            catch
            {
                return "Неизвестно";
            }
        }

        // Метод 2: Поиск в полной ARP таблице
        private string GetMacFromArpTable(string ipAddress)
        {
            try
            {
                var process = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = "arp",
                        Arguments = "-a",
                        UseShellExecute = false,
                        RedirectStandardOutput = true,
                        CreateNoWindow = true,
                        StandardOutputEncoding = GetSafeConsoleEncoding()
                    }
                };

                process.Start();
                var output = process.StandardOutput.ReadToEnd();
                process.WaitForExit();

                // Разбиваем на строки
                var lines = output.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);

                foreach (var line in lines)
                {
                    if (line.Contains(ipAddress))
                    {
                        // Паттерн для поиска MAC в строке с нужным IP
                        var match = Regex.Match(line, @"([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})");
                        if (match.Success)
                        {
                            return NormalizeMacAddress(match.Value.ToUpper());
                        }
                    }
                }

                return "Неизвестно";
            }
            catch
            {
                return "Неизвестно";
            }
        }

        // Метод 3: Через nbtstat (для Windows машин)
        private string GetMacViaNbtstat(string ipAddress)
        {
            try
            {
                var process = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = "nbtstat",
                        Arguments = $"-a {ipAddress}",
                        UseShellExecute = false,
                        RedirectStandardOutput = true,
                        RedirectStandardError = true,
                        CreateNoWindow = true,
                        StandardOutputEncoding = GetSafeConsoleEncoding()
                    }
                };

                process.Start();

                // Ограничиваем время выполнения
                if (!process.WaitForExit(3000))
                {
                    process.Kill();
                    return "Неизвестно";
                }

                var output = process.StandardOutput.ReadToEnd();

                // Ищем строку "MAC Address = XX-XX-XX-XX-XX-XX"
                var match = Regex.Match(output, @"MAC[^=]*=\s*([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})");
                if (match.Success)
                {
                    var macPart = Regex.Match(match.Value, @"([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})");
                    if (macPart.Success)
                    {
                        return NormalizeMacAddress(macPart.Value.ToUpper());
                    }
                }

                return "Неизвестно";
            }
            catch
            {
                return "Неизвестно";
            }
        }

        // Метод 4: Ping + ARP
        private string GetMacAfterPing(string ipAddress)
        {
            try
            {
                // Сначала пингуем для обновления ARP кеша
                using (var ping = new Ping())
                {
                    ping.Send(ipAddress, 1000);
                    System.Threading.Thread.Sleep(100); // Даем время на обновление ARP
                }

                // Теперь пробуем получить MAC
                return GetMacViaArpCommand(ipAddress);
            }
            catch
            {
                return "Неизвестно";
            }
        }

        // Метод 5: Получение локального MAC адреса
        private string GetLocalMacAddress()
        {
            try
            {
                foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (nic.OperationalStatus == OperationalStatus.Up &&
                        nic.NetworkInterfaceType != NetworkInterfaceType.Loopback)
                    {
                        var mac = nic.GetPhysicalAddress().ToString();
                        if (!string.IsNullOrEmpty(mac) && mac.Length == 12)
                        {
                            // Форматируем MAC
                            var formattedMac = string.Join(":",
                                Enumerable.Range(0, 6).Select(i => mac.Substring(i * 2, 2)));
                            return formattedMac.ToUpper();
                        }
                    }
                }
            }
            catch { }

            return "Неизвестно";
        }

        // Вспомогательный метод для нормализации MAC адреса
        private string NormalizeMacAddress(string mac)
        {
            if (string.IsNullOrEmpty(mac)) return mac;

            // Удаляем все разделители
            var cleanMac = Regex.Replace(mac, @"[^0-9A-Fa-f]", "");

            // Проверяем длину
            if (cleanMac.Length != 12) return mac;

            // Форматируем как XX:XX:XX:XX:XX:XX
            var formatted = string.Join(":",
                Enumerable.Range(0, 6).Select(i => cleanMac.Substring(i * 2, 2)));

            return formatted.ToUpper();
        }

        // Улучшенный метод получения hostname
        private string GetHostname(string ipAddress)
        {
            try
            {
                // Асинхронный DNS с таймаутом без блокировок .Result/.Wait на UI
                var dnsTask = Dns.GetHostEntryAsync(ipAddress);
                var timeoutTask = Task.Delay(TimeSpan.FromSeconds(3));
                var completed = Task.WhenAny(dnsTask, timeoutTask).GetAwaiter().GetResult();
                if (completed == dnsTask && dnsTask.Status == TaskStatus.RanToCompletion && dnsTask.Result != null)
                {
                    return dnsTask.Result.HostName;
                }
                return "Неизвестно";
            }
            catch (Exception)
            {
                return "Неизвестно";
            }
        }

        // Возвращаем GetVendorFromMAC как public для использования в MainForm
        public string GetVendorFromMAC(string macAddress)
        {
            if (string.IsNullOrEmpty(macAddress) || macAddress == "Неизвестно")
            {
                WriteLog($"GetVendorFromMAC: MAC адрес пустой или неизвестен", LogLevel.Debug);
                return "Неизвестно";
            }

            try
            {
                // Очищаем MAC от всех разделителей
                var cleanMac = macAddress.Replace(":", "").Replace("-", "").Replace(" ", "").ToUpper();

                // Проверяем длину
                if (cleanMac.Length < 6)
                {
                    WriteLog($"ОШИБКА: MAC слишком короткий после очистки: {cleanMac.Length} символов", LogLevel.Warning);
                    return "Неизвестно";
                }

                // Берем первые 6 символов
                var prefix = cleanMac.Substring(0, 6);

                // Специальные случаи для известных префиксов (без лишних логов)
                if (prefix.StartsWith("01005E"))
                {
                    return "Multicast адрес";
                }
                if (prefix == "FFFFFF")
                {
                    return "Broadcast адрес";
                }
                if (prefix.StartsWith("3333"))
                {
                    return "IPv6 Multicast";
                }

                // Подробные логи только для обычного поиска в базе
                WriteLog($"=== ПОИСК ВЕНДОРА ДЛЯ MAC: {macAddress} ===", LogLevel.Debug);
                WriteLog($"Очищенный MAC: {cleanMac}", LogLevel.Debug);
                WriteLog($"Префикс для поиска: {prefix}", LogLevel.Debug);

                lock (_lockObject)
                {
                    WriteLog($"Размер базы данных: {_vendorDatabase.Count} записей", LogLevel.Debug);

                    if (_vendorDatabase.Count == 0)
                    {
                        WriteLog("ОШИБКА: База данных MAC пуста!", LogLevel.Error);
                        return "Неизвестно";
                    }

                    if (_vendorDatabase.ContainsKey(prefix))
                    {
                        var vendor = _vendorDatabase[prefix];
                        WriteLog($"✓ НАЙДЕН ВЕНДОР: {vendor}", LogLevel.Success);
                        return vendor;
                    }

                    // Альтернативный поиск: иногда префикс может быть в другом формате
                    var altPrefix = prefix.ToUpper();
                    if (_vendorDatabase.ContainsKey(altPrefix))
                    {
                        var vendor = _vendorDatabase[altPrefix];
                        WriteLog($"✓ НАЙДЕН через альтернативный префикс {altPrefix}: {vendor}", LogLevel.Success);
                        return vendor;
                    }
                }

                WriteLog($"✗ Вендор НЕ НАЙДЕН для префикса: {prefix}", LogLevel.Debug);
                return "Неизвестно";
            }
            catch (Exception ex)
            {
                WriteLog($"КРИТИЧЕСКАЯ ОШИБКА в GetVendorFromMAC: {ex.Message}", LogLevel.Error);
                return "Неизвестно";
            }
        }

        /// <summary>
        /// Получает альтернативные префиксы для поиска
        /// </summary>
        private List<string> GetAlternativePrefixes(string prefix)
        {
            var alternatives = new List<string>();

            // Некоторые производители имеют несколько префиксов
            if (prefix.StartsWith("04D4C4"))
            {
                alternatives.Add("04D9F5"); // ASUSTek
                alternatives.Add("04D3CF"); // ASUSTek
            }
            else if (prefix.StartsWith("C4EB42"))
            {
                alternatives.Add("C4E984"); // TP-Link
                alternatives.Add("C46E1F"); // TP-Link
            }

            return alternatives;
        }

        /// <summary>
        /// Определяет производителя по паттерну MAC адреса
        /// </summary>
        private string DetermineVendorByPattern(string prefix)
        {
            // Известные паттерны для производителей, которых может не быть в базе
            if (prefix.StartsWith("04D4C4"))
            {
                return "ASUSTek Computer Inc. (вероятно)";
            }
            if (prefix.StartsWith("C4EB42"))
            {
                return "TP-Link Technologies (вероятно)";
            }
            if (prefix.StartsWith("04D9F5"))
            {
                return "ASUSTek Computer Inc.";
            }

            // Проверяем первые 2 символа для общих категорий
            var firstTwo = prefix.Substring(0, 2);
            switch (firstTwo)
            {
                case "00":
                    return "Старое сетевое оборудование";
                case "02":
                    return "Локально администрируемый адрес";
                case "AA":
                case "AB":
                case "AC":
                    return "Виртуальная машина (вероятно)";
                default:
                    return "Неизвестно";
            }
        }

        private string DetermineDeviceType(NetworkDevice device)
        {
            var hostname = device.Hostname?.ToLower() ?? "";
            var vendor = device.Vendor?.ToLower() ?? "";

            // Проверяем специальные типы адресов
            if (vendor.Contains("multicast"))
                return "📡 Multicast адрес";
            if (vendor.Contains("broadcast"))
                return "📢 Broadcast адрес";
            if (vendor.Contains("ipv6 multicast"))
                return "📡 IPv6 Multicast";

            // Сначала пытаемся определить тип только по hostname (более точно)
            if (hostname.Contains("iphone") || hostname.Contains("phone"))
                return "📱 iPhone";
            if (hostname.Contains("ipad") || hostname.Contains("pad"))
                return "📱 iPad";
            if (hostname.Contains("macbook") || hostname.Contains("imac") || hostname.Contains("mac"))
                return "💻 Mac компьютер";
            if (hostname.Contains("appletv") || hostname.Contains("apple-tv"))
                return "📺 Apple TV";
            if (hostname.Contains("watch"))
                return "⌚ Apple Watch";
            if (hostname.Contains("airpods") || hostname.Contains("beats"))
                return "🎧 Apple аудио";
            if (hostname.Contains("galaxy") && (hostname.Contains("tab") || hostname.Contains("note")))
                return "📱 Samsung планшет";
            if (hostname.Contains("galaxy") || hostname.Contains("sm-") || hostname.Contains("phone"))
                return "📱 Samsung телефон";
            if (hostname.Contains("switch"))
                return "🎮 Nintendo Switch";
            if (hostname.Contains("playstation") || hostname.Contains("ps"))
                return "🎮 PlayStation";
            if (hostname.Contains("xbox"))
                return "🎮 Xbox";
            if (hostname.Contains("surface"))
                return "💻 Surface планшет";
            if (hostname.Contains("router") || hostname.Contains("gateway") || hostname.Contains("openwrt"))
                return "🌐 Роутер";
            if (hostname.Contains("printer") || hostname.Contains("canon") || hostname.Contains("epson") || hostname.Contains("hp-"))
                return "🖨️ Принтер";
            if (hostname.Contains("camera") || hostname.Contains("cam") || hostname.Contains("nvr"))
                return "📹 IP камера";
            if (hostname.Contains("tv") || hostname.Contains("smart") || hostname.Contains("roku") || hostname.Contains("chromecast"))
                return "📺 Smart TV";
            if (hostname.Contains("android") || hostname.Contains("mobile"))
                return "📱 Android телефон";
            if (hostname.Contains("tablet") || hostname.Contains("tab-"))
                return "📱 Планшет";

            // Теперь проверяем по вендору из MAC базы данных
            if (!string.IsNullOrEmpty(vendor) && vendor != "неизвестно")
            {
                // Apple устройства
                if (vendor.Contains("apple"))
                    return "📱 Apple устройство";

                // Сетевое оборудование
                if (vendor.Contains("cisco") || vendor.Contains("tp-link") || vendor.Contains("d-link") ||
                    vendor.Contains("netgear") || vendor.Contains("asus") || vendor.Contains("router"))
                    return "🌐 Сетевое оборудование";

                // Принтеры
                if (vendor.Contains("hewlett") || vendor.Contains("canon") || vendor.Contains("epson") ||
                    vendor.Contains("brother") || vendor.Contains("xerox"))
                    return "🖨️ Принтер";

                // Мобильные устройства
                if (vendor.Contains("samsung") || vendor.Contains("xiaomi") || vendor.Contains("huawei") ||
                    vendor.Contains("oppo") || vendor.Contains("vivo") || vendor.Contains("realme"))
                    return "📱 Мобильное устройство";

                // Компьютеры
                if (vendor.Contains("dell") || vendor.Contains("lenovo") || vendor.Contains("acer") ||
                    vendor.Contains("intel") || vendor.Contains("microsoft"))
                    return "💻 Компьютер";

                // Smart TV
                if (vendor.Contains("lg electronics") || vendor.Contains("sony") || vendor.Contains("panasonic"))
                    return "📺 Smart устройство";

                // Игровые консоли
                if (vendor.Contains("nintendo") || vendor.Contains("playstation") || vendor.Contains("xbox"))
                    return "🎮 Игровая консоль";

                // Камеры
                if (vendor.Contains("hikvision") || vendor.Contains("dahua") || vendor.Contains("axis"))
                    return "📹 IP камера";

                // Если вендор известен, но тип не определен
                return $"🔧 {vendor}";
            }

            // Если ничего не найдено
            return "❓ Неизвестное устройство";
        }

        private string DetectOperatingSystem(NetworkDevice device)
        {
            var hostname = device.Hostname?.ToLower() ?? "";

            // Определяем ОС только по hostname (убираем захардкоженные правила для производителей)
            if (hostname.Contains("iphone")) return "iOS (iPhone)";
            if (hostname.Contains("ipad")) return "iPadOS";
            if (hostname.Contains("mac") || hostname.Contains("macbook") || hostname.Contains("imac")) return "macOS";
            if (hostname.Contains("apple-tv") || hostname.Contains("appletv")) return "tvOS";
            if (hostname.Contains("watch")) return "watchOS";
            if (hostname.Contains("android")) return "Android";
            if (hostname.Contains("linux") || hostname.Contains("ubuntu") || hostname.Contains("debian")) return "Linux";
            if (hostname.Contains("windows") || hostname.Contains("desktop") || hostname.Contains("pc")) return "Windows";

            // Определяем по портам
            var ports = device.OpenPorts ?? new List<int>();
            if (ports.Contains(3389)) // RDP
                return "Windows";
            if (ports.Contains(22) && !ports.Contains(80)) // SSH без web
                return "Linux/Unix";
            if (ports.Contains(5353)) // Bonjour
                return "macOS/iOS";

            return "Неизвестно";
        }

        private List<int> ScanCommonPorts(string ipAddress)
        {
            var openPorts = new List<int>();
            var commonPorts = new[] { 21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3389, 5900, 8080 };

            foreach (var port in commonPorts)
            {
                try
                {
                    using (var tcpClient = new System.Net.Sockets.TcpClient())
                    {
                        var result = tcpClient.BeginConnect(ipAddress, port, null, null);
                        var success = result.AsyncWaitHandle.WaitOne(TimeSpan.FromMilliseconds(100));

                        if (success && tcpClient.Connected)
                        {
                            openPorts.Add(port);
                        }

                        tcpClient.Close();
                    }
                }
                catch
                {
                    // Игнорируем ошибки подключения
                }
            }

            return openPorts;
        }

        private string GenerateDeviceDescription(NetworkDevice device)
        {
            var parts = new List<string>();

            if (!string.IsNullOrEmpty(device.DeviceType))
                parts.Add(device.DeviceType);

            if (!string.IsNullOrEmpty(device.OperatingSystem) && device.OperatingSystem != "Неизвестно")
                parts.Add($"ОС: {device.OperatingSystem}");

            if (device.OpenPorts.Any())
                parts.Add($"Порты: {string.Join(", ", device.OpenPorts)}");

            return string.Join(" | ", parts);
        }

        /// <summary>
        /// Выводит отладочную информацию о текущем состоянии
        /// </summary>
        public void DebugCurrentState()
        {
            WriteLog("\n=== ОТЛАДКА СОСТОЯНИЯ СЕТЕВОГО МОНИТОРА ===", LogLevel.Info);

            lock (_lockObject)
            {
                WriteLog($"Всего известных устройств: {_knownDevices.Count}", LogLevel.Info);

                var devicesByStatus = _knownDevices.Values.ToList()
                    .GroupBy(d => d.Status)
                    .Select(g => $"{g.Key}: {g.Count()}")
                    .ToList();

                WriteLog("Устройства по статусу:", LogLevel.Info);
                foreach (var status in devicesByStatus)
                {
                    WriteLog($"  {status}", LogLevel.Info);
                }

                WriteLog("\nСписок всех устройств:", LogLevel.Info);
                foreach (var device in _knownDevices.Values.ToList().OrderBy(d => d.IPAddress))
                {
                    WriteLog($"  IP: {device.IPAddress,-15} MAC: {device.MACAddress,-17} Hostname: {device.Hostname,-30} Status: {device.Status}",
                            device.Status == "Активен" ? LogLevel.Success : LogLevel.Warning);
                }
            }

            // Проверяем текущую ARP таблицу
            WriteLog("\n=== ТЕКУЩАЯ ARP ТАБЛИЦА ===", LogLevel.Info);
            try
            {
                var process = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = "arp",
                        Arguments = "-a",
                        UseShellExecute = false,
                        RedirectStandardOutput = true,
                        CreateNoWindow = true
                    }
                };

                process.Start();
                var output = process.StandardOutput.ReadToEnd();
                process.WaitForExit();

                var lines = output.Split('\n');
                var arpCount = 0;

                foreach (var line in lines)
                {
                    if (Regex.IsMatch(line.Trim(), @"\d+\.\d+\.\d+\.\d+\s+[0-9a-fA-F-]{17}"))
                    {
                        arpCount++;
                    }
                }

                WriteLog($"Записей в ARP таблице: {arpCount}", LogLevel.Info);
            }
            catch (Exception ex)
            {
                WriteLog($"Ошибка чтения ARP: {ex.Message}", LogLevel.Error);
            }

            WriteLog("=== КОНЕЦ ОТЛАДКИ ===\n", LogLevel.Info);
        }

        /// <summary>
        /// Диагностика базы данных MAC адресов
        /// </summary>
        public void DiagnoseMacDatabase()
        {
            WriteLog("\n=== ДИАГНОСТИКА БАЗЫ ДАННЫХ MAC ===", LogLevel.Info);
            WriteLog($"Путь к файлу: {Path.GetFullPath(_macDatabasePath)}", LogLevel.Info);
            WriteLog($"Файл существует: {File.Exists(_macDatabasePath)}", LogLevel.Info);
            WriteLog($"Текущая директория: {Directory.GetCurrentDirectory()}", LogLevel.Info);

            // Ищем MAC.db в разных местах
            var possiblePaths = new[]
            {
                _macDatabasePath,
                Path.Combine(Directory.GetCurrentDirectory(), "MAC.db"),
                Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "MAC.db"),
                Path.Combine(Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location) ?? AppDomain.CurrentDomain.BaseDirectory, "MAC.db"),
                Path.Combine(Environment.CurrentDirectory, "MAC.db")
            };

            WriteLog("\nПоиск файла MAC.db в возможных местах:", LogLevel.Info);
            string? foundPath = null;
            foreach (var path in possiblePaths)
            {
                var exists = File.Exists(path);
                WriteLog($"  {path} -> {(exists ? "НАЙДЕН" : "не найден")}", exists ? LogLevel.Success : LogLevel.Debug);
                if (exists && foundPath == null)
                {
                    foundPath = path;
                    var info = new FileInfo(path);
                    WriteLog($"    Размер: {info.Length} байт, Дата: {info.LastWriteTime}", LogLevel.Info);
                }
            }

            if (foundPath != null && File.Exists(foundPath))
            {
                var lines = File.ReadAllLines(foundPath);
                WriteLog($"\nВсего строк в файле: {lines.Length}", LogLevel.Info);

                // Анализируем первые строки
                WriteLog("\nАнализ первых 10 строк:", LogLevel.Info);
                for (int i = 0; i < Math.Min(10, lines.Length); i++)
                {
                    var line = lines[i];
                    if (string.IsNullOrWhiteSpace(line)) continue;

                    WriteLog($"\nСтрока {i + 1}: '{line}'", LogLevel.Debug);
                    WriteLog($"  Длина: {line.Length} символов", LogLevel.Debug);

                    // Проверяем наличие табуляции
                    if (line.Contains('\t'))
                    {
                        var parts = line.Split('\t');
                        WriteLog($"  ✓ Найдена табуляция, частей: {parts.Length}", LogLevel.Success);
                        if (parts.Length >= 2)
                        {
                            WriteLog($"  MAC префикс: '{parts[0]}' (длина: {parts[0].Length})", LogLevel.Info);
                            WriteLog($"  Вендор: '{parts[1]}'", LogLevel.Info);
                        }
                    }
                    else
                    {
                        WriteLog($"  ✗ НЕТ ТАБУЛЯЦИИ!", LogLevel.Warning);
                    }
                }
            }

            lock (_lockObject)
            {
                WriteLog($"\n=== СТАТУС БАЗЫ ДАННЫХ В ПАМЯТИ ===", LogLevel.Info);
                WriteLog($"Записей загружено: {_vendorDatabase.Count}", LogLevel.Success);

                if (_vendorDatabase.Count > 0)
                {
                    WriteLog("\nПервые 20 записей из памяти:", LogLevel.Info);
                    foreach (var kvp in _vendorDatabase.Take(20))
                    {
                        WriteLog($"  {kvp.Key} -> {kvp.Value}", LogLevel.Debug);
                    }

                    // Проверяем конкретные префиксы из твоего файла
                    var testPrefixes = new[] { "FC253F", "FC019E", "FC01CD", "FC10BD", "FC1186" };
                    WriteLog("\nПроверка префиксов из примера:", LogLevel.Info);
                    foreach (var prefix in testPrefixes)
                    {
                        if (_vendorDatabase.ContainsKey(prefix))
                        {
                            WriteLog($"  ✓ {prefix} -> {_vendorDatabase[prefix]}", LogLevel.Success);
                        }
                        else
                        {
                            WriteLog($"  ✗ {prefix} -> НЕ НАЙДЕН", LogLevel.Warning);
                        }
                    }
                }
                else
                {
                    WriteLog("⚠️ БАЗА ДАННЫХ ПУСТА!", LogLevel.Error);
                }
            }

            // Тестируем MAC адреса
            var testMacs = new[]
            {
                "FC:25:3F:12:34:56",
                "FC:01:9E:12:34:56",
                "FC:01:CD:12:34:56",
                "F4-BD-7C-12-34-56",
                "fc253f123456"
            };

            WriteLog("\n=== ТЕСТИРОВАНИЕ ОПРЕДЕЛЕНИЯ ВЕНДОРОВ ===", LogLevel.Info);
            foreach (var mac in testMacs)
            {
                var vendor = GetVendorFromMAC(mac);
                WriteLog($"\nРезультат для {mac}: {vendor}", vendor != "Неизвестно" ? LogLevel.Success : LogLevel.Warning);
            }

            WriteLog("\n=== КОНЕЦ ДИАГНОСТИКИ ===\n", LogLevel.Info);
        }

        public bool IsRunning => _isRunning;

        private IPAddress? GetSubnetMaskFor(IPAddress? localIp)
        {
            try
            {
                if (localIp == null) return null;
                foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (ni.OperationalStatus != OperationalStatus.Up || ni.NetworkInterfaceType == NetworkInterfaceType.Loopback)
                        continue;
                    var ipProps = ni.GetIPProperties();
                    foreach (var ua in ipProps.UnicastAddresses)
                    {
                        if (ua.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork && ua.Address.Equals(localIp))
                        {
                            return ua.IPv4Mask;
                        }
                    }
                }
            }
            catch { }
            return null;
        }

        private void DiscoverLocalSubnets()
        {
            _localSubnets.Clear();
            try
            {
                foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (ni.OperationalStatus != OperationalStatus.Up || ni.NetworkInterfaceType == NetworkInterfaceType.Loopback)
                        continue;
                    var ipProps = ni.GetIPProperties();
                    foreach (var ua in ipProps.UnicastAddresses)
                    {
                        if (ua.Address.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork) continue;
                        var ip = ua.Address;
                        var mask = ua.IPv4Mask;
                        var ipStr = ip.ToString();
                        // Поддерживаем только частные диапазоны (10.*, 172.16-31.*, 192.168.*)
                        if (!(ipStr.StartsWith("10.") || ipStr.StartsWith("192.168.") || (ipStr.StartsWith("172.") && IsInRange172(ipStr))))
                            continue;
                        var prefix = GetNetworkPrefix(ipStr);
                        _localSubnets.Add((ip, mask, prefix));
                        // Сохраняем первый как "основной"
                        if (_localIPv4Address == null)
                        {
                            _localIPv4Address = ip;
                            _localSubnetMask = mask;
                        }
                    }
                }
            }
            catch { }
        }

        private bool IsInLocalSubnet(string ipString)
        {
            try
            {
                if (IPAddress.TryParse(ipString, out var ip))
                {
                    var ipBytes = ip.GetAddressBytes();
                    foreach (var (localIp, mask, prefix) in _localSubnets)
                    {
                        if (mask == null) continue;
                        var maskBytes = mask.GetAddressBytes();
                        var localBytes = localIp.GetAddressBytes();
                        bool same = true;
                        for (int i = 0; i < 4; i++)
                        {
                            if ((ipBytes[i] & maskBytes[i]) != (localBytes[i] & maskBytes[i])) { same = false; break; }
                        }
                        if (same) return true;
                    }
                }
            }
            catch { }
            // Fallback: сравниваем по любому /24 префиксу локальных IP
            foreach (var (_, _, prefix) in _localSubnets)
            {
                if (!string.IsNullOrEmpty(prefix) && ipString.StartsWith(prefix + ".")) return true;
            }
            return false;
        }

        private bool IsMulticastOrBroadcast(string ipString)
        {
            try
            {
                if (ipString == "255.255.255.255") return true;
                var dot = ipString.IndexOf('.');
                if (dot > 0)
                {
                    var firstOctetStr = ipString.Substring(0, dot);
                    if (int.TryParse(firstOctetStr, out var firstOctet))
                    {
                        if (firstOctet >= 224 && firstOctet <= 239) return true; // Multicast 224.0.0.0/4
                    }
                }
            }
            catch { }
            return false;
        }

        private bool IsSpecialOrNonLocal(string ipString)
        {
            // Фильтруем 0.0.0.0, 169.254.0.0/16 и явно внешние не из нашей подсети
            if (string.IsNullOrEmpty(ipString)) return true;
            if (ipString == "0.0.0.0") return true;
            if (ipString.StartsWith("169.254.")) return true;
            // Мультикаст/бродкаст оставляем (включаем в локальные)
            if (IsMulticastOrBroadcast(ipString)) return false;
            // Если не в одной из наших подсетей — считаем не локальным
            if (!IsInLocalSubnet(ipString)) return true;
            return false;
        }
    }
}