using System;
using System.IO;
using System.Windows;

namespace NetworkMonitorWPF
{
    public partial class App : Application
    {
        private static string LogFile = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            "NetworkMonitorWPF_Crash.log");

        protected override void OnStartup(StartupEventArgs e)
        {
            try
            {
                LogToFile("=== APPLICATION STARTING ===");
                LogToFile($"Current Directory: {Directory.GetCurrentDirectory()}");
                LogToFile($"Base Directory: {AppDomain.CurrentDomain.BaseDirectory}");

                base.OnStartup(e);

                LogToFile("Base OnStartup completed");

                // Настройка обработки необработанных исключений
                DispatcherUnhandledException += (s, args) =>
                {
                    var error = $"DISPATCHER EXCEPTION:\n{args.Exception.GetType().Name}\n{args.Exception.Message}\n{args.Exception.StackTrace}";
                    LogToFile(error);
                    MessageBox.Show(error, "Ошибка", MessageBoxButton.OK, MessageBoxImage.Error);
                    args.Handled = true;
                };

                AppDomain.CurrentDomain.UnhandledException += (s, args) =>
                {
                    var ex = args.ExceptionObject as Exception;
                    var error = $"UNHANDLED EXCEPTION:\n{ex?.GetType().Name}\n{ex?.Message}\n{ex?.StackTrace}";
                    LogToFile(error);
                    MessageBox.Show(error, "Критическая ошибка", MessageBoxButton.OK, MessageBoxImage.Error);
                };

                LogToFile("Exception handlers registered");
                LogToFile("=== STARTUP COMPLETE ===");
            }
            catch (Exception ex)
            {
                var error = $"STARTUP FAILED:\n{ex.GetType().Name}\n{ex.Message}\n{ex.StackTrace}";
                LogToFile(error);
                MessageBox.Show(error, "Ошибка запуска", MessageBoxButton.OK, MessageBoxImage.Error);
                Shutdown(1);
            }
        }

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
    }
}
