using System;
using System.IO;
using System.Windows;
using System.Windows.Input;

namespace NetworkMonitorWPF
{
    public partial class MainWindow : Window
    {
        private static string LogFile = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            "NetworkMonitorWPF_Crash.log");

        public MainWindow()
        {
            try
            {
                LogToFile("=== MainWindow CONSTRUCTOR START ===");

                LogToFile("Calling InitializeComponent...");
                InitializeComponent();

                LogToFile("InitializeComponent completed");
                LogToFile("=== MainWindow CONSTRUCTOR END ===");
            }
            catch (Exception ex)
            {
                var error = $"MAINWINDOW CONSTRUCTOR FAILED:\n{ex.GetType().Name}\n{ex.Message}\n{ex.StackTrace}\n{ex.InnerException?.Message}";
                LogToFile(error);
                MessageBox.Show(error, "Ошибка создания окна", MessageBoxButton.OK, MessageBoxImage.Error);
                throw;
            }
        }

        private void Border_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
        {
            if (e.ChangedButton == MouseButton.Left)
            {
                this.DragMove();
            }
        }

        private void MinimizeButton_Click(object sender, RoutedEventArgs e)
        {
            WindowState = WindowState.Minimized;
        }

        private void MaximizeButton_Click(object sender, RoutedEventArgs e)
        {
            WindowState = WindowState == WindowState.Maximized
                ? WindowState.Normal
                : WindowState.Maximized;
        }

        private void CloseButton_Click(object sender, RoutedEventArgs e)
        {
            Application.Current.Shutdown();
        }

        private static void LogToFile(string message)
        {
            try
            {
                var logMessage = $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss.fff}] {message}";
                File.AppendAllText(LogFile, logMessage + Environment.NewLine);
            }
            catch
            {
                // Ignore logging errors
            }
        }
    }
}
