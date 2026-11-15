// Copyright (c) 2026 LanDen Labs - Dennis Lang

using System;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace B4Browse
{
    /// <summary>
    /// Persistent on-disk log + last-chance crash handlers. <see cref="ErrorLog"/> is in-memory
    /// only, so a crash used to take the evidence down with the process; this writes it to
    /// <c>%LOCALAPPDATA%\B4Browse\logs\b4browse.log</c> (rotated to <c>b4browse.1.log</c> past
    /// <see cref="MaxBytes"/>).
    ///
    /// <see cref="Install"/> hooks:
    /// <list type="bullet">
    /// <item>UI-thread exceptions (<c>Application.ThreadException</c>) - logged with full stack,
    ///   the user is told where the log is and may keep running or quit.</item>
    /// <item>Non-UI-thread exceptions (<c>AppDomain.UnhandledException</c>) - logged; the
    ///   runtime terminates the process afterwards (that can't be prevented).</item>
    /// <item>Unobserved faulted tasks (<c>TaskScheduler.UnobservedTaskException</c>) - logged and
    ///   marked observed (these were previously silent, e.g. a fire-and-forget <c>RunAsync</c>).</item>
    /// </list>
    /// Every method is no-throw: logging must never become the crash.
    /// </summary>
    public static class CrashLog
    {
        private const long MaxBytes = 1024 * 1024;
        private static readonly object _gate = new();
        private static int _inDialog;   // re-entrancy guard for the crash dialog

        /// <summary>Folder holding the log files.</summary>
        public static string LogDir { get; } = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "B4Browse", "logs");

        /// <summary>The current log file.</summary>
        public static string LogPath { get; } = Path.Combine(LogDir, "b4browse.log");

        /// <summary>Installs the global exception handlers. Call first thing in <c>Main</c>, before
        /// any window is created (<c>SetUnhandledExceptionMode</c> must precede the first control).</summary>
        public static void Install(bool gui)
        {
            try
            {
                AppDomain.CurrentDomain.UnhandledException += (_, e) =>
                    Write("FATAL (non-UI thread" + (e.IsTerminating ? ", terminating" : "") + ")",
                          e.ExceptionObject as Exception, e.ExceptionObject?.ToString());

                TaskScheduler.UnobservedTaskException += (_, e) =>
                {
                    Write("Unobserved task exception", e.Exception);
                    ErrorLog.Add(ErrorCategory.Error, "Unobserved task: " + Inner(e.Exception).Message,
                        e.Exception.ToString(), "TaskScheduler");
                    e.SetObserved();
                };

                if (gui)
                {
                    Application.SetUnhandledExceptionMode(UnhandledExceptionMode.CatchException);
                    Application.ThreadException += (_, e) => OnUiException(e.Exception);
                }

                Info($"Started {AppInfo.Product} {AppInfo.Version} ({(gui ? "GUI" : "headless")})");
            }
            catch { /* never block startup */ }
        }

        /// <summary>Logs an exception caught somewhere in the app (e.g. a view that failed to build)
        /// and mirrors it into <see cref="ErrorLog"/> so the status-bar badge shows it.</summary>
        public static void Report(string context, Exception ex,
            [System.Runtime.CompilerServices.CallerMemberName] string source = "")
        {
            Write(context, ex);
            ErrorLog.Add(ErrorCategory.Error, $"{context}: {ex.Message}", ex.ToString(), source);
        }

        /// <summary>Writes a one-line informational entry.</summary>
        public static void Info(string message) => Append($"{Stamp()} INFO  {message}{Environment.NewLine}");

        /// <summary>Writes an exception entry with environment details and the full stack trace.</summary>
        public static void Write(string context, Exception? ex, string? fallback = null)
        {
            var sb = new StringBuilder();
            sb.Append(Stamp()).Append(" ERROR ").AppendLine(context);
            sb.AppendLine($"  App:     {AppInfo.Product} {AppInfo.Version}  (built {AppInfo.BuildDate})");
            sb.AppendLine($"  OS:      {Environment.OSVersion}  {(Environment.Is64BitProcess ? "x64" : "x86")}");
            sb.AppendLine($"  Runtime: {Environment.Version}   Admin: {SafeIsAdmin()}   Thread: {Thread.CurrentThread.ManagedThreadId}");
            sb.AppendLine("  " + (ex?.ToString() ?? fallback ?? "(no exception object)").Replace("\n", "\n  "));
            sb.AppendLine();
            Append(sb.ToString());
        }

        /// <summary>Records a line in the on-disk log (called by <see cref="ErrorLog.Add"/>).</summary>
        internal static void Mirror(ErrorEntry e)
        {
            var line = $"{Stamp()} WARN  [{e.Category}] {e.Source}: {e.Message}{Environment.NewLine}";
            if (!string.IsNullOrWhiteSpace(e.Detail))
                line += "  " + e.Detail.Trim().Replace("\n", "\n  ") + Environment.NewLine;
            Append(line);
        }

        /// <summary>Opens the log folder in Explorer.</summary>
        public static void OpenLogFolder()
        {
            try
            {
                Directory.CreateDirectory(LogDir);
                Process.Start(new ProcessStartInfo("explorer.exe", $"\"{LogDir}\"") { UseShellExecute = true });
            }
            catch { }
        }

        // ------------------------------------------------------------------ //

        private static void OnUiException(Exception ex)
        {
            Write("Unhandled UI-thread exception", ex);
            ErrorLog.Add(ErrorCategory.Error, "Unhandled: " + ex.Message, ex.ToString(), ex.TargetSite?.Name ?? "UI");

            // A second exception while the dialog is up (e.g. a repaint that keeps throwing) is
            // logged above but doesn't stack another dialog.
            if (Interlocked.Exchange(ref _inDialog, 1) == 1) return;
            try
            {
                // Plain MessageBox, not the themed one: the themed UI may be what is broken.
                var r = MessageBox.Show(
                    $"B4-Browse hit an unexpected error:\n\n{ex.GetType().Name}: {ex.Message}\n\n" +
                    $"Details were written to:\n{LogPath}\n\n" +
                    "Keep running?  (Yes = continue, No = quit)",
                    "B4-Browse - unexpected error", MessageBoxButtons.YesNo, MessageBoxIcon.Error);
                if (r == DialogResult.No) Application.Exit();
            }
            catch { }
            finally { Volatile.Write(ref _inDialog, 0); }
        }

        private static void Append(string text)
        {
            try
            {
                lock (_gate)
                {
                    Directory.CreateDirectory(LogDir);
                    var fi = new FileInfo(LogPath);
                    if (fi.Exists && fi.Length > MaxBytes)
                    {
                        string old = Path.Combine(LogDir, "b4browse.1.log");
                        File.Delete(old);
                        File.Move(LogPath, old);
                    }
                    File.AppendAllText(LogPath, text, Encoding.UTF8);
                }
            }
            catch { /* disk full / locked - nothing more we can do */ }
        }

        private static string Stamp() => DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss.fff");

        private static string SafeIsAdmin()
        {
            try { return Elevation.IsAdmin ? "yes" : "no"; } catch { return "?"; }
        }

        private static Exception Inner(AggregateException ae) =>
            ae.InnerExceptions.Count == 1 ? ae.InnerExceptions[0] : ae;
    }
}
