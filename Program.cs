// Copyright (c) 2026 LanDen Labs - Dennis Lang

using System;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Windows.Forms;

namespace BrowseSafe
{
    /// <summary>
    /// Browse Safe - confirms the machine is in a safe state before browsing.
    ///
    /// GUI:        BrowseSafe.exe
    /// Headless:   BrowseSafe.exe --run &lt;scope&gt; [--out &lt;file&gt;]
    ///               scope = scan | chrome | services | processes | startup |
    ///                       installed | devices | events | all
    ///             BrowseSafe.exe --report        (alias for --run scan)
    ///             BrowseSafe.exe --inventory     (alias for --run all)
    ///             BrowseSafe.exe --help          (show usage and exit)
    ///
    /// Author: Dennis Lang - LanDen Labs - 2026
    /// </summary>
    static class Program
    {
        [STAThread]
        static void Main()
        {
            var args = Environment.GetCommandLineArgs();

            if (args.Any(a => a is "--help" or "-h" or "/?" or "-?" or "/help"))
            {
                PrintHelp();
                return;
            }

            int run = Array.FindIndex(args, a => a.Equals("--run", StringComparison.OrdinalIgnoreCase));
            if (run >= 0)
            {
                string scope = (run + 1 < args.Length && !args[run + 1].StartsWith("-")) ? args[run + 1] : "all";
                RunHeadless(scope, OutPath(args));
                return;
            }
            if (args.Any(a => a.Equals("--report", StringComparison.OrdinalIgnoreCase)))
            {
                RunHeadless("scan", OutPath(args));
                return;
            }
            if (args.Any(a => a.Equals("--inventory", StringComparison.OrdinalIgnoreCase)))
            {
                RunHeadless("all", OutPath(args));
                return;
            }

            ApplicationConfiguration.Initialize();
            Theme.Load();
            Theme.Apply(Theme.Current); // apply saved light/dark mode before any window is shown
            Application.Run(new MainForm());
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool AttachConsole(int dwProcessId);
        private const int ATTACH_PARENT_PROCESS = -1;

        /// <summary>
        /// BrowseSafe is a GUI-subsystem (WinExe) app, so it is not attached to the
        /// console that launched it and Console output is otherwise discarded. Attach to
        /// the parent console (if any) and rebind stdout/stderr so the headless and
        /// --help text appears in the terminal. A no-op when launched without a console
        /// (e.g. from Explorer).
        /// </summary>
        private static void EnsureConsole()
        {
            try
            {
                if (!AttachConsole(ATTACH_PARENT_PROCESS)) return;
                var stdout = new StreamWriter(Console.OpenStandardOutput()) { AutoFlush = true };
                Console.SetOut(stdout);
                var stderr = new StreamWriter(Console.OpenStandardError()) { AutoFlush = true };
                Console.SetError(stderr);
            }
            catch { /* no parent console to attach to */ }
        }

        static void PrintHelp()
        {
            EnsureConsole();

            // Per-tab scopes come from the report catalog so this stays in sync; "all" is
            // appended by Reports.Scopes and runs every scope.
            string scopes = string.Join(", ", Reports.Scopes);

            Console.WriteLine($@"{AppInfo.Product} {AppInfo.Version} - Chrome safety & system-posture checker
{AppInfo.Copyright}

USAGE:
  BrowseSafe.exe                 Launch the GUI (default; no arguments).
  BrowseSafe.exe --run <scope>   Run checks headless and print a text report.
  BrowseSafe.exe --report        Alias for: --run scan
  BrowseSafe.exe --inventory     Alias for: --run all
  BrowseSafe.exe --help          Show this help and exit.

OPTIONS:
  --run <scope>     Which checks to run. Defaults to 'all' if <scope> is omitted.
  --out <file>      Also write the report text to <file> (headless modes only).
  --help, -h, /?    Show this help and exit.

SCOPES:
  {scopes}

EXAMPLES:
  BrowseSafe.exe --run scan
  BrowseSafe.exe --run events --out events.txt
  BrowseSafe.exe --report");
        }

        static string? OutPath(string[] args)
        {
            // Accept --out, and the -out / -o short forms (the single-dash forms are easy
            // to type by mistake; treat them as the same flag rather than silently ignoring).
            int i = Array.FindIndex(args, a =>
                a.Equals("--out", StringComparison.OrdinalIgnoreCase) ||
                a.Equals("-out", StringComparison.OrdinalIgnoreCase) ||
                a.Equals("-o", StringComparison.OrdinalIgnoreCase));
            return (i >= 0 && i + 1 < args.Length) ? args[i + 1] : null;
        }

        static void RunHeadless(string scope, string? outPath)
        {
            EnsureConsole();

            if (!Reports.IsValidScope(scope))
            {
                Console.Error.WriteLine($"Unknown scope '{scope}'. Valid scopes: {string.Join(", ", Reports.Scopes)}");
                return;
            }

            try
            {
                // Progress goes to stderr (one line as each section starts and finishes) so
                // stdout stays a clean report - e.g. "SCAN (1 of 11) - started".
                var (text, _) = Reports.Build(scope, (n, total, label, done) =>
                    Console.Error.WriteLine($"{label} ({n} of {total}) - {(done ? "done" : "started")}"));

                Console.WriteLine(text);
                if (outPath != null) WriteOut(outPath, text);

                // Background-action failures (timeouts / stderr / bad output) are collected out of
                // band so the report stays clean; surface them on stderr so they aren't lost.
                FlushErrorLog();
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("Report failed: " + ex.Message);
            }
        }

        /// <summary>Writes any recorded background-action errors to stderr (keeping stdout the clean report).</summary>
        static void FlushErrorLog()
        {
            var errors = ErrorLog.Snapshot();
            if (errors.Count == 0) return;

            Console.Error.WriteLine();
            Console.Error.WriteLine($"--- {errors.Count} background error(s) ---");
            foreach (var e in errors)
            {
                Console.Error.WriteLine($"[{e.Category}] {e.Source}: {e.Message}");
                if (!string.IsNullOrWhiteSpace(e.Detail))
                    Console.Error.WriteLine("    " + e.Detail.Replace("\n", "\n    "));
            }
        }

        static void WriteOut(string outPath, string text)
        {
            try
            {
                File.WriteAllText(outPath, text);
                Console.Error.WriteLine($"(written to {Path.GetFullPath(outPath)})");
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"(could not write {outPath}: {ex.Message})");
            }
        }
    }
}
