// Copyright (c) 2026 LanDen Labs - Dennis Lang

using System;
using System.IO;
using System.Linq;
using System.Windows.Forms;

namespace BrowseSafe
{
    /// <summary>
    /// Browse Safe - confirms the machine is in a safe state before browsing.
    ///
    /// GUI:        BrowseSafe.exe
    /// Headless:   BrowseSafe.exe --run &lt;scope&gt; [--out &lt;file&gt;]
    ///               scope = scan | chrome | services | processes | startup |
    ///                       installed | devices | all
    ///             BrowseSafe.exe --report        (alias for --run scan)
    ///
    /// Author: Dennis Lang - LanDen Labs - 2026
    /// </summary>
    static class Program
    {
        [STAThread]
        static void Main()
        {
            var args = Environment.GetCommandLineArgs();

            int run = Array.FindIndex(args, a => a.Equals("--run", StringComparison.OrdinalIgnoreCase));
            if (run >= 0)
            {
                string scope = (run + 1 < args.Length && !args[run + 1].StartsWith("--")) ? args[run + 1] : "all";
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

        static string? OutPath(string[] args)
        {
            int i = Array.FindIndex(args, a => a.Equals("--out", StringComparison.OrdinalIgnoreCase));
            return (i >= 0 && i + 1 < args.Length) ? args[i + 1] : null;
        }

        static void RunHeadless(string scope, string? outPath)
        {
            if (!Reports.IsValidScope(scope))
            {
                Console.WriteLine($"Unknown scope '{scope}'. Valid scopes: {string.Join(", ", Reports.Scopes)}");
                return;
            }

            var (text, _) = Reports.Build(scope);
            Console.WriteLine(text);

            if (outPath != null)
            {
                try { File.WriteAllText(outPath, text); Console.WriteLine($"(written to {outPath})"); }
                catch (Exception ex) { Console.WriteLine($"(could not write {outPath}: {ex.Message})"); }
            }
        }
    }
}
