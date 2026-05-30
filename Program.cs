using System;
using System.IO;
using System.Linq;
using System.Text;
using System.Windows.Forms;

namespace BrowseSafe
{
    /// <summary>
    /// Browse Safe - a small diagnostic that confirms the machine is in a safe
    /// state before launching the Chrome browser.
    ///
    /// Checks performed:
    ///   1. Current DNS server IP address(es) in use.
    ///   2. Live DNS lookups of well-known public sites, confirming the
    ///      resolved addresses are public (not hijacked to private/loopback).
    ///   3. No HTTP/HTTPS proxy (manual, PAC, or environment) is configured.
    ///   4. Windows security features are enabled (Defender, Firewall,
    ///      SmartScreen, UAC, Secure Boot ...).
    ///
    /// Author: Dennis Lang - LanDen Labs - 2026
    /// </summary>
    static class Program
    {
        [STAThread]
        static void Main()
        {
            var args = Environment.GetCommandLineArgs();
            int i = Array.FindIndex(args, a => a.Equals("--report", StringComparison.OrdinalIgnoreCase));
            if (i >= 0)
            {
                string path = (i + 1 < args.Length && !args[i + 1].StartsWith("--"))
                    ? args[i + 1]
                    : Path.Combine(Path.GetTempPath(), "browse-safe-report.txt");
                WriteReport(path);
                return;
            }
            if (args.Any(a => a.Equals("--inventory", StringComparison.OrdinalIgnoreCase)))
            {
                DumpGroups("Inventory checks", new[]
                {
                    SafetyChecks.CheckChromeExe(),
                    SafetyChecks.CheckChromeExtensions(),
                    SafetyChecks.CheckServices(),
                    SafetyChecks.CheckProcesses(),
                    SafetyChecks.CheckStartup(),
                    SafetyChecks.CheckInstalled(),
                    SafetyChecks.CheckDevices(),
                });
                return;
            }

            ApplicationConfiguration.Initialize();
            Application.Run(new MainForm());
        }

        /// <summary>Headless mode: run every check and write a plain-text report.</summary>
        static void WriteReport(string path)
        {
            var sb = new StringBuilder();
            sb.AppendLine($"Browse Safe report  -  {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
            sb.AppendLine(new string('=', 64));

            CheckStatus overall = CheckStatus.Pass;
            foreach (var g in SafetyChecks.RunAll())
            {
                sb.AppendLine();
                sb.AppendLine(g.Title);
                sb.AppendLine(new string('-', 64));
                foreach (var r in g.Results)
                {
                    if (r.Table)
                    {
                        sb.AppendLine("  " + r.Name);
                        continue;
                    }
                    string tag = r.Status switch
                    {
                        CheckStatus.Pass => "[PASS]",
                        CheckStatus.Warn => "[WARN]",
                        CheckStatus.Fail => "[FAIL]",
                        _ => "[INFO]",
                    };
                    sb.AppendLine($"  {tag} {r.Name}" +
                        (string.IsNullOrEmpty(r.Detail) ? "" : $"  -  {r.Detail}"));
                }
                if (CheckGroup.Rank(g.Worst()) > CheckGroup.Rank(overall)) overall = g.Worst();
            }

            sb.AppendLine();
            sb.AppendLine(new string('=', 64));
            sb.AppendLine("VERDICT: " + overall switch
            {
                CheckStatus.Fail => "NOT SAFE - resolve the FAIL items before browsing.",
                CheckStatus.Warn => "CAUTION - review the WARN items.",
                _ => "SAFE - all checks passed.",
            });

            File.WriteAllText(path, sb.ToString());
            Console.WriteLine(sb.ToString());
            Console.WriteLine($"(report written to {path})");
        }

        /// <summary>Headless dump of arbitrary check groups (used to verify the inventory tabs).</summary>
        static void DumpGroups(string heading, System.Collections.Generic.IEnumerable<CheckGroup> groups)
        {
            Console.WriteLine($"{heading}  -  {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
            foreach (var g in groups)
            {
                Console.WriteLine();
                Console.WriteLine(g.Title);
                Console.WriteLine(new string('-', 64));
                foreach (var r in g.Results)
                {
                    if (r.Table) { Console.WriteLine("  " + r.Name); continue; }
                    string tag = r.Status switch
                    {
                        CheckStatus.Pass => "[PASS]",
                        CheckStatus.Warn => "[WARN]",
                        CheckStatus.Fail => "[FAIL]",
                        _ => "[INFO]",
                    };
                    Console.WriteLine($"  {tag} {r.Name}" +
                        (string.IsNullOrEmpty(r.Detail) ? "" : $"  -  {r.Detail}"));
                }
            }
        }
    }
}
