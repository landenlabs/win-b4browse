// Copyright (c) 2026 LanDen Labs - Dennis Lang

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace BrowseSafe
{
    /// <summary>
    /// Central catalog mapping a scope key to its check producers, plus plain-text
    /// report generation. Shared by the headless runner and the email feature.
    /// </summary>
    public static class Reports
    {
        /// <summary>Per-tab producers, in display order. "all" runs every scope.</summary>
        private static readonly (string Key, string Title, Func<CheckGroup>[] Producers)[] Catalog =
        {
            ("scan", "Safety Scan", new Func<CheckGroup>[]
            {
                SafetyChecks.CheckDnsServers, SafetyChecks.CheckRouter, SafetyChecks.CheckUpstreamResolver,
                SafetyChecks.CheckDnsLookups, SafetyChecks.CheckCrossResolver, SafetyChecks.CheckHostsFile,
                SafetyChecks.CheckEmailDns, SafetyChecks.CheckProxy, SafetyChecks.CheckTimeSync,
                SafetyChecks.CheckWindowsSecurity,
            }),
            ("chrome",    "Chrome", new Func<CheckGroup>[] { SafetyChecks.CheckChromeExe, SafetyChecks.CheckChromeExtensions }),
            ("services",  "Services", new Func<CheckGroup>[] { SafetyChecks.CheckServices }),
            ("processes", "Processes", new Func<CheckGroup>[] { SafetyChecks.CheckProcesses }),
            ("startup",   "Startup", new Func<CheckGroup>[] { SafetyChecks.CheckStartup }),
            ("installed", "Installed", new Func<CheckGroup>[] { SafetyChecks.CheckInstalled }),
            ("devices",   "Devices", new Func<CheckGroup>[] { SafetyChecks.CheckDevices }),
        };

        public static IEnumerable<string> Scopes => Catalog.Select(c => c.Key).Append("all");

        public static bool IsValidScope(string scope) =>
            scope.Equals("all", StringComparison.OrdinalIgnoreCase) ||
            Catalog.Any(c => c.Key.Equals(scope, StringComparison.OrdinalIgnoreCase));

        /// <summary>Runs the producers for a scope and formats a plain-text report.</summary>
        public static (string Text, CheckStatus Overall) Build(string scope)
        {
            var sections = scope.Equals("all", StringComparison.OrdinalIgnoreCase)
                ? Catalog
                : Catalog.Where(c => c.Key.Equals(scope, StringComparison.OrdinalIgnoreCase)).ToArray();

            var sb = new StringBuilder();
            sb.AppendLine($"Browse Safe report  -  scope: {scope}  -  {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
            sb.AppendLine(new string('=', 70));

            CheckStatus overall = CheckStatus.Pass;
            foreach (var (_, title, producers) in sections)
            {
                sb.AppendLine();
                sb.AppendLine($"### {title} ###");
                foreach (var produce in producers)
                {
                    var g = produce();
                    sb.AppendLine();
                    sb.AppendLine(g.Title);
                    sb.AppendLine(new string('-', 70));
                    foreach (var r in g.Results)
                    {
                        if (r.Table) { sb.AppendLine("  " + r.Name); continue; }
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
            }

            sb.AppendLine();
            sb.AppendLine(new string('=', 70));
            sb.AppendLine("VERDICT: " + overall switch
            {
                CheckStatus.Fail => "NOT SAFE - resolve the FAIL items before browsing.",
                CheckStatus.Warn => "CAUTION - review the WARN items.",
                _ => "OK - no failures.",
            });
            return (sb.ToString(), overall);
        }
    }
}
