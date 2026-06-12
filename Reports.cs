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
                SafetyChecks.CheckWindowsSecurity, SafetyChecks.CheckPromiscuousMode,
                SafetyChecks.CheckNetworkAdapters,
            }),
            ("dns",       "DNS Cache", new Func<CheckGroup>[] { SafetyChecks.CheckDnsCache }),
            ("arp",       "ARP Cache", new Func<CheckGroup>[] { SafetyChecks.CheckArp }),
            ("patches",   "Patches", new Func<CheckGroup>[] { SafetyChecks.CheckPatches }),
            ("chrome",    "Chrome", new Func<CheckGroup>[] { SafetyChecks.CheckChromeExe, SafetyChecks.CheckChromePrivacy, SafetyChecks.CheckChromeExtensions }),
            ("settings",  "Chrome Settings", new Func<CheckGroup>[] { SafetyChecks.CheckChromeSettings }),
            ("services",  "Services", new Func<CheckGroup>[] { SafetyChecks.CheckServices }),
            ("processes", "Processes", new Func<CheckGroup>[] { SafetyChecks.CheckProcesses }),
            ("startup",   "Startup", new Func<CheckGroup>[] { SafetyChecks.CheckStartup }),
            ("scheduled", "Scheduled Tasks", new Func<CheckGroup>[] { SafetyChecks.CheckScheduledTasks }),
            ("installed", "Installed", new Func<CheckGroup>[] { SafetyChecks.CheckInstalled }),
            ("devices",   "Devices", new Func<CheckGroup>[] { SafetyChecks.CheckDevices }),
            ("winext",    "Shell Extensions", new Func<CheckGroup>[] { SafetyChecks.CheckWinExt }),
            ("events",    "Event Log", new Func<CheckGroup>[] { SafetyChecks.CheckEventLog }),
            ("awake",     "Awake Periods", new Func<CheckGroup>[] { SafetyChecks.CheckAwake }),
            ("activity",  "App Activity", new Func<CheckGroup>[] { SafetyChecks.CheckActivity }),
            ("downloads", "Downloads", new Func<CheckGroup>[] { SafetyChecks.DownloadsHeader, SafetyChecks.CheckDownloads }),
            ("rootca",    "Root CAs", new Func<CheckGroup>[] { SafetyChecks.CheckRootCAs }),
            ("firewall",  "Firewall", new Func<CheckGroup>[] { SafetyChecks.CheckFirewall, SafetyChecks.CheckFirewallRules }),
            ("virus",     "Virus", new Func<CheckGroup>[] { SafetyChecks.VirusHeader, SafetyChecks.CheckVirus }),
            ("restores",  "Restore Points", new Func<CheckGroup>[] { SafetyChecks.CheckRestore }),
        };

        public static IEnumerable<string> Scopes => Catalog.Select(c => c.Key).Append("all");

        public static bool IsValidScope(string scope) =>
            scope.Equals("all", StringComparison.OrdinalIgnoreCase) ||
            Catalog.Any(c => c.Key.Equals(scope, StringComparison.OrdinalIgnoreCase));

        /// <summary>
        /// Runs the producers for a scope and formats a plain-text report. When
        /// <paramref name="progress"/> is supplied it fires once as each section
        /// (scope) starts and once as it finishes - the headless runner uses this to
        /// print progress to stderr. Arguments: (index 1-based, total sections,
        /// UPPERCASE scope label, done?). Each individual check is isolated so one
        /// failure becomes a [FAIL] line instead of aborting the whole report.
        /// </summary>
        public static (string Text, CheckStatus Overall) Build(
            string scope, Action<int, int, string, bool>? progress = null)
        {
            var sections = scope.Equals("all", StringComparison.OrdinalIgnoreCase)
                ? Catalog
                : Catalog.Where(c => c.Key.Equals(scope, StringComparison.OrdinalIgnoreCase)).ToArray();

            var sb = new StringBuilder();
            sb.AppendLine($"Browse Safe report  -  scope: {scope}  -  {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
            sb.AppendLine(new string('=', 70));

            int total = sections.Length;
            int index = 0;
            CheckStatus overall = CheckStatus.Pass;
            foreach (var (key, title, producers) in sections)
            {
                index++;
                string label = key.ToUpperInvariant();
                progress?.Invoke(index, total, label, false);   // started

                sb.AppendLine();
                sb.AppendLine($"### {title} ###");
                foreach (var produce in producers)
                {
                    CheckGroup g;
                    try { g = produce(); }
                    catch (Exception ex)
                    {
                        // Isolate a failing check: one exception must not abort the whole
                        // report (notably --run all, which runs every producer).
                        g = new CheckGroup($"{title} - check error");
                        g.Add(CheckStatus.Fail, "Unhandled error", ex.Message);
                        ErrorLog.Add(ErrorCategory.Error, "Unhandled error in check", ex.ToString(), title);
                    }

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

                progress?.Invoke(index, total, label, true);    // done
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
