// Copyright (c) 2026 LanDen Labs - Dennis Lang

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace B4Browse
{
    /// <summary>
    /// Central catalog mapping a scope key to its check producers, plus plain-text
    /// report generation. Shared by the headless runner and the email feature.
    /// </summary>
    public static class Reports
    {
        /// <summary>Reportable sections (those with headless producers), in display order, drawn
        /// from the single declarative <see cref="Catalog"/>. GUI-only sections (Links, Windows
        /// Security) have no producers and are excluded.</summary>
        private static IEnumerable<Catalog.Section> ReportSections =>
            Catalog.Sections.Where(s => s.HasReport);

        public static IEnumerable<string> Scopes => ReportSections.Select(s => s.Key).Append("all");

        public static bool IsValidScope(string scope) =>
            scope.Equals("all", StringComparison.OrdinalIgnoreCase) ||
            ReportSections.Any(s => s.Key.Equals(scope, StringComparison.OrdinalIgnoreCase));

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
                ? ReportSections.ToArray()
                : ReportSections.Where(c => c.Key.Equals(scope, StringComparison.OrdinalIgnoreCase)).ToArray();

            var sb = new StringBuilder();
            sb.AppendLine($"B4-Browse report  -  scope: {scope}  -  {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
            sb.AppendLine(new string('=', 70));

            int total = sections.Length;
            int index = 0;
            CheckStatus overall = CheckStatus.Pass;
            foreach (var section in sections)
            {
                string title = section.ReportTitleOrTitle;
                index++;
                string label = section.Key.ToUpperInvariant();
                progress?.Invoke(index, total, label, false);   // started

                sb.AppendLine();
                sb.AppendLine($"### {title} ###");
                foreach (var produce in section.Producers)
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
