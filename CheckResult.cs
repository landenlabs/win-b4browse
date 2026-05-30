using System.Collections.Generic;

namespace BrowseSafe
{
    /// <summary>Severity / outcome of a single check.</summary>
    public enum CheckStatus
    {
        Pass,   // good - safe
        Warn,   // questionable - review
        Fail,   // unsafe - action needed
        Info    // informational only, no judgement
    }

    /// <summary>A single line of result inside a <see cref="CheckGroup"/>.</summary>
    public sealed class CheckResult
    {
        public CheckStatus Status { get; }
        public string Name { get; }
        public string Detail { get; }

        /// <summary>
        /// When true this result is a pre-formatted monospace table line: renderers
        /// print <see cref="Name"/> verbatim in the status colour, with no [TAG] prefix
        /// and no Detail. Used for the cross-resolver comparison grid.
        /// </summary>
        public bool Table { get; }

        public CheckResult(CheckStatus status, string name, string detail, bool table = false)
        {
            Status = status;
            Name = name;
            Detail = detail;
            Table = table;
        }
    }

    /// <summary>A category of checks (one of the four requested sections).</summary>
    public sealed class CheckGroup
    {
        public string Title { get; }
        public List<CheckResult> Results { get; } = new();

        public CheckGroup(string title) => Title = title;

        public CheckResult Add(CheckStatus status, string name, string detail)
        {
            var r = new CheckResult(status, name, detail);
            Results.Add(r);
            return r;
        }

        /// <summary>Adds a pre-formatted monospace table line (rendered verbatim in the status colour).</summary>
        public CheckResult AddRow(CheckStatus status, string line)
        {
            var r = new CheckResult(status, line, "", table: true);
            Results.Add(r);
            return r;
        }

        /// <summary>
        /// Worst (most severe) status among this group's results. Pre-formatted
        /// table rows are excluded: their per-row PASS/FAIL is informational, and
        /// the section drives the overall verdict through an explicit summary line
        /// instead (so a benign CDN mismatch can't force a global "NOT SAFE").
        /// </summary>
        public CheckStatus Worst()
        {
            CheckStatus worst = CheckStatus.Pass;
            foreach (var r in Results)
            {
                if (r.Table) continue;
                if (Rank(r.Status) > Rank(worst))
                    worst = r.Status;
            }
            return worst;
        }

        /// <summary>Order of severity used to roll up an overall verdict.</summary>
        public static int Rank(CheckStatus s) => s switch
        {
            CheckStatus.Fail => 3,
            CheckStatus.Warn => 2,
            CheckStatus.Pass => 1,
            _ => 0 // Info
        };
    }
}
