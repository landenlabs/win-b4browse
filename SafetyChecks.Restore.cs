// Copyright (c) 2026 LanDen Labs - Dennis Lang

using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;

namespace B4Browse
{
    /// <summary>
    /// Windows System Restore points (the Restores tab; requires administrator). These are a
    /// security signal: modern ransomware disables System Restore and purges shadow copies right
    /// after elevating, so a disabled service or zero restore points is a high-priority IoC. A very
    /// old youngest point means the machine has no effective recovery safety net, and recent
    /// install-triggered checkpoints help map a "what changed, when" exposure timeline.
    /// </summary>
    public static partial class SafetyChecks
    {
        private const int StaleRestoreDays = 90;   // youngest point older than this = no recent safety net

        /// <summary>Structured restore-point list (used by the Restores grid). Empty if SR is off /
        /// there are none / not elevated.</summary>
        public static List<RestorePoint> GetRestorePoints()
        {
            var rows = RunPowerShellArray(
                "@(Get-ComputerRestorePoint | Select-Object SequenceNumber, Description, RestorePointType, " +
                "@{n='Created';e={$_.ConvertToDateTime($_.CreationTime).ToString('yyyy-MM-dd HH:mm:ss')}}) | " +
                "ConvertTo-Json -Compress -Depth 3");

            var list = new List<RestorePoint>();
            foreach (var r in rows)
            {
                var p = new RestorePoint
                {
                    Sequence = JInt(r, "SequenceNumber"),
                    Description = Str(r, "Description"),
                    TypeCode = JInt(r, "RestorePointType"),
                };
                p.TypeText = RestoreTypeName(p.TypeCode);

                string created = Str(r, "Created");
                if (DateTime.TryParseExact(created, "yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture,
                        DateTimeStyles.None, out var dt))
                {
                    p.Created = dt;
                    p.CreatedText = dt.ToString("yyyy-MM-dd HH:mm");
                    p.DaysOld = Math.Max(0, (int)(DateTime.Now - dt).TotalDays);
                }
                else
                {
                    p.CreatedText = "—";
                }

                // Audit C: a recent install-triggered checkpoint marks a "what changed" point worth
                // correlating against the Events tab (possible PUP / bundled-software vector).
                if (p.DaysOld is < 14 && p.TypeCode is 0 or 10)
                {
                    p.Risk = TabSeverity.Caution;
                    p.Note = "recent install-triggered checkpoint - correlate with the Events tab timeline";
                }

                list.Add(p);
            }
            return list;
        }

        private static string RestoreTypeName(int code) => code switch
        {
            0 => "App install",
            1 => "App uninstall",
            10 => "Driver install",
            12 => "Settings change",
            13 => "Cancelled operation",
            _ => $"#{code}",
        };

        /// <summary>Best-effort System Restore enabled state (registry; HKLM reads work unelevated).</summary>
        public static (bool Enabled, string Detail) SystemRestoreStatus()
        {
            bool policyOff = ReadHklmDword(@"SOFTWARE\Policies\Microsoft\Windows NT\SystemRestore", "DisableSR", 0) == 1;
            if (policyOff) return (false, "Disabled by Group Policy (DisableSR).");

            int rp = ReadHklmDword(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore", "RPSessionInterval", -1);
            if (rp == 0) return (false, "Disabled (RPSessionInterval = 0).");
            return (true, "Enabled.");
        }

        /// <summary>Concise summary for the Restores tab header panel.</summary>
        public static CheckGroup RestoreHeader()
        {
            var group = new CheckGroup("System Restore");
            if (!Elevation.IsAdmin)
            {
                group.Add(CheckStatus.Info, "Administrator", "Run as Admin to read restore points.");
                return group;
            }

            var (enabled, detail) = SystemRestoreStatus();
            group.Add(enabled ? CheckStatus.Pass : CheckStatus.Fail, "System Restore", detail);

            var points = GetRestorePoints();
            if (points.Count == 0)
            {
                group.Add(CheckStatus.Fail, "Restore points",
                    "None found - if this machine had restore points before, a purge is a ransomware IoC.");
                return group;
            }

            int youngest = points.Min(p => p.DaysOld ?? int.MaxValue);
            group.Add(youngest > StaleRestoreDays ? CheckStatus.Warn : CheckStatus.Pass, "Coverage",
                $"{points.Count} point(s); youngest {(youngest == int.MaxValue ? "unknown" : youngest + " day(s)")} old.");
            return group;
        }

        // ----------------------------------------------------------------- //
        // Report producer (headless / email / copy)
        // ----------------------------------------------------------------- //
        public static CheckGroup CheckRestore()
        {
            var group = new CheckGroup("System Restore Points");

            if (!Elevation.IsAdmin)
            {
                group.Add(CheckStatus.Info, "Restore points",
                    "Requires administrator (run the app as admin to audit System Restore).");
                return group;
            }

            var (enabled, detail) = SystemRestoreStatus();
            var points = GetRestorePoints();

            // Audit A: disabled service or zero points is a high-priority IoC.
            if (!enabled)
                group.Add(CheckStatus.Fail, "System Restore", detail + "  Ransomware disables it to block recovery.");
            else if (points.Count == 0)
                group.Add(CheckStatus.Fail, "Restore points",
                    "System Restore is enabled but there are ZERO restore points - a purge is a ransomware IoC.");
            else
                group.Add(CheckStatus.Pass, "System Restore", $"{detail}  {points.Count} restore point(s).");

            if (points.Count > 0)
            {
                int youngest = points.Min(p => p.DaysOld ?? int.MaxValue);
                // Audit B: a very old youngest point means no effective safety net.
                if (youngest > StaleRestoreDays)
                    group.Add(CheckStatus.Warn, "Stale safety net",
                        $"Youngest restore point is {youngest} day(s) old (> {StaleRestoreDays}); recovery coverage is weak.");

                int shown = 0;
                foreach (var p in points.OrderByDescending(p => p.Created ?? DateTime.MinValue))
                {
                    if (++shown > MaxList) break;
                    var st = p.Risk >= TabSeverity.Caution ? CheckStatus.Warn : CheckStatus.Info;
                    group.Add(st, $"#{p.Sequence}  {p.CreatedText}",
                        $"{p.TypeText}  -  {p.Description}" + (p.Note.Length > 0 ? $"   ({p.Note})" : ""));
                }
                if (points.Count > MaxList)
                    group.Add(CheckStatus.Info, "...", $"{points.Count - MaxList} more not shown.");
            }
            return group;
        }
    }
}
