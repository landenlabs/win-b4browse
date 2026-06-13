// Copyright (c) 2026 LanDen Labs - Dennis Lang

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;

namespace B4Browse
{
    /// <summary>
    /// Recent Windows Event Log scan: surfaces critical/error events plus a curated
    /// set of security-significant events (Defender detections, firewall rule changes,
    /// new service installs, audit-log clears, account/group changes, scheduled-task
    /// create/delete/update, and explicit-credential logons) from the last few days -
    /// the things that pile up in Event Viewer that no one ever reviews. Failed logons
    /// (4625) are listed too but not flagged significant (they are common and noisy).
    /// The Security-channel events require Administrator; without it they yield nothing.
    /// Read via Get-WinEvent so each channel is server-side filtered and a channel that
    /// requires elevation (e.g. Security) simply yields nothing instead of failing.
    /// </summary>
    public static partial class SafetyChecks
    {
        private const int EventDays = 7;

        // Security-significant event IDs (channel-independent matches). Defender and
        // Firewall channels are treated as significant wholesale (see GetEventLogIssues).
        private static readonly HashSet<int> SignificantIds = new()
        {
            7045,                       // System: a new service was installed
            1102,                       // Security: the audit log was cleared
            4720, 4728, 4732, 4756,     // Security: account created / added to a (admin) group
            4648,                       // Security: logon using explicit credentials (lateral movement)
            4698, 4699, 4702,           // Security: scheduled task created / deleted / updated
        };

        /// <summary>Structured recent-event list used by the Events grid.</summary>
        public static List<EventItem> GetEventLogIssues()
        {
            // One Get-WinEvent per source, each fault-isolated, merged into a single JSON
            // array. -FilterHashtable is server-side filtered (fast); a missing channel or
            // an access-denied (Security without admin) is swallowed by SilentlyContinue.
            string script = $@"
$ErrorActionPreference='SilentlyContinue'
$start=(Get-Date).AddDays(-{EventDays})
function Q($ht,$cap){{ try {{ Get-WinEvent -FilterHashtable $ht -MaxEvents $cap -ErrorAction SilentlyContinue }} catch {{}} }}
$ev=@()
$ev+=Q @{{LogName='System';Level=1,2;StartTime=$start}} 200
$ev+=Q @{{LogName='Application';Level=1,2;StartTime=$start}} 200
$ev+=Q @{{LogName='System';Id=7045,7030,7031,7034;StartTime=$start}} 100
$ev+=Q @{{LogName='Microsoft-Windows-Windows Defender/Operational';Id=1006,1008,1015,1116,1117,5001,5007,5010,5012;StartTime=$start}} 100
$ev+=Q @{{LogName='Microsoft-Windows-Windows Firewall With Advanced Security/Firewall';Id=2004,2005,2006,2033;StartTime=$start}} 100
$ev+=Q @{{LogName='Security';Id=1102,4720,4728,4732,4756,4648,4698,4699,4702;StartTime=$start}} 200
$ev+=Q @{{LogName='Security';Id=4625;StartTime=$start}} 200
$ev | Where-Object {{ $_ -ne $null }} | ForEach-Object {{
  $m = ([string]$_.Message -split ""`r?`n"")[0]
  [pscustomobject]@{{ Time=$_.TimeCreated.ToString('o'); Id=[int]$_.Id; Level=[string]$_.LevelDisplayName; Source=[string]$_.ProviderName; Channel=[string]$_.LogName; Message=$m }}
}} | ConvertTo-Json -Compress -Depth 3";

            var rows = RunPowerShellArray(script);
            var list = new List<EventItem>();
            var seen = new HashSet<string>();

            foreach (var r in rows)
            {
                var e = new EventItem
                {
                    EventId = JInt(r, "Id"),
                    Level = JStr(r, "Level"),
                    Source = JStr(r, "Source"),
                    Channel = JStr(r, "Channel"),
                    Message = JStr(r, "Message").Trim(),
                };

                string timeRaw = JStr(r, "Time");
                if (DateTime.TryParse(timeRaw, null,
                        System.Globalization.DateTimeStyles.RoundtripKind, out var t))
                {
                    e.Time = t.Kind == DateTimeKind.Utc ? t.ToLocalTime() : t;
                    e.TimeSort = e.Time;
                    e.TimeText = e.Time.ToString("yyyy-MM-dd HH:mm");
                }

                e.Significant =
                    SignificantIds.Contains(e.EventId) ||
                    e.Channel.IndexOf("Defender", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    e.Channel.IndexOf("Firewall", StringComparison.OrdinalIgnoreCase) >= 0;

                // The level-based and id-based queries can overlap (e.g. an Error that is
                // also one of the explicit IDs); de-dup on time+channel+id.
                string key = $"{e.TimeSort.Ticks}|{e.Channel}|{e.EventId}";
                if (!seen.Add(key)) continue;

                list.Add(e);
            }

            // Newest first; significant events still findable by sorting the Status column.
            list.Sort((a, b) => b.TimeSort.CompareTo(a.TimeSort));
            return list;
        }

        /// <summary>Report-format summary of the recent event scan (headless / email).</summary>
        public static CheckGroup CheckEventLog()
        {
            var group = new CheckGroup($"Recent Event Log issues (last {EventDays} days)");
            var events = GetEventLogIssues();

            if (events.Count == 0)
            {
                group.Add(CheckStatus.Pass, "Events",
                    "No critical/error or security-significant events found (Security log needs admin).");
                return group;
            }

            int significant = events.Count(e => e.Significant);
            int critical = events.Count(e => e.Level.Equals("Critical", StringComparison.OrdinalIgnoreCase));
            int errors = events.Count(e => e.Level.Equals("Error", StringComparison.OrdinalIgnoreCase));

            group.Add(significant > 0 ? CheckStatus.Warn : CheckStatus.Info, "Event summary",
                $"{events.Count} events  -  {significant} security-significant, {critical} critical, {errors} error.");

            int shown = 0;
            foreach (var e in events.OrderByDescending(e => e.Significant).ThenByDescending(e => e.TimeSort))
            {
                if (++shown > MaxList) break;
                var status = e.Significant ? CheckStatus.Warn : CheckStatus.Info;
                group.Add(status, $"{e.TimeText}  {ShortChannel(e.Channel)}  #{e.EventId}",
                    $"{e.Level}  -  {e.Source}  -  {Truncate(e.Message, 120)}");
            }
            if (events.Count > MaxList)
                group.Add(CheckStatus.Info, "...", $"{events.Count - MaxList} more not shown.");

            return group;
        }

        /// <summary>Drops the verbose "Microsoft-Windows-" prefix for compact display.</summary>
        public static string ShortChannel(string channel) =>
            channel.StartsWith("Microsoft-Windows-", StringComparison.OrdinalIgnoreCase)
                ? channel.Substring("Microsoft-Windows-".Length)
                : channel;

        private static string Truncate(string s, int max) =>
            s.Length <= max ? s : s.Substring(0, max) + "...";

        private static int JInt(JsonElement e, string p) =>
            e.TryGetProperty(p, out var v) && v.TryGetInt32(out int i) ? i : 0;
    }
}
