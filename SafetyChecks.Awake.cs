// Copyright (c) 2026 LanDen Labs - Dennis Lang

using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;

namespace B4Browse
{
    /// <summary>
    /// Lists recent power-state transitions (boot / wake / sleep / hibernate / modern standby /
    /// shutdown / unexpected power loss) straight from the System event log - one row per event,
    /// newest first. Read via Get-WinEvent on the System log, which standard users can read (no
    /// elevation needed). Wake events carry a "Wake Source" that often names what woke the machine
    /// (a power button, an input device, or a scheduled task), surfaced as the "Detail" column.
    ///
    /// Earlier versions tried to pair boot/wake -> sleep/shutdown into "awake periods" and debounce
    /// the noise, but on Modern Standby (S0) laptops the 506/507 enter/exit-standby pairs fire
    /// constantly (sometimes same-second), so the pairing dropped real transitions and produced a
    /// wrong timeline. The tab now lists every event verbatim - the Gap column makes the standby
    /// churn obvious without hiding anything, and a dirty power-off (41 / 6008) shows as its own row.
    /// </summary>
    public static partial class SafetyChecks
    {
        private const int AwakeDays = 14;

        /// <summary>A single power-state transition pulled from the System log.</summary>
        private sealed class PowerEvent
        {
            public DateTime Time;
            public int Id;
            public string Action = "";      // human label for the transition
            public string Detail = "";      // wake source / shutdown reason
            public bool Unexpected;         // dirty power-off (41 / 6008)
            public string PowerText = "";   // charging state at the event ("AC 100%" / "Batt 87%")
            public int BatteryPct = -1;     // battery %, -1 when unknown
        }

        /// <summary>Every power event in the window, newest first (for the grid + report).</summary>
        public static List<PowerEventRow> GetPowerEvents()
        {
            var events = ReadPowerEvents();
            events.Sort((a, b) => a.Time.CompareTo(b.Time));   // ascending; no collapse, no debounce

            var rows = new List<PowerEventRow>();
            DateTime? prev = null;
            for (int i = 0; i < events.Count; i++)
            {
                var e = events[i];
                double gap = prev.HasValue ? (e.Time - prev.Value).TotalMinutes : -1;
                rows.Add(new PowerEventRow
                {
                    Index = i + 1,
                    Time = e.Time,
                    TimeText = FmtAwakeTime(e.Time),
                    Action = e.Action,
                    Detail = e.Detail,
                    EventId = e.Id,
                    PowerText = e.PowerText,
                    BatteryPct = e.BatteryPct,
                    GapMin = gap,
                    GapText = gap < 0 ? "—" : FmtDuration(gap),
                    Unexpected = e.Unexpected,
                    Risk = e.Unexpected ? TabSeverity.Caution : TabSeverity.Ok,
                });
                prev = e.Time;
            }

            rows.Reverse();   // newest first
            return rows;
        }

        // ---- Reading + classifying the System power events ------------------------------- //
        private static List<PowerEvent> ReadPowerEvents()
        {
            var list = new List<PowerEvent>();

            // Power/boot/shutdown event IDs in the System log. Provider is checked in C# so an
            // ID that other providers also use (e.g. 12/13) is only honoured from the right source.
            // 506/507 are Kernel-Power Modern Standby (S0) enter/exit. For event 42, Target is the
            // entered power state (4 = hibernate / S4). 41 (Kernel-Power) and 6008 (EventLog) are the
            // dirty-power-off signals - a long power-button hold or power loss logs these, not a clean
            // sleep/shutdown.
            // For the Modern Standby enter/exit events (506/507) we also pull the battery + AC fields
            // out of the event's EventData (parsed by name from the XML, since Properties are
            // positional and reorder across Windows builds): PowerStateAc and the remaining/full
            // battery capacity at the transition. These give the charging state at each wake.
            string script = $@"
$ErrorActionPreference='SilentlyContinue'
$start=(Get-Date).AddDays(-{AwakeDays})
try {{
  Get-WinEvent -FilterHashtable @{{LogName='System';Id=41,1,42,107,506,507,12,13,1074,6005,6006,6008;StartTime=$start}} -MaxEvents 2000 |
    ForEach-Object {{
      $m=[string]$_.Message
      $tgt=''; $ac=''; $bc=''; $bf=''
      if ($_.Id -eq 42 -and $_.Properties.Count -gt 0) {{ try {{ $tgt=[string]$_.Properties[0].Value }} catch {{}} }}
      if ($_.Id -eq 506 -or $_.Id -eq 507) {{
        try {{
          $d=@{{}}
          foreach ($n in ([xml]$_.ToXml()).Event.EventData.Data) {{ $d[$n.Name]=[string]$n.'#text' }}
          if ($d.ContainsKey('PowerStateAc')) {{ $ac=$d['PowerStateAc'] }}
          if ($_.Id -eq 507) {{ $bc=$d['BatteryRemainingCapacityOnExit']; $bf=$d['BatteryFullChargeCapacityOnExit'] }}
          else {{ $bc=$d['BatteryRemainingCapacityOnEnter']; $bf=$d['BatteryFullChargeCapacityOnEnter'] }}
        }} catch {{}}
      }}
      [pscustomobject]@{{
        Time=$_.TimeCreated.ToString('o')
        Id=[int]$_.Id
        Provider=[string]$_.ProviderName
        Target=$tgt
        Ac=$ac
        BattCur=$bc
        BattFull=$bf
        Msg=$m.Substring(0,[Math]::Min(500,$m.Length))
      }}
    }} | ConvertTo-Json -Compress -Depth 3
}} catch {{}}";

            foreach (var r in RunPowerShellArray(script))
            {
                if (!DateTime.TryParse(JStr(r, "Time"), null, DateTimeStyles.RoundtripKind, out var t)) continue;
                DateTime time = t.Kind == DateTimeKind.Utc ? t.ToLocalTime() : t;
                int id = JInt(r, "Id");
                var pe = ClassifyPowerEvent(id, JStr(r, "Provider"), JStr(r, "Msg"), JStr(r, "Target"), time);
                if (pe == null) continue;
                (pe.PowerText, pe.BatteryPct) = MakePowerState(id, JStr(r, "Ac"), JStr(r, "BattCur"), JStr(r, "BattFull"));
                list.Add(pe);
            }
            return list;
        }

        private static PowerEvent? ClassifyPowerEvent(int id, string prov, string msg, string target, DateTime time)
        {
            bool Is(string name) => prov.Equals(name, StringComparison.OrdinalIgnoreCase);
            PowerEvent Ev(string action, string detail = "", bool unexpected = false)
                => new() { Time = time, Id = id, Action = action, Detail = detail, Unexpected = unexpected };

            // Wake. The Power-Troubleshooter (1) carries a human "Wake Source" (often "Unknown" on
            // Modern Standby); the Kernel-Power standby-exit (507) and classic resume (107) carry a
            // "Reason" - Lid / Input Mouse / Input Keyboard / Power Button / Resume from Hibernate.
            if (id == 1 && Is("Microsoft-Windows-Power-Troubleshooter"))
                return Ev("Wake", WhyFromWakeSource(ExtractField(msg, "Wake Source:")));
            if (id == 107 && Is("Microsoft-Windows-Kernel-Power"))
                return Ev("Wake", ExtractReason(msg));
            if (id == 507 && Is("Microsoft-Windows-Kernel-Power"))   // exit Modern Standby
                return Ev("Wake (exit standby)", ExtractReason(msg));

            // Sleep / hibernate. Event 42 Target = 4 means hibernate (S4); Modern Standby is 506.
            // Both carry a "Reason" - Power Button / Lid / Idle Timeout / Screen Off Request / etc.
            if (id == 42 && Is("Microsoft-Windows-Kernel-Power"))
                return Ev(target == "4" ? "Hibernate" : "Sleep", ExtractReason(msg));
            if (id == 506 && Is("Microsoft-Windows-Kernel-Power"))   // enter Modern Standby
                return Ev("Sleep (modern standby)", ExtractReason(msg));

            // Boot.
            if (id == 12 && Is("Microsoft-Windows-Kernel-General"))
                return Ev("Boot");
            if (id == 6005 && Is("EventLog"))
                return Ev("Boot (log started)");

            // Clean shutdown.
            if (id == 13 && Is("Microsoft-Windows-Kernel-General"))
                return Ev("Shutdown");
            if (id == 6006 && Is("EventLog"))
                return Ev("Shutdown (clean)");
            if (id == 1074 && Is("User32"))
                return Ev("Shutdown (initiated)", ExtractField(msg, "reason:"));

            // Dirty power-off - a long power-button hold or power loss lands here, not a clean sleep.
            if (id == 6008 && Is("EventLog"))
                return Ev("Unexpected shutdown", unexpected: true);
            if (id == 41 && Is("Microsoft-Windows-Kernel-Power"))
                return Ev("Unexpected power loss", unexpected: true);

            return null;
        }

        /// <summary>Classifies a raw "Wake Source: ..." string into a short Detail (User / Device /
        /// Scheduler: task / Network / Unknown), keeping the useful detail (e.g. the task name).</summary>
        private static string WhyFromWakeSource(string src)
        {
            if (src.Length == 0) return "";
            string s = src.ToLowerInvariant();

            if (s.Contains("power button") || s.Contains("button")) return "User (power button)";
            if (s.Contains("lid")) return "User (lid)";
            if (s.Contains("keyboard") || s.Contains("mouse") || s.Contains("hid") || s.Contains("input device"))
                return "User (input)";
            if (s.Contains("timer") || s.Contains("rtc"))
            {
                string task = ExtractWakeTask(src);
                return task.Length > 0 ? $"Scheduler: {task}" : "Scheduler (timer)";
            }
            if (s.Contains("magic packet") || s.Contains("wake on") || s.Contains("network"))
                return "Network (Wake-on-LAN)";
            if (s.Contains("device"))
            {
                // "Device -USB Root Hub..." -> trim the leading "Device" marker.
                string dev = src.TrimStart('-', ' ');
                int dash = dev.IndexOf('-');
                if (dash >= 0 && dev.StartsWith("Device", StringComparison.OrdinalIgnoreCase)) dev = dev[(dash + 1)..].Trim();
                return "Device: " + Trunc(dev, 40);
            }
            if (s.Contains("unknown")) return "Unknown";
            return Trunc(src, 44);
        }

        /// <summary>Pulls the scheduled-task name from a timer wake message and gives common tasks a
        /// friendly label (Windows Update, defrag, ...).</summary>
        private static string ExtractWakeTask(string src)
        {
            // The task path is usually quoted: ... execute 'NT TASK\Microsoft\Windows\UpdateOrchestrator\Reboot' ...
            int q1 = src.IndexOf('\'');
            int q2 = q1 >= 0 ? src.IndexOf('\'', q1 + 1) : -1;
            string raw = (q1 >= 0 && q2 > q1) ? src.Substring(q1 + 1, q2 - q1 - 1) : "";
            string lower = raw.ToLowerInvariant();

            if (lower.Contains("updateorchestrator") || lower.Contains("windowsupdate") || lower.Contains("\\update"))
                return "Windows Update";
            if (lower.Contains("defrag")) return "Defrag";
            if (lower.Contains("backup")) return "Backup";
            if (lower.Contains("\\windows defender") || lower.Contains("\\windows\\windows defender"))
                return "Defender scan";

            if (raw.Length == 0) return "";
            // Otherwise show the last path segment(s), trimming the long NT TASK prefix.
            string trimmed = raw.Replace("NT TASK\\", "", StringComparison.OrdinalIgnoreCase)
                                .Replace("Microsoft\\Windows\\", "", StringComparison.OrdinalIgnoreCase);
            return Trunc(trimmed, 40);
        }

        /// <summary>Pulls the "Reason:" value from a Kernel-Power Modern Standby / sleep message
        /// (e.g. "Lid", "Power Button", "Input Mouse", "Idle Timeout"), trimming the trailing period.
        /// Event 42's "Sleep Reason:" matches too, since it contains the "Reason:" marker.</summary>
        private static string ExtractReason(string msg)
            => ExtractField(msg, "Reason:").TrimEnd('.', ' ').Trim();

        /// <summary>Returns the rest of the line after a "Label:" marker in an event message.</summary>
        private static string ExtractField(string msg, string label)
        {
            int i = msg.IndexOf(label, StringComparison.OrdinalIgnoreCase);
            if (i < 0) return "";
            string rest = msg[(i + label.Length)..].Trim();
            int nl = rest.IndexOfAny(new[] { '\r', '\n' });
            if (nl >= 0) rest = rest[..nl].Trim();
            return rest;
        }

        private static string FmtAwakeTime(DateTime t)
        {
            // "Sun 14-Jun 8:33:49am" (weekday + lower-case meridiem, no leading zero on day/hour).
            string s = t.ToString("ddd d-MMM h:mm:sstt", CultureInfo.InvariantCulture);
            return s.Replace("AM", "am").Replace("PM", "pm");
        }

        /// <summary>Builds the "AC 100%" / "Batt 87%" / "73%" charging-state text (and a sortable
        /// battery %) from the Modern Standby event's PowerStateAc + remaining/full battery capacity.
        /// Only 506/507 carry these; everything else returns blank.</summary>
        private static (string Text, int Pct) MakePowerState(int id, string ac, string curS, string fullS)
        {
            if (id != 506 && id != 507) return ("", -1);

            long.TryParse(curS, out long cur);
            long.TryParse(fullS, out long full);
            int pct = full > 0 ? (int)Math.Round(cur * 100.0 / full) : -1;

            // PowerStateAc is recorded on the standby-exit (507) event; 506 doesn't carry it.
            string src = ac.Equals("true", StringComparison.OrdinalIgnoreCase) ? "AC"
                       : ac.Equals("false", StringComparison.OrdinalIgnoreCase) ? "Batt"
                       : "";

            string text = (src, pct >= 0) switch
            {
                ("", false) => "",
                ("", true) => $"{pct}%",
                (_, false) => src,
                (_, true) => $"{src} {pct}%",
            };
            return (text, pct);
        }

        private static string FmtDuration(double minutes)
        {
            if (minutes < 0) return "—";
            if (minutes < 1) return $"{minutes * 60:0} sec";
            if (minutes < 60) return $"{minutes:0.0} min";
            int h = (int)(minutes / 60);
            int m = (int)Math.Round(minutes - h * 60);
            if (m == 60) { h++; m = 0; }
            return $"{h}h {m:00}m";
        }

        /// <summary>Report producer (headless / email / copy / print): the raw power-event table.</summary>
        public static CheckGroup CheckAwake()
        {
            var group = new CheckGroup($"Power Events (last {AwakeDays} days)");
            var rows = GetPowerEvents();
            if (rows.Count == 0)
            {
                group.Add(CheckStatus.Info, "Power events",
                    "No boot / wake / sleep events found in the System log for this window.");
                return group;
            }

            int unexpected = rows.Count(r => r.Unexpected);
            group.Add(unexpected > 0 ? CheckStatus.Warn : CheckStatus.Info,
                $"{rows.Count} power event(s)",
                unexpected > 0
                    ? $"{unexpected} unexpected power loss/shutdown (dirty power-off). Newest first; Gap = time since the previous event."
                    : "Boot / wake / sleep / shutdown transitions, newest first; Gap = time since the previous event.");

            group.AddRow(CheckStatus.Info, AwakeReportRow("#", "Date / time", "Action", "Detail", "Power", "Gap", "Id"));
            group.AddRow(CheckStatus.Info, AwakeReportRow("----", "----------------------", "----------------------", "------------------------------------", "---------", "----------", "-----"));
            foreach (var r in rows)
                group.AddRow(r.Unexpected ? CheckStatus.Warn : CheckStatus.Info,
                    AwakeReportRow(r.Index.ToString(), r.TimeText, r.Action, r.Detail, r.PowerText, r.GapText, r.EventId.ToString()));
            return group;
        }

        private static string AwakeReportRow(string n, string time, string action, string detail, string power, string gap, string id)
            => $"  {Trunc(n, 4),-4} {Trunc(time, 22),-22} {Trunc(action, 22),-22} {Trunc(detail, 38),-38} {Trunc(power, 9),-9} {Trunc(gap, 10),-10} {id}";

        // ---- "What can wake this PC" header (devices + timers, with adjust links) -------- //

        /// <summary>Header above the Power Events grid: the devices currently armed to wake the
        /// machine and the wake timers (scheduled tasks), each with a blue link to where it's
        /// adjusted. Reads powercfg; device/last-wake queries work unelevated, wake-timer listing
        /// needs admin. Also feeds the headless report.</summary>
        public static CheckGroup WakeSourcesHeader()
        {
            var g = new CheckGroup("What can wake this PC");

            var devices = GetWakeArmedDevices();
            g.Add(CheckStatus.Info, $"Wake-armed devices ({devices.Count})",
                    devices.Count > 0 ? string.Join(", ", devices) : "none currently armed")
                .WithLink("[ Device Manager ]", "devmgmt.msc");

            g.Add(CheckStatus.Info, "Wake timers", GetWakeTimersSummary())
                .WithLink("[ Task Scheduler ]", "taskschd.msc");

            g.Add(CheckStatus.Info, "Power & sleep",
                    "sleep timeout, 'allow wake timers', and what closing the lid / power button does")
                .WithLink("[ Power options ]", "powercfg.cpl");

            return g;
        }

        /// <summary>Devices currently allowed to wake the machine (powercfg /devicequery wake_armed,
        /// no elevation needed): mouse, keyboard, network adapter, USB hubs, etc.</summary>
        private static List<string> GetWakeArmedDevices()
        {
            var list = new List<string>();
            string? outp = RunCapture("powercfg.exe", "/devicequery wake_armed", 8000);
            if (outp == null) return list;
            foreach (var raw in outp.Split('\n'))
            {
                string t = raw.Trim();
                if (t.Length == 0 || t.Equals("NONE", StringComparison.OrdinalIgnoreCase)) continue;
                list.Add(t);
            }
            return list;
        }

        /// <summary>One-line summary of the active wake timers (powercfg /waketimers). That command
        /// needs administrator; unelevated it just prints a notice, surfaced here as such.</summary>
        private static string GetWakeTimersSummary()
        {
            string? outp = RunCapture("powercfg.exe", "/waketimers", 8000, includeStdErr: true);
            if (string.IsNullOrWhiteSpace(outp)) return "none active";
            if (outp.Contains("requires administrator", StringComparison.OrdinalIgnoreCase))
                return "requires administrator to list (run as admin)";
            if (outp.Contains("no active wake timers", StringComparison.OrdinalIgnoreCase))
                return "none active";

            // Each timer block has a "Reason:" line - show how many, plus the first reason.
            var reasons = outp.Split('\n')
                .Select(l => l.Trim())
                .Where(l => l.StartsWith("Reason:", StringComparison.OrdinalIgnoreCase))
                .Select(l => l[7..].Trim())
                .ToList();
            if (reasons.Count == 0) return "active (see Task Scheduler)";
            return reasons.Count == 1 ? reasons[0] : $"{reasons.Count} active - e.g. {Trunc(reasons[0], 60)}";
        }
    }
}
