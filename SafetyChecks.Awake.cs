// Copyright (c) 2026 LanDen Labs - Dennis Lang

using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text.Json;

namespace BrowseSafe
{
    /// <summary>
    /// Reconstructs recent "awake" periods (boot/wake -> sleep/shutdown) from the System
    /// event log's power events. Read via Get-WinEvent on the System log, which standard
    /// users can read (no elevation needed). Wake events carry a "Wake Source" that often
    /// names what woke the machine - a power button, an input device, or a scheduled task
    /// (e.g. Windows Update, defrag) - which becomes the "Why" column.
    /// </summary>
    public static partial class SafetyChecks
    {
        private const int AwakeDays = 14;

        private enum AwakeKind { Boot, Wake, Sleep, Shutdown }

        /// <summary>A single power-state transition pulled from the System log.</summary>
        private sealed class PowerEvent
        {
            public DateTime Time;
            public AwakeKind Kind;
            public string Why = "";    // start trigger (Boot/Wake)
            public string Code = "";   // end code (Sleep/Shutdown)
            public bool IsStart => Kind is AwakeKind.Boot or AwakeKind.Wake;
        }

        /// <summary>The reconstructed awake periods, newest first (for the grid + report).</summary>
        public static List<AwakePeriod> GetAwakePeriods()
        {
            var events = ReadPowerEvents();
            events.Sort((a, b) => a.Time.CompareTo(b.Time));        // ascending
            events = CollapsePowerEvents(events);                  // merge duplicate signals of one transition

            var periods = new List<AwakePeriod>();
            PowerEvent? openStart = null;

            foreach (var e in events)
            {
                if (e.IsStart)
                {
                    // A new start while one is still open => the previous period ended without a
                    // recorded clean sleep/shutdown (crash / power loss): close it as unexpected.
                    if (openStart != null)
                        periods.Add(MakePeriod(openStart, null, "pwr", unexpected: true));
                    openStart = e;
                }
                else if (openStart != null)
                {
                    periods.Add(MakePeriod(openStart, e, e.Code.Length > 0 ? e.Code : "off", unexpected: false));
                    openStart = null;
                }
                // an end with nothing open (window began mid-period) is ignored
            }

            // A still-open start is the current session.
            if (openStart != null)
                periods.Add(MakePeriod(openStart, null, "on", unexpected: false, current: true));

            for (int i = 0; i < periods.Count; i++) periods[i].Index = i + 1;   // 1 = oldest
            periods.Reverse();                                                   // newest first
            return periods;
        }

        private static AwakePeriod MakePeriod(PowerEvent start, PowerEvent? end, string code,
            bool unexpected, bool current = false)
        {
            var p = new AwakePeriod
            {
                Start = start.Time,
                StartText = FmtAwakeTime(start.Time),
                Why = start.Why.Length > 0 ? start.Why : (start.Kind == AwakeKind.Boot ? "Power on" : "Wake"),
                EndCode = code,
                Unexpected = unexpected,
                Current = current,
            };

            DateTime endTime = current ? DateTime.Now : (end?.Time ?? DateTime.MinValue);

            if (endTime == DateTime.MinValue)               // unknown end (unexpected, no clean close)
            {
                p.EndSort = start.Time;
                p.EndText = $"?  ({code})";
                p.DurationMin = -1;
                p.DurationText = "—";
            }
            else
            {
                p.EndSort = endTime;
                p.EndText = current ? $"now ({code})" : $"{FmtAwakeTime(endTime)} ({code})";
                p.DurationMin = (endTime - start.Time).TotalMinutes;
                p.DurationText = FmtDuration(p.DurationMin);
            }
            return p;
        }

        // ---- Reading + classifying the System power events ------------------------------- //
        private static List<PowerEvent> ReadPowerEvents()
        {
            var list = new List<PowerEvent>();

            // Power/boot/shutdown event IDs in the System log. Provider is checked in C# so an
            // ID that other providers also use (e.g. 12/13) is only honoured from the right source.
            string script = $@"
$ErrorActionPreference='SilentlyContinue'
$start=(Get-Date).AddDays(-{AwakeDays})
try {{
  Get-WinEvent -FilterHashtable @{{LogName='System';Id=1,42,107,12,13,1074,6005,6006;StartTime=$start}} -MaxEvents 1000 |
    ForEach-Object {{
      $m=[string]$_.Message
      [pscustomobject]@{{
        Time=$_.TimeCreated.ToString('o')
        Id=[int]$_.Id
        Provider=[string]$_.ProviderName
        Msg=$m.Substring(0,[Math]::Min(500,$m.Length))
      }}
    }} | ConvertTo-Json -Compress -Depth 3
}} catch {{}}";

            foreach (var r in RunPowerShellArray(script))
            {
                if (!DateTime.TryParse(JStr(r, "Time"), null, DateTimeStyles.RoundtripKind, out var t)) continue;
                DateTime time = t.Kind == DateTimeKind.Utc ? t.ToLocalTime() : t;
                var pe = ClassifyPowerEvent(JInt(r, "Id"), JStr(r, "Provider"), JStr(r, "Msg"), time);
                if (pe != null) list.Add(pe);
            }
            return list;
        }

        private static PowerEvent? ClassifyPowerEvent(int id, string prov, string msg, DateTime time)
        {
            bool Is(string name) => prov.Equals(name, StringComparison.OrdinalIgnoreCase);

            // Wake (the Power-Troubleshooter form carries a human "Wake Source").
            if (id == 1 && Is("Microsoft-Windows-Power-Troubleshooter"))
                return new PowerEvent { Time = time, Kind = AwakeKind.Wake, Why = WhyFromWakeSource(ExtractField(msg, "Wake Source:")) };
            if (id == 107 && Is("Microsoft-Windows-Kernel-Power"))
                return new PowerEvent { Time = time, Kind = AwakeKind.Wake, Why = "Wake" };

            // Sleep / hibernate.
            if (id == 42 && Is("Microsoft-Windows-Kernel-Power"))
                return new PowerEvent { Time = time, Kind = AwakeKind.Sleep, Code = "slp" };

            // Boot.
            if (id == 12 && Is("Microsoft-Windows-Kernel-General"))
                return new PowerEvent { Time = time, Kind = AwakeKind.Boot, Why = "Power on" };
            if (id == 6005 && Is("EventLog"))
                return new PowerEvent { Time = time, Kind = AwakeKind.Boot, Why = "Power on" };

            // Clean shutdown.
            if (id == 13 && Is("Microsoft-Windows-Kernel-General"))
                return new PowerEvent { Time = time, Kind = AwakeKind.Shutdown, Code = "off" };
            if (id == 6006 && Is("EventLog"))
                return new PowerEvent { Time = time, Kind = AwakeKind.Shutdown, Code = "off" };
            if (id == 1074 && Is("User32"))
                return new PowerEvent { Time = time, Kind = AwakeKind.Shutdown, Code = "off" };

            return null;
        }

        /// <summary>Collapses consecutive same-direction signals of one transition (boot logs 12+6005,
        /// a shutdown logs 13+6006, a wake logs 1+107) that land within two minutes into one event,
        /// keeping the most descriptive "Why"/code.</summary>
        private static List<PowerEvent> CollapsePowerEvents(List<PowerEvent> asc)
        {
            var outp = new List<PowerEvent>();
            foreach (var e in asc)
            {
                if (outp.Count > 0)
                {
                    var last = outp[^1];
                    if (last.IsStart == e.IsStart && (e.Time - last.Time).TotalSeconds <= 120)
                    {
                        if (e.IsStart && IsGenericWhy(last.Why) && !IsGenericWhy(e.Why)) last.Why = e.Why;
                        if (!e.IsStart && last.Code.Length == 0) last.Code = e.Code;
                        continue;   // merged into the earlier signal
                    }
                }
                outp.Add(e);
            }
            return outp;
        }

        private static bool IsGenericWhy(string w) => w.Length == 0 || w == "Wake" || w == "Power on";

        /// <summary>Classifies a raw "Wake Source: ..." string into a short Why (User / Device /
        /// Scheduler: task / Network / Unknown), keeping the useful detail (e.g. the task name).</summary>
        private static string WhyFromWakeSource(string src)
        {
            if (src.Length == 0) return "Wake";
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
            // "6-Jun 11:23am" (lower-case meridiem, no leading zero on day/hour).
            string s = t.ToString("d-MMM h:mmtt", CultureInfo.InvariantCulture);
            return s.Replace("AM", "am").Replace("PM", "pm");
        }

        private static string FmtDuration(double minutes)
        {
            if (minutes < 0) return "—";
            if (minutes < 60) return $"{minutes:0.0} min";
            int h = (int)(minutes / 60);
            int m = (int)Math.Round(minutes - h * 60);
            if (m == 60) { h++; m = 0; }
            return $"{h}h {m:00}m";
        }

        /// <summary>Report producer (headless / email / copy / print): the awake-period table.</summary>
        public static CheckGroup CheckAwake()
        {
            var group = new CheckGroup($"Awake / Sleep Periods (last {AwakeDays} days)");
            var periods = GetAwakePeriods();
            if (periods.Count == 0)
            {
                group.Add(CheckStatus.Info, "Awake periods",
                    "No boot / wake / sleep events found in the System log for this window.");
                return group;
            }

            int unexpected = periods.Count(p => p.Unexpected);
            group.Add(unexpected > 0 ? CheckStatus.Warn : CheckStatus.Info,
                $"{periods.Count} awake period(s)",
                unexpected > 0
                    ? $"{unexpected} ended unexpectedly (no clean sleep/shutdown). End codes: off=shutdown, slp=sleep, pwr=unexpected, on=current."
                    : "End codes: off=shutdown, slp=sleep, pwr=unexpected, on=current.");

            group.AddRow(CheckStatus.Info, AwakeReportRow("#", "Start", "End", "Duration", "Why"));
            group.AddRow(CheckStatus.Info, AwakeReportRow("----", "-------------", "--------------------", "----------", "-----"));
            foreach (var p in periods)
                group.AddRow(p.Unexpected ? CheckStatus.Warn : CheckStatus.Info,
                    AwakeReportRow(p.Index.ToString(), p.StartText, p.EndText, p.DurationText, p.Why));
            return group;
        }

        private static string AwakeReportRow(string n, string start, string end, string dur, string why)
            => $"  {Trunc(n, 4),-4} {Trunc(start, 14),-14} {Trunc(end, 22),-22} {Trunc(dur, 10),-10} {why}";
    }
}
