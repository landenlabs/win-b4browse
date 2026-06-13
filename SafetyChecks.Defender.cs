// Copyright (c) 2026 LanDen Labs - Dennis Lang

using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Management;
using System.Text.Json;

namespace B4Browse
{
    /// <summary>
    /// Microsoft Defender "Virus" summary (the Virus tab and its --run virus report). Two sources:
    /// WMI <c>root\Microsoft\Windows\Defender:MSFT_MpComputerStatus</c> for the live protection /
    /// signature / last-scan state (readable without elevation), and the Defender Operational event
    /// log for the threat + scan history (read via Get-WinEvent; the log is admin-only, so a
    /// non-elevated run simply yields an empty timeline). Both paths are exception-isolated and
    /// safe to call from a background thread; small time-based caches keep the header, summary, and
    /// grid loader from repeating the same WMI query / PowerShell launch within one refresh.
    /// </summary>
    public static partial class SafetyChecks
    {
        private const int VirusEventDays = 365;     // how far back to pull threat / scan events

        private static readonly object _defLock = new();
        private static DefenderStatusSummary? _statusCache;
        private static long _statusTick;
        private static (List<ThreatDetectionRecord> Threats, List<ScanHistoryRecord> Scans)? _eventsCache;
        private static long _eventsTick;

        // ----------------------------------------------------------------- //
        // Protection state / database / scan status  (WMI MSFT_MpComputerStatus)
        // ----------------------------------------------------------------- //
        /// <summary>Live Defender protection, signature, and last-scan state. Never throws; on
        /// failure returns a summary with <see cref="DefenderStatusSummary.Available"/> = false.</summary>
        public static DefenderStatusSummary GetDefenderStatus()
        {
            lock (_defLock)
            {
                if (_statusCache != null && Environment.TickCount64 - _statusTick < 15_000)
                    return _statusCache;
                var s = ReadDefenderStatus();
                _statusCache = s;
                _statusTick = Environment.TickCount64;
                return s;
            }
        }

        private static DefenderStatusSummary ReadDefenderStatus()
        {
            var s = new DefenderStatusSummary();
            try
            {
                var scope = new ManagementScope(@"\\.\root\Microsoft\Windows\Defender");
                scope.Connect();

                using (var searcher = new ManagementObjectSearcher(scope,
                           new ObjectQuery("SELECT * FROM MSFT_MpComputerStatus")))
                {
                    ManagementBaseObject? mo = searcher.Get().Cast<ManagementBaseObject>().FirstOrDefault();
                    if (mo == null) { s.Error = "MSFT_MpComputerStatus returned no instance."; return s; }
                    using (mo)
                    {
                        s.Available = true;
                        s.AntivirusEnabled = WmiBool(mo, "AntivirusEnabled") ?? false;
                        s.RealTimeProtectionEnabled = WmiBool(mo, "RealTimeProtectionEnabled") ?? false;
                        s.BehaviorMonitorEnabled = WmiBool(mo, "BehaviorMonitorEnabled");
                        s.TamperProtected = WmiBool(mo, "IsTamperProtected");
                        s.OnAccessProtectionEnabled = WmiBool(mo, "OnAccessProtectionEnabled");
                        s.NisEnabled = WmiBool(mo, "NISEnabled");
                        s.SignatureVersion = WmiStr(mo, "AntivirusSignatureVersion");
                        s.SignatureLastUpdated = Sane(WmiDate(mo, "AntivirusSignatureLastUpdated"));
                        s.SignatureAgeDays = SaneAge(WmiInt(mo, "AntivirusSignatureAge"));
                        s.QuickScanEnd = Sane(WmiDate(mo, "QuickScanEndTime"));
                        s.FullScanEnd = Sane(WmiDate(mo, "FullScanEndTime"));
                        s.ProductVersion = WmiStr(mo, "AMProductVersion");
                        s.EngineVersion = WmiStr(mo, "AMEngineVersion");
                        s.RunningMode = WmiStr(mo, "AMRunningMode");
                    }
                }

                if (s.SignatureAgeDays == null && s.SignatureLastUpdated is DateTime lu)
                    s.SignatureAgeDays = Math.Max(0, (int)(DateTime.Now - lu).TotalDays);

                // Cloud-delivered protection (MAPS) lives in MpPreference, not MpComputerStatus.
                try
                {
                    using var pref = new ManagementObjectSearcher(scope,
                        new ObjectQuery("SELECT MAPSReporting FROM MSFT_MpPreference"));
                    if (pref.Get().Cast<ManagementBaseObject>().FirstOrDefault() is { } p)
                        using (p) { if (WmiInt(p, "MAPSReporting") is int m) s.CloudProtection = m != 0; }
                }
                catch { /* MpPreference is optional - leave CloudProtection null */ }
            }
            catch (Exception ex)
            {
                s.Available = false;
                s.Error = ex.Message;
            }
            return s;
        }

        // Defender reports "never" with sentinels: a ~65535 (or larger) signature age and an epoch
        // (1601 / pre-2000) date. Treat those as "no record" rather than printing the raw sentinel.
        private static int? SaneAge(int? days) => days is int d && d >= 0 && d < 36500 ? d : null;
        private static DateTime? Sane(DateTime? dt) => dt is DateTime t && t.Year >= 2000 ? t : null;

        private static bool? WmiBool(ManagementBaseObject mo, string prop)
        {
            try { return mo[prop] is bool b ? b : (bool?)null; } catch { return null; }
        }

        private static string WmiStr(ManagementBaseObject mo, string prop)
        {
            try { return mo[prop]?.ToString() ?? ""; } catch { return ""; }
        }

        private static int? WmiInt(ManagementBaseObject mo, string prop)
        {
            try
            {
                object? v = mo[prop];
                if (v == null) return null;
                return v is IConvertible ? Convert.ToInt32(v, CultureInfo.InvariantCulture) : (int?)null;
            }
            catch { return null; }
        }

        /// <summary>Converts a WMI value to a local DateTime, handling both a real DateTime and a
        /// DMTF/CIM datetime string ("20240115093000.000000+000").</summary>
        private static DateTime? WmiDate(ManagementBaseObject mo, string prop)
        {
            try
            {
                object? v = mo[prop];
                if (v == null) return null;
                if (v is DateTime dt) return dt;
                string sv = v.ToString() ?? "";
                if (sv.Length == 0) return null;
                try { return ManagementDateTimeConverter.ToDateTime(sv); } catch { /* not DMTF */ }
                if (DateTime.TryParse(sv, out var d)) return d;
            }
            catch { /* ignore */ }
            return null;
        }

        // ----------------------------------------------------------------- //
        // Threat + scan history  (Defender Operational event log, via Get-WinEvent)
        // ----------------------------------------------------------------- //
        private static readonly HashSet<int> ThreatEventIds = new() { 1116, 1117, 1118 };

        /// <summary>Parsed threat (1116/1117/1118) and scan (1000/1001/1002/1005) events from the
        /// Defender Operational log, newest first. Empty when not elevated (the log is admin-only)
        /// or when the log has no matching events. Cached briefly so the header, summary, and grid
        /// loader share a single PowerShell launch.</summary>
        private static (List<ThreatDetectionRecord> Threats, List<ScanHistoryRecord> Scans) GetDefenderEvents()
        {
            lock (_defLock)
            {
                if (_eventsCache is { } c && Environment.TickCount64 - _eventsTick < 15_000)
                    return c;
                var parsed = ReadDefenderEvents();
                _eventsCache = parsed;
                _eventsTick = Environment.TickCount64;
                return parsed;
            }
        }

        private static (List<ThreatDetectionRecord>, List<ScanHistoryRecord>) ReadDefenderEvents()
        {
            // One Get-WinEvent per event class, server-side filtered. Each event's structured
            // EventData is flattened (Name -> text) so threat name / path / action and the scan
            // type come straight from named fields rather than scraping the message text.
            string script = $@"
$ErrorActionPreference='SilentlyContinue'
$log='Microsoft-Windows-Windows Defender/Operational'
$start=(Get-Date).AddDays(-{VirusEventDays})
function Q($ids,$cap){{ try {{ Get-WinEvent -FilterHashtable @{{LogName=$log;Id=$ids;StartTime=$start}} -MaxEvents $cap -ErrorAction SilentlyContinue }} catch {{}} }}
$ev=@()
$ev+=Q @(1116,1117,1118) 300
$ev+=Q @(1000,1001,1002,1005) 600
$ev | Where-Object {{ $_ -ne $null }} | ForEach-Object {{
  $d=@{{}}
  try {{ $x=[xml]$_.ToXml(); foreach($n in $x.Event.EventData.Data){{ if($n.Name){{ $d[[string]$n.Name]=[string]$n.'#text' }} }} }} catch {{}}
  [pscustomobject]@{{ Id=[int]$_.Id; Time=$_.TimeCreated.ToString('o'); Msg=(([string]$_.Message -split ""`r?`n"")[0]); Data=$d }}
}} | ConvertTo-Json -Depth 4 -Compress";

            var threats = new List<ThreatDetectionRecord>();
            var scans = new List<ScanHistoryRecord>();

            foreach (var r in RunPowerShellArray(script))
            {
                int id = JInt(r, "Id");
                DateTime time = ParseIso(JStr(r, "Time"));
                string msg = JStr(r, "Msg").Trim();
                JsonElement data = r.TryGetProperty("Data", out var dd) && dd.ValueKind == JsonValueKind.Object
                    ? dd : default;

                if (ThreatEventIds.Contains(id))
                {
                    var t = new ThreatDetectionRecord
                    {
                        Time = time,
                        EventId = id,
                        ThreatName = JData(data, "Threat Name", "ThreatName"),
                        SeverityName = JData(data, "Severity Name", "SeverityName"),
                        Category = JData(data, "Category Name", "CategoryName"),
                        Path = CleanDefenderPath(JData(data, "Path")),
                        Action = JData(data, "Action Name", "ActionName", "Additional Actions String"),
                        Status = id switch { 1117 => "Remediated", 1118 => "Remediation failed", _ => "Detected" },
                        Risk = id == 1118 ? TabSeverity.Alert : TabSeverity.Caution,
                    };
                    if (t.ThreatName.Length == 0) t.ThreatName = msg.Length > 0 ? msg : "(unnamed threat)";
                    threats.Add(t);
                }
                else
                {
                    var sc = new ScanHistoryRecord
                    {
                        Time = time,
                        EventId = id,
                        ScanType = NormalizeScanType(JData(data, "Scan Type Name", "ScanTypeName", "Scan Parameters")),
                        Result = id switch
                        {
                            1000 => "Started", 1001 => "Completed", 1002 => "Canceled", 1005 => "Failed", _ => "Scan",
                        },
                        Risk = id == 1005 ? TabSeverity.Caution : TabSeverity.None,
                    };
                    string user = JData(data, "Domain", "User");
                    string err = JData(data, "Error Description", "Error Code");
                    sc.Detail = id == 1005 && err.Length > 0 ? err : user;
                    if (sc.ScanType.Length == 0) sc.ScanType = "Scan";
                    scans.Add(sc);
                }
            }

            threats.Sort((a, b) => b.Time.CompareTo(a.Time));
            scans.Sort((a, b) => b.Time.CompareTo(a.Time));
            return (threats, scans);
        }

        /// <summary>Threat history (1116/1117/1118), newest first; empty without admin.</summary>
        public static List<ThreatDetectionRecord> GetThreatHistory() => GetDefenderEvents().Threats;

        /// <summary>Scan history (1000/1001/1002/1005), newest first; empty without admin.</summary>
        public static List<ScanHistoryRecord> GetScanHistory() => GetDefenderEvents().Scans;

        /// <summary>The merged threat + scan timeline for the Virus tab grid, newest first.</summary>
        public static List<DefenderTimelineRow> GetDefenderTimeline()
        {
            var (threats, scans) = GetDefenderEvents();
            var rows = new List<DefenderTimelineRow>(threats.Count + scans.Count);

            foreach (var t in threats)
                rows.Add(new DefenderTimelineRow
                {
                    Time = t.Time, Kind = DefenderEventKind.Threat, EventId = t.EventId,
                    Title = t.ThreatName,
                    Result = t.SeverityName.Length > 0 ? $"{t.Status} ({t.SeverityName})" : t.Status,
                    Detail = t.Action.Length > 0 ? $"{t.Action}  -  {t.Path}" : t.Path,
                    Path = t.Path,
                    Category = t.Category,
                    Severity = t.Risk,
                });

            foreach (var sc in scans)
                rows.Add(new DefenderTimelineRow
                {
                    Time = sc.Time, Kind = DefenderEventKind.Scan, EventId = sc.EventId,
                    Title = sc.ScanType, Result = sc.Result, Detail = sc.Detail, Severity = sc.Risk,
                });

            foreach (var row in rows)
            {
                row.TimeSort = row.Time;
                row.TimeText = row.Time == DateTime.MinValue ? "—" : row.Time.ToString("yyyy-MM-dd HH:mm");
            }
            rows.Sort((a, b) => b.TimeSort.CompareTo(a.TimeSort));
            return rows;
        }

        // ----------------------------------------------------------------- //
        // Parsing helpers
        // ----------------------------------------------------------------- //
        private static string JData(JsonElement data, params string[] names)
        {
            if (data.ValueKind != JsonValueKind.Object) return "";
            foreach (var n in names)
                if (data.TryGetProperty(n, out var v) && v.ValueKind == JsonValueKind.String)
                {
                    string s = (v.GetString() ?? "").Trim();
                    if (s.Length > 0) return s;
                }
            return "";
        }

        private static DateTime ParseIso(string iso) =>
            DateTime.TryParse(iso, null, DateTimeStyles.RoundtripKind, out var t)
                ? (t.Kind == DateTimeKind.Utc ? t.ToLocalTime() : t)
                : DateTime.MinValue;

        /// <summary>Maps a Defender scan-type name ("Antimalware quick scan") to a short label.</summary>
        private static string NormalizeScanType(string raw)
        {
            string t = raw.ToLowerInvariant();
            if (t.Contains("quick")) return "Quick";
            if (t.Contains("full")) return "Full";
            if (t.Contains("custom")) return "Custom";
            return raw;
        }

        /// <summary>Strips Defender's resource prefixes ("file:_", "containerfile:_", "process:_")
        /// from a threat path so it reads as a plain filesystem path.</summary>
        private static string CleanDefenderPath(string path)
        {
            foreach (var prefix in new[] { "containerfile:_", "file:_", "process:_", "webfile:_", "amsi:_" })
                if (path.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                    return path.Substring(prefix.Length);
            return path;
        }

        // ----------------------------------------------------------------- //
        // Tab severity (folds protection state into the tab/grid colour)
        // ----------------------------------------------------------------- //
        /// <summary>The worst severity implied by the live protection state: red when antivirus or
        /// real-time protection is off (or status is unreadable), yellow when signatures are stale.</summary>
        public static TabSeverity DefenderStatusSeverity()
        {
            // A registered third-party AV that owns protection (Defender goes passive) is not a
            // problem - so Defender reading "off" is only an alert when nothing else is active.
            bool otherActive = GetSecurityCenterProducts("AntiVirusProduct")
                .Any(p => p.Enabled && !p.IsDefender);

            var s = GetDefenderStatus();
            if (!s.Available) return otherActive ? TabSeverity.None : TabSeverity.Caution;
            if (!s.AntivirusEnabled || !s.RealTimeProtectionEnabled)
                return otherActive ? TabSeverity.None : TabSeverity.Alert;
            if (s.SignatureAgeDays is int d && d > 7) return TabSeverity.Caution;
            return TabSeverity.None;
        }

        // ----------------------------------------------------------------- //
        // Header pane (status lines above the grid) + headless report
        // ----------------------------------------------------------------- //
        /// <summary>The Virus tab's status lines: protection state, signatures, last scans, and a
        /// one-line threat-history roll-up. Also the first section of the --run virus report.</summary>
        public static CheckGroup VirusHeader()
        {
            var g = new CheckGroup("Virus Protection");
            var s = GetDefenderStatus();

            // Authoritative "what is protecting this machine": every product the Windows Security
            // Center recognises as antivirus. A third-party agent (e.g. CrowdStrike Falcon) registers
            // here and puts Microsoft Defender into passive mode - which is exactly why Defender's own
            // WMI status can read "off" on a system that is, in fact, protected.
            // List the alternate (non-Defender) AV products; Defender's own state is reported in
            // detail below, so it would only duplicate to list it here too.
            var others = GetSecurityCenterProducts("AntiVirusProduct").Where(p => !p.IsDefender).ToList();
            var activeOther = others.FirstOrDefault(p => p.Enabled);

            foreach (var p in others)
            {
                string detail = p.Enabled ? "Enabled & active." : "Registered but not active.";
                if (p.UpToDate == false) detail += " Definitions out of date.";
                if (p.Path.Length > 0) detail += $"  {p.Path}";
                g.Add(p.Enabled ? CheckStatus.Pass : CheckStatus.Warn,
                    $"Antivirus product: {p.Name}", detail);
            }
            if (others.Count == 0 && !s.Available)
                g.Add(CheckStatus.Warn, "Antivirus products",
                    "No third-party product registered with Windows Security Center, and Defender status is unavailable.");

            // --- Microsoft Defender's own live engine state (WMI MSFT_MpComputerStatus) ---
            if (!s.Available)
            {
                g.Add(activeOther != null ? CheckStatus.Info : CheckStatus.Warn, "Microsoft Defender",
                    activeOther != null
                        ? $"Status unavailable - \"{activeOther.Name}\" is the active antivirus listed above."
                        : s.Error.Length > 0
                            ? $"Could not read MSFT_MpComputerStatus ({s.Error}). A third-party antivirus may be managing protection."
                            : "Microsoft Defender status is unavailable; a third-party antivirus may be active.");
                return g;
            }

            bool defenderActive = s.AntivirusEnabled && s.RealTimeProtectionEnabled;

            // Defender passive because a third-party product owns protection: report it as Info, not
            // a red failure, and skip Defender's per-feature posture - it would otherwise show
            // misleading "Off"s for an engine that is intentionally standing down.
            if (!defenderActive && activeOther != null)
            {
                g.Add(CheckStatus.Info, "Microsoft Defender",
                    $"Passive - \"{activeOther.Name}\" is the active antivirus.");
            }
            else
            {
                string mode = s.RunningMode.Length > 0 && !s.RunningMode.Equals("Normal", StringComparison.OrdinalIgnoreCase)
                    ? $" (mode: {s.RunningMode})" : "";
                g.Add(s.AntivirusEnabled ? CheckStatus.Pass : CheckStatus.Fail, "Antivirus",
                    (s.AntivirusEnabled ? "Enabled." : "DISABLED.") + mode);
                g.Add(s.RealTimeProtectionEnabled ? CheckStatus.Pass : CheckStatus.Fail, "Real-time protection",
                    s.RealTimeProtectionEnabled ? "On." : "OFF.");

                if (s.BehaviorMonitorEnabled is bool bm)
                    g.Add(bm ? CheckStatus.Pass : CheckStatus.Warn, "Behavior monitoring", bm ? "On." : "Off.");
                if (s.TamperProtected is bool tp)
                    g.Add(tp ? CheckStatus.Pass : CheckStatus.Warn, "Tamper protection", tp ? "On." : "Off.");
                if (s.CloudProtection is bool cp)
                    g.Add(cp ? CheckStatus.Pass : CheckStatus.Info, "Cloud-delivered protection", cp ? "On." : "Off.");

                string ver = s.SignatureVersion.Length > 0 ? "v" + s.SignatureVersion : "version unknown";
                string age = s.SignatureAgeDays is int da ? $"{da} day(s) old" : "age unknown";
                string updated = s.SignatureLastUpdated is DateTime u ? $", updated {u:yyyy-MM-dd HH:mm}" : "";
                g.Add(s.SignatureAgeDays is int d2 && d2 > 7 ? CheckStatus.Warn : CheckStatus.Info,
                    "Signatures", $"{ver}, {age}{updated}.");

                g.Add(ScanStatus(s.QuickScanEnd, 14), "Last quick scan", ScanText(s.QuickScanEnd));
                g.Add(CheckStatus.Info, "Last full scan", ScanText(s.FullScanEnd));
            }

            if (Elevation.IsAdmin)
            {
                var threats = GetThreatHistory();
                int failed = threats.Count(t => t.EventId == 1118);
                if (threats.Count == 0)
                    g.Add(CheckStatus.Pass, "Threat history",
                        $"No threats recorded in the Defender log (last {VirusEventDays} days).");
                else
                    g.Add(failed > 0 ? CheckStatus.Fail : CheckStatus.Warn, "Threat history",
                        $"{threats.Count} threat event(s); {failed} remediation failure(s). See the table below.");
            }
            else
            {
                g.Add(CheckStatus.Info, "Threat & scan history",
                    "Run as Administrator to read the Defender Operational event log (the table below).");
            }

            return g;
        }

        private static CheckStatus ScanStatus(DateTime? end, int warnDays)
        {
            if (end is not DateTime t) return CheckStatus.Warn;     // never scanned (or unreadable)
            return (DateTime.Now - t).TotalDays > warnDays ? CheckStatus.Warn : CheckStatus.Info;
        }

        private static string ScanText(DateTime? end)
        {
            if (end is not DateTime t) return "No record.";
            int days = Math.Max(0, (int)(DateTime.Now - t).TotalDays);
            return $"{t:yyyy-MM-dd HH:mm}  ({days} day(s) ago).";
        }

        /// <summary>Headless / email report producer for the Virus tab: the threat + scan timeline
        /// as a list under the protection-status header (which is emitted separately by
        /// <see cref="VirusHeader"/> in the report catalog).</summary>
        public static CheckGroup CheckVirus()
        {
            var g = new CheckGroup("Defender Threat & Scan History");

            if (!Elevation.IsAdmin)
            {
                g.Add(CheckStatus.Info, "History",
                    "Run as Administrator to read the Defender Operational event log.");
                return g;
            }

            var threats = GetThreatHistory();
            var scans = GetScanHistory();

            if (threats.Count == 0)
                g.Add(CheckStatus.Pass, "Threats", $"No threats in the last {VirusEventDays} days.");
            foreach (var t in threats.Take(MaxList))
                g.Add(t.Risk == TabSeverity.Alert ? CheckStatus.Fail : CheckStatus.Warn,
                    $"{t.Time:yyyy-MM-dd HH:mm}  {t.Status}",
                    $"{t.ThreatName}" + (t.SeverityName.Length > 0 ? $" [{t.SeverityName}]" : "") +
                    (t.Action.Length > 0 ? $"  -  {t.Action}" : "") +
                    (t.Path.Length > 0 ? $"  -  {Truncate(t.Path, 80)}" : ""));

            var lastQuick = scans.FirstOrDefault(x => x.ScanType == "Quick" && x.Result == "Completed");
            var lastFull = scans.FirstOrDefault(x => x.ScanType == "Full" && x.Result == "Completed");
            int failedScans = scans.Count(x => x.Result == "Failed");
            g.Add(failedScans > 0 ? CheckStatus.Warn : CheckStatus.Info, "Scans",
                $"{scans.Count} scan event(s); {failedScans} failed." +
                (lastQuick != null ? $" Last quick: {lastQuick.Time:yyyy-MM-dd HH:mm}." : "") +
                (lastFull != null ? $" Last full: {lastFull.Time:yyyy-MM-dd HH:mm}." : ""));

            return g;
        }
    }
}
