// Copyright (c) 2026 LanDen Labs - Dennis Lang

using System;

namespace B4Browse
{
    /// <summary>
    /// Microsoft Defender's system-wide protection state and database/scan status, read from WMI
    /// (<c>root\Microsoft\Windows\Defender:MSFT_MpComputerStatus</c>, plus a best-effort
    /// <c>MSFT_MpPreference</c> read for cloud protection). Surfaced in the Virus tab's status
    /// lines. <see cref="Available"/> is false (with <see cref="Error"/> set) when the namespace
    /// can't be read - e.g. a third-party antivirus has taken over and Defender is dormant.
    /// </summary>
    public sealed class DefenderStatusSummary
    {
        public bool Available;
        public string Error = "";

        public bool AntivirusEnabled;
        public bool RealTimeProtectionEnabled;
        public bool? BehaviorMonitorEnabled;
        public bool? TamperProtected;
        public bool? OnAccessProtectionEnabled;
        public bool? NisEnabled;              // network inspection
        public bool? CloudProtection;         // MAPSReporting != 0 (from MpPreference)

        public string SignatureVersion = "";
        public DateTime? SignatureLastUpdated;
        public int? SignatureAgeDays;

        public DateTime? QuickScanEnd;
        public DateTime? FullScanEnd;

        public string ProductVersion = "";
        public string EngineVersion = "";
        public string RunningMode = "";       // Normal / Passive / EDR Block / SxS Passive
    }

    /// <summary>One Defender threat-history entry, parsed from the Defender Operational event log
    /// (event 1116 detected, 1117 remediation succeeded, 1118 remediation failed).</summary>
    public sealed class ThreatDetectionRecord
    {
        public DateTime Time;
        public int EventId;                   // 1116 / 1117 / 1118
        public string ThreatName = "";
        public string SeverityName = "";      // Low / Moderate / High / Severe
        public string Category = "";
        public string Path = "";              // resource path where the file was found
        public string Action = "";            // remediation action (Quarantine / Remove / Allow / ...)
        public string Status = "";            // derived: Detected / Remediated / Remediation failed
        public TabSeverity Risk;
    }

    /// <summary>One Defender scan-history entry, parsed from the Defender Operational event log
    /// (event 1000 started, 1001 completed, 1002 canceled, 1005 failed).</summary>
    public sealed class ScanHistoryRecord
    {
        public DateTime Time;
        public int EventId;                   // 1000 / 1001 / 1002 / 1005
        public string ScanType = "";          // Quick / Full / Custom (or the raw name)
        public string Result = "";            // Started / Completed / Canceled / Failed
        public string Detail = "";            // user/domain, or the error description for a failure
        public TabSeverity Risk;
    }

    /// <summary>What kind of Defender event a <see cref="DefenderTimelineRow"/> is.</summary>
    public enum DefenderEventKind { Threat, Scan }

    /// <summary>
    /// A unified row for the Virus tab's merged threat + scan timeline grid - a flat projection of a
    /// <see cref="ThreatDetectionRecord"/> or <see cref="ScanHistoryRecord"/> so both kinds can share
    /// one sortable grid. <see cref="Severity"/> drives the row colour and the tab header colour.
    /// </summary>
    public sealed class DefenderTimelineRow
    {
        public DateTime Time;
        public string TimeText = "—";
        public DateTime TimeSort;             // MinValue when unknown

        public DefenderEventKind Kind;
        public string KindText => Kind == DefenderEventKind.Threat ? "Threat" : "Scan";

        public int EventId;
        public string Title = "";             // threat name, or scan type
        public string Result = "";            // Detected / Remediated / Completed / Failed / ...
        public string Detail = "";            // threat path, or scan user / error
        public string Path = "";              // clean threat file path (threats only), for the menu
        public string Category = "";          // threat category (Trojan / PUA / ...) - threats only, for the details view
        public TabSeverity Severity;
    }
}
