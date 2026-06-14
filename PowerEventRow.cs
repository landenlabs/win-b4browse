// Copyright (c) 2026 LanDen Labs - Dennis Lang

using System;

namespace B4Browse
{
    /// <summary>
    /// One raw power-state transition from the System event log (boot / wake / sleep / hibernate /
    /// shutdown / unexpected power loss), shown verbatim as a row in the Awake tab. Deliberately NOT
    /// paired into awake/sleep periods: on Modern Standby (S0) machines the 506/507 churn makes
    /// pairing unreliable, so the tab lists every event 1:1 with the log and lets the reader correlate.
    /// </summary>
    public sealed class PowerEventRow
    {
        public int Index;                 // chronological number (1 = oldest in window)

        public DateTime Time;
        public string TimeText = "";      // "Sun 14-Jun 8:33:49am"

        public string Action = "";        // Boot / Wake / Sleep / Hibernate / Shutdown / Unexpected …
        public string Detail = "";        // wake source / shutdown reason (blank for most events)

        public int EventId;               // raw System-log event id (for correlating with power-events.ps1)

        // Charging state captured in the event itself (Modern Standby 506/507 carry it). Blank for
        // events that don't record power state (classic sleep 42, resume 107, boot/shutdown).
        public string PowerText = "";     // "AC 100%" / "Batt 87%" / "73%"
        public int BatteryPct = -1;       // for sorting the Power column; -1 when unknown

        public double GapMin;             // minutes since the previous event (time spent in the prior state); -1 if none
        public string GapText = "";       // "1h 30m" / "3.2 min" / "—"

        public bool Unexpected;           // dirty power-off: EventLog 6008 / Kernel-Power 41
        public TabSeverity Risk = TabSeverity.Ok;   // Caution for unexpected, else Ok
    }
}
