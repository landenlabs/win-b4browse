// Copyright (c) 2026 LanDen Labs - Dennis Lang

using System;

namespace BrowseSafe
{
    /// <summary>
    /// One reconstructed "awake" interval - from a boot/wake to the next sleep/shutdown -
    /// derived from System power events. Shown as a row in the Awake tab.
    /// </summary>
    public sealed class AwakePeriod
    {
        public int Index;                 // chronological number (1 = oldest in window)

        public DateTime Start;
        public string StartText = "";     // "6-Jun 11:23am"

        public DateTime EndSort;          // for sorting the End column (now for current, Start when unknown)
        public string EndText = "";       // "6-Jun 3:14pm (off)" / "now (on)" / "? (pwr)"
        public string EndCode = "";       // off / slp / pwr / on

        public double DurationMin;        // -1 when unknown
        public string DurationText = "";  // "45.0 min" / "3h 51m" / "—"

        public string Why = "";           // what started the period (User / Scheduler: <task> / Device / Power on …)

        public bool Unexpected;           // ended with no clean sleep/shutdown (crash / power loss)
        public bool Current;              // the ongoing session (still awake)
    }
}
