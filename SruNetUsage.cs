// Copyright (c) 2026 LanDen Labs - Dennis Lang

using System;

namespace B4Browse
{
    /// <summary>
    /// One row of the Downloads tab - per-application network usage totalled from the Windows
    /// System Resource Usage Monitor (SRUM) database, C:\Windows\System32\sru\SRUDB.dat. SRUM
    /// records, per app and time interval, the bytes each process sent and received; this row is
    /// the sum of those intervals for one application over SRUM's retention window (~30-60 days).
    /// "Received" is data the app pulled down (its downloads); a high "Sent" by an unexpected
    /// process is a possible data-exfiltration signal.
    /// </summary>
    public sealed class SruNetUsage
    {
        /// <summary>Friendly leaf name (e.g. "chrome.exe") derived from <see cref="AppPath"/>.</summary>
        public string AppName = "";

        /// <summary>The raw application identity from SRUM's id-map (usually a full executable path,
        /// sometimes a service or "!!"-prefixed driver tag).</summary>
        public string AppPath = "";

        public long BytesRecvd;   // downloaded
        public long BytesSent;    // uploaded

        /// <summary>Newest interval timestamp seen for this app (local time); null if unknown.</summary>
        public DateTime? LastSeen;
        public string LastSeenText = "—";   // "yyyy-MM-dd HH:mm" or "—"

        /// <summary>Per-row audit severity (e.g. a networked binary running from a transient folder).</summary>
        public TabSeverity Risk;

        /// <summary>Human-readable reason for the row's status.</summary>
        public string Note = "";
    }
}
