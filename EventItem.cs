// Copyright (c) 2026 LanDen Labs - Dennis Lang

using System;

namespace B4Browse
{
    /// <summary>One row of the Events tab - a recent Windows Event Log entry.</summary>
    public sealed class EventItem
    {
        public DateTime Time;
        public string TimeText = "—";
        public DateTime TimeSort;        // MinValue when unknown

        public int EventId;
        public string Level = "";        // Critical / Error / Warning / Information
        public string Source = "";       // provider name
        public string Channel = "";      // log / channel name
        public string Message = "";      // first line of the event message

        /// <summary>True for security-significant events (Defender/Firewall changes, new
        /// service, audit-log cleared, account/group changes) that warrant attention
        /// regardless of their numeric level.</summary>
        public bool Significant;
    }
}
