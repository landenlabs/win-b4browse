// Copyright (c) 2026 LanDen Labs - Dennis Lang

using System;

namespace B4Browse
{
    /// <summary>One row of the Scheduled tab - a Windows Task Scheduler entry.</summary>
    public sealed class ScheduledTaskItem
    {
        public string Name = "";
        public string TaskPath = "";      // folder, e.g. "\Microsoft\Windows\..."
        public string State = "";         // Ready / Running / Disabled
        public bool Enabled = true;       // State != Disabled
        public string Author = "";
        public string RunAs = "";         // principal UserId (e.g. SYSTEM, a user, an SID)
        public bool Hidden;

        public string Execute = "";       // first exec action's program
        public string Arguments = "";
        public string ExePath = "";       // expanded Execute

        /// <summary>Task registration date (from the task XML), for recency colouring.</summary>
        public DateTime? Created;
        public string CreatedText = "—";

        public DateTime? LastRun;
        public string LastRunText = "—";
        public DateTime? NextRun;
        public string NextRunText = "—";

        /// <summary>Repeat cadence as a short code (e.g. "5M", "1H", "7D", "1.5D"); "—" when the
        /// trigger has no simple minute/hour/day period (weekly/monthly/event/logon/boot).</summary>
        public string RepeatText = "—";
        public double RepeatMinutes;      // the period in minutes, for sorting (0 = none)

        public DateTime StatusSort;       // Created; MinValue when unknown
        public int? DaysOld;              // days since Created, for recency colouring

        /// <summary>Audit verdict (transient-folder / LOLBin / hidden program) and its reason.</summary>
        public TabSeverity Risk = TabSeverity.None;
        public string Note = "";

        /// <summary>Full task identifier "\folder\Name" for display / copy.</summary>
        public string FullName => (TaskPath.EndsWith("\\") ? TaskPath : TaskPath + "\\") + Name;
    }
}
