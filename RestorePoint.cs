// Copyright (c) 2026 LanDen Labs - Dennis Lang

using System;

namespace B4Browse
{
    /// <summary>One row of the Restores tab - a Windows System Restore point.</summary>
    public sealed class RestorePoint
    {
        public int Sequence;
        public string Description = "";
        public int TypeCode;
        public string TypeText = "";       // friendly RestorePointType (App install / Driver install / ...)
        public DateTime? Created;
        public string CreatedText = "";    // "yyyy-MM-dd HH:mm" or "—"
        public int? DaysOld;

        /// <summary>Per-row audit severity (e.g. a recent install-triggered checkpoint).</summary>
        public TabSeverity Risk;

        /// <summary>Human-readable reason for the row's status.</summary>
        public string Note = "";
    }
}
