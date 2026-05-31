// Copyright (c) 2026 LanDen Labs - Dennis Lang

using System;

namespace BrowseSafe
{
    /// <summary>One row of the Installed tab - a registered program.</summary>
    public sealed class InstalledProgram
    {
        public string Name = "";
        public string Version = "";
        public string Publisher = "";
        public string Description = "";
        public string InstallLocation = "";
        public string DisplayIcon = "";

        /// <summary>Best-effort path to the program's main executable (for scanning), or null.</summary>
        public string? ExePath;

        /// <summary>Install (or, as a fallback, exe last-modified) date; null if unknown.</summary>
        public DateTime? InstallDate;

        /// <summary>Sort key for date columns (MinValue when unknown so it sinks to the bottom).</summary>
        public DateTime SortDate;

        /// <summary>Days since <see cref="InstallDate"/>, or null if unknown.</summary>
        public int? DaysOld;

        /// <summary>Display string for the Installed column ("yyyy-MM-dd" or "—").</summary>
        public string InstalledText = "";
    }
}
