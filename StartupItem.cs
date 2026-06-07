// Copyright (c) 2026 LanDen Labs - Dennis Lang

using System;

namespace BrowseSafe
{
    /// <summary>One row of the Startup tab - a login auto-run entry.</summary>
    public sealed class StartupItem
    {
        public string Name = "";
        public string Command = "";       // raw value / shortcut path
        public string ExePath = "";       // resolved executable
        public string Dir = "";
        public string Location = "";      // e.g. "HKCU\Run", "Startup (user)"
        public string Source = "";        // Registry / Folder

        /// <summary>Whether the entry is enabled (false = disabled in Task Manager / Settings,
        /// tracked in the Explorer\StartupApproved registry keys). Defaults to enabled.</summary>
        public bool Enabled = true;
        public string EnabledText = "Enabled";

        /// <summary>When the entry was added/changed: registry key last-write, or shortcut file time.</summary>
        public DateTime? RegistryAdded;
        public string RegistryAddedText = "—";

        /// <summary>Last-write time of the target executable.</summary>
        public DateTime? ExeModified;
        public string ExeModifiedText = "—";

        public DateTime StatusSort;       // most-recent of the two dates; MinValue when unknown
        public int? DaysOld;              // since StatusSort, for recency colouring
    }
}
