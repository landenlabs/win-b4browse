// Copyright (c) 2026 LanDen Labs - Dennis Lang

using System;

namespace B4Browse
{
    /// <summary>One row of the Chrome Extensions tab.</summary>
    public sealed class ChromeExtension
    {
        public string ProfileDir = "";
        public string ProfileId = "";
        public string ProfileName = "";   // friendly name, falls back to ProfileDir
        public string Name = "";
        public string Version = "";
        public string Description = "";
        public string Id = "";
        public int? ManifestVersion;      // 2 or 3, null if unknown
        public bool Enabled = true;
        public bool Unsupported;          // manifest_version below this Chrome's minimum

        /// <summary>Last-write time of the extension's installed version folder on disk.</summary>
        public DateTime? Modified;
        public string ModifiedText = "—";
        public DateTime ModifiedSort;     // MinValue when unknown
        public int? DaysOld;              // days since Modified, for recency colouring
    }
}
