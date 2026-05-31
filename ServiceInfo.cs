// Copyright (c) 2026 LanDen Labs - Dennis Lang

using System;

namespace BrowseSafe
{
    /// <summary>One row of the Services tab - a Windows service.</summary>
    public sealed class ServiceInfo
    {
        public string Name = "";
        public string DisplayName = "";
        public string State = "";
        public string StartMode = "";     // Auto / Manual / Disabled / ...
        public string PathRaw = "";       // full ImagePath incl. arguments
        public string ExePath = "";       // parsed executable path
        public string Dir = "";           // folder containing the executable

        /// <summary>Last-write time of the service executable on disk.</summary>
        public DateTime? Modified;
        public string ModifiedText = "—";
        public DateTime ModifiedSort;     // MinValue when unknown
        public int? DaysOld;              // since Modified, for recency colouring
    }
}
