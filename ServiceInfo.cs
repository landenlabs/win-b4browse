// Copyright (c) 2026 LanDen Labs - Dennis Lang

using System;

namespace B4Browse
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

        // Newly added fields for Option A (UI-first incremental enrichment)
        public string Account = "";       // service StartName / account
        public string Description = "";   // service description from Win32_Service
        public bool IsTransitioning = false; // StartPending / StopPending
        public DateTime? TransitionSince = null; // approximate time when a transition was observed
        public bool IsStuck = false;        // observed stuck state (to be set by background poller)
        public bool IgnoresShutdown = false; // SERVICE_ACCEPT_SHUTDOWN not accepted
        public string Sha256 = "";         // file hash (computed by background inspector)
        public string SignatureStatus = ""; // authenticode/signature status

        /// <summary>Last-write time of the service executable on disk.</summary>
        public DateTime? Modified;
        public string ModifiedText = "—";
        public DateTime ModifiedSort;     // MinValue when unknown
        public int? DaysOld;              // since Modified, for recency colouring
    }
}
