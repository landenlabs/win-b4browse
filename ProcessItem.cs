using System;

namespace BrowseSafe
{
    /// <summary>One row of the Processes tab - a running process.</summary>
    public sealed class ProcessItem
    {
        public string Name = "";
        public int Pid;
        public string ExePath = "";
        public string Company = "";
        public string Version = "";

        /// <summary>Last-write time of the process executable on disk.</summary>
        public DateTime? Modified;
        public string ModifiedText = "—";
        public DateTime ModifiedSort;     // MinValue when unknown
        public int? DaysOld;              // since Modified, for recency colouring
    }
}
