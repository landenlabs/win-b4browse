// Copyright (c) 2026 LanDen Labs - Dennis Lang

using System;

namespace B4Browse
{
    /// <summary>One row of the Win Extn tab - a File Explorer shell extension (COM handler).</summary>
    public sealed class ShellExtension
    {
        public string Clsid = "";
        public string Name = "";          // friendly name (CLSID default, else Approved description, else CLSID)
        public string Types = "";         // hook kinds, e.g. "Context menu, Icon overlay"
        public string Targets = "";       // where it hooks, e.g. "All files, Directory"
        public string DllPath = "";       // resolved InprocServer32 path ("" / "(out-of-proc)" when none)
        public string ThreadingModel = "";
        public string Company = "";        // FileVersionInfo CompanyName
        public bool Approved;              // listed in the Shell Extensions Approved key
        public bool IsBuiltin;             // Microsoft / system32 - hidden unless "All" is on

        /// <summary>Authenticode result, filled on demand by "Verify signatures" ("" until then).</summary>
        public string SignStatus = "";

        public DateTime? DllModified;
        public int? DaysOld;

        /// <summary>Worst audit condition for this row (drives Status colour + tab severity).</summary>
        public TabSeverity Risk;

        /// <summary>Human-readable reason for the row's status.</summary>
        public string Note = "";
    }
}
