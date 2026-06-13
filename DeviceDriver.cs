// Copyright (c) 2026 LanDen Labs - Dennis Lang

using System;

namespace B4Browse
{
    /// <summary>One row of the Devices tab - a signed PnP driver.</summary>
    public sealed class DeviceDriver
    {
        public string Device = "";
        public string Provider = "";
        public string Version = "";
        public bool Signed;
        public string InfName = "";
        public string InfPath = "";       // full path to the INF in %WINDIR%\INF

        public DateTime? VendorDate;
        public string VendorDateText = "";

        /// <summary>Last-write time of the driver's INF in %WINDIR%\INF (when it changed on disk).</summary>
        public DateTime? LocalChanged;
        public string LocalChangedText = "";
        public DateTime LocalSort;          // MinValue when unknown
        public int? DaysOld;                // since LocalChanged

        /// <summary>Result of parsing this driver's .inf, populated on demand by the
        /// "Scan all INFs" button or the per-row "Analyze INF" action. Null until run.</summary>
        public InfAnalysis? Inf;
    }
}
