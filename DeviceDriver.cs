using System;

namespace BrowseSafe
{
    /// <summary>One row of the Devices tab - a signed PnP driver.</summary>
    public sealed class DeviceDriver
    {
        public string Device = "";
        public string Provider = "";
        public string Version = "";
        public bool Signed;
        public string InfName = "";

        public DateTime? VendorDate;
        public string VendorDateText = "";

        /// <summary>Last-write time of the driver's INF in %WINDIR%\INF (when it changed on disk).</summary>
        public DateTime? LocalChanged;
        public string LocalChangedText = "";
        public DateTime LocalSort;          // MinValue when unknown
        public int? DaysOld;                // since LocalChanged
    }
}
