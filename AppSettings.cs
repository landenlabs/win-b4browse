// Copyright (c) 2026 LanDen Labs - Dennis Lang

namespace B4Browse
{
    /// <summary>Runtime user preferences. Defaults match the original out-of-box behaviour.</summary>
    public static class AppSettings
    {
        /// <summary>
        /// When true, each panel runs its checks automatically the first time it is opened.
        /// When false, the user must click the Run/Refresh button manually.
        /// </summary>
        public static bool AutoLoad { get; set; } = true;
    }
}
