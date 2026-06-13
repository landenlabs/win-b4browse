// Copyright (c) 2026 LanDen Labs - Dennis Lang

namespace B4Browse
{
    /// <summary>
    /// One row of the Activity tab - an app and how often it has been launched, read from
    /// Windows Search's app-usage index (AppsIndex.db, the <c>tiles</c> table). There are no
    /// timestamps in that database, so this is a frequency / behaviour signal, not a timeline.
    /// </summary>
    public sealed class AppActivity
    {
        /// <summary>Raw index id, e.g. "W~Chrome" or "P~Microsoft.ScreenSketch_8wekyb…". The
        /// "W~" / "P~" prefix is what <see cref="Kind"/> is derived from.</summary>
        public string SerializedId = "";

        /// <summary>App identifier: a file path for most Win32 apps (sometimes prefixed with a
        /// Known-Folder GUID), or an AUMID / package family name for packaged apps.</summary>
        public string AppId = "";

        public string DisplayName = "";
        public long LaunchCount;

        /// <summary>Windows Search's internal relevance rank for the tile (lower = more prominent).</summary>
        public long CRank;

        /// <summary>"Win32" (W~ prefix) or "Packaged" (P~ prefix); "Other" otherwise.</summary>
        public string Kind = "";

        /// <summary>The fully expanded executable path when <see cref="AppId"/> resolves to a real
        /// file on disk (Known-Folder GUIDs expanded); empty when the appId is only an identifier.</summary>
        public string ResolvedPath = "";

        /// <summary>Last time the executable ran, merged by path from the Program Compatibility
        /// Assistant launch log (C:\Windows\appcompat\pca\PcaAppLaunchDic.txt). Null when no match
        /// is found or the log can't be read (it needs administrator rights). The app-index database
        /// itself stores no timestamps, so this is the only "when" signal available.</summary>
        public DateTime? LastExecuted;
        public string LastExecutedText = "—";   // "yyyy-MM-dd HH:mm" or "—"

        /// <summary>True for a row synthesized purely from the PCA launch log: the executable has a
        /// recorded last-run time but Windows Search's app-usage index never tracked it, so there is
        /// no launch count, <see cref="Kind"/>, or <see cref="CRank"/>. Such rows show a launch count
        /// of 1 and "--" for the Type / Rank columns.</summary>
        public bool IsLastRunOnly;

        /// <summary>True for a row sourced from the UserAssist registry (the Windows 10 fallback,
        /// used when Windows 11's app-usage index is absent). Such rows carry a real run count and
        /// last-execution time but no Windows Search relevance rank, so the Rank column reads "--".</summary>
        public bool IsUserAssist;

        /// <summary>Rank column text: the index relevance rank, or "--" for a PCA-only / UserAssist
        /// row that the app-usage index never ranked.</summary>
        public string RankText => IsLastRunOnly || IsUserAssist ? "--" : CRank.ToString();

        /// <summary>Per-row audit severity (e.g. a launched binary that lives in a transient folder).</summary>
        public TabSeverity Risk;

        /// <summary>Human-readable reason for the row's status.</summary>
        public string Note = "";
    }
}
