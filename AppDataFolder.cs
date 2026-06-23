// Copyright (c) 2026 LanDen Labs - Dennis Lang

using System;

namespace B4Browse
{
    /// <summary>One row of the AppData tab - a top-level folder found under one of the three
    /// AppData roots (Local, Roaming, LocalLow) together with its creation date and a
    /// cross-reference against the installed-programs list.</summary>
    public sealed class AppDataFolder
    {
        /// <summary>Root tree the folder lives under: "Local", "Roaming", or "LocalLow".</summary>
        public string Root = "";

        /// <summary>Folder name only (no path), e.g. "Microsoft" or "SuspiciousApp".</summary>
        public string FolderName = "";

        /// <summary>Full absolute path to the folder.</summary>
        public string FolderPath = "";

        /// <summary>Folder creation time as reported by the file system.</summary>
        public DateTime? Created;
        public string CreatedText = "—";

        /// <summary>Days since <see cref="Created"/> (null when creation time is unknown).</summary>
        public int? DaysOld;

        /// <summary>
        /// Name of the best-matching installed program, or empty when no installer entry matches.
        /// An empty value combined with a recent creation date is the primary risk signal.
        /// </summary>
        public string MatchedProgram = "";

        /// <summary>True when <see cref="MatchedProgram"/> is non-empty (folder traces back to a
        /// known installer entry) or the folder name is a well-known Windows/system name.</summary>
        public bool IsKnown;

        /// <summary>Row-level audit severity.</summary>
        public TabSeverity Risk;
    }
}
