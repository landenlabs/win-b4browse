// Copyright (c) 2026 LanDen Labs - Dennis Lang

namespace BrowseSafe
{
    /// <summary>One row of the Firewall tab - a single Windows Firewall rule parsed
    /// from the registry rule store, with the result of the hijack audit.</summary>
    public sealed class FirewallRule
    {
        public string Id = "";            // registry value name (rule GUID/key)
        public string Name = "";          // display name (Name=, or the value name)
        public string Description = "";    // Desc=
        public string Direction = "";      // In / Out
        public string Action = "";         // Allow / Block
        public bool Active;                // Active=TRUE
        public string Protocol = "Any";    // TCP / UDP / ICMPv4 / ... / Any
        public string LocalPort = "Any";   // LPort
        public string RemotePort = "Any";  // RPort
        public string RemoteAddress = "Any"; // RA4/RA6 / RmtAddrKeyword
        public string AppPath = "";        // App= (may contain %env% variables)
        public string Service = "";        // Svc=
        public string Profile = "All";     // Domain / Private / Public (joined) or All
        public string Grouping = "";       // EmbedCtxt=
        public string Source = "Local";    // Local rule store vs. Policy store

        /// <summary>True when the rule is restricted to a specific program, packaged app
        /// (AppPkgId) or service - i.e. not a wide-open "applies to everything" rule.</summary>
        public bool HasAppScope;

        /// <summary>Worst audit condition for this row (drives Status colour + tab severity).</summary>
        public TabSeverity Risk;

        /// <summary>Human-readable reason(s) for the row's status (joined with "; ").</summary>
        public string Note = "";
    }
}
