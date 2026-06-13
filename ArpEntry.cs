// Copyright (c) 2026 LanDen Labs - Dennis Lang

namespace B4Browse
{
    /// <summary>One row of the ARP tab - a neighbor entry in the local IPv4 ARP cache.</summary>
    public sealed class ArpEntry
    {
        public string Ip = "";            // IPv4 address
        public string Mac = "";           // normalized AA-BB-CC-DD-EE-FF (or "" when incomplete)
        public string Oui = "";           // first 3 MAC bytes, AA-BB-CC
        public string State = "";         // Reachable / Stale / Delay / Probe / Permanent / Incomplete / Unreachable
        public bool IsStatic;             // State == Permanent (manually pinned via arp -s / New-NetNeighbor)
        public string Interface = "";     // InterfaceAlias
        public int InterfaceIndex;
        public bool IsGateway;            // this IP is the default IPv4 gateway
        public string Vendor = "";        // OUI vendor name, filled on demand (online lookup)

        /// <summary>Worst safety condition detected for this row (drives Status colour + tab severity).</summary>
        public TabSeverity Risk;

        /// <summary>Human-readable reason for the row's status (e.g. spoofing/shared-MAC note).</summary>
        public string Note = "";

        /// <summary>Multicast/broadcast/unspecified/incomplete rows - hidden unless "Show all" is on.</summary>
        public bool IsNoise;
    }
}
