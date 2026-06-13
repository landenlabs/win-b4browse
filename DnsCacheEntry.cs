// Copyright (c) 2026 LanDen Labs - Dennis Lang

namespace B4Browse
{
    /// <summary>One row of the DNS tab - an entry in the Windows resolver cache.</summary>
    public sealed class DnsCacheEntry
    {
        public string Entry = "";      // the originally queried name
        public string Name = "";       // the record name (may differ via CNAME chains)
        public int TypeCode;           // numeric DNS record type (1=A, 28=AAAA, 5=CNAME, ...)
        public string TypeText = "";   // friendly record type (A / AAAA / CNAME / ...)
        public int Ttl;                // remaining time-to-live, seconds
        public string Data = "";       // the answer (IP for A/AAAA, target name for CNAME, ...)

        /// <summary>
        /// True when a public-looking host resolves to a non-public (private/loopback) IP -
        /// the same hijack/redirect signal flagged by the Safety Scan's lookup tests.
        /// </summary>
        public bool Suspicious;
    }
}
