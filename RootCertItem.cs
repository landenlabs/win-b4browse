// Copyright (c) 2026 LanDen Labs - Dennis Lang

using System;

namespace BrowseSafe
{
    /// <summary>One row of the Root CAs tab - a certificate in a trusted-root store.</summary>
    public sealed class RootCertItem
    {
        public TabSeverity Severity = TabSeverity.None;
        public string StatusLabel = "Public CA";   // Public CA / System/Local / Review / Intercept

        public string Store = "";                   // LocalMachine / CurrentUser
        public string Subject = "";                 // display CN/O of the subject
        public string Issuer = "";                  // display CN/O of the issuer
        public string SubjectFull = "";             // full distinguished name (for menus)

        public DateTime NotBefore;
        public DateTime NotAfter;
        public string ExpiresText = "";

        public string Thumbprint = "";
        public string Sig = "";                     // signature algorithm
        public string Note = "";                    // why it is flagged / what it is

        /// <summary>True for well-known public CAs, Microsoft, and benign system/local roots -
        /// the routine entries hidden when the "All" toggle is off.</summary>
        public bool Expected;

        public DateTime AddedSort;                  // NotBefore, used as a recency proxy for sorting
    }
}
