// Copyright (c) 2026 LanDen Labs - Dennis Lang

using System;

namespace B4Browse
{
    /// <summary>Worst state detected on a tab, used to colour its header.</summary>
    public enum TabSeverity { None = 0, Ok = 1, Caution = 2, Alert = 3 }

    /// <summary>Helpers for mapping check results / ages to a tab severity.</summary>
    public static class Sev
    {
        public static TabSeverity FromStatus(CheckStatus s) => s switch
        {
            CheckStatus.Fail => TabSeverity.Alert,
            CheckStatus.Warn => TabSeverity.Caution,
            CheckStatus.Pass => TabSeverity.Ok,
            _ => TabSeverity.None,
        };

        /// <summary>Recency to severity: &lt;7d = Alert, &lt;30d = Caution, older = Ok, unknown = None.</summary>
        public static TabSeverity FromDays(int? days) =>
            days is null ? TabSeverity.None : days < 7 ? TabSeverity.Alert : days < 30 ? TabSeverity.Caution : TabSeverity.Ok;

        public static TabSeverity Max(TabSeverity a, TabSeverity b) => (TabSeverity)Math.Max((int)a, (int)b);
    }
}
