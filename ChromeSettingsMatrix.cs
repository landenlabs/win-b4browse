// Copyright (c) 2026 LanDen Labs - Dennis Lang

using System.Collections.Generic;

namespace BrowseSafe
{
    /// <summary>
    /// One column of the Settings matrix: either the enterprise-policy "Global" column or a
    /// single Chrome profile. <see cref="Key"/> is a stable identity ("{channel}|{profileDir}",
    /// or "__global__") used to look up cell values; <see cref="Header"/> is the friendly name
    /// shown to the user (disambiguated with the channel only when names collide).
    /// </summary>
    public readonly record struct ColumnDef(string Key, string Header, bool IsGlobal);

    /// <summary>
    /// One row of the Settings matrix - a single Chrome setting and its value in every column.
    /// <see cref="Values"/> and <see cref="Risk"/> are keyed by <see cref="ColumnDef.Key"/>; a
    /// column with no data for this setting is simply absent (rendered "—"). Chrome omits keys
    /// that are at their default, so a value is three-state: an explicit "On"/"Off"/enum text,
    /// or "Default" when the key is unset.
    /// </summary>
    public sealed class SettingRow
    {
        public string Category = "";
        public int CategoryOrder;                 // stable order for category grouping
        public string Label = "";
        public string Link = "";                  // chrome:// deep-link to this setting's page
        public Dictionary<string, string> Values = new(System.StringComparer.Ordinal);
        public Dictionary<string, TabSeverity> Risk = new(System.StringComparer.Ordinal);
    }

    /// <summary>
    /// The whole Settings tab model: the ordered columns (Global first, then one per profile)
    /// and the ordered setting rows, plus the worst per-cell severity rolled up for the tab
    /// header colour. Produced by <see cref="SafetyChecks.GetChromeSettings"/>.
    /// </summary>
    public sealed class ChromeSettingsMatrix
    {
        public List<ColumnDef> Columns = new();
        public List<SettingRow> Rows = new();
        public TabSeverity Severity;
    }
}
