// Copyright (c) 2026 LanDen Labs - Dennis Lang

using System;
using System.Text.Json.Serialization;

namespace B4Browse
{
    /// <summary>
    /// One point-in-time snapshot of system counts, persisted to history.json and
    /// displayed as a row in the History tab. Integer fields use -1 to mean "not
    /// collected / unavailable". Delta fields are computed at load time (not stored).
    /// </summary>
    public sealed class HistorySnapshot
    {
        [JsonPropertyName("ts")]
        public DateTime Timestamp { get; set; }

        // ---- AppData ----
        [JsonPropertyName("adLocal")]    public int AppDataLocal    { get; set; } = -1;
        [JsonPropertyName("adRoaming")]  public int AppDataRoaming  { get; set; } = -1;
        [JsonPropertyName("adLow")]      public int AppDataLocalLow { get; set; } = -1;

        // ---- System ----
        [JsonPropertyName("services")]   public int ServicesEnabled { get; set; } = -1;
        [JsonPropertyName("installed")]  public int AppsInstalled   { get; set; } = -1;
        [JsonPropertyName("startup")]    public int StartupEnabled  { get; set; } = -1;
        [JsonPropertyName("rootCerts")]  public int RootCerts       { get; set; } = -1;
        [JsonPropertyName("scheduled")]  public int ScheduledTasks  { get; set; } = -1;
        [JsonPropertyName("shellExt")]   public int ShellExtensions { get; set; } = -1;
        [JsonPropertyName("chromeExt")]  public int ChromeExtensions{ get; set; } = -1;
        [JsonPropertyName("users")]      public int UserAccounts    { get; set; } = -1;
        [JsonPropertyName("restores")]   public int RestorePoints   { get; set; } = -1;
        [JsonPropertyName("devices")]    public int Devices         { get; set; } = -1;
        [JsonPropertyName("firewall")]   public int FirewallRules   { get; set; } = -1;

        // ---- Runtime-only deltas (not serialised) ----
        // int.MinValue = no previous row to compare against.
        [JsonIgnore] public int DeltaAppDataLocal    = int.MinValue;
        [JsonIgnore] public int DeltaAppDataRoaming  = int.MinValue;
        [JsonIgnore] public int DeltaAppDataLocalLow = int.MinValue;
        [JsonIgnore] public int DeltaServicesEnabled = int.MinValue;
        [JsonIgnore] public int DeltaAppsInstalled   = int.MinValue;
        [JsonIgnore] public int DeltaStartupEnabled  = int.MinValue;
        [JsonIgnore] public int DeltaRootCerts       = int.MinValue;
        [JsonIgnore] public int DeltaScheduledTasks  = int.MinValue;
        [JsonIgnore] public int DeltaShellExtensions = int.MinValue;
        [JsonIgnore] public int DeltaChromeExtensions= int.MinValue;
        [JsonIgnore] public int DeltaUserAccounts    = int.MinValue;
        [JsonIgnore] public int DeltaRestorePoints   = int.MinValue;
        [JsonIgnore] public int DeltaDevices         = int.MinValue;
        [JsonIgnore] public int DeltaFirewallRules   = int.MinValue;

        /// <summary>Compute deltas relative to a previous snapshot.</summary>
        public void ComputeDeltas(HistorySnapshot prev)
        {
            DeltaAppDataLocal    = Delta(AppDataLocal,    prev.AppDataLocal);
            DeltaAppDataRoaming  = Delta(AppDataRoaming,  prev.AppDataRoaming);
            DeltaAppDataLocalLow = Delta(AppDataLocalLow, prev.AppDataLocalLow);
            DeltaServicesEnabled = Delta(ServicesEnabled, prev.ServicesEnabled);
            DeltaAppsInstalled   = Delta(AppsInstalled,   prev.AppsInstalled);
            DeltaStartupEnabled  = Delta(StartupEnabled,  prev.StartupEnabled);
            DeltaRootCerts       = Delta(RootCerts,       prev.RootCerts);
            DeltaScheduledTasks  = Delta(ScheduledTasks,  prev.ScheduledTasks);
            DeltaShellExtensions = Delta(ShellExtensions, prev.ShellExtensions);
            DeltaChromeExtensions= Delta(ChromeExtensions,prev.ChromeExtensions);
            DeltaUserAccounts    = Delta(UserAccounts,    prev.UserAccounts);
            DeltaRestorePoints   = Delta(RestorePoints,   prev.RestorePoints);
            DeltaDevices         = Delta(Devices,         prev.Devices);
            DeltaFirewallRules   = Delta(FirewallRules,   prev.FirewallRules);
        }

        private static int Delta(int current, int previous)
            => (current < 0 || previous < 0) ? int.MinValue : current - previous;
    }
}
