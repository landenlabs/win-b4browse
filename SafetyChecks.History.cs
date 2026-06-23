// Copyright (c) 2026 LanDen Labs - Dennis Lang

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Management;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Win32;

namespace B4Browse
{
    /// <summary>
    /// Lightweight system-count collectors used by the History tab. Each method returns
    /// a plain integer so the snapshot stays cheap. -1 means "unavailable / error".
    /// All methods are safe to call from a background thread.
    /// </summary>
    public static partial class SafetyChecks
    {
        // ------------------------------------------------------------------ //
        // Public entry points
        // ------------------------------------------------------------------ //

        /// <summary>
        /// Collects a full snapshot on the calling (background) thread. Fast metrics run
        /// inline; the two slow WMI calls (Devices, Firewall) run in parallel so the
        /// overall wall-clock cost is dominated by the slowest single call.
        /// </summary>
        public static HistorySnapshot CollectSnapshot()
        {
            var snap = new HistorySnapshot { Timestamp = DateTime.Now };

            // ---- Fast / in-process ----
            snap.AppDataLocal    = CountDirs(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData));
            snap.AppDataRoaming  = CountDirs(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData));
            snap.AppDataLocalLow = CountDirs(Path.Combine(
                Path.GetDirectoryName(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData)) ?? "",
                "LocalLow"));
            snap.RootCerts       = CountRootCertificates();
            snap.ShellExtensions = CountShellExtensionsApproved();
            snap.FirewallRules   = CountFirewallRulesRegistry();

            // ---- Moderate ----
            snap.AppsInstalled   = CountInstalledRegistry();
            snap.StartupEnabled  = CountStartupEnabled();
            snap.ServicesEnabled = CountServicesEnabled();
            snap.UserAccounts    = CountUserProfiles();
            snap.ChromeExtensions= CountChromeExtensions();
            snap.RestorePoints   = CountRestorePoints();

            // ---- Slower (WMI round-trip) ----
            snap.ScheduledTasks  = CountScheduledTasksWmi();
            snap.Devices         = CountDevicesWmi();

            return snap;
        }

        /// <summary>Headless producer: summarises the last few history entries as a CheckGroup.</summary>
        public static CheckGroup CheckHistory()
        {
            var group = new CheckGroup("Run history");
            var list = HistoryStore.LoadWithDeltas();

            if (list.Count == 0)
            {
                group.Add(CheckStatus.Info, "History", "No snapshots recorded yet — launch the app to collect the first one.");
                return group;
            }

            var latest = list[^1];
            group.Add(CheckStatus.Info, "Snapshots stored", $"{list.Count} (max 100)");
            group.Add(CheckStatus.Info, "Latest snapshot",  latest.Timestamp.ToString("yyyy-MM-dd HH:mm"));

            // Flag any count that changed between the two most-recent snapshots.
            if (list.Count >= 2)
            {
                ReportDelta(group, "AppData Local",    latest.AppDataLocal,    latest.DeltaAppDataLocal);
                ReportDelta(group, "AppData Roaming",  latest.AppDataRoaming,  latest.DeltaAppDataRoaming);
                ReportDelta(group, "AppData LocalLow", latest.AppDataLocalLow, latest.DeltaAppDataLocalLow);
                ReportDelta(group, "Services enabled", latest.ServicesEnabled, latest.DeltaServicesEnabled);
                ReportDelta(group, "Apps installed",   latest.AppsInstalled,   latest.DeltaAppsInstalled);
                ReportDelta(group, "Startup enabled",  latest.StartupEnabled,  latest.DeltaStartupEnabled);
                ReportDelta(group, "Root CAs",         latest.RootCerts,       latest.DeltaRootCerts);
                ReportDelta(group, "Scheduled tasks",  latest.ScheduledTasks,  latest.DeltaScheduledTasks);
                ReportDelta(group, "Shell extensions", latest.ShellExtensions, latest.DeltaShellExtensions);
                ReportDelta(group, "Chrome extensions",latest.ChromeExtensions,latest.DeltaChromeExtensions);
                ReportDelta(group, "User accounts",    latest.UserAccounts,    latest.DeltaUserAccounts);
                ReportDelta(group, "Restore points",   latest.RestorePoints,   latest.DeltaRestorePoints);
                ReportDelta(group, "Devices",          latest.Devices,         latest.DeltaDevices);
                ReportDelta(group, "Firewall rules",   latest.FirewallRules,   latest.DeltaFirewallRules);
            }

            return group;
        }

        private static void ReportDelta(CheckGroup group, string label, int current, int delta)
        {
            if (current < 0) return;
            string val = current.ToString();
            if (delta == int.MinValue || delta == 0)
                group.Add(CheckStatus.Info, label, val);
            else
                group.Add(CheckStatus.Warn, label, $"{val}  (changed by {(delta > 0 ? "+" : "")}{delta} since last snapshot)");
        }

        // ------------------------------------------------------------------ //
        // Count helpers
        // ------------------------------------------------------------------ //

        private static int CountDirs(string path)
        {
            try { return Directory.Exists(path) ? Directory.GetDirectories(path).Length : 0; }
            catch { return -1; }
        }

        private static int CountRootCertificates()
        {
            try
            {
                using var store = new X509Store(StoreName.Root, StoreLocation.LocalMachine);
                store.Open(OpenFlags.ReadOnly);
                return store.Certificates.Count;
            }
            catch { return -1; }
        }

        /// <summary>Counts keys in the Approved shell-extensions list (fast registry read).</summary>
        private static int CountShellExtensionsApproved()
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(
                    @"SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved");
                return key?.GetValueNames().Length ?? 0;
            }
            catch { return -1; }
        }

        /// <summary>Counts firewall rules via the registry (much faster than Get-NetFirewallRule).</summary>
        private static int CountFirewallRulesRegistry()
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(
                    @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules");
                return key?.GetValueNames().Length ?? 0;
            }
            catch { return -1; }
        }

        /// <summary>Counts installed programs from the Uninstall registry keys (no PowerShell).</summary>
        private static int CountInstalledRegistry()
        {
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            string[] hklmPaths =
            {
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
                @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
            };
            foreach (var path in hklmPaths)
                CountUninstallKeys(Registry.LocalMachine, path, seen);
            CountUninstallKeys(Registry.CurrentUser,
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", seen);
            return seen.Count > 0 ? seen.Count : -1;
        }

        private static void CountUninstallKeys(RegistryKey hive, string path, HashSet<string> seen)
        {
            try
            {
                using var key = hive.OpenSubKey(path);
                if (key == null) return;
                foreach (string sub in key.GetSubKeyNames())
                {
                    using var sk = key.OpenSubKey(sub);
                    if (sk?.GetValue("DisplayName") is string name && name.Length > 0)
                        seen.Add(name);
                }
            }
            catch { }
        }

        /// <summary>Counts enabled startup entries from the registry Run keys and startup folders.</summary>
        private static int CountStartupEnabled()
        {
            int count = 0;

            // Registry Run keys
            string[] runPaths =
            {
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
            };
            foreach (var path in runPaths)
            {
                try
                {
                    using var key = Registry.LocalMachine.OpenSubKey(path);
                    count += key?.GetValueNames().Length ?? 0;
                }
                catch { }
            }
            try
            {
                using var key = Registry.CurrentUser.OpenSubKey(
                    @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run");
                count += key?.GetValueNames().Length ?? 0;
            }
            catch { }

            // Startup folders
            try
            {
                string userStart = Environment.GetFolderPath(Environment.SpecialFolder.Startup);
                if (Directory.Exists(userStart))
                    count += Directory.GetFiles(userStart, "*.lnk").Length;
            }
            catch { }
            try
            {
                string allStart = Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup);
                if (Directory.Exists(allStart))
                    count += Directory.GetFiles(allStart, "*.lnk").Length;
            }
            catch { }

            return count;
        }

        /// <summary>Counts non-disabled Windows services via WMI.</summary>
        private static int CountServicesEnabled()
        {
            try
            {
                using var searcher = new ManagementObjectSearcher(
                    "SELECT Name FROM Win32_Service WHERE StartMode <> 'Disabled'");
                return searcher.Get().Count;
            }
            catch { return -1; }
        }

        /// <summary>Counts local user profiles from the registry ProfileList.</summary>
        private static int CountUserProfiles()
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(
                    @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList");
                if (key == null) return -1;
                // Count only real user SIDs (S-1-5-21-*), not system accounts.
                return key.GetSubKeyNames()
                    .Count(n => n.StartsWith("S-1-5-21-", StringComparison.Ordinal));
            }
            catch { return -1; }
        }

        /// <summary>Counts Chrome extensions across all profiles (fast directory scan).</summary>
        private static int CountChromeExtensions()
        {
            try
            {
                string chromeData = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                    "Google", "Chrome", "User Data");
                if (!Directory.Exists(chromeData)) return 0;

                int total = 0;
                foreach (string profile in Directory.GetDirectories(chromeData))
                {
                    string ext = Path.Combine(profile, "Extensions");
                    if (!Directory.Exists(ext)) continue;
                    // Each extension is a 32-char lowercase alpha CLSID-like subdirectory.
                    total += Directory.GetDirectories(ext)
                        .Count(d => Path.GetFileName(d).Length == 32);
                }
                return total;
            }
            catch { return -1; }
        }

        /// <summary>Counts VSS shadow copies (restore points) via WMI.</summary>
        private static int CountRestorePoints()
        {
            try
            {
                using var searcher = new ManagementObjectSearcher("SELECT ID FROM Win32_ShadowCopy");
                return searcher.Get().Count;
            }
            catch { return -1; }
        }

        /// <summary>Counts scheduled tasks via WMI (moderate speed, ~1-3 s).</summary>
        private static int CountScheduledTasksWmi()
        {
            try
            {
                // Use the Task Scheduler WMI provider namespace.
                var scope = new ManagementScope(@"root\Microsoft\Windows\TaskScheduler");
                scope.Connect();
                using var searcher = new ManagementObjectSearcher(scope,
                    new SelectQuery("MSFT_ScheduledTask", ""));
                return searcher.Get().Count;
            }
            catch { return -1; }
        }

        /// <summary>Counts signed PnP device drivers via WMI (can be slow, ~5-15 s).</summary>
        private static int CountDevicesWmi()
        {
            try
            {
                using var searcher = new ManagementObjectSearcher(
                    "SELECT DeviceID FROM Win32_PnPSignedDriver WHERE DeviceName IS NOT NULL");
                return searcher.Get().Count;
            }
            catch { return -1; }
        }
    }
}
