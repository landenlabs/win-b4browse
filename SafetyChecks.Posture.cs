// Copyright (c) 2026 LanDen Labs - Dennis Lang

using System;
using System.Collections.Generic;
using System.Management;
using Microsoft.Win32;

namespace BrowseSafe
{
    /// <summary>
    /// Report producers for the Patches and Firewall tabs. The GUI tabs render their
    /// own grids (see <see cref="TabViews"/>), but the headless report and the
    /// "Email this tab" feature need a <see cref="CheckGroup"/> producer per scope -
    /// these provide it, drawing on the same sources (WMI QuickFixEngineering for
    /// patches, the firewall-policy registry keys for the firewall).
    /// </summary>
    public static partial class SafetyChecks
    {
        private const string FirewallPolicyKey =
            @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy";

        // ----------------------------------------------------------------- //
        // Windows Firewall (registry-backed: per-profile state, rule count, last change)
        // ----------------------------------------------------------------- //
        public static CheckGroup CheckFirewall()
        {
            var group = new CheckGroup("Windows Firewall");

            var profiles = new (string Label, string Key)[]
            {
                ("Domain",  FirewallPolicyKey + @"\DomainProfile"),
                ("Private", FirewallPolicyKey + @"\StandardProfile"),
                ("Public",  FirewallPolicyKey + @"\PublicProfile"),
            };

            int readable = 0, enabled = 0;
            foreach (var (label, key) in profiles)
            {
                int en = ReadHklmDword(key, "EnableFirewall", -1);
                if (en < 0)
                {
                    group.Add(CheckStatus.Info, $"Firewall - {label} profile", "State unreadable.");
                    continue;
                }
                readable++;
                if (en != 0) enabled++;
                group.Add(en != 0 ? CheckStatus.Pass : CheckStatus.Fail,
                    $"Firewall - {label} profile", en != 0 ? "Enabled." : "DISABLED.");
            }

            // Local rule store size. Empty is normal when a third-party product (e.g.
            // CrowdStrike) manages the firewall, so this is informational only.
            try
            {
                using var rulesKey = Registry.LocalMachine.OpenSubKey(FirewallPolicyKey + @"\FirewallRules");
                if (rulesKey != null)
                    group.Add(CheckStatus.Info, "Firewall rules", $"{rulesKey.ValueCount} local rule(s) defined.");
            }
            catch { /* ignore */ }

            DateTime? lastChange = FirewallLastChanged();
            group.Add(CheckStatus.Info, "Last rule change",
                lastChange.HasValue ? lastChange.Value.ToString("yyyy-MM-dd HH:mm") : "Unknown.");

            if (readable == 0)
                group.Add(CheckStatus.Warn, "Firewall verdict", "Could not read firewall state from the registry.");
            else if (enabled == 0)
                group.Add(CheckStatus.Fail, "Firewall verdict", "No firewall profile is enabled.");
            else if (enabled < readable)
                group.Add(CheckStatus.Warn, "Firewall verdict", "One or more firewall profiles are disabled.");
            else
                group.Add(CheckStatus.Pass, "Firewall verdict", "All readable profiles are enabled.");

            return group;
        }

        /// <summary>
        /// Most recent last-write time across the firewall rule store and the policy/profile
        /// keys. FirewallRules can be empty when another product manages the firewall, so the
        /// profile keys are considered too and the newest change wins.
        /// </summary>
        private static DateTime? FirewallLastChanged()
        {
            string[] candidates =
            {
                FirewallPolicyKey + @"\FirewallRules",
                FirewallPolicyKey + @"\RestrictedServices\Configurable\System",
                FirewallPolicyKey + @"\StandardProfile",
                FirewallPolicyKey + @"\PublicProfile",
                FirewallPolicyKey + @"\DomainProfile",
                FirewallPolicyKey,
            };

            DateTime? latest = null;
            foreach (var path in candidates)
            {
                try
                {
                    using var key = Registry.LocalMachine.OpenSubKey(path);
                    if (key == null) continue;
                    DateTime? t = GetKeyLastWriteTime(key);   // RegQueryInfoKey, defined in SafetyChecks.Inventory.cs
                    if (t.HasValue && (latest == null || t.Value > latest.Value)) latest = t;
                }
                catch { /* ignore inaccessible key */ }
            }
            return latest;
        }

        // ----------------------------------------------------------------- //
        // Installed Windows patches (Win32_QuickFixEngineering, most recent first)
        // ----------------------------------------------------------------- //
        public static CheckGroup CheckPatches()
        {
            var group = new CheckGroup("Windows Patches (most recent first)");

            var patches = GetWindowsPatches();
            if (patches.Count == 0)
            {
                group.Add(CheckStatus.Info, "Patches",
                    "No installed updates reported by WMI (Win32_QuickFixEngineering).");
                return group;
            }

            int shown = 0;
            foreach (var p in patches)   // already newest-first
            {
                if (++shown > MaxList) break;
                group.Add(CheckStatus.Info, p.Id,
                    $"{p.Installed:yyyy-MM-dd}  -  {(p.Desc.Length > 0 ? p.Desc : "Update")}" +
                    (p.DaysOld < 14 ? "   (installed in last 14 days)" : ""));
            }
            if (patches.Count > MaxList)
                group.Add(CheckStatus.Info, "...", $"{patches.Count - MaxList} more not shown.");
            group.Add(CheckStatus.Info, "Total patches",
                $"{patches.Count} update(s) installed; newest {patches[0].Installed:yyyy-MM-dd}.");

            return group;
        }

        private static List<(string Id, DateTime Installed, string Desc, int DaysOld)> GetWindowsPatches()
        {
            var list = new List<(string, DateTime, string, int)>();
            try
            {
                using var searcher = new ManagementObjectSearcher(
                    "SELECT HotFixID, Description, InstalledOn FROM Win32_QuickFixEngineering");
                foreach (ManagementObject obj in searcher.Get())
                {
                    string id = obj["HotFixID"]?.ToString() ?? "Unknown";
                    string desc = obj["Description"]?.ToString() ?? "";
                    if (DateTime.TryParse(obj["InstalledOn"]?.ToString(), out var dt))
                    {
                        int days = Math.Max(0, (int)(DateTime.Now - dt).TotalDays);
                        list.Add((id, dt, desc, days));
                    }
                    obj.Dispose();
                }
            }
            catch { /* WMI may be unavailable */ }

            list.Sort((a, b) => b.Item2.CompareTo(a.Item2));   // newest first
            return list;
        }
    }
}
