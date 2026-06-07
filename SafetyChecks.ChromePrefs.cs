// Copyright (c) 2026 LanDen Labs - Dennis Lang

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using Microsoft.Win32;

namespace BrowseSafe
{
    /// <summary>
    /// Chrome privacy &amp; security settings audit (shown in the Chrome tab header). Reads each
    /// profile's Preferences JSON for Safe Browsing, third-party-cookie blocking, and clear-on-exit,
    /// and the enterprise policy registry to report whether the hardening is enforced. Configuration
    /// only - no cookie values or other sensitive data are read.
    /// </summary>
    public static partial class SafetyChecks
    {
        private sealed class ProfilePrivacy
        {
            public string Profile = "";
            public int? CookieControls;        // 0 allow / 1 incognito / 2 block
            public int? CookiesContent;        // 1 keep / 4 clear-on-exit
            public bool? SafeBrowsing;         // null = unset (Chrome default = on)
            public bool? SafeBrowsingEnhanced;
        }

        private static List<ProfilePrivacy> GetChromePrivacy()
        {
            var list = new List<ProfilePrivacy>();
            string local = Environment.GetEnvironmentVariable("LOCALAPPDATA") ?? "";
            if (local.Length == 0) return list;

            string[] roots =
            {
                Path.Combine(local, "Google", "Chrome", "User Data"),
                Path.Combine(local, "Google", "Chrome Beta", "User Data"),
                Path.Combine(local, "Google", "Chrome SxS", "User Data"),
                Path.Combine(local, "Chromium", "User Data"),
            };

            foreach (var root in roots)
            {
                if (!Directory.Exists(root)) continue;
                var names = LoadProfileNames(root);

                foreach (var profileDir in SafeDirs(root))
                {
                    string profile = Path.GetFileName(profileDir);
                    if (!(profile == "Default" || profile.StartsWith("Profile", StringComparison.OrdinalIgnoreCase)))
                        continue;

                    string prefs = Path.Combine(profileDir, "Preferences");
                    if (!File.Exists(prefs)) continue;

                    try
                    {
                        using var doc = JsonDocument.Parse(File.ReadAllText(prefs));
                        var rootEl = doc.RootElement;
                        var pp = new ProfilePrivacy
                        {
                            Profile = names.TryGetValue(profile, out var fn) && fn.Length > 0 ? fn : profile,
                        };

                        if (rootEl.TryGetProperty("profile", out var prof))
                        {
                            if (prof.TryGetProperty("cookie_controls_mode", out var ccm) && ccm.TryGetInt32(out int c))
                                pp.CookieControls = c;
                            if (prof.TryGetProperty("default_content_setting_values", out var dcsv) &&
                                dcsv.TryGetProperty("cookies", out var ck) && ck.TryGetInt32(out int ckv))
                                pp.CookiesContent = ckv;
                        }
                        if (rootEl.TryGetProperty("safebrowsing", out var sb))
                        {
                            if (sb.TryGetProperty("enabled", out var en) && IsBool(en)) pp.SafeBrowsing = en.GetBoolean();
                            if (sb.TryGetProperty("enhanced", out var eh) && IsBool(eh)) pp.SafeBrowsingEnhanced = eh.GetBoolean();
                        }
                        list.Add(pp);
                    }
                    catch { /* unreadable / transiently locked - skip this profile */ }
                }
            }
            return list;
        }

        private static bool IsBool(JsonElement e) => e.ValueKind is JsonValueKind.True or JsonValueKind.False;

        // ---- Enterprise policy (HKLM + HKCU \SOFTWARE\Policies\Google\Chrome) -------------- //
        private const string ChromePolicyKey = @"SOFTWARE\Policies\Google\Chrome";

        private static (bool Block3p, int? SbLevel, bool ClearOnExit, bool Any) ChromePolicy()
        {
            bool block3p = PolicyDword("BlockThirdPartyCookies") == 1;
            int? sbLevel = PolicyDword("SafeBrowsingProtectionLevel");
            bool clearOnExit = PolicyKeyHasValues("ClearBrowsingDataOnExit");
            return (block3p, sbLevel, clearOnExit, block3p || sbLevel.HasValue || clearOnExit);
        }

        private static int? PolicyDword(string name)
        {
            foreach (var hive in new[] { Registry.LocalMachine, Registry.CurrentUser })
            {
                try { using var k = hive.OpenSubKey(ChromePolicyKey); if (k?.GetValue(name) is int i) return i; }
                catch { /* ignore */ }
            }
            return null;
        }

        private static bool PolicyKeyHasValues(string subKey)
        {
            foreach (var hive in new[] { Registry.LocalMachine, Registry.CurrentUser })
            {
                try
                {
                    using var k = hive.OpenSubKey(ChromePolicyKey + "\\" + subKey);
                    if (k != null && (k.ValueCount > 0 || k.SubKeyCount > 0)) return true;
                }
                catch { /* ignore */ }
            }
            return false;
        }

        // ---- Shared line builder (header panel + report) ---------------------------------- //
        // Inline link label shown after a setting line in the Chrome tab header; clicking it
        // opens the relevant chrome://settings page (GUI only - ignored by text reports).
        private const string SettingsLink = "[ open settings ]";

        private static void AddChromePrivacy(CheckGroup g)
        {
            var profiles = GetChromePrivacy();
            if (profiles.Count == 0)
            {
                g.Add(CheckStatus.Info, "Chrome settings", "No Chrome profile preferences found.");
                return;
            }
            int n = profiles.Count;
            string scope = n > 1 ? $" ({n} profiles)" : "";

            // Safe Browsing: explicit false anywhere is the real risk.
            int sbOff = profiles.Count(p => p.SafeBrowsing == false);
            int sbEnh = profiles.Count(p => p.SafeBrowsingEnhanced == true);
            if (sbOff > 0)
                g.Add(CheckStatus.Fail, "Safe Browsing", $"OFF in {sbOff} of {n} profile(s) - no phishing/malware blocking.")
                    .WithLink(SettingsLink, "chrome://settings/security");
            else
                g.Add(CheckStatus.Pass, "Safe Browsing",
                    sbEnh > 0 ? $"On (Enhanced in {sbEnh} of {n}).{scope}" : $"On (Standard).{scope}")
                    .WithLink(SettingsLink, "chrome://settings/security");

            // Third-party cookies: 0 = allow all (tracking).
            int allow = profiles.Count(p => p.CookieControls == 0);
            int block = profiles.Count(p => p.CookieControls == 2);
            int incog = profiles.Count(p => p.CookieControls == 1);
            if (allow > 0)
                g.Add(CheckStatus.Warn, "Third-party cookies", $"Allowed (not blocked) in {allow} of {n} profile(s) - cross-site tracking.")
                    .WithLink(SettingsLink, "chrome://settings/cookies");
            else if (block > 0)
                g.Add(CheckStatus.Pass, "Third-party cookies", $"Blocked.{scope}")
                    .WithLink(SettingsLink, "chrome://settings/cookies");
            else if (incog > 0)
                g.Add(CheckStatus.Pass, "Third-party cookies", $"Blocked in Incognito.{scope}")
                    .WithLink(SettingsLink, "chrome://settings/cookies");
            else
                g.Add(CheckStatus.Info, "Third-party cookies", "Browser default (not explicitly set).")
                    .WithLink(SettingsLink, "chrome://settings/cookies");

            // Clear cookies on exit: 4 = clear; hygiene preference, never a hard fail.
            int clear = profiles.Count(p => p.CookiesContent == 4);
            g.Add(clear > 0 ? CheckStatus.Pass : CheckStatus.Info, "Cookies on exit",
                clear > 0 ? $"Cleared on exit in {clear} of {n} profile(s)." : "Kept after exit (browser default).")
                .WithLink(SettingsLink, "chrome://settings/cookies");

            // Enterprise policy enforcement.
            var pol = ChromePolicy();
            if (pol.Any)
            {
                var parts = new List<string>();
                if (pol.Block3p) parts.Add("block 3p-cookies");
                if (pol.SbLevel is int lvl) parts.Add($"SafeBrowsing={(lvl == 2 ? "Enhanced" : lvl == 1 ? "Standard" : "Off")}");
                if (pol.ClearOnExit) parts.Add("clear-on-exit");
                g.Add(CheckStatus.Pass, "Enterprise policy", "Enforced: " + string.Join(", ", parts) + ".")
                    .WithLink("[ view policies ]", "chrome://policy");
            }
            else
            {
                g.Add(CheckStatus.Info, "Enterprise policy", "Not enforced - settings are user-changeable (no hardening policy set).")
                    .WithLink("[ view policies ]", "chrome://policy");
            }
        }

        /// <summary>Tab-severity contribution of weak Chrome settings (folded into the Chrome tab).</summary>
        public static TabSeverity ChromeSettingsSeverity()
        {
            var s = TabSeverity.None;
            foreach (var p in GetChromePrivacy())
            {
                if (p.SafeBrowsing == false) s = Sev.Max(s, TabSeverity.Alert);   // protection disabled
                if (p.CookieControls == 0) s = Sev.Max(s, TabSeverity.Caution);   // 3p cookies allowed
            }
            return s;
        }

        /// <summary>Header producer for the Chrome tab: chrome.exe integrity + the privacy/policy audit.</summary>
        public static CheckGroup CheckChromeHeader()
        {
            var g = new CheckGroup("Chrome - Integrity & Privacy");
            g.Results.AddRange(CheckChromeExe().Results);
            AddChromePrivacy(g);
            return g;
        }

        /// <summary>Report producer (headless / email / copy): the privacy &amp; policy audit.</summary>
        public static CheckGroup CheckChromePrivacy()
        {
            var g = new CheckGroup("Chrome Privacy & Policy");
            AddChromePrivacy(g);
            return g;
        }
    }
}
