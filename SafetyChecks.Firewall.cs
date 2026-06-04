// Copyright (c) 2026 LanDen Labs - Dennis Lang

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using Microsoft.Win32;

namespace BrowseSafe
{
    /// <summary>
    /// Firewall rule enumeration and a hijack-focused audit. Rules are read straight
    /// from the registry rule stores (fast, no admin required) rather than the slow
    /// <c>Get-NetFirewallRule</c> cmdlet. Each rule string is a pipe-delimited list of
    /// <c>Key=Value</c> tokens (e.g. <c>v2.31|Action=Allow|Dir=In|App=...|Name=...</c>).
    /// </summary>
    public static partial class SafetyChecks
    {
        /// <summary>Hard cap on how many rules we parse, so a machine with thousands of
        /// rules can't stall the UI. Loading stops once this many have been collected.</summary>
        public const int FirewallRuleScanCap = 1000;

        // Local rule store first, then the GPO-pushed store. Both are readable by a
        // standard user. RestrictedServices is intentionally excluded (it holds service
        // hardening, not app rules).
        private static readonly string[] FirewallRuleStores =
        {
            FirewallPolicyKey + @"\FirewallRules",
            @"SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules",
        };

        // Native Windows utilities ("living off the land" binaries) that malware grants
        // network access to in order to bypass file-reputation defences.
        private static readonly HashSet<string> FirewallLolBins = new(StringComparer.OrdinalIgnoreCase)
        {
            "powershell.exe", "powershell_ise.exe", "pwsh.exe", "cmd.exe", "wmic.exe",
            "mshta.exe", "cscript.exe", "wscript.exe", "rundll32.exe", "regsvr32.exe",
            "certutil.exe", "bitsadmin.exe", "msbuild.exe", "installutil.exe",
        };

        // Rule-name keywords that reference a well-known product. A rule whose name
        // impersonates one of these while its binary sits outside the trusted install
        // roots (Program Files / Windows) is masquerading.
        private static readonly string[] FirewallVendorKeywords =
        {
            "google chrome", "chrome", "firefox", "mozilla", "microsoft edge",
            "opera", "zoom", "dropbox", "onedrive", "spotify", "steam", "discord",
            "teams", "slack", "skype", "adobe",
        };

        // Lower-cased roots a legitimately-installed program is expected to live under.
        private static readonly string[] TrustedProgramRoots =
        {
            (Environment.GetEnvironmentVariable("ProgramFiles") ?? @"C:\Program Files").ToLowerInvariant(),
            (Environment.GetEnvironmentVariable("ProgramFiles(x86)") ?? @"C:\Program Files (x86)").ToLowerInvariant(),
            (Environment.GetEnvironmentVariable("SystemRoot") ?? @"C:\Windows").ToLowerInvariant(),
        };

        // C:\Users\<anyone>\Downloads\ or \Temp\ - user-writable, no admin needed to drop a binary.
        private static readonly Regex UserDropDir =
            new(@"\\users\\[^\\]+\\(downloads|temp)\\", RegexOptions.IgnoreCase | RegexOptions.Compiled);

        // ----------------------------------------------------------------- //
        // Enumeration
        // ----------------------------------------------------------------- //
        /// <summary>Reads and audits firewall rules from the registry stores, stopping
        /// once <see cref="FirewallRuleScanCap"/> rules have been collected.</summary>
        public static List<FirewallRule> GetFirewallRules()
        {
            var list = new List<FirewallRule>();
            foreach (var store in FirewallRuleStores)
            {
                if (list.Count >= FirewallRuleScanCap) break;
                try
                {
                    using var key = Registry.LocalMachine.OpenSubKey(store);
                    if (key == null) continue;

                    bool isPolicy = store.IndexOf("Policies", StringComparison.OrdinalIgnoreCase) >= 0;
                    foreach (var valueName in key.GetValueNames())
                    {
                        if (list.Count >= FirewallRuleScanCap) break;   // stop at the cap
                        if (key.GetValue(valueName) is not string raw || raw.Length == 0) continue;

                        var rule = ParseFirewallRule(valueName, raw);
                        if (rule == null) continue;
                        rule.Source = isPolicy ? "Policy" : "Local";
                        AuditFirewallRule(rule);
                        list.Add(rule);
                    }
                }
                catch { /* skip an inaccessible store */ }
            }
            return list;
        }

        /// <summary>Total number of rules across the stores (used by the header to report
        /// whether the loaded list was truncated at the cap).</summary>
        private static int CountFirewallRules()
        {
            int total = 0;
            foreach (var store in FirewallRuleStores)
            {
                try
                {
                    using var key = Registry.LocalMachine.OpenSubKey(store);
                    if (key != null) total += key.ValueCount;
                }
                catch { /* ignore */ }
            }
            return total;
        }

        private static FirewallRule? ParseFirewallRule(string id, string raw)
        {
            var r = new FirewallRule { Id = id };
            var profiles = new List<string>();
            string? proto = null, lport = null, remote = null;
            bool hasPrincipal = false;   // packaged-app / owner / package scoping

            foreach (var part in raw.Split('|'))
            {
                int eq = part.IndexOf('=');
                if (eq <= 0) continue;
                string k = part.Substring(0, eq);
                string v = part.Substring(eq + 1);

                switch (k)
                {
                    case "Action": r.Action = v; break;
                    case "Active": r.Active = v.Equals("TRUE", StringComparison.OrdinalIgnoreCase); break;
                    case "Dir": r.Direction = v; break;
                    case "Protocol": proto = ProtocolName(v); break;
                    case "LPort": lport ??= v; break;
                    case "RPort": if (r.RemotePort == "Any") r.RemotePort = v; break;
                    case "App": r.AppPath = v; break;
                    // Tokens that restrict a rule to a specific packaged app, package or owner.
                    case "AppPkgId":   // packaged (Store) app SID
                    case "PFN":        // package family name
                    case "Pkg":        // package SID
                    case "LUOwn":      // local-user owner SID
                    case "LUAuth":     // local-user authorized list
                        hasPrincipal = true; break;
                    case "Svc": r.Service = v; break;
                    case "Name": r.Name = v; break;
                    case "Desc": r.Description = v; break;
                    case "EmbedCtxt": r.Grouping = v; break;
                    case "Profile": profiles.Add(v); break;
                    case "RA4":
                    case "RA6": remote = remote == null ? v : remote + "," + v; break;
                    case "RmtAddrKeyword": remote ??= v; break;
                }
            }

            if (proto != null) r.Protocol = proto;
            if (!string.IsNullOrEmpty(lport)) r.LocalPort = lport;
            if (!string.IsNullOrEmpty(remote)) r.RemoteAddress = remote;
            r.Profile = profiles.Count == 0 ? "All" : string.Join(",", profiles);
            if (r.Name.Length == 0) r.Name = id;

            // Scoped to a real program, a packaged app, or a specific service?
            bool appValueScopes = r.AppPath.Length > 0 &&
                                  !r.AppPath.Equals("Any", StringComparison.OrdinalIgnoreCase) &&
                                  r.AppPath != "*";
            bool svcScopes = r.Service.Length > 0 && r.Service != "*";
            r.HasAppScope = appValueScopes || hasPrincipal || svcScopes;
            return r;
        }

        /// <summary>Maps an IANA protocol number to a friendly name.</summary>
        private static string ProtocolName(string value) => value switch
        {
            "6" => "TCP",
            "17" => "UDP",
            "1" => "ICMPv4",
            "58" => "ICMPv6",
            "2" => "IGMP",
            "256" => "Any",
            "" => "Any",
            _ => value,
        };

        // ----------------------------------------------------------------- //
        // Hijack audit
        // ----------------------------------------------------------------- //
        /// <summary>
        /// Flags Indicators of Compromise on a single rule. Only "Allow" rules are
        /// audited - attackers add Allow exceptions to punch through the default
        /// block-inbound posture or to open a C2 channel. Sets <see cref="FirewallRule.Risk"/>
        /// and a human-readable <see cref="FirewallRule.Note"/>.
        /// </summary>
        private static void AuditFirewallRule(FirewallRule r)
        {
            r.Risk = TabSeverity.None;
            var notes = new List<string>();
            void Flag(TabSeverity sev, string why) { r.Risk = Sev.Max(r.Risk, sev); notes.Add(why); }

            bool allow = r.Action.Equals("Allow", StringComparison.OrdinalIgnoreCase);
            bool inbound = r.Direction.Equals("In", StringComparison.OrdinalIgnoreCase);
            // Inbound allow rules are the dangerous class; outbound is the lesser concern.
            TabSeverity high = inbound ? TabSeverity.Alert : TabSeverity.Caution;

            if (allow)
            {
                string app = r.AppPath;
                bool realPath = app.Length > 0 && app.IndexOf('\\') >= 0;
                string expanded = realPath ? SafeExpand(app) : app;
                string lower = expanded.ToLowerInvariant();
                string file = realPath ? SafeFileName(expanded) : "";

                // 1. Binary in a user-writable directory (no admin needed to plant it).
                //    Temp/Downloads/Public are transient and attacker-favoured -> high signal.
                //    AppData/ProgramData also host many legitimate per-user installs (VS Code,
                //    Electron apps), so those are Review rather than a red Alert.
                if (realPath)
                {
                    bool transient = lower.Contains(@"\windows\temp\") ||
                                     lower.Contains(@"\appdata\local\temp\") ||
                                     lower.Contains(@"\users\public\") ||
                                     UserDropDir.IsMatch(lower);
                    if (transient)
                        Flag(high, $"{(inbound ? "Inbound" : "Outbound")} allow for a binary in a temp/download folder");
                    else if (lower.Contains(@"\appdata\"))
                        Flag(TabSeverity.Caution,
                            $"{(inbound ? "Inbound" : "Outbound")} allow for a binary under AppData (per-user install location)");
                    else if (lower.Contains(@"\programdata\"))
                        Flag(TabSeverity.Caution, "Allow for a binary under ProgramData");
                }

                // 2. Living-off-the-land binary granted network access.
                if (file.Length > 0 && FirewallLolBins.Contains(file))
                    Flag(high, $"Grants network access to LoLBin {file}");

                // 3. The "Any/Any/Any" rule: any protocol, any local port, any remote peer,
                //    AND not scoped to a program, packaged app or service. An app-scoped rule
                //    that leaves protocol/port open is normal (most built-in rules look like
                //    that); a wide-open rule with no scope at all is the suspicious one.
                if (!r.HasAppScope &&
                    r.Protocol.Equals("Any", StringComparison.OrdinalIgnoreCase) &&
                    r.LocalPort.Equals("Any", StringComparison.OrdinalIgnoreCase) &&
                    r.RemoteAddress.Equals("Any", StringComparison.OrdinalIgnoreCase))
                    Flag(high, "Allows any protocol, any port, from any remote address (no app scope)");

                // 4. Masquerading: a name impersonating a known product, but whose binary is
                //    NOT under a trusted install root (Program Files / Windows). A genuine
                //    vendor binary lives there; a planted look-alike does not.
                if (realPath && r.Name.Length > 0 && !r.Name.StartsWith("@"))
                {
                    bool trusted = TrustedProgramRoots.Any(root => lower.StartsWith(root));
                    if (!trusted)
                    {
                        string nameLower = r.Name.ToLowerInvariant();
                        string? hit = FirewallVendorKeywords.FirstOrDefault(kw => nameLower.Contains(kw));
                        if (hit != null)
                            Flag(TabSeverity.Alert,
                                $"Name references \"{hit}\" but the program is outside trusted install locations");
                    }
                }
            }

            // A staged-but-disabled rule is a lesser, latent risk than a live one.
            if (!r.Active && r.Risk == TabSeverity.Alert)
            {
                r.Risk = TabSeverity.Caution;
                notes.Add("(rule is currently inactive)");
            }

            r.Note = string.Join("; ", notes);
        }

        private static string SafeExpand(string path)
        {
            try { return Environment.ExpandEnvironmentVariables(path); }
            catch { return path; }
        }

        private static string SafeFileName(string path)
        {
            try { return Path.GetFileName(path); }
            catch { return ""; }
        }

        // ----------------------------------------------------------------- //
        // CheckGroup producers (header for the grid; audit section for reports)
        // ----------------------------------------------------------------- //
        /// <summary>Header shown above the rules grid: the existing firewall posture plus a
        /// truncation note when the rule store is larger than the scan cap.</summary>
        public static CheckGroup FirewallRulesHeader()
        {
            var group = CheckFirewall();
            int total = CountFirewallRules();
            if (total > FirewallRuleScanCap)
                group.Add(CheckStatus.Warn, "Rule list truncated",
                    $"Loading the first {FirewallRuleScanCap} of {total} rule(s).");
            return group;
        }

        /// <summary>Text-report section listing the rules the audit flagged (for the
        /// headless report and "Email this tab").</summary>
        public static CheckGroup CheckFirewallRules()
        {
            var group = new CheckGroup("Firewall Rule Audit");

            List<FirewallRule> rules;
            try { rules = GetFirewallRules(); }
            catch (Exception ex)
            {
                group.Add(CheckStatus.Warn, "Firewall rules", "Could not read rules: " + ex.Message);
                return group;
            }

            var flagged = rules.Where(r => r.Risk >= TabSeverity.Caution)
                               .OrderByDescending(r => (int)r.Risk)
                               .ToList();

            if (flagged.Count == 0)
            {
                group.Add(CheckStatus.Pass, "Firewall rule audit",
                    $"No suspicious rules among {rules.Count} scanned.");
                return group;
            }

            int shown = 0;
            foreach (var r in flagged)
            {
                if (++shown > MaxList) break;
                var status = r.Risk == TabSeverity.Alert ? CheckStatus.Fail : CheckStatus.Warn;
                string scope = $"{r.Direction}/{r.Action} {r.Protocol} port {r.LocalPort}";
                string app = r.AppPath.Length > 0 ? r.AppPath : "(no application)";
                group.Add(status, r.Name, $"{scope}  -  {app}  -  {r.Note}");
            }
            if (flagged.Count > MaxList)
                group.Add(CheckStatus.Info, "...", $"{flagged.Count - MaxList} more flagged rule(s) not shown.");

            group.Add(flagged.Any(r => r.Risk == TabSeverity.Alert) ? CheckStatus.Fail : CheckStatus.Warn,
                "Firewall rule audit",
                $"{flagged.Count} of {rules.Count} rule(s) look suspicious - review the items above.");
            return group;
        }
    }
}
