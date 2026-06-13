// Copyright (c) 2026 LanDen Labs - Dennis Lang

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading;

namespace B4Browse
{
    /// <summary>
    /// Local IPv4 ARP / neighbor cache: the live layer-2 map of IP -> MAC for the
    /// immediate subnet. A snapshot (entries expire in seconds), not a persistent log,
    /// but it is where ARP spoofing / MITM, duplicate-MAC anomalies, and rogue local
    /// devices surface. Read via Get-NetNeighbor (the modern equivalent of `arp -a`).
    /// </summary>
    public static partial class SafetyChecks
    {
        /// <summary>Structured ARP cache list (used by the ARP grid).</summary>
        public static List<ArpEntry> GetArpTable()
        {
            var rows = RunPowerShellArray(
                "@(Get-NetNeighbor -AddressFamily IPv4 | Select-Object IPAddress, LinkLayerAddress, " +
                "@{n='State';e={[string]$_.State}}, InterfaceAlias, InterfaceIndex) | " +
                "ConvertTo-Json -Compress -Depth 3");

            string? gw = GetDefaultGatewayV4()?.ToString();

            var list = new List<ArpEntry>();
            foreach (var r in rows)
            {
                string ip = Str(r, "IPAddress");
                if (ip.Length == 0) continue;

                var e = new ArpEntry
                {
                    Ip = ip,
                    Mac = NormalizeMac(Str(r, "LinkLayerAddress")),
                    State = Str(r, "State"),
                    Interface = Str(r, "InterfaceAlias"),
                    InterfaceIndex = JInt(r, "InterfaceIndex"),
                };
                e.Oui = e.Mac.Length >= 8 ? e.Mac.Substring(0, 8) : "";
                e.IsStatic = e.State.Equals("Permanent", StringComparison.OrdinalIgnoreCase);
                e.IsGateway = gw != null && ip == gw;
                e.IsNoise = IsNoiseEntry(e);
                list.Add(e);
            }

            AnalyzeArp(list);
            return list;
        }

        /// <summary>Assigns each row's Risk + Note: shared/gateway MAC (spoofing), randomized MAC, static.</summary>
        private static void AnalyzeArp(List<ArpEntry> list)
        {
            // MAC -> the distinct unicast IPs that claim it (noise rows excluded).
            var byMac = new Dictionary<string, HashSet<string>>(StringComparer.OrdinalIgnoreCase);
            foreach (var e in list)
            {
                if (e.IsNoise || e.Mac.Length == 0) continue;
                if (!byMac.TryGetValue(e.Mac, out var ips)) byMac[e.Mac] = ips = new(StringComparer.OrdinalIgnoreCase);
                ips.Add(e.Ip);
            }

            foreach (var e in list)
            {
                var notes = new List<string>();
                if (e.IsGateway) notes.Add("gateway");

                if (e.IsNoise || e.Mac.Length == 0)
                {
                    e.Risk = TabSeverity.None;
                    if (notes.Count > 0) e.Note = string.Join("; ", notes);
                    continue;
                }

                var shared = byMac.TryGetValue(e.Mac, out var ips) && ips.Count > 1
                    ? ips.Where(x => x != e.Ip).ToList()
                    : new List<string>();

                if (shared.Count > 0)
                {
                    bool involvesGateway = e.IsGateway || (list.Any(o => o.IsGateway && shared.Contains(o.Ip)));
                    if (involvesGateway)
                    {
                        e.Risk = TabSeverity.Alert;
                        notes.Add($"gateway MAC shared with {string.Join(", ", shared)} - possible ARP spoofing / MITM");
                    }
                    else
                    {
                        e.Risk = TabSeverity.Caution;
                        notes.Add($"MAC shared by {shared.Count + 1} IPs ({string.Join(", ", shared)}) - " +
                                  "verify (proxy ARP / multi-homed host, or spoofing)");
                    }
                }
                else if (IsLocallyAdministered(e.Mac))
                {
                    e.Risk = TabSeverity.Caution;
                    notes.Add("locally-administered (randomized) MAC");
                }
                else
                {
                    e.Risk = TabSeverity.Ok;
                    if (e.IsStatic) notes.Add("static (manually pinned)");
                }

                e.Note = string.Join("; ", notes);
            }
        }

        // ---- helpers ----------------------------------------------------- //
        private static string NormalizeMac(string raw)
        {
            raw = (raw ?? "").Trim().ToUpperInvariant().Replace(':', '-');
            // Treat an all-zero / empty address as "no MAC" (incomplete entry).
            if (raw.Length == 0 || raw.Replace("-", "").Replace("0", "").Length == 0) return "";
            return raw;
        }

        private static byte[]? MacBytes(string mac)
        {
            var parts = mac.Split('-');
            if (parts.Length != 6) return null;
            var b = new byte[6];
            for (int i = 0; i < 6; i++)
                if (!byte.TryParse(parts[i], System.Globalization.NumberStyles.HexNumber, null, out b[i])) return null;
            return b;
        }

        // The least-significant bit of the first octet marks a group (multicast/broadcast) address.
        private static bool IsMulticastMac(string mac)
        {
            var b = MacBytes(mac);
            return b != null && (b[0] & 0x01) != 0;
        }

        // The second-least-significant bit of the first octet marks a locally-administered
        // (often randomized / privacy) address rather than a burned-in vendor OUI.
        private static bool IsLocallyAdministered(string mac)
        {
            var b = MacBytes(mac);
            return b != null && (b[0] & 0x02) != 0;
        }

        /// <summary>Multicast/broadcast/unspecified/incomplete rows: shown only under "Show all".</summary>
        private static bool IsNoiseEntry(ArpEntry e)
        {
            if (e.Mac.Length == 0) return true;                                  // incomplete (no MAC)
            if (e.State.Equals("Incomplete", StringComparison.OrdinalIgnoreCase) ||
                e.State.Equals("Unreachable", StringComparison.OrdinalIgnoreCase)) return true;
            if (IsMulticastMac(e.Mac)) return true;                              // includes broadcast FF-..
            if (IPAddress.TryParse(e.Ip, out var ip))
            {
                var b = ip.GetAddressBytes();
                if (b.Length == 4 && (b[0] >= 224 || (b[0] == 255 && b[1] == 255 && b[2] == 255 && b[3] == 255)))
                    return true;                                                 // 224.0.0.0/4 + broadcast
            }
            return false;
        }

        /// <summary>Fills <see cref="ArpEntry.Vendor"/> by OUI via the online macvendors API.
        /// Dedupes by OUI and throttles to respect the free-tier rate limit. Run off the UI thread.</summary>
        public static void ResolveArpVendors(IReadOnlyList<ArpEntry> entries)
        {
            var ouis = entries
                .Where(e => !e.IsNoise && e.Oui.Length == 8 && e.Vendor.Length == 0)
                .Select(e => e.Oui).Distinct(StringComparer.OrdinalIgnoreCase).ToList();

            bool first = true;
            foreach (var oui in ouis)
            {
                if (!first) Thread.Sleep(350);   // macvendors.com free tier ~1 req/sec
                first = false;
                string vendor = LookupOuiVendor(oui);
                if (vendor.Length == 0) continue;
                foreach (var e in entries)
                    if (e.Oui.Equals(oui, StringComparison.OrdinalIgnoreCase)) e.Vendor = vendor;
            }
        }

        /// <summary>Public single-OUI vendor lookup (used by the ARP row right-click menu).</summary>
        public static string LookupVendor(string oui) => LookupOuiVendor(oui);

        // ----------------------------------------------------------------- //
        // Report producer (headless / email / copy)
        // ----------------------------------------------------------------- //
        public static CheckGroup CheckArp()
        {
            var group = new CheckGroup("ARP Neighbor Cache");

            var entries = GetArpTable();
            var neighbors = entries.Where(e => !e.IsNoise).ToList();
            if (neighbors.Count == 0)
            {
                group.Add(CheckStatus.Info, "ARP cache",
                    "No resolved IPv4 neighbors (cache empty, or Get-NetNeighbor returned nothing).");
                return group;
            }

            var flagged = neighbors.Where(e => e.Risk >= TabSeverity.Caution)
                                   .OrderByDescending(e => (int)e.Risk).ToList();
            foreach (var e in flagged.Take(MaxList))
                group.Add(e.Risk == TabSeverity.Alert ? CheckStatus.Fail : CheckStatus.Warn,
                    $"{e.Ip}  ->  {e.Mac}", e.Note);

            // A sample of normal neighbors.
            int shown = 0;
            foreach (var e in neighbors.Where(e => e.Risk < TabSeverity.Caution)
                                       .OrderByDescending(e => e.IsGateway))
            {
                if (++shown > MaxList) break;
                string tag = e.IsGateway ? "  (gateway)" : e.IsStatic ? "  (static)" : "";
                group.Add(CheckStatus.Info, $"{e.Ip}  ->  {e.Mac}{tag}", e.State);
            }

            var worst = flagged.Count == 0 ? CheckStatus.Pass
                      : flagged.Any(e => e.Risk == TabSeverity.Alert) ? CheckStatus.Fail : CheckStatus.Warn;
            group.Add(worst, "ARP verdict",
                flagged.Count == 0
                    ? $"{neighbors.Count} neighbor(s); no duplicate/spoofed MACs detected."
                    : $"{neighbors.Count} neighbor(s); {flagged.Count} flagged - review above " +
                      "(a MAC shared across IPs can indicate ARP spoofing / MITM).");

            group.Add(CheckStatus.Info, "Note",
                "Live snapshot (entries expire in seconds). Duplicate-IP 'flip' detection needs " +
                "sampling over time; randomized (locally-administered) MACs are common and legitimate.");
            return group;
        }
    }
}
