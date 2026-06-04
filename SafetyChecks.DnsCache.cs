// Copyright (c) 2026 LanDen Labs - Dennis Lang

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Text.Json;

namespace BrowseSafe
{
    /// <summary>
    /// Windows DNS resolver cache: the live snapshot of names this PC recently
    /// resolved and the addresses they returned. Not a persistent log (entries
    /// expire per TTL and clear on flush/reboot), but the same hijack test the
    /// Safety Scan runs against probe hosts applies here to real, observed traffic.
    ///
    /// Note: Chrome's own Secure DNS (DoH) bypasses the OS resolver, so those
    /// queries do NOT appear here - the same caveat the upstream-resolver check
    /// already calls out (see AddChromeDohNote).
    /// </summary>
    public static partial class SafetyChecks
    {
        /// <summary>Structured DNS cache list (used by the DNS grid).</summary>
        public static List<DnsCacheEntry> GetDnsCache()
        {
            var rows = RunPowerShellArray(
                "@(Get-DnsClientCache | Select-Object Entry,Name,Type,TimeToLive,Data) | " +
                "ConvertTo-Json -Compress -Depth 3");

            var list = new List<DnsCacheEntry>();
            foreach (var r in rows)
            {
                var e = new DnsCacheEntry
                {
                    Entry = Str(r, "Entry"),
                    Name = Str(r, "Name"),
                    TypeCode = JInt(r, "Type"),
                    Ttl = JInt(r, "TimeToLive"),
                    Data = Str(r, "Data"),
                };
                e.TypeText = DnsTypeName(e.TypeCode);
                e.Suspicious = IsSuspiciousMapping(e);
                list.Add(e);
            }
            return list;
        }

        /// <summary>
        /// An address record (A/AAAA) whose answer is a private/loopback IP while the
        /// queried name looks like a public, internet host - the classic hijack /
        /// captive-portal / local-block signal. Internal names (single-label,
        /// .local/.lan/.home, reverse PTR zones) are intentionally not flagged.
        /// </summary>
        private static bool IsSuspiciousMapping(DnsCacheEntry e)
        {
            if (e.TypeCode is not (1 or 28)) return false;          // only A / AAAA carry an IP answer
            if (!IPAddress.TryParse(e.Data, out var ip)) return false;
            if (!(IsPrivate(ip) || IPAddress.IsLoopback(ip))) return false;
            return LooksPublicName(e.Entry.Length > 0 ? e.Entry : e.Name);
        }

        /// <summary>Heuristic: a multi-label, internet-style FQDN (not an internal/reverse name).</summary>
        private static bool LooksPublicName(string host)
        {
            host = host.Trim().TrimEnd('.').ToLowerInvariant();
            if (host.Length == 0) return false;
            // Reserved / internal suffixes that legitimately map to private IPs.
            // mshome.net is Microsoft's domain for ICS / Hyper-V / mobile-hotspot networks.
            if (host.EndsWith(".local") || host.EndsWith(".lan") || host.EndsWith(".home") ||
                host.EndsWith(".internal") || host.EndsWith(".localdomain") || host.EndsWith(".intranet") ||
                host.EndsWith(".arpa") || host.EndsWith(".test") || host.EndsWith(".invalid") ||
                host.EndsWith(".mshome.net") || host == "mshome.net")
                return false;

            string[] labels = host.Split('.');
            if (labels.Length < 2) return false;                    // single-label = local/NetBIOS name
            string tld = labels[^1];
            // A real public TLD is alphabetic and 2+ chars (rules out IP-literals and oddities).
            return tld.Length >= 2 && tld.All(char.IsLetter);
        }

        private static string DnsTypeName(int code) => code switch
        {
            1 => "A",
            2 => "NS",
            5 => "CNAME",
            6 => "SOA",
            12 => "PTR",
            15 => "MX",
            16 => "TXT",
            28 => "AAAA",
            33 => "SRV",
            39 => "DNAME",
            64 => "SVCB",
            65 => "HTTPS",
            257 => "CAA",
            _ => code == 0 ? "?" : $"#{code}",
        };

        /// <summary>
        /// Flushes the Windows DNS resolver cache (equivalent to <c>ipconfig /flushdns</c>).
        /// Works without elevation. Returns true if the command reported success.
        /// </summary>
        public static bool FlushDnsCache()
        {
            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = "ipconfig.exe",
                    Arguments = "/flushdns",
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                };
                using var proc = Process.Start(psi);
                if (proc == null) return false;
                proc.StandardOutput.ReadToEnd();
                proc.StandardError.ReadToEnd();
                if (!proc.WaitForExit(10000)) { try { proc.Kill(); } catch { } return false; }
                return proc.ExitCode == 0;
            }
            catch { return false; }
        }

        // ----------------------------------------------------------------- //
        // Report producer (headless / email)
        // ----------------------------------------------------------------- //
        public static CheckGroup CheckDnsCache()
        {
            var group = new CheckGroup("DNS Resolver Cache");

            var entries = GetDnsCache();
            if (entries.Count == 0)
            {
                group.Add(CheckStatus.Info, "DNS cache",
                    "Cache is empty, or Get-DnsClientCache returned nothing.");
                return group;
            }

            var flagged = entries.Where(e => e.Suspicious).ToList();
            foreach (var e in flagged.Take(MaxList))
                group.Add(CheckStatus.Warn, $"{e.Name}  ({e.TypeText})",
                    $"-> {e.Data}   public-looking name on a non-public IP - verify " +
                    "(DNS hijack / captive portal, or legitimate internal/split-horizon DNS).");

            // Then a sample of normal address records, newest-TTL first as a rough recency proxy.
            int shown = 0;
            foreach (var e in entries.Where(e => !e.Suspicious && e.TypeCode is (1 or 28))
                                     .OrderByDescending(e => e.Ttl))
            {
                if (++shown > MaxList) break;
                group.Add(CheckStatus.Info, $"{e.Name}  ({e.TypeText})", $"-> {e.Data}   ttl {e.Ttl}s");
            }

            group.Add(flagged.Count > 0 ? CheckStatus.Warn : CheckStatus.Pass, "DNS cache verdict",
                flagged.Count > 0
                    ? $"{entries.Count} cached entr(ies); {flagged.Count} public name(s) resolve to non-public IPs - review above."
                    : $"{entries.Count} cached entr(ies); no public name resolves to a non-public IP.");

            group.Add(CheckStatus.Info, "Note",
                "Live snapshot (entries expire per TTL). Chrome Secure DNS (DoH) bypasses this cache.");
            return group;
        }
    }
}
