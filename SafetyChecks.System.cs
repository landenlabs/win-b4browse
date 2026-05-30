using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Threading.Tasks;

namespace BrowseSafe
{
    /// <summary>
    /// Local system-integrity checks: clock accuracy against atomic time
    /// sources, and the Windows hosts file (a common local DNS-hijack vector).
    /// </summary>
    public static partial class SafetyChecks
    {
        /// <summary>Maximum tolerated clock skew before the time check fails.</summary>
        private static readonly TimeSpan ClockTolerance = TimeSpan.FromMinutes(5);

        private static readonly string[] NtpServers =
        {
            "time.nist.gov",        // NIST atomic clocks
            "time.cloudflare.com",
            "time.google.com",
        };

        /// <summary>
        /// The canonical Windows hosts file path. An optional BROWSESAFE_HOSTS
        /// environment variable overrides it (used for testing / scanning an
        /// alternate file).
        /// </summary>
        public static string HostsPath
        {
            get
            {
                string? overridePath = Environment.GetEnvironmentVariable("BROWSESAFE_HOSTS");
                return !string.IsNullOrWhiteSpace(overridePath)
                    ? overridePath
                    : Environment.ExpandEnvironmentVariables(@"%SystemRoot%\System32\drivers\etc\hosts");
            }
        }

        // ----------------------------------------------------------------- //
        // 9. Atomic time / clock accuracy
        // ----------------------------------------------------------------- //
        public static CheckGroup CheckTimeSync()
        {
            var group = new CheckGroup("9. Atomic Clock / Time Sync");

            // Query the NTP servers in parallel (UDP 123).
            var tasks = NtpServers
                .Select(s => Task.Run(() => (Server: s, Result: QueryNtp(s))))
                .ToArray();
            Task.WaitAll(tasks);

            var deltas = new List<TimeSpan>();
            foreach (var t in tasks)
            {
                if (t.Result.Result is (DateTime atomic, DateTime local))
                {
                    TimeSpan delta = local - atomic;
                    deltas.Add(delta);
                    var st = delta.Duration() <= ClockTolerance ? CheckStatus.Pass : CheckStatus.Fail;
                    group.Add(st, $"NTP {t.Result.Server}",
                        $"atomic {atomic:HH:mm:ss}Z  -  local delta {FormatDelta(delta)}");
                }
                else
                {
                    group.Add(CheckStatus.Warn, $"NTP {t.Result.Server}",
                        "No response (UDP port 123 may be blocked).");
                }
            }

            // HTTP Date header - robust fallback when UDP/NTP is blocked (second precision).
            var http = QueryHttpDate("https://www.cloudflare.com");
            if (http is (DateTime hAtomic, DateTime hLocal))
            {
                TimeSpan delta = hLocal - hAtomic;
                deltas.Add(delta);
                var st = delta.Duration() <= ClockTolerance ? CheckStatus.Pass : CheckStatus.Fail;
                group.Add(st, "HTTP Date (cloudflare.com)",
                    $"server {hAtomic:HH:mm:ss}Z  -  local delta {FormatDelta(delta)}");
            }

            // Overall verdict.
            if (deltas.Count == 0)
            {
                group.Add(CheckStatus.Warn, "Clock verdict",
                    "Could not reach any atomic time source - clock accuracy unverified.");
            }
            else
            {
                TimeSpan worst = deltas.OrderByDescending(d => d.Duration()).First();
                if (worst.Duration() <= ClockTolerance)
                    group.Add(CheckStatus.Pass, "Clock verdict",
                        $"Local clock is within 5 minutes of atomic time (max delta {FormatDelta(worst)}).");
                else
                    group.Add(CheckStatus.Fail, "Clock verdict",
                        $"Local clock is OFF by {FormatDelta(worst)} - exceeds 5 min. " +
                        "This breaks TLS certificate validation and secure browsing.");
            }

            return group;
        }

        /// <summary>SNTP client: returns (atomicUtc, localUtc-at-response) or null on failure.</summary>
        private static (DateTime Atomic, DateTime Local)? QueryNtp(string server)
        {
            try
            {
                var addrs = Dns.GetHostAddresses(server);
                if (addrs.Length == 0) return null;
                IPAddress addr = addrs[0];

                var data = new byte[48];
                data[0] = 0x1B; // LI = 0, Version = 3, Mode = 3 (client)

                using var sock = new Socket(addr.AddressFamily, SocketType.Dgram, ProtocolType.Udp)
                {
                    ReceiveTimeout = 3000,
                    SendTimeout = 3000,
                };
                sock.Connect(new IPEndPoint(addr, 123));
                sock.Send(data);
                sock.Receive(data);
                DateTime local = DateTime.UtcNow;

                // Transmit timestamp: bytes 40..47, big-endian seconds + fraction since 1900.
                const int off = 40;
                ulong intPart = ((ulong)data[off] << 24) | ((ulong)data[off + 1] << 16) |
                                ((ulong)data[off + 2] << 8) | data[off + 3];
                ulong fracPart = ((ulong)data[off + 4] << 24) | ((ulong)data[off + 5] << 16) |
                                 ((ulong)data[off + 6] << 8) | data[off + 7];
                if (intPart == 0 && fracPart == 0) return null;

                ulong ms = (intPart * 1000UL) + ((fracPart * 1000UL) >> 32);
                DateTime atomic = new DateTime(1900, 1, 1, 0, 0, 0, DateTimeKind.Utc).AddMilliseconds(ms);
                return (atomic, local);
            }
            catch { return null; }
        }

        private static (DateTime Atomic, DateTime Local)? QueryHttpDate(string url)
        {
            try
            {
                using var resp = Http.GetAsync(url, HttpCompletionOption.ResponseHeadersRead)
                                     .GetAwaiter().GetResult();
                DateTime local = DateTime.UtcNow;
                if (resp.Headers.Date is DateTimeOffset d)
                    return (d.UtcDateTime, local);
            }
            catch { /* best-effort */ }
            return null;
        }

        private static string FormatDelta(TimeSpan d)
        {
            string sign = d.Ticks >= 0 ? "+" : "-";
            string dir = d.Ticks >= 0 ? "local ahead" : "local behind";
            TimeSpan a = d.Duration();
            string mag = a.TotalSeconds < 90
                ? $"{sign}{a.TotalSeconds:F1} s"
                : $"{sign}{(int)a.TotalHours:00}:{a.Minutes:00}:{a.Seconds:00}";
            return $"{mag} ({dir})";
        }

        // ----------------------------------------------------------------- //
        // 6. Hosts file (local DNS overrides)
        // ----------------------------------------------------------------- //
        public static CheckGroup CheckHostsFile()
        {
            var group = new CheckGroup("6. Hosts File (local DNS overrides)");
            const int maxShown = 10;

            group.Add(CheckStatus.Info, "Path", HostsPath);

            if (!File.Exists(HostsPath))
            {
                group.Add(CheckStatus.Info, "Hosts file", "Not present (no local overrides).");
                return group;
            }

            string[] lines;
            try { lines = File.ReadAllLines(HostsPath); }
            catch (Exception ex)
            {
                group.Add(CheckStatus.Warn, "Read error", ex.Message);
                return group;
            }

            var maps = new List<(string Ip, string Host, bool External)>();
            foreach (var raw in lines)
            {
                string line = raw;
                int hash = line.IndexOf('#');
                if (hash >= 0) line = line.Substring(0, hash);
                line = line.Trim();
                if (line.Length == 0) continue;

                string[] parts = line.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length < 2) continue;
                if (!IPAddress.TryParse(parts[0], out var ip)) continue;

                bool external = !IPAddress.IsLoopback(ip)
                                && !ip.Equals(IPAddress.Any)
                                && !ip.Equals(IPAddress.IPv6Any);
                for (int i = 1; i < parts.Length; i++)
                    maps.Add((parts[0], parts[i], external));
            }

            if (maps.Count == 0)
            {
                group.Add(CheckStatus.Pass, "Host mappings",
                    "No active overrides (only comments / defaults). Clean.");
                return group;
            }

            int shown = Math.Min(maxShown, maps.Count);
            for (int i = 0; i < shown; i++)
            {
                var (ip, host, external) = maps[i];
                group.Add(external ? CheckStatus.Warn : CheckStatus.Info, host,
                    external
                        ? $"-> {ip}   (redirects to an EXTERNAL IP - verify this is intentional)"
                        : $"-> {ip}   (loopback/null - typical of ad/host blocking)");
            }
            if (maps.Count > shown)
                group.Add(CheckStatus.Info, "...", $"{maps.Count - shown} more mapping(s) not shown.");

            int externalCount = maps.Count(m => m.External);
            group.Add(externalCount > 0 ? CheckStatus.Warn : CheckStatus.Info,
                "Total host mappings",
                $"{maps.Count} mapping(s)" +
                (externalCount > 0
                    ? $", {externalCount} pointing to external IP(s) - review for tampering."
                    : ", all loopback/blocking (no external redirects)."));

            return group;
        }
    }
}
