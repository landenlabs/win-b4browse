// Copyright (c) 2026 LanDen Labs - Dennis Lang

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using Microsoft.Win32;

namespace BrowseSafe
{
    /// <summary>
    /// All of the diagnostic logic. Every public method returns a populated
    /// <see cref="CheckGroup"/> and is safe to call from a background thread.
    /// </summary>
    public static partial class SafetyChecks
    {
        /// <summary>Well-known hosts used to confirm DNS resolution is working and untampered.</summary>
        private static readonly string[] TestHosts =
        {
            "www.google.com",
            "www.yahoo.com",
            "www.cloudflare.com",
            "github.com",
            "www.microsoft.com",
            "en.wikipedia.org",
        };

        /// <summary>
        /// E-mail providers and the domain whose MX (mail exchange) records name
        /// the servers "designated" to receive their mail. We confirm those
        /// designated mail hosts both belong to the provider's known mail
        /// infrastructure (suffix match) and resolve to public IPs.
        /// </summary>
        private static readonly (string Label, string Domain, string ExpectedSuffix)[] EmailDomains =
        {
            ("Google / Gmail", "gmail.com", "google.com"),
            ("Yahoo Mail",     "yahoo.com", "yahoodns.net"),
        };

        /// <summary>Friendly names for popular public DNS resolvers.</summary>
        private static readonly Dictionary<string, string> KnownResolvers = new()
        {
            ["8.8.8.8"] = "Google Public DNS",
            ["8.8.4.4"] = "Google Public DNS",
            ["1.1.1.1"] = "Cloudflare DNS",
            ["1.0.0.1"] = "Cloudflare DNS",
            ["9.9.9.9"] = "Quad9 DNS",
            ["149.112.112.112"] = "Quad9 DNS",
            ["208.67.222.222"] = "OpenDNS",
            ["208.67.220.220"] = "OpenDNS",
            ["94.140.14.14"] = "AdGuard DNS",
            ["2001:4860:4860::8888"] = "Google Public DNS",
            ["2606:4700:4700::1111"] = "Cloudflare DNS",
        };

        // ----------------------------------------------------------------- //
        // 1. Current DNS servers
        // ----------------------------------------------------------------- //
        public static CheckGroup CheckDnsServers()
        {
            var group = new CheckGroup("1. Current DNS Server(s)");
            try
            {
                var seen = new HashSet<string>();
                int adapterCount = 0;

                foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (nic.OperationalStatus != OperationalStatus.Up) continue;
                    if (nic.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;
                    if (nic.NetworkInterfaceType == NetworkInterfaceType.Tunnel) continue;

                    var props = nic.GetIPProperties();
                    var dns = props.DnsAddresses
                                   .Where(a => !IPAddress.IsLoopback(a))
                                   .ToList();
                    if (dns.Count == 0) continue;

                    adapterCount++;
                    foreach (var addr in dns)
                    {
                        string ip = addr.ToString();
                        if (!seen.Add(ip)) continue;

                        string label = KnownResolvers.TryGetValue(ip, out var name)
                            ? $"{ip}  ({name})"
                            : ip;

                        // A private/local DNS server is normal (a home/office router
                        // forwarding queries). A public, recognised resolver is also fine.
                        var status = CheckStatus.Info;
                        string note = nic.Name;
                        if (KnownResolvers.ContainsKey(ip))
                            note += "  - recognised public resolver";
                        else if (IsPrivate(addr))
                            note += "  - local/router resolver";

                        group.Add(status, $"DNS {label}", note);
                    }
                }

                if (group.Results.Count == 0)
                    group.Add(CheckStatus.Warn, "No DNS servers found",
                        "No active adapter reports a DNS server. Network may be down.");
                else
                    group.Add(CheckStatus.Pass, "DNS configured",
                        $"{seen.Count} DNS server(s) across {adapterCount} active adapter(s).");
            }
            catch (Exception ex)
            {
                group.Add(CheckStatus.Warn, "DNS enumeration error", ex.Message);
            }
            return group;
        }

        // ----------------------------------------------------------------- //
        // 2. DNS lookups of public sites
        // ----------------------------------------------------------------- //
        public static CheckGroup CheckDnsLookups()
        {
            var group = new CheckGroup("4. DNS Lookup Tests (public sites)");
            foreach (var host in TestHosts)
            {
                try
                {
                    var sw = Stopwatch.StartNew();
                    IPAddress[] addrs = Dns.GetHostAddresses(host);
                    sw.Stop();

                    if (addrs.Length == 0)
                    {
                        group.Add(CheckStatus.Warn, host, "Resolved to no addresses.");
                        continue;
                    }

                    string ipList = string.Join(", ", addrs.Take(4).Select(a => a.ToString()));
                    if (addrs.Length > 4) ipList += $", (+{addrs.Length - 4} more)";

                    // Resolution to a private/loopback address for a public site is a
                    // classic sign of DNS hijacking, captive portals, or local blocking.
                    var hijacked = addrs.Where(a => IsPrivate(a) || IPAddress.IsLoopback(a)).ToList();
                    if (hijacked.Count > 0)
                    {
                        group.Add(CheckStatus.Fail, host,
                            $"Resolved to non-public address(es): {string.Join(", ", hijacked)} " +
                            "- possible DNS hijack, captive portal, or local block.");
                    }
                    else
                    {
                        group.Add(CheckStatus.Pass, host,
                            $"{ipList}   ({sw.ElapsedMilliseconds} ms)");
                    }
                }
                catch (Exception ex)
                {
                    group.Add(CheckStatus.Warn, host, $"Lookup failed: {ex.Message}");
                }
            }
            return group;
        }

        // ----------------------------------------------------------------- //
        // 3. E-mail (MX) DNS accuracy
        // ----------------------------------------------------------------- //
        public static CheckGroup CheckEmailDns()
        {
            var group = new CheckGroup("7. E-mail (MX) DNS Tests");

            foreach (var (label, domain, expectedSuffix) in EmailDomains)
            {
                List<(int Pref, string Host)> mx;
                try
                {
                    mx = ResolveMx(domain);
                }
                catch (Exception ex)
                {
                    group.Add(CheckStatus.Warn, $"{label}  ({domain})", $"MX lookup error: {ex.Message}");
                    continue;
                }

                if (mx.Count == 0)
                {
                    group.Add(CheckStatus.Warn, $"{label}  ({domain})",
                        "No MX records returned (DNS may be filtered or blocked).");
                    continue;
                }

                group.Add(CheckStatus.Info, $"{label}  ({domain})",
                    $"{mx.Count} designated mail server(s) published via MX.");

                foreach (var (pref, host) in mx)
                {
                    // 1) Does the designated host belong to the provider's known mail infrastructure?
                    bool providerMatch = host.EndsWith("." + expectedSuffix, StringComparison.OrdinalIgnoreCase)
                                         || host.Equals(expectedSuffix, StringComparison.OrdinalIgnoreCase);

                    // 2) Does that host resolve to a real, public IP address?
                    string ipText;
                    bool nonPublic = false;
                    bool resolveOk = false;
                    try
                    {
                        var addrs = Dns.GetHostAddresses(host);
                        resolveOk = addrs.Length > 0;
                        nonPublic = addrs.Any(a => IsPrivate(a) || IPAddress.IsLoopback(a));
                        ipText = addrs.Length > 0
                            ? string.Join(", ", addrs.Take(3).Select(a => a.ToString()))
                            : "(no address)";
                        if (addrs.Length > 3) ipText += $", (+{addrs.Length - 3} more)";
                    }
                    catch (Exception ex)
                    {
                        ipText = $"resolve failed: {ex.Message}";
                    }

                    CheckStatus status;
                    string note;
                    if (!resolveOk)
                    {
                        status = CheckStatus.Warn;
                        note = $"pref {pref} -> {ipText}";
                    }
                    else if (nonPublic)
                    {
                        status = CheckStatus.Fail;
                        note = $"pref {pref} -> {ipText}  - non-public address (possible hijack).";
                    }
                    else if (!providerMatch)
                    {
                        status = CheckStatus.Warn;
                        note = $"pref {pref} -> {ipText}  - host is NOT under expected \"{expectedSuffix}\".";
                    }
                    else
                    {
                        status = CheckStatus.Pass;
                        note = $"pref {pref} -> {ipText}  (matches {expectedSuffix})";
                    }

                    group.Add(status, "MX  " + host, note);
                }
            }
            return group;
        }

        /// <summary>
        /// Looks up MX (mail exchange) records for a domain via Resolve-DnsName,
        /// returning each designated mail host and its preference (lower = preferred).
        /// </summary>
        private static List<(int Pref, string Host)> ResolveMx(string domain)
        {
            var list = new List<(int, string)>();

            // Domain comes from a fixed internal table, so direct interpolation is safe.
            string script =
                $"@(Resolve-DnsName -Type MX -Name '{domain}' -DnsOnly -ErrorAction SilentlyContinue | " +
                "Where-Object {$_.QueryType -eq 'MX'} | " +
                "Select-Object Preference,NameExchange) | ConvertTo-Json -Compress -Depth 3";

            var root = RunPowerShellJson(script);
            if (root == null) return list;

            void AddOne(JsonElement e)
            {
                if (e.ValueKind != JsonValueKind.Object) return;
                string host = e.TryGetProperty("NameExchange", out var nx) ? (nx.GetString() ?? "") : "";
                int pref = e.TryGetProperty("Preference", out var p) && p.TryGetInt32(out int pv) ? pv : 0;
                if (!string.IsNullOrWhiteSpace(host))
                    list.Add((pref, host.TrimEnd('.')));
            }

            // ConvertTo-Json yields an array for multiple records, a bare object for one.
            if (root.Value.ValueKind == JsonValueKind.Array)
                foreach (var e in root.Value.EnumerateArray()) AddOne(e);
            else
                AddOne(root.Value);

            list.Sort((a, b) => a.Item1.CompareTo(b.Item1));
            return list;
        }

        // ----------------------------------------------------------------- //
        // 4. Proxy configuration
        // ----------------------------------------------------------------- //
        public static CheckGroup CheckProxy()
        {
            var group = new CheckGroup("8. Proxy Configuration");
            bool anyProxy = false;

            // --- WinINET per-user settings (what Chrome uses by default) ---
            try
            {
                using var key = Registry.CurrentUser.OpenSubKey(
                    @"Software\Microsoft\Windows\CurrentVersion\Internet Settings");
                if (key != null)
                {
                    bool enabled = (key.GetValue("ProxyEnable") as int? ?? 0) != 0;
                    string? server = key.GetValue("ProxyServer") as string;
                    string? pac = key.GetValue("AutoConfigURL") as string;

                    if (enabled && !string.IsNullOrWhiteSpace(server))
                    {
                        anyProxy = true;
                        group.Add(CheckStatus.Fail, "Manual proxy ENABLED", server!);
                    }
                    else
                    {
                        group.Add(CheckStatus.Pass, "Manual proxy disabled",
                            "Internet Settings ProxyEnable = 0.");
                    }

                    if (!string.IsNullOrWhiteSpace(pac))
                    {
                        anyProxy = true;
                        group.Add(CheckStatus.Warn, "Auto-config (PAC) script set", pac!);
                    }
                }
                else
                {
                    group.Add(CheckStatus.Info, "Internet Settings",
                        "Registry key not present (treated as no proxy).");
                }
            }
            catch (Exception ex)
            {
                group.Add(CheckStatus.Warn, "Internet Settings read error", ex.Message);
            }

            // --- WPAD auto-detect flag (DefaultConnectionSettings byte 8, bit 3) ---
            try
            {
                using var key = Registry.CurrentUser.OpenSubKey(
                    @"Software\Microsoft\Windows\CurrentVersion\Internet Settings\Connections");
                if (key?.GetValue("DefaultConnectionSettings") is byte[] dcs && dcs.Length > 8)
                {
                    bool autoDetect = (dcs[8] & 0x08) != 0;
                    group.Add(autoDetect ? CheckStatus.Warn : CheckStatus.Pass,
                        "Automatically detect settings (WPAD)",
                        autoDetect ? "Enabled - proxy may be auto-discovered." : "Disabled.");
                }
            }
            catch { /* best-effort */ }

            // --- Environment variables honoured by many tools ---
            foreach (var v in new[] { "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY" })
            {
                string? val = Environment.GetEnvironmentVariable(v)
                              ?? Environment.GetEnvironmentVariable(v.ToLowerInvariant());
                if (!string.IsNullOrWhiteSpace(val))
                {
                    anyProxy = true;
                    group.Add(CheckStatus.Warn, $"Env var {v}", val!);
                }
            }

            // --- What .NET's system proxy resolves for a normal request ---
            try
            {
                var sys = WebRequest.GetSystemWebProxy();
                var test = new Uri("https://www.google.com");
                if (!sys.IsBypassed(test))
                {
                    Uri? via = sys.GetProxy(test);
                    if (via != null && via != test)
                    {
                        anyProxy = true;
                        group.Add(CheckStatus.Warn, "System proxy in effect", via.ToString());
                    }
                }
            }
            catch { /* best-effort */ }

            group.Add(anyProxy ? CheckStatus.Warn : CheckStatus.Pass,
                "Overall proxy verdict",
                anyProxy ? "A proxy/auto-config is configured - review the items above."
                         : "No proxy configured. Chrome will connect directly.");
            return group;
        }

        // ----------------------------------------------------------------- //
        // 5. Windows security features
        // ----------------------------------------------------------------- //
        public static CheckGroup CheckWindowsSecurity()
        {
            var group = new CheckGroup("10. Windows Security Features");

            // -- Items read directly from the registry (no admin needed) --

            // User Account Control
            int uac = ReadHklmDword(
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "EnableLUA", 1);
            group.Add(uac != 0 ? CheckStatus.Pass : CheckStatus.Fail,
                "User Account Control (UAC)",
                uac != 0 ? "Enabled." : "DISABLED - elevation prompts are off.");

            // SmartScreen (Explorer / app & file reputation)
            string smart = ReadHklmString(
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer", "SmartScreenEnabled");
            if (string.IsNullOrEmpty(smart))
            {
                group.Add(CheckStatus.Warn, "SmartScreen (Explorer)",
                    "Not configured / default. Verify in Windows Security.");
            }
            else
            {
                bool on = !smart.Equals("Off", StringComparison.OrdinalIgnoreCase);
                group.Add(on ? CheckStatus.Pass : CheckStatus.Fail,
                    "SmartScreen (Explorer)", on ? $"Enabled ({smart})." : "DISABLED.");
            }

            // SmartScreen for Microsoft Edge / app installs (best-effort)
            int edgeSmart = ReadHklmDword(
                @"SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter", "EnabledV9", -1);
            if (edgeSmart >= 0)
                group.Add(edgeSmart != 0 ? CheckStatus.Pass : CheckStatus.Warn,
                    "SmartScreen (Edge phishing filter)",
                    edgeSmart != 0 ? "Enabled." : "Disabled by policy.");

            // -- Items gathered via a single PowerShell query --
            try
            {
                var ps = QueryPowerShellSecurity();
                if (ps != null)
                {
                    PopulateFromPowerShell(group, ps.Value);
                }
                else
                {
                    group.Add(CheckStatus.Warn, "Defender / Firewall query",
                        "Could not query Windows Defender / Firewall status via PowerShell.");
                }
            }
            catch (Exception ex)
            {
                group.Add(CheckStatus.Warn, "Security status query error", ex.Message);
            }

            return group;
        }

        private static void PopulateFromPowerShell(CheckGroup group, JsonElement root)
        {
            // Antivirus products registered with the Windows Security Center.
            // This is the authoritative "is some AV protecting me?" answer and
            // covers third-party products as well as Microsoft Defender.
            bool anyAvEnabled = false;
            string? activeNonDefender = null;
            if (root.TryGetProperty("AntivirusProducts", out var av) && av.ValueKind == JsonValueKind.Array)
            {
                foreach (var p in av.EnumerateArray())
                {
                    string name = p.TryGetProperty("Name", out var n) ? (n.GetString() ?? "?") : "?";
                    bool on = p.TryGetProperty("Enabled", out var e) && e.ValueKind == JsonValueKind.True;
                    if (on) anyAvEnabled = true;
                    if (on && !name.Contains("Defender", StringComparison.OrdinalIgnoreCase))
                        activeNonDefender = name;

                    group.Add(on ? CheckStatus.Pass : CheckStatus.Warn,
                        $"Antivirus product: {name}", on ? "Enabled & active." : "Present but not active.");
                }
                if (av.GetArrayLength() == 0)
                    group.Add(CheckStatus.Warn, "Antivirus product",
                        "No antivirus product is registered with Windows Security Center.");
            }

            // Windows Defender Antivirus. If Defender is passive because another
            // AV is the active product, report that as Info rather than a failure.
            if (root.TryGetProperty("Defender", out var d) && d.ValueKind == JsonValueKind.Object)
            {
                bool defenderOn = d.TryGetProperty("AntivirusEnabled", out var ae) && ae.ValueKind == JsonValueKind.True;
                if (defenderOn)
                {
                    AddBool(group, d, "AntivirusEnabled", "Defender Antivirus", failWhenOff: true);
                    AddBool(group, d, "RealTimeProtectionEnabled", "Defender Real-Time Protection", failWhenOff: true);
                    AddBool(group, d, "AntispywareEnabled", "Defender Antispyware", failWhenOff: false);
                    AddBool(group, d, "BehaviorMonitorEnabled", "Defender Behavior Monitor", failWhenOff: false);
                    AddBool(group, d, "NISEnabled", "Network Inspection System", failWhenOff: false);
                    AddBool(group, d, "IsTamperProtected", "Tamper Protection", failWhenOff: false);

                    if (d.TryGetProperty("AntivirusSignatureAge", out var ageEl) &&
                        ageEl.TryGetInt32(out int age))
                    {
                        if (age >= 65535)
                            group.Add(CheckStatus.Info, "Antivirus signatures", "Update age unknown.");
                        else
                        {
                            var st = age <= 3 ? CheckStatus.Pass : age <= 14 ? CheckStatus.Warn : CheckStatus.Fail;
                            group.Add(st, "Antivirus signatures", $"Last updated {age} day(s) ago.");
                        }
                    }
                }
                else if (activeNonDefender != null)
                {
                    group.Add(CheckStatus.Info, "Microsoft Defender",
                        $"Passive - \"{activeNonDefender}\" is the active antivirus.");
                }
                else
                {
                    var st = anyAvEnabled ? CheckStatus.Warn : CheckStatus.Fail;
                    group.Add(st, "Microsoft Defender Antivirus",
                        "Disabled and no other active antivirus detected.");
                }
            }
            else if (!anyAvEnabled)
            {
                group.Add(CheckStatus.Fail, "Antivirus",
                    "No antivirus protection detected.");
            }

            // Windows Firewall profiles
            if (root.TryGetProperty("Firewall", out var fw) && fw.ValueKind == JsonValueKind.Object)
            {
                foreach (var prof in fw.EnumerateObject())
                {
                    bool on = prof.Value.ValueKind == JsonValueKind.True ||
                              (prof.Value.ValueKind == JsonValueKind.Number && prof.Value.GetInt32() != 0);
                    group.Add(on ? CheckStatus.Pass : CheckStatus.Fail,
                        $"Firewall - {prof.Name} profile",
                        on ? "Enabled." : "DISABLED.");
                }
            }

            // Secure Boot (may be null when not elevated or not UEFI)
            if (root.TryGetProperty("SecureBoot", out var sb))
            {
                if (sb.ValueKind == JsonValueKind.True)
                    group.Add(CheckStatus.Pass, "Secure Boot", "Enabled.");
                else if (sb.ValueKind == JsonValueKind.False)
                    group.Add(CheckStatus.Warn, "Secure Boot", "Disabled (or legacy BIOS).");
                else
                    group.Add(CheckStatus.Info, "Secure Boot",
                        "Unknown - run elevated to read this, or system is non-UEFI.");
            }
        }

        private static void AddBool(CheckGroup group, JsonElement obj, string prop,
                                    string name, bool failWhenOff)
        {
            if (!obj.TryGetProperty(prop, out var el)) return;
            bool on = el.ValueKind == JsonValueKind.True;
            CheckStatus st = on ? CheckStatus.Pass : (failWhenOff ? CheckStatus.Fail : CheckStatus.Warn);
            group.Add(st, name, on ? "Enabled." : "Not enabled.");
        }

        // ----------------------------------------------------------------- //
        // PowerShell helper - one shot, returns parsed JSON root element.
        // ----------------------------------------------------------------- //
        private static JsonElement? QueryPowerShellSecurity()
        {
            const string script = @"
$ErrorActionPreference='SilentlyContinue'
$r=[ordered]@{}
$d=Get-MpComputerStatus
if($d){
  $r.Defender=[ordered]@{
    AntivirusEnabled=[bool]$d.AntivirusEnabled
    RealTimeProtectionEnabled=[bool]$d.RealTimeProtectionEnabled
    AntispywareEnabled=[bool]$d.AntispywareEnabled
    BehaviorMonitorEnabled=[bool]$d.BehaviorMonitorEnabled
    NISEnabled=[bool]$d.NISEnabled
    IsTamperProtected=[bool]$d.IsTamperProtected
    AntivirusSignatureAge=[int]$d.AntivirusSignatureAge
  }
}
$av=@()
try {
  foreach($a in (Get-CimInstance -Namespace root\SecurityCenter2 -ClassName AntiVirusProduct)){
    $hex='{0:x6}' -f [int]$a.productState
    $on = ($hex.Substring(2,2) -in '10','11')
    $av += [ordered]@{ Name=[string]$a.displayName; Enabled=[bool]$on }
  }
} catch {}
$r.AntivirusProducts=$av
$fw=[ordered]@{}
foreach($p in (Get-NetFirewallProfile)){ $fw[[string]$p.Name]=[bool]$p.Enabled }
$r.Firewall=$fw
$sb=$null
try { $sb=[bool](Confirm-SecureBootUEFI) } catch { $sb=$null }
$r.SecureBoot=$sb
$r | ConvertTo-Json -Compress -Depth 5
";
            return RunPowerShellJson(script);
        }

        /// <summary>
        /// Runs a PowerShell script (fed via stdin) and returns its JSON output
        /// as a detached <see cref="JsonElement"/>, or null on any failure.
        /// </summary>
        private static JsonElement? RunPowerShellJson(string script)
        {
            // -EncodedCommand (base64 UTF-16LE) runs multi-line scripts reliably and
            // sidesteps stdin/quoting issues. Progress/verbose streams go to stderr,
            // which we don't read, so stdout stays clean JSON.
            string full = "$ProgressPreference='SilentlyContinue';\n" + script;
            string encoded = Convert.ToBase64String(Encoding.Unicode.GetBytes(full));

            var psi = new ProcessStartInfo
            {
                FileName = "powershell.exe",
                Arguments = "-NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand " + encoded,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
                StandardOutputEncoding = Encoding.UTF8,
            };

            try
            {
                using var proc = Process.Start(psi);
                if (proc == null) return null;

                string output = proc.StandardOutput.ReadToEnd();
                proc.WaitForExit(30000);

                output = output.Trim();
                if (string.IsNullOrEmpty(output)) return null;

                // Belt-and-suspenders: isolate the (single-line, -Compress) JSON if any
                // CLIXML/progress noise ever leaks onto stdout.
                if (output[0] is not ('{' or '[' or '"'))
                {
                    foreach (var line in output.Split('\n'))
                    {
                        string t = line.Trim();
                        if (t.Length > 0 && t[0] is '{' or '[' or '"') { output = t; break; }
                    }
                }

                // Clone the root so it survives disposal of the JsonDocument.
                using var doc = JsonDocument.Parse(output);
                return doc.RootElement.Clone();
            }
            catch
            {
                return null;
            }
        }

        // ----------------------------------------------------------------- //
        // Registry helpers (HKLM reads succeed for normal users).
        // ----------------------------------------------------------------- //
        private static int ReadHklmDword(string subkey, string value, int fallback)
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(subkey);
                if (key?.GetValue(value) is int i) return i;
            }
            catch { /* fall through */ }
            return fallback;
        }

        private static string ReadHklmString(string subkey, string value)
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(subkey);
                return key?.GetValue(value) as string ?? string.Empty;
            }
            catch { return string.Empty; }
        }

        // ----------------------------------------------------------------- //
        // Address classification.
        // ----------------------------------------------------------------- //
        private static bool IsPrivate(IPAddress addr)
        {
            if (addr.AddressFamily == AddressFamily.InterNetwork)
            {
                byte[] b = addr.GetAddressBytes();
                // 10.0.0.0/8
                if (b[0] == 10) return true;
                // 172.16.0.0/12
                if (b[0] == 172 && b[1] >= 16 && b[1] <= 31) return true;
                // 192.168.0.0/16
                if (b[0] == 192 && b[1] == 168) return true;
                // 169.254.0.0/16 link-local
                if (b[0] == 169 && b[1] == 254) return true;
                // 100.64.0.0/10 CGNAT
                if (b[0] == 100 && b[1] >= 64 && b[1] <= 127) return true;
                // 127.0.0.0/8 loopback
                if (b[0] == 127) return true;
                // 0.0.0.0
                if (b[0] == 0) return true;
                return false;
            }

            if (addr.AddressFamily == AddressFamily.InterNetworkV6)
            {
                if (addr.IsIPv6LinkLocal || addr.IsIPv6SiteLocal) return true;
                if (IPAddress.IsLoopback(addr)) return true;
                byte[] b = addr.GetAddressBytes();
                // fc00::/7 unique local
                if ((b[0] & 0xFE) == 0xFC) return true;
                return false;
            }
            return false;
        }
    }
}
