using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using System.Xml.Linq;

namespace BrowseSafe
{
    /// <summary>
    /// Deeper network probes: the *true* upstream DNS resolver behind the router,
    /// and identification of the connected router (make / model / firmware).
    /// </summary>
    public static partial class SafetyChecks
    {
        /// <summary>Runs every check in display order. Used by the headless report mode.</summary>
        public static List<CheckGroup> RunAll() => new()
        {
            CheckDnsServers(),
            CheckRouter(),
            CheckUpstreamResolver(),
            CheckDnsLookups(),
            CheckCrossResolver(),
            CheckHostsFile(),
            CheckEmailDns(),
            CheckProxy(),
            CheckTimeSync(),
            CheckWindowsSecurity(),
        };

        // One shared client for the small best-effort HTTP calls (org/vendor/UPnP xml).
        private static readonly HttpClient Http = CreateHttp();

        private static HttpClient CreateHttp()
        {
            var c = new HttpClient { Timeout = TimeSpan.FromSeconds(6) };
            c.DefaultRequestHeaders.UserAgent.ParseAdd("BrowseSafe/1.0");
            return c;
        }

        // ----------------------------------------------------------------- //
        // 2. Connected router (make / model / firmware)
        // ----------------------------------------------------------------- //
        public static CheckGroup CheckRouter()
        {
            var group = new CheckGroup("2. Connected Router");

            IPAddress? gw = GetDefaultGatewayV4();
            if (gw == null)
            {
                group.Add(CheckStatus.Warn, "Default gateway", "No IPv4 default gateway found.");
                return group;
            }
            group.Add(CheckStatus.Info, "Default gateway", gw.ToString());

            // --- Layer-2: MAC address of the gateway + OUI vendor ---
            byte[]? mac = GetMacViaArp(gw);
            if (mac != null && mac.Length == 6 && mac.Any(b => b != 0))
            {
                string macStr = string.Join("-", mac.Select(b => b.ToString("X2")));
                string oui = $"{mac[0]:X2}-{mac[1]:X2}-{mac[2]:X2}";
                string vendor = LookupOuiVendor(oui);
                group.Add(CheckStatus.Pass, "Gateway MAC",
                    vendor.Length > 0 ? $"{macStr}   (OUI {oui} = {vendor})"
                                      : $"{macStr}   (OUI {oui})");
            }
            else
            {
                group.Add(CheckStatus.Info, "Gateway MAC",
                    "Could not read (gateway may be off the local segment).");
            }

            // --- UPnP / SSDP: the richest source of make/model/firmware ---
            var dev = DiscoverUpnpRouter(gw);
            if (dev != null)
            {
                string model = string.Join(" ", new[] { dev.Manufacturer, dev.ModelName }
                                   .Where(s => !string.IsNullOrWhiteSpace(s)));
                if (!string.IsNullOrWhiteSpace(dev.ModelNumber)) model += $"  (v{dev.ModelNumber})";
                if (model.Trim().Length > 0)
                    group.Add(CheckStatus.Pass, "Router (via UPnP)", model.Trim());

                if (!string.IsNullOrWhiteSpace(dev.FriendlyName))
                    group.Add(CheckStatus.Info, "Device name", dev.FriendlyName!);
                if (!string.IsNullOrWhiteSpace(dev.ModelDescription) &&
                    !string.Equals(dev.ModelDescription, dev.ModelName, StringComparison.OrdinalIgnoreCase))
                    group.Add(CheckStatus.Info, "Model description", dev.ModelDescription!);
                if (!string.IsNullOrWhiteSpace(dev.Server))
                    group.Add(CheckStatus.Info, "UPnP server banner", dev.Server!);
            }
            else
            {
                group.Add(CheckStatus.Info, "UPnP/SSDP",
                    "Router offered no UPnP description (UPnP/IGD likely disabled). " +
                    "Exact model/firmware can't be read without signing in.");
            }

            return group;
        }

        // ----------------------------------------------------------------- //
        // 3. Actual upstream DNS resolver (the "true DNS" behind the router)
        // ----------------------------------------------------------------- //
        public static CheckGroup CheckUpstreamResolver()
        {
            var group = new CheckGroup("3. Actual Upstream DNS Resolver");

            IPAddress? configured = GetPrimaryDns();
            if (configured != null)
                group.Add(CheckStatus.Info, "Configured resolver",
                    $"{configured}  (the address this PC sends queries to).");

            // The router forwards our query; the authoritative "whoami" server
            // answers with the public IP of whatever resolver actually reached it.
            IPAddress? egress = null;
            try
            {
                egress = Dns.GetHostAddresses("whoami.akamai.net")
                            .FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork)
                         ?? Dns.GetHostAddresses("whoami.akamai.net").FirstOrDefault();
            }
            catch { /* fall back to Google below */ }

            // Google cross-check (also reveals EDNS Client Subnet leakage).
            string? googleSeen = null;
            bool ecs = false;
            try
            {
                var txt = ResolveTxt("o-o.myaddr.l.google.com");
                googleSeen = txt.FirstOrDefault(s => IPAddress.TryParse(s, out _));
                ecs = txt.Any(s => s.Contains("edns0-client-subnet", StringComparison.OrdinalIgnoreCase));
            }
            catch { /* best-effort */ }

            if (egress == null && googleSeen != null)
                IPAddress.TryParse(googleSeen, out egress);

            if (egress == null)
            {
                group.Add(CheckStatus.Warn, "Upstream resolver",
                    "Could not determine the true upstream resolver (whoami queries failed " +
                    "- they may be blocked, or Chrome/OS DoH is in use).");
                AddChromeDohNote(group);
                return group;
            }

            string ptr = "";
            try { ptr = Dns.GetHostEntry(egress).HostName; } catch { /* no PTR */ }

            string detail = egress.ToString();
            if (!string.IsNullOrEmpty(ptr)) detail += $"   ({ptr})";
            group.Add(CheckStatus.Pass, "True recursive resolver", detail);

            string org = LookupIpOrg(egress.ToString());
            if (org.Length > 0)
                group.Add(CheckStatus.Info, "Resolver operator", org);

            // Interpret what we found relative to the configured resolver.
            string known = KnownResolverName(egress, ptr, org);
            string meaning;
            if (configured != null && IsPrivate(configured))
            {
                meaning = known.Length > 0
                    ? $"Your router forwards DNS to {known} - that performs the real lookups."
                    : "Your router forwards DNS to the operator above (typically your ISP); " +
                      "it is NOT resolving locally.";
            }
            else if (configured != null && configured.Equals(egress))
            {
                meaning = "You query this public resolver directly (no router forwarding).";
            }
            else
            {
                meaning = known.Length > 0
                    ? $"Queries ultimately egress via {known}."
                    : "Queries ultimately egress via the operator shown above.";
            }
            group.Add(CheckStatus.Info, "What this means", meaning);

            if (googleSeen != null && !string.Equals(googleSeen, egress.ToString()))
                group.Add(CheckStatus.Info, "Google cross-check",
                    $"Google's resolver-id reported {googleSeen} (load-balanced resolver pool).");

            if (ecs)
                group.Add(CheckStatus.Warn, "EDNS Client Subnet",
                    "Your network prefix is forwarded to authoritative servers (reduces DNS privacy).");

            AddChromeDohNote(group);
            return group;
        }

        /// <summary>
        /// Chrome can use its own encrypted DNS (DoH), which bypasses the OS
        /// resolver entirely - so the resolver detected above may not be what
        /// the browser uses. Report Chrome's policy-configured DoH mode.
        /// </summary>
        private static void AddChromeDohNote(CheckGroup group)
        {
            string mode = ReadHklmString(@"SOFTWARE\Policies\Google\Chrome", "DnsOverHttpsMode");
            string templates = ReadHklmString(@"SOFTWARE\Policies\Google\Chrome", "DnsOverHttpsTemplates");

            switch (mode.ToLowerInvariant())
            {
                case "secure":
                    group.Add(CheckStatus.Warn, "Chrome Secure DNS (DoH)",
                        $"Forced ON by policy ({templates}). Chrome BYPASSES the resolver above.");
                    break;
                case "off":
                    group.Add(CheckStatus.Info, "Chrome Secure DNS (DoH)",
                        "Disabled by policy - Chrome uses the system resolver shown above.");
                    break;
                case "automatic":
                    group.Add(CheckStatus.Info, "Chrome Secure DNS (DoH)",
                        "Policy = automatic - Chrome may upgrade to DoH if the resolver supports it.");
                    break;
                default:
                    group.Add(CheckStatus.Info, "Chrome Secure DNS (DoH)",
                        "Not set by policy. Chrome default may use DoH (Settings > Privacy > Use secure DNS), " +
                        "which can bypass the resolver above.");
                    break;
            }
        }

        // ----------------------------------------------------------------- //
        // 5. Cross-resolver DNS comparison
        // ----------------------------------------------------------------- //
        private static readonly (string Name, string Ip)[] ReferenceResolvers =
        {
            ("Cloudflare", "1.1.1.1"),
            ("Quad9",      "9.9.9.9"),
            ("Google",     "8.8.8.8"),
        };

        public static CheckGroup CheckCrossResolver()
        {
            var group = new CheckGroup("5. Cross-Resolver DNS Comparison");

            bool wantV6 = IsIPv6Enabled();

            // Query the three public resolvers in parallel (one process each), each
            // resolving the whole domain set. Reuses Resolve-DnsName -Server (no NuGet).
            var tasks = ReferenceResolvers
                .Select(s => Task.Run(() => (s.Ip, Data: QueryServerAll(s.Ip, wantV6))))
                .ToArray();
            Task.WaitAll(tasks);

            var byServer = new Dictionary<string, Dictionary<string, (List<IPAddress> A, List<IPAddress> Aaaa)>>();
            foreach (var t in tasks) byServer[t.Result.Ip] = t.Result.Data;

            group.Add(CheckStatus.Info, "Reference resolvers",
                "Cloudflare 1.1.1.1, Quad9 9.9.9.9, Google 8.8.8.8  (queried in parallel).");
            group.Add(CheckStatus.Info, "How to read",
                "Cells show how each resolver's answer compares to Local: identical / /24 / /16 / no match / fail. " +
                "Valid = PASS when Local matches at least one reference resolver.");

            BuildComparisonTable(group, byServer, AddressFamily.InterNetwork,
                "IPv4 (A records  -  prefix tiers /24, /16)", 24, 16);

            if (wantV6)
                BuildComparisonTable(group, byServer, AddressFamily.InterNetworkV6,
                    "IPv6 (AAAA records  -  prefix tiers /64, /48)", 64, 48);
            else
                group.Add(CheckStatus.Info, "IPv6",
                    "No global IPv6 connectivity detected - IPv6 comparison skipped.");

            return group;
        }

        private static void BuildComparisonTable(
            CheckGroup group,
            Dictionary<string, Dictionary<string, (List<IPAddress> A, List<IPAddress> Aaaa)>> byServer,
            AddressFamily family, string label, int bits1, int bits2)
        {
            string tier1 = "/" + bits1;
            string tier2 = "/" + bits2;
            var failed = new List<string>();
            var unreachable = new List<string>();

            group.AddRow(CheckStatus.Info, "");
            group.AddRow(CheckStatus.Info, label);
            group.AddRow(CheckStatus.Info,
                Row("Valid", "Domain", "Local", ReferenceResolvers[0].Name,
                    ReferenceResolvers[1].Name, ReferenceResolvers[2].Name));
            group.AddRow(CheckStatus.Info,
                Row("-----", "------------------", "-------", "----------", "----------", "----------"));

            foreach (var domain in TestHosts)
            {
                List<IPAddress> local = LocalLookup(domain, family);

                var cells = new string[3];
                int matched = 0, refFails = 0;
                for (int i = 0; i < ReferenceResolvers.Length; i++)
                {
                    var data = byServer[ReferenceResolvers[i].Ip];
                    List<IPAddress> refIps = data.TryGetValue(domain, out var v)
                        ? (family == AddressFamily.InterNetwork ? v.A : v.Aaaa)
                        : new List<IPAddress>();

                    (string text, int rank) = MatchTier(local, refIps, bits1, bits2, tier1, tier2);
                    cells[i] = text;
                    if (rank >= 1) matched++;
                    if (refIps.Count == 0) refFails++;
                }

                CheckStatus status;
                string valid;
                if (local.Count == 0) { status = CheckStatus.Info; valid = "n/a"; }
                else if (refFails == 3) { status = CheckStatus.Warn; valid = "WARN"; }
                else if (matched >= 1) { status = CheckStatus.Pass; valid = "PASS"; }
                else { status = CheckStatus.Fail; valid = "FAIL"; }

                string localCell = local.Count == 0 ? "none" : $"{local.Count} ip";
                group.AddRow(status, Row(valid, domain, localCell, cells[0], cells[1], cells[2]));

                if (status == CheckStatus.Fail) failed.Add(domain);
                else if (status == CheckStatus.Warn) unreachable.Add(domain);
            }

            string fam = family == AddressFamily.InterNetwork ? "IPv4" : "IPv6";
            if (failed.Count == 0 && unreachable.Count == 0)
                group.Add(CheckStatus.Pass, $"{fam} cross-resolver check",
                    "Every resolvable domain matched at least one reference resolver.");
            else
            {
                if (unreachable.Count > 0)
                    group.Add(CheckStatus.Warn, $"{fam} reference resolvers unreachable",
                        $"{string.Join(", ", unreachable)} - public DNS (port 53) may be blocked on this network.");
                if (failed.Count > 0)
                    group.Add(CheckStatus.Warn, $"{fam} domains matched no reference resolver",
                        $"{string.Join(", ", failed)} - usually geo-distributed CDNs (e.g. Yahoo), " +
                        "occasionally local DNS tampering. Review those rows.");
            }
        }

        /// <summary>Best match level between the local answer set and one resolver's set.</summary>
        private static (string Text, int Rank) MatchTier(
            List<IPAddress> local, List<IPAddress> reference, int bits1, int bits2,
            string tier1, string tier2)
        {
            if (reference.Count == 0) return ("fail", 0);
            if (local.Count == 0) return ("n/a", 0);

            foreach (var a in local)
                foreach (var b in reference)
                    if (a.Equals(b)) return ("identical", 3);

            foreach (var a in local)
                foreach (var b in reference)
                    if (SamePrefix(a, b, bits1)) return (tier1, 2);

            foreach (var a in local)
                foreach (var b in reference)
                    if (SamePrefix(a, b, bits2)) return (tier2, 1);

            return ("no match", 0);
        }

        /// <summary>True if the two addresses share their first <paramref name="bits"/> bits.</summary>
        private static bool SamePrefix(IPAddress a, IPAddress b, int bits)
        {
            if (a.AddressFamily != b.AddressFamily) return false;
            byte[] x = a.GetAddressBytes(), y = b.GetAddressBytes();
            int whole = bits / 8, rem = bits % 8;
            for (int i = 0; i < whole; i++)
                if (x[i] != y[i]) return false;
            if (rem > 0)
            {
                int mask = (0xFF << (8 - rem)) & 0xFF;
                if ((x[whole] & mask) != (y[whole] & mask)) return false;
            }
            return true;
        }

        private static string Row(string valid, string domain, string local, string c1, string c2, string c3)
            => $"{Trunc(valid, 5),-5} {Trunc(domain, 18),-18} {Trunc(local, 7),-7} " +
               $"{Trunc(c1, 10),-10} {Trunc(c2, 10),-10} {Trunc(c3, 10),-10}";

        private static string Trunc(string s, int w) => s.Length <= w ? s : s.Substring(0, w);

        private static List<IPAddress> LocalLookup(string host, AddressFamily family)
        {
            try
            {
                return Dns.GetHostAddresses(host)
                          .Where(a => a.AddressFamily == family)
                          .ToList();
            }
            catch { return new List<IPAddress>(); }
        }

        /// <summary>Global (2000::/3) IPv6 connectivity on an active, non-loopback adapter.</summary>
        private static bool IsIPv6Enabled()
        {
            if (!Socket.OSSupportsIPv6) return false;
            foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (nic.OperationalStatus != OperationalStatus.Up) continue;
                if (nic.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;
                foreach (var ua in nic.GetIPProperties().UnicastAddresses)
                {
                    var a = ua.Address;
                    if (a.AddressFamily != AddressFamily.InterNetworkV6) continue;
                    if (a.IsIPv6LinkLocal || a.IsIPv6SiteLocal || IPAddress.IsLoopback(a)) continue;
                    if ((a.GetAddressBytes()[0] & 0xE0) == 0x20) return true; // 2000::/3 global unicast
                }
            }
            return false;
        }

        /// <summary>Resolves the whole domain set against one DNS server (A, and AAAA if requested).</summary>
        private static Dictionary<string, (List<IPAddress> A, List<IPAddress> Aaaa)> QueryServerAll(
            string server, bool includeV6)
        {
            var result = new Dictionary<string, (List<IPAddress>, List<IPAddress>)>();
            foreach (var d in TestHosts) result[d] = (new List<IPAddress>(), new List<IPAddress>());

            string domainList = string.Join(",", TestHosts.Select(d => $"'{d}'"));
            string aaaaBlock = includeV6
                ? "  try{ $q=@(Resolve-DnsName -Server $s -Name $d -Type AAAA -DnsOnly -ErrorAction SilentlyContinue | " +
                  "Where-Object {$_.Type -eq 'AAAA'} | ForEach-Object {$_.IPAddress}) }catch{}\n"
                : "";

            string script =
                $"$s='{server}'\n" +
                $"$ds=@({domainList})\n" +
                "$r=[ordered]@{}\n" +
                "foreach($d in $ds){\n" +
                "  $a=@(); $q=@()\n" +
                "  try{ $a=@(Resolve-DnsName -Server $s -Name $d -Type A -DnsOnly -ErrorAction SilentlyContinue | " +
                "Where-Object {$_.Type -eq 'A'} | ForEach-Object {$_.IPAddress}) }catch{}\n" +
                aaaaBlock +
                "  $r[$d]=[ordered]@{ A=@($a); AAAA=@($q) }\n" +
                "}\n" +
                "$r | ConvertTo-Json -Compress -Depth 4";

            var root = RunPowerShellJson(script);
            if (root == null || root.Value.ValueKind != JsonValueKind.Object) return result;

            foreach (var prop in root.Value.EnumerateObject())
            {
                if (!result.ContainsKey(prop.Name)) continue;
                var obj = prop.Value;
                var a = obj.TryGetProperty("A", out var ae) ? ParseIps(ae) : new List<IPAddress>();
                var q = obj.TryGetProperty("AAAA", out var qe) ? ParseIps(qe) : new List<IPAddress>();
                result[prop.Name] = (a, q);
            }
            return result;
        }

        /// <summary>Parses a JSON value (array, single string, or absent) into IPAddresses.</summary>
        private static List<IPAddress> ParseIps(JsonElement e)
        {
            var list = new List<IPAddress>();
            void Add(string? s) { if (s != null && IPAddress.TryParse(s, out var ip)) list.Add(ip); }

            if (e.ValueKind == JsonValueKind.Array)
                foreach (var item in e.EnumerateArray())
                    if (item.ValueKind == JsonValueKind.String) Add(item.GetString());
            else if (e.ValueKind == JsonValueKind.String)
                Add(e.GetString());
            return list;
        }

        // ----------------------------------------------------------------- //
        // Router discovery helpers
        // ----------------------------------------------------------------- //
        private static IPAddress? GetDefaultGatewayV4()
        {
            foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (nic.OperationalStatus != OperationalStatus.Up) continue;
                if (nic.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;
                foreach (var g in nic.GetIPProperties().GatewayAddresses)
                {
                    if (g.Address.AddressFamily == AddressFamily.InterNetwork &&
                        !g.Address.Equals(IPAddress.Any))
                        return g.Address;
                }
            }
            return null;
        }

        private static IPAddress? GetPrimaryDns()
        {
            foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (nic.OperationalStatus != OperationalStatus.Up) continue;
                if (nic.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;
                foreach (var d in nic.GetIPProperties().DnsAddresses)
                {
                    if (!IPAddress.IsLoopback(d)) return d;
                }
            }
            return null;
        }

        [DllImport("iphlpapi.dll", ExactSpelling = true)]
        private static extern int SendARP(int destIp, int srcIp, byte[] macAddr, ref int macAddrLen);

        private static byte[]? GetMacViaArp(IPAddress ip)
        {
            try
            {
                int dest = BitConverter.ToInt32(ip.GetAddressBytes(), 0);
                var mac = new byte[6];
                int len = mac.Length;
                if (SendARP(dest, 0, mac, ref len) == 0 && len >= 6)
                    return mac;
            }
            catch { /* iphlpapi unavailable */ }
            return null;
        }

        private sealed class UpnpDevice
        {
            public string? Server;
            public string? FriendlyName;
            public string? Manufacturer;
            public string? ModelName;
            public string? ModelNumber;
            public string? ModelDescription;
        }

        /// <summary>SSDP M-SEARCH for an Internet Gateway Device, then fetch its description XML.</summary>
        private static UpnpDevice? DiscoverUpnpRouter(IPAddress gateway)
        {
            string? location = null;
            string? server = null;

            try
            {
                using var udp = new UdpClient();
                udp.Client.ReceiveTimeout = 1200;
                var multicast = new IPEndPoint(IPAddress.Parse("239.255.255.250"), 1900);
                string req =
                    "M-SEARCH * HTTP/1.1\r\n" +
                    "HOST: 239.255.255.250:1900\r\n" +
                    "MAN: \"ssdp:discover\"\r\n" +
                    "MX: 2\r\n" +
                    "ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\r\n";
                byte[] data = Encoding.ASCII.GetBytes(req);
                udp.Send(data, data.Length, multicast);

                var stop = DateTime.UtcNow.AddSeconds(3);
                while (DateTime.UtcNow < stop)
                {
                    try
                    {
                        var from = new IPEndPoint(IPAddress.Any, 0);
                        byte[] resp = udp.Receive(ref from);
                        string text = Encoding.ASCII.GetString(resp);

                        string? loc = HeaderValue(text, "LOCATION");
                        string? srv = HeaderValue(text, "SERVER");

                        // Prefer the response that actually came from the gateway.
                        if (loc != null && from.Address.Equals(gateway))
                        {
                            location = loc; server = srv; break;
                        }
                        if (loc != null && location == null)
                        {
                            location = loc; server = srv;
                        }
                    }
                    catch (SocketException) { break; } // receive timeout
                }
            }
            catch { return null; }

            var dev = new UpnpDevice { Server = server };
            if (location == null)
                return server != null ? dev : null;

            try
            {
                string xml = Http.GetStringAsync(location).GetAwaiter().GetResult();
                var doc = XDocument.Parse(xml);
                var d = doc.Descendants().FirstOrDefault(e => e.Name.LocalName == "device");
                string? Get(string n) =>
                    d?.Elements().FirstOrDefault(e => e.Name.LocalName == n)?.Value?.Trim();

                dev.FriendlyName = Get("friendlyName");
                dev.Manufacturer = Get("manufacturer");
                dev.ModelName = Get("modelName");
                dev.ModelNumber = Get("modelNumber");
                dev.ModelDescription = Get("modelDescription");
            }
            catch { /* keep whatever the SSDP banner gave us */ }

            return dev;
        }

        private static string? HeaderValue(string httpText, string name)
        {
            foreach (var line in httpText.Split('\n'))
            {
                int colon = line.IndexOf(':');
                if (colon <= 0) continue;
                if (line.Substring(0, colon).Trim().Equals(name, StringComparison.OrdinalIgnoreCase))
                    return line.Substring(colon + 1).Trim();
            }
            return null;
        }

        // ----------------------------------------------------------------- //
        // Lookups (all best-effort; empty string on failure)
        // ----------------------------------------------------------------- //
        private static string LookupOuiVendor(string oui)
        {
            try
            {
                return Http.GetStringAsync($"https://api.macvendors.com/{oui}")
                           .GetAwaiter().GetResult().Trim();
            }
            catch { return ""; }
        }

        private static string LookupIpOrg(string ip)
        {
            try
            {
                string json = Http.GetStringAsync(
                    $"http://ip-api.com/json/{ip}?fields=status,isp,org,as,city,regionName,country")
                    .GetAwaiter().GetResult();
                using var doc = JsonDocument.Parse(json);
                var r = doc.RootElement;
                if (r.TryGetProperty("status", out var st) && st.GetString() != "success") return "";

                string isp = Str(r, "isp");
                string asn = Str(r, "as");
                string city = Str(r, "regionName");
                string country = Str(r, "country");

                var sb = new StringBuilder();
                if (isp.Length > 0) sb.Append(isp);
                if (asn.Length > 0) sb.Append(sb.Length > 0 ? $"  ({asn})" : asn);
                string loc = string.Join(", ", new[] { city, country }.Where(s => s.Length > 0));
                if (loc.Length > 0) sb.Append($"  -  {loc}");
                return sb.ToString();
            }
            catch { return ""; }
        }

        private static string Str(JsonElement e, string p) =>
            e.TryGetProperty(p, out var v) ? (v.GetString() ?? "") : "";

        /// <summary>Names a recognised public resolver from its egress IP / PTR / org text.</summary>
        private static string KnownResolverName(IPAddress ip, string ptr, string org)
        {
            string hay = (ptr + " " + org).ToLowerInvariant();
            if (hay.Contains("cloudflare")) return "Cloudflare (1.1.1.1)";
            if (hay.Contains("google")) return "Google Public DNS (8.8.8.8)";
            if (hay.Contains("opendns") || hay.Contains("umbrella")) return "OpenDNS";
            if (hay.Contains("quad9")) return "Quad9 (9.9.9.9)";
            if (hay.Contains("adguard")) return "AdGuard DNS";

            string s = ip.ToString();
            if (s is "1.1.1.1" or "1.0.0.1") return "Cloudflare (1.1.1.1)";
            if (s is "8.8.8.8" or "8.8.4.4") return "Google Public DNS (8.8.8.8)";
            if (s is "9.9.9.9" or "149.112.112.112") return "Quad9 (9.9.9.9)";
            if (s.StartsWith("208.67.")) return "OpenDNS";
            return "";
        }

        private static string[] ResolveTxt(string name)
        {
            string script =
                $"@(Resolve-DnsName -Type TXT -Name '{name}' -ErrorAction SilentlyContinue | " +
                "Where-Object {$_.Type -eq 'TXT'} | Select-Object -Expand Strings) | " +
                "ConvertTo-Json -Compress";
            var root = RunPowerShellJson(script);
            if (root == null) return Array.Empty<string>();

            var list = new List<string>();
            if (root.Value.ValueKind == JsonValueKind.Array)
                foreach (var e in root.Value.EnumerateArray())
                    if (e.ValueKind == JsonValueKind.String) list.Add(e.GetString()!);
            else if (root.Value.ValueKind == JsonValueKind.String)
                list.Add(root.Value.GetString()!);
            return list.ToArray();
        }
    }
}
