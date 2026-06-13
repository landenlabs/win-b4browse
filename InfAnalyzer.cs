// Copyright (c) 2026 LanDen Labs - Dennis Lang

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace B4Browse
{
    /// <summary>One finding from analysing a driver .inf file.</summary>
    public sealed class InfFinding
    {
        public TabSeverity Severity;   // Alert = high risk, Caution = review, Ok = informational
        public string Text;
        public InfFinding(TabSeverity severity, string text) { Severity = severity; Text = text; }
    }

    /// <summary>Result of analysing a driver .inf file.</summary>
    public sealed class InfAnalysis
    {
        public string InfPath = "";
        public bool Parsed;
        public List<InfFinding> Findings = new();

        /// <summary>Overall risk = the worst finding severity.</summary>
        public TabSeverity Risk =>
            Findings.Count == 0 ? TabSeverity.Ok : (TabSeverity)Findings.Max(f => (int)f.Severity);

        public string RiskLabel => Risk switch
        {
            TabSeverity.Alert => "High",
            TabSeverity.Caution => "Review",
            _ => "OK",
        };
    }

    /// <summary>
    /// Parses a Windows driver .inf (setup script) and flags security-relevant traits:
    /// missing signing catalog, anomalous DriverVer dates, blank/look-alike providers,
    /// boot-start requests, registry edits that target security tooling, and file copies
    /// into suspicious locations. See the threat model in the project notes; this is a
    /// heuristic triage aid (BYOVD / driver-spoofing hunting), not a verdict.
    /// </summary>
    public static class InfAnalyzer
    {
        // Vendors whose names attackers commonly impersonate with typos.
        private static readonly string[] KnownVendors =
        {
            "Microsoft", "Intel", "Realtek", "NVIDIA", "AMD", "Qualcomm", "Broadcom",
            "Dell", "Lenovo", "Logitech", "Synaptics", "ASUS", "Apple", "Samsung",
        };

        private static readonly string[] PlaceholderProviders =
        {
            "", "defaultcompany", "default", "todo", "provider", "oemname", "company",
        };

        // Registry targets that legitimate hardware drivers have no reason to touch.
        private static readonly string[] SecurityKeyTokens =
        {
            "windefend", "windows defender", "disableantispyware", "disableantivirus",
            "disablerealtimemonitoring", "tamperprotection", "securityhealthservice",
            "sgrmbroker", "smartscreen", "wscsvc", "\\services\\eventlog",
        };

        public static InfAnalysis Analyze(DeviceDriver d)
        {
            var a = new InfAnalysis { InfPath = d.InfPath };

            if (string.IsNullOrEmpty(d.InfPath))
            {
                a.Findings.Add(new(TabSeverity.Caution, "No .inf file is associated with this device."));
                return a;
            }
            if (!File.Exists(d.InfPath))
            {
                a.Findings.Add(new(TabSeverity.Caution, "Referenced .inf does not exist on disk: " + d.InfPath));
                return a;
            }

            InfFile inf;
            try { inf = InfFile.Parse(ReadInf(d.InfPath)); }
            catch (Exception ex)
            {
                a.Findings.Add(new(TabSeverity.Caution, "Could not read/parse the .inf: " + ex.Message));
                return a;
            }
            a.Parsed = true;

            CheckCatalogAndSignature(inf, d, a);
            CheckDriverVer(inf, d, a);
            CheckProvider(inf, a);
            CheckBootStart(inf, a);
            CheckRegistry(inf, a);
            CheckCopyFiles(inf, a);

            if (a.Findings.Count == 0)
                a.Findings.Add(new(TabSeverity.Ok, "No suspicious directives found in the .inf."));
            return a;
        }

        // 1. Signing catalog ([Version] CatalogFile) cross-referenced with the OS signed flag.
        private static void CheckCatalogAndSignature(InfFile inf, DeviceDriver d, InfAnalysis a)
        {
            string cat = inf.GetValue("Version", "CatalogFile");
            if (cat.Length > 0)
                a.Findings.Add(new(TabSeverity.Ok, $"Signing catalog declared: {cat}."));
            else if (d.Signed)
                // In-box Windows drivers omit a package CatalogFile - they are covered by the
                // OS master catalog. Only notable, not suspicious, when the OS confirms signed.
                a.Findings.Add(new(TabSeverity.Ok,
                    "No package CatalogFile (typical of in-box drivers; OS reports the driver as signed)."));
            else
                a.Findings.Add(new(TabSeverity.Alert,
                    "No CatalogFile in [Version] and the OS reports the driver UNSIGNED."));

            if (!d.Signed && cat.Length > 0)
                a.Findings.Add(new(TabSeverity.Alert,
                    "Driver is reported UNSIGNED by Windows (Win32_PnPSignedDriver) despite declaring a catalog."));
        }

        // 2. DriverVer date: flag future dates and implausibly old (back-dated) drivers.
        private static void CheckDriverVer(InfFile inf, DeviceDriver d, InfAnalysis a)
        {
            string dv = inf.GetValue("Version", "DriverVer");
            if (dv.Length == 0) { a.Findings.Add(new(TabSeverity.Caution, "No DriverVer line in [Version].")); return; }

            string datePart = dv.Split(',')[0].Trim();
            if (!DateTime.TryParse(datePart, System.Globalization.CultureInfo.InvariantCulture,
                    System.Globalization.DateTimeStyles.None, out var date))
            {
                a.Findings.Add(new(TabSeverity.Ok, $"DriverVer present but date unparsable: '{dv}'."));
                return;
            }

            if (date > DateTime.Now.AddDays(2))
                a.Findings.Add(new(TabSeverity.Alert,
                    $"DriverVer date {date:yyyy-MM-dd} is in the future - possible time-stamp tampering."));
            else if (date.Year < 2000)
                a.Findings.Add(new(TabSeverity.Caution,
                    $"DriverVer date {date:yyyy-MM-dd} is implausibly old - possible back-dating."));
            else
                a.Findings.Add(new(TabSeverity.Ok, $"DriverVer date {date:yyyy-MM-dd}."));
        }

        // 3. Provider realism: blank/placeholder, or a look-alike of a known vendor.
        private static void CheckProvider(InfFile inf, InfAnalysis a)
        {
            string provider = inf.Resolve(inf.GetValue("Version", "Provider")).Trim();
            if (PlaceholderProviders.Contains(provider.ToLowerInvariant()))
            {
                a.Findings.Add(new(TabSeverity.Caution,
                    $"Provider is blank/placeholder ('{provider}') - legitimate drivers name a real vendor."));
                return;
            }

            string token = provider.Split(new[] { ' ', ',', '.' }, StringSplitOptions.RemoveEmptyEntries).FirstOrDefault() ?? "";
            foreach (var vendor in KnownVendors)
            {
                if (token.Equals(vendor, StringComparison.OrdinalIgnoreCase)) break;       // exact -> fine
                if (provider.IndexOf(vendor, StringComparison.OrdinalIgnoreCase) >= 0) break; // contains vendor -> fine
                if (token.Length >= 4 && Math.Abs(token.Length - vendor.Length) <= 1 &&
                    char.ToLowerInvariant(token[0]) == char.ToLowerInvariant(vendor[0]) &&
                    Levenshtein(token.ToLowerInvariant(), vendor.ToLowerInvariant()) is 1 or 2)
                {
                    a.Findings.Add(new(TabSeverity.Caution,
                        $"Provider '{provider}' closely resembles '{vendor}' - verify it is not a spoof."));
                    break;
                }
            }
        }

        // 4. Boot-start: a driver that loads before security software (Start/StartType = 0).
        private static void CheckBootStart(InfFile inf, InfAnalysis a)
        {
            foreach (var (_, lines) in inf.Sections)
                foreach (var line in lines)
                {
                    // AddReg row: root, subkey, value-name, flags, data  (e.g. HKR,,Start,0x00010001,0)
                    var f = line.Split(',');
                    if (f.Length >= 5 && StripQuotes(f[2].Trim()).Equals("Start", StringComparison.OrdinalIgnoreCase) &&
                        f[^1].Trim() == "0")
                    {
                        a.Findings.Add(new(TabSeverity.Caution,
                            "Requests Boot-start (Start = 0) - the driver loads before security software."));
                        return;
                    }
                    // Service install directive: StartType = 0  /  StartType = %SERVICE_BOOT_START%
                    int eq = line.IndexOf('=');
                    if (eq > 0 && line.Substring(0, eq).Trim().Equals("StartType", StringComparison.OrdinalIgnoreCase))
                    {
                        string v = line.Substring(eq + 1).Trim();
                        if (v == "0" || v.IndexOf("BOOT_START", StringComparison.OrdinalIgnoreCase) >= 0)
                        {
                            a.Findings.Add(new(TabSeverity.Caution,
                                "Service install requests Boot-start (StartType = 0)."));
                            return;
                        }
                    }
                }
        }

        // 5a. Registry edits that target security tooling or the event log (smoking gun).
        private static void CheckRegistry(InfFile inf, InfAnalysis a)
        {
            var addRegSections = inf.ReferencedSections("AddReg").ToList();
            var delRegSections = inf.ReferencedSections("DelReg").ToList();

            bool flaggedSecurity = false;
            foreach (var sec in addRegSections.Concat(delRegSections))
            {
                if (!inf.Sections.TryGetValue(sec, out var lines)) continue;
                foreach (var line in lines)
                {
                    string low = line.ToLowerInvariant();
                    if (SecurityKeyTokens.Any(t => low.Contains(t)))
                    {
                        a.Findings.Add(new(TabSeverity.Alert,
                            $"Registry edit targets security/logging keys: \"{Trim(line, 90)}\"."));
                        flaggedSecurity = true;
                        break;
                    }
                }
                if (flaggedSecurity) break;
            }

            // 5b. DelReg of service keys is a known way to blind endpoint tools.
            if (!flaggedSecurity && delRegSections.Count > 0)
            {
                bool delServices = delRegSections.Any(s =>
                    inf.Sections.TryGetValue(s, out var l) &&
                    l.Any(x => x.ToLowerInvariant().Contains("\\services\\")));
                if (delServices)
                    a.Findings.Add(new(TabSeverity.Caution,
                        "DelReg removes entries under \\Services\\ - review what is being deleted."));
            }
        }

        // 5c. CopyFiles into temp/user-writable locations.
        private static void CheckCopyFiles(InfFile inf, InfAnalysis a)
        {
            foreach (var (name, lines) in inf.Sections)
            {
                if (name.IndexOf("DestinationDirs", StringComparison.OrdinalIgnoreCase) < 0 &&
                    name.IndexOf("SourceDisksFiles", StringComparison.OrdinalIgnoreCase) < 0)
                    continue;
                foreach (var line in lines)
                {
                    string low = line.ToLowerInvariant();
                    if (low.Contains(@"\temp\") || low.Contains(@"\tmp\") ||
                        low.Contains(@"\downloads\") || low.Contains(@"\appdata\"))
                    {
                        a.Findings.Add(new(TabSeverity.Caution,
                            $"File path points to a user-writable/temp location: \"{Trim(line, 90)}\"."));
                        return;
                    }
                }
            }
        }

        // ---- helpers ----------------------------------------------------- //
        private static string ReadInf(string path)
        {
            var b = File.ReadAllBytes(path);
            if (b.Length >= 2 && b[0] == 0xFF && b[1] == 0xFE) return Encoding.Unicode.GetString(b, 2, b.Length - 2);
            if (b.Length >= 2 && b[0] == 0xFE && b[1] == 0xFF) return Encoding.BigEndianUnicode.GetString(b, 2, b.Length - 2);
            if (b.Length >= 3 && b[0] == 0xEF && b[1] == 0xBB && b[2] == 0xBF) return Encoding.UTF8.GetString(b, 3, b.Length - 3);
            return Encoding.Latin1.GetString(b);   // INFs are typically ANSI; Latin1 never throws
        }

        internal static string StripQuotes(string s)
        {
            s = s.Trim();
            return s.Length >= 2 && s[0] == '"' && s[^1] == '"' ? s.Substring(1, s.Length - 2) : s;
        }

        private static string Trim(string s, int max) => s.Length <= max ? s : s.Substring(0, max) + "...";

        private static int Levenshtein(string a, string b)
        {
            var d = new int[a.Length + 1, b.Length + 1];
            for (int i = 0; i <= a.Length; i++) d[i, 0] = i;
            for (int j = 0; j <= b.Length; j++) d[0, j] = j;
            for (int i = 1; i <= a.Length; i++)
                for (int j = 1; j <= b.Length; j++)
                {
                    int cost = a[i - 1] == b[j - 1] ? 0 : 1;
                    d[i, j] = Math.Min(Math.Min(d[i - 1, j] + 1, d[i, j - 1] + 1), d[i - 1, j - 1] + cost);
                }
            return d[a.Length, b.Length];
        }
    }

    /// <summary>Minimal INF (INI-like) reader: sections, line continuations, comments, %Strings% tokens.</summary>
    internal sealed class InfFile
    {
        public readonly Dictionary<string, List<string>> Sections = new(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<string, string> _strings = new(StringComparer.OrdinalIgnoreCase);

        public static InfFile Parse(string text)
        {
            var f = new InfFile();
            string? cur = null;
            foreach (var logical in LogicalLines(text))
            {
                string line = logical.Trim();
                if (line.Length == 0) continue;
                if (line[0] == '[' && line[^1] == ']')
                {
                    cur = line.Substring(1, line.Length - 2).Trim();
                    if (!f.Sections.ContainsKey(cur)) f.Sections[cur] = new List<string>();
                    continue;
                }
                if (cur != null) f.Sections[cur].Add(line);
            }

            if (f.Sections.TryGetValue("Strings", out var st))
                foreach (var l in st)
                {
                    int eq = l.IndexOf('=');
                    if (eq <= 0) continue;
                    f._strings[l.Substring(0, eq).Trim()] = InfAnalyzer.StripQuotes(l.Substring(eq + 1));
                }
            return f;
        }

        /// <summary>Value of the first key in <paramref name="section"/> whose name starts with
        /// <paramref name="keyPrefix"/> (covers decorated keys like CatalogFile.NTamd64).</summary>
        public string GetValue(string section, string keyPrefix)
        {
            if (!Sections.TryGetValue(section, out var lines)) return "";
            foreach (var l in lines)
            {
                int eq = l.IndexOf('=');
                if (eq <= 0) continue;
                if (l.Substring(0, eq).Trim().StartsWith(keyPrefix, StringComparison.OrdinalIgnoreCase))
                    return InfAnalyzer.StripQuotes(l.Substring(eq + 1));
            }
            return "";
        }

        /// <summary>Section names referenced by a directive (e.g. AddReg=Sec1,Sec2) anywhere in the file.</summary>
        public IEnumerable<string> ReferencedSections(string directive)
        {
            foreach (var (_, lines) in Sections)
                foreach (var l in lines)
                {
                    int eq = l.IndexOf('=');
                    if (eq <= 0) continue;
                    string k = l.Substring(0, eq).Trim();
                    if (k.Equals(directive, StringComparison.OrdinalIgnoreCase) ||
                        k.StartsWith(directive + ".", StringComparison.OrdinalIgnoreCase))
                        foreach (var s in l.Substring(eq + 1).Split(','))
                            if (s.Trim().Length > 0)
                                yield return s.Trim();
                }
        }

        public string Resolve(string v)
        {
            if (v.IndexOf('%') < 0) return v;
            var sb = new StringBuilder();
            int i = 0;
            while (i < v.Length)
            {
                if (v[i] == '%')
                {
                    int j = v.IndexOf('%', i + 1);
                    if (j < 0) { sb.Append(v.Substring(i)); break; }
                    string key = v.Substring(i + 1, j - i - 1);
                    sb.Append(key.Length == 0 ? "%" : (_strings.TryGetValue(key, out var val) ? val : key));
                    i = j + 1;
                }
                else sb.Append(v[i++]);
            }
            return sb.ToString();
        }

        private static IEnumerable<string> LogicalLines(string text)
        {
            var raw = text.Replace("\r\n", "\n").Replace('\r', '\n').Split('\n');
            var sb = new StringBuilder();
            foreach (var line0 in raw)
            {
                string line = StripComment(line0);
                if (line.TrimEnd().EndsWith("\\"))
                {
                    string t = line.TrimEnd();
                    sb.Append(t.Substring(0, t.Length - 1));
                    continue;
                }
                sb.Append(line);
                yield return sb.ToString();
                sb.Clear();
            }
            if (sb.Length > 0) yield return sb.ToString();
        }

        private static string StripComment(string line)
        {
            bool inQuote = false;
            for (int i = 0; i < line.Length; i++)
            {
                char c = line[i];
                if (c == '"') inQuote = !inQuote;
                else if (c == ';' && !inQuote) return line.Substring(0, i);
            }
            return line;
        }
    }
}
