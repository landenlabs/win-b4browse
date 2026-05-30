using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text.Json;

namespace BrowseSafe
{
    /// <summary>
    /// Inventory / posture checks shown on their own tabs: Chrome integrity,
    /// services, processes, startup items, installed programs, device drivers.
    /// First-pass implementations - they surface what's present and flag the
    /// obviously unusual; deeper heuristics can be layered on later.
    /// </summary>
    public static partial class SafetyChecks
    {
        private const int MaxList = 30;

        // ----------------------------------------------------------------- //
        // Chrome: executable integrity
        // ----------------------------------------------------------------- //
        public static CheckGroup CheckChromeExe()
        {
            var group = new CheckGroup("Chrome Executable & Integrity");

            string? exe = FindChrome();
            if (exe == null)
            {
                group.Add(CheckStatus.Warn, "Chrome", "chrome.exe not found in standard install locations.");
                return group;
            }
            group.Add(CheckStatus.Info, "Path", exe);

            try
            {
                var fi = System.Diagnostics.FileVersionInfo.GetVersionInfo(exe);
                group.Add(CheckStatus.Info, "Version", fi.ProductVersion ?? "(unknown)");
            }
            catch { /* ignore */ }

            string? hash = Sha256File(exe);
            group.Add(hash != null ? CheckStatus.Info : CheckStatus.Warn,
                "SHA-256", hash ?? "could not hash file");

            // Authenticode signature is the meaningful integrity/tamper check.
            var (status, signer) = VerifyAuthenticode(exe);
            if (status != "Unknown")
            {
                bool google = signer.Contains("Google LLC", StringComparison.OrdinalIgnoreCase);
                CheckStatus st = status == "Valid" && google ? CheckStatus.Pass
                               : status == "Valid" ? CheckStatus.Warn
                               : CheckStatus.Fail;
                string signerShort = signer.Length > 0 ? signer.Split(',')[0] : "(none)";
                group.Add(st, "Digital signature", $"{status}  -  {signerShort}");
            }
            else
            {
                group.Add(CheckStatus.Warn, "Digital signature", "Could not read Authenticode signature.");
            }

            return group;
        }

        // ----------------------------------------------------------------- //
        // Chrome: installed extensions
        // ----------------------------------------------------------------- //
        public static CheckGroup CheckChromeExtensions()
        {
            var group = new CheckGroup("Chrome Extensions");
            var exts = GetChromeExtensions();
            if (exts.Count == 0)
            {
                group.Add(CheckStatus.Pass, "Extensions", "No installed extensions found.");
                return group;
            }

            int shown = 0;
            foreach (var x in exts.OrderBy(e => e.ProfileName).ThenBy(e => e.Name))
            {
                if (++shown > MaxList) break;
                var st = x.Unsupported ? CheckStatus.Warn : CheckStatus.Info;
                string flags = (x.Enabled ? "" : "disabled, ") + (x.Unsupported ? "MV unsupported, " : "");
                group.Add(st, x.Name,
                    $"v{x.Version}  MV{x.ManifestVersion?.ToString() ?? "?"}  [{x.ProfileName}]  {flags}id={x.Id}");
            }
            if (exts.Count > MaxList)
                group.Add(CheckStatus.Info, "...", $"{exts.Count - MaxList} more not shown.");
            group.Add(CheckStatus.Info, "Total extensions",
                $"{exts.Count} across all profiles. Review any you don't recognise at chrome://extensions.");
            return group;
        }

        // ----------------------------------------------------------------- //
        // Chrome extensions - structured (used by the Extensions grid)
        // ----------------------------------------------------------------- //
        public static List<ChromeExtension> GetChromeExtensions()
        {
            var list = new List<ChromeExtension>();
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
                int? minMv = MinManifestVersion(ReadFirstLine(Path.Combine(root, "Last Version")));
                var names = LoadProfileNames(root);

                foreach (var profileDir in SafeDirs(root))
                {
                    string profile = Path.GetFileName(profileDir);
                    if (!(profile == "Default" || profile.StartsWith("Profile", StringComparison.OrdinalIgnoreCase)))
                        continue;

                    string extRoot = Path.Combine(profileDir, "Extensions");
                    if (!Directory.Exists(extRoot)) continue;

                    var settings = LoadExtensionSettings(Path.Combine(profileDir, "Preferences"));
                    string friendly = names.TryGetValue(profile, out var fn) && fn.Length > 0 ? fn : profile;

                    foreach (var idDir in SafeDirs(extRoot))
                    {
                        string id = Path.GetFileName(idDir);
                        string? verDir = SafeDirs(idDir)
                            .Where(d => File.Exists(Path.Combine(d, "manifest.json")))
                            .OrderBy(Path.GetFileName, StringComparer.Ordinal)
                            .LastOrDefault();
                        if (verDir == null) continue;

                        var (name, version, desc, mv) = ParseManifest(Path.Combine(verDir, "manifest.json"), id);
                        bool enabled = !settings.TryGetValue(id, out int state) || state == 1;

                        list.Add(new ChromeExtension
                        {
                            ProfileDir = profile,
                            ProfileName = friendly,
                            Name = name,
                            Version = version,
                            Description = desc,
                            Id = id,
                            ManifestVersion = mv,
                            Enabled = enabled,
                            Unsupported = minMv != null && mv != null && mv < minMv,
                        });
                    }
                }
            }
            return list;
        }

        /// <summary>Minimum extension manifest_version this Chrome will load (per Last Version).</summary>
        private static int? MinManifestVersion(string? chromeVersion)
        {
            if (string.IsNullOrEmpty(chromeVersion)) return null;
            if (!int.TryParse(chromeVersion.Split('.')[0], out int major)) return null;
            return major >= 127 ? 3 : 2; // Chrome 127+ disables MV2 by default; 138+ removes it
        }

        private static string? ReadFirstLine(string path)
        {
            try { return File.Exists(path) ? File.ReadLines(path).FirstOrDefault()?.Trim() : null; }
            catch { return null; }
        }

        /// <summary>profile-dir -> friendly name, from Local State (info_cache) then per-profile Preferences.</summary>
        private static Dictionary<string, string> LoadProfileNames(string root)
        {
            var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            try
            {
                string ls = Path.Combine(root, "Local State");
                if (File.Exists(ls))
                {
                    using var doc = JsonDocument.Parse(File.ReadAllText(ls));
                    if (doc.RootElement.TryGetProperty("profile", out var prof) &&
                        prof.TryGetProperty("info_cache", out var cache) &&
                        cache.ValueKind == JsonValueKind.Object)
                    {
                        foreach (var p in cache.EnumerateObject())
                        {
                            string nm = JStr(p.Value, "name");
                            if (nm.Length == 0) nm = JStr(p.Value, "shortcut_name");
                            if (nm.Length == 0) nm = JStr(p.Value, "gaia_name");
                            if (nm.Length > 0) map[p.Name] = nm;
                        }
                    }
                }
            }
            catch { /* ignore */ }
            return map;
        }

        /// <summary>extension-id -> state (1=enabled, 0=disabled) from a profile's Preferences.</summary>
        private static Dictionary<string, int> LoadExtensionSettings(string prefsPath)
        {
            var map = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            try
            {
                if (!File.Exists(prefsPath)) return map;
                using var doc = JsonDocument.Parse(File.ReadAllText(prefsPath));
                if (doc.RootElement.TryGetProperty("extensions", out var ex) &&
                    ex.TryGetProperty("settings", out var s) && s.ValueKind == JsonValueKind.Object)
                {
                    foreach (var p in s.EnumerateObject())
                        if (p.Value.TryGetProperty("state", out var st) && st.TryGetInt32(out int v))
                            map[p.Name] = v;
                }
            }
            catch { /* ignore */ }
            return map;
        }

        private static (string Name, string Version, string Desc, int? Mv) ParseManifest(string path, string fallbackId)
        {
            try
            {
                using var doc = JsonDocument.Parse(File.ReadAllText(path));
                var root = doc.RootElement;
                string name = root.TryGetProperty("name", out var n) ? (n.GetString() ?? "") : "";
                string version = root.TryGetProperty("version", out var v) ? (v.GetString() ?? "?") : "?";
                string desc = root.TryGetProperty("description", out var d) ? (d.GetString() ?? "") : "";
                int? mv = root.TryGetProperty("manifest_version", out var m) && m.TryGetInt32(out int mi) ? mi : null;
                string locale = root.TryGetProperty("default_locale", out var dl) ? (dl.GetString() ?? "") : "";

                string extRoot = Path.GetDirectoryName(path) ?? "";
                name = ResolveMsg(extRoot, name, locale);
                desc = ResolveMsg(extRoot, desc, locale);
                if (name.Length == 0 || name.StartsWith("__MSG_", StringComparison.OrdinalIgnoreCase)) name = fallbackId;
                return (name, version, desc, mv);
            }
            catch { return (fallbackId, "?", "", null); }
        }

        /// <summary>Resolves a Chrome __MSG_key__ string via _locales/&lt;locale&gt;/messages.json.</summary>
        private static string ResolveMsg(string extRoot, string value, string defaultLocale)
        {
            if (!value.StartsWith("__MSG_", StringComparison.Ordinal) || !value.EndsWith("__", StringComparison.Ordinal))
                return value;
            string key = value.Substring(6, value.Length - 8);
            if (key.Length == 0) return value;

            string localesDir = Path.Combine(extRoot, "_locales");
            if (!Directory.Exists(localesDir)) return value;

            var candidates = new List<string>();
            if (defaultLocale.Length > 0)
            {
                candidates.Add(defaultLocale);
                candidates.Add(defaultLocale.Replace('-', '_'));
                string fam = defaultLocale.Split('-', '_')[0];
                if (fam.Length > 0) candidates.Add(fam);
            }
            foreach (var l in new[] { "en", "en_US", "en_GB" }) candidates.Add(l);

            foreach (var loc in candidates)
            {
                string msgs = Path.Combine(localesDir, loc, "messages.json");
                if (!File.Exists(msgs)) continue;
                try
                {
                    using var doc = JsonDocument.Parse(File.ReadAllText(msgs));
                    foreach (var p in doc.RootElement.EnumerateObject())
                        if (string.Equals(p.Name, key, StringComparison.OrdinalIgnoreCase) &&
                            p.Value.TryGetProperty("message", out var msg))
                            return msg.GetString() ?? value;
                }
                catch { /* try next locale */ }
            }
            return value;
        }

        private static string JStr(JsonElement e, string p) =>
            e.TryGetProperty(p, out var v) && v.ValueKind == JsonValueKind.String ? (v.GetString() ?? "") : "";

        // ----------------------------------------------------------------- //
        // Services
        // ----------------------------------------------------------------- //
        public static CheckGroup CheckServices()
        {
            var group = new CheckGroup("Services (third-party, running)");

            var rows = RunPowerShellArray(
                "@(Get-CimInstance Win32_Service | Select-Object Name,DisplayName,State,StartMode,PathName) | " +
                "ConvertTo-Json -Compress -Depth 3");

            int total = rows.Count;
            string sysRoot = Environment.GetFolderPath(Environment.SpecialFolder.Windows);

            var thirdParty = rows.Where(r =>
            {
                string state = Str(r, "State");
                string path = Str(r, "PathName");
                return state == "Running" && path.Length > 0 &&
                       path.IndexOf(sysRoot, StringComparison.OrdinalIgnoreCase) < 0;
            }).ToList();

            group.Add(CheckStatus.Info, "Service inventory",
                $"{total} services total, {thirdParty.Count} third-party running (outside {sysRoot}).");

            int shown = 0;
            foreach (var r in thirdParty)
            {
                if (++shown > MaxList) break;
                string disp = Str(r, "DisplayName");
                if (disp.Length == 0) disp = Str(r, "Name");
                group.Add(CheckStatus.Info, disp,
                    $"{Str(r, "StartMode")}  -  {CleanPath(Str(r, "PathName"))}");
            }
            if (thirdParty.Count > MaxList)
                group.Add(CheckStatus.Info, "...", $"{thirdParty.Count - MaxList} more not shown.");
            if (total == 0)
                group.Add(CheckStatus.Warn, "Services", "Could not enumerate services.");

            return group;
        }

        // ----------------------------------------------------------------- //
        // Processes
        // ----------------------------------------------------------------- //
        public static CheckGroup CheckProcesses()
        {
            var group = new CheckGroup("Processes (non-standard locations)");

            var rows = RunPowerShellArray(
                "@(Get-CimInstance Win32_Process | Select-Object Name,ProcessId,ExecutablePath) | " +
                "ConvertTo-Json -Compress -Depth 3");

            int total = rows.Count;
            string sysRoot = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            string pf = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
            string pfx = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);

            int flagged = 0;
            foreach (var r in rows)
            {
                string path = Str(r, "ExecutablePath");
                if (path.Length == 0) continue; // system/protected - skip noise

                bool standard =
                    path.StartsWith(sysRoot, StringComparison.OrdinalIgnoreCase) ||
                    path.StartsWith(pf, StringComparison.OrdinalIgnoreCase) ||
                    (pfx.Length > 0 && path.StartsWith(pfx, StringComparison.OrdinalIgnoreCase));
                if (standard) continue;

                bool risky = LooksRisky(path);
                if (++flagged <= MaxList)
                    group.Add(risky ? CheckStatus.Warn : CheckStatus.Info,
                        Str(r, "Name"),
                        $"pid {Str(r, "ProcessId")}  -  {path}" +
                        (risky ? "   (temp/download/user location)" : ""));
            }

            if (flagged == 0)
                group.Add(CheckStatus.Pass, "Processes",
                    $"{total} running; none outside Windows/Program Files.");
            else
            {
                if (flagged > MaxList) group.Add(CheckStatus.Info, "...", $"{flagged - MaxList} more not shown.");
                group.Add(CheckStatus.Info, "Process inventory",
                    $"{total} running total, {flagged} outside standard program locations (review).");
            }
            return group;
        }

        // ----------------------------------------------------------------- //
        // Startup programs
        // ----------------------------------------------------------------- //
        public static CheckGroup CheckStartup()
        {
            var group = new CheckGroup("Startup Programs (auto-run)");

            var rows = RunPowerShellArray(
                "@(Get-CimInstance Win32_StartupCommand | Select-Object Name,Command,Location) | " +
                "ConvertTo-Json -Compress -Depth 3");

            if (rows.Count == 0)
            {
                group.Add(CheckStatus.Pass, "Startup", "No auto-start entries found.");
                return group;
            }

            int shown = 0;
            foreach (var r in rows)
            {
                if (++shown > MaxList) break;
                string cmd = Str(r, "Command");
                bool risky = LooksRisky(cmd);
                group.Add(risky ? CheckStatus.Warn : CheckStatus.Info,
                    Str(r, "Name"),
                    $"{ShortLoc(Str(r, "Location"))}  -  {cmd}");
            }
            if (rows.Count > MaxList)
                group.Add(CheckStatus.Info, "...", $"{rows.Count - MaxList} more not shown.");
            group.Add(CheckStatus.Info, "Total startup items", $"{rows.Count} auto-run entries.");
            return group;
        }

        // ----------------------------------------------------------------- //
        // Installed programs
        // ----------------------------------------------------------------- //
        public static CheckGroup CheckInstalled()
        {
            var group = new CheckGroup("Installed Programs (most recent first)");

            var progs = GetInstalledPrograms();
            if (progs.Count == 0)
            {
                group.Add(CheckStatus.Warn, "Installed programs", "Could not enumerate installed programs.");
                return group;
            }

            var ordered = progs.OrderByDescending(p => p.SortDate).ToList();
            int shown = 0;
            foreach (var p in ordered)
            {
                if (++shown > MaxList) break;
                bool recent = p.DaysOld is < 14;
                group.Add(recent ? CheckStatus.Warn : CheckStatus.Info, p.Name,
                    $"{p.InstalledText}  v{p.Version}" +
                    (p.Publisher.Length > 0 ? $"  -  {p.Publisher}" : "") +
                    (recent ? "   (installed/changed in last 14 days)" : ""));
            }
            if (progs.Count > MaxList)
                group.Add(CheckStatus.Info, "...", $"{progs.Count - MaxList} more not shown.");
            group.Add(CheckStatus.Info, "Total installed", $"{progs.Count} program(s) registered.");
            return group;
        }

        /// <summary>
        /// Structured list of installed programs (used by the Installed tab's grid).
        /// Deduplicates by name+version and resolves a best-effort executable path.
        /// </summary>
        public static List<InstalledProgram> GetInstalledPrograms()
        {
            var rows = RunPowerShellArray(
                "$k='HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*'," +
                "'HKLM:\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*'," +
                "'HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*'; " +
                "@(Get-ItemProperty $k -ErrorAction SilentlyContinue | Where-Object {$_.DisplayName} | " +
                "Select-Object DisplayName,DisplayVersion,Publisher,InstallDate,Comments,DisplayIcon,InstallLocation) | " +
                "ConvertTo-Json -Compress -Depth 3");

            var list = new List<InstalledProgram>();
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var r in rows)
            {
                string name = Str(r, "DisplayName");
                if (name.Length == 0) continue;
                string ver = Str(r, "DisplayVersion");
                if (!seen.Add(name + "|" + ver)) continue;

                var p = new InstalledProgram
                {
                    Name = name,
                    Version = ver,
                    Publisher = Str(r, "Publisher"),
                    Description = FirstNonEmpty(Str(r, "Comments"), Str(r, "Publisher")),
                    InstallLocation = Str(r, "InstallLocation"),
                    DisplayIcon = Str(r, "DisplayIcon"),
                };
                p.ExePath = ExeFromDisplayIcon(p.DisplayIcon);

                DateTime? d = ParseYmd(Str(r, "InstallDate"));
                if (d == null && p.ExePath != null)
                {
                    try { d = File.GetLastWriteTime(p.ExePath); } catch { /* ignore */ }
                }
                p.InstallDate = d;
                p.SortDate = d ?? DateTime.MinValue;
                p.DaysOld = d != null ? Math.Max(0, (int)(DateTime.Now - d.Value).TotalDays) : null;
                p.InstalledText = d != null ? d.Value.ToString("yyyy-MM-dd") : "—";

                list.Add(p);
            }
            return list;
        }

        /// <summary>Verifies a file's Authenticode signature (WinVerifyTrust). Returns (status, signerSubject).</summary>
        public static (string Status, string Signer) VerifyAuthenticode(string path)
        {
            var e = RunPowerShellJson(
                $"$x=Get-AuthenticodeSignature -LiteralPath '{path.Replace("'", "''")}'; " +
                "[pscustomobject]@{Status=$x.Status.ToString();Signer=$x.SignerCertificate.Subject} | ConvertTo-Json -Compress");
            if (e != null && e.Value.ValueKind == JsonValueKind.Object)
                return (Str(e.Value, "Status"), Str(e.Value, "Signer"));
            return ("Unknown", "");
        }

        /// <summary>SHA-256 of a file as lowercase hex, or null on error.</summary>
        public static string? Sha256File(string path)
        {
            try
            {
                using var sha = SHA256.Create();
                using var fs = File.OpenRead(path);
                return Convert.ToHexString(sha.ComputeHash(fs)).ToLowerInvariant();
            }
            catch { return null; }
        }

        /// <summary>Resolves an executable to scan for a program (DisplayIcon, then InstallLocation search).</summary>
        public static string? ResolveExeForScan(InstalledProgram p)
        {
            if (p.ExePath != null && File.Exists(p.ExePath)) return p.ExePath;

            string loc = p.InstallLocation.Trim().Trim('"');
            if (loc.Length == 0 || !Directory.Exists(loc)) return null;

            List<string> exes;
            try { exes = Directory.EnumerateFiles(loc, "*.exe", SearchOption.AllDirectories).Take(500).ToList(); }
            catch
            {
                try { exes = Directory.EnumerateFiles(loc, "*.exe").ToList(); }
                catch { return null; }
            }
            if (exes.Count == 0) return null;

            string token = new string(p.Name.TakeWhile(char.IsLetterOrDigit).ToArray());
            string? match = token.Length >= 3
                ? exes.FirstOrDefault(f => Path.GetFileNameWithoutExtension(f)
                    .Contains(token, StringComparison.OrdinalIgnoreCase))
                : null;
            return match ?? exes.OrderByDescending(FileSize).First();
        }

        private static long FileSize(string f)
        {
            try { return new FileInfo(f).Length; } catch { return 0; }
        }

        private static string? ExeFromDisplayIcon(string icon)
        {
            if (string.IsNullOrWhiteSpace(icon)) return null;
            string p = icon.Trim().Trim('"');
            int comma = p.LastIndexOf(',');
            if (comma > 0 && int.TryParse(p.AsSpan(comma + 1), out _)) p = p.Substring(0, comma);
            p = p.Trim().Trim('"');
            return p.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) && File.Exists(p) ? p : null;
        }

        private static DateTime? ParseYmd(string s) =>
            s.Length == 8 && DateTime.TryParseExact(s, "yyyyMMdd", null,
                System.Globalization.DateTimeStyles.None, out var d) ? d : null;

        private static string FirstNonEmpty(params string[] values)
        {
            foreach (var v in values) if (!string.IsNullOrWhiteSpace(v)) return v;
            return "";
        }

        // ----------------------------------------------------------------- //
        // Device drivers
        // ----------------------------------------------------------------- //
        public static CheckGroup CheckDevices()
        {
            var group = new CheckGroup("Device Drivers (third-party)");
            var drivers = GetDevices();
            if (drivers.Count == 0)
            {
                group.Add(CheckStatus.Warn, "Drivers", "Could not enumerate device drivers.");
                return group;
            }

            var thirdParty = drivers
                .Where(d => d.Provider.Length > 0 && !d.Provider.Equals("Microsoft", StringComparison.OrdinalIgnoreCase))
                .OrderByDescending(d => d.LocalSort)
                .ToList();

            group.Add(CheckStatus.Info, "Driver inventory",
                $"{drivers.Count} signed drivers total, {thirdParty.Count} from third-party providers.");

            int shown = 0;
            foreach (var d in thirdParty)
            {
                if (++shown > MaxList) break;
                group.Add(d.Signed ? CheckStatus.Info : CheckStatus.Warn, d.Device,
                    $"{d.Provider}  v{d.Version}  vendor {d.VendorDateText}  changed {d.LocalChangedText}" +
                    (d.Signed ? "" : "   (UNSIGNED)"));
            }
            if (thirdParty.Count > MaxList)
                group.Add(CheckStatus.Info, "...", $"{thirdParty.Count - MaxList} more not shown.");
            return group;
        }

        /// <summary>Structured driver list (used by the Devices grid). Includes the local INF change time.</summary>
        public static List<DeviceDriver> GetDevices()
        {
            var rows = RunPowerShellArray(
                "@(Get-CimInstance Win32_PnPSignedDriver -ErrorAction SilentlyContinue | " +
                "Where-Object {$_.DeviceName} | ForEach-Object { [pscustomobject]@{ " +
                "Device=$_.DeviceName; Provider=$_.DriverProviderName; Version=$_.DriverVersion; " +
                "Signed=[bool]$_.IsSigned; Inf=$_.InfName; " +
                "VendorDate=$(if($_.DriverDate){$_.DriverDate.ToString('yyyy-MM-dd')}else{''}) } }) | " +
                "ConvertTo-Json -Compress -Depth 3");

            string infDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "INF");
            var list = new List<DeviceDriver>();
            foreach (var r in rows)
            {
                var d = new DeviceDriver
                {
                    Device = Str(r, "Device"),
                    Provider = Str(r, "Provider"),
                    Version = Str(r, "Version"),
                    Signed = r.TryGetProperty("Signed", out var s) && s.ValueKind == JsonValueKind.True,
                    InfName = Str(r, "Inf"),
                    VendorDateText = Str(r, "VendorDate"),
                };
                if (DateTime.TryParse(d.VendorDateText, out var vd)) d.VendorDate = vd;

                if (d.InfName.Length > 0)
                {
                    string infPath = Path.Combine(infDir, d.InfName);
                    try
                    {
                        if (File.Exists(infPath))
                        {
                            DateTime lw = File.GetLastWriteTime(infPath);
                            d.LocalChanged = lw;
                            d.LocalChangedText = lw.ToString("yyyy-MM-dd");
                        }
                    }
                    catch { /* ignore */ }
                }
                if (d.LocalChangedText.Length == 0) d.LocalChangedText = "—";
                d.LocalSort = d.LocalChanged ?? DateTime.MinValue;
                d.DaysOld = d.LocalChanged != null
                    ? Math.Max(0, (int)(DateTime.Now - d.LocalChanged.Value).TotalDays) : null;

                list.Add(d);
            }
            return list;
        }

        // ----------------------------------------------------------------- //
        // Helpers
        // ----------------------------------------------------------------- //
        private static string? FindChrome()
        {
            string[] candidates =
            {
                Environment.ExpandEnvironmentVariables(@"%ProgramFiles%\Google\Chrome\Application\chrome.exe"),
                Environment.ExpandEnvironmentVariables(@"%ProgramFiles(x86)%\Google\Chrome\Application\chrome.exe"),
                Environment.ExpandEnvironmentVariables(@"%LOCALAPPDATA%\Google\Chrome\Application\chrome.exe"),
            };
            return candidates.FirstOrDefault(File.Exists);
        }

        private static IEnumerable<string> SafeDirs(string path)
        {
            try { return Directory.EnumerateDirectories(path); }
            catch { return Enumerable.Empty<string>(); }
        }

        private static bool LooksRisky(string text)
        {
            string t = text.ToLowerInvariant();
            return t.Contains(@"\temp\") || t.Contains(@"\tmp\") ||
                   t.Contains(@"\downloads\") || t.Contains(@"\appdata\local\temp");
        }

        private static string CleanPath(string raw)
        {
            raw = raw.Trim();
            if (raw.StartsWith("\""))
            {
                int end = raw.IndexOf('"', 1);
                if (end > 0) return raw.Substring(1, end - 1);
            }
            return raw;
        }

        private static string ShortLoc(string loc)
        {
            if (loc.Contains("Run", StringComparison.OrdinalIgnoreCase) && loc.Contains("HK"))
                return loc.StartsWith("HKLM", StringComparison.OrdinalIgnoreCase) ? "HKLM Run"
                     : loc.StartsWith("HKU", StringComparison.OrdinalIgnoreCase) ? "HKCU Run" : "Run key";
            return loc;
        }

        private static string FormatDate(string yyyymmdd)
        {
            if (yyyymmdd.Length == 8 &&
                DateTime.TryParseExact(yyyymmdd, "yyyyMMdd", null,
                    System.Globalization.DateTimeStyles.None, out var d))
                return d.ToString("yyyy-MM-dd");
            return yyyymmdd.Length == 0 ? "(no date)" : yyyymmdd;
        }

        /// <summary>Runs a PowerShell script whose output is a JSON array (or single object) and returns its elements.</summary>
        private static List<JsonElement> RunPowerShellArray(string script)
        {
            var list = new List<JsonElement>();
            var root = RunPowerShellJson(script);
            if (root == null) return list;
            if (root.Value.ValueKind == JsonValueKind.Array)
                foreach (var e in root.Value.EnumerateArray()) list.Add(e.Clone());
            else if (root.Value.ValueKind == JsonValueKind.Object)
                list.Add(root.Value.Clone());
            return list;
        }
    }
}
