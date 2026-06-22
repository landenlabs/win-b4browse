// Copyright (c) 2026 LanDen Labs - Dennis Lang

using System;
using System.Management;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Win32;

namespace B4Browse
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

            string? installedVer = null;
            try
            {
                var fi = System.Diagnostics.FileVersionInfo.GetVersionInfo(exe);
                installedVer = fi.ProductVersion;
                group.Add(CheckStatus.Info, "Version", installedVer ?? "(unknown)");
            }
            catch { /* ignore */ }

            // Compare the installed build against the current stable release (Google's public
            // version-history API). Network-dependent and best-effort: degrades to Info offline.
            if (!string.IsNullOrEmpty(installedVer))
            {
                string? latest = GetLatestChromeStable();
                if (latest == null)
                    group.Add(CheckStatus.Info, "Latest version",
                        "Could not check the latest stable release (offline or API unavailable).");
                else if (CompareChromeVersions(installedVer, latest) >= 0)
                    group.Add(CheckStatus.Pass, "Up to date", $"Installed build matches latest stable ({latest}).")
                        .WithLink("[ check for updates ]", "chrome://settings/help");
                else
                    group.Add(CheckStatus.Warn, "Update available",
                        $"Installed {installedVer} is behind the latest stable {latest} - update and relaunch Chrome.")
                        .WithLink("[ check for updates ]", "chrome://settings/help");
            }

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

        /// <summary>
        /// Highest current stable Chrome version for Windows, from Google's public
        /// version-history API. Returns null on any network/parse failure (treated as
        /// "unknown", never an error). Uses the shared 6-second HttpClient.
        /// </summary>
        private static string? GetLatestChromeStable()
        {
            try
            {
                string json = Http.GetStringAsync(
                    "https://versionhistory.googleapis.com/v1/chrome/platforms/win64/channels/stable/versions")
                    .GetAwaiter().GetResult();

                using var doc = JsonDocument.Parse(json);
                if (!doc.RootElement.TryGetProperty("versions", out var arr) || arr.ValueKind != JsonValueKind.Array)
                    return null;

                string? best = null;
                foreach (var v in arr.EnumerateArray())
                {
                    if (!v.TryGetProperty("version", out var vv) || vv.ValueKind != JsonValueKind.String) continue;
                    string s = vv.GetString() ?? "";
                    if (s.Length == 0) continue;
                    if (best == null || CompareChromeVersions(s, best) > 0) best = s;
                }
                return best;
            }
            catch { return null; }
        }

        /// <summary>Compares dotted version strings numerically (e.g. 126.0.6478.127). Missing parts = 0.</summary>
        private static int CompareChromeVersions(string a, string b)
        {
            int[] pa = ParseVersionParts(a), pb = ParseVersionParts(b);
            int len = Math.Max(pa.Length, pb.Length);
            for (int i = 0; i < len; i++)
            {
                int x = i < pa.Length ? pa[i] : 0;
                int y = i < pb.Length ? pb[i] : 0;
                if (x != y) return x.CompareTo(y);
            }
            return 0;
        }

        private static int[] ParseVersionParts(string v)
        {
            var parts = v.Split('.');
            var nums = new int[parts.Length];
            for (int i = 0; i < parts.Length; i++)
            {
                int j = 0;
                while (j < parts[i].Length && char.IsDigit(parts[i][j])) j++;
                nums[i] = j > 0 && int.TryParse(parts[i].AsSpan(0, j), out int n) ? n : 0;
            }
            return nums;
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
                    $"v{x.Version}  mod {x.ModifiedText}  MV{x.ManifestVersion?.ToString() ?? "?"}  [{x.ProfileName}]  {flags}id={x.Id}");
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

                        DateTime? modified = null;
                        try { modified = Directory.GetLastWriteTime(verDir); } catch { /* ignore */ }

                        list.Add(new ChromeExtension
                        {
                            ProfileDir = idDir,
                            ProfileId = profile,
                            ProfileName = friendly,
                            Name = name,
                            Version = version,
                            Description = desc,
                            Id = id,
                            ManifestVersion = mv,
                            Enabled = enabled,
                            Unsupported = minMv != null && mv != null && mv < minMv,
                            Modified = modified,
                            ModifiedText = modified?.ToString("yyyy-MM-dd") ?? "—",
                            ModifiedSort = modified ?? DateTime.MinValue,
                            DaysOld = modified != null ? Math.Max(0, (int)(DateTime.Now - modified.Value).TotalDays) : null,
                        });
                    }
                }
            }
            return list;
        }

        // ----------------------------------------------------------------- //
        // Environment variables inspector (headless producer)
        // ----------------------------------------------------------------- //
        public static CheckGroup CheckEnvVariables()
        {
            var group = new CheckGroup("Environment Variables");
            var rows = EnvironmentInspector.InspectAll();
            if (rows.Count == 0)
            {
                group.Add(CheckStatus.Info, "Environment", "No environment variables found or readable.");
                return group;
            }

            int issues = rows.Count(r => r.HasInvalidPaths || r.HasUserWritablePaths || r.IsCoreVariableAltered || r.IsLengthRisk);
            group.Add(issues > 0 ? CheckStatus.Warn : CheckStatus.Pass, "Summary",
                $"{rows.Count} variables inspected, {issues} with potential issues.");

            int shown = 0;
            foreach (var r in rows.OrderByDescending(r => (r.HasUserWritablePaths ? 4 : 0) + (r.IsCoreVariableAltered ? 2 : 0) + (r.HasInvalidPaths ? 1 : 0)))
            {
                if (++shown > MaxList) break;
                var st = r.HasUserWritablePaths ? CheckStatus.Fail
                         : r.IsCoreVariableAltered ? CheckStatus.Warn
                         : r.HasInvalidPaths ? CheckStatus.Info
                         : CheckStatus.Pass;
                group.Add(st, r.Name, r.DiagnosticRecommendation.Length > 0 ? r.DiagnosticRecommendation : r.RawValue);
            }
            if (rows.Count > MaxList)
                group.Add(CheckStatus.Info, "...", $"{rows.Count - MaxList} more not shown.");

            return group;
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
            var services = GetServices();
            if (services.Count == 0)
            {
                group.Add(CheckStatus.Warn, "Services", "Could not enumerate services.");
                return group;
            }

            string sysRoot = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            var thirdParty = services
                .Where(s => s.State == "Running" && s.ExePath.Length > 0 &&
                            s.ExePath.IndexOf(sysRoot, StringComparison.OrdinalIgnoreCase) < 0)
                .OrderByDescending(s => s.ModifiedSort)
                .ToList();

            group.Add(CheckStatus.Info, "Service inventory",
                $"{services.Count} services total, {thirdParty.Count} third-party running (outside {sysRoot}).");

            int shown = 0;
            foreach (var s in thirdParty)
            {
                if (++shown > MaxList) break;
                string disp = s.DisplayName.Length > 0 ? s.DisplayName : s.Name;
                // Enrich diagnostic text when a pending/stuck service also ignores shutdown.
                string note = "";
                try
                {
                    if (s.IsStuck && s.IgnoresShutdown)
                    {
                        note = "  [STUCK & IGNORES SHUTDOWN: may require a cold restart (shutdown /r /t 0)]";
                    }
                    else if (s.IgnoresShutdown)
                    {
                        note = "  [IGNORES SHUTDOWN]";
                    }
                }
                catch { }

                group.Add(CheckStatus.Info, disp,
                    $"{s.StartMode}  -  modified {s.ModifiedText}  -  {s.ExePath}{note}");
            }
            if (thirdParty.Count > MaxList)
                group.Add(CheckStatus.Info, "...", $"{thirdParty.Count - MaxList} more not shown.");
            return group;
        }

        /// <summary>Structured service list (used by the Services grid), with executable modify dates.</summary>
        public static List<ServiceInfo> GetServices()
        {
            var rows = RunPowerShellArray(
                "@(Get-CimInstance Win32_Service | Select-Object Name,DisplayName,State,StartMode,StartName,Description,PathName) | " +
                "ConvertTo-Json -Compress -Depth 3");

            var list = new List<ServiceInfo>();
            foreach (var r in rows)
            {
                var s = new ServiceInfo
                {
                    Name = Str(r, "Name"),
                    DisplayName = Str(r, "DisplayName"),
                    State = Str(r, "State"),
                    StartMode = Str(r, "StartMode"),
                    PathRaw = Str(r, "PathName"),
                    Account = Str(r, "StartName"),
                    Description = Str(r, "Description"),
                };
                s.ExePath = ExtractExe(s.PathRaw);
                if (s.ExePath.Length > 0)
                {
                    try { s.Dir = Path.GetDirectoryName(s.ExePath) ?? ""; } catch { /* ignore */ }
                    try
                    {
                        if (File.Exists(s.ExePath))
                        {
                            DateTime lw = File.GetLastWriteTime(s.ExePath);
                            s.Modified = lw;
                            s.ModifiedText = lw.ToString("yyyy-MM-dd");
                        }
                    }
                    catch { /* ignore */ }
                    // Schedule background inspection to compute SHA, signature status, and IGNORES_SHUTDOWN.
                    _ = Task.Run(async () => {
                        try
                        {
                            var (sha, sig) = await ServiceFileInspector.InspectAsync(s.ExePath).ConfigureAwait(false);
                            s.Sha256 = sha;
                            s.SignatureStatus = sig;
                        }
                        catch { /* ignore */ }

                        try
                        {
                            // Query native SCM for dwControlsAccepted. Return null on error; treat null as unknown (leave false).
                            bool? accepts = await ServiceFileInspector.ServiceAcceptsShutdownAsync(s.Name).ConfigureAwait(false);
                            if (accepts.HasValue) s.IgnoresShutdown = !accepts.Value;
                        }
                        catch { /* ignore */ }

                        try
                        {
                            using var regKey = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                                $@"SYSTEM\CurrentControlSet\Services\{s.Name}");
                            if (regKey != null)
                            {
                                var flag = regKey.GetValue("DeleteFlag");
                                s.IsPendingDelete = flag is int v && v != 0;
                            }
                        }
                        catch { /* ignore */ }
                        // UI grid will refresh via ServiceFileInspector.InspectionCompleted subscription.
                    });
                }
                s.ModifiedSort = s.Modified ?? DateTime.MinValue;
                s.DaysOld = s.Modified != null ? Math.Max(0, (int)(DateTime.Now - s.Modified.Value).TotalDays) : null;
                list.Add(s);
            }
            return list;
        }

        /// <summary>Extracts the executable path from a service ImagePath (handles quotes and arguments).</summary>
        private static string ExtractExe(string imagePath)
        {
            string p = imagePath.Trim();
            if (p.StartsWith("\""))
            {
                int end = p.IndexOf('"', 1);
                if (end > 0) return p.Substring(1, end - 1);
            }
            int exe = p.IndexOf(".exe", StringComparison.OrdinalIgnoreCase);
            if (exe >= 0) return p.Substring(0, exe + 4);
            int sp = p.IndexOf(' ');
            return sp > 0 ? p.Substring(0, sp) : p;
        }

        // ----------------------------------------------------------------- //
        // Processes
        // ----------------------------------------------------------------- //
        public static CheckGroup CheckProcesses()
        {
            var group = new CheckGroup("Processes (non-standard locations)");
            var procs = GetProcesses();
            int total = procs.Count;

            string sysRoot = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            string pf = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
            string pfx = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
            bool Standard(string path) =>
                path.StartsWith(sysRoot, StringComparison.OrdinalIgnoreCase) ||
                path.StartsWith(pf, StringComparison.OrdinalIgnoreCase) ||
                (pfx.Length > 0 && path.StartsWith(pfx, StringComparison.OrdinalIgnoreCase));

            var flagged = procs
                .Where(p => p.ExePath.Length > 0 && !Standard(p.ExePath))
                .OrderByDescending(p => p.ModifiedSort)
                .ToList();

            int shown = 0;
            foreach (var p in flagged)
            {
                if (++shown > MaxList) break;
                bool risky = LooksRisky(p.ExePath);
                group.Add(risky ? CheckStatus.Warn : CheckStatus.Info, p.Name,
                    $"pid {p.Pid}  -  modified {p.ModifiedText}  -  {p.ExePath}" +
                    (risky ? "   (temp/download/user location)" : ""));
            }

            if (flagged.Count == 0)
                group.Add(CheckStatus.Pass, "Processes",
                    $"{total} running; none outside Windows/Program Files.");
            else
            {
                if (flagged.Count > MaxList) group.Add(CheckStatus.Info, "...", $"{flagged.Count - MaxList} more not shown.");
                group.Add(CheckStatus.Info, "Process inventory",
                    $"{total} running total, {flagged.Count} outside standard program locations (review).");
            }
            return group;
        }

        /// <summary>Structured process list (used by the Processes grid), with exe version + modify date.</summary>
        public static List<ProcessItem> GetProcesses()
        {
            var rows = RunPowerShellArray(
                "@(Get-CimInstance Win32_Process | Select-Object Name,ProcessId,ExecutablePath) | " +
                "ConvertTo-Json -Compress -Depth 3");

            var list = new List<ProcessItem>();
            var seenPaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var r in rows)
            {
                var p = new ProcessItem { Name = Str(r, "Name"), ExePath = Str(r, "ExecutablePath") };
                int.TryParse(Str(r, "ProcessId"), out int pid);
                p.Pid = pid;

                // Collapse duplicate executables (e.g. many svchost/chrome) by path; keep path-less rows.
                if (p.ExePath.Length > 0 && !seenPaths.Add(p.ExePath)) continue;

                if (p.ExePath.Length > 0 && File.Exists(p.ExePath))
                {
                    try
                    {
                        var fi = System.Diagnostics.FileVersionInfo.GetVersionInfo(p.ExePath);
                        p.Version = fi.FileVersion ?? "";
                        p.Company = fi.CompanyName ?? "";
                    }
                    catch { /* ignore */ }
                    try { p.Modified = File.GetLastWriteTime(p.ExePath); } catch { /* ignore */ }
                }
                p.ModifiedText = p.Modified?.ToString("yyyy-MM-dd") ?? "—";
                p.ModifiedSort = p.Modified ?? DateTime.MinValue;
                p.DaysOld = p.Modified != null ? Math.Max(0, (int)(DateTime.Now - p.Modified.Value).TotalDays) : null;
                list.Add(p);
            }
            return list;
        }

        // ----------------------------------------------------------------- //
        // Startup programs
        // ----------------------------------------------------------------- //
        public static CheckGroup CheckStartup()
        {
            var group = new CheckGroup("Startup Programs (auto-run)");
            var items = GetStartup();
            if (items.Count == 0)
            {
                group.Add(CheckStatus.Pass, "Startup", "No auto-start entries found.");
                return group;
            }

            int shown = 0;
            foreach (var it in items.OrderByDescending(i => i.StatusSort))
            {
                if (++shown > MaxList) break;
                // A disabled entry doesn't run at login, so don't flag it as a risk.
                bool risky = it.Enabled && (LooksRisky(it.Command) || LooksRisky(it.ExePath));
                group.Add(risky ? CheckStatus.Warn : CheckStatus.Info, it.Name,
                    $"{it.Location}  -  {it.EnabledText}  -  added {it.RegistryAddedText}  -  {(it.ExePath.Length > 0 ? it.ExePath : it.Command)}");
            }
            if (items.Count > MaxList)
                group.Add(CheckStatus.Info, "...", $"{items.Count - MaxList} more not shown.");
            group.Add(CheckStatus.Info, "Total startup items", $"{items.Count} auto-run entries.");
            return group;
        }

        /// <summary>Structured startup list (used by the Startup grid): registry Run keys + Startup folders.</summary>
        public static List<StartupItem> GetStartup()
        {
            var list = new List<StartupItem>();

            var regSources = new (RegistryKey Hive, string Path, string Label)[]
            {
                (Registry.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKLM\\Run"),
                (Registry.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM\\RunOnce"),
                (Registry.LocalMachine, @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", "HKLM\\Run (WOW64)"),
                (Registry.CurrentUser, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKCU\\Run"),
                (Registry.CurrentUser, @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU\\RunOnce"),
            };
            foreach (var (hive, path, label) in regSources)
            {
                try
                {
                    using var key = hive.OpenSubKey(path);
                    if (key == null) continue;
                    DateTime? keyTime = GetKeyLastWriteTime(key);
                    foreach (var name in key.GetValueNames())
                    {
                        if (string.IsNullOrEmpty(name)) continue;
                        string cmd = Convert.ToString(key.GetValue(name)) ?? "";
                        if (cmd.Length == 0) continue;
                        list.Add(new StartupItem
                        {
                            Name = name, Command = cmd, Location = label, Source = "Registry",
                            ExePath = ExtractExe(cmd), RegistryAdded = keyTime,
                        });
                    }
                }
                catch { /* skip inaccessible hive */ }
            }

            var folders = new (string Dir, string Label)[]
            {
                (Environment.GetFolderPath(Environment.SpecialFolder.Startup), "Startup (user)"),
                (Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup), "Startup (common)"),
            };
            var lnkItems = new List<StartupItem>();
            foreach (var (dir, label) in folders)
            {
                if (string.IsNullOrEmpty(dir) || !Directory.Exists(dir)) continue;
                List<string> files;
                try { files = Directory.EnumerateFiles(dir).ToList(); } catch { continue; }
                foreach (var f in files)
                {
                    if (Path.GetFileName(f).Equals("desktop.ini", StringComparison.OrdinalIgnoreCase)) continue;
                    var it = new StartupItem
                    {
                        Name = Path.GetFileNameWithoutExtension(f), Command = f, Location = label, Source = "Folder",
                    };
                    try { it.RegistryAdded = File.GetLastWriteTime(f); } catch { /* ignore */ }
                    if (Path.GetExtension(f).Equals(".lnk", StringComparison.OrdinalIgnoreCase)) lnkItems.Add(it);
                    else it.ExePath = f;
                    list.Add(it);
                }
            }
            if (lnkItems.Count > 0)
            {
                var targets = ResolveShortcuts(lnkItems.Select(i => i.Command).ToList());
                foreach (var it in lnkItems)
                    if (targets.TryGetValue(it.Command, out var tgt) && tgt.Length > 0) it.ExePath = tgt;
            }

            // Enabled/disabled state lives in the Explorer\StartupApproved keys (what Task
            // Manager / Settings toggle). Read once per hive and look each entry up by name.
            var approvedHkcu = ReadStartupApproved(Registry.CurrentUser);
            var approvedHklm = ReadStartupApproved(Registry.LocalMachine);

            foreach (var it in list)
            {
                if (it.ExePath.Length > 0)
                {
                    try { it.Dir = Path.GetDirectoryName(it.ExePath) ?? ""; } catch { /* ignore */ }
                    try { if (File.Exists(it.ExePath)) it.ExeModified = File.GetLastWriteTime(it.ExePath); } catch { /* ignore */ }
                }
                it.RegistryAddedText = it.RegistryAdded?.ToString("yyyy-MM-dd") ?? "—";
                it.ExeModifiedText = it.ExeModified?.ToString("yyyy-MM-dd") ?? "—";

                DateTime? status = it.RegistryAdded;
                if (it.ExeModified != null && (status == null || it.ExeModified > status)) status = it.ExeModified;
                it.StatusSort = status ?? DateTime.MinValue;
                it.DaysOld = status != null ? Math.Max(0, (int)(DateTime.Now - status.Value).TotalDays) : null;

                // StartupApproved value name: the Run value name (registry) or the file name (folder).
                bool hklm = it.Location.StartsWith("HKLM", StringComparison.OrdinalIgnoreCase)
                            || it.Location.Equals("Startup (common)", StringComparison.OrdinalIgnoreCase);
                string lookup = it.Source == "Folder" ? Path.GetFileName(it.Command) : it.Name;
                var primary = hklm ? approvedHklm : approvedHkcu;
                var fallback = hklm ? approvedHkcu : approvedHklm;
                bool? state = primary.TryGetValue(lookup, out var e1) ? e1
                            : fallback.TryGetValue(lookup, out var e2) ? e2
                            : null;
                it.Enabled = state ?? true;        // entries with no StartupApproved record are enabled
                it.EnabledText = it.Enabled ? "Enabled" : "Disabled";
            }
            return list;
        }

        private const string StartupApprovedBase =
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved";

        /// <summary>
        /// Reads the StartupApproved state for a hive into a name -> enabled map, merging the
        /// Run, Run32 (WOW64) and StartupFolder subkeys. The state is a REG_BINARY whose first
        /// byte is even when enabled and odd when disabled (what Task Manager writes).
        /// </summary>
        private static Dictionary<string, bool> ReadStartupApproved(RegistryKey hive)
        {
            var map = new Dictionary<string, bool>(StringComparer.OrdinalIgnoreCase);
            foreach (var sub in new[] { "Run", "Run32", "StartupFolder" })
            {
                try
                {
                    using var k = hive.OpenSubKey(StartupApprovedBase + "\\" + sub);
                    if (k == null) continue;
                    foreach (var name in k.GetValueNames())
                    {
                        if (string.IsNullOrEmpty(name)) continue;
                        bool enabled = true;
                        if (k.GetValue(name) is byte[] b && b.Length >= 1) enabled = (b[0] & 1) == 0;
                        map[name] = enabled;
                    }
                }
                catch { /* ignore inaccessible subkey */ }
            }
            return map;
        }

        /// <summary>Resolves .lnk targets in one PowerShell call (WScript.Shell). Returns lnkPath -> targetPath.</summary>
        private static Dictionary<string, string> ResolveShortcuts(List<string> lnks)
        {
            var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            if (lnks.Count == 0) return map;
            string arr = string.Join(",", lnks.Select(p => "'" + p.Replace("'", "''") + "'"));
            string script =
                "$sh=New-Object -ComObject WScript.Shell; $r=[ordered]@{}; " +
                $"foreach($p in @({arr})){{ try{{ $r[$p]=$sh.CreateShortcut($p).TargetPath }}catch{{}} }}; " +
                "$r | ConvertTo-Json -Compress";
            var root = RunPowerShellJson(script);
            if (root != null && root.Value.ValueKind == JsonValueKind.Object)
                foreach (var p in root.Value.EnumerateObject())
                    if (p.Value.ValueKind == JsonValueKind.String) map[p.Name] = p.Value.GetString() ?? "";
            return map;
        }

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern int RegQueryInfoKey(
            Microsoft.Win32.SafeHandles.SafeRegistryHandle hKey, IntPtr lpClass, IntPtr lpcchClass, IntPtr lpReserved,
            IntPtr lpcSubKeys, IntPtr lpcbMaxSubKeyLen, IntPtr lpcbMaxClassLen,
            IntPtr lpcValues, IntPtr lpcbMaxValueNameLen, IntPtr lpcbMaxValueLen,
            IntPtr lpcbSecurityDescriptor, out FILETIME lpftLastWriteTime);

        /// <summary>Registry key's last-write time (the closest available "added/changed" date for Run values).</summary>
        private static DateTime? GetKeyLastWriteTime(RegistryKey key)
        {
            try
            {
                if (RegQueryInfoKey(key.Handle, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero,
                        IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, out FILETIME ft) == 0)
                {
                    long l = ((long)ft.dwHighDateTime << 32) | (uint)ft.dwLowDateTime;
                    return DateTime.FromFileTime(l);
                }
            }
            catch { /* ignore */ }
            return null;
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
                group.Add(recent || p.HasUpdate ? CheckStatus.Warn : CheckStatus.Info, p.Name,
                    $"{p.InstalledText}  v{p.Version}" +
                    (p.LastRun != null ? $"  -  last run {p.LastRunText}" : "") +
                    (p.Publisher.Length > 0 ? $"  -  {p.Publisher}" : "") +
                    (p.Source.Length > 0 ? $"  [{p.Source}]" : "") +
                    (p.HasUpdate ? $"   -> v{p.AvailableVersion} available" : "") +
                    (recent ? "   (installed/changed in last 14 days)" : ""));
            }
            if (progs.Count > MaxList)
                group.Add(CheckStatus.Info, "...", $"{progs.Count - MaxList} more not shown.");

            int updates = progs.Count(p => p.HasUpdate);
            int withRun = progs.Count(p => p.LastRun != null);
            group.Add(updates > 0 ? CheckStatus.Warn : CheckStatus.Info, "Total installed",
                $"{progs.Count} program(s)" +
                (withRun > 0 ? $"; {withRun} with a recorded last-run time" : "") +
                (updates > 0 ? $"; {updates} have an update available (run `winget upgrade`)." : "."));
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

            EnrichWithWinget(list);
            MergeLastRun(list);
            return list;
        }

        /// <summary>
        /// Populates each program's <see cref="InstalledProgram.LastRun"/> from the PCA launch log
        /// (the same source the Activity tab uses), matched on the resolved main-executable path
        /// first, then - only when that misses - on the most recent launch of any executable under a
        /// specific install directory. Matching is path-based (no fuzzy name match), so a hit means
        /// that program's binary actually ran. No rows are added or removed; programs with no match
        /// (or when the log is unreadable - it lives under C:\Windows and may need admin) keep a blank
        /// Last-run cell.
        /// </summary>
        private static void MergeLastRun(List<InstalledProgram> list)
        {
            Dictionary<string, DateTime> pca = LoadPcaLaunchTimes();   // full path -> last run (local), case-insensitive
            if (pca.Count == 0) return;
            var entries = pca.Select(kv => (Path: kv.Key, When: kv.Value)).ToList();

            foreach (var p in list)
            {
                DateTime? best = null;

                // 1. Exact match on the resolved main executable (highest confidence).
                if (!string.IsNullOrEmpty(p.ExePath) && pca.TryGetValue(p.ExePath!, out var exact))
                    best = exact;

                // 2. Fallback only when the main exe didn't match: the most recent launch of anything
                //    under a specific install directory (generic roots are excluded to avoid bogus hits).
                if (best == null)
                {
                    string dir = NormalizeInstallDir(p.InstallLocation);
                    if (dir.Length > 0)
                        foreach (var e in entries)
                            if (e.Path.StartsWith(dir, StringComparison.OrdinalIgnoreCase) &&
                                (best == null || e.When > best.Value))
                                best = e.When;
                }

                if (best != null)
                {
                    p.LastRun = best;
                    p.LastRunSort = best.Value;
                    p.LastRunText = best.Value.ToString("yyyy-MM-dd HH:mm");
                }
            }
        }

        // Install dirs that are too generic to prefix-match safely (would attribute unrelated exes).
        private static readonly string[] GenericInstallRoots =
        {
            "Program Files", "Program Files (x86)", "Windows", "Windows\\System32",
            "ProgramData", "Users", "Users\\Public",
        };

        /// <summary>An install directory trimmed to a prefix-safe form ending in a separator, or ""
        /// when it's missing or too generic (a bare drive, or a standard root like C:\Program Files).</summary>
        private static string NormalizeInstallDir(string loc)
        {
            string d = (loc ?? "").Trim().Trim('"').TrimEnd('\\', '/');
            if (d.Length < 4) return "";   // empty or a bare drive like "C:"

            string tail = d.Length > 2 && d[1] == ':' ? d[2..].TrimStart('\\', '/') : d;
            if (tail.Length == 0) return "";   // drive root only

            foreach (var generic in GenericInstallRoots)
                if (tail.Equals(generic, StringComparison.OrdinalIgnoreCase)) return "";

            return d + "\\";
        }

        /// <summary>
        /// Adds winget's package Source and pending-update version to the registry list (matched by
        /// normalized name; truncated winget names match by prefix), and appends winget-only packages
        /// (Store/MSIX apps not in the registry). No-op when winget is unavailable.
        /// </summary>
        private static void EnrichWithWinget(List<InstalledProgram> list)
        {
            List<WingetRow> winget;
            try { winget = RunWingetList(); } catch { return; }
            if (winget.Count == 0) return;

            var regNorms = list.Select(p => NormName(p.Name)).ToList();
            var consumed = new bool[winget.Count];

            for (int w = 0; w < winget.Count; w++)
            {
                var wr = winget[w];
                if (wr.Name.Length == 0) continue;
                bool truncated = IsTruncated(wr.Name);
                string wn = NormName(StripEllipsis(wr.Name));
                if (wn.Length == 0) continue;

                for (int r = 0; r < list.Count; r++)
                {
                    string rn = regNorms[r];
                    if (rn.Length == 0) continue;
                    bool match = truncated ? rn.StartsWith(wn, StringComparison.Ordinal) : rn == wn;
                    if (!match) continue;

                    var p = list[r];
                    if (p.Source.Length == 0) p.Source = wr.Source;
                    if (p.AvailableVersion.Length == 0) p.AvailableVersion = wr.Available;
                    if (p.WingetId.Length == 0) p.WingetId = StripEllipsis(wr.Id);
                    consumed[w] = true;
                    break;
                }
            }

            for (int w = 0; w < winget.Count; w++)
            {
                if (consumed[w]) continue;
                var wr = winget[w];
                if (wr.Name.Length == 0) continue;
                list.Add(new InstalledProgram
                {
                    Name = wr.Name,
                    Version = wr.Version,
                    Source = wr.Source,
                    WingetId = StripEllipsis(wr.Id),
                    AvailableVersion = wr.Available,
                    FromWinget = true,
                    InstallDate = null,
                    SortDate = DateTime.MinValue,
                    DaysOld = null,
                    InstalledText = "—",
                });
            }
        }

        private static string NormName(string s) =>
            System.Text.RegularExpressions.Regex.Replace((s ?? "").Trim().ToLowerInvariant(), @"\s+", " ");

        private static bool IsTruncated(string s)
        {
            s = s.TrimEnd();
            return s.EndsWith("…", StringComparison.Ordinal) || s.EndsWith("...", StringComparison.Ordinal);
        }

        private static string StripEllipsis(string s)
        {
            s = s.TrimEnd();
            if (s.EndsWith("…", StringComparison.Ordinal)) s = s[..^1];
            else if (s.EndsWith("...", StringComparison.Ordinal)) s = s[..^3];
            return s.TrimEnd();
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
                    d.InfPath = infPath;
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
        /// <summary>Path to chrome.exe in standard install locations, or null.</summary>
        public static string? ChromeExePath() => FindChrome();

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
        private static List<JsonElement> RunPowerShellArray(string script, [CallerMemberName] string source = "")
        {
            var list = new List<JsonElement>();
            // Forward the caller so any logged failure is attributed to the check, not this wrapper.
            var root = RunPowerShellJson(script, source: source);
            if (root == null) return list;
            if (root.Value.ValueKind == JsonValueKind.Array)
                foreach (var e in root.Value.EnumerateArray()) list.Add(e.Clone());
            else if (root.Value.ValueKind == JsonValueKind.Object)
                list.Add(root.Value.Clone());
            return list;
        }
    }
}
