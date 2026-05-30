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

            try
            {
                using var sha = SHA256.Create();
                using var fs = File.OpenRead(exe);
                string hash = Convert.ToHexString(sha.ComputeHash(fs)).ToLowerInvariant();
                group.Add(CheckStatus.Info, "SHA-256", hash);
            }
            catch (Exception ex) { group.Add(CheckStatus.Warn, "SHA-256", ex.Message); }

            // Authenticode signature is the meaningful integrity/tamper check.
            var sig = RunPowerShellJson(
                $"$x=Get-AuthenticodeSignature -LiteralPath '{exe.Replace("'", "''")}'; " +
                "[pscustomobject]@{Status=$x.Status.ToString();Signer=$x.SignerCertificate.Subject} | ConvertTo-Json -Compress");
            if (sig != null && sig.Value.ValueKind == JsonValueKind.Object)
            {
                string status = Str(sig.Value, "Status");
                string signer = Str(sig.Value, "Signer");
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

            string userData = Environment.ExpandEnvironmentVariables(
                @"%LOCALAPPDATA%\Google\Chrome\User Data");
            if (!Directory.Exists(userData))
            {
                group.Add(CheckStatus.Info, "Extensions", "No Chrome user-data directory found.");
                return group;
            }

            int total = 0;
            foreach (var profile in EnumerateChromeProfiles(userData))
            {
                string extRoot = Path.Combine(userData, profile, "Extensions");
                if (!Directory.Exists(extRoot)) continue;

                foreach (var idDir in SafeDirs(extRoot))
                {
                    string id = Path.GetFileName(idDir);
                    var verDir = SafeDirs(idDir).OrderBy(d => d).LastOrDefault();
                    if (verDir == null) continue;

                    (string name, string version) = ReadManifest(Path.Combine(verDir, "manifest.json"), id);
                    total++;
                    if (total <= MaxList)
                        group.Add(CheckStatus.Info, name, $"v{version}  [{profile}]  id={id}");
                }
            }

            if (total == 0)
                group.Add(CheckStatus.Pass, "Extensions", "No installed extensions found.");
            else
            {
                if (total > MaxList)
                    group.Add(CheckStatus.Info, "...", $"{total - MaxList} more not shown.");
                group.Add(CheckStatus.Info, "Total extensions",
                    $"{total} extension(s). Review any you don't recognise at chrome://extensions.");
            }
            return group;
        }

        private static IEnumerable<string> EnumerateChromeProfiles(string userData)
        {
            yield return "Default";
            foreach (var d in SafeDirs(userData))
            {
                string n = Path.GetFileName(d);
                if (n.StartsWith("Profile ", StringComparison.OrdinalIgnoreCase)) yield return n;
            }
        }

        private static (string Name, string Version) ReadManifest(string manifestPath, string fallbackId)
        {
            try
            {
                if (!File.Exists(manifestPath)) return (fallbackId, "?");
                using var doc = JsonDocument.Parse(File.ReadAllText(manifestPath));
                var root = doc.RootElement;
                string name = root.TryGetProperty("name", out var n) ? (n.GetString() ?? "") : "";
                string version = root.TryGetProperty("version", out var v) ? (v.GetString() ?? "?") : "?";
                // Localised names (__MSG_*) need _locales lookup; fall back to the id.
                if (name.StartsWith("__MSG_", StringComparison.OrdinalIgnoreCase) || name.Length == 0)
                    name = fallbackId;
                return (name, version);
            }
            catch { return (fallbackId, "?"); }
        }

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

            var rows = RunPowerShellArray(
                "$k='HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*'," +
                "'HKLM:\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*'," +
                "'HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*'; " +
                "@(Get-ItemProperty $k -ErrorAction SilentlyContinue | Where-Object {$_.DisplayName} | " +
                "Select-Object DisplayName,DisplayVersion,Publisher,InstallDate) | ConvertTo-Json -Compress -Depth 3");

            if (rows.Count == 0)
            {
                group.Add(CheckStatus.Warn, "Installed programs", "Could not enumerate installed programs.");
                return group;
            }

            // Sort newest-first by parsed yyyyMMdd; entries with no/odd date sort to the bottom.
            static int InstallDateKey(JsonElement r)
            {
                string d = Str(r, "InstallDate");
                return d.Length == 8 && int.TryParse(d, out int n) ? n : 0;
            }
            var ordered = rows.OrderByDescending(InstallDateKey).ToList();

            int recentCutoff = int.Parse(DateTime.Now.AddDays(-14).ToString("yyyyMMdd"));
            int shown = 0;
            foreach (var r in ordered)
            {
                if (++shown > MaxList) break;
                string date = Str(r, "InstallDate");
                bool recent = int.TryParse(date, out int d) && d >= recentCutoff;
                string ver = Str(r, "DisplayVersion");
                string pub = Str(r, "Publisher");
                group.Add(recent ? CheckStatus.Warn : CheckStatus.Info,
                    Str(r, "DisplayName"),
                    $"{FormatDate(date)}  v{ver}" + (pub.Length > 0 ? $"  -  {pub}" : "") +
                    (recent ? "   (installed in last 14 days)" : ""));
            }
            if (rows.Count > MaxList)
                group.Add(CheckStatus.Info, "...", $"{rows.Count - MaxList} more not shown.");
            group.Add(CheckStatus.Info, "Total installed", $"{rows.Count} program(s) registered.");
            return group;
        }

        // ----------------------------------------------------------------- //
        // Device drivers
        // ----------------------------------------------------------------- //
        public static CheckGroup CheckDevices()
        {
            var group = new CheckGroup("Device Drivers (third-party)");

            var rows = RunPowerShellArray(
                "@(Get-CimInstance Win32_PnPSignedDriver -ErrorAction SilentlyContinue | " +
                "Where-Object {$_.DeviceName} | " +
                "Select-Object DeviceName,DriverProviderName,DriverVersion,IsSigned) | " +
                "ConvertTo-Json -Compress -Depth 3");

            int total = rows.Count;
            if (total == 0)
            {
                group.Add(CheckStatus.Warn, "Drivers", "Could not enumerate device drivers.");
                return group;
            }

            var thirdParty = rows.Where(r =>
            {
                string prov = Str(r, "DriverProviderName");
                return prov.Length > 0 && !prov.Equals("Microsoft", StringComparison.OrdinalIgnoreCase);
            }).ToList();

            group.Add(CheckStatus.Info, "Driver inventory",
                $"{total} signed drivers total, {thirdParty.Count} from third-party providers.");

            int shown = 0;
            foreach (var r in thirdParty)
            {
                if (++shown > MaxList) break;
                bool signed = r.TryGetProperty("IsSigned", out var s) && s.ValueKind == JsonValueKind.True;
                group.Add(signed ? CheckStatus.Info : CheckStatus.Warn,
                    Str(r, "DeviceName"),
                    $"{Str(r, "DriverProviderName")}  v{Str(r, "DriverVersion")}" +
                    (signed ? "" : "   (UNSIGNED)"));
            }
            if (thirdParty.Count > MaxList)
                group.Add(CheckStatus.Info, "...", $"{thirdParty.Count - MaxList} more not shown.");
            return group;
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
