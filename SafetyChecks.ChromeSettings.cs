// Copyright (c) 2026 LanDen Labs - Dennis Lang

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using Microsoft.Data.Sqlite;

namespace B4Browse
{
    /// <summary>
    /// Chrome settings matrix (the Settings tab). Builds a pivot of settings (rows) against
    /// "Global" (enterprise policy) plus each Chrome profile (columns), reading each profile's
    /// Preferences and Secure Preferences JSON, the enterprise-policy registry, the on-disk
    /// extension folders (count only), and the Login Data SQLite database (saved-password count
    /// only - never any password value or URL). Configuration only; no sensitive data is read.
    /// </summary>
    public static partial class SafetyChecks
    {
        // ----------------------------------------------------------------- //
        // Profile / column discovery
        // ----------------------------------------------------------------- //
        private sealed class ProfileCol
        {
            public string Key = "";        // "{channel}|{profileDir}"
            public string Channel = "";    // "Chrome", "Chrome Beta", "Chrome SxS", "Chromium"
            public string Dir = "";        // "Default", "Profile 1", ...
            public string Friendly = "";   // display name from Local State
            public string FullPath = "";   // absolute profile directory
        }

        /// <summary>The Chrome/Chromium user-data roots and their channel label.</summary>
        private static List<(string Root, string Channel)> ChromeUserDataRoots()
        {
            string local = Environment.GetEnvironmentVariable("LOCALAPPDATA") ?? "";
            var roots = new List<(string, string)>();
            if (local.Length == 0) return roots;
            roots.Add((Path.Combine(local, "Google", "Chrome", "User Data"), "Chrome"));
            roots.Add((Path.Combine(local, "Google", "Chrome Beta", "User Data"), "Chrome Beta"));
            roots.Add((Path.Combine(local, "Google", "Chrome SxS", "User Data"), "Chrome SxS"));
            roots.Add((Path.Combine(local, "Chromium", "User Data"), "Chromium"));
            return roots;
        }

        /// <summary>All real Chrome profiles across every installed channel.</summary>
        private static List<ProfileCol> EnumerateChromeProfiles()
        {
            var list = new List<ProfileCol>();
            foreach (var (root, channel) in ChromeUserDataRoots())
            {
                if (!Directory.Exists(root)) continue;
                var names = LoadProfileNames(root);                 // shared with the extensions reader
                foreach (var profileDir in SafeDirs(root))
                {
                    string dir = Path.GetFileName(profileDir);
                    if (!(dir == "Default" || dir.StartsWith("Profile", StringComparison.OrdinalIgnoreCase)))
                        continue;
                    // A real profile has at least one of the two preference files.
                    if (!File.Exists(Path.Combine(profileDir, "Preferences")) &&
                        !File.Exists(Path.Combine(profileDir, "Secure Preferences")))
                        continue;

                    string friendly = names.TryGetValue(dir, out var fn) && fn.Length > 0 ? fn : dir;
                    list.Add(new ProfileCol
                    {
                        Key = channel + "|" + dir,
                        Channel = channel,
                        Dir = dir,
                        Friendly = friendly,
                        FullPath = profileDir,
                    });
                }
            }
            return list;
        }

        /// <summary>Builds the ordered column set (Global first) and the backing profile list.</summary>
        private static (List<ColumnDef> Cols, List<ProfileCol> Profiles) DiscoverSettingColumns()
        {
            var profiles = EnumerateChromeProfiles();
            // A friendly name shared by more than one profile gets the channel appended; if that is
            // still not unique (same name + channel), fall back to the profile directory, then an
            // index, so every column header is unambiguous.
            var dupNames = profiles.GroupBy(p => p.Friendly, StringComparer.OrdinalIgnoreCase)
                                   .Where(g => g.Count() > 1)
                                   .Select(g => g.Key)
                                   .ToHashSet(StringComparer.OrdinalIgnoreCase);

            var cols = new List<ColumnDef> { new("__global__", "Global", true) };
            var used = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "Global" };
            foreach (var p in profiles)
            {
                string baseHeader = dupNames.Contains(p.Friendly) ? $"{p.Friendly} ({p.Channel})" : p.Friendly;
                string header = baseHeader;
                if (used.Contains(header)) header = $"{baseHeader} - {p.Dir}";
                for (int n = 2; used.Contains(header); n++) header = $"{baseHeader} - {p.Dir} #{n}";
                used.Add(header);
                cols.Add(new ColumnDef(p.Key, header, false));
            }
            return (cols, profiles);
        }

        /// <summary>Lightweight column list for the UI (no database reads); used to build the grid
        /// columns at tab-construction time without the cost of the per-profile password counts.</summary>
        public static List<ColumnDef> GetChromeSettingColumns() => DiscoverSettingColumns().Cols;

        /// <summary>One entry per Chrome profile (no "Global" column): the grid column header and the
        /// absolute profile directory that holds its Preferences / Secure Preferences JSON. Used by
        /// the Settings tab's right-click "open the backing file" menu. The header matches the grid
        /// column header exactly (same disambiguation), so the menu lines up with the visible columns.</summary>
        public static List<(string Header, string Dir)> GetChromeProfileDirs()
        {
            var (cols, profiles) = DiscoverSettingColumns();
            // cols is "Global" + one per profile, in the same order as `profiles`; zip the non-global
            // columns back onto their profile to recover the friendly header + on-disk path together.
            var profileCols = cols.Where(c => !c.IsGlobal).ToList();
            var list = new List<(string, string)>();
            for (int i = 0; i < profiles.Count && i < profileCols.Count; i++)
                list.Add((profileCols[i].Header, profiles[i].FullPath));
            return list;
        }

        // ----------------------------------------------------------------- //
        // Merged preference reader (Secure Preferences wins, then Preferences)
        // ----------------------------------------------------------------- //
        private sealed class Prefs : IDisposable
        {
            // Secure Preferences first so integrity-protected keys (e.g. the default search
            // provider) take precedence over a possibly-stale copy in plain Preferences.
            private readonly List<JsonDocument> _docs = new();

            public static Prefs Load(string profileDir)
            {
                var p = new Prefs();
                foreach (var file in new[] { "Secure Preferences", "Preferences" })
                {
                    try
                    {
                        string path = Path.Combine(profileDir, file);
                        if (File.Exists(path)) p._docs.Add(JsonDocument.Parse(File.ReadAllText(path)));
                    }
                    catch { /* missing / locked / corrupt - skip this file */ }
                }
                return p;
            }

            private JsonElement? Find(string dottedPath)
            {
                foreach (var doc in _docs)
                {
                    var el = doc.RootElement;
                    bool ok = true;
                    foreach (var part in dottedPath.Split('.'))
                    {
                        if (el.ValueKind == JsonValueKind.Object && el.TryGetProperty(part, out var next))
                            el = next;
                        else { ok = false; break; }
                    }
                    if (ok) return el;
                }
                return null;
            }

            public bool? Bool(string path) => Find(path) is { } e
                ? e.ValueKind == JsonValueKind.True ? true : e.ValueKind == JsonValueKind.False ? false : (bool?)null
                : null;

            public int? Int(string path) =>
                Find(path) is { ValueKind: JsonValueKind.Number } e && e.TryGetInt32(out int i) ? i : (int?)null;

            public string Str(string path) =>
                Find(path) is { ValueKind: JsonValueKind.String } e ? (e.GetString() ?? "") : "";

            public List<string> Arr(string path)
            {
                var list = new List<string>();
                if (Find(path) is { ValueKind: JsonValueKind.Array } e)
                    foreach (var item in e.EnumerateArray())
                        if (item.ValueKind == JsonValueKind.String) list.Add(item.GetString() ?? "");
                return list;
            }

            public void Dispose() { foreach (var d in _docs) d.Dispose(); }
        }

        /// <summary>Counts saved passwords in a profile's Login Data SQLite DB (rows only - no
        /// password contents are read). Copies the DB to Temp first so Chrome is never locked.
        /// Returns null if the database is absent or can't be read.</summary>
        private static int? LoginPasswordCount(string profileDir)
        {
            string src = Path.Combine(profileDir, "Login Data");
            if (!File.Exists(src)) return null;

            string temp = Path.Combine(Path.GetTempPath(), $"LoginData_b4browse_{Guid.NewGuid():N}.db");
            string[] sidecars = { "", "-wal", "-shm" };
            try
            {
                foreach (var ext in sidecars)
                    if (File.Exists(src + ext)) File.Copy(src + ext, temp + ext, true);

                var cs = new SqliteConnectionStringBuilder
                {
                    DataSource = temp,
                    Mode = SqliteOpenMode.ReadWrite,   // lets SQLite fold in the -wal cleanly
                }.ToString();

                using var conn = new SqliteConnection(cs);
                conn.Open();
                using var cmd = conn.CreateCommand();
                cmd.CommandText = "SELECT COUNT(*) FROM logins;";
                var o = cmd.ExecuteScalar();
                return o is long l ? (int)l : (o != null && int.TryParse(o.ToString(), out int n) ? n : 0);
            }
            catch { return null; }
            finally
            {
                foreach (var ext in sidecars)
                {
                    try { if (File.Exists(temp + ext)) File.Delete(temp + ext); } catch { /* best effort */ }
                }
            }
        }

        /// <summary>Per-column enabled-extension counts, keyed by the column key, reusing the
        /// existing extension reader. The channel is recovered from each extension's on-disk path.</summary>
        private static Dictionary<string, int> ExtensionCountsByColumn()
        {
            var counts = new Dictionary<string, int>(StringComparer.Ordinal);
            var roots = ChromeUserDataRoots();
            foreach (var e in GetChromeExtensions())
            {
                if (!e.Enabled) continue;
                string? channel = roots.FirstOrDefault(r =>
                    e.ProfileDir.StartsWith(r.Root, StringComparison.OrdinalIgnoreCase)).Channel;
                if (string.IsNullOrEmpty(channel)) continue;
                string key = channel + "|" + e.ProfileId;
                counts[key] = counts.GetValueOrDefault(key) + 1;
            }
            return counts;
        }

        // ----------------------------------------------------------------- //
        // Setting catalog
        // ----------------------------------------------------------------- //
        /// <summary>Context for evaluating one cell: a profile (with its merged prefs and counts)
        /// or the Global enterprise-policy column.</summary>
        private sealed class Cell
        {
            public bool IsGlobal;
            public Prefs? Prefs;
            public int? PwCount;
            public int? ExtCount;
            public (bool Block3p, int? SbLevel, bool ClearOnExit, bool Any) Policy;
        }

        private sealed class SettingDef
        {
            public string Category = "";
            public int Order;
            public string Label = "";
            public string Link = "";   // chrome:// deep-link that opens this setting's page
            public Func<Cell, (string Val, TabSeverity Risk)> Eval = _ => ("—", TabSeverity.None);
        }

        private static (string, TabSeverity) None(string v) => (v, TabSeverity.None);
        private static string OnOff(bool? b) => b is null ? "Default" : b.Value ? "On" : "Off";

        private static string ContentPerm(int? v) => v switch
        {
            1 => "Allow", 2 => "Block", 3 => "Ask", null => "Default", _ => v.ToString()!,
        };

        private static SettingDef[] BuildCatalog()
        {
            const string P = "Privacy & Security";
            const string AD = "Privacy Sandbox (Ads)";
            const string PW = "Passwords & Autofill";
            const string SITE = "Site permission defaults";
            const string SRCH = "Search & Startup";
            const string DL = "Downloads";
            const string EXT = "Extensions";

            // Helper for a plain on/off preference with no risk and no Global mapping.
            SettingDef Toggle(string cat, int order, string label, string path, string link) => new()
            {
                Category = cat, Order = order, Label = label, Link = link,
                Eval = c => c.IsGlobal ? None("—") : None(OnOff(c.Prefs!.Bool(path))),
            };

            // Like Toggle, but flags the setting as Caution when it is enabled (true = risky on shared machines).
            SettingDef RiskToggle(string cat, int order, string label, string path, string link) => new()
            {
                Category = cat, Order = order, Label = label, Link = link,
                Eval = c =>
                {
                    if (c.IsGlobal) return None("—");
                    bool? b = c.Prefs!.Bool(path);
                    return (OnOff(b), b == true ? TabSeverity.Caution : TabSeverity.None);
                },
            };

            // Helper for a default content-setting permission; "allow" is flagged when risky.
            // Each permission's page lives under chrome://settings/content/<key>.
            SettingDef Perm(int order, string label, string key, bool allowRisky, string contentPath) => new()
            {
                Category = SITE, Order = order, Label = label,
                Link = "chrome://settings/content/" + contentPath,
                Eval = c =>
                {
                    if (c.IsGlobal) return None("—");
                    int? v = c.Prefs!.Int("profile.default_content_setting_values." + key);
                    var risk = allowRisky && v == 1 ? TabSeverity.Caution : TabSeverity.None;
                    return (ContentPerm(v), risk);
                },
            };

            return new[]
            {
                // ---- Privacy & Security ---------------------------------- //
                new SettingDef { Category = P, Order = 1, Label = "Safe Browsing",
                    Link = "chrome://settings/security", Eval = c =>
                {
                    if (c.IsGlobal)
                        return None(c.Policy.SbLevel switch
                        { 2 => "Enhanced (policy)", 1 => "Standard (policy)", 0 => "Off (policy)", _ => "—" });
                    bool? en = c.Prefs!.Bool("safebrowsing.enabled");
                    bool? enh = c.Prefs!.Bool("safebrowsing.enhanced");
                    if (en == false) return ("Off", TabSeverity.Alert);
                    string v = enh == true ? "Enhanced" : en == true ? "Standard" : "Default";
                    return (v, TabSeverity.None);
                } },
                new SettingDef { Category = P, Order = 2, Label = "Third-party cookies",
                    Link = "chrome://settings/cookies", Eval = c =>
                {
                    if (c.IsGlobal) return None(c.Policy.Block3p ? "Blocked (policy)" : "—");
                    int? v = c.Prefs!.Int("profile.cookie_controls_mode");
                    string txt = v switch
                    { 0 => "Allowed", 1 => "Block in Incognito", 2 => "Blocked", null => "Default", _ => v.ToString()! };
                    return (txt, v == 0 ? TabSeverity.Caution : TabSeverity.None);
                } },
                new SettingDef { Category = P, Order = 3, Label = "Clear cookies on exit",
                    Link = "chrome://settings/content/cookies", Eval = c =>
                {
                    if (c.IsGlobal) return None(c.Policy.ClearOnExit ? "On (policy)" : "—");
                    int? v = c.Prefs!.Int("profile.default_content_setting_values.cookies");
                    return None(v switch { 4 => "Clear on exit", 1 => "Keep", null => "Default", _ => v.ToString()! });
                } },
                Toggle(P, 4, "HTTPS-Only mode", "https_only_mode_enabled", "chrome://settings/security"),
                Toggle(P, 5, "Do Not Track", "enable_do_not_track", "chrome://settings/cookies"),
                new SettingDef { Category = P, Order = 6, Label = "Preload pages",
                    Link = "chrome://settings/performance", Eval = c =>
                {
                    if (c.IsGlobal) return None("—");
                    int? v = c.Prefs!.Int("net.network_prediction_options");
                    return None(v switch { 0 => "Always", 1 => "Wi-Fi only", 2 => "Never", null => "Default", _ => v.ToString()! });
                } },

                // ---- Privacy Sandbox (Ads) ------------------------------- //
                AdToggle(AD, 1, "Ad topics", "privacy_sandbox.m1.topics_enabled", "chrome://settings/adPrivacy/interests"),
                AdToggle(AD, 2, "Site-suggested ads", "privacy_sandbox.m1.fledge_enabled", "chrome://settings/adPrivacy/sites"),
                AdToggle(AD, 3, "Ad measurement", "privacy_sandbox.m1.ad_measurement_enabled", "chrome://settings/adPrivacy/measurement"),

                // ---- Passwords & Autofill -------------------------------- //
                Toggle(PW, 1, "Offer to save passwords", "credentials_enable_service", "chrome://password-manager/settings"),
                Toggle(PW, 2, "Auto sign-in", "credentials_enable_autosignin", "chrome://password-manager/settings"),
                new SettingDef { Category = PW, Order = 3, Label = "Saved passwords (count)",
                    Link = "chrome://password-manager/passwords", Eval = c =>
                    c.IsGlobal ? None("—") : None(c.PwCount?.ToString() ?? "—") },
                Toggle(PW, 4, "Autofill addresses", "autofill.profile_enabled", "chrome://settings/addresses"),
                RiskToggle(PW, 5, "Autofill payment methods", "autofill.credit_card_enabled", "chrome://settings/payments"),

                // ---- Site permission defaults ---------------------------- //
                Perm(1, "Notifications", "notifications", allowRisky: true, "notifications"),
                Perm(2, "Location", "geolocation", allowRisky: true, "location"),
                Perm(3, "Camera", "media_stream_camera", allowRisky: true, "camera"),
                Perm(4, "Microphone", "media_stream_mic", allowRisky: true, "microphone"),
                new SettingDef { Category = SITE, Order = 5, Label = "Pop-ups",
                    Link = "chrome://settings/content/popups", Eval = c =>
                {
                    if (c.IsGlobal) return None("—");
                    int? v = c.Prefs!.Int("profile.default_content_setting_values.popups");
                    string txt = v switch { 1 => "Allow", 2 => "Block", null => "Default", _ => v.ToString()! };
                    return (txt, v == 1 ? TabSeverity.Caution : TabSeverity.None);
                } },
                Perm(6, "JavaScript", "javascript", allowRisky: false, "javascript"),
                Perm(7, "Images", "images", allowRisky: false, "images"),
                Perm(8, "Sound", "sound", allowRisky: false, "sound"),
                Perm(9, "Automatic downloads", "automatic_downloads", allowRisky: true, "automaticDownloads"),

                // ---- Search & Startup ------------------------------------ //
                new SettingDef { Category = SRCH, Order = 1, Label = "Default search engine",
                    Link = "chrome://settings/search", Eval = c =>
                {
                    if (c.IsGlobal) return None("—");
                    string nm = c.Prefs!.Str("default_search_provider_data.template_url_data.short_name");
                    return None(nm.Length > 0 ? nm : "Default");
                } },
                new SettingDef { Category = SRCH, Order = 2, Label = "On startup",
                    Link = "chrome://settings/onStartup", Eval = c =>
                {
                    if (c.IsGlobal) return None("—");
                    int? v = c.Prefs!.Int("session.restore_on_startup");
                    return None(v switch
                    { 1 => "Restore last session", 4 => "Open specific pages", 5 => "New Tab page", null => "Default", _ => v.ToString()! });
                } },
                new SettingDef { Category = SRCH, Order = 3, Label = "Startup pages",
                    Link = "chrome://settings/onStartup", Eval = c =>
                {
                    if (c.IsGlobal) return None("—");
                    var urls = c.Prefs!.Arr("session.startup_urls");
                    return None(urls.Count == 0 ? "Default" : string.Join(", ", urls));
                } },

                // ---- Downloads ------------------------------------------- //
                new SettingDef { Category = DL, Order = 1, Label = "Download location",
                    Link = "chrome://settings/downloads", Eval = c =>
                {
                    if (c.IsGlobal) return None("—");
                    string dir = c.Prefs!.Str("download.default_directory");
                    return None(dir.Length > 0 ? dir : "Default");
                } },
                new SettingDef { Category = DL, Order = 2, Label = "Ask where to save",
                    Link = "chrome://settings/downloads", Eval = c =>
                {
                    if (c.IsGlobal) return None("—");
                    bool? b = c.Prefs!.Bool("download.prompt_for_download");
                    return None(b is null ? "Default" : b.Value ? "Ask each time" : "Auto-save");
                } },

                // ---- Extensions ------------------------------------------ //
                new SettingDef { Category = EXT, Order = 1, Label = "Extensions (enabled)",
                    Link = "chrome://extensions", Eval = c =>
                    c.IsGlobal ? None("—") : None(c.ExtCount?.ToString() ?? "0") },
            };
        }

        /// <summary>A Privacy-Sandbox toggle: "On" is the tracking-enabled state, so flag it.</summary>
        private static SettingDef AdToggle(string cat, int order, string label, string path, string link) => new()
        {
            Category = cat, Order = order, Label = label, Link = link,
            Eval = c =>
            {
                if (c.IsGlobal) return None("—");
                bool? b = c.Prefs!.Bool(path);
                return (OnOff(b), b == true ? TabSeverity.Caution : TabSeverity.None);
            },
        };

        // ----------------------------------------------------------------- //
        // Matrix build (structured, for the UI) + report producer
        // ----------------------------------------------------------------- //
        /// <summary>Builds the full Settings matrix: columns (Global + each profile) and one row
        /// per catalog setting, with per-cell values and risk colouring.</summary>
        public static ChromeSettingsMatrix GetChromeSettings()
        {
            var matrix = new ChromeSettingsMatrix();
            var (cols, profiles) = DiscoverSettingColumns();
            matrix.Columns = cols;

            var catalog = BuildCatalog();
            var rows = catalog.Select(d => new SettingRow
            {
                Category = d.Category,
                CategoryOrder = d.Order + CategoryBase(d.Category),
                Label = d.Label,
                Link = d.Link,
            }).ToList();
            matrix.Rows = rows;

            void Fill(string colKey, Cell cell)
            {
                for (int i = 0; i < catalog.Length; i++)
                {
                    var (val, risk) = catalog[i].Eval(cell);
                    rows[i].Values[colKey] = val;
                    if (risk != TabSeverity.None)
                    {
                        rows[i].Risk[colKey] = risk;
                        matrix.Severity = Sev.Max(matrix.Severity, risk);
                    }
                }
            }

            // Global (enterprise policy) column.
            Fill("__global__", new Cell { IsGlobal = true, Policy = ChromePolicy() });

            // One column per profile. Extension counts come from a single shared read.
            var extCounts = ExtensionCountsByColumn();
            foreach (var p in profiles)
            {
                using var prefs = Prefs.Load(p.FullPath);
                Fill(p.Key, new Cell
                {
                    Prefs = prefs,
                    PwCount = LoginPasswordCount(p.FullPath),
                    ExtCount = extCounts.GetValueOrDefault(p.Key),
                });
            }

            return matrix;
        }

        /// <summary>Spaces categories apart so a single composite order groups them in display order.</summary>
        private static int CategoryBase(string category) => category switch
        {
            "Privacy & Security" => 100,
            "Privacy Sandbox (Ads)" => 200,
            "Passwords & Autofill" => 300,
            "Site permission defaults" => 400,
            "Search & Startup" => 500,
            "Downloads" => 600,
            "Extensions" => 700,
            _ => 900,
        };

        /// <summary>Report producer (headless / email / copy): the settings matrix as a text table.</summary>
        public static CheckGroup CheckChromeSettings()
        {
            var g = new CheckGroup("Chrome Settings");
            var matrix = GetChromeSettings();

            var profileCols = matrix.Columns;   // Global + profiles
            if (matrix.Rows.Count == 0 || profileCols.Count == 0)
            {
                g.Add(CheckStatus.Info, "Chrome settings", "No Chrome profiles found.");
                return g;
            }

            // Column widths: label + each value column (capped so the report stays readable, always
            // leaving at least a one-space gutter between columns).
            const int labelW = 26, valW = 20;
            string Cell(string s, int w) => (s.Length > w - 1 ? s.Substring(0, w - 2) + "…" : s).PadRight(w);

            var header = new StringBuilder(Cell("Setting", labelW));
            foreach (var col in profileCols) header.Append(Cell(col.Header, valW));
            g.AddRow(CheckStatus.Info, header.ToString());

            int weak = 0;
            foreach (var row in matrix.Rows.OrderBy(r => r.CategoryOrder))
            {
                var sb = new StringBuilder(Cell(row.Label, labelW));
                var worst = TabSeverity.None;
                foreach (var col in profileCols)
                {
                    sb.Append(Cell(row.Values.GetValueOrDefault(col.Key, "—"), valW));
                    if (row.Risk.TryGetValue(col.Key, out var r)) worst = Sev.Max(worst, r);
                }
                if (worst != TabSeverity.None) weak++;
                g.AddRow(SevToStatus(worst), sb.ToString());
            }

            // Non-table summary line so the headless verdict can reflect weak settings.
            int profiles = profileCols.Count(c => !c.IsGlobal);
            var status = matrix.Severity switch
            {
                TabSeverity.Alert => CheckStatus.Fail,
                TabSeverity.Caution => CheckStatus.Warn,
                _ => CheckStatus.Pass,
            };
            g.Add(status, "Chrome settings",
                $"{profiles} profile(s), {matrix.Rows.Count} setting(s); {weak} row(s) with a highlighted value.");
            return g;
        }

        private static CheckStatus SevToStatus(TabSeverity s) => s switch
        {
            TabSeverity.Alert => CheckStatus.Fail,
            TabSeverity.Caution => CheckStatus.Warn,
            _ => CheckStatus.Info,
        };
    }
}
