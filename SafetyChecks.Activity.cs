// Copyright (c) 2026 LanDen Labs - Dennis Lang

using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using Microsoft.Data.Sqlite;

namespace B4Browse
{
    /// <summary>
    /// App launch activity (the Activity tab). Windows Search keeps an app-usage index in a
    /// SQLite database (AppsIndex.db); its <c>tiles</c> table records, per app, a launch count
    /// that Windows uses to rank Start-menu / search results. Reading it surfaces which apps
    /// run on this machine and how often - a behavioural signal (e.g. an unfamiliar program with
    /// a high launch count, or one launched from a transient Temp/Downloads folder). The index
    /// stores no timestamps, so this is a frequency view, not a timeline. No admin rights needed.
    /// </summary>
    public static partial class SafetyChecks
    {
        /// <summary>Per-user Windows Search app index (CBS package LocalState).</summary>
        private static string AppsIndexDbPath => Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            @"Packages\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\LocalState\Search\AppsIndex.db");

        /// <summary>
        /// Reads the launch history from AppsIndex.db. The live database is copied to a temp file
        /// first (with its -wal/-shm sidecars) so we never lock or modify Windows Search's copy,
        /// then queried read-only-in-effect. Returns an empty list if the database is absent (older
        /// Windows builds) or can't be read.
        /// </summary>
        public static List<AppActivity> GetAppActivity()
        {
            var list = new List<AppActivity>();
            string src = AppsIndexDbPath;

            // Last-run times to merge in by executable path (empty when not running elevated).
            var lastRun = LoadPcaLaunchTimes();
            // Paths consumed by an indexed app, so the leftovers can become their own rows below.
            var matchedPaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            // Secondary index for a name-based fallback: executable base name with the .exe
            // suffix removed, keyed case-insensitively, -> the most recent PCA entry (time +
            // originating path). Lets an indexed app whose on-disk path we couldn't resolve
            // (identifier-only appIds) still pick up a last-run time when its display name
            // matches the launched exe - e.g. PCA "Slack.exe" / "slack.exe" -> app "Slack".
            var lastRunByName = new Dictionary<string, (DateTime When, string Path)>(StringComparer.OrdinalIgnoreCase);
            foreach (var kv in lastRun)
            {
                string nm = StripExeSuffix(Path.GetFileName(kv.Key));
                if (nm.Length == 0) continue;
                if (!lastRunByName.TryGetValue(nm, out var prev) || kv.Value > prev.When)
                    lastRunByName[nm] = (kv.Value, kv.Key);
            }

            // Windows 11 keeps a per-user app-usage index (AppsIndex.db); read it when present.
            // Windows 10 has no such database - the UserAssist fallback at the end covers that case.
            if (File.Exists(src))
            {
                // Stage a private copy in Temp to avoid contending with Windows Search for the file.
                string temp = Path.Combine(Path.GetTempPath(), $"AppsIndex_b4browse_{Guid.NewGuid():N}.db");
                string[] sidecars = { "", "-wal", "-shm" };
                try
                {
                    foreach (var ext in sidecars)
                        if (File.Exists(src + ext)) File.Copy(src + ext, temp + ext, true);

                    // Open the throwaway copy read-write so SQLite can fold in the -wal cleanly; the
                    // bundled native provider (Microsoft.Data.Sqlite) supplies the FTS5 module the
                    // virtual 'tiles' table is built on.
                    var cs = new SqliteConnectionStringBuilder
                    {
                        DataSource = temp,
                        Mode = SqliteOpenMode.ReadWrite,
                    }.ToString();

                    using var conn = new SqliteConnection(cs);
                    conn.Open();
                    using var cmd = conn.CreateCommand();
                    cmd.CommandText =
                        "SELECT serializedId, appId, cRank, displayName, launchCount FROM tiles " +
                        "WHERE CAST(launchCount AS INTEGER) > 0 ORDER BY CAST(launchCount AS INTEGER) DESC;";
                    using var reader = cmd.ExecuteReader();
                    while (reader.Read())
                    {
                        var a = new AppActivity
                        {
                            SerializedId = reader.IsDBNull(0) ? "" : reader.GetString(0),
                            AppId = reader.IsDBNull(1) ? "" : reader.GetString(1),
                            CRank = ReadLong(reader, 2),
                            DisplayName = reader.IsDBNull(3) ? "" : reader.GetString(3),
                            LaunchCount = ReadLong(reader, 4),
                        };
                        a.Kind = a.SerializedId.StartsWith("W~", StringComparison.Ordinal) ? "Win32"
                               : a.SerializedId.StartsWith("P~", StringComparison.Ordinal) ? "Packaged"
                               : "Other";
                        a.ResolvedPath = ResolveAppPath(a.AppId);
                        if (a.ResolvedPath.Length > 0 && lastRun.TryGetValue(a.ResolvedPath, out var when))
                        {
                            a.LastExecuted = when;
                            a.LastExecutedText = when.ToString("yyyy-MM-dd HH:mm");
                            matchedPaths.Add(a.ResolvedPath);
                        }
                        // Path didn't resolve/match - fall back to a case-insensitive name match
                        // (display name vs the launched exe with its .exe suffix stripped).
                        else if (StripExeSuffix(a.DisplayName) is { Length: > 0 } key &&
                                 lastRunByName.TryGetValue(key, out var byName))
                        {
                            a.LastExecuted = byName.When;
                            a.LastExecutedText = byName.When.ToString("yyyy-MM-dd HH:mm");
                            matchedPaths.Add(byName.Path);
                        }
                        ClassifyActivity(a);
                        list.Add(a);
                    }
                }
                catch { /* absent module / locked / corrupt - return what we have */ }
                finally
                {
                    foreach (var ext in sidecars)
                    {
                        try { if (File.Exists(temp + ext)) File.Delete(temp + ext); } catch { /* best effort */ }
                    }
                }
            }

            // PCA recorded a last-run time for an executable the app-usage index never tracked: the
            // app ran but has no index row to merge into. Surface it anyway as its own row - we know
            // the path and when it ran, but nothing else, so launch count is 1 and the index-only
            // columns (Type / Rank) read "--".
            foreach (var kv in lastRun)
            {
                if (matchedPaths.Contains(kv.Key)) continue;
                var a = new AppActivity
                {
                    AppId = kv.Key,
                    ResolvedPath = kv.Key,
                    DisplayName = Path.GetFileName(kv.Key) is { Length: > 0 } name ? name : kv.Key,
                    LaunchCount = 1,
                    Kind = "--",
                    LastExecuted = kv.Value,
                    LastExecutedText = kv.Value.ToString("yyyy-MM-dd HH:mm"),
                    IsLastRunOnly = true,
                };
                ClassifyActivity(a);
                list.Add(a);
            }

            // Windows 10 fallback: neither the Windows 11 app-usage index nor the PCA launch log
            // produced anything, so derive launch activity from the UserAssist registry instead.
            // Gated to Windows 10 (and earlier) - on Windows 11 the index above is the better
            // source and folding UserAssist in would duplicate rows with a different count.
            if (list.Count == 0 && IsWindows10OrEarlier())
                list.AddRange(LoadUserAssistActivity());

            return list;
        }

        /// <summary>
        /// True on Windows 10 (and earlier). Windows 11's first build is 22000, so a build number
        /// below that is Windows 10 or older - the versions that lack the app-usage index and need
        /// the UserAssist fallback.
        /// </summary>
        private static bool IsWindows10OrEarlier() => Environment.OSVersion.Version.Build < 22000;

        /// <summary>
        /// Windows 10 fallback source for the Activity tab. Windows 11 keeps an app-usage index
        /// (AppsIndex.db) that Windows 10 lacks, so on Windows 10 the launch history is read from
        /// the per-user UserAssist registry keys instead - Explorer maintains these on every desktop
        /// Windows version. Each entry records a run count and a last-execution time (FILETIME); the
        /// value names are ROT13-encoded executable paths (Known-Folder GUIDs expanded the same way
        /// as index appIds). Only the executables sub-GUID is read; the sibling shortcut (.lnk) GUID
        /// is skipped. Returns an empty list when the key is absent or unreadable. No admin rights.
        /// </summary>
        private static List<AppActivity> LoadUserAssistActivity()
        {
            var list = new List<AppActivity>();
            const string countKey =
                @"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\" +
                @"{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count";
            try
            {
                using var key = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(countKey);
                if (key is null) return list;

                foreach (string rawName in key.GetValueNames())
                {
                    if (rawName.Length == 0) continue;
                    string name = Rot13(rawName);
                    // Session/rollup markers (UEME_CTLSESSION, UEME_RUNPATH, ...) aren't real launches.
                    if (name.StartsWith("UEME_", StringComparison.OrdinalIgnoreCase)) continue;

                    // Windows 7+ entries are a 72-byte blob: run count at offset 4 (DWORD), last-run
                    // FILETIME at offset 0x3C (8 bytes). Skip anything too short to hold both.
                    if (key.GetValue(rawName) is not byte[] data || data.Length < 68) continue;

                    long count = BitConverter.ToUInt32(data, 4);
                    if (count == 0) continue;

                    DateTime? when = null;
                    string whenText = "—";
                    long ft = BitConverter.ToInt64(data, 60);   // UTC FILETIME
                    if (ft > 0)
                    {
                        try
                        {
                            DateTime dt = DateTime.FromFileTimeUtc(ft).ToLocalTime();
                            when = dt;
                            whenText = dt.ToString("yyyy-MM-dd HH:mm");
                        }
                        catch { /* out-of-range FILETIME - leave the When column blank */ }
                    }

                    string resolved = ResolveAppPath(name);
                    string display = Path.GetFileName(resolved.Length > 0 ? resolved : name);
                    if (display.Length == 0) display = name;

                    var a = new AppActivity
                    {
                        AppId = name,
                        ResolvedPath = resolved,
                        DisplayName = display,
                        LaunchCount = count,
                        Kind = "UserAssist",
                        LastExecuted = when,
                        LastExecutedText = whenText,
                        IsUserAssist = true,
                    };
                    ClassifyActivity(a);
                    list.Add(a);
                }
            }
            catch { /* missing key / access denied - return what we have */ }

            list.Sort((x, y) => y.LaunchCount.CompareTo(x.LaunchCount));   // most-launched first
            return list;
        }

        /// <summary>ROT13 transform - the (reversible) obfuscation Windows applies to UserAssist
        /// value names. Only ASCII letters rotate; digits, GUIDs, separators and dots pass through.</summary>
        private static string Rot13(string s)
        {
            char[] chars = s.ToCharArray();
            for (int i = 0; i < chars.Length; i++)
            {
                char c = chars[i];
                if (c is >= 'a' and <= 'z') chars[i] = (char)('a' + (c - 'a' + 13) % 26);
                else if (c is >= 'A' and <= 'Z') chars[i] = (char)('A' + (c - 'A' + 13) % 26);
            }
            return new string(chars);
        }

        /// <summary>Reads a column that may be stored untyped (FTS5) as a 64-bit integer.</summary>
        private static long ReadLong(SqliteDataReader r, int i)
        {
            if (r.IsDBNull(i)) return 0;
            try { return r.GetInt64(i); }
            catch { return long.TryParse(r.GetValue(i)?.ToString(), out var v) ? v : 0; }
        }

        /// <summary>
        /// Strips a trailing ".exe" (case-insensitive) so a launched executable name can be
        /// compared to a friendly display name. Only ".exe" is removed - names that merely
        /// contain dots (e.g. "Node.js") are left intact.
        /// </summary>
        private static string StripExeSuffix(string name)
        {
            name = name.Trim();
            return name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ? name[..^4] : name;
        }

        /// <summary>Program Compatibility Assistant launch log - the only per-app "last run" source.</summary>
        private static string PcaLaunchLogPath => Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.Windows), @"appcompat\pca\PcaAppLaunchDic.txt");

        /// <summary>
        /// Parses the PCA launch log (one "exe-path|yyyy-MM-dd HH:mm:ss.fff" line per app) into a
        /// path -> last-run map, keyed case-insensitively for matching against resolved app paths.
        /// Returns an empty map if the file is missing or unreadable - it lives under C:\Windows and
        /// generally requires administrator rights, so without elevation the When column stays blank.
        /// </summary>
        private static Dictionary<string, DateTime> LoadPcaLaunchTimes()
        {
            var map = new Dictionary<string, DateTime>(StringComparer.OrdinalIgnoreCase);
            try
            {
                if (!File.Exists(PcaLaunchLogPath)) return map;
                foreach (var line in File.ReadLines(PcaLaunchLogPath))
                {
                    int bar = line.IndexOf('|');
                    if (bar <= 0) continue;
                    string path = line.Substring(0, bar).Trim();
                    string stamp = line.Substring(bar + 1).Trim();
                    if (path.Length == 0) continue;

                    // The PCA log records timestamps in UTC (no offset); parse as UTC, then convert
                    // to the user's local time so the When column reads in their timezone.
                    const DateTimeStyles asUtc = DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal;
                    if (!DateTime.TryParseExact(stamp, "yyyy-MM-dd HH:mm:ss.fff",
                            CultureInfo.InvariantCulture, asUtc, out var dt) &&
                        !DateTime.TryParse(stamp, CultureInfo.InvariantCulture, asUtc, out dt))
                        continue;
                    dt = dt.ToLocalTime();

                    // Last write wins - keep the most recent timestamp if a path repeats.
                    if (!map.TryGetValue(path, out var prev) || dt > prev) map[path] = dt;
                }
            }
            catch { /* access denied (not elevated) / locked - leave the map empty */ }
            return map;
        }

        /// <summary>Common Known-Folder GUIDs used as a prefix in tile appIds (e.g. a VLC tile's
        /// appId is "{6D809377-…}\VideoLAN\VLC\vlc.exe"). Maps each to the local folder so the
        /// path can be expanded and the executable located on disk.</summary>
        private static readonly Dictionary<string, Environment.SpecialFolder> KnownFolders = new(StringComparer.OrdinalIgnoreCase)
        {
            ["{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}"] = Environment.SpecialFolder.System,        // System32
            ["{D65231B0-B2F1-4857-A4CE-A8E7C6EA7D27}"] = Environment.SpecialFolder.SystemX86,     // SysWOW64
            ["{F38BF404-1D43-42F2-9305-67DE0B28FC23}"] = Environment.SpecialFolder.Windows,       // Windows
            ["{6D809377-6AF0-444B-8957-A3773F02200E}"] = Environment.SpecialFolder.ProgramFiles,  // Program Files (x64)
            ["{7C5A40EF-A0FB-4BFC-874A-C0F2E0B9FA8E}"] = Environment.SpecialFolder.ProgramFilesX86,
            ["{905E63B6-C1BF-494E-B29C-65B732D3D21A}"] = Environment.SpecialFolder.ProgramFiles,  // Program Files
            ["{F1B32785-6FBA-4FCF-9D55-7B8E7F157091}"] = Environment.SpecialFolder.LocalApplicationData,
            ["{3EB685DB-65F9-4CF6-A03A-E3EF65729F3D}"] = Environment.SpecialFolder.ApplicationData, // Roaming
        };

        /// <summary>
        /// Expands a tile appId to a real executable path when it is path-shaped: a plain absolute
        /// path is returned as-is; a "{KnownFolderGuid}\rest\app.exe" form has the GUID replaced by
        /// the resolved folder. Returns "" for identifier-only appIds (e.g. "Chrome", an AUMID).
        /// </summary>
        public static string ResolveAppPath(string appId)
        {
            if (string.IsNullOrEmpty(appId)) return "";

            // Already a plain absolute path (drive- or UNC-rooted).
            if (appId.Length > 2 && appId[1] == ':' && appId[2] == '\\') return appId;
            if (appId.StartsWith(@"\\", StringComparison.Ordinal)) return appId;

            // "{GUID}\rest\of\path.exe"
            if (appId.StartsWith("{", StringComparison.Ordinal))
            {
                int brace = appId.IndexOf('}');
                if (brace > 0)
                {
                    string guid = appId.Substring(0, brace + 1);
                    string rest = appId.Substring(brace + 1).TrimStart('\\');
                    if (KnownFolders.TryGetValue(guid, out var folder))
                    {
                        try
                        {
                            string root = Environment.GetFolderPath(folder);
                            if (root.Length > 0) return Path.Combine(root, rest);
                        }
                        catch { /* fall through */ }
                    }
                }
            }
            return "";
        }

        /// <summary>
        /// Conservative per-row audit: flag an app whose launched executable lives in a transient
        /// folder (Temp / Downloads) - a place legitimate installed software does not run from, and
        /// a classic spot for drive-by / dropped payloads. Everything else stays unflagged (the
        /// index carries no dates, so there is nothing recency-based to colour).
        /// </summary>
        private static void ClassifyActivity(AppActivity a)
        {
            string p = a.ResolvedPath.Length > 0 ? a.ResolvedPath : a.AppId;
            if (p.Length == 0) return;

            if (p.Contains(@"\Temp\", StringComparison.OrdinalIgnoreCase) ||
                p.Contains(@"\Downloads\", StringComparison.OrdinalIgnoreCase) ||
                p.Contains(@"\Windows\Temp\", StringComparison.OrdinalIgnoreCase))
            {
                a.Risk = TabSeverity.Caution;
                a.Note = "launched from a transient folder (Temp/Downloads) - verify it is expected";
            }
        }

        // ----------------------------------------------------------------- //
        // Report producer (headless / email / copy)
        // ----------------------------------------------------------------- //
        public static CheckGroup CheckActivity()
        {
            var group = new CheckGroup("App Launch Activity");

            var items = GetAppActivity();
            if (items.Count == 0)
            {
                // Windows 11 reads the Search app-usage index; Windows 10 falls back to UserAssist.
                group.Add(CheckStatus.Info, "App index", IsWindows10OrEarlier()
                    ? "No app-launch activity found (UserAssist registry empty)."
                    : "No launched apps recorded - Windows Search's app-usage index (AppsIndex.db) is unavailable.");
                return group;
            }

            group.Add(CheckStatus.Info, "Tracked apps", $"{items.Count} app(s) with a recorded launch count.");

            foreach (var a in items.Where(a => a.Risk >= TabSeverity.Caution))
                group.Add(CheckStatus.Warn, a.DisplayName,
                    $"{a.LaunchCount} launch(es)  -  {(a.ResolvedPath.Length > 0 ? a.ResolvedPath : a.AppId)}  ({a.Note})");

            int shown = 0;
            foreach (var a in items)   // already ordered by launch count, descending
            {
                if (a.Risk >= TabSeverity.Caution) continue;   // already listed above
                if (++shown > MaxList) break;
                string last = a.LastExecuted.HasValue ? $"  -  last run {a.LastExecutedText}" : "";
                group.Add(CheckStatus.Info, $"{a.LaunchCount,6}  {a.DisplayName}",
                    $"{a.Kind}  -  {(a.ResolvedPath.Length > 0 ? a.ResolvedPath : a.AppId)}{last}");
            }
            int rest = items.Count(a => a.Risk < TabSeverity.Caution) - shown;
            if (rest > 0) group.Add(CheckStatus.Info, "...", $"{rest} more not shown.");
            return group;
        }
    }
}
