// Copyright (c) 2026 LanDen Labs - Dennis Lang

using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using Microsoft.Data.Sqlite;

namespace BrowseSafe
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
            if (!File.Exists(src)) return list;

            // Last-run times to merge in by executable path (empty when not running elevated).
            var lastRun = LoadPcaLaunchTimes();
            // Paths consumed by an indexed app, so the leftovers can become their own rows below.
            var matchedPaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            // Stage a private copy in Temp to avoid contending with Windows Search for the file.
            string temp = Path.Combine(Path.GetTempPath(), $"AppsIndex_bsafe_{Guid.NewGuid():N}.db");
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
            return list;
        }

        /// <summary>Reads a column that may be stored untyped (FTS5) as a 64-bit integer.</summary>
        private static long ReadLong(SqliteDataReader r, int i)
        {
            if (r.IsDBNull(i)) return 0;
            try { return r.GetInt64(i); }
            catch { return long.TryParse(r.GetValue(i)?.ToString(), out var v) ? v : 0; }
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

            if (!File.Exists(AppsIndexDbPath))
            {
                group.Add(CheckStatus.Info, "App index",
                    "AppsIndex.db not found - Windows Search's app-usage index is unavailable on this machine.");
                return group;
            }

            var items = GetAppActivity();
            if (items.Count == 0)
            {
                group.Add(CheckStatus.Info, "App index", "No launched apps recorded in the Windows Search index.");
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
