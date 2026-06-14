// Copyright (c) 2026 LanDen Labs - Dennis Lang

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Principal;
using System.Text;
using Microsoft.Isam.Esent;          // EsentException (base)
using Microsoft.Isam.Esent.Interop;

namespace B4Browse
{
    /// <summary>
    /// Per-application network usage from SRUM (the Downloads tab). Windows' System Resource
    /// Usage Monitor logs, per process and ~hourly interval, the bytes each app sent and received,
    /// in an ESE / Jet-Blue database at C:\Windows\System32\sru\SRUDB.dat. That file is held open
    /// by the Diagnostic Policy Service and lives under System32, so reading it needs administrator
    /// rights and a forensic copy: we snapshot the live database with esentutl, repair the copy if
    /// it is in a dirty-shutdown state, then read it with the managed ESE API. Bytes are summed per
    /// app over SRUM's retention window (~30-60 days). High "Received" totals are an app's downloads;
    /// a large "Sent" by an unexpected process is a data-exfiltration signal worth a look.
    /// </summary>
    public static partial class SafetyChecks
    {
        public static string SruDbPath => Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.System), @"sru\SRUDB.dat");

        // The network-data-usage table is identified by its BytesSent/BytesRecvd columns rather than
        // a fixed name: SRUM's per-provider table GUID differs across Windows builds (e.g. it is
        // {973F5D5C-251D-...} in published references but {973F5D5C-1D90-...} on some Win11 builds).

        // Short-lived memo so the tab's summary + loader (back-to-back) don't each re-copy/parse.
        private static readonly object _sruLock = new();
        private static List<SruNetUsage>? _sruCache;
        private static long _sruCacheTick;
        /// <summary>One-line status from the last read attempt, shown in the tab header.</summary>
        public static string SruStatus { get; private set; } = "Not yet read.";

        /// <summary>
        /// Returns per-app network totals from SRUM, newest-and-heaviest first. Empty (with
        /// <see cref="SruStatus"/> set to the reason) when not elevated, when SRUDB.dat or esentutl
        /// is unavailable, or when the database can't be read. Never throws.
        /// </summary>
        public static List<SruNetUsage> GetDownloadUsage()
        {
            lock (_sruLock)
            {
                // Reuse a result computed in the last few seconds (summary call then loader call).
                if (_sruCache != null && Environment.TickCount64 - _sruCacheTick < 15_000)
                    return _sruCache;

                var list = ReadDownloadUsage();
                _sruCache = list;
                _sruCacheTick = Environment.TickCount64;
                return list;
            }
        }

        private static List<SruNetUsage> ReadDownloadUsage()
        {
            var empty = new List<SruNetUsage>();
            if (!Elevation.IsAdmin)
            {
                SruStatus = "Requires administrator";
                return empty;
            }
            if (!File.Exists(SruDbPath))
            {
                SruStatus = "SRUDB.dat not found - SRUM may be disabled on this machine.";
                return empty;
            }

            string copy = Path.Combine(Path.GetTempPath(), $"SRUDB_b4browse_{Guid.NewGuid():N}.dat");
            string workDir = Path.Combine(Path.GetTempPath(), $"sru_b4browse_{Guid.NewGuid():N}");
            try
            {
                Directory.CreateDirectory(workDir);

                // Snapshot the live database. esentutl /y can often copy it directly even though
                // the Diagnostic Policy Service holds it open; when the live file is locked
                // (JET_errFileAccessDenied) we retry through a VSS snapshot, which reads a frozen
                // copy of the volume and is the reliable way to grab an in-use system database.
                if (!TryCopySru(copy, out string copyErr))
                {
                    SruStatus = "Could not copy SRUDB.dat with esentutl.  " + copyErr;
                    return empty;
                }

                List<SruNetUsage> rows;
                try
                {
                    rows = ParseSru(copy, workDir);
                }
                catch (EsentException)
                {
                    // The snapshot is almost always in a dirty-shutdown state on a live machine;
                    // repair the throwaway copy in place and read it once more.
                    RunEsentutl($"/p \"{copy}\" /o", out _);
                    rows = ParseSru(copy, workDir);
                }

                SruStatus = rows.Count > 0
                    ? $"{rows.Count} app(s) with recorded network usage."
                    : "No network usage recorded in SRUM.";
                return rows;
            }
            catch (Exception ex)
            {
                SruStatus = "Could not read SRUM: " + ex.Message;
                return empty;
            }
            finally
            {
                try { if (File.Exists(copy)) File.Delete(copy); } catch { /* best effort */ }
                try { if (Directory.Exists(workDir)) Directory.Delete(workDir, true); } catch { /* best effort */ }
            }
        }

        /// <summary>Copies the live SRUDB.dat to <paramref name="dest"/>: first a direct esentutl
        /// copy, then - if that fails (the file is usually locked by the Diagnostic Policy Service) -
        /// a copy through a VSS snapshot. Returns false with the last esentutl diagnostic in
        /// <paramref name="error"/>.</summary>
        private static bool TryCopySru(string dest, out string error)
        {
            if (RunEsentutl($"/y \"{SruDbPath}\" /d \"{dest}\"", out error) && File.Exists(dest))
                return true;
            string direct = error;

            // Drop any partial copy before the VSS retry.
            try { if (File.Exists(dest)) File.Delete(dest); } catch { /* best effort */ }

            if (RunEsentutl($"/y \"{SruDbPath}\" /vss /d \"{dest}\"", out string vssErr) && File.Exists(dest))
            {
                error = "";
                return true;
            }

            // Prefer the VSS diagnostic when it said something; otherwise the direct-copy one.
            error = vssErr.Length > 0 ? $"{vssErr}  (after VSS retry)" : direct;
            return false;
        }

        /// <summary>
        /// Runs esentutl.exe with the given arguments, hidden. esentutl writes its progress AND its
        /// "Operation terminated with error ..." diagnostics to stdout (not stderr), so both streams
        /// are read - concurrently, so a full pipe buffer can't deadlock the wait - and on failure the
        /// most relevant line is returned via <paramref name="error"/>.
        /// </summary>
        private static bool RunEsentutl(string args, out string error)
        {
            error = "";
            try
            {
                var psi = new ProcessStartInfo("esentutl.exe", args)
                {
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    RedirectStandardInput = true,   // satisfy any repair confirmation prompt
                };
                using var p = Process.Start(psi);
                if (p == null) { error = "esentutl did not start"; return false; }
                try { p.StandardInput.Close(); } catch { }

                // Drain both streams asynchronously while the process runs.
                var outTask = p.StandardOutput.ReadToEndAsync();
                var errTask = p.StandardError.ReadToEndAsync();
                if (!p.WaitForExit(60_000))
                {
                    try { p.Kill(); } catch { }
                    error = "esentutl timed out";
                    return false;
                }
                string combined = outTask.GetAwaiter().GetResult() + "\n" + errTask.GetAwaiter().GetResult();
                if (p.ExitCode != 0) { error = EsentErrorLine(combined); return false; }
                return true;
            }
            catch (Exception ex) { error = ex.Message; return false; }
        }

        /// <summary>Pulls the meaningful diagnostic out of esentutl's output (its "Operation
        /// terminated with error ...", "Usage Error ...", or "system error ..." line); falls back to
        /// a trimmed snippet of the whole output.</summary>
        private static string EsentErrorLine(string output)
        {
            foreach (var raw in output.Split('\n'))
            {
                string line = raw.Trim();
                if (line.StartsWith("Operation terminated with error", StringComparison.OrdinalIgnoreCase) ||
                    line.StartsWith("Usage Error", StringComparison.OrdinalIgnoreCase) ||
                    line.Contains("system error", StringComparison.OrdinalIgnoreCase))
                    return line;
            }
            string trimmed = output.Trim();
            return trimmed.Length > 200 ? trimmed.Substring(0, 200) + "..." : trimmed;
        }

        /// <summary>Reads the network table and id-map from a (clean) ESE copy and aggregates by app.</summary>
        private static List<SruNetUsage> ParseSru(string dbPath, string workDir)
        {
            using var instance = new Instance("b4browse_sru_" + Guid.NewGuid().ToString("N"));
            instance.Parameters.Recovery = false;                 // attach the standalone copy, no logs
            instance.Parameters.CircularLog = true;
            instance.Parameters.NoInformationEvent = true;
            instance.Parameters.CreatePathIfNotExist = true;
            instance.Parameters.TempDirectory = workDir;
            instance.Parameters.SystemDirectory = workDir;
            instance.Parameters.LogFileDirectory = workDir;
            instance.Init();

            using var session = new Session(instance);
            Api.JetAttachDatabase(session, dbPath, AttachDatabaseGrbit.ReadOnly);
            Api.JetOpenDatabase(session, dbPath, null, out JET_DBID dbid, OpenDatabaseGrbit.ReadOnly);

            var tableNames = Api.GetTableNames(session, dbid).ToList();

            // The id-map table has a stable name; match it tolerant of casing.
            string? idMapTable = tableNames.FirstOrDefault(
                t => t.Equals("SruDbIdMapTable", StringComparison.OrdinalIgnoreCase));

            // Find the network-data-usage table by its COLUMNS, not by a hard-coded GUID: SRUM's
            // per-provider table GUIDs differ across Windows builds, but the network table is always
            // the one carrying the per-app byte counters (BytesSent + BytesRecvd). The disk table
            // uses BytesRead/BytesWritten, so there is no ambiguity.
            string? netTable = FindTableWithColumns(session, dbid, tableNames, "BytesSent", "BytesRecvd");

            if (netTable == null || idMapTable == null)
                throw new InvalidOperationException(
                    (netTable == null ? "no SRUM table has BytesSent/BytesRecvd columns. " : "") +
                    (idMapTable == null ? "SruDbIdMapTable not present. " : "") +
                    $"Tables in copy ({tableNames.Count}): {string.Join(", ", tableNames.Take(40))}");

            var idMap = ReadIdMap(session, dbid, idMapTable);

            // Aggregate sent/received and the newest timestamp per AppId.
            var byApp = new Dictionary<int, SruNetUsage>();
            using (var table = new Table(session, dbid, netTable, OpenTableGrbit.ReadOnly))
            {
                var cols = ColumnMap(session, table);
                JET_COLUMNID appCol = cols["AppId"], sentCol = cols["BytesSent"],
                             recvCol = cols["BytesRecvd"], tsCol = cols.TryGetValue("TimeStamp", out var tc) ? tc : default;

                Api.MoveBeforeFirst(session, table);
                while (Api.TryMoveNext(session, table))
                {
                    int appId = (int)RawInt(session, table, appCol);
                    long sent = RawInt(session, table, sentCol);
                    long recv = RawInt(session, table, recvCol);
                    DateTime? ts = tsCol.Equals(default(JET_COLUMNID)) ? null : RawDate(session, table, tsCol);

                    if (!byApp.TryGetValue(appId, out var u))
                    {
                        u = new SruNetUsage();
                        idMap.TryGetValue(appId, out string? path);
                        u.AppPath = string.IsNullOrEmpty(path) ? $"(app id {appId})" : path!;
                        u.AppName = LeafName(u.AppPath);
                        byApp[appId] = u;
                    }
                    u.BytesSent += Math.Max(0, sent);
                    u.BytesRecvd += Math.Max(0, recv);
                    if (ts.HasValue && (!u.LastSeen.HasValue || ts > u.LastSeen)) u.LastSeen = ts;
                }
            }

            foreach (var u in byApp.Values)
            {
                if (u.LastSeen.HasValue) u.LastSeenText = u.LastSeen.Value.ToString("yyyy-MM-dd HH:mm");
                ClassifyDownload(u);
            }
            return byApp.Values.OrderByDescending(u => u.BytesRecvd).ToList();
        }

        /// <summary>SruDbIdMapTable: IdIndex -> decoded app identity (path, or SID for user rows).</summary>
        private static Dictionary<int, string> ReadIdMap(Session session, JET_DBID dbid, string idMapTable)
        {
            var map = new Dictionary<int, string>();
            using var table = new Table(session, dbid, idMapTable, OpenTableGrbit.ReadOnly);
            var cols = ColumnMap(session, table);
            if (!cols.TryGetValue("IdIndex", out var idxCol) || !cols.TryGetValue("IdBlob", out var blobCol))
                return map;
            cols.TryGetValue("IdType", out var typeCol);

            Api.MoveBeforeFirst(session, table);
            while (Api.TryMoveNext(session, table))
            {
                int idx = (int)RawInt(session, table, idxCol);
                int type = typeCol.Equals(default(JET_COLUMNID)) ? -1 : (int)RawInt(session, table, typeCol);
                byte[]? blob = Api.RetrieveColumn(session, table, blobCol);
                map[idx] = DecodeIdBlob(type, blob);
            }
            return map;
        }

        /// <summary>Returns the first non-system table whose columns include every name in
        /// <paramref name="required"/> (case-insensitive), or null if none match. Used to locate the
        /// network-usage table by its byte-counter columns instead of a build-specific GUID.</summary>
        private static string? FindTableWithColumns(
            Session session, JET_DBID dbid, IEnumerable<string> tableNames, params string[] required)
        {
            foreach (var name in tableNames)
            {
                // Skip ESE catalog and SRUM bookkeeping tables (MSys*, SruDbIdMapTable, ...).
                if (name.StartsWith("MSys", StringComparison.OrdinalIgnoreCase) ||
                    name.StartsWith("SruDb", StringComparison.OrdinalIgnoreCase))
                    continue;
                try
                {
                    using var table = new Table(session, dbid, name, OpenTableGrbit.ReadOnly);
                    var cols = ColumnMap(session, table);
                    if (required.All(cols.ContainsKey)) return name;
                }
                catch { /* unreadable table - skip it */ }
            }
            return null;
        }

        /// <summary>App id blobs are UTF-16 strings; user rows (IdType 3) hold a binary SID.</summary>
        private static string DecodeIdBlob(int type, byte[]? blob)
        {
            if (blob == null || blob.Length == 0) return "";
            if (type == 3)
            {
                try { return new SecurityIdentifier(blob, 0).Value; } catch { return "(user)"; }
            }
            return Encoding.Unicode.GetString(blob).TrimEnd('\0').Trim();
        }

        private static string LeafName(string path)
        {
            if (path.Length == 0) return path;
            int slash = path.LastIndexOf('\\');
            string leaf = slash >= 0 && slash < path.Length - 1 ? path.Substring(slash + 1) : path;
            return leaf.Length > 0 ? leaf : path;
        }

        /// <summary>Conservative audit: a networked binary running from a transient folder
        /// (Temp / Downloads) - where installed software does not normally live - is worth a look.</summary>
        private static void ClassifyDownload(SruNetUsage u)
        {
            string p = u.AppPath;
            if (p.Contains(@"\Temp\", StringComparison.OrdinalIgnoreCase) ||
                p.Contains(@"\Downloads\", StringComparison.OrdinalIgnoreCase))
            {
                u.Risk = TabSeverity.Caution;
                u.Note = "network activity from a transient folder (Temp/Downloads) - verify it is expected";
            }
        }

        // ---- ESE column helpers ----------------------------------------- //
        /// <summary>Case-insensitive name -> column id map for a table.</summary>
        private static Dictionary<string, JET_COLUMNID> ColumnMap(Session session, Table table)
        {
            var map = new Dictionary<string, JET_COLUMNID>(StringComparer.OrdinalIgnoreCase);
            foreach (var kv in Api.GetColumnDictionary(session, table)) map[kv.Key] = kv.Value;
            return map;
        }

        /// <summary>Reads an integer column of any width (SRUM mixes 4- and 8-byte counters).</summary>
        private static long RawInt(JET_SESID sesid, JET_TABLEID tableid, JET_COLUMNID col)
        {
            byte[]? b = Api.RetrieveColumn(sesid, tableid, col);
            if (b == null || b.Length == 0) return 0;
            return b.Length switch
            {
                1 => b[0],
                2 => BitConverter.ToInt16(b, 0),
                4 => BitConverter.ToInt32(b, 0),
                8 => BitConverter.ToInt64(b, 0),
                _ => 0,
            };
        }

        /// <summary>Reads a SRUM timestamp (OLE-date or FILETIME) and returns it in local time.</summary>
        private static DateTime? RawDate(JET_SESID sesid, JET_TABLEID tableid, JET_COLUMNID col)
        {
            try
            {
                var d = Api.RetrieveColumnAsDateTime(sesid, tableid, col);
                if (d.HasValue) return DateTime.SpecifyKind(d.Value, DateTimeKind.Utc).ToLocalTime();
            }
            catch { /* not stored as a DateTime column - fall back to raw bytes */ }

            byte[]? b = Api.RetrieveColumn(sesid, tableid, col);
            if (b != null && b.Length == 8)
            {
                double oa = BitConverter.ToDouble(b, 0);
                if (oa > 0)
                {
                    try { return DateTime.SpecifyKind(DateTime.FromOADate(oa), DateTimeKind.Utc).ToLocalTime(); }
                    catch { /* try FILETIME instead */ }
                }
                long ft = BitConverter.ToInt64(b, 0);
                if (ft > 0)
                {
                    try { return DateTime.FromFileTimeUtc(ft).ToLocalTime(); } catch { /* give up */ }
                }
            }
            return null;
        }

        // ---- Byte formatting -------------------------------------------- //
        public static string FormatBytes(long n)
        {
            if (n <= 0) return "0";
            string[] unit = { "B", "KB", "MB", "GB", "TB" };
            double v = n;
            int i = 0;
            while (v >= 1024 && i < unit.Length - 1) { v /= 1024; i++; }
            return i == 0 ? $"{n} B" : $"{v:0.#} {unit[i]}";
        }

        // ---- Header + report producers ---------------------------------- //
        /// <summary>Concise capability line for the Downloads tab header panel.</summary>
        public static CheckGroup DownloadsHeader()
        {
            var group = new CheckGroup("Network Usage (SRUM)");
            if (!Elevation.IsAdmin)
            {
                group.Add(CheckStatus.Info, "Administrator", "Run as Admin to read SRUDB.dat (under System32\\sru).");
                return group;
            }
            if (!File.Exists(SruDbPath))
            {
                group.Add(CheckStatus.Info, "SRUDB.dat", "Not found - SRUM may be disabled.");
                return group;
            }
            group.Add(CheckStatus.Info, "Source", SruDbPath);
            group.Add(CheckStatus.Info, "About",
                "Per-app bytes received (downloaded) and sent (uploaded), summed over SRUM's ~30-60 day window.");
            return group;
        }

        public static CheckGroup CheckDownloads()
        {
            var group = new CheckGroup("App Network Usage (Downloads)");

            if (!Elevation.IsAdmin)
            {
                group.Add(CheckStatus.Info, "Network usage",
                    "Requires administrator (SRUDB.dat is under C:\\Windows\\System32\\sru).");
                return group;
            }

            var items = GetDownloadUsage();
            if (items.Count == 0)
            {
                group.Add(CheckStatus.Info, "Network usage", SruStatus);
                return group;
            }

            group.Add(CheckStatus.Info, "Tracked apps", $"{items.Count} app(s) with recorded network usage.");

            foreach (var u in items.Where(u => u.Risk >= TabSeverity.Caution))
                group.Add(CheckStatus.Warn, u.AppName,
                    $"down {FormatBytes(u.BytesRecvd)} / up {FormatBytes(u.BytesSent)}  -  {u.AppPath}  ({u.Note})");

            int shown = 0;
            foreach (var u in items)   // already ordered by bytes received, descending
            {
                if (u.Risk >= TabSeverity.Caution) continue;   // listed above
                if (++shown > MaxList) break;
                string last = u.LastSeen.HasValue ? $"  -  last {u.LastSeenText}" : "";
                group.Add(CheckStatus.Info, $"{FormatBytes(u.BytesRecvd),10} down  {u.AppName}",
                    $"up {FormatBytes(u.BytesSent)}  -  {u.AppPath}{last}");
            }
            int rest = items.Count(u => u.Risk < TabSeverity.Caution) - shown;
            if (rest > 0) group.Add(CheckStatus.Info, "...", $"{rest} more not shown.");
            return group;
        }
    }
}
