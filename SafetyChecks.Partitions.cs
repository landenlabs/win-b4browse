// Copyright (c) 2026 LanDen Labs - Dennis Lang

using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.IO;
using System.Linq;
using System.Management;
using System.Security.Cryptography;
using System.Text;
using System.Xml.Linq;

namespace B4Browse
{
    /// <summary>
    /// Disk partitions (the Partitions tab). Partition tampering is a real attack surface:
    /// <list type="bullet">
    /// <item>Bootkits (MITRE T1542.003) rewrite the MBR / boot sector or drop files on the EFI System
    /// Partition (Petya, TDL4, Rovnix, FinSpy, ESPecter, BlackLotus) - some also carve a hidden
    /// partition to store their payload.</item>
    /// <item>Ransomware inhibits recovery (T1490): <c>reagentc /disable</c>, deleting / shrinking the
    /// Recovery partition, purging shadow copies (the latter is covered by the Restores tab).</item>
    /// </list>
    /// Windows keeps no "last modified" time for a partition, so three sources are combined, all
    /// readable WITHOUT elevation:
    /// <list type="number">
    /// <item>The live layout from WMI (<c>root\Microsoft\Windows\Storage</c>: MSFT_Disk / MSFT_Partition / MSFT_Volume).</item>
    /// <item>Windows RE registration from <c>%windir%\System32\Recovery\ReAgent.xml</c>.</item>
    /// <item>The <c>Microsoft-Windows-Partition/Diagnostic</c> log: event 1006 records each disk's raw
    /// partition table and MBR every time the disk arrives (boot / plug-in), so hashing them over
    /// time shows when a table changed - including before B4-Browse was installed.</item>
    /// </list>
    /// plus B4-Browse's own run-to-run baseline (<see cref="PartitionBaseline"/>).
    /// </summary>
    public static partial class SafetyChecks
    {
        private const int RecentPartitionDays = 30;   // a change younger than this is flagged
        private const int RemovedShowDays = 90;       // removed partitions stay listed this long

        // ---- Result model ------------------------------------------------ //

        /// <summary>Windows RE registration (ReAgent.xml).</summary>
        public sealed class WinReInfo
        {
            public bool? Enabled;            // null => ReAgent.xml unreadable / absent
            public string Location = "";     // "Disk 0 partition 4" / "" when not resolved
            public string Key = "";          // partition key WinRE is registered on
            public string Detail = "";
        }

        /// <summary>One partition-table transition seen in the Partition/Diagnostic log.</summary>
        public sealed record TableChange(DateTime Before, DateTime At, string What);

        /// <summary>Partition-table history for one disk from event 1006.</summary>
        public sealed class DiskTableHistory
        {
            public string DiskName = "";
            public string Serial = "";
            public bool Fixed;
            public int Events;
            public DateTime First, Last;
            public int PartitionCount;
            public List<TableChange> Changes = new();
        }

        /// <summary>Everything the Partitions tab shows, gathered once and briefly cached so the
        /// grid's summary / header / loader / severity callbacks share a single scan.</summary>
        public sealed class PartitionAudit
        {
            public List<PartitionItem> Items = new();    // live + recently removed rows
            public WinReInfo WinRe = new();
            public PartitionBaseline.State? Baseline;
            public bool BaselineIsNew;                   // no baseline existed before this run
            public List<DiskTableHistory> TableHistory = new();
            public bool TableHistoryRead;                // false => the diagnostic log was unreadable
            public string Error = "";                    // WMI failure text
            public DateTime Taken;
        }

        private static readonly object PartitionGate = new();
        private static PartitionAudit? _partitionCache;

        /// <summary>Runs (or reuses, if younger than <paramref name="maxAgeSeconds"/>) the partition audit.</summary>
        public static PartitionAudit GetPartitionAudit(int maxAgeSeconds = 10)
        {
            lock (PartitionGate)
            {
                if (_partitionCache != null && (DateTime.Now - _partitionCache.Taken).TotalSeconds < maxAgeSeconds)
                    return _partitionCache;
                _partitionCache = BuildPartitionAudit();
                return _partitionCache;
            }
        }

        /// <summary>Rows for the Partitions grid.</summary>
        public static List<PartitionItem> GetPartitions() => GetPartitionAudit().Items;

        /// <summary>Lightweight call for the run-history snapshot: refreshes the baseline and returns
        /// the number of partitions on fixed disks (-1 on failure).</summary>
        public static int UpdatePartitionBaseline()
        {
            try
            {
                var a = GetPartitionAudit(maxAgeSeconds: 0);
                return a.Error.Length > 0 ? -1 : a.Items.Count(p => p.DiskTracked && !p.Removed);
            }
            catch { return -1; }
        }

        private static PartitionAudit BuildPartitionAudit()
        {
            var audit = new PartitionAudit { Taken = DateTime.Now };
            var live = ReadLivePartitions(out var presentDisks, out string error);
            audit.Error = error;

            audit.WinRe = ReadWinRe(live);
            foreach (var p in live) p.IsWinRe = audit.WinRe.Key.Length > 0 && p.Key == audit.WinRe.Key;

            if (error.Length == 0)
            {
                audit.BaselineIsNew = !File.Exists(PartitionBaseline.FilePath);
                audit.Baseline = PartitionBaseline.Update(live, presentDisks, audit.WinRe.Enabled, audit.WinRe.Key);
            }

            AuditPartitions(live, audit.WinRe);

            // Recently removed partitions become rows too.
            if (audit.Baseline != null)
            {
                foreach (var r in audit.Baseline.Removed.Where(r => r.RemovedAt != null &&
                             (DateTime.Now - r.RemovedAt.Value).TotalDays <= RemovedShowDays))
                {
                    var kind = KindOf(r.TypeId);
                    bool recent = (DateTime.Now - r.RemovedAt!.Value).TotalDays <= RecentPartitionDays;
                    live.Add(new PartitionItem
                    {
                        Removed = true, DiskTracked = true, DiskKey = r.DiskKey, DiskName = r.DiskName,
                        DiskNumber = -1, PartitionNumber = r.Number, Key = r.Key,
                        TypeId = r.TypeId, TypeText = r.TypeText, Kind = kind,
                        Offset = r.Offset, Size = r.Size, IsHidden = r.Hidden,
                        FirstSeen = r.FirstSeen, LastChanged = r.RemovedAt, ChangeText = "removed",
                        Risk = !recent ? TabSeverity.Ok
                             : kind is PartitionKind.Recovery or PartitionKind.Efi ? TabSeverity.Alert : TabSeverity.Caution,
                        Note = kind == PartitionKind.Recovery
                            ? "Recovery partition deleted - ransomware removes recovery options (T1490)"
                            : kind == PartitionKind.Efi
                                ? "EFI System Partition deleted - the PC may no longer boot"
                                : "partition deleted since an earlier run",
                    });
                }
            }

            audit.Items = live;
            audit.TableHistory = ReadPartitionTableHistory(out audit.TableHistoryRead);
            return audit;
        }

        // ---- Live layout (WMI) ------------------------------------------- //

        private sealed class DiskRow
        {
            public int Number;
            public string Key = "", Name = "", Serial = "", Bus = "", Style = "";
            public bool Tracked;
        }

        private static List<PartitionItem> ReadLivePartitions(out HashSet<string> presentDisks, out string error)
        {
            presentDisks = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            error = "";
            var list = new List<PartitionItem>();
            try
            {
                var scope = new ManagementScope(@"root\Microsoft\Windows\Storage");
                scope.Connect();

                var disks = new Dictionary<int, DiskRow>();
                using (var s = new ManagementObjectSearcher(scope, new ObjectQuery(
                    "SELECT Number, FriendlyName, SerialNumber, BusType, PartitionStyle, Guid, Signature, Size FROM MSFT_Disk")))
                {
                    foreach (ManagementObject d in s.Get())
                    {
                        using (d)
                        {
                            int bus = ToInt(d["BusType"]);
                            int style = ToInt(d["PartitionStyle"]);
                            string guid = d["Guid"] as string ?? "";
                            long sig = ToLong(d["Signature"]);
                            string serial = (d["SerialNumber"] as string ?? "").Trim();
                            var row = new DiskRow
                            {
                                Number = ToInt(d["Number"]),
                                Name = (d["FriendlyName"] as string ?? "").Trim(),
                                Serial = serial,
                                Bus = BusName(bus),
                                Style = style switch { 1 => "MBR", 2 => "GPT", _ => "RAW" },
                                // USB / SD / MMC / file-backed (VHD) disks come and go legitimately.
                                Tracked = bus is not (7 or 12 or 13 or 15),
                            };
                            row.Key = style == 2 && guid.Length > 0 ? guid.ToLowerInvariant()
                                    : sig != 0 ? $"mbr:{sig:X8}"
                                    : $"sn:{NormSerial(serial)}:{ToLong(d["Size"])}";
                            disks[row.Number] = row;
                            if (row.Tracked) presentDisks.Add(row.Key);
                        }
                    }
                }

                var volumes = new Dictionary<string, (string Fs, string Label)>(StringComparer.OrdinalIgnoreCase);
                try
                {
                    using var s = new ManagementObjectSearcher(scope, new ObjectQuery(
                        "SELECT Path, FileSystem, FileSystemLabel FROM MSFT_Volume"));
                    foreach (ManagementObject v in s.Get())
                        using (v)
                            if (v["Path"] is string path && path.Length > 0)
                                volumes[path] = ((v["FileSystem"] as string ?? "").Trim(),
                                                 (v["FileSystemLabel"] as string ?? "").Trim());
                }
                catch { /* volume details are optional */ }

                using (var s = new ManagementObjectSearcher(scope, new ObjectQuery(
                    "SELECT DiskNumber, PartitionNumber, DriveLetter, Offset, Size, MbrType, GptType, Guid, " +
                    "IsHidden, IsSystem, IsBoot, IsActive, AccessPaths FROM MSFT_Partition")))
                {
                    foreach (ManagementObject m in s.Get())
                    {
                        using (m)
                        {
                            int dn = ToInt(m["DiskNumber"]);
                            disks.TryGetValue(dn, out var disk);
                            var p = new PartitionItem
                            {
                                DiskNumber = dn,
                                DiskKey = disk?.Key ?? $"disk{dn}",
                                DiskName = disk?.Name ?? "",
                                DiskBus = disk?.Bus ?? "",
                                DiskStyle = disk?.Style ?? "",
                                DiskTracked = disk?.Tracked ?? false,
                                PartitionNumber = ToInt(m["PartitionNumber"]),
                                Offset = ToLong(m["Offset"]),
                                Size = ToLong(m["Size"]),
                                IsHidden = m["IsHidden"] is true,
                                IsSystem = m["IsSystem"] is true,
                                IsBoot = m["IsBoot"] is true,
                                IsActive = m["IsActive"] is true,
                            };

                            char letter = ToChar(m["DriveLetter"]);
                            if (char.IsLetter(letter)) p.DriveLetter = letter + ":";

                            string gpt = (m["GptType"] as string ?? "").Trim().ToLowerInvariant();
                            if (gpt.Length > 0)
                            {
                                p.TypeId = gpt;
                                p.Kind = KindOf(gpt);
                                p.TypeText = GptTypeName(gpt);
                                p.KnownType = p.Kind != PartitionKind.Unknown;
                            }
                            else
                            {
                                int mbr = ToInt(m["MbrType"]);
                                p.TypeId = $"MBR 0x{mbr:X2}";
                                p.Kind = KindOf(p.TypeId);
                                p.TypeText = MbrTypeName(mbr);
                            }

                            string pguid = (m["Guid"] as string ?? "").Trim().ToLowerInvariant();
                            p.Key = pguid.Length > 0 && gpt.Length > 0 ? pguid : $"{p.DiskKey}@{p.Offset}";

                            if (m["AccessPaths"] is string[] paths)
                                foreach (var ap in paths)
                                    if (volumes.TryGetValue(ap, out var vol)) { p.FileSystem = vol.Fs; p.Label = vol.Label; break; }

                            list.Add(p);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                error = ex.Message;
                ErrorLog.Add(ErrorCategory.Error, "Could not read the disk partition layout (WMI Storage).", ex.Message);
            }
            return list.OrderBy(p => p.DiskNumber).ThenBy(p => p.Offset).ToList();
        }

        // ---- Windows RE (ReAgent.xml) ------------------------------------ //

        private static WinReInfo ReadWinRe(List<PartitionItem> live)
        {
            var info = new WinReInfo();
            string path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows),
                "System32", "Recovery", "ReAgent.xml");
            try
            {
                if (!File.Exists(path)) { info.Detail = "ReAgent.xml not found - Windows RE state unknown."; return info; }
                var doc = XDocument.Load(path);
                var root = doc.Root;
                string state = root?.Element("InstallState")?.Attribute("state")?.Value ?? "";
                info.Enabled = state == "1";

                var loc = root?.Element("WinreLocation");
                string guid = (loc?.Attribute("guid")?.Value ?? "").ToLowerInvariant();
                long.TryParse(loc?.Attribute("offset")?.Value, out long offset);
                string locPath = loc?.Attribute("path")?.Value ?? "";

                if (info.Enabled == true && offset > 0)
                {
                    // GPT: guid is the disk GUID. MBR: match the offset on any tracked disk.
                    var hit = live.FirstOrDefault(p => p.Offset == offset && p.DiskKey.Equals(guid, StringComparison.OrdinalIgnoreCase))
                           ?? live.FirstOrDefault(p => p.Offset == offset && p.DiskTracked);
                    if (hit != null)
                    {
                        info.Key = hit.Key;
                        info.Location = $"Disk {hit.DiskNumber} partition {hit.PartitionNumber}";
                    }
                }
                info.Detail = info.Enabled == true
                    ? (info.Location.Length > 0
                        ? $"Enabled - {info.Location}{(locPath.Length > 0 ? " (" + locPath + ")" : "")}"
                        : "Enabled, but its registered partition was not found on any disk")
                    : "Disabled - Windows recovery (Startup Repair, Reset this PC) is unavailable";
            }
            catch (Exception ex)
            {
                info.Enabled = null;
                info.Detail = "Could not read ReAgent.xml: " + ex.Message;
            }
            return info;
        }

        // ---- Per-row audits ---------------------------------------------- //

        private static void AuditPartitions(List<PartitionItem> live, WinReInfo winRe)
        {
            foreach (var p in live)
            {
                var notes = new List<string>();
                var risk = TabSeverity.Ok;
                void Flag(TabSeverity s, string note) { risk = Sev.Max(risk, s); notes.Add(note); }

                // Baseline change (size / offset / type / hidden, a new partition, or reappeared).
                if (p.LastChanged is DateTime ch && p.ChangeText.Length > 0)
                {
                    bool recent = (DateTime.Now - ch).TotalDays <= RecentPartitionDays;
                    if (recent)
                        Flag(p.Kind is PartitionKind.Efi or PartitionKind.Recovery ? TabSeverity.Alert : TabSeverity.Caution,
                            $"{p.ChangeText} on {ch:yyyy-MM-dd}");
                    else
                        notes.Add($"{p.ChangeText} on {ch:yyyy-MM-dd}");
                }

                if (p.DiskTracked)
                {
                    if (!p.KnownType)
                        Flag(TabSeverity.Caution, "unrecognised partition type - not a standard Windows / Linux / macOS type");
                    if (p.DriveLetter.Length > 0 && p.Kind is PartitionKind.Efi or PartitionKind.Recovery or PartitionKind.MsReserved)
                        Flag(TabSeverity.Caution, $"{p.TypeText} is mounted as {p.DriveLetter} - boot-sector tools mount it to write to it (e.g. mountvol /s); unmount it if you did not");
                    if (p.Kind == PartitionKind.BasicData && p.IsHidden)
                        Flag(TabSeverity.Caution, "hidden data partition - not visible in File Explorer");
                }

                if (p.Kind == PartitionKind.Recovery && !p.IsWinRe)
                    notes.Add(winRe.Key.Length > 0
                        ? "not the active Windows RE partition (often a leftover from a Windows update, or an OEM factory image)"
                        : "recovery partition");
                if (p.IsWinRe) notes.Add("active Windows RE");

                p.Risk = risk;
                p.Note = string.Join("; ", notes);
            }

            // More than one ESP on a fixed disk is unusual (a second one can host an alternate boot manager).
            foreach (var g in live.Where(p => p.DiskTracked && p.Kind == PartitionKind.Efi).GroupBy(p => p.DiskKey).Where(g => g.Count() > 1))
                foreach (var p in g)
                {
                    p.Risk = Sev.Max(p.Risk, TabSeverity.Caution);
                    p.Note = (p.Note.Length > 0 ? p.Note + "; " : "") + $"{g.Count()} EFI System Partitions on this disk";
                }
        }

        // ---- Partition-table history (event 1006) ------------------------ //

        private const string PartitionLog = "Microsoft-Windows-Partition/Diagnostic";

        private static List<DiskTableHistory> ReadPartitionTableHistory(out bool readOk)
        {
            readOk = false;
            var byDisk = new Dictionary<string, (DiskTableHistory H, string Pt, string Mbr)>(StringComparer.OrdinalIgnoreCase);
            try
            {
                var query = new EventLogQuery(PartitionLog, PathType.LogName, "*[System[EventID=1006]]");
                using var reader = new EventLogReader(query);
                int n = 0;
                for (EventRecord? rec = reader.ReadEvent(); rec != null && n < 3000; rec = reader.ReadEvent(), n++)
                {
                    using (rec)
                    {
                        if (rec.TimeCreated is not DateTime t) continue;
                        var d = EventData(rec.ToXml());
                        if (Get(d, "Capacity") is "" or "0") continue;          // reader with no media inserted
                        string pt = Get(d, "PartitionTable");
                        if (pt.Length == 0) continue;

                        string serial = Get(d, "SerialNumber");
                        if (serial.Equals("NULL", StringComparison.OrdinalIgnoreCase)) serial = "";
                        string model = Get(d, "Model").Trim();
                        string id = $"{model}|{NormSerial(serial)}|{Get(d, "Capacity")}";
                        string ptHash = ShortHash(pt), mbrHash = ShortHash(Get(d, "Mbr"));
                        int.TryParse(Get(d, "BusType"), out int bus);
                        int.TryParse(Get(d, "PartitionCount"), out int count);

                        if (!byDisk.TryGetValue(id, out var e))
                        {
                            e = (new DiskTableHistory
                            {
                                DiskName = model, Serial = serial, Fixed = bus is not (7 or 12 or 13 or 15),
                                First = t, Last = t,
                            }, ptHash, mbrHash);
                        }
                        else
                        {
                            // Events are read oldest-first; a hash change between arrivals is a table rewrite.
                            if (ptHash != e.Pt)
                                e.H.Changes.Add(new TableChange(e.H.Last, t,
                                    mbrHash != e.Mbr ? "partition table changed (MBR rewritten)" : "partition table changed"));
                            else if (mbrHash != e.Mbr)
                                e.H.Changes.Add(new TableChange(e.H.Last, t,
                                    "MBR / boot sector changed while the partition table did not - a bootkit indicator"));
                            e = (e.H, ptHash, mbrHash);
                        }
                        e.H.Events++;
                        e.H.Last = t;
                        e.H.PartitionCount = count;
                        byDisk[id] = e;
                    }
                }
                readOk = true;
            }
            catch (EventLogNotFoundException) { /* log absent on this edition */ }
            catch (Exception ex)
            {
                ErrorLog.Add(ErrorCategory.Error, "Could not read the Partition/Diagnostic event log.", ex.Message);
            }
            return byDisk.Values.Select(v => v.H).OrderByDescending(h => h.Fixed).ThenBy(h => h.DiskName).ToList();
        }

        private static Dictionary<string, string> EventData(string xml)
        {
            var d = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            try
            {
                var doc = XDocument.Parse(xml);
                foreach (var el in doc.Descendants().Where(x => x.Name.LocalName == "Data"))
                {
                    string? name = el.Attribute("Name")?.Value;
                    if (name != null) d[name] = el.Value;
                }
            }
            catch { }
            return d;
        }

        private static string Get(Dictionary<string, string> d, string key) => d.TryGetValue(key, out var v) ? v : "";

        private static string ShortHash(string s) =>
            s.Length == 0 ? "" : Convert.ToHexString(SHA256.HashData(Encoding.ASCII.GetBytes(s)))[..16];

        private static string NormSerial(string s) =>
            new string(s.Where(char.IsLetterOrDigit).Select(char.ToUpperInvariant).ToArray());

        // ---- Header + report --------------------------------------------- //

        /// <summary>Concise summary for the Partitions tab header panel.</summary>
        public static CheckGroup PartitionsHeader()
        {
            var a = GetPartitionAudit();
            var group = new CheckGroup("Disk partitions");
            AddPartitionSummary(group, a, brief: true);
            return group;
        }

        /// <summary>Headless / email / copy report producer.</summary>
        public static CheckGroup CheckPartitions()
        {
            var a = GetPartitionAudit();
            var group = new CheckGroup("Disk Partitions");
            AddPartitionSummary(group, a, brief: false);

            foreach (var p in a.Items)
            {
                var st = p.Risk switch
                {
                    TabSeverity.Alert => CheckStatus.Fail,
                    TabSeverity.Caution => CheckStatus.Warn,
                    _ => CheckStatus.Info,
                };
                string where = p.Removed ? $"{p.DiskName} #{p.PartitionNumber} (removed)" : $"Disk {p.DiskNumber} #{p.PartitionNumber}";
                string letter = p.DriveLetter.Length > 0 ? p.DriveLetter + " " : "";
                string label = p.Label.Length > 0 ? $" \"{p.Label}\"" : "";
                string fs = p.FileSystem.Length > 0 ? $" {p.FileSystem}" : "";
                string flags = p.Flags.Length > 0 ? $"  [{p.Flags}]" : "";
                group.Add(st, where,
                    $"{letter}{p.TypeText}{fs}{label}  {FormatBytes(p.Size)}{flags}" +
                    (p.FirstSeen != null ? $"  first seen {p.FirstSeen:yyyy-MM-dd}" : "") +
                    (p.Note.Length > 0 ? $"  ({p.Note})" : ""));
            }
            return group;
        }

        private static void AddPartitionSummary(CheckGroup group, PartitionAudit a, bool brief)
        {
            if (a.Error.Length > 0)
            {
                group.Add(CheckStatus.Fail, "Partitions", "Could not read the disk layout: " + a.Error);
                return;
            }

            // Windows RE
            var re = a.WinRe;
            group.Add(re.Enabled switch { true when re.Location.Length > 0 => CheckStatus.Pass, true => CheckStatus.Warn, false => CheckStatus.Fail, _ => CheckStatus.Info },
                "Windows RE", re.Enabled == false ? re.Detail + " (reagentc /disable is a ransomware step, T1490)" : re.Detail);
            if (a.Baseline?.WinReChanged is DateTime wc && (DateTime.Now - wc).TotalDays <= RecentPartitionDays)
                group.Add(CheckStatus.Warn, "Windows RE change", $"{a.Baseline.WinReChange} on {wc:yyyy-MM-dd HH:mm}");

            // Baseline
            if (a.BaselineIsNew)
                group.Add(CheckStatus.Info, "Baseline", "First run - partition fingerprints recorded now; later runs are compared against it.");
            else if (a.Baseline != null)
            {
                int tracked = a.Baseline.Partitions.Count;
                int changed = a.Items.Count(p => !p.Removed && p.LastChanged is DateTime c && (DateTime.Now - c).TotalDays <= RecentPartitionDays);
                int removed = a.Items.Count(p => p.Removed);
                var st = changed + removed > 0 ? CheckStatus.Warn : CheckStatus.Pass;
                group.Add(st, "Baseline",
                    $"Since {a.Baseline.Created:yyyy-MM-dd}: {tracked} partition(s) on fixed disks tracked" +
                    (changed + removed == 0 ? " - no changes." :
                        $" - {changed} changed / new and {removed} removed in the last {RecentPartitionDays} days."));
            }

            // Windows' own partition-table history (event 1006).
            if (!a.TableHistoryRead)
                group.Add(CheckStatus.Info, "Table history", "The Partition/Diagnostic event log is not available.");
            foreach (var h in a.TableHistory.Where(h => h.Fixed))
            {
                string name = h.DiskName.Length > 0 ? h.DiskName : "disk";
                if (h.Changes.Count == 0)
                {
                    group.Add(CheckStatus.Pass, name,
                        $"Partition table unchanged across {h.Events} boot(s) / arrival(s) since {h.First:yyyy-MM-dd}.");
                    continue;
                }
                var last = h.Changes[^1];
                bool recent = (DateTime.Now - last.At).TotalDays <= RecentPartitionDays;
                group.Add(recent ? CheckStatus.Warn : CheckStatus.Info, name,
                    $"{h.Changes.Count} change(s) since {h.First:yyyy-MM-dd}; latest: {last.What} between " +
                    $"{last.Before:yyyy-MM-dd HH:mm} and {last.At:yyyy-MM-dd HH:mm}.");
                if (!brief)
                    foreach (var c in h.Changes.Take(h.Changes.Count - 1).Reverse().Take(MaxList))
                        group.Add(CheckStatus.Info, "  earlier", $"{c.What} between {c.Before:yyyy-MM-dd HH:mm} and {c.At:yyyy-MM-dd HH:mm}");
            }

            if (brief)
            {
                int recov = a.Items.Count(p => !p.Removed && p.Kind == PartitionKind.Recovery);
                if (recov > 1)
                    group.Add(CheckStatus.Info, "Recovery partitions",
                        $"{recov} found - usually leftovers from Windows updates that could not grow the old one, or an OEM image.");
            }
        }

        /// <summary>Tab roll-up: the worst row, Windows RE disabled, or a recent table change.</summary>
        public static TabSeverity PartitionSeverity(IReadOnlyList<object> items)
        {
            var a = GetPartitionAudit(maxAgeSeconds: 60);
            if (a.Error.Length > 0) return TabSeverity.None;
            var s = TabSeverity.Ok;
            foreach (var p in items.OfType<PartitionItem>()) s = Sev.Max(s, p.Risk);
            if (a.WinRe.Enabled == false) s = TabSeverity.Alert;
            if (a.WinRe.Enabled == true && a.WinRe.Location.Length == 0) s = Sev.Max(s, TabSeverity.Caution);
            if (a.Baseline?.WinReChanged is DateTime wc && (DateTime.Now - wc).TotalDays <= RecentPartitionDays)
                s = Sev.Max(s, TabSeverity.Caution);
            if (a.TableHistory.Any(h => h.Fixed && h.Changes.Count > 0 &&
                    (DateTime.Now - h.Changes[^1].At).TotalDays <= RecentPartitionDays))
                s = Sev.Max(s, TabSeverity.Caution);
            return s;
        }

        // ---- Type tables ------------------------------------------------- //

        private static PartitionKind KindOf(string typeId) => typeId.ToLowerInvariant() switch
        {
            "c12a7328-f81f-11d2-ba4b-00a0c93ec93b" or "{c12a7328-f81f-11d2-ba4b-00a0c93ec93b}" or "mbr 0xef" => PartitionKind.Efi,
            "e3c9e316-0b5c-4db8-817d-f92df00215ae" or "{e3c9e316-0b5c-4db8-817d-f92df00215ae}" => PartitionKind.MsReserved,
            "ebd0a0a2-b9e5-4433-87c0-68b6b72699c7" or "{ebd0a0a2-b9e5-4433-87c0-68b6b72699c7}"
                or "mbr 0x07" or "mbr 0x06" or "mbr 0x0b" or "mbr 0x0c" or "mbr 0x0e" or "mbr 0x01" or "mbr 0x04" => PartitionKind.BasicData,
            "de94bba4-06d1-4d40-a16a-bfd50179d6ac" or "{de94bba4-06d1-4d40-a16a-bfd50179d6ac}" or "mbr 0x27" or "mbr 0x12" => PartitionKind.Recovery,
            "5808c8aa-7e8f-42e0-85d2-e1e90434cfb3" or "{5808c8aa-7e8f-42e0-85d2-e1e90434cfb3}"
                or "af9b60a0-1431-4f62-bc68-3311714a69ad" or "{af9b60a0-1431-4f62-bc68-3311714a69ad}" or "mbr 0x42" => PartitionKind.Ldm,
            "e75caf8f-f680-4cee-afa3-b001e56efc2d" or "{e75caf8f-f680-4cee-afa3-b001e56efc2d}" => PartitionKind.StorageSpaces,
            "mbr 0x05" or "mbr 0x0f" => PartitionKind.Extended,
            var t when t.StartsWith("mbr ") => PartitionKind.Other,
            var t when GptTypeName(t).Length > 0 => PartitionKind.NonWindows,
            _ => PartitionKind.Unknown,
        };

        private static string GptTypeName(string guid) => guid.Trim('{', '}').ToLowerInvariant() switch
        {
            "c12a7328-f81f-11d2-ba4b-00a0c93ec93b" => "EFI System",
            "e3c9e316-0b5c-4db8-817d-f92df00215ae" => "Microsoft Reserved",
            "ebd0a0a2-b9e5-4433-87c0-68b6b72699c7" => "Basic data",
            "de94bba4-06d1-4d40-a16a-bfd50179d6ac" => "Recovery",
            "5808c8aa-7e8f-42e0-85d2-e1e90434cfb3" => "LDM metadata (dynamic disk)",
            "af9b60a0-1431-4f62-bc68-3311714a69ad" => "LDM data (dynamic disk)",
            "e75caf8f-f680-4cee-afa3-b001e56efc2d" => "Storage Spaces",
            "558d43c5-a1ac-43c0-aac8-d1472b2923d1" => "Storage Replica",
            "db97dba9-0840-4bae-97f0-ffb9a327c7e1" => "Cluster metadata",
            "21686148-6449-6e6f-744e-656564454649" => "BIOS boot",
            "0fc63daf-8483-4772-8e79-3d69d8477de4" => "Linux filesystem",
            "0657fd6d-a4ab-43c4-84e5-0933c84b4f4f" => "Linux swap",
            "e6d6d379-f507-44c2-a23c-238f2a3df928" => "Linux LVM",
            "a19d880f-05fc-4d3b-a006-743f0f84911e" => "Linux RAID",
            "4f68bce3-e8cd-4db1-96e7-fbcaf984b709" => "Linux root (x86-64)",
            "bc13c2ff-59e6-4262-a352-b275fd6f7172" => "Linux /boot (XBOOTLDR)",
            "933ac7e1-2eb4-4f13-b844-0e14e2aef915" => "Linux /home",
            "48465300-0000-11aa-aa11-00306543ecac" => "Apple HFS+",
            "7c3457ef-0000-11aa-aa11-00306543ecac" => "Apple APFS",
            "426f6f74-0000-11aa-aa11-00306543ecac" => "Apple boot",
            "516e7cb4-6ecf-11d6-8ff8-00022d09712b" => "FreeBSD data",
            "83bd6b9d-7f41-11dc-be0b-001560b84f0f" => "FreeBSD boot",
            "024dee41-33e7-11d3-9d69-0008c781f39f" => "MBR partition scheme",
            "d3bfe2de-3daf-11df-ba40-e3a556d89593" => "Intel Rapid Start",
            "f4019732-066e-4e12-8273-346c5641494f" => "Sony boot",
            "bfbfafe7-a34f-448a-9a5b-6213eb736c22" => "Lenovo boot",
            _ => "",
        };

        private static string MbrTypeName(int t) => t switch
        {
            0x01 => "FAT12", 0x04 => "FAT16 (<32 MB)", 0x05 => "Extended", 0x06 => "FAT16",
            0x07 => "Basic data", 0x0B => "FAT32", 0x0C => "FAT32 (LBA)", 0x0E => "FAT16 (LBA)",
            0x0F => "Extended (LBA)", 0x12 => "OEM recovery / diagnostics", 0x17 => "Hidden NTFS",
            0x1B => "Hidden FAT32", 0x1C => "Hidden FAT32 (LBA)", 0x27 => "Recovery (WinRE)",
            0x42 => "LDM (dynamic disk)", 0x82 => "Linux swap", 0x83 => "Linux", 0x8E => "Linux LVM",
            0xA5 => "FreeBSD", 0xAF => "Apple HFS+", 0xEE => "GPT protective", 0xEF => "EFI System",
            _ => $"MBR type 0x{t:X2}",
        };

        private static string BusName(int bus) => bus switch
        {
            1 => "SCSI", 2 => "ATAPI", 3 => "ATA", 4 => "1394", 5 => "SSA", 6 => "Fibre Channel",
            7 => "USB", 8 => "RAID", 9 => "iSCSI", 10 => "SAS", 11 => "SATA", 12 => "SD", 13 => "MMC",
            14 => "Virtual", 15 => "VHD", 16 => "Storage Spaces", 17 => "NVMe", _ => $"bus {bus}",
        };

        private static int ToInt(object? o) { try { return o == null ? 0 : Convert.ToInt32(o); } catch { return 0; } }
        private static long ToLong(object? o) { try { return o == null ? 0 : Convert.ToInt64(o); } catch { return 0; } }
        private static char ToChar(object? o)
        {
            try
            {
                return o switch { null => '\0', char c => c, string s when s.Length > 0 => s[0], _ => (char)Convert.ToUInt16(o) };
            }
            catch { return '\0'; }
        }
    }
}
