// Copyright (c) 2026 LanDen Labs - Dennis Lang

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace B4Browse
{
    /// <summary>
    /// Run-to-run partition baseline (%LOCALAPPDATA%\B4Browse\partitions.json). Windows keeps no
    /// "last modified" time for a partition, so B4-Browse fingerprints every partition on the fixed
    /// internal disks each run (identity + type + offset + size + hidden flag) together with the
    /// Windows RE state, and records when each one was first seen, last changed, or disappeared.
    ///
    /// Only fixed disks are tracked - USB / SD / virtual disks come and go legitimately. A partition
    /// is only reported as removed when its disk is still present (an absent disk is offline, not
    /// tampered with). Thread-safe: the background history snapshot and the Partitions tab can
    /// both call <see cref="Update"/>; the update is idempotent for an unchanged layout.
    /// </summary>
    public static class PartitionBaseline
    {
        public sealed class Record
        {
            [JsonPropertyName("key")]     public string Key { get; set; } = "";
            [JsonPropertyName("disk")]    public string DiskKey { get; set; } = "";
            [JsonPropertyName("diskName")] public string DiskName { get; set; } = "";
            [JsonPropertyName("num")]     public int Number { get; set; }
            [JsonPropertyName("type")]    public string TypeId { get; set; } = "";
            [JsonPropertyName("typeName")] public string TypeText { get; set; } = "";
            [JsonPropertyName("offset")]  public long Offset { get; set; }
            [JsonPropertyName("size")]    public long Size { get; set; }
            [JsonPropertyName("hidden")]  public bool Hidden { get; set; }
            [JsonPropertyName("first")]   public DateTime FirstSeen { get; set; }
            [JsonPropertyName("last")]    public DateTime LastSeen { get; set; }
            [JsonPropertyName("changed")] public DateTime? LastChanged { get; set; }
            [JsonPropertyName("change")]  public string Change { get; set; } = "";
            [JsonPropertyName("removed")] public DateTime? RemovedAt { get; set; }
        }

        public sealed class State
        {
            [JsonPropertyName("created")]  public DateTime Created { get; set; }
            [JsonPropertyName("disks")]    public List<string> Disks { get; set; } = new();
            [JsonPropertyName("parts")]    public List<Record> Partitions { get; set; } = new();
            [JsonPropertyName("removedParts")] public List<Record> Removed { get; set; } = new();
            [JsonPropertyName("winre")]    public bool? WinReEnabled { get; set; }
            [JsonPropertyName("winreKey")] public string WinReKey { get; set; } = "";
            [JsonPropertyName("winreChanged")] public DateTime? WinReChanged { get; set; }
            [JsonPropertyName("winreChange")]  public string WinReChange { get; set; } = "";
        }

        private const int MaxRemoved = 50;
        private static readonly object Gate = new();

        public static string FilePath => Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "B4Browse", "partitions.json");

        private static readonly JsonSerializerOptions JsonOpts = new()
        {
            WriteIndented = true,
            PropertyNameCaseInsensitive = true,
        };

        /// <summary>Loads the saved baseline, or null when none exists / it is unreadable.</summary>
        public static State? Load()
        {
            try
            {
                if (!File.Exists(FilePath)) return null;
                return JsonSerializer.Deserialize<State>(File.ReadAllText(FilePath), JsonOpts);
            }
            catch { return null; }
        }

        /// <summary>
        /// Merges the live layout into the baseline, saves it, and annotates the live items with
        /// their first-seen / last-changed history. Returns the updated state (whose
        /// <see cref="State.Removed"/> list holds partitions that disappeared from a present disk).
        /// </summary>
        /// <param name="live">Every live partition (untracked disks are passed through untouched).</param>
        /// <param name="presentDisks">Keys of the tracked disks currently attached.</param>
        /// <param name="winReEnabled">Windows RE state, or null when unknown.</param>
        /// <param name="winReKey">Partition key Windows RE is registered on ("" if none / unknown).</param>
        public static State Update(List<PartitionItem> live, ICollection<string> presentDisks,
            bool? winReEnabled, string winReKey)
        {
            lock (Gate)
            {
                DateTime now = DateTime.Now;
                var state = Load();
                bool firstRun = state == null;
                state ??= new State { Created = now };

                var known = state.Partitions.ToDictionary(r => r.Key, StringComparer.OrdinalIgnoreCase);
                var knownDisks = new HashSet<string>(state.Disks, StringComparer.OrdinalIgnoreCase);
                var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

                foreach (var p in live.Where(p => p.DiskTracked && p.Key.Length > 0))
                {
                    seen.Add(p.Key);
                    if (known.TryGetValue(p.Key, out var r))
                    {
                        var diffs = new List<string>();
                        if (!r.TypeId.Equals(p.TypeId, StringComparison.OrdinalIgnoreCase))
                            diffs.Add($"type {Name(r.TypeText, r.TypeId)} -> {Name(p.TypeText, p.TypeId)}");
                        if (r.Offset != p.Offset)
                            diffs.Add($"moved {Pair(r.Offset, p.Offset)}");
                        if (r.Size != p.Size)
                            diffs.Add($"resized {Pair(r.Size, p.Size)}");
                        if (r.Hidden != p.IsHidden)
                            diffs.Add(p.IsHidden ? "became hidden" : "became visible");

                        if (diffs.Count > 0)
                        {
                            r.LastChanged = now;
                            r.Change = string.Join(", ", diffs);
                        }
                        Copy(p, r);
                        r.LastSeen = now;
                    }
                    else
                    {
                        // New to the baseline. It may be a partition that came back after removal.
                        var back = state.Removed.FirstOrDefault(x => x.Key.Equals(p.Key, StringComparison.OrdinalIgnoreCase));
                        r = new Record { FirstSeen = back?.FirstSeen ?? now, LastSeen = now };
                        if (back != null)
                        {
                            state.Removed.Remove(back);
                            r.LastChanged = now;
                            r.Change = $"reappeared (removed {back.RemovedAt:yyyy-MM-dd})";
                        }
                        else if (!firstRun && knownDisks.Contains(p.DiskKey))
                        {
                            // A new partition on a disk we already knew - created since the last run.
                            r.LastChanged = now;
                            r.Change = "new partition";
                        }
                        Copy(p, r);
                        state.Partitions.Add(r);
                        known[p.Key] = r;
                    }
                    p.FirstSeen = r.FirstSeen;
                    p.LastChanged = r.LastChanged;
                    p.ChangeText = r.Change;
                }

                // Partitions that vanished from a disk that is still attached.
                foreach (var r in state.Partitions.ToList())
                {
                    if (seen.Contains(r.Key) || !presentDisks.Contains(r.DiskKey)) continue;
                    state.Partitions.Remove(r);
                    r.RemovedAt = now;
                    state.Removed.Add(r);
                }
                if (state.Removed.Count > MaxRemoved)
                    state.Removed.RemoveRange(0, state.Removed.Count - MaxRemoved);

                foreach (var d in presentDisks) if (knownDisks.Add(d)) state.Disks.Add(d);

                // Windows RE state transitions (enabled <-> disabled, or moved partition).
                if (winReEnabled != null)
                {
                    if (state.WinReEnabled != null && state.WinReEnabled != winReEnabled)
                    {
                        state.WinReChanged = now;
                        state.WinReChange = winReEnabled.Value ? "Windows RE was re-enabled" : "Windows RE was disabled";
                    }
                    else if (state.WinReEnabled == true && winReEnabled == true && state.WinReKey.Length > 0 &&
                             winReKey.Length > 0 && !state.WinReKey.Equals(winReKey, StringComparison.OrdinalIgnoreCase))
                    {
                        state.WinReChanged = now;
                        state.WinReChange = "Windows RE moved to a different partition";
                    }
                    state.WinReEnabled = winReEnabled;
                    state.WinReKey = winReKey;
                }

                Save(state);
                return state;
            }
        }

        private static void Copy(PartitionItem p, Record r)
        {
            r.Key = p.Key;
            r.DiskKey = p.DiskKey;
            r.DiskName = p.DiskName;
            r.Number = p.PartitionNumber;
            r.TypeId = p.TypeId;
            r.TypeText = p.TypeText;
            r.Offset = p.Offset;
            r.Size = p.Size;
            r.Hidden = p.IsHidden;
        }

        private static string Name(string text, string id) => text.Length > 0 ? text : id;

        /// <summary>"old -> new" in friendly units, falling back to exact bytes when the friendly
        /// forms round to the same text (a small move / resize).</summary>
        private static string Pair(long a, long b)
        {
            string fa = SafetyChecks.FormatBytes(a), fb = SafetyChecks.FormatBytes(b);
            return fa != fb ? $"{fa} -> {fb}" : $"{a:N0} -> {b:N0} bytes";
        }

        private static void Save(State state)
        {
            try
            {
                Directory.CreateDirectory(Path.GetDirectoryName(FilePath)!);
                File.WriteAllText(FilePath, JsonSerializer.Serialize(state, JsonOpts));
            }
            catch (Exception ex)
            {
                ErrorLog.Add(ErrorCategory.Error, "Could not save the partition baseline.", ex.Message);
            }
        }
    }
}
