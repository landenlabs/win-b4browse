// Copyright (c) 2026 LanDen Labs - Dennis Lang

using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;

namespace B4Browse
{
    /// <summary>
    /// Loads and saves the run-history file (%LOCALAPPDATA%\B4Browse\history.json).
    ///
    /// Rules:
    /// - On save, if the most-recent stored entry is from the same calendar day as the
    ///   new snapshot, the existing entry is replaced (keeps the latest values for that day).
    /// - The file is capped at 100 entries; the oldest are dropped when the limit is exceeded.
    /// - Thread-safe for single-writer use (the background collection task).
    /// </summary>
    public static class HistoryStore
    {
        private static readonly string DataDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "B4Browse");

        public static string FilePath => Path.Combine(DataDir, "history.json");

        private const int MaxEntries = 100;

        private static readonly JsonSerializerOptions JsonOpts = new()
        {
            WriteIndented = true,
            PropertyNameCaseInsensitive = true,
        };

        /// <summary>Loads all stored snapshots in chronological order (oldest first).</summary>
        public static List<HistorySnapshot> Load()
        {
            if (!File.Exists(FilePath)) return new List<HistorySnapshot>();
            try
            {
                string json = File.ReadAllText(FilePath);
                return JsonSerializer.Deserialize<List<HistorySnapshot>>(json, JsonOpts)
                       ?? new List<HistorySnapshot>();
            }
            catch
            {
                return new List<HistorySnapshot>();
            }
        }

        /// <summary>
        /// Saves <paramref name="snap"/> to the history file. Same-day entries are replaced;
        /// the list is trimmed to <see cref="MaxEntries"/> oldest-first.
        /// Returns the updated list (with deltas computed) for immediate UI use.
        /// </summary>
        public static List<HistorySnapshot> Save(HistorySnapshot snap)
        {
            var list = Load();

            // Replace today's entry if one already exists, otherwise append.
            if (list.Count > 0 && list[^1].Timestamp.Date == snap.Timestamp.Date)
                list[^1] = snap;
            else
                list.Add(snap);

            // Trim to the retention limit (keep newest).
            if (list.Count > MaxEntries)
                list.RemoveRange(0, list.Count - MaxEntries);

            try
            {
                Directory.CreateDirectory(DataDir);
                File.WriteAllText(FilePath, JsonSerializer.Serialize(list, JsonOpts));
            }
            catch { /* non-fatal — display still works from in-memory list */ }

            ComputeAllDeltas(list);
            return list;
        }

        /// <summary>Loads snapshots and fills in all delta fields (for display).</summary>
        public static List<HistorySnapshot> LoadWithDeltas()
        {
            var list = Load();
            ComputeAllDeltas(list);
            return list;
        }

        private static void ComputeAllDeltas(List<HistorySnapshot> list)
        {
            for (int i = 1; i < list.Count; i++)
                list[i].ComputeDeltas(list[i - 1]);
        }
    }
}
