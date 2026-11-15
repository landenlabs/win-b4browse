// Copyright (c) 2026 LanDen Labs - Dennis Lang

using System;
using System.Linq;

namespace B4Browse
{
    /// <summary>One row of the Partitions tab - a disk partition (live), or a tracked partition that
    /// has disappeared since an earlier run (<see cref="Removed"/>).</summary>
    public sealed class PartitionItem
    {
        public int DiskNumber = -1;
        public string DiskKey = "";         // stable disk identity (GPT disk GUID / MBR signature / serial)
        public string DiskName = "";        // friendly model name
        public string DiskBus = "";         // NVMe / SATA / USB / ...
        public bool DiskTracked;            // fixed internal disk -> compared against the saved baseline
        public string DiskStyle = "";       // GPT / MBR / RAW
        public int PartitionNumber;
        public string DriveLetter = "";     // "C:" or ""
        public string TypeText = "";        // friendly type (EFI System / Recovery / Basic data / ...)
        public string TypeId = "";          // raw GPT type GUID, or "MBR 0x07"
        public PartitionKind Kind;
        public bool KnownType = true;       // false => an unrecognised GPT type
        public string FileSystem = "";
        public string Label = "";
        public long Size;
        public long Offset;
        public bool IsHidden, IsSystem, IsBoot, IsActive;
        public bool IsWinRe;                // the partition Windows RE is registered on (ReAgent.xml)

        /// <summary>Stable identity for the baseline: GPT partition GUID, or MBR disk-signature + offset.</summary>
        public string Key = "";

        /// <summary>Baseline history (from %LOCALAPPDATA%\B4Browse\partitions.json).</summary>
        public DateTime? FirstSeen;
        public DateTime? LastChanged;       // last time a tracked attribute (size / offset / type / hidden) changed
        public string ChangeText = "";      // most recent change description
        public bool Removed;                // present in the baseline but not on disk any more

        /// <summary>Per-row audit severity and reason.</summary>
        public TabSeverity Risk;
        public string Note = "";

        public string Flags =>
            string.Join(" ", new[]
            {
                IsSystem ? "System" : "", IsBoot ? "Boot" : "", IsActive ? "Active" : "",
                IsHidden ? "Hidden" : "", IsWinRe ? "WinRE" : "",
            }.Where(s => s.Length > 0));
    }

    /// <summary>Coarse role of a partition, used by the audits.</summary>
    public enum PartitionKind { Other, Efi, MsReserved, BasicData, Recovery, Ldm, StorageSpaces, NonWindows, Extended, Unknown }
}
