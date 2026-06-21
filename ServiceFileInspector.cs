// Copyright (c) 2026 LanDen Labs - Dennis Lang

using System;
using System.Collections.Concurrent;
using System.IO;
using System.Security.Cryptography;
using System.Threading.Tasks;

namespace B4Browse
{
    /// <summary>
    /// Background file inspector for services: computes SHA256 and a simple signature presence
    /// marker. Results are cached in-memory to avoid repeated expensive work.
    /// </summary>
    public static class ServiceFileInspector
    {
        public static event Action<string>? InspectionCompleted;
        private sealed record InspectResult(string Sha256, string SignatureStatus, DateTime Timestamp);

        private static readonly ConcurrentDictionary<string, InspectResult> _cache = new(StringComparer.OrdinalIgnoreCase);

        public static async Task<(string sha256, string signature)> InspectAsync(string path)
        {
            if (string.IsNullOrEmpty(path) || !File.Exists(path)) return ("", "");

            if (_cache.TryGetValue(path, out var cached) && (DateTime.Now - cached.Timestamp).TotalMinutes < 60)
            {
                return (cached.Sha256, cached.SignatureStatus);
            }

            try
            {
                string sha = await ComputeSha256Async(path).ConfigureAwait(false);
                // Simple signature presence check: look for a PE certificate table (not a full Authenticode validation)
                string sig = FileHasCertificateTable(path) ? "Signed" : "Unsigned";
                var res = new InspectResult(sha, sig, DateTime.Now);
                _cache[path] = res;
                try { InspectionCompleted?.Invoke(path); } catch { }
                return (sha, sig);
            }
            catch
            {
                return ("", "");
            }
        }

        private static bool FileHasCertificateTable(string path)
        {
            try
            {
                using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
                using var br = new BinaryReader(fs);
                // Minimal PE header parse to find Certificate Table entry in Optional Header DataDirectories
                fs.Seek(0, SeekOrigin.Begin);
                if (br.ReadUInt16() != 0x5A4D) return false; // 'MZ'
                fs.Seek(0x3C, SeekOrigin.Begin);
                int pe = br.ReadInt32();
                fs.Seek(pe + 0x18, SeekOrigin.Begin);
                ushort magic = br.ReadUInt16();
                bool isPE32Plus = magic == 0x20b;
                // Skip to DataDirectory: 96 bytes for PE32, 112 for PE32+
                int skip = isPE32Plus ? 112 : 96;
                fs.Seek(pe + 0x18 + skip, SeekOrigin.Begin);
                // Certificate table is the 5th data directory (index 4): VirtualAddress + Size
                uint rva = br.ReadUInt32();
                uint size = br.ReadUInt32();
                return size > 0;
            }
            catch { return false; }
        }

        private static async Task<string> ComputeSha256Async(string path)
        {
            using var sha = SHA256.Create();
            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            var hash = await sha.ComputeHashAsync(fs).ConfigureAwait(false);
            return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
        }
    }
}
