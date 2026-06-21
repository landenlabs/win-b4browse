// Copyright (c) 2026 LanDen Labs - Dennis Lang

using System;
using System.Collections.Concurrent;
using System.IO;
using System.Runtime.InteropServices;
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
        // Win32 constants for service queries
        private const int SC_MANAGER_CONNECT = 0x0001;
        private const int SERVICE_QUERY_STATUS = 0x0004;
        private const int SC_STATUS_PROCESS_INFO = 0;
        private const int SERVICE_ACCEPT_SHUTDOWN = 0x00000004;
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

        /// <summary>
        /// Returns true if the named service accepts the SERVICE_ACCEPT_SHUTDOWN control.
        /// Returns null on error (access denied, service not found, or native failure).
        /// </summary>
        public static async Task<bool?> ServiceAcceptsShutdownAsync(string serviceName)
        {
            if (string.IsNullOrEmpty(serviceName)) return null;
            return await Task.Run<bool?>(() =>
            {
                IntPtr scm = IntPtr.Zero;
                IntPtr svc = IntPtr.Zero;
                try
                {
                    scm = OpenSCManager(null, null, SC_MANAGER_CONNECT);
                    if (scm == IntPtr.Zero) return (bool?)null;
                    svc = OpenService(scm, serviceName, SERVICE_QUERY_STATUS);
                    if (svc == IntPtr.Zero) return (bool?)null;
                    var ssp = new SERVICE_STATUS_PROCESS();
                    int size = Marshal.SizeOf<SERVICE_STATUS_PROCESS>();
                    if (!QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO, ref ssp, size, out int needed))
                        return (bool?)null;
                    bool accepts = (ssp.dwControlsAccepted & SERVICE_ACCEPT_SHUTDOWN) != 0;
                    try { InspectionCompleted?.Invoke(serviceName); } catch { }
                    return (bool?)accepts;
                }
                catch { return (bool?)null; }
                finally
                {
                    try { if (svc != IntPtr.Zero) CloseServiceHandle(svc); } catch { }
                    try { if (scm != IntPtr.Zero) CloseServiceHandle(scm); } catch { }
                }
            }).ConfigureAwait(false);
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

        // --- P/Invoke for service queries ---
        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern IntPtr OpenSCManager(string? machineName, string? databaseName, int dwDesiredAccess);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern IntPtr OpenService(IntPtr hSCManager, string lpServiceName, int dwDesiredAccess);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool CloseServiceHandle(IntPtr hSCObject);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool QueryServiceStatusEx(IntPtr hService, int InfoLevel, ref SERVICE_STATUS_PROCESS lpBuffer, int cbBufSize, out int pcbBytesNeeded);

        [StructLayout(LayoutKind.Sequential)]
        private struct SERVICE_STATUS_PROCESS
        {
            public int dwServiceType;
            public int dwCurrentState;
            public int dwControlsAccepted;
            public int dwWin32ExitCode;
            public int dwServiceSpecificExitCode;
            public int dwCheckPoint;
            public int dwWaitHint;
            public int dwProcessId;
            public int dwServiceFlags;
        }
    }
}
