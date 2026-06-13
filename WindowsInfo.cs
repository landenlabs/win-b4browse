// Copyright (c) 2026 LanDen Labs - Dennis Lang

using System;
using System.Diagnostics;
using Microsoft.Win32;

namespace B4Browse
{
    /// <summary>
    /// Read-only Windows edition / version / install-date facts for the toolbar watermark.
    /// Everything is pulled from <c>HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion</c>, the
    /// same key the Settings "About" page reads. Values are cached after the first read - they do
    /// not change while the app runs. All accessors are exception-safe and return blank/null on
    /// failure so the caller can simply hide the watermark when nothing is available.
    /// </summary>
    public static class WindowsInfo
    {
        private const string CurrentVersionKey = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion";

        private static string? _edition;
        private static string? _version;
        private static DateTime? _installed;
        private static bool _installedRead;
        private static string? _summary;

        /// <summary>
        /// Marketing edition, e.g. "Windows 11 Pro". The registry's ProductName still reads
        /// "Windows 10 ..." on Windows 11 (a long-standing Microsoft quirk), so the "10" is
        /// rewritten to "11" when the build number is 22000 or higher.
        /// </summary>
        public static string Edition
        {
            get
            {
                if (_edition != null) return _edition;
                string name = ReadString("ProductName");
                if (name.Length > 0 && Environment.OSVersion.Version.Build >= 22000)
                    name = name.Replace("Windows 10", "Windows 11");
                return _edition = name;
            }
        }

        /// <summary>
        /// Feature-update version plus build, e.g. "24H2 (build 26100.4061)". Falls back to the
        /// older ReleaseId when DisplayVersion is absent (pre-20H2). Blank if neither is present.
        /// </summary>
        public static string Version
        {
            get
            {
                if (_version != null) return _version;

                string display = ReadString("DisplayVersion");          // e.g. "24H2"
                if (display.Length == 0) display = ReadString("ReleaseId"); // pre-20H2 fallback

                string build = ReadString("CurrentBuild");               // e.g. "26100"
                int ubr = ReadDword("UBR");                              // update build revision
                string buildText = build.Length == 0 ? ""
                    : ubr > 0 ? $"build {build}.{ubr}" : $"build {build}";

                _version = (display, buildText) switch
                {
                    ("", "") => "",
                    ("", _) => buildText,
                    (_, "") => display,
                    _ => $"{display} ({buildText})",
                };
                return _version;
            }
        }

        /// <summary>OS install date, or null if unreadable. Stored as a Unix-seconds DWORD.</summary>
        public static DateTime? Installed
        {
            get
            {
                if (_installedRead) return _installed;
                _installedRead = true;
                int secs = ReadDword("InstallDate");
                if (secs > 0)
                {
                    try { _installed = DateTimeOffset.FromUnixTimeSeconds((uint)secs).LocalDateTime; }
                    catch { _installed = null; }
                }
                return _installed;
            }
        }

        /// <summary>
        /// One-line watermark text: "Windows 11 Pro  ·  24H2 (build 26100.4061)  ·  installed 2025-08-14".
        /// Each piece is omitted if unavailable; returns "" when nothing could be read.
        /// </summary>
        public static string Summary
        {
            get
            {
                if (_summary != null) return _summary;
                var parts = new System.Collections.Generic.List<string>(3);
                if (Edition.Length > 0) parts.Add(Edition);
                if (Version.Length > 0) parts.Add(Version);
                if (Installed is DateTime d) parts.Add($"installed {d:yyyy-MM-dd}");
                return _summary = string.Join("  ·  ", parts);   // " · " separators
            }
        }

        /// <summary>Opens the Windows Settings "About" page (Settings -> System -> About).</summary>
        public static void OpenAbout()
        {
            try { Process.Start(new ProcessStartInfo("ms-settings:about") { UseShellExecute = true }); }
            catch { /* Settings URI unavailable - nothing actionable to do */ }
        }

        private static string ReadString(string value)
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(CurrentVersionKey);
                return key?.GetValue(value)?.ToString() ?? string.Empty;
            }
            catch { return string.Empty; }
        }

        private static int ReadDword(string value)
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(CurrentVersionKey);
                if (key?.GetValue(value) is int i) return i;
            }
            catch { /* fall through */ }
            return 0;
        }
    }
}
