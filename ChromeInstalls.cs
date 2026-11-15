// Copyright (c) 2026 LanDen Labs - Dennis Lang

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Microsoft.Win32;

namespace B4Browse
{
    /// <summary>
    /// Locates chrome.exe. Detects the standard per-channel installs (Stable / Beta / Dev /
    /// Canary / Chromium, machine-wide and per-user) and honours a user-chosen override, persisted
    /// to <c>%LOCALAPPDATA%\B4Browse\chrome-path.txt</c>, for machines with several installs.
    /// <see cref="Resolve"/> is the single answer used by the Chrome tab (path / version / hash /
    /// signature), the Scan menu and the email launcher.
    /// </summary>
    public static class ChromeInstalls
    {
        /// <summary>One detected chrome.exe.</summary>
        public sealed record Install(string Label, string Path);

        private static readonly object _gate = new();
        private static string? _override;
        private static bool _loaded;

        private static string FilePath => System.IO.Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "B4Browse", "chrome-path.txt");

        /// <summary>The user-chosen chrome.exe, or null for auto-detect. Setting persists it
        /// (null/empty clears the override).</summary>
        public static string? Override
        {
            get
            {
                lock (_gate)
                {
                    if (!_loaded)
                    {
                        _loaded = true;
                        try
                        {
                            if (File.Exists(FilePath))
                            {
                                var p = File.ReadAllText(FilePath).Trim();
                                _override = p.Length > 0 ? p : null;
                            }
                        }
                        catch { _override = null; }
                    }
                    return _override;
                }
            }
            set
            {
                lock (_gate)
                {
                    _loaded = true;
                    _override = string.IsNullOrWhiteSpace(value) ? null : value.Trim();
                    try
                    {
                        if (_override == null)
                        {
                            if (File.Exists(FilePath)) File.Delete(FilePath);
                        }
                        else
                        {
                            Directory.CreateDirectory(System.IO.Path.GetDirectoryName(FilePath)!);
                            File.WriteAllText(FilePath, _override);
                        }
                    }
                    catch (Exception ex) { CrashLog.Report("Saving the Chrome path failed", ex); }
                }
            }
        }

        /// <summary>True when an override is set but the file no longer exists (resolution then
        /// falls back to auto-detect).</summary>
        public static bool OverrideMissing => Override is { } p && !File.Exists(p);

        /// <summary>The chrome.exe to inspect: the override when set and present, else the first
        /// detected install (Stable preferred), else null.</summary>
        public static string? Resolve()
        {
            var o = Override;
            if (o != null && File.Exists(o)) return o;
            return Detect().FirstOrDefault()?.Path;
        }

        /// <summary>Every chrome.exe found in the standard locations (plus the App Paths registry
        /// entry), de-duplicated, Stable first.</summary>
        public static IReadOnlyList<Install> Detect()
        {
            string pf   = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
            string pf86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
            string local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

            var candidates = new List<Install>();
            void Channel(string label, string folder)
            {
                foreach (var (root, scope) in new[] { (pf, "machine"), (pf86, "machine x86"), (local, "user") })
                    if (!string.IsNullOrEmpty(root))
                        candidates.Add(new Install($"{label} ({scope})",
                            System.IO.Path.Combine(root, folder, "Application", "chrome.exe")));
            }
            Channel("Chrome",        @"Google\Chrome");
            Channel("Chrome Beta",   @"Google\Chrome Beta");
            Channel("Chrome Dev",    @"Google\Chrome Dev");
            Channel("Chrome Canary", @"Google\Chrome SxS");
            Channel("Chromium",      "Chromium");

            foreach (var hive in new[] { Registry.LocalMachine, Registry.CurrentUser })
            {
                try
                {
                    using var k = hive.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\chrome.exe");
                    if (k?.GetValue(null) is string p && p.Length > 0)
                        candidates.Add(new Install("Registered (App Paths)", p.Trim('"')));
                }
                catch { }
            }

            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var found = new List<Install>();
            foreach (var c in candidates)
            {
                try
                {
                    if (!File.Exists(c.Path)) continue;
                    if (seen.Add(System.IO.Path.GetFullPath(c.Path))) found.Add(c);
                }
                catch { }
            }
            return found;
        }
    }
}
