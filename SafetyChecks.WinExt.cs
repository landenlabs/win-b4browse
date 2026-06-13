// Copyright (c) 2026 LanDen Labs - Dennis Lang

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using Microsoft.Win32;

namespace B4Browse
{
    /// <summary>
    /// File Explorer shell-extension audit (the Win Extn tab). Explorer loads third-party COM
    /// handlers (context menu, icon overlay, property sheet, drag-drop, copy hook) in-process, so a
    /// malicious or unsigned handler runs inside explorer.exe. This enumerates the handler registry
    /// keys, resolves each CLSID to its backing DLL, and flags risky ones (temp/appdata locations,
    /// orphaned DLLs, handlers not on the Shell Extensions "Approved" list; signature on demand).
    /// </summary>
    public static partial class SafetyChecks
    {
        // (registry path, hive, hook type, target). HKCR entries are read in both reg views.
        private static readonly (string Path, RegistryHive Hive, string Type, string Target)[] ShellHookKeys =
        {
            (@"*\shellex\ContextMenuHandlers",                  RegistryHive.ClassesRoot,  "Context menu",  "All files"),
            (@"AllFilesystemObjects\shellex\ContextMenuHandlers", RegistryHive.ClassesRoot, "Context menu", "Files & folders"),
            (@"Directory\shellex\ContextMenuHandlers",           RegistryHive.ClassesRoot, "Context menu",  "Directory"),
            (@"Directory\Background\shellex\ContextMenuHandlers", RegistryHive.ClassesRoot,"Context menu",  "Folder background"),
            (@"Folder\shellex\ContextMenuHandlers",              RegistryHive.ClassesRoot, "Context menu",  "Folder"),
            (@"Drive\shellex\ContextMenuHandlers",               RegistryHive.ClassesRoot, "Context menu",  "Drive"),

            (@"*\shellex\PropertySheetHandlers",                 RegistryHive.ClassesRoot, "Property sheet", "All files"),
            (@"Directory\shellex\PropertySheetHandlers",         RegistryHive.ClassesRoot, "Property sheet", "Directory"),
            (@"Drive\shellex\PropertySheetHandlers",             RegistryHive.ClassesRoot, "Property sheet", "Drive"),

            (@"Directory\shellex\DragDropHandlers",              RegistryHive.ClassesRoot, "Drag-drop",     "Directory"),
            (@"Directory\Background\shellex\DragDropHandlers",   RegistryHive.ClassesRoot, "Drag-drop",     "Folder background"),
            (@"Folder\shellex\DragDropHandlers",                 RegistryHive.ClassesRoot, "Drag-drop",     "Folder"),
            (@"Drive\shellex\DragDropHandlers",                  RegistryHive.ClassesRoot, "Drag-drop",     "Drive"),

            (@"Directory\shellex\CopyHookHandlers",              RegistryHive.ClassesRoot, "Copy hook",     "Directory"),
            (@"*\shellex\CopyHookHandlers",                      RegistryHive.ClassesRoot, "Copy hook",     "All files"),

            (@"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellIconOverlayIdentifiers",
                                                                 RegistryHive.LocalMachine, "Icon overlay", "Global"),
        };

        /// <summary>Inventory of File Explorer shell extensions (one row per CLSID).</summary>
        public static List<ShellExtension> GetShellExtensions()
        {
            var approved = ReadApprovedMap();
            var map = new Dictionary<string, ShellExtension>(StringComparer.OrdinalIgnoreCase);

            foreach (var view in new[] { RegistryView.Registry64, RegistryView.Registry32 })
            {
                foreach (var hook in ShellHookKeys)
                {
                    try
                    {
                        using var baseKey = RegistryKey.OpenBaseKey(hook.Hive, view);
                        using var k = baseKey.OpenSubKey(hook.Path);
                        if (k == null) continue;

                        foreach (var sub in k.GetSubKeyNames())
                        {
                            string clsid = ExtractClsid(k, sub);
                            if (clsid.Length == 0) continue;
                            clsid = clsid.ToUpperInvariant();

                            if (!map.TryGetValue(clsid, out var ext))
                            {
                                ext = ResolveExtension(clsid, approved, view);
                                map[clsid] = ext;
                            }
                            ext.Types = AddCsv(ext.Types, hook.Type);
                            ext.Targets = AddCsv(ext.Targets, hook.Target);
                        }
                    }
                    catch { /* key absent / access denied - skip */ }
                }
            }

            var list = map.Values.ToList();
            foreach (var e in list) Assess(e);
            return list;
        }

        private static string ExtractClsid(RegistryKey parent, string sub)
        {
            try
            {
                using var s = parent.OpenSubKey(sub);
                string def = s?.GetValue("") as string ?? "";
                if (IsClsid(def)) return def;
            }
            catch { /* ignore */ }
            return IsClsid(sub) ? sub : "";
        }

        private static ShellExtension ResolveExtension(string clsid, Dictionary<string, string> approved, RegistryView view)
        {
            var e = new ShellExtension { Clsid = clsid };
            try
            {
                using var cr = RegistryKey.OpenBaseKey(RegistryHive.ClassesRoot, view);
                using var ck = cr.OpenSubKey(@"CLSID\" + clsid);
                string name = ck?.GetValue("") as string ?? "";

                string dll = "";
                using (var ip = ck?.OpenSubKey("InprocServer32"))
                {
                    if (ip != null)
                    {
                        dll = ip.GetValue("") as string ?? "";
                        e.ThreadingModel = ip.GetValue("ThreadingModel") as string ?? "";
                    }
                }
                if (dll.Length == 0)
                {
                    using var ls = ck?.OpenSubKey("LocalServer32");
                    string exe = ls?.GetValue("") as string ?? "";
                    if (exe.Length > 0) { dll = exe; e.ThreadingModel = "(out-of-proc)"; }
                }

                if (dll.Length > 0) dll = Environment.ExpandEnvironmentVariables(CleanPath(dll));
                e.DllPath = dll;

                if (name.Length == 0 && approved.TryGetValue(clsid, out var d)) name = d;
                e.Name = name.Length > 0 ? name : clsid;
                e.Approved = approved.ContainsKey(clsid);

                if (dll.Length > 0 && File.Exists(dll))
                {
                    try
                    {
                        e.Company = FileVersionInfo.GetVersionInfo(dll).CompanyName ?? "";
                        var lw = File.GetLastWriteTime(dll);
                        e.DllModified = lw;
                        e.DaysOld = Math.Max(0, (int)(DateTime.Now - lw).TotalDays);
                    }
                    catch { /* ignore */ }
                }
            }
            catch { /* ignore */ }
            return e;
        }

        private static void Assess(ShellExtension e)
        {
            e.IsBuiltin = IsMicrosoftExt(e);
            var notes = new List<string>();

            if (e.DllPath.Length == 0)
            {
                e.Risk = TabSeverity.Caution;
                e.Note = "no in-process server DLL registered";
                return;
            }
            if (LooksRisky(e.DllPath))
            {
                e.Risk = TabSeverity.Alert;
                notes.Add("DLL loads from a temp/download/appdata location");
            }
            else if (!File.Exists(e.DllPath))
            {
                e.Risk = Sev.Max(e.Risk, TabSeverity.Caution);
                notes.Add("handler DLL is missing (orphaned)");
            }
            else if (!e.Approved && !e.IsBuiltin)
            {
                e.Risk = Sev.Max(e.Risk, TabSeverity.Caution);
                notes.Add("not on the Shell Extensions Approved list");
            }
            else if (!e.IsBuiltin)
            {
                e.Risk = Sev.Max(e.Risk, TabSeverity.Ok);
            }
            e.Note = string.Join("; ", notes);
        }

        private static bool IsMicrosoftExt(ShellExtension e)
        {
            if (e.Company.IndexOf("Microsoft", StringComparison.OrdinalIgnoreCase) >= 0) return true;
            string win = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            return win.Length > 0 && e.DllPath.StartsWith(win, StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>Verifies each distinct handler DLL's signature (on demand) and escalates unsigned
        /// non-Microsoft handlers to Alert. Runs off the UI thread.</summary>
        public static void VerifyShellExtensions(IReadOnlyList<ShellExtension> exts)
        {
            foreach (var grp in exts.Where(e => e.DllPath.Length > 0 && File.Exists(e.DllPath))
                                    .GroupBy(e => e.DllPath, StringComparer.OrdinalIgnoreCase))
            {
                var (status, signer) = VerifyAuthenticode(grp.Key);
                bool ms = signer.IndexOf("Microsoft", StringComparison.OrdinalIgnoreCase) >= 0;
                foreach (var e in grp)
                {
                    e.SignStatus = status;
                    if (status != "Valid" && !(ms || e.IsBuiltin))
                    {
                        e.Risk = Sev.Max(e.Risk, TabSeverity.Alert);
                        e.Note = e.Note.Length > 0 ? $"{e.Note}; signature {status.ToLowerInvariant()}"
                                                   : $"signature {status.ToLowerInvariant()}";
                    }
                }
            }
        }

        private static Dictionary<string, string> ReadApprovedMap()
        {
            var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            try
            {
                using var b = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
                using var k = b.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved");
                if (k != null)
                    foreach (var n in k.GetValueNames())
                        if (n.Length > 0) map[n] = k.GetValue(n) as string ?? "";
            }
            catch { /* ignore */ }
            return map;
        }

        private static bool IsClsid(string s) =>
            s.Length is >= 38 and <= 40 && s.StartsWith("{", StringComparison.Ordinal) && s.EndsWith("}", StringComparison.Ordinal);

        private static string AddCsv(string csv, string val)
        {
            if (csv.Length == 0) return val;
            return csv.Split(", ").Contains(val) ? csv : csv + ", " + val;
        }

        // ----------------------------------------------------------------- //
        // Report producer (headless / email / copy) - metadata only (no signature scan).
        // ----------------------------------------------------------------- //
        public static CheckGroup CheckWinExt()
        {
            var group = new CheckGroup("File Explorer Shell Extensions");

            var exts = GetShellExtensions();
            var thirdParty = exts.Where(e => !e.IsBuiltin).ToList();
            group.Add(CheckStatus.Info, "Inventory",
                $"{exts.Count} handler(s) registered; {thirdParty.Count} third-party.");

            var flagged = exts.Where(e => e.Risk >= TabSeverity.Caution)
                              .OrderByDescending(e => (int)e.Risk).ToList();
            foreach (var e in flagged.Take(MaxList))
                group.Add(e.Risk == TabSeverity.Alert ? CheckStatus.Fail : CheckStatus.Warn, e.Name,
                    $"{e.Types}  [{e.Targets}]  {e.DllPath}" + (e.Note.Length > 0 ? $"   ({e.Note})" : ""));

            if (flagged.Count == 0)
                group.Add(CheckStatus.Pass, "Shell extensions",
                    "No risky shell extensions by location/approval. Use 'Verify signatures' in the tab for signing checks.");
            else if (flagged.Count > MaxList)
                group.Add(CheckStatus.Info, "...", $"{flagged.Count - MaxList} more not shown.");
            return group;
        }
    }
}
