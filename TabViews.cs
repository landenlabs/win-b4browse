using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace BrowseSafe
{
    /// <summary>Factories that configure <see cref="SortableGrid"/> instances for the grid tabs.</summary>
    public static class TabViews
    {
        private static readonly Color RedBack = Color.FromArgb(250, 200, 200);
        private static readonly Color RedFore = Color.FromArgb(150, 0, 0);
        private static readonly Color YelBack = Color.FromArgb(255, 244, 180);
        private static readonly Color YelFore = Color.FromArgb(120, 90, 0);

        // ---- Installed --------------------------------------------------- //
        public static Control BuildInstalled()
        {
            SortableGrid grid = null!;
            var cols = new[]
            {
                new GridColumn { Header = "Status", Width = 80,
                    Text = o => Recency(((InstalledProgram)o).DaysOld).Label,
                    Sort = o => ((InstalledProgram)o).SortDate,
                    Style = o => RecencyStyle(((InstalledProgram)o).DaysOld) },
                new GridColumn { Header = "Scan", Width = 64, Button = true, ButtonText = "Scan" },
                new GridColumn { Header = "Installed", Width = 95,
                    Text = o => ((InstalledProgram)o).InstalledText,
                    Sort = o => ((InstalledProgram)o).SortDate },
                new GridColumn { Header = "Version", Width = 110,
                    Text = o => ((InstalledProgram)o).Version,
                    Sort = o => VersionKey(((InstalledProgram)o).Version) },
                new GridColumn { Header = "Program name", Fill = 130, Text = o => ((InstalledProgram)o).Name },
                new GridColumn { Header = "Description", Fill = 120, Text = o => ((InstalledProgram)o).Description },
            };
            grid = new SortableGrid("Refresh",
                () => SafetyChecks.GetInstalledPrograms().Cast<object>().ToList(),
                cols, defaultSortColumn: 2, defaultAscending: false,
                onButtonClick: o => { var p = (InstalledProgram)o; ShowScanMenu(grid, p.Name, () => SafetyChecks.ResolveExeForScan(p)); },
                extraButtons: new (string, Action)[] { ("Apps && features…", OpenAppsSettings) },
                legend: "Recent <7d   Month <30d   Old >30d",
                severity: items => WorstDays(items, o => (o as InstalledProgram)?.DaysOld));
            return grid;
        }

        // ---- Processes (same structure/behavior as Installed) ------------ //
        public static Control BuildProcesses()
        {
            SortableGrid grid = null!;
            var cols = new[]
            {
                new GridColumn { Header = "Status", Width = 80,
                    Text = o => RecencyLabel(((ProcessItem)o).DaysOld),
                    Sort = o => ((ProcessItem)o).ModifiedSort,
                    Style = o => RecencyStyle(((ProcessItem)o).DaysOld) },
                new GridColumn { Header = "Scan", Width = 64, Button = true, ButtonText = "Scan" },
                new GridColumn { Header = "Modified", Width = 95,
                    Text = o => ((ProcessItem)o).ModifiedText,
                    Sort = o => ((ProcessItem)o).ModifiedSort },
                new GridColumn { Header = "Version", Width = 110,
                    Text = o => ((ProcessItem)o).Version,
                    Sort = o => VersionKey(((ProcessItem)o).Version) },
                new GridColumn { Header = "Process name", Fill = 120,
                    Text = o => { var p = (ProcessItem)o; return $"{p.Name}  ({p.Pid})"; },
                    Sort = o => ((ProcessItem)o).Name },
                new GridColumn { Header = "Path", Fill = 160, Text = o => ((ProcessItem)o).ExePath },
            };
            string win = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            grid = new SortableGrid("Refresh",
                () => SafetyChecks.GetProcesses().Cast<object>().ToList(),
                cols, defaultSortColumn: 2, defaultAscending: false,
                onButtonClick: o => { var p = (ProcessItem)o; ShowScanMenu(grid, p.Name, () => ExistingPath(p.ExePath)); },
                extraButtons: new (string, Action)[] { ("Task Manager", OpenTaskManager) },
                legend: "Off: only unusual (non-Windows) processes with Old status.  Recent <7d  Month <30d  Old >30d",
                severity: items => WorstDays(items, o => (o as ProcessItem)?.DaysOld),
                showAllToggle: ("Show all", o =>
                {
                    var p = (ProcessItem)o;
                    bool unusual = p.ExePath.Length > 0 && !p.ExePath.StartsWith(win, StringComparison.OrdinalIgnoreCase);
                    bool old = p.DaysOld is >= 30;
                    return !(unusual && old);   // when off, show ONLY unusual + Old
                }));
            return grid;
        }

        private static void OpenTaskManager()
        {
            try { Process.Start(new ProcessStartInfo("taskmgr.exe") { UseShellExecute = true }); }
            catch { /* ignore */ }
        }

        // ---- Devices ----------------------------------------------------- //
        public static Control BuildDevices()
        {
            var cols = new[]
            {
                new GridColumn { Header = "Status", Width = 78,
                    Text = o => Recency(((DeviceDriver)o).DaysOld).Label,
                    Sort = o => ((DeviceDriver)o).LocalSort,
                    Style = o => RecencyStyle(((DeviceDriver)o).DaysOld) },
                new GridColumn { Header = "Signed", Width = 60,
                    Text = o => ((DeviceDriver)o).Signed ? "Yes" : "No",
                    Sort = o => ((DeviceDriver)o).Signed ? 1 : 0,
                    Style = o => ((DeviceDriver)o).Signed ? null : ((Color, Color)?)(RedBack, RedFore) },
                new GridColumn { Header = "Local changed", Width = 105,
                    Text = o => ((DeviceDriver)o).LocalChangedText,
                    Sort = o => ((DeviceDriver)o).LocalSort },
                new GridColumn { Header = "Vendor date", Width = 95,
                    Text = o => ((DeviceDriver)o).VendorDateText,
                    Sort = o => ((DeviceDriver)o).VendorDate ?? DateTime.MinValue },
                new GridColumn { Header = "Version", Width = 130,
                    Text = o => ((DeviceDriver)o).Version,
                    Sort = o => VersionKey(((DeviceDriver)o).Version) },
                new GridColumn { Header = "Provider", Width = 160, Text = o => ((DeviceDriver)o).Provider },
                new GridColumn { Header = "Device", Fill = 110, Text = o => ((DeviceDriver)o).Device },
                new GridColumn { Header = "INF file", Fill = 150,
                    Text = o => { var d = (DeviceDriver)o; return d.InfPath.Length > 0 ? d.InfPath : d.InfName; } },
            };
            SortableGrid grid = null!;
            grid = new SortableGrid("Refresh",
                () => SafetyChecks.GetDevices().Cast<object>().ToList(),
                cols, defaultSortColumn: 2, defaultAscending: false,
                extraButtons: new (string, Action)[] { ("Device Manager", OpenDeviceManager) },
                legend: "Status by local INF change:  Recent <7d   Month <30d   Old >30d.  Right-click to open the INF.",
                severity: items =>
                {
                    var s = TabSeverity.None;
                    foreach (var o in items)
                        if (o is DeviceDriver d)
                        {
                            s = Sev.Max(s, Sev.FromDays(d.DaysOld));
                            if (!d.Signed) s = Sev.Max(s, TabSeverity.Caution);
                        }
                    return s;
                },
                onRowContext: o => ShowDeviceMenu(grid, (DeviceDriver)o));
            return grid;
        }

        private static void ShowDeviceMenu(Control owner, DeviceDriver d)
        {
            string infDir = System.IO.Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.Windows), "INF");
            var menu = new ContextMenuStrip();
            var open = new ToolStripMenuItem("Open file location (INF)", null, (_, _) => OpenLocation(owner, d.InfPath, infDir))
            { Enabled = d.InfPath.Length > 0 };
            menu.Items.Add(open);
            menu.Items.Add(new ToolStripSeparator());
            menu.Items.Add("Copy INF path", null, (_, _) => { try { Clipboard.SetText(d.InfPath); } catch { } })
                .Enabled = d.InfPath.Length > 0;
            menu.Show(Cursor.Position);
        }

        // ---- Chrome (executable integrity summary + extensions grid) ----- //
        public static Control BuildChrome()
        {
            var cols = new[]
            {
                new GridColumn { Header = "Status", Width = 96,
                    Text = o => ((ChromeExtension)o).Unsupported ? "Unsupported" : "OK",
                    Sort = o => ((ChromeExtension)o).Unsupported ? 1 : 0,
                    Style = o => ((ChromeExtension)o).Unsupported ? ((Color, Color)?)(RedBack, RedFore) : null },
                new GridColumn { Header = "Modified", Width = 92,
                    Text = o => ((ChromeExtension)o).ModifiedText,
                    Sort = o => ((ChromeExtension)o).ModifiedSort,
                    Style = o => RecencyStyle(((ChromeExtension)o).DaysOld) },
                new GridColumn { Header = "Profile", Width = 110, Text = o => ((ChromeExtension)o).ProfileName },
                new GridColumn { Header = "Extension name", Fill = 130, Text = o => ((ChromeExtension)o).Name },
                new GridColumn { Header = "Version", Width = 90,
                    Text = o => ((ChromeExtension)o).Version,
                    Sort = o => VersionKey(((ChromeExtension)o).Version) },
                new GridColumn { Header = "MV", Width = 44,
                    Text = o => ((ChromeExtension)o).ManifestVersion?.ToString() ?? "?",
                    Sort = o => ((ChromeExtension)o).ManifestVersion ?? 0 },
                new GridColumn { Header = "Description", Fill = 120, Text = o => ((ChromeExtension)o).Description },
            };
            SortableGrid grid = null!;
            grid = new SortableGrid("Refresh",
                () => SafetyChecks.GetChromeExtensions().Where(e => e.Enabled).Cast<object>().ToList(),
                cols, defaultSortColumn: 2, defaultAscending: true,
                legend: "Enabled extensions only.  MV2 = unsupported on Chrome 138+",
                headerInfo: SafetyChecks.CheckChromeExe,
                severity: items =>
                {
                    var s = TabSeverity.None;
                    foreach (var o in items)
                        if (o is ChromeExtension x)
                        {
                            s = Sev.Max(s, Sev.FromDays(x.DaysOld));
                            if (x.Unsupported) s = Sev.Max(s, TabSeverity.Caution);
                        }
                    return s;
                },
                headerButton: ("Scan", () => ShowScanMenu(grid, "chrome.exe", SafetyChecks.ChromeExePath)));
            return grid;
        }

        // ---- Services ---------------------------------------------------- //
        public static Control BuildServices()
        {
            SortableGrid grid = null!;
            var cols = new[]
            {
                new GridColumn { Header = "Status", Width = 78,
                    Text = o => RecencyLabel(((ServiceInfo)o).DaysOld),
                    Sort = o => ((ServiceInfo)o).ModifiedSort,
                    Style = o => RecencyStyle(((ServiceInfo)o).DaysOld) },
                new GridColumn { Header = "Modified", Width = 95,
                    Text = o => ((ServiceInfo)o).ModifiedText,
                    Sort = o => ((ServiceInfo)o).ModifiedSort },
                new GridColumn { Header = "Run mode", Width = 86, Text = o => ((ServiceInfo)o).StartMode },
                new GridColumn { Header = "Service name", Fill = 120,
                    Text = o => { var s = (ServiceInfo)o; return s.DisplayName.Length > 0 ? s.DisplayName : s.Name; } },
                new GridColumn { Header = "Path", Fill = 170,
                    Text = o => { var s = (ServiceInfo)o; return s.ExePath.Length > 0 ? s.ExePath : s.PathRaw; } },
            };
            grid = new SortableGrid("Refresh",
                () => SafetyChecks.GetServices().Cast<object>().ToList(),
                cols, defaultSortColumn: 1, defaultAscending: false,
                legend: "Status by service .exe modify date.  Right-click a row for actions.",
                severity: items => WorstDays(items, o => (o as ServiceInfo)?.DaysOld),
                onRowContext: o => ShowServiceMenu(grid, (ServiceInfo)o),
                showAllToggle: ("Show All", o =>
                {
                    var s = (ServiceInfo)o;
                    string path = s.ExePath.Length > 0 ? s.ExePath : s.PathRaw;
                    bool system32 = path.IndexOf(@"C:\WINDOWS\system32", StringComparison.OrdinalIgnoreCase) >= 0;
                    bool old = s.DaysOld is >= 30;   // "Old" per the recency rules
                    return system32 && old;          // hidden when Show All is off
                }));
            return grid;
        }

        private static void ShowServiceMenu(Control owner, ServiceInfo svc)
        {
            var menu = new ContextMenuStrip();
            menu.Items.Add("Open Services console (services.msc)", null, (_, _) => OpenServicesConsole(owner));

            var folder = new ToolStripMenuItem("Open service folder", null, (_, _) => OpenServiceFolder(owner, svc))
            { Enabled = svc.ExePath.Length > 0 && (File.Exists(svc.ExePath) || Directory.Exists(svc.Dir)) };
            menu.Items.Add(folder);

            menu.Items.Add(new ToolStripSeparator());
            menu.Items.Add("Copy service name", null, (_, _) => { try { Clipboard.SetText(svc.Name); } catch { } });
            menu.Show(Cursor.Position);
        }

        private static void OpenServicesConsole(Control owner)
        {
            // services.msc has no documented way to pre-select a service from the CLI; open the console.
            try { Process.Start(new ProcessStartInfo("services.msc") { UseShellExecute = true }); }
            catch (Exception ex)
            {
                MessageBox.Show(owner.FindForm(), "Could not open Services console: " + ex.Message,
                    "Services", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
        }

        private static void OpenServiceFolder(Control owner, ServiceInfo svc)
        {
            try
            {
                if (File.Exists(svc.ExePath))
                    Process.Start(new ProcessStartInfo("explorer.exe", $"/select,\"{svc.ExePath}\"") { UseShellExecute = true });
                else if (Directory.Exists(svc.Dir))
                    Process.Start(new ProcessStartInfo("explorer.exe", $"\"{svc.Dir}\"") { UseShellExecute = true });
                else
                    MessageBox.Show(owner.FindForm(), "The service's folder could not be located.",
                        "Services", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show(owner.FindForm(), "Could not open the folder: " + ex.Message,
                    "Services", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
        }

        // ---- Startup ----------------------------------------------------- //
        public static Control BuildStartup()
        {
            SortableGrid grid = null!;
            var cols = new[]
            {
                new GridColumn { Header = "Status", Width = 78,
                    Text = o => RecencyLabel(((StartupItem)o).DaysOld),
                    Sort = o => ((StartupItem)o).StatusSort,
                    Style = o => RecencyStyle(((StartupItem)o).DaysOld) },
                new GridColumn { Header = "Scan", Width = 64, Button = true, ButtonText = "Scan" },
                new GridColumn { Header = "Registry added", Width = 110,
                    Text = o => ((StartupItem)o).RegistryAddedText,
                    Sort = o => ((StartupItem)o).RegistryAdded ?? DateTime.MinValue },
                new GridColumn { Header = "Exe modified", Width = 100,
                    Text = o => ((StartupItem)o).ExeModifiedText,
                    Sort = o => ((StartupItem)o).ExeModified ?? DateTime.MinValue },
                new GridColumn { Header = "App name", Fill = 110, Text = o => ((StartupItem)o).Name },
                new GridColumn { Header = "App path", Fill = 180,
                    Text = o => { var s = (StartupItem)o; return s.ExePath.Length > 0 ? s.ExePath : s.Command; } },
            };
            grid = new SortableGrid("Refresh",
                () => SafetyChecks.GetStartup().Cast<object>().ToList(),
                cols, defaultSortColumn: 0, defaultAscending: false,
                onButtonClick: o => { var it = (StartupItem)o; ShowScanMenu(grid, it.Name, () => ExistingPath(it.ExePath)); },
                legend: "Status by newest of added/modified.  Registry date = Run-key last change (shared).",
                severity: items => WorstDays(items, o => (o as StartupItem)?.DaysOld),
                onRowContext: o => ShowStartupMenu(grid, (StartupItem)o));
            return grid;
        }

        private static void ShowStartupMenu(Control owner, StartupItem item)
        {
            var menu = new ContextMenuStrip();
            var loc = new ToolStripMenuItem("Open file location", null, (_, _) => OpenLocation(owner, item.ExePath, item.Dir))
            { Enabled = item.ExePath.Length > 0 || item.Dir.Length > 0 };
            menu.Items.Add(loc);
            menu.Items.Add(new ToolStripSeparator());
            menu.Items.Add("Manage startup apps (Settings)", null, (_, _) => StartShell(owner, "ms-settings:startupapps"));
            menu.Items.Add("Open Task Manager", null, (_, _) => StartShell(owner, "taskmgr.exe"));
            menu.Show(Cursor.Position);
        }

        private static void OpenLocation(Control owner, string exePath, string dir)
        {
            try
            {
                if (exePath.Length > 0 && File.Exists(exePath))
                    Process.Start(new ProcessStartInfo("explorer.exe", $"/select,\"{exePath}\"") { UseShellExecute = true });
                else if (dir.Length > 0 && Directory.Exists(dir))
                    Process.Start(new ProcessStartInfo("explorer.exe", $"\"{dir}\"") { UseShellExecute = true });
                else
                    MessageBox.Show(owner.FindForm(), "The file location could not be determined.",
                        "Startup", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show(owner.FindForm(), "Could not open location: " + ex.Message,
                    "Startup", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
        }

        private static void StartShell(Control owner, string target)
        {
            try { Process.Start(new ProcessStartInfo(target) { UseShellExecute = true }); }
            catch (Exception ex)
            {
                MessageBox.Show(owner.FindForm(), $"Could not open '{target}': {ex.Message}",
                    "Startup", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
        }

        // ---- Shared helpers ---------------------------------------------- //
        private static TabSeverity WorstDays(System.Collections.Generic.IReadOnlyList<object> items, Func<object, int?> days)
        {
            var s = TabSeverity.None;
            foreach (var o in items) s = Sev.Max(s, Sev.FromDays(days(o)));
            return s;
        }

        private static (string Label, int? Days) Recency(int? days) => (RecencyLabel(days), days);

        private static string RecencyLabel(int? days) =>
            days is null ? "—" : days < 7 ? "Recent" : days < 30 ? "Month" : "Old";

        private static (Color Back, Color Fore)? RecencyStyle(int? days)
        {
            if (days is null) return (Color.White, Color.Gray);
            if (days < 7) return (RedBack, RedFore);
            if (days < 30) return (YelBack, YelFore);
            return null; // Old - default
        }

        /// <summary>Stable, comparable key for version strings (zero-padded components).</summary>
        private static IComparable VersionKey(string v)
        {
            if (Version.TryParse(v, out var ver))
                return $"{ver.Major:D7}.{Math.Max(ver.Minor, 0):D7}.{Math.Max(ver.Build, 0):D7}.{Math.Max(ver.Revision, 0):D7}";
            return "Z" + v; // unparseable sorts after numeric versions, consistently as string
        }

        // ---- Scan actions (signature verify / VirusTotal lookup) --------- //
        // resolveExe runs on a background thread and returns the executable to scan, or null.
        private static void ShowScanMenu(SortableGrid grid, string name, Func<string?> resolveExe)
        {
            var menu = new ContextMenuStrip();
            menu.Items.Add("Verify signature (WinVerifyTrust)", null,
                async (_, _) => await ScanVerify(grid, name, resolveExe));
            menu.Items.Add("Look up on VirusTotal (by SHA-256, no upload)", null,
                async (_, _) => await ScanVirusTotal(grid, name, resolveExe));
            menu.Show(Cursor.Position);
        }

        private static async Task ScanVerify(SortableGrid grid, string name, Func<string?> resolveExe)
        {
            string? exe = await Task.Run(resolveExe);
            if (exe == null) { Info(grid, $"Could not locate an executable for \"{name}\"."); return; }

            grid.SetStatus($"Verifying {Path.GetFileName(exe)} …");
            var (status, signer) = await Task.Run(() => SafetyChecks.VerifyAuthenticode(exe));
            grid.SetStatus($"{name}: {status}");

            string signerShort = signer.Length > 0 ? signer.Split(',')[0] : "(no signer)";
            MessageBox.Show(grid.FindForm(),
                $"{name}\n{exe}\n\nWinVerifyTrust status: {status}\nSigner: {signerShort}",
                "Signature verification", MessageBoxButtons.OK,
                status == "Valid" ? MessageBoxIcon.Information : MessageBoxIcon.Warning);
        }

        private static async Task ScanVirusTotal(SortableGrid grid, string name, Func<string?> resolveExe)
        {
            string? exe = await Task.Run(resolveExe);
            if (exe == null) { Info(grid, $"Could not locate an executable for \"{name}\"."); return; }

            grid.SetStatus($"Hashing {Path.GetFileName(exe)} …");
            string? hash = await Task.Run(() => SafetyChecks.Sha256File(exe));
            if (hash == null) { Info(grid, "Could not hash the file."); return; }

            try
            {
                Process.Start(new ProcessStartInfo($"https://www.virustotal.com/gui/file/{hash}")
                { UseShellExecute = true });
                grid.SetStatus($"Opened VirusTotal for {Path.GetFileName(exe)} (SHA-256 {hash[..12]}…).");
            }
            catch (Exception ex) { Info(grid, "Could not open VirusTotal: " + ex.Message); }
        }

        private static string? ExistingPath(string path) => path.Length > 0 && File.Exists(path) ? path : null;

        private static void Info(Control owner, string msg) =>
            MessageBox.Show(owner.FindForm(), msg, "Scan", MessageBoxButtons.OK, MessageBoxIcon.Information);

        private static void OpenAppsSettings()
        {
            try { Process.Start(new ProcessStartInfo("ms-settings:appsfeatures") { UseShellExecute = true }); }
            catch { /* ignore */ }
        }

        private static void OpenDeviceManager()
        {
            try { Process.Start(new ProcessStartInfo("devmgmt.msc") { UseShellExecute = true }); }
            catch { /* ignore */ }
        }
    }
}
