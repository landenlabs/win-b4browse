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
                onButtonClick: o => ShowScanMenu(grid, (InstalledProgram)o),
                extraButtons: new (string, Action)[] { ("Apps && features…", OpenAppsSettings) },
                legend: "Recent <7d   Month <30d   Old >30d");
            return grid;
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
                new GridColumn { Header = "Provider", Width = 180, Text = o => ((DeviceDriver)o).Provider },
                new GridColumn { Header = "Device", Fill = 130, Text = o => ((DeviceDriver)o).Device },
            };
            return new SortableGrid("Refresh",
                () => SafetyChecks.GetDevices().Cast<object>().ToList(),
                cols, defaultSortColumn: 2, defaultAscending: false,
                extraButtons: new (string, Action)[] { ("Device Manager", OpenDeviceManager) },
                legend: "Status by local INF change:  Recent <7d   Month <30d   Old >30d");
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
                new GridColumn { Header = "Enabled", Width = 64,
                    Text = o => ((ChromeExtension)o).Enabled ? "Yes" : "No",
                    Sort = o => ((ChromeExtension)o).Enabled ? 1 : 0,
                    Style = o => ((ChromeExtension)o).Enabled ? null : ((Color, Color)?)(YelBack, YelFore) },
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
            return new SortableGrid("Refresh",
                () => SafetyChecks.GetChromeExtensions().Cast<object>().ToList(),
                cols, defaultSortColumn: 2, defaultAscending: true,
                legend: "MV2 = unsupported on Chrome 138+",
                summary: ChromeIntegritySummary);
        }

        // ---- Shared helpers ---------------------------------------------- //
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

        private static string ChromeIntegritySummary()
        {
            var g = SafetyChecks.CheckChromeExe();
            string ver = "", sig = "", sha = "";
            foreach (var r in g.Results)
            {
                if (r.Name == "Version") ver = r.Detail;
                else if (r.Name == "Digital signature") sig = r.Detail;
                else if (r.Name == "SHA-256") sha = r.Detail;
            }
            if (ver.Length == 0 && sha.Length == 0) return "Chrome executable not found";
            string shaShort = sha.Length >= 12 ? sha.Substring(0, 12) + "…" : sha;
            return $"chrome.exe v{ver}  ·  Signature: {sig}  ·  SHA-256 {shaShort}";
        }

        // ---- Installed scan actions -------------------------------------- //
        private static void ShowScanMenu(SortableGrid grid, InstalledProgram prog)
        {
            var menu = new ContextMenuStrip();
            menu.Items.Add("Verify signature (WinVerifyTrust)", null,
                async (_, _) => await ScanVerify(grid, prog));
            menu.Items.Add("Look up on VirusTotal (by SHA-256, no upload)", null,
                async (_, _) => await ScanVirusTotal(grid, prog));
            menu.Show(Cursor.Position);
        }

        private static async Task ScanVerify(SortableGrid grid, InstalledProgram prog)
        {
            string? exe = await Task.Run(() => SafetyChecks.ResolveExeForScan(prog));
            if (exe == null) { Info(grid, $"Could not locate an executable for \"{prog.Name}\"."); return; }

            grid.SetStatus($"Verifying {Path.GetFileName(exe)} …");
            var (status, signer) = await Task.Run(() => SafetyChecks.VerifyAuthenticode(exe));
            grid.SetStatus($"{prog.Name}: {status}");

            string signerShort = signer.Length > 0 ? signer.Split(',')[0] : "(no signer)";
            MessageBox.Show(grid.FindForm(),
                $"{prog.Name}\n{exe}\n\nWinVerifyTrust status: {status}\nSigner: {signerShort}",
                "Signature verification", MessageBoxButtons.OK,
                status == "Valid" ? MessageBoxIcon.Information : MessageBoxIcon.Warning);
        }

        private static async Task ScanVirusTotal(SortableGrid grid, InstalledProgram prog)
        {
            string? exe = await Task.Run(() => SafetyChecks.ResolveExeForScan(prog));
            if (exe == null) { Info(grid, $"Could not locate an executable for \"{prog.Name}\"."); return; }

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
