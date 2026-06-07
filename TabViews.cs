// Copyright (c) 2026 LanDen Labs - Dennis Lang

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Management;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using System.Web;
using System.Windows.Forms;
using System.Xml.Linq;

namespace BrowseSafe
{
    /// <summary>Factories that configure <see cref="SortableGrid"/> instances for the grid tabs.</summary>
    public static class TabViews
    {
        private static readonly Color RedBack = Color.FromArgb(250, 200, 200);
        private static readonly Color RedFore = Color.FromArgb(150, 0, 0);
        private static readonly Color YelBack = Color.FromArgb(255, 244, 180);
        private static readonly Color YelFore = Color.FromArgb(120, 90, 0);
        private static readonly Color GrnBack = Color.FromArgb(208, 240, 208);
        private static readonly Color GrnFore = Color.FromArgb(0, 110, 0);
        private static readonly Color DisBack = Color.FromArgb(235, 235, 235);
        private static readonly Color DisFore = Color.FromArgb(140, 140, 140);

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
                new GridColumn { Header = "Update", Width = 100,
                    Text = o => ((InstalledProgram)o).AvailableVersion,
                    Sort = o => VersionKey(((InstalledProgram)o).AvailableVersion),
                    Style = o => ((InstalledProgram)o).HasUpdate ? ((Color, Color)?)(YelBack, YelFore) : null },
                new GridColumn { Header = "Source", Width = 80, Text = o => ((InstalledProgram)o).Source },
                new GridColumn { Header = "Program name", Fill = 130, Text = o => ((InstalledProgram)o).Name },
                new GridColumn { Header = "Description", Fill = 120, Text = o => ((InstalledProgram)o).Description },
                new GridColumn { Header = "Path", Width = 120, Text = o => ((InstalledProgram)o).ExePath??"" },
            };
            grid = new SortableGrid("Refresh",
                () => SafetyChecks.GetInstalledPrograms().Cast<object>().ToList(),
                cols, defaultSortColumn: 2, defaultAscending: false,
                onButtonClick: o => { var p = (InstalledProgram)o; ShowScanMenu(grid, p.Name, () => SafetyChecks.ResolveExeForScan(p)); },
                extraButtons: new (string, Action)[] { ("Apps && features…", OpenAppsSettings) },
                help: TabHelp.Installed,
                onRowContext: o => ShowInstalledMenu(grid, (InstalledProgram)o),
                severity: items =>
                {
                    var s = WorstDays(items, o => (o as InstalledProgram)?.DaysOld);
                    if (items.Any(o => o is InstalledProgram p && p.HasUpdate)) s = Sev.Max(s, TabSeverity.Caution);
                    return s;
                });
            return grid;
        }

        // ---- Firewall: profile posture + scrollable, audited rule list -- //
        public static Control BuildFirewall()
        {
            SortableGrid grid = null!;
            var cols = new[]
            {
                new GridColumn { Header = "Status", Width = 70,
                    Text = o => FirewallStatusLabel((FirewallRule)o),
                    Sort = o => (int)((FirewallRule)o).Risk,
                    Style = o => FirewallStyle((FirewallRule)o) },
                new GridColumn { Header = "Dir", Width = 46,
                    Text = o => ((FirewallRule)o).Direction,
                    FilterKind = ColumnFilterKind.Dropdown },
                new GridColumn { Header = "Action", Width = 58,
                    Text = o => ((FirewallRule)o).Action,
                    FilterKind = ColumnFilterKind.Dropdown },
                new GridColumn { Header = "Active", Width = 52,
                    Text = o => ((FirewallRule)o).Active ? "Yes" : "No",
                    Sort = o => ((FirewallRule)o).Active ? 1 : 0 },
                new GridColumn { Header = "Proto", Width = 58, Text = o => ((FirewallRule)o).Protocol },
                new GridColumn { Header = "L.Port", Width = 64, Text = o => ((FirewallRule)o).LocalPort },
                new GridColumn { Header = "Remote", Width = 104, Text = o => ((FirewallRule)o).RemoteAddress },
                new GridColumn { Header = "Profile", Width = 86,
                    Text = o => ((FirewallRule)o).Profile,
                    FilterKind = ColumnFilterKind.Dropdown },
                new GridColumn { Header = "Name", Fill = 150, Text = o => ((FirewallRule)o).Name,
                    FilterKind = ColumnFilterKind.Regex },
                new GridColumn { Header = "Program", Fill = 200, Text = o => ((FirewallRule)o).AppPath,
                    FilterKind = ColumnFilterKind.Regex },
            };

            grid = new SortableGrid("Refresh",
                () => SafetyChecks.GetFirewallRules().Cast<object>().ToList(),
                cols, defaultSortColumn: 0, defaultAscending: false,   // flagged rules float to the top
                extraButtons: new (string, Action)[] { ("Manage Firewall", () => StartShell(grid, "wf.msc")) },
                help: TabHelp.Firewall,
                headerInfo: SafetyChecks.FirewallRulesHeader,
                headerHeight: 128,
                severity: items =>
                {
                    var rules = items.OfType<FirewallRule>().ToList();
                    var worst = TabSeverity.None;
                    int alert = 0, review = 0;
                    foreach (var r in rules)
                    {
                        worst = Sev.Max(worst, r.Risk);
                        if (r.Risk == TabSeverity.Alert) alert++;
                        else if (r.Risk == TabSeverity.Caution) review++;
                    }
                    string flagged = alert + review == 0
                        ? "no suspicious rules"
                        : $"{alert} alert, {review} review";
                    grid.SetStatus($"{rules.Count} rule(s)  -  {flagged}");
                    return worst;
                },
                onRowContext: o => ShowFirewallMenu(grid, (FirewallRule)o),
                showAllToggle: ("All",
                    "Off: hide inactive rules.  On: show every rule, active or not.",
                    o => !((FirewallRule)o).Active));   // when off, hide rules that are not active
            return grid;
        }

        private static string FirewallStatusLabel(FirewallRule r) => r.Risk switch
        {
            TabSeverity.Alert => "Alert",
            TabSeverity.Caution => "Review",
            _ => "OK",
        };

        private static (Color Back, Color Fore)? FirewallStyle(FirewallRule r) => r.Risk switch
        {
            TabSeverity.Alert => (RedBack, RedFore),
            TabSeverity.Caution => (YelBack, YelFore),
            _ => null,
        };

        private static void ShowFirewallMenu(SortableGrid grid, FirewallRule r)
        {
            bool hasApp = r.AppPath.Length > 0 && r.AppPath.IndexOf('\\') >= 0;
            string expanded = hasApp ? Environment.ExpandEnvironmentVariables(r.AppPath) : "";

            var menu = new ContextMenuStrip();
            menu.Items.Add("Copy rule name", null, (_, _) => { try { Clipboard.SetText(r.Name); } catch { } });
            menu.Items.Add("Copy program path", null, (_, _) => { try { Clipboard.SetText(r.AppPath); } catch { } })
                .Enabled = hasApp;
            menu.Items.Add("Open file location", null,
                (_, _) => OpenLocation(grid, expanded, Path.GetDirectoryName(expanded) ?? ""))
                .Enabled = hasApp && File.Exists(expanded);
            if (r.Note.Length > 0)
                menu.Items.Add("Copy audit note", null, (_, _) => { try { Clipboard.SetText(r.Note); } catch { } });
            menu.Items.Add(new ToolStripSeparator());
            menu.Items.Add("Search web for program", null, (_, _) =>
            {
                string term = hasApp ? Path.GetFileName(expanded) : r.Name;
                string q = HttpUtility.UrlEncode(term + " firewall rule");
                OpenBrowser($"https://www.google.com/search?q={q}");
            });
            menu.Items.Add(new ToolStripSeparator());
            menu.Items.Add("Manage Firewall (wf.msc)", null, (_, _) => StartShell(grid, "wf.msc"));
            menu.Show(Cursor.Position);
        }

        // ---- Patches: recent Windows patches --------------------------- //
        public static Control BuildPatches()
        {
            var cols = new[]
            {
                new GridColumn { Header = "Status", Width = 80,
                    Text = o => Recency(((WindowsPatch)o).DaysOld).Label,
                    Sort = o => ((WindowsPatch)o).InstalledOn,
                    Style = o => RecencyStyle(((WindowsPatch)o).DaysOld) },
                new GridColumn { Header = "Installed", Width = 120, Text = o => ((WindowsPatch)o).InstalledOn.ToString("yyyy-MM-dd"), Sort = o => ((WindowsPatch)o).InstalledOn },

                new GridColumn { Header = "HotFix ID", Width = 110, Text = o => ((WindowsPatch)o).HotFixID, Sort = o => ((WindowsPatch)o).InstalledOn },
                new GridColumn { Header = "Version", Width = 110, Text = o => ((WindowsPatch)o).Version, Sort = o => ((WindowsPatch)o).Version },
                new GridColumn { Header = "DocLink", Width = 110, Link = true, Text = o => ((WindowsPatch)o).DocLink, Sort = o => ((WindowsPatch)o).DocLink },

                new GridColumn { Header = "Description", Fill = 180, Text = o => ((WindowsPatch)o).Description },
                           };

            SortableGrid grid = null!;
            grid = new SortableGrid("Refresh",
                () => GetPatches().Cast<object>().ToList(),
                cols, defaultSortColumn: 2, defaultAscending: false,
                help: TabHelp.Patches,
                severity: items => TabSeverity.None);
            return grid;
        }

        private static System.Collections.Generic.List<WindowsPatch> GetPatches()
        {
            var list = new System.Collections.Generic.List<WindowsPatch>();
            try
            {
                var searcher = new ManagementObjectSearcher("SELECT HotFixID, Description, InstalledOn, Caption, ServicePackInEffect FROM Win32_QuickFixEngineering");
                foreach (ManagementObject obj in searcher.Get())
                {
                    string id = obj["HotFixID"]?.ToString() ?? "Unknown";
                    string desc = obj["Description"]?.ToString() ?? "";
                    string raw = obj["InstalledOn"]?.ToString();

                    string doc = obj["Caption"]?.ToString();
                    string ver = obj["ServicePackInEffect"]?.ToString();

                    if (DateTime.TryParse(raw, out DateTime dt)) {
                        int daysOld = Math.Max(0, (int)(DateTime.Now - dt).TotalDays);
                        list.Add(new WindowsPatch { HotFixID = id, Description = desc, InstalledOn = dt, DaysOld = daysOld, DocLink = doc, Version = ver });
                    }
                }
            }
            catch { }
            return list.OrderByDescending(p => p.InstalledOn).ToList();
        }

        private class WindowsPatch { public string HotFixID = ""; public string Description = ""; public DateTime InstalledOn; public int DaysOld; public string DocLink = ""; public string Version = ""; }
        private static void ShowInstalledMenu(Control owner, InstalledProgram inst) {
            var menu = new ContextMenuStrip();
            var enabled = true;
            if (inst.ExePath is not null) {
                string exeDir = Path.GetDirectoryName(inst.ExePath) ?? "";

                var open = new ToolStripMenuItem("Open file location", null, (_, _) => OpenLocation(owner, inst.ExePath, exeDir)) { Enabled = enabled };
                menu.Items.Add(open);
                menu.Items.Add(new ToolStripSeparator());
                menu.Items.Add("Copy Exe path", null, (_, _) => { try { Clipboard.SetText(inst.ExePath); } catch { } })
                    .Enabled = enabled;

                var search = new ToolStripMenuItem("Search web ", null, (_, _) => SearchFor(owner, inst.ExePath)) { Enabled = enabled };
                menu.Items.Add(search);
            } else {
                var search = new ToolStripMenuItem("Search web ", null, (_, _) => SearchFor(owner, inst.Name)) { Enabled = enabled };
                menu.Items.Add(search);
            }
            menu.Show(Cursor.Position);
        }

        // ---- Links: render the links.html file in a browser control ----- //
        public static Control BuildLinks()
        {
            var browser = new WebBrowser
            {
                Dock = DockStyle.Fill,
                AllowWebBrowserDrop = false,
                IsWebBrowserContextMenuEnabled = false,
                ScriptErrorsSuppressed = true,
            };

            // Loaded from the embedded resource so it ships inside the single-file exe.
            string? html = EmbeddedAssets.ReadText("links.html");
            if (string.IsNullOrEmpty(html))
            {
                html =
"<!doctype html><html><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>Helpful Links</title>"
                    + "<style>body{font-family:Segoe UI, Tahoma, sans-serif;margin:12px;color:#222}h1{font-size:18px}li{margin:8px 0}a{color:#0066cc}</style></head><body>"
                    + "<h1>Helpful links</h1><ul>"
                    + "<li><a href=\"https://www.google.com/chrome/safety-check\" target=\"_blank\">Chrome Safety Check</a></li>"
                    + "<li><a href=\"windowsdefender://\">Windows Security</a></li>"
                    + "<li><a href=\"https://www.virustotal.com/\" target=\"_blank\">VirusTotal</a></li>"
                    + "<li><a href=\"https://developer.chrome.com/docs/extensions/\" target=\"_blank\">Chrome extensions guide</a></li>"
                    + "</ul></body></html>";
            }

            browser.DocumentText = html;

            void ApplyThemeToBrowser()
            {
                try
                {
                    var doc = browser.Document;
                    if (doc == null) return;
                    var headElems = doc.GetElementsByTagName("head");
                    HtmlElement head = headElems.Count > 0 ? headElems[0] : null;
                    string css = Theme.IsDark
                        ? "body{background:#1e1e1e;color:#ddd} a{color:#66aaff} .lead{color:#aaa} .note{color:#aaa} ul{color:#ddd}"
                        : "body{background:#fff;color:#222} a{color:#0066cc} .lead{color:#666} .note{color:#666} ul{color:#222}";

                    var existing = doc.GetElementById("app-theme-style");
                    if (existing != null)
                    {
                        try { existing.InnerHtml = css; } catch { existing.InnerText = css; }
                        return;
                    }

                    var style = doc.CreateElement("style");
                    style.SetAttribute("id", "app-theme-style");
                    style.SetAttribute("type", "text/css");
                    try { style.InnerHtml = css; } catch { style.InnerText = css; }
                    if (head != null) head.AppendChild(style);
                }
                catch { }
            }

            browser.DocumentCompleted += (_, _) => ApplyThemeToBrowser();

            browser.Navigating += (s, e) =>
            {
                try
                {
                    if (e.Url != null && (e.Url.Scheme.StartsWith("http") || e.Url.Scheme == "mailto" || e.Url.Scheme == "windowsdefender"))
                    {
                        e.Cancel = true;
                        Process.Start(new ProcessStartInfo(e.Url.AbsoluteUri) { UseShellExecute = true });
                    }
                }
                catch { }
            };

            Theme.Changed += () => { if (browser.IsHandleCreated) browser.BeginInvoke(new Action(ApplyThemeToBrowser)); };

            // The WebBrowser is a native control with no toolbar of its own, so host it
            // beneath a slim bar that carries the Help button (a floating overlay would be
            // painted over by the native browser).
            var host = new Panel { Dock = DockStyle.Fill, BackColor = Theme.Surface };
            var bar = new Panel { Dock = DockStyle.Top, Height = 40, BackColor = Theme.Toolbar };
            var help = HelpUi.CreateButton(TabHelp.Links);
            help.Top = 7;
            help.Anchor = AnchorStyles.Top | AnchorStyles.Right;
            bar.Controls.Add(help);
            void LayoutHelp() => help.Left = Math.Max(0, bar.ClientSize.Width - help.Width - 8);
            bar.SizeChanged += (_, _) => LayoutHelp();
            LayoutHelp();
            Theme.Changed += () => { if (bar.IsHandleCreated) bar.BeginInvoke(new Action(() => bar.BackColor = Theme.Toolbar)); };

            host.Controls.Add(browser);    // Fill first ...
            host.Controls.Add(bar);        // ... then the Top bar (outermost added last)
            return host;
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
                help: TabHelp.Processes,
                severity: items => WorstDays(items, o => (o as ProcessItem)?.DaysOld),
                onRowContext: o => ShowProcessMenu(grid, (ProcessItem)o),
                showAllToggle: ("All",
                    "Off: show only unusual (non-Windows) processes whose executable changed in the last 30 days.  On: show every running process.",
                    o =>
                {
                    var p = (ProcessItem)o;
                    bool unusual = p.ExePath.Length > 0 && !p.ExePath.StartsWith(win, StringComparison.OrdinalIgnoreCase);
                    bool recent = p.DaysOld is >= 0 and < 30;   // installed/updated within the last 30 days
                    return !(unusual && recent);   // when off, show ONLY unusual + recently changed
                }));
            return grid;
        }
        private static void ShowProcessMenu(Control owner, ProcessItem proc) {
            string exeDir = Path.GetDirectoryName(proc.ExePath);
            var menu = new ContextMenuStrip();
            var enabled = proc.ExePath.Length > 0;

            var open = new ToolStripMenuItem("Open file location", null, (_, _) => OpenLocation(owner, proc.ExePath, exeDir))
            { Enabled = enabled };
            menu.Items.Add(open);
            menu.Items.Add(new ToolStripSeparator());
            menu.Items.Add("Copy Exe path", null, (_, _) => { try { Clipboard.SetText(proc.ExePath); } catch { } })
                .Enabled = enabled;

            var search = new ToolStripMenuItem("Search web ", null, (_, _) => SearchFor(owner, proc.ExePath)) { Enabled = enabled };
            menu.Items.Add(search);

            menu.Show(Cursor.Position);
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
                new GridColumn { Header = "INF risk", Width = 70,
                    Text = o => ((DeviceDriver)o).Inf?.RiskLabel ?? "—",
                    Sort = o => (int)(((DeviceDriver)o).Inf?.Risk ?? TabSeverity.None),
                    Style = o => InfRiskStyle((DeviceDriver)o) },
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
                cols, defaultSortColumn: 3, defaultAscending: false,
                extraButtons: new (string, Action)[]
                {
                    ("Scan all INFs", () => _ = ScanAllInfs(grid)),
                    ("Device Manager", OpenDeviceManager),
                },
                help: TabHelp.Devices,
                severity: items =>
                {
                    var s = TabSeverity.None;
                    foreach (var o in items)
                        if (o is DeviceDriver d)
                        {
                            s = Sev.Max(s, Sev.FromDays(d.DaysOld));
                            if (!d.Signed) s = Sev.Max(s, TabSeverity.Caution);
                            if (d.Inf != null) s = Sev.Max(s, d.Inf.Risk);
                        }
                    return s;
                },
                onRowContext: o => ShowDeviceMenu(grid, (DeviceDriver)o));
            return grid;
        }

        private static (Color Back, Color Fore)? InfRiskStyle(DeviceDriver d) => d.Inf?.Risk switch
        {
            TabSeverity.Alert => (RedBack, RedFore),
            TabSeverity.Caution => (YelBack, YelFore),
            _ => null,   // not analyzed, or OK
        };

        private static void ShowDeviceMenu(Control owner, DeviceDriver d)
        {
            string infDir = System.IO.Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.Windows), "INF");
            var menu = new ContextMenuStrip();
            menu.Items.Add("Analyze INF (signing, dates, registry, directives)", null,
                (_, _) => AnalyzeInf(owner, d)).Enabled = d.InfPath.Length > 0;
            menu.Items.Add(new ToolStripSeparator());
            var open = new ToolStripMenuItem("Open file location (INF)", null, (_, _) => OpenLocation(owner, d.InfPath, infDir))
            { Enabled = d.InfPath.Length > 0 };
            menu.Items.Add(open);
            menu.Items.Add("Copy INF path", null, (_, _) => { try { Clipboard.SetText(d.InfPath); } catch { } })
                .Enabled = d.InfPath.Length > 0;

            menu.Items.Add("Search web for this event", null, (_, _) => {
                string q = HttpUtility.UrlEncode($"Windows driver  {d.Device} by {d.Provider} version {d.Version}");
                OpenBrowser($"https://www.google.com/search?q={q}");
            });

            menu.Show(Cursor.Position);
        }

        // Parse every listed driver's INF (cached per INF path) and fill the risk column.
        private static async Task ScanAllInfs(SortableGrid grid)
        {
            if (grid.Items.Count == 0) await grid.RunAsync();
            var drivers = grid.Items.OfType<DeviceDriver>().ToList();
            if (drivers.Count == 0) { grid.SetStatus("No devices to scan - click Refresh."); return; }

            grid.SetStatus("Analyzing INF files …");
            int flagged = await Task.Run(() =>
            {
                int f = 0;
                var cache = new Dictionary<string, InfAnalysis>(StringComparer.OrdinalIgnoreCase);
                foreach (var d in drivers)
                {
                    if (!cache.TryGetValue(d.InfPath, out var a)) { a = InfAnalyzer.Analyze(d); cache[d.InfPath] = a; }
                    d.Inf = a;
                    if (a.Risk == TabSeverity.Alert || a.Risk == TabSeverity.Caution) f++;
                }
                return f;
            });

            grid.RefreshDisplay();
            grid.SetStatus($"Analyzed {drivers.Count} drivers - {flagged} flagged. Sort by 'INF risk' or right-click a row for details.");
        }

        // Analyze one driver's INF and show the detailed findings.
        private static void AnalyzeInf(Control owner, DeviceDriver d)
        {
            var a = InfAnalyzer.Analyze(d);
            d.Inf = a;
            if (owner is SortableGrid g) g.RefreshDisplay();

            var sb = new StringBuilder();
            sb.AppendLine(d.Device);
            sb.AppendLine($"Provider: {(d.Provider.Length > 0 ? d.Provider : "(none)")}    Signed (Windows): {(d.Signed ? "Yes" : "No")}");
            sb.AppendLine(d.InfPath);
            sb.AppendLine();
            foreach (var f in a.Findings.OrderByDescending(x => (int)x.Severity))
                sb.AppendLine($"[{SeverityTag(f.Severity)}] {f.Text}");

            var icon = a.Risk == TabSeverity.Alert ? MessageBoxIcon.Warning
                     : a.Risk == TabSeverity.Caution ? MessageBoxIcon.Exclamation
                     : MessageBoxIcon.Information;
            MessageBox.Show(owner.FindForm(), sb.ToString(), $"INF analysis - {a.RiskLabel}",
                MessageBoxButtons.OK, icon);
        }

        private static string SeverityTag(TabSeverity s) => s switch
        {
            TabSeverity.Alert => "HIGH",
            TabSeverity.Caution => "REVIEW",
            _ => "ok",
        };

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
                new GridColumn { Header = "Path", Width = 120, Text = o => ((ChromeExtension)o).ProfileDir },
            };
            SortableGrid grid = null!;
            grid = new SortableGrid("Refresh",
                () => SafetyChecks.GetChromeExtensions().Where(e => e.Enabled).Cast<object>().ToList(),
                cols, defaultSortColumn: 2, defaultAscending: true,
                extraButtons: new (string, Action)[] { ("Remove unsupported", () => RemoveUnsupportedExtensions(grid)) },
                help: TabHelp.Chrome,
                headerInfo: SafetyChecks.CheckChromeHeader,
                headerHeight: 174,
                severity: items =>
                {
                    var s = SafetyChecks.ChromeSettingsSeverity();   // Safe Browsing / 3p-cookie risk
                    foreach (var o in items)
                        if (o is ChromeExtension x)
                        {
                            s = Sev.Max(s, Sev.FromDays(x.DaysOld));
                            if (x.Unsupported) s = Sev.Max(s, TabSeverity.Caution);
                        }
                    return s;
                },
                onRowContext: o => ShowChromeMenu(grid, (ChromeExtension)o),
                headerButton: ("Scan", () => ShowScanMenu(grid, "chrome.exe", SafetyChecks.ChromeExePath)));
            return grid;
        }

        /// <summary>
        /// Backs up every Chrome extension to a zip in Downloads, then (after confirmation)
        /// deletes the folders of all Manifest-V2 "Unsupported" extensions. Backup is best-effort;
        /// if it fails the user is asked whether to proceed without one.
        /// </summary>
        private static async void RemoveUnsupportedExtensions(SortableGrid grid)
        {
            var form = grid.FindForm();

            var all = await Task.Run(() => SafetyChecks.GetChromeExtensions());
            var unsupported = all.Where(e => e.Unsupported).ToList();
            if (unsupported.Count == 0)
            {
                MessageBox.Show(form, "No unsupported (Manifest V2) extensions were found.",
                    "Remove unsupported extensions", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }

            string list = string.Join("\n", unsupported.Take(20)
                .Select(e => $"   - {e.Name}  (v{e.Version})  [{e.ProfileName}]"));
            if (unsupported.Count > 20) list += $"\n   ...and {unsupported.Count - 20} more";

            string prompt =
                $"Remove {unsupported.Count} unsupported extension(s)?\n\n{list}\n\n" +
                $"First, all {all.Count} extension(s) will be backed up to:\n" +
                "   Downloads\\bsafe-extension-backup.zip\n\n" +
                "Close Chrome first for a clean removal. This permanently deletes the extension folders.";
            if (MessageBox.Show(form, prompt, "Remove unsupported extensions",
                    MessageBoxButtons.YesNo, MessageBoxIcon.Warning) != DialogResult.Yes)
                return;

            // 1) Backup (best-effort).
            grid.SetStatus("Backing up extensions ...");
            var (zipPath, zipCount, backupErr) = await Task.Run(() => SafetyChecks.BackupExtensions(all));

            if (backupErr != null)
            {
                var choice = MessageBox.Show(form,
                    $"The backup could not be created:\n   {backupErr}\n\nDelete the unsupported extensions anyway, WITHOUT a backup?",
                    "Backup failed", MessageBoxButtons.YesNo, MessageBoxIcon.Warning);
                if (choice != DialogResult.Yes) { grid.SetStatus("Cancelled - nothing removed."); return; }
            }

            // 2) Delete the unsupported extension folders.
            grid.SetStatus("Removing unsupported extensions ...");
            var (deleted, failed, errors) = await Task.Run(() => SafetyChecks.DeleteExtensionDirs(unsupported));

            // 3) Report and refresh.
            string summary = $"Removed {deleted} of {unsupported.Count} unsupported extension(s).";
            if (backupErr == null) summary += $"\nBackup: {zipCount} extension(s) saved to\n   {zipPath}";
            else summary += "\nNo backup was created.";
            if (failed > 0)
                summary += $"\n\n{failed} could not be removed (Chrome may be running):\n   " +
                           string.Join("\n   ", errors.Take(8));

            MessageBox.Show(form, summary, "Remove unsupported extensions",
                MessageBoxButtons.OK, failed > 0 ? MessageBoxIcon.Warning : MessageBoxIcon.Information);

            await grid.RunAsync();
        }
        private static void ShowChromeMenu(Control owner, ChromeExtension ext) {
            string exeDir = ext.ProfileDir;
            var menu = new ContextMenuStrip();
            var open = new ToolStripMenuItem("Open extension location", null, (_, _) => OpenLocation(owner, "", exeDir)) { Enabled = exeDir.Length > 0 };
            menu.Items.Add(open);
            menu.Items.Add(new ToolStripSeparator());
            menu.Items.Add("Copy extension path", null, (_, _) => { try { Clipboard.SetText(exeDir); } catch { } })
                .Enabled = exeDir.Length > 0;
            menu.Show(Cursor.Position);
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
                help: TabHelp.Services,
                severity: items => WorstDays(items, o => (o as ServiceInfo)?.DaysOld),
                onRowContext: o => ShowServiceMenu(grid, (ServiceInfo)o),
                showAllToggle: ("All",
                    "Off: hide old C:\\Windows\\system32 services to reduce noise.  On: show every installed service.",
                    o =>
                {
                    var s = (ServiceInfo)o;
                    string path = s.ExePath.Length > 0 ? s.ExePath : s.PathRaw;
                    bool system32 = path.IndexOf(@"C:\WINDOWS\system32", StringComparison.OrdinalIgnoreCase) >= 0;
                    bool old = s.DaysOld is >= 30;   // "Old" per the recency rules
                    return system32 && old;          // hidden when the All toggle is off
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
                new GridColumn { Header = "Enabled", Width = 76,
                    Text = o => ((StartupItem)o).EnabledText,
                    Sort = o => ((StartupItem)o).Enabled ? 1 : 0,
                    Style = o => ((StartupItem)o).Enabled ? null : ((Color, Color)?)(DisBack, DisFore) },
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
                extraButtons: new (string, Action)[] { ("Manage startup", () => StartShell(grid, "ms-settings:startupapps")) },
                help: TabHelp.Startup,
                severity: items => WorstDays(items, o => (o as StartupItem)?.DaysOld),
                showAllToggle: ("All", "Show disabled startup entries too (off = only enabled)",
                    o => !((StartupItem)o).Enabled),
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
        private static void SearchFor(Control owner, string fullPath) {
            string fileName = Path.GetFileName(fullPath);
            string encodedExe = HttpUtility.UrlEncode("what is windows program " + fileName);
            string url = $"https://www.google.com/search?q={encodedExe}";
            OpenBrowser(url);
        }
        static void OpenBrowser(string url) {
            try {
                // Windows approach
                if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows)) {
                    // In .NET Core/.NET 5+, UseShellExecute defaults to false, 
                    // so we must explicitly set it to true to launch a URL.
                    Process.Start(new ProcessStartInfo {
                        FileName = url,
                        UseShellExecute = true
                    });
                }
                // Linux approach
                else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux)) {
                    Process.Start("xdg-open", url);
                }
                // macOS approach
                else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX)) {
                    Process.Start("open", url);
                }
            } catch (Exception ex) {
                Console.WriteLine($"Could not open browser: {ex.Message}");
            }
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

        // ---- Events: recent Windows Event Log issues --------------------- //
        public static Control BuildEvents()
        {
            SortableGrid grid = null!;
            var cols = new[]
            {
                new GridColumn { Header = "Status", Width = 90,
                    Text = o => EventStatusLabel((EventItem)o),
                    Sort = o => EventRank((EventItem)o),
                    Style = o => EventStatusStyle((EventItem)o) },
                new GridColumn { Header = "Time", Width = 120,
                    Text = o => ((EventItem)o).TimeText,
                    Sort = o => ((EventItem)o).TimeSort },
                new GridColumn { Header = "Channel", Width = 150,
                    Text = o => SafetyChecks.ShortChannel(((EventItem)o).Channel),
                    Sort = o => ((EventItem)o).Channel,
                    FilterKind = ColumnFilterKind.Dropdown },
                new GridColumn { Header = "Source", Width = 170, Text = o => ((EventItem)o).Source,
                    FilterKind = ColumnFilterKind.Regex },
                new GridColumn { Header = "Event", Width = 60,
                    Text = o => ((EventItem)o).EventId.ToString(),
                    Sort = o => ((EventItem)o).EventId },
                new GridColumn { Header = "Message", Fill = 200, Text = o => ((EventItem)o).Message,
                    FilterKind = ColumnFilterKind.Regex },
            };
            grid = new SortableGrid("Refresh",
                () => SafetyChecks.GetEventLogIssues().Cast<object>().ToList(),
                cols, defaultSortColumn: 1, defaultAscending: false,
                extraButtons: new (string, Action)[] { ("Event Viewer", OpenEventViewer) },
                help: TabHelp.Events,
                severity: WorstEvents,
                onRowContext: o => ShowEventMenu(grid, (EventItem)o));
            return grid;
        }

        // ---- Awake periods ----------------------------------------------- //
        public static Control BuildAwake()
        {
            var cols = new[]
            {
                new GridColumn { Header = "#", Width = 54,
                    Text = o => ((AwakePeriod)o).Index.ToString(),
                    Sort = o => ((AwakePeriod)o).Index },
                new GridColumn { Header = "Start", Width = 130,
                    Text = o => ((AwakePeriod)o).StartText,
                    Sort = o => ((AwakePeriod)o).Start },
                new GridColumn { Header = "End", Width = 170,
                    Text = o => ((AwakePeriod)o).EndText,
                    Sort = o => ((AwakePeriod)o).EndSort,
                    Style = o => AwakeRowStyle((AwakePeriod)o) },
                new GridColumn { Header = "Duration", Width = 96,
                    Text = o => ((AwakePeriod)o).DurationText,
                    Sort = o => ((AwakePeriod)o).DurationMin },
                new GridColumn { Header = "Why", Fill = 180,
                    Text = o => ((AwakePeriod)o).Why,
                    FilterKind = ColumnFilterKind.Regex },
            };
            return new SortableGrid("Refresh",
                () => SafetyChecks.GetAwakePeriods().Cast<object>().ToList(),
                cols, defaultSortColumn: 1, defaultAscending: false,   // newest first
                extraButtons: new (string, Action)[] { ("Event Viewer", OpenEventViewer) },
                help: TabHelp.Awake,
                summary: () =>
                {
                    var ps = SafetyChecks.GetAwakePeriods();
                    int unexpected = ps.Count(p => p.Unexpected);
                    return unexpected > 0 ? $"{unexpected} ended unexpectedly (pwr)" : "all clean";
                },
                severity: AwakeSeverity);
        }

        // Current session -> green; an unexpected (no clean shutdown) end -> yellow.
        private static (Color Back, Color Fore)? AwakeRowStyle(AwakePeriod p)
            => p.Current ? (GrnBack, GrnFore) : p.Unexpected ? (YelBack, YelFore) : ((Color, Color)?)null;

        private static TabSeverity AwakeSeverity(System.Collections.Generic.IReadOnlyList<object> items)
        {
            foreach (var o in items)
                if (o is AwakePeriod p && p.Unexpected) return TabSeverity.Caution;
            return TabSeverity.None;
        }

        // ---- Root CAs ---------------------------------------------------- //
        public static Control BuildRootCerts()
        {
            SortableGrid grid = null!;
            var cols = new[]
            {
                new GridColumn { Header = "Status", Width = 84,
                    Text = o => ((RootCertItem)o).StatusLabel,
                    Sort = o => (int)((RootCertItem)o).Severity,
                    Style = o => RootStyle((RootCertItem)o) },
                new GridColumn { Header = "Store", Width = 104,
                    Text = o => ((RootCertItem)o).Store,
                    FilterKind = ColumnFilterKind.Dropdown },
                new GridColumn { Header = "Subject (CA)", Fill = 150, Text = o => ((RootCertItem)o).Subject,
                    FilterKind = ColumnFilterKind.Regex },
                new GridColumn { Header = "Issuer", Fill = 110, Text = o => ((RootCertItem)o).Issuer },
                new GridColumn { Header = "Expires", Width = 90,
                    Text = o => ((RootCertItem)o).ExpiresText,
                    Sort = o => ((RootCertItem)o).NotAfter },
                new GridColumn { Header = "Note", Fill = 180, Text = o => ((RootCertItem)o).Note },
            };
            grid = new SortableGrid("Refresh",
                () => SafetyChecks.GetRootCerts().Cast<object>().ToList(),
                cols, defaultSortColumn: 0, defaultAscending: false,
                extraButtons: new (string, Action)[] { ("Manage certificates", () => StartShell(grid, "certlm.msc")) },
                help: TabHelp.RootCerts,
                severity: RootSeverity,
                showAllToggle: ("All", "Show well-known public / system roots too (off = only non-public roots to review)",
                    o => ((RootCertItem)o).Expected),
                onRowContext: o => ShowRootMenu(grid, (RootCertItem)o));
            return grid;
        }

        private static (Color Back, Color Fore)? RootStyle(RootCertItem c) => c.Severity switch
        {
            TabSeverity.Alert => (RedBack, RedFore),
            TabSeverity.Caution => (YelBack, YelFore),
            _ => ((Color, Color)?)null,
        };

        private static TabSeverity RootSeverity(System.Collections.Generic.IReadOnlyList<object> items)
        {
            var s = TabSeverity.None;
            foreach (var o in items) if (o is RootCertItem c) s = Sev.Max(s, c.Severity);
            return s;
        }

        private static void ShowRootMenu(Control owner, RootCertItem c)
        {
            var menu = new ContextMenuStrip();
            menu.Items.Add("Copy subject", null, (_, _) => { try { Clipboard.SetText(c.SubjectFull); } catch { } });
            menu.Items.Add("Copy thumbprint", null, (_, _) => { try { Clipboard.SetText(c.Thumbprint); } catch { } });
            menu.Items.Add(new ToolStripSeparator());
            menu.Items.Add("Open Certificates console (certlm.msc)", null, (_, _) => StartShell(owner, "certlm.msc"));
            menu.Items.Add("Search the web for this CA", null, (_, _) =>
                OpenBrowser("https://www.google.com/search?q=" +
                    HttpUtility.UrlEncode("root certificate authority " + c.Subject)));
            menu.Show(Cursor.Position);
        }

        // Status label + colour: security-significant and Critical -> red; Error/Warning -> yellow.
        private static string EventStatusLabel(EventItem e)
        {
            if (e.Significant) return "Security";
            if (e.Level.Equals("Critical", StringComparison.OrdinalIgnoreCase)) return "Critical";
            if (e.Level.Equals("Error", StringComparison.OrdinalIgnoreCase)) return "Error";
            if (e.Level.Equals("Warning", StringComparison.OrdinalIgnoreCase)) return "Warning";
            return e.Level.Length > 0 ? e.Level : "Info";
        }

        private static (Color Back, Color Fore)? EventStatusStyle(EventItem e)
        {
            if (e.Significant || e.Level.Equals("Critical", StringComparison.OrdinalIgnoreCase)) return (RedBack, RedFore);
            if (e.Level.Equals("Error", StringComparison.OrdinalIgnoreCase) ||
                e.Level.Equals("Warning", StringComparison.OrdinalIgnoreCase)) return (YelBack, YelFore);
            return null;
        }

        // Sort key for the Status column (higher = more severe / floats to top when descending).
        private static IComparable EventRank(EventItem e)
        {
            if (e.Significant) return 4;
            return e.Level.ToLowerInvariant() switch
            {
                "critical" => 3,
                "error" => 2,
                "warning" => 1,
                _ => 0,
            };
        }

        private static TabSeverity WorstEvents(System.Collections.Generic.IReadOnlyList<object> items)
        {
            var s = TabSeverity.None;
            foreach (var o in items)
            {
                if (o is not EventItem e) continue;
                if (e.Significant || e.Level.Equals("Critical", StringComparison.OrdinalIgnoreCase))
                    s = Sev.Max(s, TabSeverity.Alert);
                else if (e.Level.Equals("Error", StringComparison.OrdinalIgnoreCase) ||
                         e.Level.Equals("Warning", StringComparison.OrdinalIgnoreCase))
                    s = Sev.Max(s, TabSeverity.Caution);
                else
                    s = Sev.Max(s, TabSeverity.Ok);
            }
            return s;
        }

        private static void OpenEventViewer()
        {
            try { Process.Start(new ProcessStartInfo("eventvwr.msc") { UseShellExecute = true }); }
            catch { /* ignore */ }
        }

        private static void ShowEventMenu(Control owner, EventItem e)
        {
            var menu = new ContextMenuStrip();
            menu.Items.Add("Open Event Viewer", null, (_, _) => OpenEventViewer());
            menu.Items.Add(new ToolStripSeparator());
            menu.Items.Add("Copy message", null, (_, _) => { try { Clipboard.SetText(e.Message); } catch { } });
            menu.Items.Add("Search web for this event", null, (_, _) =>
            {
                string q = HttpUtility.UrlEncode($"Windows event {e.EventId} {SafetyChecks.ShortChannel(e.Channel)} {e.Source}");
                OpenBrowser($"https://www.google.com/search?q={q}");
            });
            menu.Items.Add(new ToolStripSeparator());
            menu.Items.Add("Show details", null, async (_, _) => await ShowEventDetailsAsync(owner, e));
            menu.Show(Cursor.Position);
        }

        private static async System.Threading.Tasks.Task ShowEventDetailsAsync(Control owner, EventItem e)
        {
            string logName = string.IsNullOrEmpty(e.Channel) ? "System" : e.Channel;
            string provider = string.IsNullOrEmpty(e.Source) ? "Service Control Manager" : e.Source;

            string psCmd = $"Get-WinEvent -FilterHashtable @{{LogName='{logName}'; ProviderName='{provider}'; Id={e.EventId}}} -MaxEvents 1 | Format-List *";

            string output = "";
            try
            {
                var psi = new ProcessStartInfo("powershell")
                {
                    Arguments = $"-NoProfile -Command \"{psCmd}\"",
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                };

                using var p = Process.Start(psi);
                if (p != null)
                {
                    output = await p.StandardOutput.ReadToEndAsync().ConfigureAwait(false);
                    var err = await p.StandardError.ReadToEndAsync().ConfigureAwait(false);
                    p.WaitForExit(3000);
                    if (string.IsNullOrWhiteSpace(output) && !string.IsNullOrWhiteSpace(err)) output = err;
                }
            }
            catch (Exception ex)
            {
                output = "Error running PowerShell: " + ex.Message;
            }

            if (string.IsNullOrWhiteSpace(output)) output = "(no details returned)";

            // Show in a simple dialog
            try
            {
                if (owner?.FindForm() is Form parent)
                {
                    var dlg = new Form { Text = $"Event {e.EventId} details", Size = new Size(800, 520), StartPosition = FormStartPosition.CenterParent };
                    var tb = new TextBox { Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Both, Dock = DockStyle.Fill, Font = new Font("Consolas", 9f), Text = output };
                    dlg.Controls.Add(tb);
                    dlg.ShowDialog(parent);
                }
                else
                {
                    MessageBox.Show(output, $"Event {e.EventId} details", MessageBoxButtons.OK, MessageBoxIcon.Information);
                }
            }
            catch { try { MessageBox.Show(output, $"Event {e.EventId} details", MessageBoxButtons.OK, MessageBoxIcon.Information); } catch { } }
        }

        // ---- DNS: resolver cache ----------------------------------------- //
        public static Control BuildDns()
        {
            var cols = new[]
            {
                new GridColumn { Header = "Status", Width = 80,
                    Text = o => ((DnsCacheEntry)o).Suspicious ? "Review" : "OK",
                    Sort = o => ((DnsCacheEntry)o).Suspicious ? 1 : 0,
                    Style = o => ((DnsCacheEntry)o).Suspicious ? ((Color, Color)?)(YelBack, YelFore) : null },
                new GridColumn { Header = "Type", Width = 64, Text = o => ((DnsCacheEntry)o).TypeText },
                new GridColumn { Header = "TTL (s)", Width = 70,
                    Text = o => ((DnsCacheEntry)o).Ttl.ToString(),
                    Sort = o => ((DnsCacheEntry)o).Ttl },
                new GridColumn { Header = "Name", Fill = 140, Text = o => ((DnsCacheEntry)o).Name },
                new GridColumn { Header = "Data (answer)", Fill = 140, Text = o => ((DnsCacheEntry)o).Data },
                new GridColumn { Header = "Queried", Fill = 110, Text = o => ((DnsCacheEntry)o).Entry },
            };

            SortableGrid grid = null!;
            grid = new SortableGrid("Refresh",
                () => SafetyChecks.GetDnsCache().Cast<object>().ToList(),
                cols, defaultSortColumn: 0, defaultAscending: false,
                extraButtons: new (string, Action)[] { ("Flush DNS cache", () => _ = FlushDnsAndReload(grid)) },
                help: TabHelp.Dns,
                severity: items =>
                {
                    var s = TabSeverity.None;
                    foreach (var o in items)
                        if (o is DnsCacheEntry e)
                            s = Sev.Max(s, e.Suspicious ? TabSeverity.Caution : TabSeverity.Ok);
                    return s;
                },
                onRowContext: o => ShowDnsMenu(grid, (DnsCacheEntry)o));
            return grid;
        }

        private static async Task FlushDnsAndReload(SortableGrid grid)
        {
            grid.SetStatus("Flushing DNS resolver cache …");
            bool ok = await Task.Run(SafetyChecks.FlushDnsCache);
            await grid.RunAsync();   // reload the (now-empty) cache view
            grid.SetStatus(ok ? "DNS resolver cache flushed." : "Could not flush the DNS cache.");
        }

        private static void ShowDnsMenu(Control owner, DnsCacheEntry e)
        {
            var menu = new ContextMenuStrip();
            menu.Items.Add("Copy name", null, (_, _) => { try { Clipboard.SetText(e.Name); } catch { } });
            menu.Items.Add("Copy answer", null, (_, _) => { try { Clipboard.SetText(e.Data); } catch { } })
                .Enabled = e.Data.Length > 0;
            menu.Items.Add(new ToolStripSeparator());
            menu.Items.Add("Search web for this host", null, (_, _) =>
            {
                string q = HttpUtility.UrlEncode(e.Name.Length > 0 ? e.Name : e.Entry);
                OpenBrowser($"https://www.google.com/search?q={q}");
            });
            menu.Show(Cursor.Position);
        }

        // ---- ARP: local IPv4 neighbor cache ------------------------------ //
        public static Control BuildArp()
        {
            var cols = new[]
            {
                new GridColumn { Header = "Status", Width = 80,
                    Text = o => ArpStatusLabel((ArpEntry)o),
                    Sort = o => (int)((ArpEntry)o).Risk,
                    Style = o => ArpStyle((ArpEntry)o) },
                new GridColumn { Header = "IP Address", Width = 120,
                    Text = o => ((ArpEntry)o).Ip,
                    Sort = o => ArpIpKey(((ArpEntry)o).Ip) },
                new GridColumn { Header = "MAC", Width = 140, Text = o => ((ArpEntry)o).Mac },
                new GridColumn { Header = "Vendor", Width = 150,
                    Text = o => { var e = (ArpEntry)o; return e.Vendor.Length > 0 ? e.Vendor : e.Oui; } },
                new GridColumn { Header = "Type", Width = 76,
                    Text = o => { var e = (ArpEntry)o; return e.Mac.Length == 0 ? "—" : e.IsStatic ? "Static" : "Dynamic"; } },
                new GridColumn { Header = "State", Width = 90, Text = o => ((ArpEntry)o).State },
                new GridColumn { Header = "Interface", Width = 120, Text = o => ((ArpEntry)o).Interface },
                new GridColumn { Header = "Note", Fill = 160, Text = o => ((ArpEntry)o).Note },
            };

            SortableGrid grid = null!;
            grid = new SortableGrid("Refresh",
                () => SafetyChecks.GetArpTable().Cast<object>().ToList(),
                cols, defaultSortColumn: 0, defaultAscending: false,
                extraButtons: new (string, Action)[] { ("Resolve vendors", () => _ = ResolveArpVendors(grid)) },
                help: TabHelp.Arp,
                severity: items =>
                {
                    var s = TabSeverity.None;
                    foreach (var o in items)
                        if (o is ArpEntry e) s = Sev.Max(s, e.Risk);
                    return s;
                },
                onRowContext: o => ShowArpMenu(grid, (ArpEntry)o),
                showAllToggle: ("All",
                    "Off: hide multicast, broadcast and incomplete entries.  On: show the full ARP cache.",
                    o => ((ArpEntry)o).IsNoise));
            return grid;
        }

        private static string ArpStatusLabel(ArpEntry e) => e.Risk switch
        {
            TabSeverity.Alert => "Alert",
            TabSeverity.Caution => "Review",
            _ => e.IsNoise ? "—" : e.IsStatic ? "Static" : "OK",
        };

        private static (Color Back, Color Fore)? ArpStyle(ArpEntry e) => e.Risk switch
        {
            TabSeverity.Alert => (RedBack, RedFore),
            TabSeverity.Caution => (YelBack, YelFore),
            _ => null,
        };

        /// <summary>Zero-padded sort key so IPv4 addresses sort numerically, not lexically.</summary>
        private static IComparable ArpIpKey(string ip)
        {
            if (System.Net.IPAddress.TryParse(ip, out var addr))
            {
                var b = addr.GetAddressBytes();
                if (b.Length == 4) return $"{b[0]:D3}.{b[1]:D3}.{b[2]:D3}.{b[3]:D3}";
            }
            return ip;
        }

        private static async Task ResolveArpVendors(SortableGrid grid)
        {
            var entries = grid.Items.OfType<ArpEntry>().ToList();
            if (entries.Count == 0) return;
            grid.SetStatus("Resolving vendors (macvendors.com) …");
            await Task.Run(() => SafetyChecks.ResolveArpVendors(entries));
            grid.RefreshDisplay();
            grid.SetStatus("Vendors resolved.");
        }

        private static void ShowArpMenu(Control owner, ArpEntry e)
        {
            var menu = new ContextMenuStrip();
            menu.Items.Add("Copy IP", null, (_, _) => { try { Clipboard.SetText(e.Ip); } catch { } });
            menu.Items.Add("Copy MAC", null, (_, _) => { try { Clipboard.SetText(e.Mac); } catch { } })
                .Enabled = e.Mac.Length > 0;
            menu.Items.Add(new ToolStripSeparator());

            var lookup = new ToolStripMenuItem("Look up vendor (macvendors.com)", null, async (_, _) =>
            {
                string vendor = await Task.Run(() => SafetyChecks.LookupVendor(e.Oui));
                MessageBox.Show(owner.FindForm(),
                    vendor.Length > 0 ? $"{e.Mac}\nOUI {e.Oui}\n\nVendor: {vendor}"
                                      : $"{e.Mac}\nOUI {e.Oui}\n\nNo vendor found (or lookup was rate-limited).",
                    "MAC vendor", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }) { Enabled = e.Oui.Length == 8 };
            menu.Items.Add(lookup);

            menu.Items.Add("Search web for this MAC", null, (_, _) =>
            {
                string q = HttpUtility.UrlEncode($"{e.Oui} MAC OUI vendor");
                OpenBrowser($"https://www.google.com/search?q={q}");
            }).Enabled = e.Oui.Length == 8;

            menu.Items.Add(new ToolStripSeparator());
            menu.Items.Add("Copy row", null, (_, _) =>
            {
                try { Clipboard.SetText($"{e.Ip}\t{e.Mac}\t{(e.Vendor.Length > 0 ? e.Vendor : e.Oui)}\t{e.State}\t{e.Interface}\t{e.Note}"); }
                catch { }
            });
            menu.Show(Cursor.Position);
        }

        // ---- Restores: Windows System Restore points (admin) ------------- //
        public static Control BuildRestores()
        {
            var cols = new[]
            {
                new GridColumn { Header = "Status", Width = 80,
                    Text = o => ((RestorePoint)o).Risk >= TabSeverity.Caution ? "Review" : "OK",
                    Sort = o => (int)((RestorePoint)o).Risk,
                    Style = o => ((RestorePoint)o).Risk >= TabSeverity.Caution ? ((Color, Color)?)(YelBack, YelFore) : null },
                new GridColumn { Header = "Seq #", Width = 64,
                    Text = o => ((RestorePoint)o).Sequence.ToString(),
                    Sort = o => ((RestorePoint)o).Sequence },
                new GridColumn { Header = "Created", Width = 140,
                    Text = o => ((RestorePoint)o).CreatedText,
                    Sort = o => ((RestorePoint)o).Created ?? DateTime.MinValue },
                new GridColumn { Header = "Age (days)", Width = 80,
                    Text = o => ((RestorePoint)o).DaysOld?.ToString() ?? "—",
                    Sort = o => ((RestorePoint)o).DaysOld ?? int.MaxValue },
                new GridColumn { Header = "Type", Width = 120, Text = o => ((RestorePoint)o).TypeText },
                new GridColumn { Header = "Description", Fill = 200,
                    Text = o => { var p = (RestorePoint)o; return p.Note.Length > 0 ? $"{p.Description}  — {p.Note}" : p.Description; } },
            };

            SortableGrid grid = null!;
            grid = new SortableGrid("Refresh",
                () => SafetyChecks.GetRestorePoints().Cast<object>().ToList(),
                cols, defaultSortColumn: 2, defaultAscending: false,
                help: TabHelp.Restores,
                headerInfo: SafetyChecks.RestoreHeader,
                severity: items =>
                {
                    if (items.Count == 0) return TabSeverity.Alert;          // disabled / purged - IoC
                    var rps = items.OfType<RestorePoint>().ToList();
                    var s = TabSeverity.Ok;
                    foreach (var r in rps) s = Sev.Max(s, r.Risk);
                    int youngest = rps.Min(r => r.DaysOld ?? int.MaxValue);
                    if (youngest > 90) s = Sev.Max(s, TabSeverity.Caution);  // no recent safety net
                    return s;
                },
                onRowContext: o => ShowRestoreMenu(grid, (RestorePoint)o));
            return grid;
        }

        private static void ShowRestoreMenu(Control owner, RestorePoint p)
        {
            var menu = new ContextMenuStrip();
            menu.Items.Add("Copy description", null, (_, _) => { try { Clipboard.SetText(p.Description); } catch { } });
            menu.Items.Add("Copy sequence #", null, (_, _) => { try { Clipboard.SetText(p.Sequence.ToString()); } catch { } });
            menu.Items.Add(new ToolStripSeparator());
            menu.Items.Add("Open System Protection", null, (_, _) => StartShell(owner, "SystemPropertiesProtection.exe"));
            menu.Show(Cursor.Position);
        }

        // ---- Win Extn: File Explorer shell extensions -------------------- //
        public static Control BuildWinExt()
        {
            var cols = new[]
            {
                new GridColumn { Header = "Status", Width = 80,
                    Text = o => WinExtStatusLabel((ShellExtension)o),
                    Sort = o => (int)((ShellExtension)o).Risk,
                    Style = o => WinExtStyle((ShellExtension)o) },
                new GridColumn { Header = "Signed", Width = 80, Text = o => ((ShellExtension)o).SignStatus },
                new GridColumn { Header = "Type", Width = 110, Text = o => ((ShellExtension)o).Types },
                new GridColumn { Header = "Target", Width = 110, Text = o => ((ShellExtension)o).Targets },
                new GridColumn { Header = "Name", Fill = 150, Text = o => ((ShellExtension)o).Name },
                new GridColumn { Header = "Company", Width = 150, Text = o => ((ShellExtension)o).Company },
                new GridColumn { Header = "DLL path", Fill = 170, Text = o => ((ShellExtension)o).DllPath },
                new GridColumn { Header = "CLSID", Width = 150, Text = o => ((ShellExtension)o).Clsid },
            };

            SortableGrid grid = null!;
            grid = new SortableGrid("Refresh",
                () => SafetyChecks.GetShellExtensions().Cast<object>().ToList(),
                cols, defaultSortColumn: 0, defaultAscending: false,
                extraButtons: new (string, Action)[] { ("Verify signatures", () => _ = VerifyWinExt(grid)) },
                help: TabHelp.WinExt,
                severity: items =>
                {
                    var s = TabSeverity.None;
                    foreach (var o in items)
                        if (o is ShellExtension e) s = Sev.Max(s, e.Risk);
                    return s;
                },
                onRowContext: o => ShowWinExtMenu(grid, (ShellExtension)o),
                showAllToggle: ("All",
                    "Off: third-party handlers only.  On: include Microsoft / built-in shell extensions.",
                    o => ((ShellExtension)o).IsBuiltin));
            return grid;
        }

        private static string WinExtStatusLabel(ShellExtension e) => e.Risk switch
        {
            TabSeverity.Alert => "Alert",
            TabSeverity.Caution => "Review",
            _ => "OK",
        };

        private static (Color Back, Color Fore)? WinExtStyle(ShellExtension e) => e.Risk switch
        {
            TabSeverity.Alert => (RedBack, RedFore),
            TabSeverity.Caution => (YelBack, YelFore),
            _ => null,
        };

        private static async Task VerifyWinExt(SortableGrid grid)
        {
            var exts = grid.Items.OfType<ShellExtension>().ToList();
            if (exts.Count == 0) { grid.SetStatus("Nothing to verify - click Refresh."); return; }
            grid.SetStatus("Verifying handler signatures …");
            int flagged = await Task.Run(() =>
            {
                SafetyChecks.VerifyShellExtensions(exts);
                return exts.Count(e => e.Risk >= TabSeverity.Alert);
            });
            grid.RefreshDisplay();
            grid.SetStatus($"Verified {exts.Count} handler(s) - {flagged} unsigned/invalid flagged.");
        }

        private static void ShowWinExtMenu(SortableGrid grid, ShellExtension e)
        {
            bool hasDll = e.DllPath.Length > 0;
            var menu = new ContextMenuStrip();
            menu.Items.Add("Open DLL location", null,
                (_, _) => OpenLocation(grid, e.DllPath, System.IO.Path.GetDirectoryName(e.DllPath) ?? ""))
                .Enabled = hasDll && File.Exists(e.DllPath);
            menu.Items.Add("Copy CLSID", null, (_, _) => { try { Clipboard.SetText(e.Clsid); } catch { } });
            menu.Items.Add("Copy DLL path", null, (_, _) => { try { Clipboard.SetText(e.DllPath); } catch { } })
                .Enabled = hasDll;
            menu.Items.Add(new ToolStripSeparator());
            menu.Items.Add("Verify signature / VirusTotal", null,
                (_, _) => ShowScanMenu(grid, e.Name, () => File.Exists(e.DllPath) ? e.DllPath : null))
                .Enabled = hasDll;
            menu.Items.Add("Search web for this CLSID", null, (_, _) =>
            {
                string q = HttpUtility.UrlEncode(e.Clsid + " shell extension");
                OpenBrowser($"https://www.google.com/search?q={q}");
            });
            menu.Show(Cursor.Position);
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
