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

namespace B4Browse
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
                riskRow: o => o is InstalledProgram p && (Sev.FromDays(p.DaysOld) >= TabSeverity.Caution || p.HasUpdate),
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
                riskRow: o => o is FirewallRule r && r.Risk >= TabSeverity.Caution,
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
                // The WMI Caption "DocLink" is unreliable (often empty or a generic support-home URL),
                // so this opens a web search for the KB instead - which always lands on useful info.
                // Right-click offers the Update Catalog, the support article, and local details.
                new GridColumn { Header = "Lookup", Width = 110, Link = true,
                    Text = o => PatchLookupLabel((WindowsPatch)o),
                    LinkTarget = o => PatchSearchUrl((WindowsPatch)o) },

                new GridColumn { Header = "Description", Fill = 180, Text = o => ((WindowsPatch)o).Description },
                           };

            SortableGrid grid = null!;
            grid = new SortableGrid("Refresh",
                () => GetPatches().Cast<object>().ToList(),
                cols, defaultSortColumn: 2, defaultAscending: false,
                help: TabHelp.Patches,
                severity: items => TabSeverity.None,
                onRowContext: o => ShowPatchMenu(grid, (WindowsPatch)o));
            return grid;
        }

        private static System.Collections.Generic.List<WindowsPatch> GetPatches()
        {
            var list = new System.Collections.Generic.List<WindowsPatch>();
            try
            {
                var searcher = new ManagementObjectSearcher("SELECT HotFixID, Description, InstalledOn, Caption, ServicePackInEffect, InstalledBy, FixComments FROM Win32_QuickFixEngineering");
                foreach (ManagementObject obj in searcher.Get())
                {
                    string id = obj["HotFixID"]?.ToString() ?? "Unknown";
                    string desc = obj["Description"]?.ToString() ?? "";
                    string raw = obj["InstalledOn"]?.ToString();

                    string doc = obj["Caption"]?.ToString();
                    string ver = obj["ServicePackInEffect"]?.ToString();

                    if (DateTime.TryParse(raw, out DateTime dt)) {
                        int daysOld = Math.Max(0, (int)(DateTime.Now - dt).TotalDays);
                        list.Add(new WindowsPatch {
                            HotFixID = id, Description = desc, InstalledOn = dt, DaysOld = daysOld,
                            DocLink = doc, Version = ver,
                            InstalledBy = obj["InstalledBy"]?.ToString() ?? "",
                            FixComments = obj["FixComments"]?.ToString() ?? "",
                        });
                    }
                }
            }
            catch { }
            return list.OrderByDescending(p => p.InstalledOn).ToList();
        }

        private class WindowsPatch {
            public string HotFixID = ""; public string Description = ""; public DateTime InstalledOn;
            public int DaysOld; public string DocLink = ""; public string Version = "";
            public string InstalledBy = ""; public string FixComments = "";
        }

        // The KB number without the "KB" prefix, or "" when the HotFixID isn't a KB entry.
        private static string KbNumber(WindowsPatch p) =>
            p.HotFixID.StartsWith("KB", StringComparison.OrdinalIgnoreCase)
                ? new string(p.HotFixID.Where(char.IsDigit).ToArray())
                : "";

        private static string PatchLookupLabel(WindowsPatch p) => "Search web";

        // What the Lookup column opens: a web search that reliably surfaces info about the update.
        private static string PatchSearchUrl(WindowsPatch p)
        {
            string q = p.HotFixID.StartsWith("KB", StringComparison.OrdinalIgnoreCase)
                ? $"Microsoft Windows patch {p.HotFixID}"
                : $"Microsoft Windows patch {p.HotFixID} {p.Description}";
            return "https://www.google.com/search?q=" + HttpUtility.UrlEncode(q);
        }

        private static void ShowPatchMenu(Control owner, WindowsPatch p)
        {
            string kb = KbNumber(p);
            var menu = new ContextMenuStrip();

            menu.Items.Add("Search the web for this update", null, (_, _) => OpenBrowser(PatchSearchUrl(p)));
            menu.Items.Add("Open Microsoft Update Catalog", null, (_, _) =>
                OpenBrowser("https://www.catalog.update.microsoft.com/Search.aspx?q=" +
                            HttpUtility.UrlEncode(p.HotFixID)))
                .Enabled = kb.Length > 0;
            menu.Items.Add("Open Microsoft support article", null, (_, _) =>
                OpenBrowser("https://support.microsoft.com/help/" + kb))
                .Enabled = kb.Length > 0;
            menu.Items.Add(new ToolStripSeparator());
            menu.Items.Add("Show details", null, (_, _) =>
                CopyableMessageBox.Show(owner.FindForm(), PatchDetails(p),
                    $"Update {p.HotFixID}", MessageBoxButtons.OK, MessageBoxIcon.Information));
            menu.Items.Add("Copy HotFix ID", null, (_, _) => { try { Clipboard.SetText(p.HotFixID); } catch { } });
            menu.Show(Cursor.Position);
        }

        // Local fallback info, assembled from WMI (Win32_QuickFixEngineering) - no network needed.
        private static string PatchDetails(WindowsPatch p)
        {
            var sb = new StringBuilder();
            sb.AppendLine($"HotFix ID:    {p.HotFixID}");
            sb.AppendLine($"Type:         {(p.Description.Length > 0 ? p.Description : "Update")}");
            sb.AppendLine($"Installed on: {p.InstalledOn:yyyy-MM-dd}  ({p.DaysOld} day(s) ago)");
            if (p.InstalledBy.Length > 0) sb.AppendLine($"Installed by: {p.InstalledBy}");
            if (p.Version.Length > 0) sb.AppendLine($"Service pack: {p.Version}");
            if (p.FixComments.Length > 0) sb.AppendLine($"Comments:     {p.FixComments}");
            if (p.DocLink.Length > 0) sb.AppendLine($"WMI doc link: {p.DocLink}");
            sb.AppendLine();
            sb.AppendLine("Source: WMI Win32_QuickFixEngineering (local).");
            sb.AppendLine("Use the right-click web search or Update Catalog for the full description online.");
            return sb.ToString();
        }
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

            // winget package details (works for any row: by Id when known, else by name lookup).
            menu.Items.Add(new ToolStripSeparator());
            menu.Items.Add("Show winget info", null, (_, _) => ShowWingetInfo(owner, inst));

            // winget update - enabled only when winget knows the package AND reports a newer version.
            bool canUpdate = inst.WingetId.Length > 0 && inst.HasUpdate;
            string updLabel = inst.HasUpdate ? $"Update to v{inst.AvailableVersion} (winget)" : "Update (winget)";
            var update = new ToolStripMenuItem(updLabel, null, (_, _) => ShowUpdateWithWinget(owner, inst))
            {
                Enabled = canUpdate,
                ToolTipText = canUpdate ? "" :
                    inst.WingetId.Length == 0 ? "No winget package is associated with this program."
                                              : "winget reports no available update.",
            };
            menu.Items.Add(update);

            menu.Show(Cursor.Position);
        }

        /// <summary>Confirms, then runs `winget upgrade` for the program (off the UI thread) and
        /// reports the result in a selectable, non-blocking dialog, refreshing the tab afterwards.</summary>
        private static async void ShowUpdateWithWinget(Control owner, InstalledProgram inst)
        {
            var form = owner.FindForm();
            var grid = owner as SortableGrid;

            string change = inst.AvailableVersion.Length > 0
                ? $"from v{inst.Version} to v{inst.AvailableVersion}"
                : "to the latest version";
            var confirm = await CopyableMessageBox.ShowAsync(form,
                $"Update \"{inst.Name}\" {change} using winget?\n\n" +
                "winget will download and install the update silently. Close the program first if it is " +
                "running. A machine-wide package may prompt for administrator rights.",
                "Update with winget", MessageBoxButtons.YesNo, MessageBoxIcon.Warning);
            if (confirm != DialogResult.Yes) return;

            grid?.SetStatus($"Updating \"{inst.Name}\" with winget … (this can take a while)");
            string result = await Task.Run(() => SafetyChecks.WingetUpgrade(inst.WingetId, inst.Name, inst.Source));
            grid?.SetStatus($"winget update finished for \"{inst.Name}\".");

            CopyableMessageBox.Show(form, result, $"winget update - {inst.Name}",
                MessageBoxButtons.OK, MessageBoxIcon.Information);

            if (grid != null) await grid.RunAsync();   // refresh Version / Available columns
        }

        /// <summary>Queries `winget show` for the program (off the UI thread) and presents the
        /// details in a selectable, non-blocking dialog.</summary>
        private static async void ShowWingetInfo(Control owner, InstalledProgram inst)
        {
            var grid = owner as SortableGrid;
            grid?.SetStatus($"Querying winget for \"{inst.Name}\" …");
            string text = await Task.Run(() => SafetyChecks.WingetShow(inst.WingetId, inst.Name, inst.Source));
            grid?.SetStatus($"winget info shown for \"{inst.Name}\".");
            CopyableMessageBox.Show(owner.FindForm(), text, $"winget info - {inst.Name}",
                MessageBoxButtons.OK, MessageBoxIcon.Information);
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

        // ---- Windows Security: deep-link shortcuts ----------------------- //
        // The windowsdefender: protocol pages, previously buttons in the left panel; now a
        // section view under the Tools category. Each button opens its Windows Security page.
        private static readonly (string Label, string Uri)[] SecurityShortcuts =
        {
            ("Virus & threat protection",      "windowsdefender://threat"),
            ("Account protection",             "windowsdefender://account"),
            ("Firewall & network protection",  "windowsdefender://network"),
            ("App & browser control",          "windowsdefender://appbrowser"),
            ("Device security",                "windowsdefender://devicesecurity"),
            ("Device performance & health",    "windowsdefender://devicehealth"),
            ("Windows Security (home)",         "windowsdefender://"),
        };

        public static Control BuildSecurityLinks()
        {
            var host = new Panel { Dock = DockStyle.Fill, BackColor = Theme.Surface };

            var bar = new Panel { Dock = DockStyle.Top, Height = 40, BackColor = Theme.Toolbar };
            var title = new Label
            {
                Text = "  Windows Security shortcuts", AutoSize = true, Top = 10, Left = 8,
                Font = new Font("Segoe UI", 10f, FontStyle.Bold), ForeColor = Theme.Text,
            };
            bar.Controls.Add(title);
            Theme.Changed += () => { if (bar.IsHandleCreated) bar.BeginInvoke(new Action(() => { bar.BackColor = Theme.Toolbar; title.ForeColor = Theme.Text; })); };

            var flow = new FlowLayoutPanel
            {
                Dock = DockStyle.Fill,
                FlowDirection = FlowDirection.TopDown,
                WrapContents = false,
                AutoScroll = true,
                Padding = new Padding(14, 12, 14, 12),
                BackColor = Theme.Surface,
            };
            foreach (var (label, uri) in SecurityShortcuts)
            {
                var b = new Button
                {
                    Text = label,
                    Width = 280,
                    Height = 40,
                    TextAlign = ContentAlignment.MiddleLeft,
                    FlatStyle = FlatStyle.System,
                    Margin = new Padding(0, 0, 0, 8),
                    Tag = uri,
                };
                b.Click += (s, _) =>
                {
                    try { Process.Start(new ProcessStartInfo((string)((Button)s!).Tag!) { UseShellExecute = true }); }
                    catch { }
                };
                flow.Controls.Add(b);
            }
            Theme.Changed += () => { if (flow.IsHandleCreated) flow.BeginInvoke(new Action(() => flow.BackColor = Theme.Surface)); };

            host.Controls.Add(flow);   // Fill first ...
            host.Controls.Add(bar);    // ... then Top bar
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
                riskRow: o => o is ProcessItem p && Sev.FromDays(p.DaysOld) >= TabSeverity.Caution,
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
                riskRow: o => o is DeviceDriver d && (Sev.FromDays(d.DaysOld) >= TabSeverity.Caution || !d.Signed || (d.Inf?.Risk ?? TabSeverity.None) >= TabSeverity.Caution),
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
            CopyableMessageBox.Show(owner.FindForm(), sb.ToString(), $"INF analysis - {a.RiskLabel}",
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
                extraButtons: new (string, Action)[] { (RemoveExtBtnLabel, () => RemoveUnsupportedExtensions(grid)) },
                help: TabHelp.Chrome,
                riskRow: o => o is ChromeExtension x && (Sev.FromDays(x.DaysOld) >= TabSeverity.Caution || x.Unsupported),
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

        // ---- Settings (Chrome settings matrix: settings x profiles) ------ //
        public static Control BuildSettings()
        {
            // Columns are discovered once, synchronously, at construction (a cheap profile scan -
            // no database reads). The grid is fixed thereafter; a profile added while the app runs
            // won't get a column until restart (the loader can refresh row data, not columns).
            var matrixCols = SafetyChecks.GetChromeSettingColumns();

            var cols = new List<GridColumn>
            {
                new GridColumn { Header = "Category", Width = 150,
                    Text = o => ((SettingRow)o).Category,
                    Sort = o => SettingSortKey((SettingRow)o) },
                new GridColumn { Header = "Setting", Width = 190,
                    Text = o => ((SettingRow)o).Label,
                    Sort = o => SettingSortKey((SettingRow)o) },
            };
            foreach (var col in matrixCols)
            {
                string key = col.Key;   // capture per column for the cell accessors
                cols.Add(new GridColumn
                {
                    Header = col.Header,
                    Width = col.IsGlobal ? 120 : 130,
                    Text = o => ((SettingRow)o).Values.TryGetValue(key, out var v) ? v : "—",
                    Style = o => SeverityStyle(((SettingRow)o).Risk.TryGetValue(key, out var r) ? r : TabSeverity.None),
                });
            }

            // Last column: the chrome:// deep-link that opens Chrome to this setting's page.
            // Clicking it launches chrome.exe and copies the URL (the grid's link handler
            // routes chrome:// URIs through the same path the left-panel deep-links use).
            cols.Add(new GridColumn
            {
                Header = "Open in Chrome", Width = 230, Link = true,
                Text = o => ((SettingRow)o).Link,
                Sort = o => ((SettingRow)o).Link,
            });

            SortableGrid grid = null!;
            grid = new SortableGrid("Refresh",
                () => SafetyChecks.GetChromeSettings().Rows.Cast<object>().ToList(),
                cols.ToArray(), defaultSortColumn: 1, defaultAscending: true,   // grouped by category
                help: TabHelp.Settings,
                riskRow: o => o is SettingRow r && r.Risk.Values.Any(v => v >= TabSeverity.Caution),
                summary: () =>
                {
                    int profiles = SafetyChecks.GetChromeSettingColumns().Count(c => !c.IsGlobal);
                    return profiles > 0 ? $"{profiles} profile(s)" : "no Chrome profiles";
                },
                severity: items =>
                {
                    var s = TabSeverity.None;
                    foreach (var o in items)
                        if (o is SettingRow r)
                            foreach (var v in r.Risk.Values) s = Sev.Max(s, v);
                    return s;
                },
                onRowContext: o => ShowSettingsMenu(grid, (SettingRow)o));
            return grid;
        }

        /// <summary>Right-click menu for a Settings-tab row: explain the setting (offline doc + web
        /// search), copy its chrome:// link, and open / locate the profile JSON files that back it.</summary>
        private static void ShowSettingsMenu(Control owner, SettingRow row)
        {
            var menu = new ContextMenuStrip();

            menu.Items.Add($"Explain “{row.Label}”…", null,
                (_, _) => HelpUi.Show(owner.FindForm(), SettingsInfo.Help, anchor: row.Label));
            menu.Items.Add($"Search the web for “{row.Label}”", null,
                (_, _) => OpenBrowser("https://www.google.com/search?q=" +
                                      HttpUtility.UrlEncode("Chrome setting " + row.Label)));

            if (row.Link.Length > 0)
            {
                menu.Items.Add(new ToolStripSeparator());
                menu.Items.Add($"Copy link  ({row.Link})", null,
                    (_, _) => { try { Clipboard.SetText(row.Link); } catch { } });
            }

            // The backing files: every profile's Preferences / Secure Preferences JSON (the same
            // files hold every setting row). One submenu per profile so multiple profiles stay tidy.
            var profiles = SafetyChecks.GetChromeProfileDirs();
            if (profiles.Count > 0)
            {
                menu.Items.Add(new ToolStripSeparator());
                var filesHeader = new ToolStripMenuItem("Open settings file") { Enabled = false };
                menu.Items.Add(filesHeader);
                foreach (var (header, dir) in profiles)
                    menu.Items.Add(BuildProfileFilesSubmenu(owner, header, dir));
            }

            menu.Show(Cursor.Position);
        }

        /// <summary>A per-profile submenu: open either JSON file in Notepad (they are extension-less,
        /// so Notepad is the reliable way to view them), open the folder, or copy its path.</summary>
        private static ToolStripMenuItem BuildProfileFilesSubmenu(Control owner, string header, string dir)
        {
            string prefs = Path.Combine(dir, "Preferences");
            string secure = Path.Combine(dir, "Secure Preferences");
            var sub = new ToolStripMenuItem(header);

            var openPrefs = new ToolStripMenuItem("Open Preferences (Notepad)", null,
                (_, _) => OpenInNotepad(owner, prefs)) { Enabled = File.Exists(prefs) };
            var openSecure = new ToolStripMenuItem("Open Secure Preferences (Notepad)", null,
                (_, _) => OpenInNotepad(owner, secure)) { Enabled = File.Exists(secure) };
            sub.DropDownItems.Add(openPrefs);
            sub.DropDownItems.Add(openSecure);
            sub.DropDownItems.Add(new ToolStripSeparator());
            sub.DropDownItems.Add("Open profile folder", null,
                (_, _) => OpenLocation(owner, File.Exists(prefs) ? prefs : "", dir));
            sub.DropDownItems.Add("Copy folder path", null,
                (_, _) => { try { Clipboard.SetText(dir); } catch { } });
            return sub;
        }

        /// <summary>Opens a (typically extension-less Chrome JSON) file in Notepad. Shell-opening these
        /// files would prompt "how do you want to open" because they have no extension, so go straight
        /// to Notepad, which renders the JSON as plain text.</summary>
        private static void OpenInNotepad(Control owner, string path)
        {
            try { Process.Start(new ProcessStartInfo("notepad.exe", $"\"{path}\"") { UseShellExecute = true }); }
            catch (Exception ex)
            {
                CopyableMessageBox.Show(owner.FindForm(), $"Could not open '{path}': {ex.Message}",
                    "Chrome Settings", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
        }

        /// <summary>Composite sort key so the default sort groups rows by category, then setting.</summary>
        private static string SettingSortKey(SettingRow r) => $"{r.CategoryOrder:D4}{r.Label}";

        /// <summary>Maps a per-cell severity to a grid cell colour (red alert / yellow caution).</summary>
        private static (Color Back, Color Fore)? SeverityStyle(TabSeverity s) => s switch
        {
            TabSeverity.Alert => (RedBack, RedFore),
            TabSeverity.Caution => (YelBack, YelFore),
            _ => null,
        };

        private const string RemoveExtBtnLabel = "Remove unsupported";

        /// <summary>
        /// Backs up every Chrome extension to a zip in Downloads, then (after confirmation)
        /// deletes the folders of all Manifest-V2 "Unsupported" extensions. Backup is best-effort;
        /// if it fails the user is asked whether to proceed without one.
        /// The Remove button is disabled for the whole run (re-enabled in the finally) so a
        /// second removal can't be started while this one - including its modeless prompts - is pending.
        /// </summary>
        private static async void RemoveUnsupportedExtensions(SortableGrid grid)
        {
            var form = grid.FindForm();
            grid.SetExtraButtonEnabled(RemoveExtBtnLabel, false);
            try
            {
                // Chrome's per-profile extension folders are read/write protected to an
                // unelevated process on some systems, so both the backup and the deletion
                // fail with "access denied". Require admin up front and point at the relaunch.
                if (!Elevation.IsAdmin)
                {
                    CopyableMessageBox.Show(form,
                        "Removing Chrome extensions requires administrator rights.\n\n" +
                        "Chrome's extension folders are protected, so without elevation the backup " +
                        "and the deletion both fail with \"access denied\".\n\n" +
                        "Click the \"Run as Admin\" button in the left side toolbar, then run Remove again.",
                        "Administrator required", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                var all = await Task.Run(() => SafetyChecks.GetChromeExtensions());
                var unsupported = all.Where(e => e.Unsupported).ToList();
                if (unsupported.Count == 0)
                {
                    CopyableMessageBox.Show(form, "No unsupported (Manifest V2) extensions were found.",
                        "Remove unsupported extensions", MessageBoxButtons.OK, MessageBoxIcon.Information);
                    return;
                }

                string list = string.Join("\n", unsupported.Take(20)
                    .Select(e => $"   - {e.Name}  (v{e.Version})  [{e.ProfileName}]"));
                if (unsupported.Count > 20) list += $"\n   ...and {unsupported.Count - 20} more";

                string prompt =
                    $"Remove {unsupported.Count} unsupported extension(s)?\n\n{list}\n\n" +
                    $"First, all {all.Count} extension(s) will be backed up to:\n" +
                    "   Downloads\\b4browse-extension-backup.zip\n\n" +
                    "Close Chrome first for a clean removal. This permanently deletes the extension folders.";
                if (await CopyableMessageBox.ShowAsync(form, prompt, "Remove unsupported extensions",
                        MessageBoxButtons.YesNo, MessageBoxIcon.Warning) != DialogResult.Yes)
                    return;

                // 1) Backup (best-effort).
                grid.SetStatus("Backing up extensions ...");
                var (zipPath, zipCount, backupErr) = await Task.Run(() => SafetyChecks.BackupExtensions(all));

                if (backupErr != null)
                {
                    var choice = await CopyableMessageBox.ShowAsync(form,
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

                CopyableMessageBox.Show(form, summary, "Remove unsupported extensions",
                    MessageBoxButtons.OK, failed > 0 ? MessageBoxIcon.Warning : MessageBoxIcon.Information);

                await grid.RunAsync();
            }
            finally
            {
                grid.SetExtraButtonEnabled(RemoveExtBtnLabel, true);
            }
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
                riskRow: o => o is ServiceInfo s && Sev.FromDays(s.DaysOld) >= TabSeverity.Caution,
                severity: items => WorstDays(items, o => (o as ServiceInfo)?.DaysOld),
                onRowContext: o => ShowServiceMenu(grid, (ServiceInfo)o),
                showAllToggle: ("All",
                    "Off: hide recent C:\\Windows\\system32 services to reduce noise.  On: show every installed service.",
                    o =>
                {
                    var s = (ServiceInfo)o;
                    string path = s.ExePath.Length > 0 ? s.ExePath : s.PathRaw;
                    bool system32 = path.IndexOf(@"C:\WINDOWS\system32", StringComparison.OrdinalIgnoreCase) >= 0;
                    bool old = s.DaysOld is >= 30;   // "Old" per the recency rules
                    return system32 && !old;         // hidden when the All toggle is off
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
                CopyableMessageBox.Show(owner.FindForm(), "Could not open Services console: " + ex.Message,
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
                    CopyableMessageBox.Show(owner.FindForm(), "The service's folder could not be located.",
                        "Services", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            catch (Exception ex)
            {
                CopyableMessageBox.Show(owner.FindForm(), "Could not open the folder: " + ex.Message,
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
                riskRow: o => o is StartupItem s && Sev.FromDays(s.DaysOld) >= TabSeverity.Caution,
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
                    CopyableMessageBox.Show(owner.FindForm(), "The file location could not be determined.",
                        "Startup", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            catch (Exception ex)
            {
                CopyableMessageBox.Show(owner.FindForm(), "Could not open location: " + ex.Message,
                    "Startup", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
        }

        private static void StartShell(Control owner, string target)
        {
            try { Process.Start(new ProcessStartInfo(target) { UseShellExecute = true }); }
            catch (Exception ex)
            {
                CopyableMessageBox.Show(owner.FindForm(), $"Could not open '{target}': {ex.Message}",
                    "Startup", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
        }

        // ---- Scheduled: Windows Task Scheduler entries ------------------- //
        public static Control BuildScheduled()
        {
            SortableGrid grid = null!;
            var cols = new[]
            {
                new GridColumn { Header = "Status", Width = 70,
                    Text = o => ScheduledStatusLabel((ScheduledTaskItem)o),
                    Sort = o => (int)((ScheduledTaskItem)o).Risk,
                    Style = o => ScheduledStyle((ScheduledTaskItem)o) },
                new GridColumn { Header = "Enabled", Width = 76,
                    Text = o => ((ScheduledTaskItem)o).Enabled ? "Enabled" : "Disabled",
                    Sort = o => ((ScheduledTaskItem)o).Enabled ? 1 : 0,
                    Style = o => ((ScheduledTaskItem)o).Enabled ? null : ((Color, Color)?)(DisBack, DisFore) },
                new GridColumn { Header = "Scan", Width = 64, Button = true, ButtonText = "Scan" },
                new GridColumn { Header = "Created", Width = 92,
                    Text = o => ((ScheduledTaskItem)o).CreatedText,
                    Sort = o => ((ScheduledTaskItem)o).StatusSort,
                    Style = o => RecencyStyle(((ScheduledTaskItem)o).DaysOld) },
                new GridColumn { Header = "Last run", Width = 118,
                    Text = o => ((ScheduledTaskItem)o).LastRunText,
                    Sort = o => ((ScheduledTaskItem)o).LastRun ?? DateTime.MinValue },
                new GridColumn { Header = "Next run", Width = 118,
                    Text = o => ((ScheduledTaskItem)o).NextRunText,
                    Sort = o => ((ScheduledTaskItem)o).NextRun ?? DateTime.MinValue },
                new GridColumn { Header = "Repeat", Width = 64,
                    Text = o => ((ScheduledTaskItem)o).RepeatText,
                    Sort = o => ((ScheduledTaskItem)o).RepeatMinutes },
                new GridColumn { Header = "Run as", Width = 120,
                    Text = o => ((ScheduledTaskItem)o).RunAs,
                    FilterKind = ColumnFilterKind.Dropdown },
                new GridColumn { Header = "Task", Fill = 150,
                    Text = o => ((ScheduledTaskItem)o).Name,
                    FilterKind = ColumnFilterKind.Regex },
                new GridColumn { Header = "Program", Fill = 200,
                    Text = o => { var t = (ScheduledTaskItem)o; return t.Arguments.Length > 0 ? t.Execute + " " + t.Arguments : t.Execute; },
                    FilterKind = ColumnFilterKind.Regex },
                new GridColumn { Header = "Path", Fill = 130,
                    Text = o => ((ScheduledTaskItem)o).TaskPath,
                    FilterKind = ColumnFilterKind.Regex },
            };

            grid = new SortableGrid("Refresh",
                () => SafetyChecks.GetScheduledTasks().Cast<object>().ToList(),
                cols, defaultSortColumn: 0, defaultAscending: false,   // flagged tasks float to the top
                onButtonClick: o => { var t = (ScheduledTaskItem)o; ShowScanMenu(grid, t.Name, () => ExistingPath(t.ExePath)); },
                extraButtons: new (string, Action)[] { ("Open Task Scheduler", () => StartShell(grid, "taskschd.msc")) },
                help: TabHelp.Scheduled,
                riskRow: o => o is ScheduledTaskItem t && Sev.Max(t.Risk, Sev.FromDays(t.DaysOld)) >= TabSeverity.Caution,
                severity: items =>
                {
                    var tasks = items.OfType<ScheduledTaskItem>().ToList();
                    var worst = TabSeverity.None;
                    int alert = 0, review = 0, recent = 0;
                    foreach (var t in tasks)
                    {
                        worst = Sev.Max(worst, Sev.Max(t.Risk, Sev.FromDays(t.DaysOld)));
                        if (t.Risk == TabSeverity.Alert) alert++;
                        else if (t.Risk == TabSeverity.Caution) review++;
                        if (t.Risk < TabSeverity.Caution && t.DaysOld is int d && d < 30) recent++;
                    }
                    grid.SetStatus($"{tasks.Count} task(s)  -  {alert} alert, {review} review, {recent} new (30d)");
                    return worst;
                },
                showAllToggle: ("All",
                    "Off: hide disabled tasks and Windows' own built-in tasks (\\Microsoft\\Windows\\) that aren't flagged.  On: show every task.",
                    o =>
                    {
                        var t = (ScheduledTaskItem)o;
                        if (!t.Enabled) return true;   // hide disabled tasks when "All" is off
                        bool builtin = t.TaskPath.StartsWith(@"\Microsoft\", StringComparison.OrdinalIgnoreCase);
                        return builtin && t.Risk < TabSeverity.Caution;   // and non-flagged Windows built-ins
                    }),
                onRowContext: o => ShowScheduledMenu(grid, (ScheduledTaskItem)o));
            return grid;
        }

        private static string ScheduledStatusLabel(ScheduledTaskItem t) => t.Risk switch
        {
            TabSeverity.Alert => "Alert",
            TabSeverity.Caution => "Review",
            _ => "OK",
        };
        private static (Color Back, Color Fore)? ScheduledStyle(ScheduledTaskItem t) => t.Risk switch
        {
            TabSeverity.Alert => (RedBack, RedFore),
            TabSeverity.Caution => (YelBack, YelFore),
            _ => null,
        };

        private static void ShowScheduledMenu(SortableGrid grid, ScheduledTaskItem t)
        {
            bool hasExe = t.ExePath.Length > 0 && t.ExePath.IndexOf('\\') >= 0;
            var menu = new ContextMenuStrip();
            menu.Items.Add("Copy task name", null, (_, _) => { try { Clipboard.SetText(t.FullName); } catch { } });
            menu.Items.Add("Copy program path", null, (_, _) => { try { Clipboard.SetText(t.Execute); } catch { } })
                .Enabled = t.Execute.Length > 0;
            menu.Items.Add("Open file location", null,
                (_, _) => OpenLocation(grid, t.ExePath, Path.GetDirectoryName(t.ExePath) ?? ""))
                .Enabled = hasExe && File.Exists(t.ExePath);
            if (t.Note.Length > 0)
                menu.Items.Add("Copy audit note", null, (_, _) => { try { Clipboard.SetText(t.Note); } catch { } });
            menu.Items.Add(new ToolStripSeparator());
            // taskschd.msc can't be navigated to a specific task from the command line, so this
            // shows the same Properties-level detail (schtasks /v) for the right-clicked task.
            menu.Items.Add("Show task details (Properties)", null,
                async (_, _) => await ShowScheduledDetailsAsync(grid, t));
            menu.Items.Add("Search web for program", null, (_, _) =>
            {
                string term = hasExe ? Path.GetFileName(t.ExePath) : t.Name;
                string q = HttpUtility.UrlEncode(term + " scheduled task");
                OpenBrowser($"https://www.google.com/search?q={q}");
            });
            menu.Items.Add(new ToolStripSeparator());
            // Toggling state writes to the system, so it is offered only when elevated (the
            // spawned PowerShell inherits this process's rights). Otherwise show why it's greyed.
            if (Elevation.IsAdmin)
                menu.Items.Add(t.Enabled ? "Disable task" : "Enable task", null,
                    (_, _) => _ = ToggleScheduledTask(grid, t));
            else
                menu.Items.Add("Enable / disable task (run app as admin)", null, null).Enabled = false;
            menu.Items.Add(new ToolStripSeparator());
            menu.Items.Add("Open Task Scheduler (taskschd.msc)", null, (_, _) => StartShell(grid, "taskschd.msc"));
            menu.Show(Cursor.Position);
        }

        private static async Task ToggleScheduledTask(SortableGrid grid, ScheduledTaskItem t)
        {
            bool enable = !t.Enabled;
            string action = enable ? "Enable" : "Disable";

            var confirm = CopyableMessageBox.Show(grid.FindForm(),
                $"{action} this scheduled task?\n\n{t.FullName}\n\nProgram: {(t.Execute.Length > 0 ? t.Execute : "(none)")}\nRuns as: {t.RunAs}",
                $"{action} scheduled task", MessageBoxButtons.YesNo, MessageBoxIcon.Question);
            if (confirm != DialogResult.Yes) return;

            grid.SetStatus($"{action} task: {t.Name} …");
            var (ok, msg) = await Task.Run(() => SafetyChecks.SetScheduledTaskState(t.TaskPath, t.Name, enable));
            await grid.RunAsync();   // reload so the Enabled/Status columns reflect the change
            grid.SetStatus(msg);
            if (!ok)
                CopyableMessageBox.Show(grid.FindForm(), msg,
                    $"{action} task failed", MessageBoxButtons.OK, MessageBoxIcon.Warning);
        }

        private static async Task ShowScheduledDetailsAsync(Control owner, ScheduledTaskItem t)
        {
            string output = await Task.Run(() => SafetyChecks.GetScheduledTaskDetails(t.FullName));
            try
            {
                if (owner?.FindForm() is Form parent)
                {
                    var dlg = new Form
                    {
                        Text = $"Task details - {t.Name}",
                        Size = new Size(820, 560),
                        StartPosition = FormStartPosition.CenterParent,
                    };
                    var tb = new TextBox
                    {
                        Multiline = true, ReadOnly = true, WordWrap = false,
                        ScrollBars = ScrollBars.Both, Dock = DockStyle.Fill,
                        Font = new Font("Consolas", 9f), Text = output,
                    };
                    dlg.Controls.Add(tb);
                    dlg.ShowDialog(parent);
                }
                else
                {
                    CopyableMessageBox.Show(output, $"Task details - {t.Name}", MessageBoxButtons.OK, MessageBoxIcon.Information);
                }
            }
            catch { try { CopyableMessageBox.Show(output, $"Task details - {t.Name}", MessageBoxButtons.OK, MessageBoxIcon.Information); } catch { } }
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
                riskRow: o => o is EventItem e && EventIsRisk(e),
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
                new GridColumn { Header = "Woke by", Width = 170,
                    Text = o => ((AwakePeriod)o).Why,
                    FilterKind = ColumnFilterKind.Regex },
                new GridColumn { Header = "End", Width = 130,
                    Text = o => ((AwakePeriod)o).EndText,
                    Sort = o => ((AwakePeriod)o).EndSort,
                    Style = o => AwakeRowStyle((AwakePeriod)o) },
                new GridColumn { Header = "Ended", Width = 130,
                    Text = o => ((AwakePeriod)o).EndModeText,
                    Sort = o => ((AwakePeriod)o).EndCode,
                    Style = o => AwakeRowStyle((AwakePeriod)o),
                    FilterKind = ColumnFilterKind.Regex },
                new GridColumn { Header = "Duration", Width = 96,
                    Text = o => ((AwakePeriod)o).DurationText,
                    Sort = o => ((AwakePeriod)o).DurationMin },
            };
            return new SortableGrid("Refresh",
                () => SafetyChecks.GetAwakePeriods().Cast<object>().ToList(),
                cols, defaultSortColumn: 1, defaultAscending: false,   // newest first
                extraButtons: new (string, Action)[] { ("Event Viewer", OpenEventViewer) },
                help: TabHelp.Awake,
                riskRow: o => o is AwakePeriod p && p.Unexpected,
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

        // ---- Activity: Windows Search app-launch index ------------------- //
        public static Control BuildActivity()
        {
            SortableGrid grid = null!;
            var cols = new[]
            {
                new GridColumn { Header = "Status", Width = 80,
                    Text = o => ((AppActivity)o).Risk >= TabSeverity.Caution ? "Review" : "OK",
                    Sort = o => (int)((AppActivity)o).Risk,
                    Style = o => ((AppActivity)o).Risk >= TabSeverity.Caution ? ((Color, Color)?)(YelBack, YelFore) : null },
                new GridColumn { Header = "Launches", Width = 84,
                    Text = o => ((AppActivity)o).LaunchCount.ToString("N0"),
                    Sort = o => ((AppActivity)o).LaunchCount },
                new GridColumn { Header = "When", Width = 130,
                    Text = o => ((AppActivity)o).LastExecutedText,
                    Sort = o => ((AppActivity)o).LastExecuted ?? DateTime.MinValue },
                new GridColumn { Header = "Type", Width = 96,
                    Text = o => ((AppActivity)o).Kind,
                    FilterKind = ColumnFilterKind.Dropdown },
                new GridColumn { Header = "Rank", Width = 70,
                    Text = o => ((AppActivity)o).RankText,
                    Sort = o => ((AppActivity)o).CRank },
                new GridColumn { Header = "App name", Fill = 140, Text = o => ((AppActivity)o).DisplayName },
                new GridColumn { Header = "App ID / path", Fill = 200,
                    Text = o => ActivityPathText((AppActivity)o),
                    FilterKind = ColumnFilterKind.Regex },
            };

            grid = new SortableGrid("Refresh",
                () => SafetyChecks.GetAppActivity().Cast<object>().ToList(),
                cols, defaultSortColumn: 1, defaultAscending: false,   // most-launched first
                help: TabHelp.Activity,
                riskRow: o => o is AppActivity a && a.Risk >= TabSeverity.Caution,
                summary: () =>
                {
                    var items = SafetyChecks.GetAppActivity();
                    int flagged = items.Count(a => a.Risk >= TabSeverity.Caution);
                    if (flagged > 0) return $"{flagged} launched from Temp/Downloads";
                    return items.Count > 0 ? $"top: {items[0].DisplayName} ({items[0].LaunchCount:N0})" : "no data";
                },
                severity: items =>
                {
                    var s = TabSeverity.None;
                    foreach (var o in items)
                        if (o is AppActivity a) s = Sev.Max(s, a.Risk);
                    return s;
                },
                onRowContext: o => ShowActivityMenu(grid, (AppActivity)o));
            return grid;
        }

        // Prefer the resolved on-disk path; fall back to the raw appId for identifier-only tiles.
        private static string ActivityPathText(AppActivity a)
            => a.ResolvedPath.Length > 0 ? a.ResolvedPath : a.AppId;

        private static void ShowActivityMenu(Control owner, AppActivity a)
        {
            string path = ActivityPathText(a);
            bool hasFile = a.ResolvedPath.Length > 0 && File.Exists(a.ResolvedPath);

            var menu = new ContextMenuStrip();
            menu.Items.Add("Open file location", null,
                (_, _) => OpenLocation(owner, a.ResolvedPath, Path.GetDirectoryName(a.ResolvedPath) ?? ""))
                .Enabled = hasFile;
            menu.Items.Add("Copy app name", null, (_, _) => { try { Clipboard.SetText(a.DisplayName); } catch { } });
            menu.Items.Add("Copy app ID / path", null, (_, _) => { try { Clipboard.SetText(path); } catch { } });
            menu.Items.Add("Copy launch count", null, (_, _) => { try { Clipboard.SetText(a.LaunchCount.ToString()); } catch { } });
            menu.Items.Add("Copy last-run time", null, (_, _) => { try { Clipboard.SetText(a.LastExecutedText); } catch { } })
                .Enabled = a.LastExecuted.HasValue;
            menu.Items.Add(new ToolStripSeparator());
            menu.Items.Add("Search the web for this app", null, (_, _) =>
                OpenBrowser("https://www.google.com/search?q=" + HttpUtility.UrlEncode(a.DisplayName)));
            menu.Show(Cursor.Position);
        }

        // ---- Downloads (SRUM per-app network usage) ---------------------- //
        public static Control BuildDownloads()
        {
            SortableGrid grid = null!;
            var cols = new[]
            {
                new GridColumn { Header = "Status", Width = 80,
                    Text = o => ((SruNetUsage)o).Risk >= TabSeverity.Caution ? "Review" : "OK",
                    Sort = o => (int)((SruNetUsage)o).Risk,
                    Style = o => ((SruNetUsage)o).Risk >= TabSeverity.Caution ? ((Color, Color)?)(YelBack, YelFore) : null },
                new GridColumn { Header = "Downloaded", Width = 110,
                    Text = o => SafetyChecks.FormatBytes(((SruNetUsage)o).BytesRecvd),
                    Sort = o => ((SruNetUsage)o).BytesRecvd },
                new GridColumn { Header = "Uploaded", Width = 110,
                    Text = o => SafetyChecks.FormatBytes(((SruNetUsage)o).BytesSent),
                    Sort = o => ((SruNetUsage)o).BytesSent },
                new GridColumn { Header = "Last seen", Width = 130,
                    Text = o => ((SruNetUsage)o).LastSeenText,
                    Sort = o => ((SruNetUsage)o).LastSeen ?? DateTime.MinValue },
                new GridColumn { Header = "App name", Fill = 140, Text = o => ((SruNetUsage)o).AppName },
                new GridColumn { Header = "App path", Fill = 220,
                    Text = o => ((SruNetUsage)o).AppPath,
                    FilterKind = ColumnFilterKind.Regex },
            };

            grid = new SortableGrid("Refresh",
                () => SafetyChecks.GetDownloadUsage().Cast<object>().ToList(),
                cols, defaultSortColumn: 1, defaultAscending: false,   // heaviest download first
                help: TabHelp.Downloads,
                riskRow: o => o is SruNetUsage u && u.Risk >= TabSeverity.Caution,
                summary: () =>
                {
                    var items = SafetyChecks.GetDownloadUsage();
                    if (items.Count == 0) return SafetyChecks.SruStatus;
                    int flagged = items.Count(u => u.Risk >= TabSeverity.Caution);
                    if (flagged > 0) return $"{flagged} from a transient folder";
                    return $"top: {items[0].AppName} ({SafetyChecks.FormatBytes(items[0].BytesRecvd)} down)";
                },
                severity: items =>
                {
                    var s = TabSeverity.None;
                    foreach (var o in items)
                        if (o is SruNetUsage u) s = Sev.Max(s, u.Risk);
                    return s;
                },
                onRowContext: o => ShowDownloadsMenu(grid, (SruNetUsage)o));
            return grid;
        }

        private static void ShowDownloadsMenu(Control owner, SruNetUsage u)
        {
            bool hasFile = u.AppPath.Length > 0 && File.Exists(u.AppPath);

            var menu = new ContextMenuStrip();
            menu.Items.Add("Show details…", null, (_, _) => ShowDownloadDetails(owner, u));
            menu.Items.Add(new ToolStripSeparator());
            menu.Items.Add("Open file location", null,
                (_, _) => OpenLocation(owner, u.AppPath, Path.GetDirectoryName(u.AppPath) ?? ""))
                .Enabled = hasFile;
            menu.Items.Add("Copy app name", null, (_, _) => { try { Clipboard.SetText(u.AppName); } catch { } });
            menu.Items.Add("Copy app path", null, (_, _) => { try { Clipboard.SetText(u.AppPath); } catch { } });
            menu.Items.Add("Copy usage (down / up)", null, (_, _) =>
            {
                try { Clipboard.SetText($"down {SafetyChecks.FormatBytes(u.BytesRecvd)} / up {SafetyChecks.FormatBytes(u.BytesSent)}"); }
                catch { }
            });
            menu.Items.Add(new ToolStripSeparator());
            menu.Items.Add("Search the web for this app", null, (_, _) =>
                OpenBrowser("https://www.google.com/search?q=" + HttpUtility.UrlEncode(u.AppName)));
            menu.Show(Cursor.Position);
        }

        /// <summary>
        /// "Show details" for a Downloads row: classify the raw SRUM identity (which is often not a
        /// friendly name - it can be a full exe path, a Windows background-task tag, or a user SID)
        /// and, for an executable that still exists on disk, enrich it with the file's version
        /// metadata and Authenticode signature (read off the UI thread).
        /// </summary>
        private static async void ShowDownloadDetails(Control owner, SruNetUsage u)
        {
            var grid = owner as SortableGrid;
            string kind = ClassifySruIdentity(u.AppPath, out string explain);

            var sb = new StringBuilder();
            sb.AppendLine(u.AppName.Length > 0 ? u.AppName : "(unnamed)");
            sb.AppendLine();
            sb.AppendLine($"Identity type : {kind}");
            if (explain.Length > 0) sb.AppendLine($"                {explain}");
            sb.AppendLine($"SRUM identity : {u.AppPath}");
            sb.AppendLine();
            sb.AppendLine($"Downloaded    : {SafetyChecks.FormatBytes(u.BytesRecvd)}  ({u.BytesRecvd:N0} bytes)");
            sb.AppendLine($"Uploaded      : {SafetyChecks.FormatBytes(u.BytesSent)}  ({u.BytesSent:N0} bytes)");
            sb.AppendLine($"Last seen     : {u.LastSeenText}");
            if (u.Note.Length > 0) sb.AppendLine($"Note          : {u.Note}");

            // An on-disk executable gets version + signature detail; a path that no longer resolves
            // (or a non-path identity) just says so, rather than guessing.
            string? exe = u.AppPath.Length > 0 && File.Exists(u.AppPath) ? u.AppPath : null;
            if (exe != null)
            {
                grid?.SetStatus($"Reading file details for {u.AppName} …");
                var (verLines, sig) = await Task.Run(() =>
                {
                    string v = DescribeFileVersion(exe);
                    var (status, signer) = SafetyChecks.VerifyAuthenticode(exe);
                    string s = status + (signer.Length > 0 ? $" - {signer.Split(',')[0]}" : "");
                    return (v, s);
                });
                grid?.SetStatus($"Details shown for {u.AppName}.");
                sb.AppendLine();
                sb.AppendLine("On-disk file:");
                sb.AppendLine(verLines);
                sb.AppendLine($"  {"Signature",-11}: {sig}");
            }
            else if (kind is "Executable" or "File path")
            {
                sb.AppendLine();
                sb.AppendLine("On-disk file  : not found at this path - it may have been removed, or this");
                sb.AppendLine("                is a historical SRUM record for a deleted file.");
            }

            CopyableMessageBox.Show(owner.FindForm(), sb.ToString(), $"Download details - {u.AppName}",
                MessageBoxButtons.OK, MessageBoxIcon.Information);
        }

        /// <summary>
        /// Names what a SRUM id-map identity actually is. SRUM stores most rows as a full executable
        /// path, but also keeps Windows background/packaged-app activity tags ("!!"-prefixed), user
        /// rows (a security identifier), and - when an id is missing from the id-map - a synthetic
        /// "(app id N)" placeholder. <paramref name="explain"/> gets a one-line gloss.
        /// </summary>
        private static string ClassifySruIdentity(string appPath, out string explain)
        {
            explain = "";
            string p = (appPath ?? "").Trim();
            if (p.Length == 0) { explain = "SRUM recorded no identity for this row."; return "Unknown"; }
            if (p.StartsWith("(app id", StringComparison.OrdinalIgnoreCase))
            {
                explain = "The app's id was not present in SRUM's id-map, so no name is available.";
                return "Unresolved id";
            }
            if (p.StartsWith("!!", StringComparison.Ordinal))
            {
                explain = "A Windows background / packaged-app activity tag, not a file on disk.";
                return "Windows background task";
            }
            if (p.StartsWith("S-1-", StringComparison.OrdinalIgnoreCase))
            {
                explain = "A user-account security identifier (a SRUM user row, not an application).";
                return "User account (SID)";
            }
            bool rooted = (p.Length > 2 && p[1] == ':' && p[2] == '\\') ||
                          p.StartsWith(@"\\", StringComparison.Ordinal);
            if (rooted && p.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)) return "Executable";
            if (rooted) return "File path";
            return "Identity tag";
        }

        /// <summary>Formats an executable's version-resource metadata (description / product / company /
        /// file version) as indented label lines, omitting any field the file does not carry.</summary>
        private static string DescribeFileVersion(string exe)
        {
            try
            {
                var fi = FileVersionInfo.GetVersionInfo(exe);
                var parts = new List<string>();
                void Add(string label, string? val)
                {
                    if (!string.IsNullOrWhiteSpace(val)) parts.Add($"  {label,-11}: {val.Trim()}");
                }
                Add("Description", fi.FileDescription);
                Add("Product", fi.ProductName);
                Add("Company", fi.CompanyName);
                Add("File ver", fi.FileVersion);
                parts.Add($"  {"Path",-11}: {exe}");
                return string.Join("\n", parts);
            }
            catch { return $"  {"Path",-11}: {exe}"; }
        }

        // ---- Virus (Defender protection state + threat / scan timeline) -- //
        public static Control BuildVirus()
        {
            SortableGrid grid = null!;
            var cols = new[]
            {
                new GridColumn { Header = "Result", Width = 120,
                    Text = o => ((DefenderTimelineRow)o).Result,
                    Sort = o => (int)((DefenderTimelineRow)o).Severity,
                    Style = o => SeverityStyle(((DefenderTimelineRow)o).Severity) },
                new GridColumn { Header = "Time", Width = 130,
                    Text = o => ((DefenderTimelineRow)o).TimeText,
                    Sort = o => ((DefenderTimelineRow)o).TimeSort },
                new GridColumn { Header = "Type", Width = 70,
                    Text = o => ((DefenderTimelineRow)o).KindText,
                    FilterKind = ColumnFilterKind.Dropdown },
                new GridColumn { Header = "Event", Width = 60,
                    Text = o => ((DefenderTimelineRow)o).EventId.ToString(),
                    Sort = o => ((DefenderTimelineRow)o).EventId },
                new GridColumn { Header = "Name", Fill = 150,
                    Text = o => ((DefenderTimelineRow)o).Title,
                    FilterKind = ColumnFilterKind.Regex },
                new GridColumn { Header = "Detail", Fill = 240,
                    Text = o => ((DefenderTimelineRow)o).Detail,
                    FilterKind = ColumnFilterKind.Regex },
            };

            grid = new SortableGrid("Refresh",
                () => SafetyChecks.GetDefenderTimeline().Cast<object>().ToList(),
                cols, defaultSortColumn: 1, defaultAscending: false,   // newest first
                headerInfo: SafetyChecks.VirusHeader,
                help: TabHelp.Virus,
                riskRow: o => o is DefenderTimelineRow r && r.Severity >= TabSeverity.Caution,
                extraButtons: new (string, Action)[] { ("Windows Security", () => StartShell(grid, "windowsdefender:")) },
                summary: () =>
                {
                    if (!Elevation.IsAdmin) return "run as Admin for history";
                    var rows = SafetyChecks.GetDefenderTimeline();
                    int threats = rows.Count(r => ((DefenderTimelineRow)r).Kind == DefenderEventKind.Threat);
                    int scans = rows.Count - threats;
                    return threats > 0 ? $"{threats} threat(s), {scans} scan(s)" : $"no threats, {scans} scan(s)";
                },
                severity: items =>
                {
                    var s = SafetyChecks.DefenderStatusSeverity();   // protection state colours the tab too
                    foreach (var o in items)
                        if (o is DefenderTimelineRow r) s = Sev.Max(s, r.Severity);
                    return s;
                },
                onRowContext: o => ShowVirusMenu(grid, (DefenderTimelineRow)o),
                headerHeight: 172);
            return grid;
        }

        private static void ShowVirusMenu(Control owner, DefenderTimelineRow row)
        {
            var menu = new ContextMenuStrip();

            menu.Items.Add("Show details…", null, (_, _) => ShowVirusDetails(owner, row));
            menu.Items.Add(new ToolStripSeparator());

            if (row.Kind == DefenderEventKind.Threat)
            {
                menu.Items.Add("Copy threat name", null, (_, _) => { try { Clipboard.SetText(row.Title); } catch { } });
                bool hasPath = row.Path.Length > 0;
                menu.Items.Add(new ToolStripMenuItem("Open file location", null,
                    (_, _) => OpenLocation(owner, File.Exists(row.Path) ? row.Path : "",
                                           Path.GetDirectoryName(row.Path) ?? "")) { Enabled = hasPath });
                menu.Items.Add(new ToolStripMenuItem("Copy file path", null,
                    (_, _) => { try { Clipboard.SetText(row.Path); } catch { } }) { Enabled = hasPath });
                menu.Items.Add(new ToolStripSeparator());
                menu.Items.Add("Search the web for this threat", null, (_, _) =>
                    OpenBrowser("https://www.google.com/search?q=" +
                                HttpUtility.UrlEncode(row.Title + " malware")));
                menu.Items.Add(new ToolStripSeparator());
            }

            menu.Items.Add("Copy row", null, (_, _) =>
            {
                try { Clipboard.SetText($"{row.TimeText}\t{row.KindText}\t#{row.EventId}\t{row.Result}\t{row.Title}\t{row.Detail}"); }
                catch { }
            });
            menu.Items.Add("Open Windows Security", null, (_, _) => StartShell(owner, "windowsdefender:"));
            menu.Show(Cursor.Position);
        }

        /// <summary>"Show details" for a Virus-tab row: every Defender timeline field laid out on its
        /// own line, with the raw event id translated to plain English and (for threats) the threat
        /// category surfaced - information the compact grid row merges away.</summary>
        private static void ShowVirusDetails(Control owner, DefenderTimelineRow row)
        {
            var sb = new StringBuilder();
            sb.AppendLine(row.Title.Length > 0 ? row.Title : row.KindText);
            sb.AppendLine();
            sb.AppendLine($"Type      : {row.KindText}");
            sb.AppendLine($"Event id  : {row.EventId}  ({DefenderEventMeaning(row.EventId)})");
            sb.AppendLine($"Result    : {row.Result}");
            sb.AppendLine($"Time      : {row.TimeText}");

            if (row.Kind == DefenderEventKind.Threat)
            {
                sb.AppendLine($"Threat    : {row.Title}");
                if (row.Category.Length > 0) sb.AppendLine($"Category  : {row.Category}");
                if (row.Path.Length > 0) sb.AppendLine($"Location  : {row.Path}");
            }
            else
            {
                sb.AppendLine($"Scan type : {row.Title}");
            }

            if (row.Detail.Length > 0) sb.AppendLine($"Detail    : {row.Detail}");
            sb.AppendLine($"Severity  : {row.Severity}");

            var icon = row.Severity == TabSeverity.Alert ? MessageBoxIcon.Warning
                     : row.Severity == TabSeverity.Caution ? MessageBoxIcon.Exclamation
                     : MessageBoxIcon.Information;
            CopyableMessageBox.Show(owner.FindForm(), sb.ToString(),
                $"Defender event details - {row.KindText}", MessageBoxButtons.OK, icon);
        }

        /// <summary>Plain-English meaning of a Microsoft Defender event id shown in the Virus tab.</summary>
        private static string DefenderEventMeaning(int id) => id switch
        {
            1116 => "Threat detected",
            1117 => "Threat remediated - action succeeded",
            1118 => "Threat remediation failed",
            1119 => "Threat remediation critically failed",
            1000 => "Scan started",
            1001 => "Scan finished",
            1002 => "Scan stopped before completion",
            1005 => "Scan failed",
            _ => "Defender event",
        };

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
                riskRow: o => o is RootCertItem c && c.Severity >= TabSeverity.Caution,
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

        /// <summary>An event "warrants review" (counts toward the nav risk badge) when it is one we
        /// flag as significant, or its level is Critical / Error / Warning - matching <see cref="WorstEvents"/>.</summary>
        private static bool EventIsRisk(EventItem e) =>
            e.Significant
            || e.Level.Equals("Critical", StringComparison.OrdinalIgnoreCase)
            || e.Level.Equals("Error", StringComparison.OrdinalIgnoreCase)
            || e.Level.Equals("Warning", StringComparison.OrdinalIgnoreCase);

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
                    CopyableMessageBox.Show(output, $"Event {e.EventId} details", MessageBoxButtons.OK, MessageBoxIcon.Information);
                }
            }
            catch { try { CopyableMessageBox.Show(output, $"Event {e.EventId} details", MessageBoxButtons.OK, MessageBoxIcon.Information); } catch { } }
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
                riskRow: o => o is DnsCacheEntry e && e.Suspicious,
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
                riskRow: o => o is ArpEntry e && e.Risk >= TabSeverity.Caution,
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
                CopyableMessageBox.Show(owner.FindForm(),
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
                riskRow: o => o is RestorePoint r && r.Risk >= TabSeverity.Caution,
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

        // ---- Users: local user accounts ---------------------------------- //
        public static Control BuildUsers()
        {
            var cols = new[]
            {
                new GridColumn { Header = "Status", Width = 70,
                    Text = o => UserStatusLabel((UserAccount)o),
                    Sort = o => (int)((UserAccount)o).Risk,
                    Style = o => UserStyle((UserAccount)o) },
                new GridColumn { Header = "Account", Width = 150, Text = o => ((UserAccount)o).Name },
                new GridColumn { Header = "Enabled", Width = 70,
                    Text = o => ((UserAccount)o).Enabled ? "Yes" : "No",
                    Sort = o => ((UserAccount)o).Enabled ? 0 : 1,
                    Style = o => ((UserAccount)o).Enabled ? null : ((Color, Color)?)(DisBack, DisFore) },
                new GridColumn { Header = "Admin", Width = 60,
                    Text = o => ((UserAccount)o).IsAdmin ? "Yes" : "",
                    Sort = o => ((UserAccount)o).IsAdmin ? 0 : 1 },
                new GridColumn { Header = "Created", Width = 95,
                    Text = o => ((UserAccount)o).CreatedText,
                    Sort = o => ((UserAccount)o).Created ?? DateTime.MinValue,
                    Style = o => RecencyStyle(((UserAccount)o).DaysOld) },
                new GridColumn { Header = "Created src", Width = 90,
                    Text = o => UserCreatedSrc((UserAccount)o) },
                new GridColumn { Header = "Last logon", Width = 130,
                    Text = o => ((UserAccount)o).LastLogonText,
                    Sort = o => ((UserAccount)o).LastLogon ?? DateTime.MinValue },
                new GridColumn { Header = "Expires", Width = 90,
                    Text = o => ((UserAccount)o).AccountExpiresText,
                    Sort = o => ((UserAccount)o).AccountExpires ?? DateTime.MaxValue },
                new GridColumn { Header = "Source", Width = 110, Text = o => ((UserAccount)o).Source },
                new GridColumn { Header = "Full name", Width = 140, Text = o => ((UserAccount)o).FullName },
                new GridColumn { Header = "Profile path", Fill = 150,
                    Text = o => { var p = ((UserAccount)o).ProfilePath; return p.Length > 0 ? p : "—"; } },
                new GridColumn { Header = "Note", Fill = 180, Text = o => ((UserAccount)o).Note },
            };

            SortableGrid grid = null!;
            grid = new SortableGrid("Refresh",
                () => SafetyChecks.GetUserAccounts().Cast<object>().ToList(),
                cols, defaultSortColumn: 0, defaultAscending: false,
                help: TabHelp.Users,
                riskRow: o => o is UserAccount u && u.Risk >= TabSeverity.Caution,
                headerInfo: SafetyChecks.UsersHeader,
                severity: items =>
                {
                    var s = TabSeverity.Ok;
                    foreach (var o in items)
                        if (o is UserAccount u) s = Sev.Max(s, u.Risk);
                    return s;
                },
                onRowContext: o => ShowUserMenu(grid, (UserAccount)o));
            return grid;
        }

        private static string UserStatusLabel(UserAccount u) => u.Risk switch
        {
            TabSeverity.Alert => "Alert",
            TabSeverity.Caution => "Review",
            _ => "OK",
        };

        private static (Color Back, Color Fore)? UserStyle(UserAccount u) => u.Risk switch
        {
            TabSeverity.Alert => (RedBack, RedFore),
            TabSeverity.Caution => (YelBack, YelFore),
            _ => null,
        };

        private static string UserCreatedSrc(UserAccount u) => u.CreatedSource switch
        {
            "audited" => "audit log",
            "first logon" => "≈first logon",
            _ => "—",
        };

        private static void ShowUserMenu(Control owner, UserAccount u)
        {
            var menu = new ContextMenuStrip();
            menu.Items.Add("Copy account name", null, (_, _) => { try { Clipboard.SetText(u.Name); } catch { } });
            menu.Items.Add("Copy SID", null, (_, _) => { try { Clipboard.SetText(u.Sid); } catch { } })
                .Enabled = u.Sid.Length > 0;
            menu.Items.Add("Copy profile path", null, (_, _) => { try { Clipboard.SetText(u.ProfilePath); } catch { } })
                .Enabled = u.ProfilePath.Length > 0;
            menu.Items.Add(new ToolStripSeparator());
            menu.Items.Add("Open profile folder", null, (_, _) => StartShell(owner, u.ProfilePath))
                .Enabled = u.ProfilePath.Length > 0 && Directory.Exists(u.ProfilePath);
            menu.Items.Add("Open User Accounts (netplwiz)", null, (_, _) => StartShell(owner, "netplwiz.exe"));
            menu.Items.Add("Open Local Users & Groups (lusrmgr.msc)", null, (_, _) => StartShell(owner, "lusrmgr.msc"));
            menu.Items.Add(new ToolStripSeparator());
            menu.Items.Add("Search the web for this account", null, (_, _) =>
                OpenBrowser("https://www.google.com/search?q=" + HttpUtility.UrlEncode(u.Name)));
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
                riskRow: o => o is ShellExtension e && e.Risk >= TabSeverity.Caution,
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
            CopyableMessageBox.Show(grid.FindForm(),
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
            CopyableMessageBox.Show(owner.FindForm(), msg, "Scan", MessageBoxButtons.OK, MessageBoxIcon.Information);

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
