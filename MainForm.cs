using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Windows.Forms;

namespace BrowseSafe
{
    /// <summary>
    /// Main window: an overall-verdict banner, a toolbar, a collapsible left panel
    /// of Windows Security shortcuts, and a tabbed main area where each tab is a
    /// <see cref="ResultsView"/> running its own set of checks.
    /// </summary>
    public sealed class MainForm : Form
    {
        private readonly Label _banner;
        private readonly Button _toggleButton;
        private readonly Button _chromeButton;
        private readonly Button _emailButton;
        private readonly Button _emailMenuButton;
        private readonly AppSettings _settings = AppSettings.Load();
        private readonly Panel _leftPanel;
        private readonly TabControl _tabs;
        private readonly ResultsView _scanView;

        // Windows Security deep-link pages (windowsdefender: protocol).
        private static readonly (string Label, string Uri)[] SecurityShortcuts =
        {
            ("Virus && threat protection",      "windowsdefender://threat"),
            ("Account protection",              "windowsdefender://account"),
            ("Firewall && network protection",  "windowsdefender://network"),
            ("App && browser control",          "windowsdefender://appbrowser"),
            ("Device security",                 "windowsdefender://devicesecurity"),
            ("Device performance && health",    "windowsdefender://devicehealth"),
        };

        public MainForm()
        {
            Text = "Browse Safe - Chrome Safety Check";
            MinimumSize = new Size(880, 600);
            Size = new Size(1000, 740);
            StartPosition = FormStartPosition.CenterScreen;
            Font = new Font("Segoe UI", 9f);
            BackColor = Color.White;

            _banner = new Label
            {
                Dock = DockStyle.Top,
                Height = 50,
                TextAlign = ContentAlignment.MiddleCenter,
                Font = new Font("Segoe UI", 13f, FontStyle.Bold),
                ForeColor = Color.White,
                BackColor = Color.FromArgb(90, 90, 90),
                Text = "Run the Safety Scan to evaluate browsing safety",
            };

            // -- Toolbar --
            var toolbar = new Panel { Dock = DockStyle.Top, Height = 42, BackColor = Color.FromArgb(245, 245, 245) };
            _toggleButton = new Button
            {
                Text = "◀ Hide tools",
                Width = 110,
                Height = 28,
                Left = 8,
                Top = 7,
                FlatStyle = FlatStyle.System,
            };
            _toggleButton.Click += (_, _) => ToggleLeftPanel();

            _chromeButton = new Button
            {
                Text = "Launch Chrome",
                Width = 140,
                Height = 28,
                Left = 126,
                Top = 7,
                FlatStyle = FlatStyle.System,
                Enabled = false,
            };
            _chromeButton.Click += (_, _) => LaunchChrome();

            _emailButton = new Button
            {
                Text = "Email this tab",
                Width = 116,
                Height = 28,
                Left = 274,
                Top = 7,
                FlatStyle = FlatStyle.System,
            };
            _emailButton.Click += (_, _) => EmailCurrentTab();

            _emailMenuButton = new Button
            {
                Text = "▾",
                Width = 26,
                Height = 28,
                Left = 390,
                Top = 7,
                FlatStyle = FlatStyle.System,
            };
            _emailMenuButton.Click += (_, _) => ShowEmailMenu();

            var toolHint = new Label
            {
                AutoSize = true,
                Left = 426,
                Top = 13,
                ForeColor = Color.Gray,
                Text = "Left panel opens Windows Security pages.",
            };
            toolbar.Controls.Add(_toggleButton);
            toolbar.Controls.Add(_chromeButton);
            toolbar.Controls.Add(_emailButton);
            toolbar.Controls.Add(_emailMenuButton);
            toolbar.Controls.Add(toolHint);

            // -- Left panel: Windows Security shortcuts --
            _leftPanel = new Panel { Dock = DockStyle.Left, Width = 230, BackColor = Color.FromArgb(238, 240, 243) };
            var leftHeader = new Label
            {
                Dock = DockStyle.Top,
                Height = 34,
                Text = "  Windows Security",
                TextAlign = ContentAlignment.MiddleLeft,
                Font = new Font("Segoe UI", 10f, FontStyle.Bold),
                ForeColor = Color.FromArgb(40, 40, 40),
            };
            var flow = new FlowLayoutPanel
            {
                Dock = DockStyle.Fill,
                FlowDirection = FlowDirection.TopDown,
                WrapContents = false,
                AutoScroll = true,
                Padding = new Padding(10, 6, 10, 6),
            };
            foreach (var (label, uri) in SecurityShortcuts)
            {
                var b = new Button
                {
                    Text = label,
                    Width = 200,
                    Height = 40,
                    TextAlign = ContentAlignment.MiddleLeft,
                    FlatStyle = FlatStyle.System,
                    Margin = new Padding(0, 0, 0, 8),
                    Tag = uri,
                };
                b.Click += (s, _) => OpenUri((string)((Button)s!).Tag!);
                flow.Controls.Add(b);
            }
            var leftNote = new Label
            {
                AutoSize = false,
                Width = 200,
                Height = 60,
                ForeColor = Color.Gray,
                Font = new Font("Segoe UI", 8f),
                Text = "Opens the Windows Security app to the chosen page.",
                Margin = new Padding(0, 8, 0, 0),
            };
            flow.Controls.Add(leftNote);
            _leftPanel.Controls.Add(flow);
            _leftPanel.Controls.Add(leftHeader);

            // -- Tabs (owner-drawn so they can be colour-coded by worst state) --
            _tabs = new TabControl
            {
                Dock = DockStyle.Fill,
                Font = new Font("Segoe UI", 11.25f),   // ~25% larger than the 9pt default
                DrawMode = TabDrawMode.OwnerDrawFixed,
                SizeMode = TabSizeMode.Normal,
                Padding = new Point(16, 5),
            };
            _tabs.DrawItem += DrawTab;
            _tabs.SelectedIndexChanged += (_, _) => { AutoRunSelectedTab(); UpdateBanner(); _tabs.Invalidate(); };

            _scanView = AddTab("Safety Scan", "scan", "Run Safety Checks",
                "Click to scan.", ScanSteps(), reportVerdict: true);
            _scanView.Completed += OnScanCompleted;

            AddViewTab("Chrome", "chrome", TabViews.BuildChrome());
            AddViewTab("Services", "services", TabViews.BuildServices());
            AddViewTab("Processes", "processes", TabViews.BuildProcesses());
            AddViewTab("Startup", "startup", TabViews.BuildStartup());
            AddViewTab("Installed", "installed", TabViews.BuildInstalled());
            AddViewTab("Devices", "devices", TabViews.BuildDevices());

            // Add Fill first, then Left, then Top items (outermost added last).
            Controls.Add(_tabs);
            Controls.Add(_leftPanel);
            Controls.Add(toolbar);
            Controls.Add(_banner);

            UpdateBanner(); // initial title for the active (Safety Scan) tab
        }

        /// <summary>The full safety scan, as labelled steps rendered incrementally.</summary>
        private static (string, Func<CheckGroup>)[] ScanSteps() => new (string, Func<CheckGroup>)[]
        {
            ("current DNS servers", SafetyChecks.CheckDnsServers),
            ("connected router",    SafetyChecks.CheckRouter),
            ("upstream resolver",   SafetyChecks.CheckUpstreamResolver),
            ("DNS lookups",         SafetyChecks.CheckDnsLookups),
            ("cross-resolver DNS",  SafetyChecks.CheckCrossResolver),
            ("hosts file",          SafetyChecks.CheckHostsFile),
            ("e-mail (MX) DNS",     SafetyChecks.CheckEmailDns),
            ("proxy configuration", SafetyChecks.CheckProxy),
            ("atomic time sync",    SafetyChecks.CheckTimeSync),
            ("Windows security",    SafetyChecks.CheckWindowsSecurity),
        };

        private static (string, Func<CheckGroup>)[] One(string label, Func<CheckGroup> run)
            => new[] { (label, run) };

        private ResultsView AddTab(string title, string scope, string runLabel, string intro,
            (string, Func<CheckGroup>)[] steps, bool reportVerdict)
        {
            var view = new ResultsView(runLabel, intro, steps, reportVerdict);
            AddViewTab(title, scope, view);
            return view;
        }

        private void AddViewTab(string title, string scope, Control view)
        {
            var page = new TabPage(title) { UseVisualStyleBackColor = true, Tag = scope };
            page.Controls.Add(view);
            _tabs.TabPages.Add(page);
            if (view is ITabView tv)
                tv.SeverityChanged += () =>
                {
                    if (_tabs.IsHandleCreated)
                        _tabs.BeginInvoke(new Action(() => { _tabs.Invalidate(); UpdateBanner(); }));
                };
        }

        /// <summary>Owner-draws a tab header tinted by the worst state detected on that tab.</summary>
        private void DrawTab(object? sender, DrawItemEventArgs e)
        {
            var page = _tabs.TabPages[e.Index];
            bool selected = e.Index == _tabs.SelectedIndex;
            TabSeverity sev = page.Controls.Count > 0 && page.Controls[0] is ITabView v
                ? v.Severity : TabSeverity.None;

            Color back = SeverityColor(sev, selected);
            var r = e.Bounds;
            using (var b = new SolidBrush(back)) e.Graphics.FillRectangle(b, r);
            using (var pen = new Pen(Color.FromArgb(210, 210, 210))) e.Graphics.DrawRectangle(pen, r.X, r.Y, r.Width, r.Height);

            TextRenderer.DrawText(e.Graphics, page.Text, _tabs.Font, r, Color.Black,
                TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter | TextFormatFlags.EndEllipsis);
        }

        protected override void OnShown(EventArgs e)
        {
            base.OnShown(e);
            _ = _scanView.RunAsync(); // auto-run the initial tab
        }

        /// <summary>Lazily run a tab's checks the first time it is opened.</summary>
        private void AutoRunSelectedTab()
        {
            if (_tabs.SelectedTab?.Controls.Count > 0 &&
                _tabs.SelectedTab.Controls[0] is ITabView v && !v.HasRun)
                _ = v.RunAsync();
        }

        // Descriptive banner title per tab (keyed by scope tag).
        private static readonly Dictionary<string, string> BannerTitles = new()
        {
            ["scan"] = "Local network configuration",
            ["chrome"] = "Chrome browser and extensions",
            ["services"] = "3rd party background services",
            ["processes"] = "Running processes",
            ["startup"] = "Startup on login",
            ["installed"] = "Installed program changes",
            ["devices"] = "Installed device changes",
        };

        /// <summary>Tab/banner background colour for a severity (selected = stronger shade).</summary>
        private static Color SeverityColor(TabSeverity sev, bool selected) => sev switch
        {
            TabSeverity.Alert => selected ? Color.FromArgb(250, 170, 170) : Color.FromArgb(252, 214, 214),
            TabSeverity.Caution => selected ? Color.FromArgb(252, 226, 140) : Color.FromArgb(255, 244, 200),
            TabSeverity.Ok => selected ? Color.FromArgb(190, 230, 190) : Color.FromArgb(224, 244, 224),
            _ => selected ? Color.White : Color.FromArgb(238, 238, 238),
        };

        /// <summary>Banner shows the active tab's title; its colour matches that tab once it has run.</summary>
        private void UpdateBanner()
        {
            var page = _tabs.SelectedTab;
            if (page == null) return;
            string scope = page.Tag as string ?? "";
            TabSeverity sev = page.Controls.Count > 0 && page.Controls[0] is ITabView v ? v.Severity : TabSeverity.None;

            _banner.Text = BannerTitles.TryGetValue(scope, out var title) ? title : page.Text;
            _banner.BackColor = sev == TabSeverity.None ? Color.FromArgb(210, 214, 219) : SeverityColor(sev, true);
            _banner.ForeColor = Color.FromArgb(40, 40, 40);
        }

        private void OnScanCompleted(CheckStatus overall)
        {
            // The banner is driven by the active tab; here we only gate the Launch Chrome button.
            _chromeButton.Enabled = overall != CheckStatus.Fail;
        }

        private void ToggleLeftPanel()
        {
            _leftPanel.Visible = !_leftPanel.Visible;
            _toggleButton.Text = _leftPanel.Visible ? "◀ Hide tools" : "▶ Show tools";
        }

        /// <summary>Emails the report for the currently active tab using the stored client.</summary>
        private void EmailCurrentTab()
        {
            string scope = _tabs.SelectedTab?.Tag as string ?? "scan";
            string tabName = _tabs.SelectedTab?.Text ?? scope;
            ReportMailer.Send(this, scope, tabName, _settings);
        }

        /// <summary>Drop-down to choose (and persist) the email client and browser.</summary>
        private void ShowEmailMenu()
        {
            var menu = new ContextMenuStrip();

            menu.Items.Add("Email this tab now", null, (_, _) => EmailCurrentTab());
            menu.Items.Add(new ToolStripSeparator());

            var client = new ToolStripMenuItem("Email client");
            foreach (var (m, label) in new[]
            {
                (EmailMethod.DefaultMailApp, "Default mail app"),
                (EmailMethod.Gmail, "Gmail (web)"),
                (EmailMethod.OutlookWeb, "Outlook (web)"),
            })
            {
                var item = new ToolStripMenuItem(label) { Checked = _settings.EmailMethod == m };
                item.Click += (_, _) => { _settings.EmailMethod = m; _settings.Save(); };
                client.DropDownItems.Add(item);
            }
            menu.Items.Add(client);

            var browser = new ToolStripMenuItem("Open web mail in");
            foreach (BrowserChoice b in Enum.GetValues<BrowserChoice>())
            {
                string label = b == BrowserChoice.Default ? "Default browser" : b.ToString();
                var item = new ToolStripMenuItem(label) { Checked = _settings.EmailBrowser == b };
                item.Click += (_, _) => { _settings.EmailBrowser = b; _settings.Save(); };
                browser.DropDownItems.Add(item);
            }
            menu.Items.Add(browser);

            menu.Show(_emailMenuButton, new Point(0, _emailMenuButton.Height));
        }

        private void OpenUri(string uri)
        {
            try
            {
                Process.Start(new ProcessStartInfo(uri) { UseShellExecute = true });
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, $"Could not open '{uri}': {ex.Message}",
                    "Browse Safe", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
        }

        private void LaunchChrome()
        {
            try
            {
                Process.Start(new ProcessStartInfo("chrome.exe") { UseShellExecute = true });
            }
            catch
            {
                try
                {
                    Process.Start(new ProcessStartInfo("about:blank") { UseShellExecute = true });
                }
                catch (Exception ex)
                {
                    MessageBox.Show(this, "Could not launch Chrome: " + ex.Message,
                        "Browse Safe", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                }
            }
        }
    }
}
