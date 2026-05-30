using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
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
        private readonly Panel _leftPanel;
        private readonly TabControl _tabs;
        private readonly ResultsView _scanView;

        private static readonly Color ColorPass = Color.FromArgb(0, 140, 0);
        private static readonly Color ColorWarn = Color.FromArgb(190, 120, 0);
        private static readonly Color ColorFail = Color.FromArgb(200, 0, 0);

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

            var toolHint = new Label
            {
                AutoSize = true,
                Left = 278,
                Top = 13,
                ForeColor = Color.Gray,
                Text = "Left panel opens Windows Security pages. Each tab runs its own checks.",
            };
            toolbar.Controls.Add(_toggleButton);
            toolbar.Controls.Add(_chromeButton);
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

            // -- Tabs --
            _tabs = new TabControl { Dock = DockStyle.Fill };
            _tabs.SelectedIndexChanged += (_, _) => AutoRunSelectedTab();

            _scanView = AddTab("Safety Scan", "Run Safety Checks",
                "Click to scan.", ScanSteps(), reportVerdict: true);
            _scanView.Completed += OnScanCompleted;

            AddTab("Chrome", "Check Chrome", "Click to inspect Chrome.", new[]
            {
                ("Chrome executable", (Func<CheckGroup>)SafetyChecks.CheckChromeExe),
                ("Chrome extensions", (Func<CheckGroup>)SafetyChecks.CheckChromeExtensions),
            }, false);
            AddTab("Services", "Refresh", "Click to list services.", One("services", SafetyChecks.CheckServices), false);
            AddTab("Processes", "Refresh", "Click to list processes.", One("processes", SafetyChecks.CheckProcesses), false);
            AddTab("Startup", "Refresh", "Click to list startup items.", One("startup", SafetyChecks.CheckStartup), false);
            AddTab("Installed", "Refresh", "Click to list installed programs.", One("installed", SafetyChecks.CheckInstalled), false);
            AddTab("Devices", "Refresh", "Click to list drivers.", One("drivers", SafetyChecks.CheckDevices), false);

            // Add Fill first, then Left, then Top items (outermost added last).
            Controls.Add(_tabs);
            Controls.Add(_leftPanel);
            Controls.Add(toolbar);
            Controls.Add(_banner);
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

        private ResultsView AddTab(string title, string runLabel, string intro,
            (string, Func<CheckGroup>)[] steps, bool reportVerdict)
        {
            var view = new ResultsView(runLabel, intro, steps, reportVerdict);
            var page = new TabPage(title) { UseVisualStyleBackColor = true };
            page.Controls.Add(view);
            _tabs.TabPages.Add(page);
            return view;
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
                _tabs.SelectedTab.Controls[0] is ResultsView rv && !rv.HasRun)
                _ = rv.RunAsync();
        }

        private void OnScanCompleted(CheckStatus overall)
        {
            switch (overall)
            {
                case CheckStatus.Fail:
                    SetBanner("NOT SAFE  -  resolve the FAIL items before browsing", ColorFail);
                    _chromeButton.Enabled = false;
                    break;
                case CheckStatus.Warn:
                    SetBanner("CAUTION  -  review the WARN items", ColorWarn);
                    _chromeButton.Enabled = true;
                    break;
                default:
                    SetBanner("SAFE  -  all checks passed", ColorPass);
                    _chromeButton.Enabled = true;
                    break;
            }
        }

        private void SetBanner(string text, Color back)
        {
            _banner.Text = text;
            _banner.BackColor = back;
        }

        private void ToggleLeftPanel()
        {
            _leftPanel.Visible = !_leftPanel.Visible;
            _toggleButton.Text = _leftPanel.Visible ? "◀ Hide tools" : "▶ Show tools";
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
