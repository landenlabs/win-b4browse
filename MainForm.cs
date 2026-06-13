// Copyright (c) 2026 LanDen Labs - Dennis Lang

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Drawing.Printing;
using System.IO;
using System.Net.NetworkInformation;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace B4Browse
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
        private readonly Button _copyButton;
        private readonly Button _printButton;
        private Label _sysInfo = null!;   // toolbar watermark: Windows edition / version / install date
        private Label _patchInfo = null!; // toolbar (right): "Patched: <date>" - the most recent Windows update
        private readonly ToolTip _tips = new();
        private readonly Panel _leftPanel;
        private readonly TabControl _tabs;
        private readonly ResultsView _scanView;
        private readonly BusyOverlay _emailBusy = new();
        private Panel _toolbar = null!;
        private Label _leftHeader = null!;
        private Panel _leftBottom = null!;
        private Button _introButton = null!;   // pastel "Introduction" button pinned above the left panel
        private Image? _introIcon;             // app icon bitmap shown as a banner in the Intro Help

        // Bottom status bar: elevation + network indicators (left) + font-scale control (right).
        private Panel _statusBar = null!;
        private Label _adminIcon = null!;     // Segoe MDL2 shield glyph
        private Label _adminStatus = null!;   // "Administrator" / "Standard user"
        private Label _netStatus = null!;
        private Label _errorBadge = null!;    // "⚠ N errors" - click opens ErrorLogDialog; hidden at 0
        private Label _scaleCaption = null!;
        private Button _scaleMinus = null!;
        private Label _scaleLabel = null!;
        private Button _scalePlus = null!;

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
            // Version and build date come from AppInfo, which set-version.ps1 keeps in sync.
            Text = $"B4 Browse - Chrome Safety Check - {AppInfo.Version} - LanDen Labs  {AppInfo.BuildDate}";
            // Window/taskbar icon. Loaded from the embedded multi-resolution icon.ico so it
            // works inside the single-file exe; ExtractAssociatedIcon is only a last resort
            // (it is unreliable against a compressed single-file apphost).
            Icon = EmbeddedAssets.LoadIcon("icon.ico");
            if (Icon == null)
            {
                try
                {
                    var exe = Application.ExecutablePath;
                    if (!string.IsNullOrEmpty(exe)) Icon = Icon.ExtractAssociatedIcon(exe);
                }
                catch { }
            }
            MinimumSize = new Size(880, 600);
            Size = new Size(1000, 740);
            StartPosition = FormStartPosition.CenterScreen;
            Font = new Font("Segoe UI", 9f);
            BackColor = Theme.Window;

            _banner = new Label
            {
                Dock = DockStyle.Top,
                Height = 50,
                TextAlign = ContentAlignment.MiddleCenter,
                Font = new Font("Segoe UI", 13f, FontStyle.Bold),
                ForeColor = Theme.Text,
                BackColor = Color.FromArgb(90, 90, 90),
                Text = "Run the Safety Scan to evaluate browsing safety",
            };

            // -- Toolbar --
            _toolbar = new Panel { Dock = DockStyle.Top, Height = 42, BackColor = Theme.Toolbar };
            var toolbar = _toolbar;
            _toggleButton = new Button
            {
                Text = "◀ Links",
                Width = 84,
                Height = 28,
                Left = 8,
                Top = 7,
                FlatStyle = FlatStyle.System,
            };
            _toggleButton.Click += (_, _) => ToggleLeftPanel();
            _tips.SetToolTip(_toggleButton, "Show / hide the side panel of Windows Security and drill-down links");

            // Launch Chrome now lives in the left tool panel (added after the Security
            // shortcuts below); styled to match those buttons.
            _chromeButton = new Button
            {
                Text = "Launch Chrome",
                Width = 200,
                Height = 40,
                TextAlign = ContentAlignment.MiddleLeft,
                FlatStyle = FlatStyle.System,
                Margin = new Padding(0, 12, 0, 8),
                Enabled = false,
            };
            _chromeButton.Click += (_, _) => LaunchChrome();

            // Email + Copy icon buttons, anchored to the right edge of the toolbar.
            _emailButton = new Button
            {
                Text = "",                                  // Segoe MDL2 "Mail" glyph
                Width = 36, Height = 28, Top = 7,
                FlatStyle = FlatStyle.System,
                Font = new Font("Segoe MDL2 Assets", 12f),
            };
            _emailButton.Click += (_, _) => EmailCurrentTab();

            _copyButton = new Button
            {
                Text = "",                                  // Segoe MDL2 "Copy" glyph
                Width = 36, Height = 28, Top = 7,
                FlatStyle = FlatStyle.System,
                Font = new Font("Segoe MDL2 Assets", 12f),
            };
            _copyButton.Click += (_, _) => CopyCurrentTab();

            _printButton = new Button
            {
                Text = "",                            // Segoe MDL2 "Print" glyph
                Width = 36, Height = 28, Top = 7,
                FlatStyle = FlatStyle.System,
                Font = new Font("Segoe MDL2 Assets", 12f),
            };
            _printButton.Text = "";   // Segoe MDL2 "Print" glyph
            _printButton.Click += (_, _) => PrintCurrentTab();

            _tips.SetToolTip(_emailButton, "Email this tab's report (opens Gmail in Chrome; full report copied to the clipboard)");
            _tips.SetToolTip(_copyButton, "Copy this tab's report to the clipboard");
            _tips.SetToolTip(_printButton, "Print this tab's report (or save as PDF)");

            // Watermark in the toolbar's empty middle: Windows edition / version / install date.
            // Clickable - opens the Settings "About" page. Hidden when nothing could be read.
            _sysInfo = new Label
            {
                AutoSize = true,
                Text = WindowsInfo.Summary,
                Font = new Font("Segoe UI", 9f, FontStyle.Italic),
                ForeColor = Theme.Subtle,
                Cursor = Cursors.Hand,
                Visible = WindowsInfo.Summary.Length > 0,
            };
            _sysInfo.Click += (_, _) => WindowsInfo.OpenAbout();
            _tips.SetToolTip(_sysInfo, "This PC - open Windows Settings › About");

            // Most-recent Windows patch date, right-justified by the icon buttons. A core idea of the
            // app is spotting changes newer than the last patch, so the baseline date sits up top.
            // Filled asynchronously (WMI read) in OnShown; hidden until then.
            _patchInfo = new Label
            {
                AutoSize = true,
                Text = "",
                Font = new Font("Segoe UI", 9f, FontStyle.Italic),
                ForeColor = Theme.Subtle,
                Visible = false,
            };
            _tips.SetToolTip(_patchInfo,
                "Date of the most recent Windows update - use it as a baseline: items on the other tabs that changed after this date, and weren't installed by you, are worth a review");

            toolbar.Controls.Add(_toggleButton);
            toolbar.Controls.Add(_sysInfo);
            toolbar.Controls.Add(_patchInfo);
            toolbar.Controls.Add(_emailButton);
            toolbar.Controls.Add(_copyButton);
            toolbar.Controls.Add(_printButton);
            toolbar.SizeChanged += (_, _) => LayoutToolbarRight();
            LayoutToolbarRight();

            // -- Left panel: Windows Security shortcuts --
            _leftPanel = new Panel { Dock = DockStyle.Left, Width = 230, BackColor = Theme.Panel };
            _leftHeader = new Label
            {
                Dock = DockStyle.Top,
                Height = 34,
                Text = "  Windows Security",
                TextAlign = ContentAlignment.MiddleLeft,
                Font = new Font("Segoe UI", 10f, FontStyle.Bold),
                ForeColor = Theme.Text,
            };
            var leftHeader = _leftHeader;
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
            // Launch Chrome sits below the Windows Security shortcuts.
            flow.Controls.Add(_chromeButton);

            // "Run as Admin" - only when not already elevated. Relaunches via UAC and exits.
            if (!Elevation.IsAdmin)
            {
                var admin = new Button
                {
                    Text = "Run as Admin",
                    Width = 200, Height = 40,
                    TextAlign = ContentAlignment.MiddleLeft,
                    FlatStyle = FlatStyle.System,
                    Margin = new Padding(0, 12, 0, 8),
                };
                admin.Click += (_, _) => { if (Elevation.RelaunchAsAdmin()) Application.Exit(); };
                flow.Controls.Add(admin);
            }

            // Theme toggle pinned to the lower-left of the panel.
            _leftBottom = new Panel { Dock = DockStyle.Bottom, Height = 52, BackColor = Theme.Panel };
            var themeIcon = new PictureBox
            {
                Left = 10, Top = 8, Width = 40, Height = 40,
                SizeMode = PictureBoxSizeMode.Zoom,
                BackColor = Color.Transparent,
                Cursor = Cursors.Hand,
            };
            // Load a mono (black-on-transparent) icon and tint it to match the current theme text color.
            // Loaded from the embedded resource so it ships inside the single-file exe.
            Image? _themeIconSource = EmbeddedAssets.LoadImage("dark-light.png");

            if (_themeIconSource != null)
            {
                // Use the source image as-is; do not recolor or tint so the icon remains the original black/white circle.
                themeIcon.Image = _themeIconSource;
            }
            themeIcon.Click += (_, _) => ToggleTheme();

            var themeLabel = new Label
            {
                Left = 58, Top = 18, AutoSize = true, ForeColor = Theme.Subtle,
                Text = "Theme", Cursor = Cursors.Hand,
            };
            themeLabel.Click += (_, _) => ToggleTheme();

            var tip = new ToolTip();
            tip.SetToolTip(themeIcon, "Toggle dark / light theme");
            tip.SetToolTip(themeLabel, "Toggle dark / light theme");

            var aboutButton = new Button
            {
                Width = 36,
                Height = 36,
                Left = Math.Max(0, _leftBottom.Width - 44),
                Top = 8,
                Text = "?",
                FlatStyle = FlatStyle.System,
                Anchor = AnchorStyles.Top | AnchorStyles.Right,
                Cursor = Cursors.Hand,
                Font = new Font("Segoe UI", 9f, FontStyle.Bold),
            };
            aboutButton.Click += (_, _) => { try { var f = new AboutForm(); f.Show(); } catch { CopyableMessageBox.Show(this, "B4 Browse - Chrome Safety Check\n\nA small tool to inspect Chrome, extensions, and local system indicators relevant to browsing safety.", "About B4 Browse", MessageBoxButtons.OK, MessageBoxIcon.Information); } };
            tip.SetToolTip(aboutButton, "About B4 Browse");

            _leftBottom.Controls.Add(themeIcon);
            _leftBottom.Controls.Add(themeLabel);
            _leftBottom.Controls.Add(aboutButton);

            // Note: theme icon intentionally left unmodified so it always displays the original asset.

            // "Introduction" button pinned to the very top of the left panel - a soft pastel-blue
            // call-out that opens the welcome / overview Help. Hosted in a small padded panel so it
            // sits above the "Windows Security" header (docked Top, added last = outermost edge).
            var introHost = new Panel
            {
                Dock = DockStyle.Top,
                Height = 50,
                BackColor = Theme.Panel,
                Padding = new Padding(10, 8, 10, 4),
            };
            _introButton = new Button
            {
                Text = "ℹ  Introduction",
                Dock = DockStyle.Fill,
                FlatStyle = FlatStyle.Flat,
                TextAlign = ContentAlignment.MiddleCenter,
                Font = new Font("Segoe UI", 10.5f, FontStyle.Bold),
                Cursor = Cursors.Hand,
            };
            // Derive a crisp banner bitmap from the app icon (nearest 64px frame) for the Intro page.
            try { if (Icon != null) _introIcon = new Icon(Icon, new Size(64, 64)).ToBitmap(); } catch { }
            _introButton.Click += (_, _) => HelpUi.Show(this, TabHelp.Intro with { Header = _introIcon });
            _tips.SetToolTip(_introButton, "What B4 Browse does and how to use the tabs");
            introHost.Controls.Add(_introButton);
            StyleIntroButton();   // pastel colours, re-applied on theme change by ApplyThemeColors

            _leftPanel.Controls.Add(flow);
            _leftPanel.Controls.Add(_leftBottom);
            _leftPanel.Controls.Add(leftHeader);
            _leftPanel.Controls.Add(introHost);

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
                "Click to scan.", ScanSteps(), reportVerdict: true, requiresNetwork: true);
            _scanView.Completed += OnScanCompleted;

            AddViewTab("Patches", "patches", TabViews.BuildPatches());
            AddViewTab("DNS", "dns", TabViews.BuildDns());
            AddViewTab("ARP", "arp", TabViews.BuildArp());
            AddViewTab("Chrome", "chrome", TabViews.BuildChrome());
            AddViewTab("Settings", "settings", TabViews.BuildSettings());
            AddViewTab("Services", "services", TabViews.BuildServices());
            AddViewTab("Processes", "processes", TabViews.BuildProcesses());
            AddViewTab("Startup", "startup", TabViews.BuildStartup());
            AddViewTab("Scheduled", "scheduled", TabViews.BuildScheduled());
            AddViewTab("Installed", "installed", TabViews.BuildInstalled());
            AddViewTab("Devices", "devices", TabViews.BuildDevices());
            AddViewTab("Win Extn", "winext", TabViews.BuildWinExt());
            AddViewTab("Events", "events", TabViews.BuildEvents());
            AddViewTab("Awake", "awake", TabViews.BuildAwake());
            AddViewTab("Activity", "activity", TabViews.BuildActivity());
            AddViewTab("Downloads", "downloads", TabViews.BuildDownloads());
            AddViewTab("Root CAs", "rootca", TabViews.BuildRootCerts());
            AddViewTab("Firewall", "firewall", TabViews.BuildFirewall());
            AddViewTab("Virus", "virus", TabViews.BuildVirus());
            if (Elevation.IsAdmin)
                AddViewTab("Restores", "restores", TabViews.BuildRestores());

            AddViewTab("Tools", "links", TabViews.BuildLinks());

            BuildStatusBar();

            // Add Fill first, then docked edges (outermost added last). The status bar is
            // added after the left panel so it spans the full width along the bottom.
            Controls.Add(_tabs);
            Controls.Add(_leftPanel);
            Controls.Add(_statusBar);
            Controls.Add(toolbar);
            Controls.Add(_banner);
            Controls.Add(_emailBusy);   // floating spinner shown while an email report builds

            UpdateBanner(); // initial title for the active (Safety Scan) tab
            UpdateAdminStatus();
            UpdateNetStatus();
            UpdateScaleLabel();
            ApplyThemeColors(); // paint buttons/chrome for the startup theme
            Theme.Changed += () => { ApplyThemeColors(); UpdateBanner(); _tabs.Invalidate(); };
            Theme.ScaleChanged += UpdateScaleLabel;

            // Live-update the network indicator when adapters come up / go down.
            NetworkChange.NetworkAvailabilityChanged += OnNetworkChanged;
            NetworkChange.NetworkAddressChanged += OnNetworkChanged;
        }

        /// <summary>Builds the bottom status bar: a network indicator on the left and a
        /// Chrome-style [ - 100% + ] font-scale control on the right.</summary>
        private void BuildStatusBar()
        {
            _statusBar = new Panel { Dock = DockStyle.Bottom, Height = 30, BackColor = Theme.Toolbar };

            // Elevation indicator (left-most): a UAC shield + "Administrator" / "Standard user".
            // When not elevated it is a hand-cursor link that relaunches the app via UAC. Colours
            // and text are set in UpdateAdminStatus (theme-aware).
            _adminIcon = new Label
            {
                AutoSize = true, Top = 6, Text = "",   // Segoe MDL2 "Shield"
                Font = new Font("Segoe MDL2 Assets", 11f),
            };
            _adminStatus = new Label
            {
                AutoSize = true, Top = 7, Font = new Font("Segoe UI", 9f),
            };
            _adminIcon.Click += (_, _) => RelaunchAsAdmin();
            _adminStatus.Click += (_, _) => RelaunchAsAdmin();
            _statusBar.Controls.Add(_adminIcon);
            _statusBar.Controls.Add(_adminStatus);

            _netStatus = new Label
            {
                AutoSize = true, Left = 12, Top = 7, Cursor = Cursors.Hand,
                Font = new Font("Segoe UI", 9f),
            };
            _netStatus.Click += (_, _) => NetworkStatus.OpenSettings();
            _tips.SetToolTip(_netStatus, "Open Windows network / airplane-mode settings");
            _statusBar.Controls.Add(_netStatus);

            // Font-scale control: caption + [ - 100% + ], right-aligned via LayoutStatusBar.
            _scaleCaption = new Label
            {
                Text = "Font size", AutoSize = true, Top = 7, ForeColor = Theme.Subtle,
                Font = new Font("Segoe UI", 9f),
            };
            _scaleMinus = new Button
            {
                Text = "−", Width = 28, Height = 24, Top = 3, FlatStyle = FlatStyle.System,
                Font = new Font("Segoe UI", 10f, FontStyle.Bold),
            };
            _scaleLabel = new Label
            {
                AutoSize = false, Width = 52, Height = 24, Top = 3,
                TextAlign = ContentAlignment.MiddleCenter, Cursor = Cursors.Hand,
                Font = new Font("Segoe UI", 9f),
            };
            _scalePlus = new Button
            {
                Text = "+", Width = 28, Height = 24, Top = 3, FlatStyle = FlatStyle.System,
                Font = new Font("Segoe UI", 10f, FontStyle.Bold),
            };
            _scaleMinus.Click += (_, _) => Theme.StepScale(-1);
            _scalePlus.Click += (_, _) => Theme.StepScale(+1);
            _scaleLabel.Click += (_, _) => Theme.SetScale(1.0f);   // click the % to reset to 100%
            _tips.SetToolTip(_scaleMinus, "Smaller content font");
            _tips.SetToolTip(_scalePlus, "Larger content font");
            _tips.SetToolTip(_scaleLabel, "Content font scale - click to reset to 100%");

            // Error badge: a quiet count of background-action failures (PowerShell agents that
            // timed out / returned nothing / threw). Hidden when zero; click opens the detail
            // dialog. Keeps the main tabs clean - one place to look when something didn't run.
            _errorBadge = new Label
            {
                AutoSize = true, Top = 7, Visible = false, Cursor = Cursors.Hand,
                Font = new Font("Segoe UI", 9f, FontStyle.Bold),
            };
            _errorBadge.Click += (_, _) => new ErrorLogDialog().ShowDialog(this);
            _tips.SetToolTip(_errorBadge, "Background actions that failed this session - click for details");
            _statusBar.Controls.Add(_errorBadge);

            _statusBar.Controls.Add(_scaleCaption);
            _statusBar.Controls.Add(_scaleMinus);
            _statusBar.Controls.Add(_scaleLabel);
            _statusBar.Controls.Add(_scalePlus);

            ErrorLog.Changed += OnErrorLogChanged;
            UpdateErrorBadge();

            _statusBar.SizeChanged += (_, _) => LayoutStatusBar();
            LayoutStatusBar();
        }

        /// <summary>ErrorLog fires on background (check) threads; marshal the badge update to the UI.</summary>
        private void OnErrorLogChanged()
        {
            if (IsHandleCreated) BeginInvoke(new Action(UpdateErrorBadge));
        }

        /// <summary>Shows/hides and re-tints the status-bar error badge from the current count.</summary>
        private void UpdateErrorBadge()
        {
            int n = ErrorLog.Count;
            if (n == 0)
            {
                _errorBadge.Visible = false;
                return;
            }
            _errorBadge.Text = $"⚠ {n} error{(n == 1 ? "" : "s")}";
            _errorBadge.ForeColor = Theme.IsDark
                ? Color.FromArgb(240, 170, 80)
                : Color.FromArgb(170, 90, 0);
            _errorBadge.Visible = true;
            LayoutStatusBar();
        }

        /// <summary>Right-aligns the font-scale group within the status bar.</summary>
        private void LayoutStatusBar()
        {
            if (_statusBar == null) return;
            int h = _statusBar.ClientSize.Height;
            int right = _statusBar.ClientSize.Width - 10;
            _scalePlus.Left = Math.Max(0, right - _scalePlus.Width);
            _scaleLabel.Left = _scalePlus.Left - _scaleLabel.Width - 2;
            _scaleMinus.Left = _scaleLabel.Left - _scaleMinus.Width - 2;
            _scaleCaption.Left = _scaleMinus.Left - _scaleCaption.Width - 10;
            _scaleCaption.Top = (h - _scaleCaption.Height) / 2;

            // Left cluster: [shield] [Administrator | Standard user]   gap   [● Network ...]
            int x = 12;
            _adminIcon.Left = x;
            _adminIcon.Top = (h - _adminIcon.Height) / 2;
            x = _adminIcon.Right + 4;
            _adminStatus.Left = x;
            _adminStatus.Top = (h - _adminStatus.Height) / 2;
            x = _adminStatus.Right + 20;
            _netStatus.Left = x;
            _netStatus.Top = (h - _netStatus.Height) / 2;

            if (_errorBadge != null && _errorBadge.Visible)
            {
                _errorBadge.Left = _netStatus.Right + 24;
                _errorBadge.Top = (h - _errorBadge.Height) / 2;
            }
        }

        /// <summary>
        /// Sets the elevation indicator's glyph, text, colour and tooltip for the current
        /// session and theme. Admin reads as a blue shield + "Administrator"; a standard user
        /// reads as a muted shield + "Standard user" and becomes a click-to-elevate link.
        /// </summary>
        private void UpdateAdminStatus()
        {
            bool admin = Elevation.IsAdmin;
            _adminStatus.Text = admin ? "Administrator" : "Standard user";

            Color c = admin
                ? (Theme.IsDark ? Color.FromArgb(120, 190, 255) : Color.FromArgb(0, 90, 200))  // UAC blue
                : Theme.Subtle;
            _adminIcon.ForeColor = c;
            _adminStatus.ForeColor = c;

            Cursor cur = admin ? Cursors.Default : Cursors.Hand;
            _adminIcon.Cursor = cur;
            _adminStatus.Cursor = cur;

            string tip = admin
                ? "Running as Administrator - full access to the Security event log, SRUM and Defender history."
                : "Standard user - some tabs (Events, Downloads, Virus history, Restores) need elevation. Click to relaunch as Administrator.";
            _tips.SetToolTip(_adminIcon, tip);
            _tips.SetToolTip(_adminStatus, tip);

            LayoutStatusBar();
        }

        /// <summary>Relaunches the app elevated via UAC and exits the current instance. No-op when
        /// already elevated or if the user declines the prompt.</summary>
        private void RelaunchAsAdmin()
        {
            if (Elevation.IsAdmin) return;
            if (Elevation.RelaunchAsAdmin()) Application.Exit();
        }

        /// <summary>Refreshes the left network indicator from the current adapter state.</summary>
        private void UpdateNetStatus()
        {
            bool up = NetworkStatus.IsAvailable();
            _netStatus.Text = up ? "●  Network connected" : "●  Network not available";
            _netStatus.ForeColor = up
                ? (Theme.IsDark ? Color.FromArgb(90, 200, 100) : Color.FromArgb(0, 140, 0))
                : (Theme.IsDark ? Color.FromArgb(240, 110, 110) : Color.FromArgb(200, 0, 0));
            LayoutStatusBar();
        }

        /// <summary>Updates the "100%" readout from the current <see cref="Theme.FontScale"/>.</summary>
        private void UpdateScaleLabel()
        {
            _scaleLabel.Text = $"{Theme.FontScale * 100:0}%";
            LayoutStatusBar();
        }

        private void OnNetworkChanged(object? sender, EventArgs e)
        {
            // NetworkChange events arrive on a background thread; marshal to the UI.
            if (IsHandleCreated) BeginInvoke(new Action(UpdateNetStatus));
        }

        protected override void OnFormClosed(FormClosedEventArgs e)
        {
            NetworkChange.NetworkAvailabilityChanged -= OnNetworkChanged;
            NetworkChange.NetworkAddressChanged -= OnNetworkChanged;
            Theme.ScaleChanged -= UpdateScaleLabel;
            ErrorLog.Changed -= OnErrorLogChanged;
            base.OnFormClosed(e);
        }

        /// <summary>Re-colours the form chrome (left panel, toolbar, all buttons) for the current theme.</summary>
        private void ApplyThemeColors()
        {
            BackColor = Theme.Window;
            _toolbar.BackColor = Theme.Toolbar;
            _sysInfo.ForeColor = Theme.Subtle;
            _patchInfo.ForeColor = Theme.Subtle;

            _leftPanel.BackColor = Theme.Panel;
            _leftBottom.BackColor = Theme.Panel;
            _leftHeader.ForeColor = Theme.Text;
            foreach (Control c in _leftBottom.Controls)
                if (c is Label) c.ForeColor = Theme.Subtle;

            _statusBar.BackColor = Theme.Toolbar;
            _scaleCaption.ForeColor = Theme.Subtle;
            _scaleLabel.ForeColor = Theme.Text;
            UpdateAdminStatus(); // re-tint elevation indicator for the new theme
            UpdateNetStatus();   // re-tint the network indicator for the new theme
            UpdateErrorBadge();  // re-tint the error badge for the new theme

            // Explicitly paint every button (toolbar, left panel, and inside each tab view).
            Theme.StyleButtons(this);
            StyleIntroButton();   // restore the Intro button's pastel after the generic repaint
        }

        /// <summary>Paints the left-panel "Introduction" button in a soft, theme-aware pastel blue so it
        /// stands out from the neutral toolbar buttons. Called after <see cref="Theme.StyleButtons"/>,
        /// which would otherwise repaint it in the standard button colours.</summary>
        private void StyleIntroButton()
        {
            if (_introButton == null) return;
            _introButton.UseVisualStyleBackColor = false;
            _introButton.BackColor = Theme.IsDark ? Color.FromArgb(40, 66, 100) : Color.FromArgb(208, 228, 250);
            _introButton.ForeColor = Theme.IsDark ? Color.FromArgb(205, 225, 250) : Color.FromArgb(20, 45, 85);
            _introButton.FlatAppearance.BorderColor = Theme.IsDark ? Color.FromArgb(78, 116, 165) : Color.FromArgb(150, 190, 235);
            _introButton.FlatAppearance.BorderSize = 1;
            if (_introButton.Parent != null) _introButton.Parent.BackColor = Theme.Panel;
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
            ("network sniffers",    SafetyChecks.CheckPromiscuousMode),
            ("network adapters",    SafetyChecks.CheckNetworkAdapters),
        };

        private static (string, Func<CheckGroup>)[] One(string label, Func<CheckGroup> run)
            => new[] { (label, run) };

        private ResultsView AddTab(string title, string scope, string runLabel, string intro,
            (string, Func<CheckGroup>)[] steps, bool reportVerdict, bool requiresNetwork = false)
        {
            var view = new ResultsView(runLabel, intro, steps, reportVerdict, TabHelp.Scan, requiresNetwork);
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
            // Severity colours are light, so use dark text on them; neutral tabs follow the theme.
            Color fore = sev == TabSeverity.None ? Theme.Text : Color.FromArgb(30, 30, 30);
            var r = e.Bounds;
            using (var b = new SolidBrush(back)) e.Graphics.FillRectangle(b, r);
            using (var pen = new Pen(Theme.GridLine)) e.Graphics.DrawRectangle(pen, r.X, r.Y, r.Width, r.Height);

            TextRenderer.DrawText(e.Graphics, page.Text, _tabs.Font, r, fore,
                TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter | TextFormatFlags.EndEllipsis);
        }

        protected override void OnShown(EventArgs e)
        {
            base.OnShown(e);
            _ = _scanView.RunAsync(); // auto-run the initial tab
            LoadPatchDate();          // fill the toolbar "Patched:" readout off the UI thread
        }

        /// <summary>Reads the most-recent Windows patch date on a background thread (WMI) and shows it
        /// in the toolbar as "Patched: Fri Jun-12" - the baseline date for spotting newer changes.</summary>
        private void LoadPatchDate()
        {
            _ = Task.Run(() =>
            {
                DateTime? d = SafetyChecks.MostRecentPatchDate();
                if (d == null || !IsHandleCreated) return;
                try
                {
                    BeginInvoke(new Action(() =>
                    {
                        _patchInfo.Text = "Patched: " +
                            d.Value.ToString("ddd MMM-dd", System.Globalization.CultureInfo.InvariantCulture);
                        _patchInfo.Visible = true;
                        LayoutToolbarRight();
                    }));
                }
                catch { /* form closing */ }
            });
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
            ["dns"] = "DNS resolver cache",
            ["arp"] = "Local ARP neighbor cache",
            ["patches"] = "Installed Windows patches",
            ["chrome"] = "Chrome browser and extensions",
            ["services"] = "3rd party background services",
            ["processes"] = "Running processes",
            ["startup"] = "Startup on login",
            ["scheduled"] = "Scheduled tasks",
            ["installed"] = "Installed program changes",
            ["devices"] = "Installed device changes",
            ["winext"] = "File Explorer shell extensions",
            ["events"] = "Recent system & security events",
            ["awake"] = "Recent awake / sleep periods",
            ["activity"] = "App launch activity",
            ["downloads"] = "Per-app network usage (downloads)",
            ["rootca"] = "Trusted root certificate authorities",
            ["firewall"] = "Windows Firewall configuration",
            ["restores"] = "System Restore points",
        };

        /// <summary>Tab/banner background colour for a severity (selected = stronger shade).</summary>
        private static Color SeverityColor(TabSeverity sev, bool selected) => sev switch
        {
            TabSeverity.Alert => selected ? Color.FromArgb(250, 170, 170) : Color.FromArgb(252, 214, 214),
            TabSeverity.Caution => selected ? Color.FromArgb(252, 226, 140) : Color.FromArgb(255, 244, 200),
            TabSeverity.Ok => selected ? Color.FromArgb(190, 230, 190) : Color.FromArgb(224, 244, 224),
            _ => Theme.NeutralTab(selected),
        };

        /// <summary>Banner shows the active tab's title; its colour matches that tab once it has run.</summary>
        private void UpdateBanner()
        {
            var page = _tabs.SelectedTab;
            if (page == null) return;
            string scope = page.Tag as string ?? "";
            TabSeverity sev = page.Controls.Count > 0 && page.Controls[0] is ITabView v ? v.Severity : TabSeverity.None;

            _banner.Text = BannerTitles.TryGetValue(scope, out var title) ? title : page.Text;
            if (sev == TabSeverity.None)
            {
                _banner.BackColor = Theme.IsDark ? Color.FromArgb(60, 60, 64) : Color.FromArgb(210, 214, 219);
                _banner.ForeColor = Theme.Text;
            }
            else
            {
                _banner.BackColor = SeverityColor(sev, true);   // light severity shade
                _banner.ForeColor = Color.FromArgb(30, 30, 30); // dark text on light shade
            }
        }

        private void OnScanCompleted(CheckStatus overall)
        {
            // The banner is driven by the active tab; here we only gate the Launch Chrome button.
            _chromeButton.Enabled = overall != CheckStatus.Fail;
        }

        private void ToggleLeftPanel()
        {
            _leftPanel.Visible = !_leftPanel.Visible;
            _toggleButton.Text = _leftPanel.Visible ? "◀ Links" : "▶ Links";
        }

        private void ToggleTheme()
        {
            Theme.Toggle();
            Invalidate(true);  // best-effort live repaint of standard controls
        }

        /// <summary>
        /// Emails the active tab's report via Gmail in Chrome. The report is built on a
        /// background thread (Reports.Build runs the checks), so a spinner is shown and
        /// the UI stays responsive.
        /// </summary>
        private async void EmailCurrentTab()
        {
            string scope = _tabs.SelectedTab?.Tag as string ?? "scan";
            string tabName = _tabs.SelectedTab?.Text ?? scope;

            _emailButton.Enabled = false;
            CenterEmailBusy();
            _emailBusy.Start();
            try
            {
                await ReportMailer.SendAsync(this, scope, tabName);
            }
            finally
            {
                _emailBusy.Stop();
                _emailButton.Enabled = true;
            }
        }

        /// <summary>Builds the active tab's report on a background thread and copies it to the clipboard.</summary>
        private async void CopyCurrentTab()
        {
            string scope = _tabs.SelectedTab?.Tag as string ?? "scan";

            _copyButton.Enabled = false;
            CenterEmailBusy();
            _emailBusy.Start();
            try
            {
                var report = await Task.Run(() => Reports.Build(scope));
                try { Clipboard.SetText(report.Text); } catch { /* clipboard may be busy */ }
                _tips.Show("Report copied to the clipboard", _copyButton, 0, -28, 1500);
            }
            catch (Exception ex)
            {
                CopyableMessageBox.Show(this, "Could not build report: " + ex.Message, "Copy report",
                    MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
            finally
            {
                _emailBusy.Stop();
                _copyButton.Enabled = true;
            }
        }

        /// <summary>
        /// Builds the active tab's report on a background thread, then sends it to a printer
        /// chosen in the standard print dialog (which includes "Microsoft Print to PDF").
        /// </summary>
        private async void PrintCurrentTab()
        {
            string scope = _tabs.SelectedTab?.Tag as string ?? "scan";
            string tabName = _tabs.SelectedTab?.Text ?? scope;

            _printButton.Enabled = false;
            CenterEmailBusy();
            _emailBusy.Start();
            string? reportText = null;
            try
            {
                var report = await Task.Run(() => Reports.Build(scope));
                reportText = report.Text;
            }
            catch (Exception ex)
            {
                CopyableMessageBox.Show(this, "Could not build report: " + ex.Message, "Print report",
                    MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
            finally
            {
                _emailBusy.Stop();
                _printButton.Enabled = true;
            }

            // Show the (modal) print dialog after the spinner stops.
            if (reportText != null) PrintReport(reportText, $"B4 Browse - {tabName}");
        }

        /// <summary>
        /// Prints a plain-text report with a monospaced font, paginating and wrapping long
        /// lines to the page margins. Uses the standard Windows print dialog.
        /// </summary>
        private void PrintReport(string text, string docName)
        {
            using var font = new Font("Consolas", 9f);
            var raw = text.Replace("\r\n", "\n").Split('\n');

            List<string>? lines = null;   // wrapped on the first page, when a Graphics is available
            int next = 0;

            using var doc = new PrintDocument { DocumentName = docName };
            doc.PrintPage += (_, e) =>
            {
                var area = e.MarginBounds;
                lines ??= WrapToWidth(raw, font, e.Graphics!, area.Width);

                float lineH = font.GetHeight(e.Graphics!);
                int perPage = Math.Max(1, (int)(area.Height / lineH));
                float y = area.Top;

                for (int drawn = 0; drawn < perPage && next < lines.Count; drawn++, next++)
                {
                    e.Graphics!.DrawString(lines[next], font, Brushes.Black, area.Left, y);
                    y += lineH;
                }
                e.HasMorePages = next < lines.Count;
                if (!e.HasMorePages) next = 0;   // reset so a reprint starts at the top
            };

            using var dlg = new PrintDialog { Document = doc, UseEXDialog = true };
            if (dlg.ShowDialog(this) != DialogResult.OK) return;
            try { doc.Print(); }
            catch (Exception ex)
            {
                CopyableMessageBox.Show(this, "Print failed: " + ex.Message, "Print report",
                    MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
        }

        /// <summary>Character-wraps each line to the page width (Consolas is monospaced).</summary>
        private static List<string> WrapToWidth(string[] raw, Font font, Graphics g, int maxWidth)
        {
            float charW = g.MeasureString("0000000000", font).Width / 10f;
            int maxChars = Math.Max(10, (int)(maxWidth / Math.Max(1f, charW)));
            var outp = new List<string>(raw.Length);
            foreach (var ln in raw)
            {
                string s = ln.TrimEnd('\r');
                if (s.Length <= maxChars) { outp.Add(s); continue; }
                for (int i = 0; i < s.Length; i += maxChars)
                    outp.Add(s.Substring(i, Math.Min(maxChars, s.Length - i)));
            }
            return outp;
        }

        private void CenterEmailBusy()
        {
            _emailBusy.Left = Math.Max(0, (ClientSize.Width - _emailBusy.Width) / 2);
            _emailBusy.Top = Math.Max(0, (ClientSize.Height - _emailBusy.Height) / 2);
        }

        /// <summary>Pins the email + copy + print icon buttons to the right edge of the toolbar.</summary>
        private void LayoutToolbarRight()
        {
            _emailButton.Left = Math.Max(0, _toolbar.ClientSize.Width - _emailButton.Width - 8);
            _copyButton.Left = Math.Max(0, _emailButton.Left - _copyButton.Width - 6);
            _printButton.Left = Math.Max(0, _copyButton.Left - _printButton.Width - 6);

            // "Patched: <date>" sits right-justified just left of the three icon buttons.
            if (_patchInfo is { Visible: true })
            {
                _patchInfo.Top = (_toolbar.ClientSize.Height - _patchInfo.Height) / 2;
                _patchInfo.Left = Math.Max(0, _printButton.Left - _patchInfo.Width - 14);
            }

            // Centre the system-info watermark in the gap between the toggle button and whatever is
            // next on the right (the patch readout, or the icon buttons); left-align (and let it
            // clip) if the gap is too narrow.
            if (_sysInfo is { Visible: true })
            {
                int rightEdge = _patchInfo is { Visible: true } ? _patchInfo.Left : _printButton.Left;
                int availLeft = _toggleButton.Right + 12;
                int availRight = rightEdge - 12;
                _sysInfo.Top = (_toolbar.ClientSize.Height - _sysInfo.Height) / 2;
                int gap = availRight - availLeft;
                _sysInfo.Left = gap > _sysInfo.Width
                    ? availLeft + (gap - _sysInfo.Width) / 2
                    : availLeft;
            }
        }

        private void OpenUri(string uri)
        {
            try
            {
                Process.Start(new ProcessStartInfo(uri) { UseShellExecute = true });
            }
            catch (Exception ex)
            {
                CopyableMessageBox.Show(this, $"Could not open '{uri}': {ex.Message}",
                    "B4 Browse", MessageBoxButtons.OK, MessageBoxIcon.Warning);
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
                    CopyableMessageBox.Show(this, "Could not launch Chrome: " + ex.Message,
                        "B4 Browse", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                }
            }
        }
    }
}
