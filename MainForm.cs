// Copyright (c) 2026 LanDen Labs - Dennis Lang

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Drawing.Printing;
using System.IO;
using System.Linq;
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
        private readonly Button _emailButton;
        private readonly Button _copyButton;
        private readonly Button _printButton;
        private Label _sysInfo = null!;   // toolbar watermark: Windows edition / version / install date
        private Label _patchInfo = null!; // toolbar (right): "Patched: <date>" - the most recent Windows update
        private readonly ToolTip _tips = new();
        private readonly Panel _leftPanel;
        private TreeView _nav = null!;                 // category tree (replaces the old tab strip)
        private Panel _content = null!;                // hosts the selected section's view
        private readonly Dictionary<Catalog.Section, Control> _views = new();   // lazily built + cached
        private Catalog.Section? _current;             // the currently shown section
        private Font _navBoldFont = null!;             // category-row font (owner-draw)
        private Font _navBadgeFont = null!;            // small right-aligned count badge (owner-draw)
        private ResultsView _scanView = null!;
        private readonly BusyOverlay _emailBusy = new();
        private Panel _toolbar = null!;
        private Panel _introHost = null!;
        private Panel _leftBottom = null!;
        private Button _introButton = null!;   // pastel "Introduction" button pinned above the left panel
        private Image? _introIcon;             // app icon bitmap shown as a banner in the Intro Help

        // Bottom status bar: elevation + network indicators (left) + font-scale control (right).
        private Panel _statusBar = null!;
        private Label _adminIcon = null!;     // Segoe MDL2 shield glyph
        private Label _adminStatus = null!;   // "Administrator" / "Standard user"
        private Label _netStatus = null!;

        // "Needs elevation" affordances: a left-panel call-out (caption + Run-as-Admin button)
        // shown when unelevated, plus the bottom indicator above. When the active section needs
        // admin (and we aren't elevated) these turn orchid; the visible one flashes once.
        private Button? _adminBtn;            // left-panel "Run as Admin" (null when already elevated)
        private bool _currentNeedsAdmin;      // active section needs admin & we aren't elevated
        private bool _adminFlashShown;        // gentle flash fires only once per session
        private System.Windows.Forms.Timer? _adminFlashTimer;
        private int _adminFlashTick;          // ticks elapsed in the current flash run
        private Label _errorBadge = null!;    // "⚠ N errors" - click opens ErrorLogDialog; hidden at 0
        private Label _scaleCaption = null!;
        private Button _scaleMinus = null!;
        private Label _scaleLabel = null!;
        private Button _scalePlus = null!;

        public MainForm()
        {
            // Version and build date come from AppInfo, which set-version.ps1 keeps in sync.
            Text = $"B4-Browse - Chrome Safety Check - {AppInfo.Version} - LanDen Labs  {AppInfo.BuildDate}";
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
                Text = "◀ Menu",
                Width = 84,
                Height = 28,
                Left = 8,
                Top = 7,
                FlatStyle = FlatStyle.System,
            };
            _toggleButton.Click += (_, _) => ToggleLeftPanel();
            _tips.SetToolTip(_toggleButton, "Show / hide the category navigation panel");

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

            // -- Left navigation: a category tree + Intro button + theme/about footer --
            _leftPanel = new Panel { Dock = DockStyle.Left, Width = 240, BackColor = Theme.Panel };

            // Theme toggle + About pinned to the lower-left of the panel.
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
            aboutButton.Click += (_, _) => { try { var f = new AboutForm(); f.Show(); } catch { CopyableMessageBox.Show(this, "B4-Browse - Chrome Safety Check\n\nA small tool to inspect Chrome, extensions, and local system indicators relevant to browsing safety.", "About B4-Browse", MessageBoxButtons.OK, MessageBoxIcon.Information); } };
            tip.SetToolTip(aboutButton, "About B4-Browse");

            _leftBottom.Controls.Add(themeIcon);
            _leftBottom.Controls.Add(themeLabel);
            _leftBottom.Controls.Add(aboutButton);

            // Note: theme icon intentionally left unmodified so it always displays the original asset.

            // "Introduction" button pinned to the very top of the panel - a soft pastel-blue
            // call-out that opens the welcome / overview Help.
            _introHost = new Panel
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
            _tips.SetToolTip(_introButton, "What B4-Browse does and how to use the categories");
            _introHost.Controls.Add(_introButton);
            StyleIntroButton();   // pastel colours, re-applied on theme change by ApplyThemeColors

            // -- Content host + category tree navigation (replaces the old tab strip) --
            _content = new Panel { Dock = DockStyle.Fill, BackColor = Theme.Surface };

            _navBoldFont = new Font("Segoe UI", 10.5f, FontStyle.Bold);
            _navBadgeFont = new Font("Segoe UI", 8.25f);
            _nav = new TreeView
            {
                Dock = DockStyle.Fill,
                BorderStyle = BorderStyle.None,
                Font = new Font("Segoe UI", 10.5f),
                ItemHeight = 30,
                Indent = 18,
                FullRowSelect = true,
                ShowLines = false,
                ShowPlusMinus = false,
                ShowRootLines = false,
                HideSelection = false,
                DrawMode = TreeViewDrawMode.OwnerDrawText,
                BackColor = Theme.Panel,
                ForeColor = Theme.Text,
            };
            _nav.DrawNode += DrawNavNode;
            _nav.AfterSelect += (_, e) => { if (e.Node?.Tag is Catalog.Section sec) ShowSection(sec); };
            _nav.BeforeCollapse += (_, e) => e.Cancel = true;   // keep categories expanded

            foreach (var cat in Catalog.Categories)
            {
                var secs = Catalog.InCategory(cat, Elevation.IsAdmin).ToList();
                if (secs.Count == 0) continue;
                var catNode = new TreeNode(cat);   // a null Tag marks a category row
                foreach (var s in secs) catNode.Nodes.Add(new TreeNode(s.Title) { Tag = s });
                _nav.Nodes.Add(catNode);
            }
            _nav.ExpandAll();

            // "Run as Admin" call-out at the top of the panel when not elevated. Neutral by
            // default; turns orchid (with a one-time flash) only while the active section needs admin.
            Panel? adminHost = null;
            if (!Elevation.IsAdmin)
            {
                adminHost = new Panel { Dock = DockStyle.Top, Height = 44, BackColor = Theme.Panel, Padding = new Padding(10, 4, 10, 6) };
                _adminBtn = new Button { Text = "Run as Admin", Dock = DockStyle.Fill };
                Theme.StyleButton(_adminBtn);   // flat, so its colour is controllable for the needs-admin state
                _adminBtn.Click += (_, _) => RelaunchAsAdmin();
                _tips.SetToolTip(_adminBtn, "Relaunch elevated to read the Security log, SRUM, Defender history and restore points");
                adminHost.Controls.Add(_adminBtn);
            }

            // Assemble the left panel: Fill (nav) first, then Bottom, then Tops (outermost added last).
            _leftPanel.Controls.Add(_nav);
            _leftPanel.Controls.Add(_leftBottom);
            if (adminHost != null) _leftPanel.Controls.Add(adminHost);
            _leftPanel.Controls.Add(_introHost);

            BuildStatusBar();

            // Z-order: Fill content first, then docked edges (outermost added last).
            Controls.Add(_content);
            Controls.Add(_leftPanel);
            Controls.Add(_statusBar);
            Controls.Add(toolbar);
            Controls.Add(_banner);
            Controls.Add(_emailBusy);   // floating spinner shown while an email report builds

            // Build + select the Safety Scan section by default (sets _scanView, wires Completed).
            ShowSection(Catalog.Find("scan")!);
            SelectNodeFor(_current!);

            UpdateBanner(); // initial banner for the active (Safety Scan) section
            UpdateAdminStatus();
            UpdateNetStatus();
            UpdateScaleLabel();
            ApplyThemeColors(); // paint buttons/chrome for the startup theme
            Theme.Changed += () => { ApplyThemeColors(); UpdateBanner(); _nav.Invalidate(); };
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
                : (_currentNeedsAdmin ? Theme.AdminAccent : Theme.Subtle);  // orchid when the active panel needs admin
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

        /// <summary>
        /// Paints the elevation affordances (left-panel caption + Run-as-Admin button, and the
        /// bottom indicator) for the current "does the active section need admin?" state. Orchid
        /// when it does, neutral when it doesn't. The single authority for that colouring; called
        /// from <see cref="ShowSection"/> on navigation and from the theme re-paint.
        /// </summary>
        private void ApplyAdminAffordanceState(bool needsAdmin)
        {
            _currentNeedsAdmin = needsAdmin;
            UpdateAdminStatus();   // bottom indicator (orchid-aware via _currentNeedsAdmin)

            if (_adminBtn == null) return;   // already elevated: no call-out

            if (needsAdmin)
            {
                _adminBtn.BackColor = Theme.AdminAccentSoft;
                _adminBtn.ForeColor = Theme.AdminAccent;
                _adminBtn.FlatAppearance.BorderColor = Theme.AdminAccent;
            }
            else
            {
                Theme.StyleButton(_adminBtn);   // back to neutral ButtonBack/Text/border
            }
        }

        /// <summary>Begins a gentle one-shot pulse of the *visible* elevation affordance (the
        /// left button when the panel is open, else the bottom indicator) over ~3 seconds,
        /// settling on the steady orchid state. Fired once per session from <see cref="ShowSection"/>.</summary>
        private void StartAdminFlash()
        {
            _adminFlashTimer ??= new System.Windows.Forms.Timer { Interval = 150 };
            _adminFlashTimer.Tick -= AdminFlashTick;
            _adminFlashTimer.Tick += AdminFlashTick;
            _adminFlashTick = 0;
            _adminFlashTimer.Start();
        }

        private void AdminFlashTick(object? sender, EventArgs e)
        {
            const int ticks = 20;       // 20 * 150ms ~= 3s
            const double cycles = 2.0;  // two slow pulses
            _adminFlashTick++;
            if (_adminFlashTick > ticks)
            {
                _adminFlashTimer!.Stop();
                ApplyAdminAffordanceState(_currentNeedsAdmin);   // settle on the steady state
                return;
            }
            double t = (double)_adminFlashTick / ticks;
            double k = (1 - Math.Cos(2 * Math.PI * cycles * t)) / 2;   // gentle 0->1->0 ease, twice

            bool useButton = _leftPanel.Visible && _adminBtn != null;
            if (useButton)
            {
                _adminBtn!.BackColor = Lerp(Theme.ButtonBack, Theme.AdminAccentSoft, k);
                _adminBtn.ForeColor = Lerp(Theme.Text, Theme.AdminAccent, k);
                _adminBtn.FlatAppearance.BorderColor = Lerp(Theme.ButtonBorder, Theme.AdminAccent, k);
            }
            else
            {
                Color c = Lerp(Theme.Subtle, Theme.AdminAccent, k);
                _adminIcon.ForeColor = c;
                _adminStatus.ForeColor = c;
            }
        }

        /// <summary>Linear blend between two colours (t in 0..1).</summary>
        private static Color Lerp(Color a, Color b, double t)
        {
            t = Math.Clamp(t, 0, 1);
            int Mix(int x, int y) => (int)Math.Round(x + (y - x) * t);
            return Color.FromArgb(Mix(a.R, b.R), Mix(a.G, b.G), Mix(a.B, b.B));
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
            _adminFlashTimer?.Stop();
            _adminFlashTimer?.Dispose();
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
            _introHost.BackColor = Theme.Panel;
            if (_nav != null)
            {
                _nav.BackColor = Theme.Panel;
                _nav.ForeColor = Theme.Text;
                _nav.Invalidate();
            }
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
            ApplyAdminAffordanceState(_currentNeedsAdmin);   // restore orchid/neutral after the generic repaint

            // Native scrollbars (nav tree, grids, rich-text panes, scrolling tool panels) follow the
            // window theme, not managed colours - retheme them across every built view.
            Theme.ApplyScrollbarTheme(this);
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

        // ---- Tree navigation: lazy build, run, severity colouring ---------------- //

        /// <summary>Shows a section's view in the content host, building and caching it on first
        /// use, and lazily running its checks once the window is visible.</summary>
        private void ShowSection(Catalog.Section sec)
        {
            if (sec.BuildView == null) return;
            if (!_views.TryGetValue(sec, out var view))
            {
                view = sec.BuildView();
                view.Dock = DockStyle.Fill;
                _content.Controls.Add(view);
                if (view is ResultsView rv && sec.Key == "scan")
                    _scanView = rv;
                if (view is ITabView tv) tv.SeverityChanged += OnSectionSeverity;
                _views[sec] = view;
            }

            foreach (Control c in _content.Controls) c.Visible = ReferenceEquals(c, view);
            view.BringToFront();
            _current = sec;

            // Elevation cue: orchid the Run-as-Admin affordances while this section is degraded
            // without admin, and flash the visible one once (first needs-admin panel this session).
            bool needs = !Elevation.IsAdmin && sec.NeedsAdmin;
            ApplyAdminAffordanceState(needs);
            if (needs && !_adminFlashShown) { _adminFlashShown = true; StartAdminFlash(); }

            if (IsHandleCreated && view is ITabView t && !t.HasRun) _ = t.RunAsync();
            UpdateBanner();
            _nav.Invalidate();
        }

        /// <summary>Selects the tree node bound to a section (drives the highlight).</summary>
        private void SelectNodeFor(Catalog.Section sec)
        {
            foreach (TreeNode cat in _nav.Nodes)
                foreach (TreeNode n in cat.Nodes)
                    if (ReferenceEquals(n.Tag, sec)) { _nav.SelectedNode = n; return; }
        }

        /// <summary>Current severity of a section (None until its view is built and has run).</summary>
        private TabSeverity SevOf(Catalog.Section sec) =>
            _views.TryGetValue(sec, out var v) && v is ITabView tv ? tv.Severity : TabSeverity.None;

        /// <summary>Count summary of a section (null until its view is built and has run).</summary>
        private (int Total, int Risk)? CountsOf(Catalog.Section sec) =>
            _views.TryGetValue(sec, out var v) && v is ITabView tv ? tv.NavCounts : null;

        /// <summary>Rolls a category row's badge up from the counts of its visited child sections
        /// (null when none have run yet).</summary>
        private (int Total, int Risk)? CategoryCounts(TreeNode catNode)
        {
            int total = 0, risk = 0;
            bool any = false;
            foreach (TreeNode child in catNode.Nodes)
                if (child.Tag is Catalog.Section cs && CountsOf(cs) is { } c)
                {
                    total += c.Total;
                    risk += c.Risk;
                    any = true;
                }
            return any ? (total, risk) : null;
        }

        /// <summary>Formats a nav count badge: total always, with a "· N⚠" suffix when any item
        /// warrants review (e.g. "142" or "142 · 3⚠"). Empty string when there is nothing to show.</summary>
        private static string FormatBadge((int Total, int Risk)? counts)
        {
            if (counts is not { } c) return "";
            return c.Risk > 0 ? $"{c.Total} · {c.Risk}⚠" : c.Total.ToString();
        }

        /// <summary>A section's severity changed (after a run) - repaint the tree + banner.</summary>
        private void OnSectionSeverity()
        {
            if (_nav.IsHandleCreated)
                _nav.BeginInvoke(new Action(() => { _nav.Invalidate(); UpdateBanner(); }));
        }

        /// <summary>Owner-draws a nav row tinted by severity. Section rows use their own severity;
        /// a category row rolls up the worst severity of its sections.</summary>
        private void DrawNavNode(object? sender, DrawTreeNodeEventArgs e)
        {
            var node = e.Node;
            if (node == null || e.Bounds.Height <= 0) return;

            bool selected = (e.State & TreeNodeStates.Selected) != 0;

            TabSeverity sev;
            bool isCategory;
            bool needsElevationDot = false;   // section needs admin & we aren't elevated
            (int Total, int Risk)? counts;
            if (node.Tag is Catalog.Section section)
            {
                isCategory = false;
                sev = SevOf(section);
                counts = CountsOf(section);
                needsElevationDot = !Elevation.IsAdmin && section.NeedsAdmin;
            }
            else
            {
                isCategory = true;
                sev = TabSeverity.None;
                foreach (TreeNode child in node.Nodes)
                    if (child.Tag is Catalog.Section cs) sev = Sev.Max(sev, SevOf(cs));
                counts = CategoryCounts(node);
            }

            var row = new Rectangle(0, e.Bounds.Top, _nav.ClientSize.Width, e.Bounds.Height);
            Color back = sev == TabSeverity.None
                ? (selected ? Theme.NeutralTab(true) : Theme.Panel)
                : SeverityColor(sev, selected);
            Color fore = sev == TabSeverity.None ? Theme.Text : Color.FromArgb(30, 30, 30);

            using (var b = new SolidBrush(back)) e.Graphics.FillRectangle(b, row);

            // Right-aligned count badge, drawn in a muted shade. Section rows show "total · N⚠";
            // category rows roll up to risk-only ("N⚠") since summing unrelated item counts is noise.
            // Reserve the badge width so the title's ellipsis stops short rather than overlapping.
            string badge = isCategory
                ? (counts is { Risk: > 0 } cc ? $"{cc.Risk}⚠" : "")
                : FormatBadge(counts);
            int badgeW = 0;
            if (badge.Length > 0)
            {
                Size bs = TextRenderer.MeasureText(e.Graphics, badge, _navBadgeFont);
                badgeW = bs.Width;
                var badgeRect = new Rectangle(row.Width - badgeW - 10, e.Bounds.Top, badgeW, e.Bounds.Height);
                Color badgeFore = sev == TabSeverity.None
                    ? Theme.Subtle
                    : Color.FromArgb(70, 70, 70);   // dark-but-muted on a light severity tint
                TextRenderer.DrawText(e.Graphics, badge, _navBadgeFont, badgeRect, badgeFore,
                    TextFormatFlags.VerticalCenter | TextFormatFlags.Right | TextFormatFlags.NoPadding);
            }

            // A small orchid dot in the left gutter marks sections that need elevation we don't have.
            if (needsElevationDot)
            {
                const int d = 7;
                int dx = Math.Max(3, e.Bounds.X - 12);
                int dy = e.Bounds.Top + (e.Bounds.Height - d) / 2;
                var prevMode = e.Graphics.SmoothingMode;
                e.Graphics.SmoothingMode = System.Drawing.Drawing2D.SmoothingMode.AntiAlias;
                using (var db = new SolidBrush(Theme.AdminAccent)) e.Graphics.FillEllipse(db, dx, dy, d, d);
                e.Graphics.SmoothingMode = prevMode;
            }

            var font = isCategory ? _navBoldFont : _nav.Font;
            int textLeft = isCategory ? 8 : e.Bounds.X;
            int textRight = badgeW > 0 ? badgeW + 16 : 4;   // leave a gap before the badge
            var textRect = new Rectangle(textLeft, e.Bounds.Top, row.Width - textLeft - textRight, e.Bounds.Height);
            TextRenderer.DrawText(e.Graphics, node.Text, font, textRect, fore,
                TextFormatFlags.VerticalCenter | TextFormatFlags.Left | TextFormatFlags.EndEllipsis);
        }

        protected override void OnShown(EventArgs e)
        {
            base.OnShown(e);
            Theme.ApplyScrollbarTheme(this);   // initial native-scrollbar theme (handles now exist)
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

        /// <summary>Tab/banner background colour for a severity (selected = stronger shade).</summary>
        private static Color SeverityColor(TabSeverity sev, bool selected) => sev switch
        {
            TabSeverity.Alert => selected ? Color.FromArgb(250, 170, 170) : Color.FromArgb(252, 214, 214),
            TabSeverity.Caution => selected ? Color.FromArgb(252, 226, 140) : Color.FromArgb(255, 244, 200),
            TabSeverity.Ok => selected ? Color.FromArgb(190, 230, 190) : Color.FromArgb(224, 244, 224),
            _ => Theme.NeutralTab(selected),
        };

        /// <summary>Banner shows the active section's title; its colour matches that section once it has run.</summary>
        private void UpdateBanner()
        {
            if (_current == null) return;
            TabSeverity sev = SevOf(_current);

            _banner.Text = _current.BannerOrTitle;
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

        private void ToggleLeftPanel()
        {
            _leftPanel.Visible = !_leftPanel.Visible;
            _toggleButton.Text = _leftPanel.Visible ? "◀ Menu" : "▶ Menu";
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
            string scope = _current?.Key ?? "scan";
            string tabName = _current?.Title ?? scope;

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
            string scope = _current?.Key ?? "scan";

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
            string scope = _current?.Key ?? "scan";
            string tabName = _current?.Title ?? scope;

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
            if (reportText != null) PrintReport(reportText, $"B4-Browse - {tabName}");
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

    }
}
