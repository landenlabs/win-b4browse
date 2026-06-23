// Copyright (c) 2026 LanDen Labs - Dennis Lang

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace B4Browse
{
    /// <summary>How a column exposes an interactive filter in the grid's filter bar.</summary>
    public enum ColumnFilterKind { None, Dropdown, Regex }

    /// <summary>Declarative column for <see cref="SortableGrid"/>.</summary>
    public sealed class GridColumn
    {
        public string Header = "";
        public int Width = 100;
        public int Fill = 0;                                  // >0 => fill column with this weight
        public bool Button = false;                           // render as a clickable button cell
        public bool Link = false;                             // render as a clickable link cell
        public string ButtonText = "";
        public Func<object, string> Text = _ => "";           // cell display text
        public Func<object, string>? LinkTarget = null;       // for Link cells: URL to open (defaults to the displayed Text)
        public Func<object, IComparable>? Sort = null;        // sort key (defaults to Text)
        public Func<object, (Color Back, Color Fore)?>? Style = null; // per-cell colour
        public ColumnFilterKind FilterKind = ColumnFilterKind.None;   // interactive filter, if any
        public Func<object, string>? FilterValue = null;      // text tested by the filter (defaults to Text)
    }

    /// <summary>
    /// A reusable, sortable, scrollable data grid tab. Configured with columns and
    /// a background loader; supports an optional button column, extra toolbar
    /// buttons, and a summary line. Implements <see cref="ITabView"/> for lazy run.
    /// </summary>
    public sealed class SortableGrid : UserControl, ITabView
    {
        private readonly DataGridView _grid;
        private readonly Button _refresh;
        private readonly Label _status;
        private Font? _statusFont;       // base summary font
        private Font? _statusBoldFont;   // bold summary font for an elevation notice
        private readonly Func<List<object>> _loader;
        private readonly Func<string>? _summary;
        private readonly GridColumn[] _cols;
        private readonly Action<object>? _onButton;
        private readonly Func<CheckGroup>? _headerInfo;
        private readonly RichTextBox? _header;
        // Clickable inline links in the header pane: char range -> URI to open.
        private readonly List<(int Start, int End, string Uri)> _headerLinks = new();
        private readonly BusyOverlay _busy = new();
        private readonly Func<IReadOnlyList<object>, TabSeverity>? _severityEval;
        private readonly Func<object, bool>? _riskRow;   // per-row "warrants review" test for the nav count badge
        private readonly Func<object, bool>? _dimRow;    // per-row "dim this row" — mutes text for shadowed/superseded rows
        private readonly Action<object>? _onRowContext;
        private readonly CheckBox? _toggle;
        private readonly Func<object, bool>? _hideWhenOff;
        // Extra toolbar buttons, keyed by label, so callers can enable/disable one
        // (e.g. disable "Remove unsupported" while a removal is in flight).
        private readonly Dictionary<string, Button> _extraButtons = new();

        public TabSeverity Severity { get; private set; } = TabSeverity.None;
        public event Action? SeverityChanged;

        /// <summary>Total = loaded rows; Risk = rows matching <see cref="_riskRow"/> (0 when no
        /// predicate was supplied). Null until the grid has loaded. Drives the nav-row count badge.</summary>
        public (int Total, int Risk)? NavCounts =>
            HasRun ? (_items.Count, _riskRow != null ? _items.Count(_riskRow) : 0) : null;

        private static Color HdrPass => Theme.IsDark ? Color.FromArgb(90, 200, 100) : Color.FromArgb(0, 140, 0);
        private static Color HdrWarn => Theme.IsDark ? Color.FromArgb(232, 184, 64) : Color.FromArgb(190, 120, 0);
        private static Color HdrFail => Theme.IsDark ? Color.FromArgb(240, 110, 110) : Color.FromArgb(200, 0, 0);
        private static Color HdrInfo => Theme.Subtle;

        private Panel? _topPanel;
        private Button? _help;
        private Panel? _headerPanel;
        private CheckGroup? _lastHeader;
        private List<object> _items = new();
        private int _sortCol;
        private bool _asc;
        private bool _loading;
        private CancellationTokenSource? _cts;
        private int _buttonColIndex = -1;
        // True when the next Populate should re-fit column widths to content (set on data/scale
        // changes, cleared after fitting). Pure view changes - sort, filter, theme - leave it
        // false so the user's manual column widths are preserved.
        private bool _autoFitPending;

        // ---- Per-column filter bar (optional) ---------------------------- //
        private Panel? _filterBar;
        private Label? _filterCount;                          // "showing N of M"
        private readonly List<FilterControl> _filters = new();

        /// <summary>One interactive filter wired to a column.</summary>
        private sealed class FilterControl
        {
            public int ColIndex;
            public ColumnFilterKind Kind;
            public Func<object, string> Value = _ => "";       // text tested for this column
            public ComboBox? Combo;                            // Dropdown
            public TextBox? Box;                               // Regex
            public Regex? Compiled;                            // cached valid pattern (Regex kind)
        }

        public bool HasRun { get; private set; }

        public SortableGrid(
            string runLabel,
            Func<List<object>> loader,
            GridColumn[] columns,
            int defaultSortColumn,
            bool defaultAscending,
            Action<object>? onButtonClick = null,
            IEnumerable<(string Label, Action OnClick)>? extraButtons = null,
            Func<string>? summary = null,
            Func<CheckGroup>? headerInfo = null,
            Func<IReadOnlyList<object>, TabSeverity>? severity = null,
            Action<object>? onRowContext = null,
            (string Label, string Tooltip, Func<object, bool> HideWhenOff)? showAllToggle = null,
            (string Label, Action OnClick)? headerButton = null,
            HelpInfo? help = null,
            int headerHeight = 104,
            Func<object, bool>? riskRow = null,
            Func<object, bool>? dimRow = null)
        {
            _loader = loader;
            _cols = columns;
            _onButton = onButtonClick;
            _dimRow = dimRow;
            _summary = summary;
            _headerInfo = headerInfo;
            _severityEval = severity;
            _riskRow = riskRow;
            _onRowContext = onRowContext;
            _sortCol = defaultSortColumn;
            _asc = defaultAscending;

            Dock = DockStyle.Fill;
            BackColor = Theme.Surface;

            var top = new Panel { Dock = DockStyle.Top, Height = 40, BackColor = Theme.Toolbar };
            _topPanel = top;

            int x = 8;
            if (showAllToggle is { } st)
            {
                _hideWhenOff = st.HideWhenOff;
                int w = TextRenderer.MeasureText(st.Label, Font).Width + 26;
                _toggle = new CheckBox
                {
                    Text = st.Label, Left = x, Top = 9, Width = w, Height = 24, Checked = false,
                    ForeColor = Theme.Text, BackColor = Color.Transparent,
                };
                _toggle.CheckedChanged += (_, _) => Populate();
                if (!string.IsNullOrEmpty(st.Tooltip)) _toggleTip.SetToolTip(_toggle, st.Tooltip);
                top.Controls.Add(_toggle);
                x += w + 8;
            }

            _refresh = new Button
            {
                Text = runLabel, Width = 90, Height = 28, Left = x, Top = 6,
                FlatStyle = FlatStyle.System, Font = new Font("Segoe UI", 9f, FontStyle.Bold),
            };
            _refresh.Click += async (_, _) => await RunAsync();
            top.Controls.Add(_refresh);
            x = _refresh.Right + 6;

            if (extraButtons != null)
            {
                foreach (var (label, onClick) in extraButtons)
                {
                    var b = new Button
                    {
                        Text = label, Height = 28, Top = 6, Left = x,
                        Width = TextRenderer.MeasureText(label, Font).Width + 28,
                        FlatStyle = FlatStyle.System,
                    };
                    b.Click += (_, _) => onClick();
                    top.Controls.Add(b);
                    _extraButtons[label] = b;
                    x += b.Width + 6;
                }
            }

            _status = new Label
            {
                AutoSize = true, Left = x + 4, Top = 12, ForeColor = Theme.Subtle,
                Text = "Click " + runLabel + ".",
            };
            top.Controls.Add(_status);
            _statusFont = _status.Font;
            _statusBoldFont = new Font(_status.Font, FontStyle.Bold);

            if (help != null)
            {
                // A real Help button, anchored to the right edge, opens a description dialog.
                _help = HelpUi.CreateButton(help);
                _help.Top = 7;
                _help.Anchor = AnchorStyles.Top | AnchorStyles.Right;
                top.Controls.Add(_help);
                top.SizeChanged += (_, _) => LayoutHelp();
                LayoutHelp();
            }

            _grid = new DataGridView
            {
                Dock = DockStyle.Fill,
                AllowUserToAddRows = false,
                AllowUserToDeleteRows = false,
                AllowUserToResizeRows = false,
                EditMode = DataGridViewEditMode.EditProgrammatically,
                RowHeadersVisible = false,
                SelectionMode = DataGridViewSelectionMode.FullRowSelect,
                MultiSelect = false,
                AutoGenerateColumns = false,
                BackgroundColor = Theme.Surface,
                BorderStyle = BorderStyle.None,
                // Header and rows auto-size to the (scalable) cell font so the [ - 100% + ]
                // control grows the whole content area, not just the glyphs.
                ColumnHeadersHeightSizeMode = DataGridViewColumnHeadersHeightSizeMode.AutoSize,
                AutoSizeRowsMode = DataGridViewAutoSizeRowsMode.DisplayedCells,
                EnableHeadersVisualStyles = false,
                GridColor = Theme.GridLine,
                Font = Theme.Scaled("Segoe UI", 9f),
            };
            _grid.DefaultCellStyle.Font = Theme.Scaled("Segoe UI", 9f);
            _grid.DefaultCellStyle.BackColor = Theme.Surface;
            _grid.DefaultCellStyle.ForeColor = Theme.Text;
            _grid.DefaultCellStyle.SelectionBackColor = Theme.IsDark ? Color.FromArgb(70, 80, 100) : Color.FromArgb(200, 220, 245);
            _grid.DefaultCellStyle.SelectionForeColor = Theme.Text;
            _grid.ColumnHeadersDefaultCellStyle.Font = Theme.Scaled("Segoe UI", 9f);
            _grid.ColumnHeadersDefaultCellStyle.BackColor = Theme.Toolbar;
            _grid.ColumnHeadersDefaultCellStyle.ForeColor = Theme.Text;

            for (int i = 0; i < _cols.Length; i++)
            {
                var c = _cols[i];
                DataGridViewColumn col;
                if (c.Button)
                {
                    _buttonColIndex = i;
                    col = new DataGridViewButtonColumn
                    {
                        Text = c.ButtonText, UseColumnTextForButtonValue = true,
                        FlatStyle = FlatStyle.System,
                        SortMode = DataGridViewColumnSortMode.NotSortable,
                    };
                }
                else if (c.Link)
                {
                    col = new DataGridViewLinkColumn
                    {
                        TrackVisitedState = false,
                        SortMode = DataGridViewColumnSortMode.Programmatic,
                    };
                }
                else
                {
                    col = new DataGridViewTextBoxColumn
                    {
                        ReadOnly = true,
                        SortMode = DataGridViewColumnSortMode.Programmatic,
                    };
                }
                col.HeaderText = c.Header;
                // Explicit widths only (no Fill auto-size). The on-load content fit decides the
                // default width; a 2px MinimumWidth lets the user drag any column down to nothing
                // (Fill mode and a content-sized MinimumWidth both blocked that). The initial width
                // is just a placeholder until the first load auto-fits it.
                col.AutoSizeMode = DataGridViewAutoSizeColumnMode.None;
                col.MinimumWidth = 2;
                col.Width = c.Fill > 0 ? c.Fill : c.Width;
                _grid.Columns.Add(col);
            }

            _grid.ColumnHeaderMouseClick += OnHeaderClick;
            _grid.CellContentClick += OnCellClick;
            _grid.CellMouseDown += OnCellMouseDown;
            _grid.Paint += OnGridPaint;

            Controls.Add(_grid);
            if (_headerInfo != null)
            {
                _headerPanel = new Panel { Dock = DockStyle.Top, Height = headerHeight, BackColor = Theme.Surface };
                _header = new RichTextBox
                {
                    Dock = DockStyle.Fill,
                    ReadOnly = true,
                    BorderStyle = BorderStyle.None,
                    Font = Theme.Scaled("Consolas", 9f),
                    BackColor = Theme.Surface,
                    ForeColor = Theme.Text,
                    WordWrap = false,
                    ScrollBars = RichTextBoxScrollBars.Vertical,
                };
                _header.MouseDown += HeaderMouseDown;
                _header.MouseMove += HeaderMouseMove;
                var headerPanel = _headerPanel;
                headerPanel.Controls.Add(_header);
                if (headerButton is { } hb)
                {
                    // Reserve a left gutter and place the button beside the "Path" row.
                    headerPanel.Padding = new Padding(86, 0, 0, 0);
                    var b = new Button
                    {
                        Text = hb.Label, Left = 8, Top = 26, Width = 70, Height = 26,
                        FlatStyle = FlatStyle.System,
                    };
                    b.Click += (_, _) => hb.OnClick();
                    headerPanel.Controls.Add(b);
                    b.BringToFront();
                }
                Controls.Add(headerPanel);
            }
            BuildFilterBar();                  // docks below the toolbar (added before `top`)
            Controls.Add(top);

            Controls.Add(_busy);
            _busy.ShowCancel = true;
            _busy.Cancelled += OnCancelRequested;
            Resize += (_, _) => CenterBusy();

            Theme.Changed += OnThemeChanged;
            Theme.ScaleChanged += OnScaleChanged;
            Disposed += (_, _) => { Theme.Changed -= OnThemeChanged; Theme.ScaleChanged -= OnScaleChanged; };
            HandleCreated += (_, _) => Theme.ApplyScrollbarTheme(this);   // theme native grid scrollbars
        }

        private void OnThemeChanged()
        {
            if (!IsHandleCreated) { ApplyTheme(); return; }
            BeginInvoke(new Action(ApplyTheme));
        }

        private void OnScaleChanged()
        {
            if (!IsHandleCreated) { ApplyScale(); return; }
            BeginInvoke(new Action(ApplyScale));
        }

        private void ApplyScale()
        {
            var cellFont = Theme.Scaled("Segoe UI", 9f);
            _grid.Font = cellFont;
            _grid.DefaultCellStyle.Font = cellFont;
            _grid.ColumnHeadersDefaultCellStyle.Font = cellFont;
            if (_header != null) _header.Font = Theme.Scaled("Consolas", 9f);

            if (_items.Count > 0) { _autoFitPending = true; Populate(); }  // refit: glyph metrics changed
            if (_lastHeader != null) RenderHeader(_lastHeader);
            _grid.AutoResizeRows();                      // pick up the new cell-font height
        }

        private void ApplyTheme()
        {
            BackColor = Theme.Surface;
            if (_topPanel != null) _topPanel.BackColor = Theme.Toolbar;
            foreach (Control c in (_topPanel?.Controls ?? (ControlCollection)Controls))
                if (c is Label || c is CheckBox) c.ForeColor = Theme.Subtle;
            if (_toggle != null) _toggle.ForeColor = Theme.Text;
            ApplyStatusStyle();   // restore the orchid tint if the summary is an elevation notice

            _grid.BackgroundColor = Theme.Surface;
            _grid.GridColor = Theme.GridLine;
            _grid.DefaultCellStyle.BackColor = Theme.Surface;
            _grid.DefaultCellStyle.ForeColor = Theme.Text;
            _grid.DefaultCellStyle.SelectionBackColor = Theme.IsDark ? Color.FromArgb(70, 80, 100) : Color.FromArgb(200, 220, 245);
            _grid.DefaultCellStyle.SelectionForeColor = Theme.Text;
            _grid.ColumnHeadersDefaultCellStyle.BackColor = Theme.Toolbar;
            _grid.ColumnHeadersDefaultCellStyle.ForeColor = Theme.Text;

            if (_headerPanel != null) _headerPanel.BackColor = Theme.Surface;
            if (_header != null)
            {
                _header.BackColor = Theme.Surface;
                _header.ForeColor = Theme.Text;
            }

            if (_filterBar != null)
            {
                _filterBar.BackColor = Theme.Toolbar;
                foreach (Control c in _filterBar.Controls)
                    if (c is Label) c.ForeColor = Theme.Subtle;
                foreach (var fc in _filters)
                {
                    if (fc.Box == null) continue;
                    fc.Box.ForeColor = Theme.Text;
                    // Keep the error tint for an invalid pattern; otherwise reset to surface.
                    fc.Box.BackColor = fc.Compiled == null && fc.Box.Text.Length > 0
                        ? RegexErrorBack : Theme.Surface;
                }
            }

            if (_items.Count > 0) Populate();          // re-apply default cell colours
            if (_lastHeader != null) RenderHeader(_lastHeader);
            Theme.ApplyScrollbarTheme(this);           // re-theme native grid / header scrollbars
        }

        private void CenterBusy()
        {
            _busy.Left = Math.Max(0, (ClientSize.Width - _busy.Width) / 2);
            _busy.Top = Math.Max(40, (ClientSize.Height - _busy.Height) / 2);
        }

        public void SetStatus(string text) => SetStatusText(text);

        /// <summary>Enables or disables an extra toolbar button by its label (no-op if unknown).</summary>
        public void SetExtraButtonEnabled(string label, bool enabled)
        {
            if (_extraButtons.TryGetValue(label, out var b)) b.Enabled = enabled;
        }

        /// <summary>Keeps the Help button pinned to the right edge of the toolbar.</summary>
        private void LayoutHelp()
        {
            if (_help == null || _topPanel == null) return;
            _help.Left = Math.Max(0, _topPanel.ClientSize.Width - _help.Width - 8);
        }

        /// <summary>The currently loaded row objects (e.g. for an in-place enrich-then-refresh action).</summary>
        public IReadOnlyList<object> Items => _items;

        /// <summary>Re-render the rows in place (no reload/re-sort) and re-evaluate tab severity.
        /// Use after mutating the loaded row objects, e.g. an INF scan that fills a risk column.</summary>
        public void RefreshDisplay()
        {
            _autoFitPending = true;        // rows were mutated in place: refit to the new content
            Populate();
            Severity = _severityEval?.Invoke(_items) ?? TabSeverity.None;
            SeverityChanged?.Invoke();
        }

        public async Task RunAsync()
        {
            if (_loading) return;
            _loading = true;
            _refresh.Enabled = false;
            SetStatusText("Loading …");

            _cts = new CancellationTokenSource();
            var token = _cts.Token;
            _grid.Invalidate();   // clear the "Press Refresh" watermark while loading

            CenterBusy();
            _busy.Start();
            bool cancelled = false;
            try
            {
                string? summaryText = null;
                CheckGroup? headerGroup = null;

                // The loader is synchronous and not itself cancellable, but its blocking calls are
                // bounded by their own timeouts. On cancel we stop awaiting and abandon the worker -
                // it finishes on its own within those bounds (same pattern as ResultsView).
                var work = Task.Run(() =>
                {
                    if (_summary != null) summaryText = SafeSummary();
                    if (_headerInfo != null) { try { headerGroup = _headerInfo(); } catch { /* ignore */ } }
                    return _loader();
                });
                var done = await Task.WhenAny(work, Task.Delay(Timeout.Infinite, token));
                if (done != work)
                {
                    // Abandoned: swallow any later fault so it isn't an unobserved task exception.
                    _ = work.ContinueWith(static t => { _ = t.Exception; },
                        TaskContinuationOptions.OnlyOnFaulted | TaskContinuationOptions.ExecuteSynchronously);
                    cancelled = true;
                }
                else
                {
                    _items = await work;
                    _lastHeader = headerGroup;
                    if (_header != null && headerGroup != null) RenderHeader(headerGroup);
                    RebuildFilterChoices();
                    SortItems();
                    _autoFitPending = true;        // new data: re-fit column widths to its content
                    Populate();

                    string count = $"{_items.Count} item(s)   -   {DateTime.Now:HH:mm:ss}";
                    SetStatusText(summaryText != null ? $"{summaryText}      |      {count}" : count);
                }
            }
            finally
            {
                _busy.Stop();
                if (!cancelled) HasRun = true;
                _refresh.Enabled = true;
                _loading = false;
                _cts.Dispose();
                _cts = null;
            }

            // A cancelled run leaves any previously loaded rows and severity untouched.
            if (cancelled)
            {
                SetStatusText(HasRun ? "Cancelled - previous results shown." : "Cancelled.");
                return;
            }

            Severity = _severityEval?.Invoke(_items) ?? TabSeverity.None;
            SeverityChanged?.Invoke();
        }

        private void OnCancelRequested()
        {
            SetStatusText("Cancelling …");
            _cts?.Cancel();
        }

        /// <summary>Draws a centered "Press Refresh to load the table" hint over the empty grid
        /// before the first load. Disappears once the grid has loaded (HasRun = true).</summary>
        private void OnGridPaint(object? sender, PaintEventArgs e)
        {
            if (HasRun || _loading) return;
            const string msg = "Press Refresh to load the table";
            using var font = new Font("Segoe UI", 12f, FontStyle.Italic);
            var sz = e.Graphics.MeasureString(msg, font);
            float x = (_grid.ClientSize.Width - sz.Width) / 2f;
            float y = (_grid.ClientSize.Height - sz.Height) / 2f;
            using var brush = new SolidBrush(Theme.Subtle);
            e.Graphics.DrawString(msg, font, brush, Math.Max(0f, x), Math.Max(0f, y));
        }

        private string SafeSummary()
        {
            try { return _summary!(); } catch { return ""; }
        }

        /// <summary>Sets the status/summary text and tints it: an "elevation required" summary
        /// (e.g. Downloads' "Requires administrator …", Virus' "run as Admin …") is shown in the
        /// orchid accent + bold to tie it to the Run-as-Admin button; anything else stays neutral.</summary>
        private void SetStatusText(string text)
        {
            _status.Text = text;
            ApplyStatusStyle();
        }

        private void ApplyStatusStyle()
        {
            bool elevate = _status.Text.StartsWith("Requires administrator", StringComparison.OrdinalIgnoreCase)
                        || _status.Text.Contains("run as Admin", StringComparison.OrdinalIgnoreCase);
            _status.ForeColor = elevate ? Theme.AdminAccent : Theme.Subtle;
            _status.Font = elevate ? (_statusBoldFont ?? _status.Font) : (_statusFont ?? _status.Font);
        }

        private void RenderHeader(CheckGroup g)
        {
            if (_header == null) return;
            _header.Clear();
            _headerLinks.Clear();

            void Append(string text, Color color, FontStyle style = FontStyle.Regular, float size = 9f)
            {
                _header.SelectionStart = _header.TextLength;
                _header.SelectionColor = color;
                _header.SelectionFont = Theme.Scaled("Consolas", size, style);
                _header.AppendText(text);
            }

            Append(g.Title + "\n", Theme.Text, FontStyle.Bold, 10f);
            foreach (var r in g.Results)
            {
                Color c = r.Status switch
                {
                    CheckStatus.Pass => HdrPass,
                    CheckStatus.Warn => HdrWarn,
                    CheckStatus.Fail => HdrFail,
                    _ => HdrInfo,
                };
                string tag = r.Status switch
                {
                    CheckStatus.Pass => "[PASS] ",
                    CheckStatus.Warn => "[WARN] ",
                    CheckStatus.Fail => "[FAIL] ",
                    _ => "       ",
                };
                Append(tag, c, FontStyle.Bold);
                Append(r.Name, Theme.Text, FontStyle.Bold);

                // Inline clickable link (e.g. "[ open settings ]") placed before the detail so
                // it stays visible even when the detail text is long (header has no h-scroll).
                if (!string.IsNullOrEmpty(r.LinkUri) && !string.IsNullOrEmpty(r.LinkLabel))
                {
                    Append("  ", HdrInfo);
                    int start = _header.TextLength;
                    Append(r.LinkLabel!, Theme.Link, FontStyle.Underline);
                    _headerLinks.Add((start, _header.TextLength, r.LinkUri!));
                }

                if (!string.IsNullOrEmpty(r.Detail)) Append("  -  " + r.Detail, HdrInfo);
                Append("\n", Theme.Text);
            }
            _header.SelectionStart = 0;
            _header.ScrollToCaret();
        }

        // ---- Header inline links ---------------------------------------- //
        private string? HeaderLinkAt(Point p)
        {
            if (_header == null) return null;
            foreach (var (start, end, uri) in _headerLinks)
            {
                if (start < 0 || end <= start) continue;
                Point a = _header.GetPositionFromCharIndex(start);
                Point b = _header.GetPositionFromCharIndex(end);
                if (b.Y < a.Y) continue;
                int h = (int)Math.Ceiling(_header.Font.GetHeight()) + 4;
                var rect = new Rectangle(a.X, a.Y, Math.Max(1, b.X - a.X), h);
                if (rect.Contains(p)) return uri;
            }
            return null;
        }

        private void HeaderMouseDown(object? sender, MouseEventArgs e)
        {
            if (e.Button != MouseButtons.Left) return;
            string? uri = HeaderLinkAt(e.Location);
            if (uri != null) OpenSettingUri(uri);
        }

        // Held in a field so it is not garbage-collected; a ToolTip with no live reference
        // stops showing. Backs the "All" toggle's hover tooltip on every tab.
        private readonly ToolTip _toggleTip = new();

        private void HeaderMouseMove(object? sender, MouseEventArgs e)
        {
            if (_header == null) return;
            _header.Cursor = HeaderLinkAt(e.Location) != null ? Cursors.Hand : Cursors.IBeam;
        }

        /// <summary>
        /// Opens a settings link. Non-Chrome URIs (ms-settings:, windowsdefender:, *.msc, ...)
        /// open directly via the shell. A chrome:// URL can't be navigated to reliably from the
        /// command line when Chrome is already running with multiple profiles (the profile
        /// picker drops the argument), so we also copy the URL to the clipboard and tell the
        /// user to paste it into the address bar - which always works.
        /// </summary>
        private void OpenSettingUri(string uri)
        {
            bool isChrome = uri.StartsWith("chrome://", StringComparison.OrdinalIgnoreCase);
            if (isChrome)
                try { Clipboard.SetText(uri); } catch { /* clipboard may be busy */ }

            try
            {
                var psi = isChrome
                    ? new ProcessStartInfo("chrome.exe", uri)   // navigates on single-profile setups
                    : new ProcessStartInfo(uri);
                psi.UseShellExecute = true;
                Process.Start(psi);
            }
            catch (Exception ex)
            {
                CopyableMessageBox.Show(this, $"Could not open '{uri}': {ex.Message}", "B4-Browse",
                    MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            if (isChrome)
            {
                SetStatus($"Copied {uri}  -  press Ctrl+V in Chrome's address bar to open it.");
                // Chrome's profile picker drops the URL argument, so float a delayed reminder over
                // Chrome explaining how to paste the (already-copied) address. Suppressible by the user.
                ChromeHint.ShowAfterLaunch(uri);
            }
        }

        private const string AllChoice = "(All)";
        private bool _suspendFilterEvents;

        private static Color RegexErrorBack =>
            Theme.IsDark ? Color.FromArgb(90, 50, 50) : Color.FromArgb(255, 224, 224);

        /// <summary>Builds the optional filter bar (one control per column whose
        /// <see cref="GridColumn.FilterKind"/> is not None). Added before the toolbar so it
        /// docks directly beneath it; absent entirely when no column opts in.</summary>
        private void BuildFilterBar()
        {
            var filterCols = new List<int>();
            for (int i = 0; i < _cols.Length; i++)
                if (_cols[i].FilterKind != ColumnFilterKind.None) filterCols.Add(i);
            if (filterCols.Count == 0) return;

            var bar = new Panel { Dock = DockStyle.Top, Height = 40, BackColor = Theme.Toolbar };
            _filterBar = bar;

            // Use one explicit font for every control and measure label widths with it, so
            // positions never depend on AutoSize timing or an inherited default font (which
            // previously rendered labels wider than measured and clipped the next control).
            var ff = new Font("Segoe UI", 9f);
            const int inputTop = 8, inputH = 24;

            int x = 8;
            foreach (int ci in filterCols)
            {
                var c = _cols[ci];
                var fc = new FilterControl
                {
                    ColIndex = ci,
                    Kind = c.FilterKind,
                    Value = c.FilterValue ?? c.Text,
                };

                string labelText = c.Header + ":";
                int lblW = TextRenderer.MeasureText(labelText, ff).Width;
                var lbl = new Label
                {
                    Text = labelText, AutoSize = false, Font = ff,
                    Left = x, Top = 0, Width = lblW + 2, Height = bar.Height,
                    TextAlign = ContentAlignment.MiddleLeft,
                    ForeColor = Theme.Subtle, BackColor = Color.Transparent,
                };
                bar.Controls.Add(lbl);
                x = lbl.Right + 4;

                if (c.FilterKind == ColumnFilterKind.Dropdown)
                {
                    var combo = new ComboBox
                    {
                        Left = x, Top = inputTop, Width = 160, Font = ff,
                        DropDownStyle = ComboBoxStyle.DropDownList,
                        FlatStyle = FlatStyle.System,
                    };
                    combo.Items.Add(AllChoice);
                    combo.SelectedIndex = 0;
                    combo.SelectedIndexChanged += (_, _) => { if (!_suspendFilterEvents) Populate(); };
                    bar.Controls.Add(combo);
                    fc.Combo = combo;
                    x = combo.Right + 14;
                }
                else // Regex
                {
                    var box = new TextBox
                    {
                        Left = x, Top = inputTop, Width = 180, Height = inputH, Font = ff,
                        PlaceholderText = "regex…",
                        BackColor = Theme.Surface, ForeColor = Theme.Text,
                    };
                    box.TextChanged += (_, _) => { if (_suspendFilterEvents) return; CompileFilter(fc); Populate(); };
                    bar.Controls.Add(box);
                    fc.Box = box;
                    x = box.Right + 14;
                }
                _filters.Add(fc);
            }

            _filterMinX = x;
            _filterClear = new Button
            {
                Text = "Clear", Width = 64, Height = 26, Top = inputTop, Font = ff,
                FlatStyle = FlatStyle.System,
            };
            _filterClear.Click += (_, _) => ClearFilters();
            bar.Controls.Add(_filterClear);

            _filterCount = new Label
            {
                AutoSize = true, Top = 12, Text = "", Font = ff,
                ForeColor = Theme.Subtle, BackColor = Color.Transparent,
            };
            bar.Controls.Add(_filterCount);

            bar.SizeChanged += (_, _) => LayoutFilterBar();
            _filterCount.SizeChanged += (_, _) => LayoutFilterBar();
            LayoutFilterBar();

            Controls.Add(bar);
        }

        private int _filterMinX;
        private Button? _filterClear;

        /// <summary>Right-aligns the "showing N of M" label and Clear button.</summary>
        private void LayoutFilterBar()
        {
            if (_filterBar == null || _filterClear == null || _filterCount == null) return;
            _filterClear.Top = (_filterBar.ClientSize.Height - _filterClear.Height) / 2;
            _filterClear.Left = Math.Max(_filterMinX, _filterBar.ClientSize.Width - _filterClear.Width - 8);
            _filterCount.Top = (_filterBar.ClientSize.Height - _filterCount.Height) / 2;
            _filterCount.Left = Math.Max(_filterMinX, _filterClear.Left - _filterCount.Width - 10);
        }

        /// <summary>Compiles a regex filter; on an invalid pattern caches null and tints the box,
        /// and the filter falls back to a literal case-insensitive match.</summary>
        private void CompileFilter(FilterControl fc)
        {
            if (fc.Box == null) return;
            string p = fc.Box.Text;
            if (string.IsNullOrEmpty(p)) { fc.Compiled = null; fc.Box.BackColor = Theme.Surface; return; }
            try
            {
                fc.Compiled = new Regex(p, RegexOptions.IgnoreCase | RegexOptions.Compiled);
                fc.Box.BackColor = Theme.Surface;
            }
            catch { fc.Compiled = null; fc.Box.BackColor = RegexErrorBack; }
        }

        /// <summary>True when the item passes every active column filter (ANDed).</summary>
        private bool PassesFilters(object item)
        {
            foreach (var fc in _filters)
            {
                if (fc.Kind == ColumnFilterKind.Dropdown)
                {
                    if (fc.Combo?.SelectedItem is string sel && sel != AllChoice
                        && !string.Equals(fc.Value(item), sel, StringComparison.Ordinal))
                        return false;
                }
                else // Regex
                {
                    string pat = fc.Box?.Text ?? "";
                    if (pat.Length == 0) continue;
                    string val = fc.Value(item) ?? "";
                    bool ok = fc.Compiled != null
                        ? fc.Compiled.IsMatch(val)
                        : val.Contains(pat, StringComparison.OrdinalIgnoreCase);   // invalid pattern -> literal
                    if (!ok) return false;
                }
            }
            return true;
        }

        /// <summary>Refreshes dropdown choices from the distinct values currently loaded,
        /// preserving the selection when it still exists.</summary>
        private void RebuildFilterChoices()
        {
            _suspendFilterEvents = true;
            foreach (var fc in _filters)
            {
                if (fc.Combo == null) continue;
                string? prev = fc.Combo.SelectedItem as string;
                var vals = _items.Select(fc.Value).Where(s => !string.IsNullOrEmpty(s))
                    .Distinct().OrderBy(s => s, StringComparer.OrdinalIgnoreCase).ToList();
                fc.Combo.BeginUpdate();
                fc.Combo.Items.Clear();
                fc.Combo.Items.Add(AllChoice);
                foreach (var v in vals) fc.Combo.Items.Add(v);
                int idx = prev != null ? fc.Combo.Items.IndexOf(prev) : 0;
                fc.Combo.SelectedIndex = idx >= 0 ? idx : 0;
                fc.Combo.EndUpdate();
            }
            _suspendFilterEvents = false;
        }

        private void ClearFilters()
        {
            _suspendFilterEvents = true;
            foreach (var fc in _filters)
            {
                if (fc.Combo is { Items.Count: > 0 }) fc.Combo.SelectedIndex = 0;
                if (fc.Box != null) { fc.Box.Text = ""; fc.Compiled = null; fc.Box.BackColor = Theme.Surface; }
            }
            _suspendFilterEvents = false;
            Populate();
        }

        private void Populate()
        {
            _grid.SuspendLayout();
            _grid.Rows.Clear();
            bool filtering = _toggle is { Checked: false } && _hideWhenOff != null;
            int shown = 0, total = 0;
            foreach (var item in _items)
            {
                if (filtering && _hideWhenOff!(item)) continue;
                total++;
                if (_filters.Count > 0 && !PassesFilters(item)) continue;
                shown++;
                var values = new object[_cols.Length];
                for (int i = 0; i < _cols.Length; i++)
                    values[i] = _cols[i].Button ? _cols[i].ButtonText : _cols[i].Text(item);

                int idx = _grid.Rows.Add(values);
                var row = _grid.Rows[idx];
                row.Tag = item;
                // Dim rows that are shadowed/superseded — muted text at the row level so any
                // per-cell colour override (e.g. the Status column highlight) still takes precedence.
                if (_dimRow != null && _dimRow(item))
                    row.DefaultCellStyle.ForeColor = Theme.Subtle;
                for (int i = 0; i < _cols.Length; i++)
                {
                    var style = _cols[i].Style?.Invoke(item);
                    if (style is { } s)
                    {
                        var cell = row.Cells[i];
                        cell.Style.BackColor = s.Back;
                        cell.Style.ForeColor = s.Fore;
                        cell.Style.SelectionBackColor = s.Back;
                        cell.Style.SelectionForeColor = s.Fore;
                    }
                }
            }
            UpdateSortGlyphs();
            _grid.ResumeLayout();
            if (_autoFitPending) { AutoFitColumns(); _autoFitPending = false; }
            if (IsHandleCreated) Theme.ApplyScrollbarTheme(this);   // scrollbars may have just appeared

            if (_filterCount != null)
            {
                _filterCount.Text = shown == total ? $"{total} shown" : $"showing {shown} of {total}";
                LayoutFilterBar();
            }
        }

        /// <summary>
        /// Sets each column's default width to fit its content (header + widest cell across all
        /// rows) so every field is fully visible on load; when the columns together exceed the
        /// viewport the grid's built-in horizontal scrollbar appears. MinimumWidth stays at 2px so
        /// the user can still drag any column down to almost nothing. Any spare viewport width is
        /// handed to the Fill column(s) by weight so the grid still reaches the right edge.
        /// Runs only when <see cref="_autoFitPending"/> is set (a data or font-scale change), never
        /// on a plain sort/filter, so manual column widths survive those.
        /// </summary>
        private void AutoFitColumns()
        {
            int total = 0, fillWeight = 0;
            for (int i = 0; i < _grid.Columns.Count; i++)
            {
                var col = _grid.Columns[i];
                int preferred = col.GetPreferredWidth(DataGridViewAutoSizeColumnMode.AllCells, fixedHeight: true);
                col.MinimumWidth = 2;
                col.Width = Math.Max(2, preferred);
                total += col.Width;
                if (i < _cols.Length && _cols[i].Fill > 0) fillWeight += _cols[i].Fill;
            }

            // Everything fits with room to spare: spread the slack over the Fill column(s) so the
            // last columns reach the right edge instead of leaving a blank gutter.
            int slack = _grid.ClientSize.Width - total;
            if (slack > 0 && fillWeight > 0)
                for (int i = 0; i < _grid.Columns.Count; i++)
                    if (i < _cols.Length && _cols[i].Fill > 0)
                        _grid.Columns[i].Width += slack * _cols[i].Fill / fillWeight;
        }

        private void OnHeaderClick(object? sender, DataGridViewCellMouseEventArgs e)
        {
            if (e.ColumnIndex < 0 || e.ColumnIndex >= _cols.Length) return;
            if (_cols[e.ColumnIndex].Button) return;
            if (_sortCol == e.ColumnIndex) _asc = !_asc;
            else { _sortCol = e.ColumnIndex; _asc = true; }
            SortItems();
            Populate();
        }

        private void SortItems()
        {
            if (_sortCol < 0 || _sortCol >= _cols.Length) return;
            var col = _cols[_sortCol];
            Func<object, IComparable> key = col.Sort ?? (o => col.Text(o));
            _items.Sort((a, b) =>
            {
                IComparable ka = key(a), kb = key(b);
                try { return Comparer<IComparable>.Default.Compare(ka, kb); }
                catch { return string.Compare(ka?.ToString(), kb?.ToString(), StringComparison.OrdinalIgnoreCase); }
            });
            if (!_asc) _items.Reverse();
        }

        private void UpdateSortGlyphs()
        {
            foreach (DataGridViewColumn c in _grid.Columns)
                c.HeaderCell.SortGlyphDirection = SortOrder.None;
            if (_sortCol >= 0 && _sortCol < _grid.Columns.Count && !_cols[_sortCol].Button)
                _grid.Columns[_sortCol].HeaderCell.SortGlyphDirection =
                    _asc ? SortOrder.Ascending : SortOrder.Descending;
        }

        private void OnCellClick(object? sender, DataGridViewCellEventArgs e)
        {
            if (e.RowIndex < 0) return;
            // Button click
            if (e.ColumnIndex == _buttonColIndex && _onButton != null)
            {
                if (_grid.Rows[e.RowIndex].Tag is { } item)
                {
                    _grid.ClearSelection();
                    _grid.Rows[e.RowIndex].Selected = true;
                    _onButton(item);
                }
                return;
            }

            // Link cell click: open URL if the column is a link
            if (e.ColumnIndex >= 0 && e.ColumnIndex < _cols.Length && _cols[e.ColumnIndex].Link)
            {
                var col = _cols[e.ColumnIndex];
                // A column may open a different URL than it displays (e.g. show "Search web",
                // open a search query). Fall back to the displayed cell text when unset.
                string? text = col.LinkTarget != null && _grid.Rows[e.RowIndex].Tag is { } rowItem
                    ? col.LinkTarget(rowItem)
                    : _grid.Rows[e.RowIndex].Cells[e.ColumnIndex].Value?.ToString();
                if (string.IsNullOrEmpty(text)) return;
                // chrome:// URIs can't be shell-launched; route them through the same handler
                // the header deep-links use (chrome.exe + clipboard fallback).
                if (text.StartsWith("chrome://", StringComparison.OrdinalIgnoreCase))
                {
                    OpenSettingUri(text);
                    return;
                }
                try { Process.Start(new ProcessStartInfo(text) { UseShellExecute = true }); }
                catch { try { Process.Start(new ProcessStartInfo("cmd", $"/c start \"\" \"{text}\"") { CreateNoWindow = true }); } catch { } }
            }
        }

        private void OnCellMouseDown(object? sender, DataGridViewCellMouseEventArgs e)
        {
            if (e.Button != MouseButtons.Right || e.RowIndex < 0 || _onRowContext == null) return;
            if (_grid.Rows[e.RowIndex].Tag is { } item)
            {
                _grid.ClearSelection();
                _grid.Rows[e.RowIndex].Selected = true;
                _onRowContext(item);
            }
        }
    }
}
