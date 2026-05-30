using System;
using System.Collections.Generic;
using System.Drawing;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace BrowseSafe
{
    /// <summary>Declarative column for <see cref="SortableGrid"/>.</summary>
    public sealed class GridColumn
    {
        public string Header = "";
        public int Width = 100;
        public int Fill = 0;                                  // >0 => fill column with this weight
        public bool Button = false;                           // render as a clickable button cell
        public string ButtonText = "";
        public Func<object, string> Text = _ => "";           // cell display text
        public Func<object, IComparable>? Sort = null;        // sort key (defaults to Text)
        public Func<object, (Color Back, Color Fore)?>? Style = null; // per-cell colour
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
        private readonly Func<List<object>> _loader;
        private readonly Func<string>? _summary;
        private readonly GridColumn[] _cols;
        private readonly Action<object>? _onButton;
        private readonly Func<CheckGroup>? _headerInfo;
        private readonly RichTextBox? _header;
        private readonly BusyOverlay _busy = new();
        private readonly Func<IReadOnlyList<object>, TabSeverity>? _severityEval;
        private readonly Action<object>? _onRowContext;
        private readonly CheckBox? _toggle;
        private readonly Func<object, bool>? _hideWhenOff;

        public TabSeverity Severity { get; private set; } = TabSeverity.None;
        public event Action? SeverityChanged;

        private static readonly Color HdrPass = Color.FromArgb(0, 140, 0);
        private static readonly Color HdrWarn = Color.FromArgb(190, 120, 0);
        private static readonly Color HdrFail = Color.FromArgb(200, 0, 0);
        private static readonly Color HdrInfo = Color.FromArgb(70, 70, 70);

        private List<object> _items = new();
        private int _sortCol;
        private bool _asc;
        private bool _loading;
        private int _buttonColIndex = -1;

        public bool HasRun { get; private set; }

        public SortableGrid(
            string runLabel,
            Func<List<object>> loader,
            GridColumn[] columns,
            int defaultSortColumn,
            bool defaultAscending,
            Action<object>? onButtonClick = null,
            IEnumerable<(string Label, Action OnClick)>? extraButtons = null,
            string? legend = null,
            Func<string>? summary = null,
            Func<CheckGroup>? headerInfo = null,
            Func<IReadOnlyList<object>, TabSeverity>? severity = null,
            Action<object>? onRowContext = null,
            (string Label, Func<object, bool> HideWhenOff)? showAllToggle = null,
            (string Label, Action OnClick)? headerButton = null)
        {
            _loader = loader;
            _cols = columns;
            _onButton = onButtonClick;
            _summary = summary;
            _headerInfo = headerInfo;
            _severityEval = severity;
            _onRowContext = onRowContext;
            _sortCol = defaultSortColumn;
            _asc = defaultAscending;

            Dock = DockStyle.Fill;
            BackColor = Color.White;

            var top = new Panel { Dock = DockStyle.Top, Height = 40, BackColor = Color.FromArgb(245, 245, 245) };

            int x = 8;
            if (showAllToggle is { } st)
            {
                _hideWhenOff = st.HideWhenOff;
                int w = TextRenderer.MeasureText(st.Label, Font).Width + 26;
                _toggle = new CheckBox { Text = st.Label, Left = x, Top = 9, Width = w, Height = 24, Checked = false };
                _toggle.CheckedChanged += (_, _) => Populate();
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
                    x += b.Width + 6;
                }
            }

            _status = new Label
            {
                AutoSize = true, Left = x + 4, Top = 12, ForeColor = Color.Gray,
                Text = "Click " + runLabel + ".",
            };
            top.Controls.Add(_status);

            if (legend != null)
            {
                var lg = new Label { AutoSize = true, Top = 12, Left = 0, ForeColor = Color.Gray, Text = legend };
                lg.Dock = DockStyle.Right;
                lg.TextAlign = ContentAlignment.MiddleRight;
                lg.Padding = new Padding(0, 12, 10, 0);
                top.Controls.Add(lg);
                lg.BringToFront();
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
                BackgroundColor = Color.White,
                BorderStyle = BorderStyle.None,
                ColumnHeadersHeightSizeMode = DataGridViewColumnHeadersHeightSizeMode.DisableResizing,
                Font = new Font("Segoe UI", 9f),
            };

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
                else
                {
                    col = new DataGridViewTextBoxColumn
                    {
                        ReadOnly = true,
                        SortMode = DataGridViewColumnSortMode.Programmatic,
                    };
                }
                col.HeaderText = c.Header;
                if (c.Fill > 0) { col.AutoSizeMode = DataGridViewAutoSizeColumnMode.Fill; col.FillWeight = c.Fill; }
                else col.Width = c.Width;
                _grid.Columns.Add(col);
            }

            _grid.ColumnHeaderMouseClick += OnHeaderClick;
            _grid.CellContentClick += OnCellClick;
            _grid.CellMouseDown += OnCellMouseDown;

            Controls.Add(_grid);
            if (_headerInfo != null)
            {
                var headerPanel = new Panel { Dock = DockStyle.Top, Height = 104, BackColor = Color.FromArgb(250, 250, 250) };
                _header = new RichTextBox
                {
                    Dock = DockStyle.Fill,
                    ReadOnly = true,
                    BorderStyle = BorderStyle.None,
                    Font = new Font("Consolas", 9f),
                    BackColor = Color.FromArgb(250, 250, 250),
                    WordWrap = false,
                    ScrollBars = RichTextBoxScrollBars.Vertical,
                };
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
            Controls.Add(top);

            Controls.Add(_busy);
            Resize += (_, _) => CenterBusy();
        }

        private void CenterBusy()
        {
            _busy.Left = Math.Max(0, (ClientSize.Width - _busy.Width) / 2);
            _busy.Top = Math.Max(40, (ClientSize.Height - _busy.Height) / 2);
        }

        public void SetStatus(string text) => _status.Text = text;

        public async Task RunAsync()
        {
            if (_loading) return;
            _loading = true;
            _refresh.Enabled = false;
            _status.Text = "Loading …";

            CenterBusy();
            _busy.Start();
            try
            {
                string? summaryText = null;
                CheckGroup? headerGroup = null;
                _items = await Task.Run(() =>
                {
                    if (_summary != null) summaryText = SafeSummary();
                    if (_headerInfo != null) { try { headerGroup = _headerInfo(); } catch { /* ignore */ } }
                    return _loader();
                });

                if (_header != null && headerGroup != null) RenderHeader(headerGroup);
                SortItems();
                Populate();

                string count = $"{_items.Count} item(s)   -   {DateTime.Now:HH:mm:ss}";
                _status.Text = summaryText != null ? $"{summaryText}      |      {count}" : count;
            }
            finally
            {
                _busy.Stop();
                HasRun = true;
                _refresh.Enabled = true;
                _loading = false;
            }
            Severity = _severityEval?.Invoke(_items) ?? TabSeverity.None;
            SeverityChanged?.Invoke();
        }

        private string SafeSummary()
        {
            try { return _summary!(); } catch { return ""; }
        }

        private void RenderHeader(CheckGroup g)
        {
            if (_header == null) return;
            _header.Clear();

            void Append(string text, Color color, FontStyle style = FontStyle.Regular, float size = 9f)
            {
                _header.SelectionStart = _header.TextLength;
                _header.SelectionColor = color;
                _header.SelectionFont = new Font("Consolas", size, style);
                _header.AppendText(text);
            }

            Append(g.Title + "\n", Color.Black, FontStyle.Bold, 10f);
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
                Append(r.Name, Color.Black, FontStyle.Bold);
                if (!string.IsNullOrEmpty(r.Detail)) Append("  -  " + r.Detail, HdrInfo);
                Append("\n", Color.Black);
            }
            _header.SelectionStart = 0;
            _header.ScrollToCaret();
        }

        private void Populate()
        {
            _grid.SuspendLayout();
            _grid.Rows.Clear();
            bool filtering = _toggle is { Checked: false } && _hideWhenOff != null;
            foreach (var item in _items)
            {
                if (filtering && _hideWhenOff!(item)) continue;
                var values = new object[_cols.Length];
                for (int i = 0; i < _cols.Length; i++)
                    values[i] = _cols[i].Button ? _cols[i].ButtonText : _cols[i].Text(item);

                int idx = _grid.Rows.Add(values);
                var row = _grid.Rows[idx];
                row.Tag = item;
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
            if (e.RowIndex < 0 || e.ColumnIndex != _buttonColIndex || _onButton == null) return;
            if (_grid.Rows[e.RowIndex].Tag is { } item)
            {
                _grid.ClearSelection();
                _grid.Rows[e.RowIndex].Selected = true;
                _onButton(item);
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
