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
            Func<string>? summary = null)
        {
            _loader = loader;
            _cols = columns;
            _onButton = onButtonClick;
            _summary = summary;
            _sortCol = defaultSortColumn;
            _asc = defaultAscending;

            Dock = DockStyle.Fill;
            BackColor = Color.White;

            var top = new Panel { Dock = DockStyle.Top, Height = 40, BackColor = Color.FromArgb(245, 245, 245) };
            _refresh = new Button
            {
                Text = runLabel, Width = 90, Height = 28, Left = 8, Top = 6,
                FlatStyle = FlatStyle.System, Font = new Font("Segoe UI", 9f, FontStyle.Bold),
            };
            _refresh.Click += async (_, _) => await RunAsync();
            top.Controls.Add(_refresh);

            int left = 104;
            if (extraButtons != null)
            {
                foreach (var (label, onClick) in extraButtons)
                {
                    var b = new Button
                    {
                        Text = label, Height = 28, Top = 6, Left = left,
                        Width = TextRenderer.MeasureText(label, Font).Width + 28,
                        FlatStyle = FlatStyle.System,
                    };
                    b.Click += (_, _) => onClick();
                    top.Controls.Add(b);
                    left += b.Width + 6;
                }
            }

            _status = new Label
            {
                AutoSize = true, Left = left + 4, Top = 12, ForeColor = Color.Gray,
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

            Controls.Add(_grid);
            Controls.Add(top);
        }

        public void SetStatus(string text) => _status.Text = text;

        public async Task RunAsync()
        {
            if (_loading) return;
            _loading = true;
            _refresh.Enabled = false;
            _status.Text = "Loading …";

            string? summaryText = null;
            _items = await Task.Run(() =>
            {
                if (_summary != null) summaryText = SafeSummary();
                return _loader();
            });

            SortItems();
            Populate();

            string count = $"{_items.Count} item(s)   -   {DateTime.Now:HH:mm:ss}";
            _status.Text = summaryText != null ? $"{summaryText}      |      {count}" : count;
            HasRun = true;
            _refresh.Enabled = true;
            _loading = false;
        }

        private string SafeSummary()
        {
            try { return _summary!(); } catch { return ""; }
        }

        private void Populate()
        {
            _grid.SuspendLayout();
            _grid.Rows.Clear();
            foreach (var item in _items)
            {
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
    }
}
