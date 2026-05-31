// Copyright (c) 2026 LanDen Labs - Dennis Lang

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace BrowseSafe
{
    /// <summary>A tab content view that can be (re)run, with lazy first-run support.</summary>
    public interface ITabView
    {
        bool HasRun { get; }
        Task RunAsync();

        /// <summary>Worst state detected on this tab (drives the tab header colour).</summary>
        TabSeverity Severity { get; }

        /// <summary>Raised when <see cref="Severity"/> changes (after a run).</summary>
        event Action? SeverityChanged;
    }

    /// <summary>
    /// A self-contained results pane: a Run/Refresh button, a status label, and a
    /// colour-coded RichTextBox. It runs a list of named check steps on a background
    /// thread, rendering each group as it completes. Reused by every tab.
    /// </summary>
    public sealed class ResultsView : UserControl, ITabView
    {
        private readonly Button _runButton;
        private readonly Label _status;
        private readonly RichTextBox _output;
        private readonly Panel _topPanel;
        private readonly BusyOverlay _busy = new();
        private readonly IReadOnlyList<(string Label, Func<CheckGroup> Run)> _steps;
        private readonly bool _reportVerdict;
        private bool _running;

        // Char range of the inline "Open hosts folder" link (-1 = absent).
        private int _hostsLinkStart = -1;
        private int _hostsLinkEnd = -1;

        /// <summary>True once the view has completed at least one run (for lazy auto-run).</summary>
        public bool HasRun { get; private set; }

        public TabSeverity Severity { get; private set; } = TabSeverity.None;
        public event Action? SeverityChanged;

        /// <summary>Raised with the overall verdict after a run (only when reportVerdict is set).</summary>
        public event Action<CheckStatus>? Completed;

        // Theme-aware colours (brighter status hues on dark backgrounds).
        private static Color ColorPass => Theme.IsDark ? Color.FromArgb(90, 200, 100) : Color.FromArgb(0, 140, 0);
        private static Color ColorWarn => Theme.IsDark ? Color.FromArgb(232, 184, 64) : Color.FromArgb(190, 120, 0);
        private static Color ColorFail => Theme.IsDark ? Color.FromArgb(240, 110, 110) : Color.FromArgb(200, 0, 0);
        private static Color ColorInfo => Theme.Subtle;
        private static Color ColorText => Theme.Text;
        private static Color ColorLink => Theme.IsDark ? Color.FromArgb(96, 162, 250) : Color.FromArgb(0, 102, 204);

        private List<CheckGroup> _lastGroups = new();

        public ResultsView(string runLabel, string intro,
            IReadOnlyList<(string Label, Func<CheckGroup> Run)> steps, bool reportVerdict)
        {
            _steps = steps;
            _reportVerdict = reportVerdict;
            Dock = DockStyle.Fill;
            BackColor = Theme.Surface;

            var top = new Panel { Dock = DockStyle.Top, Height = 40, BackColor = Theme.Toolbar };
            _runButton = new Button
            {
                Text = runLabel,
                Width = 160,
                Height = 28,
                Left = 8,
                Top = 6,
                FlatStyle = FlatStyle.System,
                Font = new Font("Segoe UI", 9f, FontStyle.Bold),
            };
            _runButton.Click += async (_, _) => await RunAsync();

            _status = new Label
            {
                AutoSize = true,
                Left = 178,
                Top = 12,
                ForeColor = Theme.Subtle,
                Text = intro,
            };
            top.Controls.Add(_runButton);
            top.Controls.Add(_status);

            _output = new RichTextBox
            {
                Dock = DockStyle.Fill,
                ReadOnly = true,
                BorderStyle = BorderStyle.None,
                Font = new Font("Consolas", 9.5f),
                BackColor = Theme.Surface,
                ForeColor = Theme.Text,
                DetectUrls = false,
                WordWrap = false,
                ScrollBars = RichTextBoxScrollBars.Both,
                Cursor = Cursors.IBeam,
            };
            _topPanel = top;
            _output.MouseDown += Output_MouseDown;
            _output.MouseMove += Output_MouseMove;

            Controls.Add(_output);
            Controls.Add(top);

            Controls.Add(_busy);
            Resize += (_, _) => CenterBusy();

            Theme.Changed += OnThemeChanged;
            Disposed += (_, _) => Theme.Changed -= OnThemeChanged;
        }

        private void OnThemeChanged()
        {
            if (!IsHandleCreated) { ApplyTheme(); return; }
            BeginInvoke(new Action(ApplyTheme));
        }

        private void ApplyTheme()
        {
            BackColor = Theme.Surface;
            _topPanel.BackColor = Theme.Toolbar;
            _status.ForeColor = Theme.Subtle;
            _output.BackColor = Theme.Surface;
            _output.ForeColor = Theme.Text;
            if (HasRun) ReRender();   // recolour existing content (e.g. black text -> light)
        }

        private void ReRender()
        {
            _output.Clear();
            _hostsLinkStart = _hostsLinkEnd = -1;
            foreach (var g in _lastGroups) RenderGroup(g);
        }

        private void CenterBusy()
        {
            _busy.Left = Math.Max(0, (ClientSize.Width - _busy.Width) / 2);
            _busy.Top = Math.Max(40, (ClientSize.Height - _busy.Height) / 2);
        }

        public async Task RunAsync()
        {
            if (_running) return;
            _running = true;
            _runButton.Enabled = false;
            _output.Clear();
            _lastGroups = new List<CheckGroup>();
            _hostsLinkStart = _hostsLinkEnd = -1;
            AppendLine($"{DateTime.Now:yyyy-MM-dd HH:mm:ss}", ColorInfo, FontStyle.Italic);
            AppendLine("");

            CenterBusy();
            _busy.Start();
            CheckStatus overall = CheckStatus.Pass;
            try
            {
                foreach (var (label, run) in _steps)
                {
                    _status.Text = $"Running {label} ...";
                    CheckGroup g = await Task.Run(run);
                    _lastGroups.Add(g);
                    RenderGroup(g);
                    if (CheckGroup.Rank(g.Worst()) > CheckGroup.Rank(overall))
                        overall = g.Worst();
                }
                _status.Text = $"Completed {DateTime.Now:HH:mm:ss}";
            }
            finally
            {
                _busy.Stop();
                HasRun = true;
                _runButton.Enabled = true;
                _running = false;
            }
            Severity = Sev.FromStatus(overall);
            SeverityChanged?.Invoke();
            if (_reportVerdict) Completed?.Invoke(overall);
        }

        private void RenderGroup(CheckGroup group)
        {
            // The hosts section title carries an inline clickable "Open hosts folder" link.
            if (group.Title.Contains("Hosts File", StringComparison.OrdinalIgnoreCase))
            {
                Append(group.Title, ColorText, FontStyle.Bold, 11f);
                Append("      ", ColorInfo);
                _hostsLinkStart = _output.TextLength;
                Append("[ Open hosts folder ]", ColorLink, FontStyle.Underline, 9.5f);
                _hostsLinkEnd = _output.TextLength;
                AppendLine("");
            }
            else
            {
                AppendLine(group.Title, ColorText, FontStyle.Bold, 11f);
            }
            AppendLine(new string('─', 60), ColorInfo);

            foreach (var r in group.Results)
            {
                if (r.Table)
                {
                    AppendLine(r.Name, ColorFor(r.Status));
                    continue;
                }

                string tag = r.Status switch
                {
                    CheckStatus.Pass => "[ PASS ]",
                    CheckStatus.Warn => "[ WARN ]",
                    CheckStatus.Fail => "[ FAIL ]",
                    _ => "[ INFO ]",
                };
                Append(tag + "  ", ColorFor(r.Status), FontStyle.Bold);
                Append(r.Name, ColorText, FontStyle.Bold);
                if (!string.IsNullOrEmpty(r.Detail))
                    Append("  -  " + r.Detail, ColorInfo);
                AppendLine("");
            }
            AppendLine("");
        }

        private static Color ColorFor(CheckStatus s) => s switch
        {
            CheckStatus.Pass => ColorPass,
            CheckStatus.Warn => ColorWarn,
            CheckStatus.Fail => ColorFail,
            _ => ColorInfo,
        };

        // ---- RichTextBox append helpers ----
        private void Append(string text, Color color, FontStyle style = FontStyle.Regular, float size = 9.5f)
        {
            _output.SelectionStart = _output.TextLength;
            _output.SelectionLength = 0;
            _output.SelectionColor = color;
            _output.SelectionFont = new Font("Consolas", size, style);
            _output.AppendText(text);
            _output.SelectionColor = _output.ForeColor;
        }

        private void AppendLine(string text, Color color, FontStyle style = FontStyle.Regular, float size = 9.5f)
            => Append(text + Environment.NewLine, color, style, size);

        private void AppendLine(string text) => AppendLine(text, _output.ForeColor);

        // ---- Inline hosts-folder link ----
        private bool IsOverHostsLink(Point p)
        {
            if (_hostsLinkStart < 0 || _hostsLinkEnd <= _hostsLinkStart) return false;
            Point a = _output.GetPositionFromCharIndex(_hostsLinkStart);
            Point b = _output.GetPositionFromCharIndex(_hostsLinkEnd);
            if (b.Y < a.Y) return false;
            int h = (int)Math.Ceiling(_output.Font.GetHeight()) + 4;
            var rect = new Rectangle(a.X, a.Y, Math.Max(1, b.X - a.X), h);
            return rect.Contains(p);
        }

        private void Output_MouseDown(object? sender, MouseEventArgs e)
        {
            if (e.Button == MouseButtons.Left && IsOverHostsLink(e.Location))
                OpenHostsFolder();
        }

        private void Output_MouseMove(object? sender, MouseEventArgs e)
            => _output.Cursor = IsOverHostsLink(e.Location) ? Cursors.Hand : Cursors.IBeam;

        private void OpenHostsFolder()
        {
            string path = SafetyChecks.HostsPath;
            try
            {
                string arg = File.Exists(path)
                    ? $"/select,\"{path}\""
                    : $"\"{Path.GetDirectoryName(path)}\"";
                Process.Start(new ProcessStartInfo("explorer.exe", arg) { UseShellExecute = true });
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, "Could not open hosts folder: " + ex.Message,
                    "Browse Safe", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
        }
    }
}
