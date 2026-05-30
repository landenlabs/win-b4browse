using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace BrowseSafe
{
    /// <summary>
    /// A self-contained results pane: a Run/Refresh button, a status label, and a
    /// colour-coded RichTextBox. It runs a list of named check steps on a background
    /// thread, rendering each group as it completes. Reused by every tab.
    /// </summary>
    public sealed class ResultsView : UserControl
    {
        private readonly Button _runButton;
        private readonly Label _status;
        private readonly RichTextBox _output;
        private readonly IReadOnlyList<(string Label, Func<CheckGroup> Run)> _steps;
        private readonly bool _reportVerdict;
        private bool _running;

        // Char range of the inline "Open hosts folder" link (-1 = absent).
        private int _hostsLinkStart = -1;
        private int _hostsLinkEnd = -1;

        /// <summary>True once the view has completed at least one run (for lazy auto-run).</summary>
        public bool HasRun { get; private set; }

        /// <summary>Raised with the overall verdict after a run (only when reportVerdict is set).</summary>
        public event Action<CheckStatus>? Completed;

        private static readonly Color ColorPass = Color.FromArgb(0, 140, 0);
        private static readonly Color ColorWarn = Color.FromArgb(190, 120, 0);
        private static readonly Color ColorFail = Color.FromArgb(200, 0, 0);
        private static readonly Color ColorInfo = Color.FromArgb(70, 70, 70);
        private static readonly Color ColorLink = Color.FromArgb(0, 102, 204);

        public ResultsView(string runLabel, string intro,
            IReadOnlyList<(string Label, Func<CheckGroup> Run)> steps, bool reportVerdict)
        {
            _steps = steps;
            _reportVerdict = reportVerdict;
            Dock = DockStyle.Fill;
            BackColor = Color.White;

            var top = new Panel { Dock = DockStyle.Top, Height = 40 };
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
                ForeColor = Color.Gray,
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
                BackColor = Color.White,
                DetectUrls = false,
                WordWrap = false,
                ScrollBars = RichTextBoxScrollBars.Both,
                Cursor = Cursors.IBeam,
            };
            _output.MouseDown += Output_MouseDown;
            _output.MouseMove += Output_MouseMove;

            Controls.Add(_output);
            Controls.Add(top);
        }

        public async Task RunAsync()
        {
            if (_running) return;
            _running = true;
            _runButton.Enabled = false;
            _output.Clear();
            _hostsLinkStart = _hostsLinkEnd = -1;
            AppendLine($"{DateTime.Now:yyyy-MM-dd HH:mm:ss}", ColorInfo, FontStyle.Italic);
            AppendLine("");

            CheckStatus overall = CheckStatus.Pass;
            foreach (var (label, run) in _steps)
            {
                _status.Text = $"Running {label} ...";
                CheckGroup g = await Task.Run(run);
                RenderGroup(g);
                if (CheckGroup.Rank(g.Worst()) > CheckGroup.Rank(overall))
                    overall = g.Worst();
            }

            _status.Text = $"Completed {DateTime.Now:HH:mm:ss}";
            HasRun = true;
            _runButton.Enabled = true;
            _running = false;
            if (_reportVerdict) Completed?.Invoke(overall);
        }

        private void RenderGroup(CheckGroup group)
        {
            // The hosts section title carries an inline clickable "Open hosts folder" link.
            if (group.Title.Contains("Hosts File", StringComparison.OrdinalIgnoreCase))
            {
                Append(group.Title, Color.Black, FontStyle.Bold, 11f);
                Append("      ", ColorInfo);
                _hostsLinkStart = _output.TextLength;
                Append("[ Open hosts folder ]", ColorLink, FontStyle.Underline, 9.5f);
                _hostsLinkEnd = _output.TextLength;
                AppendLine("");
            }
            else
            {
                AppendLine(group.Title, Color.Black, FontStyle.Bold, 11f);
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
                Append(r.Name, Color.Black, FontStyle.Bold);
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
