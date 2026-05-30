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
    /// Single-window UI. A button runs all checks on a background thread and
    /// streams colour-coded results into a RichTextBox, with an overall
    /// "safe to run Chrome?" verdict banner on top.
    /// </summary>
    public sealed class MainForm : Form
    {
        private readonly Button _runButton;
        private readonly Button _chromeButton;
        private readonly Label _banner;
        private readonly RichTextBox _output;
        private readonly Label _hint;

        // Char range of the inline "Open hosts folder" link inside _output (-1 = not present).
        private int _hostsLinkStart = -1;
        private int _hostsLinkEnd = -1;

        // Status colours.
        private static readonly Color ColorPass = Color.FromArgb(0, 140, 0);
        private static readonly Color ColorWarn = Color.FromArgb(190, 120, 0);
        private static readonly Color ColorFail = Color.FromArgb(200, 0, 0);
        private static readonly Color ColorInfo = Color.FromArgb(70, 70, 70);
        private static readonly Color ColorLink = Color.FromArgb(0, 102, 204);

        public MainForm()
        {
            Text = "Browse Safe - Chrome Safety Check";
            MinimumSize = new Size(720, 560);
            Size = new Size(820, 680);
            StartPosition = FormStartPosition.CenterScreen;
            Font = new Font("Segoe UI", 9f);
            BackColor = Color.White;

            _banner = new Label
            {
                Dock = DockStyle.Top,
                Height = 56,
                TextAlign = ContentAlignment.MiddleCenter,
                Font = new Font("Segoe UI", 14f, FontStyle.Bold),
                ForeColor = Color.White,
                BackColor = Color.FromArgb(90, 90, 90),
                Text = "Click “Run Safety Checks” to begin",
            };

            var topPanel = new Panel { Dock = DockStyle.Top, Height = 52, Padding = new Padding(10, 9, 10, 9) };

            _runButton = new Button
            {
                Text = "Run Safety Checks",
                Width = 170,
                Height = 34,
                Left = 10,
                Top = 9,
                FlatStyle = FlatStyle.System,
                Font = new Font("Segoe UI", 9.5f, FontStyle.Bold),
            };
            _runButton.Click += async (_, _) => await RunChecksAsync();

            _chromeButton = new Button
            {
                Text = "Launch Chrome",
                Width = 140,
                Height = 34,
                Left = 190,
                Top = 9,
                FlatStyle = FlatStyle.System,
                Enabled = false,
            };
            _chromeButton.Click += (_, _) => LaunchChrome();

            _hint = new Label
            {
                AutoSize = true,
                Left = 345,
                Top = 17,
                ForeColor = Color.Gray,
                Text = "Verifies DNS, time, proxy, and Windows security before browsing.",
            };

            topPanel.Controls.Add(_runButton);
            topPanel.Controls.Add(_chromeButton);
            topPanel.Controls.Add(_hint);

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

            // Add in reverse z-order so Fill sits below the docked top items.
            Controls.Add(_output);
            Controls.Add(topPanel);
            Controls.Add(_banner);
        }

        private async Task RunChecksAsync()
        {
            _runButton.Enabled = false;
            _chromeButton.Enabled = false;
            _output.Clear();
            _hostsLinkStart = _hostsLinkEnd = -1;
            SetBanner("Running checks ...", Color.FromArgb(40, 90, 160));
            AppendLine($"Browse Safe  -  {DateTime.Now:yyyy-MM-dd HH:mm:ss}", ColorInfo, FontStyle.Italic);
            AppendLine("");

            // Each section runs on a background thread and is rendered as soon
            // as it completes, so the network probes (router/DNS) stream in.
            var checks = new (string Label, Func<CheckGroup> Run)[]
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

            CheckStatus overall = CheckStatus.Pass;
            foreach (var (label, run) in checks)
            {
                SetBanner($"Checking {label} ...", Color.FromArgb(40, 90, 160));
                CheckGroup g = await Task.Run(run);
                RenderGroup(g);
                if (CheckGroup.Rank(g.Worst()) > CheckGroup.Rank(overall))
                    overall = g.Worst();
            }

            RenderVerdict(overall);
            _runButton.Enabled = true;
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
                // Pre-formatted table line: print verbatim in the status colour, no tag.
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
                Color c = ColorFor(r.Status);

                Append(tag + "  ", c, FontStyle.Bold);
                Append(r.Name, Color.Black, FontStyle.Bold);
                if (!string.IsNullOrEmpty(r.Detail))
                    Append("  -  " + r.Detail, ColorInfo);
                AppendLine("");
            }
            AppendLine("");
        }

        private void RenderVerdict(CheckStatus overall)
        {
            switch (overall)
            {
                case CheckStatus.Fail:
                    SetBanner("NOT SAFE  -  resolve the FAIL items before browsing", ColorFail);
                    AppendLine("VERDICT: Unsafe. One or more critical checks failed. " +
                               "Do not browse until resolved.", ColorFail, FontStyle.Bold, 11f);
                    _chromeButton.Enabled = false;
                    break;
                case CheckStatus.Warn:
                    SetBanner("CAUTION  -  review the WARN items", ColorWarn);
                    AppendLine("VERDICT: Use caution. Review the warnings above before browsing.",
                               ColorWarn, FontStyle.Bold, 11f);
                    _chromeButton.Enabled = true;
                    break;
                default:
                    SetBanner("SAFE  -  all checks passed", ColorPass);
                    AppendLine("VERDICT: Safe. All checks passed - good to launch Chrome.",
                               ColorPass, FontStyle.Bold, 11f);
                    _chromeButton.Enabled = true;
                    break;
            }
        }

        private static Color ColorFor(CheckStatus s) => s switch
        {
            CheckStatus.Pass => ColorPass,
            CheckStatus.Warn => ColorWarn,
            CheckStatus.Fail => ColorFail,
            _ => ColorInfo,
        };

        private void SetBanner(string text, Color back)
        {
            _banner.Text = text;
            _banner.BackColor = back;
        }

        // ---- RichTextBox append helpers (run on UI thread) ----
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
        {
            Append(text + Environment.NewLine, color, style, size);
        }

        private void AppendLine(string text) => AppendLine(text, _output.ForeColor);

        private void LaunchChrome()
        {
            try
            {
                // Let the shell resolve the default handler / registered app.
                var psi = new ProcessStartInfo("chrome.exe") { UseShellExecute = true };
                Process.Start(psi);
            }
            catch
            {
                try
                {
                    // Fall back to opening the default browser on a blank page.
                    Process.Start(new ProcessStartInfo("about:blank") { UseShellExecute = true });
                }
                catch (Exception ex)
                {
                    MessageBox.Show(this, "Could not launch Chrome: " + ex.Message,
                        "Browse Safe", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                }
            }
        }

        /// <summary>Opens Explorer at the hosts directory with the hosts file selected.</summary>
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

        /// <summary>True if the point lies over the inline "Open hosts folder" link.</summary>
        private bool IsOverHostsLink(Point p)
        {
            if (_hostsLinkStart < 0 || _hostsLinkEnd <= _hostsLinkStart) return false;
            Point a = _output.GetPositionFromCharIndex(_hostsLinkStart);
            Point b = _output.GetPositionFromCharIndex(_hostsLinkEnd);
            if (b.Y < a.Y) return false; // link scrolled off / split
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
        {
            _output.Cursor = IsOverHostsLink(e.Location) ? Cursors.Hand : Cursors.IBeam;
        }
    }
}
