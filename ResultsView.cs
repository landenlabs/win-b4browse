// Copyright (c) 2026 LanDen Labs - Dennis Lang

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace B4Browse
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
        private readonly bool _requiresNetwork;
        private bool _running;
        private bool _networkBlocked;
        private CancellationTokenSource? _cts;

        // Inline clickable links rendered into the output (section "open settings" actions,
        // the hosts-folder link, and the offline "open network settings" link). Each region
        // maps a character range in the RichTextBox to the action it triggers.
        private sealed class LinkRegion
        {
            public int Start;
            public int End;
            public Action OnClick = () => { };
        }
        private readonly List<LinkRegion> _links = new();

        /// <summary>
        /// Per-section "open the relevant control panel" links, keyed by a substring of the
        /// section heading. Lets the user jump straight to where a flagged setting is changed.
        /// (Hosts File is handled separately - it opens a folder, not a URI.)
        /// </summary>
        private static readonly (string Match, string Label, string Uri)[] SectionLinks =
        {
            ("1. Current DNS",       "[ Open network adapters ]",    "ncpa.cpl"),
            ("8. Proxy",             "[ Open proxy settings ]",      "ms-settings:network-proxy"),
            ("9. Atomic Clock",      "[ Open date & time settings ]", "ms-settings:dateandtime"),
            ("10. Windows Security", "[ Open Windows Security ]",     "windowsdefender://threat"),
            // Capture-driver management: Device Manager disables/uninstalls a driver
            // (View > Show hidden devices); Apps removes a third-party capture tool.
            // PktMon is built-in and handled in the check text, not removable here.
            ("11. Network Sniffer",  "[ Open Device Manager ]",      "devmgmt.msc"),
            ("11. Network Sniffer",  "[ Open installed apps ]",      "ms-settings:appsfeatures"),
            // Adapter bindings (IPv4/IPv6, capture/VPN filters) are toggled in the adapter's
            // properties, reached from the classic Network Connections panel.
            ("12. Network Adapters", "[ Open network connections ]", "ncpa.cpl"),
        };

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
            IReadOnlyList<(string Label, Func<CheckGroup> Run)> steps, bool reportVerdict,
            HelpInfo? help = null, bool requiresNetwork = false)
        {
            _steps = steps;
            _reportVerdict = reportVerdict;
            _requiresNetwork = requiresNetwork;
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

            if (help != null)
            {
                var helpBtn = HelpUi.CreateButton(help);
                helpBtn.Top = 7;
                helpBtn.Anchor = AnchorStyles.Top | AnchorStyles.Right;
                top.Controls.Add(helpBtn);
                void LayoutHelp() => helpBtn.Left = Math.Max(0, top.ClientSize.Width - helpBtn.Width - 8);
                top.SizeChanged += (_, _) => LayoutHelp();
                LayoutHelp();
            }

            _output = new RichTextBox
            {
                Dock = DockStyle.Fill,
                ReadOnly = true,
                BorderStyle = BorderStyle.None,
                Font = Theme.Scaled("Consolas", 9.5f),
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
            _busy.ShowCancel = true;
            _busy.Cancelled += OnCancelRequested;
            Resize += (_, _) => CenterBusy();

            Theme.Changed += OnThemeChanged;
            Theme.ScaleChanged += OnScaleChanged;
            Disposed += (_, _) => { Theme.Changed -= OnThemeChanged; Theme.ScaleChanged -= OnScaleChanged; };
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
            _output.Font = Theme.Scaled("Consolas", 9.5f);
            if (HasRun) ReRender();   // re-emit content at the new size
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
            _links.Clear();
            if (_networkBlocked) { RenderNetworkWarning(); return; }
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
            _links.Clear();

            // Network-dependent tabs short-circuit when the machine is offline: skip every
            // check and show a single warning with a link to the Windows network settings.
            if (_requiresNetwork && !NetworkStatus.IsAvailable())
            {
                _networkBlocked = true;
                RenderNetworkWarning();
                _status.Text = "Network not available";
                HasRun = true;
                _runButton.Enabled = true;
                _running = false;
                Severity = TabSeverity.Alert;
                SeverityChanged?.Invoke();
                if (_reportVerdict) Completed?.Invoke(CheckStatus.Fail);
                return;
            }
            _networkBlocked = false;

            AppendLine($"{DateTime.Now:yyyy-MM-dd HH:mm:ss}", ColorInfo, FontStyle.Italic);
            AppendLine("");

            _cts = new CancellationTokenSource();
            var token = _cts.Token;

            CenterBusy();
            _busy.Start();
            CheckStatus overall = CheckStatus.Pass;
            bool cancelled = false;
            try
            {
                foreach (var (label, run) in _steps)
                {
                    if (token.IsCancellationRequested) { cancelled = true; break; }
                    _status.Text = $"Running {label} ...";
                    CheckGroup? g = await RunStepAsync(run, token);
                    if (g == null) { cancelled = true; break; }   // cancelled mid-step
                    _lastGroups.Add(g);
                    RenderGroup(g);
                    if (CheckGroup.Rank(g.Worst()) > CheckGroup.Rank(overall))
                        overall = g.Worst();
                }

                if (cancelled)
                {
                    AppendLine("");
                    AppendLine("Scan cancelled - partial results shown above.",
                        ColorWarn, FontStyle.Bold, 11f);
                    _status.Text = "Cancelled";
                }
                else
                {
                    _status.Text = $"Completed {DateTime.Now:HH:mm:ss}";
                }
            }
            finally
            {
                _busy.Stop();
                _cts.Dispose();
                _cts = null;
                HasRun = true;
                _runButton.Enabled = true;
                _running = false;
            }
            Severity = Sev.FromStatus(overall);
            SeverityChanged?.Invoke();
            // Don't drive the overall verdict (e.g. the Launch-Chrome gate) off a partial,
            // user-cancelled run.
            if (!cancelled && _reportVerdict) Completed?.Invoke(overall);
        }

        /// <summary>
        /// Runs one check on the thread pool, racing it against cancellation. A check is not
        /// itself cancellable, but its blocking network calls are bounded by their own timeouts,
        /// so on cancel we stop awaiting and abandon the worker - it finishes on its own within
        /// those bounds. Returns the populated group, or null if cancelled before it completed.
        /// </summary>
        private static async Task<CheckGroup?> RunStepAsync(Func<CheckGroup> run, CancellationToken token)
        {
            var work = Task.Run(run);
            var cancel = Task.Delay(Timeout.Infinite, token);
            var done = await Task.WhenAny(work, cancel);
            if (done != work)
            {
                // Abandoned: swallow any later fault so it isn't an unobserved task exception.
                _ = work.ContinueWith(static t => { _ = t.Exception; },
                    TaskContinuationOptions.OnlyOnFaulted | TaskContinuationOptions.ExecuteSynchronously);
                return null;
            }
            return await work;
        }

        private void OnCancelRequested()
        {
            _status.Text = "Cancelling ...";
            _cts?.Cancel();
        }

        private void RenderGroup(CheckGroup group)
        {
            // The heading carries an optional inline "open the relevant control panel" link.
            Append(group.Title, ColorText, FontStyle.Bold, 11f);
            AppendSectionLink(group.Title);
            AppendLine("");
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
            _output.SelectionFont = Theme.Scaled("Consolas", size, style);
            _output.AppendText(text);
            _output.SelectionColor = _output.ForeColor;
        }

        private void AppendLine(string text, Color color, FontStyle style = FontStyle.Regular, float size = 9.5f)
            => Append(text + Environment.NewLine, color, style, size);

        private void AppendLine(string text) => AppendLine(text, _output.ForeColor);

        /// <summary>The offline warning shown (in place of any checks) by network-dependent tabs.</summary>
        private void RenderNetworkWarning()
        {
            AppendLine("");
            AppendLine("  Network not available, unable to perform requested checks",
                ColorFail, FontStyle.Bold, 13f);
            AppendLine("");
            AppendLine("  Airplane mode may be on, or no network adapter is connected.", ColorInfo, FontStyle.Regular, 11f);
            AppendLine("");
            Append("  ", ColorInfo);
            AppendLink("[ Open network settings ]", NetworkStatus.OpenSettings, 11f);
            AppendLine("");
        }

        /// <summary>Appends the inline action link for a section heading, if one is mapped.</summary>
        private void AppendSectionLink(string title)
        {
            // Hosts File opens a folder (and selects the file), not a settings URI.
            if (title.Contains("Hosts File", StringComparison.OrdinalIgnoreCase))
            {
                Append("      ", ColorInfo);
                AppendLink("[ Open hosts folder ]", OpenHostsFolder);
                return;
            }
            // A section may map to more than one link (e.g. section 11 offers both
            // Device Manager and Apps); append every match, spaced apart.
            foreach (var (match, label, uri) in SectionLinks)
            {
                if (title.Contains(match, StringComparison.OrdinalIgnoreCase))
                {
                    Append("      ", ColorInfo);
                    AppendLink(label, () => OpenUri(uri));
                }
            }
        }

        // ---- Inline clickable links ----
        /// <summary>Appends underlined link text and records its char range + action.</summary>
        private void AppendLink(string text, Action onClick, float size = 9.5f)
        {
            int start = _output.TextLength;
            Append(text, ColorLink, FontStyle.Underline, size);
            _links.Add(new LinkRegion { Start = start, End = _output.TextLength, OnClick = onClick });
        }

        private bool IsOverLink(Point p, int start, int end)
        {
            if (start < 0 || end <= start) return false;
            Point a = _output.GetPositionFromCharIndex(start);
            Point b = _output.GetPositionFromCharIndex(end);
            if (b.Y < a.Y) return false;
            int h = (int)Math.Ceiling(_output.Font.GetHeight()) + 4;
            var rect = new Rectangle(a.X, a.Y, Math.Max(1, b.X - a.X), h);
            return rect.Contains(p);
        }

        private LinkRegion? LinkAt(Point p)
        {
            foreach (var lk in _links)
                if (IsOverLink(p, lk.Start, lk.End)) return lk;
            return null;
        }

        private void Output_MouseDown(object? sender, MouseEventArgs e)
        {
            if (e.Button == MouseButtons.Left) LinkAt(e.Location)?.OnClick();
        }

        private void Output_MouseMove(object? sender, MouseEventArgs e)
            => _output.Cursor = LinkAt(e.Location) != null ? Cursors.Hand : Cursors.IBeam;

        /// <summary>Opens a settings URI / control panel (e.g. ms-settings:, windowsdefender:, ncpa.cpl).</summary>
        private void OpenUri(string uri)
        {
            try { Process.Start(new ProcessStartInfo(uri) { UseShellExecute = true }); }
            catch (Exception ex)
            {
                CopyableMessageBox.Show(this, $"Could not open '{uri}': {ex.Message}",
                    "B4 Browse", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
        }

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
                CopyableMessageBox.Show(this, "Could not open hosts folder: " + ex.Message,
                    "B4 Browse", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
        }
    }
}
