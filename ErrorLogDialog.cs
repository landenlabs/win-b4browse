// Copyright (c) 2026 LanDen Labs - Dennis Lang

using System;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Windows.Forms;

namespace B4Browse
{
    /// <summary>
    /// Modal viewer for <see cref="ErrorLog"/> - the background-action failures (PowerShell
    /// agents that timed out, returned nothing, or threw) collected during the session. Opened
    /// from the status-bar error badge. Read-only; offers Copy-all and Clear. Refreshes live
    /// while open so failures from a still-running scan appear without reopening.
    /// </summary>
    public sealed class ErrorLogDialog : Form
    {
        private readonly ListView _list;
        private readonly TextBox _detail;
        private readonly Button _copy;
        private readonly Button _clear;
        private readonly Button _close;

        public ErrorLogDialog()
        {
            Text = "Background errors";
            Icon = EmbeddedAssets.LoadIcon("icon.ico");
            StartPosition = FormStartPosition.CenterParent;
            MinimumSize = new Size(620, 380);
            ClientSize = new Size(780, 470);
            BackColor = Theme.Window;
            ForeColor = Theme.Text;
            Font = new Font("Segoe UI", 9f);

            _list = new ListView
            {
                Dock = DockStyle.Fill,
                View = View.Details,
                FullRowSelect = true,
                MultiSelect = false,
                HideSelection = false,
                UseCompatibleStateImageBehavior = false,
                BackColor = Theme.Surface,
                ForeColor = Theme.Text,
            };
            _list.Columns.Add("Time", 90);
            _list.Columns.Add("Category", 90);
            _list.Columns.Add("Source", 190);
            _list.Columns.Add("Message", 380);
            _list.SelectedIndexChanged += (_, _) => ShowDetail();

            _detail = new TextBox
            {
                Dock = DockStyle.Bottom,
                Height = 140,
                Multiline = true,
                ReadOnly = true,
                ScrollBars = ScrollBars.Vertical,
                BorderStyle = BorderStyle.FixedSingle,
                BackColor = Theme.Surface,
                ForeColor = Theme.Text,
                Font = new Font("Consolas", 9f),
            };

            var buttons = new Panel { Dock = DockStyle.Bottom, Height = 46, BackColor = Theme.Toolbar };
            _copy  = new Button { Text = "Copy all", Width = 90, Height = 28, Top = 9 };
            _clear = new Button { Text = "Clear",    Width = 90, Height = 28, Top = 9 };
            _close = new Button { Text = "Close",    Width = 90, Height = 28, Top = 9 };
            _copy.Click  += (_, _) => CopyAll();
            _clear.Click += (_, _) => ErrorLog.Clear();   // Changed event repopulates the list
            _close.Click += (_, _) => Close();
            buttons.Controls.Add(_copy);
            buttons.Controls.Add(_clear);
            buttons.Controls.Add(_close);
            buttons.SizeChanged += (_, _) => LayoutButtons(buttons);

            // Fill first, then the docked-bottom panes (outermost added last).
            Controls.Add(_list);
            Controls.Add(_detail);
            Controls.Add(buttons);

            Theme.StyleButtons(this);
            LayoutButtons(buttons);

            Populate();
            ErrorLog.Changed += OnLogChanged;
            FormClosed += (_, _) => ErrorLog.Changed -= OnLogChanged;
        }

        private void LayoutButtons(Panel p)
        {
            int right = p.ClientSize.Width - 12;
            _close.Left = right - _close.Width;
            _clear.Left = _close.Left - _clear.Width - 8;
            _copy.Left  = _clear.Left - _copy.Width - 8;
        }

        private void OnLogChanged()
        {
            if (IsHandleCreated) BeginInvoke(new Action(Populate));
        }

        private void Populate()
        {
            // Preserve the selected entry across a live refresh where possible.
            var selected = _list.SelectedItems.Count > 0 ? _list.SelectedItems[0].Tag as ErrorEntry : null;

            _list.BeginUpdate();
            _list.Items.Clear();
            foreach (var e in ErrorLog.Snapshot().Reverse())   // newest first
            {
                var item = new ListViewItem(e.TimeLocal.ToString("HH:mm:ss"));
                item.SubItems.Add(e.Category.ToString());
                item.SubItems.Add(e.Source);
                item.SubItems.Add(OneLine(e.Message));
                item.Tag = e;
                item.ForeColor = CategoryColor(e.Category);
                if (ReferenceEquals(e, selected)) item.Selected = true;
                _list.Items.Add(item);
            }
            _list.EndUpdate();

            if (_list.SelectedItems.Count == 0 && _list.Items.Count > 0)
                _list.Items[0].Selected = true;
            if (_list.Items.Count == 0)
                _detail.Text = "No background errors recorded this session.";
        }

        private void ShowDetail()
        {
            if (_list.SelectedItems.Count == 0 || _list.SelectedItems[0].Tag is not ErrorEntry e)
                return;
            var sb = new StringBuilder();
            sb.AppendLine($"{e.TimeLocal:yyyy-MM-dd HH:mm:ss}  [{e.Category}]  {e.Source}");
            sb.AppendLine(e.Message);
            if (!string.IsNullOrWhiteSpace(e.Detail))
            {
                sb.AppendLine();
                sb.AppendLine(e.Detail);
            }
            _detail.Text = sb.ToString();
        }

        private void CopyAll()
        {
            var sb = new StringBuilder();
            foreach (var e in ErrorLog.Snapshot())
            {
                sb.AppendLine($"{e.TimeLocal:yyyy-MM-dd HH:mm:ss}  [{e.Category}]  {e.Source}  -  {OneLine(e.Message)}");
                if (!string.IsNullOrWhiteSpace(e.Detail))
                    sb.AppendLine("    " + e.Detail.Replace("\n", "\n    "));
            }
            try { if (sb.Length > 0) Clipboard.SetText(sb.ToString()); } catch { /* clipboard busy */ }
        }

        private static string OneLine(string s) =>
            s.Replace("\r", " ").Replace("\n", " ").Trim();

        private static Color CategoryColor(ErrorCategory c) => c switch
        {
            ErrorCategory.Timeout => Theme.IsDark ? Color.FromArgb(240, 190, 90) : Color.FromArgb(170, 105, 0),
            _ => Theme.IsDark ? Color.FromArgb(240, 120, 120) : Color.FromArgb(190, 0, 0),
        };
    }
}
