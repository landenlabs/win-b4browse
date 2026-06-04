// Copyright (c) 2026 LanDen Labs - Dennis Lang

using System;
using System.Diagnostics;
using System.Drawing;
using System.Windows.Forms;

namespace BrowseSafe
{
    /// <summary>Title + body for a tab's Help dialog. The body uses a light markup:
    /// a line starting "# " is a heading, "## " a sub-heading, "- "/"• " a bullet;
    /// blank lines are preserved. http(s) URLs are auto-detected and clickable.</summary>
    public sealed record HelpInfo(string Title, string Body);

    /// <summary>Shared "Help" button factory and the modal description dialog it opens.
    /// Reused by every tab (grids, the scan view, the firewall and links panels).</summary>
    public static class HelpUi
    {
        /// <summary>A small toolbar "Help" button wired to open <paramref name="info"/>'s dialog.
        /// The caller positions it (the tabs anchor it to the right edge of their toolbar).</summary>
        public static Button CreateButton(HelpInfo info)
        {
            var btn = new Button
            {
                Text = "Help",
                Width = 56,
                Height = 26,
                FlatStyle = FlatStyle.System,
                Font = new Font("Segoe UI", 9f),
            };
            btn.Click += (_, _) => Show(btn.FindForm(), info);
            return btn;
        }

        /// <summary>Shows a theme-aware, modal, resizable dialog describing a tab.</summary>
        public static void Show(IWin32Window? owner, HelpInfo info)
        {
            using var dlg = new Form
            {
                Text = info.Title,
                Size = new Size(660, 540),
                MinimumSize = new Size(420, 320),
                StartPosition = owner != null ? FormStartPosition.CenterParent : FormStartPosition.CenterScreen,
                FormBorderStyle = FormBorderStyle.Sizable,
                ShowInTaskbar = false,
                MaximizeBox = true,
                MinimizeBox = false,
                BackColor = Theme.Window,
                ForeColor = Theme.Text,
            };

            var body = new RichTextBox
            {
                Dock = DockStyle.Fill,
                ReadOnly = true,
                BorderStyle = BorderStyle.None,
                WordWrap = true,
                ScrollBars = RichTextBoxScrollBars.Vertical,
                BackColor = Theme.Surface,
                ForeColor = Theme.Text,
                DetectUrls = true,
                Cursor = Cursors.Arrow,
            };
            body.LinkClicked += (_, e) =>
            {
                if (string.IsNullOrEmpty(e.LinkText)) return;
                try { Process.Start(new ProcessStartInfo(e.LinkText) { UseShellExecute = true }); }
                catch { /* ignore */ }
            };

            var bottom = new Panel { Dock = DockStyle.Bottom, Height = 48, BackColor = Theme.Toolbar };
            var close = new Button
            {
                Text = "Close",
                Width = 90,
                Height = 28,
                FlatStyle = FlatStyle.System,
                Font = new Font("Segoe UI", 9f),
                Anchor = AnchorStyles.Right | AnchorStyles.Top,
            };
            close.Click += (_, _) => dlg.Close();
            bottom.Controls.Add(close);
            bottom.Resize += (_, _) =>
            {
                close.Left = bottom.ClientSize.Width - close.Width - 12;
                close.Top = (bottom.ClientSize.Height - close.Height) / 2;
            };

            // A little breathing room around the text.
            var pad = new Panel { Dock = DockStyle.Fill, Padding = new Padding(14, 12, 14, 8), BackColor = Theme.Surface };
            pad.Controls.Add(body);

            dlg.Controls.Add(pad);
            dlg.Controls.Add(bottom);
            dlg.AcceptButton = close;
            dlg.CancelButton = close;          // Esc closes

            RenderBody(body, info);
            // Force the bottom panel to lay out the Close button at its initial size.
            close.Left = bottom.ClientSize.Width - close.Width - 12;
            close.Top = (bottom.ClientSize.Height - close.Height) / 2;

            if (owner is Form f) dlg.ShowDialog(f);
            else dlg.ShowDialog();
        }

        // ---- Light markup renderer --------------------------------------- //
        private static void RenderBody(RichTextBox rtb, HelpInfo info)
        {
            Color heading = Theme.Text;
            Color subtle = Theme.Subtle;

            void Append(string text, Color color, float size, FontStyle style)
            {
                rtb.SelectionStart = rtb.TextLength;
                rtb.SelectionLength = 0;
                rtb.SelectionColor = color;
                rtb.SelectionFont = new Font("Segoe UI", size, style);
                rtb.AppendText(text);
            }

            // Title banner inside the body (the caption shows it too, but this anchors the page).
            Append(info.Title + "\n", heading, 13.5f, FontStyle.Bold);

            foreach (var raw in info.Body.Replace("\r\n", "\n").Split('\n'))
            {
                string line = raw;
                if (line.Length == 0) { Append("\n", subtle, 5f, FontStyle.Regular); continue; }

                if (line.StartsWith("# "))
                    Append(line.Substring(2) + "\n", heading, 11.5f, FontStyle.Bold);
                else if (line.StartsWith("## "))
                    Append(line.Substring(3) + "\n", heading, 10.5f, FontStyle.Bold);
                else if (line.StartsWith("- ") || line.StartsWith("• "))
                    Append("   •  " + line.Substring(2) + "\n", Theme.Text, 10f, FontStyle.Regular);
                else
                    Append(line + "\n", Theme.Text, 10f, FontStyle.Regular);
            }

            rtb.SelectionStart = 0;
            rtb.SelectionLength = 0;
            rtb.ScrollToCaret();
        }
    }
}
