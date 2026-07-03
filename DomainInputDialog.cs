// Copyright (c) 2026 LanDen Labs - Dennis Lang

using System;
using System.Drawing;
using System.Windows.Forms;

namespace B4Browse
{
    /// <summary>
    /// Small modal prompt used by the "Check my domain" link on the Cross-Resolver DNS
    /// Comparison section: one text box + OK/Cancel. Manual layout (like <see cref="AboutForm"/>
    /// and <see cref="CopyableMessageBox"/>) so it stays tiny and themeable.
    /// </summary>
    public sealed class DomainInputDialog : Form
    {
        private readonly TextBox _domainBox;

        /// <summary>The trimmed text the user entered when the dialog closes with OK.</summary>
        public string Domain => _domainBox.Text.Trim();

        public DomainInputDialog(string prompt, string caption, string initialValue = "")
        {
            const int pad = 14;
            Text = caption;
            FormBorderStyle = FormBorderStyle.FixedDialog;
            StartPosition = FormStartPosition.CenterParent;
            MaximizeBox = false;
            MinimizeBox = false;
            ShowInTaskbar = false;
            BackColor = Theme.Window;
            ForeColor = Theme.Text;
            try { Icon = EmbeddedAssets.LoadIcon("icon.ico"); } catch { /* non-fatal */ }

            var font = new Font("Segoe UI", 9.75f);

            var label = new Label
            {
                AutoSize = true,
                Left = pad,
                Top = pad,
                MaximumSize = new Size(360, 0),
                Font = font,
                ForeColor = Theme.Text,
                Text = prompt,
            };
            Controls.Add(label);

            _domainBox = new TextBox
            {
                Left = pad,
                Top = label.Bottom + 8,
                Width = 360,
                Font = font,
                Text = initialValue,
                BackColor = Theme.Surface,
                ForeColor = Theme.Text,
            };
            Controls.Add(_domainBox);

            const int bw = 92, bh = 30, gap = 8;
            int rowTop = _domainBox.Bottom + pad;
            int contentRight = pad + _domainBox.Width;

            var cancel = new Button { Text = "Cancel", AutoSize = false };
            cancel.Click += (_, _) => { DialogResult = DialogResult.Cancel; Close(); };
            cancel.SetBounds(contentRight - bw, rowTop, bw, bh);

            var ok = new Button { Text = "OK", AutoSize = false };
            ok.Click += (_, _) => { DialogResult = DialogResult.OK; Close(); };
            ok.SetBounds(cancel.Left - gap - bw, rowTop, bw, bh);

            Controls.Add(ok);
            Controls.Add(cancel);

            ClientSize = new Size(contentRight + pad, rowTop + bh + pad);
            Theme.StyleButtons(this);

            AcceptButton = ok;
            CancelButton = cancel;

            Shown += (_, _) => { _domainBox.Focus(); _domainBox.SelectAll(); };
        }
    }
}
