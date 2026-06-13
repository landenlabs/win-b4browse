// Copyright (c) 2026 LanDen Labs - Dennis Lang

using System;
using System.Drawing;
using System.Media;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace B4Browse
{
    /// <summary>
    /// A drop-in replacement for <see cref="MessageBox"/> whose message lives in a
    /// read-only, selectable <see cref="TextBox"/> so the text can always be copied.
    /// While the dialog has focus, <c>Ctrl+A</c> selects the whole message and
    /// <c>Ctrl+C</c> copies it (an explicit <b>Copy</b> button does the same), so the
    /// content of an error never has to be transcribed from a screenshot.
    ///
    /// The signatures mirror the <see cref="MessageBox.Show(IWin32Window, string, string, MessageBoxButtons, MessageBoxIcon)"/>
    /// overloads the app uses, so call sites swap <c>MessageBox.Show</c> for
    /// <c>CopyableMessageBox.Show</c> with no other change.
    /// </summary>
    public static class CopyableMessageBox
    {
        public static DialogResult Show(string text, string caption,
            MessageBoxButtons buttons = MessageBoxButtons.OK, MessageBoxIcon icon = MessageBoxIcon.None)
            => Show(null, text, caption, buttons, icon);

        public static DialogResult Show(IWin32Window? owner, string text, string caption,
            MessageBoxButtons buttons = MessageBoxButtons.OK, MessageBoxIcon icon = MessageBoxIcon.None)
        {
            // An OK-only dialog carries no decision, so show it MODELESS: it never blocks the
            // main app - the user can keep working with it open and dismiss it whenever.
            if (buttons == MessageBoxButtons.OK)
            {
                var dlg = new CopyableDialog(text ?? "", caption ?? "", buttons, icon);
                dlg.FormClosed += (_, _) => dlg.Dispose();
                if (owner is Form f) dlg.Owner = f;   // stay above the parent; close with it
                dlg.Show();
                return DialogResult.OK;
            }

            // A decision dialog (Yes/No, OK/Cancel, ...) must be modal: the caller branches on
            // the result and cannot proceed until the user answers.
            using var modal = new CopyableDialog(text ?? "", caption ?? "", buttons, icon);
            return owner != null ? modal.ShowDialog(owner) : modal.ShowDialog();
        }

        /// <summary>
        /// Like <see cref="Show(IWin32Window, string, string, MessageBoxButtons, MessageBoxIcon)"/>
        /// but NON-BLOCKING even for a decision (Yes/No) dialog: the dialog is shown modeless so
        /// the main window stays live (drag it, scroll it, review the list behind the dialog),
        /// and the answer is delivered when the user closes it. <c>await</c> the returned task
        /// from a UI handler - the UI thread returns to its message loop while awaiting.
        /// Closing via the title-bar X resolves to <see cref="DialogResult.Cancel"/>.
        /// </summary>
        public static Task<DialogResult> ShowAsync(IWin32Window? owner, string text, string caption,
            MessageBoxButtons buttons = MessageBoxButtons.OK, MessageBoxIcon icon = MessageBoxIcon.None)
        {
            var tcs = new TaskCompletionSource<DialogResult>();
            var dlg = new CopyableDialog(text ?? "", caption ?? "", buttons, icon);
            dlg.FormClosed += (_, _) =>
            {
                var result = dlg.DialogResult == DialogResult.None ? DialogResult.Cancel : dlg.DialogResult;
                dlg.Dispose();
                tcs.TrySetResult(result);
            };
            if (owner is Form f) dlg.Owner = f;   // stay above the parent; close with it
            dlg.Show();
            return tcs.Task;
        }

        /// <summary>The actual dialog window. Manual layout (like AboutForm) so it sizes to its text.</summary>
        private sealed class CopyableDialog : Form
        {
            private const int Pad = 14;
            private const int IconSize = 32;
            private const int MaxTextWidth = 680;
            private const int MaxTextHeight = 480;

            private readonly TextBox _text;

            public CopyableDialog(string message, string caption, MessageBoxButtons buttons, MessageBoxIcon icon)
            {
                Text = caption;
                FormBorderStyle = FormBorderStyle.FixedDialog;
                StartPosition = FormStartPosition.CenterParent;
                MaximizeBox = false;
                MinimizeBox = false;
                ShowInTaskbar = false;
                KeyPreview = true;          // so Ctrl+A / Ctrl+C work no matter which control has focus
                BackColor = Theme.Window;
                ForeColor = Theme.Text;
                try { Icon = EmbeddedAssets.LoadIcon("icon.ico"); } catch { /* non-fatal */ }

                Image? sysIcon = IconFor(icon);
                int iconCol = sysIcon != null ? Pad + IconSize + Pad : Pad;

                // A WinForms TextBox only breaks lines on CRLF, so normalise the message's
                // bare "\n" to "\r\n" - otherwise every line runs together as one paragraph.
                message = message.Replace("\r\n", "\n").Replace('\r', '\n').Replace("\n", "\r\n");

                // Natural width = widest line if nothing wrapped; the box grows to that, capped at
                // MaxTextWidth. Word-wrap is ON (explicit "\r\n" breaks are still honoured, so the
                // caller's line layout - e.g. one extension per line - is preserved), so any longer
                // line reflows to the chosen width. That means a horizontal scrollbar is never needed;
                // only a vertical one appears, and only when the wrapped text is taller than the cap.
                var font = new Font("Segoe UI", 9.75f);
                Size natural = TextRenderer.MeasureText(
                    message, font, new Size(int.MaxValue, int.MaxValue), TextFormatFlags.TextBoxControl);
                int textWidth = Math.Clamp(natural.Width + 4, 220, MaxTextWidth);

                Size measured = TextRenderer.MeasureText(
                    message, font, new Size(textWidth, int.MaxValue),
                    TextFormatFlags.WordBreak | TextFormatFlags.TextBoxControl);
                int textHeight = Math.Min(measured.Height + 4, MaxTextHeight);
                bool needV = measured.Height + 4 > MaxTextHeight;
                if (needV) textWidth += SystemInformation.VerticalScrollBarWidth;   // keep wrap width unchanged

                _text = new TextBox
                {
                    Multiline = true,
                    ReadOnly = true,
                    WordWrap = true,
                    BorderStyle = BorderStyle.None,
                    ScrollBars = needV ? ScrollBars.Vertical : ScrollBars.None,
                    Font = font,
                    Text = message,
                    BackColor = Theme.Window,
                    ForeColor = Theme.Text,
                    Left = iconCol,
                    Top = Pad,
                    Width = textWidth,
                    Height = textHeight,
                    TabStop = false,
                };

                if (sysIcon != null)
                {
                    Controls.Add(new PictureBox
                    {
                        Image = sysIcon,
                        SizeMode = PictureBoxSizeMode.CenterImage,
                        Left = Pad,
                        Top = Pad,
                        Width = IconSize,
                        Height = IconSize,
                        BackColor = Color.Transparent,
                    });
                }
                Controls.Add(_text);

                // --- Buttons row ------------------------------------------------ //
                int rowTop = _text.Bottom + Pad;
                const int bw = 92, bh = 30, gap = 8;

                var actionButtons = MakeActionButtons(buttons);

                // Content is at least wide enough for the (right-aligned) action buttons.
                int actionsWidth = actionButtons.Count * bw + Math.Max(0, actionButtons.Count - 1) * gap;
                int contentWidth = Math.Max(textWidth, actionsWidth);
                int contentRight = iconCol + contentWidth;
                _text.Width = contentWidth;

                int x = contentRight;
                for (int i = actionButtons.Count - 1; i >= 0; i--)
                {
                    var b = actionButtons[i];
                    b.SetBounds(x - bw, rowTop, bw, bh);
                    x -= bw + gap;
                    Controls.Add(b);
                }

                int clientWidth = contentRight + Pad;
                int clientHeight = rowTop + bh + Pad;
                ClientSize = new Size(clientWidth, clientHeight);

                Theme.StyleButtons(this);

                // Enter triggers the default action button; Esc triggers the cancel one.
                if (actionButtons.Count > 0) AcceptButton = actionButtons[0];
                CancelButton = actionButtons.Count > 1 ? actionButtons[^1] : actionButtons[0];

                KeyDown += OnKeyDown;
                Shown += (_, _) =>
                {
                    // CenterParent only applies to ShowDialog; centre a modeless dialog by hand.
                    if (!Modal && Owner != null)
                    {
                        var o = Owner.Bounds;
                        Location = new Point(o.Left + (o.Width - Width) / 2, o.Top + (o.Height - Height) / 2);
                    }
                    if (AcceptButton is Button ab) ab.Focus();
                    PlaySound(icon);
                };
            }

            // ---- behaviour --------------------------------------------------- //

            private void OnKeyDown(object? sender, KeyEventArgs e)
            {
                if (e.Control && e.KeyCode == Keys.A)
                {
                    _text.Focus();
                    _text.SelectAll();
                    e.Handled = e.SuppressKeyPress = true;
                }
                else if (e.Control && e.KeyCode == Keys.C)
                {
                    CopyAll();
                    e.Handled = e.SuppressKeyPress = true;
                }
            }

            /// <summary>Copies the current selection, or the whole message if nothing is selected.</summary>
            private void CopyAll()
            {
                string s = _text.SelectionLength > 0 ? _text.SelectedText : _text.Text;
                try { if (s.Length > 0) Clipboard.SetText(s); } catch { /* clipboard busy - non-fatal */ }
            }

            // ---- construction helpers --------------------------------------- //

            private System.Collections.Generic.List<Button> MakeActionButtons(MessageBoxButtons buttons)
            {
                var list = new System.Collections.Generic.List<Button>();
                switch (buttons)
                {
                    case MessageBoxButtons.OKCancel:
                        list.Add(MakeResultButton("OK", DialogResult.OK));
                        list.Add(MakeResultButton("Cancel", DialogResult.Cancel));
                        break;
                    case MessageBoxButtons.YesNo:
                        list.Add(MakeResultButton("Yes", DialogResult.Yes));
                        list.Add(MakeResultButton("No", DialogResult.No));
                        break;
                    case MessageBoxButtons.YesNoCancel:
                        list.Add(MakeResultButton("Yes", DialogResult.Yes));
                        list.Add(MakeResultButton("No", DialogResult.No));
                        list.Add(MakeResultButton("Cancel", DialogResult.Cancel));
                        break;
                    case MessageBoxButtons.RetryCancel:
                        list.Add(MakeResultButton("Retry", DialogResult.Retry));
                        list.Add(MakeResultButton("Cancel", DialogResult.Cancel));
                        break;
                    default: // OK
                        list.Add(MakeResultButton("OK", DialogResult.OK));
                        break;
                }
                return list;
            }

            private Button MakeResultButton(string text, DialogResult result)
            {
                // Set the result and close explicitly: a button's implicit DialogResult only
                // auto-closes inside ShowDialog's modal loop, not a modeless (Show) dialog.
                return MakeButton(text, (_, _) => { DialogResult = result; Close(); });
            }

            private static Button MakeButton(string text, EventHandler? onClick)
            {
                var b = new Button { Text = text, AutoSize = false };
                if (onClick != null) b.Click += onClick;
                return b;
            }

            private static Image? IconFor(MessageBoxIcon icon) => icon switch
            {
                // Error/Stop/Hand share a value; same for Warning/Exclamation, Information/Asterisk.
                MessageBoxIcon.Error => SystemIcons.Error.ToBitmap(),
                MessageBoxIcon.Warning => SystemIcons.Warning.ToBitmap(),
                MessageBoxIcon.Question => SystemIcons.Question.ToBitmap(),
                MessageBoxIcon.Information => SystemIcons.Information.ToBitmap(),
                _ => null,
            };

            private static void PlaySound(MessageBoxIcon icon)
            {
                try
                {
                    switch (icon)
                    {
                        case MessageBoxIcon.Error: SystemSounds.Hand.Play(); break;
                        case MessageBoxIcon.Warning: SystemSounds.Exclamation.Play(); break;
                        case MessageBoxIcon.Question: SystemSounds.Question.Play(); break;
                        case MessageBoxIcon.Information: SystemSounds.Asterisk.Play(); break;
                    }
                }
                catch { /* no audio device - non-fatal */ }
            }
        }
    }
}
