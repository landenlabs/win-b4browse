using System;
using System.Drawing;
using System.Diagnostics;
using System.Drawing.Imaging;
using System.Reflection;
using System.IO;
using System.Threading;
using System.Windows.Forms;

namespace BrowseSafe
{
    public class AboutForm : Form
    {
        private PictureBox _picture = null!;
        private Label _title = null!;
        private Label _version = null!;
        private TextBox _desc = null!;
        private LinkLabel _link = null!;
        private Button _ok = null!;

        private Image? _animImage;
        private int _frameCount;
        private int _frameEvents;
        private EventHandler? _frameHandler;

        public AboutForm()
        {
            Text = "About Browse Safe";
            FormBorderStyle = FormBorderStyle.FixedDialog;
            StartPosition = FormStartPosition.CenterParent;
            ClientSize = new Size(420, 320);
            MaximizeBox = false;
            MinimizeBox = false;

            _picture = new PictureBox
            {
                Left = 12,
                Top = 12,
                Width = 64,
                Height = 64,
                SizeMode = PictureBoxSizeMode.Zoom,
                BackColor = Color.Transparent,
            };

            _title = new Label
            {
                Left = 88,
                Top = 12,
                Width = 312,
                Height = 24,
                Font = new Font("Segoe UI", 11f, FontStyle.Bold),
                Text = "Browse Safe - Chrome Safety Check",
            };

            _version = new Label
            {
                Left = 88,
                Top = 38,
                Width = 312,
                Height = 18,
                Font = new Font("Segoe UI", 9f, FontStyle.Regular),
                ForeColor = Theme.Subtle,
            };

            _desc = new TextBox
            {
                Left = 12,
                Top = 88,
                Width = 396,
                Height = 160,
                Multiline = true,
                ReadOnly = true,
                BorderStyle = BorderStyle.None,
                BackColor = SystemColors.Window,
                Text = "A small tool to inspect Chrome, extensions, and local system indicators relevant to browsing safety.",
            };

            _link = new LinkLabel
            {
                Left = 12,
                Top = 256,
                Width = 300,
                Height = 20,
                Text = "https://github.com/landenlabs/win-browse-safe",
                LinkBehavior = LinkBehavior.HoverUnderline
            };
            _link.LinkClicked += (_, _) => { try { ProcessStartInfo psi = new ProcessStartInfo(_link.Text) { UseShellExecute = true }; System.Diagnostics.Process.Start(psi); } catch { } };

            _ok = new Button
            {
                Text = "OK",
                Width = 90,
                Height = 28,
                Left = ClientSize.Width - 102,
                Top = ClientSize.Height - 42,
                Anchor = AnchorStyles.Bottom | AnchorStyles.Right,
            };
            _ok.Click += (_, _) => Close();

            Controls.Add(_picture);
            Controls.Add(_title);
            Controls.Add(_version);
            Controls.Add(_desc);
            Controls.Add(_link);
            Controls.Add(_ok);

            Load += AboutForm_Load;
            FormClosed += AboutForm_FormClosed;
        }

        private void AboutForm_Load(object? sender, EventArgs e)
        {
            try
            {
                var asm = System.Reflection.Assembly.GetEntryAssembly();
                string ver = asm?.GetCustomAttribute<System.Reflection.AssemblyInformationalVersionAttribute>()?.InformationalVersion
                    ?? asm?.GetName().Version?.ToString() ?? "?";
                _version.Text = "Version: " + ver;
            }
            catch { _version.Text = "Version: ?"; }

            string path = Path.Combine(AppContext.BaseDirectory, "landenlabs.webp");
            if (File.Exists(path))
            {
                try
                {
                    _animImage = Image.FromFile(path);
                    _picture.Image = _animImage;

                    // If image has multiple frames, animate it once.
                    var dim = new FrameDimension(_animImage.FrameDimensionsList[0]);
                    _frameCount = _animImage.GetFrameCount(dim);
                    if (_frameCount > 1)
                    {
                        _frameEvents = 0;
                        _frameHandler = new EventHandler((s, ev) =>
                        {
                            if (IsDisposed) return;
                            try
                            {
                                BeginInvoke(new Action(() =>
                                {
                                    try { ImageAnimator.UpdateFrames(_animImage); _picture.Invalidate(); } catch { }
                                    _frameEvents++;
                                    if (_frameEvents >= _frameCount)
                                    {
                                        try { ImageAnimator.StopAnimate(_animImage, _frameHandler); } catch { }
                                    }
                                }));
                            }
                            catch { }
                        });
                        try { ImageAnimator.Animate(_animImage, _frameHandler); }
                        catch { }
                    }
                }
                catch { /* ignore image errors */ }
            }
        }

        private void AboutForm_FormClosed(object? sender, FormClosedEventArgs e)
        {
            if (_animImage != null && _frameHandler != null)
            {
                try { ImageAnimator.StopAnimate(_animImage, _frameHandler); } catch { }
            }
            try { _picture.Image?.Dispose(); } catch { }
            try { _animImage?.Dispose(); } catch { }
        }
    }
}
