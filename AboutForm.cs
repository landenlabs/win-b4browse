// Copyright (c) 2026 LanDen Labs - Dennis Lang

using System;
using System.Drawing;
using System.Diagnostics;
using System.Drawing.Imaging;
using System.IO;
using System.Windows.Forms;

namespace B4Browse
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
        private MemoryStream? _animStream;
        private int _frameCount;
        private EventHandler? _frameHandler;
        private System.Windows.Forms.Timer? _animTimer;

        public AboutForm()
        {
            Text = "About B4 Browse";
            Icon = EmbeddedAssets.LoadIcon("icon.ico");
            FormBorderStyle = FormBorderStyle.FixedDialog;
            StartPosition = FormStartPosition.CenterParent;
            ClientSize = new Size(420, 320);
            MaximizeBox = false;
            MinimizeBox = false;

            _picture = new PictureBox
            {
                Dock = DockStyle.Top,
                Height = 100, // will be adjusted after image load
                SizeMode = PictureBoxSizeMode.Zoom,
                BackColor = Color.Transparent,
                Visible = true,
            };

            _title = new Label
            {
                Left = 12,
                Top = _picture.Bottom + 8,
                Width = ClientSize.Width - 24,
                Height = 24,
                Font = new Font("Segoe UI", 11f, FontStyle.Bold),
                Text = "B4 Browse - Chrome Safety Check",
                TextAlign = ContentAlignment.MiddleCenter,
            };

            _version = new Label
            {
                Left = 12,
                Top = _title.Bottom + 4,
                Width = ClientSize.Width - 24,
                Height = 18,
                Font = new Font("Segoe UI", 9f, FontStyle.Regular),
                ForeColor = Theme.Subtle,
                TextAlign = ContentAlignment.MiddleCenter,
            };

            _desc = new TextBox
            {
                Left = 12,
                Top = _version.Bottom + 8,
                Width = ClientSize.Width - 24,
                Height = 120,
                Multiline = true,
                ReadOnly = true,
                BorderStyle = BorderStyle.None,
                BackColor = SystemColors.Window,
                Text = "A small tool to inspect Chrome, extensions, and local system indicators relevant to browsing safety.",
            };

            _link = new LinkLabel
            {
                Left = 12,
                Top = _desc.Bottom + 8,
                Width = ClientSize.Width - 140,
                Height = 20,
                Text = "https://github.com/landenlabs/win-b4-browse",
                LinkBehavior = LinkBehavior.HoverUnderline
            };
            _link.LinkClicked += (_, _) => { try { var psi = new ProcessStartInfo(_link.Text) { UseShellExecute = true }; Process.Start(psi); } catch { } };

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

            // Add controls in top-to-bottom order so Dock/Top layout behaves predictably
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
            // Single source of truth, kept in sync with VERSION / csproj / README by set-version.ps1.
            _version.Text = $"Version: {AppInfo.Version}   ({AppInfo.BuildDate})";

            // Prefer the animated GIF asset, then the static PNG. Load from the embedded
            // resource baked into the (single-file) exe, with a fallback to a loose file
            // next to the exe for debug runs from the build folder.
            _animImage = LoadBrandImage("landenlabs_400.gif") ?? LoadBrandImage("landenlabs_400.png");

            if (_animImage != null)
            {
                try
                {
                    // Resize picture box to full width and maintain aspect ratio based on image size
                    int w = ClientSize.Width - 24;
                    int h = (int)Math.Round(w * (_animImage.Height / (double)_animImage.Width));
                    _picture.Width = w;
                    _picture.Height = h;
                    _picture.Top = 12;
                    _picture.Left = 12;
                    _picture.Image = _animImage;

                    // Move subsequent controls below the image
                    _title.Top = _picture.Bottom + 8;
                    _version.Top = _title.Bottom + 4;
                    _desc.Top = _version.Bottom + 8;
                    _link.Top = _desc.Bottom + 8;
                    _ok.Top = ClientSize.Height - 42;

                    var dim = new FrameDimension(_animImage.FrameDimensionsList[0]);
                    _frameCount = _animImage.GetFrameCount(dim);
                    if (_frameCount > 1)
                    {
                        // Use ImageAnimator + a WinForms Timer to reliably advance frames and repaint the PictureBox.
                        _frameHandler = new EventHandler((s, ev) => { /* no-op, timer drives updates */ });
                        try { ImageAnimator.Animate(_animImage, _frameHandler); }
                        catch { _frameHandler = null; }

                        try
                        {
                            _animTimer = new System.Windows.Forms.Timer();
                            // Safe default: try to read frame delay from property, otherwise fall back to 100ms.
                            int interval = 100;
                            try
                            {
                                // GIF frame delays are stored in property 0x5100 (PropertyTagFrameDelay) as byte[]. Values are in 1/100 sec.
                                const int PropertyTagFrameDelay = 0x5100;
                                if (_animImage.PropertyIdList != null && Array.IndexOf(_animImage.PropertyIdList, PropertyTagFrameDelay) >= 0)
                                {
                                    var prop = _animImage.GetPropertyItem(PropertyTagFrameDelay);
                                    if (prop != null && prop.Value != null && prop.Value.Length >= 4)
                                    {
                                        // take first frame delay
                                        int delay = BitConverter.ToInt32(prop.Value, 0);
                                        if (delay > 0) interval = Math.Max(20, delay * 10); // convert 1/100s to ms
                                    }
                                }
                            }
                            catch { }

                            _animTimer.Interval = interval;
                            _animTimer.Tick += (_, _) =>
                            {
                                try { ImageAnimator.UpdateFrames(_animImage); _picture.Invalidate(); }
                                catch { }
                            };
                            _animTimer.Start();
                        }
                        catch { }
                    }
                }
                catch { }
            }
        }

        // Loads a brand image by file name from the embedded manifest resources, falling
        // back to a loose file beside the exe (debug runs). GDI+ requires the backing
        // stream to stay open for the life of the Image (GIF frame seeking), so the
        // MemoryStream is held in _animStream and disposed when the form closes.
        private Image? LoadBrandImage(string fileName)
        {
            try
            {
                var asm = System.Reflection.Assembly.GetExecutingAssembly();
                var resName = asm.GetManifestResourceNames()
                    .FirstOrDefault(n => n.EndsWith("." + fileName, StringComparison.OrdinalIgnoreCase)
                                      || n.Equals(fileName, StringComparison.OrdinalIgnoreCase));
                if (resName != null)
                {
                    using var rs = asm.GetManifestResourceStream(resName);
                    if (rs != null)
                    {
                        var ms = new MemoryStream();
                        rs.CopyTo(ms);
                        ms.Position = 0;
                        var img = Image.FromStream(ms);
                        _animStream?.Dispose();
                        _animStream = ms;
                        return img;
                    }
                }
            }
            catch { }

            try
            {
                var path = Path.Combine(AppContext.BaseDirectory, fileName);
                if (File.Exists(path))
                {
                    // Read into memory so the file on disk isn't held locked.
                    var ms = new MemoryStream(File.ReadAllBytes(path));
                    var img = Image.FromStream(ms);
                    _animStream?.Dispose();
                    _animStream = ms;
                    return img;
                }
            }
            catch { }

            return null;
        }

        private void AboutForm_FormClosed(object? sender, FormClosedEventArgs e)
        {
            if (_animImage != null && _frameHandler != null)
            {
                try { ImageAnimator.StopAnimate(_animImage, _frameHandler); } catch { }
            }
            try { _animTimer?.Stop(); _animTimer?.Dispose(); } catch { }
            try { _picture.Image?.Dispose(); } catch { }
            try { _animImage?.Dispose(); } catch { }
            try { _animStream?.Dispose(); } catch { }
        }
    }
}
