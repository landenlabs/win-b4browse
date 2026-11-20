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
        private PictureBox _appIcon = null!;     // app launch icon shown left of the title block
        private Label _title = null!;
        private Label _version = null!;
        private Button _introButton = null!;    // opens the Introduction / welcome Help page
        private Button _repoButton = null!;      // opens the GitHub repository in the browser
        private Button _updateButton = null!;    // checks GitHub for a newer release (then offers download)
        private Button _issueButton = null!;     // opens the GitHub Issues page to report a problem
        private LinkLabel _updateStatus = null!; // result line under the update button ("Release notes" link)
        private Label _legal = null!;            // copyright + license footer (text only, no links)
        private Button _ok = null!;
        private Image? _introIcon;               // app icon banner reused on the Intro page
        private string? _pendingDownloadUrl;     // set once an update is found; next click opens it

        private Image? _animImage;
        private MemoryStream? _animStream;
        private int _frameCount;
        private EventHandler? _frameHandler;
        private System.Windows.Forms.Timer? _animTimer;

        public AboutForm()
        {
            Text = "About B4-Browse";
            Icon = EmbeddedAssets.LoadIcon("icon.ico");
            FormBorderStyle = FormBorderStyle.FixedDialog;
            StartPosition = FormStartPosition.CenterParent;
            ClientSize = new Size(420, 400);
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
                Text = "B4-Browse - Chrome Safety Check",
                TextAlign = ContentAlignment.MiddleLeft,
            };

            _version = new Label
            {
                Left = 12,
                Top = _title.Bottom + 4,
                Width = ClientSize.Width - 24,
                Height = 18,
                Font = new Font("Segoe UI", 9f, FontStyle.Regular),
                ForeColor = Theme.Subtle,
                TextAlign = ContentAlignment.MiddleLeft,
            };

            // Reuse the app icon as the banner shown atop the Introduction page (same as the
            // left-panel Intro button in MainForm).
            try { if (Icon != null) _introIcon = new Icon(Icon, new Size(64, 64)).ToBitmap(); } catch { }

            _appIcon = new PictureBox
            {
                SizeMode = PictureBoxSizeMode.Zoom,
                BackColor = Color.Transparent,
                Image = _introIcon,   // shared with the Intro page header; disposed once on close
            };

            _introButton = new Button
            {
                Text = "ℹ  Introduction",
                Font = new Font("Segoe UI", 9.5f, FontStyle.Bold),
                Cursor = Cursors.Hand,
            };
            _introButton.Click += (_, _) => HelpUi.Show(this, TabHelp.Intro with { Header = _introIcon });

            _repoButton = new Button
            {
                Text = "🌐  Open GitHub repository",
                Cursor = Cursors.Hand,
            };
            _repoButton.Click += (_, _) => OpenUrl(UpdateCheck.RepoUrl);

            // Store (MSIX) installs are updated by the Microsoft Store, so the button hands off to the
            // Store instead of querying GitHub (see InstallSource / UpdateCheck for why).
            _updateButton = new Button
            {
                Text = InstallSource.IsStore ? "⟳  Check for updates in Store" : "⟳  Check for updates",
                Cursor = Cursors.Hand,
            };
            _updateButton.Click += UpdateButton_Click;

            _issueButton = new Button
            {
                Text = "🐞  Submit issue",
                Cursor = Cursors.Hand,
            };
            _issueButton.Click += (_, _) => OpenUrl(UpdateCheck.IssuesUrl);

            // A LinkLabel so the "Release notes" part of the status can be clicked; with no link
            // area set it renders as a plain label.
            _updateStatus = new LinkLabel
            {
                AutoSize = false,
                TextAlign = ContentAlignment.MiddleCenter,
                ForeColor = Theme.Subtle,
                LinkColor = Theme.Link,
                ActiveLinkColor = Theme.Link,
                VisitedLinkColor = Theme.Link,
            };
            if (InstallSource.IsStore)
                SetStatus("Installed from the Microsoft Store — updates are installed automatically.", Theme.Subtle,
                          "Store page", InstallSource.StoreListingUri);
            else
                SetStatus("", Theme.Subtle);
            _updateStatus.LinkClicked += (_, e) => { if (e.Link?.LinkData is string url) OpenUrl(url); };

            // Copyright + license footer. Plain text (no links) sourced from AppInfo so it never
            // needs separate maintenance.
            _legal = new Label
            {
                AutoSize = false,
                TextAlign = ContentAlignment.MiddleCenter,
                ForeColor = Theme.Subtle,
                Font = new Font("Segoe UI", 8.5f),
                Text = $"© {AppInfo.Copyright}  ·  {AppInfo.Author}\nLicensed under the Apache License 2.0",
            };

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
            Controls.Add(_appIcon);
            Controls.Add(_title);
            Controls.Add(_version);
            Controls.Add(_introButton);
            Controls.Add(_repoButton);
            Controls.Add(_updateButton);
            Controls.Add(_issueButton);
            Controls.Add(_updateStatus);
            Controls.Add(_legal);
            Controls.Add(_ok);

            LayoutBody();

            Load += AboutForm_Load;
            FormClosed += AboutForm_FormClosed;
        }

        private void AboutForm_Load(object? sender, EventArgs e)
        {
            // Single source of truth, kept in sync with VERSION / csproj / README by set-version.ps1.
            // Install channel appended so screenshots / issue reports show where the copy came from.
            _version.Text = $"Version: {AppInfo.Version}   ({AppInfo.BuildDate})  ·  {InstallSource.Label}";

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

                    // Re-flow the title/version/buttons below the (now sized) image.
                    LayoutBody();

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

        // Positions the title, version, and the four stacked buttons + status line relative to the
        // bottom of the (possibly resized) picture box. Called once from the constructor and again
        // from Load after the brand image is sized. The OK button stays bottom-right anchored.
        private void LayoutBody()
        {
            // Header row: app icon on the left, title + version stacked to its right.
            const int iconSize = 48;
            int headerTop = _picture.Bottom + 10;
            int textLeft = 24 + iconSize + 12;
            int textWidth = ClientSize.Width - textLeft - 12;
            _title.SetBounds(textLeft, headerTop, textWidth, 24);
            _version.SetBounds(textLeft, _title.Bottom + 2, textWidth, 18);
            // Vertically centre the icon against the two-line title/version block.
            int iconTop = headerTop + ((_version.Bottom - headerTop) - iconSize) / 2;
            _appIcon.SetBounds(24, iconTop, iconSize, iconSize);

            int headerBottom = Math.Max(_version.Bottom, _appIcon.Bottom);

            const int bw = 260, bh = 30;
            int bx = (ClientSize.Width - bw) / 2;
            _introButton.SetBounds(bx, headerBottom + 14, bw, bh);
            _repoButton.SetBounds(bx, _introButton.Bottom + 8, bw, bh);
            _updateButton.SetBounds(bx, _repoButton.Bottom + 8, bw, bh);
            _issueButton.SetBounds(bx, _updateButton.Bottom + 8, bw, bh);
            _updateStatus.SetBounds(12, _issueButton.Bottom + 8, ClientSize.Width - 24, 34);
            _legal.SetBounds(12, _updateStatus.Bottom + 6, ClientSize.Width - 24, 34);

            // Grow the dialog to fit the content so the OK button always clears the footer, then
            // pin OK to the bottom-right. The banner image height is dynamic, so the required
            // height can't be a fixed constant.
            int desired = _legal.Bottom + 12 + _ok.Height + 12;
            if (ClientSize.Height != desired)
                ClientSize = new Size(ClientSize.Width, desired);
            _ok.SetBounds(ClientSize.Width - _ok.Width - 12, ClientSize.Height - _ok.Height - 12, _ok.Width, _ok.Height);
        }

        // Sets the status line, optionally making a trailing phrase a clickable link. Links are reset
        // on every call because assigning LinkLabel.Text can otherwise re-link the whole text.
        private void SetStatus(string text, Color color, string? linkText = null, string? linkUrl = null)
        {
            string full = linkText != null && linkUrl != null ? $"{text}  {linkText}" : text;
            _updateStatus.ForeColor = color;
            _updateStatus.Text = full;
            _updateStatus.Links.Clear();
            if (linkText != null && linkUrl != null)
                _updateStatus.Links.Add(full.Length - linkText.Length, linkText.Length, linkUrl);
        }

        // Store install: hand off to the Store's "Downloads and updates" page (no GitHub request).
        // Otherwise: run the GitHub check; once an update is found the button doubles as a "download"
        // action that opens the asset matching this install (the .msi or the portable exe), falling
        // back to the release page.
        private async void UpdateButton_Click(object? sender, EventArgs e)
        {
            if (InstallSource.IsStore)
            {
                OpenUrl(InstallSource.StoreUpdatesUri);
                SetStatus("Opened the Microsoft Store — click “Get updates” there to update now.", Theme.Subtle);
                return;
            }

            if (_pendingDownloadUrl != null)
            {
                OpenUrl(_pendingDownloadUrl);
                return;
            }

            _updateButton.Enabled = false;
            SetStatus("Checking GitHub for a newer release…", Theme.Subtle);

            UpdateInfo info = await UpdateCheck.CheckAsync();

            _updateButton.Enabled = true;
            if (info.Error != null)
            {
                SetStatus("Update check failed: " + info.Error, Color.FromArgb(200, 80, 80));
            }
            else if (info.Available)
            {
                _pendingDownloadUrl = info.DownloadUrl ?? info.ReleaseUrl;
                string what = InstallSource.Kind == InstallKind.Msi && info.DownloadUrl != null ? " installer" : "";
                _updateButton.Text = $"⬇  Download {info.LatestVersion}{what}";
                SetStatus($"New version {info.LatestVersion} available — you have {info.CurrentVersion}.",
                    Theme.Link, "Release notes", info.ReleaseUrl);
            }
            else
            {
                SetStatus($"You're up to date (version {info.CurrentVersion}).", Theme.Subtle);
            }
        }

        private static void OpenUrl(string url)
        {
            try { Process.Start(new ProcessStartInfo(url) { UseShellExecute = true }); } catch { }
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
