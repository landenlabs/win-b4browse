// Copyright (c) 2026 LanDen Labs - Dennis Lang

using System;
using System.ComponentModel;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Windows.Forms;

namespace B4Browse
{
    /// <summary>
    /// A small floating "busy" indicator: an animated rotating spinner with a
    /// "Loading …" caption. Add it to a view, then Start()/Stop() around work.
    /// </summary>
    public sealed class BusyOverlay : Control
    {
        private const int BaseHeight = 104;
        private const int CancelHeight = 140;

        private readonly System.Windows.Forms.Timer _timer;
        private readonly Button _cancel;
        private float _angle;
        private const int Ticks = 12;

        /// <summary>Raised when the (optional) Cancel button is clicked.</summary>
        public event Action? Cancelled;

        public BusyOverlay()
        {
            DoubleBuffered = true;
            BackColor = Color.White;
            Visible = false;
            TabStop = false;

            // Create the Cancel button before sizing: setting Size raises OnResize, which
            // lays the button out - so the field must already be assigned.
            _cancel = new Button
            {
                Text = "Cancel",
                Width = 90,
                Height = 26,
                FlatStyle = FlatStyle.System,
                Visible = false,
            };
            _cancel.Click += (_, _) => Cancelled?.Invoke();
            Controls.Add(_cancel);

            Size = new Size(150, BaseHeight);

            _timer = new System.Windows.Forms.Timer { Interval = 66 }; // ~15 fps
            _timer.Tick += (_, _) => { _angle = (_angle + 360f / Ticks) % 360f; Invalidate(); };
        }

        /// <summary>When true, shows a Cancel button below the caption (raises <see cref="Cancelled"/>).
        /// Left false for indicators that drive non-cancellable work.</summary>
        [DesignerSerializationVisibility(DesignerSerializationVisibility.Hidden)]
        public bool ShowCancel
        {
            get => _cancel.Visible;
            set
            {
                _cancel.Visible = value;
                Height = value ? CancelHeight : BaseHeight;
                LayoutCancel();
            }
        }

        private void LayoutCancel()
        {
            _cancel.Left = Math.Max(0, (Width - _cancel.Width) / 2);
            _cancel.Top = Height - _cancel.Height - 8;
        }

        protected override void OnResize(EventArgs e)
        {
            base.OnResize(e);
            LayoutCancel();
        }

        public void Start()
        {
            Visible = true;
            BringToFront();
            _timer.Start();
        }

        public void Stop()
        {
            _timer.Stop();
            Visible = false;
        }

        protected override void OnPaint(PaintEventArgs e)
        {
            var g = e.Graphics;
            g.SmoothingMode = SmoothingMode.AntiAlias;

            // Subtle card background + border.
            var rect = new Rectangle(0, 0, Width - 1, Height - 1);
            using (var bg = new SolidBrush(Color.FromArgb(250, 250, 250))) g.FillRectangle(bg, rect);
            using (var border = new Pen(Color.FromArgb(220, 220, 220))) g.DrawRectangle(border, rect);

            // Rotating ticks - the brightest tick sweeps around.
            var center = new PointF(Width / 2f, 40f);
            const float inner = 9f, outer = 18f;
            for (int i = 0; i < Ticks; i++)
            {
                double a = (_angle * Math.PI / 180.0) + i * (2 * Math.PI / Ticks);
                float cos = (float)Math.Cos(a), sin = (float)Math.Sin(a);
                int alpha = 30 + 225 * i / (Ticks - 1);
                using var pen = new Pen(Color.FromArgb(alpha, 70, 70, 70), 3f)
                { StartCap = LineCap.Round, EndCap = LineCap.Round };
                g.DrawLine(pen,
                    center.X + cos * inner, center.Y + sin * inner,
                    center.X + cos * outer, center.Y + sin * outer);
            }

            TextRenderer.DrawText(g, "Loading …", Font,
                new Rectangle(0, 66, Width, 28), Color.DimGray,
                TextFormatFlags.HorizontalCenter | TextFormatFlags.Top);
        }
    }
}
