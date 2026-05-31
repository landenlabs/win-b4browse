// Copyright (c) 2026 LanDen Labs - Dennis Lang

using System;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Windows.Forms;

namespace BrowseSafe
{
    /// <summary>
    /// A small floating "busy" indicator: an animated rotating spinner with a
    /// "Loading …" caption. Add it to a view, then Start()/Stop() around work.
    /// </summary>
    public sealed class BusyOverlay : Control
    {
        private readonly System.Windows.Forms.Timer _timer;
        private float _angle;
        private const int Ticks = 12;

        public BusyOverlay()
        {
            Size = new Size(150, 104);
            DoubleBuffered = true;
            BackColor = Color.White;
            Visible = false;
            TabStop = false;
            _timer = new System.Windows.Forms.Timer { Interval = 66 }; // ~15 fps
            _timer.Tick += (_, _) => { _angle = (_angle + 360f / Ticks) % 360f; Invalidate(); };
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
