// Copyright (c) 2026 LanDen Labs - Dennis Lang

using System;
using System.Drawing;
using System.Globalization;
using System.IO;
using System.Runtime.InteropServices;
using System.Windows.Forms;

namespace B4Browse
{
    /// <summary>
    /// App light/dark theme via WinForms <see cref="Application.SetColorMode"/> plus an
    /// explicit colour palette (since the app sets many custom colours that the system
    /// dark mode won't touch). Choice persisted to %LOCALAPPDATA%\B4Browse\theme.txt.
    /// </summary>
    public static class Theme
    {
        public enum Mode { Light, Dark }

        public static Mode Current { get; private set; } = Mode.Light;

        /// <summary>Raised after the mode changes so views can re-apply their colours.</summary>
        public static event Action? Changed;

        public static bool IsDark => Current == Mode.Dark;

        // Content font scaling ---------------------------------------------- //
        // Driven by the status-bar [ - 100% + ] control; views multiply their base
        // point sizes by FontScale and re-render when ScaleChanged fires.
        public const float MinScale = 0.7f;     // 70%
        public const float MaxScale = 2.0f;     // 200%
        public const float ScaleStep = 0.1f;    // 10% per nudge

        /// <summary>Current content font scale (1.0 = 100%).</summary>
        public static float FontScale { get; private set; } = 1.0f;

        /// <summary>Raised after the content font scale changes so views can re-apply fonts.</summary>
        public static event Action? ScaleChanged;

        /// <summary>A font in <paramref name="family"/> sized by <paramref name="size"/> times the current scale.</summary>
        public static Font Scaled(string family, float size, FontStyle style = FontStyle.Regular)
            => new Font(family, size * FontScale, style);

        /// <summary>Sets the content font scale (clamped), notifies views, and persists the choice.</summary>
        public static void SetScale(float scale)
        {
            scale = Math.Clamp(scale, MinScale, MaxScale);
            if (Math.Abs(scale - FontScale) < 0.001f) return;
            FontScale = scale;
            ScaleChanged?.Invoke();
            SaveScale();
        }

        /// <summary>Nudges the scale by one step (direction +1 = larger, -1 = smaller).</summary>
        public static void StepScale(int direction)
            => SetScale((float)Math.Round(FontScale + direction * ScaleStep, 2));

        // Palette ---------------------------------------------------------- //
        public static Color Window  => IsDark ? Color.FromArgb(32, 32, 34)   : Color.White;
        public static Color Surface => IsDark ? Color.FromArgb(43, 43, 46)   : Color.White;            // grids / text panes
        public static Color Panel   => IsDark ? Color.FromArgb(50, 50, 54)   : Color.FromArgb(238, 240, 243);
        public static Color Toolbar => IsDark ? Color.FromArgb(50, 50, 54)   : Color.FromArgb(245, 245, 245);
        public static Color Text    => IsDark ? Color.FromArgb(232, 232, 232) : Color.Black;
        public static Color Subtle  => IsDark ? Color.FromArgb(165, 165, 165) : Color.FromArgb(70, 70, 70);
        public static Color GridLine => IsDark ? Color.FromArgb(64, 64, 68)  : Color.FromArgb(230, 230, 230);
        public static Color Card    => IsDark ? Color.FromArgb(52, 52, 56)   : Color.FromArgb(248, 248, 250);
        public static Color Link    => IsDark ? Color.FromArgb(96, 162, 250) : Color.FromArgb(0, 102, 204);
        public static Color ButtonBack   => IsDark ? Color.FromArgb(62, 62, 66)   : Color.FromArgb(240, 240, 240);
        public static Color ButtonBorder => IsDark ? Color.FromArgb(92, 92, 98)   : Color.FromArgb(176, 176, 180);

        /// <summary>Paints a button explicitly (FlatStyle.System buttons don't revert from dark to light).</summary>
        public static void StyleButton(Button b)
        {
            b.FlatStyle = FlatStyle.Flat;
            b.UseVisualStyleBackColor = false;
            b.BackColor = ButtonBack;
            b.ForeColor = Text;
            b.FlatAppearance.BorderColor = ButtonBorder;
            b.FlatAppearance.BorderSize = 1;
        }

        /// <summary>Recursively applies <see cref="StyleButton"/> to every Button under a control.</summary>
        public static void StyleButtons(Control root)
        {
            foreach (Control c in root.Controls)
            {
                if (c is Button b) StyleButton(b);
                if (c.HasChildren) StyleButtons(c);
            }
        }

        [DllImport("uxtheme.dll", CharSet = CharSet.Unicode)]
        private static extern int SetWindowTheme(IntPtr hWnd, string? pszSubAppName, string? pszSubIdList);

        /// <summary>True for controls with native, OS-drawn scrollbars that ignore managed
        /// BackColor/ForeColor and instead follow the window theme.</summary>
        private static bool WantsScrollbarTheme(Control c) =>
            c is DataGridView or RichTextBox or TreeView or ListView or ScrollBar
            || (c is ScrollableControl sc && sc.AutoScroll);

        /// <summary>
        /// Applies the matching dark/light <em>window</em> theme to every scrollable control under
        /// <paramref name="root"/> so their native scrollbars follow the theme (grids and rich-text
        /// panes otherwise keep light scrollbars in dark mode). Managed colours can't reach these
        /// non-client scrollbars; <c>SetWindowTheme</c> can. Idempotent; skips not-yet-created handles
        /// and leaves non-scrolling controls (buttons, labels) untouched.
        /// </summary>
        public static void ApplyScrollbarTheme(Control? root)
        {
            if (root == null) return;
            string sub = IsDark ? "DarkMode_Explorer" : "Explorer";
            void Walk(Control c)
            {
                if (c.IsHandleCreated && WantsScrollbarTheme(c))
                    try { SetWindowTheme(c.Handle, sub, null); } catch { /* best-effort */ }
                foreach (Control child in c.Controls) Walk(child);
            }
            Walk(root);
        }

        /// <summary>Neutral (not-yet-run) tab/banner colour.</summary>
        public static Color NeutralTab(bool selected) => IsDark
            ? (selected ? Color.FromArgb(66, 66, 70) : Color.FromArgb(48, 48, 52))
            : (selected ? Color.White : Color.FromArgb(238, 238, 238));

        private static string FilePath => Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "B4Browse", "theme.txt");

        private static string ScaleFilePath => Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "B4Browse", "scale.txt");

        public static void Load()
        {
            try
            {
                if (File.Exists(FilePath) &&
                    File.ReadAllText(FilePath).Trim().Equals("Dark", StringComparison.OrdinalIgnoreCase))
                    Current = Mode.Dark;
            }
            catch { /* default light */ }

            try
            {
                if (File.Exists(ScaleFilePath) &&
                    float.TryParse(File.ReadAllText(ScaleFilePath).Trim(),
                        NumberStyles.Float, CultureInfo.InvariantCulture, out var s))
                    FontScale = Math.Clamp(s, MinScale, MaxScale);
            }
            catch { /* default 100% */ }
        }

        private static void SaveScale()
        {
            try
            {
                Directory.CreateDirectory(Path.GetDirectoryName(ScaleFilePath)!);
                File.WriteAllText(ScaleFilePath, FontScale.ToString(CultureInfo.InvariantCulture));
            }
            catch { /* non-fatal */ }
        }

        private static void Save()
        {
            try
            {
                Directory.CreateDirectory(Path.GetDirectoryName(FilePath)!);
                File.WriteAllText(FilePath, Current.ToString());
            }
            catch { /* non-fatal */ }
        }

        /// <summary>Applies a mode to the running app (best-effort live) without persisting.</summary>
        public static void Apply(Mode mode)
        {
            Current = mode;
            Application.SetColorMode(mode == Mode.Dark ? SystemColorMode.Dark : SystemColorMode.Classic);
            Changed?.Invoke();
        }

        /// <summary>Toggles light/dark, applies it, and persists the choice.</summary>
        public static Mode Toggle()
        {
            Apply(Current == Mode.Dark ? Mode.Light : Mode.Dark);
            Save();
            return Current;
        }
    }
}
