// Copyright (c) 2026 LanDen Labs - Dennis Lang

using System;
using System.Drawing;
using System.IO;
using System.Windows.Forms;

namespace BrowseSafe
{
    /// <summary>
    /// App light/dark theme via WinForms <see cref="Application.SetColorMode"/> plus an
    /// explicit colour palette (since the app sets many custom colours that the system
    /// dark mode won't touch). Choice persisted to %LOCALAPPDATA%\BrowseSafe\theme.txt.
    /// </summary>
    public static class Theme
    {
        public enum Mode { Light, Dark }

        public static Mode Current { get; private set; } = Mode.Light;

        /// <summary>Raised after the mode changes so views can re-apply their colours.</summary>
        public static event Action? Changed;

        public static bool IsDark => Current == Mode.Dark;

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

        /// <summary>Neutral (not-yet-run) tab/banner colour.</summary>
        public static Color NeutralTab(bool selected) => IsDark
            ? (selected ? Color.FromArgb(66, 66, 70) : Color.FromArgb(48, 48, 52))
            : (selected ? Color.White : Color.FromArgb(238, 238, 238));

        private static string FilePath => Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "BrowseSafe", "theme.txt");

        public static void Load()
        {
            try
            {
                if (File.Exists(FilePath) &&
                    File.ReadAllText(FilePath).Trim().Equals("Dark", StringComparison.OrdinalIgnoreCase))
                    Current = Mode.Dark;
            }
            catch { /* default light */ }
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
