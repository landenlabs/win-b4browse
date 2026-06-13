// Copyright (c) 2026 LanDen Labs - Dennis Lang

using System;
using System.IO;
using System.Linq;
using System.Reflection;

namespace B4Browse
{
    // Loads assets that are baked into the (single-file) exe as manifest resources,
    // falling back to a loose file next to the exe for debug runs from the build folder.
    // install.bat publishes a single-file exe and copies only that exe, so loose
    // Content files are not present at runtime — embedded resources always are.
    internal static class EmbeddedAssets
    {
        // Resolves a manifest resource by file name (e.g. "links.html"). The default
        // MSBuild resource name is "<RootNamespace>.<fileName>", so match by suffix.
        private static Stream? OpenResource(string fileName)
        {
            var asm = Assembly.GetExecutingAssembly();
            var name = asm.GetManifestResourceNames()
                .FirstOrDefault(n => n.EndsWith("." + fileName, StringComparison.OrdinalIgnoreCase)
                                  || n.Equals(fileName, StringComparison.OrdinalIgnoreCase));
            return name != null ? asm.GetManifestResourceStream(name) : null;
        }

        // Returns the text content of an embedded asset, or null if it can't be found.
        public static string? ReadText(string fileName)
        {
            try
            {
                using var rs = OpenResource(fileName);
                if (rs != null)
                {
                    using var reader = new StreamReader(rs);
                    return reader.ReadToEnd();
                }
            }
            catch { }

            try
            {
                var path = Path.Combine(AppContext.BaseDirectory, fileName);
                if (File.Exists(path)) return File.ReadAllText(path);
            }
            catch { }

            return null;
        }

        // Returns an Icon loaded from an embedded .ico (all frames), or null. new Icon(stream)
        // copies the data, so the stream can close immediately. This is reliable inside a
        // single-file exe, where Icon.ExtractAssociatedIcon on the apphost is not.
        public static System.Drawing.Icon? LoadIcon(string fileName)
        {
            try
            {
                using var rs = OpenResource(fileName);
                if (rs != null) return new System.Drawing.Icon(rs);
            }
            catch { }

            try
            {
                var path = Path.Combine(AppContext.BaseDirectory, fileName);
                if (File.Exists(path)) return new System.Drawing.Icon(path);
            }
            catch { }

            return null;
        }

        // Returns an independent Bitmap copy of an embedded image, or null. The copy lets
        // the backing stream close immediately. NOTE: this flattens animated GIFs to a
        // single frame — AboutForm has its own stream-retaining loader for animation.
        public static System.Drawing.Image? LoadImage(string fileName)
        {
            try
            {
                using var rs = OpenResource(fileName);
                if (rs != null)
                {
                    using var tmp = System.Drawing.Image.FromStream(rs);
                    return new System.Drawing.Bitmap(tmp);
                }
            }
            catch { }

            try
            {
                var path = Path.Combine(AppContext.BaseDirectory, fileName);
                if (File.Exists(path))
                {
                    using var tmp = System.Drawing.Image.FromFile(path);
                    return new System.Drawing.Bitmap(tmp);
                }
            }
            catch { }

            return null;
        }
    }
}
