// Copyright (c) 2026 LanDen Labs - Dennis Lang

using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace B4Browse
{
    /// <summary>How this copy of B4-Browse was installed - decides who delivers updates.</summary>
    public enum InstallKind
    {
        /// <summary>MSIX package (the Microsoft Store). The Store updates it; never point at GitHub.</summary>
        Store,
        /// <summary>MSI installer (GitHub release) - installed under Program Files.</summary>
        Msi,
        /// <summary>Loose / portable exe (GitHub release exe or zip, or install.bat's copy).</summary>
        Portable,
    }

    /// <summary>
    /// Detects the install channel once per process. A packaged (MSIX) process has a package
    /// identity, read via <c>GetCurrentPackageFamilyName</c> (kernel32, Windows 8+) - no WinRT
    /// projection or Windows-SDK target framework needed. The only MSIX we ship is the Store
    /// upload, so "packaged" is treated as "from the Store". Otherwise an exe living in the MSI's
    /// Program Files\B4Browse folder is an MSI install, and anything else is portable.
    /// </summary>
    public static class InstallSource
    {
        private const int APPMODEL_ERROR_NO_PACKAGE = 15700;
        private const int ERROR_INSUFFICIENT_BUFFER = 122;

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
        private static extern int GetCurrentPackageFamilyName(ref int packageFamilyNameLength, StringBuilder? packageFamilyName);

        private static readonly Lazy<(InstallKind Kind, string? Pfn)> Detected = new(Detect);

        public static InstallKind Kind => Detected.Value.Kind;

        /// <summary>MSIX package family name (e.g. "LanDenLabs.B4Browse_abc123xyz"), or null when unpackaged.</summary>
        public static string? PackageFamilyName => Detected.Value.Pfn;

        public static bool IsStore => Kind == InstallKind.Store;

        /// <summary>Short label for the About version line and issue reports.</summary>
        public static string Label => Kind switch
        {
            InstallKind.Store => "Microsoft Store",
            InstallKind.Msi => "MSI installer",
            _ => "portable",
        };

        /// <summary>Store "Downloads and updates" (library) page - where the user can force a Store update check.</summary>
        public const string StoreUpdatesUri = "ms-windows-store://downloadsandupdates";

        /// <summary>This app's Store listing, addressed by package family name (no product ID needed).
        /// Falls back to the updates page when unpackaged.</summary>
        public static string StoreListingUri =>
            PackageFamilyName is { } pfn ? $"ms-windows-store://pdp/?PFN={Uri.EscapeDataString(pfn)}" : StoreUpdatesUri;

        private static (InstallKind, string?) Detect()
        {
            string? pfn = TryGetPackageFamilyName();
            if (pfn != null) return (InstallKind.Store, pfn);

            try
            {
                string? exe = Environment.ProcessPath;
                string? dir = exe != null ? Path.GetDirectoryName(Path.GetFullPath(exe)) : null;
                if (dir != null)
                {
                    foreach (var pf in new[]
                             {
                                 Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                                 Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
                             })
                    {
                        if (string.IsNullOrEmpty(pf)) continue;
                        // b4browse.wxs installs to <ProgramFiles>\B4Browse.
                        string msiDir = Path.Combine(pf, "B4Browse");
                        if (string.Equals(dir.TrimEnd('\\'), msiDir.TrimEnd('\\'), StringComparison.OrdinalIgnoreCase))
                            return (InstallKind.Msi, null);
                    }
                }
            }
            catch { /* fall through to portable */ }

            return (InstallKind.Portable, null);
        }

        private static string? TryGetPackageFamilyName()
        {
            try
            {
                int len = 0;
                int rc = GetCurrentPackageFamilyName(ref len, null);
                if (rc == APPMODEL_ERROR_NO_PACKAGE || rc != ERROR_INSUFFICIENT_BUFFER || len <= 0) return null;
                var sb = new StringBuilder(len);
                rc = GetCurrentPackageFamilyName(ref len, sb);
                return rc == 0 && sb.Length > 0 ? sb.ToString() : null;
            }
            catch
            {
                return null;   // API missing / P/Invoke failure: treat as unpackaged
            }
        }
    }
}
