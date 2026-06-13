// Copyright (c) 2026 LanDen Labs - Dennis Lang

using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Runtime.InteropServices;

namespace B4Browse
{
    /// <summary>
    /// Back up and remove Chrome extension folders (used by the Chrome tab's
    /// "Remove unsupported" action). Operates purely on the on-disk extension
    /// directories; the caller handles all confirmation.
    /// </summary>
    public static partial class SafetyChecks
    {
        /// <summary>Result of a backup + removal run.</summary>
        public sealed class ExtCleanupResult
        {
            public string ZipPath = "";
            public int BackedUp;
            public string? BackupError;     // null on success
            public int Deleted;
            public int Failed;
            public List<string> Errors = new();
        }

        /// <summary>
        /// Zips every extension folder (supported and unsupported, all profiles) into
        /// <c>b4browse-extension-backup.zip</c> in the Downloads folder. Best-effort: a locked or
        /// unreadable file is skipped; a fatal error is returned in <c>Error</c>.
        /// </summary>
        public static (string ZipPath, int Count, string? Error) BackupExtensions(List<ChromeExtension> all)
        {
            string zipPath = Path.Combine(GetDownloadsFolder(), "b4browse-extension-backup.zip");
            int count = 0;
            try
            {
                Directory.CreateDirectory(Path.GetDirectoryName(zipPath)!);
                if (File.Exists(zipPath)) File.Delete(zipPath);

                using var zip = ZipFile.Open(zipPath, ZipArchiveMode.Create);
                var used = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                foreach (var e in all)
                {
                    if (!Directory.Exists(e.ProfileDir)) continue;

                    // One top-level folder per extension; keep it unique and human-readable.
                    string baseName = Sanitize($"{e.ProfileName}_{e.Name}_{e.Id}");
                    string folder = baseName;
                    for (int n = 2; !used.Add(folder); n++) folder = $"{baseName}_{n}";

                    AddDirectoryToZip(zip, e.ProfileDir, folder);
                    count++;
                }
            }
            catch (Exception ex)
            {
                return (zipPath, count, ex.Message);
            }
            return (zipPath, count, null);
        }

        /// <summary>Deletes each extension's folder. Each delete is guarded so only a genuine
        /// <c>...\Extensions\&lt;id&gt;</c> path can be removed, and isolated so one failure
        /// (e.g. a file locked by a running Chrome) doesn't stop the rest.</summary>
        public static (int Deleted, int Failed, List<string> Errors) DeleteExtensionDirs(List<ChromeExtension> items)
        {
            int deleted = 0, failed = 0;
            var errors = new List<string>();
            foreach (var e in items)
            {
                if (!IsSafeExtensionDir(e.ProfileDir))
                {
                    failed++;
                    errors.Add($"{e.Name}: refused (path doesn't look like an extension folder).");
                    continue;
                }
                try
                {
                    if (Directory.Exists(e.ProfileDir))
                    {
                        Directory.Delete(e.ProfileDir, recursive: true);
                        deleted++;
                    }
                }
                catch (Exception ex)
                {
                    failed++;
                    errors.Add($"{e.Name}: {ex.Message}");
                }
            }
            return (deleted, failed, errors);
        }

        /// <summary>Guard for the destructive delete: the path must be a rooted
        /// <c>...\Extensions\&lt;something&gt;</c> directory several levels deep.</summary>
        private static bool IsSafeExtensionDir(string dir)
        {
            if (string.IsNullOrWhiteSpace(dir)) return false;
            string norm = dir.Replace('/', '\\').TrimEnd('\\');
            return Path.IsPathRooted(norm)
                && norm.IndexOf(@"\Extensions\", StringComparison.OrdinalIgnoreCase) >= 0
                && norm.Count(c => c == '\\') >= 4;   // never a drive root or shallow path
        }

        private static void AddDirectoryToZip(ZipArchive zip, string dir, string entryPrefix)
        {
            IEnumerable<string> files;
            try { files = Directory.EnumerateFiles(dir, "*", SearchOption.AllDirectories); }
            catch { return; }

            foreach (var file in files)
            {
                string rel = Path.GetRelativePath(dir, file).Replace('\\', '/');
                try { zip.CreateEntryFromFile(file, entryPrefix + "/" + rel, CompressionLevel.Optimal); }
                catch { /* skip a locked / unreadable file, keep going */ }
            }
        }

        private static string Sanitize(string name)
        {
            foreach (char c in Path.GetInvalidFileNameChars()) name = name.Replace(c, '_');
            return name.Length > 80 ? name.Substring(0, 80) : name;
        }

        [DllImport("shell32.dll")]
        private static extern int SHGetKnownFolderPath(
            [MarshalAs(UnmanagedType.LPStruct)] Guid rfid, uint dwFlags, IntPtr hToken, out IntPtr ppszPath);

        /// <summary>The user's Downloads folder (handles OneDrive/redirected Downloads),
        /// falling back to %USERPROFILE%\Downloads.</summary>
        private static string GetDownloadsFolder()
        {
            try
            {
                var downloads = new Guid("374DE290-123F-4565-9164-39C4925E467B");
                if (SHGetKnownFolderPath(downloads, 0, IntPtr.Zero, out IntPtr p) == 0)
                {
                    string s = Marshal.PtrToStringUni(p) ?? "";
                    Marshal.FreeCoTaskMem(p);
                    if (s.Length > 0) return s;
                }
            }
            catch { /* fall through */ }
            return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads");
        }
    }
}
