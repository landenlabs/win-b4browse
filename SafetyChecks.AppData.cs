// Copyright (c) 2026 LanDen Labs - Dennis Lang

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace B4Browse
{
    /// <summary>
    /// AppData folder scan (the AppData tab). Enumerates the immediate sub-folders of the three
    /// AppData roots (Local, Roaming, LocalLow) and cross-references each against the installed-
    /// programs list so that orphaned folders — ones with no matching installer entry — stand out,
    /// especially when they were created recently. This is a lightweight persistence-location audit:
    /// malware, PUPs, and browser hijackers commonly drop a folder here without registering an
    /// installer entry. No administrator rights needed.
    /// </summary>
    public static partial class SafetyChecks
    {
        // Folder names that are part of Windows itself or universal runtimes - not interesting.
        private static readonly HashSet<string> WellKnownFolders = new(StringComparer.OrdinalIgnoreCase)
        {
            "Microsoft", "MicrosoftEdge", "MicrosoftEdgeUpdate",
            "Windows", "WindowsApps", "WindowsPowerShell", "WindowsNT",
            "Packages", "Temp", "Temporary Internet Files", "INetCache", "INetCookies",
            "Local Settings", "Application Data",
            ".NET", ".NETFramework", ".dotnet", "dotnet",
            "NuGet", "npm", "pip", "cargo",
        };

        public static List<AppDataFolder> GetAppDataFolders()
        {
            string local    = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            string roaming  = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
            // LocalLow sits one level up from Local
            string localLow = Path.Combine(Path.GetDirectoryName(local) ?? local, "LocalLow");

            var roots = new[] { ("Local", local), ("Roaming", roaming), ("LocalLow", localLow) };

            // Build a lookup from the installed-programs list for cross-referencing.
            // We index by: program Name (words), InstallLocation last segment, and ExePath directory name.
            List<InstalledProgram> installed;
            try { installed = GetInstalledPrograms(); }
            catch { installed = new List<InstalledProgram>(); }

            var installedNames = BuildInstalledNameIndex(installed);

            var result = new List<AppDataFolder>();
            foreach (var (rootLabel, rootPath) in roots)
            {
                if (!Directory.Exists(rootPath)) continue;
                DirectoryInfo[] dirs;
                try { dirs = new DirectoryInfo(rootPath).GetDirectories(); }
                catch { continue; }

                foreach (var dir in dirs)
                {
                    var row = new AppDataFolder
                    {
                        Root       = rootLabel,
                        FolderName = dir.Name,
                        FolderPath = dir.FullName,
                    };

                    try
                    {
                        DateTime ct = dir.CreationTime;
                        // CreationTime == LastWriteTime on some systems when the folder was never
                        // individually stamped — treat as unknown rather than misleading.
                        if (ct > DateTime.MinValue && ct.Year > 2000)
                        {
                            row.Created     = ct;
                            row.CreatedText = ct.ToString("yyyy-MM-dd");
                            row.DaysOld     = Math.Max(0, (int)(DateTime.Now - ct).TotalDays);
                        }
                    }
                    catch { /* leave Created null */ }

                    // Cross-reference: look for a matching installer name.
                    row.MatchedProgram = FindInstalledMatch(dir.Name, installedNames);
                    row.IsKnown = row.MatchedProgram.Length > 0
                                  || WellKnownFolders.Contains(dir.Name);

                    // Flag as Caution when recent AND unknown — the combination that warrants review.
                    if (!row.IsKnown && row.DaysOld is >= 0 and <= 30)
                        row.Risk = TabSeverity.Caution;

                    result.Add(row);
                }
            }

            return result;
        }

        public static CheckGroup CheckAppData()
        {
            var group = new CheckGroup("AppData folders (recent, unknown)");
            List<AppDataFolder> rows;
            try { rows = GetAppDataFolders(); }
            catch (Exception ex)
            {
                group.Add(CheckStatus.Fail, "AppData scan failed", ex.Message);
                return group;
            }

            var recent  = rows.Where(r => r.DaysOld is >= 0 and <= 30).ToList();
            var unknown = recent.Where(r => !r.IsKnown).ToList();
            var known   = recent.Where(r => r.IsKnown).ToList();

            if (unknown.Count == 0 && known.Count == 0)
            {
                group.Add(CheckStatus.Pass, "AppData folders", "No folders created in the last 30 days.");
                return group;
            }

            foreach (var r in unknown.OrderBy(r => r.DaysOld))
                group.Add(CheckStatus.Warn, r.FolderName,
                    $"{r.Root}  -  created {r.CreatedText}  -  no matching installer entry");

            foreach (var r in known.OrderBy(r => r.DaysOld))
                group.Add(CheckStatus.Info, r.FolderName,
                    $"{r.Root}  -  created {r.CreatedText}  -  matches: {r.MatchedProgram}");

            int total = rows.Count;
            group.Add(CheckStatus.Info, "Total AppData sub-folders",
                $"{total} across Local / Roaming / LocalLow  —  {recent.Count} created in the last 30 days" +
                (unknown.Count > 0 ? $"  ({unknown.Count} with no installer match)" : ""));

            return group;
        }

        // ------------------------------------------------------------------ //
        // Cross-reference helpers
        // ------------------------------------------------------------------ //

        /// <summary>
        /// Normalises a string for fuzzy matching: lowercase, strip every character that is not a
        /// letter or digit. "B4-Browse" → "b4browse", "B4Browse" → "b4browse", "Google Chrome" →
        /// "googlechrome". This makes folder/program comparisons insensitive to hyphens, spaces,
        /// underscores, dots, and mixed casing.
        /// </summary>
        private static string Normalize(string s)
        {
            var sb = new System.Text.StringBuilder(s.Length);
            foreach (char c in s)
                if (char.IsLetterOrDigit(c)) sb.Append(char.ToLowerInvariant(c));
            return sb.ToString();
        }

        /// <summary>
        /// Index keyed by the <see cref="Normalize"/>d form of every token derived from
        /// installed-program names and install locations. Value is the full display name.
        /// </summary>
        private static Dictionary<string, string> BuildInstalledNameIndex(List<InstalledProgram> installed)
        {
            var index = new Dictionary<string, string>(StringComparer.Ordinal);

            foreach (var p in installed)
            {
                // Whole program name (e.g. "B4-Browse" → "b4browse")
                AddToken(index, Normalize(p.Name), p.Name);

                // First whitespace-delimited word (e.g. "Google Chrome" → "google")
                string firstWord = p.Name.Split(' ', 2)[0];
                if (firstWord.Length >= 3)
                    AddToken(index, Normalize(firstWord), p.Name);

                // Last segment of the install location
                if (!string.IsNullOrEmpty(p.InstallLocation))
                {
                    string seg = Path.GetFileName(p.InstallLocation.TrimEnd('\\', '/'));
                    if (seg.Length >= 3)
                        AddToken(index, Normalize(seg), p.Name);
                }

                // Directory name containing the main executable
                if (!string.IsNullOrEmpty(p.ExePath))
                {
                    string? dir = Path.GetDirectoryName(p.ExePath);
                    if (!string.IsNullOrEmpty(dir))
                    {
                        string seg = Path.GetFileName(dir);
                        if (seg.Length >= 3)
                            AddToken(index, Normalize(seg), p.Name);
                    }
                }
            }

            return index;
        }

        private static void AddToken(Dictionary<string, string> index, string normalizedToken, string programName)
        {
            if (normalizedToken.Length < 3) return;
            // Prefer the shorter / more precise display name when a token already exists.
            if (!index.ContainsKey(normalizedToken) || programName.Length < index[normalizedToken].Length)
                index[normalizedToken] = programName;
        }

        /// <summary>
        /// Returns the display name of the best installed-program match for <paramref name="folderName"/>,
        /// or an empty string when nothing matches. Both sides are normalised before comparison so that
        /// "B4Browse" matches "B4-Browse", "GoogleChrome" matches "Google Chrome", etc.
        /// Also tries stripping trailing version/arch suffixes and the first camelCase word as fallbacks.
        /// </summary>
        private static string FindInstalledMatch(string folderName, Dictionary<string, string> index)
        {
            // 1. Full folder name normalised (handles "B4Browse" ↔ "B4-Browse")
            string key = Normalize(folderName);
            if (key.Length >= 3 && index.TryGetValue(key, out var m1)) return m1;

            // 2. Strip trailing version-like suffixes: "AppName_1.2", "AppName (x86)", "App v2", etc.
            string stripped = System.Text.RegularExpressions.Regex
                .Replace(folderName, @"[\s_\.\-]+[vV]?[\d].*$", "").Trim();
            if (stripped.Length >= 3 && stripped != folderName)
            {
                string sk = Normalize(stripped);
                if (sk.Length >= 3 && index.TryGetValue(sk, out var m2)) return m2;
            }

            // 3. First camelCase/PascalCase word (e.g. "GoogleChrome" → "google")
            var camel = System.Text.RegularExpressions.Regex.Match(folderName, @"^[A-Z][a-z]+");
            if (camel.Success)
            {
                string ck = Normalize(camel.Value);
                if (ck.Length >= 3 && index.TryGetValue(ck, out var m3)) return m3;
            }

            return "";
        }
    }
}
