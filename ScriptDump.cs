// Copyright (c) 2026 LanDen Labs - Dennis Lang

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace B4Browse
{
    /// <summary>
    /// Opt-in sink that records every PowerShell script and external command the diagnostic
    /// runners execute, one file per originating check, into a directory - so the committed
    /// <c>scripts/</c> reference (a plain-language "how the data is collected" view) can be
    /// regenerated from the real execution path rather than hand-copied.
    ///
    /// Off by default: <see cref="Enabled"/> is false and <see cref="Record"/> is a cheap no-op,
    /// so normal GUI/headless runs pay nothing. The headless <c>--dump-scripts &lt;dir&gt;</c> mode
    /// (see <c>Program</c>) calls <see cref="Enable"/>, exercises every check, then
    /// <see cref="WriteIndex"/>. The two PowerShell runners both flow through
    /// <c>RunPowerShellJson</c>, and external commands through <c>RunCapture</c>, so those two
    /// hooks capture everything.
    /// </summary>
    internal static class ScriptDump
    {
        private static string? _dir;
        private static readonly object _lock = new();
        // Output filename -> how many invocations we've already appended (for checks that run
        // more than one script/command). Also doubles as the set of files written this session.
        private static readonly Dictionary<string, int> _seen = new(StringComparer.OrdinalIgnoreCase);

        /// <summary>True once <see cref="Enable"/> has been called; gates the runner hooks.</summary>
        public static bool Enabled => _dir != null;

        /// <summary>Number of distinct files written this session.</summary>
        public static int FileCount { get { lock (_lock) return _seen.Count; } }

        /// <summary>Turns dumping on, writing into <paramref name="dir"/> (created if absent).
        /// Pre-existing generated files in the directory are removed so a regenerate is a clean
        /// snapshot rather than an append onto stale content.</summary>
        public static void Enable(string dir)
        {
            Directory.CreateDirectory(dir);
            // Clear our own prior output only (*.ps1 / *.txt / README.md); leave anything else alone.
            foreach (var f in Directory.EnumerateFiles(dir)
                         .Where(f => f.EndsWith(".ps1", StringComparison.OrdinalIgnoreCase)
                                  || f.EndsWith(".txt", StringComparison.OrdinalIgnoreCase)
                                  || Path.GetFileName(f).Equals("README.md", StringComparison.OrdinalIgnoreCase)))
            {
                try { File.Delete(f); } catch { /* best effort */ }
            }
            lock (_lock) { _dir = dir; _seen.Clear(); }
        }

        /// <summary>Records one executed script/command under its originating check.
        /// <paramref name="kind"/> is <c>"ps"</c> (PowerShell) or <c>"cmd"</c> (external exe).
        /// Never throws - dumping must not perturb the run it observes.</summary>
        public static void Record(string kind, string source, string content)
        {
            var dir = _dir;
            if (dir == null) return;
            try
            {
                bool isCmd = kind == "cmd";
                string ext = isCmd ? "txt" : "ps1";
                string name = Sanitize(string.IsNullOrEmpty(source) ? "unknown" : source) + "." + ext;
                string path = Path.Combine(dir, name);
                string body = content.Replace("\r\n", "\n").Replace("\r", "\n").TrimEnd();

                lock (_lock)
                {
                    _seen.TryGetValue(name, out int n);
                    _seen[name] = n + 1;

                    if (n == 0)
                    {
                        var head = new StringBuilder();
                        head.Append("# B4-Browse - data-collection ").Append(isCmd ? "command" : "script").Append('\n');
                        head.Append("# Check:  ").Append(source).Append('\n');
                        head.Append("# Runner: ").Append(isCmd
                            ? "RunCapture - launched as an external process (no window; stdout captured)."
                            : "RunPowerShellJson/Array - run as: powershell.exe -NoProfile -NonInteractive\n"
                              + "#         -ExecutionPolicy Bypass -EncodedCommand <base64-utf16(script)>,\n"
                              + "#         with $ProgressPreference='SilentlyContinue' prepended.").Append('\n');
                        head.Append("# Note:   Generated snapshot of what the app runs; interpolated values reflect\n");
                        head.Append("#         the machine it was generated on. Regenerate: B4Browse.exe --dump-scripts <dir>\n");
                        head.Append("# ").Append(new string('=', 72)).Append("\n\n");
                        File.WriteAllText(path, head + body + "\n");
                    }
                    else
                    {
                        var sep = new StringBuilder();
                        sep.Append("\n\n# ").Append(new string('-', 60)).Append('\n');
                        sep.Append("# additional invocation #").Append(n + 1).Append(" from ").Append(source).Append('\n');
                        sep.Append("# ").Append(new string('-', 60)).Append("\n\n");
                        File.AppendAllText(path, sep + body + "\n");
                    }
                }
            }
            catch { /* dumping must never perturb a run */ }
        }

        /// <summary>Writes a README.md index of every file written this session.</summary>
        public static void WriteIndex()
        {
            var dir = _dir;
            if (dir == null) return;
            try
            {
                List<string> names;
                lock (_lock) names = _seen.Keys.OrderBy(s => s, StringComparer.OrdinalIgnoreCase).ToList();

                var sb = new StringBuilder();
                sb.Append("# B4-Browse - data-collection scripts\n\n");
                sb.Append("A generated snapshot of every PowerShell script and external command B4-Browse\n");
                sb.Append("runs to gather the information shown in each tab - one file per originating check,\n");
                sb.Append("so you can see exactly *how* each piece of information is collected.\n\n");
                sb.Append("- `*.ps1` - PowerShell, run through `powershell.exe` (`-NoProfile -NonInteractive`,\n");
                sb.Append("  encoded). The file shows the readable script, not the base64 form.\n");
                sb.Append("- `*.txt` - external commands (e.g. `winget`).\n\n");
                sb.Append("Not every tab is script-driven: a few collect data through native .NET APIs and so\n");
                sb.Append("have nothing to dump here - the **Downloads** tab reads the SRUM ESE database\n");
                sb.Append("(`SRUDB.dat`) directly, **Virus** queries Defender over WMI (`MSFT_MpComputerStatus`),\n");
                sb.Append("and **Activity** reads the Windows Search SQLite database. See the source\n");
                sb.Append("(`SafetyChecks.*.cs`) for those.\n\n");
                sb.Append("## Regenerate\n\n");
                sb.Append("```\nB4Browse.exe --dump-scripts scripts\n```\n\n");
                sb.Append("Run from an elevated prompt to also capture the Administrator-only checks\n");
                sb.Append("(Security event log, SRUM downloads, Defender history, true user creation dates);\n");
                sb.Append("otherwise those checks return early and emit no script.\n\n");
                sb.Append("## Files\n\n");
                sb.Append("| File | Originating check | Type |\n");
                sb.Append("| --- | --- | --- |\n");
                foreach (var name in names)
                {
                    string check = Path.GetFileNameWithoutExtension(name);
                    string type = name.EndsWith(".txt", StringComparison.OrdinalIgnoreCase) ? "command" : "PowerShell";
                    sb.Append("| `").Append(name).Append("` | `").Append(check).Append("` | ").Append(type).Append(" |\n");
                }
                File.WriteAllText(Path.Combine(dir, "README.md"), sb.ToString());
            }
            catch { /* best effort */ }
        }

        private static string Sanitize(string s)
        {
            var invalid = Path.GetInvalidFileNameChars();
            var chars = s.ToCharArray();
            for (int i = 0; i < chars.Length; i++)
                if (Array.IndexOf(invalid, chars[i]) >= 0) chars[i] = '_';
            return new string(chars);
        }
    }
}
