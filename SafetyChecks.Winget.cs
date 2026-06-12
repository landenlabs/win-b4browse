// Copyright (c) 2026 LanDen Labs - Dennis Lang

using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading.Tasks;

namespace BrowseSafe
{
    /// <summary>
    /// winget (App Installer) integration for the Installed tab. `winget list` is a
    /// superset of the registry uninstall list (it also sees Store/MSIX packages) and
    /// adds a pending-update ("Available") column and a package "Source". It has no JSON
    /// output, so its fixed-width text table is parsed here. Absent winget -> empty list
    /// and the tab falls back to the registry inventory.
    /// </summary>
    public static partial class SafetyChecks
    {
        public sealed class WingetRow
        {
            public string Name = "";
            public string Id = "";
            public string Version = "";
            public string Available = "";   // pending update version ("" when none)
            public string Source = "";      // winget / msstore / "" (ARP-only)
        }

        /// <summary>Runs `winget list` and parses its table. Empty when winget is unavailable.</summary>
        public static List<WingetRow> RunWingetList()
        {
            string? output = RunCapture("winget.exe", "list --accept-source-agreements --disable-interactivity");
            return string.IsNullOrEmpty(output) ? new List<WingetRow>() : ParseWingetList(output);
        }

        /// <summary>
        /// Runs `winget show` and returns the package's detail text (publisher, version, available
        /// update, homepage, description, license, ...). Prefers the package Id; falls back to a
        /// name query for registry-only programs. The output is winget's own (localized) text -
        /// shown verbatim. Returns a short explanation when winget is absent or nothing matched.
        /// </summary>
        public static string WingetShow(string? id, string name, string source)
        {
            // --id does a substring match (works for a full or truncated-then-stripped Id); a
            // registry-only program with no Id is looked up by name in the winget repo instead.
            string target = !string.IsNullOrWhiteSpace(id)
                ? $"--id \"{id!.Trim()}\""
                : $"--query \"{(name ?? "").Trim()}\"";
            string src = source is "winget" or "msstore" ? $" --source {source}" : "";

            string? output = RunCapture("winget.exe",
                $"show {target}{src} --accept-source-agreements --disable-interactivity");

            if (output == null)
                return "winget is not available, or the query timed out.\n\n" +
                       "Install \"App Installer\" from the Microsoft Store to enable winget.";

            output = output.Trim();
            return output.Length == 0
                ? $"winget returned no details for \"{name}\"."
                : output;
        }

        /// <summary>
        /// Runs `winget upgrade --id ...` to install the available update for a package, silently and
        /// non-interactively, and returns winget's combined output (success line, "no applicable
        /// upgrade", or the error). Requires a package Id. A longer timeout allows for the download
        /// and install; a machine-scope package may still need administrator rights (winget reports that).
        /// </summary>
        public static string WingetUpgrade(string? id, string name, string source)
        {
            if (string.IsNullOrWhiteSpace(id))
                return $"winget can't update \"{name}\": no winget package Id is associated with it.";

            string src = source is "winget" or "msstore" ? $" --source {source}" : "";
            string? output = RunCapture("winget.exe",
                $"upgrade --id \"{id.Trim()}\"{src} --accept-package-agreements --accept-source-agreements " +
                "--silent --disable-interactivity",
                timeoutMs: 300_000, includeStdErr: true);

            if (output == null)
                return "winget is not available, or the update timed out (it may still be running).\n\n" +
                       $"You can run it yourself in a terminal:\n   winget upgrade --id {id}";

            output = output.Trim();
            return output.Length == 0
                ? $"winget produced no output for \"{name}\"; it may already be up to date."
                : output;
        }

        /// <summary>Runs a console tool and returns its stdout, or null on failure / timeout / absence.
        /// Drains stdout and stderr concurrently to avoid the pipe-buffer deadlock (see RunPowerShellJson).
        /// <paramref name="timeoutMs"/> bounds the wait (longer for installs); when
        /// <paramref name="includeStdErr"/> is set, any stderr text is appended (so a failed command
        /// still reports its error rather than looking like empty success).</summary>
        private static string? RunCapture(string fileName, string args, int timeoutMs = 30000,
            bool includeStdErr = false, [CallerMemberName] string source = "")
        {
            var psi = new ProcessStartInfo
            {
                FileName = fileName,
                Arguments = args,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
                StandardOutputEncoding = Encoding.UTF8,
            };
            try
            {
                using var proc = Process.Start(psi);
                if (proc == null) return null;
                Task<string> outTask = proc.StandardOutput.ReadToEndAsync();
                Task<string> errTask = proc.StandardError.ReadToEndAsync();
                if (!Task.WaitAll(new Task[] { outTask, errTask }, timeoutMs))
                {
                    try { proc.Kill(entireProcessTree: true); } catch { /* already exited */ }
                    ErrorLog.Add(ErrorCategory.Timeout,
                        $"{System.IO.Path.GetFileName(fileName)} timed out after {timeoutMs} ms and was killed.",
                        source: source);
                    return null;
                }
                proc.WaitForExit();
                string outText = outTask.Result;
                if (includeStdErr && errTask.Result.Trim().Length > 0)
                    outText = outText.Length > 0 ? outText + "\n" + errTask.Result : errTask.Result;
                return outText;
            }
            catch (Win32Exception) { return null; }   // winget not installed / not on PATH - an expected, quiet condition
            catch (Exception ex)
            {
                ErrorLog.Add(ErrorCategory.Error,
                    $"{System.IO.Path.GetFileName(fileName)} failed: {ex.Message}", ex.ToString(), source);
                return null;
            }
        }

        /// <summary>
        /// Parses winget's fixed-width list. The separator winget prints under the header is one
        /// continuous run of dashes (no per-column gaps), so column boundaries are taken from the
        /// header row instead - the start of each title after a run of 2+ spaces. That is
        /// locale-independent (it never reads the localized title text), and winget pads/truncates
        /// every cell to its column width, so slicing by those offsets is reliable.
        /// </summary>
        internal static List<WingetRow> ParseWingetList(string output)
        {
            var rows = new List<WingetRow>();
            var lines = output.Replace("\r\n", "\n").Replace("\r", "\n").Split('\n');

            int dash = -1;
            for (int i = 0; i < lines.Length; i++)
            {
                string t = lines[i].Trim();
                if (t.Length >= 8 && t.All(c => c == '-')) { dash = i; break; }
            }
            if (dash <= 0) return rows;

            int h = dash - 1;
            while (h >= 0 && lines[h].Trim().Length == 0) h--;
            if (h < 0) return rows;

            var starts = ColumnStarts(lines[h]);
            if (starts.Count < 5) return rows;             // expect Name, Id, Version, Available, Source

            for (int i = dash + 1; i < lines.Length; i++)
            {
                string line = lines[i];
                if (line.Trim().Length == 0) break;        // table ends at the first blank line

                string Cell(int c)
                {
                    int s = starts[c];
                    if (s >= line.Length) return "";
                    int e = c + 1 < starts.Count ? Math.Min(starts[c + 1], line.Length) : line.Length;
                    return line.Substring(s, e - s).Trim();
                }

                var row = new WingetRow
                {
                    Name = Cell(0), Id = Cell(1), Version = Cell(2),
                    Available = Cell(3), Source = Cell(4),
                };
                if (row.Id.Length == 0 && row.Version.Length == 0) continue;   // skip footer / noise
                rows.Add(row);
            }
            return rows;
        }

        /// <summary>Column start offsets = index 0, plus each non-space preceded by 2+ spaces.</summary>
        private static List<int> ColumnStarts(string header)
        {
            var starts = new List<int>();
            int i = 0;
            while (i < header.Length && header[i] == ' ') i++;
            if (i < header.Length) starts.Add(i);
            for (; i < header.Length; i++)
                if (header[i] != ' ' && i >= 2 && header[i - 1] == ' ' && header[i - 2] == ' ')
                    starts.Add(i);
            return starts;
        }
    }
}
