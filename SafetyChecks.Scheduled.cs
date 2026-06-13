// Copyright (c) 2026 LanDen Labs - Dennis Lang

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.Linq;
using System.Text.Json;

namespace B4Browse
{
    /// <summary>
    /// Windows Task Scheduler entries (the Scheduled tab). Scheduled tasks are one of the
    /// top program-persistence mechanisms alongside services and Run keys, so the same
    /// "recent change that doesn't line up with a patch" lens plus a hijack-focused audit
    /// applies. Read via <c>Get-ScheduledTask</c> / <c>Get-ScheduledTaskInfo</c> (no admin
    /// needed to enumerate). Each task's first executable action is resolved and audited
    /// for the attacker-favoured patterns (runs from Temp/Downloads/AppData, a
    /// living-off-the-land binary, a hidden task pointing outside trusted install roots).
    /// </summary>
    public static partial class SafetyChecks
    {
        /// <summary>Structured scheduled-task list (used by the Scheduled grid), newest-created first.</summary>
        public static List<ScheduledTaskItem> GetScheduledTasks()
        {
            // One pass: Get-ScheduledTask for definition (actions, principal, registration date),
            // piped through Get-ScheduledTaskInfo for the last/next run times. Each task is
            // fault-isolated so one unreadable entry can't abort the enumeration.
            const string script = @"
$ErrorActionPreference='SilentlyContinue'
@(Get-ScheduledTask | ForEach-Object {
  $t=$_
  $a=($t.Actions | Where-Object { $_.Execute } | Select-Object -First 1)
  $i=$null; try { $i = $t | Get-ScheduledTaskInfo } catch {}
  # Repeat period: prefer a trigger's sub-pattern repetition (ISO-8601 'every X'), else a
  # daily trigger's day interval. Weekly/monthly/event/logon/boot have no simple period.
  $rep=''
  foreach($trg in @($t.Triggers | Where-Object { $_ })){ if($trg.Repetition -and $trg.Repetition.Interval){ $rep=[string]$trg.Repetition.Interval; break } }
  if(-not $rep){ foreach($trg in @($t.Triggers | Where-Object { $_ })){ if($trg.PSObject.Properties['DaysInterval'] -and [int]$trg.DaysInterval -ge 1){ $rep='P'+([int]$trg.DaysInterval)+'D'; break } } }
  [pscustomobject]@{
    Name=[string]$t.TaskName
    Path=[string]$t.TaskPath
    State=[string]$t.State
    Author=[string]$t.Author
    RunAs=[string]$t.Principal.UserId
    Hidden=[bool]$t.Settings.Hidden
    Execute=[string]$a.Execute
    Arguments=[string]$a.Arguments
    Created=[string]$t.Date
    LastRun=$(if($i -and $i.LastRunTime){$i.LastRunTime.ToString('o')}else{''})
    NextRun=$(if($i -and $i.NextRunTime){$i.NextRunTime.ToString('o')}else{''})
    Repeat=[string]$rep
  }
}) | ConvertTo-Json -Compress -Depth 4";

            var list = new List<ScheduledTaskItem>();
            foreach (var r in RunPowerShellArray(script))
            {
                var t = new ScheduledTaskItem
                {
                    Name = Str(r, "Name"),
                    TaskPath = Str(r, "Path"),
                    State = Str(r, "State"),
                    Author = Str(r, "Author"),
                    RunAs = Str(r, "RunAs"),
                    Hidden = Str(r, "Hidden").Equals("true", StringComparison.OrdinalIgnoreCase),
                    Execute = Str(r, "Execute"),
                    Arguments = Str(r, "Arguments"),
                };
                if (t.Name.Length == 0) continue;

                t.Enabled = !t.State.Equals("Disabled", StringComparison.OrdinalIgnoreCase);
                t.ExePath = SafeExpand(t.Execute);

                t.Created = SaneTaskDate(Str(r, "Created"));
                t.LastRun = SaneTaskDate(Str(r, "LastRun"));
                t.NextRun = SaneTaskDate(Str(r, "NextRun"));

                t.CreatedText = t.Created?.ToString("yyyy-MM-dd") ?? "—";
                t.LastRunText = t.LastRun?.ToString("yyyy-MM-dd HH:mm") ?? "—";
                t.NextRunText = t.NextRun?.ToString("yyyy-MM-dd HH:mm") ?? "—";
                (t.RepeatText, t.RepeatMinutes) = FormatRepeat(Str(r, "Repeat"));

                t.StatusSort = t.Created ?? DateTime.MinValue;
                if (t.Created is DateTime c)
                    t.DaysOld = Math.Max(0, (int)(DateTime.Now - c).TotalDays);

                AuditScheduledTask(t);
                list.Add(t);
            }

            // Flagged first, then newest-created; an unknown date sorts last.
            list.Sort((a, b) =>
            {
                int byRisk = ((int)b.Risk).CompareTo((int)a.Risk);
                return byRisk != 0 ? byRisk : b.StatusSort.CompareTo(a.StatusSort);
            });
            return list;
        }

        /// <summary>
        /// Enables or disables a scheduled task via <c>Enable-/Disable-ScheduledTask</c>. The spawned
        /// PowerShell inherits this process's privileges, so it succeeds only when B4 Browse is
        /// running elevated (and even then some protected <c>\Microsoft\Windows\</c> tasks owned by
        /// TrustedInstaller may refuse). Never throws; returns (ok, message) for the UI to display.
        /// </summary>
        public static (bool Ok, string Message) SetScheduledTaskState(string taskPath, string taskName, bool enable)
        {
            string verb = enable ? "Enable-ScheduledTask" : "Disable-ScheduledTask";
            // Task path/name come from the live task list; single-quote-escape for the literal.
            string p = (taskPath ?? "").Replace("'", "''");
            string n = (taskName ?? "").Replace("'", "''");
            string script =
                "$ErrorActionPreference='Stop'; " +
                "try { " + verb + " -TaskName '" + n + "' -TaskPath '" + p + "' | Out-Null; " +
                "@{ok=$true} | ConvertTo-Json -Compress } " +
                "catch { @{ok=$false; err=[string]$_.Exception.Message} | ConvertTo-Json -Compress }";

            var root = RunPowerShellJson(script);
            if (root == null) return (false, "No response from PowerShell - task state unchanged.");

            bool ok = root.Value.TryGetProperty("ok", out var okEl) && okEl.ValueKind == JsonValueKind.True;
            if (ok) return (true, enable ? "Task enabled." : "Task disabled.");

            string err = root.Value.TryGetProperty("err", out var e) ? (e.GetString() ?? "") : "";
            return (false, err.Length > 0 ? err : "Failed to change the task state.");
        }

        /// <summary>
        /// Converts an ISO-8601 repeat interval ("PT5M", "PT1H", "P7D", "P1DT12H") to a short code:
        /// minutes (5M), whole hours (6H), whole days (7D), or fractional days (1.5D). Returns
        /// ("—", 0) when the period is absent or not a simple minute/hour/day interval.
        /// </summary>
        private static (string Text, double Minutes) FormatRepeat(string iso)
        {
            if (string.IsNullOrEmpty(iso)) return ("—", 0);
            TimeSpan ts;
            try { ts = System.Xml.XmlConvert.ToTimeSpan(iso); }
            catch { return ("—", 0); }
            if (ts <= TimeSpan.Zero) return ("—", 0);

            string text;
            if (ts.TotalDays >= 1)
            {
                double d = ts.TotalDays;
                text = d == Math.Floor(d) ? $"{(int)d}D" : $"{d:0.0}D";
            }
            else if (ts.TotalHours >= 1)
            {
                double h = ts.TotalHours;
                text = h == Math.Floor(h) ? $"{(int)h}H" : $"{h:0.0}H";
            }
            else
                text = $"{(int)Math.Round(ts.TotalMinutes)}M";

            return (text, ts.TotalMinutes);
        }

        /// <summary>
        /// Returns the full Properties-style detail for one task (triggers, conditions, last result,
        /// run-as, etc.) via <c>schtasks /query /tn ... /v /fo LIST</c>. The MMC console (taskschd.msc)
        /// cannot be deep-linked to a specific task from the command line, so this is the in-app
        /// equivalent of landing on that task's Properties. Never throws; returns an error string.
        /// </summary>
        public static string GetScheduledTaskDetails(string fullTaskName)
        {
            try
            {
                var psi = new ProcessStartInfo("schtasks.exe")
                {
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    StandardOutputEncoding = System.Text.Encoding.UTF8,
                };
                psi.ArgumentList.Add("/query");
                psi.ArgumentList.Add("/tn");
                psi.ArgumentList.Add(fullTaskName);
                psi.ArgumentList.Add("/v");
                psi.ArgumentList.Add("/fo");
                psi.ArgumentList.Add("LIST");

                using var p = Process.Start(psi);
                if (p == null) return "Could not start schtasks.exe.";
                string outp = p.StandardOutput.ReadToEnd();
                string err = p.StandardError.ReadToEnd();
                if (!p.WaitForExit(8000)) { try { p.Kill(); } catch { } return "schtasks timed out."; }

                outp = outp.Trim();
                if (outp.Length == 0) outp = err.Trim();
                return outp.Length > 0 ? outp : "(no details returned)";
            }
            catch (Exception ex) { return "Error running schtasks: " + ex.Message; }
        }

        /// <summary>Task Scheduler reports "never run" as a 1899/1999 sentinel; treat pre-2000 as none.</summary>
        private static DateTime? SaneTaskDate(string s)
        {
            if (string.IsNullOrWhiteSpace(s)) return null;
            if (!DateTime.TryParse(s, CultureInfo.InvariantCulture,
                    DateTimeStyles.RoundtripKind, out var dt)) return null;
            if (dt.Kind == DateTimeKind.Utc) dt = dt.ToLocalTime();
            return dt.Year >= 2000 ? dt : (DateTime?)null;
        }

        /// <summary>
        /// Flags the attacker-favoured patterns on a task's executable action. Mirrors the
        /// firewall-rule audit and reuses its trusted-root / LOLBin / user-drop-dir sets.
        /// </summary>
        private static void AuditScheduledTask(ScheduledTaskItem t)
        {
            t.Risk = TabSeverity.None;
            var notes = new List<string>();
            void Flag(TabSeverity sev, string why) { t.Risk = Sev.Max(t.Risk, sev); notes.Add(why); }

            string exe = t.ExePath.Length > 0 ? t.ExePath : t.Execute;
            string lower = exe.ToLowerInvariant();
            bool realPath = exe.IndexOf('\\') >= 0;
            string file = realPath ? SafeFileName(exe) : "";
            // Windows' own tasks (\Microsoft\...) running the genuine system binary are signed OS
            // plumbing - Windows schedules hundreds of rundll32/cmd tasks - so they must not flag.
            bool builtin = t.TaskPath.StartsWith(@"\Microsoft\", StringComparison.OrdinalIgnoreCase);
            bool trustedExe = realPath && TrustedProgramRoots.Any(root => lower.StartsWith(root));

            // 1. Program in a user-writable / transient directory - no admin needed to plant it.
            if (realPath)
            {
                bool transient = lower.Contains(@"\windows\temp\") ||
                                 lower.Contains(@"\appdata\local\temp\") ||
                                 lower.Contains(@"\users\public\") ||
                                 UserDropDir.IsMatch(lower);
                if (transient)
                    Flag(TabSeverity.Alert, "Runs a program from a temp/download folder");
                else if (lower.Contains(@"\appdata\"))
                    Flag(TabSeverity.Caution, "Runs a program under AppData (per-user location)");
                else if (lower.Contains(@"\programdata\"))
                    Flag(TabSeverity.Caution, "Runs a program under ProgramData");
            }

            // 2. Living-off-the-land binary - dangerous when it carries arguments (download cradle).
            //    Skip the signed Windows built-ins; flag third-party/user tasks or a LOLBin invoked
            //    from outside the trusted install roots.
            if (file.Length > 0 && FirewallLolBins.Contains(file) && !(builtin && trustedExe))
                Flag(t.Arguments.Length > 0 ? TabSeverity.Alert : TabSeverity.Caution,
                    $"Runs living-off-the-land binary {file}");

            // 3. Hidden task pointing outside the trusted install roots.
            if (t.Hidden && realPath && !TrustedProgramRoots.Any(root => lower.StartsWith(root)))
                Flag(TabSeverity.Caution, "Hidden task running a program outside trusted locations");

            // A disabled task is a lesser, latent risk than a live one.
            if (!t.Enabled && t.Risk == TabSeverity.Alert)
            {
                t.Risk = TabSeverity.Caution;
                notes.Add("(task is disabled)");
            }

            t.Note = string.Join("; ", notes);
        }

        // ----------------------------------------------------------------- //
        // Report producer (headless / email)
        // ----------------------------------------------------------------- //
        public static CheckGroup CheckScheduledTasks()
        {
            var group = new CheckGroup("Scheduled Tasks");

            List<ScheduledTaskItem> tasks;
            try { tasks = GetScheduledTasks(); }
            catch (Exception ex)
            {
                group.Add(CheckStatus.Warn, "Scheduled tasks", "Could not read tasks: " + ex.Message);
                return group;
            }

            if (tasks.Count == 0)
            {
                group.Add(CheckStatus.Info, "Scheduled tasks", "No scheduled tasks reported.");
                return group;
            }

            var flagged = tasks.Where(t => t.Risk >= TabSeverity.Caution)
                               .OrderByDescending(t => (int)t.Risk).ToList();
            var recent = tasks.Where(t => t.Risk < TabSeverity.Caution && t.DaysOld is int d && d < 30)
                              .OrderByDescending(t => t.StatusSort).ToList();

            foreach (var t in flagged.Take(MaxList))
                group.Add(t.Risk == TabSeverity.Alert ? CheckStatus.Fail : CheckStatus.Warn,
                    t.FullName,
                    $"{(t.Execute.Length > 0 ? t.Execute : "(no program)")}  -  runs as {t.RunAs}  -  {t.Note}");

            int shown = 0;
            foreach (var t in recent)
            {
                if (++shown > MaxList) break;
                string repeat = t.RepeatText != "—" ? $"  -  every {t.RepeatText}" : "";
                group.Add(CheckStatus.Info, $"{t.CreatedText}  {t.FullName}",
                    $"{(t.Execute.Length > 0 ? t.Execute : "(no program)")}  -  runs as {t.RunAs}{repeat}");
            }

            group.Add(flagged.Any(t => t.Risk == TabSeverity.Alert) ? CheckStatus.Fail
                      : flagged.Count > 0 ? CheckStatus.Warn : CheckStatus.Pass,
                "Scheduled task audit",
                $"{tasks.Count} task(s); {flagged.Count} flagged, {recent.Count} created in the last 30 days.");
            return group;
        }
    }
}
