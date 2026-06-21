// Copyright (c) 2026 LanDen Labs - Dennis Lang

using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text.Json;
using Microsoft.Win32;
using System.Security.Principal;

namespace B4Browse
{
    /// <summary>
    /// Local user accounts (the Users tab). A rogue local account is a classic persistence /
    /// backdoor mechanism, so this surfaces every local account with the signals that matter:
    /// when it was created (best-effort - see below), when it last logged in, whether it is an
    /// administrator, hidden from the sign-in screen, has no password requirement, or has expired
    /// yet is still enabled. The roster and most fields come from Get-LocalUser (no elevation
    /// needed). Administrators membership is resolved by the well-known SID S-1-5-32-544 (locale
    /// independent). Hidden accounts come from the Winlogon SpecialAccounts\UserList registry key.
    ///
    /// "Created" is the hard one: Windows exposes no reliable account-creation timestamp through a
    /// standard API (the SAM holds it but HKLM\SAM is ACL-locked to SYSTEM). So it is layered and
    /// each row records which source it used: the real time from Security event 4720 when an admin
    /// can read the Security log; otherwise the profile folder's creation time (a first-logon proxy,
    /// labelled approximate); otherwise unknown - and an enabled account that has never logged in
    /// AND has no known creation date is itself flagged (the dormant-backdoor pattern).
    /// </summary>
    public static partial class SafetyChecks
    {
        private const int NewAccountDays = 30;   // created within this window = worth a look (recency)
        private const string ProfileListKey =
            @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList";
        private const string SpecialAccountsKey =
            @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList";

        /// <summary>Structured local-account list (used by the Users grid). Empty only if
        /// Get-LocalUser is unavailable (very old Windows) - it needs no elevation.</summary>
        public static List<UserAccount> GetUserAccounts() {
            // Primary roster + per-account fields from Get-LocalUser. Dates are formatted in
            // PowerShell to a fixed string (empty when $null = "never"), sidestepping the
            // DateTime JSON-serialisation differences between PowerShell versions.
            var rows = RunPowerShellArray(
                "@(Get-LocalUser | Select-Object Name, FullName, Description, Enabled, " +
                "@{n='Sid';e={$_.SID.Value}}, @{n='Source';e={[string]$_.PrincipalSource}}, " +
                "PasswordRequired, UserMayChangePassword, " +
                "@{n='AccountExpires';e={if($_.AccountExpires){$_.AccountExpires.ToString('yyyy-MM-dd HH:mm:ss')}else{''}}}, " +
                "@{n='PasswordExpires';e={if($_.PasswordExpires){$_.PasswordExpires.ToString('yyyy-MM-dd HH:mm:ss')}else{''}}}, " +
                "@{n='PasswordLastSet';e={if($_.PasswordLastSet){$_.PasswordLastSet.ToString('yyyy-MM-dd HH:mm:ss')}else{''}}}, " +
                "@{n='LastLogon';e={if($_.LastLogon){$_.LastLogon.ToString('yyyy-MM-dd HH:mm:ss')}else{''}}}) | " +
                "ConvertTo-Json -Compress -Depth 3");

            var adminSids = GetAdministratorMemberSids();
            var hiddenNames = GetHiddenAccountNames();
            var profilePaths = GetProfileListPaths();
            var createdEvents = GetAccountCreationTimes();   // empty unless elevated (Security log)
            var lastLogonEvents = GetAccountLastLogonTimes(); // empty unless elevated (Security log)

            var list = new List<UserAccount>();
            foreach (var r in rows) {
                var u = new UserAccount {
                    Name = Str(r, "Name"),
                    FullName = Str(r, "FullName"),
                    Description = Str(r, "Description"),
                    Sid = Str(r, "Sid"),
                    Source = Str(r, "Source"),
                    Enabled = JBool(r, "Enabled"),
                    PasswordRequired = JBool(r, "PasswordRequired"),
                };

                u.IsAdmin = u.Sid.Length > 0 && adminSids.Contains(u.Sid);
                u.IsBuiltin = IsBuiltinRid(u.Sid);
                u.IsHidden = hiddenNames.Contains(u.Name) ||
                             (u.Name.EndsWith("$", StringComparison.Ordinal));

                u.AccountExpires = ParseStamp(Str(r, "AccountExpires"));
                u.AccountExpiresText = u.AccountExpires is { } ae ? ae.ToString("yyyy-MM-dd") : "never";

                u.PasswordLastSet = ParseStamp(Str(r, "PasswordLastSet"));
                u.PasswordLastSetText = u.PasswordLastSet is { } pls ? pls.ToString("yyyy-MM-dd") : "—";

                // PasswordExpires null = password never expires (a hardening weakness on an enabled account).
                u.PasswordNeverExpires = u.Enabled && ParseStamp(Str(r, "PasswordExpires")) is null;

                u.LastLogon = ParseStamp(Str(r, "LastLogon"));
                u.LastLogonText = u.LastLogon is { } ll ? ll.ToString("yyyy-MM-dd HH:mm") : "never";

                if (u.Sid.Length > 0 && profilePaths.TryGetValue(u.Sid, out var profile))
                    u.ProfilePath = profile;
                if (u.ProfilePath.Length > 0)
                    u.ProfileUserName = Path.GetFileName(u.ProfilePath);

                AssignCreated(u, createdEvents, profilePaths);
                Classify(u);
                list.Add(u);
            }



            // (LastLogon mapping moved later so it can cover profile-only rows added below.)

            // Include profiled non-local accounts (domain / Microsoft accounts that have
            // a folder under C:\Users but are not listed by Get-LocalUser). This ensures
            // the currently-running user (whoami) whose profile is present is visible.
            var existingSids = new HashSet<string>(list.Select(u => u.Sid), StringComparer.OrdinalIgnoreCase);
            var profNames = EnumerateProfileAccountNames();
            foreach (var kv in profilePaths)
            {
                var sid = kv.Key;
                var path = kv.Value;
                if (existingSids.Contains(sid)) continue;
                // Heuristic: only include SIDs that look like user profile SIDs.
                if (!sid.StartsWith("S-1-5-21-", StringComparison.OrdinalIgnoreCase) &&
                    !sid.StartsWith("S-1-12-1-", StringComparison.OrdinalIgnoreCase))
                    continue;

                var name = profNames.TryGetValue(sid, out var an) ? an : sid;
                var u = new UserAccount
                {
                    Name = name,
                    FullName = "",
                    Description = "",
                    Sid = sid,
                    Source = "profile",
                    Enabled = true,
                    PasswordRequired = true,
                    ProfilePath = path,
                    ProfileUserName = Path.GetFileName(path)
                };
                u.IsAdmin = adminSids.Contains(sid);
                u.IsBuiltin = IsBuiltinRid(sid);
                u.IsHidden = false;
                AssignCreated(u, createdEvents, profilePaths);
                Classify(u);
                list.Add(u);
            }

            // After adding any profile-only rows, populate LastLogon for all rows using
            // Security log (4624) when available, otherwise fall back to NTUSER.DAT/profile timestamps.
            foreach (var u in list)
            {
                if (u.LastLogon is null)
                {
                    if (u.Sid.Length > 0 && lastLogonEvents.TryGetValue(u.Sid, out var sldt))
                    {
                        u.LastLogon = sldt;
                        u.LastLogonText = sldt.ToString("yyyy-MM-dd HH:mm");
                        continue;
                    }

                    if (u.ProfilePath.Length > 0 && TryProfileLastLogon(u.ProfilePath, out var lt))
                    {
                        u.LastLogon = lt;
                        u.LastLogonText = lt.ToString("yyyy-MM-dd HH:mm");
                    }
                }
            }

            list.Sort((a, b) => b.Risk.CompareTo(a.Risk));
            return list;
        }

        /// <summary>
        /// Enumerates ProfileList SIDs and attempts to translate each SID to an NT account name
        /// (e.g. AzureAD\user or DOMAIN\user). Returns a map SID -> accountName (or SID when
        /// translation fails). This is safe to call unelevated.
        /// </summary>
        public static Dictionary<string, string> EnumerateProfileAccountNames()
        {
            var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(ProfileListKey);
                if (key == null) return map;
                foreach (var sid in key.GetSubKeyNames())
                {
                    try
                    {
                        string account = sid;
                        try
                        {
                            var sidObj = new SecurityIdentifier(sid);
                            var nt = (NTAccount)sidObj.Translate(typeof(NTAccount));
                            if (!string.IsNullOrEmpty(nt.Value)) account = nt.Value;
                        }
                        catch { /* leave account as SID when translation fails */ }

                        map[sid] = account;
                    }
                    catch { /* skip a single unreadable profile key */ }
                }
            }
            catch { /* fall through to empty */ }
            return map;
        }

        /// <summary>Real last-interactive-logon times from Security event 4624, keyed by target SID.
        /// Only interactive / unlock / remote-interactive logon types are considered (2,7,10).
        /// Empty unless elevated (the Security log is admin-only) - degrades silently.</summary>
        private static Dictionary<string, DateTime> GetAccountLastLogonTimes()
        {
            var map = new Dictionary<string, DateTime>(StringComparer.OrdinalIgnoreCase);
            if (!Elevation.IsAdmin) return map;

            var rows = RunPowerShellArray(@"
$ErrorActionPreference='SilentlyContinue'
$ev = Get-WinEvent -FilterHashtable @{LogName='Security';Id=4624} -MaxEvents 2000 -ErrorAction SilentlyContinue
@($ev | ForEach-Object {
  $x=[xml]$_.ToXml()
  $sid=($x.Event.EventData.Data | Where-Object {$_.Name -eq 'TargetSid'}).'#text'
  $lt=($x.Event.EventData.Data | Where-Object {$_.Name -eq 'LogonType'}).'#text'
  if ($lt -in @('2','7','10')) { [pscustomobject]@{ Sid=[string]$sid; Time=$_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss') } }
}) | ConvertTo-Json -Compress -Depth 3");

            foreach (var r in rows)
            {
                string sid = Str(r, "Sid");
                var t = ParseStamp(Str(r, "Time"));
                if (sid.Length == 0 || t is null) continue;
                // Keep the latest 4624 per SID (we want most recent interactive logon).
                if (!map.TryGetValue(sid, out var prev) || t.Value > prev) map[sid] = t.Value;
            }
            return map;
        }

        /// <summary>Layered creation date: Security event 4720 (real, admin) -> profile-folder
        /// creation time (first-logon proxy) -> unknown.</summary>
        private static void AssignCreated(
            UserAccount u, IReadOnlyDictionary<string, DateTime> events,
            IReadOnlyDictionary<string, string> profilePaths)
        {
            if (u.Sid.Length > 0 && events.TryGetValue(u.Sid, out var evt))
            {
                u.Created = evt;
                u.CreatedSource = "audited";
            }
            else if (u.Sid.Length > 0 && profilePaths.TryGetValue(u.Sid, out var path) &&
                     TryDirCreationTime(path, out var ctime))
            {
                u.Created = ctime;
                u.CreatedSource = "first logon";
            }

            if (u.Created is { } c)
            {
                u.CreatedText = c.ToString("yyyy-MM-dd");
                u.DaysOld = Math.Max(0, (int)(DateTime.Now - c).TotalDays);
            }
            else
            {
                u.CreatedText = "—";
            }
        }

        /// <summary>Per-row audit. Enabled built-in Administrator/Guest, an enabled hidden
        /// non-built-in account, and recently-created accounts are the strong signals; an
        /// expired-but-enabled account, no-password-required, password-never-expires, and the
        /// dormant (never-logged-in, unknown-creation) pattern are softer cautions.</summary>
        private static void Classify(UserAccount u)
        {
            var sev = TabSeverity.Ok;
            var notes = new List<string>();

            // Built-in Administrator (RID 500) / Guest (RID 501) should normally be disabled.
            if (u.Enabled && u.Sid.EndsWith("-500", StringComparison.Ordinal))
            {
                sev = Sev.Max(sev, TabSeverity.Alert);
                notes.Add("built-in Administrator is enabled");
            }
            if (u.Enabled && u.Sid.EndsWith("-501", StringComparison.Ordinal))
            {
                sev = Sev.Max(sev, TabSeverity.Alert);
                notes.Add("Guest account is enabled");
            }

            // A hidden, non-built-in, enabled account is a classic backdoor (hidden from the sign-in screen).
            if (u.IsHidden && u.Enabled && !u.IsBuiltin)
            {
                sev = Sev.Max(sev, TabSeverity.Alert);
                notes.Add("hidden from the sign-in screen");
            }

            // Recently created (the "what changed and why" thesis): correlate against the patch date.
            if (u.DaysOld is { } d && !u.IsBuiltin)
            {
                sev = Sev.Max(sev, Sev.FromDays(d));
                if (d < NewAccountDays)
                    notes.Add($"created {d} day(s) ago ({CreatedSourceLabel(u)})");
            }

            // Expired but still enabled.
            if (u.Enabled && u.AccountExpires is { } ae && ae < DateTime.Now)
            {
                sev = Sev.Max(sev, TabSeverity.Caution);
                notes.Add("account expired but still enabled");
            }

            // Hardening weaknesses on interactive accounts.
            if (u.Enabled && !u.PasswordRequired && !u.IsBuiltin)
            {
                sev = Sev.Max(sev, TabSeverity.Caution);
                notes.Add("no password required");
            }

            // Dormant + unknown creation: exists, never signed in, and we can't date it.
            if (u.Enabled && !u.IsBuiltin && u.LastLogon is null && u.Created is null)
            {
                sev = Sev.Max(sev, TabSeverity.Caution);
                notes.Add("never logged in; creation date unknown");
            }

            if (u.IsAdmin && notes.Count > 0)
                notes.Insert(0, "administrator");

            u.Risk = sev;
            u.Note = string.Join("; ", notes);
        }

        private static string CreatedSourceLabel(UserAccount u) => u.CreatedSource switch
        {
            "audited" => "from the audit log",
            "first logon" => "approx, first logon",
            _ => "date unknown",
        };

        // ----------------------------------------------------------------- //
        // Supporting lookups
        // ----------------------------------------------------------------- //

        /// <summary>SIDs of the members of the local Administrators group, resolved by the
        /// well-known SID S-1-5-32-544 so it works on non-English Windows.</summary>
        private static HashSet<string> GetAdministratorMemberSids()
        {
            var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var rows = RunPowerShellArray(
                "@(Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction SilentlyContinue | " +
                "Select-Object @{n='Sid';e={$_.SID.Value}}) | ConvertTo-Json -Compress -Depth 3");
            foreach (var r in rows)
            {
                string sid = Str(r, "Sid");
                if (sid.Length > 0) set.Add(sid);
            }
            return set;
        }

        /// <summary>Real account-creation times from Security event 4720, keyed by target SID.
        /// Empty unless elevated (the Security log is admin-only) - degrades silently.</summary>
        private static Dictionary<string, DateTime> GetAccountCreationTimes()
        {
            var map = new Dictionary<string, DateTime>(StringComparer.OrdinalIgnoreCase);
            if (!Elevation.IsAdmin) return map;

            var rows = RunPowerShellArray(@"
$ErrorActionPreference='SilentlyContinue'
$ev = Get-WinEvent -FilterHashtable @{LogName='Security';Id=4720} -MaxEvents 500 -ErrorAction SilentlyContinue
@($ev | ForEach-Object {
  $x=[xml]$_.ToXml()
  $sid=($x.Event.EventData.Data | Where-Object {$_.Name -eq 'TargetSid'}).'#text'
  [pscustomobject]@{ Sid=[string]$sid; Time=$_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss') }
}) | ConvertTo-Json -Compress -Depth 3");

            foreach (var r in rows)
            {
                string sid = Str(r, "Sid");
                var t = ParseStamp(Str(r, "Time"));
                if (sid.Length == 0 || t is null) continue;
                // Keep the earliest 4720 per SID (an account can be re-created on a reused SID rarely).
                if (!map.TryGetValue(sid, out var prev) || t.Value < prev) map[sid] = t.Value;
            }
            return map;
        }

        /// <summary>SID -> profile directory path from the ProfileList registry key (HKLM reads
        /// work unelevated). Used for the first-logon creation proxy and the profiled-account count.</summary>
        private static Dictionary<string, string> GetProfileListPaths()
        {
            var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(ProfileListKey);
                if (key == null) return map;
                foreach (var sid in key.GetSubKeyNames())
                {
                    try
                    {
                        using var sub = key.OpenSubKey(sid);
                        if (sub?.GetValue("ProfileImagePath") is string p && p.Length > 0)
                            map[sid] = Environment.ExpandEnvironmentVariables(p);
                    }
                    catch { /* skip a single unreadable profile key */ }
                }
            }
            catch { /* fall through to empty */ }
            return map;
        }

        /// <summary>Account names hidden from the sign-in screen (SpecialAccounts\UserList = 0).</summary>
        private static HashSet<string> GetHiddenAccountNames()
        {
            var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(SpecialAccountsKey);
                if (key == null) return set;
                foreach (var name in key.GetValueNames())
                    if (key.GetValue(name) is int i && i == 0) set.Add(name);
            }
            catch { /* fall through to empty */ }
            return set;
        }

        /// <summary>True for the well-known built-in local accounts by RID: Administrator (500),
        /// Guest (501), DefaultAccount (503), WDAGUtilityAccount (504).</summary>
        private static bool IsBuiltinRid(string sid) =>
            sid.EndsWith("-500", StringComparison.Ordinal) ||
            sid.EndsWith("-501", StringComparison.Ordinal) ||
            sid.EndsWith("-503", StringComparison.Ordinal) ||
            sid.EndsWith("-504", StringComparison.Ordinal);

        private static bool TryDirCreationTime(string path, out DateTime created)
        {
            created = default;
            try
            {
                if (!Directory.Exists(path)) return false;
                created = Directory.GetCreationTime(path);
                return created.Year > 1980;
            }
            catch { return false; }
        }

        // Best-effort last-logon from profile: use NTUSER.DAT last-write time when present.
        private static bool TryProfileLastLogon(string profilePath, out DateTime lastLogon)
        {
            lastLogon = default;
            try
            {
                if (string.IsNullOrEmpty(profilePath) || !Directory.Exists(profilePath)) return false;
                var ntuser = Path.Combine(profilePath, "NTUSER.DAT");
                if (File.Exists(ntuser))
                {
                    lastLogon = File.GetLastWriteTime(ntuser);
                    if (lastLogon.Year > 1980) return true;
                }
                // Fallback: profile directory last write
                var dirWrite = Directory.GetLastWriteTime(profilePath);
                if (dirWrite.Year > 1980)
                {
                    lastLogon = dirWrite;
                    return true;
                }
            }
            catch { }
            return false;
        }

        private static DateTime? ParseStamp(string s) =>
            DateTime.TryParseExact(s, "yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture,
                DateTimeStyles.None, out var dt) ? dt : null;

        private static bool JBool(JsonElement e, string p) =>
            e.TryGetProperty(p, out var v) &&
            (v.ValueKind == JsonValueKind.True ||
             (v.ValueKind == JsonValueKind.String && bool.TryParse(v.GetString(), out var b) && b));

        /// <summary>Count of non-local "real user" profiles that have signed in on this PC
        /// (domain / Azure AD accounts): ProfileList SIDs that look like user accounts but are
        /// not in the local SAM. A note for the header, not a per-row signal.</summary>
        private static int CountProfiledNonLocalAccounts(
            IReadOnlyDictionary<string, string> profilePaths, IEnumerable<string> localSids)
        {
            var local = new HashSet<string>(localSids, StringComparer.OrdinalIgnoreCase);
            return profilePaths.Keys.Count(sid =>
                !local.Contains(sid) &&
                (sid.StartsWith("S-1-5-21-", StringComparison.OrdinalIgnoreCase) ||
                 sid.StartsWith("S-1-12-1-", StringComparison.OrdinalIgnoreCase)));
        }

        // ----------------------------------------------------------------- //
        // Tab header
        // ----------------------------------------------------------------- //
        /// <summary>Concise summary for the Users tab header panel.</summary>
        public static CheckGroup UsersHeader()
        {
            var group = new CheckGroup("User Accounts");
            var users = GetUserAccounts();

            if (users.Count == 0)
            {
                group.Add(CheckStatus.Info, "Accounts", "No local accounts read (Get-LocalUser unavailable?).");
                return group;
            }

            int enabled = users.Count(u => u.Enabled);
            int admins = users.Count(u => u.IsAdmin && u.Enabled);
            group.Add(CheckStatus.Info, "Local accounts",
                $"{users.Count} total, {enabled} enabled, {admins} enabled administrator(s).");

            var flagged = users.Where(u => u.Risk >= TabSeverity.Caution).ToList();
            if (flagged.Count > 0)
            {
                var worst = flagged.Max(u => u.Risk);
                group.Add(worst == TabSeverity.Alert ? CheckStatus.Fail : CheckStatus.Warn, "Review",
                    $"{flagged.Count} account(s) flagged: {string.Join(", ", flagged.Take(4).Select(u => u.Name))}" +
                    (flagged.Count > 4 ? ", ..." : "") + ".");
            }
            else
            {
                group.Add(CheckStatus.Pass, "Review", "No accounts flagged.");
            }

            if (!Elevation.IsAdmin)
                group.Add(CheckStatus.Info, "Created dates",
                    "Run as Admin for true creation dates from the audit log; otherwise approximated from profile age.");

            int profiled = CountProfiledNonLocalAccounts(GetProfileListPaths(), users.Select(u => u.Sid));
            if (profiled > 0)
                group.Add(CheckStatus.Info, "Other profiles",
                    $"{profiled} domain / Microsoft account profile(s) have also signed in on this PC (not listed here).");

            // Show the currently running user (whoami) and the user profile folder name.
            try
            {
                var who = Environment.UserDomainName + "\\" + Environment.UserName;
                var upath = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
                var pf = upath.Length > 0 ? Path.GetFileName(upath) : "";
                group.Add(CheckStatus.Info, "Current user",
                    $"{who} (profile folder: {upath}{(pf.Length>0? $" (profile name: {pf})":"")})");
            }
            catch { }

            return group;
        }

        // ----------------------------------------------------------------- //
        // Report producer (headless / email / copy)
        // ----------------------------------------------------------------- //
        public static CheckGroup CheckUsers()
        {
            var group = new CheckGroup("Local User Accounts");
            var users = GetUserAccounts();

            if (users.Count == 0)
            {
                group.Add(CheckStatus.Info, "Accounts",
                    "No local accounts read (Get-LocalUser unavailable on this system).");
                return group;
            }

            int enabled = users.Count(u => u.Enabled);
            int admins = users.Count(u => u.IsAdmin && u.Enabled);
            int flagged = users.Count(u => u.Risk >= TabSeverity.Caution);
            group.Add(flagged > 0 ? CheckStatus.Warn : CheckStatus.Pass, "Summary",
                $"{users.Count} local account(s), {enabled} enabled, {admins} enabled admin(s), {flagged} flagged.");

            if (!Elevation.IsAdmin)
                group.Add(CheckStatus.Info, "Created dates",
                    "Run as administrator for true creation dates (Security event 4720); otherwise approximated from profile age.");

            int shown = 0;
            foreach (var u in users.OrderByDescending(u => u.Risk).ThenBy(u => u.Name))
            {
                if (++shown > MaxList) break;
                var st = u.Risk switch
                {
                    TabSeverity.Alert => CheckStatus.Warn,
                    TabSeverity.Caution => CheckStatus.Warn,
                    _ => CheckStatus.Info,
                };
                string flags = string.Join(" ", new[]
                {
                    u.Enabled ? "" : "[disabled]",
                    u.IsAdmin ? "[admin]" : "",
                    u.IsHidden ? "[hidden]" : "",
                }.Where(s => s.Length > 0));

                string profileInfo = "";
                if (u.ProfilePath.Length > 0)
                {
                    var pname = Path.GetFileName(u.ProfilePath);
                    profileInfo = $"  -  {u.ProfilePath} (profile: {pname})";
                }

                string detail =
                    $"created {u.CreatedText}" +
                    (u.CreatedSource.Length > 0 ? $" ({CreatedSourceLabel(u)})" : "") +
                    $"  -  last logon {u.LastLogonText}" +
                    profileInfo +
                    (flags.Length > 0 ? $"  {flags}" : "") +
                    (u.Note.Length > 0 ? $"   ({u.Note})" : "");
                group.Add(st, u.Name, detail);
            }
            if (users.Count > MaxList)
                group.Add(CheckStatus.Info, "...", $"{users.Count - MaxList} more not shown.");

            return group;
        }
    }
}
