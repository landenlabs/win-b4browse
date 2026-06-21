// Copyright (c) 2026 LanDen Labs - Dennis Lang

using System;

namespace B4Browse
{
    /// <summary>One row of the Users tab - a local Windows user account (Get-LocalUser),
    /// enriched with Administrators membership, hidden-account flags, and a best-effort
    /// creation date. Windows exposes no reliable "account created" timestamp through a
    /// standard API, so <see cref="Created"/> is layered (see <see cref="CreatedSource"/>):
    /// the real time from Security event 4720 when an administrator can read it, else the
    /// profile folder's creation time (a first-logon proxy), else unknown.</summary>
    public sealed class UserAccount
    {
        public string Name = "";
        public string FullName = "";
        public string Description = "";
        public string Sid = "";
        public string Source = "";          // PrincipalSource: Local / MicrosoftAccount / AzureAD / ...
        public string ProfilePath = "";     // user profile root dir (ProfileList\<SID>\ProfileImagePath); "" if never profiled
        public string ProfileUserName = ""; // folder name under C:\Users (e.g. 'alice') when ProfilePath set

        public bool Enabled;
        public bool IsAdmin;                // member of Administrators (well-known SID S-1-5-32-544)
        public bool IsBuiltin;              // RID 500/501/503/504 (Administrator/Guest/DefaultAccount/WDAGUtility)
        public bool IsHidden;               // SpecialAccounts\UserList = 0, or name ends with '$'
        public bool PasswordRequired = true;
        public bool PasswordNeverExpires;   // enabled account whose password has no expiry

        public DateTime? Created;
        public string CreatedText = "";     // "yyyy-MM-dd" or "—"
        public string CreatedSource = "";   // "audited" (event 4720) / "first logon" (profile) / "" (unknown)
        public int? DaysOld;                // age of Created in days (drives the recency colour)

        public DateTime? LastLogon;
        public string LastLogonText = "";   // "yyyy-MM-dd HH:mm" or "never"

        public DateTime? AccountExpires;
        public string AccountExpiresText = "never";

        public DateTime? PasswordLastSet;
        public string PasswordLastSetText = "—";

        /// <summary>Per-row audit severity (rogue/hidden/recent/expired/dormant account).</summary>
        public TabSeverity Risk;

        /// <summary>Human-readable reason for the row's status.</summary>
        public string Note = "";
    }
}
