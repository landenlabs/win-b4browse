// Copyright (c) 2026 LanDen Labs - Dennis Lang

namespace BrowseSafe
{
    /// <summary>Authored Help text for every tab, shown by the toolbar Help button via
    /// <see cref="HelpUi.Show"/>. Body uses the light markup documented on <see cref="HelpInfo"/>
    /// ("# " heading, "## " sub-heading, "- " bullet, blank line = spacer).</summary>
    public static class TabHelp
    {
        // Reused note: the recency colouring is shared by most grid tabs.
        private const string Recency =
            "Status colours flag how recently an item changed, so new or unexpected changes stand out:\n" +
            "- Recent  - changed in the last 7 days (highlighted red)\n" +
            "- Month   - changed in the last 30 days (highlighted yellow)\n" +
            "- Old     - older than 30 days (no highlight)\n";

        private const string Common =
            "# General\n" +
            "- Click any column header to sort; click again to reverse.\n" +
            "- Press Refresh in the toolbar to reload the data.\n";

        public static readonly HelpInfo Scan = new("Safety Scan",
            "# What this shows\n" +
            "Runs the full set of safety checks and prints a colour-coded report: each check is tagged " +
            "[ PASS ], [ WARN ], [ FAIL ], or [ INFO ]. The overall verdict drives the window banner and " +
            "the Safety Scan tab colour.\n" +
            "\n" +
            "The other tabs drill into individual areas (patches, processes, services, startup, drivers, " +
            "DNS, browser extensions, events, firewall). This tab is the at-a-glance summary.\n" +
            "\n" +
            "# Network sniffers / promiscuous mode\n" +
            "The scan flags local packet capture: any adapter whose NDIS packet filter has the PROMISCUOUS " +
            "bit set (the defining trait of a live capture), installed capture drivers (Npcap / WinPcap / " +
            "pktmon), and running capture tools (Wireshark, dumpcap, tshark, tcpdump, ...).\n" +
            "\n" +
            "# Special actions\n" +
            "- Run Safety Checks - runs every check; groups render as each completes.\n" +
            "- In the Hosts File section, click [ Open hosts folder ] to reveal the hosts file in Explorer.\n");

        public static readonly HelpInfo Patches = new("Windows Patches",
            "# What this shows\n" +
            "Installed Windows updates and hotfixes reported by WMI (Win32_QuickFixEngineering), newest first.\n" +
            "\n" +
            "# Columns\n" +
            "- Installed - date the update was applied.\n" +
            "- HotFix ID - the KB identifier.\n" +
            "- DocLink   - opens the Microsoft article for that KB in your browser.\n" +
            "\n" + Common);

        public static readonly HelpInfo Dns = new("DNS Resolver Cache",
            "# What this shows\n" +
            "The live Windows DNS resolver cache (the same data as `ipconfig /displaydns`). It is a snapshot " +
            "only - entries expire on their own TTL and Chrome's Secure DNS (DoH) bypasses this cache entirely.\n" +
            "\n" +
            "# Status\n" +
            "- Review - a public-looking name resolving to a non-public IP. That can mean a hijack or captive " +
            "portal, but is often legitimate internal / split-horizon DNS.\n" +
            "- OK     - nothing unusual.\n" +
            "\n" +
            "# Columns\n" +
            "- TTL (s) - remaining time-to-live in seconds (counts down; the cache stores no insert date).\n" +
            "- Data    - the resolved answer (IP or target host).\n" +
            "\n" +
            "# Special actions\n" +
            "- Flush DNS cache - clears the resolver cache, then reloads the (now-empty) view.\n" +
            "- Right-click a row to copy the name or the answer.\n" +
            "\n" + Common);

        public static readonly HelpInfo Arp = new("ARP Neighbor Cache",
            "# What this shows\n" +
            "The live IPv4 ARP cache - the local subnet's map of IP address to physical MAC " +
            "address (the modern `Get-NetNeighbor`, equivalent to `arp -a`). It is a snapshot: " +
            "entries expire within seconds when idle, so this is a real-time view of the network " +
            "neighbours this PC has recently talked to, not a persistent log.\n" +
            "\n" +
            "# Status\n" +
            "- Alert  - a MAC address is shared by the default gateway and another IP. That is the " +
            "classic ARP spoofing / man-in-the-middle (MITM) signature - traffic may be intercepted.\n" +
            "- Review - a MAC is shared by two or more IPs (could be proxy-ARP or a multi-homed host, " +
            "or spoofing), or the address is locally-administered / randomized.\n" +
            "- Static - a manually pinned (Permanent) entry; OK - a normal resolved neighbour.\n" +
            "\n" +
            "# Columns\n" +
            "- MAC / Vendor - the hardware address; Vendor shows the OUI (first 3 bytes) until resolved " +
            "to a manufacturer name.\n" +
            "- Type - Dynamic (learned automatically) or Static (pinned via arp -s / New-NetNeighbor).\n" +
            "- State - Reachable / Stale / Delay / Probe / Permanent, as reported by Windows.\n" +
            "\n" +
            "# Special actions\n" +
            "- All - off by default to hide multicast, broadcast and incomplete rows; turn it on " +
            "to see the full cache.\n" +
            "- Resolve vendors - looks up each unique OUI on macvendors.com (throttled) and fills the " +
            "Vendor column. This makes outbound web requests, so it only runs when you click it.\n" +
            "- Right-click a row to copy the IP or MAC, look up / search the MAC vendor, or copy the row.\n" +
            "\n" +
            "# Note\n" +
            "Duplicate-IP 'flip' detection needs sampling over time and isn't possible from one snapshot; " +
            "what's flagged here is a single MAC claimed by multiple IPs. Randomized MACs are common and " +
            "legitimate on phones and laptops.\n" +
            "\n" + Common);

        public static readonly HelpInfo Chrome = new("Chrome Extensions",
            "# What this shows\n" +
            "Enabled Chrome extensions across your profiles, plus a privacy & security audit in the " +
            "header panel above the table.\n" +
            "\n" +
            "# Header audit\n" +
            "Read from each profile's Preferences and the Chrome policy registry (configuration only - " +
            "no cookie values or other sensitive data are read):\n" +
            "- chrome.exe integrity - path, version, and Authenticode signature.\n" +
            "- Safe Browsing - OFF is flagged (no phishing/malware blocking); Enhanced is noted.\n" +
            "- Third-party cookies - 'Allowed' is flagged (cross-site tracking).\n" +
            "- Cookies on exit - whether cookies are cleared when Chrome closes.\n" +
            "- Enterprise policy - whether the hardening is enforced by policy or user-changeable.\n" +
            "Weak settings (Safe Browsing off, or third-party cookies allowed) also colour the Chrome " +
            "tab so the risk is visible at a glance.\n" +
            "\n" +
            "Each audit line has an inline link (e.g. [ open settings ]) to the matching chrome:// page. " +
            "Chrome can't always be steered to a chrome:// page from outside when it is already running " +
            "with multiple profiles, so the link also copies that URL to the clipboard - just press Ctrl+V " +
            "in Chrome's address bar to jump there.\n" +
            "\n" +
            "# Status\n" +
            "- Unsupported - a Manifest V2 (MV2) extension, which Chrome 138+ no longer supports.\n" +
            "- The Modified column is also tinted by recency.\n" +
            "\n" + Recency +
            "\n" +
            "# Special actions\n" +
            "- Remove unsupported - after confirmation, deletes the folders of all Manifest V2 " +
            "(Unsupported) extensions. It first backs up ALL extensions to " +
            "Downloads\\bsafe-extension-backup.zip; close Chrome first for a clean removal.\n" +
            "- Scan (header) - verify chrome.exe's signature or look it up on VirusTotal.\n" +
            "- Right-click a row to open the extension's folder or copy its path.\n" +
            "\n" + Common);

        public static readonly HelpInfo Services = new("Windows Services",
            "# What this shows\n" +
            "Installed services, with status driven by the modify date of each service's executable.\n" +
            "\n" + Recency +
            "\n" +
            "# Special actions\n" +
            "- All - off by default to hide the noise of old C:\\Windows\\system32 services; turn it on " +
            "to list every service.\n" +
            "- Right-click a row to open the Services console (services.msc), open the service's folder, or " +
            "copy the service name.\n" +
            "\n" + Common);

        public static readonly HelpInfo Processes = new("Running Processes",
            "# What this shows\n" +
            "Currently running processes, with status driven by the modify date of each process's executable.\n" +
            "\n" + Recency +
            "\n" +
            "# Special actions\n" +
            "- All - off by default to surface only the items worth a look: non-Windows executables that " +
            "were installed or updated in the last 30 days (a Recent status). Turn it on to list every process.\n" +
            "- Task Manager - opens taskmgr.exe.\n" +
            "- Scan (per row) - verify the executable's signature or look it up on VirusTotal by SHA-256.\n" +
            "- Right-click a row to open its file location, copy the path, or search the web for it.\n" +
            "\n" + Common);

        public static readonly HelpInfo Startup = new("Startup Apps",
            "# What this shows\n" +
            "Programs configured to launch at startup. Status is the newer of two dates.\n" +
            "\n" +
            "# Columns\n" +
            "- Enabled - whether the entry runs at login. Disabled entries (greyed out) are turned off in " +
            "Task Manager / Settings and tracked in the Explorer\\StartupApproved registry keys.\n" +
            "- Registry added - when the Run-key entry last changed (the key is shared, so this is approximate).\n" +
            "- Exe modified   - modify date of the target executable.\n" +
            "\n" + Recency +
            "\n" +
            "# Filters\n" +
            "- All - off by default to show only enabled entries; turn it on to include disabled ones. " +
            "You can also filter the Enabled column directly.\n" +
            "\n" +
            "# Special actions\n" +
            "- Manage startup - opens the Windows Settings Startup Apps page, where entries can be enabled or disabled.\n" +
            "- Scan (per row) - verify the executable's signature or look it up on VirusTotal.\n" +
            "- Right-click a row to open its file location, manage startup apps in Settings, or open Task Manager.\n" +
            "\n" + Common);

        public static readonly HelpInfo Installed = new("Installed Programs",
            "# What this shows\n" +
            "Installed programs from the uninstall registry, enriched with winget so the list is a " +
            "superset: it also includes Store/MSIX apps and adds each package's Source and any pending " +
            "update. Registry entries keep their install date, Path and Scan action; winget-only rows " +
            "(Store/MSIX) show Status '—' because Windows reports no install date or path for them.\n" +
            "\n" + Recency +
            "\n" +
            "# Columns\n" +
            "- Update - the newer version winget has available; the cell is highlighted yellow and the " +
            "tab is flagged when any app has a pending update (outdated software is a security signal).\n" +
            "- Source - winget / msstore / blank (registry-only).\n" +
            "\n" +
            "# Special actions\n" +
            "- Apps & features... - opens the Windows Settings page.\n" +
            "- Scan (per row) - verify the program's executable signature or look it up on VirusTotal " +
            "(registry entries only; winget-only rows have no exe path to scan).\n" +
            "- Right-click a row for actions (open location, copy path, search the web).\n" +
            "\n" +
            "# Note\n" +
            "Refresh runs `winget list` (a few seconds). If winget isn't installed, the tab falls back to " +
            "the registry list with Source/Update blank. Updates come from winget's own data; run " +
            "`winget upgrade` to apply them.\n" +
            "\n" + Common);

        public static readonly HelpInfo Devices = new("Device Drivers",
            "# What this shows\n" +
            "Installed device drivers. Status is driven by the local INF change date.\n" +
            "\n" +
            "# Columns\n" +
            "- Signed   - whether the driver is digitally signed (unsigned rows are flagged red).\n" +
            "- INF risk - result of analysing the driver's INF for risky directives.\n" +
            "- Vendor date / Version - as reported by the driver package.\n" +
            "\n" + Recency +
            "\n" +
            "# Special actions\n" +
            "- Scan all INFs - analyses every driver INF and fills the INF risk column.\n" +
            "- Device Manager - opens devmgmt.msc.\n" +
            "- Right-click a row to analyse just that driver's INF.\n" +
            "\n" + Common);

        public static readonly HelpInfo WinExt = new("File Explorer Shell Extensions",
            "# What this shows\n" +
            "Third-party File Explorer shell extensions - COM handlers that Windows loads in-process into " +
            "explorer.exe (context menus, icon overlays, property sheets, drag-drop and copy hooks). Each " +
            "row is one extension (CLSID), resolved to the DLL that backs it. A malicious or buggy handler " +
            "runs with Explorer, so this is a useful place to spot unwanted hooks.\n" +
            "\n" +
            "# Status\n" +
            "- Alert  - the DLL loads from a temp / download / AppData location, or (after verifying) is " +
            "unsigned/invalid and not from Microsoft.\n" +
            "- Review - the handler is not on the Windows 'Approved' shell-extensions list, or its DLL is " +
            "missing (orphaned registration).\n" +
            "- OK     - a normal handler.\n" +
            "\n" +
            "# Columns\n" +
            "- Type / Target - the hook kind and what it hooks (all files, Directory, Drive, ...).\n" +
            "- Signed - blank until you run Verify signatures; then Valid / NotSigned / etc.\n" +
            "- DLL path / CLSID - the backing binary and its class id (resolved from InprocServer32).\n" +
            "\n" +
            "# Special actions\n" +
            "- All - off by default to show only third-party handlers; turn it on to include the many " +
            "Microsoft / built-in extensions.\n" +
            "- Verify signatures - checks each handler DLL's Authenticode signature (on demand, since it's " +
            "slow) and turns unsigned non-Microsoft handlers red.\n" +
            "- Right-click a row to open the DLL location, copy the CLSID/path, verify it or look it up on " +
            "VirusTotal, or search the web.\n" +
            "\n" + Common);

        public static readonly HelpInfo Events = new("Windows Events",
            "# What this shows\n" +
            "Recent significant Windows Event Log entries: Critical/Error from the System and Application logs, " +
            "plus security-relevant events (Windows Defender, firewall rule changes, new services, audit-log " +
            "clears). The Security log requires running as administrator.\n" +
            "\n" +
            "# Status\n" +
            "- Critical and security-significant events are flagged red; Error/Warning yellow.\n" +
            "\n" +
            "# Special actions\n" +
            "- Filter bar - narrow the list by Channel (dropdown), or by a regular expression on Source and/or " +
            "Message. Invalid regex falls back to a plain substring match. Clear resets all filters.\n" +
            "- Event Viewer - opens the Windows Event Viewer.\n" +
            "- Right-click a row to open Event Viewer, copy the message, search the web, or show full details.\n" +
            "\n" + Common);

        public static readonly HelpInfo Awake = new("Awake / Sleep Periods",
            "# What this shows\n" +
            "Recent periods the computer was awake, reconstructed from the System event log's power " +
            "events (boot, resume-from-sleep, sleep, and shutdown). Each row is one awake interval, " +
            "newest first. Reading the System log needs no administrator rights.\n" +
            "\n" +
            "# Columns\n" +
            "- # - the interval's number (1 = oldest in the window).\n" +
            "- Start - when the machine booted or woke.\n" +
            "- End - when it next slept or shut down, with a code:\n" +
            "    (off) clean shutdown   (slp) sleep / hibernate   (pwr) ended unexpectedly (crash / power loss)   (on) still awake now.\n" +
            "- Duration - how long the machine stayed awake.\n" +
            "- Why - what started the period, taken from the wake source: a power button / lid / input " +
            "device (User), a scheduled task such as Windows Update or defrag (Scheduler), a Wake-on-LAN " +
            "packet (Network), or a cold power-on.\n" +
            "\n" +
            "# Status colours\n" +
            "- Green  - the current session (still awake).\n" +
            "- Yellow - the period ended unexpectedly (no clean sleep/shutdown was logged).\n" +
            "\n" +
            "# Note\n" +
            "Covers the last 14 days. When a shutdown wasn't logged cleanly the End time can't be known, " +
            "so it shows \"? (pwr)\" with no duration. Scheduled-wake task names come straight from the " +
            "Power-Troubleshooter event text.\n" +
            "\n" +
            "# Special actions\n" +
            "- Event Viewer - opens the Windows Event Viewer to inspect the underlying power events.\n" +
            "- Filter the Why column with a regular expression.\n" +
            "\n" + Common);

        public static readonly HelpInfo RootCerts = new("Trusted Root CAs",
            "# What this shows\n" +
            "The certificates in your trusted-root stores (Local Machine + Current User). A root CA is " +
            "trusted to vouch for ANY HTTPS site, so an unexpected root means your encrypted browsing can " +
            "be silently intercepted (man-in-the-middle). Chrome on Windows honours these roots, so this " +
            "is directly relevant to safe browsing. Reading the store needs no administrator rights.\n" +
            "\n" +
            "# Status\n" +
            "- Intercept - a root from a security/proxy product that performs TLS inspection. It can " +
            "decrypt your HTTPS traffic; expected only if you (or your IT) run that product.\n" +
            "- Review (red) - a non-public root added in the last 30 days. Confirm you installed it - a " +
            "freshly planted root is the classic HTTPS-interception attack.\n" +
            "- Review (yellow) - a non-public root CA (enterprise / AV / developer). Verify it is expected.\n" +
            "- Public CA / System/Local - a well-known public authority or a benign built-in root.\n" +
            "\n" +
            "# Columns\n" +
            "- Subject (CA) / Issuer - the authority's name (root certificates are self-issued).\n" +
            "- Expires - the certificate's validity end date.\n" +
            "- Note - why the row is flagged, and whether it is expired.\n" +
            "\n" +
            "# Filters\n" +
            "- All - off by default to show only the non-public roots worth reviewing; turn it on to list " +
            "every trusted root including the standard public CAs.\n" +
            "\n" +
            "# Special actions\n" +
            "- Manage certificates - opens the Certificates console (certlm.msc) where a root can be removed.\n" +
            "- Right-click a row to copy its subject/thumbprint, open the console, or search the web for the CA.\n" +
            "\n" + Common);

        public static readonly HelpInfo Firewall = new("Windows Firewall",
            "# What this shows\n" +
            "The header panel summarises the Windows Defender Firewall state read from the registry " +
            "(whether each profile is enabled, the rule count, and when the rule/policy store last changed). " +
            "Below it, a scrollable, sortable list of every firewall rule parsed from the registry rule " +
            "stores (local + Group Policy).\n" +
            "\n" +
            "When the firewall is managed by another product (e.g. an EDR agent) the local rule store can be " +
            "empty; the last-changed date considers the policy and profile keys too.\n" +
            "\n" +
            "# Rule audit (hijack indicators)\n" +
            "Each Allow rule is checked for the signs an attacker leaves when punching a hole through the " +
            "firewall for persistence or a command-and-control channel. The Status column flags:\n" +
            "- Alert  - an inbound Allow rule whose program lives in a transient folder (Temp, Downloads, " +
            "Public); a rule granting access to a living-off-the-land binary (PowerShell, cmd, wmic, mshta, " +
            "rundll32, regsvr32, ...); an unscoped \"any protocol / any port / any remote address\" rule; or a " +
            "rule whose name impersonates a known app (e.g. \"Google Chrome\") but whose binary is outside the " +
            "trusted install locations (Program Files / Windows).\n" +
            "- Review - the outbound or lower-confidence form of those signals: a binary under AppData or " +
            "ProgramData (also common for legitimate per-user installs), or a flagged rule that is inactive.\n" +
            "- OK     - nothing unusual. Block rules are not audited (they are protective).\n" +
            "\n" +
            "Sort by Status (default) to float flagged rules to the top, and correlate a rule's appearance " +
            "with the Events tab timeline to pin down when it was added.\n" +
            "\n" +
            "# Note\n" +
            "Loading stops after the first 1000 rules; the header notes when the store is larger than that.\n" +
            "\n" +
            "# Filters\n" +
            "- All - off by default to hide inactive (disabled) rules; turn it on to show every rule.\n" +
            "- Narrow the list by Direction, Action, or Profile (dropdowns), or by a regular expression on the " +
            "rule Name and/or Program path.\n" +
            "\n" +
            "# Special actions\n" +
            "- Manage Firewall - opens Windows Defender Firewall with Advanced Security (wf.msc).\n" +
            "- Right-click a rule to copy its name / program path / audit note, open the program's location, " +
            "or search the web.\n" +
            "\n" + Common);

        public static readonly HelpInfo Restores = new("System Restore Points",
            "# What this shows\n" +
            "The Windows System Restore points on this machine (via Get-ComputerRestorePoint). This " +
            "tab only appears when the app is running as administrator, which is required to read them.\n" +
            "\n" +
            "# Why it matters (security)\n" +
            "- Ransomware disables System Restore and purges shadow copies right after gaining " +
            "privileges, so a disabled service or ZERO restore points is a high-priority indicator of " +
            "compromise - the tab header turns red (Alert) in that case.\n" +
            "- If the youngest restore point is very old (> 90 days), the machine has no effective " +
            "recovery safety net - flagged Review.\n" +
            "- Recent install-triggered checkpoints (App install / Driver install) are highlighted so " +
            "you can map a 'what changed, when' timeline - correlate their timestamps with the Events " +
            "tab to pinpoint a PUP / bundled-software exposure.\n" +
            "\n" +
            "# Columns\n" +
            "- Seq # / Created / Age - the restore point's sequence number, creation time, and age.\n" +
            "- Type - App install / App uninstall / Driver install / Settings change / Cancelled.\n" +
            "\n" +
            "# Special actions\n" +
            "- Right-click a row to copy its description or sequence number, or open System Protection.\n" +
            "\n" +
            "# Note\n" +
            "Before rolling back, be aware malware can survive inside an older restore point; cross-check " +
            "the checkpoint date against any known infection window (e.g. Defender events) first.\n" +
            "\n" + Common);

        public static readonly HelpInfo Links = new("Helpful Links",
            "# What this shows\n" +
            "A page of curated links to security tools and references (Chrome Safety Check, Windows Security, " +
            "VirusTotal, the Chrome extensions guide, and more).\n" +
            "\n" +
            "# Special actions\n" +
            "- Click any link to open it in your default browser.\n");
    }
}
