// Copyright (c) 2026 LanDen Labs - Dennis Lang

namespace B4Browse
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

        public static readonly HelpInfo Intro = new("Welcome to B4-Browse",
            "# What B4-Browse does\n" +
            "B4-Browse inspects your Windows PC for common signs of trouble and presents what it finds in " +
            "colour-coded tabs, so anything suspicious stands out at a glance. It has two jobs:\n" +
            "\n" +
            "- Confirm the network path is clean - no rogue proxy, no DNS hijack or spoofing - before you browse.\n" +
            "- Surface files, extensions, programs, processes, services and drivers that changed recently but " +
            "don't line up with a Windows update - a place to focus when your PC starts behaving differently.\n" +
            "\n" +
            "Almost every tab only reads and reports. The few actions that change anything (flush the DNS cache, " +
            "remove an unsupported extension) are clearly labelled and always ask first.\n" +
            "\n" +
            "# How to use it\n" +
            "B4-Browse runs the Safety Scan automatically when it opens and shows an overall verdict in the " +
            "banner at the top. From there, work through the tabs along the top.\n" +
            "\n" +
            "A good strategy when you suspect something changed on your machine:\n" +
            "- Open the Patches tab and note the date Windows last updated its files. That is your reference point.\n" +
            "- Visit the other tabs and look for items that changed AFTER that date but were not part of a Windows " +
            "update - and not something you installed yourself.\n" +
            "- Recently-changed items are highlighted (red = last 7 days, yellow = last 30 days), so they float to " +
            "the top when you sort by Status or by date.\n" +
            "\n" +
            "An unexpected change that doesn't line up with a patch date, or with anything you did yourself, is " +
            "worth a closer look.\n" +
            "\n" +
            "# Every tab has its own Help\n" +
            "Each tab has a Help button that explains what it shows, what its colours and columns mean, and what " +
            "its right-click actions do. Use those for the detail - this page is just the map.\n" +
            "\n" +
            "# Administrator rights\n" +
            "A few tabs (Events, Downloads, Virus history, Restores) need Administrator rights to read their data. " +
            "If one of those looks empty, use Run as Admin in the left panel to relaunch with elevation.\n" +
            "\n" +
            "# The tabs at a glance\n" +
            "- Safety Scan - the startup network & security verdict: DNS, proxy, router, packet sniffers, and " +
            "Windows Security state.\n" +
            "- Patches - installed Windows updates, newest first; the reference date for judging the other tabs.\n" +
            "- DNS (Domain Name System) - the live resolver cache; flags public names resolving to private IPs " +
            "(possible hijack or captive portal).\n" +
            "- ARP (Address Resolution Protocol) - the local IP-to-MAC neighbour cache; flags the shared-MAC " +
            "pattern of ARP spoofing / man-in-the-middle.\n" +
            "- Chrome - enabled Chrome extensions, plus a privacy & security audit (Safe Browsing, cookies, " +
            "chrome.exe signature).\n" +
            "- Settings - a matrix of Chrome settings across your profiles; highlights known-weak privacy choices.\n" +
            "- Services - installed background services, flagged by how recently each one's program changed.\n" +
            "- Processes - currently running processes, flagged by how recently each executable changed.\n" +
            "- Startup - programs set to launch at login (a common foothold for unwanted software).\n" +
            "- Scheduled - Task Scheduler entries with a hijack audit (temp-folder, living-off-the-land, hidden tasks).\n" +
            "- Installed - installed programs (registry + winget), with any pending updates flagged.\n" +
            "- Devices - installed device drivers; flags unsigned drivers and risky INF directives.\n" +
            "- Win Extn - third-party File Explorer shell extensions that load inside explorer.exe.\n" +
            "- Events - recent significant Windows event-log entries (errors and security-relevant events).\n" +
            "- Awake - recent power events (boot / wake / sleep / shutdown), listed straight from the log.\n" +
            "- Activity - how often each app has been launched, from Windows Search's usage index.\n" +
            "- Downloads - per-app bytes received and sent (from SRUM); a high upload from an odd process is a " +
            "possible data-exfiltration signal.\n" +
            "- Root CAs - trusted root certificate authorities; flags new or unexpected roots that could enable " +
            "silent HTTPS interception.\n" +
            "- Firewall - firewall state and rules, with an audit for hole-punching / persistence rules.\n" +
            "- Virus - Microsoft Defender protection state and its threat / scan history.\n" +
            "- Restores - System Restore points; zero points or a disabled service is a ransomware indicator (admin only).\n" +
            "- Users - local user accounts, flagging hidden, admin, recently-created or dormant accounts.\n" +
            "- Links - curated links to security tools and references.\n" +
            "\n" +
            "# Command line (advanced)\n" +
            "Most people will only ever use this window, but B4-Browse can also run from a terminal " +
            "(PowerShell or Command Prompt) - useful for saving a report, scheduling an unattended check, " +
            "or auditing exactly how it gathers its data:\n" +
            "\n" +
            "- B4Browse.exe --run <scope>  - run one area's checks and print a plain-text report. A scope is a " +
            "tab name (scan, dns, patches, installed, processes, events, virus, users, ...) or all for everything.\n" +
            "- B4Browse.exe --report  - shorthand for --run scan;  --inventory  - shorthand for --run all.\n" +
            "- B4Browse.exe --out <file>  - also write the report to a file (pairs with any --run mode).\n" +
            "- B4Browse.exe --dump-scripts [dir]  - save every PowerShell script and command the app runs, one " +
            "file per check, to [dir] (default: scripts) - so you can see exactly how each tab collects its data.\n" +
            "- B4Browse.exe --help  - list every option and scope.\n" +
            "\n" +
            "> Example:   B4Browse.exe --run events --out events.txt\n" +
            ">\n" +
            "> The report prints to standard output (progress goes to standard error), so it pipes and redirects " +
            "like any console program. Run from an elevated terminal to include the Administrator-only checks.\n");

        public static readonly HelpInfo Scan = new("Safety Scan",
            "# What this tab does\n" +
            "The Safety Scan is the app's headline check. It runs a battery of network and OS safety probes " +
            "and prints a colour-coded report: each result line is tagged [ PASS ], [ WARN ], [ FAIL ], or " +
            "[ INFO ], and the worst result sets the overall verdict shown in the window banner and on this tab.\n" +
            "\n" +
            "Run it first when you sit down to browse: it confirms the path between this PC and the internet " +
            "is clean - no rogue proxy, no DNS hijack or spoof, no packet sniffer - and that Windows' own " +
            "defences are switched on. Press [ Run Safety Checks ] to run (or re-run) it; each numbered " +
            "section below appears as it finishes.\n" +
            "\n" +
            "# The checks\n" +
            "The report is organised into twelve numbered sections, run in this order:\n" +
            "\n" +
            "## 1. Current DNS Servers\n" +
            "Lists the DNS server each active adapter is set to use, naming any well-known public resolver " +
            "(Google, Cloudflare, Quad9, ...). A local/router address or a recognised public resolver is " +
            "normal - this section is the informational baseline the later DNS checks build on.\n" +
            "\n" +
            "## 2. Connected Router\n" +
            "Identifies your default gateway (the router): its IP, its MAC address and hardware vendor (from " +
            "the OUI), and - when the router answers UPnP - its make, model and firmware. Knowing the " +
            "gateway's real MAC helps you notice if it ever changes unexpectedly. On a Wi-Fi connection it " +
            "also reports the network name (SSID) and the access point you're associated with (BSSID), with " +
            "its signal and channel - so on a mesh of several nodes sharing one SSID you can tell which node " +
            "you're actually on.\n" +
            "\n" +
            "## 3. Actual Upstream DNS Resolver\n" +
            "Looks past the router to the resolver that actually answers out on the public internet, by asking " +
            "a \"whoami\" DNS server which IP reached it. This reveals the true upstream resolver even when " +
            "your router quietly forwards queries, so a resolver you didn't choose stands out.\n" +
            "\n" +
            "## 4. DNS Lookup Tests (public sites)\n" +
            "Resolves a handful of well-known sites (Google, GitHub, Microsoft, Wikipedia, ...) and times each. " +
            "A public site that resolves to a private or loopback address is flagged FAIL - the classic " +
            "signature of DNS hijacking, a captive portal, or local blocking.\n" +
            "\n" +
            "## 5. Cross-Resolver DNS Comparison\n" +
            "Resolves the same sites again through three independent public resolvers (Cloudflare, Quad9, " +
            "Google) and compares their answers with your local result. Agreement is reassuring; a local " +
            "answer that is private or bogus while the references agree points to tampering on your path. " +
            "CDN and geographic differences are expected and labelled as such, not failures.\n" +
            "\n" +
            "## 6. Hosts File\n" +
            "Reads C:\\Windows\\System32\\drivers\\etc\\hosts - the local file that can override DNS for any " +
            "name. Entries that redirect external sites are surfaced, since malware and adware commonly plant " +
            "them here. Use [ Open hosts folder ] to reveal the file in Explorer.\n" +
            "\n" +
            "## 7. E-mail (MX) DNS Tests\n" +
            "Looks up the mail servers (MX records) for Gmail and Yahoo and verifies each designated host both " +
            "belongs to the provider's real mail infrastructure and resolves to a public IP. A mismatch or a " +
            "non-public address can indicate DNS tampering aimed at intercepting mail.\n" +
            "\n" +
            "## 8. Proxy Configuration\n" +
            "Checks every place a proxy can hide - the WinINET per-user settings Chrome uses, a PAC " +
            "auto-config URL, WPAD auto-detect, the HTTP(S)_PROXY environment variables, and what the system " +
            "proxy resolves for a real request. An unexpected proxy can silently route and read all your " +
            "traffic, so a manual proxy is flagged FAIL.\n" +
            "\n" +
            "## 9. Atomic Clock / Time Sync\n" +
            "Compares your PC clock against public NTP time servers. A large skew breaks TLS certificate " +
            "validation (HTTPS may fail or become easier to spoof) and can itself be a sign of tampering, so " +
            "the measured offset is reported and flagged when it drifts too far.\n" +
            "\n" +
            "## 10. Windows Security Features\n" +
            "Confirms the OS defences are on: User Account Control, SmartScreen, Microsoft Defender (or another " +
            "registered antivirus) with its real-time protection and signature age, the firewall profiles, and " +
            "Secure Boot. Anything core that is switched off is flagged.\n" +
            "\n" +
            "## 11. Network Sniffers / Promiscuous Mode\n" +
            "Looks for local packet capture three ways: any adapter whose NDIS packet filter has the " +
            "PROMISCUOUS bit set (the defining trait of a live capture, flagged FAIL), installed capture " +
            "drivers (Npcap / WinPcap / the built-in pktmon), and running capture tools (Wireshark, dumpcap, " +
            "tshark, tcpdump, ...).\n" +
            "\n" +
            "## 12. Network Adapters\n" +
            "A compact table of your network adapters - enabled state, IPv4/IPv6 binding, and any non-standard " +
            "bindings worth noting (capture filters, Zscaler, VPN, virtual switches). Informational only: it " +
            "never changes the verdict, but it's a quick map of what is attached to the network.\n" +
            "\n" +
            "# Status tags\n" +
            "- PASS - the check looks healthy.\n" +
            "- WARN - worth a look; not necessarily a problem.\n" +
            "- FAIL - a strong indicator something is wrong; the overall verdict turns red.\n" +
            "- INFO - context rather than a pass/fail (baseline data such as the adapter list).\n" +
            "\n" +
            "# Special actions\n" +
            "- Run Safety Checks - runs every check; sections render as each one completes.\n" +
            "- Open hosts folder - in the Hosts File section, reveals the hosts file in Explorer.\n" +
            "\n" +
            "# Note\n" +
            "Some DNS sections are skipped with a WARN if a quick probe finds outbound DNS is being dropped " +
            "(an aggressive firewall, a VPN filter, or a captive portal), so the scan returns in seconds " +
            "instead of stalling. Re-run it once connectivity is restored.\n");

        public static readonly HelpInfo Virus = new("Virus Protection",
            "# What this shows\n" +
            "A summary of Microsoft Defender's state and history. The status lines above the table report " +
            "the live protection state, signature (definition) version and age, and the last quick/full " +
            "scan times - read from WMI (MSFT_MpComputerStatus). The table below is a merged timeline of " +
            "threats Defender found and scans it ran, read from the Defender Operational event log.\n" +
            "\n" +
            "# Status lines\n" +
            "- Antivirus / Real-time protection - the core on/off state; either being OFF turns the tab red.\n" +
            "- Behavior monitoring / Tamper protection / Cloud-delivered protection - extra defences; off is " +
            "flagged yellow.\n" +
            "- Signatures - definition version and how many days old; older than 7 days is flagged yellow.\n" +
            "- Last quick / full scan - when each last finished; a quick scan older than 14 days is flagged.\n" +
            "\n" +
            "# The table\n" +
            "One row per Defender event, newest first. The Type column (filterable) is either:\n" +
            "- Threat - something Defender detected. Event 1116 = detected, 1117 = remediated, 1118 = " +
            "remediation FAILED (red). The Name is the threat, Detail is the action and file path.\n" +
            "- Scan - a scan Defender ran. 1001 = completed, 1005 = failed (yellow), 1002 = canceled, " +
            "1000 = started.\n" +
            "\n" +
            "# Scan Cancelled\n" +
            "Is a common system action when one of the following occurs:\n" +
            "- Laptop unplugged or power low\n" +
            "- Scan only when idle and system becomes busy.\n" +
            "- Signature database updates\n" +
            "\n" +
            "# Administrator\n" +
            "The protection-status lines read without elevation, but the Defender Operational event log " +
            "(the threat/scan table) is readable only by an administrator. Without elevation the status " +
            "lines still appear and the table is empty - use the left-panel \"Run as Admin\" to see history.\n" +
            "\n" +
            "# Special actions\n" +
            "- Windows Security - opens the Windows Security app (to run a scan or change settings).\n" +
            "- Right-click a threat row - copy its name or path, open the file location, or search the web " +
            "for the threat name.\n" +
            "\n" + Common);

        public static readonly HelpInfo EnvList = new("Environment Variables",
            "# What this tab shows\n" +
            "Inspects system (Machine) and per-user (User) environment variables and highlights common " +
            "security and hygiene issues. Variables containing ';' are split so each semicolon-separated " +
            "part appears as its own row in the Value column for precise inspection.\n" +
            "\n" +
            "# Status codes\n" +
            "- Urgent - a machine PATH entry is writable by non-administrative principals (e.g. Everyone, " +
            "  BUILTIN\\Users, Authenticated Users) with Write/Modify/FullControl rights. This is a high-risk " +
            "  privilege escalation / persistence vector because an unprivileged user can place an executable or DLL " +
            "  into that directory and it may be loaded by higher-privilege processes. Fix urgently by removing " +
            "  the writable principal or tightening the folder ACL.\n" +
            "- Review - core system variables (ComSpec, windir/SystemRoot) or their targets look altered, or the " +
            "  path includes unusual storage locations such as AppData\\Local\\Temp or C:\\Users\\Public. These can be " +
            "  indicators of tampering or persistence. Confirm the intended value and restore defaults if necessary.\n" +
            "- Clean - a value part points to a non-existent directory (dead PATH entry). Removing these entries reduces " +
            "  ambiguity and avoids accidental execution of wrong binaries.\n" +
            "- OK - no immediate problems detected for this value part.\n" +
            "\n" +
            "# Columns and meanings\n" +
            "- Name - the environment variable name (e.g. PATH, ComSpec).\n" +
            "- Scope - Machine or User. Machine-scope PATH entries are globally visible and higher-risk if writable.\n" +
            "- Value - the individual semicolon-delimited part (or the whole value when not delimited). Checks are run per-value.\n" +
            "- Invalid / User-writable / Core altered / Length risk - quick flags summarising the heuristics.\n" +
            "- Recommendation - concise remediation advice (e.g. remove dead entry, tighten ACLs, restore ComSpec).\n" +
            "\n" +
            "# Heuristics used\n" +
            "- PATH parsing: PATH and Path-like variables are split on ';' and each entry is validated as a directory.\n" +
            "- Directory existence: non-existent entries are flagged as Clean (remove them).\n" +
            "- ACL inspection (Machine PATH only): checks whether broad non-admin principals have Allow rights that include " +
            "  Write/Modify/FullControl and flags Urgent when found. ACL reads are best-effort and may require Administrator rights.\n" +
            "- Core variables: ComSpec must point to cmd.exe and windir/SystemRoot should match the Windows folder; deviations are flagged Review.\n" +
            "- Unusual storage: entries under AppData\\Local\\Temp or C:\\Users\\Public are flagged Review as common persistence targets.\n" +
            "- Length risk: PATH string longer than ~2048 characters is warned as legacy tools may truncate it.\n" +
            "- Author inference: the inspector attempts to read an executable's Company/Product metadata in each folder to suggest the likely owner of the entry. This is a hint only.\n" +
            "\n" +
            "# Notes and actions\n" +
            "- The Manage env button opens the standard Environment Variables dialog so you can edit values.\n" +
            "- ACL checks are heuristic and conservative: if you see Urgent, treat it as high priority to investigate, even if the environment is a managed or shared machine.\n" +
            "- If a Value row is flagged Clean (dead), remove that specific part from the variable rather than deleting the whole variable.\n" +
            "- For domain-joined machines or Azure AD scenarios, authoritative owner info (who set a variable) often requires central logs or AD/Graph queries and is out of scope for this tab.\n" +
            "\n" + Common);

        public static readonly HelpInfo Patches = new("Windows Patches",
            "# What this shows\n" +
            "Installed Windows updates and hotfixes reported by WMI (Win32_QuickFixEngineering), newest first. " +
            "Read it two ways: that updates are arriving on a routine cadence (the sign of a healthy, " +
            "maintained system), and - just as useful - the date of the most recent few updates.\n" +
            "\n" +
            "# Use the latest patch date as a baseline\n" +
            "Each Windows update rewrites a batch of system files, so the date of the newest patch is a natural " +
            "\"known-good\" reference point: most of what changed on disk around then changed because Windows " +
            "updated it.\n" +
            "\n" +
            "Note the date of the last few patches, then visit the inventory tabs - Processes, Services, " +
            "Startup, Scheduled, Installed, Devices, Win Extn, Root CAs - which each list items together with " +
            "when they last changed. A program or component that changed NEWER than the latest patch, and that " +
            "you didn't install or update yourself, merits a closer look: it changed outside the normal Windows " +
            "update window.\n" +
            "\n" +
            "Those tabs already highlight recent changes (red = last 7 days, yellow = last 30 days), so sorting " +
            "a tab by its date column floats anything newer than your patch baseline to the top.\n" +
            "\n" +
            "# Columns\n" +
            "- Installed - date the update was applied.\n" +
            "- HotFix ID - the KB identifier.\n" +
            "- Lookup    - click to open a web search for that KB. Windows' own per-update link (WMI " +
            "Caption) is often missing or points only at the support home page, so a search is used " +
            "instead because it reliably lands on a description of the update.\n" +
            "\n" +
            "# Right-click a row\n" +
            "- Search the web for this update - the same reliable web search as the Lookup column.\n" +
            "- Open Microsoft Update Catalog - the authoritative catalog listing for the KB.\n" +
            "- Open Microsoft support article - the support.microsoft.com KB page (when one exists).\n" +
            "- Show details - a local, offline summary read from WMI: type, install date and age, who " +
            "installed it, and any comments - a fallback when you have no network or the online pages are " +
            "unhelpful.\n" +
            "- Copy HotFix ID - copies the KB id to the clipboard.\n" +
            "\n" +
            "# Note\n" +
            "This list covers servicing updates that carry a KB number (cumulative and security updates, " +
            "hotfixes). Some changes - feature updates, driver and Microsoft Store app updates - don't appear " +
            "as KB rows here; the Installed, Devices and Activity tabs cover those.\n" +
            "\n" + Common);

        public static readonly HelpInfo Dns = new("DNS (Domain Name System) Cache",
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
            "# Type\n" +
            "  A = IPv4 address; AAAA = IPv6; CNAME = canonical name (alias to another name); other types are rare.\n" +
            "# Special actions\n" +
            "- Flush DNS cache - clears the resolver cache, then reloads the (now-empty) view.\n" +
            "- Right-click a row to copy the name or the answer.\n" +
            "\n" + Common);

        public static readonly HelpInfo Arp = new("ARP (Address Resolution Protocol) Neighbor Cache",
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
            "# The blue links\n" +
            "> The blue links give you quick access to Chrome's matching feature or settings page. If your " +
            "browser has more than one user profile, Chrome opens its profile selector first; the exact page " +
            "address is also copied to your clipboard, so after you pick a profile you can paste it into the " +
            "address bar to jump straight there.\n" +
            ">\n" +
            "> Steps:\n" +
            "> 1. Click the blue link.\n" +
            "> 2. Select your Chrome profile.\n" +
            "> 3. Click in Chrome's address (URL) bar.\n" +
            "> 4. Press Ctrl+V to paste the copied link.\n" +
            "> 5. Press Enter.\n" +
            "\n" +
            "# Special actions\n" +
            "- Remove unsupported - after confirmation, deletes the folders of all Manifest V2 " +
            "(Unsupported) extensions. It first backs up ALL extensions to " +
            "Downloads\\b4browse-extension-backup.zip; close Chrome first for a clean removal.\n" +
            "- Scan (header) - verify chrome.exe's signature or look it up on VirusTotal.\n" +
            "- Right-click a row to open the extension's folder or copy its path.\n" +
            "\n" + Common);

        public static readonly HelpInfo Settings = new("Chrome Settings",
            "# What this shows\n" +
            "A matrix of Chrome settings: one row per setting, one column per Chrome profile (by its " +
            "friendly name), plus a 'Global' column for settings enforced by enterprise policy. It reads " +
            "each profile's Preferences and Secure Preferences files, the Chrome policy registry, the " +
            "extension folders, and - for the saved-password count only - the Login Data database. " +
            "Configuration only: no password values, URLs, or other sensitive data are ever read.\n" +
            "\n" +
            "# Values\n" +
            "Chrome stores a setting only when you change it from its default, so each cell is one of:\n" +
            "- an explicit value - On / Off / Allowed / Blocked / a number, etc.\n" +
            "- Default - the setting is unchanged from Chrome's built-in default.\n" +
            "- a dash - that column has no value for the row (e.g. most rows in the policy-only Global " +
            "column, which is sparse by design).\n" +
            "\n" +
            "# Colour\n" +
            "Known-weak values are highlighted and roll into the tab's colour: Safe Browsing OFF is red; " +
            "allowed third-party cookies, permissive site defaults (notifications / location / camera / " +
            "microphone / pop-ups / automatic downloads set to Allow), and enabled ad-tracking (Privacy " +
            "Sandbox) are yellow. Only explicit risky values are flagged - 'Default' is never coloured.\n" +
            "\n" +
            "# Right-click a setting\n" +
            "- Explain - opens a description of what every setting does, scrolled to the one you clicked.\n" +
            "- Search the web - opens an online search for that setting.\n" +
            "- Open settings file - per Chrome profile, opens that profile's Preferences or Secure " +
            "Preferences JSON (in Notepad - they have no file extension), opens the folder, or copies its " +
            "path. These JSON files are where Chrome stores the values shown in this matrix.\n" +
            "\n" +
            "# Notes\n" +
            "- The last column, 'Open in Chrome', is the chrome:// page where that setting lives. Click it " +
            "to launch Chrome there; the URL is also copied to the clipboard, so if Chrome opens its profile " +
            "picker instead of navigating, just paste (Ctrl+V) into the address bar.\n" +
            "- The saved-password count is a count only - the Login Data database is copied to a temp file " +
            "and the rows are counted; no password is read or decrypted.\n" +
            "- Columns are fixed when the tab opens. A Chrome profile created while B4-Browse is running " +
            "won't get its own column until you restart the app (Refresh reloads values, not columns).\n" +
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

        public static readonly HelpInfo Scheduled = new("Scheduled Tasks",
            "# What this shows\n" +
            "Windows Task Scheduler entries. Scheduled tasks are a top program-persistence mechanism " +
            "(alongside services and Run keys), so risky and recently-created tasks float to the top.\n" +
            "\n" +
            "# Status (the audit)\n" +
            "- Alert (red) - the task runs a program from a temp/download folder, or a living-off-the-land " +
            "binary (powershell, mshta, rundll32, ...) with arguments.\n" +
            "- Review (yellow) - runs from AppData/ProgramData, a LOLBin without arguments, or a hidden task " +
            "whose program sits outside Program Files / Windows.\n" +
            "- OK - nothing notable.\n" +
            "\n" +
            "# Columns\n" +
            "- Created - task registration date (also drives the recency colour).\n" +
            "- Last run / Next run - from Get-ScheduledTaskInfo; '—' when never run or no future trigger.\n" +
            "- Repeat - the trigger's repeat period: minutes (5M), hours (6H / 6.2H) or days (7D / 1.5D). " +
            "'—' for weekly/monthly/event/logon/boot triggers, which have no simple period.\n" +
            "- Run as - the principal the task runs under (SYSTEM is more powerful than a user).\n" +
            "- Program - the first executable action and its arguments.\n" +
            "- Path - the task folder; \\Microsoft\\Windows\\... are Windows' own built-in tasks.\n" +
            "\n" + Recency +
            "\n" +
            "# Filters\n" +
            "- All - off by default hides Windows' own built-in tasks (\\Microsoft\\Windows\\) that are not " +
            "flagged; turn it on to list every task.\n" +
            "\n" +
            "# Special actions\n" +
            "- Open Task Scheduler - launches taskschd.msc.\n" +
            "- Scan (per row) - verify the program's signature or look it up on VirusTotal by SHA-256.\n" +
            "- Right-click a row to open the file location, copy the task name/program, or open Task Scheduler.\n" +
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
            "- Last run - the last time this program's executable was launched, from the Windows PCA " +
            "launch log (appcompat\\pca). Matched by executable path (the program's exe, or any exe under " +
            "its install folder), so it is blank when there is no match - the log only records " +
            "interactive launches, and many components/redistributables never appear in it.\n" +
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

        public static readonly HelpInfo Awake = new("Power Events",
            "# What this shows\n" +
            "Every power-state transition from the System event log - boot, resume-from-sleep, sleep, " +
            "hibernate, shutdown, and unexpected power loss - one row per event, newest first. This is a " +
            "verbatim 1:1 list of what the OS logged (no pairing, no smoothing), so the timeline always " +
            "matches the log. Reading the System log needs no administrator rights.\n" +
            "\n" +
            "# Columns\n" +
            "- Status - 'Review' for an unexpected power loss/shutdown, otherwise 'OK'.\n" +
            "- # - the event's number (1 = oldest in the window).\n" +
            "- Date / time - when the event was logged.\n" +
            "- Action - Boot, Wake, Wake (exit standby), Sleep, Sleep (modern standby), Hibernate, " +
            "Shutdown, Unexpected shutdown, or Unexpected power loss.\n" +
            "- Detail - for a wake, the wake source: a power button / lid / input device (User), a " +
            "scheduled task such as Windows Update or defrag (Scheduler), a Wake-on-LAN packet (Network), " +
            "or Unknown. For an initiated shutdown, the reason.\n" +
            "- Power - the charging state captured in the event: 'AC 100%' (plugged in) or 'Batt 87%' " +
            "(on battery). Only the Modern Standby sleep/wake events (506/507) record this, so it is " +
            "blank for classic sleep, resume, boot and shutdown rows.\n" +
            "- Gap - time since the previous event, i.e. how long the machine spent in the prior state.\n" +
            "- Event ID - the raw System-log event id (1, 42, 107, 506/507, 12/13, 41, 6008 ...) for " +
            "correlating against Event Viewer or the power-events.ps1 helper script.\n" +
            "\n" +
            "# What can wake this PC (header)\n" +
            "Above the table is a summary of what is allowed to wake the machine, each with a link to " +
            "adjust it:\n" +
            "- Wake-armed devices - hardware currently permitted to wake the PC (mouse, keyboard, network " +
            "adapter, USB hubs). Open Device Manager, then a device's Power Management tab to toggle " +
            "'Allow this device to wake the computer'.\n" +
            "- Wake timers - scheduled tasks set to wake the PC (e.g. Windows Update, maintenance). Listing " +
            "the active timers needs administrator; Task Scheduler shows which tasks have 'Wake the computer " +
            "to run this task' set.\n" +
            "- Power & sleep - the Power Options control panel: sleep timeout, 'Allow wake timers', and the " +
            "power-button / lid behaviour.\n" +
            "\n" +
            "# Status colours\n" +
            "- Yellow - an unexpected power loss / dirty shutdown (Kernel-Power 41 or EventLog 6008), " +
            "such as a long power-button hold or a power cut - it leaves no clean sleep/shutdown record.\n" +
            "\n" +
            "# Modern Standby (S0) laptops\n" +
            "Most current laptops sleep via Modern Standby (connected standby) rather than classic S3 " +
            "sleep, recorded as Kernel-Power 506 (enter) / 507 (exit). These can fire many times an hour " +
            "- sometimes within the same second - so an overnight standby shows as many rows, not one. " +
            "That is intentional: the Gap column makes the churn obvious (tiny gaps = standby bounce), and " +
            "nothing is dropped. A real sleep you initiated is the 506 with a long Gap before the next wake.\n" +
            "\n" +
            "# Note\n" +
            "Covers the last 14 days. Hibernate is detected best-effort from the event 42 target state and " +
            "may appear as Sleep on some hardware. Wake-source/task text comes straight from the " +
            "Power-Troubleshooter event.\n" +
            "\n" +
            "# Special actions\n" +
            "- Event Viewer - opens the Windows Event Viewer to inspect the underlying power events.\n" +
            "- Filter the 'Action', 'Detail', or 'Event ID' column.\n" +
            "\n" + Common);

        public static readonly HelpInfo Activity = new("App Launch Activity",
            "# What this shows\n" +
            "How often each app has been launched on this machine, read from Windows Search's app-usage " +
            "index (the AppsIndex.db SQLite database Windows uses to rank Start-menu and search results). " +
            "It surfaces what runs here and how heavily - an unfamiliar program with a high launch count, " +
            "or one started from an unexpected location, is worth a look. Reading the index needs no " +
            "administrator rights.\n" +
            "\n" +
            "# Columns\n" +
            "- Launches - the recorded launch count (default sort, highest first).\n" +
            "- When - the last time the app's executable ran, merged in by path from the Program " +
            "Compatibility Assistant log (C:\\Windows\\appcompat\\pca\\PcaAppLaunchDic.txt). That log " +
            "lives under C:\\Windows and needs administrator rights, so When is blank ('—') when the app " +
            "is not run elevated, and for apps with no path to match (most packaged apps).\n" +
            "- Type - Win32 (desktop / legacy app) or Packaged (Store / MSIX / UWP).\n" +
            "- Rank - Windows Search's internal relevance rank for the tile (lower = more prominent).\n" +
            "- App ID / path - the executable path when known (Known-Folder GUIDs are expanded), otherwise " +
            "the raw app identifier (e.g. an AUMID for packaged apps).\n" +
            "\n" +
            "# Status\n" +
            "- Review - the launched executable lives in a transient folder (Temp / Downloads), where " +
            "legitimate installed software does not normally run from - verify it is expected.\n" +
            "- OK     - nothing unusual.\n" +
            "\n" +
            "# Note\n" +
            "The app index itself stores no timestamps - it is a frequency view. The When column is the " +
            "only last-run signal, merged in from the separate PCA log (admin only). The database is copied " +
            "to a temp file before reading, so Windows Search is never locked or modified. If AppsIndex.db " +
            "is absent (older Windows builds) the tab is empty.\n" +
            "\n" +
            "# Last-run source (PCA log)\n" +
            "The 'When' column comes from the Program Compatibility Assistant log:\n" +
            "    C:\\Windows\\appcompat\\pca\\PcaAppLaunchDic.txt\n" +
            "An executable that the app-usage index never tracked but the PCA log has a last-run time for is " +
            "still listed as its own row (launch count 1; Type / Rank show '--').\n" +
            "\n" +
            "The log can be cleared by first stopping the service, then deleting the file:\n" +
            "    net stop PcaSvc\n" +
            "    del C:\\Windows\\appcompat\\pca\\PcaAppLaunchDic.txt\n" +
            "\n" +
            "PCA last-run tracking can be permanently disabled with:\n" +
            "    sc config PcaSvc start= disabled\n" +
            "    net stop PcaSvc\n" +
            "These commands need an elevated (Administrator) command prompt.\n" +
            "\n" +
            "# Special actions\n" +
            "- Right-click a row to open the file location, copy the name / app ID / launch count, or search " +
            "the web for the app.\n" +
            "\n" + Common);

        public static readonly HelpInfo Downloads = new("App Network Usage (Downloads)",
            "# What this shows\n" +
            "How many bytes each application has received (downloaded) and sent (uploaded), read from " +
            "Windows' System Resource Usage Monitor (SRUM). Windows logs, per process and roughly hourly, " +
            "the network bytes each app moved; this tab sums those intervals per application over SRUM's " +
            "retention window (about 30-60 days). It answers \"what has been pulling data down, and what " +
            "has been sending it out\" - a high Uploaded total from an unexpected process is a possible " +
            "data-exfiltration signal.\n" +
            "\n" +
            "# Requires administrator\n" +
            "The SRUM database (C:\\Windows\\System32\\sru\\SRUDB.dat) lives under System32 and is held open " +
            "by the Diagnostic Policy Service, so this tab is empty unless B4-Browse is run as " +
            "administrator. The live database is never touched: it is snapshotted to a temp copy with " +
            "esentutl, the throwaway copy is repaired if it was in a dirty-shutdown state, and only that " +
            "copy is read.\n" +
            "\n" +
            "# Columns\n" +
            "- Downloaded - bytes the app received (default sort, largest first).\n" +
            "- Uploaded - bytes the app sent.\n" +
            "- Last seen - the newest interval recorded for the app.\n" +
            "- App name / App path - the executable, resolved from SRUM's id-map (sometimes a service tag " +
            "or SID for system rows).\n" +
            "\n" +
            "# Status\n" +
            "- Review - the app runs from a transient folder (Temp / Downloads), where installed software " +
            "does not normally live, and has network activity - verify it is expected.\n" +
            "- OK     - nothing unusual.\n" +
            "\n" +
            "# Note\n" +
            "Totals are cumulative over SRUM's window, not a live rate. If SRUDB.dat is absent (SRUM " +
            "disabled) or esentutl is unavailable the tab is empty, with the reason shown in the header.\n" +
            "\n" +
            "# Special actions\n" +
            "- Right-click a row to open the file location, copy the name / path / usage, or search the web " +
            "for the app.\n" +
            "\n" + Common);

        public static readonly HelpInfo RootCerts = new("Trusted Root Certification Authorities",
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

        public static readonly HelpInfo Users = new("User Accounts",
            "# What this shows\n" +
            "Every local user account on this PC (from Get-LocalUser), with the signals that matter for " +
            "spotting a rogue or forgotten account: when it was created, when it last signed in, whether " +
            "it is an administrator, hidden from the sign-in screen, has no password requirement, or has " +
            "expired but is still enabled. Reading the account list needs no administrator rights.\n" +
            "\n" +
            "# Why it matters (security)\n" +
            "A hidden or unexpected local account - especially one with administrator rights - is a classic " +
            "persistence / backdoor mechanism. Sort by Status to float flagged accounts to the top, and " +
            "correlate a recently-created account against the Patches tab date: an account that appeared " +
            "outside a Windows update window, and that you didn't create, is worth a close look.\n" +
            "\n" +
            "# Status (the audit)\n" +
            "- Alert (red) - the built-in Administrator or Guest account is enabled; an enabled account " +
            "hidden from the sign-in screen; or a non-built-in account created in the last 7 days.\n" +
            "- Review (yellow) - created in the last 30 days; expired but still enabled; no password " +
            "required; or an account that has never signed in and whose creation date can't be determined " +
            "(the dormant-backdoor pattern).\n" +
            "- OK - nothing notable.\n" +
            "\n" +
            "# The 'Created' column is best-effort\n" +
            "Windows does not expose a reliable account-creation timestamp through any normal interface, so " +
            "this column is layered and the 'Created src' column tells you which source each row used:\n" +
            "- audit log - the true creation time from Security event 4720 (only when running as " +
            "administrator and the event is still in the log).\n" +
            "- ≈first logon - the user profile folder's creation date, used as a proxy. This is when the " +
            "account first signed in and got a profile, which is shortly AFTER it was created - not the " +
            "creation time itself, and blank for an account that has never signed in.\n" +
            "- a dash - no creation date could be determined.\n" +
            "Run the app as administrator to upgrade approximate dates to true ones from the audit log.\n" +
            "\n" + Recency +
            "\n" +
            "# Columns\n" +
            "- Enabled - whether the account can sign in (disabled accounts are greyed).\n" +
            "- Admin - a member of the local Administrators group.\n" +
            "- Last logon - the last interactive sign-in recorded for the account, or 'never'.\n" +
            "- Expires - the account expiry date, or 'never'.\n" +
            "- Source - Local, MicrosoftAccount, or AzureAD (from Get-LocalUser's PrincipalSource).\n" +
            "- Profile path - the account's user-profile root directory (typically C:\\Users\\<name>), read " +
            "from the registry. A dash means the account has never signed in, so no profile folder exists yet.\n" +
            "- Note - why the row is flagged.\n" +
            "\n" +
            "# Special actions\n" +
            "- Right-click a row to copy the account name, SID or profile path, open the profile folder in " +
            "Explorer, open User Accounts (netplwiz) or Local Users & Groups (lusrmgr.msc), or search the " +
            "web for the account name.\n" +
            "\n" +
            "# Note\n" +
            "This lists local SAM accounts only. Domain and Azure AD accounts that have signed in appear as " +
            "profiles but not as local accounts; the header notes how many such profiles exist. " +
            "lusrmgr.msc is not present on Windows Home editions - use netplwiz there.\n" +
            "\n" + Common);

        public static readonly HelpInfo History = new("Run History",
            "# What this shows\n" +
            "A table of system counts captured each time B4-Browse runs. Each row is one snapshot; " +
            "the newest is at the top. If the app runs more than once on the same day the earlier " +
            "reading for that day is replaced, so you get at most one row per day.\n" +
            "\n" +
            "Up to 100 snapshots are kept. The data is stored in:\n" +
            "    %LOCALAPPDATA%\\B4Browse\\history.json\n" +
            "\n" +
            "# Columns\n" +
            "- Date/time   - when the snapshot was taken.\n" +
            "- AD Local    - folders in %LOCALAPPDATA%.\n" +
            "- AD Roaming  - folders in %APPDATA% (Roaming).\n" +
            "- AD Low      - folders in LocalLow.\n" +
            "- Services    - non-disabled Windows services.\n" +
            "- Installed   - programs in the Add/Remove registry keys.\n" +
            "- Startup     - enabled startup entries (Run keys + startup folders).\n" +
            "- Root CAs    - trusted root certificates in the machine store.\n" +
            "- Scheduled   - registered scheduled tasks.\n" +
            "- Shell Ext   - entries in the Approved shell-extensions registry key.\n" +
            "- Chrome Ext  - Chrome extensions across all profiles.\n" +
            "- Users       - local user profiles (S-1-5-21-* SIDs in ProfileList).\n" +
            "- Restores    - VSS shadow copies (restore points).\n" +
            "- Devices     - PnP signed device drivers (WMI; may be slow).\n" +
            "- Firewall    - firewall rules in the registry.\n" +
            "\n" +
            "# Trend colours\n" +
            "A cell is highlighted when its count changed from the previous snapshot:\n" +
            "- Yellow - count increased (something was added).\n" +
            "- Blue   - count decreased (something was removed).\n" +
            "The first row has no previous snapshot to compare against, so it is never coloured.\n" +
            "\n" +
            "# What to look for\n" +
            "- A sudden jump in Installed, Startup, Scheduled, Shell Ext, or Firewall between two " +
            "snapshots you did not expect is worth investigating on the corresponding tab.\n" +
            "- A drop in Restores is a red flag — legitimate software rarely deletes restore points.\n" +
            "- A new Users entry (count up by 1) may indicate an account was created without your knowledge.\n" +
            "\n" +
            "# Note\n" +
            "Counts are lightweight readings optimised for speed, so they may differ slightly from the " +
            "full grid tabs (which apply additional filtering). Their purpose is consistent trend tracking, " +
            "not an exact match to the tab totals. A '—' means the count could not be read on that run.\n" +
            "\n" + Common);

        public static readonly HelpInfo AppData = new("AppData Folders",
            "# What this shows\n" +
            "The immediate sub-folders of the three AppData roots on this machine:\n" +
            "- Local      (%LOCALAPPDATA%)     — per-user, machine-specific app data\n" +
            "- Roaming    (%APPDATA%)           — per-user, syncs across machines when roaming profiles are used\n" +
            "- LocalLow   (%LOCALAPPDATA%\\..\\LocalLow) — low-integrity sandbox data (browsers, etc.)\n" +
            "\n" +
            "Only the top level (one folder deep) is scanned. The default view shows folders created in the " +
            "last 30 days; use the All toggle to see every folder.\n" +
            "\n" +
            "# Why this matters\n" +
            "AppData is writable by any process running as the current user — no elevation needed. It is therefore " +
            "a primary persistence location for malware, PUPs, browser hijackers, and rogue updaters. A folder " +
            "dropped here without a corresponding installer entry is the signal worth reviewing, especially when " +
            "it appeared recently.\n" +
            "\n" +
            "# Columns\n" +
            "- Status   - recency tint (Recent = last 7 days, Month = last 30 days) combined with the Known flag.\n" +
            "- Created  - file-system creation timestamp of the folder.\n" +
            "- Root     - which AppData tree the folder is in (Local / Roaming / LocalLow).\n" +
            "- Folder   - the folder name.\n" +
            "- Known    - Yes when the folder matches an entry in the Installed programs list or is a well-known " +
            "Windows/runtime name; No otherwise.\n" +
            "- Matched program - the installer display name that best matches this folder, when Known = Yes.\n" +
            "- Path     - full path to the folder.\n" +
            "\n" +
            "# Status colours\n" +
            Recency +
            "Unknown folders (Known = No) created within the last 30 days are highlighted yellow as Caution.\n" +
            "\n" +
            "# What to look for\n" +
            "- A Caution row (yellow, Known = No, recent) — cross-check the folder name against your own " +
            "installs; if you do not recognise it, inspect the contents.\n" +
            "- A very recently created folder (red / last 7 days) with no installer match is the highest-priority signal.\n" +
            "- A Known = No folder that is old (> 30 days) may be a leftover from an uninstalled program " +
            "that didn't clean up after itself — lower priority but worth noting.\n" +
            "\n" +
            "# Limitations\n" +
            "The 'Known' cross-reference matches folder names against installer display names heuristically " +
            "(full name, first word, install-location segment). It will miss some legitimate programs " +
            "whose folder name bears no resemblance to the installer name, and may occasionally match " +
            "incorrectly on short or generic names. Use it as a triage signal, not a verdict.\n" +
            "\n" +
            "# Special actions\n" +
            "- Right-click a row to open the folder in Explorer, copy the path, or search the web for the folder name.\n" +
            "\n" + Common);

        public static readonly HelpInfo Links = new("Tools & Links",
            "# What this shows\n" +
            "A page of curated links to security tools and references (Chrome Safety Check, Windows Security, " +
            "VirusTotal, the Chrome extensions guide, and more).\n" +
            "\n" +
            "# Special actions\n" +
            "- Click any link to open it in your default browser.\n");
    }
}
