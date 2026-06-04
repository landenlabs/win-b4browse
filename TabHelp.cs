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

        public static readonly HelpInfo Chrome = new("Chrome Extensions",
            "# What this shows\n" +
            "Enabled Chrome extensions across your profiles. The header summarises the detected chrome.exe.\n" +
            "\n" +
            "# Status\n" +
            "- Unsupported - a Manifest V2 (MV2) extension, which Chrome 138+ no longer supports.\n" +
            "- The Modified column is also tinted by recency.\n" +
            "\n" + Recency +
            "\n" +
            "# Special actions\n" +
            "- Scan (header) - verify chrome.exe's signature or look it up on VirusTotal.\n" +
            "- Right-click a row to open the extension's folder or copy its path.\n" +
            "\n" + Common);

        public static readonly HelpInfo Services = new("Windows Services",
            "# What this shows\n" +
            "Installed services, with status driven by the modify date of each service's executable.\n" +
            "\n" + Recency +
            "\n" +
            "# Special actions\n" +
            "- Show All - off by default to hide the noise of old C:\\Windows\\system32 services; turn it on " +
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
            "- Show all - off by default to surface only the items worth a look: non-Windows executables with " +
            "an Old status. Turn it on to list every process.\n" +
            "- Task Manager - opens taskmgr.exe.\n" +
            "- Scan (per row) - verify the executable's signature or look it up on VirusTotal by SHA-256.\n" +
            "- Right-click a row to open its file location, copy the path, or search the web for it.\n" +
            "\n" + Common);

        public static readonly HelpInfo Startup = new("Startup Apps",
            "# What this shows\n" +
            "Programs configured to launch at startup. Status is the newer of two dates.\n" +
            "\n" +
            "# Columns\n" +
            "- Registry added - when the Run-key entry last changed (the key is shared, so this is approximate).\n" +
            "- Exe modified   - modify date of the target executable.\n" +
            "\n" + Recency +
            "\n" +
            "# Special actions\n" +
            "- Scan (per row) - verify the executable's signature or look it up on VirusTotal.\n" +
            "- Right-click a row to open its file location, manage startup apps in Settings, or open Task Manager.\n" +
            "\n" + Common);

        public static readonly HelpInfo Installed = new("Installed Programs",
            "# What this shows\n" +
            "Programs registered as installed (from the uninstall registry), with status driven by install date.\n" +
            "\n" + Recency +
            "\n" +
            "# Special actions\n" +
            "- Apps & features... - opens the Windows Settings page.\n" +
            "- Scan (per row) - verify the program's executable signature or look it up on VirusTotal.\n" +
            "- Right-click a row for actions (open location, copy path, search the web).\n" +
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

        public static readonly HelpInfo Firewall = new("Windows Firewall",
            "# What this shows\n" +
            "A summary of the Windows Defender Firewall state read from the registry:\n" +
            "- whether the firewall is enabled,\n" +
            "- the number of local firewall rules,\n" +
            "- when the rule/policy store last changed.\n" +
            "\n" +
            "When the firewall is managed by another product (e.g. an EDR agent) the local rule store can be " +
            "empty; the last-changed date considers the policy and profile keys too.\n" +
            "\n" +
            "# Special actions\n" +
            "- Manage Firewall - opens Windows Defender Firewall with Advanced Security (wf.msc).\n");

        public static readonly HelpInfo Links = new("Helpful Links",
            "# What this shows\n" +
            "A page of curated links to security tools and references (Chrome Safety Check, Windows Security, " +
            "VirusTotal, the Chrome extensions guide, and more).\n" +
            "\n" +
            "# Special actions\n" +
            "- Click any link to open it in your default browser.\n");
    }
}
