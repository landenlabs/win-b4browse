// Copyright (c) 2026 LanDen Labs - Dennis Lang

using System;
using System.Collections.Generic;
using System.Linq;
using System.Windows.Forms;

namespace B4Browse
{
    /// <summary>
    /// The single declarative registry of everything the app surfaces: each <see cref="Section"/>
    /// names its category, its display/report titles, its headless report producers, and its GUI
    /// view factory. This is the one place to add a feature - a new row appears automatically in
    /// the tree navigation (<see cref="MainForm"/>), the headless <c>--run</c> scopes and the
    /// "all" report (<see cref="Reports"/>), the per-tab severity roll-up, and email/copy/print.
    ///
    /// Adding a browser, for example, is purely additive: register the per-browser sections here
    /// (a Build* view + Check* producers) under the "Browser" category - no edits to MainForm or
    /// Reports are required.
    /// </summary>
    public static class Catalog
    {
        /// <summary>One navigable area: a GUI view and/or a set of headless report producers.</summary>
        public sealed class Section
        {
            public string Category = "";
            public string Title = "";                 // nav label
            public string Key = "";                   // scope (headless --run key)
            public string Banner = "";                // banner caption (defaults to Title)
            public string ReportTitle = "";           // headless section header (defaults to Title)
            public bool AdminOnly = false;            // GUI: only shown when elevated
            public Func<CheckGroup>[] Producers = Array.Empty<Func<CheckGroup>>();  // empty => GUI-only
            public Func<Control>? BuildView = null;   // GUI factory; null => headless-only

            public string BannerOrTitle => Banner.Length > 0 ? Banner : Title;
            public string ReportTitleOrTitle => ReportTitle.Length > 0 ? ReportTitle : Title;
            public bool HasReport => Producers.Length > 0;
        }

        /// <summary>Category display order for the tree navigation.</summary>
        public static readonly string[] Categories =
        {
            "Network path", "Recent changes", "Accounts & usage", "Protection", "Browser", "Tools",
        };

        /// <summary>The Safety Scan's labelled steps - shared by the GUI ResultsView and the
        /// headless producer list (so the scan is defined once).</summary>
        private static readonly (string Label, Func<CheckGroup> Run)[] ScanSteps =
        {
            ("current DNS servers", SafetyChecks.CheckDnsServers),
            ("connected router",    SafetyChecks.CheckRouter),
            ("upstream resolver",   SafetyChecks.CheckUpstreamResolver),
            ("DNS lookups",         SafetyChecks.CheckDnsLookups),
            ("cross-resolver DNS",  SafetyChecks.CheckCrossResolver),
            ("hosts file",          SafetyChecks.CheckHostsFile),
            ("e-mail (MX) DNS",     SafetyChecks.CheckEmailDns),
            ("proxy configuration", SafetyChecks.CheckProxy),
            ("atomic time sync",    SafetyChecks.CheckTimeSync),
            ("Windows security",    SafetyChecks.CheckWindowsSecurity),
            ("network sniffers",    SafetyChecks.CheckPromiscuousMode),
            ("network adapters",    SafetyChecks.CheckNetworkAdapters),
        };

        /// <summary>Builds the Safety Scan's ResultsView (incremental, labelled steps).</summary>
        public static Control BuildScanView() =>
            new ResultsView("Run Safety Checks", "Click to scan.", ScanSteps, reportVerdict: true,
                help: TabHelp.Scan, requiresNetwork: true);

        /// <summary>Every section, in display + report order. Grouped by category.</summary>
        public static readonly Section[] Sections =
        {
            // -- Network path --
            new() { Category = "Network path", Title = "Safety Scan", Key = "scan",
                    Banner = "Local network configuration", ReportTitle = "Safety Scan",
                    Producers = ScanSteps.Select(s => s.Run).ToArray(), BuildView = BuildScanView },
            new() { Category = "Network path", Title = "DNS", Key = "dns",
                    Banner = "DNS resolver cache", ReportTitle = "DNS Cache",
                    Producers = new Func<CheckGroup>[] { SafetyChecks.CheckDnsCache }, BuildView = TabViews.BuildDns },
            new() { Category = "Network path", Title = "ARP", Key = "arp",
                    Banner = "Local ARP neighbor cache", ReportTitle = "ARP Cache",
                    Producers = new Func<CheckGroup>[] { SafetyChecks.CheckArp }, BuildView = TabViews.BuildArp },
            new() { Category = "Network path", Title = "Root CAs", Key = "rootca",
                    Banner = "Trusted root certificate authorities", ReportTitle = "Root CAs",
                    Producers = new Func<CheckGroup>[] { SafetyChecks.CheckRootCAs }, BuildView = TabViews.BuildRootCerts },
            new() { Category = "Network path", Title = "Firewall", Key = "firewall",
                    Banner = "Windows Firewall configuration", ReportTitle = "Firewall",
                    Producers = new Func<CheckGroup>[] { SafetyChecks.CheckFirewall, SafetyChecks.CheckFirewallRules }, BuildView = TabViews.BuildFirewall },

            // -- Recent changes (vs the Patches baseline) --
            new() { Category = "Recent changes", Title = "Patches", Key = "patches",
                    Banner = "Installed Windows patches", ReportTitle = "Patches",
                    Producers = new Func<CheckGroup>[] { SafetyChecks.CheckPatches }, BuildView = TabViews.BuildPatches },
            new() { Category = "Recent changes", Title = "Processes", Key = "processes",
                    Banner = "Running processes", ReportTitle = "Processes",
                    Producers = new Func<CheckGroup>[] { SafetyChecks.CheckProcesses }, BuildView = TabViews.BuildProcesses },
            new() { Category = "Recent changes", Title = "Services", Key = "services",
                    Banner = "3rd party background services", ReportTitle = "Services",
                    Producers = new Func<CheckGroup>[] { SafetyChecks.CheckServices }, BuildView = TabViews.BuildServices },
            new() { Category = "Recent changes", Title = "Startup", Key = "startup",
                    Banner = "Startup on login", ReportTitle = "Startup",
                    Producers = new Func<CheckGroup>[] { SafetyChecks.CheckStartup }, BuildView = TabViews.BuildStartup },
            new() { Category = "Recent changes", Title = "Scheduled", Key = "scheduled",
                    Banner = "Scheduled tasks", ReportTitle = "Scheduled Tasks",
                    Producers = new Func<CheckGroup>[] { SafetyChecks.CheckScheduledTasks }, BuildView = TabViews.BuildScheduled },
            new() { Category = "Recent changes", Title = "Installed", Key = "installed",
                    Banner = "Installed program changes", ReportTitle = "Installed",
                    Producers = new Func<CheckGroup>[] { SafetyChecks.CheckInstalled }, BuildView = TabViews.BuildInstalled },
            new() { Category = "Recent changes", Title = "Devices", Key = "devices",
                    Banner = "Installed device changes", ReportTitle = "Devices",
                    Producers = new Func<CheckGroup>[] { SafetyChecks.CheckDevices }, BuildView = TabViews.BuildDevices },
            new() { Category = "Recent changes", Title = "Win Extn", Key = "winext",
                    Banner = "File Explorer shell extensions", ReportTitle = "Shell Extensions",
                    Producers = new Func<CheckGroup>[] { SafetyChecks.CheckWinExt }, BuildView = TabViews.BuildWinExt },

            // -- Accounts & usage --
            new() { Category = "Accounts & usage", Title = "Users", Key = "users",
                    Banner = "Local user accounts", ReportTitle = "User Accounts",
                    Producers = new Func<CheckGroup>[] { SafetyChecks.CheckUsers }, BuildView = TabViews.BuildUsers },
            new() { Category = "Accounts & usage", Title = "Activity", Key = "activity",
                    Banner = "App launch activity", ReportTitle = "App Activity",
                    Producers = new Func<CheckGroup>[] { SafetyChecks.CheckActivity }, BuildView = TabViews.BuildActivity },
            new() { Category = "Accounts & usage", Title = "Awake", Key = "awake",
                    Banner = "Recent awake / sleep periods", ReportTitle = "Awake Periods",
                    Producers = new Func<CheckGroup>[] { SafetyChecks.CheckAwake }, BuildView = TabViews.BuildAwake },
            new() { Category = "Accounts & usage", Title = "Downloads", Key = "downloads",
                    Banner = "Per-app network usage (downloads)", ReportTitle = "Downloads",
                    Producers = new Func<CheckGroup>[] { SafetyChecks.DownloadsHeader, SafetyChecks.CheckDownloads }, BuildView = TabViews.BuildDownloads },
            new() { Category = "Accounts & usage", Title = "Events", Key = "events",
                    Banner = "Recent system & security events", ReportTitle = "Event Log",
                    Producers = new Func<CheckGroup>[] { SafetyChecks.CheckEventLog }, BuildView = TabViews.BuildEvents },

            // -- Protection --
            new() { Category = "Protection", Title = "Virus", Key = "virus",
                    Banner = "Virus protection", ReportTitle = "Virus",
                    Producers = new Func<CheckGroup>[] { SafetyChecks.VirusHeader, SafetyChecks.CheckVirus }, BuildView = TabViews.BuildVirus },
            new() { Category = "Protection", Title = "Restores", Key = "restores",
                    Banner = "System Restore points", ReportTitle = "Restore Points", AdminOnly = true,
                    Producers = new Func<CheckGroup>[] { SafetyChecks.CheckRestore }, BuildView = TabViews.BuildRestores },

            // -- Browser --
            new() { Category = "Browser", Title = "Chrome", Key = "chrome",
                    Banner = "Chrome browser and extensions", ReportTitle = "Chrome",
                    Producers = new Func<CheckGroup>[] { SafetyChecks.CheckChromeExe, SafetyChecks.CheckChromePrivacy, SafetyChecks.CheckChromeExtensions }, BuildView = TabViews.BuildChrome },
            new() { Category = "Browser", Title = "Settings", Key = "settings",
                    Banner = "Chrome settings", ReportTitle = "Chrome Settings",
                    Producers = new Func<CheckGroup>[] { SafetyChecks.CheckChromeSettings }, BuildView = TabViews.BuildSettings },

            // -- Tools (GUI-only: no headless producers) --
            new() { Category = "Tools", Title = "Links", Key = "links",
                    Banner = "Tools & links", BuildView = TabViews.BuildLinks },
            new() { Category = "Tools", Title = "Windows Security", Key = "security",
                    Banner = "Windows Security shortcuts", BuildView = TabViews.BuildSecurityLinks },
        };

        /// <summary>Lookup by scope key (case-insensitive).</summary>
        public static Section? Find(string key) =>
            Sections.FirstOrDefault(s => s.Key.Equals(key, StringComparison.OrdinalIgnoreCase));

        /// <summary>Sections in a category, honouring elevation for admin-only entries.</summary>
        public static IEnumerable<Section> InCategory(string category, bool isAdmin) =>
            Sections.Where(s => s.Category == category && (!s.AdminOnly || isAdmin));
    }
}
