// Copyright (c) 2026 LanDen Labs - Dennis Lang

using System;
using System.Collections.Generic;
using System.Text;

namespace B4Browse
{
    /// <summary>
    /// Plain-language descriptions for every row of the Settings tab (the Chrome settings matrix).
    /// One short paragraph per setting, grouped by the same categories the grid uses. Surfaced two
    /// ways from a setting's right-click menu: <see cref="Help"/> is the whole "what each setting
    /// does" document (opened in the modeless help dialog, scrolled to the clicked setting via the
    /// setting's <see cref="Entry.Label"/> as the anchor), and <see cref="Lookup"/> gives the single
    /// paragraph for one label. Labels here must match the catalog labels in
    /// <c>SafetyChecks.ChromeSettings.cs</c> exactly - they are the anchor keys.
    /// </summary>
    public static class SettingsInfo
    {
        public readonly record struct Entry(string Category, string Label, string Body);

        // Display order matches the grid (CategoryBase / Order in SafetyChecks.ChromeSettings.cs).
        private static readonly Entry[] Entries =
        {
            // ---- Privacy & Security -------------------------------------- //
            new("Privacy & Security", "Safe Browsing",
                "Chrome's built-in protection against dangerous sites, downloads, and extensions. " +
                "\"Standard\" checks what you visit against a list Google updates; \"Enhanced\" sends more " +
                "browsing data to Google for faster, predictive warnings. \"Off\" disables this " +
                "protection entirely and is the single most security-relevant value on this tab - a " +
                "profile silently switched to Off is a classic sign of malware or a hijacked profile."),
            new("Privacy & Security", "Third-party cookies",
                "Controls whether sites other than the one in your address bar may set cookies. These " +
                "are the cookies used to track you across sites. \"Blocked\" is the safest; \"Block in " +
                "Incognito\" only blocks them in private windows; \"Allowed\" lets every site track you " +
                "and is flagged here as a weak choice."),
            new("Privacy & Security", "Clear cookies on exit",
                "When set, Chrome deletes all site cookies (signing you out everywhere) each time it " +
                "closes. \"Keep\" retains them between sessions. This is a convenience/privacy trade-off, " +
                "not a security risk either way."),
            new("Privacy & Security", "HTTPS-Only mode",
                "When on, Chrome tries to load every site over an encrypted HTTPS connection and warns " +
                "before falling back to unencrypted HTTP. Turning it on reduces the chance that someone " +
                "on your network can read or tamper with the pages you load."),
            new("Privacy & Security", "Do Not Track",
                "Adds a \"do not track\" request header to your traffic. It is only a polite request - " +
                "most sites ignore it - so it has little practical effect and no security impact."),
            new("Privacy & Security", "Preload pages",
                "Lets Chrome fetch pages it predicts you will open next, so they load faster. This shares " +
                "some browsing activity with Google and the preloaded sites ahead of time; \"Never\" is " +
                "the most private. It is a performance/privacy trade-off, not a security risk."),

            // ---- Privacy Sandbox (Ads) ----------------------------------- //
            new("Privacy Sandbox (Ads)", "Ad topics",
                "Part of Google's Privacy Sandbox. When on, Chrome infers interest \"topics\" from your " +
                "browsing and shares them with sites to pick ads. \"On\" means in-browser ad profiling is " +
                "active; turning it off stops Chrome from building this interest list."),
            new("Privacy Sandbox (Ads)", "Site-suggested ads",
                "Privacy Sandbox feature (FLEDGE/Protected Audience) that lets a site you visit later show " +
                "you ads chosen in the browser. \"On\" enables this in-browser ad targeting; off disables it."),
            new("Privacy Sandbox (Ads)", "Ad measurement",
                "Privacy Sandbox feature that lets sites and advertisers measure ad performance (e.g. " +
                "whether an ad led to a visit) through the browser. \"On\" enables this measurement; off " +
                "disables it."),

            // ---- Passwords & Autofill ------------------------------------ //
            new("Passwords & Autofill", "Offer to save passwords",
                "Whether Chrome's password manager offers to save the passwords you type. Convenient, but " +
                "anything saved in the profile can be exported by anyone with access to your signed-in " +
                "Windows session, so it matters most on shared machines."),
            new("Passwords & Autofill", "Auto sign-in",
                "When on, Chrome automatically signs you in to sites using a saved password without asking " +
                "first. Turning it off makes Chrome confirm before using a stored credential."),
            new("Passwords & Autofill", "Saved passwords (count)",
                "How many passwords this profile has stored in Chrome's password manager. B4-Browse only " +
                "counts the rows - it never reads, decrypts, or displays any password or the site it " +
                "belongs to. A surprisingly large count on an unfamiliar profile is worth a look."),
            new("Passwords & Autofill", "Autofill addresses",
                "Whether Chrome offers to fill saved names, postal addresses, and phone numbers into web " +
                "forms. A privacy convenience with no direct security impact."),
            new("Passwords & Autofill", "Autofill payment methods",
                "Whether Chrome offers to fill saved credit/debit card details into checkout forms. On " +
                "shared machines, off is safer; the card data is tied to your Windows sign-in."),

            // ---- Site permission defaults -------------------------------- //
            new("Site permission defaults", "Notifications",
                "The default answer when a site asks to show desktop notifications. \"Block\" or \"Ask\" is " +
                "safe; \"Allow\" lets any site push notifications without prompting - a common vector for " +
                "scam and \"your PC is infected\" pop-ups - so Allow is flagged here."),
            new("Site permission defaults", "Location",
                "The default answer when a site asks for your physical location. \"Allow\" hands your " +
                "location to any site without asking and is flagged; \"Ask\" or \"Block\" is safer."),
            new("Site permission defaults", "Camera",
                "The default answer when a site asks to use your webcam. \"Allow\" lets any site access the " +
                "camera without prompting and is flagged; keep this at \"Ask\" or \"Block\"."),
            new("Site permission defaults", "Microphone",
                "The default answer when a site asks to use your microphone. \"Allow\" lets any site listen " +
                "without prompting and is flagged; keep this at \"Ask\" or \"Block\"."),
            new("Site permission defaults", "Pop-ups",
                "The default for pop-up windows and redirects. \"Block\" is normal and recommended; " +
                "\"Allow\" lets any site open pop-ups and forced redirects, which adware relies on, so " +
                "Allow is flagged."),
            new("Site permission defaults", "JavaScript",
                "The default for running JavaScript. Virtually every site needs it, so \"Allow\" is the " +
                "normal, expected value here and is not flagged. \"Block\" breaks most sites."),
            new("Site permission defaults", "Images",
                "The default for loading images. \"Allow\" is normal; \"Block\" gives a text-only web. No " +
                "security impact."),
            new("Site permission defaults", "Sound",
                "The default for letting sites play audio. \"Allow\" is normal; some users set \"Block\" to " +
                "silence autoplay. No security impact."),
            new("Site permission defaults", "Automatic downloads",
                "Whether a site may download multiple files without asking each time. \"Allow\" lets a site " +
                "drop several files on your machine automatically and is flagged; \"Ask\" is safer."),

            // ---- Search & Startup ---------------------------------------- //
            new("Search & Startup", "Default search engine",
                "The search provider used from the address bar. Worth confirming this is the engine you " +
                "expect (Google, Bing, DuckDuckGo, etc.) - browser hijackers commonly swap in an " +
                "unfamiliar search provider that routes your queries through their servers."),
            new("Search & Startup", "On startup",
                "What Chrome opens when it launches: the New Tab page, the pages from your last session, or " +
                "a specific set of pages. \"Open specific pages\" you don't recognise can be a sign a " +
                "hijacker has pinned a start page."),
            new("Search & Startup", "Startup pages",
                "The exact pages opened at launch when \"On startup\" is set to open specific pages. Review " +
                "this list for unexpected URLs - an unfamiliar entry here is a hijack indicator."),

            // ---- Downloads ----------------------------------------------- //
            new("Downloads", "Download location",
                "The folder Chrome saves downloads to. Informational; useful to know where files land, " +
                "with no direct security impact."),
            new("Downloads", "Ask where to save",
                "When \"Ask each time\" is set, Chrome prompts for a location on every download; \"Auto-save\" " +
                "drops files straight into the download folder. Asking each time gives you a moment to " +
                "notice an unexpected download."),

            // ---- Extensions ---------------------------------------------- //
            new("Extensions", "Extensions (enabled)",
                "How many browser extensions are enabled in this profile. Extensions are the highest-risk " +
                "add-ons in Chrome - they can read and change the pages you visit - so a high or unfamiliar " +
                "count deserves review on the Chrome tab, where each extension is listed individually."),
        };

        /// <summary>Label -> paragraph, for the single-setting lookup.</summary>
        private static readonly Dictionary<string, string> ByLabel = BuildIndex();

        private static Dictionary<string, string> BuildIndex()
        {
            var d = new Dictionary<string, string>(StringComparer.Ordinal);
            foreach (var e in Entries) d[e.Label] = e.Body;
            return d;
        }

        /// <summary>The paragraph for one setting label, or null if none is catalogued.</summary>
        public static string? Lookup(string label) => ByLabel.TryGetValue(label, out var b) ? b : null;

        /// <summary>The full "what each setting does" document, grouped by category, rendered with the
        /// shared light markup. Each setting is a <c>## Label</c> sub-heading, so the label doubles as
        /// the scroll anchor passed to <see cref="HelpUi.Show(System.Windows.Forms.IWin32Window?, HelpInfo, string?)"/>.</summary>
        public static HelpInfo Help { get; } = BuildHelp();

        private static HelpInfo BuildHelp()
        {
            var sb = new StringBuilder();
            sb.Append("Right-click any setting and choose \"Explain\" to jump here; \"Search the web\" opens ");
            sb.Append("an online search for it.\n\n");

            string? lastCat = null;
            foreach (var e in Entries)
            {
                if (e.Category != lastCat)
                {
                    sb.Append("# ").Append(e.Category).Append('\n');
                    lastCat = e.Category;
                }
                sb.Append("## ").Append(e.Label).Append('\n');
                sb.Append(e.Body).Append("\n\n");
            }

            return new HelpInfo("Chrome Settings - what each setting does", sb.ToString());
        }
    }
}
