// Copyright (c) 2026 LanDen Labs - Dennis Lang

namespace B4Browse
{
    // Central application metadata, single source for the version shown in-app.
    //
    // AUTO-VERSION: the Version, BuildDate and Copyright constants below are
    // rewritten by set-version.ps1 when a release is cut. That same run also
    // updates the VERSION file, the README.md <!-- VERSION --> / <!-- DATE -->
    // markers, and the <Version>/<Copyright> properties in B4Browse.csproj
    // (which drive the exe's File/Product version and copyright in its Details
    // tab), so every place the version appears stays in sync. The literal
    // "AUTO-VERSION" marker above is what scopes the script's edits to this file.
    internal static class AppInfo
    {
        // Bare semantic version, e.g. "6.05.26" (no leading 'v'); matches VERSION and <Version>.
        public const string Version = "6.05.26";

        // Human-readable release date in dd-MMM-yyyy form; matches the README <!-- DATE --> marker.
        public const string BuildDate = "31-May-2026";

        public const string Product = "B4 Browse";
        public const string Company = "LanDen Labs";
        public const string Author = "Dennis Lang";

        // Copyright; set-version.ps1 keeps the 4-digit year current.
        public const string Copyright = "LanDen Labs (2026)";
    }
}
