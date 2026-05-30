namespace BrowseSafe
{
    /// <summary>One row of the Chrome Extensions tab.</summary>
    public sealed class ChromeExtension
    {
        public string ProfileDir = "";
        public string ProfileName = "";   // friendly name, falls back to ProfileDir
        public string Name = "";
        public string Version = "";
        public string Description = "";
        public string Id = "";
        public int? ManifestVersion;      // 2 or 3, null if unknown
        public bool Enabled = true;
        public bool Unsupported;          // manifest_version below this Chrome's minimum
    }
}
