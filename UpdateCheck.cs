// Copyright (c) 2026 LanDen Labs - Dennis Lang

using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace B4Browse
{
    /// <summary>Result of a GitHub "latest release" check. <see cref="Available"/> is true only when a
    /// strictly newer version is published. <see cref="Error"/> is non-null when the check could not be
    /// completed (offline, rate-limited, parse failure) - the UI shows it instead of a verdict.
    /// <see cref="DownloadUrl"/> is the release asset matching this install (the .msi for an MSI
    /// install, B4Browse.exe for a portable one), or null to fall back to <see cref="ReleaseUrl"/>.</summary>
    public sealed record UpdateInfo(
        bool Available,
        string LatestVersion,
        string CurrentVersion,
        string ReleaseUrl,
        string? Notes,
        string? Error,
        string? DownloadUrl = null);

    /// <summary>Queries the GitHub Releases API for the newest published B4-Browse release and compares
    /// it to the running <see cref="AppInfo.Version"/>. Network-only, no install side effects - the
    /// "download" step just opens the matching asset (or the release page) in the browser (replacing a
    /// running single-file exe in place is a separate, larger problem). Safe to call from the UI thread
    /// (fully async, no throw).
    ///
    /// NOT used for Microsoft Store (MSIX) installs: the Store delivers those updates itself, and a
    /// GitHub release is visible days before the Store finishes certifying the same version, so this
    /// check would wrongly report an update the Store can't install yet (and a GitHub download would
    /// create a second, separately-updated copy). See <see cref="InstallSource"/>.</summary>
    public static class UpdateCheck
    {
        public const string Owner = "landenlabs";
        public const string Repo = "win-b4browse";

        public static string RepoUrl => $"https://github.com/{Owner}/{Repo}";
        public static string ReleasesUrl => $"{RepoUrl}/releases/latest";
        public static string IssuesUrl => $"{RepoUrl}/issues";

        // One shared client. GitHub requires a User-Agent or it rejects the request with 403.
        private static readonly HttpClient Http = CreateClient();

        private static HttpClient CreateClient()
        {
            var c = new HttpClient { Timeout = TimeSpan.FromSeconds(10) };
            c.DefaultRequestHeaders.UserAgent.ParseAdd("B4Browse/" + AppInfo.Version);
            c.DefaultRequestHeaders.Accept.ParseAdd("application/vnd.github+json");
            return c;
        }

        /// <summary>Fetch the latest release and decide whether it is newer than the running build.
        /// Never throws; failures are returned in <see cref="UpdateInfo.Error"/>.</summary>
        public static async Task<UpdateInfo> CheckAsync(CancellationToken ct = default)
        {
            string current = AppInfo.Version;
            try
            {
                string url = $"https://api.github.com/repos/{Owner}/{Repo}/releases/latest";
                using var resp = await Http.GetAsync(url, ct);
                if (!resp.IsSuccessStatusCode)
                {
                    // 404 = no releases published yet; treat as "up to date" rather than an error.
                    if (resp.StatusCode == System.Net.HttpStatusCode.NotFound)
                        return new UpdateInfo(false, current, current, ReleasesUrl, null, null);
                    return new UpdateInfo(false, "", current, ReleasesUrl, null,
                        $"GitHub returned {(int)resp.StatusCode} {resp.ReasonPhrase}");
                }

                await using var stream = await resp.Content.ReadAsStreamAsync(ct);
                using var doc = await JsonDocument.ParseAsync(stream, default, ct);
                var root = doc.RootElement;

                string tag = root.TryGetProperty("tag_name", out var t) ? (t.GetString() ?? "") : "";
                string htmlUrl = root.TryGetProperty("html_url", out var h) ? (h.GetString() ?? ReleasesUrl) : ReleasesUrl;
                string? notes = root.TryGetProperty("body", out var b) ? b.GetString() : null;

                string latest = NormalizeVersion(tag);
                bool available = !string.IsNullOrEmpty(latest) && CompareVersions(latest, current) > 0;
                string? download = root.TryGetProperty("assets", out var assets)
                    ? PickAsset(assets, InstallSource.Kind) : null;
                return new UpdateInfo(available, latest, current, htmlUrl, notes, null, download);
            }
            catch (OperationCanceledException)
            {
                return new UpdateInfo(false, "", current, ReleasesUrl, null, "Update check timed out.");
            }
            catch (Exception ex)
            {
                return new UpdateInfo(false, "", current, ReleasesUrl, null, ex.Message);
            }
        }

        /// <summary>Choose the release asset that matches how this copy was installed (publish.yml
        /// uploads B4Browse.exe, B4Browse-win-x64-portable.zip, B4Browse-&lt;ver&gt;-x64.msix and
        /// B4Browse-&lt;ver&gt;-x64.msi). Returns its browser_download_url, or null if none matches.</summary>
        private static string? PickAsset(JsonElement assets, InstallKind kind)
        {
            if (assets.ValueKind != JsonValueKind.Array || kind == InstallKind.Store) return null;
            string? exe = null, zip = null, msi = null;
            foreach (var a in assets.EnumerateArray())
            {
                string name = a.TryGetProperty("name", out var n) ? (n.GetString() ?? "") : "";
                string? url = a.TryGetProperty("browser_download_url", out var u) ? u.GetString() : null;
                if (string.IsNullOrEmpty(url)) continue;
                if (name.EndsWith(".msi", StringComparison.OrdinalIgnoreCase)) msi ??= url;
                else if (name.Equals("B4Browse.exe", StringComparison.OrdinalIgnoreCase)) exe ??= url;
                else if (name.EndsWith("-portable.zip", StringComparison.OrdinalIgnoreCase)) zip ??= url;
            }
            return kind == InstallKind.Msi ? msi : (exe ?? zip);
        }

        /// <summary>Strip a leading 'v'/'V' from a tag like "v6.05.26" -> "6.05.26".</summary>
        public static string NormalizeVersion(string tag)
        {
            tag = (tag ?? "").Trim();
            if (tag.Length > 0 && (tag[0] == 'v' || tag[0] == 'V')) tag = tag.Substring(1);
            return tag;
        }

        /// <summary>Compare two dot-separated numeric versions. Returns &gt;0 if <paramref name="a"/> is
        /// newer, &lt;0 if older, 0 if equal. Missing trailing parts count as 0 (so "6.05" == "6.05.0").</summary>
        public static int CompareVersions(string a, string b)
        {
            int[] pa = ParseParts(a);
            int[] pb = ParseParts(b);
            int n = Math.Max(pa.Length, pb.Length);
            for (int i = 0; i < n; i++)
            {
                int va = i < pa.Length ? pa[i] : 0;
                int vb = i < pb.Length ? pb[i] : 0;
                if (va != vb) return va.CompareTo(vb);
            }
            return 0;
        }

        // Parse the leading run of numeric components, stopping at the first non-numeric segment
        // (so a "-beta" / "+build" suffix is ignored rather than crashing the comparison).
        private static int[] ParseParts(string v)
        {
            if (string.IsNullOrWhiteSpace(v)) return Array.Empty<int>();
            var list = new List<int>();
            foreach (var part in v.Split('.', '-', '+'))
            {
                int j = 0;
                while (j < part.Length && char.IsDigit(part[j])) j++;
                if (j == 0) break;
                if (int.TryParse(part.Substring(0, j), out int num)) list.Add(num);
                else break;
            }
            return list.ToArray();
        }
    }
}
