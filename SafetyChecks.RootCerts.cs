// Copyright (c) 2026 LanDen Labs - Dennis Lang

using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text.Json;

namespace B4Browse
{
    /// <summary>
    /// Audits the trusted-root certificate stores (LocalMachine + CurrentUser). A root in
    /// these stores is trusted to vouch for ANY HTTPS site, so an unexpected one - especially
    /// a TLS-inspection root from an AV/proxy, or a freshly planted one - means your encrypted
    /// browsing can be silently intercepted (man-in-the-middle). Chrome on Windows honours the
    /// Windows roots, so this is directly relevant to safe browsing. Read via Get-ChildItem on
    /// the Cert: drive, which standard users can do (the root store is world-readable).
    /// </summary>
    public static partial class SafetyChecks
    {
        // Well-known PUBLIC certificate authorities + Microsoft's own roots: expected anywhere.
        private static readonly string[] PublicCaKeywords =
        {
            "digicert", "globalsign", "sectigo", "comodo", "entrust", "godaddy", "go daddy",
            "starfield", "verisign", "symantec", "thawte", "geotrust", "rapidssl",
            "baltimore cybertrust", "usertrust", "addtrust", "isrg root", "let's encrypt",
            "amazon root", "amazon rsa", "amazon ecdsa", "google trust services", "gts root",
            "certum", "actalis", "buypass", "swisssign", "t-systems", "quovadis", "identrust",
            "dst root", "ssl.com", "harica", "d-trust", "affirmtrust", "trustwave",
            "secure global", "securetrust", "network solutions", "twca", "emsign", "xramp",
            "equifax", "valicert", "microsoft", "ms-organization", "windows azure",
        };

        // Software/appliances that install a root to DECRYPT TLS (SSL inspection / MITM proxy).
        private static readonly string[] TlsInterceptKeywords =
        {
            "fiddler", "burp", "charles", "mitmproxy", "proxyman", "do_not_trust", "do not trust",
            "avast", "avg ", "kaspersky", "eset", "bitdefender", "bullguard", "zscaler", "netskope",
            "forcepoint", "fortinet", "fortigate", "sophos", "umbrella", "opendns", "contentkeeper",
            "lightspeed", "securly", "barracuda", "palo alto", "bluecoat", "blue coat", "mcafee web",
            "trend micro", "webroot", "smoothwall", "untangle", "sonicwall", "watchguard",
            "checkpoint", "check point", "symantec web", "menlo", "ericom", "gfi", "kerio",
            "cloudflare for teams", "cloudflare gateway",
        };

        // Benign local / developer / domain-join roots: expected, low interest.
        private static readonly string[] BenignLocalKeywords =
        {
            "localhost", "iis express", "asp.net core", "remote desktop", "wmsvc", "configmgr",
            "dotnet", "kestrel", "127.0.0.1",
        };

        /// <summary>Trusted-root certificates from both stores, most-interesting first.</summary>
        public static List<RootCertItem> GetRootCerts()
        {
            const string script = @"
$ErrorActionPreference='SilentlyContinue'
function Dump($loc){
  Get-ChildItem -Path ('Cert:\' + $loc + '\Root') | ForEach-Object {
    [pscustomobject]@{
      Store=$loc
      Subject=[string]$_.Subject
      Issuer=[string]$_.Issuer
      NotBefore=$_.NotBefore.ToString('o')
      NotAfter=$_.NotAfter.ToString('o')
      Thumbprint=[string]$_.Thumbprint
      Sig=[string]$_.SignatureAlgorithm.FriendlyName
    }
  }
}
@(Dump 'LocalMachine') + @(Dump 'CurrentUser') | ConvertTo-Json -Compress -Depth 3";

            // The CurrentUser\Root view is a MERGE that already includes the machine roots, so the
            // same thumbprint shows up in both stores. Process LocalMachine first and dedupe by
            // thumbprint so each root appears once - as CurrentUser only when it's user-added.
            var list = new List<RootCertItem>();
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var r in RunPowerShellArray(script))
            {
                string subjectDn = JStr(r, "Subject");
                if (subjectDn.Length == 0) continue;
                string thumb = JStr(r, "Thumbprint");
                string key = thumb.Length > 0 ? thumb : subjectDn + "|" + JStr(r, "NotAfter");
                if (!seen.Add(key)) continue;
                list.Add(ClassifyRoot(
                    JStr(r, "Store"), subjectDn, JStr(r, "Issuer"),
                    JStr(r, "NotBefore"), JStr(r, "NotAfter"), thumb, JStr(r, "Sig")));
            }

            // Most severe first, then non-public before public, then by name.
            return list
                .OrderByDescending(c => (int)c.Severity)
                .ThenBy(c => c.Expected)
                .ThenBy(c => c.Subject, StringComparer.OrdinalIgnoreCase)
                .ToList();
        }

        private static RootCertItem ClassifyRoot(string store, string subjectDn, string issuerDn,
            string notBefore, string notAfter, string thumb, string sig)
        {
            var item = new RootCertItem
            {
                Store = store,
                SubjectFull = subjectDn,
                Subject = RootName(subjectDn),
                Issuer = RootName(issuerDn),
                Thumbprint = thumb,
                Sig = sig,
            };
            if (DateTime.TryParse(notBefore, null, DateTimeStyles.RoundtripKind, out var nb)) item.NotBefore = nb;
            if (DateTime.TryParse(notAfter, null, DateTimeStyles.RoundtripKind, out var na)) item.NotAfter = na;
            item.AddedSort = item.NotBefore;
            item.ExpiresText = item.NotAfter == default ? "—" : item.NotAfter.ToString("yyyy-MM-dd");

            string hay = (subjectDn + " " + issuerDn).ToLowerInvariant();
            bool intercept = TlsInterceptKeywords.Any(hay.Contains);
            bool publicCa = PublicCaKeywords.Any(hay.Contains);
            bool benign = BenignLocalKeywords.Any(hay.Contains);
            bool expired = item.NotAfter != default && item.NotAfter < DateTime.Now;
            int ageDays = item.NotBefore == default ? 9999 : (int)(DateTime.Now - item.NotBefore).TotalDays;
            bool recent = ageDays is >= 0 and < 30;

            if (intercept)
            {
                item.Severity = TabSeverity.Caution;
                item.StatusLabel = "Intercept";
                item.Expected = false;
                item.Note = "TLS-inspection root - can decrypt your HTTPS traffic. Expected only if you run this security/proxy product.";
            }
            else if (!publicCa && !benign)
            {
                item.Expected = false;
                item.StatusLabel = "Review";
                if (recent)
                {
                    item.Severity = TabSeverity.Alert;
                    item.Note = "Non-public root added in the last 30 days - confirm you or your IT installed it; a rogue root enables HTTPS interception.";
                }
                else
                {
                    item.Severity = TabSeverity.Caution;
                    item.Note = "Non-public root CA - verify it is expected (enterprise / AV / developer).";
                }
            }
            else
            {
                item.Severity = TabSeverity.None;
                item.Expected = true;
                item.StatusLabel = publicCa ? "Public CA" : "System/Local";
                item.Note = publicCa ? "Well-known public certificate authority." : "Built-in / local root.";
            }

            if (expired) item.Note += $"  (expired {item.NotAfter:yyyy-MM-dd})";
            return item;
        }

        /// <summary>Short display name for a certificate: its CN, else O, else the raw DN.</summary>
        private static string RootName(string dn)
        {
            string cn = Rdn(dn, "CN");
            if (cn.Length > 0) return cn;
            string o = Rdn(dn, "O");
            return o.Length > 0 ? o : dn;
        }

        /// <summary>Reads one RDN value (e.g. CN= / O=) out of a distinguished name.</summary>
        private static string Rdn(string dn, string key)
        {
            int i = dn.IndexOf(key + "=", StringComparison.OrdinalIgnoreCase);
            if (i < 0) return "";
            int start = i + key.Length + 1;
            if (start >= dn.Length) return "";
            if (dn[start] == '"')
            {
                int end = dn.IndexOf('"', start + 1);
                return (end > start ? dn[(start + 1)..end] : dn[(start + 1)..]).Trim();
            }
            int comma = dn.IndexOf(',', start);
            return (comma >= 0 ? dn[start..comma] : dn[start..]).Trim();
        }

        /// <summary>Report producer (headless / email / copy / print): the non-public root audit.</summary>
        public static CheckGroup CheckRootCAs()
        {
            var group = new CheckGroup("Trusted Root Certificate Authorities");
            var certs = GetRootCerts();
            if (certs.Count == 0)
            {
                group.Add(CheckStatus.Info, "Root CAs", "Could not enumerate the trusted root certificate store.");
                return group;
            }

            var interesting = certs.Where(c => !c.Expected).ToList();
            if (interesting.Count == 0)
            {
                group.Add(CheckStatus.Pass, "Trusted roots",
                    $"All {certs.Count} trusted root(s) are well-known public CAs or built-in system roots.");
                return group;
            }

            int intercept = interesting.Count(c => c.StatusLabel == "Intercept");
            group.Add(CheckStatus.Warn, "Trusted roots",
                $"{certs.Count} root(s); {interesting.Count} non-public" +
                (intercept > 0 ? $", including {intercept} TLS-inspection root(s) that can decrypt HTTPS" : "") +
                " - review the entries below.");

            foreach (var c in interesting)   // already severity-ordered
            {
                var st = c.Severity >= TabSeverity.Caution ? CheckStatus.Warn : CheckStatus.Info;
                group.Add(st, c.Subject, $"{c.Store}  -  {c.Note}  -  expires {c.ExpiresText}  -  {c.Thumbprint}");
            }
            return group;
        }
    }
}
