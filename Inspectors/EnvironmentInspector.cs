// Copyright (c) 2026 LanDen Labs - Dennis Lang

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Diagnostics;

namespace B4Browse
{
    /// <summary>
    /// Inspects environment variables (machine + user) and applies heuristics to surface
    /// suspicious entries: invalid paths, user-writable PATH directories, core-variable
    /// tampering, and length risks.
    /// </summary>
    public static class EnvironmentInspector
    {
        private static readonly string[] PathLikeNames = new[] { "PATH", "Path" };

        public static List<EnvVariableInfo> InspectAll()
        {
            var list = new List<EnvVariableInfo>();

            InspectScope(EnvironmentVariableTarget.Machine, true, list);
            InspectScope(EnvironmentVariableTarget.User, false, list);

            return list;
        }

        private static void InspectScope(EnvironmentVariableTarget target, bool isMachine, List<EnvVariableInfo> outList)
        {
            try
            {
                var dict = Environment.GetEnvironmentVariables(target);
                foreach (System.Collections.DictionaryEntry de in dict)
                {
                    string name = de.Key?.ToString() ?? "";
                    string raw = de.Value?.ToString() ?? "";

                    // Split into parts when semicolon-delimited (PATH-like). Each part becomes its own row.
                    var parts = raw.Contains(';') ? raw.Split(';').Select(s => s?.Trim() ?? "").Where(s => s.Length > 0).ToList()
                                : new List<string> { raw };

                    bool lengthRisk = raw.Length > 2048;

                    foreach (var part in parts)
                    {
                        var info = new EnvVariableInfo { Name = name, RawValue = raw, IsMachineScope = isMachine, Value = part };
                        if (lengthRisk) info.IsLengthRisk = true;

                        // For compatibility keep parsed paths list with single item when the part looks like a path
                        if (part.Length > 0) info.ParsedPaths.Add(part);

                        // Validate path-like parts and attempt author inference
                        var p = part;
                        try
                        {
                            if (!Directory.Exists(p))
                            {
                                info.HasInvalidPaths = true;
                            }
                            else
                            {
                                // Attempt author inference: find an exe and read its company name
                                try
                                {
                                    var exe = Directory.EnumerateFiles(p, "*.exe", SearchOption.TopDirectoryOnly).FirstOrDefault();
                                    if (exe != null)
                                    {
                                        try
                                        {
                                            var fi = FileVersionInfo.GetVersionInfo(exe);
                                            var comp = fi.CompanyName ?? fi.ProductName ?? Path.GetFileNameWithoutExtension(exe);
                                            info.InferredAuthors.Add(comp);
                                        }
                                        catch { info.InferredAuthors.Add(Path.GetFileName(p)); }
                                    }
                                    else
                                    {
                                        info.InferredAuthors.Add(Path.GetFileName(p));
                                    }
                                }
                                catch { info.InferredAuthors.Add(Path.GetFileName(p)); }

                                // ACL check only for machine-scope PATH entries (risk of escalation)
                                if (isMachine && name.Equals("PATH", StringComparison.OrdinalIgnoreCase))
                                {
                                    try
                                    {
                                        var di = new DirectoryInfo(p);
                                        var acl = di.GetAccessControl();
                                        var rules = acl.GetAccessRules(true, true, typeof(SecurityIdentifier));
                                        foreach (FileSystemAccessRule rule in rules)
                                        {
                                            if (rule.AccessControlType != AccessControlType.Allow) continue;
                                            var rights = rule.FileSystemRights;
                                            if ((rights & (FileSystemRights.Write | FileSystemRights.Modify | FileSystemRights.FullControl)) == 0) continue;

                                            // Translate SID to NTAccount if possible
                                            try
                                            {
                                                var id = (SecurityIdentifier)rule.IdentityReference;
                                                var nt = (NTAccount)id.Translate(typeof(NTAccount));
                                                var acct = nt.Value ?? id.Value;
                                                if (IsUntrustedPrincipal(acct))
                                                {
                                                    info.HasUserWritablePaths = true;
                                                    break;
                                                }
                                            }
                                            catch
                                            {
                                                // Fallback: check string form
                                                var s = rule.IdentityReference.Value ?? "";
                                                if (IsUntrustedPrincipal(s))
                                                {
                                                    info.HasUserWritablePaths = true;
                                                    break;
                                                }
                                            }
                                        }
                                    }
                                    catch { /* swallow ACL read errors */ }
                                }
                            }
                        }
                        catch { info.HasInvalidPaths = true; }

                        // Core variable checks (apply per-part but derive from full raw when relevant)
                        try
                        {
                            if (name.Equals("ComSpec", StringComparison.OrdinalIgnoreCase))
                            {
                                if (!raw.EndsWith("cmd.exe", StringComparison.OrdinalIgnoreCase))
                                    info.IsCoreVariableAltered = true;
                            }
                            if (name.Equals("windir", StringComparison.OrdinalIgnoreCase) || name.Equals("SystemRoot", StringComparison.OrdinalIgnoreCase))
                            {
                                var expected = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
                                if (!string.Equals(raw, expected, StringComparison.OrdinalIgnoreCase) && !raw.StartsWith(expected, StringComparison.OrdinalIgnoreCase))
                                    info.IsCoreVariableAltered = true;
                            }

                            // Unusual storage paths
                            if (p.IndexOf("AppData\\Local\\Temp", StringComparison.OrdinalIgnoreCase) >= 0 ||
                                p.IndexOf("C:\\Users\\Public", StringComparison.OrdinalIgnoreCase) >= 0)
                            {
                                info.IsCoreVariableAltered = true; // repurpose flag for anomalous paths
                            }
                        }
                        catch { /* ignore */ }

                        // Build a diagnostic recommendation per-part
                        var recs = new List<string>();
                        if (info.HasUserWritablePaths)
                            recs.Add("Urgent: machine PATH contains directory writable by non-admin users (risk of DLL/exe hijack). Remove or tighten ACLs.");
                        if (info.HasInvalidPaths)
                            recs.Add("Clean: remove dead/invalid path entries to avoid PATH rot.");
                        if (info.IsCoreVariableAltered)
                            recs.Add("Review: core system variable altered or contains unusual locations.");
                        if (info.IsLengthRisk)
                            recs.Add("Warn: PATH length approaching legacy limits; shorten or use directory junctions.");
                        if (info.InferredAuthors.Count > 0)
                            recs.Add($"Author hints: {string.Join(", ", info.InferredAuthors.Distinct().Take(3))}.");

                        info.DiagnosticRecommendation = string.Join(" ", recs);

                        outList.Add(info);
                    }
                }
            }
            catch { /* swallow scope read errors */ }
        }

        private static bool IsUntrustedPrincipal(string account)
        {
            if (string.IsNullOrEmpty(account)) return false;
            account = account.Trim();
            if (account.Equals("Everyone", StringComparison.OrdinalIgnoreCase)) return true;
            if (account.EndsWith("\\Users", StringComparison.OrdinalIgnoreCase)) return true; // BUILTIN\Users
            if (account.IndexOf("Authenticated", StringComparison.OrdinalIgnoreCase) >= 0) return true; // Authenticated Users
            return false;
        }
    }
}
