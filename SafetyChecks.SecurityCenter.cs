// Copyright (c) 2026 LanDen Labs - Dennis Lang

using System;
using System.Collections.Generic;

namespace B4Browse
{
    /// <summary>
    /// Windows Security Center (<c>root\SecurityCenter2</c>) product registry: the authoritative
    /// list of antivirus and firewall products Windows recognises as protecting this machine. A
    /// third-party product (CrowdStrike Falcon, ZoneAlarm, ...) registers here and, when it is the
    /// active provider, puts Microsoft Defender / Windows Defender Firewall into passive mode -
    /// which is why the Defender-only WMI status can read "off" while the system is in fact
    /// protected. Reading this surfaces the real provider. No elevation required. The namespace
    /// exists only on client SKUs, so on Windows Server / unusual builds the query returns nothing.
    /// </summary>
    public static partial class SafetyChecks
    {
        /// <summary>A single product registered with the Windows Security Center.</summary>
        private sealed class ScProduct
        {
            public string Name = "";
            public string Path = "";
            public bool Enabled;        // active per the WSC productState bitmask
            public bool? UpToDate;      // signatures current (antivirus only; null = unknown / N-A)
            public bool IsDefender;     // the built-in Microsoft product
        }

        private static readonly object _scLock = new();
        private static readonly Dictionary<string, (List<ScProduct> Items, long Tick)> _scCache = new();

        /// <summary>
        /// Lists the products registered under a Security Center class - "AntiVirusProduct" or
        /// "FirewallProduct". Each carries its display name, signed exe path, and an enabled flag
        /// decoded from the WSC productState bitmask. Cached briefly per class so a single tab
        /// refresh that asks twice launches PowerShell once. Never throws; returns an empty list
        /// on any failure (namespace absent, query blocked, no products registered).
        /// </summary>
        private static List<ScProduct> GetSecurityCenterProducts(string className)
        {
            lock (_scLock)
            {
                if (_scCache.TryGetValue(className, out var c) &&
                    Environment.TickCount64 - c.Tick < 15_000)
                    return c.Items;
                var items = ReadSecurityCenterProducts(className);
                _scCache[className] = (items, Environment.TickCount64);
                return items;
            }
        }

        private static List<ScProduct> ReadSecurityCenterProducts(string className)
        {
            var list = new List<ScProduct>();
            bool isAv = className.Equals("AntiVirusProduct", StringComparison.OrdinalIgnoreCase);

            // className is one of two fixed internal literals, so direct interpolation is safe.
            string script =
                "$ErrorActionPreference='SilentlyContinue'; " +
                $"@(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName {className} | " +
                "Select-Object displayName,productState,pathToSignedProductExe) | " +
                "ConvertTo-Json -Compress -Depth 3";

            foreach (var r in RunPowerShellArray(script))
            {
                string name = Str(r, "displayName").Trim();
                if (name.Length == 0) continue;
                int state = JInt(r, "productState");

                // WSC productState is a 3-byte bitmask (0xAABBCC): the middle byte BB encodes the
                // on/off state (0x10 / 0x11 = enabled) and the low byte CC the signature freshness
                // (0x00 = up to date, 0x10 = out of date). Firewall products use the same enabled
                // encoding; their freshness byte is not meaningful.
                int mid = (state >> 8) & 0xFF;
                int low = state & 0xFF;

                list.Add(new ScProduct
                {
                    Name = name,
                    Path = Str(r, "pathToSignedProductExe").Trim(),
                    Enabled = mid is 0x10 or 0x11,
                    UpToDate = isAv ? (low == 0x00 ? true : low == 0x10 ? false : (bool?)null) : null,
                    IsDefender = name.Contains("Defender", StringComparison.OrdinalIgnoreCase) ||
                                 name.Contains("Windows Security", StringComparison.OrdinalIgnoreCase),
                });
            }
            return list;
        }
    }
}
