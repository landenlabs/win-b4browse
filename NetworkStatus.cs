// Copyright (c) 2026 LanDen Labs - Dennis Lang

using System;
using System.Diagnostics;
using System.Net.NetworkInformation;

namespace BrowseSafe
{
    /// <summary>
    /// Network availability helper. Used to short-circuit network-dependent tabs
    /// (e.g. the Safety Scan) when the machine is offline, and to drive the status-bar
    /// connectivity indicator.
    /// </summary>
    public static class NetworkStatus
    {
        /// <summary>Settings page where airplane mode / network access is managed.</summary>
        public const string SettingsUri = "ms-settings:network-airplanemode";

        /// <summary>
        /// True when at least one non-loopback, non-tunnel adapter is up - mirroring the
        /// adapter filtering used by the safety checks. Fails open (returns true) if probing
        /// throws, so a detection glitch never blocks the checks.
        /// </summary>
        public static bool IsAvailable()
        {
            try
            {
                if (!NetworkInterface.GetIsNetworkAvailable()) return false;
                foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (nic.OperationalStatus != OperationalStatus.Up) continue;
                    if (nic.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;
                    if (nic.NetworkInterfaceType == NetworkInterfaceType.Tunnel) continue;
                    return true;
                }
                return false;
            }
            catch { return true; }
        }

        /// <summary>Opens the Windows Settings page for airplane mode / network access.</summary>
        public static void OpenSettings()
        {
            try { Process.Start(new ProcessStartInfo(SettingsUri) { UseShellExecute = true }); }
            catch { /* ignore - settings app unavailable */ }
        }
    }
}
