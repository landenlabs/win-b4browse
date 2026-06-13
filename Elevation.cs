// Copyright (c) 2026 LanDen Labs - Dennis Lang

using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Security.Principal;

namespace B4Browse
{
    /// <summary>
    /// Administrator-elevation helpers. The app ships with an <c>asInvoker</c> manifest, so it
    /// runs unelevated by default and elevates only on demand (the "Run as Admin" button), which
    /// relaunches it through UAC. Admin is required for the Restore Points tab.
    /// </summary>
    public static class Elevation
    {
        /// <summary>True when the current process is running with administrator rights.</summary>
        public static bool IsAdmin { get; } = ComputeIsAdmin();

        private static bool ComputeIsAdmin()
        {
            try
            {
                using var id = WindowsIdentity.GetCurrent();
                return new WindowsPrincipal(id).IsInRole(WindowsBuiltInRole.Administrator);
            }
            catch { return false; }
        }

        /// <summary>
        /// Relaunches this executable elevated via the UAC "runas" verb. Returns true if the new
        /// (elevated) process started - the caller should then exit this instance. Returns false
        /// when the user declines the UAC prompt or the launch otherwise fails.
        /// </summary>
        public static bool RelaunchAsAdmin()
        {
            string? exe = Environment.ProcessPath;
            if (string.IsNullOrEmpty(exe)) return false;

            var psi = new ProcessStartInfo
            {
                FileName = exe,
                UseShellExecute = true,   // required for the shell verb
                Verb = "runas",
            };
            try { Process.Start(psi); return true; }
            catch (Win32Exception) { return false; }   // user cancelled the UAC prompt
            catch { return false; }
        }
    }
}
