// Copyright (c) 2026 LanDen Labs - Dennis Lang

using System;
using System.Diagnostics;
using System.IO;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace B4Browse
{
    /// <summary>
    /// Emails a report by opening a Gmail compose window in Chrome with the report
    /// as the body. The report is built on a background thread; a copy is also saved
    /// to a temp file and the clipboard as a backup.
    /// </summary>
    public static class ReportMailer
    {
        public static async Task SendAsync(Form owner, string scope, string tabName)
        {
            (string Text, CheckStatus Overall) report;
            try { report = await Task.Run(() => Reports.Build(scope)); }
            catch (Exception ex)
            {
                CopyableMessageBox.Show(owner, "Could not build report: " + ex.Message, "Email report",
                    MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            string file = Path.Combine(Path.GetTempPath(),
                $"b4-browse-{scope}-{DateTime.Now:yyyyMMdd-HHmmss}.txt");
            try { await Task.Run(() => File.WriteAllText(file, report.Text)); } catch { /* non-fatal */ }
            try { Clipboard.SetText(report.Text); } catch { /* clipboard may be busy */ }

            // Gmail's compose URL rejects long bodies with HTTP 400, so the body is a short
            // summary + instruction; the full report is on the clipboard, ready to paste.
            string subject = $"B4-Browse report - {tabName} - {DateTime.Now:yyyy-MM-dd HH:mm}";
            string body = ShortBody(tabName, report.Overall);
            string url = "https://mail.google.com/mail/?view=cm&fs=1" +
                         $"&su={Uri.EscapeDataString(subject)}&body={Uri.EscapeDataString(body)}";
            OpenInChrome(owner, url);
        }

        private static string ShortBody(string tabName, CheckStatus overall)
        {
            string verdict = overall switch
            {
                CheckStatus.Fail => "NOT SAFE - resolve the FAIL items before browsing.",
                CheckStatus.Warn => "CAUTION - review the WARN items.",
                _ => "OK - no failures.",
            };
            return
                $"B4-Browse report - {tabName}\r\n" +
                $"Verdict: {verdict}\r\n\r\n" +
                "The full report is on your clipboard.\r\n" +
                "Click in the message body and press Ctrl+V to paste it here, then send.";
        }

        private static void OpenInChrome(Form owner, string url)
        {
            string? chrome = SafetyChecks.ChromeExePath();
            try
            {
                Process.Start(new ProcessStartInfo(chrome ?? "chrome.exe") { Arguments = url, UseShellExecute = true });
            }
            catch
            {
                try { Process.Start(new ProcessStartInfo(url) { UseShellExecute = true }); } // default browser
                catch (Exception ex)
                {
                    CopyableMessageBox.Show(owner, "Could not open Chrome: " + ex.Message, "Email report",
                        MessageBoxButtons.OK, MessageBoxIcon.Warning);
                }
            }
        }
    }
}
