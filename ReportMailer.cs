using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading;
using System.Windows.Forms;

namespace BrowseSafe
{
    /// <summary>
    /// Emails a report using the user's chosen client:
    ///   - DefaultMailApp: Simple MAPI compose window (report as body + .txt attachment).
    ///   - Gmail / OutlookWeb: a web compose URL opened in the chosen browser.
    /// Always saves a copy to a temp file and to the clipboard as a fallback.
    /// </summary>
    public static class ReportMailer
    {
        public static void Send(Form owner, string scope, string tabName, AppSettings settings)
        {
            string text;
            try { (text, _) = Reports.Build(scope); }
            catch (Exception ex)
            {
                MessageBox.Show(owner, "Could not build report: " + ex.Message, "Email report",
                    MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            string file = Path.Combine(Path.GetTempPath(),
                $"browse-safe-{scope}-{DateTime.Now:yyyyMMdd-HHmmss}.txt");
            string? savedTo = null;
            try { File.WriteAllText(file, text); savedTo = file; } catch { /* non-fatal */ }
            try { Clipboard.SetText(text); } catch { /* clipboard may be busy */ }

            string subject = $"Browse Safe report - {tabName} - {DateTime.Now:yyyy-MM-dd HH:mm}";

            switch (settings.EmailMethod)
            {
                case EmailMethod.Gmail:
                    OpenWeb(owner, GmailUrl(subject, text), settings.EmailBrowser);
                    break;
                case EmailMethod.OutlookWeb:
                    OpenWeb(owner, OutlookUrl(subject, text), settings.EmailBrowser);
                    break;
                default:
                    // Desktop mail client: full report in the body AND attached.
                    SendViaMapi(owner, subject, text, savedTo);
                    break;
            }
        }

        // Max total URL length we dare pass on the launch command line (OS limit ~32767).
        private const int MaxUrl = 30000;

        /// <summary>
        /// URL-encodes the whole report as the compose body, only trimming if the
        /// resulting URL would exceed the command-line limit (rare). The full report
        /// is always on the clipboard as a backup.
        /// </summary>
        private static string FitBody(string text, string baseUrl)
        {
            string enc = Uri.EscapeDataString(text);
            if (baseUrl.Length + enc.Length <= MaxUrl) return enc;

            const string note = "\r\n\r\n[Report truncated for the browser - the full report is on your clipboard; press Ctrl+V to paste it.]";
            int raw = text.Length;
            while (raw > 0)
            {
                string candidate = text.Substring(0, raw) + note;
                enc = Uri.EscapeDataString(candidate);
                if (baseUrl.Length + enc.Length <= MaxUrl) return enc;
                raw -= 1000;
            }
            return Uri.EscapeDataString(note);
        }

        // ---- Web compose ------------------------------------------------- //
        private static void OpenWeb(Form owner, string url, BrowserChoice browser)
        {
            try { OpenInBrowser(url, browser); }
            catch (Exception ex)
            {
                MessageBox.Show(owner, "Could not open the browser: " + ex.Message, "Email report",
                    MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
        }

        private static void OpenInBrowser(string url, BrowserChoice browser)
        {
            string? exe = browser switch
            {
                BrowserChoice.Chrome => "chrome.exe",
                BrowserChoice.Firefox => "firefox.exe",
                BrowserChoice.Edge => "msedge.exe",
                _ => null,
            };
            try
            {
                if (exe != null)
                {
                    Process.Start(new ProcessStartInfo(exe) { Arguments = url, UseShellExecute = true });
                    return;
                }
            }
            catch { /* fall through to default browser */ }
            Process.Start(new ProcessStartInfo(url) { UseShellExecute = true });
        }

        private static string GmailUrl(string subject, string text)
        {
            string baseUrl = "https://mail.google.com/mail/?view=cm&fs=1" +
                             $"&su={Uri.EscapeDataString(subject)}&body=";
            return baseUrl + FitBody(text, baseUrl);
        }

        private static string OutlookUrl(string subject, string text)
        {
            string baseUrl = "https://outlook.office.com/mail/deeplink/compose?" +
                             $"subject={Uri.EscapeDataString(subject)}&body=";
            return baseUrl + FitBody(text, baseUrl);
        }

        // ---- Simple MAPI (default desktop mail client) ------------------- //
        private const int MAPI_LOGON_UI = 0x00000001;
        private const int MAPI_DIALOG = 0x00000008;
        private const int SUCCESS_SUCCESS = 0;
        private const int MAPI_USER_ABORT = 1;

        private static void SendViaMapi(Form owner, string subject, string body, string? attachment)
        {
            // MAPI compose blocks until send/cancel, so run it off the UI thread (STA).
            var t = new Thread(() =>
            {
                int err = MapiCompose(subject, body, attachment);
                if (err != SUCCESS_SUCCESS && err != MAPI_USER_ABORT && owner.IsHandleCreated)
                {
                    owner.BeginInvoke(new Action(() => MessageBox.Show(owner,
                        $"Could not open your default mail client (MAPI code {err}).\n\n" +
                        (attachment != null ? $"The report was saved to:\n{attachment}\n\n" : "") +
                        "It has also been copied to the clipboard.\n\n" +
                        "Tip: use the email dropdown to pick Gmail or Outlook (web) instead.",
                        "Email report", MessageBoxButtons.OK, MessageBoxIcon.Warning)));
                }
            });
            t.IsBackground = true;
            t.SetApartmentState(ApartmentState.STA);
            t.Start();
        }

        private static int MapiCompose(string subject, string body, string? attachment)
        {
            var msg = new MapiMessage { Subject = subject, NoteText = body };
            IntPtr fileBuf = IntPtr.Zero;
            try
            {
                if (attachment != null && File.Exists(attachment))
                {
                    var fd = new MapiFileDesc { Position = -1, Path = attachment, Name = Path.GetFileName(attachment) };
                    fileBuf = Marshal.AllocHGlobal(Marshal.SizeOf<MapiFileDesc>());
                    Marshal.StructureToPtr(fd, fileBuf, false);
                    msg.FileCount = 1;
                    msg.Files = fileBuf;
                }
                return MAPISendMail(IntPtr.Zero, IntPtr.Zero, msg, MAPI_LOGON_UI | MAPI_DIALOG, 0);
            }
            catch { return -1; }
            finally
            {
                if (fileBuf != IntPtr.Zero)
                {
                    Marshal.DestroyStructure<MapiFileDesc>(fileBuf);
                    Marshal.FreeHGlobal(fileBuf);
                }
            }
        }

        [DllImport("MAPI32.DLL", CharSet = CharSet.Ansi)]
        private static extern int MAPISendMail(IntPtr session, IntPtr hwnd, MapiMessage message, int flags, int reserved);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
        private sealed class MapiMessage
        {
            public int Reserved;
            public string? Subject;
            public string? NoteText;
            public string? MessageType;
            public string? DateReceived;
            public string? ConversationID;
            public int Flags;
            public IntPtr Originator;
            public int RecipCount;
            public IntPtr Recips;
            public int FileCount;
            public IntPtr Files;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
        private struct MapiFileDesc
        {
            public int Reserved;
            public int Flags;
            public int Position;
            public string? Path;
            public string? Name;
            public IntPtr Type;
        }
    }
}
