---
title: Privacy Policy
---

# B4-Browse Privacy Policy

**Effective date:** November 15, 2026
**Publisher:** LanDen Labs

B4-Browse is a Windows desktop utility that checks whether your network and PC are in a safe
state before you browse. This policy explains what the app looks at, what leaves your computer,
and what is stored.

## Summary

- B4-Browse has **no accounts, no analytics, no advertising and no telemetry**.
- LanDen Labs **does not collect, receive or store any of your data**. There is no B4-Browse
  server.
- Scan results stay on your PC unless **you** choose to copy, print or email them.
- To do its checks, the app makes some network requests to well-known public services. These
  are listed below so you know exactly what is sent.

## Information the app reads on your PC

To find problems, B4-Browse reads system information locally, including network and DNS
settings, the hosts file, the ARP cache, installed programs, running processes, services,
drivers, startup entries, scheduled tasks, shell extensions, firewall rules, Windows event logs,
Microsoft Defender status and history, System Restore points, disk partition layout and Windows
Recovery Environment status, local user accounts, app usage records kept by Windows, and Google
Chrome settings, extensions and profile metadata.

This information is shown to you in the app and **is not sent to LanDen Labs or anyone else**,
except for the specific items listed in the next section.

## Network requests the app makes

| Purpose | Service contacted | What is sent |
| --- | --- | --- |
| DNS safety checks (spoofing, hijacking, cross-resolver comparison) | Your configured DNS servers and public resolvers such as Google (8.8.8.8), Cloudflare (1.1.1.1) and Quad9 (9.9.9.9) | Standard DNS lookups for common, well-known domain names (for example `www.google.com`, `www.microsoft.com`) |
| Find the DNS resolver your traffic actually uses | Akamai and Google "whoami" DNS names (`whoami.akamai.net`, `o-o.myaddr.l.google.com`) | Standard DNS lookups |
| Name the operator of that resolver | [ip-api.com](https://ip-api.com/) | The IP address of the DNS resolver (not your PC's address, although the service sees your public IP as with any web request) |
| Identify router and network-device makers | [macvendors.com](https://macvendors.com/) | The manufacturer prefix (first half) of a device's network hardware address, never the full address |
| Discover your router's model | Your local router (UPnP/SSDP, on your own network only) | A standard local discovery request |
| Check that your clock is correct | NTP time servers (`time.nist.gov`, `time.cloudflare.com`, `time.google.com`) and `www.cloudflare.com` | A standard time request |
| Check whether Chrome is up to date | Google's Chrome version-history API (`versionhistory.googleapis.com`) | A request for the current stable version number; nothing about your PC |
| Check for B4-Browse updates (only when you click it in **About**) | GitHub (`api.github.com`) | A request for the latest release |

As with any internet request, these services can see your public IP address and the time of the
request. Their own privacy policies apply to them. B4-Browse does not send your name, your files,
your scan results or any identifier for your PC.

## Actions you choose to take

Some features open your web browser or another program only when you click them:

- **Search the web** for an item (for example, a process or service name) opens a search page
  with that name.
- **Look up on VirusTotal** opens VirusTotal with the file's SHA-256 fingerprint. The file
  itself is **never uploaded**.
- **Email this tab** copies the report to your clipboard and opens a Gmail draft in your browser.
  Nothing is sent until you paste the report and send the email yourself.
- **Copy** and **Print** work only on your PC.
- **Help links** open Microsoft, Google or other documentation pages.

## Information stored on your PC

B4-Browse keeps a small amount of data in `%LOCALAPPDATA%\B4Browse`:

- Your preferences: theme and display scale (`theme.txt`, `scale.txt`), the Chrome location you
  chose if you overrode auto-detection (`chrome-path.txt`), and whether you turned off the Chrome
  tip (`chrome-hint-off.txt`).
- Scan history (`history.json`): one entry per day, at most 100, holding only **counts** (for
  example, the number of installed programs, services or partitions), so the app can show what
  changed since the last scan. It does not store names, file paths or other details.
- A partition baseline (`partitions.json`), so the Partitions tab can tell when a disk partition
  was created, resized or removed. For each partition on your internal disks it stores the disk
  model name and the disk's and partition's identifiers (GUIDs), plus the partition's type,
  position, size, hidden flag, and the dates it was first seen and last changed. It also stores
  whether the Windows Recovery Environment is enabled. These identifiers are specific to your
  disks, but they never leave your PC.
- Crash and error logs (`logs\b4browse.log`), used only to show you what went wrong.

Exporting or emailing a report also writes a text copy to your Windows temporary folder.

This data never leaves your PC. To delete it, uninstall the app or delete the
`%LOCALAPPDATA%\B4Browse` folder.

## Children

B4-Browse is a general-purpose utility. It is not directed at children and collects no personal
information from anyone.

## Changes to this policy

If the app's behavior changes in a way that affects privacy, this page will be updated and the
effective date above will change. The history of this page is public on
[GitHub](https://github.com/landenlabs/win-b4browse/commits/main/docs/privacy.md).

## Contact

For questions about this policy, open an issue at
[github.com/landenlabs/win-b4browse/issues](https://github.com/landenlabs/win-b4browse/issues).
