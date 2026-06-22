
<table border="0">
  <tr>
    <td>
      <!-- VERSION -->v6.06.18<br>
      <!-- DATE -->22-Jun-2026<br>
      Windows<br>
      <a href="https://landenlabs.com/index.html">Home</a>
    </td>
    <td>
      <a href="https://landenlabs.com/index.html">
        <img src="screens/landenlabs.webp" width="300" alt="Logo">
      </a>
    </td>
  </tr>
</table>

# B4-Browse

**B4-Browse** is a small Windows desktop utility that helps you answer two questions before you trust your machine to browse the web:

1. **Is my network configuration safe?** — Confirm there is no rogue proxy in the path and that DNS resolution is not being spoofed or silently redirected.
2. **Has anything changed that shouldn't have?** — Surface files, extensions, programs, processes, services, and drivers that were **modified recently but don't line up with a Windows patch / update date**. A binary that changed last Tuesday when Windows Update didn't run that week is exactly the kind of thing worth a second look.

It runs a Safety Scan on startup and presents its findings in a left-hand navigator grouped into categories — **Network path**, **Recent changes**, **Accounts & usage**, **Protection**, **Browser**, and **Tools**. Each section is sortable and color-coded by its worst finding, and that color rolls up to its category, so anything that needs attention stands out at a glance. Recently-changed items are highlighted so you can quickly separate "this is just last month's patch" from "why did *that* change yesterday?"


---

## What it checks

### 1. Network safety (Safety Scan tab)

The Safety Scan inspects the live network configuration and reports each finding as `PASS` / `INFO` / `WARN`:

- **DNS servers** currently configured on each active adapter.
- **Connected router** — gateway, MAC / OUI vendor, UPnP banner.
- **Actual upstream DNS resolver** — the resolver your queries really reach, its operator/ASN, and whether it matches what you expect (catches DNS hijacking / spoofing).
- **Proxy configuration** — flags any system or per-user proxy in the path.
- **DNS lookup tests** against well-known public sites to confirm answers and latency are sane.
- **Cross-resolver DNS comparison** and Windows Security state (time sync, firewall, etc.).

![Safety Scan — network configuration](screens/scan-1.png)

The whole app supports a **light / dark theme** toggle (bottom-left):

![Safety Scan in dark theme](screens/scan-1-dark.png)

### 2. Recent-change detection (inventory tabs)

The inventory tabs each list items by modification date and tag every row with a **status** so anything unexpected stands out:

| Status | Meaning |
| ------ | ------- |
| **Recent** | Changed within the last **7 days** |
| **Month**  | Changed within the last **30 days** |
| **Old**    | Changed more than **30 days** ago |

The idea is to correlate these dates against your known Windows patch cadence: changes that *don't* correspond to an update are the ones to investigate.

- **Chrome** — Chrome's own executable integrity (path, version, SHA-256, Authenticode signature) plus every enabled extension with its profile, version, manifest version (MV2 extensions are flagged as unsupported on Chrome 138+), and description.

  ![Chrome browser and extensions](screens/chrome-1.png)

- **Installed** — installed program changes, newest first.

  ![Installed program changes](screens/installed-1.png)

- **Processes** — running processes, with an option to show **only unusual (non-Windows) processes** so signed OS components don't drown out the rest.

  ![Running processes](screens/process-1.png)

- **Services** — 3rd-party background services ranked by their `.exe` modify date.

  ![3rd party background services](screens/services-1.png)

- **Startup** — programs that launch at login, by registry-add / executable-modify date.

  ![Startup on login](screens/startup-1.png)

- **Devices** — installed device / driver changes by local INF change date, including signed status and vendor date.

  ![Installed device changes](screens/devices-1.png)

- **DNS** — the live Windows resolver cache (`ipconfig /displaydns`): every name recently resolved and the address it returned. A **public-looking host on a non-public (private/loopback) IP** is flagged `Review` — possibly a redirect / captive portal, or legitimate internal / split-horizon DNS. A **Flush DNS cache** button clears the cache (`ipconfig /flushdns`). Note: it's a live snapshot (entries expire per TTL), and Chrome's Secure DNS (DoH) bypasses this cache.

- **Users** — every local user account (`Get-LocalUser`), flagging the ones worth a look: the built-in **Administrator** or **Guest** enabled, an account **hidden** from the sign-in screen, **recently-created** accounts (a classic backdoor / persistence trick — correlate against the Patches date), and **expired-but-enabled** or **dormant** accounts. Shows each account's administrator membership, last sign-in, and expiry. The **Created** date is best-effort: the true time from the Security audit log (event 4720) when run as Administrator, otherwise the profile folder's age as an approximate first-logon proxy — the *Created src* column says which.

### 3. Right-click actions

Several panels let you **right-click a row** to investigate the item directly:

- **Verify signature (WinVerifyTrust)** — runs an Authenticode signature check on the executable and reports the signer.
- **Look up on VirusTotal (by SHA-256, no upload)** — hashes the file locally and opens its VirusTotal report by hash; the file itself is never uploaded.
- **Search the web** for the app/executable name, **copy the exe / INF / extension path**, or jump to the relevant Windows console (Services, Task Manager, Device Manager, Settings).

Rows also expose an inline **Scan** button for the same verify / lookup actions.

### Helpful links

A built-in **Links** tab collects quick references — Chrome Safety Check, Windows Security, VirusTotal, the Chrome extensions guide, and clean-up / autoruns tools.

![Helpful links](screens/links-1.png)

---

## Usage

- Requires **.NET 10** (`net10.0-windows`).
- Build with Visual Studio or `dotnet build`, then run `B4Browse.exe`. The Safety Scan runs automatically on first show.
- Use **Email this tab (Chrome)** to share a scan result.

### Command-line options

Run with no arguments to launch the GUI. The headless modes run the same checks and print a plain-text report to stdout (useful for scheduled tasks, logging, or piping to a file):

| Invocation | Effect |
| --- | --- |
| `B4Browse.exe` | Launch the GUI (default). |
| `B4Browse.exe --run <scope>` | Run the checks for `<scope>` headless and print a text report. Defaults to `all` if `<scope>` is omitted. |
| `B4Browse.exe --report` | Alias for `--run scan`. |
| `B4Browse.exe --inventory` | Alias for `--run all`. |
| `B4Browse.exe --out <file>` | Also write the report text to `<file>` (headless modes only). |
| `B4Browse.exe --help` | Show usage and exit. Also `-h`, `-?`, `/?`. |

**Scopes:** `scan`, `dns`, `arp`, `rootca`, `firewall`, `patches`, `processes`, `services`, `startup`, `scheduled`, `installed`, `devices`, `winext`, `users`, `activity`, `awake`, `downloads`, `events`, `virus`, `restores`, `chrome`, `settings`, `all`.

```bat
B4Browse.exe --run scan
B4Browse.exe --run events --out events.txt
B4Browse.exe --report
```

> Note: the Security event log requires Administrator to read, so `--run events` (and the Events tab) will omit those entries unless run elevated.

### Publishing a single-file build

`install.bat` produces a self-contained, single-file executable and copies it to `c:\opt\bin`:

```bat
dotnet publish -c Release -r win-x64 --self-contained true /p:PublishSingleFile=true /p:EnableCompressionInSingleFile=true
```

All runtime assets (icon, brand image, theme icon, links page) are embedded in the exe, so the single file is fully portable.

---

## License

Licensed under the **Apache License, Version 2.0**. See [LICENSE](LICENSE) for the full text.

## Author

**Dennis Lang** — LanDen Labs (2026)
<https://github.com/landenlabs/win-b4-browse>
