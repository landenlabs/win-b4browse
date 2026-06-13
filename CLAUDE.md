# B4 Browse — project index

Windows desktop utility (C# WinForms) that verifies the network and OS are in a safe
state before browsing. Two jobs: (1) confirm the network path is clean — no rogue proxy,
no DNS hijack/spoof; (2) surface files/extensions/programs/processes/services/drivers that
changed recently but don't line up with a Windows patch date. Runs a Safety Scan on startup
and presents results across sortable, color-coded tabs. Also runs headless to print a
plain-text report. See `README.md` for the user-facing feature tour.

- **Framework:** .NET 10 (`net10.0-windows`), WinForms, nullable + implicit usings enabled.
- **Namespace / assembly:** `B4Browse`. Single project, flat directory (no subfolders).
- **Author:** Dennis Lang — LanDen Labs (2026). Apache-2.0.

## Build & run

```pwsh
dotnet build                       # or open B4Browse.sln in Visual Studio
dotnet run                         # launch the GUI (Safety Scan runs on first show)
B4Browse.exe --run <scope>       # headless: run checks, print text report to stdout
B4Browse.exe --report            # alias for --run scan
B4Browse.exe --inventory         # alias for --run all
B4Browse.exe --run events --out events.txt   # also write report to a file
```

Scopes: `scan, dns, arp, patches, chrome, settings, services, processes, startup, scheduled,
installed, devices, winext, events, activity, downloads, firewall, virus, restores, users, all` (the
catalog in `Reports.cs` is the source of truth). `events` needs Administrator to read the Security log;
`downloads` needs Administrator to read the SRUM database; `virus` reads protection state without
elevation but needs Administrator for the Defender threat/scan history (the event log); `users` lists
local accounts without elevation but needs Administrator for true creation dates (Security event 4720;
otherwise the profile-folder age is used as an approximate first-logon proxy).

`install.bat` publishes a self-contained single-file exe (`win-x64`) and copies it to
`c:\opt\bin`. All runtime assets (icon, brand images, links page) are embedded, so the
single file is portable.

## Architecture

The whole app is built on one small data model and a single declarative catalog:

- **`CheckResult.cs`** — the model. `CheckStatus` enum (`Pass/Warn/Fail/Info`),
  `CheckResult` (one line: status + name + detail, or a pre-formatted `Table` row), and
  `CheckGroup` (a titled list of results; `Worst()` rolls up severity, table rows excluded).
- **`SafetyChecks`** — all diagnostic logic, a `static partial class` split across 15
  files (see below). Every public `CheckXxx()` method returns a populated `CheckGroup`
  and is safe to call from a background thread.
- **`Catalog.cs`** — **the single source of truth for everything the app surfaces.** A flat
  `Section[]` (grouped by `Category`), each carrying its nav `Title`, scope `Key`, `Banner`,
  `ReportTitle`, `AdminOnly` flag, headless `Producers` (`Func<CheckGroup>[]`), and GUI
  `BuildView` factory (`Func<Control>`). **Add a feature by adding one `Section` row here** —
  it then appears automatically in the tree nav (`MainForm`), the headless `--run` scopes and
  the `all` report (`Reports`), the severity roll-up, and email/copy/print. Adding a browser is
  purely additive (register per-browser sections under the `Browser` category). Sections with no
  `Producers` (Links, Windows Security) are GUI-only.
- **`Reports.cs`** — runs the `Catalog` sections' producers for a scope and formats the
  plain-text report (isolating each check so one failure becomes a `[FAIL]` line, not an
  abort). Shared by the headless runner and the email feature. GUI-only sections are excluded.
- **`Program.cs`** — entry point. Parses `--run/--report/--inventory/--out/--help`;
  headless paths call `Reports.Build`. GUI path loads `Theme` then runs `MainForm`.
  Re-attaches to the parent console (`AttachConsole`) so a WinExe app can print headless
  output to the terminal.

### UI layer
- **`MainForm.cs`** — main window: verdict banner, toolbar (Launch Chrome, Email/Copy/Print),
  and a left **category tree** (`TreeView`, built from `Catalog` and grouped by category) that
  selects sections into a content host. The tree is owner-drawn and severity-tinted: each
  section row colours by its worst state and each category row rolls up the worst of its
  sections. Section views are built lazily, cached, and run on first show. The Intro button is
  pinned above the tree; theme toggle + About below it; Links and Windows Security are a "Tools"
  category.
- **`ResultsView.cs`** — a single tab: runs its set of checks on a background thread and
  renders the resulting `CheckGroup`s.
- **`TabViews.cs`** — the large file (per-tab grid construction + right-click context
  menus: verify signature, VirusTotal-by-hash, copy path, open the relevant Windows
  console, etc.). One `ShowXxxMenu` per item type.
- **`SortableGrid.cs`** — custom sortable, themeable grid control used by the tabs.
- **`TabHelp.cs` / `TabSeverity.cs` / `Help.cs` / `AboutForm.cs` / `BusyOverlay.cs`** —
  per-tab help text, severity legend, help/about dialogs, busy overlay.
- **`ErrorLogDialog.cs`** — modal viewer for `ErrorLog`: a themed ListView of background-action
  failures (time / category / source / message + detail), Copy/Clear, live-refreshes while open.
  Opened from the `⚠ N errors` badge in the `MainForm` status bar (hidden at 0).
- **`Theme.cs`** — light/dark theme (toggle bottom-left); loaded before any window shows.

### SafetyChecks partials (the checks)
| File | Produces |
| --- | --- |
| `SafetyChecks.cs` | DNS servers, lookups, cross-resolver, email DNS, well-known resolver table |
| `SafetyChecks.Network.cs` | Router/gateway, upstream resolver, proxy, hosts file |
| `SafetyChecks.Posture.cs` | Time sync, Windows Security state |
| `SafetyChecks.System.cs` | OS / patch posture |
| `SafetyChecks.DnsCache.cs` | Live resolver cache (`ipconfig /displaydns`) + flush |
| `SafetyChecks.Arp.cs` | ARP cache |
| `SafetyChecks.ChromePrefs.cs` | Chrome exe integrity, privacy prefs, extensions |
| `SafetyChecks.ChromeSettings.cs` | Chrome settings matrix (settings × profiles + policy Global col) — the Settings tab |
| `SafetyChecks.Inventory.cs` | Services, processes, startup, installed, devices (largest) |
| `SafetyChecks.Scheduled.cs` | Task Scheduler entries + hijack audit (Temp/LOLBin/hidden) — the Scheduled tab |
| `SafetyChecks.Winget.cs` | winget-sourced install metadata |
| `SafetyChecks.WinExt.cs` | Shell / context-menu extensions |
| `SafetyChecks.Firewall.cs` | Firewall state + rules |
| `SafetyChecks.Events.cs` | Windows Event Log entries |
| `SafetyChecks.Activity.cs` | App launch counts (Windows Search `AppsIndex.db`) + PCA last-run merge |
| `SafetyChecks.Sru.cs` | Per-app network bytes sent/received from SRUM (`SRUDB.dat`, via esentutl + ManagedEsent) — the Downloads tab |
| `SafetyChecks.Defender.cs` | Defender protection state (WMI `MSFT_MpComputerStatus`) + threat/scan history (Defender Operational event log) — the Virus tab |
| `SafetyChecks.SecurityCenter.cs` | Windows Security Center (`root\SecurityCenter2`) registered antivirus/firewall products — feeds the Virus tab (alternate AV, e.g. CrowdStrike) and the Firewall tab (third-party firewall provider) |
| `SafetyChecks.Restore.cs` | System Restore points |
| `SafetyChecks.Users.cs` | Local user accounts (`Get-LocalUser`) + Administrators membership, hidden/`SpecialAccounts`, layered creation date (event 4720 → profile-folder ctime → unknown) — the Users tab |

### Row model / DTO classes
One small record-like class per item type, consumed by the grids:
`AppActivity`, `ArpEntry`, `ChromeExtension`, `DeviceDriver`, `DnsCacheEntry`, `EventItem`,
`FirewallRule`, `InstalledProgram`, `ProcessItem`, `RestorePoint`, `ScheduledTaskItem`,
`ServiceInfo`, `ShellExtension`, `SruNetUsage`, `StartupItem`, `UserAccount`. The Settings tab uses a small matrix model
instead (`ChromeSettingsMatrix.cs`: `ChromeSettingsMatrix` / `SettingRow` / `ColumnDef`). The
Virus tab uses `DefenderModels.cs`: `DefenderStatusSummary` (WMI state), `ThreatDetectionRecord` /
`ScanHistoryRecord` (parsed events), and `DefenderTimelineRow` (the merged grid row).

### Helpers
- `Elevation.cs` — admin/elevation detection.
- `EmbeddedAssets.cs` — load embedded icon/images (works inside the single-file exe).
- `InfAnalyzer.cs` — parse/analyze driver `.inf` files (driver tab "Analyze INF").
- `ReportMailer.cs` — "Email this tab (Chrome)".
- `ShellExtension.cs` — shell-extension lookup support.
- `ErrorLog.cs` — process-wide, thread-safe, bounded in-memory sink for background-action
  failures (`ErrorCategory` Timeout/ParseError/Error, `ErrorEntry`, `Changed` event,
  `Count`/`Snapshot`/`Clear`). No-throw, so logging never perturbs the failure it records. The
  three diagnostic runners (`RunPowerShellJson`, `RunPowerShellArray`, `RunCapture`) and the
  `Reports.Build` producer-exception catch feed it; viewed via `ErrorLogDialog`.

## Versioning — keep in sync

Version lives in several places; **do not hand-edit them individually**.
`set-version.ps1` is the single source that rewrites all of them on release:
- `AppInfo.cs` (`Version`, `BuildDate`, `Copyright`) — guarded by the `AUTO-VERSION` marker comment.
- `VERSION` file, `README.md` `<!-- VERSION -->` / `<!-- DATE -->` markers.
- `B4Browse.csproj` `<Version>` / `<Copyright>` (drive the exe's file/product version).

`AppInfo` is the runtime source for the version shown in-app.

## Conventions
- Files are flat in the repo root, one top-level type per file, `B4Browse` namespace.
- Each check is self-contained and exception-isolated — a failing check returns a
  `Fail` result rather than throwing across the report.
- Background-action failures (an agent that times out, writes stderr, exits non-zero, or
  returns unparseable output) are recorded to `ErrorLog` instead of being swallowed by the
  runners' `return null`. A script that legitimately returns nothing (exit 0, no stderr) is
  **not** logged — only real failures are, so the `⚠ N errors` badge stays meaningful. The GUI
  surfaces them via the badge → `ErrorLogDialog`; headless `--run` flushes them to stderr.
- Headless progress goes to **stderr**, the report to **stdout** (so stdout stays clean).
- Dependencies: `System.Management` (WMI), `Microsoft.Data.Sqlite` (reads the Windows
  Search `AppsIndex.db` for the Activity tab — its bundled native SQLite supplies the FTS5
  module that database needs — and counts rows in Chrome's `Login Data` for the Settings
  tab), and `ManagedEsent` (reads the SRUM ESE database `SRUDB.dat` for the Downloads tab)
  are the only NuGet packages.
