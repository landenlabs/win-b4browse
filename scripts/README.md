# B4-Browse - data-collection scripts

A generated snapshot of every PowerShell script and external command B4-Browse
runs to gather the information shown in each section - one file per originating check,
so you can see exactly *how* each piece of information is collected. All of them only
read system state; none change your PC.

Back to the [main README](../README.md) · [Privacy policy](../docs/privacy.md)

- `*.ps1` - PowerShell, run through `powershell.exe` (`-NoProfile -NonInteractive`,
  encoded). The file shows the readable script, not the base64 form.
- `*.txt` - external commands (e.g. `winget`).

Each file is a snapshot from the machine it was generated on, so values embedded in a
script (paths, adapter names) may differ on yours.

Not every section is script-driven: some collect data through native .NET APIs and so
have nothing to dump here - for example **Downloads** reads the SRUM ESE database
(`SRUDB.dat`) directly, **Virus** queries Defender over WMI (`MSFT_MpComputerStatus`),
**Activity** reads the Windows Search SQLite database, **Firewall** reads the registry
rule stores, and **Chrome** / **Settings** read Chrome's profile files. See the source
(`SafetyChecks.*.cs`) for those.

## Regenerate

```
B4Browse.exe --dump-scripts scripts
```

This runs every check (the same as `--run all`), including the network checks listed
in the privacy policy. Run from an elevated prompt to also capture the
Administrator-only checks (Security event log, SRUM downloads, Defender history, true
user creation dates); otherwise those checks return early and emit no script.

## Files

| File | Originating check | Type |
| --- | --- | --- |
| `GetAdministratorMemberSids.ps1` | `GetAdministratorMemberSids` | PowerShell |
| `GetArpTable.ps1` | `GetArpTable` | PowerShell |
| `GetDevices.ps1` | `GetDevices` | PowerShell |
| `GetDnsCache.ps1` | `GetDnsCache` | PowerShell |
| `GetEventLogIssues.ps1` | `GetEventLogIssues` | PowerShell |
| `GetInstalledPrograms.ps1` | `GetInstalledPrograms` | PowerShell |
| `GetProcesses.ps1` | `GetProcesses` | PowerShell |
| `GetRootCerts.ps1` | `GetRootCerts` | PowerShell |
| `GetScheduledTasks.ps1` | `GetScheduledTasks` | PowerShell |
| `GetServices.ps1` | `GetServices` | PowerShell |
| `GetUserAccounts.ps1` | `GetUserAccounts` | PowerShell |
| `QueryAdapters.ps1` | `QueryAdapters` | PowerShell |
| `QueryPowerShellSecurity.ps1` | `QueryPowerShellSecurity` | PowerShell |
| `QueryPromiscuousState.ps1` | `QueryPromiscuousState` | PowerShell |
| `QueryServerAll.ps1` | `QueryServerAll` | PowerShell |
| `QueryWlanInterfaces.txt` | `QueryWlanInterfaces` | command |
| `ReadPowerEvents.ps1` | `ReadPowerEvents` | PowerShell |
| `ReadSecurityCenterProducts.ps1` | `ReadSecurityCenterProducts` | PowerShell |
| `ResolveMx.ps1` | `ResolveMx` | PowerShell |
| `ResolveShortcuts.ps1` | `ResolveShortcuts` | PowerShell |
| `ResolveTxt.ps1` | `ResolveTxt` | PowerShell |
| `RunWingetList.txt` | `RunWingetList` | command |
| `VerifyAuthenticode.ps1` | `VerifyAuthenticode` | PowerShell |
