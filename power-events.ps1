<#
  power-events.ps1  --  B4-Browse scratch / evaluation tool (NOT part of the app build).

  Lists the raw Windows power-state events (boot / wake / sleep / hibernate / modern standby /
  shutdown / unexpected power loss) from the System event log, newest first, so you can see
  exactly what the OS recorded and correlate it against the app's "Awake" tab.

  Unlike the app's current Awake tab, this does NO pairing and NO debouncing - every recorded
  transition is shown, including the dirty-power-off signals (Kernel-Power 41, EventLog 6008)
  that a long power-button hold produces. Everything here is read-only and needs no elevation
  (the System log is readable by standard users).

  Usage:
    powershell -ExecutionPolicy Bypass -File .\power-events.ps1
    powershell -ExecutionPolicy Bypass -File .\power-events.ps1 -Days 3
    powershell -ExecutionPolicy Bypass -File .\power-events.ps1 -Days 2 -Raw   # also print full messages
#>

[CmdletBinding()]
param(
    [int]$Days = 14,     # how far back to look
    [switch]$Raw         # also dump each event's first message line
)

$ErrorActionPreference = 'SilentlyContinue'

# Power-relevant System-log event IDs. Some (12/13) are reused by other providers, so the
# Classify function below only honours each id from the provider that legitimately owns it.
$ids   = 41, 1, 42, 107, 506, 507, 12, 13, 1074, 6005, 6006, 6008
$start = (Get-Date).AddDays(-$Days)

function Get-WakeSource {
    param([string]$msg)
    $m = [regex]::Match($msg, 'Wake Source:\s*(.+)')
    if ($m.Success) { return ($m.Groups[1].Value -split "`r?`n")[0].Trim() }
    return ''
}

function Get-Reason {
    # Kernel-Power Modern Standby (506/507) and sleep (42) messages carry "Reason: <X>"
    # (Lid / Input Mouse / Power Button / Idle Timeout / Screen Off Request / ...).
    param([string]$msg)
    $m = [regex]::Match($msg, 'Reason:\s*(.+)')
    if ($m.Success) { return (($m.Groups[1].Value -split "`r?`n")[0].Trim()).TrimEnd('.') }
    return ''
}

function Classify {
    param($e)
    $p = [string]$e.ProviderName
    switch ([int]$e.Id) {
        1    { if ($p -eq 'Microsoft-Windows-Power-Troubleshooter') { return 'WAKE' } }
        107  { if ($p -eq 'Microsoft-Windows-Kernel-Power') { return 'WAKE' } }
        507  { if ($p -eq 'Microsoft-Windows-Kernel-Power') { return 'WAKE (exit standby)' } }
        42   { if ($p -eq 'Microsoft-Windows-Kernel-Power') {
                   $tgt = ''
                   if ($e.Properties.Count -gt 0) { try { $tgt = [string]$e.Properties[0].Value } catch {} }
                   if ($tgt -eq '4') { return 'HIBERNATE' } else { return 'SLEEP' } } }
        506  { if ($p -eq 'Microsoft-Windows-Kernel-Power') { return 'SLEEP (modern standby)' } }
        12   { if ($p -eq 'Microsoft-Windows-Kernel-General') { return 'BOOT' } }
        6005 { if ($p -eq 'EventLog') { return 'BOOT (log started)' } }
        13   { if ($p -eq 'Microsoft-Windows-Kernel-General') { return 'SHUTDOWN' } }
        6006 { if ($p -eq 'EventLog') { return 'SHUTDOWN (clean)' } }
        1074 { if ($p -eq 'User32') { return 'SHUTDOWN (initiated)' } }
        6008 { if ($p -eq 'EventLog') { return 'UNEXPECTED SHUTDOWN' } }
        41   { if ($p -eq 'Microsoft-Windows-Kernel-Power') { return 'UNEXPECTED POWER LOSS (Kernel-Power 41)' } }
    }
    return ''   # an id reused by some other provider - skip it
}

Write-Host ""
Write-Host "Power events from the System log - last $Days day(s), newest first" -ForegroundColor Cyan
Write-Host ("=" * 90)

$events = Get-WinEvent -FilterHashtable @{ LogName = 'System'; Id = $ids; StartTime = $start } -ErrorAction SilentlyContinue

$rows = foreach ($e in $events) {
    $action = Classify $e
    if (-not $action) { continue }
    $detail = if ([int]$e.Id -eq 1) { Get-WakeSource ([string]$e.Message) } else { Get-Reason ([string]$e.Message) }
    [pscustomobject]@{
        Time     = $e.TimeCreated
        Action   = $action
        Id       = [int]$e.Id
        Detail   = $detail
        Message  = [string]$e.Message
    }
}

$rows = @($rows | Sort-Object Time -Descending)
if ($rows.Count -eq 0) {
    Write-Host "No power events found in this window." -ForegroundColor Yellow
    return
}

$n = $rows.Count
foreach ($r in $rows) {
    '{0,4}  {1:yyyy-MM-dd ddd HH:mm:ss}  {2,-40}  id {3,-5} {4}' -f $n, $r.Time, $r.Action, $r.Id, $r.Detail | Write-Host
    if ($Raw -and $r.Message) {
        Write-Host ('        ' + (($r.Message -split "`r?`n")[0]).Trim()) -ForegroundColor DarkGray
    }
    $n--
}

Write-Host ""
Write-Host "Legend" -ForegroundColor Cyan
Write-Host "  BOOT      = OS started                 (Kernel-General 12 / EventLog 6005)"
Write-Host "  WAKE      = resumed from sleep/standby  (Power-Troubleshooter 1, Kernel-Power 107/507)"
Write-Host "  SLEEP     = entered sleep / standby     (Kernel-Power 42 / 506)"
Write-Host "  HIBERNATE = entered hibernate (S4)      (Kernel-Power 42, target = 4)"
Write-Host "  SHUTDOWN  = clean shutdown / restart    (Kernel-General 13, EventLog 6006, User32 1074)"
Write-Host "  UNEXPECTED SHUTDOWN / POWER LOSS        (EventLog 6008, Kernel-Power 41)"
Write-Host "             ^ a long power-button hold or power loss shows up here, NOT as a clean SLEEP/WAKE."
Write-Host ""
Write-Host "Tip: -Raw adds each event's first message line; -Days N widens or narrows the window." -ForegroundColor DarkGray
