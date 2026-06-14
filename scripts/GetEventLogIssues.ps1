# B4-Browse - data-collection script
# Check:  GetEventLogIssues
# Runner: RunPowerShellJson/Array - run as: powershell.exe -NoProfile -NonInteractive
#         -ExecutionPolicy Bypass -EncodedCommand <base64-utf16(script)>,
#         with $ProgressPreference='SilentlyContinue' prepended.
# Note:   Generated snapshot of what the app runs; interpolated values reflect
#         the machine it was generated on. Regenerate: B4Browse.exe --dump-scripts <dir>
# ========================================================================


$ErrorActionPreference='SilentlyContinue'
$start=(Get-Date).AddDays(-7)
function Q($ht,$cap){ try { Get-WinEvent -FilterHashtable $ht -MaxEvents $cap -ErrorAction SilentlyContinue } catch {} }
$ev=@()
$ev+=Q @{LogName='System';Level=1,2;StartTime=$start} 200
$ev+=Q @{LogName='Application';Level=1,2;StartTime=$start} 200
$ev+=Q @{LogName='System';Id=7045,7030,7031,7034;StartTime=$start} 100
$ev+=Q @{LogName='Microsoft-Windows-Windows Defender/Operational';Id=1006,1008,1015,1116,1117,5001,5007,5010,5012;StartTime=$start} 100
$ev+=Q @{LogName='Microsoft-Windows-Windows Firewall With Advanced Security/Firewall';Id=2004,2005,2006,2033;StartTime=$start} 100
$ev+=Q @{LogName='Security';Id=1102,4720,4728,4732,4756,4648,4698,4699,4702;StartTime=$start} 200
$ev+=Q @{LogName='Security';Id=4625;StartTime=$start} 200
$ev | Where-Object { $_ -ne $null } | ForEach-Object {
  $m = ([string]$_.Message -split "`r?`n")[0]
  [pscustomobject]@{ Time=$_.TimeCreated.ToString('o'); Id=[int]$_.Id; Level=[string]$_.LevelDisplayName; Source=[string]$_.ProviderName; Channel=[string]$_.LogName; Message=$m }
} | ConvertTo-Json -Compress -Depth 3
