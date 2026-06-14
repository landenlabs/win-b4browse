# B4-Browse - data-collection script
# Check:  ReadPowerEvents
# Runner: RunPowerShellJson/Array - run as: powershell.exe -NoProfile -NonInteractive
#         -ExecutionPolicy Bypass -EncodedCommand <base64-utf16(script)>,
#         with $ProgressPreference='SilentlyContinue' prepended.
# Note:   Generated snapshot of what the app runs; interpolated values reflect
#         the machine it was generated on. Regenerate: B4Browse.exe --dump-scripts <dir>
# ========================================================================


$ErrorActionPreference='SilentlyContinue'
$start=(Get-Date).AddDays(-14)
try {
  Get-WinEvent -FilterHashtable @{LogName='System';Id=1,42,107,506,507,12,13,1074,6005,6006;StartTime=$start} -MaxEvents 2000 |
    ForEach-Object {
      $m=[string]$_.Message
      $tgt=''
      if ($_.Id -eq 42 -and $_.Properties.Count -gt 0) { try { $tgt=[string]$_.Properties[0].Value } catch {} }
      [pscustomobject]@{
        Time=$_.TimeCreated.ToString('o')
        Id=[int]$_.Id
        Provider=[string]$_.ProviderName
        Target=$tgt
        Msg=$m.Substring(0,[Math]::Min(500,$m.Length))
      }
    } | ConvertTo-Json -Compress -Depth 3
} catch {}
