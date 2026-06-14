# B4-Browse - data-collection script
# Check:  QueryPromiscuousState
# Runner: RunPowerShellJson/Array - run as: powershell.exe -NoProfile -NonInteractive
#         -ExecutionPolicy Bypass -EncodedCommand <base64-utf16(script)>,
#         with $ProgressPreference='SilentlyContinue' prepended.
# Note:   Generated snapshot of what the app runs; interpolated values reflect
#         the machine it was generated on. Regenerate: B4Browse.exe --dump-scripts <dir>
# ========================================================================


$ErrorActionPreference='SilentlyContinue'
$r=[ordered]@{}

# NDIS current packet filter per adapter; PROMISCUOUS = bit 0x20.
$ad=@()
try {
  foreach($f in (Get-CimInstance -Namespace root/WMI -ClassName MSNdis_CurrentPacketFilter)){
    $flt=[int64]$f.NdisCurrentPacketFilter
    $ad += [ordered]@{
      Name=[string]$f.InstanceName
      Filter=$flt
      Promiscuous=[bool](($flt -band 0x20) -ne 0)
    }
  }
} catch {}
$r.Adapters=@($ad)

# Installed capture drivers/services: Npcap, WinPcap (npf), Microsoft pktmon.
$dv=@()
try {
  foreach($d in (Get-CimInstance Win32_SystemDriver | Where-Object { $_.Name -match '(?i)npcap|^npf$|winpcap|pktmon' })){
    $dv += [ordered]@{ Name=[string]$d.Name; Display=[string]$d.DisplayName; State=[string]$d.State }
  }
} catch {}
$r.CaptureDrivers=@($dv)

# Running capture tools.
$pr=@()
try {
  foreach($p in (Get-Process | Where-Object { $_.Name -match '(?i)wireshark|dumpcap|tshark|tcpdump|windump|netmon|ettercap|rawcap' })){
    $pr += [string]$p.Name
  }
} catch {}
$r.SnifferProcesses=@($pr | Select-Object -Unique)

$r | ConvertTo-Json -Compress -Depth 5
