# B4-Browse - data-collection script
# Check:  QueryAdapters
# Runner: RunPowerShellJson/Array - run as: powershell.exe -NoProfile -NonInteractive
#         -ExecutionPolicy Bypass -EncodedCommand <base64-utf16(script)>,
#         with $ProgressPreference='SilentlyContinue' prepended.
# Note:   Generated snapshot of what the app runs; interpolated values reflect
#         the machine it was generated on. Regenerate: B4Browse.exe --dump-scripts <dir>
# ========================================================================


$ErrorActionPreference='SilentlyContinue'
# Routine components to omit from Notes (by ComponentID). ms_ndiscap (packet capture) is
# deliberately NOT skipped so capture plumbing shows up.
$skip = @('ms_tcpip','ms_tcpip6','ms_pacer','ms_wfplwf_native','ms_wfplwf_upper',
          'ms_server','ms_msclient','ms_netbt','ms_lldp','ms_rspndr','ms_lltdio','ms_implat')

$bind=@{}
try {
  foreach($b in (Get-NetAdapterBinding -AllBindings)){
    $k=[string]$b.Name
    if(-not $bind.ContainsKey($k)){ $bind[$k]=New-Object System.Collections.ArrayList }
    [void]$bind[$k].Add(@{ id=[string]$b.ComponentID; disp=[string]$b.DisplayName; en=[bool]$b.Enabled })
  }
} catch {}

$out=@()
try {
  foreach($a in (Get-NetAdapter)){
    $name=[string]$a.Name
    $ip4=$false; $ip6=$false; $notes=@()
    if($bind.ContainsKey($name)){
      foreach($c in $bind[$name]){
        if($c.id -eq 'ms_tcpip'){ $ip4=$c.en; continue }
        if($c.id -eq 'ms_tcpip6'){ $ip6=$c.en; continue }
        if($c.en -and ($skip -notcontains $c.id)){ $notes += $c.disp }
      }
    }
    $out += [ordered]@{
      Name=$name
      Desc=[string]$a.InterfaceDescription
      Status=[string]$a.Status
      IPv4=[bool]$ip4
      IPv6=[bool]$ip6
      Notes=@($notes)
    }
  }
} catch {}
$out | ConvertTo-Json -Compress -Depth 5
