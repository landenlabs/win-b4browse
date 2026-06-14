# B4-Browse - data-collection script
# Check:  QueryPowerShellSecurity
# Runner: RunPowerShellJson/Array - run as: powershell.exe -NoProfile -NonInteractive
#         -ExecutionPolicy Bypass -EncodedCommand <base64-utf16(script)>,
#         with $ProgressPreference='SilentlyContinue' prepended.
# Note:   Generated snapshot of what the app runs; interpolated values reflect
#         the machine it was generated on. Regenerate: B4Browse.exe --dump-scripts <dir>
# ========================================================================


$ErrorActionPreference='SilentlyContinue'
$r=[ordered]@{}
$d=Get-MpComputerStatus
if($d){
  $r.Defender=[ordered]@{
    AntivirusEnabled=[bool]$d.AntivirusEnabled
    RealTimeProtectionEnabled=[bool]$d.RealTimeProtectionEnabled
    AntispywareEnabled=[bool]$d.AntispywareEnabled
    BehaviorMonitorEnabled=[bool]$d.BehaviorMonitorEnabled
    NISEnabled=[bool]$d.NISEnabled
    IsTamperProtected=[bool]$d.IsTamperProtected
    AntivirusSignatureAge=[int]$d.AntivirusSignatureAge
  }
}
$av=@()
try {
  foreach($a in (Get-CimInstance -Namespace root\SecurityCenter2 -ClassName AntiVirusProduct)){
    $hex='{0:x6}' -f [int]$a.productState
    $on = ($hex.Substring(2,2) -in '10','11')
    $av += [ordered]@{ Name=[string]$a.displayName; Enabled=[bool]$on }
  }
} catch {}
$r.AntivirusProducts=$av
$fw=[ordered]@{}
foreach($p in (Get-NetFirewallProfile)){ $fw[[string]$p.Name]=[bool]$p.Enabled }
$r.Firewall=$fw
$sb=$null
try { $sb=[bool](Confirm-SecureBootUEFI) } catch { $sb=$null }
$r.SecureBoot=$sb
$r | ConvertTo-Json -Compress -Depth 5
