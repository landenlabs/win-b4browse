# B4-Browse - data-collection script
# Check:  GetRootCerts
# Runner: RunPowerShellJson/Array - run as: powershell.exe -NoProfile -NonInteractive
#         -ExecutionPolicy Bypass -EncodedCommand <base64-utf16(script)>,
#         with $ProgressPreference='SilentlyContinue' prepended.
# Note:   Generated snapshot of what the app runs; interpolated values reflect
#         the machine it was generated on. Regenerate: B4Browse.exe --dump-scripts <dir>
# ========================================================================


$ErrorActionPreference='SilentlyContinue'
function Dump($loc){
  Get-ChildItem -Path ('Cert:\' + $loc + '\Root') | ForEach-Object {
    [pscustomobject]@{
      Store=$loc
      Subject=[string]$_.Subject
      Issuer=[string]$_.Issuer
      NotBefore=$_.NotBefore.ToString('o')
      NotAfter=$_.NotAfter.ToString('o')
      Thumbprint=[string]$_.Thumbprint
      Sig=[string]$_.SignatureAlgorithm.FriendlyName
    }
  }
}
@(Dump 'LocalMachine') + @(Dump 'CurrentUser') | ConvertTo-Json -Compress -Depth 3
