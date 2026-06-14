# B4-Browse - data-collection script
# Check:  ReadSecurityCenterProducts
# Runner: RunPowerShellJson/Array - run as: powershell.exe -NoProfile -NonInteractive
#         -ExecutionPolicy Bypass -EncodedCommand <base64-utf16(script)>,
#         with $ProgressPreference='SilentlyContinue' prepended.
# Note:   Generated snapshot of what the app runs; interpolated values reflect
#         the machine it was generated on. Regenerate: B4Browse.exe --dump-scripts <dir>
# ========================================================================

$ErrorActionPreference='SilentlyContinue'; @(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName FirewallProduct | Select-Object displayName,productState,pathToSignedProductExe) | ConvertTo-Json -Compress -Depth 3


# ------------------------------------------------------------
# additional invocation #2 from ReadSecurityCenterProducts
# ------------------------------------------------------------

$ErrorActionPreference='SilentlyContinue'; @(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct | Select-Object displayName,productState,pathToSignedProductExe) | ConvertTo-Json -Compress -Depth 3
