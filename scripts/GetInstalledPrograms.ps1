# B4-Browse - data-collection script
# Check:  GetInstalledPrograms
# Runner: RunPowerShellJson/Array - run as: powershell.exe -NoProfile -NonInteractive
#         -ExecutionPolicy Bypass -EncodedCommand <base64-utf16(script)>,
#         with $ProgressPreference='SilentlyContinue' prepended.
# Note:   Generated snapshot of what the app runs; interpolated values reflect
#         the machine it was generated on. Regenerate: B4Browse.exe --dump-scripts <dir>
# ========================================================================

$k='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*','HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'; @(Get-ItemProperty $k -ErrorAction SilentlyContinue | Where-Object {$_.DisplayName} | Select-Object DisplayName,DisplayVersion,Publisher,InstallDate,Comments,DisplayIcon,InstallLocation) | ConvertTo-Json -Compress -Depth 3
