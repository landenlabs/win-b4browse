# B4-Browse - data-collection script
# Check:  GetProcesses
# Runner: RunPowerShellJson/Array - run as: powershell.exe -NoProfile -NonInteractive
#         -ExecutionPolicy Bypass -EncodedCommand <base64-utf16(script)>,
#         with $ProgressPreference='SilentlyContinue' prepended.
# Note:   Generated snapshot of what the app runs; interpolated values reflect
#         the machine it was generated on. Regenerate: B4Browse.exe --dump-scripts <dir>
# ========================================================================

@(Get-CimInstance Win32_Process | Select-Object Name,ProcessId,ExecutablePath) | ConvertTo-Json -Compress -Depth 3
