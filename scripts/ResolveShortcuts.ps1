# B4-Browse - data-collection script
# Check:  ResolveShortcuts
# Runner: RunPowerShellJson/Array - run as: powershell.exe -NoProfile -NonInteractive
#         -ExecutionPolicy Bypass -EncodedCommand <base64-utf16(script)>,
#         with $ProgressPreference='SilentlyContinue' prepended.
# Note:   Generated snapshot of what the app runs; interpolated values reflect
#         the machine it was generated on. Regenerate: B4Browse.exe --dump-scripts <dir>
# ========================================================================

$sh=New-Object -ComObject WScript.Shell; $r=[ordered]@{}; foreach($p in @('C:\Users\DennisLang\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\MSN Money.lnk')){ try{ $r[$p]=$sh.CreateShortcut($p).TargetPath }catch{} }; $r | ConvertTo-Json -Compress
