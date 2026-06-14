# B4-Browse - data-collection script
# Check:  ResolveTxt
# Runner: RunPowerShellJson/Array - run as: powershell.exe -NoProfile -NonInteractive
#         -ExecutionPolicy Bypass -EncodedCommand <base64-utf16(script)>,
#         with $ProgressPreference='SilentlyContinue' prepended.
# Note:   Generated snapshot of what the app runs; interpolated values reflect
#         the machine it was generated on. Regenerate: B4Browse.exe --dump-scripts <dir>
# ========================================================================

@(Resolve-DnsName -Type TXT -Name 'o-o.myaddr.l.google.com' -ErrorAction SilentlyContinue | Where-Object {$_.Type -eq 'TXT'} | Select-Object -Expand Strings) | ConvertTo-Json -Compress
