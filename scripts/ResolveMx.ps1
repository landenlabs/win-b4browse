# B4-Browse - data-collection script
# Check:  ResolveMx
# Runner: RunPowerShellJson/Array - run as: powershell.exe -NoProfile -NonInteractive
#         -ExecutionPolicy Bypass -EncodedCommand <base64-utf16(script)>,
#         with $ProgressPreference='SilentlyContinue' prepended.
# Note:   Generated snapshot of what the app runs; interpolated values reflect
#         the machine it was generated on. Regenerate: B4Browse.exe --dump-scripts <dir>
# ========================================================================

@(Resolve-DnsName -Type MX -Name 'gmail.com' -DnsOnly -ErrorAction SilentlyContinue | Where-Object {$_.QueryType -eq 'MX'} | Select-Object Preference,NameExchange) | ConvertTo-Json -Compress -Depth 3


# ------------------------------------------------------------
# additional invocation #2 from ResolveMx
# ------------------------------------------------------------

@(Resolve-DnsName -Type MX -Name 'yahoo.com' -DnsOnly -ErrorAction SilentlyContinue | Where-Object {$_.QueryType -eq 'MX'} | Select-Object Preference,NameExchange) | ConvertTo-Json -Compress -Depth 3
