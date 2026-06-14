# B4-Browse - data-collection script
# Check:  VerifyAuthenticode
# Runner: RunPowerShellJson/Array - run as: powershell.exe -NoProfile -NonInteractive
#         -ExecutionPolicy Bypass -EncodedCommand <base64-utf16(script)>,
#         with $ProgressPreference='SilentlyContinue' prepended.
# Note:   Generated snapshot of what the app runs; interpolated values reflect
#         the machine it was generated on. Regenerate: B4Browse.exe --dump-scripts <dir>
# ========================================================================

$x=Get-AuthenticodeSignature -LiteralPath 'C:\Program Files\Google\Chrome\Application\chrome.exe'; [pscustomobject]@{Status=$x.Status.ToString();Signer=$x.SignerCertificate.Subject} | ConvertTo-Json -Compress
