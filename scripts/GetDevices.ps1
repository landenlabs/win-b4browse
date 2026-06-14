# B4-Browse - data-collection script
# Check:  GetDevices
# Runner: RunPowerShellJson/Array - run as: powershell.exe -NoProfile -NonInteractive
#         -ExecutionPolicy Bypass -EncodedCommand <base64-utf16(script)>,
#         with $ProgressPreference='SilentlyContinue' prepended.
# Note:   Generated snapshot of what the app runs; interpolated values reflect
#         the machine it was generated on. Regenerate: B4Browse.exe --dump-scripts <dir>
# ========================================================================

@(Get-CimInstance Win32_PnPSignedDriver -ErrorAction SilentlyContinue | Where-Object {$_.DeviceName} | ForEach-Object { [pscustomobject]@{ Device=$_.DeviceName; Provider=$_.DriverProviderName; Version=$_.DriverVersion; Signed=[bool]$_.IsSigned; Inf=$_.InfName; VendorDate=$(if($_.DriverDate){$_.DriverDate.ToString('yyyy-MM-dd')}else{''}) } }) | ConvertTo-Json -Compress -Depth 3
