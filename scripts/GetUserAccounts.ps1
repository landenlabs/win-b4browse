# B4-Browse - data-collection script
# Check:  GetUserAccounts
# Runner: RunPowerShellJson/Array - run as: powershell.exe -NoProfile -NonInteractive
#         -ExecutionPolicy Bypass -EncodedCommand <base64-utf16(script)>,
#         with $ProgressPreference='SilentlyContinue' prepended.
# Note:   Generated snapshot of what the app runs; interpolated values reflect
#         the machine it was generated on. Regenerate: B4Browse.exe --dump-scripts <dir>
# ========================================================================

@(Get-LocalUser | Select-Object Name, FullName, Description, Enabled, @{n='Sid';e={$_.SID.Value}}, @{n='Source';e={[string]$_.PrincipalSource}}, PasswordRequired, UserMayChangePassword, @{n='AccountExpires';e={if($_.AccountExpires){$_.AccountExpires.ToString('yyyy-MM-dd HH:mm:ss')}else{''}}}, @{n='PasswordExpires';e={if($_.PasswordExpires){$_.PasswordExpires.ToString('yyyy-MM-dd HH:mm:ss')}else{''}}}, @{n='PasswordLastSet';e={if($_.PasswordLastSet){$_.PasswordLastSet.ToString('yyyy-MM-dd HH:mm:ss')}else{''}}}, @{n='LastLogon';e={if($_.LastLogon){$_.LastLogon.ToString('yyyy-MM-dd HH:mm:ss')}else{''}}}) | ConvertTo-Json -Compress -Depth 3
