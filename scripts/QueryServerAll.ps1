# B4-Browse - data-collection script
# Check:  QueryServerAll
# Runner: RunPowerShellJson/Array - run as: powershell.exe -NoProfile -NonInteractive
#         -ExecutionPolicy Bypass -EncodedCommand <base64-utf16(script)>,
#         with $ProgressPreference='SilentlyContinue' prepended.
# Note:   Generated snapshot of what the app runs; interpolated values reflect
#         the machine it was generated on. Regenerate: B4Browse.exe --dump-scripts <dir>
# ========================================================================

$s='9.9.9.9'
$ds=@('www.google.com','youtube.com','www.cloudflare.com','github.com','www.microsoft.com','en.wikipedia.org')
$r=[ordered]@{}
foreach($d in $ds){
  $a=@(); $q=@()
  try{ $a=@(Resolve-DnsName -Server $s -Name $d -Type A -DnsOnly -ErrorAction SilentlyContinue | Where-Object {$_.Type -eq 'A'} | ForEach-Object {$_.IPAddress}) }catch{}
  $r[$d]=[ordered]@{ A=@($a); AAAA=@($q) }
}
$r | ConvertTo-Json -Compress -Depth 4


# ------------------------------------------------------------
# additional invocation #2 from QueryServerAll
# ------------------------------------------------------------

$s='8.8.8.8'
$ds=@('www.google.com','youtube.com','www.cloudflare.com','github.com','www.microsoft.com','en.wikipedia.org')
$r=[ordered]@{}
foreach($d in $ds){
  $a=@(); $q=@()
  try{ $a=@(Resolve-DnsName -Server $s -Name $d -Type A -DnsOnly -ErrorAction SilentlyContinue | Where-Object {$_.Type -eq 'A'} | ForEach-Object {$_.IPAddress}) }catch{}
  $r[$d]=[ordered]@{ A=@($a); AAAA=@($q) }
}
$r | ConvertTo-Json -Compress -Depth 4


# ------------------------------------------------------------
# additional invocation #3 from QueryServerAll
# ------------------------------------------------------------

$s='1.1.1.1'
$ds=@('www.google.com','youtube.com','www.cloudflare.com','github.com','www.microsoft.com','en.wikipedia.org')
$r=[ordered]@{}
foreach($d in $ds){
  $a=@(); $q=@()
  try{ $a=@(Resolve-DnsName -Server $s -Name $d -Type A -DnsOnly -ErrorAction SilentlyContinue | Where-Object {$_.Type -eq 'A'} | ForEach-Object {$_.IPAddress}) }catch{}
  $r[$d]=[ordered]@{ A=@($a); AAAA=@($q) }
}
$r | ConvertTo-Json -Compress -Depth 4
