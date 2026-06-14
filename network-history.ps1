<#
  network-history.ps1  --  B4-Browse scratch / evaluation tool (NOT part of the app build).

  Dumps the Wi-Fi / network "join history" Windows keeps, so you can see what
  forensic data is actually available on this machine before deciding whether to
  fold any of it into B4-Browse (proposed item #6).

  Sources (all read-only):
    * HKLM\...\NetworkList\Profiles    - every network ever joined: name, category,
                                         first-created and last-connected timestamps.
    * HKLM\...\NetworkList\Signatures  - per-network DEFAULT GATEWAY MAC + DNS suffix
                                         (joined to the profile by GUID). A changed
                                         gateway MAC for a known SSID = evil-twin signal.
    * netsh wlan ...                   - saved Wi-Fi profiles, auth/cipher, and (with
                                         -ShowKeys, admin only) the stored passphrase.
    * Get-NetConnectionProfile         - the network(s) currently connected.

  Usage:
    powershell -ExecutionPolicy Bypass -File .\network-history.ps1
    powershell -ExecutionPolicy Bypass -File .\network-history.ps1 -ShowKeys   (run elevated)
#>

[CmdletBinding()]
param(
    [switch]$ShowKeys   # also print saved Wi-Fi passphrases (requires Administrator)
)

$ErrorActionPreference = 'SilentlyContinue'

function Convert-SystemTime {
    # NetworkList stores DateCreated / DateLastConnected as a 16-byte SYSTEMTIME (local time).
    param([byte[]]$b)
    if (-not $b -or $b.Length -lt 16) { return $null }
    try {
        $y  = [BitConverter]::ToUInt16($b, 0)
        $mo = [BitConverter]::ToUInt16($b, 2)
        $d  = [BitConverter]::ToUInt16($b, 6)
        $h  = [BitConverter]::ToUInt16($b, 8)
        $mi = [BitConverter]::ToUInt16($b, 10)
        $s  = [BitConverter]::ToUInt16($b, 12)
        if ($y -lt 1601 -or $mo -lt 1 -or $mo -gt 12 -or $d -lt 1 -or $d -gt 31) { return $null }
        Get-Date -Year $y -Month $mo -Day $d -Hour $h -Minute $mi -Second $s
    } catch { $null }
}

function Format-Mac {
    param([byte[]]$b)
    if (-not $b -or $b.Length -lt 6) { return '' }
    (($b[0..5]) | ForEach-Object { $_.ToString('x2') }) -join ':'
}

$isAdmin = ([Security.Principal.WindowsPrincipal]`
    [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltinRole]::Administrator)

Write-Host ''
Write-Host '================ NETWORK / WI-FI JOIN HISTORY ================' -ForegroundColor Cyan
Write-Host ("Host: {0}    Admin: {1}    {2}" -f $env:COMPUTERNAME, $isAdmin, (Get-Date))
Write-Host ''

# --- 1. Signatures: ProfileGuid -> gateway MAC / DNS suffix / first network --------------
$sigRoot   = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures'
$sigByGuid = @{}
foreach ($scope in 'Managed', 'Unmanaged') {
    Get-ChildItem "$sigRoot\$scope" | ForEach-Object {
        $p = Get-ItemProperty $_.PSPath
        if ($p.ProfileGuid) {
            $sigByGuid[[string]$p.ProfileGuid] = [pscustomobject]@{
                GatewayMac   = Format-Mac $p.DefaultGatewayMac
                DnsSuffix    = [string]$p.DnsSuffix
                FirstNetwork = [string]$p.FirstNetwork
                Scope        = $scope
            }
        }
    }
}

# --- 2. Profiles: every network ever joined --------------------------------------------
$profRoot = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles'
$catMap   = @{ 0 = 'Public'; 1 = 'Private'; 2 = 'Domain' }

$rows = Get-ChildItem $profRoot | ForEach-Object {
    $g   = Split-Path $_.PSPath -Leaf
    $p   = Get-ItemProperty $_.PSPath
    $sig = $sigByGuid[$g]
    [pscustomobject]@{
        Name        = [string]$p.ProfileName
        Category    = $catMap[[int]$p.Category]
        Managed     = [bool]$p.Managed
        Created     = Convert-SystemTime $p.DateCreated
        LastConnect = Convert-SystemTime $p.DateLastConnected
        GatewayMac  = if ($sig) { $sig.GatewayMac } else { '' }
        DnsSuffix   = if ($sig) { $sig.DnsSuffix } else { '' }
    }
} | Sort-Object LastConnect -Descending

Write-Host ("--- Networks ever joined: {0} ---" -f @($rows).Count) -ForegroundColor Yellow
$rows | Format-Table Name, Category, Managed,
    @{ N = 'Created';     E = { if ($_.Created)     { $_.Created.ToString('yyyy-MM-dd HH:mm') }     else { '-' } } },
    @{ N = 'LastConnect'; E = { if ($_.LastConnect) { $_.LastConnect.ToString('yyyy-MM-dd HH:mm') } else { '-' } } },
    GatewayMac, DnsSuffix -AutoSize

# --- 3. Currently-connected networks ---------------------------------------------------
Write-Host '--- Currently connected (Get-NetConnectionProfile) ---' -ForegroundColor Yellow
Get-NetConnectionProfile | Format-Table Name, InterfaceAlias, NetworkCategory, IPv4Connectivity, IPv6Connectivity -AutoSize

# --- 4. Current Wi-Fi radio state ------------------------------------------------------
Write-Host '--- Current Wi-Fi interface (netsh wlan show interfaces) ---' -ForegroundColor Yellow
(netsh wlan show interfaces) | Where-Object { $_ -match '^\s*(Name|State|SSID|BSSID|Signal|Channel|Authentication|Cipher|Radio type)\s*:' }

# --- 5. Saved Wi-Fi profiles -----------------------------------------------------------
Write-Host ''
Write-Host '--- Saved Wi-Fi profiles (netsh wlan show profiles) ---' -ForegroundColor Yellow
$ssids = (netsh wlan show profiles) |
    Select-String 'All User Profile\s*:\s*(.+)$' |
    ForEach-Object { $_.Matches[0].Groups[1].Value.Trim() }

if (-not $ssids) {
    Write-Host '  (none, or no Wi-Fi adapter present)'
} else {
    foreach ($ssid in $ssids) {
        $args = "key=clear"
        if (-not $ShowKeys) { $args = '' }
        $detail = netsh wlan show profile name="$ssid" $args
        $auth = ($detail | Select-String 'Authentication\s*:\s*(.+)$' | Select-Object -First 1).Matches.Groups[1].Value.Trim()
        $key  = ($detail | Select-String 'Key Content\s*:\s*(.+)$'    | Select-Object -First 1).Matches.Groups[1].Value
        $line = "  {0,-32} auth={1}" -f $ssid, $auth
        if ($ShowKeys) {
            if ($key)         { $line += "  key=$key" }
            elseif (-not $isAdmin) { $line += "  key=(needs admin)" }
        }
        Write-Host $line
    }
    if ($ShowKeys -and -not $isAdmin) {
        Write-Host '  (note: passphrases require running this script as Administrator)' -ForegroundColor DarkGray
    }
}

Write-Host ''
Write-Host '=============================================================' -ForegroundColor Cyan
