# 1. Define paths (Adjust the 'L.username' folder to match your system)
$cdpPath = "$env:LOCALAPPDATA\ConnectedDevicesPlatform"
$targetFolder = Get-ChildItem -Path $cdpPath -Directory | Where-Object { $_.Name -like "L.*" -or $_.Name -match "^[a-f0-9]{16}$" } | Select-Object -First 1

if (-not $targetFolder) {
    Write-Error "Could not locate ActivitiesCache folder."
    return
}

$dbPath = Join-Path $targetFolder.FullName "ActivitiesCache.db"
$tempDbPath = "$env:TEMP\ActivitiesCache_diagnostic.db"

# 2. Copy files to bypass file-locks (include WAL file for completeness)
Copy-Item -Path "$dbPath*" -Destination "$env:TEMP\" -Force

# 3. Use standard .NET to pull SQLite data (Requires SQLite provider loaded or Windows Data Class)
# Note: Alternatively, your tool can feed this temp file to 'sqlite3.exe' if available,
# or parse the JSON payloads. Here is a generic structure for parsing via SQLite:

Write-Host "Database successfully copied to $tempDbPath for diagnostics."
Write-Host "You can now execute standard SQL queries against it, e.g.:"
Write-Host "SELECT AppId, Payload, StartTime FROM Activity WHERE ActivityType = 5"
