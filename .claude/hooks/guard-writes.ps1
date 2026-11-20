# PreToolUse hook (Edit|Write|NotebookEdit): force a permission prompt for any file write
# outside this project directory. Writes inside the project (and Claude's own session temp
# scratchpad under %TEMP%\claude) fall through to the normal allow rules - no prompt.
$ErrorActionPreference = 'Stop'
try {
    $payload = [Console]::In.ReadToEnd() | ConvertFrom-Json
    $path = $payload.tool_input.file_path
    if (-not $path) { $path = $payload.tool_input.notebook_path }
    if (-not $path) { exit 0 }

    # Git-Bash style /c/foo -> C:\foo, then normalise (8.3 short names and '..' included).
    function ConvertTo-WinPath([string]$p) {
        if ($p -match '^/([a-zA-Z])/(.*)$') { $p = "$($Matches[1]):\$($Matches[2])" }
        return [IO.Path]::GetFullPath($p.Replace('/', '\'))
    }
    $full = ConvertTo-WinPath $path

    $projDir = $env:CLAUDE_PROJECT_DIR
    if (-not $projDir) { $projDir = $payload.cwd }
    $roots = @(ConvertTo-WinPath $projDir)
    $roots += [IO.Path]::GetFullPath((Join-Path ([IO.Path]::GetTempPath()) 'claude'))
    # Long-form temp path too (TEMP is often the 8.3 short form DENNIS~1).
    $roots += [IO.Path]::GetFullPath((Join-Path $env:LOCALAPPDATA 'Temp\claude'))

    foreach ($r in $roots) {
        $rr = $r.TrimEnd('\') + '\'
        if ($full.StartsWith($rr, [StringComparison]::OrdinalIgnoreCase)) { exit 0 }
    }

    @{ hookSpecificOutput = @{
        hookEventName = 'PreToolUse'
        permissionDecision = 'ask'
        permissionDecisionReason = "Write outside the project directory: $full"
    } } | ConvertTo-Json -Compress -Depth 4
    exit 0
} catch {
    # Fail safe: if the path can't be evaluated, ask rather than silently allow.
    '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"ask","permissionDecisionReason":"guard-writes hook could not evaluate the path"}}'
    exit 0
}
