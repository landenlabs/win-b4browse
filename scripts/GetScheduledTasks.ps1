# B4-Browse - data-collection script
# Check:  GetScheduledTasks
# Runner: RunPowerShellJson/Array - run as: powershell.exe -NoProfile -NonInteractive
#         -ExecutionPolicy Bypass -EncodedCommand <base64-utf16(script)>,
#         with $ProgressPreference='SilentlyContinue' prepended.
# Note:   Generated snapshot of what the app runs; interpolated values reflect
#         the machine it was generated on. Regenerate: B4Browse.exe --dump-scripts <dir>
# ========================================================================


$ErrorActionPreference='SilentlyContinue'
@(Get-ScheduledTask | ForEach-Object {
  $t=$_
  $a=($t.Actions | Where-Object { $_.Execute } | Select-Object -First 1)
  $i=$null; try { $i = $t | Get-ScheduledTaskInfo } catch {}
  # Repeat period: prefer a trigger's sub-pattern repetition (ISO-8601 'every X'), else a
  # daily trigger's day interval. Weekly/monthly/event/logon/boot have no simple period.
  $rep=''
  foreach($trg in @($t.Triggers | Where-Object { $_ })){ if($trg.Repetition -and $trg.Repetition.Interval){ $rep=[string]$trg.Repetition.Interval; break } }
  if(-not $rep){ foreach($trg in @($t.Triggers | Where-Object { $_ })){ if($trg.PSObject.Properties['DaysInterval'] -and [int]$trg.DaysInterval -ge 1){ $rep='P'+([int]$trg.DaysInterval)+'D'; break } } }
  [pscustomobject]@{
    Name=[string]$t.TaskName
    Path=[string]$t.TaskPath
    State=[string]$t.State
    Author=[string]$t.Author
    RunAs=[string]$t.Principal.UserId
    Hidden=[bool]$t.Settings.Hidden
    Execute=[string]$a.Execute
    Arguments=[string]$a.Arguments
    Created=[string]$t.Date
    LastRun=$(if($i -and $i.LastRunTime){$i.LastRunTime.ToString('o')}else{''})
    NextRun=$(if($i -and $i.NextRunTime){$i.NextRunTime.ToString('o')}else{''})
    Repeat=[string]$rep
  }
}) | ConvertTo-Json -Compress -Depth 4
