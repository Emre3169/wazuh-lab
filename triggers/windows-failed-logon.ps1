<#
.SYNOPSIS
  Trigger Windows logon-failure alerts (event 4625 -> Wazuh rule 60122). Runs ON windows-lab, elevated.

.DESCRIPTION
  Makes N SMB logon attempts against the machine itself as a user that does not exist, so
  no real account is ever locked out (hardening-lab sets a 5-attempt lockout). Then counts
  the 4625 events Windows wrote, which the Wazuh agent forwards from the Security log.

.EXAMPLE
  powershell -NoProfile -ExecutionPolicy Bypass -File windows-failed-logon.ps1
#>
[CmdletBinding()]
param([int]$Count = 6)
$ErrorActionPreference = 'Stop'

$start = Get-Date
"== $Count failed SMB logons as 'nosuchuser' ($($start.ToUniversalTime().ToString('u')))"
for ($i = 1; $i -le $Count; $i++) {
  # Windows PowerShell 5.1 turns a native command's redirected stderr into an error record,
  # which 'Stop' would make fatal; the failure (system error 1326) is the point here.
  $ErrorActionPreference = 'Continue'
  $out = & net use '\\127.0.0.1\IPC$' /user:nosuchuser wrongpass 2>&1
  $ErrorActionPreference = 'Stop'
  if ($LASTEXITCODE -eq 0) {
    & net use '\\127.0.0.1\IPC$' /delete /y | Out-Null
    throw "attempt $i unexpectedly succeeded"
  }
  "  attempt $i refused: $((($out | Out-String) -split "`r?`n" | Where-Object { $_ -match 'error' } | Select-Object -First 1).Trim())"
  Start-Sleep -Seconds 1
}
Start-Sleep -Seconds 2
$events = @(Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4625; StartTime = $start } -ErrorAction SilentlyContinue)
"  OK       $($events.Count) event(s) 4625 written since $($start.ToString('T'))"
@"
== check
  Manager:  sudo grep '"windows-lab"' /var/ossec/logs/alerts/alerts.json | grep -c '"id":"60122"'
  Dashboard: Threat Hunting > agent windows-lab > rule.id:60122
"@
