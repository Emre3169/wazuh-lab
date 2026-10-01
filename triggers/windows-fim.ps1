<#
.SYNOPSIS
  Trigger Windows FIM alerts in C:\Windows\System32\drivers\etc (a default agent FIM path). Runs ON windows-lab, elevated.

.DESCRIPTION
  -Step all (default): create, modify, delete wazuh-lab-test.txt, pausing between steps.
  -Step create | modify | delete: one step only. The default agent config scans this folder
  on a schedule (every 12 h), not in real time, so to see each event separately run one
  step, force a scan from the manager (agent_control -r -u <id>), then run the next step.
  Nothing is left behind: -Step all always removes the test file; -Step delete is the revert.
  Expected rules: 554 (added), 550 (modified), 553 (deleted).

.EXAMPLE
  powershell -NoProfile -ExecutionPolicy Bypass -File windows-fim.ps1 -Step create
#>
[CmdletBinding()]
param(
  [ValidateSet('all', 'create', 'modify', 'delete')][string]$Step = 'all',
  [int]$PauseSeconds = 10
)
$ErrorActionPreference = 'Stop'
$file = Join-Path $env:WINDIR 'System32\drivers\etc\wazuh-lab-test.txt'

function Do-Create { Set-Content -Path $file -Value 'lab_setting = 1' -Encoding ASCII; "  CHANGED  created $file" }
function Do-Modify {
  if (-not (Test-Path $file)) { throw "$file does not exist; run -Step create first" }
  Set-Content -Path $file -Value "lab_setting = 2`r`nnew_line = yes" -Encoding ASCII; "  CHANGED  modified $file"
}
function Do-Delete {
  if (Test-Path $file) { Remove-Item $file -Force; "  CHANGED  deleted $file (reverted)" } else { "  OK       $file already absent" }
}

"== FIM $Step ($((Get-Date).ToUniversalTime().ToString('u')))"
switch ($Step) {
  'create' { Do-Create }
  'modify' { Do-Modify }
  'delete' { Do-Delete }
  'all' {
    try {
      Do-Create; Start-Sleep -Seconds $PauseSeconds
      Do-Modify; Start-Sleep -Seconds $PauseSeconds
    } finally {
      Do-Delete
    }
  }
}
