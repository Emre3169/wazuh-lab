<#
.SYNOPSIS
  Install and enroll the Wazuh agent on windows-lab (PLAN.md section 5). Runs ON the Windows VM, elevated.

.DESCRIPTION
  Idempotent: if the WazuhSvc service already exists it only makes sure it is running.
  Otherwise downloads the agent MSI (pinned to the manager's version), checks its size and
  Authenticode signature, installs it silently with the manager / name / registration
  server set, starts WazuhSvc, and waits (bounded) for the agent to connect.
  The x86 MSI runs under Windows' x86 emulation on ARM64.

.EXAMPLE
  powershell -NoProfile -ExecutionPolicy Bypass -File windows-agent.ps1
#>
[CmdletBinding()]
param(
  [string]$Manager = '192.168.64.2',
  [string]$AgentName = 'windows-lab',
  [string]$Version = '4.14.8-1'    # must not be newer than the manager (4.14.8)
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2

function Ok([string]$m)      { '  {0,-8} {1}' -f 'OK', $m }
function Changed([string]$m) { '  {0,-8} {1}' -f 'CHANGED', $m }

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'run elevated (administrator)' }

$AgentDir = "${env:ProgramFiles(x86)}\ossec-agent"
$AgentLog = Join-Path $AgentDir 'ossec.log'

$svc = Get-Service -Name WazuhSvc -ErrorAction SilentlyContinue
if ($svc) {
  Ok "WazuhSvc already installed ($($svc.Status)); skipping install"
  if ($svc.Status -ne 'Running') { & net start WazuhSvc | Out-Null; Changed 'WazuhSvc started' }
} else {
  $url = "https://packages.wazuh.com/4.x/windows/wazuh-agent-$Version.msi"
  $msi = Join-Path $env:TEMP "wazuh-agent-$Version.msi"
  [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
  Invoke-WebRequest -UseBasicParsing -Uri $url -OutFile $msi
  $size = (Get-Item $msi).Length
  if ($size -le 1MB) { throw "download too small ($size bytes): $url" }
  Ok "downloaded $url ($([math]::Round($size/1MB, 1)) MB)"

  $sig = Get-AuthenticodeSignature $msi
  if ($sig.Status -ne 'Valid') { throw "MSI signature is $($sig.Status); refusing to install" }
  Ok "MSI signature valid: $($sig.SignerCertificate.GetNameInfo('SimpleName', $false))"

  $log = Join-Path $env:TEMP 'wazuh-agent-install.log'
  $msiArgs = "/i `"$msi`" /q WAZUH_MANAGER=`"$Manager`" WAZUH_AGENT_NAME=`"$AgentName`" " +
             "WAZUH_REGISTRATION_SERVER=`"$Manager`" /l*v `"$log`""
  $p = Start-Process msiexec.exe -ArgumentList $msiArgs -Wait -PassThru
  if ($p.ExitCode -notin 0, 3010) { throw "msiexec exited $($p.ExitCode); see $log" }
  Changed "installed Wazuh agent $Version (manager $Manager, name $AgentName)"

  & net start WazuhSvc | Out-Null
  if ($LASTEXITCODE) { throw "NET START WazuhSvc failed ($LASTEXITCODE)" }
  Changed 'WazuhSvc started'
}

# Wait up to 60 s for the agent to report a connection to the manager.
for ($i = 1; $i -le 12; $i++) {
  if ((Test-Path $AgentLog) -and (Select-String -Path $AgentLog -Pattern 'Connected to the server' -Quiet)) { break }
  Start-Sleep -Seconds 5
}
$line = if (Test-Path $AgentLog) { Select-String -Path $AgentLog -Pattern 'Connected to the server' | Select-Object -Last 1 } else { $null }
if ($line) { Ok "agent connected: $($line.Line.Trim())" }
else { '  {0,-8} {1}' -f 'WARN', "no 'Connected to the server' in $AgentLog after 60 s" }
"WazuhSvc: $((Get-Service WazuhSvc).Status)"
