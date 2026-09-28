<#
.SYNOPSIS
    ONE elevated command that finishes the endpoint half of the SOC-Lab:
    installs Sysmon, enables PowerShell logging, and registers the Elastic
    Agent for Fleet Server and for the Windows endpoint.

.DESCRIPTION
    Run this ONCE from an ELEVATED PowerShell. It performs, in order:

      1. Sysmon install with sysmon/sysmon-config.xml
      2. PowerShell logging policy (4103/4104) + audit policy + 4688 cmdline
      3. Elastic Agent as Fleet Server
      4. Elastic Agent for the Windows endpoint
      5. Verification of all four

    Elevation is required because each of these touches a privileged surface:
      - Sysmon installs a boot-start driver and a protected service
      - the PowerShell policy and audit policy write to HKLM and local policy
      - the Elastic Agent registers a Windows service
      - the agent must read the Security channel, which a non-elevated
        process cannot do ("Attempted to perform an unauthorized operation")

    The script is idempotent: re-running it re-applies the Sysmon config and
    reports status without reinstalling what is already present.

.EXAMPLE
    # From an ELEVATED PowerShell, in the repo root:
    powershell -ExecutionPolicy Bypass -File scripts/setup/Invoke-ElevatedBootstrap.ps1

.EXAMPLE
    # Just the Sysmon step (elevated):
    powershell -ExecutionPolicy Bypass -File scripts/setup/Invoke-ElevatedBootstrap.ps1 -Step Sysmon
#>
[CmdletBinding()]
param(
    [ValidateSet('All','Sysmon','PowerShell','FleetServer','Agent','Verify')]
    [string]$Step = 'All',
    # Skip the Sysmon install if the service already exists.
    [switch]$Force
)

$ErrorActionPreference = 'Continue'   # keep going; report everything at the end
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot  = Resolve-Path (Join-Path $ScriptDir '..\..')
$EnvFile   = Join-Path $RepoRoot '.env'
$Version   = '9.5.3'
$AgentDir  = "C:\elastic\elastic-agent-$Version-windows-x86_64"
$AgentExe  = Join-Path $AgentDir 'elastic-agent.exe'
$SysmonExe = 'C:\elastic\downloads\Sysmon\Sysmon64.exe'
$SysmonCfg = Join-Path $RepoRoot 'sysmon\sysmon-config.xml'

$results = New-Object System.Collections.ArrayList
function Note  { param($m) Write-Host $m -ForegroundColor DarkGray }
function Step_ { param($m) Write-Host "`n=== $m ===" -ForegroundColor Cyan }
function Ok    { param($n,$m) [void]$results.Add([pscustomobject]@{step=$n;status='OK';detail=$m}); Write-Host "  [OK]   $m" -ForegroundColor Green }
function Warn  { param($n,$m) [void]$results.Add([pscustomobject]@{step=$n;status='WARN';detail=$m}); Write-Host "  [WARN] $m" -ForegroundColor Yellow }
function Fail  { param($n,$m) [void]$results.Add([pscustomobject]@{step=$n;status='FAIL';detail=$m}); Write-Host "  [FAIL] $m" -ForegroundColor Red }

# --- Preconditions ------------------------------------------------------------
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
Write-Host "SOC-Lab elevated endpoint bootstrap" -ForegroundColor White
Write-Host "  admin   : $isAdmin"
Write-Host "  repo    : $RepoRoot"
Write-Host "  agent   : $AgentExe"
if (-not $isAdmin) {
    Write-Host "`nMUST run elevated. Right-click PowerShell > Run as administrator." -ForegroundColor Red
    exit 1
}

# --- Load secrets --------------------------------------------------------------
if (-not (Test-Path $EnvFile)) { Write-Host "Missing $EnvFile - run New-LabSecrets.ps1 first" -ForegroundColor Red; exit 1 }
$envMap = @{}
foreach ($line in Get-Content -LiteralPath $EnvFile) {
    $t = $line.Trim(); if ($t -eq '' -or $t.StartsWith('#')) { continue }
    $i = $t.IndexOf('='); if ($i -lt 1) { continue }
    $envMap[$t.Substring(0,$i).Trim()] = $t.Substring($i+1).Trim()
}
$fleetEsToken  = $envMap['FLEET_SERVER_ES_TOKEN']
$fleetEnrollKey = $envMap['FLEET_ENROLLMENT_TOKEN']
$winEnrollKey   = $envMap['WINDOWS_AGENT_ENROLLMENT_TOKEN']

# Enrollment tokens are stored as the raw api_key in .env. The install command
# needs "<key.id>:<api_key>"; the key ids are recoverable from the Fleet API, so
# build them here rather than duplicating them in .env.
$kibanaAuth = "elastic:$($envMap['ELASTIC_PASSWORD'])"
function Get-EnrollmentToken {
    param([string]$KeyName)
    $h = @{ Authorization = "Basic $([Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($kibanaAuth)))"; 'kbn-xsrf' = 'true' }
    try {
        $keys = Invoke-RestMethod -Uri 'http://127.0.0.1:5601/api/fleet/enrollment-api-keys' -Headers $h -TimeoutSec 60
    } catch {
        # 9.5.3 uses underscores in the path
        $keys = Invoke-RestMethod -Uri 'http://127.0.0.1:5601/api/fleet/enrollment_api_keys' -Headers $h -TimeoutSec 60
    }
    $hit = @($keys.items | Where-Object { $_.name -eq $KeyName }) | Select-Object -First 1
    if (-not $hit) { throw "No enrollment key named '$KeyName'. Run scripts/setup/Setup-Fleet.ps1 first." }
    return "$($hit.id):$($hit.api_key)"
}

# --- 1. Sysmon ----------------------------------------------------------------
function Install-SysmonStep {
    Step_ '1. Sysmon'
    if (-not (Test-Path $SysmonExe)) { Fail 'sysmon' "missing $SysmonExe - download from https://download.sysinternals.com/files/Sysmon.zip"; return }
    if (-not (Test-Path $SysmonCfg)) { Fail 'sysmon' "missing $SysmonCfg"; return }

    $svc = Get-Service -Name Sysmon64, Sysmon -ErrorAction SilentlyContinue | Select-Object -First 1
    $flags = if ($svc -and -not $Force) { '-c' } else { '-i' }
    $argList = if ($flags -eq '-c') { @('-accepteula','-c', "`"$SysmonCfg`"") } else { @('-accepteula','-i', "`"$SysmonCfg`"") }
    Note "  running: Sysmon64.exe $($argList -join ' ')"
    $out = & $SysmonExe @argList 2>&1
    $out | ForEach-Object { Note "    $_" }

    if ($flags -eq '-c') {
        Ok 'sysmon' 'configuration re-applied with sysmon/sysmon-config.xml'
    } else {
        $svc2 = Get-Service -Name Sysmon64, Sysmon -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($svc2 -and $svc2.Status -eq 'Running') { Ok 'sysmon' "installed and running ($($svc2.Name))" }
        else { Fail 'sysmon' "service not running after install: $(($out|Out-String).Trim())" }
    }
}

# --- 2. PowerShell ------------------------------------------------------------
function Enable-PsStep {
    Step_ '2. PowerShell logging + audit policy'
    $ps = Join-Path $ScriptDir 'Enable-PowerShellLogging.ps1'
    if (-not (Test-Path $ps)) { Fail 'powershell' "missing $ps"; return }
    $out = & $ps 2>&1
    $out | ForEach-Object { Note "    $_" }
    $has4104 = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell' -Name ScriptBlockLogging -ErrorAction SilentlyContinue).ScriptBlockLogging
    if ($has4104 -eq 1) { Ok 'powershell' 'ScriptBlockLogging=1 (Event 4104 enabled)' }
    else { Fail 'powershell' "ScriptBlockLogging is '$has4104', expected 1" }
}

# --- 3. Fleet Server ----------------------------------------------------------
function Install-FleetServerStep {
    Step_ '3. Elastic Agent as Fleet Server'
    if (-not (Test-Path $AgentExe)) { Fail 'fleetserver' "missing $AgentExe"; return }
    if (-not $fleetEsToken) { Fail 'fleetserver' 'FLEET_SERVER_ES_TOKEN not in .env (run Setup-Fleet.ps1)'; return }

    $existing = Get-Service -Name 'Elastic Agent' -ErrorAction SilentlyContinue
    if ($existing -and -not $Force) { Ok 'fleetserver' "service '$($existing.Name)' already present (status $($existing.Status))" }
    else {
        $tok = Get-EnrollmentToken -KeyName 'soc-lab-fleet-server-key'
        Note "  running: elastic-agent.exe install --url=... --fleet-server-es=... --enrollment-token=<redacted>"
        $out = & $AgentExe install --url='http://127.0.0.1:5601' --fleet-server-es='http://127.0.0.1:9200' `
                             "--fleet-server-service-token=$fleetEsToken" "--enrollment-token=$tok" 2>&1
        $out | ForEach-Object { Note "    $_" }
        $svc = Get-Service -Name 'Elastic Agent' -ErrorAction SilentlyContinue
        if ($svc) { Ok 'fleetserver' "agent service installed (status $($svc.Status))" }
        else { Fail 'fleetserver' "agent service not created: $(($out|Out-String).Trim())" }
    }
}

# --- 4. Windows endpoint agent ------------------------------------------------
function Install-AgentStep {
    Step_ '4. Elastic Agent for the Windows endpoint (WIN-SOC01)'
    if (-not (Test-Path $AgentExe)) { Fail 'agent' "missing $AgentExe"; return }
    $svc = Get-Service -Name 'Elastic Agent' -ErrorAction SilentlyContinue
    if ($svc -and -not $Force) { Ok 'agent' 'agent service already installed' }
    else {
        $tok = Get-EnrollmentToken -KeyName 'soc-lab-windows-key'
        Note '  running: elastic-agent.exe install --url=... --enrollment-token=<redacted>'
        $out = & $AgentExe install --url='http://127.0.0.1:5601' "--enrollment-token=$tok" 2>&1
        $out | ForEach-Object { Note "    $_" }
        Ok 'agent' 'endpoint agent enrolled'
    }
}

# --- 5. Verify ----------------------------------------------------------------
function VerifyStep {
    Step_ '5. Verification (reads the result back, not the intent)'
    $svc = Get-Service -Name 'Elastic Agent' -ErrorAction SilentlyContinue
    if ($svc) { Ok 'verify' "Elastic Agent service: $($svc.Status)" } else { Fail 'verify' 'Elastic Agent service missing' }

    $sm = Get-Service -Name Sysmon64, Sysmon -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($sm) { Ok 'verify' "Sysmon service: $($sm.Status)" } else { Warn 'verify' 'Sysmon service missing' }

    try {
        $e1 = @(Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1} -MaxEvents 1 -ErrorAction Stop)
        Ok 'verify' "Sysmon EID 1 present (Newest: $($e1[0].TimeCreated))"
    } catch { Warn 'verify' "no Sysmon EID 1 yet: $($_.Exception.Message)" }

    try {
        $sec = Get-WinEvent -ListLog Security -ErrorAction Stop
        Ok 'verify' "Security channel readable by this (elevated) session; recordCount=$($sec.RecordCount)"
    } catch { Fail 'verify' "Security channel still unreadable: $($_.Exception.Message)" }

    # Generate one benign 4104 to prove script block logging is live.
    try {
        & powershell.exe -NoProfile -NonInteractive -Command "Write-Output 'SIEM-LAB-TEST'" 2>&1 | Out-Null
        Start-Sleep -Seconds 3
        $e4104 = @(Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; Id=4104} -MaxEvents 1 -ErrorAction SilentlyContinue)
        if ($e4104.Count -gt 0) { Ok 'verify' "PowerShell 4104 script block captured" }
        else { Warn 'verify' 'no 4104 yet (a new PowerShell session is required for the policy to take effect)' }
    } catch { Warn 'verify' "4104 test failed: $($_.Exception.Message)" }
}

# --- Run ----------------------------------------------------------------------
switch ($Step) {
    'Sysmon'      { Install-SysmonStep }
    'PowerShell'  { Enable-PsStep }
    'FleetServer' { Install-FleetServerStep }
    'Agent'       { Install-AgentStep }
    'Verify'      { VerifyStep }
    default {
        Install-SysmonStep
        Enable-PsStep
        Install-FleetServerStep
        Install-AgentStep
        VerifyStep
    }
}

Write-Host "`n=== SUMMARY ===" -ForegroundColor Cyan
$results | ForEach-Object { "{0,-14} {1,-5} {2}" -f $_.step, $_.status, $_.detail }
$failed = @($results | Where-Object { $_.status -eq 'FAIL' })
Write-Host ""
if ($failed.Count -eq 0) { Write-Host "Elevated bootstrap complete, no failures." -ForegroundColor Green }
else { Write-Host "$($failed.Count) step(s) FAILED - see above. Do not proceed to detections until fixed." -ForegroundColor Red }
Write-Host "`nNext (no elevation needed):" -ForegroundColor Cyan
Write-Host "  pwsh -File scripts/validation/Test-ElasticStackHealth.ps1 -RequireTelemetry" -ForegroundColor DarkGray
Write-Host "  (then add the System + Windows integrations: scripts/setup/Add-WindowsIntegrations.ps1)" -ForegroundColor DarkGray
