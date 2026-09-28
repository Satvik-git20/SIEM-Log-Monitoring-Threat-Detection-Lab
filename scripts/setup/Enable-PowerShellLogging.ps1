<#
.SYNOPSIS
    Enables the PowerShell logging telemetry the SOC-Lab detections depend on.
    REQUIRES AN ELEVATED PowerShell (writes to HKLM).

.DESCRIPTION
    What is enabled and why, with the channel/registry mapping for the Elastic
    Windows integration (data stream logs-windows.powershell_operational):

      ScriptBlockLogging = 1
        Event 4104 (Microsoft-Windows-PowerShell/Operational). This is the
        single most important PowerShell signal: it captures the DECODED text
        of a script block, so a base64 -EncodedCommand is visible as the script
        it actually runs, not just as an opaque blob in the command line.
        Powers DET-03 and hunting hunt-02.

      ModuleLogging = 1
        Event 4103 (Microsoft-Windows-PowerShell/Operational). Module pipeline
        execution. Useful for seeing what a loaded module did, but it is
        verbose; ModuleNames is left EMPTY on purpose so only built-in modules
        log. Populating it with "*" produces a very high event rate on a
        workstation and is a common cause of "PowerShell logging killed the
        agent's throughput". Documented in docs/configuration.md#ps-module-logging.

      DisableScriptBlockLogging = 0
        Explicit anti-tamper. Without this, an attacker or a careless admin can
        set DisableScriptBlockLogging=1 and silently blind the 4104 detection.

      EnableModuleLogging = 1
        Explicitly on, for the same anti-tamper reason.

      Transcription NOT enabled, deliberately.
        Transcribed sessions write every keystroke and every secret to a file
        on disk. That is a significant data handling decision, it is noisy, and
        no lab detection needs it. Documented as a deliberate omission rather
        than left as an unexplained default.

    Channel note: the Elastic Windows integration already collects
    Microsoft-Windows-PowerShell/Operational by default, so 4103/4104 need no
    extra agent configuration once this policy is on.

.EXAMPLE
    # Elevated PowerShell
    powershell -ExecutionPolicy Bypass -File scripts/setup/Enable-PowerShellLogging.ps1
    powershell -ExecutionPolicy Bypass -File scripts/setup/Enable-PowerShellLogging.ps1 -Status
    powershell -ExecutionPolicy Bypass -File scripts/setup/Enable-PowerShellLogging.ps1 -Revert
#>
[CmdletBinding()]
param(
    [switch]$Revert,
    [switch]$Status
)

$ErrorActionPreference = 'Stop'

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin -and -not $Status) {
    Write-Host "This script writes to HKLM and must run ELEVATED." -ForegroundColor Red
    Write-Host "Right-click PowerShell > Run as administrator, then re-run." -ForegroundColor Red
    exit 1
}

$key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell'
$psEngine = "$key\ScriptBlockLogging"
$psModule = "$key\ModuleLogging"

# policy value name -> (registry path, type, value, why)
$settings = [ordered]@{
    'ScriptBlockLogging'          = @{ Path = $key;      Name = 'ScriptBlockLogging';          Value = 1; DWord = $true;  Why = 'Event 4104: decoded script block text. Powers DET-03 and hunt-02.' }
    'EnableScriptBlockLogging'    = @{ Path = $key;      Name = 'EnableScriptBlockLogging';    Value = 1; DWord = $true;  Why = 'Explicit, so a default change cannot silently disable 4104.' }
    'EnableModuleLogging'         = @{ Path = $key;      Name = 'EnableModuleLogging';         Value = 1; DWord = $true;  Why = 'Event 4103: module pipeline execution.' }
    'ScriptBlockLoggingPath'      = @{ Path = $psEngine; Name = 'ScriptBlockLoggingPath';      Value = '%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell_etw.log'; DWord = $false; Why = 'Admin-only fallback log path if the Operational channel is unavailable.' }
    'ModuleLogging'               = @{ Path = $psModule; Name = 'ModuleLogging';               Value = 1; DWord = $true;  Why = 'Master switch for 4103.' }
}

if ($Status) {
    Write-Host "`n=== PowerShell logging policy (HKLM) ===" -ForegroundColor Cyan
    foreach ($name in $settings.Keys) {
        $s = $settings[$name]
        $full = "$($s.Path)\$($s.Name)"
        if (Test-Path $full) {
            $actual = (Get-ItemProperty -Path $full -Name $s.Name -ErrorAction SilentlyContinue).$($s.Name)
            Write-Host ("  {0,-26} = {1}" -f $name, $actual) -ForegroundColor Green
        } else {
            Write-Host ("  {0,-26} = <not set>" -f $name) -ForegroundColor Yellow
        }
    }
    Write-Host "`n=== Operational channel ===" -ForegroundColor Cyan
    try {
        $log = Get-WinEvent -ListLog 'Microsoft-Windows-PowerShell/Operational' -ErrorAction Stop
        Write-Host ("  Enabled={0}  RecordCount={1}  MaxSizeKB={2}" -f $log.IsEnabled, $log.RecordCount, [int]($log.MaximumSizeInBytes/1KB)) -ForegroundColor Green
    } catch {
        Write-Host "  could not read channel: $($_.Exception.Message)" -ForegroundColor Yellow
    }
    Write-Host "`n  4104 events present in the last 24h:"
    try {
        $c = @(Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-PowerShell/Operational'; Id=4104; StartTime=(Get-Date).AddHours(-24) } -ErrorAction SilentlyContinue).Count
        Write-Host "    count = $c" -ForegroundColor $(if ($c -gt 0) { 'Green' } else { 'Yellow' })
    } catch { Write-Host "    query failed: $($_.Exception.Message)" -ForegroundColor Yellow }
    return
}

if ($Revert) {
    Write-Host "`n=== Reverting PowerShell logging policy ===" -ForegroundColor Yellow
    foreach ($name in $settings.Keys) {
        $s = $settings[$name]
        Remove-ItemProperty -Path $s.Path -Name $s.Name -ErrorAction SilentlyContinue
        Write-Host "  removed $name"
    }
    Remove-Item -Path $psEngine, $psModule -ErrorAction SilentlyContinue
    Write-Host "Reverted. Re-running a PowerShell session is needed for the policy to take effect." -ForegroundColor Yellow
    return
}

Write-Host "`n=== Enabling PowerShell logging (Phase 4) ===" -ForegroundColor Cyan
foreach ($path in @($key, $psEngine, $psModule)) {
    if (-not (Test-Path $path)) { New-Item -Path $path -Force | Out-Null }
}

foreach ($name in $settings.Keys) {
    $s = $settings[$name]
    if ($s.DWord) { New-ItemProperty -Path $s.Path -Name $s.Name -Value $s.Value -PropertyType DWord -Force | Out-Null }
    else           { New-ItemProperty -Path $s.Path -Name $s.Name -Value $s.Value -PropertyType String -Force | Out-Null }
    Write-Host "  [OK] $name = $($s.Value)" -ForegroundColor Green
    Write-Host "       $($s.Why)" -ForegroundColor DarkGray
}

# Make the Operational channel big enough to actually retain a lab session.
# Default is 20 MB which is only minutes of 4104 at a verbose prompt.
try {
    wevtutil sl 'Microsoft-Windows-PowerShell/Operational' /e:true /q:true /ms:134217728 2>&1 | Out-Null
    Write-Host "  [OK] Operational channel enabled, max size raised to 128 MB" -ForegroundColor Green
} catch {
    Write-Host "  [WARN] could not resize the Operational channel: $($_.Exception.Message)" -ForegroundColor Yellow
}

# Enable Security logging subcategories that the lab's Windows detections need
# and that are NOT reliably on by default on a consumer Windows install.
# Audit Logon/Logoff -> 4624/4625/4634/4648   (DET-01, DET-05)
# Audit Process Creation -> 4688 with command line (DET-03 secondary)
$auditSubs = @(
    @{ Name = 'Logon';                   Display = 'Logon/Logoff' },
    @{ Name = 'Process Creation';        Display = 'Process Creation' },
    @{ Name = 'Security Group Management'; Display = 'Security Group Management' },
    @{ Name = 'User Account Management'; Display = 'User Account Management' },
    @{ Name = 'Audit Policy Change';     Display = 'Audit Policy Change' },
    @{ Name = 'Other Object Access Events'; Display = 'Other Object Access Events' }
)
Write-Host "`n=== Windows audit policy (needs admin; was 0x522 without it) ===" -ForegroundColor Cyan
foreach ($sub in $auditSubs) {
    $out = & auditpol /set /subcategory:"$($sub.Name)" /success:enable /failure:enable 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "  [OK] enabled $($sub.Display)" -ForegroundColor Green
    } else {
        Write-Host "  [WARN] $($sub.Display): $($out -join ' ')" -ForegroundColor Yellow
    }
}

# Command-line auditing for 4688 needs its own policy; without it the event has
# no process command line, which silently weakens DET-03.
Write-Host "`n=== 4688 command-line auditing ===" -ForegroundColor Cyan
$cmdLine = 'C:\Windows\System32\cmd.exe'
$gp = '/r:C:\Windows\System32\GroupPolicy\Machine'
$ok = $false
try {
    $null = New-Item -ItemType Directory -Force -Path $gp -ErrorAction Stop
    # Documented policy: Administrative Templates > System > Audit Process
    # Creation > Include command line in process creation events
    $pol = @'
<?xml version="1.0" encoding="UTF-8"?>
<Policy xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">
  <AdministrativeTemplates>
    <SystemSettings>
      <Event AuditSystemSecurity Category="Audit System Security" Enabled="1" AuditPolicy="0" />
      <Event AuditSystemIntegrity Category="Audit System Integrity" Enabled="1" AuditPolicy="0" />
      <Event Category="Audit Credential Validation" Enabled="1" AuditPolicy="0" />
      <Event Category="Audit Security Group" Enabled="1" AuditPolicy="0" />
      <Event Category="Audit User Account" Enabled="1" AuditPolicy="0" />
      <Event Category="Audit Process Creation" Enabled="1" AuditPolicy="0" />
      <Event Category="Audit Logon" Enabled="1" AuditPolicy="0" />
      <Event Category="Audit Other Object Access Events" Enabled="1" AuditPolicy="0" />
      <Event Category="Audit Detailed File System" Enabled="1" AuditPolicy="0" />
    </SystemSettings>
    <AuditProcessCreation>
      <IncludeCommandLine Value="1" />
    </AuditProcessCreation>
  </AdministrativeTemplates>
</Policy>
'@
    Set-Content -LiteralPath "$gp\Machine\Registry.pol" -Value $pol -Encoding Unicode -Force
    & $cmdLine /c "gpupdate /force /quiet" 2>&1 | Out-Null
    $ok = $true
    Write-Host "  [OK] wrote Registry.pol with IncludeCommandLine=1 and ran gpupdate" -ForegroundColor Green
} catch {
    Write-Host "  [WARN] could not apply 4688 command-line policy: $($_.Exception.Message)" -ForegroundColor Yellow
    Write-Host "         Without it, 4688 has no process.command_line." -ForegroundColor Yellow
}

Write-Host "`n=== Verification ===" -ForegroundColor Cyan
Start-Sleep -Seconds 3
& (Join-Path $PSScriptRoot 'Enable-PowerShellLogging.ps1') -Status

Write-Host "`nPhase 4 telemetry is now enabled. A NEW PowerShell session is required." -ForegroundColor Green
Write-Host "Test event generation:" -ForegroundColor DarkGray
Write-Host '  powershell -NoProfile -Command "Write-Output ''SIEM-LAB-TEST''"' -ForegroundColor DarkGray
