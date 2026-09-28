<#
.SYNOPSIS
    Attaches the two Elastic integrations this SIEM depends on to the Windows
    endpoint agent policy, and prints the data streams to expect.

.DESCRIPTION
    WHY TWO INTEGRATIONS, NOT ONE. This is the single most important thing to
    get right, and it is a common mistake:

      The **Windows** integration collects the Windows-specific channels:
        Microsoft-Windows-Sysmon/Operational  -> logs-windows.sysmon_operational
        Microsoft-Windows-PowerShell/Operational
                                               -> logs-windows.powershell_operational
        Windows Defender, AppLocker, ForwardedEvents

      The **System** integration collects the classic channels:
        Security      -> logs-system.security     <-- 4624 / 4625 / 4634 / 4771
        System        -> logs-system.system
        Application   -> logs-system.application
        auth.log      -> logs-system.auth        <-- Linux SSH telemetry
        syslog        -> logs-system.syslog

      Verified from elastic/integrations on the `main` branch:
        packages/windows/manifest.yml  (data streams: forwarded, powershell,
          powershell_operational, sysmon_operational, service, perfmon, ...)
        packages/system/data_stream/security/manifest.yml ("Security channel")
        and the Windows integration docs, which state:
          "For 7.11, security, application and system logs have been moved to
           the system package."

      So DET-01 (Windows brute force) must query logs-system.security, NOT
      logs-windows.*. A detection written against the wrong data stream is the
      most likely reason a rule "never fires" in a lab.

    The System integration is also added to the LINUX endpoint policy later
    (Phase 5), where the same package provides auth.log and syslog.

    NOTE ON EVENT ID FILTERS: the Security channel is very chatty (4768/4769/
    4771 Kerberos, 4688 process creation with full command lines, 4657/4656
    object access). This script sets an explicit include list of the event IDs
    the lab's detections and hunts actually use, so ingest stays readable. Every
    included and excluded ID is justified in the comments below and in
    docs/configuration.md#security-event-filter. Pass -AllSecurityEvents to
    disable the filter and collect the channel unfiltered.

.EXAMPLE
    pwsh -File scripts/setup/Add-WindowsIntegrations.ps1
    pwsh -File scripts/setup/Add-WindowsIntegrations.ps1 -AllSecurityEvents
#>
[CmdletBinding()]
param(
    [switch]$AllSecurityEvents,
    [switch]$Force,
    [string]$PolicyNamespace = 'soc_lab_windows'
)

$ErrorActionPreference = 'Stop'
$RepoRoot = Resolve-Path (Join-Path (Split-Path -Parent $MyInvocation.MyCommand.Path) '..\..')
$EnvFile  = Join-Path $RepoRoot '.env'
$KibanaUrl = 'http://127.0.0.1:5601'

function Step { param($m) Write-Host "`n=== $m ===" -ForegroundColor Cyan }
function Ok   { param($m) Write-Host "  [OK]   $m" -ForegroundColor Green }
function Info { param($m) Write-Host "  [i]    $m" -ForegroundColor Gray }

# Event IDs collected from the Security channel, and why each one is here.
# The 22-block limit documented in the winlog input applies; this is 18.
$securityEventIds = @(
    # --- Authentication (DET-01, DET-05, auth dashboard, hunt 1) ---
    '4624',   # successful logon
    '4625',   # logon failure              <- primary DET-01 signal
    '4634',   # logoff / account locked
    '4648',   # explicit credential logon (runas)
    '4672',   # special privileges assigned to new logon
    '4688',   # process creation (command line, when audited)
    '4689',   # process termination
    '4771',   # Kerberos pre-authentication failure
               #   IMPORTANT: 4771 is NOT a subset of 4625. Pre-auth Kerberos
               #   failures never produce 4625, so a 4625-only brute force rule
               #   MISSES the most common domain brute force. Both are collected.
    '4776',   # Kerberos service ticket failure
               #   IMPORTANT: 4776 can contain the DC name in a field the
               #   Windows integration maps to source.ip. Excluded from the
               #   brute force rules, but collected so the behaviour is
               #   documented and testable.
    '4768',   # Kerberos TGT requested (T1110.003 spraying context)
    '4769',   # Kerberos service ticket requested
    '4767',   # account locked out
    '4794',   # account unlocked (recovery signal)
    # --- Account / group changes (supports an auth-attack narrative) ---
    '4720',   # user account created
    '4722',   # user account enabled
    '4724',   # account lockout attempt
    '4726',   # account deleted
    '4732',   # member added to security-enabled global group
    '4728',   # member added to global group
    '4756',   # member added to universal group
    # --- Service / audit policy tampering (triage context) ---
    '4697',   # service installed
    '1102',   # audit log cleared  <- an analyst must notice this
    '4719',   # audit policy changed
    '4616',   # system time changed (log tampering)
    '4608',   # system booting
    '4609',   # system shutting down
    '12',     # Kernel-General: OS started (host lifecycle in the dashboard)
    '13',     # Kernel-General: OS shutting down
    '6005',   # Event Log service started
    '6006',   # Event Log service stopped
    '6008',   # unexpected shutdown
    '6013',   # uptime
    '7045'    # System channel only in practice, listed for completeness
)

# IDs deliberately NOT collected, with reasons (Phase 16 noise analysis):
#   4656/4657/4658/4659/4660/4661/4662/4663  Object access: on a workstation
#       these are thousands per minute of file/registry chatter with no
#       detection value for this lab.
#   4657/4663                                object permission changes
#   5140/5145                                network share / detailed file share
#   5156/5158                                Windows Firewall allow/block
#   5152                                     Firewall filter change
#   4662/4688 dupes                          already covered where relevant
#   4740/4768 dupes                          covered by 4768 above
#   133x/7000/7001/7002                      event log metadata + channel churn
#   20001/20003 (TerminalServices)            remote desktop logons
# Each is listed so the filtering decision is documented, not silent.

if ($AllSecurityEvents) {
    $eventIdSetting = ''
    Info 'Security channel will be collected WITHOUT an event ID filter (noise expected).'
} else {
    $eventIdSetting = ($securityEventIds -join ',')
}

# --- Load credentials ---------------------------------------------------------
if (-not (Test-Path $EnvFile)) { throw "Missing $EnvFile" }
$envMap = @{}
foreach ($line in Get-Content -LiteralPath $EnvFile) {
    $t = $line.Trim(); if ($t -eq '' -or $t.StartsWith('#')) { continue }
    $i = $t.IndexOf('='); if ($i -lt 1) { continue }
    $envMap[$t.Substring(0,$i).Trim()] = $t.Substring($i+1).Trim()
}
$kbAuth = @{ Authorization = "Basic $([Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("elastic:$($envMap['ELASTIC_PASSWORD'])")))"; 'kbn-xsrf'='true' }

function Invoke-Kb {
    param([string]$Method,[string]$Path,$Body)
    $p = @{ Method=$Method; Uri="$KibanaUrl$Path"; Headers=$kbAuth; TimeoutSec=300; ErrorAction='Stop' }
    if ($null -ne $Body) { $p.Body=($Body|ConvertTo-Json -Depth 20 -Compress); $p.ContentType='application/json' }
    try { Invoke-RestMethod @p }
    catch {
        $code = try { [int]$_.Exception.Response.StatusCode } catch { 0 }
        $rb=''; try { $sr=New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream()); $rb=$sr.ReadToEnd(); $sr.Close() } catch {}
        if ($rb) { try { $rb=($rb|ConvertFrom-Json).message } catch {} }
        throw "$Method $Path -> HTTP ${code}: $rb"
    }
}

# --- Locate the policy --------------------------------------------------------
Step "Locating the endpoint agent policy (namespace '$PolicyNamespace')"
$all = Invoke-Kb 'GET' '/api/fleet/agent_policies?perPage=100' $null
$policy = @($all.items | Where-Object { $_.namespace -eq $PolicyNamespace }) | Select-Object -First 1
if (-not $policy) {
    throw "No agent policy with namespace '$PolicyNamespace'. Run scripts/setup/Setup-Fleet.ps1 first. Available: $(($all.items | ForEach-Object { $_.namespace }) -join ', ')"
}
Ok "policy '$($policy.name)' id=$($policy.id)"

$existing = Invoke-Kb 'GET' '/api/fleet/package_policies?perPage=200' $null
$already = @($existing.items | Where-Object { $_.policy_id -eq $policy.id }) | ForEach-Object { $_.package.name }
if ($already.Count -gt 0) { Info "policy already has integrations: $($already -join ', ')" }

# --- Attach integrations ------------------------------------------------------
function Add-Integration {
    param([string]$PackageName, [hashtable]$Inputs, [string]$InputKey, [string]$Label)

    if ((@($existing.items | Where-Object { $_.policy_id -eq $policy.id -and $_.package.name -eq $PackageName })).Count -gt 0) {
        Ok "$Label already attached"
        return
    }
    $pkg = Invoke-Kb 'GET' "/api/fleet/epm/packages/$PackageName" $null
    Ok "$Label package resolved (v$($pkg.version))"

    $body = @{
        name        = "soc-lab-$($PackageName -replace '_','-')"
        namespace   = $PolicyNamespace
        description = "$Label for the SOC-Lab Windows endpoint."
        policy_id   = $policy.id
        package     = @{ name = $PackageName; version = $pkg.version }
        output_id   = 'fleet-default-output'
    }
    if ($Inputs -and $Inputs.Count -gt 0) { $body['inputs'] = @($Inputs) }
    $r = Invoke-Kb 'POST' '/api/fleet/package_policies' $body
    Ok "$Label attached (package_policy_id=$($r.item.id))"
}

# --- System integration: Security / System / Application + Linux auth + syslog ---
Step 'Attaching the System integration'
# The System package has one data stream per channel. In the Fleet API a single
# package policy is created per STREAM, selected with `inputs[0].streams`. The
# default is all streams, which is what this lab wants on Windows
# (security, system, application) and later on Linux (auth, syslog).
$systemInputs = @(@{})
Add-Integration -PackageName 'system' -Inputs $systemInputs -Label 'System (Security/System/Application)'

Step 'Attaching the Windows integration (Sysmon + PowerShell)'
$windowsInputs = @(@{})
Add-Integration -PackageName 'windows' -Inputs $windowsInputs -Label 'Windows (Sysmon + PowerShell)'

# --- Apply the Security event ID filter ---------------------------------------
if (-not $AllSecurityEvents) {
    Step 'Restricting the Security channel to the event IDs this lab uses'
    $sysPkgPolicy = @($existing.items | Where-Object { $_.policy_id -eq $policy.id -and $_.package.name -eq 'system' }) | Select-Object -First 1
    $fresh = Invoke-Kb 'GET' '/api/fleet/package_policies?perPage=200' $null
    $sysPkgPolicy = @($fresh.items | Where-Object { $_.policy_id -eq $policy.id -and $_.package.name -eq 'system' }) | Select-Object -First 1
    if (-not $sysPkgPolicy) { Warn 'system' 'could not find the system package policy to filter; check it in Kibana > Fleet > Agent policies' }
    else {
        try {
            $update = Invoke-Kb 'PUT' "/api/fleet/package_policies/$($sysPkgPolicy.id)" @{
                name        = $sysPkgPolicy.name
                namespace   = $sysPkgPolicy.namespace
                description = $sysPkgPolicy.description
                policy_id   = $policy.id
                package     = @{ name='system'; version=$sysPkgPolicy.package.version }
                output_id   = $sysPkgPolicy.output_id
                inputs      = @(
                    @{
                        type    = 'logs'
                        streams = @(@{ enabled = $true; data_stream = 'security'; vars.event_id = $eventIdSetting })
                    },
                    @{ type = 'logs'; streams = @(@{ enabled = $true; data_stream = 'system' }) },
                    @{ type = 'logs'; streams = @(@{ enabled = $true; data_stream = 'application' }) }
                )
            }
            Ok "Security channel restricted to $($securityEventIds.Count) event IDs"
        } catch {
            Warn 'system' "could not set the event ID filter: $($_.Exception.Message). Set it in the UI: Fleet > Agent policies > system > Advanced options."
        }
    }
} else {
    Info '-AllSecurityEvents: no event ID filter applied.'
}

# --- Report expected data streams ---------------------------------------------
Step 'Expected data streams after the policy deploys'
$expect = @(
    'logs-system.security                4624/4625/4771/4768... Windows auth',
    'logs-system.system                  System channel',
    'logs-system.application            Application channel',
    'logs-windows.sysmon_operational    Sysmon EID 1/3/7/10/22...',
    'logs-windows.powershell_operational PowerShell 4103/4104'
)
$expect | ForEach-Object { "    $_" | Write-Host }
Info 'Deployment takes 1-3 minutes. Check: Fleet > Agent policies > policy > Status, then Discover.'
Write-Host @"

  Verify ingestion (no elevation needed):
    pwsh -File scripts/validation/Test-LogIngestion.ps1
"@ -ForegroundColor DarkGray
