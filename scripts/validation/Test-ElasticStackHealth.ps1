<#
.SYNOPSIS
    Independent health validation for the SOC-Lab Elastic Stack.

.DESCRIPTION
    This is deliberately NOT the installer's own self-report. It re-checks the
    running stack from scratch, asserts each claim, and exits non-zero on any
    failure, so it is usable as a CI-style gate:

        pwsh -File scripts/validation/Test-ElasticStackHealth.ps1
        pwsh -File scripts/validation/Test-ElasticStackHealth.ps1 -Json
        pwsh -File scripts/validation/Test-ElasticStackHealth.ps1 -ReportPath tests/validation/results/health.json

    Checks performed:
      1. Elasticsearch root endpoint returns a version
      2. Elasticsearch security is enforcing (unauthenticated -> HTTP 401)
      3. Cluster health is green or yellow
      4. Elasticsearch and Kibana are bound to loopback only
      5. Kibana overall status is 'available'
      6. Kibana core services (elasticsearch, savedObjects) are available
      7. The Kibana service account token authenticates
      8. Fleet is enabled and the expected data-stream namespace exists

.EXAMPLE
    pwsh -File scripts/validation/Test-ElasticStackHealth.ps1
#>
[CmdletBinding()]
param(
    [switch]$Json,
    [string]$ReportPath,
    # Before Phase 4 there is no Fleet setup and no agent, so "Fleet not
    # initialized" and "no telemetry data streams" are the correct state, not
    # defects. With this switch (the default) they are reported as PENDING and
    # excluded from the exit code. Pass -RequireTelemetry once agents are
    # enrolled to turn them into hard failures.
    [switch]$RequireTelemetry
)

$ErrorActionPreference = 'Stop'
$RepoRoot = Resolve-Path (Join-Path (Split-Path -Parent $MyInvocation.MyCommand.Path) '..\..')
$EnvFile  = Join-Path $RepoRoot '.env'

$results = New-Object System.Collections.ArrayList
function Add-Result {
    param([string]$Name, [bool]$Pass, [string]$Detail, [switch]$Pending)
    $status = if ($Pending) { 'PENDING' } elseif ($Pass) { 'PASS' } else { 'FAIL' }
    [void]$results.Add([pscustomobject]@{ check = $Name; status = $status; pass = $Pass; detail = $Detail })
    $col = switch ($status) { 'PASS' { 'Green' } 'PENDING' { 'Yellow' } default { 'Red' } }
    Write-Host ("  [{0,-7}] {1,-40} {2}" -f $status, $Name, $Detail) -ForegroundColor $col
}

Write-Host "`nSOC-Lab Elastic Stack health validation" -ForegroundColor Cyan
Write-Host "  expected version : 9.5.3" -ForegroundColor DarkGray
Write-Host "  endpoints        : ES 127.0.0.1:9200 | Kibana 127.0.0.1:5601`n" -ForegroundColor DarkGray

# --- Load secrets -------------------------------------------------------------
if (-not (Test-Path -LiteralPath $EnvFile)) {
    Write-Host "  .env not found at $EnvFile - run scripts/setup/New-LabSecrets.ps1 first" -ForegroundColor Red
    exit 2
}
$envMap = @{}
foreach ($line in Get-Content -LiteralPath $EnvFile) {
    $t = $line.Trim()
    if ($t -eq '' -or $t.StartsWith('#')) { continue }
    $i = $t.IndexOf('=')
    if ($i -lt 1) { continue }
    $envMap[$t.Substring(0, $i).Trim()] = $t.Substring($i + 1).Trim()
}
$esPass  = $envMap['ELASTIC_PASSWORD']
$kbToken = $envMap['KIBANA_SERVICE_TOKEN']

$esAuth = @{ Authorization = "Basic $([Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("elastic:$esPass")))" }
$esUrl  = 'http://127.0.0.1:9200'
$kbUrl  = 'http://127.0.0.1:5601'

# --- 1. Elasticsearch reachable ------------------------------------------------
try {
    $root = Invoke-RestMethod -Uri $esUrl -Headers $esAuth -TimeoutSec 20
    Add-Result 'elasticsearch.reachable' $true "$($root.name) v$($root.version.number) cluster='$($root.cluster_name)'"
    Add-Result 'elasticsearch.version' ($root.version.number -eq '9.5.3') "got $($root.version.number), expected 9.5.3"
} catch {
    Add-Result 'elasticsearch.reachable' $false $_.Exception.Message
    Write-Host "`nElasticsearch is not reachable. Start it: scripts/setup/Install-ElasticStack.ps1 -Stage StartElasticsearch" -ForegroundColor Red
    if ($Json) { $results | ConvertTo-Json -Depth 4 } else { }
    exit 1
}

# --- 2. Security is enforcing -------------------------------------------------
$unauth = try { (Invoke-WebRequest -Uri "$esUrl/_cluster/health" -UseBasicParsing -TimeoutSec 20).StatusCode } catch { [int]$_.Exception.Response.StatusCode }
Add-Result 'security.enforces_auth' ($unauth -eq 401) "unauthenticated /_cluster/health -> HTTP $unauth (want 401)"

# --- 3. Cluster health ---------------------------------------------------------
$h = Invoke-RestMethod -Uri "$esUrl/_cluster/health" -Headers $esAuth -TimeoutSec 20
Add-Result 'cluster.health' ($h.status -in @('green','yellow')) "status=$($h.status) nodes=$($h.number_of_nodes) shards=$($h.active_shards) unassigned=$($h.unassigned_shards)"

# --- 4. Loopback-only binds ---------------------------------------------------
foreach ($p in 9200, 5601) {
    $addrs = @(Get-NetTCPConnection -LocalPort $p -State Listen -ErrorAction SilentlyContinue |
               Select-Object -ExpandProperty LocalAddress -Unique)
    if ($addrs.Count -eq 0) { Add-Result "network.bind.$p" $false 'nothing listening'; continue }
    $bad = @($addrs | Where-Object { $_ -in @('0.0.0.0','::') })
    Add-Result "network.bind.$p" ($bad.Count -eq 0) "listening on $($addrs -join ', ')"
}

# --- 5/6. Kibana ---------------------------------------------------------------
try {
    # /api/status is redacted without credentials, so authenticate to get the
    # version and per-plugin/core detail.
    $kbAuth = @{ Authorization = "Basic $([Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("elastic:$esPass")))" }
    $kb = Invoke-RestMethod -Uri "$kbUrl/api/status" -Headers $kbAuth -TimeoutSec 30
    Add-Result 'kibana.reachable' $true "v$($kb.version.number) status=$($kb.status.overall.level)"
    Add-Result 'kibana.available' ($kb.status.overall.level -eq 'available') "overall=$($kb.status.overall.level)"

    foreach ($svc in 'elasticsearch', 'savedObjects') {
        $lvl = $kb.status.core.$svc.level
        Add-Result "kibana.core.$svc" ($lvl -eq 'available') "level=$lvl"
    }

    $plugins = @($kb.status.plugins.PSObject.Properties)
    $bad = @($plugins | Where-Object { $_.Value.level -and $_.Value.level -ne 'available' })
    Add-Result 'kibana.plugins' ($bad.Count -eq 0) "$($plugins.Count) plugins, $($bad.Count) not available"
} catch {
    Add-Result 'kibana.reachable' $false $_.Exception.Message
}

# --- 7. Service account token --------------------------------------------------
if ($kbToken -and $kbToken -notlike 'CHANGE_ME*') {
    try {
        $me = Invoke-RestMethod -Uri "$esUrl/_security/_authenticate" -Headers @{ Authorization = "Bearer $kbToken" } -TimeoutSec 20
        Add-Result 'kibana.service_token' ($me.username -eq 'elastic/kibana') "authenticates as '$($me.username)'"
    } catch {
        Add-Result 'kibana.service_token' $false "token rejected: $($_.Exception.Message)"
    }
} else {
    Add-Result 'kibana.service_token' $false 'KIBANA_SERVICE_TOKEN missing from .env (run -Stage ServiceToken)'
}

# --- 8. Fleet + data streams ---------------------------------------------------
try {
    $fleet = Invoke-RestMethod -Uri "$kbUrl/api/fleet/agents/setup" -Headers @{ Authorization = "Basic $([Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("elastic:$esPass")))" } -TimeoutSec 30
    # 9.5.3 shape (verified against the live API):
    #   { isReady, missing_requirements: [ "fleet_server", ... ],
    #     missing_optional_features: [ "encrypted_saved_object_encryption_key_required" ],
    #     is_secrets_storage_enabled, package_verification_key_id, ... }
    # There is NO isInitialized field in 9.5.3.
    if ($null -eq $fleet.isReady) {
        Add-Result 'fleet.setup' $false "setup API returned an unexpected shape: $($fleet.PSObject.Properties.Name -join ', ')"
    } elseif ($fleet.isReady) {
        Add-Result 'fleet.setup' $true 'Fleet setup is ready'
    } else {
        $reqs = @($fleet.missing_requirements)
        $detail = "not ready; missing_requirements=[$($reqs -join ', ')]"
        if ($reqs -contains 'fleet_server') { $detail += ' (expected: Fleet Server is added in Phase 4)' }
        if ($RequireTelemetry) { Add-Result 'fleet.setup' $false $detail }
        else { Add-Result 'fleet.setup' $true $detail -Pending }
    }

    # encrypted_saved_object_encryption_key_required is reported as an OPTIONAL
    # missing feature. It only matters if you use encrypted saved objects
    # (e.g. ES|QL rules with sensitive values), so surface it, do not fail on it.
    # NOTE: use Write-Host here, not the installer's Write-Warn2 helper - this
    # script is standalone and calling an undefined function throws, which was
    # being caught by the surrounding try and reported as a bogus HTTP 0 failure.
    $opt = @($fleet.missing_optional_features)
    if ($opt.Count -gt 0) { Write-Host "  [NOTE   ] optional Fleet features missing: $($opt -join ', ')" -ForegroundColor Yellow }
} catch {
    $code = try { [int]$_.Exception.Response.StatusCode } catch { 0 }
    if ($code -eq 400) {
        $detail = 'Fleet setup endpoint reports not ready (expected before Phase 4)'
        if ($RequireTelemetry) { Add-Result 'fleet.setup' $false $detail }
        else { Add-Result 'fleet.setup' $true $detail -Pending }
    } else {
        Add-Result 'fleet.setup' $false "setup API returned HTTP $code"
    }
}

$ds = Invoke-RestMethod -Uri "$esUrl/_data_stream?filter_path=data_streams" -Headers $esAuth -TimeoutSec 20
$names = @($ds.data_streams | ForEach-Object { $_.name })
$expected = @('logs-system.security', 'logs-system.auth', 'logs-windows.sysmon_operational', 'logs-windows.powershell_operational')
$missing = @($expected | Where-Object { $names -notcontains $_ })
$detail = "$($expected.Count - $missing.Count)/$($expected.Count) expected data streams present"
if ($missing.Count -gt 0) { $detail += " (missing: $($missing -join ', '))" }
if ($missing.Count -eq 0) {
    Add-Result 'ingest.data_streams' $true $detail
} elseif ($RequireTelemetry) {
    Add-Result 'ingest.data_streams' $false $detail
} else {
    Add-Result 'ingest.data_streams' $true "$detail - expected before Phase 4" -Pending
}

# --- Summary -------------------------------------------------------------------
$failed  = @($results | Where-Object { $_.status -eq 'FAIL' })
$pending = @($results | Where-Object { $_.status -eq 'PENDING' })
Write-Host ""
if ($failed.Count -eq 0) {
    $msg = "PASS - $($results.Count) checks green"
    if ($pending.Count -gt 0) { $msg += ", $($pending.Count) pending (pre-telemetry)" }
    Write-Host "  RESULT: $msg" -ForegroundColor Green
} else {
    Write-Host "  RESULT: FAIL - $($failed.Count) of $($results.Count) checks failed:" -ForegroundColor Red
    $failed | ForEach-Object { Write-Host "    - $($_.check): $($_.detail)" -ForegroundColor Red }
}

if ($Json) { $results | Select-Object check, status, detail | ConvertTo-Json -Depth 4 }

if ($ReportPath) {
    $full = if ([System.IO.Path]::IsPathRooted($ReportPath)) { $ReportPath } else { Join-Path $RepoRoot $ReportPath }
    $dir = Split-Path -Parent $full
    if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
    $payload = [pscustomobject]@{
        generatedAtUtc   = (Get-Date).ToUniversalTime().ToString('o')
        expectedVersion  = '9.5.3'
        requireTelemetry = [bool]$RequireTelemetry
        pass             = ($failed.Count -eq 0)
        counts           = [pscustomobject]@{
            pass = @($results | Where-Object { $_.status -eq 'PASS' }).Count
            pending = $pending.Count
            fail = $failed.Count
        }
        checks           = ($results | Select-Object check, status, detail)
    }
    $enc = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($full, ($payload | ConvertTo-Json -Depth 6), $enc)
    Write-Host "  report written to $full" -ForegroundColor DarkGray
}

exit $(if ($failed.Count -eq 0) { 0 } else { 1 })
