<#
.SYNOPSIS
    Independent log-ingestion validation for the SOC-Lab.

.DESCRIPTION
    Proves that telemetry actually reaches Elasticsearch as data streams,
    rather than just that the stack is "up". Exits non-zero when any expected
    data stream is missing, or when the expected recent event counts are zero.

    It is the ingestion counterpart to Test-ElasticStackHealth.ps1:
    health checks the stack, ingestion checks the data.

        pwsh -File scripts/validation/Test-LogIngestion.ps1
        pwsh -File scripts/validation/Test-LogIngestion.ps1 -Json
        pwsh -File scripts/validation/Test-LogIngestion.ps1 -ReportPath tests/validation/results/ingestion.json

.EXAMPLE
    pwsh -File scripts/validation/Test-LogIngestion.ps1
#>
param(
    [switch]$Json,
    [string]$ReportPath,
    [int]$WindowMinutes = 30
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
    Write-Host ("  [{0,-7}] {1,-42} {2}" -f $status, $Name, $Detail) -ForegroundColor $col
}

Write-Host "`nSOC-Lab log ingestion validation" -ForegroundColor Cyan
Write-Host "  window : ${WindowMinutes} minutes" -ForegroundColor DarkGray
Write-Host "  endpoints: ES 127.0.0.1:9200 | Kibana 127.0.0.1:5601`n" -ForegroundColor DarkGray

# --- Load secrets -------------------------------------------------------------
if (-not (Test-Path -LiteralPath $EnvFile)) {
    Write-Host "  .env not found at $EnvFile - run New-LabSecrets.ps1 first" -ForegroundColor Red
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
$esPass = $envMap['ELASTIC_PASSWORD']
if (-not $esPass -or $esPass -like 'CHANGE_ME*') {
    Write-Host "  ELASTIC_PASSWORD is still a placeholder" -ForegroundColor Yellow
}
$esAuth = @{ Authorization = "Basic $([Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("elastic:$esPass")))" }
$esUrl  = 'http://127.0.0.1:9200'
$kbUrl  = 'http://127.0.0.1:5601'

# --- 1. Elasticsearch reachable -------------------------------------------------
try {
    $root = Invoke-RestMethod -Uri $esUrl -Headers $esAuth -TimeoutSec 20
    Add-Result 'es.reachable' $true "$($root.name) v$($root.version.number)"
} catch {
    Add-Result 'es.reachable' $false $_.Exception.Message
    Write-Host "`nElasticsearch is not reachable." -ForegroundColor Red
    exit 1
}

# --- 2. Expected data streams present -----------------------------------------
$ds = Invoke-RestMethod -Uri "$esUrl/_data_stream?filter_path=data_streams.name" -Headers $esAuth -TimeoutSec 20
$names = @($ds.data_streams.name)
$expected = @('logs-system.security','logs-system.system','logs-system.application',
              'logs-windows.sysmon_operational','logs-windows.powershell_operational')
$missing = @($expected | Where-Object { $names -notcontains $_ })
Add-Result 'ingest.data_streams' ($missing.Count -eq 0) `
    "$($expected.Count - $missing.Count)/$($expected.Count) present" + if ($missing.Count) { " (missing: $($missing -join ', '))" } else { '' }

# --- 3. Recent event volume (proves data, not just streams) ---------------------
$window = (Get-Date).AddMinutes(-$WindowMinutes)
$counts = @{}
foreach ($stream in @('logs-system.security','logs-windows.sysmon_operational')) {
    try {
        $q = @{
            index    = $stream
            size     = 0
            query    = @{ range = @{ '@timestamp' = @{ gte = $window.ToString('o') } } }
            aggs     = @{ top = @{ terms = @{ field = '@timestamp' ; size = 1 } } }
        }
        $res = Invoke-RestMethod -Uri "$esUrl/_search?filter_path=responses.*.hits.total" -Headers $esAuth -Method Post -Body (ConvertTo-Json $q -Compress) -ContentType 'application/json' -TimeoutSec 30
        $hits = if ($res.responses) { $res.responses.hits.total } else { 0 }
        $counts[$stream] = if ($hits -is [string]) { [int]$hits } else { $hits }
    } catch {
        $counts[$stream] = 0
    }
}

$report = @()
$counts.GetEnumerator() | ForEach-Object { $report += $_ }
foreach ($kv in $report) {
    $ok = $_.Value -gt 0
    Add-Result ("ingest.${_.Name}") $ok "$kv hits in last $WindowMinutes minutes"
}

# --- 4. Kibana reachable (Fleet enabled) ---------------------------------------
try {
    $kbAuth = @{ Authorization = "Basic $([Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("elastic:$esPass")))" }
    $kb = Invoke-RestMethod -Uri "$kbUrl/api/status" -Headers $kbAuth -TimeoutSec 30
    Add-Result 'kibana.reachable' $true "v$($kb.version.number) overall=$($kb.status.overall.level)"
} catch {
    Add-Result 'kibana.reachable' $false $_.Exception.Message
}

# --- Summary -------------------------------------------------------------------
$failed = @($results | Where-Object { $_.status -eq 'FAIL' })
Write-Host ""
if ($failed.Count -eq 0) {
    $msg = "PASS - $($results.Count) checks green"
    if (@($results | Where-Object { $_.status -eq 'PENDING' }).Count -gt 0) { $msg += ", some checks pending" }
    Write-Host "  RESULT: $msg" -ForegroundColor Green
} else {
    Write-Host "  RESULT: FAIL - $($failed.Count) check(s) failed" -ForegroundColor Red
    $failed | ForEach-Object { Write-Host "    - $($_.check): $($_.detail)" -ForegroundColor Red }
}

if ($Json) { $results | Select-Object check, status, detail | ConvertTo-Json -Depth 4 }
if ($ReportPath) {
    $full = if ([System.IO.Path]::IsPathRooted($ReportPath)) { $ReportPath } else { Join-Path $RepoRoot $ReportPath }
    $dir = Split-Path -Parent $full
    if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
    $payload = [pscustomobject]@{
        generatedAtUtc   = (Get-Date).ToUniversalTime().ToString('o')
        esReachable      = @($results | Where-Object { $_.check -eq 'es.reachable' -and $_.status -eq 'PASS' }).Count -gt 0
        streamsPresent   = @($results | Where-Object { $_.check -eq 'ingest.data_streams' -and $_.status -eq 'PASS' }).Count -gt 0
        eventCounts      = @($results | Where-Object { $_.check -like 'ingest.*' -and $_.status -eq 'FAIL' }).Count
        pass             = ($failed.Count -eq 0)
        checks           = ($results | Select-Object check, status, detail)
    }
    $enc = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($full, ($payload | ConvertTo-Json -Depth 6), $enc)
    Write-Host "  report written to $full" -ForegroundColor DarkGray
}

exit $(if ($failed.Count -eq 0) { 0 } else { 1 })
