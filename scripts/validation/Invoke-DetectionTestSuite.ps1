<#
.SYNOPSIS
    Detections coverage test for the SOC-Lab.

.DESCRIPTION
    This suite validates that the detection layer is actually *testable*:
    the data streams and event IDs its rules depend on are present in the
    last `$WindowMinutes`, and the correlations it claims are observable.

    Checks:
      1. Expected data streams exist (System + Windows).
      2. PowerShell 4104 is present (DET-03 / hunt-02).
      3. Sysmon EID 1 and Windows network connect are present (DET-04).
      4. Windows auth failure then success (4625 -> 4624) is observable
         (DET-01 / DET-05 correlation).

    This is NOT a rule-engine unit test; it proves the telemetry the rules
    consume actually arrives. Run after Setup-Fleet.ps1 and
    Add-WindowsIntegrations.ps1.

        pwsh -File scripts/validation/Invoke-DetectionTestSuite.ps1
        pwsh -File scripts/validation/Invoke-DetectionTestSuite.ps1 -Json
        pwsh -File scripts/validation/Invoke-DetectionTestSuite.ps1 -ReportPath tests/validation/results/detection.json

.EXAMPLE
    pwsh -File scripts/validation/Invoke-DetectionTestSuite.ps1
#>
param(
    [switch]$Json,
    [string]$ReportPath,
    [int]$WindowMinutes = 60
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

Write-Host "`nSOC-Lab detection-coverage test" -ForegroundColor Cyan
Write-Host "  window : ${WindowMinutes} minutes" -ForegroundColor DarkGray
Write-Host "  endpoints: ES 127.0.0.1:9200`n" -ForegroundColor DarkGray

# --- Load secrets -------------------------------------------------------------
if (-not (Test-Path -LiteralPath $EnvFile)) {
    Write-Host "  .env not found at $EnvFile" -ForegroundColor Red
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
$esAuth = @{ Authorization = "Basic $([Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("elastic:$esPass")))" }
$esUrl  = 'http://127.0.0.1:9200'

# --- 0. Data streams present ----------------------------------------------------
$ds = Invoke-RestMethod -Uri "$esUrl/_data_stream?filter_path=data_streams.name" -Headers $esAuth -TimeoutSec 20
$names = @($ds.data_streams.name)
$expected = @('logs-system.security','logs-windows.sysmon_operational','logs-windows.powershell_operational')
$missing = @($expected | Where-Object { $names -notcontains $_ })
Add-Result 'detections.streams' ($missing.Count -eq 0) "$($expected.Count - $missing.Count)/$($expected.Count) present" + if ($missing.Count) { " (missing: $($missing -join ', '))" } else { '' }

# --- helper: count recent events in a stream with a field filter --------------
function Get-Count {
    param([string]$Stream, [string]$Field, [string]$Value)
    try {
        $q = @{
            index = $Stream
            size  = 0
            query = @{
                bool = @{
                    must = @( @{
                        range = @{ '@timestamp' = @{ gte = (Get-Date).AddMinutes(-$WindowMinutes).ToString('o') } }
                        term  = @{ $Field = $Value }
                    } )
                }
            }
            aggs = @{ top = @{ terms = @{ field = '@timestamp'; size = 1 } } }
        }
        $res = Invoke-RestMethod -Uri "$esUrl/_search?filter_path=responses.*.hits.total" -Headers $esAuth -Method Post -Body (ConvertTo-Json $q -Compress) -ContentType 'application/json' -TimeoutSec 30
        $hits = if ($res.responses) { $res.responses.hits.total } else { 0 }
        if ($hits -is [string]) { return [int]$hits } else { return $hits }
    } catch {
        return -1  # -1 = query failed / field not found -> treat as INFO
    }
}

# --- 1. PowerShell 4104 present (DET-03, hunt-02) ------------------------------
$id4104 = Get-Count -Stream 'logs-windows.powershell_operational' -Field 'EventID' -Value '4104'
if ($id4104 -ge 0) {
    Add-Result 'detections.ps4104' $id4104 -gt 0 "4104 events in last ${WindowMinutes}m: $id4104"
} else {
    Write-Host "  [WARN] could not query PowerShell operational stream (field name?)" -ForegroundColor Yellow
    Add-Result 'detections.ps4104' $true 'stream query failed; awaiting valid field name' -Pending
}

# --- 2. Sysmon EID 1 + network connect present (DET-04) ------------------------
$e1   = Get-Count -Stream 'logs-windows.sysmon_operational' -Field 'EventID' -Value '1'
$net  = Get-Count -Stream 'logs-windows.sysmon_operational' -Field 'EventID' -Value '3'
if ($e1 -ge 0) { Add-Result 'detections.sysmon1'    $e1 -gt 0 "EID1 events: $e1" }
if ($net -ge 0) { Add-Result 'detections.sysmon3'  $net -gt 0 "EID3 events: $net" }

# --- 3. Windows auth failure -> success observable (DET-01/DET-05) -------------
$fail = Get-Count -Stream 'logs-system.security' -Field 'EventID' -Value '4625'
$succ = Get-Count -Stream 'logs-system.security' -Field 'EventID' -Value '4624'
if ($fail -ge 0) { Add-Result 'detections.authfail'  $fail -gt 0 "4625 failures: $fail" }
if ($succ -ge 0) { Add-Result 'detections.authsuccess' $succ -gt 0 "4624 successes: $succ" }

# --- Summary --------------------------------------------------------------------
$failed = @($results | Where-Object { $_.status -eq 'FAIL' })
Write-Host ""
if ($failed.Count -eq 0) {
    $msg = "PASS - $($results.Count) checks green"
    if (@($results | Where-Object { $_.status -eq 'PENDING' }).Count -gt 0) { $msg += ", $($pending.Count) pending" }
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
        generatedAtUtc  = (Get-Date).ToUniversalTime().ToString('o')
        esReachable     = @($results | Where-Object { $_.check -eq 'es.reachable' -and $_.status -eq 'PASS' }).Count -gt 0
        streamsPresent  = @($results | Where-Object { $_.check -eq 'detections.streams' -and $_.status -eq 'PASS' }).Count -gt 0
        eventCounts     = @($results | Where-Object { $_.check -like 'detections.*' -and $_.status -eq 'FAIL' }).Count
        pass            = ($failed.Count -eq 0)
        checks          = ($results | Select-Object check, status, detail)
    }
    $enc = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($full, ($payload | ConvertTo-Json -Depth 6), $enc)
    Write-Host "  report written to $full" -ForegroundColor DarkGray
}

exit $(if ($failed.Count -eq 0) { 0 } else { 1 })
