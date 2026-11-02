<#
.SYNOPSIS
    Exports the Elasticsearch field inventory for the lab's index templates.

.DESCRIPTION
    Runs `_field_caps` against the indices the lab is producing and writes a
    markdown inventory into `elastic/index-templates/field-inventory.md`.

    The inventory is the reference for detection engineers: it shows which
    fields are actually populated (and their types) so a rule is written
    against real data, not guesses. Re-run it after any new integration or
    ILM rollover so the template docs stay in sync with the data.

        pwsh -File scripts/validation/Export-FieldInventory.ps1

.EXAMPLE
    pwsh -File scripts/validation/Export-FieldInventory.ps1
#>
param(
    [string]$OutPath = 'elastic/index-templates/field-inventory.md'
)

$ErrorActionPreference = 'Stop'
$RepoRoot = Resolve-Path (Join-Path (Split-Path -Parent $MyInvocation.MyCommand.Path) '..\..')
$OutFile  = Join-Path $RepoRoot $OutPath
$EsUrl    = 'http://127.0.0.1:9200'

if (-not (Test-Path 'http://127.0.0.1:9200/_cluster/health')) {
    Write-Host "  Elasticsearch is not reachable at $EsUrl - start it first." -ForegroundColor Red
    exit 1
}

Write-Host "`n=== SOC-Lab field inventory ===" -ForegroundColor Cyan
Write-Host "  collecting from $EsUrl`n" -ForegroundColor DarkGray

# --- Query field capabilities across all indices --------------------------------
$response = Invoke-RestMethod -Uri "$EsUrl/_field_caps?filter_path=indices.*.fields" -Method Post -Body '{"fields":["*"]}' -ContentType 'application/json' -TimeoutSec 60

$lines = @(
    '# Elasticsearch field inventory (SOC-Lab)',
    '',
    'Collected: (Get-Date).ToUniversalTime().ToString("o")',
    'Target:   logs-system.* (Windows auth/system/application), logs-windows.* (Sysmon, PowerShell)',
    'Method:   GET /_field_caps with fields=["*"]',
    '',
    '| Field | Type | Populated (indices) | Purpose ',
    '|---|---|---|---|'
)

$indices = @($response.indices)
if ($indices.Count -eq 0) {
    Write-Host "  no indices matched" -ForegroundColor Yellow
} else {
    $allFields = @{}
    $indices | ForEach-Object {
        $idx = $_.Name
        $fields = $_.fields
        if (-not $fields) { return }
        $fields.GetEnumerator() | ForEach-Object {
            $name = $_.Key
            $type = $_.Type
            if (-not $allFields.ContainsKey($name)) { $allFields[$name] = @() }
            $allFields[$name] += $idx
            $null = $allFields[$name].Add($type)
        }
    }
    $allFields.GetEnumerator() | Sort-Object -Property Name | ForEach-Object {
        $grouped = @($allFields[$_.Name])
        $types = ($grouped | Sort-Object -Unique)
        $purpose = switch -Regex ($_.Name) {
            'EventID|eventID' { 'Event identifiers (Sysmon, Windows, PowerShell)'; break }
            'AccountName|account_name|username' { 'Account names in auth events'; break }
            'CommandLine|command_line' { 'Process command lines (DET-03)'; break }
            'LogonId|logon_id' { 'Logon IDs for correlation'; break }
            'SourceIP|source_ip|ip' { 'Source addresses'; break }
            'TargetImage|target_image|process' { 'Process image paths'; break }
            'ParentProcessGuid|parent_process_guid' { 'Parent process (DEP correlation)'; break }
            'UtcTime|timestamp' { 'Event timestamps'; break }
            default { '' }
        }
        $lines += "| $($_.Name) | $(($types -join ', ') -replace 'Object','object') | $($grouped -join ', ') | $purpose"
    }
}

$lines += ''
$lines += '| Summary | Count |'
$lines += '|---|---|'
$fieldCounts = @($allFields.GetEnumerator() | Measure-Object -Property Name -Maximum 1).Count
$lines += ("| total fields | $fieldCounts |")
$lines += "| distinct event-id fields | $(@($allFields.GetEnumerator() | Where-Object { $_.Name -match 'EventID|eventID' }).Count) |"

$content = ($lines -join "`n")
$enc = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText($OutFile, $content, $enc)

Write-Host "  written to $OutFile" -ForegroundColor Green
Write-Host "  fields  : $fieldCounts" -ForegroundColor White
Write-Host "  indices : $($indices.Count)" -ForegroundColor White

$summary = @(
    '## Notes',
    '',
    "- This inventory is generated; do not hand-edit `elastic/index-templates/field-inventory.md`. It is referenced by `docs/configuration.md` and by `Install-ElasticStack.ps1`'s ILM documentation.",
    '- Re-run after new integrations or ILM rollovers:',
    '  pwsh -File scripts/validation/Export-FieldInventory.ps1',
    ''
)
[System.IO.File]::AppendAllText($OutFile, ($summary -join "`n"))
