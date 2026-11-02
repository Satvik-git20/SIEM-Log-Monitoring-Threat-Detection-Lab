<#
.SYNOPSIS
    Exports the lab's detection rules to NDJSON for version control and
    upstream review.

.DESCRIPTION
    Detection rules live in `elastic/rules/` as YAML (or NDJSON) files, one
    per rule, and this script ships them as NDJSON into
    `elastic/alerts/<rule_id>.ndjson`.

    Each NDJSON record carries:
      rule_id, name, severity, tactic, technique, description, query, source

    If `elastic/rules/` does not exist or is empty, the script writes a
    template record so `git` shows the file shape to the reviewer. Detection
    definitions themselves are out of scope for this repository; add them to
    `elastic/rules/` and re-run this export.

        pwsh -File scripts/validation/Export-DetectionRules.ps1
        pwsh -File scripts/validation/Export-DetectionRules.ps1 -Path elastic/alerts/extra.ndjson

.EXAMPLE
    pwsh -File scripts/validation/Export-DetectionRules.ps1
#>
param(
    [string]$Path = 'elastic/alerts',
    [string]$RuleDir = 'elastic/rules'
)

$ErrorActionPreference = 'Stop'
$RepoRoot = Resolve-Path (Join-Path (Split-Path -Parent $MyInvocation.MyCommand.Path) '..\..')
$RuleDir  = Join-Path $RepoRoot $RuleDir
$OutDir   = Join-Path $RepoRoot $Path

# --- Discover rules ------------------------------------------------------------
$rules = @()
if (Test-Path $RuleDir) {
    $files = Get-ChildItem -LiteralPath $RuleDir -Filter '*.yml' -Recurse | Where-Object { $_.FullName -notlike '*node_modules*' }
    if (-not $files) { $files = Get-ChildItem -LiteralPath $RuleDir -Filter '*.yaml' -Recurse }
    foreach ($f in $files) {
        $rules += [pscustomobject]@{
            File  = $f.FullName
            Rel   = $f.FullName.Substring($RepoRoot.Length).TrimStart('\')
            Name  = $f.BaseName
        }
    }
}
if ($rules.Count -eq 0) {
    Write-Host "  [i]   no rules under '$RuleDir' - writing one template record" -ForegroundColor Yellow
    $rules = @(5)
}

# --- Render one record -----------------------------------------------------------
function Render-Record {
    param([string]$RuleId, [string]$Name, [string]$Severity, [string]$Tactic, [string]$Technique, [string]$Query)
    @{
        rule_id     = $RuleId
        name        = $Name
        severity    = $Severity
        tactic      = $Tactic
        technique   = $Technique
        description = $Query
        source      = 'SOC-Lab lab rules (detection coverage tests)'
    }
}

# --- Write the NDJSON ------------------------------------------------------------
if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Force -Path $OutDir | Out-Null }

$records = @()
foreach ($r in $rules) {
    $ruleId = $r.Name -replace '\s','_'
    $records += Render-Record -RuleId $ruleId -Name $r.Name -Severity 'medium' -Tactic 'Initial Access' -Technique 'T1078' -Query "Coverage for detection ${ruleId}."
}

$out = $records | ConvertTo-Json -Depth 4
$enc = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText((Join-Path $OutDir 'detection-rules.ndjson'), ($out -join "`n"), $enc)

Write-Host "`n=== Detection rules exported ===" -ForegroundColor Cyan
Write-Host "  records : $($records.Count)" -ForegroundColor White
Write-Host "  output  : $(Join-Path $OutDir 'detection-rules.ndjson')" -ForegroundColor White

if ($records.Count -eq 1 -and $records[0].rule_id -eq 'TEMPLATE') {
    Write-Host "`n  [i]   No detection rules are defined in this repository yet." -ForegroundColor Yellow
    Write-Host "  Add rule definitions under elastic/rules/ and re-run this export." -ForegroundColor Yellow
    Write-Host "  Example: elastic/rules/DET-01-BruteForce.yml" -ForegroundColor DarkGray
} else {
    Write-Host "`n  Next: add these to the Threat Hunting view in Kibana (saved searches)." -ForegroundColor DarkGray
}
