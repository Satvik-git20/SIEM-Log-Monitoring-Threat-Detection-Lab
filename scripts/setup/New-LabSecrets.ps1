<#
.SYNOPSIS
    Generates cryptographically random local lab secrets and writes the
    gitignored .env from .env.example. Never overwrites an existing .env
    unless -Force is given.

.DESCRIPTION
    Password policy for this lab:
      - >= 24 characters
      - mixed case + digits + a symbol
      - generated with System.Security.Cryptography.RandomNumberGenerator,
        not Get-Random (which is not a CSPRNG)

    These credentials protect a loopback-only lab on one workstation. They are
    NOT production credentials and must not be reused anywhere else.

.EXAMPLE
    pwsh -File scripts/setup/New-LabSecrets.ps1
    pwsh -File scripts/setup/New-LabSecrets.ps1 -Force    # regenerate
#>
[CmdletBinding()]
param([switch]$Force)

$ErrorActionPreference = 'Stop'
$RepoRoot = Resolve-Path (Join-Path (Split-Path -Parent $MyInvocation.MyCommand.Path) '..\..')
$Example  = Join-Path $RepoRoot '.env.example'
$EnvFile  = Join-Path $RepoRoot '.env'

function New-LabPassword {
    param([int]$Length = 28)
    # Exclude characters that are painful in .env / Kibana / shell contexts:
    # quotes, backslash, backtick, dollar, and whitespace.
    $sets = @(
        'abcdefghijkmnopqrstuvwxyz',
        'ABCDEFGHJKLMNPQRSTUVWXYZ',
        '23456789',
        '!#%+=?@:,.<>_-|~'
    )
    $all = ($sets -join '').ToCharArray()
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()

    function Get-RandomInt([int]$Max) {
        # Rejection sampling to avoid modulo bias.
        # NOTE: the buffer MUST be 1 byte here. Deriving a UInt32 and comparing
        # it against a byte-scaled limit rejects ~all values and hangs forever.
        if ($Max -gt 256) { throw "Get-RandomInt supports Max <= 256, got $Max" }
        $limit = [math]::Floor(256 / $Max) * $Max
        $buf = New-Object byte[] 1
        do { $rng.GetBytes($buf); $val = [int]$buf[0] } while ($val -ge $limit)
        return ($val % $Max)
    }

    # Guarantee at least one character from each set
    $chars = New-Object System.Collections.Generic.List[char]
    foreach ($s in $sets) { $chars.Add($s[(Get-RandomInt $s.Length)]) }
    while ($chars.Count -lt $Length) { $chars.Add($all[(Get-RandomInt $all.Length)]) }

    # Fisher-Yates shuffle with the same CSPRNG
    for ($i = $chars.Count - 1; $i -gt 0; $i--) {
        $j = Get-RandomInt ($i + 1)
        $tmp = $chars[$i]; $chars[$i] = $chars[$j]; $chars[$j] = $tmp
    }
    $rng.Dispose()
    return -join $chars
}

if ((Test-Path -LiteralPath $EnvFile) -and -not $Force) {
    Write-Host ".env already exists at $EnvFile" -ForegroundColor Yellow
    Write-Host "Re-run with -Force to regenerate ALL lab secrets." -ForegroundColor Yellow
    Write-Host "Warning: regenerating changes the `elastic` superuser password, which is" -ForegroundColor Yellow
    Write-Host "already persisted in C:\elastic\elasticsearch-*\config\elasticsearch.yml." -ForegroundColor Yellow
    Write-Host "Use scripts/troubleshooting/Reset-ElasticPassword.ps1 for that case." -ForegroundColor Yellow
    exit 1
}

if (-not (Test-Path -LiteralPath $Example)) { throw "Missing $Example" }

$generated = [ordered]@{
    # ES_BOOTSTRAP_PASSWORD becomes the keystore `bootstrap.password` secure
    # setting. It is the transient credential that lets the install script set
    # the real elastic password via the change-password API, after which it is
    # retired. Elasticsearch 9.x removed `ELASTIC_PASSWORD` from elasticsearch.yml,
    # so this is the supported bootstrap path.
    'ES_BOOTSTRAP_PASSWORD'  = New-LabPassword
    'ELASTIC_PASSWORD'       = New-LabPassword
    # KIBANA_SERVICE_TOKEN is NOT generated here. It is a service account
    # token, not a password: it can only be minted by a running Elasticsearch
    # via the Service Accounts API. Install-ElasticStack.ps1 -Stage ServiceToken
    # creates it and writes it into .env.
    'KIBANA_SERVICE_TOKEN'   = 'CHANGE_ME_created_by_Install-ElasticStack_-Stage_ServiceToken'
    # KIBANA_ENCRYPTION_KEY becomes xpack.encryptedSavedObjects.encryptionKey in
    # kibana.yml. Kibana requires >= 32 characters. Without it, Fleet setup
    # fails forever with FleetEncryptedSavedObjectEncryptionKeyRequired.
    # Rotating it makes existing encrypted saved objects unreadable.
    'KIBANA_ENCRYPTION_KEY'  = (New-LabPassword -Length 48)
}

$lines = foreach ($line in Get-Content -LiteralPath $Example) {
    if ($line -match '^([A-Z_][A-Z0-9_]*)=') {
        $key = $Matches[1]
        if ($generated.Contains($key)) { "$key=$($generated[$key])" } else { $line }
    } else { $line }
}

Set-Content -LiteralPath $EnvFile -Value $lines -Encoding UTF8

# Prove the file is actually ignored before we tell anyone it is safe
$ignored = $false
try {
    Push-Location $RepoRoot
    $null = git check-ignore -q .env 2>$null
    $ignored = ($LASTEXITCODE -eq 0)
} finally { Pop-Location }

Write-Host "Wrote $EnvFile" -ForegroundColor Green
Write-Host "  ES_BOOTSTRAP_PASSWORD  : $($generated['ES_BOOTSTRAP_PASSWORD'].Length) chars (transient, retired at install)" -ForegroundColor DarkGray
Write-Host "  ELASTIC_PASSWORD       : $($generated['ELASTIC_PASSWORD'].Length) chars" -ForegroundColor DarkGray
Write-Host "  KIBANA_SERVICE_TOKEN   : created later by Install-ElasticStack.ps1 -Stage ServiceToken" -ForegroundColor DarkGray
Write-Host "  KIBANA_ENCRYPTION_KEY  : $($generated['KIBANA_ENCRYPTION_KEY'].Length) chars (must stay >= 32; rotating it orphans encrypted saved objects)" -ForegroundColor DarkGray
if ($ignored) {
    Write-Host "  .gitignore check       : CONFIRMED ignored by git" -ForegroundColor Green
} else {
    Write-Host "  .gitignore check       : WARNING - .env is NOT ignored! Do not commit." -ForegroundColor Red
    exit 2
}
Write-Host "`nNext: pwsh -File scripts/setup/Install-ElasticStack.ps1" -ForegroundColor Cyan
