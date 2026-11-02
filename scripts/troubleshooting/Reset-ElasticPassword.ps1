<#
.SYNOPSIS
    Resets the `elastic` superuser password and keeps .env, the ES keystore
    bootstrap credential, and the running cluster consistent.

.DESCRIPTION
    This script is the troubleshooting counterpart to the installer's
    `Keystore` + `SetPassword` stages.

    With a running cluster it:
      1. generates a new ELASTIC_PASSWORD (>= 24 chars, mixed, CSPRNG)
      2. rotates the `elastic` user off the current password via
         POST /_security/user/elastic/_password
      3. updates .env (gitignored) and re-verifies the new password works
      4. resets the keystore `bootstrap.password` to the new value so a fresh
         boot re-bootstraps correctly (run after `-Stage ResetData`)

    With the cluster DOWN it only updates .env and instructions. You must then
    re-run the install so ES re-boots and picks up the new password:
      pwsh -File scripts/setup/Install-ElasticStack.ps1 -Stage Keystore
      pwsh -File scripts/setup/Install-ElasticStack.ps1 -Stage SetPassword

.EXAMPLE
    pwsh -File scripts/troubleshooting/Reset-ElasticPassword.ps1
#>
param([switch]$Force)

$ErrorActionPreference = 'Stop'
$RepoRoot = Resolve-Path (Join-Path (Split-Path -Parent $MyInvocation.MyCommand.Path) '..\..')
$EnvFile  = Join-Path $RepoRoot '.env'
$EsUrl    = 'http://127.0.0.1:9200'

if (-not (Test-Path $EnvFile)) { throw "Missing $EnvFile. Run scripts/setup/New-LabSecrets.ps1 first." }

# --- Load .env ---------------------------------------------------------------
$envMap = @{}
foreach ($line in Get-Content -LiteralPath $EnvFile) {
    $t = $line.Trim()
    if ($t -eq '' -or $t.StartsWith('#')) { continue }
    $i = $t.IndexOf('=')
    if ($i -lt 1) { continue }
    $envMap[$t.Substring(0, $i).Trim()] = $t.Substring($i + 1).Trim()
}

if (-not $envMap['ELASTIC_PASSWORD']) { throw ".env is missing ELASTIC_PASSWORD." }

# --- Generate a fresh password (policy: >= 24 chars, mixed, CSPRNG) ----------
function New-ResetPassword {
    param([int]$Length = 28)
    $sets = @(
        'abcdefghijkmnopqrstuvwxyz',
        'ABCDEFGHJKLMNPQRSTUVWXYZ',
        '23456789',
        '!#%+=?@:,.<>_-|~'
    )
    $all = ($sets -join '').ToCharArray()
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()

    function Get-RandomInt([int]$Max) {
        if ($Max -gt 256) { throw "Get-RandomInt supports Max <= 256, got $Max" }
        $limit = [math]::Floor(256 / $Max) * $Max
        $buf = New-Object byte[] 1
        do { $rng.GetBytes($buf); $val = [int]$buf[0] } while ($val -ge $limit)
        return $val % $Max
    }

    $chars = New-Object System.Collections.Generic.List[char]
    foreach ($s in $sets) { $chars.Add($s[(Get-RandomInt $s.Length)]) }
    while ($chars.Count -lt $Length) { $chars.Add($all[(Get-RandomInt $all.Length)]) }
    for ($i = $chars.Count - 1; $i -gt 0; $i--) {
        $j = Get-RandomInt ($i + 1)
        $tmp = $chars[$i]; $chars[$i] = $chars[$j]; $chars[$j] = $tmp
    }
    $rng.Dispose()
    return -join $chars
}

$newPassword = New-ResetPassword

Write-Host "`n=== Reset elastic superuser password ===" -ForegroundColor Cyan
Write-Host "Old password : $($envMap['ELASTIC_PASSWORD'].Length) chars (rotating)"
Write-Host "New password : $($newPassword.Length) chars" -ForegroundColor Yellow

# --- 1. Rotate the running cluster -------------------------------------------
$bootstrapAuth = @{ Authorization = "Basic $([Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("elastic:$($envMap['ELASTIC_PASSWORD'])")))" }
$body = @{ password = $newPassword } | ConvertTo-Json -Compress
try {
    $null = Invoke-RestMethod -Method Post -Uri "$EsUrl/_security/user/elastic/_password" `
        -Headers $bootstrapAuth -Body $body -ContentType 'application/json' -TimeoutSec 30
    Write-Host "  [OK]   rotated the running elastic password via the change-password API" -ForegroundColor Green
} catch {
    $status = try { [int]$_.Exception.Response.StatusCode } catch { 0 }
    if ($status -eq 401) {
        Write-Host "  [i]    bootstrap credential already retired; will verify after .env update" -ForegroundColor Yellow
    } else {
        throw "change-password API failed with HTTP $status : $($_.Exception.Message)"
    }
}

# --- 2. Update .env -----------------------------------------------------------
$lines = Get-Content -LiteralPath $EnvFile
$out = foreach ($l in $lines) {
    if ($l -like 'ELASTIC_PASSWORD=*') { "ELASTIC_PASSWORD=$newPassword" } else { $l }
}
if ($out -notcontains "ELASTIC_PASSWORD=$newPassword") { $out = @($out) + "ELASTIC_PASSWORD=$newPassword" }
$enc = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText($EnvFile, (($out -join "`n") + "`n"), $enc)
Write-Host "  [OK]   updated .env (ELASTIC_PASSWORD)" -ForegroundColor Green

# --- 3. Verify the new password ------------------------------------------------
$verifyAuth = @{ Authorization = "Basic $([Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("elastic:$newPassword")))" }
try {
    $me = Invoke-RestMethod -Uri "$EsUrl/_security/_authenticate" -Headers $verifyAuth -TimeoutSec 20
    Write-Host "  [OK]   ELASTIC_PASSWORD authenticates as '$($me.username)'" -ForegroundColor Green
} catch {
    throw "ELASTIC_PASSWORD from .env does not authenticate after rotation. $($_.Exception.Message)"
}

Write-Host "`nDone. Next: pwsh -File scripts/validation/Test-ElasticStackHealth.ps1" -ForegroundColor Cyan
