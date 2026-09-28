<#
.SYNOPSIS
    Sets up Fleet Server and the Windows endpoint agent policy via the Kibana
    Fleet API, and prints the exact elevated command needed to install the
    Elastic Agent services.

.DESCRIPTION
    Fleet setup in 9.5.3 happens in a specific order, and getting it wrong
    produces confusing 400s. This script performs the order that works and
    proves each step:

      1. POST /api/fleet/agents/setup
         Initialises Fleet. In 9.5.3 this REQUIRES
         xpack.encryptedSavedObjects.encryptionKey (>= 32 chars) in kibana.yml,
         otherwise it fails forever with
         FleetEncryptedSavedObjectEncryptionKeyRequired and returns HTTP 400.
      2. Create an Elasticsearch service token for the built-in
         `elastic/fleet-server` service account. Fleet Server needs credentials
         for Elasticsearch; a service token is the correct credential and is
         required because xpack.security is enabled.
      3. Create the Fleet Server agent policy.
      4. Add the `fleet-server` integration package to that policy.
      5. Create a Fleet enrollment API key scoped to that policy.
      6. Create the Windows endpoint agent policy (no integrations yet).
      7. Create a second enrollment API key for it.

    Step 7 writes the two enrollment keys into the gitignored .env.

    The script does NOT install the agent: that needs an elevated session
    because the Windows Security channel and the service registration both
    require administrator rights. It emits the exact command to run instead.

.NOTES
    API paths verified against the installed 9.5.3 Fleet plugin
    (node_modules/@kbn/fleet-plugin/common/constants/routes.js):
      /api/fleet/agent_policies
      /api/fleet/package_policies
      /api/fleet/enrollment_api_keys     <- underscores, NOT 'enrollment-api-keys'
      /api/fleet/agents/setup

.EXAMPLE
    pwsh -File scripts/setup/Setup-Fleet.ps1
    pwsh -File scripts/setup/Setup-Fleet.ps1 -SkipAgentInstall
#>
[CmdletBinding()]
param(
    # Set to omit the agent-enrollment section (used when only Fleet Server is wanted).
    [switch]$SkipEndpointAgent,
    [switch]$Force   # delete and recreate policies instead of reusing them
)

$ErrorActionPreference = 'Stop'
$RepoRoot   = Resolve-Path (Join-Path (Split-Path -Parent $MyInvocation.MyCommand.Path) '..\..')
$EnvFile    = Join-Path $RepoRoot '.env'
$Version    = '9.5.3'
$AgentDir   = "C:\elastic\elastic-agent-$Version-windows-x86_64"
$KibanaUrl  = 'http://127.0.0.1:5601'
$EsUrl      = 'http://127.0.0.1:9200'
$FleetUrl   = 'http://127.0.0.1:8220'

function Step { param($m) Write-Host "`n=== $m ===" -ForegroundColor Cyan }
function Ok   { param($m) Write-Host "  [OK]   $m" -ForegroundColor Green }
function Info { param($m) Write-Host "  [i]    $m" -ForegroundColor Gray }
function Warn { param($m) Write-Host "  [WARN] $m" -ForegroundColor Yellow }

# --- Load .env (this is where the ES credential comes from) ---------------------
if (-not (Test-Path $EnvFile)) { throw "Missing $EnvFile. Run scripts/setup/New-LabSecrets.ps1 first." }
$envMap = @{}
foreach ($line in Get-Content -LiteralPath $EnvFile) {
    $t = $line.Trim(); if ($t -eq '' -or $t.StartsWith('#')) { continue }
    $i = $t.IndexOf('='); if ($i -lt 1) { continue }
    $envMap[$t.Substring(0,$i).Trim()] = $t.Substring($i+1).Trim()
}
$esPass = $envMap['ELASTIC_PASSWORD']

$kbAuth = @{ Authorization = "Basic $([Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("elastic:$esPass")))"; 'kbn-xsrf' = 'true' }
$esAuth = @{ Authorization = "Basic $([Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("elastic:$esPass")))" }

function Invoke-Kb {
    param([string]$Method, [string]$Path, $Body)
    $p = @{ Method = $Method; Uri = "$KibanaUrl$Path"; Headers = $kbAuth; TimeoutSec = 180; ErrorAction = 'Stop' }
    if ($null -ne $Body) { $p.Body = ($Body | ConvertTo-Json -Depth 12 -Compress); $p.ContentType = 'application/json' }
    try {
        return Invoke-RestMethod @p
    } catch {
        $code = try { [int]$_.Exception.Response.StatusCode } catch { 0 }
        # The Fleet API DOES return a JSON body with a useful `message` field.
        # Prefer it over the bare WebException, which says only "400 Bad Request".
        $respBody = ''
        try {
            $stream = $_.Exception.Response.GetResponseStream()
            $sr = New-Object System.IO.StreamReader($stream)
            $respBody = $sr.ReadToEnd(); $sr.Close()
        } catch { }
        if ($respBody) {
            try { $respBody = ($respBody | ConvertFrom-Json).message } catch { }
        }
        throw "$Method $Path failed with HTTP ${code}: $respBody"
    }
}

# Agent policy namespace rules, read from the installed 9.5.3 source at
# node_modules/@kbn/fleet-plugin/common/services/is_valid_namespace.js:
#   const INVALID_NAMESPACE_CHARACTERS = /[\*\\/\?"<>|\s,#:-]+/;
# A namespace becomes part of an index name, so it must be LOWERCASE and must
# not contain any of:  * \ / ? " < > | whitespace , # : -
# HYPHENS ARE REJECTED. `soc-lab-fleet-server` returns HTTP 400; use
# `soc_lab_fleet_server`. Names (the human label) DO allow hyphens.
function Assert-Namespace {
    param([string]$Namespace)
    if ($Namespace -ne $Namespace.ToLower()) { throw "Namespace '$Namespace' must be lowercase." }
    $bad = [regex]::Match($Namespace, '[\*\\/\?"<>|\s,#:-]')
    if ($bad.Success) {
        throw "Namespace '$Namespace' contains the invalid character '$($bad.Value)'. Use underscores, not hyphens (the namespace becomes part of an index name)."
    }
}

# --- 1. Fleet initialisation ----------------------------------------------------
Step '1. Fleet initialisation (POST /api/fleet/agents/setup)'
$setup = Invoke-Kb 'POST' '/api/fleet/agents/setup' $null
if ($setup.isInitialized) { Ok "Fleet initialised (nonFatalErrors: $(@($setup.nonFatalErrors).Count))" }
else { throw "Fleet setup returned isInitialized=false: $($setup | ConvertTo-Json -Depth 5 -Compress)" }

# --- 2. Elasticsearch service token for Fleet Server ----------------------------
Step '2. Elasticsearch service token for the elastic/fleet-server service account'
$fleetServerEsTokenName = 'soc-lab-fleet-server-token'
# POST on an existing name returns 409, so clear first (tolerating 404).
try { Invoke-RestMethod -Method Delete -Uri "$EsUrl/_security/service/elastic/fleet-server/credential/token/$fleetServerEsTokenName" -Headers $esAuth -TimeoutSec 30 | Out-Null } catch { }
try {
    $fsTok = Invoke-RestMethod -Method Post -Uri "$EsUrl/_security/service/elastic/fleet-server/credential/token/$fleetServerEsTokenName" -Headers $esAuth -TimeoutSec 60
} catch {
    $b=''; try { $sr=New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream()); $b=$sr.ReadToEnd(); $sr.Close() } catch {}
    throw "Could not create the Fleet Server ES service token: $b"
}
$fleetServerEsToken = if ($fsTok.token) { $fsTok.token.value } else { $fsTok.value }
if (-not $fleetServerEsToken) { throw "Fleet Server ES service token came back empty: $($fsTok | ConvertTo-Json -Compress)" }
Ok "service token '$fleetServerEsTokenName' created ($($fleetServerEsToken.Length) chars)"

# Verify it authenticates before Fleet Server depends on it.
$verify = Invoke-RestMethod -Uri "$EsUrl/_security/_authenticate" -Headers @{ Authorization = "Bearer $fleetServerEsToken" } -TimeoutSec 30
Ok "verifies as '$($verify.username)' (service account: $($verify.authentication.service_account))"

# --- 3/4. Fleet Server agent policy + integration ------------------------------
Step '3. Fleet Server agent policy'
$fsPolicyName = 'SOC-Lab Fleet Server'
$fsPolicyNamespace = 'soc_lab_fleet_server'
Assert-Namespace $fsPolicyNamespace
$existing = Invoke-Kb 'GET' '/api/fleet/agent_policies?perPage=100' $null
$fsPolicy = @($existing.items | Where-Object { $_.namespace -eq $fsPolicyNamespace }) | Select-Object -First 1

if ($fsPolicy -and $Force) {
    # DELETE_PATTERN is /api/fleet/agent_policies/delete and it is a **POST**
    # with { agentPolicyId: <single id string>, force: bool } in the body.
    # It is not a path-parameter DELETE, and agentPolicyId is a STRING, not an
    # array. Verified from server/routes/agent_policy/index.js + handlers.js.
    Invoke-Kb 'POST' '/api/fleet/agent_policies/delete' @{ agentPolicyId = $fsPolicy.id; force = $true } | Out-Null
    Ok "deleted existing policy '$fsPolicyName' (-Force)"
    $fsPolicy = $null
}
if (-not $fsPolicy) {
    # Request body schema: NewAgentPolicySchema
    # { id?, space_ids?, name, namespace, description?, is_managed?, has_fleet_server?,
    #   is_default?, is_default_fleet_server?, unenroll_timeout?, inactivity_timeout?,
    #   monitoring_enabled?, keep_monitoring_alive?, data_output_id?, ... }
    # Response is WRAPPED: { item: { id, name, namespace, ... } } -> use .item.id
    $res = Invoke-Kb 'POST' '/api/fleet/agent_policies' @{
        name               = $fsPolicyName
        description        = 'Fleet Server for the SOC-Lab. Manages endpoint agent enrollment and policy distribution.'
        namespace          = $fsPolicyNamespace
        monitoring_enabled = @('logs')
    }
    $fsPolicy = $res.item
    Ok "created agent policy (id=$($fsPolicy.id))"
} else {
    Ok "reusing agent policy '$fsPolicyName' (id=$($fsPolicy.id))"
}

Step '4. Fleet Server does NOT need an EPM package in 9.x'
# Verified against the live registry: GET /api/fleet/epm/packages returns 474
# packages and `fleet-server` is NOT among them
#   packages returned: 474
#   fleet-server present? False
# In Elastic 9.x Fleet Server ships INSIDE the Fleet plugin and the agent
# starts it via the --fleet-server-es / --fleet-server-service-token flags.
# The 8.x habit of adding a `fleet-server` package policy to an agent policy is
# obsolete, and GET /api/fleet/epm/packages/fleet-server returns 404.
# Nothing to do in this step.
Info 'skipped (verified: not an EPM package in 9.5.3)'

# --- 5. Fleet Server enrollment key --------------------------------------------
Step '5. Fleet Server enrollment API key'
# Path is enrollment_api_keys (UNDERSCORES). `enrollment-api-keys` returns 404.
# Request body field is `policy_id` (NOT `agent_policy_id`), and the secret comes
# back at item.api_key (NOT a top-level `key`).
# Verified from server/routes/enrollment_api_key/index.js + its
# examples/post_enrollment_api_key.yaml.js.
$fsKeyRes = Invoke-Kb 'POST' '/api/fleet/enrollment_api_keys' @{ name = 'soc-lab-fleet-server-key'; policy_id = $fsPolicy.id }
$fsKey = $fsKeyRes.item
if (-not $fsKey.api_key) { throw "Enrollment key response had no api_key: $($fsKeyRes | ConvertTo-Json -Depth 4 -Compress)" }
Ok "enrollment key created (id=$($fsKey.id), api_key_id=$($fsKey.api_key_id))"

# --- 6/7. Windows endpoint policy ----------------------------------------------
$winPolicy = $null
$winKey = $null
if (-not $SkipEndpointAgent) {
    Step '6. Windows endpoint agent policy (WIN-SOC01)'
    $winPolicyName = 'SOC-Lab Windows Endpoint'
    $winPolicyNamespace = 'soc_lab_windows'
    Assert-Namespace $winPolicyNamespace
    $winPolicy = @($existing.items | Where-Object { $_.namespace -eq $winPolicyNamespace }) | Select-Object -First 1
    if ($winPolicy -and $Force) {
        Invoke-Kb 'POST' '/api/fleet/agent_policies/delete' @{ agentPolicyId = $winPolicy.id; force = $true } | Out-Null
        Ok "deleted existing policy '$winPolicyName' (-Force)"
        $winPolicy = $null
    }
    if (-not $winPolicy) {
        $res = Invoke-Kb 'POST' '/api/fleet/agent_policies' @{
            name               = $winPolicyName
            description        = 'Windows endpoint WIN-SOC01. Collects Security/System/Application logs, Sysmon and PowerShell.'
            namespace          = $winPolicyNamespace
            monitoring_enabled = @('logs')
        }
        $winPolicy = $res.item
        Ok "created agent policy (id=$($winPolicy.id))"
    } else {
        Ok "reusing agent policy '$winPolicyName' (id=$($winPolicy.id))"
    }

    Step '7. Windows endpoint enrollment API key'
    $winKeyRes = Invoke-Kb 'POST' '/api/fleet/enrollment_api_keys' @{ name = 'soc-lab-windows-key'; policy_id = $winPolicy.id }
    $winKey = $winKeyRes.item
    if (-not $winKey.api_key) { throw "Windows enrollment key response had no api_key: $($winKeyRes | ConvertTo-Json -Depth 4 -Compress)" }
    Ok "enrollment key created (id=$($winKey.id), api_key_id=$($winKey.api_key_id))"
}

# --- Persist keys to .env (gitignored) -----------------------------------------
Step 'Persisting credentials to .env (gitignored)'
$lines = Get-Content -LiteralPath $EnvFile
$updates = @{
    'FLEET_SERVER_ES_TOKEN' = $fleetServerEsToken
    'FLEET_ENROLLMENT_TOKEN' = $fsKey.api_key
}
if ($winKey) { $updates['WINDOWS_AGENT_ENROLLMENT_TOKEN'] = $winKey.api_key }

$out = foreach ($l in $lines) {
    $k = ($l -split '=',2)[0]
    if ($updates.ContainsKey($k)) { "$k=$($updates[$k])" } else { $l }
}
foreach ($k in $updates.Keys) {
    if (-not ($lines | Where-Object { $_ -like "$k=*" })) { $out = @($out) + "$k=$($updates[$k])" }
}
$enc = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText($EnvFile, (($out -join "`n") + "`n"), $enc)
Ok "wrote $($updates.Keys.Count) secret(s) to .env"

# --- Emit the elevated install commands ----------------------------------------
# Enrollment token format verified against the Kibana-generated install command:
#   <key.id>:<key.api_key>
$fsTokenArg = "$($fsKey.id):$($fsKey.api_key)"
$winTokenArg = if ($winKey) { "$($winKey.id):$($winKey.api_key)" } else { '<not created>' }

$cmdFleetServer = @"
  # Fleet Server (run FIRST, in an ELEVATED PowerShell)
  & '$AgentDir\elastic-agent.exe' install `
    --url=$KibanaUrl `
    --fleet-server-es=$EsUrl `
    --fleet-server-service-token=$fleetServerEsToken `
    --enrollment-token=$fsTokenArg
"@

$cmdWindows = @"

  # Windows endpoint agent (after Fleet Server is Healthy)
  & '$AgentDir\elastic-agent.exe' install `
    --url=$KibanaUrl `
    --enrollment-token=$winTokenArg
"@

Write-Host "`n=== NEXT STEP: ELEVATED agent install ===" -ForegroundColor Yellow
Write-Host $cmdFleetServer -ForegroundColor White
if (-not $SkipEndpointAgent) { Write-Host $cmdWindows -ForegroundColor White }

Write-Host @"

  Flags verified against `elastic-agent.exe install --help` for 9.5.3:
    --url, --enrollment-token, --fleet-server-es, --fleet-server-service-token

  --fleet-server-insecure-http is NOT passed: this lab serves Fleet Server on
  loopback over plain HTTP already, and that flag is documented as insecure.
  Do not add it to a non-lab deployment.

  Why elevated:
    - the Elastic Agent registers a Windows service and installs a driver
    - reading the Windows SECURITY channel requires administrator rights
      (a non-elevated Get-WinEvent -ListLog Security returns "Attempted to
      perform an unauthorized operation")
    - installing Sysmon and setting the PowerShell 4104 policy write to HKLM

  Verify afterwards (no elevation needed):
    pwsh -File scripts/validation/Test-ElasticStackHealth.ps1 -RequireTelemetry
"@ -ForegroundColor DarkGray
