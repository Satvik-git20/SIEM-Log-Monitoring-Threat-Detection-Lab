<#
.SYNOPSIS
    Downloads, verifies and installs the Elastic Stack (Elasticsearch + Kibana)
    natively on Windows, without Docker. Renders the config templates in
    elastic/config-templates/ from the gitignored .env.

.DESCRIPTION
    This is the path actually used to build this lab, because the build host
    had no Docker installed. docker/compose.yml is the equivalent path for
    reviewers who do.

    Stages (each idempotent, each validated):
      1. Preflight   - PowerShell version, RAM, free disk, admin, port conflicts
      2. Download    - vendor ZIPs + .sha512, verified before anything is unpacked
      3. Extract     - to C:\elastic\<component>-<version>
      4. Render      - elasticsearch.yml / kibana.yml from templates + .env
      5. Tune        - jvm.options.d heap cap
      6. First run   - start Elasticsearch, wait for cluster health
      7. Kibana      - start Kibana, wait for /api/status available

    Security posture: all listeners bind 127.0.0.1. No secret is written into
    the git repository - rendered config files live under C:\elastic, which is
    outside the repo, and are also covered by .gitignore patterns.

.PARAMETER Version
    Elastic Stack version. Default 9.5.3 (GA 2026-09-03, verified available).

.PARAMETER InstallRoot
    Where to install. Default C:\elastic. Keep this OUTSIDE the git repository.

.PARAMETER Stage
    Run a single stage instead of all of them. Useful for iterating on a
    failure without re-downloading 1.4 GB.

.PARAMETER Force
    Re-render config files and re-extract even if already present.

.EXAMPLE
    pwsh -File scripts/setup/Install-ElasticStack.ps1
    pwsh -File scripts/setup/Install-ElasticStack.ps1 -Stage Health
#>
[CmdletBinding()]
param(
    [string]$Version = '9.5.3',
    [string]$InstallRoot = 'C:\elastic',
    [ValidateSet('Preflight','Download','Extract','Keystore','Tune','StartElasticsearch','SetPassword','ServiceToken','Render','StartKibana','Health','Stop','ResetData','All')]
    [string]$Stage = 'All',
    [switch]$Force,
    # Wipe the Elasticsearch data directory so security re-bootstraps from the
    # keystore. The lab holds no data worth keeping, but this is destructive by
    # design, so it is opt-in and never part of -Stage All.
    [switch]$ResetData
)

$ErrorActionPreference = 'Stop'
$ScriptDir  = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot   = Resolve-Path (Join-Path $ScriptDir '..\..')
$EnvFile    = Join-Path $RepoRoot '.env'
$TmplDir    = Join-Path $RepoRoot 'elastic\config-templates'
$DownloadDir= Join-Path $InstallRoot 'downloads'

function Write-Step  { param($m) Write-Host "`n=== $m ===" -ForegroundColor Cyan }
function Write-Ok    { param($m) Write-Host "  [OK]   $m" -ForegroundColor Green }
function Write-Warn2 { param($m) Write-Host "  [WARN] $m" -ForegroundColor Yellow }
function Write-Fail2 { param($m) Write-Host "  [FAIL] $m" -ForegroundColor Red }

# Write text WITHOUT a byte-order mark.
#
# This is not cosmetic. PowerShell 5.1's `Set-Content -Encoding UTF8` writes a
# BOM, and two of the files this script generates are parsed by components that
# reject it:
#   - config/jvm.options.d/*.options -> the JVM options parser fails with
#     "improperly formatted JVM option ... exit code 78"
#   - elasticsearch.yml / kibana.yml -> YAML loaders are not guaranteed to
#     tolerate a leading BOM
# UTF8Encoding($false) emits no BOM.
function Write-TextNoBom {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][AllowEmptyString()][string]$Content)
    $enc = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($Path, $Content, $enc)
}

# --- Load .env into $env: so ${TOKEN} style substitution works consistently ---
function Import-DotEnv {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        throw "Missing $Path. Copy .env.example to .env and fill in the values first. Run: pwsh -File scripts/setup/New-LabSecrets.ps1"
    }
    $count = 0
    foreach ($line in Get-Content -LiteralPath $Path) {
        $t = $line.Trim()
        if ($t -eq '' -or $t.StartsWith('#')) { continue }
        $i = $t.IndexOf('=')
        if ($i -lt 1) { continue }
        $k = $t.Substring(0, $i).Trim()
        $v = $t.Substring($i + 1).Trim()
        # strip surrounding quotes if present
        if (($v.StartsWith('"') -and $v.EndsWith('"')) -or ($v.StartsWith("'") -and $v.EndsWith("'"))) {
            $v = $v.Substring(1, $v.Length - 2)
        }
        [Environment]::SetEnvironmentVariable($k, $v, 'Process')
        $count++
    }
    Write-Ok "Loaded $count variables from $(Split-Path -Leaf $Path)"
    # Fail fast on placeholders so we never run a stack with a CHANGE_ME password
    $placeholderVars = @('ELASTIC_PASSWORD','KIBANA_ES_PASSWORD') | Where-Object {
        (Get-Item "Env:$_" -ErrorAction SilentlyContinue).Value -like 'CHANGE_ME*'
    }
    if ($placeholderVars) {
        throw "Unresolved placeholder(s): $($placeholderVars -join ', '). Run: pwsh -File scripts/setup/New-LabSecrets.ps1"
    }
}

# --- Stage 1: Preflight -------------------------------------------------------
function Invoke-Preflight {
    Write-Step 'Preflight'

    if ($PSVersionTable.PSVersion.Major -lt 5) { throw "PowerShell 5.1+ required, found $($PSVersionTable.PSVersion)" }
    Write-Ok "PowerShell $($PSVersionTable.PSVersion)"

    $os = Get-CimInstance Win32_OperatingSystem
    $ramGB = [math]::Round($os.TotalVisibleMemorySize / 1MB, 1)
    Write-Ok "RAM ${ramGB} GB"
    if ($ramGB -lt 8) { Write-Warn2 "Lab target is 8 GB minimum. Elasticsearch + Kibana + Fleet + a Windows agent will thrash below that." }

    $drive = Get-PSDrive -Name ([System.IO.Path]::GetPathRoot($InstallRoot).TrimEnd(':','\')) -ErrorAction SilentlyContinue
    if ($drive) {
        $freeGB = [math]::Round($drive.Free / 1GB, 1)
        Write-Ok "Free disk on $(Split-Path -Qualifier $InstallRoot): ${freeGB} GB"
        if ($freeGB -lt 12) { throw "Need >= 12 GB free for the stack plus lab data. Have ${freeGB} GB." }
    }

    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if ($isAdmin) { Write-Ok 'Running elevated' } else { Write-Warn2 'Not elevated. ES/Kibana do not need elevation; Elastic Agent + Fleet Server service DO (Phase 4).' }

    foreach ($p in 9200, 9300, 5601, 8220) {
        $conn = @(Get-NetTCPConnection -LocalPort $p -State Listen -ErrorAction SilentlyContinue)
        if ($conn.Count -eq 0) { Write-Ok "Port $p free"; continue }

        $procName = (Get-Process -Id $conn[0].OwningProcess -ErrorAction SilentlyContinue).ProcessName
        $procPath = (Get-CimInstance Win32_Process -Filter "ProcessId=$($conn[0].OwningProcess)" -ErrorAction SilentlyContinue).CommandLine

        # Re-running the installer against a lab stack we already started is a
        # normal case, not an error. The Start* stages are idempotent and skip
        # whatever is already listening. Only a FOREIGN process on the port is
        # a real conflict.
        $isOurs = $procPath -and ($procPath -like "*$InstallRoot*" -or $procPath -match 'kibana|elasticsearch')
        if ($isOurs) {
            Write-Ok "Port $p already held by this lab stack ($procName, PID $($conn[0].OwningProcess)) - will be reused"
        } else {
            throw "Port $p is in use by '$procName' (PID $($conn[0].OwningProcess)), which is not part of this lab. Stop it, or change the port in .env before continuing."
        }
    }

    # .env is loaded once by the orchestrator before any stage runs.
    if (-not (Test-Path -LiteralPath $EnvFile)) { throw "Missing $EnvFile" }
}

# --- Stage 2: Download + checksum verify ---------------------------------------
function Invoke-Download {
    Write-Step "Download Elastic Stack $Version"

    New-Item -ItemType Directory -Force -Path $DownloadDir | Out-Null

    # Sizes are MiB (bytes/1048576) as reported by the vendor Content-Range
    # header, verified against the downloaded file size.
    $targets = @(
        @{ Name = 'elasticsearch'; File = "elasticsearch-$Version-windows-x86_64.zip"; SizeMB = 647 }
        @{ Name = 'kibana';        File = "kibana-$Version-windows-x86_64.zip";        SizeMB = 458 }
    )

    foreach ($t in $targets) {
        $url  = "https://artifacts.elastic.co/downloads/$($t.Name)/$($t.File)"
        $zip  = Join-Path $DownloadDir $t.File
        $sha  = "$zip.sha512"

        if ((Test-Path -LiteralPath $zip) -and -not $Force) {
            Write-Ok "$($t.File) already downloaded ($([math]::Round((Get-Item $zip).Length/1MB)) MB)"
        } else {
            Write-Host "  downloading $($t.File) (~$($t.SizeMB) MB) ..." -ForegroundColor DarkGray
            # BITS is resumable and survives flaky university networks
            try {
                Start-BitsTransfer -Source $url -Destination $zip -ErrorAction Stop
            } catch {
                Write-Warn2 "BITS failed ($($_.Exception.Message)); falling back to Invoke-WebRequest"
                $ProgressPreference = 'SilentlyContinue'
                Invoke-WebRequest -Uri $url -OutFile $zip -UseBasicParsing -TimeoutSec 1800
            }
            Write-Ok "downloaded $([math]::Round((Get-Item $zip).Length/1MB)) MB"
        }

        # Verify checksum BEFORE unpacking. This is the supply-chain control.
        if (-not (Test-Path -LiteralPath $sha)) {
            $ProgressPreference = 'SilentlyContinue'
            Invoke-WebRequest -Uri "$url.sha512" -OutFile $sha -UseBasicParsing -TimeoutSec 120
        }
        $expected = ((Get-Content -LiteralPath $sha -Raw) -split '\s+')[0].Trim().ToLower()
        $actual   = (Get-FileHash -LiteralPath $zip -Algorithm SHA512).Hash.ToLower()

        if ($expected -ne $actual) {
            throw "SHA-512 MISMATCH for $($t.File).`n  expected: $expected`n  actual:   $actual`nRefusing to install. Delete the file and re-download."
        }
        Write-Ok "SHA-512 verified for $($t.File)"
    }
}

# --- Stage 3: Extract ------------------------------------------------------------
function Invoke-Extract {
    Write-Step 'Extract archives'

    foreach ($name in 'elasticsearch', 'kibana') {
        $dir = Join-Path $InstallRoot "$name-$Version"
        if ((Test-Path -LiteralPath $dir) -and -not $Force) {
            Write-Ok "$name already extracted to $dir"
            continue
        }
        $zip = Join-Path $DownloadDir "$name-$Version-windows-x86_64.zip"
        Write-Host "  extracting $name ..." -ForegroundColor DarkGray
        # -Force on Expand-Archive is slow on 678 MB; use tar (bsdtar ships with Win10+)
        & tar -xf $zip -C $InstallRoot
        if ($LASTEXITCODE -ne 0) { throw "tar extraction failed for $name (exit $LASTEXITCODE)" }
        if (-not (Test-Path -LiteralPath $dir)) { throw "Expected directory $dir not created - archive layout changed?" }
        Write-Ok "$name extracted to $dir"
    }
}

# --- Stage 4: Render config from templates -------------------------------------
function Invoke-RenderConfig {
    Write-Step 'Render Elasticsearch and Kibana config from templates'

    $esDir = Join-Path $InstallRoot "elasticsearch-$Version"
    $kbDir = Join-Path $InstallRoot "kibana-$Version"

    foreach ($d in @($esDir, $kbDir)) { if (-not (Test-Path $d)) { throw "Missing $d - run -Stage Extract first" } }

    $esData = Join-Path $esDir 'data'
    $esLogs = Join-Path $esDir 'logs'
    $kbData = Join-Path $kbDir 'data'
    $kbLogs = Join-Path $kbDir 'logs'
    foreach ($d in @($esData, $esLogs, $kbData, $kbLogs)) { New-Item -ItemType Directory -Force -Path $d | Out-Null }

    # The lab uses a service account token for Kibana, not the elastic
    # superuser: Kibana 9.x hard-rejects elastic as elasticsearch.username.
    $kibanaToken = $env:KIBANA_SERVICE_TOKEN
    if (-not $kibanaToken -or $kibanaToken -like 'CHANGE_ME*') {
        throw ("KIBANA_SERVICE_TOKEN is not set. Run -Stage ServiceToken before -Stage Render " +
               "(Elasticsearch must be running first).")
    }

    $map = @{
        '__ES_CLUSTER_NAME__'     = if ($env:ES_CLUSTER_NAME) { $env:ES_CLUSTER_NAME } else { 'soc-lab-cluster' }
        '__ES_PATH_DATA__'        = ($esData -replace '\\','/')
        '__ES_PATH_LOGS__'        = ($esLogs -replace '\\','/')
        '__KIBANA_PATH_DATA__'    = ($kbData -replace '\\','/')
        '__KIBANA_PATH_LOGS__'    = ($kbLogs -replace '\\','/')
        '__KIBANA_SERVICE_TOKEN__' = $kibanaToken
    }

    $pairs = @(
        @{ Template = 'elasticsearch.yml.tmpl'; Target = (Join-Path $esDir 'config\elasticsearch.yml') }
        @{ Template = 'kibana.yml.tmpl';        Target = (Join-Path $kbDir 'config\kibana.yml') }
    )

    foreach ($p in $pairs) {
        $src = Join-Path $TmplDir $p.Template
        if (-not (Test-Path $src)) { throw "Template not found: $src" }
        $text = Get-Content -LiteralPath $src -Raw
        foreach ($k in $map.Keys) { $text = $text.Replace($k, $map[$k]) }

        $leftover = [regex]::Matches($text, '__[A-Z_]+__') | ForEach-Object { $_.Value } | Sort-Object -Unique
        if ($leftover) { throw "Unsubstituted token(s) in $($p.Template): $($leftover -join ', ')" }

        # Guard against the silent-empty-substitution failure mode: a token can be
        # "replaced" with an empty string if .env was never loaded. That produced a
        # real outage here (ES refused to boot with
        # "null-valued setting found for key [ELASTIC_PASSWORD]"). Require the
        # rendered value to be present.
        if ($p.Template -like 'elasticsearch*') {
            foreach ($req in 'cluster.name:', 'network.host:', 'path.data:', 'xpack.security.enabled:') {
                if (-not $text.Contains($req)) { throw "elasticsearch.yml is missing required setting '$req' - template render is incomplete" }
            }
            # 9.x removed ELASTIC_PASSWORD from elasticsearch.yml. If it reappears,
            # Elasticsearch aborts startup, so assert it is absent.
            if ($text -match '(?m)^ELASTIC_PASSWORD:') {
                throw 'elasticsearch.yml still contains ELASTIC_PASSWORD. That setting was removed in Elasticsearch 9.x and aborts startup. The password belongs in the keystore as bootstrap.password.'
            }
        }
        if ($p.Template -like 'kibana*') {
            # 9.x forbids elastic as elasticsearch.username. Assert the
            # serviceAccountToken form is what actually got rendered.
            if ($text -match '(?m)^\s*elasticsearch\.username:') {
                throw 'kibana.yml contains elasticsearch.username - Kibana 9.x rejects that. Use elasticsearch.serviceAccountToken.'
            }
            $m = [regex]::Match($text, '(?m)^\s*elasticsearch\.serviceAccountToken:\s*(\S*)\s*$')
            if (-not $m.Success -or $m.Groups[1].Value.Length -lt 20) {
                throw ("kibana.yml rendered without a usable elasticsearch.serviceAccountToken " +
                       "(found length: " + $(if ($m.Success) { $m.Groups[1].Value.Length } else { 'key absent' }) + ")")
            }
        }

        Write-TextNoBom -Path $p.Target -Content $text
        Write-Ok "rendered $($p.Template)"
        Write-Ok "  -> $($p.Target)"
    }
}

# --- Stage 5: Keystore + elastic superuser password ---------------------------------
# Elasticsearch 9.x removed `ELASTIC_PASSWORD` from elasticsearch.yml. The
# supported mechanism is a `bootstrap.password` SECURE SETTING in the keystore.
# This mirrors what Elastic's own docker-entrypoint.sh does.
function Invoke-Keystore {
    Write-Step 'Keystore: bootstrap.password (Elasticsearch 9.x mechanism)'

    $esDir = Join-Path $InstallRoot "elasticsearch-$Version"
    $ks    = Join-Path $esDir 'config\elasticsearch.keystore'
    $ksBat = Join-Path $esDir 'bin\elasticsearch-keystore.bat'

    $bootstrap = if ($env:ES_BOOTSTRAP_PASSWORD) { $env:ES_BOOTSTRAP_PASSWORD } else { $env:ELASTIC_PASSWORD }
    if (-not $bootstrap) { throw 'Neither ES_BOOTSTRAP_PASSWORD nor ELASTIC_PASSWORD is set in .env' }

    if (-not (Test-Path $ks)) {
        Write-Host '  creating keystore ...' -ForegroundColor DarkGray
        & $ksBat create | Out-Null
        if (-not (Test-Path $ks)) { throw "Keystore was not created at $ks" }
        Write-Ok 'keystore created'
    } else {
        Write-Ok 'keystore already present'
    }

    # Idempotent: remove first so re-running replaces rather than appends.
    $existing = & $ksBat list 2>$null
    if ($existing -match '^bootstrap\.password$') {
        Write-Host '  bootstrap.password already present, replacing ...' -ForegroundColor DarkGray
        & $ksBat remove 'bootstrap.password' | Out-Null
    }

    # Write the secret to the tool's stdin as EXACT bytes, with no trailing
    # newline.
    #
    # The obvious `cmd /c "(echo $pw) | elasticsearch-keystore add -x ..."`
    # is WRONG: `echo` appends CRLF and the keystore stores the trailing CR as
    # part of the value. The result is a 29-character secret for a 28-character
    # password, and Elasticsearch then rejects every authentication attempt
    # against it with a bare 401 and no hint about the cause. This cost real
    # debugging time on this build, so it is worth the extra code.
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName  = 'cmd.exe'
    $psi.Arguments = "/c `"`"$ksBat`" add -x bootstrap.password`""
    $psi.UseShellExecute        = $false
    $psi.RedirectStandardInput   = $true
    $psi.RedirectStandardOutput  = $true
    $psi.RedirectStandardError   = $true
    $psi.CreateNoWindow         = $true

    $proc = New-Object System.Diagnostics.Process
    $proc.StartInfo = $psi
    [void]$proc.Start()
    $proc.StandardInput.Write($bootstrap)   # NO WriteLine, NO trailing newline
    $proc.StandardInput.Close()
    $stdout = $proc.StandardOutput.ReadToEnd()
    $stderr = $proc.StandardError.ReadToEnd()
    $proc.WaitForExit()

    if ($proc.ExitCode -ne 0) { throw "elasticsearch-keystore add failed (exit $($proc.ExitCode)): $stderr" }

    # Prove it is exactly what we intended, not merely present. Compare the raw
    # value with NO trimming so any stray CR/LF is caught here rather than
    # becoming an unauthenticatable cluster.
    $stored = (& $ksBat show 'bootstrap.password' 2>$null | Out-String)
    # Out-String appends exactly one trailing newline of its own; strip only that.
    $stored = $stored -replace "(\r\n|\n|\r)$", ''

    if ($stored -cne $bootstrap) {
        throw ("bootstrap.password in the keystore does not match .env." +
               " stored length=$($stored.Length) expected length=$($bootstrap.Length)." +
               " A mismatch here means the stored secret has stray whitespace and" +
               " Elasticsearch will reject every login. Re-run -Stage Keystore.")
    }
    Write-Ok "bootstrap.password stored and byte-verified ($($stored.Length) chars, no stray whitespace)"
}

# --- Stage 6: Rotate the elastic user off the bootstrap credential --------------------
function Set-ElasticUserPassword {
    Write-Step 'Set elastic superuser password (retire the bootstrap credential)'

    $bootstrap = if ($env:ES_BOOTSTRAP_PASSWORD) { $env:ES_BOOTSTRAP_PASSWORD } else { $env:ELASTIC_PASSWORD }
    $target    = $env:ELASTIC_PASSWORD

    $body = @{ password = $target } | ConvertTo-Json -Compress

    # Try the bootstrap credential first. If elastic's password is already the
    # target (e.g. a re-run), this succeeds and nothing changes.
    try {
        $hdr = @{ Authorization = "Basic $([Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("elastic:$bootstrap")))" }
        Invoke-RestMethod -Method Post -Uri 'http://127.0.0.1:9200/_security/user/elastic/_password' `
                           -Headers $hdr -Body $body -ContentType 'application/json' -TimeoutSec 30 | Out-Null
        Write-Ok 'elastic password set to ELASTIC_PASSWORD via the change password API'
    } catch {
        $status = $_.Exception.Response.StatusCode.value__
        if ($status -eq 401) {
            Write-Ok 'bootstrap credential already retired; verifying ELASTIC_PASSWORD works'
        } else {
            throw "change password API failed with HTTP $status : $($_.Exception.Message)"
        }
    }

    # Final proof: authenticate with the target password, not the bootstrap one.
    $hdr = @{ Authorization = "Basic $([Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("elastic:$target")))" }
    try {
        $me = Invoke-RestMethod -Uri 'http://127.0.0.1:9200/_security/_authenticate' -Headers $hdr -TimeoutSec 20
        # roles is a string array, so -join is correct here. Using
        # .PSObject.Properties.Name on it prints the .NET array type's members
        # (Count, Length, LongLength, ...) instead of the role names.
        Write-Ok "authenticated as '$($me.username)' with roles: $($me.roles -join ', ')"
    } catch {
        throw "ELASTIC_PASSWORD from .env does not authenticate. Fix .env or run scripts/troubleshooting/Reset-ElasticPassword.ps1. $($_.Exception.Message)"
    }
}

# --- Stage: Kibana service account token ----------------------------------------
# Kibana 9.x refuses `elasticsearch.username: elastic`. The supported
# credential is a service account token for the built-in `elastic/kibana`
# service account, created through the Service Accounts API.
function Get-KibanaServiceToken {
    Write-Step 'Kibana service account token (elastic/kibana)'

    $auth = @{ Authorization = "Basic $([Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("elastic:$($env:ELASTIC_PASSWORD)")))" }
    $tokenName = 'soc-lab-kibana-token'
    $tokenPath = '/_security/service/elastic/kibana/credential/token/' + $tokenName

    $existing = $env:KIBANA_SERVICE_TOKEN
    $haveReal = $existing -and $existing -notlike 'CHANGE_ME*' -and $existing -notlike '*PENDING*'

    if ($haveReal) {
        Write-Ok "reusing KIBANA_SERVICE_TOKEN from .env (${($existing.Length)} chars)"
    } else {
        Write-Host '  creating service account token via the Service Accounts API ...' -ForegroundColor DarkGray

        # POST on an existing token name returns HTTP 409
        # (resource_already_exists_exception). This happens on any re-run where
        # a previous attempt created the token but failed later, and the raw
        # WebException says nothing useful. Delete first, tolerating 404.
        try {
            Invoke-RestMethod -Method Delete -Uri "http://127.0.0.1:9200$tokenPath" -Headers $auth -TimeoutSec 30 | Out-Null
            Write-Host "  cleared any pre-existing token '$tokenName'" -ForegroundColor DarkGray
        } catch {
            $s = $null; try { $s = [int]$_.Exception.Response.StatusCode } catch { }
            if ($s -ne 404) { Write-Warn2 "pre-delete returned HTTP $s (continuing anyway)" }
        }

        try {
            $resp = Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:9200$tokenPath" -Headers $auth -TimeoutSec 30
        } catch {
            $body = ''
            try {
                $sr = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
                $body = $sr.ReadToEnd(); $sr.Close()
            } catch { }
            throw "Service account token creation failed: $($_.Exception.Message) $body"
        }

        # The Service Accounts API nests the secret under `token.value`:
        #   { "created": true,
        #     "token": { "name": "soc-lab-kibana-token", "value": "AAEAAW..." } }
        $existing = $null
        if (($resp.PSObject.Properties.Name -contains 'token') -and $resp.token) { $existing = $resp.token.value }
        elseif ($resp.PSObject.Properties.Name -contains 'value')                { $existing = $resp.value }
        if (-not $existing) { throw "Service account token creation returned no usable value. Response: $($resp | ConvertTo-Json -Compress)" }

        # Persist to .env so re-rendering is stable and the token is not
        # regenerated on every install run. .env is gitignored.
        $lines = Get-Content -LiteralPath $EnvFile
        $found = $false
        $out = foreach ($l in $lines) {
            if ($l -like 'KIBANA_SERVICE_TOKEN=*') { $found = $true; "KIBANA_SERVICE_TOKEN=$existing" } else { $l }
        }
        if (-not $found) { $out = @($out) + "KIBANA_SERVICE_TOKEN=$existing" }
        Write-TextNoBom -Path $EnvFile -Content (($out -join "`n") + "`n")
        [Environment]::SetEnvironmentVariable('KIBANA_SERVICE_TOKEN', $existing, 'Process')
        Write-Ok "service account token created and stored in .env (token '$tokenName')"
    }

    # Prove the token actually authenticates before Kibana depends on it.
    $tokHdr = @{ Authorization = "Bearer $existing" }
    try {
        $me = Invoke-RestMethod -Uri 'http://127.0.0.1:9200/_security/_authenticate' -Headers $tokHdr -TimeoutSec 20
        Write-Ok "token authenticates as '$($me.username)' (service account: $($me.authentication.service_account))"
    } catch {
        throw "KIBANA_SERVICE_TOKEN does not authenticate. Delete the KIBANA_SERVICE_TOKEN line from .env and re-run -Stage ServiceToken. $($_.Exception.Message)"
    }
}

# --- Stage 7: Heap tuning ---------------------------------------------------------
function Invoke-Tune {
    Write-Step 'Tune JVM heap'
    $esDir = Join-Path $InstallRoot "elasticsearch-$Version"
    $heap  = if ($env:ES_JVM_HEAP) { $env:ES_JVM_HEAP } else { '1g' }
    $optsDir = Join-Path $esDir 'config\jvm.options.d'
    New-Item -ItemType Directory -Force -Path $optsDir | Out-Null
    $file = Join-Path $optsDir 'soc-lab.options'

    # Hard cap, not MaxRAMPercentage: the Windows endpoint that PRODUCES the
    # telemetry shares this 15.3 GB box with WSL2. A percentage-based heap can
    # starve the endpoint and silently truncate Sysmon/Security collection.
    #
    # TWO syntax rules for jvm.options.d files, both learned the hard way:
    #   1. Comments use a SINGLE '#'. '##' is not a comment and aborts startup
    #      with "improperly formatted JVM option ... exit code 78".
    #   2. No byte-order mark. PowerShell 5.1's -Encoding UTF8 emits one and the
    #      parser rejects it. Hence Write-TextNoBom.
    $content = @"
# SOC-Lab heap cap (generated by scripts/setup/Install-ElasticStack.ps1)
# Rationale: hard cap, not -XX:MaxRAMPercentage. See docs/configuration.md#memory-budget
-Xms$heap
-Xmx$heap
"@
    Write-TextNoBom -Path $file -Content $content
    Write-Ok "heap set to $heap in $file"
}

# --- Stage 6: Start Elasticsearch ---------------------------------------------------
function Start-Elasticsearch {
    Write-Step 'Start Elasticsearch'
    $esDir = Join-Path $InstallRoot "elasticsearch-$Version"

    # VERSION NOTE (9.5.3): the PowerShell launcher (bin\elasticsearch.ps1) is no
    # longer shipped in the Windows ZIP distribution. Only the cmd launcher
    # (bin\elasticsearch.bat) and the POSIX shell script are present. Verified by
    # listing bin\ after extraction. If a future release restores the .ps1
    # launcher, prefer it; otherwise this is the supported entry point.
    $ps1   = Join-Path $esDir 'bin\elasticsearch.bat'
    if (-not (Test-Path $ps1)) { throw "Missing $ps1" }

    $listener = Get-NetTCPConnection -LocalPort 9200 -State Listen -ErrorAction SilentlyContinue
    if ($listener) { Write-Ok "already listening on 9200 (PID $($listener[0].OwningProcess))"; return }

    Write-Host '  launching elasticsearch (first boot provisions security, may take 60-120s) ...' -ForegroundColor DarkGray
    # Redirect the launcher's own output to a file. Without this, a failure that
    # happens before the logging framework starts (e.g. a config parse error)
    # vanishes, which is exactly what happened during the first attempt at this
    # build: ES exited with a ParseException and the log directory stayed empty.
    $bootLog = Join-Path $esDir 'logs\soc-lab-bootstrap.log'
    Start-Process -FilePath $ps1 -WorkingDirectory $esDir -WindowStyle Minimized `
                  -RedirectStandardOutput $bootLog -RedirectStandardError "$bootLog.err"

    $deadline = (Get-Date).AddMinutes(4)
    $ok = $false
    while ((Get-Date) -lt $deadline) {
        Start-Sleep -Seconds 5
        # Probe WITHOUT credentials and accept ANY HTTP status.
        # At this point in the install the elastic password is still the
        # keystore bootstrap.password, so authenticating with
        # ELASTIC_PASSWORD here returns 401 forever and the loop can never
        # succeed. Set-ElasticUserPassword runs next and does the rotation.
        # A 401 still proves the node is up, serving HTTP, with security on.
        try {
            $resp = Invoke-WebRequest -Uri 'http://127.0.0.1:9200/_cluster/health' -TimeoutSec 10 -UseBasicParsing -ErrorAction Stop
            $ok = $true
            Write-Ok "Elasticsearch answering HTTP $($resp.StatusCode) on 127.0.0.1:9200"
            break
        } catch {
            $code = $null
            try { $code = [int]$_.Exception.Response.StatusCode } catch { }
            if ($code -and $code -gt 0) {
                $ok = $true
                Write-Ok "Elasticsearch answering HTTP $code on 127.0.0.1:9200 (security active, credential not yet rotated)"
                break
            }
        }
    }
    if (-not $ok) {
        $log = Join-Path $esDir 'logs\soc-lab-cluster.log'
        $boot = Join-Path $esDir 'logs\soc-lab-bootstrap.log'
        Write-Host "Elasticsearch did not become healthy in 4 minutes." -ForegroundColor Red
        foreach ($f in @($boot, "$boot.err", $log)) {
            if ((Test-Path $f) -and (Get-Item $f).Length -gt 0) {
                Write-Host "--- last 30 lines of $f ---" -ForegroundColor Red
                Get-Content $f -Tail 30 | ForEach-Object { Write-Host "    $_" -ForegroundColor DarkGray }
            }
        }
        if (-not (Test-Path $log)) {
            Write-Host "No cluster log was written. A config parse error is the usual cause:" -ForegroundColor Yellow
            Write-Host "  (Get-Content '$esDir\config\elasticsearch.yml') | Select-String 'ELASTIC_PASSWORD'" -ForegroundColor Yellow
        }
        throw 'Elasticsearch failed to start. See docs/troubleshooting.md#elasticsearch-startup'
    }
}

# --- Stage 7: Start Kibana ------------------------------------------------------------
function Start-Kibana {
    Write-Step 'Start Kibana'
    $kbDir = Join-Path $InstallRoot "kibana-$Version"
    $bat   = Join-Path $kbDir 'bin\kibana.bat'

    if (-not (Test-Path $bat)) { throw "Missing $bat" }

    $listener = Get-NetTCPConnection -LocalPort 5601 -State Listen -ErrorAction SilentlyContinue
    if ($listener) { Write-Ok "already listening on 5601 (PID $($listener[0].OwningProcess))"; return }

    Write-Host '  launching kibana (first boot can take 90-180s) ...' -ForegroundColor DarkGray
    # Capture stdout/stderr. A kibana.yml schema error is printed to the console
    # and Kibana exits, leaving logs\kibana.log EMPTY - without redirection the
    # reason is lost entirely. That is how the `logging.appenders.rolling.policy`
    # breakage was found the hard way.
    $bootLog = Join-Path $kbDir 'logs\soc-lab-bootstrap.log'
    Start-Process -FilePath $bat -WorkingDirectory $kbDir -WindowStyle Minimized `
                  -RedirectStandardOutput $bootLog -RedirectStandardError "$bootLog.err"

    $deadline = (Get-Date).AddMinutes(8)
    $ok = $false
    while ((Get-Date) -lt $deadline) {
        Start-Sleep -Seconds 10
        try {
            $s = Invoke-RestMethod -Uri 'http://127.0.0.1:5601/api/status' -TimeoutSec 10 -ErrorAction Stop
            $lvl = $s.status.overall.level
            if ($lvl -eq 'available') { $ok = $true; Write-Ok "Kibana overall status: $lvl"; break }
            Write-Host "    status: $lvl (waiting) ..." -ForegroundColor DarkGray
        } catch {
            if (Test-Path "$bootLog.err") {
                $err = (Get-Content "$bootLog.err" -Raw -ErrorAction SilentlyContinue)
                if ($err -and $err -match 'ValidationError|Error:|error ') {
                    Write-Host "Kibana reported a configuration error and exited:" -ForegroundColor Red
                    $err -split "`n" | Select-Object -First 25 | ForEach-Object { Write-Host "    $_" -ForegroundColor DarkGray }
                    throw 'Kibana failed to start due to a configuration error. See docs/troubleshooting.md#kibana-startup'
                }
            }
        }
    }
    if (-not $ok) {
        $log = Join-Path $kbDir 'logs\kibana.log'
        Write-Host "Kibana did not reach 'available' in 5 minutes. Last 30 lines of $log :" -ForegroundColor Red
        if (Test-Path $log) { Get-Content $log -Tail 30 | ForEach-Object { Write-Host "    $_" -ForegroundColor DarkGray } }
        throw 'Kibana failed to start. See docs/troubleshooting.md#kibana-startup'
    }
}

# --- Stage: Stop the stack cleanly ------------------------------------------------
function Stop-ElasticStack {
    Write-Step 'Stop Elasticsearch'

    $pids = @(Get-CimInstance Win32_Process -Filter "Name='java.exe'" |
              Where-Object { $_.CommandLine -match 'elasticsearch' } |
              Select-Object -ExpandProperty ProcessId)
    if ($pids.Count -eq 0) { Write-Ok 'no Elasticsearch process running'; return }

    foreach ($p in $pids) { Write-Host "  stopping PID $p ..." -ForegroundColor DarkGray }
    Stop-Process -Id $pids -Force -ErrorAction SilentlyContinue

    # Wait for the listener to actually go away before anything tries to rebind
    $deadline = (Get-Date).AddSeconds(60)
    while ((Get-Date) -lt $deadline) {
        if (-not (Get-NetTCPConnection -LocalPort 9200 -State Listen -ErrorAction SilentlyContinue)) { break }
        Start-Sleep -Seconds 2
    }
    if (Get-NetTCPConnection -LocalPort 9200 -State Listen -ErrorAction SilentlyContinue) {
        throw "Elasticsearch did not release port 9200 within 60s. A leftover process is holding it."
    }
    Write-Ok 'Elasticsearch stopped, port 9200 released'
}

# --- Stage: Reset data (destructive, opt-in) -------------------------------------
function Invoke-ResetData {
    Write-Step 'Reset Elasticsearch data directory (DESTRUCTIVE)'

    $dataDir = Join-Path $InstallRoot "elasticsearch-$Version\data"
    if (-not (Test-Path $dataDir)) { Write-Ok "nothing to remove ($dataDir)"; return }

    Stop-ElasticStack

    $bytes = (Get-ChildItem -Recurse -LiteralPath $dataDir -File -ErrorAction SilentlyContinue |
              Measure-Object Length -Sum).Sum
    Write-Host "  removing $([math]::Round($bytes/1MB,1)) MB from $dataDir" -ForegroundColor Yellow
    Remove-Item -Recurse -Force -LiteralPath $dataDir
    New-Item -ItemType Directory -Force -Path $dataDir | Out-Null
    Write-Ok 'data directory cleared'
    Write-Host "  Security will re-bootstrap from the keystore on next start, so" -ForegroundColor DarkGray
    Write-Host "  ES_BOOTSTRAP_PASSWORD must match .env at that moment." -ForegroundColor DarkGray
    Write-Host "  Next: -Stage StartElasticsearch, then -Stage SetPassword" -ForegroundColor Cyan
}

# --- Stage 8: Health ------------------------------------------------------------------
function Test-Health {
    Write-Step 'Health verification'

    $auth = @{ Authorization = "Basic $([Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("elastic:$($env:ELASTIC_PASSWORD)")))" }

    $es = Invoke-RestMethod -Uri 'http://127.0.0.1:9200' -Headers $auth -TimeoutSec 15
    Write-Ok "Elasticsearch $($es.version.number) (cluster '$($es.cluster_name)')"

    $h = Invoke-RestMethod -Uri 'http://127.0.0.1:9200/_cluster/health' -Headers $auth -TimeoutSec 15
    Write-Ok "cluster: $($h.status) | nodes=$($h.number_of_nodes) | active_shards=$($h.active_shards) | unassigned=$($h.unassigned_shards)"

    # Prove the bind is really loopback-only rather than assuming the config took.
    foreach ($p in 9200, 5601) {
        $addrs = @(Get-NetTCPConnection -LocalPort $p -State Listen -ErrorAction SilentlyContinue |
                   Select-Object -ExpandProperty LocalAddress -Unique)
        if ($addrs.Count -eq 0) { throw "Nothing is listening on port $p" }
        Write-Ok "port $p listening on: $($addrs -join ', ')"
        if ($addrs -contains '0.0.0.0' -or $addrs -contains '::') {
            Write-Warn2 "port $p is bound to ALL interfaces. Lab policy is loopback only - see docs/configuration.md#network-binding"
        }
    }

    $kbAuth = @{ Authorization = "Basic $([Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("elastic:$($env:ELASTIC_PASSWORD)")))" }
    # GET /api/status is REDACTED when called unauthenticated: 9.x returns only
    #   {"status":{"overall":{"level":"available"}}}
    # with no `version` and no per-plugin `status.statuses`. Authenticate so the
    # check can actually report the version and find degraded plugins.
    $kb = Invoke-RestMethod -Uri 'http://127.0.0.1:5601/api/status' -Headers $kbAuth -TimeoutSec 20
    Write-Ok "Kibana $($kb.version.number) status $($kb.status.overall.level)"

    # Per-plugin health lives at status.plugins in 9.5.3.
    # (status.statuses was the 8.x shape and is now absent/null.)
    # Each entry is a FLAT { level, summary } object - there is no nested
    # `overall` object, which is why reading .overall.level yields '' and makes
    # every plugin look broken.
    $pluginProps = @($kb.status.plugins.PSObject.Properties)
    $degraded = @($pluginProps |
                  ForEach-Object { [pscustomobject]@{ Name = $_.Name; Level = $_.Value.level; Summary = $_.Value.summary } } |
                  Where-Object { $_.Name -and $_.Level -and $_.Level -ne 'available' })
    if ($pluginProps.Count -eq 0) {
        Write-Warn2 'Kibana /api/status returned no per-plugin detail (it can be redacted); overall level was checked only'
    } elseif ($degraded.Count -eq 0) {
        Write-Ok "all $($pluginProps.Count) Kibana plugins report 'available'"
    } else {
        foreach ($d in $degraded) { Write-Warn2 "plugin $($d.Name) is '$($d.Level)': $($d.Summary)" }
    }

    # Core services matter more than the long plugin list for this lab:
    # Elasticsearch connectivity and saved-objects migration state.
    foreach ($svc in 'elasticsearch', 'savedObjects') {
        $lvl = $kb.status.core.$svc.level
        if ($lvl -eq 'available') { Write-Ok "core.$svc available" }
        else { Write-Warn2 "core.$svc is '$lvl': $($kb.status.core.$svc.summary)" }
    }

    # The two facts a reviewer cares about most: is security really on, and is
    # the deployment self-contained on loopback.
    #
    # Security proof uses /_security/_authenticate, NOT /_xpack/usage.
    # In 9.5.3 `/_xpack/usage` returns an EMPTY _xpack object, so the old
    # `_xpack.available` check silently reported security as disabled.
    $me = Invoke-RestMethod -Uri 'http://127.0.0.1:9200/_security/_authenticate' -Headers $auth -TimeoutSec 20
    if ($me.enabled -and $me.username -eq 'elastic') {
        Write-Ok "Elasticsearch security active (authenticated as '$($me.username)', enabled=$($me.enabled))"
    } else {
        throw "Elasticsearch security is not behaving as expected: username='$($me.username)' enabled=$($me.enabled). Fleet enrollment requires security."
    }

    $unauth = try { (Invoke-WebRequest -Uri 'http://127.0.0.1:9200/_cluster/health' -UseBasicParsing -TimeoutSec 15).StatusCode } catch { [int]$_.Exception.Response.StatusCode }
    if ($unauth -eq 401) { Write-Ok 'unauthenticated API access correctly rejected with HTTP 401' }
    else { throw "Unauthenticated request to /_cluster/health returned HTTP $unauth instead of 401. Security is not enforcing authentication." }
}

# --- Orchestrator -----------------------------------------------------------------------
Write-Host 'SOC-Lab Elastic Stack installer' -ForegroundColor White
Write-Host "Version    : $Version"
Write-Host "InstallRoot: $InstallRoot"
Write-Host "Repo       : $RepoRoot"

$stages = [ordered]@{
    Preflight          = { Invoke-Preflight }
    Download           = { Invoke-Download }
    Extract            = { Invoke-Extract }
    Render             = { Invoke-RenderConfig }
    Keystore           = { Invoke-Keystore }
    Tune               = { Invoke-Tune }
    StartElasticsearch = { Start-Elasticsearch }
    SetPassword        = { Set-ElasticUserPassword }
    ServiceToken       = { Get-KibanaServiceToken }
    StartKibana        = { Start-Kibana }
    Health             = { Test-Health }
    Stop               = { Stop-ElasticStack }
    ResetData          = { Invoke-ResetData }
}

# .env must be loaded for EVERY stage, not just Preflight. Running
# `-Stage Render` in a fresh process previously produced a config with an
# empty ELASTIC_PASSWORD, because the token check cannot distinguish
# "substituted with a value" from "substituted with nothing".
Import-DotEnv $EnvFile

# -ResetData is a modifier: stop, wipe, then continue through the normal order.
if ($ResetData) {
    Invoke-ResetData
    Invoke-Keystore
    Invoke-Tune
    Start-Elasticsearch
    Set-ElasticUserPassword
    Get-KibanaServiceToken
    Invoke-RenderConfig
    if ($Stage -eq 'All') { Start-Kibana; Test-Health }
    exit 0
}

if ($Stage -eq 'All') {
    Invoke-Preflight
    # ServiceToken MUST precede Render: Kibana's config embeds the token, and
    # rendering first leaves an unsubstituted token that Kibana rejects.
    foreach ($k in 'Download','Extract','Keystore','Tune','StartElasticsearch','SetPassword','ServiceToken','Render','StartKibana','Health') {
        & $stages[$k]
    }
} else {
    & $stages[$Stage]
}

Write-Host "`nDone. Next: scripts/validation/Test-ElasticStackHealth.ps1" -ForegroundColor Green
