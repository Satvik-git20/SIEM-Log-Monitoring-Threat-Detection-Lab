# SOC-Lab installation

How to install the stack, and how versions are pinned.

---

## Version pinning

The lab target is **Elasticstack 9.5.3** (GA). Versions are pinned in three
places and must change together:

| File | Key |
|---|---|
| `docker/.env.example` | `STACK_VERSION=9.5.3` |
| `elastic/config-templates/elasticsearch.yml.tmpl` | (comment: verified against 9.5.3) |
| `elastic/config-templates/kibana.yml.tmpl` | (comment: verified against 9.5.3) |

Both `Install-ElasticStack.ps1` and the Docker `compose.yml` read
`STACK_VERSION` with a default of `9.5.3`; change it in one place and re-verify
the image tags you use.

## Native installation (Windows, no Docker)

`scripts/setup/Install-ElasticStack.ps1` runs an ordered, idempotent set of
stages. Run it plain to execute **All**, or pick a stage to iterate:

```powershell
# All
pwsh -File scripts/setup/Install-ElasticStack.ps1
# One stage
pwsh -File scripts/setup/Install-ElasticStack.ps1 -Stage StartElasticsearch
```

Stages (in order):

1. **Preflight** — PowerShell 5.1+, RAM ≥ 8 GB, ≥ 12 GB free disk, admin check,
   port conflicts (9200/9300/5601/8220).
2. **Download** — vendor ZIPs (`artifacts.elastic.co`), SHA-512 verified *before*
   unpacking (supply-chain control).
3. **Extract** — to `C:\elastic\<component>-<version>` (uses `tar`).
4. **Render** — `elasticsearch.yml` / `kibana.yml` from the templates + `.env`.
5. **Keystore** — `bootstrap.password` secure setting (Elasticsearch 9.x
   mechanism; written byte-exact, no trailing newline, verified).
6. **Tune** — `-Xms/-Xmx` heap cap in `config\jvm.options.d\soc-lab.options`
   (single `#` comments, no BOM).
7. **StartElasticsearch** — launches `elasticsearch.bat`, waits for HTTP.
8. **SetPassword** — rotates the `elastic` superuser off the bootstrap
   credential (`POST /_security/user/elastic/_password`).
9. **ServiceToken** — creates `elastic/kibana` service-account token, writes it
   to `.env`.
10. **Render** — (re-)render configs with the token present.
11. **StartKibana** — launches `kibana.bat`, waits for `/api/status`.
12. **Health** — `Test-ElasticStackHealth.ps1`.

`-Stage ResetData` is the only destructive stage and is opt-in; it wipes the ES
data dir and re-bootstraps the keystore.

## Docker installation

```powershell
cp docker/.env.example docker/.env
docker compose up -d
```

The Docker path uses `docker/ compose.yml` + a rendered `docker/kibana.yml`.
Both read `STACK_VERSION`/`ELASTIC_PASSWORD` from `docker/.env` (read by
`docker compose` via the `.env` next to the compose file), while the PowerShell
scripts always read the **repo-root** `.env`.

## Agent installation (endpoint)

This is the Windows endpoint (`WIN-SOC01`) and its services:

```powershell
# Elevated, once
powershell -ExecutionPolicy Bypass -File scripts/setup/Invoke-ElevatedBootstrap.ps1
# Fleet policies + enrollment keys (non-elevated)
pwsh -File scripts/setup/Setup-Fleet.ps1
# Attach integrations to the Windows policy (non-elevated)
pwsh -File scripts/setup/Add-WindowsIntegrations.ps1
```

See `scripts/setup/Invoke-ElevatedBootstrap.ps1` for the exact elevated
`elastic-agent.exe install` command it prints.

## Version upgrade

1. Update `STACK_VERSION` in `docker/.env.example` and the two template
   comments.
2. Update `Install-ElasticStack.ps1` default `$Version` (a `ValidateSet` stage
   list) if new stages were added.
3. Review the removed settings in `kibana.yml.tmpl` / `elasticsearch.yml.tmpl`
   for the new version (9.x removed several settings; a template that aborts
   startup on the new version is the first signal).
4. Re-render native configs and re-run the health gate.
