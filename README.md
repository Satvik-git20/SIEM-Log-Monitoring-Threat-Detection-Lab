# SOC-Lab: SIEM Log Monitoring & Threat Detection Platform

**A local, loopback-only SIEM lab built on the Elastic Stack (Elasticsearch 9.x +
Kibana 9.x + Elastic Agent / Fleet Server) with Sysmon and PowerShell logging on a
Windows endpoint.**

> **Status:** partial implementation of the full lab described in this repo.
> Setup scripts and docs are present and functional for the install path that was
> actually used to build this lab; a Docker path has been added and a few
> referenced assets (docs/, validation/export scripts, troubleshooting script,
> Reset-ElasticPassword.ps1) were missing and have now been added.

---

## What you get

| Layer | What it collects |
|---|---|
| **Windows endpoint (WIN-SOC01)** | Sysmon (process create, network connect, image load, process access, file create, registry, DNS), PowerShell 4103/4104, Windows Security/System/Application logs (4624/4625/4688 …) |
| **Elasticsearch** | Ingestion store, ILM retention, index templates, security (auth + authorization) |
| **Kibana 9.x** | SOC dashboard, Fleet, Elastic Security, saved-objects encryption key |
| **Elastic Agent / Fleet Server** | Fleet-managed Windows + Linux agents, policy distribution, enrollment |

Detection rules, dashboards and the Threat Hunting view work on the **Basic**
license; no trial licence is required.

> Lab posture: **everything binds to 127.0.0.1 on a single-user workstation.
> There is no untrusted network path.** This is a documented lab deviation, NOT
> a production pattern (see `docs/configuration.md#tls-deviation`).

---

## Prerequisites

- **Windows 10/11** (native path) or **Docker Desktop** (Docker path)
- **PowerShell 5.1+** with `Set-ExecutionPolicy -ExecutionPolicy RemoteSigned` or
  `Bypass` (scripts use `pwsh`/`powershell`)
- **RAM:** 8 GB minimum recommended (lab target is 15.3 GB host RAM); ES + Kibana
  + Fleet + a Windows agent thrash below 8 GB
- **Disk:** ≥ 12 GB free (native path installs into `C:\elastic`)
- **Network:** loopback-only. Do **not** bind to `0.0.0.0` on a shared or
  university network.
- **Admin** rights (for Sysmon/agent service/PowerShell policy on the native path)

---

## Quickstart

Two paths. Pick **one**. Both produce the same data model (see
`docs/architecture/deviations.md` for the differences).

### Path A — Native (Windows, no Docker)

The path used to build this lab (the build host had no Docker).

```powershell
# 1. Generate secrets (writes the gitignored .env)
pwsh -File scripts/setup/New-LabSecrets.ps1

# 2. Install Elasticsearch + Kibana natively (all idempotent stages)
pwsh -File scripts/setup/Install-ElasticStack.ps1
#    (run -Stage StartElasticsearch, -Stage SetPassword, -Stage ServiceToken,
#     -Stage Render, -Stage StartKibana individually to iterate on a failure)

# 3. Finish the endpoint (elevated PowerShell, run once)
powershell -ExecutionPolicy Bypass -File scripts/setup/Invoke-ElevatedBootstrap.ps1

# 4. Set up Fleet Server + Windows endpoint agent policies
pwsh -File scripts/setup/Setup-Fleet.ps1

# 5. Attach the System + Windows integrations to the Windows policy
pwsh -File scripts/setup/Add-WindowsIntegrations.ps1

# 6. Validate the whole stack (CI-style gate)
pwsh -File scripts/validation/Test-ElasticStackHealth.ps1
```

### Path B — Docker

```powershell
# 1. Copy the Docker environment template
cp docker/.env.example docker/.env

# 2. Start the stack
docker compose up -d

# 3. Verify
docker compose ps
docker compose logs -f kibana | select-string -Pattern 'available|error'

# 4. Validate
pwsh -File scripts/validation/Test-ElasticStackHealth.ps1
```

See `docker/README.md` for the credential render step and agent enrollment.

---

## Evidence & next steps

- **What is in this repo vs. what is just documented** — `screenshots/README.md`
  (no placeholder screenshots; it points to reproducible validation output in
  `tests/validation/results/` and to the index-template/rule exports).
- **Configuration decisions, network binding, and the TLS/password deviations** —
  `docs/configuration.md`.
- **Known deviations between the Docker and native paths** —
  `docs/architecture/deviations.md`.
- **Startup/runtime troubleshooting** — `docs/troubleshooting.md`.
- **How to install** (native install stages, version pinning) — `docs/installation.md`.

---

## Repo layout

```
docker/             Docker Compose + rendered Kibana config (Path B)
  docker-compose.yml
  .env.example
  kibana.yml        Rendered Kibana config for Docker (has KIBANA_SERVICE_TOKEN)
elastic/
  config-templates/ Elasticsearch + Kibana YAML templates (native path only)
  index-templates/    (ILM field inventory — see scripts/validation/Export-FieldInventory.ps1)
scripts/setup/       Secrets, Elasticsearch + Kibana install, Fleet, integrations
scripts/validation/  Health gate + ingestion + detection + export scripts
scripts/troubleshooting/ Reset-ElasticPassword.ps1
sysmon/             Sysmon configuration for WIN-SOC01
tests/validation/    Validation results (health.json, etc.)
```

---

## Security note

The credentials in `.env` protect a **loopback-only lab on one workstation**.
They are **not** production credentials and must **not** be reused. Never
commit `.env` — it is gitignored (see `.gitignore`). Reminder:
`git log -p | grep -iE 'password|token|BEGIN .*PRIVATE KEY'`.
