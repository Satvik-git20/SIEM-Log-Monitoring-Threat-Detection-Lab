# SOC-Lab configuration

This document records the configuration decisions for the SOC-Lab: what is on,
where it binds, how credentials are handled, and which data streams land in
Elasticsearch.

---

## Network binding

**All lab listeners bind to `127.0.0.1` only.** This is the lab's primary
network security control.

| Component | Native (Windows ZIP) | Docker |
|---|---|---|
| Elasticsearch HTTP | `network.host: 127.0.0.1`, `http.port: 9200` | `docker compose` publishes `127.0.0.1:9200:9200` |
| Elasticsearch transport | `transport.port: 9300` (single-node, no TLS) | container-internal only |
| Kibana | `server.host: 127.0.0.1` | `docker compose` publishes `127.0.0.1:5601:5601` |
| Fleet Server | `FLEET_SERVER_HOST=127.0.0.1`, `FLEET_SERVER_PORT=8220` | `docker compose` publishes `127.0.0.1:8220:8220` |
| Elastic Agent / Fleet Server service | loopback to Kibana/Fleet Server | container-internal only |

**Important:** the loopback guarantee is enforced at the *host port* mapping
(`127.0.0.1:9200:9200`), not by the container's internal bind address.
In Docker, `network.host=0.0.0.0` inside the ES container is what allows other
containers on the `soc-lab` bridge to reach the cluster; only the host-side
port translation to `127.0.0.1` stops external hosts on your network. Do not
change the host-side bind to `0.0.0.0` on a shared network.

---

## TLS

**TLS is disabled deliberately and is a documented lab deviation.**

Every listener in the lab is bound to `127.0.0.1` on a single-user workstation.
There is no untrusted network path carrying credentials or telemetry, so TLS is
overhead rather than protection. Removing it keeps startup deterministic and
lets enrollment commands stay simple (`--enrollment-token`, plain HTTP).

This is **not** a production pattern. For a real deployment:

1. Put ELASTICSEARCH_HTTP_SSL/transport TLS certificates in place (native or
   Docker).
2. Point `elasticsearch.hosts` at `https://...`.
3. Set `KIBANA_ENCRYPTION_KEY` and `xpack.encryptedSavedObjects.encryptionKey`
   and the Fleet Server `--fleet-server-insecure-http=0`.
4. Regenerate the Fleet Server certificate authority and enroll agents against
   it.

See `docs/architecture/deviations.md` for the full deviation list.

---

## Memory budget

- Lab target host: ~15.3 GB RAM shared with WSL2 and the Windows endpoint agent.
- Elasticsearch heap: **1 GB** (`ES_JVM_HEAP=1g`), capped with `-Xms/-Xmx` (a hard
  cap, not `-XX:MaxRAMPercentage`). A percentage-based heap can starve the
  Windows endpoint that *produces* the telemetry and silently truncate
  Sysmon/Security collection.
- Kibana uses its default (non-heap-critical) sizing.

Raise to `2g` only if ingest/queries are slow **and** the host has memory to
spare.

---

## Credentials

| Secret | Purpose | Where it lives |
|---|---|---|
| `ES_BOOTSTRAP_PASSWORD` | Transient keystore `bootstrap.password`, used once at install to set the real `elastic` password, then retired | `.env` (gitignored) |
| `ELASTIC_PASSWORD` | `elastic` superuser password; used by every setup/validation script | `.env` (gitignored) |
| `KIBANA_SERVICE_TOKEN` | Service-account token for the built-in `elastic/kibana` service account; Kibana 9.x hard-rejects the `elastic` superuser | `.env` (gitignored) |
| `KIBANA_ENCRYPTION_KEY` | `xpack.encryptedSavedObjects.encryptionKey`; ≥ 32 chars, required for Fleet setup to complete in 9.x | `.env` (gitignored) |
| `FLEET_ENROLLMENT_TOKEN` | Fleet enrollment API key for the Windows endpoint | `.env` (gitignored) |
| `FLEET_SERVER_ES_TOKEN` | ES service-account token for the `elastic/fleet-server` service account | `.env` (gitignored) |
| `WINDOWS_AGENT_ENROLLMENT_TOKEN` | Fleet enrollment API key for the Windows endpoint | `.env` (gitignored) |

**Keystore note:** Elasticsearch 9.x removed `ELASTIC_PASSWORD` from
`elasticsearch.yml`. The supported mechanism is a `bootstrap.password` SECURE
SETTING in the Elasticsearch keystore (see `Install-ElasticStack.ps1` stages
`Keystore`/`SetPassword`).

**Rotation warning:** changing `KIBANA_ENCRYPTION_KEY` after Kibana has stored
encrypted saved objects makes them unreadable. Treat it as a permanent, stable
secret.

---

## Console/base URL and Fleet

- `server.publicBaseUrl` is `http://localhost:5601` (native) or
  `http://localhost:5601` (Docker, see `docker/kibana.yml`).
- Fleet Server is a Fleet-managed **integration**, not a Kibana boolean
  (`xpack.fleet.agents.fleet_server.enabled` was removed in 9.x).

---

## Security event filter (Windows Security channel)

`Add-WindowsIntegrations.ps1` restricts the `logs-system.security` data stream
to the event IDs the lab's detections and hunts actually use (4624, 4625, 4634,
4648, 4672, 4688, 4689, 4771, 4776, 4768, 4769, 4767, 4794, 4720, 4722, 4724,
4726, 4732, 4728, 4756, 4697, 1102, 4719, 4616, 4608, 4609, 12, 13, 6005, 6006,
6008, 6013, 7045). This keeps ingest readable: the Security channel is chatty
(4768/4769/4771 Kerberos, 4688 with command lines, 4657/4656 object access).

`4771` is *not* a subset of `4625` (pre-auth Kerberos failures never produce
`4625`), so a `4625`-only brute-force rule would miss the most common domain
brute force; both are collected.

---

## Data model

The lab ingests these data streams (verified against the live API):

| Stream | Source |
|---|---|
| `logs-system.security` | Windows Security channel (filtered event IDs) |
| `logs-system.system` | Windows System channel |
| `logs-system.application` | Windows Application channel |
| `logs-windows.sysmon_operational` | Sysmon (EID 1/3/7/10/22/…) |
| `logs-windows.powershell_operational` | PowerShell 4103/4104 |

`logs-system.auth` / `logs-system.syslog` are collected on the **Linux**
endpoint later (Phase 5) — the same `system` integration package.

---

## Retention and ILM

Index templates bound to ILM retain the lab's telemetry for a bounded window
(on the host this is ~148 GB free disk; the lab is expected to generate well
under 1 GB/day). See `scripts/validation/Export-FieldInventory.ps1` for the
current field inventory.
