# SOC-Lab troubleshooting

Concise, ordered answers to the problems that actually come up in this lab.

---

## Elasticsearch will not start

1. Check the bootstrap log:
   ```powershell
   Get-Content C:\elastic\elasticsearch-<version>\logs\soc-lab-bootstrap.log -Tail 50
   ```
2. The most common causes:
   - `ELASTIC_PASSWORD` (or an `ELASTIC_PASSWORD:` line) still in the rendered
     `config\elasticsearch.yml`. Elasticsearch 9.x removed it; it must live in
     the keystore as `bootstrap.password`.
   - A token survived rendering in the YAML (check for `__TOKEN__` leftovers).
   - A **BOM** or a `##` comment in `config\jvm.options.d\soc-lab.options`
     (PowerShell's default `-Encoding UTF8` writes a BOM; JVM rejects it).
3. If the node answers `401` on `http://127.0.0.1:9200/_cluster/health` but no
   `400`, it is *up and secure*; the password simply hasn't been rotated yet.

## Kibana will not start

1. If startup dies with a `ValidationError` and the log is empty, Kibana exits
   before its logging framework starts; read
   `...\kibana-<version>\logs\soc-lab-bootstrap.log.err`.
2. Common causes:
   - `elasticsearch.username: elastic` present → Kibana 9.x forbids it
     (`FATAL: value of "elastic" is forbidden`). Use
     `elasticsearch.serviceAccountToken`.
   - `elasticsearch.shutdownTimeout` present → removed in 9.x; use
     `elasticsearch.requestTimeout` (a duration, not a bare ms number).
   - `logging.appenders.rolling` defined but not attached to `logging.root`
     → the file is never written and the root logger stays on `console` only.
   - `xpack.fleet.agents.elasticsearch.ssl.enabled` / `...fleet_server.ssl.enabled`
     present → removed in 9.x; configure trust on the *agent* side instead.
   - `xpack.encryptedSavedObjects.encryptionKey` missing / < 32 chars →
     Fleet setup fails with `FleetEncryptedSavedObjectEncryptionKeyRequired`.

## `elastic` passworders 401 everywhere

1. Confirm `ELASTIC_PASSWORD` is **not** in `config\elasticsearch.yml`.
2. Run the keystore stage:
   ```powershell
   pwsh -File scripts/setup/Install-ElasticStack.ps1 -Stage Keystore
   pwsh -File scripts/setup/Install-ElasticStack.ps1 -Stage SetPassword
   ```
3. Verify with the health gate (`Test-ElasticStackHealth.ps1`), which asserts
   unauthenticated `/_cluster/health` returns `401` and that `ELASTIC_PASSWORD`
   actually authenticates.

## Fleet setup returns `FleetEncryptedSavedObjectEncryptionKeyRequired`

Kibana 9.x reports this as an *optional* missing feature but it is mandatory in
practice. Ensure
`xpack.encryptedSavedObjects.encryptionKey` (≥ 32 chars) is in `kibana.yml` and
matches `.env`. Do not rotate it after the first successful Fleet setup.

## Kibana 9.x rejects `elasticsearch.username: elastic`

Use a service-account token instead. On the native path, `Install-ElasticStack.ps1`
stages: `StartElasticsearch` → `ServiceToken` → `Render`. The token is created
via `POST /_security/service/elastic/kibana/credential/token/soc-lab-kibana-token`
and written back to `.env` as `KIBANA_SERVICE_TOKEN`.

## Agent enrollment fails

- The agent must reach Kibana on the Fleet Server URL. Native: `http://127.0.0.1:5601`.
- Docker: the host machine's IP or container IP, not `localhost` (agents run on
  other hosts). Use the Docker host networking or publish the required ports.
- The enrollment API key must exist in `.env` as `FLEET_ENROLLMENT_TOKEN`, and
  `WINDOWS_AGENT_ENROLLMENT_TOKEN` for the Windows endpoint.
- The agent policy for the endpoint must be attached (run
  `Add-WindowsIntegrations.ps1` after `Setup-Fleet.ps1`).

## Sysmon events are missing

- Run `Invoke-ElevatedBootstrap.ps1` (elevated) to reinstall/reapply the config.
- Verify EID 1 is present:
  ```powershell
  Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1} -MaxEvents 1
  ```
- `sysmon/sysmon-config.xml` is shipped with `ImageLoad` OFF on purpose (noise).
  Enable it for injection hunting if needed.

## PowerShell 4104 not firing

- The policy must be applied in a **new** PowerShell session.
- `ScriptBlockLogging=1` must be `1`, not merely present.
- The `Audit Process Creation` policy must include the command line; otherwise
  `4688` has no `CommandLine` and `DET-03` weakens silently.

## Out of memory (lab host)

- Reduce Kibana / ES heap; the lab default is 1 GB. Do not set `0.0.0.0` on a
  shared network while raising the heap — the loopback-only control is the host
  port mapping.
- Close WSL2 VMs / other heavy processes.

## Data streams are missing

- Run `Test-ElasticStackHealth.ps1 -RequireTelemetry` after agents are enrolled.
- Verify the fleet policies in Kibana → Fleet → Agent policies.
- Check `logs-windows.sysmon_operational` in Discover; the agent policy may not
  have the `System` / `Windows` integrations attached.

## Reset a changed `ELASTIC_PASSWORD`

```powershell
pwsh -File scripts/troubleshooting/Reset-ElasticPassword.ps1
```

The installer's `ResetData` stage (debug use only) wipes ES data **and**
re-bootstrap the keystore; it is opt-in and never part of `-Stage All`.
