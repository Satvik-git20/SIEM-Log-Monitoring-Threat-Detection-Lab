# Architecture & deviations

This lab deploys the same data model through two paths. Document the
differences so a reviewer does not judge the Docker path against the native
checklist.

---

## Architecture (both paths)

```
[Sysmon + PowerShell + Windows Security logs]   [Elastic Agent]
        WIN-SOC01 endpoint                            |
        (Fleet Server integration)                     |  (Linux endpoint,
                                                       |   added Phase 5)
        ES container / native ES                       |  logs-windows.*
        Kibana container / native Kibana               v
        Fleet Server (control plane)  --->  Kibana UI
```

Both paths produce the same data model:

| Stream | Native | Docker |
|---|---|---|
| `logs-system.security` | yes | yes |
| `logs-system.system` | yes | yes |
| `logs-system.application` | yes | yes |
| `logs-windows.sysmon_operational` | yes | yes |
| `logs-windows.powershell_operational` | yes | yes |

## Deviations (Docker path vs native)

1. **No Docker on the build host.** This lab was originally built natively, so
   `docker/compose.yml` is the equivalent path for Docker reviewers, not the
   path the build used. Both produce identical data.
2. **Kibana credential model.** Native uses `elasticsearch.serviceAccountToken`
   in a rendered config. Docker mounts a rendered `docker/kibana.yml` with the
   same token. Neither sets `ELASTICSEARCH_USERNAME=elastic` (Kibana 9.x
   forbids it).
3. **Paths.** Native `path.data/path.logs` are Windows paths inside
   `C:\elastic`; Docker uses `/usr/share/kibana/{data,logs}`.
4. **Bind addresses.** Native binds ES and Fleet Server to `127.0.0.1` in
   `elasticsearch.yml`/`kibana.yml`. Docker binds the *container* to
   `0.0.0.0` and relies on the host-side port mapping (`127.0.0.1:9200:9200`)
   to enforce loopback-only. This is the same control, expressed differently.
5. **Projects.**
   - Native: single-node, no bootstrap checks, no transport TLS.
   - Docker: single-node, all ports published to the host at `127.0.0.1` only.

## Security posture

- Everything binds to `127.0.0.1`. In Docker, the host-side port mapping is
  the actual external control.
- `xpack.security.enabled=true` in ES; Kibana uses the `elastic/kibana`
  service-account token (not the superuser).
- TLS is disabled (lab deviation; see `docs/configuration.md#tls`).
- The Windows Security channel is filtered to the lab's event IDs (see
  `Add-WindowsIntegrations.ps1`).
