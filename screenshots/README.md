# Screenshots

This directory is intentionally **empty of images**.

## Why there are no screenshots yet

Placeholder or mock screenshots are worse than no screenshots: they are
indistinguishable from evidence of a working lab until someone opens them, and a
reviewer who does open them loses trust in the whole repository.

A screenshot belongs here only when it is a real capture of this lab running on
this machine.

## How to capture real evidence

Use these instead of screenshots wherever possible, because they are
reproducible and diff-able:

| Evidence | Command | Output location |
|---|---|---|
| Stack health | `scripts/validation/Test-ElasticStackHealth.ps1` | `tests/validation/results/` |
| Ingestion proof | `scripts/validation/Test-LogIngestion.ps1` | `tests/validation/results/` |
| Detection pass/fail | `scripts/validation/Invoke-DetectionTestSuite.ps1` | `tests/validation/results/` |
| Field inventory | `scripts/validation/Export-FieldInventory.ps1` | `elastic/index-templates/field-inventory.md` |
| Rule export | `scripts/validation/Export-DetectionRules.ps1` | `elastic/alerts/*.ndjson` |

To capture an actual image (Windows):

```powershell
# Capture the Kibana SOC Operations Dashboard to screenshots/soc-operations-dashboard.png
Add-Type -AssemblyName System.Windows.Forms, System.Drawing
$bounds = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
$bmp = New-Object System.Drawing.Bitmap $bounds.Width, $bounds.Height
$gfx = [System.Drawing.Graphics]::FromImage($bmp)
$gfx.CopyFromScreen($bounds.Location, [System.Drawing.Point]::Empty, $bounds.Size)
$bmp.Save("$PSScriptRoot\screenshots\soc-operations-dashboard.png", [System.Drawing.Imaging.ImageFormat]::Png)
$gfx.Dispose(); $bmp.Dispose()
```

## Checklist before committing an image

- [ ] Taken from this lab, on this machine
- [ ] Browser URL bar visible so the reviewer can see host/port
- [ ] Kibana timestamp/filter visible so the data range is obvious
- [ ] No secrets, tokens or real personal data in frame
- [ ] Filename describes content: `det-01-alert-fired.png`, not `screenshot1.png`
