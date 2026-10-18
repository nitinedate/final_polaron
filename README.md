# Polaron external evidence drive recovery and verification

This package contains a **non-destructive diagnostic wrapper**, not a claim to have repaired Docker Desktop on an inaccessible Windows workstation. It requires the resolver, Test-ForensicMedia.ps1, helper and Compose setup from the uploaded Polaron project. Copy scripts/Verify-EvidenceDrive.ps1 into the same scripts directory of your deployed project.

## Steps for the failing G: drive (PowerShell)

1. Checkpoint active jobs. Keep evidence drive connected and prevent drive letter reassignment.
2. Check Windows: `Test-Path -LiteralPath 'G:\DISK2\DataExtration\SegerEx-1'`; `Get-Volume -DriveLetter G`.
3. Check Docker Desktop: `docker context show`; `docker info`; `wsl --list --verbose`.
4. Check active project/helper: `powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\hostdrive-doctor.ps1` (use `-Fix` only after all jobs checkpoint).
5. Run: `powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\Verify-EvidenceDrive.ps1 -EvidencePath 'G:\DISK2\DataExtration\SegerEx-1'`.
6. If still ENODEV, ensure Docker Desktop uses WSL2, install a normal WSL2 Ubuntu distribution if none exists, enable that distribution under Docker Desktop > Settings > Resources > WSL Integration, and verify the exact folder in WSL: `wsl -d Ubuntu --exec sh -lc 'ls -la /mnt/g/DISK2/DataExtration/SegerEx-1'`.
7. WSL filesystem bridge if the path is absent: within Ubuntu, `sudo mkdir -p /mnt/g` and `sudo mount -t drvfs -o ro G: /mnt/g` (use only if not already mounted). Repeat verification. Docker Desktop integration is necessary but not sufficient; the resolver must report a verified Docker bind.
8. On success, checkpoint affected cases, then use HostDrive > Select disk folder / Refresh drive mounts; confirm Docker can enumerate the exact E01/E02 folder inside both API and extraction worker before starting extraction.

Avoid `wsl --mount` for a Windows-mounted USB flash drive. Never format/initialize/repair source media without appropriate forensic procedures. Never run `docker compose down -v`, prune database volumes, or switch a required source to a dummy/empty directory.

## Source project observations

- `scripts/resolve-docker-drive-source.ps1` already handles native bind, selected-folder bind, ENODEV detection, and WSL fallback; actual physical-device access must be tested on the affected host.
- `scripts/refresh-drive-mounts-job.ps1` already implements affected-service remounting and evidence path verification.
- `scripts/hostdrive-doctor.ps1` detects helper processes serving a different/older source checkout.
- `scripts/Test-ForensicMedia.ps1` already enumerates all Windows-accessible local filesystem volume letters irrespective of bus type.
- The fix must **not** replace this logic with hardcoded G: mapping or claim that any Windows-visible filesystem is invariably Docker-shareable.

## Acceptance criteria

* Attach an NTFS/exFAT HDD, SSD or USB disk and verify Windows discovery and exact-folder selection.
* Docker API and worker both can list the source evidence filenames and sizes, including first/last EWF segments, through a read-only mount.
* Disconnect/reconnect/swap device: no stale path is processed; job pauses/fails closed and requests remount.
* No evidence bytes copied or mutated. No other case or database restarted as a side effect of drive discovery.
* Resume only when mounted evidence identity is consistent with the registered case.

Physical Windows/Docker validation is outstanding; no Docker Desktop engine is available in the analysis container.
