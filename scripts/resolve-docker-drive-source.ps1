# Resolve a Windows drive to a Docker-readable bind source.
#
# Why this exists:
# Docker Desktop can create a bind mount for a newly attached/removable Windows
# drive while exposing an empty/stale directory to Linux containers.  A plain
# "G:/ -> /host/g" Compose entry therefore is not sufficient evidence that the
# real disk is readable.
#
# Resolution order:
#   1. Test several Docker Desktop direct-source spellings against the exact
#      selected Windows path (or a root sentinel when no path was supplied).
#   2. If those fail, mount the Windows drive with WSL DrvFs under /mnt/wsl and
#      test Docker-accessible views of that bridge.
#
# The script never copies evidence bytes.  The final container mount remains
# read-only.  It writes a JSON result when -OutputFile is supplied.

param(
    [Parameter(Mandatory = $true)][string]$DriveLetter,
    [string]$RequiredPath = "",
    [string]$Root = "",
    [string]$ApiImage = "",
    [string]$OutputFile = "",
    [switch]$ForceWslBridge,
    [switch]$RemountOnly,
    [switch]$PrivateDrive
)

$ErrorActionPreference = "Stop"

$env:DOCKER_CLI_HINTS = "false"

function Convert-NativeOutputToLines {
    # Normalises redirected native output (strings, and on Windows PowerShell
    # 5.1 ErrorRecord objects for stderr lines) into plain text lines.
    param($Output)
    $lines = @()
    foreach ($item in @($Output)) {
        if ($null -eq $item) { continue }
        $text = if ($item -is [System.Management.Automation.ErrorRecord]) {
            [string]$item.Exception.Message
        }
        else {
            [string]$item
        }
        # [char]27: the `e escape only exists in PowerShell 6+, not in 5.1.
        $esc = [char]27
        $text = ($text -replace "$esc\[[0-9;?]*[ -/]*[@-~]", '') -replace "`0", ''
        foreach ($piece in ($text -split "`r?`n")) {
            $trimmed = $piece.TrimEnd()
            if ($trimmed.Trim()) { $lines += $trimmed }
        }
    }
    return @($lines)
}

function Invoke-NativeCapture {
    # Run a native executable and capture stdout + stderr as text WITHOUT the
    # Windows PowerShell 5.1 behaviour where the first redirected stderr line
    # becomes a terminating error under $ErrorActionPreference = "Stop".
    # "docker info" (WARNING: lines) and "docker run" (image pull / python
    # tracebacks) both write to stderr in perfectly normal situations, and
    # previously made a healthy probe look like a failure.
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [string[]]$ArgumentList = @(),
        [string]$StdinText = ""
    )
    $ErrorActionPreference = "Continue"
    $global:LASTEXITCODE = 0
    $raw = @()
    $code = 0
    # A [string] parameter coerces $null to "", so use the bound-parameter set
    # to decide whether stdin should be fed to the process at all.
    $feedStdin = $PSBoundParameters.ContainsKey('StdinText')
    try {
        if ($feedStdin) {
            $raw = @($StdinText | & $FilePath @ArgumentList 2>&1)
        }
        else {
            $raw = @(& $FilePath @ArgumentList 2>&1)
        }
        $code = if ($null -ne $LASTEXITCODE) { [int]$LASTEXITCODE } else { 0 }
    }
    catch {
        $raw = @($raw) + @($_.Exception.Message)
        $code = -1
    }
    $global:LASTEXITCODE = $code
    $lines = @(Convert-NativeOutputToLines $raw)
    return @{
        ExitCode = $code
        Output   = $lines
        Text     = ($lines -join "`n")
    }
}

function Normalize-DriveLetter {
    param([string]$Value)
    $text = ("$Value").Trim()
    if ($text -match '^([A-Za-z])(?::.*)?$') {
        return $Matches[1].ToUpper()
    }
    return $null
}

function Convert-ToShSingleQuoted {
    param([string]$Value)
    # Used only for the fixed bridge path and drive spec, neither of which can
    # contain a single quote. Keep shell quoting intentionally simple here.
    if ($Value.Contains("'")) { throw "Unexpected single quote in bridge shell value" }
    return "'" + $Value + "'"
}

function Get-RequiredRelativePath {
    param([string]$Path, [string]$Letter)
    $text = ("$Path").Trim()
    if (-not $text) { return "" }
    if ($text -notmatch '^([A-Za-z]):[\\/]?(.*)$') {
        throw "RequiredPath must be an absolute Windows drive path. Received: $Path"
    }
    if ($Matches[1].ToUpper() -ne $Letter.ToUpper()) {
        throw "RequiredPath is on drive $($Matches[1].ToUpper()):, not ${Letter}:"
    }
    return (($Matches[2] -replace '\\', '/').Trim('/'))
}


function Get-ExactMountPlan {
    param([string]$Path, [string]$Letter)
    $text = ("$Path").Trim()
    if (-not $text) { return $null }
    $norm = $text -replace '/', '\\'
    if ($norm -notmatch '^([A-Za-z]):[\\/](.*)$') { return $null }
    if ($Matches[1].ToUpper() -ne $Letter.ToUpper()) { return $null }

    $item = $null
    try { $item = Get-Item -LiteralPath $norm -Force -ErrorAction Stop } catch { return $null }
    $source = if ($item.PSIsContainer) { [string]$item.FullName } else { [string]$item.DirectoryName }
    if (-not $source) { return $null }

    $sourceNorm = $source -replace '/', '\\'
    if ($sourceNorm -notmatch '^([A-Za-z]):[\\/]?(.*)$') { return $null }
    $sourceRel = (($Matches[2] -replace '\\', '/').Trim('/'))
    $lower = $Letter.ToLower()
    $target = if ($sourceRel) { "/host/$lower/$sourceRel" } else { "/host/$lower" }
    $probeRelative = if ($item.PSIsContainer) { "" } else { [string]$item.Name }

    return @{
        source = $source
        target = $target
        probe_relative = $probeRelative
        selected_is_file = (-not [bool]$item.PSIsContainer)
    }
}

function Get-RootSentinelRelativePath {
    param([string]$Letter)
    $rootPath = "${Letter}:\"
    try {
        $item = Get-ChildItem -LiteralPath $rootPath -Force -ErrorAction Stop |
            Where-Object { $_.Name -notmatch '\$' } |
            Select-Object -First 1
        if ($item) { return [string]$item.Name }
    }
    catch { }
    return ""
}

function Get-ApiImage {
    param([string]$Preferred)
    if ($Preferred) { return $Preferred }
    try {
        $psRun = Invoke-NativeCapture -FilePath 'docker' -ArgumentList @('ps', '--filter', 'label=com.docker.compose.service=api', '--format', '{{.ID}}')
        $apiId = if ($psRun.ExitCode -eq 0 -and $psRun.Output.Count) { ("$($psRun.Output[0])").Trim() } else { '' }
        if ($apiId) {
            $imgRun = Invoke-NativeCapture -FilePath 'docker' -ArgumentList @('inspect', '--format', '{{.Image}}', $apiId)
            $image = if ($imgRun.ExitCode -eq 0 -and $imgRun.Output.Count) { ("$($imgRun.Output[0])").Trim() } else { '' }
            if ($image) { return $image }
        }
    }
    catch { }
    # The split-stack API image name changed from rag_new2-api. Before trying
    # an old hardcoded tag, use a locally available Python-based project image
    # (or the official Python image, if already cached). Never pull during a
    # forensic drive probe: a download failure is unrelated to drive access.
    try {
        $imgList = Invoke-NativeCapture -FilePath 'docker' -ArgumentList @('image', 'ls', '--format', '{{.Repository}}:{{.Tag}}')
        if ($imgList.ExitCode -eq 0) {
            foreach ($prefix in @('aetheris-forensic-api', 'rag_new2-api', 'aetheris-forensic', 'aetheris-mobile-android-api', 'aetheris-mobile-ios-api', 'python')) {
                $matches = @($imgList.Output | Where-Object { "$_" -match ('^' + [regex]::Escape($prefix) + '(:|-)') })
                if ($matches.Count) { return ([string]$matches[0]).Trim() }
            }
        }
    }
    catch { }
    return "rag_new2-api"
}

function Test-WindowsLetterHasFiles {
    param([string]$Letter)
    $L = Normalize-DriveLetter $Letter
    if (-not $L) { return $false }
    try {
        return [bool](Get-ChildItem -LiteralPath "${L}:\" -Force -ErrorAction Stop | Select-Object -First 1)
    }
    catch {
        return $false
    }
}

# A dead Docker Desktop letter share (ENODEV / "No such device") is not the same
# as a missing disk. Only that one letter is detached and remounted read-only.
# Healthy letters are left alone, and /mnt/host itself is never unmounted.
function Repair-StaleWindowsLetter {
    param(
        [Parameter(Mandatory = $true)][string]$Letter,
        [string]$RelativePath = ""
    )
    $lower = $Letter.ToLowerInvariant()
    $relative = (($RelativePath -replace '\\', '/').Trim('/'))
    $shell = @'
set -eu
LETTER="$1"
LOWER="$2"
REL="$3"
is_mount() {
  grep -q " $1 " /proc/self/mountinfo 2>/dev/null
}
readable() {
  ls -d "$1" >/dev/null 2>&1
}
paths="/mnt/host/${LOWER} /tmp/docker-desktop-root/mnt/host/${LOWER} /tmp/docker-desktop-root/run/desktop/mnt/host/${LOWER}"
healthy=0
total=0
for mp in $paths; do
  total=$((total + 1))
  if is_mount "$mp" && readable "$mp"; then
    healthy=$((healthy + 1))
  fi
done
if [ "$healthy" -eq "$total" ]; then
  echo "letter already readable"
  exit 0
fi
for mp in $paths; do
  if ! is_mount "$mp"; then
    continue
  fi
  if readable "$mp"; then
    continue
  fi
  i=0
  while [ "$i" -lt 8 ]; do
    i=$((i + 1))
    if ! is_mount "$mp"; then
      break
    fi
    umount -l "$mp" || true
  done
done
for mp in $paths; do
  if is_mount "$mp" && readable "$mp"; then
    continue
  fi
  mkdir -p "$mp"
  mount -t drvfs -o ro,metadata,uid=0,gid=0 "${LETTER}:" "$mp"
done
check="/mnt/host/${LOWER}"
if [ -n "$REL" ]; then
  check="${check}/${REL}"
fi
ls -d "$check" >/dev/null
dpid=""
for proc in /proc/[0-9]*; do
  cmd=$(tr "\0" " " < "$proc/cmdline" 2>/dev/null || true)
  case "$cmd" in
    /usr/local/bin/dockerd\ *) dpid=${proc#/proc/}; break ;;
  esac
done
if [ -n "$dpid" ] && command -v nsenter >/dev/null 2>&1; then
  dockcheck="/run/desktop/mnt/host/${LOWER}"
  if [ -n "$REL" ]; then
    dockcheck="${dockcheck}/${REL}"
  fi
  nsenter -t "$dpid" -m -- ls -d "$dockcheck" >/dev/null
fi
echo "remounted ${LETTER}: read-only"
'@
    $shell = $shell -replace "`r", ""
    try {
        $run = Invoke-NativeCapture -FilePath 'wsl.exe' -ArgumentList @(
            '-d', 'docker-desktop', '-u', 'root', '--', 'sh', '-s', '--', $Letter, $lower, $relative
        ) -StdinText $shell
        return @{
            ok     = ($run.ExitCode -eq 0)
            exit   = $run.ExitCode
            output = $run.Text
        }
    }
    catch {
        return @{ ok = $false; exit = -1; output = $_.Exception.Message }
    }
}


function Test-DockerSource {
    param(
        [Parameter(Mandatory = $true)][string]$Source,
        [Parameter(Mandatory = $true)][string]$Image,
        [string]$RelativePath = ""
    )
    $relBytes = [System.Text.Encoding]::UTF8.GetBytes(("$RelativePath"))
    $relB64 = [Convert]::ToBase64String($relBytes)
    # Empty base64 is omitted from docker argv on Windows, which crashed
    # sys.argv[1] and made a working G: bind look like a failed probe.
    if (-not $relB64) { $relB64 = 'Cg==' }
    $code = @'
import base64, pathlib, sys
root = pathlib.Path('/probe')
arg = sys.argv[1] if len(sys.argv) > 1 else ''
rel = base64.b64decode(arg).decode('utf-8', errors='strict').replace('\\', '/').strip('/') if arg else ''
if rel == '\n':
    rel = ''
target = root
if rel:
    for part in [p for p in rel.split('/') if p]:
        target = target / part
ok = root.is_dir() and target.exists()
if ok and target.is_dir() and not rel:
    # An empty Docker Desktop stub is NOT a successfully mounted evidence disk.
    ok = next(target.iterdir(), None) is not None
raise SystemExit(0 if ok else 41)
'@

    # IMPORTANT: resolve native Windows binds with the Windows Docker client.
    # Never create local-driver volumes for Docker Desktop's /mnt/host/g,
    # /run/desktop/mnt/host/g, etc. Those are aliases of the SAME broken
    # device; Docker volume create accepts an unusable device, and the first
    # container that attaches it fails with "no such device". Worse, it leaves
    # orphan aetheris_drive_probe_* volumes if the daemon becomes unavailable.
    # A verified Linux/WSL source is probed separately, from the SAME WSL
    # distribution, by Test-DockerSourceViaWsl below.
    try {
        $run = Invoke-NativeCapture -FilePath 'docker' -ArgumentList @(
            'run', '--rm', '--network', 'none', '--pull', 'never',
            '--entrypoint', 'python',
            '--mount', "type=bind,source=$Source,target=/probe,readonly",
            $Image, '-c', $code, $relB64
        )
        return @{
            ok     = ($run.ExitCode -eq 0)
            exit   = $run.ExitCode
            output = $run.Text
        }
    }
    catch {
        return @{
            ok     = $false
            exit   = -1
            output = $_.Exception.Message
        }
    }
}

function Get-WslDistros {
    # IMPORTANT (Windows PowerShell 5.1): avoid New-Object Generic List + @($list).
    # That combination can throw System.ArgumentException: "Argument types do not match".
    # Plain PowerShell arrays/hashtables are reliable in both Windows PowerShell 5.1
    # and PowerShell 7 and the distro list is tiny, so they are the safest choice.
    $ordered = @()
    $seen = @{}

    if ($env:AETHERIS_WSL_DISTRO) {
        $d = $env:AETHERIS_WSL_DISTRO.Trim()
        if ($d) {
            $key = $d.ToLowerInvariant()
            if (-not $seen.ContainsKey($key)) {
                $seen[$key] = $true
                $ordered += $d
            }
        }
    }

    try {
        $listRun = Invoke-NativeCapture -FilePath 'wsl.exe' -ArgumentList @('--list', '--quiet')
        foreach ($line in @($listRun.Output)) {
            $d = (("$line") -replace "`0", "").Trim()
            if (-not $d) { continue }
            if ($d -match '^docker-desktop-data$') { continue }
            # Prefer a normal distro; Docker Desktop itself is attempted last.
            if ($d -notmatch '^docker-desktop$') {
                $key = $d.ToLowerInvariant()
                if (-not $seen.ContainsKey($key)) {
                    $seen[$key] = $true
                    $ordered += $d
                }
            }
        }
        foreach ($line in @($listRun.Output)) {
            $d = (("$line") -replace "`0", "").Trim()
            if ($d -eq 'docker-desktop') {
                $key = $d.ToLowerInvariant()
                if (-not $seen.ContainsKey($key)) {
                    $seen[$key] = $true
                    $ordered += $d
                }
            }
        }
    }
    catch { }

    return $ordered
}

function Mount-DockerDesktopPrivateLetter {
    param(
        [Parameter(Mandatory = $true)][string]$Letter,
        [string]$RelativePath = ""
    )
    # Docker Desktop's /mnt/host/<letter> 9p share is what `source: G:/` uses.
    # On a drive attached after Desktop started, that share is ENODEV, and a
    # later Compose bind of G:/ puts the dead share back. DrvFs is mounted in
    # the docker-desktop init namespace (dockerd itself has no drvfs), then
    # bind-mounted into dockerd at a path the file-sharing agent does not own.
    $lower = $Letter.ToLowerInvariant()
    $relative = (($RelativePath -replace '\\', '/').Trim('/'))
    $relativeB64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($relative))
    $shell = @'
:
set -eu
LETTER="$1"
LOWER="$2"
B64="$3"
MP="/mnt/aetheris-host-drives/${LOWER}"
RELFILE=/tmp/aetheris-rel-$$
CHECKFILE=/tmp/aetheris-check-$$
: > "$RELFILE"
if [ -n "$B64" ]; then
  printf '%s' "$B64" | base64 -d > "$RELFILE"
fi
printf '%s' "$MP" > "$CHECKFILE"
if [ -s "$RELFILE" ]; then
  printf '/' >> "$CHECKFILE"
  cat "$RELFILE" >> "$CHECKFILE"
fi
mkdir -p "$MP"
if grep -qs " ${MP} " /proc/mounts 2>/dev/null; then
  if ! ls -d "$MP" >/dev/null 2>&1; then
    umount -l "$MP" >/dev/null 2>&1 || true
  fi
fi
if ! ls -d "$MP" >/dev/null 2>&1; then
  mkdir -p "$MP"
fi
if ! grep -qs " ${MP} " /proc/mounts 2>/dev/null; then
  mount -t drvfs -o ro,metadata,uid=0,gid=0 "${LETTER}:" "$MP"
fi
printf '\0' >> "$CHECKFILE"
cat "$CHECKFILE" | xargs -0 ls -d >/dev/null
dpid=""
for proc in /proc/[0-9]*; do
  cmd=$(tr "\0" " " < "$proc/cmdline" 2>/dev/null || true)
  case "$cmd" in
    *dockerd*) dpid=${proc#/proc/}; break ;;
  esac
done
if [ -z "$dpid" ]; then
  echo "dockerd not found"
  exit 1
fi
nsenter -t "$dpid" -m -- mkdir -p "$MP"
if ! nsenter -t "$dpid" -m -- ls -d "$MP" >/dev/null 2>&1; then
  nsenter -t "$dpid" -m -- umount -l "$MP" >/dev/null 2>&1 || true
  nsenter -t "$dpid" -m -- mkdir -p "$MP"
  nsenter -t "$dpid" -m -- mount --bind "/proc/1/root${MP}" "$MP"
fi
nsenter -t "$dpid" -m -- ls -d "$MP" >/dev/null
echo "mounted ${LETTER}: read-only at ${MP}"
'@
    $shell = $shell.TrimStart([char]0xFEFF) -replace "`r", ""
    try {
        $run = Invoke-NativeCapture -FilePath 'wsl.exe' -ArgumentList @(
            '-d', 'docker-desktop', '-u', 'root', '--', 'sh', '-s', '--', $Letter, $lower, $relativeB64
        ) -StdinText $shell
        return @{
            ok          = ($run.ExitCode -eq 0)
            exit        = $run.ExitCode
            output      = $run.Text
            source      = "/mnt/aetheris-host-drives/$lower"
            mount_point = "/mnt/aetheris-host-drives/$lower"
        }
    }
    catch {
        return @{
            ok          = $false
            exit        = -1
            output      = $_.Exception.Message
            source      = "/mnt/aetheris-host-drives/$lower"
            mount_point = "/mnt/aetheris-host-drives/$lower"
        }
    }
}

function Try-PrivateDriveResult {
    param(
        [Parameter(Mandatory = $true)][string]$Letter,
        [string]$RelativePath = "",
        [string]$Image = "",
        [object[]]$Attempts = @()
    )
    $mounted = Mount-DockerDesktopPrivateLetter -Letter $Letter -RelativePath $RelativePath
    $Attempts += [pscustomobject]@{
        source = $mounted.source
        mode   = "docker-drvfs"
        ok     = [bool]$mounted.ok
        detail = $mounted.output
    }
    if (-not $mounted.ok) {
        return @{ ok = $false; attempts = $Attempts }
    }
    $probe = Test-DockerSource -Source $mounted.source -Image $Image -RelativePath $RelativePath
    $Attempts += [pscustomobject]@{
        source = $mounted.source
        mode   = "docker-drvfs-probe"
        ok     = [bool]$probe.ok
        detail = $probe.output
    }
    if (-not $probe.ok) {
        return @{ ok = $false; attempts = $Attempts }
    }
    $lower = $Letter.ToLowerInvariant()
    Write-Result @{
        ok             = $true
        drive          = $Letter
        source         = $mounted.source
        mode           = "docker-drvfs"
        mount_target   = "/host/$lower"
        source_scope   = "drive"
        required_path  = $(if ($script:normalizedRequired) { $script:normalizedRequired } else { $null })
        probe_relative = $RelativePath
        api_image      = $Image
        attempts       = $Attempts
        message        = "Docker Desktop could not share ${Letter}:. The drive was mounted read-only for the engine. No evidence was copied."
    }
    exit 0
}

function Ensure-WslDrvFsBridge {
    param(
        [Parameter(Mandatory = $true)][string]$Distro,
        [Parameter(Mandatory = $true)][string]$Letter,
        [string]$RelativePath = ""
    )
    $lower = $Letter.ToLower()
    $mountPoint = "/mnt/aetheris-host-drives/$lower"
    $qMount = Convert-ToShSingleQuoted $mountPoint
    $qDrive = Convert-ToShSingleQuoted "${Letter}:"

    # Rebind the current Windows drive letter inside the selected WSL distro.
    # v4.4 intentionally does NOT use /mnt/wsl as a daemon-local handoff: Docker
    # Desktop isolates docker-desktop from user distros. Instead Docker Compose
    # is later executed from this same WSL-integrated distro, which is the
    # supported path for bind-mounting Linux/WSL files into Linux containers.
    $shell = @"
set -eu
mkdir -p $qMount
if grep -qs " $mountPoint " /proc/mounts 2>/dev/null; then
  umount -l $qMount >/dev/null 2>&1 || true
fi
bridge_mode=ro
if mount -t drvfs -o metadata,ro $qDrive $qMount >/dev/null 2>&1; then
  bridge_mode=ro
elif mount -t drvfs -o ro $qDrive $qMount >/dev/null 2>&1; then
  bridge_mode=ro
elif mount -t drvfs -o metadata $qDrive $qMount >/dev/null 2>&1; then
  bridge_mode=rw
else
  mount -t drvfs $qDrive $qMount >/dev/null 2>&1
  bridge_mode=rw
fi
test -d $qMount
printf '__AETHERIS_BRIDGE_MODE__=%s\n' "`$bridge_mode"
"@

    try {
        $shRun = Invoke-NativeCapture -FilePath 'wsl.exe' -ArgumentList @('-d', $Distro, '-u', 'root', '--', 'sh', '-lc', $shell)
        $outText = $shRun.Text
        $bridgeReadOnly = ($outText -match '__AETHERIS_BRIDGE_MODE__=ro')
        return @{
            ok          = ($shRun.ExitCode -eq 0)
            distro      = $Distro
            mount_point = $mountPoint
            read_only   = $bridgeReadOnly
            output      = $outText
        }
    }
    catch {
        return @{
            ok          = $false
            distro      = $Distro
            mount_point = $mountPoint
            read_only   = $false
            output      = $_.Exception.Message
        }
    }
}


function Test-WslDockerIntegration {
    param([Parameter(Mandatory = $true)][string]$Distro)
    try {
        $info = Invoke-NativeCapture -FilePath 'wsl.exe' -ArgumentList @('-d', $Distro, '--exec', 'docker', 'info', '--format', '{{.ServerVersion}}')
        if ($info.ExitCode -ne 0) {
            return @{
                ok = $false
                distro = $Distro
                detail = $info.Text
            }
        }
        $compose = Invoke-NativeCapture -FilePath 'wsl.exe' -ArgumentList @('-d', $Distro, '--exec', 'docker', 'compose', 'version')
        if ($compose.ExitCode -ne 0) {
            return @{
                ok = $false
                distro = $Distro
                detail = $compose.Text
            }
        }
        return @{
            ok = $true
            distro = $Distro
            detail = (($info.Text, $compose.Text) -join "`n")
        }
    }
    catch {
        return @{ ok = $false; distro = $Distro; detail = $_.Exception.Message }
    }
}

function Test-DockerSourceViaWsl {
    param(
        [Parameter(Mandatory = $true)][string]$Distro,
        [Parameter(Mandatory = $true)][string]$Source,
        [Parameter(Mandatory = $true)][string]$Image,
        [string]$RelativePath = ""
    )
    $relBytes = [System.Text.Encoding]::UTF8.GetBytes(("$RelativePath"))
    $relB64 = [Convert]::ToBase64String($relBytes)
    # Empty base64 is omitted from docker argv on Windows, which crashed
    # sys.argv[1] and made a working G: bind look like a failed probe.
    if (-not $relB64) { $relB64 = 'Cg==' }
    $code = @'
import base64, pathlib, sys
root = pathlib.Path('/probe')
arg = sys.argv[1] if len(sys.argv) > 1 else ''
rel = base64.b64decode(arg).decode('utf-8', errors='strict').replace('\\', '/').strip('/') if arg else ''
if rel == '\n':
    rel = ''
target = root
if rel:
    for part in [p for p in rel.split('/') if p]:
        target = target / part
ok = root.is_dir() and target.exists()
if ok and target.is_dir() and not rel:
    # An empty Docker Desktop stub is NOT a successfully mounted evidence disk.
    ok = next(target.iterdir(), None) is not None
raise SystemExit(0 if ok else 41)
'@
    $mountSpec = "type=bind,source=$Source,target=/probe,readonly"
    try {
        $run = Invoke-NativeCapture -FilePath 'wsl.exe' -ArgumentList @(
            '-d', $Distro, '--exec', 'docker', 'run', '--rm', '--network', 'none', '--pull', 'never', '--entrypoint', 'python',
            '--mount', $mountSpec, $Image, '-c', $code, $relB64
        )
        return @{
            ok = ($run.ExitCode -eq 0)
            exit = $run.ExitCode
            output = $run.Text
        }
    }
    catch {
        return @{ ok = $false; exit = -1; output = $_.Exception.Message }
    }
}

function Get-AttemptSummary {
    param([object[]]$Attempts)
    $parts = @()
    foreach ($a in @($Attempts)) {
        if ($a.ok) { continue }
        $label = "mode=$($a.mode) source=$($a.source)"
        if ($a.distro) { $label += " distro=$($a.distro)" }
        $detail = ("$($a.detail)").Trim()
        if ($detail -match 'no such device|error evaluating symlinks|invalid mount config') {
            $detail = 'Docker Desktop reports unavailable device/mount (ENODEV)'
        }
        elseif ($detail.Length -gt 180) { $detail = $detail.Substring(0, 180) }
        if ($detail) { $label += " detail=$detail" }
        $parts += $label
    }
    # Report the decisive failures only; the UI must not print hundreds of
    # lines of identical Docker Desktop "no such device" errors.
    if ($parts.Count -gt 2) { $parts = @($parts | Select-Object -First 2) }
    return ($parts -join ' | ')
}

function Write-Result {
    param([hashtable]$Result)
    $json = $Result | ConvertTo-Json -Depth 8 -Compress
    if ($OutputFile) {
        $parent = Split-Path -Parent $OutputFile
        if ($parent -and -not (Test-Path -LiteralPath $parent)) {
            New-Item -ItemType Directory -Force -Path $parent | Out-Null
        }
        [System.IO.File]::WriteAllText($OutputFile, $json, [System.Text.UTF8Encoding]::new($false))
    }
    Write-Output $json
}

$letter = Normalize-DriveLetter $DriveLetter
if (-not $letter) {
    Write-Result @{
        ok = $false; drive = $DriveLetter; error = "Invalid drive letter: $DriveLetter"; mode = "none"; source = ""
    }
    exit 2
}

$windowsRoot = "${letter}:\"
if (-not (Test-Path -LiteralPath $windowsRoot)) {
    Write-Result @{
        ok = $false; drive = $letter; error = "Windows cannot see drive ${letter}:"; mode = "none"; source = ""
    }
    exit 3
}

$normalizedRequired = ("$RequiredPath").Trim()
if ($normalizedRequired) {
    $normalizedRequired = $normalizedRequired -replace '/', '\\'
    if (-not (Test-Path -LiteralPath $normalizedRequired)) {
        Write-Result @{
            ok = $false; drive = $letter; error = "Windows cannot see the selected path: $normalizedRequired"; mode = "none"; source = ""
        }
        exit 4
    }
}

try {
    $relative = Get-RequiredRelativePath -Path $normalizedRequired -Letter $letter
}
catch {
    Write-Result @{
        ok = $false; drive = $letter; error = $_.Exception.Message; mode = "none"; source = ""
    }
    exit 5
}
if (-not $normalizedRequired -or -not $relative) {
    $relative = Get-RootSentinelRelativePath -Letter $letter
}

$image = Get-ApiImage -Preferred $ApiImage
$lower = $letter.ToLower()
$attempts = @()

# A narrow bind is only for a drive Windows cannot list at the root, such as a
# stale removable disk whose G:\ is an empty stub. Applying it to a normal
# drive replaces /host/e with one folder and recreates every API. Folder
# selection then fails with 502 while extraction is trying to start.
$driveRootHasFiles = Test-WindowsLetterHasFiles -Letter $letter
if (-not $ForceWslBridge -and $normalizedRequired -and -not $driveRootHasFiles) {
    $exactPlan = Get-ExactMountPlan -Path $normalizedRequired -Letter $letter
    if ($exactPlan) {
        $exactProbe = Test-DockerSource -Source ([string]$exactPlan.source) -Image $image -RelativePath ([string]$exactPlan.probe_relative)
        $attempts += [pscustomobject]@{
            source = [string]$exactPlan.source
            mode = "docker-exact-path"
            target = [string]$exactPlan.target
            ok = [bool]$exactProbe.ok
            detail = $exactProbe.output
        }
        if ($exactProbe.ok) {
            Write-Result @{
                ok             = $true
                drive          = $letter
                source         = [string]$exactPlan.source
                mode           = "docker-exact-path"
                mount_target   = [string]$exactPlan.target
                source_scope   = "selected-folder"
                required_path  = $normalizedRequired
                probe_relative = [string]$exactPlan.probe_relative
                api_image      = $image
                attempts       = $attempts
                message        = "Docker can read the selected ${letter}: evidence folder directly; mounting only that folder read-only."
            }
            exit 0
        }
    }
}

if ($RemountOnly) {
    # Do not unmount Docker Desktop's internal /mnt/host/ 9p/virtiofs mounts.
    # Modifying them from inside docker-desktop can disrupt unrelated mounts
    # and cannot repair a Windows USB device that Docker Desktop cannot see.
    $readOnlyProbe = Test-DockerSource -Source "${letter}:/" -Image $image -RelativePath $relative
    Write-Result @{
        ok     = [bool]$readOnlyProbe.ok
        drive  = $letter
        source = $(if ($readOnlyProbe.ok) { "${letter}:/" } else { '' })
        mode   = $(if ($readOnlyProbe.ok) { 'docker-direct' } else { 'unavailable' })
        error  = $(if ($readOnlyProbe.ok) { $null } else { "Docker Desktop cannot bind ${letter}:. Reconnect the device and restart Docker Desktop after active jobs finish; no daemon-internal mount was modified." })
    }
    exit $(if ($readOnlyProbe.ok) { 0 } else { 31 })
}

# Docker Desktop's letter share is dead. Mount the Windows drive read-only
# where Compose cannot replace it with that share.
if ($PrivateDrive) {
    $privateTried = $true
    $private = Try-PrivateDriveResult -Letter $letter -RelativePath $relative -Image $image -Attempts $attempts
    $attempts = @($private.attempts)
    # A failed private mount must not fall through to source G:/. Compose
    # would then reinstall Docker Desktop's dead letter share.
    $summary = Get-AttemptSummary -Attempts $attempts
    $errorText = "Windows can see ${letter}:, but the read-only engine mount failed. No evidence was copied or marked processed."
    if ($summary) { $errorText += " Diagnostic: $summary" }
    Write-Result @{
        ok            = $false
        drive         = $letter
        source        = ""
        mode          = "none"
        required_path = $(if ($normalizedRequired) { $normalizedRequired } else { $null })
        attempts      = $attempts
        error         = $errorText
    }
    exit 30
}

# Read the Windows letter itself first. A compose bind of G:/ is the path
# Docker Desktop keeps after a USB replug. /mnt/host/g is an internal stub
# that becomes "no such device" and must not win while the letter is readable.
if (-not $ForceWslBridge) {
    # All daemon aliases point to the same Docker Desktop G: share. After a
    # native G:/ failure, retrying those aliases is not a new data path and
    # creates misleading errors and temporary Docker volumes. Try one direct
    # bind, then fall back to verified Docker Desktop WSL Integration.
    $directSources = @( "${letter}:/" )

    foreach ($source in $directSources) {
        $probe = Test-DockerSource -Source $source -Image $image -RelativePath $relative
        $attempts += [pscustomobject]@{ source = $source; mode = "direct"; ok = [bool]$probe.ok; detail = $probe.output }
        if ($probe.ok) {
            if ($source -match '^[A-Za-z]:[/\\]?$') {
                $source = "{0}:/" -f $source.Substring(0, 1).ToUpper()
            }
            Write-Result @{
                ok             = $true
                drive          = $letter
                source         = $source
                mode           = "docker-direct"
                mount_target   = "/host/$lower"
                source_scope   = "drive"
                required_path  = $(if ($normalizedRequired) { $normalizedRequired } else { $null })
                probe_relative = $relative
                api_image      = $image
                attempts       = $attempts
                message        = "Docker can read ${letter}: directly."
            }
            exit 0
        }
    }
}

# Some external SSD/HDD/USB bridges refuse a whole-letter bind but permit a
# narrowly scoped folder bind. Do this ONLY for the selected evidence directory;
# don't build a fake /host/g from a stale root or create Docker local volumes.
# The early exact-path probe above already covered an empty/unreadable root.
if (-not $ForceWslBridge -and $normalizedRequired -and $driveRootHasFiles) {
    $exactPlan = Get-ExactMountPlan -Path $normalizedRequired -Letter $letter
    if ($exactPlan) {
        $exactProbe = Test-DockerSource -Source ([string]$exactPlan.source) -Image $image -RelativePath ([string]$exactPlan.probe_relative)
        $attempts += [pscustomobject]@{
            source = [string]$exactPlan.source
            mode = "docker-exact-path"
            target = [string]$exactPlan.target
            ok = [bool]$exactProbe.ok
            detail = $exactProbe.output
        }
        if ($exactProbe.ok) {
            Write-Result @{
                ok = $true
                drive = $letter
                source = [string]$exactPlan.source
                mode = "docker-exact-path"
                mount_target = [string]$exactPlan.target
                source_scope = "selected-folder"
                required_path = $normalizedRequired
                probe_relative = [string]$exactPlan.probe_relative
                api_image = $image
                attempts = $attempts
                message = "Selected evidence directory is verified directly from Docker, read-only; full-drive sharing was unavailable."
            }
            exit 0
        }
    }
}

# Direct and exact-folder binds both use Docker Desktop's letter share. When
# that share is a dead device, retrying the same bind cannot succeed. Detach
# only this letter and mount it read-only, then probe once more.
$staleShare = $false
$privateTried = $false
foreach ($attempt in @($attempts)) {
    if (-not $attempt.ok -and "$($attempt.detail)" -match 'no such device|ENODEV|error evaluating symlinks|invalid mount config|bind source path does not exist') {
        $staleShare = $true
        break
    }
}
if (-not $ForceWslBridge -and $staleShare) {
    # Private DrvFs first. Repairing /mnt/host and returning source G:/ lets
    # the next Compose bind put the dead 9p share back over the letter.
    $privateTried = $true
    $private = Try-PrivateDriveResult -Letter $letter -RelativePath $relative -Image $image -Attempts $attempts
    $attempts = @($private.attempts)
    $repair = Repair-StaleWindowsLetter -Letter $letter -RelativePath $relative
    $attempts += [pscustomobject]@{
        source = "${letter}:/"
        mode   = "stale-letter-repair"
        ok     = [bool]$repair.ok
        detail = $repair.output
    }
    if ($repair.ok) {
        $probe = Test-DockerSource -Source "${letter}:/" -Image $image -RelativePath $relative
        $attempts += [pscustomobject]@{ source = "${letter}:/"; mode = "direct"; ok = [bool]$probe.ok; detail = $probe.output }
        if ($probe.ok) {
            Write-Result @{
                ok             = $true
                drive          = $letter
                source         = "${letter}:/"
                mode           = "docker-direct"
                mount_target   = "/host/$lower"
                source_scope   = "drive"
                required_path  = $(if ($normalizedRequired) { $normalizedRequired } else { $null })
                probe_relative = $relative
                api_image      = $image
                attempts       = $attempts
                message        = "Docker Desktop had a dead ${letter}: share. It was remounted read-only and the selected evidence path is readable. No evidence was copied."
            }
            exit 0
        }
        if ($normalizedRequired) {
            $exactPlan = Get-ExactMountPlan -Path $normalizedRequired -Letter $letter
            if ($exactPlan) {
                $exactProbe = Test-DockerSource -Source ([string]$exactPlan.source) -Image $image -RelativePath ([string]$exactPlan.probe_relative)
                $attempts += [pscustomobject]@{
                    source = [string]$exactPlan.source
                    mode   = "docker-exact-path"
                    target = [string]$exactPlan.target
                    ok     = [bool]$exactProbe.ok
                    detail = $exactProbe.output
                }
                if ($exactProbe.ok) {
                    Write-Result @{
                        ok             = $true
                        drive          = $letter
                        source         = [string]$exactPlan.source
                        mode           = "docker-exact-path"
                        mount_target   = [string]$exactPlan.target
                        source_scope   = "selected-folder"
                        required_path  = $normalizedRequired
                        probe_relative = [string]$exactPlan.probe_relative
                        api_image      = $image
                        attempts       = $attempts
                        message        = "Docker Desktop had a dead ${letter}: share. The selected evidence folder is readable after a read-only remount. No evidence was copied."
                    }
                    exit 0
                }
            }
        }
    }
}

# Docker Desktop isolates its internal docker-desktop distribution from normal
# user distributions. A bind source mounted in Ubuntu is therefore not safely
# usable as a daemon-local path from the Windows docker.exe client. The reliable
# fallback is to use a WSL2 distribution with Docker Desktop WSL Integration
# enabled and run the Docker bind probe from that distribution. Docker Desktop
# then creates its supported docker-desktop-bind-mounts bridge for that distro.
$distros = @(Get-WslDistros)
if (-not $distros.Count) {
    Write-Result @{
        ok            = $false
        drive         = $letter
        source        = ""
        mode          = "none"
        required_path = $(if ($normalizedRequired) { $normalizedRequired } else { $null })
        attempts      = $attempts
        error         = "Docker cannot read ${letter}: directly and no WSL2 user distribution is available. Install/enable a WSL2 distribution, enable Docker Desktop > Settings > Resources > WSL Integration for it, then retry."
    }
    exit 20
}

$integrationAvailable = $false
foreach ($distro in $distros) {
    if ($distro -match '^docker-desktop(?:-data)?$') { continue }

    $integration = Test-WslDockerIntegration -Distro $distro
    $attempts += [pscustomobject]@{
        source = "docker-cli"
        mode = "wsl-integration"
        distro = $distro
        ok = [bool]$integration.ok
        detail = $integration.detail
    }
    if (-not $integration.ok) { continue }
    $integrationAvailable = $true

    # First try WSL's normal automatic Windows-drive mount. This avoids any
    # remount and is sufficient on most machines, even when Windows docker.exe
    # exposes the same external drive as an empty directory.
    $autoMount = "/mnt/$lower"
    $autoProbe = Test-DockerSourceViaWsl -Distro $distro -Source $autoMount -Image $image -RelativePath $relative
    $attempts += [pscustomobject]@{
        source = $autoMount
        mode = "wsl-compose-auto"
        distro = $distro
        ok = [bool]$autoProbe.ok
        detail = $autoProbe.output
    }
    if ($autoProbe.ok) {
        Write-Result @{
            ok             = $true
            drive          = $letter
            source         = $autoMount
            mode           = "wsl-compose"
            mount_target   = "/host/$lower"
            source_scope   = "drive"
            wsl_distro     = $distro
            wsl_mount      = $autoMount
            wsl_bridge_read_only = $false
            required_path  = $(if ($normalizedRequired) { $normalizedRequired } else { $null })
            probe_relative = $relative
            api_image      = $image
            attempts       = $attempts
            message        = "Docker direct sharing was stale; ${letter}: is readable through Docker Desktop WSL Integration using $distro."
        }
        exit 0
    }

    # If /mnt/<letter> is absent/stale, explicitly bind the Windows drive into
    # this WSL distro with DrvFs and probe Docker from the SAME distro. This is
    # intentionally different from the old daemon-local-volume workaround.
    $bridge = Ensure-WslDrvFsBridge -Distro $distro -Letter $letter -RelativePath $relative
    $attempts += [pscustomobject]@{
        source = $bridge.mount_point
        mode = "wsl-provision"
        distro = $distro
        ok = [bool]$bridge.ok
        bridge_read_only = [bool]$bridge.read_only
        detail = $bridge.output
    }
    if (-not $bridge.ok) { continue }

    $mountPoint = [string]$bridge.mount_point
    $bridgeProbe = Test-DockerSourceViaWsl -Distro $distro -Source $mountPoint -Image $image -RelativePath $relative
    $attempts += [pscustomobject]@{
        source = $mountPoint
        mode = "wsl-compose-drvfs"
        distro = $distro
        ok = [bool]$bridgeProbe.ok
        detail = $bridgeProbe.output
    }
    if ($bridgeProbe.ok) {
        Write-Result @{
            ok             = $true
            drive          = $letter
            source         = $mountPoint
            mode           = "wsl-compose"
            mount_target   = "/host/$lower"
            source_scope   = "drive"
            wsl_distro     = $distro
            wsl_mount      = $mountPoint
            wsl_bridge_read_only = [bool]$bridge.read_only
            required_path  = $(if ($normalizedRequired) { $normalizedRequired } else { $null })
            probe_relative = $relative
            api_image      = $image
            attempts       = $attempts
            message        = $(if ($bridge.read_only) {
                "Docker direct sharing was stale; ${letter}: is available through a read-only WSL DrvFs mount and Docker Desktop WSL Integration."
            } else {
                "Docker direct sharing was stale; ${letter}: is available through WSL DrvFs and Docker Desktop WSL Integration. Aetheris container mounts remain read-only."
            })
        }
        exit 0
    }
}

if (-not $privateTried) {
    $private = Try-PrivateDriveResult -Letter $letter -RelativePath $relative -Image $image -Attempts $attempts
    $attempts = @($private.attempts)
}

$summary = Get-AttemptSummary -Attempts $attempts
$evidenceDescription = $(if ($normalizedRequired) { "selected evidence path '$normalizedRequired'" } else { "drive ${letter}:" })
if (-not $integrationAvailable) {
    $errorText = "Windows can access $evidenceDescription, but the Docker Desktop Linux engine cannot bind the drive. Close case processing, reconnect the disk, restart Docker Desktop, then retry the selected folder. If this drive must be used without Docker Desktop direct sharing, enable Docker Desktop WSL Integration for an installed WSL2 distribution. No evidence was copied or marked processed."
}
else {
    $errorText = "Windows can access $evidenceDescription, but neither Docker Desktop direct sharing nor the WSL2 integrated bind probe can access its contents. Reconnect the drive, restart Docker Desktop when jobs are idle, and verify it in a read-only container before processing. No evidence was copied or marked processed."
}
if ($summary) { $errorText += " Diagnostic: $summary" }
Write-Result @{
    ok            = $false
    drive         = $letter
    source        = ""
    mode          = "none"
    required_path = $(if ($normalizedRequired) { $normalizedRequired } else { $null })
    attempts      = $attempts
    error         = $errorText
}
exit 30
