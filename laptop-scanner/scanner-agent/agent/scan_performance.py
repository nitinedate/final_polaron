"""V1.6.6 scan speed profiles, NVT hang learning and stalled-task detection.

Field evidence (jobs 57b12618, 096705e1, d26e3145 on 192.168.0.163): every run
reached 94 % in about 3.5 minutes. Clean runs finished 46 s later (~4 min).
Slow runs spent exactly 324 s per hung NVT (the 320 s plugins_timeout) in a
dependency tail: one hang = +5.5 min, two = +11 min. So the speed work is:

* ``fast`` profile: Nessus/OpenVAS-default socket read timeout (5 s instead of
  10 s), Nessus-default 5 simultaneous checks per host, Nmap "Aggressive"
  (T4) timing, and a learned per-NVT timeout cap for checks that have already
  timed out repeatedly. Every NVT still runs; nothing is removed from scope.
* A stalled-task watchdog that stops a Greenbone task only when it makes no
  progress for far longer than any single NVT may run, and reports the host
  as *incomplete (stalled)*, never as completed.
"""
from __future__ import annotations

import json
import logging
import os
import re
import threading
import time
from pathlib import Path
from typing import Any

log = logging.getLogger("scanner_agent.performance")

PROFILES = ("standard", "fast", "turbo")


def _cpu_count() -> int:
    try:
        return max(1, int(os.cpu_count() or 1))
    except Exception:
        return 1


def turbo_max_checks() -> int:
    """Per-host NVT concurrency for the turbo profile.

    This is the main lever for a *single* IP: host-level concurrency does
    nothing when there is one host, but running many NVTs at once against that
    host does. OpenVAS runs one OS process per concurrent check, so we scale
    with CPUs (default 4x, since NVT checks are I/O/network-bound and spend most
    of their time waiting on the target) and cap it so a small laptop is not
    overwhelmed. Override with TURBO_MAX_CHECKS.
    """
    override = _int_env("TURBO_MAX_CHECKS", 0, 0, 128)
    if override:
        return override
    per_cpu = _int_env("TURBO_CHECKS_PER_CPU", 4, 1, 16)
    hard_cap = _int_env("TURBO_MAX_CHECKS_CAP", 40, 4, 128)
    return max(10, min(hard_cap, _cpu_count() * per_cpu))
_TIMEOUT_RE = re.compile(r"time ?out|timed out|took too long|exceeded|killed", re.I)
# Port scanners and service discovery are never capped: they define coverage.
_NEVER_CAP_OIDS = frozenset({
    "1.3.6.1.4.1.25623.1.0.14259",   # Nmap (NASL wrapper)
    "1.3.6.1.4.1.25623.1.0.100315",  # Ping Host
    "1.3.6.1.4.1.25623.1.0.10330",   # Services (find_service)
    "1.3.6.1.4.1.25623.1.0.900239",  # Check Open TCP Ports
    "1.3.6.1.4.1.25623.1.0.108521",  # Nmap UDP
    "1.3.6.1.4.1.25623.1.0.11219",
})
_NEVER_CAP_NAME_RE = re.compile(
    r"nmap|port ?scan|ping host|^services$|open tcp port|web mirror|crawl|spider", re.I
)


def _int_env(name: str, default: int, lo: int, hi: int) -> int:
    try:
        value = int(str(os.environ.get(name) or default).strip())
    except (TypeError, ValueError):
        value = default
    return max(lo, min(hi, value))


def resolve_profile(request: dict[str, Any] | None = None) -> str:
    """Policy ``performance`` wins, then SCAN_PERFORMANCE, then ``standard``."""
    for raw in ((request or {}).get("performance"), os.environ.get("SCAN_PERFORMANCE")):
        value = str(raw or "").strip().lower()
        if value in PROFILES:
            return value
    return "standard"


def profile_settings(profile: str) -> dict[str, Any]:
    """Engine settings for a profile. ``None`` means "keep the configured value".

    V1.6.7: these are written as *scanner preferences on the scan config*.
    gvmd forwards only max_checks/max_hosts from task preferences; every other
    scanner value comes from the config's SERVER_PREFS or gvmd's global
    defaults (verified in gvmd manage_osp.c / init_preference_iterator).
    """
    if profile not in {"fast", "turbo"}:
        return {"checks_read_timeout": None, "max_checks": None, "nmap_timing": None,
                "hang_caps": False, "plugins_timeout": None}
    hang_on = (os.environ.get("NVT_HANG_CAPS") or "true").strip().lower() in {"1", "true", "yes", "on"}
    if profile == "turbo":
        # Turbo (V1.9.0): maximise per-host NVT concurrency and keep the tail
        # short. Coverage is unchanged - every applicable NVT still runs - but
        # many more run at once and a stuck check is capped sooner so it cannot
        # pin the host at 98%. Aggressive Nmap timing. Best with
        # optimize_test=yes (skip NVTs whose prerequisite ports/services were
        # not found) and enough CPU/RAM on the OpenVAS container.
        timing = (os.environ.get("TURBO_NMAP_TIMING") or "Aggressive").strip()
        return {
            "checks_read_timeout": _int_env("TURBO_CHECKS_READ_TIMEOUT", 5, 2, 30),
            "max_checks": turbo_max_checks(),
            "nmap_timing": None if timing.lower() in {"", "off", "none", "normal"} else timing,
            "hang_caps": hang_on,
            # Shorter per-check ceiling so one slow NVT costs ~2 min instead of
            # 5.5 at the tail. Still well above a normal check's runtime.
            "plugins_timeout": _int_env("TURBO_PLUGINS_TIMEOUT", 180, 30, 3600),
        }
    timing = (os.environ.get("FAST_NMAP_TIMING") or "Aggressive").strip()
    return {
        # OpenVAS default checks_read_timeout and Nessus "network timeout" are both 5 s.
        "checks_read_timeout": _int_env("FAST_CHECKS_READ_TIMEOUT", 5, 3, 30),
        # Nessus default "max simultaneous checks per host" is 5.
        "max_checks": _int_env("FAST_MAX_CHECKS", 5, 1, 10),
        "nmap_timing": None if timing.lower() in {"", "off", "none", "normal"} else timing,
        "hang_caps": hang_on,
        # Per-check limit for ordinary NVTs: Nessus/OpenVAS default 320 s (V1.6.8:
        # no reduction). Checks that already hung repeatedly get NVT_HANG_CAP_SEC.
        "plugins_timeout": _int_env("FAST_PLUGINS_TIMEOUT", 320, 30, 3600),
    }


def ip_deadline_sec(profile: str) -> int:
    """Optional hard per-IP time limit. V1.6.8: OFF (0) unless SCAN_IP_DEADLINE_SEC is set."""
    del profile
    return _int_env("SCAN_IP_DEADLINE_SEC", 0, 0, 86400)


CHECK_SCOPES = ("vulnerability", "all")


def resolve_check_scope(request: dict[str, Any] | None = None) -> str:
    """Which checks run: policy ``check_scope``, then SCAN_CHECK_SCOPE, default vulnerability.

    ``vulnerability``: only checks that can report Critical/High/Medium/Low,
    plus whatever detection those checks depend on (OpenVAS auto-loads
    declared dependencies) and a few cheap host/port reporting checks.
    ``all``: every check in "Full and fast", including informational ones.
    """
    for raw in ((request or {}).get("check_scope"), os.environ.get("SCAN_CHECK_SCOPE")):
        value = str(raw or "").strip().lower()
        if value in CHECK_SCOPES:
            return value
    return "vulnerability"


def fixed_ip_workers() -> int:
    """Fixed number of IPs scanned at once (default 4). 0 = adaptive capacity sizing."""
    return _int_env("SCAN_IP_WORKERS_FIXED", 4, 0, 32)


def _is_cappable(oid: str, name: str) -> bool:
    return bool(oid) and oid not in _NEVER_CAP_OIDS and not _NEVER_CAP_NAME_RE.search(name or "")


class NvtHangRegistry:
    """File-backed record of NVTs that timed out, used to cap repeat offenders.

    Stored as JSON under the durable logs volume so learning survives restarts.
    Only NVTs that hit their timeout ``NVT_HANG_MIN_EVENTS`` times within
    ``NVT_HANG_WINDOW_DAYS`` are capped, at ``NVT_HANG_CAP_SEC`` seconds. A
    capped NVT still runs on every host; it simply cannot block a host for
    the full 320 s again. Port scanners and crawlers are never capped.
    """

    def __init__(self, path: str | os.PathLike[str] | None = None) -> None:
        self.path = Path(path or os.environ.get("NVT_HANG_STATS_FILE") or "/app/logs/nvt_hang_stats.json")
        self._lock = threading.Lock()

    # -- persistence ------------------------------------------------------
    def _load(self) -> dict[str, Any]:
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            return data if isinstance(data, dict) and isinstance(data.get("nvts"), dict) else {"nvts": {}}
        except (OSError, ValueError):
            return {"nvts": {}}

    def _save(self, data: dict[str, Any]) -> None:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_suffix(self.path.suffix + ".tmp")
            tmp.write_text(json.dumps(data, indent=1, sort_keys=True), encoding="utf-8")
            os.replace(tmp, self.path)
        except OSError:
            log.warning("Could not persist NVT hang statistics to %s", self.path, exc_info=True)

    # -- learning ---------------------------------------------------------
    def record(self, errors: list[dict[str, Any]] | None, *, host: str, job_id: str = "") -> list[str]:
        """Record timeout errors from one host's report. Returns OIDs recorded."""
        recorded: list[str] = []
        rows = [e for e in (errors or []) if isinstance(e, dict)]
        hits = [
            e for e in rows
            if _TIMEOUT_RE.search(str(e.get("description") or "")) and str(e.get("nvt_oid") or "").strip()
        ]
        if not hits:
            return recorded
        now = time.time()
        with self._lock:
            data = self._load()
            nvts = data["nvts"]
            for err in hits:
                oid = str(err["nvt_oid"]).strip()
                item = nvts.setdefault(oid, {"name": "", "events": [], "hosts": [], "ports": []})
                item["name"] = str(err.get("nvt_name") or item.get("name") or "")[:200]
                item["events"] = [t for t in item.get("events", []) if isinstance(t, (int, float))][-49:] + [now]
                for key, value in (("hosts", host), ("ports", err.get("port"))):
                    if value and value not in item[key]:
                        item[key] = (item[key] + [str(value)])[-20:]
                item["last_description"] = str(err.get("description") or "")[:240]
                item["last_job"] = str(job_id)[:64]
                recorded.append(oid)
            data["updated_at"] = now
            self._save(data)
        if recorded:
            log.warning("NVT_TIMEOUT host=%s recorded %d timed-out NVT(s): %s", host, len(recorded), ", ".join(recorded))
        return recorded

    def caps(self, now: float | None = None) -> dict[str, int]:
        """OID -> timeout seconds for repeat offenders inside the window."""
        cap = _int_env("NVT_HANG_CAP_SEC", 60, 30, 600)
        min_events = _int_env("NVT_HANG_MIN_EVENTS", 2, 1, 50)
        window = _int_env("NVT_HANG_WINDOW_DAYS", 30, 1, 365) * 86400
        limit = _int_env("NVT_HANG_MAX_CAPPED", 50, 0, 500)
        now = time.time() if now is None else now
        scored: list[tuple[int, str]] = []
        for oid, item in self._load()["nvts"].items():
            if not _is_cappable(oid, str(item.get("name") or "")):
                continue
            recent = [t for t in item.get("events", []) if isinstance(t, (int, float)) and now - t <= window]
            if len(recent) >= min_events:
                scored.append((len(recent), oid))
        scored.sort(reverse=True)
        return {oid: cap for _, oid in scored[:limit]}

    def summary(self) -> list[dict[str, Any]]:
        caps = self.caps()
        out = []
        for oid, item in self._load()["nvts"].items():
            events = [t for t in item.get("events", []) if isinstance(t, (int, float))]
            out.append({
                "nvt_oid": oid,
                "name": item.get("name"),
                "timeouts": len(events),
                "last_seen": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(max(events))) if events else None,
                "hosts": item.get("hosts", []),
                "ports": item.get("ports", []),
                "capped_at_sec": caps.get(oid),
                "never_capped": not _is_cappable(oid, str(item.get("name") or "")),
                "last_description": item.get("last_description"),
            })
        out.sort(key=lambda r: (-r["timeouts"], r["nvt_oid"]))
        return out

    def reset(self, oid: str | None = None) -> int:
        with self._lock:
            data = self._load()
            if oid:
                removed = 1 if data["nvts"].pop(oid, None) is not None else 0
            else:
                removed = len(data["nvts"])
                data["nvts"] = {}
            self._save(data)
        return removed


_REGISTRY: NvtHangRegistry | None = None


def hang_registry() -> NvtHangRegistry:
    global _REGISTRY
    if _REGISTRY is None:
        _REGISTRY = NvtHangRegistry()
    return _REGISTRY


# ---------------------------------------------------------------------------
# Stalled-task watchdog
# ---------------------------------------------------------------------------
def stall_limits() -> dict[str, int]:
    """Seconds without any progress before a task is treated as stalled (0 = off).

    The defaults are several times the 320 s per-NVT limit so a slow but
    healthy dependency chain is never cut: NVT timeouts are handled by the
    scanner itself; this only catches a scanner/task that stopped working.
    """
    return {
        "start": _int_env("SCAN_TASK_START_STALL_SEC", 900, 0, 86400),
        "portscan": _int_env("SCAN_PORTSCAN_STALL_SEC", 3600, 0, 86400),
        "checks": _int_env("SCAN_IP_STALL_SEC", 1800, 0, 86400),
    }


def classify_stall(gmp_status: str, progress: float, unchanged_sec: float,
                   limits: dict[str, int] | None = None) -> str | None:
    """Return a stall reason, or None while the task is healthy."""
    lim = limits or stall_limits()
    status = str(gmp_status or "").strip().lower()
    if status in {"new", "requested", "queued"}:
        if lim["start"] and unchanged_sec >= lim["start"]:
            return f"task stayed '{status}' for {int(unchanged_sec)}s (scanner never started it)"
        return None
    if status not in {"running", "processing"}:
        return None
    if progress < 10:
        if lim["portscan"] and unchanged_sec >= lim["portscan"]:
            return f"no progress for {int(unchanged_sec)}s during port scanning ({int(progress)}%)"
        return None
    if lim["checks"] and unchanged_sec >= lim["checks"]:
        return f"no progress for {int(unchanged_sec)}s at {int(progress)}% (vulnerability checks stopped advancing)"
    return None


def caps_digest(caps: dict[str, int], extra: str = "") -> str:
    import hashlib

    blob = json.dumps({"caps": caps, "extra": extra}, sort_keys=True)
    return hashlib.sha256(blob.encode()).hexdigest()[:10]


def stall_action() -> str:
    """SCAN_STALL_ACTION: auto (default, evidence-based), stop (old: stop on time), off."""
    raw = (os.environ.get("SCAN_STALL_ACTION") or "auto").strip().lower()
    return raw if raw in {"auto", "stop", "off"} else "auto"


def stall_decision(activity: dict[str, Any] | None, action: str | None = None) -> str:
    """Decide what to do with an IP that has shown no progress for a long time.

    V1.6.8 has no time limits: a slow scan is never stopped for being slow.
    ``auto`` stops only when OpenVAS's own log proves nothing is running on
    the host (per-check logging on, no running check, host not finished),
    i.e. the scanner process died. Running checks are bounded by their own
    timeouts, and a finished host means Greenbone is importing the report;
    both are waited for. Without log evidence it waits.
    """
    mode = action or stall_action()
    if mode == "off":
        return "wait"
    if mode == "stop":
        return "stop"
    act = activity or {}
    if not act.get("available") or not act.get("whole_attack_logging"):
        return "wait"
    if act.get("host_finished") or act.get("running"):
        return "wait"
    return "stop"
