"""Read-only view of OpenVAS's own log for one host (V1.6.8).

With ``log_whole_attack = yes`` in openvas.conf (written by the
configure-openvas service), openvas-scanner logs, per check (NVT):

    Launching <file> (<oid>) against <ip> [<pid>]                  (attack.c)
    <file> (<oid>) [<pid>] finished its job in <s> seconds         (pluginlaunch.c)
    <oid> (pid <pid>) is slow to finish - killing it               (pluginlaunch.c)
    Vulnerability scan <id> finished for host <ip> in <s> seconds  (attack.c, always)

Finish/kill lines carry no IP, so they are matched to this host by PID. The
result says which checks are running right now on the host and for how long,
which slow checks already finished, and whether OpenVAS has finished the host.
It never changes anything. Formats verified against openvas-scanner main.
"""
from __future__ import annotations

import os
import re
from datetime import datetime
from pathlib import Path

_OID = r"1\.3\.6\.1\.4\.1\.25623\.1\.\d+\.\d+"
_OID_RE = re.compile(_OID)
_LAUNCH_RE = re.compile(rf"Launching (?P<name>\S+) \((?P<oid>{_OID})\) against (?P<ip>\S+) \[(?P<pid>\d+)\]")
_FINISH_RE = re.compile(
    rf"(?P<name>\S+) \((?P<oid>{_OID})\) \[(?P<pid>\d+)\] finished its job in (?P<sec>[\d.]+) seconds")
_KILL_RE = re.compile(rf"(?P<oid>{_OID}) \(pid (?P<pid>\d+)\) is slow to finish - killing it")
_HOST_DONE_RE = re.compile(r"Vulnerability scan \S+ finished for host (?P<ip>\S+) in (?P<sec>[\d.]+) seconds")
# gvm/openvas log timestamps look like "2026-10-14 04h54.08 utc"
_TS_RE = re.compile(r"(\d{4}-\d{2}-\d{2}) (\d{2})h(\d{2})\.(\d{2})")


def _log_path() -> Path:
    return Path(os.environ.get("OPENVAS_LOG_FILE") or "/var/log/openvas/openvas.log")


def _ts(line: str) -> datetime | None:
    m = _TS_RE.search(line)
    if not m:
        return None
    try:
        return datetime.strptime(f"{m.group(1)} {m.group(2)}:{m.group(3)}:{m.group(4)}", "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return None


def host_activity(host: str, *, max_lines: int = 15, max_bytes: int = 8_000_000) -> dict[str, object]:
    """Running/finished/killed checks for ``host`` from the tail of openvas.log."""
    path = _log_path()
    out: dict[str, object] = {
        "log_file": str(path), "available": False, "lines": [], "nvt_oids": [], "running": [],
        "slow_finished": [], "killed": [], "host_finished": False, "host_lines": 0,
        "whole_attack_logging": False,
    }
    try:
        size = path.stat().st_size
        with path.open("rb") as handle:
            handle.seek(max(0, size - max_bytes))
            tail = handle.read().decode("utf-8", errors="replace")
    except OSError as exc:
        out["error"] = f"{exc.__class__.__name__}: {exc}"[:200]
        return out
    out["available"] = True
    ip_re = re.compile(r"(?<![\d.])" + re.escape(host) + r"(?![\d])")
    running: dict[str, dict[str, object]] = {}
    host_pids: set[str] = set()
    slow: list[dict[str, object]] = []
    killed: list[dict[str, object]] = []
    host_lines: list[str] = []
    last_ts: datetime | None = None
    for line in tail.splitlines():
        stamp = _ts(line)
        if stamp:
            last_ts = stamp
        launch = _LAUNCH_RE.search(line)
        if launch:
            out["whole_attack_logging"] = True
            if launch.group("ip") == host:
                pid = launch.group("pid")
                host_pids.add(pid)
                running[pid] = {"oid": launch.group("oid"), "name": launch.group("name"), "pid": int(pid),
                                "started": stamp}
                host_lines.append(line.strip())
            continue
        finish = _FINISH_RE.search(line)
        if finish:
            pid = finish.group("pid")
            if pid in host_pids:
                running.pop(pid, None)
                sec = float(finish.group("sec"))
                if sec >= 60:
                    slow.append({"oid": finish.group("oid"), "name": finish.group("name"), "seconds": round(sec, 1)})
            continue
        kill = _KILL_RE.search(line)
        if kill:
            pid = kill.group("pid")
            if pid in host_pids:
                item = running.pop(pid, None) or {"oid": kill.group("oid")}
                killed.append({"oid": kill.group("oid"), "name": item.get("name")})
            continue
        done = _HOST_DONE_RE.search(line)
        if done and done.group("ip") == host:
            out["host_finished"] = True
            out["host_scan_seconds"] = float(done.group("sec"))
            running.clear()
            host_lines.append(line.strip())
            continue
        if ip_re.search(line):
            host_lines.append(line.strip())
    run_list = []
    for item in running.values():
        started = item.get("started")
        age = int((last_ts - started).total_seconds()) if isinstance(started, datetime) and last_ts else None
        run_list.append({"oid": item["oid"], "name": item["name"], "pid": item["pid"], "running_sec": age})
    run_list.sort(key=lambda r: -(r["running_sec"] or 0))
    slow.sort(key=lambda r: -float(r["seconds"]))
    oids: list[str] = []
    for line in host_lines[-max_lines:]:
        for oid in _OID_RE.findall(line):
            if oid not in oids:
                oids.append(oid)
    for item in run_list:
        if item["oid"] not in oids:
            oids.insert(0, str(item["oid"]))
    out.update({
        "lines": [line[:400] for line in host_lines[-max_lines:]],
        "nvt_oids": oids,
        "running": run_list[:20],
        "slow_finished": slow[:10],
        "killed": killed[-10:],
        "host_lines": len(host_lines),
    })
    return out


def describe(activity: dict[str, object]) -> str:
    """One-line human summary for logs."""
    if not activity.get("available"):
        return f"OpenVAS log unavailable ({activity.get('error') or 'not mounted'})"
    if activity.get("host_finished"):
        return (f"OpenVAS finished this host in {int(float(activity.get('host_scan_seconds') or 0))}s; "
                "Greenbone is still processing the report")
    running = activity.get("running") or []
    if running:
        parts = [f"{r['name']} ({r['oid']})" + (f" for {r['running_sec']}s" if r.get("running_sec") is not None else "")
                 for r in running[:5]]
        return f"{len(running)} check(s) still running in OpenVAS: " + "; ".join(parts)
    if not activity.get("whole_attack_logging"):
        return "OpenVAS per-check logging is off (set log_whole_attack); cannot see running checks"
    return "OpenVAS shows no running checks and has not finished this host"
