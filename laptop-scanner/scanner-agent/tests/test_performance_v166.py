"""V1.6.6: fast profile, NVT hang learning, fast config and stalled-task watchdog."""
from __future__ import annotations

import time
from contextlib import contextmanager

import pytest
from lxml import etree

from agent import gmp_local, main, scan_performance as perf
from agent.scan_performance import NvtHangRegistry, classify_stall, profile_settings, resolve_profile

TIMEOUT = "NVT timed out after 320 seconds."
OID_A = "1.3.6.1.4.1.25623.1.0.999101"
OID_B = "1.3.6.1.4.1.25623.1.0.999102"


@pytest.fixture(autouse=True)
def _env(monkeypatch, tmp_path):
    for key in ("SCAN_PERFORMANCE", "FAST_CHECKS_READ_TIMEOUT", "FAST_MAX_CHECKS", "FAST_NMAP_TIMING",
                "NVT_HANG_CAPS", "NVT_HANG_CAP_SEC", "NVT_HANG_MIN_EVENTS", "NVT_HANG_WINDOW_DAYS",
                "SCAN_IP_STALL_SEC", "SCAN_PORTSCAN_STALL_SEC", "SCAN_TASK_START_STALL_SEC",
                "PORT_PROFILE", "UDP_PROFILE", "UDP_PORT_RANGE", "GVM_OPTIMIZE_TEST"):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setattr(perf, "_REGISTRY", NvtHangRegistry(tmp_path / "hangs.json"))


def _err(oid, name="SMB slow check", desc=TIMEOUT, host="192.168.0.163"):
    return {"host": host, "port": "445/tcp", "nvt_oid": oid, "nvt_name": name, "description": desc}


# --- profiles -----------------------------------------------------------------
def test_profile_resolution_policy_beats_env(monkeypatch):
    assert resolve_profile(None) == "standard"
    monkeypatch.setenv("SCAN_PERFORMANCE", "fast")
    assert resolve_profile(None) == "fast"
    assert resolve_profile({"performance": "standard"}) == "standard"
    assert resolve_profile({"performance": "turbo"}) == "fast"  # invalid policy value -> env


def test_fast_settings_are_nessus_and_openvas_defaults():
    fast = profile_settings("fast")
    assert fast["checks_read_timeout"] == 5 and fast["max_checks"] == 5
    assert fast["nmap_timing"] == "Aggressive" and fast["hang_caps"] is True
    std = profile_settings("standard")
    assert std["checks_read_timeout"] is None and std["hang_caps"] is False


# --- hang learning ------------------------------------------------------------
def test_only_repeat_timeouts_are_capped(tmp_path):
    reg = NvtHangRegistry(tmp_path / "h.json")
    reg.record([_err(OID_A)], host="h1")
    assert reg.caps() == {}  # one event is not a pattern
    reg.record([_err(OID_A), _err(OID_B, desc="Connection refused")], host="h2")
    assert reg.caps() == {OID_A: 120}  # B was not a timeout
    assert NvtHangRegistry(tmp_path / "h.json").caps() == {OID_A: 120}  # persisted


def test_port_scanners_and_crawlers_are_never_capped(tmp_path):
    reg = NvtHangRegistry(tmp_path / "h.json")
    for _ in range(3):
        reg.record([_err("1.3.6.1.4.1.25623.1.0.14259", "Nmap (NASL wrapper)"),
                    _err("1.3.6.1.4.1.25623.1.0.555", "Web mirroring")], host="h")
    assert reg.caps() == {}
    assert all(r["never_capped"] for r in reg.summary())


def test_old_events_expire_and_reset_works(tmp_path, monkeypatch):
    reg = NvtHangRegistry(tmp_path / "h.json")
    reg.record([_err(OID_A)], host="h1")
    reg.record([_err(OID_A)], host="h2")
    assert reg.caps(now=time.time() + 40 * 86400) == {}  # outside the 30-day window
    monkeypatch.setenv("NVT_HANG_CAP_SEC", "90")
    assert reg.caps() == {OID_A: 90}
    assert reg.reset(OID_A) == 1 and reg.caps() == {}


def test_corrupt_statistics_file_is_tolerated(tmp_path):
    path = tmp_path / "h.json"
    path.write_text("{not json")
    reg = NvtHangRegistry(path)
    assert reg.caps() == {}
    reg.record([_err(OID_A)], host="h")
    assert reg.summary()[0]["timeouts"] == 1


# --- stall classification -----------------------------------------------------
@pytest.mark.parametrize("status,progress,secs,stalled", [
    ("requested", 0, 899, False), ("requested", 0, 900, True),
    ("running", 5, 3599, False), ("running", 5, 3600, True),
    ("running", 98, 355, False),            # one NVT timeout tail: healthy
    ("running", 98, 1799, False), ("running", 98, 1800, True),
    ("done", 100, 99999, False),
])
def test_classify_stall(status, progress, secs, stalled):
    assert bool(classify_stall(status, progress, secs)) is stalled


def test_stall_rules_can_be_disabled():
    assert classify_stall("running", 98, 10**6, {"start": 0, "portscan": 0, "checks": 0}) is None


# --- fast config --------------------------------------------------------------
NMAP = gmp_local.NMAP_NVT_OID
CONFIG_XML = f"""<get_configs_response><config id="c"><preferences>
  <preference><nvt oid="{NMAP}"><name>Nmap (NASL wrapper)</name></nvt><id>1</id>
    <name>TCP scanning technique :</name><type>radio</type><value>SYN scan</value></preference>
  <preference><nvt oid="{NMAP}"><name>Nmap (NASL wrapper)</name></nvt><id>11</id>
    <name>Timing policy :</name><type>radio</type><value>Normal</value></preference>
</preferences></config></get_configs_response>""".encode()


class FastGmp:
    def __init__(self, existing=None, with_timing=True, clone_error=False):
        self.existing = existing or []
        self.with_timing = with_timing
        self.clone_error = clone_error
        self.prefs: list[tuple[str, str, str, str]] = []
        self.names: list[str] = []

    def get_scan_configs(self, **kw):
        rows = "".join(f'<config id="{cid}"><name>{name}</name><comment>{c}</comment></config>'
                       for cid, name, c in self.existing)
        return etree.fromstring(f"<r>{rows}</r>".encode())

    def clone_scan_config(self, cid):
        if self.clone_error:
            raise RuntimeError("permission denied")
        return {"id": f"fast-of-{cid}"}

    def modify_scan_config_set_name(self, cid, name):
        self.names.append(name)

    def get_scan_config(self, cid):
        return etree.fromstring(CONFIG_XML if self.with_timing else b"<r/>")

    def modify_scan_config_set_nvt_preference(self, cid, name, nvt_oid, value=None):
        self.prefs.append((cid, name, nvt_oid, value))

    def modify_scan_config_set_comment(self, cid, comment):
        pass

    def delete_scan_config(self, cid, ultimate=False):
        pass


def test_fast_config_sets_gvmd_timeout_preferences_and_looked_up_timing():
    g = FastGmp()
    cid, status = gmp_local._ensure_fast_config(g, "base", {OID_A: 120}, "Aggressive")
    assert cid == "fast-of-base" and g.names[0].startswith("Aetheris fast ")
    assert ("fast-of-base", f"{OID_A}:0:entry:timeout", OID_A, "120") in g.prefs
    assert ("fast-of-base", f"{NMAP}:11:radio:Timing policy :", NMAP, "Aggressive") in g.prefs
    assert status["nvt_timeout_caps"] == 1 and status["nmap_timing"] == "Aggressive"


def test_missing_timing_preference_is_reported_not_guessed():
    g = FastGmp(with_timing=False)
    _, status = gmp_local._ensure_fast_config(g, "base", {}, "Aggressive")
    assert "not found" in status["nmap_timing"]
    assert not any("Timing" in p[1] for p in g.prefs)


def test_fast_config_is_reused_and_falls_back_safely():
    from agent.scan_performance import caps_digest

    name = f"Aetheris fast {caps_digest({OID_A: 120}, 'base|Aggressive')}"
    g = FastGmp(existing=[("fast-1", name, '{"nvt_timeout_caps": 1}')])
    cid, status = gmp_local._ensure_fast_config(g, "base", {OID_A: 120}, "Aggressive")
    assert cid == "fast-1" and status["config"].startswith("reused") and g.prefs == []
    cid, status = gmp_local._ensure_fast_config(FastGmp(clone_error=True), "base", {OID_A: 120}, None)
    assert cid == "base" and status["config"].startswith("not applied")


def _launch(monkeypatch, policy=None):
    g = FastGmp()
    created = {}

    g.create_target = lambda **kw: created.setdefault("target", kw) and {"id": "t1"}
    g.create_task = lambda **kw: created.setdefault("task", kw) and {"id": "task-1"}
    g.start_task = lambda tid: etree.fromstring(b"<r><report_id>r</report_id></r>")
    g.get_feeds = lambda: etree.fromstring(b"<r/>")
    g.get_credential = lambda cid: etree.fromstring(b"<r/>")

    @contextmanager
    def sess(**kw):
        yield g

    monkeypatch.setattr(gmp_local, "_session", sess)
    monkeypatch.setattr(gmp_local, "_ensure_portscan_config", lambda gmp, base: "cfg")
    monkeypatch.setattr(gmp_local, "_assert_feed_quality", lambda gmp, cid: {})
    monkeypatch.setattr(gmp_local, "_find_scanner_id", lambda gmp: "s")
    monkeypatch.setattr(gmp_local, "_named_port_list_tcp", lambda gmp, name: {80})
    scanner = gmp_local.LocalOpenVAS()
    tid = scanner.start_scan(name="t", targets=["192.0.2.1"], scan_policy=policy, max_checks=4)
    return created, scanner.policy_snapshots[tid]


def test_fast_profile_reaches_the_greenbone_task(monkeypatch):
    perf.hang_registry().record([_err(OID_A)], host="a")
    perf.hang_registry().record([_err(OID_A)], host="b")
    created, snap = _launch(monkeypatch, {"template": "basic_network", "performance": "fast"})
    prefs = created["task"]["preferences"]
    assert prefs["checks_read_timeout"] == "5" and prefs["max_checks"] == "5"
    assert created["task"]["config_id"] == "fast-of-cfg"
    assert snap["performance"] == "fast"
    assert snap["nvt_timeout_caps"]["oids"] == [OID_A] and snap["nvt_timeout_caps"]["applied"] == 1
    assert snap["performance_status"]["nmap_timing"] == "Aggressive"


def test_standard_profile_is_unchanged(monkeypatch):
    created, snap = _launch(monkeypatch, {"template": "basic_network", "performance": "standard"})
    prefs = created["task"]["preferences"]
    assert prefs["checks_read_timeout"] == "10" and prefs["max_checks"] == "4"
    assert created["task"]["config_id"] == "cfg"
    assert snap["performance"] == "standard"


# --- watchdog in the real job loop ---------------------------------------------
def _run_loop(monkeypatch, polls, *, stall_env=None):
    from agent import reachability

    uploaded, stops, events = [], [], []
    clock = {"t": 1000.0}

    def mono():
        clock["t"] += 30.0
        return clock["t"]

    class Api:
        def patch_job(self, job_id, payload):
            return {"id": job_id}

        def upload_results(self, job_id, payload):
            uploaded.append(payload)
            return {"status": "completed"}

    class Scanner:
        port_profile = "nexus"

        def __init__(self):
            self.n = 0
            self.stopped = False

        def start_scan(self, *, name, targets, port_range=None):
            return "task-1"

        def get_task_hosts(self, task_id):
            return ["10.0.0.9"]

        def poll(self, task_id, **kw):
            self.n += 1
            if self.stopped:
                return {"status": "stopped", "gmp_status": "stopped", "progress": 98,
                        "vulnerabilities": [{"host": "10.0.0.9", "severity": "medium", "result_id": "r1"}],
                        "evidence": {"report_id": "rep", "task_status": "stopped"}}
            return polls(self.n)

        def stop(self, task_id):
            stops.append(task_id)
            self.stopped = True
            return True

    for key, value in (stall_env or {}).items():
        monkeypatch.setenv(key, value)
    monkeypatch.setattr(main.time, "sleep", lambda _: None)
    monkeypatch.setattr(main.time, "monotonic", mono)
    monkeypatch.setattr(main, "should_watch_lan", lambda *a, **kw: False)
    monkeypatch.setattr(main, "probe_laptop_capacity", lambda **kw: {
        "chunk_size": 1, "ip_workers": 1, "configured_ceiling": 1, "hot": False, "admission_paused": False})
    monkeypatch.setattr(main, "emit_ip_event", lambda job, host, event, **kw: events.append((event, kw)))
    monkeypatch.setattr(reachability, "partition_targets", lambda targets, **kw: {
        "reachable": list(targets), "unreachable": [], "skipped_hosts": []})
    monkeypatch.setenv("SKIP_UNREACHABLE_TARGETS", "false")
    monkeypatch.setenv("SCAN_DEGRADED_RETRY", "0")
    scanner = Scanner()
    main._run_job_body({"api": Api(), "openvas": scanner, "poll": 0, "max_scan_runtime_sec": 0,
                        "progress_report_interval": 0, "high_progress_warn_sec": 300,
                        "high_progress_stall_sec": 0},
                       {"id": "00000000-0000-0000-0000-000000000009", "targets": [{"target": "10.0.0.9"}]})
    return uploaded, stops, events


def test_frozen_task_is_stopped_and_reported_stalled_not_completed(monkeypatch):
    frozen = lambda n: {"status": "running", "gmp_status": "running", "progress": 98,
                        "vulnerabilities": [], "evidence": {}}
    uploaded, stops, events = _run_loop(monkeypatch, frozen)
    assert stops == ["task-1"]
    stalled = [kw for ev, kw in events if ev == "stalled"]
    assert stalled and "no progress" in stalled[0]["reason"]
    final = uploaded[-1]
    skipped = final.get("skipped_hosts") or (final.get("evidence") or {}).get("skipped_hosts") or []
    assert any(s.get("reason") == "scan_stalled" and "Stalled" in str(s.get("error")) for s in skipped)
    assert any(v.get("result_id") == "r1" for v in final.get("vulnerabilities") or [])


def test_slow_but_moving_task_is_never_stopped(monkeypatch):
    def climbing(n):
        if n >= 120:
            return {"status": "completed", "gmp_status": "done", "progress": 100, "vulnerabilities": [],
                    "evidence": {"report_id": "rep", "task_status": "done", "assessed_hosts": ["10.0.0.9"],
                                 "hosts_assessed": 1, "assessment_complete": True}}
        # one percent every 15 polls (~22 min of fake time per step): far slower
        # than the real 355 s NVT-timeout tail, but still alive -> never stopped.
        return {"status": "running", "gmp_status": "running", "progress": 90 + n // 15,
                "vulnerabilities": [], "evidence": {}}
    stamps = []

    def stamped(n):
        stamps.append(main.time.monotonic())
        return climbing(n)

    uploaded, stops, events = _run_loop(monkeypatch, stamped)
    assert stops == []
    assert not [e for e, _ in events if e == "stalled"]
    plateau = max(stamps[i + 14] - stamps[i] for i in range(0, len(stamps) - 15, 15))
    assert 1000 < plateau < 1800, plateau
