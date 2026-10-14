"""Regression against the old 600s per-IP forced-stop path."""
import inspect
from pathlib import Path
from agent import main
from agent import AGENT_BUILD


def test_legacy_budget_branch_removed():
    source = inspect.getsource(main)
    assert "_nexus_budget_complete" not in source
    assert "degraded_time_budget" not in source
    assert '"nexus_budget"' not in source
    assert 'ip_budget_sec > 0' not in source
    assert "LEGACY_IP_BUDGET_IGNORED" in source


def test_legacy_budget_600_no_longer_interrupts(monkeypatch):
    monkeypatch.setenv("SCAN_IP_BUDGET_SEC", "600")
    monkeypatch.setenv("MAX_SCAN_RUNTIME_SEC", "0")
    # _cfg is only for top-level configuration requiring credentials; the
    # obsolete setting has no scan lifecycle branches and default job ceiling is 0.
    assert '600' not in inspect.getsource(main._cfg)
    assert AGENT_BUILD.startswith("1.6.6-")


def test_full_profile_ports_and_service_audit_still_enabled():
    from agent.audit_scan_policy import audit
    report = audit(profile="full", udp="priority")
    assert report["service_families"] == 52
    assert report["requested_tcp_ports"] == 65535
    assert report["families_with_port_hints_in_scope"] == 52
    assert report["actual_greenbone_execution_verified"] is False


def test_legacy_performance_scripts_do_not_reduce_scope():
    root = Path(__file__).resolve().parents[2]
    for filename in ("Apply-Vuln-Throughput-v1.3.5.ps1", "scripts/Apply-Vuln-Performance-Profile.ps1"):
        script = (root / filename).read_text(encoding="utf-8")
        assert "'PORT_PROFILE' = 'full'" in script
        assert "'GVM_OPTIMIZE_TEST' = 'no'" in script
        assert "'SCAN_IP_BUDGET_SEC' = '0'" in script
