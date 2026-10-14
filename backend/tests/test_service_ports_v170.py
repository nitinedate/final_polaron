"""V1.7.0 central: service port policy endpoint and no-exposed-services hosts."""
from app.services.scanner_agent_jobs import classify_host_coverage


def test_no_exposed_services_is_a_finished_result():
    cov = {"verdict": "no_exposed_services", "network_scan_complete": True, "host_responded": False,
           "port_state_counts": {"open": 0, "closed": 0, "filtered": 87}}
    tp, degraded, done = classify_host_coverage({"172.20.10.2": cov}, {})
    row = tp["172.20.10.2"]
    assert degraded == [] and done == ["172.20.10.2"] and row["status"] == "completed"
    assert row["activity"] == "No exposed services - 0 policy ports closed, 87 not answering (firewall blocking or host offline)"
    cov.update({"host_responded": True, "port_state_counts": {"closed": 80, "filtered": 7}})
    tp, _, _ = classify_host_coverage({"h": cov}, {})
    assert tp["h"]["activity"] == "No exposed services - 80 policy ports closed, 7 not answering"


def test_no_exposed_without_completed_network_scan_stays_incomplete():
    tp, degraded, _ = classify_host_coverage({"h": {"verdict": "no_exposed_services", "network_scan_complete": False,
                                                    "reason": "x"}}, {})
    assert degraded == ["h"] and tp["h"]["status"] == "incomplete"


def test_service_port_policy_endpoint(monkeypatch):
    from app.routers import vuln

    monkeypatch.setattr(vuln, "_require_vuln_module", lambda: None)
    out = vuln.get_service_port_policy(current=None)
    assert out["tcp_port_count"] == 87 and out["udp_port_count"] == 25
    assert len(out["services"]) == 67 and all(s["low_plus_examples"] for s in out["services"])
    assert {x["port"] for x in out["not_checked"]} >= {"20/tcp", "67-68/udp"}


def test_disabled_services_are_validated_in_policies():
    import pytest
    from fastapi import HTTPException

    from app.routers import vuln

    assert vuln._validated_policy_settings({"disabled_services": ["vnc"]})["disabled_services"] == ["vnc"]
    with pytest.raises(HTTPException):
        vuln._validated_policy_settings({"disabled_services": ["nope"]})
