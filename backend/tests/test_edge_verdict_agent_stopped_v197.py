"""V1.9.7: a multi-IP job where some IPs were stopped by the agent's own limits.

Field job de53e2fe: 192.168.0.163 assessed (50 results); 192.168.0.195 answered
nothing and was stopped at the per-IP time limit before its port scan finished, so
the OpenVAS report has no host record for it. The whole job turned red "failed".
It is now amber "incomplete" (findings kept, never verified/clean) - but only when
the agent accounts for every IP without results. An IP that simply never appears
in the report still fails the job.
"""
from app.services.scanner_agent_jobs import evaluate_edge_ingest_verdict

LIVE, SILENT = "192.168.0.163", "192.168.0.195"


def _verdict(**overrides):
    base = {
        "target_list": [LIVE, SILENT],
        "skipped_details": [],
        "skipped_set": set(),
        "assessed_list": [LIVE],
        "status": "completed",
        "partial": True,
        "partial_reason": "OpenVAS finished but assessed 1 of 2 target(s): incomplete_coverage",
        "error": None,
        "external_scan_id": "5e979cd4-5ac4-418a-8a21-b477d3ca930b,b86da11d-f24c-4c42-8610-45620eea414b",
        "report_id": "d55bb965-5e34-4a00-9196-d681c2ab695a",
        "task_status": "stopped",
        "hosts_attempted": 2,
        "hosts_assessed": 1,
        "report_result_count": 50,
        "plugin_error_count": 3,
        "scan_start": "2026-10-15T14:20:29Z",
        "scan_end": "2026-10-15T15:20:59Z",
        "assessment_complete": False,
        "assessment_verdict": "incomplete_coverage",
        "report_read_error": None,
        "vulnerability_count": 50,
        "evidence_present": True,
        "host_coverage": {
            LIVE: {"verdict": "observed_unverified"},
            SILENT: {"verdict": "degraded_time_limit"},
        },
    }
    base.update(overrides)
    return evaluate_edge_ingest_verdict(**base)


def test_field_job_with_time_limited_silent_ip_is_incomplete_not_failed():
    v = _verdict()
    assert v["final_status"] == "incomplete"
    assert v["verified_complete"] is False and v["clean_eligible"] is False
    assert v["missing_ip_targets"] == [SILENT]
    assert v["missing_agent_stopped"] == [SILENT]
    assert "stopped at the per-IP time limit before port scanning finished: 192.168.0.195" in v["err_text"]
    assert "has no assessment evidence" not in v["err_text"]


def test_no_response_ip_is_named_as_such():
    v = _verdict(host_coverage={LIVE: {"verdict": "observed_unverified"}, SILENT: {"verdict": "no_response"}})
    assert v["final_status"] == "incomplete"
    assert "no response, not assessed (host offline or all traffic dropped): 192.168.0.195" in v["err_text"]


def test_finished_ips_reporting_done_still_allow_incomplete():
    """In a 40-IP job the merged task status can be "done" (finished IPs)."""
    v = _verdict(task_status="done",
                 host_coverage={LIVE: {"verdict": "observed_unverified"}, SILENT: {"verdict": "no_response"}})
    assert v["final_status"] == "incomplete"


def test_ip_missing_without_an_agent_explanation_still_fails():
    v = _verdict(host_coverage={LIVE: {"verdict": "observed_unverified"}})
    assert v["final_status"] == "failed"
    assert "OpenVAS report has no assessment evidence for target(s): 192.168.0.195" in v["err_text"]


def test_one_explained_and_one_unexplained_missing_ip_fails():
    third = "192.168.0.50"
    v = _verdict(target_list=[LIVE, SILENT, third], hosts_attempted=3)
    assert v["final_status"] == "failed"
    assert v["missing_agent_stopped"] == [SILENT]
    assert third in v["err_text"]


def test_no_ip_assessed_at_all_still_fails():
    v = _verdict(assessed_list=[], hosts_assessed=0, report_result_count=0, vulnerability_count=0,
                 host_coverage={LIVE: {"verdict": "no_response"}, SILENT: {"verdict": "no_response"}})
    assert v["final_status"] == "failed"


def test_integrity_mismatch_still_fails_even_when_missing_ips_are_explained():
    v = _verdict(report_result_count=60)
    assert v["final_status"] == "failed"
    assert "result integrity mismatch" in v["err_text"]


def test_other_coverage_verdicts_do_not_excuse_a_missing_ip():
    v = _verdict(host_coverage={LIVE: {"verdict": "observed_unverified"}, SILENT: {"verdict": "unverified"}})
    assert v["final_status"] == "failed"


def test_without_host_coverage_behaviour_is_unchanged():
    v = _verdict(host_coverage=None)
    assert v["final_status"] == "failed"
