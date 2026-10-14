"""Cross-check observed TCP listeners versus native Greenbone report evidence.

Only actual observations count as endpoints. Never synthesize vulnerabilities.
"""
from __future__ import annotations
from typing import Any


def reconcile_host_observations(details: dict[str, Any], host: str, preprobe_ports: list[int] | None) -> dict[str, Any]:
    evidence = details.get("evidence") or {}
    coverages = evidence.get("host_coverage") or {}
    coverage = coverages.get(host)
    if not isinstance(coverage, dict):
        return details
    preprobe = sorted({int(x) for x in (preprobe_ports or []) if str(x).isdigit() and 1 <= int(x) <= 65535})
    coverage["preprobe_tcp_ports"] = preprobe
    coverage["preprobe_source"] = "scanner_agent_tcp_connect"
    coverage["preprobe_is_not_vulnerability_evidence"] = True
    native = sorted({int(x) for x in coverage.get("open_tcp_ports") or [] if str(x).isdigit() and 1 <= int(x) <= 65535})
    coverage["greenbone_tcp_ports"] = native
    if preprobe and not native:
        coverage["verdict"] = "degraded_discovery_mismatch"
        coverage["reason"] = (
            f"Scanner agent established TCP connections on {preprobe}, but Greenbone did not report "
            "any open TCP ports. Investigate OSPd network route, Nmap preferences, container permissions, "
            "and native scan errors. Vulnerability coverage remains unverified"
        )
        coverage["service_checks_verified"] = False
        coverage["coverage_complete"] = False
        coverage["network_scan_complete"] = False
    elif preprobe and native and set(preprobe) - set(native):
        missing = sorted(set(preprobe) - set(native))
        coverage["preprobe_only_ports"] = missing
        warnings = list(coverage.get("warnings") or [])
        note = (
            f"TCP connect pre-probe saw port(s) {missing} open, but Greenbone reported no port detail "
            "or result for them; those listeners may be untested"
        )
        if note not in warnings:
            warnings.append(note)
        coverage["warnings"] = warnings
    elif not preprobe and not native and coverage.get("verdict") == "degraded_no_ports":
        coverage["reason"] = (
            "Neither the fast scanner-agent TCP connect probe nor Greenbone evidenced an open listener. "
            "This does not prove the host is down or that every port was tested. Compare Windows host "
            "and Docker reachability, verify firewall/ACL and Nmap/OpenVAS port-scanner logs"
        )
    # Pre-probe results are corroborating context, not verified service coverage.
    return details
