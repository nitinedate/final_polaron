"""CVSS v3 severity labels from environment; no port-based severity."""
import os

def cvss_severity(score: float | None, *, informational: bool=False) -> str:
    if informational:
        return os.getenv("VULN_SEVERITY_INFORMATIONAL", "Info")
    if score is None:
        return os.getenv("VULN_SEVERITY_UNSCORED", "Unscored")
    score = float(score)
    if not 0 <= score <= 10:
        raise ValueError("CVSS score must be between 0 and 10")
    for name in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        threshold = float(os.getenv(f"VULN_SEVERITY_{name}_MIN", {"CRITICAL":9.0,"HIGH":7.0,"MEDIUM":4.0,"LOW":0.1}[name]))
        if score >= threshold:
            return name.title()
    return "None"
