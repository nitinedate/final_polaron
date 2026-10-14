"""V1.6.6: scan policies accept a validated speed setting."""
import pytest
from fastapi import HTTPException


def test_policy_speed_is_validated():
    from app.routers import vuln

    assert vuln._validated_policy_settings({"performance": "fast"}, "basic_network") == {
        "performance": "fast", "template": "basic_network"}
    assert vuln._validated_policy_settings({"performance": "standard"})["performance"] == "standard"
    with pytest.raises(HTTPException) as err:
        vuln._validated_policy_settings({"performance": "turbo"})
    assert err.value.status_code == 400


def test_speed_survives_into_the_agent_request_and_snapshot_fields():
    from app.services.scanner_service_policy import SNAPSHOT_FIELDS, effective_policy, validate_request

    assert validate_request({"template": "advanced", "performance": "fast"})["performance"] == "fast"
    assert effective_policy({"performance": "fast"})["performance"] == "fast"
    assert {"performance", "performance_status", "nvt_timeout_caps"} <= SNAPSHOT_FIELDS
