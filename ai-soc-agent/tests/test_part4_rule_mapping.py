from pathlib import Path
import importlib.util


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "agent" / "live_triage.py"

spec = importlib.util.spec_from_file_location("live_triage", SCRIPT)
live_triage = importlib.util.module_from_spec(spec)
spec.loader.exec_module(live_triage)


def test_part4_rule_ids_map_to_event_types():
    cases = {
        "100201": "sudo_failure",
        "100202": "port_scan",
        "100203": "new_privileged_account",
        "100204": "suspicious_outbound_connection",
        "100205": "web_auth_failure",
    }

    for rule_id, expected in cases.items():
        alert = {
            "rule": {"id": rule_id},
            "agent": {"name": "test-agent"},
            "data": {"srcip": "192.0.2.10", "dstuser": "testuser"},
        }

        sanitized = live_triage.sanitize_alert(alert)

        assert live_triage.determine_event_type(sanitized) == expected


def test_unknown_rule_maps_to_generic_security_event():
    alert = {
        "rule": {"id": "999999"},
        "agent": {"name": "test-agent"},
        "data": {"srcip": "192.0.2.10", "dstuser": "testuser"},
    }

    sanitized = live_triage.sanitize_alert(alert)

    assert live_triage.determine_event_type(sanitized) == "generic_security_event"
