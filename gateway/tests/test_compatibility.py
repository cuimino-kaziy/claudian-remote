import json
from pathlib import Path

from gateway.protocol.compatibility import COMPATIBILITY_SET, combine_compatibility, evaluate_compatibility


ROOT = Path(__file__).resolve().parents[2]


def test_python_handshake_contract_matches_release_support_matrix():
    matrix = json.loads((ROOT / "release" / "support-matrix.json").read_text(encoding="utf-8"))
    assert COMPATIBILITY_SET == {
        "id": matrix["components"]["compatibility_set_id"],
        "plugin": matrix["components"]["plugin"],
        "companion": matrix["components"]["companion"],
        "relay": matrix["components"]["relay"],
        "protocol": matrix["protocol"]["current"],
        "configuration_schema": matrix["components"]["configuration_schema"],
    }


def test_missing_or_mixed_bridge_metadata_fails_closed_with_remediation():
    missing = combine_compatibility(COMPATIBILITY_SET)
    assert missing["writable"] is False
    assert missing["reason"] == "bridge_compatibility_missing"
    assert missing["remediation"]

    mixed = evaluate_compatibility({**COMPATIBILITY_SET, "configuration_schema": 2})
    result = combine_compatibility(COMPATIBILITY_SET, mixed)
    assert result["writable"] is False
    assert result["reason"] == "compatibility_set_mismatch"
    assert result["mismatches"][0]["component"] == "configuration_schema"
