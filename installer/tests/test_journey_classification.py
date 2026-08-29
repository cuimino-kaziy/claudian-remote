import json
from pathlib import Path

import pytest

from installer.claudian_remote_lifecycle.journey import classify_journey


FIXTURE_PATH = Path(__file__).parent / "fixtures" / "beta4" / "entry-states.json"


def _fixture(fixture_id):
    bundle = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
    return next(entry for entry in bundle["entries"] if entry["fixture_id"] == fixture_id)


def _observation(entry):
    vault = entry["entry_state"]["vault"]
    enabled = set(vault["enabled_plugin_ids"])
    plugins = {item["id"]: item for item in vault["plugin_directories"]}
    current = plugins.get("claudian-remote")
    legacy = plugins.get("whale-agent-bridge")
    return {
        "current": {
            "present": current is not None,
            "enabled": "claudian-remote" in enabled,
            "recognized": current is None or current.get("version") == "0.2.0-beta.4",
        },
        "legacy": {
            "present": legacy is not None,
            "enabled": "whale-agent-bridge" in enabled,
            "recognized": legacy is None or legacy.get("version") == "recognized-dogfood-lineage",
        },
        "legacy_authority_capability": (
            "unavailable"
            if entry["entry_state"].get("legacy_authority", {}).get("production_revoker_available") is False
            else "unknown"
        ),
    }


@pytest.mark.parametrize(
    ("fixture_id", "expected_journey", "expected_reason", "re_pair_required"),
    [
        ("clean", "fresh_install", "clean_installation", True),
        ("current", "current_update", "recognized_current_installation", None),
        ("legacy", "legacy_upgrade", "recognized_legacy_installation", True),
        ("conflict", "coexistence_conflict", "legacy_and_current_plugin_enabled", None),
    ],
)
def test_beta4_entry_states_classify_deterministically(
    fixture_id, expected_journey, expected_reason, re_pair_required
):
    decision = classify_journey(_observation(_fixture(fixture_id)))

    assert decision.journey == expected_journey
    assert decision.reason_code == expected_reason
    assert decision.re_pair_required is re_pair_required
    assert decision.prior_operation_terminal is True
    assert decision.blocked is (expected_journey == "coexistence_conflict")
    if expected_journey != "legacy_upgrade":
        assert decision.legacy_authority_capability == "not_applicable"


def test_unfinished_operation_is_arbitrated_before_journey_selection():
    entry = _fixture("recovery-required")
    checkpoint = entry["entry_state"]["lifecycle"]["checkpoint"]

    decision = classify_journey(
        _observation(entry),
        prior_operation={
            "operation_id": checkpoint["operation_id"],
            "terminal": False,
            "recommended_action": "rollback",
        },
    )

    assert decision.journey == "unclassified"
    assert decision.reason_code == "operation_reconciliation_required"
    assert decision.blocked is True
    assert decision.prior_operation_terminal is False
    assert decision.existing_operation == {
        "operation_id": checkpoint["operation_id"],
        "terminal": False,
        "recommended_action": "rollback",
    }


def test_closed_operation_allows_the_environment_to_be_reclassified():
    entry = _fixture("recovery-required")
    decision = classify_journey(
        _observation(entry),
        prior_operation={
            "operation_id": "op-" + "4" * 32,
            "terminal": True,
            "recommended_action": None,
        },
    )

    assert decision.journey == "legacy_upgrade"
    assert decision.prior_operation_terminal is True


def test_unidentified_invalid_prior_operation_still_blocks_classification():
    decision = classify_journey(
        _observation(_fixture("clean")),
        prior_operation_terminal=False,
    )

    assert decision.journey == "unclassified"
    assert decision.reason_code == "operation_reconciliation_required"
    assert decision.existing_operation is None
    assert decision.prior_operation_terminal is False


def test_prior_operation_identity_and_terminal_flag_cannot_disagree():
    with pytest.raises(ValueError, match="prior_operation_terminal_mismatch"):
        classify_journey(
            _observation(_fixture("clean")),
            prior_operation={
                "operation_id": "op-" + "a" * 32,
                "terminal": False,
                "recommended_action": "resume",
            },
            prior_operation_terminal=True,
        )


@pytest.mark.parametrize(
    ("field", "reason"),
    [
        ("current", "unsupported_current_lineage"),
        ("legacy", "unsupported_legacy_lineage"),
    ],
)
def test_unknown_plugin_lineage_fails_closed(field, reason):
    observation = _observation(_fixture("clean"))
    observation[field] = {"present": True, "enabled": True, "recognized": False}

    decision = classify_journey(observation)

    assert decision.journey == "coexistence_conflict"
    assert decision.reason_code == reason
    assert decision.blocked is True


def test_two_inactive_plugin_directories_are_ambiguous_not_fresh():
    decision = classify_journey(
        {
            "current": {"present": True, "enabled": False, "recognized": True},
            "legacy": {"present": True, "enabled": False, "recognized": True},
            "legacy_authority_capability": "unknown",
        }
    )

    assert decision.journey == "coexistence_conflict"
    assert decision.reason_code == "plugin_lineage_ambiguous"
    assert decision.blocked is True
