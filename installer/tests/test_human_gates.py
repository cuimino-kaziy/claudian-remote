import json

import pytest

from installer.claudian_remote_lifecycle.checkpoint import CheckpointStore
from installer.claudian_remote_lifecycle.human_gates import HumanGateController


def test_human_gate_survives_restart_and_chat_ack_cannot_satisfy_it(tmp_path):
    store = CheckpointStore(tmp_path / "state")
    checkpoint = store.create(command="install", plan_id="plan-a", phase="await_login")
    external_state = {"logged_in": False}
    controller = HumanGateController(store, {"tailscale_logged_in": lambda: external_state["logged_in"]})
    gate = controller.require(
        checkpoint["operation_id"],
        gate_type="tailscale_login_required",
        explanation="Tailscale must be logged in by the user.",
        exact_action="Open Tailscale and finish sign-in.",
        verification_probe="tailscale_logged_in",
    )

    persisted = CheckpointStore(tmp_path / "state").read(checkpoint["operation_id"])
    assert persisted["active_gate"] == gate.to_dict()
    blocked = controller.verify_and_resume(checkpoint["operation_id"], chat_acknowledged=True)
    assert blocked["verified"] is False
    assert blocked["code"] == "human_action_required"
    assert blocked["chat_acknowledged"] is True

    external_state["logged_in"] = True
    verified = HumanGateController(
        CheckpointStore(tmp_path / "state"),
        {"tailscale_logged_in": lambda: external_state["logged_in"]},
    ).verify_and_resume(checkpoint["operation_id"])
    assert verified["verified"] is True
    assert verified["checkpoint"]["active_gate"] == gate.to_dict()
    assert verified["checkpoint"]["state"] == "blocked"


def test_expired_gate_refreshes_under_the_same_operation(tmp_path):
    now = {"value": 1000.0}
    store = CheckpointStore(tmp_path / "state")
    checkpoint = store.create(command="install", plan_id="plan-a", phase="await_login")
    controller = HumanGateController(
        store,
        {"tailscale_logged_in": lambda: True},
        now=lambda: now["value"],
        gate_ttl_seconds=60,
    )
    original = controller.require(
        checkpoint["operation_id"],
        gate_type="tailscale_login_required",
        explanation="Tailscale must be logged in by the user.",
        exact_action="Open Tailscale and finish sign-in.",
        verification_probe="tailscale_logged_in",
    )

    now["value"] = 1060.0
    result = controller.verify(checkpoint["operation_id"])

    assert result["verified"] is False
    assert result["code"] == "human_gate_refreshed"
    assert result["checkpoint"]["operation_id"] == checkpoint["operation_id"]
    assert result["gate"]["gate_id"] != original.gate_id
    assert result["gate"]["refresh_generation"] == 1
    assert result["gate"]["expires_at_epoch"] == 1120


def test_gate_requires_a_known_verification_probe(tmp_path):
    store = CheckpointStore(tmp_path / "state")
    checkpoint = store.create(command="install", plan_id="plan-a")
    controller = HumanGateController(store, {})
    try:
        controller.require(
            checkpoint["operation_id"],
            gate_type="pairing_approval_required",
            explanation="Approve the displayed device on the Mac.",
            exact_action="Approve the matching code.",
            verification_probe="pairing_credential_active",
        )
    except ValueError as exc:
        assert str(exc) == "unknown_gate_probe"
    else:
        raise AssertionError("unknown probes must fail closed")


def test_operator_options_are_narrowly_validated_before_checkpointing(tmp_path):
    store = CheckpointStore(tmp_path / "state")
    checkpoint = store.create(command="install", plan_id="plan-a")
    controller = HumanGateController(store, {"ready": lambda: False})

    gate = controller.require(
        checkpoint["operation_id"],
        gate_type="tailscale_install_required",
        explanation="Install Tailscale.",
        exact_action="Use one supported route.",
        verification_probe="ready",
        operator_options=({
            "id": "agent_continue",
            "label": "由 Agent 继续操作",
            "instructions": "Open the official page.",
            "recommended": True,
            "url": "https://tailscale.com/download/mac",
            "requires_capability": "browser_control",
        },),
    )

    assert gate.to_dict()["operator_options"][0]["url"] == "https://tailscale.com/download/mac"
    with pytest.raises(ValueError, match="invalid_operator_option"):
        controller.require(
            checkpoint["operation_id"],
            gate_type="bad_option",
            explanation="Bad option.",
            exact_action="Reject it.",
            verification_probe="ready",
            operator_options=({
                "id": "manual",
                "label": "Manual",
                "instructions": "Open it.",
                "url": "http://attacker.example/collect?token=secret",
            },),
        )


def test_legacy_authority_gate_offers_agent_and_manual_routes_without_secret_data(
    tmp_path,
):
    store = CheckpointStore(tmp_path / "state")
    checkpoint = store.create(command="install", plan_id="plan-a")
    controller = HumanGateController(
        store,
        {"legacy_authority_authorized": lambda: False},
    )

    gate = controller.require(
        checkpoint["operation_id"],
        gate_type="legacy_authority_authorization_required",
        explanation="Authorize retirement for this installation only.",
        exact_action="Choose one supported authorization route.",
        verification_probe="legacy_authority_authorized",
        operator_options=(
            {
                "id": "agent_continue",
                "label": "由 Agent 继续",
                "instructions": "Use the pinned authority profile.",
                "recommended": True,
                "requires_capability": "legacy_retirement",
            },
            {
                "id": "manual_continue",
                "label": "我自己操作",
                "instructions": "Confirm the displayed authority identity.",
            },
        ),
    )

    encoded = json.dumps(gate.to_dict(), ensure_ascii=False)
    assert [item["id"] for item in gate.to_dict()["operator_options"]] == [
        "agent_continue",
        "manual_continue",
    ]
    assert "token" not in encoded.lower()


def test_agent_route_declares_capability_and_manual_route_is_human_only(tmp_path):
    store = CheckpointStore(tmp_path / "state")
    checkpoint = store.create(command="install", plan_id="plan-a")
    controller = HumanGateController(store, {"tailscale_logged_in": lambda: False})

    gate = controller.require(
        checkpoint["operation_id"],
        gate_type="tailscale_login_required",
        explanation="Tailscale must be signed in by the user.",
        exact_action="Open Tailscale and finish sign-in.",
        verification_probe="tailscale_logged_in",
        operator_options=(
            {
                "id": "agent_continue",
                "label": "由 Agent 继续操作",
                "instructions": "Open the installed Tailscale app and guide sign-in.",
                "recommended": True,
                "requires_capability": "computer_control",
            },
            {
                "id": "manual",
                "label": "我自己操作",
                "instructions": "Open the Tailscale app on this Mac and finish sign-in.",
            },
        ),
    )

    options = {item["id"]: item for item in gate.to_dict()["operator_options"]}
    assert options["agent_continue"]["requires_capability"] == "computer_control"
    assert "requires_capability" not in options["manual"]
    assert gate.resume_reference == checkpoint["operation_id"]
    assert gate.verification_probe == "tailscale_logged_in"
