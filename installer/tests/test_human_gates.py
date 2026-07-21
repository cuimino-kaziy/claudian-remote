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
    resumed = HumanGateController(
        CheckpointStore(tmp_path / "state"),
        {"tailscale_logged_in": lambda: external_state["logged_in"]},
    ).verify_and_resume(checkpoint["operation_id"])
    assert resumed["verified"] is True
    assert resumed["checkpoint"]["active_gate"] is None
    assert resumed["checkpoint"]["state"] == "prepared"


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
