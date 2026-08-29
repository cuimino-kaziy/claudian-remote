import json

import pytest

from installer.claudian_remote_lifecycle.pairing import (
    PairingAdminBootstrap,
    PairingIdentityTransition,
    PairingLifecycle,
)


PROFILE = {
    "mode": "local_tailscale",
    "installation_id": "installation-a",
    "vault_id": "vault-a",
    "endpoint_audience": "claudian-remote:local_tailscale:installation-a",
}


class FakePairingManagement:
    claim = "seeded-one-time-claim"
    durable_credential = "seeded-durable-mobile-credential"
    admin_secret = "seeded-pairing-admin-secret"

    def __init__(self):
        self.claims = {}
        self.revoked = []

    def create_claim(self, profile):
        assert profile == PROFILE
        self.claims["claim-a"] = {"state": "pending_redemption", "profile": dict(profile)}
        return {
            "claim_id": "claim-a",
            "claim": self.claim,
            "short_code": "ABCD2345",
            "deep_link": f"obsidian://claudian-remote?claim={self.claim}",
            "admin_secret": self.admin_secret,
            "expires_at": 999,
        }

    def inspect_claim(self, claim_id):
        return {"claim_id": claim_id, **self.claims[claim_id]}

    def approve_claim(self, claim_id, device_id):
        self.claims[claim_id] = {
            **self.claims[claim_id],
            "state": "credential_ready",
            "device_id": device_id,
        }
        return {
            "claim_id": claim_id,
            "state": "credential_ready",
            "device_id": device_id,
            "credential": self.durable_credential,
        }

    def revoke_device(self, device_id):
        self.revoked.append(device_id)
        return {"device_id": device_id, "state": "revoked", "credential": self.durable_credential}


def assert_agent_safe(value):
    encoded = json.dumps(value, sort_keys=True)
    assert FakePairingManagement.claim not in encoded
    assert FakePairingManagement.durable_credential not in encoded
    assert FakePairingManagement.admin_secret not in encoded
    assert "obsidian://" not in encoded
    assert "/Users/" not in encoded


def test_pairing_begin_presents_claim_only_to_human_ui_and_returns_verifiable_gate():
    management = FakePairingManagement()
    presented = []
    lifecycle = PairingLifecycle(management, presented.append)

    result = lifecycle.begin(PROFILE)

    assert presented == [
        {
            "claim_id": "claim-a",
            "claim": FakePairingManagement.claim,
            "short_code": "ABCD2345",
            "deep_link": f"obsidian://claudian-remote?claim={FakePairingManagement.claim}",
            "admin_secret": FakePairingManagement.admin_secret,
            "expires_at": 999,
        }
    ]
    assert result == {
        "state": "blocked",
        "ready": False,
        "code": "pairing_approval_required",
        "gate": {
            "gate_type": "pairing_approval_required",
            "explanation": "A person must redeem the code on the phone and approve that device on the Mac.",
            "human_action": "Use the code shown in the Mac pairing window, then review and approve the displayed phone.",
            "verification_probe": "pairing_claim_state",
            "resume_reference": result["gate"]["resume_reference"],
        },
    }
    assert result["gate"]["resume_reference"].startswith("pairing:")
    assert_agent_safe(result)


def test_pairing_admin_bootstrap_requires_verified_device_local_secure_reference():
    bootstrap = PairingAdminBootstrap()

    blocked = bootstrap.inspect(credential_ref=None, verify_ref=lambda _ref: False)
    assert blocked["gate"]["gate_type"] == "pairing_admin_bootstrap_required"
    assert blocked["gate"]["verification_probe"] == "pairing_admin_secure_reference"

    ready = bootstrap.inspect(
        credential_ref="keychain:pairing-admin",
        verify_ref=lambda ref: ref == "keychain:pairing-admin",
    )
    assert ready == {
        "state": "ready",
        "ready": True,
        "pairing_admin": {"credential_ref": "<secure-reference>"},
    }
    assert "keychain:pairing-admin" not in json.dumps(ready)


def test_pairing_resume_requires_verified_pending_device_then_returns_only_safe_identity():
    management = FakePairingManagement()
    lifecycle = PairingLifecycle(management, lambda _created: None)
    started = lifecycle.begin(PROFILE)
    resume_reference = started["gate"]["resume_reference"]

    waiting = lifecycle.resume(resume_reference)
    assert waiting["state"] == "blocked"
    assert waiting["gate"]["gate_type"] == "pairing_redemption_required"

    management.claims["claim-a"].update({"state": "pending_approval", "device_id": "iphone-a"})
    approval = lifecycle.resume(resume_reference)
    assert approval["gate"]["gate_type"] == "pairing_device_confirmation_required"
    assert approval["device"] == {"device_id": "iphone-a"}

    approved = lifecycle.approve(resume_reference, confirmed_device_id="iphone-a")
    assert approved["state"] == "blocked"
    assert approved["gate"]["gate_type"] == "pairing_mobile_completion_required"
    management.claims["claim-a"]["state"] = "issued"
    completed = lifecycle.resume(resume_reference)
    assert completed == {
        "state": "paired",
        "ready": True,
        "device": {"device_id": "iphone-a"},
        "profile": PROFILE,
        "repair_required": False,
    }
    assert_agent_safe(waiting)
    assert_agent_safe(approval)
    assert_agent_safe(completed)


def test_revoke_and_repair_paths_are_explicit_and_never_reuse_credentials():
    management = FakePairingManagement()
    lifecycle = PairingLifecycle(management, lambda _created: None)

    revoked = lifecycle.revoke("iphone-a", reason="lost_device")
    assert revoked == {
        "state": "revoked",
        "ready": False,
        "device": {"device_id": "iphone-a"},
        "reason": "lost_device",
        "re_pair_required": True,
        "restore_cache": False,
        "reuse_credential": False,
    }
    assert management.revoked == ["iphone-a"]

    for reason in ("legacy_token_migration", "profile_changed", "suspected_disclosure"):
        repair = lifecycle.repair_required(reason)
        assert repair["state"] == "blocked"
        assert repair["code"] == "new_pairing_required"
        assert repair["re_pair_required"] is True
        assert repair["restore_cache"] is False
        assert repair["reuse_credential"] is False
        assert repair["gate"]["gate_type"] == "pairing_repair_required"
        assert_agent_safe(repair)


def test_current_update_preserve_keeps_the_existing_device_without_revocation(tmp_path):
    devices = {"iphone-a"}
    revoked = []
    transition = PairingIdentityTransition(
        tmp_path,
        active_device_ids=lambda: devices,
        revoke_device=lambda device_id, reason: revoked.append((device_id, reason)),
    )
    operation_id = "op-" + "a" * 32
    plan_id = "plan-" + "a" * 64

    transition.capture(operation_id=operation_id, plan_id=plan_id, policy="preserve")
    result = transition.finalize(
        operation_id=operation_id, plan_id=plan_id, policy="preserve"
    )

    assert result == {
        "state": "ready",
        "code": "pairing_identity_preserved",
        "re_pair_required": False,
    }
    assert revoked == []


def test_current_update_rotate_revokes_once_and_requires_a_deliberate_new_device(tmp_path):
    devices = {"iphone-old"}
    revoked = []

    def revoke(device_id, reason):
        revoked.append((device_id, reason))
        devices.discard(device_id)
        return {"state": "ready", "code": "device_revoked"}

    transition = PairingIdentityTransition(
        tmp_path,
        active_device_ids=lambda: devices,
        revoke_device=revoke,
    )
    operation_id = "op-" + "b" * 32
    plan_id = "plan-" + "b" * 64
    transition.capture(operation_id=operation_id, plan_id=plan_id, policy="rotate")

    waiting = transition.finalize(
        operation_id=operation_id, plan_id=plan_id, policy="rotate"
    )
    assert waiting == {
        "state": "blocked",
        "code": "pairing_approval_required",
        "re_pair_required": True,
    }
    assert revoked == [("iphone-old", "profile_changed")]

    assert transition.finalize(
        operation_id=operation_id, plan_id=plan_id, policy="rotate"
    ) == waiting
    assert revoked == [("iphone-old", "profile_changed")]

    devices.add("iphone-new")
    assert transition.finalize(
        operation_id=operation_id, plan_id=plan_id, policy="rotate"
    ) == {
        "state": "ready",
        "code": "pairing_identity_rotated",
        "re_pair_required": False,
    }


def test_operation_rotation_committed_accepts_valid_preserve_journal(
    tmp_path,
) -> None:
    transition = PairingIdentityTransition(
        tmp_path,
        active_device_ids=lambda: ["iphone-existing"],
    )
    operation_id = "op-" + "d" * 32
    plan_id = "plan-" + "d" * 64

    transition.capture(
        operation_id=operation_id,
        plan_id=plan_id,
        policy="preserve",
    )

    assert transition.operation_rotation_committed(
        operation_id=operation_id,
        plan_id=plan_id,
    ) is False

    assert transition.finalize(
        operation_id=operation_id,
        plan_id=plan_id,
        policy="preserve",
    )["state"] == "ready"
    assert transition.rollback(
        operation_id=operation_id,
        plan_id=plan_id,
        policy="preserve",
    ) is True


def test_rotation_checkpoint_is_irreversible_and_replay_safe_after_interruption(tmp_path):
    devices = {"iphone-old"}
    revoked = []
    interrupted = {"enabled": True}

    def revoke(device_id, reason):
        revoked.append((device_id, reason))
        devices.discard(device_id)
        return {"state": "ready"}

    def interrupt(phase):
        if interrupted["enabled"]:
            raise RuntimeError(phase)

    transition = PairingIdentityTransition(
        tmp_path,
        active_device_ids=lambda: devices,
        revoke_device=revoke,
        interruption_probe=interrupt,
    )
    operation_id = "op-" + "c" * 32
    plan_id = "plan-" + "c" * 64
    transition.capture(operation_id=operation_id, plan_id=plan_id, policy="rotate")

    with pytest.raises(RuntimeError, match="after_pairing_identity_rotation"):
        transition.finalize(
            operation_id=operation_id, plan_id=plan_id, policy="rotate"
        )

    assert transition.rotation_committed(
        operation_id=operation_id, plan_id=plan_id, policy="rotate"
    ) is True
    assert transition.rollback(
        operation_id=operation_id, plan_id=plan_id, policy="rotate"
    ) is False

    interrupted["enabled"] = False
    devices.add("iphone-new")
    assert transition.finalize(
        operation_id=operation_id, plan_id=plan_id, policy="rotate"
    )["state"] == "ready"
    assert revoked == [("iphone-old", "profile_changed")]
