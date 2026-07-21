import json

from installer.claudian_remote_lifecycle.pairing import PairingAdminBootstrap, PairingLifecycle


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
