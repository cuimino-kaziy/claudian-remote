from __future__ import annotations

import json
import os
from datetime import datetime, timezone

from installer.claudian_remote_lifecycle.diagnostics import DiagnosticService


def unsafe_observation(secret: str) -> dict:
    return {
        "components": {"plugin": "0.2.0-beta.1", "relay": "0.2.0-beta.1", "extra": secret},
        "lifecycle": {"state": "blocked", "phase": "verify", "raw_path": f"/Users/{secret}"},
        "reason_codes": ["relay_offline", secret],
        "connection": {
            "mode": "local_tailscale",
            "transport_status": "disconnected",
            "endpoint": f"https://{secret}.invalid/path",
            "pairing_state": secret,
        },
        "counters": {"failed_checks": 2},
        "argv": ["--password", secret],
        "environment": {"TOKEN": secret},
        "stack": f"trace: {secret}",
        "content": f"markdown {secret}",
    }


def test_agent_summary_is_typed_and_ignores_arbitrary_sensitive_fields():
    marker = "CANARY-SECRET-秘密"
    service = DiagnosticService(clock=lambda: datetime(2026, 7, 21, tzinfo=timezone.utc))
    encoded = json.dumps(service.agent_safe_summary(unsafe_observation(marker)), ensure_ascii=False)
    assert marker not in encoded
    assert "/Users/" not in encoded
    assert "https://" not in encoded
    assert "pairing_state" not in encoded
    assert "relay_offline" in encoded


def test_semantic_looking_ascii_secrets_cannot_cross_allowlisted_fields():
    marker = "sk_live_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnop"
    observation = unsafe_observation(marker)
    observation["components"]["plugin"] = marker
    observation["components"]["protocol"] = marker
    observation["lifecycle"]["phase"] = marker
    observation["reason_codes"] = [marker]
    observation["connection"]["mode"] = marker
    service = DiagnosticService(clock=lambda: datetime(2026, 7, 21, tzinfo=timezone.utc))

    encoded = json.dumps(service.agent_safe_summary(observation))

    assert marker not in encoded
    assert encoded.count("unknown") >= 5


def test_export_requires_verified_confirmation_and_writes_private_local_file(tmp_path):
    marker = "CANARY-SECRET-秘密"
    service = DiagnosticService(clock=lambda: datetime(2026, 7, 21, tzinfo=timezone.utc))
    destination = (tmp_path / "diagnostics.json").resolve()
    blocked = service.export(unsafe_observation(marker), destination, confirmation_verified=False)
    assert blocked["code"] == "diagnostic_export_confirmation_required"
    assert not destination.exists()

    ready = service.export(unsafe_observation(marker), destination, confirmation_verified=True)
    assert ready["code"] == "diagnostic_export_ready"
    assert ready["uploaded"] is False
    assert os.stat(destination).st_mode & 0o777 == 0o600
    text = destination.read_text(encoding="utf-8")
    assert marker not in text
    assert "/Users/" not in text
    assert "https://" not in text
    assert service.delete_export(destination) is True
    assert not destination.exists()
