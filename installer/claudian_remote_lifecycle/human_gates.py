"""Persistent human-only gates verified by injected external probes."""

from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass
from typing import Any, Callable, Mapping

from .checkpoint import CheckpointStore


@dataclass(frozen=True)
class HumanGate:
    gate_id: str
    gate_type: str
    explanation: str
    exact_action: str
    verification_probe: str
    resume_reference: str
    status: str = "waiting"

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


class HumanGateController:
    def __init__(self, checkpoints: CheckpointStore, probes: Mapping[str, Callable[[], bool]]) -> None:
        self.checkpoints = checkpoints
        self.probes = dict(probes)

    def require(
        self,
        operation_id: str,
        *,
        gate_type: str,
        explanation: str,
        exact_action: str,
        verification_probe: str,
    ) -> HumanGate:
        if verification_probe not in self.probes:
            raise ValueError("unknown_gate_probe")
        identity = f"{operation_id}:{gate_type}:{verification_probe}".encode("utf-8")
        gate = HumanGate(
            gate_id="gate-" + hashlib.sha256(identity).hexdigest()[:24],
            gate_type=gate_type,
            explanation=explanation,
            exact_action=exact_action,
            verification_probe=verification_probe,
            resume_reference=operation_id,
        )
        self.checkpoints.update(operation_id, state="blocked", active_gate=gate.to_dict())
        return gate

    def verify_and_resume(self, operation_id: str, *, chat_acknowledged: bool = False) -> dict[str, Any]:
        """Resume only on external probe success; chat acknowledgement is ignored."""

        checkpoint = self.checkpoints.read(operation_id)
        gate = checkpoint.get("active_gate")
        if not gate:
            return {"verified": True, "checkpoint": checkpoint}
        probe_name = gate["verification_probe"]
        probe = self.probes.get(probe_name)
        try:
            verified = probe is not None and bool(probe())
        except Exception:  # A failed external probe is never approval.
            verified = False
        if not verified:
            return {
                "verified": False,
                "code": "human_action_required",
                "gate": gate,
                "chat_acknowledged": bool(chat_acknowledged),
            }
        checkpoint = self.checkpoints.update(operation_id, state="prepared", active_gate=None)
        return {"verified": True, "checkpoint": checkpoint}
