"""Persistent human-only gates verified by injected external probes."""

from __future__ import annotations

import hashlib
import re
import time
import urllib.parse
from dataclasses import asdict, dataclass, field
from typing import Any, Callable, Mapping

from .checkpoint import CheckpointStore


@dataclass(frozen=True)
class OperatorOption:
    option_id: str
    label: str
    instructions: str
    recommended: bool = False
    url: str | None = None
    requires_capability: str | None = None

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "OperatorOption":
        option_id = str(value.get("id") or "")
        label = str(value.get("label") or "")
        instructions = str(value.get("instructions") or "")
        recommended = value.get("recommended", False)
        url = value.get("url")
        capability = value.get("requires_capability")
        if (
            not re.fullmatch(r"[a-z][a-z0-9_]{1,31}", option_id)
            or not label
            or len(label) > 80
            or not instructions
            or len(instructions) > 1000
            or not isinstance(recommended, bool)
            or any(character in label + instructions for character in ("\x00", "\r"))
        ):
            raise ValueError("invalid_operator_option")
        if url is not None:
            parsed = urllib.parse.urlsplit(str(url))
            if (
                parsed.scheme != "https"
                or not parsed.hostname
                or parsed.username
                or parsed.password
                or parsed.query
                or parsed.fragment
            ):
                raise ValueError("invalid_operator_option")
            url = urllib.parse.urlunsplit(parsed)
        if capability is not None and not re.fullmatch(
            r"[a-z][a-z0-9_]{1,63}", str(capability)
        ):
            raise ValueError("invalid_operator_option")
        return cls(
            option_id=option_id,
            label=label,
            instructions=instructions,
            recommended=recommended,
            url=str(url) if url is not None else None,
            requires_capability=str(capability) if capability is not None else None,
        )

    def to_dict(self) -> dict[str, Any]:
        value = {
            "id": self.option_id,
            "label": self.label,
            "instructions": self.instructions,
            "recommended": self.recommended,
        }
        if self.url is not None:
            value["url"] = self.url
        if self.requires_capability is not None:
            value["requires_capability"] = self.requires_capability
        return value


@dataclass(frozen=True)
class HumanGate:
    gate_id: str
    gate_type: str
    explanation: str
    exact_action: str
    verification_probe: str
    resume_reference: str
    operator_options: tuple[OperatorOption, ...] = field(default_factory=tuple)
    status: str = "waiting"
    created_at_epoch: int = 0
    expires_at_epoch: int = 0
    refresh_generation: int = 0

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["operator_options"] = [option.to_dict() for option in self.operator_options]
        return value


class HumanGateController:
    def __init__(
        self,
        checkpoints: CheckpointStore,
        probes: Mapping[str, Callable[[], bool]],
        *,
        now: Callable[[], float] = time.time,
        gate_ttl_seconds: int = 1800,
    ) -> None:
        if gate_ttl_seconds < 60:
            raise ValueError("invalid_gate_ttl")
        self.checkpoints = checkpoints
        self.probes = dict(probes)
        self.now = now
        self.gate_ttl_seconds = gate_ttl_seconds

    def _gate(
        self,
        operation_id: str,
        *,
        gate_type: str,
        explanation: str,
        exact_action: str,
        verification_probe: str,
        operator_options: tuple[Mapping[str, Any] | OperatorOption, ...],
        refresh_generation: int,
    ) -> HumanGate:
        created_at = int(self.now())
        identity = (
            f"{operation_id}:{gate_type}:{verification_probe}:{refresh_generation}"
        ).encode("utf-8")
        return HumanGate(
            gate_id="gate-" + hashlib.sha256(identity).hexdigest()[:24],
            gate_type=gate_type,
            explanation=explanation,
            exact_action=exact_action,
            verification_probe=verification_probe,
            resume_reference=operation_id,
            operator_options=tuple(
                option
                if isinstance(option, OperatorOption)
                else OperatorOption.from_mapping(option)
                for option in operator_options
            ),
            created_at_epoch=created_at,
            expires_at_epoch=created_at + self.gate_ttl_seconds,
            refresh_generation=refresh_generation,
        )

    def require(
        self,
        operation_id: str,
        *,
        gate_type: str,
        explanation: str,
        exact_action: str,
        verification_probe: str,
        operator_options: tuple[Mapping[str, Any] | OperatorOption, ...] = (),
    ) -> HumanGate:
        if verification_probe not in self.probes:
            raise ValueError("unknown_gate_probe")
        gate = self._gate(
            operation_id,
            gate_type=gate_type,
            explanation=explanation,
            exact_action=exact_action,
            verification_probe=verification_probe,
            operator_options=operator_options,
            refresh_generation=0,
        )
        self.checkpoints.update(operation_id, state="blocked", active_gate=gate.to_dict())
        return gate

    def refresh(self, operation_id: str) -> dict[str, Any]:
        """Refresh an expired gate without creating or switching operations."""

        checkpoint = self.checkpoints.read(operation_id)
        raw_gate = checkpoint.get("active_gate")
        if not isinstance(raw_gate, Mapping):
            raise ValueError("active_gate_required")
        options = tuple(
            option for option in raw_gate.get("operator_options", ())
            if isinstance(option, Mapping)
        )
        gate = self._gate(
            operation_id,
            gate_type=str(raw_gate["gate_type"]),
            explanation=str(raw_gate["explanation"]),
            exact_action=str(raw_gate["exact_action"]),
            verification_probe=str(raw_gate["verification_probe"]),
            operator_options=options,
            refresh_generation=int(raw_gate["refresh_generation"]) + 1,
        )
        return self.checkpoints.update(
            operation_id,
            state="blocked",
            active_gate=gate.to_dict(),
        )

    def verify(self, operation_id: str, *, chat_acknowledged: bool = False) -> dict[str, Any]:
        """Probe a gate without clearing it before the guarded mutation commits."""

        checkpoint = self.checkpoints.read(operation_id)
        gate = checkpoint.get("active_gate")
        if not gate:
            return {"verified": True, "checkpoint": checkpoint}
        if int(gate["expires_at_epoch"]) <= int(self.now()):
            refreshed = self.refresh(operation_id)
            return {
                "verified": False,
                "code": "human_gate_refreshed",
                "gate": refreshed["active_gate"],
                "checkpoint": refreshed,
                "chat_acknowledged": bool(chat_acknowledged),
            }
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
        return {"verified": True, "checkpoint": checkpoint}

    def verify_and_resume(self, operation_id: str, *, chat_acknowledged: bool = False) -> dict[str, Any]:
        """Compatibility name for the read-only gate verifier."""

        return self.verify(operation_id, chat_acknowledged=chat_acknowledged)
