"""Versioned Relay policy loaded from the signed-set support matrix."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping


SUPPORT_MATRIX_PATH = Path(__file__).resolve().parents[2] / "release" / "support-matrix.json"


@dataclass(frozen=True)
class RelayLimits:
    terminal_recovery_seconds: int
    stale_in_flight_seconds: int
    upload_after_terminal_seconds: int
    upload_absolute_seconds: int
    max_file_bytes: int
    max_outstanding_bytes_per_installation: int
    max_concurrent_uploads: int
    max_frame_bytes: int
    managed_volume_refusal_percent: int

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "RelayLimits":
        expected = set(cls.__dataclass_fields__)
        if set(value) != expected:
            raise ValueError("support_matrix_relay_limits_mismatch")
        limits = cls(**{name: int(value[name]) for name in expected})
        if any(getattr(limits, name) <= 0 for name in expected):
            raise ValueError("support_matrix_relay_limit_invalid")
        if not 1 <= limits.managed_volume_refusal_percent <= 99:
            raise ValueError("support_matrix_watermark_invalid")
        return limits


def load_support_matrix(path: Path = SUPPORT_MATRIX_PATH) -> RelayLimits:
    document = json.loads(Path(path).read_text(encoding="utf-8"))
    return RelayLimits.from_mapping(document.get("relay_limits") or {})


DEFAULT_LIMITS = load_support_matrix()
