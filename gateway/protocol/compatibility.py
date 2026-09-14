"""Exact, secret-free compatibility metadata shared by Companion and Relay."""

from __future__ import annotations

from typing import Any, Dict, Mapping


COMPATIBILITY_SET: Dict[str, Any] = {
    "id": "claudian-remote-0.2.0-beta.6.7",
    "plugin": "0.2.0-beta.6.7",
    "companion": "0.2.0-beta.6.7",
    "relay": "0.2.0-beta.6.7",
    "protocol": "claudian.remote.v2",
    "configuration_schema": 1,
}


def evaluate_compatibility(actual: Any) -> Dict[str, Any]:
    source: Mapping[str, Any] = actual if isinstance(actual, Mapping) else {}
    mismatches = [
        {
            "component": component,
            "current": source.get(component),
            "required": required,
        }
        for component, required in COMPATIBILITY_SET.items()
        if source.get(component) != required
    ]
    return {
        "writable": not mismatches,
        "mode": "streaming" if not mismatches else "read_only",
        "reason": "ready" if not mismatches else "compatibility_set_mismatch",
        "mismatches": mismatches,
        "actual": {key: source.get(key) for key in COMPATIBILITY_SET},
        "required": dict(COMPATIBILITY_SET),
        "remediation": None if not mismatches else "Update Claudian Remote components to one compatible release set",
    }


def combine_compatibility(actual: Any, downstream: Any = None) -> Dict[str, Any]:
    result = evaluate_compatibility(actual)
    if not isinstance(downstream, Mapping) or downstream.get("writable") is not True:
        reason = (
            str(downstream.get("reason") or "bridge_compatibility_missing")
            if isinstance(downstream, Mapping)
            else "bridge_compatibility_missing"
        )
        return {
            **result,
            "writable": False,
            "mode": "read_only",
            "reason": reason,
            "mismatches": list(downstream.get("mismatches") or result["mismatches"])
            if isinstance(downstream, Mapping)
            else result["mismatches"],
            "remediation": str(downstream.get("remediation") or result["remediation"] or "Update required components")
            if isinstance(downstream, Mapping)
            else "Update the Claudian Remote plugin and reconnect",
        }
    return result
