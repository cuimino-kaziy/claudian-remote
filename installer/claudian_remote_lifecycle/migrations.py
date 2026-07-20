"""Non-secret migration steps used by the lifecycle transaction engine."""

from __future__ import annotations

import re
from typing import Any, Callable, Dict, Mapping, MutableMapping


MIGRATION_ID = "legacy_shared_token_v1"
VAULT_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$")


def _sync_preferences(value: Mapping[str, Any]) -> Dict[str, Any]:
    mode = str(value.get("connection_mode") or "")
    vault_id = str(value.get("vault_id") or "")
    if mode not in ("", "local_tailscale", "local_lan", "remote_vps"):
        mode = ""
    return {
        "schema_version": 2,
        "vault_id": vault_id if VAULT_ID.fullmatch(vault_id) else "",
        "connection_mode": mode,
        "notifications_enabled": value.get("notifications_enabled") if isinstance(value.get("notifications_enabled"), bool) else True,
        "haptics_enabled": value.get("haptics_enabled") if isinstance(value.get("haptics_enabled"), bool) else True,
    }


def migrate_legacy_shared_token(
    synchronized: Mapping[str, Any],
    state: MutableMapping[str, Any],
    revoke: Callable[[str], None],
    *,
    purge: bool = False,
) -> Dict[str, Any]:
    """Revoke a synchronized legacy token exactly once and emit no secret journal data."""
    migrations = state.setdefault("migrations", {})
    marker = migrations.get(MIGRATION_ID)
    if marker and marker.get("completed") is True:
        result = {
            "migration_id": MIGRATION_ID,
            "already_completed": True,
            "re_pair_required": bool(marker.get("re_pair_required")),
            "synchronized": _sync_preferences(synchronized),
            "remove_device_cache": bool(purge),
        }
        if purge:
            state["device_cache_present"] = False
        return result

    credential = str(synchronized.get("mobile_token") or synchronized.get("relayToken") or "")
    if credential:
        revoke(credential)
    marker = {"completed": True, "re_pair_required": bool(credential)}
    migrations[MIGRATION_ID] = marker
    if purge:
        state["device_cache_present"] = False
    return {
        "migration_id": MIGRATION_ID,
        "already_completed": False,
        "re_pair_required": bool(credential),
        "synchronized": _sync_preferences(synchronized),
        "remove_device_cache": bool(purge),
    }
