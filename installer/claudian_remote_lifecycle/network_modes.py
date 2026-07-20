"""Profile switching transaction boundary with no automatic fallback."""

from __future__ import annotations

from typing import Any, Callable, Mapping

from .connection_profile import ConnectionProfile, ConnectionProfileStore, LifecycleAuthority


class ConnectionModeController:
    def __init__(self, store: ConnectionProfileStore, authority: LifecycleAuthority) -> None:
        self.store = store
        self.authority = authority

    def switch(
        self,
        candidate: ConnectionProfile,
        *,
        validate: Callable[[ConnectionProfile], Mapping[str, Any]],
    ) -> dict[str, Any]:
        candidate.validate()
        prior = self.store.read() if self.store.path.exists() else None
        steps = ["settle_active_turn", "stop_old_exposure", "validate_new_endpoint"]
        profile_changed = prior is not None and any(
            getattr(prior, field) != getattr(candidate, field)
            for field in ("mode", "installation_id", "vault_id", "endpoint", "endpoint_audience")
        )
        if profile_changed and (
            prior.companion_credential_ref == candidate.companion_credential_ref
            or prior.mobile_credential_ref == candidate.mobile_credential_ref
        ):
            return {
                "state": "blocked",
                "code": "profile_credential_rotation_required",
                "mode": candidate.mode,
                "ready": False,
                "fallback_performed": False,
                "prior_profile_restored": True,
                "steps": steps + ["restore_prior_profile"],
            }
        outcome = dict(validate(candidate))
        if outcome.get("state") != "ready":
            return {
                **outcome,
                "mode": candidate.mode,
                "fallback_performed": False,
                "prior_profile_restored": prior is not None,
                "steps": steps + (["restore_prior_profile"] if prior else []),
            }
        steps.extend(["rotate_profile_credentials", "reset_cursor_epoch", "commit_profile"])
        self.store.write(candidate, authority=self.authority)
        return {
            **outcome,
            "mode": candidate.mode,
            "fallback_performed": False,
            "steps": steps,
        }


class LocalRuntimePlanner:
    """Describe owned process state without touching launchd or the network."""

    def plan(self, profile: ConnectionProfile) -> dict[str, Any]:
        profile.validate()
        local = profile.mode in {"local_tailscale", "local_lan"}
        return {
            "companion": {
                "desired": "running",
                "health_check": "authenticated_bridge_and_relay",
            },
            "relay": {
                "desired": "running" if local else "stopped",
                "bind": "127.0.0.1:8787" if local else None,
                "health_check": "authenticated_loopback" if local else "must_not_listen",
            },
            "exposure": (
                "tailscale_serve" if profile.mode == "local_tailscale"
                else "lan_tls_gateway" if profile.mode == "local_lan"
                else "none"
            ),
        }
