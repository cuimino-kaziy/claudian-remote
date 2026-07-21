"""Fail-closed credential revocation used by uninstall and purge."""

from __future__ import annotations

import re
from typing import Any, Callable, Mapping, Protocol


IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")


class CredentialStore(Protocol):
    def delete(self, reference: str) -> None: ...


class CredentialRevocationService:
    """Revoke every active mobile credential before deleting local secrets.

    The remote list is read again after the revoke requests.  This deliberately
    blocks uninstall while Relay is unavailable: deleting the local admin key
    without authoritative revocation could let an old phone credential become
    active again after a reinstall.
    """

    def __init__(
        self,
        *,
        list_devices: Callable[[], Mapping[str, Any]],
        revoke_device: Callable[[str], Mapping[str, Any]],
        credential_store: CredentialStore,
        credential_references: Callable[[], Mapping[str, Any]],
    ) -> None:
        self.list_devices = list_devices
        self.revoke_device = revoke_device
        self.credential_store = credential_store
        self.credential_references = credential_references

    @staticmethod
    def _active_device_ids(payload: Mapping[str, Any]) -> list[str]:
        devices = payload.get("devices")
        if not isinstance(devices, list):
            raise RuntimeError("device_list_invalid")
        identifiers: list[str] = []
        for item in devices:
            if not isinstance(item, Mapping):
                raise RuntimeError("device_list_invalid")
            identifier = str(item.get("device_id") or "")
            status = str(item.get("status") or "")
            revoked = item.get("revoked") is True or status == "revoked"
            if revoked:
                continue
            if not IDENTIFIER_RE.fullmatch(identifier):
                raise RuntimeError("device_list_invalid")
            identifiers.append(identifier)
        return sorted(set(identifiers))

    def revoke_all(self) -> None:
        try:
            active = self._active_device_ids(self.list_devices())
        except RuntimeError:
            raise
        except Exception as exc:
            raise RuntimeError("device_revocation_unavailable") from exc

        for identifier in active:
            try:
                outcome = self.revoke_device(identifier)
            except Exception as exc:
                raise RuntimeError("device_revocation_failed") from exc
            if outcome.get("state") != "ready" or outcome.get("code") != "device_revoked":
                raise RuntimeError("device_revocation_failed")

        try:
            remaining = self._active_device_ids(self.list_devices())
        except RuntimeError:
            raise
        except Exception as exc:
            raise RuntimeError("device_revocation_unavailable") from exc
        if remaining:
            raise RuntimeError("device_revocation_unverified")

        references = self.credential_references()
        for field in (
            "pairing_admin_credential_ref",
            "bridge_credential_ref",
            "relay_token_ref",
        ):
            reference = str(references.get(field) or "")
            if reference:
                self.credential_store.delete(reference)
