"""Managed service entrypoints which resolve secrets only in process memory."""
from __future__ import annotations

import argparse
import json
import os
import tempfile
from pathlib import Path

from gateway.mac_companion.config import MacOSKeychain


def load_relay_config(path: Path, keychain=None):
    """Load a Relay config whose token values are Keychain references.

    ``RelayConfig`` predates the lifecycle manager and accepts token values.
    The compatibility shim feeds it a private, one-use file, unlinks the file
    immediately, and never places a credential in argv or the public config.
    """

    from gateway.relay.relay_server import RelayConfig

    keychain = keychain or MacOSKeychain()
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    for token in value.get("tokens", []):
        reference = str(token.pop("token_ref", ""))
        if token.get("token") or not reference:
            raise ValueError("relay_plaintext_or_missing_credential")
        token["token"] = keychain.get(reference)
    descriptor, temporary = tempfile.mkstemp(prefix="relay-runtime.", dir=Path(path).parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(value, handle, ensure_ascii=False, separators=(",", ":"))
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        return RelayConfig.from_file(Path(temporary))
    finally:
        Path(temporary).unlink(missing_ok=True)


def main(argv=None) -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("role", choices=("relay", "companion", "availability"))
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--status", type=Path)
    args = parser.parse_args(argv)
    if args.role == "availability":
        from .availability import ObsidianLauncher, validate_bound_vault_name
        from .private_io import write_private_json

        value = json.loads(args.config.read_text(encoding="utf-8"))
        if not isinstance(value, dict) or value.get("schema") != "claudian-remote.availability/v1":
            raise ValueError("availability_config_invalid")
        if args.status is None:
            raise ValueError("availability_status_path_required")
        vault_name = validate_bound_vault_name(value.get("vault_name"))
        base_status = {
            "schema": "claudian-remote.availability-status/v1",
            "vault_name": vault_name,
        }
        write_private_json(args.status, {**base_status, "state": "launching"})
        if not ObsidianLauncher().launch(vault_name):
            write_private_json(args.status, {**base_status, "state": "launch_failed"})
            raise RuntimeError("obsidian_launch_failed")
        write_private_json(args.status, {**base_status, "state": "launch_succeeded"})
    elif args.role == "relay":
        from gateway.relay.app import run_relay

        run_relay(load_relay_config(args.config))
    else:
        import asyncio

        from gateway.mac_companion.config import CompanionRuntimeConfig
        from gateway.mac_companion.stream_pump import AsyncMacCompanion

        config = CompanionRuntimeConfig.from_file(args.config)
        config.validate()
        asyncio.run(AsyncMacCompanion.from_config(config).run_forever())


if __name__ == "__main__":  # pragma: no cover
    main()
