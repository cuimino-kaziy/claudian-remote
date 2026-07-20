#!/usr/bin/env python3
"""Mac-side connector for the Claudian Remote relay."""

import argparse
import asyncio
import hashlib
import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set

try:
    from gateway.mac_companion.config import Keychain, MacOSKeychain, load_secret_fields
    from gateway.relay.crypto import PayloadCrypto, redact_text
except ImportError:  # pragma: no cover - script execution fallback
    import sys

    sys.path.append(str(Path(__file__).resolve().parents[2]))
    from gateway.mac_companion.config import Keychain, MacOSKeychain, load_secret_fields
    from gateway.relay.crypto import PayloadCrypto, redact_text


class CompanionError(Exception):
    pass


class AdapterTimeout(CompanionError):
    pass


@dataclass
class CompanionConfig:
    relay_base_url: str
    relay_token: str
    pairing_id: str
    adapter_base_url: str
    adapter_token: str
    payload_secret: str = ""
    poll_timeout_seconds: float = 15.0
    poll_interval_seconds: float = 2.0
    request_timeout_seconds: float = 10.0
    snapshot_interval_seconds: float = 10.0
    state_path: str = ""
    v2_state_path: str = ""
    relay_ws_url: str = ""
    bridge_sse_path: str = "/claudian-remote/v2/events"
    bridge_command_path: str = "/claudian-remote/v2/command"
    bridge_bind_path: str = "/claudian-remote/v2/transport/bind"
    bridge_invalidate_path: str = "/claudian-remote/v2/transport/invalidate"
    bridge_keyframe_path: str = "/claudian-remote/v2/keyframe"
    bridge_import_path: str = "/claudian-remote/v2/import"
    upload_temp_dir: str = ""
    upload_stream_bytes: int = 64 * 1024
    outbound_max_events: int = 256
    outbound_max_bytes: int = 2 * 1024 * 1024
    relay_heartbeat_seconds: float = 20.0
    reconnect_min_seconds: float = 0.25
    reconnect_max_seconds: float = 10.0
    shutdown_drain_seconds: float = 5.0

    @classmethod
    def from_file(cls, path: Path, keychain: Optional[Keychain] = None) -> "CompanionConfig":
        data = json.loads(path.read_text(encoding="utf-8"))
        secrets = load_secret_fields(data, keychain or MacOSKeychain())
        poll_timeout_seconds = float(data.get("poll_timeout_seconds", 15))
        request_timeout_seconds = max(float(data.get("request_timeout_seconds", 30)), poll_timeout_seconds + 5)
        return cls(
            relay_base_url=str(data.get("relay_base_url", "")).rstrip("/"),
            relay_token=secrets["relay_token"],
            pairing_id=str(data.get("pairing_id", "")),
            adapter_base_url=str(data.get("adapter_base_url", "")).rstrip("/"),
            adapter_token=secrets["adapter_token"],
            payload_secret=secrets["payload_secret"],
            poll_timeout_seconds=poll_timeout_seconds,
            poll_interval_seconds=float(data.get("poll_interval_seconds", 2)),
            request_timeout_seconds=request_timeout_seconds,
            snapshot_interval_seconds=float(data.get("snapshot_interval_seconds", 2)),
            state_path=str(data.get("state_path") or path.with_name("companion_state.json")),
            v2_state_path=str(data.get("v2_state_path") or path.with_name("companion_state_v2.json")),
            relay_ws_url=str(data.get("relay_ws_url") or ""),
            bridge_sse_path=str(data.get("bridge_sse_path") or "/claudian-remote/v2/events"),
            bridge_command_path=str(data.get("bridge_command_path") or "/claudian-remote/v2/command"),
            bridge_bind_path=str(data.get("bridge_bind_path") or "/claudian-remote/v2/transport/bind"),
            bridge_invalidate_path=str(data.get("bridge_invalidate_path") or "/claudian-remote/v2/transport/invalidate"),
            bridge_keyframe_path=str(data.get("bridge_keyframe_path") or "/claudian-remote/v2/keyframe"),
            bridge_import_path=str(data.get("bridge_import_path") or "/claudian-remote/v2/import"),
            upload_temp_dir=str(data.get("upload_temp_dir") or path.with_name("upload_temp")),
            upload_stream_bytes=min(64 * 1024, max(4096, int(data.get("upload_stream_bytes", 64 * 1024)))),
            outbound_max_events=max(16, int(data.get("outbound_max_events", 256))),
            outbound_max_bytes=max(64 * 1024, int(data.get("outbound_max_bytes", 2 * 1024 * 1024))),
            relay_heartbeat_seconds=float(data.get("relay_heartbeat_seconds", 20)),
            reconnect_min_seconds=max(0.05, float(data.get("reconnect_min_seconds", 0.25))),
            reconnect_max_seconds=max(0.25, float(data.get("reconnect_max_seconds", 10))),
            shutdown_drain_seconds=max(0.0, float(data.get("shutdown_drain_seconds", 5))),
        )

    def resolved_relay_ws_url(self) -> str:
        if self.relay_ws_url:
            return self.relay_ws_url
        parsed = urllib.parse.urlsplit(self.relay_base_url)
        scheme = "wss" if parsed.scheme == "https" else "ws"
        return urllib.parse.urlunsplit((scheme, parsed.netloc, "/api/v2/ws/mac", "", ""))

    def validate(self) -> None:
        missing = [
            name
            for name, value in [
                ("relay_base_url", self.relay_base_url),
                ("relay_token", self.relay_token),
                ("pairing_id", self.pairing_id),
                ("adapter_base_url", self.adapter_base_url),
                ("adapter_token", self.adapter_token),
            ]
            if not value
        ]
        if missing:
            raise CompanionError("missing companion config: " + ", ".join(missing))


class HttpJsonClient:
    def __init__(self, base_url: str, token: str, timeout_seconds: float = 10.0):
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.timeout_seconds = timeout_seconds

    def get(self, path: str, query: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        url = self.base_url + path
        if query:
            url += "?" + urllib.parse.urlencode(query)
        return self._request("GET", url, None)

    def post(self, path: str, body: Dict[str, Any]) -> Dict[str, Any]:
        return self._request("POST", self.base_url + path, body)

    def _request(self, method: str, url: str, body: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        data = None
        headers = {"Authorization": f"Bearer {self.token}", "Accept": "application/json"}
        if body is not None:
            data = json.dumps(scrub_json_text(body), ensure_ascii=False).encode("utf-8")
            headers["Content-Type"] = "application/json; charset=utf-8"
        request = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(request, timeout=self.timeout_seconds) as response:
                payload = response.read().decode("utf-8")
        except TimeoutError as exc:
            raise AdapterTimeout(str(exc)) from exc
        except urllib.error.URLError as exc:
            if isinstance(exc.reason, TimeoutError):
                raise AdapterTimeout(str(exc)) from exc
            raise CompanionError(str(exc)) from exc
        value = json.loads(payload or "{}")
        if not isinstance(value, dict):
            raise CompanionError("expected JSON object response")
        return value


class RelayClient:
    def join(self) -> Dict[str, Any]:
        raise NotImplementedError

    def heartbeat(self) -> Dict[str, Any]:
        raise NotImplementedError

    def poll(self, since: int, timeout_seconds: float) -> Dict[str, Any]:
        raise NotImplementedError

    def submit(self, event_type: str, body: Dict[str, Any], delivery_id: str, target_role: str = "mobile") -> Dict[str, Any]:
        raise NotImplementedError


def scrub_json_text(value: Any) -> Any:
    if isinstance(value, str):
        return "".join("\ufffd" if 0xD800 <= ord(char) <= 0xDFFF else char for char in value)
    if isinstance(value, list):
        return [scrub_json_text(item) for item in value]
    if isinstance(value, dict):
        return {str(scrub_json_text(key)): scrub_json_text(item) for key, item in value.items()}
    return value


class RelayHttpClient(RelayClient):
    def __init__(self, config: CompanionConfig):
        self._http = HttpJsonClient(config.relay_base_url, config.relay_token, config.request_timeout_seconds)

    def join(self) -> Dict[str, Any]:
        return self._http.post("/api/session/join", {"session_id": "mac-companion"})

    def heartbeat(self) -> Dict[str, Any]:
        return self._http.post("/api/session/heartbeat", {})

    def poll(self, since: int, timeout_seconds: float) -> Dict[str, Any]:
        return self._http.get("/api/events", {"since": since, "timeout": timeout_seconds})

    def submit(self, event_type: str, body: Dict[str, Any], delivery_id: str, target_role: str = "mobile") -> Dict[str, Any]:
        return self._http.post(
            "/api/envelopes",
            {
                "type": event_type,
                "delivery_id": delivery_id,
                "target_role": target_role,
                "body": body,
            },
        )


class AdapterClient:
    def submit_text(self, text: str, delivery_id: str, source: str) -> Dict[str, Any]:
        raise NotImplementedError

    def submit_approval(self, approval_id: str, value: str, delivery_id: str, source: str) -> Dict[str, Any]:
        raise NotImplementedError

    def snapshot(self) -> Dict[str, Any]:
        return {}


class LocalAdapterClient(AdapterClient):
    def __init__(self, config: CompanionConfig):
        self._http = HttpJsonClient(config.adapter_base_url, config.adapter_token, config.request_timeout_seconds)

    def submit_text(self, text: str, delivery_id: str, source: str) -> Dict[str, Any]:
        return self._http.post(
            "/claudian-remote/submit",
            {
                "text": text,
                "delivery_id": delivery_id,
                "source": source,
            },
        )

    def submit_approval(self, approval_id: str, value: str, delivery_id: str, source: str) -> Dict[str, Any]:
        return self._http.post(
            "/claudian-remote/approval",
            {
                "approval_id": approval_id,
                "value": value,
                "delivery_id": delivery_id,
                "source": source,
            },
        )

    def snapshot(self) -> Dict[str, Any]:
        return self._http.get("/claudian-remote/snapshot")


class MacCompanion:
    def __init__(self, config: CompanionConfig, relay: RelayClient, adapter: AdapterClient):
        config.validate()
        self.config = config
        self.relay = relay
        self.adapter = adapter
        self.crypto = PayloadCrypto(config.payload_secret, config.pairing_id) if config.payload_secret else None
        self.last_event_id = 0
        self.processed_delivery_ids: Set[str] = set()
        self.last_snapshot_at = 0.0
        self.last_snapshot_signature = ""
        self.state_path = Path(config.state_path).expanduser() if config.state_path else None
        self._load_state()

    @classmethod
    def from_config(cls, config: CompanionConfig) -> "MacCompanion":
        return cls(config, RelayHttpClient(config), LocalAdapterClient(config))

    def start(self) -> Dict[str, Any]:
        return self.relay.join()

    def run_once(self) -> List[Dict[str, Any]]:
        response = self.relay.poll(self.last_event_id, self.config.poll_timeout_seconds)
        events = response.get("events", [])
        if not events:
            events = self._recover_events_after_relay_reset()
        receipts = []
        saw_events = False
        for event in events:
            self.last_event_id = max(self.last_event_id, int(event.get("id", 0)))
            saw_events = True
            receipt = self.process_event(event)
            if receipt:
                receipts.append(receipt)
        if saw_events:
            self._save_state()
        if not receipts:
            self.relay.heartbeat()
            self.publish_snapshot_if_changed()
        return receipts

    def _recover_events_after_relay_reset(self) -> List[Dict[str, Any]]:
        if self.last_event_id <= 0:
            return []
        try:
            probe = self.relay.poll(0, 0)
        except Exception:
            return []
        events = probe.get("events", [])
        if not events:
            return []
        max_seen = max(int(event.get("id", 0)) for event in events)
        if max_seen >= self.last_event_id:
            return []
        self.last_event_id = 0
        self._save_state()
        return events

    def run_forever(self) -> None:
        self.start()
        while True:
            try:
                self.run_once()
            except Exception as exc:  # pragma: no cover - daemon resilience
                print(redact_text(f"companion loop error: {exc}"))
                time.sleep(self.config.poll_interval_seconds)

    def process_event(self, event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        if event.get("type") not in {"message.submit", "schedule.submit", "approval.respond", "snapshot.request"}:
            return None
        delivery_id = str(event.get("delivery_id") or "")
        if not delivery_id:
            return self._receipt("unknown", "failed", "missing delivery id")
        if delivery_id in self.processed_delivery_ids:
            return self._receipt(delivery_id, "duplicate", "already processed")

        try:
            payload = self._decode_payload(event.get("body") or {})
        except Exception as exc:
            return self._receipt(delivery_id, "failed", f"payload decode error: {exc}")

        if event.get("type") == "snapshot.request":
            self.processed_delivery_ids.add(delivery_id)
            self.publish_snapshot_if_changed(delivery_id=f"snapshot-{delivery_id}", force=True)
            return self._receipt(delivery_id, "accepted", "published desktop Claudian snapshot")

        if event.get("type") == "approval.respond":
            approval_id = str(payload.get("approval_id") or "").strip()
            value = str(payload.get("value") or payload.get("decision") or "").strip()
            if not approval_id or not value:
                return self._receipt(delivery_id, "failed", "missing approval decision")
            try:
                adapter_response = self.adapter.submit_approval(
                    approval_id=approval_id,
                    value=value,
                    delivery_id=delivery_id,
                    source=str(event.get("source_role") or "relay"),
                )
            except AdapterTimeout as exc:
                return self._receipt(delivery_id, "failed", f"adapter timeout: {exc}")
            except Exception as exc:
                return self._receipt(delivery_id, "failed", f"adapter error: {exc}")
            self.processed_delivery_ids.add(delivery_id)
            receipt = self._receipt(delivery_id, "accepted", "submitted approval to desktop Claudian", adapter_response)
            self.publish_snapshot_if_changed(delivery_id=f"snapshot-{delivery_id}", force=True)
            return receipt

        text = str(payload.get("text") or payload.get("prompt") or "").strip()
        if not text:
            return self._receipt(delivery_id, "failed", "empty text")

        try:
            adapter_response = self.adapter.submit_text(text=text, delivery_id=delivery_id, source=str(event.get("source_role") or "relay"))
        except AdapterTimeout as exc:
            return self._receipt(delivery_id, "failed", f"adapter timeout: {exc}")
        except Exception as exc:
            return self._receipt(delivery_id, "failed", f"adapter error: {exc}")

        self.processed_delivery_ids.add(delivery_id)
        receipt = self._receipt(delivery_id, "accepted", "submitted to desktop Claudian", adapter_response)
        self.publish_snapshot_if_changed(delivery_id=f"snapshot-{delivery_id}", force=True)
        return receipt

    def publish_snapshot_if_changed(self, delivery_id: Optional[str] = None, force: bool = False) -> Optional[Dict[str, Any]]:
        now = time.monotonic()
        if not force:
            interval = max(0.0, self.config.snapshot_interval_seconds)
            if interval and now - self.last_snapshot_at < interval:
                return None
        self.last_snapshot_at = now
        try:
            snapshot = self.adapter.snapshot()
        except Exception as exc:
            snapshot = {"available": False, "error": str(exc)}
        if not snapshot:
            return None

        payload = snapshot.get("snapshot", snapshot)
        signature = self._snapshot_signature(payload)
        if not force and signature == self.last_snapshot_signature:
            return None
        self.last_snapshot_signature = signature
        return self._submit_to_mobile(
            "conversation.snapshot",
            {"payload": payload},
            delivery_id=delivery_id or f"snapshot-sync-{int(time.time() * 1000)}",
        )

    @staticmethod
    def _snapshot_signature(payload: Dict[str, Any]) -> str:
        stable_payload = {
            "available": payload.get("available"),
            "conversation_id": payload.get("conversation_id"),
            "is_streaming": payload.get("is_streaming"),
            "queued_message_present": payload.get("queued_message_present"),
            "permission_pending": payload.get("permission_pending"),
            "ask_user_pending": payload.get("ask_user_pending"),
            "current_step": payload.get("current_step"),
            "activity": payload.get("activity") or {},
            "message_count": payload.get("message_count"),
            "messages": payload.get("messages") or [],
        }
        encoded = json.dumps(stable_payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    def _decode_payload(self, body: Dict[str, Any]) -> Dict[str, Any]:
        encrypted = body.get("encrypted_payload")
        if isinstance(encrypted, dict):
            if not self.crypto:
                raise CompanionError("encrypted payload received but payload_secret is not configured")
            return self.crypto.decrypt_json(encrypted)
        payload = body.get("payload")
        if isinstance(payload, dict):
            return payload
        return {}

    def _receipt(self, delivery_id: str, status: str, message: str, adapter_response: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        body = {
            "payload": {
                "delivery_id": delivery_id,
                "status": status,
                "message": message,
                "adapter": adapter_response or {},
            }
        }
        # Never include config or Local REST token data in relay-bound receipts.
        return self._submit_to_mobile("message.receipt", body, delivery_id=f"receipt-{delivery_id}")

    def _submit_to_mobile(self, event_type: str, body: Dict[str, Any], delivery_id: str) -> Dict[str, Any]:
        try:
            return self.relay.submit(event_type, body, delivery_id=delivery_id, target_role="mobile")
        except CompanionError as exc:
            # Relay refuses plaintext offline queueing by design. Receipts and snapshots are
            # opportunistic mobile updates, so mobile-offline refusal must not crash the Mac loop.
            return {"ok": False, "queued": False, "error": str(exc), "delivery_id": delivery_id}

    def _load_state(self) -> None:
        if not self.state_path or not self.state_path.exists():
            return
        try:
            state = json.loads(self.state_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return
        try:
            self.last_event_id = int(state.get("last_event_id") or 0)
        except (TypeError, ValueError):
            self.last_event_id = 0
        delivery_ids = state.get("processed_delivery_ids") or []
        if isinstance(delivery_ids, list):
            self.processed_delivery_ids = {str(item) for item in delivery_ids[-1000:]}
        self.last_snapshot_signature = str(state.get("last_snapshot_signature") or "")

    def _save_state(self) -> None:
        if not self.state_path:
            return
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "last_event_id": self.last_event_id,
            "processed_delivery_ids": sorted(self.processed_delivery_ids)[-1000:],
            "last_snapshot_signature": self.last_snapshot_signature,
        }
        tmp_path = self.state_path.with_suffix(self.state_path.suffix + ".tmp")
        tmp_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        os.chmod(tmp_path, 0o600)
        tmp_path.replace(self.state_path)


def main() -> None:
    parser = argparse.ArgumentParser(description="Mac companion for Claudian Remote relay")
    parser.add_argument("--config", required=True, help="Path to companion config JSON")
    args = parser.parse_args()
    config = CompanionConfig.from_file(Path(args.config))
    config.validate()
    from gateway.mac_companion.stream_pump import AsyncMacCompanion

    asyncio.run(AsyncMacCompanion.from_config(config).run_forever())


if __name__ == "__main__":
    main()
