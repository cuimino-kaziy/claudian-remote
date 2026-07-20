#!/usr/bin/env python3
"""HTTP fallback relay for Claudian Remote V0."""

import argparse
import json
import os
import secrets
import threading
import time
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, urlparse

try:
    from .crypto import redact_text
    from .config import DEFAULT_LIMITS
except ImportError:  # pragma: no cover - script execution fallback
    from crypto import redact_text
    from config import DEFAULT_LIMITS


VERSION = "0.2.0-beta.1"
ROLES = {"mac", "mobile"}
ALLOWED_EVENT_TYPES = {
    "mac": {"message.receipt", "conversation.snapshot", "conversation.event"},
    "mobile": {"message.submit", "approval.respond", "snapshot.request"},
}


@dataclass(frozen=True)
class RelayToken:
    name: str
    role: str
    pairing_id: str
    token: str
    installation_id: str = ""
    vault_id: str = ""
    device_id: str = ""
    endpoint_audience: str = ""
    revoked: bool = False
    generation: int = 1


@dataclass
class RelayConfig:
    host: str = "127.0.0.1"
    port: int = 8787
    public_base_url: str = "https://relay.example.invalid"
    fallback_base_url: str = ""
    installation_id: str = "installation-test"
    vault_id: str = "vault-test"
    endpoint_audience: str = "claudian-remote:local_tailscale:installation-test"
    presence_ttl_seconds: float = 45.0
    max_events_per_poll: int = 100
    max_stored_events: int = 5000
    tokens: List[RelayToken] = field(default_factory=list)
    database_path: str = "/var/lib/claudian-remote-relay/relay-v2.db"
    enable_v1_compatibility: bool = False
    allowed_origins: List[str] = field(default_factory=lambda: ["app://obsidian.md", "capacitor://localhost"])
    ticket_ttl_seconds: float = 30.0
    ticket_auth_timeout_seconds: float = 5.0
    websocket_heartbeat_seconds: float = 20.0
    websocket_max_message_bytes: int = DEFAULT_LIMITS.max_frame_bytes
    client_queue_max_events: int = 256
    client_queue_max_bytes: int = 2 * 1024 * 1024
    retention_seconds: float = DEFAULT_LIMITS.stale_in_flight_seconds
    completed_grace_seconds: float = DEFAULT_LIMITS.terminal_recovery_seconds
    event_store_max_bytes: int = 64 * 1024 * 1024
    event_store_max_rows: int = 100_000
    upload_root: str = "/var/lib/claudian-remote-relay/uploads"
    upload_ttl_seconds: float = DEFAULT_LIMITS.upload_after_terminal_seconds
    upload_absolute_seconds: float = DEFAULT_LIMITS.upload_absolute_seconds
    upload_max_file_bytes: int = DEFAULT_LIMITS.max_file_bytes
    upload_max_outstanding_bytes_per_installation: int = DEFAULT_LIMITS.max_outstanding_bytes_per_installation
    upload_max_concurrent: int = DEFAULT_LIMITS.max_concurrent_uploads
    managed_volume_refusal_percent: int = DEFAULT_LIMITS.managed_volume_refusal_percent
    upload_chunk_bytes: int = 1024 * 1024
    upload_stream_bytes: int = 64 * 1024
    upload_reserve_min_bytes: int = 1024 * 1024 * 1024
    upload_reserve_fraction: float = 0.10

    def __post_init__(self) -> None:
        if self.host not in {"127.0.0.1", "::1", "localhost"}:
            raise ValueError("relay_must_bind_loopback")
        if self.fallback_base_url:
            raise ValueError("relay_fallback_forbidden")
        exact_limits = {
            "retention_seconds": DEFAULT_LIMITS.stale_in_flight_seconds,
            "completed_grace_seconds": DEFAULT_LIMITS.terminal_recovery_seconds,
            "upload_ttl_seconds": DEFAULT_LIMITS.upload_after_terminal_seconds,
            "upload_absolute_seconds": DEFAULT_LIMITS.upload_absolute_seconds,
            "upload_max_file_bytes": DEFAULT_LIMITS.max_file_bytes,
            "upload_max_outstanding_bytes_per_installation": DEFAULT_LIMITS.max_outstanding_bytes_per_installation,
            "upload_max_concurrent": DEFAULT_LIMITS.max_concurrent_uploads,
            "websocket_max_message_bytes": DEFAULT_LIMITS.max_frame_bytes,
            "managed_volume_refusal_percent": DEFAULT_LIMITS.managed_volume_refusal_percent,
        }
        if any(float(getattr(self, name)) != float(expected) for name, expected in exact_limits.items()):
            raise ValueError("relay_limit_drift")
        bound = []
        for item in self.tokens:
            bound.append(
                RelayToken(
                    name=item.name,
                    role=item.role,
                    pairing_id=item.pairing_id,
                    token=item.token,
                    installation_id=item.installation_id or self.installation_id,
                    vault_id=item.vault_id or self.vault_id,
                    device_id=item.device_id or item.name,
                    endpoint_audience=item.endpoint_audience or self.endpoint_audience,
                    revoked=item.revoked,
                    generation=item.generation,
                )
            )
        self.tokens = bound

    @classmethod
    def from_file(cls, path: Path) -> "RelayConfig":
        data = json.loads(path.read_text(encoding="utf-8"))
        tokens = [
            RelayToken(
                name=str(item["name"]),
                role=str(item["role"]),
                pairing_id=str(item["pairing_id"]),
                token=str(item["token"]),
                installation_id=str(item.get("installation_id") or ""),
                vault_id=str(item.get("vault_id") or ""),
                device_id=str(item.get("device_id") or ""),
                endpoint_audience=str(item.get("endpoint_audience") or ""),
                revoked=bool(item.get("revoked", False)),
                generation=int(item.get("generation", 1)),
            )
            for item in data.get("tokens", [])
        ]
        return cls(
            host=str(data.get("host", "127.0.0.1")),
            port=int(data.get("port", 8787)),
            public_base_url=str(data.get("public_base_url", "https://relay.example.invalid")),
            fallback_base_url=str(data.get("fallback_base_url", "")),
            installation_id=str(data.get("installation_id") or "installation-test"),
            vault_id=str(data.get("vault_id") or "vault-test"),
            endpoint_audience=str(data.get("endpoint_audience") or "claudian-remote:local_tailscale:installation-test"),
            presence_ttl_seconds=float(data.get("presence_ttl_seconds", 45)),
            max_events_per_poll=int(data.get("max_events_per_poll", 100)),
            max_stored_events=int(data.get("max_stored_events", 5000)),
            tokens=tokens,
            database_path=str(data.get("database_path", "/var/lib/claudian-remote-relay/relay-v2.db")),
            enable_v1_compatibility=bool(data.get("enable_v1_compatibility", False)),
            allowed_origins=[str(item) for item in data.get("allowed_origins", ["app://obsidian.md", "capacitor://localhost"])],
            ticket_ttl_seconds=float(data.get("ticket_ttl_seconds", 30)),
            ticket_auth_timeout_seconds=float(data.get("ticket_auth_timeout_seconds", 5)),
            websocket_heartbeat_seconds=float(data.get("websocket_heartbeat_seconds", 20)),
            websocket_max_message_bytes=int(data.get("websocket_max_message_bytes", DEFAULT_LIMITS.max_frame_bytes)),
            client_queue_max_events=int(data.get("client_queue_max_events", 256)),
            client_queue_max_bytes=int(data.get("client_queue_max_bytes", 2 * 1024 * 1024)),
            retention_seconds=float(data.get("retention_seconds", DEFAULT_LIMITS.stale_in_flight_seconds)),
            completed_grace_seconds=float(data.get("completed_grace_seconds", DEFAULT_LIMITS.terminal_recovery_seconds)),
            event_store_max_bytes=int(data.get("event_store_max_bytes", 64 * 1024 * 1024)),
            event_store_max_rows=int(data.get("event_store_max_rows", 100_000)),
            upload_root=str(data.get("upload_root", "/var/lib/claudian-remote-relay/uploads")),
            upload_ttl_seconds=float(data.get("upload_ttl_seconds", DEFAULT_LIMITS.upload_after_terminal_seconds)),
            upload_absolute_seconds=float(data.get("upload_absolute_seconds", DEFAULT_LIMITS.upload_absolute_seconds)),
            upload_max_file_bytes=int(data.get("upload_max_file_bytes", DEFAULT_LIMITS.max_file_bytes)),
            upload_max_outstanding_bytes_per_installation=int(data.get("upload_max_outstanding_bytes_per_installation", DEFAULT_LIMITS.max_outstanding_bytes_per_installation)),
            upload_max_concurrent=int(data.get("upload_max_concurrent", DEFAULT_LIMITS.max_concurrent_uploads)),
            managed_volume_refusal_percent=int(data.get("managed_volume_refusal_percent", DEFAULT_LIMITS.managed_volume_refusal_percent)),
            upload_chunk_bytes=min(1024 * 1024, max(1, int(data.get("upload_chunk_bytes", 1024 * 1024)))),
            upload_stream_bytes=min(64 * 1024, max(4096, int(data.get("upload_stream_bytes", 64 * 1024)))),
            upload_reserve_min_bytes=max(0, int(data.get("upload_reserve_min_bytes", 1024 * 1024 * 1024))),
            upload_reserve_fraction=max(0.0, min(0.90, float(data.get("upload_reserve_fraction", 0.10)))),
        )

    def token_index(self) -> Dict[str, RelayToken]:
        return {item.token: item for item in self.tokens}


@dataclass
class RelayEvent:
    id: int
    pairing_id: str
    target_role: str
    source_role: str
    type: str
    body: Dict[str, Any]
    created_at: float
    delivery_id: str

    def public_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "pairing_id": self.pairing_id,
            "target_role": self.target_role,
            "source_role": self.source_role,
            "type": self.type,
            "body": self.body,
            "created_at": self.created_at,
            "delivery_id": self.delivery_id,
        }


@dataclass
class Presence:
    online: bool = False
    last_seen: float = 0.0
    session_id: Optional[str] = None


class RelayService:
    def __init__(self, config: RelayConfig):
        self.config = config
        self._tokens = config.token_index()
        self._events: List[RelayEvent] = []
        self._presence: Dict[str, Dict[str, Presence]] = {}
        self._next_event_id = 1
        self._lock = threading.Condition()

    def authenticate(self, authorization: str) -> Optional[RelayToken]:
        prefix = "Bearer "
        if not authorization.startswith(prefix):
            return None
        presented = authorization[len(prefix):].strip()
        for token_value, token in self._tokens.items():
            if secrets.compare_digest(token_value, presented):
                return token
        return None

    def presence_snapshot(self, pairing_id: str) -> Dict[str, bool]:
        room = self._presence.setdefault(pairing_id, {})
        return {role: room.get(role, Presence()).online for role in sorted(ROLES)}

    def join(self, token: RelayToken, session_id: Optional[str] = None, now: Optional[float] = None) -> Dict[str, Any]:
        self._validate_token(token)
        now = time.time() if now is None else now
        with self._lock:
            room = self._presence.setdefault(token.pairing_id, {})
            room[token.role] = Presence(online=True, last_seen=now, session_id=session_id or secrets.token_urlsafe(12))
            self._append_event_locked(
                pairing_id=token.pairing_id,
                source_role=token.role,
                target_role=self.counterpart(token.role),
                event_type="presence.changed",
                body={"role": token.role, "online": True},
                delivery_id=f"presence-{token.role}-{int(now * 1000)}",
                now=now,
            )
            self._lock.notify_all()
            return {
                "ok": True,
                "role": token.role,
                "pairing_id": token.pairing_id,
                "session_id": room[token.role].session_id,
                "presence": self.presence_snapshot(token.pairing_id),
            }

    def heartbeat(self, token: RelayToken, now: Optional[float] = None) -> Dict[str, Any]:
        self._validate_token(token)
        now = time.time() if now is None else now
        with self._lock:
            room = self._presence.setdefault(token.pairing_id, {})
            current = room.get(token.role, Presence())
            room[token.role] = Presence(online=True, last_seen=now, session_id=current.session_id)
            return {"ok": True, "presence": self.presence_snapshot(token.pairing_id)}

    def submit(self, token: RelayToken, body: Dict[str, Any], now: Optional[float] = None) -> Tuple[int, Dict[str, Any]]:
        self._validate_token(token)
        now = time.time() if now is None else now
        target_role = str(body.get("target_role") or self.counterpart(token.role))
        if target_role not in ROLES or target_role == token.role:
            return 400, {"ok": False, "error": "invalid_target_role"}

        event_type = str(body.get("type") or "message.submit")
        if event_type not in ALLOWED_EVENT_TYPES.get(token.role, set()):
            return 403, {"ok": False, "error": "event_type_not_allowed"}
        envelope = body.get("body")
        if not isinstance(envelope, dict):
            return 400, {"ok": False, "error": "invalid_body"}

        encrypted_payload = envelope.get("encrypted_payload")
        plaintext_payload = envelope.get("payload")
        with self._lock:
            self._expire_presence_locked(now)
            room = self._presence.setdefault(token.pairing_id, {})
            current_presence = room.get(token.role, Presence())
            room[token.role] = Presence(
                online=True,
                last_seen=now,
                session_id=current_presence.session_id or secrets.token_urlsafe(12),
            )
            target_online = self._presence.get(token.pairing_id, {}).get(target_role, Presence()).online
            has_plaintext_body = bool(plaintext_payload)
            has_encrypted_body = isinstance(encrypted_payload, dict)
            if not target_online and has_plaintext_body and not has_encrypted_body:
                return 409, {
                    "ok": False,
                    "error": "offline_queue_requires_encryption",
                    "target_online": False,
                }
            delivery_id = str(body.get("delivery_id") or secrets.token_urlsafe(18))
            event = self._append_event_locked(
                pairing_id=token.pairing_id,
                source_role=token.role,
                target_role=target_role,
                event_type=event_type,
                body=envelope,
                delivery_id=delivery_id,
                now=now,
            )
            self._lock.notify_all()
            return 202, {
                "ok": True,
                "event_id": event.id,
                "delivery_id": delivery_id,
                "target_online": target_online,
                "queued": not target_online,
            }

    def poll(self, token: RelayToken, since: int = 0, timeout_seconds: float = 0.0, now: Optional[float] = None) -> Dict[str, Any]:
        self._validate_token(token)
        deadline = time.time() + max(0.0, min(timeout_seconds, 25.0))
        with self._lock:
            while True:
                current_now = time.time() if now is None else now
                self._expire_presence_locked(current_now)
                events = self._events_for(token, since)
                if events or time.time() >= deadline or timeout_seconds <= 0:
                    return {
                        "ok": True,
                        "events": [event.public_dict() for event in events[: self.config.max_events_per_poll]],
                        "presence": self.presence_snapshot(token.pairing_id),
                        "latest_event_id": self._latest_event_id_for(token),
                    }
                self._lock.wait(timeout=min(1.0, deadline - time.time()))

    def _latest_event_id_for(self, token: RelayToken) -> int:
        ids = [
            event.id
            for event in self._events
            if event.pairing_id == token.pairing_id and event.target_role == token.role
        ]
        return max(ids, default=0)

    def health(self) -> Dict[str, Any]:
        return {
            "ok": True,
            "service": "claudian-remote-relay",
            "version": VERSION,
            "public_base_url": self.config.public_base_url,
            "fallback_base_url": self.config.fallback_base_url,
        }

    def _events_for(self, token: RelayToken, since: int) -> List[RelayEvent]:
        return [
            event
            for event in self._events
            if event.pairing_id == token.pairing_id
            and event.target_role == token.role
            and event.id > since
        ]

    def _append_event_locked(
        self,
        pairing_id: str,
        source_role: str,
        target_role: str,
        event_type: str,
        body: Dict[str, Any],
        delivery_id: str,
        now: float,
    ) -> RelayEvent:
        event = RelayEvent(
            id=self._next_event_id,
            pairing_id=pairing_id,
            source_role=source_role,
            target_role=target_role,
            type=event_type,
            body=body,
            created_at=now,
            delivery_id=delivery_id,
        )
        self._events.append(event)
        if len(self._events) > self.config.max_stored_events:
            self._events = self._events[-self.config.max_stored_events :]
        self._next_event_id += 1
        return event

    def _expire_presence_locked(self, now: float) -> None:
        for pairing_id, room in list(self._presence.items()):
            for role, presence in list(room.items()):
                if not presence.online:
                    continue
                if now - presence.last_seen <= self.config.presence_ttl_seconds:
                    continue
                presence.online = False
                self._append_event_locked(
                    pairing_id=pairing_id,
                    source_role=role,
                    target_role=self.counterpart(role),
                    event_type="presence.changed",
                    body={"role": role, "online": False},
                    delivery_id=f"presence-{role}-offline-{int(now * 1000)}",
                    now=now,
                )
                self._lock.notify_all()

    @staticmethod
    def counterpart(role: str) -> str:
        if role == "mac":
            return "mobile"
        if role == "mobile":
            return "mac"
        raise ValueError("invalid role")

    @staticmethod
    def _validate_token(token: RelayToken) -> None:
        if token.role not in ROLES:
            raise ValueError("invalid token role")
        if not token.pairing_id:
            raise ValueError("token pairing_id is required")


class RelayHandler(BaseHTTPRequestHandler):
    service: RelayService

    def log_message(self, fmt: str, *args: Any) -> None:
        print(redact_text("[%s] %s %s" % (time.strftime("%Y-%m-%dT%H:%M:%S"), self.address_string(), fmt % args)))

    def send_json(self, status: int, payload: Dict[str, Any]) -> None:
        raw = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Authorization, Content-Type")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.end_headers()
        self.wfile.write(raw)

    def do_OPTIONS(self) -> None:
        self.send_json(200, {"ok": True})

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/health":
            self.send_json(200, self.service.health())
            return
        token = self._auth()
        if token is None:
            self.send_json(401, {"ok": False, "error": "unauthorized"})
            return
        if parsed.path == "/api/events":
            query = parse_qs(parsed.query)
            since = int(query.get("since", ["0"])[0] or 0)
            timeout = float(query.get("timeout", ["0"])[0] or 0)
            self.send_json(200, self.service.poll(token, since=since, timeout_seconds=timeout))
            return
        self.send_json(404, {"ok": False, "error": "not_found"})

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        token = self._auth()
        if token is None:
            self.send_json(401, {"ok": False, "error": "unauthorized"})
            return
        try:
            body = self._read_body()
        except json.JSONDecodeError:
            self.send_json(400, {"ok": False, "error": "invalid_json"})
            return
        if parsed.path == "/api/session/join":
            self.send_json(200, self.service.join(token, session_id=str(body.get("session_id") or "") or None))
            return
        if parsed.path == "/api/session/heartbeat":
            self.send_json(200, self.service.heartbeat(token))
            return
        if parsed.path == "/api/envelopes":
            status, payload = self.service.submit(token, body)
            self.send_json(status, payload)
            return
        self.send_json(404, {"ok": False, "error": "not_found"})

    def _auth(self) -> Optional[RelayToken]:
        return self.service.authenticate(self.headers.get("Authorization", ""))

    def _read_body(self) -> Dict[str, Any]:
        length = int(self.headers.get("Content-Length", "0") or 0)
        if length <= 0:
            return {}
        raw = self.rfile.read(length).decode("utf-8")
        value = json.loads(raw or "{}")
        if not isinstance(value, dict):
            raise json.JSONDecodeError("expected object", raw, 0)
        return value


def build_service(config_path: Optional[str]) -> RelayService:
    if config_path:
        config = RelayConfig.from_file(Path(config_path))
    else:
        config = RelayConfig(
            tokens=[
                RelayToken(name="local-mac", role="mac", pairing_id="local", token=os.environ.get("CLAUDIAN_RELAY_MAC_TOKEN", secrets.token_urlsafe(32))),
                RelayToken(name="local-mobile", role="mobile", pairing_id="local", token=os.environ.get("CLAUDIAN_RELAY_MOBILE_TOKEN", secrets.token_urlsafe(32))),
            ]
        )
    return RelayService(config)


def main() -> None:
    parser = argparse.ArgumentParser(description="Claudian Remote Relay HTTP fallback service")
    parser.add_argument("--config", help="Path to relay config JSON")
    parser.add_argument("--host", help="Override bind host")
    parser.add_argument("--port", type=int, help="Override bind port")
    args = parser.parse_args()

    service = build_service(args.config)
    if args.host:
        service.config.host = args.host
    if args.port:
        service.config.port = args.port
    from gateway.relay.app import run_relay

    run_relay(service.config)


if __name__ == "__main__":
    main()
