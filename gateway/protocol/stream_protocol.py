"""Executable contract for the Claudian Remote v2 semantic stream.

The module deliberately uses only the Python standard library so the protocol
fixtures can be checked before either the v2 Relay or Companion environment is
installed.  It is a strict boundary validator, not a general JSON schema
implementation.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, Mapping, Optional, Set


PROTOCOL = "claudian.remote.v2"
WS_SUBPROTOCOL = PROTOCOL
MAX_EVENT_BYTES = 64 * 1024
MAX_FRAME_BYTES = 1024 * 1024


class ProtocolError(ValueError):
    """A stable, machine-readable protocol validation failure."""

    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(code if not detail else f"{code}: {detail}")
        self.code = code
        self.detail = detail


EVENT_FIELDS: Dict[str, Set[str]] = {
    "capability.state": {
        "mode", "supports_turn_steer", "supports_history", "supports_stop",
        "supports_approval", "reason", "writable", "current_version",
        "required_version", "missing_capabilities", "remediation",
    },
    "conversation.activated": {"conversation_id", "title"},
    "history.list": {"items", "next_page"},
    "turn.started": {"status", "started_at"},
    "activity.updated": {"stage", "label", "detail", "status", "duration_ms"},
    "tool.started": {"tool_name", "label", "status", "started_at"},
    "tool.completed": {"tool_name", "label", "status", "duration_ms", "summary"},
    "approval.requested": {"approval_id", "title", "options", "status"},
    "approval.resolved": {"approval_id", "selected", "status", "resolved_by"},
    "text.delta": {"text", "base_revision", "offset"},
    "text.replace": {"text"},
    "artifact.available": {"artifact_id", "kind", "label", "vault_path", "url", "size"},
    "keyframe.page": {"keyframe_id", "page_index", "page_count", "projection"},
    "keyframe.final": {"keyframe_id", "page_count", "checksum", "revision"},
    "turn.completed": {"status", "duration_ms", "checksum"},
    "turn.interrupted": {"status", "duration_ms", "queued_draft_returned"},
    "turn.failed": {"status", "error_code", "message"},
    "command.receipt": {"delivery_id", "status", "error_code", "message"},
    "presence.changed": {"role", "status", "mac_session_id", "mac_connection_generation"},
    "resync.required": {"reason", "retained_floor", "epoch"},
}

TERMINAL_EVENTS = {"turn.completed", "turn.interrupted", "turn.failed"}
KEYFRAME_EVENTS = {"keyframe.page", "keyframe.final"}

COMMAND_FIELDS: Dict[str, Set[str]] = {
    "message.submit": {"text", "attachment_refs", "mode"},
    "turn.stop": set(),
    "turn.steer": {"text"},
    "approval.respond": {"approval_id", "value"},
    "history.list": {"page"},
    "history.select": {"conversation_id"},
    "keyframe.request": {"reason"},
    "upload.cancel": {"upload_id"},
}

ROUTE_AUTH_MATRIX = {
    ("POST", "/api/v2/ws-ticket"): {"mobile"},
    ("GET", "/api/v2/ws/mobile"): {"mobile_ticket"},
    ("GET", "/api/v2/ws/mac"): {"mac"},
    ("POST", "/api/v2/commands"): {"mobile"},
    ("POST", "/api/v2/uploads"): {"mobile"},
    ("GET", "/api/v2/uploads"): {"mac"},
    ("GET", "/health"): {"pairing_admin"},
    ("POST", "/api/v2/pairing/claims"): {"pairing_admin"},
    ("POST", "/api/v2/pairing/redeem"): {"pairing_claim"},
    ("POST", "/api/v2/pairing/approve"): {"pairing_admin"},
}

_BASE_EVENT_KEYS = {
    "protocol",
    "kind",
    "event_type",
    "source",
    "entity",
    "revision",
    "payload",
    "occurred_at",
}
_BASE_COMMAND_KEYS = {
    "protocol",
    "kind",
    "command_type",
    "delivery_id",
    "mac_session_id",
    "mac_connection_generation",
    "expires_at",
    "expected_revision",
    "target",
    "payload",
}
_ENTITY_KEYS = {"conversation_id", "turn_id", "message_id", "block_id", "approval_id"}
_TARGET_KEYS = {"conversation_id", "turn_id", "message_id", "block_id", "approval_id"}
_FORBIDDEN_KEYS = {
    "thinking",
    "reasoning",
    "chain_of_thought",
    "tool_args",
    "tool_input",
    "raw_input",
    "command",
    "command_line",
    "shell",
    "token",
    "role_token",
    "ticket",
    "authorization",
    "secret",
    "api_key",
}
_SECRET_VALUE_PATTERNS = (
    re.compile(r"(?i)authorization\s*:\s*bearer\s+\S+"),
    re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+\-/]+=*"),
    re.compile(r"(?i)\b(?:sk|sess|token|ticket)-[A-Za-z0-9_-]{8,}"),
)
_ABSOLUTE_PATH_PATTERNS = (
    re.compile(r"(?:^|[\s'\"(])/(?:Users|home|var|private|Volumes)/[^\s'\")]+"),
    re.compile(r"(?:^|[\s'\"(])[A-Za-z]:\\[^\s'\")]+"),
)
_TRANSPORT_KEYS = {"cursor", "epoch", "received_at", "transport", "checksum"}


def _require_mapping(value: Any, code: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ProtocolError(code)
    return value


def _require_nonempty_string(value: Any, code: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ProtocolError(code)
    return value


def _require_nonnegative_int(value: Any, code: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ProtocolError(code)
    return value


def _reject_unknown(mapping: Mapping[str, Any], allowed: Iterable[str], code: str) -> None:
    unknown = set(mapping) - set(allowed)
    if unknown:
        raise ProtocolError(code, ",".join(sorted(unknown)))


def _encoded_size(value: Any) -> int:
    return len(json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))


def _parse_rfc3339(value: Any) -> datetime:
    text = _require_nonempty_string(value, "invalid_expires_at")
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise ProtocolError("invalid_expires_at") from exc
    if parsed.tzinfo is None:
        raise ProtocolError("invalid_expires_at")
    return parsed.astimezone(timezone.utc)


def event_uid(event: Mapping[str, Any]) -> str:
    source = _require_mapping(event.get("source"), "missing_source")
    instance_id = _require_nonempty_string(source.get("instance_id"), "missing_source_instance")
    sequence = _require_nonnegative_int(source.get("sequence"), "missing_source_sequence")
    return f"{instance_id}:{sequence}"


def _scan_source_firewall(value: Any, path: str = "payload") -> None:
    if isinstance(value, Mapping):
        for key, nested in value.items():
            lowered = str(key).lower()
            if lowered in _FORBIDDEN_KEYS:
                raise ProtocolError("forbidden_source_field", f"{path}.{key}")
            _scan_source_firewall(nested, f"{path}.{key}")
        return
    if isinstance(value, list):
        for index, nested in enumerate(value):
            _scan_source_firewall(nested, f"{path}[{index}]")
        return
    if isinstance(value, str):
        for pattern in _ABSOLUTE_PATH_PATTERNS:
            if pattern.search(value):
                raise ProtocolError("absolute_path_forbidden", path)
        for pattern in _SECRET_VALUE_PATTERNS:
            if pattern.search(value):
                raise ProtocolError("secret_value_forbidden", path)


def validate_event(event: Mapping[str, Any]) -> Mapping[str, Any]:
    event = _require_mapping(event, "event_not_object")
    if event.get("protocol") != PROTOCOL or event.get("kind") != "event":
        raise ProtocolError("unsupported_protocol")
    _reject_unknown(event, _BASE_EVENT_KEYS, "unknown_event_field")
    if _encoded_size(event) > (MAX_FRAME_BYTES if event.get("event_type") in KEYFRAME_EVENTS else MAX_EVENT_BYTES):
        raise ProtocolError("payload_too_large")

    event_type = _require_nonempty_string(event.get("event_type"), "missing_event_type")
    allowed_payload = EVENT_FIELDS.get(event_type)
    if allowed_payload is None:
        raise ProtocolError("unknown_event_type", event_type)
    source = _require_mapping(event.get("source"), "missing_source")
    _reject_unknown(source, {"instance_id", "sequence"}, "unknown_source_field")
    event_uid(event)
    entity = _require_mapping(event.get("entity"), "missing_entity")
    _reject_unknown(entity, _ENTITY_KEYS, "unknown_entity_field")
    _require_nonempty_string(entity.get("conversation_id"), "missing_conversation_id")
    _require_nonnegative_int(event.get("revision"), "missing_revision")
    payload = _require_mapping(event.get("payload"), "missing_payload")
    _scan_source_firewall(payload)
    _reject_unknown(payload, allowed_payload, "forbidden_payload_field")

    if event_type.startswith("turn.") and not entity.get("turn_id"):
        raise ProtocolError("missing_turn_id")
    if event_type.startswith("text."):
        for key in ("turn_id", "message_id", "block_id"):
            _require_nonempty_string(entity.get(key), f"missing_{key}")
        if not isinstance(payload.get("text"), str):
            raise ProtocolError("missing_text")
    if event_type == "text.delta":
        _require_nonnegative_int(payload.get("base_revision"), "missing_text_base_revision")
        _require_nonnegative_int(payload.get("offset"), "missing_text_offset")
        if payload["base_revision"] + 1 != event["revision"]:
            raise ProtocolError("invalid_text_base_revision")
    if event_type == "keyframe.page":
        index = _require_nonnegative_int(payload.get("page_index"), "invalid_keyframe_page")
        count = _require_nonnegative_int(payload.get("page_count"), "invalid_keyframe_page")
        if count == 0 or index >= count:
            raise ProtocolError("invalid_keyframe_page")
        _require_mapping(payload.get("projection"), "invalid_keyframe_projection")
    if event_type in {"keyframe.final", "turn.completed"}:
        checksum = _require_nonempty_string(payload.get("checksum"), "missing_checksum")
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", checksum):
            raise ProtocolError("invalid_checksum")
    return event


def validate_command(command: Mapping[str, Any], now: Optional[datetime] = None) -> Mapping[str, Any]:
    command = _require_mapping(command, "command_not_object")
    if command.get("protocol") != PROTOCOL or command.get("kind") != "command":
        raise ProtocolError("unsupported_protocol")
    _reject_unknown(command, _BASE_COMMAND_KEYS, "unknown_command_field")
    if _encoded_size(command) > MAX_FRAME_BYTES:
        raise ProtocolError("payload_too_large")
    command_type = _require_nonempty_string(command.get("command_type"), "missing_command_type")
    allowed_payload = COMMAND_FIELDS.get(command_type)
    if allowed_payload is None:
        raise ProtocolError("unknown_command_type", command_type)
    _require_nonempty_string(command.get("delivery_id"), "missing_delivery_id")
    _require_nonempty_string(command.get("mac_session_id"), "missing_mac_session_id")
    generation = command.get("mac_connection_generation")
    if isinstance(generation, bool) or not isinstance(generation, int) or generation <= 0:
        raise ProtocolError("missing_mac_connection_generation")
    expires_at = _parse_rfc3339(command.get("expires_at"))
    reference = now or datetime.now(timezone.utc)
    if reference.tzinfo is None:
        reference = reference.replace(tzinfo=timezone.utc)
    if expires_at <= reference.astimezone(timezone.utc):
        raise ProtocolError("command_expired")
    _require_nonnegative_int(command.get("expected_revision"), "missing_expected_revision")
    target = _require_mapping(command.get("target"), "missing_target")
    _reject_unknown(target, _TARGET_KEYS, "unknown_target_field")
    _require_nonempty_string(target.get("conversation_id"), "missing_conversation_id")
    payload = _require_mapping(command.get("payload"), "missing_payload")
    _reject_unknown(payload, allowed_payload, "forbidden_payload_field")
    if command_type in {"turn.stop", "turn.steer"}:
        _require_nonempty_string(target.get("turn_id"), "missing_turn_id")
    if command_type == "approval.respond":
        _require_nonempty_string(target.get("approval_id") or payload.get("approval_id"), "missing_approval_id")
    if command_type == "message.submit":
        text = payload.get("text")
        if not isinstance(text, str):
            raise ProtocolError("missing_text")
        attachments = payload.get("attachment_refs", [])
        if not isinstance(attachments, list) or len(attachments) > 16:
            raise ProtocolError("invalid_attachment_refs")
        for index, item in enumerate(attachments):
            reference = _require_mapping(item, "invalid_attachment_ref")
            _reject_unknown(reference, {"upload_id", "vault_path", "label"}, "unknown_attachment_field")
            _require_nonempty_string(reference.get("upload_id"), "missing_upload_id")
            vault_path = _require_nonempty_string(reference.get("vault_path"), "missing_vault_path")
            if vault_path.startswith(("/", "\\")) or "\\" in vault_path or ".." in vault_path.split("/"):
                raise ProtocolError("invalid_vault_path", str(index))
        if not text.strip() and not attachments:
            raise ProtocolError("empty_message")
    return command


def authorize_route(method: str, path: str, credential_role: str) -> bool:
    return credential_role in ROUTE_AUTH_MATRIX.get((method.upper(), path), set())


def negotiate_protocol(offered: Iterable[str]) -> Dict[str, Any]:
    offered_set = set(offered)
    if PROTOCOL in offered_set:
        return {"protocol": PROTOCOL, "mode": "streaming", "compatible": True}
    return {
        "protocol": "claudian.remote.v1",
        "mode": "compatibility_snapshot",
        "compatible": False,
        "reason": "v2_not_offered",
    }


def canonical_projection_json(projection: Any) -> str:
    """Return deterministic UTF-8 JSON for a source projection.

    Transport metadata and a pre-existing checksum are recursively excluded.
    The remaining contract is ordinary JSON: object keys are sorted, numbers use
    Python's JSON encoding, and non-finite floats are rejected.
    """

    def clean(value: Any) -> Any:
        if isinstance(value, Mapping):
            return {key: clean(value[key]) for key in sorted(value) if key not in _TRANSPORT_KEYS}
        if isinstance(value, list):
            return [clean(item) for item in value]
        return value

    try:
        return json.dumps(
            clean(projection),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise ProtocolError("non_canonical_projection") from exc


def projection_checksum(projection: Any) -> str:
    encoded = canonical_projection_json(projection).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def assert_final_keyframe_before_completion(events: Iterable[Mapping[str, Any]]) -> None:
    finals: Dict[str, str] = {}
    for raw in events:
        event = validate_event(raw)
        entity = event["entity"]
        turn_id = entity.get("turn_id")
        if event["event_type"] == "keyframe.final" and turn_id:
            finals[turn_id] = event["payload"]["checksum"]
        if event["event_type"] == "turn.completed":
            if not turn_id or finals.get(turn_id) != event["payload"]["checksum"]:
                raise ProtocolError("completion_without_final_keyframe")
