import copy
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from gateway.protocol.stream_protocol import (
    PROTOCOL,
    ProtocolError,
    assert_final_keyframe_before_completion,
    authorize_route,
    canonical_projection_json,
    event_uid,
    negotiate_protocol,
    projection_checksum,
    validate_command,
    validate_event,
)


FIXTURES = Path("gateway/protocol/fixtures/v2")


def load(name):
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def test_semantic_stream_is_valid_and_completion_has_final_barrier():
    fixture = load("semantic-stream.json")
    events = fixture["events"]
    assert [event_uid(item) for item in events] == [
        f"bridge-a:{index}" for index in range(1, len(events) + 1)
    ]
    assert_final_keyframe_before_completion(events)


def test_non_prefix_revision_has_unambiguous_replace_event():
    events = load("semantic-stream.json")["events"]
    replacement = next(item for item in events if item["event_type"] == "text.replace")
    assert validate_event(replacement)["payload"]["text"] == "修订后的完整回答。"


def test_keyframe_checksum_is_canonical_and_excludes_transport_metadata():
    fixture = load("replay-gap-keyframe.json")
    a = fixture["projection"]
    b = copy.deepcopy(a)
    b["epoch"] = "different-transport-epoch"
    b["cursor"] = 99999
    b["checksum"] = "ignored"
    assert canonical_projection_json(a) == canonical_projection_json(b)
    assert projection_checksum(a) == fixture["checksum"]


def test_command_contract_binds_current_connection_and_expires():
    fixture = load("command-races.json")
    now = datetime(2099, 1, 1, tzinfo=timezone.utc)
    command = validate_command(fixture["valid"], now=now)
    assert command["mac_connection_generation"] == 7
    for case in fixture["invalid"]:
        with pytest.raises(ProtocolError) as error:
            validate_command(case["command"], now=now)
        assert error.value.code == case["error"]


def test_source_firewall_rejects_sensitive_payloads():
    fixture = load("redaction-negative.json")
    for case in fixture["invalid_events"]:
        with pytest.raises(ProtocolError) as error:
            validate_event(case["event"])
        assert error.value.code == case["error"]


def test_role_auth_matrix_does_not_allow_role_confusion():
    assert authorize_route("POST", "/api/v2/commands", "mobile")
    assert not authorize_route("POST", "/api/v2/commands", "mac")
    assert authorize_route("GET", "/api/v2/ws/mac", "mac")
    assert not authorize_route("GET", "/api/v2/ws/mac", "mobile")
    assert authorize_route("GET", "/health", "public")


def test_v1_is_not_silently_treated_as_v2():
    v1 = {"type": "conversation.event", "body": {}}
    with pytest.raises(ProtocolError, match="unsupported_protocol"):
        validate_event(v1)
    result = negotiate_protocol(["claudian.remote.v1"])
    assert result == {
        "protocol": "claudian.remote.v1",
        "mode": "compatibility_snapshot",
        "compatible": False,
        "reason": "v2_not_offered",
    }
    assert negotiate_protocol([PROTOCOL])["mode"] == "streaming"


def test_completed_event_without_matching_final_keyframe_is_rejected():
    events = load("semantic-stream.json")["events"]
    with pytest.raises(ProtocolError, match="completion_without_final_keyframe"):
        assert_final_keyframe_before_completion([events[-1]])
