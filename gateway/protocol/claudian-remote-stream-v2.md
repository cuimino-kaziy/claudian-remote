# Claudian Remote Semantic Stream v2

Status: implementation contract for the true-streaming path.

The desktop Claudian runtime is authoritative. The Bridge emits only semantic,
post-commit observations; the Companion transports them; the Relay commits a
short-lived recovery log; Mobile reduces committed events into a disposable
projection. Polling snapshots are not the normal v2 data path.

## Transport and authentication

- Bridge to Companion: localhost SSE for events and localhost POST for controls.
- Companion to Relay: one header-authenticated WebSocket.
- Mobile events: WebSocket subprotocol `claudian.remote.v2`.
- Mobile obtains a 30-second, single-use ticket over authenticated HTTPS. The
  ticket is sent only in the first WebSocket frame, within five seconds. It is
  never placed in a URL, access log, reducer state, or event payload.
- Commands and uploads use authenticated HTTPS. A Relay acceptance response
  means only that routing began; desktop acceptance is a separate receipt.

Role boundaries are executable in `stream_protocol.ROUTE_AUTH_MATRIX`:

| Route | Allowed credential |
|---|---|
| `POST /api/v2/ws-ticket` | Mobile role token |
| `GET /api/v2/ws/mobile` | consumed Mobile ticket |
| `GET /api/v2/ws/mac` | Mac role token |
| `POST /api/v2/commands` | Mobile role token |
| `POST /api/v2/uploads` | Mobile role token |
| `GET /api/v2/uploads` | Mac role token |
| `POST /api/v2/pairing/claims` | Pairing Admin credential |
| `GET /api/v2/pairing/claims` | Pairing Admin credential |
| `POST /api/v2/pairing/redeem` | one-time Pairing Claim plus current Vault identity |
| `POST /api/v2/pairing/claims/{id}/approve` | Pairing Admin credential |
| `POST /api/v2/pairing/claims/{id}/reject` | Pairing Admin credential |
| `POST /api/v2/pairing/claims/{id}/complete` | one-time redemption handle bound to the displayed device |
| `GET /api/v2/pairing/devices` | Pairing Admin credential |
| `POST /api/v2/pairing/devices/{id}/revoke` | Pairing Admin credential |
| `GET /health` | Pairing Admin credential; private deployment surface |

Pairing claims expire after five minutes by default, are single use and
attempt-limited, and contain no durable device credential. The QR deep link may
carry the non-secret Relay URL and installation/Vault/audience binding so a
fresh phone can establish device-local profile state. The service persists only
claim/handle digests and durable credential verifier digests. Approved but
unclaimed credentials fail closed on expiry or Relay restart. Terminal claim
rows are scrubbed immediately and deleted after the bounded terminal-retention
window; they are not history or diagnostics.

## Event identity and ordering

Every source event contains:

```json
{
  "protocol": "claudian.remote.v2",
  "kind": "event",
  "event_type": "text.delta",
  "source": {"instance_id": "bridge-instance", "sequence": 42},
  "entity": {
    "conversation_id": "conversation-id",
    "turn_id": "turn-id",
    "message_id": "message-id",
    "block_id": "block-id"
  },
  "revision": 8,
  "payload": {"text": "new suffix"}
}
```

`source.instance_id + source.sequence` is the Relay idempotency key. The Relay
assigns `epoch + cursor` only after the SQLite transaction commits. Mobile
ignores a duplicate cursor, an already applied source UID, and an entity event
older than its current revision.

`text.delta` contains only a suffix for a known block. A non-prefix repair uses
`text.replace` and carries the complete safe text for that block. IDs are stable
for the lifetime of their desktop entities and are never inferred from list
positions.

### Delivery provenance and optimistic reconciliation

For the canonical v2 path, a remote user message included in a keyframe SHOULD
carry `origin_delivery_id`, whose value is the `delivery_id` of the command that
created the message. Mobile uses this provenance to reconcile the optimistic
message rendered at submit time with the authoritative desktop message.

`origin_delivery_id` identifies the delivery that produced a message. It is not
the message entity ID, stream event ID, or Relay idempotency key, and MUST NOT be
reused as any of them.

Legacy producers may omit `origin_delivery_id` and may rewrite message IDs
between keyframes. In that compatibility path, Mobile MUST NOT trust message IDs
across keyframes or bind to the first message with matching text. Before submit,
it records the authoritative message count (or equivalent baseline) and may
claim only the next unmatched same-text remote-user message after that baseline.

## Completion barrier

Provider `done` is not a Remote terminal event. The Bridge waits for the outer
desktop `sendMessage()` promise to finish saving, cleanup, queue handling, and
controller state updates. It then emits, in order:

1. all pages of the final keyframe;
2. `keyframe.final` with the projection revision and checksum;
3. `turn.completed` with the same checksum.

`turn.interrupted` and `turn.failed` are separate terminal states. A replayed or
background terminal event does not request a new user notification.

## Canonical keyframe checksum

`canonical_projection_json()` recursively removes `cursor`, `epoch`,
`received_at`, `transport`, and `checksum`, sorts object keys, preserves array
order, emits compact UTF-8 JSON, and rejects non-finite numbers. The checksum is
`sha256:` followed by lowercase SHA-256 hex of those bytes. Fixtures contain a
known checksum so JavaScript and Python implementations can prove parity.

Keyframes may be paged. A page has a zero-based `page_index`, a positive
`page_count`, a `keyframe_id`, and a bounded projection fragment. Mobile stages
all pages off-screen, validates the final checksum, then atomically replaces its
projection. Partial keyframes never modify visible state.

## Replay to live hand-off

One Relay owner coordinates event commits and subscribers. Recovery uses this
boundary:

1. register a bounded live buffer under the same owner used by commits;
2. read the committed high-water cursor `H`;
3. replay committed rows in `(client_cursor, H]`;
4. drain buffered rows above `H`, deduplicating by cursor;
5. continue live delivery.

An epoch mismatch, cursor below retained floor, source gap, checksum mismatch,
or slow-consumer disconnect yields `resync.required`. Mobile stops applying
incremental events until a valid Mac keyframe arrives.

## Commands: online only and connection-bound

Every state-changing command carries:

```json
{
  "protocol": "claudian.remote.v2",
  "kind": "command",
  "command_type": "turn.stop",
  "delivery_id": "mobile-generated-id",
  "mac_session_id": "current-process-session",
  "mac_connection_generation": 7,
  "expires_at": "2099-12-31T23:59:59Z",
  "expected_revision": 12,
  "target": {"conversation_id": "id", "turn_id": "id"},
  "payload": {}
}
```

Commands are never inserted into the event database or an offline queue. The
Relay routes only to the exact live Mac session and connection generation. When
that socket closes, all commands not yet accepted by the desktop expire; a new
socket generation cannot consume them even if the Companion process retained
the same session ID. `expires_at` is an additional absolute deadline.

The Bridge rechecks session, target entity IDs, capability, and revision. A
delivery ID may be retried only with byte-equivalent semantics in the same
session and generation. Unknown delivery status triggers calibration, not an
automatic retry with a new ID. Mobile preserves user input for manual retry.

## Source firewall

Filtering happens on the Mac before an event reaches the Companion. Event
payloads are allowlisted by type in `stream_protocol.EVENT_FIELDS`. The boundary
rejects:

- hidden thinking, reasoning, or chain-of-thought fields;
- raw tool arguments, raw input, shell commands, or command lines;
- bearer credentials, role tokens, API keys, WebSocket tickets, or secrets;
- Mac/Unix/Windows absolute paths;
- unknown payload fields and oversized frames.

Activity events may contain a user-facing stage, label, status, duration, and a
short safe detail. Tool events may expose a normalized tool name and safe
summary, never the original input. Artifact events expose a Vault-relative path
or an allowlisted `http/https` URL. Diagnostics contain IDs, types, counts,
states, and timings only.

## Event families

- capability and presence: `capability.state`, `presence.changed`
- desktop navigation: `conversation.activated`, `history.list`; commands
  `history.new`, `history.rename`, `history.archive`, and `history.select` are
  capability-checked and update mobile state only from an authoritative desktop
  receipt. Permanent deletion is intentionally absent. Claudian 2.0.4 exposes
  no durable archive API, so `history.archive` reports `capability_missing`
  rather than mapping to deletion or a local-only flag.
- turn lifecycle: `turn.started`, `turn.completed`, `turn.interrupted`, `turn.failed`
- observable work: `activity.updated`, `tool.started`, `tool.completed`
- answer content: `text.delta`, `text.replace`
- approval: `approval.requested`, `approval.resolved`
- files and links: `artifact.available`
- recovery: `keyframe.page`, `keyframe.final`, `resync.required`
- delivery: `command.receipt`

`turn.started` is the lifecycle boundary for the current-operation projection.
A consumer MUST clear activities and tools from the previous turn before
applying events for the new turn. A keyframe's `current_operation` MUST derive
from the live turn projection and MUST NOT be reconstructed from historical tool
blocks attached to older conversation messages.

Ordinary events target at most 64 KiB. The WebSocket frame limit is 256 KiB;
larger keyframes and history lists must be paged. Source text is coalesced for at
most 40 ms or 8 KiB, whichever comes first; approvals, errors, control receipts,
and terminal events are never delayed for coalescing.

## Compatibility

The v1 HTTP polling protocol remains a temporary, explicit compatibility mode.
If v2 is not offered or required private Claudian capabilities are missing, the
UI displays compatibility snapshot mode. It must never label snapshot polling
as true streaming. v2 removes offline command delivery and does not accept a v1
envelope as a v2 event.
