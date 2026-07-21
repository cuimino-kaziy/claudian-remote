# Claudian Remote Relay Protocol (Legacy v1)

> Legacy compatibility contract. New true-streaming work uses
> `claudian-remote-stream-v2.md`. v2 removes offline Mobile-to-Mac command
> queueing and periodic snapshot polling from the primary path. This document is
> retained only for staged upgrade and rollback of the existing installation.

This protocol keeps the public VPS relay narrow. The relay authenticates a role, forwards envelopes, reports presence, and stores only ciphertext or body-free metadata for offline delivery.

## Roles

- `mac`: the Mac companion connected to desktop Obsidian and Claudian.
- `mobile`: the Obsidian Mobile remote window.

Each role has its own relay token. Tokens are scoped to one `pairing_id`; a token for one role cannot impersonate the other role.

## Endpoint Targets

- Example: `https://relay.example.invalid`
- Fallback: none by default. Configure a temporary fallback only after its DNS and TLS behavior has been verified from the target client network.

## HTTP Fallback API

All `/api/*` calls require `Authorization: Bearer <role-token>`.

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/health` | Pairing-Admin-authenticated private health metadata. |
| `POST` | `/api/session/join` | Mark the authenticated role online and emit a presence event to its counterpart. |
| `POST` | `/api/session/heartbeat` | Refresh the authenticated role's presence timestamp. |
| `POST` | `/api/envelopes` | Submit an envelope to the counterpart role. |
| `GET` | `/api/events?since=<id>&timeout=<seconds>` | Poll events for the authenticated role. |

The same envelope semantics should be used when a WSS transport is added.

## Envelope Shape

```json
{
  "type": "message.submit",
  "delivery_id": "client-generated-or-relay-generated-id",
  "target_role": "mac",
  "body": {
    "encrypted_payload": {
      "alg": "pbkdf2-hmac-sha256+xor-hmac-v1",
      "pairing_id": "pairing-id",
      "nonce": "...",
      "ciphertext": "...",
      "tag": "..."
    }
  }
}
```

Online pass-through may carry a `payload` object during local testing, but offline body queueing requires `encrypted_payload`.
If encryption is not configured, clients should submit online-only events and the relay must refuse plaintext body queueing while the counterpart is offline.

## Event Types

| Type | Source | Meaning |
|---|---|---|
| `presence.changed` | relay | A paired role moved online or offline. |
| `message.submit` | mobile | User text intended for active desktop Claudian. |
| `approval.respond` | mobile | User selected a desktop Claudian permission option from the remote window. |
| `message.receipt` | mac or mobile | Delivery, accepted, failed, or duplicate status for a `delivery_id`. |
| `conversation.snapshot` | mac | Current active conversation state. |
| `conversation.event` | mac | Delta or revision update from desktop Claudian. |
| `schedule.submit` | scheduler | Scheduled prompt event entering the same adapter path. |

## Remote Approval Response

When desktop Claudian is waiting on a permission prompt, the Mac adapter may include
`pending_approvals` in a `conversation.snapshot`. The mobile plugin can answer through the relay:

```json
{
  "type": "approval.respond",
  "delivery_id": "approval-response-id",
  "target_role": "mac",
  "body": {
    "encrypted_payload": {
      "alg": "pbkdf2-hmac-sha256+xor-hmac-v1",
      "pairing_id": "pairing-id",
      "nonce": "...",
      "ciphertext": "...",
      "tag": "..."
    }
  }
}
```

The decrypted payload has this shape:

```json
{
  "approval_id": "approval-request-id",
  "value": "allow"
}
```

The relay only transports the choice. The Mac-local adapter resolves the pending Claudian
permission callback, and the Local REST token remains Mac-only.

## Security Rules

- Local REST API tokens never appear in relay requests, relay config, mobile settings, or relay logs.
- Pairing secrets are shared only by the mobile plugin and Mac companion.
- The relay stores queued message bodies only as encrypted payload envelopes.
- Logs redact bearer tokens, token-like JSON fields, and local Mac paths.
- `/health` requires the profile-bound Pairing Admin credential and must not
  reveal room names, pairing ids, message bodies, or token names.
