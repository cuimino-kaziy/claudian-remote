# Claudian Remote security model

Claudian Remote has three explicit connection profiles: `local_tailscale`,
`local_lan`, and `remote_vps`. The lifecycle manager is the only component that
writes the active profile. Relay, Companion, and plugin code consume that
profile; they do not choose another endpoint, reuse another profile's
credential, or fall back automatically after a failure.

## Network boundary

- Relay always listens on loopback. It must reject `0.0.0.0` and other external
  bind addresses.
- Tailscale mode uses private Tailscale Serve HTTPS/WSS in front of the
  loopback Relay. Funnel is never planned or enabled. Tailnet membership limits
  reachability but does not grant Claudian Remote authority.
- LAN mode is off by default. Its separate Gateway may listen only on the
  approved private interface, uses TLS and application authentication, and
  closes when the interface or recorded network fingerprint changes. It must
  remain unavailable for release until U9 real-device and traffic-inspection
  evidence confirms that no credential or content is sent in plaintext.
- VPS mode uses a user-owned host. Only HTTPS and WSS conversation routes are
  public; management, database, and health access stay private.

Persistent credentials bind their role, installation, Vault, device,
credential generation, and active endpoint audience. Companion, Mobile Device,
Pairing Admin, and one-time Pairing Claim roles are not interchangeable.
WebSocket tickets are short-lived and single use. Credentials are not accepted
in URLs, cookies, command-line arguments, synchronized plugin data, logs, or
Agent-visible text.

U5 uses explicit test credentials to verify an endpoint. U6 owns formal mobile
claim creation, Mac approval, durable credential issue, rotation, and
revocation.

Pairing uses a five-minute single-use claim and an eight-character fallback
code. The QR opens the system Obsidian deep-link handler; the plugin does not
request camera access. Its Relay URL and installation/Vault/audience values are
non-secret bootstrap metadata for a new phone. The phone's synchronized Vault
identity must match, and the Relay revalidates the claim binding before it
creates authority. Mac approval creates a distinct device credential; only its
verifier digest persists server-side, while the raw credential is delivered
once to device-local mobile storage. Approved-but-unclaimed credentials are
revoked after expiry or process restart. Revocation closes active sockets and
blocks all future HTTP, upload, command, ticket, and WebSocket use.

Pairing request/response bodies must be excluded from reverse-proxy access-body
logging. Active claim UI state is cleared on expiry. Terminal claim digests are
scrubbed immediately and the remaining device labels/identifiers are deleted
after the configured short retention window. Device credential rows remain
only for active-device inspection and explicit revocation history; they never
contain the raw credential.

## Recovery data and resource limits

Relay is a recovery buffer, not conversation history. The compatibility set's
support matrix is the only limit source:

| Policy | Beta value |
|---|---:|
| Terminal recovery events | 1 hour |
| Stale in-flight turns | 6 hours from last event/heartbeat |
| Upload after terminal state | 30 minutes |
| Upload absolute lifetime | 2 hours |
| File size | 256 MiB |
| Outstanding uploads per installation | 512 MiB |
| Concurrent uploads per installation | 2 |
| Protocol frame | 1 MiB |
| Managed upload-volume refusal | before 80% usage |
| Terminal pairing-claim metadata | 1 hour |

SQLite runs in WAL mode under a single owner. Cleanup advances the replay floor,
checkpoints WAL, removes startup upload orphans, and retries after a failed
cleanup cycle. Recovery databases and upload spools are excluded from routine
backups.

## Privacy and trust disclosure

The plugin sends no telemetry, diagnostic data, message or attachment content,
paths, network identities, or credentials to the maintainer. Diagnostic export
is a separate explicit action and uses an allowlist.

A user-owned VPS terminates TLS and can read conversation and attachment
content handled by Relay. This beta does not claim end-to-end encryption for
that deployment. Users must trust and administer the VPS they select.
