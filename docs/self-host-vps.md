# Self-hosting the beta Relay on a user-owned VPS

VPS mode is an optional explicit profile. The Agent first asks whether the user
has a suitable VPS; declining it selects the Tailscale planning branch, not an
automatic runtime fallback.

## Supported beta profile

- Ubuntu 24.04 x86_64, or Debian 12 x86_64/aarch64.
- At least 2 GiB available managed storage.
- A user-controlled hostname with a trusted HTTPS certificate.
- SSH host-key fingerprint confirmed by the user through a lifecycle human
  gate. Conversation text such as "done" cannot satisfy this check.
- The exact invited Release Relay artifact and digest from the signed
  compatibility manifest.

The lifecycle plan creates a dedicated `claudian-remote` service identity, an
owned data directory, and an immutable versioned release directory. Remote
values are passed as validated data through standard input; hostnames, paths,
credentials, and release metadata are never interpolated as executable text.
No author hostname, Vault path, account, token, or development checkout is a
default.

## Exposure and verification

The reverse proxy exposes only `HTTPS /api/v2/*` and `WSS /api/v2/ws/*`.
Management, database, and health probes are private and require the appropriate
application role. The deployment remains `prepared` until lifecycle probes
confirm all of the following with a profile-bound test credential:

1. exact artifact digest and compatible Relay/protocol versions;
2. trusted HTTPS and WSS negotiation;
3. bounded storage, retention, quota, and disk-watermark policy;
4. separate Companion and Mobile credential audiences;
5. no externally reachable management, database, health, plaintext, or
   fallback listener.

Formal mobile enrollment is performed by U6 pairing. Real VPS and iPhone
acceptance is intentionally deferred to U9; unit tests use injected command and
probe runners and do not modify an external host.

## Failure and removal

Deployment is a reversible saga. A failed TLS, WSS, storage, compatibility, or
health check stops the staged service, removes only the owned staged release,
and restores the prior compatible service. Pairing cannot start after a failed
verification. Ordinary uninstall removes only owned, unchanged resources;
purge of credentials, recovery data, logs, and backups is a separate confirmed
operation.

Before choosing VPS mode, read the trust disclosure in
[`security.md`](security.md): the selected VPS terminates TLS and can read
Relay-handled content, so this beta does not provide end-to-end encryption.
