# Claudian Remote

Claudian Remote is an internal beta for using one supported Mac Claudian
installation from one iPhone or iPad through an Obsidian plugin, Mac Companion,
and a user-controlled Relay.

## Beta contract

- Supported Claudian version: **2.0.4 only**. Other versions must remain
  read-only; inspection, diagnostics, rollback, and removal stay available.
- Plugin ID: `claudian-remote`. The old private ID `whale-agent-bridge` is only
  a migration source and must not coexist with this plugin.
- Distribution: exact invited GitHub Release assets only. Mutable branches,
  development checkouts, `curl | shell`, and server-returned commands are not
  installation sources.
- Update owner: the external lifecycle manager for `private_beta`; the plugin
  never overwrites its own assets. A future `community` release delegates
  plugin updates to Obsidian.
- Integrity: a release is accepted only after its Ed25519 manifest signature,
  pinned-key fingerprint, asset SHA-256 values, and dependency-lock SHA-256
  values all verify.

This repository contains no production credentials, local configuration,
device state, logs, databases, Vault paths, or recovery data. Example values
are intentionally non-working.

## Device-local state boundary

Obsidian-synchronized plugin data is an allowlisted preference document: a
non-secret Vault identity, explicit connection mode, and notification/haptic
choices. Relay endpoints, credentials, device identity, cursors, recent-history
cache, pairing state, and local paths stay in device-local storage. Companion
credentials are referenced from public configuration and resolved from the
macOS login Keychain only in memory.

The iPhone/iPad cache is a bounded, text-only convenience copy. Offline mode is
read-only, keeps no send queue, and never stores attachment binaries. Purge and
device revocation remove it. This separation prevents Obsidian Sync and iCloud
from copying authority between devices, but it is not a hardware security
boundary: another malicious Obsidian plugin in the same mobile sandbox, or a
compromised phone, may still access web storage. The beta limits that residual
risk to one revocable mobile device and requires immediate revocation after
loss or compromise.

## Licenses and external services

The plugin, Mac Companion, and lifecycle/packaging code are MIT licensed. The
self-hosted Relay under `gateway/relay/` is AGPL-3.0-only; see its own license.
GitHub Releases is used only to authenticate invited downloads and is not the
integrity root. Depending on the selected mode, users operate Tailscale or a
user-owned VPS. A VPS terminates TLS and can read Relay plaintext; this beta
does not claim end-to-end encryption.

Connection-mode security and exact recovery limits are documented in
[`docs/security.md`](docs/security.md). The narrow user-owned VPS profile is in
[`docs/self-host-vps.md`](docs/self-host-vps.md).

## Development gates

```sh
npm ci --ignore-scripts
npm run verify
python3.12 -m pytest gateway/tests -q
```

Release metadata lives in `release/`. Publication remains fail-closed until a
maintainer configures a real signing key and pins its public fingerprint in the
trusted lifecycle bootstrap; no signing secret is stored here.

The lifecycle release asset includes the Agent guide, executable entrypoint,
Python package, and a per-file content lock. Private macOS arm64 and x86_64
CPython/uv asset URLs and SHA-256 values are supplied only by the release job;
the repository contains variable names and exact versions, not invented
downloads or digests. See [`docs/beta-checklist.md`](docs/beta-checklist.md) for
the remaining maintainer and real-device release gates.
