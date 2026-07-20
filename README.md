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

## Licenses and external services

The plugin, Mac Companion, and lifecycle/packaging code are MIT licensed. The
self-hosted Relay under `gateway/relay/` is AGPL-3.0-only; see its own license.
GitHub Releases is used only to authenticate invited downloads and is not the
integrity root. Depending on the selected mode, users operate Tailscale or a
user-owned VPS. A VPS terminates TLS and can read Relay plaintext; this beta
does not claim end-to-end encryption.

## Development gates

```sh
npm ci --ignore-scripts
npm run verify
python3.12 -m pytest gateway/tests -q
```

Release metadata lives in `release/`. Publication remains fail-closed until a
maintainer configures a real signing key and pins its public fingerprint in the
trusted lifecycle bootstrap; no signing secret is stored here.
