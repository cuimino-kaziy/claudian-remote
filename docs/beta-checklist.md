# Internal beta release checklist

This checklist distinguishes automated package readiness from evidence that
only a maintainer and real devices can supply. An Agent must not mark the beta
released while any item in **Human release blockers** remains open.

## Automated release gates

- [ ] Clean checkout passes `npm ci --ignore-scripts`, `npm run verify`, the
  Gateway suite, and the installer suite.
- [ ] `sh release/packaging/build-assets.sh --assets-only` produces plugin,
  Companion, Relay, and lifecycle archives; the lifecycle archive contains the
  guide, package, entrypoint, release trust files, and a matching source lock.
- [ ] Every third-party GitHub Action is pinned to a 40-character commit SHA;
  CI has read-only repository permission and only the publish job receives
  `contents: write`.
- [ ] Contract tests reject manifest/asset tampering, dependency-lock drift,
  unknown or revoked signing keys, mutable Action refs, and incomplete runtime
  metadata.
- [ ] Source and packaged-asset scans contain no credentials, personal paths,
  local state, logs, databases, or private deployment identifiers.

## Human release blockers

- [ ] Generate the maintainer Ed25519 signing key outside the repository, keep
  the private key only in the release secret store, and commit the matching
  trusted public key plus fingerprint to `release/trust-root.json`.
- [ ] Select immutable private CPython `3.12.11` and uv `0.10.12` archives for
  macOS arm64 and x86_64. Configure every URL and SHA-256 repository variable
  named in `release/support-matrix.json`; do not use mutable `latest` URLs.
- [ ] Create the exact signed Git tag and let the pinned release workflow create
  a private GitHub **prerelease**. Confirm all invited testers download the same
  manifest and asset digests.
- [ ] Run the required clean-Mac and real-iPhone/iPad matrix and preserve the
  non-sensitive evidence. Unit or simulated tests do not replace this gate.
- [ ] Start with two canary testers. Expand to the remaining invited cohort only
  after both complete install, daily use, update/rollback, revocation, and
  removal without maintainer screen control.

## Real-device matrix

- [ ] Apple Silicon Mac + iPhone over Tailscale and cellular: WSS streaming,
  background/foreground, Wi-Fi-to-cellular change, replay recovery,
  attachments, stop, and Steer Now.
- [ ] Intel Mac uses the x86_64 managed runtime and reaches the same verified
  lifecycle state, or Intel support is removed from the signed support matrix
  before release rather than silently falling back.
- [ ] User-owned supported VPS: HTTPS/WSS, pairing, resource checks, and safe
  failure for invalid TLS, insufficient capacity, or incompatible versions.
- [ ] Obsidian Sync and iCloud separately: plugin arrival, same-Vault binding,
  pairing, generated Markdown visibility, and mixed-version read-only state.
- [ ] Lost-phone revocation closes the active connection and the old identity
  fails every later route.
- [ ] Interrupted install/update resumes or rolls back after Agent-session loss
  and Mac restart without duplicate resources.
- [ ] Uninstall and purge leave no owned process, LaunchAgent, listener,
  credential, recovery data, or mixed compatibility set.
- [ ] Trusted LAN remains unavailable unless its separate permission, trusted
  WSS, interface binding, network-change shutdown, authorization, and packet
  inspection matrix all pass with no plaintext content or credential.

## Explicit non-evidence

The empty trust root is not a development convenience, an unsigned archive is
not a beta release, and a locally generated test key does not establish the
maintainer trust root. Likewise, a simulator, desktop browser, or unit-test
fixture cannot satisfy the clean-machine or real-iPhone acceptance matrix.
