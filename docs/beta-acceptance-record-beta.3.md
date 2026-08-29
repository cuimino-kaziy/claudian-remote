# U9 internal beta acceptance record — beta.3

> Superseded on 2026-07-22 by `0.2.0-beta.4`. A real legacy-plugin upgrade
> exposed a staging-only compensation and checkpoint-diagnosis defect. Do not
> start or resume beta.3 lifecycle operations; use the independently verified
> beta.4 Kit and begin a new operation.

Date: 2026-07-22  
Candidate: `0.2.0-beta.3`  
Working tree base: `b874bb6`  
Scope: safe managed-runtime installation, Agent-led onboarding, Tailscale fallback, and macOS availability

## Decision

This candidate is ready for maintainer-controlled real-device acceptance. It
supersedes beta.2, whose managed CPython archive could not be installed because
legitimate archive-internal relative symlinks were rejected.

This record does not claim that the iPhone/cellular matrix has passed. The Kit
may be sent to a tester only together with the independently delivered trusted
Bootstrap, and the real-device gates in `docs/beta-checklist.md` remain release
authority.

## Changes in this candidate

- Safely extract pinned runtime archives while rejecting absolute paths,
  traversal, device nodes, FIFOs, unsupported entries, and escaping links.
- Make the one-file guide explain Claudian Remote before configuration, assume
  the intended Mac + iPhone setup, and recommend free `local_tailscale` unless
  the tester already has a suitable VPS.
- Offer explicit Agent-operated and user-operated routes at human-owned gates;
  passwords, 2FA, macOS permissions, and consent remain user-owned.
- Use the official signed Tailscale app executable when PATH CLI integration is
  absent or stale. The Kit does not bundle Tailscale or use `curl | shell`.
- Add a one-shot macOS availability job that opens a fixed Obsidian app through
  a validated `obsidian://` Vault URI after login. It does not prevent sleep,
  wake the Mac, or repeatedly relaunch Obsidian after the user quits it.
- Preserve availability state across update, rollback, interrupted resume, and
  removal, including an explicit change from one Vault binding to another.
- Keep beta compatibility exact: mixed beta.2/beta.3 component sets are
  read-only until all managed components match beta.3.

## Automated evidence

| Gate | Result |
| --- | --- |
| Installer suite | 159/159 passed |
| Gateway suite | 132/132 passed |
| Node/full product suite | 195/195 passed, including source boundary, build, protocol, and package tests |
| Swift menu controller | `swiftc -typecheck` passed |
| Managed runtime extraction | The pinned CPython 3.12.11 arm64 archive extracted successfully with the production extractor |
| Managed runtime assets | CPython 3.12.11 and uv 0.10.12 downloaded and matched pinned SHA-256 on darwin/arm64 and darwin/x86_64 |
| Signed release contract | Ed25519 signature and every declared component digest verified |
| Kit contents | Guide, lifecycle, plugin, Companion, Relay, signed manifest, trust metadata, and exact assets only |

The build still emits the existing direct-`eval` warning from
`src/desktop/bridge-bootstrap.js`. It remains a non-blocking hardening item.

## Candidate artifact digests

| Artifact | SHA-256 |
| --- | --- |
| `claudian-remote-plugin-0.2.0-beta.3.tar.gz` | `a11217cc1361cc751134c99ceb8cf660b8d8de35d2d036160fe4c19a427d1df7` |
| `claudian-remote-companion-0.2.0-beta.3.tar.gz` | `20be9708615860bd7a6374e9b0fa1872ccdca1dac20f5629889eb3eec2490e30` |
| `claudian-remote-relay-0.2.0-beta.3.tar.gz` | `cda0e3829788316b2155136537d96bb196af339b6c7ea161b80429587bfc11a0` |
| `claudian-remote-lifecycle-0.2.0-beta.3.tar.gz` | `ab145169ad0ddc3718944e0ce6f8f759386bade18ee2ded62255dc046d463486` |
| `release-manifest.json` | `486f61c6cb4c98a68dbdd1f3b5f8f68adea0c87758ce0ecc8e6a316deb600613` |
| `claudian-remote-beta-kit-0.2.0-beta.3.tar.gz` | `779d67f88914b616dbaaab0888e5e411bf4ae22892bcbac3c59d64e6c56af9de` |
| `CLAUDIAN_REMOTE_TRUSTED_BOOTSTRAP-0.2.0-beta.3.md` | `bb4668eda05fd9e297643525ebe49af65c0d9e450b06db55c68b1381bd7a27d3` |

Signing key fingerprint:
`ace5a202634648deff4058a124e3d51c83554dd76a2a96f6b656e70ca8687023`.

The trusted Bootstrap is deliberately outside the Kit and must arrive through
an existing authenticated direct channel before the Kit is extracted or run.

## Known boundaries

- The Mac must be powered on, logged in, and awake. The display may be off.
- Login availability is one-shot. If the user later quits Obsidian, Claudian
  Remote does not force it open again.
- The candidate does not wake a sleeping or powered-off Mac and does not alter
  system sleep policy.
- `local_tailscale` is the supported no-VPS beta path. `remote_vps` remains an
  advanced deferred path and `local_lan` is not release eligible.
- The current distribution Kit does not package a standalone menu-bar app; its
  controller source is development tooling and is verified separately.
- Vault opening uses the Obsidian display name. Testers should avoid keeping two
  registered Vaults with the same display name during this beta.

## Next human gate

1. Deliver the trusted Bootstrap and Kit through separate channels.
2. Let the tester's Agent verify the whole-Kit SHA-256 before extraction.
3. Start a new beta.3 operation; do not resume beta.1 or beta.2 state.
4. Complete official Tailscale installation, network-extension consent,
   same-Tailnet sign-in, HTTPS consent, pairing, and first mobile message.
5. Verify on a real iPhone over cellular: connect, stream, reconnect, attach a
   file, stop, insert-now, and return to the same Mac Claudian conversation.
