# U9 internal beta acceptance record — beta.4

Date: 2026-07-22  
Candidate: `0.2.0-beta.4`  
Working tree base: `b874bb6`  
Scope: lifecycle recovery correctness for the Mac + iPhone local-Tailscale beta

## Decision

This candidate is ready for maintainer-controlled real-device acceptance. It
supersedes beta.3, whose legacy-plugin upgrade could leave a staging-only
operation marked `recovery_required` after an unnecessary, non-idempotent
compensation attempt.

This is not a public release claim. The independently delivered trusted
Bootstrap remains mandatory, and the real-iPhone gates in
`docs/beta-checklist.md` remain release authority.

## Changes in this candidate

- Derive lifecycle diagnosis from real checkpoint inventory instead of a
  hard-coded zero; unreadable checkpoint files now fail closed and remain
  visible as pending operator attention.
- Expose an allowlisted recovery action only after the transaction journal has
  validated the operation and immutable plan binding.
- Preserve an active legacy credential when revocation was not verified;
  staging-only rollback is metadata- and operation-scoped.
- Do not run LaunchAgent or Tailscale cleanup when the failed operation never
  activated runtime resources.
- Make Tailscale Serve removal idempotent when the owned proxy was never
  created, while still failing closed when an owned proxy survives removal.
- Detect an unavailable authoritative legacy-credential revoker before release
  staging and return a stable non-mutating block instead of pretending that a
  migration can complete.
- Keep compatibility exact: mixed beta.3/beta.4 component sets are read-only
  until all managed components match beta.4.

## Automated evidence

| Gate | Result |
| --- | --- |
| Installer suite | 169/169 passed |
| Gateway suite | 132/132 passed |
| Node/full product suite | 195/195 passed, including source boundary, build, protocol, deterministic package, and Kit tests |
| Swift menu controller | `swiftc -parse-as-library -typecheck` passed |
| Signed release contract | Ed25519 signature and every declared component digest verified |
| Trusted Bootstrap binding | Version, whole-Kit SHA-256, and signing-key fingerprint matched independently |
| Kit contents | Guide, lifecycle, plugin, Companion, Relay, signed manifest, trust metadata, and exact beta.4 assets only |

The build still emits the existing direct-`eval` warning from
`src/desktop/bridge-bootstrap.js`. It remains a non-blocking hardening item.

## Candidate artifact digests

| Artifact | SHA-256 |
| --- | --- |
| `claudian-remote-plugin-0.2.0-beta.4.tar.gz` | `3f3b16ec480f5bc4d42c496072f02fdce68050ae6429079fbfdd4b96562cdc45` |
| `claudian-remote-companion-0.2.0-beta.4.tar.gz` | `196f7fb1e482892b1b764911349e1918bc12c8158474e4524a083d6c4774b171` |
| `claudian-remote-relay-0.2.0-beta.4.tar.gz` | `75e5d286fc73111e0a7c4571501afa6f14d36786baac03abd19d2bda45849e26` |
| `claudian-remote-lifecycle-0.2.0-beta.4.tar.gz` | `1c5c6b81703b5e448c14a04fc0ccfdeaad400c46a1ff1eeed76a3a1b4868e83f` |
| `release-manifest.json` | `f21be782290b6646660c4cab0f9c35ebcb00dd37e97bdfb329564f59189d0c72` |
| `claudian-remote-beta-kit-0.2.0-beta.4.tar.gz` | `ac255415a2509273efa5138c97936eeb61824d1d233ecec30ed500a58a9c736b` |
| `CLAUDIAN_REMOTE_TRUSTED_BOOTSTRAP-0.2.0-beta.4.md` | `bc2c3663e8d081524170c7dbbb598ae7b981f38b367c6618f548910f35bba03d` |

Signing key fingerprint:
`ace5a202634648deff4058a124e3d51c83554dd76a2a96f6b656e70ca8687023`.

## Known boundaries

- The Mac must remain powered on, logged in, and awake; this candidate does
  not wake a sleeping or powered-off Mac.
- `local_tailscale` is the supported no-VPS beta path. `remote_vps` remains an
  advanced deferred path and `local_lan` is not release eligible.
- A legacy plugin that still contains a shared credential is deliberately
  blocked before staging when authoritative revocation is unavailable. Do not
  delete or bypass that guard; retire the old credential through its owning
  service, then start a fresh beta.4 operation.
- A beta.1, beta.2, or beta.3 recovery operation must not be resumed with this
  Kit. Diagnose it, use its validated beta.4 recovery action if one is exposed,
  and then create a new beta.4 plan and operation.

## Next human gate

1. Deliver the trusted Bootstrap and Kit through separate channels.
2. Let the tester's Agent verify the whole-Kit SHA-256 before extraction.
3. Start a new beta.4 operation; do not resume an older operation.
4. Complete official Tailscale installation, network-extension consent,
   same-Tailnet sign-in, HTTPS consent, pairing, and first mobile message.
5. Verify on a real iPhone over cellular: connect, stream, reconnect, attach a
   file, stop, insert-now, and return to the same Mac Claudian conversation.
