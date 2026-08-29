# U9 internal beta acceptance record — beta.2

> Superseded on 2026-07-22; the current replacement is `0.2.0-beta.4`. A real clean install exposed
> `release_archive_unsafe_member`: beta.2 rejected the pinned CPython runtime's
> legitimate archive-internal relative symlinks. Do not distribute or resume
> beta.2; begin a new operation from the independently verified beta.4 Kit.

Date: 2026-07-22  
Candidate: `0.2.0-beta.2`  
Implementation revision tested: `a2d4eb2`  
Scope: Tailscale onboarding repair and signed replacement candidate

## Decision

This candidate replaces beta.1 for the maintainer-controlled real-device
acceptance pass. It is not a public release. The remaining human gates and
device matrix in `docs/beta-checklist.md` still apply.

The Kit does not bundle or silently install Tailscale. Testers install the
official macOS and iOS apps and approve the operating-system network extension.
The lifecycle no longer requires Tailscale CLI integration: it uses the PATH
command when available and otherwise invokes the executable inside the signed
macOS Tailscale App.

## Defects repaired

- Accept real Tailscale version strings such as
  `1.98.9-t4fb758c39-g200941d74` without treating them as version zero.
- Discover `/Applications/Tailscale.app/Contents/MacOS/Tailscale` and the
  per-user Applications equivalent when CLI integration is absent.
- Explain official installation, VPN/network-extension approval, same-Tailnet
  sign-in, private Serve topology, and the optional CLI integration in the
  Agent installation manual.
- Preserve a human gate for installation and HTTPS certificate consent; no
  third-party installer, Funnel exposure, or `curl | shell` path was added.

## Verification evidence

| Gate | Result |
| --- | --- |
| Installer suite | 134/134 passed |
| Node/full product suite | 195/195 passed, including source boundary and package tests |
| Managed runtimes | Pinned CPython and uv assets verified for darwin/arm64 and darwin/x86_64 |
| Real Tailscale status | Current Mac status parsed successfully; preflight advanced to the expected `tailscale_https_consent_required` gate |
| Signed release contract | Ed25519 signature, pinned trust root, component hashes, and Kit preparation passed |
| Kit contents | Lifecycle, plugin, Companion, Relay, guide, signed manifest, and exact assets only; no Tailscale installer |

The build still emits the known direct-`eval` warning from
`src/desktop/bridge-bootstrap.js`. It remains a non-blocking hardening item.

## Candidate artifact digests

| Artifact | SHA-256 |
| --- | --- |
| `claudian-remote-plugin-0.2.0-beta.2.tar.gz` | `b57ac933caa357871c2b46fa000f430d154e48de1bace71cf5a4ee1a9b48677d` |
| `claudian-remote-companion-0.2.0-beta.2.tar.gz` | `5a16c0703c689c8782757298e93ddf3a1c9c6f9aefe3d094e811c4ea1a2d4226` |
| `claudian-remote-relay-0.2.0-beta.2.tar.gz` | `8a14feb7aa18966db73dd3e0e5b1bd683162842d6aaf8592af80d36b20bc7714` |
| `claudian-remote-lifecycle-0.2.0-beta.2.tar.gz` | `45e1456eaf51c845ace3ccb93b1aee31e31936c805d1df2a9c6f59e92eba1063` |
| `release-manifest.json` | `7257631caa4dc64aa027b89f782e27e6e3a09f7ac305119bdf4bb1048288f694` |
| `claudian-remote-beta-kit-0.2.0-beta.2.tar.gz` | `e0b38461f957efe994591cf964055b27fe3664a92699ce4c07ccd504fb4b6163` |
| `CLAUDIAN_REMOTE_TRUSTED_BOOTSTRAP-0.2.0-beta.2.md` | `e8ed1212d1da12f13f15e6d69da9e49dd493a5ea88ed2b85b2330953d8e6474f` |

The trusted bootstrap remains outside the Kit and must be delivered through an
independent authenticated channel before the Kit is extracted or executed.

## Next human gate

Start a new operation from the beta.2 Kit. Do not resume the beta.1 operation.
After inspect and plan, the expected next external gate on the maintainer Mac is
Tailscale HTTPS certificate consent. Complete it in the Tailscale-owned browser
or admin interface, then resume the same beta.2 operation and continue pairing.
