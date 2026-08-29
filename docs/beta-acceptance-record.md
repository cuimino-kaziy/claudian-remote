# U9 internal beta acceptance record

> Superseded on 2026-07-22; the current replacement is `0.2.0-beta.4`. Real Tailscale validation found
> that beta.1 rejected Tailscale versions with a build suffix and assumed the
> optional CLI integration was installed. A later clean-install pass also
> superseded beta.2, and beta.4 later repaired lifecycle recovery. Do not distribute or resume beta.1.

Date: 2026-07-22  
Candidate: `0.2.0-beta.1`  
Implementation revision tested: `e8fb0f8`  
Scope: automated packaging and release-contract readiness

## Decision

The candidate is ready for maintainer-controlled real-device acceptance. It is
not yet a released beta: the signed prerelease, independent bootstrap delivery,
real-device matrix, and two-person canary remain human release blockers.

The current eligible deployment path is user-owned Tailscale. Trusted LAN stays
disabled until its separate security matrix passes. The user-owned VPS path is
documented but is not a releaseable primary lifecycle path until its production
adapter and real-VPS acceptance case are complete.

## Automated evidence

All commands below passed from a clean checkout, not only the maintainer's
working tree.

| Gate | Result |
| --- | --- |
| Node install and full verification | `npm ci --ignore-scripts`; 195/195 tests, source boundary, build, and syntax checks passed |
| Gateway | 132/132 tests passed with locked dependencies on managed CPython 3.12.11 |
| Installer | 132/132 tests passed with locked dependencies on managed CPython 3.12.11 |
| macOS bootstrap compatibility | 15/15 safe-extraction tests passed on system Python 3.9.6 |
| Managed runtimes | Both CPython 3.12.11 and uv 0.10.12 downloaded and matched pinned SHA-256 on darwin/arm64 and darwin/x86_64 |
| Package trust | Package, Ed25519 signing, manifest verification, and Kit preparation passed |
| Reproducibility | Current-tree and clean-checkout artifact SHA-256 values matched exactly |

The build still emits the known direct-`eval` warning from
`src/desktop/bridge-bootstrap.js`. It is recorded as a non-blocking hardening
item and did not bypass the source or package boundary checks.

## Candidate artifact digests

| Artifact | SHA-256 |
| --- | --- |
| `claudian-remote-plugin-0.2.0-beta.1.tar.gz` | `b71f0af68f673b16f6420ed0c2999f7bfa82562604d223574b04be91353a78fb` |
| `claudian-remote-companion-0.2.0-beta.1.tar.gz` | `150489dda6f3e84fc3f418a221773a820f03bb11f08e7e42eed9d94b5902f6aa` |
| `claudian-remote-relay-0.2.0-beta.1.tar.gz` | `77b2f1cde39917b1c12493f0190134af1bba08f573f2b98624a49c074cc7a593` |
| `claudian-remote-lifecycle-0.2.0-beta.1.tar.gz` | `13dc3758e30f5a1d353f4208d23ca4721412aec8edefd9c579fed07c8460b960` |
| `release-manifest.json` | `4baf4934b2e5d2d95733c10b49c2096137a3a59ae4098c8b0e7db1baba11a7c4` |
| `claudian-remote-beta-kit-0.2.0-beta.1.tar.gz` | `0e054bba13150f2f526ba23b130f06c227dca8a5e82bd4fd080ba6a2e518efbf` |
| `CLAUDIAN_REMOTE_TRUSTED_BOOTSTRAP-0.2.0-beta.1.md` | `e499e027504acedcc67d03218c49a592cf69551075e46bb9fbae30d431501bad` |

The trusted bootstrap document is deliberately outside the Kit. It pins the
whole-Kit digest and maintainer signing fingerprint and must reach each tester
through an existing authenticated direct channel before any Kit-provided code
is run.

## Human release blockers

- Copy the already-created maintainer signing key from macOS Keychain into the
  release secret store without exposing it in shell arguments, logs, or files.
- Configure a Git remote, create the exact signed version tag, and let the
  pinned workflow create a private GitHub prerelease. No Git remote is
  configured in this checkout, so this was intentionally not performed.
- Send the trusted bootstrap document independently and record successful
  whole-Kit verification before extraction.
- Complete the real-device matrix in `docs/beta-checklist.md`, including Apple
  Silicon plus cellular iPhone, Intel Mac or explicit Intel removal, Obsidian
  Sync and iCloud, revocation, interrupted resume/rollback, and uninstall/purge.
- Complete the user-owned VPS production adapter and one real-VPS acceptance
  case before advertising VPS as an available beta path.
- Pass two canary testers through install, daily use, update/rollback,
  revocation, and removal before expanding to the remaining invitees.

## Maintainer handoff

Use `docs/beta-checklist.md` as the release authority. An Agent may regenerate
and verify the candidate, but it must not check any human blocker merely from a
unit test, simulator, desktop browser, or locally generated fixture.
