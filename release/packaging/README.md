# Release packaging contract

Release tooling must build from committed dependency locks, produce one asset
for each compatibility-set component, hash every asset and lock, sign the
canonical manifest with Ed25519 outside the repository, verify it against the
pinned public trust root, and only then publish an exact immutable tag.

The lifecycle asset is an installable bundle, not a documentation placeholder.
It contains `CLAUDIAN_REMOTE_INSTALL.md`, the Python lifecycle package, a
launcher, the release trust files, and `lifecycle-runtime.lock.json`. The lock
hashes every shipped lifecycle source file and pins the required Python/uv
versions and macOS targets.

After signing and contract verification, `npm run release:kit` creates the
tester-facing `claudian-remote-beta-kit-<version>.tar.gz`. It contains the
lifecycle bundle at its root, the signed manifest, and every manifest-bound
component archive under `assets/`. Its launcher supplies that same extracted
directory as `--release-dir`, so an Agent never has to reconstruct the release
handoff or fall back to a source checkout.

`sh release/packaging/build-assets.sh --assets-only` builds artifacts for CI
content inspection without claiming they are releasable. The normal
`npm run release:package` path resolves the exact CPython and uv release URLs
and SHA-256 digests committed in `support-matrix.json` for macOS arm64 and
x86_64. These upstream release URLs are immutable and the installer verifies
the committed digest before extraction. A missing, non-HTTPS,
credential-bearing, query-bearing, or digest-less runtime description stops
manifest preparation.

`npm run release:verify:runtimes` downloads each pinned runtime as a stream and
checks its full SHA-256 digest. The release workflow runs this availability and
integrity gate before it creates any signed artifact.

Run `npm run release:key:init` once on the maintainer Mac to generate an Ed25519
key. The command stores the private key in macOS Keychain without printing it
and prints only the public trust-root entry. Pin that public key and fingerprint
in `trust-root.json`; the same private key must later be copied through a secure
channel into the GitHub Actions secret. Local signing reads Keychain when the
Actions secret environment variable is absent. Never commit a private key or
substitute GitHub authentication for signature checks.
The empty trust root, runtime metadata drift, absence of an exact private GitHub
prerelease, or an incomplete real-device matrix are release blockers, not
warnings that an Agent may bypass.
