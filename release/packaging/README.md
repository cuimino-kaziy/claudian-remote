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
`npm run release:package` path additionally requires all eight URL/SHA-256
variables named by `support-matrix.json` for private CPython and uv assets on
macOS arm64 and x86_64. A missing, non-HTTPS, credential-bearing, query-bearing,
or digest-less runtime description stops manifest preparation.

`trust-root.json` intentionally contains no key during repository bootstrap.
The release workflow fails until a maintainer provides a signing key through
GitHub Actions secrets and pins the corresponding public fingerprint. Never
commit a private key or substitute GitHub authentication for signature checks.
The empty trust root, missing runtime variables, absence of an exact private
GitHub prerelease, or an incomplete real-device matrix are release blockers,
not warnings that an Agent may bypass.
