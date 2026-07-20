# Release packaging contract

Release tooling must build from committed dependency locks, produce one asset
for each compatibility-set component, hash every asset and lock, sign the
canonical manifest with Ed25519 outside the repository, verify it against the
pinned public trust root, and only then publish an exact immutable tag.

`trust-root.json` intentionally contains no key during repository bootstrap.
The release workflow fails until a maintainer provides a signing key through
GitHub Actions secrets and pins the corresponding public fingerprint. Never
commit a private key or substitute GitHub authentication for signature checks.
