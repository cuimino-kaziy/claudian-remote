#!/bin/sh
set -eu

release_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
release_version=$(node -p "require('${release_root}/package.json').version")
release_dist="${release_root}/dist"
release_tmp=$(mktemp -d "${TMPDIR:-/tmp}/claudian-remote-release.XXXXXX")
trap 'rm -rf "${release_tmp}"' EXIT HUP INT TERM

mkdir -p "${release_dist}" "${release_tmp}/plugin" "${release_tmp}/companion/gateway" "${release_tmp}/relay/gateway" "${release_tmp}/installer/release"

cd "${release_root}"
npm run build

cp main.js manifest.json styles.css LICENSE "${release_tmp}/plugin/"
cp -R gateway/mac_companion gateway/protocol "${release_tmp}/companion/gateway/"
cp gateway/requirements.lock LICENSE "${release_tmp}/companion/"
cp -R gateway/relay gateway/protocol "${release_tmp}/relay/gateway/"
cp gateway/requirements.lock "${release_tmp}/relay/gateway/"
cp -R release/packaging release/release-manifest.schema.json release/support-matrix.json release/trust-root.json "${release_tmp}/installer/release/"
cp LICENSE "${release_tmp}/installer/"

COPYFILE_DISABLE=1 tar -C "${release_tmp}/plugin" -czf "${release_dist}/claudian-remote-plugin-${release_version}.tar.gz" .
COPYFILE_DISABLE=1 tar -C "${release_tmp}/companion" -czf "${release_dist}/claudian-remote-companion-${release_version}.tar.gz" .
COPYFILE_DISABLE=1 tar -C "${release_tmp}/relay" -czf "${release_dist}/claudian-remote-relay-${release_version}.tar.gz" .
COPYFILE_DISABLE=1 tar -C "${release_tmp}/installer" -czf "${release_dist}/claudian-remote-lifecycle-contract-${release_version}.tar.gz" .

node release/packaging/prepare-manifest.mjs "${CLAUDIAN_RELEASE_TAG:-v${release_version}}" "${release_dist}"
