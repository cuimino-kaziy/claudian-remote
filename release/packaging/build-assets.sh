#!/bin/sh
set -eu

release_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
release_version=$(node -p "require('${release_root}/package.json').version")
release_dist="${CLAUDIAN_RELEASE_DIST:-${release_root}/dist}"
release_tmp=$(mktemp -d "${TMPDIR:-/tmp}/claudian-remote-release.XXXXXX")
trap 'rm -rf "${release_tmp}"' EXIT HUP INT TERM

assets_only=false
if [ "${1:-}" = "--assets-only" ]; then
  assets_only=true
elif [ "$#" -ne 0 ]; then
  echo "usage: $0 [--assets-only]" >&2
  exit 64
fi

mkdir -p "${release_dist}" "${release_tmp}/plugin" \
  "${release_tmp}/companion/gateway/mac_companion/launchd" "${release_tmp}/companion/gateway/protocol" \
  "${release_tmp}/relay/gateway/relay" "${release_tmp}/relay/gateway/protocol" "${release_tmp}/relay/release" \
  "${release_tmp}/installer/bin" "${release_tmp}/installer/installer/claudian_remote_lifecycle" \
  "${release_tmp}/installer/release"

cd "${release_root}"
npm run build

cp main.js manifest.json styles.css LICENSE "${release_tmp}/plugin/"
cp main.js manifest.json styles.css "${release_dist}/"
python3.12 - "${release_tmp}/plugin" "${release_dist}/claudian-remote-plugin-${release_version}.zip" <<'PY'
from pathlib import Path
import sys
from zipfile import ZipFile, ZipInfo, ZIP_STORED

plugin_root, output = map(Path, sys.argv[1:])
with ZipFile(output, "w", compression=ZIP_STORED) as archive:
    for name in ("LICENSE", "main.js", "manifest.json", "styles.css"):
        entry = ZipInfo(f"claudian-remote/{name}", (2000, 1, 1, 0, 0, 0))
        entry.create_system = 3
        entry.external_attr = 0o100644 << 16
        archive.writestr(entry, (plugin_root / name).read_bytes())
PY
cp gateway/mac_companion/__init__.py gateway/mac_companion/bridge_server.py \
  gateway/mac_companion/config.py gateway/mac_companion/relay_ws_client.py \
  gateway/mac_companion/pairing_admin.py \
  gateway/mac_companion/runner.py gateway/mac_companion/stream_pump.py \
  gateway/mac_companion/upload_receiver.py gateway/mac_companion/config.example.json \
  "${release_tmp}/companion/gateway/mac_companion/"
cp gateway/mac_companion/launchd/com.claudian.remote.companion.plist.example \
  "${release_tmp}/companion/gateway/mac_companion/launchd/"
cp gateway/protocol/*.py gateway/protocol/*.md "${release_tmp}/companion/gateway/protocol/"
cp -R gateway/protocol/fixtures "${release_tmp}/companion/gateway/protocol/"
cp gateway/requirements.lock LICENSE "${release_tmp}/companion/"
cp gateway/relay/*.py gateway/relay/Caddyfile.example gateway/relay/config.example.json gateway/relay/LICENSE \
  "${release_tmp}/relay/gateway/relay/"
cp -R gateway/relay/edge gateway/relay/systemd "${release_tmp}/relay/gateway/relay/"
cp gateway/protocol/*.py gateway/protocol/*.md "${release_tmp}/relay/gateway/protocol/"
cp -R gateway/protocol/fixtures "${release_tmp}/relay/gateway/protocol/"
cp gateway/requirements.lock "${release_tmp}/relay/gateway/"
cp release/support-matrix.json "${release_tmp}/relay/release/"
cp CLAUDIAN_REMOTE_INSTALL.md LICENSE "${release_tmp}/installer/"
cp installer/__init__.py "${release_tmp}/installer/installer/"
cp installer/claudian_remote_lifecycle/*.py "${release_tmp}/installer/installer/claudian_remote_lifecycle/"
cp release/packaging/claudian-remote-lifecycle "${release_tmp}/installer/bin/"
chmod 0755 "${release_tmp}/installer/bin/claudian-remote-lifecycle"
cp release/lifecycle-dependencies.lock.json release/release-manifest.schema.json \
  release/support-matrix.json release/trust-root.json \
  "${release_tmp}/installer/release/"
node release/packaging/prepare-lifecycle-lock.mjs "${release_tmp}/installer"

sh release/packaging/deterministic-tar.sh "${release_tmp}/plugin" "${release_dist}/claudian-remote-plugin-${release_version}.tar.gz"
sh release/packaging/deterministic-tar.sh "${release_tmp}/companion" "${release_dist}/claudian-remote-companion-${release_version}.tar.gz"
sh release/packaging/deterministic-tar.sh "${release_tmp}/relay" "${release_dist}/claudian-remote-relay-${release_version}.tar.gz"
sh release/packaging/deterministic-tar.sh "${release_tmp}/installer" "${release_dist}/claudian-remote-lifecycle-${release_version}.tar.gz"
cp gateway/relay/legacy_retirement.py \
  "${release_dist}/claudian-remote-legacy-retirement-helper-${release_version}.py"

if [ "${assets_only}" = false ]; then
  node release/packaging/prepare-manifest.mjs "${CLAUDIAN_RELEASE_TAG:-v${release_version}}" "${release_dist}"
fi
