#!/bin/sh
set -eu

if [ "$#" -ne 2 ]; then
  echo "usage: $0 ROOT OUTPUT" >&2
  exit 64
fi

archive_root=$1
archive_output=$2
archive_parent=$(dirname "${archive_output}")
archive_name=$(basename "${archive_output}")
archive_tmp=$(mktemp "${archive_parent}/.${archive_name}.XXXXXX")
trap 'rm -f "${archive_tmp}"' EXIT HUP INT TERM

export TZ=UTC
find "${archive_root}" -exec touch -h -t 200001010000 {} +
(
  cd "${archive_root}"
  find . -print0 \
    | LC_ALL=C sort -z \
    | COPYFILE_DISABLE=1 tar --null --no-recursion --no-mac-metadata \
        --format ustar --uid 0 --gid 0 --uname root --gname wheel \
        -T - -cf -
) | gzip -n > "${archive_tmp}"
mv "${archive_tmp}" "${archive_output}"
trap - EXIT HUP INT TERM
