#!/bin/sh
# Run in the local verification container; package the portable client.
set -eu
[ "$#" -eq 2 ] || { echo 'usage: package_hub_cli.sh OUTPUT COMMIT' >&2; exit 2; }
output=$1
revision=$2
case "$revision" in *[!0-9a-f]*|'') echo 'invalid commit' >&2; exit 2 ;; esac
[ "${#revision}" -eq 40 ] || { echo 'commit must be 40 hex characters' >&2; exit 2; }
source_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
mkdir -p "$output"
output=$(CDPATH= cd -- "$output" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT HUP INT TERM
install -m 755 "$source_dir/plugins/hub/bin/hub" "$work/hub"
install -m 644 "$source_dir/README.md" "$work/README.md"
install -m 644 "$source_dir/LICENSE" "$work/LICENSE"
printf '%s\n' "$revision" > "$work/REVISION"
chmod 644 "$work/REVISION"
name="hub-cli-$revision.tar.gz"
tar --sort=name --mtime=@0 --owner=0 --group=0 --numeric-owner \
    -C "$work" -cf "$work/package.tar" LICENSE README.md REVISION hub
gzip -n -c "$work/package.tar" > "$output/$name"
(cd "$output" && sha256sum "$name" > "$name.sha256")
