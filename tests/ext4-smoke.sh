#!/usr/bin/env bash
# Non-provisioning Linux test. Only writes to the supplied scratch directory.
set -eu
scratch=${1:?Supply a scratch directory}
mkdir -p "$scratch"
scratch=$(cd "$scratch" && pwd)
image="$scratch/evidence.img"
note="$scratch/note.txt"
dd if=/dev/zero of="$image" bs=1048576 count=2 2>/dev/null
mke2fs -q -F -t ext4 -b 1024 -I 128 -m 0 \
  -O 'extent,filetype,^has_journal,^64bit,^metadata_csum,^orphan_file' "$image"
printf 'Investigator note: LAB{deleted_is_not_erased}\n' > "$note"
debugfs -w -R "write $note /deleted-note.txt" "$image"
block=$(debugfs -R 'blocks /deleted-note.txt' "$image" 2>/dev/null | tr -d ' \n')
test -n "$block"
debugfs -w -R 'rm /deleted-note.txt' "$image"
debugfs -R "testb $block" "$image" 2>/dev/null | grep 'not in use'
dd if="$image" bs=1024 skip="$block" count=1 2>/dev/null | grep -a 'LAB{deleted_is_not_erased}'
if command -v blkls >/dev/null 2>&1; then
    blkls "$image" | grep -a 'LAB{deleted_is_not_erased}'
    echo 'PASS: actual Sleuth Kit unallocated-block recovery.'
else
    echo 'PASS: file deleted, block marked free, content retained. blkls unavailable in this environment.'
fi
