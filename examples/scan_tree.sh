#!/bin/sh
# Run ELFMint on every ELF file under a directory and write one JSONL file.
# Usage: examples/scan_tree.sh DIR OUT.jsonl
set -eu
DIR=${1:?directory}; OUT=${2:?output.jsonl}
LIST=$(mktemp)
find "$DIR" -type f -size +15c -print0 | xargs -0 grep -l -a -m1 '^.ELF' > "$LIST" 2>/dev/null || true
elfmint --jsonl "$OUT" --list "$LIST"
echo "$(wc -l < "$LIST") files analysed -> $OUT"
rm -f "$LIST"
