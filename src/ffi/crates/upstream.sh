#!/usr/bin/env bash
# The vendored files are upstream leanVM at the revision Cargo.toml pins, plus this repository's EIP-8288 changes:
# crates/aggregation (upstream crates/aggregation) and guests/lean_ethereum.py (upstream guests/lean_ethereum.py).
# Usage (LEANVM_REPO overrides the clone URL):
#   crates/upstream.sh diff            print those changes: upstream at the pin against the vendored files
#   crates/upstream.sh update <rev>    move the vendored files and the pin to <rev>: each file gets a three-way merge
#                                      (ours, upstream at the pin, upstream at <rev>); conflicts stay marked for review,
#                                      files upstream added or removed are listed, not applied
set -euo pipefail
cd "$(dirname "$0")/.."
root=$PWD
mode=${1:?usage: crates/upstream.sh diff | update <rev>}
old=$(grep -o 'leanEthereum/leanVM", rev = "[0-9a-f]*"' Cargo.toml | grep -o '[0-9a-f]\{40\}' | sort -u)
[ "$(wc -l <<<"$old" | tr -d " ")" = 1 ] || { echo "Cargo.toml must pin exactly one leanVM revision" >&2; exit 1; }
vendored=(crates/aggregation guests/lean_ethereum.py)

work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
git clone -q --filter=blob:none "${LEANVM_REPO:-https://github.com/leanEthereum/leanVM}" "$work/repo"
git -C "$work/repo" worktree add -q --detach "$work/base" "$old"

if [ "$mode" = diff ]; then
  for path in "${vendored[@]}"; do
    git diff --no-index --stat=200 -- "$work/base/$path" "$path" | sed "s|$work/base/||g" || true
    git diff --no-index -- "$work/base/$path" "$path" | sed "s|$work/base/||g" || true
  done
  exit 0
fi
[ "$mode" = update ] || { echo "usage: crates/upstream.sh diff | update <rev>" >&2; exit 1; }
new=$(git -C "$work/repo" rev-parse --verify "${2:?update needs a revision}^{commit}")
git -C "$work/repo" worktree add -q --detach "$work/next" "$new"

conflicts=0
files=$(for tree in "$work/base" "$work/next" "$root"; do (cd "$tree" && find "${vendored[@]}" -type f 2>/dev/null); done | sort -u)
for f in $files; do
  base=$work/base/$f next=$work/next/$f
  if [ -f "$f" ] && [ -f "$base" ] && [ -f "$next" ]; then
    git merge-file -q -L ours -L "leanVM ${old:0:10}" -L "leanVM ${new:0:10}" "$f" "$base" "$next" \
      || { echo "conflict: $f"; conflicts=$((conflicts + 1)); }
  elif [ ! -f "$f" ] && [ -f "$base" ] && [ -f "$next" ] && ! cmp -s "$base" "$next"; then
    echo "upstream changed a file this copy dropped: $f"
  elif [ ! -f "$base" ] && [ -f "$next" ]; then
    echo "upstream added: $f"
  elif [ -f "$base" ] && [ ! -f "$next" ] && [ -f "$f" ]; then
    echo "upstream removed: $f"
  fi
done

sed -i.bak "s/$old/$new/g" Cargo.toml && rm Cargo.toml.bak
cargo update -q -p isa
echo "leanVM ${old:0:10} -> ${new:0:10}; $conflicts conflicted file(s). Rebuild, rerun the tests and print the new AGGREGATED_VK."
