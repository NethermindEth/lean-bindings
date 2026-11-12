#!/usr/bin/env bash
# The vendored crates are upstream leanVM at the revision Cargo.toml pins, plus this repository's EIP-8288 changes.
# Usage (LEANVM_REPO overrides the clone URL):
#   crates/upstream.sh diff            print those changes: upstream crates at the pin against crates/
#   crates/upstream.sh update <rev>    move the crates and the pin to <rev>: each vendored file gets a three-way merge
#                                      (ours, upstream at the pin, upstream at <rev>); conflicts stay marked for review,
#                                      files upstream added or removed are listed, not applied
set -euo pipefail
cd "$(dirname "$0")/.."
root=$PWD
mode=${1:?usage: crates/upstream.sh diff | update <rev>}
old=$(grep -o 'leanEthereum/leanVM", rev = "[0-9a-f]*"' Cargo.toml | grep -o '[0-9a-f]\{40\}' | sort -u)
[ "$(wc -l <<<"$old")" = 1 ] || { echo "Cargo.toml must pin exactly one leanVM revision" >&2; exit 1; }

work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
git clone -q --filter=blob:none "${LEANVM_REPO:-https://github.com/leanEthereum/leanVM}" "$work/repo"
git -C "$work/repo" worktree add -q --detach "$work/base" "$old"

if [ "$mode" = diff ]; then
  for crate in rec_aggregation signatures; do
    git diff --no-index --stat=200 -- "$work/base/crates/$crate" "crates/$crate" | sed "s|$work/base||g" || true
    git diff --no-index -- "$work/base/crates/$crate" "crates/$crate" | sed "s|$work/base||g" || true
  done
  exit 0
fi
[ "$mode" = update ] || { echo "usage: crates/upstream.sh diff | update <rev>" >&2; exit 1; }
new=$(git -C "$work/repo" rev-parse --verify "${2:?update needs a revision}^{commit}")
git -C "$work/repo" worktree add -q --detach "$work/next" "$new"

conflicts=0
for crate in rec_aggregation signatures; do
  files=$(for tree in "$work/base" "$work/next" "$root"; do (cd "$tree/crates/$crate" && find . -type f); done | sort -u)
  for f in $files; do
    ours=crates/$crate/$f base=$work/base/crates/$crate/$f next=$work/next/crates/$crate/$f
    if [ -f "$ours" ] && [ -f "$base" ] && [ -f "$next" ]; then
      git merge-file -q -L ours -L "leanVM ${old:0:10}" -L "leanVM ${new:0:10}" "$ours" "$base" "$next" \
        || { echo "conflict: $ours"; conflicts=$((conflicts + 1)); }
    elif [ ! -f "$ours" ] && [ -f "$base" ] && [ -f "$next" ] && ! cmp -s "$base" "$next"; then
      echo "upstream changed a file this copy dropped: crates/$crate/$f"
    elif [ ! -f "$base" ] && [ -f "$next" ]; then
      echo "upstream added: crates/$crate/$f"
    elif [ -f "$base" ] && [ ! -f "$next" ] && [ -f "$ours" ]; then
      echo "upstream removed: $ours"
    fi
  done
done

sed -i "s/$old/$new/g" Cargo.toml
cargo update -q -p leanvm_core
echo "leanVM ${old:0:10} -> ${new:0:10}; $conflicts conflicted file(s). Rebuild, rerun the tests and print the new AGGREGATED_VK."
