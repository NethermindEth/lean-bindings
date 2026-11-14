#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Demerzel Solutions Limited
# SPDX-License-Identifier: MIT
#
# Runs upstream leanVM's README benchmarks exactly as documented at each revision, to relate a machine to the README's
# published figures.
#
#   leanvm-readme-bench.sh OUT REV [REV...]
#
# For each REV it clones leanEthereum/leanVM, copies README.md, and runs every `cargo leanvm ...` line from the
# README's bash blocks in order, saving each command's output to OUT/leanvm-REV/NN.txt.
set -euo pipefail
out=$1; shift
for rev in "$@"; do
  dir=$out/leanvm-${rev:0:10}
  src=$(mktemp -d)
  mkdir -p "$dir"
  git clone -q https://github.com/leanEthereum/leanVM.git "$src"
  git -C "$src" -c advice.detachedHead=false checkout -q "$rev"
  git -C "$src" rev-parse HEAD > "$dir/revision.txt"
  cp "$src/README.md" "$dir/README.md"
  awk '/^```bash/{b=1; next} /^```/{b=0} b && /^cargo leanvm /' "$src/README.md" > "$dir/commands.txt"
  (cd "$src" && cargo build -q --release -p leanvm-cli) > "$dir/build.txt" 2>&1
  i=0
  while IFS= read -r cmd; do
    i=$((i + 1))
    echo "== $cmd" | tee "$dir/$(printf %02d $i).txt"
    (cd "$src" && eval "$cmd") >> "$dir/$(printf %02d $i).txt" 2>&1 || echo "exit $?" >> "$dir/$(printf %02d $i).txt"
    tail -n 12 "$dir/$(printf %02d $i).txt"
  done < "$dir/commands.txt"
  rm -rf "$src"
done
