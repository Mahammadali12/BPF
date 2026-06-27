#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN_DIR="$ROOT_DIR/bin"
ELF_DIR="$ROOT_DIR/elf"
BPF_SRC="$ROOT_DIR/src/bpf/latency_ringbuf.bpf.c"
LOADER_SRC="$ROOT_DIR/src/loader/loader_ringbuf.c"
BPF_OBJ="$ELF_DIR/latency_ringbuf.bpf.o"
LOADER_BIN="$BIN_DIR/loader_ringbuf"

mkdir -p "$BIN_DIR" "$ELF_DIR"

clang -O2 -g -target bpf -c "$BPF_SRC" -o "$BPF_OBJ"
gcc -O2 -o "$LOADER_BIN" "$LOADER_SRC" -lbpf -lelf -lz -lpthread