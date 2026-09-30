#!/usr/bin/env bash
set -euo pipefail
binary=$1
target=$2
file "$binary"
case "$target" in
  x86_64-unknown-linux-musl|aarch64-unknown-linux-musl)
    readelf -lW "$binary" > "$binary.program-headers"
    readelf -dW "$binary" > "$binary.dynamic-section"
    if grep -Eq 'INTERP|Requesting program interpreter' "$binary.program-headers" ||
       grep -q '(NEEDED)' "$binary.dynamic-section"; then
      echo 'Linux release must have no dynamic loader or shared libraries' >&2
      exit 1
    fi
    case "$target" in
      x86_64-*) readelf -h "$binary" | grep -q 'Machine:.*X86-64' ;;
      aarch64-*) readelf -h "$binary" | grep -q 'Machine:.*AArch64' ;;
    esac
    ;;
  x86_64-apple-darwin) lipo "$binary" -verify_arch x86_64 ;;
  aarch64-apple-darwin) lipo "$binary" -verify_arch arm64 ;;
  *) echo 'Unsupported release target' >&2; exit 1 ;;
esac
"$binary" --version
