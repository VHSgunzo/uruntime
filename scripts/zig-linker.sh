#!/usr/bin/env bash
set -euo pipefail

: "${URUNTIME_RUST_TARGET:?URUNTIME_RUST_TARGET is required}"
: "${URUNTIME_ZIG_TARGET:?URUNTIME_ZIG_TARGET is required}"
: "${URUNTIME_RUST_SYSROOT:?URUNTIME_RUST_SYSROOT is required}"

case "$URUNTIME_RUST_TARGET" in
  x86_64-unknown-linux-musl) expected=x86_64-linux-musl ;;
  aarch64-unknown-linux-musl) expected=aarch64-linux-musl ;;
  riscv64gc-unknown-linux-musl) expected=riscv64-linux-musl ;;
  loongarch64-unknown-linux-musl) expected=loongarch64-linux-musl ;;
  powerpc64-unknown-linux-musl) expected=powerpc64-linux-musl ;;
  powerpc64le-unknown-linux-musl) expected=powerpc64le-linux-musl ;;
  *) printf 'zig-linker: unsupported Rust target: %s\n' "$URUNTIME_RUST_TARGET" >&2; exit 2 ;;
esac

if [[ "$URUNTIME_ZIG_TARGET" != "$expected" ]]; then
  printf 'zig-linker: target mismatch: Rust %s maps to Zig %s, not %s\n' \
    "$URUNTIME_RUST_TARGET" "$expected" "$URUNTIME_ZIG_TARGET" >&2
  exit 2
fi

rust_crt_dir="$URUNTIME_RUST_SYSROOT/lib/rustlib/$URUNTIME_RUST_TARGET/lib/self-contained"
args=()
skip_target_value=false
for arg in "$@"; do
  if $skip_target_value; then
    skip_target_value=false
    continue
  fi
  case "$arg" in
    --target|-target)
      skip_target_value=true
      ;;
    --target=*|-target=*)
      ;;
    -Wl,--fix-cortex-a53-843419)
      ;;
    -nostartfiles|-lc)
      ;;
    "$rust_crt_dir/crt1.o"|"$rust_crt_dir/Scrt1.o"|"$rust_crt_dir/rcrt1.o"|\
    "$rust_crt_dir/crti.o"|"$rust_crt_dir/crtn.o"|"$rust_crt_dir/crtbegin.o"|\
    "$rust_crt_dir/crtbeginS.o"|"$rust_crt_dir/crtend.o"|"$rust_crt_dir/crtendS.o")
      ;;
    *)
      args+=("$arg")
      ;;
  esac
done

zig=${URUNTIME_ZIG:-zig}
exec "$zig" cc -target "$URUNTIME_ZIG_TARGET" "${args[@]}"
