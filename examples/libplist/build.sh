#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
BUILD_DIR="$ROOT/third_party/libplist/build"
LIB_DIR="$BUILD_DIR/src/.libs"
CNARY_LIB_DIR="$BUILD_DIR/libcnary/.libs"
INC_DIR_SRC="$ROOT/third_party/libplist/include"
INC_DIR_BUILD="$BUILD_DIR/include"

if [[ -n "${LLVM_PREFIX:-}" ]]; then
  TOOLCHAIN="$LLVM_PREFIX"
elif [[ -d /opt/homebrew/opt/llvm ]]; then
  TOOLCHAIN=/opt/homebrew/opt/llvm
elif [[ -d /usr/local/opt/llvm ]]; then
  TOOLCHAIN=/usr/local/opt/llvm
else
  TOOLCHAIN="$(dirname "$(command -v clang)")/.."
fi

CLANG="$TOOLCHAIN/bin/clang"
LIBCXX_DIR="$TOOLCHAIN/lib/c++"

# ensure libplist is built with sanitizers
if [[ ! -f "$LIB_DIR/libplist-2.0.a" ]]; then
  echo "[*] libplist static archive missing; building via 'make libplist'"
  (cd "$ROOT" && make libplist)
fi

mkdir -p out
"$CLANG" -O1 -g -fsanitize=address,undefined,fuzzer \
  -I"$INC_DIR_SRC" \
  -I"$INC_DIR_BUILD" \
  fuzz_libplist.c \
  "$LIB_DIR/libplist-2.0.a" \
  "$CNARY_LIB_DIR/libcnary.a" \
  -L"$LIBCXX_DIR" -Wl,-rpath,"$LIBCXX_DIR" -lc++abi \
  -o out/fuzz_libplist
