#!/usr/bin/env bash
# Cross compiles the JNI library for every target into build/native/<target>/.
# Takes "zig" or "android", each run inside its own image. Run through
# scripts/docker-build.sh so the toolchain versions stay pinned.
set -euo pipefail

SRC=(vendor/monocypher/src/monocypher.c vendor/monocypher/src/optional/monocypher-ed25519.c src/main/c/*.c)
OUT=build/native
LOGS=$(mktemp -d)
CFLAGS=(-O3 -fPIC -shared -fvisibility=hidden -Wall -Wextra -Ivendor/monocypher/src -Isrc/main/c -Ithird_party/jni)
ANDROID_API=21

export ZIG_GLOBAL_CACHE_DIR="$PWD/build/.zig-cache"
export ZIG_LOCAL_CACHE_DIR="$PWD/build/.zig-cache"

# zig_build <dir> <lib name> <jni_md dir> <zig target> [extra flags...]
zig_build() {
  local dir=$1 lib=$2 md=$3 target=$4
  shift 4
  mkdir -p "$OUT/$dir"
  zig cc -target "$target" "${CFLAGS[@]}" -Ithird_party/jni/"$md" \
    -fno-sanitize=undefined -s "$@" "${SRC[@]}" -o "$OUT/$dir/$lib"
  # Windows links also leave import libraries and debug info behind.
  rm -f "$OUT/$dir"/*.lib "$OUT/$dir"/*.pdb
}

# The JVM cannot find MinGW's @N-decorated stdcall exports on 32-bit Windows and
# zig cc rejects --kill-at, so link twice: once to learn the decorated names,
# then again with a .def file that also exports the plain ones.
zig_build_stdcall() {
  local dir=$1 lib=$2 def="$LOGS/$1.def"
  zig_build "$@"
  {
    echo EXPORTS
    grep -aoE '(Java_[A-Za-z0-9_]+|JNI_OnLoad)@[0-9]+' "$OUT/$dir/$lib" | sort -u |
      while read -r name; do echo "${name%@*}=$name"; done
  } >"$def"
  zig_build "$@" "$def"
}

# ndk_build <dir> <clang target>
ndk_build() {
  local dir=$1 target=$2
  mkdir -p "$OUT/$dir"
  clang --target="$target$ANDROID_API" "${CFLAGS[@]}" -Ithird_party/jni/unix \
    -s -Wl,-z,max-page-size=16384 "${SRC[@]}" -o "$OUT/$dir/libmonocypher_jni.so"
}

NAMES=()
PIDS=()

# job <build function> <dir> [args...]: starts one target in the background.
job() {
  local dir=$2
  ("$@") >"$LOGS/$dir" 2>&1 &
  NAMES+=("$dir")
  PIDS+=($!)
}

# Waits for every job, printing each log in order so output never interleaves.
finish() {
  local failed=0 i
  for i in "${!PIDS[@]}"; do
    if wait "${PIDS[$i]}"; then
      echo "built ${NAMES[$i]}"
    else
      echo "FAILED ${NAMES[$i]}"
      failed=1
    fi
    cat "$LOGS/${NAMES[$i]}"
  done
  exit "$failed"
}

SO=libmonocypher_jni.so
DYLIB=libmonocypher_jni.dylib
DLL=monocypher_jni.dll

if [ "$1" = android ]; then
  job ndk_build android-arm64-v8a   aarch64-linux-android
  job ndk_build android-armeabi-v7a armv7a-linux-androideabi
  job ndk_build android-x86         i686-linux-android
  job ndk_build android-x86_64      x86_64-linux-android
  finish
fi

job zig_build linux-x86_64      $SO unix x86_64-linux-gnu.2.17
job zig_build linux-arm64       $SO unix aarch64-linux-gnu.2.17
job zig_build linux-armv6       $SO unix arm-linux-gnueabihf.2.17 -mcpu=arm1176jzf_s
job zig_build linux-x86_64-musl $SO unix x86_64-linux-musl
job zig_build linux-arm64-musl  $SO unix aarch64-linux-musl

job zig_build macos-x86_64 $DYLIB unix x86_64-macos.11.0
job zig_build macos-arm64  $DYLIB unix aarch64-macos.11.0

job zig_build_stdcall windows-x86 $DLL windows x86-windows-gnu
job zig_build windows-x86_64 $DLL windows x86_64-windows-gnu
job zig_build windows-arm64  $DLL windows aarch64-windows-gnu
finish
