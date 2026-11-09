#!/usr/bin/env bash
# Runs the JUnit suite against an ASan and UBSan build of the JNI library, on
# the Docker host's architecture.
set -euo pipefail
cd "$(dirname "$0")/.."

docker run --rm -v "$PWD:/work" -w /work maven:3.9.11-eclipse-temurin-21 bash -c '
set -euo pipefail
apt-get update -qq >/dev/null
apt-get install -y -qq --no-install-recommends gcc libc6-dev >/dev/null

mkdir -p build/sanitizers build/native
gcc -g -O1 -fno-omit-frame-pointer -fsanitize=address,undefined \
  -fno-sanitize-recover=undefined -fPIC -shared -fvisibility=hidden -w \
  -Ivendor/monocypher/src -Isrc/main/c -Ithird_party/jni -Ithird_party/jni/unix \
  vendor/monocypher/src/monocypher.c vendor/monocypher/src/optional/monocypher-ed25519.c src/main/c/*.c \
  -o build/sanitizers/libmonocypher_jni.so

# handle_segv=0 because HotSpot relies on its own SIGSEGV handler.
export ASAN_OPTIONS=handle_segv=0:allow_user_segv_handler=1:detect_leaks=0
export LD_PRELOAD=$(gcc -print-file-name=libasan.so)
mvn -B -Dmaven.repo.local=/work/build/.m2 \
  "-DargLine=-Xcheck:jni -Dmonocypher.library.path=/work/build/sanitizers/libmonocypher_jni.so" test "$@"
' bash "$@"
