#!/usr/bin/env bash
# Builds the toolchain images, then every native library and the smoke test.
set -euo pipefail
cd "$(dirname "$0")/.."

rm -rf build/native build/smoke
mkdir -p build/smoke

docker build --target zig -t monocypher-java-zig docker
docker build --platform linux/amd64 --target ndk -t monocypher-java-ndk docker

run_in() {
  local platform=$1 image=$2 cmd=$3
  docker run --rm --platform "$platform" -u "$(id -u):$(id -g)" -v "$PWD:/work" "$image" bash -c "$cmd"
}

native_platform="linux/$(docker version --format '{{.Server.Arch}}')"
run_in "$native_platform" monocypher-java-zig \
  'scripts/build-natives.sh zig && javac -d build/smoke smoke/net/lastninja/monocypher/Monocypher.java'
run_in linux/amd64 monocypher-java-ndk 'scripts/build-natives.sh android'
