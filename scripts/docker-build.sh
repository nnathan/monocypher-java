#!/usr/bin/env bash
# Builds the toolchain images, then every native library, the jar, the AAR and the smoke test.
set -euo pipefail
cd "$(dirname "$0")/.."

MAVEN_IMAGE=maven:3.9.11-eclipse-temurin-21

rm -rf build/native build/smoke target
mkdir -p build/smoke

docker build --target zig -t monocypher-java-zig docker
docker build --platform linux/amd64 --target ndk -t monocypher-java-ndk docker

run_in() {
  local platform=$1 image=$2 cmd=$3
  docker run --rm --platform "$platform" -u "$(id -u):$(id -g)" -v "$PWD:/work" -w /work "$image" bash -c "$cmd"
}

native_platform="linux/$(docker version --format '{{.Server.Arch}}')"
run_in "$native_platform" monocypher-java-zig 'scripts/build-natives.sh zig'
run_in linux/amd64 monocypher-java-ndk 'scripts/build-natives.sh android'
run_in "$native_platform" "$MAVEN_IMAGE" \
  'mvn -B -q -Dmaven.repo.local=/work/build/.m2 package && cp target/monocypher-java-*[0-9].jar build/monocypher-java.jar && scripts/build-aar.sh'
run_in "$native_platform" monocypher-java-zig 'javac -cp build/monocypher-java.jar -d build/smoke smoke/Smoke.java'
