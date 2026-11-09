#!/usr/bin/env bash
# Loads each Linux library in a real JVM of that platform. Run after
# scripts/docker-build.sh. Exits non-zero if any run fails, and lists any
# platform this Docker host cannot emulate as skipped.
set -uo pipefail
cd "$(dirname "$0")/.."

FAILED=()
SKIPPED=()

# run <target> <docker platform> <image> <java setup command>
run() {
  local target=$1 platform=$2 image=$3 setup=$4
  local label="$target on $image"
  if ! docker run --rm --platform "$platform" "$image" true >/dev/null 2>&1; then
    echo "SKIP $label ($platform not runnable here)"
    SKIPPED+=("$label")
    return
  fi
  echo "RUN  $label"
  # Host networking: the 32-bit Debian container cannot resolve DNS on GitHub runners.
  if ! docker run --rm --network host --platform "$platform" -v "$PWD/build:/build:ro" "$image" \
    sh -c "$setup java -cp /build/smoke net.lastninja.monocypher.Monocypher \
      /build/native/$target/libmonocypher_jni.so"; then
    FAILED+=("$label")
  fi
}

APK8='apk add --quiet --no-cache openjdk8-jre-base; export PATH=/usr/lib/jvm/default-jvm/jre/bin:$PATH;'
APT17='apt-get update -qq >/dev/null && apt-get install -y -qq --no-install-recommends openjdk-17-jre-headless >/dev/null;'

run linux-x86_64      linux/amd64  eclipse-temurin:8u462-b08-jre ''
run linux-x86_64      linux/amd64  eclipse-temurin:25-jre        ''
run linux-arm64       linux/arm64  eclipse-temurin:8u462-b08-jre ''
run linux-arm64       linux/arm64  eclipse-temurin:25-jre        ''
# No maintained Java 8 image exists for 32-bit x86.
run linux-x86         linux/386    debian:bookworm-slim          "$APT17"
# An armv7 JVM loads armv6 hard-float libraries; there is no armv6 Temurin.
run linux-armv6       linux/arm/v7 eclipse-temurin:8u462-b08-jre ''
run linux-x86_64-musl linux/amd64  alpine:3.20                   "$APK8"
run linux-x86_64-musl linux/amd64  eclipse-temurin:25-jre-alpine ''
run linux-arm64-musl  linux/arm64  alpine:3.20                   "$APK8"
run linux-arm64-musl  linux/arm64  eclipse-temurin:25-jre-alpine ''

echo
echo "skipped: ${#SKIPPED[@]}, failed: ${#FAILED[@]}"
for label in "${FAILED[@]+"${FAILED[@]}"}"; do echo "FAILED $label"; done
[ ${#FAILED[@]} -eq 0 ]
