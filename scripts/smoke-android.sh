#!/usr/bin/env bash
# Runs the smoke test from the AAR on a connected x86_64 emulator.
set -euo pipefail

DIR=/data/local/tmp/monocypher
BUILD_TOOLS=$(ls -d "$ANDROID_HOME"/build-tools/* | sort -V | tail -1)

rm -rf build/dex build/aar-unpacked
mkdir -p build/dex build/aar-unpacked
unzip -q build/monocypher-android.aar -d build/aar-unpacked
"$BUILD_TOOLS/d8" --min-api 21 --output build/dex \
  build/smoke/Smoke.class build/aar-unpacked/classes.jar

adb shell mkdir -p "$DIR"
adb push build/dex/classes.dex build/aar-unpacked/jni/x86_64/libmonocypher_jni.so "$DIR"
adb shell "cd $DIR && dalvikvm64 -Djava.library.path=$DIR -cp classes.dex Smoke" | tee build/android.log
grep -q '^OK java' build/android.log
