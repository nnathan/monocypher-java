#!/usr/bin/env bash
# Packages the compiled classes and Android libraries into build/monocypher-android.aar.
# Run after Maven has compiled target/classes.
set -euo pipefail

AAR=build/aar
rm -rf "$AAR" build/monocypher-android.aar
mkdir -p "$AAR"

jar cf "$AAR/classes.jar" -C target/classes net
: >"$AAR/R.txt"
cat >"$AAR/AndroidManifest.xml" <<'EOF'
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="net.lastninja.monocypher">
    <uses-sdk android:minSdkVersion="21" />
</manifest>
EOF

for abi in arm64-v8a armeabi-v7a x86 x86_64; do
  mkdir -p "$AAR/jni/$abi"
  cp "build/native/android-$abi/libmonocypher_jni.so" "$AAR/jni/$abi/"
done

jar cfM build/monocypher-android.aar -C "$AAR" .
