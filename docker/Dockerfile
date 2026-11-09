# Pinned toolchains for every native target, as two images. Zig runs natively
# on the host architecture because it crashes intermittently under x86_64
# emulation. The Android NDK ships no arm64 Linux host, so it is always x86_64.

FROM eclipse-temurin:8u462-b08-jdk AS zig
ARG TARGETARCH
ENV ZIG_VERSION=0.17.0
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl xz-utils \
 && rm -rf /var/lib/apt/lists/*
RUN case "${TARGETARCH}" in \
      amd64) arch=x86_64;  sha=1cbe9df9f27e6b78d14ccbca43b6703a404ef79ef1c463de901d7f088d4e2026 ;; \
      arm64) arch=aarch64; sha=9e8d11661d4ae3bd57702a3832781e23ad151dde5798e16a5ccd503f65234ff8 ;; \
      *) echo "unsupported architecture ${TARGETARCH}"; exit 1 ;; \
    esac \
 && curl -fsSL "https://ziglang.org/download/${ZIG_VERSION}/zig-${arch}-linux-${ZIG_VERSION}.tar.xz" -o /tmp/zig.tar.xz \
 && echo "${sha}  /tmp/zig.tar.xz" | sha256sum -c - \
 && mkdir /opt/zig && tar -xJf /tmp/zig.tar.xz -C /opt/zig --strip-components=1 \
 && rm /tmp/zig.tar.xz
ENV PATH=/opt/zig:$PATH
WORKDIR /work

FROM debian:bookworm-slim AS ndk
ENV NDK_VERSION=r27d
ENV NDK_SHA256=601246087a682d1944e1e16dd85bc6e49560fe8b6d61255be2829178c8ed15d9
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl unzip \
 && rm -rf /var/lib/apt/lists/*
RUN curl -fsSL "https://dl.google.com/android/repository/android-ndk-${NDK_VERSION}-linux.zip" -o /tmp/ndk.zip \
 && echo "${NDK_SHA256}  /tmp/ndk.zip" | sha256sum -c - \
 && unzip -q /tmp/ndk.zip -d /opt \
 && mv "/opt/android-ndk-${NDK_VERSION}" /opt/ndk \
 && rm /tmp/ndk.zip
ENV PATH=/opt/ndk/toolchains/llvm/prebuilt/linux-x86_64/bin:$PATH
WORKDIR /work
