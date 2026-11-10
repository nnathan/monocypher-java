# monocypher-java

[![Maven Central](https://img.shields.io/maven-central/v/net.lastninja.monocypher/monocypher-java)](https://central.sonatype.com/artifact/net.lastninja.monocypher/monocypher-java)
[![javadoc](https://javadoc.io/badge/net.lastninja.monocypher/monocypher-java.svg)](https://javadoc.io/doc/net.lastninja.monocypher/monocypher-java)

monocypher-java provides JNI bindings for [Monocypher](https://monocypher.org/),
for Java 8 and later and for Android, with no runtime dependencies.

## Status

monocypher-java binds the full public API of Monocypher 4.0.3, including the
optional SHA-512 and Ed25519 functions. Functions keep their C names and
argument order, so the [Monocypher manual](https://monocypher.org/manual/)
applies directly. Each function's Javadoc has an example and links to its
page in the manual.

Everything is in two classes. `Monocypher` holds the API, and `Hazmat` holds
the low-level EdDSA building blocks.

The bindings differ from C in these ways:

  - Every byte argument is a direct `ByteBuffer`, used from its position to its
    limit. A pointer and its size become one buffer. Calls never move the
    position of any buffer.
  - Fixed sizes, such as a 32-byte key, are checked. A buffer with the wrong
    number of bytes remaining throws `IllegalArgumentException`. So does a heap
    buffer, or a read-only buffer that C would write to.
  - A `null` buffer throws `NullPointerException`, except where C allows
    `NULL`, such as additional data. There `null` means the same as an empty
    buffer.
  - Integers narrower than the Java type are checked rather than truncated. For
    example, the IETF ChaCha20 counter is a `long` that must fit in 32 bits.
  - Buffers may only overlap where the manual and Monocypher's tests allow it.
    Where in-place operation is allowed, the input and output must be exactly
    the same bytes or not overlap at all. Other overlap throws
    `IllegalArgumentException` instead of being undefined behaviour.
  - Functions that return an `int` status return 0 on success and -1 on
    failure, as in C.
  - Contexts such as `Blake2b_ctx` are objects whose state lives off the Java
    heap, where C uses it in place. Using one before it is initialised, or
    after it is finalised or wiped, throws `IllegalStateException`. Contexts
    are `AutoCloseable`, and closing one wipes it.
  - The Argon2 parameters are the typed classes `Argon2_config`,
    `Argon2_inputs` and `Argon2_extras`. The algorithm is an enum usable by the
    same names as in C, such as `CRYPTO_ARGON2_ID`.
  - Arguments that Monocypher wipes, such as key pair seeds, count as outputs,
    so they must be writable.

Rules that cannot be checked, such as never reusing a nonce with the same key,
are still the caller's responsibility.

## Installation

monocypher-java is on Maven Central. The API is not yet stable, so expect
changes between 0.x versions.

With Maven:

```xml
<dependency>
  <groupId>net.lastninja.monocypher</groupId>
  <artifactId>monocypher-java</artifactId>
  <version>0.1.0</version>
</dependency>
```

With Gradle:

```kotlin
implementation("net.lastninja.monocypher:monocypher-java:0.1.0")
```

For Android, download `monocypher-android.aar` from the
[releases page](https://github.com/nnathan/monocypher-java/releases), put it in
your module's `libs` folder, and add:

```kotlin
implementation(files("libs/monocypher-android.aar"))
```

Use the AAR instead of the jar on Android, not alongside it, as both contain the
same classes.

Releases are signed with this key:

```
5F78 B3CA 429A 65F2 62B0  E3D2 7CD6 F762 D57F 5184
Naveen Nathan <naveen@lastninja.net>
```

To check a downloaded AAR, fetch the key and verify its `.asc` signature:

```
gpg --keyserver hkps://keys.openpgp.org --recv-keys 5F78B3CA429A65F262B0E3D27CD6F762D57F5184
gpg --verify monocypher-android.aar.asc monocypher-android.aar
```

## Platforms

`monocypher-java.jar` contains native libraries for these platforms, and loads
the right one when the `Monocypher` class is first used:

| Operating system | Architectures |
|---|---|
| Linux, glibc 2.17 or later | x86_64, arm64, armv6 |
| Linux, musl | x86_64, arm64 |
| macOS 11 or later | x86_64, arm64 |
| Windows | x86, x86_64, arm64 |

`monocypher-android.aar` contains the Android libraries for arm64-v8a,
armeabi-v7a, x86 and x86_64, for API level 21 or later.

To load a different build of the native library, set the
`monocypher.library.path` system property to its full path.

## Supported functions

### Constant time comparison

  - `crypto_verify16`
  - `crypto_verify32`
  - `crypto_verify64`

### Memory wipe

  - `crypto_wipe`, for `byte[]`, `ByteBuffer` and every context

### Authenticated encryption

  - `crypto_aead_lock`
  - `crypto_aead_unlock`
  - `crypto_aead_init_x`
  - `crypto_aead_init_djb`
  - `crypto_aead_init_ietf`
  - `crypto_aead_write`
  - `crypto_aead_read`
  - `AEAD_ctx`

### BLAKE2b

  - `crypto_blake2b`
  - `crypto_blake2b_keyed`
  - `crypto_blake2b_init`
  - `crypto_blake2b_keyed_init`
  - `crypto_blake2b_update`
  - `crypto_blake2b_final`
  - `Blake2b_ctx`

### Argon2

  - `crypto_argon2`
  - `crypto_argon2_no_extras`
  - `Argon2_config`, `Argon2_inputs`, `Argon2_extras`
  - `CRYPTO_ARGON2_D`, `CRYPTO_ARGON2_I`, `CRYPTO_ARGON2_ID`

### X25519

  - `crypto_x25519_public_key`
  - `crypto_x25519`
  - `crypto_x25519_to_eddsa`
  - `crypto_x25519_inverse`
  - `crypto_x25519_dirty_small`
  - `crypto_x25519_dirty_fast`

### EdDSA

  - `crypto_eddsa_key_pair`
  - `crypto_eddsa_sign`
  - `crypto_eddsa_check`
  - `crypto_eddsa_to_x25519`

### EdDSA building blocks, in `Hazmat`

  - `crypto_eddsa_trim_scalar`
  - `crypto_eddsa_reduce`
  - `crypto_eddsa_mul_add`
  - `crypto_eddsa_scalarbase`
  - `crypto_eddsa_check_equation`

### ChaCha20

  - `crypto_chacha20_h`
  - `crypto_chacha20_djb`
  - `crypto_chacha20_ietf`
  - `crypto_chacha20_x`

### Poly1305

  - `crypto_poly1305`
  - `crypto_poly1305_init`
  - `crypto_poly1305_update`
  - `crypto_poly1305_final`
  - `Poly1305_ctx`

### Elligator

  - `crypto_elligator_map`
  - `crypto_elligator_rev`
  - `crypto_elligator_key_pair`

### SHA-512

  - `crypto_sha512`
  - `crypto_sha512_init`
  - `crypto_sha512_update`
  - `crypto_sha512_final`
  - `SHA512_ctx`

### HMAC-SHA-512

  - `crypto_sha512_hmac`
  - `crypto_sha512_hmac_init`
  - `crypto_sha512_hmac_update`
  - `crypto_sha512_hmac_final`
  - `SHA512_HMAC_ctx`

### HKDF-SHA-512

  - `crypto_sha512_hkdf`
  - `crypto_sha512_hkdf_expand`

### Ed25519

  - `crypto_ed25519_key_pair`
  - `crypto_ed25519_sign`
  - `crypto_ed25519_check`
  - `crypto_ed25519_ph_sign`
  - `crypto_ed25519_ph_check`

## Known limitations

  - **Only direct buffers are accepted.** The garbage collector may copy a heap
    buffer or array while moving it, leaving copies of secrets that cannot be
    wiped. Direct buffers stay in one place.
  - **Wiping a `byte[]` cannot reach earlier copies.** `crypto_wipe(byte[])`
    leaves no unwiped copy of its own behind, but copies the garbage collector
    made earlier are out of reach. Prefer direct buffers for secrets.
  - **In-place operation must be exact.** Where Monocypher allows the input and
    output of AEAD or ChaCha20 to be the same buffer, they must be exactly the
    same bytes. A partial overlap is rejected.
  - **Argon2 is stricter than Monocypher's tests.** The password, salt, key and
    additional data may overlap each other, as the manual allows. The hash and
    work area may not overlap anything. Monocypher's own tests also overlap the
    work area with the inputs, which these bindings reject.
  - **The Argon2 work area is limited to one `ByteBuffer`.** It must be exactly
    `nb_blocks * 1024` bytes and 8-byte aligned, so `nb_blocks` is at most
    2097151, just under 2 GiB. A fresh `ByteBuffer.allocateDirect` buffer is
    aligned in practice.
  - **BLAKE2b cannot produce an empty hash.** The manual requires a hash size
    between 1 and 64, so the 85 vectors in Monocypher's tests with a
    zero-length hash are not run.
  - **Ed25519 has no overlap checks.** It shares EdDSA's signing code, which the
    manual and Monocypher's tests allow to overlap, but the manual says nothing
    about Ed25519 itself.
  - **Contexts and buffers are not safe to share between threads.** Nothing
    stops two threads using one context, or changing a buffer during a call.
  - **On Windows one small file stays behind.** The desktop jar extracts its
    native library to a temporary file, and Windows cannot delete a loaded DLL.

## Building and testing

Only Docker is required:

```
scripts/docker-build.sh     # every native target, the JUnit suite, the jar and the AAR
scripts/smoke-linux.sh      # runs the jar in real JVMs
scripts/test-sanitizers.sh  # runs the suite under AddressSanitizer and UBSan
```

The JUnit suite runs with `-Xcheck:jni`. Besides tests for each group of
functions, it ports Monocypher's own `tests/test.c` and runs it against the
official test vectors from the 4.0.3 release. See
`src/test/resources/upstream/PROVENANCE.md` for where the vectors come from.

Monocypher is a submodule, so clone with `--recurse-submodules`.

## Licence

monocypher-java is released under [CC0 1.0 Universal](LICENSE), dedicating it
to the public domain.

It includes [Monocypher](https://monocypher.org/), which is compiled into the
native libraries in the jar and the AAR. Monocypher is copyright Loup Vaillant,
Michael Savage and Fabio Scotoni, and is dual-licensed under your choice of the
2-clause BSD licence or CC0 1.0 Universal. See
[Monocypher's licence](https://github.com/LoupVaillant/Monocypher/blob/4.0.3/LICENCE.md).

The jar and the AAR include both licences, as `META-INF/LICENSE` and
`META-INF/monocypher/LICENCE.md`.

The JNI headers in `third_party/jni` are from OpenJDK 8 and keep their own
licence, GPL version 2 with the Classpath Exception, as stated in
[`third_party/jni/LICENSE`](third_party/jni/LICENSE). They are only used to
compile the native libraries.
