# monocypher-java

JNI bindings for Monocypher: as C-like as possible, with Java safety where it helps, so anyone familiar with Monocypher can easily use this library. Java 8+, no runtime dependencies. `~/code/mini-monocypher` is the sibling Rust binding and uses the same module groups.

## Layout

- `src/main/java/net/lastninja/monocypher/Monocypher.java`: the whole public API, deliberately one class
- `src/main/c/<group>.c`: JNI code per group; shared macros are in `jni_util.h`
- `src/test/java/<Group>Test.java`: tests per group; helpers are in `net/lastninja/monocypher/TestUtil.java`
- `vendor/monocypher`: upstream, as a submodule (clone with `--recurse-submodules`)
- `third_party/jni`: unmodified Java 8 JNI headers

## Build and test

`scripts/docker-build.sh` builds every native target, runs the JUnit suite, and produces `build/monocypher-java.jar` and `build/monocypher-android.aar`. `scripts/smoke-linux.sh` then runs the jar in real JVMs. Only Docker is required.

## Adding a binding

1. Add the `native` declaration to `Monocypher.java`.
2. Regenerate `src/main/c/net_lastninja_monocypher_Monocypher.h` with `javac -h`.
3. Implement it in the matching `src/main/c/<group>.c`.
4. Add a test to `<Group>Test.java`.

## Rules

- A human reviews all crypto code. For each group, show classes and structs first, then signatures for approval, then the implementation.
- Check every function against the Monocypher manual.
- Wipe every copy of a secret on all exit paths, including exceptions.
- Keep moves and behaviour changes in separate commits.
