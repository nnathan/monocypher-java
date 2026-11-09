# monocypher-java

JNI bindings for Monocypher: as C-like as possible, with Java safety where it helps, so anyone familiar with Monocypher can easily use this library. Java 8+, no runtime dependencies. `~/code/mini-monocypher` is the sibling Rust binding and uses the same module groups.

## Layout

- `src/main/java/net/lastninja/monocypher/Monocypher.java`: the whole public API, deliberately one class
- `src/main/c/<group>.c`: JNI code per group; shared macros are in `jni_util.h`
- `src/test/java/<Group>Test.java`: tests per group; helpers are in `net/lastninja/monocypher/TestUtil.java`
- `vendor/monocypher`: upstream, as a submodule (clone with `--recurse-submodules`)
- `third_party/jni`: unmodified Java 8 JNI headers

## Build and test

`scripts/docker-build.sh` builds every native target, runs the JUnit suite with `-Xcheck:jni`, and produces `build/monocypher-java.jar` and `build/monocypher-android.aar`. `scripts/smoke-linux.sh` then runs the jar in real JVMs, and `scripts/test-sanitizers.sh` runs the suite under ASan and UBSan. CI also runs `clang-tidy`, configured in `.clang-tidy`, and fails on any warning. Only Docker is required.

## Adding a binding

1. Add a `public static native` declaration to `Monocypher.java`, or to `Hazmat.java` for dangerous low-level building blocks.
2. Regenerate the headers in `src/main/c/` with `javac -h src/main/c`.
3. Implement it in the matching `src/main/c/<group>.c`, validating every argument with the `mc_` helpers in `jni_util.h` and returning as soon as one fails.
4. Add tests to `<Group>Test.java`, including the rejected cases.

## API conventions

- Names and argument order follow C; behaviour follows what a Java developer expects.
- Every byte argument is a direct `ByteBuffer`, used from `position` to `limit`. Calls do not move `position` (not settled; outputs are exact sizes so this can be loosened later).
- Optional C pointers accept `null`; outputs must be writable; arguments Monocypher wipes, such as seeds, count as outputs.
- Overlap rules come from the manual and upstream tests: exact alias or disjoint (`mc_check_overlap`), never overlapping (`mc_check_disjoint`), or no check where the manual allows any overlap. Comment which applies.
- Contexts extend `Ctx`: off-heap memory C uses in place, with a state byte so use before init or after final/wipe throws `IllegalStateException`. They implement `AutoCloseable`.
- Integer ranges narrower than the Java type are checked, never truncated.

## Rules

- A human reviews all crypto code. For each group, show classes and structs first, then signatures for approval, then the implementation.
- Check every function against the Monocypher manual.
- Wipe every copy of a secret on all exit paths, including exceptions.
- Keep moves and behaviour changes in separate commits.
