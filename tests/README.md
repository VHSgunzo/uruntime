# Runtime filesystem test sources

The repository does not store generated SquashFS or DwarFS images. The Rust
fixture generator creates both filesystems from source whenever lifecycle or
reproducibility checks need them. Each image contains two regular files:

```text
AppRun       mode=0755  uid=0  gid=0  mtime=0
payload.txt  mode=0644  uid=0  gid=0  mtime=0
```

The payload is:

```text
retained inode payload
```

`AppRun` is compiled from [`fixtures/apprun.rs`](fixtures/apprun.rs) as a
stripped static PIE for the selected musl target. Its default diagnostic mode
emits the stable `fixture=uruntime-apprun-v1` marker, arguments, PID/PPID,
UID/GID, cwd, AppImage variables, and user/mount namespace identities. Missing
procfs is reported as `namespace.*=unavailable` rather than treated as an
application failure.

The same Rust executable also provides bounded lifecycle scenarios:

- `hold` publishes a ready marker, waits for an external release marker, and verifies that `payload.txt` remains accessible;
- `daemon` performs `fork`, `setsid`, a second `fork`, closes descriptors `3..1023`, then executes the same barrier and payload checks.

[`fixtures/deny_subreaper.rs`](fixtures/deny_subreaper.rs) is a static Rust seccomp launcher. It denies only `PR_SET_CHILD_SUBREAPER`, allowing the end-to-end harness to exercise old-kernel/seccomp fallback and fail-safe retention without weakening the rest of the sandbox.

[`build_support_tests.rs`](build_support_tests.rs) is the Cargo integration-test target for the shared repository-root [`build_support.rs`](../build_support.rs). The test file imports that module directly; it is not a duplicate build-support implementation.

## Generating images

Build the full AppImage runtime, then use the Rust fixture generator. Generated
images default to the ignored `target/fixtures/` directory; `--output` can place
them elsewhere for manual inspection.

```sh
cargo build --release --locked --target x86_64-unknown-linux-musl \
  --no-default-features --features appimage,squashfs,dwarfs

cargo --locked xtask fixtures \
  --runtime target/x86_64-unknown-linux-musl/release/uruntime \
  --target x86_64-unknown-linux-musl
```

The generator in `xtask/src/lifecycle.rs`:

- creates the source tree from scratch;
- compiles the Rust `AppRun` with the selected toolchain and musl target;
- fixes contents, modes, stored ownership, timestamps, ordering, compression settings, and worker counts;
- invokes the project-pinned embedded `mksquashfs`, `unsquashfs`, `mkdwarfs`, and `dwarfsck` helpers through uruntime rather than host filesystem utilities;
- validates SquashFS payload extraction and DwarFS block integrity;
- appends each filesystem to the selected runtime and performs a real bounded diagnostic launch.

The generated images use the helper versions pinned in `build_support.rs`.
After changing `AppRun`, helper versions, or generation policy, require two
independent byte-identical generations:

```sh
cargo --locked xtask fixtures \
  --runtime target/x86_64-unknown-linux-musl/release/uruntime \
  --target x86_64-unknown-linux-musl \
  --check
```

## End-to-end lifecycle harness

Run every native lifecycle scenario explicitly with:

```sh
cargo --locked xtask lifecycle \
  --runtime target/x86_64-unknown-linux-musl/release/uruntime \
  --target x86_64-unknown-linux-musl \
  --fuse=required
```

The harness runs both SquashFS and DwarFS through:

1. overlapping no-proc extraction users with explicit unshare;
2. an FD-closing double-fork daemon in the same no-proc sandbox;
3. live seccomp denial of child-subreaper setup and fail-safe target retention;
4. overlapping current-namespace reusable FUSE mounts.

`--fuse=required` fails when `/dev/fuse` or `fusermount` is unavailable. `--fuse=auto` reports an explicit `NOT RUN` result for that lane instead of silently treating it as passed. Native `cargo xtask check` uses `auto`; all extraction, daemon, seccomp, and cleanup scenarios remain mandatory.
