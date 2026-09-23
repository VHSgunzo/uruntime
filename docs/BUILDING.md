# Building uruntime

This document describes the project build matrix and the reproducible Rust/Zig toolchain path. See [TESTING.md](TESTING.md) for validation commands and [RELEASING.md](RELEASING.md) for the release procedure.

## Supported targets

The release matrix contains six static musl targets:

| Artifact architecture | Rust target | Zig target |
|---|---|---|
| `x86_64` | `x86_64-unknown-linux-musl` | `x86_64-linux-musl` |
| `aarch64` | `aarch64-unknown-linux-musl` | `aarch64-linux-musl` |
| `riscv64` | `riscv64gc-unknown-linux-musl` | `riscv64-linux-musl` |
| `loongarch64` | `loongarch64-unknown-linux-musl` | `loongarch64-linux-musl` |
| `ppc64` | `powerpc64-unknown-linux-musl` | `powerpc64-linux-musl` |
| `ppc64le` | `powerpc64le-unknown-linux-musl` | `powerpc64le-linux-musl` |

Each architecture has nine AppImage/RunImage and filesystem combinations, producing 54 release artifacts.

## Prerequisites

A normal build requires:

- the pinned Rust nightly from `rust-toolchain.toml`;
- `rust-src` for `build-std`;
- LLVM tools used to publish runtime sections;
- `curl`, `xz`, and standard archive utilities for verified helper and Zig downloads.

Install the Rust components and target you need, for example:

```sh
rustup component add rust-src rustfmt clippy
rustup target add x86_64-unknown-linux-musl aarch64-unknown-linux-musl
```

## Build commands

```sh
# List all targets and tasks
cargo --locked xtask help

# Build nine variants for one architecture
cargo --locked xtask x86_64

# Build one variant
cargo --locked xtask appimage-squashfs-aarch64

# Build all 54 release artifacts
cargo --locked xtask all
```

Finished files are published to `dist/uruntime-<variant>-<architecture>`.

## Rust Zig linker

Cross-linking no longer depends on a shell wrapper. `xtask/src/zig_linker.rs` is compiled by `xtask` into `target/toolchains/uruntime-zig-linker` and used consistently for native and foreign musl targets.

The wrapper:

1. validates the complete Rust-to-Zig target mapping;
2. removes Rust/GNU-only target and CRT arguments that conflict with `zig cc`;
3. drops Rust's LoongArch-only `--no-rosegment` linker option because the pinned Zig frontend rejects it;
4. preserves unrelated linker options verbatim;
5. executes the pinned Zig compiler with the validated target.

`xtask` downloads the pinned Zig archive from metadata validated against `checksums.txt`. The index, archive, and extracted toolchain are cached under `target/toolchains/` and keyed by version, host, and SHA-256.

## Embedded helpers

`build.rs` resolves the helper inventory from the single shared implementation in the repository-root [`build_support.rs`](../build_support.rs) and `checksums.txt`. The same module is imported by `xtask`, while [`tests/build_support_tests.rs`](../tests/build_support_tests.rs) is only its integration-test target; it does not contain a second implementation. Cached files are accepted only after their source and decoded payload hashes and ELF policy match the manifest. Missing or invalid entries are downloaded and published atomically.

DwarFS self-extracting wrappers are decoded on the build host; foreign helper payloads are inspected but never executed. Release artifacts remain static and must contain the required mutable/runtime sections.

## Updating helper and toolchain checksums

`checksums.txt` records the source and extracted-payload SHA-256 values for all filesystem helpers. It also records the URLs and hashes of Zig archives for supported Linux hosts.

```sh
# Recompute all entries and fail if the manifest differs
cargo --locked xtask update-checksums --check

# Rewrite checksums.txt after an intentional version or URL change
cargo --locked xtask update-checksums
git diff -- checksums.txt
```

Both commands validate all 30 helper sources rather than only the current architecture. A source is reused only when its bounded SHA-256 matches the manifest. Missing or invalid files are downloaded atomically into dependency-specific cache trees later consumed by `build.rs`. A fully populated cache allows checksum validation without network access. `URUNTIME_CURL=/path/to/curl` selects the download program.

Always inspect the manifest diff after an update. A version or URL change is incomplete until both source and decoded-payload hashes have been reviewed.

## Artifact validation

Artifact and release validation is implemented in `xtask/src/artifacts.rs` rather than an external Python script:

```sh
cargo --locked xtask artifacts validate-arch x86_64 dist --smoke
```

It requires exactly nine artifacts, validates ELF class/machine/endian, runtime magic, required sections, and absence of dynamic interpreter/dependencies, then smoke-tests private copies. Foreign smoke tests use the matching static QEMU user-mode binary.

## Repository tooling layout

Repository-owned build, test, and release orchestration is Rust-only:

- `build_support.rs` is the shared build/helper implementation used by `build.rs`, `xtask`, and its integration tests;
- `xtask/src/zig_linker.rs` replaces the former shell linker wrapper;
- `xtask/src/artifacts.rs` replaces Python artifact and release validators;
- `xtask/src/lifecycle.rs` replaces shell/Python fixture generation and lifecycle orchestration;
- `xtask/src/workflow_contract.rs` replaces Python workflow contract checks;
- `tests/fixtures/*.rs` contains executable fixture programs, including the seccomp child-subreaper probe formerly represented by a C source.

There is intentionally no `scripts/` directory: all previous repository scripts have Rust owners in `xtask`.
