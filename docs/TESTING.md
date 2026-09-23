# Testing uruntime

The canonical gate is implemented entirely in Rust and is invoked with:

```sh
cargo --locked xtask check
```

See [BUILDING.md](BUILDING.md) for toolchain setup, [APPLICATION_LIFECYCLE.md](APPLICATION_LIFECYCLE.md) for runtime state machines, and [`../tests/README.md`](../tests/README.md) for fixture details.

## Canonical gate

For the native musl target, `cargo xtask check` runs:

1. formatting;
2. root Check and Clippy with `-D warnings`;
3. root tests with all features;
4. both network-backed helper download/cache/ELF tests once;
5. every distinct release feature combination;
6. Check, Clippy, and all tests for `xtask`;
7. a release AppImage runtime build;
8. the repository-owned end-to-end lifecycle harness;
9. checksum-manifest validation;
10. `git diff --check`.

A foreign target also runs its Rust tests under QEMU, but reports the native namespace/FUSE lifecycle harness as `NOT RUN` because QEMU user mode cannot substitute for real target-architecture namespaces and mounts.

## Rust test components

All repository test and CI orchestration is Rust:

- `src/runtime_elf_tests.rs` covers runtime policy and low-level mechanism regressions;
- `tests/build_support_tests.rs` integration-tests the single shared implementation in the repository-root `build_support.rs`;
- `xtask/src/tests.rs` covers the release matrix, linker, checksum cache, and artifact publication;
- `xtask/src/artifacts.rs` contains the ELF/release validator and its adversarial tests;
- `xtask/src/workflow_contract.rs` parses and validates the GitHub Actions workflow;
- `xtask/src/lifecycle.rs` generates filesystem fixtures and executes live lifecycle scenarios;
- `tests/fixtures/*.rs` are executable test payloads and helpers.

There are no Python test runners, Python CI validators, shell fixture generators, shell linker wrappers, or C fixture launchers. Shell snippets may still appear inside tests as controlled input to process-launch behavior, but no repository orchestration is implemented in shell.

## Test design policy

Every test must protect a current observable contract, security property,
compatibility fallback, or reproducible build/release result. Expected values
for public matrices, commands, manifests, and CLI help come from independent
contracts rather than the production tables being tested. Tests must not merely
assert that a removed filename, language, tool, or historical implementation
has not returned.

Source/configuration inspection is reserved for active properties that cannot be exercised as ordinary function output, such as immutable GitHub Action pins, lockfile use in workflow commands, safe transport of GitHub expressions, and documentation link integrity. Panic-prone constructs in production Rust are enforced by crate-level Clippy denials for `unwrap`, `expect`, `panic`, `todo`, `unimplemented`, and `unreachable`; test modules explicitly allow them where assertion-oriented code needs them.

Where a real operation is available, tests execute it: artifact publication uses actual temporary files and ELF tools, helper-cache tests exercise atomic publication and concurrency, lifecycle tests launch appended filesystems, and release validators consume complete synthetic manifests rather than checking implementation text.

## Lifecycle scenarios

The native harness builds real appended SquashFS and DwarFS AppImages from the checked-in scenario-driven `AppRun`. For both filesystems it verifies:

- overlapping no-proc extraction reuse with explicit unshare;
- lease protection while one overlapping user exits;
- final target removal after the last user exits;
- double-fork + `setsid()` daemonization;
- closure of descriptors `3..1023` by the daemon;
- subreaper adoption and eventual cleanup;
- live seccomp denial of `PR_SET_CHILD_SUBREAPER`;
- fail-safe target retention when neither procfs nor subreaper visibility exists;
- overlapping current-namespace FUSE reuse when FUSE is available.

Run it directly and require FUSE:

```sh
cargo --locked xtask lifecycle \
  --runtime target/x86_64-unknown-linux-musl/release/uruntime \
  --target x86_64-unknown-linux-musl \
  --fuse=required
```

Modes:

- `--fuse=required`: unavailable FUSE is a test failure;
- `--fuse=auto`: unavailable FUSE is reported explicitly as `NOT RUN`; all non-FUSE lanes remain mandatory;
- `--fuse=skip`: explicit operator-requested omission.

## Fixture reproducibility

Generate inspectable images or validate reproducibility with Rust `xtask`
commands. Generated files default to the ignored `target/fixtures/` directory:

```sh
cargo --locked xtask fixtures \
  --runtime target/x86_64-unknown-linux-musl/release/uruntime \
  --target x86_64-unknown-linux-musl

cargo --locked xtask fixtures \
  --runtime target/x86_64-unknown-linux-musl/release/uruntime \
  --target x86_64-unknown-linux-musl \
  --check
```

The check creates each filesystem twice in independent temporary directories
and requires byte-for-byte equality. Each generation also validates the
filesystem payload and performs a real launch after appending the image to the
selected runtime. No generated filesystem image is stored in Git.

## Artifact and release contracts

```sh
# Validate one architecture and smoke-test private copies
cargo --locked xtask artifacts validate-arch x86_64 dist --smoke

# Validate six downloaded architecture directories and stage exactly 54 files
cargo --locked xtask artifacts aggregate-release artifacts release-dist

# Validate the published asset readback
cargo --locked xtask artifacts validate-release release-assets.json
```

The validator rejects symlinks, non-regular files, stale entries, oversized inputs, malformed bounded ELF metadata, dynamic interpreters/dependencies, wrong machine/endian/magic, missing runtime sections, duplicates, and incomplete release manifests.

## Required native tools

The full native gate requires `bwrap`. The FUSE lane additionally requires readable/writable `/dev/fuse` and `fusermount3` or `fusermount`. CI installs Bubblewrap and FUSE tooling; whether the hosted runner exposes `/dev/fuse` is reported explicitly by the harness.

## GitHub Actions integration

`.github/workflows/ci.yml` has no dependency on repository-owned Python, shell, or C files:

1. **Preflight** installs Bubblewrap, FUSE, musl, LLVM, QEMU, and both required Rust targets. It runs the canonical native Rust gate and the foreign AArch64 gate under QEMU.
2. **Build** invokes `cargo --locked xtask <architecture>` for all six architectures. `xtask/src/artifacts.rs` then validates each exact nine-file manifest and runs native or QEMU smoke tests before upload.
3. **Release** downloads the six architecture artifacts and uses only Rust `xtask artifacts` subcommands for aggregation, paginated GitHub JSON handling, asset-ID extraction, and final 54-file manifest validation.

The multiline `run:` blocks that remain in the workflow are GitHub Actions command steps for package installation, GitHub API calls, and guarded publication. They do not reference a repository `scripts/` directory or reimplement the Rust validators.

Workflow contract tests in `xtask/src/workflow_contract.rs` parse the YAML and require the canonical gates, exact six-architecture matrix, Rust artifact/release commands, immutable action pins, lockfile use, and safe GitHub-expression transport. They validate current executable workflow behavior; they do not blacklist names or extensions from removed implementations.
