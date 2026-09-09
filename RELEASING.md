# Updating and releasing uruntime

This document covers a normal version release, updates to Rust dependencies, filesystem helpers, and Zig, pre-release validation through the `action` branch, and safe reissuing from the same tag.

## 1. Prepare a working branch

Start from an up-to-date `main` and create a separate branch:

```sh
git switch main
git pull --ff-only
git switch -c release/v0.7.1
```

Before making changes, confirm that the working tree contains no accidental files:

```sh
git status --short
git diff --check
```

Build directories, local helper caches, CI staging, editor settings, and Python caches are excluded through `.gitignore`. Both lockfiles, `Cargo.lock` and `xtask/Cargo.lock`, must be tracked by Git.

## 2. Make the changes

### uruntime code only

Change the code and update the version in the root `Cargo.toml`:

```toml
[package]
version = "0.7.1"
```

`src/main.rs` gets the version from `CARGO_PKG_VERSION`; there is no separate constant to update.

### Rust dependencies

Change the constraints or pinned `rev` values in the relevant `Cargo.toml`, then update the corresponding lockfile:

```sh
# Root package
cargo update

# Separate xtask package, if its dependencies changed
cargo update --manifest-path xtask/Cargo.toml

git diff -- Cargo.toml Cargo.lock xtask/Cargo.toml xtask/Cargo.lock
```

Do not edit lockfiles manually. Normal builds and CI use `--locked`, so an unrecorded dependency graph change will be caught before the release matrix runs.

### SquashFS or DwarFS helpers

First release and verify the new assets in the corresponding upstream/helper repository. Change the relevant version in `uruntime/build_support.rs`:

```rust
pub const DWARFS_VERSION: &str = "...";
pub const SQUASHFS_TOOLS_VERSION: &str = "...";
pub const SQUASHFUSE_VERSION: &str = "...";
```

Then regenerate the manifest:

```sh
cargo xtask update-checksums
git diff -- checksums.txt
```

The command validates all 30 helper sources, reusing only local release files whose SHA-256 matches the current manifest. Missing or mismatched files are downloaded atomically into dependency-specific architecture/version caches that are also consumed by `build.rs`. It validates helper boundaries and ELF types, extracts DwarFS payloads, and records the SHA-256 of both each source file and its final payload. Review the `checksums.txt` diff before committing.

### Zig

Change `ZIG_VERSION` in `build_support.rs`, then run:

```sh
cargo xtask update-checksums
git diff -- checksums.txt
```

`xtask` reads the official `https://ziglang.org/download/index.json` and updates the URLs and SHA-256 values of the archives for supported Linux hosts. The index, current-host archive, and extracted installation are cached under `target/toolchains/`; archives and installations are keyed by version, host, and full SHA-256. Checksum validation and real builds reuse the same verified archive.

## 3. Run local checks

Update `RELEASE_NOTES.md` with the public notes for the version being prepared. The release workflow uses this file verbatim when creating or refreshing the GitHub release, so same-tag reruns do not replace the intended notes with an automation placeholder.

Run the full check suite before pushing:

```sh
cargo xtask check
```

By default, `xtask` selects the musl target for the current Linux platform. On `x86_64`, this is `x86_64-unknown-linux-musl`. You can specify the target explicitly:

```sh
cargo xtask check x86_64-unknown-linux-musl
```

An explicitly selected foreign target uses the pinned Zig linker backend and requires the matching QEMU user-mode executable (for example, `qemu-aarch64` or `qemu-aarch64-static`) in `PATH` to run the root tests.

The command runs `cargo fmt --check`, root Check/Clippy/tests with `--locked`, separate Check/Clippy/tests for `xtask`, `cargo xtask update-checksums --check`, and `git diff --check` in sequence. It stops at the first failure. The checksum step validates all pinned helper sources and Zig metadata. It uses the network only for missing, mismatched, or stale cache entries; a fully populated verified cache works offline.

If cross-linking changed, also build one foreign runtime:

```sh
cargo xtask runimage-aarch64
qemu-aarch64 dist/uruntime-runimage-aarch64 --runtime-version
```

QEMU is needed only for the smoke test of the finished foreign ELF. It does not participate in the build.

## 4. Commit every reproducible input

Confirm that Git sees the source files, CI scripts, manifests, and both lockfiles, but not build/cache directories:

```sh
git status --short --untracked-files=all
git check-ignore -v dist target xtask/target assets-x86_64 || true
if git check-ignore -q Cargo.lock || git check-ignore -q xtask/Cargo.lock; then
  echo 'Cargo.lock is still ignored' >&2
  exit 1
fi
```

After checking, create the commit. For example:

```sh
git add -A
git diff --cached --check
git commit -m "Release v0.7.1"
```

Do not use `git add -f` for files under `dist/`, `target/`, `assets-*`, or `release-dist/`.

## 5. Validate the full matrix without releasing

The workflow runs when you push to the `action` branch:

```sh
git push origin HEAD:action
```

This run performs preflight, builds all six architectures, verifies nine files per architecture, and runs foreign runtimes through QEMU. It does not create a GitHub Release for the `action` branch.

Monitor the run through the GitHub UI or `gh`:

```sh
gh run list --branch action --limit 5
gh run watch <RUN_ID>
```

After the matrix passes, transfer the exact verified commit to `main` using the project's chosen method, then push it:

```sh
git switch main
git pull --ff-only
# Merge/cherry-pick the verified commit
git push origin main
```

## 6. Create a new release

Confirm that `HEAD` contains the intended version and the code that passed CI:

```sh
git status --short
git log -1 --oneline
grep '^version = ' Cargo.toml
```

Create and push an annotated tag:

```sh
git tag -a v0.7.1 -m "uruntime v0.7.1"
git push origin v0.7.1
```

The tag-push workflow rebuilds 54 files from the tagged commit. The release job:

1. verifies that the remote tag points to `github.sha`;
2. creates a new draft or changes the existing release for that tag back to a draft;
3. deletes the old assets from that release;
4. uploads exactly 54 freshly verified runtimes;
5. reads the complete paginated asset manifest by numeric release ID;
6. verifies the remote tag SHA again;
7. publishes the same numeric release ID.

If upload or verification is interrupted, the release remains a draft and does not publicly expose a mixture of old and new assets.

## 7. Reissue from the same tag

### The tag and commit have not changed

Click **Re-run all jobs** on the original tag-push workflow, or run:

```sh
gh run rerun <RUN_ID>
```

CI rebuilds the tagged commit and safely replaces the release assets through the draft stage.

### The tag has moved to another commit

Move the local annotated tag and push the tag update itself:

```sh
git tag -fa v0.7.1 -m "uruntime v0.7.1" <NEW_COMMIT>
git push --force origin refs/tags/v0.7.1
```

The force-push creates a new tag-push workflow with a new `github.sha`. Do not rerun the old workflow for the previous commit: its SHA check must fail after the tag moves.

Moving a published tag breaks users', package managers', and caches' expectation that releases are immutable. Do this only for a deliberate release correction. For a normal fix, prefer a new version number such as `v0.7.2`.

## 8. Verify the published release

```sh
release_id=$(gh api repos/VHSgunzo/uruntime/releases/tags/v0.7.1 --jq .id)

gh api --paginate --slurp \
  "repos/VHSgunzo/uruntime/releases/$release_id/assets?per_page=100" \
  --jq 'add | length'

gh release view v0.7.1
```

The expected asset count is `54`. CI performs the same check automatically and publishes the release only after the complete manifest matches.
