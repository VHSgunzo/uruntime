# Changelog

All notable changes to uruntime are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.8.1] - 2026-09-24

This patch release hardens startup and reusable-mount behavior in minimal Linux roots, compatibility environments, and older-kernel procfs layouts without weakening normal Linux namespace authentication.

### Changed

- Reusable current-namespace FUSE mounts may be accepted without a PID record only for automatic hash-derived targets with implicit identity mapping when `/proc/self/ns/{user,mnt}` identities are unavailable, as on Linuxulator, some older kernels, or partial procfs implementations. Normal Linux systems with namespace identities continue to require the strict trusted-record path.
- Process-capable procfs detection now requires `/proc/self/stat` to be a readable, nonempty regular file. Namespace-identity availability is probed separately instead of being inferred from process-stat access.
- Current-namespace mounts that cannot publish verifiable namespace identities no longer create a PID record. A `.pid.lock` sidecar is opened only when a PID-record candidate actually exists.
- Stable zero-length lock inodes remain adjacent to reusable targets after cleanup so concurrent launches cannot split across different lock identities. Systems without OFD locks continue to use the separate `.lease` and `.lease.lock` files of the conservative `flock` backend.
- Foreign QEMU execution gates are temporarily disabled in CI because of their runtime cost. All six architectures are still built, and every artifact still receives manifest and ELF metadata validation; the native full quality and lifecycle gate remains enabled.

### Fixed

- Preserved an explicitly configured AppImage or RunImage target directory across the internal no-FUSE re-execution used for extraction fallback. The target variable is still removed before launching the application payload.
- Avoided calling `create_dir_all` for an existing target-lock parent. This fixes lifetime-lease startup in restricted roots where an existing writable `/tmp` can be used but attempting to recreate or modify the parent is denied.
- Allowed missing target-lock parents to be created when necessary while rejecting an existing non-directory parent with a precise error.
- Kept file descriptors `0`, `1`, and `2` occupied when detaching the cleanup supervisor without `/dev/null`. A low-numbered fallback descriptor is duplicated and dropped before `dup2`, preventing its destructor from closing a newly installed standard descriptor.
- Prevented Linuxulator and similarly partial procfs environments from warning about an unwritable PID record or remounting an already visible automatic FUSE target on the next launch.
- Prevented an absent PID record from leaving an unnecessary `.pid.lock` file during reuse probing.

### Validation

- Added regression coverage for existing and missing target-lock parents, low-numbered descriptor ownership without `/dev/null`, no-FUSE fixed-target fallback, readable procfs probing, partial-procfs direct reuse, and PID-record sidecar creation.
- Extended the real SquashFS and DwarFS lifecycle harness to verify fixed-target extraction fallback, operation without `/dev`, and UID-map-only current-namespace mounting.
- Verified consecutive DwarFS AppImage launches and reusable-mount reuse on Gentoo under FreeBSD 14.1 Linuxulator.

## [0.8.0] - 2026-09-24

This is a major runtime-safety and compatibility update. It changes how uruntime retains its executable and image, authenticates reusable mounts, enters namespaces, operates without procfs, and cleans up failed or expired mounts.

### Added

- Retained-descriptor execution for the runtime and appended filesystem image. The runtime, mount helpers, and extraction helpers continue using the originally opened inode even if the source pathname is renamed, removed, or replaced.
- `execveat(AT_EMPTY_PATH)` self-reexecution with a compatibility chain through verified `/proc/self/fd` or `/dev/fd` descriptor paths and, as a final fallback, a pathname whose `dev` and `ino` still match the retained executable.
- The runtime executable path can be recovered from `AT_EXECFN` when procfs-backed `current_exe` resolution is unavailable.
- Explicit namespace-state tracking for the current namespace, a mount-only namespace, and a combined user-and-mount namespace.
- Versioned trusted mount records containing the helper PID, namespace kind, effective UID/GID mapping, process start time, and concrete user/mount namespace `dev` and `ino` identities.
- Race-resistant private-mount reuse through `pidfd_open`, retained namespace file descriptors, pre-transition identity validation, and typed namespace-entry outcomes.
- Safe fresh-target allocation when a reusable automatic target cannot be authenticated because `pidfd_open` or a pre-transition `setns` operation is unavailable or denied. Fresh paths are atomically reserved as private mode-`0700` directories, verified empty before publication, and removed after failed lease acquisition when still empty; rollback failures are reported without recursively deleting untrusted entries.
- Procfs-free direct reuse for an automatic hash-derived FUSE mount already visible in the current namespace. This path requires implicit mapping and the absence of both direct and private PID records, and never calls `setns`.
- A cross-launch lifetime protocol for reusable extraction and FUSE targets. Every participating launch holds a shared target lease, while cleanup requires the coordinator plus an exclusive lease before removing or unmounting the target. Descendants that retain the inherited lease descriptor continue holding it after the launcher exits. On OFD-capable kernels, coordinator, lifetime, and record-publication locks occupy three byte ranges of one protected adjacent inode, which remains as the stable lock identity after target cleanup.
- Extract-and-run application supervision through `PR_SET_CHILD_SUBREAPER` so no-proc extracted-target cleanup can wait for daemonized and double-forked descendants even when they close every inherited file descriptor. FUSE cleanup does not depend on child-subreaper supervision.
- `MNT_EXPIRE` state handling for delayed reusable-mount cleanup, including renewed-access detection and safe retention on busy or hard-failure outcomes.
- Deterministic executable SquashFS and DwarFS fixtures containing a scenario-driven static Rust `AppRun` for diagnostics, overlapping-use barriers, and FD-closing double-fork daemon tests.
- A release-derived local test matrix covering all nine distinct runtime feature combinations, plus the all-features interaction gate.
- A canonical AArch64 quality-gate lane under QEMU in CI.
- A universal `--uruntime-*` CLI prefix accepted by both AppImage and RunImage formats while retaining their existing format-specific prefixes.
- A comprehensive application lifecycle reference with Mermaid diagrams covering entry dispatch, target selection, namespace/FUSE/extraction fallbacks, authenticated reuse, process supervision, exit-status propagation, and every cleanup outcome.
- An all-Rust test and release toolchain: fixture generation, native lifecycle orchestration, bounded ELF/release validation, GitHub Actions contract tests, release JSON helpers, and the Zig linker wrapper now live in `xtask` or Rust fixture sources instead of Python, C, or shell scripts.
- Dedicated build, testing, release, and lifecycle documentation under `docs/`.

### Changed

- Bumped the project version from `0.7.1` to `0.8.0` to reflect the new mount-reuse, namespace, lifecycle, and execution guarantees.
- Explicit UID/GID or root mapping intent is now distinct from implicit current-ID operation and is included in reusable-target identity.
- An explicitly requested mapping must be applied in a verified user-and-mount namespace. uruntime now exits instead of silently launching without the requested isolation.
- Reusable mount hashes include explicit requested UID/GID mappings while preserving the previous key for implicit mapping.
- Private namespace reuse now requires exact mapping, process-generation, namespace-kind, and namespace-identity matches before any irreversible transition.
- Legacy PID-only and identity-less mount records remain parseable for compatibility but are no longer trusted for namespace reuse.
- Rejected reusable state can no longer be accepted later by generic mounted/nonempty-target handling.
- Automatic targets use a separate fresh mount when pre-transition identity operations are unavailable. Fixed targets fail closed because silently selecting a different path would violate the caller's request.
- Without procfs, an automatic FUSE mount already visible in the current namespace may be reused directly without publishing an unverifiable PID record.
- Without procfs, persistent reuse is disabled before target generation whenever a private namespace is requested or required. Such launches use random non-reusable mount paths instead of colliding on a stable hash target.
- Extracted-directory reuse remains hash-based and does not require procfs because no live helper or namespace transition must be authenticated. Concurrent launches now share one target lifetime lease, preventing the first launch from deleting the directory while another launch is still using it. After a successful extracted launch, destructive cleanup still requires complete descendant visibility: procfs or child-subreaper supervision. Without both, uruntime warns and retains the extracted target. Failed application spawn remains immediately cleanable because no application tree was created.
- Procfs availability is now detected through functional access to `/proc/self/stat`, rather than directory existence alone.
- Process liveness checks use `kill(pid, 0)`, which remains usable when procfs is absent.
- No-proc normal execution may mount in the current namespace when no mapping is requested and the process already has `CAP_SYS_ADMIN`; the mount namespace is made private first.
- No-proc mount-only execution keeps a private mount namespace and reports `/proc/<pid>/root/...` for consumption by an outer namespace that provides procfs.
- Target-directory inspection now distinguishes empty, nonempty, and unsafe states. Read errors and dangling entries no longer masquerade as an absent target.
- Broken FUSE mounts identified by `ENOTCONN`, `ESTALE`, or `EIO` are handled separately from healthy reusable mounts.
- Reusable-mount PID records are published atomically under a persistent lock using a same-directory `0600` temporary file, `sync_all`, and `rename`.
- Record and lifetime locks reject symlink substitution with `O_NOFOLLOW`, require a regular current-owner file with no group/other permissions, and verify the locked inode against its pathname. The normal OFD-lock path reuses the opened inode and captured identity across coordinator, lifetime, and publication ranges, reducing startup file operations; bounded orphan-temporary scavenging repairs state left by immediate aborts.
- Fresh automatic mount names no longer use an extra extension before their random suffix, preventing `.pid`/`.un.pid` sidecar collisions caused by `Path::with_extension`.
- Failed application launches run cleanup synchronously and immediately instead of waiting for the normal reuse delay.
- Capability dropping is applied only after a namespace has been created or re-entered successfully and only to the launched application; filesystem helpers retain the privileges required for mounting.
- Inline failed-launch cleanup preserves the application's original failure status; only detached normal cleanup exits independently.
- Runtime option parsing consumes `--` before launching the application while preserving all following application arguments.
- The opened executable size is cached, redundant descriptor clones and metadata operations were removed from startup paths, and per-target locking now avoids separate coordinator, lease, and record-lock opens on OFD-capable systems. Hot reuse also defers unnecessary target-directory reads, skips irrelevant PID-record metadata checks, reuses the post-transition procfs probe, and canonicalizes mounted paths once.
- Root Check, Clippy, and tests consistently use the project-provided Zig linker setup; foreign test binaries run under the matching QEMU user-mode runner.
- Canonical `cargo xtask check` explicitly runs the two network-backed upstream helper integration tests once after the normal matrix passes, reusing verified caches and downloading only missing or invalid assets instead of skipping those checks or repeating them for every feature set.
- Test contracts now target current behavior, security properties, compatibility fallbacks, and reproducible outputs; historical filename/language blacklists, README/build-source wording checks, tautological constant checks, and duplicate table assertions were removed.
- AArch64 foreign debug Check/Test commands apply target-specific `CFLAGS_aarch64_unknown_linux_musl=-O1` to avoid a reproducible vendored Zstd `-O0` abort under QEMU. Release builds and other targets are unaffected.
- Rust transitive dependencies were refreshed; direct runtime dependency declarations are unchanged.

### Fixed

- Prevented self-reexecution and helper startup from resolving a replacement file at the original pathname.
- Rejected missing, unreadable, or inode-mismatched pathname fallbacks instead of potentially executing unrelated content.
- Prevented PID reuse from authenticating a stale mount record by checking `/proc/<pid>/stat` process start time.
- Prevented namespace-owner substitution by comparing the recorded and opened user/mount namespace identities.
- Prevented explicit same-ID mapping requests from degrading into implicit unmapped execution.
- Prevented a rejected `.un.pid` record from being resurrected by a later generic mount check.
- Prevented fresh fallback after a successful namespace transition, where the caller may already have irreversibly changed namespaces.
- Treated mount-namespace privatization failure after entry as an irreversible error rather than successful isolation.
- Treated a missing expected mount after namespace entry as rejection rather than a recoverable pre-transition failure.
- Prevented unmounted-but-nonempty persistent targets from being accepted as authenticated reusable mounts.
- Correctly restarts the expiration delay when a second `MNT_EXPIRE` call returns `EAGAIN`, indicating renewed mount access.
- Retains busy or failed mounts instead of falling through to an unsafe ordinary unmount; ordinary unmount fallback is limited to unsupported expiration semantics.
- Prevented failed `AppRun` startup from leaving PID records, temporary extraction directories, mount helpers, or delayed cleanup behind.
- Prevented the first reusable extraction launch from deleting a shared directory while a later launch still uses it. Descendants retaining the inherited lease descriptor continue blocking cleanup; daemonized descendants that close it are covered by procfs or child-subreaper supervision, otherwise the extracted target is retained.
- Prevented reusable FUSE cleanup from becoming ownerless after an early launcher exits; the cleanup actor now waits for every shared lease and keeps `MNT_EXPIRE` as a second kernel-level guard.
- Preserved file-descriptor counts and `FD_CLOEXEC` state across repeated failed descriptor/pathname execution fallbacks.
- Removed production error paths that relied on panic-reporting constructs under `panic=immediate-abort`; fallible operations now use explicit results, checked arithmetic, or intentional wrapping hash arithmetic. Crate-level Clippy denials enforce `unwrap`, `expect`, `panic`, `todo`, `unimplemented`, and `unreachable` without source-text scanning.
- Added bounded test subprocess waits, kill/reap handling, and RAII FUSE cleanup to prevent test hangs and stranded helpers.

### Security

- Mount reuse no longer treats a hash-derived pathname or a live PID as sufficient proof of namespace ownership.
- Every path that can accept persistent reusable state validates the relevant mapping, process generation, namespace kind, and namespace identity before reuse.
- PID-record parsing rejects duplicate or malformed known fields instead of allowing a later field to repair an earlier invalid value.
- PID-record publication and maintenance avoid following symlinks and serialize validation, stale removal, cleanup, and replacement under one lock discipline.
- Reusable target preparation and cleanup are serialized by the coordinator range of a private adjacent lock inode; cleanup cannot race a new shared user between its final lifetime check and destructive removal. Coordinator, record, and cleanup ranges are explicitly unlocked when their guards end, while shared lifetime ownership is released only by closing the final inherited descriptor. Descendants block through that lease only while they retain the descriptor; procfs or child-subreaper supervision covers extracted descendants that close it.
- Namespace transitions fail closed after irreversible operations; fallback is permitted only while the caller is still in its original namespace.

### Compatibility

- `execveat` compatibility fallback now includes `EPERM` in addition to `ENOSYS`, `ENOTSUP`, and compatible `EINVAL`, while retaining exact inode verification.
- Normal no-proc execution is supported without weakening private namespace authentication. FUSE cleanup remains guarded by shared leases, lifetime descriptors, and mount-level expiry/unmount checks. Extracted-target cleanup has the stricter descendant-visibility rule described below.
- On kernels or seccomp profiles where `PR_SET_CHILD_SUBREAPER` is unavailable, procfs remains the extracted-application descendant-visibility fallback. If neither mechanism is available after a successful extracted launch, uruntime retains that extracted target instead of risking cleanup beneath an unobservable daemon. Failed application spawn still receives immediate inline cleanup.
- Old kernels and seccomp profiles that block `pidfd_open` or pre-transition `setns` can use a safe fresh automatic mount; fixed targets remain fail-closed.
- Kernels before Linux 3.15 and filesystems without OFD-lock support retain the same lifecycle semantics through the separate-file `flock` backend. OFD permission denials fail closed so sandbox policy cannot split concurrent processes across independent OFD and `flock` lock domains.
- Existing legacy mount records can still be parsed, but a new trusted record is required before namespace reuse.

### Validation

- Added real descriptor-retention tests that replace the runtime/image pathname before reexecution, mounting, and extraction.
- Added isolated tests for descriptor fallback, pathname identity rejection, FD lifetime, `FD_CLOEXEC`, and leak resistance.
- Added regression coverage for mapping identity, process generation, namespace identity, stale and malformed records, atomic publication, symlink attacks, orphan temporary cleanup, and fresh-target sidecar isolation.
- Added no-proc tests for current-namespace direct reuse, private random-target fallback, cross-launch lifetime leases, child-subreaper supervision, failed launch cleanup, and mount-only export behavior.
- Added canonical end-to-end validation of overlapping extraction and current-namespace FUSE reuse with both SquashFS and DwarFS, plus a double-fork payload that closes inherited descriptors before accessing its image and exiting.
- Added live seccomp denial of `PR_SET_CHILD_SUBREAPER` inside a no-proc explicit-unshare sandbox and required fail-safe target retention with the expected warning.
- Generated SquashFS and DwarFS fixtures exclusively with the project-pinned embedded helpers and verified byte-for-byte reproducibility and real bounded application launches.
- Validated all nine x86_64 and all nine AArch64 release variants, including QEMU execution for AArch64 artifacts.

[Unreleased]: https://github.com/VHSgunzo/uruntime/compare/v0.8.1...HEAD
[0.8.1]: https://github.com/VHSgunzo/uruntime/compare/v0.8.0...v0.8.1
[0.8.0]: https://github.com/VHSgunzo/uruntime/compare/v0.7.1...v0.8.0
