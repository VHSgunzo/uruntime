## uruntime v0.8.0

uruntime 0.8.0 is a major runtime-safety and compatibility release. It hardens reusable mounts and namespace transitions, keeps execution bound to the originally opened runtime and image, and makes operation without procfs predictable instead of relying on partial identity checks.

### Safer execution and re-execution

The runtime and appended filesystem are now retained as open file descriptors. Re-execution prefers `execveat(AT_EMPTY_PATH)` and falls back through verified descriptor paths or an exact `dev`/`ino`-matched pathname. Renaming, deleting, or replacing the original file can no longer silently redirect a running uruntime or its filesystem helpers to different content.

### Authenticated reusable mounts

Trusted mount records now bind together the helper PID, process generation, effective UID/GID mapping, namespace kind, and concrete user/mount namespace identities. Legacy PID-only records remain readable but are not trusted for namespace reuse.

Private namespace reuse validates all identity data before `setns`. If an old kernel or seccomp policy blocks the required pre-transition operations, automatic targets move to a safe fresh mount while fixed targets fail closed. Once a namespace transition has happened, uruntime never pretends that a normal fallback is still safe.

### Correct behavior without procfs

Normal no-proc execution can mount in the current namespace when no mapping is requested and `CAP_SYS_ADMIN` is already available. A live automatic hash-derived mount visible in that namespace can also be reused directly without a PID record or `setns`.

Private no-proc mounts deliberately use random non-reusable targets because their namespace owner cannot be authenticated safely. Extracted-directory reuse remains hash-based and continues to work without procfs.

Overlapping launches now share a per-target lifetime lease, so the first launcher cannot delete a reusable extraction or abandon FUSE cleanup while another application is still using it. Coordinator, lifetime, and PID-record operations normally use separate OFD-lock ranges on one protected inode, reducing startup filesystem work while preserving independent lock lifetimes; the shared range remains held by inherited application descriptors after the launcher closes its copy. Older kernels and filesystems without OFD-lock support fall back to the conservative `flock` backend, while policy-denial errors fail closed to avoid split lock domains. A child-subreaper supervisor also tracks double-forked daemons that close inherited descriptors. If neither procfs nor child-subreaper supervision is available, cleanup retains the target rather than deleting it unsafely.

### Isolation and cleanup guarantees

Explicit root or UID/GID mapping is now a strict request: if uruntime cannot establish the requested user-and-mount namespace, it exits instead of launching with weaker isolation.

Failed application startup triggers immediate inline cleanup and preserves the original failure status. Delayed reusable cleanup waits for every participating application tree and follows `MNT_EXPIRE` semantics correctly: renewed access restarts the delay, unsupported expiration may use the regular unmount path, and busy or hard-failed mounts are retained safely.

PID records are published atomically under symlink-safe locking, and stale temporary publications are recovered after interrupted or immediate-abort runs. Production error handling was also hardened for the project's `panic=immediate-abort` release profile.

### Upgrade notes

- Every CLI option now also accepts the universal `--uruntime-*` prefix in both AppImage and RunImage formats; existing `--appimage-*` and `--runtime-*` commands remain supported.
- Legacy PID-only mount records are still readable, but they are not sufficient for private namespace reuse; uruntime will establish fresh trusted state instead.
- Explicit root or UID/GID mapping now fails closed when it cannot be applied.
- Persistent private mounts are intentionally non-reusable without procfs, while visible current-namespace mounts and extracted directories retain their safe reuse paths.

### Release validation

The local quality gate now derives tests from all nine release feature combinations, explicitly runs the two upstream helper download/cache/verification tests once, and verifies the complete checksum inventory. CI adds a canonical AArch64 QEMU lane. A repository-owned Rust lifecycle harness builds real appended SquashFS and DwarFS images and automatically verifies overlapping extraction and FUSE reuse, explicit-unshare no-proc execution, FD-closing double-fork descendants, live child-subreaper denial, fail-safe retention, and eventual cleanup. Fixture generation, ELF/release validation, workflow contract tests, and the Zig linker wrapper are also implemented in Rust rather than external Python or shell scripts. All nine x86_64 and all nine AArch64 release variants were built and validated.

See the [application lifecycle reference](https://github.com/VHSgunzo/uruntime/blob/v0.8.0/docs/APPLICATION_LIFECYCLE.md) for the complete launch, fallback, supervision, and cleanup state machines, and the [full changelog](https://github.com/VHSgunzo/uruntime/blob/v0.8.0/CHANGELOG.md) for the complete technical change list and compatibility details.
