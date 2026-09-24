## uruntime v0.8.1

uruntime 0.8.1 is a compatibility and correctness release for minimal Linux roots, older kernels, restricted sandboxes, and Linux compatibility environments. It fixes startup regressions around target locking, no-FUSE fallback, supervisor detachment, and reusable mounts when procfs exposes process data but not complete namespace identities.

### Better compatibility with partial procfs

A readable `/proc/self/stat` no longer implies that `/proc/self/ns/{user,mnt}` is available. uruntime now probes these capabilities separately.

On Linuxulator, older kernels, and partial procfs implementations, an automatic hash-derived FUSE mount already visible in the current namespace can be reused without publishing an unverifiable PID record. This exception remains deliberately narrow: it requires implicit identity mapping, no private namespace record, no direct PID record, and an automatic target. Normal Linux systems with namespace identities continue through strict trusted-record validation.

This also removes the misleading PID-file warning and avoids remounting the same visible target on consecutive launches. When no PID record exists, uruntime no longer leaves an unnecessary `.pid.lock` sidecar.

### Reliable minimal-root fallbacks

Target-lock setup no longer attempts to recreate an existing parent directory. This fixes restricted roots where `/tmp` is present and usable but metadata-changing operations on its parent are denied. A genuinely missing parent is still created, while a non-directory parent fails with a precise error.

Internal no-FUSE re-execution now preserves an explicitly configured AppImage or RunImage target directory until extraction fallback has selected it. The variable is still removed before the application payload starts.

Cleanup-supervisor detachment also works without `/dev/null`, including when opening the fallback sink initially returns descriptor `0`, `1`, or `2`. The runtime keeps all standard descriptors occupied instead of accidentally closing a newly installed descriptor during ownership cleanup.

### Stable reusable-target locking

Zero-length lock files intentionally remain adjacent to reusable targets after unmount or extraction cleanup. Their stable inodes prevent concurrent launches from splitting into independent lock domains. OFD-capable Linux normally uses the unified `.lock` inode; older kernels and compatibility layers without OFD locks use the conservative `.lease` and `.lease.lock` files.

### Validation

The release adds focused regression tests for restricted target parents, missing `/dev/null`, fixed-target extraction fallback, functional procfs probing, partial-procfs direct reuse, and PID-record sidecars. The real SquashFS and DwarFS lifecycle harness now exercises the corresponding fallback paths.

Consecutive DwarFS AppImage launches and reusable-mount reuse were also verified on Gentoo under FreeBSD 14.1 Linuxulator.

Foreign QEMU execution gates are temporarily disabled in CI because of their runtime cost. CI still builds all six supported architectures and validates every artifact manifest and ELF, while the full native quality and lifecycle gate remains enabled.

See the [application lifecycle reference](https://github.com/VHSgunzo/uruntime/blob/v0.8.1/docs/APPLICATION_LIFECYCLE.md) for the complete launch, reuse, locking, and cleanup behavior, and the [full changelog](https://github.com/VHSgunzo/uruntime/blob/v0.8.1/CHANGELOG.md) for the exhaustive technical list.