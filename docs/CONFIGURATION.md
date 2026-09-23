# Configuring uruntime

This document describes embedded launch policies, environment variables, namespace controls, and DwarFS settings. See [USAGE.md](USAGE.md) for command-line options and [APPLICATION_LIFECYCLE.md](APPLICATION_LIFECYCLE.md) for the complete state machines and safety invariants.

## Embedded launch policy

Four fixed-width strings are stored directly in the runtime ELF. Current builds use:

```text
URUNTIME_MOUNT=3
URUNTIME_CLEANUP=1
URUNTIME_EXTRACT=3
URUNTIME_UNSHARE=0
```

They can be replaced in a finished runtime, including after a filesystem image has been appended. The value must remain a single digit so the file size and image offset do not change.

### Extraction policy

| `URUNTIME_EXTRACT` | Behavior |
|---|---|
| `0` | Use only a FUSE mount; do not extract automatically. |
| `1` | Always extract and run without FUSE. |
| `2` | Try FUSE first; on failure, extract regardless of file size. |
| `3` | Try FUSE first; on failure, extract only if the complete file is no larger than 350 MiB. This is the default. |

```sh
sed -i 's|URUNTIME_EXTRACT=[0-9]|URUNTIME_EXTRACT=2|' /path/to/runtime
```

The explicit `--<prefix>-mount` option never falls back to extraction. The `--<prefix>-extract` option works independently of this policy.

### Extraction cleanup

| `URUNTIME_CLEANUP` | Behavior |
|---|---|
| `0` | Do not remove the directory after extract-and-run. |
| `1` | Remove it after the application exits and the reuse wait period ends. This is the default. |

```sh
sed -i 's|URUNTIME_CLEANUP=[0-9]|URUNTIME_CLEANUP=0|' /path/to/runtime
```

`NO_CLEANUP=1` overrides cleanup for one extraction-mode run.

Reusable targets normally coordinate through three OFD-lock byte ranges on one adjacent private `<target>.lock` inode: preparation/final cleanup, shared or exclusive application lifetime, and PID-record maintenance. The lock inode intentionally remains after target cleanup so current and future waiters keep the same coordination identity. Kernels before Linux 3.15 and filesystems without OFD-lock support use a conservative compatibility backend with separate `.lease`, `.lease.lock`, and record `.lock` files. OFD permission denials fail closed instead of selecting the compatibility backend, preventing differently sandboxed peers from splitting coordination across independent lock domains.

Without procfs, uruntime uses child-subreaper supervision to include daemonized and double-forked descendants even after they close inherited descriptors. If the kernel or sandbox provides neither procfs nor child-subreaper support, uruntime retains the target and warns instead of performing unsafe cleanup.

### Namespace and capability policy

| `URUNTIME_UNSHARE` | Behavior |
|---|---|
| `0` | Do not enable `unshare` in advance. The runtime may still use it when normal FUSE mounting is unavailable. This is the default. |
| `1` | Create user and mount namespaces by default. |
| `2` | Create namespaces and drop capabilities before starting the application. |
| `3` | Keep normal mounting as the first choice; drop capabilities only if `unshare` is selected automatically as a fallback. |

```sh
sed -i 's|URUNTIME_UNSHARE=[0-9]|URUNTIME_UNSHARE=2|' /path/to/runtime
```

Mode `3` is useful when normal FUSE mounting should remain the first attempt but an automatically selected `unshare` fallback must launch the application without ambient, bounding, effective, permitted, or inheritable capabilities:

```sh
sed -i 's|URUNTIME_UNSHARE=[0-9]|URUNTIME_UNSHARE=3|' /path/to/runtime
```

Capabilities are dropped only for the launched application and only after isolation has succeeded. Filesystem helpers retain the privileges needed for mounting.

Normal execution can work without procfs when no UID/GID mapping is requested. A hash-derived FUSE target already visible in the current namespace can also be reused without procfs after uruntime verifies that it is a live mount and that no PID record or explicit mapping is involved. A private namespace without procfs uses a random non-reusable FUSE target instead. UID/GID mapping and exporting mount-only paths from a private namespace require procfs.

### Mount reuse policy

| `URUNTIME_MOUNT` | Behavior |
|---|---|
| `0` | Reuse a stable mount point and keep it mounted indefinitely by default. |
| `1` | Use a random mount point and unmount after the application exits. |
| `2` | Use a stable mount point and unmount after 30 minutes without use. |
| `3` | Use a stable mount point and unmount after 5 seconds without use. This is the default. |

```sh
sed -i 's|URUNTIME_MOUNT=[0-9]|URUNTIME_MOUNT=1|' /path/to/runtime
```

`REUSE_CHECK_DELAY` changes the wait period. `NO_UNMOUNT=1` keeps the mount indefinitely for one run.

Only the launch that created a target owns its cleanup actor. Later launches join the shared lifetime lease and do not start competing cleanup actors. The owner waits for all overlapping launches before cleanup, while `MNT_EXPIRE` also protects a reusable FUSE mount from renewed kernel-level access.

## Environment variables

In the tables below, `<ENV>` means `APPIMAGE` or `RUNIMAGE`.

### Paths and launch mode

| Variable | Value |
|---|---|
| `URUNTIME` | Path to the executable runtime processing the image. The runtime sets it. |
| `URUNTIME_DIR` | Directory containing the runtime. The runtime sets it. |
| `<ENV>_EXTRACT_AND_RUN=1` | Extract and run without FUSE. |
| `NO_CLEANUP=1` | Retain data after extract-and-run. |
| `NO_UNMOUNT=1` | Keep a FUSE mount indefinitely for this run. |
| `TMPDIR=/path` | Base temporary directory for mounting or extraction. |
| `<ENV>_TARGET_DIR=/path` | Exact directory for mounting or extraction. |
| `REUSE_CHECK_DELAY=5s` | Wait before checking whether a target is still in use. Accepts integer seconds or one `s`, `m`, or `h` suffix; `inf` disables expiry and `0` disables reuse. An invalid value produces a one-second delay. |
| `FUSERMOUNT_PROG=/path` | Explicit path to a SUID `fusermount` or `fusermount3`. |
| `ENABLE_FUSE_DEBUG=1` | Enable debug output from the selected FUSE helper. |
| `TARGET_<ENV>=/path` | Perform a maintenance operation on another image instead of the runtime itself. |
| `NO_MEMFDEXEC=1` | Run an extracted helper through a temporary executable file instead of `memfd`. |

AppImage uses `APPIMAGE_EXTRACT_AND_RUN`, `APPIMAGE_TARGET_DIR`, and `TARGET_APPIMAGE`. RunImage uses `RUNIMAGE_EXTRACT_AND_RUN`, `RUNIMAGE_TARGET_DIR`, and `TARGET_RUNIMAGE`.

### Namespaces and UID/GID mapping

| Variable | Value |
|---|---|
| `<ENV>_UNSHARE=1` | Create user and mount namespaces. |
| `<ENV>_UNSHARE=2` | Create namespaces and drop capabilities before starting the application. |
| `<ENV>_UNSHARE=3` | Do not enable `unshare` in advance; drop capabilities if it is selected automatically as a fallback. |
| `<ENV>_UNSHARE_ROOT=1` | Map the current user to UID 0 and GID 0 inside the user namespace. |
| `<ENV>_UNSHARE_UID=<uid>` | Map the current UID to the specified UID. |
| `<ENV>_UNSHARE_GID=<gid>` | Map the current GID to the specified GID. |

Any UID/GID mapping enables `unshare`. Root mapping takes precedence over separate UID/GID values. If a requested mapping cannot be applied, uruntime exits instead of launching the application without the requested isolation.

When an ordinary `unshare` request and a capability-drop mode are both present, capability dropping takes precedence.

### DwarFS settings

| Variable | Value |
|---|---|
| `DWARFS_WORKERS=2` | Explicit number of worker threads. Without it, uruntime selects the count from cache size and CPU count. |
| `DWARFS_CACHESIZE=1024M` | Block cache size. Supports `K`, `M`, and `G`; 1024M is the fallback when memory information is unavailable. |
| `DWARFS_BLOCKSIZE=512K` | Block I/O size; the default is 512K. |
| `DWARFS_READAHEAD=32M` | Readahead size; the default is 32M. |
| `DWARFS_PRELOAD_ALL=1` | Preload all blocks instead of the default `hotness` category. |
| `DWARFS_ANALYSIS_FILE=/path` | Write a profile of opened files for a later `mkdwarfs` build. |
| `DWARFS_USE_MMAP=1` | Use the `mmap` block allocator instead of `malloc`. |

## External and embedded environment

The runtime processes its embedded `.envs` section first and then an adjacent file named:

```text
${RUNTIME_NAME}.env
```

For example, `/opt/My.AppImage` uses `/opt/My.AppImage.env`. Syntax follows the project's [`dotenv`](https://github.com/VHSgunzo/dotenv) fork. After each source is read, `unset NAME` removes the specified variable:

```dotenv
QT_QPA_PLATFORM=xcb
APP_DEBUG=1
unset LD_PRELOAD
```

Embed the file in an AppImage with:

```sh
./My.AppImage --appimage-addenvs ./My.AppImage.env
```

The external file is convenient for local changes, while the embedded section travels with the image.
