# uruntime 0.7.0

`uruntime` is a static runtime for [RunImage](https://github.com/VHSgunzo/runimage) and [AppImage](https://appimage.org/). It detects an appended [SquashFS](https://docs.kernel.org/filesystems/squashfs.html) or [DwarFS](https://github.com/mhx/dwarfs) image, mounts it through FUSE, or extracts it and runs the application without FUSE.

The project is intended for both users of prebuilt images and AppImage/RunImage authors. A single ELF contains the launcher, static filesystem tools, and mutable areas for configuration, environment variables, a signature, and update information.

## How it works

When started, `uruntime`:

1. reads the runtime format, embedded settings, and boundary of the appended image;
2. identifies the filesystem by its signature and selects the embedded SquashFS or DwarFS helper;
3. prepares the `.env` file, portable directories, and internal environment variables;
4. creates user and mount namespaces with the requested UID/GID mapping when needed;
5. mounts the image through FUSE or falls back to extraction if the configuration permits it;
6. runs `AppRun` for an AppImage or runs `Run.sh` through the embedded `static/bash` for a RunImage;
7. after the application exits, removes the extracted directory or unmounts the image according to the reuse mode.

Filesystem helpers are stored inside the runtime in Zstd-compressed form and executed through `memfd`. If `memfd-exec` is disabled, the runtime uses a temporary executable file. You can change the launch configuration, embedded environment, and update information in a finished runtime without recompiling it or rebuilding the appended image.

## Features

### Mounting and extraction

- SquashFS and DwarFS in one runtime, or separate filesystem-specific variants.
- FUSE operation, forced extraction, and configurable fallback to extraction when FUSE is unavailable.
- A fallback limit based on the total file size: by default, automatic extraction is allowed only for files up to 350 MiB.
- Mount point reuse, including mount points created in a separate namespace.
- Delayed unmount after the mount is no longer in use: seconds, minutes, hours, or no time limit.
- An explicit mount or extraction directory and a separate FUSE debug mode.

### DwarFS

- Configurable worker count, cache size, block size, and readahead.
- Automatic reduction of the cache and worker count when available memory is low.
- Preloading of all blocks or the default `hotness` category.
- An `analysis_file` containing file access statistics. This profile can be passed to `mkdwarfs` the next time the image is built.
- A choice of `malloc` or `mmap` for block allocation.

### Embedded tools and configuration

- Direct invocation of `squashfuse`, `unsquashfs`, `sqfscat`, `mksquashfs`, `sqfstar`, `dwarfs`, `dwarfsck`, `mkdwarfs`, and `dwarfsextract` when the selected runtime variant includes the tool.
- Helper invocation through a runtime option or through a hard link, symbolic link, or runtime copy named after the tool.
- Updating embedded environment variables, update information, and signatures from a string or file.
- Loading variables from the embedded section and adjacent `${RUNTIME_NAME}.env` file; the `unset NAME` directive removes a variable.
- Four portable directories beside the image: home, data, config, and cache.

### Isolation

`unshare` creates user and mount namespaces and supports UID/GID mapping. This also allows mounting without a SUID `fusermount` on systems where user namespaces are available.

`APPIMAGE_UNSHARE=2` and `RUNIMAGE_UNSHARE=2` enable `unshare` and drop capabilities before starting the main child process. The embedded `URUNTIME_UNSHARE=2` mode has the same behavior by default. Value `3` keeps normal mounting as the first choice and drops capabilities only when `unshare` is entered automatically as a fallback. Capabilities are dropped only after a namespace has been created or re-entered successfully, and only for the launched application; filesystem helpers retain the privileges needed for mounting.

## Supported architectures

| Artifact architecture | Rust target | Byte order |
|---|---|---|
| `x86_64` | `x86_64-unknown-linux-musl` | little-endian |
| `aarch64` | `aarch64-unknown-linux-musl` | little-endian |
| `riscv64` | `riscv64gc-unknown-linux-musl` | little-endian |
| `loongarch64` | `loongarch64-unknown-linux-musl` | little-endian |
| `ppc64` | `powerpc64-unknown-linux-musl` | big-endian |
| `ppc64le` | `powerpc64le-unknown-linux-musl` | little-endian |

`ppc64` and `ppc64le` share the Rust `target_arch` value `powerpc64`, so runtimes and helpers are selected by the complete Rust target. Big-endian and little-endian artifacts are not interchangeable.

All six targets are implemented in `build.rs`, `xtask`, and the CI matrix. At the time v0.7.0 was prepared, full release CI validation for all six architectures had not yet completed. A target's presence in this table does not mean that all 54 artifacts for the new release have already been published and verified.

## Runtime variants

For each architecture, `cargo xtask` generates nine variants. The complete filename is `uruntime-<variant>-<architecture>`.

| Variant | Format | Filesystems | Contents |
|---|---|---|---|
| `runimage` | RunImage | SquashFS + DwarFS | full |
| `runimage-squashfs` | RunImage | SquashFS | full |
| `runimage-dwarfs` | RunImage | DwarFS | full |
| `appimage` | AppImage | SquashFS + DwarFS | full |
| `appimage-lite` | AppImage | SquashFS + DwarFS | no creation/checking tools |
| `appimage-squashfs` | AppImage | SquashFS | full |
| `appimage-squashfs-lite` | AppImage | SquashFS | no `mksquashfs` or `sqfstar` |
| `appimage-dwarfs` | AppImage | DwarFS | full |
| `appimage-dwarfs-lite` | AppImage | DwarFS | no `dwarfsck` or `mkdwarfs` |

Lite variants retain the tools needed for mounting and extraction. Full variants can also create and check images.

## Projects using uruntime

The following projects have public build scripts that confirm direct use of `uruntime` or use through `quick-sharun`:

- [AnyLinux-AppImages](https://github.com/pkgforge-dev/Anylinux-AppImages/blob/main/useful-tools/quick-sharun.sh#L3853-L3855), a collection of scripts and AppImage builds for different Linux systems.
- [GOverlay](https://github.com/benjamimgois/goverlay/blob/main/appimage/goverlay-appimage.sh#L101-L102), a graphical configuration tool for MangoHud, vkBasalt, and other gaming tools.
- [Ghostty AppImage](https://github.com/pkgforge-dev/ghostty-appimage/blob/main/bin/bundle-appimage.sh#L9-L18), an AppImage build of the Ghostty terminal.
- [Interstellar](https://github.com/interstellar-app/interstellar/blob/main/scripts/build-appimage.sh#L10-L45), a client for Mbin, Lemmy, and PieFed.
- [QDiskInfo](https://github.com/edisionnano/QDiskInfo/blob/main/qdiskinfo-appimage.sh#L70-L73), a graphical interface for `smartctl` and drive SMART data.
- [CPU-X](https://github.com/TheTumultuousUnicornOfDarkness/CPU-X/blob/master/scripts/build_appimage.sh#L132-L139), a viewer for processor, motherboard, and other hardware information.
- [Eden](https://git.eden-emu.dev/eden-emu/eden/src/commit/1f091191f2d28289c6f7d237ea9f1fd6dd2333cd/.ci/package-appimage.sh), a Nintendo Switch emulator.
- [PPSSPP](https://github.com/hrydgard/ppsspp/blob/master/scripts/makeappimage_64-bit.sh#L24-L26), a PlayStation Portable emulator.
- [RPCS3](https://github.com/RPCS3/rpcs3/blob/master/.ci/deploy-linux.sh#L57-L60), a PlayStation 3 emulator.
- [Converseen](https://github.com/Faster3ck/Converseen/blob/main/package/AppImage/converseen-appimage.sh#L53-L55), a batch image conversion and resizing tool.
- [MangoJuice](https://github.com/radiolamp/mangojuice/releases/tag/1.0.0), a graphical configuration tool for MangoHud.
- [RSS Guard](https://github.com/martinrotter/rssguard/releases/tag/5.2.5), a client for RSS, Atom, and other feed formats.

For MangoJuice and RSS Guard, the evidence comes from the official release AppImages themselves rather than a reference to `quick-sharun` in source code. The files were inspected without executing them:

| Project | Tag and file | SHA-256 | Evidence |
|---|---|---|---|
| MangoJuice | [`1.0.0 / MangoJuice-1.0.0-x86_64.AppImage`](https://github.com/radiolamp/mangojuice/releases/download/1.0.0/MangoJuice-1.0.0-x86_64.AppImage) | `3b603eca0aff333c5606faad2913020397858bc4842089493e00992bb6b0ec73` | ELF64 x86-64, AppImage magic `AI\x02`; string `Repository: https://github.com/VHSgunzo/uruntime` at offset 348459. |
| RSS Guard | [`5.2.5 / rssguard-5.2.5-text-qt5-linux64.AppImage`](https://github.com/martinrotter/rssguard/releases/download/5.2.5/rssguard-5.2.5-text-qt5-linux64.AppImage) | `f5641941bce03b259647c30513b730770b099d5fef6accb32d208ed990702ed7` | ELF64 x86-64, AppImage magic `AI\x02`; string `Repository: https://github.com/VHSgunzo/uruntime` at offset 348459. |

## Getting a prebuilt runtime

Prebuilt files are published on the [Releases](https://github.com/VHSgunzo/uruntime/releases) page. Choose a variant and architecture from the tables above, then make the file executable:

```sh
chmod +x uruntime-appimage-x86_64
./uruntime-appimage-x86_64 --appimage-help
```

The option prefix depends on the format:

- AppImage: `--appimage-*`, with `APPIMAGE_*` variables;
- RunImage: `--runtime-*`, with `RUNIMAGE_*` variables.

In the reference below, `<prefix>` means `appimage` or `runtime`, and `<ENV>` means `APPIMAGE` or `RUNIMAGE`.

## Usage

### Main options

| Option | Action |
|---|---|
| `--<prefix>-extract [PATTERN]` | Extract the image into the current directory; if a pattern is provided, extract only matching paths. |
| `--<prefix>-extract-and-run [ARGS]` | Extract the image and run the application without FUSE. |
| `--<prefix>-offset` | Print the byte offset where the filesystem image begins. |
| `--<prefix>-mount` | Mount the image, print the mount point, and wait for `Ctrl-C`. |
| `--<prefix>-unshare` | Try to create user and mount namespaces. |
| `--<prefix>-unshare-root` | Enable `unshare` and map the current user to UID 0 and GID 0. |
| `--<prefix>-unshare-uid UID` | Enable `unshare` and map the current UID to `UID`. The `--...-uid=UID` form is also accepted. |
| `--<prefix>-unshare-gid GID` | Enable `unshare` and map the current GID to `GID`. The `--...-gid=GID` form is also accepted. |
| `--<prefix>-unshare-drop-caps` | Enable `unshare` and drop capabilities before starting the application. |
| `--<prefix>-unshare-fallback-drop-caps` | Keep normal mounting as the first choice and drop capabilities if `unshare` is selected automatically as a fallback. |
| `--<prefix>-portable-home` | Create `${RUNTIME_NAME}.home`. |
| `--<prefix>-portable-share` | Create `${RUNTIME_NAME}.share`. |
| `--<prefix>-portable-config` | Create `${RUNTIME_NAME}.config`. |
| `--<prefix>-portable-cache` | Create `${RUNTIME_NAME}.cache`. |
| `--<prefix>-help` | Show help for the selected runtime. |
| `--<prefix>-version` | Print the runtime version. |
| `--<prefix>-signature` | Print the embedded digital signature. |
| `--<prefix>-addsign 'SIGN\|/file'` | Write a signature from an argument or file. |
| `--<prefix>-updateinfo` | Print update information. The full form `--<prefix>-updateinformation` is also accepted. |
| `--<prefix>-addupdinfo 'INFO\|/file'` | Write update information from an argument or file. |
| `--<prefix>-envs` | Print the embedded environment. |
| `--<prefix>-addenvs 'ENVS\|/file'` | Write the environment from an argument or file. |

Examples:

```sh
# Show the AppImage image offset
./My.AppImage --appimage-offset

# Extract only matching files
./My.AppImage --appimage-extract 'usr/bin/*'

# Run without FUSE
./My.AppImage --appimage-extract-and-run --help

# Write update information to a finished image
./My.AppImage --appimage-addupdinfo \
  'gh-releases-zsync|owner|project|latest|*.AppImage.zsync'

# Embed an environment from a file
./My.AppImage --appimage-addenvs ./app.env
```

The value for `addsign`, `addupdinfo`, or `addenvs` must fit in the preallocated ELF section. Current sizes are 1024 bytes for the signature and update information and 16 KiB for the environment. The command fills the unused remainder with zero bytes.

### Embedded CLI tools

| Option | Tool | Availability |
|---|---|---|
| `--<prefix>-squashfuse [ARGS]` | `squashfuse` | variants with SquashFS |
| `--<prefix>-unsquashfs [ARGS]` | `unsquashfs` | variants with SquashFS |
| `--<prefix>-sqfscat [ARGS]` | `sqfscat` | variants with SquashFS |
| `--<prefix>-mksquashfs [ARGS]` | `mksquashfs` | full variants with SquashFS |
| `--<prefix>-sqfstar [ARGS]` | `sqfstar` | full variants with SquashFS |
| `--<prefix>-dwarfs [ARGS]` | `dwarfs` | variants with DwarFS |
| `--<prefix>-dwarfsck [ARGS]` | `dwarfsck` | full variants with DwarFS |
| `--<prefix>-mkdwarfs [ARGS]` | `mkdwarfs` | full variants with DwarFS |
| `--<prefix>-dwarfsextract [ARGS]` | `dwarfsextract` | variants with DwarFS |

The same tool can be invoked through the filename:

```sh
ln uruntime-appimage-x86_64 mksquashfs
./mksquashfs --help
```

### Portable directories

If the following directories exist beside the image, the runtime changes the corresponding variables before starting the application:

| Directory | Variable |
|---|---|
| `${RUNTIME_NAME}.home` | `HOME` |
| `${RUNTIME_NAME}.share` | `XDG_DATA_HOME` |
| `${RUNTIME_NAME}.config` | `XDG_CONFIG_HOME` |
| `${RUNTIME_NAME}.cache` | `XDG_CACHE_HOME` |

You can create them with the matching `--<prefix>-portable-*` options. The directories are tied to the file's current name and location.

## Local builds

The repository uses nightly Rust from `rust-toolchain.toml` and Cargo `build-std`. Install Rust and the `rust-src` component. Preparing helpers and publishing files to `dist/` also requires `curl` and `llvm-objcopy`; automatic Zig installation requires `tar` with XZ support.

```sh
git clone https://github.com/VHSgunzo/uruntime.git
cd uruntime
rustup component add rust-src

# List targets and all 54 tasks
cargo xtask help

# Run all local checks for the current platform's musl target
cargo xtask check

# Do the same for an explicitly selected supported Rust target
cargo xtask check x86_64-unknown-linux-musl

# Build nine variants for an architecture
cargo xtask x86_64
cargo xtask aarch64

# Build one variant
cargo xtask appimage-squashfs-riscv64

# Build the full matrix: 6 architectures x 9 variants
cargo xtask all
```

Each successful task creates `dist/uruntime-<variant>-<arch>`.

`cargo xtask check` detects the musl target for the current Linux platform. For example, it uses `x86_64-unknown-linux-musl` on `x86_64` and `aarch64-unknown-linux-musl` on `aarch64`. The command runs `cargo fmt --check`, Check, Clippy with `-D warnings`, tests for the root package and `xtask`, validation of all checksums, and `git diff --check`. One of the six Rust targets can be passed explicitly as a second argument. A foreign target uses the same pinned Zig linker backend as a build and requires its matching QEMU user-mode runner to execute the root tests.

For the host architecture, `xtask` runs a regular `cargo build` with the native linker. Cargo is the only compiler backend needed; Zig and a separate cross backend are not used. For a foreign target, the same Cargo invocation receives the project-provided Zig linker wrapper. The pinned Zig 0.16.0 is downloaded automatically to `target/toolchains/`, verified against its SHA-256, and reused. Automatic downloads are supported on Linux hosts with `x86_64`, `aarch64`, `riscv64`, `loongarch64`, or `powerpc64le`. On another host, set `URUNTIME_ZIG`; running `zig version` for the selected file must return exactly `0.16.0`.

QEMU is not involved in the build and is not needed to extract DwarFS helpers. It is used only to run `--version` on finished foreign-architecture files during smoke tests.

`build.rs` pins DwarFS 0.15.7, squashfs-tools 4.7.5.r2, and squashfuse 0.6.3.r2. Normal builds do not depend on UPX. DwarFS publishes Zstd self-extracting wrappers; `build.rs` parses the `SQUEEZE!` trailer, checks the size and XXH64, extracts the target ELF on the host, and then verifies the SHA-256 and ELF machine/endian. The foreign ELF is never executed during this process.

## Verifying and updating checksums

`checksums.txt` pins two checksums for every filesystem helper: the downloaded file and the extracted payload. It also records the URLs and SHA-256 values of Zig archives for supported Linux hosts.

```sh
# Download the sources, recompute the data, and check for drift
cargo xtask update-checksums --check

# Update checksums.txt after an intentional version or URL change
cargo xtask update-checksums

git diff -- checksums.txt
```

Both commands access the network and check all 30 helper sources, not just the current architecture. Always review the diff after an update. `URUNTIME_CURL=/path/to/curl` selects the download program for both `build.rs` and `update-checksums`.

## CI builds

The `.github/workflows/ci.yml` workflow has three parts:

1. Preflight runs the canonical `cargo xtask check` command: formatting, Check, Clippy, Rust tests, `xtask` tests, pinned helper/Zig validation, and `git diff --check`.
2. Six independent build jobs run `cargo xtask <arch>`, verify the exact list of nine files, ELF64 machine/endian, absence of `PT_INTERP` and `DT_NEEDED`, required sections, and runtime magic; foreign jobs run `--version` through QEMU.
3. On a tag push, the release job builds exactly 54 files and publishes them through a verified draft stage. A rerun can safely refresh the release for the same tag: old assets are deleted only after the release becomes a draft, and it is made public again only after the new complete manifest has been verified.

A QEMU smoke test does not replace a FUSE mount test on a foreign architecture. Full mount/run behavior must be tested separately where the runner provides a working `/dev/fuse`.

[RELEASING.md](RELEASING.md) describes the step-by-step process for updating the code, Rust dependencies, helpers, and Zig, and for creating or reissuing a tag.

## Embedded configuration

Four strings are stored directly in the runtime ELF. In the current build they are `URUNTIME_MOUNT=3`, `URUNTIME_CLEANUP=1`, `URUNTIME_EXTRACT=3`, and `URUNTIME_UNSHARE=0`. They can be replaced in a finished runtime, including after an image has been appended. The value must remain a single digit so that the file size and image offset do not change.

### `URUNTIME_EXTRACT`

| Value | Behavior |
|---|---|
| `0` | Use only a FUSE mount; do not extract automatically. |
| `1` | Always extract and run without FUSE. |
| `2` | Try FUSE first; on failure, extract regardless of file size. |
| `3` | Try FUSE first; on failure, extract only if the file is no larger than 350 MiB. This is the default. |

```sh
sed -i 's|URUNTIME_EXTRACT=[0-9]|URUNTIME_EXTRACT=2|' /path/to/runtime
```

The explicit `--<prefix>-mount` option never falls back to extraction. The `--<prefix>-extract` option works independently of the fallback mode.

### `URUNTIME_CLEANUP`

| Value | Behavior |
|---|---|
| `0` | Do not remove the directory after extract-and-run. |
| `1` | Remove the extracted directory after the application exits and the wait period ends. This is the default. |

```sh
sed -i 's|URUNTIME_CLEANUP=[0-9]|URUNTIME_CLEANUP=0|' /path/to/runtime
```

`NO_CLEANUP=1` overrides cleanup for one run in extraction mode.

### `URUNTIME_UNSHARE`

| Value | Behavior |
|---|---|
| `0` | Do not enable `unshare` in advance. The runtime may still try it if FUSE is unavailable without a SUID `fusermount`. This is the default. |
| `1` | Create user and mount namespaces by default. |
| `2` | Create namespaces and drop capabilities before starting the application. |
| `3` | Do not enable `unshare` in advance. If the runtime enters `unshare` automatically as a fallback, drop capabilities before starting the application. Explicit `--<prefix>-unshare` and `<ENV>_UNSHARE=1` requests do not enable capability dropping by themselves. |

```sh
sed -i 's|URUNTIME_UNSHARE=[0-9]|URUNTIME_UNSHARE=2|' /path/to/runtime
```

Use mode `3` when normal FUSE mounting should remain the first attempt, but an automatically selected `unshare` fallback must launch the application without ambient, bounding, effective, permitted, or inheritable capabilities:

```sh
sed -i 's|URUNTIME_UNSHARE=[0-9]|URUNTIME_UNSHARE=3|' /path/to/runtime
```

### `URUNTIME_MOUNT`

| Value | Behavior |
|---|---|
| `0` | Reuse a stable mount point; by default, the FUSE mount remains mounted indefinitely. |
| `1` | Use a random mount point and unmount after the application exits. |
| `2` | Use a stable mount point and unmount after 30 minutes without use. |
| `3` | Use a stable mount point and unmount after 5 seconds without use. This is the default. |

```sh
sed -i 's|URUNTIME_MOUNT=[0-9]|URUNTIME_MOUNT=1|' /path/to/runtime
```

`REUSE_CHECK_DELAY` changes the delay for reuse modes. `NO_UNMOUNT=1` keeps the mount indefinitely for one run.

## Environment variables

### Paths and launch mode

| Variable | Value |
|---|---|
| `URUNTIME` | Path to the executable runtime processing the image. The runtime sets this variable itself. |
| `URUNTIME_DIR` | Directory containing this runtime. The runtime sets this variable itself. |
| `<ENV>_EXTRACT_AND_RUN=1` | Extract and run without FUSE. |
| `NO_CLEANUP=1` | Do not remove data after extract-and-run. |
| `NO_UNMOUNT=1` | Do not unmount the image after the application exits; enables mount point reuse. |
| `TMPDIR=/path` | Base temporary directory for mounting or extraction. |
| `<ENV>_TARGET_DIR=/path` | Exact directory for mounting or extraction. |
| `REUSE_CHECK_DELAY=5s` | Delay before checking whether the directory is in use. Accepts an integer number of seconds or one `s`, `m`, or `h` suffix; `inf` disables the timeout, while `0` disables reuse. An invalid value produces a one-second delay. |
| `FUSERMOUNT_PROG=/path` | Explicit path to a SUID `fusermount`/`fusermount3`. |
| `ENABLE_FUSE_DEBUG=1` | Enable debug output from the selected FUSE helper. |
| `TARGET_<ENV>=/path` | Perform a maintenance operation on the specified AppImage/RunImage instead of the runtime itself. |
| `NO_MEMFDEXEC=1` | Run the extracted helper through a temporary file instead of `memfd-exec`. |

AppImage uses `APPIMAGE_EXTRACT_AND_RUN`, `APPIMAGE_TARGET_DIR`, and `TARGET_APPIMAGE`. RunImage uses `RUNIMAGE_EXTRACT_AND_RUN`, `RUNIMAGE_TARGET_DIR`, and `TARGET_RUNIMAGE`.

### `unshare` and UID/GID mapping

| Variable | Value |
|---|---|
| `<ENV>_UNSHARE=1` | Create user and mount namespaces. |
| `<ENV>_UNSHARE=2` | Create namespaces and drop ambient, bounding, effective, permitted, and inheritable capabilities before starting the application. |
| `<ENV>_UNSHARE=3` | Do not enable `unshare` in advance; drop capabilities if it is selected automatically as a fallback. |
| `<ENV>_UNSHARE_ROOT=1` | Map the current user to UID 0 and GID 0 inside the user namespace. |
| `<ENV>_UNSHARE_UID=<uid>` | Map the current UID to the specified UID inside the namespace. |
| `<ENV>_UNSHARE_GID=<gid>` | Map the current GID to the specified GID inside the namespace. |


Substituting `<ENV>` gives the complete set of `APPIMAGE_*` or `RUNIMAGE_*` variables. Any UID/GID mapping also enables `unshare`. If `*_UNSHARE_ROOT=1` or `--<prefix>-unshare-root` is set, root mapping takes precedence over separate UID/GID values from either CLI options or environment variables.

The CLI options can be combined. For example:

```sh
./My.AppImage \
  --appimage-unshare-uid 1000 \
  --appimage-unshare-gid 1000 \
  --appimage-unshare-drop-caps
```

When an ordinary `unshare` request and a capability-drop mode are both present, capability dropping takes precedence. Use `--` to stop runtime option parsing and pass the following arguments unchanged to the application; the separator itself is consumed by the runtime.

### DwarFS settings

| Variable | Value |
|---|---|
| `DWARFS_WORKERS=2` | Explicit number of worker threads. Without this variable, the runtime selects the count based on cache size and CPU count. |
| `DWARFS_CACHESIZE=1024M` | Block cache size. The `K`, `M`, and `G` suffixes are supported. Without this variable, the size is selected from available memory; 1024M is the fallback if `/proc` is unavailable. |
| `DWARFS_BLOCKSIZE=512K` | Block I/O size; the default is 512K. |
| `DWARFS_READAHEAD=32M` | Readahead size; the default is 32M. |
| `DWARFS_PRELOAD_ALL=1` | Preload all blocks; without this variable, `preload_category=hotness` is used. |
| `DWARFS_ANALYSIS_FILE=/path` | Write a profile of opened files to the specified file. |
| `DWARFS_USE_MMAP=1` | Use the `mmap` block allocator; without this variable, `malloc` is used. |

### The `.env` file and embedded environment

The runtime processes the embedded `.envs` section first and then the adjacent file:

```text
${RUNTIME_NAME}.env
```

For example, `/opt/My.AppImage` uses `/opt/My.AppImage.env`. Variable syntax follows the project's [`dotenv`](https://github.com/VHSgunzo/dotenv) fork. After each source is read, lines in the form `unset NAME` remove the specified variables:

```dotenv
QT_QPA_PLATFORM=xcb
APP_DEBUG=1
unset LD_PRELOAD
```

Embed such a file with:

```sh
./My.AppImage --appimage-addenvs ./My.AppImage.env
```

The external file is useful for local changes, while the embedded section travels with the image.

## License

[MIT](LICENSE)
