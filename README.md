# uruntime

`uruntime` is a static runtime for [RunImage](https://github.com/VHSgunzo/runimage) and [AppImage](https://appimage.org/). It launches appended SquashFS and DwarFS images through FUSE, with extraction as a configurable fallback when FUSE is unavailable.

A single ELF contains the launcher and static filesystem tools. Runtime settings, environment variables, signatures, and update information can be changed after an image has been built, without recompiling the runtime or repacking its filesystem.

## Highlights

- AppImage and RunImage support.
- SquashFS and DwarFS support in one runtime or filesystem-specific builds.
- Fully static binaries for six Linux architectures.
- FUSE mounting, forced extraction, and automatic extraction fallback.
- Safe reuse of shared mounts and extracted directories across overlapping launches.
- User and mount namespaces with optional UID/GID mapping and capability dropping.
- Portable home, data, config, and cache directories beside the image.
- Embedded filesystem tools that can be called through runtime options or executable names.
- Mutable ELF sections for environment variables, signatures, and update information.
- Operation without procfs when the selected launch mode does not require it.

## How it works

When an image starts, `uruntime`:

1. finds and validates the appended SquashFS or DwarFS image;
2. mounts it through FUSE or extracts it according to the configured policy;
3. prepares namespaces, portable directories, and the runtime environment;
4. starts `AppRun` for AppImage or `Run.sh` for RunImage;
5. keeps shared targets alive while participating application trees are still running, then cleans them up according to the reuse policy.

Filesystem helpers are stored inside the runtime in Zstd-compressed form and normally run through `memfd`. Cleanup fails safe: if uruntime cannot prove that a shared target is no longer in use, it retains the target instead of deleting active data or unmounting a live filesystem.

The complete launch, fallback, reuse, supervision, and cleanup model is documented in [Application launch, lifetime, and cleanup](docs/APPLICATION_LIFECYCLE.md).

## Runtime variants

Each release contains nine variants per architecture:

| Variant | Format | Filesystems | Contents |
|---|---|---|---|
| `runimage` | RunImage | SquashFS + DwarFS | full |
| `runimage-squashfs` | RunImage | SquashFS | full |
| `runimage-dwarfs` | RunImage | DwarFS | full |
| `appimage` | AppImage | SquashFS + DwarFS | full |
| `appimage-lite` | AppImage | SquashFS + DwarFS | mount/extract only |
| `appimage-squashfs` | AppImage | SquashFS | full |
| `appimage-squashfs-lite` | AppImage | SquashFS | mount/extract only |
| `appimage-dwarfs` | AppImage | DwarFS | full |
| `appimage-dwarfs-lite` | AppImage | DwarFS | mount/extract only |

Full variants can create and check filesystem images. Lite variants retain the tools needed to mount and extract them.

Supported release architectures are `x86_64`, `aarch64`, `riscv64`, `loongarch64`, `ppc64`, and `ppc64le`. See the [build guide](docs/BUILDING.md) for Rust targets and cross-build details.

## Getting a prebuilt runtime

Download a runtime from [Releases](https://github.com/VHSgunzo/uruntime/releases), choose the required variant and architecture, then make it executable:

```sh
chmod +x uruntime-appimage-x86_64
./uruntime-appimage-x86_64 --appimage-help
```

Common operations:

```sh
# Show the image offset
./My.AppImage --appimage-offset

# Extract the image
./My.AppImage --appimage-extract

# Run without FUSE
./My.AppImage --appimage-extract-and-run

# Create portable directories beside the image
./My.AppImage --appimage-portable-home
./My.AppImage --appimage-portable-config
```

AppImage options use the `--appimage-*` prefix and RunImage options use `--runtime-*`. The universal `--uruntime-*` prefix works with both formats. See the [usage reference](docs/USAGE.md) for all commands and embedded tools, and the [configuration reference](docs/CONFIGURATION.md) for launch policies and environment variables.

## Building

The project uses the pinned Rust nightly from `rust-toolchain.toml`. Repository build, test, and release orchestration is implemented in Rust through `xtask`.

```sh
git clone https://github.com/VHSgunzo/uruntime.git
cd uruntime
rustup component add rust-src rustfmt clippy

# Run the canonical local gate
cargo --locked xtask check

# Build nine variants for x86_64
cargo --locked xtask x86_64
```

See [Building uruntime](docs/BUILDING.md) for prerequisites, targets, toolchains, helper verification, and artifact validation.

## Projects using uruntime

- [AnyLinux-AppImages](https://github.com/pkgforge-dev/Anylinux-AppImages) — a
  collection of AppImage build scripts for many Linux applications.
- [appimagetool](https://github.com/pkgforge-dev/appimagetool) — a Rust
  AppImage builder that packages AppDirs as DwarFS images with uruntime,
  including pinned runtime resolution and ELF section configuration.
- [CPU-X](https://github.com/TheTumultuousUnicornOfDarkness/CPU-X) — a system
  information and hardware monitoring application.
- [Converseen](https://github.com/Faster3ck/Converseen) — a batch image
  conversion and resizing application.
- [Eden](https://git.eden-emu.dev/eden-emu/eden) — a Nintendo Switch emulator.
- [Ghostty AppImage](https://github.com/pkgforge-dev/ghostty-appimage) — a
  portable AppImage build of the Ghostty terminal.
- [GOverlay](https://github.com/benjamimgois/goverlay) — a graphical
  configurator for MangoHud, vkBasalt, and related gaming tools.
- [Interstellar](https://github.com/interstellar-app/interstellar) — a client
  for Mbin, Lemmy, and PieFed.
- [MangoJuice](https://github.com/radiolamp/mangojuice) — a graphical
  configuration tool for MangoHud.
- [PPSSPP](https://github.com/hrydgard/ppsspp) — a PlayStation Portable
  emulator.
- [QDiskInfo](https://github.com/edisionnano/QDiskInfo) — a graphical frontend
  for `smartctl` and drive SMART data.
- [RPCS3](https://github.com/RPCS3/rpcs3) — a PlayStation 3 emulator.
- [RSS Guard](https://github.com/martinrotter/rssguard) — a desktop client for
  RSS, Atom, and other feed formats.

## Documentation

- [Usage reference](docs/USAGE.md)
- [Configuration reference](docs/CONFIGURATION.md)
- [Application launch, lifetime, and cleanup](docs/APPLICATION_LIFECYCLE.md)
- [Building uruntime](docs/BUILDING.md)
- [Testing uruntime](docs/TESTING.md)
- [Release procedure](docs/RELEASING.md)
- [Release history](CHANGELOG.md)

## License

[MIT](LICENSE)
