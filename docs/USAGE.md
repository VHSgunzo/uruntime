# Using uruntime

This document is the command-line reference for AppImage and RunImage runtimes. See [CONFIGURATION.md](CONFIGURATION.md) for embedded launch policies and environment variables.

## Option prefixes

The format-specific option prefixes and environment variable namespaces are:

- AppImage: `--appimage-*` and `APPIMAGE_*`;
- RunImage: `--runtime-*` and `RUNIMAGE_*`.

Every CLI option also accepts the universal `--uruntime-*` prefix in both formats, including a runtime that does not yet have an appended filesystem. Environment variable names remain format-specific.

In the reference below, `<prefix>` means `appimage`, `runtime`, or `uruntime`, and `<ENV>` means `APPIMAGE` or `RUNIMAGE`.

Use `--` to stop runtime option parsing and pass all following arguments unchanged to the application. The separator itself is consumed by the runtime.

## Main options

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

The value for `addsign`, `addupdinfo`, or `addenvs` must fit in the preallocated ELF section. Current capacities are 1024 bytes for the signature and update information and 16 KiB for the environment. The command fills the unused remainder with zero bytes.

## Examples

```sh
# Universal prefix, valid for both formats
./uruntime-appimage-x86_64 --uruntime-version

# Show the AppImage filesystem offset
./My.AppImage --appimage-offset

# Extract only matching files
./My.AppImage --appimage-extract 'usr/bin/*'

# Run without FUSE
./My.AppImage --appimage-extract-and-run --help

# Write update information to a finished image
./My.AppImage --appimage-addupdinfo \
  'gh-releases-zsync|owner|project|latest|*.AppImage.zsync'

# Embed environment variables from a file
./My.AppImage --appimage-addenvs ./app.env

# Create a namespace and map the application user
./My.AppImage \
  --appimage-unshare-uid 1000 \
  --appimage-unshare-gid 1000 \
  --appimage-unshare-drop-caps
```

## Embedded filesystem tools

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

An embedded tool can also be invoked through the executable name. Create a hard link, symbolic link, or runtime copy whose basename matches the tool:

```sh
ln uruntime-appimage-x86_64 mksquashfs
./mksquashfs --help
```

## Portable directories

If these directories exist beside the image, the runtime changes the corresponding variables before starting the application:

| Directory | Variable |
|---|---|
| `${RUNTIME_NAME}.home` | `HOME` |
| `${RUNTIME_NAME}.share` | `XDG_DATA_HOME` |
| `${RUNTIME_NAME}.config` | `XDG_CONFIG_HOME` |
| `${RUNTIME_NAME}.cache` | `XDG_CACHE_HOME` |

Create them with the matching `--<prefix>-portable-*` options. The directory names are tied to the image's current name and location.
