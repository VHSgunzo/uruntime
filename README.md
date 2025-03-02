# URUNTIME
Universal [RunImage](https://github.com/VHSgunzo/runimage) and [AppImage](https://appimage.org/) runtime with [SquashFS](https://docs.kernel.org/filesystems/squashfs.html) and [DwarFS](https://github.com/mhx/dwarfs) supports

## To get started:
* **Download the latest revision**
```
git clone https://github.com/VHSgunzo/uruntime.git && cd uruntime
```

* **Compile a binary**
```
rustup default nightly
rustup target add x86_64-unknown-linux-musl
rustup component add rust-src --toolchain nightly

cargo xtask
# Tasks:
#     x86_64                           build x86_64 RunImage and AppImage uruntime
#     runimage-x86_64                  build x86_64 RunImage uruntime
#     runimage-squashfs-x86_64         build x86_64 RunImage uruntime (SquashFS-only)
#     runimage-dwarfs-x86_64           build x86_64 RunImage uruntime (DwarFS-only)
#     appimage-x86_64                  build x86_64 AppImage uruntime
#     appimage-lite-x86_64             build x86_64 AppImage uruntime (no mksquashfs)
#     appimage-squashfs-x86_64         build x86_64 AppImage uruntime (SquashFS-only)
#     appimage-squashfs-lite-x86_64    build x86_64 AppImage uruntime (SquashFS-only no mksquashfs)
#     appimage-dwarfs-x86_64           build x86_64 AppImage uruntime (DwarFS-only)
# 
#     aarch64                          build aarch64 RunImage and AppImage uruntime
#     runimage-aarch64                 build aarch64 RunImage uruntime
#     runimage-squashfs-aarch64        build aarch64 RunImage uruntime (SquashFS-only)
#     runimage-dwarfs-aarch64          build aarch64 RunImage uruntime (DwarFS-only)
#     appimage-aarch64                 build aarch64 AppImage uruntime
#     appimage-lite-aarch64            build aarch64 AppImage uruntime (no mksquashfs)
#     appimage-squashfs-aarch64        build aarch64 AppImage uruntime (SquashFS-only)
#     appimage-squashfs-lite-aarch64   build aarch64 AppImage uruntime (SquashFS-only no mksquashfs)
#     appimage-dwarfs-aarch64          build aarch64 AppImage uruntime (DwarFS-only)
# 
#     all                              build all of the above

# for RunImage x86_64
cargo xtask runimage-x86_64

# for AppImage x86_64
cargo xtask appimage-x86_64
```
See [Build step in ci.yml](https://github.com/VHSgunzo/uruntime/blob/main/.github/workflows/ci.yml#L34)

* Or take an already precompiled from the [releases](https://github.com/VHSgunzo/uruntime/releases)

* **RunImage runtime usage**
```
   Runtime options:
    --runtime-extract [PATTERN]          Extract content from embedded filesystem image
                                             If pattern is passed, only extract matching files
     --runtime-extract-and-run [ARGS]    Run the RunImage afer extraction without using FUSE
     --runtime-offset                    Print byte offset to start of embedded filesystem image
     --runtime-portable-home             Create a portable home folder to use as $HOME
     --runtime-portable-config           Create a portable config folder to use as $XDG_CONFIG_HOME
     --runtime-help                      Print this help
     --runtime-version                   Print version of Runtime
     --runtime-signature                 Print digital signature embedded in RunImage
     --runtime-updateinfo[rmation]       Print update info embedded in RunImage
     --runtime-mount                     Mount embedded filesystem image and print
                                             mount point and wait for kill with Ctrl-C

    Embedded tools options:
      --runtime-squashfuse    [ARGS]       Launch squashfuse
      --runtime-unsquashfs    [ARGS]       Launch unsquashfs
      --runtime-mksquashfs    [ARGS]       Launch mksquashfs
      --runtime-dwarfs        [ARGS]       Launch dwarfs
      --runtime-dwarfsck      [ARGS]       Launch dwarfsck
      --runtime-mkdwarfs      [ARGS]       Launch mkdwarfs
      --runtime-dwarfsextract [ARGS]       Launch dwarfsextract

      Also you can create a hardlink, symlink or rename the runtime with
      the name of the built-in utility to use it directly.

    Portable home and config:

      If you would like the application contained inside this RunImage to store its
      data alongside this RunImage rather than in your home directory, then you can
      place a directory named

      for portable-home:
      "${RUNTIME_NAME}.home"

      for portable-config:
      "${RUNTIME_NAME}.config"

      Or you can invoke this RunImage with the --runtime-portable-home or
      --runtime-portable-config option, which will create this directory for you.
      As long as the directory exists and is neither moved nor renamed, the
      application contained inside this RunImage to store its data in this
      directory rather than in your home directory

    Environment variables:

      RUNTIME_EXTRACT_AND_RUN=1      Run the RunImage afer extraction without using FUSE
      NO_CLEANUP=1                   Do not clear the unpacking directory after closing when
                                       using extract and run option for reuse extracted data
      NO_UNMOUNT=1                   Do not unmount the mount directory after closing 
                                      for reuse mount point
      TMPDIR=/path                   Specifies a custom path for mounting or extracting the image
      FUSERMOUNT_PROG=/path          Specifies a custom path for fusermount
      DWARFS_WORKERS=2               Number of worker threads for DwarFS (default: equal CPU threads)
      DWARFS_CACHESIZE=512M          Size of the block cache, in bytes for DwarFS (suffixes K, M, G)
      DWARFS_BLOCKSIZE=512K          Size of the block file I/O, in bytes for DwarFS (suffixes K, M, G)
```

* **AppImage runtime usage**
```
   Runtime options:
    --appimage-extract [PATTERN]          Extract content from embedded filesystem image
                                             If pattern is passed, only extract matching files
     --appimage-extract-and-run [ARGS]    Run the AppImage afer extraction without using FUSE
     --appimage-offset                    Print byte offset to start of embedded filesystem image
     --appimage-portable-home             Create a portable home folder to use as $HOME
     --appimage-portable-config           Create a portable config folder to use as $XDG_CONFIG_HOME
     --appimage-help                      Print this help
     --appimage-version                   Print version of Runtime
     --appimage-signature                 Print digital signature embedded in AppImage
     --appimage-updateinfo[rmation]       Print update info embedded in AppImage
     --appimage-mount                     Mount embedded filesystem image and print
                                             mount point and wait for kill with Ctrl-C

    Embedded tools options:
      --appimage-squashfuse    [ARGS]       Launch squashfuse
      --appimage-unsquashfs    [ARGS]       Launch unsquashfs
      --appimage-mksquashfs    [ARGS]       Launch mksquashfs
      --appimage-dwarfs        [ARGS]       Launch dwarfs
      --appimage-dwarfsck      [ARGS]       Launch dwarfsck
      --appimage-mkdwarfs      [ARGS]       Launch mkdwarfs
      --appimage-dwarfsextract [ARGS]       Launch dwarfsextract

      Also you can create a hardlink, symlink or rename the runtime with
      the name of the built-in utility to use it directly.

    Portable home and config:

      If you would like the application contained inside this AppImage to store its
      data alongside this AppImage rather than in your home directory, then you can
      place a directory named

      for portable-home:
      "${RUNTIME_NAME}.home"

      for portable-config:
      "${RUNTIME_NAME}.config"

      Or you can invoke this AppImage with the --appimage-portable-home or
      --appimage-portable-config option, which will create this directory for you.
      As long as the directory exists and is neither moved nor renamed, the
      application contained inside this AppImage to store its data in this
      directory rather than in your home directory

    Environment variables:

      APPIMAGE_EXTRACT_AND_RUN=1     Run the AppImage afer extraction without using FUSE
      NO_CLEANUP=1                   Do not clear the unpacking directory after closing when
                                       using extract and run option for reuse extracted data
      NO_UNMOUNT=1                   Do not unmount the mount directory after closing 
                                      for reuse mount point
      TMPDIR=/path                   Specifies a custom path for mounting or extracting the image
      FUSERMOUNT_PROG=/path          Specifies a custom path for fusermount
      TARGET_APPIMAGE=/path          Operate on a target AppImage rather than this file itself
      DWARFS_WORKERS=2               Number of worker threads for DwarFS (default: equal CPU threads)
      DWARFS_CACHESIZE=512M          Size of the block cache, in bytes for DwarFS (suffixes K, M, G)
      DWARFS_BLOCKSIZE=512K          Size of the block file I/O, in bytes for DwarFS (suffixes K, M, G)
```

### **Built-in configuration:**
You can change the startup logic by changing the built-in uruntime parameters.
* `URUNTIME_EXTRACT` - Specifies the logic of extracting or mounting
```
# URUNTIME_EXTRACT=0 - FUSE mounting only
sed -i 's|URUNTIME_EXTRACT=[0-9]|URUNTIME_EXTRACT=0|' /path/uruntime

# URUNTIME_EXTRACT=1 - Do not use FUSE mounting, but extract and run
sed -i 's|URUNTIME_EXTRACT=[0-9]|URUNTIME_EXTRACT=1|' /path/uruntime

# URUNTIME_EXTRACT=2 - Try to use FUSE mounting and if it is unavailable extract and run
sed -i 's|URUNTIME_EXTRACT=[0-9]|URUNTIME_EXTRACT=2|' /path/uruntime

# URUNTIME_EXTRACT=3 - As above, but if the image size is less than 350 MB (default)
sed -i 's|URUNTIME_EXTRACT=[0-9]|URUNTIME_EXTRACT=3|' /path/uruntime
```

* `URUNTIME_CLEANUP` - Specifies the logic of cleanup after extract and run
```
# URUNTIME_CLEANUP=0 - Disable extracting directory cleanup
sed -i 's|URUNTIME_CLEANUP=[0-9]|URUNTIME_CLEANUP=0|' /path/uruntime

# URUNTIME_CLEANUP=1 - Enable extracting directory cleanup (default)
sed -i 's|URUNTIME_CLEANUP=[0-9]|URUNTIME_CLEANUP=1|' /path/uruntime
```

* `URUNTIME_MOUNT` - Specifies the mount logic
```
# URUNTIME_MOUNT=0 - Disable unmounting of the mount directory for reuse mount point
sed -i 's|URUNTIME_MOUNT=[0-9]|URUNTIME_MOUNT=0|' /path/uruntime

# URUNTIME_MOUNT=1 - Enable unmounting of the mount directory (default)
sed -i 's|URUNTIME_MOUNT=[0-9]|URUNTIME_MOUNT=1|' /path/uruntime
```