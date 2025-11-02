# URUNTIME
Universal [RunImage](https://github.com/VHSgunzo/runimage) and [AppImage](https://appimage.org/) runtime with [SquashFS](https://docs.kernel.org/filesystems/squashfs.html) and [DwarFS](https://github.com/mhx/dwarfs) supports

## To get started:
* **Download the latest revision**
```
git clone https://github.com/VHSgunzo/uruntime.git && cd uruntime
```

* **Compile a binary**
```
rustup toolchain add nightly
rustup target add x86_64-unknown-linux-musl
rustup component add rust-src --toolchain nightly

cargo xtask
# Tasks:
#     x86_64                           build x86_64 RunImage and AppImage uruntime
#     runimage-x86_64                  build x86_64 RunImage uruntime
#     appimage-x86_64                  build x86_64 AppImage uruntime
#     appimage-lite-x86_64             build x86_64 AppImage uruntime (no dwarfsck, mkdwarfs, mksquashfs, sqfstar)
#     appimage-squashfs-x86_64         build x86_64 AppImage uruntime (SquashFS-only)
#     appimage-squashfs-lite-x86_64    build x86_64 AppImage uruntime (SquashFS-only no mksquashfs, sqfstar)
#     appimage-dwarfs-x86_64           build x86_64 AppImage uruntime (DwarFS-only)
#     appimage-dwarfs-lite-x86_64      build x86_64 AppImage uruntime (DwarFS-only no dwarfsck, mkdwarfs)
# 
#     aarch64                          build aarch64 RunImage and AppImage uruntime
#     runimage-aarch64                 build aarch64 RunImage uruntime
#     appimage-aarch64                 build aarch64 AppImage uruntime
#     appimage-lite-aarch64            build aarch64 AppImage uruntime (no dwarfsck, mkdwarfs, mksquashfs, sqfstar)
#     appimage-squashfs-aarch64        build aarch64 AppImage uruntime (SquashFS-only)
#     appimage-squashfs-lite-aarch64   build aarch64 AppImage uruntime (SquashFS-only no mksquashfs, sqfstar)
#     appimage-dwarfs-aarch64          build aarch64 AppImage uruntime (DwarFS-only)
#     appimage-dwarfs-lite-aarch64     build aarch64 AppImage uruntime (DwarFS-only no dwarfsck, mkdwarfs)
# 
#     all                              build all of the above

# for RunImage x86_64
cargo xtask runimage-x86_64

# for AppImage x86_64
cargo xtask appimage-x86_64
```
See [Build step in ci.yml](https://github.com/VHSgunzo/uruntime/blob/main/.github/workflows/ci.yml#L34)

* Or take an already precompiled from the [releases](https://github.com/VHSgunzo/uruntime/releases)

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

* `URUNTIME_UNSHARE` - Specifies whether to try using unshare user and mount namespaces by default
```
# URUNTIME_UNSHARE=0 - Don't run in unshare mode by default (default)
sed -i 's|URUNTIME_UNSHARE=[0-9]|URUNTIME_UNSHARE=0|' /path/uruntime

# URUNTIME_UNSHARE=1 - Run in unshare mode by default
sed -i 's|URUNTIME_UNSHARE=[0-9]|URUNTIME_UNSHARE=1|' /path/uruntime
```

* `URUNTIME_MOUNT` - Specifies the mount logic
```
# URUNTIME_MOUNT=0 - Reuse mount point and disable unmounting of the mount directory
sed -i 's|URUNTIME_MOUNT=[0-9]|URUNTIME_MOUNT=0|' /path/uruntime

# URUNTIME_MOUNT=1 - Random mount points and unmounting of the mount directory
sed -i 's|URUNTIME_MOUNT=[0-9]|URUNTIME_MOUNT=1|' /path/uruntime

# URUNTIME_MOUNT=2 - Reuse mount point and unmounting of the mount directory 
#                    with a 30 minutes delay of inactivity
sed -i 's|URUNTIME_MOUNT=[0-9]|URUNTIME_MOUNT=2|' /path/uruntime

# URUNTIME_MOUNT=3 - Reuse mount point and unmounting of the mount directory 
#                    with a 5 second delay of inactivity (default)
sed -i 's|URUNTIME_MOUNT=[0-9]|URUNTIME_MOUNT=3|' /path/uruntime
```

<details><summary style="font-size: 15px;"><b>
RunImage runtime usage
</b></summary>

```
   Runtime options:
    --runtime-extract [PATTERN]          Extract content from embedded filesystem image
                                             If pattern is passed, only extract matching files
     --runtime-extract-and-run [ARGS]    Run the RunImage afer extraction without using FUSE
     --runtime-offset                    Print byte offset to start of embedded filesystem image
     --runtime-portable-home             Create a portable home folder to use as $HOME
     --runtime-portable-share            Create a portable share folder to use as $XDG_DATA_HOME
     --runtime-portable-config           Create a portable config folder to use as $XDG_CONFIG_HOME
     --runtime-portable-cache            Create a portable cache folder to use as $XDG_CACHE_HOME
     --runtime-help                      Print this help
     --runtime-unshare                   Try to use unshare user and mount namespaces
     --runtime-version                   Print version of Runtime
     --runtime-signature                 Print digital signature embedded in RunImage
     --runtime-addsign    'SIGN|/file'   Add digital signature to RunImage
     --runtime-updateinfo[rmation]       Print update info embedded in RunImage
     --runtime-addupdinfo 'INFO|/file'   Add update info to RunImage
     --runtime-envs                      Print environment variables embedded in RunImage
     --runtime-addenvs    'ENVS|/file'   Add environment variables to RunImage
     --runtime-mount                     Mount embedded filesystem image and print
                                             mount point and wait for kill with Ctrl-C

    Embedded tools options:
      --runtime-squashfuse    [ARGS]       Launch squashfuse
      --runtime-unsquashfs    [ARGS]       Launch unsquashfs
      --runtime-sqfscat       [ARGS]       Launch sqfscat
      --runtime-mksquashfs    [ARGS]       Launch mksquashfs
      --runtime-sqfstar       [ARGS]       Launch sqfstar
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

      for portable-share:
      "${RUNTIME_NAME}.share"

      for portable-config:
      "${RUNTIME_NAME}.config"
      
      for portable-cache:
      "${RUNTIME_NAME}.cache"

      Or you can invoke this RunImage with the --runtime-portable-home or
      --runtime-portable-share or --runtime-portable-config or
      --runtime-portable-cache option, which will create this directory for you.
      As long as the directory exists and is neither moved nor renamed, the
      application contained inside this RunImage to store its data in this
      directory rather than in your home directory

    Environment variables:

      URUNTIME                       Path to uruntime
      URUNTIME_DIR                   Path to uruntime directory
      RUNIMAGE_UNSHARE=1             Try to use unshare user and mount namespaces
      RUNIMAGE_UNSHARE_ROOT=1        Map to root (UID 0, GID 0) in user namespace
      RUNIMAGE_UNSHARE_UID=0         Map to specified UID in user namespace
      RUNIMAGE_UNSHARE_GID=0         Map to specified GID in user namespace
      RUNTIME_EXTRACT_AND_RUN=1      Run the RunImage afer extraction without using FUSE
      NO_CLEANUP=1                   Do not clear the unpacking directory after closing when
                                       using extract and run option for reuse extracted data
      NO_UNMOUNT=1                   Do not unmount the mount directory after closing 
                                      for reuse mount point
      TMPDIR=/path                   Specifies a custom path for mounting or extracting the image
      RUNIMAGE_TARGET_DIR=/path      Specifies the exact path for mounting or extracting the image
      REUSE_CHECK_DELAY=5s           Specifies the delay between checks of using the image dir (0|inf|1|1s|1m|1h)
      FUSERMOUNT_PROG=/path          Specifies a custom path for fusermount
      ENABLE_FUSE_DEBUG=1            Enables debug mode for the mounted filesystem
      TARGET_RUNIMAGE=/path          Operate on a target RunImage rather than this file itself
      NO_MEMFDEXEC=1                 Do not use memfd-exec (use a temporary file instead)
      DWARFS_WORKERS=2               Number of worker threads for DwarFS (default: equal CPU threads)
      DWARFS_CACHESIZE=1024M         Size of the block cache, in bytes for DwarFS (suffixes K, M, G)
      DWARFS_BLOCKSIZE=512K          Size of the block file I/O, in bytes for DwarFS (suffixes K, M, G)
      DWARFS_READAHEAD=32M           Set readahead size, in bytes for DwarFS (suffixes K, M, G)
      DWARFS_PRELOAD_ALL=1           Enable preloading of all blocks from the DwarFS file system
      DWARFS_ANALYSIS_FILE=/path     A file for profiling open files when launching the application for DwarFS
      DWARFS_USE_MMAP=1              Use mmap for allocating blocks for DwarFS

      Environment variables can be specified in the env file (see https://crates.io/crates/dotenv)
      and environment variables can also be deleted using `unset ENV_VAR` in the end of the env file:
      "${RUNTIME_NAME}.env"
      You can also embed environment variables directly into runtime using the --runtime-addenvs option.
```

</details> 

<details><summary style="font-size: 15px;"><b>
AppImage runtime usage
</b></summary>

```
   Runtime options:
    --appimage-extract [PATTERN]          Extract content from embedded filesystem image
                                             If pattern is passed, only extract matching files
     --appimage-extract-and-run [ARGS]    Run the AppImage afer extraction without using FUSE
     --appimage-offset                    Print byte offset to start of embedded filesystem image
     --appimage-portable-home             Create a portable home folder to use as $HOME
     --appimage-portable-share            Create a portable share folder to use as $XDG_DATA_HOME
     --appimage-portable-config           Create a portable config folder to use as $XDG_CONFIG_HOME
     --appimage-portable-cache            Create a portable cache folder to use as $XDG_CACHE_HOME
     --appimage-help                      Print this help
     --appimage-unshare                   Try to use unshare user and mount namespaces
     --appimage-version                   Print version of Runtime
     --appimage-signature                 Print digital signature embedded in AppImage
     --appimage-addsign    'SIGN|/file'   Add digital signature to AppImage
     --appimage-updateinfo[rmation]       Print update info embedded in AppImage
     --appimage-addupdinfo 'INFO|/file'   Add update info to AppImage
     --appimage-envs                      Print environment variables embedded in AppImage
     --appimage-addenvs    'ENVS|/file'   Add environment variables to AppImage
     --appimage-mount                     Mount embedded filesystem image and print
                                             mount point and wait for kill with Ctrl-C

    Embedded tools options:
      --appimage-squashfuse    [ARGS]       Launch squashfuse
      --appimage-unsquashfs    [ARGS]       Launch unsquashfs
      --appimage-sqfscat       [ARGS]       Launch sqfscat
      --appimage-mksquashfs    [ARGS]       Launch mksquashfs
      --appimage-sqfstar       [ARGS]       Launch sqfstar
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
      
      for portable-cache:
      "${RUNTIME_NAME}.cache"

      Or you can invoke this AppImage with the --appimage-portable-home or
      --appimage-portable-share or --appimage-portable-config or
      --appimage-portable-cache option, which will create this directory for you.
      As long as the directory exists and is neither moved nor renamed, the
      application contained inside this AppImage to store its data in this
      directory rather than in your home directory

    Environment variables:

      URUNTIME                       Path to uruntime
      URUNTIME_DIR                   Path to uruntime directory
      APPIMAGE_UNSHARE=1             Try to use unshare user and mount namespaces
      APPIMAGE_UNSHARE_ROOT=1        Map to root (UID 0, GID 0) in user namespace
      APPIMAGE_UNSHARE_UID=0         Map to specified UID in user namespace
      APPIMAGE_UNSHARE_GID=0         Map to specified GID in user namespace
      APPIMAGE_EXTRACT_AND_RUN=1     Run the AppImage afer extraction without using FUSE
      NO_CLEANUP=1                   Do not clear the unpacking directory after closing when
                                       using extract and run option for reuse extracted data
      NO_UNMOUNT=1                   Do not unmount the mount directory after closing 
                                      for reuse mount point
      TMPDIR=/path                   Specifies a custom path for mounting or extracting the image
      APPIMAGE_TARGET_DIR=/path      Specifies the exact path for mounting or extracting the image
      REUSE_CHECK_DELAY=5s           Specifies the delay between checks of using the image dir (0|inf|1|1s|1m|1h)
      FUSERMOUNT_PROG=/path          Specifies a custom path for fusermount
      ENABLE_FUSE_DEBUG=1            Enables debug mode for the mounted filesystem
      TARGET_APPIMAGE=/path          Operate on a target AppImage rather than this file itself
      NO_MEMFDEXEC=1                 Do not use memfd-exec (use a temporary file instead)
      DWARFS_WORKERS=2               Number of worker threads for DwarFS (default: equal CPU threads)
      DWARFS_CACHESIZE=1024M         Size of the block cache, in bytes for DwarFS (suffixes K, M, G)
      DWARFS_BLOCKSIZE=512K          Size of the block file I/O, in bytes for DwarFS (suffixes K, M, G)
      DWARFS_READAHEAD=32M           Set readahead size, in bytes for DwarFS (suffixes K, M, G)
      DWARFS_PRELOAD_ALL=1           Enable preloading of all blocks from the DwarFS file system
      DWARFS_ANALYSIS_FILE=/path     A file for profiling open files when launching the application for DwarFS
      DWARFS_USE_MMAP=1              Use mmap for allocating blocks for DwarFS
      
      Environment variables can be specified in the env file (see https://crates.io/crates/dotenv)
      and environment variables can also be deleted using `unset ENV_VAR` in the end of the env file:
      "${RUNTIME_NAME}.env"
      You can also embed environment variables directly into runtime using the --appimage-addenvs option.
```

</details> 
