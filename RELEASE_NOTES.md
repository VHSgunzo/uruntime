## uruntime v0.7.1

### Faster startup

- Eliminated per-launch copies of embedded filesystem helpers; the runtime now uses their static embedded bytes directly.
- Reads and validates the ELF prefix sequentially without zero-filling large buffers or rereading the same ranges.
- Reduced temporary strings, argument cloning, metadata lookups, and permission probes in the startup path.
- Kept exact filesystem magic checks and all malformed-ELF range, endian, and size validation.
- Improved both normal startup and the default reusable-mount path without changing mount or extraction behavior.

### Reproducible cache validation

- Checksum validation and normal builds now consume the same verified local helper-source cache.
- Missing or mismatched helper releases are downloaded atomically; valid cached releases are reused.
- SquashFUSE, squashfs-tools, and DwarFS sources are cached independently by architecture and dependency version.
- The Zig release index, current-host archive, and extracted installation are cached and verified.
- Zig archives and installations are content-addressed by version, host, and full SHA-256 to prevent races between verification and use.

### Validation

- Preserves all six architectures and all nine RunImage/AppImage variants per architecture.
- Covers little-endian and big-endian ELF layouts, exact SquashFS/DwarFS boundaries, unshare option handling, and reusable mount behavior.
