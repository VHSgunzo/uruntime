## uruntime v0.8.2

- Recover startup after interrupted mount-record publication: automatic persistent mounts select a fresh target without trusting temporary PID files or unmounting the existing target (#28).
- Fix helper-execution aborts without `/proc` and after failed exec through memfd-exec 0.2.7.
- Update bundled DwarFS to 0.15.8 and squashfuse to 0.6.5; refresh Rust dependencies. mimalloc remains 2.1.7.
- Restore QEMU smoke checks for every foreign release variant.

No configuration changes are required. Explicit targets and malformed published PID records retain strict validation.

See the [full changelog](https://github.com/VHSgunzo/uruntime/blob/v0.8.2/CHANGELOG.md) and [application lifecycle reference](https://github.com/VHSgunzo/uruntime/blob/v0.8.2/docs/APPLICATION_LIFECYCLE.md).
