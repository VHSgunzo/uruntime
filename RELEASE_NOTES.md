## uruntime v0.8.3

- Add metadata SquashFS sidecars so DwarFS AppImages expose icons and desktop entries to SquashFS-only tools (#29).
- Invalidate reusable targets when sidecar metadata changes.

The new layout uses a fixed 128 KiB metadata slot. Existing single-image layouts remain supported. See the [builder requirements](https://github.com/VHSgunzo/uruntime/blob/v0.8.3/docs/METADATA_SIDECAR.md).

[Full changelog](https://github.com/VHSgunzo/uruntime/blob/v0.8.3/CHANGELOG.md).
