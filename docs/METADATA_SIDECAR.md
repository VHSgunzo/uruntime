# Metadata SquashFS sidecar

A builder can place a small SquashFS metadata image between the runtime and a
DwarFS application filesystem so SquashFS-only tools, such as thumbnailers and
desktop integration helpers, can read `.DirIcon` and the desktop entry from a
DwarFS AppImage.

## Layout

```text
ELF runtime
metadata SquashFS at the ELF boundary
zero padding
DwarFS payload at the ELF boundary + 128 KiB
```

The slot is exactly **128 KiB**. The metadata image must be a SquashFS 4.0
filesystem whose `bytes_used` superblock field is at most 128 KiB. The bytes
between `bytes_used` and the end of the slot must be zero.

The fixed-size metadata slot gives the builder and runtime a deterministic
DwarFS payload offset and keeps that offset unchanged when the metadata image
size changes.

The application payload is a complete DwarFS image. It is not merged with the
metadata image, and the runtime mounts or extracts it as the real application.
SquashFS AppImages already expose their filesystem to SquashFS tools, so they
do not need this layout.

## Builder requirements

- Write the metadata SquashFS immediately after the ELF runtime.
- Keep the metadata image small enough that `bytes_used <= 128 KiB`.
- Zero-pad the metadata image to exactly 128 KiB so the payload offset stays
  deterministic when the metadata image changes.
- Append a complete DwarFS application image.
- The metadata image should carry `.DirIcon`, the desktop entry, and a stub
  `AppRun` for tools that expect a SquashFS AppImage.

Use a compact original SVG when available. Otherwise optimize or downscale the
PNG used for the preview; the full-size application icon can remain in DwarFS.
Check the finished SquashFS `bytes_used`, including filesystem overhead, and
reject oversized metadata before appending it. Pixel dimensions alone do not
guarantee that the image fits. The runtime does not build or resize the sidecar.

## Offsets

`--appimage-offset`, `APPOFFSET`, and `RUNOFFSET` point at the metadata
SquashFS. This is intentional: SquashFS-only tools can mount the metadata
image at that offset. The runtime itself mounts or extracts the payload at
`offset + 128 KiB`.

## Runtime support

The runtime only skips the metadata image when the build includes the `dwarfs`
feature. Builds without it keep ordinary single-SquashFS behavior at the ELF
boundary.

If the metadata superblock, the zero padding, or the DwarFS payload header do
not validate, the runtime also keeps ordinary single-SquashFS behavior.

## Reuse identity and diagnostics

For a selected sidecar layout, the runtime hashes all metadata SquashFS bytes
up to `bytes_used` with XXH3 and includes the result in the reusable mount and
extraction key, alongside the ELF and sampled application-payload hashes.
Changing metadata therefore invalidates reuse without changing the payload.
Ordinary images have no metadata contribution and retain their existing key
formula. These are noncryptographic cache keys, not integrity checks.

Set `URUNTIME_DEBUG_METADATA=1` to print the metadata and selected payload
offsets to standard error when a sidecar is selected.
