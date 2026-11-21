## uruntime v0.8.5

- Fix invocation-name preservation when FUSE is unavailable or mounting requires an internal retry ([#30](https://github.com/VHSgunzo/uruntime/issues/30)). AppImage `ARGV0` and RunImage `ARG0` keep the original launch name, including symlinks, instead of changing to the resolved image path.

No runtime configuration or image layout changes are required. Rebuild existing images with the updated runtime to include the fix.

[Full changelog](https://github.com/VHSgunzo/uruntime/blob/v0.8.5/CHANGELOG.md).
