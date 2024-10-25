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

# for RunImage x86_64
cargo +nightly build --release --target x86_64-unknown-linux-musl -Z unstable-options -Z build-std=std,panic_abort -Z build-std-features=panic_immediate_abort
mv target/x86_64-unknown-linux-musl/release/uruntime uruntime-runimage-x86_64
echo -ne 'RI\x02'|dd of=uruntime-runimage-x86_64 bs=1 count=3 seek=8 conv=notrunc

# for AppImage x86_64
cargo +nightly build --release --target x86_64-unknown-linux-musl -Z unstable-options -Z build-std=std,panic_abort -Z build-std-features=panic_immediate_abort --features appimage
mv target/x86_64-unknown-linux-musl/release/uruntime uruntime-appimage-x86_64
echo -ne 'AI\x02'|dd of=uruntime-appimage-x86_64 bs=1 count=3 seek=8 conv=notrunc
```
See [Build step in ci.yml](https://github.com/VHSgunzo/uruntime/blob/main/.github/workflows/ci.yml#L34)

* Or take an already precompiled from the [releases](https://github.com/VHSgunzo/uruntime/releases)
