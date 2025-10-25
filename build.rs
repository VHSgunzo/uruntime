use std::{
    env,
    path::Path,
    process::{exit, Command},
    os::unix::fs::{symlink, PermissionsExt},
    fs::{create_dir, remove_file, set_permissions, Permissions}
};

#[allow(unused_imports)]
use cfg_if::cfg_if;
use indexmap::IndexMap;


#[cfg(feature = "dwarfs")]
const DWARFS_VERSION: &str = "0.14.1";
#[cfg(feature = "squashfs")]
const SQUASHFS_TOOLS_VERSION: &str = "4.7.2";
#[cfg(feature = "squashfs")]
const SQUASHFUSE_VERSION: &str = "0.6.1";


fn main() {
    let arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap();

    let project = env::var("CARGO_MANIFEST_DIR").unwrap();
    let project_path = Path::new(&project);

    let assets_path = project_path.join(format!("assets-{arch}"));
    let assets_path_link = project_path.join("assets");

    let assets = IndexMap::from([
        #[cfg(feature = "squashfs")]
        ("squashfuse", format!("https://github.com/VHSgunzo/squashfuse-static/releases/download/v{SQUASHFUSE_VERSION}/squashfuse-musl-mimalloc-{arch}")),
        #[cfg(feature = "squashfs")]
        ("unsquashfs", format!("https://github.com/VHSgunzo/squashfs-tools-static/releases/download/v{SQUASHFS_TOOLS_VERSION}/unsquashfs-{arch}")),
        #[cfg(all(not(feature = "lite"), feature = "squashfs"))]
        ("mksquashfs", format!("https://github.com/VHSgunzo/squashfs-tools-static/releases/download/v{SQUASHFS_TOOLS_VERSION}/mksquashfs-{arch}")),
        #[cfg(feature = "dwarfs")]
        {
            cfg_if! {
                if #[cfg(feature = "lite")] {
                    ("dwarfs-fuse-extract-upx", format!("https://github.com/mhx/dwarfs/releases/download/v{0}/dwarfs-fuse-extract-{0}-Linux-{arch}.upx", DWARFS_VERSION))
                } else {
                    ("dwarfs-universal-upx", format!("https://github.com/mhx/dwarfs/releases/download/v{0}/dwarfs-universal-{0}-Linux-{arch}.upx", DWARFS_VERSION))
                }
            }
        },
    ]);

    if !assets_path.exists() {
        create_dir(&assets_path).unwrap()
    }

    let _ = remove_file(&assets_path_link);
    symlink(&assets_path, &assets_path_link).unwrap();

    for asset in assets.keys() {
        #[allow(unused_mut)]
        let mut asset = *asset;
        #[allow(unused_mut)]
        let mut asset_path = assets_path.join(asset);
        #[allow(unused_mut)]
        let mut asset_url = assets.get(asset).unwrap().clone();

        #[cfg(feature = "upx")]
        if !asset.ends_with("-upx") {
            asset_path = assets_path.join(format!("{asset}-upx"));
            asset_url = format!("{}-upx", asset_url)
        }

        if !asset_path.exists() {
            let output = Command::new("curl").args([
                "--insecure",
                "-L", &asset_url,
                "-o", asset_path.to_str().unwrap()
            ]).output().unwrap_or_else(|err| panic!("Failed to execute curl: {err}: {asset}"));

            if !output.status.success() {
                eprintln!("Failed to get asset: {}", String::from_utf8_lossy(&output.stderr));
                exit(1)
            }

            set_permissions(&asset_path, Permissions::from_mode(0o755))
                .unwrap_or_else(|err| panic!("Unable to set permissions: {err}: {asset}"));
        }

        #[cfg(not(feature = "upx"))]
        {
            if asset.ends_with("-upx") {
                asset = asset.strip_suffix("-upx").unwrap();
                let asset_noupx_path = assets_path.join(asset);
                if !asset_noupx_path.exists() {
                    let output = Command::new("upx").args([
                        "-d",
                        asset_path.to_str().unwrap(), "-o",
                        asset_noupx_path.to_str().unwrap()
                    ]).output().unwrap_or_else(|err| panic!("Failed to execute upx: {err}"));

                    if !output.status.success() {
                        eprintln!("Failed to decompress upx asset: {asset}: {}", String::from_utf8_lossy(&output.stderr));
                        exit(1)
                    }
                }
                asset_path = asset_noupx_path
            }

            let asset_zstd_path = assets_path.join(format!("{asset}-zst"));
            if !asset_zstd_path.exists() {
                let asset_data = std::fs::read(asset_path).unwrap();
                let asset_zstd_data = zstd::stream::encode_all(&asset_data[..], 22).unwrap();
                std::fs::write(asset_zstd_path, asset_zstd_data).unwrap();
            }
        }
    }
}
