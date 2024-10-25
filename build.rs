use std::path::Path;
use std::process::exit;
use std::collections::HashMap;
use std::{env, process::Command};
use std::os::unix::fs::{symlink, PermissionsExt};
use std::fs::{create_dir, metadata, remove_file, set_permissions, write};

use reqwest::blocking::Client;


fn main() {
    let arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap();

    let project = env::var("CARGO_MANIFEST_DIR").unwrap();
    let project_path = Path::new(&project);

    let assets_path = project_path.join(format!("assets-{arch}"));
    let assets_path_link = project_path.join("assets");
    let upx = assets_path.join("upx");

    let mut assets: HashMap<String, String>;
    if arch == "aarch64" {
        assets = HashMap::from([
            (format!("upx"), format!("https://bin.ajam.dev/{arch}_arm64_Linux/upx")),
            (format!("squashfuse"), format!("https://bin.ajam.dev/{arch}_arm64_Linux/squashfuse")),
            (format!("unsquashfs"), format!("https://bin.ajam.dev/{arch}_arm64_Linux/Baseutils/squashfstools/unsquashfs")),
        ]);
    } else {
        assets = HashMap::from([
            (format!("upx"), format!("https://bin.ajam.dev/{arch}_Linux/upx")),
            (format!("squashfuse"), format!("https://bin.ajam.dev/{arch}_Linux/squashfuse")),
            (format!("unsquashfs"), format!("https://bin.ajam.dev/{arch}_Linux/Baseutils/squashfstools/unsquashfs")),
        ]);
    }
    assets.insert(
        format!("dwarfs-universal-upx"), format!("https://github.com/mhx/dwarfs/releases/download/v0.10.1/dwarfs-universal-0.10.1-Linux-{arch}-clang")
    );

    if !assets_path.exists() {
        create_dir(&assets_path).unwrap()
    }

    let _ = remove_file(&assets_path_link);
    symlink(&assets_path, &assets_path_link).unwrap();

    for asset in assets.keys() {
        let asset_path = assets_path.join(asset);
        let asset_upx_path = assets_path.join(format!("{asset}-upx"));

        if !asset_path.exists() {
            let url = assets.get(asset).unwrap();
            let client = Client::builder()
                .danger_accept_invalid_certs(true)
                .timeout(None)
                .user_agent("Mozilla/5.0 (Macintosh; Intel Mac OS X 14_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15")
                .build()
                .unwrap();

            match client.get(url).send() {
                Ok(data) => {
                    write(&asset_path, &data.bytes().unwrap().to_vec())
                        .expect("Failed to write asset: {asset}");

                    let mut permissions = metadata(&asset_path)
                        .expect("Unable to read metadata")
                        .permissions();
                    permissions.set_mode(0o755);
                    set_permissions(&asset_path, permissions)
                        .expect("Unable to set permissions");
                }
                Err(err) => {
                    eprintln!("Failed to get asset: {asset}: {err}");
                    exit(1)
                }
            }
            drop(client)
        }

        if asset_path != upx && !asset_upx_path.exists() {
            println!("upx: {}", upx.display());
            let output = Command::new(&upx).args([
                "--force-overwrite", "-9", "--best", 
                asset_path.to_str().unwrap(), "-o", 
                asset_upx_path.to_str().unwrap()
            ]).output().expect("Failed to execute upx command!");

            if !output.status.success() {
                eprintln!("Error upxing the asset binary: {}", String::from_utf8_lossy(&output.stderr));
            }
        }
    }
}