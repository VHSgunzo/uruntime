mod build_support;

use std::{env, path::PathBuf};

use build_support::{
    asset_urls, cache_generation_path, download_atomic, prepare_assets_with, target_spec,
    BuildFeatures,
};

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=build_support.rs");
    println!("cargo:rerun-if-env-changed=TARGET");
    println!("cargo:rerun-if-env-changed=URUNTIME_CURL");

    if let Err(err) = run() {
        panic!("uruntime helper preparation failed: {err}");
    }
}

fn run() -> Result<(), String> {
    build_support::validate_configuration()?;
    let target_name = env::var("TARGET").map_err(|err| format!("TARGET is not set: {err}"))?;
    let target = target_spec(&target_name)?;
    let project = PathBuf::from(
        env::var_os("CARGO_MANIFEST_DIR")
            .ok_or_else(|| "CARGO_MANIFEST_DIR is not set".to_string())?,
    );
    let out_dir =
        PathBuf::from(env::var_os("OUT_DIR").ok_or_else(|| "OUT_DIR is not set".to_string())?);
    let features = BuildFeatures {
        squashfs: cfg!(feature = "squashfs"),
        dwarfs: cfg!(feature = "dwarfs"),
        lite: cfg!(feature = "lite"),
    };
    let assets = asset_urls(target.release_arch, features);
    let cache = project.join(cache_generation_path(target, features));
    let generated = out_dir.join("uruntime-helper-assets");
    let curl = env::var_os("URUNTIME_CURL").unwrap_or_else(|| "curl".into());

    prepare_assets_with(
        &cache,
        &generated,
        target,
        &assets,
        &|asset, destination| download_atomic(&curl, &asset.url, destination),
    )?;

    let generated = generated
        .canonicalize()
        .map_err(|err| format!("failed to canonicalize {}: {err}", generated.display()))?;
    println!(
        "cargo:rustc-env=URUNTIME_HELPER_DIR={}",
        generated.display()
    );
    Ok(())
}
