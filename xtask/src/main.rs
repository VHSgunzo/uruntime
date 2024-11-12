use std::{
    env,
    path::{Path, PathBuf},
    io::{Seek, SeekFrom, Write},
    process::{exit, Command, Stdio},
    fs::{create_dir_all, rename, OpenOptions},
};


const BIN_NAME: &str = "uruntime";
const TARGET_X86_64: &str = "x86_64-unknown-linux-musl";
const TARGET_AARCH64: &str = "aarch64-unknown-linux-musl";

type DynError = Box<dyn std::error::Error>;

fn main() {
    if let Err(e) = try_main() {
        eprintln!("{}", e);
        exit(-1);
    }
}

fn try_main() -> Result<(), DynError> {
    let all_bins = vec![
        "runimage-x86_64",
        "runimage-squashfs-x86_64",
        "runimage-dwarfs-x86_64",
        "appimage-x86_64",
        "appimage-squashfs-x86_64",
        "appimage-dwarfs-x86_64",

        "runimage-aarch64",
        "runimage-squashfs-aarch64",
        "runimage-dwarfs-aarch64",
        "appimage-aarch64",
        "appimage-squashfs-aarch64",
        "appimage-dwarfs-aarch64",
    ];
    let arg = env::args().nth(1).unwrap_or_else(||{
        "".into()
    });
    let arg = arg.as_str();

    if all_bins.contains(&arg) {
        build(&arg)?;
        return Ok(())
    }

    match arg {
        "all" => {
            for bin in all_bins {
                build(bin)?
            }
        },
        "x86_64" => {
            for bin in all_bins.iter().filter(|&bin| bin.ends_with("x86_64")) {
                build(bin)?
            }
        },
        "aarch64" => {
            for bin in all_bins.iter().filter(|&bin| bin.ends_with("aarch64")) {
                build(bin)?
            }
        },
        _ => print_help(),
    }
    Ok(())
}

fn create_dist_dir() -> Result<(), DynError> {
    create_dir_all(&dist_dir())?;
    Ok(())
}

fn print_help() {
    eprintln!("Tasks:
    x86_64                     build x86_64 RunImage and AppImage uruntime
    runimage-x86_64            build x86_64 RunImage uruntime
    runimage-squashfs-x86_64   build x86_64 RunImage uruntime (SquashFS only)
    runimage-dwarfs-x86_64     build x86_64 RunImage uruntime (DwarFS only)
    appimage-x86_64            build x86_64 AppImage uruntime
    appimage-squashfs-x86_64   build x86_64 AppImage uruntime (SquashFS only)
    appimage-dwarfs-x86_64     build x86_64 AppImage uruntime (DwarFS only)

    aarch64                     build aarch64 RunImage and AppImage uruntime
    runimage-aarch64            build aarch64 RunImage uruntime
    runimage-squashfs-aarch64   build aarch64 RunImage uruntime (SquashFS only)
    runimage-dwarfs-aarch64     build aarch64 RunImage uruntime (DwarFS only)
    appimage-aarch64            build aarch64 AppImage uruntime
    appimage-squashfs-aarch64   build aarch64 AppImage uruntime (SquashFS only)
    appimage-dwarfs-aarch64     build aarch64 AppImage uruntime (DwarFS only)

    all                         build all of the above")
}

fn strip(path: &PathBuf) -> Result<(), DynError> {
    if Command::new("strip")
        .arg("--version")
        .stdout(Stdio::null())
        .status()
        .is_ok()
    {
        eprint!(" stripping: ");
        let status = Command::new("strip").args([
            "-s", "-R", ".comment", "-R", ".gnu.version",
            "--strip-unneeded"
        ]).arg(&path).status()?;
        if !status.success() {
            Err("strip failed")?;
        }
        eprint!("OK");
    } else {
        eprintln!("no `strip` utility found!")
    }
    Ok(())
}

fn add_magic(path: &PathBuf, magic: &str) -> Result<(), DynError> {
    eprint!(" embed magic: ");
    let magic = format!("{}\x02", magic);
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .open(path)?;
    file.seek(SeekFrom::Start(8))?;
    file.write_all(&magic[..3].as_bytes())?;
    eprint!("OK");
    Ok(())
}

fn build(bin: &str) -> Result<(), DynError> {
    create_dist_dir()?;

    let cargo: &str;
    let target: &str;
    let mut is_strip = true;
    let mut build_args = Vec::new();

    if bin.ends_with("aarch64") {
        cargo = "cross";
        is_strip = false;
        target = TARGET_AARCH64;
        build_args.append(&mut vec![
            "build", "--release",
            "--target", target
        ])
    } else {
        cargo = "cargo";
        target = TARGET_X86_64;
        build_args.append(&mut vec![
            "+nightly", "build", "--release",
            "--target", target,
            "-Z", "unstable-options", "-Z", "build-std=std,panic_abort",
            "-Z", "build-std-features=panic_immediate_abort"
        ])
    }

    let mut magic = "RI";
    if bin.contains("appimage") {
        magic = "AI";
        build_args.append(&mut vec!["--features", "appimage"])
    }
    if bin.contains("squashfs") {
        build_args.append(&mut vec!["--no-default-features", "--features", "squashfs"]);
    } else if bin.contains("dwarfs") {
        build_args.append(&mut vec!["--no-default-features", "--features", "dwarfs"]);
    }

    let status = Command::new(cargo)
        .current_dir(project_root())
        .args(build_args)
        .status()?;

    if !status.success() {
        Err("cargo build failed")?;
    }

    let src = project_root()
        .join("target")
        .join(target)
        .join("release")
        .join(BIN_NAME);

    let dst_bin_name = &format!("{BIN_NAME}-{bin}");
    let dst = dist_dir().join(dst_bin_name);

    rename(&src, &dst)?;
    eprint!("{dst_bin_name}: OK");

    if is_strip {
        strip(&dst)?;
    }

    add_magic(&dst, magic)?;

    eprintln!("");
    Ok(())
}

fn project_root() -> PathBuf {
    Path::new(&env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(1)
        .unwrap()
        .to_path_buf()
}

fn dist_dir() -> PathBuf {
    project_root().join("dist")
}