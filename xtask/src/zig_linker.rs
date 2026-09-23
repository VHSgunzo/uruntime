use std::env;
use std::ffi::{OsStr, OsString};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{self, Command};

fn target_mapping(rust_target: &str) -> Option<&'static str> {
    match rust_target {
        "x86_64-unknown-linux-musl" => Some("x86_64-linux-musl"),
        "aarch64-unknown-linux-musl" => Some("aarch64-linux-musl"),
        "riscv64gc-unknown-linux-musl" => Some("riscv64-linux-musl"),
        "loongarch64-unknown-linux-musl" => Some("loongarch64-linux-musl"),
        "powerpc64-unknown-linux-musl" => Some("powerpc64-linux-musl"),
        "powerpc64le-unknown-linux-musl" => Some("powerpc64le-linux-musl"),
        _ => None,
    }
}

fn crt_objects(directory: &Path) -> [PathBuf; 9] {
    [
        "crt1.o",
        "Scrt1.o",
        "rcrt1.o",
        "crti.o",
        "crtn.o",
        "crtbegin.o",
        "crtbeginS.o",
        "crtend.o",
        "crtendS.o",
    ]
    .map(|name| directory.join(name))
}

fn filter_arguments(
    arguments: impl IntoIterator<Item = OsString>,
    rust_target: &str,
    sysroot: &Path,
) -> Vec<OsString> {
    let rust_crt = sysroot
        .join("lib/rustlib")
        .join(rust_target)
        .join("lib/self-contained");
    let rust_target_lib = sysroot.join("lib/rustlib").join(rust_target).join("lib");
    let crt_objects = crt_objects(&rust_crt);
    let mut filtered = Vec::new();
    let mut skip_target_value = false;
    let mut pending_library_directory = false;
    for argument in arguments {
        if skip_target_value {
            skip_target_value = false;
            continue;
        }
        if pending_library_directory {
            pending_library_directory = false;
            if Path::new(&argument) == rust_target_lib && !rust_target_lib.is_dir() {
                continue;
            }
            filtered.push("-L".into());
            filtered.push(argument);
            continue;
        }
        let text = argument.to_string_lossy();
        if matches!(text.as_ref(), "--target" | "-target") {
            skip_target_value = true;
        } else if text.starts_with("--target=") || text.starts_with("-target=") {
        } else if text == "-L" {
            pending_library_directory = true;
        } else if text == format!("-L{}", rust_target_lib.display()) && !rust_target_lib.is_dir() {
        } else if matches!(
            text.as_ref(),
            "-Wl,--fix-cortex-a53-843419" | "-nostartfiles" | "-lc"
        ) {
        } else if rust_target == "loongarch64-unknown-linux-musl"
            && text == "-Wl,--no-rosegment"
        {
        } else if crt_objects.iter().any(|path| path.as_os_str() == argument) {
        } else {
            filtered.push(argument);
        }
    }
    if pending_library_directory {
        filtered.push("-L".into());
    }
    filtered
}

fn required_env(name: &str) -> Result<OsString, String> {
    env::var_os(name).ok_or_else(|| format!("zig-linker: {name} is required"))
}

fn run() -> Result<std::io::Error, String> {
    let rust_target = required_env("URUNTIME_RUST_TARGET")?;
    let rust_target_text = rust_target
        .to_str()
        .ok_or("zig-linker: URUNTIME_RUST_TARGET is not valid UTF-8")?;
    let zig_target = required_env("URUNTIME_ZIG_TARGET")?;
    let zig_target_text = zig_target
        .to_str()
        .ok_or("zig-linker: URUNTIME_ZIG_TARGET is not valid UTF-8")?;
    let expected = target_mapping(rust_target_text)
        .ok_or_else(|| format!("zig-linker: unsupported Rust target: {rust_target_text}"))?;
    if zig_target_text != expected {
        return Err(format!(
            "zig-linker: target mismatch: Rust {rust_target_text} maps to Zig {expected}, not {zig_target_text}"
        ));
    }
    let sysroot = PathBuf::from(required_env("URUNTIME_RUST_SYSROOT")?);
    let zig = env::var_os("URUNTIME_ZIG").unwrap_or_else(|| "zig".into());
    let arguments = filter_arguments(env::args_os().skip(1), rust_target_text, &sysroot);
    Ok(Command::new(zig)
        .args([
            OsStr::new("cc"),
            OsStr::new("-target"),
            zig_target.as_os_str(),
        ])
        .args(arguments)
        .exec())
}

fn main() {
    match run() {
        Ok(error) => {
            eprintln!("zig-linker: failed to execute Zig: {error}");
            process::exit(127);
        }
        Err(error) => {
            eprintln!("{error}");
            process::exit(2);
        }
    }
}
