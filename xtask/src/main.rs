use std::{
    env,
    ffi::{OsStr, OsString},
    fs::{self, create_dir_all, File, OpenOptions},
    io::{Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    process::{exit, Command, Stdio},
};

use fs2::FileExt;

#[path = "../../build_support.rs"]
pub mod build_support;
use build_support::{
    CHECKSUM_MANIFEST, ZIG_DOWNLOAD_BASE, ZIG_DOWNLOAD_MAX, ZIG_INDEX_URL, ZIG_PLATFORMS,
    ZIG_VERSION,
};

const BIN_NAME: &str = "uruntime";

fn zig_download_url(platform: &str) -> String {
    format!("{ZIG_DOWNLOAD_BASE}/{ZIG_VERSION}/zig-{platform}-{ZIG_VERSION}.tar.xz")
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ZigPackage {
    version: String,
    platform: String,
    url: String,
    sha256: String,
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn parse_zig_packages(manifest: &str) -> Result<Vec<ZigPackage>, DynError> {
    let mut section = "";
    let mut packages = Vec::new();
    for (index, line) in manifest.lines().enumerate() {
        let line_number = index + 1;
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            section = line;
            continue;
        }
        if section != "[zig]" {
            continue;
        }
        let fields: Vec<&str> = line.split('\t').collect();
        if fields.len() != 4 || !valid_sha256(fields[3]) {
            return Err(format!("invalid Zig checksum record on line {line_number}").into());
        }
        packages.push(ZigPackage {
            version: fields[0].to_string(),
            platform: fields[1].to_string(),
            url: fields[2].to_string(),
            sha256: fields[3].to_string(),
        });
    }
    packages.sort_by(|left, right| left.platform.cmp(&right.platform));
    if packages.len() != ZIG_PLATFORMS.len()
        || packages
            .iter()
            .map(|package| package.platform.as_str())
            .ne(ZIG_PLATFORMS)
    {
        return Err(
            "Zig checksum inventory must contain exactly the five supported Linux hosts".into(),
        );
    }
    let version = packages
        .first()
        .ok_or("Zig checksum inventory is empty")?
        .version
        .clone();
    if packages.iter().any(|package| package.version != version) {
        return Err("Zig checksum inventory mixes multiple versions".into());
    }
    if version != ZIG_VERSION {
        return Err(format!(
            "Zig checksum manifest contains version {version}, but build_support.rs requires {ZIG_VERSION}; run `cargo xtask update-checksums`"
        )
        .into());
    }
    Ok(packages)
}

fn zig_platform(os: &str, arch: &str) -> Option<&'static str> {
    if os != "linux" {
        return None;
    }
    match arch {
        "x86_64" => Some("x86_64-linux"),
        "aarch64" => Some("aarch64-linux"),
        "riscv64" => Some("riscv64-linux"),
        "powerpc64" if cfg!(target_endian = "little") => Some("powerpc64le-linux"),
        "loongarch64" => Some("loongarch64-linux"),
        _ => None,
    }
}

fn zig_packages() -> Result<Vec<ZigPackage>, DynError> {
    parse_zig_packages(CHECKSUM_MANIFEST)
}

fn zig_package(os: &str, arch: &str) -> Result<ZigPackage, DynError> {
    let platform = zig_platform(os, arch).ok_or_else(|| {
        format!(
            "automatic Zig installation is unsupported on {arch}-{os}; set URUNTIME_ZIG to a compatible Zig binary"
        )
    })?;
    zig_packages()?
        .into_iter()
        .find(|package| package.platform == platform)
        .ok_or_else(|| format!("missing Zig checksum for host platform {platform}").into())
}

type DynError = Box<dyn std::error::Error>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Endian {
    Little,
    Big,
}

#[derive(Clone, Copy, Debug)]
struct Arch {
    artifact_name: &'static str,
    rust_target: &'static str,
    zig_target: &'static str,
    endian: Endian,
}

const ARCHES: [Arch; 6] = [
    Arch {
        artifact_name: "x86_64",
        rust_target: "x86_64-unknown-linux-musl",
        zig_target: "x86_64-linux-musl",
        endian: Endian::Little,
    },
    Arch {
        artifact_name: "aarch64",
        rust_target: "aarch64-unknown-linux-musl",
        zig_target: "aarch64-linux-musl",
        endian: Endian::Little,
    },
    Arch {
        artifact_name: "riscv64",
        rust_target: "riscv64gc-unknown-linux-musl",
        zig_target: "riscv64-linux-musl",
        endian: Endian::Little,
    },
    Arch {
        artifact_name: "loongarch64",
        rust_target: "loongarch64-unknown-linux-musl",
        zig_target: "loongarch64-linux-musl",
        endian: Endian::Little,
    },
    Arch {
        artifact_name: "ppc64",
        rust_target: "powerpc64-unknown-linux-musl",
        zig_target: "powerpc64-linux-musl",
        endian: Endian::Big,
    },
    Arch {
        artifact_name: "ppc64le",
        rust_target: "powerpc64le-unknown-linux-musl",
        zig_target: "powerpc64le-linux-musl",
        endian: Endian::Little,
    },
];

#[derive(Clone, Copy, Debug)]
struct Variant {
    name: &'static str,
    description: &'static str,
    no_default_features: bool,
    features: &'static [&'static str],
    magic: [u8; 3],
}

const VARIANTS: [Variant; 9] = [
    Variant {
        name: "runimage",
        description: "RunImage (SquashFS + DwarFS)",
        no_default_features: false,
        features: &[],
        magic: *b"RI\x02",
    },
    Variant {
        name: "runimage-squashfs",
        description: "RunImage (SquashFS-only)",
        no_default_features: true,
        features: &["squashfs"],
        magic: *b"RI\x02",
    },
    Variant {
        name: "runimage-dwarfs",
        description: "RunImage (DwarFS-only)",
        no_default_features: true,
        features: &["dwarfs"],
        magic: *b"RI\x02",
    },
    Variant {
        name: "appimage",
        description: "AppImage (SquashFS + DwarFS)",
        no_default_features: false,
        features: &["appimage"],
        magic: *b"AI\x02",
    },
    Variant {
        name: "appimage-lite",
        description: "AppImage lite (SquashFS + DwarFS)",
        no_default_features: false,
        features: &["appimage", "lite"],
        magic: *b"AI\x02",
    },
    Variant {
        name: "appimage-squashfs",
        description: "AppImage (SquashFS-only)",
        no_default_features: true,
        features: &["appimage", "squashfs"],
        magic: *b"AI\x02",
    },
    Variant {
        name: "appimage-squashfs-lite",
        description: "AppImage lite (SquashFS-only)",
        no_default_features: true,
        features: &["appimage", "squashfs", "lite"],
        magic: *b"AI\x02",
    },
    Variant {
        name: "appimage-dwarfs",
        description: "AppImage (DwarFS-only)",
        no_default_features: true,
        features: &["appimage", "dwarfs"],
        magic: *b"AI\x02",
    },
    Variant {
        name: "appimage-dwarfs-lite",
        description: "AppImage lite (DwarFS-only)",
        no_default_features: true,
        features: &["appimage", "dwarfs", "lite"],
        magic: *b"AI\x02",
    },
];

impl Variant {
    fn features_arg(self) -> Option<String> {
        (!self.features.is_empty()).then(|| self.features.join(","))
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct Task {
    name: String,
    arch_index: usize,
    variant_index: usize,
}

impl Task {
    fn arch(&self) -> &'static Arch {
        &ARCHES[self.arch_index]
    }

    fn variant(&self) -> &'static Variant {
        &VARIANTS[self.variant_index]
    }

    fn output_name(&self) -> String {
        format!("{BIN_NAME}-{}", self.name)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Backend {
    Cargo,
    Zig,
}

impl Backend {
    fn display(self) -> &'static str {
        match self {
            Self::Cargo => "cargo (native linker)",
            Self::Zig => "cargo + Zig 0.16.0",
        }
    }
}

fn arch_by_name(name: &str) -> Option<&'static Arch> {
    ARCHES.iter().find(|arch| arch.artifact_name == name)
}

fn all_tasks() -> Vec<Task> {
    ARCHES
        .iter()
        .enumerate()
        .flat_map(|(arch_index, arch)| {
            VARIANTS
                .iter()
                .enumerate()
                .map(move |(variant_index, variant)| Task {
                    name: format!("{}-{}", variant.name, arch.artifact_name),
                    arch_index,
                    variant_index,
                })
        })
        .collect()
}

fn select_tasks(args: &[&str]) -> Result<Vec<Task>, String> {
    if args.len() != 1 {
        let extra = args.get(1).copied().unwrap_or("<missing task>");
        return Err(format!(
            "unexpected extra argument `{extra}`; pass exactly one task (UPX is not supported)"
        ));
    }

    let tasks = all_tasks();
    if args[0] == "all" {
        Ok(tasks)
    } else if arch_by_name(args[0]).is_some() {
        Ok(tasks
            .into_iter()
            .filter(|task| task.arch().artifact_name == args[0])
            .collect())
    } else if let Some(task) = tasks.into_iter().find(|task| task.name == args[0]) {
        Ok(vec![task])
    } else {
        Err(format!(
            "unknown task `{}`; run `cargo xtask help` to list the 54 valid tasks",
            args[0]
        ))
    }
}

fn cargo_build_args(arch: &Arch, variant: &Variant) -> Vec<String> {
    let mut args = vec![
        "build".into(),
        "--locked".into(),
        "--release".into(),
        "--target".into(),
        arch.rust_target.into(),
    ];
    if variant.no_default_features {
        args.push("--no-default-features".into());
    }
    if let Some(features) = variant.features_arg() {
        args.push("--features".into());
        args.push(features);
    }
    args
}

fn backend_for(arch: &Arch, host_arch: &str) -> Backend {
    if arch.artifact_name == host_arch {
        Backend::Cargo
    } else {
        Backend::Zig
    }
}

fn build_backend() -> Backend {
    Backend::Zig
}

fn host_artifact_arch() -> &'static str {
    match env::consts::ARCH {
        "powerpc64" if cfg!(target_endian = "little") => "ppc64le",
        "powerpc64" => "ppc64",
        other => other,
    }
}

fn default_check_target(os: &str, arch: &str, little_endian: bool) -> Result<&'static str, String> {
    if os != "linux" {
        return Err(format!(
            "cannot infer a default musl target for {arch}-{os}; pass one of the supported Rust targets explicitly"
        ));
    }
    match arch {
        "x86_64" => Ok("x86_64-unknown-linux-musl"),
        "aarch64" => Ok("aarch64-unknown-linux-musl"),
        "riscv64" => Ok("riscv64gc-unknown-linux-musl"),
        "loongarch64" => Ok("loongarch64-unknown-linux-musl"),
        "powerpc64" if little_endian => Ok("powerpc64le-unknown-linux-musl"),
        "powerpc64" => Ok("powerpc64-unknown-linux-musl"),
        _ => Err(format!(
            "cannot infer a supported musl target for host architecture `{arch}`"
        )),
    }
}

fn check_commands(target: &str) -> Vec<Vec<String>> {
    vec![
        vec!["fmt".into(), "--check".into()],
        vec![
            "check".into(),
            "--locked".into(),
            "--workspace".into(),
            "--all-features".into(),
            "--target".into(),
            target.into(),
        ],
        vec![
            "clippy".into(),
            "--locked".into(),
            "--workspace".into(),
            "--all-features".into(),
            "--all-targets".into(),
            "--target".into(),
            target.into(),
            "--".into(),
            "-D".into(),
            "warnings".into(),
        ],
        vec![
            "test".into(),
            "--locked".into(),
            "--workspace".into(),
            "--all-features".into(),
            "--target".into(),
            target.into(),
        ],
        vec![
            "check".into(),
            "--locked".into(),
            "--manifest-path".into(),
            "xtask/Cargo.toml".into(),
        ],
        vec![
            "clippy".into(),
            "--locked".into(),
            "--manifest-path".into(),
            "xtask/Cargo.toml".into(),
            "--all-targets".into(),
            "--".into(),
            "-D".into(),
            "warnings".into(),
        ],
        vec![
            "test".into(),
            "--locked".into(),
            "--manifest-path".into(),
            "xtask/Cargo.toml".into(),
        ],
    ]
}

fn run_status(program: &str, args: &[String]) -> Result<(), DynError> {
    eprintln!("+ {program} {}", args.join(" "));
    let status = Command::new(program)
        .current_dir(project_root())
        .args(args)
        .status()?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("`{program} {}` failed with {status}", args.join(" ")).into())
    }
}

fn qemu_runner_names(arch: &Arch) -> [String; 2] {
    let name = match arch.artifact_name {
        "x86_64" => "qemu-x86_64",
        "aarch64" => "qemu-aarch64",
        "riscv64" => "qemu-riscv64",
        "loongarch64" => "qemu-loongarch64",
        "ppc64" => "qemu-ppc64",
        "ppc64le" => "qemu-ppc64le",
        _ => unreachable!("all check targets come from ARCHES"),
    };
    [name.to_string(), format!("{name}-static")]
}

fn configure_target_runner(command: &mut Command, arch: &Arch) -> Result<(), DynError> {
    let project = project_root();
    let names = qemu_runner_names(arch);
    let runner = names
        .iter()
        .find_map(|name| resolve_program(Path::new(name), &project).ok())
        .ok_or_else(|| {
            format!(
                "foreign tests for {} require `{}` or `{}` in PATH",
                arch.rust_target, names[0], names[1]
            )
        })?;
    command.env(
        target_env_key("CARGO_TARGET", arch.rust_target, "_RUNNER"),
        runner,
    );
    Ok(())
}

fn run_check_command(args: &[String], arch: &Arch, foreign: bool) -> Result<(), DynError> {
    eprintln!("+ cargo {}", args.join(" "));
    let mut command = Command::new("cargo");
    command.current_dir(project_root()).args(args);
    let targets_root_package = args.iter().any(|arg| arg == "--target");
    if foreign && targets_root_package {
        configure_zig(&mut command, arch)?;
        if args.first().is_some_and(|arg| arg == "test") {
            configure_target_runner(&mut command, arch)?;
        }
    }
    let status = command.status()?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("`cargo {}` failed with {status}", args.join(" ")).into())
    }
}

fn run_checks(target: &str) -> Result<(), DynError> {
    let arch = ARCHES
        .iter()
        .find(|arch| arch.rust_target == target)
        .ok_or_else(|| {
            format!(
                "unsupported check target `{target}`; use one of the Rust targets shown by `cargo xtask help`"
            )
        })?;
    let foreign = backend_for(arch, host_artifact_arch()) == Backend::Zig;
    eprintln!("running local checks for Rust target {target}");
    for args in check_commands(target) {
        run_check_command(&args, arch, foreign)?;
    }
    eprintln!("+ cargo xtask update-checksums --check");
    update_checksums(true)?;
    run_status("git", &["diff".into(), "--check".into()])?;
    eprintln!("all local checks passed for {target}");
    Ok(())
}

fn resolve_program(program: &Path, base: &Path) -> Result<PathBuf, DynError> {
    let has_separator = program.components().count() > 1;
    if program.is_absolute() || has_separator {
        let candidate = if program.is_absolute() {
            program.to_path_buf()
        } else {
            base.join(program)
        };
        if candidate.is_file() {
            return Ok(candidate);
        }
        return Err(format!("program not found: {}", candidate.display()).into());
    }

    let path = env::var_os("PATH").ok_or("PATH is not set")?;
    for directory in env::split_paths(&path) {
        let directory = if directory.is_absolute() {
            directory
        } else {
            base.join(directory)
        };
        let candidate = directory.join(program);
        if candidate.is_file() {
            return Ok(candidate);
        }
    }
    Err(format!("program `{}` was not found in PATH", program.display()).into())
}

fn require_tool(path: &Path, display_name: &str) -> Result<(), DynError> {
    if path.is_file() {
        return Ok(());
    }
    Err(format!("required {display_name} not found at {}", path.display()).into())
}

fn zig_version(path: &Path) -> Result<String, DynError> {
    let output = Command::new(path).arg("version").output()?;
    if !output.status.success() {
        return Err(format!("failed to execute `{}` version", path.display()).into());
    }
    Ok(std::str::from_utf8(&output.stdout)?.trim().to_string())
}

fn require_zig_version(path: &Path) -> Result<(), DynError> {
    let version = zig_version(path)?;
    if version != ZIG_VERSION {
        return Err(format!(
            "Zig {ZIG_VERSION} is required for reproducible foreign builds, but `{}` reported `{version}`",
            path.display()
        )
        .into());
    }
    Ok(())
}

fn ensure_zig() -> Result<PathBuf, DynError> {
    if let Some(override_path) = env::var_os("URUNTIME_ZIG") {
        let path = resolve_program(&PathBuf::from(override_path), &env::current_dir()?)?;
        require_zig_version(&path)?;
        return Ok(path);
    }

    let package = zig_package(env::consts::OS, env::consts::ARCH)?;
    let toolchains = project_root().join("target/toolchains");
    create_dir_all(&toolchains)?;
    let install = toolchains.join(format!("zig-{ZIG_VERSION}-{}", package.platform));
    let zig = install.join("zig");
    if zig.is_file() && require_zig_version(&zig).is_ok() {
        return Ok(zig);
    }

    let lock_path = toolchains.join(format!(".zig-{ZIG_VERSION}-{}.lock", package.platform));
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&lock_path)?;
    lock.lock_exclusive()?;
    if zig.is_file() && require_zig_version(&zig).is_ok() {
        return Ok(zig);
    }

    let url = &package.url;
    eprintln!("installing pinned Zig {ZIG_VERSION} from {url}");
    let archive = tempfile::NamedTempFile::new_in(&toolchains)?;
    let archive_output = archive.reopen()?;
    let status = Command::new("curl")
        .args(["--fail", "--location", "--retry", "3", "--max-filesize"])
        .arg(ZIG_DOWNLOAD_MAX.to_string())
        .arg(url)
        .stdout(Stdio::from(archive_output))
        .status()?;
    if !status.success() {
        return Err(format!("failed to download pinned Zig {ZIG_VERSION} from {url}").into());
    }
    archive.as_file().sync_all()?;
    let actual = build_support::sha256_file(archive.path(), ZIG_DOWNLOAD_MAX)
        .map_err(|error| -> DynError { error.into() })?;
    if actual != package.sha256 {
        return Err(format!(
            "SHA-256 mismatch for Zig {ZIG_VERSION}: expected {}, got {actual}",
            package.sha256
        )
        .into());
    }

    let stage = tempfile::Builder::new()
        .prefix(".zig-install-")
        .tempdir_in(&toolchains)?;
    let status = Command::new("tar")
        .args(["-xJf"])
        .arg(archive.path())
        .arg("-C")
        .arg(stage.path())
        .arg("--strip-components=1")
        .status()?;
    if !status.success() {
        return Err(format!("failed to extract pinned Zig {ZIG_VERSION}").into());
    }
    let staged_zig = stage.path().join("zig");
    require_zig_version(&staged_zig)?;
    if install.exists() {
        fs::remove_dir_all(&install)?;
    }
    fs::rename(stage.keep(), &install)?;
    File::open(&toolchains)?.sync_all()?;
    eprintln!("installed Zig {ZIG_VERSION} at {}", zig.display());
    Ok(zig)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ManifestUpdate {
    Updated,
    Unchanged,
}

fn render_helper_section_with<F>(
    sources: &[build_support::AssetSource],
    fetch: &F,
) -> Result<String, DynError>
where
    F: Fn(&build_support::AssetSource) -> Result<Vec<u8>, String>,
{
    let mut rows = Vec::with_capacity(sources.len());
    for source in sources {
        eprintln!(
            "validating {}/{} from {}",
            source.target.release_arch, source.name, source.url
        );
        let bytes = fetch(source).map_err(|error| -> DynError { error.into() })?;
        if bytes.len() > build_support::MAX_DOWNLOAD_SIZE {
            return Err(format!(
                "downloaded {}/{} is {} bytes, exceeding limit {}",
                source.target.release_arch,
                source.name,
                bytes.len(),
                build_support::MAX_DOWNLOAD_SIZE
            )
            .into());
        }
        let source_sha256 = build_support::sha256_hex(&bytes);
        let payload = match source.kind {
            build_support::AssetKind::Direct => bytes,
            build_support::AssetKind::DwarfsWrapper => build_support::extract_dwarfs_wrapper(
                &bytes,
                source.target,
                build_support::MAX_HELPER_SIZE,
            )
            .map_err(|error| -> DynError { error.into() })?,
        };
        build_support::validate_elf(&payload, source.target, source.elf_type)
            .map_err(|error| -> DynError { error.into() })?;
        rows.push((
            source.target.release_arch,
            source.name,
            source_sha256,
            build_support::sha256_hex(&payload),
        ));
    }
    rows.sort_by(|left, right| (left.0, left.1).cmp(&(right.0, right.1)));
    if rows
        .windows(2)
        .any(|pair| (pair[0].0, pair[0].1) == (pair[1].0, pair[1].1))
    {
        return Err("duplicate helper source inventory entry".into());
    }
    let mut section = String::from("[helpers]\n# arch\tname\tsource_sha256\tpayload_sha256\n");
    for (arch, name, source_sha256, payload_sha256) in rows {
        section.push_str(&format!(
            "{arch}\t{name}\t{source_sha256}\t{payload_sha256}\n"
        ));
    }
    Ok(section)
}

fn render_zig_section(index: &[u8]) -> Result<String, DynError> {
    let root: serde_json::Value = serde_json::from_slice(index)?;
    let release = root
        .get(ZIG_VERSION)
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| format!("Zig {ZIG_VERSION} is absent from {ZIG_INDEX_URL}"))?;
    let mut section = String::from("[zig]\n# version\tplatform\turl\tsha256\n");
    for platform in ZIG_PLATFORMS {
        let package = release
            .get(platform)
            .and_then(serde_json::Value::as_object)
            .ok_or_else(|| format!("Zig {ZIG_VERSION} has no {platform} package"))?;
        let url = package
            .get("tarball")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| format!("Zig {ZIG_VERSION} {platform} has no tarball URL"))?;
        let sha256 = package
            .get("shasum")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| format!("Zig {ZIG_VERSION} {platform} has no SHA-256"))?;
        let expected_url = zig_download_url(platform);
        if url != expected_url || !valid_sha256(sha256) {
            return Err(format!("invalid Zig {ZIG_VERSION} metadata for {platform}").into());
        }
        section.push_str(&format!("{ZIG_VERSION}\t{platform}\t{url}\t{sha256}\n"));
    }
    Ok(section)
}

fn render_checksum_manifest_with<F>(
    sources: &[build_support::AssetSource],
    fetch: &F,
    zig_index: &[u8],
) -> Result<String, DynError>
where
    F: Fn(&build_support::AssetSource) -> Result<Vec<u8>, String>,
{
    Ok(format!(
        "# uruntime checksum manifest v1\n\n{}\n{}",
        render_helper_section_with(sources, fetch)?,
        render_zig_section(zig_index)?
    ))
}

fn update_checksum_manifest_with<F>(
    manifest_path: &Path,
    check: bool,
    sources: &[build_support::AssetSource],
    fetch: &F,
    zig_index: &[u8],
) -> Result<ManifestUpdate, DynError>
where
    F: Fn(&build_support::AssetSource) -> Result<Vec<u8>, String>,
{
    let generated = render_checksum_manifest_with(sources, fetch, zig_index)?;
    let current = match fs::read(manifest_path) {
        Ok(current) => current,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(error) => {
            return Err(format!(
                "failed to read checksum manifest {}: {error}",
                manifest_path.display()
            )
            .into())
        }
    };
    if current == generated.as_bytes() {
        return Ok(ManifestUpdate::Unchanged);
    }
    if check {
        return Err(format!(
            "checksum manifest drift detected at {}; rerun `cargo xtask update-checksums` and review the diff",
            manifest_path.display()
        )
        .into());
    }
    build_support::atomic_write(manifest_path, generated.as_bytes())
        .map_err(|error| -> DynError { error.into() })?;
    Ok(ManifestUpdate::Updated)
}

fn update_checksums(check: bool) -> Result<(), DynError> {
    let temporary = tempfile::tempdir()?;
    let curl = env::var_os("URUNTIME_CURL").unwrap_or_else(|| "curl".into());
    let fetch = |source: &build_support::AssetSource| -> Result<Vec<u8>, String> {
        let destination = temporary
            .path()
            .join(format!("{}-{}", source.target.release_arch, source.name));
        build_support::download_atomic(&curl, &source.url, &destination)?;
        fs::read(&destination)
            .map_err(|error| format!("failed to read {}: {error}", destination.display()))
    };
    let zig_index_path = temporary.path().join("zig-index.json");
    build_support::download_atomic(&curl, ZIG_INDEX_URL, &zig_index_path)
        .map_err(|error| -> DynError { error.into() })?;
    let zig_index = fs::read(&zig_index_path)?;
    let manifest_path = project_root().join("checksums.txt");
    match update_checksum_manifest_with(
        &manifest_path,
        check,
        &build_support::all_asset_sources(),
        &fetch,
        &zig_index,
    )? {
        ManifestUpdate::Updated => eprintln!("updated {}", manifest_path.display()),
        ManifestUpdate::Unchanged => eprintln!("{} is current", manifest_path.display()),
    }
    Ok(())
}

fn main() {
    if let Err(error) = try_main() {
        eprintln!("error: {error}");
        exit(1);
    }
}

fn try_main() -> Result<(), DynError> {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.is_empty() || (args.len() == 1 && matches!(args[0].as_str(), "help" | "-h" | "--help"))
    {
        eprint!("{}", help_text());
        return Ok(());
    }

    if args.first().map(String::as_str) == Some("check") {
        let target = match args.as_slice() {
            [_] => default_check_target(
                env::consts::OS,
                env::consts::ARCH,
                cfg!(target_endian = "little"),
            )
            .map_err(|error| -> DynError { error.into() })?,
            [_, target] => ARCHES
                .iter()
                .find(|arch| arch.rust_target == target)
                .map(|arch| arch.rust_target)
                .ok_or_else(|| format!("unsupported check target `{target}`"))?,
            _ => return Err("usage: cargo xtask check [RUST_TARGET]".into()),
        };
        return run_checks(target);
    }

    if args.first().map(String::as_str) == Some("update-checksums") {
        return match args.as_slice() {
            [_] => update_checksums(false),
            [_, flag] if flag == "--check" => update_checksums(true),
            _ => Err("usage: cargo xtask update-checksums [--check]"
                .to_string()
                .into()),
        };
    }

    let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
    for task in select_tasks(&arg_refs).map_err(|error| -> DynError { error.into() })? {
        build(&task)?;
    }
    Ok(())
}

fn help_text() -> String {
    let mut text = String::from(
        "Usage:\n  cargo xtask <task|architecture|all>\n  cargo xtask check [RUST_TARGET]\n  cargo xtask update-checksums [--check]\n\nArchitectures:\n",
    );
    for arch in ARCHES {
        text.push_str(&format!(
            "  {:12} {} ({:?}-endian)\n",
            arch.artifact_name, arch.rust_target, arch.endian
        ));
    }
    text.push_str(&format!("\nTasks ({}):\n", ARCHES.len() * VARIANTS.len()));
    for task in all_tasks() {
        text.push_str(&format!(
            "  {:38} {}\n",
            task.name,
            task.variant().description
        ));
    }
    text.push_str("\n  all                                    build all 54 tasks\n");
    text
}

fn create_dist_dir() -> Result<(), DynError> {
    create_dir_all(dist_dir())?;
    Ok(())
}

fn add_sections(path: &Path, section_root: &Path, objcopy: &OsStr) -> Result<(), DynError> {
    let mut section_files = section_root.read_dir()?.collect::<Result<Vec<_>, _>>()?;
    section_files.sort_by_key(|entry| entry.file_name());

    let mut args = Vec::<OsString>::new();
    for entry in section_files {
        let section_file = entry.path();
        if !section_file.is_file() {
            continue;
        }
        let filename = section_file
            .file_name()
            .and_then(OsStr::to_str)
            .ok_or("section filenames must be valid UTF-8")?;
        let section_path = section_file
            .to_str()
            .ok_or("section paths must be valid UTF-8 for llvm-objcopy")?;
        let section_name = format!(".{filename}");
        args.push(format!("--add-section={section_name}={section_path}").into());
        args.push(format!("--set-section-flags={section_name}=noload,readonly").into());
    }
    args.push(path.as_os_str().to_owned());

    let status = Command::new(objcopy).args(args).status()?;
    if !status.success() {
        return Err("llvm-objcopy failed to add runtime sections".into());
    }
    Ok(())
}

fn add_magic(path: &Path, magic: [u8; 3]) -> Result<(), DynError> {
    let mut file = OpenOptions::new().write(true).open(path)?;
    file.seek(SeekFrom::Start(8))?;
    file.write_all(&magic)?;
    file.sync_all()?;
    Ok(())
}

fn publish_artifact(
    src: &Path,
    dst: &Path,
    section_root: &Path,
    magic: [u8; 3],
) -> Result<(), DynError> {
    let parent = dst.parent().ok_or("artifact output has no parent")?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    let mut source = File::open(src)?;
    std::io::copy(&mut source, temporary.as_file_mut())?;
    temporary
        .as_file_mut()
        .set_permissions(source.metadata()?.permissions())?;
    temporary.as_file_mut().sync_all()?;
    add_sections(temporary.path(), section_root, OsStr::new("llvm-objcopy"))?;
    add_magic(temporary.path(), magic)?;
    temporary.as_file().sync_all()?;
    temporary.persist(dst)?;
    File::open(parent)?.sync_all()?;
    Ok(())
}

fn target_env_key(prefix: &str, target: &str, suffix: &str) -> String {
    format!(
        "{prefix}_{}{suffix}",
        target.replace('-', "_").to_ascii_uppercase()
    )
}

fn query_rust_sysroot(project: &Path, compiler: &OsStr) -> Result<String, DynError> {
    let compiler = resolve_program(Path::new(compiler), project)?;
    let output = Command::new(&compiler)
        .current_dir(project)
        .args(["--print", "sysroot"])
        .output()?;
    if !output.status.success() {
        return Err(format!(
            "failed to determine the active Rust sysroot with {}",
            compiler.display()
        )
        .into());
    }
    Ok(std::str::from_utf8(&output.stdout)?.trim().to_string())
}

fn configure_zig(command: &mut Command, arch: &Arch) -> Result<(), DynError> {
    let zig = ensure_zig()?;
    let project = project_root();
    let wrapper = project.join("scripts/zig-linker.sh");
    require_tool(&wrapper, "project Zig linker wrapper")?;
    let rustc = env::var_os("RUSTC").unwrap_or_else(|| "rustc".into());
    let rust_sysroot = query_rust_sysroot(&project, &rustc)?;
    command
        .env(
            target_env_key("CARGO_TARGET", arch.rust_target, "_LINKER"),
            &wrapper,
        )
        .env(
            target_env_key("CARGO_TARGET", arch.rust_target, "_RUSTFLAGS"),
            "-Ctarget-feature=+crt-static -Clink-self-contained=no",
        )
        .env(
            format!("CC_{}", arch.rust_target.replace('-', "_")),
            &wrapper,
        )
        .env("URUNTIME_RUST_TARGET", arch.rust_target)
        .env("URUNTIME_ZIG_TARGET", arch.zig_target)
        .env("URUNTIME_RUST_SYSROOT", rust_sysroot)
        .env("URUNTIME_ZIG", zig);
    Ok(())
}

fn build(task: &Task) -> Result<(), DynError> {
    create_dist_dir()?;
    let backend = build_backend();
    eprintln!(
        "building {}: artifact arch={}, Rust target={}, backend={}",
        task.name,
        task.arch().artifact_name,
        task.arch().rust_target,
        backend.display()
    );

    let mut command = Command::new("cargo");
    command
        .current_dir(project_root())
        .args(cargo_build_args(task.arch(), task.variant()));
    configure_zig(&mut command, task.arch())?;
    let status = command.status()?;
    if !status.success() {
        return Err(format!("cargo build failed for {}", task.name).into());
    }

    let src = project_root()
        .join("target")
        .join(task.arch().rust_target)
        .join("release")
        .join(BIN_NAME);
    let dst_name = task.output_name();
    let dst = dist_dir().join(&dst_name);
    publish_artifact(&src, &dst, &sections_dir(), task.variant().magic)?;
    eprintln!("{dst_name}: OK");
    Ok(())
}

fn project_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask must be directly below the project root")
        .to_path_buf()
}

fn dist_dir() -> PathBuf {
    project_root().join("dist")
}

fn sections_dir() -> PathBuf {
    project_root().join("sections")
}

#[cfg(test)]
mod tests;
