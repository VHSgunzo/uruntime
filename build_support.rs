use std::{
    ffi::{OsStr, OsString},
    fmt,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use fs2::FileExt;
use sha2::{Digest, Sha256};
use tempfile::{Builder as TempBuilder, NamedTempFile};
use xxhash_rust::xxh64::xxh64;

pub const DWARFS_VERSION: &str = "0.15.7";

pub const SQUASHFS_TOOLS_VERSION: &str = "4.7.5.r2";
pub const SQUASHFUSE_VERSION: &str = "0.6.3.r2";
pub const ZIG_VERSION: &str = "0.16.0";
pub const ZIG_INDEX_URL: &str = "https://ziglang.org/download/index.json";
pub const ZIG_DOWNLOAD_BASE: &str = "https://ziglang.org/download";
pub const ZIG_DOWNLOAD_MAX: usize = 64 * 1024 * 1024;
pub const ZIG_PLATFORMS: [&str; 5] = [
    "aarch64-linux",
    "loongarch64-linux",
    "powerpc64le-linux",
    "riscv64-linux",
    "x86_64-linux",
];
pub const CHECKSUM_MANIFEST: &str = include_str!("checksums.txt");

// Largest v0.15.7 wrapper: 2,965,645 bytes; largest r2 direct helper:
// 1,264,416 bytes. Eight MiB leaves >2.8x margin while bounding downloads/cache reads.
pub const MAX_DOWNLOAD_SIZE: usize = 8 * 1024 * 1024;
// Largest extracted v0.15.7 helper: 8,766,832 bytes. Sixteen MiB leaves >1.9x margin.
pub const MAX_HELPER_SIZE: usize = 16 * 1024 * 1024;
const LOCK_TIMEOUT: Duration = Duration::from_secs(120);
const LOCK_RETRY: Duration = Duration::from_millis(25);
const SQUEEZE_TRAILER_LEN: usize = 32;
const SQUEEZE_MAGIC: &[u8; 8] = b"SQUEEZE!";

pub fn validate_configuration() -> Result<(), String> {
    for (name, version) in [
        ("DwarFS", DWARFS_VERSION),
        ("squashfs-tools", SQUASHFS_TOOLS_VERSION),
        ("squashfuse", SQUASHFUSE_VERSION),
        ("Zig", ZIG_VERSION),
    ] {
        if version.is_empty() {
            return Err(format!("{name} version must not be empty"));
        }
    }
    if !ZIG_INDEX_URL.starts_with("https://ziglang.org/")
        || !ZIG_DOWNLOAD_BASE.starts_with("https://ziglang.org/")
    {
        return Err("Zig index URL must use HTTPS on ziglang.org".into());
    }
    if ZIG_DOWNLOAD_MAX < MAX_DOWNLOAD_SIZE || ZIG_PLATFORMS.is_empty() {
        return Err("invalid Zig download limits or platform inventory".into());
    }
    if !CHECKSUM_MANIFEST.contains("[helpers]") || !CHECKSUM_MANIFEST.contains("[zig]") {
        return Err("checksums.txt must contain helpers and Zig sections".into());
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ElfEndian {
    Little,
    Big,
}

impl fmt::Display for ElfEndian {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Little => f.write_str("little-endian"),
            Self::Big => f.write_str("big-endian"),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TargetSpec {
    pub release_arch: &'static str,
    pub endian: ElfEndian,
    pub elf_machine: u16,
}

pub fn target_spec(target: &str) -> Result<TargetSpec, String> {
    let spec = match target {
        "x86_64-unknown-linux-musl" => TargetSpec {
            release_arch: "x86_64",
            endian: ElfEndian::Little,
            elf_machine: 62,
        },
        "aarch64-unknown-linux-musl" => TargetSpec {
            release_arch: "aarch64",
            endian: ElfEndian::Little,
            elf_machine: 183,
        },
        "riscv64gc-unknown-linux-musl" => TargetSpec {
            release_arch: "riscv64",
            endian: ElfEndian::Little,
            elf_machine: 243,
        },
        "loongarch64-unknown-linux-musl" => TargetSpec {
            release_arch: "loongarch64",
            endian: ElfEndian::Little,
            elf_machine: 258,
        },
        "powerpc64-unknown-linux-musl" => TargetSpec {
            release_arch: "ppc64",
            endian: ElfEndian::Big,
            elf_machine: 21,
        },
        "powerpc64le-unknown-linux-musl" => TargetSpec {
            release_arch: "ppc64le",
            endian: ElfEndian::Little,
            elf_machine: 21,
        },
        _ => {
            return Err(format!(
                "unsupported TARGET `{target}`; supported targets: \
                 x86_64-unknown-linux-musl, aarch64-unknown-linux-musl, \
                 riscv64gc-unknown-linux-musl, loongarch64-unknown-linux-musl, \
                 powerpc64-unknown-linux-musl, powerpc64le-unknown-linux-musl"
            ));
        }
    };
    Ok(spec)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BuildFeatures {
    pub squashfs: bool,
    pub dwarfs: bool,
    pub lite: bool,
}

impl BuildFeatures {
    pub fn cache_key(self) -> String {
        format!(
            "squashfs-{}_dwarfs-{}_lite-{}",
            u8::from(self.squashfs),
            u8::from(self.dwarfs),
            u8::from(self.lite)
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AssetKind {
    Direct,
    DwarfsWrapper,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ElfType {
    /// squashfs-tools-static/squashfuse-static r2 files are static PIE (ET_DYN).
    StaticPie,
    /// DwarFS v0.15.7 wrapper payloads are static ET_EXEC files.
    StaticExec,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Asset {
    pub name: &'static str,
    pub url: String,
    pub kind: AssetKind,
    pub source_sha256: String,
    pub payload_sha256: String,
    pub elf_type: ElfType,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DigestRecord {
    pub arch: String,
    pub name: String,
    pub source_sha256: String,
    pub payload_sha256: String,
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

pub fn parse_digest_manifest(manifest: &str) -> Result<Vec<DigestRecord>, String> {
    let mut records = Vec::new();
    let mut section = "[helpers]";
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
        if section != "[helpers]" {
            continue;
        }
        let fields: Vec<&str> = line.split('\t').collect();
        if fields.len() != 4 {
            return Err(format!(
                "checksum manifest line {line_number} has {} fields, expected 4 tab-separated fields",
                fields.len()
            ));
        }
        if !valid_sha256(fields[2]) || !valid_sha256(fields[3]) {
            return Err(format!(
                "checksum manifest line {line_number} contains an invalid SHA-256"
            ));
        }
        records.push(DigestRecord {
            arch: fields[0].to_string(),
            name: fields[1].to_string(),
            source_sha256: fields[2].to_ascii_lowercase(),
            payload_sha256: fields[3].to_ascii_lowercase(),
        });
    }
    records.sort_by(|left, right| (&left.arch, &left.name).cmp(&(&right.arch, &right.name)));
    for pair in records.windows(2) {
        if pair[0].arch == pair[1].arch && pair[0].name == pair[1].name {
            return Err(format!(
                "duplicate checksum manifest entry for {}/{}",
                pair[0].arch, pair[0].name
            ));
        }
    }
    Ok(records)
}

pub fn digest_records() -> Result<Vec<DigestRecord>, String> {
    parse_digest_manifest(CHECKSUM_MANIFEST)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AssetSource {
    pub target: TargetSpec,
    pub name: &'static str,
    pub url: String,
    pub kind: AssetKind,
    pub elf_type: ElfType,
}

pub fn all_asset_sources() -> Vec<AssetSource> {
    const TARGETS: [&str; 6] = [
        "x86_64-unknown-linux-musl",
        "aarch64-unknown-linux-musl",
        "riscv64gc-unknown-linux-musl",
        "loongarch64-unknown-linux-musl",
        "powerpc64-unknown-linux-musl",
        "powerpc64le-unknown-linux-musl",
    ];
    let mut sources = Vec::with_capacity(30);
    for target_name in TARGETS {
        let target = target_spec(target_name).expect("static target table must be valid");
        let arch = target.release_arch;
        sources.extend([
            AssetSource {
                target,
                name: "squashfuse",
                url: format!("https://github.com/VHSgunzo/squashfuse-static/releases/download/v{SQUASHFUSE_VERSION}/squashfuse-musl-mimalloc-{arch}"),
                kind: AssetKind::Direct,
                elf_type: ElfType::StaticPie,
            },
            AssetSource {
                target,
                name: "unsquashfs",
                url: format!("https://github.com/VHSgunzo/squashfs-tools-static/releases/download/v{SQUASHFS_TOOLS_VERSION}/unsquashfs-{arch}"),
                kind: AssetKind::Direct,
                elf_type: ElfType::StaticPie,
            },
            AssetSource {
                target,
                name: "mksquashfs",
                url: format!("https://github.com/VHSgunzo/squashfs-tools-static/releases/download/v{SQUASHFS_TOOLS_VERSION}/mksquashfs-{arch}"),
                kind: AssetKind::Direct,
                elf_type: ElfType::StaticPie,
            },
            AssetSource {
                target,
                name: "dwarfs-universal",
                url: format!("https://github.com/mhx/dwarfs/releases/download/v{DWARFS_VERSION}/dwarfs-universal-{DWARFS_VERSION}-Linux-{arch}"),
                kind: AssetKind::DwarfsWrapper,
                elf_type: ElfType::StaticExec,
            },
            AssetSource {
                target,
                name: "dwarfs-fuse-extract",
                url: format!("https://github.com/mhx/dwarfs/releases/download/v{DWARFS_VERSION}/dwarfs-fuse-extract-{DWARFS_VERSION}-Linux-{arch}"),
                kind: AssetKind::DwarfsWrapper,
                elf_type: ElfType::StaticExec,
            },
        ]);
    }
    sources.sort_by(|left, right| {
        (left.target.release_arch, left.name).cmp(&(right.target.release_arch, right.name))
    });
    sources
}

fn asset(source: &AssetSource) -> Asset {
    let release_arch = source.target.release_arch;
    let name = source.name;
    let records = digest_records().unwrap_or_else(|error| panic!("invalid checksums.txt: {error}"));
    let digest = records
        .iter()
        .find(|record| record.arch == release_arch && record.name == name)
        .unwrap_or_else(|| panic!("missing digest manifest entry for {release_arch}/{name}"));
    Asset {
        name,
        url: source.url.clone(),
        kind: source.kind,
        source_sha256: digest.source_sha256.clone(),
        payload_sha256: digest.payload_sha256.clone(),
        elf_type: source.elf_type,
    }
}

pub fn asset_urls(release_arch: &str, features: BuildFeatures) -> Vec<Asset> {
    let sources = all_asset_sources();
    let find = |name| {
        sources
            .iter()
            .find(|source| source.target.release_arch == release_arch && source.name == name)
            .unwrap_or_else(|| {
                panic!("missing helper source inventory entry for {release_arch}/{name}")
            })
    };
    let mut names = Vec::new();
    if features.squashfs {
        names.extend(["squashfuse", "unsquashfs"]);
        if !features.lite {
            names.push("mksquashfs");
        }
    }
    if features.dwarfs {
        names.push(if features.lite {
            "dwarfs-fuse-extract"
        } else {
            "dwarfs-universal"
        });
    }
    names.into_iter().map(|name| asset(find(name))).collect()
}

pub fn cache_version(squashfuse: &str, squashfs_tools: &str, dwarfs: &str) -> String {
    format!("squashfuse-{squashfuse}_squashfs-tools-{squashfs_tools}_dwarfs-{dwarfs}")
}

pub fn current_cache_version() -> String {
    cache_version(SQUASHFUSE_VERSION, SQUASHFS_TOOLS_VERSION, DWARFS_VERSION)
}

pub fn cache_relative_path(target: TargetSpec) -> PathBuf {
    PathBuf::from(format!("assets-{}", target.release_arch)).join(current_cache_version())
}

pub fn cache_generation_path(target: TargetSpec, features: BuildFeatures) -> PathBuf {
    cache_relative_path(target).join(features.cache_key())
}

fn checked_range(
    offset: u64,
    size: u64,
    length: usize,
    what: &str,
) -> Result<std::ops::Range<usize>, String> {
    let offset =
        usize::try_from(offset).map_err(|_| format!("{what} offset does not fit usize"))?;
    let size = usize::try_from(size).map_err(|_| format!("{what} size does not fit usize"))?;
    let end = offset
        .checked_add(size)
        .ok_or_else(|| format!("{what} range overflow"))?;
    if end > length {
        return Err(format!(
            "{what} range {offset}..{end} exceeds file size {length}"
        ));
    }
    Ok(offset..end)
}

fn read_u16(data: &[u8], offset: usize, endian: ElfEndian) -> Result<u16, String> {
    let bytes: [u8; 2] = data
        .get(offset..offset + 2)
        .ok_or_else(|| "truncated ELF field".to_string())?
        .try_into()
        .map_err(|_| "invalid ELF field".to_string())?;
    Ok(match endian {
        ElfEndian::Little => u16::from_le_bytes(bytes),
        ElfEndian::Big => u16::from_be_bytes(bytes),
    })
}

fn read_u32(data: &[u8], offset: usize, endian: ElfEndian) -> Result<u32, String> {
    let bytes: [u8; 4] = data
        .get(offset..offset + 4)
        .ok_or_else(|| "truncated ELF field".to_string())?
        .try_into()
        .map_err(|_| "invalid ELF field".to_string())?;
    Ok(match endian {
        ElfEndian::Little => u32::from_le_bytes(bytes),
        ElfEndian::Big => u32::from_be_bytes(bytes),
    })
}

fn read_u64(data: &[u8], offset: usize, endian: ElfEndian) -> Result<u64, String> {
    let bytes: [u8; 8] = data
        .get(offset..offset + 8)
        .ok_or_else(|| "truncated ELF field".to_string())?
        .try_into()
        .map_err(|_| "invalid ELF field".to_string())?;
    Ok(match endian {
        ElfEndian::Little => u64::from_le_bytes(bytes),
        ElfEndian::Big => u64::from_be_bytes(bytes),
    })
}

pub fn validate_elf(payload: &[u8], target: TargetSpec, elf_type: ElfType) -> Result<(), String> {
    if payload.len() < 64 {
        return Err("truncated ELF64 header".to_string());
    }
    if &payload[..4] != b"\x7fELF" {
        return Err("payload has invalid ELF magic".to_string());
    }
    if payload[4] != 2 {
        return Err(format!(
            "unsupported ELF class {} (expected ELF64)",
            payload[4]
        ));
    }
    let expected_data = match target.endian {
        ElfEndian::Little => 1,
        ElfEndian::Big => 2,
    };
    if payload[5] != expected_data {
        return Err(format!(
            "ELF endian {} does not match expected {}",
            payload[5], target.endian
        ));
    }
    if payload[6] != 1 {
        return Err(format!(
            "unsupported ELF identification version {}",
            payload[6]
        ));
    }
    let actual_type = read_u16(payload, 16, target.endian)?;
    let expected_type = match elf_type {
        ElfType::StaticPie => 3,
        ElfType::StaticExec => 2,
    };
    if actual_type != expected_type {
        return Err(format!(
            "ELF type {actual_type} does not match expected {expected_type:?} ({elf_type:?})"
        ));
    }
    let machine = read_u16(payload, 18, target.endian)?;
    if machine != target.elf_machine {
        return Err(format!(
            "ELF machine {machine} does not match expected {} for {}",
            target.elf_machine, target.release_arch
        ));
    }
    if read_u32(payload, 20, target.endian)? != 1 {
        return Err("unsupported ELF header version".to_string());
    }
    if read_u16(payload, 52, target.endian)? != 64 {
        return Err("invalid ELF64 header size".to_string());
    }
    let phoff = read_u64(payload, 32, target.endian)?;
    let phentsize = usize::from(read_u16(payload, 54, target.endian)?);
    let phnum = usize::from(read_u16(payload, 56, target.endian)?);
    if phentsize != 56 || phnum == 0 {
        return Err(format!(
            "invalid ELF program header table dimensions: entry={phentsize}, count={phnum}"
        ));
    }
    let table_size = phentsize
        .checked_mul(phnum)
        .ok_or_else(|| "ELF program header table size overflow".to_string())?;
    let table = checked_range(
        phoff,
        table_size as u64,
        payload.len(),
        "ELF program header table",
    )?;

    let mut executable_load = false;
    for index in 0..phnum {
        let offset = table.start + index * phentsize;
        let p_type = read_u32(payload, offset, target.endian)?;
        let flags = read_u32(payload, offset + 4, target.endian)?;
        let file_offset = read_u64(payload, offset + 8, target.endian)?;
        let file_size = read_u64(payload, offset + 32, target.endian)?;
        let memory_size = read_u64(payload, offset + 40, target.endian)?;
        if p_type == 1 && file_size > memory_size {
            return Err(format!(
                "PT_LOAD program header {index} has p_filesz > p_memsz"
            ));
        }
        let range = checked_range(
            file_offset,
            file_size,
            payload.len(),
            &format!("program header {index}"),
        )?;
        match p_type {
            1 if flags & 1 != 0 => executable_load = true,
            3 => return Err("ELF contains forbidden PT_INTERP".to_string()),
            2 => {
                if range.len() % 16 != 0 {
                    return Err(
                        "PT_DYNAMIC size is not a multiple of ELF64 dynamic entry size".to_string(),
                    );
                }
                let mut terminated = false;
                for dynamic_offset in (range.start..range.end).step_by(16) {
                    let tag = read_u64(payload, dynamic_offset, target.endian)?;
                    if tag == 0 {
                        terminated = true;
                        break;
                    }
                    if tag == 1 {
                        return Err("ELF contains forbidden DT_NEEDED".to_string());
                    }
                }
                if !terminated {
                    return Err("unterminated PT_DYNAMIC table".to_string());
                }
            }
            _ => {}
        }
    }
    if !executable_load {
        return Err("ELF has no executable PT_LOAD segment".to_string());
    }
    Ok(())
}

pub fn extract_dwarfs_wrapper(
    wrapper: &[u8],
    target: TargetSpec,
    max_output_size: usize,
) -> Result<Vec<u8>, String> {
    let trailer_offset = wrapper
        .len()
        .checked_sub(SQUEEZE_TRAILER_LEN)
        .ok_or_else(|| "truncated DwarFS wrapper trailer".to_string())?;
    let trailer = &wrapper[trailer_offset..];
    if &trailer[..8] != SQUEEZE_MAGIC {
        return Err("invalid DwarFS wrapper magic".to_string());
    }
    let field = |offset: usize| -> Result<u64, String> {
        let bytes: [u8; 8] = trailer
            .get(offset..offset + 8)
            .ok_or_else(|| "truncated DwarFS wrapper trailer field".to_string())?
            .try_into()
            .map_err(|_| "invalid DwarFS wrapper trailer field".to_string())?;
        Ok(u64::from_le_bytes(bytes))
    };
    let declared_size_u64 = field(8)?;
    let compressed_size_u64 = field(16)?;
    let expected_xxh64 = field(24)?;
    let declared_size = usize::try_from(declared_size_u64).map_err(|_| {
        format!("declared uncompressed size {declared_size_u64} does not fit usize")
    })?;
    if declared_size > max_output_size {
        return Err(format!(
            "declared uncompressed size {declared_size} exceeds limit {max_output_size}"
        ));
    }
    let compressed_size = usize::try_from(compressed_size_u64).map_err(|_| {
        format!("declared compressed size {compressed_size_u64} does not fit usize")
    })?;
    if compressed_size > MAX_DOWNLOAD_SIZE {
        return Err(format!(
            "declared compressed size {compressed_size} exceeds limit {MAX_DOWNLOAD_SIZE}"
        ));
    }
    let payload_offset = trailer_offset.checked_sub(compressed_size).ok_or_else(|| {
        format!("declared compressed size {compressed_size} exceeds wrapper payload area {trailer_offset}")
    })?;
    let compressed_end = payload_offset
        .checked_add(compressed_size)
        .ok_or_else(|| "compressed payload range overflow".to_string())?;
    if compressed_end != trailer_offset {
        return Err("compressed payload does not end at DwarFS trailer".to_string());
    }

    let decoder = zstd::stream::read::Decoder::new(&wrapper[payload_offset..compressed_end])
        .map_err(|err| format!("failed to initialize DwarFS Zstd decoder: {err}"))?;
    let read_limit = declared_size
        .checked_add(1)
        .ok_or_else(|| "DwarFS declared output size overflow".to_string())?;
    let mut payload = Vec::new();
    payload.try_reserve_exact(declared_size).map_err(|err| {
        format!("failed to allocate {declared_size} bytes for DwarFS payload: {err}")
    })?;
    decoder
        .take(read_limit as u64)
        .read_to_end(&mut payload)
        .map_err(|err| format!("failed to decode DwarFS Zstd payload: {err}"))?;
    if payload.len() != declared_size {
        return Err(format!(
            "DwarFS uncompressed size mismatch: expected {declared_size}, got {}",
            payload.len()
        ));
    }
    let actual_xxh64 = xxh64(&payload, 0);
    if actual_xxh64 != expected_xxh64 {
        return Err(format!(
            "DwarFS XXH64 mismatch: expected {expected_xxh64:016x}, got {actual_xxh64:016x}"
        ));
    }
    validate_elf(&payload, target, ElfType::StaticExec)?;
    Ok(payload)
}

fn read_bounded(path: &Path, max_size: usize) -> Result<Vec<u8>, String> {
    let file =
        File::open(path).map_err(|err| format!("failed to open {}: {err}", path.display()))?;
    let metadata = file
        .metadata()
        .map_err(|err| format!("failed to inspect {}: {err}", path.display()))?;
    if !metadata.is_file() {
        return Err(format!("{} is not a regular file", path.display()));
    }
    if metadata.len() > max_size as u64 {
        return Err(format!(
            "{} size {} exceeds limit {max_size}",
            path.display(),
            metadata.len()
        ));
    }
    let capacity = usize::try_from(metadata.len())
        .map_err(|_| format!("{} size does not fit usize", path.display()))?;
    let mut data = Vec::new();
    data.try_reserve_exact(capacity).map_err(|err| {
        format!(
            "failed to allocate {capacity} bytes for {}: {err}",
            path.display()
        )
    })?;
    file.take((max_size as u64).saturating_add(1))
        .read_to_end(&mut data)
        .map_err(|err| format!("failed to read {}: {err}", path.display()))?;
    if data.len() > max_size {
        return Err(format!("{} exceeds limit {max_size}", path.display()));
    }
    Ok(data)
}

pub fn sha256_hex(data: &[u8]) -> String {
    format!("{:x}", Sha256::digest(data))
}

pub fn sha256_file(path: &Path, max_size: usize) -> Result<String, String> {
    Ok(sha256_hex(&read_bounded(path, max_size)?))
}

fn verify_digest(path: &Path, expected: &str, max_size: usize) -> Result<(), String> {
    let actual = sha256_file(path, max_size)?;
    if actual != expected {
        return Err(format!(
            "SHA-256 mismatch for {}: expected {expected}, got {actual}",
            path.display()
        ));
    }
    Ok(())
}

pub fn atomic_write(destination: &Path, data: &[u8]) -> Result<(), String> {
    let parent = destination
        .parent()
        .ok_or_else(|| format!("destination has no parent: {}", destination.display()))?;
    fs::create_dir_all(parent)
        .map_err(|err| format!("failed to create {}: {err}", parent.display()))?;
    let mut temporary = NamedTempFile::new_in(parent).map_err(|err| {
        format!(
            "failed to create secure temporary file in {}: {err}",
            parent.display()
        )
    })?;
    temporary.write_all(data).map_err(|err| {
        format!(
            "failed to write temporary file for {}: {err}",
            destination.display()
        )
    })?;
    temporary.flush().map_err(|err| {
        format!(
            "failed to flush temporary file for {}: {err}",
            destination.display()
        )
    })?;
    temporary.as_file().sync_all().map_err(|err| {
        format!(
            "failed to sync temporary file for {}: {err}",
            destination.display()
        )
    })?;
    temporary.persist(destination).map_err(|err| {
        format!(
            "failed to atomically publish {}: {}",
            destination.display(),
            err.error
        )
    })?;
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|err| format!("failed to sync directory {}: {err}", parent.display()))?;
    Ok(())
}

pub fn curl_args(url: &str, max_size: usize) -> Vec<String> {
    [
        "--fail".to_string(),
        "--location".to_string(),
        "--retry".to_string(),
        "3".to_string(),
        "--max-filesize".to_string(),
        max_size.to_string(),
        url.to_string(),
    ]
    .into_iter()
    .collect()
}

pub fn download_atomic<S: AsRef<OsStr>>(
    curl: S,
    url: &str,
    destination: &Path,
) -> Result<(), String> {
    let parent = destination
        .parent()
        .ok_or_else(|| format!("destination has no parent: {}", destination.display()))?;
    fs::create_dir_all(parent)
        .map_err(|err| format!("failed to create {}: {err}", parent.display()))?;
    let temporary = NamedTempFile::new_in(parent).map_err(|err| {
        format!(
            "failed to create secure download file in {}: {err}",
            parent.display()
        )
    })?;
    let stdout_file = temporary
        .reopen()
        .map_err(|err| format!("failed to reopen secure download file: {err}"))?;
    let output = Command::new(curl.as_ref())
        .args(curl_args(url, MAX_DOWNLOAD_SIZE))
        .stdout(Stdio::from(stdout_file))
        .stderr(Stdio::piped())
        .output()
        .map_err(|err| format!("failed to execute {:?} for {url}: {err}", curl.as_ref()))?;
    if !output.status.success() {
        return Err(format!(
            "failed to download {url}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let size = temporary
        .as_file()
        .metadata()
        .map_err(|err| format!("failed to inspect download for {url}: {err}"))?
        .len();
    if size > MAX_DOWNLOAD_SIZE as u64 {
        return Err(format!(
            "download from {url} is {size} bytes, exceeding limit {MAX_DOWNLOAD_SIZE}"
        ));
    }
    temporary.persist(destination).map_err(|err| {
        format!(
            "failed to atomically publish {}: {}",
            destination.display(),
            err.error
        )
    })?;
    Ok(())
}

struct CacheLock {
    file: File,
}

impl CacheLock {
    fn acquire(cache: &Path) -> Result<Self, String> {
        let parent = cache
            .parent()
            .ok_or_else(|| format!("cache has no parent: {}", cache.display()))?;
        fs::create_dir_all(parent)
            .map_err(|err| format!("failed to create {}: {err}", parent.display()))?;
        let name = cache
            .file_name()
            .ok_or_else(|| format!("cache has no file name: {}", cache.display()))?;
        let mut lock_name = OsString::from(".");
        lock_name.push(name);
        lock_name.push(".lock");
        let path = parent.join(lock_name);
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .map_err(|err| format!("failed to open cache lock {}: {err}", path.display()))?;
        let started = Instant::now();
        loop {
            match file.try_lock_exclusive() {
                Ok(()) => return Ok(Self { file }),
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    if started.elapsed() >= LOCK_TIMEOUT {
                        return Err(format!(
                            "timed out waiting for cache lock {}",
                            path.display()
                        ));
                    }
                    thread::sleep(LOCK_RETRY);
                }
                Err(err) => return Err(format!("failed to lock {}: {err}", path.display())),
            }
        }
    }
}

impl Drop for CacheLock {
    fn drop(&mut self) {
        let _ = self.file.unlock();
    }
}

#[allow(dead_code)]
pub fn with_cache_lock<T, F>(path: &Path, operation: F) -> Result<T, String>
where
    F: FnOnce() -> Result<T, String>,
{
    let _lock = CacheLock::acquire(path)?;
    operation()
}

fn source_name(asset: &Asset) -> OsString {
    let mut name = OsString::from(".source-");
    name.push(asset.name);
    name
}

pub fn source_cache_name(name: &str, kind: AssetKind) -> String {
    match kind {
        AssetKind::Direct => name.to_string(),
        AssetKind::DwarfsWrapper => format!("{name}-wrapper"),
    }
}

fn source_cache_component(name: &str) -> Result<String, String> {
    match name {
        "squashfuse" => Ok(format!("squashfuse-{SQUASHFUSE_VERSION}")),
        "unsquashfs" | "mksquashfs" => Ok(format!("squashfs-tools-{SQUASHFS_TOOLS_VERSION}")),
        "dwarfs-universal" | "dwarfs-fuse-extract" => Ok(format!("dwarfs-{DWARFS_VERSION}")),
        _ => Err(format!("unknown helper source `{name}`")),
    }
}

#[allow(dead_code)]
pub fn source_cache_relative_path(
    target: TargetSpec,
    name: &str,
    kind: AssetKind,
) -> Result<PathBuf, String> {
    Ok(PathBuf::from(format!("assets-{}", target.release_arch))
        .join(source_cache_component(name)?)
        .join(source_cache_name(name, kind)))
}

fn source_cache_path(cache: &Path, target: TargetSpec, asset: &Asset) -> Result<PathBuf, String> {
    let architecture_dir = format!("assets-{}", target.release_arch);
    let root = cache
        .ancestors()
        .find(|path| path.file_name() == Some(OsStr::new(&architecture_dir)))
        .or_else(|| cache.parent())
        .ok_or_else(|| format!("cache has no parent directory: {}", cache.display()))?;
    Ok(root
        .join(source_cache_component(asset.name)?)
        .join(source_cache_name(asset.name, asset.kind)))
}

fn generation_valid(cache: &Path, target: TargetSpec, assets: &[Asset]) -> Result<(), String> {
    for asset in assets {
        verify_digest(
            &cache.join(source_name(asset)),
            &asset.source_sha256,
            MAX_DOWNLOAD_SIZE,
        )?;
        let raw = read_bounded(&cache.join(asset.name), MAX_HELPER_SIZE)?;
        if sha256_hex(&raw) != asset.payload_sha256 {
            return Err(format!("cached {} payload SHA-256 mismatch", asset.name));
        }
        validate_elf(&raw, target, asset.elf_type)?;
        let compressed_path = cache.join(format!("{}-zst", asset.name));
        let compressed = read_bounded(&compressed_path, MAX_DOWNLOAD_SIZE)?;
        let decoded = decode_zstd_bounded(&compressed, raw.len())?;
        if decoded != raw {
            return Err(format!(
                "cached {}-zst does not decode to cached raw ELF",
                asset.name
            ));
        }
    }
    Ok(())
}

fn decode_zstd_bounded(compressed: &[u8], declared_size: usize) -> Result<Vec<u8>, String> {
    if declared_size > MAX_HELPER_SIZE {
        return Err(format!(
            "declared Zstd output {declared_size} exceeds {MAX_HELPER_SIZE}"
        ));
    }
    let decoder = zstd::stream::read::Decoder::new(compressed)
        .map_err(|err| format!("failed to initialize Zstd decoder: {err}"))?;
    let limit = declared_size
        .checked_add(1)
        .ok_or_else(|| "Zstd output size overflow".to_string())?;
    let mut decoded = Vec::new();
    decoded
        .try_reserve_exact(declared_size)
        .map_err(|err| format!("failed to allocate {declared_size} decoded bytes: {err}"))?;
    decoder
        .take(limit as u64)
        .read_to_end(&mut decoded)
        .map_err(|err| format!("failed to decode Zstd data: {err}"))?;
    if decoded.len() != declared_size {
        return Err(format!(
            "Zstd output size mismatch: expected {declared_size}, got {}",
            decoded.len()
        ));
    }
    Ok(decoded)
}

fn copy_bounded(source: &Path, destination: &Path, max_size: usize) -> Result<(), String> {
    let data = read_bounded(source, max_size)?;
    atomic_write(destination, &data)
}

fn replace_directory(stage: PathBuf, destination: &Path) -> Result<(), String> {
    let parent = destination
        .parent()
        .ok_or_else(|| format!("destination has no parent: {}", destination.display()))?;
    let backup = TempBuilder::new()
        .prefix(".uruntime-backup-")
        .tempdir_in(parent)
        .map_err(|err| {
            format!(
                "failed to reserve backup path in {}: {err}",
                parent.display()
            )
        })?;
    let backup_path = backup.path().to_path_buf();
    backup
        .close()
        .map_err(|err| format!("failed to release backup path: {err}"))?;
    let had_destination = destination.exists();
    if had_destination {
        fs::rename(destination, &backup_path)
            .map_err(|err| format!("failed to move {} to backup: {err}", destination.display()))?;
    }
    if let Err(err) = fs::rename(&stage, destination) {
        if had_destination {
            if let Err(rollback_err) = fs::rename(&backup_path, destination) {
                return Err(format!(
                    "failed to publish {}: {err}; rollback also failed: {rollback_err}; previous generation remains at {}",
                    destination.display(),
                    backup_path.display()
                ));
            }
        }
        return Err(format!(
            "failed to publish {}: {err}",
            destination.display()
        ));
    }
    if had_destination {
        fs::remove_dir_all(&backup_path).map_err(|err| {
            format!(
                "failed to remove cache backup {}: {err}",
                backup_path.display()
            )
        })?;
    }
    Ok(())
}

pub fn stage_output(source: &Path, destination: &Path, files: &[&str]) -> Result<(), String> {
    let parent = destination
        .parent()
        .ok_or_else(|| format!("output has no parent: {}", destination.display()))?;
    fs::create_dir_all(parent)
        .map_err(|err| format!("failed to create {}: {err}", parent.display()))?;
    let stage = TempBuilder::new()
        .prefix(".uruntime-output-")
        .tempdir_in(parent)
        .map_err(|err| {
            format!(
                "failed to create output stage in {}: {err}",
                parent.display()
            )
        })?;
    for name in files {
        let max = if name.ends_with("-zst") {
            MAX_DOWNLOAD_SIZE
        } else {
            MAX_HELPER_SIZE
        };
        copy_bounded(&source.join(name), &stage.path().join(name), max)?;
    }
    let stage_path = stage.keep();
    replace_directory(stage_path, destination)
}

pub fn prepare_assets_with<F>(
    cache: &Path,
    output: &Path,
    target: TargetSpec,
    assets: &[Asset],
    downloader: &F,
) -> Result<(), String>
where
    F: Fn(&Asset, &Path) -> Result<(), String>,
{
    let _lock = CacheLock::acquire(cache)?;
    if generation_valid(cache, target, assets).is_err() {
        let parent = cache
            .parent()
            .ok_or_else(|| format!("cache has no parent: {}", cache.display()))?;
        fs::create_dir_all(parent)
            .map_err(|err| format!("failed to create {}: {err}", parent.display()))?;
        let stage = TempBuilder::new()
            .prefix(".uruntime-cache-stage-")
            .tempdir_in(parent)
            .map_err(|err| {
                format!(
                    "failed to create cache stage in {}: {err}",
                    parent.display()
                )
            })?;

        for asset in assets {
            let stage_source = stage.path().join(source_name(asset));
            let cached_source = cache.join(source_name(asset));
            if verify_digest(&cached_source, &asset.source_sha256, MAX_DOWNLOAD_SIZE).is_ok() {
                copy_bounded(&cached_source, &stage_source, MAX_DOWNLOAD_SIZE)?;
            } else {
                let source_cache = source_cache_path(cache, target, asset)?;
                {
                    let _source_lock = CacheLock::acquire(&source_cache)?;
                    if verify_digest(&source_cache, &asset.source_sha256, MAX_DOWNLOAD_SIZE)
                        .is_err()
                    {
                        downloader(asset, &source_cache)?;
                        verify_digest(&source_cache, &asset.source_sha256, MAX_DOWNLOAD_SIZE)
                            .map_err(|err| {
                                let _ = fs::remove_file(&source_cache);
                                format!("downloaded asset failed integrity validation: {err}")
                            })?;
                    }
                    copy_bounded(&source_cache, &stage_source, MAX_DOWNLOAD_SIZE)?;
                }
            }

            let source = read_bounded(&stage_source, MAX_DOWNLOAD_SIZE)?;
            let payload = match asset.kind {
                AssetKind::Direct => source,
                AssetKind::DwarfsWrapper => {
                    extract_dwarfs_wrapper(&source, target, MAX_HELPER_SIZE)?
                }
            };
            let actual_payload = sha256_hex(&payload);
            if actual_payload != asset.payload_sha256 {
                return Err(format!(
                    "payload SHA-256 mismatch for {}: expected {}, got {actual_payload}",
                    asset.name, asset.payload_sha256
                ));
            }
            validate_elf(&payload, target, asset.elf_type)?;
            atomic_write(&stage.path().join(asset.name), &payload)?;
            let compressed = zstd::stream::encode_all(&payload[..], 22)
                .map_err(|err| format!("failed to Zstd-compress {}: {err}", asset.name))?;
            if compressed.len() > MAX_DOWNLOAD_SIZE {
                return Err(format!(
                    "compressed {} size {} exceeds {MAX_DOWNLOAD_SIZE}",
                    asset.name,
                    compressed.len()
                ));
            }
            let decoded = decode_zstd_bounded(&compressed, payload.len())?;
            if decoded != payload {
                return Err(format!(
                    "generated {}-zst failed byte-equality verification",
                    asset.name
                ));
            }
            atomic_write(
                &stage.path().join(format!("{}-zst", asset.name)),
                &compressed,
            )?;
        }
        generation_valid(stage.path(), target, assets)?;
        let stage_path = stage.keep();
        replace_directory(stage_path, cache)?;
    }

    let mut files = Vec::with_capacity(assets.len() * 2);
    for asset in assets {
        files.push(asset.name);
    }
    let compressed_names: Vec<String> = assets
        .iter()
        .map(|asset| format!("{}-zst", asset.name))
        .collect();
    let mut all_names: Vec<&str> = files;
    all_names.extend(compressed_names.iter().map(String::as_str));
    stage_output(cache, output, &all_names)
}
