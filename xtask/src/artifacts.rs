use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::Value;

use super::{
    host_artifact_arch, project_root, qemu_runner_names, resolve_program, terminate_process_group,
    DynError, VARIANTS,
};

#[cfg(test)]
use super::ARCHES;

const REQUIRED_SECTIONS: [&str; 5] = [
    ".envs",
    ".upd_info",
    ".sig_key",
    ".sha256_sig",
    ".digest_md5",
];
const PT_DYNAMIC: u32 = 2;
const PT_INTERP: u32 = 3;
const DT_NULL: u64 = 0;
const DT_NEEDED: u64 = 1;
const SHT_NOBITS: u32 = 8;
const PN_XNUM: u16 = 0xffff;
const MAX_ARTIFACT_SIZE: usize = 64 * 1024 * 1024;
const MAX_PROGRAM_HEADERS: usize = 128;
const MAX_SECTION_HEADERS: usize = 1024;
const MAX_SECTION_NAME_TABLE: usize = 1024 * 1024;
const MAX_SMOKE_OUTPUT: usize = 64 * 1024;
const SMOKE_TIMEOUT: Duration = Duration::from_secs(30);
const O_NOFOLLOW: i32 = 0x20000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ByteOrder {
    Little,
    Big,
}

#[derive(Clone, Copy)]
struct ArtifactArch {
    name: &'static str,
    machine: u16,
    order: ByteOrder,
}

const ARTIFACT_ARCHES: [ArtifactArch; 6] = [
    ArtifactArch {
        name: "x86_64",
        machine: 62,
        order: ByteOrder::Little,
    },
    ArtifactArch {
        name: "aarch64",
        machine: 183,
        order: ByteOrder::Little,
    },
    ArtifactArch {
        name: "riscv64",
        machine: 243,
        order: ByteOrder::Little,
    },
    ArtifactArch {
        name: "loongarch64",
        machine: 258,
        order: ByteOrder::Little,
    },
    ArtifactArch {
        name: "ppc64",
        machine: 21,
        order: ByteOrder::Big,
    },
    ArtifactArch {
        name: "ppc64le",
        machine: 21,
        order: ByteOrder::Little,
    },
];

fn arch(name: &str) -> Result<ArtifactArch, DynError> {
    ARTIFACT_ARCHES
        .iter()
        .copied()
        .find(|arch| arch.name == name)
        .ok_or_else(|| format!("unsupported architecture: {name}").into())
}

fn expected_artifact_names(arch: &str) -> Result<Vec<String>, DynError> {
    let _ = self::arch(arch)?;
    Ok(VARIANTS
        .iter()
        .map(|variant| format!("uruntime-{}-{arch}", variant.name))
        .collect())
}

fn expected_all_artifact_names() -> Vec<String> {
    ARTIFACT_ARCHES
        .iter()
        .flat_map(|arch| expected_artifact_names(arch.name).unwrap_or_default())
        .collect()
}

fn checked_range(
    offset: u64,
    size: u64,
    length: usize,
    description: &str,
) -> Result<std::ops::Range<usize>, DynError> {
    let start = usize::try_from(offset)
        .map_err(|_| format!("{description} offset does not fit in memory"))?;
    let size =
        usize::try_from(size).map_err(|_| format!("{description} size does not fit in memory"))?;
    let end = start
        .checked_add(size)
        .ok_or_else(|| format!("{description} range overflow"))?;
    if end > length {
        return Err(
            format!("{description} range {start}..{end} exceeds file size {length}").into(),
        );
    }
    Ok(start..end)
}

fn read_regular(path: &Path, limit: usize) -> Result<Vec<u8>, DynError> {
    if fs::symlink_metadata(path)?.file_type().is_symlink() {
        return Err(format!("{}: symlink is not allowed", path.display()).into());
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(O_NOFOLLOW)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(format!("{}: not a regular file", path.display()).into());
    }
    if metadata.len() > limit as u64 {
        return Err(format!(
            "{}: file size {} exceeds size limit {limit}",
            path.display(),
            metadata.len()
        )
        .into());
    }
    let mut data = Vec::with_capacity(metadata.len() as usize);
    Read::by_ref(&mut file)
        .take((limit + 1) as u64)
        .read_to_end(&mut data)?;
    if data.len() > limit {
        return Err(format!("{}: file exceeds size limit {limit}", path.display()).into());
    }
    Ok(data)
}

fn bytes<'a>(
    data: &'a [u8],
    offset: usize,
    size: usize,
    field: &str,
) -> Result<&'a [u8], DynError> {
    let end = offset
        .checked_add(size)
        .ok_or_else(|| format!("{field} offset overflow"))?;
    data.get(offset..end)
        .ok_or_else(|| format!("{field} exceeds file size").into())
}

fn u16_at(data: &[u8], offset: usize, order: ByteOrder, field: &str) -> Result<u16, DynError> {
    let value: [u8; 2] = bytes(data, offset, 2, field)?.try_into()?;
    Ok(match order {
        ByteOrder::Little => u16::from_le_bytes(value),
        ByteOrder::Big => u16::from_be_bytes(value),
    })
}

fn u32_at(data: &[u8], offset: usize, order: ByteOrder, field: &str) -> Result<u32, DynError> {
    let value: [u8; 4] = bytes(data, offset, 4, field)?.try_into()?;
    Ok(match order {
        ByteOrder::Little => u32::from_le_bytes(value),
        ByteOrder::Big => u32::from_be_bytes(value),
    })
}

fn u64_at(data: &[u8], offset: usize, order: ByteOrder, field: &str) -> Result<u64, DynError> {
    let value: [u8; 8] = bytes(data, offset, 8, field)?.try_into()?;
    Ok(match order {
        ByteOrder::Little => u64::from_le_bytes(value),
        ByteOrder::Big => u64::from_be_bytes(value),
    })
}

fn section_names(table: &[u8]) -> Result<BTreeMap<usize, String>, DynError> {
    let mut names = BTreeMap::new();
    let mut offset = 0;
    while offset < table.len() {
        let relative_end = table[offset..]
            .iter()
            .position(|byte| *byte == 0)
            .ok_or("unterminated section name table")?;
        let end = offset + relative_end;
        let name = std::str::from_utf8(&table[offset..end])?;
        if !name.is_ascii() {
            return Err("non-ASCII section name".into());
        }
        names.insert(offset, name.to_string());
        offset = end + 1;
    }
    Ok(names)
}

fn validate_elf_bytes(
    data: &[u8],
    display: &str,
    arch_name: &str,
    expected_magic: [u8; 3],
) -> Result<(), DynError> {
    let spec = arch(arch_name)?;
    if data.len() < 64 || data.get(..4) != Some(b"\x7fELF") {
        return Err(format!("{display}: not an ELF64 file").into());
    }
    if data[4] != 2 {
        return Err(format!("{display}: expected ELF64 class, got {}", data[4]).into());
    }
    let expected_data = if spec.order == ByteOrder::Little {
        1
    } else {
        2
    };
    if data[5] != expected_data {
        return Err(format!("{display}: ELF endian byte does not match {arch_name}").into());
    }
    if data[6] != 1 {
        return Err(format!("{display}: unsupported ELF version {}", data[6]).into());
    }
    if data.get(8..11) != Some(expected_magic.as_slice()) {
        return Err(format!("{display}: runtime magic mismatch").into());
    }
    if u16_at(data, 18, spec.order, "ELF machine")? != spec.machine {
        return Err(format!("{display}: ELF machine does not match {arch_name}").into());
    }
    if u16_at(data, 52, spec.order, "ELF header size")? != 64 {
        return Err(format!("{display}: invalid ELF64 header size").into());
    }

    let phoff = u64_at(data, 32, spec.order, "program header offset")?;
    let phentsize = u16_at(data, 54, spec.order, "program header entry size")? as usize;
    let phnum = u16_at(data, 56, spec.order, "program header count")?;
    if phnum == PN_XNUM {
        return Err(format!("{display}: extended program-header numbering is unsupported").into());
    }
    if phentsize != 56 || phnum == 0 || phnum as usize > MAX_PROGRAM_HEADERS {
        return Err(format!("{display}: invalid program header dimensions").into());
    }
    let program_table = checked_range(
        phoff,
        (phentsize * phnum as usize) as u64,
        data.len(),
        "program header table",
    )?;
    for index in 0..phnum as usize {
        let offset = program_table.start + index * phentsize;
        let kind = u32_at(data, offset, spec.order, "program header type")?;
        let file_offset = u64_at(data, offset + 8, spec.order, "segment offset")?;
        let file_size = u64_at(data, offset + 32, spec.order, "segment size")?;
        let segment = checked_range(
            file_offset,
            file_size,
            data.len(),
            &format!("program header {index}"),
        )?;
        if kind == PT_INTERP {
            return Err(format!("{display}: static contract violated by PT_INTERP").into());
        }
        if kind == PT_DYNAMIC {
            if segment.len() % 16 != 0 {
                return Err(format!("{display}: malformed PT_DYNAMIC table").into());
            }
            let mut terminated = false;
            for dynamic_offset in (segment.start..segment.end).step_by(16) {
                let tag = u64_at(data, dynamic_offset, spec.order, "dynamic tag")?;
                if tag == DT_NULL {
                    terminated = true;
                    break;
                }
                if tag == DT_NEEDED {
                    return Err(format!("{display}: static contract violated by DT_NEEDED").into());
                }
            }
            if !terminated {
                return Err(format!("{display}: unterminated PT_DYNAMIC table").into());
            }
        }
    }

    let shoff = u64_at(data, 40, spec.order, "section header offset")?;
    let shentsize = u16_at(data, 58, spec.order, "section header entry size")? as usize;
    let shnum = u16_at(data, 60, spec.order, "section header count")? as usize;
    let shstrndx = u16_at(data, 62, spec.order, "section string index")? as usize;
    if shentsize != 64
        || shnum == 0
        || shnum > MAX_SECTION_HEADERS
        || shstrndx == 0xffff
        || shstrndx >= shnum
    {
        return Err(
            format!("{display}: invalid or unsupported section header dimensions/index").into(),
        );
    }
    let section_table = checked_range(
        shoff,
        (shentsize * shnum) as u64,
        data.len(),
        "section header table",
    )?;
    let header = |index: usize| -> Result<(usize, u32, u64, u64), DynError> {
        let offset = section_table.start + index * shentsize;
        Ok((
            u32_at(data, offset, spec.order, "section name offset")? as usize,
            u32_at(data, offset + 4, spec.order, "section type")?,
            u64_at(data, offset + 24, spec.order, "section offset")?,
            u64_at(data, offset + 32, spec.order, "section size")?,
        ))
    };
    let (_, _, names_offset, names_size) = header(shstrndx)?;
    if names_size > MAX_SECTION_NAME_TABLE as u64 {
        return Err(format!("{display}: section name table exceeds size limit").into());
    }
    let names_range = checked_range(names_offset, names_size, data.len(), "section string table")?;
    let names = section_names(&data[names_range])?;
    let mut present = BTreeSet::new();
    for index in 1..shnum {
        let (name_offset, kind, file_offset, size) = header(index)?;
        if kind != SHT_NOBITS {
            checked_range(file_offset, size, data.len(), &format!("section {index}"))?;
        }
        let name = names
            .get(&name_offset)
            .ok_or_else(|| format!("section name offset {name_offset} is not a string boundary"))?;
        present.insert(name.as_str());
    }
    let missing = REQUIRED_SECTIONS
        .into_iter()
        .filter(|name| !present.contains(name))
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        return Err(format!(
            "{display}: missing required runtime section(s): {}",
            missing.join(", ")
        )
        .into());
    }
    Ok(())
}

fn directory_files(directory: &Path) -> Result<BTreeSet<String>, DynError> {
    if fs::symlink_metadata(directory)?.file_type().is_symlink() {
        return Err(format!(
            "artifact path must not be a symlink: {}",
            directory.display()
        )
        .into());
    }
    if !directory.is_dir() {
        return Err(format!("artifact path is not a directory: {}", directory.display()).into());
    }
    let mut files = BTreeSet::new();
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let metadata = fs::symlink_metadata(entry.path())?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err(format!("non-regular artifact entry: {}", entry.path().display()).into());
        }
        files.insert(
            entry
                .file_name()
                .into_string()
                .map_err(|_| "artifact filename is not valid UTF-8")?,
        );
    }
    Ok(files)
}

fn write_exclusive(path: &Path, data: &[u8], mode: u32) -> Result<(), DynError> {
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .custom_flags(O_NOFOLLOW)
        .open(path)?;
    if let Err(error) = output.write_all(data).and_then(|()| output.sync_all()) {
        let _ = fs::remove_file(path);
        return Err(format!("cannot stage {}: {error}", path.display()).into());
    }
    fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    Ok(())
}

fn wait_child(
    child: &mut Child,
    description: &str,
    output_paths: [&Path; 2],
) -> Result<std::process::ExitStatus, DynError> {
    let deadline = Instant::now() + SMOKE_TIMEOUT;
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(status);
        }
        if output_paths.iter().any(|path| {
            path.metadata()
                .is_ok_and(|metadata| metadata.len() > MAX_SMOKE_OUTPUT as u64)
        }) {
            terminate_process_group(child);
            return Err(format!("{description} exceeded the output limit").into());
        }
        if Instant::now() >= deadline {
            terminate_process_group(child);
            return Err(format!("{description} exceeded {SMOKE_TIMEOUT:?}").into());
        }
        thread::sleep(Duration::from_millis(25));
    }
}

fn smoke_runner_names(
    artifact_arch: &str,
    host_arch: &str,
) -> Result<Option<[String; 2]>, DynError> {
    if artifact_arch == host_arch {
        Ok(None)
    } else {
        Ok(Some(qemu_runner_names(artifact_arch)?))
    }
}

fn smoke_command(spec: ArtifactArch, binary: &Path) -> Result<Command, DynError> {
    if let Some(names) = smoke_runner_names(spec.name, host_artifact_arch())? {
        let qemu = names
            .iter()
            .find_map(|name| resolve_program(Path::new(name), &project_root()).ok())
            .ok_or_else(|| {
                format!(
                    "smoke test for {} requires `{}` or `{}` in PATH",
                    spec.name, names[0], names[1]
                )
            })?;
        let mut command = Command::new(qemu);
        command.arg(binary).arg("--uruntime-version");
        Ok(command)
    } else {
        let mut command = Command::new(binary);
        command.arg("--uruntime-version");
        Ok(command)
    }
}

fn run_smoke_command(command: &mut Command, name: &str) -> Result<(), DynError> {
    let capture = tempfile::Builder::new()
        .prefix("uruntime-smoke-output-")
        .tempdir()?;
    let stdout_path = capture.path().join("stdout");
    let stderr_path = capture.path().join("stderr");
    command
        .process_group(0)
        .stdout(Stdio::from(File::create(&stdout_path)?))
        .stderr(Stdio::from(File::create(&stderr_path)?));
    let mut child = command.spawn()?;
    let status = wait_child(
        &mut child,
        &format!("smoke test {name}"),
        [&stdout_path, &stderr_path],
    )?;
    // A version probe must not leave descendants behind. Killing the now-childless
    // process group is harmless and closes files inherited by an unexpected daemon.
    terminate_process_group(&mut child);
    let stdout = read_regular(&stdout_path, MAX_SMOKE_OUTPUT)?;
    let stderr = read_regular(&stderr_path, MAX_SMOKE_OUTPUT)?;
    if !status.success() {
        return Err(format!(
            "smoke test failed for {name} ({status}): {}",
            String::from_utf8_lossy(&stderr).trim()
        )
        .into());
    }
    if !String::from_utf8_lossy(&stdout).trim().starts_with('v') {
        return Err(format!("smoke test returned unexpected version for {name}").into());
    }
    Ok(())
}

fn smoke_validated_bytes(spec: ArtifactArch, name: &str, data: &[u8]) -> Result<(), DynError> {
    if !expected_artifact_names(spec.name)?
        .iter()
        .any(|expected| expected == name)
    {
        return Err(format!("unexpected smoke-test artifact name: {name}").into());
    }
    let root = tempfile::Builder::new()
        .prefix("uruntime-smoke-")
        .tempdir()?;
    let binary = root.path().join(name);
    write_exclusive(&binary, data, 0o700)?;
    let mut command = smoke_command(spec, &binary)?;
    run_smoke_command(&mut command, name)
}

pub fn validate_arch(directory: &Path, arch_name: &str, smoke: bool) -> Result<(), DynError> {
    let spec = arch(arch_name)?;
    let expected = expected_artifact_names(arch_name)?
        .into_iter()
        .collect::<BTreeSet<_>>();
    let actual = directory_files(directory)?;
    if actual != expected {
        let missing = expected.difference(&actual).cloned().collect::<Vec<_>>();
        let unexpected = actual.difference(&expected).cloned().collect::<Vec<_>>();
        return Err(format!(
            "artifact manifest mismatch for {arch_name}; missing={missing:?}, unexpected={unexpected:?}"
        )
        .into());
    }
    for name in &expected {
        let path = directory.join(name);
        let magic = if name.starts_with("uruntime-appimage") {
            *b"AI\x02"
        } else {
            *b"RI\x02"
        };
        let data = read_regular(&path, MAX_ARTIFACT_SIZE)?;
        validate_elf_bytes(&data, &path.display().to_string(), arch_name, magic)?;
        if smoke {
            smoke_validated_bytes(spec, name, &data)?;
        }
    }
    println!("validated {} {arch_name} artifacts", expected.len());
    Ok(())
}

pub fn aggregate_release(downloads: &Path, output: &Path) -> Result<(), DynError> {
    let expected_directories = ARTIFACT_ARCHES
        .iter()
        .map(|arch| format!("uruntime-{}", arch.name))
        .collect::<BTreeSet<_>>();
    if fs::symlink_metadata(downloads)?.file_type().is_symlink() || !downloads.is_dir() {
        return Err(format!("invalid download path: {}", downloads.display()).into());
    }
    let actual_directories = fs::read_dir(downloads)?
        .map(|entry| {
            entry?
                .file_name()
                .into_string()
                .map_err(|_| std::io::Error::other("download directory name is not UTF-8"))
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    if actual_directories != expected_directories {
        return Err("unexpected artifact directories".into());
    }
    if output.symlink_metadata().is_ok() && output.is_symlink() {
        return Err(format!("release output must not be a symlink: {}", output.display()).into());
    }
    if output.exists() && fs::read_dir(output)?.next().is_some() {
        return Err(format!("release output is not empty: {}", output.display()).into());
    }
    fs::create_dir_all(output)?;

    let mut seen = BTreeSet::new();
    for arch in ARTIFACT_ARCHES {
        let source_directory = downloads.join(format!("uruntime-{}", arch.name));
        let expected = expected_artifact_names(arch.name)?
            .into_iter()
            .collect::<BTreeSet<_>>();
        if directory_files(&source_directory)? != expected {
            return Err(format!("artifact manifest mismatch for {}", arch.name).into());
        }
        for name in expected {
            if !seen.insert(name.clone()) {
                return Err(format!("duplicate release artifact: {name}").into());
            }
            let source = source_directory.join(&name);
            let magic = if name.starts_with("uruntime-appimage") {
                *b"AI\x02"
            } else {
                *b"RI\x02"
            };
            let data = read_regular(&source, MAX_ARTIFACT_SIZE)?;
            validate_elf_bytes(&data, &source.display().to_string(), arch.name, magic)?;
            write_exclusive(&output.join(name), &data, 0o755)?;
        }
    }
    let expected = expected_all_artifact_names()
        .into_iter()
        .collect::<BTreeSet<_>>();
    if seen != expected || directory_files(output)? != expected {
        return Err("release staging manifest does not contain exactly 54 artifacts".into());
    }
    println!(
        "staged {} release artifacts in {}",
        seen.len(),
        output.display()
    );
    Ok(())
}

pub fn validate_release(path: &Path) -> Result<(), DynError> {
    let value: Value = serde_json::from_slice(&read_regular(path, 8 * 1024 * 1024)?)?;
    let assets = value
        .as_array()
        .ok_or("release assets payload must be a JSON list")?;
    let mut names = Vec::with_capacity(assets.len());
    for asset in assets {
        names.push(
            asset
                .get("name")
                .and_then(Value::as_str)
                .ok_or("release asset has no string name")?
                .to_string(),
        );
    }
    let actual = names.iter().cloned().collect::<BTreeSet<_>>();
    let expected = expected_all_artifact_names()
        .into_iter()
        .collect::<BTreeSet<_>>();
    if names.len() != actual.len() || actual != expected {
        return Err("published release manifest mismatch".into());
    }
    println!("validated exact 54-asset published release manifest");
    Ok(())
}

pub fn release_id(path: &Path, tag: &str) -> Result<Option<u64>, DynError> {
    let value: Value = serde_json::from_slice(&read_regular(path, 8 * 1024 * 1024)?)?;
    let pages = value
        .as_array()
        .ok_or("invalid paginated release-list response")?;
    let mut matches = Vec::new();
    for page in pages {
        let page = page
            .as_array()
            .ok_or("invalid paginated release-list response")?;
        for release in page {
            if release.get("tag_name").and_then(Value::as_str) == Some(tag) {
                let id = release
                    .get("id")
                    .and_then(Value::as_u64)
                    .filter(|id| *id > 0)
                    .ok_or("exact-tag release has an invalid numeric ID")?;
                matches.push(id);
            }
        }
    }
    if matches.len() > 1 {
        return Err(format!("multiple releases found for exact tag {tag:?}").into());
    }
    Ok(matches.into_iter().next())
}

pub fn write_asset_ids(input: &Path, output: &Path) -> Result<(), DynError> {
    let value: Value = serde_json::from_slice(&read_regular(input, 8 * 1024 * 1024)?)?;
    let pages = value
        .as_array()
        .ok_or("invalid paginated asset-list response")?;
    let mut contents = String::new();
    for page in pages {
        for asset in page
            .as_array()
            .ok_or("invalid paginated asset-list response")?
        {
            let id = asset
                .get("id")
                .and_then(Value::as_u64)
                .filter(|id| *id > 0)
                .ok_or("release asset has an invalid numeric ID")?;
            contents.push_str(&format!("{id}\n"));
        }
    }
    write_exclusive(output, contents.as_bytes(), 0o600)
}

pub fn flatten_assets(input: &Path, output: &Path) -> Result<(), DynError> {
    let value: Value = serde_json::from_slice(&read_regular(input, 8 * 1024 * 1024)?)?;
    let pages = value
        .as_array()
        .ok_or("invalid paginated asset-list response")?;
    let mut assets = Vec::new();
    for page in pages {
        assets.extend(
            page.as_array()
                .ok_or("invalid paginated asset-list response")?
                .iter()
                .cloned(),
        );
    }
    write_exclusive(output, &serde_json::to_vec(&assets)?, 0o600)
}

pub fn command(args: &[String]) -> Result<(), DynError> {
    match args {
        [operation, arch, directory] if operation == "validate-arch" => {
            validate_arch(Path::new(directory), arch, false)
        }
        [operation, arch, directory, flag]
            if operation == "validate-arch" && flag == "--smoke" =>
        {
            validate_arch(Path::new(directory), arch, true)
        }
        [operation, downloads, output] if operation == "aggregate-release" => {
            aggregate_release(Path::new(downloads), Path::new(output))
        }
        [operation, metadata] if operation == "validate-release" => {
            validate_release(Path::new(metadata))
        }
        [operation, metadata, tag] if operation == "release-id" => {
            if let Some(id) = release_id(Path::new(metadata), tag)? {
                println!("{id}");
            }
            Ok(())
        }
        [operation, input, output] if operation == "asset-ids" => {
            write_asset_ids(Path::new(input), Path::new(output))
        }
        [operation, input, output] if operation == "flatten-assets" => {
            flatten_assets(Path::new(input), Path::new(output))
        }
        _ => Err("usage: cargo xtask artifacts <validate-arch ARCH DIR [--smoke]|aggregate-release DOWNLOADS OUTPUT|validate-release JSON|release-id JSON TAG|asset-ids JSON OUTPUT|flatten-assets JSON OUTPUT>".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PUBLIC_ARCHES: [(&str, u16, ByteOrder); 6] = [
        ("x86_64", 62, ByteOrder::Little),
        ("aarch64", 183, ByteOrder::Little),
        ("riscv64", 243, ByteOrder::Little),
        ("loongarch64", 258, ByteOrder::Little),
        ("ppc64", 21, ByteOrder::Big),
        ("ppc64le", 21, ByteOrder::Little),
    ];
    const PUBLIC_VARIANTS: [&str; 9] = [
        "runimage",
        "runimage-squashfs",
        "runimage-dwarfs",
        "appimage",
        "appimage-lite",
        "appimage-squashfs",
        "appimage-squashfs-lite",
        "appimage-dwarfs",
        "appimage-dwarfs-lite",
    ];

    fn public_artifact_names_for_arch(arch: &str) -> Vec<String> {
        PUBLIC_VARIANTS
            .iter()
            .map(|variant| format!("uruntime-{variant}-{arch}"))
            .collect()
    }

    fn public_artifact_names() -> Vec<String> {
        PUBLIC_ARCHES
            .iter()
            .flat_map(|(arch, _, _)| public_artifact_names_for_arch(arch))
            .collect()
    }

    fn put_u16(data: &mut [u8], offset: usize, value: u16, order: ByteOrder) {
        data[offset..offset + 2].copy_from_slice(&match order {
            ByteOrder::Little => value.to_le_bytes(),
            ByteOrder::Big => value.to_be_bytes(),
        });
    }

    fn put_u32(data: &mut [u8], offset: usize, value: u32, order: ByteOrder) {
        data[offset..offset + 4].copy_from_slice(&match order {
            ByteOrder::Little => value.to_le_bytes(),
            ByteOrder::Big => value.to_be_bytes(),
        });
    }

    fn put_u64(data: &mut [u8], offset: usize, value: u64, order: ByteOrder) {
        data[offset..offset + 8].copy_from_slice(&match order {
            ByteOrder::Little => value.to_le_bytes(),
            ByteOrder::Big => value.to_be_bytes(),
        });
    }

    fn synthetic_elf(
        spec: ArtifactArch,
        magic: [u8; 3],
        interp: bool,
        needed: bool,
        omit: Option<&str>,
        nobits_outside: bool,
    ) -> Vec<u8> {
        let mut names = REQUIRED_SECTIONS
            .into_iter()
            .filter(|name| Some(*name) != omit)
            .collect::<Vec<_>>();
        if nobits_outside {
            names.push(".bss");
        }
        let mut shstr = vec![0];
        let mut offsets = BTreeMap::new();
        for name in names.iter().copied().chain([".shstrtab"]) {
            offsets.insert(name, shstr.len());
            shstr.extend_from_slice(name.as_bytes());
            shstr.push(0);
        }
        let phnum = if interp || needed { 2 } else { 1 };
        let shnum = names.len() + 2;
        let phoff = 64;
        let shstr_offset = 256;
        let data_offset = 384;
        let shoff = 512;
        let size = shoff + shnum * 64;
        let mut image = vec![0; size];
        image[..4].copy_from_slice(b"\x7fELF");
        image[4..8].copy_from_slice(&[
            2,
            if spec.order == ByteOrder::Little {
                1
            } else {
                2
            },
            1,
            0,
        ]);
        image[8..11].copy_from_slice(&magic);
        put_u16(&mut image, 16, 3, spec.order);
        put_u16(&mut image, 18, spec.machine, spec.order);
        put_u32(&mut image, 20, 1, spec.order);
        put_u64(&mut image, 32, phoff as u64, spec.order);
        put_u64(&mut image, 40, shoff as u64, spec.order);
        put_u16(&mut image, 52, 64, spec.order);
        put_u16(&mut image, 54, 56, spec.order);
        put_u16(&mut image, 56, phnum as u16, spec.order);
        put_u16(&mut image, 58, 64, spec.order);
        put_u16(&mut image, 60, shnum as u16, spec.order);
        put_u16(&mut image, 62, (shnum - 1) as u16, spec.order);
        put_u32(&mut image, phoff, 1, spec.order);
        put_u32(&mut image, phoff + 4, 5, spec.order);
        put_u64(&mut image, phoff + 32, size as u64, spec.order);
        if interp {
            put_u32(&mut image, phoff + 56, PT_INTERP, spec.order);
            put_u64(&mut image, phoff + 64, data_offset as u64, spec.order);
            put_u64(&mut image, phoff + 88, 8, spec.order);
        }
        if needed {
            put_u32(&mut image, phoff + 56, PT_DYNAMIC, spec.order);
            put_u64(
                &mut image,
                phoff + 64,
                (data_offset + 64) as u64,
                spec.order,
            );
            put_u64(&mut image, phoff + 88, 32, spec.order);
            put_u64(&mut image, data_offset + 64, DT_NEEDED, spec.order);
            put_u64(&mut image, data_offset + 80, DT_NULL, spec.order);
        }
        image[shstr_offset..shstr_offset + shstr.len()].copy_from_slice(&shstr);
        for (index, name) in names.iter().enumerate() {
            let header = shoff + (index + 1) * 64;
            let nobits = *name == ".bss";
            put_u32(&mut image, header, offsets[name] as u32, spec.order);
            put_u32(
                &mut image,
                header + 4,
                if nobits { SHT_NOBITS } else { 1 },
                spec.order,
            );
            put_u64(
                &mut image,
                header + 24,
                if nobits {
                    (size + 4096) as u64
                } else {
                    (data_offset + index) as u64
                },
                spec.order,
            );
            put_u64(
                &mut image,
                header + 32,
                if nobits { 8192 } else { 1 },
                spec.order,
            );
        }
        let names_header = shoff + (shnum - 1) * 64;
        put_u32(
            &mut image,
            names_header,
            offsets[".shstrtab"] as u32,
            spec.order,
        );
        put_u32(&mut image, names_header + 4, 3, spec.order);
        put_u64(
            &mut image,
            names_header + 24,
            shstr_offset as u64,
            spec.order,
        );
        put_u64(
            &mut image,
            names_header + 32,
            shstr.len() as u64,
            spec.order,
        );
        image
    }

    #[test]
    fn smoke_runner_selection_is_relative_to_the_actual_host() {
        assert_eq!(smoke_runner_names("x86_64", "x86_64").unwrap(), None);
        assert_eq!(smoke_runner_names("aarch64", "aarch64").unwrap(), None);
        assert_eq!(
            smoke_runner_names("x86_64", "aarch64").unwrap().unwrap()[0],
            "qemu-x86_64"
        );
        assert_eq!(
            smoke_runner_names("ppc64le", "ppc64").unwrap().unwrap()[0],
            "qemu-ppc64le"
        );
        assert!(smoke_runner_names("unknown", "x86_64").is_err());
    }

    #[test]
    fn smoke_capture_does_not_wait_for_a_descendant_holding_output_descriptors() {
        let started = Instant::now();
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "printf 'vtest\\n'; sleep 30 &"]);
        run_smoke_command(&mut command, "inherited-output-fixture").unwrap();
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn artifact_architecture_and_manifest_match_the_public_release_contract() {
        let actual_arches = ARTIFACT_ARCHES
            .iter()
            .map(|arch| (arch.name, arch.machine, arch.order))
            .collect::<Vec<_>>();
        assert_eq!(actual_arches, PUBLIC_ARCHES);
        assert_eq!(expected_all_artifact_names(), public_artifact_names());
        let build_arches = ARCHES
            .iter()
            .map(|arch| (arch.artifact_name, arch.endian))
            .collect::<Vec<_>>();
        let public_build_arches = PUBLIC_ARCHES
            .iter()
            .map(|(name, _, order)| {
                (
                    *name,
                    match order {
                        ByteOrder::Little => super::super::Endian::Little,
                        ByteOrder::Big => super::super::Endian::Big,
                    },
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(build_arches, public_build_arches);
    }

    #[test]
    fn elf_validation_accepts_big_endian_and_non_file_backed_nobits() {
        let spec = arch("ppc64").unwrap();
        let data = synthetic_elf(spec, *b"RI\x02", false, false, None, true);
        validate_elf_bytes(&data, "fixture", "ppc64", *b"RI\x02").unwrap();
    }

    #[test]
    fn elf_validation_rejects_magic_sections_interp_needed_and_bounds() {
        let spec = arch("x86_64").unwrap();
        let wrong_magic = synthetic_elf(spec, *b"AI\x02", false, false, None, false);
        assert!(validate_elf_bytes(&wrong_magic, "fixture", "x86_64", *b"RI\x02").is_err());
        let missing = synthetic_elf(spec, *b"RI\x02", false, false, Some(".upd_info"), false);
        assert!(validate_elf_bytes(&missing, "fixture", "x86_64", *b"RI\x02").is_err());
        let interp = synthetic_elf(spec, *b"RI\x02", true, false, None, false);
        assert!(validate_elf_bytes(&interp, "fixture", "x86_64", *b"RI\x02").is_err());
        let needed = synthetic_elf(spec, *b"RI\x02", false, true, None, false);
        assert!(validate_elf_bytes(&needed, "fixture", "x86_64", *b"RI\x02").is_err());
        let mut extended = synthetic_elf(spec, *b"RI\x02", false, false, None, false);
        put_u16(&mut extended, 56, PN_XNUM, spec.order);
        assert!(validate_elf_bytes(&extended, "fixture", "x86_64", *b"RI\x02").is_err());
    }

    #[test]
    fn exclusive_staging_refuses_to_clobber() {
        let root = tempfile::tempdir().unwrap();
        let destination = root.path().join("artifact");
        fs::write(&destination, b"existing").unwrap();
        assert!(write_exclusive(&destination, b"replacement", 0o755).is_err());
        assert_eq!(fs::read(destination).unwrap(), b"existing");
    }

    #[test]
    fn release_json_requires_exact_unique_manifest() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("release.json");
        let names = public_artifact_names();
        let write_manifest = |names: &[String]| {
            fs::write(
                &path,
                serde_json::to_vec(
                    &names
                        .iter()
                        .map(|name| serde_json::json!({"name": name}))
                        .collect::<Vec<_>>(),
                )
                .unwrap(),
            )
            .unwrap();
        };
        write_manifest(&names);
        validate_release(&path).unwrap();

        write_manifest(&names[..53]);
        assert!(validate_release(&path).is_err());
        let mut duplicate = names.clone();
        duplicate[53] = duplicate[0].clone();
        write_manifest(&duplicate);
        assert!(validate_release(&path).is_err());
        let mut unexpected = names.clone();
        unexpected[53] = "uruntime-unexpected-x86_64".to_string();
        write_manifest(&unexpected);
        assert!(validate_release(&path).is_err());
    }

    #[test]
    fn paginated_release_helpers_extract_positive_ids_and_reject_invalid_ones() {
        let root = tempfile::tempdir().unwrap();
        let releases = root.path().join("releases.json");
        fs::write(
            &releases,
            br#"[[{"id":17,"tag_name":"v1"}],[{"id":18,"tag_name":"v2"}]]"#,
        )
        .unwrap();
        assert_eq!(release_id(&releases, "v1").unwrap(), Some(17));
        assert_eq!(release_id(&releases, "missing").unwrap(), None);
        let assets = root.path().join("assets.json");
        let output = root.path().join("ids");
        fs::write(&assets, br#"[[{"id":9}],[{"id":12}]]"#).unwrap();
        write_asset_ids(&assets, &output).unwrap();
        assert_eq!(fs::read_to_string(output).unwrap(), "9\n12\n");

        for invalid in [
            r#"[[{"id":0,"tag_name":"v1"}]]"#,
            r#"[[{"id":"17","tag_name":"v1"}]]"#,
            r#"[[{"id":17,"tag_name":"v1"},{"id":18,"tag_name":"v1"}]]"#,
        ] {
            fs::write(&releases, invalid).unwrap();
            assert!(release_id(&releases, "v1").is_err(), "accepted {invalid}");
        }
        for invalid in [r#"[[{"id":0}]]"#, r#"[[{"id":"9"}]]"#, r#"{}"#] {
            fs::write(&assets, invalid).unwrap();
            let invalid_output = root.path().join(format!("invalid-{}", invalid.len()));
            assert!(
                write_asset_ids(&assets, &invalid_output).is_err(),
                "accepted {invalid}"
            );
        }
    }

    fn populate_arch(directory: &Path, spec: ArtifactArch) {
        fs::create_dir_all(directory).unwrap();
        for name in public_artifact_names_for_arch(spec.name) {
            let magic = if name.starts_with("uruntime-appimage") {
                *b"AI\x02"
            } else {
                *b"RI\x02"
            };
            fs::write(
                directory.join(name),
                synthetic_elf(spec, magic, false, false, None, false),
            )
            .unwrap();
        }
    }

    #[test]
    fn architecture_validation_requires_exact_regular_manifest() {
        let root = tempfile::tempdir().unwrap();
        populate_arch(root.path(), arch("ppc64").unwrap());
        validate_arch(root.path(), "ppc64", false).unwrap();
        fs::write(root.path().join("stale-file"), b"stale").unwrap();
        assert!(validate_arch(root.path(), "ppc64", false).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn artifact_roots_and_files_reject_symlinks() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().unwrap();
        let real = root.path().join("real");
        fs::create_dir(&real).unwrap();
        let linked = root.path().join("linked");
        symlink(&real, &linked).unwrap();
        assert!(directory_files(&linked).is_err());

        let target = real.join("target");
        fs::write(&target, b"not trusted through a link").unwrap();
        let artifact = real.join("artifact");
        symlink("target", &artifact).unwrap();
        assert!(read_regular(&artifact, MAX_ARTIFACT_SIZE).is_err());
    }

    #[test]
    fn release_aggregation_requires_six_inputs_and_stages_exactly_fifty_four() {
        let root = tempfile::tempdir().unwrap();
        let downloads = root.path().join("downloads");
        let release = root.path().join("release");
        fs::create_dir(&downloads).unwrap();
        for spec in ARTIFACT_ARCHES {
            populate_arch(&downloads.join(format!("uruntime-{}", spec.name)), spec);
        }
        aggregate_release(&downloads, &release).unwrap();
        assert_eq!(directory_files(&release).unwrap().len(), 54);

        let stale = downloads.join("stale-artifact");
        fs::create_dir(&stale).unwrap();
        assert!(aggregate_release(&downloads, &root.path().join("second-release")).is_err());
    }

    #[test]
    fn bounded_metadata_and_file_size_are_rejected() {
        let root = tempfile::tempdir().unwrap();
        let oversized = root.path().join("oversized");
        File::create(&oversized)
            .unwrap()
            .set_len((MAX_ARTIFACT_SIZE + 1) as u64)
            .unwrap();
        assert!(read_regular(&oversized, MAX_ARTIFACT_SIZE).is_err());

        let spec = arch("x86_64").unwrap();
        let mut sections = synthetic_elf(spec, *b"RI\x02", false, false, None, false);
        put_u16(
            &mut sections,
            60,
            (MAX_SECTION_HEADERS + 1) as u16,
            spec.order,
        );
        assert!(validate_elf_bytes(&sections, "fixture", "x86_64", *b"RI\x02").is_err());

        let mut programs = synthetic_elf(spec, *b"RI\x02", false, false, None, false);
        put_u16(
            &mut programs,
            56,
            (MAX_PROGRAM_HEADERS + 1) as u16,
            spec.order,
        );
        assert!(validate_elf_bytes(&programs, "fixture", "x86_64", *b"RI\x02").is_err());
    }

    fn compile_smoke_fixture(source: &str, destination: &Path) {
        let status = Command::new("rustc")
            .args(["--edition=2021", "-O", "-o"])
            .arg(destination)
            .arg(project_root().join(source))
            .status()
            .unwrap();
        assert!(status.success());
    }

    #[test]
    fn smoke_uses_private_rust_executable_and_enforces_output_limit() {
        let root = tempfile::tempdir().unwrap();
        let good = root.path().join("good");
        compile_smoke_fixture("tests/fixtures/smoke_version.rs", &good);
        smoke_validated_bytes(
            arch("x86_64").unwrap(),
            "uruntime-runimage-x86_64",
            &fs::read(good).unwrap(),
        )
        .unwrap();

        let noisy = root.path().join("noisy");
        compile_smoke_fixture("tests/fixtures/smoke_noisy.rs", &noisy);
        let error = smoke_validated_bytes(
            arch("x86_64").unwrap(),
            "uruntime-runimage-x86_64",
            &fs::read(noisy).unwrap(),
        )
        .unwrap_err();
        assert!(error.to_string().contains("output limit"));
    }
}
