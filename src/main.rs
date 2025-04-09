use std::{
    str, path::PathBuf,
    thread::{sleep, spawn},
    process::{exit, Command},
    env::{self, current_exe},
    time::{self, Duration, Instant},
    hash::{DefaultHasher, Hash, Hasher},
    io::{Error, ErrorKind::{NotFound, InvalidData}, Read, Write, Result, Seek, SeekFrom},
    os::unix::{prelude::PermissionsExt, fs::{symlink, MetadataExt}, process::CommandExt},
    fs::{self, File, Permissions, create_dir, create_dir_all, remove_dir, remove_dir_all, remove_file, set_permissions},
};

use which::which;
use cfg_if::cfg_if;
use xxhash_rust::xxh3::xxh3_64;
use goblin::elf::{Elf, SectionHeader};
use memfd_exec::{MemFdExecutable, Stdio};
use nix::{libc, sys::{wait::waitpid, signal::{Signal, kill}}};
use nix::unistd::{access, fork, setsid, getcwd, AccessFlags, ForkResult, Pid};
use signal_hook::{consts::{SIGINT, SIGTERM, SIGQUIT, SIGHUP}, iterator::Signals};

const URUNTIME_VERSION: &str = env!("CARGO_PKG_VERSION");
const URUNTIME_MOUNT: &str = "URUNTIME_MOUNT=1";
const URUNTIME_CLEANUP: &str = "URUNTIME_CLEANUP=1";
const URUNTIME_EXTRACT: &str = "URUNTIME_EXTRACT=3";
const MAX_EXTRACT_SELF_SIZE: u64 = 350 * 1024 * 1024; // 350 MB
#[cfg(feature = "dwarfs")]
const DWARFS_CACHESIZE: &str = "1024M";
#[cfg(feature = "dwarfs")]
const DWARFS_BLOCKSIZE: &str = "512K";
#[cfg(feature = "dwarfs")]
const DWARFS_READAHEAD: &str = "32M";

cfg_if! {
    if #[cfg(feature = "appimage")] {
        const ARG_PFX: &str = "appimage";
        const SELF_NAME: &str = "AppImage";
    } else {
        const ARG_PFX: &str = "runtime";
        const SELF_NAME: &str = "RunImage";
    }
}

#[derive(Debug)]
struct Runtime {
    path: PathBuf,
    size: u64,
    headers_bytes: Vec<u8>,
}

#[derive(Debug)]
struct Image {
    path: PathBuf,
    offset: u64,
    is_squash: bool,
    is_dwar: bool,
}

#[derive(Debug)]
struct Embed {
    #[cfg(feature = "squashfs")]
    squashfuse: Vec<u8>,
    #[cfg(feature = "squashfs")]
    unsquashfs: Vec<u8>,
    #[cfg(all(not(feature = "lite"), feature = "squashfs"))]
    mksquashfs: Vec<u8>,
    #[cfg(feature = "dwarfs")]
    dwarfs_universal: Vec<u8>,
}

impl Embed {
    fn new() -> Self {
        cfg_if! {
            if #[cfg(feature = "upx")] {
                Embed {
                    #[cfg(feature = "squashfs")]
                    squashfuse: include_bytes!("../assets/squashfuse-upx").to_vec(),
                    #[cfg(feature = "squashfs")]
                    unsquashfs: include_bytes!("../assets/unsquashfs-upx").to_vec(),
                    #[cfg(all(not(feature = "lite"), feature = "squashfs"))]
                    mksquashfs: include_bytes!("../assets/mksquashfs-upx").to_vec(),
                    #[cfg(all(feature = "lite", feature = "dwarfs"))]
                    dwarfs_universal: include_bytes!("../assets/dwarfs-fuse-extract-upx").to_vec(),
                    #[cfg(all(not(feature = "lite"), feature = "dwarfs"))]
                    dwarfs_universal: include_bytes!("../assets/dwarfs-universal-upx").to_vec(),
                }
            } else {
                Embed {
                    #[cfg(feature = "squashfs")]
                    squashfuse: include_bytes!("../assets/squashfuse-zst").to_vec(),
                    #[cfg(feature = "squashfs")]
                    unsquashfs: include_bytes!("../assets/unsquashfs-zst").to_vec(),
                    #[cfg(all(not(feature = "lite"), feature = "squashfs"))]
                    mksquashfs: include_bytes!("../assets/mksquashfs-zst").to_vec(),
                    #[cfg(all(feature = "lite", feature = "dwarfs"))]
                    dwarfs_universal: include_bytes!("../assets/dwarfs-fuse-extract-zst").to_vec(),
                    #[cfg(all(not(feature = "lite"), feature = "dwarfs"))]
                    dwarfs_universal: include_bytes!("../assets/dwarfs-universal-zst").to_vec(),
                }
            }
        }
    }

    #[cfg(feature = "squashfs")]
    fn squashfuse(&self, exec_args: Vec<String>) {
        mfd_exec("squashfuse", &self.squashfuse, exec_args);
    }

    #[cfg(feature = "squashfs")]
    fn unsquashfs(&self, exec_args: Vec<String>) {
        mfd_exec("unsquashfs", &self.unsquashfs, exec_args);
    }

    #[cfg(feature = "squashfs")]
    fn sqfscat(&self, exec_args: Vec<String>) {
        mfd_exec("sqfscat", &self.unsquashfs, exec_args);
    }

    #[cfg(all(not(feature = "lite"), feature = "squashfs"))]
    fn mksquashfs(&self, exec_args: Vec<String>) {
        mfd_exec("mksquashfs", &self.mksquashfs, exec_args);
    }

    #[cfg(all(not(feature = "lite"), feature = "squashfs"))]
    fn sqfstar(&self, exec_args: Vec<String>) {
        mfd_exec("sqfstar", &self.mksquashfs, exec_args);
    }

    #[cfg(feature = "dwarfs")]
    fn dwarfs(&self, exec_args: Vec<String>) {
        mfd_exec("dwarfs", &self.dwarfs_universal, exec_args);
    }

    #[cfg(all(not(feature = "lite"), feature = "dwarfs"))]
    fn dwarfsck(&self, exec_args: Vec<String>) {
        mfd_exec("dwarfsck", &self.dwarfs_universal, exec_args);
    }

    #[cfg(all(not(feature = "lite"), feature = "dwarfs"))]
    fn mkdwarfs(&self, exec_args: Vec<String>) {
        mfd_exec("mkdwarfs", &self.dwarfs_universal, exec_args);
    }

    #[cfg(feature = "dwarfs")]
    fn dwarfsextract(&self, exec_args: Vec<String>) {
        mfd_exec("dwarfsextract", &self.dwarfs_universal, exec_args);
    }
}

fn mfd_exec(exec_name: &str, exec_bytes: &[u8], exec_args: Vec<String>) {
    env::set_var("LC_ALL", "C");
    if get_env_var("MALLOC_CONF").is_empty() {
        env::set_var("MALLOC_CONF", "background_thread:true,dirty_decay_ms:1000,muzzy_decay_ms:1000")
    }

    #[cfg(not(feature = "upx"))]
    fn decompress(exec_name: &str, data: &[u8]) -> Vec<u8> {
        if exec_name != "uruntime" {
            let mut decoder = zstd::stream::read::Decoder::new(data).unwrap();
            let mut decompressed_data = Vec::new();
            decoder.read_to_end(&mut decompressed_data).unwrap();
            decompressed_data
        } else { data.to_vec() }
    }
    #[cfg(not(feature = "upx"))]
    let exec_bytes = &decompress(exec_name, exec_bytes);

    let err = MemFdExecutable::new(exec_name, exec_bytes)
        .args(exec_args)
        .envs(env::vars())
        .exec(Stdio::inherit());
    eprintln!("Failed to execute {exec_name}: {err}");
    exit(1)
}

fn get_image(path: &PathBuf, offset: u64) -> Result<Image> {
    let mut file = File::open(path)?;
    let mut buff = [0u8; 4];
    file.seek(SeekFrom::Start(offset))?;
    let bytes_read = file.read(&mut buff)?;
    let mut image = Image {
        path: path.to_path_buf(),
        offset,
        is_dwar: false,
        is_squash: false
    };
    if bytes_read == 4 {
        let read_str = String::from_utf8_lossy(&buff);
        if read_str.contains("DWAR") {
            image.is_dwar = true
        } else if read_str.contains("hsqs") {
            image.is_squash = true
        }
    }
    if !image.is_squash && !image.is_dwar {
        return Err(Error::new(NotFound, "SquashFS or DwarFS image not found!"))
    }
    Ok(image)
}

fn get_env_var(var: &str) -> String {
    env::var(var).unwrap_or("".into())
}

fn add_to_path(path: &PathBuf) {
    let old_path = get_env_var("PATH");
    if old_path.is_empty() {
        env::set_var("PATH", path)
    } else {
        let new_path = path.to_str().unwrap();
        if !old_path.contains(new_path) {
            env::set_var("PATH", format!("{new_path}:{old_path}"))
        }
    }
}

fn check_fuse() -> bool {
    let mut is_fusermount = true;
    let tmp_path_dir = &PathBuf::from("/tmp/.path");
    if tmp_path_dir.is_dir() {
        add_to_path(tmp_path_dir)
    }
    let fusermount_prog = &get_env_var("FUSERMOUNT_PROG");
    if PathBuf::from(fusermount_prog).is_file() {
        if !tmp_path_dir.is_dir() {
            if let Err(err) = create_dir_all(tmp_path_dir) {
                eprintln!("Failed to create fusermount PATH dir: {err}: {:?}", tmp_path_dir);
                exit(1)
            }
            add_to_path(tmp_path_dir);
        }
        let fsmntlink_path = tmp_path_dir.join(basename(fusermount_prog));
        let _ = remove_file(&fsmntlink_path);
        if let Err(err) = symlink(fusermount_prog, &fsmntlink_path) {
            eprintln!("Failed to create fusermount symlink: {err}: {:?}", fsmntlink_path);
            exit(1)
        }
    } else {
        for fusermount in ["fusermount", "fusermount3"] {
            let fallback: &str = if fusermount.ends_with("3") {
                "fusermount"
            } else {
                "fusermount3"
            };
            if which(fusermount).is_err() {
                if let Ok(fusermount_path) = which(fallback) {
                    if !tmp_path_dir.is_dir() {
                        if let Err(err) = create_dir_all(tmp_path_dir) {
                            eprintln!("Failed to create fusermount fallback dir: {err}: {:?}", tmp_path_dir);
                            break
                        }
                    }
                    let fsmntlink_path = tmp_path_dir.join(fusermount);
                    let _ = remove_file(&fsmntlink_path);
                    if let Err(err) = symlink(fusermount_path, &fsmntlink_path) {
                        eprintln!("Failed to create fusermount fallback symlink: {err}: {:?}", tmp_path_dir);
                        break
                    }
                    add_to_path(tmp_path_dir);
                    break
                } else {
                    is_fusermount = false
                }
            }
        }
    }
    if access("/dev/fuse", AccessFlags::R_OK).is_err() ||
       access("/dev/fuse", AccessFlags::W_OK).is_err() || !is_fusermount {
        return false
    }
    true
}

macro_rules! check_extract {
    (
        $is_mount_only:expr,
        $uruntime_extract:expr,
        $self_exe:expr,
        $true_block:block
    ) => {
        eprintln!("{}: failed to utilize FUSE during startup!", basename($self_exe.to_str().unwrap()));
        let self_size = get_file_size($self_exe).unwrap_or_else(|err| {
            eprintln!("Failed to get self size: {err}");
            exit(1)
        });
        if !$is_mount_only && ($uruntime_extract == 2 || ($uruntime_extract == 3 &&
            self_size <= MAX_EXTRACT_SELF_SIZE)) {
            $true_block
        } else {
            eprintln!(
"Cannot mount {SELF_NAME}, please check your FUSE setup.
You might still be able to extract the contents of this {SELF_NAME}
if you run it with the --{ARG_PFX}-extract option
See https://github.com/AppImage/AppImageKit/wiki/FUSE
and run it with the --{ARG_PFX}-help option for more information");
            exit(1)
        }
    };
}

fn get_runtime(path: &PathBuf) -> Result<Runtime> {
    let mut file = File::open(path)?;
    let mut elf_header_raw = [0; 64];
    file.read_exact(&mut elf_header_raw)?;
    let section_table_offset = u64::from_le_bytes(elf_header_raw[40..48].try_into().unwrap()); // e_shoff
    let section_count = u16::from_le_bytes(elf_header_raw[60..62].try_into().unwrap()); // e_shnum
    let section_table_size = section_count as u64 * 64;
    let required_bytes = section_table_offset + section_table_size;
    let mut headers_bytes = vec![0; required_bytes as usize];
    file.seek(SeekFrom::Start(0))?;
    file.read_exact(&mut headers_bytes)?;
    let elf = Elf::parse(&headers_bytes)
        .map_err(|err| Error::new(InvalidData, err))?;
    let section_table_end =
        elf.header.e_shoff + (elf.header.e_shentsize as u64 * elf.header.e_shnum as u64);
    let last_section_end = elf
        .section_headers
        .last()
        .map(|section| section.sh_offset + section.sh_size)
        .unwrap_or(0);
    Ok(Runtime {
        path: path.to_path_buf(),
        headers_bytes: headers_bytes.clone(),
        size: section_table_end.max(last_section_end),
    })
}

fn random_string(length: usize) -> String {
    const CHARSET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let mut rng = time::SystemTime::now().duration_since(time::UNIX_EPOCH).unwrap().as_millis();
    let mut result = String::with_capacity(length);
    for _ in 0..length {
        rng = rng.wrapping_mul(48271).wrapping_rem(0x7FFFFFFF);
        let idx = (rng as u64 % CHARSET.len() as u64) as usize;
        result.push(CHARSET[idx] as char);
    }
    result
}

fn basename(path: &str) -> String {
    let pieces: Vec<&str> = path.rsplit('/').collect();
    pieces.first().unwrap().to_string()
}

fn is_mount_point(path: &PathBuf) -> Result<bool> {
    let metadata = fs::metadata(path)?;
    let device_id = metadata.dev();
    match path.parent() {
        Some(parent) => {
            let parent_metadata = fs::metadata(parent)?;
            Ok(device_id != parent_metadata.dev())
        }
        None => Ok(false)
    }
}

fn get_file_size(path: &PathBuf) -> Result<u64> {
    Ok(fs::metadata(path)?.len())
}

fn is_pid_exists(pid: Pid) -> bool {
    if PathBuf::from(format!("/proc/{pid}")).exists() {
        return true
    }
    false
}

fn wait_pid_exit(pid: Pid, timeout: Option<Duration>) -> bool {
    let start_time = Instant::now();
    while is_pid_exists(pid) {
        if let Some(timeout) = timeout {
            if start_time.elapsed() >= timeout {
                return false
            }
        }
        sleep(Duration::from_millis(10))
    }
    true
}

fn wait_mount(pid: Pid, path: &PathBuf, timeout: Duration) -> bool {
    let start_time = Instant::now();
    spawn(move || waitpid(pid, None) );
    while !path.exists() || !is_mount_point(path).unwrap_or(false) {
        if !is_pid_exists(pid) {
            return false
        } else if start_time.elapsed() >= timeout {
            eprintln!("Timeout reached while waiting for mount: {:?}", path);
            return false
        }
        sleep(Duration::from_millis(2))
    }
    true
}

fn try_setsid() {
    if let Err(err) = setsid() {
        eprintln!("Failed to call setsid: {err}");
        exit(1)
    }
}

fn remove_tmp_dirs(dirs: Vec<&PathBuf> ) {
    for dir in dirs {
        let _ = remove_dir(dir);
    }
}

fn create_tmp_dirs(dirs: Vec<&PathBuf>) -> Result<()> {
    if let Some(dir) = dirs.first() {
        create_dir_all(dir)?;
        for dir in dirs {
            if let Err(err) = set_permissions(dir, Permissions::from_mode(0o700)) {
                if let Some(os_error) = err.raw_os_error() {
                    if os_error != 30 { return Err(err) }
                }
            }
        }
        return Ok(());
    }
    Err(Error::last_os_error())
}

#[cfg(feature = "dwarfs")]
fn get_dwfs_option(option: &str, default: &str) -> String {
    let option_env = get_env_var(option);
    if option_env.is_empty() {
        default.into()
    } else {
        let opts: Vec<&str> = option_env.split(',').collect();
        opts.first().unwrap_or(&default).to_string()
    }
}

fn mount_image(embed: &Embed, image: &Image, mount_dir: PathBuf) {
    if is_mount_point(&mount_dir).unwrap_or(false) {
        return
    }
    let uid = unsafe { libc::getuid() };
    let gid = unsafe { libc::getgid() };
    let mount_dir = mount_dir.to_str().unwrap().to_string();
    let image_path = image.path.to_str().unwrap().to_string();
    if image.is_dwar {
        #[cfg(feature = "dwarfs")]
        {
            let mut exec_args = vec![
                image_path, mount_dir, "-f".into(),
                "-o".into(), "ro,nodev,noatime,clone_fd".into(),
                "-o".into(), "cache_files,no_cache_image".into(),
                "-o".into(), format!("cachesize={}", get_dwfs_option("DWARFS_CACHESIZE", DWARFS_CACHESIZE)),
                "-o".into(), format!("blocksize={}", get_dwfs_option("DWARFS_BLOCKSIZE", DWARFS_BLOCKSIZE)),
                "-o".into(), format!("readahead={}", get_dwfs_option("DWARFS_READAHEAD", DWARFS_READAHEAD)),
                "-o".into(), "tidy_strategy=time,tidy_interval=1s,tidy_max_age=2s,seq_detector=1".into(),
                "-o".into(), format!("workers={}", get_dwfs_option("DWARFS_WORKERS", &num_cpus::get().to_string())),
                "-o".into(), format!("uid={uid},gid={gid}"),
                "-o".into(), format!("offset={}", image.offset)
            ];
            if get_env_var("ENABLE_FUSE_DEBUG") == "1" {
                exec_args.append(&mut vec!["-o".into(), "debuglevel=debug".into()]);
            } else {
                exec_args.append(&mut vec!["-o".into(), "debuglevel=error".into()]);
            }
            if get_env_var("DWARFS_PRELOAD_ALL") == "1" {
                exec_args.append(&mut vec!["-o".into(), "preload_all".into()]);
            } else {
                exec_args.append(&mut vec!["-o".into(), "preload_category=hotness".into()]);
            }
            let dwarfs_analysis_file = get_env_var("DWARFS_ANALYSIS_FILE");
            if !dwarfs_analysis_file.is_empty() {
                exec_args.append(&mut vec!["-o".into(), format!("analysis_file={dwarfs_analysis_file}")]);
            }
            if get_env_var("DWARFS_USE_MMAP") == "1" {
                exec_args.append(&mut vec!["-o".into(), "block_allocator=mmap".into()]);
            }
            embed.dwarfs(exec_args)
        }
    } else {
        #[cfg(feature = "squashfs")]
        {
            let mut exec_args = vec![
                image_path, mount_dir, "-f".into(),
                "-o".into(), "ro,nodev,noatime".into(),
                "-o".into(), format!("uid={uid},gid={gid}"),
                "-o".into(), format!("offset={}", image.offset)
            ];
            if get_env_var("ENABLE_FUSE_DEBUG") == "1" {
                exec_args.append(&mut vec!["-o".into(), "debug".into()]);
            }
            embed.squashfuse(exec_args)
        }
    }
}

fn extract_image(embed: &Embed, image: &Image, mut extract_dir: PathBuf, is_extract_run: bool, pattern: Option<&String>) {
    if is_extract_run {
        if let Ok(dir) = extract_dir.read_dir() {
            if dir.flatten().any(|entry|entry.path().exists()) {
                return
            }
        }
    }

    cfg_if! {
        if #[cfg(feature = "appimage")] {
            let applink_dir = extract_dir.join("squashfs-root");
            if !is_extract_run {
                extract_dir = extract_dir.join("AppDir");
            }
        } else {
            if !is_extract_run {
                extract_dir = extract_dir.join("RunDir");
            }
        }
    }
    let extract_dir = extract_dir.to_str().unwrap().to_string();
    if let Err(err) = create_dir_all(&extract_dir) {
        eprintln!("Failed to create extract dir: {err}: {extract_dir}");
        exit(1)
    }
    #[cfg(feature = "appimage")]
    {
        if !is_extract_run {
            let _ = remove_file(&applink_dir);
            if let Err(err) = symlink(&extract_dir, &applink_dir) {
                eprintln!("Failed to create squashfs-root symlink to extract dir: {err}");
                exit(1)
            }
        }
    }
    let image_path = image.path.to_str().unwrap().to_string();
    if image.is_dwar {
        #[cfg(feature = "dwarfs")]
        {
            let mut exec_args = vec![
                "--input".into(), image_path,
                "--log-level=error".into(),
                format!("--cache-size={}", get_dwfs_option("DWARFS_CACHESIZE", DWARFS_CACHESIZE)),
                format!("--image-offset={}", image.offset),
                format!("--num-workers={}", get_dwfs_option("DWARFS_WORKERS", &num_cpus::get().to_string())),
                "--output".into(), extract_dir,
                "--stdout-progress".into()
            ];
            if let Some(pattern) = pattern {
                exec_args.append(&mut vec!["--pattern".into(), pattern.to_string()]);
            }
            embed.dwarfsextract(exec_args)
        }
    } else {
        #[cfg(feature = "squashfs")]
        {
            let mut exec_args = vec!["-f".into(),
                "-d".into(), extract_dir,
                "-o".into(), image.offset.to_string(),
                image_path
            ];
            if let Some(pattern) = pattern {
                exec_args.push(pattern.into())
            }
            embed.unsquashfs(exec_args)
        }
    }
}

fn try_set_portable(kind: &str, dir: &PathBuf) {
    if dir.exists() {
        match kind {
            "home" => {
                println!("Setting $HOME to {:?}", dir);
                env::set_var("HOME", dir)
            }
            "config" => {
                println!("Setting $XDG_CONFIG_HOME to {:?}", dir);
                env::set_var("XDG_CONFIG_HOME", dir)
            }
            _ => {}
        }
    }
}

fn signals_handler(pid: Pid) {
    let mut signals = Signals::new([SIGINT, SIGTERM, SIGQUIT]).unwrap();
    let _ = signals.handle();
    for signal in signals.forever() {
        match signal {
            SIGINT | SIGTERM | SIGQUIT | SIGHUP => {
                let _ = kill(pid, Signal::SIGTERM);
                break
            }
            _ => {}
        }
    }
}

fn get_section_header(headers_bytes: &[u8], section_name: &str) -> Result<SectionHeader> {
    let elf = Elf::parse(headers_bytes)
        .map_err(|err| Error::new(InvalidData, err))?;
    let section_index = elf.section_headers
        .iter()
        .position(|sh| {
            if let Some(name) = elf.shdr_strtab.get_at(sh.sh_name)
                { name == section_name } else { false }
        })
        .ok_or(Error::new(InvalidData,
            format!("Section header with name '{section_name}' not found!")
        ))?;
    Ok(elf.section_headers[section_index].clone())
}

fn get_section_data(headers_bytes: Vec<u8>, section_name: &str) -> Result<String> {
    let section = &mut get_section_header(&headers_bytes, section_name)?;
    let section_data = &headers_bytes[section.sh_offset as usize..(section.sh_offset + section.sh_size) as usize];
    if let Ok(data_str) = str::from_utf8(section_data) {
        Ok(data_str.trim().into())
    } else {
        Err(Error::new(InvalidData,
            format!("Section data is not valid UTF-8: {section_name}")
        ))
    }
}

fn add_section_data(runtime: &Runtime, section_name: &str, exec_args: &[String]) -> Result<()> {
    if get_env_var(&format!("TARGET_{}", SELF_NAME.to_uppercase())).is_empty() {
        env::set_var(format!("TARGET_{}", SELF_NAME.to_uppercase()), &runtime.path);
        mfd_exec("uruntime", &runtime.headers_bytes, exec_args.to_vec());
    }
    let section = get_section_header(&runtime.headers_bytes, section_name)?;
    let offset = section.sh_offset;
    let original_size = section.sh_size;
    let string_bytes = if let Some(section_data) = exec_args.get(1)
        { section_data.as_bytes() } else { &[] };
    let new_size = string_bytes.len() as u64;
    if new_size > original_size {
        return Err(Error::new(InvalidData,
            "New section header data is larger than the section size!"
        ));
    }
    let mut file = fs::OpenOptions::new()
        .write(true)
        .open(&runtime.path)?;
    file.seek(SeekFrom::Start(offset))?;
    file.write_all(string_bytes)?;
    if new_size < original_size {
        let padding_size = original_size - new_size;
        let padding = vec![0u8; padding_size as usize];
        file.write_all(&padding)?;
    }
    Ok(())
}

fn hash_string(data: &str) -> String {
    let mut hasher = DefaultHasher::new();
    data.hash(&mut hasher);
    hasher.finish().to_string()
}

fn fast_hash_file(path: &PathBuf, offset: u64) -> Result<u32> {
    let mut file = File::open(path)?;
    let file_size = get_file_size(path)?.saturating_sub(offset);
    let mut buffer = [0u8; 48];
    file.seek(SeekFrom::Start(offset))?;
    file.read_exact(&mut buffer[0..16])?;
    file.seek(SeekFrom::Start(file_size / 2))?;
    file.read_exact(&mut buffer[16..32])?;
    file.seek(SeekFrom::Start(file_size.saturating_sub(16)))?;
    file.read_exact(&mut buffer[32..48])?;
    Ok(xxh3_64(&buffer) as u32)
}

fn print_usage(portable_home: &PathBuf, portable_config: &PathBuf) {
    println!("{} v{URUNTIME_VERSION}
   Repository: {}

   Runtime options:
    --{ARG_PFX}-extract [PATTERN]          Extract content from embedded filesystem image
                                             If pattern is passed, only extract matching files
     --{ARG_PFX}-extract-and-run [ARGS]    Run the {SELF_NAME} afer extraction without using FUSE
     --{ARG_PFX}-offset                    Print byte offset to start of embedded filesystem image
     --{ARG_PFX}-portable-home             Create a portable home folder to use as $HOME
     --{ARG_PFX}-portable-config           Create a portable config folder to use as $XDG_CONFIG_HOME
     --{ARG_PFX}-help                      Print this help
     --{ARG_PFX}-version                   Print version of Runtime
     --{ARG_PFX}-signature                 Print digital signature embedded in {SELF_NAME}
     --{ARG_PFX}-addsign         'SIGN'    Add digital signature to {SELF_NAME}
     --{ARG_PFX}-updateinfo[rmation]       Print update info embedded in {SELF_NAME}
     --{ARG_PFX}-addupdinfo      'INFO'    Add update info to {SELF_NAME}
     --{ARG_PFX}-mount                     Mount embedded filesystem image and print
                                             mount point and wait for kill with Ctrl-C",
    env!("CARGO_PKG_DESCRIPTION"), env!("CARGO_PKG_REPOSITORY"));

    println!("\n    Embedded tools options:");
    #[cfg(feature = "squashfs")]
    println!("      --{ARG_PFX}-squashfuse    [ARGS]       Launch squashfuse");
    #[cfg(feature = "squashfs")]
    println!("      --{ARG_PFX}-unsquashfs    [ARGS]       Launch unsquashfs");
    #[cfg(feature = "squashfs")]
    println!("      --{ARG_PFX}-sqfscat       [ARGS]       Launch sqfscat");
    #[cfg(all(not(feature = "lite"), feature = "squashfs"))]
    println!("      --{ARG_PFX}-mksquashfs    [ARGS]       Launch mksquashfs");
    #[cfg(all(not(feature = "lite"), feature = "squashfs"))]
    println!("      --{ARG_PFX}-sqfstar       [ARGS]       Launch sqfstar");
    #[cfg(feature = "dwarfs")]
    println!("      --{ARG_PFX}-dwarfs        [ARGS]       Launch dwarfs");
    #[cfg(all(not(feature = "lite"), feature = "dwarfs"))]
    println!("      --{ARG_PFX}-dwarfsck      [ARGS]       Launch dwarfsck");
    #[cfg(all(not(feature = "lite"), feature = "dwarfs"))]
    println!("      --{ARG_PFX}-mkdwarfs      [ARGS]       Launch mkdwarfs");
    #[cfg(feature = "dwarfs")]
    println!("      --{ARG_PFX}-dwarfsextract [ARGS]       Launch dwarfsextract");
    println!("
      Also you can create a hardlink, symlink or rename the runtime with
      the name of the built-in utility to use it directly.");

    println!("\n    Portable home and config:

      If you would like the application contained inside this {SELF_NAME} to store its
      data alongside this {SELF_NAME} rather than in your home directory, then you can
      place a directory named

      for portable-home:
      {:?}

      for portable-config:
      {:?}

      Or you can invoke this {SELF_NAME} with the --{ARG_PFX}-portable-home or
      --{ARG_PFX}-portable-config option, which will create this directory for you.
      As long as the directory exists and is neither moved nor renamed, the
      application contained inside this {SELF_NAME} to store its data in this
      directory rather than in your home directory", portable_home, portable_config);

    println!("\n    Environment variables:

      {}_EXTRACT_AND_RUN=1      Run the {SELF_NAME} afer extraction without using FUSE
      NO_CLEANUP=1                   Do not clear the unpacking directory after closing when
                                       using extract and run option for reuse extracted data
      NO_UNMOUNT=1                   Do not unmount the mount directory after closing
                                      for reuse mount point
      TMPDIR=/path                   Specifies a custom path for mounting or extracting the image
      FUSERMOUNT_PROG=/path          Specifies a custom path for fusermount
      ENABLE_FUSE_DEBUG=1            Enables debug mode for the mounted filesystem
      TARGET_{}=/path          Operate on a target {SELF_NAME} rather than this file itself",
    ARG_PFX.to_uppercase(), SELF_NAME.to_uppercase());
    #[cfg(feature = "dwarfs")]
    {
    println!("      DWARFS_WORKERS=2               Number of worker threads for DwarFS (default: equal CPU threads)
      DWARFS_CACHESIZE=1024M         Size of the block cache, in bytes for DwarFS (suffixes K, M, G)
      DWARFS_BLOCKSIZE=512K          Size of the block file I/O, in bytes for DwarFS (suffixes K, M, G)
      DWARFS_READAHEAD=32M           Set readahead size, in bytes for DwarFS (suffixes K, M, G)
      DWARFS_PRELOAD_ALL=1           Enable preloading of all blocks from the DwarFS file system
      DWARFS_ANALYSIS_FILE=/path     A file for profiling open files when launching the application for DwarFS
      DWARFS_USE_MMAP=1              Use mmap for allocating blocks for DwarFS");
    }
}

fn main() {
    let embed = Embed::new();

    let mut exec_args: Vec<String> = env::args().collect();
    let arg0 = &exec_args.remove(0);

    match basename(arg0).as_str() {
        #[cfg(feature = "squashfs")]
        "squashfuse"       => { embed.squashfuse(exec_args); return }
        #[cfg(feature = "squashfs")]
        "unsquashfs"       => { embed.unsquashfs(exec_args); return }
        #[cfg(feature = "squashfs")]
        "sqfscat"       => { embed.sqfscat(exec_args); return }
        #[cfg(all(not(feature = "lite"), feature = "squashfs"))]
        "mksquashfs"       => { embed.mksquashfs(exec_args); return }
        #[cfg(all(not(feature = "lite"), feature = "squashfs"))]
        "sqfstar"       => { embed.sqfstar(exec_args); return }
        #[cfg(feature = "dwarfs")]
        "dwarfs"           => { embed.dwarfs(exec_args); return }
        #[cfg(all(not(feature = "lite"), feature = "dwarfs"))]
        "dwarfsck"         => { embed.dwarfsck(exec_args); return }
        #[cfg(all(not(feature = "lite"), feature = "dwarfs"))]
        "mkdwarfs"         => { embed.mkdwarfs(exec_args); return }
        #[cfg(feature = "dwarfs")]
        "dwarfsextract"    => { embed.dwarfsextract(exec_args); return }
        _ => {}
    }

    let arg1 = if !exec_args.is_empty() {
        exec_args[0].to_string()
    } else {"".into()};

    if !arg1.is_empty() {
        match arg1 {
            arg if arg == format!("--{ARG_PFX}-version") => {
                println!("v{URUNTIME_VERSION}");
                return
            }
            #[cfg(feature = "squashfs")]
            arg if arg == format!("--{ARG_PFX}-squashfuse") => {
                embed.squashfuse(exec_args[1..].to_vec());
                return
            }
            #[cfg(feature = "squashfs")]
            arg if arg == format!("--{ARG_PFX}-unsquashfs") => {
                embed.unsquashfs(exec_args[1..].to_vec());
                return
            }
            #[cfg(feature = "squashfs")]
            arg if arg == format!("--{ARG_PFX}-sqfscat") => {
                embed.sqfscat(exec_args[1..].to_vec());
                return
            }
            #[cfg(all(not(feature = "lite"), feature = "squashfs"))]
            arg if arg == format!("--{ARG_PFX}-mksquashfs") => {
                embed.mksquashfs(exec_args[1..].to_vec());
                return
            }
            #[cfg(all(not(feature = "lite"), feature = "squashfs"))]
            arg if arg == format!("--{ARG_PFX}-sqfstar") => {
                embed.sqfstar(exec_args[1..].to_vec());
                return
            }
            #[cfg(feature = "dwarfs")]
            arg if arg == format!("--{ARG_PFX}-dwarfs") => {
                embed.dwarfs(exec_args[1..].to_vec());
                return
            }
            #[cfg(all(not(feature = "lite"), feature = "dwarfs"))]
            arg if arg == format!("--{ARG_PFX}-dwarfsck") => {
                embed.dwarfsck(exec_args[1..].to_vec());
                return
            }
            #[cfg(all(not(feature = "lite"), feature = "dwarfs"))]
            arg if arg == format!("--{ARG_PFX}-mkdwarfs") => {
                embed.mkdwarfs(exec_args[1..].to_vec());
                return
            }
            #[cfg(feature = "dwarfs")]
            arg if arg == format!("--{ARG_PFX}-dwarfsextract") => {
                embed.dwarfsextract(exec_args[1..].to_vec());
                return
            }
            _ => {}
        }
    }

    let target_image = PathBuf::from(get_env_var(&format!("TARGET_{}", SELF_NAME.to_uppercase())));
    let self_exe = if target_image.is_file() { &target_image } else { &current_exe().unwrap() };

    let runtime = get_runtime(self_exe).unwrap_or_else(|err|{
        eprintln!("Failed to get runtime: {err}");
        exit(1)
    });
    let runtime_size = runtime.size;

    let mut is_mount_only = false;
    let mut is_extract_run = false;
    let mut is_noclenup = !matches!(URUNTIME_CLEANUP.replace("URUNTIME_CLEANUP=", "=").as_str(), "=1");
    let mut is_nounmount = !matches!(URUNTIME_MOUNT.replace("URUNTIME_MOUNT=", "=").as_str(), "=1");

    let mut tmp_dir = env::temp_dir();

    if get_env_var(&format!("{}_EXTRACT_AND_RUN", ARG_PFX.to_uppercase())) == "1" {
        is_extract_run = true
    }

    let self_exe_dir = self_exe.parent().unwrap();
    let self_exe_name = self_exe.file_name().unwrap().to_str().unwrap();

    let portable_home = &self_exe_dir.join(format!("{self_exe_name}.home"));
    let portable_config = &self_exe_dir.join(format!("{self_exe_name}.config"));

    if !arg1.is_empty() {
        match arg1 {
            arg if arg == format!("--{ARG_PFX}-help") => {
                print_usage(portable_home, portable_config);
                return
            }
            arg if arg == format!("--{ARG_PFX}-portable-home") => {
                if let Err(err) = create_dir(portable_home) {
                    eprintln!("Failed to create portable home directory: {:?}: {err}", portable_home)
                }
                println!("Portable home directory created: {:?}", portable_home);
                return
            }
            arg if arg == format!("--{ARG_PFX}-portable-config") => {
                if let Err(err) = create_dir(portable_config) {
                    eprintln!("Failed to create portable config directory: {:?}: {err}", portable_config)
                }
                println!("Portable config directory created: {:?}", portable_config);
                return
            }
            arg if arg == format!("--{ARG_PFX}-offset") => {
                println!("{runtime_size}");
                return
            }
            arg if arg == format!("--{ARG_PFX}-updateinfo") ||
                           arg == format!("--{ARG_PFX}-updateinformation") => {
                let updateinfo = get_section_data(runtime.headers_bytes, ".upd_info")
                    .unwrap_or_else(|err|{
                        eprintln!("Failed to get update info: {err}");
                        exit(1)
                });
                println!("{updateinfo}");
                return
            }
            arg if arg == format!("--{ARG_PFX}-addupdinfo") => {
                if let Err(err) = add_section_data(&runtime, ".upd_info", &exec_args) {
                    eprintln!("Failed to add update info: {err}");
                    exit(1)
                };
                return
            }
            arg if arg == format!("--{ARG_PFX}-signature") => {
                let signature = get_section_data(runtime.headers_bytes, ".sha256_sig")
                    .unwrap_or_else(|err|{
                        eprintln!("Failed to get signature info: {err}");
                        exit(1)
                });
                println!("{signature}");
                return
            }
            arg if arg == format!("--{ARG_PFX}-addsign") => {
                if let Err(err) = add_section_data(&runtime, ".sha256_sig", &exec_args) {
                    eprintln!("Failed to add signature info: {err}");
                    exit(1)
                };
                return
            }
            ref arg if arg == &format!("--{ARG_PFX}-extract-and-run") => {
                exec_args.remove(0);
                is_extract_run = true
            }
            _ => {}
        }
    }

    let image = get_image(self_exe, runtime_size).unwrap_or_else(|err|{
        eprintln!("Failed to get image: {err}");
        exit(1)
    });

    let uruntime_extract = match URUNTIME_EXTRACT.replace("URUNTIME_EXTRACT=", "=").as_str() {
        "=1" => { is_extract_run = true; 1 }
        "=2" => { 2 }
        "=3" => { 3 }
        _ => { 0 }
    };

    if (!is_extract_run || is_mount_only) && !check_fuse() {
        check_extract!(is_mount_only, uruntime_extract, self_exe, {
            is_extract_run = true
        });
    }

    if is_extract_run && get_env_var("NO_CLEANUP") == "1" {
        is_noclenup = true
    }

    if !is_extract_run && get_env_var("NO_UNMOUNT") == "1" {
        is_nounmount = true
    }

    let mut self_hash: String = "".into();
    if is_extract_run || is_nounmount {
        let uid = unsafe { libc::getuid() };
        self_hash = hash_string(&(
            xxh3_64(&runtime.headers_bytes) as u32 +
            fast_hash_file(&image.path, image.offset).unwrap_or_else(|err|{
                eprintln!("Failed to get image hash: {err}");
                exit(1)}) +
            uid
        ).to_string())
    }

    drop(runtime);

    cfg_if! {
        if #[cfg(feature = "appimage")] {
            let tmp_dir_name: String = if is_extract_run {
                format!("appimage_extracted_{self_hash}")
            } else if is_nounmount {
                format!(".mount_remp{self_hash}")
            } else {
                format!(".mount_{}", random_string(8))
            };
            tmp_dir = tmp_dir.join(tmp_dir_name);
            let tmp_dirs = vec![&tmp_dir];
        } else {
            let uid = unsafe { libc::getuid() };
            let ruid_dir = tmp_dir.join(format!(".r{uid}"));
            let mnt_dir = ruid_dir.join("mnt");
            let tmp_dir_name: String = if is_extract_run || is_nounmount {
                format!("remp{self_hash}")
            } else {
                random_string(8)
            };
            tmp_dir = mnt_dir.join(tmp_dir_name);
            let tmp_dirs = vec![&tmp_dir, &mnt_dir, &ruid_dir];
        }
    }

    if !arg1.is_empty() {
        match arg1 {
            arg if arg == format!("--{ARG_PFX}-extract") => {
                extract_image(&embed, &image, PathBuf::from("."),
                    false, exec_args.get(1));
                return
            }
            arg if arg == format!("--{ARG_PFX}-mount") => {
                println!("{}", tmp_dir.display());
                is_mount_only = true
            }
            _ => {}
        }
    }

    match unsafe { fork() } {
        Ok(ForkResult::Parent { child: child_pid }) => {
            if is_extract_run {
                if let Err(err) = waitpid(child_pid, None) {
                    eprintln!("Failed to extract image: {err}");
                    remove_tmp_dirs(tmp_dirs);
                    exit(1)
                }
            } else if !wait_mount(child_pid, &tmp_dir, Duration::from_millis(1000)) {
                remove_tmp_dirs(tmp_dirs);
                check_extract!(is_mount_only, uruntime_extract, self_exe, {
                    let err = Command::new(self_exe)
                        .env(format!("{}_EXTRACT_AND_RUN", ARG_PFX.to_uppercase()), "1")
                        .args(&exec_args)
                        .exec();
                    eprintln!("Failed to exec: {:?}: {err}", self_exe);
                });
                exit(1)
            }

            let mut exit_code = 143;
            if !is_mount_only {
                cfg_if! {
                    if #[cfg(feature = "appimage")] {
                        let run = tmp_dir.join("AppRun");
                        if !run.is_file() {
                            eprintln!("AppRun not found: {:?}", run);
                            remove_tmp_dirs(tmp_dirs);
                            exit(1)
                        }
                        env::set_var("ARGV0", arg0);
                        env::set_var("APPDIR", &tmp_dir);
                        env::set_var("APPIMAGE", self_exe);
                        env::set_var("APPOFFSET", format!("{runtime_size}"));
                    } else {
                        let run = tmp_dir.join("static").join("bash");
                        if !run.is_file() {
                            eprintln!("Static bash not found: {:?}", run);
                            remove_tmp_dirs(tmp_dirs);
                            exit(1)
                        }
                        exec_args.insert(0, format!("{}/Run.sh", tmp_dir.display()));
                        env::set_var("ARG0", arg0);
                        env::set_var("RUNDIR", &tmp_dir);
                        env::set_var("RUNIMAGE", self_exe);
                        env::set_var("RUNOFFSET", format!("{runtime_size}"));
                    }
                }
                env::set_var("OWD", getcwd().unwrap());

                try_set_portable("home", portable_home);
                try_set_portable("config", portable_config);

                let mut cmd = Command::new(run.canonicalize().unwrap())
                    .args(&exec_args).spawn().unwrap();
                let pid = Pid::from_raw(cmd.id() as i32);

                spawn(move || signals_handler(pid) );

                if let Ok(status) = cmd.wait() {
                    if let Some(code) = status.code() {
                        exit_code = code
                    }
                }
            } else {
                spawn(move || signals_handler(child_pid) );
                wait_pid_exit(child_pid, None);
            }

            match unsafe { fork() } {
                Ok(ForkResult::Parent { child: _ }) => { exit(exit_code) }
                Ok(ForkResult::Child) => {
                    try_setsid();

                    if !is_extract_run && !is_nounmount && !is_mount_only {
                        let _ = kill(child_pid, Signal::SIGTERM);
                    }
                    if is_extract_run {
                        if !is_noclenup {
                            let _ = remove_dir_all(&tmp_dir);
                        }
                    } else if !is_nounmount && !is_mount_only {
                        wait_pid_exit(child_pid, Some(Duration::from_millis(1000)));
                    }
                    remove_tmp_dirs(tmp_dirs);
                }
                Err(err) => {
                    eprintln!("Fork error: {err}");
                    exit(1)
                }
            }
        }
        Ok(ForkResult::Child) => {
            try_setsid();

            if let Err(err) = create_tmp_dirs(tmp_dirs) {
                eprintln!("Failed to create tmp dir: {err}");
                exit(1)
            }

            unsafe { libc::dup2(libc::STDERR_FILENO, libc::STDOUT_FILENO) };

            if is_extract_run {
                extract_image(&embed, &image, tmp_dir, is_extract_run, None)
            } else {
                mount_image(&embed, &image, tmp_dir)
            }
        }
        Err(err) => {
            eprintln!("Fork error: {err}");
            exit(1)
        }
    }
}
