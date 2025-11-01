use std::{
    thread::{sleep, spawn},
    process::{exit, Command},
    env::{self, current_exe},
    str, path::{PathBuf, Path},
    time::{self, Duration, Instant},
    hash::{DefaultHasher, Hash, Hasher},
    io::{Error, ErrorKind::{NotFound, InvalidData}, Read, Write, Result, Seek, SeekFrom},
    os::unix::{prelude::PermissionsExt, fs::{symlink, MetadataExt}, process::CommandExt},
    fs::{self, File, Permissions, create_dir, create_dir_all, remove_dir, remove_dir_all, remove_file, set_permissions, read_to_string},
};

macro_rules! get_env_var {
    ($var:literal) => {
        std::env::var($var).unwrap_or_default()
    };
    ($($arg:tt)*) => {
        {
            let env_name = format!($($arg)*);
            std::env::var(env_name).unwrap_or_default()
        }
    };
}

use cfg_if::cfg_if;
use which::which_all;
use xxhash_rust::xxh3::xxh3_64;
use goblin::elf::{Elf, SectionHeader};
use memfd_exec::{MemFdExecutable, Stdio};
use nix::unistd::{access, fork, setsid, getcwd, AccessFlags, ForkResult, Pid};
use signal_hook::{consts::{SIGINT, SIGTERM, SIGQUIT, SIGHUP}, iterator::Signals};
use nix::{libc, sys::{wait::waitpid, signal::{Signal, kill}}, mount::umount, errno::Errno};

const _LINUX_CAPABILITY_VERSION_3: u32 = 0x20080522;
const URUNTIME_VERSION: &str = env!("CARGO_PKG_VERSION");

const URUNTIME_MOUNT: &str = "URUNTIME_MOUNT=3";
const URUNTIME_CLEANUP: &str = "URUNTIME_CLEANUP=1";
const URUNTIME_EXTRACT: &str = "URUNTIME_EXTRACT=3";

const REUSE_CHECK_DELAY: &str = "5s";
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
        const ENV_NAME: &str = "APPIMAGE";
        const SELF_NAME: &str = "AppImage";
    } else {
        const ARG_PFX: &str = "runtime";
        const ENV_NAME: &str = "RUNIMAGE";
        const SELF_NAME: &str = "RunImage";
    }
}

#[repr(C)]
struct CapHeader {
    version: u32,
    pid: i32,
}
#[repr(C)]
struct CapData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

#[derive(Debug)]
struct Runtime {
    path: PathBuf,
    size: u64,
    headers_bytes: Vec<u8>,
    envs: String,
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
    if get_env_var!("MALLOC_CONF").is_empty() {
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

fn add_to_path(path: &PathBuf) {
    let old_path = get_env_var!("PATH");
    if old_path.is_empty() {
        env::set_var("PATH", path)
    } else {
        let new_path = path.to_str().unwrap();
        if !old_path.contains(new_path) {
            env::set_var("PATH", format!("{new_path}:{old_path}"))
        }
    }
}

fn restore_capabilities() {
    let mut caps = CapHeader { version: _LINUX_CAPABILITY_VERSION_3, pid: 0 };
    let mut cap_data = CapData { effective: 0, permitted: 0, inheritable: 0 };
    if unsafe { libc::syscall(libc::SYS_capget, &mut caps, &mut cap_data) } == 0 {
        let last_cap = std::fs::read_to_string("/proc/sys/kernel/cap_last_cap")
            .ok()
            .and_then(|s| s.trim().parse::<u32>().ok())
            .unwrap_or(39);
        let all_caps = (1u64 << (last_cap + 1)) - 1;
        cap_data.effective = all_caps as u32;
        cap_data.permitted = all_caps as u32;
        cap_data.inheritable = all_caps as u32;
        unsafe { libc::syscall(libc::SYS_capset, &caps, &cap_data) };
        for cap in 0..=last_cap {
            unsafe { libc::prctl(libc::PR_CAP_AMBIENT, libc::PR_CAP_AMBIENT_RAISE, cap, 0, 0) };
        }
    } else {
        eprintln!("Warning: failed to get capabilities: {}", Error::last_os_error())
    }
}

fn try_make_mount_private() -> bool {
    unsafe {
        libc::mount(
            c"none".as_ptr(),
            c"/".as_ptr(),
            c"none".as_ptr(),
            libc::MS_REC | libc::MS_PRIVATE,
            std::ptr::null()
        ) == 0
    }
}

fn try_unshare(uid: u32, gid: u32, unshare_uid: &str, unshare_gid: &str) -> bool {
    let target_uid = unshare_uid.parse().unwrap_or(uid);
    let target_gid = unshare_gid.parse().unwrap_or(gid);
    let flags = libc::CLONE_NEWUSER | libc::CLONE_NEWNS;
    let result = unsafe { libc::unshare(flags) };
    if result == 0 {
        let _ = fs::write("/proc/self/setgroups", "deny");
        let uid_map = format!("{target_uid} {uid} 1");
        let gid_map = format!("{target_gid} {gid} 1");
        if fs::write("/proc/self/uid_map", uid_map).is_ok() &&
           fs::write("/proc/self/gid_map", gid_map).is_ok() {
            restore_capabilities();
            if !try_make_mount_private() {
                eprintln!("Warning: failed to make mount private: {}", Error::last_os_error())
            }
            return true
        }
    }
    eprintln!("Failed to create user and mount namespaces: {}", Error::last_os_error());
    false
}

fn is_in_user_and_mount_namespace() -> bool {
    let uid_map = match read_to_string("/proc/self/uid_map") {
        Ok(content) => content,
        Err(_) => return false,
    };
    let uid_map = uid_map.trim();
    if uid_map.is_empty() || uid_map.split_whitespace().collect::<Vec<_>>() == vec!["0", "0", "4294967295"] {
        return false
    }
    let lines: Vec<&str> = uid_map.lines().collect();
    if lines.is_empty() {
        return false
    }
    for line in lines {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() == 3 {
            if let Ok(count) = parts[2].parse::<u32>() {
                if count < 4294967295 {
                    return try_make_mount_private()
                }
            }
        }
    }
    false
}

fn check_fuse(uruntime: &Path, uid: u32, gid: u32, unshare_uid: &str, unshare_gid: &str, unshare_succeeded: &mut bool) -> bool {
    if access("/dev/fuse", AccessFlags::R_OK).is_err() ||
       access("/dev/fuse", AccessFlags::W_OK).is_err() {
        return false
    }
    if uid == 0 || *unshare_succeeded || is_in_user_and_mount_namespace() { return true }
    fn create_fusermount_dir(tmp_path_dir: &PathBuf) -> bool {
        if !tmp_path_dir.is_dir() {
            if let Err(err) = create_dir_all(tmp_path_dir) {
                eprintln!("Failed to create fusermount PATH dir: {err}: {:?}", tmp_path_dir);
                return false
            }
            add_to_path(tmp_path_dir);
        }
        true
    }
    fn create_fusermount_symlink(tmp_path_dir: &Path, fusermount_path: &str, fusermount_name: &str) -> bool {
        let fsmntlink_path = tmp_path_dir.join(fusermount_name);
        let _ = remove_file(&fsmntlink_path);
        if let Err(err) = symlink(fusermount_path, &fsmntlink_path) {
            eprintln!("Failed to create fusermount symlink: {err}: {:?}", fsmntlink_path);
            return false
        }
        true
    }
    let mut is_fusermount = true;
    let fusermount_list = ["fusermount", "fusermount3"];
    let tmp_path_dir = &PathBuf::from(format!("/tmp/.path{uid}"));
    if tmp_path_dir.is_dir() {
        let uruntime_path = uruntime.canonicalize().ok();
        for fusermount in fusermount_list {
            let old_symlink = tmp_path_dir.join(fusermount);
            if old_symlink.exists() {
                if let Ok(canonical_path) = old_symlink.canonicalize() {
                    if is_suid_exe(&canonical_path).unwrap_or(false) {
                        continue
                    }
                    if let Some(ref uruntime_canonical) = uruntime_path {
                        if canonical_path == *uruntime_canonical {
                            continue
                        }
                    }
                }
                let _ = remove_file(&old_symlink);
            }
        }
        add_to_path(tmp_path_dir)
    }
    let fusermount_prog = &get_env_var!("FUSERMOUNT_PROG");
    if is_suid_exe(&PathBuf::from(fusermount_prog)).unwrap_or(false) {
        if !create_fusermount_dir(tmp_path_dir) { exit(1) }
        if !create_fusermount_symlink(tmp_path_dir, fusermount_prog, &basename(fusermount_prog)) { exit(1) }
    } else {
        for fusermount in fusermount_list {
            if find_suid_exe(fusermount).is_some() {
                continue
            }
            let fallback: &str = if fusermount.ends_with("3")
                { "fusermount" } else { "fusermount3" };
            if let Some(fusermount_path) = find_suid_exe(fallback) {
                if !create_fusermount_dir(tmp_path_dir) { break }
                if !create_fusermount_symlink(tmp_path_dir, &fusermount_path.to_string_lossy(), fusermount) { break }
                break
            }
            is_fusermount = false
        }
    }
    if !is_fusermount {
        eprintln!("SUID fusermount not found in PATH, trying to unshare...");
        if try_unshare(uid, gid, unshare_uid, unshare_gid) {
            *unshare_succeeded = true;
            return true
        }
        for fusermount in fusermount_list {
            if !create_fusermount_dir(tmp_path_dir) { break }
            if !create_fusermount_symlink(tmp_path_dir, &uruntime.to_string_lossy(), fusermount) { break }
        }
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

fn get_section_index(elf: &Elf<'_>, section_name: &str) -> Result<usize> {
    let section_index = elf.section_headers
        .iter()
        .position(|sh| {
            if let Some(name) = elf.shdr_strtab.get_at(sh.sh_name)
                { name == section_name } else { false }
        })
        .ok_or(Error::new(InvalidData,
            format!("Section header with name '{section_name}' not found!")
        ))?;
    Ok(section_index)
}

fn get_section_header(headers_bytes: &[u8], section_name: &str) -> Result<SectionHeader> {
    let elf = Elf::parse(headers_bytes)
        .map_err(|err| Error::new(InvalidData, err))?;
    let section_index = get_section_index(&elf, section_name)?;
    Ok(elf.section_headers[section_index].clone())
}

fn get_section_data(headers_bytes: &[u8], section_name: &str) -> Result<String> {
    let section = &mut get_section_header(headers_bytes, section_name)?;
    let section_data = &headers_bytes[section.sh_offset as usize..(section.sh_offset + section.sh_size) as usize];
    if let Ok(data_str) = str::from_utf8(section_data) {
        Ok(data_str.trim().trim_matches('\0').into())
    } else {
        Err(Error::new(InvalidData,
            format!("Section data is not valid UTF-8: {section_name}")
        ))
    }
}

fn add_section_data(runtime: &Runtime, section_name: &str, exec_args: &[String]) -> Result<()> {
    if get_env_var!("TARGET_{}", ENV_NAME).is_empty() {
        env::set_var(format!("TARGET_{ENV_NAME}"), &runtime.path);
        mfd_exec("uruntime", &runtime.headers_bytes, exec_args.to_vec());
    }
    let section = get_section_header(&runtime.headers_bytes, section_name)?;
    let offset = section.sh_offset;
    let original_size = section.sh_size;
    let file_data: String;
    let string_bytes = if let Some(section_data) = exec_args.get(1) {
        if PathBuf::from(section_data).is_file() {
            file_data = read_to_string(section_data)?.trim().to_string();
            file_data.as_bytes()
        } else {
            section_data.as_bytes()
        }
    } else { &[] };
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
    let envs = if let Ok(section_index) = get_section_index(&elf, ".envs") {
        let section = &elf.section_headers[section_index];
        let section_data = &headers_bytes[section.sh_offset as usize..(section.sh_offset + section.sh_size) as usize];
        str::from_utf8(section_data).unwrap_or_default().trim_matches('\0').to_string()
    } else { "".into() };
    Ok(Runtime {
        path: path.to_path_buf(),
        headers_bytes,
        size: section_table_end.max(last_section_end),
        envs,
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

fn is_mount_point(path: &Path) -> Result<bool> {
    let full_path = &path.canonicalize().unwrap_or_default();
    let metadata = fs::metadata(full_path)?;
    let device_id = metadata.dev();
    match full_path.parent() {
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

fn is_suid_exe(path: &PathBuf) -> Result<bool> {
    let metadata = fs::metadata(path)?;
    let permissions = metadata.permissions();
    let mode = permissions.mode();
    Ok((mode & 0o4000 != 0) && (mode & 0o111 != 0))
}

fn find_suid_exe(name: &str) -> Option<PathBuf> {
    for path in which_all(name).ok()? {
        let canonical_path = path.canonicalize().ok()?;
        if is_suid_exe(&canonical_path).unwrap_or(false) {
            return Some(canonical_path)
        }
    }
    None
}

fn is_dir_inuse(mount_point: &PathBuf) -> Result<bool> {
    for entry in fs::read_dir("/proc")? {
        if let Ok(target) = fs::read_link(entry?.path().join("exe")) {
            if target.starts_with(mount_point) {
                return Ok(true)
            }
        }
    }
    Ok(false)
}

fn wait_dir_notuse(
    mount_point: &PathBuf,
    timeout: Option<Duration>,
    delay: Option<Duration>,
    delay_check: bool) -> bool {
    let start_time = Instant::now();
    let default_delay = Duration::from_millis(100);
    let delay = delay.unwrap_or(default_delay);
    loop {
        if delay_check {
            sleep(delay);
            for num_check in 1..=5 {
                if is_dir_inuse(mount_point).unwrap_or(false)
                { break } else { sleep(default_delay * 2) }
                if num_check == 5 { return true }
            }
        } else {
            if !is_dir_inuse(mount_point).unwrap_or(false) {
                return true
            }
            if let Some(timeout) = timeout {
                if start_time.elapsed() >= timeout {
                    return false
                }
            }
        }
        sleep(delay)
    }
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

fn try_unmount(fuse_pid: Option<Pid>, mount_point: &Path) -> bool {
    if !is_mount_point(mount_point).unwrap_or(false)
        {
            eprintln!("{:?}: not mounted!", mount_point);
            return false
        }

    let mut is_busy = false;

    let res = umount(mount_point);
    if res.is_ok() { return true }
    else if let Err(e) = res {
        if e == nix::Error::from(Errno::EBUSY) {
            is_busy = true
        }
    }

    fn handle_command(cmd: &str, args: &Vec<&str>) -> (bool, bool) {
        let res = Command::new(cmd).args(args).output();
        if let Ok(output) = res {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            if !stdout.is_empty() { println!("{stdout}") }
            if !stderr.is_empty() { eprintln!("{stderr}") }
            return (
                output.status.success(),
                stderr.to_ascii_lowercase().contains("busy") || stdout.to_ascii_lowercase().contains("busy")
            )
        } else { eprintln!("Failed to execute {cmd}: {}", res.err().unwrap()) }
        (false, false)
    }

    let args = vec![mount_point.to_str().unwrap_or_default()];
    let mut fusermount_args= args.clone();
    fusermount_args.insert(0, "-u");

    for fusermount in &["fusermount", "fusermount3"] {
        if is_busy { break }
        let (success, busy) = handle_command(fusermount, &fusermount_args);
        if success { return true } else if busy { is_busy = true }
    }

    if !is_busy {
        let (success, busy) = handle_command("umount", &args);
        if success { return true } else if busy { is_busy = true }
    }

    if let Some(fuse_pid) = fuse_pid {
        if !is_busy && kill(fuse_pid, Signal::SIGTERM).is_ok() { return true }
    }

    eprintln!("Failed to unmount: {:?}", mount_point);
    if fuse_pid.is_some() && is_mount_point(mount_point).unwrap_or(false) {
        eprintln!("Unmount it manually!");
    }
    false
}

fn wait_mount(pid: Pid, path: &PathBuf, timeout: Duration) -> bool {
    let start_time = Instant::now();
    spawn(move || waitpid(pid, None) );
    while !is_mount_point(path).unwrap_or(false) {
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
    let option_env = get_env_var!("{}", option);
    if option_env.is_empty() {
        default.into()
    } else {
        let opts: Vec<&str> = option_env.split(',').collect();
        opts.first().unwrap_or(&default).to_string()
    }
}

#[cfg(feature = "dwarfs")]
fn get_dwfs_cachesize() -> String {
    get_dwfs_option("DWARFS_CACHESIZE",
    &if let Ok(meminfo) = <procfs::Meminfo as procfs::Current>::current() {
        let available_memory = meminfo.mem_available.unwrap_or(meminfo.mem_free) as f64;
        let available_memory_mb = available_memory / 1024.0 / 1024.0 / 1.3;
        let cache_sizes_mb: [u32; 10] = [1536, 1024, 896, 768, 640, 512, 384, 256, 128, 64];
        let cache_size_mb = cache_sizes_mb
            .iter()
            .find(|threshold| available_memory_mb > (**threshold as f64)).copied()
            .unwrap_or(32);
        format!("{}M", cache_size_mb)
    } else {
        DWARFS_CACHESIZE.into()
    })
}

#[cfg(feature = "dwarfs")]
fn get_dwfs_workers(cachesize: &str, cpus: usize) -> String {
    get_dwfs_option("DWARFS_WORKERS", &match cachesize {
        "1536M"|"1024M" => { cpus }
        "896M" => { 2 }
        _ => { 1 }
    }.to_string())
}

fn mount_image(embed: &Embed, image: &Image, mount_dir: PathBuf, uid: u32, gid: u32) {
    if is_mount_point(&mount_dir).unwrap_or(false) {
        return
    }
    let mount_dir = mount_dir.to_str().unwrap().to_string();
    let image_path = image.path.to_str().unwrap().to_string();
    if image.is_dwar {
        #[cfg(feature = "dwarfs")]
        {
            let cpus = num_cpus::get();
            let cachesize = get_dwfs_cachesize();
            let workers = get_dwfs_workers(&cachesize, cpus);
            let mut exec_args = vec![
                image_path, mount_dir, "-f".into(),
                "-o".into(), format!("uid={uid},gid={gid}"),
                "-o".into(), format!("offset={},cachesize={cachesize},workers={workers}", image.offset),
                "-o".into(), "ro,nodev,tidy_strategy=time,seq_detector=1,cache_files".into(),
                "-o".into(), format!("blocksize={}", get_dwfs_option("DWARFS_BLOCKSIZE", DWARFS_BLOCKSIZE)),
                "-o".into(), format!("readahead={}", get_dwfs_option("DWARFS_READAHEAD", DWARFS_READAHEAD)),
            ];
            match cachesize.as_str() {
                "1536M"|"1024M" => { exec_args.append(&mut vec!["-o".into(), "clone_fd,tidy_interval=2s,tidy_max_age=10s".into()]); }
                _ => { exec_args.append(&mut vec!["-o".into(), "tidy_interval=500ms,tidy_max_age=1s".into()]); }
            }
            if get_env_var!("ENABLE_FUSE_DEBUG") == "1" {
                exec_args.append(&mut vec!["-o".into(), "debuglevel=debug".into()]);
            } else {
                exec_args.append(&mut vec!["-o".into(), "debuglevel=error".into()]);
            }
            if get_env_var!("DWARFS_PRELOAD_ALL") == "1" {
                exec_args.append(&mut vec!["-o".into(), "preload_all".into()]);
            } else {
                exec_args.append(&mut vec!["-o".into(), "preload_category=hotness".into()]);
            }
            let dwarfs_analysis_file = get_env_var!("DWARFS_ANALYSIS_FILE");
            if !dwarfs_analysis_file.is_empty() {
                exec_args.append(&mut vec!["-o".into(), format!("analysis_file={dwarfs_analysis_file}")]);
            }
            if get_env_var!("DWARFS_USE_MMAP") == "1" {
                exec_args.append(&mut vec!["-o".into(), "block_allocator=mmap".into()]);
            } else {
                exec_args.append(&mut vec!["-o".into(), "block_allocator=malloc".into()]);
            }
            embed.dwarfs(exec_args)
        }
    } else {
        #[cfg(feature = "squashfs")]
        {
            let mut exec_args = vec![
                image_path, mount_dir, "-f".into(),
                "-o".into(), "ro,nodev".into(),
                "-o".into(), format!("uid={uid},gid={gid}"),
                "-o".into(), format!("offset={}", image.offset)
            ];
            if get_env_var!("ENABLE_FUSE_DEBUG") == "1" {
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
            let cachesize = get_dwfs_cachesize();
            let mut exec_args = vec![
                "--input".into(), image_path,
                "--log-level=error".into(),
                format!("--cache-size={cachesize}"),
                format!("--image-offset={}", image.offset),
                format!("--num-workers={}", get_dwfs_workers(&cachesize, num_cpus::get())),
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

fn try_set_portable_dir(dir: &PathBuf, env_var: &str, default_path: Option<&str>) {
    let real_env_var = format!("REAL_{}", env_var);
    if dir.is_dir() {
        if get_env_var!("{}", real_env_var).is_empty() {
            if let Ok(current_value) = env::var(env_var) {
                env::set_var(&real_env_var, current_value);
            } else if let Some(default) = default_path {
                if let Ok(home) = env::var("HOME") {
                    let default_dir = PathBuf::from(home).join(default);
                    env::set_var(&real_env_var, default_dir);
                }
            }
        }
        eprintln!("Setting ${} to {:?}", env_var, dir);
        env::set_var(env_var, dir);
    }
}

fn parse_reuse_check_delay(delay: &str) -> Option<Duration> {
    if delay == "inf" { return None }
    let default_delay = Some(Duration::from_secs(1));
    let mut chars = delay.chars();
    let mut num_part = String::new();
    while let Some(c) = chars.next() {
        if c.is_ascii_digit() {
            num_part.push(c);
        } else {
            let suffix = c.to_lowercase();
            if chars.next().is_some() {
                return default_delay;
            }
            let num: u64 = num_part.parse().unwrap_or(1);
            let multiplier = match suffix.to_string().as_str() {
                "s" => 1,
                "m" => 60,
                "h" => 3600,
                _ => return default_delay,
            };
            return Some(Duration::from_secs(num * multiplier))
        }
    }
    if !num_part.is_empty() {
        num_part.parse().ok().map(Duration::from_secs)
    } else { default_delay }
}

fn try_read_dotenv(dotenv_path: &PathBuf, dotenv_string: &str) {
    fn try_unset_env_data(data: &str) {
        for string in data.trim().split('\n') {
            let string = string.trim();
            if string.starts_with("unset ") {
                for var_name in string.split_whitespace().skip(1) {
                    env::remove_var(var_name);
                }
            }
        }
    }
    if !dotenv_string.is_empty() {
        dotenv::from_string(dotenv_string).ok();
        try_unset_env_data(dotenv_string)
    }
    if dotenv_path.is_file() {
        dotenv::from_path(dotenv_path).ok();
        if let Ok(data) = read_to_string(dotenv_path) {
            eprintln!("Read env file: {:?}", dotenv_path.display());
            try_unset_env_data(&data)
        } else {
            eprintln!("Failed to read env file: {:?}", dotenv_path.display())
        }
    }
}

fn signals_handler(pid: Pid, mount_point: &Path, selfexit: bool) {
    let sig_list = [SIGINT, SIGTERM, SIGQUIT, SIGHUP];
    let mut signals = match Signals::new(sig_list) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Failed to register signal handlers: {e}");
            return
        }
    };
    let _handle = signals.handle();
    for signal in signals.forever() {
        if sig_list.contains(&signal) {
            try_unmount(Some(pid), mount_point);
            unsafe {
                for &sig in sig_list.iter() {
                    libc::signal(sig, libc::SIG_DFL);
                }
            }
            if selfexit { exit(0) };
            break
        }
    }
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

fn print_usage(portable_home: &PathBuf, portable_share: &PathBuf, portable_config: &PathBuf, portable_cache: &PathBuf, self_exe_dotenv: &PathBuf) {
    println!("{} v{URUNTIME_VERSION}
   Repository: {}

   Runtime options:
    --{ARG_PFX}-extract [PATTERN]          Extract content from embedded filesystem image
                                             If pattern is passed, only extract matching files
     --{ARG_PFX}-extract-and-run [ARGS]    Run the {SELF_NAME} afer extraction without using FUSE
     --{ARG_PFX}-offset                    Print byte offset to start of embedded filesystem image
     --{ARG_PFX}-portable-home             Create a portable home folder to use as $HOME
     --{ARG_PFX}-portable-share            Create a portable share folder to use as $XDG_DATA_HOME
     --{ARG_PFX}-portable-config           Create a portable config folder to use as $XDG_CONFIG_HOME
     --{ARG_PFX}-portable-cache            Create a portable cache folder to use as $XDG_CACHE_HOME
     --{ARG_PFX}-help                      Print this help
     --{ARG_PFX}-unshare                   Try to use unshare user and mount namespaces
     --{ARG_PFX}-version                   Print version of Runtime
     --{ARG_PFX}-signature                 Print digital signature embedded in {SELF_NAME}
     --{ARG_PFX}-addsign    'SIGN|/file'   Add digital signature to {SELF_NAME}
     --{ARG_PFX}-updateinfo[rmation]       Print update info embedded in {SELF_NAME}
     --{ARG_PFX}-addupdinfo 'INFO|/file'   Add update info to {SELF_NAME}
     --{ARG_PFX}-envs                      Print environment variables embedded in {SELF_NAME}
     --{ARG_PFX}-addenvs    'ENVS|/file'   Add environment variables to {SELF_NAME}
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

      for portable-share:
      {:?}

      for portable-config:
      {:?}

      for portable-cache:
      {:?}

      Or you can invoke this {SELF_NAME} with the --{ARG_PFX}-portable-home or
      --{ARG_PFX}-portable-share or --{ARG_PFX}-portable-config or
      --{ARG_PFX}-portable-cache option, which will create this directory for you.
      As long as the directory exists and is neither moved nor renamed, the
      application contained inside this {SELF_NAME} to store its data in this
      directory rather than in your home directory", portable_home, portable_share, portable_config, portable_cache);

    println!("\n    Environment variables:

      URUNTIME                       Path to uruntime
      URUNTIME_DIR                   Path to uruntime directory
      {ENV_NAME}_UNSHARE=1             Try to use unshare user and mount namespaces
      {ENV_NAME}_UNSHARE_ROOT=1        Map to root (UID 0, GID 0) in user namespace
      {ENV_NAME}_UNSHARE_UID=0         Map to specified UID in user namespace
      {ENV_NAME}_UNSHARE_GID=0         Map to specified GID in user namespace
      {ENV_NAME}_EXTRACT_AND_RUN=1     Run the {SELF_NAME} afer extraction without using FUSE
      NO_CLEANUP=1                   Do not clear the unpacking directory after closing when
                                       using extract and run option for reuse extracted data
      NO_UNMOUNT=1                   Do not unmount the mount directory after closing
                                      for reuse mount point
      TMPDIR=/path                   Specifies a custom path for mounting or extracting the image
      {ENV_NAME}_TARGET_DIR=/path      Specifies the exact path for mounting or extracting the image
      REUSE_CHECK_DELAY=5s           Specifies the delay between checks of using the image dir (0|inf|1|1s|1m|1h)
      FUSERMOUNT_PROG=/path          Specifies a custom path for fusermount
      ENABLE_FUSE_DEBUG=1            Enables debug mode for the mounted filesystem
      TARGET_{ENV_NAME}=/path          Operate on a target {SELF_NAME} rather than this file itself
      NO_MEMFDEXEC=1                 Do not use memfd-exec (use a temporary file instead)");
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
    println!("
      Environment variables can be specified in the env file (see https://crates.io/crates/dotenv)
      and environment variables can also be deleted using `unset ENV_VAR` in the end of the env file:
      {0:?}
      You can also embed environment variables directly into runtime using the --{ARG_PFX}-addenvs option."
      , self_exe_dotenv)
}

fn main() {
    let embed = Embed::new();

    let mut exec_args: Vec<String> = env::args().collect();
    let arg0 = &exec_args.remove(0);
    let arg0_name = &basename(arg0);

    match arg0_name.as_str() {
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
        "fusermount" | "fusermount3"    => {
            let mut umount = false;
            let mut mount_point = String::new();
            for arg in &exec_args {
                if arg == "-u" || arg == "--unmount" { umount = true }
                else if !arg.starts_with('-') {
                    mount_point = arg.clone();
                    break
                }
            }
            let current_path = env::var("PATH").unwrap_or_default();
            let filtered_path = current_path
                .split(':')
                .filter(|path| !path.starts_with("/tmp/.path"))
                .collect::<Vec<_>>()
                .join(":");
            env::set_var("PATH", filtered_path);
            drop(current_path);
            if umount && !mount_point.is_empty() {
                if !try_unmount(None, Path::new(&mount_point))
                    { exit(1) } return
            }
            let err = Command::new(arg0_name)
                .args(&exec_args).exec();
            eprintln!("Failed to execute {arg0_name}: {err}");
            exit(1)
         }
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

    let uruntime = &current_exe().unwrap();
    let target_image = &PathBuf::from(get_env_var!("TARGET_{}", ENV_NAME));
    let self_exe = if target_image.is_file() { target_image } else { uruntime };

    let runtime = get_runtime(self_exe).unwrap_or_else(|err|{
        eprintln!("Failed to get runtime: {err}");
        exit(1)
    });
    let runtime_size = runtime.size;

    let uruntime_dir = uruntime.parent().unwrap();
    let self_exe_dir = self_exe.parent().unwrap();
    let self_exe_name = self_exe.file_name().unwrap().to_str().unwrap();

    let portable_home = &self_exe_dir.join(format!("{self_exe_name}.home"));
    let portable_share = &self_exe_dir.join(format!("{self_exe_name}.share"));
    let portable_config = &self_exe_dir.join(format!("{self_exe_name}.config"));
    let portable_cache = &self_exe_dir.join(format!("{self_exe_name}.cache"));

    env::set_var("URUNTIME", uruntime);
    env::set_var("URUNTIME_DIR", uruntime_dir);

    let self_exe_dotenv = &self_exe_dir.join(format!("{self_exe_name}.env"));
    try_read_dotenv(self_exe_dotenv, &runtime.envs);

    let mut is_unshare = false;
    let mut is_mount_only = false;
    let mut is_extract_run = false;
    let mut is_noclenup = !matches!(URUNTIME_CLEANUP.replace("URUNTIME_CLEANUP=", "=").as_str(), "=1");

    if get_env_var!("{}_EXTRACT_AND_RUN", ENV_NAME) == "1" {
        is_extract_run = true
    }

    if !arg1.is_empty() {
        match arg1 {
            arg if arg == format!("--{ARG_PFX}-help") => {
                print_usage(portable_home, portable_share, portable_config, portable_cache, self_exe_dotenv);
                return
            }
            arg if arg == format!("--{ARG_PFX}-portable-home") => {
                if let Err(err) = create_dir(portable_home) {
                    eprintln!("Failed to create portable home directory: {:?}: {err}", portable_home)
                }
                println!("Portable home directory created: {:?}", portable_home);
                return
            }
            arg if arg == format!("--{ARG_PFX}-portable-share") => {
                if let Err(err) = create_dir(portable_share) {
                    eprintln!("Failed to create portable share directory: {:?}: {err}", portable_share)
                }
                println!("Portable share directory created: {:?}", portable_share);
                return
            }
            arg if arg == format!("--{ARG_PFX}-portable-config") => {
                if let Err(err) = create_dir(portable_config) {
                    eprintln!("Failed to create portable config directory: {:?}: {err}", portable_config)
                }
                println!("Portable config directory created: {:?}", portable_config);
                return
            }
            arg if arg == format!("--{ARG_PFX}-portable-cache") => {
                if let Err(err) = create_dir(portable_cache) {
                    eprintln!("Failed to create portable cache directory: {:?}: {err}", portable_cache)
                }
                println!("Portable cache directory created: {:?}", portable_cache);
                return
            }
            arg if arg == format!("--{ARG_PFX}-offset") => {
                println!("{runtime_size}");
                return
            }
            arg if arg == format!("--{ARG_PFX}-updateinfo") ||
                           arg == format!("--{ARG_PFX}-updateinformation") => {
                let updateinfo = get_section_data(&runtime.headers_bytes, ".upd_info")
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
                let signature = get_section_data(&runtime.headers_bytes, ".sha256_sig")
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
            arg if arg == format!("--{ARG_PFX}-envs") => {
                println!("{}", runtime.envs);
                return
            }
            arg if arg == format!("--{ARG_PFX}-addenvs") => {
                if let Err(err) = add_section_data(&runtime, ".envs", &exec_args) {
                    eprintln!("Failed to add envs: {err}");
                    exit(1)
                };
                return
            }
            ref arg if arg == &format!("--{ARG_PFX}-extract-and-run") => {
                exec_args.remove(0);
                is_extract_run = true
            }
            ref arg if arg == &format!("--{ARG_PFX}-unshare") => {
                exec_args.remove(0);
                is_unshare = true
            }
            _ => {}
        }
    }

    let image = get_image(self_exe, runtime_size).unwrap_or_else(|err|{
        eprintln!("Failed to get image: {err}");
        exit(1)
    });

    if !arg1.is_empty() {
        match arg1 {
            arg if arg == format!("--{ARG_PFX}-extract") => {
                extract_image(&embed, &image, PathBuf::from("."),
                    false, exec_args.get(1));
                return
            }
            arg if arg == format!("--{ARG_PFX}-mount") => {
                is_mount_only = true
            }
            _ => {}
        }
    }

    let uruntime_extract =
    match URUNTIME_EXTRACT.replace("URUNTIME_EXTRACT=", "=").as_str() {
        "=1" => { is_extract_run = true; 1 }
        "=2" => { 2 }
        "=3" => { 3 }
        _ => { 0 }
    };

    let mut reuse_check_delay = get_env_var!("REUSE_CHECK_DELAY");

    let (mut is_remp_mount, default_delay) =
    match URUNTIME_MOUNT.replace("URUNTIME_MOUNT=", "=").as_str() {
        "=0" => (true, if is_extract_run { Some(REUSE_CHECK_DELAY) } else { Some("inf") }),
        "=1" => (false, None),
        "=2" => (true, Some("30m")),
        "=3" => (true, Some(REUSE_CHECK_DELAY)),
        _ => (false, None),
    };

    if let Some(default) = default_delay {
        if reuse_check_delay.is_empty() {
            reuse_check_delay = default.into();
        } else if reuse_check_delay == "0" {
            is_remp_mount = false
        }
    };

    let target_dir = get_env_var!("{}_TARGET_DIR", ENV_NAME);
    let mut tmp_dir: PathBuf;
    let tmp_dirs: Vec<&PathBuf>;
    #[cfg(not(feature = "appimage"))]
    let ruid_dir: PathBuf;
    #[cfg(not(feature = "appimage"))]
    let mnt_dir: PathBuf;

    let uid: u32 = unsafe { libc::getuid() };
    let gid = unsafe { libc::getgid() };

    if target_dir.is_empty() {
        tmp_dir = env::temp_dir();
        let mut self_hash = "".to_string();
        let first5name: String = self_exe_name.split(".").next()
        .unwrap_or(self_exe_name).chars().take(5).collect();
        if is_extract_run || is_remp_mount {
            self_hash = hash_string(&(
                xxh3_64(&runtime.headers_bytes) as u32 +
                fast_hash_file(&image.path, image.offset).unwrap_or_else(|err|{
                    eprintln!("Failed to get image hash: {err}");
                    exit(1)}) +
                uid
            ).to_string())
        }

        cfg_if! {
            if #[cfg(feature = "appimage")] {
                let tmp_dir_name: String = if is_extract_run && !is_mount_only {
                    format!("appimage_extracted_{first5name}{self_hash}")
                } else if is_remp_mount {
                    format!(".mount_{first5name}remp{self_hash}")
                } else {
                    format!(".mount_{first5name}{}", random_string(6))
                };
                tmp_dir = tmp_dir.join(tmp_dir_name);
                tmp_dirs = vec![&tmp_dir];
            } else {
                ruid_dir = tmp_dir.join(format!(".r{uid}"));
                 mnt_dir = ruid_dir.join("mnt");
                let tmp_dir_name: String = if is_extract_run && !is_mount_only {
                    format!("{first5name}extr{self_hash}")
                } else if is_remp_mount {
                    format!("{first5name}remp{self_hash}")
                } else {
                    format!("{first5name}{}", random_string(6))
                };
                tmp_dir = mnt_dir.join(tmp_dir_name);
                tmp_dirs = vec![&tmp_dir, &mnt_dir, &ruid_dir];
            }
        }
        drop(first5name);
    } else {
        env::remove_var(format!("{ENV_NAME}_TARGET_DIR"));
        tmp_dir = PathBuf::from(target_dir);
        tmp_dirs = vec![&tmp_dir]
    }

    drop(runtime);

    let unshare_var = get_env_var!("{}_UNSHARE", ENV_NAME);
    let unshare_root = get_env_var!("{}_UNSHARE_ROOT", ENV_NAME);
    let (unshare_uid, unshare_gid) = if unshare_root == "1" { ("0".into(), "0".into()) }
    else { (get_env_var!("{}_UNSHARE_UID", ENV_NAME), get_env_var!("{}_UNSHARE_GID", ENV_NAME)) };
    let should_unshare = is_unshare
        || unshare_var == "1"
        || unshare_root == "1"
        || !unshare_uid.is_empty()
        || !unshare_gid.is_empty();
    let mut unshare_succeeded = if should_unshare {
        try_unshare(uid, gid, &unshare_uid, &unshare_gid)
    } else { false  };

    if (!is_extract_run || is_mount_only) &&
    !check_fuse(uruntime, uid, gid, &unshare_uid, &unshare_gid, &mut unshare_succeeded) {
        check_extract!(is_mount_only, uruntime_extract, self_exe, {
            is_extract_run = true
        });
    }
    drop(unshare_var); drop(unshare_uid); drop(unshare_gid);

    if is_mount_only {
        is_extract_run = false
    } else if is_extract_run {
        is_noclenup = get_env_var!("NO_CLEANUP") == "1"
    }

    if !is_extract_run && get_env_var!("NO_UNMOUNT") == "1" {
        is_remp_mount = true;
        reuse_check_delay = "inf".into()
    }

    let is_tmpdir_exists = is_mount_point(&tmp_dir).unwrap_or(false) ||
        if let Ok(dir) = tmp_dir.read_dir() {
            dir.flatten().any(|entry|entry.path().exists())
        } else { false };

    match unsafe { fork() } {
        Ok(ForkResult::Parent { child: child_pid }) => {
            if !is_tmpdir_exists {
                if is_extract_run {
                    if let Err(err) = waitpid(child_pid, None) {
                        eprintln!("Failed to extract image: {err}");
                        remove_tmp_dirs(tmp_dirs);
                        exit(1)
                    }
                } else if !wait_mount(child_pid, &tmp_dir, Duration::from_secs(1)) {
                    remove_tmp_dirs(tmp_dirs);
                    check_extract!(is_mount_only, uruntime_extract, self_exe, {
                        let err = Command::new(self_exe)
                            .env(format!("{ENV_NAME}_EXTRACT_AND_RUN"), "1")
                            .args(&exec_args)
                            .exec();
                        eprintln!("Failed to exec: {:?}: {err}", self_exe);
                    });
                    exit(1)
                }
            } else { spawn(move || waitpid(child_pid, None) ); }

            if is_mount_only {
                if unshare_succeeded { println!("/proc/{child_pid}/root{}", tmp_dir.display()) }
                else { println!("{}", tmp_dir.display()) }
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

                try_set_portable_dir(portable_share, "XDG_DATA_HOME", Some(".local/share"));
                try_set_portable_dir(portable_config, "XDG_CONFIG_HOME", Some(".config"));
                try_set_portable_dir(portable_cache, "XDG_CACHE_HOME", Some(".cache"));
                try_set_portable_dir(portable_home, "HOME", None);

                let mut cmd = Command::new(run.canonicalize().unwrap())
                    .args(&exec_args).spawn().unwrap();
                let pid = Pid::from_raw(cmd.id() as i32);
                let tmp_dir_clone = tmp_dir.clone();
                spawn(move || signals_handler(pid, &tmp_dir_clone, false) );

                if let Ok(status) = cmd.wait() {
                    if let Some(code) = status.code() {
                        exit_code = code
                    }
                }
            } else if !is_tmpdir_exists {
                let tmp_dir_clone = tmp_dir.clone();
                spawn(move || signals_handler(child_pid, &tmp_dir_clone, false) );
                wait_pid_exit(child_pid, None);
            } else { exit(0) }

            if is_tmpdir_exists { exit(exit_code) } else {
                match unsafe { fork() } {
                    Ok(ForkResult::Parent { child: _ }) => { exit(exit_code) }
                    Ok(ForkResult::Child) => {
                        try_setsid();
                        if unshare_succeeded { restore_capabilities() }

                        let tmp_dir_clone = tmp_dir.clone();
                        spawn(move || signals_handler(child_pid, &tmp_dir_clone, true) );

                        let is_mount = !is_extract_run && !is_mount_only;
                        let reuse_check_delay = parse_reuse_check_delay(&reuse_check_delay);

                        if is_extract_run {
                            if !is_noclenup && reuse_check_delay.is_some() {
                                wait_dir_notuse(&tmp_dir, None, reuse_check_delay, true);
                                let _ = remove_dir_all(&tmp_dir);
                            }
                        } else if !is_remp_mount && is_mount {
                            wait_dir_notuse(&tmp_dir, None, None, false);
                            try_unmount(Some(child_pid), &tmp_dir);
                        } else if is_remp_mount && is_mount && reuse_check_delay.is_some() {
                            wait_dir_notuse(&tmp_dir, None, reuse_check_delay, true);
                            try_unmount(Some(child_pid), &tmp_dir);
                        }
                        if is_mount {
                            wait_pid_exit(child_pid, Some(Duration::from_secs(1)));
                        }
                        remove_tmp_dirs(tmp_dirs);
                        exit(0)
                    }
                    Err(err) => {
                        eprintln!("Fork error: {err}");
                        exit(1)
                    }
                }
            }
        }
        Ok(ForkResult::Child) => {
            if !is_tmpdir_exists {
                try_setsid();
                if unshare_succeeded { restore_capabilities() }

                if let Err(err) = create_tmp_dirs(tmp_dirs) {
                    eprintln!("Failed to create tmp dir: {err}");
                    exit(1)
                }

                unsafe { libc::dup2(libc::STDERR_FILENO, libc::STDOUT_FILENO) };

                if is_extract_run {
                    extract_image(&embed, &image, tmp_dir, is_extract_run, None)
                } else {
                    mount_image(&embed, &image, tmp_dir, uid, gid)
                }
            } else { exit(0) }
        }
        Err(err) => {
            eprintln!("Fork error: {err}");
            exit(1)
        }
    }
}
