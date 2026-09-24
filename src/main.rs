#![deny(
    clippy::expect_used,
    clippy::panic,
    clippy::todo,
    clippy::unimplemented,
    clippy::unreachable,
    clippy::unwrap_used
)]

use std::{
    env::{self, current_exe},
    ffi::{CStr, CString, OsStr},
    fs::{
        self, create_dir, create_dir_all, read_to_string, remove_dir, remove_dir_all, remove_file,
        set_permissions, DirBuilder, File, Metadata, Permissions,
    },
    hash::{DefaultHasher, Hash, Hasher},
    io::{
        Error,
        ErrorKind::{AlreadyExists, InvalidData, InvalidInput, NotFound, Other, Unsupported},
        Read, Result, Seek, SeekFrom, Write,
    },
    os::unix::{
        ffi::OsStrExt,
        fs::{symlink, DirBuilderExt, FileExt, MetadataExt, OpenOptionsExt},
        io::{AsRawFd, FromRawFd, OwnedFd, RawFd},
        prelude::PermissionsExt,
        process::CommandExt,
    },
    path::{Path, PathBuf},
    process::{exit, Command},
    str,
    thread::{sleep, spawn},
    time::{self, Duration, Instant},
};

use cfg_if::cfg_if;
use goblin::elf::{Elf, SectionHeader};
use memfd_exec::{MemFdExecutable, Stdio};
use nix::fcntl::{open, OFlag};
use nix::unistd::{access, close, fork, getcwd, setsid, AccessFlags, ForkResult, Pid};
use nix::{
    errno::Errno,
    libc,
    mount::{umount, umount2, MntFlags},
    sys::{
        signal::{kill, Signal},
        stat::Mode,
        wait::waitpid,
    },
};
use signal_hook::{
    consts::{SIGHUP, SIGINT, SIGQUIT, SIGTERM, SIGUSR1, SIGUSR2},
    iterator::Signals,
};
use which::which_all;
use xxhash_rust::xxh3::xxh3_64;

mod elf_layout;

const _LINUX_CAPABILITY_VERSION_3: u32 = 0x20080522;
const CAP_SYS_ADMIN: u32 = 21;
const SECBIT_NOROOT: libc::c_ulong = 1;
const SECBIT_NOROOT_LOCKED: libc::c_ulong = 2;
const URUNTIME_VERSION: &str = env!("CARGO_PKG_VERSION");

const URUNTIME_MOUNT: &str = "URUNTIME_MOUNT=3";
const URUNTIME_CLEANUP: &str = "URUNTIME_CLEANUP=1";
const URUNTIME_EXTRACT: &str = "URUNTIME_EXTRACT=3";
const URUNTIME_UNSHARE: &str = "URUNTIME_UNSHARE=0";

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

#[repr(C)]
struct CapHeader {
    version: u32,
    pid: i32,
}
#[repr(C)]
#[derive(Clone, Copy)]
struct CapData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FileIdentity {
    dev: u64,
    ino: u64,
}

impl FileIdentity {
    fn from_metadata(metadata: &Metadata) -> Self {
        Self {
            dev: metadata.dev(),
            ino: metadata.ino(),
        }
    }
}

#[derive(Debug)]
struct SelfExecutable {
    file: File,
    location: PathBuf,
    identity: FileIdentity,
    size: u64,
}

impl SelfExecutable {
    fn from_open_file(file: File, location: PathBuf) -> Result<Self> {
        let metadata = file.metadata()?;
        if !metadata.file_type().is_file() {
            return Err(Error::new(
                InvalidInput,
                format!(
                    "runtime executable {} is not a regular file",
                    location.display()
                ),
            ));
        }
        let identity = FileIdentity::from_metadata(&metadata);
        Ok(Self {
            file,
            location,
            identity,
            size: metadata.len(),
        })
    }

    fn open_path(path: &Path) -> Result<Self> {
        let file = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(path)?;
        Self::from_open_file(file, path.to_path_buf())
    }

    fn open_self(arg0: &str) -> Result<Self> {
        if let Ok(file) = File::open("/proc/self/exe") {
            let location = executable_path(arg0)?;
            return Self::from_open_file(file, location);
        }
        Self::open_path(&executable_path(arg0)?)
    }

    #[cfg(test)]
    fn read_all(&self) -> Result<Vec<u8>> {
        let len = usize::try_from(self.size)
            .map_err(|_| Error::new(InvalidData, "self executable does not fit in memory"))?;
        let mut bytes = vec![0; len];
        let mut offset = 0_usize;
        while offset < bytes.len() {
            let remaining = bytes
                .get_mut(offset..)
                .ok_or_else(|| Error::new(InvalidData, "self executable read offset is invalid"))?;
            let file_offset = u64::try_from(offset)
                .map_err(|_| Error::new(InvalidData, "self executable read offset overflows"))?;
            let read = self.file.read_at(remaining, file_offset)?;
            if read == 0 {
                return Err(Error::new(
                    InvalidData,
                    "self executable ended before its reported size",
                ));
            }
            offset = offset
                .checked_add(read)
                .ok_or_else(|| Error::new(InvalidData, "self executable read size overflows"))?;
        }
        Ok(bytes)
    }
}

fn open_optional_target_source(value: &str) -> Result<Option<SelfExecutable>> {
    if value.is_empty() {
        return Ok(None);
    }
    match SelfExecutable::open_path(Path::new(value)) {
        Ok(source) => Ok(Some(source)),
        Err(err) if err.kind() == NotFound => match fs::symlink_metadata(value) {
            Err(metadata_error) if metadata_error.kind() == NotFound => Ok(None),
            Ok(_) => Err(Error::new(
                InvalidInput,
                format!(
                    "target runtime executable {value} exists or changed while it was being opened"
                ),
            )),
            Err(metadata_error) => Err(metadata_error),
        },
        Err(err) => Err(err),
    }
}

#[derive(Debug)]
struct Runtime {
    path: PathBuf,
    identity: FileIdentity,
    size: u64,
    headers_bytes: Vec<u8>,
    envs: String,
}

#[derive(Debug)]
struct Image {
    file: File,
    path: PathBuf,
    offset: u64,
    is_squash: bool,
    is_dwar: bool,
}

#[derive(Debug, Eq, PartialEq)]
struct HelperSource {
    path: PathBuf,
    inherited_fd: Option<RawFd>,
}

impl HelperSource {
    fn prepare_for_exec(&self) -> Result<()> {
        let Some(fd) = self.inherited_fd else {
            return Ok(());
        };
        clear_fd_cloexec(fd)
    }
}

fn descriptor_source(file: &File, fd_roots: &[&Path], purpose: &str) -> Result<HelperSource> {
    let fd = file.as_raw_fd();
    let expected = FileIdentity::from_metadata(&file.metadata()?);
    for root in fd_roots {
        let fd_path = root.join(fd.to_string());
        if let Ok(metadata) = fd_path.metadata() {
            if FileIdentity::from_metadata(&metadata) == expected {
                return Ok(HelperSource {
                    path: fd_path,
                    inherited_fd: Some(fd),
                });
            }
        }
    }
    Err(Error::new(
        Unsupported,
        format!("no verified descriptor path is available for {purpose} fd {fd}"),
    ))
}

fn pathname_source(file: &File, path: &Path, purpose: &str) -> Result<HelperSource> {
    let expected = FileIdentity::from_metadata(&file.metadata()?);
    let current = File::open(path).map_err(|err| {
        Error::new(
            err.kind(),
            format!(
                "cannot verify pathname fallback for {purpose} at {}: {err}",
                path.display()
            ),
        )
    })?;
    if FileIdentity::from_metadata(&current.metadata()?) != expected {
        return Err(Error::new(
            InvalidData,
            format!(
                "refusing pathname fallback for {purpose}: {} no longer refers to the retained inode",
                path.display()
            ),
        ));
    }
    Ok(HelperSource {
        path: path.to_path_buf(),
        inherited_fd: None,
    })
}

impl Image {
    fn helper_path(&self) -> Result<String> {
        self.helper_path_with_fd_roots(&[Path::new("/proc/self/fd"), Path::new("/dev/fd")])
    }

    fn helper_path_with_fd_roots(&self, fd_roots: &[&Path]) -> Result<String> {
        let source = self.helper_source_with_fd_roots(fd_roots)?;
        source.prepare_for_exec()?;
        Ok(source.path.to_string_lossy().into_owned())
    }

    fn helper_source_with_fd_roots(&self, fd_roots: &[&Path]) -> Result<HelperSource> {
        descriptor_source(&self.file, fd_roots, "image")
            .or_else(|_| pathname_source(&self.file, &self.path, "image"))
    }
}

#[derive(Debug)]
struct Embed {
    #[cfg(feature = "squashfs")]
    squashfuse: &'static [u8],
    #[cfg(feature = "squashfs")]
    unsquashfs: &'static [u8],
    #[cfg(all(not(feature = "lite"), feature = "squashfs"))]
    mksquashfs: &'static [u8],
    #[cfg(feature = "dwarfs")]
    dwarfs_universal: &'static [u8],
}

impl Embed {
    fn new() -> Self {
        Embed {
            #[cfg(feature = "squashfs")]
            squashfuse: include_bytes!(concat!(env!("URUNTIME_HELPER_DIR"), "/squashfuse-zst")),
            #[cfg(feature = "squashfs")]
            unsquashfs: include_bytes!(concat!(env!("URUNTIME_HELPER_DIR"), "/unsquashfs-zst")),
            #[cfg(all(not(feature = "lite"), feature = "squashfs"))]
            mksquashfs: include_bytes!(concat!(env!("URUNTIME_HELPER_DIR"), "/mksquashfs-zst")),
            #[cfg(all(feature = "lite", feature = "dwarfs"))]
            dwarfs_universal: include_bytes!(concat!(
                env!("URUNTIME_HELPER_DIR"),
                "/dwarfs-fuse-extract-zst"
            )),
            #[cfg(all(not(feature = "lite"), feature = "dwarfs"))]
            dwarfs_universal: include_bytes!(concat!(
                env!("URUNTIME_HELPER_DIR"),
                "/dwarfs-universal-zst"
            )),
        }
    }

    #[cfg(feature = "squashfs")]
    fn squashfuse(&self, exec_args: Vec<String>) {
        mfd_exec("squashfuse", self.squashfuse, exec_args);
    }

    #[cfg(feature = "squashfs")]
    fn unsquashfs(&self, exec_args: Vec<String>) {
        mfd_exec("unsquashfs", self.unsquashfs, exec_args);
    }

    #[cfg(feature = "squashfs")]
    fn sqfscat(&self, exec_args: Vec<String>) {
        mfd_exec("sqfscat", self.unsquashfs, exec_args);
    }

    #[cfg(all(not(feature = "lite"), feature = "squashfs"))]
    fn mksquashfs(&self, exec_args: Vec<String>) {
        mfd_exec("mksquashfs", self.mksquashfs, exec_args);
    }

    #[cfg(all(not(feature = "lite"), feature = "squashfs"))]
    fn sqfstar(&self, exec_args: Vec<String>) {
        mfd_exec("sqfstar", self.mksquashfs, exec_args);
    }

    #[cfg(feature = "dwarfs")]
    fn dwarfs(&self, exec_args: Vec<String>) {
        mfd_exec("dwarfs", self.dwarfs_universal, exec_args);
    }

    #[cfg(all(not(feature = "lite"), feature = "dwarfs"))]
    fn dwarfsck(&self, exec_args: Vec<String>) {
        mfd_exec("dwarfsck", self.dwarfs_universal, exec_args);
    }

    #[cfg(all(not(feature = "lite"), feature = "dwarfs"))]
    fn mkdwarfs(&self, exec_args: Vec<String>) {
        mfd_exec("mkdwarfs", self.dwarfs_universal, exec_args);
    }

    #[cfg(feature = "dwarfs")]
    fn dwarfsextract(&self, exec_args: Vec<String>) {
        mfd_exec("dwarfsextract", self.dwarfs_universal, exec_args);
    }
}

fn mfd_exec(exec_name: &str, exec_bytes: &[u8], exec_args: Vec<String>) {
    env::set_var("LC_ALL", "C");
    if get_env_var!("MALLOC_CONF").is_empty() {
        env::set_var(
            "MALLOC_CONF",
            "background_thread:true,dirty_decay_ms:1000,muzzy_decay_ms:1000",
        )
    }

    fn decompress(exec_name: &str, data: &[u8]) -> Vec<u8> {
        if exec_name != "uruntime" {
            let mut decoder = zstd::stream::read::Decoder::new(data).unwrap_or_else(|err| {
                eprintln!("Failed to create decoder for decompress embed exe: {exec_name}: {err}");
                exit(1)
            });
            let mut decompressed_data = Vec::new();
            decoder
                .read_to_end(&mut decompressed_data)
                .unwrap_or_else(|err| {
                    eprintln!("Failed to decompress embed exe: {exec_name}: {err}");
                    exit(1)
                });
            decompressed_data
        } else {
            data.to_vec()
        }
    }
    let exec_bytes = &decompress(exec_name, exec_bytes);

    let err = MemFdExecutable::new(exec_name, exec_bytes)
        .args(exec_args)
        .envs(env::vars_os())
        .exec(Stdio::inherit());
    eprintln!("Failed to execute {exec_name}: {err}");
    exit(1)
}

fn get_image(executable: &SelfExecutable, offset: u64) -> Result<Image> {
    let mut buff = [0u8; 4];
    let bytes_read = executable.file.read_at(&mut buff, offset)?;
    let mut image = Image {
        file: executable.file.try_clone()?,
        path: executable.location.clone(),
        offset,
        is_dwar: false,
        is_squash: false,
    };
    if bytes_read == 4 {
        if buff == *b"DWAR" {
            image.is_dwar = true
        } else if buff == *b"hsqs" {
            image.is_squash = true
        }
    }
    if !image.is_squash && !image.is_dwar {
        return Err(Error::new(NotFound, "SquashFS or DwarFS image not found!"));
    }
    Ok(image)
}

fn add_to_path(path: &PathBuf) {
    let old_path = get_env_var!("PATH");
    if old_path.is_empty() {
        env::set_var("PATH", path)
    } else {
        let new_path = path.to_str().unwrap_or_default();
        if !old_path.contains(new_path) {
            env::set_var("PATH", format!("{new_path}:{old_path}"))
        }
    }
}

fn restore_capabilities() {
    let mut caps = CapHeader {
        version: _LINUX_CAPABILITY_VERSION_3,
        pid: 0,
    };
    let mut cap_data = [CapData {
        effective: 0,
        permitted: 0,
        inheritable: 0,
    }; 2];
    if unsafe { libc::syscall(libc::SYS_capget, &mut caps, cap_data.as_mut_ptr()) } == 0 {
        let last_cap = last_capability();
        let all_caps = last_cap
            .checked_add(1)
            .and_then(|width| 1_u64.checked_shl(width))
            .map_or(u64::MAX, |limit| limit.saturating_sub(1));
        if let Some(low) = cap_data.get_mut(0) {
            low.effective = all_caps as u32;
            low.permitted = all_caps as u32;
            low.inheritable = all_caps as u32;
        }
        if let Some(high) = cap_data.get_mut(1) {
            high.effective = (all_caps >> 32) as u32;
            high.permitted = (all_caps >> 32) as u32;
            high.inheritable = (all_caps >> 32) as u32;
        }
        unsafe { libc::syscall(libc::SYS_capset, &caps, cap_data.as_ptr()) };
        for cap in 0..=last_cap {
            unsafe { libc::prctl(libc::PR_CAP_AMBIENT, libc::PR_CAP_AMBIENT_RAISE, cap, 0, 0) };
        }
    } else {
        eprintln!(
            "Warning: failed to get capabilities: {}",
            Error::last_os_error()
        )
    }
}

fn last_capability() -> u32 {
    std::fs::read_to_string("/proc/sys/kernel/cap_last_cap")
        .ok()
        .and_then(|s| s.trim().parse::<u32>().ok())
        .unwrap_or(39)
        .min(63)
}

fn should_drop_capabilities(unshare_succeeded: bool, drop_caps: bool) -> bool {
    unshare_succeeded && drop_caps
}

fn embedded_unshare_policy(mode: &str) -> (bool, bool, bool) {
    match mode {
        "=1" => (true, false, false),
        "=2" => (true, true, false),
        "=3" => (false, false, true),
        _ => (false, false, false),
    }
}

fn fallback_should_drop_capabilities(
    fallback_unshare_succeeded: bool,
    drop_caps_on_fallback: bool,
) -> bool {
    fallback_unshare_succeeded && drop_caps_on_fallback
}

fn environment_drop_caps_policy(value: &str) -> (bool, bool, bool) {
    match value {
        "1" => (true, false, false),
        "2" => (true, true, false),
        "3" => (false, false, true),
        _ => (false, false, false),
    }
}

fn is_runtime_option(arg: &str, option: &str) -> bool {
    let Some(arg) = arg.strip_prefix("--") else {
        return false;
    };
    [ARG_PFX, "uruntime"].iter().any(|prefix| {
        arg.strip_prefix(prefix)
            .is_some_and(|arg| arg.strip_prefix('-') == Some(option))
    })
}

#[derive(Debug, Default, Eq, PartialEq)]
struct UnshareCliOptions {
    enable: bool,
    root: bool,
    uid: Option<String>,
    gid: Option<String>,
    drop_caps: bool,
    drop_caps_on_fallback: bool,
}

fn unshare_option_suffix<'a>(arg: &'a str, format_base: &str) -> Option<&'a str> {
    match arg.strip_prefix(format_base) {
        Some(suffix) => Some(suffix),
        None => arg.strip_prefix("--uruntime-unshare"),
    }
}

fn parse_unshare_cli_options(
    args: &mut Vec<String>,
    prefix: &str,
) -> std::result::Result<UnshareCliOptions, String> {
    let format_base = format!("--{prefix}-unshare");
    if !args
        .iter()
        .take_while(|arg| arg.as_str() != "--")
        .any(|arg| unshare_option_suffix(arg, &format_base).is_some())
    {
        return Ok(UnshareCliOptions::default());
    }
    let mut options = UnshareCliOptions::default();
    let mut remove = vec![false; args.len()];
    let mut index = 0_usize;
    while index < args.len() {
        let arg = args
            .get(index)
            .ok_or_else(|| "unshare argument index is out of bounds".to_string())?;
        if arg == "--" {
            break;
        }
        let suffix = unshare_option_suffix(arg, &format_base);
        let split_kind = match suffix {
            Some("-uid") => Some("uid"),
            Some("-gid") => Some("gid"),
            _ => None,
        };
        if let Some(kind) = split_kind {
            let value_index = index
                .checked_add(1)
                .ok_or_else(|| format!("{arg} argument index overflows"))?;
            let value = args
                .get(value_index)
                .ok_or_else(|| format!("{arg} requires a numeric value"))?;
            value
                .parse::<u32>()
                .map_err(|_| format!("invalid {kind} value `{value}` for {arg}"))?;
            if kind == "uid" {
                options.uid = Some(value.clone());
            } else {
                options.gid = Some(value.clone());
            }
            options.enable = true;
            *remove
                .get_mut(index)
                .ok_or_else(|| format!("{arg} removal index is out of bounds"))? = true;
            *remove
                .get_mut(value_index)
                .ok_or_else(|| format!("{arg} value removal index is out of bounds"))? = true;
            index = value_index
                .checked_add(1)
                .ok_or_else(|| format!("{arg} argument index overflows"))?;
            continue;
        }
        let inline_value = suffix.and_then(|suffix| {
            suffix
                .strip_prefix("-uid=")
                .map(|value| ("uid", value))
                .or_else(|| suffix.strip_prefix("-gid=").map(|value| ("gid", value)))
        });
        if let Some((kind, value)) = inline_value {
            value
                .parse::<u32>()
                .map_err(|_| format!("invalid {kind} value `{value}` for {arg}"))?;
            if kind == "uid" {
                options.uid = Some(value.to_string());
            } else {
                options.gid = Some(value.to_string());
            }
            options.enable = true;
            *remove
                .get_mut(index)
                .ok_or_else(|| format!("{arg} removal index is out of bounds"))? = true;
        } else if suffix == Some("") {
            options.enable = true;
            *remove
                .get_mut(index)
                .ok_or_else(|| format!("{arg} removal index is out of bounds"))? = true;
        } else if suffix == Some("-root") {
            options.enable = true;
            options.root = true;
            *remove
                .get_mut(index)
                .ok_or_else(|| format!("{arg} removal index is out of bounds"))? = true;
        } else if suffix == Some("-drop-caps") {
            options.enable = true;
            options.drop_caps = true;
            *remove
                .get_mut(index)
                .ok_or_else(|| format!("{arg} removal index is out of bounds"))? = true;
        } else if suffix == Some("-fallback-drop-caps") {
            options.drop_caps_on_fallback = true;
            *remove
                .get_mut(index)
                .ok_or_else(|| format!("{arg} removal index is out of bounds"))? = true;
        }
        index = index
            .checked_add(1)
            .ok_or_else(|| format!("{arg} argument index overflows"))?;
    }
    if options.drop_caps_on_fallback && options.enable {
        options.drop_caps = true;
        options.drop_caps_on_fallback = false;
    }
    *args = std::mem::take(args)
        .into_iter()
        .zip(remove)
        .filter_map(|(arg, remove)| (!remove).then_some(arg))
        .collect();
    Ok(options)
}

fn remove_runtime_separator(args: &mut Vec<String>) {
    if let Some(index) = args.iter().position(|arg| arg == "--") {
        args.remove(index);
    }
}

fn drop_capabilities(last_cap: u32) -> Result<()> {
    let syscall_failed = |result: libc::c_long| {
        if result == 0 {
            Ok(())
        } else {
            Err(Error::last_os_error())
        }
    };

    let mut caps = CapHeader {
        version: _LINUX_CAPABILITY_VERSION_3,
        pid: 0,
    };
    let mut current = [CapData {
        effective: 0,
        permitted: 0,
        inheritable: 0,
    }; 2];
    syscall_failed(unsafe { libc::syscall(libc::SYS_capget, &mut caps, current.as_mut_ptr()) })?;
    let securebits = unsafe { libc::prctl(libc::PR_GET_SECUREBITS, 0, 0, 0, 0) };
    let capabilities_are_empty = current
        .iter()
        .all(|data| data.effective == 0 && data.permitted == 0 && data.inheritable == 0);
    if capabilities_are_empty
        && securebits >= 0
        && securebits as libc::c_ulong & (SECBIT_NOROOT | SECBIT_NOROOT_LOCKED)
            == SECBIT_NOROOT | SECBIT_NOROOT_LOCKED
    {
        return Ok(());
    }

    syscall_failed(unsafe {
        libc::prctl(
            libc::PR_CAP_AMBIENT,
            libc::PR_CAP_AMBIENT_CLEAR_ALL,
            0,
            0,
            0,
        ) as libc::c_long
    })?;
    syscall_failed(unsafe {
        libc::prctl(
            libc::PR_SET_SECUREBITS,
            SECBIT_NOROOT | SECBIT_NOROOT_LOCKED,
            0,
            0,
            0,
        ) as libc::c_long
    })?;
    for cap in 0..=last_cap {
        syscall_failed(unsafe {
            libc::prctl(libc::PR_CAPBSET_DROP, cap, 0, 0, 0) as libc::c_long
        })?;
    }
    let cap_data = [CapData {
        effective: 0,
        permitted: 0,
        inheritable: 0,
    }; 2];
    syscall_failed(unsafe { libc::syscall(libc::SYS_capset, &caps, cap_data.as_ptr()) })
}

fn try_make_mount_private() -> bool {
    unsafe {
        libc::mount(
            c"none".as_ptr(),
            c"/".as_ptr(),
            c"none".as_ptr(),
            libc::MS_REC | libc::MS_PRIVATE,
            std::ptr::null(),
        ) == 0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NamespaceKind {
    Current,
    MountOnly,
    UserAndMount,
}

impl NamespaceKind {
    fn is_unshared(self) -> bool {
        !matches!(self, Self::Current)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct NamespaceOutcome {
    kind: NamespaceKind,
    direct_mount_fallback: bool,
}

impl NamespaceOutcome {
    fn current(direct_mount_fallback: bool) -> Self {
        Self {
            kind: NamespaceKind::Current,
            direct_mount_fallback,
        }
    }

    fn unshared(kind: NamespaceKind) -> Option<Self> {
        kind.is_unshared().then_some(Self {
            kind,
            direct_mount_fallback: false,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TryUnshareResult {
    Created(NamespaceOutcome),
    Unavailable,
    IrreversibleFailure,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NamespaceEntryResult {
    Entered,
    Unavailable,
    Rejected,
    IrreversibleFailure,
}

fn namespace_entry_outcome(
    setns_succeeded: bool,
    mount_namespace_entered: bool,
    mount_private_succeeded: bool,
) -> NamespaceEntryResult {
    if !setns_succeeded {
        NamespaceEntryResult::Unavailable
    } else if mount_namespace_entered && !mount_private_succeeded {
        NamespaceEntryResult::IrreversibleFailure
    } else {
        NamespaceEntryResult::Entered
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DirectMountSetupResult {
    Ready(NamespaceOutcome),
    Unavailable,
}

fn direct_mount_setup_outcome(
    existing: Option<NamespaceOutcome>,
    procfs_available: bool,
    has_cap_sys_admin: bool,
    mount_private_succeeded: bool,
) -> DirectMountSetupResult {
    if !procfs_available && has_cap_sys_admin && !mount_private_succeeded {
        return DirectMountSetupResult::Unavailable;
    }
    let outcome = match existing {
        Some(outcome) => outcome,
        None => NamespaceOutcome::current(direct_mount_is_fallback(
            false,
            procfs_available,
            has_cap_sys_admin,
        )),
    };
    DirectMountSetupResult::Ready(outcome)
}

#[derive(Debug, Eq, PartialEq)]
enum UnsharePlan {
    UserAndMount,
    MountOnly,
    Impossible,
}

fn plan_unshare(
    uid: u32,
    gid: u32,
    target_uid: u32,
    target_gid: u32,
    procfs_available: bool,
    mapping_requested: bool,
) -> UnsharePlan {
    let mapping_needed = mapping_requested || target_uid != uid || target_gid != gid;
    if mapping_needed && !procfs_available {
        UnsharePlan::Impossible
    } else if !mapping_needed && !procfs_available {
        UnsharePlan::MountOnly
    } else {
        UnsharePlan::UserAndMount
    }
}

fn requested_id_mapping(_uid: u32, _gid: u32, unshare_uid: &str, unshare_gid: &str) -> bool {
    !unshare_uid.is_empty() || !unshare_gid.is_empty()
}

fn mount_only_requires_procfs_notice(private_mount: bool, procfs_available: bool) -> bool {
    private_mount && !procfs_available
}

#[derive(Debug, Eq, PartialEq)]
enum FailedUnshareAction {
    Abort,
    TryMountOnly,
    ReturnFailure,
}

fn failed_unshare_action(
    user_namespace_created: bool,
    mapping_requested: bool,
) -> FailedUnshareAction {
    if user_namespace_created {
        FailedUnshareAction::Abort
    } else if !mapping_requested {
        FailedUnshareAction::TryMountOnly
    } else {
        FailedUnshareAction::ReturnFailure
    }
}

fn direct_mount_is_fallback(
    unshare_succeeded: bool,
    procfs_available: bool,
    has_cap_sys_admin: bool,
) -> bool {
    !unshare_succeeded && !procfs_available && has_cap_sys_admin
}

fn can_mount_directly(
    uid: u32,
    unshare_succeeded: bool,
    in_user_and_mount_namespace: bool,
    procfs_available: bool,
    has_cap_sys_admin: bool,
    is_mount_only: bool,
) -> bool {
    if is_mount_only && !procfs_available && !unshare_succeeded {
        return false;
    }
    uid == 0
        || unshare_succeeded
        || in_user_and_mount_namespace
        || (!procfs_available && has_cap_sys_admin)
}

fn has_effective_capability(capability: u32) -> bool {
    let mut header = CapHeader {
        version: _LINUX_CAPABILITY_VERSION_3,
        pid: 0,
    };
    let mut data = [CapData {
        effective: 0,
        permitted: 0,
        inheritable: 0,
    }; 2];
    if unsafe { libc::syscall(libc::SYS_capget, &mut header, data.as_mut_ptr()) } != 0 {
        return false;
    }
    let index = (capability / 32) as usize;
    data.get(index)
        .is_some_and(|entry| entry.effective & (1u32 << (capability % 32)) != 0)
}

fn finish_mount_namespace_outcome(
    kind: NamespaceKind,
    mount_private_succeeded: bool,
) -> TryUnshareResult {
    if !mount_private_succeeded {
        return TryUnshareResult::IrreversibleFailure;
    }
    match NamespaceOutcome::unshared(kind) {
        Some(outcome) => TryUnshareResult::Created(outcome),
        None => TryUnshareResult::IrreversibleFailure,
    }
}

fn finish_mount_namespace(kind: NamespaceKind) -> TryUnshareResult {
    let result = finish_mount_namespace_outcome(kind, try_make_mount_private());
    if result == TryUnshareResult::IrreversibleFailure {
        eprintln!(
            "Failed to make the new mount namespace private: {}",
            Error::last_os_error()
        );
    }
    result
}

fn try_unshare(
    uid: u32,
    gid: u32,
    requested_mapping: IdMapping,
    mapping_requested: bool,
) -> TryUnshareResult {
    let target_uid = requested_mapping.uid;
    let target_gid = requested_mapping.gid;
    let procfs_available = process_procfs_available_at(Path::new("/proc"));

    match plan_unshare(
        uid,
        gid,
        target_uid,
        target_gid,
        procfs_available,
        mapping_requested,
    ) {
        UnsharePlan::Impossible => {
            eprintln!(
                "Failed to create user and mount namespaces: UID/GID mapping requires procfs (/proc/self/uid_map), which is unavailable"
            );
            return TryUnshareResult::Unavailable;
        }
        UnsharePlan::MountOnly => {
            // Without procfs and a requested ID mapping, a new user namespace
            // cannot be configured. An existing CAP_SYS_ADMIN is sufficient
            // to create the mount namespace required for FUSE.
            if unsafe { libc::unshare(libc::CLONE_NEWNS) } == 0 {
                return finish_mount_namespace(NamespaceKind::MountOnly);
            }
            eprintln!(
                "Failed to create mount namespace: {}",
                Error::last_os_error()
            );
            return TryUnshareResult::Unavailable;
        }
        UnsharePlan::UserAndMount => {}
    }

    let flags = libc::CLONE_NEWUSER | libc::CLONE_NEWNS;
    let result = unsafe { libc::unshare(flags) };
    let action = failed_unshare_action(result == 0, mapping_requested);
    if result == 0 {
        let _ = fs::write("/proc/self/setgroups", "deny");
        let uid_map = format!("{target_uid} {uid} 1");
        let gid_map = format!("{target_gid} {gid} 1");
        let mapping_result = fs::write("/proc/self/uid_map", uid_map)
            .and_then(|()| fs::write("/proc/self/gid_map", gid_map));
        match mapping_result {
            Ok(()) => {
                restore_capabilities();
                return finish_mount_namespace(NamespaceKind::UserAndMount);
            }
            Err(err) => {
                eprintln!(
                    "Failed to configure UID/GID mappings after creating the user namespace: {err}"
                );
                return TryUnshareResult::IrreversibleFailure;
            }
        }
    }
    // A mount-only fallback is safe only when creation of the user namespace
    // itself failed. Once CLONE_NEWUSER succeeds, that transition cannot be
    // rolled back in-process, even if writing uid_map or gid_map then fails.
    if action == FailedUnshareAction::TryMountOnly
        && unsafe { libc::unshare(libc::CLONE_NEWNS) } == 0
    {
        return finish_mount_namespace(NamespaceKind::MountOnly);
    }
    eprintln!(
        "Failed to create user and mount namespaces: {}",
        Error::last_os_error()
    );
    TryUnshareResult::Unavailable
}

fn is_in_user_and_mount_namespace() -> bool {
    let uid_map = match read_to_string("/proc/self/uid_map") {
        Ok(content) => content,
        Err(_) => return false,
    };
    let uid_map = uid_map.trim();
    if uid_map.is_empty()
        || uid_map.split_whitespace().collect::<Vec<_>>() == vec!["0", "0", "4294967295"]
    {
        return false;
    }
    let lines: Vec<&str> = uid_map.lines().collect();
    if lines.is_empty() {
        return false;
    }
    for line in lines {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() == 3 {
            if let Ok(count) = parts[2].parse::<u32>() {
                if count < 4294967295 {
                    return try_make_mount_private();
                }
            }
        }
    }
    false
}

fn namespace_diff_is_compatible(namespace_kind: NamespaceKind, flags: i32) -> bool {
    let known_flags = libc::CLONE_NEWUSER | libc::CLONE_NEWNS;
    if flags & !known_flags != 0 {
        return false;
    }
    match namespace_kind {
        NamespaceKind::Current => flags == 0,
        NamespaceKind::MountOnly => flags & libc::CLONE_NEWUSER == 0,
        NamespaceKind::UserAndMount => true,
    }
}

fn read_process_starttime(pid: Pid) -> Option<u64> {
    read_to_string(format!("/proc/{pid}/stat"))
        .ok()
        .and_then(|value| parse_proc_stat_starttime(&value))
}

struct NamespaceFiles {
    user: File,
    mount: File,
}

impl NamespaceFiles {
    fn open(pid: &str) -> Result<Self> {
        Ok(Self {
            user: File::open(format!("/proc/{pid}/ns/user"))?,
            mount: File::open(format!("/proc/{pid}/ns/mnt"))?,
        })
    }

    fn identities(&self) -> Result<NamespaceIdentities> {
        Ok(NamespaceIdentities {
            user: NamespaceIdentity::from_file(&self.user)?,
            mount: NamespaceIdentity::from_file(&self.mount)?,
        })
    }
}

fn namespace_identity_flags(current: NamespaceIdentities, target: NamespaceIdentities) -> i32 {
    let mut flags = 0;
    if current.user != target.user {
        flags |= libc::CLONE_NEWUSER;
    }
    if current.mount != target.mount {
        flags |= libc::CLONE_NEWNS;
    }
    flags
}

fn try_setns(
    pid: Pid,
    namespace_kind: NamespaceKind,
    expected_starttime: Option<u64>,
    expected_namespaces: Option<NamespaceIdentities>,
) -> NamespaceEntryResult {
    let original_cwd = getcwd().ok();
    let pidfd_raw =
        unsafe { libc::syscall(libc::SYS_pidfd_open, pid.as_raw() as i64, 0i64) as i32 };
    if pidfd_raw < 0 {
        eprintln!(
            "Failed to open pidfd: {} - mount point reuse unavailable",
            Error::last_os_error()
        );
        return NamespaceEntryResult::Unavailable;
    }
    let _pidfd = unsafe { File::from_raw_fd(pidfd_raw) };
    let expected_starttime = match expected_starttime {
        Some(value) => value,
        None => return NamespaceEntryResult::Rejected,
    };
    match read_process_starttime(pid) {
        Some(actual) if actual == expected_starttime => {}
        Some(_) => return NamespaceEntryResult::Rejected,
        None => return NamespaceEntryResult::Unavailable,
    }
    let target_namespaces = match NamespaceFiles::open(&pid.to_string()) {
        Ok(files) => files,
        Err(err) => {
            eprintln!("Failed to pin mount owner namespaces: {err}");
            return NamespaceEntryResult::Unavailable;
        }
    };
    let target_identities = match target_namespaces.identities() {
        Ok(identities) => identities,
        Err(err) => {
            eprintln!("Failed to identify pinned mount owner namespaces: {err}");
            return NamespaceEntryResult::Unavailable;
        }
    };
    if !namespace_identities_match(expected_namespaces, target_identities) {
        eprintln!("Recorded namespace identities do not match the mount owner namespaces");
        return NamespaceEntryResult::Rejected;
    }
    match read_process_starttime(pid) {
        Some(actual) if actual == expected_starttime => {}
        Some(_) => return NamespaceEntryResult::Rejected,
        None => return NamespaceEntryResult::Unavailable,
    }
    let current_namespaces = match NamespaceFiles::open("self") {
        Ok(files) => files,
        Err(err) => {
            eprintln!("Failed to pin current namespaces: {err}");
            return NamespaceEntryResult::Unavailable;
        }
    };
    let current_identities = match current_namespaces.identities() {
        Ok(identities) => identities,
        Err(err) => {
            eprintln!("Failed to identify current namespaces: {err}");
            return NamespaceEntryResult::Unavailable;
        }
    };
    let flags = namespace_identity_flags(current_identities, target_identities);
    if !namespace_diff_is_compatible(namespace_kind, flags) {
        eprintln!("Recorded namespace kind does not match the mount owner namespaces");
        return NamespaceEntryResult::Rejected;
    }
    if flags == 0 {
        return NamespaceEntryResult::Entered;
    }
    let mut irreversible_transition = false;
    if flags & libc::CLONE_NEWUSER != 0 {
        if unsafe { libc::setns(target_namespaces.user.as_raw_fd(), libc::CLONE_NEWUSER) } != 0 {
            eprintln!(
                "Failed to enter pinned user namespace: {}",
                Error::last_os_error()
            );
            return NamespaceEntryResult::Unavailable;
        }
        irreversible_transition = true;
        restore_capabilities();
    }
    let entered_mount_namespace = flags & libc::CLONE_NEWNS != 0;
    if entered_mount_namespace
        && unsafe { libc::setns(target_namespaces.mount.as_raw_fd(), libc::CLONE_NEWNS) } != 0
    {
        eprintln!(
            "Failed to enter pinned mount namespace: {}",
            Error::last_os_error()
        );
        return if irreversible_transition {
            NamespaceEntryResult::IrreversibleFailure
        } else {
            NamespaceEntryResult::Unavailable
        };
    }
    let mount_private_succeeded = !entered_mount_namespace || try_make_mount_private();
    if !mount_private_succeeded {
        eprintln!(
            "Failed to make the entered mount namespace private: {}",
            Error::last_os_error()
        );
    }
    if entered_mount_namespace {
        if let Some(cwd) = original_cwd {
            if let Err(err) = env::set_current_dir(&cwd) {
                eprintln!("Warning: failed to restore working directory: {err}");
            }
        }
    }
    namespace_entry_outcome(true, entered_mount_namespace, mount_private_succeeded)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct IdMapping {
    uid: u32,
    gid: u32,
}

fn parse_requested_mapping(
    uid: u32,
    gid: u32,
    unshare_uid: &str,
    unshare_gid: &str,
) -> Result<IdMapping> {
    let parse = |value: &str, current, name: &str| {
        if value.is_empty() {
            Ok(current)
        } else {
            value.parse::<u32>().map_err(|err| {
                Error::new(
                    InvalidInput,
                    format!("invalid requested {name} `{value}`: {err}"),
                )
            })
        }
    };
    Ok(IdMapping {
        uid: parse(unshare_uid, uid, "UID")?,
        gid: parse(unshare_gid, gid, "GID")?,
    })
}

fn reuse_hash_material(base: u64, mapping: IdMapping, explicit: bool) -> String {
    if explicit {
        format!("{base}:uid={}:gid={}", mapping.uid, mapping.gid)
    } else {
        base.to_string()
    }
}

fn base_hash(runtime_hash: u64, image_hash: u32, uid: u32) -> u32 {
    (runtime_hash as u32)
        .wrapping_add(image_hash)
        .wrapping_add(uid)
}

fn reusable_mapping_matches(
    recorded: Option<IdMapping>,
    requested: IdMapping,
    _explicit: bool,
) -> bool {
    recorded == Some(requested)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct NamespaceIdentity {
    device: u64,
    inode: u64,
}

impl NamespaceIdentity {
    fn from_file(file: &File) -> Result<Self> {
        let metadata = file.metadata()?;
        Ok(Self {
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct NamespaceIdentities {
    user: NamespaceIdentity,
    mount: NamespaceIdentity,
}

fn namespace_identities_match(
    recorded: Option<NamespaceIdentities>,
    actual: NamespaceIdentities,
) -> bool {
    recorded == Some(actual)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct MountPidRecord {
    pid: Pid,
    namespace_kind: Option<NamespaceKind>,
    mapping: Option<IdMapping>,
    process_starttime: Option<u64>,
    namespace_identities: Option<NamespaceIdentities>,
}

fn record_reusable_for_mapping(
    record: &MountPidRecord,
    requested: IdMapping,
    explicit: bool,
) -> bool {
    record.process_starttime.is_some()
        && record.namespace_identities.is_some()
        && reusable_mapping_matches(record.mapping, requested, explicit)
        && (!explicit || record.namespace_kind == Some(NamespaceKind::UserAndMount))
}

fn record_process_generation_matches(record: &MountPidRecord) -> bool {
    record
        .process_starttime
        .zip(read_process_starttime(record.pid))
        .is_some_and(|(expected, actual)| expected == actual)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReuseUnavailableAction {
    Continue,
    Fresh,
    Reject,
}

fn reuse_unavailable_action(fixed_target: bool) -> ReuseUnavailableAction {
    if fixed_target {
        ReuseUnavailableAction::Reject
    } else {
        ReuseUnavailableAction::Fresh
    }
}

fn stale_removed_action(fixed_target: bool, occupied: bool) -> ReuseUnavailableAction {
    if fixed_target {
        ReuseUnavailableAction::Reject
    } else if occupied {
        ReuseUnavailableAction::Fresh
    } else {
        ReuseUnavailableAction::Continue
    }
}

fn fresh_mount_target(path: &Path) -> Result<PathBuf> {
    let file_name = path.file_name().ok_or_else(|| {
        Error::new(
            InvalidInput,
            format!("cannot derive a fresh mount target from {}", path.display()),
        )
    })?;
    for _ in 0..128 {
        let mut fresh_name = file_name.to_os_string();
        fresh_name.push(format!("fresh{}", random_string(6)));
        let candidate = path.with_file_name(fresh_name);
        if path_entry_present(&candidate.with_extension("pid"))
            || path_entry_present(&candidate.with_extension("un.pid"))
        {
            continue;
        }
        match DirBuilder::new().mode(0o700).create(&candidate) {
            Ok(()) => return Ok(candidate),
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(err) => return Err(err),
        }
    }
    Err(Error::new(
        Other,
        format!(
            "failed to allocate a fresh mount target beside {}",
            path.display()
        ),
    ))
}

fn verify_fresh_target_reservation(target: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(target)?;
    if !metadata.file_type().is_dir()
        || metadata.uid() != unsafe { libc::getuid() }
        || metadata.mode() & 0o077 != 0
    {
        return Err(Error::new(
            InvalidData,
            format!(
                "fresh target reservation {} is not a private owner directory",
                target.display()
            ),
        ));
    }
    match inspect_target_directory(target) {
        TargetDirectoryState::Empty => Ok(()),
        TargetDirectoryState::Nonempty => Err(Error::new(
            InvalidData,
            format!("fresh target reservation {} is not empty", target.display()),
        )),
        TargetDirectoryState::Unsafe => Err(Error::new(
            InvalidData,
            format!(
                "fresh target reservation {} cannot be inspected safely",
                target.display()
            ),
        )),
    }
}

fn rollback_fresh_target(target: &Path, primary_error: Error) -> Error {
    match remove_dir(target) {
        Ok(()) => primary_error,
        Err(rollback_error) => Error::new(
            rollback_error.kind(),
            format!(
                "{primary_error}; failed to roll back fresh target reservation {}: {rollback_error}",
                target.display()
            ),
        ),
    }
}

struct FreshTargetTransition {
    target: PathBuf,
    tmp_dirs: Vec<PathBuf>,
    coordinator: Option<TargetCoordinator>,
    lease: Option<LifetimeLease>,
}

fn prepare_fresh_target_transition_with<S, A>(
    old_target: &Path,
    tmp_dirs: &[PathBuf],
    lifetime_lease_enabled: bool,
    select_target: S,
    acquire_usage_lease: A,
) -> Result<FreshTargetTransition>
where
    S: FnOnce(&Path) -> Result<PathBuf>,
    A: FnOnce(&Path) -> Result<(TargetCoordinator, LifetimeLease)>,
{
    let target = select_target(old_target)?;
    if let Err(err) = verify_fresh_target_reservation(&target) {
        return Err(rollback_fresh_target(&target, err));
    }
    let (coordinator, lease) = if lifetime_lease_enabled {
        let (coordinator, lease) = match acquire_usage_lease(&target) {
            Ok(value) => value,
            Err(err) => return Err(rollback_fresh_target(&target, err)),
        };
        (Some(coordinator), Some(lease))
    } else {
        (None, None)
    };
    if path_entry_present(&target.with_extension("pid"))
        || path_entry_present(&target.with_extension("un.pid"))
    {
        drop(lease);
        drop(coordinator);
        let err = Error::new(
            AlreadyExists,
            format!(
                "fresh mount target {} acquired a PID record",
                target.display()
            ),
        );
        return Err(rollback_fresh_target(&target, err));
    }
    if let Err(err) = verify_fresh_target_reservation(&target) {
        drop(lease);
        drop(coordinator);
        return Err(rollback_fresh_target(&target, err));
    }
    let tmp_dirs = tmp_dirs
        .iter()
        .map(|path| {
            if path == old_target {
                target.clone()
            } else {
                path.clone()
            }
        })
        .collect();
    Ok(FreshTargetTransition {
        target,
        tmp_dirs,
        coordinator,
        lease,
    })
}

fn transition_to_fresh_mount_target(
    target: &mut PathBuf,
    tmp_dirs: &mut Vec<PathBuf>,
    coordinator: &mut Option<TargetCoordinator>,
    lease: &mut Option<LifetimeLease>,
    lifetime_lease_enabled: bool,
) -> Result<()> {
    let transition = prepare_fresh_target_transition_with(
        target,
        tmp_dirs,
        lifetime_lease_enabled,
        fresh_mount_target,
        acquire_target_usage_lease,
    )?;
    *target = transition.target;
    *tmp_dirs = transition.tmp_dirs;
    *coordinator = transition.coordinator;
    *lease = transition.lease;
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ExistingTargetAction {
    Reuse,
    Create,
    Reject,
}

fn visible_direct_reuse_allowed(
    persistent_reuse: bool,
    automatic_target: bool,
    explicit_mapping: bool,
    namespace_identity_available: bool,
    unshare_record_present: bool,
    direct_record_present: bool,
    mounted: bool,
) -> bool {
    persistent_reuse
        && automatic_target
        && !explicit_mapping
        && !namespace_identity_available
        && !unshare_record_present
        && !direct_record_present
        && mounted
}

fn proc_free_private_mount_requires_random_target(
    reusable_mount: bool,
    extract_run: bool,
    procfs_available: bool,
    private_namespace_requested: bool,
    direct_mount_available: bool,
) -> bool {
    reusable_mount
        && !extract_run
        && !procfs_available
        && (private_namespace_requested || !direct_mount_available)
}

fn should_write_mount_pid_record(
    persistent_reuse: bool,
    namespace_kind: Option<NamespaceKind>,
    namespace_identity_available: bool,
    automatic_target: bool,
    explicit_mapping: bool,
) -> bool {
    persistent_reuse
        && !(!namespace_identity_available
            && namespace_kind == Some(NamespaceKind::Current)
            && automatic_target
            && !explicit_mapping)
}

fn should_validate_direct_reuse_record(
    persistent_reuse: bool,
    explicit_mapping: bool,
    unshare_reuse_rejected: bool,
    mounted: bool,
    direct_record_present: bool,
) -> bool {
    direct_record_present
        && !unshare_reuse_rejected
        && (persistent_reuse || (explicit_mapping && mounted))
}

fn unshare_reuse_was_rejected(
    record_present: bool,
    record_valid: bool,
    relevant_to_requested_isolation: bool,
) -> bool {
    relevant_to_requested_isolation && record_present && !record_valid
}

fn existing_target_action(
    persistent_reuse: bool,
    explicit_mapping: bool,
    unshare_reuse_rejected: bool,
    mounted: bool,
    nonempty: bool,
    direct_record_valid: bool,
) -> ExistingTargetAction {
    if unshare_reuse_rejected {
        return ExistingTargetAction::Reject;
    }
    if persistent_reuse && nonempty && !mounted {
        return ExistingTargetAction::Reject;
    }
    if (persistent_reuse && mounted) || (explicit_mapping && mounted) {
        return if !unshare_reuse_rejected && direct_record_valid {
            ExistingTargetAction::Reuse
        } else {
            ExistingTargetAction::Reject
        };
    }
    if !persistent_reuse {
        return if mounted || (nonempty && !explicit_mapping) {
            ExistingTargetAction::Reuse
        } else {
            ExistingTargetAction::Create
        };
    }
    if nonempty && !explicit_mapping && !unshare_reuse_rejected {
        ExistingTargetAction::Reuse
    } else {
        ExistingTargetAction::Create
    }
}

fn parse_proc_stat_starttime(value: &str) -> Option<u64> {
    let open = value.find('(')?;
    let close = value.rfind(')')?;
    if close <= open {
        return None;
    }
    let fields_start = close.checked_add(1)?;
    value
        .get(fields_start..)?
        .split_whitespace()
        .nth(19)?
        .parse::<u64>()
        .ok()
}

fn parse_namespace_identity(value: &str) -> Option<NamespaceIdentity> {
    let (device, inode) = value.split_once(':')?;
    if device.is_empty() || inode.is_empty() || inode.contains(':') {
        return None;
    }
    Some(NamespaceIdentity {
        device: device.parse::<u64>().ok()?,
        inode: inode.parse::<u64>().ok()?,
    })
}

fn parse_mount_pid_record(value: &str) -> Option<MountPidRecord> {
    let mut fields = value.split_whitespace();
    let pid = fields.next()?.parse::<i32>().ok()?;
    if pid <= 0 {
        return None;
    }
    let mut version = None;
    let mut namespace_kind = None;
    let mut uid = None;
    let mut gid = None;
    let mut process_starttime = None;
    let mut user_namespace = None;
    let mut mount_namespace = None;
    for field in fields {
        match field {
            "v=2" if version.is_none() => version = Some(2_u8),
            "current" if namespace_kind.is_none() => namespace_kind = Some(NamespaceKind::Current),
            "mnt" if namespace_kind.is_none() => namespace_kind = Some(NamespaceKind::MountOnly),
            "user,mnt" if namespace_kind.is_none() => {
                namespace_kind = Some(NamespaceKind::UserAndMount)
            }
            _ if field.starts_with("uid=") && uid.is_none() => {
                uid = Some(field.strip_prefix("uid=")?.parse::<u32>().ok()?);
            }
            _ if field.starts_with("gid=") && gid.is_none() => {
                gid = Some(field.strip_prefix("gid=")?.parse::<u32>().ok()?);
            }
            _ if field.starts_with("start=") && process_starttime.is_none() => {
                process_starttime = Some(field.strip_prefix("start=")?.parse::<u64>().ok()?);
            }
            _ if field.starts_with("userns=") && user_namespace.is_none() => {
                user_namespace = Some(parse_namespace_identity(field.strip_prefix("userns=")?)?);
            }
            _ if field.starts_with("mntns=") && mount_namespace.is_none() => {
                mount_namespace = Some(parse_namespace_identity(field.strip_prefix("mntns=")?)?);
            }
            _ => return None,
        }
    }
    let mapping = match (uid, gid) {
        (None, None) => None,
        (Some(uid), Some(gid)) => Some(IdMapping { uid, gid }),
        _ => return None,
    };
    let namespace_identities = match (user_namespace, mount_namespace) {
        (None, None) => None,
        (Some(user), Some(mount)) => Some(NamespaceIdentities { user, mount }),
        _ => return None,
    };
    if version == Some(2)
        && (namespace_kind.is_none()
            || mapping.is_none()
            || process_starttime.is_none()
            || namespace_identities.is_none())
    {
        return None;
    }
    if version.is_none() && namespace_identities.is_some() {
        return None;
    }
    Some(MountPidRecord {
        pid: Pid::from_raw(pid),
        namespace_kind,
        mapping,
        process_starttime,
        namespace_identities,
    })
}

fn format_mount_pid_record(record: &MountPidRecord) -> String {
    let mut value = record.pid.as_raw().to_string();
    if record.namespace_identities.is_some() {
        value.push_str(" v=2");
    }
    match record.namespace_kind {
        Some(NamespaceKind::Current) => value.push_str(" current"),
        Some(NamespaceKind::MountOnly) => value.push_str(" mnt"),
        Some(NamespaceKind::UserAndMount) => value.push_str(" user,mnt"),
        None => {}
    }
    if let Some(mapping) = record.mapping {
        value.push_str(&format!(" uid={} gid={}", mapping.uid, mapping.gid));
    }
    if let Some(starttime) = record.process_starttime {
        value.push_str(&format!(" start={starttime}"));
    }
    if let Some(identities) = record.namespace_identities {
        value.push_str(&format!(
            " userns={}:{} mntns={}:{}",
            identities.user.device,
            identities.user.inode,
            identities.mount.device,
            identities.mount.inode
        ));
    }
    value
}

fn read_mount_pid_file(mount_point: &Path, extension: &str) -> Option<MountPidRecord> {
    let pid_file = mount_point.with_extension(extension);
    read_to_string(pid_file)
        .ok()
        .and_then(|value| parse_mount_pid_record(&value))
}

fn path_entry_present(path: &Path) -> bool {
    match fs::symlink_metadata(path) {
        Ok(_) => true,
        Err(err) => err.kind() != NotFound,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TargetDirectoryState {
    Empty,
    Nonempty,
    Unsafe,
}

fn classify_target_directory(
    read_result: std::result::Result<bool, std::io::ErrorKind>,
) -> TargetDirectoryState {
    match read_result {
        Ok(false) | Err(NotFound) => TargetDirectoryState::Empty,
        Ok(true) => TargetDirectoryState::Nonempty,
        Err(_) => TargetDirectoryState::Unsafe,
    }
}

fn inspect_target_directory(path: &Path) -> TargetDirectoryState {
    let read_result = match fs::read_dir(path) {
        Ok(mut entries) => match entries.next() {
            None => Ok(false),
            Some(Ok(_)) => Ok(true),
            Some(Err(err)) => Err(err.kind()),
        },
        Err(err) => Err(err.kind()),
    };
    classify_target_directory(read_result)
}

fn inspect_target_nonempty(path: &Path) -> Result<bool> {
    match inspect_target_directory(path) {
        TargetDirectoryState::Empty => Ok(false),
        TargetDirectoryState::Nonempty => Ok(true),
        TargetDirectoryState::Unsafe => Err(Error::new(
            Other,
            format!(
                "cannot safely inspect existing target directory {}",
                path.display()
            ),
        )),
    }
}

#[cfg(test)]
fn directory_nonempty_or_unsafe(path: &Path, _errors_are_unsafe: bool) -> bool {
    inspect_target_directory(path) != TargetDirectoryState::Empty
}

fn record_namespace_matches_extension(record: &MountPidRecord, extension: &str) -> bool {
    match (extension, record.namespace_kind) {
        ("pid", Some(NamespaceKind::Current)) => true,
        ("un.pid", Some(kind)) => kind.is_unshared(),
        _ => false,
    }
}

const RECORD_TEMP_SCAN_LIMIT: usize = 4096;
const RECORD_TEMP_RANDOM_LENGTH: usize = 12;

fn is_record_temporary_name(record_name: &OsStr, candidate_name: &OsStr) -> bool {
    let record_bytes = record_name.as_bytes();
    let candidate_bytes = candidate_name.as_bytes();
    let suffix = match candidate_bytes
        .strip_prefix(record_bytes)
        .and_then(|value| value.strip_prefix(b".tmp."))
    {
        Some(value) => value,
        None => return false,
    };
    let separator = match suffix.iter().position(|value| *value == b'.') {
        Some(value) => value,
        None => return false,
    };
    let pid = match suffix.get(..separator) {
        Some(value) => value,
        None => return false,
    };
    let random = match separator
        .checked_add(1)
        .and_then(|start| suffix.get(start..))
    {
        Some(value) => value,
        None => return false,
    };
    let pid_is_exact = pid
        .first()
        .is_some_and(|first| (b'1'..=b'9').contains(first))
        && pid.iter().all(u8::is_ascii_digit)
        && std::str::from_utf8(pid)
            .ok()
            .and_then(|value| value.parse::<u32>().ok())
            .is_some();
    pid_is_exact
        && random.len() == RECORD_TEMP_RANDOM_LENGTH
        && random.iter().all(u8::is_ascii_alphanumeric)
}

fn scavenge_record_temporary_entries(record_path: &Path) {
    let parent = record_path.parent().unwrap_or_else(|| Path::new("."));
    let record_name = match record_path.file_name() {
        Some(value) => value,
        None => return,
    };
    let entries = match fs::read_dir(parent) {
        Ok(value) => value,
        Err(_) => return,
    };
    for entry_result in entries.take(RECORD_TEMP_SCAN_LIMIT) {
        let entry = match entry_result {
            Ok(value) => value,
            Err(_) => continue,
        };
        if !is_record_temporary_name(record_name, &entry.file_name()) {
            continue;
        }
        let entry_path = entry.path();
        let metadata = match fs::symlink_metadata(&entry_path) {
            Ok(value) => value,
            Err(_) => continue,
        };
        let file_type = metadata.file_type();
        if file_type.is_file() || file_type.is_symlink() {
            let _ = remove_file(entry_path);
        }
    }
}

fn read_validated_mount_pid_file(
    mount_point: &Path,
    extension: &str,
    requested_mapping: IdMapping,
    explicit_mapping: bool,
    lifetime_lease: Option<&LifetimeLease>,
) -> Option<MountPidRecord> {
    let record_path = mount_point.with_extension(extension);
    let _record_lock = RecordLock::acquire(mount_point, &record_path, lifetime_lease).ok()?;
    let record = read_mount_pid_file(mount_point, extension)?;
    let namespace_files = NamespaceFiles::open(&record.pid.to_string()).ok()?;
    let actual_namespaces = namespace_files.identities().ok()?;
    (record_namespace_matches_extension(&record, extension)
        && record_reusable_for_mapping(&record, requested_mapping, explicit_mapping)
        && record_process_generation_matches(&record)
        && namespace_identities_match(record.namespace_identities, actual_namespaces))
    .then_some(record)
}

const COORDINATOR_LOCK_RANGE: libc::off_t = 0;
const LIFETIME_LOCK_RANGE: libc::off_t = 1;
const RECORD_LOCK_RANGE: libc::off_t = 2;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OfdLockResult {
    Acquired,
    Busy,
    Unsupported,
}

fn append_target_sidecar(target: &Path, suffix: &str) -> PathBuf {
    let normalized: PathBuf = target.components().collect();
    let mut path = normalized.as_os_str().to_os_string();
    path.push(suffix);
    PathBuf::from(path)
}

fn target_lock_path(target: &Path) -> PathBuf {
    append_target_sidecar(target, ".lock")
}

fn target_lease_path(target: &Path) -> PathBuf {
    append_target_sidecar(target, ".lease")
}

fn prepare_target_lock_parent_with<F>(target: &Path, create_parent: F) -> Result<()>
where
    F: FnOnce(&Path) -> Result<()>,
{
    let lock_path = target_lock_path(target);
    let parent = lock_path
        .parent()
        .filter(|value| !value.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    match fs::metadata(parent) {
        Ok(metadata) if metadata.is_dir() => return Ok(()),
        Ok(_) => {
            return Err(Error::new(
                std::io::ErrorKind::NotADirectory,
                format!("target lock parent {} is not a directory", parent.display()),
            ));
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => {
            return Err(Error::new(
                err.kind(),
                format!(
                    "failed to inspect target lock parent {}: {err}",
                    parent.display()
                ),
            ));
        }
    }
    create_parent(parent).map_err(|err| {
        Error::new(
            err.kind(),
            format!(
                "failed to create missing target lock parent {}: {err}",
                parent.display()
            ),
        )
    })
}

fn prepare_target_lock_parent(target: &Path) -> Result<()> {
    prepare_target_lock_parent_with(target, |parent| create_dir_all(parent))
}

fn private_owner_file_identity(
    metadata: &Metadata,
    path: &Path,
    description: &str,
) -> Result<FileIdentity> {
    if !metadata.file_type().is_file()
        || metadata.uid() != unsafe { libc::getuid() }
        || metadata.mode() & 0o077 != 0
    {
        return Err(Error::new(
            InvalidData,
            format!(
                "{description} {} is not a private owner file",
                path.display()
            ),
        ));
    }
    Ok(FileIdentity::from_metadata(metadata))
}

fn open_private_owner_file(path: &Path, description: &str) -> Result<(File, FileIdentity)> {
    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let metadata = file.metadata()?;
    let identity = private_owner_file_identity(&metadata, path, description)?;
    Ok((file, identity))
}

fn verify_locked_file_identity(
    file: &File,
    identity: FileIdentity,
    path: &Path,
    description: &str,
) -> Result<()> {
    let descriptor_metadata = file.metadata()?;
    let descriptor_identity = private_owner_file_identity(&descriptor_metadata, path, description)?;
    let path_metadata = fs::symlink_metadata(path)?;
    let path_identity = private_owner_file_identity(&path_metadata, path, description)?;
    if descriptor_identity != identity || path_identity != identity {
        return Err(Error::new(
            InvalidData,
            format!("{description} {} changed while locking", path.display()),
        ));
    }
    Ok(())
}

fn classify_ofd_lock_error(errno: libc::c_int, blocking: bool) -> Option<OfdLockResult> {
    if !blocking && errno == libc::EAGAIN {
        return Some(OfdLockResult::Busy);
    }
    if matches!(errno, libc::EINVAL | libc::ENOSYS | libc::EOPNOTSUPP) {
        return Some(OfdLockResult::Unsupported);
    }
    None
}

fn legacy_flock_would_block(errno: libc::c_int) -> bool {
    errno == libc::EWOULDBLOCK
}

fn set_ofd_range_lock(
    file: &File,
    lock_type: libc::c_short,
    start: libc::off_t,
    blocking: bool,
) -> Result<OfdLockResult> {
    let command = if blocking {
        libc::F_OFD_SETLKW
    } else {
        libc::F_OFD_SETLK
    };
    loop {
        let mut lock: libc::flock = unsafe { std::mem::zeroed() };
        lock.l_type = lock_type;
        lock.l_whence = libc::SEEK_SET as libc::c_short;
        lock.l_start = start;
        lock.l_len = 1;
        lock.l_pid = 0;
        if unsafe { libc::fcntl(file.as_raw_fd(), command, &lock) } == 0 {
            return Ok(OfdLockResult::Acquired);
        }
        let err = Error::last_os_error();
        if err.kind() == std::io::ErrorKind::Interrupted {
            continue;
        }
        if let Some(result) = err
            .raw_os_error()
            .and_then(|errno| classify_ofd_lock_error(errno, blocking))
        {
            return Ok(result);
        }
        return Err(err);
    }
}

struct OfdRangeLock {
    file: File,
    identity: FileIdentity,
    start: libc::off_t,
    unlock_on_drop: bool,
}

impl Drop for OfdRangeLock {
    fn drop(&mut self) {
        if !self.unlock_on_drop {
            return;
        }
        let _ = set_ofd_range_lock(
            &self.file,
            libc::F_UNLCK as libc::c_short,
            self.start,
            false,
        );
    }
}

enum TargetCoordinator {
    Ofd { _lock: OfdRangeLock },
    Legacy { _file: File },
}

enum LifetimeLease {
    Ofd(OfdRangeLock),
    Legacy(File),
}

impl LifetimeLease {
    fn as_raw_fd(&self) -> RawFd {
        match self {
            Self::Ofd(lock) => lock.file.as_raw_fd(),
            Self::Legacy(file) => file.as_raw_fd(),
        }
    }

    fn prepare_fd_for_exec(fd: RawFd) -> Result<()> {
        clear_fd_cloexec(fd)
    }

    fn acquire_legacy(target: &Path, operation: libc::c_int) -> Result<Option<Self>> {
        acquire_legacy_flock(&target_lease_path(target), "lifetime lease", operation)
            .map(|file| file.map(Self::Legacy))
    }
}

fn legacy_record_lock_path(record_path: &Path) -> Result<PathBuf> {
    let parent = record_path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = record_path.file_name().ok_or_else(|| {
        Error::new(
            InvalidInput,
            format!("cannot lock a record at {}", record_path.display()),
        )
    })?;
    let mut lock_name = file_name.to_os_string();
    lock_name.push(".lock");
    Ok(parent.join(lock_name))
}

fn acquire_legacy_flock(
    path: &Path,
    description: &str,
    operation: libc::c_int,
) -> Result<Option<File>> {
    let (file, identity) = open_private_owner_file(path, description)?;
    loop {
        if unsafe { libc::flock(file.as_raw_fd(), operation) } == 0 {
            verify_locked_file_identity(&file, identity, path, description)?;
            return Ok(Some(file));
        }
        let err = Error::last_os_error();
        if operation & libc::LOCK_NB != 0
            && err.raw_os_error().is_some_and(legacy_flock_would_block)
        {
            return Ok(None);
        }
        if err.kind() != std::io::ErrorKind::Interrupted {
            return Err(err);
        }
    }
}

fn acquire_legacy_target_usage_lease(target: &Path) -> Result<(TargetCoordinator, LifetimeLease)> {
    let coordinator_path = legacy_record_lock_path(&target_lease_path(target))?;
    let coordinator =
        acquire_legacy_flock(&coordinator_path, "lifetime coordinator", libc::LOCK_EX)?
            .ok_or_else(|| Error::new(Other, "lifetime coordinator is busy"))?;
    let lease = LifetimeLease::acquire_legacy(target, libc::LOCK_SH)?
        .ok_or_else(|| Error::new(Other, "lifetime lease is busy"))?;
    Ok((TargetCoordinator::Legacy { _file: coordinator }, lease))
}

struct CleanupLease {
    _coordinator: TargetCoordinator,
    _lease: LifetimeLease,
}

fn acquire_target_usage_lease(target: &Path) -> Result<(TargetCoordinator, LifetimeLease)> {
    acquire_target_usage_lease_with_hook(target, |_| Ok(()))
}

fn acquire_target_usage_lease_with_hook<F>(
    target: &Path,
    after_coordinator: F,
) -> Result<(TargetCoordinator, LifetimeLease)>
where
    F: FnOnce(&Path) -> Result<()>,
{
    let path = target_lock_path(target);
    let (file, identity) = open_private_owner_file(&path, "target lock")?;
    match set_ofd_range_lock(
        &file,
        libc::F_WRLCK as libc::c_short,
        COORDINATOR_LOCK_RANGE,
        true,
    )? {
        OfdLockResult::Acquired => {}
        OfdLockResult::Unsupported => return acquire_legacy_target_usage_lease(target),
        OfdLockResult::Busy => return Err(Error::new(Other, "target coordinator is busy")),
    }
    verify_locked_file_identity(&file, identity, &path, "target lock")?;
    after_coordinator(&path)?;
    match set_ofd_range_lock(
        &file,
        libc::F_RDLCK as libc::c_short,
        LIFETIME_LOCK_RANGE,
        true,
    )? {
        OfdLockResult::Acquired => {
            verify_locked_file_identity(&file, identity, &path, "target lock")?;
            let coordinator_file = file.try_clone()?;
            Ok((
                TargetCoordinator::Ofd {
                    _lock: OfdRangeLock {
                        file: coordinator_file,
                        identity,
                        start: COORDINATOR_LOCK_RANGE,
                        unlock_on_drop: true,
                    },
                },
                LifetimeLease::Ofd(OfdRangeLock {
                    file,
                    identity,
                    start: LIFETIME_LOCK_RANGE,
                    unlock_on_drop: false,
                }),
            ))
        }
        OfdLockResult::Unsupported => acquire_legacy_target_usage_lease(target),
        OfdLockResult::Busy => Err(Error::new(Other, "lifetime lease is busy")),
    }
}

fn try_acquire_ofd_cleanup_lease(target: &Path) -> Result<Option<Option<CleanupLease>>> {
    let path = target_lock_path(target);
    let (file, identity) = open_private_owner_file(&path, "target lock")?;
    match set_ofd_range_lock(
        &file,
        libc::F_WRLCK as libc::c_short,
        COORDINATOR_LOCK_RANGE,
        true,
    )? {
        OfdLockResult::Acquired => {}
        OfdLockResult::Unsupported => return Ok(None),
        OfdLockResult::Busy => return Ok(Some(None)),
    }
    verify_locked_file_identity(&file, identity, &path, "target lock")?;
    match set_ofd_range_lock(
        &file,
        libc::F_WRLCK as libc::c_short,
        LIFETIME_LOCK_RANGE,
        false,
    )? {
        OfdLockResult::Acquired => {
            verify_locked_file_identity(&file, identity, &path, "target lock")?;
            let coordinator_file = file.try_clone()?;
            Ok(Some(Some(CleanupLease {
                _coordinator: TargetCoordinator::Ofd {
                    _lock: OfdRangeLock {
                        file: coordinator_file,
                        identity,
                        start: COORDINATOR_LOCK_RANGE,
                        unlock_on_drop: true,
                    },
                },
                _lease: LifetimeLease::Ofd(OfdRangeLock {
                    file,
                    identity,
                    start: LIFETIME_LOCK_RANGE,
                    unlock_on_drop: true,
                }),
            })))
        }
        OfdLockResult::Busy => Ok(Some(None)),
        OfdLockResult::Unsupported => Ok(None),
    }
}

fn try_acquire_legacy_cleanup_lease(target: &Path) -> Result<Option<CleanupLease>> {
    let coordinator_path = legacy_record_lock_path(&target_lease_path(target))?;
    let coordinator =
        acquire_legacy_flock(&coordinator_path, "lifetime coordinator", libc::LOCK_EX)?
            .ok_or_else(|| Error::new(Other, "lifetime coordinator is busy"))?;
    match LifetimeLease::acquire_legacy(target, libc::LOCK_EX | libc::LOCK_NB)? {
        Some(lease) => Ok(Some(CleanupLease {
            _coordinator: TargetCoordinator::Legacy { _file: coordinator },
            _lease: lease,
        })),
        None => Ok(None),
    }
}

fn acquire_cleanup_lease(target: &Path) -> Result<CleanupLease> {
    loop {
        let acquired = match try_acquire_ofd_cleanup_lease(target)? {
            Some(result) => result,
            None => try_acquire_legacy_cleanup_lease(target)?,
        };
        match acquired {
            Some(lease) => return Ok(lease),
            None => sleep(Duration::from_millis(100)),
        }
    }
}

fn acquire_optional_cleanup_lease(target: &Path, enabled: bool) -> Result<Option<CleanupLease>> {
    if enabled {
        acquire_cleanup_lease(target).map(Some)
    } else {
        Ok(None)
    }
}

fn cleanup_lease_or_exit(target: &Path, enabled: bool) -> Option<CleanupLease> {
    acquire_optional_cleanup_lease(target, enabled).unwrap_or_else(|err| {
        eprintln!(
            "Failed to acquire cleanup lease for {}: {err}",
            target.display()
        );
        exit(1)
    })
}

enum RecordLock {
    Ofd { _lock: OfdRangeLock },
    Legacy { _file: File },
}

impl RecordLock {
    fn acquire(
        target: &Path,
        record_path: &Path,
        lifetime_lease: Option<&LifetimeLease>,
    ) -> Result<Self> {
        if let Some(LifetimeLease::Ofd(lease)) = lifetime_lease {
            let file = lease.file.try_clone()?;
            return match set_ofd_range_lock(
                &file,
                libc::F_WRLCK as libc::c_short,
                RECORD_LOCK_RANGE,
                true,
            )? {
                OfdLockResult::Acquired => {
                    verify_locked_file_identity(
                        &file,
                        lease.identity,
                        &target_lock_path(target),
                        "target lock",
                    )?;
                    Ok(Self::Ofd {
                        _lock: OfdRangeLock {
                            file,
                            identity: lease.identity,
                            start: RECORD_LOCK_RANGE,
                            unlock_on_drop: true,
                        },
                    })
                }
                OfdLockResult::Busy => Err(Error::new(Other, "record lock is busy")),
                OfdLockResult::Unsupported => Self::acquire_legacy(record_path),
            };
        }
        let path = target_lock_path(target);
        let (file, identity) = open_private_owner_file(&path, "target lock")?;
        match set_ofd_range_lock(
            &file,
            libc::F_WRLCK as libc::c_short,
            RECORD_LOCK_RANGE,
            true,
        )? {
            OfdLockResult::Acquired => {
                verify_locked_file_identity(&file, identity, &path, "target lock")?;
                Ok(Self::Ofd {
                    _lock: OfdRangeLock {
                        file,
                        identity,
                        start: RECORD_LOCK_RANGE,
                        unlock_on_drop: true,
                    },
                })
            }
            OfdLockResult::Busy => Err(Error::new(Other, "record lock is busy")),
            OfdLockResult::Unsupported => Self::acquire_legacy(record_path),
        }
    }

    fn acquire_legacy(record_path: &Path) -> Result<Self> {
        let lock_path = legacy_record_lock_path(record_path)?;
        let file = acquire_legacy_flock(&lock_path, "record lock", libc::LOCK_EX)?
            .ok_or_else(|| Error::new(Other, "record lock is busy"))?;
        Ok(Self::Legacy { _file: file })
    }
}

struct TemporaryPublication {
    path: PathBuf,
    published: bool,
}

impl Drop for TemporaryPublication {
    fn drop(&mut self) {
        if !self.published {
            let _ = remove_file(&self.path);
        }
    }
}

fn atomic_publish_file_with<F>(
    target: &Path,
    path: &Path,
    lifetime_lease: Option<&LifetimeLease>,
    content: &[u8],
    before_rename: F,
) -> Result<()>
where
    F: FnOnce(&Path) -> Result<()>,
{
    let _record_lock = RecordLock::acquire(target, path, lifetime_lease)?;
    scavenge_record_temporary_entries(path);
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = path.file_name().ok_or_else(|| {
        Error::new(
            InvalidInput,
            format!("cannot publish a record at {}", path.display()),
        )
    })?;
    let (mut temporary, mut file) = {
        let mut opened = None;
        for _ in 0..128 {
            let mut name = file_name.to_os_string();
            name.push(format!(".tmp.{}.{}", std::process::id(), random_string(12)));
            let temporary_path = parent.join(name);
            match fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&temporary_path)
            {
                Ok(file) => {
                    opened = Some((
                        TemporaryPublication {
                            path: temporary_path,
                            published: false,
                        },
                        file,
                    ));
                    break;
                }
                Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(err) => return Err(err),
            }
        }
        opened.ok_or_else(|| {
            Error::new(
                std::io::ErrorKind::AlreadyExists,
                format!(
                    "failed to allocate a temporary record beside {}",
                    path.display()
                ),
            )
        })?
    };
    file.write_all(content)?;
    file.sync_all()?;
    before_rename(&temporary.path)?;
    drop(file);
    fs::rename(&temporary.path, path)?;
    temporary.published = true;
    Ok(())
}

fn write_mount_pid_file(
    mount_point: &Path,
    pid: Pid,
    namespace: NamespaceOutcome,
    mapping: IdMapping,
    lifetime_lease: Option<&LifetimeLease>,
) -> Result<()> {
    let pidfile_ext = if namespace.kind.is_unshared() {
        "un.pid"
    } else {
        "pid"
    };
    let pidfile_path = mount_point.with_extension(pidfile_ext);
    let process_starttime = read_process_starttime(pid).ok_or_else(|| {
        Error::new(
            NotFound,
            format!("failed to read process generation for mount owner PID {pid}"),
        )
    })?;
    let namespace_files = NamespaceFiles::open(&pid.to_string()).map_err(|err| {
        Error::new(
            err.kind(),
            format!("failed to open namespaces for mount owner PID {pid}: {err}"),
        )
    })?;
    let namespace_identities = namespace_files.identities().map_err(|err| {
        Error::new(
            err.kind(),
            format!("failed to identify namespaces for mount owner PID {pid}: {err}"),
        )
    })?;
    if read_process_starttime(pid) != Some(process_starttime) {
        return Err(Error::new(
            NotFound,
            format!("mount owner PID {pid} changed while recording its identity"),
        ));
    }
    let record = MountPidRecord {
        pid,
        namespace_kind: Some(namespace.kind),
        mapping: Some(mapping),
        process_starttime: Some(process_starttime),
        namespace_identities: Some(namespace_identities),
    };
    let serialized = format_mount_pid_record(&record);
    atomic_publish_file_with(
        mount_point,
        &pidfile_path,
        lifetime_lease,
        serialized.as_bytes(),
        |_| Ok(()),
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TryReuseResult {
    Reused(MountPidRecord),
    StaleRemoved,
    Unavailable,
    Rejected,
    IrreversibleFailure,
}

fn try_reuse_unshare_mount_point(
    mount_point: &Path,
    requested_mapping: IdMapping,
    explicit_mapping: bool,
    lifetime_lease: Option<&LifetimeLease>,
) -> TryReuseResult {
    try_reuse_unshare_mount_point_for_mode_with(
        mount_point,
        requested_mapping,
        explicit_mapping,
        lifetime_lease,
        |path| is_mounted(path).unwrap_or(false),
        try_setns,
    )
}

fn try_reuse_unshare_mount_point_for_mode_with<M, N>(
    mount_point: &Path,
    requested_mapping: IdMapping,
    explicit_mapping: bool,
    lifetime_lease: Option<&LifetimeLease>,
    mounted: M,
    enter_namespaces: N,
) -> TryReuseResult
where
    M: FnOnce(&Path) -> bool,
    N: FnOnce(Pid, NamespaceKind, Option<u64>, Option<NamespaceIdentities>) -> NamespaceEntryResult,
{
    try_reuse_unshare_mount_point_for_mode_with_lock_hook(
        mount_point,
        requested_mapping,
        explicit_mapping,
        lifetime_lease,
        || {},
        mounted,
        enter_namespaces,
    )
}

fn try_reuse_unshare_mount_point_for_mode_with_lock_hook<L, M, N>(
    mount_point: &Path,
    requested_mapping: IdMapping,
    explicit_mapping: bool,
    lifetime_lease: Option<&LifetimeLease>,
    after_lock: L,
    mounted: M,
    enter_namespaces: N,
) -> TryReuseResult
where
    L: FnOnce(),
    M: FnOnce(&Path) -> bool,
    N: FnOnce(Pid, NamespaceKind, Option<u64>, Option<NamespaceIdentities>) -> NamespaceEntryResult,
{
    let record_path = mount_point.with_extension("un.pid");
    let _record_lock = match RecordLock::acquire(mount_point, &record_path, lifetime_lease) {
        Ok(lock) => lock,
        Err(_) => return TryReuseResult::Rejected,
    };
    after_lock();
    let record = match read_mount_pid_file(mount_point, "un.pid") {
        Some(record) => record,
        None => return TryReuseResult::Rejected,
    };
    if !record_namespace_matches_extension(&record, "un.pid") {
        return TryReuseResult::Rejected;
    }
    if record.namespace_identities.is_none() {
        return TryReuseResult::Unavailable;
    }
    if !record_reusable_for_mapping(&record, requested_mapping, explicit_mapping) {
        return TryReuseResult::Rejected;
    }
    if !is_pid_exists(record.pid) {
        return match remove_file(&record_path) {
            Ok(()) => TryReuseResult::StaleRemoved,
            Err(_) => TryReuseResult::Rejected,
        };
    }
    let namespace_kind = match record.namespace_kind {
        Some(kind) => kind,
        None => return TryReuseResult::Unavailable,
    };
    match enter_namespaces(
        record.pid,
        namespace_kind,
        record.process_starttime,
        record.namespace_identities,
    ) {
        NamespaceEntryResult::Entered => {
            if mounted(mount_point) {
                TryReuseResult::Reused(record)
            } else {
                // Namespace entry may already have changed this process. Never
                // classify a missing mount after entry as safely unavailable,
                // because that would permit a fresh-mount fallback in the
                // transitioned namespace.
                TryReuseResult::Rejected
            }
        }
        NamespaceEntryResult::Unavailable => TryReuseResult::Unavailable,
        NamespaceEntryResult::Rejected => TryReuseResult::Rejected,
        NamespaceEntryResult::IrreversibleFailure => TryReuseResult::IrreversibleFailure,
    }
}

struct FuseState<'a> {
    namespace_outcome: &'a mut Option<NamespaceOutcome>,
    is_unshare: &'a mut bool,
}

fn check_fuse(
    uruntime: &Path,
    uid: u32,
    gid: u32,
    requested_mapping: IdMapping,
    mapping_requested: bool,
    state: FuseState<'_>,
    is_mount_only: bool,
) -> bool {
    if access("/dev/fuse", AccessFlags::R_OK | AccessFlags::W_OK).is_err() {
        return false;
    }
    let procfs_available = process_procfs_available_at(Path::new("/proc"));
    let in_user_and_mount_namespace = procfs_available && is_in_user_and_mount_namespace();
    let has_cap_sys_admin = has_effective_capability(CAP_SYS_ADMIN);
    let existing_unshare_succeeded = state
        .namespace_outcome
        .is_some_and(|outcome| outcome.kind.is_unshared());
    if can_mount_directly(
        uid,
        existing_unshare_succeeded,
        in_user_and_mount_namespace,
        procfs_available,
        has_cap_sys_admin,
        is_mount_only,
    ) {
        let mount_private_succeeded =
            procfs_available || !has_cap_sys_admin || try_make_mount_private();
        match direct_mount_setup_outcome(
            *state.namespace_outcome,
            procfs_available,
            has_cap_sys_admin,
            mount_private_succeeded,
        ) {
            DirectMountSetupResult::Ready(outcome) => {
                *state.namespace_outcome = Some(outcome);
                return true;
            }
            DirectMountSetupResult::Unavailable => {
                eprintln!(
                    "Failed to make the current mount namespace private: {}",
                    Error::last_os_error()
                );
                return false;
            }
        }
    }
    fn create_fusermount_dir(tmp_path_dir: &PathBuf) -> bool {
        if !tmp_path_dir.is_dir() {
            if let Err(err) = create_dir_all(tmp_path_dir) {
                eprintln!(
                    "Failed to create fusermount PATH dir: {err}: {:?}",
                    tmp_path_dir
                );
                return false;
            }
            add_to_path(tmp_path_dir);
        }
        true
    }
    fn create_fusermount_symlink(
        tmp_path_dir: &Path,
        fusermount_path: &str,
        fusermount_name: &str,
    ) -> bool {
        let fsmntlink_path = tmp_path_dir.join(fusermount_name);
        let _ = remove_file(&fsmntlink_path);
        if let Err(err) = symlink(fusermount_path, &fsmntlink_path) {
            eprintln!(
                "Failed to create fusermount symlink: {err}: {:?}",
                fsmntlink_path
            );
            return false;
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
                        continue;
                    }
                    if let Some(ref uruntime_canonical) = uruntime_path {
                        if canonical_path == *uruntime_canonical {
                            continue;
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
        if !create_fusermount_dir(tmp_path_dir) {
            exit(1)
        }
        if !create_fusermount_symlink(tmp_path_dir, fusermount_prog, basename(fusermount_prog)) {
            exit(1)
        }
    } else {
        for fusermount in fusermount_list {
            if find_suid_exe(fusermount).is_some() {
                continue;
            }
            let fallback: &str = if fusermount.ends_with("3") {
                "fusermount"
            } else {
                "fusermount3"
            };
            if let Some(fusermount_path) = find_suid_exe(fallback) {
                if !create_fusermount_dir(tmp_path_dir) {
                    break;
                }
                if !create_fusermount_symlink(
                    tmp_path_dir,
                    &fusermount_path.to_string_lossy(),
                    fusermount,
                ) {
                    break;
                }
                break;
            }
            is_fusermount = false
        }
    }
    if !is_fusermount {
        eprintln!("SUID fusermount not found in PATH, trying to unshare...");
        *state.is_unshare = true;
        match try_unshare(uid, gid, requested_mapping, mapping_requested) {
            TryUnshareResult::Created(outcome) => {
                *state.namespace_outcome = Some(outcome);
                return true;
            }
            TryUnshareResult::Unavailable => {}
            TryUnshareResult::IrreversibleFailure => exit(1),
        }
        for fusermount in fusermount_list {
            if !create_fusermount_dir(tmp_path_dir) {
                break;
            }
            if !create_fusermount_symlink(tmp_path_dir, &uruntime.to_string_lossy(), fusermount) {
                break;
            }
        }
    }
    if state.namespace_outcome.is_none() {
        *state.namespace_outcome = Some(NamespaceOutcome::current(false));
    }
    true
}

macro_rules! check_extract {
    (
        $is_mount_only:expr,
        $uruntime_extract:expr,
        $self_exe:expr,
        $self_size:expr,
        $true_block:block
    ) => {
        eprintln!(
            "{}: failed to utilize FUSE during startup!",
            basename($self_exe.to_str().unwrap_or_default())
        );
        if !$is_mount_only
            && ($uruntime_extract == 2
                || ($uruntime_extract == 3 && $self_size <= MAX_EXTRACT_SELF_SIZE))
        {
            $true_block
        } else {
            eprintln!(
                "Cannot mount {SELF_NAME}, please check your FUSE setup.
You might still be able to extract the contents of this {SELF_NAME}
if you run it with the --{ARG_PFX}-extract option
See https://github.com/AppImage/AppImageKit/wiki/FUSE
and run it with the --{ARG_PFX}-help option for more information"
            );
            exit(1)
        }
    };
}

fn get_section_index(elf: &Elf<'_>, section_name: &str) -> Result<usize> {
    let section_index = elf
        .section_headers
        .iter()
        .position(|sh| {
            if let Some(name) = elf.shdr_strtab.get_at(sh.sh_name) {
                name == section_name
            } else {
                false
            }
        })
        .ok_or(Error::new(
            InvalidData,
            format!("Section header with name '{section_name}' not found!"),
        ))?;
    Ok(section_index)
}

fn get_section_header(headers_bytes: &[u8], section_name: &str) -> Result<SectionHeader> {
    let elf = Elf::parse(headers_bytes).map_err(|err| Error::new(InvalidData, err))?;
    let section_index = get_section_index(&elf, section_name)?;
    elf.section_headers
        .get(section_index)
        .cloned()
        .ok_or_else(|| Error::new(InvalidData, "section index is outside the section table"))
}

fn section_bytes<'a>(headers_bytes: &'a [u8], section: &SectionHeader) -> Result<&'a [u8]> {
    let start = usize::try_from(section.sh_offset)
        .map_err(|_| Error::new(InvalidData, "section offset does not fit in memory"))?;
    let size = usize::try_from(section.sh_size)
        .map_err(|_| Error::new(InvalidData, "section size does not fit in memory"))?;
    let end = start
        .checked_add(size)
        .ok_or_else(|| Error::new(InvalidData, "section range overflows"))?;
    headers_bytes
        .get(start..end)
        .ok_or_else(|| Error::new(InvalidData, "section range is outside the ELF prefix"))
}

fn get_section_data(headers_bytes: &[u8], section_name: &str) -> Result<String> {
    let section = get_section_header(headers_bytes, section_name)?;
    let section_data = section_bytes(headers_bytes, &section)?;
    if let Ok(data_str) = str::from_utf8(section_data) {
        Ok(data_str.trim().trim_matches('\0').into())
    } else {
        Err(Error::new(
            InvalidData,
            format!("Section data is not valid UTF-8: {section_name}"),
        ))
    }
}

fn add_section_data(runtime: &Runtime, section_name: &str, exec_args: &[String]) -> Result<()> {
    if get_env_var!("TARGET_{}", ENV_NAME).is_empty() {
        env::set_var(format!("TARGET_{ENV_NAME}"), &runtime.path);
        env::set_var("URUNTIME_TARGET_DEV", runtime.identity.dev.to_string());
        env::set_var("URUNTIME_TARGET_INO", runtime.identity.ino.to_string());
        mfd_exec("uruntime", &runtime.headers_bytes, exec_args.to_vec());
    }
    let expected_dev = get_env_var!("URUNTIME_TARGET_DEV");
    let expected_ino = get_env_var!("URUNTIME_TARGET_INO");
    if !expected_dev.is_empty()
        && !expected_ino.is_empty()
        && (expected_dev.parse::<u64>().ok() != Some(runtime.identity.dev)
            || expected_ino.parse::<u64>().ok() != Some(runtime.identity.ino))
    {
        return Err(Error::new(
            InvalidData,
            "target executable changed during maintenance re-exec",
        ));
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
    } else {
        &[]
    };
    let new_size = string_bytes.len() as u64;
    if new_size > original_size {
        return Err(Error::new(
            InvalidData,
            "New section header data is larger than the section size!",
        ));
    }
    let mut file = fs::OpenOptions::new().write(true).open(&runtime.path)?;
    if FileIdentity::from_metadata(&file.metadata()?) != runtime.identity {
        return Err(Error::new(
            InvalidData,
            "target executable changed before section update",
        ));
    }
    file.seek(SeekFrom::Start(offset))?;
    file.write_all(string_bytes)?;
    if new_size < original_size {
        let padding_size = original_size
            .checked_sub(new_size)
            .ok_or_else(|| Error::new(InvalidData, "section padding underflows"))?;
        let padding_size = usize::try_from(padding_size)
            .map_err(|_| Error::new(InvalidData, "section padding does not fit in memory"))?;
        let padding = vec![0u8; padding_size];
        file.write_all(&padding)?;
    }
    Ok(())
}

fn get_runtime(executable: &SelfExecutable) -> Result<Runtime> {
    let mut file = &executable.file;
    file.seek(SeekFrom::Start(0))?;
    let prefix = elf_layout::read_elf_prefix(&mut file, executable.size)?;
    let headers_bytes = prefix.bytes;
    let elf = Elf::parse(&headers_bytes).map_err(|err| Error::new(InvalidData, err))?;
    let envs = match get_section_index(&elf, ".envs") {
        Ok(section_index) => {
            let section = elf.section_headers.get(section_index).ok_or_else(|| {
                Error::new(
                    InvalidData,
                    "environment section index is outside the section table",
                )
            })?;
            str::from_utf8(section_bytes(&headers_bytes, section)?)
                .unwrap_or_default()
                .trim_matches('\0')
                .to_string()
        }
        Err(_) => "".into(),
    };
    Ok(Runtime {
        path: executable.location.clone(),
        identity: executable.identity,
        headers_bytes,
        size: prefix.boundary,
        envs,
    })
}

fn random_string(length: usize) -> String {
    const CHARSET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let mut rng = time::SystemTime::now()
        .duration_since(time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    let mut result = String::with_capacity(length);
    for _ in 0..length {
        rng = rng.wrapping_mul(48271).wrapping_rem(0x7FFFFFFF);
        let idx = (rng as u64 % CHARSET.len() as u64) as usize;
        if let Some(value) = CHARSET.get(idx) {
            result.push(*value as char);
        }
    }
    result
}

fn basename(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or_default()
}

fn executable_path_from_auxv() -> Result<PathBuf> {
    // AT_EXECFN preserves the filename given to execve(2), independently of procfs.
    // In particular, a shell that resolves a bare command through PATH records the
    // resolved filename here while argv[0] may still be only the command name.
    let path = unsafe {
        let ptr = libc::getauxval(libc::AT_EXECFN) as *const libc::c_char;
        if ptr.is_null() {
            return Err(Error::new(NotFound, "AT_EXECFN is unavailable"));
        }
        PathBuf::from(std::ffi::OsStr::from_bytes(CStr::from_ptr(ptr).to_bytes()))
    };
    path.canonicalize()
}

fn executable_path(arg0: &str) -> Result<PathBuf> {
    current_exe()
        .or_else(|_| executable_path_from_auxv())
        .or_else(|_| {
            let path = PathBuf::from(arg0);
            if path.components().count() > 1 {
                path.canonicalize()
            } else {
                which::which(&path)
                    .map_err(|error| Error::new(NotFound, error.to_string()))?
                    .canonicalize()
            }
        })
}

fn exec_self_fd(executable: &SelfExecutable, args: &[String]) -> Result<()> {
    exec_self_fd_with(
        executable,
        args,
        &[Path::new("/proc/self/fd"), Path::new("/dev/fd")],
        |fd, argv, envp| {
            let result = unsafe {
                libc::syscall(
                    libc::SYS_execveat,
                    fd,
                    c"".as_ptr(),
                    argv,
                    envp,
                    libc::AT_EMPTY_PATH,
                )
            };
            if result == -1 {
                Err(Error::last_os_error())
            } else {
                Ok(())
            }
        },
    )
}

fn exec_self_fd_with<F>(
    executable: &SelfExecutable,
    args: &[String],
    fd_roots: &[&Path],
    try_execveat: F,
) -> Result<()>
where
    F: FnOnce(RawFd, *const *const libc::c_char, *const *const libc::c_char) -> Result<()>,
{
    let argv_capacity = args
        .len()
        .checked_add(1)
        .ok_or_else(|| Error::new(InvalidData, "argument count overflows"))?;
    let mut argv = Vec::new();
    argv.try_reserve_exact(argv_capacity)
        .map_err(|error| Error::other(format!("failed to reserve argument storage: {error}")))?;
    argv.push(
        CString::new(executable.location.as_os_str().as_bytes())
            .map_err(|error| Error::new(InvalidData, error))?,
    );
    for arg in args {
        argv.push(CString::new(arg.as_bytes()).map_err(|error| Error::new(InvalidData, error))?);
    }
    let mut argv_ptrs: Vec<*const libc::c_char> = argv.iter().map(|arg| arg.as_ptr()).collect();
    argv_ptrs.push(std::ptr::null());

    let mut envp = Vec::new();
    for (name, value) in env::vars_os() {
        let mut entry = name.as_os_str().as_bytes().to_vec();
        entry.push(b'=');
        entry.extend_from_slice(value.as_os_str().as_bytes());
        envp.push(CString::new(entry).map_err(|error| Error::new(InvalidData, error))?);
    }
    let mut envp_ptrs: Vec<*const libc::c_char> = envp.iter().map(|entry| entry.as_ptr()).collect();
    envp_ptrs.push(std::ptr::null());

    let err = match try_execveat(
        executable.file.as_raw_fd(),
        argv_ptrs.as_ptr(),
        envp_ptrs.as_ptr(),
    ) {
        Ok(()) => {
            return Err(Error::other(
                "execveat unexpectedly returned success without replacing the process",
            ));
        }
        Err(err) => err,
    };
    match err.raw_os_error() {
        // execveat(AT_EMPTY_PATH) is not usable here (kernel < 3.19, or a
        // compatibility layer such as the FreeBSD Linuxulator). Prefer a
        // kernel-provided descriptor path verified against the held inode.
        // As a final compatibility fallback, verify the original pathname's
        // dev/ino immediately before execve. That check is best-effort because
        // pathname verification and execve(path) cannot be atomic.
        Some(libc::ENOSYS) | Some(libc::ENOTSUP) | Some(libc::EINVAL) | Some(libc::EPERM) => {
            let source =
                descriptor_source(&executable.file, fd_roots, "executable").or_else(|_| {
                    pathname_source(&executable.file, &executable.location, "executable")
                })?;
            // execve resolves /proc/self/fd/N or /dev/fd/N before applying
            // close-on-exec, so the retained self-executable FD must remain
            // CLOEXEC. Image descriptors inherited by helper processes use
            // HelperSource::prepare_for_exec separately.
            let path_c = CString::new(source.path.as_os_str().as_bytes())
                .map_err(|error| Error::new(InvalidData, error))?;
            unsafe {
                libc::execve(path_c.as_ptr(), argv_ptrs.as_ptr(), envp_ptrs.as_ptr());
            }
            Err(Error::last_os_error())
        }
        _ => Err(err),
    }
}

fn is_broken_mount_errno(err: Errno) -> bool {
    err == Errno::ENOTCONN || err == Errno::ESTALE || err == Errno::EIO
}

fn get_metadata_or_broken_mount(path: &Path) -> Result<Metadata> {
    match fs::metadata(path) {
        Ok(m) => Ok(m),
        Err(err) => {
            if let Some(errno) = Errno::from_raw(err.raw_os_error().unwrap_or(0)).into() {
                if is_broken_mount_errno(errno) {
                    return Err(Error::new(Other, "broken mount point"));
                }
            }
            Err(err)
        }
    }
}

fn is_mount_point_at(full_path: &Path) -> Result<bool> {
    let metadata = match get_metadata_or_broken_mount(full_path) {
        Ok(m) => m,
        Err(err) if err.kind() == Other => return Ok(true),
        Err(err) => return Err(err),
    };
    let device_id = metadata.dev();
    match full_path.parent() {
        Some(parent) => {
            let parent_metadata = match get_metadata_or_broken_mount(parent) {
                Ok(m) => m,
                Err(err) if err.kind() == Other => return Ok(true),
                Err(err) => return Err(err),
            };
            Ok(device_id != parent_metadata.dev())
        }
        None => Ok(false),
    }
}

fn is_mount_point(path: &Path) -> Result<bool> {
    let full_path = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    is_mount_point_at(&full_path)
}

fn is_mounted(path: &Path) -> Result<bool> {
    let full_path = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    let is_mount = is_mount_point_at(&full_path)?;
    if is_mount {
        match open(
            &full_path,
            OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC,
            Mode::empty(),
        ) {
            Ok(fd) => {
                let _ = close(fd);
            }
            Err(err) => {
                if is_broken_mount_errno(err) {
                    try_unmount(None, &full_path);
                    return Ok(false);
                }
                return Err(Error::from(err));
            }
        }
    }
    Ok(is_mount)
}

fn is_suid_exe(path: &PathBuf) -> Result<bool> {
    let metadata = fs::metadata(path)?;
    let permissions = metadata.permissions();
    let mode = permissions.mode();
    Ok((mode & 0o4000 != 0) && (mode & 0o111 != 0))
}

fn find_suid_exe(name: &str) -> Option<PathBuf> {
    for path in which_all(name).ok()? {
        let canonical_path = path.canonicalize().unwrap_or(path);
        if is_suid_exe(&canonical_path).unwrap_or(false) {
            return Some(canonical_path);
        }
    }
    None
}

fn process_procfs_available_with<F>(proc_root: &Path, probe: F) -> bool
where
    F: FnOnce(&Path) -> Result<()>,
{
    let stat = proc_root.join("self/stat");
    stat.is_file() && probe(&stat).is_ok()
}

fn process_procfs_available_at(proc_root: &Path) -> bool {
    process_procfs_available_with(proc_root, |stat| {
        let mut file = File::open(stat)?;
        let mut byte = [0_u8; 1];
        file.read_exact(&mut byte)
    })
}

fn cleanup_observation_complete(_procfs_available: bool, child_subreaper_enabled: bool) -> bool {
    child_subreaper_enabled
}

fn reusable_mount_expiry_available(procfs_available: bool, cap_sys_admin: bool) -> bool {
    !procfs_available || cap_sys_admin
}

fn application_supervisor_required(is_extract_run: bool) -> bool {
    is_extract_run
}

fn extraction_cleanup_requires_descendant_visibility(
    application_state: ApplicationState,
    is_extract_run: bool,
    application_tree_observable: bool,
) -> bool {
    application_state == ApplicationState::Started && is_extract_run && !application_tree_observable
}

fn enable_child_subreaper_with<F>(mut enable: F) -> Result<bool>
where
    F: FnMut() -> Result<()>,
{
    match enable() {
        Ok(()) => Ok(true),
        Err(err)
            if matches!(
                err.raw_os_error(),
                Some(libc::EINVAL) | Some(libc::ENOSYS) | Some(libc::EPERM) | Some(libc::EACCES)
            ) =>
        {
            Ok(false)
        }
        Err(err) => Err(err),
    }
}

fn enable_child_subreaper() -> Result<bool> {
    enable_child_subreaper_with(|| {
        if unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) } == 0 {
            Ok(())
        } else {
            Err(Error::last_os_error())
        }
    })
}

fn write_supervisor_value(fd: RawFd, value: i32) -> Result<()> {
    let bytes = value.to_ne_bytes();
    let mut offset = 0_usize;
    while offset < bytes.len() {
        let written = unsafe {
            libc::write(
                fd,
                bytes.as_ptr().add(offset).cast(),
                bytes.len().saturating_sub(offset),
            )
        };
        if written > 0 {
            offset = offset.saturating_add(written as usize);
            continue;
        }
        if written == 0 {
            return Err(Error::new(
                std::io::ErrorKind::WriteZero,
                "supervisor pipe closed",
            ));
        }
        let err = Error::last_os_error();
        if err.kind() != std::io::ErrorKind::Interrupted {
            return Err(err);
        }
    }
    Ok(())
}

fn read_supervisor_value(fd: RawFd) -> Result<Option<i32>> {
    let mut bytes = [0_u8; std::mem::size_of::<i32>()];
    let mut offset = 0_usize;
    while offset < bytes.len() {
        let read = unsafe {
            libc::read(
                fd,
                bytes.as_mut_ptr().add(offset).cast(),
                bytes.len().saturating_sub(offset),
            )
        };
        if read > 0 {
            offset = offset.saturating_add(read as usize);
            continue;
        }
        if read == 0 {
            return if offset == 0 {
                Ok(None)
            } else {
                Err(Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "partial supervisor status message",
                ))
            };
        }
        let err = Error::last_os_error();
        if err.kind() != std::io::ErrorKind::Interrupted {
            return Err(err);
        }
    }
    Ok(Some(i32::from_ne_bytes(bytes)))
}

fn wait_for_all_children() -> Result<()> {
    loop {
        match waitpid(Pid::from_raw(-1), None) {
            Ok(_) => {}
            Err(Errno::EINTR) => {}
            Err(Errno::ECHILD) => return Ok(()),
            Err(err) => return Err(Error::from_raw_os_error(err as i32)),
        }
    }
}

fn create_lifetime_pipe() -> Result<(OwnedFd, OwnedFd)> {
    let mut fds = [-1; 2];
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(Error::last_os_error());
    }
    let [reader, writer] = fds;
    Ok(unsafe { (OwnedFd::from_raw_fd(reader), OwnedFd::from_raw_fd(writer)) })
}

fn clear_fd_cloexec(fd: RawFd) -> Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags == -1 || unsafe { libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) } == -1 {
        return Err(Error::last_os_error());
    }
    Ok(())
}

fn wait_for_lifetime_end(fd: OwnedFd) -> Result<()> {
    let mut byte = 0u8;
    loop {
        let read = unsafe { libc::read(fd.as_raw_fd(), (&mut byte as *mut u8).cast(), 1) };
        if read == 0 {
            return Ok(());
        }
        if read < 0 {
            let err = Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err);
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ApplicationState {
    NotLaunched,
    Started,
    NeverStarted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CleanupExecution {
    Skip,
    Detached,
    Inline,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CleanupWork {
    ImmediateMount,
    ImmediateExtraction,
    Normal,
}

fn cleanup_work_for_application(
    application: ApplicationState,
    is_extract_run: bool,
    is_mount: bool,
) -> CleanupWork {
    if application != ApplicationState::NeverStarted {
        CleanupWork::Normal
    } else if is_mount {
        CleanupWork::ImmediateMount
    } else if is_extract_run {
        CleanupWork::ImmediateExtraction
    } else {
        CleanupWork::Normal
    }
}

fn cleanup_exit_code(execution: CleanupExecution, application_exit_code: i32) -> i32 {
    if execution == CleanupExecution::Inline {
        application_exit_code
    } else {
        0
    }
}

impl CleanupExecution {
    fn for_application(application: ApplicationState, reused_mount: bool) -> Self {
        if reused_mount {
            Self::Skip
        } else if application == ApplicationState::NeverStarted {
            Self::Inline
        } else {
            Self::Detached
        }
    }
}

fn finish_application_spawn<T>(
    result: Result<T>,
    lifetime_pipe: Option<(OwnedFd, OwnedFd)>,
) -> (ApplicationState, Result<T>, Option<OwnedFd>) {
    let lifetime_reader = lifetime_pipe.map(|(reader, writer)| {
        drop(writer);
        reader
    });
    let state = if result.is_ok() {
        ApplicationState::Started
    } else {
        ApplicationState::NeverStarted
    };
    (state, result, lifetime_reader)
}

fn is_dir_inuse(mount_point: &PathBuf) -> Result<bool> {
    for entry in fs::read_dir("/proc")? {
        if let Ok(target) = fs::read_link(entry?.path().join("exe")) {
            if target.starts_with(mount_point) {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

fn wait_dir_notuse(
    mount_point: &PathBuf,
    timeout: Option<Duration>,
    delay: Option<Duration>,
    delay_check: bool,
    lifetime_fd: Option<OwnedFd>,
) -> bool {
    let start_time = Instant::now();
    let default_delay = Duration::from_millis(100);
    let delay = delay.unwrap_or(default_delay);
    if !process_procfs_available_at(Path::new("/proc")) {
        let Some(fd) = lifetime_fd else {
            eprintln!(
                "Warning: cleanup was skipped because procfs and the application lifetime descriptor are unavailable"
            );
            return false;
        };
        if let Err(err) = wait_for_lifetime_end(fd) {
            eprintln!("Warning: failed to wait for the application lifetime descriptor: {err}");
            return false;
        }
        if delay_check {
            sleep(delay);
        }
        return true;
    }
    loop {
        if delay_check {
            sleep(delay);
            for num_check in 1..=5 {
                if is_dir_inuse(mount_point).unwrap_or(false) {
                    break;
                } else {
                    sleep(default_delay.checked_mul(2).unwrap_or(default_delay))
                }
                if num_check == 5 {
                    return true;
                }
            }
        } else {
            if !is_dir_inuse(mount_point).unwrap_or(false) {
                return true;
            }
            if let Some(timeout) = timeout {
                if start_time.elapsed() >= timeout {
                    return false;
                }
            }
        }
        sleep(delay)
    }
}

fn is_pid_exists(pid: Pid) -> bool {
    // Signal 0 is not delivered; it only checks whether the process exists.
    // Unlike /proc/{pid}, this also works without procfs.
    match kill(pid, None) {
        Ok(()) => true,
        Err(Errno::EPERM) => true,
        Err(_) => false,
    }
}

fn wait_pid_exit(pid: Pid, timeout: Option<Duration>) -> bool {
    let start_time = Instant::now();
    while is_pid_exists(pid) {
        if let Some(timeout) = timeout {
            if start_time.elapsed() >= timeout {
                return false;
            }
        }
        sleep(Duration::from_millis(10))
    }
    true
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ExpireMountResult {
    Unmounted,
    Marked,
    Busy,
    Unsupported,
    Failed,
}

fn classify_expire_mount_error(error: Errno) -> ExpireMountResult {
    match error {
        Errno::EAGAIN => ExpireMountResult::Marked,
        Errno::EBUSY => ExpireMountResult::Busy,
        Errno::EINVAL | Errno::ENOSYS | Errno::EOPNOTSUPP => ExpireMountResult::Unsupported,
        _ => ExpireMountResult::Failed,
    }
}

fn expire_mount_once(mount_point: &Path) -> ExpireMountResult {
    match umount2(mount_point, MntFlags::MNT_EXPIRE) {
        Ok(()) => ExpireMountResult::Unmounted,
        Err(error) => classify_expire_mount_error(error),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ExpireMountOutcome {
    Unmounted,
    Retained,
    FallbackUnmount,
}

fn try_expire_mount_with<E, S>(
    delay: Duration,
    mut expire_once: E,
    mut wait: S,
) -> ExpireMountOutcome
where
    E: FnMut() -> ExpireMountResult,
    S: FnMut(Duration),
{
    let mut result = expire_once();
    loop {
        match result {
            ExpireMountResult::Unmounted => return ExpireMountOutcome::Unmounted,
            ExpireMountResult::Marked => {
                wait(delay);
                result = expire_once();
            }
            ExpireMountResult::Unsupported => return ExpireMountOutcome::FallbackUnmount,
            ExpireMountResult::Busy | ExpireMountResult::Failed => {
                return ExpireMountOutcome::Retained;
            }
        }
    }
}

fn try_expire_mount(mount_point: &Path, delay: Duration) -> ExpireMountOutcome {
    let outcome = try_expire_mount_with(delay, || expire_mount_once(mount_point), sleep);
    if outcome == ExpireMountOutcome::Retained {
        eprintln!(
            "Reusable mount at {} remains mounted because expiry could not complete safely",
            mount_point.display()
        );
    }
    outcome
}

fn try_unmount(fuse_pid: Option<Pid>, mount_point: &Path) -> bool {
    if let Some(fuse_pid) = fuse_pid {
        sleep(Duration::from_millis(100));
        if !is_pid_exists(fuse_pid) {
            return false;
        }
    }
    if !is_mount_point(mount_point).unwrap_or(false) {
        eprintln!("{:?}: not mounted!", mount_point);
        return false;
    }

    let mut is_busy = false;

    let res = umount(mount_point);
    if res.is_ok() {
        return true;
    } else if let Err(err) = res {
        if err == nix::Error::from(Errno::EBUSY) {
            is_busy = true
        }
    }

    fn handle_command(cmd: &str, args: &Vec<&str>) -> (bool, bool) {
        match Command::new(cmd).args(args).output() {
            Ok(output) => {
                let stdout = String::from_utf8_lossy(&output.stdout);
                let stderr = String::from_utf8_lossy(&output.stderr);
                if !stdout.is_empty() {
                    println!("{stdout}")
                }
                if !stderr.is_empty() {
                    eprintln!("{stderr}")
                }
                return (
                    output.status.success(),
                    stderr.to_ascii_lowercase().contains("busy")
                        || stdout.to_ascii_lowercase().contains("busy"),
                );
            }
            Err(err) => {
                eprintln!("Failed to execute {cmd}: {err}")
            }
        }
        (false, false)
    }

    let args = vec![mount_point.to_str().unwrap_or_default()];
    let mut fusermount_args = args.clone();
    fusermount_args.insert(0, "-u");

    for fusermount in &["fusermount", "fusermount3"] {
        if is_busy {
            break;
        }
        let (success, busy) = handle_command(fusermount, &fusermount_args);
        if success {
            return true;
        } else if busy {
            is_busy = true
        }
    }

    if !is_busy {
        let (success, busy) = handle_command("umount", &args);
        if success {
            return true;
        } else if busy {
            is_busy = true
        }
    }

    if let Some(fuse_pid) = fuse_pid {
        if !is_busy && kill(fuse_pid, Signal::SIGTERM).is_ok() {
            return true;
        }
    }

    eprintln!("Failed to unmount: {:?}", mount_point);
    if fuse_pid.is_some() && is_mount_point(mount_point).unwrap_or(false) {
        eprintln!("Unmount it manually!");
    }
    false
}

fn wait_mount(pid: Pid, path: &PathBuf, timeout: Duration) -> bool {
    let start_time = Instant::now();
    spawn(move || waitpid(pid, None));
    while !is_mounted(path).unwrap_or(false) {
        if !is_pid_exists(pid) {
            eprintln!("The mount process ended unexpectedly! PID: {pid}");
            return false;
        } else if start_time.elapsed() >= timeout {
            eprintln!("Timeout reached while waiting for mount: {:?}", path);
            return false;
        }
        sleep(Duration::from_millis(2))
    }
    true
}

fn open_supervisor_stdio_sink(null_path: &Path, target: &Path) -> Result<File> {
    match fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(null_path)
    {
        Ok(file) => return Ok(file),
        Err(err) if err.kind() == NotFound => {}
        Err(err) => return Err(err),
    }

    for attempt in 0_u32..32 {
        let suffix = format!(".stdio.{}.{attempt}", unsafe { libc::getpid() });
        let path = append_target_sidecar(target, &suffix);
        match fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&path)
        {
            Ok(file) => {
                remove_file(&path)?;
                return Ok(file);
            }
            Err(err) if err.kind() == AlreadyExists => continue,
            Err(err) => return Err(err),
        }
    }
    Err(Error::new(
        AlreadyExists,
        "failed to allocate an anonymous supervisor stdio sink",
    ))
}

fn detach_supervisor_stdio_with(null_path: &Path, target: &Path) -> Result<()> {
    let sink = open_supervisor_stdio_sink(null_path, target)?;
    let sink = if sink.as_raw_fd() <= libc::STDERR_FILENO {
        let duplicated = unsafe { libc::fcntl(sink.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 3) };
        if duplicated == -1 {
            return Err(Error::last_os_error());
        }
        drop(sink);
        unsafe { File::from_raw_fd(duplicated) }
    } else {
        sink
    };
    for target in [libc::STDIN_FILENO, libc::STDOUT_FILENO, libc::STDERR_FILENO] {
        if unsafe { libc::dup2(sink.as_raw_fd(), target) } == -1 {
            return Err(Error::last_os_error());
        }
    }
    Ok(())
}

fn detach_supervisor_stdio(target: &Path) -> Result<()> {
    detach_supervisor_stdio_with(Path::new("/dev/null"), target)
}

fn try_setsid() {
    if let Err(err) = setsid() {
        eprintln!("Failed to call setsid: {err}");
        exit(1)
    }
}

fn remove_tmp_dirs(dirs: &[PathBuf], unshare_succeeded: bool) {
    if let Some(dir) = dirs.first() {
        if !is_mounted(dir).unwrap_or(false) {
            let pidfile_ext = if !unshare_succeeded { "pid" } else { "un.pid" };
            let pid_file = dir.with_extension(pidfile_ext);
            if pid_file.is_file() {
                let _ = remove_file(&pid_file);
            }
        }
    }
    for dir in dirs {
        let _ = remove_dir(dir);
    }
}

fn create_tmp_dirs(dirs: &[PathBuf]) -> Result<()> {
    if let Some(dir) = dirs.first() {
        create_dir_all(dir)?;
        for dir in dirs {
            if let Err(err) = set_permissions(dir, Permissions::from_mode(0o700)) {
                if let Some(os_error) = err.raw_os_error() {
                    if os_error != 30 {
                        return Err(err);
                    }
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
    get_dwfs_option(
        "DWARFS_CACHESIZE",
        &if let Ok(meminfo) = <procfs::Meminfo as procfs::Current>::current() {
            let available_memory = meminfo.mem_available.unwrap_or(meminfo.mem_free) as f64;
            let available_memory_mb = available_memory / 1024.0 / 1024.0 / 1.3;
            let cache_sizes_mb: [u32; 10] = [1536, 1024, 896, 768, 640, 512, 384, 256, 128, 64];
            let cache_size_mb = cache_sizes_mb
                .iter()
                .find(|threshold| available_memory_mb > (**threshold as f64))
                .copied()
                .unwrap_or(32);
            format!("{}M", cache_size_mb)
        } else {
            DWARFS_CACHESIZE.into()
        },
    )
}

#[cfg(feature = "dwarfs")]
fn get_dwfs_workers(cachesize: &str, cpus: usize) -> String {
    get_dwfs_option(
        "DWARFS_WORKERS",
        &match cachesize {
            "1536M" | "1024M" => cpus,
            "896M" => 2,
            _ => 1,
        }
        .to_string(),
    )
}

fn mount_image(embed: &Embed, image: &Image, mount_dir: PathBuf, uid: u32, gid: u32) {
    #[cfg(not(any(feature = "squashfs", feature = "dwarfs")))]
    let _ = (embed, uid, gid);
    if is_mounted(&mount_dir).unwrap_or(false) {
        return;
    }
    let mount_dir = mount_dir.to_str().unwrap_or_default().to_string();
    let image_path = image.helper_path().unwrap_or_else(|err| {
        eprintln!("Failed to get a stable image path: {err}");
        exit(1)
    });
    #[cfg(not(any(feature = "squashfs", feature = "dwarfs")))]
    let _ = (&mount_dir, &image_path);
    if image.is_dwar {
        #[cfg(feature = "dwarfs")]
        {
            let cpus = num_cpus::get();
            let cachesize = get_dwfs_cachesize();
            let workers = get_dwfs_workers(&cachesize, cpus);
            let mut exec_args = vec![
                image_path,
                mount_dir,
                "-f".into(),
                "-o".into(),
                format!("uid={uid},gid={gid}"),
                "-o".into(),
                format!(
                    "offset={},cachesize={cachesize},workers={workers}",
                    image.offset
                ),
                "-o".into(),
                "ro,nodev,tidy_strategy=time,seq_detector=1,cache_files".into(),
                "-o".into(),
                format!(
                    "blocksize={}",
                    get_dwfs_option("DWARFS_BLOCKSIZE", DWARFS_BLOCKSIZE)
                ),
                "-o".into(),
                format!(
                    "readahead={}",
                    get_dwfs_option("DWARFS_READAHEAD", DWARFS_READAHEAD)
                ),
            ];
            match cachesize.as_str() {
                "1536M" | "1024M" => {
                    exec_args.append(&mut vec![
                        "-o".into(),
                        "clone_fd,tidy_interval=2s,tidy_max_age=10s".into(),
                    ]);
                }
                _ => {
                    exec_args.append(&mut vec![
                        "-o".into(),
                        "tidy_interval=500ms,tidy_max_age=1s".into(),
                    ]);
                }
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
                exec_args.append(&mut vec![
                    "-o".into(),
                    format!("analysis_file={dwarfs_analysis_file}"),
                ]);
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
                image_path,
                mount_dir,
                "-f".into(),
                "-o".into(),
                "ro,nodev".into(),
                "-o".into(),
                format!("uid={uid},gid={gid}"),
                "-o".into(),
                format!("offset={}", image.offset),
            ];
            if get_env_var!("ENABLE_FUSE_DEBUG") == "1" {
                exec_args.append(&mut vec!["-o".into(), "debug".into()]);
            }
            embed.squashfuse(exec_args)
        }
    }
}

fn extract_image(
    embed: &Embed,
    image: &Image,
    mut extract_dir: PathBuf,
    is_extract_run: bool,
    pattern: Option<&String>,
) {
    #[cfg(not(any(feature = "squashfs", feature = "dwarfs")))]
    let _ = (embed, pattern);
    if is_extract_run {
        if let Ok(dir) = extract_dir.read_dir() {
            if dir.flatten().any(|entry| entry.path().exists()) {
                return;
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
    let extract_dir = extract_dir.to_str().unwrap_or_default().to_string();
    if let Err(err) = create_dir_all(&extract_dir) {
        eprintln!("Failed to create extract dir: {err}: {extract_dir}");
        exit(1)
    }
    #[cfg(feature = "appimage")]
    {
        if !is_extract_run {
            let _ = remove_file(&applink_dir);
            if let Err(err) = symlink(&extract_dir, &applink_dir) {
                eprintln!("Warning: failed to create squashfs-root symlink to extract dir: {err}");
            }
        }
    }
    let image_path = image.helper_path().unwrap_or_else(|err| {
        eprintln!("Failed to get a stable image path: {err}");
        exit(1)
    });
    #[cfg(not(any(feature = "squashfs", feature = "dwarfs")))]
    let _ = &image_path;
    if image.is_dwar {
        #[cfg(feature = "dwarfs")]
        {
            let cachesize = get_dwfs_cachesize();
            let mut exec_args = vec![
                "--input".into(),
                image_path,
                "--log-level=error".into(),
                format!("--cache-size={cachesize}"),
                format!("--image-offset={}", image.offset),
                format!(
                    "--num-workers={}",
                    get_dwfs_workers(&cachesize, num_cpus::get())
                ),
                "--output".into(),
                extract_dir,
                "--stdout-progress".into(),
            ];
            if let Some(pattern) = pattern {
                exec_args.append(&mut vec!["--pattern".into(), pattern.to_string()]);
            }
            embed.dwarfsextract(exec_args)
        }
    } else {
        #[cfg(feature = "squashfs")]
        {
            let mut exec_args = vec![
                "-f".into(),
                "-d".into(),
                extract_dir,
                "-o".into(),
                image.offset.to_string(),
                image_path,
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
    if delay == "inf" {
        return None;
    }
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
            return num
                .checked_mul(multiplier)
                .map(Duration::from_secs)
                .or(default_delay);
        }
    }
    if !num_part.is_empty() {
        num_part.parse().ok().map(Duration::from_secs)
    } else {
        default_delay
    }
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

fn signals_handler(pid: Pid, mount_point: &Path, killpid: bool, selfexit: bool) {
    let sig_list = [SIGINT, SIGTERM, SIGQUIT, SIGHUP, SIGUSR1, SIGUSR2];
    let mut signals = match Signals::new(sig_list) {
        Ok(sig) => sig,
        Err(err) => {
            eprintln!("Failed to register signal handlers: {err}");
            return;
        }
    };
    let _handle = signals.handle();
    for signal in signals.forever() {
        if sig_list.contains(&signal) {
            if killpid {
                if let Ok(signal_enum) = Signal::try_from(signal) {
                    let _ = kill(pid, signal_enum);
                }
            } else {
                try_unmount(Some(pid), mount_point);
                unsafe {
                    for &sig in sig_list.iter() {
                        libc::signal(sig, libc::SIG_DFL);
                    }
                }
            }
            if selfexit {
                exit(0)
            };
            if !killpid {
                break;
            }
        }
    }
}

fn hash_string(data: &str) -> String {
    let mut hasher = DefaultHasher::new();
    data.hash(&mut hasher);
    hasher.finish().to_string()
}

fn fast_hash_file(file: &File, file_len: u64, offset: u64) -> Result<u32> {
    let image_size = file_len.saturating_sub(offset);
    let mut buffer = [0u8; 48];
    let first = buffer
        .get_mut(0..16)
        .ok_or_else(|| Error::new(InvalidData, "hash buffer has no first sample"))?;
    file.read_exact_at(first, offset)?;
    let middle_offset = offset
        .checked_add(image_size / 2)
        .ok_or_else(|| Error::new(InvalidData, "middle image sample offset overflows"))?;
    let middle = buffer
        .get_mut(16..32)
        .ok_or_else(|| Error::new(InvalidData, "hash buffer has no middle sample"))?;
    file.read_exact_at(middle, middle_offset)?;
    let last = buffer
        .get_mut(32..48)
        .ok_or_else(|| Error::new(InvalidData, "hash buffer has no final sample"))?;
    file.read_exact_at(last, file_len.saturating_sub(16))?;
    Ok(xxh3_64(&buffer) as u32)
}

fn print_usage(
    portable_home: &PathBuf,
    portable_share: &PathBuf,
    portable_config: &PathBuf,
    portable_cache: &PathBuf,
    self_exe_dotenv: &PathBuf,
) {
    println!("{} v{URUNTIME_VERSION}
   Repository: {}

   Runtime options:
    Every --{ARG_PFX}-* option below also accepts the universal --uruntime-* prefix.

    --{ARG_PFX}-extract [PATTERN]          Extract content from embedded filesystem image
                                             If pattern is passed, only extract matching files
     --{ARG_PFX}-extract-and-run [ARGS]    Run the {SELF_NAME} after extraction without using FUSE
     --{ARG_PFX}-offset                    Print byte offset to start of embedded filesystem image
     --{ARG_PFX}-portable-home             Create a portable home folder to use as $HOME
     --{ARG_PFX}-portable-share            Create a portable share folder to use as $XDG_DATA_HOME
     --{ARG_PFX}-portable-config           Create a portable config folder to use as $XDG_CONFIG_HOME
     --{ARG_PFX}-portable-cache            Create a portable cache folder to use as $XDG_CACHE_HOME
     --{ARG_PFX}-help                      Print this help
     --{ARG_PFX}-unshare                   Try to use unshare user and mount namespaces
     --{ARG_PFX}-unshare-root              Use unshare and map the current user to UID/GID 0
     --{ARG_PFX}-unshare-uid UID           Use unshare and map the current UID to UID
     --{ARG_PFX}-unshare-gid GID           Use unshare and map the current GID to GID
     --{ARG_PFX}-unshare-drop-caps         Use unshare and drop capabilities before the application
     --{ARG_PFX}-unshare-fallback-drop-caps
                                             Drop capabilities only when unshare is selected as fallback
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
    println!(
        "
      Also you can create a hardlink, symlink or rename the runtime with
      the name of the built-in utility to use it directly."
    );

    println!(
        "\n    Portable home and config:

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
      directory rather than in your home directory",
        portable_home, portable_share, portable_config, portable_cache
    );

    println!("\n    Environment variables:

      URUNTIME                       Path to uruntime
      URUNTIME_DIR                   Path to uruntime directory
      {ENV_NAME}_UNSHARE=1             Try to use unshare user and mount namespaces
      {ENV_NAME}_UNSHARE=2             Use unshare and drop capabilities before the application
      {ENV_NAME}_UNSHARE=3             Drop capabilities only when unshare is selected as fallback
      {ENV_NAME}_UNSHARE_ROOT=1        Map to root (UID 0, GID 0) in user namespace
      {ENV_NAME}_UNSHARE_UID=0         Map to specified UID in user namespace
      {ENV_NAME}_UNSHARE_GID=0         Map to specified GID in user namespace

      {ENV_NAME}_EXTRACT_AND_RUN=1     Run the {SELF_NAME} after extraction without using FUSE
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

    let mut args = env::args();
    let arg0 = args.next().unwrap_or_default();
    let mut exec_args: Vec<String> = args.collect();
    let arg0_name = basename(&arg0);

    match arg0_name {
        #[cfg(feature = "squashfs")]
        "squashfuse" => {
            embed.squashfuse(exec_args);
            return;
        }
        #[cfg(feature = "squashfs")]
        "unsquashfs" => {
            embed.unsquashfs(exec_args);
            return;
        }
        #[cfg(feature = "squashfs")]
        "sqfscat" => {
            embed.sqfscat(exec_args);
            return;
        }
        #[cfg(all(not(feature = "lite"), feature = "squashfs"))]
        "mksquashfs" => {
            embed.mksquashfs(exec_args);
            return;
        }
        #[cfg(all(not(feature = "lite"), feature = "squashfs"))]
        "sqfstar" => {
            embed.sqfstar(exec_args);
            return;
        }
        #[cfg(feature = "dwarfs")]
        "dwarfs" => {
            embed.dwarfs(exec_args);
            return;
        }
        #[cfg(all(not(feature = "lite"), feature = "dwarfs"))]
        "dwarfsck" => {
            embed.dwarfsck(exec_args);
            return;
        }
        #[cfg(all(not(feature = "lite"), feature = "dwarfs"))]
        "mkdwarfs" => {
            embed.mkdwarfs(exec_args);
            return;
        }
        #[cfg(feature = "dwarfs")]
        "dwarfsextract" => {
            embed.dwarfsextract(exec_args);
            return;
        }
        "fusermount" | "fusermount3" => {
            let mut umount = false;
            let mut mount_point = String::new();
            for arg in &exec_args {
                if arg == "-u" || arg == "--unmount" {
                    umount = true
                } else if !arg.starts_with('-') {
                    mount_point = arg.clone();
                    break;
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
                if !try_unmount(None, Path::new(&mount_point)) {
                    exit(1)
                }
                return;
            }
            let err = Command::new(arg0_name).args(&exec_args).exec();
            eprintln!("Failed to execute {arg0_name}: {err}");
            exit(1)
        }
        _ => {}
    }

    let unshare_cli = parse_unshare_cli_options(&mut exec_args, ARG_PFX).unwrap_or_else(|error| {
        eprintln!("Invalid unshare option: {error}");
        exit(2)
    });
    let arg1 = exec_args.first().map(String::as_str).unwrap_or_default();

    if !arg1.is_empty() {
        match arg1 {
            arg if is_runtime_option(arg, "version") => {
                println!("v{URUNTIME_VERSION}");
                return;
            }
            #[cfg(feature = "squashfs")]
            arg if is_runtime_option(arg, "squashfuse") => {
                embed.squashfuse(exec_args.get(1..).map_or_else(Vec::new, <[String]>::to_vec));
                return;
            }
            #[cfg(feature = "squashfs")]
            arg if is_runtime_option(arg, "unsquashfs") => {
                embed.unsquashfs(exec_args.get(1..).map_or_else(Vec::new, <[String]>::to_vec));
                return;
            }
            #[cfg(feature = "squashfs")]
            arg if is_runtime_option(arg, "sqfscat") => {
                embed.sqfscat(exec_args.get(1..).map_or_else(Vec::new, <[String]>::to_vec));
                return;
            }
            #[cfg(all(not(feature = "lite"), feature = "squashfs"))]
            arg if is_runtime_option(arg, "mksquashfs") => {
                embed.mksquashfs(exec_args.get(1..).map_or_else(Vec::new, <[String]>::to_vec));
                return;
            }
            #[cfg(all(not(feature = "lite"), feature = "squashfs"))]
            arg if is_runtime_option(arg, "sqfstar") => {
                embed.sqfstar(exec_args.get(1..).map_or_else(Vec::new, <[String]>::to_vec));
                return;
            }
            #[cfg(feature = "dwarfs")]
            arg if is_runtime_option(arg, "dwarfs") => {
                embed.dwarfs(exec_args.get(1..).map_or_else(Vec::new, <[String]>::to_vec));
                return;
            }
            #[cfg(all(not(feature = "lite"), feature = "dwarfs"))]
            arg if is_runtime_option(arg, "dwarfsck") => {
                embed.dwarfsck(exec_args.get(1..).map_or_else(Vec::new, <[String]>::to_vec));
                return;
            }
            #[cfg(all(not(feature = "lite"), feature = "dwarfs"))]
            arg if is_runtime_option(arg, "mkdwarfs") => {
                embed.mkdwarfs(exec_args.get(1..).map_or_else(Vec::new, <[String]>::to_vec));
                return;
            }
            #[cfg(feature = "dwarfs")]
            arg if is_runtime_option(arg, "dwarfsextract") => {
                embed.dwarfsextract(exec_args.get(1..).map_or_else(Vec::new, <[String]>::to_vec));
                return;
            }
            _ => {}
        }
    }

    let uruntime_source = SelfExecutable::open_self(&arg0).unwrap_or_else(|err| {
        eprintln!("Failed to open self runtime executable: {err}");
        exit(1)
    });
    let uruntime = &uruntime_source.location;
    let target_image_value = get_env_var!("TARGET_{}", ENV_NAME);
    let target_source = open_optional_target_source(&target_image_value).unwrap_or_else(|err| {
        eprintln!("Failed to open target runtime executable: {err}");
        exit(1)
    });
    let executable = target_source.as_ref().unwrap_or(&uruntime_source);
    let self_exe = &executable.location;

    let runtime = get_runtime(executable).unwrap_or_else(|err| {
        eprintln!("Failed to get runtime: {err}");
        exit(1)
    });
    let runtime_size = runtime.size;
    let executable_size = executable.size;

    let uruntime_dir = uruntime.parent().unwrap_or_else(|| {
        eprintln!("Failed to get self runtime parent dir!");
        exit(1)
    });
    let self_exe_dir = self_exe.parent().unwrap_or_else(|| {
        eprintln!("Failed to get runtime parent dir!");
        exit(1)
    });
    let self_exe_name = self_exe
        .file_name()
        .unwrap_or_else(|| {
            eprintln!("Failed to get runtime name!");
            exit(1)
        })
        .to_str()
        .unwrap_or_default();

    let portable_home = &self_exe_dir.join(format!("{self_exe_name}.home"));
    let portable_share = &self_exe_dir.join(format!("{self_exe_name}.share"));
    let portable_config = &self_exe_dir.join(format!("{self_exe_name}.config"));
    let portable_cache = &self_exe_dir.join(format!("{self_exe_name}.cache"));

    env::set_var("URUNTIME", uruntime);
    env::set_var("URUNTIME_DIR", uruntime_dir);

    let self_exe_dotenv = &self_exe_dir.join(format!("{self_exe_name}.env"));
    try_read_dotenv(self_exe_dotenv, &runtime.envs);

    let mut is_mount_only = false;
    let mut is_extract_run = false;
    let mut is_noclenup = URUNTIME_CLEANUP.strip_prefix("URUNTIME_CLEANUP") != Some("=1");
    let unshare_mode = URUNTIME_UNSHARE
        .strip_prefix("URUNTIME_UNSHARE")
        .unwrap_or_default();
    let (mut is_unshare, mut drop_caps, mut drop_caps_on_fallback) =
        embedded_unshare_policy(unshare_mode);
    is_unshare |= unshare_cli.enable;
    drop_caps |= unshare_cli.drop_caps;
    drop_caps_on_fallback |= unshare_cli.drop_caps_on_fallback;
    if get_env_var!("{}_EXTRACT_AND_RUN", ENV_NAME) == "1" {
        is_extract_run = true
    }

    let arg1 = exec_args.first().map(String::as_str).unwrap_or_default();
    let extract_and_run = is_runtime_option(arg1, "extract-and-run");
    let explicit_unshare = is_runtime_option(arg1, "unshare");
    if !arg1.is_empty() {
        match arg1 {
            arg if is_runtime_option(arg, "help") => {
                print_usage(
                    portable_home,
                    portable_share,
                    portable_config,
                    portable_cache,
                    self_exe_dotenv,
                );
                return;
            }
            arg if is_runtime_option(arg, "portable-home") => {
                if let Err(err) = create_dir(portable_home) {
                    eprintln!(
                        "Failed to create portable home directory: {:?}: {err}",
                        portable_home
                    )
                }
                println!("Portable home directory created: {:?}", portable_home);
                return;
            }
            arg if is_runtime_option(arg, "portable-share") => {
                if let Err(err) = create_dir(portable_share) {
                    eprintln!(
                        "Failed to create portable share directory: {:?}: {err}",
                        portable_share
                    )
                }
                println!("Portable share directory created: {:?}", portable_share);
                return;
            }
            arg if is_runtime_option(arg, "portable-config") => {
                if let Err(err) = create_dir(portable_config) {
                    eprintln!(
                        "Failed to create portable config directory: {:?}: {err}",
                        portable_config
                    )
                }
                println!("Portable config directory created: {:?}", portable_config);
                return;
            }
            arg if is_runtime_option(arg, "portable-cache") => {
                if let Err(err) = create_dir(portable_cache) {
                    eprintln!(
                        "Failed to create portable cache directory: {:?}: {err}",
                        portable_cache
                    )
                }
                println!("Portable cache directory created: {:?}", portable_cache);
                return;
            }
            arg if is_runtime_option(arg, "offset") => {
                println!("{runtime_size}");
                return;
            }
            arg if is_runtime_option(arg, "updateinfo")
                || is_runtime_option(arg, "updateinformation") =>
            {
                let updateinfo = get_section_data(&runtime.headers_bytes, ".upd_info")
                    .unwrap_or_else(|err| {
                        eprintln!("Failed to get update info: {err}");
                        exit(1)
                    });
                println!("{updateinfo}");
                return;
            }
            arg if is_runtime_option(arg, "addupdinfo") => {
                if let Err(err) = add_section_data(&runtime, ".upd_info", &exec_args) {
                    eprintln!("Failed to add update info: {err}");
                    exit(1)
                };
                return;
            }
            arg if is_runtime_option(arg, "signature") => {
                let signature = get_section_data(&runtime.headers_bytes, ".sha256_sig")
                    .unwrap_or_else(|err| {
                        eprintln!("Failed to get signature info: {err}");
                        exit(1)
                    });
                println!("{signature}");
                return;
            }
            arg if is_runtime_option(arg, "addsign") => {
                if let Err(err) = add_section_data(&runtime, ".sha256_sig", &exec_args) {
                    eprintln!("Failed to add signature info: {err}");
                    exit(1)
                };
                return;
            }
            arg if is_runtime_option(arg, "envs") => {
                println!("{}", runtime.envs);
                return;
            }
            arg if is_runtime_option(arg, "addenvs") => {
                if let Err(err) = add_section_data(&runtime, ".envs", &exec_args) {
                    eprintln!("Failed to add envs: {err}");
                    exit(1)
                };
                return;
            }
            _ => {}
        }
    }
    if extract_and_run {
        exec_args.remove(0);
        is_extract_run = true;
    } else if explicit_unshare {
        exec_args.remove(0);
        is_unshare = true;
    }

    let image = get_image(executable, runtime_size).unwrap_or_else(|err|{
        eprintln!("Failed to get image: {err}");
        eprintln!("The embedded filesystem image may be corrupted, truncated by 'strip', or not yet included in this executable");
        exit(1)
    });

    let arg1 = exec_args.first().map(String::as_str).unwrap_or_default();
    if !arg1.is_empty() {
        match arg1 {
            arg if is_runtime_option(arg, "extract") => {
                extract_image(&embed, &image, PathBuf::from("."), false, exec_args.get(1));
                return;
            }
            arg if is_runtime_option(arg, "mount") => is_mount_only = true,
            _ => {}
        }
    }

    let uruntime_extract = match URUNTIME_EXTRACT
        .strip_prefix("URUNTIME_EXTRACT")
        .unwrap_or_default()
    {
        "=1" => {
            is_extract_run = true;
            1
        }
        "=2" => 2,
        "=3" => 3,
        _ => 0,
    };

    let mut reuse_check_delay = get_env_var!("REUSE_CHECK_DELAY");

    let (mut is_remp_mount, default_delay) = match URUNTIME_MOUNT
        .strip_prefix("URUNTIME_MOUNT")
        .unwrap_or_default()
    {
        "=0" => (
            true,
            if is_extract_run {
                Some(REUSE_CHECK_DELAY)
            } else {
                Some("inf")
            },
        ),
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
    let target_dir_is_empty = target_dir.is_empty();

    let uid: u32 = unsafe { libc::getuid() };
    let gid = unsafe { libc::getgid() };

    let env_unshare = get_env_var!("{}_UNSHARE", ENV_NAME);
    let (env_enables_unshare, env_drops_caps, env_drops_caps_on_fallback) =
        environment_drop_caps_policy(&env_unshare);
    is_unshare |= env_enables_unshare;
    drop_caps |= env_drops_caps;
    drop_caps_on_fallback |= env_drops_caps_on_fallback;

    let env_unshare_root = get_env_var!("{}_UNSHARE_ROOT", ENV_NAME) == "1";
    let (unshare_uid, unshare_gid) = if unshare_cli.root || env_unshare_root {
        ("0".into(), "0".into())
    } else {
        (
            unshare_cli
                .uid
                .unwrap_or_else(|| get_env_var!("{}_UNSHARE_UID", ENV_NAME)),
            unshare_cli
                .gid
                .unwrap_or_else(|| get_env_var!("{}_UNSHARE_GID", ENV_NAME)),
        )
    };
    let explicit_mapping = unshare_cli.root
        || env_unshare_root
        || requested_id_mapping(uid, gid, &unshare_uid, &unshare_gid);
    let requested_mapping = match parse_requested_mapping(uid, gid, &unshare_uid, &unshare_gid) {
        Ok(mapping) => mapping,
        Err(err) => {
            eprintln!("Failed to parse requested UID/GID mapping: {err}");
            exit(1)
        }
    };
    if explicit_mapping || env_enables_unshare {
        is_unshare = true
    }
    if is_unshare && drop_caps_on_fallback {
        drop_caps = true;
    }

    let procfs_available = process_procfs_available_at(Path::new("/proc"));
    let namespace_identity_available = NamespaceFiles::open("self")
        .and_then(|files| files.identities())
        .is_ok();
    let direct_mount_available = can_mount_directly(
        uid,
        false,
        false,
        procfs_available,
        has_effective_capability(CAP_SYS_ADMIN),
        is_mount_only,
    );
    if proc_free_private_mount_requires_random_target(
        is_remp_mount,
        is_extract_run,
        procfs_available,
        is_unshare,
        direct_mount_available,
    ) {
        is_remp_mount = false;
        reuse_check_delay = "0".into();
    }

    let (mut tmp_dir, mut tmp_dirs) = if target_dir_is_empty {
        let base_tmp_dir = env::temp_dir();
        let mut self_hash = "".to_string();
        let first5name: String = self_exe_name
            .split(".")
            .next()
            .unwrap_or(self_exe_name)
            .chars()
            .filter(|c| c.is_ascii_alphanumeric())
            .take(5)
            .collect();
        if is_extract_run || is_remp_mount {
            let image_hash = fast_hash_file(&image.file, executable_size, image.offset)
                .unwrap_or_else(|err| {
                    eprintln!("Failed to get image hash: {err}");
                    exit(1)
                });
            let base_hash = base_hash(xxh3_64(&runtime.headers_bytes), image_hash, uid);
            self_hash = hash_string(&reuse_hash_material(
                u64::from(base_hash),
                requested_mapping,
                explicit_mapping,
            ))
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
                let tmp_dir = base_tmp_dir.join(tmp_dir_name);
                (tmp_dir.clone(), vec![tmp_dir])
            } else {
                let ruid_dir = base_tmp_dir.join(format!(".r{uid}"));
                let mnt_dir = ruid_dir.join("mnt");
                let tmp_dir_name: String = if is_extract_run && !is_mount_only {
                    format!("{first5name}extr{self_hash}")
                } else if is_remp_mount {
                    format!("{first5name}remp{self_hash}")
                } else {
                    format!("{first5name}{}", random_string(6))
                };
                let tmp_dir = mnt_dir.join(tmp_dir_name);
                (tmp_dir.clone(), vec![tmp_dir, mnt_dir, ruid_dir])
            }
        }
    } else {
        env::remove_var(format!("{ENV_NAME}_TARGET_DIR"));
        let tmp_dir = PathBuf::from(&target_dir);
        (tmp_dir.clone(), vec![tmp_dir])
    };
    drop(runtime);

    let mut namespace_outcome = None;

    let mut is_tmpdir_exists = false;
    let mut is_unshare_remp = false;
    let mut child_pid = Pid::from_raw(0);
    let persistent_reuse = is_remp_mount && !is_extract_run;
    let lifetime_lease_enabled = is_extract_run || persistent_reuse;
    let (mut target_coordinator, mut lifetime_lease) = if lifetime_lease_enabled {
        match prepare_target_lock_parent(&tmp_dir)
            .and_then(|()| acquire_target_usage_lease(&tmp_dir))
        {
            Ok((coordinator, lease)) => (Some(coordinator), Some(lease)),
            Err(err) => {
                eprintln!(
                    "Failed to acquire lifetime lease for {}: {err}",
                    tmp_dir.display()
                );
                exit(1)
            }
        }
    } else {
        (None, None)
    };
    let mut unshare_record_present = path_entry_present(&tmp_dir.with_extension("un.pid"));
    let mut target_nonempty = None;
    let mut unshare_reuse_rejected = false;
    if unshare_record_present {
        match try_reuse_unshare_mount_point(
            &tmp_dir,
            requested_mapping,
            explicit_mapping,
            lifetime_lease.as_ref(),
        ) {
            TryReuseResult::Reused(record) => {
                if let Some(outcome) = record.namespace_kind.and_then(NamespaceOutcome::unshared) {
                    is_tmpdir_exists = true;
                    namespace_outcome = Some(outcome);
                    is_unshare_remp = true;
                    child_pid = record.pid
                }
            }
            TryReuseResult::StaleRemoved => {
                let mounted = is_mounted(&tmp_dir).unwrap_or(true);
                let occupied = if mounted {
                    true
                } else {
                    let nonempty = inspect_target_nonempty(&tmp_dir).unwrap_or_else(|err| {
                        eprintln!("{err}; refusing reuse");
                        exit(1)
                    });
                    target_nonempty = Some(nonempty);
                    nonempty
                };
                match stale_removed_action(!target_dir_is_empty, occupied) {
                    ReuseUnavailableAction::Continue => unshare_record_present = false,
                    ReuseUnavailableAction::Fresh => {
                        if let Err(err) = transition_to_fresh_mount_target(
                            &mut tmp_dir,
                            &mut tmp_dirs,
                            &mut target_coordinator,
                            &mut lifetime_lease,
                            lifetime_lease_enabled,
                        ) {
                            eprintln!("Failed to prepare a fresh mount target: {err}");
                            exit(1)
                        }
                        unshare_record_present = false;
                        target_nonempty = Some(false);
                    }
                    ReuseUnavailableAction::Reject => unshare_reuse_rejected = true,
                }
            }
            TryReuseResult::Unavailable => match reuse_unavailable_action(!target_dir_is_empty) {
                ReuseUnavailableAction::Fresh => {
                    if let Err(err) = transition_to_fresh_mount_target(
                        &mut tmp_dir,
                        &mut tmp_dirs,
                        &mut target_coordinator,
                        &mut lifetime_lease,
                        lifetime_lease_enabled,
                    ) {
                        eprintln!("Failed to prepare a fresh mount target: {err}");
                        exit(1)
                    }
                    unshare_record_present = false;
                    target_nonempty = Some(false);
                }
                ReuseUnavailableAction::Reject | ReuseUnavailableAction::Continue => {
                    unshare_reuse_rejected = true
                }
            },
            TryReuseResult::Rejected => unshare_reuse_rejected = true,
            TryReuseResult::IrreversibleFailure => exit(1),
        }
    }

    unshare_reuse_rejected |=
        unshare_reuse_was_rejected(unshare_record_present, is_unshare_remp, true);
    let mut direct_reuse_record = None;
    if !is_unshare_remp {
        let mounted_in_current_namespace = is_mounted(&tmp_dir).unwrap_or(false);
        let direct_record_present = path_entry_present(&tmp_dir.with_extension("pid"));
        if should_validate_direct_reuse_record(
            persistent_reuse,
            explicit_mapping,
            unshare_reuse_rejected,
            mounted_in_current_namespace,
            direct_record_present,
        ) && direct_reuse_record.is_none()
        {
            direct_reuse_record = read_validated_mount_pid_file(
                &tmp_dir,
                "pid",
                requested_mapping,
                explicit_mapping,
                lifetime_lease.as_ref(),
            );
        }
        let visible_direct_reuse = visible_direct_reuse_allowed(
            persistent_reuse,
            target_dir_is_empty,
            explicit_mapping,
            namespace_identity_available,
            unshare_record_present,
            direct_record_present,
            mounted_in_current_namespace,
        );
        let target_nonempty = if mounted_in_current_namespace {
            false
        } else {
            target_nonempty.unwrap_or_else(|| {
                inspect_target_nonempty(&tmp_dir).unwrap_or_else(|err| {
                    eprintln!("{err}; refusing reuse");
                    exit(1)
                })
            })
        };
        let existing_target_action = existing_target_action(
            persistent_reuse,
            explicit_mapping,
            unshare_reuse_rejected,
            mounted_in_current_namespace,
            target_nonempty,
            direct_reuse_record.is_some() || visible_direct_reuse,
        );
        if existing_target_action == ExistingTargetAction::Reject {
            eprintln!(
                "Existing mount at {} does not have a valid mapping and process generation record; refusing unsafe reuse",
                tmp_dir.display()
            );
            exit(1)
        }
        is_tmpdir_exists = existing_target_action == ExistingTargetAction::Reuse;
        if is_tmpdir_exists {
            if let Some(record) = direct_reuse_record {
                namespace_outcome = match record.namespace_kind {
                    Some(NamespaceKind::Current) => Some(NamespaceOutcome::current(false)),
                    Some(kind) => NamespaceOutcome::unshared(kind),
                    None => None,
                };
            } else if mounted_in_current_namespace {
                namespace_outcome = Some(NamespaceOutcome::current(false));
            }
        }
        if mounted_in_current_namespace
            && !procfs_available
            && has_effective_capability(CAP_SYS_ADMIN)
            && !is_unshare
        {
            namespace_outcome = Some(NamespaceOutcome::current(true));
        }
    }
    if fallback_should_drop_capabilities(
        namespace_outcome.is_some_and(|outcome| {
            (outcome.kind.is_unshared() || outcome.direct_mount_fallback) && !is_unshare
        }),
        drop_caps_on_fallback,
    ) {
        drop_caps = true;
    }

    if persistent_reuse && !is_unshare_remp {
        child_pid = direct_reuse_record
            .map(|record| record.pid)
            .unwrap_or(Pid::from_raw(0))
    }

    if !is_tmpdir_exists {
        if !is_unshare_remp && is_unshare {
            match try_unshare(uid, gid, requested_mapping, explicit_mapping) {
                TryUnshareResult::Created(outcome) => namespace_outcome = Some(outcome),
                TryUnshareResult::Unavailable if explicit_mapping => {
                    eprintln!(
                        "Failed to apply the requested UID/GID mapping; refusing to continue without the requested isolation"
                    );
                    exit(1)
                }
                TryUnshareResult::Unavailable => {}
                TryUnshareResult::IrreversibleFailure => exit(1),
            }
        }

        if !is_extract_run || is_mount_only {
            let unshare_was_requested = is_unshare;
            let fuse_available = check_fuse(
                uruntime,
                uid,
                gid,
                requested_mapping,
                explicit_mapping,
                FuseState {
                    namespace_outcome: &mut namespace_outcome,
                    is_unshare: &mut is_unshare,
                },
                is_mount_only,
            );
            if fallback_should_drop_capabilities(
                namespace_outcome.is_some_and(|outcome| {
                    (outcome.kind.is_unshared() || outcome.direct_mount_fallback)
                        && !unshare_was_requested
                }),
                drop_caps_on_fallback,
            ) {
                drop_caps = true;
            }
            if !fuse_available {
                check_extract!(
                    is_mount_only,
                    uruntime_extract,
                    self_exe,
                    executable_size,
                    {
                        eprintln!("Trying to extract and run...");
                        env::set_var(format!("{ENV_NAME}_EXTRACT_AND_RUN"), "1");
                        if !target_dir_is_empty {
                            env::set_var(format!("{ENV_NAME}_TARGET_DIR"), &target_dir);
                        }
                        let err = match exec_self_fd(executable, &exec_args) {
                            Err(err) => err,
                            Ok(()) => Error::other(
                                "exec unexpectedly returned success without replacing the process",
                            ),
                        };
                        eprintln!(
                            "Failed to execute {:?} through its open fd: {err}",
                            self_exe
                        );
                        exit(1)
                    }
                );
            }
        }
        drop(unshare_uid);
        drop(unshare_gid);
        let unshare_succeeded = namespace_outcome.is_some_and(|outcome| outcome.kind.is_unshared());
        if is_mount_only {
            is_extract_run = false
        } else if is_extract_run {
            is_noclenup = get_env_var!("NO_CLEANUP") == "1"
        }

        if !is_extract_run && get_env_var!("NO_UNMOUNT") == "1" {
            is_remp_mount = true;
            reuse_check_delay = "inf".into()
        }

        child_pid = match unsafe { fork() } {
            Ok(ForkResult::Parent { child }) => child,
            Ok(ForkResult::Child) => {
                try_setsid();
                if unshare_succeeded {
                    restore_capabilities()
                }
                if let Err(err) = create_tmp_dirs(&tmp_dirs) {
                    eprintln!("Failed to create tmp dir: {err}");
                    exit(1)
                }
                unsafe { libc::dup2(libc::STDERR_FILENO, libc::STDOUT_FILENO) };
                if is_extract_run {
                    extract_image(&embed, &image, tmp_dir, is_extract_run, None)
                } else {
                    mount_image(&embed, &image, tmp_dir, uid, gid)
                }
                exit(0)
            }
            Err(err) => {
                eprintln!("Fork error: {err}");
                exit(1)
            }
        };

        if is_extract_run {
            if let Err(err) = waitpid(child_pid, None) {
                eprintln!("Failed to extract image: {err}");
                remove_tmp_dirs(&tmp_dirs, unshare_succeeded);
                exit(1)
            }
        } else if !wait_mount(child_pid, &tmp_dir, Duration::from_secs(1)) {
            remove_tmp_dirs(&tmp_dirs, unshare_succeeded);
            if !unshare_succeeded && !is_unshare {
                eprintln!("Trying to unshare...");
                env::set_var(
                    format!("{ENV_NAME}_UNSHARE"),
                    if drop_caps_on_fallback { "2" } else { "1" },
                );
            } else {
                check_extract!(
                    is_mount_only,
                    uruntime_extract,
                    self_exe,
                    executable_size,
                    {
                        eprintln!("Trying to extract and run...");
                        if is_unshare && !unshare_succeeded {
                            env::remove_var(format!("{ENV_NAME}_UNSHARE"));
                            env::remove_var(format!("{ENV_NAME}_UNSHARE_ROOT"));
                            env::remove_var(format!("{ENV_NAME}_UNSHARE_UID"));
                            env::remove_var(format!("{ENV_NAME}_UNSHARE_GID"));
                        }
                        env::set_var(format!("{ENV_NAME}_EXTRACT_AND_RUN"), "1");
                    }
                );
            }
            if !target_dir_is_empty {
                env::set_var(format!("{ENV_NAME}_TARGET_DIR"), &target_dir);
            }
            let err = match exec_self_fd(executable, &exec_args) {
                Err(err) => err,
                Ok(()) => {
                    Error::other("exec unexpectedly returned success without replacing the process")
                }
            };
            eprintln!(
                "Failed to execute {:?} through its open fd: {err}",
                self_exe
            );
            exit(1)
        }
        if should_write_mount_pid_record(
            persistent_reuse,
            namespace_outcome.map(|outcome| outcome.kind),
            namespace_identity_available,
            target_dir_is_empty,
            explicit_mapping,
        ) {
            if let Some(outcome) = namespace_outcome {
                if let Err(err) = write_mount_pid_file(
                    &tmp_dir,
                    child_pid,
                    outcome,
                    requested_mapping,
                    lifetime_lease.as_ref(),
                ) {
                    eprintln!("Warning: failed to write PID file: {err}");
                }
            } else {
                eprintln!(
                    "Failed to identify the namespace used by the mount; refusing to write an untrusted PID record"
                );
                remove_tmp_dirs(&tmp_dirs, false);
                exit(1)
            }
        }
    }

    drop(target_coordinator.take());

    let unshare_succeeded = namespace_outcome.is_some_and(|outcome| outcome.kind.is_unshared());
    let direct_mount_fallback =
        namespace_outcome.is_some_and(|outcome| outcome.direct_mount_fallback);

    if is_mount_only {
        if unshare_succeeded && (!is_tmpdir_exists || is_unshare_remp) {
            if mount_only_requires_procfs_notice(
                true,
                process_procfs_available_at(Path::new("/proc")),
            ) {
                eprintln!(
                    "Warning: this private mount is accessible only through the /proc/<pid>/root path printed below; the consuming namespace must provide procfs"
                );
            }
            println!("/proc/{child_pid}/root{}", tmp_dir.display())
        } else {
            println!("{}", tmp_dir.display())
        }
    }

    let mut exit_code = 0;
    let mut lifetime_pipe = None;
    let mut lifetime_read_fd = None;
    let mut application_state = ApplicationState::NotLaunched;
    let mut application_supervisor = false;
    let mut child_subreaper_enabled = false;
    let mut application_tree_observable = true;
    let mut supervisor_status_writer: Option<OwnedFd> = None;
    if !is_mount_only {
        cfg_if! {
            if #[cfg(feature = "appimage")] {
                let run = tmp_dir.join("AppRun");
                if !run.is_file() {
                    eprintln!("AppRun not found: {:?}", run);
                    remove_tmp_dirs(&tmp_dirs, unshare_succeeded);
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
                    remove_tmp_dirs(&tmp_dirs, unshare_succeeded);
                    exit(1)
                }
                exec_args.insert(0, format!("{}/Run.sh", tmp_dir.display()));
                env::set_var("ARG0", arg0);
                env::set_var("RUNDIR", &tmp_dir);
                env::set_var("RUNIMAGE", self_exe);
                env::set_var("RUNOFFSET", format!("{runtime_size}"));
            }
        }
        env::set_var("OWD", getcwd().unwrap_or_default());

        try_set_portable_dir(portable_share, "XDG_DATA_HOME", Some(".local/share"));
        try_set_portable_dir(portable_config, "XDG_CONFIG_HOME", Some(".config"));
        try_set_portable_dir(portable_cache, "XDG_CACHE_HOME", Some(".cache"));
        try_set_portable_dir(portable_home, "HOME", None);

        let process_procfs_available = process_procfs_available_at(Path::new("/proc"));
        if application_supervisor_required(is_extract_run) {
            match create_lifetime_pipe() {
                Ok((status_reader, status_writer)) => match unsafe { fork() } {
                    Ok(ForkResult::Parent { child: _ }) => {
                        drop(status_writer);
                        drop(lifetime_lease.take());
                        let application_pid = match read_supervisor_value(status_reader.as_raw_fd())
                        {
                            Ok(Some(pid)) if pid > 0 => Some(Pid::from_raw(pid)),
                            Ok(Some(_)) => None,
                            Ok(None) => {
                                eprintln!("Application supervisor exited without a PID");
                                exit(1)
                            }
                            Err(err) => {
                                eprintln!("Failed to read application supervisor PID: {err}");
                                exit(1)
                            }
                        };
                        if let Some(application_pid) = application_pid {
                            let tmp_dir_clone = tmp_dir.clone();
                            spawn(move || {
                                signals_handler(application_pid, &tmp_dir_clone, true, false)
                            });
                        }
                        match read_supervisor_value(status_reader.as_raw_fd()) {
                            Ok(Some(code)) => exit(code),
                            Ok(None) => {
                                eprintln!("Application supervisor exited without a status");
                                exit(1)
                            }
                            Err(err) => {
                                eprintln!("Failed to read application supervisor status: {err}");
                                exit(1)
                            }
                        }
                    }
                    Ok(ForkResult::Child) => {
                        drop(status_reader);
                        application_supervisor = true;
                        supervisor_status_writer = Some(status_writer);
                        child_subreaper_enabled = match enable_child_subreaper() {
                            Ok(enabled) => enabled,
                            Err(err) => {
                                eprintln!(
                                    "Warning: failed to enable child-subreaper supervision: {err}"
                                );
                                false
                            }
                        };
                        application_tree_observable = cleanup_observation_complete(
                            process_procfs_available,
                            child_subreaper_enabled,
                        );
                        if !application_tree_observable {
                            eprintln!(
                                "Warning: child-subreaper supervision is unavailable; extracted-target cleanup will retain the target after a successful launch because procfs cannot prove the lifetime of descendants that close inherited descriptors and exec external programs"
                            );
                        }
                    }
                    Err(err) => {
                        drop(status_reader);
                        drop(status_writer);
                        application_tree_observable = false;
                        eprintln!(
                            "Warning: failed to create application supervisor: {err}; extracted-target cleanup will retain the target after a successful launch"
                        );
                    }
                },
                Err(err) => {
                    application_tree_observable = false;
                    eprintln!(
                    "Warning: failed to create application supervisor channel: {err}; extracted-target cleanup will retain the target after a successful launch"
                );
                }
            }
        }

        let mut run_command = Command::new(run.canonicalize().unwrap_or(run.clone()));
        if let Some(lease) = lifetime_lease.as_ref() {
            let lease_fd = lease.as_raw_fd();
            unsafe {
                run_command.pre_exec(move || LifetimeLease::prepare_fd_for_exec(lease_fd));
            }
        }
        if !process_procfs_available {
            match create_lifetime_pipe() {
                Ok((reader, writer)) => {
                    let writer_fd = writer.as_raw_fd();
                    lifetime_pipe = Some((reader, writer));
                    unsafe {
                        run_command.pre_exec(move || clear_fd_cloexec(writer_fd));
                    }
                }
                Err(err) => {
                    eprintln!(
                        "Warning: failed to create the application lifetime descriptor: {err}"
                    );
                }
            }
        }
        if should_drop_capabilities(unshare_succeeded || direct_mount_fallback, drop_caps) {
            let last_cap = last_capability();
            unsafe {
                run_command.pre_exec(move || drop_capabilities(last_cap));
            }
        }

        remove_runtime_separator(&mut exec_args);
        let (state, spawn_result, lifetime_reader) =
            finish_application_spawn(run_command.args(&exec_args).spawn(), lifetime_pipe.take());
        application_state = state;
        match spawn_result {
            Ok(mut run_child) => {
                let pid = Pid::from_raw(run_child.id() as i32);
                if let Some(writer) = supervisor_status_writer.as_ref() {
                    if let Err(err) = write_supervisor_value(writer.as_raw_fd(), pid.as_raw()) {
                        eprintln!("Warning: failed to report supervised application PID: {err}");
                    }
                } else {
                    let tmp_dir_clone = tmp_dir.clone();
                    spawn(move || signals_handler(pid, &tmp_dir_clone, true, false));
                }

                if let Ok(status) = run_child.wait() {
                    if let Some(code) = status.code() {
                        exit_code = code
                    }
                }
            }
            Err(err) => {
                if let Some(writer) = supervisor_status_writer.as_ref() {
                    let _ = write_supervisor_value(writer.as_raw_fd(), 0);
                }
                eprintln!("Failed to execute {:?}: {err}", run);
                exit_code = 1
            }
        }
        if let Some(writer) = supervisor_status_writer.take() {
            if let Err(err) = write_supervisor_value(writer.as_raw_fd(), exit_code) {
                eprintln!("Warning: failed to report supervised application status: {err}");
            }
            drop(writer);
        }
        if application_supervisor {
            try_setsid();
            if let Err(err) = detach_supervisor_stdio(&tmp_dir) {
                eprintln!("Warning: failed to detach application supervisor streams: {err}");
            }
        }
        if application_supervisor && child_subreaper_enabled {
            if let Err(err) = wait_for_all_children() {
                eprintln!("Warning: failed while supervising application descendants: {err}");
                application_tree_observable = false;
            }
        }
        lifetime_read_fd = lifetime_reader;
    } else if !is_tmpdir_exists {
        let tmp_dir_clone = tmp_dir.clone();
        spawn(move || signals_handler(child_pid, &tmp_dir_clone, false, false));
        wait_pid_exit(child_pid, None);
    } else {
        exit(exit_code)
    }

    let cleanup_execution = CleanupExecution::for_application(application_state, is_tmpdir_exists);
    if cleanup_execution == CleanupExecution::Skip {
        exit(exit_code)
    } else {
        if cleanup_execution == CleanupExecution::Detached && !application_supervisor {
            match unsafe { fork() } {
                Ok(ForkResult::Parent { child: _ }) => exit(exit_code),
                Ok(ForkResult::Child) => {}
                Err(err) => {
                    eprintln!("Fork error: {err}");
                    exit(1)
                }
            }
            try_setsid();
        }
        if unshare_succeeded {
            restore_capabilities()
        }
        drop(lifetime_lease.take());
        if extraction_cleanup_requires_descendant_visibility(
            application_state,
            is_extract_run,
            application_tree_observable,
        ) {
            eprintln!(
                "Warning: extraction cleanup was skipped because this kernel cannot prove that every daemonized descendant has exited"
            );
            exit(cleanup_exit_code(cleanup_execution, exit_code))
        }

        let tmp_dir_clone = tmp_dir.clone();
        spawn(move || signals_handler(child_pid, &tmp_dir_clone, false, true));

        let is_mount = !is_extract_run && !is_mount_only;
        let reuse_check_delay = parse_reuse_check_delay(&reuse_check_delay);

        let cleanup_work =
            cleanup_work_for_application(application_state, is_extract_run, is_mount);
        if cleanup_work == CleanupWork::ImmediateExtraction {
            let _cleanup_lease = cleanup_lease_or_exit(&tmp_dir, lifetime_lease_enabled);
            let _ = remove_dir_all(&tmp_dir);
        } else if cleanup_work == CleanupWork::ImmediateMount {
            if wait_dir_notuse(&tmp_dir, None, None, false, lifetime_read_fd) {
                let _cleanup_lease = cleanup_lease_or_exit(&tmp_dir, lifetime_lease_enabled);
                try_unmount(Some(child_pid), &tmp_dir);
            }
        } else if is_extract_run {
            if !is_noclenup
                && reuse_check_delay.is_some()
                && wait_dir_notuse(&tmp_dir, None, reuse_check_delay, true, lifetime_read_fd)
            {
                let _cleanup_lease = cleanup_lease_or_exit(&tmp_dir, lifetime_lease_enabled);
                let _ = remove_dir_all(&tmp_dir);
            }
        } else if !is_remp_mount && is_mount {
            if wait_dir_notuse(&tmp_dir, None, None, false, lifetime_read_fd) {
                try_unmount(Some(child_pid), &tmp_dir);
            }
        } else if is_remp_mount && is_mount {
            if let Some(reuse_delay) = reuse_check_delay {
                let has_procfs = process_procfs_available_at(Path::new("/proc"));
                let ready = wait_dir_notuse(
                    &tmp_dir,
                    None,
                    if has_procfs { Some(reuse_delay) } else { None },
                    has_procfs,
                    lifetime_read_fd,
                );
                if ready {
                    let _cleanup_lease = cleanup_lease_or_exit(&tmp_dir, lifetime_lease_enabled);
                    let expire_outcome = if reusable_mount_expiry_available(
                        has_procfs,
                        has_effective_capability(CAP_SYS_ADMIN),
                    ) {
                        try_expire_mount(&tmp_dir, reuse_delay)
                    } else {
                        ExpireMountOutcome::FallbackUnmount
                    };
                    if expire_outcome == ExpireMountOutcome::FallbackUnmount {
                        try_unmount(Some(child_pid), &tmp_dir);
                    }
                }
            }
        }
        if is_mount {
            wait_pid_exit(child_pid, Some(Duration::from_secs(1)));
        }
        remove_tmp_dirs(&tmp_dirs, unshare_succeeded);
        exit(cleanup_exit_code(cleanup_execution, exit_code))
    }
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::panic,
    clippy::todo,
    clippy::unimplemented,
    clippy::unreachable,
    clippy::unwrap_used
)]
mod runtime_elf_tests;
