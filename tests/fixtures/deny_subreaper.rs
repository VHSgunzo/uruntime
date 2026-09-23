use std::env;
use std::ffi::c_int;
use std::os::unix::process::CommandExt;
use std::process::{self, Command};

#[repr(C)]
struct SockFilter {
    code: u16,
    jump_true: u8,
    jump_false: u8,
    value: u32,
}

#[repr(C)]
struct SockFilterProgram {
    length: u16,
    filters: *const SockFilter,
}

unsafe extern "C" {
    fn prctl(option: c_int, ...) -> c_int;
}

const PR_SET_NO_NEW_PRIVS: c_int = 38;
const PR_SET_SECCOMP: c_int = 22;
const PR_SET_CHILD_SUBREAPER: u32 = 36;
const SECCOMP_MODE_FILTER: usize = 2;
const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
const EPERM: u32 = 1;
const BPF_LD_W_ABS: u16 = 0x20;
const BPF_JMP_JEQ_K: u16 = 0x15;
const BPF_RET_K: u16 = 0x06;
const SECCOMP_DATA_NR_OFFSET: u32 = 0;
#[cfg(target_endian = "little")]
const SECCOMP_DATA_ARGS_OFFSET: u32 = 16;
#[cfg(target_endian = "big")]
const SECCOMP_DATA_ARGS_OFFSET: u32 = 20;

#[cfg(target_arch = "x86_64")]
const SYS_PRCTL: u32 = 157;
#[cfg(target_arch = "aarch64")]
const SYS_PRCTL: u32 = 167;
#[cfg(target_arch = "riscv64")]
const SYS_PRCTL: u32 = 167;
#[cfg(target_arch = "loongarch64")]
const SYS_PRCTL: u32 = 167;
#[cfg(target_arch = "powerpc64")]
const SYS_PRCTL: u32 = 171;

fn statement(code: u16, value: u32) -> SockFilter {
    SockFilter {
        code,
        jump_true: 0,
        jump_false: 0,
        value,
    }
}

fn jump(code: u16, value: u32, jump_true: u8, jump_false: u8) -> SockFilter {
    SockFilter {
        code,
        jump_true,
        jump_false,
        value,
    }
}

fn install_filter() -> Result<(), String> {
    let filters = [
        statement(BPF_LD_W_ABS, SECCOMP_DATA_NR_OFFSET),
        jump(BPF_JMP_JEQ_K, SYS_PRCTL, 0, 3),
        statement(BPF_LD_W_ABS, SECCOMP_DATA_ARGS_OFFSET),
        jump(BPF_JMP_JEQ_K, PR_SET_CHILD_SUBREAPER, 0, 1),
        statement(BPF_RET_K, SECCOMP_RET_ERRNO | EPERM),
        statement(BPF_RET_K, SECCOMP_RET_ALLOW),
    ];
    let program = SockFilterProgram {
        length: filters.len() as u16,
        filters: filters.as_ptr(),
    };
    if unsafe { prctl(PR_SET_NO_NEW_PRIVS, 1usize, 0usize, 0usize, 0usize) } != 0 {
        return Err(format!(
            "PR_SET_NO_NEW_PRIVS failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    if unsafe {
        prctl(
            PR_SET_SECCOMP,
            SECCOMP_MODE_FILTER,
            &program as *const SockFilterProgram,
        )
    } != 0
    {
        return Err(format!(
            "PR_SET_SECCOMP failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

fn main() {
    let mut arguments = env::args_os();
    let _program = arguments.next();
    let Some(command) = arguments.next() else {
        eprintln!("usage: deny_subreaper PROGRAM [ARG...]");
        process::exit(64);
    };
    if let Err(error) = install_filter() {
        eprintln!("{error}");
        process::exit(65);
    }
    let error = Command::new(command).args(arguments).exec();
    eprintln!("exec failed: {error}");
    process::exit(66);
}
