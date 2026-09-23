use std::env;
use std::ffi::{c_int, OsStr};
use std::fs;
use std::path::Path;
use std::process;
use std::thread;
use std::time::{Duration, Instant};

unsafe extern "C" {
    fn getpid() -> c_int;
    fn getppid() -> c_int;
    fn getuid() -> u32;
    fn geteuid() -> u32;
    fn getgid() -> u32;
    fn getegid() -> u32;
    fn fork() -> c_int;
    fn setsid() -> c_int;
    fn close(fd: c_int) -> c_int;
}

fn display(value: &OsStr) -> String {
    value.to_string_lossy().into_owned()
}

fn print_env(name: &str) {
    match env::var_os(name) {
        Some(value) => println!("env.{name}={}", display(&value)),
        None => println!("env.{name}=<unset>"),
    }
}

fn print_namespace(name: &str) {
    let path = Path::new("/proc/self/ns").join(name);
    match std::fs::read_link(path) {
        Ok(target) => println!("namespace.{name}={}", target.display()),
        Err(error) => println!("namespace.{name}=unavailable:{error}"),
    }
}

fn bool_text(value: bool) -> &'static str {
    if value {
        "true"
    } else {
        "false"
    }
}

fn scenario_paths(label: &str) -> Result<(std::path::PathBuf, std::path::PathBuf), String> {
    let output = env::var_os("URUNTIME_FIXTURE_OUTPUT")
        .map(std::path::PathBuf::from)
        .ok_or_else(|| "URUNTIME_FIXTURE_OUTPUT is not set".to_string())?;
    let appdir = env::var_os("APPDIR")
        .map(std::path::PathBuf::from)
        .ok_or_else(|| "APPDIR is not set".to_string())?;
    if label.is_empty()
        || !label
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        return Err("scenario label must contain only ASCII letters, digits, '-' or '_'".into());
    }
    Ok((output, appdir))
}

fn publish(path: &Path, contents: &str) -> Result<(), String> {
    let mut temporary = path.as_os_str().to_os_string();
    temporary.push(format!(".tmp.{}", unsafe { getpid() }));
    let temporary = std::path::PathBuf::from(temporary);
    fs::write(&temporary, contents)
        .map_err(|error| format!("failed to write {}: {error}", temporary.display()))?;
    fs::rename(&temporary, path)
        .map_err(|error| format!("failed to publish {}: {error}", path.display()))
}

fn wait_for_release(path: &Path, timeout: Duration) -> Result<(), String> {
    let started = Instant::now();
    while !path.is_file() {
        if started.elapsed() >= timeout {
            return Err(format!("timed out waiting for {}", path.display()));
        }
        thread::sleep(Duration::from_millis(10));
    }
    Ok(())
}

fn run_lifecycle_body(label: &str, timeout_ms: u64, daemonized: bool) -> Result<(), String> {
    let (output, appdir) = scenario_paths(label)?;
    let payload = appdir.join("payload.txt");
    let start_present = payload.is_file();
    let ready = format!(
        "label={label}\nappdir={}\nstart_present={}\ndaemonized={}\n",
        appdir.display(),
        bool_text(start_present),
        bool_text(daemonized)
    );
    publish(&output.join(format!("{label}.ready")), &ready)?;
    wait_for_release(
        &output.join(format!("{label}.release")),
        Duration::from_millis(timeout_ms),
    )?;
    let end_present = payload.is_file();
    let result = format!(
        "label={label}\nappdir={}\nstart_present={}\nend_present={}\ndaemonized={}\n",
        appdir.display(),
        bool_text(start_present),
        bool_text(end_present),
        bool_text(daemonized)
    );
    publish(&output.join(format!("{label}.result")), &result)?;
    if start_present && end_present {
        Ok(())
    } else {
        Err("payload was unavailable during the lifecycle scenario".into())
    }
}

fn run_lifecycle_scenario(arguments: &[std::ffi::OsString]) -> Result<bool, String> {
    if arguments.get(1).and_then(|value| value.to_str()) != Some("--fixture-scenario") {
        return Ok(false);
    }
    let mode = arguments
        .get(2)
        .and_then(|value| value.to_str())
        .ok_or_else(|| "missing fixture scenario mode".to_string())?;
    let label = arguments
        .get(3)
        .and_then(|value| value.to_str())
        .ok_or_else(|| "missing fixture scenario label".to_string())?;
    let timeout_ms = arguments
        .get(4)
        .and_then(|value| value.to_str())
        .ok_or_else(|| "missing fixture scenario timeout".to_string())?
        .parse::<u64>()
        .map_err(|error| format!("invalid fixture scenario timeout: {error}"))?;
    if timeout_ms == 0 || timeout_ms > 60_000 {
        return Err("fixture scenario timeout must be between 1 and 60000 ms".into());
    }

    match mode {
        "hold" => run_lifecycle_body(label, timeout_ms, false)?,
        "daemon" => {
            let first = unsafe { fork() };
            if first < 0 {
                return Err("first daemon fork failed".into());
            }
            if first > 0 {
                return Ok(true);
            }
            if unsafe { setsid() } < 0 {
                process::exit(71);
            }
            let second = unsafe { fork() };
            if second < 0 {
                process::exit(72);
            }
            if second > 0 {
                process::exit(0);
            }
            for fd in 3..1024 {
                unsafe {
                    close(fd);
                }
            }
            if let Err(error) = run_lifecycle_body(label, timeout_ms, true) {
                eprintln!("fixture daemon scenario failed: {error}");
                process::exit(73);
            }
        }
        _ => return Err(format!("unknown fixture scenario: {mode}")),
    }
    Ok(true)
}

fn main() {
    let arguments: Vec<_> = env::args_os().collect();
    match run_lifecycle_scenario(&arguments) {
        Ok(true) => return,
        Ok(false) => {}
        Err(error) => {
            eprintln!("fixture scenario failed: {error}");
            process::exit(70);
        }
    }

    println!("fixture=uruntime-apprun-v1");
    unsafe {
        println!("pid={}", getpid());
        println!("ppid={}", getppid());
        println!("uid={}", getuid());
        println!("euid={}", geteuid());
        println!("gid={}", getgid());
        println!("egid={}", getegid());
    }
    match env::current_dir() {
        Ok(path) => println!("cwd={}", path.display()),
        Err(error) => println!("cwd=unavailable:{error}"),
    }

    print_namespace("user");
    print_namespace("mnt");

    for name in [
        "APPDIR",
        "APPIMAGE",
        "APPOFFSET",
        "ARGV0",
        "OWD",
        "URUNTIME",
        "URUNTIME_DIR",
    ] {
        print_env(name);
    }

    println!("argc={}", arguments.len());
    for (index, argument) in arguments.iter().enumerate() {
        println!("argv.{index}={}", display(argument));
    }
}
