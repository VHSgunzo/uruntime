use std::collections::BTreeMap;
use std::env;
use std::ffi::OsStr;
use std::fs::{self, File, FileTimes, OpenOptions};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime};

use super::{project_root, resolve_program, terminate_process_group, DynError};

const WAIT_TIMEOUT: Duration = Duration::from_secs(20);
const COMMAND_TIMEOUT: Duration = Duration::from_secs(60);
const MAX_COMMAND_OUTPUT: u64 = 1024 * 1024;
const SCENARIO_TIMEOUT_MS: &str = "10000";
pub struct FixtureImages {
    pub squashfs: PathBuf,
    pub dwarfs: PathBuf,
}

struct CommandOutput {
    status: std::process::ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

fn bounded_command(command: &mut Command, description: &str) -> Result<CommandOutput, DynError> {
    eprintln!("+ {description}");
    let capture = tempfile::Builder::new()
        .prefix("uruntime-command-output-")
        .tempdir()?;
    let stdout_path = capture.path().join("stdout");
    let stderr_path = capture.path().join("stderr");
    command
        .process_group(0)
        .stdout(Stdio::from(File::create(&stdout_path)?))
        .stderr(Stdio::from(File::create(&stderr_path)?));
    let mut child = command.spawn()?;
    let deadline = Instant::now() + COMMAND_TIMEOUT;
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if [&stdout_path, &stderr_path].iter().any(|path| {
            path.metadata()
                .is_ok_and(|metadata| metadata.len() > MAX_COMMAND_OUTPUT)
        }) {
            terminate_process_group(&mut child);
            return Err(format!("{description} exceeded the output limit").into());
        }
        if Instant::now() >= deadline {
            terminate_process_group(&mut child);
            return Err(format!("{description} exceeded {COMMAND_TIMEOUT:?}").into());
        }
        thread::sleep(Duration::from_millis(25));
    };
    terminate_process_group(&mut child);
    let stdout = fs::read(&stdout_path)?;
    let stderr = fs::read(&stderr_path)?;
    if stdout.len() as u64 > MAX_COMMAND_OUTPUT || stderr.len() as u64 > MAX_COMMAND_OUTPUT {
        return Err(format!("{description} exceeded the output limit").into());
    }
    Ok(CommandOutput {
        status,
        stdout,
        stderr,
    })
}

fn run(command: &mut Command, description: &str) -> Result<(), DynError> {
    let result = bounded_command(command, description)?;
    if result.status.success() {
        Ok(())
    } else {
        Err(format!(
            "{description} failed with {}: {}",
            result.status,
            String::from_utf8_lossy(&result.stderr).trim()
        )
        .into())
    }
}

fn output(command: &mut Command, description: &str) -> Result<Vec<u8>, DynError> {
    let result = bounded_command(command, description)?;
    if result.status.success() {
        Ok(result.stdout)
    } else {
        Err(format!(
            "{description} failed with {}: {}",
            result.status,
            String::from_utf8_lossy(&result.stderr).trim()
        )
        .into())
    }
}

fn compile_rust_fixture(
    source: &Path,
    destination: &Path,
    target: &str,
    rustc: &Path,
) -> Result<(), DynError> {
    run(
        Command::new(rustc)
            .env("SOURCE_DATE_EPOCH", "0")
            .args(["--edition=2021", "--target", target])
            .args(["-C", "opt-level=s", "-C", "strip=symbols"])
            .args(["-C", "link-arg=-Wl,--build-id=none", "-o"])
            .arg(destination)
            .arg(source),
        &format!("compile {}", source.display()),
    )?;
    fs::set_permissions(destination, fs::Permissions::from_mode(0o755))?;
    Ok(())
}

fn set_epoch(path: &Path) -> Result<(), DynError> {
    File::open(path)?.set_times(
        FileTimes::new()
            .set_accessed(SystemTime::UNIX_EPOCH)
            .set_modified(SystemTime::UNIX_EPOCH),
    )?;
    Ok(())
}

fn append_files(destination: &Path, first: &Path, second: &Path) -> Result<(), DynError> {
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(destination)?;
    let mut input = File::open(first)?;
    std::io::copy(&mut input, &mut output)?;
    input = File::open(second)?;
    std::io::copy(&mut input, &mut output)?;
    output.sync_all()?;
    fs::set_permissions(destination, fs::Permissions::from_mode(0o755))?;
    Ok(())
}

pub fn generate_fixtures(
    runtime: &Path,
    output_dir: &Path,
    target: &str,
    rustc: &Path,
) -> Result<FixtureImages, DynError> {
    if !runtime.is_file() {
        return Err(format!("fixture runtime is not a file: {}", runtime.display()).into());
    }
    fs::create_dir_all(output_dir)?;
    let work = tempfile::Builder::new()
        .prefix("uruntime-fixture-source-")
        .tempdir()?;
    let source = work.path().join("source");
    fs::create_dir(&source)?;
    let app_run = source.join("AppRun");
    let payload = source.join("payload.txt");
    fs::write(&payload, b"retained inode payload\n")?;
    compile_rust_fixture(
        &project_root().join("tests/fixtures/apprun.rs"),
        &app_run,
        target,
        rustc,
    )?;
    fs::set_permissions(&source, fs::Permissions::from_mode(0o755))?;
    fs::set_permissions(&payload, fs::Permissions::from_mode(0o644))?;
    set_epoch(&app_run)?;
    set_epoch(&payload)?;
    set_epoch(&source)?;

    let diagnostic = output(
        Command::new(&app_run).arg("fixture-self-test"),
        "run AppRun diagnostic contract",
    )?;
    let diagnostic = String::from_utf8(diagnostic)?;
    for expected in [
        "fixture=uruntime-apprun-v1",
        "argc=2",
        "argv.1=fixture-self-test",
    ] {
        if !diagnostic.lines().any(|line| line == expected) {
            return Err(format!("AppRun diagnostic contract omitted `{expected}`").into());
        }
    }

    let squashfs = output_dir.join("tiny.squashfs");
    run(
        Command::new(runtime)
            .arg("--appimage-mksquashfs")
            .arg(&source)
            .arg(&squashfs)
            .args([
                "-noappend",
                "-comp",
                "gzip",
                "-repro-time",
                "0",
                "-all-root",
                "-no-xattrs",
                "-force-dir-mode",
                "0755",
                "-no-progress",
            ]),
        "generate deterministic SquashFS fixture",
    )?;

    let dwarfs = output_dir.join("tiny.dwarfs");
    run(
        Command::new(runtime)
            .arg("--appimage-mkdwarfs")
            .args(["--input"])
            .arg(&source)
            .args(["--output"])
            .arg(&dwarfs)
            .args([
                "--force",
                "--compress-level=0",
                "--compression=zstd:level=1",
                "--schema-compression=zstd:level=1",
                "--metadata-compression=zstd:level=1",
                "--order=path",
                "--num-workers=1",
                "--num-scanner-workers=1",
                "--num-segmenter-workers=1",
                "--set-owner=0",
                "--set-group=0",
                "--set-time=0",
                "--no-create-timestamp",
                "--no-history",
                "--no-progress",
                "--log-level=error",
            ]),
        "generate deterministic DwarFS fixture",
    )?;

    let extracted = output(
        Command::new(runtime)
            .args(["--appimage-unsquashfs", "-cat"])
            .arg(&squashfs)
            .arg("payload.txt"),
        "validate SquashFS payload",
    )?;
    if extracted != fs::read(&payload)? {
        return Err("SquashFS fixture payload mismatch".into());
    }
    run(
        Command::new(runtime)
            .args(["--appimage-dwarfsck", "--input"])
            .arg(&dwarfs)
            .args(["--check-integrity", "--log-level=error"])
            .stdout(Stdio::null()),
        "validate DwarFS fixture integrity",
    )?;

    for (name, filesystem) in [("squashfs", &squashfs), ("dwarfs", &dwarfs)] {
        let image = work.path().join(format!("{name}.AppImage"));
        append_files(&image, runtime, filesystem)?;
        let launched = output(
            Command::new(&image).arg("fixture-image-test"),
            &format!("launch {name} fixture image"),
        )?;
        let launched = String::from_utf8(launched)?;
        for expected in [
            "fixture=uruntime-apprun-v1",
            "argc=2",
            "argv.1=fixture-image-test",
        ] {
            if !launched.lines().any(|line| line == expected) {
                return Err(format!("{name} launch omitted `{expected}`").into());
            }
        }
        if !launched
            .lines()
            .any(|line| line.starts_with("env.APPDIR=/"))
            || !launched
                .lines()
                .any(|line| line.starts_with("namespace.mnt="))
        {
            return Err(format!("{name} launch omitted AppDir or mount namespace data").into());
        }
    }

    Ok(FixtureImages { squashfs, dwarfs })
}

fn parse_result(path: &Path) -> Result<BTreeMap<String, String>, DynError> {
    let contents = fs::read_to_string(path)?;
    let mut values = BTreeMap::new();
    for line in contents.lines() {
        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| format!("invalid result line in {}: {line:?}", path.display()))?;
        if key.is_empty() || values.insert(key.to_string(), value.to_string()).is_some() {
            return Err(format!("invalid or duplicate result key in {}", path.display()).into());
        }
    }
    Ok(values)
}

fn wait_for(
    mut predicate: impl FnMut() -> bool,
    description: &str,
    timeout: Duration,
) -> Result<(), DynError> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if predicate() {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(25));
    }
    Err(format!("timed out waiting for {description}").into())
}

fn wait_file(path: &Path, description: &str) -> Result<BTreeMap<String, String>, DynError> {
    wait_for(|| path.is_file(), description, WAIT_TIMEOUT)?;
    parse_result(path)
}

fn wait_file_from_child(
    path: &Path,
    description: &str,
    child: &mut Child,
    log: &Path,
) -> Result<BTreeMap<String, String>, DynError> {
    let deadline = Instant::now() + WAIT_TIMEOUT;
    loop {
        if path.is_file() {
            return parse_result(path);
        }
        if let Some(status) = child.try_wait()? {
            let output = fs::read_to_string(log)
                .unwrap_or_else(|error| format!("<failed to read {}: {error}>", log.display()));
            return Err(format!(
                "{description}: launcher exited with {status} before publishing the marker; log: {}",
                output.trim()
            )
            .into());
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            let output = fs::read_to_string(log)
                .unwrap_or_else(|error| format!("<failed to read {}: {error}>", log.display()));
            return Err(format!(
                "timed out waiting for {description}; launcher log: {}",
                output.trim()
            )
            .into());
        }
        thread::sleep(Duration::from_millis(25));
    }
}

fn target_from_result(
    state: &Path,
    values: &BTreeMap<String, String>,
) -> Result<PathBuf, DynError> {
    let appdir = values.get("appdir").ok_or("fixture result has no appdir")?;
    if appdir == "/state" {
        return Ok(state.to_path_buf());
    }
    if let Some(relative) = appdir.strip_prefix("/state/") {
        return Ok(state.join(relative));
    }
    let path = PathBuf::from(appdir);
    if path.is_absolute() {
        Ok(path)
    } else {
        Err(format!("fixture returned non-absolute appdir: {appdir:?}").into())
    }
}

fn wait_child(child: &mut Child, description: &str) -> Result<(), DynError> {
    let deadline = Instant::now() + WAIT_TIMEOUT;
    loop {
        if let Some(status) = child.try_wait()? {
            return if status.success() {
                Ok(())
            } else {
                Err(format!("{description} exited with {status}").into())
            };
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(format!("{description} exceeded {WAIT_TIMEOUT:?}").into());
        }
        thread::sleep(Duration::from_millis(25));
    }
}

fn process_mounts(path: &Path) -> bool {
    let Ok(path) = path.canonicalize() else {
        return false;
    };
    fs::read_to_string("/proc/self/mountinfo").is_ok_and(|contents| {
        contents
            .lines()
            .any(|line| line.contains(&*path.to_string_lossy()))
    })
}

fn log_file(path: &Path) -> Result<Stdio, DynError> {
    Ok(Stdio::from(File::create(path)?))
}

fn verify_no_fuse_automatic_extraction_fallback(
    bwrap: &Path,
    image: &Path,
    filesystem: &str,
) -> Result<(), DynError> {
    for launch in ["first", "second"] {
        let result = bounded_command(
            Command::new(bwrap)
                .args([
                    "--tmpfs",
                    "/",
                    "--dev",
                    "/dev",
                    "--cap-add",
                    "ALL",
                    "--ro-bind",
                ])
                .arg(image)
                .arg("/image.AppImage")
                .args(["--clearenv", "--setenv", "PATH", "/usr/bin:/bin"])
                .args(["--setenv", "REUSE_CHECK_DELAY", "1s"])
                .args(["/image.AppImage", "fixture-image-test"]),
            &format!("{launch} {filesystem} no-FUSE automatic extraction fallback"),
        )?;
        if !result.status.success() {
            return Err(format!(
                "{launch} {filesystem} no-FUSE automatic extraction fallback failed with {}: {}",
                result.status,
                String::from_utf8_lossy(&result.stderr).trim()
            )
            .into());
        }
        let launched = String::from_utf8(result.stdout)?;
        let stderr = String::from_utf8_lossy(&result.stderr);
        if stderr.contains("failed to detach application supervisor streams") {
            return Err(format!(
                "{launch} {filesystem} no-FUSE fallback could not detach supervisor streams"
            )
            .into());
        }
        for expected in ["fixture=uruntime-apprun-v1", "argv.1=fixture-image-test"] {
            if !launched.lines().any(|line| line == expected) {
                return Err(
                    format!("{launch} {filesystem} no-FUSE fallback omitted `{expected}`").into(),
                );
            }
        }
    }
    Ok(())
}

fn verify_no_fuse_fixed_target_fallback(
    bwrap: &Path,
    image: &Path,
    state: &Path,
    filesystem: &str,
) -> Result<(), DynError> {
    let target = state.join("fixed-target");
    let result = bounded_command(
        Command::new(bwrap)
            .args(["--tmpfs", "/", "--dev", "/dev", "--cap-add", "ALL"])
            .args(["--ro-bind"])
            .arg(image)
            .arg("/image.AppImage")
            .args(["--bind"])
            .arg(state)
            .arg("/state")
            .args(["--clearenv", "--setenv", "PATH", "/usr/bin:/bin"])
            .args(["--setenv", "APPIMAGE_TARGET_DIR", "/state/fixed-target/"])
            .args(["--setenv", "NO_CLEANUP", "1"])
            .args(["/image.AppImage", "fixture-image-test"]),
        &format!("{filesystem} no-FUSE fixed-target extraction fallback"),
    )?;
    if !result.status.success() {
        return Err(format!(
            "{filesystem} no-FUSE fixed-target fallback failed with {}: {}",
            result.status,
            String::from_utf8_lossy(&result.stderr).trim()
        )
        .into());
    }
    let launched = String::from_utf8(result.stdout)?;
    if !launched
        .lines()
        .any(|line| line == "fixture=uruntime-apprun-v1")
        || !target.join("AppRun").is_file()
        || !state.join("fixed-target.lock").is_file()
        || target.join(".lock").exists()
    {
        return Err(format!(
            "{filesystem} no-FUSE fallback did not preserve its normalized fixed target"
        )
        .into());
    }
    Ok(())
}

fn verify_no_dev_automatic_extraction_fallback(
    bwrap: &Path,
    image: &Path,
    filesystem: &str,
) -> Result<(), DynError> {
    let result = bounded_command(
        Command::new(bwrap)
            .args(["--tmpfs", "/", "--ro-bind"])
            .arg(image)
            .arg("/image.AppImage")
            .args(["--clearenv", "--setenv", "PATH", "/usr/bin:/bin"])
            .args(["/image.AppImage", "fixture-image-test"]),
        &format!("{filesystem} no-/dev automatic extraction fallback"),
    )?;
    if !result.status.success() {
        return Err(format!(
            "{filesystem} no-/dev automatic extraction fallback failed with {}: {}",
            result.status,
            String::from_utf8_lossy(&result.stderr).trim()
        )
        .into());
    }
    let launched = String::from_utf8(result.stdout)?;
    for expected in ["fixture=uruntime-apprun-v1", "argv.1=fixture-image-test"] {
        if !launched.lines().any(|line| line == expected) {
            return Err(format!("{filesystem} no-/dev fallback omitted `{expected}`").into());
        }
    }
    let stderr = String::from_utf8_lossy(&result.stderr);
    if stderr.contains("failed to detach application supervisor streams") {
        return Err(
            format!("{filesystem} no-/dev fallback could not detach supervisor streams").into(),
        );
    }
    Ok(())
}

fn verify_uid_map_only_proc_uses_no_proc_direct_mount(
    bwrap: &Path,
    image: &Path,
    state: &Path,
    filesystem: &str,
) -> Result<(), DynError> {
    fs::create_dir_all(state.join("tmp"))?;
    let uid_map = state.join("uid_map");
    fs::write(&uid_map, b"0 0 4294967295\n")?;
    let log = state.join("uid-map-only.log");
    let mut child = Command::new(bwrap);
    child
        .args(["--tmpfs", "/", "--dev-bind", "/dev", "/dev"])
        .args(["--cap-add", "ALL", "--ro-bind"])
        .arg(image)
        .arg("/image.AppImage")
        .args(["--bind"])
        .arg(state)
        .arg("/state")
        .args(["--dir", "/proc", "--dir", "/proc/self", "--ro-bind"])
        .arg(&uid_map)
        .arg("/proc/self/uid_map")
        .args(["--clearenv", "--setenv", "PATH", "/usr/bin:/bin"])
        .args(["--setenv", "TMPDIR", "/state/tmp"])
        .args(["--setenv", "URUNTIME_FIXTURE_OUTPUT", "/state"])
        .args(["--setenv", "REUSE_CHECK_DELAY", "200ms"])
        .args([
            "/image.AppImage",
            "--fixture-scenario",
            "hold",
            "uid-map-only",
            SCENARIO_TIMEOUT_MS,
        ])
        .stdout(log_file(&log)?)
        .stderr(Stdio::from(File::options().append(true).open(&log)?));
    eprintln!("+ {filesystem} uid-map-only procfs direct mount");
    let mut child = child.spawn()?;
    let ready = wait_file_from_child(
        &state.join("uid-map-only.ready"),
        "uid-map-only ready marker",
        &mut child,
        &log,
    )?;
    let target = target_from_result(state, &ready)?;
    if !target
        .file_name()
        .is_some_and(|name| name.to_string_lossy().contains(".mount_"))
    {
        return Err(format!(
            "{filesystem} uid-map-only procfs launch used extraction instead of direct FUSE: {}",
            target.display()
        )
        .into());
    }
    File::create(state.join("uid-map-only.release"))?;
    wait_child(&mut child, "uid-map-only launcher")?;
    verify_result(&state.join("uid-map-only.result"), "uid-map-only result")?;
    Ok(())
}

fn launch_no_proc(
    bwrap: &Path,
    image: &Path,
    state: &Path,
    scenario: &str,
    label: &str,
    log: &Path,
    deny_subreaper: Option<&Path>,
) -> Result<Child, DynError> {
    fs::create_dir_all(state.join("tmp"))?;
    let mut command = Command::new(bwrap);
    command
        .args(["--tmpfs", "/", "--dev-bind", "/dev", "/dev", "--ro-bind"])
        .arg(image)
        .arg("/image.AppImage")
        .args(["--bind"])
        .arg(state)
        .arg("/state")
        .args(["--dir", "/tmp", "--clearenv"])
        .args(["--setenv", "PATH", "/usr/bin:/bin"])
        .args(["--setenv", "TMPDIR", "/state/tmp"])
        .args(["--setenv", "URUNTIME_FIXTURE_OUTPUT", "/state"])
        .args(["--setenv", "APPIMAGE_EXTRACT_AND_RUN", "1"])
        .args(["--setenv", "APPIMAGE_UNSHARE", "1"])
        .args(["--setenv", "REUSE_CHECK_DELAY", "200ms"]);
    if let Some(helper) = deny_subreaper {
        command
            .args(["--ro-bind"])
            .arg(helper)
            .arg("/deny-subreaper")
            .args(["/deny-subreaper", "/image.AppImage"]);
    } else {
        command.arg("/image.AppImage");
    }
    command
        .args(["--fixture-scenario", scenario, label, SCENARIO_TIMEOUT_MS])
        .stdout(log_file(log)?)
        .stderr(Stdio::from(File::options().append(true).open(log)?));
    eprintln!("+ no-proc {scenario} scenario ({label})");
    Ok(command.spawn()?)
}

fn launch_fuse(image: &Path, state: &Path, label: &str, log: &Path) -> Result<Child, DynError> {
    fs::create_dir_all(state.join("tmp"))?;
    let mut command = Command::new(image);
    for name in [
        "APPIMAGE_EXTRACT_AND_RUN",
        "APPIMAGE_UNSHARE",
        "APPIMAGE_UNSHARE_ROOT",
        "APPIMAGE_UNSHARE_UID",
        "APPIMAGE_UNSHARE_GID",
        "NO_UNMOUNT",
    ] {
        command.env_remove(name);
    }
    command
        .env("TMPDIR", state.join("tmp"))
        .env("URUNTIME_FIXTURE_OUTPUT", state)
        .env("REUSE_CHECK_DELAY", "200ms")
        .args(["--fixture-scenario", "hold", label, SCENARIO_TIMEOUT_MS])
        .stdout(log_file(log)?)
        .stderr(Stdio::from(File::options().append(true).open(log)?));
    eprintln!("+ current-namespace FUSE hold scenario ({label})");
    Ok(command.spawn()?)
}

fn verify_result(path: &Path, description: &str) -> Result<BTreeMap<String, String>, DynError> {
    let result = wait_file(path, description)?;
    if result.get("start_present").map(String::as_str) != Some("true")
        || result.get("end_present").map(String::as_str) != Some("true")
    {
        return Err(format!("{description} lost its payload").into());
    }
    Ok(result)
}

fn run_overlap<F>(
    filesystem: &str,
    image: &Path,
    state: &Path,
    require_mount: bool,
    mut launch: F,
) -> Result<(), DynError>
where
    F: FnMut(&Path, &Path, &str, &Path) -> Result<Child, DynError>,
{
    let first_log = state.join("first.log");
    let mut first = launch(image, state, "first", &first_log)?;
    let first_ready = wait_file_from_child(
        &state.join("first.ready"),
        "first ready marker",
        &mut first,
        &first_log,
    )?;
    let first_target = target_from_result(state, &first_ready)?;
    let second_log = state.join("second.log");
    let mut second = launch(image, state, "second", &second_log)?;
    let second_ready = wait_file_from_child(
        &state.join("second.ready"),
        "second ready marker",
        &mut second,
        &second_log,
    )?;
    let second_target = target_from_result(state, &second_ready)?;
    if first_target != second_target {
        return Err(format!("{filesystem} overlapping launches selected different targets").into());
    }
    if !first_target.join("payload.txt").is_file() {
        return Err(format!("{filesystem} target has no payload").into());
    }
    if require_mount
        && (!process_mounts(&first_target)
            || !first_target
                .file_name()
                .is_some_and(|name| name.to_string_lossy().contains(".mount_")))
    {
        return Err(format!("{filesystem} target is not a live reusable FUSE mount").into());
    }

    File::create(state.join("first.release"))?;
    wait_child(&mut first, "first overlapping launcher")?;
    verify_result(&state.join("first.result"), "first overlap result")?;
    thread::sleep(Duration::from_millis(500));
    if !second_target.join("payload.txt").is_file()
        || (require_mount && !process_mounts(&second_target))
    {
        return Err(format!("{filesystem} target vanished beneath the second launch").into());
    }

    File::create(state.join("second.release"))?;
    wait_child(&mut second, "second overlapping launcher")?;
    verify_result(&state.join("second.result"), "second overlap result")?;
    wait_for(
        || !process_mounts(&second_target) && !second_target.exists(),
        "final overlapping target cleanup",
        WAIT_TIMEOUT,
    )?;
    Ok(())
}

fn run_daemon(
    filesystem: &str,
    image: &Path,
    state: &Path,
    bwrap: &Path,
    deny_subreaper: Option<&Path>,
) -> Result<(), DynError> {
    let retained = deny_subreaper.is_some();
    let label = if retained { "denied" } else { "daemon" };
    let log = state.join(format!("{label}.log"));
    let mut child = launch_no_proc(bwrap, image, state, "daemon", label, &log, deny_subreaper)?;
    let ready = wait_file_from_child(
        &state.join(format!("{label}.ready")),
        "daemon ready marker",
        &mut child,
        &log,
    )?;
    let target = target_from_result(state, &ready)?;
    if !target.join("payload.txt").is_file() {
        return Err(format!("{filesystem} daemon target has no payload").into());
    }
    File::create(state.join(format!("{label}.release")))?;
    let result = verify_result(
        &state.join(format!("{label}.result")),
        "daemon scenario result",
    )?;
    if result.get("daemonized").map(String::as_str) != Some("true") {
        return Err(format!("{filesystem} payload did not report daemonization").into());
    }
    wait_child(&mut child, "daemon launcher")?;
    if retained {
        thread::sleep(Duration::from_secs(1));
        if !target.is_dir() {
            return Err(
                format!("{filesystem} target was removed without descendant visibility").into(),
            );
        }
        let log = fs::read_to_string(log)?;
        if !log.contains("child-subreaper supervision is unavailable") {
            return Err(
                format!("{filesystem} launch omitted unavailable-subreaper warning").into(),
            );
        }
    } else {
        wait_for(|| !target.exists(), "daemon target cleanup", WAIT_TIMEOUT)?;
    }
    Ok(())
}

fn fixture_contract(target: &str, rustc: &Path) -> Result<(), DynError> {
    let root = tempfile::Builder::new()
        .prefix("uruntime-apprun-contract-")
        .tempdir()?;
    let appdir = root.path().join("appdir");
    let state = root.path().join("state");
    fs::create_dir(&appdir)?;
    fs::create_dir(&state)?;
    fs::write(appdir.join("payload.txt"), b"fixture payload\n")?;
    let executable = root.path().join("AppRun");
    compile_rust_fixture(
        &project_root().join("tests/fixtures/apprun.rs"),
        &executable,
        target,
        rustc,
    )?;
    let mut child = Command::new(&executable)
        .env("APPDIR", &appdir)
        .env("URUNTIME_FIXTURE_OUTPUT", &state)
        .args([
            "--fixture-scenario",
            "hold",
            "contract",
            SCENARIO_TIMEOUT_MS,
        ])
        .spawn()?;
    wait_for(
        || state.join("contract.ready").is_file(),
        "fixture contract ready marker",
        WAIT_TIMEOUT,
    )?;
    File::create(state.join("contract.release"))?;
    wait_child(&mut child, "fixture contract")?;
    verify_result(&state.join("contract.result"), "fixture contract result")?;
    Ok(())
}

fn fuse_prerequisite(project: &Path) -> Result<(), String> {
    let fuse = Path::new("/dev/fuse");
    if !fuse.exists() {
        return Err("/dev/fuse does not exist".into());
    }
    let writable = OpenOptions::new().read(true).write(true).open(fuse);
    if let Err(error) = writable {
        return Err(format!("/dev/fuse is not readable and writable: {error}"));
    }
    if resolve_program(Path::new("fusermount3"), project).is_err()
        && resolve_program(Path::new("fusermount"), project).is_err()
    {
        return Err("neither fusermount3 nor fusermount is in PATH".into());
    }
    Ok(())
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub enum FuseMode {
    Auto,
    Required,
    Skip,
}

pub fn run_lifecycle(runtime: &Path, target: &str, fuse_mode: FuseMode) -> Result<(), DynError> {
    let project = project_root();
    let rustc = resolve_program(
        Path::new(
            env::var_os("RUSTC")
                .as_deref()
                .unwrap_or(OsStr::new("rustc")),
        ),
        &project,
    )?;
    fixture_contract(target, &rustc)?;
    eprintln!("PASS fixture scenario contract");

    let bwrap = resolve_program(Path::new("bwrap"), &project)?;
    let root = tempfile::Builder::new()
        .prefix("uruntime-lifecycle-")
        .tempdir()?;
    let fixtures = generate_fixtures(runtime, &root.path().join("fixtures"), target, &rustc)?;
    let deny_subreaper = root.path().join("deny-subreaper");
    compile_rust_fixture(
        &project.join("tests/fixtures/deny_subreaper.rs"),
        &deny_subreaper,
        target,
        &rustc,
    )?;

    for (filesystem, filesystem_image) in
        [("squashfs", fixtures.squashfs), ("dwarfs", fixtures.dwarfs)]
    {
        let image = root.path().join(format!("lifecycle-{filesystem}.AppImage"));
        append_files(&image, runtime, &filesystem_image)?;

        verify_no_fuse_automatic_extraction_fallback(&bwrap, &image, filesystem)?;
        eprintln!("PASS {filesystem} empty-root no-FUSE automatic extraction fallback");
        let state = root.path().join(format!("{filesystem}-fixed-target"));
        fs::create_dir(&state)?;
        verify_no_fuse_fixed_target_fallback(&bwrap, &image, &state, filesystem)?;
        eprintln!("PASS {filesystem} no-FUSE fixed-target extraction fallback");
        verify_no_dev_automatic_extraction_fallback(&bwrap, &image, filesystem)?;
        eprintln!("PASS {filesystem} empty-root no-/dev supervisor detachment");

        let state = root.path().join(format!("{filesystem}-extract-overlap"));
        fs::create_dir(&state)?;
        run_overlap(
            filesystem,
            &image,
            &state,
            false,
            |image, state, label, log| {
                launch_no_proc(&bwrap, image, state, "hold", label, log, None)
            },
        )?;
        eprintln!("PASS {filesystem} no-proc explicit-unshare extraction overlap");

        let state = root.path().join(format!("{filesystem}-daemon"));
        fs::create_dir(&state)?;
        run_daemon(filesystem, &image, &state, &bwrap, None)?;
        eprintln!("PASS {filesystem} no-proc explicit-unshare FD-closing double-fork");

        let state = root.path().join(format!("{filesystem}-retain"));
        fs::create_dir(&state)?;
        run_daemon(filesystem, &image, &state, &bwrap, Some(&deny_subreaper))?;
        eprintln!("PASS {filesystem} no-proc denied-subreaper fail-safe retention");

        match (fuse_mode, fuse_prerequisite(&project)) {
            (FuseMode::Skip, _) => {
                eprintln!("NOT RUN {filesystem} FUSE lifecycle lane: disabled explicitly")
            }
            (FuseMode::Required, Err(reason)) => {
                return Err(format!("required FUSE lifecycle lane unavailable: {reason}").into())
            }
            (FuseMode::Auto, Err(reason)) => {
                eprintln!("NOT RUN {filesystem} FUSE lifecycle lane: {reason}")
            }
            (_, Ok(())) => {
                let state = root.path().join(format!("{filesystem}-fuse-overlap"));
                fs::create_dir(&state)?;
                verify_uid_map_only_proc_uses_no_proc_direct_mount(
                    &bwrap, &image, &state, filesystem,
                )?;
                eprintln!("PASS {filesystem} uid-map-only procfs direct FUSE launch");
                run_overlap(filesystem, &image, &state, true, launch_fuse)?;
                eprintln!("PASS {filesystem} current-namespace FUSE overlap");
            }
        }
    }
    eprintln!("PASS uruntime lifecycle harness");
    Ok(())
}

pub fn fixture_command(args: &[String]) -> Result<(), DynError> {
    let mut runtime = None;
    let mut output = project_root().join("target/fixtures");
    let mut target = "x86_64-unknown-linux-musl".to_string();
    let mut check = false;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--runtime" => {
                index += 1;
                runtime = args.get(index).map(PathBuf::from);
            }
            "--output" => {
                index += 1;
                output = args
                    .get(index)
                    .map(PathBuf::from)
                    .ok_or("--output requires a path")?;
            }
            "--target" => {
                index += 1;
                target = args
                    .get(index)
                    .cloned()
                    .ok_or("--target requires a value")?;
            }
            "--check" => check = true,
            other => return Err(format!("unknown fixtures option `{other}`").into()),
        }
        index += 1;
    }
    let runtime = runtime.ok_or("fixtures requires --runtime PATH")?;
    let project = project_root();
    let rustc = resolve_program(Path::new("rustc"), &project)?;
    if check {
        let first = tempfile::tempdir()?;
        let second = tempfile::tempdir()?;
        let first_images = generate_fixtures(&runtime, first.path(), &target, &rustc)?;
        let second_images = generate_fixtures(&runtime, second.path(), &target, &rustc)?;
        for (name, first, second) in [
            ("SquashFS", first_images.squashfs, second_images.squashfs),
            ("DwarFS", first_images.dwarfs, second_images.dwarfs),
        ] {
            let first = fs::read(first)?;
            if first != fs::read(second)? {
                return Err(format!("{name} fixture generation is not deterministic").into());
            }
        }
        eprintln!("fixture images are reproducible for {target}");
    } else {
        let generated = generate_fixtures(&runtime, &output, &target, &rustc)?;
        eprintln!("generated {}", generated.squashfs.display());
        eprintln!("generated {}", generated.dwarfs.display());
    }
    Ok(())
}

pub fn parse_lifecycle_args(args: &[String]) -> Result<(PathBuf, String, FuseMode), DynError> {
    let mut runtime = None;
    let mut target = "x86_64-unknown-linux-musl".to_string();
    let mut fuse = FuseMode::Auto;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--runtime" => {
                index += 1;
                runtime = args.get(index).map(PathBuf::from);
            }
            "--target" => {
                index += 1;
                target = args
                    .get(index)
                    .cloned()
                    .ok_or("--target requires a value")?;
            }
            "--fuse=auto" => fuse = FuseMode::Auto,
            "--fuse=required" => fuse = FuseMode::Required,
            "--fuse=skip" => fuse = FuseMode::Skip,
            other => return Err(format!("unknown lifecycle option `{other}`").into()),
        }
        index += 1;
    }
    Ok((
        runtime.ok_or("lifecycle requires --runtime PATH")?,
        target,
        fuse,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_output_does_not_wait_for_inherited_descriptors() {
        let started = Instant::now();
        let bytes = output(
            Command::new("/bin/sh").args(["-c", "printf done; sleep 3 &"]),
            "inherited output fixture",
        )
        .unwrap();
        assert_eq!(bytes, b"done");
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn lifecycle_arguments_require_runtime_and_validate_options() {
        assert!(parse_lifecycle_args(&[]).is_err());
        let parsed = parse_lifecycle_args(&[
            "--runtime".into(),
            "runtime".into(),
            "--target".into(),
            "aarch64-unknown-linux-musl".into(),
            "--fuse=required".into(),
        ])
        .unwrap();
        assert_eq!(parsed.0, PathBuf::from("runtime"));
        assert_eq!(parsed.1, "aarch64-unknown-linux-musl");
        assert!(parsed.2 == FuseMode::Required);
        assert!(parse_lifecycle_args(&["--unknown".into()]).is_err());
    }

    #[test]
    fn marker_wait_reports_an_early_launcher_failure_and_log() {
        let root = tempfile::tempdir().unwrap();
        let marker = root.path().join("ready");
        let log = root.path().join("launcher.log");
        let output = File::create(&log).unwrap();
        let mut child = Command::new("/bin/sh")
            .args(["-c", "printf 'namespace denied\\n' >&2; exit 42"])
            .stderr(Stdio::from(output))
            .spawn()
            .unwrap();
        let started = Instant::now();
        let error = wait_file_from_child(&marker, "test marker", &mut child, &log)
            .unwrap_err()
            .to_string();
        assert!(started.elapsed() < Duration::from_secs(2));
        assert!(error.contains("exit status: 42"));
        assert!(error.contains("namespace denied"));
    }

    #[test]
    fn result_parser_rejects_malformed_and_duplicate_records() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("result");
        fs::write(&path, "one=1\ntwo=2\n").unwrap();
        assert_eq!(parse_result(&path).unwrap().len(), 2);
        fs::write(&path, "one=1\none=2\n").unwrap();
        assert!(parse_result(&path).is_err());
        fs::write(&path, "missing separator\n").unwrap();
        assert!(parse_result(&path).is_err());
    }
}
