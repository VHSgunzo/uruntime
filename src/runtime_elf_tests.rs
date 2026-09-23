use super::{
    acquire_legacy_target_usage_lease, acquire_target_usage_lease, add_section_data,
    application_supervisor_required, atomic_publish_file_with, base_hash, can_mount_directly,
    classify_expire_mount_error, classify_ofd_lock_error, classify_target_directory,
    cleanup_exit_code, cleanup_observation_complete, create_lifetime_pipe,
    direct_mount_is_fallback, direct_mount_setup_outcome, directory_nonempty_or_unsafe,
    embedded_unshare_policy, enable_child_subreaper_with, environment_drop_caps_policy,
    exec_self_fd_with, executable_path_from_auxv, existing_target_action,
    extraction_cleanup_requires_descendant_visibility, failed_unshare_action,
    fallback_should_drop_capabilities, fast_hash_file, finish_application_spawn,
    finish_mount_namespace_outcome, format_mount_pid_record, fresh_mount_target, get_image,
    get_runtime, get_section_data, is_runtime_option, mount_only_requires_procfs_notice,
    namespace_diff_is_compatible, namespace_entry_outcome, open_optional_target_source,
    parse_mount_pid_record, parse_proc_stat_starttime, parse_requested_mapping,
    parse_reuse_check_delay, parse_unshare_cli_options, path_entry_present, plan_unshare,
    prepare_fresh_target_transition_with, proc_free_direct_reuse_allowed,
    proc_free_private_mount_requires_random_target, process_procfs_available_at,
    read_process_starttime, read_supervisor_value, read_validated_mount_pid_file,
    record_reusable_for_mapping, remove_runtime_separator, remove_tmp_dirs, requested_id_mapping,
    reuse_hash_material, reuse_unavailable_action, should_drop_capabilities,
    should_validate_direct_reuse_record, should_write_mount_pid_record, stale_removed_action,
    try_acquire_ofd_cleanup_lease, try_expire_mount_with,
    try_reuse_unshare_mount_point_for_mode_with,
    try_reuse_unshare_mount_point_for_mode_with_lock_hook, unshare_reuse_was_rejected,
    wait_for_all_children, wait_for_lifetime_end, write_mount_pid_file, write_supervisor_value,
    ApplicationState, CleanupExecution, CleanupWork, DirectMountSetupResult, ExistingTargetAction,
    ExpireMountOutcome, ExpireMountResult, FailedUnshareAction, FileIdentity, IdMapping,
    LifetimeLease, MountPidRecord, NamespaceEntryResult, NamespaceIdentities, NamespaceIdentity,
    NamespaceKind, NamespaceOutcome, ReuseUnavailableAction, Runtime, SelfExecutable,
    TargetDirectoryState, TryReuseResult, TryUnshareResult, UnshareCliOptions, UnsharePlan,
    ARG_PFX,
};
use crate::elf_layout::tests::{fixture, Endian};
use nix::libc;
use std::ffi::OsString;
use std::fs::File;
use std::os::fd::AsRawFd;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::process::Command;
use std::sync::Mutex;
use std::time::{Duration, Instant};

static ENV_LOCK: Mutex<()> = Mutex::new(());
static EXECUTABLE_FIXTURE_LOCK: Mutex<()> = Mutex::new(());

fn wait_child_with_timeout(
    child: &mut std::process::Child,
    timeout: Duration,
    label: &str,
) -> Result<std::process::ExitStatus, String> {
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status),
            Ok(None) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Ok(None) => {
                let kill_error = child.kill().err();
                let reap_result = child.wait();
                return Err(format!(
                    "timed out waiting for {label}; kill error: {kill_error:?}; reap result: {reap_result:?}"
                ));
            }
            Err(err) => return Err(format!("failed waiting for {label}: {err}")),
        }
    }
}

fn run_command_with_timeout(
    command: &mut Command,
    timeout: Duration,
    label: &str,
) -> Result<std::process::ExitStatus, String> {
    let mut child = command
        .spawn()
        .map_err(|err| format!("failed to spawn {label}: {err}"))?;
    wait_child_with_timeout(&mut child, timeout, label)
}

fn current_namespace_identities() -> NamespaceIdentities {
    let user = File::open("/proc/self/ns/user").unwrap();
    let mount = File::open("/proc/self/ns/mnt").unwrap();
    NamespaceIdentities {
        user: NamespaceIdentity::from_file(&user).unwrap(),
        mount: NamespaceIdentity::from_file(&mount).unwrap(),
    }
}

struct EnvGuard {
    key: String,
    previous: Option<OsString>,
}

impl EnvGuard {
    fn set(key: String, value: &std::path::Path) -> Self {
        let previous = std::env::var_os(&key);
        std::env::set_var(&key, value);
        Self { key, previous }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        if let Some(previous) = &self.previous {
            std::env::set_var(&self.key, previous);
        } else {
            std::env::remove_var(&self.key);
        }
    }
}

#[test]
fn self_executable_keeps_the_opened_inode_after_path_replacement() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("image");
    std::fs::write(&path, b"original").unwrap();

    let opened = std::fs::File::open(&path).unwrap();
    let executable = SelfExecutable::from_open_file(opened, path.clone()).unwrap();
    std::fs::rename(&path, dir.path().join("original-moved")).unwrap();
    std::fs::write(&path, b"replacement").unwrap();

    assert_eq!(executable.read_all().unwrap(), b"original");
    assert_eq!(executable.size, b"original".len() as u64);
    assert_ne!(
        FileIdentity::from_metadata(&std::fs::metadata(&path).unwrap()),
        executable.identity
    );
}

#[test]
fn empty_target_value_selects_the_running_executable() {
    assert!(open_optional_target_source("").unwrap().is_none());
}

#[test]
fn missing_target_value_preserves_the_running_executable_fallback() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("missing");

    assert!(open_optional_target_source(missing.to_str().unwrap())
        .unwrap()
        .is_none());
}

#[test]
fn target_source_opens_once_and_retains_the_selected_inode() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("target");
    std::fs::write(&target, b"selected").unwrap();

    let source = open_optional_target_source(target.to_str().unwrap())
        .unwrap()
        .unwrap();
    std::fs::rename(&target, dir.path().join("selected-moved")).unwrap();
    std::fs::write(&target, b"replacement").unwrap();

    assert_eq!(source.read_all().unwrap(), b"selected");
}

#[test]
fn existing_non_regular_target_is_rejected_instead_of_silently_falling_back() {
    let dir = tempfile::tempdir().unwrap();

    let error = open_optional_target_source(dir.path().to_str().unwrap())
        .err()
        .unwrap();

    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
}

#[test]
fn dangling_target_symlink_is_rejected_instead_of_treated_as_missing() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("target");
    std::os::unix::fs::symlink(dir.path().join("missing"), &target).unwrap();

    let error = open_optional_target_source(target.to_str().unwrap())
        .err()
        .unwrap();

    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
}

#[test]
fn fifo_target_is_rejected_without_waiting_for_a_writer() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("target.fifo");
    let target_c = std::ffi::CString::new(target.as_os_str().as_encoded_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(target_c.as_ptr(), 0o600) }, 0);
    let started = Instant::now();

    let error = open_optional_target_source(target.to_str().unwrap())
        .err()
        .unwrap();

    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
    assert!(started.elapsed() < Duration::from_secs(1));
}

#[test]
fn auxv_execfn_resolves_the_executable_independently_of_procfs() {
    let path = executable_path_from_auxv().unwrap();
    assert!(path.is_absolute());
    assert!(path.is_file());
}

#[test]
fn helper_source_selects_proc_fd_without_clearing_cloexec() {
    let mut bytes = fixture(Endian::Little);
    bytes[0x380..0x384].copy_from_slice(b"hsqs");
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("image");
    std::fs::write(&path, &bytes).unwrap();
    let executable = SelfExecutable::open_path(&path).unwrap();
    let image = get_image(&executable, 0x380).unwrap();

    let proc_root = tempfile::tempdir().unwrap();
    let proc_path = proc_root.path().join(image.file.as_raw_fd().to_string());
    std::os::unix::fs::symlink(
        format!("/proc/self/fd/{}", image.file.as_raw_fd()),
        &proc_path,
    )
    .unwrap();

    let source = image
        .helper_source_with_fd_roots(&[proc_root.path()])
        .unwrap();
    assert_eq!(source.path, proc_path);
    assert_eq!(source.inherited_fd, Some(image.file.as_raw_fd()));
    // Selecting the source must not mutate the shared fd: CLOEXEC stays set so
    // the parent never leaks the image descriptor into unrelated children.
    let flags = unsafe { libc::fcntl(image.file.as_raw_fd(), libc::F_GETFD) };
    assert_ne!(flags & libc::FD_CLOEXEC, 0);
}

#[test]
fn helper_source_uses_verified_pathname_after_descriptor_paths_fail() {
    let mut bytes = fixture(Endian::Little);
    bytes[0x380..0x384].copy_from_slice(b"hsqs");
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("image");
    std::fs::write(&path, &bytes).unwrap();
    let executable = SelfExecutable::open_path(&path).unwrap();
    let image = get_image(&executable, 0x380).unwrap();
    let empty_root = tempfile::tempdir().unwrap();

    let source = image
        .helper_source_with_fd_roots(&[empty_root.path()])
        .unwrap();
    assert_eq!(source.path, path);
    assert_eq!(source.inherited_fd, None);
}

#[test]
fn helper_source_refuses_replaced_pathname_after_descriptor_paths_fail() {
    let mut bytes = fixture(Endian::Little);
    bytes[0x380..0x384].copy_from_slice(b"hsqs");
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("image");
    std::fs::write(&path, &bytes).unwrap();
    let executable = SelfExecutable::open_path(&path).unwrap();
    let image = get_image(&executable, 0x380).unwrap();
    std::fs::rename(&path, dir.path().join("retained")).unwrap();
    std::fs::write(&path, &bytes).unwrap();
    let empty_root = tempfile::tempdir().unwrap();

    let err = image
        .helper_source_with_fd_roots(&[empty_root.path()])
        .unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    assert!(
        err.to_string()
            .contains("no longer refers to the retained inode"),
        "unexpected error: {err}"
    );
}

#[test]
fn helper_source_refuses_missing_pathname_after_descriptor_paths_fail() {
    let mut bytes = fixture(Endian::Little);
    bytes[0x380..0x384].copy_from_slice(b"hsqs");
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("image");
    std::fs::write(&path, &bytes).unwrap();
    let executable = SelfExecutable::open_path(&path).unwrap();
    let image = get_image(&executable, 0x380).unwrap();
    std::fs::remove_file(&path).unwrap();
    let empty_root = tempfile::tempdir().unwrap();

    let err = image
        .helper_source_with_fd_roots(&[empty_root.path()])
        .unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
    assert!(
        err.to_string().contains("cannot verify pathname fallback"),
        "unexpected error: {err}"
    );
}

#[test]
fn helper_source_prepare_for_exec_clears_cloexec() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("image");
    std::fs::write(&path, b"data").unwrap();
    let file = std::fs::File::open(&path).unwrap();
    let source = super::HelperSource {
        path: path.clone(),
        inherited_fd: Some(file.as_raw_fd()),
    };
    let before = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFD) };
    assert_ne!(before & libc::FD_CLOEXEC, 0);

    source.prepare_for_exec().unwrap();
    let after = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFD) };
    assert_eq!(after & libc::FD_CLOEXEC, 0);
}

#[test]
fn maintenance_write_refuses_a_replaced_target() {
    let _env_lock = ENV_LOCK.lock().unwrap();
    let bytes = fixture(Endian::Little);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("image");
    std::fs::write(&path, &bytes).unwrap();

    let metadata = std::fs::metadata(&path).unwrap();
    let runtime = Runtime {
        path: path.clone(),
        identity: FileIdentity::from_metadata(&metadata),
        size: 0,
        headers_bytes: bytes[..0x380].to_vec(),
        envs: String::new(),
    };
    let _target = EnvGuard::set(format!("TARGET_{}", super::ENV_NAME), &path);

    let moved = dir.path().join("image-moved");
    std::fs::rename(&path, &moved).unwrap();
    std::fs::write(&path, &bytes).unwrap();

    let err = add_section_data(
        &runtime,
        ".envs",
        &["--runtime-addenvs".into(), "X=2".into()],
    )
    .unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
}

#[test]
fn exec_pathname_fallback_refuses_a_replaced_inode() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("image");
    std::fs::write(&path, b"original").unwrap();
    let executable = SelfExecutable::open_path(&path).unwrap();
    std::fs::rename(&path, dir.path().join("retained")).unwrap();
    std::fs::write(&path, b"replacement").unwrap();
    let empty_root = tempfile::tempdir().unwrap();

    for errno in [libc::ENOSYS, libc::ENOTSUP, libc::EINVAL, libc::EPERM] {
        let err = exec_self_fd_with(&executable, &[], &[empty_root.path()], |_, _, _| {
            Err(std::io::Error::from_raw_os_error(errno))
        })
        .unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        assert!(
            err.to_string()
                .contains("no longer refers to the retained inode"),
            "unexpected error for errno {errno}: {err}"
        );
    }
}

#[test]
fn exec_pathname_fallback_refuses_a_missing_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("image");
    std::fs::write(&path, b"original").unwrap();
    let executable = SelfExecutable::open_path(&path).unwrap();
    std::fs::remove_file(&path).unwrap();
    let empty_root = tempfile::tempdir().unwrap();

    for errno in [libc::ENOSYS, libc::ENOTSUP, libc::EINVAL, libc::EPERM] {
        let err = exec_self_fd_with(&executable, &[], &[empty_root.path()], |_, _, _| {
            Err(std::io::Error::from_raw_os_error(errno))
        })
        .unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
        assert!(
            err.to_string().contains("cannot verify pathname fallback"),
            "unexpected error for errno {errno}: {err}"
        );
    }
}

#[test]
fn execveat_unexpected_success_is_returned_as_an_error() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("image");
    std::fs::write(&path, b"original").unwrap();
    let executable = SelfExecutable::open_path(&path).unwrap();

    let err = exec_self_fd_with(&executable, &[], &[], |_, _, _| Ok(())).unwrap_err();

    assert!(err
        .to_string()
        .contains("unexpectedly returned success without replacing the process"));
}

#[test]
fn repeated_descriptor_fallback_failures_preserve_cloexec_and_fd_count() {
    if std::env::var_os("URUNTIME_FD_COUNT_WORKER").is_none() {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "runtime_elf_tests::repeated_descriptor_fallback_failures_preserve_cloexec_and_fd_count",
                "--exact",
                "--nocapture",
            ])
            .env("URUNTIME_FD_COUNT_WORKER", "1");
        let status = run_command_with_timeout(
            &mut command,
            Duration::from_secs(10),
            "isolated FD-count worker",
        )
        .unwrap();
        assert!(
            status.success(),
            "isolated FD-count worker failed: {status}"
        );
        return;
    }

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("not-an-elf");
    std::fs::write(&path, b"not an executable image").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    let executable = SelfExecutable::open_path(&path).unwrap();
    let fd = executable.file.as_raw_fd();
    let initial_flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    assert_ne!(initial_flags, -1);
    assert_ne!(initial_flags & libc::FD_CLOEXEC, 0);
    let initial_fd_count = std::fs::read_dir("/proc/self/fd").unwrap().count();

    for _ in 0..32 {
        let error = exec_self_fd_with(
            &executable,
            &[],
            &[std::path::Path::new("/proc/self/fd")],
            |_, _, _| Err(std::io::Error::from_raw_os_error(libc::EPERM)),
        )
        .unwrap_err();
        assert!(matches!(error.raw_os_error(), Some(libc::ENOEXEC)));
    }

    let final_flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    assert_ne!(final_flags, -1);
    assert_ne!(final_flags & libc::FD_CLOEXEC, 0);
    assert_eq!(
        std::fs::read_dir("/proc/self/fd").unwrap().count(),
        initial_fd_count
    );
}

#[test]
fn exec_fallback_worker() {
    let Some(mode) = std::env::var_os("URUNTIME_EXEC_FALLBACK_WORKER") else {
        return;
    };

    let path = std::env::current_exe().unwrap();
    let executable = SelfExecutable::open_path(&path).unwrap();
    let empty_root = tempfile::tempdir().unwrap();
    let fd_roots: Vec<&std::path::Path> = if mode == "descriptor" {
        std::fs::rename(&path, path.with_extension("retained")).unwrap();
        std::fs::write(&path, b"replacement must not execute").unwrap();
        vec![
            std::path::Path::new("/proc/self/fd"),
            std::path::Path::new("/dev/fd"),
        ]
    } else {
        assert_eq!(mode, "pathname");
        vec![empty_root.path()]
    };
    std::env::set_var("URUNTIME_EXEC_FALLBACK_LANDING", "1");

    let injected_errno = std::env::var("URUNTIME_EXEC_FALLBACK_ERRNO")
        .ok()
        .and_then(|value| value.parse::<i32>().ok())
        .unwrap_or(libc::ENOSYS);
    if let Some(marker) = std::env::var_os("URUNTIME_QEMU_DESCRIPTOR_MARKER") {
        std::fs::write(
            marker,
            format!("{}:{injected_errno}", mode.to_string_lossy()),
        )
        .unwrap();
    }
    let err = exec_self_fd_with(
        &executable,
        &[
            "runtime_elf_tests::exec_fallback_landing".into(),
            "--exact".into(),
            "--nocapture".into(),
        ],
        &fd_roots,
        |_, _, _| Err(std::io::Error::from_raw_os_error(injected_errno)),
    )
    .unwrap_err();
    panic!("{mode:?} fallback failed: {err}");
}

#[test]
fn exec_fallback_landing() {
    if std::env::var_os("URUNTIME_EXEC_FALLBACK_LANDING").is_some() {
        assert_eq!(
            std::env::var("URUNTIME_EXEC_FALLBACK_LANDING").unwrap(),
            "1"
        );
    }
}

fn run_exec_fallback_worker(mode: &str, errno: i32) {
    let fixture_guard = EXECUTABLE_FIXTURE_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let dir = tempfile::tempdir().unwrap();
    let source = std::env::current_exe().unwrap();
    let executable = dir.path().join("fallback-test");
    let qemu_descriptor = mode == "descriptor"
        && std::env::var("URUNTIME_FOREIGN_TEST_RUNNER").as_deref() == Ok("qemu-user");
    let marker = dir.path().join("qemu-descriptor-attempted");
    std::fs::copy(&source, &executable).unwrap();
    std::fs::set_permissions(
        &executable,
        std::fs::metadata(&source).unwrap().permissions(),
    )
    .unwrap();

    let mut command = Command::new(&executable);
    command
        .args([
            "runtime_elf_tests::exec_fallback_worker",
            "--exact",
            "--nocapture",
        ])
        .env("URUNTIME_EXEC_FALLBACK_WORKER", mode)
        .env("URUNTIME_EXEC_FALLBACK_ERRNO", errno.to_string());
    if qemu_descriptor {
        command.env("URUNTIME_QEMU_DESCRIPTOR_MARKER", &marker);
    }
    let status = run_command_with_timeout(
        &mut command,
        Duration::from_secs(10),
        "exec fallback worker",
    )
    .unwrap();
    drop(fixture_guard);
    if qemu_descriptor {
        assert_eq!(
            std::fs::read_to_string(marker).unwrap(),
            format!("{mode}:{errno}")
        );
        if !status.success() {
            assert_eq!(status.code(), Some(1));
        }
        return;
    }
    assert!(
        status.success(),
        "{mode} fallback worker failed for errno {errno}: {status}"
    );
}

#[test]
fn exec_descriptor_path_fallback_reexecutes_retained_inode_after_path_replacement() {
    for errno in [libc::ENOSYS, libc::EPERM] {
        run_exec_fallback_worker("descriptor", errno);
    }
}

#[test]
fn exec_pathname_fallback_reexecutes_verified_inode() {
    for errno in [libc::ENOSYS, libc::EPERM] {
        run_exec_fallback_worker("pathname", errno);
    }
}

#[test]
fn embedded_unshare_modes_distinguish_explicit_and_fallback_capability_drop() {
    assert_eq!(embedded_unshare_policy("=0"), (false, false, false));
    assert_eq!(embedded_unshare_policy("=1"), (true, false, false));
    assert_eq!(embedded_unshare_policy("=2"), (true, true, false));
    assert_eq!(embedded_unshare_policy("=3"), (false, false, true));
    assert_eq!(embedded_unshare_policy("=invalid"), (false, false, false));
    assert_eq!(environment_drop_caps_policy("1"), (true, false, false));
    assert_eq!(environment_drop_caps_policy("2"), (true, true, false));
    assert_eq!(environment_drop_caps_policy("3"), (false, false, true));
    assert_eq!(
        environment_drop_caps_policy("invalid"),
        (false, false, false)
    );

    assert!(!fallback_should_drop_capabilities(false, true));
    assert!(fallback_should_drop_capabilities(true, true));
    assert!(!fallback_should_drop_capabilities(true, false));
    assert!(should_drop_capabilities(true, true));
    assert!(!should_drop_capabilities(false, true));
    assert!(!should_drop_capabilities(true, false));
}

#[test]
fn unshare_plan_without_procfs_prefers_mount_only_when_no_mapping_needed() {
    assert_eq!(
        plan_unshare(1000, 985, 1000, 985, false, false),
        UnsharePlan::MountOnly
    );
}

#[test]
fn unshare_plan_without_procfs_is_impossible_when_mapping_needed() {
    assert_eq!(
        plan_unshare(1000, 985, 0, 0, false, true),
        UnsharePlan::Impossible
    );
}

#[test]
fn unshare_plan_with_procfs_uses_user_and_mount() {
    assert_eq!(
        plan_unshare(1000, 985, 1000, 985, true, false),
        UnsharePlan::UserAndMount
    );
    assert_eq!(
        plan_unshare(1000, 985, 0, 0, true, true),
        UnsharePlan::UserAndMount
    );
}

#[test]
fn unshare_plan_implicit_target_matches_current_ids() {
    // Empty unshare_uid/unshare_gid values resolve to the current IDs, so no
    // mapping is required and MountOnly remains available without procfs.
    assert_eq!(
        plan_unshare(0, 0, 0, 0, false, false),
        UnsharePlan::MountOnly
    );
}

#[test]
fn explicit_same_id_mapping_without_procfs_is_impossible() {
    assert_eq!(
        plan_unshare(0, 0, 0, 0, false, true),
        UnsharePlan::Impossible
    );
}

#[test]
fn nonempty_mapping_fields_mark_mapping_as_requested() {
    assert!(requested_id_mapping(1000, 985, "0", "0"));
    assert!(requested_id_mapping(1000, 985, "1001", ""));
    assert!(requested_id_mapping(1000, 985, "", "986"));
}

#[test]
fn private_mount_path_warns_when_procfs_is_missing() {
    assert!(mount_only_requires_procfs_notice(true, false));
    assert!(!mount_only_requires_procfs_notice(true, true));
    assert!(!mount_only_requires_procfs_notice(false, false));
}

#[test]
fn no_procfs_with_cap_sys_admin_mounts_in_the_current_namespace() {
    assert!(can_mount_directly(1000, false, false, false, true, false));
}

#[test]
fn mount_only_without_procfs_requires_an_exportable_private_namespace() {
    assert!(!can_mount_directly(1000, false, false, false, true, true));
    assert!(!can_mount_directly(0, false, false, false, true, true));
    assert!(can_mount_directly(1000, true, false, false, true, true));
}

#[test]
fn mount_privatization_failure_is_irreversible_not_mount_only_success() {
    assert_eq!(
        finish_mount_namespace_outcome(NamespaceKind::MountOnly, false),
        TryUnshareResult::IrreversibleFailure
    );
    assert_eq!(
        finish_mount_namespace_outcome(NamespaceKind::MountOnly, true),
        TryUnshareResult::Created(NamespaceOutcome::unshared(NamespaceKind::MountOnly).unwrap())
    );
}

#[test]
fn successful_setns_with_failed_privatization_is_irreversible() {
    assert_eq!(
        namespace_entry_outcome(true, true, false),
        NamespaceEntryResult::IrreversibleFailure
    );
    assert_eq!(
        namespace_entry_outcome(true, true, true),
        NamespaceEntryResult::Entered
    );
}

#[test]
fn no_proc_direct_fuse_privatization_failure_is_not_ready_or_current() {
    assert_eq!(
        direct_mount_setup_outcome(None, false, true, false),
        DirectMountSetupResult::Unavailable
    );
}

#[test]
fn cap_sys_admin_does_not_bypass_normal_namespace_detection_with_procfs() {
    assert!(!can_mount_directly(1000, false, false, true, true, false));
    assert!(can_mount_directly(1000, false, true, true, false, false));
    assert!(can_mount_directly(0, false, false, true, false, false));
    assert!(can_mount_directly(1000, true, false, true, false, false));
}

#[test]
fn direct_mount_fallback_includes_root_inside_a_no_proc_sandbox() {
    assert!(direct_mount_is_fallback(false, false, true));
    assert!(!direct_mount_is_fallback(true, false, true));
    assert!(!direct_mount_is_fallback(false, true, true));
    assert!(!direct_mount_is_fallback(false, false, false));
}

#[test]
fn partial_user_namespace_setup_is_never_recoverable_by_mount_only_unshare() {
    assert_eq!(
        failed_unshare_action(true, false),
        FailedUnshareAction::Abort
    );
    assert_eq!(
        failed_unshare_action(true, true),
        FailedUnshareAction::Abort
    );
    assert_eq!(
        failed_unshare_action(false, false),
        FailedUnshareAction::TryMountOnly
    );
    assert_eq!(
        failed_unshare_action(false, true),
        FailedUnshareAction::ReturnFailure
    );
}

#[test]
fn pid_existence_works_without_procfs() {
    // Signal 0 is not delivered; it only checks whether the process exists.
    // Unlike /proc/{pid}, this also works without procfs.
    assert!(super::is_pid_exists(nix::unistd::getpid()));
    assert!(!super::is_pid_exists(nix::unistd::Pid::from_raw(
        1_000_000_000
    )));
}

#[test]
fn reusable_mount_hash_separates_explicit_mappings_and_preserves_implicit_key() {
    let root = IdMapping { uid: 0, gid: 0 };
    let user = IdMapping {
        uid: 1000,
        gid: 1000,
    };

    assert_eq!(reuse_hash_material(42, user, false), "42");
    assert_ne!(
        reuse_hash_material(42, root, true),
        reuse_hash_material(42, user, true)
    );
}

#[test]
fn reusable_mount_base_hash_wraps_without_panicking() {
    assert_eq!(base_hash(u64::from(u32::MAX), 1, 1), 1);
}

#[test]
fn reuse_check_delay_boundaries_default_instead_of_overflowing() {
    for (suffix, multiplier) in [('m', 60_u64), ('h', 3600_u64)] {
        let maximum = u64::MAX / multiplier;
        assert_eq!(
            parse_reuse_check_delay(&format!("{maximum}{suffix}")),
            Some(Duration::from_secs(maximum * multiplier))
        );
        assert_eq!(
            parse_reuse_check_delay(&format!("{}{suffix}", maximum + 1)),
            Some(Duration::from_secs(1))
        );
    }
}

#[test]
fn requested_mapping_rejects_invalid_explicit_values() {
    assert_eq!(
        parse_requested_mapping(1000, 985, "", "").unwrap(),
        IdMapping {
            uid: 1000,
            gid: 985,
        }
    );
    assert!(parse_requested_mapping(1000, 985, "not-a-uid", "985").is_err());
    assert!(parse_requested_mapping(1000, 985, "1000", "not-a-gid").is_err());
}

#[test]
fn implicit_record_without_mapping_is_not_trusted_for_reuse() {
    let legacy = parse_mount_pid_record("12345 user,mnt start=987654").unwrap();
    let requested = IdMapping {
        uid: 1000,
        gid: 985,
    };
    let exact = parse_mount_pid_record(
        "12345 v=2 user,mnt uid=1000 gid=985 start=987654 userns=4:100 mntns=4:200",
    )
    .unwrap();

    assert!(!record_reusable_for_mapping(&legacy, requested, false));
    assert!(record_reusable_for_mapping(&exact, requested, false));
}

#[test]
fn exact_recorded_mapping_is_reusable() {
    let record = parse_mount_pid_record(
        "12345 v=2 user,mnt uid=0 gid=0 start=987654 userns=4:100 mntns=4:200",
    )
    .unwrap();

    assert!(record_reusable_for_mapping(
        &record,
        IdMapping { uid: 0, gid: 0 },
        true
    ));
}

#[test]
fn explicit_mapping_rejects_current_namespace_record() {
    let current = parse_mount_pid_record(
        "12345 v=2 current uid=0 gid=0 start=987654 userns=4:100 mntns=4:200",
    )
    .unwrap();
    let unshared = parse_mount_pid_record(
        "12345 v=2 user,mnt uid=0 gid=0 start=987654 userns=4:100 mntns=4:200",
    )
    .unwrap();
    let requested = IdMapping { uid: 0, gid: 0 };

    assert!(!record_reusable_for_mapping(&current, requested, true));
    assert!(record_reusable_for_mapping(&unshared, requested, true));
}

#[test]
fn explicit_mapping_requires_user_and_mount_namespace_record() {
    let mount_only =
        parse_mount_pid_record("12345 v=2 mnt uid=0 gid=0 start=987654 userns=4:100 mntns=4:200")
            .unwrap();
    let user_and_mount = parse_mount_pid_record(
        "12345 v=2 user,mnt uid=0 gid=0 start=987654 userns=4:100 mntns=4:200",
    )
    .unwrap();
    let requested = IdMapping { uid: 0, gid: 0 };

    assert!(!record_reusable_for_mapping(&mount_only, requested, true));
    assert!(record_reusable_for_mapping(
        &user_and_mount,
        requested,
        true
    ));
}

#[test]
fn incomplete_legacy_record_is_not_reusable() {
    let record = parse_mount_pid_record("12345 user,mnt uid=0 gid=0").unwrap();

    assert!(!record_reusable_for_mapping(
        &record,
        IdMapping { uid: 0, gid: 0 },
        true
    ));
}

#[test]
fn proc_stat_starttime_parser_handles_spaces_and_parentheses_in_comm() {
    let stat =
        "123 (worker name ) with spaces) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 987654";

    assert_eq!(parse_proc_stat_starttime(stat), Some(987654));
    assert_eq!(parse_proc_stat_starttime("123 malformed"), None);
}

#[test]
fn recorded_namespace_kind_must_match_the_target_namespace_difference() {
    assert!(namespace_diff_is_compatible(NamespaceKind::Current, 0));
    assert!(!namespace_diff_is_compatible(
        NamespaceKind::Current,
        libc::CLONE_NEWNS
    ));
    assert!(namespace_diff_is_compatible(
        NamespaceKind::MountOnly,
        libc::CLONE_NEWNS
    ));
    assert!(!namespace_diff_is_compatible(
        NamespaceKind::MountOnly,
        libc::CLONE_NEWUSER | libc::CLONE_NEWNS
    ));
    assert!(namespace_diff_is_compatible(
        NamespaceKind::UserAndMount,
        libc::CLONE_NEWUSER | libc::CLONE_NEWNS
    ));
}

#[test]
fn trusted_namespace_record_roundtrips_concrete_identities() {
    let record = MountPidRecord {
        pid: nix::unistd::Pid::from_raw(12345),
        namespace_kind: Some(NamespaceKind::UserAndMount),
        mapping: Some(IdMapping { uid: 0, gid: 0 }),
        process_starttime: Some(987654),
        namespace_identities: Some(NamespaceIdentities {
            user: NamespaceIdentity {
                device: 4,
                inode: 100,
            },
            mount: NamespaceIdentity {
                device: 4,
                inode: 200,
            },
        }),
    };

    let serialized = format_mount_pid_record(&record);
    assert_eq!(
        serialized,
        "12345 v=2 user,mnt uid=0 gid=0 start=987654 userns=4:100 mntns=4:200"
    );
    assert_eq!(parse_mount_pid_record(&serialized), Some(record));
}

#[test]
fn trusted_namespace_record_rejects_missing_malformed_or_duplicate_identities() {
    for value in [
        "12345 v=2 uid=0 gid=0 start=1 userns=4:100 mntns=4:200",
        "12345 v=2 user,mnt gid=0 start=1 userns=4:100 mntns=4:200",
        "12345 v=2 user,mnt uid=0 gid=0 userns=4:100 mntns=4:200",
        "12345 v=2 user,mnt uid=0 gid=0 start=1 mntns=4:200",
        "12345 v=2 user,mnt uid=0 gid=0 start=1 userns=bad mntns=4:200",
        "12345 v=2 v=2 user,mnt uid=0 gid=0 start=1 userns=4:100 mntns=4:200",
        "12345 v=2 user,mnt uid=0 gid=0 start=1 userns=4:100 userns=4:100 mntns=4:200",
        "12345 v=2 user,mnt uid=0 gid=0 start=1 userns=4:100 mntns=4:200 mntns=4:200",
    ] {
        assert!(parse_mount_pid_record(value).is_none(), "accepted {value}");
    }
}

#[test]
fn legacy_namespace_record_remains_parseable_but_untrusted() {
    let legacy = parse_mount_pid_record("12345 user,mnt uid=0 gid=0 start=1").unwrap();

    assert_eq!(legacy.namespace_identities, None);
    assert!(!record_reusable_for_mapping(
        &legacy,
        IdMapping { uid: 0, gid: 0 },
        true
    ));
}

#[test]
fn unavailable_reuse_never_continues_on_the_same_target() {
    assert_eq!(
        reuse_unavailable_action(false),
        ReuseUnavailableAction::Fresh
    );

    assert_eq!(
        reuse_unavailable_action(true),
        ReuseUnavailableAction::Reject
    );
}

#[test]
fn fresh_automatic_target_does_not_collide_with_the_original_pid_record() {
    let dir = tempfile::tempdir().unwrap();
    let original = dir.path().join(".mount_testremp123");
    std::fs::write(original.with_extension("un.pid"), b"occupied").unwrap();

    let fresh = fresh_mount_target(&original).unwrap();

    assert_ne!(fresh, original);
    assert_ne!(
        fresh.with_extension("un.pid"),
        original.with_extension("un.pid")
    );
    assert!(fresh.is_dir());
    assert!(!fresh.with_extension("pid").exists());
    assert!(!fresh.with_extension("un.pid").exists());
}

#[test]
fn fresh_automatic_target_is_atomically_private_under_a_permissive_umask() {
    const WORKER: &str = "URUNTIME_FRESH_TARGET_UMASK_WORKER";
    if std::env::var_os(WORKER).is_none() {
        let status = Command::new(std::env::current_exe().unwrap())
            .args([
                "runtime_elf_tests::fresh_automatic_target_is_atomically_private_under_a_permissive_umask",
                "--exact",
                "--nocapture",
            ])
            .env(WORKER, "1")
            .status()
            .unwrap();
        assert!(status.success());
        return;
    }

    unsafe {
        libc::umask(0);
    }
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("mount");
    let fresh = fresh_mount_target(&target).unwrap();
    let metadata = std::fs::symlink_metadata(&fresh).unwrap();

    assert!(metadata.file_type().is_dir());
    assert_eq!(metadata.permissions().mode() & 0o777, 0o700);
}

#[test]
fn fresh_target_transition_replaces_exact_cleanup_entries_without_reordering_others() {
    let dir = tempfile::tempdir().unwrap();
    let old_target = dir.path().join("old-target");
    let fresh_target = dir.path().join("fresh-target");
    let before = dir.path().join("before");
    let after = dir.path().join("after");
    let cleanup = vec![
        before.clone(),
        old_target.clone(),
        after.clone(),
        old_target.clone(),
    ];

    let transition = prepare_fresh_target_transition_with(
        &old_target,
        &cleanup,
        false,
        |_| {
            std::fs::create_dir(&fresh_target)?;
            std::fs::set_permissions(&fresh_target, std::fs::Permissions::from_mode(0o700))?;
            Ok(fresh_target.clone())
        },
        |_| unreachable!("leasing is disabled"),
    )
    .unwrap();

    assert_eq!(transition.target, fresh_target);
    assert_eq!(
        transition.tmp_dirs,
        vec![before, fresh_target.clone(), after, fresh_target.clone(),]
    );
    assert!(transition.coordinator.is_none());
    assert!(transition.lease.is_none());
}

#[test]
fn failed_fresh_target_lease_does_not_publish_partial_transition_state() {
    let dir = tempfile::tempdir().unwrap();
    let old_target = dir.path().join("old-target");
    let fresh_target = dir.path().join("fresh-target");
    let cleanup = vec![old_target.clone()];

    let error = prepare_fresh_target_transition_with(
        &old_target,
        &cleanup,
        true,
        |_| {
            std::fs::create_dir(&fresh_target)?;
            std::fs::set_permissions(&fresh_target, std::fs::Permissions::from_mode(0o700))?;
            Ok(fresh_target.clone())
        },
        |_| Err(std::io::Error::other("injected fresh target lease failure")),
    )
    .err()
    .unwrap();

    assert_eq!(error.to_string(), "injected fresh target lease failure");
    assert_eq!(cleanup, vec![old_target]);
    assert!(!fresh_target.exists());
}

#[test]
fn failed_fresh_target_rollback_reports_the_primary_and_cleanup_errors() {
    let dir = tempfile::tempdir().unwrap();
    let old_target = dir.path().join("old-target");
    let fresh_target = dir.path().join("fresh-target");
    let injected_entry = fresh_target.join("injected");

    let error = prepare_fresh_target_transition_with(
        &old_target,
        std::slice::from_ref(&old_target),
        true,
        |_| {
            std::fs::create_dir(&fresh_target)?;
            std::fs::set_permissions(&fresh_target, std::fs::Permissions::from_mode(0o700))?;
            Ok(fresh_target.clone())
        },
        |_| {
            std::fs::write(&injected_entry, b"occupied")?;
            Err(std::io::Error::other("injected lease failure"))
        },
    )
    .err()
    .unwrap();

    let message = error.to_string();
    assert!(message.contains("injected lease failure"));
    assert!(message.contains("failed to roll back fresh target reservation"));
    assert!(fresh_target.is_dir());
    assert!(injected_entry.is_file());
}

#[test]
fn occupied_fresh_target_is_rejected_before_lease_acquisition() {
    let dir = tempfile::tempdir().unwrap();
    let old_target = dir.path().join("old-target");
    let fresh_target = dir.path().join("fresh-target");
    let lease_called = std::cell::Cell::new(false);

    let error = prepare_fresh_target_transition_with(
        &old_target,
        std::slice::from_ref(&old_target),
        true,
        |_| {
            std::fs::create_dir(&fresh_target)?;
            std::fs::set_permissions(&fresh_target, std::fs::Permissions::from_mode(0o700))?;
            std::fs::write(fresh_target.join("injected"), b"occupied")?;
            Ok(fresh_target.clone())
        },
        |_| {
            lease_called.set(true);
            unreachable!("occupied reservations must fail before lease acquisition")
        },
    )
    .err()
    .unwrap();

    assert!(!lease_called.get());
    assert!(error.to_string().contains("is not empty"));
    assert!(error
        .to_string()
        .contains("failed to roll back fresh target reservation"));
}

#[test]
fn dead_unshare_record_is_removed() {
    let dir = tempfile::tempdir().unwrap();
    let mount_point = dir.path().join("mount");
    let record_path = mount_point.with_extension("un.pid");
    let mapping = IdMapping {
        uid: unsafe { libc::getuid() },
        gid: unsafe { libc::getgid() },
    };
    let record = MountPidRecord {
        pid: nix::unistd::Pid::from_raw(1_000_000_000),
        namespace_kind: Some(NamespaceKind::MountOnly),
        mapping: Some(mapping),
        process_starttime: Some(1),
        namespace_identities: Some(current_namespace_identities()),
    };
    std::fs::write(&record_path, format_mount_pid_record(&record)).unwrap();

    let result = try_reuse_unshare_mount_point_for_mode_with(
        &mount_point,
        mapping,
        false,
        None,
        |_| false,
        |_, _, _, _| panic!("dead owner must not trigger namespace entry"),
    );

    assert_eq!(result, TryReuseResult::StaleRemoved);
    assert!(!record_path.exists());
}

#[test]
fn stale_removed_truth_table_distinguishes_automatic_and_fixed_targets() {
    assert_eq!(
        stale_removed_action(false, false),
        ReuseUnavailableAction::Continue
    );
    assert_eq!(
        stale_removed_action(false, true),
        ReuseUnavailableAction::Fresh
    );
    assert_eq!(
        stale_removed_action(true, false),
        ReuseUnavailableAction::Reject
    );
    assert_eq!(
        stale_removed_action(true, true),
        ReuseUnavailableAction::Reject
    );
    assert_eq!(
        existing_target_action(true, false, true, true, true, false),
        ExistingTargetAction::Reject
    );
}

#[test]
fn entered_namespace_with_missing_mount_is_rejected_not_freshened() {
    let dir = tempfile::tempdir().unwrap();
    let mount_point = dir.path().join("mount");
    let mapping = IdMapping {
        uid: unsafe { libc::getuid() },
        gid: unsafe { libc::getgid() },
    };
    let pid = nix::unistd::getpid();
    let record = MountPidRecord {
        pid,
        namespace_kind: Some(NamespaceKind::MountOnly),
        mapping: Some(mapping),
        process_starttime: read_process_starttime(pid),
        namespace_identities: Some(current_namespace_identities()),
    };
    std::fs::write(
        mount_point.with_extension("un.pid"),
        format_mount_pid_record(&record),
    )
    .unwrap();

    let result = try_reuse_unshare_mount_point_for_mode_with(
        &mount_point,
        mapping,
        false,
        None,
        |_| false,
        |_, _, _, _| NamespaceEntryResult::Entered,
    );

    assert_eq!(result, TryReuseResult::Rejected);
}

#[test]
fn mount_pid_record_roundtrips_mapping_and_process_generation() {
    let record = MountPidRecord {
        pid: nix::unistd::Pid::from_raw(12345),
        namespace_kind: Some(NamespaceKind::UserAndMount),
        mapping: Some(IdMapping { uid: 0, gid: 0 }),
        process_starttime: Some(987654),
        namespace_identities: None,
    };

    let serialized = format_mount_pid_record(&record);
    assert_eq!(parse_mount_pid_record(&serialized), Some(record));
}

#[test]
fn mount_pid_record_rejects_malformed_known_values_before_later_repair() {
    for value in [
        "12345 user,mnt uid=bad uid=1000 gid=985 start=1",
        "12345 user,mnt uid=1000 gid=bad gid=985 start=1",
        "12345 user,mnt uid=1000 gid=985 start=bad start=1",
        "12345 user,bad user,mnt uid=1000 gid=985 start=1",
    ] {
        assert!(parse_mount_pid_record(value).is_none(), "accepted {value}");
    }
}

#[test]
fn mount_pid_record_rejects_duplicate_known_fields() {
    for value in [
        "12345 user,mnt uid=1000 uid=1000 gid=985 start=1",
        "12345 user,mnt uid=1000 gid=985 gid=985 start=1",
        "12345 user,mnt uid=1000 gid=985 start=1 start=1",
        "12345 mnt user,mnt uid=1000 gid=985 start=1",
    ] {
        assert!(parse_mount_pid_record(value).is_none(), "accepted {value}");
    }
}

#[test]
fn trusted_mount_only_record_serializes_explicit_namespace_kind() {
    let record = MountPidRecord {
        pid: nix::unistd::Pid::from_raw(12345),
        namespace_kind: Some(NamespaceKind::MountOnly),
        mapping: Some(IdMapping {
            uid: 1000,
            gid: 985,
        }),
        process_starttime: Some(987654),
        namespace_identities: Some(NamespaceIdentities {
            user: NamespaceIdentity {
                device: 4,
                inode: 100,
            },
            mount: NamespaceIdentity {
                device: 4,
                inode: 200,
            },
        }),
    };

    assert_eq!(
        format_mount_pid_record(&record),
        "12345 v=2 mnt uid=1000 gid=985 start=987654 userns=4:100 mntns=4:200"
    );
}

#[test]
fn trusted_direct_pid_record_serializes_explicit_current_namespace_kind() {
    let record = MountPidRecord {
        pid: nix::unistd::Pid::from_raw(12345),
        namespace_kind: Some(NamespaceKind::Current),
        mapping: Some(IdMapping {
            uid: 1000,
            gid: 985,
        }),
        process_starttime: Some(987654),
        namespace_identities: Some(NamespaceIdentities {
            user: NamespaceIdentity {
                device: 4,
                inode: 100,
            },
            mount: NamespaceIdentity {
                device: 4,
                inode: 200,
            },
        }),
    };

    assert_eq!(
        format_mount_pid_record(&record),
        "12345 v=2 current uid=1000 gid=985 start=987654 userns=4:100 mntns=4:200"
    );
}

#[test]
fn writer_refuses_extended_record_without_process_generation() {
    let dir = tempfile::tempdir().unwrap();
    let mount_point = dir.path().join("mount");
    let impossible_pid = nix::unistd::Pid::from_raw(1_000_000_000);

    let error = write_mount_pid_file(
        &mount_point,
        impossible_pid,
        NamespaceOutcome::unshared(NamespaceKind::MountOnly).unwrap(),
        IdMapping { uid: 0, gid: 0 },
        None,
    )
    .unwrap_err();

    assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
    assert!(!mount_point.with_extension("un.pid").exists());
}

#[test]
fn record_publication_replaces_symlink_without_touching_its_target() {
    let dir = tempfile::tempdir().unwrap();
    let mount_point = dir.path().join("mount");
    let record_path = mount_point.with_extension("pid");
    let symlink_target = dir.path().join("victim");
    std::fs::write(&symlink_target, b"do not modify").unwrap();
    std::os::unix::fs::symlink(&symlink_target, &record_path).unwrap();
    let mapping = IdMapping {
        uid: unsafe { libc::getuid() },
        gid: unsafe { libc::getgid() },
    };

    write_mount_pid_file(
        &mount_point,
        nix::unistd::getpid(),
        NamespaceOutcome::current(false),
        mapping,
        None,
    )
    .unwrap();

    assert_eq!(std::fs::read(&symlink_target).unwrap(), b"do not modify");
    assert!(std::fs::symlink_metadata(&record_path)
        .unwrap()
        .file_type()
        .is_file());
    let published = std::fs::read_to_string(&record_path).unwrap();
    let parsed = parse_mount_pid_record(&published).unwrap();
    assert_eq!(parsed.pid, nix::unistd::getpid());
    assert_eq!(parsed.mapping, Some(mapping));
}

#[test]
fn atomic_record_publication_keeps_old_content_until_rename_then_installs_new_content() {
    let dir = tempfile::tempdir().unwrap();
    let record_path = dir.path().join("mount.pid");
    let old = b"old complete record".to_vec();
    let new = vec![b'n'; 512 * 1024];
    std::fs::write(&record_path, &old).unwrap();
    let ready = std::sync::Arc::new(std::sync::Barrier::new(2));
    let release = std::sync::Arc::new(std::sync::Barrier::new(2));
    let writer_path = record_path.clone();
    let writer_new = new.clone();
    let writer_ready = ready.clone();
    let writer_release = release.clone();

    let writer = std::thread::spawn(move || {
        atomic_publish_file_with(
            &writer_path.with_extension(""),
            &writer_path,
            None,
            &writer_new,
            |_| {
                writer_ready.wait();
                writer_release.wait();
                Ok(())
            },
        )
    });
    ready.wait();
    assert_eq!(std::fs::read(&record_path).unwrap(), old);
    release.wait();
    writer.join().unwrap().unwrap();
    assert_eq!(std::fs::read(&record_path).unwrap(), new);
    let entries: Vec<_> = std::fs::read_dir(dir.path())
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    assert_eq!(entries.len(), 2);
    assert!(entries.contains(&record_path.file_name().unwrap().to_os_string()));
    assert!(entries.contains(&std::ffi::OsString::from("mount.lock")));
}

#[test]
fn target_coordination_and_record_publication_share_one_lock_inode() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("mount");
    let record_path = target.with_extension("pid");

    let (_coordinator, lease) = acquire_target_usage_lease(&target).unwrap();
    atomic_publish_file_with(
        &target,
        &record_path,
        Some(&lease),
        b"complete record",
        |_| Ok(()),
    )
    .unwrap();

    let mut entries: Vec<_> = std::fs::read_dir(dir.path())
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    entries.sort();
    assert_eq!(
        entries,
        [
            std::ffi::OsString::from("mount.lock"),
            std::ffi::OsString::from("mount.pid"),
        ]
    );
}

#[test]
fn atomic_record_publication_cleans_temporary_file_after_failure() {
    let dir = tempfile::tempdir().unwrap();
    let record_path = dir.path().join("mount.pid");
    std::fs::write(&record_path, b"old record").unwrap();

    let error = atomic_publish_file_with(
        &record_path.with_extension(""),
        &record_path,
        None,
        b"new record",
        |_| Err(std::io::Error::other("induced publication failure")),
    )
    .unwrap_err();

    assert_eq!(error.kind(), std::io::ErrorKind::Other);
    assert_eq!(std::fs::read(&record_path).unwrap(), b"old record");
    let entries: Vec<_> = std::fs::read_dir(dir.path())
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    assert_eq!(entries.len(), 2);
    assert!(entries.contains(&record_path.file_name().unwrap().to_os_string()));
    assert!(entries.contains(&std::ffi::OsString::from("mount.lock")));
}

#[test]
fn atomic_record_publication_scavenges_only_exact_orphan_temporary_entries() {
    let dir = tempfile::tempdir().unwrap();
    let record_path = dir.path().join("mount.pid");
    let orphan = dir.path().join("mount.pid.tmp.123.abcdefghijkl");
    let orphan_symlink = dir.path().join("mount.pid.tmp.456.ABCDEFGHIJKL");
    let victim = dir.path().join("victim");
    let lookalikes = [
        dir.path().join("mount.pid.tmp.123.abcdefghijk"),
        dir.path().join("mount.pid.tmp.x.abcdefghijkl"),
        dir.path().join("mount.pid.tmp.123.abcdefghijk!"),
        dir.path().join("other.pid.tmp.123.abcdefghijkl"),
    ];
    let unrelated_symlink = dir.path().join("mount.pid.tmp.1234.abcdefghijkl.extra");

    std::fs::write(&record_path, b"old record").unwrap();
    std::fs::write(&orphan, b"aborted publication").unwrap();
    std::fs::write(&victim, b"do not touch").unwrap();
    std::os::unix::fs::symlink(&victim, &orphan_symlink).unwrap();
    for lookalike in &lookalikes {
        std::fs::write(lookalike, b"unrelated").unwrap();
    }
    std::os::unix::fs::symlink(&victim, &unrelated_symlink).unwrap();

    atomic_publish_file_with(
        &record_path.with_extension(""),
        &record_path,
        None,
        b"new record",
        |_| Ok(()),
    )
    .unwrap();

    assert_eq!(std::fs::read(&record_path).unwrap(), b"new record");
    assert!(!orphan.exists());
    assert!(std::fs::symlink_metadata(&orphan_symlink).is_err());
    assert_eq!(std::fs::read(&victim).unwrap(), b"do not touch");
    for lookalike in &lookalikes {
        assert!(std::fs::symlink_metadata(lookalike).is_ok());
    }
    assert!(std::fs::symlink_metadata(&unrelated_symlink).is_ok());
}

#[test]
fn stale_removal_serializes_with_record_publication() {
    let dir = tempfile::tempdir().unwrap();
    let mount_point = dir.path().join("mount");
    let record_path = mount_point.with_extension("un.pid");
    let mapping = IdMapping {
        uid: unsafe { libc::getuid() },
        gid: unsafe { libc::getgid() },
    };
    let stale = MountPidRecord {
        pid: nix::unistd::Pid::from_raw(1_000_000_000),
        namespace_kind: Some(NamespaceKind::MountOnly),
        mapping: Some(mapping),
        process_starttime: Some(1),
        namespace_identities: Some(current_namespace_identities()),
    };
    std::fs::write(&record_path, format_mount_pid_record(&stale)).unwrap();
    let acquired = std::sync::Arc::new(std::sync::Barrier::new(2));
    let release = std::sync::Arc::new(std::sync::Barrier::new(2));
    let remover_mount = mount_point.clone();
    let remover_acquired = acquired.clone();
    let remover_release = release.clone();
    let remover = std::thread::spawn(move || {
        try_reuse_unshare_mount_point_for_mode_with_lock_hook(
            &remover_mount,
            mapping,
            false,
            None,
            || {
                remover_acquired.wait();
                remover_release.wait();
            },
            |_| false,
            |_, _, _, _| panic!("dead owner must not trigger namespace entry"),
        )
    });
    acquired.wait();

    let new_record = b"new complete record".to_vec();
    let publisher_path = record_path.clone();
    let publisher_target = mount_point.clone();
    let publisher_content = new_record.clone();
    let (started_tx, started_rx) = std::sync::mpsc::channel();
    let (published_tx, published_rx) = std::sync::mpsc::channel();
    let publisher = std::thread::spawn(move || {
        started_tx.send(()).unwrap();
        let result = atomic_publish_file_with(
            &publisher_target,
            &publisher_path,
            None,
            &publisher_content,
            |_| Ok(()),
        );
        published_tx.send(()).unwrap();
        result
    });
    started_rx.recv().unwrap();
    assert!(published_rx
        .recv_timeout(Duration::from_millis(100))
        .is_err());

    release.wait();
    assert_eq!(remover.join().unwrap(), TryReuseResult::StaleRemoved);
    publisher.join().unwrap().unwrap();
    assert_eq!(std::fs::read(&record_path).unwrap(), new_record);
}

#[test]
fn record_lock_symlink_attack_is_rejected_without_touching_target() {
    let dir = tempfile::tempdir().unwrap();
    let record_path = dir.path().join("mount.pid");
    let lock_path = dir.path().join("mount.lock");
    let victim = dir.path().join("victim");
    std::fs::write(&record_path, b"old record").unwrap();
    std::fs::write(&victim, b"do not touch").unwrap();
    std::os::unix::fs::symlink(&victim, &lock_path).unwrap();

    let error = atomic_publish_file_with(
        &record_path.with_extension(""),
        &record_path,
        None,
        b"new record",
        |_| Ok(()),
    )
    .unwrap_err();

    assert!(matches!(
        error.raw_os_error(),
        Some(libc::ELOOP) | Some(libc::EINVAL)
    ));
    assert_eq!(std::fs::read(&record_path).unwrap(), b"old record");
    assert_eq!(std::fs::read(&victim).unwrap(), b"do not touch");
    let entries: Vec<_> = std::fs::read_dir(dir.path())
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    assert_eq!(entries.len(), 3);
}

#[test]
fn rejected_unshare_reuse_is_not_reaccepted_by_existing_target_policy() {
    assert_eq!(
        existing_target_action(true, true, true, true, true, false),
        ExistingTargetAction::Reject
    );
}

#[test]
fn dangling_unshare_pid_symlink_is_present_for_rejection() {
    let dir = tempfile::tempdir().unwrap();
    let mount_point = dir.path().join("mount");
    let unshare_pid = mount_point.with_extension("un.pid");
    std::os::unix::fs::symlink(dir.path().join("missing-record"), &unshare_pid).unwrap();

    assert!(path_entry_present(&unshare_pid));
}

#[test]
fn rejected_unshare_record_is_sticky_for_nonpersistent_requested_isolation() {
    assert!(unshare_reuse_was_rejected(true, false, true));
    assert_eq!(
        existing_target_action(false, true, true, true, true, true),
        ExistingTargetAction::Reject
    );
    assert_eq!(
        existing_target_action(false, true, true, false, false, false),
        ExistingTargetAction::Reject
    );
}

#[test]
fn rejected_unshare_record_is_sticky_for_empty_persistent_target() {
    assert_eq!(
        existing_target_action(true, false, true, false, false, false),
        ExistingTargetAction::Reject
    );
}

#[test]
fn unvalidated_persistent_mount_is_rejected_instead_of_remounted() {
    assert_eq!(
        existing_target_action(true, true, false, true, true, false),
        ExistingTargetAction::Reject
    );
}

#[test]
fn automatic_visible_mount_can_be_reused_without_procfs_or_pid_records() {
    assert!(proc_free_direct_reuse_allowed(
        true, true, false, false, false, false, true
    ));
}

#[test]
fn proc_free_direct_reuse_rejects_fixed_mapped_private_recorded_or_unmounted_targets() {
    let baseline = [true, true, false, false, false, false, true];
    for index in [1_usize, 2, 3, 4, 5, 6] {
        let mut values = baseline;
        values[index] = !values[index];
        assert!(
            !proc_free_direct_reuse_allowed(
                values[0], values[1], values[2], values[3], values[4], values[5], values[6]
            ),
            "condition {index} must prevent proc-free direct reuse"
        );
    }
}

#[test]
fn proc_free_private_mount_reuse_switches_to_random_target() {
    assert!(proc_free_private_mount_requires_random_target(
        true, false, false, true, true
    ));
    assert!(proc_free_private_mount_requires_random_target(
        true, false, false, false, false
    ));
    assert!(!proc_free_private_mount_requires_random_target(
        true, false, false, false, true
    ));
    assert!(!proc_free_private_mount_requires_random_target(
        true, true, false, true, false
    ));
    assert!(!proc_free_private_mount_requires_random_target(
        false, false, false, true, false
    ));
}

#[test]
fn proc_free_direct_mount_does_not_publish_an_unverifiable_pid_record() {
    assert!(!should_write_mount_pid_record(
        true,
        Some(NamespaceKind::Current),
        false,
        true,
        false
    ));
    assert!(should_write_mount_pid_record(
        true,
        Some(NamespaceKind::Current),
        true,
        true,
        false
    ));
    assert!(should_write_mount_pid_record(
        true,
        Some(NamespaceKind::MountOnly),
        false,
        true,
        false
    ));
}

#[test]
fn unmounted_nonempty_persistent_target_rejects_any_pid_record_state() {
    for direct_record_valid in [false, true] {
        assert_eq!(
            existing_target_action(true, false, false, false, true, direct_record_valid,),
            ExistingTargetAction::Reject
        );
    }
}

#[test]
fn dangling_entry_makes_persistent_target_nonempty() {
    let dir = tempfile::tempdir().unwrap();
    std::os::unix::fs::symlink(dir.path().join("missing"), dir.path().join("dangling")).unwrap();

    assert!(directory_nonempty_or_unsafe(dir.path(), true));
}

#[test]
fn missing_persistent_target_is_safe_for_fresh_creation() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("missing-target");
    let nonempty = directory_nonempty_or_unsafe(&missing, true);

    assert!(!nonempty);
    assert_eq!(
        existing_target_action(true, false, false, false, nonempty, false),
        ExistingTargetAction::Create
    );
}

#[test]
fn target_directory_classifier_treats_only_not_found_as_empty() {
    use std::io::ErrorKind::{NotFound, Other, PermissionDenied};

    assert_eq!(
        classify_target_directory(Err(NotFound)),
        TargetDirectoryState::Empty
    );
    assert_eq!(
        classify_target_directory(Err(PermissionDenied)),
        TargetDirectoryState::Unsafe
    );
    assert_eq!(
        classify_target_directory(Err(Other)),
        TargetDirectoryState::Unsafe
    );
    assert_eq!(
        classify_target_directory(Ok(false)),
        TargetDirectoryState::Empty
    );
    assert_eq!(
        classify_target_directory(Ok(true)),
        TargetDirectoryState::Nonempty
    );
}

#[test]
fn persistent_pid_record_is_validated_while_target_is_unmounted() {
    assert!(should_validate_direct_reuse_record(
        true, false, false, false
    ));
}

#[test]
fn explicit_mapping_rejects_unvalidated_nonpersistent_mount() {
    assert_eq!(
        existing_target_action(false, true, false, true, true, false),
        ExistingTargetAction::Reject
    );
}

#[test]
fn validated_explicit_mapping_mount_is_accepted() {
    assert_eq!(
        existing_target_action(false, true, false, true, true, true),
        ExistingTargetAction::Reuse
    );
}

#[test]
fn nonpersistent_visible_unshare_mount_still_requires_namespace_entry() {
    let dir = tempfile::tempdir().unwrap();
    let mount_point = dir.path().join("mount");
    let mapping = IdMapping {
        uid: unsafe { libc::getuid() },
        gid: unsafe { libc::getgid() },
    };
    let pid = nix::unistd::getpid();
    let process_starttime = read_process_starttime(pid);
    let namespace_identities = current_namespace_identities();
    let record = MountPidRecord {
        pid,
        namespace_kind: Some(NamespaceKind::UserAndMount),
        mapping: Some(mapping),
        process_starttime,
        namespace_identities: Some(namespace_identities),
    };
    std::fs::write(
        mount_point.with_extension("un.pid"),
        format_mount_pid_record(&record),
    )
    .unwrap();
    let namespace_entry_attempted = std::cell::Cell::new(false);

    let reused = try_reuse_unshare_mount_point_for_mode_with(
        &mount_point,
        mapping,
        false,
        None,
        |_| true,
        |actual_pid, actual_kind, actual_starttime, actual_identities| {
            assert_eq!(actual_pid, pid);
            assert_eq!(actual_kind, NamespaceKind::UserAndMount);
            assert_eq!(actual_starttime, process_starttime);
            assert_eq!(actual_identities, Some(namespace_identities));
            namespace_entry_attempted.set(true);
            NamespaceEntryResult::Unavailable
        },
    );

    assert!(namespace_entry_attempted.get());
    assert_eq!(reused, TryReuseResult::Unavailable);
    assert_eq!(
        existing_target_action(false, false, true, true, true, false),
        ExistingTargetAction::Reject
    );
}

#[test]
fn irreversible_namespace_entry_failure_cannot_fall_back_to_fresh_mount() {
    let dir = tempfile::tempdir().unwrap();
    let mount_point = dir.path().join("mount");
    let mapping = IdMapping {
        uid: unsafe { libc::getuid() },
        gid: unsafe { libc::getgid() },
    };
    let pid = nix::unistd::getpid();
    let process_starttime = read_process_starttime(pid);
    let namespace_identities = current_namespace_identities();
    let record = MountPidRecord {
        pid,
        namespace_kind: Some(NamespaceKind::MountOnly),
        mapping: Some(mapping),
        process_starttime,
        namespace_identities: Some(namespace_identities),
    };
    std::fs::write(
        mount_point.with_extension("un.pid"),
        format_mount_pid_record(&record),
    )
    .unwrap();

    let reused = try_reuse_unshare_mount_point_for_mode_with(
        &mount_point,
        mapping,
        false,
        None,
        |_| true,
        |actual_pid, actual_kind, actual_starttime, actual_identities| {
            assert_eq!(actual_pid, pid);
            assert_eq!(actual_kind, NamespaceKind::MountOnly);
            assert_eq!(actual_starttime, process_starttime);
            assert_eq!(actual_identities, Some(namespace_identities));
            NamespaceEntryResult::IrreversibleFailure
        },
    );

    assert_eq!(reused, TryReuseResult::IrreversibleFailure);
}

#[test]
fn ordinary_nonreusable_target_keeps_existing_directory_behavior() {
    assert_eq!(
        existing_target_action(false, false, false, false, true, false),
        ExistingTargetAction::Reuse
    );
}

#[test]
fn validated_record_reads_do_not_scan_or_mutate_the_parent_directory() {
    let dir = tempfile::tempdir().unwrap();
    let mount_point = dir.path().join("mount");
    let mapping = IdMapping {
        uid: unsafe { libc::getuid() },
        gid: unsafe { libc::getgid() },
    };
    let pid = nix::unistd::getpid();
    write_mount_pid_file(
        &mount_point,
        pid,
        NamespaceOutcome::current(false),
        mapping,
        None,
    )
    .unwrap();
    let orphan = dir.path().join("mount.pid.tmp.123.abcdefghijkl");
    std::fs::write(&orphan, b"aborted publication").unwrap();

    assert_eq!(
        read_validated_mount_pid_file(&mount_point, "pid", mapping, false, None)
            .map(|record| record.pid),
        Some(pid)
    );
    assert!(orphan.is_file());
}

#[test]
fn direct_pid_record_is_only_reusable_for_implicit_mapping() {
    let dir = tempfile::tempdir().unwrap();
    let mount_point = dir.path().join("mount");
    let mapping = IdMapping {
        uid: 1000,
        gid: 985,
    };
    let pid = nix::unistd::getpid();
    write_mount_pid_file(
        &mount_point,
        pid,
        NamespaceOutcome::current(false),
        mapping,
        None,
    )
    .unwrap();

    assert!(read_validated_mount_pid_file(&mount_point, "pid", mapping, true, None).is_none());
    assert_eq!(
        read_validated_mount_pid_file(&mount_point, "pid", mapping, false, None)
            .map(|record| record.pid),
        Some(pid)
    );
    assert!(read_validated_mount_pid_file(
        &mount_point,
        "pid",
        IdMapping { uid: 0, gid: 0 },
        true,
        None,
    )
    .is_none());

    std::fs::write(
        mount_point.with_extension("pid"),
        format!("{} uid=1000 gid=985", pid.as_raw()),
    )
    .unwrap();
    assert!(read_validated_mount_pid_file(&mount_point, "pid", mapping, true, None).is_none());
}

#[test]
fn mount_pid_records_remain_backward_compatible() {
    let legacy = parse_mount_pid_record("12345").unwrap();
    assert_eq!(legacy.pid.as_raw(), 12345);
    assert_eq!(legacy.namespace_kind, None);

    let mount_only = parse_mount_pid_record("12345 mnt").unwrap();
    assert_eq!(mount_only.pid.as_raw(), 12345);
    assert_eq!(mount_only.namespace_kind, Some(NamespaceKind::MountOnly));

    let user_and_mount = parse_mount_pid_record("12345 user,mnt").unwrap();
    assert_eq!(
        user_and_mount.namespace_kind,
        Some(NamespaceKind::UserAndMount)
    );

    assert!(parse_mount_pid_record("12345 unknown").is_none());
    assert!(parse_mount_pid_record("not-a-pid mnt").is_none());
    assert!(parse_mount_pid_record("0 mnt").is_none());
    assert!(parse_mount_pid_record("-1 mnt").is_none());
}

#[test]
fn expire_mount_errors_degrade_to_safe_fallbacks() {
    assert_eq!(
        classify_expire_mount_error(nix::errno::Errno::EAGAIN),
        ExpireMountResult::Marked
    );
    assert_eq!(
        classify_expire_mount_error(nix::errno::Errno::EBUSY),
        ExpireMountResult::Busy
    );
    for error in [
        nix::errno::Errno::EINVAL,
        nix::errno::Errno::ENOSYS,
        nix::errno::Errno::EOPNOTSUPP,
    ] {
        assert_eq!(
            classify_expire_mount_error(error),
            ExpireMountResult::Unsupported
        );
    }
    assert_eq!(
        classify_expire_mount_error(nix::errno::Errno::EPERM),
        ExpireMountResult::Failed
    );
}

#[test]
fn renewed_expiry_access_restarts_wait_instead_of_falling_back_to_unmount() {
    let mut results = std::collections::VecDeque::from([
        ExpireMountResult::Marked,
        ExpireMountResult::Marked,
        ExpireMountResult::Unmounted,
    ]);
    let waits = std::cell::Cell::new(0_u32);

    let outcome = try_expire_mount_with(
        Duration::from_millis(1),
        || results.pop_front().unwrap_or(ExpireMountResult::Failed),
        |_| waits.set(waits.get().saturating_add(1)),
    );

    assert_eq!(outcome, ExpireMountOutcome::Unmounted);
    assert_eq!(waits.get(), 2);
    assert!(results.is_empty());
}

#[test]
fn unsupported_expiry_uses_regular_unmount_but_busy_or_failed_mounts_are_retained() {
    for result in [ExpireMountResult::Busy, ExpireMountResult::Failed] {
        assert_eq!(
            try_expire_mount_with(Duration::ZERO, || result, |_| {}),
            ExpireMountOutcome::Retained
        );
    }
    assert_eq!(
        try_expire_mount_with(Duration::ZERO, || ExpireMountResult::Unsupported, |_| {}),
        ExpireMountOutcome::FallbackUnmount
    );
}

#[test]
fn process_procfs_detection_rejects_an_empty_proc_directory() {
    let root = tempfile::tempdir().unwrap();
    assert!(!process_procfs_available_at(root.path()));

    std::fs::create_dir(root.path().join("self")).unwrap();
    std::fs::write(root.path().join("self/stat"), b"fixture").unwrap();
    assert!(process_procfs_available_at(root.path()));
}

#[test]
fn supervisor_status_pipe_roundtrips_pid_and_exit_code() {
    let (reader, writer) = create_lifetime_pipe().unwrap();
    write_supervisor_value(writer.as_raw_fd(), 4242).unwrap();
    write_supervisor_value(writer.as_raw_fd(), 17).unwrap();
    drop(writer);
    assert_eq!(
        read_supervisor_value(reader.as_raw_fd()).unwrap(),
        Some(4242)
    );
    assert_eq!(read_supervisor_value(reader.as_raw_fd()).unwrap(), Some(17));
    assert_eq!(read_supervisor_value(reader.as_raw_fd()).unwrap(), None);
}

#[test]
fn child_subreaper_waits_for_a_reparented_background_descendant() {
    if std::env::var_os("URUNTIME_FOREIGN_TEST_RUNNER").is_some() {
        eprintln!(
            "NOT RUN live child-subreaper reparenting under qemu-user: PR_SET_CHILD_SUBREAPER is not a reliable linux-user contract"
        );
        return;
    }
    if std::env::var_os("URUNTIME_SUBREAPER_WORKER").is_none() {
        let status = Command::new(std::env::current_exe().unwrap())
            .args([
                "runtime_elf_tests::child_subreaper_waits_for_a_reparented_background_descendant",
                "--exact",
                "--nocapture",
            ])
            .env("URUNTIME_SUBREAPER_WORKER", "1")
            .status()
            .unwrap();
        assert!(status.success());
        return;
    }

    assert!(super::enable_child_subreaper().unwrap());
    let started = Instant::now();
    let mut shell = Command::new("/bin/sh")
        .args(["-c", "sleep 0.2 &"])
        .spawn()
        .unwrap();
    assert!(shell.wait().unwrap().success());
    wait_for_all_children().unwrap();
    assert!(started.elapsed() >= Duration::from_millis(150));
}

#[test]
fn application_supervisor_is_limited_to_extracted_runs() {
    assert!(application_supervisor_required(true));
    assert!(!application_supervisor_required(false));
}

#[test]
fn old_kernel_cleanup_uses_procfs_or_fails_safe_without_visibility() {
    assert!(cleanup_observation_complete(true, false));
    assert!(cleanup_observation_complete(false, true));
    assert!(!cleanup_observation_complete(false, false));

    assert!(extraction_cleanup_requires_descendant_visibility(
        ApplicationState::Started,
        true,
        false
    ));
    assert!(!extraction_cleanup_requires_descendant_visibility(
        ApplicationState::Started,
        false,
        false
    ));
    assert!(!extraction_cleanup_requires_descendant_visibility(
        ApplicationState::NeverStarted,
        true,
        false
    ));
    assert!(!extraction_cleanup_requires_descendant_visibility(
        ApplicationState::Started,
        true,
        true
    ));
}

#[test]
fn old_kernel_or_seccomp_subreaper_errors_degrade_without_failing_launch() {
    assert!(enable_child_subreaper_with(|| Ok(())).unwrap());
    for errno in [libc::EINVAL, libc::ENOSYS, libc::EPERM, libc::EACCES] {
        let result = enable_child_subreaper_with(|| Err(std::io::Error::from_raw_os_error(errno)));
        assert!(!result.unwrap());
    }
    let unexpected =
        enable_child_subreaper_with(|| Err(std::io::Error::from_raw_os_error(libc::EIO)));
    assert_eq!(unexpected.unwrap_err().raw_os_error(), Some(libc::EIO));
}

#[test]
fn lifetime_coordinator_rejects_group_or_other_permissions() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("image");
    let coordinator = dir.path().join("image.lock");
    std::fs::write(&coordinator, b"").unwrap();
    std::fs::set_permissions(&coordinator, std::fs::Permissions::from_mode(0o644)).unwrap();

    let error = match acquire_target_usage_lease(&target) {
        Ok(_) => panic!("insecure lifetime coordinator was accepted"),
        Err(error) => error,
    };

    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    assert_eq!(
        std::fs::metadata(&coordinator)
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o644
    );
}

#[test]
fn unsupported_ofd_errors_select_the_legacy_lock_backend() {
    for errno in [libc::EINVAL, libc::ENOSYS, libc::EOPNOTSUPP] {
        assert_eq!(
            classify_ofd_lock_error(errno, true),
            Some(super::OfdLockResult::Unsupported)
        );
    }
    assert_eq!(classify_ofd_lock_error(libc::EACCES, true), None);
    assert_eq!(classify_ofd_lock_error(libc::EPERM, true), None);
    assert_eq!(
        classify_ofd_lock_error(libc::EAGAIN, false),
        Some(super::OfdLockResult::Busy)
    );
    assert_eq!(classify_ofd_lock_error(libc::EIO, true), None);
}

#[test]
fn legacy_flock_treats_only_lock_contention_as_busy() {
    assert!(super::legacy_flock_would_block(libc::EWOULDBLOCK));
    assert!(super::legacy_flock_would_block(libc::EAGAIN));
    assert!(!super::legacy_flock_would_block(libc::EACCES));
    assert!(!super::legacy_flock_would_block(libc::EPERM));
}

#[test]
fn legacy_lock_backend_retains_shared_and_exclusive_lifetime_semantics() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("image");
    let (coordinator, shared) = acquire_legacy_target_usage_lease(&target).unwrap();
    drop(coordinator);

    assert!(target.with_extension("lease").is_file());
    assert!(dir.path().join("image.lease.lock").is_file());
    assert!(
        super::LifetimeLease::acquire_legacy(&target, libc::LOCK_EX | libc::LOCK_NB)
            .unwrap()
            .is_none()
    );
    drop(shared);
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        if super::LifetimeLease::acquire_legacy(&target, libc::LOCK_EX | libc::LOCK_NB)
            .unwrap()
            .is_some()
        {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "legacy shared lease remained locked after inherited CLOEXEC descriptors should have closed"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn lifetime_lease_prepare_for_exec_preserves_the_shared_lock() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("image");
    let (coordinator, lease) = acquire_target_usage_lease(&target).unwrap();
    drop(coordinator);
    let before = unsafe { libc::fcntl(lease.as_raw_fd(), libc::F_GETFD) };
    assert_ne!(before & libc::FD_CLOEXEC, 0);
    LifetimeLease::prepare_fd_for_exec(lease.as_raw_fd()).unwrap();
    let after = unsafe { libc::fcntl(lease.as_raw_fd(), libc::F_GETFD) };
    assert_eq!(after & libc::FD_CLOEXEC, 0);
}

#[test]
fn lifetime_lease_nonblocking_cleanup_reports_active_users() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("image");
    let (coordinator, shared) = acquire_target_usage_lease(&target).unwrap();
    drop(coordinator);
    assert!(try_acquire_ofd_cleanup_lease(&target)
        .unwrap()
        .expect("host kernel must support OFD locks")
        .is_none());
    drop(shared);
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        if try_acquire_ofd_cleanup_lease(&target)
            .unwrap()
            .expect("host kernel must support OFD locks")
            .is_some()
        {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "shared OFD lease remained locked after inherited CLOEXEC descriptors should have closed"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn target_usage_lease_rejects_lock_inode_replacement_after_coordinator_acquisition() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("image");
    let lock_path = super::target_lock_path(&target);
    let displaced = dir.path().join("displaced.lock");

    let error = super::acquire_target_usage_lease_with_hook(&target, |_| {
        std::fs::rename(&lock_path, &displaced)?;
        std::fs::write(&lock_path, b"")?;
        std::fs::set_permissions(&lock_path, std::fs::Permissions::from_mode(0o600))?;
        Ok(())
    })
    .err()
    .unwrap();

    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    assert!(error.to_string().contains("changed while locking"));
}

#[test]
fn target_usage_lease_rejects_permission_change_after_coordinator_acquisition() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("image");

    let error = super::acquire_target_usage_lease_with_hook(&target, |lock_path| {
        std::fs::set_permissions(lock_path, std::fs::Permissions::from_mode(0o660))?;
        Ok(())
    })
    .err()
    .unwrap();

    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    assert!(error.to_string().contains("is not a private owner file"));
}

#[test]
fn inherited_ofd_lifetime_descriptor_keeps_the_shared_lock_after_parent_drop() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("image");
    let (coordinator, shared) = acquire_target_usage_lease(&target).unwrap();
    drop(coordinator);
    let inherited = match &shared {
        LifetimeLease::Ofd(lock) => lock.file.try_clone().unwrap(),
        LifetimeLease::Legacy(_) => panic!("host kernel must support OFD locks"),
    };

    drop(shared);
    assert!(try_acquire_ofd_cleanup_lease(&target)
        .unwrap()
        .expect("host kernel must support OFD locks")
        .is_none());

    drop(inherited);
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        if try_acquire_ofd_cleanup_lease(&target)
            .unwrap()
            .expect("host kernel must support OFD locks")
            .is_some()
        {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "inherited OFD lifetime descriptor remained open after its final local copy closed"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn dropping_one_ofd_range_releases_it_while_the_lifetime_range_stays_held() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("image");
    let record_path = target.with_extension("pid");
    let (coordinator, lifetime) = acquire_target_usage_lease(&target).unwrap();

    drop(coordinator);
    let (next_coordinator, next_lifetime) = acquire_target_usage_lease(&target).unwrap();
    drop(next_coordinator);
    drop(next_lifetime);

    let record = super::RecordLock::acquire(&target, &record_path, Some(&lifetime)).unwrap();
    drop(record);

    let lock_path = super::target_lock_path(&target);
    let (probe, _) = super::open_private_owner_file(&lock_path, "target lock").unwrap();
    assert_eq!(
        super::set_ofd_range_lock(
            &probe,
            libc::F_WRLCK as libc::c_short,
            super::RECORD_LOCK_RANGE,
            false,
        )
        .unwrap(),
        super::OfdLockResult::Acquired
    );
    assert_eq!(
        super::set_ofd_range_lock(
            &probe,
            libc::F_UNLCK as libc::c_short,
            super::RECORD_LOCK_RANGE,
            false,
        )
        .unwrap(),
        super::OfdLockResult::Acquired
    );

    assert!(try_acquire_ofd_cleanup_lease(&target)
        .unwrap()
        .expect("host kernel must support OFD locks")
        .is_none());
}

#[test]
fn lifetime_pipe_reaches_eof_only_after_every_writer_closes() {
    let (reader, writer) = create_lifetime_pipe().unwrap();
    let inherited_writer = unsafe { libc::dup(writer.as_raw_fd()) };
    assert!(inherited_writer >= 0);
    drop(writer);

    let (done_tx, done_rx) = std::sync::mpsc::channel();
    let waiter = std::thread::spawn(move || {
        let result = wait_for_lifetime_end(reader);
        let _ = done_tx.send(result);
    });
    assert!(done_rx.recv_timeout(Duration::from_millis(20)).is_err());

    assert_eq!(unsafe { libc::close(inherited_writer) }, 0);
    assert!(done_rx
        .recv_timeout(Duration::from_secs(1))
        .expect("lifetime EOF wait hung")
        .is_ok());
    waiter.join().unwrap();
}

#[test]
fn lifetime_writer_survives_exec_and_tracks_a_background_descendant() {
    let (reader, writer) = create_lifetime_pipe().unwrap();
    let mut command = Command::new("/bin/sh");
    command.args(["-c", "sleep 0.15 &"]);
    let writer_fd = writer.as_raw_fd();
    unsafe {
        command.pre_exec(move || super::clear_fd_cloexec(writer_fd));
    }

    let started = Instant::now();
    let mut child = command.spawn().unwrap();
    drop(writer);
    assert!(
        wait_child_with_timeout(&mut child, Duration::from_secs(2), "lifetime exec shell",)
            .unwrap()
            .success()
    );
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    let waiter = std::thread::spawn(move || {
        let result = wait_for_lifetime_end(reader);
        let _ = done_tx.send(result);
    });
    assert!(done_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("background-descendant lifetime wait hung")
        .is_ok());
    waiter.join().unwrap();
    assert!(started.elapsed() >= Duration::from_millis(100));
}

#[test]
fn application_spawn_failure_preserves_reader_and_reaches_eof_for_cleanup() {
    let (reader, writer) = create_lifetime_pipe().unwrap();
    let induced = std::io::Error::new(
        std::io::ErrorKind::PermissionDenied,
        "induced spawn failure",
    );

    let (state, result, lifetime_reader) =
        finish_application_spawn::<()>(Err(induced), Some((reader, writer)));

    assert_eq!(state, ApplicationState::NeverStarted);
    assert_eq!(
        result.unwrap_err().kind(),
        std::io::ErrorKind::PermissionDenied
    );
    let lifetime_reader = lifetime_reader.expect("spawn failure must retain the cleanup reader");
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = done_tx.send(wait_for_lifetime_end(lifetime_reader));
    });
    assert!(done_rx
        .recv_timeout(Duration::from_secs(1))
        .expect("cleanup lifetime wait hung")
        .is_ok());
}

#[test]
fn application_state_selects_inline_failure_cleanup_without_changing_reuse_semantics() {
    assert_eq!(
        CleanupExecution::for_application(ApplicationState::NeverStarted, false),
        CleanupExecution::Inline
    );
    assert_eq!(
        CleanupExecution::for_application(ApplicationState::Started, false),
        CleanupExecution::Detached
    );
    assert_eq!(
        CleanupExecution::for_application(ApplicationState::NeverStarted, true),
        CleanupExecution::Skip
    );
    assert_eq!(
        CleanupExecution::for_application(ApplicationState::Started, true),
        CleanupExecution::Skip
    );
}

#[test]
fn application_spawn_failure_forces_immediate_cleanup_work() {
    assert_eq!(
        super::cleanup_work_for_application(ApplicationState::NeverStarted, false, true),
        CleanupWork::ImmediateMount
    );
    assert_eq!(
        super::cleanup_work_for_application(ApplicationState::NeverStarted, true, false),
        CleanupWork::ImmediateExtraction
    );
    assert_eq!(
        super::cleanup_work_for_application(ApplicationState::Started, false, true),
        CleanupWork::Normal
    );
    assert_eq!(cleanup_exit_code(CleanupExecution::Inline, 1), 1);
    assert_eq!(cleanup_exit_code(CleanupExecution::Detached, 1), 0);
}

#[test]
fn failed_launch_cleanup_removes_pid_record_and_temporary_directories() {
    let root = tempfile::tempdir().unwrap();
    let parent = root.path().join("parent");
    let mount = parent.join("mount");
    std::fs::create_dir_all(&mount).unwrap();
    let pid_record = mount.with_extension("pid");
    std::fs::write(&pid_record, b"stale launch record").unwrap();

    remove_tmp_dirs(&[mount.clone(), parent.clone()], false);

    assert!(!pid_record.exists());
    assert!(!mount.exists());
    assert!(!parent.exists());
}

#[test]
fn runtime_option_matching_is_exact_and_accepts_universal_prefix() {
    let valid = format!("--{ARG_PFX}-version");
    let unshare = format!("--{ARG_PFX}-unshare");
    let extra = format!("--{ARG_PFX}-version-extra");
    assert!(is_runtime_option(&valid, "version"));
    assert!(is_runtime_option(&unshare, "unshare"));
    assert!(is_runtime_option("--uruntime-version", "version"));
    assert!(is_runtime_option("--uruntime-unshare", "unshare"));
    assert!(!is_runtime_option("--uruntime-version-extra", "version"));
    assert!(!is_runtime_option("--other-version", "version"));
    assert!(!is_runtime_option(&extra, "version"));
    assert!(!is_runtime_option("runtime-version", "version"));
    assert!(!is_runtime_option("uruntime-version", "version"));
}

#[test]
fn unshare_cli_options_are_composable_and_removed_before_application_launch() {
    let mut args = vec![
        "--appimage-unshare-uid".into(),
        "1000".into(),
        "--appimage-unshare-gid=1001".into(),
        "--appimage-unshare-drop-caps".into(),
        "--application-option".into(),
    ];
    let options = parse_unshare_cli_options(&mut args, "appimage").unwrap();
    assert!(options.enable);
    assert!(options.drop_caps);
    assert!(!options.drop_caps_on_fallback);
    assert_eq!(options.uid.as_deref(), Some("1000"));
    assert_eq!(options.gid.as_deref(), Some("1001"));
    assert_eq!(args, ["--application-option"]);

    let mut args = vec![
        "--runtime-unshare-root".into(),
        "--runtime-unshare-drop-caps".into(),
    ];
    let options = parse_unshare_cli_options(&mut args, "runtime").unwrap();
    assert!(options.root && options.enable && options.drop_caps);
    assert!(args.is_empty());

    let mut args = vec![
        "--uruntime-unshare-uid=2000".into(),
        "--uruntime-unshare-gid".into(),
        "2001".into(),
        "--uruntime-unshare-drop-caps".into(),
        "--application-option".into(),
    ];
    let options = parse_unshare_cli_options(&mut args, "appimage").unwrap();
    assert!(options.enable && options.drop_caps);
    assert_eq!(options.uid.as_deref(), Some("2000"));
    assert_eq!(options.gid.as_deref(), Some("2001"));
    assert_eq!(args, ["--application-option"]);
}

#[test]
fn unshare_parser_moves_retained_argument_storage_instead_of_cloning_it() {
    let retained = "x".repeat(4096);
    let retained_pointer = retained.as_ptr();
    let mut args = vec!["--appimage-unshare".into(), retained];

    parse_unshare_cli_options(&mut args, "appimage").unwrap();

    assert_eq!(args.len(), 1);
    assert_eq!(args[0].as_ptr(), retained_pointer);
}

#[test]
fn runtime_separator_survives_parsing_but_is_removed_before_application_launch() {
    let mut args = vec![
        "--appimage-unshare".into(),
        "--".into(),
        "--appimage-version".into(),
    ];
    let options = parse_unshare_cli_options(&mut args, "appimage").unwrap();
    assert!(options.enable);
    assert_eq!(args, ["--", "--appimage-version"]);

    // A fallback re-exec parses the same argv again; the separator must still
    // protect application arguments until the final application launch.
    assert_eq!(
        parse_unshare_cli_options(&mut args, "appimage").unwrap(),
        UnshareCliOptions::default()
    );
    assert_eq!(args, ["--", "--appimage-version"]);

    remove_runtime_separator(&mut args);
    assert_eq!(args, ["--appimage-version"]);
}

#[test]
fn fallback_only_unshare_cli_mode_combines_with_explicit_unshare_by_prioritizing_drop() {
    let mut args = vec!["--appimage-unshare-fallback-drop-caps".into()];
    let options = parse_unshare_cli_options(&mut args, "appimage").unwrap();
    assert!(!options.enable);
    assert!(options.drop_caps_on_fallback);

    let mut args = vec![
        "--appimage-unshare".into(),
        "--appimage-unshare-fallback-drop-caps".into(),
    ];
    let options = parse_unshare_cli_options(&mut args, "appimage").unwrap();
    assert!(options.enable && options.drop_caps);
    assert!(!options.drop_caps_on_fallback);

    let mut args = vec![
        "--appimage-unshare-root".into(),
        "--appimage-unshare-uid=1000".into(),
        "--appimage-unshare-gid=1001".into(),
    ];
    let options = parse_unshare_cli_options(&mut args, "appimage").unwrap();
    assert!(options.root && options.enable);
    assert_eq!(options.uid.as_deref(), Some("1000"));
    assert_eq!(options.gid.as_deref(), Some("1001"));

    for mut args in [
        vec!["--appimage-unshare-uid".into()],
        vec!["--appimage-unshare-gid=not-a-number".into()],
    ] {
        let original = args.clone();
        assert!(parse_unshare_cli_options(&mut args, "appimage").is_err());
        assert_eq!(args, original);
    }

    let mut ordinary_args = vec!["--application-option".into(), "value".into()];
    let original = ordinary_args.clone();
    assert_eq!(
        parse_unshare_cli_options(&mut ordinary_args, "appimage").unwrap(),
        UnshareCliOptions::default()
    );
    assert_eq!(ordinary_args, original);
}

#[test]
fn runtime_boundary_points_to_squashfs_and_dwarfs_magic() {
    for endian in [Endian::Little, Endian::Big] {
        for magic in [b"hsqs", b"DWAR"] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join(format!(
                "image-{}-{}",
                if matches!(endian, Endian::Big) {
                    "be"
                } else {
                    "le"
                },
                if magic == b"hsqs" { "sqfs" } else { "dwar" }
            ));
            let mut bytes = fixture(endian);
            bytes.resize(0x380 + 96, 0x5a);
            bytes[0x380..0x384].copy_from_slice(magic);
            std::fs::write(&path, &bytes).unwrap();

            let executable = SelfExecutable::open_path(&path).unwrap();
            let original_hash = fast_hash_file(&executable.file, executable.size, 0x380).unwrap();
            let moved = dir.path().join(format!(
                "image-moved-{}-{}",
                if matches!(endian, Endian::Big) {
                    "be"
                } else {
                    "le"
                },
                if magic == b"hsqs" { "sqfs" } else { "dwar" }
            ));
            std::fs::rename(&path, &moved).unwrap();
            std::fs::write(&path, vec![0xa5; bytes.len()]).unwrap();

            let runtime = get_runtime(&executable).unwrap();

            assert_eq!(runtime.size, 0x380);
            assert_eq!(runtime.headers_bytes.len(), 0x380);
            assert_eq!(runtime.envs, "VALUE=1");
            assert_eq!(
                get_section_data(&runtime.headers_bytes, ".envs").unwrap(),
                "VALUE=1"
            );
            let image = get_image(&executable, runtime.size).unwrap();
            assert_eq!(image.is_squash, magic == b"hsqs");
            assert_eq!(image.is_dwar, magic == b"DWAR");
            assert_eq!(
                fast_hash_file(&image.file, executable.size, image.offset).unwrap(),
                original_hash
            );

            let missing_proc = dir.path().join(format!(
                "no-proc-fd-{}-{}",
                if matches!(endian, Endian::Big) {
                    "be"
                } else {
                    "le"
                },
                if magic == b"hsqs" { "sqfs" } else { "dwar" }
            ));
            assert!(image.helper_path_with_fd_roots(&[&missing_proc]).is_err());
        }
    }
}
