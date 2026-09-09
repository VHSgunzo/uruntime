use super::*;
use std::collections::HashSet;

#[test]
fn declarative_matrix_has_six_arches_and_54_unique_tasks() {
    assert_eq!(ARCHES.len(), 6);
    assert_eq!(VARIANTS.len(), 9);
    let tasks = all_tasks();
    assert_eq!(tasks.len(), 54);
    assert_eq!(tasks.iter().collect::<HashSet<_>>().len(), 54);
}

#[test]
fn architecture_contract_includes_correct_powerpc_endian_targets() {
    assert_eq!(
        arch_by_name("x86_64").unwrap().rust_target,
        "x86_64-unknown-linux-musl"
    );
    assert_eq!(
        arch_by_name("riscv64").unwrap().rust_target,
        "riscv64gc-unknown-linux-musl"
    );
    assert_eq!(
        arch_by_name("ppc64").unwrap().rust_target,
        "powerpc64-unknown-linux-musl"
    );
    assert_eq!(arch_by_name("ppc64").unwrap().endian, Endian::Big);
    assert_eq!(
        arch_by_name("ppc64le").unwrap().rust_target,
        "powerpc64le-unknown-linux-musl"
    );
    assert_eq!(arch_by_name("ppc64le").unwrap().endian, Endian::Little);
}

#[test]
fn matrix_contains_runimage_filesystem_only_tasks_and_public_output_names() {
    let tasks = all_tasks();
    assert!(tasks
        .iter()
        .any(|task| task.name == "runimage-squashfs-loongarch64"));
    assert!(tasks
        .iter()
        .any(|task| task.name == "runimage-dwarfs-ppc64"));
    assert!(tasks
        .iter()
        .any(|task| task.output_name() == "uruntime-appimage-dwarfs-lite-ppc64le"));
}

#[test]
fn variants_produce_exact_single_feature_argument() {
    let cases = [
        ("runimage", false, None),
        ("runimage-squashfs", true, Some("squashfs")),
        ("runimage-dwarfs", true, Some("dwarfs")),
        ("appimage", false, Some("appimage")),
        ("appimage-lite", false, Some("appimage,lite")),
        ("appimage-squashfs", true, Some("appimage,squashfs")),
        (
            "appimage-squashfs-lite",
            true,
            Some("appimage,squashfs,lite"),
        ),
        ("appimage-dwarfs", true, Some("appimage,dwarfs")),
        ("appimage-dwarfs-lite", true, Some("appimage,dwarfs,lite")),
    ];
    for (name, no_default, features) in cases {
        let variant = VARIANTS
            .iter()
            .find(|variant| variant.name == name)
            .unwrap();
        assert_eq!(variant.no_default_features, no_default, "{name}");
        assert_eq!(variant.features_arg().as_deref(), features, "{name}");
        let args = cargo_build_args(arch_by_name("x86_64").unwrap(), variant);
        assert!(args.iter().any(|arg| arg == "--locked"), "{name}");
        assert_eq!(
            args.iter()
                .filter(|arg| arg.as_str() == "--features")
                .count(),
            usize::from(features.is_some()),
            "{name}"
        );
    }
}

#[test]
fn cli_selects_exact_arch_and_all_and_rejects_unknown_or_extra_args() {
    assert_eq!(
        select_tasks(&["appimage-squashfs-riscv64"]).unwrap().len(),
        1
    );
    assert_eq!(select_tasks(&["riscv64"]).unwrap().len(), 9);
    assert_eq!(select_tasks(&["all"]).unwrap().len(), 54);
    let unknown = select_tasks(&["not-a-task"]).unwrap_err();
    assert!(unknown.contains("unknown task `not-a-task`"));
    assert!(unknown.contains("cargo xtask help"));
    let extra = select_tasks(&["x86_64", "--upx"]).unwrap_err();
    assert!(extra.contains("unexpected extra argument `--upx`"));
    assert!(extra.contains("UPX is not supported"));
}

#[test]
fn check_command_defaults_to_the_current_platform_musl_target() {
    assert_eq!(
        default_check_target("linux", "x86_64", false).unwrap(),
        "x86_64-unknown-linux-musl"
    );
    assert_eq!(
        default_check_target("linux", "aarch64", false).unwrap(),
        "aarch64-unknown-linux-musl"
    );
    assert_eq!(
        default_check_target("linux", "powerpc64", false).unwrap(),
        "powerpc64-unknown-linux-musl"
    );
    assert_eq!(
        default_check_target("linux", "powerpc64", true).unwrap(),
        "powerpc64le-unknown-linux-musl"
    );
    assert!(default_check_target("windows", "x86_64", false).is_err());
}

#[test]
fn check_command_contains_all_local_quality_gates() {
    let commands = check_commands("x86_64-unknown-linux-musl");
    assert_eq!(commands.len(), 7);
    let rendered = commands
        .iter()
        .map(|command| command.join(" "))
        .collect::<Vec<_>>()
        .join("\n");
    for required in [
        "fmt --check",
        "check --locked --workspace --all-features --target x86_64-unknown-linux-musl",
        "clippy --locked --workspace --all-features --all-targets --target x86_64-unknown-linux-musl -- -D warnings",
        "test --locked --workspace --all-features --target x86_64-unknown-linux-musl",
        "check --locked --manifest-path xtask/Cargo.toml",
        "clippy --locked --manifest-path xtask/Cargo.toml --all-targets -- -D warnings",
        "test --locked --manifest-path xtask/Cargo.toml",
    ] {
        assert!(rendered.contains(required), "missing `{required}` in:\n{rendered}");
    }
}

#[test]
fn foreign_check_runners_match_every_supported_architecture() {
    for (target, expected) in [
        ("aarch64-unknown-linux-musl", "qemu-aarch64"),
        ("riscv64gc-unknown-linux-musl", "qemu-riscv64"),
        ("loongarch64-unknown-linux-musl", "qemu-loongarch64"),
        ("powerpc64-unknown-linux-musl", "qemu-ppc64"),
        ("powerpc64le-unknown-linux-musl", "qemu-ppc64le"),
    ] {
        let arch = ARCHES.iter().find(|arch| arch.rust_target == target).unwrap();
        assert_eq!(qemu_runner_names(arch)[0], expected);
    }
}

#[test]
fn help_is_generated_from_the_same_tables() {
    let help = help_text();
    for task in all_tasks() {
        assert!(help.contains(&task.name), "missing {}", task.name);
    }
    assert!(help.contains("Tasks (54):"));
    assert!(help.contains("cargo xtask check [RUST_TARGET]"));
    assert!(help.contains("cargo xtask update-checksums [--check]"));
}

#[test]
fn backend_is_cargo_for_native_arch_and_zig_for_every_foreign_arch() {
    for arch in ARCHES {
        let expected = if arch.artifact_name == "x86_64" {
            Backend::Cargo
        } else {
            Backend::Zig
        };
        assert_eq!(backend_for(&arch, "x86_64"), expected);
    }
    assert_eq!(
        backend_for(arch_by_name("x86_64").unwrap(), "aarch64"),
        Backend::Zig
    );
}

#[test]
fn release_builds_always_use_the_pinned_zig_linker() {
    assert_eq!(build_backend(), Backend::Zig);
}

#[test]
fn zig_bootstrap_is_version_and_sha256_pinned_for_supported_linux_hosts() {
    let expected = [
        ("x86_64", "x86_64-linux"),
        ("aarch64", "aarch64-linux"),
        ("riscv64", "riscv64-linux"),
        ("loongarch64", "loongarch64-linux"),
    ];
    for (arch, platform) in expected {
        let package = zig_package("linux", arch).unwrap();
        assert_eq!(package.platform, platform);
        assert_eq!(package.sha256.len(), 64);
        assert!(package.sha256.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert_eq!(package.url, zig_download_url(platform));
    }
    assert!(zig_package("windows", "x86_64").is_err());
    assert!(zig_package("linux", "unsupported").is_err());
}

#[cfg(unix)]
#[test]
fn relative_program_overrides_are_resolved_against_the_intended_working_directory() {
    use std::os::unix::fs::PermissionsExt;

    let root = test_dir("relative-program");
    fs::create_dir_all(&root).unwrap();
    let program = root.join("zig-local");
    fs::write(&program, "#!/bin/sh\nexit 0\n").unwrap();
    fs::set_permissions(&program, fs::Permissions::from_mode(0o755)).unwrap();

    assert_eq!(
        resolve_program(Path::new("./zig-local"), &root).unwrap(),
        program
    );
    fs::remove_dir_all(root).unwrap();
}

#[cfg(unix)]
#[test]
fn rust_sysroot_is_queried_with_the_selected_compiler_from_project_root() {
    use std::os::unix::fs::PermissionsExt;

    let root = test_dir("rust-sysroot");
    fs::create_dir_all(&root).unwrap();
    let compiler = root.join("custom-rustc");
    fs::write(
        &compiler,
        "#!/bin/sh\ntest \"$1 $2\" = '--print sysroot' || exit 2\nprintf '/fixture/sysroot\\n'\n",
    )
    .unwrap();
    fs::set_permissions(&compiler, fs::Permissions::from_mode(0o755)).unwrap();

    assert_eq!(
        query_rust_sysroot(&root, OsStr::new("./custom-rustc")).unwrap(),
        "/fixture/sysroot"
    );
    fs::remove_dir_all(root).unwrap();
}

#[cfg(unix)]
#[test]
fn zig_wrapper_maps_all_targets_and_filters_rust_gnu_only_link_args() {
    use std::os::unix::fs::PermissionsExt;

    let root = test_dir("zig-wrapper");
    fs::create_dir_all(&root).unwrap();
    let fake_zig = root.join("fake-zig.sh");
    fs::write(
        &fake_zig,
        "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$FAKE_ZIG_LOG\"\n",
    )
    .unwrap();
    fs::set_permissions(&fake_zig, fs::Permissions::from_mode(0o755)).unwrap();
    let wrapper = project_root().join("scripts/zig-linker.sh");
    let rust_sysroot = root.join("rust-sysroot");

    for arch in ARCHES {
        let log = root.join(format!("{}.log", arch.artifact_name));
        let status = Command::new(&wrapper)
            .env("URUNTIME_ZIG", &fake_zig)
            .env("URUNTIME_RUST_TARGET", arch.rust_target)
            .env("URUNTIME_ZIG_TARGET", arch.zig_target)
            .env("URUNTIME_RUST_SYSROOT", &rust_sysroot)
            .env("FAKE_ZIG_LOG", &log)
            .args([
                format!("--target={}", arch.rust_target),
                "-Wl,--fix-cortex-a53-843419".into(),
                "-nostartfiles".into(),
                rust_sysroot
                    .join("lib/rustlib")
                    .join(arch.rust_target)
                    .join("lib/self-contained/crt1.o")
                    .display()
                    .to_string(),
                "-lc".into(),
                "-L".into(),
                rust_sysroot
                    .join("lib/rustlib")
                    .join(arch.rust_target)
                    .join("lib")
                    .display()
                    .to_string(),
                "-Lkeep-me".into(),
                "/checkout/self-contained/keep.o".into(),
                "-Wl,--wrap=contains--fix-cortex-a53-843419-text".into(),
            ])
            .status()
            .unwrap();
        assert!(status.success(), "{}", arch.artifact_name);
        let actual = fs::read_to_string(log).unwrap();
        assert!(actual.starts_with(&format!("cc\n-target\n{}\n", arch.zig_target)));
        assert!(actual.contains("-Lkeep-me\n"));
        assert!(!actual.contains(
            rust_sysroot
                .join("lib/rustlib")
                .join(arch.rust_target)
                .join("lib")
                .to_string_lossy()
                .as_ref()
        ));
        assert!(actual.contains("/checkout/self-contained/keep.o\n"));
        assert!(actual.contains("-Wl,--wrap=contains--fix-cortex-a53-843419-text\n"));
        assert!(!actual
            .lines()
            .any(|line| line == "-Wl,--fix-cortex-a53-843419"));
        for forbidden in ["unknown-linux", "nostartfiles", "crt1.o", "-lc\n"] {
            assert!(
                !actual.contains(forbidden),
                "{forbidden} leaked for {}: {actual}",
                arch.artifact_name
            );
        }
    }
    fs::remove_dir_all(root).unwrap();
}

#[cfg(unix)]
#[test]
fn artifact_publish_preserves_cargo_output_and_adds_sections_and_magic_atomically() {
    use std::os::unix::fs::PermissionsExt;

    let root = test_dir("publish");
    let sections = root.join("sections");
    fs::create_dir_all(&sections).unwrap();
    fs::write(sections.join("envs"), b"test-envs").unwrap();
    fs::write(sections.join("upd_info"), b"test-update").unwrap();
    let source = env::current_exe().unwrap();
    let destination = root.join("uruntime-appimage-x86_64");

    publish_artifact(&source, &destination, &sections, *b"AI\x02").unwrap();

    assert!(source.is_file(), "Cargo output was moved instead of copied");
    assert_ne!(
        fs::metadata(&destination).unwrap().permissions().mode() & 0o111,
        0,
        "published artifact lost executable bits"
    );
    let bytes = fs::read(&destination).unwrap();
    assert_eq!(&bytes[8..11], b"AI\x02");
    let sections_output = Command::new("llvm-readelf")
        .arg("--sections")
        .arg(&destination)
        .output()
        .unwrap();
    assert!(sections_output.status.success());
    let table = String::from_utf8(sections_output.stdout).unwrap();
    assert!(table.contains(".envs"));
    assert!(table.contains(".upd_info"));
    assert_eq!(
        fs::read_dir(&root)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().contains(".tmp-"))
            .count(),
        0
    );
    fs::remove_dir_all(root).unwrap();
}

#[cfg(unix)]
#[test]
fn artifact_publish_replaces_destination_symlink_without_clobbering_its_target() {
    use std::os::unix::fs::symlink;

    let root = test_dir("publish-symlink");
    let sections = root.join("sections");
    fs::create_dir_all(&sections).unwrap();
    fs::write(sections.join("envs"), b"test-envs").unwrap();
    let victim = root.join("victim");
    fs::write(&victim, b"do-not-touch").unwrap();
    let destination = root.join("uruntime-appimage-x86_64");
    symlink(&victim, &destination).unwrap();

    publish_artifact(
        &env::current_exe().unwrap(),
        &destination,
        &sections,
        *b"AI\x02",
    )
    .unwrap();

    assert_eq!(fs::read(&victim).unwrap(), b"do-not-touch");
    assert!(!fs::symlink_metadata(&destination)
        .unwrap()
        .file_type()
        .is_symlink());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn checksum_update_uses_validated_payloads_sorted_atomic_check_and_no_change() {
    use build_support::{AssetKind, AssetSource, ElfType};
    use xxhash_rust::xxh64::xxh64;

    let target = build_support::target_spec("x86_64-unknown-linux-musl").unwrap();
    let direct = synthetic_helper_elf(3);
    let payload = synthetic_helper_elf(2);
    let compressed = zstd::stream::encode_all(&payload[..], 3).unwrap();
    let mut wrapper = b"wrapper-prefix".to_vec();
    wrapper.extend_from_slice(&compressed);
    wrapper.extend_from_slice(b"SQUEEZE!");
    wrapper.extend_from_slice(&(payload.len() as u64).to_le_bytes());
    wrapper.extend_from_slice(&(compressed.len() as u64).to_le_bytes());
    wrapper.extend_from_slice(&xxh64(&payload, 0).to_le_bytes());
    let sources = vec![
        AssetSource {
            target,
            name: "z-direct",
            url: "fixture://direct".into(),
            kind: AssetKind::Direct,
            elf_type: ElfType::StaticPie,
        },
        AssetSource {
            target,
            name: "a-wrapper",
            url: "fixture://wrapper".into(),
            kind: AssetKind::DwarfsWrapper,
            elf_type: ElfType::StaticExec,
        },
    ];
    let fetch = |source: &AssetSource| match source.url.as_str() {
        "fixture://direct" => Ok(direct.clone()),
        "fixture://wrapper" => Ok(wrapper.clone()),
        _ => Err("unexpected URL".to_string()),
    };
    let root = test_dir("checksum-update");
    let manifest = root.join("checksums.txt");
    let zig_index = synthetic_zig_index();
    fs::create_dir_all(&root).unwrap();
    fs::write(&manifest, b"original\n").unwrap();

    let drift =
        update_checksum_manifest_with(&manifest, true, &sources, &fetch, &zig_index).unwrap_err();
    assert!(drift.to_string().contains("drift"));
    assert_eq!(fs::read(&manifest).unwrap(), b"original\n");

    assert_eq!(
        update_checksum_manifest_with(&manifest, false, &sources, &fetch, &zig_index).unwrap(),
        ManifestUpdate::Updated
    );
    let generated = fs::read_to_string(&manifest).unwrap();
    let records = build_support::parse_digest_manifest(&generated).unwrap();
    assert_eq!(records.len(), 2);
    assert_eq!(records[0].name, "a-wrapper");
    assert_eq!(records[1].name, "z-direct");
    assert_ne!(records[0].source_sha256, records[0].payload_sha256);
    assert_eq!(records[1].source_sha256, records[1].payload_sha256);
    assert_eq!(
        update_checksum_manifest_with(&manifest, false, &sources, &fetch, &zig_index).unwrap(),
        ManifestUpdate::Unchanged
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn helper_checksum_cache_uses_the_build_source_directory() {
    let project = PathBuf::from("/project");
    let target = build_support::target_spec("x86_64-unknown-linux-musl").unwrap();
    let direct = build_support::AssetSource {
        target,
        name: "squashfuse",
        url: "fixture://direct".into(),
        kind: build_support::AssetKind::Direct,
        elf_type: build_support::ElfType::StaticPie,
    };
    let wrapper = build_support::AssetSource {
        target,
        name: "dwarfs-universal",
        url: "fixture://wrapper".into(),
        kind: build_support::AssetKind::DwarfsWrapper,
        elf_type: build_support::ElfType::StaticExec,
    };

    assert_eq!(
        helper_source_cache_path(&project, &direct).unwrap(),
        project
            .join("assets-x86_64")
            .join("squashfuse-0.6.3.r2")
            .join("squashfuse")
    );
    assert_eq!(
        helper_source_cache_path(&project, &wrapper).unwrap(),
        project
            .join("assets-x86_64")
            .join("dwarfs-0.15.7")
            .join("dwarfs-universal-wrapper")
    );
}

#[test]
fn checksum_cache_is_reused_only_when_its_digest_matches() {
    let root = test_dir("verified-helper-cache");
    fs::create_dir_all(&root).unwrap();
    let cached = root.join("helper");
    fs::write(&cached, b"release bytes").unwrap();
    let expected = build_support::sha256_hex(b"release bytes");

    assert_eq!(
        read_verified_cached_helper_source(&cached, Some(&expected)).unwrap(),
        Some(b"release bytes".to_vec())
    );
    assert_eq!(
        read_verified_cached_helper_source(&cached, Some(&"0".repeat(64))).unwrap(),
        None
    );
    assert_eq!(
        read_verified_cached_helper_source(&cached, None).unwrap(),
        None
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn synthetic_zig_index_matches_pinned_manifest_and_resolves_host_archive() {
    let mut release = serde_json::Map::new();
    for package in zig_packages().unwrap() {
        release.insert(
            package.platform,
            serde_json::json!({
                "tarball": package.url,
                "shasum": package.sha256,
            }),
        );
    }
    let index = serde_json::to_vec(&serde_json::json!({ ZIG_VERSION: release })).unwrap();
    assert!(cached_zig_index_matches_manifest(&index));
    let package = zig_package_from_index(&index, "linux", "x86_64").unwrap();
    assert_eq!(package.platform, "x86_64-linux");
    assert_eq!(
        zig_archive_path(Path::new("/cache"), &package),
        PathBuf::from(format!(
            "/cache/zig-{ZIG_VERSION}-x86_64-linux-{}.tar.xz",
            package.sha256
        ))
    );

    let mut changed: serde_json::Value = serde_json::from_slice(&index).unwrap();
    changed[ZIG_VERSION]["x86_64-linux"]["shasum"] = serde_json::Value::String("b".repeat(64));
    assert!(!cached_zig_index_matches_manifest(
        &serde_json::to_vec(&changed).unwrap()
    ));
}

#[test]
fn checksum_update_propagates_manifest_read_errors() {
    let root = test_dir("checksum-read-error");
    fs::create_dir_all(&root).unwrap();
    let error = update_checksum_manifest_with(
        &root,
        true,
        &[],
        &|_| unreachable!(),
        &synthetic_zig_index(),
    )
    .unwrap_err();
    assert!(error.to_string().contains("failed to read"));
    fs::remove_dir_all(root).unwrap();
}

fn synthetic_zig_index() -> Vec<u8> {
    let mut release = serde_json::Map::new();
    for platform in ZIG_PLATFORMS {
        release.insert(
            platform.to_string(),
            serde_json::json!({
                "tarball": zig_download_url(platform),
                "shasum": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            }),
        );
    }
    serde_json::to_vec(&serde_json::json!({ ZIG_VERSION: release })).unwrap()
}

fn synthetic_helper_elf(elf_type: u16) -> Vec<u8> {
    let mut elf = vec![0u8; 160];
    elf[..4].copy_from_slice(b"\x7fELF");
    elf[4] = 2;
    elf[5] = 1;
    elf[6] = 1;
    elf[16..18].copy_from_slice(&elf_type.to_le_bytes());
    elf[18..20].copy_from_slice(&62u16.to_le_bytes());
    elf[20..24].copy_from_slice(&1u32.to_le_bytes());
    elf[32..40].copy_from_slice(&64u64.to_le_bytes());
    elf[52..54].copy_from_slice(&64u16.to_le_bytes());
    elf[54..56].copy_from_slice(&56u16.to_le_bytes());
    elf[56..58].copy_from_slice(&1u16.to_le_bytes());
    elf[64..68].copy_from_slice(&1u32.to_le_bytes());
    elf[68..72].copy_from_slice(&5u32.to_le_bytes());
    elf[72..80].copy_from_slice(&120u64.to_le_bytes());
    elf[96..104].copy_from_slice(&40u64.to_le_bytes());
    elf[104..112].copy_from_slice(&40u64.to_le_bytes());
    elf
}

fn test_dir(label: &str) -> PathBuf {
    env::temp_dir().join(format!("uruntime-xtask-{label}-{}", std::process::id()))
}
