#[path = "../build_support.rs"]
pub mod build_support;

use build_support::{
    all_asset_sources, asset_urls, atomic_write, cache_relative_path, cache_version, curl_args,
    digest_records, download_atomic, extract_dwarfs_wrapper, parse_digest_manifest,
    prepare_assets_with, sha256_file, sha256_hex, source_cache_name, source_cache_relative_path,
    stage_output, target_spec, validate_elf, Asset, AssetKind, BuildFeatures, ElfEndian, ElfType,
    MAX_DOWNLOAD_SIZE, MAX_HELPER_SIZE,
};
use xxhash_rust::xxh64::xxh64;

const TARGETS: [(&str, &str, ElfEndian); 6] = [
    ("x86_64-unknown-linux-musl", "x86_64", ElfEndian::Little),
    ("aarch64-unknown-linux-musl", "aarch64", ElfEndian::Little),
    ("riscv64gc-unknown-linux-musl", "riscv64", ElfEndian::Little),
    (
        "loongarch64-unknown-linux-musl",
        "loongarch64",
        ElfEndian::Little,
    ),
    ("powerpc64-unknown-linux-musl", "ppc64", ElfEndian::Big),
    (
        "powerpc64le-unknown-linux-musl",
        "ppc64le",
        ElfEndian::Little,
    ),
];

#[test]
fn exact_target_triples_map_to_release_arch_and_endian() {
    for (target, arch, endian) in TARGETS {
        let spec = target_spec(target).unwrap();
        assert_eq!(spec.release_arch, arch);
        assert_eq!(spec.endian, endian);
    }
}

#[test]
fn powerpc_endian_variants_do_not_share_assets() {
    let be = target_spec("powerpc64-unknown-linux-musl").unwrap();
    let le = target_spec("powerpc64le-unknown-linux-musl").unwrap();
    assert_eq!(be.release_arch, "ppc64");
    assert_eq!(be.endian, ElfEndian::Big);
    assert_eq!(le.release_arch, "ppc64le");
    assert_eq!(le.endian, ElfEndian::Little);
}

#[test]
fn unknown_target_has_actionable_error() {
    let err = target_spec("mips64-unknown-linux-musl").unwrap_err();
    assert!(err.contains("unsupported TARGET `mips64-unknown-linux-musl`"));
    assert!(err.contains("x86_64-unknown-linux-musl"));
}

#[test]
fn urls_cover_feature_and_lite_combinations() {
    for (_, arch, _) in TARGETS {
        let squash_only = asset_urls(
            arch,
            BuildFeatures {
                squashfs: true,
                dwarfs: false,
                lite: false,
            },
        );
        assert_eq!(squash_only.len(), 3);
        assert!(squash_only.iter().any(|a| a
            .url
            .ends_with(&format!("/squashfuse-musl-mimalloc-{arch}"))));
        assert!(squash_only
            .iter()
            .any(|a| a.url.ends_with(&format!("/unsquashfs-{arch}"))));
        assert!(squash_only
            .iter()
            .any(|a| a.url.ends_with(&format!("/mksquashfs-{arch}"))));

        let squash_lite = asset_urls(
            arch,
            BuildFeatures {
                squashfs: true,
                dwarfs: false,
                lite: true,
            },
        );
        assert_eq!(squash_lite.len(), 2);
        assert!(!squash_lite.iter().any(|a| a.name == "mksquashfs"));

        let dwarfs_full = asset_urls(
            arch,
            BuildFeatures {
                squashfs: false,
                dwarfs: true,
                lite: false,
            },
        );
        assert_eq!(dwarfs_full.len(), 1);
        assert_eq!(dwarfs_full[0].name, "dwarfs-universal");
        assert!(dwarfs_full[0]
            .url
            .ends_with(&format!("/dwarfs-universal-0.15.7-Linux-{arch}")));

        let dwarfs_lite = asset_urls(
            arch,
            BuildFeatures {
                squashfs: false,
                dwarfs: true,
                lite: true,
            },
        );
        assert_eq!(dwarfs_lite.len(), 1);
        assert_eq!(dwarfs_lite[0].name, "dwarfs-fuse-extract");
        assert!(dwarfs_lite[0]
            .url
            .ends_with(&format!("/dwarfs-fuse-extract-0.15.7-Linux-{arch}")));

        let full = asset_urls(
            arch,
            BuildFeatures {
                squashfs: true,
                dwarfs: true,
                lite: false,
            },
        );
        assert_eq!(full.len(), 4);
        let lite = asset_urls(
            arch,
            BuildFeatures {
                squashfs: true,
                dwarfs: true,
                lite: true,
            },
        );
        assert_eq!(lite.len(), 3);
    }
}

#[test]
fn helper_urls_use_r2_releases() {
    let urls = asset_urls(
        "x86_64",
        BuildFeatures {
            squashfs: true,
            dwarfs: false,
            lite: false,
        },
    );
    assert!(urls.iter().any(|a| a.url.contains("/v0.6.3.r2/")));
    assert!(urls.iter().any(|a| a.url.contains("/v4.7.5.r2/")));
}

#[test]
fn build_uses_only_out_dir_staging_and_target_specific_include_path() {
    let build_rs = include_str!("../build.rs");
    let main_rs = include_str!("../src/main.rs");
    assert!(build_rs.contains("OUT_DIR"));
    assert!(build_rs.contains("URUNTIME_HELPER_DIR"));
    assert!(build_rs.contains("prepare_assets_with"));
    assert!(!build_rs.contains("symlink"));
    assert!(!build_rs.contains("project_path.join(\"assets\")"));
    assert!(main_rs.contains("env!(\"URUNTIME_HELPER_DIR\")"));
    assert!(!main_rs.contains("../assets/"));
}

#[test]
fn cache_version_changes_when_any_helper_version_changes() {
    let current = cache_version("0.6.3.r2", "4.7.5.r2", "0.15.7");
    assert_eq!(
        current,
        "squashfuse-0.6.3.r2_squashfs-tools-4.7.5.r2_dwarfs-0.15.7"
    );
    assert_ne!(current, cache_version("0.6.3.r1", "4.7.5.r2", "0.15.7"));
    assert_ne!(current, cache_version("0.6.3.r2", "4.7.5.r1", "0.15.7"));
    assert_ne!(current, cache_version("0.6.3.r2", "4.7.5.r2", "0.15.6"));
}

#[test]
fn cache_path_contains_release_arch_and_all_versions() {
    let be = target_spec("powerpc64-unknown-linux-musl").unwrap();
    let le = target_spec("powerpc64le-unknown-linux-musl").unwrap();
    assert_eq!(
        cache_relative_path(be),
        std::path::PathBuf::from(
            "assets-ppc64/squashfuse-0.6.3.r2_squashfs-tools-4.7.5.r2_dwarfs-0.15.7"
        )
    );
    assert_eq!(
        cache_relative_path(le),
        std::path::PathBuf::from(
            "assets-ppc64le/squashfuse-0.6.3.r2_squashfs-tools-4.7.5.r2_dwarfs-0.15.7"
        )
    );
}

fn synthetic_elf(machine: u16, endian: ElfEndian) -> Vec<u8> {
    let mut elf = vec![0u8; 256];
    elf[..4].copy_from_slice(b"\x7fELF");
    elf[4] = 2;
    elf[5] = match endian {
        ElfEndian::Little => 1,
        ElfEndian::Big => 2,
    };
    elf[6] = 1;
    write_u16(&mut elf, 16, 2, endian); // ET_EXEC (DwarFS payload)
    write_u16(&mut elf, 18, machine, endian);
    write_u32(&mut elf, 20, 1, endian);
    write_u64(&mut elf, 24, 0x400080, endian);
    write_u64(&mut elf, 32, 64, endian);
    write_u16(&mut elf, 52, 64, endian);
    write_u16(&mut elf, 54, 56, endian);
    write_u16(&mut elf, 56, 1, endian);
    write_u32(&mut elf, 64, 1, endian); // PT_LOAD
    write_u32(&mut elf, 68, 5, endian); // PF_R | PF_X
    write_u64(&mut elf, 72, 128, endian);
    write_u64(&mut elf, 80, 0x400080, endian);
    write_u64(&mut elf, 88, 0x400080, endian);
    write_u64(&mut elf, 96, 64, endian);
    write_u64(&mut elf, 104, 64, endian);
    write_u64(&mut elf, 112, 0x1000, endian);
    elf[128..160].copy_from_slice(b"synthetic DwarFS payload fixture");
    elf
}

fn write_u16(bytes: &mut [u8], offset: usize, value: u16, endian: ElfEndian) {
    let encoded = match endian {
        ElfEndian::Little => value.to_le_bytes(),
        ElfEndian::Big => value.to_be_bytes(),
    };
    bytes[offset..offset + 2].copy_from_slice(&encoded);
}

fn write_u32(bytes: &mut [u8], offset: usize, value: u32, endian: ElfEndian) {
    let encoded = match endian {
        ElfEndian::Little => value.to_le_bytes(),
        ElfEndian::Big => value.to_be_bytes(),
    };
    bytes[offset..offset + 4].copy_from_slice(&encoded);
}

fn write_u64(bytes: &mut [u8], offset: usize, value: u64, endian: ElfEndian) {
    let encoded = match endian {
        ElfEndian::Little => value.to_le_bytes(),
        ElfEndian::Big => value.to_be_bytes(),
    };
    bytes[offset..offset + 8].copy_from_slice(&encoded);
}

fn wrapper(payload: &[u8]) -> Vec<u8> {
    let compressed = zstd::stream::encode_all(payload, 3).unwrap();
    let mut wrapper = b"synthetic wrapper prefix".to_vec();
    wrapper.extend_from_slice(&compressed);
    wrapper.extend_from_slice(b"SQUEEZE!");
    wrapper.extend_from_slice(&(payload.len() as u64).to_le_bytes());
    wrapper.extend_from_slice(&(compressed.len() as u64).to_le_bytes());
    wrapper.extend_from_slice(&xxh64(payload, 0).to_le_bytes());
    wrapper
}

#[test]
fn valid_wrapper_decodes_to_exact_elf_payload() {
    let spec = target_spec("x86_64-unknown-linux-musl").unwrap();
    let payload = synthetic_elf(spec.elf_machine, spec.endian);
    assert_eq!(
        extract_dwarfs_wrapper(&wrapper(&payload), spec, 1024).unwrap(),
        payload
    );
}

#[test]
fn truncated_wrapper_is_rejected() {
    let spec = target_spec("x86_64-unknown-linux-musl").unwrap();
    let err = extract_dwarfs_wrapper(b"too short", spec, 1024).unwrap_err();
    assert!(err.contains("truncated"));
}

#[test]
fn bad_wrapper_magic_is_rejected() {
    let spec = target_spec("x86_64-unknown-linux-musl").unwrap();
    let payload = synthetic_elf(spec.elf_machine, spec.endian);
    let mut input = wrapper(&payload);
    let trailer = input.len() - 32;
    input[trailer..trailer + 8].copy_from_slice(b"NOTMAGIC");
    let err = extract_dwarfs_wrapper(&input, spec, 1024).unwrap_err();
    assert!(err.contains("magic"));
}

#[test]
fn impossible_compressed_size_is_rejected() {
    let spec = target_spec("x86_64-unknown-linux-musl").unwrap();
    let payload = synthetic_elf(spec.elf_machine, spec.endian);
    let mut input = wrapper(&payload);
    let csize = input.len() - 16;
    input[csize..csize + 8].copy_from_slice(&u64::MAX.to_le_bytes());
    let err = extract_dwarfs_wrapper(&input, spec, 1024).unwrap_err();
    assert!(err.contains("compressed size"));
}

#[test]
fn checksum_mismatch_is_rejected() {
    let spec = target_spec("x86_64-unknown-linux-musl").unwrap();
    let payload = synthetic_elf(spec.elf_machine, spec.endian);
    let mut input = wrapper(&payload);
    let checksum = input.len() - 8;
    input[checksum..].copy_from_slice(&0u64.to_le_bytes());
    let err = extract_dwarfs_wrapper(&input, spec, 1024).unwrap_err();
    assert!(err.contains("XXH64"));
}

#[test]
fn oversized_declared_output_is_rejected_before_decode() {
    let spec = target_spec("x86_64-unknown-linux-musl").unwrap();
    let payload = synthetic_elf(spec.elf_machine, spec.endian);
    let mut input = wrapper(&payload);
    let usize_field = input.len() - 24;
    input[usize_field..usize_field + 8].copy_from_slice(&2048u64.to_le_bytes());
    let err = extract_dwarfs_wrapper(&input, spec, 1024).unwrap_err();
    assert!(err.contains("exceeds limit"));
}

#[test]
fn exact_uncompressed_size_is_required() {
    let spec = target_spec("x86_64-unknown-linux-musl").unwrap();
    let payload = synthetic_elf(spec.elf_machine, spec.endian);
    let mut input = wrapper(&payload);
    let usize_field = input.len() - 24;
    input[usize_field..usize_field + 8]
        .copy_from_slice(&((payload.len() + 1) as u64).to_le_bytes());
    let err = extract_dwarfs_wrapper(&input, spec, 1024).unwrap_err();
    assert!(err.contains("uncompressed size"));
}

#[test]
fn elf_endian_and_machine_must_match_target() {
    let x86 = target_spec("x86_64-unknown-linux-musl").unwrap();
    let wrong_endian = synthetic_elf(x86.elf_machine, ElfEndian::Big);
    assert!(extract_dwarfs_wrapper(&wrapper(&wrong_endian), x86, 1024)
        .unwrap_err()
        .contains("endian"));

    let wrong_machine = synthetic_elf(183, ElfEndian::Little);
    assert!(extract_dwarfs_wrapper(&wrapper(&wrong_machine), x86, 1024)
        .unwrap_err()
        .contains("machine"));
}

#[test]
fn elf_validation_rejects_short_fake_header_and_bad_program_bounds() {
    let spec = target_spec("x86_64-unknown-linux-musl").unwrap();
    let mut short = vec![0u8; 20];
    short[..6].copy_from_slice(b"\x7fELF\x02\x01");
    assert!(validate_elf(&short, spec, ElfType::StaticExec)
        .unwrap_err()
        .contains("truncated"));

    let mut bad_bounds = synthetic_elf(spec.elf_machine, spec.endian);
    write_u64(&mut bad_bounds, 32, u64::MAX, spec.endian);
    assert!(validate_elf(&bad_bounds, spec, ElfType::StaticExec)
        .unwrap_err()
        .contains("program header"));
}

#[test]
fn elf_validation_rejects_non_executable_load_interpreter_and_needed_library() {
    let spec = target_spec("x86_64-unknown-linux-musl").unwrap();
    let mut no_exec = synthetic_elf(spec.elf_machine, spec.endian);
    write_u32(&mut no_exec, 68, 4, spec.endian);
    assert!(validate_elf(&no_exec, spec, ElfType::StaticExec)
        .unwrap_err()
        .contains("executable PT_LOAD"));

    let mut interpreter = synthetic_elf(spec.elf_machine, spec.endian);
    write_u32(&mut interpreter, 64, 3, spec.endian);
    assert!(validate_elf(&interpreter, spec, ElfType::StaticExec)
        .unwrap_err()
        .contains("PT_INTERP"));

    let mut dynamic = synthetic_elf(spec.elf_machine, spec.endian);
    dynamic.resize(320, 0);
    write_u16(&mut dynamic, 56, 2, spec.endian);
    write_u32(&mut dynamic, 120, 2, spec.endian); // PT_DYNAMIC
    write_u64(&mut dynamic, 128, 256, spec.endian);
    write_u64(&mut dynamic, 152, 32, spec.endian);
    write_u64(&mut dynamic, 160, 32, spec.endian);
    write_u64(&mut dynamic, 256, 1, spec.endian); // DT_NEEDED
    assert!(validate_elf(&dynamic, spec, ElfType::StaticExec)
        .unwrap_err()
        .contains("DT_NEEDED"));
}

#[test]
fn exact_executable_type_is_enforced() {
    let spec = target_spec("x86_64-unknown-linux-musl").unwrap();
    let mut elf = synthetic_elf(spec.elf_machine, spec.endian);
    assert!(validate_elf(&elf, spec, ElfType::StaticPie).is_err());
    write_u16(&mut elf, 16, 3, spec.endian);
    validate_elf(&elf, spec, ElfType::StaticPie).unwrap();
    assert!(validate_elf(&elf, spec, ElfType::StaticExec).is_err());
}

#[test]
fn upstream_pack_py_zstd_vector_decodes_exactly() {
    let spec = target_spec("x86_64-unknown-linux-musl").unwrap();
    let wrapper = include_bytes!("fixtures/pack-py-zstd.wrapper");
    let payload = include_bytes!("fixtures/pack-py-payload.elf");
    assert_eq!(
        extract_dwarfs_wrapper(wrapper, spec, MAX_HELPER_SIZE).unwrap(),
        payload
    );
}

#[test]
fn helper_source_inventory_is_derived_from_pinned_versions_for_all_30_assets() {
    let sources = all_asset_sources();
    assert_eq!(sources.len(), 30);
    let keys: std::collections::BTreeSet<_> = sources
        .iter()
        .map(|source| (source.target.release_arch, source.name))
        .collect();
    assert_eq!(keys.len(), 30);
    assert!(sources.iter().all(|source| {
        source.url.contains("0.15.7")
            || source.url.contains("0.6.3.r2")
            || source.url.contains("4.7.5.r2")
    }));
}

#[test]
fn manifest_pins_every_remote_asset_for_all_arches() {
    let records = digest_records().unwrap();
    assert_eq!(records.len(), 30);
    assert!(records.windows(2).all(|pair| {
        (pair[0].arch.as_str(), pair[0].name.as_str())
            < (pair[1].arch.as_str(), pair[1].name.as_str())
    }));
    let malformed = "x86_64\thelper\tnot-a-hash\talso-bad\n";
    assert!(parse_digest_manifest(malformed)
        .unwrap_err()
        .contains("SHA-256"));
    let duplicate = format!(
        "x86_64\thelper\t{}\t{}\nx86_64\thelper\t{}\t{}\n",
        "0".repeat(64),
        "1".repeat(64),
        "2".repeat(64),
        "3".repeat(64)
    );
    assert!(parse_digest_manifest(&duplicate)
        .unwrap_err()
        .contains("duplicate"));

    let mut sources = std::collections::BTreeSet::new();
    for (_, arch, _) in TARGETS {
        let assets = asset_urls(
            arch,
            BuildFeatures {
                squashfs: true,
                dwarfs: true,
                lite: false,
            },
        );
        assert_eq!(assets.len(), 4);
        for asset in assets {
            assert_eq!(asset.source_sha256.len(), 64);
            assert!(asset.source_sha256.bytes().all(|b| b.is_ascii_hexdigit()));
            assert_eq!(asset.payload_sha256.len(), 64);
            sources.insert(asset.url);
        }
        let lite = asset_urls(
            arch,
            BuildFeatures {
                squashfs: false,
                dwarfs: true,
                lite: true,
            },
        );
        assert_eq!(lite.len(), 1);
        assert_eq!(lite[0].source_sha256.len(), 64);
        assert_eq!(lite[0].payload_sha256.len(), 64);
        sources.insert(lite[0].url.clone());
    }
    assert_eq!(sources.len(), 30);
}

#[test]
fn resource_limits_cover_published_assets_without_being_unbounded() {
    assert_eq!(MAX_DOWNLOAD_SIZE, 8 * 1024 * 1024);
    assert_eq!(MAX_HELPER_SIZE, 16 * 1024 * 1024);
}

#[test]
fn curl_download_arguments_are_secure_and_retrying() {
    let args = curl_args("https://example.invalid/helper", MAX_DOWNLOAD_SIZE);
    assert_eq!(
        args,
        [
            "--fail",
            "--location",
            "--retry",
            "3",
            "--max-filesize",
            "8388608",
            "https://example.invalid/helper",
        ]
    );
    assert!(!args.iter().any(|arg| arg == "--insecure" || arg == "-k"));
    assert!(!args.iter().any(|arg| arg == "--output" || arg == "-o"));
}

#[test]
fn failed_wrapper_extraction_does_not_touch_existing_destination() {
    let spec = target_spec("x86_64-unknown-linux-musl").unwrap();
    let dir = std::env::temp_dir().join(format!(
        "uruntime-wrapper-test-{}-{}",
        std::process::id(),
        std::thread::current().name().unwrap_or("unnamed")
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let wrapper_path = dir.join("wrapper");
    let destination = dir.join("payload");
    std::fs::write(&wrapper_path, b"invalid").unwrap();
    std::fs::write(&destination, b"existing cache").unwrap();

    let wrapper = std::fs::read(&wrapper_path).unwrap();
    assert!(extract_dwarfs_wrapper(&wrapper, spec, 1024).is_err());
    assert_eq!(std::fs::read(&destination).unwrap(), b"existing cache");
    let names: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    assert!(!names
        .iter()
        .any(|name| name.to_string_lossy().contains(".part-")));
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn oversized_cache_file_is_rejected_before_reading() {
    let root = test_dir("oversized-cache");
    let path = root.join("oversized");
    let file = std::fs::File::create(&path).unwrap();
    file.set_len((MAX_DOWNLOAD_SIZE + 1) as u64).unwrap();
    let err = sha256_file(&path, MAX_DOWNLOAD_SIZE).unwrap_err();
    assert!(err.contains("exceeds limit"));
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn atomic_write_replaces_destination_symlink_without_following_it() {
    use std::os::unix::fs::symlink;

    let root = test_dir("atomic-symlink");
    let victim = root.join("victim");
    let destination = root.join("destination");
    std::fs::write(&victim, b"victim-data").unwrap();
    symlink(&victim, &destination).unwrap();

    atomic_write(&destination, b"new-data").unwrap();

    assert_eq!(std::fs::read(&victim).unwrap(), b"victim-data");
    assert_eq!(std::fs::read(&destination).unwrap(), b"new-data");
    assert!(!std::fs::symlink_metadata(&destination)
        .unwrap()
        .file_type()
        .is_symlink());
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn corrupted_source_cache_is_deleted_and_reacquired() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    let spec = target_spec("x86_64-unknown-linux-musl").unwrap();
    let payload = synthetic_elf(spec.elf_machine, spec.endian);
    let digest = sha256_hex(&payload);
    let asset = Asset {
        name: "squashfuse",
        url: "https://example.invalid/helper".to_string(),
        kind: AssetKind::Direct,
        source_sha256: digest.clone(),
        payload_sha256: digest,
        elf_type: ElfType::StaticExec,
    };
    let root = test_dir("corrupt-cache");
    let cache = root.join("cache");
    let out = root.join("out");
    let calls = AtomicUsize::new(0);
    let downloader = |_: &Asset, path: &std::path::Path| {
        calls.fetch_add(1, Ordering::SeqCst);
        std::fs::write(path, &payload).map_err(|err| err.to_string())
    };

    prepare_assets_with(
        &cache,
        &out,
        spec,
        std::slice::from_ref(&asset),
        &downloader,
    )
    .unwrap();
    std::fs::write(cache.join(".source-squashfuse"), b"corrupt").unwrap();
    prepare_assets_with(&cache, &out, spec, &[asset], &downloader).unwrap();

    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        sha256_file(&cache.join(".source-squashfuse"), MAX_DOWNLOAD_SIZE).unwrap(),
        asset_source_hash(&payload)
    );
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn shared_source_cache_is_reused_by_new_feature_generations() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    let spec = target_spec("x86_64-unknown-linux-musl").unwrap();
    let payload = synthetic_elf(spec.elf_machine, spec.endian);
    let digest = sha256_hex(&payload);
    let asset = Asset {
        name: "squashfuse",
        url: "https://example.invalid/helper".to_string(),
        kind: AssetKind::Direct,
        source_sha256: digest.clone(),
        payload_sha256: digest,
        elf_type: ElfType::StaticExec,
    };
    let root = test_dir("shared-source-cache");
    let cache = root.join("version").join("feature-generation");
    let out = root.join("out");
    std::fs::create_dir_all(cache.parent().unwrap()).unwrap();
    let shared_source = cache
        .parent()
        .unwrap()
        .join("squashfuse-0.6.3.r2")
        .join(source_cache_name(asset.name, asset.kind));
    std::fs::create_dir_all(shared_source.parent().unwrap()).unwrap();
    std::fs::write(shared_source, &payload).unwrap();
    let calls = AtomicUsize::new(0);
    let downloader = |_: &Asset, _: &std::path::Path| {
        calls.fetch_add(1, Ordering::SeqCst);
        Err("shared source should avoid a download".to_string())
    };

    prepare_assets_with(&cache, &out, spec, &[asset], &downloader).unwrap();

    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert!(out.join("squashfuse-zst").is_file());
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn helper_source_caches_are_versioned_per_upstream_project() {
    let target = target_spec("x86_64-unknown-linux-musl").unwrap();
    assert_eq!(
        source_cache_relative_path(target, "squashfuse", AssetKind::Direct).unwrap(),
        std::path::PathBuf::from("assets-x86_64/squashfuse-0.6.3.r2/squashfuse")
    );
    assert_eq!(
        source_cache_relative_path(target, "mksquashfs", AssetKind::Direct).unwrap(),
        std::path::PathBuf::from("assets-x86_64/squashfs-tools-4.7.5.r2/mksquashfs")
    );
    assert_eq!(
        source_cache_relative_path(target, "dwarfs-universal", AssetKind::DwarfsWrapper).unwrap(),
        std::path::PathBuf::from("assets-x86_64/dwarfs-0.15.7/dwarfs-universal-wrapper")
    );
}

#[test]
fn wrapper_sources_have_distinct_shared_cache_names() {
    assert_eq!(
        source_cache_name("dwarfs-universal", AssetKind::DwarfsWrapper),
        "dwarfs-universal-wrapper"
    );
    assert_eq!(
        source_cache_name("squashfuse", AssetKind::Direct),
        "squashfuse"
    );
}

#[test]
fn partial_generation_recovers_and_level_22_zst_is_byte_equal_to_raw_elf() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    let spec = target_spec("x86_64-unknown-linux-musl").unwrap();
    let payload = synthetic_elf(spec.elf_machine, spec.endian);
    let digest = sha256_hex(&payload);
    let asset = Asset {
        name: "squashfuse",
        url: "https://example.invalid/helper".to_string(),
        kind: AssetKind::Direct,
        source_sha256: digest.clone(),
        payload_sha256: digest,
        elf_type: ElfType::StaticExec,
    };
    let root = test_dir("partial-generation");
    let cache = root.join("cache");
    let out = root.join("out");
    let calls = AtomicUsize::new(0);
    let downloader = |_: &Asset, path: &std::path::Path| {
        calls.fetch_add(1, Ordering::SeqCst);
        std::fs::write(path, &payload).map_err(|err| err.to_string())
    };

    prepare_assets_with(
        &cache,
        &out,
        spec,
        std::slice::from_ref(&asset),
        &downloader,
    )
    .unwrap();
    std::fs::remove_file(cache.join("squashfuse-zst")).unwrap();
    prepare_assets_with(&cache, &out, spec, &[asset], &downloader).unwrap();

    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let raw = std::fs::read(cache.join("squashfuse")).unwrap();
    let decoded =
        zstd::stream::decode_all(std::fs::File::open(cache.join("squashfuse-zst")).unwrap())
            .unwrap();
    assert_eq!(decoded, raw);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn concurrent_generation_uses_one_locked_transaction() {
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Barrier,
    };

    let spec = target_spec("x86_64-unknown-linux-musl").unwrap();
    let payload = Arc::new(synthetic_elf(spec.elf_machine, spec.endian));
    let digest = sha256_hex(&payload);
    let asset = Asset {
        name: "squashfuse",
        url: "https://example.invalid/helper".to_string(),
        kind: AssetKind::Direct,
        source_sha256: digest.clone(),
        payload_sha256: digest,
        elf_type: ElfType::StaticExec,
    };
    let root = test_dir("concurrent-generation");
    let cache = root.join("cache");
    let calls = Arc::new(AtomicUsize::new(0));
    let barrier = Arc::new(Barrier::new(2));
    let mut threads = Vec::new();
    for n in 0..2 {
        let payload = Arc::clone(&payload);
        let calls = Arc::clone(&calls);
        let barrier = Arc::clone(&barrier);
        let cache = cache.clone();
        let out = root.join(format!("out-{n}"));
        let asset = asset.clone();
        threads.push(std::thread::spawn(move || {
            barrier.wait();
            prepare_assets_with(&cache, &out, spec, &[asset], &|_, path| {
                calls.fetch_add(1, Ordering::SeqCst);
                std::thread::sleep(std::time::Duration::from_millis(75));
                std::fs::write(path, payload.as_slice()).map_err(|err| err.to_string())
            })
        }));
    }
    for thread in threads {
        thread.join().unwrap().unwrap();
    }
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn sequential_a_b_a_and_concurrent_outputs_are_isolated() {
    let root = test_dir("output-isolation");
    let a = root.join("cache-a");
    let b = root.join("cache-b");
    std::fs::create_dir_all(&a).unwrap();
    std::fs::create_dir_all(&b).unwrap();
    std::fs::write(a.join("helper-zst"), b"architecture-a").unwrap();
    std::fs::write(b.join("helper-zst"), b"architecture-b").unwrap();
    let shared_out = root.join("sequential-out");
    stage_output(&a, &shared_out, &["helper-zst"]).unwrap();
    assert_eq!(
        std::fs::read(shared_out.join("helper-zst")).unwrap(),
        b"architecture-a"
    );
    stage_output(&b, &shared_out, &["helper-zst"]).unwrap();
    assert_eq!(
        std::fs::read(shared_out.join("helper-zst")).unwrap(),
        b"architecture-b"
    );
    stage_output(&a, &shared_out, &["helper-zst"]).unwrap();
    assert_eq!(
        std::fs::read(shared_out.join("helper-zst")).unwrap(),
        b"architecture-a"
    );

    let out_a = root.join("out-a");
    let out_b = root.join("out-b");
    let a2 = a.clone();
    let b2 = b.clone();
    let ta = std::thread::spawn(move || stage_output(&a2, &out_a, &["helper-zst"]));
    let tb = std::thread::spawn(move || stage_output(&b2, &out_b, &["helper-zst"]));
    ta.join().unwrap().unwrap();
    tb.join().unwrap().unwrap();
    assert_eq!(
        std::fs::read(root.join("out-a/helper-zst")).unwrap(),
        b"architecture-a"
    );
    assert_eq!(
        std::fs::read(root.join("out-b/helper-zst")).unwrap(),
        b"architecture-b"
    );
    std::fs::remove_dir_all(root).unwrap();
}

fn asset_source_hash(payload: &[u8]) -> String {
    sha256_hex(payload)
}

fn test_dir(label: &str) -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!(
        "uruntime-{label}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).unwrap();
    path
}

#[test]
#[ignore = "downloads and validates all upstream direct SquashFS helpers"]
fn all_upstream_direct_helpers_match_manifest_and_elf_policy() {
    let cache = std::env::temp_dir().join("uruntime-direct-helper-tests-r2");
    std::fs::create_dir_all(&cache).unwrap();
    for (target, arch, _) in TARGETS {
        let spec = target_spec(target).unwrap();
        for asset in asset_urls(
            arch,
            BuildFeatures {
                squashfs: true,
                dwarfs: false,
                lite: false,
            },
        ) {
            let path = cache.join(format!("{arch}-{}", asset.name));
            if sha256_file(&path, MAX_DOWNLOAD_SIZE).ok().as_deref() != Some(&asset.source_sha256) {
                let _ = std::fs::remove_file(&path);
                download_atomic("curl", &asset.url, &path).unwrap();
            }
            assert_eq!(
                sha256_file(&path, MAX_DOWNLOAD_SIZE).unwrap(),
                asset.source_sha256
            );
            let payload = std::fs::read(&path).unwrap();
            assert_eq!(sha256_hex(&payload), asset.payload_sha256);
            validate_elf(&payload, spec, asset.elf_type).unwrap();
        }
    }
}

#[test]
#[ignore = "downloads and validates all upstream DwarFS wrappers"]
fn all_upstream_wrappers_decode_and_match_target_elf() {
    use std::os::unix::fs::PermissionsExt;

    let cache = std::env::temp_dir().join("uruntime-dwarfs-wrapper-tests-0.15.7");
    std::fs::create_dir_all(&cache).unwrap();
    for (target, arch, _) in TARGETS {
        let spec = target_spec(target).unwrap();
        for lite in [false, true] {
            let asset = asset_urls(
                arch,
                BuildFeatures {
                    squashfs: false,
                    dwarfs: true,
                    lite,
                },
            )
            .pop()
            .unwrap();
            let wrapper_path = cache.join(format!("{arch}-{}-wrapper", asset.name));
            if sha256_file(&wrapper_path, MAX_DOWNLOAD_SIZE)
                .ok()
                .as_deref()
                != Some(&asset.source_sha256)
            {
                let _ = std::fs::remove_file(&wrapper_path);
                download_atomic("curl", &asset.url, &wrapper_path).unwrap();
            }
            assert_eq!(
                sha256_file(&wrapper_path, MAX_DOWNLOAD_SIZE).unwrap(),
                asset.source_sha256
            );
            let wrapper_data = std::fs::read(&wrapper_path).unwrap();
            let decoded = extract_dwarfs_wrapper(&wrapper_data, spec, MAX_HELPER_SIZE).unwrap();

            if arch == "x86_64" {
                let mut permissions = std::fs::metadata(&wrapper_path).unwrap().permissions();
                permissions.set_mode(0o755);
                std::fs::set_permissions(&wrapper_path, permissions).unwrap();
                let reference = cache.join(format!("{arch}-{}-reference", asset.name));
                let _ = std::fs::remove_file(&reference);
                let status = std::process::Command::new(&wrapper_path)
                    .arg("--extract-wrapped-binary")
                    .arg(&reference)
                    .status()
                    .unwrap();
                assert!(status.success());
                assert_eq!(decoded, std::fs::read(&reference).unwrap());
                std::fs::remove_file(reference).unwrap();
            }
        }
    }
}
