use super::{
    embedded_unshare_policy, environment_drop_caps_policy, fallback_should_drop_capabilities,
    get_image, get_runtime, get_section_data, parse_unshare_cli_options, remove_runtime_separator,
    should_drop_capabilities, UnshareCliOptions,
};
use crate::elf_layout::tests::{fixture, Endian};
use std::io::Write;
use tempfile::NamedTempFile;

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

    let readme = include_str!("../README.md");
    assert!(readme.contains("| `3` | Do not enable `unshare` in advance"));
    assert!(readme.contains("capabilities only when `unshare` is entered automatically"));
    assert!(readme.contains("<ENV>_UNSHARE=3"));
    assert!(readme.contains("--<prefix>-unshare-fallback-drop-caps"));
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
        assert!(parse_unshare_cli_options(&mut args, "appimage").is_err());
    }
}

#[test]
fn runtime_boundary_points_to_squashfs_and_dwarfs_magic() {
    for endian in [Endian::Little, Endian::Big] {
        for magic in [b"hsqs", b"DWAR"] {
            let mut bytes = fixture(endian);
            bytes[0x380..0x384].copy_from_slice(magic);
            let mut file = NamedTempFile::new().unwrap();
            file.write_all(&bytes).unwrap();

            let runtime = get_runtime(&file.path().to_path_buf()).unwrap();

            assert_eq!(runtime.size, 0x380);
            assert_eq!(runtime.headers_bytes.len(), 0x380);
            assert_eq!(runtime.envs, "VALUE=1");
            assert_eq!(
                get_section_data(&runtime.headers_bytes, ".envs").unwrap(),
                "VALUE=1"
            );
            let image = get_image(&runtime.path, runtime.size).unwrap();
            assert_eq!(image.is_squash, magic == b"hsqs");
            assert_eq!(image.is_dwar, magic == b"DWAR");
        }
    }
}
