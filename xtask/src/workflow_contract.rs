use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use serde_yaml::Value;

use super::project_root;

fn workflow() -> (String, Value) {
    let raw = fs::read_to_string(project_root().join(".github/workflows/ci.yml")).unwrap();
    let parsed = serde_yaml::from_str(&raw).unwrap();
    (raw, parsed)
}

fn sequence<'a>(value: &'a Value, key: &str) -> &'a Vec<Value> {
    value[key]
        .as_sequence()
        .unwrap_or_else(|| panic!("{key} must be a sequence"))
}

fn mapping_keys(value: &Value) -> BTreeSet<String> {
    value
        .as_mapping()
        .unwrap()
        .keys()
        .map(|key| key.as_str().unwrap().to_string())
        .collect()
}

fn step_runs(job: &Value) -> Vec<&str> {
    sequence(job, "steps")
        .iter()
        .map(|step| step["run"].as_str().unwrap_or(""))
        .collect()
}

fn named_step<'a>(job: &'a Value, name: &str) -> &'a Value {
    sequence(job, "steps")
        .iter()
        .find(|step| step["name"].as_str() == Some(name))
        .unwrap_or_else(|| panic!("missing workflow step {name:?}"))
}

fn executable_lines(run: &str) -> Vec<&str> {
    run.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .collect()
}

#[test]
fn workflow_yaml_and_trigger_contract_are_preserved() {
    let (_, workflow) = workflow();
    let triggers = &workflow["on"];
    assert_eq!(
        sequence(&triggers["push"], "branches"),
        &vec![Value::String("action".into())]
    );
    assert_eq!(
        sequence(&triggers["push"], "tags"),
        &vec![Value::String("*".into())]
    );
    assert!(triggers["workflow_dispatch"].is_mapping() || triggers["workflow_dispatch"].is_null());
    assert_eq!(
        workflow["concurrency"]["group"].as_str(),
        Some("ci-${{ github.workflow }}-${{ github.ref }}")
    );
    assert_eq!(
        workflow["concurrency"]["cancel-in-progress"].as_bool(),
        Some(true)
    );
}

#[test]
fn preflight_installs_prerequisites_and_runs_canonical_rust_gates() {
    let (_, workflow) = workflow();
    let jobs = &workflow["jobs"];
    let job_names = mapping_keys(jobs);
    for name in ["preflight", "build", "release"] {
        assert!(job_names.contains(name), "missing required job {name}");
        assert_eq!(jobs[name]["runs-on"].as_str(), Some("ubuntu-24.04"));
    }
    let install = named_step(&jobs["preflight"], "Install preflight dependencies")["run"]
        .as_str()
        .unwrap();
    for dependency in [
        "bubblewrap",
        "fuse3",
        "llvm",
        "musl-tools",
        "rust-src",
        "rustfmt",
        "clippy",
    ] {
        assert!(
            install
                .split_whitespace()
                .any(|token| token.trim_end_matches('\\') == dependency),
            "missing preflight dependency {dependency}"
        );
    }
    let namespace_setup = named_step(
        &jobs["preflight"],
        "Enable user namespaces for lifecycle sandbox",
    )["run"]
        .as_str()
        .unwrap();
    assert!(
        namespace_setup.contains("sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0")
    );
    assert!(namespace_setup.contains("bwrap --unshare-user --ro-bind / / true"));
    assert_eq!(
        named_step(
            &jobs["preflight"],
            "Run local quality gates and checksum validation"
        )["run"]
            .as_str(),
        Some("cargo --locked xtask check")
    );
    assert!(jobs["preflight"]["steps"]
        .as_sequence()
        .unwrap()
        .iter()
        .all(|step| step["name"].as_str() != Some("Run foreign AArch64 quality gates under QEMU")));
}

#[test]
fn build_matrix_and_rust_artifact_validation_contract_are_preserved() {
    let (_, workflow) = workflow();
    let build = &workflow["jobs"]["build"];
    assert_eq!(build["needs"].as_str(), Some("preflight"));
    assert_eq!(build["strategy"]["fail-fast"].as_bool(), Some(false));
    let arches = sequence(&build["strategy"]["matrix"], "arch")
        .iter()
        .map(|value| value.as_str().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(
        arches,
        [
            "x86_64",
            "aarch64",
            "riscv64",
            "loongarch64",
            "ppc64",
            "ppc64le"
        ]
    );
    let steps = sequence(build, "steps");
    let step_index = |name: &str| {
        steps
            .iter()
            .position(|step| step["name"].as_str() == Some(name))
            .unwrap_or_else(|| panic!("missing build step {name:?}"))
    };
    let build_index = step_index("Build all runtime variants");
    let validation_index = step_index("Validate artifact manifest and ELF metadata");
    let upload_index = steps
        .iter()
        .position(|step| {
            step["uses"]
                .as_str()
                .is_some_and(|uses| uses.starts_with("actions/upload-artifact@"))
        })
        .unwrap();
    assert!(build_index < validation_index && validation_index < upload_index);
    let qemu_install = named_step(build, "Install QEMU for foreign smoke tests");
    assert_eq!(qemu_install["if"].as_str(), Some("matrix.arch != 'x86_64'"));
    assert_eq!(
        qemu_install["run"].as_str(),
        Some("sudo apt-get install --yes qemu-user-static")
    );
    assert_eq!(
        steps[build_index]["run"].as_str(),
        Some("cargo --locked xtask ${{ matrix.arch }}")
    );
    assert_eq!(
        steps[validation_index]["run"].as_str(),
        Some("cargo --locked xtask artifacts validate-arch '${{ matrix.arch }}' dist --smoke")
    );
    assert_eq!(
        steps[upload_index]["with"]["if-no-files-found"].as_str(),
        Some("error")
    );
}

#[test]
fn release_uses_rust_manifest_tools_and_exact_numeric_release_id() {
    let (_, workflow) = workflow();
    let release = &workflow["jobs"]["release"];
    assert_eq!(release["needs"].as_str(), Some("build"));
    assert_eq!(release["permissions"]["contents"].as_str(), Some("write"));
    let install = named_step(release, "Install release tooling")["run"]
        .as_str()
        .unwrap();
    assert!(executable_lines(install).contains(&"rustup component add rust-src"));
    assert_eq!(
        named_step(release, "Validate and stage the exact release manifest")["run"].as_str(),
        Some("cargo --locked xtask artifacts aggregate-release artifacts release-dist")
    );

    let required_lines = [
        (
            "Create or refresh the exact-tag draft release",
            "release_id=$(cargo --locked xtask artifacts release-id \"$releases_file\" \"$RELEASE_TAG\")",
        ),
        (
            "Delete every old asset from the exact draft release ID",
            "cargo --locked xtask artifacts asset-ids \\",
        ),
        (
            "Verify the exact paginated asset manifest by release ID",
            "cargo --locked xtask artifacts flatten-assets \\",
        ),
        (
            "Verify the exact paginated asset manifest by release ID",
            "cargo --locked xtask artifacts validate-release release-assets.json",
        ),
    ];
    for (step_name, required) in required_lines {
        let run = named_step(release, step_name)["run"].as_str().unwrap();
        assert!(
            executable_lines(run).contains(&required),
            "{step_name}: missing {required:?}"
        );
    }

    for step_name in [
        "Delete every old asset from the exact draft release ID",
        "Upload exactly 54 assets to the draft release ID",
        "Verify the exact paginated asset manifest by release ID",
        "Publish only the verified exact-tag release ID",
    ] {
        let run = named_step(release, step_name)["run"].as_str().unwrap();
        assert!(executable_lines(run).contains(&"[[ $RELEASE_ID =~ ^[0-9]+$ ]]"));
    }

    for step_name in [
        "Verify the remote tag identifies this workflow commit",
        "Re-verify the remote tag immediately before publishing",
    ] {
        let run = named_step(release, step_name)["run"].as_str().unwrap();
        assert_eq!(
            executable_lines(run)
                .iter()
                .filter(|line| line.starts_with("done < <(git ls-remote origin "))
                .count(),
            1,
            "{step_name}"
        );
    }
}

#[test]
fn release_shell_receives_github_expressions_only_through_environment() {
    let (_, workflow) = workflow();
    for step in sequence(&workflow["jobs"]["release"], "steps") {
        assert!(!step["run"].as_str().unwrap_or("").contains("${{"));
    }
}

#[test]
fn actions_are_immutable_known_version_pins() {
    let (_, workflow) = workflow();
    let expected = [
        (
            "actions/checkout",
            "3d3c42e5aac5ba805825da76410c181273ba90b1",
        ),
        (
            "actions/upload-artifact",
            "043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
        ),
        (
            "actions/download-artifact",
            "3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c",
        ),
    ];
    let mut count = 0;
    for job in workflow["jobs"].as_mapping().unwrap().values() {
        for step in sequence(job, "steps") {
            let Some(reference) = step["uses"].as_str() else {
                continue;
            };
            count += 1;
            let (action, sha) = reference.split_once('@').unwrap();
            let expected_sha = expected
                .iter()
                .find_map(|(expected_action, expected_sha)| {
                    (*expected_action == action).then_some(*expected_sha)
                })
                .unwrap_or_else(|| panic!("unknown action {action}"));
            assert_eq!(sha, expected_sha);
            assert_eq!(sha.len(), 40);
            assert!(sha
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()));
        }
    }
    assert!(count >= 5);
}

#[test]
fn every_literal_workflow_cargo_command_uses_the_lockfile() {
    let (_, workflow) = workflow();
    let mut count = 0;
    for job in workflow["jobs"].as_mapping().unwrap().values() {
        for run in step_runs(job) {
            for line in executable_lines(run) {
                let words = line.split_whitespace().collect::<Vec<_>>();
                for (index, _) in words
                    .iter()
                    .enumerate()
                    .filter(|(_, word)| **word == "cargo")
                {
                    count += 1;
                    assert_eq!(words.get(index + 1), Some(&"--locked"), "{line}");
                }
            }
        }
    }
    assert!(count >= 5);
}

fn source_files(root: &Path, relative: &Path, files: &mut Vec<PathBuf>) {
    let directory = root.join(relative);
    for entry in fs::read_dir(&directory).unwrap() {
        let entry = entry.unwrap();
        let name = entry.file_name();
        let child_relative = relative.join(&name);
        let file_type = entry.file_type().unwrap();
        if file_type.is_dir() {
            if matches!(
                name.to_str(),
                Some(".git" | "assets" | "dist" | "release-dist" | "target")
            ) || name.to_string_lossy().starts_with("assets-")
                || (relative == Path::new("xtask") && name == "target")
            {
                continue;
            }
            source_files(root, &child_relative, files);
        } else if file_type.is_file() {
            files.push(child_relative);
        }
    }
}

#[test]
fn documentation_relative_links_resolve() {
    let root = project_root();
    let mut files = Vec::new();
    source_files(&root, Path::new(""), &mut files);
    for relative in files
        .iter()
        .filter(|path| path.extension().is_some_and(|extension| extension == "md"))
    {
        let contents = fs::read_to_string(root.join(relative)).unwrap();
        let base = relative.parent().unwrap_or(Path::new(""));
        let mut remainder = contents.as_str();
        while let Some(start) = remainder.find("](") {
            remainder = &remainder[start + 2..];
            let Some(end) = remainder.find(')') else {
                panic!("unterminated Markdown link in {}", relative.display());
            };
            let target = &remainder[..end];
            remainder = &remainder[end + 1..];
            let target = target.split('#').next().unwrap_or("");
            if target.is_empty()
                || target.starts_with('#')
                || target.contains("://")
                || target.starts_with("mailto:")
            {
                continue;
            }
            let destination = root.join(base).join(target);
            assert!(
                destination.exists(),
                "broken relative link in {}: {target}",
                relative.display()
            );
        }
    }
}
