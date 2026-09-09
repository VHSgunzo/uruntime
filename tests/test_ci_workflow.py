#!/usr/bin/env python3
import re
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_PATH = ROOT / ".github" / "workflows" / "ci.yml"
ARCHES = ["x86_64", "aarch64", "riscv64", "loongarch64", "ppc64", "ppc64le"]
PINNED_ACTIONS = {
    "actions/checkout": ("3d3c42e5aac5ba805825da76410c181273ba90b1", "v7.0.1"),
    "actions/upload-artifact": ("043fb46d1a93c77aae656e7c1c64a875d1fc6a0a", "v7.0.1"),
    "actions/download-artifact": ("3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c", "v8.0.1"),
}


class WorkflowContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.raw = WORKFLOW_PATH.read_text()
        cls.workflow = yaml.load(cls.raw, Loader=yaml.BaseLoader)
        cls.jobs = cls.workflow["jobs"]

    def test_yaml_and_existing_trigger_contract(self):
        triggers = self.workflow["on"]
        self.assertEqual(["action"], triggers["push"]["branches"])
        self.assertEqual(["*"], triggers["push"]["tags"])
        self.assertIn("workflow_dispatch", triggers)
        self.assertEqual("ci-${{ github.workflow }}-${{ github.ref }}", self.workflow["concurrency"]["group"])
        self.assertEqual("true", self.workflow["concurrency"]["cancel-in-progress"])

    def test_preflight_uses_the_canonical_xtask_check_command(self):
        self.assertEqual({"preflight", "build", "release"}, set(self.jobs))
        preflight = self.jobs["preflight"]
        self.assertEqual("ubuntu-24.04", preflight["runs-on"])
        self.assertEqual("ubuntu-24.04", self.jobs["build"]["runs-on"])
        self.assertEqual("ubuntu-24.04", self.jobs["release"]["runs-on"])
        runs = [step.get("run", "") for step in preflight["steps"]]
        combined = "\n".join(runs)
        for component in ("rust-src", "rustfmt", "clippy"):
            self.assertIn(component, runs[1])
        self.assertIn("cargo --locked xtask check", combined)
        self.assertIn("python3 -m unittest discover -s tests -p 'test_ci_*.py' -v", combined)
        self.assertIn("python3-yaml", runs[1])
        self.assertIn("llvm", runs[1])
        self.assertNotIn("cargo --locked fmt --check", combined)
        self.assertNotIn("cargo --locked xtask update-checksums --check", combined)
        self.assertNotIn("qemu", combined.lower())

    def test_build_is_six_arch_fail_slow_matrix_using_xtask(self):
        build = self.jobs["build"]
        self.assertEqual("preflight", build["needs"])
        self.assertEqual("false", build["strategy"]["fail-fast"])
        self.assertEqual(ARCHES, build["strategy"]["matrix"]["arch"])
        runs = "\n".join(step.get("run", "") for step in build["steps"])
        self.assertIn("cargo --locked xtask ${{ matrix.arch }}", runs)
        self.assertNotRegex(runs, r"cargo\s+install\s+cross|\bcross\b|\bupx\b")
        self.assertNotIn("ziglang.org", self.raw)

    def test_qemu_is_installed_only_for_foreign_smoke_tests(self):
        steps = self.jobs["build"]["steps"]
        qemu_steps = [step for step in steps if "qemu-user-static" in step.get("run", "")]
        self.assertEqual(1, len(qemu_steps))
        self.assertEqual("matrix.arch != 'x86_64'", qemu_steps[0]["if"])
        build_index = next(i for i, step in enumerate(steps) if "cargo --locked xtask ${{ matrix.arch }}" in step.get("run", ""))
        qemu_index = steps.index(qemu_steps[0])
        self.assertGreater(qemu_index, build_index, "QEMU must not be available during the build")
        validation = [step for step in steps if "ci_artifacts.py validate-arch" in step.get("run", "")]
        self.assertEqual(1, len(validation))
        self.assertIn("--smoke", validation[0]["run"])

    def test_each_build_validates_then_uploads_one_arch_artifact(self):
        steps = self.jobs["build"]["steps"]
        validate_index = next(i for i, step in enumerate(steps) if "validate-arch" in step.get("run", ""))
        upload_index = next(i for i, step in enumerate(steps) if step.get("uses", "").startswith("actions/upload-artifact@"))
        self.assertLess(validate_index, upload_index)
        upload = steps[upload_index]["with"]
        self.assertEqual("uruntime-${{ matrix.arch }}", upload["name"])
        self.assertEqual("error", upload["if-no-files-found"])
        self.assertIn("${{ matrix.arch }}", upload["path"])

    def test_release_safely_creates_or_refreshes_same_tag_by_numeric_id(self):
        release = self.jobs["release"]
        self.assertEqual("build", release["needs"])
        condition = release["if"]
        self.assertIn("github.event_name == 'push'", condition)
        self.assertIn("startsWith(github.ref, 'refs/tags/')", condition)
        self.assertEqual("write", release["permissions"]["contents"])

        steps = release["steps"]
        runs = [step.get("run", "") for step in steps]
        combined = "\n".join(runs)
        aggregate_index = next(i for i, run in enumerate(runs) if "aggregate-release" in run)
        acquire_index = next(i for i, run in enumerate(runs) if "--method POST" in run and "--method PATCH" in run)
        delete_index = next(i for i, run in enumerate(runs) if "--method DELETE" in run)
        upload_index = next(i for i, run in enumerate(runs) if "uploads.github.com" in run)
        verify_index = next(i for i, run in enumerate(runs) if "validate-release" in run)
        tag_check_indices = [i for i, run in enumerate(runs) if "git ls-remote" in run]
        self.assertEqual(2, len(tag_check_indices))
        initial_tag_check_index, tag_recheck_index = tag_check_indices
        publish_index = next(i for i, run in enumerate(runs) if "draft=false" in run and "--method PATCH" in run)
        self.assertLess(aggregate_index, initial_tag_check_index)
        self.assertLess(initial_tag_check_index, acquire_index)
        self.assertLess(acquire_index, delete_index)
        self.assertLess(delete_index, upload_index)
        self.assertLess(upload_index, verify_index)
        self.assertLess(verify_index, tag_recheck_index)
        self.assertLess(tag_recheck_index, publish_index)

        self.assertNotIn("softprops/action-gh-release", self.raw)
        self.assertNotIn("releases/tags/$RELEASE_TAG", combined)
        acquire = runs[acquire_index]
        self.assertIn("gh api --paginate --slurp", acquire)
        self.assertIn("releases?per_page=100", acquire)
        self.assertIn("len(matches) > 1", acquire)
        self.assertIn("--method POST", acquire)
        self.assertIn("--method PATCH", acquire)
        self.assertIn("releases/$release_id", acquire)
        self.assertIn('if [[ -n "$release_id" ]]', acquire)
        self.assertIn("release_action=refreshed", acquire)
        self.assertIn("release_action=created", acquire)
        for field in ("target_commitish", "tag_name", "name", "body"):
            self.assertIn(field, acquire)
        for field in ("draft=true", "prerelease=false", "generate_release_notes=false", "make_latest=false"):
            self.assertIn(field, acquire)
        self.assertIn("RELEASE_MARKER", acquire)
        self.assertIn(".id == $id", acquire)
        self.assertIn(".tag_name == $tag", acquire)
        deletion = runs[delete_index]
        self.assertIn("releases/$RELEASE_ID/assets?per_page=100", deletion)
        self.assertIn("releases/assets/$asset_id", deletion)
        self.assertIn("--paginate", deletion)
        self.assertIn("--slurp", deletion)
        self.assertIn(".id == $id", deletion)
        self.assertIn(".tag_name == $tag", deletion)
        self.assertIn(".draft == true", deletion)
        self.assertIn("RELEASE_ID", runs[upload_index])
        self.assertIn("releases/$RELEASE_ID/assets", runs[upload_index])
        self.assertIn('--data-binary "@$file"', runs[upload_index])
        self.assertIn('Authorization: Bearer ', runs[upload_index])
        self.assertIn("--paginate", runs[verify_index])
        self.assertIn("--slurp", runs[verify_index])
        self.assertIn("releases/$RELEASE_ID/assets?per_page=100", runs[verify_index])
        self.assertIn("releases/$RELEASE_ID", runs[publish_index])
        self.assertIn("draft=false", runs[publish_index])
        self.assertIn("generate_release_notes=false", runs[publish_index])
        self.assertIn("make_latest=legacy", runs[publish_index])
        self.assertIn("RELEASE_MARKER", runs[publish_index])
        self.assertIn("published-release-readback.json", runs[publish_index])
        self.assertRegex(combined, r"\[\[ \$RELEASE_ID =~ \^\[0-9\]\+\$ \]\]")

        expected_id = "${{ steps.acquire_release.outputs.release_id }}"
        for index in (delete_index, upload_index, verify_index, publish_index):
            self.assertEqual(expected_id, steps[index]["env"]["RELEASE_ID"])

    def test_every_cargo_command_uses_the_committed_lockfile(self):
        commands = re.findall(r"\bcargo --locked [^\n]+", self.raw)
        self.assertGreaterEqual(len(commands), 2)
        self.assertNotRegex(self.raw, r"\bcargo\s+(?!--locked\b)")

    def test_release_shell_receives_expressions_only_through_environment(self):
        release = self.jobs["release"]
        for step in release["steps"]:
            run = step.get("run", "")
            self.assertNotIn("${{", run, step.get("name", "unnamed step"))

    def test_every_action_is_an_immutable_current_version_pin_with_comment(self):
        uses = re.findall(r"^\s*uses:\s*([^\s#]+)(?:\s+#\s*(\S+))?", self.raw, re.MULTILINE)
        self.assertGreaterEqual(len(uses), 5)
        for action_ref, comment in uses:
            action, separator, sha = action_ref.partition("@")
            self.assertTrue(separator, action_ref)
            self.assertRegex(sha, r"^[0-9a-f]{40}$")
            self.assertIn(action, PINNED_ACTIONS)
            expected_sha, expected_version = PINNED_ACTIONS[action]
            self.assertEqual(expected_sha, sha)
            self.assertEqual(expected_version, comment)


if __name__ == "__main__":
    unittest.main()
