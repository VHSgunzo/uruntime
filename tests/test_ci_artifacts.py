#!/usr/bin/env python3
import importlib.util
import json
import struct
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "ci_artifacts.py"


def load_module():
    spec = importlib.util.spec_from_file_location("ci_artifacts", MODULE_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {MODULE_PATH}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def make_elf(path: Path, *, machine: int, endian: str, magic: bytes, interp: bool = False,
             needed: bool = False,
             omit_section: str | None = None, nobits_outside: bool = False):
    order = "<" if endian == "little" else ">"
    names = [".envs", ".upd_info", ".sig_key", ".sha256_sig", ".digest_md5"]
    if omit_section:
        names.remove(omit_section)
    if nobits_outside:
        names.append(".bss")
    shstr = b"\0"
    name_offsets = {}
    for name in names + [".shstrtab"]:
        name_offsets[name] = len(shstr)
        shstr += name.encode() + b"\0"

    phnum = 2 if interp or needed else 1
    shnum = 1 + len(names) + 1
    phoff = 64
    shstr_offset = 256
    data_offset = 384
    shoff = 512
    size = shoff + shnum * 64
    image = bytearray(size)
    image[:4] = b"\x7fELF"
    image[4:8] = bytes((2, 1 if endian == "little" else 2, 1, 0))
    image[8:11] = magic
    struct.pack_into(order + "HHIQQQIHHHHHH", image, 16,
                     3, machine, 1, 0, phoff, shoff, 0, 64, 56, phnum, 64, shnum,
                     shnum - 1)
    struct.pack_into(order + "IIQQQQQQ", image, phoff,
                     1, 5, 0, 0, 0, size, size, 0x1000)
    if interp:
        struct.pack_into(order + "IIQQQQQQ", image, phoff + 56,
                         3, 4, data_offset, 0, 0, 8, 8, 1)
    if needed:
        struct.pack_into(order + "IIQQQQQQ", image, phoff + 56,
                         2, 4, data_offset + 64, 0, 0, 32, 32, 8)
    image[shstr_offset:shstr_offset + len(shstr)] = shstr
    for index, name in enumerate(names, 1):
        image[data_offset + index] = index
        section_type = 8 if name == ".bss" else 1
        section_offset = size + 4096 if name == ".bss" else data_offset + index
        section_size = 8192 if name == ".bss" else 1
        struct.pack_into(order + "IIQQQQIIQQ", image, shoff + index * 64,
                         name_offsets[name], section_type, 0, 0, section_offset, section_size,
                         0, 0, 1, 0)
    struct.pack_into(order + "IIQQQQIIQQ", image, shoff + (shnum - 1) * 64,
                     name_offsets[".shstrtab"], 3, 0, 0, shstr_offset, len(shstr), 0, 0, 1, 0)
    if needed:
        struct.pack_into(order + "QQQQ", image, data_offset + 64, 1, 1, 0, 0)
    path.write_bytes(image)
    path.chmod(0o755)


class ArtifactValidationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ci = load_module()

    def populate_arch(self, root: Path, arch: str):
        spec = self.ci.ARCHES[arch]
        for name in self.ci.expected_artifact_names(arch):
            magic = b"AI\x02" if "appimage" in name else b"RI\x02"
            make_elf(root / name, machine=spec.machine, endian=spec.endian, magic=magic)

    def test_expected_manifest_has_nine_unique_files_per_arch(self):
        all_names = []
        for arch in self.ci.ARCHES:
            names = self.ci.expected_artifact_names(arch)
            self.assertEqual(9, len(names))
            self.assertEqual(9, len(set(names)))
            all_names.extend(names)
        self.assertEqual(54, len(set(all_names)))

    def test_validate_arch_checks_exact_manifest_and_big_endian_elf_contract(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.populate_arch(root, "ppc64")
            self.ci.validate_arch(root, "ppc64")
            (root / "stale-file").write_text("stale")
            with self.assertRaisesRegex(ValueError, "unexpected"):
                self.ci.validate_arch(root, "ppc64")

    def test_validate_arch_rejects_missing_static_sections_and_wrong_magic(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.populate_arch(root, "aarch64")
            victim = root / "uruntime-appimage-aarch64"
            make_elf(victim, machine=183, endian="little", magic=b"RI\x02",
                     omit_section=".upd_info")
            with self.assertRaisesRegex(ValueError, "magic|section"):
                self.ci.validate_arch(root, "aarch64")

    def test_validate_arch_rejects_dynamic_interpreter(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.populate_arch(root, "x86_64")
            victim = root / "uruntime-runimage-x86_64"
            make_elf(victim, machine=62, endian="little", magic=b"RI\x02", interp=True)
            with self.assertRaisesRegex(ValueError, "PT_INTERP"):
                self.ci.validate_arch(root, "x86_64")

    def test_validate_arch_rejects_needed_shared_library(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.populate_arch(root, "x86_64")
            victim = root / "uruntime-runimage-x86_64"
            make_elf(victim, machine=62, endian="little", magic=b"RI\x02", needed=True)
            with self.assertRaisesRegex(ValueError, "DT_NEEDED"):
                self.ci.validate_arch(root, "x86_64")

    def test_validate_elf_rejects_oversized_files_and_extended_program_numbering(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            oversized = root / "oversized"
            with oversized.open("wb") as output:
                output.truncate(self.ci.MAX_ARTIFACT_SIZE + 1)
            with self.assertRaisesRegex(ValueError, "size limit"):
                self.ci.validate_elf(oversized, "x86_64", b"RI\x02")

            binary = root / "extended"
            make_elf(binary, machine=62, endian="little", magic=b"RI\x02")
            data = bytearray(binary.read_bytes())
            struct.pack_into("<H", data, 56, 0xFFFF)
            binary.write_bytes(data)
            with self.assertRaisesRegex(ValueError, "extended program-header numbering"):
                self.ci.validate_elf(binary, "x86_64", b"RI\x02")

    def test_artifact_roots_and_files_must_not_be_symlinks(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            real = root / "real"
            real.mkdir()
            linked = root / "linked"
            linked.symlink_to(real, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "symlink"):
                self.ci.validate_arch(linked, "x86_64")

            binary = real / "uruntime-runimage-x86_64"
            target = real / "target"
            make_elf(target, machine=62, endian="little", magic=b"RI\x02")
            binary.symlink_to(target.name)
            with self.assertRaisesRegex(ValueError, "symlink"):
                self.ci.validate_elf(binary, "x86_64", b"RI\x02")

    def test_validate_elf_allows_non_file_backed_nobits_section(self):
        with tempfile.TemporaryDirectory() as temporary:
            binary = Path(temporary) / "uruntime-runimage-x86_64"
            make_elf(
                binary,
                machine=62,
                endian="little",
                magic=b"RI\x02",
                nobits_outside=True,
            )
            self.ci.validate_elf(binary, "x86_64", b"RI\x02")

    def test_release_aggregation_requires_six_named_inputs_and_stages_exactly_54(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "downloads"
            output = Path(temporary) / "release"
            root.mkdir()
            for arch in self.ci.ARCHES:
                artifact = root / f"uruntime-{arch}"
                artifact.mkdir()
                self.populate_arch(artifact, arch)
            self.ci.aggregate_release(root, output)
            self.assertEqual(54, len(list(output.iterdir())))
            self.assertEqual(set(self.ci.expected_all_artifact_names()), {p.name for p in output.iterdir()})

    def test_release_aggregation_rejects_duplicates_and_stale_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "downloads"
            output = Path(temporary) / "release"
            root.mkdir()
            for arch in self.ci.ARCHES:
                artifact = root / f"uruntime-{arch}"
                artifact.mkdir()
                self.populate_arch(artifact, arch)
            duplicate_dir = root / "stale-artifact"
            duplicate_dir.mkdir()
            source = root / "uruntime-x86_64" / "uruntime-runimage-x86_64"
            (duplicate_dir / source.name).write_bytes(source.read_bytes())
            with self.assertRaisesRegex(ValueError, "unexpected artifact directories|duplicate"):
                self.ci.aggregate_release(root, output)

    def test_published_release_requires_exactly_the_54_expected_assets(self):
        with tempfile.TemporaryDirectory() as temporary:
            metadata = Path(temporary) / "release.json"
            names = self.ci.expected_all_artifact_names()
            metadata.write_text(json.dumps([{"name": name} for name in names]))
            self.ci.validate_release(metadata)
            metadata.write_text(json.dumps([{"name": name} for name in names[:-1]]))
            with self.assertRaisesRegex(ValueError, "published release manifest mismatch"):
                self.ci.validate_release(metadata)

    def test_validate_arch_reads_once_then_smokes_the_validated_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.populate_arch(root, "x86_64")
            reads = []
            original_read = self.ci._read_regular

            def recording_read(path, limit=self.ci.MAX_ARTIFACT_SIZE):
                reads.append(path)
                return original_read(path, limit)

            with (
                mock.patch.object(self.ci, "_read_regular", side_effect=recording_read),
                mock.patch.object(self.ci, "_smoke_validated_bytes") as smoke,
            ):
                self.ci.validate_arch(root, "x86_64", smoke=True)

            self.assertEqual(9, len(reads))
            self.assertEqual(9, len(set(reads)))
            self.assertEqual(9, smoke.call_count)
            for call in smoke.call_args_list:
                arch, name, data = call.args
                self.assertEqual("x86_64", arch)
                self.assertIn(name, self.ci.expected_artifact_names(arch))
                self.assertIsInstance(data, bytes)
                self.assertTrue(data.startswith(b"\x7fELF"))

    def test_smoke_runs_a_private_executable_copy_and_enforces_each_output_limit(self):
        good = b"#!/bin/sh\nprintf 'v-private-copy\\n'\n"
        self.ci._smoke_validated_bytes("x86_64", "uruntime-runimage-x86_64", good)

        for redirect in ("", " >&2"):
            noisy = (
                "#!/bin/sh\n"
                "while :; do printf '0123456789abcdef0123456789abcdef'"
                f"{redirect}; done\n"
            ).encode()
            with self.subTest(redirect=redirect), self.assertRaisesRegex(
                ValueError, "output limit|signal|failed"
            ):
                self.ci._smoke_validated_bytes(
                    "x86_64", "uruntime-runimage-x86_64", noisy
                )

    def test_exclusive_staging_refuses_to_clobber(self):
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "artifact"
            destination.write_bytes(b"existing")
            with self.assertRaisesRegex(ValueError, "already exists|exclusive"):
                self.ci._write_exclusive(destination, b"replacement")
            self.assertEqual(b"existing", destination.read_bytes())

    def test_release_aggregation_stages_the_bytes_that_were_validated_without_reopen(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "downloads"
            output = Path(temporary) / "release"
            root.mkdir()
            for arch in self.ci.ARCHES:
                artifact = root / f"uruntime-{arch}"
                artifact.mkdir()
                self.populate_arch(artifact, arch)

            victim = root / "uruntime-x86_64" / "uruntime-runimage-x86_64"
            validated_bytes = victim.read_bytes()
            original_read = self.ci._read_regular
            victim_reads = 0

            def swap_after_read(path, limit=self.ci.MAX_ARTIFACT_SIZE):
                nonlocal victim_reads
                data = original_read(path, limit)
                if path == victim:
                    victim_reads += 1
                    victim.write_bytes(b"unvalidated replacement")
                return data

            with mock.patch.object(self.ci, "_read_regular", side_effect=swap_after_read):
                self.ci.aggregate_release(root, output)

            self.assertEqual(1, victim_reads)
            self.assertEqual(validated_bytes, (output / victim.name).read_bytes())

    def test_validate_elf_rejects_bounded_metadata_dimensions(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for field_offset, value, message in (
                (60, self.ci.MAX_SECTION_HEADERS + 1, "section header"),
                (56, self.ci.MAX_PROGRAM_HEADERS + 1, "program header"),
            ):
                binary = root / f"bounded-{field_offset}"
                make_elf(binary, machine=62, endian="little", magic=b"RI\x02")
                data = bytearray(binary.read_bytes())
                struct.pack_into("<H", data, field_offset, value)
                binary.write_bytes(data)
                with self.subTest(field_offset=field_offset), self.assertRaisesRegex(
                    ValueError, message
                ):
                    self.ci.validate_elf(binary, "x86_64", b"RI\x02")

            binary = root / "large-name-table"
            make_elf(binary, machine=62, endian="little", magic=b"RI\x02")
            data = bytearray(binary.read_bytes())
            shoff = struct.unpack_from("<Q", data, 40)[0]
            shnum = struct.unpack_from("<H", data, 60)[0]
            struct.pack_into(
                "<Q", data, shoff + (shnum - 1) * 64 + 32,
                self.ci.MAX_SECTION_NAME_TABLE + 1,
            )
            binary.write_bytes(data)
            with self.assertRaisesRegex(ValueError, "section name table"):
                self.ci.validate_elf(binary, "x86_64", b"RI\x02")

    def test_foreign_smoke_command_uses_arch_specific_static_qemu(self):
        binary = Path("dist/uruntime-appimage-loongarch64")
        self.assertEqual(
            ["qemu-loongarch64-static", str(binary), "--appimage-version"],
            self.ci.smoke_command("loongarch64", binary),
        )
        native = Path("dist/uruntime-runimage-x86_64")
        self.assertEqual([str(native), "--runtime-version"], self.ci.smoke_command("x86_64", native))


if __name__ == "__main__":
    unittest.main()
