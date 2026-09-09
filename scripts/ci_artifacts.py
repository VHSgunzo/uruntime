#!/usr/bin/env python3
"""Validate and aggregate uruntime CI artifacts without trusting filenames alone."""

from __future__ import annotations

import argparse
import json
import os
import resource
import signal
import stat
import struct
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class ArchSpec:
    machine: int
    endian: str
    qemu: str | None


ARCHES = {
    "x86_64": ArchSpec(62, "little", None),
    "aarch64": ArchSpec(183, "little", "qemu-aarch64-static"),
    "riscv64": ArchSpec(243, "little", "qemu-riscv64-static"),
    "loongarch64": ArchSpec(258, "little", "qemu-loongarch64-static"),
    "ppc64": ArchSpec(21, "big", "qemu-ppc64-static"),
    "ppc64le": ArchSpec(21, "little", "qemu-ppc64le-static"),
}

VARIANTS = (
    "runimage",
    "runimage-squashfs",
    "runimage-dwarfs",
    "appimage",
    "appimage-lite",
    "appimage-squashfs",
    "appimage-squashfs-lite",
    "appimage-dwarfs",
    "appimage-dwarfs-lite",
)

REQUIRED_SECTIONS = frozenset(
    {".envs", ".upd_info", ".sig_key", ".sha256_sig", ".digest_md5"}
)
PT_INTERP = 3
PT_DYNAMIC = 2
DT_NULL = 0
DT_NEEDED = 1
PN_XNUM = 0xFFFF
MAX_ARTIFACT_SIZE = 64 * 1024 * 1024
MAX_PROGRAM_HEADERS = 128
MAX_SECTION_HEADERS = 1024
MAX_SECTION_NAME_TABLE = 1024 * 1024
MAX_SMOKE_OUTPUT = 64 * 1024


def expected_artifact_names(arch: str) -> list[str]:
    if arch not in ARCHES:
        raise ValueError(f"unsupported architecture: {arch}")
    return [f"uruntime-{variant}-{arch}" for variant in VARIANTS]


def expected_all_artifact_names() -> list[str]:
    return [name for arch in ARCHES for name in expected_artifact_names(arch)]


def _range(offset: int, size: int, length: int, description: str) -> range:
    if offset < 0 or size < 0 or offset > length or size > length - offset:
        raise ValueError(
            f"{description} range {offset}..{offset + size} exceeds file size {length}"
        )
    return range(offset, offset + size)


def _read_regular(path: Path, limit: int = MAX_ARTIFACT_SIZE) -> bytes:
    if path.is_symlink():
        raise ValueError(f"{path}: symlink is not allowed")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise ValueError(f"cannot open {path}: {error}") from error
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError(f"{path}: not a regular file")
        if metadata.st_size > limit:
            raise ValueError(f"{path}: file size {metadata.st_size} exceeds size limit {limit}")
        with os.fdopen(descriptor, "rb", closefd=False) as source:
            data = source.read(limit + 1)
        if len(data) > limit:
            raise ValueError(f"{path}: file exceeds size limit {limit}")
        return data
    finally:
        os.close(descriptor)


def _section_names(table: bytes) -> dict[int, str]:
    names = {}
    offset = 0
    while offset < len(table):
        end = table.find(b"\0", offset)
        if end < 0:
            raise ValueError("unterminated section name table")
        try:
            names[offset] = table[offset:end].decode("ascii")
        except UnicodeDecodeError as error:
            raise ValueError("non-ASCII section name") from error
        offset = end + 1
    return names


def validate_elf(path: Path, arch: str, expected_magic: bytes) -> None:
    data = _read_regular(path)
    _validate_elf_bytes(data, path, arch, expected_magic)


def _validate_elf_bytes(
    data: bytes, path: Path | str, arch: str, expected_magic: bytes
) -> None:
    spec = ARCHES[arch]
    if len(data) < 64 or data[:4] != b"\x7fELF":
        raise ValueError(f"{path}: not an ELF64 file")
    if data[4] != 2:
        raise ValueError(f"{path}: expected ELF64 class, got {data[4]}")
    expected_data = 1 if spec.endian == "little" else 2
    if data[5] != expected_data:
        raise ValueError(
            f"{path}: ELF endian byte {data[5]} does not match {spec.endian}"
        )
    if data[6] != 1:
        raise ValueError(f"{path}: unsupported ELF version {data[6]}")
    if data[8:11] != expected_magic:
        raise ValueError(
            f"{path}: runtime magic {data[8:11].hex()} does not match {expected_magic.hex()}"
        )

    order = "<" if spec.endian == "little" else ">"
    machine = struct.unpack_from(order + "H", data, 18)[0]
    if machine != spec.machine:
        raise ValueError(
            f"{path}: ELF machine {machine} does not match {spec.machine} for {arch}"
        )
    ehsize = struct.unpack_from(order + "H", data, 52)[0]
    if ehsize != 64:
        raise ValueError(f"{path}: invalid ELF64 header size {ehsize}")

    phoff = struct.unpack_from(order + "Q", data, 32)[0]
    phentsize, phnum = struct.unpack_from(order + "HH", data, 54)
    if phnum == PN_XNUM:
        raise ValueError(f"{path}: extended program-header numbering is unsupported")
    if phentsize != 56 or phnum == 0 or phnum > MAX_PROGRAM_HEADERS:
        raise ValueError(
            f"{path}: invalid program header dimensions ({phentsize}, {phnum})"
        )
    ph_table = _range(phoff, phentsize * phnum, len(data), "program header table")
    for index in range(phnum):
        offset = ph_table.start + index * phentsize
        p_type = struct.unpack_from(order + "I", data, offset)[0]
        p_offset = struct.unpack_from(order + "Q", data, offset + 8)[0]
        p_filesz = struct.unpack_from(order + "Q", data, offset + 32)[0]
        segment = _range(p_offset, p_filesz, len(data), f"program header {index}")
        if p_type == PT_INTERP:
            raise ValueError(f"{path}: static contract violated by PT_INTERP")
        if p_type == PT_DYNAMIC:
            if len(segment) % 16:
                raise ValueError(f"{path}: malformed PT_DYNAMIC table")
            terminated = False
            for dynamic_offset in range(segment.start, segment.stop, 16):
                tag = struct.unpack_from(order + "Q", data, dynamic_offset)[0]
                if tag == DT_NULL:
                    terminated = True
                    break
                if tag == DT_NEEDED:
                    raise ValueError(f"{path}: static contract violated by DT_NEEDED")
            if not terminated:
                raise ValueError(f"{path}: unterminated PT_DYNAMIC table")

    shoff = struct.unpack_from(order + "Q", data, 40)[0]
    shentsize, shnum, shstrndx = struct.unpack_from(order + "HHH", data, 58)
    if (
        shentsize != 64
        or shnum == 0
        or shnum > MAX_SECTION_HEADERS
        or shstrndx == 0xFFFF
        or shstrndx >= shnum
    ):
        raise ValueError(
            f"{path}: invalid or unsupported section header dimensions/index "
            f"({shentsize}, {shnum}, {shstrndx})"
        )
    sh_table = _range(shoff, shentsize * shnum, len(data), "section header table")

    def section_header(index: int) -> tuple[int, int, int, int]:
        offset = sh_table.start + index * shentsize
        name_offset, section_type = struct.unpack_from(order + "II", data, offset)
        file_offset, size = struct.unpack_from(order + "QQ", data, offset + 24)
        return name_offset, section_type, file_offset, size

    _, _, names_offset, names_size = section_header(shstrndx)
    if names_size > MAX_SECTION_NAME_TABLE:
        raise ValueError(f"{path}: section name table exceeds size limit")
    names_range = _range(names_offset, names_size, len(data), "section string table")
    names_table = data[names_range.start:names_range.stop]
    section_names = _section_names(names_table)
    present = set()
    for index in range(1, shnum):
        name_offset, section_type, file_offset, size = section_header(index)
        if section_type != 8:  # SHT_NOBITS has no file-backed range.
            _range(file_offset, size, len(data), f"section {index}")
        try:
            present.add(section_names[name_offset])
        except KeyError as error:
            raise ValueError(f"section name offset {name_offset} is not a string boundary") from error
    missing = sorted(REQUIRED_SECTIONS - present)
    if missing:
        raise ValueError(f"{path}: missing required runtime section(s): {', '.join(missing)}")


def _directory_files(directory: Path) -> set[str]:
    if directory.is_symlink():
        raise ValueError(f"artifact path must not be a symlink: {directory}")
    if not directory.is_dir():
        raise ValueError(f"artifact path is not a directory: {directory}")
    entries = list(directory.iterdir())
    invalid = sorted(entry.name for entry in entries if not entry.is_file() or entry.is_symlink())
    if invalid:
        raise ValueError(f"non-regular artifact entries: {', '.join(invalid)}")
    return {entry.name for entry in entries}


def _write_exclusive(path: Path, data: bytes, mode: int = 0o755) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags, mode)
    except OSError as error:
        raise ValueError(f"cannot create exclusive output {path}: {error}") from error
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as output:
            output.write(data)
            output.flush()
            os.fsync(descriptor)
    except OSError as error:
        try:
            path.unlink()
        except OSError:
            pass
        raise ValueError(f"cannot stage {path}: {error}") from error
    finally:
        os.close(descriptor)


def _set_smoke_limits() -> None:
    resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_SMOKE_OUTPUT, MAX_SMOKE_OUTPUT))


def _smoke_validated_bytes(arch: str, name: str, data: bytes) -> None:
    if name not in expected_artifact_names(arch):
        raise ValueError(f"unexpected smoke-test artifact name: {name}")
    with tempfile.TemporaryDirectory(prefix="uruntime-smoke-") as temporary:
        private_binary = Path(temporary) / name
        _write_exclusive(private_binary, data, 0o700)
        command = smoke_command(arch, private_binary)
        try:
            with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
                result = subprocess.run(
                    command,
                    check=False,
                    stdout=stdout,
                    stderr=stderr,
                    timeout=30,
                    preexec_fn=_set_smoke_limits,
                )
                stdout.seek(0)
                stderr.seek(0)
                stdout_bytes = stdout.read(MAX_SMOKE_OUTPUT + 1)
                stderr_bytes = stderr.read(MAX_SMOKE_OUTPUT + 1)
        except (OSError, subprocess.TimeoutExpired) as error:
            raise ValueError(f"smoke test failed to execute {name}: {error}") from error
        if (
            result.returncode in (-signal.SIGXFSZ, 128 + signal.SIGXFSZ)
            or len(stdout_bytes) > MAX_SMOKE_OUTPUT
            or len(stderr_bytes) > MAX_SMOKE_OUTPUT
        ):
            raise ValueError(f"smoke test output limit exceeded for {name}")
        stderr_text = stderr_bytes.decode(errors="replace")
        if result.returncode != 0:
            raise ValueError(
                f"smoke test failed for {name} ({result.returncode}): {stderr_text.strip()}"
            )
        stdout_text = stdout_bytes.decode(errors="replace")
        if not stdout_text.strip().startswith("v"):
            raise ValueError(f"smoke test returned unexpected version for {name}")


def validate_arch(directory: Path, arch: str, smoke: bool = False) -> None:
    if arch not in ARCHES:
        raise ValueError(f"unsupported architecture: {arch}")
    expected = set(expected_artifact_names(arch))
    actual = _directory_files(directory)
    missing = sorted(expected - actual)
    unexpected = sorted(actual - expected)
    if missing or unexpected:
        raise ValueError(
            f"artifact manifest mismatch for {arch}; missing={missing}, unexpected={unexpected}"
        )
    for name in sorted(expected):
        path = directory / name
        magic = b"AI\x02" if name.startswith("uruntime-appimage") else b"RI\x02"
        data = _read_regular(path)
        _validate_elf_bytes(data, path, arch, magic)
        if smoke:
            _smoke_validated_bytes(arch, name, data)
    print(f"validated {len(expected)} {arch} artifacts")


def smoke_command(arch: str, binary: Path) -> list[str]:
    if arch not in ARCHES:
        raise ValueError(f"unsupported architecture: {arch}")
    prefix = "appimage" if binary.name.startswith("uruntime-appimage") else "runtime"
    command = [str(binary), f"--{prefix}-version"]
    qemu = ARCHES[arch].qemu
    if qemu:
        command.insert(0, qemu)
    return command


def aggregate_release(downloads: Path, output: Path) -> None:
    expected_directories = {f"uruntime-{arch}" for arch in ARCHES}
    if downloads.is_symlink():
        raise ValueError(f"download path must not be a symlink: {downloads}")
    if not downloads.is_dir():
        raise ValueError(f"download path is not a directory: {downloads}")
    actual_directories = {entry.name for entry in downloads.iterdir()}
    if actual_directories != expected_directories:
        raise ValueError(
            "unexpected artifact directories; "
            f"missing={sorted(expected_directories - actual_directories)}, "
            f"unexpected={sorted(actual_directories - expected_directories)}"
        )
    if output.is_symlink():
        raise ValueError(f"release output must not be a symlink: {output}")
    if output.exists() and any(output.iterdir()):
        raise ValueError(f"release output is not empty (stale files): {output}")
    output.mkdir(parents=True, exist_ok=True)

    seen = set()
    for arch in ARCHES:
        source_directory = downloads / f"uruntime-{arch}"
        expected_arch = set(expected_artifact_names(arch))
        actual_arch = _directory_files(source_directory)
        if actual_arch != expected_arch:
            raise ValueError(
                f"artifact manifest mismatch for {arch}; "
                f"missing={sorted(expected_arch - actual_arch)}, "
                f"unexpected={sorted(actual_arch - expected_arch)}"
            )
        for name in expected_artifact_names(arch):
            if name in seen:
                raise ValueError(f"duplicate release artifact: {name}")
            source = source_directory / name
            magic = b"AI\x02" if name.startswith("uruntime-appimage") else b"RI\x02"
            data = _read_regular(source)
            _validate_elf_bytes(data, source, arch, magic)
            seen.add(name)
            _write_exclusive(output / name, data)

    expected = set(expected_all_artifact_names())
    if seen != expected or _directory_files(output) != expected:
        raise ValueError("release staging manifest does not contain exactly 54 artifacts")
    print(f"staged {len(seen)} release artifacts in {output}")


def validate_release(release_json: Path) -> None:
    try:
        assets = json.loads(release_json.read_text())
        if not isinstance(assets, list):
            raise TypeError("release assets payload must be a JSON list")
        names = [asset["name"] for asset in assets]
    except (OSError, json.JSONDecodeError, KeyError, TypeError) as error:
        raise ValueError(f"invalid release metadata: {error}") from error
    expected = set(expected_all_artifact_names())
    if len(names) != len(set(names)) or set(names) != expected:
        raise ValueError(
            "published release manifest mismatch; "
            f"missing={sorted(expected - set(names))}, unexpected={sorted(set(names) - expected)}"
        )
    print("validated exact 54-asset published release manifest")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    arch_parser = subparsers.add_parser("validate-arch")
    arch_parser.add_argument("arch", choices=ARCHES)
    arch_parser.add_argument("directory", type=Path)
    arch_parser.add_argument("--smoke", action="store_true")
    aggregate_parser = subparsers.add_parser("aggregate-release")
    aggregate_parser.add_argument("downloads", type=Path)
    aggregate_parser.add_argument("output", type=Path)
    release_parser = subparsers.add_parser("validate-release")
    release_parser.add_argument("metadata", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.command == "validate-arch":
            validate_arch(args.directory, args.arch, args.smoke)
        elif args.command == "aggregate-release":
            aggregate_release(args.downloads, args.output)
        else:
            validate_release(args.metadata)
    except ValueError as error:
        parser.exit(1, f"error: {error}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
