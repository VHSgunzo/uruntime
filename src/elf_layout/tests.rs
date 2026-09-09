use super::read_elf_prefix;
use std::io::{Cursor, Read, Result};

struct CountingCursor {
    inner: Cursor<Vec<u8>>,
    bytes_read: usize,
}

impl CountingCursor {
    fn new(bytes: Vec<u8>) -> Self {
        Self {
            inner: Cursor::new(bytes),
            bytes_read: 0,
        }
    }
}

impl Read for CountingCursor {
    fn read(&mut self, buffer: &mut [u8]) -> Result<usize> {
        let count = self.inner.read(buffer)?;
        self.bytes_read += count;
        Ok(count)
    }
}

#[derive(Clone, Copy)]
pub(crate) enum Endian {
    Little,
    Big,
}

impl Endian {
    fn ei_data(self) -> u8 {
        match self {
            Self::Little => 1,
            Self::Big => 2,
        }
    }
}

fn put_u16(bytes: &mut [u8], offset: usize, value: u16, endian: Endian) {
    let raw = match endian {
        Endian::Little => value.to_le_bytes(),
        Endian::Big => value.to_be_bytes(),
    };
    bytes[offset..offset + 2].copy_from_slice(&raw);
}

fn put_u32(bytes: &mut [u8], offset: usize, value: u32, endian: Endian) {
    let raw = match endian {
        Endian::Little => value.to_le_bytes(),
        Endian::Big => value.to_be_bytes(),
    };
    bytes[offset..offset + 4].copy_from_slice(&raw);
}

fn put_u64(bytes: &mut [u8], offset: usize, value: u64, endian: Endian) {
    let raw = match endian {
        Endian::Little => value.to_le_bytes(),
        Endian::Big => value.to_be_bytes(),
    };
    bytes[offset..offset + 8].copy_from_slice(&raw);
}

pub(crate) fn fixture(endian: Endian) -> Vec<u8> {
    const PHOFF: usize = 64;
    const SHOFF: usize = 0x180;
    const SECTION_DATA_END: usize = 0x320;
    const SEGMENT_END: usize = 0x380;

    let mut bytes = vec![0; SEGMENT_END];
    bytes[0..4].copy_from_slice(b"\x7fELF");
    bytes[4] = 2;
    bytes[5] = endian.ei_data();
    bytes[6] = 1;
    put_u16(&mut bytes, 16, 2, endian);
    put_u16(&mut bytes, 18, 21, endian);
    put_u32(&mut bytes, 20, 1, endian);
    put_u64(&mut bytes, 32, PHOFF as u64, endian);
    put_u64(&mut bytes, 40, SHOFF as u64, endian);
    put_u16(&mut bytes, 52, 64, endian);
    put_u16(&mut bytes, 54, 56, endian);
    put_u16(&mut bytes, 56, 1, endian);
    put_u16(&mut bytes, 58, 64, endian);
    put_u16(&mut bytes, 60, 4, endian);
    put_u16(&mut bytes, 62, 2, endian);

    put_u32(&mut bytes, PHOFF, 1, endian);
    put_u64(&mut bytes, PHOFF + 8, 0x340, endian);
    put_u64(&mut bytes, PHOFF + 32, 0x40, endian);

    let first = SHOFF + 64;
    put_u32(&mut bytes, first, 17, endian);
    put_u32(&mut bytes, first + 4, 1, endian);
    put_u64(&mut bytes, first + 24, 0x300, endian);
    put_u64(
        &mut bytes,
        first + 32,
        (SECTION_DATA_END - 0x300) as u64,
        endian,
    );

    let second = SHOFF + 128;
    put_u32(&mut bytes, second, 1, endian);
    put_u32(&mut bytes, second + 4, 3, endian);
    put_u64(&mut bytes, second + 24, 0x120, endian);
    put_u64(&mut bytes, second + 32, 26, endian);
    bytes[0x120..0x120 + 26].copy_from_slice(b"\0.shstrtab\0.envs\0.payload\0");

    let third = SHOFF + 192;
    put_u32(&mut bytes, third, 11, endian);
    put_u32(&mut bytes, third + 4, 1, endian);
    put_u64(&mut bytes, third + 24, 0x150, endian);
    put_u64(&mut bytes, third + 32, 16, endian);
    bytes[0x150..0x158].copy_from_slice(b"VALUE=1\0");

    bytes.extend_from_slice(b"hsqs");
    bytes.extend_from_slice(&[0x5a; 4096]);
    bytes
}

#[test]
fn reads_each_prefix_byte_only_once() {
    let bytes = fixture(Endian::Little);
    let mut reader = CountingCursor::new(bytes.clone());

    let prefix = read_elf_prefix(&mut reader, bytes.len() as u64).unwrap();

    assert_eq!(prefix.boundary, 0x380);
    assert_eq!(reader.bytes_read, prefix.boundary as usize);
}

#[test]
fn powerpc64le_fixture_uses_little_endian_boundary() {
    let bytes = fixture(Endian::Little);
    let mut cursor = Cursor::new(&bytes);

    let prefix = read_elf_prefix(&mut cursor, bytes.len() as u64).unwrap();

    assert_eq!(prefix.boundary, 0x380);
    assert_eq!(prefix.bytes.len(), 0x380);
    assert_eq!(&bytes[prefix.boundary as usize..][..4], b"hsqs");
}

#[test]
fn powerpc64_big_endian_fixture_has_same_boundary() {
    let bytes = fixture(Endian::Big);
    let mut cursor = Cursor::new(&bytes);

    let prefix = read_elf_prefix(&mut cursor, bytes.len() as u64).unwrap();

    assert_eq!(prefix.boundary, 0x380);
    assert_eq!(prefix.bytes.len(), 0x380);
}

#[test]
fn unknown_elf_data_encoding_is_invalid_data() {
    let mut bytes = fixture(Endian::Little);
    bytes[5] = 0;
    let mut cursor = Cursor::new(&bytes);

    let error = match read_elf_prefix(&mut cursor, bytes.len() as u64) {
        Ok(_) => panic!("invalid EI_DATA was accepted"),
        Err(error) => error,
    };

    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
}

fn assert_invalid(bytes: Vec<u8>) {
    let file_len = bytes.len() as u64;
    assert_invalid_with_len(bytes, file_len);
}

fn assert_invalid_with_len(bytes: Vec<u8>, file_len: u64) {
    let mut cursor = Cursor::new(&bytes);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        read_elf_prefix(&mut cursor, file_len)
    }));
    let error = match result {
        Ok(Err(error)) => error,
        Ok(Ok(_)) => panic!("malformed ELF was accepted"),
        Err(_) => panic!("malformed ELF caused a panic"),
    };
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
}

#[test]
fn malformed_headers_fail_closed_as_invalid_data() {
    assert_invalid(vec![0; 10]);

    let mut bad_magic = fixture(Endian::Little);
    bad_magic[0] = 0;
    assert_invalid(bad_magic);

    let mut bad_class = fixture(Endian::Little);
    bad_class[4] = 1;
    assert_invalid(bad_class);

    let mut bad_ehsize = fixture(Endian::Little);
    put_u16(&mut bad_ehsize, 52, 63, Endian::Little);
    assert_invalid(bad_ehsize);

    let mut bad_phentsize = fixture(Endian::Little);
    put_u16(&mut bad_phentsize, 54, 55, Endian::Little);
    assert_invalid(bad_phentsize);

    let mut bad_shentsize = fixture(Endian::Little);
    put_u16(&mut bad_shentsize, 58, 63, Endian::Little);
    assert_invalid(bad_shentsize);

    let mut bad_absent_phentsize = fixture(Endian::Little);
    put_u64(&mut bad_absent_phentsize, 32, 0, Endian::Little);
    put_u16(&mut bad_absent_phentsize, 56, 0, Endian::Little);
    put_u16(&mut bad_absent_phentsize, 54, 55, Endian::Little);
    assert_invalid(bad_absent_phentsize);

    let mut bad_absent_shentsize = fixture(Endian::Little);
    put_u64(&mut bad_absent_shentsize, 40, 0, Endian::Little);
    put_u16(&mut bad_absent_shentsize, 60, 0, Endian::Little);
    put_u16(&mut bad_absent_shentsize, 62, 0, Endian::Little);
    put_u16(&mut bad_absent_shentsize, 58, 63, Endian::Little);
    assert_invalid(bad_absent_shentsize);

    let mut extended_phnum = fixture(Endian::Little);
    put_u16(&mut extended_phnum, 56, u16::MAX, Endian::Little);
    assert_invalid(extended_phnum);

    let mut extended_shnum = fixture(Endian::Little);
    put_u16(&mut extended_shnum, 60, 0, Endian::Little);
    assert_invalid(extended_shnum);

    let mut extended_shstrndx = fixture(Endian::Little);
    put_u16(&mut extended_shstrndx, 62, u16::MAX, Endian::Little);
    assert_invalid(extended_shstrndx);

    let mut out_of_range_shstrndx = fixture(Endian::Little);
    put_u16(&mut out_of_range_shstrndx, 62, 4, Endian::Little);
    assert_invalid(out_of_range_shstrndx);
}

#[test]
fn invalid_ranges_and_overflow_fail_without_panicking() {
    let mut table_past_eof = fixture(Endian::Little);
    let table_past_eof_offset = table_past_eof.len() as u64 - 32;
    put_u64(
        &mut table_past_eof,
        40,
        table_past_eof_offset,
        Endian::Little,
    );
    assert_invalid(table_past_eof);

    let mut segment_past_eof = fixture(Endian::Little);
    let segment_past_eof_size = segment_past_eof.len() as u64;
    put_u64(&mut segment_past_eof, 64 + 8, 0x300, Endian::Little);
    put_u64(
        &mut segment_past_eof,
        64 + 32,
        segment_past_eof_size,
        Endian::Little,
    );
    assert_invalid(segment_past_eof);

    let mut segment_overflow = fixture(Endian::Little);
    put_u64(&mut segment_overflow, 64 + 8, u64::MAX, Endian::Little);
    put_u64(&mut segment_overflow, 64 + 32, 2, Endian::Little);
    assert_invalid_with_len(segment_overflow, u64::MAX);

    let mut section_overflow = fixture(Endian::Little);
    let section = 0x180 + 64;
    put_u64(
        &mut section_overflow,
        section + 24,
        u64::MAX,
        Endian::Little,
    );
    put_u64(&mut section_overflow, section + 32, 2, Endian::Little);
    assert_invalid_with_len(section_overflow, u64::MAX);

    let mut remote_table = fixture(Endian::Little);
    put_u64(&mut remote_table, 40, 0x1_0000_0000, Endian::Little);
    assert_invalid_with_len(remote_table, u64::MAX);

    let mut table_overflow = fixture(Endian::Little);
    put_u64(&mut table_overflow, 40, u64::MAX - 32, Endian::Little);
    assert_invalid_with_len(table_overflow, u64::MAX);

    let mut oversized_prefix = fixture(Endian::Little);
    put_u64(
        &mut oversized_prefix,
        64 + 8,
        super::MAX_ELF_PREFIX_BYTES,
        Endian::Little,
    );
    put_u64(&mut oversized_prefix, 64 + 32, 1, Endian::Little);
    assert_invalid_with_len(oversized_prefix, u64::MAX);
}

#[test]
fn header_and_table_ranges_can_each_define_boundary() {
    let mut header_only = fixture(Endian::Little);
    put_u64(&mut header_only, 32, 0, Endian::Little);
    put_u16(&mut header_only, 54, 0, Endian::Little);
    put_u16(&mut header_only, 56, 0, Endian::Little);
    put_u64(&mut header_only, 40, 0, Endian::Little);
    put_u16(&mut header_only, 58, 0, Endian::Little);
    put_u16(&mut header_only, 60, 0, Endian::Little);
    put_u16(&mut header_only, 62, 0, Endian::Little);
    let mut cursor = Cursor::new(&header_only);
    let prefix = read_elf_prefix(&mut cursor, header_only.len() as u64).unwrap();
    assert_eq!(prefix.boundary, 64);

    let mut program_table = header_only.clone();
    put_u64(&mut program_table, 32, 0x80, Endian::Little);
    put_u16(&mut program_table, 54, 56, Endian::Little);
    put_u16(&mut program_table, 56, 1, Endian::Little);
    let mut cursor = Cursor::new(&program_table);
    let prefix = read_elf_prefix(&mut cursor, program_table.len() as u64).unwrap();
    assert_eq!(prefix.boundary, 0xb8);

    let mut section_table = header_only;
    put_u64(&mut section_table, 40, 0x180, Endian::Little);
    put_u16(&mut section_table, 58, 64, Endian::Little);
    put_u16(&mut section_table, 60, 1, Endian::Little);
    let mut cursor = Cursor::new(&section_table);
    let prefix = read_elf_prefix(&mut cursor, section_table.len() as u64).unwrap();
    assert_eq!(prefix.boundary, 0x1c0);
}

#[test]
fn elf_without_section_table_is_supported() {
    let mut bytes = fixture(Endian::Big);
    put_u64(&mut bytes, 40, 0, Endian::Big);
    put_u16(&mut bytes, 58, 0, Endian::Big);
    put_u16(&mut bytes, 60, 0, Endian::Big);
    put_u16(&mut bytes, 62, 0, Endian::Big);
    let mut cursor = Cursor::new(&bytes);

    let prefix = read_elf_prefix(&mut cursor, bytes.len() as u64).unwrap();

    assert_eq!(prefix.boundary, 0x380);
}

#[test]
fn unordered_section_headers_use_largest_file_end() {
    let mut bytes = fixture(Endian::Little);
    put_u64(&mut bytes, 64 + 32, 0, Endian::Little);
    let mut cursor = Cursor::new(&bytes);

    let prefix = read_elf_prefix(&mut cursor, bytes.len() as u64).unwrap();

    assert_eq!(prefix.boundary, 0x320);
}

#[test]
fn nobits_section_does_not_occupy_file_bytes() {
    let mut bytes = fixture(Endian::Little);
    let section = 0x180 + 64;
    put_u32(&mut bytes, section + 4, 8, Endian::Little);
    put_u64(&mut bytes, section + 24, 0x10_0000, Endian::Little);
    put_u64(&mut bytes, section + 32, 0x20_0000, Endian::Little);
    let mut cursor = Cursor::new(&bytes);

    let prefix = read_elf_prefix(&mut cursor, bytes.len() as u64).unwrap();

    assert_eq!(prefix.boundary, 0x380);
}
