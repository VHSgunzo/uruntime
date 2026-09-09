use std::io::{Error, ErrorKind::InvalidData, Read, Result, Seek, SeekFrom};

#[derive(Clone, Copy)]
enum Endian {
    Little,
    Big,
}

impl Endian {
    fn u16(self, bytes: &[u8]) -> Result<u16> {
        let raw = bytes
            .try_into()
            .map_err(|_| invalid_data("truncated 16-bit ELF field"))?;
        Ok(match self {
            Self::Little => u16::from_le_bytes(raw),
            Self::Big => u16::from_be_bytes(raw),
        })
    }

    fn u32(self, bytes: &[u8]) -> Result<u32> {
        let raw = bytes
            .try_into()
            .map_err(|_| invalid_data("truncated 32-bit ELF field"))?;
        Ok(match self {
            Self::Little => u32::from_le_bytes(raw),
            Self::Big => u32::from_be_bytes(raw),
        })
    }

    fn u64(self, bytes: &[u8]) -> Result<u64> {
        let raw = bytes
            .try_into()
            .map_err(|_| invalid_data("truncated 64-bit ELF field"))?;
        Ok(match self {
            Self::Little => u64::from_le_bytes(raw),
            Self::Big => u64::from_be_bytes(raw),
        })
    }
}

const ELF64_HEADER_SIZE: u64 = 64;
const ELF64_PROGRAM_HEADER_SIZE: u64 = 56;
const ELF64_SECTION_HEADER_SIZE: u64 = 64;
// Bound attacker-controlled seeks and allocations while leaving ample room for the
// compressed helpers and custom sections in supported uruntime binaries.
const MAX_ELF_TABLE_BYTES: u64 = 8 * 1024 * 1024;
const MAX_ELF_PREFIX_BYTES: u64 = 128 * 1024 * 1024;
const SHT_NOBITS: u32 = 8;
const PN_XNUM: u16 = u16::MAX;
const SHN_XINDEX: u16 = u16::MAX;

fn invalid_data(message: impl Into<String>) -> Error {
    Error::new(InvalidData, message.into())
}

fn checked_end(offset: u64, size: u64, file_len: u64, label: &str) -> Result<u64> {
    let end = offset
        .checked_add(size)
        .ok_or_else(|| invalid_data(format!("{label} range overflows u64")))?;
    if end > file_len {
        return Err(invalid_data(format!(
            "{label} range {offset}..{end} exceeds file length {file_len}"
        )));
    }
    Ok(end)
}

fn allocate_zeroed(size: u64, label: &str) -> Result<Vec<u8>> {
    let size = usize::try_from(size)
        .map_err(|_| invalid_data(format!("{label} size does not fit usize")))?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(size)
        .map_err(|error| invalid_data(format!("cannot allocate {label}: {error}")))?;
    bytes.resize(size, 0);
    Ok(bytes)
}

pub(crate) struct ElfPrefix {
    pub(crate) boundary: u64,
    pub(crate) bytes: Vec<u8>,
}

pub(crate) fn read_elf_prefix<R: Read + Seek>(reader: &mut R, file_len: u64) -> Result<ElfPrefix> {
    if file_len < ELF64_HEADER_SIZE {
        return Err(invalid_data("file is shorter than an ELF64 header"));
    }

    let mut header = [0u8; ELF64_HEADER_SIZE as usize];
    reader
        .read_exact(&mut header)
        .map_err(|error| invalid_data(format!("cannot read ELF64 header: {error}")))?;
    if &header[..4] != b"\x7fELF" {
        return Err(invalid_data("invalid ELF magic"));
    }
    if header[4] != 2 {
        return Err(invalid_data(format!(
            "unsupported ELF EI_CLASS value {} (expected ELF64)",
            header[4]
        )));
    }
    if header[6] != 1 {
        return Err(invalid_data("invalid ELF identification version"));
    }

    let endian = match header[5] {
        1 => Endian::Little,
        2 => Endian::Big,
        value => {
            return Err(invalid_data(format!(
                "unsupported ELF EI_DATA value {value}"
            )))
        }
    };
    let phoff = endian.u64(&header[32..40])?;
    let shoff = endian.u64(&header[40..48])?;
    let ehsize = u64::from(endian.u16(&header[52..54])?);
    let phentsize = u64::from(endian.u16(&header[54..56])?);
    let phnum = endian.u16(&header[56..58])?;
    let shentsize = u64::from(endian.u16(&header[58..60])?);
    let shnum = endian.u16(&header[60..62])?;
    let shstrndx = endian.u16(&header[62..64])?;

    if ehsize != ELF64_HEADER_SIZE {
        return Err(invalid_data(format!(
            "invalid ELF64 e_ehsize {ehsize} (expected {ELF64_HEADER_SIZE})"
        )));
    }
    if phnum == PN_XNUM {
        return Err(invalid_data(
            "extended ELF program-header numbering is unsupported",
        ));
    }
    if phnum == 0 {
        if phoff != 0 || !matches!(phentsize, 0 | ELF64_PROGRAM_HEADER_SIZE) {
            return Err(invalid_data("inconsistent absent ELF program-header table"));
        }
    } else if phoff == 0 || phentsize != ELF64_PROGRAM_HEADER_SIZE {
        return Err(invalid_data(
            "invalid ELF64 program-header table offset or e_phentsize",
        ));
    }
    if shstrndx == SHN_XINDEX {
        return Err(invalid_data(
            "extended ELF section-name indexing is unsupported",
        ));
    }
    if shstrndx != 0 && shstrndx >= shnum {
        return Err(invalid_data(format!(
            "ELF section-name table index {shstrndx} is outside {shnum} section headers"
        )));
    }
    if (shoff == 0) != (shnum == 0) {
        return Err(invalid_data(
            "extended or inconsistent ELF section-header numbering is unsupported",
        ));
    }
    if shnum == 0 {
        if !matches!(shentsize, 0 | ELF64_SECTION_HEADER_SIZE) {
            return Err(invalid_data("inconsistent absent ELF section-header table"));
        }
    } else if shentsize != ELF64_SECTION_HEADER_SIZE {
        return Err(invalid_data(format!(
            "invalid ELF64 e_shentsize {shentsize} (expected {ELF64_SECTION_HEADER_SIZE})"
        )));
    }

    let ph_table_size = phentsize
        .checked_mul(u64::from(phnum))
        .ok_or_else(|| invalid_data("program-header table size overflows u64"))?;
    let sh_table_size = shentsize
        .checked_mul(u64::from(shnum))
        .ok_or_else(|| invalid_data("section-header table size overflows u64"))?;
    if ph_table_size > MAX_ELF_TABLE_BYTES || sh_table_size > MAX_ELF_TABLE_BYTES {
        return Err(invalid_data("ELF metadata table exceeds safety limit"));
    }

    let ph_table_end = checked_end(phoff, ph_table_size, file_len, "program-header table")?;
    let sh_table_end = checked_end(shoff, sh_table_size, file_len, "section-header table")?;
    if ph_table_end > MAX_ELF_PREFIX_BYTES || sh_table_end > MAX_ELF_PREFIX_BYTES {
        return Err(invalid_data("ELF metadata table lies beyond safety limit"));
    }
    let mut boundary = ehsize.max(ph_table_end).max(sh_table_end);

    if ph_table_size != 0 {
        let mut table = allocate_zeroed(ph_table_size, "program-header table")?;
        reader.seek(SeekFrom::Start(phoff))?;
        reader
            .read_exact(&mut table)
            .map_err(|error| invalid_data(format!("cannot read program-header table: {error}")))?;
        for entry in table.chunks_exact(phentsize as usize) {
            let offset = endian.u64(&entry[8..16])?;
            let size = endian.u64(&entry[32..40])?;
            if size != 0 {
                boundary = boundary.max(checked_end(offset, size, file_len, "program segment")?);
            }
        }
    }

    if sh_table_size != 0 {
        let mut table = allocate_zeroed(sh_table_size, "section-header table")?;
        reader.seek(SeekFrom::Start(shoff))?;
        reader
            .read_exact(&mut table)
            .map_err(|error| invalid_data(format!("cannot read section-header table: {error}")))?;
        for entry in table.chunks_exact(shentsize as usize) {
            let section_type = endian.u32(&entry[4..8])?;
            let size = endian.u64(&entry[32..40])?;
            if section_type == SHT_NOBITS || size == 0 {
                continue;
            }
            let offset = endian.u64(&entry[24..32])?;
            boundary = boundary.max(checked_end(offset, size, file_len, "section")?);
        }
    }

    if boundary > MAX_ELF_PREFIX_BYTES {
        return Err(invalid_data(format!(
            "ELF file-backed prefix size {boundary} exceeds safety limit {MAX_ELF_PREFIX_BYTES}"
        )));
    }
    let mut bytes = allocate_zeroed(boundary, "ELF prefix")?;
    reader.seek(SeekFrom::Start(0))?;
    reader
        .read_exact(&mut bytes)
        .map_err(|error| invalid_data(format!("cannot read ELF prefix: {error}")))?;
    Ok(ElfPrefix { boundary, bytes })
}

#[cfg(test)]
pub(crate) mod tests;
