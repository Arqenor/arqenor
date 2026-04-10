//! Minimal PE (Portable Executable) parser for static analysis.
//!
//! Parses DOS header, COFF header, optional header, section headers,
//! import directory, and export directory from raw bytes.
//! Designed for malware analysis — never panics on malformed input.

use crate::entropy::shannon_entropy;

// ── PE constants ────────────────────────────────────────────────────

const MZ_MAGIC: u16 = 0x5A4D;
const PE_SIGNATURE: u32 = 0x0000_4550;
const PE32_MAGIC: u16 = 0x10B;
const PE32PLUS_MAGIC: u16 = 0x20B;

const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
const IMAGE_SCN_MEM_READ: u32 = 0x4000_0000;
const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;

const IMAGE_FILE_DLL: u16 = 0x2000;

/// Data directory indices.
const DIR_EXPORT: usize = 0;
const DIR_IMPORT: usize = 1;
const DIR_RESOURCE: usize = 2;
const DIR_SECURITY: usize = 4;
const DIR_RELOC: usize = 5;
const DIR_DEBUG: usize = 6;
const DIR_TLS: usize = 9;

// ── Public types ────────────────────────────────────────────────────

/// Parsed PE file information.
#[derive(Debug, Clone)]
pub struct PeInfo {
    pub is_valid: bool,
    pub is_64bit: bool,
    pub is_dll: bool,
    pub machine: u16,
    pub timestamp: u32,
    pub entry_point: u32,
    pub image_base: u64,
    pub size_of_image: u32,
    pub subsystem: u16,
    pub dll_characteristics: u16,
    pub characteristics: u16,
    pub sections: Vec<SectionInfo>,
    pub imports: Vec<ImportEntry>,
    pub has_exports: bool,
    pub has_debug: bool,
    pub has_resources: bool,
    pub has_tls: bool,
    pub has_relocs: bool,
    pub has_security: bool,
    pub overlay_size: usize,
}

/// Parsed section header with computed metadata.
#[derive(Debug, Clone)]
pub struct SectionInfo {
    pub name: String,
    pub virtual_size: u32,
    pub virtual_address: u32,
    pub raw_size: u32,
    pub raw_offset: u32,
    pub characteristics: u32,
    pub is_executable: bool,
    pub is_writable: bool,
    pub is_readable: bool,
    pub entropy: f64,
}

/// A single imported DLL and its functions.
#[derive(Debug, Clone)]
pub struct ImportEntry {
    pub dll_name: String,
    pub functions: Vec<String>,
}

impl Default for PeInfo {
    fn default() -> Self {
        Self {
            is_valid: false,
            is_64bit: false,
            is_dll: false,
            machine: 0,
            timestamp: 0,
            entry_point: 0,
            image_base: 0,
            size_of_image: 0,
            subsystem: 0,
            dll_characteristics: 0,
            characteristics: 0,
            sections: Vec::new(),
            imports: Vec::new(),
            has_exports: false,
            has_debug: false,
            has_resources: false,
            has_tls: false,
            has_relocs: false,
            has_security: false,
            overlay_size: 0,
        }
    }
}

// ── Safe read helpers ───────────────────────────────────────────────

fn read_u16_le(data: &[u8], offset: usize) -> Option<u16> {
    let bytes = data.get(offset..offset + 2)?;
    Some(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn read_u32_le(data: &[u8], offset: usize) -> Option<u32> {
    let bytes = data.get(offset..offset + 4)?;
    Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn read_u64_le(data: &[u8], offset: usize) -> Option<u64> {
    let bytes = data.get(offset..offset + 8)?;
    Some(u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]))
}

/// Read a null-terminated ASCII string starting at `offset`, up to `max_len` bytes.
fn read_cstring(data: &[u8], offset: usize, max_len: usize) -> Option<String> {
    let start = data.get(offset..)?;
    let limit = start.len().min(max_len);
    let slice = &start[..limit];
    let end = slice.iter().position(|&b| b == 0).unwrap_or(limit);
    let s: String = slice[..end]
        .iter()
        .filter(|&&b| b.is_ascii_graphic() || b == b' ')
        .map(|&b| b as char)
        .collect();
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

/// Read a fixed-length section name (8 bytes, null-padded).
fn read_section_name(data: &[u8], offset: usize) -> Option<String> {
    let bytes = data.get(offset..offset + 8)?;
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(8);
    let s: String = bytes[..end]
        .iter()
        .filter(|&&b| b.is_ascii_graphic() || b == b'.')
        .map(|&b| b as char)
        .collect();
    Some(s)
}

// ── RVA to file offset conversion ──────────────────────────────────

/// Convert a Relative Virtual Address to a file offset using section mappings.
fn rva_to_offset(rva: u32, sections: &[SectionInfo]) -> Option<usize> {
    if rva == 0 {
        return None;
    }
    for sec in sections {
        let va_start = sec.virtual_address;
        let va_end = va_start.saturating_add(sec.virtual_size.max(sec.raw_size));
        if rva >= va_start && rva < va_end {
            let delta = rva - va_start;
            if delta < sec.raw_size {
                return Some((sec.raw_offset + delta) as usize);
            }
        }
    }
    None
}

// ── Data directory helper ──────────────────────────────────────────

struct DataDir {
    rva: u32,
    #[allow(dead_code)]
    size: u32,
}

fn read_data_dir(data: &[u8], dd_offset: usize, index: usize) -> Option<DataDir> {
    let base = dd_offset + index * 8;
    let rva = read_u32_le(data, base)?;
    let size = read_u32_le(data, base + 4)?;
    if rva == 0 || size == 0 {
        return None;
    }
    Some(DataDir { rva, size })
}

// ── Import parsing ─────────────────────────────────────────────────

/// Maximum number of imports to parse (safety limit for malformed PEs).
const MAX_IMPORT_DLLS: usize = 512;
const MAX_IMPORT_FUNCTIONS: usize = 4096;

fn parse_imports(
    data: &[u8],
    import_dir: &DataDir,
    sections: &[SectionInfo],
    is_64bit: bool,
) -> Vec<ImportEntry> {
    let mut imports = Vec::new();

    let Some(import_offset) = rva_to_offset(import_dir.rva, sections) else {
        return imports;
    };

    // Each IMAGE_IMPORT_DESCRIPTOR is 20 bytes, null-terminated array.
    let mut desc_offset = import_offset;
    for _ in 0..MAX_IMPORT_DLLS {
        // Bounds check for full descriptor (20 bytes).
        if desc_offset + 20 > data.len() {
            break;
        }

        let original_first_thunk = read_u32_le(data, desc_offset).unwrap_or(0);
        let name_rva = read_u32_le(data, desc_offset + 12).unwrap_or(0);
        let first_thunk = read_u32_le(data, desc_offset + 16).unwrap_or(0);

        // Null descriptor terminates the array.
        if name_rva == 0 && original_first_thunk == 0 && first_thunk == 0 {
            break;
        }

        // Read DLL name.
        let dll_name = if let Some(name_off) = rva_to_offset(name_rva, sections) {
            read_cstring(data, name_off, 256).unwrap_or_default()
        } else {
            String::new()
        };

        // Parse function names from OriginalFirstThunk (preferred) or FirstThunk.
        let thunk_rva = if original_first_thunk != 0 {
            original_first_thunk
        } else {
            first_thunk
        };
        let functions = parse_thunk_array(data, thunk_rva, sections, is_64bit);

        if !dll_name.is_empty() {
            imports.push(ImportEntry {
                dll_name,
                functions,
            });
        }

        desc_offset += 20;
    }

    imports
}

fn parse_thunk_array(
    data: &[u8],
    thunk_rva: u32,
    sections: &[SectionInfo],
    is_64bit: bool,
) -> Vec<String> {
    let mut functions = Vec::new();

    let Some(mut offset) = rva_to_offset(thunk_rva, sections) else {
        return functions;
    };

    let thunk_size = if is_64bit { 8 } else { 4 };
    let ordinal_flag: u64 = if is_64bit {
        0x8000_0000_0000_0000
    } else {
        0x8000_0000
    };

    for _ in 0..MAX_IMPORT_FUNCTIONS {
        if offset + thunk_size > data.len() {
            break;
        }

        let thunk_value = if is_64bit {
            read_u64_le(data, offset).unwrap_or(0)
        } else {
            read_u32_le(data, offset).unwrap_or(0) as u64
        };

        if thunk_value == 0 {
            break;
        }

        // Check if import is by ordinal.
        if thunk_value & ordinal_flag != 0 {
            let ordinal = thunk_value & 0xFFFF;
            functions.push(format!("ordinal_{ordinal}"));
        } else {
            // Import by name: thunk_value is RVA to IMAGE_IMPORT_BY_NAME.
            // Skip 2-byte hint, then read null-terminated name.
            let hint_rva = thunk_value as u32;
            if let Some(hint_off) = rva_to_offset(hint_rva, sections) {
                if let Some(name) = read_cstring(data, hint_off + 2, 512) {
                    functions.push(name);
                }
            }
        }

        offset += thunk_size;
    }

    functions
}

// ── Main parser ────────────────────────────────────────────────────

/// Parse a PE file from raw bytes.
///
/// Returns [`PeInfo`] with `is_valid: false` if the data is not a valid PE.
/// Never panics — all byte accesses are bounds-checked.
pub fn parse_pe(data: &[u8]) -> PeInfo {
    let mut pe = PeInfo::default();

    // ── DOS header ──────────────────────────────────────────────
    let Some(mz) = read_u16_le(data, 0) else {
        return pe;
    };
    if mz != MZ_MAGIC {
        return pe;
    }

    let Some(e_lfanew) = read_u32_le(data, 0x3C) else {
        return pe;
    };
    let pe_offset = e_lfanew as usize;

    // ── PE signature ────────────────────────────────────────────
    let Some(sig) = read_u32_le(data, pe_offset) else {
        return pe;
    };
    if sig != PE_SIGNATURE {
        return pe;
    }

    // ── COFF header (20 bytes starting at pe_offset + 4) ───────
    let coff = pe_offset + 4;
    let Some(machine) = read_u16_le(data, coff) else {
        return pe;
    };
    let Some(num_sections) = read_u16_le(data, coff + 2) else {
        return pe;
    };
    let Some(timestamp) = read_u32_le(data, coff + 4) else {
        return pe;
    };
    let Some(size_of_optional) = read_u16_le(data, coff + 16) else {
        return pe;
    };
    let Some(characteristics) = read_u16_le(data, coff + 18) else {
        return pe;
    };

    pe.machine = machine;
    pe.timestamp = timestamp;
    pe.characteristics = characteristics;
    pe.is_dll = characteristics & IMAGE_FILE_DLL != 0;

    // ── Optional header ─────────────────────────────────────────
    let opt_offset = coff + 20;
    let Some(magic) = read_u16_le(data, opt_offset) else {
        return pe;
    };

    pe.is_64bit = magic == PE32PLUS_MAGIC;
    if magic != PE32_MAGIC && magic != PE32PLUS_MAGIC {
        return pe;
    }

    // Entry point is at offset 16 from optional header start for both PE32/PE32+.
    pe.entry_point = read_u32_le(data, opt_offset + 16).unwrap_or(0);

    if pe.is_64bit {
        pe.image_base = read_u64_le(data, opt_offset + 24).unwrap_or(0);
    } else {
        pe.image_base = read_u32_le(data, opt_offset + 28).unwrap_or(0) as u64;
    }

    // SizeOfImage, Subsystem, DllCharacteristics differ by PE32 vs PE32+.
    let (size_of_image_off, subsystem_off, dllchar_off, num_rva_off, dd_offset) = if pe.is_64bit {
        (opt_offset + 56, opt_offset + 68, opt_offset + 70, opt_offset + 108, opt_offset + 112)
    } else {
        (opt_offset + 56, opt_offset + 68, opt_offset + 70, opt_offset + 92, opt_offset + 96)
    };

    pe.size_of_image = read_u32_le(data, size_of_image_off).unwrap_or(0);
    pe.subsystem = read_u16_le(data, subsystem_off).unwrap_or(0);
    pe.dll_characteristics = read_u16_le(data, dllchar_off).unwrap_or(0);

    let num_rva_sizes = read_u32_le(data, num_rva_off).unwrap_or(0) as usize;

    // ── Data directories ────────────────────────────────────────
    pe.has_exports = num_rva_sizes > DIR_EXPORT
        && read_data_dir(data, dd_offset, DIR_EXPORT).is_some();
    pe.has_resources = num_rva_sizes > DIR_RESOURCE
        && read_data_dir(data, dd_offset, DIR_RESOURCE).is_some();
    pe.has_security = num_rva_sizes > DIR_SECURITY
        && read_data_dir(data, dd_offset, DIR_SECURITY).is_some();
    pe.has_relocs = num_rva_sizes > DIR_RELOC
        && read_data_dir(data, dd_offset, DIR_RELOC).is_some();
    pe.has_debug = num_rva_sizes > DIR_DEBUG
        && read_data_dir(data, dd_offset, DIR_DEBUG).is_some();
    pe.has_tls = num_rva_sizes > DIR_TLS
        && read_data_dir(data, dd_offset, DIR_TLS).is_some();

    // ── Section headers ─────────────────────────────────────────
    let section_start = opt_offset + size_of_optional as usize;
    let num_sections = (num_sections as usize).min(96); // safety cap

    let mut last_section_end: usize = 0;

    for i in 0..num_sections {
        let sec_off = section_start + i * 40;
        if sec_off + 40 > data.len() {
            break;
        }

        let name = read_section_name(data, sec_off).unwrap_or_default();
        let virtual_size = read_u32_le(data, sec_off + 8).unwrap_or(0);
        let virtual_address = read_u32_le(data, sec_off + 12).unwrap_or(0);
        let raw_size = read_u32_le(data, sec_off + 16).unwrap_or(0);
        let raw_offset = read_u32_le(data, sec_off + 20).unwrap_or(0);
        let sec_chars = read_u32_le(data, sec_off + 36).unwrap_or(0);

        // Compute entropy of section data.
        let entropy = if raw_size > 0 && raw_offset > 0 {
            let start = raw_offset as usize;
            let end = start.saturating_add(raw_size as usize).min(data.len());
            if start < data.len() {
                shannon_entropy(&data[start..end])
            } else {
                0.0
            }
        } else {
            0.0
        };

        let sec_end = (raw_offset as usize).saturating_add(raw_size as usize);
        if sec_end > last_section_end {
            last_section_end = sec_end;
        }

        pe.sections.push(SectionInfo {
            name,
            virtual_size,
            virtual_address,
            raw_size,
            raw_offset,
            characteristics: sec_chars,
            is_executable: sec_chars & IMAGE_SCN_MEM_EXECUTE != 0,
            is_writable: sec_chars & IMAGE_SCN_MEM_WRITE != 0,
            is_readable: sec_chars & IMAGE_SCN_MEM_READ != 0,
            entropy,
        });
    }

    // Overlay = bytes after the last section's raw data.
    pe.overlay_size = data.len().saturating_sub(last_section_end);

    // ── Imports ─────────────────────────────────────────────────
    if num_rva_sizes > DIR_IMPORT {
        if let Some(import_dir) = read_data_dir(data, dd_offset, DIR_IMPORT) {
            pe.imports = parse_imports(data, &import_dir, &pe.sections, pe.is_64bit);
        }
    }

    pe.is_valid = true;
    pe
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_data_returns_invalid() {
        let pe = parse_pe(&[]);
        assert!(!pe.is_valid);
    }

    #[test]
    fn garbage_data_returns_invalid() {
        let pe = parse_pe(&[0xFF; 256]);
        assert!(!pe.is_valid);
    }

    #[test]
    fn only_mz_returns_invalid() {
        let mut data = vec![0u8; 128];
        data[0] = b'M';
        data[1] = b'Z';
        let pe = parse_pe(&data);
        assert!(!pe.is_valid);
    }

    /// Build a minimal valid PE32 in memory for testing.
    fn build_minimal_pe32() -> Vec<u8> {
        let mut buf = vec![0u8; 512];

        // DOS header
        buf[0] = b'M';
        buf[1] = b'Z';
        // e_lfanew -> 0x80
        buf[0x3C] = 0x80;

        let pe_off = 0x80usize;
        // PE signature
        buf[pe_off] = b'P';
        buf[pe_off + 1] = b'E';

        // COFF header at pe_off + 4
        let coff = pe_off + 4;
        // Machine = 0x14C (i386)
        buf[coff] = 0x4C;
        buf[coff + 1] = 0x01;
        // NumberOfSections = 1
        buf[coff + 2] = 0x01;
        // SizeOfOptionalHeader = 0xE0 (standard PE32)
        buf[coff + 16] = 0xE0;
        buf[coff + 17] = 0x00;

        // Optional header at coff + 20
        let opt = coff + 20;
        // Magic = 0x10B (PE32)
        buf[opt] = 0x0B;
        buf[opt + 1] = 0x01;
        // NumberOfRvaAndSizes = 16
        buf[opt + 92] = 16;

        // Section header at opt + 0xE0
        let sec = opt + 0xE0;
        // Name = ".text"
        buf[sec] = b'.';
        buf[sec + 1] = b't';
        buf[sec + 2] = b'e';
        buf[sec + 3] = b'x';
        buf[sec + 4] = b't';
        // VirtualSize = 0x100
        buf[sec + 8] = 0x00;
        buf[sec + 9] = 0x01;
        // VirtualAddress = 0x1000
        buf[sec + 12] = 0x00;
        buf[sec + 13] = 0x10;
        // SizeOfRawData = 0x100
        buf[sec + 16] = 0x00;
        buf[sec + 17] = 0x01;
        // PointerToRawData = 0x200
        buf[sec + 20] = 0x00;
        buf[sec + 21] = 0x02;
        // Characteristics = EXECUTE | READ
        let chars = IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;
        let chars_bytes = chars.to_le_bytes();
        buf[sec + 36] = chars_bytes[0];
        buf[sec + 37] = chars_bytes[1];
        buf[sec + 38] = chars_bytes[2];
        buf[sec + 39] = chars_bytes[3];

        buf
    }

    #[test]
    fn minimal_pe32_parses_correctly() {
        let data = build_minimal_pe32();
        let pe = parse_pe(&data);
        assert!(pe.is_valid);
        assert!(!pe.is_64bit);
        assert_eq!(pe.machine, 0x14C);
        assert_eq!(pe.sections.len(), 1);
        assert_eq!(pe.sections[0].name, ".text");
        assert!(pe.sections[0].is_executable);
        assert!(pe.sections[0].is_readable);
        assert!(!pe.sections[0].is_writable);
    }
}
