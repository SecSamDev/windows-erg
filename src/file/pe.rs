//! PE (Portable Executable) file analysis: hashes, imports, and a handful
//! of structural signals.
//!
//! Parsing is pure and bounds-checked against arbitrary/malformed input
//! ([`analyze_pe_bytes`] never panics, only returns `Err`); [`analyze_pe_file`]
//! is a thin `std::fs::read` wrapper. Nothing here calls a Win32 API — hashing
//! goes through [`crate::crypto`] (CNG) purely to avoid a third-party hashing
//! crate, not because this module needs Windows.
//!
//! # Scope
//!
//! Deliberately limited to signals that are well-defined and cheap to get
//! right: [`PeAnalysis::has_overlay`] (extra bytes past the last section),
//! [`PeAnalysis::checksum_mismatch`] (the header's stored checksum doesn't
//! match reality), and [`PeAnalysis::is_dotnet`]/[`PeAnalysis::is_64bit`]
//! (direct header fields). Deliberately **not** attempted: Rich header
//! validation, "packed section" entropy heuristics, and mixed native/CLR
//! detection — all three need real calibration against known-good and
//! known-bad samples to avoid being either useless or actively misleading,
//! which this module cannot do on its own.

use std::path::Path;

use crate::crypto::{MD5_LEN, SHA1_LEN, SHA256_LEN, md5, sha1, sha256};
use crate::error::{Error, FileOperationError, InvalidParameterError, Result};

const IMAGE_DOS_SIGNATURE: u16 = 0x5A4D; // "MZ"
const E_LFANEW_OFFSET: usize = 0x3C;
const IMAGE_NT_SIGNATURE: u32 = 0x0000_4550; // "PE\0\0"
const FILE_HEADER_SIZE: usize = 20;
const NUMBER_OF_SECTIONS_OFFSET: usize = 2; // within the file header
const SIZE_OF_OPTIONAL_HEADER_OFFSET: usize = 16; // within the file header
const MAGIC_PE32: u16 = 0x10b;
const MAGIC_PE32_PLUS: u16 = 0x20b;
const CHECKSUM_OFFSET: usize = 0x40; // within the optional header, same for PE32 and PE32+
const RVA_COUNT_OFFSET_PE32: usize = 0x5C;
const RVA_COUNT_OFFSET_PE32_PLUS: usize = 0x6C;
const DATA_DIRECTORY_OFFSET_PE32: usize = 0x60;
const DATA_DIRECTORY_OFFSET_PE32_PLUS: usize = 0x70;
const DATA_DIRECTORY_ENTRY_SIZE: usize = 8;
const DIRECTORY_IMPORT: u32 = 1;
const DIRECTORY_COM_DESCRIPTOR: u32 = 14;
const SECTION_HEADER_SIZE: usize = 40;
const IMPORT_DESCRIPTOR_SIZE: usize = 20;
const IMAGE_ORDINAL_FLAG32: u32 = 0x8000_0000;
const IMAGE_ORDINAL_FLAG64: u64 = 0x8000_0000_0000_0000;
/// Bail out of the import walk rather than loop forever on a corrupt/hostile
/// thunk array that never hits a zero terminator.
const MAX_IMPORTS_PER_DLL: usize = 4096;
const MAX_IMPORT_DESCRIPTORS: usize = 4096;

/// Cryptographic hashes and structural signals for a PE (`.exe`/`.dll`) file.
#[derive(Debug, Clone)]
pub struct PeAnalysis {
    /// SHA-256 of the raw file bytes.
    pub sha256: [u8; SHA256_LEN],
    /// SHA-1 of the raw file bytes (legacy hash-database compatibility).
    pub sha1: [u8; SHA1_LEN],
    /// MD5 of the raw file bytes.
    pub md5: [u8; MD5_LEN],
    /// MD5 of `"dll.func,dll.func,…"` (lowercase, extension stripped from
    /// the DLL name, `ord<N>` for ordinal imports), in import-table order —
    /// the standard "imphash" algorithm, matching community threat-intel
    /// tooling. `None` when the file has no import table at all (common
    /// for packed/obfuscated binaries).
    pub imphash: Option<[u8; MD5_LEN]>,
    /// Distinct imported DLL names, lowercase, in order of first appearance.
    pub imported_dlls: Vec<String>,
    /// `true` for PE32+ (64-bit); `false` for PE32 (32-bit).
    pub is_64bit: bool,
    /// The file has a CLR (COM descriptor) header — a .NET assembly.
    pub is_dotnet: bool,
    /// Extra bytes appended after the last section's raw data — common for
    /// self-extracting installers, also used to hide payloads.
    pub has_overlay: bool,
    /// The header's stored checksum is nonzero and does not match the
    /// actual computed one. Regular EXEs are not required to carry a
    /// correct (or any) checksum, so this is a signal, not proof of
    /// tampering — see the module docs.
    pub checksum_mismatch: bool,
}

/// Read and analyze the PE file at `path`.
pub fn analyze_pe_file(path: &Path) -> Result<PeAnalysis> {
    let bytes = std::fs::read(path).map_err(|e| {
        Error::FileOperation(FileOperationError::with_code(
            path.to_string_lossy().into_owned(),
            "read",
            e.raw_os_error().unwrap_or(-1),
        ))
    })?;
    analyze_pe_bytes(&bytes)
}

/// Analyze already-read PE bytes.
pub fn analyze_pe_bytes(bytes: &[u8]) -> Result<PeAnalysis> {
    let headers = PeHeaders::parse(bytes)?;
    let imports = headers.parse_imports(bytes);
    let imphash = if imports.is_empty() {
        None
    } else {
        Some(md5(imphash_input(&imports).as_bytes())?)
    };
    let imported_dlls = dedup_dll_names(&imports);

    Ok(PeAnalysis {
        sha256: sha256(bytes)?,
        sha1: sha1(bytes)?,
        md5: md5(bytes)?,
        imphash,
        imported_dlls,
        is_64bit: headers.is_64bit,
        is_dotnet: headers
            .data_directory(DIRECTORY_COM_DESCRIPTOR, bytes)
            .is_some(),
        has_overlay: headers.has_overlay(bytes.len()),
        checksum_mismatch: headers.checksum_mismatch(bytes),
    })
}

/// One resolved import: the (lowercase, extension-stripped) DLL name, and
/// either a lowercase imported symbol name or `ord<N>` for an ordinal import.
struct Import {
    dll: String,
    symbol: String,
}

fn imphash_input(imports: &[Import]) -> String {
    imports
        .iter()
        .map(|i| format!("{}.{}", strip_extension(&i.dll), i.symbol))
        .collect::<Vec<_>>()
        .join(",")
}

fn dedup_dll_names(imports: &[Import]) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for import in imports {
        if seen.insert(import.dll.clone()) {
            out.push(import.dll.clone());
        }
    }
    out
}

fn parse_error(reason: &'static str) -> Error {
    Error::InvalidParameter(InvalidParameterError::new("pe_bytes", reason))
}

/// A resolved section's virtual and file extents, for RVA → file-offset
/// translation and overlay detection.
struct Section {
    virtual_address: u32,
    virtual_size: u32,
    raw_offset: u32,
    raw_size: u32,
}

/// Parsed DOS/NT/optional headers and section table — everything needed to
/// resolve RVAs and walk the import table, without re-parsing per query.
struct PeHeaders {
    is_64bit: bool,
    checksum_offset: usize,
    number_of_rva_and_sizes: u32,
    data_directory_offset: usize,
    sections: Vec<Section>,
}

impl PeHeaders {
    fn parse(bytes: &[u8]) -> Result<Self> {
        if u16_at(bytes, 0) != Some(IMAGE_DOS_SIGNATURE) {
            return Err(parse_error("missing MZ (DOS) signature"));
        }
        let e_lfanew = u32_at(bytes, E_LFANEW_OFFSET)
            .ok_or_else(|| parse_error("truncated DOS header"))? as usize;
        if u32_at(bytes, e_lfanew) != Some(IMAGE_NT_SIGNATURE) {
            return Err(parse_error("missing PE signature"));
        }

        let file_header_offset = e_lfanew + 4;
        let number_of_sections = u16_at(bytes, file_header_offset + NUMBER_OF_SECTIONS_OFFSET)
            .ok_or_else(|| parse_error("truncated file header"))?;
        let size_of_optional_header =
            u16_at(bytes, file_header_offset + SIZE_OF_OPTIONAL_HEADER_OFFSET)
                .ok_or_else(|| parse_error("truncated file header"))? as usize;

        let optional_header_offset = file_header_offset + FILE_HEADER_SIZE;
        let magic = u16_at(bytes, optional_header_offset)
            .ok_or_else(|| parse_error("truncated optional header"))?;
        let is_64bit = match magic {
            MAGIC_PE32 => false,
            MAGIC_PE32_PLUS => true,
            _ => return Err(parse_error("unrecognized optional header magic")),
        };

        let rva_count_offset = optional_header_offset
            + if is_64bit {
                RVA_COUNT_OFFSET_PE32_PLUS
            } else {
                RVA_COUNT_OFFSET_PE32
            };
        let number_of_rva_and_sizes = u32_at(bytes, rva_count_offset)
            .ok_or_else(|| parse_error("truncated optional header"))?;
        let data_directory_offset = optional_header_offset
            + if is_64bit {
                DATA_DIRECTORY_OFFSET_PE32_PLUS
            } else {
                DATA_DIRECTORY_OFFSET_PE32
            };

        let section_table_offset = optional_header_offset + size_of_optional_header;
        let mut sections = Vec::with_capacity(number_of_sections as usize);
        for i in 0..number_of_sections as usize {
            let base = section_table_offset + i * SECTION_HEADER_SIZE;
            let virtual_size =
                u32_at(bytes, base + 8).ok_or_else(|| parse_error("truncated section table"))?;
            let virtual_address =
                u32_at(bytes, base + 12).ok_or_else(|| parse_error("truncated section table"))?;
            let raw_size =
                u32_at(bytes, base + 16).ok_or_else(|| parse_error("truncated section table"))?;
            let raw_offset =
                u32_at(bytes, base + 20).ok_or_else(|| parse_error("truncated section table"))?;
            sections.push(Section {
                virtual_address,
                virtual_size,
                raw_offset,
                raw_size,
            });
        }

        Ok(Self {
            is_64bit,
            checksum_offset: optional_header_offset + CHECKSUM_OFFSET,
            number_of_rva_and_sizes,
            data_directory_offset,
            sections,
        })
    }

    /// `(virtual_address, size)` of data directory `index`, if present and
    /// nonzero.
    fn data_directory(&self, index: u32, bytes: &[u8]) -> Option<(u32, u32)> {
        if index >= self.number_of_rva_and_sizes {
            return None;
        }
        let offset = self.data_directory_offset + index as usize * DATA_DIRECTORY_ENTRY_SIZE;
        let rva = u32_at(bytes, offset)?;
        let size = u32_at(bytes, offset + 4)?;
        (rva != 0 && size != 0).then_some((rva, size))
    }

    fn rva_to_offset(&self, rva: u32) -> Option<usize> {
        if rva == 0 {
            return None;
        }
        for section in &self.sections {
            let extent = section.virtual_size.max(section.raw_size);
            if rva >= section.virtual_address
                && rva < section.virtual_address.saturating_add(extent)
            {
                let offset = section.raw_offset + (rva - section.virtual_address);
                return Some(offset as usize);
            }
        }
        None
    }

    /// The offset just past the last section's raw data — where any
    /// overlay begins.
    fn end_of_sections(&self) -> u64 {
        self.sections
            .iter()
            .map(|s| u64::from(s.raw_offset) + u64::from(s.raw_size))
            .max()
            .unwrap_or(0)
    }

    fn has_overlay(&self, file_len: usize) -> bool {
        (file_len as u64) > self.end_of_sections()
    }

    /// The header's stored checksum, if nonzero, does not match the value
    /// [`checksum_of`] computes over the whole file.
    fn checksum_mismatch(&self, bytes: &[u8]) -> bool {
        let Some(stored) = u32_at(bytes, self.checksum_offset) else {
            return false;
        };
        stored != 0 && stored != checksum_of(bytes, self.checksum_offset)
    }

    fn parse_imports(&self, bytes: &[u8]) -> Vec<Import> {
        let Some((import_rva, _)) = self.data_directory(DIRECTORY_IMPORT, bytes) else {
            return Vec::new();
        };
        let Some(mut offset) = self.rva_to_offset(import_rva) else {
            return Vec::new();
        };

        let mut imports = Vec::new();
        for _ in 0..MAX_IMPORT_DESCRIPTORS {
            let Some(original_first_thunk) = u32_at(bytes, offset) else {
                break;
            };
            let Some(name_rva) = u32_at(bytes, offset + 12) else {
                break;
            };
            let Some(first_thunk) = u32_at(bytes, offset + 16) else {
                break;
            };
            // The descriptor array is terminated by an all-zero entry.
            if original_first_thunk == 0 && name_rva == 0 && first_thunk == 0 {
                break;
            }
            offset += IMPORT_DESCRIPTOR_SIZE;

            let Some(dll) = self
                .rva_to_offset(name_rva)
                .and_then(|o| read_c_string(bytes, o))
            else {
                continue;
            };
            // Kept as the full lowercase name (e.g. "kernel32.dll") — the
            // extension is only stripped for `imphash_input`, matching the
            // documented imphash algorithm.
            let dll = dll.to_ascii_lowercase();

            let thunk_rva = if original_first_thunk != 0 {
                original_first_thunk
            } else {
                first_thunk
            };
            let Some(thunk_offset) = self.rva_to_offset(thunk_rva) else {
                continue;
            };
            self.walk_thunks(bytes, thunk_offset, &dll, &mut imports);
        }
        imports
    }

    fn walk_thunks(&self, bytes: &[u8], mut offset: usize, dll: &str, out: &mut Vec<Import>) {
        for _ in 0..MAX_IMPORTS_PER_DLL {
            let symbol = if self.is_64bit {
                let Some(thunk) = u64_at(bytes, offset) else {
                    break;
                };
                if thunk == 0 {
                    break;
                }
                offset += 8;
                self.resolve_thunk64(bytes, thunk)
            } else {
                let Some(thunk) = u32_at(bytes, offset) else {
                    break;
                };
                if thunk == 0 {
                    break;
                }
                offset += 4;
                self.resolve_thunk32(bytes, thunk)
            };
            if let Some(symbol) = symbol {
                out.push(Import {
                    dll: dll.to_string(),
                    symbol,
                });
            }
        }
    }

    fn resolve_thunk32(&self, bytes: &[u8], thunk: u32) -> Option<String> {
        if thunk & IMAGE_ORDINAL_FLAG32 != 0 {
            return Some(format!("ord{}", thunk & 0xFFFF));
        }
        self.rva_to_offset(thunk)
            .and_then(|o| read_c_string(bytes, o + 2)) // skip the Hint field
            .map(|s| s.to_ascii_lowercase())
    }

    fn resolve_thunk64(&self, bytes: &[u8], thunk: u64) -> Option<String> {
        if thunk & IMAGE_ORDINAL_FLAG64 != 0 {
            return Some(format!("ord{}", thunk & 0xFFFF));
        }
        let rva = u32::try_from(thunk).ok()?;
        self.rva_to_offset(rva)
            .and_then(|o| read_c_string(bytes, o + 2))
            .map(|s| s.to_ascii_lowercase())
    }
}

fn strip_extension(name: &str) -> &str {
    name.rsplit_once('.').map_or(name, |(stem, _ext)| stem)
}

fn u16_at(bytes: &[u8], offset: usize) -> Option<u16> {
    bytes
        .get(offset..offset + 2)
        .map(|s| u16::from_le_bytes(s.try_into().unwrap()))
}

fn u32_at(bytes: &[u8], offset: usize) -> Option<u32> {
    bytes
        .get(offset..offset + 4)
        .map(|s| u32::from_le_bytes(s.try_into().unwrap()))
}

fn u64_at(bytes: &[u8], offset: usize) -> Option<u64> {
    bytes
        .get(offset..offset + 8)
        .map(|s| u64::from_le_bytes(s.try_into().unwrap()))
}

/// A null-terminated ASCII/UTF-8-ish string starting at `offset`, capped at
/// a sane length so a corrupt file can't force an unbounded scan.
fn read_c_string(bytes: &[u8], offset: usize) -> Option<String> {
    const MAX_LEN: usize = 512;
    let slice = bytes.get(offset..)?;
    let end = slice.iter().take(MAX_LEN).position(|&b| b == 0)?;
    Some(String::from_utf8_lossy(&slice[..end]).into_owned())
}

/// Microsoft's PE checksum algorithm (as `imagehlp.dll`'s `CheckSumMappedFile`
/// computes it): sum the file as little-endian 16-bit words with carry
/// folded back in, skipping the two words the checksum field itself
/// occupies, then add the file length.
fn checksum_of(bytes: &[u8], checksum_field_offset: usize) -> u32 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < bytes.len() {
        if i == checksum_field_offset || i == checksum_field_offset + 2 {
            i += 2;
            continue;
        }
        sum += u16::from_le_bytes([bytes[i], bytes[i + 1]]) as u32;
        sum = (sum & 0xFFFF) + (sum >> 16);
        i += 2;
    }
    if i < bytes.len() {
        sum += bytes[i] as u32;
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    sum + bytes.len() as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a minimal but structurally valid PE32 (32-bit) byte buffer
    /// with one section holding an import table for `KERNEL32.dll`
    /// (`ExitProcess` by name, ordinal 5) — just enough for every parser
    /// path to exercise real bytes instead of being tautological.
    ///
    /// Every offset a test might want to corrupt is exposed as a field
    /// (computed once here) rather than re-derived with hardcoded numbers
    /// at each call site.
    struct FakePe {
        bytes: Vec<u8>,
        checksum_offset: usize,
        import_dir_offset: usize,
    }

    impl FakePe {
        fn build() -> Self {
            const SECTION_VA: u32 = 0x1000;
            const SECTION_FILE_OFFSET: u32 = 0x200;
            // Layout inside the section, as offsets from SECTION_VA/SECTION_FILE_OFFSET.
            const IMPORT_DESC: u32 = 0; // 20 bytes: one descriptor + one zero terminator (40 bytes total)
            const ILT: u32 = 40; // import lookup table: two u32 thunks + terminator (12 bytes)
            const IAT: u32 = 52; // import address table: same shape (12 bytes)
            const NAME_BY: u32 = 64; // IMAGE_IMPORT_BY_NAME {hint:u16, "ExitProcess\0"}
            const DLL_NAME: u32 = 90; // "kernel32.dll\0"

            // The lowest e_lfanew that cannot overlap E_LFANEW_OFFSET's own
            // 4-byte field (0x3C..0x40) is 0x40, same as a real minimal DOS
            // header.
            let e_lfanew = 0x40usize;
            let file_header_offset = e_lfanew + 4;
            let optional_header_offset = file_header_offset + FILE_HEADER_SIZE;
            let data_directory_offset = optional_header_offset + DATA_DIRECTORY_OFFSET_PE32;
            let number_of_rva_and_sizes = 16u32;
            let section_table_offset = optional_header_offset + 0xE0; // full 16-entry PE32 optional header
            let section_raw_size = 0x300u32;
            let file_len = SECTION_FILE_OFFSET + section_raw_size;

            let mut b = vec![0u8; file_len as usize];
            // DOS header.
            b[0..2].copy_from_slice(&IMAGE_DOS_SIGNATURE.to_le_bytes());
            b[E_LFANEW_OFFSET..E_LFANEW_OFFSET + 4]
                .copy_from_slice(&(e_lfanew as u32).to_le_bytes());

            // NT signature + file header.
            b[e_lfanew..e_lfanew + 4].copy_from_slice(&IMAGE_NT_SIGNATURE.to_le_bytes());
            b[file_header_offset + NUMBER_OF_SECTIONS_OFFSET
                ..file_header_offset + NUMBER_OF_SECTIONS_OFFSET + 2]
                .copy_from_slice(&1u16.to_le_bytes());
            b[file_header_offset + SIZE_OF_OPTIONAL_HEADER_OFFSET
                ..file_header_offset + SIZE_OF_OPTIONAL_HEADER_OFFSET + 2]
                .copy_from_slice(&0xE0u16.to_le_bytes());

            // Optional header: magic + RVA count + data directories.
            b[optional_header_offset..optional_header_offset + 2]
                .copy_from_slice(&MAGIC_PE32.to_le_bytes());
            b[optional_header_offset + RVA_COUNT_OFFSET_PE32
                ..optional_header_offset + RVA_COUNT_OFFSET_PE32 + 4]
                .copy_from_slice(&number_of_rva_and_sizes.to_le_bytes());
            // Import directory (#1): VA + size.
            let import_dir_offset = data_directory_offset + 8;
            b[import_dir_offset..import_dir_offset + 4]
                .copy_from_slice(&(SECTION_VA + IMPORT_DESC).to_le_bytes());
            b[import_dir_offset + 4..import_dir_offset + 8].copy_from_slice(&40u32.to_le_bytes());

            // Section header.
            let sh = section_table_offset;
            b[sh + 8..sh + 12].copy_from_slice(&section_raw_size.to_le_bytes()); // VirtualSize
            b[sh + 12..sh + 16].copy_from_slice(&SECTION_VA.to_le_bytes());
            b[sh + 16..sh + 20].copy_from_slice(&section_raw_size.to_le_bytes()); // SizeOfRawData
            b[sh + 20..sh + 24].copy_from_slice(&SECTION_FILE_OFFSET.to_le_bytes());

            // Import descriptor: OriginalFirstThunk, TimeDateStamp, ForwarderChain, Name, FirstThunk.
            let desc = (SECTION_FILE_OFFSET + IMPORT_DESC) as usize;
            b[desc..desc + 4].copy_from_slice(&(SECTION_VA + ILT).to_le_bytes());
            b[desc + 12..desc + 16].copy_from_slice(&(SECTION_VA + DLL_NAME).to_le_bytes());
            b[desc + 16..desc + 20].copy_from_slice(&(SECTION_VA + IAT).to_le_bytes());
            // Zero terminator descriptor follows automatically (buffer already zeroed).

            // Import lookup table: one by-name thunk, one ordinal thunk, terminator.
            let ilt = (SECTION_FILE_OFFSET + ILT) as usize;
            b[ilt..ilt + 4].copy_from_slice(&(SECTION_VA + NAME_BY).to_le_bytes());
            b[ilt + 4..ilt + 8].copy_from_slice(&(IMAGE_ORDINAL_FLAG32 | 5).to_le_bytes());
            // ilt+8..ilt+12 stays zero (terminator).

            // IMAGE_IMPORT_BY_NAME: Hint (u16) + "ExitProcess\0".
            let name_by = (SECTION_FILE_OFFSET + NAME_BY) as usize;
            b[name_by + 2..name_by + 2 + b"ExitProcess".len()].copy_from_slice(b"ExitProcess");

            // DLL name.
            let dll_name = (SECTION_FILE_OFFSET + DLL_NAME) as usize;
            b[dll_name..dll_name + b"kernel32.dll".len()].copy_from_slice(b"kernel32.dll");

            Self {
                bytes: b,
                checksum_offset: optional_header_offset + CHECKSUM_OFFSET,
                import_dir_offset,
            }
        }
    }

    #[test]
    fn rejects_bytes_without_a_dos_signature() {
        let err = analyze_pe_bytes(&[0u8; 64]).unwrap_err();
        assert!(err.to_string().contains("MZ"));
    }

    #[test]
    fn rejects_truncated_dos_header() {
        assert!(analyze_pe_bytes(b"MZ").is_err());
    }

    #[test]
    fn parses_imports_and_computes_imphash() {
        let pe = FakePe::build();
        let analysis = analyze_pe_bytes(&pe.bytes).unwrap();

        assert!(!analysis.is_64bit);
        assert!(!analysis.is_dotnet);
        assert_eq!(analysis.imported_dlls, vec!["kernel32.dll".to_string()]);

        let expected_input = "kernel32.exitprocess,kernel32.ord5";
        assert_eq!(
            analysis.imphash,
            Some(md5(expected_input.as_bytes()).unwrap())
        );
    }

    #[test]
    fn no_import_directory_means_no_imphash() {
        let mut pe = FakePe::build();
        // Zero out the import directory entry so there is nothing to parse.
        pe.bytes[pe.import_dir_offset..pe.import_dir_offset + 8].fill(0);

        let analysis = analyze_pe_bytes(&pe.bytes).unwrap();
        assert!(analysis.imported_dlls.is_empty());
        assert_eq!(analysis.imphash, None);
    }

    #[test]
    fn extra_trailing_bytes_are_an_overlay() {
        let mut pe = FakePe::build();
        pe.bytes.extend_from_slice(b"unexpected trailer data");
        let analysis = analyze_pe_bytes(&pe.bytes).unwrap();
        assert!(analysis.has_overlay);
    }

    #[test]
    fn exact_section_end_is_not_an_overlay() {
        let pe = FakePe::build();
        let analysis = analyze_pe_bytes(&pe.bytes).unwrap();
        assert!(!analysis.has_overlay);
    }

    #[test]
    fn zero_checksum_is_never_a_mismatch() {
        // The checksum field is left at 0 by `FakePe::build` — the common,
        // unenforced case for a plain EXE — and must not be flagged.
        let pe = FakePe::build();
        let analysis = analyze_pe_bytes(&pe.bytes).unwrap();
        assert!(!analysis.checksum_mismatch);
    }

    #[test]
    fn wrong_nonzero_checksum_is_a_mismatch() {
        let mut pe = FakePe::build();
        let offset = pe.checksum_offset;
        pe.bytes[offset..offset + 4].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
        let analysis = analyze_pe_bytes(&pe.bytes).unwrap();
        assert!(analysis.checksum_mismatch);
    }

    #[test]
    fn correct_nonzero_checksum_is_not_a_mismatch() {
        let mut pe = FakePe::build();
        let offset = pe.checksum_offset;
        let real = checksum_of(&pe.bytes, offset);
        pe.bytes[offset..offset + 4].copy_from_slice(&real.to_le_bytes());
        let analysis = analyze_pe_bytes(&pe.bytes).unwrap();
        assert!(!analysis.checksum_mismatch);
    }

    #[test]
    #[ignore] // Run manually: cargo test -- --ignored (reads a real system file)
    fn a_real_system_binary_has_a_correct_checksum() {
        let path = Path::new(r"C:\Windows\System32\notepad.exe");
        let analysis = analyze_pe_file(path).expect("should parse a real system PE file");
        assert!(analysis.is_64bit);
        assert!(
            !analysis.checksum_mismatch,
            "notepad.exe should carry a correct checksum"
        );
        assert!(
            // Modern Windows binaries import via ApiSet contracts
            // (`api-ms-win-core-*.dll`) rather than `kernel32.dll` directly.
            analysis.imported_dlls.iter().any(|d| d == "user32.dll"),
            "{:?}",
            analysis.imported_dlls
        );
    }
}
