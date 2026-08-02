#![cfg_attr(not(any(target_os = "ios", target_os = "macos")), allow(dead_code))]

use common::Result;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeSymbol {
    pub module_name: String,
    pub module_base: usize,
    pub symbol_name: String,
    pub address: usize,
    pub offset: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageSymbol {
    pub module_name: String,
    pub module_base: usize,
    pub symbol_name: String,
    pub symbol_type: &'static str,
    pub address: usize,
    pub offset: usize,
    pub is_global: bool,
    pub is_defined: bool,
}

pub fn native_symbol_support_available() -> bool {
    platform::native_symbol_support_available()
}

pub fn find_native_symbols(module_name: Option<&str>, query: &str) -> Result<Vec<NativeSymbol>> {
    platform::find_native_symbols(module_name, query)
}

pub fn find_image_symbols(module_name: &str) -> Result<Vec<ImageSymbol>> {
    platform::find_image_symbols(module_name)
}

const N_EXT: u8 = 0x01;
const N_TYPE: u8 = 0x0e;
const N_UNDF: u8 = 0x00;
const N_ABS: u8 = 0x02;
const N_INDR: u8 = 0x0a;
const N_PBUD: u8 = 0x0c;
const N_SECT: u8 = 0x0e;
const N_STAB: u8 = 0xe0;
const NLIST_64_SIZE: usize = 16;
const S_ATTR_PURE_INSTRUCTIONS: u32 = 0x8000_0000;
const S_ATTR_SOME_INSTRUCTIONS: u32 = 0x0000_0400;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MachNlistKind {
    Undefined,
    Absolute,
    Indirect,
    PreboundUndefined,
    Section,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct MachSection {
    address: u64,
    size: u64,
    flags: u32,
}

impl MachSection {
    fn contains_preferred_address(self, address: u64) -> bool {
        let Some(end) = self.address.checked_add(self.size) else {
            return false;
        };
        // A linker-defined end label may legally sit exactly at the section end.
        address >= self.address && address <= end
    }

    fn symbol_type(self) -> &'static str {
        if self.flags & (S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS) != 0 {
            "function"
        } else {
            "variable"
        }
    }
}

fn macho_nlist_kind(n_type: u8) -> MachNlistKind {
    match n_type & N_TYPE {
        N_UNDF => MachNlistKind::Undefined,
        N_ABS => MachNlistKind::Absolute,
        N_INDR => MachNlistKind::Indirect,
        N_PBUD => MachNlistKind::PreboundUndefined,
        N_SECT => MachNlistKind::Section,
        _ => MachNlistKind::Unknown,
    }
}

fn macho_symbol_is_global(n_type: u8) -> bool {
    n_type & N_EXT != 0
}

fn macho_symbol_is_defined(kind: MachNlistKind) -> bool {
    matches!(
        kind,
        MachNlistKind::Absolute | MachNlistKind::Indirect | MachNlistKind::Section
    )
}

fn macho_symbol_type(kind: MachNlistKind, n_sect: u8, sections: &[MachSection]) -> &'static str {
    match kind {
        MachNlistKind::Section if n_sect != 0 => sections
            .get(usize::from(n_sect) - 1)
            .copied()
            .map(MachSection::symbol_type)
            .unwrap_or("variable"),
        _ => "variable",
    }
}

fn nlist_section_is_valid(kind: MachNlistKind, n_sect: u8, n_value: u64, sections: &[MachSection]) -> bool {
    match kind {
        MachNlistKind::Section if n_sect != 0 => sections
            .get(usize::from(n_sect) - 1)
            .copied()
            .map(|section| section.contains_preferred_address(n_value))
            .unwrap_or(false),
        MachNlistKind::Section => false,
        MachNlistKind::Undefined
        | MachNlistKind::Absolute
        | MachNlistKind::Indirect
        | MachNlistKind::PreboundUndefined => n_sect == 0,
        MachNlistKind::Unknown => false,
    }
}

fn apply_macho_slide(address: u64, slide: isize) -> Option<usize> {
    let runtime_address = i128::from(address) + slide as i128;
    if !(0..=usize::MAX as i128).contains(&runtime_address) {
        return None;
    }
    Some(runtime_address as usize)
}

fn macho_symbol_address(kind: MachNlistKind, n_value: u64, slide: isize) -> Option<usize> {
    match kind {
        MachNlistKind::Section => apply_macho_slide(n_value, slide),
        MachNlistKind::Absolute => usize::try_from(n_value).ok(),
        _ => None,
    }
}

#[cfg_attr(not(any(target_os = "ios", target_os = "macos")), allow(dead_code))]
fn normalize_symbol_name(symbol_name: &str) -> &str {
    symbol_name.strip_prefix('_').unwrap_or(symbol_name)
}

#[cfg_attr(not(any(target_os = "ios", target_os = "macos")), allow(dead_code))]
fn query_matches_symbol(symbol_name: &str, query: &str) -> bool {
    let trimmed = query.trim();
    if trimmed.is_empty() {
        return false;
    }

    let needle = trimmed.to_ascii_lowercase();
    let normalized = normalize_symbol_name(symbol_name).to_ascii_lowercase();
    normalized.contains(&needle) || symbol_name.to_ascii_lowercase().contains(&needle)
}

fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    let raw: [u8; 4] = bytes.get(offset..offset.checked_add(4)?)?.try_into().ok()?;
    Some(u32::from_le_bytes(raw))
}

fn read_u64(bytes: &[u8], offset: usize) -> Option<u64> {
    let raw: [u8; 8] = bytes.get(offset..offset.checked_add(8)?)?.try_into().ok()?;
    Some(u64::from_le_bytes(raw))
}

fn read_symbol_name(strtab: &[u8], offset: usize) -> Option<String> {
    let raw = strtab.get(offset..)?;
    let end = raw.iter().position(|byte| *byte == 0)?;
    if end == 0 {
        return None;
    }
    Some(String::from_utf8_lossy(&raw[..end]).into_owned())
}

fn checked_linkedit_file_range(
    linkedit_file_offset: u64,
    linkedit_file_size: u64,
    data_offset: u64,
    data_size: usize,
) -> Option<std::ops::Range<usize>> {
    let linkedit_end = linkedit_file_offset.checked_add(linkedit_file_size)?;
    let data_size = u64::try_from(data_size).ok()?;
    let data_end = data_offset.checked_add(data_size)?;
    if data_offset < linkedit_file_offset || data_end > linkedit_end {
        return None;
    }
    Some(usize::try_from(data_offset).ok()?..usize::try_from(data_end).ok()?)
}

fn symbol_preference(symbol: &ImageSymbol) -> (bool, bool, bool, bool) {
    (
        symbol.is_defined,
        symbol.address != 0,
        symbol.is_global,
        symbol.symbol_type == "function",
    )
}

fn dedup_and_sort_image_symbols(symbols: &mut Vec<ImageSymbol>) {
    symbols.sort_by(|left, right| {
        normalize_symbol_name(&left.symbol_name)
            .cmp(normalize_symbol_name(&right.symbol_name))
            .then_with(|| symbol_preference(right).cmp(&symbol_preference(left)))
            .then(left.address.cmp(&right.address))
            .then(left.symbol_name.cmp(&right.symbol_name))
    });
    symbols
        .dedup_by(|left, right| normalize_symbol_name(&left.symbol_name) == normalize_symbol_name(&right.symbol_name));
    symbols.sort_by(|left, right| {
        left.address
            .cmp(&right.address)
            .then_with(|| normalize_symbol_name(&left.symbol_name).cmp(normalize_symbol_name(&right.symbol_name)))
            .then(left.symbol_name.cmp(&right.symbol_name))
    });
}

fn parse_nlist_symbols(
    module_name: &str,
    module_base: usize,
    slide: isize,
    symtab: &[u8],
    strtab: &[u8],
    sections: &[MachSection],
    query: Option<&str>,
) -> Vec<ImageSymbol> {
    if symtab.len() % NLIST_64_SIZE != 0 {
        return Vec::new();
    }

    let mut symbols = Vec::new();
    for entry in symtab.chunks_exact(NLIST_64_SIZE) {
        let Some(n_strx) = read_u32(entry, 0) else {
            continue;
        };
        let n_type = entry[4];
        let n_sect = entry[5];
        let Some(n_value) = read_u64(entry, 8) else {
            continue;
        };
        if n_type & N_STAB != 0 {
            continue;
        }

        let kind = macho_nlist_kind(n_type);
        if !nlist_section_is_valid(kind, n_sect, n_value, sections) {
            continue;
        }
        if kind == MachNlistKind::Indirect
            && usize::try_from(n_value)
                .ok()
                .and_then(|offset| read_symbol_name(strtab, offset))
                .is_none()
        {
            continue;
        }

        let Some(symbol_name) = usize::try_from(n_strx)
            .ok()
            .and_then(|offset| read_symbol_name(strtab, offset))
        else {
            continue;
        };
        if query.is_some_and(|query| !query_matches_symbol(&symbol_name, query)) {
            continue;
        }

        let address = macho_symbol_address(kind, n_value, slide).unwrap_or(0);
        symbols.push(ImageSymbol {
            module_name: module_name.to_owned(),
            module_base,
            symbol_name,
            symbol_type: macho_symbol_type(kind, n_sect, sections),
            address,
            offset: address.checked_sub(module_base).unwrap_or(0),
            is_global: macho_symbol_is_global(n_type),
            is_defined: macho_symbol_is_defined(kind),
        });
    }

    dedup_and_sort_image_symbols(&mut symbols);
    symbols
}

#[cfg(any(target_os = "ios", target_os = "macos"))]
mod platform {
    use common::{Error, Result};
    use std::mem::size_of;

    use crate::{enumerate_images, image_name_matches, ImageInfo, ImageSymbol, NativeSymbol};

    use super::{checked_linkedit_file_range, parse_nlist_symbols, read_u32, read_u64, MachSection, NLIST_64_SIZE};

    const LC_SEGMENT_64: u32 = 0x19;
    const LC_SYMTAB: u32 = 0x2;
    const MH_MAGIC_64: u32 = 0xfeedfacf;
    const LOAD_COMMAND_SIZE: usize = 8;
    const SEGMENT_COMMAND_64_SIZE: usize = 72;
    const SECTION_64_SIZE: usize = 80;
    const SYMTAB_COMMAND_SIZE: usize = 24;

    #[repr(C)]
    struct MachHeader64 {
        magic: u32,
        cputype: i32,
        cpusubtype: i32,
        filetype: u32,
        ncmds: u32,
        sizeofcmds: u32,
        flags: u32,
        reserved: u32,
    }

    #[derive(Debug, Clone, Copy)]
    struct LinkeditLayout {
        vmaddr: u64,
        fileoff: u64,
        filesize: u64,
    }

    #[derive(Debug, Clone, Copy)]
    struct SymtabLayout {
        symoff: u64,
        nsyms: usize,
        stroff: u64,
        strsize: usize,
    }

    pub fn native_symbol_support_available() -> bool {
        true
    }

    pub fn find_native_symbols(module_name: Option<&str>, query: &str) -> Result<Vec<NativeSymbol>> {
        let trimmed = query.trim();
        if trimmed.is_empty() {
            return Err(Error::InvalidArgument(
                "native symbol query must not be empty; use `native.symbols <query>` or `native.symbols <module> -- <query>`"
                    .into(),
            ));
        }

        let images = enumerate_images()?;
        let mut matches = Vec::new();
        for image in images {
            if let Some(module_name) = module_name {
                if !image_name_matches(module_name, &image.name) {
                    continue;
                }
            }

            matches.extend(
                collect_symbols_in_image(&image, Some(trimmed))?
                    .into_iter()
                    .filter(|symbol| symbol.is_defined && symbol.address != 0)
                    .map(|symbol| NativeSymbol {
                        module_name: symbol.module_name,
                        module_base: symbol.module_base,
                        symbol_name: symbol.symbol_name,
                        address: symbol.address,
                        offset: symbol.offset,
                    }),
            );
        }

        dedup_and_sort_symbols(&mut matches);
        Ok(matches)
    }

    pub fn find_image_symbols(module_name: &str) -> Result<Vec<ImageSymbol>> {
        let trimmed = module_name.trim();
        if trimmed.is_empty() {
            return Err(Error::InvalidArgument(
                "module name must not be empty; use `Module.enumerateSymbols(moduleName)`".into(),
            ));
        }

        let Some(image) = enumerate_images()?
            .into_iter()
            .find(|image| image_name_matches(trimmed, &image.name))
        else {
            return Ok(Vec::new());
        };
        collect_symbols_in_image(&image, None)
    }

    fn dedup_and_sort_symbols(matches: &mut Vec<NativeSymbol>) {
        matches.sort_by(|left, right| {
            left.module_name
                .cmp(&right.module_name)
                .then(left.address.cmp(&right.address))
                .then(left.symbol_name.cmp(&right.symbol_name))
        });
        matches.dedup_by(|left, right| {
            left.module_name == right.module_name
                && left.address == right.address
                && left.symbol_name == right.symbol_name
        });
    }

    fn collect_symbols_in_image(image: &ImageInfo, query: Option<&str>) -> Result<Vec<ImageSymbol>> {
        let header = image.base as *const MachHeader64;
        if header.is_null() || image.size < size_of::<MachHeader64>() {
            return Ok(Vec::new());
        }

        let header = unsafe { &*header };
        if header.magic != MH_MAGIC_64 {
            return Ok(Vec::new());
        }

        let command_region_size = header.sizeofcmds as usize;
        let Some(image_header_size) = size_of::<MachHeader64>().checked_add(command_region_size) else {
            return Ok(Vec::new());
        };
        if image_header_size > image.size
            || image.base.checked_add(image_header_size).is_none()
            || header.ncmds as usize > command_region_size / LOAD_COMMAND_SIZE
        {
            return Ok(Vec::new());
        }

        let command_ptr = unsafe { header_ptr_after_header(header) };
        let commands = unsafe { std::slice::from_raw_parts(command_ptr, command_region_size) };
        let mut linkedit_segment = None;
        let mut symtab = None;
        let mut sections = Vec::new();
        let mut consumed = 0usize;

        for _ in 0..header.ncmds {
            let Some(load_end) = consumed.checked_add(LOAD_COMMAND_SIZE) else {
                return Ok(Vec::new());
            };
            if load_end > commands.len() {
                return Ok(Vec::new());
            }

            let Some(command_kind) = read_u32(commands, consumed) else {
                return Ok(Vec::new());
            };
            let Some(command_size) = read_u32(commands, consumed + 4).map(|value| value as usize) else {
                return Ok(Vec::new());
            };
            let Some(command_end) = consumed.checked_add(command_size) else {
                return Ok(Vec::new());
            };
            if command_size < LOAD_COMMAND_SIZE || command_size % 8 != 0 || command_end > commands.len() {
                return Ok(Vec::new());
            }
            let command = &commands[consumed..command_end];

            match command_kind {
                LC_SEGMENT_64 => {
                    if !collect_segment_layout(command, &mut linkedit_segment, &mut sections) {
                        return Ok(Vec::new());
                    }
                }
                LC_SYMTAB => {
                    if command.len() < SYMTAB_COMMAND_SIZE || symtab.is_some() {
                        return Ok(Vec::new());
                    }
                    let Some(symoff) = read_u32(command, 8) else {
                        return Ok(Vec::new());
                    };
                    let Some(nsyms) = read_u32(command, 12) else {
                        return Ok(Vec::new());
                    };
                    let Some(stroff) = read_u32(command, 16) else {
                        return Ok(Vec::new());
                    };
                    let Some(strsize) = read_u32(command, 20) else {
                        return Ok(Vec::new());
                    };
                    symtab = Some(SymtabLayout {
                        symoff: u64::from(symoff),
                        nsyms: nsyms as usize,
                        stroff: u64::from(stroff),
                        strsize: strsize as usize,
                    });
                }
                _ => {}
            }

            consumed = command_end;
        }
        if consumed != commands.len() {
            return Ok(Vec::new());
        }

        let Some(linkedit_segment) = linkedit_segment else {
            return Ok(Vec::new());
        };
        let Some(symtab) = symtab else {
            return Ok(Vec::new());
        };
        if symtab.nsyms == 0 || symtab.strsize == 0 {
            return Ok(Vec::new());
        }

        let linkedit_base = compute_linkedit_base(image, linkedit_segment)?;
        let Some(symtab_size) = symtab.nsyms.checked_mul(NLIST_64_SIZE) else {
            return Ok(Vec::new());
        };
        let Some(symtab_range) = checked_linkedit_file_range(
            linkedit_segment.fileoff,
            linkedit_segment.filesize,
            symtab.symoff,
            symtab_size,
        ) else {
            return Ok(Vec::new());
        };
        let Some(strtab_range) = checked_linkedit_file_range(
            linkedit_segment.fileoff,
            linkedit_segment.filesize,
            symtab.stroff,
            symtab.strsize,
        ) else {
            return Ok(Vec::new());
        };

        let Some(symtab_address) = linkedit_base.checked_add(symtab_range.start) else {
            return Ok(Vec::new());
        };
        let Some(strtab_address) = linkedit_base.checked_add(strtab_range.start) else {
            return Ok(Vec::new());
        };
        if symtab_address == 0 || strtab_address == 0 {
            return Ok(Vec::new());
        }

        let symtab_bytes = unsafe { std::slice::from_raw_parts(symtab_address as *const u8, symtab_size) };
        let strtab_bytes = unsafe { std::slice::from_raw_parts(strtab_address as *const u8, symtab.strsize) };
        Ok(parse_nlist_symbols(
            &image.name,
            image.base,
            image.slide,
            symtab_bytes,
            strtab_bytes,
            &sections,
            query,
        ))
    }

    unsafe fn header_ptr_after_header(header: &MachHeader64) -> *const u8 {
        (header as *const MachHeader64).add(1) as *const u8
    }

    fn collect_segment_layout(
        command: &[u8],
        linkedit_segment: &mut Option<LinkeditLayout>,
        sections: &mut Vec<MachSection>,
    ) -> bool {
        if command.len() < SEGMENT_COMMAND_64_SIZE {
            return false;
        }
        let Some(vmaddr) = read_u64(command, 24) else {
            return false;
        };
        let Some(vmsize) = read_u64(command, 32) else {
            return false;
        };
        let Some(fileoff) = read_u64(command, 40) else {
            return false;
        };
        let Some(filesize) = read_u64(command, 48) else {
            return false;
        };
        let Some(nsects) = read_u32(command, 64).map(|value| value as usize) else {
            return false;
        };
        let Some(vm_end) = vmaddr.checked_add(vmsize) else {
            return false;
        };
        if fileoff.checked_add(filesize).is_none() || filesize > vmsize {
            return false;
        }
        let Some(section_bytes) = nsects.checked_mul(SECTION_64_SIZE) else {
            return false;
        };
        let Some(required_size) = SEGMENT_COMMAND_64_SIZE.checked_add(section_bytes) else {
            return false;
        };
        let Some(total_sections) = sections.len().checked_add(nsects) else {
            return false;
        };
        if required_size > command.len() || total_sections > u8::MAX as usize {
            return false;
        }

        if fixed_name(command.get(8..24).unwrap_or_default()) == Some("__LINKEDIT") {
            if linkedit_segment.is_some() {
                return false;
            }
            *linkedit_segment = Some(LinkeditLayout {
                vmaddr,
                fileoff,
                filesize,
            });
        }

        for index in 0..nsects {
            let Some(section_offset) = index
                .checked_mul(SECTION_64_SIZE)
                .and_then(|offset| SEGMENT_COMMAND_64_SIZE.checked_add(offset))
            else {
                return false;
            };
            let Some(section_end) = section_offset.checked_add(SECTION_64_SIZE) else {
                return false;
            };
            let Some(section) = command.get(section_offset..section_end) else {
                return false;
            };
            let Some(address) = read_u64(section, 32) else {
                return false;
            };
            let Some(size) = read_u64(section, 40) else {
                return false;
            };
            let Some(flags) = read_u32(section, 64) else {
                return false;
            };
            let Some(section_end) = address.checked_add(size) else {
                return false;
            };
            if address < vmaddr || section_end > vm_end {
                return false;
            }
            sections.push(MachSection { address, size, flags });
        }
        true
    }

    fn fixed_name(bytes: &[u8]) -> Option<&str> {
        let length = bytes.iter().position(|byte| *byte == 0).unwrap_or(bytes.len());
        std::str::from_utf8(&bytes[..length]).ok()
    }

    fn compute_linkedit_base(image: &ImageInfo, linkedit_segment: LinkeditLayout) -> Result<usize> {
        let base = image.slide as i128 + linkedit_segment.vmaddr as i128 - linkedit_segment.fileoff as i128;
        if base < 0 || base > usize::MAX as i128 {
            return Err(Error::State(format!(
                "computed __LINKEDIT base for {} overflowed address space",
                image.name
            )));
        }
        let base = base as usize;
        let Some(runtime_start) = base.checked_add(usize::try_from(linkedit_segment.fileoff).map_err(|_| {
            Error::State(format!(
                "__LINKEDIT file offset for {} overflowed address space",
                image.name
            ))
        })?) else {
            return Err(Error::State(format!(
                "computed __LINKEDIT start for {} overflowed address space",
                image.name
            )));
        };
        let runtime_size = usize::try_from(linkedit_segment.filesize).map_err(|_| {
            Error::State(format!(
                "__LINKEDIT file size for {} overflowed address space",
                image.name
            ))
        })?;
        if runtime_start.checked_add(runtime_size).is_none() {
            return Err(Error::State(format!(
                "computed __LINKEDIT end for {} overflowed address space",
                image.name
            )));
        }
        Ok(base)
    }
}

#[cfg(not(any(target_os = "ios", target_os = "macos")))]
mod platform {
    use common::{Error, Result};

    use crate::{ImageSymbol, NativeSymbol};

    pub fn native_symbol_support_available() -> bool {
        false
    }

    pub fn find_native_symbols(_module_name: Option<&str>, query: &str) -> Result<Vec<NativeSymbol>> {
        if query.trim().is_empty() {
            return Err(Error::InvalidArgument(
                "native symbol query must not be empty; use `native.symbols <query>` or `native.symbols <module> -- <query>`"
                    .into(),
            ));
        }

        Err(Error::Unsupported(
            "native symbol enumeration is currently only available on Apple targets".into(),
        ))
    }

    pub fn find_image_symbols(module_name: &str) -> Result<Vec<ImageSymbol>> {
        if module_name.trim().is_empty() {
            return Err(Error::InvalidArgument(
                "module name must not be empty; use `Module.enumerateSymbols(moduleName)`".into(),
            ));
        }
        Err(Error::Unsupported(
            "image symbol enumeration is currently only available on Apple targets".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn section(address: u64, size: u64, flags: u32) -> MachSection {
        MachSection { address, size, flags }
    }

    fn push_name(strtab: &mut Vec<u8>, name: &str) -> u32 {
        let offset = u32::try_from(strtab.len()).expect("test string table offset");
        strtab.extend_from_slice(name.as_bytes());
        strtab.push(0);
        offset
    }

    fn push_nlist(symtab: &mut Vec<u8>, n_strx: u32, n_type: u8, n_sect: u8, n_value: u64) {
        symtab.extend_from_slice(&n_strx.to_le_bytes());
        symtab.push(n_type);
        symtab.push(n_sect);
        symtab.extend_from_slice(&0u16.to_le_bytes());
        symtab.extend_from_slice(&n_value.to_le_bytes());
    }

    fn symbol<'a>(symbols: &'a [ImageSymbol], name: &str) -> &'a ImageSymbol {
        symbols
            .iter()
            .find(|symbol| symbol.symbol_name == name)
            .unwrap_or_else(|| panic!("missing symbol {name}"))
    }

    #[test]
    fn query_matches_plain_and_underscored_names() {
        assert!(query_matches_symbol("_malloc", "malloc"));
        assert!(query_matches_symbol("objc_msgSend", "msgsend"));
        assert!(!query_matches_symbol("free", "malloc"));
    }

    #[test]
    fn nlist_parser_rebases_sections_and_keeps_absolute_and_undefined_semantics() {
        let sections = [
            section(0x1000, 0x100, 0),
            section(0x2000, 0x100, S_ATTR_PURE_INSTRUCTIONS),
        ];
        let mut strtab = vec![0];
        let local_fn = push_name(&mut strtab, "_local_fn");
        let global_data = push_name(&mut strtab, "_global_data");
        let undefined = push_name(&mut strtab, "_undefined");
        let absolute = push_name(&mut strtab, "_absolute");
        let stab = push_name(&mut strtab, "_debug_only");

        let mut symtab = Vec::new();
        push_nlist(&mut symtab, local_fn, N_SECT, 2, 0x2020);
        push_nlist(&mut symtab, global_data, N_SECT | N_EXT, 1, 0x1010);
        push_nlist(&mut symtab, undefined, N_UNDF | N_EXT, 0, 0);
        push_nlist(&mut symtab, absolute, N_ABS | N_EXT, 0, 0x77);
        push_nlist(&mut symtab, stab, N_STAB | N_SECT, 2, 0x2030);

        let symbols = parse_nlist_symbols("/tmp/Test.dylib", 0x11000, 0x10000, &symtab, &strtab, &sections, None);
        assert_eq!(symbols.len(), 4);

        let local_fn = symbol(&symbols, "_local_fn");
        assert_eq!(local_fn.symbol_type, "function");
        assert_eq!(local_fn.address, 0x12020);
        assert_eq!(local_fn.offset, 0x1020);
        assert!(local_fn.is_defined);
        assert!(!local_fn.is_global);

        let global_data = symbol(&symbols, "_global_data");
        assert_eq!(global_data.symbol_type, "variable");
        assert_eq!(global_data.address, 0x11010);
        assert_eq!(global_data.offset, 0x10);
        assert!(global_data.is_defined);
        assert!(global_data.is_global);

        let undefined = symbol(&symbols, "_undefined");
        assert_eq!(undefined.address, 0);
        assert!(!undefined.is_defined);
        assert!(undefined.is_global);

        let absolute = symbol(&symbols, "_absolute");
        assert_eq!(absolute.address, 0x77);
        assert_eq!(absolute.offset, 0);
        assert!(absolute.is_defined);
    }

    #[test]
    fn nlist_parser_validates_section_ordinals_and_preferred_ranges() {
        let sections = [section(0x1000, 0x100, S_ATTR_SOME_INSTRUCTIONS)];
        let mut strtab = vec![0];
        let valid = push_name(&mut strtab, "_valid");
        let missing_section = push_name(&mut strtab, "_missing_section");
        let outside_section = push_name(&mut strtab, "_outside_section");
        let malformed_absolute = push_name(&mut strtab, "_malformed_absolute");
        let unknown_type = push_name(&mut strtab, "_unknown_type");
        let mut symtab = Vec::new();
        push_nlist(&mut symtab, valid, N_SECT, 1, 0x1100);
        push_nlist(&mut symtab, missing_section, N_SECT, 2, 0x1000);
        push_nlist(&mut symtab, outside_section, N_SECT, 1, 0x2000);
        push_nlist(&mut symtab, malformed_absolute, N_ABS, 1, 0x20);
        push_nlist(&mut symtab, unknown_type, 0x04, 0, 0);

        let symbols = parse_nlist_symbols("Test", 0x5000, 0x4000, &symtab, &strtab, &sections, None);
        assert_eq!(symbols.len(), 1);
        assert_eq!(symbols[0].symbol_name, "_valid");
        assert_eq!(symbols[0].address, 0x5100);
        assert_eq!(symbols[0].symbol_type, "function");
    }

    #[test]
    fn nlist_parser_handles_undefined_prebound_and_indirect_types_without_rebasing_values() {
        let sections = [section(0x1000, 0x100, 0)];
        let mut strtab = vec![0];
        let common = push_name(&mut strtab, "_common");
        let prebound = push_name(&mut strtab, "_prebound");
        let indirect = push_name(&mut strtab, "_alias");
        let target = push_name(&mut strtab, "_target");
        let invalid_indirect = push_name(&mut strtab, "_invalid_alias");
        let mut symtab = Vec::new();
        push_nlist(&mut symtab, common, N_UNDF | N_EXT, 0, 0x40);
        push_nlist(&mut symtab, prebound, N_PBUD | N_EXT, 0, 0x2000);
        push_nlist(&mut symtab, indirect, N_INDR | N_EXT, 0, u64::from(target));
        push_nlist(&mut symtab, invalid_indirect, N_INDR | N_EXT, 0, u64::MAX);

        let symbols = parse_nlist_symbols("Test", 0x5000, 0x4000, &symtab, &strtab, &sections, None);
        assert_eq!(symbols.len(), 3);

        let common = symbol(&symbols, "_common");
        assert_eq!(common.address, 0);
        assert!(!common.is_defined);

        let prebound = symbol(&symbols, "_prebound");
        assert_eq!(prebound.address, 0);
        assert!(!prebound.is_defined);

        let indirect = symbol(&symbols, "_alias");
        assert_eq!(indirect.address, 0);
        assert!(indirect.is_defined);
    }

    #[test]
    fn nlist_parser_deduplicates_normalized_names_and_prefers_definitions() {
        let sections = [section(0x1000, 0x100, 0)];
        let mut strtab = vec![0];
        let undefined = push_name(&mut strtab, "_duplicate");
        let defined = push_name(&mut strtab, "duplicate");
        let mut symtab = Vec::new();
        push_nlist(&mut symtab, undefined, N_UNDF | N_EXT, 0, 0);
        push_nlist(&mut symtab, defined, N_SECT, 1, 0x1020);

        let symbols = parse_nlist_symbols("Test", 0x5000, 0x4000, &symtab, &strtab, &sections, None);
        assert_eq!(symbols.len(), 1);
        assert_eq!(symbols[0].symbol_name, "duplicate");
        assert_eq!(symbols[0].address, 0x5020);
        assert!(symbols[0].is_defined);
        assert!(!symbols[0].is_global);
    }

    #[test]
    fn nlist_parser_rejects_truncated_entries_and_invalid_strings() {
        let sections = [section(0x1000, 0x100, 0)];
        let mut symtab = Vec::new();
        push_nlist(&mut symtab, 1, N_SECT, 1, 0x1020);
        assert!(parse_nlist_symbols("Test", 0, 0, &symtab[..15], b"\0_name\0", &sections, None).is_empty());
        assert!(parse_nlist_symbols("Test", 0, 0, &symtab, b"\0unterminated", &sections, None).is_empty());

        let mut invalid_offset = Vec::new();
        push_nlist(&mut invalid_offset, 99, N_SECT, 1, 0x1020);
        assert!(parse_nlist_symbols("Test", 0, 0, &invalid_offset, b"\0_name\0", &sections, None).is_empty());
    }

    #[test]
    fn slide_and_linkedit_ranges_are_checked() {
        assert_eq!(apply_macho_slide(0x3000, -0x1000), Some(0x2000));
        assert_eq!(apply_macho_slide(0x1000, -0x2000), None);
        assert_eq!(apply_macho_slide(u64::MAX, 1), None);

        assert_eq!(
            checked_linkedit_file_range(0x1000, 0x400, 0x1100, 0x20),
            Some(0x1100..0x1120)
        );
        assert!(checked_linkedit_file_range(0x1000, 0x400, 0x0ff0, 0x20).is_none());
        assert!(checked_linkedit_file_range(0x1000, 0x400, 0x13f0, 0x20).is_none());
        assert!(checked_linkedit_file_range(u64::MAX - 1, 8, u64::MAX - 1, 1).is_none());
    }

    #[test]
    fn query_filter_applies_after_nlist_validation() {
        let sections = [section(0x1000, 0x100, 0)];
        let mut strtab = vec![0];
        let wanted = push_name(&mut strtab, "_WantedSymbol");
        let other = push_name(&mut strtab, "_other");
        let mut symtab = Vec::new();
        push_nlist(&mut symtab, wanted, N_SECT, 1, 0x1010);
        push_nlist(&mut symtab, other, N_SECT, 1, 0x1020);

        let symbols = parse_nlist_symbols("Test", 0x5000, 0x4000, &symtab, &strtab, &sections, Some("wanted"));
        assert_eq!(symbols.len(), 1);
        assert_eq!(symbols[0].symbol_name, "_WantedSymbol");
    }

    #[cfg(not(any(target_os = "ios", target_os = "macos")))]
    #[test]
    fn non_apple_symbol_enumeration_reports_unsupported() {
        let err = find_native_symbols(None, "malloc").expect_err("non-apple platforms should be unsupported");
        assert!(err.to_string().contains("Apple targets"));

        let err = find_image_symbols("Test.dylib").expect_err("non-apple platforms should be unsupported");
        assert!(err.to_string().contains("Apple targets"));
    }
}
