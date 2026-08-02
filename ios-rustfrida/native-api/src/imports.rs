use common::Result;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageImport {
    pub module_name: String,
    pub module_base: usize,
    pub symbol_name: String,
    pub symbol_type: String,
    pub slot: usize,
    pub address: usize,
    pub dylib_ordinal: u8,
    pub dylib_name: Option<String>,
    pub weak_import: bool,
}

pub fn image_import_support_available() -> bool {
    platform::image_import_support_available()
}

pub fn find_image_imports(module_name: &str, query: Option<&str>) -> Result<Vec<ImageImport>> {
    platform::find_image_imports(module_name, query)
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

#[cfg(any(target_os = "ios", target_os = "macos"))]
mod platform {
    use common::{Error, Result};
    use std::mem::size_of;
    use std::ptr;

    use crate::macho_load_commands::{
        LC_DYSYMTAB, LC_LAZY_LOAD_DYLIB, LC_LOAD_DYLIB, LC_LOAD_UPWARD_DYLIB, LC_LOAD_WEAK_DYLIB, LC_REEXPORT_DYLIB,
        LC_SEGMENT_64, LC_SYMTAB,
    };
    use crate::{enumerate_images, image_name_matches, ImageImport, ImageInfo};

    use super::query_matches_symbol;

    const MH_MAGIC_64: u32 = 0xfeedfacf;
    const SECTION_TYPE: u32 = 0x0000_00ff;
    const S_NON_LAZY_SYMBOL_POINTERS: u32 = 0x6;
    const S_LAZY_SYMBOL_POINTERS: u32 = 0x7;
    const INDIRECT_SYMBOL_LOCAL: u32 = 0x8000_0000;
    const INDIRECT_SYMBOL_ABS: u32 = 0x4000_0000;
    const N_UNDF: u8 = 0x0;
    const N_TYPE: u8 = 0x0e;
    const N_EXT: u8 = 0x01;
    const N_STAB: u8 = 0xe0;
    const N_WEAK_REF: u16 = 0x0040;
    const N_REF_TO_WEAK: u16 = 0x0080;
    const ORDINAL_MASK: u16 = 0xff00;
    const ORDINAL_SHIFT: u16 = 8;
    const ORDINAL_SELF: u8 = 0;
    const ORDINAL_DYNAMIC_LOOKUP: u8 = 0xfe;
    const ORDINAL_EXECUTABLE: u8 = 0xff;
    const POINTER_SIZE: usize = size_of::<usize>();
    const MAX_LOAD_COMMAND_BYTES: usize = 64 * 1024 * 1024;

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

    #[repr(C)]
    struct LoadCommand {
        cmd: u32,
        cmdsize: u32,
    }

    #[repr(C)]
    struct SymtabCommand {
        cmd: u32,
        cmdsize: u32,
        symoff: u32,
        nsyms: u32,
        stroff: u32,
        strsize: u32,
    }

    #[repr(C)]
    struct DysymtabCommand {
        cmd: u32,
        cmdsize: u32,
        ilocalsym: u32,
        nlocalsym: u32,
        iextdefsym: u32,
        nextdefsym: u32,
        iundefsym: u32,
        nundefsym: u32,
        tocoff: u32,
        ntoc: u32,
        modtaboff: u32,
        nmodtab: u32,
        extrefsymoff: u32,
        nextrefsyms: u32,
        indirectsymoff: u32,
        nindirectsyms: u32,
        extreloff: u32,
        nextrel: u32,
        locreloff: u32,
        nlocrel: u32,
    }

    #[repr(C)]
    struct SegmentCommand64 {
        cmd: u32,
        cmdsize: u32,
        segname: [u8; 16],
        vmaddr: u64,
        vmsize: u64,
        fileoff: u64,
        filesize: u64,
        maxprot: i32,
        initprot: i32,
        nsects: u32,
        flags: u32,
    }

    #[repr(C)]
    struct Section64 {
        sectname: [u8; 16],
        segname: [u8; 16],
        addr: u64,
        size: u64,
        offset: u32,
        align: u32,
        reloff: u32,
        nreloc: u32,
        flags: u32,
        reserved1: u32,
        reserved2: u32,
        reserved3: u32,
    }

    #[repr(C)]
    struct Dylib {
        name: u32,
        timestamp: u32,
        current_version: u32,
        compatibility_version: u32,
    }

    #[repr(C)]
    struct DylibCommand {
        cmd: u32,
        cmdsize: u32,
        dylib: Dylib,
    }

    #[repr(C)]
    struct Nlist64 {
        n_strx: u32,
        n_type: u8,
        n_sect: u8,
        n_desc: u16,
        n_value: u64,
    }

    #[derive(Clone, Copy)]
    struct SymtabLayout {
        symoff: u32,
        nsyms: u32,
        stroff: u32,
        strsize: u32,
    }

    #[derive(Clone, Copy)]
    struct DysymtabLayout {
        indirectsymoff: u32,
        nindirectsyms: u32,
    }

    #[derive(Clone, Copy)]
    struct LinkeditLayout {
        vmaddr: u64,
        vmsize: u64,
        fileoff: u64,
        filesize: u64,
    }

    #[derive(Clone, Copy)]
    struct ImportSection {
        address: u64,
        size: u64,
        indirect_start: u32,
        symbol_type: &'static str,
        readable: bool,
    }

    struct LinkeditTables {
        symtab: *const Nlist64,
        nsyms: usize,
        strtab: *const u8,
        strtab_len: usize,
        indirect_symbols: *const u32,
        nindirect_symbols: usize,
    }

    pub fn image_import_support_available() -> bool {
        true
    }

    pub fn find_image_imports(module_name: &str, query: Option<&str>) -> Result<Vec<ImageImport>> {
        let trimmed_module = module_name.trim();
        if trimmed_module.is_empty() {
            return Err(Error::InvalidArgument(
                "module name must not be empty; use `native.imports <module>` or `native.imports <module> -- <query>`"
                    .into(),
            ));
        }

        let trimmed_query = query.map(str::trim).filter(|value| !value.is_empty());
        let Some(image) = enumerate_images()?
            .into_iter()
            .find(|image| image_name_matches(trimmed_module, &image.name))
        else {
            return Ok(Vec::new());
        };

        collect_imports_in_image(&image, trimmed_query)
    }

    fn collect_imports_in_image(image: &ImageInfo, query: Option<&str>) -> Result<Vec<ImageImport>> {
        let header = image.base as *const MachHeader64;
        if header.is_null() {
            return Ok(Vec::new());
        }

        let header = unsafe { &*header };
        if header.magic != MH_MAGIC_64 {
            return Ok(Vec::new());
        }

        let mut symtab = None::<SymtabLayout>;
        let mut dysymtab = None::<DysymtabLayout>;
        let mut linkedit = None::<LinkeditLayout>;
        let mut dylibs = Vec::new();
        let command_region_size = header.sizeofcmds as usize;
        if command_region_size > MAX_LOAD_COMMAND_BYTES
            || header.ncmds as usize > command_region_size / size_of::<LoadCommand>()
        {
            return Ok(Vec::new());
        }
        let Some(command_start) = image.base.checked_add(size_of::<MachHeader64>()) else {
            return Ok(Vec::new());
        };
        let Some(command_end) = command_start.checked_add(command_region_size) else {
            return Ok(Vec::new());
        };
        if image.size != 0
            && image
                .base
                .checked_add(image.size)
                .map(|image_end| command_end > image_end)
                .unwrap_or(true)
        {
            return Ok(Vec::new());
        }

        let mut import_sections = Vec::new();
        let mut consumed = 0usize;

        for _ in 0..header.ncmds {
            let Some(load_end) = consumed.checked_add(size_of::<LoadCommand>()) else {
                return Ok(Vec::new());
            };
            if load_end > command_region_size {
                return Ok(Vec::new());
            }
            let Some(command_address) = command_start.checked_add(consumed) else {
                return Ok(Vec::new());
            };
            if command_address < command_start || command_address >= command_end {
                return Ok(Vec::new());
            }
            let command_ptr = command_address as *const u8;
            let load = unsafe { ptr::read_unaligned(command_ptr as *const LoadCommand) };
            let command_size = load.cmdsize as usize;
            let Some(next_consumed) = consumed.checked_add(command_size) else {
                return Ok(Vec::new());
            };
            if command_size < size_of::<LoadCommand>() || next_consumed > command_region_size {
                return Ok(Vec::new());
            }

            match load.cmd {
                LC_SYMTAB => {
                    if command_size < size_of::<SymtabCommand>() {
                        return Ok(Vec::new());
                    }
                    let table = unsafe { ptr::read_unaligned(command_ptr as *const SymtabCommand) };
                    symtab = Some(SymtabLayout {
                        symoff: table.symoff,
                        nsyms: table.nsyms,
                        stroff: table.stroff,
                        strsize: table.strsize,
                    });
                }
                LC_DYSYMTAB => {
                    if command_size < size_of::<DysymtabCommand>() {
                        return Ok(Vec::new());
                    }
                    let table = unsafe { ptr::read_unaligned(command_ptr as *const DysymtabCommand) };
                    dysymtab = Some(DysymtabLayout {
                        indirectsymoff: table.indirectsymoff,
                        nindirectsyms: table.nindirectsyms,
                    });
                }
                LC_LOAD_DYLIB | LC_LOAD_WEAK_DYLIB | LC_REEXPORT_DYLIB | LC_LAZY_LOAD_DYLIB | LC_LOAD_UPWARD_DYLIB => {
                    if command_size < size_of::<DylibCommand>() {
                        return Ok(Vec::new());
                    }
                    let command = unsafe { ptr::read_unaligned(command_ptr as *const DylibCommand) };
                    let bytes = unsafe { std::slice::from_raw_parts(command_ptr, command_size) };
                    dylibs.push(read_command_string(bytes, command.dylib.name));
                }
                LC_SEGMENT_64 => {
                    if command_size < size_of::<SegmentCommand64>() {
                        return Ok(Vec::new());
                    }
                    let segment = unsafe { ptr::read_unaligned(command_ptr as *const SegmentCommand64) };
                    if fixed_name(&segment.segname) == "__LINKEDIT" {
                        linkedit = Some(LinkeditLayout {
                            vmaddr: segment.vmaddr,
                            vmsize: segment.vmsize,
                            fileoff: segment.fileoff,
                            filesize: segment.filesize,
                        });
                    }

                    let section_count = segment.nsects as usize;
                    let Some(section_bytes) = section_count.checked_mul(size_of::<Section64>()) else {
                        return Ok(Vec::new());
                    };
                    let Some(required_size) = size_of::<SegmentCommand64>().checked_add(section_bytes) else {
                        return Ok(Vec::new());
                    };
                    if required_size > command_size {
                        return Ok(Vec::new());
                    }

                    for section_index in 0..section_count {
                        let Some(section_offset) = section_index
                            .checked_mul(size_of::<Section64>())
                            .and_then(|offset| size_of::<SegmentCommand64>().checked_add(offset))
                        else {
                            return Ok(Vec::new());
                        };
                        let section =
                            unsafe { ptr::read_unaligned(command_ptr.add(section_offset) as *const Section64) };
                        let symbol_type = match section.flags & SECTION_TYPE {
                            S_LAZY_SYMBOL_POINTERS => "function",
                            S_NON_LAZY_SYMBOL_POINTERS => "variable",
                            _ => continue,
                        };
                        if section.size == 0
                            || section.size % POINTER_SIZE as u64 != 0
                            || !range_contains(segment.vmaddr, segment.vmsize, section.addr, section.size)
                        {
                            continue;
                        }
                        import_sections.push(ImportSection {
                            address: section.addr,
                            size: section.size,
                            indirect_start: section.reserved1,
                            symbol_type,
                            readable: segment.initprot & 1 != 0,
                        });
                    }
                }
                _ => {}
            }

            consumed = next_consumed;
        }

        let Some(symtab) = symtab else {
            return Ok(Vec::new());
        };
        let Some(dysymtab) = dysymtab else {
            return Ok(Vec::new());
        };
        let Some(linkedit) = linkedit else {
            return Ok(Vec::new());
        };
        if symtab.nsyms == 0 || symtab.strsize == 0 || dysymtab.nindirectsyms == 0 || import_sections.is_empty() {
            return Ok(Vec::new());
        }

        let Some(tables) = resolve_linkedit_tables(image, linkedit, symtab, dysymtab) else {
            return Ok(Vec::new());
        };

        let mut matches = Vec::new();
        for section in import_sections {
            if !section.readable || image.size == 0 {
                continue;
            }
            let Some(pointer_count) = usize::try_from(section.size / POINTER_SIZE as u64).ok() else {
                continue;
            };
            let indirect_start = section.indirect_start as usize;
            let Some(indirect_end) = indirect_start.checked_add(pointer_count) else {
                continue;
            };
            if indirect_end > tables.nindirect_symbols {
                continue;
            }
            let Some(slot_start) = apply_slide(section.address, image.slide) else {
                continue;
            };
            let Some(slot_bytes) = pointer_count.checked_mul(POINTER_SIZE) else {
                continue;
            };
            let Some(slot_end) = slot_start.checked_add(slot_bytes) else {
                continue;
            };
            let Some(image_end) = image.base.checked_add(image.size) else {
                continue;
            };
            if slot_start < image.base || slot_end > image_end {
                continue;
            }

            for pointer_index in 0..pointer_count {
                let indirect_index = indirect_start + pointer_index;
                let symbol_index = unsafe { ptr::read_unaligned(tables.indirect_symbols.add(indirect_index)) };
                if symbol_index & (INDIRECT_SYMBOL_LOCAL | INDIRECT_SYMBOL_ABS) != 0 {
                    continue;
                }
                let symbol_index = symbol_index as usize;
                if symbol_index >= tables.nsyms {
                    continue;
                }

                let entry = unsafe { ptr::read_unaligned(tables.symtab.add(symbol_index)) };
                if (entry.n_type & N_STAB) != 0 || (entry.n_type & N_EXT) == 0 || (entry.n_type & N_TYPE) != N_UNDF {
                    continue;
                }

                let Some(symbol_name) = read_symbol_name(tables.strtab, tables.strtab_len, entry.n_strx as usize)
                else {
                    continue;
                };
                if query
                    .map(|query| !query_matches_symbol(&symbol_name, query))
                    .unwrap_or(false)
                {
                    continue;
                }

                let Some(slot_offset) = pointer_index.checked_mul(POINTER_SIZE) else {
                    continue;
                };
                let Some(slot) = slot_start.checked_add(slot_offset) else {
                    continue;
                };
                let address = unsafe { ptr::read_unaligned(slot as *const usize) };
                let ordinal = ((entry.n_desc & ORDINAL_MASK) >> ORDINAL_SHIFT) as u8;
                matches.push(ImageImport {
                    module_name: image.name.clone(),
                    module_base: image.base,
                    symbol_name,
                    symbol_type: section.symbol_type.into(),
                    slot,
                    address,
                    dylib_ordinal: ordinal,
                    dylib_name: resolve_dylib_name(ordinal, &dylibs),
                    weak_import: (entry.n_desc & (N_WEAK_REF | N_REF_TO_WEAK)) != 0,
                });
            }
        }

        dedup_and_sort_imports(&mut matches);
        Ok(matches)
    }

    fn dedup_and_sort_imports(matches: &mut Vec<ImageImport>) {
        matches.sort_by(|left, right| {
            left.module_name
                .cmp(&right.module_name)
                .then(left.symbol_name.cmp(&right.symbol_name))
                .then(left.slot.cmp(&right.slot))
                .then(left.dylib_ordinal.cmp(&right.dylib_ordinal))
                .then(left.weak_import.cmp(&right.weak_import))
        });
        matches.dedup_by(|left, right| {
            left.module_name == right.module_name && left.symbol_name == right.symbol_name && left.slot == right.slot
        });
    }

    fn resolve_linkedit_tables(
        image: &ImageInfo,
        linkedit: LinkeditLayout,
        symtab: SymtabLayout,
        dysymtab: DysymtabLayout,
    ) -> Option<LinkeditTables> {
        let symtab_size = (symtab.nsyms as usize).checked_mul(size_of::<Nlist64>())?;
        let strtab_size = symtab.strsize as usize;
        let indirect_size = (dysymtab.nindirectsyms as usize).checked_mul(size_of::<u32>())?;
        if !file_range_in_linkedit(symtab.symoff as u64, symtab_size, linkedit)
            || !file_range_in_linkedit(symtab.stroff as u64, strtab_size, linkedit)
            || !file_range_in_linkedit(dysymtab.indirectsymoff as u64, indirect_size, linkedit)
        {
            return None;
        }

        let linkedit_runtime_start = apply_slide(linkedit.vmaddr, image.slide)?;
        let linkedit_runtime_end = linkedit_runtime_start.checked_add(usize::try_from(linkedit.vmsize).ok()?)?;
        let linkedit_base = linkedit_runtime_start.checked_sub(usize::try_from(linkedit.fileoff).ok()?)?;
        let symtab_address = checked_table_address(linkedit_base, symtab.symoff as u64, symtab_size)?;
        let strtab_address = checked_table_address(linkedit_base, symtab.stroff as u64, strtab_size)?;
        let indirect_address = checked_table_address(linkedit_base, dysymtab.indirectsymoff as u64, indirect_size)?;
        if !runtime_range_in_linkedit(
            symtab_address,
            symtab_size,
            linkedit_runtime_start,
            linkedit_runtime_end,
        ) || !runtime_range_in_linkedit(
            strtab_address,
            strtab_size,
            linkedit_runtime_start,
            linkedit_runtime_end,
        ) || !runtime_range_in_linkedit(
            indirect_address,
            indirect_size,
            linkedit_runtime_start,
            linkedit_runtime_end,
        ) {
            return None;
        }

        Some(LinkeditTables {
            symtab: symtab_address as *const Nlist64,
            nsyms: symtab.nsyms as usize,
            strtab: strtab_address as *const u8,
            strtab_len: strtab_size,
            indirect_symbols: indirect_address as *const u32,
            nindirect_symbols: dysymtab.nindirectsyms as usize,
        })
    }

    fn file_range_in_linkedit(offset: u64, size: usize, linkedit: LinkeditLayout) -> bool {
        let Ok(size) = u64::try_from(size) else {
            return false;
        };
        let Some(range_end) = offset.checked_add(size) else {
            return false;
        };
        let Some(linkedit_end) = linkedit.fileoff.checked_add(linkedit.filesize) else {
            return false;
        };
        offset >= linkedit.fileoff && range_end <= linkedit_end
    }

    fn checked_table_address(base: usize, file_offset: u64, size: usize) -> Option<usize> {
        if size > isize::MAX as usize {
            return None;
        }
        let address = base.checked_add(usize::try_from(file_offset).ok()?)?;
        if address == 0 || address.checked_add(size).is_none() {
            return None;
        }
        Some(address)
    }

    fn runtime_range_in_linkedit(address: usize, size: usize, start: usize, end: usize) -> bool {
        address >= start
            && address
                .checked_add(size)
                .map(|range_end| range_end <= end)
                .unwrap_or(false)
    }

    fn apply_slide(address: u64, slide: isize) -> Option<usize> {
        let runtime_address = i128::from(address).checked_add(slide as i128)?;
        if runtime_address < 0 {
            return None;
        }
        usize::try_from(runtime_address).ok()
    }

    fn range_contains(outer_start: u64, outer_size: u64, inner_start: u64, inner_size: u64) -> bool {
        let Some(outer_end) = outer_start.checked_add(outer_size) else {
            return false;
        };
        let Some(inner_end) = inner_start.checked_add(inner_size) else {
            return false;
        };
        inner_start >= outer_start && inner_end <= outer_end
    }

    fn resolve_dylib_name(ordinal: u8, dylibs: &[Option<String>]) -> Option<String> {
        match ordinal {
            ORDINAL_SELF => Some("<self>".into()),
            ORDINAL_DYNAMIC_LOOKUP => Some("<dynamic-lookup>".into()),
            ORDINAL_EXECUTABLE => Some("<main-executable>".into()),
            value if value >= 1 => dylibs.get((value - 1) as usize).cloned().flatten(),
            _ => None,
        }
    }

    fn read_command_string(bytes: &[u8], offset: u32) -> Option<String> {
        let start = offset as usize;
        if start >= bytes.len() {
            return None;
        }
        let tail = &bytes[start..];
        let end = tail.iter().position(|byte| *byte == 0).unwrap_or(tail.len());
        if end == 0 {
            return None;
        }
        Some(String::from_utf8_lossy(&tail[..end]).into_owned())
    }

    fn read_symbol_name(strtab_ptr: *const u8, strtab_len: usize, offset: usize) -> Option<String> {
        if offset >= strtab_len {
            return None;
        }

        let raw = unsafe { std::slice::from_raw_parts(strtab_ptr.add(offset), strtab_len - offset) };
        let end = raw.iter().position(|byte| *byte == 0)?;
        if end == 0 {
            return None;
        }

        Some(String::from_utf8_lossy(&raw[..end]).into_owned())
    }

    fn fixed_name(raw: &[u8; 16]) -> &str {
        let end = raw.iter().position(|byte| *byte == 0).unwrap_or(raw.len());
        std::str::from_utf8(&raw[..end]).unwrap_or("")
    }
}

#[cfg(not(any(target_os = "ios", target_os = "macos")))]
mod platform {
    use common::{Error, Result};

    use crate::ImageImport;

    pub fn image_import_support_available() -> bool {
        false
    }

    pub fn find_image_imports(module_name: &str, _query: Option<&str>) -> Result<Vec<ImageImport>> {
        if module_name.trim().is_empty() {
            return Err(Error::InvalidArgument(
                "module name must not be empty; use `native.imports <module>` or `native.imports <module> -- <query>`"
                    .into(),
            ));
        }

        Err(Error::Unsupported(
            "native import enumeration is currently only available on Apple targets".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::{find_image_imports, query_matches_symbol};

    #[test]
    fn import_query_matches_plain_and_underscored_names() {
        assert!(query_matches_symbol("_malloc", "malloc"));
        assert!(query_matches_symbol("_objc_msgSend", "msgsend"));
        assert!(!query_matches_symbol("_free", "malloc"));
    }

    #[cfg(not(any(target_os = "ios", target_os = "macos")))]
    #[test]
    fn non_apple_import_enumeration_reports_unsupported() {
        let err =
            find_image_imports("libsystem_malloc.dylib", None).expect_err("non-apple platforms should be unsupported");
        assert!(err.to_string().contains("Apple targets"));
    }
}
