use common::Result;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeSymbol {
    pub module_name: String,
    pub module_base: usize,
    pub symbol_name: String,
    pub address: usize,
    pub offset: usize,
}

pub fn native_symbol_support_available() -> bool {
    platform::native_symbol_support_available()
}

pub fn find_native_symbols(module_name: Option<&str>, query: &str) -> Result<Vec<NativeSymbol>> {
    platform::find_native_symbols(module_name, query)
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

    use crate::{enumerate_images, image_name_matches, ImageInfo, NativeSymbol};

    use super::query_matches_symbol;

    const LC_SEGMENT_64: u32 = 0x19;
    const LC_SYMTAB: u32 = 0x2;
    const MH_MAGIC_64: u32 = 0xfeedfacf;
    const N_STAB: u8 = 0xe0;

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
    struct SymtabCommand {
        cmd: u32,
        cmdsize: u32,
        symoff: u32,
        nsyms: u32,
        stroff: u32,
        strsize: u32,
    }

    #[repr(C)]
    struct Nlist64 {
        n_strx: u32,
        n_type: u8,
        n_sect: u8,
        n_desc: u16,
        n_value: u64,
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

            matches.extend(collect_symbols_in_image(&image, trimmed)?);
        }

        dedup_and_sort_symbols(&mut matches);
        Ok(matches)
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

    fn collect_symbols_in_image(image: &ImageInfo, query: &str) -> Result<Vec<NativeSymbol>> {
        let header = image.base as *const MachHeader64;
        if header.is_null() {
            return Ok(Vec::new());
        }

        let header = unsafe { &*header };
        if header.magic != MH_MAGIC_64 {
            return Ok(Vec::new());
        }

        let mut linkedit_segment = None;
        let mut symtab = None;
        let mut command_ptr = unsafe { header_ptr_after_header(header) };
        let command_region_size = header.sizeofcmds as usize;
        let mut consumed = 0usize;

        for _ in 0..header.ncmds {
            if consumed.saturating_add(size_of::<LoadCommand>()) > command_region_size {
                break;
            }

            let load = unsafe { &*(command_ptr as *const LoadCommand) };
            let command_size = load.cmdsize as usize;
            if command_size < size_of::<LoadCommand>() || consumed.saturating_add(command_size) > command_region_size {
                break;
            }

            match load.cmd {
                LC_SEGMENT_64 => {
                    if command_size < size_of::<SegmentCommand64>() {
                        consumed += command_size;
                        command_ptr = unsafe { command_ptr.add(command_size) };
                        continue;
                    }
                    let segment = unsafe { &*(command_ptr as *const SegmentCommand64) };
                    if segment_name(segment) == "__LINKEDIT" {
                        linkedit_segment = Some(segment);
                    }
                }
                LC_SYMTAB => {
                    if command_size < size_of::<SymtabCommand>() {
                        consumed += command_size;
                        command_ptr = unsafe { command_ptr.add(command_size) };
                        continue;
                    }
                    let table = unsafe { &*(command_ptr as *const SymtabCommand) };
                    symtab = Some(table);
                }
                _ => {}
            }

            consumed += command_size;
            command_ptr = unsafe { command_ptr.add(command_size) };
        }

        let Some(linkedit_segment) = linkedit_segment else {
            return Ok(Vec::new());
        };
        let Some(symtab) = symtab else {
            return Ok(Vec::new());
        };

        let linkedit_base = compute_linkedit_base(image, linkedit_segment)?;
        let symtab_ptr = unsafe { linkedit_base.add(symtab.symoff as usize) as *const Nlist64 };
        let strtab_ptr = unsafe { linkedit_base.add(symtab.stroff as usize) };
        let strtab_len = symtab.strsize as usize;

        let mut matches = Vec::new();
        for index in 0..symtab.nsyms as usize {
            let entry = unsafe { &*symtab_ptr.add(index) };
            if entry.n_value == 0 || (entry.n_type & N_STAB) != 0 {
                continue;
            }

            let Some(symbol_name) = read_symbol_name(strtab_ptr, strtab_len, entry.n_strx as usize) else {
                continue;
            };
            if !query_matches_symbol(&symbol_name, query) {
                continue;
            }

            let address = entry.n_value as usize;
            let offset = address.saturating_sub(image.base);
            matches.push(NativeSymbol {
                module_name: image.name.clone(),
                module_base: image.base,
                symbol_name,
                address,
                offset,
            });
        }

        Ok(matches)
    }

    unsafe fn header_ptr_after_header(header: &MachHeader64) -> *const u8 {
        (header as *const MachHeader64).add(1) as *const u8
    }

    fn segment_name(segment: &SegmentCommand64) -> &str {
        let length = segment
            .segname
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(segment.segname.len());
        std::str::from_utf8(&segment.segname[..length]).unwrap_or("")
    }

    fn compute_linkedit_base(image: &ImageInfo, linkedit_segment: &SegmentCommand64) -> Result<*const u8> {
        let base = image.slide as i128 + linkedit_segment.vmaddr as i128 - linkedit_segment.fileoff as i128;
        if base < 0 || base > usize::MAX as i128 {
            return Err(Error::State(format!(
                "computed __LINKEDIT base for {} overflowed address space",
                image.name
            )));
        }
        Ok(base as usize as *const u8)
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
}

#[cfg(not(any(target_os = "ios", target_os = "macos")))]
mod platform {
    use common::{Error, Result};

    use crate::NativeSymbol;

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
}

#[cfg(test)]
mod tests {
    use super::{find_native_symbols, query_matches_symbol};

    #[test]
    fn query_matches_plain_and_underscored_names() {
        assert!(query_matches_symbol("_malloc", "malloc"));
        assert!(query_matches_symbol("objc_msgSend", "msgsend"));
        assert!(!query_matches_symbol("free", "malloc"));
    }

    #[cfg(not(any(target_os = "ios", target_os = "macos")))]
    #[test]
    fn non_apple_symbol_enumeration_reports_unsupported() {
        let err = find_native_symbols(None, "malloc").expect_err("non-apple platforms should be unsupported");
        assert!(err.to_string().contains("Apple targets"));
    }
}
