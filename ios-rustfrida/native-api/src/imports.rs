use common::Result;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageImport {
    pub module_name: String,
    pub module_base: usize,
    pub symbol_name: String,
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

    use crate::{enumerate_images, image_name_matches, ImageImport, ImageInfo};

    use super::query_matches_symbol;

    const LC_LOAD_DYLIB: u32 = 0xc;
    const LC_LOAD_WEAK_DYLIB: u32 = 0x18;
    const LC_REEXPORT_DYLIB: u32 = 0x1f;
    const LC_LOAD_UPWARD_DYLIB: u32 = 0x24;
    const LC_DYSYMTAB: u32 = 0xb;
    const LC_SYMTAB: u32 = 0x2;
    const MH_MAGIC_64: u32 = 0xfeedfacf;
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

        let mut symtab = None;
        let mut dysymtab = None;
        let mut dylibs = Vec::new();
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
                LC_SYMTAB => {
                    if command_size < size_of::<SymtabCommand>() {
                        consumed += command_size;
                        command_ptr = unsafe { command_ptr.add(command_size) };
                        continue;
                    }
                    let table = unsafe { &*(command_ptr as *const SymtabCommand) };
                    symtab = Some(table);
                }
                LC_DYSYMTAB => {
                    if command_size < size_of::<DysymtabCommand>() {
                        consumed += command_size;
                        command_ptr = unsafe { command_ptr.add(command_size) };
                        continue;
                    }
                    let table = unsafe { &*(command_ptr as *const DysymtabCommand) };
                    dysymtab = Some(table);
                }
                LC_LOAD_DYLIB | LC_LOAD_WEAK_DYLIB | LC_REEXPORT_DYLIB | LC_LOAD_UPWARD_DYLIB => {
                    if command_size < size_of::<DylibCommand>() {
                        consumed += command_size;
                        command_ptr = unsafe { command_ptr.add(command_size) };
                        continue;
                    }
                    let command = unsafe { &*(command_ptr as *const DylibCommand) };
                    let bytes = unsafe { std::slice::from_raw_parts(command_ptr, command_size) };
                    dylibs.push(read_command_string(bytes, command.dylib.name));
                }
                _ => {}
            }

            consumed += command_size;
            command_ptr = unsafe { command_ptr.add(command_size) };
        }

        let Some(symtab) = symtab else {
            return Ok(Vec::new());
        };
        let Some(dysymtab) = dysymtab else {
            return Ok(Vec::new());
        };
        if dysymtab.nundefsym == 0 {
            return Ok(Vec::new());
        }

        let symtab_ptr = unsafe { image.base as *const u8 }.wrapping_add(symtab.symoff as usize) as *const Nlist64;
        let strtab_ptr = unsafe { image.base as *const u8 }.wrapping_add(symtab.stroff as usize);
        let strtab_len = symtab.strsize as usize;

        let mut matches = Vec::new();
        let start = dysymtab.iundefsym as usize;
        let end = start.saturating_add(dysymtab.nundefsym as usize);
        for index in start..end {
            if index >= symtab.nsyms as usize {
                break;
            }

            let entry = unsafe { &*symtab_ptr.add(index) };
            if (entry.n_type & N_STAB) != 0 {
                continue;
            }
            if (entry.n_type & N_EXT) == 0 || (entry.n_type & N_TYPE) != N_UNDF {
                continue;
            }

            let Some(symbol_name) = read_symbol_name(strtab_ptr, strtab_len, entry.n_strx as usize) else {
                continue;
            };
            if let Some(query) = query {
                if !query_matches_symbol(&symbol_name, query) {
                    continue;
                }
            }

            let ordinal = ((entry.n_desc & ORDINAL_MASK) >> ORDINAL_SHIFT) as u8;
            matches.push(ImageImport {
                module_name: image.name.clone(),
                module_base: image.base,
                symbol_name,
                dylib_ordinal: ordinal,
                dylib_name: resolve_dylib_name(ordinal, &dylibs),
                weak_import: (entry.n_desc & (N_WEAK_REF | N_REF_TO_WEAK)) != 0,
            });
        }

        dedup_and_sort_imports(&mut matches);
        Ok(matches)
    }

    fn dedup_and_sort_imports(matches: &mut Vec<ImageImport>) {
        matches.sort_by(|left, right| {
            left.module_name
                .cmp(&right.module_name)
                .then(left.symbol_name.cmp(&right.symbol_name))
                .then(left.dylib_ordinal.cmp(&right.dylib_ordinal))
                .then(left.weak_import.cmp(&right.weak_import))
        });
        matches.dedup_by(|left, right| {
            left.module_name == right.module_name
                && left.symbol_name == right.symbol_name
                && left.dylib_ordinal == right.dylib_ordinal
                && left.weak_import == right.weak_import
        });
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

    unsafe fn header_ptr_after_header(header: &MachHeader64) -> *const u8 {
        (header as *const MachHeader64).add(1) as *const u8
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
