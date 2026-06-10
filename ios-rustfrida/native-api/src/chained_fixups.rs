use common::{Error, Result};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageChainedFixupsPage {
    pub page_index: u16,
    pub has_fixups: bool,
    pub page_start: Option<u16>,
    pub uses_multiple_starts: bool,
    pub chain_starts: Vec<u16>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageChainedFixupsSegment {
    pub segment_index: usize,
    pub offset_in_starts: u32,
    pub size: u32,
    pub page_size: u16,
    pub pointer_format: u16,
    pub pointer_format_name: String,
    pub segment_offset: u64,
    pub max_valid_pointer: u32,
    pub page_count: u16,
    pub fixup_page_count: usize,
    pub multi_page_count: usize,
    pub pages: Vec<ImageChainedFixupsPage>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageChainedFixupsImport {
    pub index: usize,
    pub lib_ordinal_raw: u64,
    pub lib_ordinal: i64,
    pub weak_import: bool,
    pub name_offset: u32,
    pub name: Option<String>,
    pub addend: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageChainedFixups {
    pub module_name: String,
    pub module_base: usize,
    pub dataoff: u32,
    pub datasize: u32,
    pub linkedit_base: usize,
    pub data_address: usize,
    pub fixups_version: u32,
    pub starts_offset: u32,
    pub imports_offset: u32,
    pub symbols_offset: u32,
    pub imports_count: u32,
    pub imports_format: u32,
    pub imports_format_name: String,
    pub symbols_format: u32,
    pub symbols_format_name: String,
    pub segments: Vec<ImageChainedFixupsSegment>,
    pub imports: Vec<ImageChainedFixupsImport>,
}

pub fn image_chained_fixups_support_available() -> bool {
    platform::image_chained_fixups_support_available()
}

pub fn find_image_chained_fixups(module_name: &str) -> Result<Option<ImageChainedFixups>> {
    platform::find_image_chained_fixups(module_name)
}

#[allow(dead_code)]
fn checked_add_usize(base: usize, addend: u64, label: &str) -> Result<usize> {
    base.checked_add(addend as usize)
        .filter(|_| addend <= usize::MAX as u64)
        .ok_or_else(|| Error::State(format!("{label} address overflowed address space")))
}

#[cfg_attr(not(test), allow(dead_code))]
fn read_le_u16(bytes: &[u8], offset: usize, label: &str) -> Result<u16> {
    let end = offset
        .checked_add(2)
        .ok_or_else(|| Error::State(format!("{label} offset overflowed")))?;
    let raw = bytes
        .get(offset..end)
        .ok_or_else(|| Error::State(format!("{label} was truncated")))?;
    Ok(u16::from_le_bytes([raw[0], raw[1]]))
}

#[cfg_attr(not(test), allow(dead_code))]
fn read_le_u32(bytes: &[u8], offset: usize, label: &str) -> Result<u32> {
    let end = offset
        .checked_add(4)
        .ok_or_else(|| Error::State(format!("{label} offset overflowed")))?;
    let raw = bytes
        .get(offset..end)
        .ok_or_else(|| Error::State(format!("{label} was truncated")))?;
    Ok(u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]))
}

#[cfg_attr(not(test), allow(dead_code))]
fn read_le_i32(bytes: &[u8], offset: usize, label: &str) -> Result<i32> {
    let end = offset
        .checked_add(4)
        .ok_or_else(|| Error::State(format!("{label} offset overflowed")))?;
    let raw = bytes
        .get(offset..end)
        .ok_or_else(|| Error::State(format!("{label} was truncated")))?;
    Ok(i32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]))
}

#[cfg_attr(not(test), allow(dead_code))]
fn read_le_u64(bytes: &[u8], offset: usize, label: &str) -> Result<u64> {
    let end = offset
        .checked_add(8)
        .ok_or_else(|| Error::State(format!("{label} offset overflowed")))?;
    let raw = bytes
        .get(offset..end)
        .ok_or_else(|| Error::State(format!("{label} was truncated")))?;
    Ok(u64::from_le_bytes([
        raw[0], raw[1], raw[2], raw[3], raw[4], raw[5], raw[6], raw[7],
    ]))
}

#[cfg_attr(not(test), allow(dead_code))]
fn read_le_i64(bytes: &[u8], offset: usize, label: &str) -> Result<i64> {
    let end = offset
        .checked_add(8)
        .ok_or_else(|| Error::State(format!("{label} offset overflowed")))?;
    let raw = bytes
        .get(offset..end)
        .ok_or_else(|| Error::State(format!("{label} was truncated")))?;
    Ok(i64::from_le_bytes([
        raw[0], raw[1], raw[2], raw[3], raw[4], raw[5], raw[6], raw[7],
    ]))
}

#[cfg_attr(not(test), allow(dead_code))]
fn read_cstring_at(bytes: &[u8], offset: usize, label: &str) -> Result<String> {
    let rest = bytes
        .get(offset..)
        .ok_or_else(|| Error::State(format!("{label} offset overflowed")))?;
    let end = rest
        .iter()
        .position(|byte| *byte == 0)
        .ok_or_else(|| Error::State(format!("{label} was missing a terminating NUL")))?;
    Ok(String::from_utf8_lossy(&rest[..end]).into_owned())
}

#[cfg_attr(not(test), allow(dead_code))]
fn imports_format_name(format: u32) -> &'static str {
    match format {
        1 => "DYLD_CHAINED_IMPORT",
        2 => "DYLD_CHAINED_IMPORT_ADDEND",
        3 => "DYLD_CHAINED_IMPORT_ADDEND64",
        _ => "DYLD_CHAINED_IMPORT_UNKNOWN",
    }
}

#[cfg_attr(not(test), allow(dead_code))]
fn symbols_format_name(format: u32) -> &'static str {
    match format {
        0 => "uncompressed",
        1 => "zlib-compressed",
        _ => "unknown",
    }
}

#[cfg_attr(not(test), allow(dead_code))]
fn pointer_format_name(format: u16) -> &'static str {
    match format {
        1 => "DYLD_CHAINED_PTR_ARM64E",
        2 => "DYLD_CHAINED_PTR_64",
        3 => "DYLD_CHAINED_PTR_32",
        4 => "DYLD_CHAINED_PTR_32_CACHE",
        5 => "DYLD_CHAINED_PTR_32_FIRMWARE",
        6 => "DYLD_CHAINED_PTR_64_OFFSET",
        7 => "DYLD_CHAINED_PTR_ARM64E_KERNEL",
        8 => "DYLD_CHAINED_PTR_64_KERNEL_CACHE",
        9 => "DYLD_CHAINED_PTR_ARM64E_USERLAND",
        10 => "DYLD_CHAINED_PTR_ARM64E_FIRMWARE",
        11 => "DYLD_CHAINED_PTR_X86_64_KERNEL_CACHE",
        12 => "DYLD_CHAINED_PTR_ARM64E_USERLAND24",
        13 => "DYLD_CHAINED_PTR_ARM64E_SHARED_CACHE",
        14 => "DYLD_CHAINED_PTR_ARM64E_SEGMENTED",
        _ => "DYLD_CHAINED_PTR_UNKNOWN",
    }
}

#[cfg_attr(not(test), allow(dead_code))]
fn decode_signed_ordinal(raw: u64, bits: u8) -> i64 {
    let full = 1u64 << bits;
    let negative_start = full - 15;
    if raw >= negative_start {
        raw as i64 - full as i64
    } else {
        raw as i64
    }
}

#[cfg_attr(not(test), allow(dead_code))]
fn parse_chained_fixups_pages(
    bytes: &[u8],
    segment_offset: usize,
    segment_end: usize,
    page_count: u16,
) -> Result<(Vec<ImageChainedFixupsPage>, usize, usize)> {
    const DYLD_CHAINED_PTR_START_NONE: u16 = 0xffff;
    const DYLD_CHAINED_PTR_START_MULTI: u16 = 0x8000;
    const DYLD_CHAINED_PTR_START_LAST: u16 = 0x8000;

    let page_array_offset = segment_offset
        .checked_add(22)
        .ok_or_else(|| Error::State("dyld chained fixups page array offset overflowed".into()))?;

    let mut pages = Vec::with_capacity(page_count as usize);
    let mut fixup_page_count = 0usize;
    let mut multi_page_count = 0usize;

    for page_index in 0..page_count as usize {
        let raw = read_le_u16(
            bytes,
            page_array_offset + page_index * 2,
            "dyld chained fixups page_start",
        )?;
        if raw == DYLD_CHAINED_PTR_START_NONE {
            pages.push(ImageChainedFixupsPage {
                page_index: page_index as u16,
                has_fixups: false,
                page_start: None,
                uses_multiple_starts: false,
                chain_starts: Vec::new(),
            });
            continue;
        }

        fixup_page_count += 1;
        if (raw & DYLD_CHAINED_PTR_START_MULTI) != 0 {
            multi_page_count += 1;
            let mut chain_starts = Vec::new();
            let mut chain_index = usize::from(raw & !DYLD_CHAINED_PTR_START_MULTI);
            loop {
                let chain_entry_offset = page_array_offset
                    .checked_add(page_count as usize * 2)
                    .and_then(|base| base.checked_add(chain_index * 2))
                    .ok_or_else(|| Error::State("dyld chained fixups chain_starts offset overflowed".into()))?;
                if chain_entry_offset + 2 > segment_end {
                    return Err(Error::State(
                        "dyld chained fixups chain_starts overflowed segment record".into(),
                    ));
                }
                let entry = read_le_u16(bytes, chain_entry_offset, "dyld chained fixups chain_starts entry")?;
                chain_starts.push(entry & !DYLD_CHAINED_PTR_START_LAST);
                chain_index += 1;
                if (entry & DYLD_CHAINED_PTR_START_LAST) != 0 {
                    break;
                }
            }
            pages.push(ImageChainedFixupsPage {
                page_index: page_index as u16,
                has_fixups: true,
                page_start: None,
                uses_multiple_starts: true,
                chain_starts,
            });
        } else {
            pages.push(ImageChainedFixupsPage {
                page_index: page_index as u16,
                has_fixups: true,
                page_start: Some(raw),
                uses_multiple_starts: false,
                chain_starts: Vec::new(),
            });
        }
    }

    Ok((pages, fixup_page_count, multi_page_count))
}

#[cfg_attr(not(test), allow(dead_code))]
fn parse_chained_fixups_segments(bytes: &[u8], starts_offset: u32) -> Result<Vec<ImageChainedFixupsSegment>> {
    let starts_offset = starts_offset as usize;
    let seg_count = read_le_u32(bytes, starts_offset, "dyld chained fixups seg_count")? as usize;
    let seg_info_base = starts_offset
        .checked_add(4)
        .ok_or_else(|| Error::State("dyld chained fixups seg_info base overflowed".into()))?;

    let mut segments = Vec::with_capacity(seg_count);
    for segment_index in 0..seg_count {
        let seg_info_offset = read_le_u32(
            bytes,
            seg_info_base + segment_index * 4,
            "dyld chained fixups seg_info_offset",
        )?;
        if seg_info_offset == 0 {
            continue;
        }

        let segment_offset = starts_offset
            .checked_add(seg_info_offset as usize)
            .ok_or_else(|| Error::State("dyld chained fixups segment info offset overflowed".into()))?;
        let size = read_le_u32(bytes, segment_offset, "dyld chained fixups segment size")?;
        let segment_end = segment_offset
            .checked_add(size as usize)
            .ok_or_else(|| Error::State("dyld chained fixups segment range overflowed".into()))?;
        if segment_end > bytes.len() {
            return Err(Error::State(
                "dyld chained fixups segment record overflowed payload".into(),
            ));
        }

        let page_size = read_le_u16(bytes, segment_offset + 4, "dyld chained fixups page_size")?;
        let pointer_format = read_le_u16(bytes, segment_offset + 6, "dyld chained fixups pointer_format")?;
        let segment_vm_offset = read_le_u64(bytes, segment_offset + 8, "dyld chained fixups segment_offset")?;
        let max_valid_pointer = read_le_u32(bytes, segment_offset + 16, "dyld chained fixups max_valid_pointer")?;
        let page_count = read_le_u16(bytes, segment_offset + 20, "dyld chained fixups page_count")?;
        let (pages, fixup_page_count, multi_page_count) =
            parse_chained_fixups_pages(bytes, segment_offset, segment_end, page_count)?;

        segments.push(ImageChainedFixupsSegment {
            segment_index,
            offset_in_starts: seg_info_offset,
            size,
            page_size,
            pointer_format,
            pointer_format_name: pointer_format_name(pointer_format).into(),
            segment_offset: segment_vm_offset,
            max_valid_pointer,
            page_count,
            fixup_page_count,
            multi_page_count,
            pages,
        });
    }

    Ok(segments)
}

#[cfg_attr(not(test), allow(dead_code))]
fn parse_chained_fixups_imports(
    bytes: &[u8],
    imports_offset: u32,
    imports_count: u32,
    imports_format: u32,
    symbols_offset: u32,
    symbols_format: u32,
) -> Result<Vec<ImageChainedFixupsImport>> {
    let imports_offset = imports_offset as usize;
    let symbols_offset = symbols_offset as usize;
    let resolve_name = |name_offset: u32| -> Result<Option<String>> {
        if symbols_format != 0 {
            return Ok(None);
        }
        Ok(Some(read_cstring_at(
            bytes,
            symbols_offset
                .checked_add(name_offset as usize)
                .ok_or_else(|| Error::State("dyld chained fixups symbol name offset overflowed".into()))?,
            "dyld chained fixups symbol name",
        )?))
    };

    let mut imports = Vec::with_capacity(imports_count as usize);
    for index in 0..imports_count as usize {
        match imports_format {
            1 => {
                let raw = read_le_u32(bytes, imports_offset + index * 4, "dyld chained fixups import entry")?;
                let lib_ordinal_raw = u64::from(raw & 0xff);
                let weak_import = ((raw >> 8) & 1) != 0;
                let name_offset = raw >> 9;
                imports.push(ImageChainedFixupsImport {
                    index,
                    lib_ordinal_raw,
                    lib_ordinal: decode_signed_ordinal(lib_ordinal_raw, 8),
                    weak_import,
                    name_offset,
                    name: resolve_name(name_offset)?,
                    addend: None,
                });
            }
            2 => {
                let base = imports_offset + index * 8;
                let raw = read_le_u32(bytes, base, "dyld chained fixups import_addend entry")?;
                let addend = read_le_i32(bytes, base + 4, "dyld chained fixups import addend")?;
                let lib_ordinal_raw = u64::from(raw & 0xff);
                let weak_import = ((raw >> 8) & 1) != 0;
                let name_offset = raw >> 9;
                imports.push(ImageChainedFixupsImport {
                    index,
                    lib_ordinal_raw,
                    lib_ordinal: decode_signed_ordinal(lib_ordinal_raw, 8),
                    weak_import,
                    name_offset,
                    name: resolve_name(name_offset)?,
                    addend: Some(addend as i64),
                });
            }
            3 => {
                let base = imports_offset + index * 16;
                let raw = read_le_u64(bytes, base, "dyld chained fixups import_addend64 entry")?;
                let addend = read_le_i64(bytes, base + 8, "dyld chained fixups import addend64")?;
                let lib_ordinal_raw = raw & 0xffff;
                let weak_import = ((raw >> 16) & 1) != 0;
                let name_offset = (raw >> 32) as u32;
                imports.push(ImageChainedFixupsImport {
                    index,
                    lib_ordinal_raw,
                    lib_ordinal: decode_signed_ordinal(lib_ordinal_raw, 16),
                    weak_import,
                    name_offset,
                    name: resolve_name(name_offset)?,
                    addend: Some(addend),
                });
            }
            _ => {
                return Err(Error::Unsupported(format!(
                    "dyld chained fixups imports format {imports_format} is not supported"
                )));
            }
        }
    }

    Ok(imports)
}

#[cfg(any(target_os = "ios", target_os = "macos"))]
mod platform {
    use common::{Error, Result};
    use std::mem::size_of;

    use super::{
        checked_add_usize, imports_format_name, parse_chained_fixups_imports, parse_chained_fixups_segments,
        symbols_format_name, ImageChainedFixups,
    };
    use crate::{enumerate_images, image_name_matches, ImageInfo};

    const LC_SEGMENT_64: u32 = 0x19;
    const LC_DYLD_CHAINED_FIXUPS: u32 = 0x35;
    const LC_DYLD_CHAINED_FIXUPS_ALT: u32 = 0x34;
    const LC_REQ_DYLD: u32 = 0x8000_0000;
    const MH_MAGIC_64: u32 = 0xfeedfacf;

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
    struct LinkeditDataCommand {
        cmd: u32,
        cmdsize: u32,
        dataoff: u32,
        datasize: u32,
    }

    pub fn image_chained_fixups_support_available() -> bool {
        true
    }

    pub fn find_image_chained_fixups(module_name: &str) -> Result<Option<ImageChainedFixups>> {
        let trimmed = module_name.trim();
        if trimmed.is_empty() {
            return Err(Error::InvalidArgument(
                "module name must not be empty; use `native.chainedFixups <module>`".into(),
            ));
        }

        let Some(image) = enumerate_images()?
            .into_iter()
            .find(|image| image_name_matches(trimmed, &image.name))
        else {
            return Ok(None);
        };

        find_chained_fixups_in_image(&image)
    }

    fn find_chained_fixups_in_image(image: &ImageInfo) -> Result<Option<ImageChainedFixups>> {
        let header = image.base as *const MachHeader64;
        if header.is_null() {
            return Ok(None);
        }

        let header = unsafe { &*header };
        if header.magic != MH_MAGIC_64 {
            return Ok(None);
        }

        let mut linkedit_segment = None;
        let mut chained_fixups = None;
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

            let normalized_cmd = load.cmd & !LC_REQ_DYLD;
            match normalized_cmd {
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
                cmd if cmd == LC_DYLD_CHAINED_FIXUPS || cmd == LC_DYLD_CHAINED_FIXUPS_ALT => {
                    if command_size < size_of::<LinkeditDataCommand>() {
                        consumed += command_size;
                        command_ptr = unsafe { command_ptr.add(command_size) };
                        continue;
                    }
                    chained_fixups = Some(unsafe { &*(command_ptr as *const LinkeditDataCommand) });
                }
                _ => {}
            }

            consumed += command_size;
            command_ptr = unsafe { command_ptr.add(command_size) };
        }

        let (Some(linkedit), Some(command)) = (linkedit_segment, chained_fixups) else {
            return Ok(None);
        };

        let linkedit_base = compute_linkedit_base(image, linkedit)?;
        let data_address = checked_add_usize(linkedit_base, command.dataoff as u64, "LC_DYLD_CHAINED_FIXUPS blob")?;
        let bytes = if command.datasize == 0 {
            &[][..]
        } else {
            unsafe { std::slice::from_raw_parts(data_address as *const u8, command.datasize as usize) }
        };

        let fixups_version = super::read_le_u32(bytes, 0, "dyld chained fixups version")?;
        let starts_offset = super::read_le_u32(bytes, 4, "dyld chained fixups starts_offset")?;
        let imports_offset = super::read_le_u32(bytes, 8, "dyld chained fixups imports_offset")?;
        let symbols_offset = super::read_le_u32(bytes, 12, "dyld chained fixups symbols_offset")?;
        let imports_count = super::read_le_u32(bytes, 16, "dyld chained fixups imports_count")?;
        let imports_format = super::read_le_u32(bytes, 20, "dyld chained fixups imports_format")?;
        let symbols_format = super::read_le_u32(bytes, 24, "dyld chained fixups symbols_format")?;

        let segments = parse_chained_fixups_segments(bytes, starts_offset)?;
        let imports = parse_chained_fixups_imports(
            bytes,
            imports_offset,
            imports_count,
            imports_format,
            symbols_offset,
            symbols_format,
        )?;

        Ok(Some(ImageChainedFixups {
            module_name: image.name.clone(),
            module_base: image.base,
            dataoff: command.dataoff,
            datasize: command.datasize,
            linkedit_base,
            data_address,
            fixups_version,
            starts_offset,
            imports_offset,
            symbols_offset,
            imports_count,
            imports_format,
            imports_format_name: imports_format_name(imports_format).into(),
            symbols_format,
            symbols_format_name: symbols_format_name(symbols_format).into(),
            segments,
            imports,
        }))
    }

    unsafe fn header_ptr_after_header(header: &MachHeader64) -> *const u8 {
        (header as *const MachHeader64).add(1) as *const u8
    }

    fn segment_name(segment: &SegmentCommand64) -> &str {
        let len = segment
            .segname
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(segment.segname.len());
        std::str::from_utf8(&segment.segname[..len]).unwrap_or("")
    }

    fn compute_linkedit_base(image: &ImageInfo, linkedit_segment: &SegmentCommand64) -> Result<usize> {
        let base = image.slide as i128 + linkedit_segment.vmaddr as i128 - linkedit_segment.fileoff as i128;
        if base < 0 || base > usize::MAX as i128 {
            return Err(Error::State(format!(
                "computed __LINKEDIT base for {} overflowed address space",
                image.name
            )));
        }
        Ok(base as usize)
    }
}

#[cfg(not(any(target_os = "ios", target_os = "macos")))]
mod platform {
    use common::{Error, Result};

    use crate::ImageChainedFixups;

    pub fn image_chained_fixups_support_available() -> bool {
        false
    }

    pub fn find_image_chained_fixups(module_name: &str) -> Result<Option<ImageChainedFixups>> {
        if module_name.trim().is_empty() {
            return Err(Error::InvalidArgument(
                "module name must not be empty; use `native.chainedFixups <module>`".into(),
            ));
        }

        Err(Error::Unsupported(
            "Mach-O chained-fixups enumeration is currently only available on Apple targets".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::{
        decode_signed_ordinal, find_image_chained_fixups, imports_format_name, parse_chained_fixups_imports,
        parse_chained_fixups_segments, pointer_format_name, symbols_format_name,
    };

    fn push_u16(bytes: &mut Vec<u8>, value: u16) {
        bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn push_u32(bytes: &mut Vec<u8>, value: u32) {
        bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn push_i32(bytes: &mut Vec<u8>, value: i32) {
        bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn push_u64(bytes: &mut Vec<u8>, value: u64) {
        bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn push_i64(bytes: &mut Vec<u8>, value: i64) {
        bytes.extend_from_slice(&value.to_le_bytes());
    }

    #[test]
    fn parses_chained_fixups_segments_and_pages() {
        let mut starts = Vec::new();
        push_u32(&mut starts, 2);
        push_u32(&mut starts, 12);
        push_u32(&mut starts, 0);

        push_u32(&mut starts, 26);
        push_u16(&mut starts, 0x1000);
        push_u16(&mut starts, 9);
        push_u64(&mut starts, 0x4000);
        push_u32(&mut starts, 0);
        push_u16(&mut starts, 2);
        push_u16(&mut starts, 0x20);
        push_u16(&mut starts, 0xffff);

        let segments = parse_chained_fixups_segments(&starts, 0).expect("segments");
        assert_eq!(segments.len(), 1);
        let segment = &segments[0];
        assert_eq!(segment.segment_index, 0);
        assert_eq!(segment.pointer_format_name, "DYLD_CHAINED_PTR_ARM64E_USERLAND");
        assert_eq!(segment.segment_offset, 0x4000);
        assert_eq!(segment.page_count, 2);
        assert_eq!(segment.fixup_page_count, 1);
        assert_eq!(segment.multi_page_count, 0);
        assert_eq!(segment.pages[0].page_start, Some(0x20));
        assert!(!segment.pages[0].uses_multiple_starts);
        assert!(!segment.pages[1].has_fixups);
    }

    #[test]
    fn parses_multi_start_pages() {
        let mut starts = Vec::new();
        push_u32(&mut starts, 1);
        push_u32(&mut starts, 8);

        push_u32(&mut starts, 28);
        push_u16(&mut starts, 0x1000);
        push_u16(&mut starts, 6);
        push_u64(&mut starts, 0x8000);
        push_u32(&mut starts, 0);
        push_u16(&mut starts, 1);
        push_u16(&mut starts, 0x8000);
        push_u16(&mut starts, 0x0010);
        push_u16(&mut starts, 0x8004);

        let segments = parse_chained_fixups_segments(&starts, 0).expect("segments");
        let page = &segments[0].pages[0];
        assert!(page.has_fixups);
        assert!(page.uses_multiple_starts);
        assert_eq!(page.page_start, None);
        assert_eq!(page.chain_starts, vec![0x0010, 0x0004]);
    }

    #[test]
    fn parses_chained_fixups_imports() {
        let mut bytes = Vec::new();
        push_u32(&mut bytes, 1);
        push_i32(&mut bytes, 4);
        push_u32(&mut bytes, 0x000009f2);
        push_i32(&mut bytes, -8);
        bytes.extend_from_slice(b"foo\0bar\0");

        let imports = parse_chained_fixups_imports(&bytes, 0, 2, 2, 16, 0).expect("imports");
        assert_eq!(imports.len(), 2);
        assert_eq!(imports[0].name.as_deref(), Some("foo"));
        assert_eq!(imports[0].lib_ordinal, 1);
        assert_eq!(imports[0].addend, Some(4));
        assert_eq!(imports[1].name.as_deref(), Some("bar"));
        assert_eq!(imports[1].lib_ordinal_raw, 0xf2);
        assert_eq!(imports[1].lib_ordinal, -14);
        assert!(imports[1].weak_import);
        assert_eq!(imports[1].addend, Some(-8));
    }

    #[test]
    fn parses_chained_fixups_imports_with_compressed_symbols_as_null_names() {
        let mut bytes = Vec::new();
        push_u64(&mut bytes, (8u64 << 32) | 2);
        push_i64(&mut bytes, 0x1234);
        bytes.extend_from_slice(b"ignored\0");

        let imports = parse_chained_fixups_imports(&bytes, 0, 1, 3, 16, 1).expect("imports");
        assert_eq!(imports[0].name, None);
        assert_eq!(imports[0].addend, Some(0x1234));
    }

    #[test]
    fn decodes_signed_ordinals_for_wrapped_negative_values() {
        assert_eq!(decode_signed_ordinal(0xf1, 8), -15);
        assert_eq!(decode_signed_ordinal(0xf0, 8), 240);
        assert_eq!(decode_signed_ordinal(0xfff1, 16), -15);
        assert_eq!(decode_signed_ordinal(0xfff0, 16), 65520);
    }

    #[test]
    fn reports_known_names() {
        assert_eq!(imports_format_name(1), "DYLD_CHAINED_IMPORT");
        assert_eq!(symbols_format_name(1), "zlib-compressed");
        assert_eq!(pointer_format_name(6), "DYLD_CHAINED_PTR_64_OFFSET");
    }

    #[cfg(not(any(target_os = "ios", target_os = "macos")))]
    #[test]
    fn non_apple_chained_fixups_reports_unsupported() {
        let err =
            find_image_chained_fixups("libsystem_malloc.dylib").expect_err("non-apple platforms should be unsupported");
        assert!(err.to_string().contains("Apple targets"));
    }
}
