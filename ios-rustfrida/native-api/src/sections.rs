use common::Result;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageSection {
    pub module_name: String,
    pub module_base: usize,
    pub segment_name: String,
    pub section_name: String,
    pub addr: usize,
    pub size: usize,
    pub offset: u32,
    pub align: u32,
    pub flags: u32,
}

pub fn image_section_support_available() -> bool {
    platform::image_section_support_available()
}

pub fn find_image_sections(module_name: &str) -> Result<Vec<ImageSection>> {
    platform::find_image_sections(module_name)
}

pub fn section_name_matches(segment_name: &str, section_name: &str, segment_query: &str, section_query: &str) -> bool {
    if !segment_name.trim().eq_ignore_ascii_case(segment_query.trim()) {
        return false;
    }

    let section_query = normalized_section_query(section_query);
    section_name.trim().eq_ignore_ascii_case(section_query)
}

fn normalized_section_query(query: &str) -> &str {
    let trimmed = query.trim();
    trimmed
        .rsplit_once('.')
        .or_else(|| trimmed.rsplit_once(','))
        .map(|(_segment, section)| section.trim())
        .filter(|section| !section.is_empty())
        .unwrap_or(trimmed)
}

#[cfg(any(target_os = "ios", target_os = "macos"))]
mod platform {
    use common::{Error, Result};
    use std::mem::size_of;

    use crate::macho_load_commands::LC_SEGMENT_64;
    use crate::{enumerate_images, image_name_matches, ImageInfo, ImageSection};

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

    pub fn image_section_support_available() -> bool {
        true
    }

    pub fn find_image_sections(module_name: &str) -> Result<Vec<ImageSection>> {
        let trimmed = module_name.trim();
        if trimmed.is_empty() {
            return Err(Error::InvalidArgument(
                "module name must not be empty; use `native.sections <module>`".into(),
            ));
        }

        let Some(image) = enumerate_images()?
            .into_iter()
            .find(|image| image_name_matches(trimmed, &image.name))
        else {
            return Ok(Vec::new());
        };

        collect_sections_in_image(&image)
    }

    fn collect_sections_in_image(image: &ImageInfo) -> Result<Vec<ImageSection>> {
        let header = image.base as *const MachHeader64;
        if header.is_null() {
            return Ok(Vec::new());
        }

        let header = unsafe { &*header };
        if header.magic != MH_MAGIC_64 {
            return Ok(Vec::new());
        }

        let mut sections = Vec::new();
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

            if load.cmd == LC_SEGMENT_64 {
                if command_size < size_of::<SegmentCommand64>() {
                    consumed += command_size;
                    command_ptr = unsafe { command_ptr.add(command_size) };
                    continue;
                }

                let segment = unsafe { &*(command_ptr as *const SegmentCommand64) };
                let segment_name = fixed_string(&segment.segname);
                let section_bytes = command_size.saturating_sub(size_of::<SegmentCommand64>());
                let available_sections = section_bytes / size_of::<Section64>();
                let section_count = (segment.nsects as usize).min(available_sections);
                let section_ptr =
                    unsafe { (command_ptr as *const u8).add(size_of::<SegmentCommand64>()) } as *const Section64;

                for index in 0..section_count {
                    let section = unsafe { &*section_ptr.add(index) };
                    sections.push(ImageSection {
                        module_name: image.name.clone(),
                        module_base: image.base,
                        segment_name: if segment_name.is_empty() {
                            fixed_string(&section.segname).to_string()
                        } else {
                            segment_name.to_string()
                        },
                        section_name: fixed_string(&section.sectname).to_string(),
                        addr: section.addr as usize,
                        size: section.size as usize,
                        offset: section.offset,
                        align: section.align,
                        flags: section.flags,
                    });
                }
            }

            consumed += command_size;
            command_ptr = unsafe { command_ptr.add(command_size) };
        }

        Ok(sections)
    }

    unsafe fn header_ptr_after_header(header: &MachHeader64) -> *const u8 {
        (header as *const MachHeader64).add(1) as *const u8
    }

    fn fixed_string(bytes: &[u8; 16]) -> &str {
        let length = bytes.iter().position(|byte| *byte == 0).unwrap_or(bytes.len());
        std::str::from_utf8(&bytes[..length]).unwrap_or("")
    }
}

#[cfg(not(any(target_os = "ios", target_os = "macos")))]
mod platform {
    use common::{Error, Result};

    use crate::ImageSection;

    pub fn image_section_support_available() -> bool {
        false
    }

    pub fn find_image_sections(module_name: &str) -> Result<Vec<ImageSection>> {
        if module_name.trim().is_empty() {
            return Err(Error::InvalidArgument(
                "module name must not be empty; use `native.sections <module>`".into(),
            ));
        }

        Err(Error::Unsupported(
            "Mach-O section enumeration is currently only available on Apple targets".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::{find_image_sections, section_name_matches};

    #[test]
    fn section_name_matching_accepts_case_and_full_names() {
        assert!(section_name_matches("__TEXT", "__text", "__text", "__TEXT.__text"));
        assert!(section_name_matches("__TEXT", "__text", "__TEXT", "__TEXT,__text"));
        assert!(section_name_matches("__DATA_CONST", "__got", "__data_const", "__got"));
        assert!(!section_name_matches("__TEXT", "__text", "__DATA", "__text"));
        assert!(!section_name_matches("__TEXT", "__text", "__TEXT", "__cstring"));
    }

    #[cfg(not(any(target_os = "ios", target_os = "macos")))]
    #[test]
    fn non_apple_section_enumeration_reports_unsupported() {
        let err = find_image_sections("malloc").expect_err("non-apple platforms should be unsupported");
        assert!(err.to_string().contains("Apple targets"));
    }
}
