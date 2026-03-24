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

#[cfg(any(target_os = "ios", target_os = "macos"))]
mod platform {
    use common::{Error, Result};

    use crate::{enumerate_images, image_name_matches, ImageInfo, ImageSection};

    const LC_SEGMENT_64: u32 = 0x19;
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

        for _ in 0..header.ncmds {
            let load = unsafe { &*(command_ptr as *const LoadCommand) };
            if load.cmd == LC_SEGMENT_64 {
                let segment = unsafe { &*(command_ptr as *const SegmentCommand64) };
                let segment_name = fixed_string(&segment.segname);
                let section_ptr = unsafe { (command_ptr as *const u8).add(std::mem::size_of::<SegmentCommand64>()) }
                    as *const Section64;

                for index in 0..segment.nsects as usize {
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

            let command_size = load.cmdsize as usize;
            if command_size == 0 {
                break;
            }
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
    use super::find_image_sections;

    #[cfg(not(any(target_os = "ios", target_os = "macos")))]
    #[test]
    fn non_apple_section_enumeration_reports_unsupported() {
        let err = find_image_sections("malloc").expect_err("non-apple platforms should be unsupported");
        assert!(err.to_string().contains("Apple targets"));
    }
}
