use common::Result;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageSegment {
    pub module_name: String,
    pub module_base: usize,
    pub segment_name: String,
    pub vmaddr: usize,
    pub vmsize: usize,
    pub fileoff: usize,
    pub filesize: usize,
    pub maxprot: i32,
    pub initprot: i32,
}

pub fn image_segment_support_available() -> bool {
    platform::image_segment_support_available()
}

pub fn find_image_segments(module_name: &str) -> Result<Vec<ImageSegment>> {
    platform::find_image_segments(module_name)
}

pub fn segment_name_matches(segment_name: &str, query: &str) -> bool {
    segment_name.trim().eq_ignore_ascii_case(query.trim())
}

#[cfg(any(target_os = "ios", target_os = "macos"))]
mod platform {
    use common::{Error, Result};
    use std::mem::size_of;

    use crate::macho_load_commands::LC_SEGMENT_64;
    use crate::{enumerate_images, image_name_matches, ImageInfo, ImageSegment};

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

    pub fn image_segment_support_available() -> bool {
        true
    }

    pub fn find_image_segments(module_name: &str) -> Result<Vec<ImageSegment>> {
        let trimmed = module_name.trim();
        if trimmed.is_empty() {
            return Err(Error::InvalidArgument(
                "module name must not be empty; use `native.segments <module>`".into(),
            ));
        }

        let Some(image) = enumerate_images()?
            .into_iter()
            .find(|image| image_name_matches(trimmed, &image.name))
        else {
            return Ok(Vec::new());
        };

        collect_segments_in_image(&image)
    }

    fn collect_segments_in_image(image: &ImageInfo) -> Result<Vec<ImageSegment>> {
        let header = image.base as *const MachHeader64;
        if header.is_null() {
            return Ok(Vec::new());
        }

        let header = unsafe { &*header };
        if header.magic != MH_MAGIC_64 {
            return Ok(Vec::new());
        }

        let mut segments = Vec::new();
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
                segments.push(ImageSegment {
                    module_name: image.name.clone(),
                    module_base: image.base,
                    segment_name: segment_name(segment).to_string(),
                    vmaddr: segment.vmaddr as usize,
                    vmsize: segment.vmsize as usize,
                    fileoff: segment.fileoff as usize,
                    filesize: segment.filesize as usize,
                    maxprot: segment.maxprot,
                    initprot: segment.initprot,
                });
            }

            consumed += command_size;
            command_ptr = unsafe { command_ptr.add(command_size) };
        }

        Ok(segments)
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
}

#[cfg(not(any(target_os = "ios", target_os = "macos")))]
mod platform {
    use common::{Error, Result};

    use crate::ImageSegment;

    pub fn image_segment_support_available() -> bool {
        false
    }

    pub fn find_image_segments(module_name: &str) -> Result<Vec<ImageSegment>> {
        if module_name.trim().is_empty() {
            return Err(Error::InvalidArgument(
                "module name must not be empty; use `native.segments <module>`".into(),
            ));
        }

        Err(Error::Unsupported(
            "Mach-O segment enumeration is currently only available on Apple targets".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::{find_image_segments, segment_name_matches};

    #[test]
    fn segment_name_matching_is_case_insensitive() {
        assert!(segment_name_matches("__TEXT", "__text"));
        assert!(segment_name_matches("__DATA_CONST", "__data_const"));
        assert!(!segment_name_matches("__TEXT", "__DATA"));
    }

    #[cfg(not(any(target_os = "ios", target_os = "macos")))]
    #[test]
    fn non_apple_segment_enumeration_reports_unsupported() {
        let err = find_image_segments("malloc").expect_err("non-apple platforms should be unsupported");
        assert!(err.to_string().contains("Apple targets"));
    }
}
