use common::Result;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageLinkeditInfo {
    pub module_name: String,
    pub module_base: usize,
    pub vmaddr: u64,
    pub vmsize: u64,
    pub fileoff: u64,
    pub filesize: u64,
    pub computed_base: usize,
    pub symoff: Option<u32>,
    pub nsyms: Option<u32>,
    pub stroff: Option<u32>,
    pub strsize: Option<u32>,
    pub indirectsymoff: Option<u32>,
    pub nindirectsyms: Option<u32>,
}

pub fn image_linkedit_info_support_available() -> bool {
    platform::image_linkedit_info_support_available()
}

pub fn find_image_linkedit_info(module_name: &str) -> Result<Option<ImageLinkeditInfo>> {
    platform::find_image_linkedit_info(module_name)
}

#[cfg(any(target_os = "ios", target_os = "macos"))]
mod platform {
    use common::{Error, Result};
    use std::mem::size_of;

    use crate::macho_load_commands::{LC_DYSYMTAB, LC_SEGMENT_64, LC_SYMTAB};
    use crate::{enumerate_images, image_name_matches, ImageInfo, ImageLinkeditInfo};

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

    pub fn image_linkedit_info_support_available() -> bool {
        true
    }

    pub fn find_image_linkedit_info(module_name: &str) -> Result<Option<ImageLinkeditInfo>> {
        let trimmed = module_name.trim();
        if trimmed.is_empty() {
            return Err(Error::InvalidArgument(
                "module name must not be empty; use `native.linkedit <module>`".into(),
            ));
        }

        let Some(image) = enumerate_images()?
            .into_iter()
            .find(|image| image_name_matches(trimmed, &image.name))
        else {
            return Ok(None);
        };

        find_linkedit_info_in_image(&image)
    }

    fn find_linkedit_info_in_image(image: &ImageInfo) -> Result<Option<ImageLinkeditInfo>> {
        let header = image.base as *const MachHeader64;
        if header.is_null() {
            return Ok(None);
        }

        let header = unsafe { &*header };
        if header.magic != MH_MAGIC_64 {
            return Ok(None);
        }

        let mut linkedit_segment = None;
        let mut symtab = None;
        let mut dysymtab = None;
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
                    symtab = Some(unsafe { &*(command_ptr as *const SymtabCommand) });
                }
                LC_DYSYMTAB => {
                    if command_size < size_of::<DysymtabCommand>() {
                        consumed += command_size;
                        command_ptr = unsafe { command_ptr.add(command_size) };
                        continue;
                    }
                    dysymtab = Some(unsafe { &*(command_ptr as *const DysymtabCommand) });
                }
                _ => {}
            }

            consumed += command_size;
            command_ptr = unsafe { command_ptr.add(command_size) };
        }

        let Some(linkedit) = linkedit_segment else {
            return Ok(None);
        };

        Ok(Some(ImageLinkeditInfo {
            module_name: image.name.clone(),
            module_base: image.base,
            vmaddr: linkedit.vmaddr,
            vmsize: linkedit.vmsize,
            fileoff: linkedit.fileoff,
            filesize: linkedit.filesize,
            computed_base: compute_linkedit_base(image, linkedit)?,
            symoff: symtab.map(|table| table.symoff),
            nsyms: symtab.map(|table| table.nsyms),
            stroff: symtab.map(|table| table.stroff),
            strsize: symtab.map(|table| table.strsize),
            indirectsymoff: dysymtab.map(|table| table.indirectsymoff),
            nindirectsyms: dysymtab.map(|table| table.nindirectsyms),
        }))
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

    use crate::ImageLinkeditInfo;

    pub fn image_linkedit_info_support_available() -> bool {
        false
    }

    pub fn find_image_linkedit_info(module_name: &str) -> Result<Option<ImageLinkeditInfo>> {
        if module_name.trim().is_empty() {
            return Err(Error::InvalidArgument(
                "module name must not be empty; use `native.linkedit <module>`".into(),
            ));
        }

        Err(Error::Unsupported(
            "Mach-O __LINKEDIT enumeration is currently only available on Apple targets".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::find_image_linkedit_info;

    #[cfg(not(any(target_os = "ios", target_os = "macos")))]
    #[test]
    fn non_apple_linkedit_reports_unsupported() {
        let err =
            find_image_linkedit_info("libsystem_malloc.dylib").expect_err("non-apple platforms should be unsupported");
        assert!(err.to_string().contains("Apple targets"));
    }
}
