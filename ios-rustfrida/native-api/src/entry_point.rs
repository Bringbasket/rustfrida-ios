use common::Result;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageEntryPoint {
    pub module_name: String,
    pub module_base: usize,
    pub entryoff: u64,
    pub stacksize: u64,
}

pub fn image_entry_point_support_available() -> bool {
    platform::image_entry_point_support_available()
}

pub fn find_image_entry_point(module_name: &str) -> Result<Option<ImageEntryPoint>> {
    platform::find_image_entry_point(module_name)
}

#[cfg(any(target_os = "ios", target_os = "macos"))]
mod platform {
    use common::{Error, Result};
    use std::mem::size_of;

    use crate::{enumerate_images, image_name_matches, ImageEntryPoint, ImageInfo};

    const LC_MAIN: u32 = 0x29;
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
    struct EntryPointCommand {
        cmd: u32,
        cmdsize: u32,
        entryoff: u64,
        stacksize: u64,
    }

    pub fn image_entry_point_support_available() -> bool {
        true
    }

    pub fn find_image_entry_point(module_name: &str) -> Result<Option<ImageEntryPoint>> {
        let trimmed = module_name.trim();
        if trimmed.is_empty() {
            return Err(Error::InvalidArgument(
                "module name must not be empty; use `native.entryPoint <module>`".into(),
            ));
        }

        let Some(image) = enumerate_images()?
            .into_iter()
            .find(|image| image_name_matches(trimmed, &image.name))
        else {
            return Ok(None);
        };

        find_entry_point_in_image(&image)
    }

    fn find_entry_point_in_image(image: &ImageInfo) -> Result<Option<ImageEntryPoint>> {
        let header = image.base as *const MachHeader64;
        if header.is_null() {
            return Ok(None);
        }

        let header = unsafe { &*header };
        if header.magic != MH_MAGIC_64 {
            return Ok(None);
        }

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

            if load.cmd == LC_MAIN {
                if command_size < size_of::<EntryPointCommand>() {
                    return Ok(None);
                }

                let command = unsafe { &*(command_ptr as *const EntryPointCommand) };
                return Ok(Some(ImageEntryPoint {
                    module_name: image.name.clone(),
                    module_base: image.base,
                    entryoff: command.entryoff,
                    stacksize: command.stacksize,
                }));
            }

            consumed += command_size;
            command_ptr = unsafe { command_ptr.add(command_size) };
        }

        Ok(None)
    }

    unsafe fn header_ptr_after_header(header: &MachHeader64) -> *const u8 {
        (header as *const MachHeader64).add(1) as *const u8
    }
}

#[cfg(not(any(target_os = "ios", target_os = "macos")))]
mod platform {
    use common::{Error, Result};

    use crate::ImageEntryPoint;

    pub fn image_entry_point_support_available() -> bool {
        false
    }

    pub fn find_image_entry_point(module_name: &str) -> Result<Option<ImageEntryPoint>> {
        if module_name.trim().is_empty() {
            return Err(Error::InvalidArgument(
                "module name must not be empty; use `native.entryPoint <module>`".into(),
            ));
        }

        Err(Error::Unsupported(
            "Mach-O entry-point enumeration is currently only available on Apple targets".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::find_image_entry_point;

    #[cfg(not(any(target_os = "ios", target_os = "macos")))]
    #[test]
    fn non_apple_entry_point_reports_unsupported() {
        let err =
            find_image_entry_point("libsystem_malloc.dylib").expect_err("non-apple platforms should be unsupported");
        assert!(err.to_string().contains("Apple targets"));
    }
}
