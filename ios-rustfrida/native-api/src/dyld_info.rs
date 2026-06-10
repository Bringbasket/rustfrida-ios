use common::Result;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageDyldInfo {
    pub module_name: String,
    pub module_base: usize,
    pub command: u32,
    pub command_name: String,
    pub rebase_off: u32,
    pub rebase_size: u32,
    pub bind_off: u32,
    pub bind_size: u32,
    pub weak_bind_off: u32,
    pub weak_bind_size: u32,
    pub lazy_bind_off: u32,
    pub lazy_bind_size: u32,
    pub export_off: u32,
    pub export_size: u32,
}

pub fn image_dyld_info_support_available() -> bool {
    platform::image_dyld_info_support_available()
}

pub fn find_image_dyld_info(module_name: &str) -> Result<Option<ImageDyldInfo>> {
    platform::find_image_dyld_info(module_name)
}

#[cfg(any(target_os = "ios", target_os = "macos"))]
mod platform {
    use common::{Error, Result};
    use std::mem::size_of;

    use crate::{enumerate_images, image_name_matches, ImageDyldInfo, ImageInfo};

    const LC_DYLD_INFO: u32 = 0x22;
    const LC_DYLD_INFO_ONLY: u32 = 0x23;
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
    struct DyldInfoCommand {
        cmd: u32,
        cmdsize: u32,
        rebase_off: u32,
        rebase_size: u32,
        bind_off: u32,
        bind_size: u32,
        weak_bind_off: u32,
        weak_bind_size: u32,
        lazy_bind_off: u32,
        lazy_bind_size: u32,
        export_off: u32,
        export_size: u32,
    }

    pub fn image_dyld_info_support_available() -> bool {
        true
    }

    pub fn find_image_dyld_info(module_name: &str) -> Result<Option<ImageDyldInfo>> {
        let trimmed = module_name.trim();
        if trimmed.is_empty() {
            return Err(Error::InvalidArgument(
                "module name must not be empty; use `native.dyldInfo <module>`".into(),
            ));
        }

        let Some(image) = enumerate_images()?
            .into_iter()
            .find(|image| image_name_matches(trimmed, &image.name))
        else {
            return Ok(None);
        };

        find_dyld_info_in_image(&image)
    }

    fn find_dyld_info_in_image(image: &ImageInfo) -> Result<Option<ImageDyldInfo>> {
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

            let normalized_cmd = load.cmd & !LC_REQ_DYLD;
            if normalized_cmd == LC_DYLD_INFO || normalized_cmd == LC_DYLD_INFO_ONLY {
                if command_size < size_of::<DyldInfoCommand>() {
                    return Ok(None);
                }

                let command = unsafe { &*(command_ptr as *const DyldInfoCommand) };
                return Ok(Some(ImageDyldInfo {
                    module_name: image.name.clone(),
                    module_base: image.base,
                    command: load.cmd,
                    command_name: command_name(load.cmd).into(),
                    rebase_off: command.rebase_off,
                    rebase_size: command.rebase_size,
                    bind_off: command.bind_off,
                    bind_size: command.bind_size,
                    weak_bind_off: command.weak_bind_off,
                    weak_bind_size: command.weak_bind_size,
                    lazy_bind_off: command.lazy_bind_off,
                    lazy_bind_size: command.lazy_bind_size,
                    export_off: command.export_off,
                    export_size: command.export_size,
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

    fn command_name(cmd: u32) -> &'static str {
        match cmd & !LC_REQ_DYLD {
            LC_DYLD_INFO => "LC_DYLD_INFO",
            LC_DYLD_INFO_ONLY => "LC_DYLD_INFO_ONLY",
            _ => "LC_UNKNOWN",
        }
    }
}

#[cfg(not(any(target_os = "ios", target_os = "macos")))]
mod platform {
    use common::{Error, Result};

    use crate::ImageDyldInfo;

    pub fn image_dyld_info_support_available() -> bool {
        false
    }

    pub fn find_image_dyld_info(module_name: &str) -> Result<Option<ImageDyldInfo>> {
        if module_name.trim().is_empty() {
            return Err(Error::InvalidArgument(
                "module name must not be empty; use `native.dyldInfo <module>`".into(),
            ));
        }

        Err(Error::Unsupported(
            "Mach-O dyld-info enumeration is currently only available on Apple targets".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::find_image_dyld_info;

    #[cfg(not(any(target_os = "ios", target_os = "macos")))]
    #[test]
    fn non_apple_dyld_info_reports_unsupported() {
        let err =
            find_image_dyld_info("libsystem_malloc.dylib").expect_err("non-apple platforms should be unsupported");
        assert!(err.to_string().contains("Apple targets"));
    }
}
