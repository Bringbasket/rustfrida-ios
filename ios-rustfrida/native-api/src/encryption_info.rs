use common::Result;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageEncryptionInfo {
    pub module_name: String,
    pub module_base: usize,
    pub cryptoff: u32,
    pub cryptsize: u32,
    pub cryptid: u32,
}

pub fn image_encryption_info_support_available() -> bool {
    platform::image_encryption_info_support_available()
}

pub fn find_image_encryption_info(module_name: &str) -> Result<Option<ImageEncryptionInfo>> {
    platform::find_image_encryption_info(module_name)
}

#[cfg(any(target_os = "ios", target_os = "macos"))]
mod platform {
    use common::{Error, Result};
    use std::mem::size_of;

    use crate::{enumerate_images, image_name_matches, ImageEncryptionInfo, ImageInfo};

    const LC_ENCRYPTION_INFO_64: u32 = 0x2d;
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
    struct EncryptionInfoCommand64 {
        cmd: u32,
        cmdsize: u32,
        cryptoff: u32,
        cryptsize: u32,
        cryptid: u32,
        pad: u32,
    }

    pub fn image_encryption_info_support_available() -> bool {
        true
    }

    pub fn find_image_encryption_info(module_name: &str) -> Result<Option<ImageEncryptionInfo>> {
        let trimmed = module_name.trim();
        if trimmed.is_empty() {
            return Err(Error::InvalidArgument(
                "module name must not be empty; use `native.encryptionInfo <module>`".into(),
            ));
        }

        let Some(image) = enumerate_images()?
            .into_iter()
            .find(|image| image_name_matches(trimmed, &image.name))
        else {
            return Ok(None);
        };

        find_encryption_info_in_image(&image)
    }

    fn find_encryption_info_in_image(image: &ImageInfo) -> Result<Option<ImageEncryptionInfo>> {
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

            if load.cmd == LC_ENCRYPTION_INFO_64 {
                if command_size < size_of::<EncryptionInfoCommand64>() {
                    return Ok(None);
                }

                let command = unsafe { &*(command_ptr as *const EncryptionInfoCommand64) };
                return Ok(Some(ImageEncryptionInfo {
                    module_name: image.name.clone(),
                    module_base: image.base,
                    cryptoff: command.cryptoff,
                    cryptsize: command.cryptsize,
                    cryptid: command.cryptid,
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

    use crate::ImageEncryptionInfo;

    pub fn image_encryption_info_support_available() -> bool {
        false
    }

    pub fn find_image_encryption_info(module_name: &str) -> Result<Option<ImageEncryptionInfo>> {
        if module_name.trim().is_empty() {
            return Err(Error::InvalidArgument(
                "module name must not be empty; use `native.encryptionInfo <module>`".into(),
            ));
        }

        Err(Error::Unsupported(
            "Mach-O encryption-info enumeration is currently only available on Apple targets".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::find_image_encryption_info;

    #[cfg(not(any(target_os = "ios", target_os = "macos")))]
    #[test]
    fn non_apple_encryption_info_reports_unsupported() {
        let err = find_image_encryption_info("libsystem_malloc.dylib")
            .expect_err("non-apple platforms should be unsupported");
        assert!(err.to_string().contains("Apple targets"));
    }
}
