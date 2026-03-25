use common::Result;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageUuid {
    pub module_name: String,
    pub module_base: usize,
    pub uuid: String,
}

pub fn image_uuid_support_available() -> bool {
    platform::image_uuid_support_available()
}

pub fn find_image_uuid(module_name: &str) -> Result<Option<ImageUuid>> {
    platform::find_image_uuid(module_name)
}

#[cfg(any(target_os = "ios", target_os = "macos"))]
mod platform {
    use common::{Error, Result};

    use crate::{enumerate_images, image_name_matches, ImageInfo, ImageUuid};

    const LC_UUID: u32 = 0x1b;
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
    struct UuidCommand {
        cmd: u32,
        cmdsize: u32,
        uuid: [u8; 16],
    }

    pub fn image_uuid_support_available() -> bool {
        true
    }

    pub fn find_image_uuid(module_name: &str) -> Result<Option<ImageUuid>> {
        let trimmed = module_name.trim();
        if trimmed.is_empty() {
            return Err(Error::InvalidArgument(
                "module name must not be empty; use `native.uuid <module>`".into(),
            ));
        }

        let Some(image) = enumerate_images()?
            .into_iter()
            .find(|image| image_name_matches(trimmed, &image.name))
        else {
            return Ok(None);
        };

        find_uuid_in_image(&image)
    }

    fn find_uuid_in_image(image: &ImageInfo) -> Result<Option<ImageUuid>> {
        let header = image.base as *const MachHeader64;
        if header.is_null() {
            return Ok(None);
        }

        let header = unsafe { &*header };
        if header.magic != MH_MAGIC_64 {
            return Ok(None);
        }

        let mut command_ptr = unsafe { header_ptr_after_header(header) };
        for _ in 0..header.ncmds {
            let load = unsafe { &*(command_ptr as *const LoadCommand) };
            if load.cmd == LC_UUID {
                let command = unsafe { &*(command_ptr as *const UuidCommand) };
                return Ok(Some(ImageUuid {
                    module_name: image.name.clone(),
                    module_base: image.base,
                    uuid: format_uuid(&command.uuid),
                }));
            }

            let command_size = load.cmdsize as usize;
            if command_size == 0 {
                break;
            }
            command_ptr = unsafe { command_ptr.add(command_size) };
        }

        Ok(None)
    }

    unsafe fn header_ptr_after_header(header: &MachHeader64) -> *const u8 {
        (header as *const MachHeader64).add(1) as *const u8
    }

    fn format_uuid(bytes: &[u8; 16]) -> String {
        format!(
            "{:02X}{:02X}{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
            bytes[0],
            bytes[1],
            bytes[2],
            bytes[3],
            bytes[4],
            bytes[5],
            bytes[6],
            bytes[7],
            bytes[8],
            bytes[9],
            bytes[10],
            bytes[11],
            bytes[12],
            bytes[13],
            bytes[14],
            bytes[15]
        )
    }
}

#[cfg(not(any(target_os = "ios", target_os = "macos")))]
mod platform {
    use common::{Error, Result};

    use crate::ImageUuid;

    pub fn image_uuid_support_available() -> bool {
        false
    }

    pub fn find_image_uuid(module_name: &str) -> Result<Option<ImageUuid>> {
        if module_name.trim().is_empty() {
            return Err(Error::InvalidArgument(
                "module name must not be empty; use `native.uuid <module>`".into(),
            ));
        }

        Err(Error::Unsupported(
            "Mach-O UUID enumeration is currently only available on Apple targets".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::find_image_uuid;

    #[cfg(not(any(target_os = "ios", target_os = "macos")))]
    #[test]
    fn non_apple_uuid_reports_unsupported() {
        let err = find_image_uuid("libsystem_malloc.dylib").expect_err("non-apple platforms should be unsupported");
        assert!(err.to_string().contains("Apple targets"));
    }
}
