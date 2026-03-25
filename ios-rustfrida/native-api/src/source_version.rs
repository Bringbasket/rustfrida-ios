use common::Result;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageSourceVersion {
    pub module_name: String,
    pub module_base: usize,
    pub version: String,
}

pub fn image_source_version_support_available() -> bool {
    platform::image_source_version_support_available()
}

pub fn find_image_source_version(module_name: &str) -> Result<Option<ImageSourceVersion>> {
    platform::find_image_source_version(module_name)
}

#[cfg(any(target_os = "ios", target_os = "macos"))]
mod platform {
    use common::{Error, Result};

    use crate::{enumerate_images, image_name_matches, ImageInfo, ImageSourceVersion};

    const LC_SOURCE_VERSION: u32 = 0x2b;
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
    struct SourceVersionCommand {
        cmd: u32,
        cmdsize: u32,
        version: u64,
    }

    pub fn image_source_version_support_available() -> bool {
        true
    }

    pub fn find_image_source_version(module_name: &str) -> Result<Option<ImageSourceVersion>> {
        let trimmed = module_name.trim();
        if trimmed.is_empty() {
            return Err(Error::InvalidArgument(
                "module name must not be empty; use `native.sourceVersion <module>`".into(),
            ));
        }

        let Some(image) = enumerate_images()?
            .into_iter()
            .find(|image| image_name_matches(trimmed, &image.name))
        else {
            return Ok(None);
        };

        find_source_version_in_image(&image)
    }

    fn find_source_version_in_image(image: &ImageInfo) -> Result<Option<ImageSourceVersion>> {
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
            if load.cmd == LC_SOURCE_VERSION {
                let command = unsafe { &*(command_ptr as *const SourceVersionCommand) };
                return Ok(Some(ImageSourceVersion {
                    module_name: image.name.clone(),
                    module_base: image.base,
                    version: format_source_version(command.version),
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

    fn format_source_version(version: u64) -> String {
        format!(
            "{}.{}.{}.{}.{}",
            (version >> 40) & 0x00ff_ffff,
            (version >> 30) & 0x03ff,
            (version >> 20) & 0x03ff,
            (version >> 10) & 0x03ff,
            version & 0x03ff
        )
    }
}

#[cfg(not(any(target_os = "ios", target_os = "macos")))]
mod platform {
    use common::{Error, Result};

    use crate::ImageSourceVersion;

    pub fn image_source_version_support_available() -> bool {
        false
    }

    pub fn find_image_source_version(module_name: &str) -> Result<Option<ImageSourceVersion>> {
        if module_name.trim().is_empty() {
            return Err(Error::InvalidArgument(
                "module name must not be empty; use `native.sourceVersion <module>`".into(),
            ));
        }

        Err(Error::Unsupported(
            "Mach-O source-version enumeration is currently only available on Apple targets".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::find_image_source_version;

    #[cfg(not(any(target_os = "ios", target_os = "macos")))]
    #[test]
    fn non_apple_source_version_reports_unsupported() {
        let err =
            find_image_source_version("libsystem_malloc.dylib").expect_err("non-apple platforms should be unsupported");
        assert!(err.to_string().contains("Apple targets"));
    }
}
