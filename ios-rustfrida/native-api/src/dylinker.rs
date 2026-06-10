use common::Result;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageDylinker {
    pub module_name: String,
    pub module_base: usize,
    pub path: String,
    pub kind: String,
}

pub fn image_dylinker_support_available() -> bool {
    platform::image_dylinker_support_available()
}

pub fn find_image_dylinker(module_name: &str) -> Result<Option<ImageDylinker>> {
    platform::find_image_dylinker(module_name)
}

#[cfg(any(target_os = "ios", target_os = "macos"))]
mod platform {
    use common::{Error, Result};
    use std::mem::size_of;

    use crate::{enumerate_images, image_name_matches, ImageDylinker, ImageInfo};

    const LC_LOAD_DYLINKER: u32 = 0xe;
    const LC_ID_DYLINKER: u32 = 0xf;
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
    struct DylinkerCommand {
        cmd: u32,
        cmdsize: u32,
        name: u32,
    }

    pub fn image_dylinker_support_available() -> bool {
        true
    }

    pub fn find_image_dylinker(module_name: &str) -> Result<Option<ImageDylinker>> {
        let trimmed = module_name.trim();
        if trimmed.is_empty() {
            return Err(Error::InvalidArgument(
                "module name must not be empty; use `native.dylinker <module>`".into(),
            ));
        }

        let Some(image) = enumerate_images()?
            .into_iter()
            .find(|image| image_name_matches(trimmed, &image.name))
        else {
            return Ok(None);
        };

        find_dylinker_in_image(&image)
    }

    fn find_dylinker_in_image(image: &ImageInfo) -> Result<Option<ImageDylinker>> {
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

            if matches!(load.cmd, LC_LOAD_DYLINKER | LC_ID_DYLINKER) {
                if command_size < size_of::<DylinkerCommand>() {
                    return Ok(None);
                }

                let command = unsafe { &*(command_ptr as *const DylinkerCommand) };
                let bytes = unsafe { std::slice::from_raw_parts(command_ptr, command_size) };
                return Ok(Some(ImageDylinker {
                    module_name: image.name.clone(),
                    module_base: image.base,
                    path: read_command_string(bytes, command.name).unwrap_or_default(),
                    kind: dylinker_kind(load.cmd).to_string(),
                }));
            }

            consumed += command_size;
            command_ptr = unsafe { command_ptr.add(command_size) };
        }

        Ok(None)
    }

    fn dylinker_kind(command: u32) -> &'static str {
        match command {
            LC_LOAD_DYLINKER => "load",
            LC_ID_DYLINKER => "id",
            _ => "unknown",
        }
    }

    unsafe fn header_ptr_after_header(header: &MachHeader64) -> *const u8 {
        (header as *const MachHeader64).add(1) as *const u8
    }

    fn read_command_string(bytes: &[u8], offset: u32) -> Option<String> {
        let start = offset as usize;
        if start >= bytes.len() {
            return None;
        }
        let tail = &bytes[start..];
        let end = tail.iter().position(|byte| *byte == 0).unwrap_or(tail.len());
        if end == 0 {
            return None;
        }
        Some(String::from_utf8_lossy(&tail[..end]).into_owned())
    }
}

#[cfg(not(any(target_os = "ios", target_os = "macos")))]
mod platform {
    use common::{Error, Result};

    use crate::ImageDylinker;

    pub fn image_dylinker_support_available() -> bool {
        false
    }

    pub fn find_image_dylinker(module_name: &str) -> Result<Option<ImageDylinker>> {
        if module_name.trim().is_empty() {
            return Err(Error::InvalidArgument(
                "module name must not be empty; use `native.dylinker <module>`".into(),
            ));
        }

        Err(Error::Unsupported(
            "Mach-O dylinker enumeration is currently only available on Apple targets".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::find_image_dylinker;

    #[cfg(not(any(target_os = "ios", target_os = "macos")))]
    #[test]
    fn non_apple_dylinker_reports_unsupported() {
        let err = find_image_dylinker("libsystem_malloc.dylib").expect_err("non-apple platforms should be unsupported");
        assert!(err.to_string().contains("Apple targets"));
    }
}
