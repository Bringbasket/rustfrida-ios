use common::Result;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageRpath {
    pub module_name: String,
    pub module_base: usize,
    pub path: String,
}

pub fn image_rpath_support_available() -> bool {
    platform::image_rpath_support_available()
}

pub fn find_image_rpaths(module_name: &str, query: Option<&str>) -> Result<Vec<ImageRpath>> {
    platform::find_image_rpaths(module_name, query)
}

#[cfg_attr(not(any(target_os = "ios", target_os = "macos")), allow(dead_code))]
fn query_matches_rpath(path: &str, query: &str) -> bool {
    let trimmed = query.trim();
    if trimmed.is_empty() {
        return false;
    }

    path.to_ascii_lowercase().contains(&trimmed.to_ascii_lowercase())
}

#[cfg(any(target_os = "ios", target_os = "macos"))]
mod platform {
    use common::{Error, Result};

    use crate::{enumerate_images, image_name_matches, ImageInfo, ImageRpath};

    use super::query_matches_rpath;

    const LC_RPATH: u32 = 0x1c;
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
    struct RpathCommand {
        cmd: u32,
        cmdsize: u32,
        path: u32,
    }

    pub fn image_rpath_support_available() -> bool {
        true
    }

    pub fn find_image_rpaths(module_name: &str, query: Option<&str>) -> Result<Vec<ImageRpath>> {
        let trimmed = module_name.trim();
        if trimmed.is_empty() {
            return Err(Error::InvalidArgument(
                "module name must not be empty; use `native.rpaths <module>` or `native.rpaths <module> -- <query>`"
                    .into(),
            ));
        }

        let trimmed_query = query.map(str::trim).filter(|value| !value.is_empty());
        let Some(image) = enumerate_images()?
            .into_iter()
            .find(|image| image_name_matches(trimmed, &image.name))
        else {
            return Ok(Vec::new());
        };

        collect_rpaths_in_image(&image, trimmed_query)
    }

    fn collect_rpaths_in_image(image: &ImageInfo, query: Option<&str>) -> Result<Vec<ImageRpath>> {
        let header = image.base as *const MachHeader64;
        if header.is_null() {
            return Ok(Vec::new());
        }

        let header = unsafe { &*header };
        if header.magic != MH_MAGIC_64 {
            return Ok(Vec::new());
        }

        let mut rpaths = Vec::new();
        let mut command_ptr = unsafe { header_ptr_after_header(header) };

        for _ in 0..header.ncmds {
            let load = unsafe { &*(command_ptr as *const LoadCommand) };
            if load.cmd == LC_RPATH {
                let command = unsafe { &*(command_ptr as *const RpathCommand) };
                let bytes = unsafe { std::slice::from_raw_parts(command_ptr, load.cmdsize as usize) };
                let path = read_command_string(bytes, command.path).unwrap_or_default();
                if query.map(|query| query_matches_rpath(&path, query)).unwrap_or(true) {
                    rpaths.push(ImageRpath {
                        module_name: image.name.clone(),
                        module_base: image.base,
                        path,
                    });
                }
            }

            let command_size = load.cmdsize as usize;
            if command_size == 0 {
                break;
            }
            command_ptr = unsafe { command_ptr.add(command_size) };
        }

        Ok(rpaths)
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

    use crate::ImageRpath;

    pub fn image_rpath_support_available() -> bool {
        false
    }

    pub fn find_image_rpaths(module_name: &str, _query: Option<&str>) -> Result<Vec<ImageRpath>> {
        if module_name.trim().is_empty() {
            return Err(Error::InvalidArgument(
                "module name must not be empty; use `native.rpaths <module>` or `native.rpaths <module> -- <query>`"
                    .into(),
            ));
        }

        Err(Error::Unsupported(
            "Mach-O rpath enumeration is currently only available on Apple targets".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::{find_image_rpaths, query_matches_rpath};

    #[test]
    fn rpath_query_matches_substrings() {
        assert!(query_matches_rpath("@loader_path/Frameworks", "frameworks"));
        assert!(query_matches_rpath("@executable_path/Frameworks", "EXECUTABLE_PATH"));
        assert!(!query_matches_rpath("@loader_path/Frameworks", "plugins"));
    }

    #[cfg(not(any(target_os = "ios", target_os = "macos")))]
    #[test]
    fn non_apple_rpath_enumeration_reports_unsupported() {
        let err =
            find_image_rpaths("libsystem_malloc.dylib", None).expect_err("non-apple platforms should be unsupported");
        assert!(err.to_string().contains("Apple targets"));
    }
}
