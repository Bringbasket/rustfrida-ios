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

pub fn rpath_path_or_name_matches(path: &str, query: &str) -> bool {
    query_matches_rpath(path, query)
}

#[cfg_attr(not(any(target_os = "ios", target_os = "macos")), allow(dead_code))]
fn query_matches_rpath(path: &str, query: &str) -> bool {
    let trimmed = query.trim();
    if trimmed.is_empty() {
        return false;
    }

    let needle = trimmed.to_ascii_lowercase();
    rpath_search_terms(path).into_iter().any(|term| term.contains(&needle))
}

fn rpath_search_terms(path: &str) -> Vec<String> {
    let trimmed = path.trim();
    let mut terms = Vec::new();
    push_unique_lowercase(&mut terms, trimmed);

    for token in ["@loader_path/", "@executable_path/", "@rpath/"] {
        if let Some(without_token) = trimmed.strip_prefix(token) {
            push_unique_lowercase(&mut terms, without_token);
        }
    }

    let basename = trimmed.rsplit('/').next().unwrap_or(trimmed);
    push_unique_lowercase(&mut terms, basename);

    terms
}

fn push_unique_lowercase(terms: &mut Vec<String>, value: &str) {
    if value.is_empty() {
        return;
    }
    let normalized = value.to_ascii_lowercase();
    if !terms.iter().any(|term| term == &normalized) {
        terms.push(normalized);
    }
}

#[cfg(any(target_os = "ios", target_os = "macos"))]
mod platform {
    use common::{Error, Result};
    use std::mem::size_of;

    use crate::macho_load_commands::LC_RPATH;
    use crate::{enumerate_images, image_name_matches, ImageInfo, ImageRpath};

    use super::query_matches_rpath;

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

            if load.cmd == LC_RPATH {
                if command_size < size_of::<RpathCommand>() {
                    consumed += command_size;
                    command_ptr = unsafe { command_ptr.add(command_size) };
                    continue;
                }

                let command = unsafe { &*(command_ptr as *const RpathCommand) };
                let bytes = unsafe { std::slice::from_raw_parts(command_ptr, command_size) };
                let path = read_command_string(bytes, command.path).unwrap_or_default();
                if query.map(|query| query_matches_rpath(&path, query)).unwrap_or(true) {
                    rpaths.push(ImageRpath {
                        module_name: image.name.clone(),
                        module_base: image.base,
                        path,
                    });
                }
            }

            consumed += command_size;
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
    use super::{find_image_rpaths, query_matches_rpath, rpath_path_or_name_matches};

    #[test]
    fn rpath_query_matches_substrings() {
        assert!(query_matches_rpath("@loader_path/Frameworks", "frameworks"));
        assert!(query_matches_rpath("@executable_path/Frameworks", "EXECUTABLE_PATH"));
        assert!(!query_matches_rpath("@loader_path/Frameworks", "plugins"));
    }

    #[test]
    fn rpath_query_matches_token_stripped_paths() {
        assert!(rpath_path_or_name_matches(
            "@loader_path/Frameworks",
            "loader_path/Frameworks"
        ));
        assert!(rpath_path_or_name_matches("@loader_path/Frameworks", "Frameworks"));
        assert!(rpath_path_or_name_matches("@executable_path/PlugIns", "PlugIns"));
        assert!(rpath_path_or_name_matches(
            "@rpath/Nested/Frameworks",
            "Nested/Frameworks"
        ));
        assert!(!rpath_path_or_name_matches("@loader_path/Frameworks", "Libraries"));
    }

    #[cfg(not(any(target_os = "ios", target_os = "macos")))]
    #[test]
    fn non_apple_rpath_enumeration_reports_unsupported() {
        let err =
            find_image_rpaths("libsystem_malloc.dylib", None).expect_err("non-apple platforms should be unsupported");
        assert!(err.to_string().contains("Apple targets"));
    }
}
