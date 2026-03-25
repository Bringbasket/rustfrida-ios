use common::Result;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageDependency {
    pub module_name: String,
    pub module_base: usize,
    pub ordinal: usize,
    pub path: String,
    pub kind: String,
    pub current_version: u32,
    pub compatibility_version: u32,
    pub timestamp: u32,
}

pub fn image_dependency_support_available() -> bool {
    platform::image_dependency_support_available()
}

pub fn find_image_dependencies(module_name: &str, query: Option<&str>) -> Result<Vec<ImageDependency>> {
    platform::find_image_dependencies(module_name, query)
}

#[cfg_attr(not(any(target_os = "ios", target_os = "macos")), allow(dead_code))]
fn query_matches_dependency(path: &str, query: &str) -> bool {
    let trimmed = query.trim();
    if trimmed.is_empty() {
        return false;
    }

    let needle = trimmed.to_ascii_lowercase();
    path.to_ascii_lowercase().contains(&needle)
}

#[cfg(any(target_os = "ios", target_os = "macos"))]
mod platform {
    use common::{Error, Result};

    use crate::{enumerate_images, image_name_matches, ImageDependency, ImageInfo};

    use super::query_matches_dependency;

    const LC_LOAD_DYLIB: u32 = 0xc;
    const LC_LOAD_WEAK_DYLIB: u32 = 0x18;
    const LC_REEXPORT_DYLIB: u32 = 0x1f;
    const LC_LOAD_UPWARD_DYLIB: u32 = 0x24;
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
    struct Dylib {
        name: u32,
        timestamp: u32,
        current_version: u32,
        compatibility_version: u32,
    }

    #[repr(C)]
    struct DylibCommand {
        cmd: u32,
        cmdsize: u32,
        dylib: Dylib,
    }

    pub fn image_dependency_support_available() -> bool {
        true
    }

    pub fn find_image_dependencies(module_name: &str, query: Option<&str>) -> Result<Vec<ImageDependency>> {
        let trimmed = module_name.trim();
        if trimmed.is_empty() {
            return Err(Error::InvalidArgument(
                "module name must not be empty; use `native.dependencies <module>` or `native.dependencies <module> -- <query>`"
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

        collect_dependencies_in_image(&image, trimmed_query)
    }

    fn collect_dependencies_in_image(image: &ImageInfo, query: Option<&str>) -> Result<Vec<ImageDependency>> {
        let header = image.base as *const MachHeader64;
        if header.is_null() {
            return Ok(Vec::new());
        }

        let header = unsafe { &*header };
        if header.magic != MH_MAGIC_64 {
            return Ok(Vec::new());
        }

        let mut dependencies = Vec::new();
        let mut command_ptr = unsafe { header_ptr_after_header(header) };
        let mut ordinal = 0usize;

        for _ in 0..header.ncmds {
            let load = unsafe { &*(command_ptr as *const LoadCommand) };
            match load.cmd {
                LC_LOAD_DYLIB | LC_LOAD_WEAK_DYLIB | LC_REEXPORT_DYLIB | LC_LOAD_UPWARD_DYLIB => {
                    ordinal += 1;
                    let command = unsafe { &*(command_ptr as *const DylibCommand) };
                    let bytes = unsafe { std::slice::from_raw_parts(command_ptr, load.cmdsize as usize) };
                    let path = read_command_string(bytes, command.dylib.name).unwrap_or_default();
                    if query
                        .map(|query| query_matches_dependency(&path, query))
                        .unwrap_or(true)
                    {
                        dependencies.push(ImageDependency {
                            module_name: image.name.clone(),
                            module_base: image.base,
                            ordinal,
                            path,
                            kind: dependency_kind(load.cmd).to_string(),
                            current_version: command.dylib.current_version,
                            compatibility_version: command.dylib.compatibility_version,
                            timestamp: command.dylib.timestamp,
                        });
                    }
                }
                _ => {}
            }

            let command_size = load.cmdsize as usize;
            if command_size == 0 {
                break;
            }
            command_ptr = unsafe { command_ptr.add(command_size) };
        }

        Ok(dependencies)
    }

    fn dependency_kind(command: u32) -> &'static str {
        match command {
            LC_LOAD_DYLIB => "load",
            LC_LOAD_WEAK_DYLIB => "weak",
            LC_REEXPORT_DYLIB => "reexport",
            LC_LOAD_UPWARD_DYLIB => "upward",
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

    use crate::ImageDependency;

    pub fn image_dependency_support_available() -> bool {
        false
    }

    pub fn find_image_dependencies(module_name: &str, _query: Option<&str>) -> Result<Vec<ImageDependency>> {
        if module_name.trim().is_empty() {
            return Err(Error::InvalidArgument(
                "module name must not be empty; use `native.dependencies <module>` or `native.dependencies <module> -- <query>`"
                    .into(),
            ));
        }

        Err(Error::Unsupported(
            "Mach-O dependency enumeration is currently only available on Apple targets".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::{find_image_dependencies, query_matches_dependency};

    #[test]
    fn dependency_query_matches_substrings() {
        assert!(query_matches_dependency("/usr/lib/libobjc.A.dylib", "objc"));
        assert!(query_matches_dependency(
            "/System/Library/Frameworks/UIKit.framework/UIKit",
            "uikit"
        ));
        assert!(!query_matches_dependency("/usr/lib/libSystem.B.dylib", "uikit"));
    }

    #[cfg(not(any(target_os = "ios", target_os = "macos")))]
    #[test]
    fn non_apple_dependency_enumeration_reports_unsupported() {
        let err = find_image_dependencies("libsystem_malloc.dylib", None)
            .expect_err("non-apple platforms should be unsupported");
        assert!(err.to_string().contains("Apple targets"));
    }
}
