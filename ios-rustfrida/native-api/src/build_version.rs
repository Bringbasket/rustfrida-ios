use common::Result;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageBuildTool {
    pub tool: String,
    pub version: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageBuildVersion {
    pub module_name: String,
    pub module_base: usize,
    pub platform: String,
    pub min_os: String,
    pub sdk: String,
    pub tools: Vec<ImageBuildTool>,
}

pub fn image_build_version_support_available() -> bool {
    platform::image_build_version_support_available()
}

pub fn find_image_build_version(module_name: &str) -> Result<Option<ImageBuildVersion>> {
    platform::find_image_build_version(module_name)
}

#[cfg(any(target_os = "ios", target_os = "macos"))]
mod platform {
    use common::{Error, Result};
    use std::mem::size_of;

    use crate::{enumerate_images, image_name_matches, ImageBuildTool, ImageBuildVersion, ImageInfo};

    const LC_BUILD_VERSION: u32 = 0x33;
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
    struct BuildVersionCommand {
        cmd: u32,
        cmdsize: u32,
        platform: u32,
        minos: u32,
        sdk: u32,
        ntools: u32,
    }

    #[derive(Clone, Copy)]
    #[repr(C)]
    struct BuildToolVersion {
        tool: u32,
        version: u32,
    }

    pub fn image_build_version_support_available() -> bool {
        true
    }

    pub fn find_image_build_version(module_name: &str) -> Result<Option<ImageBuildVersion>> {
        let trimmed = module_name.trim();
        if trimmed.is_empty() {
            return Err(Error::InvalidArgument(
                "module name must not be empty; use `native.buildVersion <module>`".into(),
            ));
        }

        let Some(image) = enumerate_images()?
            .into_iter()
            .find(|image| image_name_matches(trimmed, &image.name))
        else {
            return Ok(None);
        };

        find_build_version_in_image(&image)
    }

    fn find_build_version_in_image(image: &ImageInfo) -> Result<Option<ImageBuildVersion>> {
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

            if load.cmd == LC_BUILD_VERSION {
                if command_size < size_of::<BuildVersionCommand>() {
                    return Ok(None);
                }

                let command = unsafe { &*(command_ptr as *const BuildVersionCommand) };
                let bytes = unsafe { std::slice::from_raw_parts(command_ptr, command_size) };
                return Ok(Some(ImageBuildVersion {
                    module_name: image.name.clone(),
                    module_base: image.base,
                    platform: platform_name(command.platform).to_string(),
                    min_os: format_packed_version(command.minos),
                    sdk: format_packed_version(command.sdk),
                    tools: parse_build_tools(bytes, command.ntools),
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

    fn parse_build_tools(bytes: &[u8], count: u32) -> Vec<ImageBuildTool> {
        let base = size_of::<BuildVersionCommand>();
        let tool_size = size_of::<BuildToolVersion>();
        let available = bytes.len().saturating_sub(base) / tool_size;
        let count = count.min(available as u32) as usize;

        let mut tools = Vec::with_capacity(count);
        for index in 0..count {
            let start = base + index * tool_size;
            let end = start + tool_size;
            let Some(tool) = read_struct::<BuildToolVersion>(&bytes[start..end]) else {
                continue;
            };
            tools.push(ImageBuildTool {
                tool: build_tool_name(tool.tool).to_string(),
                version: format_packed_version(tool.version),
            });
        }
        tools
    }

    fn read_struct<T: Copy>(bytes: &[u8]) -> Option<T> {
        if bytes.len() < size_of::<T>() {
            return None;
        }
        Some(unsafe { std::ptr::read_unaligned(bytes.as_ptr() as *const T) })
    }

    fn format_packed_version(version: u32) -> String {
        format!(
            "{}.{}.{}",
            (version >> 16) & 0xffff,
            (version >> 8) & 0xff,
            version & 0xff
        )
    }

    fn platform_name(platform: u32) -> &'static str {
        match platform {
            1 => "macos",
            2 => "ios",
            3 => "tvos",
            4 => "watchos",
            5 => "bridgeos",
            6 => "maccatalyst",
            7 => "ios-simulator",
            8 => "tvos-simulator",
            9 => "watchos-simulator",
            10 => "driverkit",
            11 => "visionos",
            12 => "visionos-simulator",
            _ => "unknown",
        }
    }

    fn build_tool_name(tool: u32) -> &'static str {
        match tool {
            1 => "clang",
            2 => "swift",
            3 => "ld",
            _ => "tool",
        }
    }
}

#[cfg(not(any(target_os = "ios", target_os = "macos")))]
mod platform {
    use common::{Error, Result};

    use crate::ImageBuildVersion;

    pub fn image_build_version_support_available() -> bool {
        false
    }

    pub fn find_image_build_version(module_name: &str) -> Result<Option<ImageBuildVersion>> {
        if module_name.trim().is_empty() {
            return Err(Error::InvalidArgument(
                "module name must not be empty; use `native.buildVersion <module>`".into(),
            ));
        }

        Err(Error::Unsupported(
            "Mach-O build-version enumeration is currently only available on Apple targets".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::find_image_build_version;

    #[cfg(not(any(target_os = "ios", target_os = "macos")))]
    #[test]
    fn non_apple_build_version_reports_unsupported() {
        let err =
            find_image_build_version("libsystem_malloc.dylib").expect_err("non-apple platforms should be unsupported");
        assert!(err.to_string().contains("Apple targets"));
    }
}
