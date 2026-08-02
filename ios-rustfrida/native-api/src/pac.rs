use common::Result;

use crate::ImageInfo;

pub fn pac_support_available() -> bool {
    platform::pac_support_available()
}

pub fn current_process_uses_arm64e() -> Result<bool> {
    platform::current_process_uses_arm64e()
}

pub fn image_uses_arm64e(module_name: &str) -> Result<Option<bool>> {
    platform::image_uses_arm64e(module_name)
}

pub fn enumerate_arm64e_images(query: Option<&str>) -> Result<Vec<ImageInfo>> {
    platform::enumerate_arm64e_images(query)
}

pub fn strip_code_pointer(address: usize) -> Result<usize> {
    platform::strip_code_pointer(address)
}

pub fn strip_data_pointer(address: usize) -> Result<usize> {
    platform::strip_data_pointer(address)
}

pub fn normalize_code_pointer(address: usize) -> usize {
    strip_code_pointer(address).unwrap_or(address)
}

#[cfg(any(target_os = "ios", target_os = "macos"))]
mod platform {
    #[cfg(all(target_arch = "aarch64", target_feature = "paca", target_feature = "pacg"))]
    use core::arch::asm;

    use common::Result;

    use crate::{enumerate_images, image_name_matches};

    const MH_MAGIC_64: u32 = 0xfeedfacf;
    const CPU_TYPE_ARM64: i32 = 0x0100000c;
    const CPU_SUBTYPE_ARM64E: i32 = 2;

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

    pub fn pac_support_available() -> bool {
        cfg!(target_arch = "aarch64")
    }

    pub fn current_process_uses_arm64e() -> Result<bool> {
        let Some(image) = enumerate_images()?.into_iter().next() else {
            return Ok(false);
        };

        Ok(image_uses_arm64e_base(image.base))
    }

    pub fn image_uses_arm64e(module_name: &str) -> Result<Option<bool>> {
        let trimmed = module_name.trim();
        if trimmed.is_empty() {
            return Err(common::Error::InvalidArgument(
                "module name must not be empty; use `pac.image <module>`".into(),
            ));
        }

        let Some(image) = enumerate_images()?
            .into_iter()
            .find(|image| image_name_matches(trimmed, &image.name))
        else {
            return Ok(None);
        };

        Ok(Some(image_uses_arm64e_base(image.base)))
    }

    pub fn enumerate_arm64e_images(query: Option<&str>) -> Result<Vec<crate::ImageInfo>> {
        let needle = query
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(|value| value.to_ascii_lowercase());

        let images = enumerate_images()?
            .into_iter()
            .filter(|image| image_uses_arm64e_base(image.base))
            .filter(|image| {
                needle
                    .as_ref()
                    .map(|needle| image.name.to_ascii_lowercase().contains(needle))
                    .unwrap_or(true)
            })
            .collect::<Vec<_>>();
        Ok(images)
    }

    pub fn strip_code_pointer(address: usize) -> Result<usize> {
        Ok(strip_instruction_pointer_best_effort(address))
    }

    pub fn strip_data_pointer(address: usize) -> Result<usize> {
        Ok(strip_data_pointer_best_effort(address))
    }

    fn image_uses_arm64e_base(base: usize) -> bool {
        let header = base as *const MachHeader64;
        if header.is_null() {
            return false;
        }

        let header = unsafe { &*header };
        if header.magic != MH_MAGIC_64 || header.cputype != CPU_TYPE_ARM64 {
            return false;
        }

        (header.cpusubtype & 0xff) == CPU_SUBTYPE_ARM64E
    }

    #[cfg(all(target_arch = "aarch64", target_feature = "paca", target_feature = "pacg"))]
    fn strip_instruction_pointer_best_effort(address: usize) -> usize {
        let mut value = address;
        unsafe {
            asm!("xpaci {value}", value = inout(reg) value, options(nomem, nostack, preserves_flags));
        }
        value
    }

    #[cfg(not(all(target_arch = "aarch64", target_feature = "paca", target_feature = "pacg")))]
    fn strip_instruction_pointer_best_effort(address: usize) -> usize {
        canonicalize_apple_user_pointer(address)
    }

    #[cfg(all(target_arch = "aarch64", target_feature = "paca", target_feature = "pacg"))]
    fn strip_data_pointer_best_effort(address: usize) -> usize {
        let mut value = address;
        unsafe {
            asm!("xpacd {value}", value = inout(reg) value, options(nomem, nostack, preserves_flags));
        }
        value
    }

    #[cfg(not(all(target_arch = "aarch64", target_feature = "paca", target_feature = "pacg")))]
    fn strip_data_pointer_best_effort(address: usize) -> usize {
        canonicalize_apple_user_pointer(address)
    }

    fn canonicalize_apple_user_pointer(address: usize) -> usize {
        #[cfg(target_arch = "aarch64")]
        {
            return address & 0x0000_ffff_ffff_ffff;
        }

        #[cfg(not(target_arch = "aarch64"))]
        address
    }
}

#[cfg(not(any(target_os = "ios", target_os = "macos")))]
mod platform {
    use common::Result;

    pub fn pac_support_available() -> bool {
        false
    }

    pub fn current_process_uses_arm64e() -> Result<bool> {
        Ok(false)
    }

    pub fn image_uses_arm64e(module_name: &str) -> Result<Option<bool>> {
        if module_name.trim().is_empty() {
            return Err(common::Error::InvalidArgument(
                "module name must not be empty; use `pac.image <module>`".into(),
            ));
        }
        Ok(None)
    }

    pub fn enumerate_arm64e_images(_query: Option<&str>) -> Result<Vec<crate::ImageInfo>> {
        Ok(Vec::new())
    }

    pub fn strip_code_pointer(address: usize) -> Result<usize> {
        Ok(address)
    }

    pub fn strip_data_pointer(address: usize) -> Result<usize> {
        Ok(address)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        current_process_uses_arm64e, enumerate_arm64e_images, image_uses_arm64e, normalize_code_pointer,
        pac_support_available, strip_code_pointer,
    };

    #[test]
    fn normalization_is_identity_when_pac_support_is_absent() {
        if !pac_support_available() {
            assert_eq!(normalize_code_pointer(0x1234_5678), 0x1234_5678);
            assert_eq!(
                strip_code_pointer(0x1234_5678).expect("strip code pointer"),
                0x1234_5678
            );
        }
    }

    #[test]
    fn arm64e_query_is_callable() {
        let _ = current_process_uses_arm64e().expect("query arm64e state");
    }

    #[test]
    fn image_arm64e_query_is_callable() {
        let _ = image_uses_arm64e("libsystem_malloc.dylib").expect("query image arm64e state");
    }

    #[test]
    fn arm64e_image_enumeration_is_callable() {
        let _ = enumerate_arm64e_images(Some("libsystem")).expect("enumerate arm64e images");
    }
}
