use common::{Error, Result};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageCodeSignature {
    pub module_name: String,
    pub module_base: usize,
    pub dataoff: u32,
    pub datasize: u32,
    pub linkedit_base: usize,
    pub data_address: usize,
    pub magic: Option<u32>,
    pub magic_name: Option<String>,
    pub length: Option<u32>,
    pub count: Option<u32>,
}

pub fn image_code_signature_support_available() -> bool {
    platform::image_code_signature_support_available()
}

pub fn find_image_code_signature(module_name: &str) -> Result<Option<ImageCodeSignature>> {
    platform::find_image_code_signature(module_name)
}

#[allow(dead_code)]
fn checked_add_usize(base: usize, addend: u64, label: &str) -> Result<usize> {
    base.checked_add(addend as usize)
        .filter(|_| addend <= usize::MAX as u64)
        .ok_or_else(|| Error::State(format!("{label} address overflowed address space")))
}

#[cfg_attr(not(test), allow(dead_code))]
fn parse_be_u32(bytes: &[u8], offset: usize, label: &str) -> Result<u32> {
    let end = offset
        .checked_add(4)
        .ok_or_else(|| Error::State(format!("{label} offset overflowed")))?;
    let raw = bytes
        .get(offset..end)
        .ok_or_else(|| Error::State(format!("{label} was truncated")))?;
    Ok(u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]))
}

#[cfg_attr(not(test), allow(dead_code))]
fn code_signature_magic_name(magic: u32) -> &'static str {
    match magic {
        0xfade0b01 => "CSMAGIC_BLOBWRAPPER",
        0xfade0b02 => "CSMAGIC_EMBEDDED_SIGNATURE_OLD",
        0xfade0c00 => "CSMAGIC_REQUIREMENT",
        0xfade0c01 => "CSMAGIC_REQUIREMENTS",
        0xfade0c02 => "CSMAGIC_CODEDIRECTORY",
        0xfade0c05 => "CSMAGIC_EMBEDDED_ENTITLEMENTS",
        0xfade0cc0 => "CSMAGIC_EMBEDDED_SIGNATURE",
        0xfade0cc1 => "CSMAGIC_DETACHED_SIGNATURE",
        0xfade7171 => "CSMAGIC_EMBEDDED_ENTITLEMENTS_DER",
        0xfade7172 => "CSMAGIC_EMBEDDED_LAUNCH_CONSTRAINT",
        _ => "CSMAGIC_UNKNOWN",
    }
}

#[cfg_attr(not(test), allow(dead_code))]
fn parse_code_signature_blob_header(bytes: &[u8]) -> Result<(u32, String, u32, Option<u32>)> {
    if bytes.is_empty() {
        return Err(Error::State("LC_CODE_SIGNATURE blob was empty".into()));
    }

    let magic = parse_be_u32(bytes, 0, "LC_CODE_SIGNATURE magic")?;
    let length = parse_be_u32(bytes, 4, "LC_CODE_SIGNATURE length")?;
    let count = match magic {
        0xfade0cc0 | 0xfade0cc1 => Some(parse_be_u32(bytes, 8, "LC_CODE_SIGNATURE superblob count")?),
        _ => None,
    };

    Ok((magic, code_signature_magic_name(magic).into(), length, count))
}

#[cfg(any(target_os = "ios", target_os = "macos"))]
mod platform {
    use common::{Error, Result};
    use std::mem::size_of;

    use super::{checked_add_usize, parse_code_signature_blob_header};
    use crate::{enumerate_images, image_name_matches, ImageCodeSignature, ImageInfo};

    const LC_SEGMENT_64: u32 = 0x19;
    const LC_CODE_SIGNATURE: u32 = 0x1d;
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
    struct SegmentCommand64 {
        cmd: u32,
        cmdsize: u32,
        segname: [u8; 16],
        vmaddr: u64,
        vmsize: u64,
        fileoff: u64,
        filesize: u64,
        maxprot: i32,
        initprot: i32,
        nsects: u32,
        flags: u32,
    }

    #[repr(C)]
    struct LinkeditDataCommand {
        cmd: u32,
        cmdsize: u32,
        dataoff: u32,
        datasize: u32,
    }

    pub fn image_code_signature_support_available() -> bool {
        true
    }

    pub fn find_image_code_signature(module_name: &str) -> Result<Option<ImageCodeSignature>> {
        let trimmed = module_name.trim();
        if trimmed.is_empty() {
            return Err(Error::InvalidArgument(
                "module name must not be empty; use `native.codeSignature <module>`".into(),
            ));
        }

        let Some(image) = enumerate_images()?
            .into_iter()
            .find(|image| image_name_matches(trimmed, &image.name))
        else {
            return Ok(None);
        };

        find_code_signature_in_image(&image)
    }

    fn find_code_signature_in_image(image: &ImageInfo) -> Result<Option<ImageCodeSignature>> {
        let header = image.base as *const MachHeader64;
        if header.is_null() {
            return Ok(None);
        }

        let header = unsafe { &*header };
        if header.magic != MH_MAGIC_64 {
            return Ok(None);
        }

        let mut linkedit_segment = None;
        let mut code_signature = None;
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

            match load.cmd {
                LC_SEGMENT_64 => {
                    if command_size < size_of::<SegmentCommand64>() {
                        consumed += command_size;
                        command_ptr = unsafe { command_ptr.add(command_size) };
                        continue;
                    }
                    let segment = unsafe { &*(command_ptr as *const SegmentCommand64) };
                    if segment_name(segment) == "__LINKEDIT" {
                        linkedit_segment = Some(segment);
                    }
                }
                LC_CODE_SIGNATURE => {
                    if command_size < size_of::<LinkeditDataCommand>() {
                        consumed += command_size;
                        command_ptr = unsafe { command_ptr.add(command_size) };
                        continue;
                    }
                    code_signature = Some(unsafe { &*(command_ptr as *const LinkeditDataCommand) });
                }
                _ => {}
            }

            consumed += command_size;
            command_ptr = unsafe { command_ptr.add(command_size) };
        }

        let (Some(linkedit), Some(command)) = (linkedit_segment, code_signature) else {
            return Ok(None);
        };

        let linkedit_base = compute_linkedit_base(image, linkedit)?;
        let data_address = checked_add_usize(linkedit_base, command.dataoff as u64, "LC_CODE_SIGNATURE blob")?;
        let bytes = if command.datasize == 0 {
            &[][..]
        } else {
            unsafe { std::slice::from_raw_parts(data_address as *const u8, command.datasize as usize) }
        };

        let (magic, magic_name, length, count) = if bytes.is_empty() {
            (None, None, None, None)
        } else {
            let (magic, magic_name, length, count) = parse_code_signature_blob_header(bytes)?;
            (Some(magic), Some(magic_name), Some(length), count)
        };

        Ok(Some(ImageCodeSignature {
            module_name: image.name.clone(),
            module_base: image.base,
            dataoff: command.dataoff,
            datasize: command.datasize,
            linkedit_base,
            data_address,
            magic,
            magic_name,
            length,
            count,
        }))
    }

    unsafe fn header_ptr_after_header(header: &MachHeader64) -> *const u8 {
        (header as *const MachHeader64).add(1) as *const u8
    }

    fn segment_name(segment: &SegmentCommand64) -> &str {
        let len = segment
            .segname
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(segment.segname.len());
        std::str::from_utf8(&segment.segname[..len]).unwrap_or("")
    }

    fn compute_linkedit_base(image: &ImageInfo, linkedit_segment: &SegmentCommand64) -> Result<usize> {
        let base = image.slide as i128 + linkedit_segment.vmaddr as i128 - linkedit_segment.fileoff as i128;
        if base < 0 || base > usize::MAX as i128 {
            return Err(Error::State(format!(
                "computed __LINKEDIT base for {} overflowed address space",
                image.name
            )));
        }
        Ok(base as usize)
    }
}

#[cfg(not(any(target_os = "ios", target_os = "macos")))]
mod platform {
    use common::{Error, Result};

    use crate::ImageCodeSignature;

    pub fn image_code_signature_support_available() -> bool {
        false
    }

    pub fn find_image_code_signature(module_name: &str) -> Result<Option<ImageCodeSignature>> {
        if module_name.trim().is_empty() {
            return Err(Error::InvalidArgument(
                "module name must not be empty; use `native.codeSignature <module>`".into(),
            ));
        }

        Err(Error::Unsupported(
            "Mach-O code-signature enumeration is currently only available on Apple targets".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::{find_image_code_signature, parse_code_signature_blob_header};

    #[test]
    fn parses_superblob_header_fields() {
        let bytes = [0xfa, 0xde, 0x0c, 0xc0, 0x00, 0x00, 0x01, 0x20, 0x00, 0x00, 0x00, 0x03];
        let (magic, magic_name, length, count) = parse_code_signature_blob_header(&bytes).expect("parse");
        assert_eq!(magic, 0xfade0cc0);
        assert_eq!(magic_name, "CSMAGIC_EMBEDDED_SIGNATURE");
        assert_eq!(length, 0x120);
        assert_eq!(count, Some(3));
    }

    #[test]
    fn parses_non_superblob_header_without_count() {
        let bytes = [0xfa, 0xde, 0x0c, 0x02, 0x00, 0x00, 0x00, 0x44];
        let (magic, magic_name, length, count) = parse_code_signature_blob_header(&bytes).expect("parse");
        assert_eq!(magic, 0xfade0c02);
        assert_eq!(magic_name, "CSMAGIC_CODEDIRECTORY");
        assert_eq!(length, 0x44);
        assert_eq!(count, None);
    }

    #[test]
    fn rejects_truncated_code_signature_header() {
        let err = parse_code_signature_blob_header(&[0xfa, 0xde, 0x0c]).expect_err("truncated header should fail");
        assert!(err.to_string().contains("truncated"));
    }

    #[cfg(not(any(target_os = "ios", target_os = "macos")))]
    #[test]
    fn non_apple_code_signature_reports_unsupported() {
        let err =
            find_image_code_signature("libsystem_malloc.dylib").expect_err("non-apple platforms should be unsupported");
        assert!(err.to_string().contains("Apple targets"));
    }
}
