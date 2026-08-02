use common::{Error, Result};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageFunctionStart {
    pub offset: u64,
    pub address: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageFunctionStarts {
    pub module_name: String,
    pub module_base: usize,
    pub dataoff: u32,
    pub datasize: u32,
    pub linkedit_base: usize,
    pub data_address: usize,
    pub starts: Vec<ImageFunctionStart>,
}

pub fn image_function_starts_support_available() -> bool {
    platform::image_function_starts_support_available()
}

pub fn find_image_function_starts(module_name: &str) -> Result<Option<ImageFunctionStarts>> {
    platform::find_image_function_starts(module_name)
}

#[cfg_attr(not(test), allow(dead_code))]
fn checked_add_usize(base: usize, addend: u64, label: &str) -> Result<usize> {
    base.checked_add(addend as usize)
        .filter(|_| addend <= usize::MAX as u64)
        .ok_or_else(|| Error::State(format!("{label} address overflowed address space")))
}

#[cfg_attr(not(test), allow(dead_code))]
fn read_uleb128(bytes: &[u8], cursor: &mut usize) -> Result<u64> {
    let mut value = 0u64;
    let mut shift = 0u32;
    while *cursor < bytes.len() {
        let byte = bytes[*cursor];
        *cursor += 1;
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
        shift += 7;
        if shift >= 64 {
            return Err(Error::State(
                "LC_FUNCTION_STARTS contains an oversized ULEB128 value".into(),
            ));
        }
    }

    Err(Error::State(
        "LC_FUNCTION_STARTS ended with a truncated ULEB128 value".into(),
    ))
}

#[cfg_attr(not(test), allow(dead_code))]
fn decode_function_starts_data(module_base: usize, bytes: &[u8]) -> Result<Vec<ImageFunctionStart>> {
    let mut starts = Vec::new();
    let mut offset = 0u64;
    let mut cursor = 0usize;
    while cursor < bytes.len() {
        let delta = read_uleb128(bytes, &mut cursor)?;
        if delta == 0 {
            break;
        }
        offset = offset
            .checked_add(delta)
            .ok_or_else(|| Error::State("LC_FUNCTION_STARTS offset overflowed u64".into()))?;
        let address = checked_add_usize(module_base, offset, "function start")?;
        starts.push(ImageFunctionStart { offset, address });
    }
    Ok(starts)
}

#[cfg(any(target_os = "ios", target_os = "macos"))]
mod platform {
    use common::{Error, Result};
    use std::mem::size_of;

    use super::{checked_add_usize, decode_function_starts_data};
    use crate::macho_load_commands::{LC_FUNCTION_STARTS, LC_SEGMENT_64};
    use crate::{enumerate_images, image_name_matches, ImageFunctionStarts, ImageInfo};

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

    pub fn image_function_starts_support_available() -> bool {
        true
    }

    pub fn find_image_function_starts(module_name: &str) -> Result<Option<ImageFunctionStarts>> {
        let trimmed = module_name.trim();
        if trimmed.is_empty() {
            return Err(Error::InvalidArgument(
                "module name must not be empty; use `native.functionStarts <module>`".into(),
            ));
        }

        let Some(image) = enumerate_images()?
            .into_iter()
            .find(|image| image_name_matches(trimmed, &image.name))
        else {
            return Ok(None);
        };

        find_function_starts_in_image(&image)
    }

    fn find_function_starts_in_image(image: &ImageInfo) -> Result<Option<ImageFunctionStarts>> {
        let header = image.base as *const MachHeader64;
        if header.is_null() {
            return Ok(None);
        }

        let header = unsafe { &*header };
        if header.magic != MH_MAGIC_64 {
            return Ok(None);
        }

        let mut linkedit_segment = None;
        let mut function_starts = None;
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
                LC_FUNCTION_STARTS => {
                    if command_size < size_of::<LinkeditDataCommand>() {
                        consumed += command_size;
                        command_ptr = unsafe { command_ptr.add(command_size) };
                        continue;
                    }
                    function_starts = Some(unsafe { &*(command_ptr as *const LinkeditDataCommand) });
                }
                _ => {}
            }

            consumed += command_size;
            command_ptr = unsafe { command_ptr.add(command_size) };
        }

        let (Some(linkedit), Some(command)) = (linkedit_segment, function_starts) else {
            return Ok(None);
        };

        let linkedit_base = compute_linkedit_base(image, linkedit)?;
        let data_address = checked_add_usize(linkedit_base, command.dataoff as u64, "LC_FUNCTION_STARTS blob")?;
        let bytes = if command.datasize == 0 {
            &[][..]
        } else {
            unsafe { std::slice::from_raw_parts(data_address as *const u8, command.datasize as usize) }
        };

        Ok(Some(ImageFunctionStarts {
            module_name: image.name.clone(),
            module_base: image.base,
            dataoff: command.dataoff,
            datasize: command.datasize,
            linkedit_base,
            data_address,
            starts: decode_function_starts_data(image.base, bytes)?,
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

    use crate::ImageFunctionStarts;

    pub fn image_function_starts_support_available() -> bool {
        false
    }

    pub fn find_image_function_starts(module_name: &str) -> Result<Option<ImageFunctionStarts>> {
        if module_name.trim().is_empty() {
            return Err(Error::InvalidArgument(
                "module name must not be empty; use `native.functionStarts <module>`".into(),
            ));
        }

        Err(Error::Unsupported(
            "Mach-O function-start enumeration is currently only available on Apple targets".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::{decode_function_starts_data, find_image_function_starts};

    #[test]
    fn decodes_function_starts_deltas_until_terminator() {
        let starts = decode_function_starts_data(0x1000, &[0x10, 0x05, 0x80, 0x01, 0x00]).expect("decode");
        assert_eq!(starts.len(), 3);
        assert_eq!(starts[0].offset, 0x10);
        assert_eq!(starts[0].address, 0x1010);
        assert_eq!(starts[1].offset, 0x15);
        assert_eq!(starts[1].address, 0x1015);
        assert_eq!(starts[2].offset, 0x95);
        assert_eq!(starts[2].address, 0x1095);
    }

    #[test]
    fn rejects_truncated_uleb128_in_function_starts() {
        let err = decode_function_starts_data(0x1000, &[0x80]).expect_err("truncated uleb128 should fail");
        assert!(err.to_string().contains("truncated ULEB128"));
    }

    #[cfg(not(any(target_os = "ios", target_os = "macos")))]
    #[test]
    fn non_apple_function_starts_reports_unsupported() {
        let err = find_image_function_starts("libsystem_malloc.dylib")
            .expect_err("non-apple platforms should be unsupported");
        assert!(err.to_string().contains("Apple targets"));
    }
}
