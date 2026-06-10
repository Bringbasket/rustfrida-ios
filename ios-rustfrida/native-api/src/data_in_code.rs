use common::{Error, Result};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageDataInCodeEntry {
    pub offset: u32,
    pub address: usize,
    pub length: u16,
    pub kind: u16,
    pub kind_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageDataInCode {
    pub module_name: String,
    pub module_base: usize,
    pub dataoff: u32,
    pub datasize: u32,
    pub linkedit_base: usize,
    pub data_address: usize,
    pub entries: Vec<ImageDataInCodeEntry>,
}

pub fn image_data_in_code_support_available() -> bool {
    platform::image_data_in_code_support_available()
}

pub fn find_image_data_in_code(module_name: &str) -> Result<Option<ImageDataInCode>> {
    platform::find_image_data_in_code(module_name)
}

#[cfg_attr(not(test), allow(dead_code))]
fn checked_add_usize(base: usize, addend: u64, label: &str) -> Result<usize> {
    base.checked_add(addend as usize)
        .filter(|_| addend <= usize::MAX as u64)
        .ok_or_else(|| Error::State(format!("{label} address overflowed address space")))
}

#[cfg_attr(not(test), allow(dead_code))]
fn data_in_code_kind_name(kind: u16) -> &'static str {
    match kind {
        1 => "DICE_KIND_DATA",
        2 => "DICE_KIND_JUMP_TABLE8",
        3 => "DICE_KIND_JUMP_TABLE16",
        4 => "DICE_KIND_JUMP_TABLE32",
        5 => "DICE_KIND_ABS_JUMP_TABLE32",
        _ => "DICE_KIND_UNKNOWN",
    }
}

#[cfg_attr(not(test), allow(dead_code))]
fn decode_data_in_code_entries(module_base: usize, bytes: &[u8]) -> Result<Vec<ImageDataInCodeEntry>> {
    const ENTRY_SIZE: usize = 8;
    if bytes.len() % ENTRY_SIZE != 0 {
        return Err(Error::State(format!(
            "LC_DATA_IN_CODE size {} was not aligned to entry size {}",
            bytes.len(),
            ENTRY_SIZE
        )));
    }

    let mut entries = Vec::with_capacity(bytes.len() / ENTRY_SIZE);
    for chunk in bytes.chunks_exact(ENTRY_SIZE) {
        let offset = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        let length = u16::from_le_bytes([chunk[4], chunk[5]]);
        let kind = u16::from_le_bytes([chunk[6], chunk[7]]);
        let address = checked_add_usize(module_base, u64::from(offset), "LC_DATA_IN_CODE entry")?;
        entries.push(ImageDataInCodeEntry {
            offset,
            address,
            length,
            kind,
            kind_name: data_in_code_kind_name(kind).into(),
        });
    }
    Ok(entries)
}

#[cfg(any(target_os = "ios", target_os = "macos"))]
mod platform {
    use common::{Error, Result};
    use std::mem::size_of;

    use super::{checked_add_usize, decode_data_in_code_entries};
    use crate::{enumerate_images, image_name_matches, ImageDataInCode, ImageInfo};

    const LC_SEGMENT_64: u32 = 0x19;
    const LC_DATA_IN_CODE: u32 = 0x29;
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

    pub fn image_data_in_code_support_available() -> bool {
        true
    }

    pub fn find_image_data_in_code(module_name: &str) -> Result<Option<ImageDataInCode>> {
        let trimmed = module_name.trim();
        if trimmed.is_empty() {
            return Err(Error::InvalidArgument(
                "module name must not be empty; use `native.dataInCode <module>`".into(),
            ));
        }

        let Some(image) = enumerate_images()?
            .into_iter()
            .find(|image| image_name_matches(trimmed, &image.name))
        else {
            return Ok(None);
        };

        find_data_in_code_in_image(&image)
    }

    fn find_data_in_code_in_image(image: &ImageInfo) -> Result<Option<ImageDataInCode>> {
        let header = image.base as *const MachHeader64;
        if header.is_null() {
            return Ok(None);
        }

        let header = unsafe { &*header };
        if header.magic != MH_MAGIC_64 {
            return Ok(None);
        }

        let mut linkedit_segment = None;
        let mut data_in_code = None;
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
                LC_DATA_IN_CODE => {
                    if command_size < size_of::<LinkeditDataCommand>() {
                        consumed += command_size;
                        command_ptr = unsafe { command_ptr.add(command_size) };
                        continue;
                    }
                    data_in_code = Some(unsafe { &*(command_ptr as *const LinkeditDataCommand) });
                }
                _ => {}
            }

            consumed += command_size;
            command_ptr = unsafe { command_ptr.add(command_size) };
        }

        let (Some(linkedit), Some(command)) = (linkedit_segment, data_in_code) else {
            return Ok(None);
        };

        let linkedit_base = compute_linkedit_base(image, linkedit)?;
        let data_address = checked_add_usize(linkedit_base, command.dataoff as u64, "LC_DATA_IN_CODE blob")?;
        let bytes = if command.datasize == 0 {
            &[][..]
        } else {
            unsafe { std::slice::from_raw_parts(data_address as *const u8, command.datasize as usize) }
        };

        Ok(Some(ImageDataInCode {
            module_name: image.name.clone(),
            module_base: image.base,
            dataoff: command.dataoff,
            datasize: command.datasize,
            linkedit_base,
            data_address,
            entries: decode_data_in_code_entries(image.base, bytes)?,
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

    use crate::ImageDataInCode;

    pub fn image_data_in_code_support_available() -> bool {
        false
    }

    pub fn find_image_data_in_code(module_name: &str) -> Result<Option<ImageDataInCode>> {
        if module_name.trim().is_empty() {
            return Err(Error::InvalidArgument(
                "module name must not be empty; use `native.dataInCode <module>`".into(),
            ));
        }

        Err(Error::Unsupported(
            "Mach-O data-in-code enumeration is currently only available on Apple targets".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::{data_in_code_kind_name, decode_data_in_code_entries, find_image_data_in_code};

    #[test]
    fn decodes_data_in_code_entries() {
        let bytes = [
            0x10, 0x00, 0x00, 0x00, 0x08, 0x00, 0x01, 0x00, 0x40, 0x00, 0x00, 0x00, 0x10, 0x00, 0x04, 0x00,
        ];
        let entries = decode_data_in_code_entries(0x1000, &bytes).expect("decode");
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].offset, 0x10);
        assert_eq!(entries[0].address, 0x1010);
        assert_eq!(entries[0].length, 8);
        assert_eq!(entries[0].kind, 1);
        assert_eq!(entries[0].kind_name, "DICE_KIND_DATA");
        assert_eq!(entries[1].offset, 0x40);
        assert_eq!(entries[1].address, 0x1040);
        assert_eq!(entries[1].length, 0x10);
        assert_eq!(entries[1].kind_name, "DICE_KIND_JUMP_TABLE32");
    }

    #[test]
    fn rejects_truncated_data_in_code_table() {
        let err = decode_data_in_code_entries(0x1000, &[0, 1, 2]).expect_err("truncated table should fail");
        assert!(err.to_string().contains("not aligned"));
    }

    #[test]
    fn reports_known_data_in_code_kinds() {
        assert_eq!(data_in_code_kind_name(1), "DICE_KIND_DATA");
        assert_eq!(data_in_code_kind_name(5), "DICE_KIND_ABS_JUMP_TABLE32");
        assert_eq!(data_in_code_kind_name(99), "DICE_KIND_UNKNOWN");
    }

    #[cfg(not(any(target_os = "ios", target_os = "macos")))]
    #[test]
    fn non_apple_data_in_code_reports_unsupported() {
        let err =
            find_image_data_in_code("libsystem_malloc.dylib").expect_err("non-apple platforms should be unsupported");
        assert!(err.to_string().contains("Apple targets"));
    }
}
