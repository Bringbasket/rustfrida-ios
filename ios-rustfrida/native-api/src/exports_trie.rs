use common::{Error, Result};
use std::collections::HashSet;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageExportsTrieEntry {
    pub name: String,
    pub flags: u64,
    pub kind: String,
    pub address: Option<usize>,
    pub offset: Option<u64>,
    pub other: Option<u64>,
    pub import_name: Option<String>,
    pub is_weak_definition: bool,
    pub is_reexport: bool,
    pub is_stub_and_resolver: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageExportsTrie {
    pub module_name: String,
    pub module_base: usize,
    pub dataoff: u32,
    pub datasize: u32,
    pub linkedit_base: usize,
    pub data_address: usize,
    pub entries: Vec<ImageExportsTrieEntry>,
}

pub fn image_exports_trie_support_available() -> bool {
    platform::image_exports_trie_support_available()
}

pub fn find_image_exports_trie(module_name: &str) -> Result<Option<ImageExportsTrie>> {
    platform::find_image_exports_trie(module_name)
}

#[cfg_attr(not(test), allow(dead_code))]
fn checked_add_usize(base: usize, addend: u64, label: &str) -> Result<usize> {
    base.checked_add(addend as usize)
        .filter(|_| addend <= usize::MAX as u64)
        .ok_or_else(|| Error::State(format!("{label} address overflowed address space")))
}

#[cfg_attr(not(test), allow(dead_code))]
fn read_uleb128(bytes: &[u8], cursor: &mut usize, label: &str) -> Result<u64> {
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
            return Err(Error::State(format!("{label} contained an oversized ULEB128 value")));
        }
    }

    Err(Error::State(format!(
        "{label} ended with a truncated ULEB128 value"
    )))
}

#[cfg_attr(not(test), allow(dead_code))]
fn read_cstring(bytes: &[u8], cursor: &mut usize, label: &str) -> Result<String> {
    if *cursor > bytes.len() {
        return Err(Error::State(format!("{label} offset overflowed blob")));
    }
    let rest = bytes
        .get(*cursor..)
        .ok_or_else(|| Error::State(format!("{label} offset overflowed blob")))?;
    let end = rest
        .iter()
        .position(|byte| *byte == 0)
        .ok_or_else(|| Error::State(format!("{label} was missing a terminating NUL")))?;
    let value = String::from_utf8_lossy(&rest[..end]).into_owned();
    *cursor += end + 1;
    Ok(value)
}

#[cfg_attr(not(test), allow(dead_code))]
fn export_kind_name(flags: u64) -> &'static str {
    const EXPORT_SYMBOL_FLAGS_KIND_MASK: u64 = 0x03;
    const EXPORT_SYMBOL_FLAGS_KIND_REGULAR: u64 = 0x00;
    const EXPORT_SYMBOL_FLAGS_KIND_THREAD_LOCAL: u64 = 0x01;
    const EXPORT_SYMBOL_FLAGS_KIND_ABSOLUTE: u64 = 0x02;

    match flags & EXPORT_SYMBOL_FLAGS_KIND_MASK {
        EXPORT_SYMBOL_FLAGS_KIND_REGULAR => "regular",
        EXPORT_SYMBOL_FLAGS_KIND_THREAD_LOCAL => "thread-local",
        EXPORT_SYMBOL_FLAGS_KIND_ABSOLUTE => "absolute",
        _ => "unknown",
    }
}

#[cfg_attr(not(test), allow(dead_code))]
fn decode_exports_trie(module_base: usize, bytes: &[u8]) -> Result<Vec<ImageExportsTrieEntry>> {
    const EXPORT_SYMBOL_FLAGS_KIND_MASK: u64 = 0x03;
    const EXPORT_SYMBOL_FLAGS_KIND_ABSOLUTE: u64 = 0x02;
    const EXPORT_SYMBOL_FLAGS_WEAK_DEFINITION: u64 = 0x04;
    const EXPORT_SYMBOL_FLAGS_REEXPORT: u64 = 0x08;
    const EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER: u64 = 0x10;

    if bytes.is_empty() {
        return Ok(Vec::new());
    }

    let mut entries = Vec::new();
    let mut stack = vec![(String::new(), 0usize)];
    let mut seen = HashSet::new();

    while let Some((prefix, node_offset)) = stack.pop() {
        if node_offset >= bytes.len() {
            return Err(Error::State(format!(
                "LC_DYLD_EXPORTS_TRIE child offset 0x{node_offset:x} was outside the blob"
            )));
        }
        if !seen.insert(node_offset) {
            continue;
        }

        let mut cursor = node_offset;
        let terminal_size = read_uleb128(bytes, &mut cursor, "LC_DYLD_EXPORTS_TRIE terminal size")? as usize;
        let terminal_end = cursor
            .checked_add(terminal_size)
            .ok_or_else(|| Error::State("LC_DYLD_EXPORTS_TRIE terminal range overflowed".into()))?;
        if terminal_end > bytes.len() {
            return Err(Error::State(format!(
                "LC_DYLD_EXPORTS_TRIE terminal at 0x{node_offset:x} overflowed the blob"
            )));
        }

        if terminal_size != 0 {
            let mut terminal_cursor = cursor;
            let flags = read_uleb128(bytes, &mut terminal_cursor, "LC_DYLD_EXPORTS_TRIE flags")?;
            let is_weak_definition = (flags & EXPORT_SYMBOL_FLAGS_WEAK_DEFINITION) != 0;
            let is_reexport = (flags & EXPORT_SYMBOL_FLAGS_REEXPORT) != 0;
            let is_stub_and_resolver = (flags & EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER) != 0;
            let kind = export_kind_name(flags).to_string();

            let mut address = None;
            let mut offset = None;
            let mut other = None;
            let mut import_name = None;

            if is_reexport {
                let ordinal = read_uleb128(
                    bytes,
                    &mut terminal_cursor,
                    "LC_DYLD_EXPORTS_TRIE reexport ordinal",
                )?;
                let import = read_cstring(
                    bytes,
                    &mut terminal_cursor,
                    "LC_DYLD_EXPORTS_TRIE reexport import name",
                )?;
                other = Some(ordinal);
                import_name = Some(if import.is_empty() { prefix.clone() } else { import });
            } else {
                let value = read_uleb128(bytes, &mut terminal_cursor, "LC_DYLD_EXPORTS_TRIE address")?;
                offset = Some(value);
                address = Some(if (flags & EXPORT_SYMBOL_FLAGS_KIND_MASK) == EXPORT_SYMBOL_FLAGS_KIND_ABSOLUTE {
                    usize::try_from(value).map_err(|_| {
                        Error::State("LC_DYLD_EXPORTS_TRIE absolute export exceeded address space".into())
                    })?
                } else {
                    checked_add_usize(module_base, value, "exports trie symbol")?
                });
                if is_stub_and_resolver {
                    other = Some(read_uleb128(
                        bytes,
                        &mut terminal_cursor,
                        "LC_DYLD_EXPORTS_TRIE resolver offset",
                    )?);
                }
            }

            if terminal_cursor > terminal_end {
                return Err(Error::State(format!(
                    "LC_DYLD_EXPORTS_TRIE terminal for `{prefix}` overflowed its node"
                )));
            }

            entries.push(ImageExportsTrieEntry {
                name: prefix.clone(),
                flags,
                kind,
                address,
                offset,
                other,
                import_name,
                is_weak_definition,
                is_reexport,
                is_stub_and_resolver,
            });
        }

        cursor = terminal_end;
        let child_count = *bytes
            .get(cursor)
            .ok_or_else(|| Error::State(format!(
                "LC_DYLD_EXPORTS_TRIE node at 0x{node_offset:x} was truncated before child count"
            )))? as usize;
        cursor += 1;

        let mut children = Vec::with_capacity(child_count);
        for index in 0..child_count {
            let suffix = read_cstring(
                bytes,
                &mut cursor,
                &format!("LC_DYLD_EXPORTS_TRIE child name #{index}"),
            )?;
            let child_offset = read_uleb128(
                bytes,
                &mut cursor,
                &format!("LC_DYLD_EXPORTS_TRIE child offset #{index}"),
            )? as usize;
            if child_offset >= bytes.len() {
                return Err(Error::State(format!(
                    "LC_DYLD_EXPORTS_TRIE child offset 0x{child_offset:x} was outside the blob"
                )));
            }
            children.push((suffix, child_offset));
        }

        for (suffix, child_offset) in children.into_iter().rev() {
            let mut child_name = prefix.clone();
            child_name.push_str(&suffix);
            stack.push((child_name, child_offset));
        }
    }

    entries.sort_by(|left, right| left.name.cmp(&right.name).then(left.flags.cmp(&right.flags)));
    Ok(entries)
}

#[cfg(any(target_os = "ios", target_os = "macos"))]
mod platform {
    use common::{Error, Result};

    use super::{checked_add_usize, decode_exports_trie};
    use crate::{enumerate_images, image_name_matches, ImageExportsTrie, ImageInfo};

    const LC_SEGMENT_64: u32 = 0x19;
    const LC_DYLD_EXPORTS_TRIE: u32 = 0x34;
    const LC_DYLD_EXPORTS_TRIE_ALT: u32 = 0x33;
    const LC_REQ_DYLD: u32 = 0x8000_0000;
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

    pub fn image_exports_trie_support_available() -> bool {
        true
    }

    pub fn find_image_exports_trie(module_name: &str) -> Result<Option<ImageExportsTrie>> {
        let trimmed = module_name.trim();
        if trimmed.is_empty() {
            return Err(Error::InvalidArgument(
                "module name must not be empty; use `native.exportsTrie <module>`".into(),
            ));
        }

        let Some(image) = enumerate_images()?
            .into_iter()
            .find(|image| image_name_matches(trimmed, &image.name))
        else {
            return Ok(None);
        };

        find_exports_trie_in_image(&image)
    }

    fn find_exports_trie_in_image(image: &ImageInfo) -> Result<Option<ImageExportsTrie>> {
        let header = image.base as *const MachHeader64;
        if header.is_null() {
            return Ok(None);
        }

        let header = unsafe { &*header };
        if header.magic != MH_MAGIC_64 {
            return Ok(None);
        }

        let mut linkedit_segment = None;
        let mut exports_trie = None;
        let mut command_ptr = unsafe { header_ptr_after_header(header) };
        for _ in 0..header.ncmds {
            let load = unsafe { &*(command_ptr as *const LoadCommand) };
            let normalized_cmd = load.cmd & !LC_REQ_DYLD;
            match normalized_cmd {
                LC_SEGMENT_64 => {
                    let segment = unsafe { &*(command_ptr as *const SegmentCommand64) };
                    if segment_name(segment) == "__LINKEDIT" {
                        linkedit_segment = Some(segment);
                    }
                }
                cmd if cmd == LC_DYLD_EXPORTS_TRIE || cmd == LC_DYLD_EXPORTS_TRIE_ALT => {
                    exports_trie = Some(unsafe { &*(command_ptr as *const LinkeditDataCommand) });
                }
                _ => {}
            }

            let command_size = load.cmdsize as usize;
            if command_size == 0 {
                break;
            }
            command_ptr = unsafe { command_ptr.add(command_size) };
        }

        let (Some(linkedit), Some(command)) = (linkedit_segment, exports_trie) else {
            return Ok(None);
        };

        let linkedit_base = compute_linkedit_base(image, linkedit)?;
        let data_address = checked_add_usize(linkedit_base, command.dataoff as u64, "LC_DYLD_EXPORTS_TRIE blob")?;
        let bytes = if command.datasize == 0 {
            &[][..]
        } else {
            unsafe { std::slice::from_raw_parts(data_address as *const u8, command.datasize as usize) }
        };

        Ok(Some(ImageExportsTrie {
            module_name: image.name.clone(),
            module_base: image.base,
            dataoff: command.dataoff,
            datasize: command.datasize,
            linkedit_base,
            data_address,
            entries: decode_exports_trie(image.base, bytes)?,
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

    use crate::ImageExportsTrie;

    pub fn image_exports_trie_support_available() -> bool {
        false
    }

    pub fn find_image_exports_trie(module_name: &str) -> Result<Option<ImageExportsTrie>> {
        if module_name.trim().is_empty() {
            return Err(Error::InvalidArgument(
                "module name must not be empty; use `native.exportsTrie <module>`".into(),
            ));
        }

        Err(Error::Unsupported(
            "Mach-O exports-trie enumeration is currently only available on Apple targets".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::{decode_exports_trie, export_kind_name, find_image_exports_trie};

    fn encode_uleb128(mut value: u64) -> Vec<u8> {
        let mut bytes = Vec::new();
        loop {
            let mut byte = (value & 0x7f) as u8;
            value >>= 7;
            if value != 0 {
                byte |= 0x80;
            }
            bytes.push(byte);
            if value == 0 {
                break;
            }
        }
        bytes
    }

    fn encode_leaf(terminal_payload: &[u8]) -> Vec<u8> {
        let mut node = encode_uleb128(terminal_payload.len() as u64);
        node.extend_from_slice(terminal_payload);
        node.push(0);
        node
    }

    fn build_flat_trie(children: Vec<(&str, Vec<u8>)>) -> Vec<u8> {
        let root_len = 2 + children.iter().map(|(name, _)| name.len() + 2).sum::<usize>();
        assert!(root_len < 0x80, "test trie root must use 1-byte offsets");

        let mut offsets = Vec::with_capacity(children.len());
        let mut next_offset = root_len;
        for (_, node) in &children {
            assert!(next_offset < 0x80, "test trie child offset must fit in 1 byte");
            offsets.push(next_offset as u8);
            next_offset += node.len();
        }

        let mut bytes = vec![0, children.len() as u8];
        for ((name, _), offset) in children.iter().zip(offsets.iter()) {
            bytes.extend_from_slice(name.as_bytes());
            bytes.push(0);
            bytes.push(*offset);
        }
        for (_, node) in children {
            bytes.extend_from_slice(&node);
        }
        bytes
    }

    #[test]
    fn decodes_exports_trie_entries() {
        let foo = encode_leaf(&[0x00, 0x20]);
        let bar = encode_leaf(&[0x08, 0x02, b'q', b'u', b'x', 0x00]);
        let baz = encode_leaf(&[0x10, 0x30, 0x40]);
        let abs = encode_leaf(&[0x02, 0x55]);
        let trie = build_flat_trie(vec![("foo", foo), ("bar", bar), ("baz", baz), ("abs", abs)]);

        let entries = decode_exports_trie(0x1000, &trie).expect("decode");
        assert_eq!(entries.len(), 4);

        let abs = entries.iter().find(|entry| entry.name == "abs").expect("abs entry");
        assert_eq!(abs.kind, "absolute");
        assert_eq!(abs.offset, Some(0x55));
        assert_eq!(abs.address, Some(0x55));

        let bar = entries.iter().find(|entry| entry.name == "bar").expect("bar entry");
        assert!(bar.is_reexport);
        assert_eq!(bar.other, Some(2));
        assert_eq!(bar.import_name.as_deref(), Some("qux"));
        assert_eq!(bar.address, None);

        let baz = entries.iter().find(|entry| entry.name == "baz").expect("baz entry");
        assert!(baz.is_stub_and_resolver);
        assert_eq!(baz.offset, Some(0x30));
        assert_eq!(baz.address, Some(0x1030));
        assert_eq!(baz.other, Some(0x40));

        let foo = entries.iter().find(|entry| entry.name == "foo").expect("foo entry");
        assert_eq!(foo.kind, "regular");
        assert_eq!(foo.offset, Some(0x20));
        assert_eq!(foo.address, Some(0x1020));
    }

    #[test]
    fn substitutes_symbol_name_for_empty_reexport_import_name() {
        let same = encode_leaf(&[0x08, 0x01, 0x00]);
        let trie = build_flat_trie(vec![("same", same)]);

        let entries = decode_exports_trie(0x2000, &trie).expect("decode");
        assert_eq!(entries[0].import_name.as_deref(), Some("same"));
    }

    #[test]
    fn rejects_truncated_exports_trie() {
        let err = decode_exports_trie(0x1000, &[0x01, 0x00]).expect_err("truncated trie should fail");
        assert!(err.to_string().contains("LC_DYLD_EXPORTS_TRIE"));
    }

    #[test]
    fn reports_known_export_kinds() {
        assert_eq!(export_kind_name(0), "regular");
        assert_eq!(export_kind_name(1), "thread-local");
        assert_eq!(export_kind_name(2), "absolute");
    }

    #[cfg(not(any(target_os = "ios", target_os = "macos")))]
    #[test]
    fn non_apple_exports_trie_reports_unsupported() {
        let err =
            find_image_exports_trie("libsystem_malloc.dylib").expect_err("non-apple platforms should be unsupported");
        assert!(err.to_string().contains("Apple targets"));
    }
}
