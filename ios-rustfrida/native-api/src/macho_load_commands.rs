#![cfg_attr(not(any(target_os = "ios", target_os = "macos")), allow(dead_code))]

pub(crate) const LC_REQ_DYLD: u32 = 0x8000_0000;

const fn required_by_dyld(command: u32) -> u32 {
    command | LC_REQ_DYLD
}

pub(crate) const fn load_command_base(command: u32) -> u32 {
    command & !LC_REQ_DYLD
}

pub(crate) const fn load_command_requires_dyld(command: u32) -> bool {
    command & LC_REQ_DYLD != 0
}

pub(crate) const LC_SYMTAB: u32 = 0x02;
pub(crate) const LC_DYSYMTAB: u32 = 0x0b;
pub(crate) const LC_LOAD_DYLIB: u32 = 0x0c;
pub(crate) const LC_ID_DYLIB: u32 = 0x0d;
pub(crate) const LC_LOAD_DYLINKER: u32 = 0x0e;
pub(crate) const LC_ID_DYLINKER: u32 = 0x0f;
pub(crate) const LC_LOAD_WEAK_DYLIB: u32 = required_by_dyld(0x18);
pub(crate) const LC_SEGMENT_64: u32 = 0x19;
pub(crate) const LC_UUID: u32 = 0x1b;
pub(crate) const LC_RPATH: u32 = required_by_dyld(0x1c);
pub(crate) const LC_CODE_SIGNATURE: u32 = 0x1d;
pub(crate) const LC_REEXPORT_DYLIB: u32 = required_by_dyld(0x1f);
pub(crate) const LC_LAZY_LOAD_DYLIB: u32 = 0x20;
pub(crate) const LC_DYLD_INFO: u32 = 0x22;
pub(crate) const LC_DYLD_INFO_ONLY: u32 = required_by_dyld(0x22);
pub(crate) const LC_LOAD_UPWARD_DYLIB: u32 = required_by_dyld(0x23);
pub(crate) const LC_VERSION_MIN_MACOSX: u32 = 0x24;
pub(crate) const LC_VERSION_MIN_IPHONEOS: u32 = 0x25;
pub(crate) const LC_FUNCTION_STARTS: u32 = 0x26;
pub(crate) const LC_MAIN: u32 = required_by_dyld(0x28);
pub(crate) const LC_DATA_IN_CODE: u32 = 0x29;
pub(crate) const LC_SOURCE_VERSION: u32 = 0x2a;
pub(crate) const LC_ENCRYPTION_INFO_64: u32 = 0x2c;
pub(crate) const LC_VERSION_MIN_TVOS: u32 = 0x2f;
pub(crate) const LC_VERSION_MIN_WATCHOS: u32 = 0x30;
pub(crate) const LC_BUILD_VERSION: u32 = 0x32;
pub(crate) const LC_DYLD_EXPORTS_TRIE: u32 = required_by_dyld(0x33);
pub(crate) const LC_DYLD_CHAINED_FIXUPS: u32 = required_by_dyld(0x34);
pub(crate) const LC_FILESET_ENTRY: u32 = required_by_dyld(0x35);

pub(crate) fn load_command_name(command: u32) -> &'static str {
    if command == LC_FILESET_ENTRY {
        return "LC_FILESET_ENTRY";
    }

    match (load_command_base(command), load_command_requires_dyld(command)) {
        (0x01, false) => "LC_SEGMENT",
        (0x02, false) => "LC_SYMTAB",
        (0x04, false) => "LC_THREAD",
        (0x05, false) => "LC_UNIXTHREAD",
        (0x06, false) => "LC_LOADFVMLIB",
        (0x07, false) => "LC_IDFVMLIB",
        (0x08, false) => "LC_IDENT",
        (0x09, false) => "LC_FVMFILE",
        (0x0a, false) => "LC_PREPAGE",
        (0x0b, false) => "LC_DYSYMTAB",
        (0x0c, false) => "LC_LOAD_DYLIB",
        (0x0d, false) => "LC_ID_DYLIB",
        (0x0e, false) => "LC_LOAD_DYLINKER",
        (0x0f, false) => "LC_ID_DYLINKER",
        (0x10, false) => "LC_PREBOUND_DYLIB",
        (0x11, false) => "LC_ROUTINES",
        (0x12, false) => "LC_SUB_FRAMEWORK",
        (0x13, false) => "LC_SUB_UMBRELLA",
        (0x14, false) => "LC_SUB_CLIENT",
        (0x15, false) => "LC_SUB_LIBRARY",
        (0x16, false) => "LC_TWOLEVEL_HINTS",
        (0x17, false) => "LC_PREBIND_CKSUM",
        (0x18, true) => "LC_LOAD_WEAK_DYLIB",
        (0x19, false) => "LC_SEGMENT_64",
        (0x1a, false) => "LC_ROUTINES_64",
        (0x1b, false) => "LC_UUID",
        (0x1c, true) => "LC_RPATH",
        (0x1d, false) => "LC_CODE_SIGNATURE",
        (0x1e, false) => "LC_SEGMENT_SPLIT_INFO",
        (0x1f, true) => "LC_REEXPORT_DYLIB",
        (0x20, false) => "LC_LAZY_LOAD_DYLIB",
        (0x21, false) => "LC_ENCRYPTION_INFO",
        (0x22, false) => "LC_DYLD_INFO",
        (0x22, true) => "LC_DYLD_INFO_ONLY",
        (0x23, true) => "LC_LOAD_UPWARD_DYLIB",
        (0x24, false) => "LC_VERSION_MIN_MACOSX",
        (0x25, false) => "LC_VERSION_MIN_IPHONEOS",
        (0x26, false) => "LC_FUNCTION_STARTS",
        (0x27, false) => "LC_DYLD_ENVIRONMENT",
        (0x28, true) => "LC_MAIN",
        (0x29, false) => "LC_DATA_IN_CODE",
        (0x2a, false) => "LC_SOURCE_VERSION",
        (0x2b, false) => "LC_DYLIB_CODE_SIGN_DRS",
        (0x2c, false) => "LC_ENCRYPTION_INFO_64",
        (0x2d, false) => "LC_LINKER_OPTION",
        (0x2e, false) => "LC_LINKER_OPTIMIZATION_HINT",
        (0x2f, false) => "LC_VERSION_MIN_TVOS",
        (0x30, false) => "LC_VERSION_MIN_WATCHOS",
        (0x31, false) => "LC_NOTE",
        (0x32, false) => "LC_BUILD_VERSION",
        (0x33, true) => "LC_DYLD_EXPORTS_TRIE",
        (0x34, true) => "LC_DYLD_CHAINED_FIXUPS",
        (0x36, false) => "LC_ATOM_INFO",
        _ => "LC_UNKNOWN",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MH_MAGIC_64: u32 = 0xfeed_facf;
    const MACH_HEADER_64_SIZE: usize = 32;

    struct ParsedCommand<'a> {
        raw: u32,
        bytes: &'a [u8],
    }

    fn push_u32(bytes: &mut Vec<u8>, value: u32) {
        bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn push_u64(bytes: &mut Vec<u8>, value: u64) {
        bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn read_u32(bytes: &[u8], offset: usize) -> u32 {
        u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
    }

    fn read_u64(bytes: &[u8], offset: usize) -> u64 {
        u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
    }

    fn command(raw: u32, payload: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(8 + payload.len());
        push_u32(&mut bytes, raw);
        push_u32(&mut bytes, (8 + payload.len()) as u32);
        bytes.extend_from_slice(payload);
        bytes
    }

    fn synthetic_macho(commands: &[Vec<u8>]) -> Vec<u8> {
        let command_size = commands.iter().map(Vec::len).sum::<usize>();
        let mut bytes = Vec::with_capacity(MACH_HEADER_64_SIZE + command_size);
        push_u32(&mut bytes, MH_MAGIC_64);
        push_u32(&mut bytes, 0x0100_000c);
        push_u32(&mut bytes, 0);
        push_u32(&mut bytes, 2);
        push_u32(&mut bytes, commands.len() as u32);
        push_u32(&mut bytes, command_size as u32);
        push_u32(&mut bytes, 0);
        push_u32(&mut bytes, 0);
        commands.iter().for_each(|command| bytes.extend_from_slice(command));
        bytes
    }

    fn parse_commands(bytes: &[u8]) -> Vec<ParsedCommand<'_>> {
        assert_eq!(read_u32(bytes, 0), MH_MAGIC_64);
        let count = read_u32(bytes, 16) as usize;
        let command_region_size = read_u32(bytes, 20) as usize;
        let command_limit = MACH_HEADER_64_SIZE + command_region_size;
        assert!(command_limit <= bytes.len());

        let mut parsed = Vec::with_capacity(count);
        let mut offset = MACH_HEADER_64_SIZE;
        for _ in 0..count {
            assert!(offset + 8 <= command_limit);
            let command_size = read_u32(bytes, offset + 4) as usize;
            assert!(command_size >= 8 && offset + command_size <= command_limit);
            parsed.push(ParsedCommand {
                raw: read_u32(bytes, offset),
                bytes: &bytes[offset..offset + command_size],
            });
            offset += command_size;
        }
        assert_eq!(offset, command_limit);
        parsed
    }

    #[test]
    fn canonical_values_preserve_base_and_required_bit() {
        assert_eq!(LC_FUNCTION_STARTS, 0x26);
        assert_eq!(LC_SOURCE_VERSION, 0x2a);
        assert_eq!(LC_BUILD_VERSION, 0x32);
        assert_eq!(LC_MAIN, 0x8000_0028);
        assert_eq!(LC_DYLD_EXPORTS_TRIE, 0x8000_0033);
        assert_eq!(LC_DYLD_CHAINED_FIXUPS, 0x8000_0034);
        assert_eq!(load_command_base(LC_DYLD_INFO_ONLY), LC_DYLD_INFO);
        assert!(load_command_requires_dyld(LC_DYLD_INFO_ONLY));
        assert!(!load_command_requires_dyld(LC_DYLD_INFO));
    }

    #[test]
    fn synthetic_macho_parses_affected_commands_by_canonical_raw_value() {
        let mut entry = Vec::new();
        push_u64(&mut entry, 0x1234);
        push_u64(&mut entry, 0x4000);
        let mut source = Vec::new();
        push_u64(&mut source, 0x0000_0100_0800_3004);
        let mut build = Vec::new();
        for value in [7, 0x000d_0201, 0x0012_0300, 1, 1, 0x0010_0000] {
            push_u32(&mut build, value);
        }
        let mut function_starts = Vec::new();
        push_u32(&mut function_starts, 0x700);
        push_u32(&mut function_starts, 4);
        let mut exports = Vec::new();
        push_u32(&mut exports, 0x800);
        push_u32(&mut exports, 8);
        let mut chained = Vec::new();
        push_u32(&mut chained, 0x900);
        push_u32(&mut chained, 28);

        let image = synthetic_macho(&[
            command(LC_MAIN, &entry),
            command(LC_SOURCE_VERSION, &source),
            command(LC_BUILD_VERSION, &build),
            command(LC_FUNCTION_STARTS, &function_starts),
            command(LC_DYLD_EXPORTS_TRIE, &exports),
            command(LC_DYLD_CHAINED_FIXUPS, &chained),
        ]);
        let commands = parse_commands(&image);

        assert_eq!(
            commands.iter().map(|command| command.raw).collect::<Vec<_>>(),
            [
                LC_MAIN,
                LC_SOURCE_VERSION,
                LC_BUILD_VERSION,
                LC_FUNCTION_STARTS,
                LC_DYLD_EXPORTS_TRIE,
                LC_DYLD_CHAINED_FIXUPS,
            ]
        );
        assert_eq!(read_u64(commands[0].bytes, 8), 0x1234);
        assert_eq!(read_u64(commands[0].bytes, 16), 0x4000);
        assert_eq!(read_u64(commands[1].bytes, 8), 0x0000_0100_0800_3004);
        assert_eq!(read_u32(commands[2].bytes, 8), 7);
        assert_eq!(read_u32(commands[2].bytes, 20), 1);
        assert_eq!(read_u32(commands[3].bytes, 8), 0x700);
        assert_eq!(read_u32(commands[4].bytes, 8), 0x800);
        assert_eq!(read_u32(commands[5].bytes, 8), 0x900);
    }

    #[test]
    fn command_names_distinguish_required_raw_values_from_their_bases() {
        for (raw, base, name, base_name) in [
            (LC_LOAD_WEAK_DYLIB, 0x18, "LC_LOAD_WEAK_DYLIB", "LC_UNKNOWN"),
            (LC_RPATH, 0x1c, "LC_RPATH", "LC_UNKNOWN"),
            (LC_REEXPORT_DYLIB, 0x1f, "LC_REEXPORT_DYLIB", "LC_UNKNOWN"),
            (LC_DYLD_INFO_ONLY, 0x22, "LC_DYLD_INFO_ONLY", "LC_DYLD_INFO"),
            (LC_LOAD_UPWARD_DYLIB, 0x23, "LC_LOAD_UPWARD_DYLIB", "LC_UNKNOWN"),
            (LC_MAIN, 0x28, "LC_MAIN", "LC_UNKNOWN"),
            (LC_DYLD_EXPORTS_TRIE, 0x33, "LC_DYLD_EXPORTS_TRIE", "LC_UNKNOWN"),
            (LC_DYLD_CHAINED_FIXUPS, 0x34, "LC_DYLD_CHAINED_FIXUPS", "LC_UNKNOWN"),
            (LC_FILESET_ENTRY, 0x35, "LC_FILESET_ENTRY", "LC_UNKNOWN"),
        ] {
            assert_eq!(load_command_base(raw), base);
            assert!(load_command_requires_dyld(raw));
            assert_eq!(load_command_name(raw), name);
            assert_eq!(load_command_name(base), base_name);
        }
        assert_eq!(load_command_name(LC_DYLD_INFO), "LC_DYLD_INFO");
    }
}
