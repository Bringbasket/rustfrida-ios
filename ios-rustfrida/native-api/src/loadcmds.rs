use common::Result;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageLoadCommand {
    pub module_name: String,
    pub module_base: usize,
    pub index: usize,
    pub command: u32,
    pub command_size: u32,
    pub command_offset: usize,
    pub command_name: String,
    pub detail: Option<String>,
}

pub fn image_load_command_support_available() -> bool {
    platform::image_load_command_support_available()
}

pub fn find_image_load_commands(module_name: &str) -> Result<Vec<ImageLoadCommand>> {
    platform::find_image_load_commands(module_name)
}

#[cfg(any(target_os = "ios", target_os = "macos"))]
mod platform {
    use common::{Error, Result};
    use std::mem::size_of;
    use std::slice;

    use crate::{enumerate_images, image_name_matches, ImageInfo, ImageLoadCommand};

    const LC_SEGMENT_64: u32 = 0x19;
    const LC_SYMTAB: u32 = 0x2;
    const LC_DYSYMTAB: u32 = 0xb;
    const LC_LOAD_DYLIB: u32 = 0xc;
    const LC_ID_DYLIB: u32 = 0xd;
    const LC_LOAD_DYLINKER: u32 = 0xe;
    const LC_ID_DYLINKER: u32 = 0xf;
    const LC_LOAD_WEAK_DYLIB: u32 = 0x18;
    const LC_UUID: u32 = 0x1b;
    const LC_RPATH: u32 = 0x1c;
    const LC_REEXPORT_DYLIB: u32 = 0x1f;
    const LC_DYLD_INFO: u32 = 0x22;
    const LC_DYLD_INFO_ONLY: u32 = 0x23;
    const LC_LOAD_UPWARD_DYLIB: u32 = 0x24;
    const LC_VERSION_MIN_MACOSX: u32 = 0x25;
    const LC_VERSION_MIN_IPHONEOS: u32 = 0x26;
    const LC_MAIN: u32 = 0x29;
    const LC_SOURCE_VERSION: u32 = 0x2b;
    const LC_ENCRYPTION_INFO_64: u32 = 0x2d;
    const LC_VERSION_MIN_TVOS: u32 = 0x30;
    const LC_VERSION_MIN_WATCHOS: u32 = 0x31;
    const LC_BUILD_VERSION: u32 = 0x33;
    const LC_DYLD_EXPORTS_TRIE: u32 = 0x34;
    const LC_DYLD_CHAINED_FIXUPS: u32 = 0x35;
    const MH_MAGIC_64: u32 = 0xfeedfacf;
    const LC_REQ_DYLD: u32 = 0x8000_0000;

    #[derive(Clone, Copy)]
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

    #[derive(Clone, Copy)]
    #[repr(C)]
    struct LoadCommand {
        cmd: u32,
        cmdsize: u32,
    }

    #[derive(Clone, Copy)]
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

    #[derive(Clone, Copy)]
    #[repr(C)]
    struct SymtabCommand {
        cmd: u32,
        cmdsize: u32,
        symoff: u32,
        nsyms: u32,
        stroff: u32,
        strsize: u32,
    }

    #[derive(Clone, Copy)]
    #[repr(C)]
    struct DysymtabCommand {
        cmd: u32,
        cmdsize: u32,
        ilocalsym: u32,
        nlocalsym: u32,
        iextdefsym: u32,
        nextdefsym: u32,
        iundefsym: u32,
        nundefsym: u32,
        tocoff: u32,
        ntoc: u32,
        modtaboff: u32,
        nmodtab: u32,
        extrefsymoff: u32,
        nextrefsyms: u32,
        indirectsymoff: u32,
        nindirectsyms: u32,
        extreloff: u32,
        nextrel: u32,
        locreloff: u32,
        nlocrel: u32,
    }

    #[derive(Clone, Copy)]
    #[repr(C)]
    struct Dylib {
        name: u32,
        timestamp: u32,
        current_version: u32,
        compatibility_version: u32,
    }

    #[derive(Clone, Copy)]
    #[repr(C)]
    struct DylibCommand {
        cmd: u32,
        cmdsize: u32,
        dylib: Dylib,
    }

    #[derive(Clone, Copy)]
    #[repr(C)]
    struct DylinkerCommand {
        cmd: u32,
        cmdsize: u32,
        name: u32,
    }

    #[derive(Clone, Copy)]
    #[repr(C)]
    struct UuidCommand {
        cmd: u32,
        cmdsize: u32,
        uuid: [u8; 16],
    }

    #[derive(Clone, Copy)]
    #[repr(C)]
    struct RpathCommand {
        cmd: u32,
        cmdsize: u32,
        path: u32,
    }

    #[derive(Clone, Copy)]
    #[repr(C)]
    struct EntryPointCommand {
        cmd: u32,
        cmdsize: u32,
        entryoff: u64,
        stacksize: u64,
    }

    #[derive(Clone, Copy)]
    #[repr(C)]
    struct EncryptionInfoCommand64 {
        cmd: u32,
        cmdsize: u32,
        cryptoff: u32,
        cryptsize: u32,
        cryptid: u32,
        pad: u32,
    }

    #[derive(Clone, Copy)]
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

    #[derive(Clone, Copy)]
    #[repr(C)]
    struct LinkeditDataCommand {
        cmd: u32,
        cmdsize: u32,
        dataoff: u32,
        datasize: u32,
    }

    #[derive(Clone, Copy)]
    #[repr(C)]
    struct VersionMinCommand {
        cmd: u32,
        cmdsize: u32,
        version: u32,
        sdk: u32,
    }

    #[derive(Clone, Copy)]
    #[repr(C)]
    struct SourceVersionCommand {
        cmd: u32,
        cmdsize: u32,
        version: u64,
    }

    pub fn image_load_command_support_available() -> bool {
        true
    }

    pub fn find_image_load_commands(module_name: &str) -> Result<Vec<ImageLoadCommand>> {
        let trimmed = module_name.trim();
        if trimmed.is_empty() {
            return Err(Error::InvalidArgument(
                "module name must not be empty; use `native.loadcmds <module>`".into(),
            ));
        }

        let Some(image) = enumerate_images()?
            .into_iter()
            .find(|image| image_name_matches(trimmed, &image.name))
        else {
            return Ok(Vec::new());
        };

        collect_load_commands_in_image(&image)
    }

    fn collect_load_commands_in_image(image: &ImageInfo) -> Result<Vec<ImageLoadCommand>> {
        let header = image.base as *const MachHeader64;
        if header.is_null() {
            return Ok(Vec::new());
        }

        let header = unsafe { &*header };
        if header.magic != MH_MAGIC_64 {
            return Ok(Vec::new());
        }

        let header_size = std::mem::size_of::<MachHeader64>();
        let commands_size = header.sizeofcmds as usize;
        let commands_limit = header_size.saturating_add(commands_size);
        let mut commands = Vec::new();
        let mut command_ptr = unsafe { header_ptr_after_header(header) };
        let mut command_offset = header_size;

        for index in 0..header.ncmds as usize {
            if command_offset.saturating_add(size_of::<LoadCommand>()) > commands_limit {
                break;
            }

            let load = unsafe { read_unaligned::<LoadCommand>(command_ptr) };
            let command_size = load.cmdsize as usize;
            if command_size == 0 || command_offset.saturating_add(command_size) > commands_limit {
                break;
            }

            let command_bytes = unsafe { slice::from_raw_parts(command_ptr, command_size) };

            commands.push(ImageLoadCommand {
                module_name: image.name.clone(),
                module_base: image.base,
                index,
                command: load.cmd,
                command_size: load.cmdsize,
                command_offset,
                command_name: command_name(load.cmd).to_string(),
                detail: parse_command_detail(command_bytes),
            });

            command_ptr = unsafe { command_ptr.add(command_size) };
            command_offset += command_size;
        }

        Ok(commands)
    }

    unsafe fn header_ptr_after_header(header: &MachHeader64) -> *const u8 {
        (header as *const MachHeader64).add(1) as *const u8
    }

    unsafe fn read_unaligned<T: Copy>(ptr: *const u8) -> T {
        std::ptr::read_unaligned(ptr as *const T)
    }

    fn read_struct<T: Copy>(bytes: &[u8]) -> Option<T> {
        if bytes.len() < size_of::<T>() {
            return None;
        }
        Some(unsafe { read_unaligned(bytes.as_ptr()) })
    }

    fn parse_command_detail(bytes: &[u8]) -> Option<String> {
        let load = read_struct::<LoadCommand>(bytes)?;
        match load.cmd & !LC_REQ_DYLD {
            LC_SEGMENT_64 => {
                let segment = read_struct::<SegmentCommand64>(bytes)?;
                Some(format!(
                    "segname={} vmaddr=0x{:x} vmsize=0x{:x} fileoff=0x{:x} filesize=0x{:x} nsects={} maxprot={} initprot={}",
                    fixed_string(&segment.segname),
                    segment.vmaddr,
                    segment.vmsize,
                    segment.fileoff,
                    segment.filesize,
                    segment.nsects,
                    segment.maxprot,
                    segment.initprot
                ))
            }
            LC_SYMTAB => {
                let symtab = read_struct::<SymtabCommand>(bytes)?;
                Some(format!(
                    "symoff=0x{:x} nsyms={} stroff=0x{:x} strsize=0x{:x}",
                    symtab.symoff, symtab.nsyms, symtab.stroff, symtab.strsize
                ))
            }
            LC_DYSYMTAB => {
                let dysymtab = read_struct::<DysymtabCommand>(bytes)?;
                Some(format!(
                    "locals={}/{} extdefs={}/{} undefs={}/{} indirect=0x{:x}/{}",
                    dysymtab.ilocalsym,
                    dysymtab.nlocalsym,
                    dysymtab.iextdefsym,
                    dysymtab.nextdefsym,
                    dysymtab.iundefsym,
                    dysymtab.nundefsym,
                    dysymtab.indirectsymoff,
                    dysymtab.nindirectsyms
                ))
            }
            LC_LOAD_DYLIB | LC_ID_DYLIB | LC_LOAD_WEAK_DYLIB | LC_REEXPORT_DYLIB | LC_LOAD_UPWARD_DYLIB => {
                let dylib = read_struct::<DylibCommand>(bytes)?;
                let name = read_command_string(bytes, dylib.dylib.name).unwrap_or_default();
                Some(format!(
                    "name={} current={} compat={} timestamp={}",
                    name,
                    format_packed_version(dylib.dylib.current_version),
                    format_packed_version(dylib.dylib.compatibility_version),
                    dylib.dylib.timestamp
                ))
            }
            LC_LOAD_DYLINKER | LC_ID_DYLINKER => {
                let dylinker = read_struct::<DylinkerCommand>(bytes)?;
                read_command_string(bytes, dylinker.name).map(|name| format!("name={name}"))
            }
            LC_UUID => {
                let uuid = read_struct::<UuidCommand>(bytes)?;
                Some(format!("uuid={}", format_uuid(&uuid.uuid)))
            }
            LC_RPATH => {
                let rpath = read_struct::<RpathCommand>(bytes)?;
                read_command_string(bytes, rpath.path).map(|path| format!("path={path}"))
            }
            LC_DYLD_INFO | LC_DYLD_INFO_ONLY => {
                let info = read_struct::<DyldInfoCommand>(bytes)?;
                Some(format!(
                    "rebase=0x{:x}/0x{:x} bind=0x{:x}/0x{:x} weak=0x{:x}/0x{:x} lazy=0x{:x}/0x{:x} export=0x{:x}/0x{:x}",
                    info.rebase_off,
                    info.rebase_size,
                    info.bind_off,
                    info.bind_size,
                    info.weak_bind_off,
                    info.weak_bind_size,
                    info.lazy_bind_off,
                    info.lazy_bind_size,
                    info.export_off,
                    info.export_size
                ))
            }
            LC_VERSION_MIN_MACOSX | LC_VERSION_MIN_IPHONEOS | LC_VERSION_MIN_TVOS | LC_VERSION_MIN_WATCHOS => {
                let version = read_struct::<VersionMinCommand>(bytes)?;
                Some(format!(
                    "version={} sdk={}",
                    format_packed_version(version.version),
                    format_packed_version(version.sdk)
                ))
            }
            LC_MAIN => {
                let entry = read_struct::<EntryPointCommand>(bytes)?;
                Some(format!(
                    "entryoff=0x{:x} stacksize=0x{:x}",
                    entry.entryoff, entry.stacksize
                ))
            }
            LC_SOURCE_VERSION => {
                let version = read_struct::<SourceVersionCommand>(bytes)?;
                Some(format!("version={}", format_source_version(version.version)))
            }
            LC_ENCRYPTION_INFO_64 => {
                let encryption = read_struct::<EncryptionInfoCommand64>(bytes)?;
                Some(format!(
                    "cryptoff=0x{:x} cryptsize=0x{:x} cryptid={}",
                    encryption.cryptoff, encryption.cryptsize, encryption.cryptid
                ))
            }
            LC_BUILD_VERSION => {
                let build = read_struct::<BuildVersionCommand>(bytes)?;
                let tools = parse_build_tools(bytes, build.ntools);
                let tools = if tools.is_empty() {
                    "none".to_string()
                } else {
                    tools.join(",")
                };
                Some(format!(
                    "platform={} minos={} sdk={} tools={}",
                    platform_name(build.platform),
                    format_packed_version(build.minos),
                    format_packed_version(build.sdk),
                    tools
                ))
            }
            LC_DYLD_EXPORTS_TRIE | LC_DYLD_CHAINED_FIXUPS => {
                let linkedit = read_struct::<LinkeditDataCommand>(bytes)?;
                Some(format!(
                    "dataoff=0x{:x} datasize=0x{:x}",
                    linkedit.dataoff, linkedit.datasize
                ))
            }
            _ => None,
        }
    }

    #[derive(Clone, Copy)]
    #[repr(C)]
    struct DyldInfoCommand {
        cmd: u32,
        cmdsize: u32,
        rebase_off: u32,
        rebase_size: u32,
        bind_off: u32,
        bind_size: u32,
        weak_bind_off: u32,
        weak_bind_size: u32,
        lazy_bind_off: u32,
        lazy_bind_size: u32,
        export_off: u32,
        export_size: u32,
    }

    fn read_command_string(bytes: &[u8], offset: u32) -> Option<String> {
        let start = offset as usize;
        if start >= bytes.len() {
            return None;
        }
        let tail = &bytes[start..];
        let end = tail.iter().position(|byte| *byte == 0).unwrap_or(tail.len());
        Some(String::from_utf8_lossy(&tail[..end]).into_owned())
    }

    fn fixed_string(bytes: &[u8; 16]) -> &str {
        let length = bytes.iter().position(|byte| *byte == 0).unwrap_or(bytes.len());
        std::str::from_utf8(&bytes[..length]).unwrap_or("")
    }

    fn format_uuid(bytes: &[u8; 16]) -> String {
        format!(
            "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            bytes[0],
            bytes[1],
            bytes[2],
            bytes[3],
            bytes[4],
            bytes[5],
            bytes[6],
            bytes[7],
            bytes[8],
            bytes[9],
            bytes[10],
            bytes[11],
            bytes[12],
            bytes[13],
            bytes[14],
            bytes[15]
        )
    }

    fn format_packed_version(version: u32) -> String {
        format!(
            "{}.{}.{}",
            (version >> 16) & 0xffff,
            (version >> 8) & 0xff,
            version & 0xff
        )
    }

    fn format_source_version(version: u64) -> String {
        format!(
            "{}.{}.{}.{}.{}",
            (version >> 40) & 0x00ff_ffff,
            (version >> 30) & 0x03ff,
            (version >> 20) & 0x03ff,
            (version >> 10) & 0x03ff,
            version & 0x03ff
        )
    }

    fn parse_build_tools(bytes: &[u8], count: u32) -> Vec<String> {
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
            tools.push(format!(
                "{}:{}",
                build_tool_name(tool.tool),
                format_packed_version(tool.version)
            ));
        }
        tools
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

    fn command_name(cmd: u32) -> &'static str {
        match cmd & !LC_REQ_DYLD {
            0x1 => "LC_SEGMENT",
            0x2 => "LC_SYMTAB",
            0x4 => "LC_THREAD",
            0x5 => "LC_UNIXTHREAD",
            0x6 => "LC_LOADFVMLIB",
            0x7 => "LC_IDFVMLIB",
            0x8 => "LC_IDENT",
            0x9 => "LC_FVMFILE",
            0xa => "LC_PREPAGE",
            0xb => "LC_DYSYMTAB",
            0xc => "LC_LOAD_DYLIB",
            0xd => "LC_ID_DYLIB",
            0xe => "LC_LOAD_DYLINKER",
            0xf => "LC_ID_DYLINKER",
            0x10 => "LC_PREBOUND_DYLIB",
            0x11 => "LC_ROUTINES",
            0x12 => "LC_SUB_FRAMEWORK",
            0x13 => "LC_SUB_UMBRELLA",
            0x14 => "LC_SUB_CLIENT",
            0x15 => "LC_SUB_LIBRARY",
            0x16 => "LC_TWOLEVEL_HINTS",
            0x17 => "LC_PREBIND_CKSUM",
            0x18 => "LC_LOAD_WEAK_DYLIB",
            0x19 => "LC_SEGMENT_64",
            0x1a => "LC_ROUTINES_64",
            0x1b => "LC_UUID",
            0x1c => "LC_RPATH",
            0x1d => "LC_CODE_SIGNATURE",
            0x1e => "LC_SEGMENT_SPLIT_INFO",
            0x1f => "LC_REEXPORT_DYLIB",
            0x20 => "LC_LAZY_LOAD_DYLIB",
            0x21 => "LC_ENCRYPTION_INFO",
            0x22 => "LC_DYLD_INFO",
            0x23 => "LC_DYLD_INFO_ONLY",
            0x24 => "LC_LOAD_UPWARD_DYLIB",
            0x25 => "LC_VERSION_MIN_MACOSX",
            0x26 => "LC_VERSION_MIN_IPHONEOS",
            0x27 => "LC_FUNCTION_STARTS",
            0x28 => "LC_DYLD_ENVIRONMENT",
            0x29 => "LC_MAIN",
            0x2a => "LC_DATA_IN_CODE",
            0x2b => "LC_SOURCE_VERSION",
            0x2c => "LC_DYLIB_CODE_SIGN_DRS",
            0x2d => "LC_ENCRYPTION_INFO_64",
            0x2e => "LC_LINKER_OPTION",
            0x2f => "LC_LINKER_OPTIMIZATION_HINT",
            0x30 => "LC_VERSION_MIN_TVOS",
            0x31 => "LC_VERSION_MIN_WATCHOS",
            0x32 => "LC_NOTE",
            0x33 => "LC_BUILD_VERSION",
            0x34 => "LC_DYLD_EXPORTS_TRIE",
            0x35 => "LC_DYLD_CHAINED_FIXUPS",
            0x36 => "LC_FILESET_ENTRY",
            _ => "LC_UNKNOWN",
        }
    }
}

#[cfg(not(any(target_os = "ios", target_os = "macos")))]
mod platform {
    use common::{Error, Result};

    use crate::ImageLoadCommand;

    pub fn image_load_command_support_available() -> bool {
        false
    }

    pub fn find_image_load_commands(module_name: &str) -> Result<Vec<ImageLoadCommand>> {
        if module_name.trim().is_empty() {
            return Err(Error::InvalidArgument(
                "module name must not be empty; use `native.loadcmds <module>`".into(),
            ));
        }

        Err(Error::Unsupported(
            "Mach-O load-command enumeration is currently only available on Apple targets".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::find_image_load_commands;

    #[cfg(not(any(target_os = "ios", target_os = "macos")))]
    #[test]
    fn non_apple_load_command_enumeration_reports_unsupported() {
        let err = find_image_load_commands("malloc").expect_err("non-apple platforms should be unsupported");
        assert!(err.to_string().contains("Apple targets"));
    }
}
