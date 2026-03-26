use common::Result;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SwiftSymbol {
    pub module_name: String,
    pub module_base: usize,
    pub symbol_name: String,
    pub demangled_name: Option<String>,
    pub address: usize,
    pub offset: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SwiftType {
    pub module_name: String,
    pub module_base: usize,
    pub type_name: String,
    pub source_symbol_name: String,
    pub source_demangled_name: Option<String>,
    pub source_kind: String,
    pub source_address: usize,
    pub source_offset: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SwiftProtocol {
    pub module_name: String,
    pub module_base: usize,
    pub protocol_name: String,
    pub source_symbol_name: String,
    pub source_demangled_name: Option<String>,
    pub source_kind: String,
    pub source_address: usize,
    pub source_offset: usize,
}

pub fn swift_support_available() -> bool {
    platform::swift_support_available()
}

pub fn swift_demangle_symbol(symbol_name: &str) -> Result<Option<String>> {
    platform::swift_demangle_symbol(symbol_name)
}

pub fn find_swift_symbols(module_name: Option<&str>, query: &str) -> Result<Vec<SwiftSymbol>> {
    platform::find_swift_symbols(module_name, query)
}

pub fn find_swift_types(module_name: Option<&str>, query: &str) -> Result<Vec<SwiftType>> {
    platform::find_swift_types(module_name, query)
}

pub fn find_swift_protocols(module_name: Option<&str>, query: Option<&str>) -> Result<Vec<SwiftProtocol>> {
    platform::find_swift_protocols(module_name, query)
}

pub fn swift_type_source_kinds() -> &'static [&'static str] {
    &[
        "metadata-accessor",
        "nominal-descriptor",
        "metadata-cache",
        "associated-type-descriptor",
        "protocol-conformance-descriptor",
        "protocol-witness-table",
        "protocol-witness",
        "dispatch-thunk",
        "member",
        "symbol",
    ]
}

pub fn find_swift_types_of_kind(module_name: Option<&str>, source_kind: &str, query: &str) -> Result<Vec<SwiftType>> {
    platform::find_swift_types_of_kind(module_name, source_kind, query)
}

pub fn find_swift_method_owners(module_name: Option<&str>, method_query: &str) -> Result<Vec<SwiftType>> {
    platform::find_swift_method_owners(module_name, method_query)
}

pub fn find_swift_type_methods(module_name: Option<&str>, type_query: &str) -> Result<Vec<SwiftSymbol>> {
    platform::find_swift_type_methods(module_name, type_query)
}

pub fn find_swift_methods(module_name: Option<&str>, type_name: &str, method_query: &str) -> Result<Vec<SwiftSymbol>> {
    platform::find_swift_methods(module_name, type_name, method_query)
}

#[cfg_attr(not(any(target_os = "ios", target_os = "macos")), allow(dead_code))]
fn normalize_symbol_name(symbol_name: &str) -> &str {
    symbol_name.strip_prefix('_').unwrap_or(symbol_name)
}

#[cfg_attr(not(any(target_os = "ios", target_os = "macos")), allow(dead_code))]
fn looks_like_swift_symbol(symbol_name: &str) -> bool {
    let normalized = normalize_symbol_name(symbol_name);
    normalized.starts_with("$s") || normalized.starts_with("$S") || normalized.starts_with("_T")
}

#[cfg_attr(not(any(target_os = "ios", target_os = "macos")), allow(dead_code))]
fn query_matches_symbol(symbol_name: &str, demangled_name: Option<&str>, query: &str) -> bool {
    let trimmed = query.trim();
    if trimmed.is_empty() {
        return false;
    }

    let needle = trimmed.to_ascii_lowercase();
    let normalized = normalize_symbol_name(symbol_name).to_ascii_lowercase();
    if normalized.contains(&needle) || symbol_name.to_ascii_lowercase().contains(&needle) {
        return true;
    }

    demangled_name
        .map(|name| name.to_ascii_lowercase().contains(&needle))
        .unwrap_or(false)
}

#[cfg_attr(not(any(target_os = "ios", target_os = "macos")), allow(dead_code))]
fn query_matches_swift_method(
    symbol_name: &str,
    demangled_name: Option<&str>,
    type_name: &str,
    method_query: &str,
) -> bool {
    let type_name = type_name.trim();
    let method_query = method_query.trim();
    if type_name.is_empty() || method_query.is_empty() {
        return false;
    }

    let type_needle = type_name.to_ascii_lowercase();
    let method_needle = method_query.to_ascii_lowercase();

    let symbol_lower = symbol_name.to_ascii_lowercase();
    if symbol_lower.contains(&type_needle) && symbol_lower.contains(&method_needle) {
        return true;
    }

    demangled_name
        .map(|name| {
            let lower = name.to_ascii_lowercase();
            lower.contains(&type_needle) && lower.contains(&method_needle)
        })
        .unwrap_or(false)
}

#[cfg_attr(not(any(target_os = "ios", target_os = "macos")), allow(dead_code))]
fn query_matches_swift_type(type_name: &str, query: &str) -> bool {
    let trimmed = query.trim();
    if trimmed.is_empty() {
        return false;
    }

    let needle = trimmed.to_ascii_lowercase();
    let lower = type_name.to_ascii_lowercase();
    if lower.contains(&needle) {
        return true;
    }

    type_name
        .rsplit('.')
        .next()
        .map(|basename| basename.to_ascii_lowercase().contains(&needle))
        .unwrap_or(false)
}

#[cfg_attr(not(any(target_os = "ios", target_os = "macos")), allow(dead_code))]
fn extract_swift_protocol_name(demangled_name: Option<&str>) -> Option<String> {
    let demangled = demangled_name?.trim();
    if demangled.is_empty() {
        return None;
    }

    for prefix in ["protocol descriptor for ", "protocol requirements base descriptor for "] {
        if let Some(rest) = demangled.strip_prefix(prefix) {
            return sanitize_swift_type_candidate(rest);
        }
    }

    None
}

#[cfg_attr(not(any(target_os = "ios", target_os = "macos")), allow(dead_code))]
fn infer_swift_protocol_source_kind(demangled_name: Option<&str>) -> &'static str {
    let Some(demangled_name) = demangled_name.map(str::trim) else {
        return "symbol";
    };

    if demangled_name.starts_with("protocol descriptor for ") {
        "protocol-descriptor"
    } else if demangled_name.starts_with("protocol requirements base descriptor for ") {
        "protocol-requirements-base-descriptor"
    } else {
        "symbol"
    }
}

#[cfg_attr(not(any(target_os = "ios", target_os = "macos")), allow(dead_code))]
fn query_matches_swift_member_name(member_name: &str, query: &str) -> bool {
    let trimmed = query.trim();
    if trimmed.is_empty() {
        return false;
    }

    member_name.to_ascii_lowercase().contains(&trimmed.to_ascii_lowercase())
}

#[cfg_attr(not(any(target_os = "ios", target_os = "macos")), allow(dead_code))]
fn extract_swift_type_name(symbol_name: &str, demangled_name: Option<&str>) -> Option<String> {
    let demangled = demangled_name?.trim();
    if demangled.is_empty() {
        return None;
    }

    for prefix in [
        "type metadata accessor for ",
        "nominal type descriptor for ",
        "lazy cache variable for type metadata for ",
        "associated type descriptor for ",
        "protocol conformance descriptor for ",
        "protocol witness table for ",
        "protocol witness for ",
        "dispatch thunk of ",
    ] {
        if let Some(rest) = demangled.strip_prefix(prefix) {
            return sanitize_swift_type_candidate(rest);
        }
    }

    extract_swift_type_from_member_signature(demangled)
        .or_else(|| extract_swift_type_from_symbol_name(symbol_name))
        .and_then(|candidate| sanitize_swift_type_candidate(&candidate))
}

#[cfg_attr(not(any(target_os = "ios", target_os = "macos")), allow(dead_code))]
fn extract_swift_member_owner_type(demangled_name: Option<&str>) -> Option<String> {
    let demangled = demangled_name?.trim();
    extract_swift_type_from_member_signature(demangled).and_then(|candidate| sanitize_swift_type_candidate(&candidate))
}

#[cfg_attr(not(any(target_os = "ios", target_os = "macos")), allow(dead_code))]
fn extract_swift_member_name(demangled_name: Option<&str>) -> Option<String> {
    let mut head = demangled_name?.trim();
    for prefix in ["static ", "class ", "mutating "] {
        if let Some(rest) = head.strip_prefix(prefix) {
            head = rest.trim();
        }
    }

    if head.starts_with("type metadata accessor for ")
        || head.starts_with("nominal type descriptor for ")
        || head.starts_with("lazy cache variable for type metadata for ")
        || head.starts_with("associated type descriptor for ")
        || head.starts_with("protocol conformance descriptor for ")
        || head.starts_with("protocol witness table for ")
        || head.starts_with("protocol witness for ")
        || head.starts_with("dispatch thunk of ")
    {
        return None;
    }

    if let Some(index) = head.find(" : ") {
        head = &head[..index];
    }
    if let Some(index) = head.find(" -> ") {
        head = &head[..index];
    }

    let parts = head.split('.').collect::<Vec<_>>();
    if parts.len() < 2 {
        return None;
    }

    let tail = parts.last().copied().unwrap_or_default();
    let raw_name = if let Some(index) = tail.find('(') {
        &tail[..index]
    } else if matches!(
        tail,
        "getter"
            | "setter"
            | "modify"
            | "read"
            | "unsafeAddressor"
            | "unsafeMutableAddressor"
            | "materializeForSet"
            | "allocator"
            | "deallocator"
            | "initializer"
    ) {
        parts.get(parts.len().saturating_sub(2)).copied().unwrap_or_default()
    } else {
        tail
    };

    let trimmed = raw_name.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

#[cfg_attr(not(any(target_os = "ios", target_os = "macos")), allow(dead_code))]
fn extract_swift_type_from_member_signature(demangled_name: &str) -> Option<String> {
    let mut head = demangled_name.trim();
    for prefix in ["static ", "class ", "mutating "] {
        if let Some(rest) = head.strip_prefix(prefix) {
            head = rest.trim();
        }
    }

    if let Some(index) = head.find(" : ") {
        head = &head[..index];
    }
    if let Some(index) = head.find(" -> ") {
        head = &head[..index];
    }

    if let Some(index) = head.find(".Type.") {
        return Some(head[..index].trim().to_string());
    }

    let parts = head.split('.').collect::<Vec<_>>();
    if parts.len() < 2 {
        return None;
    }

    let tail = parts.last().copied().unwrap_or_default();
    let type_part_count = if tail.contains('(') {
        parts.len().saturating_sub(1)
    } else if matches!(
        tail,
        "getter"
            | "setter"
            | "modify"
            | "read"
            | "unsafeAddressor"
            | "unsafeMutableAddressor"
            | "materializeForSet"
            | "allocator"
            | "deallocator"
            | "initializer"
    ) {
        parts.len().saturating_sub(2)
    } else {
        parts.len().saturating_sub(1)
    };

    if type_part_count == 0 {
        return None;
    }

    Some(parts[..type_part_count].join("."))
}

#[cfg_attr(not(any(target_os = "ios", target_os = "macos")), allow(dead_code))]
fn extract_swift_type_from_symbol_name(symbol_name: &str) -> Option<String> {
    let normalized = normalize_symbol_name(symbol_name);
    if !looks_like_swift_symbol(normalized) {
        return None;
    }
    None
}

#[cfg_attr(not(any(target_os = "ios", target_os = "macos")), allow(dead_code))]
fn sanitize_swift_type_candidate(candidate: &str) -> Option<String> {
    let trimmed = candidate.trim().trim_matches(|ch| ch == '(' || ch == ')');
    if trimmed.is_empty() {
        return None;
    }

    let trimmed = trimmed
        .trim_start_matches("type metadata for ")
        .trim_start_matches("partial apply for ")
        .trim_start_matches("specialized ")
        .trim();

    if trimmed.is_empty() || !trimmed.contains('.') {
        return None;
    }

    Some(trimmed.to_string())
}

#[cfg_attr(not(any(target_os = "ios", target_os = "macos")), allow(dead_code))]
fn infer_swift_type_source_kind(demangled_name: Option<&str>) -> &'static str {
    let Some(demangled_name) = demangled_name.map(str::trim) else {
        return "symbol";
    };

    if demangled_name.starts_with("type metadata accessor for ") {
        "metadata-accessor"
    } else if demangled_name.starts_with("nominal type descriptor for ") {
        "nominal-descriptor"
    } else if demangled_name.starts_with("lazy cache variable for type metadata for ") {
        "metadata-cache"
    } else if demangled_name.starts_with("associated type descriptor for ") {
        "associated-type-descriptor"
    } else if demangled_name.starts_with("protocol conformance descriptor for ") {
        "protocol-conformance-descriptor"
    } else if demangled_name.starts_with("protocol witness table for ") {
        "protocol-witness-table"
    } else if demangled_name.starts_with("protocol witness for ") {
        "protocol-witness"
    } else if demangled_name.starts_with("dispatch thunk of ") {
        "dispatch-thunk"
    } else if extract_swift_member_owner_type(Some(demangled_name)).is_some() {
        "member"
    } else {
        "symbol"
    }
}

#[cfg_attr(not(any(target_os = "ios", target_os = "macos")), allow(dead_code))]
fn normalize_swift_type_source_kind(kind: &str) -> Option<&'static str> {
    let trimmed = kind.trim().to_ascii_lowercase();
    match trimmed.as_str() {
        "metadata-accessor" | "metadata" | "accessor" => Some("metadata-accessor"),
        "nominal-descriptor" | "nominal" | "descriptor" => Some("nominal-descriptor"),
        "metadata-cache" | "cache" => Some("metadata-cache"),
        "associated-type-descriptor" | "associated-type" => Some("associated-type-descriptor"),
        "protocol-conformance-descriptor" | "conformance" => Some("protocol-conformance-descriptor"),
        "protocol-witness-table" | "witness-table" => Some("protocol-witness-table"),
        "protocol-witness" | "witness" => Some("protocol-witness"),
        "dispatch-thunk" | "thunk" => Some("dispatch-thunk"),
        "member" => Some("member"),
        "symbol" => Some("symbol"),
        _ => None,
    }
}

#[cfg(any(target_os = "ios", target_os = "macos"))]
mod platform {
    use std::ffi::{CStr, CString};
    use std::os::raw::{c_char, c_void};

    use common::{Error, Result};

    use crate::{enumerate_images, image_name_matches, ImageInfo, SwiftProtocol, SwiftSymbol, SwiftType};

    use super::{
        extract_swift_member_name, extract_swift_member_owner_type, extract_swift_protocol_name,
        extract_swift_type_name, infer_swift_protocol_source_kind, infer_swift_type_source_kind,
        looks_like_swift_symbol, normalize_swift_type_source_kind, query_matches_swift_member_name,
        query_matches_swift_method, query_matches_swift_type, query_matches_symbol, swift_type_source_kinds,
    };

    const LC_SEGMENT_64: u32 = 0x19;
    const LC_SYMTAB: u32 = 0x2;
    const MH_MAGIC_64: u32 = 0xfeedfacf;
    const N_STAB: u8 = 0xe0;

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
    struct SymtabCommand {
        cmd: u32,
        cmdsize: u32,
        symoff: u32,
        nsyms: u32,
        stroff: u32,
        strsize: u32,
    }

    #[repr(C)]
    struct Nlist64 {
        n_strx: u32,
        n_type: u8,
        n_sect: u8,
        n_desc: u16,
        n_value: u64,
    }

    type SwiftDemangleFn = unsafe extern "C" fn(*const c_char, usize, *mut c_char, *mut usize, u32) -> *mut c_char;

    pub fn swift_support_available() -> bool {
        true
    }

    pub fn swift_demangle_symbol(symbol_name: &str) -> Result<Option<String>> {
        let trimmed = symbol_name.trim();
        if trimmed.is_empty() {
            return Err(Error::InvalidArgument("swift symbol must not be empty".into()));
        }

        demangle_symbol_best_effort(trimmed)
    }

    pub fn find_swift_symbols(module_name: Option<&str>, query: &str) -> Result<Vec<SwiftSymbol>> {
        let trimmed = query.trim();
        if trimmed.is_empty() {
            return Err(Error::InvalidArgument(
                "swift query must not be empty; use `swift.symbols <query>` or `swift.symbols <module> -- <query>`"
                    .into(),
            ));
        }

        let mut matches = collect_swift_symbols(module_name)?;
        matches.retain(|symbol| query_matches_symbol(&symbol.symbol_name, symbol.demangled_name.as_deref(), trimmed));
        dedup_and_sort_symbols(&mut matches);
        Ok(matches)
    }

    pub fn find_swift_types(module_name: Option<&str>, query: &str) -> Result<Vec<SwiftType>> {
        let trimmed = query.trim();
        if trimmed.is_empty() {
            return Err(Error::InvalidArgument(
                "swift type query must not be empty; use `swift.types <query>` or `swift.types <module> -- <query>`"
                    .into(),
            ));
        }

        let mut matches = collect_swift_symbols(module_name)?
            .into_iter()
            .filter_map(|symbol| {
                let type_name = extract_swift_type_name(&symbol.symbol_name, symbol.demangled_name.as_deref())?;
                if !query_matches_swift_type(&type_name, trimmed) {
                    return None;
                }
                let source_kind = infer_swift_type_source_kind(symbol.demangled_name.as_deref()).to_string();

                Some(SwiftType {
                    module_name: symbol.module_name,
                    module_base: symbol.module_base,
                    type_name,
                    source_symbol_name: symbol.symbol_name,
                    source_demangled_name: symbol.demangled_name,
                    source_kind,
                    source_address: symbol.address,
                    source_offset: symbol.offset,
                })
            })
            .collect::<Vec<_>>();
        dedup_and_sort_types(&mut matches);
        Ok(matches)
    }

    pub fn find_swift_protocols(module_name: Option<&str>, query: Option<&str>) -> Result<Vec<SwiftProtocol>> {
        let trimmed = query.map(str::trim).filter(|value| !value.is_empty());
        let mut matches = collect_swift_symbols(module_name)?
            .into_iter()
            .filter_map(|symbol| {
                let protocol_name = extract_swift_protocol_name(symbol.demangled_name.as_deref())?;
                if let Some(query) = trimmed {
                    if !query_matches_swift_type(&protocol_name, query) {
                        return None;
                    }
                }
                let source_kind = infer_swift_protocol_source_kind(symbol.demangled_name.as_deref()).to_string();

                Some(SwiftProtocol {
                    module_name: symbol.module_name,
                    module_base: symbol.module_base,
                    protocol_name,
                    source_symbol_name: symbol.symbol_name,
                    source_demangled_name: symbol.demangled_name,
                    source_kind,
                    source_address: symbol.address,
                    source_offset: symbol.offset,
                })
            })
            .collect::<Vec<_>>();
        dedup_and_sort_protocols(&mut matches);
        Ok(matches)
    }

    pub fn find_swift_methods(
        module_name: Option<&str>,
        type_name: &str,
        method_query: &str,
    ) -> Result<Vec<SwiftSymbol>> {
        let trimmed_type = type_name.trim();
        let trimmed_method = method_query.trim();
        if trimmed_type.is_empty() || trimmed_method.is_empty() {
            return Err(Error::InvalidArgument(
                "swift method lookup requires a non-empty type and method query".into(),
            ));
        }

        let mut matches = collect_swift_symbols(module_name)?;
        matches.retain(|symbol| {
            query_matches_swift_method(
                &symbol.symbol_name,
                symbol.demangled_name.as_deref(),
                trimmed_type,
                trimmed_method,
            )
        });
        dedup_and_sort_symbols(&mut matches);
        Ok(matches)
    }

    pub fn find_swift_type_methods(module_name: Option<&str>, type_query: &str) -> Result<Vec<SwiftSymbol>> {
        let trimmed = type_query.trim();
        if trimmed.is_empty() {
            return Err(Error::InvalidArgument(
                "swift type-method query must not be empty; use `swift.typeMethods <type>` or `swift.typeMethods <module> -- <type>`"
                    .into(),
            ));
        }

        let mut matches = collect_swift_symbols(module_name)?;
        matches.retain(|symbol| {
            extract_swift_member_owner_type(symbol.demangled_name.as_deref())
                .map(|owner_type| query_matches_swift_type(&owner_type, trimmed))
                .unwrap_or(false)
        });
        dedup_and_sort_symbols(&mut matches);
        Ok(matches)
    }

    pub fn find_swift_types_of_kind(
        module_name: Option<&str>,
        source_kind: &str,
        query: &str,
    ) -> Result<Vec<SwiftType>> {
        let canonical_kind = normalize_swift_type_source_kind(source_kind).ok_or_else(|| {
            Error::InvalidArgument(format!(
                "unsupported swift type source kind `{}`; supported kinds: {}",
                source_kind.trim(),
                swift_type_source_kinds().join(", ")
            ))
        })?;

        let mut matches = find_swift_types(module_name, query)?;
        matches.retain(|type_info| type_info.source_kind == canonical_kind);
        Ok(matches)
    }

    pub fn find_swift_method_owners(module_name: Option<&str>, method_query: &str) -> Result<Vec<SwiftType>> {
        let trimmed = method_query.trim();
        if trimmed.is_empty() {
            return Err(Error::InvalidArgument(
                "swift method-owner query must not be empty; use `swift.methodOwners <method>` or `swift.methodOwners <module> -- <method>`"
                    .into(),
            ));
        }

        let mut matches = collect_swift_symbols(module_name)?
            .into_iter()
            .filter_map(|symbol| {
                let owner_type = extract_swift_member_owner_type(symbol.demangled_name.as_deref())?;
                let member_name = extract_swift_member_name(symbol.demangled_name.as_deref())?;
                if !query_matches_swift_member_name(&member_name, trimmed) {
                    return None;
                }

                Some(SwiftType {
                    module_name: symbol.module_name,
                    module_base: symbol.module_base,
                    type_name: owner_type,
                    source_symbol_name: symbol.symbol_name,
                    source_demangled_name: symbol.demangled_name,
                    source_kind: "member".to_string(),
                    source_address: symbol.address,
                    source_offset: symbol.offset,
                })
            })
            .collect::<Vec<_>>();
        dedup_and_sort_types(&mut matches);
        Ok(matches)
    }

    fn collect_swift_symbols(module_name: Option<&str>) -> Result<Vec<SwiftSymbol>> {
        let images = enumerate_images()?;
        let mut symbols = Vec::new();
        for image in images {
            if let Some(module_name) = module_name {
                if !image_name_matches(module_name, &image.name) {
                    continue;
                }
            }

            symbols.extend(collect_swift_symbols_in_image(&image)?);
        }
        Ok(symbols)
    }

    fn dedup_and_sort_symbols(matches: &mut Vec<SwiftSymbol>) {
        matches.sort_by(|left, right| {
            left.module_name
                .cmp(&right.module_name)
                .then(left.address.cmp(&right.address))
                .then(left.symbol_name.cmp(&right.symbol_name))
        });
        matches.dedup_by(|left, right| {
            left.module_name == right.module_name
                && left.address == right.address
                && left.symbol_name == right.symbol_name
        });
    }

    fn dedup_and_sort_types(matches: &mut Vec<SwiftType>) {
        matches.sort_by(|left, right| {
            left.module_name
                .cmp(&right.module_name)
                .then(left.type_name.cmp(&right.type_name))
                .then(left.source_symbol_name.cmp(&right.source_symbol_name))
        });
        matches.dedup_by(|left, right| left.module_name == right.module_name && left.type_name == right.type_name);
    }

    fn dedup_and_sort_protocols(matches: &mut Vec<SwiftProtocol>) {
        matches.sort_by(|left, right| {
            left.module_name
                .cmp(&right.module_name)
                .then(left.protocol_name.cmp(&right.protocol_name))
                .then(left.source_symbol_name.cmp(&right.source_symbol_name))
        });
        matches
            .dedup_by(|left, right| left.module_name == right.module_name && left.protocol_name == right.protocol_name);
    }

    fn collect_swift_symbols_in_image(image: &ImageInfo) -> Result<Vec<SwiftSymbol>> {
        let header = image.base as *const MachHeader64;
        if header.is_null() {
            return Ok(Vec::new());
        }

        let header = unsafe { &*header };
        if header.magic != MH_MAGIC_64 {
            return Ok(Vec::new());
        }

        let mut linkedit_segment = None;
        let mut symtab = None;
        let mut command_ptr = unsafe { header_ptr_after_header(header) };

        for _ in 0..header.ncmds {
            let load = unsafe { &*(command_ptr as *const LoadCommand) };
            match load.cmd {
                LC_SEGMENT_64 => {
                    let segment = unsafe { &*(command_ptr as *const SegmentCommand64) };
                    if segment_name(segment) == "__LINKEDIT" {
                        linkedit_segment = Some(segment);
                    }
                }
                LC_SYMTAB => {
                    let table = unsafe { &*(command_ptr as *const SymtabCommand) };
                    symtab = Some(table);
                }
                _ => {}
            }

            let command_size = load.cmdsize as usize;
            if command_size == 0 {
                break;
            }
            command_ptr = unsafe { command_ptr.add(command_size) };
        }

        let Some(linkedit_segment) = linkedit_segment else {
            return Ok(Vec::new());
        };
        let Some(symtab) = symtab else {
            return Ok(Vec::new());
        };

        let linkedit_base = compute_linkedit_base(image, linkedit_segment)?;
        let symtab_ptr = unsafe { linkedit_base.add(symtab.symoff as usize) as *const Nlist64 };
        let strtab_ptr = unsafe { linkedit_base.add(symtab.stroff as usize) };
        let strtab_len = symtab.strsize as usize;

        let mut matches = Vec::new();
        for index in 0..symtab.nsyms as usize {
            let entry = unsafe { &*symtab_ptr.add(index) };
            if entry.n_value == 0 || (entry.n_type & N_STAB) != 0 {
                continue;
            }

            let Some(symbol_name) = read_symbol_name(strtab_ptr, strtab_len, entry.n_strx as usize) else {
                continue;
            };
            if !looks_like_swift_symbol(&symbol_name) {
                continue;
            }

            let demangled_name = demangle_symbol_best_effort(&symbol_name)?;
            let address = entry.n_value as usize;
            let offset = address.saturating_sub(image.base);
            matches.push(SwiftSymbol {
                module_name: image.name.clone(),
                module_base: image.base,
                symbol_name,
                demangled_name,
                address,
                offset,
            });
        }

        Ok(matches)
    }

    unsafe fn header_ptr_after_header(header: &MachHeader64) -> *const u8 {
        (header as *const MachHeader64).add(1) as *const u8
    }

    fn segment_name(segment: &SegmentCommand64) -> &str {
        let length = segment
            .segname
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(segment.segname.len());
        std::str::from_utf8(&segment.segname[..length]).unwrap_or("")
    }

    fn compute_linkedit_base(image: &ImageInfo, linkedit_segment: &SegmentCommand64) -> Result<*const u8> {
        let base = image.slide as i128 + linkedit_segment.vmaddr as i128 - linkedit_segment.fileoff as i128;
        if base < 0 || base > usize::MAX as i128 {
            return Err(Error::State(format!(
                "computed __LINKEDIT base for {} overflowed address space",
                image.name
            )));
        }
        Ok(base as usize as *const u8)
    }

    fn read_symbol_name(strtab_ptr: *const u8, strtab_len: usize, offset: usize) -> Option<String> {
        if offset >= strtab_len {
            return None;
        }

        let raw = unsafe { std::slice::from_raw_parts(strtab_ptr.add(offset), strtab_len - offset) };
        let end = raw.iter().position(|byte| *byte == 0)?;
        if end == 0 {
            return None;
        }

        Some(String::from_utf8_lossy(&raw[..end]).into_owned())
    }

    fn demangle_symbol_best_effort(symbol_name: &str) -> Result<Option<String>> {
        let Some(swift_demangle) = lookup_swift_demangle()? else {
            return Ok(None);
        };

        let input = CString::new(symbol_name)
            .map_err(|_| Error::InvalidArgument("swift symbol contains an interior NUL byte".into()))?;
        let mut output_size = 0usize;
        let output_ptr = unsafe {
            swift_demangle(
                input.as_ptr(),
                symbol_name.len(),
                std::ptr::null_mut(),
                &mut output_size,
                0,
            )
        };
        if output_ptr.is_null() {
            return Ok(None);
        }

        let output = unsafe { CStr::from_ptr(output_ptr) }.to_string_lossy().into_owned();
        unsafe {
            libc::free(output_ptr as *mut c_void);
        }

        if output.is_empty() {
            Ok(None)
        } else {
            Ok(Some(output))
        }
    }

    fn lookup_swift_demangle() -> Result<Option<SwiftDemangleFn>> {
        let symbol_name = CString::new("swift_demangle")
            .map_err(|_| Error::State("failed to build swift_demangle symbol name".into()))?;
        let ptr = unsafe { libc::dlsym(libc::RTLD_DEFAULT, symbol_name.as_ptr()) };
        if ptr.is_null() {
            Ok(None)
        } else {
            Ok(Some(unsafe {
                std::mem::transmute::<*mut c_void, SwiftDemangleFn>(ptr)
            }))
        }
    }
}

#[cfg(not(any(target_os = "ios", target_os = "macos")))]
mod platform {
    use common::{Error, Result};

    use crate::{SwiftProtocol, SwiftSymbol, SwiftType};

    pub fn swift_support_available() -> bool {
        false
    }

    pub fn swift_demangle_symbol(_symbol_name: &str) -> Result<Option<String>> {
        Err(Error::Unsupported(
            "Swift symbol lookup is only available on Apple targets".into(),
        ))
    }

    pub fn find_swift_symbols(_module_name: Option<&str>, _query: &str) -> Result<Vec<SwiftSymbol>> {
        Err(Error::Unsupported(
            "Swift symbol lookup is only available on Apple targets".into(),
        ))
    }

    pub fn find_swift_types(_module_name: Option<&str>, _query: &str) -> Result<Vec<SwiftType>> {
        Err(Error::Unsupported(
            "Swift symbol lookup is only available on Apple targets".into(),
        ))
    }

    pub fn find_swift_protocols(_module_name: Option<&str>, _query: Option<&str>) -> Result<Vec<SwiftProtocol>> {
        Err(Error::Unsupported(
            "Swift symbol lookup is only available on Apple targets".into(),
        ))
    }

    pub fn find_swift_types_of_kind(
        _module_name: Option<&str>,
        _source_kind: &str,
        _query: &str,
    ) -> Result<Vec<SwiftType>> {
        Err(Error::Unsupported(
            "Swift symbol lookup is only available on Apple targets".into(),
        ))
    }

    pub fn find_swift_method_owners(_module_name: Option<&str>, _method_query: &str) -> Result<Vec<SwiftType>> {
        Err(Error::Unsupported(
            "Swift symbol lookup is only available on Apple targets".into(),
        ))
    }

    pub fn find_swift_type_methods(_module_name: Option<&str>, _type_query: &str) -> Result<Vec<SwiftSymbol>> {
        Err(Error::Unsupported(
            "Swift symbol lookup is only available on Apple targets".into(),
        ))
    }

    pub fn find_swift_methods(
        _module_name: Option<&str>,
        _type_name: &str,
        _method_query: &str,
    ) -> Result<Vec<SwiftSymbol>> {
        Err(Error::Unsupported(
            "Swift symbol lookup is only available on Apple targets".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::{
        extract_swift_member_name, extract_swift_member_owner_type, extract_swift_protocol_name,
        extract_swift_type_name, infer_swift_protocol_source_kind, infer_swift_type_source_kind,
        looks_like_swift_symbol, normalize_swift_type_source_kind, query_matches_swift_member_name,
        query_matches_swift_method, query_matches_swift_type, query_matches_symbol,
    };

    #[test]
    fn detects_swift_mangled_names() {
        assert!(looks_like_swift_symbol("_$s4Demo6methodyyF"));
        assert!(looks_like_swift_symbol("$s4Demo6methodyyF"));
        assert!(looks_like_swift_symbol("__T012LegacySwift6methodyyF"));
        assert!(!looks_like_swift_symbol("_objc_msgSend"));
        assert!(!looks_like_swift_symbol("malloc"));
    }

    #[test]
    fn matches_query_against_mangled_and_demangled_names() {
        assert!(query_matches_symbol(
            "_$s4Demo14ViewControllerC11viewDidLoadyyF",
            Some("Demo.ViewController.viewDidLoad() -> ()"),
            "viewdidload"
        ));
        assert!(query_matches_symbol(
            "_$s4Demo14ViewControllerC11viewDidLoadyyF",
            Some("Demo.ViewController.viewDidLoad() -> ()"),
            "$s4demo"
        ));
        assert!(!query_matches_symbol(
            "_$s4Demo14ViewControllerC11viewDidLoadyyF",
            Some("Demo.ViewController.viewDidLoad() -> ()"),
            "applicationdidfinishlaunching"
        ));
    }

    #[test]
    fn matches_swift_method_against_type_and_method_name() {
        assert!(query_matches_swift_method(
            "_$s4Demo14ViewControllerC11viewDidLoadyyF",
            Some("Demo.ViewController.viewDidLoad() -> ()"),
            "ViewController",
            "viewDidLoad"
        ));
        assert!(query_matches_swift_method(
            "_$s4Demo14ViewControllerC11viewDidLoadyyF",
            Some("Demo.ViewController.viewDidLoad() -> ()"),
            "demo.viewcontroller",
            "viewdid"
        ));
        assert!(!query_matches_swift_method(
            "_$s4Demo14ViewControllerC11viewDidLoadyyF",
            Some("Demo.ViewController.viewDidLoad() -> ()"),
            "AppDelegate",
            "viewDidLoad"
        ));
    }

    #[test]
    fn extracts_swift_type_names_from_demangled_symbols() {
        assert_eq!(
            extract_swift_type_name(
                "_$s4Demo14ViewControllerC11viewDidLoadyyF",
                Some("Demo.ViewController.viewDidLoad() -> ()")
            ),
            Some("Demo.ViewController".into())
        );
        assert_eq!(
            extract_swift_type_name(
                "_$s4Demo14ViewControllerCMa",
                Some("type metadata accessor for Demo.ViewController")
            ),
            Some("Demo.ViewController".into())
        );
        assert_eq!(
            extract_swift_type_name(
                "_$s4Demo14ViewControllerC6sharedACvgZ",
                Some("static Demo.ViewController.shared.getter : Demo.ViewController")
            ),
            Some("Demo.ViewController".into())
        );
    }

    #[test]
    fn extracts_swift_protocol_names_from_demangled_symbols() {
        assert_eq!(
            extract_swift_protocol_name(Some("protocol descriptor for Demo.Renderable")),
            Some("Demo.Renderable".into())
        );
        assert_eq!(
            extract_swift_protocol_name(Some("protocol requirements base descriptor for Demo.Renderable")),
            Some("Demo.Renderable".into())
        );
        assert_eq!(
            extract_swift_protocol_name(Some(
                "protocol conformance descriptor for Demo.ViewController : Demo.Renderable in Demo"
            )),
            None
        );
    }

    #[test]
    fn matches_swift_type_query_against_full_and_basename() {
        assert!(query_matches_swift_type("Demo.ViewController", "viewcontroller"));
        assert!(query_matches_swift_type("Demo.ViewController", "demo.view"));
        assert!(!query_matches_swift_type("Demo.ViewController", "appdelegate"));
    }

    #[test]
    fn extracts_swift_member_owner_type_from_demangled_member_signatures() {
        assert_eq!(
            extract_swift_member_owner_type(Some("Demo.ViewController.viewDidLoad() -> ()")),
            Some("Demo.ViewController".into())
        );
        assert_eq!(
            extract_swift_member_owner_type(Some("static Demo.ViewController.shared.getter : Demo.ViewController")),
            Some("Demo.ViewController".into())
        );
        assert_eq!(
            extract_swift_member_owner_type(Some("type metadata accessor for Demo.ViewController")),
            None
        );
    }

    #[test]
    fn infers_swift_type_source_kind_from_demangled_names() {
        assert_eq!(
            infer_swift_type_source_kind(Some("type metadata accessor for Demo.ViewController")),
            "metadata-accessor"
        );
        assert_eq!(
            infer_swift_type_source_kind(Some("nominal type descriptor for Demo.ViewController")),
            "nominal-descriptor"
        );
        assert_eq!(
            infer_swift_type_source_kind(Some("Demo.ViewController.viewDidLoad() -> ()")),
            "member"
        );
        assert_eq!(infer_swift_type_source_kind(None), "symbol");
    }

    #[test]
    fn infers_swift_protocol_source_kind_from_demangled_names() {
        assert_eq!(
            infer_swift_protocol_source_kind(Some("protocol descriptor for Demo.Renderable")),
            "protocol-descriptor"
        );
        assert_eq!(
            infer_swift_protocol_source_kind(Some("protocol requirements base descriptor for Demo.Renderable")),
            "protocol-requirements-base-descriptor"
        );
        assert_eq!(infer_swift_protocol_source_kind(None), "symbol");
    }

    #[test]
    fn normalizes_swift_type_source_kind_aliases() {
        assert_eq!(normalize_swift_type_source_kind("metadata"), Some("metadata-accessor"));
        assert_eq!(
            normalize_swift_type_source_kind("descriptor"),
            Some("nominal-descriptor")
        );
        assert_eq!(
            normalize_swift_type_source_kind("witness-table"),
            Some("protocol-witness-table")
        );
        assert_eq!(normalize_swift_type_source_kind("unknown-kind"), None);
    }

    #[test]
    fn extracts_and_matches_swift_member_names() {
        assert_eq!(
            extract_swift_member_name(Some("Demo.ViewController.viewDidLoad() -> ()")),
            Some("viewDidLoad".into())
        );
        assert_eq!(
            extract_swift_member_name(Some("static Demo.ViewController.shared.getter : Demo.ViewController")),
            Some("shared".into())
        );
        assert!(query_matches_swift_member_name("viewDidLoad", "didload"));
        assert!(!query_matches_swift_member_name("viewDidLoad", "appdelegate"));
    }
}
