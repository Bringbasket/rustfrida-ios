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
    pub type_representation: String,
    pub object_representation: String,
    pub abi_argument_kind: String,
    pub abi_pass_mode: String,
    pub abi_call_supported: bool,
    pub abi_call_reason: String,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SwiftConformance {
    pub module_name: String,
    pub module_base: usize,
    pub type_name: String,
    pub protocol_name: String,
    pub source_symbol_name: String,
    pub source_demangled_name: Option<String>,
    pub source_kind: String,
    pub source_address: usize,
    pub source_offset: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SwiftVtableEntry {
    pub module_name: String,
    pub module_base: usize,
    pub type_name: String,
    pub member_name: String,
    pub symbol_name: String,
    pub demangled_name: Option<String>,
    pub source_kind: String,
    pub address: usize,
    pub offset: usize,
    pub is_dispatch_thunk: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SwiftWitnessTable {
    pub module_name: String,
    pub module_base: usize,
    pub type_name: String,
    pub protocol_name: String,
    pub symbol_name: String,
    pub demangled_name: Option<String>,
    pub source_kind: String,
    pub address: usize,
    pub offset: usize,
    pub is_accessor: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SwiftTypeLayout {
    pub module_name: String,
    pub module_base: usize,
    pub type_name: String,
    pub metadata: Vec<SwiftType>,
    pub metadata_accessors: Vec<SwiftType>,
    pub nominal_descriptors: Vec<SwiftType>,
    pub metadata_caches: Vec<SwiftType>,
    pub associated_type_descriptors: Vec<SwiftType>,
    pub vtable_entries: Vec<SwiftVtableEntry>,
    pub witness_tables: Vec<SwiftWitnessTable>,
}

/// Ownership carried by a live Swift class-object handle.
///
/// `Borrowed` does not change the native reference count, `Adopt` consumes one
/// reference already owned by the caller, and `Retain` creates a new strong
/// reference before the handle is exposed to the script runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SwiftObjectOwnership {
    Borrowed,
    Adopt,
    Retain,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SwiftLiveObjectInfo {
    pub object_address: usize,
    pub metadata_address: usize,
    /// `true` when the metadata address came from the object's first word.
    pub metadata_inferred: bool,
    /// `true` after the first-word identity check; this is not full metadata or ABI validation.
    pub metadata_verified: bool,
    pub ownership: SwiftObjectOwnership,
    pub retain_available: bool,
    pub release_available: bool,
}

#[cfg_attr(not(any(target_os = "ios", target_os = "macos")), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SwiftMetadataIdentity {
    address: usize,
    inferred: bool,
    verified: bool,
}

#[cfg_attr(not(any(target_os = "ios", target_os = "macos")), allow(dead_code))]
fn validate_swift_metadata_identity(observed: usize, supplied: Option<usize>) -> Result<SwiftMetadataIdentity> {
    let address = supplied.unwrap_or(observed);
    if address == 0 {
        return Err(common::Error::State("Swift object metadata identity is null".into()));
    }
    if !address.is_multiple_of(std::mem::size_of::<usize>()) {
        return Err(common::Error::InvalidArgument(format!(
            "Swift metadata address {address:#x} is not aligned to {} bytes",
            std::mem::size_of::<usize>()
        )));
    }
    if let Some(expected) = supplied {
        if expected != observed {
            return Err(common::Error::InvalidArgument(format!(
                "Swift metadata address {expected:#x} does not match object first word {observed:#x}"
            )));
        }
    }
    Ok(SwiftMetadataIdentity {
        address,
        inferred: supplied.is_none(),
        verified: true,
    })
}

/// Resolve the first-word metadata identity of a Swift class object and
/// report the runtime retain/release boundary available in the current image.
/// The caller must still supply a valid live class-object address.
pub fn inspect_swift_live_object(
    object_address: usize,
    metadata_address: Option<usize>,
    ownership: SwiftObjectOwnership,
) -> Result<SwiftLiveObjectInfo> {
    platform::inspect_swift_live_object(object_address, metadata_address, ownership)
}

#[cfg_attr(not(any(target_os = "ios", target_os = "macos")), allow(dead_code))]
const SWIFT_ABI_CALL_UNSUPPORTED_REASON: &str =
    "Swift runtime calls require verified metadata, ownership conventions, generic context, and hidden ABI arguments";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SwiftAbiTypeInfo {
    pub type_representation: &'static str,
    pub object_representation: &'static str,
    pub argument_kind: &'static str,
    pub pass_mode: &'static str,
}

pub fn classify_swift_abi_type(type_name: &str) -> SwiftAbiTypeInfo {
    let compact = type_name.trim();
    let unqualified = compact.strip_prefix("Swift.").unwrap_or(compact);
    let base = compact.rsplit('.').next().unwrap_or(compact);

    if compact.is_empty() {
        return SwiftAbiTypeInfo {
            type_representation: "unknown",
            object_representation: "unknown",
            argument_kind: "unsupported",
            pass_mode: "unknown",
        };
    }
    if compact == "()" || base == "Void" {
        return SwiftAbiTypeInfo {
            type_representation: "void",
            object_representation: "none",
            argument_kind: "void",
            pass_mode: "none",
        };
    }
    if base == "Never" {
        return SwiftAbiTypeInfo {
            type_representation: "noreturn",
            object_representation: "none",
            argument_kind: "noreturn",
            pass_mode: "unsupported",
        };
    }
    if compact.ends_with(".Type") || compact.ends_with(".Protocol") {
        return SwiftAbiTypeInfo {
            type_representation: "metatype",
            object_representation: "metadata-pointer",
            argument_kind: "metatype",
            pass_mode: "direct-pointer",
        };
    }
    if compact == "Any" || compact == "AnyObject" || compact.starts_with("any ") {
        return SwiftAbiTypeInfo {
            type_representation: "existential",
            object_representation: "existential-container",
            argument_kind: "existential",
            pass_mode: "metadata-dependent",
        };
    }
    if compact.contains("->") {
        return SwiftAbiTypeInfo {
            type_representation: "function",
            object_representation: "thick-function",
            argument_kind: "function",
            pass_mode: "context-dependent",
        };
    }
    if compact.starts_with('(') && compact.ends_with(')') {
        return SwiftAbiTypeInfo {
            type_representation: "tuple",
            object_representation: "inline-value",
            argument_kind: "aggregate",
            pass_mode: "layout-dependent",
        };
    }
    if unqualified.starts_with("UnsafePointer<")
        || unqualified.starts_with("UnsafeMutablePointer<")
        || unqualified.starts_with("AutoreleasingUnsafeMutablePointer<")
        || matches!(base, "OpaquePointer" | "UnsafeRawPointer" | "UnsafeMutableRawPointer")
    {
        return SwiftAbiTypeInfo {
            type_representation: "pointer",
            object_representation: "raw-pointer",
            argument_kind: "pointer",
            pass_mode: "direct-pointer",
        };
    }
    if matches!(
        base,
        "Bool"
            | "Int"
            | "Int8"
            | "Int16"
            | "Int32"
            | "Int64"
            | "UInt"
            | "UInt8"
            | "UInt16"
            | "UInt32"
            | "UInt64"
            | "Float"
            | "Double"
            | "Float16"
            | "Float80"
            | "CChar"
            | "CSignedChar"
            | "CUnsignedChar"
            | "CShort"
            | "CUShort"
            | "CInt"
            | "CUInt"
            | "CLong"
            | "CULong"
            | "CFloat"
            | "CDouble"
    ) {
        return SwiftAbiTypeInfo {
            type_representation: "scalar",
            object_representation: "inline-value",
            argument_kind: if base.starts_with("Float") || matches!(base, "Double" | "CFloat" | "CDouble") {
                "floating-point"
            } else {
                "integer"
            },
            pass_mode: "direct-scalar",
        };
    }
    if compact.starts_with("some ") {
        return SwiftAbiTypeInfo {
            type_representation: "opaque-result",
            object_representation: "metadata-dependent",
            argument_kind: "opaque-value",
            pass_mode: "metadata-dependent",
        };
    }

    SwiftAbiTypeInfo {
        type_representation: "nominal",
        object_representation: "metadata-dependent",
        argument_kind: "nominal-value-or-reference",
        pass_mode: "metadata-dependent",
    }
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

pub fn find_swift_conformances(module_name: Option<&str>, query: &str) -> Result<Vec<SwiftConformance>> {
    platform::find_swift_conformances(module_name, query)
}

pub fn find_swift_metadata(module_name: Option<&str>, query: &str) -> Result<Vec<SwiftType>> {
    platform::find_swift_metadata(module_name, query)
}

pub fn find_swift_vtable(module_name: Option<&str>, query: &str) -> Result<Vec<SwiftVtableEntry>> {
    platform::find_swift_vtable(module_name, query)
}

pub fn find_swift_witness_tables(module_name: Option<&str>, query: &str) -> Result<Vec<SwiftWitnessTable>> {
    platform::find_swift_witness_tables(module_name, query)
}

pub fn find_swift_type_layouts(module_name: Option<&str>, query: &str) -> Result<Vec<SwiftTypeLayout>> {
    platform::find_swift_type_layouts(module_name, query)
}

pub fn swift_type_source_kinds() -> &'static [&'static str] {
    &[
        "metadata",
        "metadata-accessor",
        "nominal-descriptor",
        "metadata-cache",
        "associated-type-descriptor",
        "protocol-conformance-descriptor",
        "protocol-witness-table",
        "protocol-witness-table-accessor",
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

pub fn swift_type_name_matches(type_name: &str, query: &str) -> bool {
    query_matches_swift_type(type_name, query)
}

pub fn swift_protocol_name_matches(protocol_name: &str, query: &str) -> bool {
    query_matches_swift_type(protocol_name, query)
}

pub fn swift_conformance_names_match(
    type_name: &str,
    protocol_name: &str,
    type_query: &str,
    protocol_query: &str,
) -> bool {
    query_matches_swift_type(type_name, type_query) && query_matches_swift_type(protocol_name, protocol_query)
}

pub fn swift_member_name_matches(member_name: &str, query: &str) -> bool {
    query_matches_swift_member_name(member_name, query)
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
fn query_matches_swift_conformance_query(type_name: &str, protocol_name: &str, query: &str) -> bool {
    query_matches_swift_type(type_name, query) || query_matches_swift_type(protocol_name, query)
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
fn extract_swift_conformance(demangled_name: Option<&str>) -> Option<(String, String)> {
    let demangled = demangled_name?.trim();
    if demangled.is_empty() {
        return None;
    }

    let mut rest = None;
    for prefix in [
        "protocol conformance descriptor for ",
        "protocol witness table for ",
        "protocol witness table accessor for ",
        "protocol witness for ",
    ] {
        if let Some(value) = demangled.strip_prefix(prefix) {
            rest = Some(value.trim());
            break;
        }
    }
    let mut rest = rest?;

    if let Some((head, _)) = rest.rsplit_once(" in ") {
        rest = head.trim();
    }
    if let Some((head, _)) = rest.split_once(" where ") {
        rest = head.trim();
    }

    let (type_name, protocol_name) = rest.split_once(" : ")?;
    let type_name = sanitize_swift_type_candidate(type_name)?;
    let protocol_name = sanitize_swift_type_candidate(protocol_name)?;
    Some((type_name, protocol_name))
}

#[cfg_attr(not(any(target_os = "ios", target_os = "macos")), allow(dead_code))]
fn infer_swift_conformance_source_kind(demangled_name: Option<&str>) -> &'static str {
    let Some(demangled_name) = demangled_name.map(str::trim) else {
        return "symbol";
    };

    if demangled_name.starts_with("protocol conformance descriptor for ") {
        "protocol-conformance-descriptor"
    } else if demangled_name.starts_with("protocol witness table for ") {
        "protocol-witness-table"
    } else if demangled_name.starts_with("protocol witness table accessor for ") {
        "protocol-witness-table-accessor"
    } else if demangled_name.starts_with("protocol witness for ") {
        "protocol-witness"
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
        "type metadata for ",
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
    } else if demangled_name.starts_with("type metadata for ") {
        "metadata"
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
fn extract_swift_vtable_parts(demangled_name: Option<&str>) -> Option<(String, String, &'static str)> {
    let demangled = demangled_name?.trim();
    if demangled.is_empty() {
        return None;
    }

    let (signature, source_kind) = if let Some(rest) = demangled.strip_prefix("dispatch thunk of ") {
        (rest.trim(), "dispatch-thunk")
    } else if infer_swift_type_source_kind(Some(demangled)) == "member" {
        (demangled, "member")
    } else {
        return None;
    };

    let type_name = extract_swift_member_owner_type(Some(signature))?;
    let member_name = extract_swift_member_name(Some(signature))?;
    Some((type_name, member_name, source_kind))
}

#[cfg_attr(not(any(target_os = "ios", target_os = "macos")), allow(dead_code))]
fn normalize_swift_type_source_kind(kind: &str) -> Option<&'static str> {
    let trimmed = kind.trim().to_ascii_lowercase();
    match trimmed.as_str() {
        "full-metadata" | "type-metadata" => Some("metadata"),
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
    use std::collections::BTreeMap;
    use std::ffi::{CStr, CString};
    use std::mem::size_of;
    use std::os::raw::{c_char, c_void};

    use common::{Error, Result};

    use crate::{
        enumerate_images, image_name_matches, ImageInfo, SwiftConformance, SwiftLiveObjectInfo, SwiftObjectOwnership,
        SwiftProtocol, SwiftSymbol, SwiftType, SwiftTypeLayout, SwiftVtableEntry, SwiftWitnessTable,
    };

    use super::{
        classify_swift_abi_type, extract_swift_conformance, extract_swift_member_name, extract_swift_member_owner_type,
        extract_swift_protocol_name, extract_swift_type_name, extract_swift_vtable_parts,
        infer_swift_conformance_source_kind, infer_swift_protocol_source_kind, infer_swift_type_source_kind,
        looks_like_swift_symbol, normalize_swift_type_source_kind, query_matches_swift_conformance_query,
        query_matches_swift_member_name, query_matches_swift_method, query_matches_swift_type, query_matches_symbol,
        swift_type_source_kinds, validate_swift_metadata_identity, SWIFT_ABI_CALL_UNSUPPORTED_REASON,
    };

    const LC_SEGMENT_64: u32 = 0x19;
    const LC_SYMTAB: u32 = 0x2;
    const MH_MAGIC_64: u32 = 0xfeedfacf;
    const N_STAB: u8 = 0xe0;
    const VM_PROT_READ: libc::vm_prot_t = 1;

    #[repr(C, packed(4))]
    #[derive(Default)]
    struct VmRegionSubmapInfo64 {
        protection: libc::vm_prot_t,
        max_protection: libc::vm_prot_t,
        inheritance: libc::vm_inherit_t,
        offset: libc::memory_object_offset_t,
        user_tag: libc::c_uint,
        pages_resident: libc::c_uint,
        pages_shared_now_private: libc::c_uint,
        pages_swapped_out: libc::c_uint,
        pages_dirtied: libc::c_uint,
        ref_count: libc::c_uint,
        shadow_depth: libc::c_ushort,
        external_pager: libc::c_uchar,
        share_mode: libc::c_uchar,
        is_submap: libc::boolean_t,
        behavior: libc::c_int,
        object_id: libc::c_uint,
        user_wired_count: libc::c_ushort,
        flags: libc::c_ushort,
        pages_reusable: libc::c_uint,
        object_id_full: u64,
    }

    const VM_REGION_SUBMAP_INFO_COUNT_64: libc::mach_msg_type_number_t =
        (size_of::<VmRegionSubmapInfo64>() / size_of::<libc::natural_t>()) as libc::mach_msg_type_number_t;

    extern "C" {
        static mach_task_self_: libc::mach_port_t;

        fn mach_vm_region_recurse(
            target_task: libc::vm_map_t,
            address: *mut libc::mach_vm_address_t,
            size: *mut libc::mach_vm_size_t,
            nesting_depth: *mut libc::natural_t,
            info: *mut libc::integer_t,
            info_count: *mut libc::mach_msg_type_number_t,
        ) -> libc::kern_return_t;
    }

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

    fn lookup_runtime_symbol(name: &str) -> Option<usize> {
        let symbol = CString::new(name).ok()?;
        let address = unsafe { libc::dlsym(libc::RTLD_DEFAULT, symbol.as_ptr()) };
        (!address.is_null()).then_some(address as usize)
    }

    pub fn inspect_swift_live_object(
        object_address: usize,
        metadata_address: Option<usize>,
        ownership: SwiftObjectOwnership,
    ) -> Result<SwiftLiveObjectInfo> {
        if object_address == 0 {
            return Err(Error::InvalidArgument("Swift object address must not be null".into()));
        }
        if !object_address.is_multiple_of(size_of::<usize>()) {
            return Err(Error::InvalidArgument(format!(
                "Swift object address {object_address:#x} is not aligned to {} bytes",
                size_of::<usize>()
            )));
        }
        ensure_readable(object_address, size_of::<usize>())?;
        let observed_metadata = unsafe { (object_address as *const usize).read_unaligned() };
        let metadata_identity = validate_swift_metadata_identity(observed_metadata, metadata_address)?;

        let retain_available = lookup_runtime_symbol("swift_retain").is_some();
        let release_available = lookup_runtime_symbol("swift_release").is_some();
        if matches!(ownership, SwiftObjectOwnership::Retain) && !retain_available {
            return Err(Error::Unsupported(
                "swift_retain is not exported by the loaded Swift runtime".into(),
            ));
        }
        if matches!(ownership, SwiftObjectOwnership::Adopt | SwiftObjectOwnership::Retain) && !release_available {
            return Err(Error::Unsupported(
                "swift_release is not exported by the loaded Swift runtime".into(),
            ));
        }

        Ok(SwiftLiveObjectInfo {
            object_address,
            metadata_address: metadata_identity.address,
            metadata_inferred: metadata_identity.inferred,
            metadata_verified: metadata_identity.verified,
            ownership,
            retain_available,
            release_available,
        })
    }

    fn ensure_readable(address: usize, length: usize) -> Result<()> {
        let end = address
            .checked_add(length)
            .ok_or_else(|| Error::InvalidArgument("Swift object metadata range overflow".into()))?;
        let mut cursor = address;
        while cursor < end {
            let region = readable_region_at(cursor)?;
            if region.start > cursor || region.end <= cursor {
                return Err(Error::State(format!(
                    "Swift object metadata range has an unmapped gap at {cursor:#x}"
                )));
            }
            if region.protection & VM_PROT_READ == 0 {
                return Err(Error::State(format!(
                    "Swift object metadata region {:#x}..{:#x} is not readable",
                    region.start, region.end
                )));
            }
            let next = region.end.min(end);
            if next <= cursor {
                return Err(Error::State(
                    "Swift object metadata region query made no progress".into(),
                ));
            }
            cursor = next;
        }
        Ok(())
    }

    struct ReadableRegion {
        start: usize,
        end: usize,
        protection: libc::vm_prot_t,
    }

    fn readable_region_at(cursor: usize) -> Result<ReadableRegion> {
        let mut nesting_depth = 0;
        loop {
            let mut address = cursor as libc::mach_vm_address_t;
            let mut size = 0 as libc::mach_vm_size_t;
            let mut info = VmRegionSubmapInfo64::default();
            let mut info_count = VM_REGION_SUBMAP_INFO_COUNT_64;
            let result = unsafe {
                mach_vm_region_recurse(
                    mach_task_self_,
                    &mut address,
                    &mut size,
                    &mut nesting_depth,
                    &mut info as *mut VmRegionSubmapInfo64 as *mut libc::integer_t,
                    &mut info_count,
                )
            };
            if result != 0 || size == 0 {
                return Err(Error::State(format!(
                    "mach_vm_region_recurse failed at {cursor:#x}: kern_return={result}"
                )));
            }
            if info.is_submap != 0 {
                nesting_depth = nesting_depth
                    .checked_add(1)
                    .ok_or_else(|| Error::State("Mach VM nesting depth overflow".into()))?;
                continue;
            }
            let start =
                usize::try_from(address).map_err(|_| Error::State("Mach region start does not fit usize".into()))?;
            let size = usize::try_from(size).map_err(|_| Error::State("Mach region size does not fit usize".into()))?;
            let end = start
                .checked_add(size)
                .ok_or_else(|| Error::State("Mach region range overflow".into()))?;
            return Ok(ReadableRegion {
                start,
                end,
                protection: info.protection,
            });
        }
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
                let abi = classify_swift_abi_type(&type_name);

                Some(SwiftType {
                    module_name: symbol.module_name,
                    module_base: symbol.module_base,
                    type_name,
                    type_representation: abi.type_representation.to_string(),
                    object_representation: abi.object_representation.to_string(),
                    abi_argument_kind: abi.argument_kind.to_string(),
                    abi_pass_mode: abi.pass_mode.to_string(),
                    abi_call_supported: false,
                    abi_call_reason: SWIFT_ABI_CALL_UNSUPPORTED_REASON.to_string(),
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

    pub fn find_swift_metadata(module_name: Option<&str>, query: &str) -> Result<Vec<SwiftType>> {
        let trimmed = query.trim();
        if trimmed.is_empty() {
            return Err(Error::InvalidArgument(
                "swift metadata query must not be empty; use `swift.metadata <type>` or `swift.metadata <module> -- <type>`"
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

                let source_kind = infer_swift_type_source_kind(symbol.demangled_name.as_deref());
                if !matches!(
                    source_kind,
                    "metadata" | "metadata-accessor" | "metadata-cache" | "nominal-descriptor"
                ) {
                    return None;
                }
                let abi = classify_swift_abi_type(&type_name);

                Some(SwiftType {
                    module_name: symbol.module_name,
                    module_base: symbol.module_base,
                    type_name,
                    type_representation: abi.type_representation.to_string(),
                    object_representation: abi.object_representation.to_string(),
                    abi_argument_kind: abi.argument_kind.to_string(),
                    abi_pass_mode: abi.pass_mode.to_string(),
                    abi_call_supported: false,
                    abi_call_reason: SWIFT_ABI_CALL_UNSUPPORTED_REASON.to_string(),
                    source_symbol_name: symbol.symbol_name,
                    source_demangled_name: symbol.demangled_name,
                    source_kind: source_kind.to_string(),
                    source_address: symbol.address,
                    source_offset: symbol.offset,
                })
            })
            .collect::<Vec<_>>();
        dedup_and_sort_types(&mut matches);
        Ok(matches)
    }

    pub fn find_swift_conformances(module_name: Option<&str>, query: &str) -> Result<Vec<SwiftConformance>> {
        let trimmed = query.trim();
        if trimmed.is_empty() {
            return Err(Error::InvalidArgument(
                "swift conformance query must not be empty; use `swift.conformances <type>` or `swift.conformances <module> -- <type>`"
                    .into(),
            ));
        }

        let mut matches = collect_swift_symbols(module_name)?
            .into_iter()
            .filter_map(|symbol| {
                let (type_name, protocol_name) = extract_swift_conformance(symbol.demangled_name.as_deref())?;
                if !query_matches_swift_type(&type_name, trimmed) {
                    return None;
                }
                let source_kind = infer_swift_conformance_source_kind(symbol.demangled_name.as_deref()).to_string();

                Some(SwiftConformance {
                    module_name: symbol.module_name,
                    module_base: symbol.module_base,
                    type_name,
                    protocol_name,
                    source_symbol_name: symbol.symbol_name,
                    source_demangled_name: symbol.demangled_name,
                    source_kind,
                    source_address: symbol.address,
                    source_offset: symbol.offset,
                })
            })
            .collect::<Vec<_>>();
        dedup_and_sort_conformances(&mut matches);
        Ok(matches)
    }

    pub fn find_swift_vtable(module_name: Option<&str>, query: &str) -> Result<Vec<SwiftVtableEntry>> {
        let trimmed = query.trim();
        if trimmed.is_empty() {
            return Err(Error::InvalidArgument(
                "swift vtable query must not be empty; use `swift.vtable <type>` or `swift.vtable <module> -- <type>`"
                    .into(),
            ));
        }

        let mut matches = collect_swift_symbols(module_name)?
            .into_iter()
            .filter_map(|symbol| {
                let (type_name, member_name, source_kind) =
                    extract_swift_vtable_parts(symbol.demangled_name.as_deref())?;
                if !query_matches_swift_type(&type_name, trimmed) {
                    return None;
                }

                Some(SwiftVtableEntry {
                    module_name: symbol.module_name,
                    module_base: symbol.module_base,
                    type_name,
                    member_name,
                    symbol_name: symbol.symbol_name,
                    demangled_name: symbol.demangled_name,
                    source_kind: source_kind.to_string(),
                    address: symbol.address,
                    offset: symbol.offset,
                    is_dispatch_thunk: source_kind == "dispatch-thunk",
                })
            })
            .collect::<Vec<_>>();
        dedup_and_sort_vtable_entries(&mut matches);
        Ok(matches)
    }

    pub fn find_swift_witness_tables(module_name: Option<&str>, query: &str) -> Result<Vec<SwiftWitnessTable>> {
        let trimmed = query.trim();
        if trimmed.is_empty() {
            return Err(Error::InvalidArgument(
                "swift witness-table query must not be empty; use `swift.witnessTable <type|protocol>` or `swift.witnessTable <module> -- <type|protocol>`"
                    .into(),
            ));
        }

        let mut matches = collect_swift_symbols(module_name)?
            .into_iter()
            .filter_map(|symbol| {
                let (type_name, protocol_name) = extract_swift_conformance(symbol.demangled_name.as_deref())?;
                let source_kind = infer_swift_conformance_source_kind(symbol.demangled_name.as_deref());
                if !matches!(
                    source_kind,
                    "protocol-witness-table" | "protocol-witness-table-accessor" | "protocol-witness"
                ) {
                    return None;
                }
                if !query_matches_swift_conformance_query(&type_name, &protocol_name, trimmed) {
                    return None;
                }

                Some(SwiftWitnessTable {
                    module_name: symbol.module_name,
                    module_base: symbol.module_base,
                    type_name,
                    protocol_name,
                    symbol_name: symbol.symbol_name,
                    demangled_name: symbol.demangled_name,
                    source_kind: source_kind.to_string(),
                    address: symbol.address,
                    offset: symbol.offset,
                    is_accessor: source_kind == "protocol-witness-table-accessor",
                })
            })
            .collect::<Vec<_>>();
        dedup_and_sort_witness_tables(&mut matches);
        Ok(matches)
    }

    pub fn find_swift_type_layouts(module_name: Option<&str>, query: &str) -> Result<Vec<SwiftTypeLayout>> {
        let trimmed = query.trim();
        if trimmed.is_empty() {
            return Err(Error::InvalidArgument(
                "swift type-layout query must not be empty; use `swift.typeLayout <type>` or `swift.typeLayout <module> -- <type>`"
                    .into(),
            ));
        }

        let mut layouts = BTreeMap::<(String, String), SwiftTypeLayout>::new();
        let symbols = collect_swift_symbols(module_name)?;
        for symbol in symbols {
            let demangled_name = symbol.demangled_name.as_deref();

            if let Some(type_name) = extract_swift_type_name(&symbol.symbol_name, demangled_name) {
                if query_matches_swift_type(&type_name, trimmed) {
                    let source_kind = infer_swift_type_source_kind(demangled_name);
                    if matches!(
                        source_kind,
                        "metadata"
                            | "metadata-accessor"
                            | "nominal-descriptor"
                            | "metadata-cache"
                            | "associated-type-descriptor"
                    ) {
                        let layout =
                            ensure_type_layout(&mut layouts, &symbol.module_name, symbol.module_base, &type_name);
                        let abi = classify_swift_abi_type(&type_name);
                        let type_info = SwiftType {
                            module_name: symbol.module_name.clone(),
                            module_base: symbol.module_base,
                            type_name,
                            type_representation: abi.type_representation.to_string(),
                            object_representation: abi.object_representation.to_string(),
                            abi_argument_kind: abi.argument_kind.to_string(),
                            abi_pass_mode: abi.pass_mode.to_string(),
                            abi_call_supported: false,
                            abi_call_reason: SWIFT_ABI_CALL_UNSUPPORTED_REASON.to_string(),
                            source_symbol_name: symbol.symbol_name.clone(),
                            source_demangled_name: symbol.demangled_name.clone(),
                            source_kind: source_kind.to_string(),
                            source_address: symbol.address,
                            source_offset: symbol.offset,
                        };
                        match source_kind {
                            "metadata" => layout.metadata.push(type_info),
                            "metadata-accessor" => layout.metadata_accessors.push(type_info),
                            "nominal-descriptor" => layout.nominal_descriptors.push(type_info),
                            "metadata-cache" => layout.metadata_caches.push(type_info),
                            "associated-type-descriptor" => layout.associated_type_descriptors.push(type_info),
                            _ => {}
                        }
                    }
                }
            }

            if let Some((type_name, member_name, source_kind)) = extract_swift_vtable_parts(demangled_name) {
                if query_matches_swift_type(&type_name, trimmed) {
                    let layout = ensure_type_layout(&mut layouts, &symbol.module_name, symbol.module_base, &type_name);
                    layout.vtable_entries.push(SwiftVtableEntry {
                        module_name: symbol.module_name.clone(),
                        module_base: symbol.module_base,
                        type_name,
                        member_name,
                        symbol_name: symbol.symbol_name.clone(),
                        demangled_name: symbol.demangled_name.clone(),
                        source_kind: source_kind.to_string(),
                        address: symbol.address,
                        offset: symbol.offset,
                        is_dispatch_thunk: source_kind == "dispatch-thunk",
                    });
                }
            }

            if let Some((type_name, protocol_name)) = extract_swift_conformance(demangled_name) {
                if query_matches_swift_type(&type_name, trimmed) {
                    let source_kind = infer_swift_conformance_source_kind(demangled_name);
                    if matches!(
                        source_kind,
                        "protocol-witness-table" | "protocol-witness-table-accessor" | "protocol-witness"
                    ) {
                        let layout =
                            ensure_type_layout(&mut layouts, &symbol.module_name, symbol.module_base, &type_name);
                        layout.witness_tables.push(SwiftWitnessTable {
                            module_name: symbol.module_name.clone(),
                            module_base: symbol.module_base,
                            type_name,
                            protocol_name,
                            symbol_name: symbol.symbol_name.clone(),
                            demangled_name: symbol.demangled_name.clone(),
                            source_kind: source_kind.to_string(),
                            address: symbol.address,
                            offset: symbol.offset,
                            is_accessor: source_kind == "protocol-witness-table-accessor",
                        });
                    }
                }
            }
        }

        let mut results = layouts.into_values().collect::<Vec<_>>();
        for layout in &mut results {
            dedup_and_sort_types(&mut layout.metadata);
            dedup_and_sort_types(&mut layout.metadata_accessors);
            dedup_and_sort_types(&mut layout.nominal_descriptors);
            dedup_and_sort_types(&mut layout.metadata_caches);
            dedup_and_sort_types(&mut layout.associated_type_descriptors);
            dedup_and_sort_vtable_entries(&mut layout.vtable_entries);
            dedup_and_sort_witness_tables(&mut layout.witness_tables);
        }
        results.sort_by(|left, right| {
            left.module_name
                .cmp(&right.module_name)
                .then(left.type_name.cmp(&right.type_name))
        });
        Ok(results)
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
                let abi = classify_swift_abi_type(&owner_type);

                Some(SwiftType {
                    module_name: symbol.module_name,
                    module_base: symbol.module_base,
                    type_name: owner_type,
                    type_representation: abi.type_representation.to_string(),
                    object_representation: abi.object_representation.to_string(),
                    abi_argument_kind: abi.argument_kind.to_string(),
                    abi_pass_mode: abi.pass_mode.to_string(),
                    abi_call_supported: false,
                    abi_call_reason: SWIFT_ABI_CALL_UNSUPPORTED_REASON.to_string(),
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

    fn dedup_and_sort_vtable_entries(matches: &mut Vec<SwiftVtableEntry>) {
        matches.sort_by(|left, right| {
            left.module_name
                .cmp(&right.module_name)
                .then(left.type_name.cmp(&right.type_name))
                .then(left.member_name.cmp(&right.member_name))
                .then(left.is_dispatch_thunk.cmp(&right.is_dispatch_thunk))
                .then(left.address.cmp(&right.address))
                .then(left.symbol_name.cmp(&right.symbol_name))
        });
        matches.dedup_by(|left, right| {
            left.module_name == right.module_name
                && left.address == right.address
                && left.symbol_name == right.symbol_name
        });
    }

    fn dedup_and_sort_witness_tables(matches: &mut Vec<SwiftWitnessTable>) {
        matches.sort_by(|left, right| {
            left.module_name
                .cmp(&right.module_name)
                .then(left.type_name.cmp(&right.type_name))
                .then(left.protocol_name.cmp(&right.protocol_name))
                .then(left.source_kind.cmp(&right.source_kind))
                .then(left.address.cmp(&right.address))
                .then(left.symbol_name.cmp(&right.symbol_name))
        });
        matches.dedup_by(|left, right| {
            left.module_name == right.module_name
                && left.address == right.address
                && left.symbol_name == right.symbol_name
        });
    }

    fn ensure_type_layout<'a>(
        layouts: &'a mut BTreeMap<(String, String), SwiftTypeLayout>,
        module_name: &str,
        module_base: usize,
        type_name: &str,
    ) -> &'a mut SwiftTypeLayout {
        layouts
            .entry((module_name.to_string(), type_name.to_string()))
            .or_insert_with(|| SwiftTypeLayout {
                module_name: module_name.to_string(),
                module_base,
                type_name: type_name.to_string(),
                metadata: Vec::new(),
                metadata_accessors: Vec::new(),
                nominal_descriptors: Vec::new(),
                metadata_caches: Vec::new(),
                associated_type_descriptors: Vec::new(),
                vtable_entries: Vec::new(),
                witness_tables: Vec::new(),
            })
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
                LC_SYMTAB => {
                    if command_size < size_of::<SymtabCommand>() {
                        consumed += command_size;
                        command_ptr = unsafe { command_ptr.add(command_size) };
                        continue;
                    }

                    let table = unsafe { &*(command_ptr as *const SymtabCommand) };
                    symtab = Some(table);
                }
                _ => {}
            }

            consumed += command_size;
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

    fn dedup_and_sort_conformances(matches: &mut Vec<SwiftConformance>) {
        matches.sort_by(|left, right| {
            left.module_name
                .cmp(&right.module_name)
                .then(left.type_name.cmp(&right.type_name))
                .then(left.protocol_name.cmp(&right.protocol_name))
                .then(left.source_symbol_name.cmp(&right.source_symbol_name))
        });
        matches.dedup_by(|left, right| {
            left.module_name == right.module_name
                && left.type_name == right.type_name
                && left.protocol_name == right.protocol_name
        });
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

    use super::{
        SwiftConformance, SwiftLiveObjectInfo, SwiftObjectOwnership, SwiftProtocol, SwiftSymbol, SwiftType,
        SwiftTypeLayout, SwiftVtableEntry, SwiftWitnessTable,
    };

    pub fn swift_support_available() -> bool {
        false
    }

    pub fn inspect_swift_live_object(
        _object_address: usize,
        _metadata_address: Option<usize>,
        _ownership: SwiftObjectOwnership,
    ) -> Result<SwiftLiveObjectInfo> {
        Err(Error::Unsupported(
            "Swift live object inspection is only available on Apple targets".into(),
        ))
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

    pub fn find_swift_metadata(_module_name: Option<&str>, _query: &str) -> Result<Vec<SwiftType>> {
        Err(Error::Unsupported(
            "Swift symbol lookup is only available on Apple targets".into(),
        ))
    }

    pub fn find_swift_conformances(_module_name: Option<&str>, _query: &str) -> Result<Vec<SwiftConformance>> {
        Err(Error::Unsupported(
            "Swift symbol lookup is only available on Apple targets".into(),
        ))
    }

    pub fn find_swift_vtable(_module_name: Option<&str>, _query: &str) -> Result<Vec<SwiftVtableEntry>> {
        Err(Error::Unsupported(
            "Swift symbol lookup is only available on Apple targets".into(),
        ))
    }

    pub fn find_swift_witness_tables(_module_name: Option<&str>, _query: &str) -> Result<Vec<SwiftWitnessTable>> {
        Err(Error::Unsupported(
            "Swift symbol lookup is only available on Apple targets".into(),
        ))
    }

    pub fn find_swift_type_layouts(_module_name: Option<&str>, _query: &str) -> Result<Vec<SwiftTypeLayout>> {
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
        classify_swift_abi_type, extract_swift_conformance, extract_swift_member_name, extract_swift_member_owner_type,
        extract_swift_protocol_name, extract_swift_type_name, extract_swift_vtable_parts,
        infer_swift_conformance_source_kind, infer_swift_protocol_source_kind, infer_swift_type_source_kind,
        looks_like_swift_symbol, normalize_swift_type_source_kind, query_matches_swift_conformance_query,
        query_matches_swift_member_name, query_matches_swift_method, query_matches_swift_type, query_matches_symbol,
        swift_conformance_names_match, swift_member_name_matches, swift_protocol_name_matches, swift_type_name_matches,
        validate_swift_metadata_identity,
    };

    #[test]
    fn validates_swift_metadata_identity_and_source() {
        let inferred = validate_swift_metadata_identity(0x1000, None).expect("infer metadata");
        assert_eq!(inferred.address, 0x1000);
        assert!(inferred.inferred);
        assert!(inferred.verified);

        let explicit = validate_swift_metadata_identity(0x1000, Some(0x1000)).expect("verify metadata");
        assert_eq!(explicit.address, 0x1000);
        assert!(!explicit.inferred);
        assert!(explicit.verified);

        let mismatch = validate_swift_metadata_identity(0x1000, Some(0x2000)).unwrap_err();
        assert!(mismatch.to_string().contains("does not match object first word 0x1000"));
    }

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
                "_$s4Demo14ViewControllerCN",
                Some("type metadata for Demo.ViewController")
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
    fn extracts_swift_conformances_from_demangled_symbols() {
        assert_eq!(
            extract_swift_conformance(Some(
                "protocol conformance descriptor for Demo.ViewController : Demo.Renderable in Demo"
            )),
            Some(("Demo.ViewController".into(), "Demo.Renderable".into()))
        );
        assert_eq!(
            extract_swift_conformance(Some(
                "protocol witness table for Demo.ViewController : Swift.Hashable in Demo"
            )),
            Some(("Demo.ViewController".into(), "Swift.Hashable".into()))
        );
        assert_eq!(
            extract_swift_conformance(Some("protocol witness table accessor for Swift.Optional<A> : Swift.Equatable where A : Swift.Equatable in Swift")),
            Some(("Swift.Optional<A>".into(), "Swift.Equatable".into()))
        );
        assert_eq!(
            extract_swift_conformance(Some("protocol descriptor for Demo.Renderable")),
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
    fn public_swift_info_matchers_accept_partial_names() {
        assert!(swift_type_name_matches("Demo.ViewController", "ViewController"));
        assert!(swift_protocol_name_matches("Demo.Renderable", "renderable"));
        assert!(swift_conformance_names_match(
            "Demo.ViewController",
            "Demo.Renderable",
            "viewcontroller",
            "render"
        ));
        assert!(swift_member_name_matches("viewDidLoad", "didload"));
        assert!(!swift_conformance_names_match(
            "Demo.ViewController",
            "Demo.Renderable",
            "viewcontroller",
            "hashable"
        ));
    }

    #[test]
    fn matches_swift_conformance_query_against_type_or_protocol_name() {
        assert!(query_matches_swift_conformance_query(
            "Demo.ViewController",
            "Demo.Renderable",
            "ViewController"
        ));
        assert!(query_matches_swift_conformance_query(
            "Demo.ViewController",
            "Demo.Renderable",
            "Renderable"
        ));
        assert!(!query_matches_swift_conformance_query(
            "Demo.ViewController",
            "Demo.Renderable",
            "Hashable"
        ));
    }

    #[test]
    fn extracts_swift_vtable_parts_from_members_and_dispatch_thunks() {
        assert_eq!(
            extract_swift_vtable_parts(Some("Demo.ViewController.viewDidLoad() -> ()")),
            Some(("Demo.ViewController".into(), "viewDidLoad".into(), "member"))
        );
        assert_eq!(
            extract_swift_vtable_parts(Some("dispatch thunk of Demo.ViewController.viewDidLoad() -> ()")),
            Some(("Demo.ViewController".into(), "viewDidLoad".into(), "dispatch-thunk"))
        );
        assert_eq!(
            extract_swift_vtable_parts(Some("type metadata accessor for Demo.ViewController")),
            None
        );
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
            infer_swift_type_source_kind(Some("type metadata for Demo.ViewController")),
            "metadata"
        );
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
    fn infers_swift_conformance_source_kind_from_demangled_names() {
        assert_eq!(
            infer_swift_conformance_source_kind(Some(
                "protocol conformance descriptor for Demo.ViewController : Demo.Renderable in Demo"
            )),
            "protocol-conformance-descriptor"
        );
        assert_eq!(
            infer_swift_conformance_source_kind(Some(
                "protocol witness table for Demo.ViewController : Demo.Renderable in Demo"
            )),
            "protocol-witness-table"
        );
        assert_eq!(
            infer_swift_conformance_source_kind(Some(
                "protocol witness table accessor for Demo.ViewController : Demo.Renderable in Demo"
            )),
            "protocol-witness-table-accessor"
        );
        assert_eq!(
            infer_swift_conformance_source_kind(Some(
                "protocol witness for Demo.ViewController : Demo.Renderable in Demo"
            )),
            "protocol-witness"
        );
        assert_eq!(infer_swift_conformance_source_kind(None), "symbol");
    }

    #[test]
    fn normalizes_swift_type_source_kind_aliases() {
        assert_eq!(normalize_swift_type_source_kind("full-metadata"), Some("metadata"));
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

    #[test]
    fn classifies_swift_type_and_object_representations_conservatively() {
        let scalar = classify_swift_abi_type("Swift.Int64");
        assert_eq!(scalar.type_representation, "scalar");
        assert_eq!(scalar.object_representation, "inline-value");
        assert_eq!(scalar.argument_kind, "integer");
        assert_eq!(scalar.pass_mode, "direct-scalar");

        let pointer = classify_swift_abi_type("Swift.UnsafeMutablePointer<Swift.Int>");
        assert_eq!(pointer.object_representation, "raw-pointer");
        assert_eq!(pointer.pass_mode, "direct-pointer");

        let existential = classify_swift_abi_type("any Demo.Renderable");
        assert_eq!(existential.type_representation, "existential");
        assert_eq!(existential.object_representation, "existential-container");
        assert_eq!(existential.pass_mode, "metadata-dependent");

        let nominal = classify_swift_abi_type("Demo.ViewController");
        assert_eq!(nominal.type_representation, "nominal");
        assert_eq!(nominal.object_representation, "metadata-dependent");
        assert_eq!(nominal.argument_kind, "nominal-value-or-reference");
    }

    #[test]
    fn classifies_hidden_context_swift_abi_shapes_without_claiming_calls() {
        let metatype = classify_swift_abi_type("Demo.ViewController.Type");
        assert_eq!(metatype.argument_kind, "metatype");
        assert_eq!(metatype.object_representation, "metadata-pointer");

        let function = classify_swift_abi_type("(Swift.Int) -> Swift.String");
        assert_eq!(function.argument_kind, "function");
        assert_eq!(function.object_representation, "thick-function");
        assert_eq!(function.pass_mode, "context-dependent");

        let tuple = classify_swift_abi_type("(Swift.Int, Swift.Int)");
        assert_eq!(tuple.argument_kind, "aggregate");
        assert_eq!(tuple.pass_mode, "layout-dependent");
    }

    #[test]
    fn classifies_swift_scalar_edge_cases_from_one_table() {
        let cases = [
            ("Swift.Never", "noreturn", "noreturn", "unsupported"),
            ("Swift.CInt", "scalar", "integer", "direct-scalar"),
            ("Swift.Float16", "scalar", "floating-point", "direct-scalar"),
            ("Swift.Float80", "scalar", "floating-point", "direct-scalar"),
        ];

        for (type_name, representation, argument_kind, pass_mode) in cases {
            let info = classify_swift_abi_type(type_name);
            assert_eq!(info.type_representation, representation, "{type_name}");
            assert_eq!(info.argument_kind, argument_kind, "{type_name}");
            assert_eq!(info.pass_mode, pass_mode, "{type_name}");
        }
    }
}
