use crate::context::JSContext;
use crate::ffi;
use crate::ptr::{create_native_pointer, get_native_pointer_addr};
use crate::util::{
    add_cfunction_to_object, js_throw_internal_error, js_throw_range_error, js_throw_type_error, require_string_arg,
};
use crate::value::JSValue;
use common::Error as CommonError;
use native_api::{
    find_swift_conformances, find_swift_metadata, find_swift_method_owners, find_swift_methods, find_swift_protocols,
    find_swift_symbols, find_swift_type_layouts, find_swift_type_methods, find_swift_types, find_swift_types_of_kind,
    find_swift_vtable, find_swift_witness_tables, inspect_swift_live_object, swift_conformance_names_match,
    swift_demangle_symbol, swift_member_name_matches, swift_protocol_name_matches, swift_support_available,
    swift_type_name_matches, swift_type_source_kinds, SwiftConformance,
    SwiftObjectOwnership as NativeSwiftObjectOwnership, SwiftProtocol, SwiftSymbol, SwiftType, SwiftTypeLayout,
    SwiftVtableEntry, SwiftWitnessTable,
};
use std::ffi::c_void;
#[cfg(any(target_os = "ios", target_os = "macos"))]
use std::ffi::CString;
use std::sync::atomic::{AtomicU32, Ordering};

const MAX_SWIFT_ABI_ARGUMENTS: usize = 64;
const SWIFT_RUNTIME_CALL_UNSUPPORTED_REASON: &str = "Swift object access and ABI invocation are metadata-only: verified runtime metadata, ownership conventions, generic context, and hidden ABI arguments are required";
const SWIFT_OBJECT_DISPOSED_ERROR: &str = "Swift object wrapper has been disposed";
static SWIFT_OBJECT_CLASS_ID: AtomicU32 = AtomicU32::new(0);
const SWIFT_OBJECT_CLASS_NAME: &[u8] = b"IOSRustFridaSwiftObject\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SwiftObjectOwnership {
    Borrowed,
    Adopt,
    Retain,
}

impl SwiftObjectOwnership {
    fn name(self) -> &'static str {
        match self {
            Self::Borrowed => "borrowed",
            Self::Adopt => "adopted",
            Self::Retain => "retained",
        }
    }
}

impl From<SwiftObjectOwnership> for NativeSwiftObjectOwnership {
    fn from(value: SwiftObjectOwnership) -> Self {
        match value {
            SwiftObjectOwnership::Borrowed => Self::Borrowed,
            SwiftObjectOwnership::Adopt => Self::Adopt,
            SwiftObjectOwnership::Retain => Self::Retain,
        }
    }
}

unsafe fn swift_object_backend_info(
    ctx: *mut ffi::JSContext,
    object_address: usize,
    metadata_address: Option<usize>,
    ownership: SwiftObjectOwnership,
) -> Result<native_api::SwiftLiveObjectInfo, ffi::JSValue> {
    inspect_swift_live_object(object_address, metadata_address, ownership.into()).map_err(|error| match error {
        CommonError::InvalidArgument(message) => js_throw_type_error(ctx, &message),
        other => js_throw_internal_error(ctx, &other.to_string()),
    })
}

struct SwiftObjectState {
    object_address: usize,
    metadata_address: usize,
    metadata_inferred: bool,
    metadata_verified: bool,
    type_name: Option<String>,
    ownership: SwiftObjectOwnership,
    owned_references: usize,
    release_address: Option<usize>,
    retain_available: bool,
    release_available: bool,
    disposed: bool,
}

impl SwiftObjectState {
    fn is_disposed(&self) -> bool {
        self.disposed || self.object_address == 0
    }

    fn ownership_name(&self) -> &'static str {
        if self.is_disposed() {
            "disposed"
        } else {
            self.ownership.name()
        }
    }

    fn metadata_source_name(&self) -> &'static str {
        if self.is_disposed() {
            "none"
        } else if self.metadata_inferred {
            "inferred"
        } else {
            "explicit"
        }
    }

    fn mark_disposed(&mut self) -> bool {
        let was_live = !self.is_disposed();
        self.disposed = true;
        self.object_address = 0;
        self.metadata_address = 0;
        self.owned_references = 0;
        self.release_address = None;
        was_live
    }
}

#[cfg(any(target_os = "ios", target_os = "macos"))]
fn swift_runtime_symbol(name: &str) -> Option<usize> {
    let name = CString::new(name).ok()?;
    let address = unsafe { libc::dlsym(libc::RTLD_DEFAULT, name.as_ptr()) };
    (!address.is_null()).then_some(address as usize)
}

#[cfg(not(any(target_os = "ios", target_os = "macos")))]
fn swift_runtime_symbol(_name: &str) -> Option<usize> {
    None
}

fn swift_runtime_ownership_available() -> (bool, bool) {
    (
        swift_runtime_symbol("swift_retain").is_some(),
        swift_runtime_symbol("swift_release").is_some(),
    )
}

unsafe fn swift_release_references(state: &mut SwiftObjectState) {
    if state.object_address == 0 || state.owned_references == 0 {
        state.owned_references = 0;
        return;
    }
    let Some(address) = state.release_address else {
        state.owned_references = 0;
        return;
    };
    let release: unsafe extern "C" fn(*const c_void) = std::mem::transmute(address);
    for _ in 0..state.owned_references {
        release(state.object_address as *const c_void);
    }
    state.owned_references = 0;
}

unsafe extern "C" fn swift_object_finalizer(_runtime: *mut ffi::JSRuntime, value: ffi::JSValue) {
    let class_id = SWIFT_OBJECT_CLASS_ID.load(Ordering::Acquire);
    if class_id == 0 {
        return;
    }
    let opaque = ffi::JS_GetOpaque(value, class_id);
    if !opaque.is_null() {
        let mut state = Box::from_raw(opaque as *mut SwiftObjectState);
        swift_release_references(&mut state);
    }
}

fn get_or_init_swift_object_class_id(ctx: *mut ffi::JSContext) -> Result<u32, String> {
    let mut class_id = SWIFT_OBJECT_CLASS_ID.load(Ordering::Acquire);
    if class_id == 0 {
        let mut candidate = 0u32;
        unsafe { ffi::JS_NewClassID(&mut candidate) };
        match SWIFT_OBJECT_CLASS_ID.compare_exchange(0, candidate, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => class_id = candidate,
            Err(existing) => class_id = existing,
        }
    }

    unsafe {
        let runtime = ffi::JS_GetRuntime(ctx);
        if ffi::JS_IsRegisteredClass(runtime, class_id) == 0 {
            let class_def = ffi::JSClassDef {
                class_name: SWIFT_OBJECT_CLASS_NAME.as_ptr() as *const _,
                finalizer: Some(swift_object_finalizer),
                gc_mark: None,
                call: None,
                exotic: std::ptr::null_mut(),
            };
            if ffi::JS_NewClass(runtime, class_id, &class_def) != 0 {
                return Err("failed to register QuickJS Swift object class".into());
            }
        }
    }
    Ok(class_id)
}

unsafe fn swift_object_state_any(
    ctx: *mut ffi::JSContext,
    value: ffi::JSValue,
) -> Result<*mut SwiftObjectState, ffi::JSValue> {
    let class_id = SWIFT_OBJECT_CLASS_ID.load(Ordering::Acquire);
    if class_id == 0 {
        return Err(js_throw_type_error(ctx, "value is not a Swift object wrapper"));
    }
    let opaque = ffi::JS_GetOpaque(value, class_id);
    if opaque.is_null() {
        return Err(js_throw_type_error(ctx, "value is not a Swift object wrapper"));
    }
    let state = opaque as *mut SwiftObjectState;
    Ok(state)
}

unsafe fn swift_object_state(
    ctx: *mut ffi::JSContext,
    value: ffi::JSValue,
) -> Result<*mut SwiftObjectState, ffi::JSValue> {
    let state = swift_object_state_any(ctx, value)?;
    if (*state).is_disposed() {
        return Err(js_throw_type_error(ctx, SWIFT_OBJECT_DISPOSED_ERROR));
    }
    Ok(state)
}

unsafe fn create_swift_object_wrapper(ctx: *mut ffi::JSContext, mut state: SwiftObjectState) -> ffi::JSValue {
    let class_id = match get_or_init_swift_object_class_id(ctx) {
        Ok(value) => value,
        Err(error) => {
            swift_release_references(&mut state);
            return js_throw_internal_error(ctx, &error);
        }
    };
    let object = ffi::JS_NewObjectClass(ctx, class_id as i32);
    if ffi::qjs_is_exception(object) != 0 {
        swift_release_references(&mut state);
        return object;
    }
    ffi::JS_SetOpaque(object, Box::into_raw(Box::new(state)).cast());
    object
}

unsafe fn swift_pointer_argument(ctx: *mut ffi::JSContext, value: JSValue, label: &str) -> Result<usize, ffi::JSValue> {
    if let Some(address) = get_native_pointer_addr(value) {
        if address == 0 {
            return Err(js_throw_type_error(ctx, &format!("{label} must not be null")));
        }
        return Ok(address as usize);
    }
    let Some(address) = value.to_u64(ctx) else {
        return Err(js_throw_type_error(
            ctx,
            &format!("{label} must be a NativePointer or integer"),
        ));
    };
    if address == 0 {
        return Err(js_throw_type_error(ctx, &format!("{label} must not be null")));
    }
    Ok(address as usize)
}

unsafe fn optional_pointer_argument(
    ctx: *mut ffi::JSContext,
    value: JSValue,
    label: &str,
) -> Result<Option<usize>, ffi::JSValue> {
    if value.is_null() || value.is_undefined() {
        return Ok(None);
    }
    swift_pointer_argument(ctx, value, label).map(Some)
}
const SWIFT_THIN_CALL_BOOTSTRAP: &str = r#"
(function () {
    'use strict';
    const api = globalThis.Swift;
    if (!api) return;

    const originalStatus = api.status;
    const MAX_ARGUMENTS = 64;

    function normalizeType(typeName, role) {
        if (typeof typeName !== 'string' || typeName.trim().length === 0) {
            throw new TypeError('Swift thin ABI ' + role + ' type must be a non-empty string');
        }
        const compact = typeName.trim();
        const unqualified = compact.indexOf('Swift.') === 0 ? compact.slice(6) : compact;
        const base = unqualified.split('.').pop();

        if (compact === '()' || base === 'Void') return 'void';
        if (base === 'Never') {
            throw new TypeError('Swift thin ABI ' + role + ' type Never is non-returning and is not a C-compatible call shape');
        }
        if (base === 'Bool') return 'bool';
        if (base === 'Int' || base === 'CLong') return 'int64';
        if (base === 'UInt' || base === 'CULong') return 'uint64';
        if (base === 'Int8') return 'int8';
        if (base === 'UInt8') return 'uint8';
        if (base === 'Int16') return 'int16';
        if (base === 'UInt16') return 'uint16';
        if (base === 'Int32') return 'int32';
        if (base === 'UInt32') return 'uint32';
        if (base === 'Int64') return 'int64';
        if (base === 'UInt64') return 'uint64';
        if (base === 'CChar' || base === 'CSignedChar') return 'int8';
        if (base === 'CUnsignedChar') return 'uint8';
        if (base === 'CShort') return 'int16';
        if (base === 'CUShort') return 'uint16';
        if (base === 'CInt') return 'int32';
        if (base === 'CUInt') return 'uint32';
        if (base === 'Float' || base === 'CFloat') return 'float';
        if (base === 'Double' || base === 'CDouble') return 'double';
        if (base === 'Float16' || base === 'Float80') {
            throw new TypeError('Swift thin ABI ' + role + ' type ' + compact + ' is not supported by the AAPCS64 NativeFunction backend');
        }
        if (unqualified.indexOf('UnsafePointer<') === 0 ||
            unqualified.indexOf('UnsafeMutablePointer<') === 0 ||
            unqualified.indexOf('AutoreleasingUnsafeMutablePointer<') === 0 ||
            base === 'OpaquePointer' || base === 'UnsafeRawPointer' ||
            base === 'UnsafeMutableRawPointer') return 'pointer';

        throw new TypeError(
            'Swift thin ABI ' + role + ' type ' + compact +
            ' requires metadata, ownership, or hidden ABI arguments'
        );
    }

    function validateOptions(options) {
        const value = options == null ? {} : options;
        if (typeof value !== 'object' || Array.isArray(value)) {
            throw new TypeError('Swift thin ABI options must be an object');
        }
        if (value.abi !== 'c-compatible' || value.verified !== true) {
            throw new TypeError(
                "Swift thin ABI requires options { abi: 'c-compatible', verified: true }"
            );
        }
        ['async', 'throws', 'generic', 'indirectResult'].forEach(function (name) {
            if (value[name] != null && typeof value[name] !== 'boolean') {
                throw new TypeError('Swift thin ABI option ' + name + ' must be boolean when provided');
            }
            if (value[name] === true) {
                throw new TypeError('Swift thin ABI does not accept ' + name + ' functions');
            }
        });
        if (value.context != null) {
            throw new TypeError('Swift thin ABI does not accept context functions');
        }
        return value;
    }

    function thinSignature(returnType, argumentTypes, options) {
        if (!Array.isArray(argumentTypes)) {
            throw new TypeError('Swift.thinSignature argumentTypes must be an array');
        }
        if (argumentTypes.length > MAX_ARGUMENTS) {
            throw new RangeError('Swift.thinSignature accepts at most ' + MAX_ARGUMENTS + ' arguments');
        }
        validateOptions(options);
        const nativeReturn = normalizeType(returnType, 'return');
        const nativeArguments = argumentTypes.map(function (item, index) {
            const mapped = normalizeType(item, 'argument[' + index + ']');
            if (mapped === 'void') {
                throw new TypeError('Swift thin ABI argument[' + index + '] must not be void');
            }
            return mapped;
        });
        return Object.freeze({
            abi: 'c-compatible-thin',
            verified: true,
            returnType: returnType,
            argumentTypes: Object.freeze(argumentTypes.slice()),
            nativeReturnType: nativeReturn,
            nativeArgumentTypes: Object.freeze(nativeArguments.slice())
        });
    }

    function thinFunction(address, returnType, argumentTypes, options) {
        const signature = thinSignature(returnType, argumentTypes, options);
        if (typeof globalThis.NativeFunction !== 'function') {
            throw new Error('Swift thin ABI requires the NativeFunction AAPCS64 backend');
        }
        const fn = new globalThis.NativeFunction(address, signature.nativeReturnType, signature.nativeArgumentTypes);
        Object.defineProperties(fn, {
            swiftReturnType: { value: signature.returnType, enumerable: true },
            swiftArgumentTypes: { value: signature.argumentTypes, enumerable: true },
            swiftAbi: { value: signature.abi, enumerable: true },
            swiftSignature: { value: signature, enumerable: true }
        });
        return fn;
    }

    function invoke(address, signature, args) {
        if (!signature || typeof signature !== 'object' || Array.isArray(signature)) {
            throw new TypeError('Swift.invoke signature must be an object');
        }
        if (!Array.isArray(args)) throw new TypeError('Swift.invoke args must be an array');
        const fn = thinFunction(address, signature.returnType, signature.argumentTypes, signature);
        if (args.length !== signature.argumentTypes.length) {
            throw new TypeError(
                'Swift.invoke expected ' + signature.argumentTypes.length +
                ' arguments, got ' + args.length
            );
        }
        return fn.apply(null, args);
    }

    api.thinSignature = thinSignature;
    api.thinFunction = thinFunction;
    api.invoke = invoke;
    api.call = invoke;
    api.thinAbiCallAvailable = typeof globalThis.NativeFunction === 'function';
    api.runtimeInvocationAvailable = api.thinAbiCallAvailable;
    api.abiCallAvailable = api.thinAbiCallAvailable;
    api.fullSwiftAbiCallAvailable = false;
    api.liveObjectWrapperAvailable = true;
    api.metadataOnly = !api.thinAbiCallAvailable && !api.liveObjectWrapperAvailable;
    api.status = api.info = api.capabilities = function () {
        const status = originalStatus.call(api);
        status.thinAbiCallAvailable = typeof globalThis.NativeFunction === 'function';
        status.thinAbiRequirements = {
            abi: 'c-compatible',
            verified: true,
            supportedValues: ['void', 'integer', 'floating-point', 'pointer'],
            supportedCTypeAliases: ['CChar', 'CShort', 'CInt', 'CLong', 'CUnsignedChar', 'CUShort', 'CUInt', 'CULong', 'CFloat', 'CDouble'],
            rejectedFeatures: ['async', 'throws', 'generic', 'indirect-result', 'hidden-context']
        };
        status.runtimeInvocationAvailable = status.thinAbiCallAvailable;
        status.abiCallAvailable = status.thinAbiCallAvailable;
        status.fullSwiftAbiCallAvailable = false;
        status.liveObjectWrapperAvailable = true;
        status.metadataOnly = !status.thinAbiCallAvailable && !status.liveObjectWrapperAvailable;
        return status;
    };
})();
"#;
const SWIFT_SUPPORTED_METHODS: &[&str] = &[
    "demangle",
    "findSymbols",
    "symbolInfo",
    "findProtocols",
    "protocolInfo",
    "findConformances",
    "conformanceInfo",
    "findMetadata",
    "metadataInfo",
    "findVtable",
    "vtableInfo",
    "findWitnessTable",
    "witnessTableInfo",
    "findTypeLayout",
    "typeLayoutInfo",
    "findMethods",
    "methodInfo",
    "findTypeMethods",
    "findMethodOwners",
    "findTypesOfKind",
    "findTypes",
    "typeInfo",
    "typeSourceKinds",
    "status",
    "typeRepresentation",
    "objectRepresentation",
    "classifyAbiArgument",
    "classifyAbiArguments",
    "object",
    "metadataOf",
    "thinSignature",
    "thinFunction",
    "invoke",
    "call",
];
const SWIFT_UNSUPPORTED_METHOD_DESCRIPTORS: &[(&str, i32, &str, &str)] = &[
    (
        "construct",
        2,
        "object",
        "ObjC.class for Objective-C-compatible classes",
    ),
    (
        "hookMethod",
        3,
        "hook",
        "Swift.findMethods plus Interceptor.attach after ABI verification",
    ),
    (
        "replaceMethod",
        3,
        "hook",
        "Swift.findMethods plus Interceptor.replace after ABI verification",
    ),
];

#[derive(Debug, Clone, PartialEq, Eq)]
struct SwiftAbiDescriptor {
    type_name: String,
    type_representation: &'static str,
    object_representation: &'static str,
    argument_kind: &'static str,
    pass_mode: &'static str,
}

fn classify_swift_abi_type(type_name: &str) -> Result<SwiftAbiDescriptor, String> {
    let compact = type_name.trim();
    if compact.is_empty() {
        return Err("Swift ABI type name must not be empty".into());
    }
    let unqualified = compact.strip_prefix("Swift.").unwrap_or(compact);
    let base = compact.rsplit('.').next().unwrap_or(compact);
    let shape = if compact == "()" || base == "Void" {
        ("void", "none", "void", "none")
    } else if base == "Never" {
        ("noreturn", "none", "noreturn", "unsupported")
    } else if compact.ends_with(".Type") || compact.ends_with(".Protocol") {
        ("metatype", "metadata-pointer", "metatype", "direct-pointer")
    } else if compact == "Any" || compact == "AnyObject" || compact.starts_with("any ") {
        (
            "existential",
            "existential-container",
            "existential",
            "metadata-dependent",
        )
    } else if compact.contains("->") {
        ("function", "thick-function", "function", "context-dependent")
    } else if compact.starts_with('(') && compact.ends_with(')') {
        ("tuple", "inline-value", "aggregate", "layout-dependent")
    } else if unqualified.starts_with("UnsafePointer<")
        || unqualified.starts_with("UnsafeMutablePointer<")
        || unqualified.starts_with("AutoreleasingUnsafeMutablePointer<")
        || matches!(base, "OpaquePointer" | "UnsafeRawPointer" | "UnsafeMutableRawPointer")
    {
        ("pointer", "raw-pointer", "pointer", "direct-pointer")
    } else if matches!(
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
        let kind = if base.starts_with("Float") || matches!(base, "Double" | "CFloat" | "CDouble") {
            "floating-point"
        } else {
            "integer"
        };
        ("scalar", "inline-value", kind, "direct-scalar")
    } else if compact.starts_with("some ") {
        (
            "opaque-result",
            "metadata-dependent",
            "opaque-value",
            "metadata-dependent",
        )
    } else {
        (
            "nominal",
            "metadata-dependent",
            "nominal-value-or-reference",
            "metadata-dependent",
        )
    };

    Ok(SwiftAbiDescriptor {
        type_name: compact.to_string(),
        type_representation: shape.0,
        object_representation: shape.1,
        argument_kind: shape.2,
        pass_mode: shape.3,
    })
}

unsafe fn swift_symbol_to_js(ctx: *mut ffi::JSContext, symbol: &SwiftSymbol) -> ffi::JSValue {
    let object = JSValue(ffi::JS_NewObject(ctx));
    object.set_property(ctx, "moduleName", JSValue::string(ctx, &symbol.module_name));
    object.set_property(ctx, "moduleBase", create_native_pointer(ctx, symbol.module_base as u64));
    object.set_property(ctx, "name", JSValue::string(ctx, &symbol.symbol_name));
    object.set_property(ctx, "address", create_native_pointer(ctx, symbol.address as u64));
    object.set_property(ctx, "offset", JSValue(ffi::JS_NewBigUint64(ctx, symbol.offset as u64)));

    match &symbol.demangled_name {
        Some(name) => object.set_property(ctx, "demangledName", JSValue::string(ctx, name)),
        None => object.set_property(ctx, "demangledName", JSValue::null()),
    };

    object.raw()
}

unsafe fn swift_type_to_js(ctx: *mut ffi::JSContext, type_info: &SwiftType) -> ffi::JSValue {
    let object = JSValue(ffi::JS_NewObject(ctx));
    object.set_property(ctx, "moduleName", JSValue::string(ctx, &type_info.module_name));
    object.set_property(
        ctx,
        "moduleBase",
        create_native_pointer(ctx, type_info.module_base as u64),
    );
    object.set_property(ctx, "name", JSValue::string(ctx, &type_info.type_name));
    object.set_property(
        ctx,
        "typeRepresentation",
        JSValue::string(ctx, &type_info.type_representation),
    );
    object.set_property(
        ctx,
        "objectRepresentation",
        JSValue::string(ctx, &type_info.object_representation),
    );
    object.set_property(
        ctx,
        "abiArgumentKind",
        JSValue::string(ctx, &type_info.abi_argument_kind),
    );
    object.set_property(ctx, "abiPassMode", JSValue::string(ctx, &type_info.abi_pass_mode));
    object.set_property(ctx, "abiCallSupported", JSValue::bool(type_info.abi_call_supported));
    object.set_property(ctx, "abiCallReason", JSValue::string(ctx, &type_info.abi_call_reason));
    object.set_property(
        ctx,
        "sourceSymbolName",
        JSValue::string(ctx, &type_info.source_symbol_name),
    );
    object.set_property(ctx, "sourceKind", JSValue::string(ctx, &type_info.source_kind));
    object.set_property(
        ctx,
        "sourceAddress",
        create_native_pointer(ctx, type_info.source_address as u64),
    );
    object.set_property(
        ctx,
        "sourceOffset",
        JSValue(ffi::JS_NewBigUint64(ctx, type_info.source_offset as u64)),
    );

    match &type_info.source_demangled_name {
        Some(name) => object.set_property(ctx, "sourceDemangledName", JSValue::string(ctx, name)),
        None => object.set_property(ctx, "sourceDemangledName", JSValue::null()),
    };

    object.raw()
}

unsafe fn swift_protocol_to_js(ctx: *mut ffi::JSContext, protocol_info: &SwiftProtocol) -> ffi::JSValue {
    let object = JSValue(ffi::JS_NewObject(ctx));
    object.set_property(ctx, "moduleName", JSValue::string(ctx, &protocol_info.module_name));
    object.set_property(
        ctx,
        "moduleBase",
        create_native_pointer(ctx, protocol_info.module_base as u64),
    );
    object.set_property(ctx, "name", JSValue::string(ctx, &protocol_info.protocol_name));
    object.set_property(
        ctx,
        "sourceSymbolName",
        JSValue::string(ctx, &protocol_info.source_symbol_name),
    );
    object.set_property(ctx, "sourceKind", JSValue::string(ctx, &protocol_info.source_kind));
    object.set_property(
        ctx,
        "sourceAddress",
        create_native_pointer(ctx, protocol_info.source_address as u64),
    );
    object.set_property(
        ctx,
        "sourceOffset",
        JSValue(ffi::JS_NewBigUint64(ctx, protocol_info.source_offset as u64)),
    );

    match &protocol_info.source_demangled_name {
        Some(name) => object.set_property(ctx, "sourceDemangledName", JSValue::string(ctx, name)),
        None => object.set_property(ctx, "sourceDemangledName", JSValue::null()),
    };

    object.raw()
}

unsafe fn swift_conformance_to_js(ctx: *mut ffi::JSContext, conformance: &SwiftConformance) -> ffi::JSValue {
    let object = JSValue(ffi::JS_NewObject(ctx));
    object.set_property(ctx, "moduleName", JSValue::string(ctx, &conformance.module_name));
    object.set_property(
        ctx,
        "moduleBase",
        create_native_pointer(ctx, conformance.module_base as u64),
    );
    object.set_property(ctx, "typeName", JSValue::string(ctx, &conformance.type_name));
    object.set_property(ctx, "protocolName", JSValue::string(ctx, &conformance.protocol_name));
    object.set_property(
        ctx,
        "sourceSymbolName",
        JSValue::string(ctx, &conformance.source_symbol_name),
    );
    object.set_property(ctx, "sourceKind", JSValue::string(ctx, &conformance.source_kind));
    object.set_property(
        ctx,
        "sourceAddress",
        create_native_pointer(ctx, conformance.source_address as u64),
    );
    object.set_property(
        ctx,
        "sourceOffset",
        JSValue(ffi::JS_NewBigUint64(ctx, conformance.source_offset as u64)),
    );

    match &conformance.source_demangled_name {
        Some(name) => object.set_property(ctx, "sourceDemangledName", JSValue::string(ctx, name)),
        None => object.set_property(ctx, "sourceDemangledName", JSValue::null()),
    };

    object.raw()
}

unsafe fn swift_vtable_entry_to_js(ctx: *mut ffi::JSContext, entry: &SwiftVtableEntry) -> ffi::JSValue {
    let object = JSValue(ffi::JS_NewObject(ctx));
    object.set_property(ctx, "moduleName", JSValue::string(ctx, &entry.module_name));
    object.set_property(ctx, "moduleBase", create_native_pointer(ctx, entry.module_base as u64));
    object.set_property(ctx, "typeName", JSValue::string(ctx, &entry.type_name));
    object.set_property(ctx, "memberName", JSValue::string(ctx, &entry.member_name));
    object.set_property(ctx, "name", JSValue::string(ctx, &entry.symbol_name));
    object.set_property(ctx, "sourceKind", JSValue::string(ctx, &entry.source_kind));
    object.set_property(ctx, "address", create_native_pointer(ctx, entry.address as u64));
    object.set_property(ctx, "offset", JSValue(ffi::JS_NewBigUint64(ctx, entry.offset as u64)));
    object.set_property(ctx, "isDispatchThunk", JSValue::bool(entry.is_dispatch_thunk));

    match &entry.demangled_name {
        Some(name) => object.set_property(ctx, "demangledName", JSValue::string(ctx, name)),
        None => object.set_property(ctx, "demangledName", JSValue::null()),
    };

    object.raw()
}

unsafe fn swift_witness_table_to_js(ctx: *mut ffi::JSContext, entry: &SwiftWitnessTable) -> ffi::JSValue {
    let object = JSValue(ffi::JS_NewObject(ctx));
    object.set_property(ctx, "moduleName", JSValue::string(ctx, &entry.module_name));
    object.set_property(ctx, "moduleBase", create_native_pointer(ctx, entry.module_base as u64));
    object.set_property(ctx, "typeName", JSValue::string(ctx, &entry.type_name));
    object.set_property(ctx, "protocolName", JSValue::string(ctx, &entry.protocol_name));
    object.set_property(ctx, "name", JSValue::string(ctx, &entry.symbol_name));
    object.set_property(ctx, "sourceKind", JSValue::string(ctx, &entry.source_kind));
    object.set_property(ctx, "address", create_native_pointer(ctx, entry.address as u64));
    object.set_property(ctx, "offset", JSValue(ffi::JS_NewBigUint64(ctx, entry.offset as u64)));
    object.set_property(ctx, "isAccessor", JSValue::bool(entry.is_accessor));

    match &entry.demangled_name {
        Some(name) => object.set_property(ctx, "demangledName", JSValue::string(ctx, name)),
        None => object.set_property(ctx, "demangledName", JSValue::null()),
    };

    object.raw()
}

unsafe fn swift_type_layout_to_js(ctx: *mut ffi::JSContext, layout: &SwiftTypeLayout) -> ffi::JSValue {
    let object = JSValue(ffi::JS_NewObject(ctx));
    object.set_property(ctx, "moduleName", JSValue::string(ctx, &layout.module_name));
    object.set_property(ctx, "moduleBase", create_native_pointer(ctx, layout.module_base as u64));
    object.set_property(ctx, "name", JSValue::string(ctx, &layout.type_name));

    let metadata = ffi::JS_NewArray(ctx);
    for (index, item) in layout.metadata.iter().enumerate() {
        ffi::JS_SetPropertyUint32(ctx, metadata, index as u32, swift_type_to_js(ctx, item));
    }
    object.set_property(ctx, "metadata", JSValue(metadata));

    let metadata_accessors = ffi::JS_NewArray(ctx);
    for (index, item) in layout.metadata_accessors.iter().enumerate() {
        ffi::JS_SetPropertyUint32(ctx, metadata_accessors, index as u32, swift_type_to_js(ctx, item));
    }
    object.set_property(ctx, "metadataAccessors", JSValue(metadata_accessors));

    let nominal_descriptors = ffi::JS_NewArray(ctx);
    for (index, item) in layout.nominal_descriptors.iter().enumerate() {
        ffi::JS_SetPropertyUint32(ctx, nominal_descriptors, index as u32, swift_type_to_js(ctx, item));
    }
    object.set_property(ctx, "nominalDescriptors", JSValue(nominal_descriptors));

    let metadata_caches = ffi::JS_NewArray(ctx);
    for (index, item) in layout.metadata_caches.iter().enumerate() {
        ffi::JS_SetPropertyUint32(ctx, metadata_caches, index as u32, swift_type_to_js(ctx, item));
    }
    object.set_property(ctx, "metadataCaches", JSValue(metadata_caches));

    let associated_type_descriptors = ffi::JS_NewArray(ctx);
    for (index, item) in layout.associated_type_descriptors.iter().enumerate() {
        ffi::JS_SetPropertyUint32(
            ctx,
            associated_type_descriptors,
            index as u32,
            swift_type_to_js(ctx, item),
        );
    }
    object.set_property(ctx, "associatedTypeDescriptors", JSValue(associated_type_descriptors));

    let vtable_entries = ffi::JS_NewArray(ctx);
    for (index, item) in layout.vtable_entries.iter().enumerate() {
        ffi::JS_SetPropertyUint32(ctx, vtable_entries, index as u32, swift_vtable_entry_to_js(ctx, item));
    }
    object.set_property(ctx, "vtableEntries", JSValue(vtable_entries));

    let witness_tables = ffi::JS_NewArray(ctx);
    for (index, item) in layout.witness_tables.iter().enumerate() {
        ffi::JS_SetPropertyUint32(ctx, witness_tables, index as u32, swift_witness_table_to_js(ctx, item));
    }
    object.set_property(ctx, "witnessTables", JSValue(witness_tables));

    object.raw()
}

unsafe fn set_string_array_property(ctx: *mut ffi::JSContext, object: &JSValue, name: &str, items: &[&str]) {
    let array = ffi::JS_NewArray(ctx);
    for (index, item) in items.iter().enumerate() {
        ffi::JS_SetPropertyUint32(ctx, array, index as u32, JSValue::string(ctx, item).raw());
    }
    object.set_property(ctx, name, JSValue(array));
}

unsafe fn swift_abi_descriptor_to_js(
    ctx: *mut ffi::JSContext,
    descriptor: &SwiftAbiDescriptor,
    boundary: &str,
) -> ffi::JSValue {
    let base = descriptor.type_name.rsplit('.').next().unwrap_or(&descriptor.type_name);
    let native_call_type = match base {
        "Void" | "()" => Some("void"),
        "Bool" => Some("bool"),
        "Int" | "Int64" | "CLong" => Some("int64"),
        "UInt" | "UInt64" | "CULong" => Some("uint64"),
        "Int8" | "CChar" | "CSignedChar" => Some("int8"),
        "UInt8" | "CUnsignedChar" => Some("uint8"),
        "Int16" | "CShort" => Some("int16"),
        "UInt16" | "CUShort" => Some("uint16"),
        "Int32" | "CInt" => Some("int32"),
        "UInt32" | "CUInt" => Some("uint32"),
        "Float" | "CFloat" => Some("float"),
        "Double" | "CDouble" => Some("double"),
        "OpaquePointer" | "UnsafeRawPointer" | "UnsafeMutableRawPointer" => Some("pointer"),
        _ if descriptor.type_name.contains("UnsafePointer<")
            || descriptor.type_name.contains("UnsafeMutablePointer<")
            || descriptor.type_name.contains("AutoreleasingUnsafeMutablePointer<") =>
        {
            Some("pointer")
        }
        _ => None,
    };
    let thin_call_supported =
        native_call_type.is_some() && matches!(descriptor.pass_mode, "none" | "direct-pointer" | "direct-scalar");
    let object = JSValue(ffi::JS_NewObject(ctx));
    object.set_property(ctx, "typeName", JSValue::string(ctx, &descriptor.type_name));
    object.set_property(ctx, "boundary", JSValue::string(ctx, boundary));
    object.set_property(
        ctx,
        "typeRepresentation",
        JSValue::string(ctx, descriptor.type_representation),
    );
    object.set_property(
        ctx,
        "objectRepresentation",
        JSValue::string(ctx, descriptor.object_representation),
    );
    object.set_property(ctx, "argumentKind", JSValue::string(ctx, descriptor.argument_kind));
    object.set_property(ctx, "passMode", JSValue::string(ctx, descriptor.pass_mode));
    object.set_property(ctx, "metadataOnly", JSValue::bool(true));
    object.set_property(ctx, "classificationAvailable", JSValue::bool(true));
    object.set_property(ctx, "objectAccessSupported", JSValue::bool(false));
    object.set_property(ctx, "callSupported", JSValue::bool(false));
    object.set_property(ctx, "thinCallSupported", JSValue::bool(thin_call_supported));
    match native_call_type {
        Some(name) => object.set_property(ctx, "nativeCallType", JSValue::string(ctx, name)),
        None => object.set_property(ctx, "nativeCallType", JSValue::null()),
    };
    object.set_property(
        ctx,
        "thinCallRequirement",
        JSValue::string(ctx, "{ abi: 'c-compatible', verified: true }"),
    );
    object.set_property(
        ctx,
        "unsupportedReason",
        JSValue::string(ctx, SWIFT_RUNTIME_CALL_UNSUPPORTED_REASON),
    );
    object.raw()
}

unsafe fn swift_unsupported_descriptors_to_js(ctx: *mut ffi::JSContext) -> JSValue {
    let array = ffi::JS_NewArray(ctx);
    for (index, (name, arity, category, replacement)) in SWIFT_UNSUPPORTED_METHOD_DESCRIPTORS.iter().enumerate() {
        let descriptor = JSValue(ffi::JS_NewObject(ctx));
        descriptor.set_property(ctx, "name", JSValue::string(ctx, name));
        descriptor.set_property(ctx, "arity", JSValue::int(*arity));
        descriptor.set_property(ctx, "category", JSValue::string(ctx, category));
        descriptor.set_property(ctx, "available", JSValue::bool(false));
        descriptor.set_property(ctx, "metadataOnly", JSValue::bool(true));
        descriptor.set_property(ctx, "replacement", JSValue::string(ctx, replacement));
        descriptor.set_property(
            ctx,
            "message",
            JSValue::string(ctx, SWIFT_RUNTIME_CALL_UNSUPPORTED_REASON),
        );
        ffi::JS_SetPropertyUint32(ctx, array, index as u32, descriptor.raw());
    }
    JSValue(array)
}

unsafe fn swift_status_object(ctx: *mut ffi::JSContext) -> JSValue {
    let available = swift_support_available();
    let result = JSValue(ffi::JS_NewObject(ctx));
    result.set_property(ctx, "available", JSValue::bool(available));
    result.set_property(ctx, "platform", JSValue::string(ctx, "ios"));
    result.set_property(ctx, "backend", JSValue::string(ctx, "swift-metadata"));
    result.set_property(ctx, "metadataQueryAvailable", JSValue::bool(available));
    result.set_property(ctx, "typeRepresentationAvailable", JSValue::bool(true));
    result.set_property(ctx, "objectRepresentationAvailable", JSValue::bool(true));
    result.set_property(ctx, "abiArgumentClassificationAvailable", JSValue::bool(true));
    result.set_property(ctx, "objectBridgeAvailable", JSValue::bool(true));
    result.set_property(ctx, "liveObjectWrapperAvailable", JSValue::bool(true));
    result.set_property(ctx, "runtimeInvocationAvailable", JSValue::bool(false));
    result.set_property(ctx, "abiCallAvailable", JSValue::bool(false));
    result.set_property(ctx, "metadataOnly", JSValue::bool(false));
    let (retain_available, release_available) = swift_runtime_ownership_available();
    result.set_property(ctx, "swiftRetainAvailable", JSValue::bool(retain_available));
    result.set_property(ctx, "swiftReleaseAvailable", JSValue::bool(release_available));
    result.set_property(ctx, "objectOwnership", JSValue::string(ctx, "borrowed/adopt/retain"));
    result.set_property(
        ctx,
        "supportedMethodCount",
        JSValue::int(SWIFT_SUPPORTED_METHODS.len() as i32),
    );
    result.set_property(
        ctx,
        "unsupportedMethodCount",
        JSValue::int(SWIFT_UNSUPPORTED_METHOD_DESCRIPTORS.len() as i32),
    );
    result.set_property(
        ctx,
        "unsupportedDescriptorCount",
        JSValue::int(SWIFT_UNSUPPORTED_METHOD_DESCRIPTORS.len() as i32),
    );
    result.set_property(
        ctx,
        "methodDescriptorCount",
        JSValue::int(SWIFT_UNSUPPORTED_METHOD_DESCRIPTORS.len() as i32),
    );
    result.set_property(
        ctx,
        "lastError",
        JSValue::string(ctx, SWIFT_RUNTIME_CALL_UNSUPPORTED_REASON),
    );
    set_string_array_property(ctx, &result, "supportedMethods", SWIFT_SUPPORTED_METHODS);
    let unsupported_methods = SWIFT_UNSUPPORTED_METHOD_DESCRIPTORS
        .iter()
        .map(|descriptor| descriptor.0)
        .collect::<Vec<_>>();
    set_string_array_property(ctx, &result, "unsupportedMethods", &unsupported_methods);
    result.set_property(ctx, "unsupportedDescriptors", swift_unsupported_descriptors_to_js(ctx));
    result.set_property(ctx, "methodDescriptors", swift_unsupported_descriptors_to_js(ctx));
    result
}

unsafe fn classify_swift_type_to_js(
    ctx: *mut ffi::JSContext,
    argc: i32,
    argv: *mut ffi::JSValue,
    usage: &str,
    boundary: &str,
) -> ffi::JSValue {
    let type_name = match require_string_arg(ctx, argc, argv, 0, usage) {
        Ok(value) => value,
        Err(error) => return error,
    };
    match classify_swift_abi_type(&type_name) {
        Ok(descriptor) => swift_abi_descriptor_to_js(ctx, &descriptor, boundary),
        Err(error) => js_throw_type_error(ctx, &error),
    }
}

unsafe extern "C" fn js_swift_status(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    swift_status_object(ctx).raw()
}

unsafe extern "C" fn js_swift_last_error(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    JSValue::string(ctx, SWIFT_RUNTIME_CALL_UNSUPPORTED_REASON).raw()
}

unsafe extern "C" fn js_swift_type_representation(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    classify_swift_type_to_js(
        ctx,
        argc,
        argv,
        "Swift.typeRepresentation(typeName) requires one string argument",
        "type",
    )
}

unsafe extern "C" fn js_swift_object_representation(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    classify_swift_type_to_js(
        ctx,
        argc,
        argv,
        "Swift.objectRepresentation(typeName) requires one string argument",
        "object",
    )
}

unsafe extern "C" fn js_swift_classify_abi_argument(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    classify_swift_type_to_js(
        ctx,
        argc,
        argv,
        "Swift.classifyAbiArgument(typeName) requires one string argument",
        "argument",
    )
}

unsafe extern "C" fn js_swift_classify_abi_arguments(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 1 {
        return js_throw_type_error(ctx, "Swift.classifyAbiArguments(typeNames) requires one string array");
    }
    let values = JSValue(*argv);
    if ffi::JS_IsArray(ctx, values.raw()) != 1 {
        return js_throw_type_error(ctx, "Swift.classifyAbiArguments(typeNames) requires one string array");
    }
    let length_value = values.get_property(ctx, "length");
    let length = length_value.to_u64(ctx).unwrap_or(u64::MAX);
    length_value.free(ctx);
    let length = usize::try_from(length).unwrap_or(usize::MAX);
    if length > MAX_SWIFT_ABI_ARGUMENTS {
        return js_throw_range_error(
            ctx,
            &format!("Swift.classifyAbiArguments accepts at most {MAX_SWIFT_ABI_ARGUMENTS} arguments"),
        );
    }

    let result = ffi::JS_NewArray(ctx);
    for index in 0..length {
        let value = JSValue(ffi::JS_GetPropertyUint32(ctx, values.raw(), index as u32));
        if value.is_exception() {
            JSValue(result).free(ctx);
            return value.raw();
        }
        if !value.is_string() {
            value.free(ctx);
            JSValue(result).free(ctx);
            return js_throw_type_error(
                ctx,
                &format!("Swift.classifyAbiArguments typeNames[{index}] must be a string"),
            );
        }
        let type_name = value.to_string(ctx).unwrap_or_default();
        value.free(ctx);
        let descriptor = match classify_swift_abi_type(&type_name) {
            Ok(descriptor) => descriptor,
            Err(error) => {
                JSValue(result).free(ctx);
                return js_throw_type_error(ctx, &format!("typeNames[{index}]: {error}"));
            }
        };
        ffi::JS_SetPropertyUint32(
            ctx,
            result,
            index as u32,
            swift_abi_descriptor_to_js(ctx, &descriptor, "argument"),
        );
    }
    result
}

unsafe fn swift_object_option_string(
    ctx: *mut ffi::JSContext,
    options: JSValue,
    name: &str,
) -> Result<Option<String>, ffi::JSValue> {
    let value = options.get_property(ctx, name);
    if value.is_undefined() || value.is_null() {
        value.free(ctx);
        return Ok(None);
    }
    if !value.is_string() {
        value.free(ctx);
        return Err(js_throw_type_error(
            ctx,
            &format!("Swift.object options.{name} must be a string"),
        ));
    }
    let result = value
        .to_string(ctx)
        .ok_or_else(|| js_throw_type_error(ctx, &format!("Swift.object options.{name} must be a string")));
    value.free(ctx);
    result.map(Some)
}

unsafe fn swift_object_option_bool(
    ctx: *mut ffi::JSContext,
    options: JSValue,
    name: &str,
    default: bool,
) -> Result<bool, ffi::JSValue> {
    let value = options.get_property(ctx, name);
    if value.is_undefined() || value.is_null() {
        value.free(ctx);
        return Ok(default);
    }
    let result = value
        .to_bool()
        .ok_or_else(|| js_throw_type_error(ctx, &format!("Swift.object options.{name} must be boolean")));
    value.free(ctx);
    result
}

unsafe extern "C" fn js_swift_metadata_of(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 1 {
        return js_throw_type_error(ctx, "Swift.metadataOf(object) requires one object pointer");
    }
    let object = match swift_pointer_argument(ctx, JSValue(*argv), "object") {
        Ok(value) => value,
        Err(error) => return error,
    };
    match swift_object_backend_info(ctx, object, None, SwiftObjectOwnership::Borrowed) {
        Ok(info) => create_native_pointer(ctx, info.metadata_address as u64).raw(),
        Err(error) => error,
    }
}

unsafe extern "C" fn js_swift_object(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 1 {
        return js_throw_type_error(
            ctx,
            "Swift.object(pointer[, metadata[, options]]) requires an object pointer",
        );
    }
    let object_address = match swift_pointer_argument(ctx, JSValue(*argv), "pointer") {
        Ok(value) => value,
        Err(error) => return error,
    };
    let metadata_address = if argc >= 2 {
        match optional_pointer_argument(ctx, JSValue(*argv.add(1)), "metadata") {
            Ok(value) => value,
            Err(error) => return error,
        }
    } else {
        None
    };

    let options = if argc >= 3 {
        let value = JSValue(*argv.add(2));
        if !value.is_object() {
            return js_throw_type_error(ctx, "Swift.object options must be an object");
        }
        value
    } else {
        JSValue::undefined()
    };
    let infer_metadata = if options.is_undefined() {
        true
    } else {
        match swift_object_option_bool(ctx, options, "inferMetadata", true) {
            Ok(value) => value,
            Err(error) => return error,
        }
    };
    let type_name = if options.is_undefined() {
        None
    } else {
        match swift_object_option_string(ctx, options, "typeName") {
            Ok(value) => value,
            Err(error) => return error,
        }
    };
    let ownership_name = if options.is_undefined() {
        None
    } else {
        match swift_object_option_string(ctx, options, "ownership") {
            Ok(value) => value,
            Err(error) => return error,
        }
    };
    let ownership = match ownership_name.as_deref().unwrap_or("borrowed") {
        "borrowed" => SwiftObjectOwnership::Borrowed,
        "adopt" | "adopted" => SwiftObjectOwnership::Adopt,
        "retain" | "retained" => SwiftObjectOwnership::Retain,
        _ => return js_throw_type_error(ctx, "Swift.object options.ownership must be borrowed, adopt, or retain"),
    };
    let metadata_address = match metadata_address {
        Some(value) => Some(value),
        None if infer_metadata => None,
        None => return js_throw_type_error(ctx, "Swift.object requires metadata or options.inferMetadata=true"),
    };
    let backend_info = match swift_object_backend_info(ctx, object_address, metadata_address, ownership) {
        Ok(info) => info,
        Err(error) => return error,
    };
    let metadata_address = backend_info.metadata_address;
    let release_address = match ownership {
        SwiftObjectOwnership::Borrowed => None,
        SwiftObjectOwnership::Adopt | SwiftObjectOwnership::Retain => {
            let Some(address) = swift_runtime_symbol("swift_release") else {
                return js_throw_internal_error(ctx, "swift_release is not exported by the loaded Swift runtime");
            };
            Some(address)
        }
    };

    let owned_references = if matches!(ownership, SwiftObjectOwnership::Borrowed) {
        0
    } else {
        if matches!(ownership, SwiftObjectOwnership::Retain) {
            let Some(retain_address) = swift_runtime_symbol("swift_retain") else {
                return js_throw_internal_error(ctx, "swift_retain is not exported by the loaded Swift runtime");
            };
            let retain: unsafe extern "C" fn(*const c_void) -> *const c_void = std::mem::transmute(retain_address);
            if retain(object_address as *const c_void).is_null() {
                return js_throw_internal_error(ctx, "swift_retain returned a null object");
            }
        }
        1
    };
    create_swift_object_wrapper(
        ctx,
        SwiftObjectState {
            object_address,
            metadata_address,
            metadata_inferred: backend_info.metadata_inferred,
            metadata_verified: backend_info.metadata_verified,
            type_name,
            ownership,
            owned_references,
            release_address,
            retain_available: backend_info.retain_available,
            release_available: backend_info.release_available,
            disposed: false,
        },
    )
}

unsafe extern "C" fn swift_object_to_pointer(
    ctx: *mut ffi::JSContext,
    this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let state = match swift_object_state(ctx, this) {
        Ok(value) => &*value,
        Err(error) => return error,
    };
    create_native_pointer(ctx, state.object_address as u64).raw()
}

unsafe extern "C" fn swift_object_metadata(
    ctx: *mut ffi::JSContext,
    this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let state = match swift_object_state(ctx, this) {
        Ok(value) => &*value,
        Err(error) => return error,
    };
    create_native_pointer(ctx, state.metadata_address as u64).raw()
}

unsafe extern "C" fn swift_object_is_type(
    ctx: *mut ffi::JSContext,
    this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 1 {
        return js_throw_type_error(ctx, "Swift object.isType(metadata) requires a metadata pointer");
    }
    let state = match swift_object_state(ctx, this) {
        Ok(value) => &*value,
        Err(error) => return error,
    };
    let metadata = match swift_pointer_argument(ctx, JSValue(*argv), "metadata") {
        Ok(value) => value,
        Err(error) => return error,
    };
    JSValue::bool(state.metadata_address == metadata).raw()
}

unsafe extern "C" fn swift_object_type_name(
    ctx: *mut ffi::JSContext,
    this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let state = match swift_object_state(ctx, this) {
        Ok(value) => &*value,
        Err(error) => return error,
    };
    match state.type_name.as_deref() {
        Some(name) => JSValue::string(ctx, name).raw(),
        None => JSValue::null().raw(),
    }
}

unsafe extern "C" fn swift_object_ownership(
    ctx: *mut ffi::JSContext,
    this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let state = match swift_object_state_any(ctx, this) {
        Ok(value) => &*value,
        Err(error) => return error,
    };
    JSValue::string(ctx, state.ownership_name()).raw()
}

unsafe extern "C" fn swift_object_is_disposed(
    ctx: *mut ffi::JSContext,
    this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let state = match swift_object_state_any(ctx, this) {
        Ok(value) => &*value,
        Err(error) => return error,
    };
    JSValue::bool(state.is_disposed()).raw()
}

unsafe extern "C" fn swift_object_status(
    ctx: *mut ffi::JSContext,
    this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let state = match swift_object_state_any(ctx, this) {
        Ok(value) => &*value,
        Err(error) => return error,
    };
    let disposed = state.is_disposed();
    let result = JSValue(ffi::JS_NewObject(ctx));
    result.set_property(ctx, "disposed", JSValue::bool(disposed));
    result.set_property(ctx, "ownership", JSValue::string(ctx, state.ownership_name()));
    result.set_property(
        ctx,
        "ownedReferenceCount",
        JSValue(ffi::JS_NewBigUint64(ctx, state.owned_references as u64)),
    );
    result.set_property(
        ctx,
        "ownershipManaged",
        JSValue::bool(!disposed && state.owned_references != 0),
    );
    result.set_property(ctx, "retainAvailable", JSValue::bool(state.retain_available));
    result.set_property(ctx, "releaseAvailable", JSValue::bool(state.release_available));
    result.set_property(
        ctx,
        "metadataSource",
        JSValue::string(ctx, state.metadata_source_name()),
    );
    result.set_property(
        ctx,
        "metadataInferred",
        JSValue::bool(!disposed && state.metadata_inferred),
    );
    result.set_property(
        ctx,
        "metadataVerified",
        JSValue::bool(!disposed && state.metadata_verified),
    );
    if disposed {
        result.set_property(ctx, "objectAddress", JSValue::null());
        result.set_property(ctx, "metadataAddress", JSValue::null());
    } else {
        result.set_property(
            ctx,
            "objectAddress",
            create_native_pointer(ctx, state.object_address as u64),
        );
        result.set_property(
            ctx,
            "metadataAddress",
            create_native_pointer(ctx, state.metadata_address as u64),
        );
    }
    match state.type_name.as_deref() {
        Some(name) => result.set_property(ctx, "typeName", JSValue::string(ctx, name)),
        None => result.set_property(ctx, "typeName", JSValue::null()),
    };
    result.raw()
}

unsafe extern "C" fn swift_object_dispose(
    ctx: *mut ffi::JSContext,
    this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let state = match swift_object_state_any(ctx, this) {
        Ok(value) => &mut *value,
        Err(error) => return error,
    };
    if state.is_disposed() {
        return JSValue::undefined().raw();
    }
    swift_release_references(state);
    state.mark_disposed();
    JSValue::undefined().raw()
}

unsafe extern "C" fn swift_object_retain(
    ctx: *mut ffi::JSContext,
    this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let state = match swift_object_state(ctx, this) {
        Ok(value) => &mut *value,
        Err(error) => return error,
    };
    let Some(address) = swift_runtime_symbol("swift_retain") else {
        return js_throw_internal_error(ctx, "swift_retain is not exported by the loaded Swift runtime");
    };
    let Some(release_address) = swift_runtime_symbol("swift_release") else {
        return js_throw_internal_error(ctx, "swift_release is not exported by the loaded Swift runtime");
    };
    let retain: unsafe extern "C" fn(*const c_void) -> *const c_void = std::mem::transmute(address);
    if retain(state.object_address as *const c_void).is_null() {
        return js_throw_internal_error(ctx, "swift_retain returned a null object");
    }
    if state.owned_references == usize::MAX {
        let release: unsafe extern "C" fn(*const c_void) = std::mem::transmute(release_address);
        release(state.object_address as *const c_void);
        return js_throw_internal_error(ctx, "Swift object retain count overflow");
    }
    state.release_address = Some(release_address);
    state.owned_references += 1;
    state.ownership = SwiftObjectOwnership::Retain;
    state.retain_available = true;
    state.release_available = true;
    JSValue::undefined().raw()
}

unsafe extern "C" fn swift_object_to_string(
    ctx: *mut ffi::JSContext,
    this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let state = match swift_object_state_any(ctx, this) {
        Ok(value) => &*value,
        Err(error) => return error,
    };
    if state.is_disposed() {
        return JSValue::string(ctx, "<SwiftObject disposed>").raw();
    }
    let type_name = state.type_name.as_deref().unwrap_or("unknown");
    JSValue::string(ctx, &format!("<SwiftObject {type_name} {:#x}>", state.object_address)).raw()
}

unsafe extern "C" fn js_swift_unsupported(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    js_throw_internal_error(ctx, SWIFT_RUNTIME_CALL_UNSUPPORTED_REASON)
}

unsafe extern "C" fn js_swift_demangle(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let symbol_name = match require_string_arg(ctx, argc, argv, 0, "Swift.demangle(symbol) requires 1 string argument")
    {
        Ok(value) => value,
        Err(err) => return err,
    };

    match swift_demangle_symbol(&symbol_name) {
        Ok(Some(name)) => JSValue::string(ctx, &name).raw(),
        Ok(None) | Err(CommonError::Unsupported(_)) => JSValue::null().raw(),
        Err(CommonError::InvalidArgument(message)) => js_throw_type_error(ctx, &message),
        Err(err) => js_throw_internal_error(ctx, &err.to_string()),
    }
}

unsafe extern "C" fn js_swift_find_symbols(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let query = match require_string_arg(
        ctx,
        argc,
        argv,
        0,
        "Swift.findSymbols(query[, moduleName]) requires at least 1 string argument",
    ) {
        Ok(value) => value,
        Err(err) => return err,
    };

    let module_name = if argc >= 2 {
        let value = JSValue(*argv.add(1));
        if value.is_null() || value.is_undefined() {
            None
        } else {
            match value.to_string(ctx) {
                Some(module_name) => Some(module_name),
                None => {
                    return js_throw_type_error(
                        ctx,
                        "Swift.findSymbols(query[, moduleName]) expected moduleName to be a string when provided",
                    )
                }
            }
        }
    } else {
        None
    };

    let symbols = match find_swift_symbols(module_name.as_deref(), &query) {
        Ok(symbols) => symbols,
        Err(CommonError::Unsupported(_)) => return ffi::JS_NewArray(ctx),
        Err(CommonError::InvalidArgument(message)) => return js_throw_type_error(ctx, &message),
        Err(err) => return js_throw_internal_error(ctx, &err.to_string()),
    };

    let array = ffi::JS_NewArray(ctx);
    for (index, symbol) in symbols.iter().enumerate() {
        ffi::JS_SetPropertyUint32(ctx, array, index as u32, swift_symbol_to_js(ctx, symbol));
    }
    array
}

unsafe extern "C" fn js_swift_symbol_info(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let symbol_name = match require_string_arg(
        ctx,
        argc,
        argv,
        0,
        "Swift.symbolInfo(symbolName[, moduleName]) requires at least 1 string argument",
    ) {
        Ok(value) => value,
        Err(err) => return err,
    };

    let module_name =
        if argc >= 2 {
            let value = JSValue(*argv.add(1));
            if value.is_null() || value.is_undefined() {
                None
            } else {
                match value.to_string(ctx) {
                    Some(module_name) => Some(module_name),
                    None => return js_throw_type_error(
                        ctx,
                        "Swift.symbolInfo(symbolName[, moduleName]) expected moduleName to be a string when provided",
                    ),
                }
            }
        } else {
            None
        };

    let symbols = match find_swift_symbols(module_name.as_deref(), &symbol_name) {
        Ok(symbols) => symbols,
        Err(CommonError::Unsupported(_)) => return JSValue::null().raw(),
        Err(CommonError::InvalidArgument(message)) => return js_throw_type_error(ctx, &message),
        Err(err) => return js_throw_internal_error(ctx, &err.to_string()),
    };

    match symbols.into_iter().next() {
        Some(symbol) => swift_symbol_to_js(ctx, &symbol),
        None => JSValue::null().raw(),
    }
}

unsafe extern "C" fn js_swift_find_methods(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let type_name = match require_string_arg(
        ctx,
        argc,
        argv,
        0,
        "Swift.findMethods(typeName, methodQuery[, moduleName]) requires at least 2 string arguments",
    ) {
        Ok(value) => value,
        Err(err) => return err,
    };
    let method_query = match require_string_arg(
        ctx,
        argc,
        argv,
        1,
        "Swift.findMethods(typeName, methodQuery[, moduleName]) requires at least 2 string arguments",
    ) {
        Ok(value) => value,
        Err(err) => return err,
    };

    let module_name = if argc >= 3 {
        let value = JSValue(*argv.add(2));
        if value.is_null() || value.is_undefined() {
            None
        } else {
            match value.to_string(ctx) {
                Some(module_name) => Some(module_name),
                None => {
                    return js_throw_type_error(
                        ctx,
                        "Swift.findMethods(typeName, methodQuery[, moduleName]) expected moduleName to be a string when provided",
                    )
                }
            }
        }
    } else {
        None
    };

    let symbols = match find_swift_methods(module_name.as_deref(), &type_name, &method_query) {
        Ok(symbols) => symbols,
        Err(CommonError::Unsupported(_)) => return ffi::JS_NewArray(ctx),
        Err(CommonError::InvalidArgument(message)) => return js_throw_type_error(ctx, &message),
        Err(err) => return js_throw_internal_error(ctx, &err.to_string()),
    };

    let array = ffi::JS_NewArray(ctx);
    for (index, symbol) in symbols.iter().enumerate() {
        ffi::JS_SetPropertyUint32(ctx, array, index as u32, swift_symbol_to_js(ctx, symbol));
    }
    array
}

unsafe extern "C" fn js_swift_method_info(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let type_name = match require_string_arg(
        ctx,
        argc,
        argv,
        0,
        "Swift.methodInfo(typeName, methodName[, moduleName]) requires at least 2 string arguments",
    ) {
        Ok(value) => value,
        Err(err) => return err,
    };
    let method_name = match require_string_arg(
        ctx,
        argc,
        argv,
        1,
        "Swift.methodInfo(typeName, methodName[, moduleName]) requires at least 2 string arguments",
    ) {
        Ok(value) => value,
        Err(err) => return err,
    };

    let module_name = if argc >= 3 {
        let value = JSValue(*argv.add(2));
        if value.is_null() || value.is_undefined() {
            None
        } else {
            match value.to_string(ctx) {
                Some(module_name) => Some(module_name),
                None => {
                    return js_throw_type_error(
                        ctx,
                        "Swift.methodInfo(typeName, methodName[, moduleName]) expected moduleName to be a string when provided",
                    )
                }
            }
        }
    } else {
        None
    };

    let symbols = match find_swift_methods(module_name.as_deref(), &type_name, &method_name) {
        Ok(symbols) => symbols,
        Err(CommonError::Unsupported(_)) => return JSValue::null().raw(),
        Err(CommonError::InvalidArgument(message)) => return js_throw_type_error(ctx, &message),
        Err(err) => return js_throw_internal_error(ctx, &err.to_string()),
    };

    match symbols.into_iter().next() {
        Some(symbol) => swift_symbol_to_js(ctx, &symbol),
        None => JSValue::null().raw(),
    }
}

unsafe extern "C" fn js_swift_find_type_methods(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let type_query = match require_string_arg(
        ctx,
        argc,
        argv,
        0,
        "Swift.findTypeMethods(typeQuery[, moduleName]) requires at least 1 string argument",
    ) {
        Ok(value) => value,
        Err(err) => return err,
    };

    let module_name = if argc >= 2 {
        let value = JSValue(*argv.add(1));
        if value.is_null() || value.is_undefined() {
            None
        } else {
            match value.to_string(ctx) {
                Some(module_name) => Some(module_name),
                None => return js_throw_type_error(
                    ctx,
                    "Swift.findTypeMethods(typeQuery[, moduleName]) expected moduleName to be a string when provided",
                ),
            }
        }
    } else {
        None
    };

    let symbols = match find_swift_type_methods(module_name.as_deref(), &type_query) {
        Ok(symbols) => symbols,
        Err(CommonError::Unsupported(_)) => return ffi::JS_NewArray(ctx),
        Err(CommonError::InvalidArgument(message)) => return js_throw_type_error(ctx, &message),
        Err(err) => return js_throw_internal_error(ctx, &err.to_string()),
    };

    let array = ffi::JS_NewArray(ctx);
    for (index, symbol) in symbols.iter().enumerate() {
        ffi::JS_SetPropertyUint32(ctx, array, index as u32, swift_symbol_to_js(ctx, symbol));
    }
    array
}

unsafe extern "C" fn js_swift_find_method_owners(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let method_query = match require_string_arg(
        ctx,
        argc,
        argv,
        0,
        "Swift.findMethodOwners(methodQuery[, moduleName]) requires at least 1 string argument",
    ) {
        Ok(value) => value,
        Err(err) => return err,
    };

    let module_name = if argc >= 2 {
        let value = JSValue(*argv.add(1));
        if value.is_null() || value.is_undefined() {
            None
        } else {
            match value.to_string(ctx) {
                Some(module_name) => Some(module_name),
                None => {
                    return js_throw_type_error(
                        ctx,
                        "Swift.findMethodOwners(methodQuery[, moduleName]) expected moduleName to be a string when provided",
                    )
                }
            }
        }
    } else {
        None
    };

    let owners = match find_swift_method_owners(module_name.as_deref(), &method_query) {
        Ok(owners) => owners,
        Err(CommonError::Unsupported(_)) => return ffi::JS_NewArray(ctx),
        Err(CommonError::InvalidArgument(message)) => return js_throw_type_error(ctx, &message),
        Err(err) => return js_throw_internal_error(ctx, &err.to_string()),
    };

    let array = ffi::JS_NewArray(ctx);
    for (index, type_info) in owners.iter().enumerate() {
        ffi::JS_SetPropertyUint32(ctx, array, index as u32, swift_type_to_js(ctx, type_info));
    }
    array
}

unsafe extern "C" fn js_swift_find_types_of_kind(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let source_kind = match require_string_arg(
        ctx,
        argc,
        argv,
        0,
        "Swift.findTypesOfKind(sourceKind, query[, moduleName]) requires at least 2 string arguments",
    ) {
        Ok(value) => value,
        Err(err) => return err,
    };
    let query = match require_string_arg(
        ctx,
        argc,
        argv,
        1,
        "Swift.findTypesOfKind(sourceKind, query[, moduleName]) requires at least 2 string arguments",
    ) {
        Ok(value) => value,
        Err(err) => return err,
    };

    let module_name = if argc >= 3 {
        let value = JSValue(*argv.add(2));
        if value.is_null() || value.is_undefined() {
            None
        } else {
            match value.to_string(ctx) {
                Some(module_name) => Some(module_name),
                None => {
                    return js_throw_type_error(
                        ctx,
                        "Swift.findTypesOfKind(sourceKind, query[, moduleName]) expected moduleName to be a string when provided",
                    )
                }
            }
        }
    } else {
        None
    };

    let types = match find_swift_types_of_kind(module_name.as_deref(), &source_kind, &query) {
        Ok(types) => types,
        Err(CommonError::Unsupported(_)) => return ffi::JS_NewArray(ctx),
        Err(CommonError::InvalidArgument(message)) => return js_throw_type_error(ctx, &message),
        Err(err) => return js_throw_internal_error(ctx, &err.to_string()),
    };

    let array = ffi::JS_NewArray(ctx);
    for (index, type_info) in types.iter().enumerate() {
        ffi::JS_SetPropertyUint32(ctx, array, index as u32, swift_type_to_js(ctx, type_info));
    }
    array
}

unsafe extern "C" fn js_swift_type_source_kinds(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let array = ffi::JS_NewArray(ctx);
    for (index, kind) in swift_type_source_kinds().iter().enumerate() {
        ffi::JS_SetPropertyUint32(ctx, array, index as u32, JSValue::string(ctx, kind).raw());
    }
    array
}

unsafe extern "C" fn js_swift_find_types(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let query = match require_string_arg(
        ctx,
        argc,
        argv,
        0,
        "Swift.findTypes(query[, moduleName]) requires at least 1 string argument",
    ) {
        Ok(value) => value,
        Err(err) => return err,
    };

    let module_name = if argc >= 2 {
        let value = JSValue(*argv.add(1));
        if value.is_null() || value.is_undefined() {
            None
        } else {
            match value.to_string(ctx) {
                Some(module_name) => Some(module_name),
                None => {
                    return js_throw_type_error(
                        ctx,
                        "Swift.findTypes(query[, moduleName]) expected moduleName to be a string when provided",
                    )
                }
            }
        }
    } else {
        None
    };

    let types = match find_swift_types(module_name.as_deref(), &query) {
        Ok(types) => types,
        Err(CommonError::Unsupported(_)) => return ffi::JS_NewArray(ctx),
        Err(CommonError::InvalidArgument(message)) => return js_throw_type_error(ctx, &message),
        Err(err) => return js_throw_internal_error(ctx, &err.to_string()),
    };

    let array = ffi::JS_NewArray(ctx);
    for (index, type_info) in types.iter().enumerate() {
        ffi::JS_SetPropertyUint32(ctx, array, index as u32, swift_type_to_js(ctx, type_info));
    }
    array
}

unsafe extern "C" fn js_swift_type_info(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let type_name = match require_string_arg(
        ctx,
        argc,
        argv,
        0,
        "Swift.typeInfo(typeName[, moduleName]) requires at least 1 string argument",
    ) {
        Ok(value) => value,
        Err(err) => return err,
    };

    let module_name = if argc >= 2 {
        let value = JSValue(*argv.add(1));
        if value.is_null() || value.is_undefined() {
            None
        } else {
            match value.to_string(ctx) {
                Some(module_name) => Some(module_name),
                None => {
                    return js_throw_type_error(
                        ctx,
                        "Swift.typeInfo(typeName[, moduleName]) expected moduleName to be a string when provided",
                    )
                }
            }
        }
    } else {
        None
    };

    let types = match find_swift_types(module_name.as_deref(), &type_name) {
        Ok(types) => types,
        Err(CommonError::Unsupported(_)) => return JSValue::null().raw(),
        Err(CommonError::InvalidArgument(message)) => return js_throw_type_error(ctx, &message),
        Err(err) => return js_throw_internal_error(ctx, &err.to_string()),
    };

    match types
        .into_iter()
        .find(|type_info| swift_type_name_matches(&type_info.type_name, &type_name))
    {
        Some(type_info) => swift_type_to_js(ctx, &type_info),
        None => JSValue::null().raw(),
    }
}

unsafe extern "C" fn js_swift_find_protocols(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let query = if argc >= 1 {
        let value = JSValue(*argv.add(0));
        if value.is_null() || value.is_undefined() {
            None
        } else {
            match value.to_string(ctx) {
                Some(query) => Some(query),
                None => {
                    return js_throw_type_error(
                        ctx,
                        "Swift.findProtocols([query[, moduleName]]) expected query to be a string when provided",
                    )
                }
            }
        }
    } else {
        None
    };

    let module_name =
        if argc >= 2 {
            let value = JSValue(*argv.add(1));
            if value.is_null() || value.is_undefined() {
                None
            } else {
                match value.to_string(ctx) {
                    Some(module_name) => Some(module_name),
                    None => return js_throw_type_error(
                        ctx,
                        "Swift.findProtocols([query[, moduleName]]) expected moduleName to be a string when provided",
                    ),
                }
            }
        } else {
            None
        };

    let protocols = match find_swift_protocols(module_name.as_deref(), query.as_deref()) {
        Ok(protocols) => protocols,
        Err(CommonError::Unsupported(_)) => return ffi::JS_NewArray(ctx),
        Err(CommonError::InvalidArgument(message)) => return js_throw_type_error(ctx, &message),
        Err(err) => return js_throw_internal_error(ctx, &err.to_string()),
    };

    let array = ffi::JS_NewArray(ctx);
    for (index, protocol_info) in protocols.iter().enumerate() {
        ffi::JS_SetPropertyUint32(ctx, array, index as u32, swift_protocol_to_js(ctx, protocol_info));
    }
    array
}

unsafe extern "C" fn js_swift_protocol_info(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let protocol_name = match require_string_arg(
        ctx,
        argc,
        argv,
        0,
        "Swift.protocolInfo(protocolName[, moduleName]) requires at least 1 string argument",
    ) {
        Ok(value) => value,
        Err(err) => return err,
    };

    let module_name = if argc >= 2 {
        let value = JSValue(*argv.add(1));
        if value.is_null() || value.is_undefined() {
            None
        } else {
            match value.to_string(ctx) {
                Some(module_name) => Some(module_name),
                None => return js_throw_type_error(
                    ctx,
                    "Swift.protocolInfo(protocolName[, moduleName]) expected moduleName to be a string when provided",
                ),
            }
        }
    } else {
        None
    };

    let protocols = match find_swift_protocols(module_name.as_deref(), Some(protocol_name.as_str())) {
        Ok(protocols) => protocols,
        Err(CommonError::Unsupported(_)) => return JSValue::null().raw(),
        Err(CommonError::InvalidArgument(message)) => return js_throw_type_error(ctx, &message),
        Err(err) => return js_throw_internal_error(ctx, &err.to_string()),
    };

    match protocols
        .into_iter()
        .find(|protocol_info| swift_protocol_name_matches(&protocol_info.protocol_name, &protocol_name))
    {
        Some(protocol_info) => swift_protocol_to_js(ctx, &protocol_info),
        None => JSValue::null().raw(),
    }
}

unsafe extern "C" fn js_swift_find_conformances(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let type_query = match require_string_arg(
        ctx,
        argc,
        argv,
        0,
        "Swift.findConformances(typeQuery[, moduleName]) requires at least 1 string argument",
    ) {
        Ok(value) => value,
        Err(err) => return err,
    };

    let module_name = if argc >= 2 {
        let value = JSValue(*argv.add(1));
        if value.is_null() || value.is_undefined() {
            None
        } else {
            match value.to_string(ctx) {
                Some(module_name) => Some(module_name),
                None => return js_throw_type_error(
                    ctx,
                    "Swift.findConformances(typeQuery[, moduleName]) expected moduleName to be a string when provided",
                ),
            }
        }
    } else {
        None
    };

    let conformances = match find_swift_conformances(module_name.as_deref(), &type_query) {
        Ok(conformances) => conformances,
        Err(CommonError::Unsupported(_)) => return ffi::JS_NewArray(ctx),
        Err(CommonError::InvalidArgument(message)) => return js_throw_type_error(ctx, &message),
        Err(err) => return js_throw_internal_error(ctx, &err.to_string()),
    };

    let array = ffi::JS_NewArray(ctx);
    for (index, conformance) in conformances.iter().enumerate() {
        ffi::JS_SetPropertyUint32(ctx, array, index as u32, swift_conformance_to_js(ctx, conformance));
    }
    array
}

unsafe extern "C" fn js_swift_conformance_info(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let type_name = match require_string_arg(
        ctx,
        argc,
        argv,
        0,
        "Swift.conformanceInfo(typeName, protocolName[, moduleName]) requires at least 2 string arguments",
    ) {
        Ok(value) => value,
        Err(err) => return err,
    };
    let protocol_name = match require_string_arg(
        ctx,
        argc,
        argv,
        1,
        "Swift.conformanceInfo(typeName, protocolName[, moduleName]) requires at least 2 string arguments",
    ) {
        Ok(value) => value,
        Err(err) => return err,
    };

    let module_name = if argc >= 3 {
        let value = JSValue(*argv.add(2));
        if value.is_null() || value.is_undefined() {
            None
        } else {
            match value.to_string(ctx) {
                Some(module_name) => Some(module_name),
                None => return js_throw_type_error(
                    ctx,
                    "Swift.conformanceInfo(typeName, protocolName[, moduleName]) expected moduleName to be a string when provided",
                ),
            }
        }
    } else {
        None
    };

    let conformances = match find_swift_conformances(module_name.as_deref(), &type_name) {
        Ok(conformances) => conformances,
        Err(CommonError::Unsupported(_)) => return JSValue::null().raw(),
        Err(CommonError::InvalidArgument(message)) => return js_throw_type_error(ctx, &message),
        Err(err) => return js_throw_internal_error(ctx, &err.to_string()),
    };

    match conformances.into_iter().find(|conformance| {
        swift_conformance_names_match(
            &conformance.type_name,
            &conformance.protocol_name,
            &type_name,
            &protocol_name,
        )
    }) {
        Some(conformance) => swift_conformance_to_js(ctx, &conformance),
        None => JSValue::null().raw(),
    }
}

unsafe extern "C" fn js_swift_find_metadata(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let type_query = match require_string_arg(
        ctx,
        argc,
        argv,
        0,
        "Swift.findMetadata(typeQuery[, moduleName]) requires at least 1 string argument",
    ) {
        Ok(value) => value,
        Err(err) => return err,
    };

    let module_name =
        if argc >= 2 {
            let value = JSValue(*argv.add(1));
            if value.is_null() || value.is_undefined() {
                None
            } else {
                match value.to_string(ctx) {
                    Some(module_name) => Some(module_name),
                    None => return js_throw_type_error(
                        ctx,
                        "Swift.findMetadata(typeQuery[, moduleName]) expected moduleName to be a string when provided",
                    ),
                }
            }
        } else {
            None
        };

    let metadata = match find_swift_metadata(module_name.as_deref(), &type_query) {
        Ok(metadata) => metadata,
        Err(CommonError::Unsupported(_)) => return ffi::JS_NewArray(ctx),
        Err(CommonError::InvalidArgument(message)) => return js_throw_type_error(ctx, &message),
        Err(err) => return js_throw_internal_error(ctx, &err.to_string()),
    };

    let array = ffi::JS_NewArray(ctx);
    for (index, type_info) in metadata.iter().enumerate() {
        ffi::JS_SetPropertyUint32(ctx, array, index as u32, swift_type_to_js(ctx, type_info));
    }
    array
}

unsafe extern "C" fn js_swift_metadata_info(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let type_name = match require_string_arg(
        ctx,
        argc,
        argv,
        0,
        "Swift.metadataInfo(typeName[, moduleName]) requires at least 1 string argument",
    ) {
        Ok(value) => value,
        Err(err) => return err,
    };

    let module_name =
        if argc >= 2 {
            let value = JSValue(*argv.add(1));
            if value.is_null() || value.is_undefined() {
                None
            } else {
                match value.to_string(ctx) {
                    Some(module_name) => Some(module_name),
                    None => return js_throw_type_error(
                        ctx,
                        "Swift.metadataInfo(typeName[, moduleName]) expected moduleName to be a string when provided",
                    ),
                }
            }
        } else {
            None
        };

    let metadata = match find_swift_metadata(module_name.as_deref(), &type_name) {
        Ok(metadata) => metadata,
        Err(CommonError::Unsupported(_)) => return JSValue::null().raw(),
        Err(CommonError::InvalidArgument(message)) => return js_throw_type_error(ctx, &message),
        Err(err) => return js_throw_internal_error(ctx, &err.to_string()),
    };

    match metadata
        .into_iter()
        .find(|type_info| swift_type_name_matches(&type_info.type_name, &type_name))
    {
        Some(type_info) => swift_type_to_js(ctx, &type_info),
        None => JSValue::null().raw(),
    }
}

unsafe extern "C" fn js_swift_find_vtable(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let type_query = match require_string_arg(
        ctx,
        argc,
        argv,
        0,
        "Swift.findVtable(typeQuery[, moduleName]) requires at least 1 string argument",
    ) {
        Ok(value) => value,
        Err(err) => return err,
    };

    let module_name =
        if argc >= 2 {
            let value = JSValue(*argv.add(1));
            if value.is_null() || value.is_undefined() {
                None
            } else {
                match value.to_string(ctx) {
                    Some(module_name) => Some(module_name),
                    None => return js_throw_type_error(
                        ctx,
                        "Swift.findVtable(typeQuery[, moduleName]) expected moduleName to be a string when provided",
                    ),
                }
            }
        } else {
            None
        };

    let entries = match find_swift_vtable(module_name.as_deref(), &type_query) {
        Ok(entries) => entries,
        Err(CommonError::Unsupported(_)) => return ffi::JS_NewArray(ctx),
        Err(CommonError::InvalidArgument(message)) => return js_throw_type_error(ctx, &message),
        Err(err) => return js_throw_internal_error(ctx, &err.to_string()),
    };

    let array = ffi::JS_NewArray(ctx);
    for (index, entry) in entries.iter().enumerate() {
        ffi::JS_SetPropertyUint32(ctx, array, index as u32, swift_vtable_entry_to_js(ctx, entry));
    }
    array
}

unsafe extern "C" fn js_swift_vtable_info(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let type_name = match require_string_arg(
        ctx,
        argc,
        argv,
        0,
        "Swift.vtableInfo(typeName, memberName[, moduleName]) requires at least 2 string arguments",
    ) {
        Ok(value) => value,
        Err(err) => return err,
    };
    let member_name = match require_string_arg(
        ctx,
        argc,
        argv,
        1,
        "Swift.vtableInfo(typeName, memberName[, moduleName]) requires at least 2 string arguments",
    ) {
        Ok(value) => value,
        Err(err) => return err,
    };

    let module_name = if argc >= 3 {
        let value = JSValue(*argv.add(2));
        if value.is_null() || value.is_undefined() {
            None
        } else {
            match value.to_string(ctx) {
                Some(module_name) => Some(module_name),
                None => {
                    return js_throw_type_error(
                        ctx,
                        "Swift.vtableInfo(typeName, memberName[, moduleName]) expected moduleName to be a string when provided",
                    )
                }
            }
        }
    } else {
        None
    };

    let entries = match find_swift_vtable(module_name.as_deref(), &type_name) {
        Ok(entries) => entries,
        Err(CommonError::Unsupported(_)) => return JSValue::null().raw(),
        Err(CommonError::InvalidArgument(message)) => return js_throw_type_error(ctx, &message),
        Err(err) => return js_throw_internal_error(ctx, &err.to_string()),
    };

    match entries.into_iter().find(|entry| {
        swift_type_name_matches(&entry.type_name, &type_name)
            && swift_member_name_matches(&entry.member_name, &member_name)
    }) {
        Some(entry) => swift_vtable_entry_to_js(ctx, &entry),
        None => JSValue::null().raw(),
    }
}

unsafe extern "C" fn js_swift_find_witness_table(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let query = match require_string_arg(
        ctx,
        argc,
        argv,
        0,
        "Swift.findWitnessTable(query[, moduleName]) requires at least 1 string argument",
    ) {
        Ok(value) => value,
        Err(err) => return err,
    };

    let module_name =
        if argc >= 2 {
            let value = JSValue(*argv.add(1));
            if value.is_null() || value.is_undefined() {
                None
            } else {
                match value.to_string(ctx) {
                    Some(module_name) => Some(module_name),
                    None => return js_throw_type_error(
                        ctx,
                        "Swift.findWitnessTable(query[, moduleName]) expected moduleName to be a string when provided",
                    ),
                }
            }
        } else {
            None
        };

    let entries = match find_swift_witness_tables(module_name.as_deref(), &query) {
        Ok(entries) => entries,
        Err(CommonError::Unsupported(_)) => return ffi::JS_NewArray(ctx),
        Err(CommonError::InvalidArgument(message)) => return js_throw_type_error(ctx, &message),
        Err(err) => return js_throw_internal_error(ctx, &err.to_string()),
    };

    let array = ffi::JS_NewArray(ctx);
    for (index, entry) in entries.iter().enumerate() {
        ffi::JS_SetPropertyUint32(ctx, array, index as u32, swift_witness_table_to_js(ctx, entry));
    }
    array
}

unsafe extern "C" fn js_swift_witness_table_info(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let type_name = match require_string_arg(
        ctx,
        argc,
        argv,
        0,
        "Swift.witnessTableInfo(typeName, protocolName[, moduleName]) requires at least 2 string arguments",
    ) {
        Ok(value) => value,
        Err(err) => return err,
    };
    let protocol_name = match require_string_arg(
        ctx,
        argc,
        argv,
        1,
        "Swift.witnessTableInfo(typeName, protocolName[, moduleName]) requires at least 2 string arguments",
    ) {
        Ok(value) => value,
        Err(err) => return err,
    };

    let module_name = if argc >= 3 {
        let value = JSValue(*argv.add(2));
        if value.is_null() || value.is_undefined() {
            None
        } else {
            match value.to_string(ctx) {
                Some(module_name) => Some(module_name),
                None => {
                    return js_throw_type_error(
                        ctx,
                        "Swift.witnessTableInfo(typeName, protocolName[, moduleName]) expected moduleName to be a string when provided",
                    )
                }
            }
        }
    } else {
        None
    };

    let entries = match find_swift_witness_tables(module_name.as_deref(), &type_name) {
        Ok(entries) => entries,
        Err(CommonError::Unsupported(_)) => return JSValue::null().raw(),
        Err(CommonError::InvalidArgument(message)) => return js_throw_type_error(ctx, &message),
        Err(err) => return js_throw_internal_error(ctx, &err.to_string()),
    };

    match entries
        .into_iter()
        .find(|entry| swift_conformance_names_match(&entry.type_name, &entry.protocol_name, &type_name, &protocol_name))
    {
        Some(entry) => swift_witness_table_to_js(ctx, &entry),
        None => JSValue::null().raw(),
    }
}

unsafe extern "C" fn js_swift_find_type_layout(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let query = match require_string_arg(
        ctx,
        argc,
        argv,
        0,
        "Swift.findTypeLayout(typeQuery[, moduleName]) requires at least 1 string argument",
    ) {
        Ok(value) => value,
        Err(err) => return err,
    };

    let module_name = if argc >= 2 {
        let value = JSValue(*argv.add(1));
        if value.is_null() || value.is_undefined() {
            None
        } else {
            match value.to_string(ctx) {
                Some(module_name) => Some(module_name),
                None => return js_throw_type_error(
                    ctx,
                    "Swift.findTypeLayout(typeQuery[, moduleName]) expected moduleName to be a string when provided",
                ),
            }
        }
    } else {
        None
    };

    let layouts = match find_swift_type_layouts(module_name.as_deref(), &query) {
        Ok(layouts) => layouts,
        Err(CommonError::Unsupported(_)) => return ffi::JS_NewArray(ctx),
        Err(CommonError::InvalidArgument(message)) => return js_throw_type_error(ctx, &message),
        Err(err) => return js_throw_internal_error(ctx, &err.to_string()),
    };

    let array = ffi::JS_NewArray(ctx);
    for (index, layout) in layouts.iter().enumerate() {
        ffi::JS_SetPropertyUint32(ctx, array, index as u32, swift_type_layout_to_js(ctx, layout));
    }
    array
}

unsafe extern "C" fn js_swift_type_layout_info(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let type_name = match require_string_arg(
        ctx,
        argc,
        argv,
        0,
        "Swift.typeLayoutInfo(typeName[, moduleName]) requires at least 1 string argument",
    ) {
        Ok(value) => value,
        Err(err) => return err,
    };

    let module_name =
        if argc >= 2 {
            let value = JSValue(*argv.add(1));
            if value.is_null() || value.is_undefined() {
                None
            } else {
                match value.to_string(ctx) {
                    Some(module_name) => Some(module_name),
                    None => return js_throw_type_error(
                        ctx,
                        "Swift.typeLayoutInfo(typeName[, moduleName]) expected moduleName to be a string when provided",
                    ),
                }
            }
        } else {
            None
        };

    let layouts = match find_swift_type_layouts(module_name.as_deref(), &type_name) {
        Ok(layouts) => layouts,
        Err(CommonError::Unsupported(_)) => return JSValue::null().raw(),
        Err(CommonError::InvalidArgument(message)) => return js_throw_type_error(ctx, &message),
        Err(err) => return js_throw_internal_error(ctx, &err.to_string()),
    };

    match layouts
        .into_iter()
        .find(|layout| swift_type_name_matches(&layout.type_name, &type_name))
    {
        Some(layout) => swift_type_layout_to_js(ctx, &layout),
        None => JSValue::null().raw(),
    }
}

pub(crate) fn register_swift_api(ctx: &JSContext) -> Result<(), String> {
    let global = ctx.global_object();
    let swift = ctx.new_object();
    let available = swift_support_available();
    let swift_object_class_id = get_or_init_swift_object_class_id(ctx.as_ptr())?;

    swift.set_property(ctx.as_ptr(), "available", JSValue::bool(available));
    swift.set_property(ctx.as_ptr(), "backend", JSValue::string(ctx.as_ptr(), "swift-metadata"));
    swift.set_property(ctx.as_ptr(), "metadataOnly", JSValue::bool(false));
    swift.set_property(ctx.as_ptr(), "metadataQueryAvailable", JSValue::bool(available));
    swift.set_property(ctx.as_ptr(), "typeRepresentationAvailable", JSValue::bool(true));
    swift.set_property(ctx.as_ptr(), "objectRepresentationAvailable", JSValue::bool(true));
    swift.set_property(ctx.as_ptr(), "abiArgumentClassificationAvailable", JSValue::bool(true));
    swift.set_property(ctx.as_ptr(), "objectBridgeAvailable", JSValue::bool(true));
    swift.set_property(ctx.as_ptr(), "liveObjectWrapperAvailable", JSValue::bool(true));
    swift.set_property(ctx.as_ptr(), "runtimeInvocationAvailable", JSValue::bool(false));
    swift.set_property(ctx.as_ptr(), "abiCallAvailable", JSValue::bool(false));
    swift.set_property(
        ctx.as_ptr(),
        "supportedMethodCount",
        JSValue::int(SWIFT_SUPPORTED_METHODS.len() as i32),
    );
    swift.set_property(
        ctx.as_ptr(),
        "unsupportedMethodCount",
        JSValue::int(SWIFT_UNSUPPORTED_METHOD_DESCRIPTORS.len() as i32),
    );
    swift.set_property(
        ctx.as_ptr(),
        "methodDescriptorCount",
        JSValue::int(SWIFT_UNSUPPORTED_METHOD_DESCRIPTORS.len() as i32),
    );
    swift.set_property(
        ctx.as_ptr(),
        "lastErrorText",
        JSValue::string(ctx.as_ptr(), SWIFT_RUNTIME_CALL_UNSUPPORTED_REASON),
    );

    unsafe {
        let ctx_ptr = ctx.as_ptr();
        set_string_array_property(ctx_ptr, &swift, "supportedMethods", SWIFT_SUPPORTED_METHODS);
        let unsupported_methods = SWIFT_UNSUPPORTED_METHOD_DESCRIPTORS
            .iter()
            .map(|descriptor| descriptor.0)
            .collect::<Vec<_>>();
        set_string_array_property(ctx_ptr, &swift, "unsupportedMethods", &unsupported_methods);
        swift.set_property(
            ctx_ptr,
            "unsupportedDescriptors",
            swift_unsupported_descriptors_to_js(ctx_ptr),
        );
        swift.set_property(
            ctx_ptr,
            "methodDescriptors",
            swift_unsupported_descriptors_to_js(ctx_ptr),
        );
        add_cfunction_to_object(ctx_ptr, swift.raw(), "status", js_swift_status, 0);
        add_cfunction_to_object(ctx_ptr, swift.raw(), "info", js_swift_status, 0);
        add_cfunction_to_object(ctx_ptr, swift.raw(), "capabilities", js_swift_status, 0);
        add_cfunction_to_object(ctx_ptr, swift.raw(), "lastError", js_swift_last_error, 0);
        add_cfunction_to_object(ctx_ptr, swift.raw(), "object", js_swift_object, 3);
        add_cfunction_to_object(ctx_ptr, swift.raw(), "metadataOf", js_swift_metadata_of, 1);
        let object_prototype = ffi::JS_NewObject(ctx_ptr);
        add_cfunction_to_object(ctx_ptr, object_prototype, "toPointer", swift_object_to_pointer, 0);
        add_cfunction_to_object(ctx_ptr, object_prototype, "metadata", swift_object_metadata, 0);
        add_cfunction_to_object(ctx_ptr, object_prototype, "isType", swift_object_is_type, 1);
        add_cfunction_to_object(ctx_ptr, object_prototype, "typeName", swift_object_type_name, 0);
        add_cfunction_to_object(ctx_ptr, object_prototype, "ownership", swift_object_ownership, 0);
        add_cfunction_to_object(ctx_ptr, object_prototype, "isDisposed", swift_object_is_disposed, 0);
        add_cfunction_to_object(ctx_ptr, object_prototype, "status", swift_object_status, 0);
        add_cfunction_to_object(ctx_ptr, object_prototype, "retain", swift_object_retain, 0);
        add_cfunction_to_object(ctx_ptr, object_prototype, "dispose", swift_object_dispose, 0);
        add_cfunction_to_object(ctx_ptr, object_prototype, "toString", swift_object_to_string, 0);
        add_cfunction_to_object(ctx_ptr, object_prototype, "toJSON", swift_object_to_string, 0);
        ffi::JS_SetClassProto(ctx_ptr, swift_object_class_id, object_prototype);
        add_cfunction_to_object(
            ctx_ptr,
            swift.raw(),
            "typeRepresentation",
            js_swift_type_representation,
            1,
        );
        add_cfunction_to_object(
            ctx_ptr,
            swift.raw(),
            "objectRepresentation",
            js_swift_object_representation,
            1,
        );
        add_cfunction_to_object(
            ctx_ptr,
            swift.raw(),
            "classifyAbiArgument",
            js_swift_classify_abi_argument,
            1,
        );
        add_cfunction_to_object(ctx_ptr, swift.raw(), "abiArgument", js_swift_classify_abi_argument, 1);
        add_cfunction_to_object(
            ctx_ptr,
            swift.raw(),
            "classifyAbiArguments",
            js_swift_classify_abi_arguments,
            1,
        );
        add_cfunction_to_object(ctx_ptr, swift.raw(), "abiArguments", js_swift_classify_abi_arguments, 1);
        add_cfunction_to_object(ctx_ptr, swift.raw(), "demangle", js_swift_demangle, 1);
        add_cfunction_to_object(ctx_ptr, swift.raw(), "findSymbols", js_swift_find_symbols, 2);
        add_cfunction_to_object(ctx_ptr, swift.raw(), "symbols", js_swift_find_symbols, 2);
        add_cfunction_to_object(ctx_ptr, swift.raw(), "symbolInfo", js_swift_symbol_info, 2);
        add_cfunction_to_object(ctx_ptr, swift.raw(), "findSymbolInfo", js_swift_symbol_info, 2);
        add_cfunction_to_object(ctx_ptr, swift.raw(), "findProtocols", js_swift_find_protocols, 2);
        add_cfunction_to_object(ctx_ptr, swift.raw(), "protocols", js_swift_find_protocols, 2);
        add_cfunction_to_object(ctx_ptr, swift.raw(), "protocolInfo", js_swift_protocol_info, 2);
        add_cfunction_to_object(ctx_ptr, swift.raw(), "findProtocolInfo", js_swift_protocol_info, 2);
        add_cfunction_to_object(ctx_ptr, swift.raw(), "findConformances", js_swift_find_conformances, 2);
        add_cfunction_to_object(ctx_ptr, swift.raw(), "conformances", js_swift_find_conformances, 2);
        add_cfunction_to_object(ctx_ptr, swift.raw(), "conformanceInfo", js_swift_conformance_info, 3);
        add_cfunction_to_object(
            ctx_ptr,
            swift.raw(),
            "findConformanceInfo",
            js_swift_conformance_info,
            3,
        );
        add_cfunction_to_object(ctx_ptr, swift.raw(), "findMetadata", js_swift_find_metadata, 2);
        add_cfunction_to_object(ctx_ptr, swift.raw(), "metadata", js_swift_find_metadata, 2);
        add_cfunction_to_object(ctx_ptr, swift.raw(), "metadataInfo", js_swift_metadata_info, 2);
        add_cfunction_to_object(ctx_ptr, swift.raw(), "findMetadataInfo", js_swift_metadata_info, 2);
        add_cfunction_to_object(ctx_ptr, swift.raw(), "findVtable", js_swift_find_vtable, 2);
        add_cfunction_to_object(ctx_ptr, swift.raw(), "vtable", js_swift_find_vtable, 2);
        add_cfunction_to_object(ctx_ptr, swift.raw(), "vtableInfo", js_swift_vtable_info, 3);
        add_cfunction_to_object(ctx_ptr, swift.raw(), "findVtableInfo", js_swift_vtable_info, 3);
        add_cfunction_to_object(ctx_ptr, swift.raw(), "findWitnessTable", js_swift_find_witness_table, 2);
        add_cfunction_to_object(ctx_ptr, swift.raw(), "witnessTable", js_swift_find_witness_table, 2);
        add_cfunction_to_object(ctx_ptr, swift.raw(), "witnessTableInfo", js_swift_witness_table_info, 3);
        add_cfunction_to_object(
            ctx_ptr,
            swift.raw(),
            "findWitnessTableInfo",
            js_swift_witness_table_info,
            3,
        );
        add_cfunction_to_object(ctx_ptr, swift.raw(), "findTypeLayout", js_swift_find_type_layout, 2);
        add_cfunction_to_object(ctx_ptr, swift.raw(), "typeLayout", js_swift_find_type_layout, 2);
        add_cfunction_to_object(ctx_ptr, swift.raw(), "typeLayoutInfo", js_swift_type_layout_info, 2);
        add_cfunction_to_object(ctx_ptr, swift.raw(), "findTypeLayoutInfo", js_swift_type_layout_info, 2);
        add_cfunction_to_object(ctx_ptr, swift.raw(), "findMethods", js_swift_find_methods, 3);
        add_cfunction_to_object(ctx_ptr, swift.raw(), "methods", js_swift_find_methods, 3);
        add_cfunction_to_object(ctx_ptr, swift.raw(), "methodInfo", js_swift_method_info, 3);
        add_cfunction_to_object(ctx_ptr, swift.raw(), "findMethodInfo", js_swift_method_info, 3);
        add_cfunction_to_object(ctx_ptr, swift.raw(), "findTypeMethods", js_swift_find_type_methods, 2);
        add_cfunction_to_object(ctx_ptr, swift.raw(), "typeMethods", js_swift_find_type_methods, 2);
        add_cfunction_to_object(ctx_ptr, swift.raw(), "findMethodOwners", js_swift_find_method_owners, 2);
        add_cfunction_to_object(ctx_ptr, swift.raw(), "methodOwners", js_swift_find_method_owners, 2);
        add_cfunction_to_object(ctx_ptr, swift.raw(), "findTypesOfKind", js_swift_find_types_of_kind, 3);
        add_cfunction_to_object(ctx_ptr, swift.raw(), "typesOfKind", js_swift_find_types_of_kind, 3);
        add_cfunction_to_object(ctx_ptr, swift.raw(), "findTypes", js_swift_find_types, 2);
        add_cfunction_to_object(ctx_ptr, swift.raw(), "types", js_swift_find_types, 2);
        add_cfunction_to_object(ctx_ptr, swift.raw(), "typeInfo", js_swift_type_info, 2);
        add_cfunction_to_object(ctx_ptr, swift.raw(), "findTypeInfo", js_swift_type_info, 2);
        add_cfunction_to_object(ctx_ptr, swift.raw(), "typeSourceKinds", js_swift_type_source_kinds, 0);
        add_cfunction_to_object(ctx_ptr, swift.raw(), "typeKinds", js_swift_type_source_kinds, 0);
        for &(name, arity, _, _) in SWIFT_UNSUPPORTED_METHOD_DESCRIPTORS {
            add_cfunction_to_object(ctx_ptr, swift.raw(), name, js_swift_unsupported, arity);
        }
    }

    global.set_property(ctx.as_ptr(), "Swift", swift);
    global.free(ctx.as_ptr());

    let value = ctx.eval(SWIFT_THIN_CALL_BOOTSTRAP, "<swift-thin-call-api>")?;
    value.free(ctx.as_ptr());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::JSRuntime;

    fn with_context(test: impl FnOnce(&JSContext)) {
        let runtime = JSRuntime::new().expect("create QuickJS runtime");
        let context = runtime.new_context().expect("create QuickJS context");
        register_swift_api(&context).expect("register Swift API");
        test(&context);
    }

    fn with_fake_native_function(test: impl FnOnce(&JSContext)) {
        let runtime = JSRuntime::new().expect("create QuickJS runtime");
        let context = runtime.new_context().expect("create QuickJS context");
        let bootstrap = context
            .eval(
                "globalThis.NativeFunction = function(address, ret, args) { const fn = function() { return ret + ':' + args.join(',') + ':' + Array.prototype.join.call(arguments, ','); }; fn.address = address; fn.returnType = ret; fn.argumentTypes = args; return fn; };",
                "<fake-native-function>",
            )
            .expect("install fake NativeFunction");
        bootstrap.free(context.as_ptr());
        register_swift_api(&context).expect("register Swift API");
        test(&context);
    }

    fn eval_text(context: &JSContext, script: &str) -> String {
        let value = context.eval(script, "<swift-test>").expect("evaluate Swift expression");
        let text = value.to_string(context.as_ptr()).expect("stringify Swift expression");
        value.free(context.as_ptr());
        text
    }

    fn eval_error(context: &JSContext, script: &str) -> String {
        match context.eval(script, "<swift-test>") {
            Ok(value) => {
                value.free(context.as_ptr());
                panic!("Swift expression unexpectedly succeeded")
            }
            Err(error) => error,
        }
    }

    #[test]
    fn models_swift_object_disposal_as_idempotent_and_non_owned_afterward() {
        let mut state = SwiftObjectState {
            object_address: 0x1000,
            metadata_address: 0x2000,
            metadata_inferred: false,
            metadata_verified: true,
            type_name: Some("Demo.Value".into()),
            ownership: SwiftObjectOwnership::Adopt,
            owned_references: 1,
            release_address: Some(0x3000),
            retain_available: true,
            release_available: true,
            disposed: false,
        };

        assert!(!state.is_disposed());
        assert_eq!(state.ownership_name(), "adopted");
        assert_eq!(state.metadata_source_name(), "explicit");
        assert!(state.mark_disposed());
        assert!(state.is_disposed());
        assert_eq!(state.ownership_name(), "disposed");
        assert_eq!(state.metadata_source_name(), "none");
        assert_eq!(state.object_address, 0);
        assert_eq!(state.metadata_address, 0);
        assert_eq!(state.owned_references, 0);
        assert!(state.release_address.is_none());
        assert!(!state.mark_disposed());
    }

    #[test]
    fn exposes_swift_object_lifecycle_contract_through_quickjs() {
        let runtime = JSRuntime::new().expect("create QuickJS runtime");
        let context = runtime.new_context().expect("create QuickJS context");
        register_swift_api(&context).expect("register Swift API");
        let wrapper = unsafe {
            create_swift_object_wrapper(
                context.as_ptr(),
                SwiftObjectState {
                    object_address: 0x1000,
                    metadata_address: 0x2000,
                    metadata_inferred: true,
                    metadata_verified: true,
                    type_name: Some("Demo.Value".into()),
                    ownership: SwiftObjectOwnership::Borrowed,
                    owned_references: 0,
                    release_address: None,
                    retain_available: false,
                    release_available: false,
                    disposed: false,
                },
            )
        };
        assert_eq!(unsafe { ffi::qjs_is_exception(wrapper) }, 0);
        let global = context.global_object();
        assert!(global.set_property(context.as_ptr(), "__swiftTestObject", JSValue(wrapper)));
        global.free(context.as_ptr());

        assert_eq!(
            eval_text(
                &context,
                "(function () { const s = __swiftTestObject.status(); return [__swiftTestObject.isDisposed(), s.disposed, s.ownership, s.metadataSource, s.metadataVerified, String(s.ownedReferenceCount), s.objectAddress !== null].join('|'); })()",
            ),
            "false|false|borrowed|inferred|true|0|true"
        );
        assert_eq!(
            eval_text(
                &context,
                "(function () { __swiftTestObject.dispose(); __swiftTestObject.dispose(); const s = __swiftTestObject.status(); return [__swiftTestObject.isDisposed(), s.disposed, s.ownership, s.metadataSource, s.metadataVerified, String(s.ownedReferenceCount), s.objectAddress === null, String(__swiftTestObject)].join('|'); })()",
            ),
            "true|true|disposed|none|false|0|true|<SwiftObject disposed>"
        );
        assert!(eval_error(&context, "__swiftTestObject.toPointer()").contains(SWIFT_OBJECT_DISPOSED_ERROR));
    }

    #[test]
    fn classifies_swift_abi_shapes_without_enabling_runtime_calls() {
        let scalar = classify_swift_abi_type("Swift.Int64").expect("classify integer");
        assert_eq!(scalar.type_representation, "scalar");
        assert_eq!(scalar.argument_kind, "integer");
        assert_eq!(scalar.pass_mode, "direct-scalar");

        let pointer = classify_swift_abi_type("Swift.UnsafePointer<Swift.UInt8>").expect("classify pointer");
        assert_eq!(pointer.argument_kind, "pointer");
        assert_eq!(pointer.pass_mode, "direct-pointer");

        let function = classify_swift_abi_type("(Swift.Int) -> Swift.String").expect("classify function");
        assert_eq!(function.object_representation, "thick-function");
        assert_eq!(function.pass_mode, "context-dependent");

        let nominal = classify_swift_abi_type("Demo.ViewController").expect("classify nominal type");
        assert_eq!(nominal.argument_kind, "nominal-value-or-reference");
        assert_eq!(nominal.pass_mode, "metadata-dependent");
        assert!(classify_swift_abi_type("  ").unwrap_err().contains("must not be empty"));
    }

    #[test]
    fn exposes_swift_capability_and_unsupported_descriptors() {
        with_context(|context| {
            assert_eq!(
                eval_text(
                    context,
                    "!Swift.status().metadataOnly && Swift.status().typeRepresentationAvailable && Swift.status().abiArgumentClassificationAvailable && Swift.status().objectBridgeAvailable && Swift.status().liveObjectWrapperAvailable && !Swift.status().fullSwiftAbiCallAvailable"
                ),
                "true"
            );
            assert_eq!(
                eval_text(
                    context,
                    "Swift.status().unsupportedMethodCount === Swift.status().unsupportedDescriptors.length && Swift.status().methodDescriptorCount === Swift.status().methodDescriptors.length && Swift.status().unsupportedMethods.indexOf('invoke') === -1 && Swift.status().supportedMethods.indexOf('thinFunction') !== -1 && Swift.unsupportedMethodCount === Swift.methodDescriptors.length && Swift.methodDescriptors[0].name === 'construct' && Swift.methodDescriptors[0].available === false && Swift.object.length === 3"
                ),
                "true"
            );
        });
    }

    #[test]
    fn exposes_type_object_and_argument_representation_boundaries() {
        with_context(|context| {
            assert_eq!(
                eval_text(
                    context,
                    "Swift.typeRepresentation('Swift.Int64').typeRepresentation + ':' + Swift.objectRepresentation('any Demo.Renderable').objectRepresentation + ':' + Swift.abiArgument('(Swift.Int) -> Swift.String').passMode"
                ),
                "scalar:existential-container:context-dependent"
            );
            assert_eq!(
                eval_text(
                    context,
                    "Swift.abiArguments(['Swift.Int64', 'UnsafeRawPointer', 'Demo.Value']).map(function(x) { return x.argumentKind; }).join(':')"
                ),
                "integer:pointer:nominal-value-or-reference"
            );
            assert_eq!(
                eval_text(
                    context,
                    "Swift.abiArgument('Demo.Value').metadataOnly && !Swift.abiArgument('Demo.Value').callSupported && !Swift.abiArgument('Demo.Value').thinCallSupported && Swift.abiArgument('Swift.Int64').thinCallSupported"
                ),
                "true"
            );
        });
    }

    #[test]
    fn maps_verified_thin_signatures_to_native_function_types() {
        with_fake_native_function(|context| {
            assert_eq!(
                eval_text(
                    context,
                    "(function () { const fn = Swift.thinFunction(4096, 'Swift.UInt64', ['Swift.Int32', 'UnsafeRawPointer', 'Swift.Double'], { abi: 'c-compatible', verified: true }); return fn.returnType + ':' + fn.argumentTypes.join(',') + ':' + fn.swiftAbi; })()"
                ),
                "uint64:int32,pointer,double:c-compatible-thin"
            );
            assert_eq!(
                eval_text(
                    context,
                    "Swift.invoke(4096, { returnType: 'Swift.Int', argumentTypes: ['Swift.UInt8'], abi: 'c-compatible', verified: true }, [7])"
                ),
                "int64:uint8:7"
            );
            assert_eq!(eval_text(context, "Swift.status().thinAbiCallAvailable"), "true");
        });
    }

    #[test]
    fn verifies_native_call_shapes_and_c_type_aliases_before_construction() {
        with_fake_native_function(|context| {
            assert_eq!(
                eval_text(
                    context,
                    "(function () { const s = Swift.thinSignature('Swift.Int', ['CInt', 'CULong', 'CFloat', 'UnsafeRawPointer'], { abi: 'c-compatible', verified: true }); return s.nativeReturnType + ':' + s.nativeArgumentTypes.join(',') + ':' + s.abi + ':' + s.verified; })()"
                ),
                "int64:int32,uint64,float,pointer:c-compatible-thin:true"
            );
            assert_eq!(
                eval_text(
                    context,
                    "Swift.thinFunction(4096, 'Swift.Int', ['Swift.UInt'], { abi: 'c-compatible', verified: true }).swiftSignature.nativeArgumentTypes[0]"
                ),
                "uint64"
            );
            assert_eq!(
                eval_text(context, "Swift.abiArgument('Swift.Float16').thinCallSupported"),
                "false"
            );
        });
    }

    #[test]
    fn rejects_invalid_descriptors_and_live_runtime_calls_stably() {
        with_context(|context| {
            assert!(eval_error(context, "Swift.classifyAbiArgument('')").contains("must not be empty"));
            assert!(eval_error(context, "Swift.classifyAbiArguments(['Swift.Int', 1])")
                .contains("typeNames[1] must be a string"));
            assert!(eval_error(context, "Swift.invoke()").contains("signature must be an object"));
            assert!(eval_error(
                context,
                "Swift.thinFunction(1, 'Swift.Int', [], { abi: 'c-compatible', verified: false })"
            )
            .contains("verified: true"));
            assert!(eval_error(
                context,
                "Swift.thinFunction(1, 'Demo.Value', [], { abi: 'c-compatible', verified: true })"
            )
            .contains("requires metadata"));
            assert!(eval_error(
                context,
                "Swift.thinSignature('Swift.Never', [], { abi: 'c-compatible', verified: true })"
            )
            .contains("non-returning"));
            assert!(eval_error(
                context,
                "Swift.thinSignature('Swift.Int', [], { abi: 'c-compatible', verified: true, throws: 'maybe' })"
            )
            .contains("must be boolean"));
            assert!(eval_error(
                context,
                "Swift.thinSignature('Swift.Int', [], { abi: 'c-compatible', verified: true, async: true })"
            )
            .contains("does not accept async"));
            #[cfg(not(any(target_os = "ios", target_os = "macos")))]
            {
                assert!(eval_error(context, "Swift.metadataOf(4096)").contains("only available on Apple targets"));
                assert!(eval_error(context, "Swift.object(4096)").contains("only available on Apple targets"));
            }
        });
    }
}
