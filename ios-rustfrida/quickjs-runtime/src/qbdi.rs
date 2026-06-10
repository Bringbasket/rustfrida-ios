use crate::context::JSContext;
use crate::ffi;
use crate::util::{add_cfunction_to_object, js_throw_internal_error};
use crate::value::JSValue;

const QBDI_UNSUPPORTED_MESSAGE: &str =
    "QBDI VM APIs are not available on iOS; use trace/stalker/hfl/jhook/shook via the ARM64 hook engine";

const QBDI_UNSUPPORTED_METHODS: &[&str] = &[
    "newVM",
    "destroyVM",
    "addInstrumentedRange",
    "addInstrumentedModule",
    "addInstrumentedModuleFromAddr",
    "instrumentAllExecutableMaps",
    "removeInstrumentedRange",
    "removeAllInstrumentedRanges",
    "deleteAllInstrumentations",
    "recordMemoryAccess",
    "allocateVirtualStack",
    "clearVirtualStacks",
    "simulateCall",
    "run",
    "call",
    "switchStackAndCall",
    "getGPR",
    "setGPR",
    "getFPR",
    "setFPR",
    "getErrno",
    "setErrno",
    "setTraceBundleMetadata",
    "registerTraceCallbacks",
    "unregisterTraceCallbacks",
];

const QBDI_METHOD_DESCRIPTORS: &[(&str, i32, &str, &str)] = &[
    ("newVM", 0, "vm", "trace/stalker/hfl for iOS runtime observation"),
    ("destroyVM", 1, "vm", "trace/stalker stop commands"),
    (
        "addInstrumentedRange",
        3,
        "instrumentation",
        "trace <address> or stalker <address>",
    ),
    (
        "addInstrumentedModule",
        2,
        "instrumentation",
        "trace native <module> -- <symbol>",
    ),
    (
        "addInstrumentedModuleFromAddr",
        2,
        "instrumentation",
        "native.image <address> plus trace/stalker",
    ),
    (
        "instrumentAllExecutableMaps",
        1,
        "instrumentation",
        "stalker <address> with explicit target filters",
    ),
    (
        "removeInstrumentedRange",
        3,
        "instrumentation",
        "trace stop or stalker stop",
    ),
    (
        "removeAllInstrumentedRanges",
        1,
        "instrumentation",
        "trace stop or stalker stop",
    ),
    (
        "deleteAllInstrumentations",
        1,
        "instrumentation",
        "trace stop or stalker stop",
    ),
    (
        "recordMemoryAccess",
        2,
        "memory",
        "stalker memory telemetry when available",
    ),
    (
        "allocateVirtualStack",
        2,
        "call",
        "NativeFunction / direct call helpers",
    ),
    ("clearVirtualStacks", 1, "call", "not applicable on iOS hook engine"),
    ("simulateCall", 2, "call", "NativeFunction / direct call helpers"),
    ("run", 3, "execution", "trace/stalker inline instrumentation"),
    ("call", 2, "call", "NativeFunction / direct call helpers"),
    ("switchStackAndCall", 3, "call", "NativeFunction / direct call helpers"),
    ("getGPR", 2, "registers", "trace/stalker callback context"),
    ("setGPR", 3, "registers", "trace/stalker callback context"),
    ("getFPR", 2, "registers", "trace/stalker callback context"),
    ("setFPR", 4, "registers", "trace/stalker callback context"),
    ("getErrno", 1, "state", "native.lastError when available"),
    ("setErrno", 2, "state", "not applicable on iOS hook engine"),
    (
        "setTraceBundleMetadata",
        2,
        "trace-export",
        "controller command JSON metadata",
    ),
    (
        "registerTraceCallbacks",
        2,
        "trace-export",
        "trace/stalker controller dispatch",
    ),
    (
        "unregisterTraceCallbacks",
        1,
        "trace-export",
        "trace stop or stalker stop",
    ),
];

unsafe fn set_string_array_property(ctx: *mut ffi::JSContext, object: &JSValue, name: &str, items: &[&str]) {
    let array = ffi::JS_NewArray(ctx);
    for (index, item) in items.iter().enumerate() {
        ffi::JS_SetPropertyUint32(ctx, array, index as u32, JSValue::string(ctx, item).raw());
    }
    object.set_property(ctx, name, JSValue(array));
}

unsafe fn qbdi_method_descriptors_array(ctx: *mut ffi::JSContext) -> JSValue {
    let array = ffi::JS_NewArray(ctx);
    for (index, (name, arity, category, replacement)) in QBDI_METHOD_DESCRIPTORS.iter().enumerate() {
        let entry = JSValue(ffi::JS_NewObject(ctx));
        entry.set_property(ctx, "name", JSValue::string(ctx, name));
        entry.set_property(ctx, "arity", JSValue::int(*arity));
        entry.set_property(ctx, "category", JSValue::string(ctx, category));
        entry.set_property(ctx, "available", JSValue::bool(false));
        entry.set_property(ctx, "androidOnly", JSValue::bool(true));
        entry.set_property(ctx, "commandJsonEligible", JSValue::bool(false));
        entry.set_property(ctx, "replacement", JSValue::string(ctx, replacement));
        entry.set_property(ctx, "message", JSValue::string(ctx, QBDI_UNSUPPORTED_MESSAGE));
        ffi::JS_SetPropertyUint32(ctx, array, index as u32, entry.raw());
    }
    JSValue(array)
}

unsafe fn qbdi_constants_object(ctx: *mut ffi::JSContext) -> JSValue {
    let constants = JSValue(ffi::JS_NewObject(ctx));
    constants.set_property(ctx, "MEMORY_READ", JSValue::int(1));
    constants.set_property(ctx, "MEMORY_WRITE", JSValue::int(2));
    constants.set_property(ctx, "MEMORY_READ_WRITE", JSValue::int(3));
    constants.set_property(ctx, "REG_RETURN", JSValue::int(0));
    constants.set_property(ctx, "REG_BP", JSValue::int(29));
    constants.set_property(ctx, "REG_LR", JSValue::int(30));
    constants.set_property(ctx, "REG_SP", JSValue::int(31));
    constants.set_property(ctx, "REG_FLAG", JSValue::int(32));
    constants.set_property(ctx, "REG_PC", JSValue::int(33));
    constants
}

unsafe fn qbdi_status_object(ctx: *mut ffi::JSContext) -> JSValue {
    let result = JSValue(ffi::JS_NewObject(ctx));
    result.set_property(ctx, "available", JSValue::bool(false));
    result.set_property(ctx, "platform", JSValue::string(ctx, "ios"));
    result.set_property(ctx, "backend", JSValue::string(ctx, "unsupported-ios"));
    result.set_property(ctx, "androidReferenceBackend", JSValue::string(ctx, "QBDI"));
    result.set_property(ctx, "iosAlternativeBackend", JSValue::string(ctx, "arm64-hook-engine"));
    result.set_property(ctx, "compatible", JSValue::bool(false));
    result.set_property(ctx, "qbdiVmAvailable", JSValue::bool(false));
    result.set_property(ctx, "qbdiHelperAvailable", JSValue::bool(false));
    result.set_property(ctx, "virtualStackAvailable", JSValue::bool(false));
    result.set_property(ctx, "registerStateApiAvailable", JSValue::bool(false));
    result.set_property(ctx, "memoryAccessTraceAvailable", JSValue::bool(false));
    result.set_property(ctx, "traceBundleExportAvailable", JSValue::bool(false));
    result.set_property(ctx, "supportedMethodCount", JSValue::int(0));
    result.set_property(
        ctx,
        "recommendedPath",
        JSValue::string(ctx, "trace-stalker-inline-hook"),
    );
    result.set_property(ctx, "lastError", JSValue::string(ctx, QBDI_UNSUPPORTED_MESSAGE));
    result.set_property(ctx, "constantCount", JSValue::int(9));
    result.set_property(ctx, "constants", qbdi_constants_object(ctx));
    set_string_array_property(
        ctx,
        &result,
        "supportedCommands",
        &["qbdi.status", "qbdi.info", "qbdi.methods", "qbdi.lastError"],
    );
    result.set_property(ctx, "supportedCommandCount", JSValue::int(4));
    set_string_array_property(ctx, &result, "unsupportedMethods", QBDI_UNSUPPORTED_METHODS);
    result.set_property(
        ctx,
        "unsupportedMethodCount",
        JSValue::int(QBDI_UNSUPPORTED_METHODS.len() as i32),
    );
    result.set_property(
        ctx,
        "methodDescriptorCount",
        JSValue::int(QBDI_METHOD_DESCRIPTORS.len() as i32),
    );
    result.set_property(ctx, "methodDescriptors", qbdi_method_descriptors_array(ctx));
    result
}

unsafe extern "C" fn js_qbdi_unsupported(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    js_throw_internal_error(ctx, QBDI_UNSUPPORTED_MESSAGE)
}

unsafe extern "C" fn js_qbdi_last_error(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    JSValue::string(ctx, QBDI_UNSUPPORTED_MESSAGE).raw()
}

unsafe extern "C" fn js_qbdi_shutdown(
    _ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    JSValue::bool(false).raw()
}

unsafe extern "C" fn js_qbdi_status(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    qbdi_status_object(ctx).raw()
}

unsafe extern "C" fn js_qbdi_methods(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    qbdi_method_descriptors_array(ctx).raw()
}

pub(crate) fn register_qbdi_api(ctx: &JSContext) {
    let global = ctx.global_object();
    let qbdi = ctx.new_object();
    let ctx_ptr = ctx.as_ptr();

    qbdi.set_property(ctx_ptr, "available", JSValue::bool(false));
    qbdi.set_property(ctx_ptr, "platform", JSValue::string(ctx_ptr, "ios"));
    qbdi.set_property(ctx_ptr, "backend", JSValue::string(ctx_ptr, "unsupported-ios"));
    qbdi.set_property(ctx_ptr, "androidReferenceBackend", JSValue::string(ctx_ptr, "QBDI"));
    qbdi.set_property(
        ctx_ptr,
        "iosAlternativeBackend",
        JSValue::string(ctx_ptr, "arm64-hook-engine"),
    );
    qbdi.set_property(ctx_ptr, "compatible", JSValue::bool(false));
    qbdi.set_property(ctx_ptr, "qbdiVmAvailable", JSValue::bool(false));
    qbdi.set_property(ctx_ptr, "qbdiHelperAvailable", JSValue::bool(false));
    qbdi.set_property(ctx_ptr, "virtualStackAvailable", JSValue::bool(false));
    qbdi.set_property(ctx_ptr, "registerStateApiAvailable", JSValue::bool(false));
    qbdi.set_property(ctx_ptr, "memoryAccessTraceAvailable", JSValue::bool(false));
    qbdi.set_property(ctx_ptr, "traceBundleExportAvailable", JSValue::bool(false));
    qbdi.set_property(
        ctx_ptr,
        "recommendedPath",
        JSValue::string(ctx_ptr, "trace-stalker-inline-hook"),
    );
    qbdi.set_property(
        ctx_ptr,
        "lastErrorMessage",
        JSValue::string(ctx_ptr, QBDI_UNSUPPORTED_MESSAGE),
    );
    qbdi.set_property(
        ctx_ptr,
        "methodCount",
        JSValue::int(QBDI_METHOD_DESCRIPTORS.len() as i32),
    );
    unsafe {
        qbdi.set_property(ctx_ptr, "methodDescriptors", qbdi_method_descriptors_array(ctx_ptr));
    }

    // Constants mirror the Android QBDI bridge so scripts can feature-detect without
    // tripping over platform-specific register numbering.
    qbdi.set_property(ctx_ptr, "MEMORY_READ", JSValue::int(1));
    qbdi.set_property(ctx_ptr, "MEMORY_WRITE", JSValue::int(2));
    qbdi.set_property(ctx_ptr, "MEMORY_READ_WRITE", JSValue::int(3));
    qbdi.set_property(ctx_ptr, "REG_RETURN", JSValue::int(0));
    qbdi.set_property(ctx_ptr, "REG_BP", JSValue::int(29));
    qbdi.set_property(ctx_ptr, "REG_LR", JSValue::int(30));
    qbdi.set_property(ctx_ptr, "REG_SP", JSValue::int(31));
    qbdi.set_property(ctx_ptr, "REG_FLAG", JSValue::int(32));
    qbdi.set_property(ctx_ptr, "REG_PC", JSValue::int(33));

    unsafe {
        for name in QBDI_UNSUPPORTED_METHODS {
            add_cfunction_to_object(ctx_ptr, qbdi.raw(), name, js_qbdi_unsupported, 0);
        }
        add_cfunction_to_object(ctx_ptr, qbdi.raw(), "status", js_qbdi_status, 0);
        add_cfunction_to_object(ctx_ptr, qbdi.raw(), "info", js_qbdi_status, 0);
        add_cfunction_to_object(ctx_ptr, qbdi.raw(), "methods", js_qbdi_methods, 0);
        add_cfunction_to_object(ctx_ptr, qbdi.raw(), "lastError", js_qbdi_last_error, 0);
        add_cfunction_to_object(ctx_ptr, qbdi.raw(), "shutdown", js_qbdi_shutdown, 0);
    }

    global.set_property(ctx_ptr, "qbdi", qbdi);
    global.free(ctx_ptr);
}
