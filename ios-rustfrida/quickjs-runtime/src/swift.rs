use crate::context::JSContext;
use crate::ffi;
use crate::ptr::create_native_pointer;
use crate::util::{add_cfunction_to_object, js_throw_internal_error, js_throw_type_error, require_string_arg};
use crate::value::JSValue;
use common::Error as CommonError;
use native_api::{
    find_swift_conformances, find_swift_metadata, find_swift_method_owners, find_swift_methods, find_swift_protocols,
    find_swift_symbols, find_swift_type_methods, find_swift_types, find_swift_types_of_kind, swift_demangle_symbol,
    swift_support_available, swift_type_source_kinds, SwiftConformance, SwiftProtocol, SwiftSymbol, SwiftType,
};

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

pub(crate) fn register_swift_api(ctx: &JSContext) {
    let global = ctx.global_object();
    let swift = ctx.new_object();

    swift.set_property(ctx.as_ptr(), "available", JSValue::bool(swift_support_available()));

    unsafe {
        let ctx_ptr = ctx.as_ptr();
        add_cfunction_to_object(ctx_ptr, swift.raw(), "demangle", js_swift_demangle, 1);
        add_cfunction_to_object(ctx_ptr, swift.raw(), "findSymbols", js_swift_find_symbols, 2);
        add_cfunction_to_object(ctx_ptr, swift.raw(), "findProtocols", js_swift_find_protocols, 2);
        add_cfunction_to_object(ctx_ptr, swift.raw(), "findConformances", js_swift_find_conformances, 2);
        add_cfunction_to_object(ctx_ptr, swift.raw(), "findMetadata", js_swift_find_metadata, 2);
        add_cfunction_to_object(ctx_ptr, swift.raw(), "findMethods", js_swift_find_methods, 3);
        add_cfunction_to_object(ctx_ptr, swift.raw(), "findTypeMethods", js_swift_find_type_methods, 2);
        add_cfunction_to_object(ctx_ptr, swift.raw(), "findMethodOwners", js_swift_find_method_owners, 2);
        add_cfunction_to_object(ctx_ptr, swift.raw(), "findTypesOfKind", js_swift_find_types_of_kind, 3);
        add_cfunction_to_object(ctx_ptr, swift.raw(), "findTypes", js_swift_find_types, 2);
        add_cfunction_to_object(ctx_ptr, swift.raw(), "typeSourceKinds", js_swift_type_source_kinds, 0);
    }

    global.set_property(ctx.as_ptr(), "Swift", swift);
    global.free(ctx.as_ptr());
}
