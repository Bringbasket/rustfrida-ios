use crate::context::JSContext;
use crate::ffi;
use crate::ptr::create_native_pointer;
use crate::util::{add_cfunction_to_object, js_throw_internal_error};
use crate::value::JSValue;
use native_api::{
    detect_hook_environment, find_image_dependencies, find_image_exports, find_image_imports, find_image_load_commands,
    find_image_rpaths, find_image_sections, find_image_segments, find_native_symbols, hook_environment_recommendations,
    image_dependency_support_available, image_import_support_available, image_load_command_support_available,
    image_rpath_support_available, image_section_support_available, image_segment_support_available,
    native_export_support_available, native_symbol_support_available, resolve_hook_strategy,
};

unsafe fn set_string_array_property(ctx: *mut ffi::JSContext, obj: ffi::JSValue, name: &str, items: &[String]) {
    let array = ffi::JS_NewArray(ctx);
    for (index, item) in items.iter().enumerate() {
        ffi::JS_SetPropertyUint32(ctx, array, index as u32, JSValue::string(ctx, item).raw());
    }
    JSValue(obj).set_property(ctx, name, JSValue(array));
}

unsafe fn report_to_js(ctx: *mut ffi::JSContext, report: &native_api::HookEnvironmentReport) -> ffi::JSValue {
    let result = JSValue(ffi::JS_NewObject(ctx));
    let decision = resolve_hook_strategy().ok();

    match &report.active_backend {
        Some(active) => result.set_property(ctx, "activeBackend", JSValue::string(ctx, active)),
        None => result.set_property(ctx, "activeBackend", JSValue::null()),
    };

    if let Some(decision) = &decision {
        result.set_property(ctx, "policy", JSValue::string(ctx, decision.policy.as_str()));
        result.set_property(ctx, "strategy", JSValue::string(ctx, &decision.strategy));
        result.set_property(ctx, "allowed", JSValue::bool(decision.allowed));
        result.set_property(ctx, "inlineHooksAllowed", JSValue::bool(decision.inline_hooks_allowed));
        match &decision.reason {
            Some(reason) => result.set_property(ctx, "reason", JSValue::string(ctx, reason)),
            None => result.set_property(ctx, "reason", JSValue::null()),
        };
    } else {
        result.set_property(ctx, "policy", JSValue::string(ctx, "warn"));
        result.set_property(ctx, "strategy", JSValue::null());
        result.set_property(ctx, "allowed", JSValue::bool(true));
        result.set_property(ctx, "inlineHooksAllowed", JSValue::bool(true));
        result.set_property(ctx, "reason", JSValue::null());
    }

    let warnings = ffi::JS_NewArray(ctx);
    for (index, warning) in report.warnings.iter().enumerate() {
        ffi::JS_SetPropertyUint32(ctx, warnings, index as u32, JSValue::string(ctx, warning).raw());
    }
    result.set_property(ctx, "warnings", JSValue(warnings));

    let recommendations = ffi::JS_NewArray(ctx);
    for (index, recommendation) in hook_environment_recommendations(report, decision.as_ref())
        .iter()
        .enumerate()
    {
        ffi::JS_SetPropertyUint32(
            ctx,
            recommendations,
            index as u32,
            JSValue::string(ctx, recommendation).raw(),
        );
    }
    result.set_property(ctx, "recommendations", JSValue(recommendations));

    let backends = ffi::JS_NewArray(ctx);
    for (index, backend) in report.backends.iter().enumerate() {
        let item = JSValue(ffi::JS_NewObject(ctx));
        item.set_property(ctx, "id", JSValue::string(ctx, &backend.id));
        item.set_property(ctx, "name", JSValue::string(ctx, &backend.display_name));
        item.set_property(ctx, "loaded", JSValue::bool(!backend.loaded_images.is_empty()));
        item.set_property(
            ctx,
            "presentOnFilesystem",
            JSValue::bool(!backend.filesystem_paths.is_empty()),
        );
        set_string_array_property(ctx, item.raw(), "loadedImages", &backend.loaded_images);
        set_string_array_property(ctx, item.raw(), "filesystemPaths", &backend.filesystem_paths);
        ffi::JS_SetPropertyUint32(ctx, backends, index as u32, item.raw());
    }
    result.set_property(ctx, "backends", JSValue(backends));

    result.raw()
}

unsafe fn native_symbol_to_js(ctx: *mut ffi::JSContext, symbol: &native_api::NativeSymbol) -> ffi::JSValue {
    let result = JSValue(ffi::JS_NewObject(ctx));
    result.set_property(ctx, "moduleName", JSValue::string(ctx, &symbol.module_name));
    result.set_property(ctx, "moduleBase", create_native_pointer(ctx, symbol.module_base as u64));
    result.set_property(ctx, "name", JSValue::string(ctx, &symbol.symbol_name));
    result.set_property(ctx, "address", create_native_pointer(ctx, symbol.address as u64));
    result.set_property(ctx, "offset", JSValue(ffi::JS_NewBigUint64(ctx, symbol.offset as u64)));
    result.raw()
}

unsafe fn image_import_to_js(ctx: *mut ffi::JSContext, import: &native_api::ImageImport) -> ffi::JSValue {
    let result = JSValue(ffi::JS_NewObject(ctx));
    result.set_property(ctx, "moduleName", JSValue::string(ctx, &import.module_name));
    result.set_property(ctx, "moduleBase", create_native_pointer(ctx, import.module_base as u64));
    result.set_property(ctx, "name", JSValue::string(ctx, &import.symbol_name));
    result.set_property(ctx, "dylibOrdinal", JSValue::int(import.dylib_ordinal as i32));
    match &import.dylib_name {
        Some(name) => result.set_property(ctx, "dylibName", JSValue::string(ctx, name)),
        None => result.set_property(ctx, "dylibName", JSValue::null()),
    };
    result.set_property(ctx, "weakImport", JSValue::bool(import.weak_import));
    result.raw()
}

unsafe fn image_dependency_to_js(ctx: *mut ffi::JSContext, dependency: &native_api::ImageDependency) -> ffi::JSValue {
    let result = JSValue(ffi::JS_NewObject(ctx));
    result.set_property(ctx, "moduleName", JSValue::string(ctx, &dependency.module_name));
    result.set_property(
        ctx,
        "moduleBase",
        create_native_pointer(ctx, dependency.module_base as u64),
    );
    result.set_property(ctx, "ordinal", JSValue::int(dependency.ordinal as i32));
    result.set_property(ctx, "path", JSValue::string(ctx, &dependency.path));
    result.set_property(ctx, "kind", JSValue::string(ctx, &dependency.kind));
    result.set_property(
        ctx,
        "currentVersion",
        JSValue(ffi::qjs_new_uint32(ctx, dependency.current_version)),
    );
    result.set_property(
        ctx,
        "compatibilityVersion",
        JSValue(ffi::qjs_new_uint32(ctx, dependency.compatibility_version)),
    );
    result.set_property(
        ctx,
        "timestamp",
        JSValue(ffi::qjs_new_uint32(ctx, dependency.timestamp)),
    );
    result.raw()
}

unsafe fn image_rpath_to_js(ctx: *mut ffi::JSContext, rpath: &native_api::ImageRpath) -> ffi::JSValue {
    let result = JSValue(ffi::JS_NewObject(ctx));
    result.set_property(ctx, "moduleName", JSValue::string(ctx, &rpath.module_name));
    result.set_property(ctx, "moduleBase", create_native_pointer(ctx, rpath.module_base as u64));
    result.set_property(ctx, "path", JSValue::string(ctx, &rpath.path));
    result.raw()
}

unsafe fn image_segment_to_js(ctx: *mut ffi::JSContext, segment: &native_api::ImageSegment) -> ffi::JSValue {
    let result = JSValue(ffi::JS_NewObject(ctx));
    result.set_property(ctx, "moduleName", JSValue::string(ctx, &segment.module_name));
    result.set_property(
        ctx,
        "moduleBase",
        create_native_pointer(ctx, segment.module_base as u64),
    );
    result.set_property(ctx, "name", JSValue::string(ctx, &segment.segment_name));
    result.set_property(ctx, "vmaddr", create_native_pointer(ctx, segment.vmaddr as u64));
    result.set_property(ctx, "vmsize", JSValue(ffi::JS_NewBigUint64(ctx, segment.vmsize as u64)));
    result.set_property(
        ctx,
        "fileoff",
        JSValue(ffi::JS_NewBigUint64(ctx, segment.fileoff as u64)),
    );
    result.set_property(
        ctx,
        "filesize",
        JSValue(ffi::JS_NewBigUint64(ctx, segment.filesize as u64)),
    );
    result.set_property(ctx, "maxprot", JSValue::int(segment.maxprot));
    result.set_property(ctx, "initprot", JSValue::int(segment.initprot));
    result.raw()
}

unsafe fn image_section_to_js(ctx: *mut ffi::JSContext, section: &native_api::ImageSection) -> ffi::JSValue {
    let result = JSValue(ffi::JS_NewObject(ctx));
    result.set_property(ctx, "moduleName", JSValue::string(ctx, &section.module_name));
    result.set_property(
        ctx,
        "moduleBase",
        create_native_pointer(ctx, section.module_base as u64),
    );
    result.set_property(ctx, "segmentName", JSValue::string(ctx, &section.segment_name));
    result.set_property(ctx, "name", JSValue::string(ctx, &section.section_name));
    result.set_property(ctx, "addr", create_native_pointer(ctx, section.addr as u64));
    result.set_property(ctx, "size", JSValue(ffi::JS_NewBigUint64(ctx, section.size as u64)));
    result.set_property(ctx, "offset", JSValue::int(section.offset as i32));
    result.set_property(ctx, "align", JSValue::int(section.align as i32));
    result.set_property(ctx, "flags", JSValue::int(section.flags as i32));
    result.raw()
}

unsafe fn image_load_command_to_js(ctx: *mut ffi::JSContext, command: &native_api::ImageLoadCommand) -> ffi::JSValue {
    let result = JSValue(ffi::JS_NewObject(ctx));
    result.set_property(ctx, "moduleName", JSValue::string(ctx, &command.module_name));
    result.set_property(
        ctx,
        "moduleBase",
        create_native_pointer(ctx, command.module_base as u64),
    );
    result.set_property(ctx, "index", JSValue(ffi::qjs_new_uint32(ctx, command.index as u32)));
    result.set_property(ctx, "cmd", JSValue(ffi::qjs_new_uint32(ctx, command.command)));
    result.set_property(ctx, "cmdsize", JSValue(ffi::qjs_new_uint32(ctx, command.command_size)));
    result.set_property(
        ctx,
        "offset",
        JSValue(ffi::JS_NewBigUint64(ctx, command.command_offset as u64)),
    );
    result.set_property(ctx, "name", JSValue::string(ctx, &command.command_name));
    match &command.detail {
        Some(detail) => result.set_property(ctx, "detail", JSValue::string(ctx, detail)),
        None => result.set_property(ctx, "detail", JSValue::null()),
    };
    result.raw()
}

unsafe extern "C" fn js_native_detect_hook_environment(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    match detect_hook_environment() {
        Ok(report) => report_to_js(ctx, &report),
        Err(err) => js_throw_internal_error(ctx, &err.to_string()),
    }
}

unsafe extern "C" fn js_native_find_symbols(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 1 {
        return crate::util::js_throw_type_error(
            ctx,
            "Native.findSymbols(query[, moduleName]) requires at least 1 string argument",
        );
    }

    let query = match JSValue(*argv).to_string(ctx) {
        Some(value) if !value.trim().is_empty() => value,
        _ => {
            return crate::util::js_throw_type_error(
                ctx,
                "Native.findSymbols(query[, moduleName]) requires query to be a non-empty string",
            )
        }
    };

    let module_name = if argc >= 2 {
        let value = JSValue(*argv.add(1));
        if value.is_null() || value.is_undefined() {
            None
        } else {
            match value.to_string(ctx) {
                Some(module_name) => Some(module_name),
                None => {
                    return crate::util::js_throw_type_error(
                        ctx,
                        "Native.findSymbols(query[, moduleName]) expected moduleName to be a string when provided",
                    )
                }
            }
        }
    } else {
        None
    };

    let symbols = match find_native_symbols(module_name.as_deref(), &query) {
        Ok(symbols) => symbols,
        Err(common::Error::Unsupported(_)) => return ffi::JS_NewArray(ctx),
        Err(common::Error::InvalidArgument(message)) => return crate::util::js_throw_type_error(ctx, &message),
        Err(err) => return js_throw_internal_error(ctx, &err.to_string()),
    };

    let array = ffi::JS_NewArray(ctx);
    for (index, symbol) in symbols.iter().enumerate() {
        ffi::JS_SetPropertyUint32(ctx, array, index as u32, native_symbol_to_js(ctx, symbol));
    }
    array
}

unsafe extern "C" fn js_native_find_exports(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 1 {
        return crate::util::js_throw_type_error(
            ctx,
            "Native.findExports(moduleName[, query]) requires at least 1 string argument",
        );
    }

    let module_name = match JSValue(*argv).to_string(ctx) {
        Some(value) if !value.trim().is_empty() => value,
        _ => {
            return crate::util::js_throw_type_error(
                ctx,
                "Native.findExports(moduleName[, query]) requires moduleName to be a non-empty string",
            )
        }
    };

    let query = if argc >= 2 {
        let value = JSValue(*argv.add(1));
        if value.is_null() || value.is_undefined() {
            None
        } else {
            match value.to_string(ctx) {
                Some(query) if !query.trim().is_empty() => Some(query),
                Some(_) => None,
                None => {
                    return crate::util::js_throw_type_error(
                        ctx,
                        "Native.findExports(moduleName[, query]) expected query to be a string when provided",
                    )
                }
            }
        }
    } else {
        None
    };

    let symbols = match find_image_exports(&module_name, query.as_deref()) {
        Ok(symbols) => symbols,
        Err(common::Error::Unsupported(_)) => return ffi::JS_NewArray(ctx),
        Err(common::Error::InvalidArgument(message)) => return crate::util::js_throw_type_error(ctx, &message),
        Err(err) => return js_throw_internal_error(ctx, &err.to_string()),
    };

    let array = ffi::JS_NewArray(ctx);
    for (index, symbol) in symbols.iter().enumerate() {
        ffi::JS_SetPropertyUint32(ctx, array, index as u32, native_symbol_to_js(ctx, symbol));
    }
    array
}

unsafe extern "C" fn js_native_find_imports(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 1 {
        return crate::util::js_throw_type_error(
            ctx,
            "Native.findImports(moduleName[, query]) requires at least 1 string argument",
        );
    }

    let module_name = match JSValue(*argv).to_string(ctx) {
        Some(value) if !value.trim().is_empty() => value,
        _ => {
            return crate::util::js_throw_type_error(
                ctx,
                "Native.findImports(moduleName[, query]) requires moduleName to be a non-empty string",
            )
        }
    };

    let query = if argc >= 2 {
        let value = JSValue(*argv.add(1));
        if value.is_null() || value.is_undefined() {
            None
        } else {
            match value.to_string(ctx) {
                Some(query) if !query.trim().is_empty() => Some(query),
                Some(_) => None,
                None => {
                    return crate::util::js_throw_type_error(
                        ctx,
                        "Native.findImports(moduleName[, query]) expected query to be a string when provided",
                    )
                }
            }
        }
    } else {
        None
    };

    let imports = match find_image_imports(&module_name, query.as_deref()) {
        Ok(imports) => imports,
        Err(common::Error::Unsupported(_)) => return ffi::JS_NewArray(ctx),
        Err(common::Error::InvalidArgument(message)) => return crate::util::js_throw_type_error(ctx, &message),
        Err(err) => return js_throw_internal_error(ctx, &err.to_string()),
    };

    let array = ffi::JS_NewArray(ctx);
    for (index, import) in imports.iter().enumerate() {
        ffi::JS_SetPropertyUint32(ctx, array, index as u32, image_import_to_js(ctx, import));
    }
    array
}

unsafe extern "C" fn js_native_find_dependencies(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 1 {
        return crate::util::js_throw_type_error(
            ctx,
            "Native.findDependencies(moduleName[, query]) requires at least 1 string argument",
        );
    }

    let module_name = match JSValue(*argv).to_string(ctx) {
        Some(value) if !value.trim().is_empty() => value,
        _ => {
            return crate::util::js_throw_type_error(
                ctx,
                "Native.findDependencies(moduleName[, query]) requires moduleName to be a non-empty string",
            )
        }
    };

    let query = if argc >= 2 {
        let value = JSValue(*argv.add(1));
        if value.is_null() || value.is_undefined() {
            None
        } else {
            match value.to_string(ctx) {
                Some(query) if !query.trim().is_empty() => Some(query),
                Some(_) => None,
                None => {
                    return crate::util::js_throw_type_error(
                        ctx,
                        "Native.findDependencies(moduleName[, query]) expected query to be a string when provided",
                    )
                }
            }
        }
    } else {
        None
    };

    let dependencies = match find_image_dependencies(&module_name, query.as_deref()) {
        Ok(dependencies) => dependencies,
        Err(common::Error::Unsupported(_)) => return ffi::JS_NewArray(ctx),
        Err(common::Error::InvalidArgument(message)) => return crate::util::js_throw_type_error(ctx, &message),
        Err(err) => return js_throw_internal_error(ctx, &err.to_string()),
    };

    let array = ffi::JS_NewArray(ctx);
    for (index, dependency) in dependencies.iter().enumerate() {
        ffi::JS_SetPropertyUint32(ctx, array, index as u32, image_dependency_to_js(ctx, dependency));
    }
    array
}

unsafe extern "C" fn js_native_find_rpaths(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 1 {
        return crate::util::js_throw_type_error(
            ctx,
            "Native.findRpaths(moduleName[, query]) requires at least 1 string argument",
        );
    }

    let module_name = match JSValue(*argv).to_string(ctx) {
        Some(value) if !value.trim().is_empty() => value,
        _ => {
            return crate::util::js_throw_type_error(
                ctx,
                "Native.findRpaths(moduleName[, query]) requires moduleName to be a non-empty string",
            )
        }
    };

    let query = if argc >= 2 {
        let value = JSValue(*argv.add(1));
        if value.is_null() || value.is_undefined() {
            None
        } else {
            match value.to_string(ctx) {
                Some(query) if !query.trim().is_empty() => Some(query),
                Some(_) => None,
                None => {
                    return crate::util::js_throw_type_error(
                        ctx,
                        "Native.findRpaths(moduleName[, query]) expected query to be a string when provided",
                    )
                }
            }
        }
    } else {
        None
    };

    let rpaths = match find_image_rpaths(&module_name, query.as_deref()) {
        Ok(rpaths) => rpaths,
        Err(common::Error::Unsupported(_)) => return ffi::JS_NewArray(ctx),
        Err(common::Error::InvalidArgument(message)) => return crate::util::js_throw_type_error(ctx, &message),
        Err(err) => return js_throw_internal_error(ctx, &err.to_string()),
    };

    let array = ffi::JS_NewArray(ctx);
    for (index, rpath) in rpaths.iter().enumerate() {
        ffi::JS_SetPropertyUint32(ctx, array, index as u32, image_rpath_to_js(ctx, rpath));
    }
    array
}

unsafe extern "C" fn js_native_find_segments(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 1 {
        return crate::util::js_throw_type_error(ctx, "Native.findSegments(moduleName) requires 1 string argument");
    }

    let module_name = match JSValue(*argv).to_string(ctx) {
        Some(value) if !value.trim().is_empty() => value,
        _ => {
            return crate::util::js_throw_type_error(
                ctx,
                "Native.findSegments(moduleName) requires moduleName to be a non-empty string",
            )
        }
    };

    let segments = match find_image_segments(&module_name) {
        Ok(segments) => segments,
        Err(common::Error::Unsupported(_)) => return ffi::JS_NewArray(ctx),
        Err(common::Error::InvalidArgument(message)) => return crate::util::js_throw_type_error(ctx, &message),
        Err(err) => return js_throw_internal_error(ctx, &err.to_string()),
    };

    let array = ffi::JS_NewArray(ctx);
    for (index, segment) in segments.iter().enumerate() {
        ffi::JS_SetPropertyUint32(ctx, array, index as u32, image_segment_to_js(ctx, segment));
    }
    array
}

unsafe extern "C" fn js_native_find_sections(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 1 {
        return crate::util::js_throw_type_error(ctx, "Native.findSections(moduleName) requires 1 string argument");
    }

    let module_name = match JSValue(*argv).to_string(ctx) {
        Some(value) if !value.trim().is_empty() => value,
        _ => {
            return crate::util::js_throw_type_error(
                ctx,
                "Native.findSections(moduleName) requires moduleName to be a non-empty string",
            )
        }
    };

    let sections = match find_image_sections(&module_name) {
        Ok(sections) => sections,
        Err(common::Error::Unsupported(_)) => return ffi::JS_NewArray(ctx),
        Err(common::Error::InvalidArgument(message)) => return crate::util::js_throw_type_error(ctx, &message),
        Err(err) => return js_throw_internal_error(ctx, &err.to_string()),
    };

    let array = ffi::JS_NewArray(ctx);
    for (index, section) in sections.iter().enumerate() {
        ffi::JS_SetPropertyUint32(ctx, array, index as u32, image_section_to_js(ctx, section));
    }
    array
}

unsafe extern "C" fn js_native_find_load_commands(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 1 {
        return crate::util::js_throw_type_error(ctx, "Native.findLoadCommands(moduleName) requires 1 string argument");
    }

    let module_name = match JSValue(*argv).to_string(ctx) {
        Some(value) if !value.trim().is_empty() => value,
        _ => {
            return crate::util::js_throw_type_error(
                ctx,
                "Native.findLoadCommands(moduleName) requires moduleName to be a non-empty string",
            )
        }
    };

    let commands = match find_image_load_commands(&module_name) {
        Ok(commands) => commands,
        Err(common::Error::Unsupported(_)) => return ffi::JS_NewArray(ctx),
        Err(common::Error::InvalidArgument(message)) => return crate::util::js_throw_type_error(ctx, &message),
        Err(err) => return js_throw_internal_error(ctx, &err.to_string()),
    };

    let array = ffi::JS_NewArray(ctx);
    for (index, command) in commands.iter().enumerate() {
        ffi::JS_SetPropertyUint32(ctx, array, index as u32, image_load_command_to_js(ctx, command));
    }
    array
}

pub(crate) fn register_native_api(ctx: &JSContext) {
    let global = ctx.global_object();
    let native = ctx.new_object();
    native.set_property(ctx.as_ptr(), "platform", JSValue::string(ctx.as_ptr(), "ios"));
    native.set_property(ctx.as_ptr(), "backend", JSValue::string(ctx.as_ptr(), "mach"));
    native.set_property(
        ctx.as_ptr(),
        "symbolSupportAvailable",
        JSValue::bool(native_symbol_support_available()),
    );
    native.set_property(
        ctx.as_ptr(),
        "exportSupportAvailable",
        JSValue::bool(native_export_support_available()),
    );
    native.set_property(
        ctx.as_ptr(),
        "dependencySupportAvailable",
        JSValue::bool(image_dependency_support_available()),
    );
    native.set_property(
        ctx.as_ptr(),
        "rpathSupportAvailable",
        JSValue::bool(image_rpath_support_available()),
    );
    native.set_property(
        ctx.as_ptr(),
        "importSupportAvailable",
        JSValue::bool(image_import_support_available()),
    );
    native.set_property(
        ctx.as_ptr(),
        "segmentSupportAvailable",
        JSValue::bool(image_segment_support_available()),
    );
    native.set_property(
        ctx.as_ptr(),
        "sectionSupportAvailable",
        JSValue::bool(image_section_support_available()),
    );
    native.set_property(
        ctx.as_ptr(),
        "loadCommandSupportAvailable",
        JSValue::bool(image_load_command_support_available()),
    );

    unsafe {
        add_cfunction_to_object(
            ctx.as_ptr(),
            native.raw(),
            "detectHookEnvironment",
            js_native_detect_hook_environment,
            0,
        );
        add_cfunction_to_object(ctx.as_ptr(), native.raw(), "findSymbols", js_native_find_symbols, 2);
        add_cfunction_to_object(ctx.as_ptr(), native.raw(), "findExports", js_native_find_exports, 2);
        add_cfunction_to_object(
            ctx.as_ptr(),
            native.raw(),
            "findDependencies",
            js_native_find_dependencies,
            2,
        );
        add_cfunction_to_object(ctx.as_ptr(), native.raw(), "findRpaths", js_native_find_rpaths, 2);
        add_cfunction_to_object(ctx.as_ptr(), native.raw(), "findImports", js_native_find_imports, 2);
        add_cfunction_to_object(ctx.as_ptr(), native.raw(), "findSegments", js_native_find_segments, 1);
        add_cfunction_to_object(ctx.as_ptr(), native.raw(), "findSections", js_native_find_sections, 1);
        add_cfunction_to_object(
            ctx.as_ptr(),
            native.raw(),
            "findLoadCommands",
            js_native_find_load_commands,
            1,
        );
    }

    global.set_property(ctx.as_ptr(), "Native", native);
    global.free(ctx.as_ptr());
}
