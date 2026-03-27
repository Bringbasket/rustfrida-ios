use crate::context::JSContext;
use crate::ffi;
use crate::ptr::create_native_pointer;
use crate::util::{add_cfunction_to_object, js_throw_internal_error};
use crate::value::JSValue;
use native_api::{
    detect_hook_environment, find_image_build_version, find_image_chained_fixups, find_image_code_signature,
    find_image_dependencies, find_image_data_in_code, find_image_dyld_info, find_image_dylinker,
    find_image_encryption_info,
    find_image_entry_point, find_image_exports, find_image_exports_trie, find_image_function_starts,
    find_image_imports,
    find_image_install_name, find_image_linkedit_info, find_image_load_commands, find_image_rpaths,
    find_image_sections, find_image_segments, find_image_source_version, find_image_uuid, find_native_symbols,
    hook_environment_recommendations, image_build_version_support_available, image_chained_fixups_support_available,
    image_code_signature_support_available, image_dependency_support_available, image_data_in_code_support_available,
    image_exports_trie_support_available,
    image_dyld_info_support_available, image_dylinker_support_available,
    image_encryption_info_support_available, image_entry_point_support_available,
    image_function_starts_support_available, image_import_support_available,
    image_install_name_support_available, image_linkedit_info_support_available,
    image_load_command_support_available, image_rpath_support_available,
    image_section_support_available, image_segment_support_available,
    image_source_version_support_available, image_uuid_support_available,
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

unsafe fn image_encryption_info_to_js(
    ctx: *mut ffi::JSContext,
    encryption_info: &native_api::ImageEncryptionInfo,
) -> ffi::JSValue {
    let result = JSValue(ffi::JS_NewObject(ctx));
    result.set_property(ctx, "moduleName", JSValue::string(ctx, &encryption_info.module_name));
    result.set_property(
        ctx,
        "moduleBase",
        create_native_pointer(ctx, encryption_info.module_base as u64),
    );
    result.set_property(
        ctx,
        "cryptoff",
        JSValue(ffi::qjs_new_uint32(ctx, encryption_info.cryptoff)),
    );
    result.set_property(
        ctx,
        "cryptsize",
        JSValue(ffi::qjs_new_uint32(ctx, encryption_info.cryptsize)),
    );
    result.set_property(
        ctx,
        "cryptid",
        JSValue(ffi::qjs_new_uint32(ctx, encryption_info.cryptid)),
    );
    result.raw()
}

unsafe fn image_entry_point_to_js(ctx: *mut ffi::JSContext, entry_point: &native_api::ImageEntryPoint) -> ffi::JSValue {
    let result = JSValue(ffi::JS_NewObject(ctx));
    result.set_property(ctx, "moduleName", JSValue::string(ctx, &entry_point.module_name));
    result.set_property(
        ctx,
        "moduleBase",
        create_native_pointer(ctx, entry_point.module_base as u64),
    );
    result.set_property(
        ctx,
        "entryoff",
        JSValue(ffi::JS_NewBigUint64(ctx, entry_point.entryoff)),
    );
    result.set_property(
        ctx,
        "stacksize",
        JSValue(ffi::JS_NewBigUint64(ctx, entry_point.stacksize)),
    );
    result.raw()
}

unsafe fn image_dyld_info_to_js(ctx: *mut ffi::JSContext, dyld_info: &native_api::ImageDyldInfo) -> ffi::JSValue {
    let result = JSValue(ffi::JS_NewObject(ctx));
    result.set_property(ctx, "moduleName", JSValue::string(ctx, &dyld_info.module_name));
    result.set_property(
        ctx,
        "moduleBase",
        create_native_pointer(ctx, dyld_info.module_base as u64),
    );
    result.set_property(ctx, "command", JSValue(ffi::qjs_new_uint32(ctx, dyld_info.command)));
    result.set_property(ctx, "commandName", JSValue::string(ctx, &dyld_info.command_name));
    result.set_property(ctx, "rebaseOff", JSValue(ffi::qjs_new_uint32(ctx, dyld_info.rebase_off)));
    result.set_property(ctx, "rebaseSize", JSValue(ffi::qjs_new_uint32(ctx, dyld_info.rebase_size)));
    result.set_property(ctx, "bindOff", JSValue(ffi::qjs_new_uint32(ctx, dyld_info.bind_off)));
    result.set_property(ctx, "bindSize", JSValue(ffi::qjs_new_uint32(ctx, dyld_info.bind_size)));
    result.set_property(
        ctx,
        "weakBindOff",
        JSValue(ffi::qjs_new_uint32(ctx, dyld_info.weak_bind_off)),
    );
    result.set_property(
        ctx,
        "weakBindSize",
        JSValue(ffi::qjs_new_uint32(ctx, dyld_info.weak_bind_size)),
    );
    result.set_property(
        ctx,
        "lazyBindOff",
        JSValue(ffi::qjs_new_uint32(ctx, dyld_info.lazy_bind_off)),
    );
    result.set_property(
        ctx,
        "lazyBindSize",
        JSValue(ffi::qjs_new_uint32(ctx, dyld_info.lazy_bind_size)),
    );
    result.set_property(ctx, "exportOff", JSValue(ffi::qjs_new_uint32(ctx, dyld_info.export_off)));
    result.set_property(ctx, "exportSize", JSValue(ffi::qjs_new_uint32(ctx, dyld_info.export_size)));
    result.raw()
}

unsafe fn image_source_version_to_js(
    ctx: *mut ffi::JSContext,
    source_version: &native_api::ImageSourceVersion,
) -> ffi::JSValue {
    let result = JSValue(ffi::JS_NewObject(ctx));
    result.set_property(ctx, "moduleName", JSValue::string(ctx, &source_version.module_name));
    result.set_property(
        ctx,
        "moduleBase",
        create_native_pointer(ctx, source_version.module_base as u64),
    );
    result.set_property(ctx, "version", JSValue::string(ctx, &source_version.version));
    result.raw()
}

unsafe fn image_build_version_to_js(
    ctx: *mut ffi::JSContext,
    build_version: &native_api::ImageBuildVersion,
) -> ffi::JSValue {
    let result = JSValue(ffi::JS_NewObject(ctx));
    result.set_property(ctx, "moduleName", JSValue::string(ctx, &build_version.module_name));
    result.set_property(
        ctx,
        "moduleBase",
        create_native_pointer(ctx, build_version.module_base as u64),
    );
    result.set_property(ctx, "platform", JSValue::string(ctx, &build_version.platform));
    result.set_property(ctx, "minOs", JSValue::string(ctx, &build_version.min_os));
    result.set_property(ctx, "sdk", JSValue::string(ctx, &build_version.sdk));

    let tools = ffi::JS_NewArray(ctx);
    for (index, tool) in build_version.tools.iter().enumerate() {
        let item = JSValue(ffi::JS_NewObject(ctx));
        item.set_property(ctx, "tool", JSValue::string(ctx, &tool.tool));
        item.set_property(ctx, "version", JSValue::string(ctx, &tool.version));
        ffi::JS_SetPropertyUint32(ctx, tools, index as u32, item.raw());
    }
    result.set_property(ctx, "tools", JSValue(tools));
    result.raw()
}

unsafe fn image_dylinker_to_js(ctx: *mut ffi::JSContext, dylinker: &native_api::ImageDylinker) -> ffi::JSValue {
    let result = JSValue(ffi::JS_NewObject(ctx));
    result.set_property(ctx, "moduleName", JSValue::string(ctx, &dylinker.module_name));
    result.set_property(
        ctx,
        "moduleBase",
        create_native_pointer(ctx, dylinker.module_base as u64),
    );
    result.set_property(ctx, "path", JSValue::string(ctx, &dylinker.path));
    result.set_property(ctx, "kind", JSValue::string(ctx, &dylinker.kind));
    result.raw()
}

unsafe fn image_install_name_to_js(
    ctx: *mut ffi::JSContext,
    install_name: &native_api::ImageInstallName,
) -> ffi::JSValue {
    let result = JSValue(ffi::JS_NewObject(ctx));
    result.set_property(ctx, "moduleName", JSValue::string(ctx, &install_name.module_name));
    result.set_property(
        ctx,
        "moduleBase",
        create_native_pointer(ctx, install_name.module_base as u64),
    );
    result.set_property(ctx, "path", JSValue::string(ctx, &install_name.path));
    result.set_property(
        ctx,
        "currentVersion",
        JSValue(ffi::qjs_new_uint32(ctx, install_name.current_version)),
    );
    result.set_property(
        ctx,
        "compatibilityVersion",
        JSValue(ffi::qjs_new_uint32(ctx, install_name.compatibility_version)),
    );
    result.set_property(
        ctx,
        "timestamp",
        JSValue(ffi::qjs_new_uint32(ctx, install_name.timestamp)),
    );
    result.raw()
}

unsafe fn image_linkedit_info_to_js(
    ctx: *mut ffi::JSContext,
    linkedit: &native_api::ImageLinkeditInfo,
) -> ffi::JSValue {
    let result = JSValue(ffi::JS_NewObject(ctx));
    result.set_property(ctx, "moduleName", JSValue::string(ctx, &linkedit.module_name));
    result.set_property(
        ctx,
        "moduleBase",
        create_native_pointer(ctx, linkedit.module_base as u64),
    );
    result.set_property(ctx, "vmaddr", create_native_pointer(ctx, linkedit.vmaddr));
    result.set_property(ctx, "vmsize", JSValue(ffi::JS_NewBigUint64(ctx, linkedit.vmsize)));
    result.set_property(ctx, "fileoff", JSValue(ffi::JS_NewBigUint64(ctx, linkedit.fileoff)));
    result.set_property(ctx, "filesize", JSValue(ffi::JS_NewBigUint64(ctx, linkedit.filesize)));
    result.set_property(
        ctx,
        "computedBase",
        create_native_pointer(ctx, linkedit.computed_base as u64),
    );
    match linkedit.symoff {
        Some(value) => result.set_property(ctx, "symoff", JSValue(ffi::qjs_new_uint32(ctx, value))),
        None => result.set_property(ctx, "symoff", JSValue::null()),
    };
    match linkedit.nsyms {
        Some(value) => result.set_property(ctx, "nsyms", JSValue(ffi::qjs_new_uint32(ctx, value))),
        None => result.set_property(ctx, "nsyms", JSValue::null()),
    };
    match linkedit.stroff {
        Some(value) => result.set_property(ctx, "stroff", JSValue(ffi::qjs_new_uint32(ctx, value))),
        None => result.set_property(ctx, "stroff", JSValue::null()),
    };
    match linkedit.strsize {
        Some(value) => result.set_property(ctx, "strsize", JSValue(ffi::qjs_new_uint32(ctx, value))),
        None => result.set_property(ctx, "strsize", JSValue::null()),
    };
    match linkedit.indirectsymoff {
        Some(value) => result.set_property(ctx, "indirectsymoff", JSValue(ffi::qjs_new_uint32(ctx, value))),
        None => result.set_property(ctx, "indirectsymoff", JSValue::null()),
    };
    match linkedit.nindirectsyms {
        Some(value) => result.set_property(ctx, "nindirectsyms", JSValue(ffi::qjs_new_uint32(ctx, value))),
        None => result.set_property(ctx, "nindirectsyms", JSValue::null()),
    };
    result.raw()
}

unsafe fn image_function_start_to_js(
    ctx: *mut ffi::JSContext,
    function_start: &native_api::ImageFunctionStart,
) -> ffi::JSValue {
    let result = JSValue(ffi::JS_NewObject(ctx));
    result.set_property(ctx, "offset", JSValue(ffi::JS_NewBigUint64(ctx, function_start.offset)));
    result.set_property(
        ctx,
        "address",
        create_native_pointer(ctx, function_start.address as u64),
    );
    result.raw()
}

unsafe fn image_function_starts_to_js(
    ctx: *mut ffi::JSContext,
    function_starts: &native_api::ImageFunctionStarts,
) -> ffi::JSValue {
    let result = JSValue(ffi::JS_NewObject(ctx));
    result.set_property(
        ctx,
        "moduleName",
        JSValue::string(ctx, &function_starts.module_name),
    );
    result.set_property(
        ctx,
        "moduleBase",
        create_native_pointer(ctx, function_starts.module_base as u64),
    );
    result.set_property(
        ctx,
        "dataoff",
        JSValue(ffi::qjs_new_uint32(ctx, function_starts.dataoff)),
    );
    result.set_property(
        ctx,
        "datasize",
        JSValue(ffi::qjs_new_uint32(ctx, function_starts.datasize)),
    );
    result.set_property(
        ctx,
        "linkeditBase",
        create_native_pointer(ctx, function_starts.linkedit_base as u64),
    );
    result.set_property(
        ctx,
        "dataAddress",
        create_native_pointer(ctx, function_starts.data_address as u64),
    );
    let starts = ffi::JS_NewArray(ctx);
    for (index, item) in function_starts.starts.iter().enumerate() {
        ffi::JS_SetPropertyUint32(ctx, starts, index as u32, image_function_start_to_js(ctx, item));
    }
    result.set_property(ctx, "starts", JSValue(starts));
    result.raw()
}

unsafe fn image_code_signature_to_js(
    ctx: *mut ffi::JSContext,
    code_signature: &native_api::ImageCodeSignature,
) -> ffi::JSValue {
    let result = JSValue(ffi::JS_NewObject(ctx));
    result.set_property(
        ctx,
        "moduleName",
        JSValue::string(ctx, &code_signature.module_name),
    );
    result.set_property(
        ctx,
        "moduleBase",
        create_native_pointer(ctx, code_signature.module_base as u64),
    );
    result.set_property(
        ctx,
        "dataoff",
        JSValue(ffi::qjs_new_uint32(ctx, code_signature.dataoff)),
    );
    result.set_property(
        ctx,
        "datasize",
        JSValue(ffi::qjs_new_uint32(ctx, code_signature.datasize)),
    );
    result.set_property(
        ctx,
        "linkeditBase",
        create_native_pointer(ctx, code_signature.linkedit_base as u64),
    );
    result.set_property(
        ctx,
        "dataAddress",
        create_native_pointer(ctx, code_signature.data_address as u64),
    );
    match code_signature.magic {
        Some(value) => result.set_property(ctx, "magic", JSValue(ffi::qjs_new_uint32(ctx, value))),
        None => result.set_property(ctx, "magic", JSValue::null()),
    };
    match &code_signature.magic_name {
        Some(value) => result.set_property(ctx, "magicName", JSValue::string(ctx, value)),
        None => result.set_property(ctx, "magicName", JSValue::null()),
    };
    match code_signature.length {
        Some(value) => result.set_property(ctx, "length", JSValue(ffi::qjs_new_uint32(ctx, value))),
        None => result.set_property(ctx, "length", JSValue::null()),
    };
    match code_signature.count {
        Some(value) => result.set_property(ctx, "count", JSValue(ffi::qjs_new_uint32(ctx, value))),
        None => result.set_property(ctx, "count", JSValue::null()),
    };
    result.raw()
}

unsafe fn image_data_in_code_entry_to_js(
    ctx: *mut ffi::JSContext,
    entry: &native_api::ImageDataInCodeEntry,
) -> ffi::JSValue {
    let result = JSValue(ffi::JS_NewObject(ctx));
    result.set_property(ctx, "offset", JSValue(ffi::qjs_new_uint32(ctx, entry.offset)));
    result.set_property(ctx, "address", create_native_pointer(ctx, entry.address as u64));
    result.set_property(ctx, "length", JSValue::int(entry.length as i32));
    result.set_property(ctx, "kind", JSValue::int(entry.kind as i32));
    result.set_property(ctx, "kindName", JSValue::string(ctx, &entry.kind_name));
    result.raw()
}

unsafe fn image_data_in_code_to_js(
    ctx: *mut ffi::JSContext,
    data_in_code: &native_api::ImageDataInCode,
) -> ffi::JSValue {
    let result = JSValue(ffi::JS_NewObject(ctx));
    result.set_property(ctx, "moduleName", JSValue::string(ctx, &data_in_code.module_name));
    result.set_property(
        ctx,
        "moduleBase",
        create_native_pointer(ctx, data_in_code.module_base as u64),
    );
    result.set_property(ctx, "dataoff", JSValue(ffi::qjs_new_uint32(ctx, data_in_code.dataoff)));
    result.set_property(ctx, "datasize", JSValue(ffi::qjs_new_uint32(ctx, data_in_code.datasize)));
    result.set_property(
        ctx,
        "linkeditBase",
        create_native_pointer(ctx, data_in_code.linkedit_base as u64),
    );
    result.set_property(
        ctx,
        "dataAddress",
        create_native_pointer(ctx, data_in_code.data_address as u64),
    );
    let entries = ffi::JS_NewArray(ctx);
    for (index, item) in data_in_code.entries.iter().enumerate() {
        ffi::JS_SetPropertyUint32(ctx, entries, index as u32, image_data_in_code_entry_to_js(ctx, item));
    }
    result.set_property(ctx, "entries", JSValue(entries));
    result.raw()
}

unsafe fn image_exports_trie_entry_to_js(
    ctx: *mut ffi::JSContext,
    entry: &native_api::ImageExportsTrieEntry,
) -> ffi::JSValue {
    let result = JSValue(ffi::JS_NewObject(ctx));
    result.set_property(ctx, "name", JSValue::string(ctx, &entry.name));
    result.set_property(ctx, "flags", JSValue(ffi::JS_NewBigUint64(ctx, entry.flags)));
    result.set_property(ctx, "kind", JSValue::string(ctx, &entry.kind));
    match entry.address {
        Some(value) => result.set_property(ctx, "address", create_native_pointer(ctx, value as u64)),
        None => result.set_property(ctx, "address", JSValue::null()),
    };
    match entry.offset {
        Some(value) => result.set_property(ctx, "offset", JSValue(ffi::JS_NewBigUint64(ctx, value))),
        None => result.set_property(ctx, "offset", JSValue::null()),
    };
    match entry.other {
        Some(value) => result.set_property(ctx, "other", JSValue(ffi::JS_NewBigUint64(ctx, value))),
        None => result.set_property(ctx, "other", JSValue::null()),
    };
    match &entry.import_name {
        Some(value) => result.set_property(ctx, "importName", JSValue::string(ctx, value)),
        None => result.set_property(ctx, "importName", JSValue::null()),
    };
    result.set_property(
        ctx,
        "isWeakDefinition",
        JSValue::bool(entry.is_weak_definition),
    );
    result.set_property(ctx, "isReexport", JSValue::bool(entry.is_reexport));
    result.set_property(
        ctx,
        "isStubAndResolver",
        JSValue::bool(entry.is_stub_and_resolver),
    );
    result.raw()
}

unsafe fn image_exports_trie_to_js(
    ctx: *mut ffi::JSContext,
    exports_trie: &native_api::ImageExportsTrie,
) -> ffi::JSValue {
    let result = JSValue(ffi::JS_NewObject(ctx));
    result.set_property(
        ctx,
        "moduleName",
        JSValue::string(ctx, &exports_trie.module_name),
    );
    result.set_property(
        ctx,
        "moduleBase",
        create_native_pointer(ctx, exports_trie.module_base as u64),
    );
    result.set_property(
        ctx,
        "dataoff",
        JSValue(ffi::qjs_new_uint32(ctx, exports_trie.dataoff)),
    );
    result.set_property(
        ctx,
        "datasize",
        JSValue(ffi::qjs_new_uint32(ctx, exports_trie.datasize)),
    );
    result.set_property(
        ctx,
        "linkeditBase",
        create_native_pointer(ctx, exports_trie.linkedit_base as u64),
    );
    result.set_property(
        ctx,
        "dataAddress",
        create_native_pointer(ctx, exports_trie.data_address as u64),
    );
    let entries = ffi::JS_NewArray(ctx);
    for (index, item) in exports_trie.entries.iter().enumerate() {
        ffi::JS_SetPropertyUint32(ctx, entries, index as u32, image_exports_trie_entry_to_js(ctx, item));
    }
    result.set_property(ctx, "entries", JSValue(entries));
    result.raw()
}

unsafe fn image_chained_fixups_page_to_js(
    ctx: *mut ffi::JSContext,
    page: &native_api::ImageChainedFixupsPage,
) -> ffi::JSValue {
    let result = JSValue(ffi::JS_NewObject(ctx));
    result.set_property(ctx, "pageIndex", JSValue::int(page.page_index as i32));
    result.set_property(ctx, "hasFixups", JSValue::bool(page.has_fixups));
    match page.page_start {
        Some(value) => result.set_property(ctx, "pageStart", JSValue::int(value as i32)),
        None => result.set_property(ctx, "pageStart", JSValue::null()),
    };
    result.set_property(
        ctx,
        "usesMultipleStarts",
        JSValue::bool(page.uses_multiple_starts),
    );
    let chain_starts = ffi::JS_NewArray(ctx);
    for (index, item) in page.chain_starts.iter().enumerate() {
        ffi::JS_SetPropertyUint32(ctx, chain_starts, index as u32, JSValue::int(*item as i32).raw());
    }
    result.set_property(ctx, "chainStarts", JSValue(chain_starts));
    result.raw()
}

unsafe fn image_chained_fixups_segment_to_js(
    ctx: *mut ffi::JSContext,
    segment: &native_api::ImageChainedFixupsSegment,
) -> ffi::JSValue {
    let result = JSValue(ffi::JS_NewObject(ctx));
    result.set_property(ctx, "segmentIndex", JSValue::int(segment.segment_index as i32));
    result.set_property(
        ctx,
        "offsetInStarts",
        JSValue(ffi::qjs_new_uint32(ctx, segment.offset_in_starts)),
    );
    result.set_property(ctx, "size", JSValue(ffi::qjs_new_uint32(ctx, segment.size)));
    result.set_property(ctx, "pageSize", JSValue::int(segment.page_size as i32));
    result.set_property(ctx, "pointerFormat", JSValue::int(segment.pointer_format as i32));
    result.set_property(
        ctx,
        "pointerFormatName",
        JSValue::string(ctx, &segment.pointer_format_name),
    );
    result.set_property(
        ctx,
        "segmentOffset",
        JSValue(ffi::JS_NewBigUint64(ctx, segment.segment_offset)),
    );
    result.set_property(
        ctx,
        "maxValidPointer",
        JSValue(ffi::qjs_new_uint32(ctx, segment.max_valid_pointer)),
    );
    result.set_property(ctx, "pageCount", JSValue::int(segment.page_count as i32));
    result.set_property(
        ctx,
        "fixupPageCount",
        JSValue::int(segment.fixup_page_count as i32),
    );
    result.set_property(
        ctx,
        "multiPageCount",
        JSValue::int(segment.multi_page_count as i32),
    );
    let pages = ffi::JS_NewArray(ctx);
    for (index, item) in segment.pages.iter().enumerate() {
        ffi::JS_SetPropertyUint32(ctx, pages, index as u32, image_chained_fixups_page_to_js(ctx, item));
    }
    result.set_property(ctx, "pages", JSValue(pages));
    result.raw()
}

unsafe fn image_chained_fixups_import_to_js(
    ctx: *mut ffi::JSContext,
    import: &native_api::ImageChainedFixupsImport,
) -> ffi::JSValue {
    let result = JSValue(ffi::JS_NewObject(ctx));
    result.set_property(ctx, "index", JSValue::int(import.index as i32));
    result.set_property(
        ctx,
        "libOrdinalRaw",
        JSValue(ffi::JS_NewBigUint64(ctx, import.lib_ordinal_raw)),
    );
    result.set_property(ctx, "libOrdinal", JSValue::int(import.lib_ordinal as i32));
    result.set_property(ctx, "weakImport", JSValue::bool(import.weak_import));
    result.set_property(
        ctx,
        "nameOffset",
        JSValue(ffi::qjs_new_uint32(ctx, import.name_offset)),
    );
    match &import.name {
        Some(value) => result.set_property(ctx, "name", JSValue::string(ctx, value)),
        None => result.set_property(ctx, "name", JSValue::null()),
    };
    match import.addend {
        Some(value) => result.set_property(ctx, "addend", JSValue(ffi::JS_NewBigInt64(ctx, value))),
        None => result.set_property(ctx, "addend", JSValue::null()),
    };
    result.raw()
}

unsafe fn image_chained_fixups_to_js(
    ctx: *mut ffi::JSContext,
    chained_fixups: &native_api::ImageChainedFixups,
) -> ffi::JSValue {
    let result = JSValue(ffi::JS_NewObject(ctx));
    result.set_property(
        ctx,
        "moduleName",
        JSValue::string(ctx, &chained_fixups.module_name),
    );
    result.set_property(
        ctx,
        "moduleBase",
        create_native_pointer(ctx, chained_fixups.module_base as u64),
    );
    result.set_property(
        ctx,
        "dataoff",
        JSValue(ffi::qjs_new_uint32(ctx, chained_fixups.dataoff)),
    );
    result.set_property(
        ctx,
        "datasize",
        JSValue(ffi::qjs_new_uint32(ctx, chained_fixups.datasize)),
    );
    result.set_property(
        ctx,
        "linkeditBase",
        create_native_pointer(ctx, chained_fixups.linkedit_base as u64),
    );
    result.set_property(
        ctx,
        "dataAddress",
        create_native_pointer(ctx, chained_fixups.data_address as u64),
    );
    result.set_property(
        ctx,
        "fixupsVersion",
        JSValue(ffi::qjs_new_uint32(ctx, chained_fixups.fixups_version)),
    );
    result.set_property(
        ctx,
        "startsOffset",
        JSValue(ffi::qjs_new_uint32(ctx, chained_fixups.starts_offset)),
    );
    result.set_property(
        ctx,
        "importsOffset",
        JSValue(ffi::qjs_new_uint32(ctx, chained_fixups.imports_offset)),
    );
    result.set_property(
        ctx,
        "symbolsOffset",
        JSValue(ffi::qjs_new_uint32(ctx, chained_fixups.symbols_offset)),
    );
    result.set_property(
        ctx,
        "importsCount",
        JSValue(ffi::qjs_new_uint32(ctx, chained_fixups.imports_count)),
    );
    result.set_property(
        ctx,
        "importsFormat",
        JSValue(ffi::qjs_new_uint32(ctx, chained_fixups.imports_format)),
    );
    result.set_property(
        ctx,
        "importsFormatName",
        JSValue::string(ctx, &chained_fixups.imports_format_name),
    );
    result.set_property(
        ctx,
        "symbolsFormat",
        JSValue(ffi::qjs_new_uint32(ctx, chained_fixups.symbols_format)),
    );
    result.set_property(
        ctx,
        "symbolsFormatName",
        JSValue::string(ctx, &chained_fixups.symbols_format_name),
    );
    let segments = ffi::JS_NewArray(ctx);
    for (index, item) in chained_fixups.segments.iter().enumerate() {
        ffi::JS_SetPropertyUint32(ctx, segments, index as u32, image_chained_fixups_segment_to_js(ctx, item));
    }
    result.set_property(ctx, "segments", JSValue(segments));
    let imports = ffi::JS_NewArray(ctx);
    for (index, item) in chained_fixups.imports.iter().enumerate() {
        ffi::JS_SetPropertyUint32(ctx, imports, index as u32, image_chained_fixups_import_to_js(ctx, item));
    }
    result.set_property(ctx, "imports", JSValue(imports));
    result.raw()
}

unsafe fn image_uuid_to_js(ctx: *mut ffi::JSContext, image_uuid: &native_api::ImageUuid) -> ffi::JSValue {
    let result = JSValue(ffi::JS_NewObject(ctx));
    result.set_property(ctx, "moduleName", JSValue::string(ctx, &image_uuid.module_name));
    result.set_property(
        ctx,
        "moduleBase",
        create_native_pointer(ctx, image_uuid.module_base as u64),
    );
    result.set_property(ctx, "uuid", JSValue::string(ctx, &image_uuid.uuid));
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

unsafe extern "C" fn js_native_symbol_info(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 1 {
        return crate::util::js_throw_type_error(
            ctx,
            "Native.symbolInfo(symbolName[, moduleName]) requires at least 1 string argument",
        );
    }

    let symbol_name = match JSValue(*argv).to_string(ctx) {
        Some(value) if !value.trim().is_empty() => value,
        _ => {
            return crate::util::js_throw_type_error(
                ctx,
                "Native.symbolInfo(symbolName[, moduleName]) requires symbolName to be a non-empty string",
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
                        "Native.symbolInfo(symbolName[, moduleName]) expected moduleName to be a string when provided",
                    )
                }
            }
        }
    } else {
        None
    };

    let normalized_symbol_name = symbol_name.strip_prefix('_').unwrap_or(&symbol_name);
    let symbols = match find_native_symbols(module_name.as_deref(), &symbol_name) {
        Ok(symbols) => symbols,
        Err(common::Error::Unsupported(_)) => return JSValue::null().raw(),
        Err(common::Error::InvalidArgument(message)) => return crate::util::js_throw_type_error(ctx, &message),
        Err(err) => return js_throw_internal_error(ctx, &err.to_string()),
    };

    match symbols.into_iter().find(|symbol| {
        symbol.symbol_name == symbol_name
            || symbol.symbol_name.strip_prefix('_').unwrap_or(&symbol.symbol_name) == normalized_symbol_name
    }) {
        Some(symbol) => native_symbol_to_js(ctx, &symbol),
        None => JSValue::null().raw(),
    }
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

unsafe extern "C" fn js_native_find_encryption_info(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 1 {
        return crate::util::js_throw_type_error(
            ctx,
            "Native.findEncryptionInfo(moduleName) requires 1 string argument",
        );
    }

    let module_name = match JSValue(*argv).to_string(ctx) {
        Some(value) if !value.trim().is_empty() => value,
        _ => {
            return crate::util::js_throw_type_error(
                ctx,
                "Native.findEncryptionInfo(moduleName) requires moduleName to be a non-empty string",
            )
        }
    };

    match find_image_encryption_info(&module_name) {
        Ok(Some(encryption_info)) => image_encryption_info_to_js(ctx, &encryption_info),
        Ok(None) | Err(common::Error::Unsupported(_)) => JSValue::null().raw(),
        Err(common::Error::InvalidArgument(message)) => crate::util::js_throw_type_error(ctx, &message),
        Err(err) => js_throw_internal_error(ctx, &err.to_string()),
    }
}

unsafe extern "C" fn js_native_find_entry_point(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 1 {
        return crate::util::js_throw_type_error(ctx, "Native.findEntryPoint(moduleName) requires 1 string argument");
    }

    let module_name = match JSValue(*argv).to_string(ctx) {
        Some(value) if !value.trim().is_empty() => value,
        _ => {
            return crate::util::js_throw_type_error(
                ctx,
                "Native.findEntryPoint(moduleName) requires moduleName to be a non-empty string",
            )
        }
    };

    match find_image_entry_point(&module_name) {
        Ok(Some(entry_point)) => image_entry_point_to_js(ctx, &entry_point),
        Ok(None) | Err(common::Error::Unsupported(_)) => JSValue::null().raw(),
        Err(common::Error::InvalidArgument(message)) => crate::util::js_throw_type_error(ctx, &message),
        Err(err) => js_throw_internal_error(ctx, &err.to_string()),
    }
}

unsafe extern "C" fn js_native_find_dyld_info(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 1 {
        return crate::util::js_throw_type_error(ctx, "Native.findDyldInfo(moduleName) requires 1 string argument");
    }

    let module_name = match JSValue(*argv).to_string(ctx) {
        Some(value) if !value.trim().is_empty() => value,
        _ => {
            return crate::util::js_throw_type_error(
                ctx,
                "Native.findDyldInfo(moduleName) requires moduleName to be a non-empty string",
            )
        }
    };

    match find_image_dyld_info(&module_name) {
        Ok(Some(dyld_info)) => image_dyld_info_to_js(ctx, &dyld_info),
        Ok(None) | Err(common::Error::Unsupported(_)) => JSValue::null().raw(),
        Err(common::Error::InvalidArgument(message)) => crate::util::js_throw_type_error(ctx, &message),
        Err(err) => js_throw_internal_error(ctx, &err.to_string()),
    }
}

unsafe extern "C" fn js_native_find_source_version(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 1 {
        return crate::util::js_throw_type_error(
            ctx,
            "Native.findSourceVersion(moduleName) requires 1 string argument",
        );
    }

    let module_name = match JSValue(*argv).to_string(ctx) {
        Some(value) if !value.trim().is_empty() => value,
        _ => {
            return crate::util::js_throw_type_error(
                ctx,
                "Native.findSourceVersion(moduleName) requires moduleName to be a non-empty string",
            )
        }
    };

    match find_image_source_version(&module_name) {
        Ok(Some(source_version)) => image_source_version_to_js(ctx, &source_version),
        Ok(None) | Err(common::Error::Unsupported(_)) => JSValue::null().raw(),
        Err(common::Error::InvalidArgument(message)) => crate::util::js_throw_type_error(ctx, &message),
        Err(err) => js_throw_internal_error(ctx, &err.to_string()),
    }
}

unsafe extern "C" fn js_native_find_build_version(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 1 {
        return crate::util::js_throw_type_error(ctx, "Native.findBuildVersion(moduleName) requires 1 string argument");
    }

    let module_name = match JSValue(*argv).to_string(ctx) {
        Some(value) if !value.trim().is_empty() => value,
        _ => {
            return crate::util::js_throw_type_error(
                ctx,
                "Native.findBuildVersion(moduleName) requires moduleName to be a non-empty string",
            )
        }
    };

    match find_image_build_version(&module_name) {
        Ok(Some(build_version)) => image_build_version_to_js(ctx, &build_version),
        Ok(None) | Err(common::Error::Unsupported(_)) => JSValue::null().raw(),
        Err(common::Error::InvalidArgument(message)) => crate::util::js_throw_type_error(ctx, &message),
        Err(err) => js_throw_internal_error(ctx, &err.to_string()),
    }
}

unsafe extern "C" fn js_native_find_dylinker(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 1 {
        return crate::util::js_throw_type_error(ctx, "Native.findDylinker(moduleName) requires 1 string argument");
    }

    let module_name = match JSValue(*argv).to_string(ctx) {
        Some(value) if !value.trim().is_empty() => value,
        _ => {
            return crate::util::js_throw_type_error(
                ctx,
                "Native.findDylinker(moduleName) requires moduleName to be a non-empty string",
            )
        }
    };

    match find_image_dylinker(&module_name) {
        Ok(Some(dylinker)) => image_dylinker_to_js(ctx, &dylinker),
        Ok(None) | Err(common::Error::Unsupported(_)) => JSValue::null().raw(),
        Err(common::Error::InvalidArgument(message)) => crate::util::js_throw_type_error(ctx, &message),
        Err(err) => js_throw_internal_error(ctx, &err.to_string()),
    }
}

unsafe extern "C" fn js_native_find_install_name(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 1 {
        return crate::util::js_throw_type_error(ctx, "Native.findInstallName(moduleName) requires 1 string argument");
    }

    let module_name = match JSValue(*argv).to_string(ctx) {
        Some(value) if !value.trim().is_empty() => value,
        _ => {
            return crate::util::js_throw_type_error(
                ctx,
                "Native.findInstallName(moduleName) requires moduleName to be a non-empty string",
            )
        }
    };

    match find_image_install_name(&module_name) {
        Ok(Some(install_name)) => image_install_name_to_js(ctx, &install_name),
        Ok(None) | Err(common::Error::Unsupported(_)) => JSValue::null().raw(),
        Err(common::Error::InvalidArgument(message)) => crate::util::js_throw_type_error(ctx, &message),
        Err(err) => js_throw_internal_error(ctx, &err.to_string()),
    }
}

unsafe extern "C" fn js_native_find_linkedit(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 1 {
        return crate::util::js_throw_type_error(ctx, "Native.findLinkedit(moduleName) requires 1 string argument");
    }

    let module_name = match JSValue(*argv).to_string(ctx) {
        Some(value) if !value.trim().is_empty() => value,
        _ => {
            return crate::util::js_throw_type_error(
                ctx,
                "Native.findLinkedit(moduleName) requires moduleName to be a non-empty string",
            )
        }
    };

    match find_image_linkedit_info(&module_name) {
        Ok(Some(linkedit)) => image_linkedit_info_to_js(ctx, &linkedit),
        Ok(None) | Err(common::Error::Unsupported(_)) => JSValue::null().raw(),
        Err(common::Error::InvalidArgument(message)) => crate::util::js_throw_type_error(ctx, &message),
        Err(err) => js_throw_internal_error(ctx, &err.to_string()),
    }
}

unsafe extern "C" fn js_native_find_function_starts(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 1 {
        return crate::util::js_throw_type_error(
            ctx,
            "Native.findFunctionStarts(moduleName) requires 1 string argument",
        );
    }

    let module_name = match JSValue(*argv).to_string(ctx) {
        Some(value) if !value.trim().is_empty() => value,
        _ => {
            return crate::util::js_throw_type_error(
                ctx,
                "Native.findFunctionStarts(moduleName) requires moduleName to be a non-empty string",
            )
        }
    };

    match find_image_function_starts(&module_name) {
        Ok(Some(function_starts)) => image_function_starts_to_js(ctx, &function_starts),
        Ok(None) | Err(common::Error::Unsupported(_)) => JSValue::null().raw(),
        Err(common::Error::InvalidArgument(message)) => crate::util::js_throw_type_error(ctx, &message),
        Err(err) => js_throw_internal_error(ctx, &err.to_string()),
    }
}

unsafe extern "C" fn js_native_find_code_signature(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 1 {
        return crate::util::js_throw_type_error(
            ctx,
            "Native.findCodeSignature(moduleName) requires 1 string argument",
        );
    }

    let module_name = match JSValue(*argv).to_string(ctx) {
        Some(value) if !value.trim().is_empty() => value,
        _ => {
            return crate::util::js_throw_type_error(
                ctx,
                "Native.findCodeSignature(moduleName) requires moduleName to be a non-empty string",
            )
        }
    };

    match find_image_code_signature(&module_name) {
        Ok(Some(code_signature)) => image_code_signature_to_js(ctx, &code_signature),
        Ok(None) | Err(common::Error::Unsupported(_)) => JSValue::null().raw(),
        Err(common::Error::InvalidArgument(message)) => crate::util::js_throw_type_error(ctx, &message),
        Err(err) => js_throw_internal_error(ctx, &err.to_string()),
    }
}

unsafe extern "C" fn js_native_find_data_in_code(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 1 {
        return crate::util::js_throw_type_error(
            ctx,
            "Native.findDataInCode(moduleName) requires 1 string argument",
        );
    }

    let module_name = match JSValue(*argv).to_string(ctx) {
        Some(value) if !value.trim().is_empty() => value,
        _ => {
            return crate::util::js_throw_type_error(
                ctx,
                "Native.findDataInCode(moduleName) requires moduleName to be a non-empty string",
            )
        }
    };

    match find_image_data_in_code(&module_name) {
        Ok(Some(data_in_code)) => image_data_in_code_to_js(ctx, &data_in_code),
        Ok(None) | Err(common::Error::Unsupported(_)) => JSValue::null().raw(),
        Err(common::Error::InvalidArgument(message)) => crate::util::js_throw_type_error(ctx, &message),
        Err(err) => js_throw_internal_error(ctx, &err.to_string()),
    }
}

unsafe extern "C" fn js_native_find_exports_trie(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 1 {
        return crate::util::js_throw_type_error(
            ctx,
            "Native.findExportsTrie(moduleName) requires 1 string argument",
        );
    }

    let module_name = match JSValue(*argv).to_string(ctx) {
        Some(value) if !value.trim().is_empty() => value,
        _ => {
            return crate::util::js_throw_type_error(
                ctx,
                "Native.findExportsTrie(moduleName) requires moduleName to be a non-empty string",
            )
        }
    };

    match find_image_exports_trie(&module_name) {
        Ok(Some(exports_trie)) => image_exports_trie_to_js(ctx, &exports_trie),
        Ok(None) | Err(common::Error::Unsupported(_)) => JSValue::null().raw(),
        Err(common::Error::InvalidArgument(message)) => crate::util::js_throw_type_error(ctx, &message),
        Err(err) => js_throw_internal_error(ctx, &err.to_string()),
    }
}

unsafe extern "C" fn js_native_find_chained_fixups(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 1 {
        return crate::util::js_throw_type_error(
            ctx,
            "Native.findChainedFixups(moduleName) requires 1 string argument",
        );
    }

    let module_name = match JSValue(*argv).to_string(ctx) {
        Some(value) if !value.trim().is_empty() => value,
        _ => {
            return crate::util::js_throw_type_error(
                ctx,
                "Native.findChainedFixups(moduleName) requires moduleName to be a non-empty string",
            )
        }
    };

    match find_image_chained_fixups(&module_name) {
        Ok(Some(chained_fixups)) => image_chained_fixups_to_js(ctx, &chained_fixups),
        Ok(None) | Err(common::Error::Unsupported(_)) => JSValue::null().raw(),
        Err(common::Error::InvalidArgument(message)) => crate::util::js_throw_type_error(ctx, &message),
        Err(err) => js_throw_internal_error(ctx, &err.to_string()),
    }
}

unsafe extern "C" fn js_native_find_uuid(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 1 {
        return crate::util::js_throw_type_error(ctx, "Native.findUuid(moduleName) requires 1 string argument");
    }

    let module_name = match JSValue(*argv).to_string(ctx) {
        Some(value) if !value.trim().is_empty() => value,
        _ => {
            return crate::util::js_throw_type_error(
                ctx,
                "Native.findUuid(moduleName) requires moduleName to be a non-empty string",
            )
        }
    };

    match find_image_uuid(&module_name) {
        Ok(Some(image_uuid)) => image_uuid_to_js(ctx, &image_uuid),
        Ok(None) | Err(common::Error::Unsupported(_)) => JSValue::null().raw(),
        Err(common::Error::InvalidArgument(message)) => crate::util::js_throw_type_error(ctx, &message),
        Err(err) => js_throw_internal_error(ctx, &err.to_string()),
    }
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

unsafe extern "C" fn js_native_import_info(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 2 {
        return crate::util::js_throw_type_error(
            ctx,
            "Native.importInfo(moduleName, symbolName) requires 2 string arguments",
        );
    }

    let module_name = match JSValue(*argv).to_string(ctx) {
        Some(value) if !value.trim().is_empty() => value,
        _ => {
            return crate::util::js_throw_type_error(
                ctx,
                "Native.importInfo(moduleName, symbolName) requires moduleName to be a non-empty string",
            )
        }
    };

    let symbol_name = match JSValue(*argv.add(1)).to_string(ctx) {
        Some(value) if !value.trim().is_empty() => value,
        _ => {
            return crate::util::js_throw_type_error(
                ctx,
                "Native.importInfo(moduleName, symbolName) requires symbolName to be a non-empty string",
            )
        }
    };

    let normalized_symbol_name = symbol_name.strip_prefix('_').unwrap_or(&symbol_name);
    let imports = match find_image_imports(&module_name, Some(&symbol_name)) {
        Ok(imports) => imports,
        Err(common::Error::Unsupported(_)) => return JSValue::null().raw(),
        Err(common::Error::InvalidArgument(message)) => return crate::util::js_throw_type_error(ctx, &message),
        Err(err) => return js_throw_internal_error(ctx, &err.to_string()),
    };

    match imports.into_iter().find(|imp| {
        imp.symbol_name == symbol_name
            || imp.symbol_name.strip_prefix('_').unwrap_or(&imp.symbol_name) == normalized_symbol_name
    }) {
        Some(import) => image_import_to_js(ctx, &import),
        None => JSValue::null().raw(),
    }
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
        "encryptionInfoSupportAvailable",
        JSValue::bool(image_encryption_info_support_available()),
    );
    native.set_property(
        ctx.as_ptr(),
        "dyldInfoSupportAvailable",
        JSValue::bool(image_dyld_info_support_available()),
    );
    native.set_property(
        ctx.as_ptr(),
        "entryPointSupportAvailable",
        JSValue::bool(image_entry_point_support_available()),
    );
    native.set_property(
        ctx.as_ptr(),
        "sourceVersionSupportAvailable",
        JSValue::bool(image_source_version_support_available()),
    );
    native.set_property(
        ctx.as_ptr(),
        "buildVersionSupportAvailable",
        JSValue::bool(image_build_version_support_available()),
    );
    native.set_property(
        ctx.as_ptr(),
        "dylinkerSupportAvailable",
        JSValue::bool(image_dylinker_support_available()),
    );
    native.set_property(
        ctx.as_ptr(),
        "installNameSupportAvailable",
        JSValue::bool(image_install_name_support_available()),
    );
    native.set_property(
        ctx.as_ptr(),
        "linkeditSupportAvailable",
        JSValue::bool(image_linkedit_info_support_available()),
    );
    native.set_property(
        ctx.as_ptr(),
        "functionStartsSupportAvailable",
        JSValue::bool(image_function_starts_support_available()),
    );
    native.set_property(
        ctx.as_ptr(),
        "codeSignatureSupportAvailable",
        JSValue::bool(image_code_signature_support_available()),
    );
    native.set_property(
        ctx.as_ptr(),
        "dataInCodeSupportAvailable",
        JSValue::bool(image_data_in_code_support_available()),
    );
    native.set_property(
        ctx.as_ptr(),
        "exportsTrieSupportAvailable",
        JSValue::bool(image_exports_trie_support_available()),
    );
    native.set_property(
        ctx.as_ptr(),
        "chainedFixupsSupportAvailable",
        JSValue::bool(image_chained_fixups_support_available()),
    );
    native.set_property(
        ctx.as_ptr(),
        "uuidSupportAvailable",
        JSValue::bool(image_uuid_support_available()),
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
        add_cfunction_to_object(ctx.as_ptr(), native.raw(), "symbolInfo", js_native_symbol_info, 2);
        add_cfunction_to_object(ctx.as_ptr(), native.raw(), "findExports", js_native_find_exports, 2);
        add_cfunction_to_object(
            ctx.as_ptr(),
            native.raw(),
            "findDependencies",
            js_native_find_dependencies,
            2,
        );
        add_cfunction_to_object(
            ctx.as_ptr(),
            native.raw(),
            "findEncryptionInfo",
            js_native_find_encryption_info,
            1,
        );
        add_cfunction_to_object(
            ctx.as_ptr(),
            native.raw(),
            "findDyldInfo",
            js_native_find_dyld_info,
            1,
        );
        add_cfunction_to_object(
            ctx.as_ptr(),
            native.raw(),
            "findEntryPoint",
            js_native_find_entry_point,
            1,
        );
        add_cfunction_to_object(
            ctx.as_ptr(),
            native.raw(),
            "findSourceVersion",
            js_native_find_source_version,
            1,
        );
        add_cfunction_to_object(
            ctx.as_ptr(),
            native.raw(),
            "findBuildVersion",
            js_native_find_build_version,
            1,
        );
        add_cfunction_to_object(ctx.as_ptr(), native.raw(), "findDylinker", js_native_find_dylinker, 1);
        add_cfunction_to_object(
            ctx.as_ptr(),
            native.raw(),
            "findInstallName",
            js_native_find_install_name,
            1,
        );
        add_cfunction_to_object(ctx.as_ptr(), native.raw(), "findLinkedit", js_native_find_linkedit, 1);
        add_cfunction_to_object(
            ctx.as_ptr(),
            native.raw(),
            "findFunctionStarts",
            js_native_find_function_starts,
            1,
        );
        add_cfunction_to_object(
            ctx.as_ptr(),
            native.raw(),
            "findCodeSignature",
            js_native_find_code_signature,
            1,
        );
        add_cfunction_to_object(
            ctx.as_ptr(),
            native.raw(),
            "findDataInCode",
            js_native_find_data_in_code,
            1,
        );
        add_cfunction_to_object(
            ctx.as_ptr(),
            native.raw(),
            "findExportsTrie",
            js_native_find_exports_trie,
            1,
        );
        add_cfunction_to_object(
            ctx.as_ptr(),
            native.raw(),
            "findChainedFixups",
            js_native_find_chained_fixups,
            1,
        );
        add_cfunction_to_object(ctx.as_ptr(), native.raw(), "findUuid", js_native_find_uuid, 1);
        add_cfunction_to_object(ctx.as_ptr(), native.raw(), "findRpaths", js_native_find_rpaths, 2);
        add_cfunction_to_object(ctx.as_ptr(), native.raw(), "findImports", js_native_find_imports, 2);
        add_cfunction_to_object(ctx.as_ptr(), native.raw(), "importInfo", js_native_import_info, 2);
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
