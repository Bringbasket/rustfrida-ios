use crate::context::JSContext;
use crate::ffi;
use crate::ptr::create_native_pointer;
use crate::util::{
    add_cfunction_to_object, js_i64_to_js_number_or_bigint, js_throw_internal_error, js_u64_to_js_number_or_bigint,
    require_string_arg,
};
use crate::value::JSValue;
use common::Error as CommonError;
use native_api::{
    enumerate_images, find_export_by_name, find_image_by_address, find_image_exports, find_image_imports,
    find_image_segments, find_image_symbols, ImageInfo, ImageSegment,
};
use std::path::Path;

#[cfg(any(target_os = "ios", target_os = "macos"))]
use std::ffi::{c_void, CStr, CString};
#[cfg(any(target_os = "ios", target_os = "macos"))]
use std::sync::{Mutex, OnceLock};

#[derive(Debug, Clone, PartialEq, Eq)]
struct ModuleRange {
    base: u64,
    size: u64,
    protection: String,
    path: String,
    file_offset: u64,
    file_size: u64,
}

fn image_matches(module_name: &str, image: &ImageInfo) -> bool {
    if image.name == module_name {
        return true;
    }

    let module_basename = Path::new(module_name).file_name().and_then(|name| name.to_str());
    let image_basename = Path::new(&image.name).file_name().and_then(|name| name.to_str());
    matches!((module_basename, image_basename), (Some(module), Some(image)) if module == image)
}

fn find_matching_image<'a>(module_name: &str, images: &'a [ImageInfo]) -> Option<&'a ImageInfo> {
    images
        .iter()
        .find(|image| image.name == module_name)
        .or_else(|| images.iter().find(|image| image_matches(module_name, image)))
}

fn normalize_macho_symbol_name(name: &str) -> &str {
    name.strip_prefix('_').unwrap_or(name)
}

fn apply_image_slide(address: usize, slide: isize) -> Option<u64> {
    let address = address as i128 + slide as i128;
    if !(0..=u64::MAX as i128).contains(&address) {
        return None;
    }
    Some(address as u64)
}

fn protection_from_mach(flags: i32) -> String {
    let mut protection = String::with_capacity(3);
    protection.push(if flags & 1 != 0 { 'r' } else { '-' });
    protection.push(if flags & 2 != 0 { 'w' } else { '-' });
    protection.push(if flags & 4 != 0 { 'x' } else { '-' });
    protection
}

fn valid_protection_filter(filter: &str) -> bool {
    let filter = filter.as_bytes();
    filter.len() == 3
        && matches!(filter[0], b'r' | b'-')
        && matches!(filter[1], b'w' | b'-')
        && matches!(filter[2], b'x' | b'-')
}

fn protection_matches(actual: &str, filter: &str) -> bool {
    let actual = actual.as_bytes();
    let filter = filter.as_bytes();
    filter.len() == 3
        && actual.len() >= 3
        && (0..3).all(|index| filter[index] == b'-' || filter[index] == actual[index])
}

fn symbol_export_type(address: usize, segments: &[ImageSegment]) -> &'static str {
    segments
        .iter()
        .find(|segment| address >= segment.vmaddr && address < segment.vmaddr.saturating_add(segment.vmsize))
        .map(|segment| {
            if segment.initprot & 4 != 0 {
                "function"
            } else {
                "variable"
            }
        })
        .unwrap_or("variable")
}

fn module_range_from_segment(
    image: &ImageInfo,
    segment: &ImageSegment,
    protection_filter: Option<&str>,
) -> Option<ModuleRange> {
    if segment.vmsize == 0 || segment.segment_name == "__PAGEZERO" {
        return None;
    }

    let protection = protection_from_mach(segment.initprot);
    if protection_filter
        .map(|filter| !protection_matches(&protection, filter))
        .unwrap_or(false)
    {
        return None;
    }

    Some(ModuleRange {
        base: apply_image_slide(segment.vmaddr, image.slide)?,
        size: segment.vmsize as u64,
        protection,
        path: image.name.clone(),
        file_offset: segment.fileoff as u64,
        file_size: segment.filesize as u64,
    })
}

fn resolve_image(module_name: &str) -> Result<Option<ImageInfo>, CommonError> {
    let images = enumerate_images()?;
    Ok(find_matching_image(module_name, &images).cloned())
}

unsafe fn require_nonempty_string_arg(
    ctx: *mut ffi::JSContext,
    argc: i32,
    argv: *mut ffi::JSValue,
    index: usize,
    usage: &str,
) -> Result<String, ffi::JSValue> {
    if argc <= index as i32 || !JSValue(*argv.add(index)).is_string() {
        return Err(crate::util::js_throw_type_error(ctx, usage));
    }

    let value = require_string_arg(ctx, argc, argv, index, usage)?;
    if value.trim().is_empty() {
        return Err(crate::util::js_throw_type_error(ctx, usage));
    }
    Ok(value)
}

unsafe fn image_to_js(ctx: *mut ffi::JSContext, image: &ImageInfo) -> ffi::JSValue {
    let object = JSValue(ffi::JS_NewObject(ctx));
    let basename = Path::new(&image.name)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(&image.name);
    object.set_property(ctx, "name", JSValue::string(ctx, basename));
    object.set_property(ctx, "path", JSValue::string(ctx, &image.name));
    object.set_property(ctx, "base", create_native_pointer(ctx, image.base as u64));
    object.set_property(
        ctx,
        "slide",
        JSValue(js_i64_to_js_number_or_bigint(ctx, image.slide as i64)),
    );
    object.set_property(
        ctx,
        "size",
        JSValue(js_u64_to_js_number_or_bigint(ctx, image.size as u64)),
    );
    object.raw()
}

unsafe fn export_to_js(
    ctx: *mut ffi::JSContext,
    symbol: &native_api::NativeSymbol,
    address: u64,
    segments: &[ImageSegment],
) -> ffi::JSValue {
    let object = JSValue(ffi::JS_NewObject(ctx));
    object.set_property(
        ctx,
        "type",
        JSValue::string(ctx, symbol_export_type(symbol.address, segments)),
    );
    object.set_property(
        ctx,
        "name",
        JSValue::string(ctx, normalize_macho_symbol_name(&symbol.symbol_name)),
    );
    object.set_property(ctx, "address", create_native_pointer(ctx, address));
    object.raw()
}

unsafe fn import_to_js(ctx: *mut ffi::JSContext, import: &native_api::ImageImport) -> ffi::JSValue {
    let object = JSValue(ffi::JS_NewObject(ctx));
    object.set_property(ctx, "type", JSValue::string(ctx, &import.symbol_type));
    object.set_property(
        ctx,
        "name",
        JSValue::string(ctx, normalize_macho_symbol_name(&import.symbol_name)),
    );
    match import.dylib_name.as_deref() {
        Some(module) => object.set_property(ctx, "module", JSValue::string(ctx, module)),
        None => object.set_property(ctx, "module", JSValue::null()),
    };
    object.set_property(ctx, "slot", create_native_pointer(ctx, import.slot as u64));
    object.set_property(ctx, "address", create_native_pointer(ctx, import.address as u64));
    object.set_property(ctx, "ordinal", JSValue::int(import.dylib_ordinal as i32));
    object.set_property(ctx, "weak", JSValue::bool(import.weak_import));
    object.raw()
}

unsafe fn symbol_to_js(
    ctx: *mut ffi::JSContext,
    symbol_type: &str,
    name: &str,
    address: u64,
    is_global: bool,
    is_defined: bool,
) -> ffi::JSValue {
    let object = JSValue(ffi::JS_NewObject(ctx));
    object.set_property(ctx, "type", JSValue::string(ctx, symbol_type));
    object.set_property(ctx, "name", JSValue::string(ctx, normalize_macho_symbol_name(name)));
    object.set_property(ctx, "address", create_native_pointer(ctx, address));
    object.set_property(ctx, "isGlobal", JSValue::bool(is_global));
    object.set_property(ctx, "isDefined", JSValue::bool(is_defined));
    object.raw()
}

unsafe fn range_to_js(ctx: *mut ffi::JSContext, range: &ModuleRange) -> ffi::JSValue {
    let object = JSValue(ffi::JS_NewObject(ctx));
    object.set_property(ctx, "base", create_native_pointer(ctx, range.base));
    object.set_property(ctx, "size", JSValue(js_u64_to_js_number_or_bigint(ctx, range.size)));
    object.set_property(ctx, "protection", JSValue::string(ctx, &range.protection));

    let file = JSValue(ffi::JS_NewObject(ctx));
    file.set_property(ctx, "path", JSValue::string(ctx, &range.path));
    file.set_property(
        ctx,
        "offset",
        JSValue(js_u64_to_js_number_or_bigint(ctx, range.file_offset)),
    );
    file.set_property(
        ctx,
        "size",
        JSValue(js_u64_to_js_number_or_bigint(ctx, range.file_size)),
    );
    object.set_property(ctx, "file", file);
    object.raw()
}

unsafe extern "C" fn js_module_enumerate(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let images = match enumerate_images() {
        Ok(images) => images,
        Err(CommonError::Unsupported(_)) => return ffi::JS_NewArray(ctx),
        Err(err) => return js_throw_internal_error(ctx, &err.to_string()),
    };

    let array = ffi::JS_NewArray(ctx);
    for (index, image) in images.iter().enumerate() {
        ffi::JS_SetPropertyUint32(ctx, array, index as u32, image_to_js(ctx, image));
    }
    array
}

unsafe extern "C" fn js_module_find_base(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let module_name = match require_string_arg(
        ctx,
        argc,
        argv,
        0,
        "Module.findBaseAddress(moduleName) requires 1 string argument",
    ) {
        Ok(value) => value,
        Err(err) => return err,
    };

    let images = match enumerate_images() {
        Ok(images) => images,
        Err(CommonError::Unsupported(_)) => return JSValue::null().raw(),
        Err(err) => return js_throw_internal_error(ctx, &err.to_string()),
    };

    match images.into_iter().find(|image| image_matches(&module_name, image)) {
        Some(image) => create_native_pointer(ctx, image.base as u64).raw(),
        None => JSValue::null().raw(),
    }
}

unsafe extern "C" fn js_module_find_by_address(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 1 {
        return crate::util::js_throw_type_error(ctx, "Module.findByAddress(addr) requires 1 address argument");
    }

    let value = JSValue(*argv);
    let address = if let Some(address) = crate::ptr::get_native_pointer_addr(value) {
        address
    } else if value.is_int() || value.is_float() || ffi::qjs_is_big_int(ctx, value.raw()) != 0 {
        let mut address = 0u64;
        if ffi::qjs_value_to_u64(ctx, &mut address, value.raw()) != 0 {
            return crate::util::js_throw_type_error(ctx, "Module.findByAddress(addr) expected a pointer-like value");
        }
        address
    } else {
        return crate::util::js_throw_type_error(ctx, "Module.findByAddress(addr) expected a pointer-like value");
    };

    match find_image_by_address(address as usize) {
        Ok(Some(image)) => image_to_js(ctx, &image),
        Ok(None) => JSValue::null().raw(),
        Err(CommonError::Unsupported(_)) => JSValue::null().raw(),
        Err(err) => js_throw_internal_error(ctx, &err.to_string()),
    }
}

unsafe extern "C" fn js_module_find_export(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 2 {
        return crate::util::js_throw_type_error(
            ctx,
            "Module.findExportByName(moduleName, symbolName) requires 2 arguments",
        );
    }

    let module_name =
        {
            let value = JSValue(*argv);
            if value.is_null() || value.is_undefined() {
                None
            } else if value.is_string() {
                match value.to_string(ctx) {
                    Some(value) => Some(value),
                    None => return crate::util::js_throw_type_error(
                        ctx,
                        "Module.findExportByName(moduleName, symbolName) expected moduleName to be a string or null",
                    ),
                }
            } else {
                return crate::util::js_throw_type_error(
                    ctx,
                    "Module.findExportByName(moduleName, symbolName) expected moduleName to be a string or null",
                );
            }
        };

    let symbol_name = match require_string_arg(
        ctx,
        argc,
        argv,
        1,
        "Module.findExportByName(moduleName, symbolName) requires symbolName to be a string",
    ) {
        Ok(value) => value,
        Err(err) => return err,
    };

    match find_export_by_name(module_name.as_deref(), &symbol_name) {
        Ok(Some(addr)) => create_native_pointer(ctx, addr as u64).raw(),
        Ok(None) => JSValue::null().raw(),
        Err(CommonError::Unsupported(_)) => JSValue::null().raw(),
        Err(err) => js_throw_internal_error(ctx, &err.to_string()),
    }
}

unsafe extern "C" fn js_module_enumerate_exports(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let module_name = match require_nonempty_string_arg(
        ctx,
        argc,
        argv,
        0,
        "Module.enumerateExports(moduleName) requires moduleName to be a non-empty string",
    ) {
        Ok(value) => value,
        Err(err) => return err,
    };

    let image = match resolve_image(module_name.trim()) {
        Ok(Some(image)) => image,
        Ok(None) | Err(CommonError::Unsupported(_)) => return ffi::JS_NewArray(ctx),
        Err(CommonError::InvalidArgument(message)) => return crate::util::js_throw_type_error(ctx, &message),
        Err(err) => return js_throw_internal_error(ctx, &err.to_string()),
    };
    let exports = match find_image_exports(module_name.trim(), None) {
        Ok(exports) => exports,
        Err(CommonError::Unsupported(_)) => return ffi::JS_NewArray(ctx),
        Err(CommonError::InvalidArgument(message)) => return crate::util::js_throw_type_error(ctx, &message),
        Err(err) => return js_throw_internal_error(ctx, &err.to_string()),
    };
    let segments = match find_image_segments(module_name.trim()) {
        Ok(segments) => segments,
        Err(CommonError::Unsupported(_)) => Vec::new(),
        Err(CommonError::InvalidArgument(message)) => return crate::util::js_throw_type_error(ctx, &message),
        Err(err) => return js_throw_internal_error(ctx, &err.to_string()),
    };

    let array = ffi::JS_NewArray(ctx);
    let mut output_index = 0u32;
    for symbol in &exports {
        let Some(address) = apply_image_slide(symbol.address, image.slide) else {
            continue;
        };
        ffi::JS_SetPropertyUint32(ctx, array, output_index, export_to_js(ctx, symbol, address, &segments));
        output_index += 1;
    }
    array
}

unsafe extern "C" fn js_module_enumerate_imports(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let module_name = match require_nonempty_string_arg(
        ctx,
        argc,
        argv,
        0,
        "Module.enumerateImports(moduleName) requires moduleName to be a non-empty string",
    ) {
        Ok(value) => value,
        Err(err) => return err,
    };

    match resolve_image(module_name.trim()) {
        Ok(Some(_)) => {}
        Ok(None) | Err(CommonError::Unsupported(_)) => return ffi::JS_NewArray(ctx),
        Err(CommonError::InvalidArgument(message)) => return crate::util::js_throw_type_error(ctx, &message),
        Err(err) => return js_throw_internal_error(ctx, &err.to_string()),
    }
    let imports = match find_image_imports(module_name.trim(), None) {
        Ok(imports) => imports,
        Err(CommonError::Unsupported(_)) => return ffi::JS_NewArray(ctx),
        Err(CommonError::InvalidArgument(message)) => return crate::util::js_throw_type_error(ctx, &message),
        Err(err) => return js_throw_internal_error(ctx, &err.to_string()),
    };

    let array = ffi::JS_NewArray(ctx);
    for (index, import) in imports.iter().enumerate() {
        ffi::JS_SetPropertyUint32(ctx, array, index as u32, import_to_js(ctx, import));
    }
    array
}

unsafe extern "C" fn js_module_enumerate_symbols(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let module_name = match require_nonempty_string_arg(
        ctx,
        argc,
        argv,
        0,
        "Module.enumerateSymbols(moduleName) requires moduleName to be a non-empty string",
    ) {
        Ok(value) => value,
        Err(err) => return err,
    };

    match resolve_image(module_name.trim()) {
        Ok(Some(_)) => {}
        Ok(None) | Err(CommonError::Unsupported(_)) => return ffi::JS_NewArray(ctx),
        Err(CommonError::InvalidArgument(message)) => return crate::util::js_throw_type_error(ctx, &message),
        Err(err) => return js_throw_internal_error(ctx, &err.to_string()),
    }
    let symbols = match find_image_symbols(module_name.trim()) {
        Ok(symbols) => symbols,
        Err(CommonError::Unsupported(_)) => return ffi::JS_NewArray(ctx),
        Err(CommonError::InvalidArgument(message)) => return crate::util::js_throw_type_error(ctx, &message),
        Err(err) => return js_throw_internal_error(ctx, &err.to_string()),
    };

    let array = ffi::JS_NewArray(ctx);
    let mut output_index = 0u32;
    for symbol in &symbols {
        ffi::JS_SetPropertyUint32(
            ctx,
            array,
            output_index,
            symbol_to_js(
                ctx,
                symbol.symbol_type,
                &symbol.symbol_name,
                symbol.address as u64,
                symbol.is_global,
                symbol.is_defined,
            ),
        );
        output_index += 1;
    }
    array
}

unsafe extern "C" fn js_module_enumerate_ranges(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let module_name = match require_nonempty_string_arg(
        ctx,
        argc,
        argv,
        0,
        "Module.enumerateRanges(moduleName, protection?) requires moduleName to be a non-empty string",
    ) {
        Ok(value) => value,
        Err(err) => return err,
    };

    let protection = if argc < 2 {
        None
    } else {
        let value = JSValue(*argv.add(1));
        if value.is_null() || value.is_undefined() {
            None
        } else if value.is_string() {
            let Some(protection) = value.to_string(ctx) else {
                return crate::util::js_throw_type_error(
                    ctx,
                    "Module.enumerateRanges(moduleName, protection?) expected protection to be an rwx string",
                );
            };
            if !valid_protection_filter(&protection) {
                return crate::util::js_throw_type_error(
                    ctx,
                    "Module.enumerateRanges(moduleName, protection?) expected protection to be an rwx string",
                );
            }
            Some(protection)
        } else {
            return crate::util::js_throw_type_error(
                ctx,
                "Module.enumerateRanges(moduleName, protection?) expected protection to be an rwx string",
            );
        }
    };

    let image = match resolve_image(module_name.trim()) {
        Ok(Some(image)) => image,
        Ok(None) | Err(CommonError::Unsupported(_)) => return ffi::JS_NewArray(ctx),
        Err(CommonError::InvalidArgument(message)) => return crate::util::js_throw_type_error(ctx, &message),
        Err(err) => return js_throw_internal_error(ctx, &err.to_string()),
    };
    let segments = match find_image_segments(module_name.trim()) {
        Ok(segments) => segments,
        Err(CommonError::Unsupported(_)) => return ffi::JS_NewArray(ctx),
        Err(CommonError::InvalidArgument(message)) => return crate::util::js_throw_type_error(ctx, &message),
        Err(err) => return js_throw_internal_error(ctx, &err.to_string()),
    };

    let array = ffi::JS_NewArray(ctx);
    let mut output_index = 0u32;
    for range in segments
        .iter()
        .filter_map(|segment| module_range_from_segment(&image, segment, protection.as_deref()))
    {
        ffi::JS_SetPropertyUint32(ctx, array, output_index, range_to_js(ctx, &range));
        output_index += 1;
    }
    array
}

#[cfg(any(target_os = "ios", target_os = "macos"))]
fn loaded_module_handles() -> &'static Mutex<Vec<(usize, usize)>> {
    static HANDLES: OnceLock<Mutex<Vec<(usize, usize)>>> = OnceLock::new();
    HANDLES.get_or_init(|| Mutex::new(Vec::new()))
}

#[cfg(any(target_os = "ios", target_os = "macos"))]
fn load_module_image(path: &str, runtime: usize) -> Result<ImageInfo, String> {
    let path_c = CString::new(path).map_err(|_| "Module.load path contains an interior NUL byte".to_string())?;
    unsafe {
        libc::dlerror();
    }
    let handle = unsafe { libc::dlopen(path_c.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
    if handle.is_null() {
        let detail = unsafe {
            let error = libc::dlerror();
            if error.is_null() {
                "dlopen returned null without an error".to_string()
            } else {
                CStr::from_ptr(error).to_string_lossy().into_owned()
            }
        };
        return Err(format!("Module.load('{}') failed: {detail}", path));
    }

    let image = enumerate_images()
        .map_err(|err| format!("Module.load('{}') could not enumerate images: {err}", path))
        .and_then(|images| {
            find_matching_image(path, &images)
                .cloned()
                .ok_or_else(|| format!("Module.load('{}') succeeded but the loaded image was not found", path))
        });

    match image {
        Ok(image) => {
            loaded_module_handles()
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push((runtime, handle as usize));
            Ok(image)
        }
        Err(error) => {
            unsafe {
                libc::dlclose(handle);
            }
            Err(error)
        }
    }
}

#[cfg(not(any(target_os = "ios", target_os = "macos")))]
fn load_module_image(_path: &str, _runtime: usize) -> Result<ImageInfo, String> {
    Err("Module.load is only supported on Apple targets".to_string())
}

unsafe extern "C" fn js_module_load(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let path = match require_nonempty_string_arg(
        ctx,
        argc,
        argv,
        0,
        "Module.load(path) requires path to be a non-empty string",
    ) {
        Ok(value) => value,
        Err(err) => return err,
    };
    if path.as_bytes().contains(&0) {
        return crate::util::js_throw_type_error(ctx, "Module.load(path) path must not contain a NUL byte");
    }

    match load_module_image(&path, ffi::JS_GetRuntime(ctx) as usize) {
        Ok(image) => image_to_js(ctx, &image),
        Err(err) => js_throw_internal_error(ctx, &err),
    }
}

#[cfg(any(target_os = "ios", target_os = "macos"))]
#[allow(dead_code)]
pub(crate) fn cleanup_loaded_modules(runtime: *mut ffi::JSRuntime) {
    if runtime.is_null() {
        return;
    }

    let handles = {
        let mut handles = loaded_module_handles()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut owned = Vec::new();
        handles.retain(|(owner, handle)| {
            if *owner == runtime as usize {
                owned.push(*handle);
                false
            } else {
                true
            }
        });
        owned
    };
    for handle in handles.into_iter().rev() {
        unsafe {
            libc::dlclose(handle as *mut c_void);
        }
    }
}

#[cfg(not(any(target_os = "ios", target_os = "macos")))]
#[allow(dead_code)]
pub(crate) fn cleanup_loaded_modules(_runtime: *mut ffi::JSRuntime) {}

pub(crate) fn register_module_api(ctx: &JSContext) {
    let global = ctx.global_object();
    let module = ctx.new_object();

    unsafe {
        let ctx_ptr = ctx.as_ptr();
        add_cfunction_to_object(ctx_ptr, module.raw(), "enumerateModules", js_module_enumerate, 0);
        add_cfunction_to_object(ctx_ptr, module.raw(), "findBaseAddress", js_module_find_base, 1);
        add_cfunction_to_object(ctx_ptr, module.raw(), "findByAddress", js_module_find_by_address, 1);
        add_cfunction_to_object(ctx_ptr, module.raw(), "findExportByName", js_module_find_export, 2);
        add_cfunction_to_object(
            ctx_ptr,
            module.raw(),
            "enumerateExports",
            js_module_enumerate_exports,
            1,
        );
        add_cfunction_to_object(
            ctx_ptr,
            module.raw(),
            "enumerateImports",
            js_module_enumerate_imports,
            1,
        );
        add_cfunction_to_object(
            ctx_ptr,
            module.raw(),
            "enumerateSymbols",
            js_module_enumerate_symbols,
            1,
        );
        add_cfunction_to_object(ctx_ptr, module.raw(), "enumerateRanges", js_module_enumerate_ranges, 2);
        add_cfunction_to_object(ctx_ptr, module.raw(), "load", js_module_load, 1);
    }

    global.set_property(ctx.as_ptr(), "Module", module);
    global.free(ctx.as_ptr());
}

#[cfg(test)]
mod tests {
    use super::*;

    fn segment(name: &str, vmaddr: usize, vmsize: usize, initprot: i32) -> ImageSegment {
        ImageSegment {
            module_name: "/tmp/Test.dylib".into(),
            module_base: 0x11000,
            segment_name: name.into(),
            vmaddr,
            vmsize,
            fileoff: 0x200,
            filesize: 0x800,
            maxprot: initprot,
            initprot,
        }
    }

    #[test]
    fn macho_symbol_names_drop_one_abi_underscore() {
        assert_eq!(normalize_macho_symbol_name("_malloc"), "malloc");
        assert_eq!(normalize_macho_symbol_name("$s4Demo3fooyyF"), "$s4Demo3fooyyF");
        assert_eq!(normalize_macho_symbol_name("__hidden"), "_hidden");
    }

    #[test]
    fn image_slide_handles_positive_negative_and_overflow() {
        assert_eq!(apply_image_slide(0x1000, 0x2000), Some(0x3000));
        assert_eq!(apply_image_slide(0x3000, -0x1000), Some(0x2000));
        assert_eq!(apply_image_slide(0x1000, -0x2000), None);
    }

    #[test]
    fn protection_filters_use_frida_wildcards() {
        assert_eq!(protection_from_mach(5), "r-x");
        assert!(valid_protection_filter("r-x"));
        assert!(valid_protection_filter("---"));
        assert!(!valid_protection_filter("rx-"));
        assert!(!valid_protection_filter("read"));
        assert!(protection_matches("rwx", "r-x"));
        assert!(!protection_matches("rw-", "r-x"));
    }

    #[test]
    fn export_type_follows_segment_execute_permission() {
        let segments = vec![
            segment("__TEXT", 0x1000, 0x1000, 5),
            segment("__DATA", 0x2000, 0x1000, 3),
        ];
        assert_eq!(symbol_export_type(0x1100, &segments), "function");
        assert_eq!(symbol_export_type(0x2100, &segments), "variable");
        assert_eq!(symbol_export_type(0x5000, &segments), "variable");
    }

    #[test]
    fn module_ranges_rebase_segments_and_keep_file_metadata() {
        let image = ImageInfo {
            name: "/tmp/Test.dylib".into(),
            base: 0x11000,
            slide: 0x10000,
            size: 0x2000,
        };
        let text = segment("__TEXT", 0x1000, 0x1000, 5);
        let range = module_range_from_segment(&image, &text, Some("r-x")).expect("matching range");
        assert_eq!(range.base, 0x11000);
        assert_eq!(range.size, 0x1000);
        assert_eq!(range.protection, "r-x");
        assert_eq!(range.path, "/tmp/Test.dylib");
        assert_eq!(range.file_offset, 0x200);
        assert_eq!(range.file_size, 0x800);
        assert!(module_range_from_segment(&image, &text, Some("-w-")).is_none());
        assert!(module_range_from_segment(&image, &segment("__PAGEZERO", 0, 0x1000, 0), None).is_none());
    }

    #[test]
    fn loaded_image_resolution_prefers_exact_paths() {
        let images = vec![
            ImageInfo {
                name: "/first/Test.dylib".into(),
                base: 1,
                slide: 0,
                size: 1,
            },
            ImageInfo {
                name: "/second/Test.dylib".into(),
                base: 2,
                slide: 0,
                size: 1,
            },
        ];
        assert_eq!(
            find_matching_image("/second/Test.dylib", &images).map(|image| image.base),
            Some(2)
        );
        assert_eq!(
            find_matching_image("Test.dylib", &images).map(|image| image.base),
            Some(1)
        );
        assert_eq!(
            find_matching_image("/different/Test.dylib", &images).map(|image| image.base),
            Some(1)
        );
    }
}
