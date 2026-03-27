use crate::context::JSContext;
use crate::ffi;
use crate::ptr::create_native_pointer;
use crate::util::{
    add_cfunction_to_object, js_i64_to_js_number_or_bigint, js_throw_internal_error, js_u64_to_js_number_or_bigint,
    require_string_arg,
};
use crate::value::JSValue;
use common::Error as CommonError;
use native_api::{enumerate_images, find_export_by_name, find_image_by_address, ImageInfo};
use std::path::Path;

fn image_matches(module_name: &str, image: &ImageInfo) -> bool {
    if image.name == module_name {
        return true;
    }

    Path::new(&image.name)
        .file_name()
        .and_then(|name| name.to_str())
        .map(|name| name == module_name)
        .unwrap_or(false)
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
    object.set_property(ctx, "slide", JSValue(js_i64_to_js_number_or_bigint(ctx, image.slide as i64)));
    object.set_property(ctx, "size", JSValue(js_u64_to_js_number_or_bigint(ctx, image.size as u64)));
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

pub(crate) fn register_module_api(ctx: &JSContext) {
    let global = ctx.global_object();
    let module = ctx.new_object();

    unsafe {
        let ctx_ptr = ctx.as_ptr();
        add_cfunction_to_object(ctx_ptr, module.raw(), "enumerateModules", js_module_enumerate, 0);
        add_cfunction_to_object(ctx_ptr, module.raw(), "findBaseAddress", js_module_find_base, 1);
        add_cfunction_to_object(ctx_ptr, module.raw(), "findByAddress", js_module_find_by_address, 1);
        add_cfunction_to_object(ctx_ptr, module.raw(), "findExportByName", js_module_find_export, 2);
    }

    global.set_property(ctx.as_ptr(), "Module", module);
    global.free(ctx.as_ptr());
}
