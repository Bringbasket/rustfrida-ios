use crate::context::JSContext;
use crate::ffi;
use crate::ptr::create_native_pointer;
use crate::util::{add_cfunction_to_object, js_throw_internal_error, js_throw_type_error};
use crate::value::JSValue;
use native_api::{
    current_process_uses_arm64e, enumerate_arm64e_images, image_uses_arm64e, pac_support_available, strip_code_pointer,
    strip_data_pointer, ImageInfo,
};

unsafe fn image_to_js(ctx: *mut ffi::JSContext, image: &ImageInfo) -> ffi::JSValue {
    let object = JSValue(ffi::JS_NewObject(ctx));
    object.set_property(ctx, "name", JSValue::string(ctx, &image.name));
    object.set_property(ctx, "path", JSValue::string(ctx, &image.name));
    object.set_property(ctx, "base", create_native_pointer(ctx, image.base as u64));
    object.set_property(ctx, "slide", JSValue(ffi::JS_NewBigInt64(ctx, image.slide as i64)));
    object.raw()
}

unsafe fn pointer_arg_to_u64(ctx: *mut ffi::JSContext, value: JSValue, usage: &str) -> Result<u64, ffi::JSValue> {
    if let Some(address) = crate::ptr::get_native_pointer_addr(value) {
        return Ok(address);
    }

    if value.is_int() || value.is_float() || ffi::qjs_is_big_int(ctx, value.raw()) != 0 {
        let mut address = 0u64;
        if ffi::qjs_value_to_u64(ctx, &mut address, value.raw()) == 0 {
            return Ok(address);
        }
    }

    Err(js_throw_type_error(ctx, usage))
}

unsafe extern "C" fn js_pac_strip(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 1 {
        return js_throw_type_error(ctx, "PAC.strip(address) requires 1 address argument");
    }

    let address = match pointer_arg_to_u64(ctx, JSValue(*argv), "PAC.strip(address) expected a pointer-like value") {
        Ok(value) => value,
        Err(err) => return err,
    };

    match strip_code_pointer(address as usize) {
        Ok(stripped) => create_native_pointer(ctx, stripped as u64).raw(),
        Err(err) => js_throw_internal_error(ctx, &err.to_string()),
    }
}

unsafe extern "C" fn js_pac_strip_data(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 1 {
        return js_throw_type_error(ctx, "PAC.stripData(address) requires 1 address argument");
    }

    let address = match pointer_arg_to_u64(
        ctx,
        JSValue(*argv),
        "PAC.stripData(address) expected a pointer-like value",
    ) {
        Ok(value) => value,
        Err(err) => return err,
    };

    match strip_data_pointer(address as usize) {
        Ok(stripped) => create_native_pointer(ctx, stripped as u64).raw(),
        Err(err) => js_throw_internal_error(ctx, &err.to_string()),
    }
}

unsafe extern "C" fn js_pac_process_arm64e(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    match current_process_uses_arm64e() {
        Ok(value) => JSValue::bool(value).raw(),
        Err(err) => js_throw_internal_error(ctx, &err.to_string()),
    }
}

unsafe extern "C" fn js_pac_image_arm64e(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 1 {
        return js_throw_type_error(ctx, "PAC.isImageArm64e(moduleName) requires 1 string argument");
    }

    let module_name = match JSValue(*argv).to_string(ctx) {
        Some(value) if !value.trim().is_empty() => value,
        _ => {
            return js_throw_type_error(
                ctx,
                "PAC.isImageArm64e(moduleName) requires moduleName to be a non-empty string",
            )
        }
    };

    match image_uses_arm64e(&module_name) {
        Ok(Some(value)) => JSValue::bool(value).raw(),
        Ok(None) => JSValue::null().raw(),
        Err(common::Error::InvalidArgument(message)) => js_throw_type_error(ctx, &message),
        Err(err) => js_throw_internal_error(ctx, &err.to_string()),
    }
}

unsafe extern "C" fn js_pac_arm64e_images(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let query = if argc >= 1 {
        match JSValue(*argv).to_string(ctx) {
            Some(value) if !value.trim().is_empty() => Some(value),
            Some(_) => None,
            None => {
                return js_throw_type_error(
                    ctx,
                    "PAC.arm64eImages([query]) expected query to be a string when provided",
                )
            }
        }
    } else {
        None
    };

    let images = match enumerate_arm64e_images(query.as_deref()) {
        Ok(images) => images,
        Err(common::Error::Unsupported(_)) => return ffi::JS_NewArray(ctx),
        Err(common::Error::InvalidArgument(message)) => return js_throw_type_error(ctx, &message),
        Err(err) => return js_throw_internal_error(ctx, &err.to_string()),
    };

    let array = ffi::JS_NewArray(ctx);
    for (index, image) in images.iter().enumerate() {
        ffi::JS_SetPropertyUint32(ctx, array, index as u32, image_to_js(ctx, image));
    }
    array
}

pub(crate) fn register_pac_api(ctx: &JSContext) {
    let global = ctx.global_object();
    let pac = ctx.new_object();

    pac.set_property(ctx.as_ptr(), "available", JSValue::bool(pac_support_available()));

    unsafe {
        let ctx_ptr = ctx.as_ptr();
        add_cfunction_to_object(ctx_ptr, pac.raw(), "isProcessArm64e", js_pac_process_arm64e, 0);
        add_cfunction_to_object(ctx_ptr, pac.raw(), "isImageArm64e", js_pac_image_arm64e, 1);
        add_cfunction_to_object(ctx_ptr, pac.raw(), "arm64eImages", js_pac_arm64e_images, 1);
        add_cfunction_to_object(ctx_ptr, pac.raw(), "strip", js_pac_strip, 1);
        add_cfunction_to_object(ctx_ptr, pac.raw(), "stripData", js_pac_strip_data, 1);
    }

    global.set_property(ctx.as_ptr(), "PAC", pac);
    global.free(ctx.as_ptr());
}
