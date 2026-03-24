use crate::context::JSContext;
use crate::ffi;
use crate::ptr::create_native_pointer;
use crate::util::{add_cfunction_to_object, js_throw_internal_error, js_throw_type_error, require_string_arg};
use crate::value::JSValue;
use common::Error as CommonError;
use objc_api::{ObjcApi, ObjcMethodInfo};

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

unsafe extern "C" fn js_objc_classes(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let classes = match ObjcApi::new().enumerate_classes() {
        Ok(classes) => classes,
        Err(CommonError::Unsupported(_)) => return ffi::JS_NewArray(ctx),
        Err(err) => return js_throw_internal_error(ctx, &err.to_string()),
    };

    let array = ffi::JS_NewArray(ctx);
    for (index, name) in classes.iter().enumerate() {
        ffi::JS_SetPropertyUint32(ctx, array, index as u32, JSValue::string(ctx, name).raw());
    }
    array
}

unsafe extern "C" fn js_objc_find_classes(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let query = match require_string_arg(ctx, argc, argv, 0, "ObjC.findClasses(query) requires 1 string argument") {
        Ok(value) => value,
        Err(err) => return err,
    };

    let classes = match ObjcApi::new().find_classes(&query) {
        Ok(classes) => classes,
        Err(CommonError::Unsupported(_)) => return ffi::JS_NewArray(ctx),
        Err(CommonError::InvalidArgument(message)) => return js_throw_type_error(ctx, &message),
        Err(err) => return js_throw_internal_error(ctx, &err.to_string()),
    };

    let array = ffi::JS_NewArray(ctx);
    for (index, name) in classes.iter().enumerate() {
        ffi::JS_SetPropertyUint32(ctx, array, index as u32, JSValue::string(ctx, name).raw());
    }
    array
}

unsafe extern "C" fn js_objc_class_exists(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let name = match require_string_arg(ctx, argc, argv, 0, "ObjC.classExists(name) requires 1 string argument") {
        Ok(value) => value,
        Err(err) => return err,
    };

    JSValue::bool(ObjcApi::new().class_exists(&name)).raw()
}

unsafe extern "C" fn js_objc_selector(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let name = match require_string_arg(ctx, argc, argv, 0, "ObjC.selector(name) requires 1 string argument") {
        Ok(value) => value,
        Err(err) => return err,
    };

    match ObjcApi::new().selector(&name) {
        Ok(selector) => create_native_pointer(ctx, selector as u64).raw(),
        Err(CommonError::Unsupported(_)) => JSValue::null().raw(),
        Err(CommonError::InvalidArgument(message)) => js_throw_type_error(ctx, &message),
        Err(err) => js_throw_internal_error(ctx, &err.to_string()),
    }
}

unsafe extern "C" fn js_objc_method_imp(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let class_name = match require_string_arg(
        ctx,
        argc,
        argv,
        0,
        "ObjC.methodImp(className, selectorName[, isClassMethod]) requires 2 string arguments",
    ) {
        Ok(value) => value,
        Err(err) => return err,
    };
    let selector_name = match require_string_arg(
        ctx,
        argc,
        argv,
        1,
        "ObjC.methodImp(className, selectorName[, isClassMethod]) requires 2 string arguments",
    ) {
        Ok(value) => value,
        Err(err) => return err,
    };
    let is_class_method = if argc >= 3 {
        JSValue(*argv.add(2)).to_bool().unwrap_or(false)
    } else {
        false
    };

    match ObjcApi::new().method_imp(&class_name, &selector_name, is_class_method) {
        Ok(Some(address)) => create_native_pointer(ctx, address as u64).raw(),
        Ok(None) | Err(CommonError::Unsupported(_)) => JSValue::null().raw(),
        Err(CommonError::InvalidArgument(message)) => js_throw_type_error(ctx, &message),
        Err(err) => js_throw_internal_error(ctx, &err.to_string()),
    }
}

unsafe extern "C" fn js_objc_class_image(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let class_name = match require_string_arg(
        ctx,
        argc,
        argv,
        0,
        "ObjC.classImage(className) requires 1 string argument",
    ) {
        Ok(value) => value,
        Err(err) => return err,
    };

    match ObjcApi::new().class_image(&class_name) {
        Ok(Some(path)) => JSValue::string(ctx, &path).raw(),
        Ok(None) | Err(CommonError::Unsupported(_)) => JSValue::null().raw(),
        Err(CommonError::InvalidArgument(message)) => js_throw_type_error(ctx, &message),
        Err(err) => js_throw_internal_error(ctx, &err.to_string()),
    }
}

unsafe extern "C" fn js_objc_method_image(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let class_name = match require_string_arg(
        ctx,
        argc,
        argv,
        0,
        "ObjC.methodImage(className, selectorName[, isClassMethod]) requires 2 string arguments",
    ) {
        Ok(value) => value,
        Err(err) => return err,
    };
    let selector_name = match require_string_arg(
        ctx,
        argc,
        argv,
        1,
        "ObjC.methodImage(className, selectorName[, isClassMethod]) requires 2 string arguments",
    ) {
        Ok(value) => value,
        Err(err) => return err,
    };
    let is_class_method = if argc >= 3 {
        JSValue(*argv.add(2)).to_bool().unwrap_or(false)
    } else {
        false
    };

    match ObjcApi::new().method_image(&class_name, &selector_name, is_class_method) {
        Ok(Some(path)) => JSValue::string(ctx, &path).raw(),
        Ok(None) | Err(CommonError::Unsupported(_)) => JSValue::null().raw(),
        Err(CommonError::InvalidArgument(message)) => js_throw_type_error(ctx, &message),
        Err(err) => js_throw_internal_error(ctx, &err.to_string()),
    }
}

unsafe fn objc_method_to_js(ctx: *mut ffi::JSContext, method: &ObjcMethodInfo) -> ffi::JSValue {
    let object = JSValue(ffi::JS_NewObject(ctx));
    object.set_property(ctx, "className", JSValue::string(ctx, &method.class_name));
    object.set_property(ctx, "selector", JSValue::string(ctx, &method.selector_name));
    object.set_property(ctx, "imp", create_native_pointer(ctx, method.imp as u64));
    object.set_property(ctx, "isClassMethod", JSValue::bool(method.is_class_method));
    object.raw()
}

unsafe extern "C" fn js_objc_methods(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let class_name = match require_string_arg(
        ctx,
        argc,
        argv,
        0,
        "ObjC.methods(className[, isClassMethod]) requires 1 string argument",
    ) {
        Ok(value) => value,
        Err(err) => return err,
    };
    let is_class_method = if argc >= 2 {
        JSValue(*argv.add(1)).to_bool().unwrap_or(false)
    } else {
        false
    };

    let methods = match ObjcApi::new().enumerate_methods(&class_name, is_class_method) {
        Ok(methods) => methods,
        Err(CommonError::Unsupported(_)) => return ffi::JS_NewArray(ctx),
        Err(CommonError::InvalidArgument(message)) => return js_throw_type_error(ctx, &message),
        Err(err) => return js_throw_internal_error(ctx, &err.to_string()),
    };

    let array = ffi::JS_NewArray(ctx);
    for (index, method) in methods.iter().enumerate() {
        ffi::JS_SetPropertyUint32(ctx, array, index as u32, objc_method_to_js(ctx, method));
    }
    array
}

unsafe extern "C" fn js_objc_find_methods(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let class_name = match require_string_arg(
        ctx,
        argc,
        argv,
        0,
        "ObjC.findMethods(className, query[, isClassMethod]) requires 2 string arguments",
    ) {
        Ok(value) => value,
        Err(err) => return err,
    };
    let query = match require_string_arg(
        ctx,
        argc,
        argv,
        1,
        "ObjC.findMethods(className, query[, isClassMethod]) requires 2 string arguments",
    ) {
        Ok(value) => value,
        Err(err) => return err,
    };
    let is_class_method = if argc >= 3 {
        JSValue(*argv.add(2)).to_bool().unwrap_or(false)
    } else {
        false
    };

    let methods = match ObjcApi::new().find_methods(&class_name, &query, is_class_method) {
        Ok(methods) => methods,
        Err(CommonError::Unsupported(_)) => return ffi::JS_NewArray(ctx),
        Err(CommonError::InvalidArgument(message)) => return js_throw_type_error(ctx, &message),
        Err(err) => return js_throw_internal_error(ctx, &err.to_string()),
    };

    let array = ffi::JS_NewArray(ctx);
    for (index, method) in methods.iter().enumerate() {
        ffi::JS_SetPropertyUint32(ctx, array, index as u32, objc_method_to_js(ctx, method));
    }
    array
}

unsafe extern "C" fn js_objc_find_method_owners(
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
        "ObjC.findMethodOwners(query[, isClassMethod]) requires 1 string argument",
    ) {
        Ok(value) => value,
        Err(err) => return err,
    };
    let is_class_method = if argc >= 2 {
        JSValue(*argv.add(1)).to_bool().unwrap_or(false)
    } else {
        false
    };

    let methods = match ObjcApi::new().find_method_owners(&query, is_class_method) {
        Ok(methods) => methods,
        Err(CommonError::Unsupported(_)) => return ffi::JS_NewArray(ctx),
        Err(CommonError::InvalidArgument(message)) => return js_throw_type_error(ctx, &message),
        Err(err) => return js_throw_internal_error(ctx, &err.to_string()),
    };

    let array = ffi::JS_NewArray(ctx);
    for (index, method) in methods.iter().enumerate() {
        ffi::JS_SetPropertyUint32(ctx, array, index as u32, objc_method_to_js(ctx, method));
    }
    array
}

unsafe extern "C" fn js_objc_selector_name(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 1 {
        return js_throw_type_error(ctx, "ObjC.selectorName(selector) requires 1 selector argument");
    }

    let selector = match pointer_arg_to_u64(
        ctx,
        JSValue(*argv),
        "ObjC.selectorName(selector) expected a pointer-like selector argument",
    ) {
        Ok(value) => value,
        Err(err) => return err,
    };

    match ObjcApi::new().selector_name(selector as usize) {
        Ok(Some(name)) => JSValue::string(ctx, &name).raw(),
        Ok(None) | Err(CommonError::Unsupported(_)) => JSValue::null().raw(),
        Err(CommonError::InvalidArgument(message)) => js_throw_type_error(ctx, &message),
        Err(err) => js_throw_internal_error(ctx, &err.to_string()),
    }
}

unsafe extern "C" fn js_objc_object_class_name(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 1 {
        return js_throw_type_error(ctx, "ObjC.objectClassName(object) requires 1 object argument");
    }

    let object = match pointer_arg_to_u64(
        ctx,
        JSValue(*argv),
        "ObjC.objectClassName(object) expected a pointer-like object argument",
    ) {
        Ok(value) => value,
        Err(err) => return err,
    };

    match ObjcApi::new().object_class_name(object as usize) {
        Ok(Some(name)) => JSValue::string(ctx, &name).raw(),
        Ok(None) | Err(CommonError::Unsupported(_)) => JSValue::null().raw(),
        Err(CommonError::InvalidArgument(message)) => js_throw_type_error(ctx, &message),
        Err(err) => js_throw_internal_error(ctx, &err.to_string()),
    }
}

pub(crate) fn register_objc_api(ctx: &JSContext) {
    let global = ctx.global_object();
    let objc = ctx.new_object();
    let api = ObjcApi::new();

    objc.set_property(ctx.as_ptr(), "available", JSValue::bool(api.is_available()));

    unsafe {
        let ctx_ptr = ctx.as_ptr();
        add_cfunction_to_object(ctx_ptr, objc.raw(), "classes", js_objc_classes, 0);
        add_cfunction_to_object(ctx_ptr, objc.raw(), "findClasses", js_objc_find_classes, 1);
        add_cfunction_to_object(ctx_ptr, objc.raw(), "classExists", js_objc_class_exists, 1);
        add_cfunction_to_object(ctx_ptr, objc.raw(), "selector", js_objc_selector, 1);
        add_cfunction_to_object(ctx_ptr, objc.raw(), "methodImp", js_objc_method_imp, 3);
        add_cfunction_to_object(ctx_ptr, objc.raw(), "classImage", js_objc_class_image, 1);
        add_cfunction_to_object(ctx_ptr, objc.raw(), "methodImage", js_objc_method_image, 3);
        add_cfunction_to_object(ctx_ptr, objc.raw(), "methods", js_objc_methods, 2);
        add_cfunction_to_object(ctx_ptr, objc.raw(), "findMethods", js_objc_find_methods, 3);
        add_cfunction_to_object(ctx_ptr, objc.raw(), "findMethodOwners", js_objc_find_method_owners, 2);
        add_cfunction_to_object(ctx_ptr, objc.raw(), "selectorName", js_objc_selector_name, 1);
        add_cfunction_to_object(ctx_ptr, objc.raw(), "objectClassName", js_objc_object_class_name, 1);
    }

    global.set_property(ctx.as_ptr(), "ObjC", objc);
    global.free(ctx.as_ptr());
}
