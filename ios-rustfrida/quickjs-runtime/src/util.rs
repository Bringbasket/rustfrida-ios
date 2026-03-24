use crate::ffi;
use crate::value::JSValue;
use std::ffi::CString;

pub(crate) type JSCFn = unsafe extern "C" fn(
    ctx: *mut ffi::JSContext,
    this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue;

pub(crate) unsafe fn add_cfunction_to_object(
    ctx: *mut ffi::JSContext,
    obj: ffi::JSValue,
    name: &str,
    func: JSCFn,
    argc: i32,
) {
    let cname = CString::new(name).unwrap();
    let func_val = ffi::qjs_new_cfunction(ctx, Some(func), cname.as_ptr(), argc);
    let atom = ffi::JS_NewAtom(ctx, cname.as_ptr());
    ffi::qjs_set_property(ctx, obj, atom, func_val);
    ffi::JS_FreeAtom(ctx, atom);
}

fn make_cstring(message: &str) -> CString {
    CString::new(message).unwrap_or_else(|_| CString::new(message.replace('\0', " ")).expect("sanitized CString"))
}

pub(crate) fn js_throw_internal_error(ctx: *mut ffi::JSContext, message: &str) -> ffi::JSValue {
    let message = make_cstring(message);
    unsafe { ffi::JS_ThrowInternalError(ctx, message.as_ptr()) }
}

pub(crate) fn js_throw_type_error(ctx: *mut ffi::JSContext, message: &str) -> ffi::JSValue {
    let message = make_cstring(message);
    unsafe { ffi::JS_ThrowTypeError(ctx, message.as_ptr()) }
}

pub(crate) fn js_throw_range_error(ctx: *mut ffi::JSContext, message: &str) -> ffi::JSValue {
    let message = make_cstring(message);
    unsafe { ffi::JS_ThrowRangeError(ctx, message.as_ptr()) }
}

const JS_MAX_SAFE_INTEGER: u64 = (1u64 << 53) - 1;

#[cfg_attr(not(quickjs_hook_engine), allow(dead_code))]
pub(crate) unsafe fn set_js_u64_property(ctx: *mut ffi::JSContext, obj: ffi::JSValue, name: &str, value: u64) {
    let cname = CString::new(name).unwrap();
    let atom = ffi::JS_NewAtom(ctx, cname.as_ptr());
    let val = ffi::JS_NewBigUint64(ctx, value);
    ffi::qjs_set_property(ctx, obj, atom, val);
    ffi::JS_FreeAtom(ctx, atom);
}

#[cfg_attr(not(quickjs_hook_engine), allow(dead_code))]
pub(crate) unsafe fn get_js_u64_property(ctx: *mut ffi::JSContext, obj: ffi::JSValue, name: &str) -> u64 {
    let prop = JSValue(obj).get_property(ctx, name);
    let value = prop.to_u64(ctx).unwrap_or(0);
    prop.free(ctx);
    value
}

#[cfg_attr(not(quickjs_hook_engine), allow(dead_code))]
pub(crate) unsafe fn set_js_cfunction_property(
    ctx: *mut ffi::JSContext,
    obj: ffi::JSValue,
    name: &str,
    func: JSCFn,
    argc: i32,
) {
    let cname = CString::new(name).unwrap();
    let func_val = ffi::qjs_new_cfunction(ctx, Some(func), cname.as_ptr(), argc);
    let atom = ffi::JS_NewAtom(ctx, cname.as_ptr());
    ffi::qjs_set_property(ctx, obj, atom, func_val);
    ffi::JS_FreeAtom(ctx, atom);
}

pub(crate) unsafe fn require_string_arg(
    ctx: *mut ffi::JSContext,
    argc: i32,
    argv: *mut ffi::JSValue,
    index: usize,
    usage: &str,
) -> Result<String, ffi::JSValue> {
    if argc <= index as i32 {
        return Err(js_throw_type_error(ctx, usage));
    }

    let value = crate::value::JSValue(*argv.add(index));
    value.to_string(ctx).ok_or_else(|| js_throw_type_error(ctx, usage))
}

pub(crate) unsafe fn js_i64_to_js_number_or_bigint(ctx: *mut ffi::JSContext, value: i64) -> ffi::JSValue {
    if value.unsigned_abs() <= JS_MAX_SAFE_INTEGER {
        ffi::qjs_new_int64(ctx, value)
    } else {
        ffi::JS_NewBigInt64(ctx, value)
    }
}

#[cfg_attr(not(quickjs_hook_engine), allow(dead_code))]
pub(crate) unsafe fn js_u64_to_js_number_or_bigint(ctx: *mut ffi::JSContext, value: u64) -> ffi::JSValue {
    if value <= JS_MAX_SAFE_INTEGER {
        ffi::qjs_new_int64(ctx, value as i64)
    } else {
        ffi::JS_NewBigUint64(ctx, value)
    }
}
