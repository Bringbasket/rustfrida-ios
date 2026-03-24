use crate::context::JSContext;
use crate::ffi;
use crate::util::{add_cfunction_to_object, js_throw_type_error};
use crate::value::JSValue;
use std::sync::atomic::{AtomicU32, Ordering};

static NATIVE_POINTER_CLASS_ID: AtomicU32 = AtomicU32::new(0);
const NATIVE_POINTER_CLASS_NAME: &[u8] = b"NativePointer\0";

unsafe extern "C" fn native_pointer_finalizer(_rt: *mut ffi::JSRuntime, val: ffi::JSValue) {
    let class_id = NATIVE_POINTER_CLASS_ID.load(Ordering::Relaxed);
    if class_id == 0 {
        return;
    }

    let opaque = ffi::JS_GetOpaque(val, class_id);
    if !opaque.is_null() {
        drop(Box::from_raw(opaque as *mut u64));
    }
}

fn get_or_init_class_id(ctx: *mut ffi::JSContext) -> u32 {
    let mut class_id = NATIVE_POINTER_CLASS_ID.load(Ordering::Relaxed);

    if class_id == 0 {
        let mut new_id = 0u32;
        unsafe {
            ffi::JS_NewClassID(&mut new_id);
        }
        match NATIVE_POINTER_CLASS_ID.compare_exchange(0, new_id, Ordering::SeqCst, Ordering::Relaxed) {
            Ok(_) => class_id = new_id,
            Err(existing) => class_id = existing,
        }
    }

    unsafe {
        let rt = ffi::JS_GetRuntime(ctx);
        let class_def = ffi::JSClassDef {
            class_name: NATIVE_POINTER_CLASS_NAME.as_ptr() as *const _,
            finalizer: Some(native_pointer_finalizer),
            gc_mark: None,
            call: None,
            exotic: std::ptr::null_mut(),
        };
        let _ = ffi::JS_NewClass(rt, class_id, &class_def);
    }

    class_id
}

pub(crate) fn create_native_pointer(ctx: *mut ffi::JSContext, addr: u64) -> JSValue {
    let class_id = get_or_init_class_id(ctx);

    unsafe {
        let obj = ffi::JS_NewObjectClass(ctx, class_id as i32);
        if ffi::qjs_is_exception(obj) != 0 {
            return JSValue(obj);
        }

        let addr_ptr = Box::into_raw(Box::new(addr));
        ffi::JS_SetOpaque(obj, addr_ptr as *mut _);
        JSValue(obj)
    }
}

pub(crate) fn get_native_pointer_addr(val: JSValue) -> Option<u64> {
    let class_id = NATIVE_POINTER_CLASS_ID.load(Ordering::Relaxed);
    if class_id == 0 {
        return None;
    }

    unsafe {
        let opaque = ffi::JS_GetOpaque(val.raw(), class_id);
        if opaque.is_null() {
            return None;
        }
        Some(*(opaque as *const u64))
    }
}

fn format_native_pointer(addr: u64) -> String {
    format!("0x{addr:x}")
}

unsafe fn parse_offset(ctx: *mut ffi::JSContext, arg: JSValue) -> Result<i64, ffi::JSValue> {
    if arg.is_int() || arg.is_float() || ffi::qjs_is_big_int(ctx, arg.raw()) != 0 {
        return arg
            .to_i64(ctx)
            .ok_or_else(|| js_throw_type_error(ctx, "failed to convert numeric offset"));
    }

    if arg.is_string() {
        let Some(value) = arg.to_string(ctx) else {
            return Err(js_throw_type_error(ctx, "invalid string argument"));
        };
        let trimmed = value.trim();
        if !trimmed.starts_with("0x") && !trimmed.starts_with("0X") {
            return Err(js_throw_type_error(ctx, "string offset must be hex (0x...)"));
        }

        return u64::from_str_radix(&trimmed[2..], 16)
            .map(|value| value as i64)
            .map_err(|_| js_throw_type_error(ctx, "invalid hex string"));
    }

    if let Some(ptr_addr) = get_native_pointer_addr(arg) {
        return Ok(ptr_addr as i64);
    }

    Err(js_throw_type_error(
        ctx,
        "offset must be a number, hex string, or NativePointer",
    ))
}

unsafe extern "C" fn js_ptr(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 1 {
        return js_throw_type_error(ctx, "ptr() requires 1 argument");
    }

    let arg = JSValue(*argv);
    let addr = if arg.is_string() {
        let Some(value) = arg.to_string(ctx) else {
            return js_throw_type_error(ctx, "ptr() argument must be a string, number, BigInt, or NativePointer");
        };
        let trimmed = value.trim().trim_start_matches("0x").trim_start_matches("0X");
        match u64::from_str_radix(trimmed, 16) {
            Ok(addr) => addr,
            Err(_) => return js_throw_type_error(ctx, "ptr() expected a hex string"),
        }
    } else if arg.is_int() || arg.is_float() || ffi::qjs_is_big_int(ctx, arg.raw()) != 0 {
        let mut value = 0u64;
        if ffi::qjs_value_to_u64(ctx, &mut value, arg.raw()) != 0 {
            return js_throw_type_error(ctx, "ptr() failed to convert numeric value");
        }
        value
    } else if let Some(addr) = get_native_pointer_addr(arg) {
        addr
    } else {
        return js_throw_type_error(ctx, "ptr() argument must be a string, number, BigInt, or NativePointer");
    };

    create_native_pointer(ctx, addr).raw()
}

unsafe extern "C" fn native_pointer_add(
    ctx: *mut ffi::JSContext,
    this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let Some(addr) = get_native_pointer_addr(JSValue(this)) else {
        return js_throw_type_error(ctx, "Not a NativePointer");
    };
    if argc < 1 {
        return js_throw_type_error(ctx, "add() requires 1 argument");
    }

    let offset = match parse_offset(ctx, JSValue(*argv)) {
        Ok(value) => value,
        Err(err) => return err,
    };

    create_native_pointer(ctx, (addr as i64 + offset) as u64).raw()
}

unsafe extern "C" fn native_pointer_sub(
    ctx: *mut ffi::JSContext,
    this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let Some(addr) = get_native_pointer_addr(JSValue(this)) else {
        return js_throw_type_error(ctx, "Not a NativePointer");
    };
    if argc < 1 {
        return js_throw_type_error(ctx, "sub() requires 1 argument");
    }

    let offset = match parse_offset(ctx, JSValue(*argv)) {
        Ok(value) => value,
        Err(err) => return err,
    };

    create_native_pointer(ctx, (addr as i64 - offset) as u64).raw()
}

unsafe extern "C" fn native_pointer_to_string(
    ctx: *mut ffi::JSContext,
    this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let Some(addr) = get_native_pointer_addr(JSValue(this)) else {
        return js_throw_type_error(ctx, "Not a NativePointer");
    };

    JSValue::string(ctx, &format_native_pointer(addr)).raw()
}

unsafe extern "C" fn native_pointer_to_number(
    ctx: *mut ffi::JSContext,
    this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let Some(addr) = get_native_pointer_addr(JSValue(this)) else {
        return js_throw_type_error(ctx, "Not a NativePointer");
    };

    ffi::JS_NewBigUint64(ctx, addr)
}

pub(crate) fn register_ptr(ctx: &JSContext) {
    let class_id = get_or_init_class_id(ctx.as_ptr());
    let global = ctx.global_object();

    unsafe {
        let ctx_ptr = ctx.as_ptr();
        add_cfunction_to_object(ctx_ptr, global.raw(), "ptr", js_ptr, 1);

        let proto = ffi::JS_NewObject(ctx_ptr);
        add_cfunction_to_object(ctx_ptr, proto, "add", native_pointer_add, 1);
        add_cfunction_to_object(ctx_ptr, proto, "sub", native_pointer_sub, 1);
        add_cfunction_to_object(ctx_ptr, proto, "toString", native_pointer_to_string, 0);
        add_cfunction_to_object(ctx_ptr, proto, "toJSON", native_pointer_to_string, 0);
        add_cfunction_to_object(ctx_ptr, proto, "toNumber", native_pointer_to_number, 0);
        add_cfunction_to_object(ctx_ptr, proto, "toInt", native_pointer_to_number, 0);
        ffi::JS_SetClassProto(ctx_ptr, class_id, proto);
    }

    global.free(ctx.as_ptr());
}

#[cfg(test)]
mod tests {
    use super::format_native_pointer;

    #[test]
    fn formats_native_pointer_as_hex_string() {
        assert_eq!(format_native_pointer(0x1234_abcd), "0x1234abcd");
    }
}
