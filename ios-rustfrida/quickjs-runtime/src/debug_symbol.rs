use crate::context::JSContext;
use crate::ffi;
use crate::ptr::create_native_pointer;
use crate::util::{add_cfunction_to_object, js_throw_internal_error, js_throw_type_error};
use crate::value::JSValue;
use common::Error as CommonError;
use native_api::{find_symbol_by_address, SymbolInfo};

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

unsafe fn symbol_to_js(ctx: *mut ffi::JSContext, symbol: &SymbolInfo) -> ffi::JSValue {
    let object = JSValue(ffi::JS_NewObject(ctx));
    object.set_property(ctx, "moduleName", JSValue::string(ctx, &symbol.module_name));
    object.set_property(ctx, "moduleBase", create_native_pointer(ctx, symbol.module_base as u64));
    object.set_property(ctx, "offset", JSValue(ffi::JS_NewBigUint64(ctx, symbol.offset as u64)));

    match &symbol.symbol_name {
        Some(symbol_name) => object.set_property(ctx, "name", JSValue::string(ctx, symbol_name)),
        None => object.set_property(ctx, "name", JSValue::null()),
    };

    match symbol.symbol_address {
        Some(symbol_address) => object.set_property(ctx, "address", create_native_pointer(ctx, symbol_address as u64)),
        None => object.set_property(ctx, "address", JSValue::null()),
    };

    object.raw()
}

unsafe extern "C" fn js_debug_symbol_from_address(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 1 {
        return js_throw_type_error(ctx, "DebugSymbol.fromAddress(address) requires 1 address argument");
    }

    let address = match pointer_arg_to_u64(
        ctx,
        JSValue(*argv),
        "DebugSymbol.fromAddress(address) expected a pointer-like address argument",
    ) {
        Ok(value) => value,
        Err(err) => return err,
    };

    match find_symbol_by_address(address as usize) {
        Ok(Some(symbol)) => symbol_to_js(ctx, &symbol),
        Ok(None) | Err(CommonError::Unsupported(_)) => JSValue::null().raw(),
        Err(err) => js_throw_internal_error(ctx, &err.to_string()),
    }
}

pub(crate) fn register_debug_symbol_api(ctx: &JSContext) {
    let global = ctx.global_object();
    let debug_symbol = ctx.new_object();

    unsafe {
        add_cfunction_to_object(
            ctx.as_ptr(),
            debug_symbol.raw(),
            "fromAddress",
            js_debug_symbol_from_address,
            1,
        );
    }

    global.set_property(ctx.as_ptr(), "DebugSymbol", debug_symbol);
    global.free(ctx.as_ptr());
}
