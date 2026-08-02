use crate::console::output_message;
use crate::context::JSContext;
use crate::ffi;
#[cfg(quickjs_hook_engine)]
use crate::memory::is_executable_address;
#[cfg(quickjs_hook_engine)]
use crate::ptr::create_native_pointer;
use crate::ptr::get_native_pointer_addr;
use crate::util::{
    add_cfunction_to_object, js_i64_to_js_number_or_bigint, js_throw_internal_error, js_throw_range_error,
    js_throw_type_error,
};
use crate::value::JSValue;
use native_api::{find_image_by_address, normalize_code_pointer};

#[cfg(quickjs_hook_engine)]
use crate::util::{get_js_u64_property, js_u64_to_js_number_or_bigint, set_js_cfunction_property, set_js_u64_property};
#[cfg(quickjs_hook_engine)]
use native_api::{detect_hook_environment, resolve_hook_strategy};
#[cfg(any(quickjs_hook_engine, test))]
use std::cell::RefCell;
#[cfg(any(quickjs_hook_engine, test))]
use std::collections::HashMap;
#[cfg(quickjs_hook_engine)]
use std::collections::HashSet;
#[cfg(quickjs_hook_engine)]
use std::ffi::CStr;
#[cfg(quickjs_hook_engine)]
use std::os::raw::c_void;
#[cfg(any(quickjs_hook_engine, test))]
use std::sync::atomic::{AtomicU64, Ordering};
#[cfg(quickjs_hook_engine)]
use std::sync::{Condvar, MutexGuard, Once};
#[cfg(any(quickjs_hook_engine, test))]
use std::sync::{Mutex, OnceLock};
#[cfg(quickjs_hook_engine)]
use std::time::{Duration, Instant};

const MAX_CALL_NATIVE_ARGS: usize = 6;
const MIN_VALID_CALL_TARGET: u64 = 0x1_0000;
const HOOK_NORMAL: i32 = 0;
const HOOK_WXSHADOW: i32 = 1;
const HOOK_RECOMP: i32 = 2;

#[cfg(any(quickjs_hook_engine, test))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HookStealthArg {
    Normal,
    WxShadow,
    Recomp,
    Unknown,
}

#[cfg(any(quickjs_hook_engine, test))]
fn classify_hook_stealth_arg(mode: i64) -> HookStealthArg {
    match i32::try_from(mode).ok() {
        Some(HOOK_NORMAL) => HookStealthArg::Normal,
        Some(HOOK_WXSHADOW) => HookStealthArg::WxShadow,
        Some(HOOK_RECOMP) => HookStealthArg::Recomp,
        _ => HookStealthArg::Unknown,
    }
}

#[cfg(quickjs_hook_engine)]
const INTERCEPTOR_ENTER_HELPER: &str = "__iosRustFridaInterceptorEnter";
#[cfg(quickjs_hook_engine)]
const INTERCEPTOR_LEAVE_HELPER: &str = "__iosRustFridaInterceptorLeave";
const INTERCEPTOR_BOOTSTRAP: &str = r#"
(function () {
    "use strict";

    function toUInt64(value) {
        var converted;
        if (typeof value === "bigint") {
            converted = value;
        } else if (typeof value === "number") {
            if (!Number.isFinite(value)) {
                throw new TypeError("expected a finite pointer-like value");
            }
            converted = BigInt(Math.trunc(value));
        } else if (typeof value === "boolean") {
            converted = value ? 1n : 0n;
        } else if (typeof value === "string") {
            converted = BigInt(value);
        } else if (value !== null && typeof value === "object" && typeof value.toString === "function") {
            converted = BigInt(value.toString());
        } else {
            throw new TypeError("expected a pointer-like value");
        }
        return BigInt.asUintN(64, converted);
    }

    function argumentIndex(property) {
        if (typeof property !== "string" || !/^(?:0|[1-7])$/.test(property)) {
            return -1;
        }
        return Number(property);
    }

    function makeArgs(invocation) {
        return new Proxy(Object.create(null), {
            get: function (_target, property) {
                if (property === "length") {
                    return 8;
                }
                var index = argumentIndex(property);
                if (index < 0) {
                    return undefined;
                }
                return ptr(invocation["x" + index]);
            },
            set: function (_target, property, value) {
                var index = argumentIndex(property);
                if (index < 0) {
                    return false;
                }
                invocation["x" + index] = toUInt64(value);
                return true;
            },
            has: function (_target, property) {
                return property === "length" || argumentIndex(property) >= 0;
            }
        });
    }

    function makeRetval(invocation) {
        function currentValue() {
            return toUInt64(invocation.x0);
        }

        var retval = Object.create(null);
        Object.defineProperties(retval, {
            replace: {
                value: function (value) {
                    invocation.x0 = toUInt64(value);
                }
            },
            toInt32: {
                value: function () {
                    return Number(BigInt.asIntN(32, currentValue()));
                }
            },
            toUInt32: {
                value: function () {
                    return Number(BigInt.asUintN(32, currentValue()));
                }
            },
            toString: {
                value: function () {
                    return "0x" + currentValue().toString(16);
                }
            }
        });
        return retval;
    }

    globalThis.__iosRustFridaInterceptorEnter = function (userFunction, invocation) {
        return userFunction.call(invocation, makeArgs(invocation));
    };

    globalThis.__iosRustFridaInterceptorLeave = function (userFunction, invocation) {
        return userFunction.call(invocation, makeRetval(invocation));
    };
})();
"#;

#[cfg(quickjs_hook_engine)]
const EXECUTABLE_POOL_SIZE: usize = 128 * 1024;
#[cfg(quickjs_hook_engine)]
const CALLBACK_LOCK_WAIT_SPIN_LIMIT: usize = 32;
#[cfg(quickjs_hook_engine)]
const CALLBACK_LOCK_WAIT_TIMEOUT: Duration = Duration::from_millis(3);

#[cfg(quickjs_hook_engine)]
const HOOK_OK: i32 = 0;
#[cfg(quickjs_hook_engine)]
const HOOK_ERROR_NOT_INITIALIZED: i32 = -1;
#[cfg(quickjs_hook_engine)]
const HOOK_ERROR_INVALID_PARAM: i32 = -2;
#[cfg(quickjs_hook_engine)]
const HOOK_ERROR_ALREADY_HOOKED: i32 = -3;
#[cfg(quickjs_hook_engine)]
const HOOK_ERROR_ALLOC_FAILED: i32 = -4;
#[cfg(quickjs_hook_engine)]
const HOOK_ERROR_MPROTECT_FAILED: i32 = -5;
#[cfg(quickjs_hook_engine)]
const HOOK_ERROR_NOT_FOUND: i32 = -6;
#[cfg(quickjs_hook_engine)]
const HOOK_ERROR_BUFFER_TOO_SMALL: i32 = -7;
#[cfg(quickjs_hook_engine)]
const HOOK_ERROR_WXSHADOW_FAILED: i32 = -8;

#[cfg(quickjs_hook_engine)]
static JS_RUNTIME_LOCK: Mutex<()> = Mutex::new(());
#[cfg(quickjs_hook_engine)]
static JS_RUNTIME_OWNER_THREAD: AtomicU64 = AtomicU64::new(0);

#[cfg(quickjs_hook_engine)]
#[derive(Clone, Copy)]
struct HookData {
    target: u64,
    ctx: usize,
    mode: HookMode,
    native_callback_data: usize,
    dispatch_data: usize,
}

#[cfg(quickjs_hook_engine)]
struct HookDispatchData {
    target: u64,
    ctx: usize,
    mode: HookMode,
    trampoline: AtomicU64,
}

#[cfg(quickjs_hook_engine)]
#[derive(Clone, Copy)]
struct NativeHookFrame {
    ctx_ptr: usize,
    trampoline: u64,
    orig_called: bool,
}

#[cfg(any(quickjs_hook_engine, test))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct InvocationFrame {
    ctx: usize,
    target: u64,
    hook_ctx: usize,
    value_id: u64,
}

#[cfg(any(quickjs_hook_engine, test))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct InvocationValue {
    ctx: usize,
    target: u64,
    value_bytes: [u8; 16],
}

#[cfg(any(quickjs_hook_engine, test))]
thread_local! {
    static INVOCATION_STACK: RefCell<Vec<InvocationFrame>> = const { RefCell::new(Vec::new()) };
    static DEFERRED_INVOCATIONS: RefCell<Vec<InvocationFrame>> = const { RefCell::new(Vec::new()) };
}

#[cfg(quickjs_hook_engine)]
thread_local! {
    static RUNTIME_CONTEXT_STACK: RefCell<Vec<usize>> = const { RefCell::new(Vec::new()) };
    static CALLBACK_DEPTH: RefCell<usize> = const { RefCell::new(0) };
}

#[cfg(quickjs_hook_engine)]
#[derive(Clone, Copy)]
struct HookEnginePool {
    base: *mut c_void,
    size: usize,
}

#[cfg(quickjs_hook_engine)]
unsafe impl Send for HookEnginePool {}

#[cfg(quickjs_hook_engine)]
#[derive(Clone, Copy)]
enum HookMode {
    Replace {
        callback_bytes: [u8; 16],
        trampoline: u64,
    },
    Attach {
        on_enter_bytes: Option<[u8; 16]>,
        on_leave_bytes: Option<[u8; 16]>,
    },
    NativeReplace,
    NativeAttach,
}

#[cfg(quickjs_hook_engine)]
type NativeHookCallback = unsafe extern "C" fn(*mut ffi::hook::HookContext, *mut c_void);

#[cfg(quickjs_hook_engine)]
#[repr(C)]
struct NativeReplaceCallbacks {
    callback: NativeHookCallback,
    user_data: *mut c_void,
}

#[cfg(quickjs_hook_engine)]
#[repr(C)]
struct NativeAttachCallbacks {
    on_enter: Option<NativeHookCallback>,
    on_leave: Option<NativeHookCallback>,
    user_data: *mut c_void,
}

#[cfg(quickjs_hook_engine)]
unsafe fn parse_hook_stealth_arg(
    ctx: *mut ffi::JSContext,
    value: JSValue,
    api_name: &str,
) -> Result<bool, ffi::JSValue> {
    if let Some(mode) = value.to_i64(ctx) {
        return match classify_hook_stealth_arg(mode) {
            HookStealthArg::Normal => Ok(false),
            HookStealthArg::WxShadow => Ok(true),
            HookStealthArg::Recomp => Err(js_throw_internal_error(
                ctx,
                &format!("{api_name} Hook.RECOMP is Android-only; iOS currently uses ARM64 hook engine without recomp page mode"),
            )),
            HookStealthArg::Unknown => Ok(false),
        };
    }

    Ok(value.to_bool().unwrap_or(false))
}

#[cfg(quickjs_hook_engine)]
enum RuntimeJsGuardInner {
    Locked { _guard: MutexGuard<'static, ()> },
    Reentrant,
}

#[cfg(quickjs_hook_engine)]
impl Drop for RuntimeJsGuardInner {
    fn drop(&mut self) {
        if matches!(self, Self::Locked { .. }) {
            clear_runtime_owner_current_thread();
        }
    }
}

#[cfg(quickjs_hook_engine)]
pub(crate) struct RuntimeJsGuard {
    _inner: RuntimeJsGuardInner,
    ctx: usize,
}

#[cfg(quickjs_hook_engine)]
impl Drop for RuntimeJsGuard {
    fn drop(&mut self) {
        RUNTIME_CONTEXT_STACK.with(|stack| {
            let popped = stack.borrow_mut().pop();
            debug_assert_eq!(popped, Some(self.ctx));
        });
    }
}

#[cfg(not(quickjs_hook_engine))]
pub(crate) struct RuntimeJsGuard;

#[cfg(quickjs_hook_engine)]
pub(crate) fn enter_runtime_js(ctx: *mut ffi::JSContext) -> RuntimeJsGuard {
    if runtime_owner_is_current_thread() {
        unsafe {
            ffi::qjs_update_stack_top(ctx);
        }
        RUNTIME_CONTEXT_STACK.with(|stack| stack.borrow_mut().push(ctx as usize));
        return RuntimeJsGuard {
            _inner: RuntimeJsGuardInner::Reentrant,
            ctx: ctx as usize,
        };
    }

    let guard = JS_RUNTIME_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    mark_runtime_owner_current_thread();
    unsafe {
        ffi::qjs_update_stack_top(ctx);
    }
    RUNTIME_CONTEXT_STACK.with(|stack| stack.borrow_mut().push(ctx as usize));

    RuntimeJsGuard {
        _inner: RuntimeJsGuardInner::Locked { _guard: guard },
        ctx: ctx as usize,
    }
}

#[cfg(not(quickjs_hook_engine))]
pub(crate) fn enter_runtime_js(_ctx: *mut ffi::JSContext) -> RuntimeJsGuard {
    RuntimeJsGuard
}

unsafe extern "C" fn js_call_native(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 1 {
        return js_throw_type_error(ctx, "callNative() requires at least 1 argument");
    }

    let normalized_target = match extract_pointer_address(ctx, JSValue(*argv), "callNative") {
        Ok(target) => target,
        Err(err) => return err,
    };

    if normalized_target < MIN_VALID_CALL_TARGET {
        return js_throw_range_error(ctx, "callNative() address is not mapped");
    }

    match find_image_by_address(normalized_target as usize) {
        Ok(Some(_)) => {}
        Ok(None) => return js_throw_range_error(ctx, "callNative() address is not in a loaded image"),
        Err(err) => return js_throw_internal_error(ctx, &err.to_string()),
    }

    let mut args = [0u64; MAX_CALL_NATIVE_ARGS];
    for index in 0..MAX_CALL_NATIVE_ARGS {
        if (index + 1) < argc as usize {
            args[index] = js_value_to_u64_or_zero(ctx, JSValue(*argv.add(index + 1)));
        }
    }

    let func: unsafe extern "C" fn(u64, u64, u64, u64, u64, u64) -> i64 =
        std::mem::transmute(normalized_target as usize);
    let result = func(args[0], args[1], args[2], args[3], args[4], args[5]);
    js_i64_to_js_number_or_bigint(ctx, result)
}

#[cfg(quickjs_hook_engine)]
unsafe extern "C" fn js_hook(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 2 {
        return js_throw_type_error(ctx, "hook() requires at least 2 arguments");
    }

    let target = match extract_pointer_address(ctx, JSValue(*argv), "hook") {
        Ok(target) => target,
        Err(err) => return err,
    };

    let callback = JSValue(*argv.add(1));
    if !callback.is_function(ctx) {
        return js_throw_type_error(ctx, "hook() second argument must be a function");
    }

    let stealth = if argc >= 3 {
        match parse_hook_stealth_arg(ctx, JSValue(*argv.add(2)), "hook()") {
            Ok(value) => value,
            Err(err) => return err,
        }
    } else {
        false
    };

    if hook_registry()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .contains_key(&target)
    {
        return js_throw_internal_error(ctx, "hook() target is already hooked");
    }

    if let Err(err) = enforce_hook_installation_policy() {
        return js_throw_internal_error(ctx, &err);
    }

    if let Err(err) = initialize_hook_backend() {
        return js_throw_internal_error(ctx, &err);
    }

    let callback_bytes = dup_callback_to_bytes(ctx, callback.raw());
    let dispatch_ptr = Box::into_raw(Box::new(HookDispatchData {
        target,
        ctx: ctx as usize,
        mode: HookMode::Replace {
            callback_bytes,
            trampoline: 0,
        },
        trampoline: AtomicU64::new(0),
    }));
    let trampoline = ffi::hook::hook_replace(
        target as *mut c_void,
        Some(hook_callback_wrapper),
        dispatch_ptr as *mut c_void,
        if stealth { 1 } else { 0 },
    );

    if trampoline.is_null() {
        let dispatch = Box::from_raw(dispatch_ptr);
        free_hook_mode_callbacks(dispatch.ctx, dispatch.mode);
        return js_throw_internal_error(
            ctx,
            "hook_replace failed: could not install hook on this target address",
        );
    }

    (*dispatch_ptr).trampoline.store(trampoline as u64, Ordering::Release);
    let registry_mode = HookMode::Replace {
        callback_bytes,
        trampoline: trampoline as u64,
    };
    let registry_data = HookData {
        target,
        ctx: ctx as usize,
        mode: registry_mode,
        native_callback_data: 0,
        dispatch_data: dispatch_ptr as usize,
    };
    hook_registry()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(target, registry_data);

    JSValue::bool(true).raw()
}

#[cfg(not(quickjs_hook_engine))]
unsafe extern "C" fn js_hook(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    js_throw_internal_error(
        ctx,
        "hook() is currently only available when quickjs-runtime is built for ARM64 with the native hook engine enabled",
    )
}

/// hookNative(target, callbackPtr, userData?, mode?)
///
/// Installs a native HookCallback without entering QuickJS on the hot path.
/// The callback receives the ARM64 register frame and the exact userData value
/// supplied by the caller. The original is not invoked automatically.
#[cfg(quickjs_hook_engine)]
unsafe extern "C" fn js_hook_native(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 2 {
        return js_throw_type_error(
            ctx,
            "hookNative(target, callbackPtr, userData?, mode?) requires target and callback",
        );
    }

    let target = match extract_pointer_address(ctx, JSValue(*argv), "hookNative target") {
        Ok(target) => target,
        Err(err) => return err,
    };
    let callback_address = match extract_pointer_address(ctx, JSValue(*argv.add(1)), "hookNative callback") {
        Ok(callback) => callback,
        Err(err) => return err,
    };
    if callback_address < MIN_VALID_CALL_TARGET || !is_executable_address(callback_address) {
        return js_throw_range_error(ctx, "hookNative callback address is not executable");
    }

    let user_data = if argc >= 3 {
        match extract_native_u64_or_exception(ctx, JSValue(*argv.add(2)), "hookNative userData") {
            Ok(value) => value,
            Err(err) => return err,
        }
    } else {
        0
    };
    let stealth = if argc >= 4 {
        match parse_hook_stealth_arg(ctx, JSValue(*argv.add(3)), "hookNative()") {
            Ok(value) => value,
            Err(err) => return err,
        }
    } else {
        false
    };

    if let Err(err) = enforce_hook_installation_policy() {
        return js_throw_internal_error(ctx, &err);
    }
    if let Err(err) = initialize_hook_backend() {
        return js_throw_internal_error(ctx, &err);
    }

    if let Err(err) = remove_registered_hook_for_native_install(target) {
        return js_throw_internal_error(ctx, &err);
    }

    let callback: NativeHookCallback = std::mem::transmute(callback_address as usize);
    let callback_data = Box::into_raw(Box::new(NativeReplaceCallbacks {
        callback,
        user_data: user_data as *mut c_void,
    })) as usize;
    let trampoline = ffi::hook::hook_replace(
        target as *mut c_void,
        Some(native_hook_replace_wrapper),
        callback_data as *mut c_void,
        if stealth { 1 } else { 0 },
    );
    if trampoline.is_null() {
        drop(Box::from_raw(callback_data as *mut NativeReplaceCallbacks));
        return js_throw_internal_error(ctx, "hookNative: hook_replace failed");
    }

    hook_registry().lock().unwrap_or_else(|e| e.into_inner()).insert(
        target,
        HookData {
            target,
            ctx: ctx as usize,
            mode: HookMode::NativeReplace,
            native_callback_data: callback_data,
            dispatch_data: 0,
        },
    );

    create_native_pointer(ctx, trampoline as u64).raw()
}

#[cfg(not(quickjs_hook_engine))]
unsafe extern "C" fn js_hook_native(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    js_throw_internal_error(
        ctx,
        "hookNative() is currently only available when quickjs-runtime is built for ARM64 with the native hook engine enabled",
    )
}

/// attachNative(target, callbackPtr, userData?, mode?)
/// attachNative(target, { onEnter?, onLeave?, data?, mode? })
#[cfg(quickjs_hook_engine)]
unsafe extern "C" fn js_attach_native(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 2 {
        return js_throw_type_error(
            ctx,
            "attachNative(target, callbackPtr|options, userData?, mode?) requires target and callback",
        );
    }

    let target = match extract_pointer_address(ctx, JSValue(*argv), "attachNative target") {
        Ok(target) => target,
        Err(err) => return err,
    };

    let callback_arg = JSValue(*argv.add(1));
    let on_enter_prop = callback_arg.get_property(ctx, "onEnter");
    let on_leave_prop = callback_arg.get_property(ctx, "onLeave");
    let is_options = callback_arg.is_object() && (!on_enter_prop.is_undefined() || !on_leave_prop.is_undefined());

    let (on_enter_address, on_leave_address, user_data, stealth) = if is_options {
        let data_prop = callback_arg.get_property(ctx, "data");
        let mode_prop = callback_arg.get_property(ctx, "mode");
        let parsed = (|| -> Result<(u64, u64, u64, bool), ffi::JSValue> {
            let on_enter = if on_enter_prop.is_undefined() || on_enter_prop.is_null() {
                0
            } else {
                extract_pointer_address(ctx, on_enter_prop, "attachNative onEnter")?
            };
            let on_leave = if on_leave_prop.is_undefined() || on_leave_prop.is_null() {
                0
            } else {
                extract_pointer_address(ctx, on_leave_prop, "attachNative onLeave")?
            };
            if on_enter == 0 && on_leave == 0 {
                return Err(js_throw_type_error(
                    ctx,
                    "attachNative options must provide onEnter or onLeave",
                ));
            }
            let data = if data_prop.is_undefined() || data_prop.is_null() {
                0
            } else {
                extract_native_u64_or_exception(ctx, data_prop, "attachNative data")?
            };
            let stealth = if mode_prop.is_undefined() || mode_prop.is_null() {
                false
            } else {
                parse_hook_stealth_arg(ctx, mode_prop, "attachNative()")?
            };
            Ok((on_enter, on_leave, data, stealth))
        })();
        data_prop.free(ctx);
        mode_prop.free(ctx);
        match parsed {
            Ok(value) => value,
            Err(err) => {
                on_enter_prop.free(ctx);
                on_leave_prop.free(ctx);
                return err;
            }
        }
    } else {
        let on_enter = match extract_pointer_address(ctx, callback_arg, "attachNative callback") {
            Ok(callback) => callback,
            Err(err) => {
                on_enter_prop.free(ctx);
                on_leave_prop.free(ctx);
                return err;
            }
        };
        let data = if argc >= 3 {
            match extract_native_u64_or_exception(ctx, JSValue(*argv.add(2)), "attachNative userData") {
                Ok(value) => value,
                Err(err) => {
                    on_enter_prop.free(ctx);
                    on_leave_prop.free(ctx);
                    return err;
                }
            }
        } else {
            0
        };
        let stealth = if argc >= 4 {
            match parse_hook_stealth_arg(ctx, JSValue(*argv.add(3)), "attachNative()") {
                Ok(value) => value,
                Err(err) => {
                    on_enter_prop.free(ctx);
                    on_leave_prop.free(ctx);
                    return err;
                }
            }
        } else {
            false
        };
        (on_enter, 0, data, stealth)
    };
    on_enter_prop.free(ctx);
    on_leave_prop.free(ctx);

    if on_enter_address != 0 && (on_enter_address < MIN_VALID_CALL_TARGET || !is_executable_address(on_enter_address)) {
        return js_throw_range_error(ctx, "attachNative onEnter address is not executable");
    }
    if on_leave_address != 0 && (on_leave_address < MIN_VALID_CALL_TARGET || !is_executable_address(on_leave_address)) {
        return js_throw_range_error(ctx, "attachNative onLeave address is not executable");
    }

    if let Err(err) = enforce_hook_installation_policy() {
        return js_throw_internal_error(ctx, &err);
    }
    if let Err(err) = initialize_hook_backend() {
        return js_throw_internal_error(ctx, &err);
    }

    if let Err(err) = remove_registered_hook_for_native_install(target) {
        return js_throw_internal_error(ctx, &err);
    }

    let on_enter = (on_enter_address != 0).then(|| std::mem::transmute(on_enter_address as usize));
    let on_leave = (on_leave_address != 0).then(|| std::mem::transmute(on_leave_address as usize));
    let callback_data = Box::into_raw(Box::new(NativeAttachCallbacks {
        on_enter,
        on_leave,
        user_data: user_data as *mut c_void,
    })) as usize;
    let status = ffi::hook::hook_attach(
        target as *mut c_void,
        Some(native_hook_attach_on_enter_wrapper),
        Some(native_hook_attach_on_leave_wrapper),
        callback_data as *mut c_void,
        if stealth { 1 } else { 0 },
    );
    if status != HOOK_OK {
        drop(Box::from_raw(callback_data as *mut NativeAttachCallbacks));
        return js_throw_internal_error(ctx, &format!("attachNative: {}", hook_error_message(status)));
    }

    hook_registry().lock().unwrap_or_else(|e| e.into_inner()).insert(
        target,
        HookData {
            target,
            ctx: ctx as usize,
            mode: HookMode::NativeAttach,
            native_callback_data: callback_data,
            dispatch_data: 0,
        },
    );

    JSValue::bool(true).raw()
}

#[cfg(not(quickjs_hook_engine))]
unsafe extern "C" fn js_attach_native(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    js_throw_internal_error(
        ctx,
        "attachNative() is currently only available when quickjs-runtime is built for ARM64 with the native hook engine enabled",
    )
}

unsafe extern "C" fn js_recomp_hook(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    js_throw_internal_error(
        ctx,
        "recompHook() is Android-only; iOS currently uses ARM64 hook engine without recomp page mode",
    )
}

#[cfg(quickjs_hook_engine)]
unsafe extern "C" fn js_unhook(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 1 {
        return js_throw_type_error(ctx, "unhook() requires 1 argument");
    }

    let target = match extract_pointer_address(ctx, JSValue(*argv), "unhook") {
        Ok(target) => target,
        Err(err) => return err,
    };

    let result = ffi::hook::hook_remove(target as *mut c_void);
    if result != HOOK_OK {
        return js_throw_internal_error(ctx, hook_error_message(result));
    }

    if let Some(data) = hook_registry()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(&target)
    {
        if wait_for_in_flight_callbacks(Duration::from_millis(20)) && hook_engine_quiescent(20) {
            cleanup_invocations(ctx, Some(target));
            free_hook_data_callbacks(data);
            ffi::hook::hook_reclaim_retired();
        } else {
            output_message(&format!(
                "[hook cleanup] unhook timed out waiting for callbacks at target=0x{target:x}; callback storage and thunk were retained"
            ));
        }
    }

    JSValue::bool(true).raw()
}

#[cfg(not(quickjs_hook_engine))]
unsafe extern "C" fn js_unhook(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    js_throw_internal_error(
        ctx,
        "unhook() is currently only available when quickjs-runtime is built for ARM64 with the native hook engine enabled",
    )
}

#[cfg(quickjs_hook_engine)]
unsafe extern "C" fn js_interceptor_attach(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 2 {
        return js_throw_type_error(
            ctx,
            "Interceptor.attach(target, callbacks[, stealth]) requires at least 2 arguments",
        );
    }

    let target = match extract_pointer_address(ctx, JSValue(*argv), "Interceptor.attach") {
        Ok(target) => target,
        Err(err) => return err,
    };

    if hook_registry()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .contains_key(&target)
    {
        return js_throw_internal_error(ctx, "Interceptor.attach() target is already hooked");
    }

    let callbacks = JSValue(*argv.add(1));
    let (on_enter_bytes, on_leave_bytes) = match extract_attach_callbacks(ctx, callbacks) {
        Ok(callbacks) => callbacks,
        Err(err) => return err,
    };

    let stealth = if argc >= 3 {
        match parse_hook_stealth_arg(ctx, JSValue(*argv.add(2)), "Interceptor.attach()") {
            Ok(value) => value,
            Err(err) => return err,
        }
    } else {
        false
    };

    if let Err(err) = enforce_hook_installation_policy() {
        free_optional_callback_bytes(ctx, on_enter_bytes);
        free_optional_callback_bytes(ctx, on_leave_bytes);
        return js_throw_internal_error(ctx, &err);
    }

    if let Err(err) = initialize_hook_backend() {
        free_optional_callback_bytes(ctx, on_enter_bytes);
        free_optional_callback_bytes(ctx, on_leave_bytes);
        return js_throw_internal_error(ctx, &err);
    }

    let dispatch_ptr = Box::into_raw(Box::new(HookDispatchData {
        target,
        ctx: ctx as usize,
        mode: HookMode::Attach {
            on_enter_bytes,
            on_leave_bytes,
        },
        trampoline: AtomicU64::new(0),
    }));
    let status = ffi::hook::hook_attach(
        target as *mut c_void,
        if on_enter_bytes.is_some() {
            Some(hook_attach_on_enter_wrapper)
        } else {
            None
        },
        if on_leave_bytes.is_some() {
            Some(hook_attach_on_leave_wrapper)
        } else {
            None
        },
        dispatch_ptr as *mut c_void,
        if stealth { 1 } else { 0 },
    );

    if status != HOOK_OK {
        let dispatch = Box::from_raw(dispatch_ptr);
        free_hook_mode_callbacks(dispatch.ctx, dispatch.mode);
        return js_throw_internal_error(ctx, hook_error_message(status));
    }

    let registry_mode = (*dispatch_ptr).mode;
    hook_registry().lock().unwrap_or_else(|e| e.into_inner()).insert(
        target,
        HookData {
            target,
            ctx: ctx as usize,
            mode: registry_mode,
            native_callback_data: 0,
            dispatch_data: dispatch_ptr as usize,
        },
    );

    build_attach_handle(ctx, target)
}

#[cfg(not(quickjs_hook_engine))]
unsafe extern "C" fn js_interceptor_attach(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    js_throw_internal_error(
        ctx,
        "Interceptor.attach() is currently only available when quickjs-runtime is built for ARM64 with the native hook engine enabled",
    )
}

#[cfg(quickjs_hook_engine)]
unsafe extern "C" fn js_interceptor_detach_all(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if cleanup_registered_hooks(Some(ctx as usize)) {
        cleanup_invocations(ctx, None);
    }
    JSValue::undefined().raw()
}

#[cfg(not(quickjs_hook_engine))]
unsafe extern "C" fn js_interceptor_detach_all(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    js_throw_internal_error(
        ctx,
        "Interceptor.detachAll() is currently only available when quickjs-runtime is built for ARM64 with the native hook engine enabled",
    )
}

unsafe extern "C" fn js_interceptor_flush(
    _ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    // The native hook engine commits attach/replace/revert synchronously.
    JSValue::undefined().raw()
}

unsafe extern "C" fn js_diag_alloc_near(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 1 {
        return js_throw_type_error(ctx, "diagAllocNear(addr) requires 1 address argument");
    }

    let target = match extract_pointer_address(ctx, JSValue(*argv), "diagAllocNear") {
        Ok(target) => target,
        Err(err) => return err,
    };

    let result = JSValue(ffi::JS_NewObject(ctx));
    result.set_property(ctx, "available", JSValue::bool(false));
    result.set_property(ctx, "platform", JSValue::string(ctx, "ios"));
    result.set_property(ctx, "backend", JSValue::string(ctx, "arm64-hook-engine"));
    result.set_property(ctx, "androidReferenceApi", JSValue::string(ctx, "diagAllocNear"));
    result.set_property(ctx, "target", JSValue::string(ctx, &format!("0x{target:x}")));
    result.set_property(
        ctx,
        "reason",
        JSValue::string(
            ctx,
            "Android hook_alloc_near diagnostics are not exposed on iOS; use native.instrumentation/native.hookenv for iOS hook backend status",
        ),
    );
    result.raw()
}

#[cfg(quickjs_hook_engine)]
unsafe extern "C" fn js_attach_handle_detach(
    ctx: *mut ffi::JSContext,
    this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let target = get_js_u64_property(ctx, this, "__target");
    if target == 0 {
        return js_throw_internal_error(ctx, "attach handle does not contain a target address");
    }

    let arg = JSValue(ffi::JS_NewBigUint64(ctx, target));
    let mut args = [arg.raw()];
    let result = js_unhook(ctx, this, 1, args.as_mut_ptr());
    arg.free(ctx);
    result
}

pub(crate) fn register_hook_api(ctx: &JSContext) {
    #[cfg(quickjs_hook_engine)]
    clear_runtime_context_closing(ctx.as_ptr());

    let global = ctx.global_object();
    let interceptor = ctx.new_object();

    unsafe {
        let ctx_ptr = ctx.as_ptr();
        add_cfunction_to_object(ctx_ptr, global.raw(), "callNative", js_call_native, 1);
        add_cfunction_to_object(ctx_ptr, global.raw(), "hook", js_hook, 2);
        add_cfunction_to_object(ctx_ptr, global.raw(), "hookNative", js_hook_native, 4);
        add_cfunction_to_object(ctx_ptr, global.raw(), "attachNative", js_attach_native, 4);
        add_cfunction_to_object(ctx_ptr, global.raw(), "unhook", js_unhook, 1);
        add_cfunction_to_object(ctx_ptr, global.raw(), "recompHook", js_recomp_hook, 2);
        add_cfunction_to_object(ctx_ptr, global.raw(), "diagAllocNear", js_diag_alloc_near, 1);
        add_cfunction_to_object(ctx_ptr, interceptor.raw(), "attach", js_interceptor_attach, 2);
        add_cfunction_to_object(ctx_ptr, interceptor.raw(), "replace", js_hook, 2);
        add_cfunction_to_object(ctx_ptr, interceptor.raw(), "revert", js_unhook, 1);
        add_cfunction_to_object(ctx_ptr, interceptor.raw(), "detachAll", js_interceptor_detach_all, 0);
        add_cfunction_to_object(ctx_ptr, interceptor.raw(), "flush", js_interceptor_flush, 0);
    }

    let hook = ctx.new_object();
    hook.set_property(ctx.as_ptr(), "NORMAL", JSValue::int(HOOK_NORMAL));
    hook.set_property(ctx.as_ptr(), "WXSHADOW", JSValue::int(HOOK_WXSHADOW));
    hook.set_property(ctx.as_ptr(), "RECOMP", JSValue::int(HOOK_RECOMP));
    hook.set_property(
        ctx.as_ptr(),
        "backend",
        JSValue::string(ctx.as_ptr(), "arm64-hook-engine"),
    );
    hook.set_property(ctx.as_ptr(), "recompAvailable", JSValue::bool(false));
    hook.set_property(ctx.as_ptr(), "wxShadowAvailable", JSValue::bool(true));
    hook.set_property(ctx.as_ptr(), "androidRecompCompatible", JSValue::bool(false));

    global.set_property(ctx.as_ptr(), "Hook", hook);
    global.set_property(ctx.as_ptr(), "Interceptor", interceptor);
    global.free(ctx.as_ptr());

    match ctx.eval(INTERCEPTOR_BOOTSTRAP, "<interceptor-bootstrap>") {
        Ok(value) => value.free(ctx.as_ptr()),
        Err(error) => output_message(&format!("[Interceptor bootstrap error] {error}")),
    }
}

#[cfg(quickjs_hook_engine)]
pub(crate) fn initialize_hook_backend() -> Result<(), String> {
    let mut pool = hook_engine_pool().lock().unwrap_or_else(|e| e.into_inner());
    if pool.is_some() {
        return Ok(());
    }

    let (base, size) = allocate_executable_pool(EXECUTABLE_POOL_SIZE)?;
    let result = unsafe { ffi::hook::hook_engine_init(base, size) };
    if result != 0 {
        unsafe {
            libc::munmap(base, size);
        }
        return Err("failed to initialize ARM64 hook engine executable pool".into());
    }

    unsafe {
        ffi::hook::hook_engine_set_log_fn(Some(hook_engine_log_impl));
    }

    *pool = Some(HookEnginePool { base, size });
    Ok(())
}

#[cfg_attr(not(quickjs_hook_engine), allow(dead_code))]
#[cfg(not(quickjs_hook_engine))]
pub(crate) fn initialize_hook_backend() -> Result<(), String> {
    Ok(())
}

#[cfg(quickjs_hook_engine)]
pub(crate) fn cleanup_hook_backend() {
    let runtime_context = current_runtime_context();
    if let Some(ctx) = runtime_context {
        mark_runtime_context_closing(ctx as *mut ffi::JSContext);
    }
    let hooks_quiescent = cleanup_registered_hooks(runtime_context);
    if !hooks_quiescent {
        output_message("[hook cleanup] executable pool retained because hook callbacks are still in flight");
        return;
    }
    if !hook_registry().lock().unwrap_or_else(|e| e.into_inner()).is_empty() {
        output_message("[hook cleanup] executable pool retained because another QuickJS runtime still owns hooks");
        return;
    }
    if let Some(ctx) = runtime_context {
        unsafe { cleanup_invocations(ctx as *mut ffi::JSContext, None) };
    }

    let mut pool = hook_engine_pool().lock().unwrap_or_else(|e| e.into_inner());
    let Some(pool_state) = pool.take() else {
        return;
    };

    let cleanup_status = unsafe { ffi::hook::hook_engine_cleanup() };
    if cleanup_status != 0 {
        *pool = Some(pool_state);
        output_message("[hook cleanup] ARM64 hook engine remained mapped because generated thunks were not quiescent");
        return;
    }
    unsafe {
        libc::munmap(pool_state.base, pool_state.size);
    }
}

#[cfg(not(quickjs_hook_engine))]
pub(crate) fn cleanup_hook_backend() {}

#[cfg(quickjs_hook_engine)]
fn enforce_hook_installation_policy() -> Result<(), String> {
    let decision = resolve_hook_strategy().map_err(|err| err.to_string())?;
    warn_external_hook_environment_once(&decision);

    if decision.hook_install_commands_allowed() {
        Ok(())
    } else {
        let reason = decision
            .reason
            .unwrap_or_else(|| "hook installation was blocked by the current ios-rustfrida hook policy".into());
        Err(format!(
            "{} (policy={}, strategy={})",
            reason,
            decision.policy.as_str(),
            decision.strategy
        ))
    }
}

#[cfg(quickjs_hook_engine)]
fn warn_external_hook_environment_once(decision: &native_api::HookStrategyDecision) {
    static WARN_ONCE: Once = Once::new();
    WARN_ONCE.call_once(|| {
        let Ok(report) = detect_hook_environment() else {
            return;
        };

        let loaded_backends = report
            .backends
            .iter()
            .filter(|backend| !backend.loaded_images.is_empty())
            .map(|backend| backend.display_name.as_str())
            .collect::<Vec<_>>();

        if loaded_backends.is_empty() {
            return;
        }

        let active_backend = report.active_backend.as_deref().unwrap_or("<unknown>");
        output_message(&format!(
            "[hook warning] external hook backend(s) detected: {} (active={}); policy={} strategy={}; ios-rustfrida has no coexistence layer yet, so inline hooks may conflict",
            loaded_backends.join(", "),
            active_backend,
            decision.policy.as_str(),
            decision.strategy
        ));

        if let Some(reason) = &decision.reason {
            output_message(&format!("[hook warning] {reason}"));
        }
        for warning in report.warnings {
            output_message(&format!("[hook warning] {warning}"));
        }
    });
}

unsafe fn extract_pointer_address(
    ctx: *mut ffi::JSContext,
    arg: JSValue,
    func_name: &str,
) -> Result<u64, ffi::JSValue> {
    // Native code entry points are always normalized up front so downstream hook/call
    // paths do not accidentally mix PAC-tagged pointers with canonical addresses.
    if let Some(address) = get_native_pointer_addr(arg) {
        return Ok(normalize_code_pointer(address as usize) as u64);
    }
    if let Some(address) = arg.to_u64(ctx) {
        return Ok(normalize_code_pointer(address as usize) as u64);
    }

    Err(js_throw_type_error(
        ctx,
        &format!("{func_name}() argument must be a pointer-like value"),
    ))
}

unsafe fn js_value_to_u64_or_zero(ctx: *mut ffi::JSContext, value: JSValue) -> u64 {
    get_native_pointer_addr(value)
        .or_else(|| value.to_u64(ctx))
        .unwrap_or(0)
}

#[cfg(quickjs_hook_engine)]
unsafe fn extract_native_u64_or_exception(
    ctx: *mut ffi::JSContext,
    value: JSValue,
    _argument_name: &str,
) -> Result<u64, ffi::JSValue> {
    if let Some(pointer) = get_native_pointer_addr(value) {
        return Ok(pointer);
    }
    value.to_u64(ctx).ok_or_else(|| ffi::qjs_exception())
}

#[cfg(quickjs_hook_engine)]
fn hook_engine_pool() -> &'static Mutex<Option<HookEnginePool>> {
    static POOL: OnceLock<Mutex<Option<HookEnginePool>>> = OnceLock::new();
    POOL.get_or_init(|| Mutex::new(None))
}

#[cfg(quickjs_hook_engine)]
fn hook_registry() -> &'static Mutex<HashMap<u64, HookData>> {
    static REGISTRY: OnceLock<Mutex<HashMap<u64, HookData>>> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
}

#[cfg(quickjs_hook_engine)]
unsafe fn remove_registered_hook_for_native_install(target: u64) -> Result<(), String> {
    let old_data = hook_registry()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(&target);
    let Some(old_data) = old_data else {
        return Ok(());
    };

    let status = ffi::hook::hook_remove(target as *mut c_void);
    if status != HOOK_OK && status != HOOK_ERROR_NOT_FOUND {
        hook_registry()
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(target, old_data);
        return Err(format!(
            "failed to remove the existing hook before native hook installation: {}",
            hook_error_message(status)
        ));
    }

    if wait_for_in_flight_callbacks(Duration::from_millis(20)) && hook_engine_quiescent(20) {
        if old_data.ctx != 0 {
            cleanup_invocations(old_data.ctx as *mut ffi::JSContext, Some(target));
        }
        free_hook_data_callbacks(old_data);
        ffi::hook::hook_reclaim_retired();
    } else {
        output_message(&format!(
            "[hook cleanup] native hook replacement timed out waiting for callbacks at target=0x{target:x}; callback storage was retained"
        ));
    }

    Ok(())
}

#[cfg(quickjs_hook_engine)]
fn native_hook_stack() -> &'static Mutex<Vec<NativeHookFrame>> {
    static STACK: OnceLock<Mutex<Vec<NativeHookFrame>>> = OnceLock::new();
    STACK.get_or_init(|| Mutex::new(Vec::new()))
}

#[cfg(any(quickjs_hook_engine, test))]
fn invocation_values() -> &'static Mutex<HashMap<u64, InvocationValue>> {
    static VALUES: OnceLock<Mutex<HashMap<u64, InvocationValue>>> = OnceLock::new();
    VALUES.get_or_init(|| Mutex::new(HashMap::new()))
}

#[cfg(quickjs_hook_engine)]
fn closing_runtime_contexts() -> &'static Mutex<HashSet<usize>> {
    static CONTEXTS: OnceLock<Mutex<HashSet<usize>>> = OnceLock::new();
    CONTEXTS.get_or_init(|| Mutex::new(HashSet::new()))
}

#[cfg(quickjs_hook_engine)]
fn mark_runtime_context_closing(ctx: *mut ffi::JSContext) {
    closing_runtime_contexts()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(ctx as usize);
}

#[cfg(quickjs_hook_engine)]
fn clear_runtime_context_closing(ctx: *mut ffi::JSContext) {
    closing_runtime_contexts()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(&(ctx as usize));
}

#[cfg(quickjs_hook_engine)]
fn runtime_context_is_closing(ctx: *mut ffi::JSContext) -> bool {
    closing_runtime_contexts()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .contains(&(ctx as usize))
}

#[cfg(any(quickjs_hook_engine, test))]
fn store_invocation_value(ctx: usize, target: u64, value_bytes: [u8; 16]) -> u64 {
    static NEXT_ID: AtomicU64 = AtomicU64::new(1);

    loop {
        let value_id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        if value_id == 0 {
            continue;
        }

        let previous = invocation_values().lock().unwrap_or_else(|e| e.into_inner()).insert(
            value_id,
            InvocationValue {
                ctx,
                target,
                value_bytes,
            },
        );
        debug_assert!(previous.is_none());
        return value_id;
    }
}

#[cfg(any(quickjs_hook_engine, test))]
fn invocation_push(frame: InvocationFrame) {
    INVOCATION_STACK.with(|stack| stack.borrow_mut().push(frame));
}

#[cfg(any(quickjs_hook_engine, test))]
fn invocation_take(ctx: usize, target: u64, hook_ctx: usize) -> Option<InvocationFrame> {
    INVOCATION_STACK.with(|stack| {
        let mut stack = stack.borrow_mut();
        let index = stack
            .iter()
            .rposition(|frame| frame.ctx == ctx && frame.target == target && frame.hook_ctx == hook_ctx)?;
        Some(stack.remove(index))
    })
}

#[cfg(quickjs_hook_engine)]
fn invocation_take_by_hook(target: u64, hook_ctx: usize) -> Option<InvocationFrame> {
    INVOCATION_STACK.with(|stack| {
        let mut stack = stack.borrow_mut();
        let index = stack
            .iter()
            .rposition(|frame| frame.target == target && frame.hook_ctx == hook_ctx)?;
        Some(stack.remove(index))
    })
}

#[cfg(quickjs_hook_engine)]
fn defer_invocation(frame: InvocationFrame) {
    DEFERRED_INVOCATIONS.with(|deferred| deferred.borrow_mut().push(frame));
}

#[cfg(any(quickjs_hook_engine, test))]
fn take_invocation_value(frame: InvocationFrame) -> Option<[u8; 16]> {
    let value = invocation_values()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(&frame.value_id)?;
    debug_assert_eq!(value.ctx, frame.ctx);
    debug_assert_eq!(value.target, frame.target);
    Some(value.value_bytes)
}

#[cfg(quickjs_hook_engine)]
fn invocation_value_exists(frame: InvocationFrame) -> bool {
    invocation_values()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .contains_key(&frame.value_id)
}

#[cfg(any(quickjs_hook_engine, test))]
fn take_invocation_values(ctx: usize, target: Option<u64>) -> Vec<[u8; 16]> {
    let mut values = invocation_values().lock().unwrap_or_else(|e| e.into_inner());
    let value_ids = values
        .iter()
        .filter_map(|(value_id, value)| {
            (value.ctx == ctx && target.is_none_or(|target| value.target == target)).then_some(*value_id)
        })
        .collect::<Vec<_>>();

    value_ids
        .into_iter()
        .filter_map(|value_id| values.remove(&value_id).map(|value| value.value_bytes))
        .collect()
}

#[cfg(any(quickjs_hook_engine, test))]
fn discard_local_invocation_frames(ctx: usize, target: Option<u64>) {
    let retain = |frame: &InvocationFrame| frame.ctx != ctx || target.is_some_and(|target| frame.target != target);
    INVOCATION_STACK.with(|stack| stack.borrow_mut().retain(retain));
    DEFERRED_INVOCATIONS.with(|deferred| deferred.borrow_mut().retain(retain));
}

#[cfg(quickjs_hook_engine)]
unsafe fn drain_deferred_invocations(ctx: *mut ffi::JSContext) {
    let frames = DEFERRED_INVOCATIONS.with(|deferred| {
        let mut deferred = deferred.borrow_mut();
        let mut frames = Vec::new();
        let mut index = 0;
        while index < deferred.len() {
            if deferred[index].ctx == ctx as usize {
                frames.push(deferred.remove(index));
            } else {
                index += 1;
            }
        }
        frames
    });

    for value_bytes in frames.into_iter().filter_map(take_invocation_value) {
        let value = std::ptr::read_unaligned(value_bytes.as_ptr() as *const ffi::JSValue);
        ffi::qjs_free_value(ctx, value);
    }
}

#[cfg(quickjs_hook_engine)]
unsafe fn cleanup_invocations(ctx: *mut ffi::JSContext, target: Option<u64>) {
    discard_local_invocation_frames(ctx as usize, target);
    for value_bytes in take_invocation_values(ctx as usize, target) {
        let value = std::ptr::read_unaligned(value_bytes.as_ptr() as *const ffi::JSValue);
        ffi::qjs_free_value(ctx, value);
    }
}

#[cfg(quickjs_hook_engine)]
fn invocation_frame(
    ctx: *mut ffi::JSContext,
    target: u64,
    hook_ctx: *mut ffi::hook::HookContext,
    value: ffi::JSValue,
) -> InvocationFrame {
    const _: [(); 16] = [(); std::mem::size_of::<ffi::JSValue>()];

    let mut value_bytes = [0u8; 16];
    unsafe {
        std::ptr::copy_nonoverlapping(
            &value as *const ffi::JSValue as *const u8,
            value_bytes.as_mut_ptr(),
            value_bytes.len(),
        );
    }

    InvocationFrame {
        ctx: ctx as usize,
        target,
        hook_ctx: hook_ctx as usize,
        value_id: store_invocation_value(ctx as usize, target, value_bytes),
    }
}

#[cfg(quickjs_hook_engine)]
unsafe fn invocation_value(frame: InvocationFrame) -> Option<ffi::JSValue> {
    take_invocation_value(frame)
        .map(|value_bytes| std::ptr::read_unaligned(value_bytes.as_ptr() as *const ffi::JSValue))
}

#[cfg(quickjs_hook_engine)]
fn in_flight_callbacks() -> &'static Mutex<usize> {
    static COUNTER: OnceLock<Mutex<usize>> = OnceLock::new();
    COUNTER.get_or_init(|| Mutex::new(0))
}

#[cfg(quickjs_hook_engine)]
fn in_flight_callbacks_cv() -> &'static Condvar {
    static CV: OnceLock<Condvar> = OnceLock::new();
    CV.get_or_init(Condvar::new)
}

#[cfg(quickjs_hook_engine)]
fn current_thread_id_u64() -> u64 {
    unsafe { libc::pthread_self() as usize as u64 }
}

#[cfg(quickjs_hook_engine)]
fn runtime_owner_is_current_thread() -> bool {
    JS_RUNTIME_OWNER_THREAD.load(Ordering::Acquire) == current_thread_id_u64()
}

#[cfg(quickjs_hook_engine)]
fn mark_runtime_owner_current_thread() {
    JS_RUNTIME_OWNER_THREAD.store(current_thread_id_u64(), Ordering::Release);
}

#[cfg(quickjs_hook_engine)]
fn clear_runtime_owner_current_thread() {
    let current = current_thread_id_u64();
    let _ = JS_RUNTIME_OWNER_THREAD.compare_exchange(current, 0, Ordering::AcqRel, Ordering::Relaxed);
}

#[cfg(quickjs_hook_engine)]
fn current_runtime_context() -> Option<usize> {
    RUNTIME_CONTEXT_STACK.with(|stack| stack.borrow().last().copied())
}

#[cfg(quickjs_hook_engine)]
fn try_enter_runtime_js_for_callback(
    ctx: *mut ffi::JSContext,
    context_name: &str,
    target: u64,
) -> Option<RuntimeJsGuard> {
    if runtime_context_is_closing(ctx) {
        return None;
    }
    if runtime_owner_is_current_thread() {
        unsafe {
            ffi::qjs_update_stack_top(ctx);
        }
        RUNTIME_CONTEXT_STACK.with(|stack| stack.borrow_mut().push(ctx as usize));
        return Some(RuntimeJsGuard {
            _inner: RuntimeJsGuardInner::Reentrant,
            ctx: ctx as usize,
        });
    }

    let start = Instant::now();
    let mut spins = 0usize;

    loop {
        if runtime_context_is_closing(ctx) {
            return None;
        }
        match JS_RUNTIME_LOCK.try_lock() {
            Ok(guard) => {
                if runtime_context_is_closing(ctx) {
                    drop(guard);
                    return None;
                }
                mark_runtime_owner_current_thread();
                unsafe {
                    ffi::qjs_update_stack_top(ctx);
                }
                RUNTIME_CONTEXT_STACK.with(|stack| stack.borrow_mut().push(ctx as usize));
                return Some(RuntimeJsGuard {
                    _inner: RuntimeJsGuardInner::Locked { _guard: guard },
                    ctx: ctx as usize,
                });
            }
            Err(std::sync::TryLockError::WouldBlock) => {
                if runtime_owner_is_current_thread() {
                    unsafe {
                        ffi::qjs_update_stack_top(ctx);
                    }
                    RUNTIME_CONTEXT_STACK.with(|stack| stack.borrow_mut().push(ctx as usize));
                    return Some(RuntimeJsGuard {
                        _inner: RuntimeJsGuardInner::Reentrant,
                        ctx: ctx as usize,
                    });
                }

                if start.elapsed() >= CALLBACK_LOCK_WAIT_TIMEOUT {
                    output_message(&format!(
                        "[{context_name}] callback skipped (QuickJS runtime busy > {} ms), target=0x{target:x}",
                        CALLBACK_LOCK_WAIT_TIMEOUT.as_millis()
                    ));
                    return None;
                }

                if spins < CALLBACK_LOCK_WAIT_SPIN_LIMIT {
                    spins += 1;
                    std::hint::spin_loop();
                } else {
                    std::thread::yield_now();
                }
            }
            Err(std::sync::TryLockError::Poisoned(error)) => {
                if runtime_context_is_closing(ctx) {
                    drop(error.into_inner());
                    return None;
                }
                mark_runtime_owner_current_thread();
                unsafe {
                    ffi::qjs_update_stack_top(ctx);
                }
                RUNTIME_CONTEXT_STACK.with(|stack| stack.borrow_mut().push(ctx as usize));
                return Some(RuntimeJsGuard {
                    _inner: RuntimeJsGuardInner::Locked {
                        _guard: error.into_inner(),
                    },
                    ctx: ctx as usize,
                });
            }
        }
    }
}

#[cfg(quickjs_hook_engine)]
fn dup_callback_to_bytes(ctx: *mut ffi::JSContext, callback: ffi::JSValue) -> [u8; 16] {
    let duplicated = unsafe { ffi::qjs_dup_value(ctx, callback) };
    let mut bytes = [0u8; 16];
    unsafe {
        std::ptr::copy_nonoverlapping(
            &duplicated as *const ffi::JSValue as *const u8,
            bytes.as_mut_ptr(),
            bytes.len(),
        );
    }
    bytes
}

#[cfg(quickjs_hook_engine)]
fn free_callback_bytes(ctx: *mut ffi::JSContext, callback_bytes: [u8; 16]) {
    unsafe {
        let callback = std::ptr::read_unaligned(callback_bytes.as_ptr() as *const ffi::JSValue);
        ffi::qjs_free_value(ctx, callback);
    }
}

#[cfg(quickjs_hook_engine)]
fn free_optional_callback_bytes(ctx: *mut ffi::JSContext, callback_bytes: Option<[u8; 16]>) {
    if let Some(callback_bytes) = callback_bytes {
        free_callback_bytes(ctx, callback_bytes);
    }
}

#[cfg(quickjs_hook_engine)]
fn free_hook_mode_callbacks(ctx: usize, mode: HookMode) {
    match mode {
        HookMode::Replace { callback_bytes, .. } => {
            free_callback_bytes(ctx as *mut ffi::JSContext, callback_bytes);
        }
        HookMode::Attach {
            on_enter_bytes,
            on_leave_bytes,
        } => {
            free_optional_callback_bytes(ctx as *mut ffi::JSContext, on_enter_bytes);
            free_optional_callback_bytes(ctx as *mut ffi::JSContext, on_leave_bytes);
        }
        HookMode::NativeReplace => {
            // Native callback storage is owned by HookData and handled below.
        }
        HookMode::NativeAttach => {}
    }
}

#[cfg(quickjs_hook_engine)]
fn free_hook_data_callbacks(data: HookData) {
    if data.dispatch_data != 0 {
        unsafe {
            let dispatch = Box::from_raw(data.dispatch_data as *mut HookDispatchData);
            free_hook_mode_callbacks(dispatch.ctx, dispatch.mode);
        }
        return;
    }

    match data.mode {
        HookMode::NativeReplace => {
            if data.native_callback_data != 0 {
                unsafe {
                    drop(Box::from_raw(data.native_callback_data as *mut NativeReplaceCallbacks));
                }
            }
        }
        HookMode::NativeAttach => {
            if data.native_callback_data != 0 {
                unsafe {
                    drop(Box::from_raw(data.native_callback_data as *mut NativeAttachCallbacks));
                }
            }
        }
        mode => free_hook_mode_callbacks(data.ctx, mode),
    }
}

#[cfg(quickjs_hook_engine)]
unsafe fn extract_attach_callbacks(
    ctx: *mut ffi::JSContext,
    callbacks: JSValue,
) -> Result<(Option<[u8; 16]>, Option<[u8; 16]>), ffi::JSValue> {
    if callbacks.is_function(ctx) {
        return Ok((Some(dup_callback_to_bytes(ctx, callbacks.raw())), None));
    }

    if !callbacks.is_object() {
        return Err(js_throw_type_error(
            ctx,
            "Interceptor.attach() callbacks must be a function or an object with onEnter/onLeave",
        ));
    }

    let on_enter = callbacks.get_property(ctx, "onEnter");
    let on_leave = callbacks.get_property(ctx, "onLeave");

    let on_enter_bytes = if on_enter.is_undefined() || on_enter.is_null() {
        None
    } else if on_enter.is_function(ctx) {
        Some(dup_callback_to_bytes(ctx, on_enter.raw()))
    } else {
        on_enter.free(ctx);
        on_leave.free(ctx);
        return Err(js_throw_type_error(
            ctx,
            "Interceptor.attach() callbacks.onEnter must be a function when provided",
        ));
    };

    let on_leave_bytes = if on_leave.is_undefined() || on_leave.is_null() {
        None
    } else if on_leave.is_function(ctx) {
        Some(dup_callback_to_bytes(ctx, on_leave.raw()))
    } else {
        on_enter.free(ctx);
        on_leave.free(ctx);
        if let Some(callback_bytes) = on_enter_bytes {
            free_callback_bytes(ctx, callback_bytes);
        }
        return Err(js_throw_type_error(
            ctx,
            "Interceptor.attach() callbacks.onLeave must be a function when provided",
        ));
    };

    on_enter.free(ctx);
    on_leave.free(ctx);

    if on_enter_bytes.is_none() && on_leave_bytes.is_none() {
        return Err(js_throw_type_error(
            ctx,
            "Interceptor.attach() requires at least one callback: onEnter or onLeave",
        ));
    }

    Ok((on_enter_bytes, on_leave_bytes))
}

#[cfg(quickjs_hook_engine)]
unsafe fn build_attach_handle(ctx: *mut ffi::JSContext, target: u64) -> ffi::JSValue {
    let handle = ffi::JS_NewObject(ctx);
    set_js_u64_property(ctx, handle, "__target", target);
    set_js_u64_property(ctx, handle, "target", target);
    set_js_cfunction_property(ctx, handle, "detach", js_attach_handle_detach, 0);
    handle
}

#[cfg(quickjs_hook_engine)]
unsafe fn sync_js_context_to_native(
    ctx: *mut ffi::JSContext,
    js_ctx: ffi::JSValue,
    hook_ctx_ptr: *mut ffi::hook::HookContext,
) {
    let hook_ctx = &mut *hook_ctx_ptr;
    for index in 0..hook_ctx.x.len() {
        hook_ctx.x[index] = get_js_u64_property(ctx, js_ctx, &format!("x{index}"));
    }
}

#[cfg(quickjs_hook_engine)]
unsafe fn build_invocation_context(
    ctx: *mut ffi::JSContext,
    hook_ctx_ptr: *mut ffi::hook::HookContext,
) -> ffi::JSValue {
    let invocation = build_hook_context(ctx, hook_ctx_ptr, 0, false);
    let hook_ctx = &*hook_ctx_ptr;
    set_js_u64_property(ctx, invocation, "lr", hook_ctx.x[30]);
    set_js_u64_property(ctx, invocation, "returnAddress", hook_ctx.x[30]);
    invocation
}

#[cfg(quickjs_hook_engine)]
unsafe fn refresh_invocation_context(
    ctx: *mut ffi::JSContext,
    invocation: ffi::JSValue,
    hook_ctx_ptr: *mut ffi::hook::HookContext,
) {
    let hook_ctx = &*hook_ctx_ptr;
    for (index, value) in hook_ctx.x.iter().enumerate() {
        set_js_u64_property(ctx, invocation, &format!("x{index}"), *value);
    }
    set_js_u64_property(ctx, invocation, "sp", hook_ctx.sp);
    set_js_u64_property(ctx, invocation, "pc", hook_ctx.pc);
    set_js_u64_property(ctx, invocation, "lr", hook_ctx.x[30]);
    set_js_u64_property(ctx, invocation, "returnAddress", hook_ctx.x[30]);
}

#[cfg(quickjs_hook_engine)]
unsafe fn call_interceptor_helper(
    ctx: *mut ffi::JSContext,
    callback_bytes: [u8; 16],
    invocation: ffi::JSValue,
    helper_name: &str,
) -> ffi::JSValue {
    let callback = std::ptr::read_unaligned(callback_bytes.as_ptr() as *const ffi::JSValue);
    let callback_dup = ffi::qjs_dup_value(ctx, callback);
    let global = ffi::JS_GetGlobalObject(ctx);
    let helper = JSValue(global).get_property(ctx, helper_name);

    let result = if helper.is_function(ctx) {
        let mut args = [callback_dup, invocation];
        ffi::JS_Call(ctx, helper.raw(), global, args.len() as i32, args.as_mut_ptr())
    } else {
        output_message(&format!("[Interceptor error] missing bootstrap helper {helper_name}"));
        let mut args = [invocation];
        ffi::JS_Call(ctx, callback_dup, invocation, args.len() as i32, args.as_mut_ptr())
    };

    helper.free(ctx);
    ffi::qjs_free_value(ctx, global);
    ffi::qjs_free_value(ctx, callback_dup);
    result
}

#[cfg(quickjs_hook_engine)]
struct InFlightCallbackGuard;

#[cfg(quickjs_hook_engine)]
impl InFlightCallbackGuard {
    fn enter() -> Self {
        increment_in_flight_callbacks();
        Self
    }
}

#[cfg(quickjs_hook_engine)]
impl Drop for InFlightCallbackGuard {
    fn drop(&mut self) {
        decrement_in_flight_callbacks();
    }
}

#[cfg(quickjs_hook_engine)]
fn increment_in_flight_callbacks() {
    let mut guard = in_flight_callbacks().lock().unwrap_or_else(|e| e.into_inner());
    *guard += 1;
}

#[cfg(quickjs_hook_engine)]
fn decrement_in_flight_callbacks() {
    let mut guard = in_flight_callbacks().lock().unwrap_or_else(|e| e.into_inner());
    *guard = guard.saturating_sub(1);
    if *guard == 0 {
        in_flight_callbacks_cv().notify_all();
    }
}

#[cfg(quickjs_hook_engine)]
fn wait_for_in_flight_callbacks(timeout: Duration) -> bool {
    let start = Instant::now();
    let mut guard = in_flight_callbacks().lock().unwrap_or_else(|e| e.into_inner());

    while *guard != 0 {
        let Some(remaining) = timeout.checked_sub(start.elapsed()) else {
            return false;
        };

        let (next_guard, wait_result) = in_flight_callbacks_cv()
            .wait_timeout(guard, remaining)
            .unwrap_or_else(|e| e.into_inner());
        guard = next_guard;
        if wait_result.timed_out() && *guard != 0 {
            return false;
        }
    }

    true
}

#[cfg(quickjs_hook_engine)]
fn hook_engine_quiescent(timeout_ms: u32) -> bool {
    unsafe { ffi::hook::hook_engine_wait_for_quiescence(timeout_ms) != 0 }
}

#[cfg(quickjs_hook_engine)]
fn push_native_hook_frame(ctx_ptr: *mut ffi::hook::HookContext, trampoline: u64) {
    native_hook_stack()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .push(NativeHookFrame {
            ctx_ptr: ctx_ptr as usize,
            trampoline,
            orig_called: false,
        });
}

#[cfg(quickjs_hook_engine)]
fn pop_native_hook_frame(ctx_ptr: *mut ffi::hook::HookContext, trampoline: u64) -> bool {
    let mut guard = native_hook_stack().lock().unwrap_or_else(|e| e.into_inner());
    if let Some(frame) = guard.pop() {
        debug_assert_eq!(frame.ctx_ptr, ctx_ptr as usize);
        debug_assert_eq!(frame.trampoline, trampoline);
        frame.orig_called
    } else {
        false
    }
}

#[cfg(quickjs_hook_engine)]
fn current_native_hook_frame() -> Option<(*mut ffi::hook::HookContext, u64)> {
    native_hook_stack()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .last()
        .map(|frame| (frame.ctx_ptr as *mut ffi::hook::HookContext, frame.trampoline))
}

#[cfg(quickjs_hook_engine)]
fn mark_native_hook_frame_orig_called(ctx_ptr: *mut ffi::hook::HookContext, trampoline: u64) -> bool {
    let mut guard = native_hook_stack().lock().unwrap_or_else(|e| e.into_inner());
    if let Some(frame) = guard
        .iter_mut()
        .rfind(|frame| frame.ctx_ptr == ctx_ptr as usize && frame.trampoline == trampoline)
    {
        frame.orig_called = true;
        true
    } else {
        false
    }
}

#[cfg(quickjs_hook_engine)]
unsafe extern "C" fn hook_engine_log_impl(msg: *const i8) {
    if msg.is_null() {
        return;
    }

    let rendered = CStr::from_ptr(msg).to_string_lossy();
    output_message(&format!("[hook_engine] {rendered}"));
}

#[cfg(quickjs_hook_engine)]
fn allocate_executable_pool(size: usize) -> Result<(*mut c_void, usize), String> {
    let mut flags = libc::MAP_PRIVATE | libc::MAP_ANON;
    #[cfg(any(target_os = "ios", target_os = "macos"))]
    {
        flags |= apple_map_jit_flag();
    }

    let ptr = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            size,
            libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
            flags,
            -1,
            0,
        )
    };

    if ptr == libc::MAP_FAILED {
        return Err(format!(
            "mmap(RWX) failed while allocating hook engine pool: {}",
            std::io::Error::last_os_error()
        ));
    }

    Ok((ptr, size))
}

#[cfg(any(target_os = "ios", target_os = "macos"))]
fn apple_map_jit_flag() -> i32 {
    libc::MAP_JIT
}

#[cfg(quickjs_hook_engine)]
unsafe extern "C" fn native_hook_replace_wrapper(ctx_ptr: *mut ffi::hook::HookContext, callback_data: *mut c_void) {
    if ctx_ptr.is_null() || callback_data.is_null() {
        return;
    }

    let _in_flight_guard = InFlightCallbackGuard::enter();
    let callbacks = &*(callback_data as *const NativeReplaceCallbacks);
    (callbacks.callback)(ctx_ptr, callbacks.user_data);
}

#[cfg(quickjs_hook_engine)]
unsafe extern "C" fn native_hook_attach_on_enter_wrapper(
    ctx_ptr: *mut ffi::hook::HookContext,
    callback_data: *mut c_void,
) {
    if ctx_ptr.is_null() || callback_data.is_null() {
        return;
    }

    increment_in_flight_callbacks();
    let callbacks = &*(callback_data as *const NativeAttachCallbacks);
    if let Some(callback) = callbacks.on_enter {
        callback(ctx_ptr, callbacks.user_data);
    }
}

#[cfg(quickjs_hook_engine)]
unsafe extern "C" fn native_hook_attach_on_leave_wrapper(
    ctx_ptr: *mut ffi::hook::HookContext,
    callback_data: *mut c_void,
) {
    if ctx_ptr.is_null() || callback_data.is_null() {
        return;
    }

    let callbacks = &*(callback_data as *const NativeAttachCallbacks);
    if let Some(callback) = callbacks.on_leave {
        callback(ctx_ptr, callbacks.user_data);
    }
    decrement_in_flight_callbacks();
}

#[cfg(quickjs_hook_engine)]
unsafe extern "C" fn hook_callback_wrapper(ctx_ptr: *mut ffi::hook::HookContext, user_data: *mut c_void) {
    if ctx_ptr.is_null() || user_data.is_null() {
        return;
    }

    let _in_flight_guard = InFlightCallbackGuard::enter();
    let dispatch = &*(user_data as *const HookDispatchData);
    let target = dispatch.target;
    let HookMode::Replace { callback_bytes, .. } = dispatch.mode else {
        return;
    };
    let trampoline = dispatch.trampoline.load(Ordering::Acquire);
    let ctx_raw = dispatch.ctx;

    push_native_hook_frame(ctx_ptr, trampoline);

    let mut result_was_set = false;
    let ctx = ctx_raw as *mut ffi::JSContext;

    let Some(_runtime_guard) = try_enter_runtime_js_for_callback(ctx, "hook", target) else {
        let orig_called = pop_native_hook_frame(ctx_ptr, trampoline);
        if trampoline != 0 && !orig_called {
            (*ctx_ptr).x[0] = ffi::hook::hook_invoke_trampoline(ctx_ptr, trampoline as *mut c_void);
        }
        return;
    };

    let callback = std::ptr::read_unaligned(callback_bytes.as_ptr() as *const ffi::JSValue);
    let callback_dup = ffi::qjs_dup_value(ctx, callback);
    let js_ctx = build_hook_context(ctx, ctx_ptr, trampoline, true);
    let global = ffi::JS_GetGlobalObject(ctx);
    let result = ffi::JS_Call(ctx, callback_dup, global, 1, &js_ctx as *const _ as *mut _);

    if !handle_js_exception(ctx, result, "hook") {
        sync_js_context_to_native(ctx, js_ctx, ctx_ptr);
        result_was_set = true;
        if ffi::qjs_is_undefined(result) == 0 {
            (*ctx_ptr).x[0] = js_value_to_u64_or_zero(ctx, JSValue(result));
        } else {
            (*ctx_ptr).x[0] = 0;
        }
    }

    ffi::qjs_free_value(ctx, js_ctx);
    ffi::qjs_free_value(ctx, result);
    ffi::qjs_free_value(ctx, global);
    ffi::qjs_free_value(ctx, callback_dup);

    let orig_called = pop_native_hook_frame(ctx_ptr, trampoline);
    if !result_was_set && trampoline != 0 && !orig_called {
        (*ctx_ptr).x[0] = ffi::hook::hook_invoke_trampoline(ctx_ptr, trampoline as *mut c_void);
    }
}

#[cfg(quickjs_hook_engine)]
unsafe extern "C" fn hook_attach_on_enter_wrapper(ctx_ptr: *mut ffi::hook::HookContext, user_data: *mut c_void) {
    if ctx_ptr.is_null() || user_data.is_null() {
        return;
    }

    let _in_flight_guard = InFlightCallbackGuard::enter();
    let dispatch = &*(user_data as *const HookDispatchData);
    let target = dispatch.target;
    let HookMode::Attach {
        on_enter_bytes,
        on_leave_bytes,
    } = dispatch.mode
    else {
        return;
    };
    let Some(callback_bytes) = on_enter_bytes else {
        return;
    };
    let ctx_raw = dispatch.ctx;
    let has_on_leave = on_leave_bytes.is_some();

    let ctx = ctx_raw as *mut ffi::JSContext;
    let Some(_runtime_guard) = try_enter_runtime_js_for_callback(ctx, "Interceptor.attach/onEnter", target) else {
        return;
    };

    drain_deferred_invocations(ctx);
    let invocation = build_invocation_context(ctx, ctx_ptr);
    let result = call_interceptor_helper(ctx, callback_bytes, invocation, INTERCEPTOR_ENTER_HELPER);
    let _callback_failed = handle_js_exception(ctx, result, "Interceptor.attach/onEnter");
    sync_js_context_to_native(ctx, invocation, ctx_ptr);
    ffi::qjs_free_value(ctx, result);

    if has_on_leave {
        invocation_push(invocation_frame(ctx, target, ctx_ptr, invocation));
    } else {
        ffi::qjs_free_value(ctx, invocation);
    }
}

#[cfg(quickjs_hook_engine)]
unsafe extern "C" fn hook_attach_on_leave_wrapper(ctx_ptr: *mut ffi::hook::HookContext, user_data: *mut c_void) {
    if ctx_ptr.is_null() || user_data.is_null() {
        return;
    }

    let _in_flight_guard = InFlightCallbackGuard::enter();
    let dispatch = &*(user_data as *const HookDispatchData);
    let target = dispatch.target;
    let callback_data = match dispatch.mode {
        HookMode::Attach {
            on_leave_bytes: Some(callback_bytes),
            ..
        } => Some((dispatch.ctx, callback_bytes)),
        _ => None,
    };

    let Some((ctx_raw, callback_bytes)) = callback_data else {
        if let Some(frame) = invocation_take_by_hook(target, ctx_ptr as usize) {
            if !invocation_value_exists(frame) {
                return;
            }
            let ctx = frame.ctx as *mut ffi::JSContext;
            if let Some(_runtime_guard) =
                try_enter_runtime_js_for_callback(ctx, "Interceptor.attach/onLeave cleanup", target)
            {
                drain_deferred_invocations(ctx);
                if let Some(invocation) = invocation_value(frame) {
                    ffi::qjs_free_value(ctx, invocation);
                }
            } else if !runtime_context_is_closing(ctx) {
                defer_invocation(frame);
            }
        }
        return;
    };

    let frame = invocation_take(ctx_raw, target, ctx_ptr as usize);
    let ctx = ctx_raw as *mut ffi::JSContext;
    let Some(_runtime_guard) = try_enter_runtime_js_for_callback(ctx, "Interceptor.attach/onLeave", target) else {
        if let Some(frame) = frame {
            if !runtime_context_is_closing(ctx) {
                defer_invocation(frame);
            }
        }
        return;
    };

    drain_deferred_invocations(ctx);
    let invocation = match frame {
        Some(frame) => invocation_value(frame).unwrap_or_else(|| build_invocation_context(ctx, ctx_ptr)),
        None => build_invocation_context(ctx, ctx_ptr),
    };
    refresh_invocation_context(ctx, invocation, ctx_ptr);

    let result = call_interceptor_helper(ctx, callback_bytes, invocation, INTERCEPTOR_LEAVE_HELPER);
    let callback_failed = handle_js_exception(ctx, result, "Interceptor.attach/onLeave");
    sync_js_context_to_native(ctx, invocation, ctx_ptr);
    if !callback_failed && ffi::qjs_is_undefined(result) == 0 {
        (*ctx_ptr).x[0] = js_value_to_u64_or_zero(ctx, JSValue(result));
    }

    ffi::qjs_free_value(ctx, result);
    ffi::qjs_free_value(ctx, invocation);
}

#[cfg(quickjs_hook_engine)]
unsafe fn build_hook_context(
    ctx: *mut ffi::JSContext,
    hook_ctx_ptr: *mut ffi::hook::HookContext,
    trampoline: u64,
    include_orig: bool,
) -> ffi::JSValue {
    let object = ffi::JS_NewObject(ctx);
    let hook_ctx = &*hook_ctx_ptr;

    for (index, value) in hook_ctx.x.iter().enumerate() {
        set_js_u64_property(ctx, object, &format!("x{index}"), *value);
    }

    set_js_u64_property(ctx, object, "sp", hook_ctx.sp);
    set_js_u64_property(ctx, object, "pc", hook_ctx.pc);
    set_js_u64_property(ctx, object, "trampoline", trampoline);
    set_js_u64_property(ctx, object, "__hookCtxPtr", hook_ctx_ptr as usize as u64);
    set_js_u64_property(ctx, object, "__hookTrampoline", trampoline);
    if include_orig {
        set_js_cfunction_property(ctx, object, "orig", js_native_call_original, 0);
    }

    object
}

#[cfg(quickjs_hook_engine)]
unsafe extern "C" fn js_native_call_original(
    ctx: *mut ffi::JSContext,
    this_val: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let hook_ctx_ptr = {
        let pointer = get_js_u64_property(ctx, this_val, "__hookCtxPtr") as *mut ffi::hook::HookContext;
        if pointer.is_null() {
            current_native_hook_frame()
                .map(|(ctx_ptr, _)| ctx_ptr)
                .unwrap_or(std::ptr::null_mut())
        } else {
            pointer
        }
    };

    let trampoline = {
        let value = get_js_u64_property(ctx, this_val, "__hookTrampoline");
        if value == 0 {
            current_native_hook_frame()
                .map(|(_, trampoline)| trampoline)
                .unwrap_or(0)
        } else {
            value
        }
    };

    if hook_ctx_ptr.is_null() || trampoline == 0 {
        return ffi::JS_ThrowInternalError(
            ctx,
            b"orig() can only be called inside a hook callback\0".as_ptr() as *const _,
        );
    }

    sync_js_context_to_native(ctx, this_val, hook_ctx_ptr);
    let _ = mark_native_hook_frame_orig_called(hook_ctx_ptr, trampoline);
    let result = ffi::hook::hook_invoke_trampoline(hook_ctx_ptr, trampoline as *mut c_void);
    (*hook_ctx_ptr).x[0] = result;
    js_u64_to_js_number_or_bigint(ctx, result)
}

#[cfg(quickjs_hook_engine)]
unsafe fn handle_js_exception(ctx: *mut ffi::JSContext, result: ffi::JSValue, context_name: &str) -> bool {
    if ffi::qjs_is_exception(result) == 0 {
        return false;
    }

    output_message(&format!("[{context_name} error] {}", take_exception_string(ctx)));
    true
}

#[cfg(quickjs_hook_engine)]
unsafe fn take_exception_string(ctx: *mut ffi::JSContext) -> String {
    let exception = ffi::JS_GetException(ctx);
    let exception_value = JSValue(exception);

    let message = exception_value
        .to_string(ctx)
        .unwrap_or_else(|| "unknown exception".to_string());

    let stack = exception_value.get_property(ctx, "stack");
    let stack_string = if !stack.is_undefined() {
        stack.to_string(ctx).unwrap_or_default()
    } else {
        String::new()
    };

    exception_value.free(ctx);
    stack.free(ctx);

    if stack_string.is_empty() {
        message
    } else {
        format!("{message}\n{stack_string}")
    }
}

#[cfg(quickjs_hook_engine)]
fn cleanup_registered_hooks(owner_ctx: Option<usize>) -> bool {
    let targets = {
        let guard = hook_registry().lock().unwrap_or_else(|e| e.into_inner());
        guard
            .iter()
            .filter_map(|(target, data)| {
                owner_ctx
                    .map(|owner| data.ctx == owner)
                    .unwrap_or(true)
                    .then_some(*target)
            })
            .collect::<Vec<_>>()
    };

    let mut removed_targets = Vec::new();
    let mut removal_failed = false;
    for target in targets {
        let status = unsafe { ffi::hook::hook_remove(target as *mut c_void) };
        if status == HOOK_OK || status == HOOK_ERROR_NOT_FOUND {
            removed_targets.push(target);
        } else {
            removal_failed = true;
            output_message(&format!(
                "[hook cleanup] failed to remove target=0x{target:x}: {}",
                hook_error_message(status)
            ));
        }
    }

    if !wait_for_in_flight_callbacks(Duration::from_millis(200)) {
        let remaining = *in_flight_callbacks().lock().unwrap_or_else(|e| e.into_inner());
        output_message(&format!(
            "[hook cleanup] waiting for in-flight callbacks timed out, remaining={remaining}"
        ));
        return false;
    }
    if !hook_engine_quiescent(200) {
        output_message("[hook cleanup] generated ARM64 thunks did not quiesce");
        return false;
    }

    let callbacks = {
        let mut guard = hook_registry().lock().unwrap_or_else(|e| e.into_inner());
        removed_targets
            .into_iter()
            .filter_map(|target| guard.remove(&target))
            .collect::<Vec<_>>()
    };
    for data in callbacks {
        free_hook_data_callbacks(data);
    }
    unsafe {
        ffi::hook::hook_reclaim_retired();
    }
    !removal_failed
}

#[cfg(quickjs_hook_engine)]
fn hook_error_message(code: i32) -> &'static str {
    match code {
        HOOK_ERROR_NOT_INITIALIZED => "hook engine not initialized",
        HOOK_ERROR_INVALID_PARAM => "invalid hook parameter",
        HOOK_ERROR_ALREADY_HOOKED => "target is already hooked",
        HOOK_ERROR_ALLOC_FAILED => "hook engine memory allocation failed",
        HOOK_ERROR_MPROTECT_FAILED => "mprotect failed while patching target code",
        HOOK_ERROR_NOT_FOUND => "hook not found at target address",
        HOOK_ERROR_BUFFER_TOO_SMALL => "hook engine buffer too small for generated jump",
        HOOK_ERROR_WXSHADOW_FAILED => "wxshadow patch/release failed",
        _ => "unknown hook engine error",
    }
}

#[cfg(test)]
mod tests {
    use super::{
        classify_hook_stealth_arg, discard_local_invocation_frames, invocation_push, invocation_take,
        invocation_values, register_hook_api, store_invocation_value, take_invocation_value, take_invocation_values,
        HookStealthArg, InvocationFrame, DEFERRED_INVOCATIONS, HOOK_NORMAL, HOOK_RECOMP, HOOK_WXSHADOW,
        INVOCATION_STACK,
    };
    use crate::context::JSContext;
    use crate::ptr::register_ptr;
    use crate::runtime::JSRuntime;
    use std::sync::{Mutex, OnceLock};

    fn test_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    #[test]
    fn hook_stealth_modes_accept_i64_values_without_changing_js_constants() {
        assert_eq!(
            classify_hook_stealth_arg(i64::from(HOOK_NORMAL)),
            HookStealthArg::Normal
        );
        assert_eq!(
            classify_hook_stealth_arg(i64::from(HOOK_WXSHADOW)),
            HookStealthArg::WxShadow
        );
        assert_eq!(
            classify_hook_stealth_arg(i64::from(HOOK_RECOMP)),
            HookStealthArg::Recomp
        );
        assert_eq!(classify_hook_stealth_arg(-1), HookStealthArg::Unknown);
        assert_eq!(
            classify_hook_stealth_arg(i64::from(i32::MAX) + 1),
            HookStealthArg::Unknown
        );
    }

    #[test]
    fn interceptor_bootstrap_provides_frida_style_wrappers_and_flush() {
        let _guard = test_lock().lock().unwrap_or_else(|e| e.into_inner());
        let runtime = JSRuntime::new().expect("create QuickJS runtime");
        let context = JSContext::new(&runtime).expect("create QuickJS context");
        register_ptr(&context);
        register_hook_api(&context);

        let script = r#"
            (function () {
                var invocation = {};
                for (var i = 0; i < 31; i++) invocation["x" + i] = 0n;
                invocation.x0 = 0x123456789abcdef0n;

                var enterPointer;
                var enterLength;
                __iosRustFridaInterceptorEnter(function (args) {
                    enterPointer = args[0].toString();
                    enterLength = args.length;
                    args[1] = ptr("0xffffffffffffffff");
                    args[7] = -2;
                    this.marker = "shared";
                }, invocation);

                invocation.x0 = 0xffffffffn;
                var sameThis = false;
                var before;
                var after;
                __iosRustFridaInterceptorLeave(function (retval) {
                    sameThis = this === invocation && this.marker === "shared";
                    before = [retval.toInt32(), retval.toUInt32(), retval.toString()].join(",");
                    retval.replace(ptr("0x100000002"));
                    after = [retval.toInt32(), retval.toUInt32(), retval.toString()].join(",");
                }, invocation);

                var exceptionObserved = false;
                try {
                    __iosRustFridaInterceptorEnter(function () {
                        this.beforeThrow = "retained";
                        throw new Error("expected helper exception");
                    }, invocation);
                } catch (error) {
                    exceptionObserved = String(error).indexOf("expected helper exception") !== -1;
                }

                return [
                    enterPointer,
                    enterLength,
                    String(invocation.x1),
                    String(invocation.x7),
                    sameThis,
                    before,
                    after,
                    String(invocation.x0),
                    invocation.beforeThrow,
                    exceptionObserved,
                    typeof Interceptor.flush,
                    Interceptor.flush() === undefined
                ].join("|");
            })()
        "#;

        let result = context.eval(script, "<interceptor-test>").expect("evaluate wrappers");
        assert_eq!(
            result.to_string(context.as_ptr()).as_deref(),
            Some(
                "0x123456789abcdef0|8|-1|-2|true|-1,4294967295,0xffffffff|2,2,0x100000002|4294967298|retained|true|function|true"
            )
        );
        result.free(context.as_ptr());
    }

    #[test]
    fn invocation_stack_is_nested_exact_and_thread_local() {
        let _guard = test_lock().lock().unwrap_or_else(|e| e.into_inner());
        INVOCATION_STACK.with(|stack| stack.borrow_mut().clear());
        DEFERRED_INVOCATIONS.with(|deferred| deferred.borrow_mut().clear());
        invocation_values().lock().unwrap_or_else(|e| e.into_inner()).clear();

        let outer = InvocationFrame {
            ctx: 1,
            target: 0x1000,
            hook_ctx: 0x2000,
            value_id: store_invocation_value(1, 0x1000, [1; 16]),
        };
        let inner = InvocationFrame {
            ctx: 1,
            target: 0x3000,
            hook_ctx: 0x4000,
            value_id: store_invocation_value(1, 0x3000, [2; 16]),
        };
        invocation_push(outer);
        invocation_push(inner);

        std::thread::spawn(|| {
            assert!(invocation_take(1, 0x3000, 0x4000).is_none());
            let thread_frame = InvocationFrame {
                ctx: 9,
                target: 0x9000,
                hook_ctx: 0xa000,
                value_id: store_invocation_value(9, 0x9000, [9; 16]),
            };
            invocation_push(thread_frame);
            let taken = invocation_take(9, 0x9000, 0xa000).expect("thread invocation frame");
            assert_eq!(taken, thread_frame);
            assert_eq!(take_invocation_value(taken), Some([9; 16]));
        })
        .join()
        .expect("join invocation stack thread");

        let taken_inner = invocation_take(1, 0x3000, 0x4000).expect("inner invocation frame");
        assert_eq!(taken_inner, inner);
        assert_eq!(take_invocation_value(taken_inner), Some([2; 16]));
        let taken_outer = invocation_take(1, 0x1000, 0x2000).expect("outer invocation frame");
        assert_eq!(taken_outer, outer);
        assert_eq!(take_invocation_value(taken_outer), Some([1; 16]));
        assert!(invocation_take(1, 0x1000, 0x2000).is_none());
        assert!(invocation_values().lock().unwrap_or_else(|e| e.into_inner()).is_empty());
    }

    #[test]
    fn invocation_cleanup_is_scoped_to_one_runtime() {
        let _guard = test_lock().lock().unwrap_or_else(|e| e.into_inner());
        INVOCATION_STACK.with(|stack| stack.borrow_mut().clear());
        DEFERRED_INVOCATIONS.with(|deferred| deferred.borrow_mut().clear());
        invocation_values().lock().unwrap_or_else(|e| e.into_inner()).clear();

        let first = InvocationFrame {
            ctx: 1,
            target: 0x1000,
            hook_ctx: 0x2000,
            value_id: store_invocation_value(1, 0x1000, [1; 16]),
        };
        let second = InvocationFrame {
            ctx: 1,
            target: 0x3000,
            hook_ctx: 0x4000,
            value_id: store_invocation_value(1, 0x3000, [2; 16]),
        };
        let other_runtime = InvocationFrame {
            ctx: 9,
            target: 0x9000,
            hook_ctx: 0xa000,
            value_id: store_invocation_value(9, 0x9000, [9; 16]),
        };
        invocation_push(first);
        invocation_push(second);
        invocation_push(other_runtime);

        discard_local_invocation_frames(1, None);
        let mut cleaned = take_invocation_values(1, None);
        cleaned.sort();
        assert_eq!(cleaned, vec![[1; 16], [2; 16]]);
        assert!(invocation_take(1, 0x1000, 0x2000).is_none());
        assert!(invocation_take(1, 0x3000, 0x4000).is_none());

        let remaining = invocation_take(9, 0x9000, 0xa000).expect("other runtime frame");
        assert_eq!(remaining, other_runtime);
        assert_eq!(take_invocation_value(remaining), Some([9; 16]));
        assert!(invocation_values().lock().unwrap_or_else(|e| e.into_inner()).is_empty());
    }
}
