use crate::context::JSContext;
use crate::ffi;
use crate::ptr::get_native_pointer_addr;
use crate::util::{
    add_cfunction_to_object, js_i64_to_js_number_or_bigint, js_throw_internal_error, js_throw_range_error,
    js_throw_type_error,
};
use crate::value::JSValue;
use native_api::{find_image_by_address, normalize_code_pointer};

#[cfg(quickjs_hook_engine)]
use crate::console::output_message;
#[cfg(quickjs_hook_engine)]
use crate::util::{get_js_u64_property, js_u64_to_js_number_or_bigint, set_js_cfunction_property, set_js_u64_property};
#[cfg(quickjs_hook_engine)]
use native_api::{detect_hook_environment, resolve_hook_strategy};
#[cfg(quickjs_hook_engine)]
use std::collections::HashMap;
#[cfg(quickjs_hook_engine)]
use std::ffi::CStr;
#[cfg(quickjs_hook_engine)]
use std::os::raw::c_void;
#[cfg(quickjs_hook_engine)]
use std::sync::atomic::{AtomicU64, Ordering};
#[cfg(quickjs_hook_engine)]
use std::sync::{Condvar, Mutex, MutexGuard, Once, OnceLock};
#[cfg(quickjs_hook_engine)]
use std::time::{Duration, Instant};

const MAX_CALL_NATIVE_ARGS: usize = 6;
const MIN_VALID_CALL_TARGET: u64 = 0x1_0000;

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
    ctx: usize,
    mode: HookMode,
}

#[cfg(quickjs_hook_engine)]
#[derive(Clone, Copy)]
struct NativeHookFrame {
    ctx_ptr: usize,
    trampoline: u64,
    orig_called: bool,
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
}

#[cfg(quickjs_hook_engine)]
#[derive(Clone, Copy)]
enum AttachPhase {
    Enter,
    Leave,
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
}

#[cfg(not(quickjs_hook_engine))]
pub(crate) struct RuntimeJsGuard;

#[cfg(quickjs_hook_engine)]
pub(crate) fn enter_runtime_js(ctx: *mut ffi::JSContext) -> RuntimeJsGuard {
    if runtime_owner_is_current_thread() {
        unsafe {
            ffi::qjs_update_stack_top(ctx);
        }
        return RuntimeJsGuard {
            _inner: RuntimeJsGuardInner::Reentrant,
        };
    }

    let guard = JS_RUNTIME_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    mark_runtime_owner_current_thread();
    unsafe {
        ffi::qjs_update_stack_top(ctx);
    }

    RuntimeJsGuard {
        _inner: RuntimeJsGuardInner::Locked { _guard: guard },
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
        JSValue(*argv.add(2)).to_bool().unwrap_or(false)
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
    let trampoline = ffi::hook::hook_replace(
        target as *mut c_void,
        Some(hook_callback_wrapper),
        target as *mut c_void,
        if stealth { 1 } else { 0 },
    );

    if trampoline.is_null() {
        free_callback_bytes(ctx, callback_bytes);
        return js_throw_internal_error(
            ctx,
            "hook_replace failed: could not install hook on this target address",
        );
    }

    hook_registry().lock().unwrap_or_else(|e| e.into_inner()).insert(
        target,
        HookData {
            ctx: ctx as usize,
            mode: HookMode::Replace {
                callback_bytes,
                trampoline: trampoline as u64,
            },
        },
    );

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
        free_hook_data_callbacks(data);
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
        JSValue(*argv.add(2)).to_bool().unwrap_or(false)
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
        target as *mut c_void,
        if stealth { 1 } else { 0 },
    );

    if status != HOOK_OK {
        free_optional_callback_bytes(ctx, on_enter_bytes);
        free_optional_callback_bytes(ctx, on_leave_bytes);
        return js_throw_internal_error(ctx, hook_error_message(status));
    }

    hook_registry().lock().unwrap_or_else(|e| e.into_inner()).insert(
        target,
        HookData {
            ctx: ctx as usize,
            mode: HookMode::Attach {
                on_enter_bytes,
                on_leave_bytes,
            },
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
    _ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    cleanup_registered_hooks();
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
    let global = ctx.global_object();
    let interceptor = ctx.new_object();

    unsafe {
        let ctx_ptr = ctx.as_ptr();
        add_cfunction_to_object(ctx_ptr, global.raw(), "callNative", js_call_native, 1);
        add_cfunction_to_object(ctx_ptr, global.raw(), "hook", js_hook, 2);
        add_cfunction_to_object(ctx_ptr, global.raw(), "unhook", js_unhook, 1);
        add_cfunction_to_object(ctx_ptr, interceptor.raw(), "attach", js_interceptor_attach, 2);
        add_cfunction_to_object(ctx_ptr, interceptor.raw(), "replace", js_hook, 2);
        add_cfunction_to_object(ctx_ptr, interceptor.raw(), "revert", js_unhook, 1);
        add_cfunction_to_object(ctx_ptr, interceptor.raw(), "detachAll", js_interceptor_detach_all, 0);
    }

    global.set_property(ctx.as_ptr(), "Interceptor", interceptor);
    global.free(ctx.as_ptr());
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
    cleanup_registered_hooks();

    let mut pool = hook_engine_pool().lock().unwrap_or_else(|e| e.into_inner());
    let Some(pool_state) = pool.take() else {
        return;
    };

    unsafe {
        ffi::hook::hook_engine_cleanup();
        libc::munmap(pool_state.base, pool_state.size);
    }
}

#[cfg(not(quickjs_hook_engine))]
pub(crate) fn cleanup_hook_backend() {}

#[cfg(quickjs_hook_engine)]
fn enforce_hook_installation_policy() -> Result<(), String> {
    let decision = resolve_hook_strategy().map_err(|err| err.to_string())?;
    warn_external_hook_environment_once(&decision);

    if decision.inline_hooks_allowed {
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
    value.to_u64(ctx).unwrap_or(0)
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
fn native_hook_stack() -> &'static Mutex<Vec<NativeHookFrame>> {
    static STACK: OnceLock<Mutex<Vec<NativeHookFrame>>> = OnceLock::new();
    STACK.get_or_init(|| Mutex::new(Vec::new()))
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
fn try_enter_runtime_js_for_callback(
    ctx: *mut ffi::JSContext,
    context_name: &str,
    target: u64,
) -> Option<RuntimeJsGuard> {
    if runtime_owner_is_current_thread() {
        unsafe {
            ffi::qjs_update_stack_top(ctx);
        }
        return Some(RuntimeJsGuard {
            _inner: RuntimeJsGuardInner::Reentrant,
        });
    }

    let start = Instant::now();
    let mut spins = 0usize;

    loop {
        match JS_RUNTIME_LOCK.try_lock() {
            Ok(guard) => {
                mark_runtime_owner_current_thread();
                unsafe {
                    ffi::qjs_update_stack_top(ctx);
                }
                return Some(RuntimeJsGuard {
                    _inner: RuntimeJsGuardInner::Locked { _guard: guard },
                });
            }
            Err(std::sync::TryLockError::WouldBlock) => {
                if runtime_owner_is_current_thread() {
                    unsafe {
                        ffi::qjs_update_stack_top(ctx);
                    }
                    return Some(RuntimeJsGuard {
                        _inner: RuntimeJsGuardInner::Reentrant,
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
                mark_runtime_owner_current_thread();
                unsafe {
                    ffi::qjs_update_stack_top(ctx);
                }
                return Some(RuntimeJsGuard {
                    _inner: RuntimeJsGuardInner::Locked {
                        _guard: error.into_inner(),
                    },
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
fn free_hook_data_callbacks(data: HookData) {
    match data.mode {
        HookMode::Replace { callback_bytes, .. } => {
            free_callback_bytes(data.ctx as *mut ffi::JSContext, callback_bytes);
        }
        HookMode::Attach {
            on_enter_bytes,
            on_leave_bytes,
        } => {
            free_optional_callback_bytes(data.ctx as *mut ffi::JSContext, on_enter_bytes);
            free_optional_callback_bytes(data.ctx as *mut ffi::JSContext, on_leave_bytes);
        }
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
struct InFlightCallbackGuard;

#[cfg(quickjs_hook_engine)]
impl InFlightCallbackGuard {
    fn enter() -> Self {
        let mut guard = in_flight_callbacks().lock().unwrap_or_else(|e| e.into_inner());
        *guard += 1;
        Self
    }
}

#[cfg(quickjs_hook_engine)]
impl Drop for InFlightCallbackGuard {
    fn drop(&mut self) {
        let mut guard = in_flight_callbacks().lock().unwrap_or_else(|e| e.into_inner());
        *guard = guard.saturating_sub(1);
        if *guard == 0 {
            in_flight_callbacks_cv().notify_all();
        }
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
unsafe extern "C" fn hook_callback_wrapper(ctx_ptr: *mut ffi::hook::HookContext, user_data: *mut c_void) {
    if ctx_ptr.is_null() || user_data.is_null() {
        return;
    }

    let _in_flight_guard = InFlightCallbackGuard::enter();
    let target = user_data as u64;

    let (ctx_raw, callback_bytes, trampoline) = {
        let guard = hook_registry().lock().unwrap_or_else(|e| e.into_inner());
        let Some(data) = guard.get(&target).copied() else {
            return;
        };
        let HookMode::Replace {
            callback_bytes,
            trampoline,
        } = data.mode
        else {
            return;
        };
        (data.ctx, callback_bytes, trampoline)
    };

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
    attach_callback_wrapper(ctx_ptr, user_data, AttachPhase::Enter);
}

#[cfg(quickjs_hook_engine)]
unsafe extern "C" fn hook_attach_on_leave_wrapper(ctx_ptr: *mut ffi::hook::HookContext, user_data: *mut c_void) {
    attach_callback_wrapper(ctx_ptr, user_data, AttachPhase::Leave);
}

#[cfg(quickjs_hook_engine)]
unsafe fn attach_callback_wrapper(ctx_ptr: *mut ffi::hook::HookContext, user_data: *mut c_void, phase: AttachPhase) {
    if ctx_ptr.is_null() || user_data.is_null() {
        return;
    }

    let _in_flight_guard = InFlightCallbackGuard::enter();
    let target = user_data as u64;

    let (ctx_raw, callback_bytes) = {
        let guard = hook_registry().lock().unwrap_or_else(|e| e.into_inner());
        let Some(data) = guard.get(&target).copied() else {
            return;
        };
        let HookMode::Attach {
            on_enter_bytes,
            on_leave_bytes,
        } = data.mode
        else {
            return;
        };

        let callback_bytes = match phase {
            AttachPhase::Enter => on_enter_bytes,
            AttachPhase::Leave => on_leave_bytes,
        };
        let Some(callback_bytes) = callback_bytes else {
            return;
        };
        (data.ctx, callback_bytes)
    };

    let ctx = ctx_raw as *mut ffi::JSContext;
    let context_name = match phase {
        AttachPhase::Enter => "Interceptor.attach/onEnter",
        AttachPhase::Leave => "Interceptor.attach/onLeave",
    };

    let Some(_runtime_guard) = try_enter_runtime_js_for_callback(ctx, context_name, target) else {
        return;
    };

    let callback = std::ptr::read_unaligned(callback_bytes.as_ptr() as *const ffi::JSValue);
    let callback_dup = ffi::qjs_dup_value(ctx, callback);
    let js_ctx = build_hook_context(ctx, ctx_ptr, 0, false);
    let global = ffi::JS_GetGlobalObject(ctx);
    let result = ffi::JS_Call(ctx, callback_dup, global, 1, &js_ctx as *const _ as *mut _);

    if !handle_js_exception(ctx, result, context_name) {
        sync_js_context_to_native(ctx, js_ctx, ctx_ptr);
        if matches!(phase, AttachPhase::Leave) && ffi::qjs_is_undefined(result) == 0 {
            (*ctx_ptr).x[0] = js_value_to_u64_or_zero(ctx, JSValue(result));
        }
    }

    ffi::qjs_free_value(ctx, js_ctx);
    ffi::qjs_free_value(ctx, result);
    ffi::qjs_free_value(ctx, global);
    ffi::qjs_free_value(ctx, callback_dup);
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
fn cleanup_registered_hooks() {
    let targets = {
        let guard = hook_registry().lock().unwrap_or_else(|e| e.into_inner());
        guard.keys().copied().collect::<Vec<_>>()
    };

    for target in targets {
        unsafe {
            let _ = ffi::hook::hook_remove(target as *mut c_void);
        }
    }

    if !wait_for_in_flight_callbacks(Duration::from_millis(200)) {
        let remaining = *in_flight_callbacks().lock().unwrap_or_else(|e| e.into_inner());
        output_message(&format!(
            "[hook cleanup] waiting for in-flight callbacks timed out, remaining={remaining}"
        ));
    }

    let callbacks = {
        let mut guard = hook_registry().lock().unwrap_or_else(|e| e.into_inner());
        guard.drain().map(|(_, data)| data).collect::<Vec<_>>()
    };

    for data in callbacks {
        free_hook_data_callbacks(data);
    }
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
