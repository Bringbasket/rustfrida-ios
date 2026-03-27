#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuntimeStatus {
    Cold,
    Ready,
}

#[cfg(not(quickjs_runtime_stub))]
mod imp {
    use super::RuntimeStatus;
    use crate::agent_api::bootstrap_agent_api;
    use crate::completion::complete_script;
    use crate::console::{clear_console_callback, register_console, set_console_callback};
    use crate::context::JSContext;
    use crate::controller_api::bootstrap_controller_api;
    use crate::debug_symbol::register_debug_symbol_api;
    use crate::ffi;
    use crate::hook::{cleanup_hook_backend, enter_runtime_js, register_hook_api};
    use crate::memory::register_memory_api;
    use crate::module::register_module_api;
    use crate::native::register_native_api;
    use crate::native_hooks::bootstrap_native_hooks;
    use crate::objc::register_objc_api;
    use crate::pac::register_pac_api;
    use crate::ptr::register_ptr;
    use crate::swift::register_swift_api;
    use common::{Error, Result};
    use std::collections::BTreeSet;
    use std::ptr::NonNull;
    use std::sync::{Arc, Mutex};

    const DEFAULT_MEMORY_LIMIT: usize = 64 * 1024 * 1024;
    const DEFAULT_STACK_LIMIT: usize = 512 * 1024;

    pub struct QuickJsRuntime {
        status: RuntimeStatus,
        builtins: BTreeSet<&'static str>,
        last_script: Option<String>,
        engine: Option<QuickJsEngine>,
        pending_logs: Arc<Mutex<Vec<String>>>,
    }

    struct QuickJsEngine {
        context: JSContext,
        _runtime: JSRuntime,
    }

    impl Default for QuickJsRuntime {
        fn default() -> Self {
            Self::new()
        }
    }

    impl QuickJsRuntime {
        pub fn new() -> Self {
            Self {
                status: RuntimeStatus::Cold,
                builtins: builtin_set(),
                last_script: None,
                engine: None,
                pending_logs: Arc::new(Mutex::new(Vec::new())),
            }
        }

        pub fn status(&self) -> &RuntimeStatus {
            &self.status
        }

        pub fn initialize(&mut self) -> Result<String> {
            if self.status == RuntimeStatus::Ready {
                return Ok(self.bootstrap_script());
            }

            let runtime = JSRuntime::new().ok_or_else(|| Error::State("failed to create QuickJS runtime".into()))?;
            runtime.set_memory_limit(DEFAULT_MEMORY_LIMIT);
            runtime.set_max_stack_size(DEFAULT_STACK_LIMIT);

            let context = runtime
                .new_context()
                .ok_or_else(|| Error::State("failed to create QuickJS context".into()))?;

            let log_sink = Arc::clone(&self.pending_logs);
            set_console_callback(move |msg| {
                let mut guard = log_sink.lock().unwrap_or_else(|e| e.into_inner());
                guard.push(msg.to_string());
            });
            register_console(&context);
            register_ptr(&context);
            register_hook_api(&context);
            register_debug_symbol_api(&context);
            register_memory_api(&context);
            register_native_api(&context);
            register_objc_api(&context);
            register_module_api(&context);
            register_pac_api(&context);
            register_swift_api(&context);

            let bootstrap = self.bootstrap_script();
            let _runtime_guard = enter_runtime_js(context.as_ptr());
            let init_value = context.eval(&bootstrap, "<bootstrap>").map_err(Error::State)?;
            while context.execute_pending_job() {}
            init_value.free(context.as_ptr());

            self.engine = Some(QuickJsEngine {
                context,
                _runtime: runtime,
            });
            self.status = RuntimeStatus::Ready;
            Ok(bootstrap)
        }

        pub fn eval(&mut self, script: &str) -> Result<String> {
            if self.status != RuntimeStatus::Ready {
                return Err(Error::State("quickjs runtime is not initialized".into()));
            }
            let trimmed = script.trim();
            if trimmed.is_empty() {
                return Err(Error::InvalidArgument("script is empty".into()));
            }
            self.last_script = Some(trimmed.to_string());

            let engine = self
                .engine
                .as_mut()
                .ok_or_else(|| Error::State("quickjs runtime engine is missing".into()))?;
            let _runtime_guard = enter_runtime_js(engine.context.as_ptr());
            let value = engine.context.eval(trimmed, "<eval>").map_err(Error::State)?;
            while engine.context.execute_pending_job() {}

            let rendered = if value.is_undefined() {
                "undefined".to_string()
            } else {
                value
                    .to_string(engine.context.as_ptr())
                    .unwrap_or_else(|| "[unprintable]".to_string())
            };
            value.free(engine.context.as_ptr());
            Ok(rendered)
        }

        pub fn cleanup(&mut self) -> Result<String> {
            if self.status != RuntimeStatus::Ready {
                return Err(Error::State("quickjs runtime is not initialized".into()));
            }

            if let Some(engine) = self.engine.as_ref() {
                let _runtime_guard = enter_runtime_js(engine.context.as_ptr());
                cleanup_hook_backend();
            }

            self.engine = None;
            self.status = RuntimeStatus::Cold;
            self.last_script = None;
            self.pending_logs.lock().unwrap_or_else(|e| e.into_inner()).clear();
            clear_console_callback();
            Ok("cleaned up".into())
        }

        pub fn complete(&self, prefix: &str) -> Vec<String> {
            if self.status != RuntimeStatus::Ready {
                return self
                    .builtins
                    .iter()
                    .filter(|item| item.starts_with(prefix))
                    .map(|item| item.to_string())
                    .collect();
            }

            let Some(engine) = self.engine.as_ref() else {
                return Vec::new();
            };

            let _runtime_guard = enter_runtime_js(engine.context.as_ptr());
            let mut candidates = complete_script(&engine.context, prefix);
            if !prefix.contains('.') {
                candidates.extend(
                    self.builtins
                        .iter()
                        .filter(|item| item.starts_with(prefix))
                        .map(|item| item.to_string()),
                );
                candidates.sort();
                candidates.dedup();
            }
            candidates
        }

        pub fn take_pending_logs(&mut self) -> Vec<String> {
            let mut guard = self.pending_logs.lock().unwrap_or_else(|e| e.into_inner());
            std::mem::take(&mut *guard)
        }

        pub fn bootstrap_script(&self) -> String {
            let builtins = self
                .builtins
                .iter()
                .map(|name| format!("\"{name}\""))
                .collect::<Vec<_>>()
                .join(", ");

            let template = r#"globalThis.__iosRustFrida = { builtins: [__IOSRF_BUILTINS__], backendAvailable: true };
globalThis.Native = globalThis.Native || { platform: 'ios', backend: 'mach' };
globalThis.ObjC = globalThis.ObjC || { available: true };
globalThis.PAC = globalThis.PAC || { available: false };
globalThis.Swift = globalThis.Swift || { available: true };
globalThis.Module = globalThis.Module || {};
globalThis.Memory = globalThis.Memory || {};
globalThis.Interceptor = globalThis.Interceptor || {};
globalThis.Interceptor.replace = globalThis.Interceptor.replace || function(target, callback, stealth) {
    return hook(target, callback, stealth);
};
globalThis.Interceptor.revert = globalThis.Interceptor.revert || function(target) {
    return unhook(target);
};
globalThis.Interceptor.attach = globalThis.Interceptor.attach || function() {
    throw new Error('Interceptor.attach() is unavailable in this build; build quickjs-runtime with the native ARM64 hook engine enabled');
};
globalThis.Interceptor.detachAll = globalThis.Interceptor.detachAll || function() {
    throw new Error('Interceptor.detachAll() is unavailable in this build; build quickjs-runtime with the native ARM64 hook engine enabled');
};
__IOSRF_NATIVE_HOOKS__
__IOSRF_CONTROLLER_API__
__IOSRF_AGENT_API__
undefined;
"#;

            template
                .replace("__IOSRF_BUILTINS__", &builtins)
                .replace("__IOSRF_NATIVE_HOOKS__", bootstrap_native_hooks())
                .replace("__IOSRF_CONTROLLER_API__", bootstrap_controller_api())
                .replace("__IOSRF_AGENT_API__", bootstrap_agent_api())
        }
    }

    impl Drop for QuickJsRuntime {
        fn drop(&mut self) {
            if self.status == RuntimeStatus::Ready {
                let _ = self.cleanup();
            }
            clear_console_callback();
        }
    }

    pub struct JSRuntime {
        ptr: NonNull<ffi::JSRuntime>,
    }

    impl JSRuntime {
        pub fn new() -> Option<Self> {
            let ptr = unsafe { ffi::JS_NewRuntime() };
            NonNull::new(ptr).map(|ptr| JSRuntime { ptr })
        }

        pub fn new_context(&self) -> Option<JSContext> {
            JSContext::new(self)
        }

        pub fn as_ptr(&self) -> *mut ffi::JSRuntime {
            self.ptr.as_ptr()
        }

        pub fn set_memory_limit(&self, limit: usize) {
            unsafe {
                ffi::JS_SetMemoryLimit(self.ptr.as_ptr(), limit);
            }
        }

        pub fn run_gc(&self) {
            unsafe {
                ffi::JS_RunGC(self.ptr.as_ptr());
            }
        }

        pub fn set_max_stack_size(&self, stack_size: usize) {
            unsafe {
                ffi::JS_SetMaxStackSize(self.ptr.as_ptr(), stack_size);
            }
        }
    }

    impl Drop for JSRuntime {
        fn drop(&mut self) {
            unsafe {
                ffi::JS_FreeRuntime(self.ptr.as_ptr());
            }
        }
    }

    unsafe impl Send for JSRuntime {}
    unsafe impl Sync for JSRuntime {}

    impl Default for JSRuntime {
        fn default() -> Self {
            Self::new().expect("failed to create JSRuntime")
        }
    }

    fn builtin_set() -> BTreeSet<&'static str> {
        BTreeSet::from([
            "callNative",
            "console",
            "DebugSymbol",
            "hook",
            "Interceptor",
            "Memory",
            "Module",
            "Native",
            "ObjC",
            "PAC",
            "Swift",
            "ptr",
            "unhook",
        ])
    }

    #[cfg(test)]
    mod tests {
        use super::QuickJsRuntime;
        use std::sync::{Mutex, OnceLock};

        fn has_apple_objc_runtime() -> bool {
            cfg!(any(target_os = "macos", target_os = "ios"))
        }

        fn has_pac_support() -> bool {
            cfg!(all(
                any(target_os = "macos", target_os = "ios"),
                target_arch = "aarch64"
            ))
        }

        fn has_swift_support() -> bool {
            cfg!(any(target_os = "macos", target_os = "ios"))
        }

        fn test_lock() -> &'static Mutex<()> {
            static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
            LOCK.get_or_init(|| Mutex::new(()))
        }

        #[test]
        fn eval_basic_expression() {
            let _guard = test_lock().lock().unwrap_or_else(|e| e.into_inner());
            let mut runtime = QuickJsRuntime::new();
            runtime.initialize().expect("init runtime");
            let result = runtime.eval("1 + 2").expect("eval expression");
            assert_eq!(result, "3");
        }

        #[test]
        fn collect_console_logs() {
            let _guard = test_lock().lock().unwrap_or_else(|e| e.into_inner());
            let mut runtime = QuickJsRuntime::new();
            runtime.initialize().expect("init runtime");
            let result = runtime
                .eval("console.log('hello', 7); 40 + 2")
                .expect("eval expression");
            assert_eq!(result, "42");
            assert_eq!(runtime.take_pending_logs(), vec!["hello 7".to_string()]);
        }

        #[test]
        fn complete_global_names() {
            let _guard = test_lock().lock().unwrap_or_else(|e| e.into_inner());
            let mut runtime = QuickJsRuntime::new();
            runtime.initialize().expect("init runtime");
            let candidates = runtime.complete("cons");
            assert!(candidates.iter().any(|item| item == "console"));
        }

        #[test]
        fn objc_and_module_are_registered() {
            let _guard = test_lock().lock().unwrap_or_else(|e| e.into_inner());
            let mut runtime = QuickJsRuntime::new();
            runtime.initialize().expect("init runtime");

            let objc_available = if has_apple_objc_runtime() { "true" } else { "false" };
            assert_eq!(runtime.eval("ObjC.available").expect("objc available"), objc_available);
            assert_eq!(runtime.eval("typeof callNative").expect("callNative type"), "function");
            assert_eq!(
                runtime
                    .eval("typeof DebugSymbol.fromAddress")
                    .expect("DebugSymbol.fromAddress type"),
                "function"
            );
            assert_eq!(runtime.eval("typeof hook").expect("hook type"), "function");
            assert_eq!(runtime.eval("typeof unhook").expect("unhook type"), "function");
            assert_eq!(
                runtime
                    .eval("typeof Interceptor.attach")
                    .expect("Interceptor.attach type"),
                "function"
            );
            assert_eq!(
                runtime
                    .eval("typeof Interceptor.detachAll")
                    .expect("Interceptor.detachAll type"),
                "function"
            );
            assert_eq!(
                runtime.eval("ObjC.classExists('NSObject')").expect("objc classExists"),
                objc_available
            );
            assert_eq!(
                runtime.eval("typeof ObjC.findClasses").expect("objc findClasses type"),
                "function"
            );
            assert_eq!(
                runtime.eval("typeof ObjC.protocols").expect("objc protocols type"),
                "function"
            );
            assert_eq!(
                runtime
                    .eval("typeof ObjC.findProtocols")
                    .expect("objc findProtocols type"),
                "function"
            );
            assert_eq!(
                runtime
                    .eval("typeof ObjC.classProtocols")
                    .expect("objc classProtocols type"),
                "function"
            );
            assert_eq!(
                runtime.eval("typeof ObjC.classInfo").expect("objc classInfo type"),
                "function"
            );
            assert_eq!(
                runtime
                    .eval("typeof ObjC.protocolInfo")
                    .expect("objc protocolInfo type"),
                "function"
            );
            assert_eq!(
                runtime
                    .eval("typeof Swift.protocolInfo")
                    .expect("swift protocolInfo type"),
                "function"
            );
            assert_eq!(
                runtime
                    .eval("typeof Swift.conformanceInfo")
                    .expect("swift conformanceInfo type"),
                "function"
            );
            assert_eq!(
                runtime.eval("typeof Swift.typeInfo").expect("swift typeInfo type"),
                "function"
            );
            assert_eq!(
                runtime.eval("typeof Swift.methodInfo").expect("swift methodInfo type"),
                "function"
            );
            assert_eq!(
                runtime
                    .eval("typeof ObjC.protocolProtocols")
                    .expect("objc protocolProtocols type"),
                "function"
            );
            assert_eq!(
                runtime
                    .eval("typeof ObjC.protocolMethods")
                    .expect("objc protocolMethods type"),
                "function"
            );
            assert_eq!(
                runtime
                    .eval("typeof ObjC.protocolMethodInfo")
                    .expect("objc protocolMethodInfo type"),
                "function"
            );
            assert_eq!(
                runtime
                    .eval("typeof ObjC.protocolProperties")
                    .expect("objc protocolProperties type"),
                "function"
            );
            assert_eq!(
                runtime
                    .eval("typeof ObjC.protocolPropertyInfo")
                    .expect("objc protocolPropertyInfo type"),
                "function"
            );
            assert_eq!(
                runtime.eval("typeof ObjC.superclass").expect("objc superclass type"),
                "function"
            );
            assert_eq!(
                runtime.eval("typeof ObjC.classChain").expect("objc classChain type"),
                "function"
            );
            assert_eq!(
                runtime.eval("typeof ObjC.methodImp").expect("objc methodImp type"),
                "function"
            );
            assert_eq!(
                runtime.eval("typeof ObjC.methodInfo").expect("objc methodInfo type"),
                "function"
            );
            assert_eq!(
                runtime.eval("typeof ObjC.properties").expect("objc properties type"),
                "function"
            );
            assert_eq!(
                runtime
                    .eval("typeof ObjC.propertyInfo")
                    .expect("objc propertyInfo type"),
                "function"
            );
            assert_eq!(
                runtime.eval("typeof ObjC.ivarInfo").expect("objc ivarInfo type"),
                "function"
            );
            assert_eq!(
                runtime
                    .eval("typeof ObjC.findProperties")
                    .expect("objc findProperties type"),
                "function"
            );
            assert_eq!(runtime.eval("typeof ObjC.ivars").expect("objc ivars type"), "function");
            assert_eq!(
                runtime.eval("typeof ObjC.findIvars").expect("objc findIvars type"),
                "function"
            );
            assert_eq!(
                runtime.eval("typeof ObjC.classImage").expect("objc classImage type"),
                "function"
            );
            assert_eq!(
                runtime.eval("typeof ObjC.methodImage").expect("objc methodImage type"),
                "function"
            );
            assert_eq!(
                runtime.eval("typeof ObjC.methods").expect("objc methods type"),
                "function"
            );
            assert_eq!(
                runtime.eval("typeof ObjC.findMethods").expect("objc findMethods type"),
                "function"
            );
            assert_eq!(
                runtime
                    .eval("typeof ObjC.findMethodOwners")
                    .expect("objc findMethodOwners type"),
                "function"
            );
            assert_eq!(
                runtime
                    .eval("typeof ObjC.selectorName")
                    .expect("objc selectorName type"),
                "function"
            );
            assert_eq!(
                runtime
                    .eval("typeof ObjC.objectClassName")
                    .expect("objc objectClassName type"),
                "function"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() { const value = ObjC.methodImp('NSObject', 'description'); return ObjC.available ? (value === null || value.toString().indexOf('0x') === 0) : value === null; })()"
                    )
                    .expect("objc methodImp"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() { const value = ObjC.classImage('NSObject'); return ObjC.available ? (value === null || value.indexOf('/') !== -1) : value === null; })()"
                    )
                    .expect("objc classImage"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() { const value = ObjC.methodImage('NSObject', 'init'); return ObjC.available ? (value === null || value.indexOf('/') !== -1) : value === null; })()"
                    )
                    .expect("objc methodImage"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() { const value = ObjC.methodInfo('NSObject', 'init'); return value === null || (typeof value.selector === 'string' && typeof value.typeEncoding === 'string' && typeof value.isClassMethod === 'boolean'); })()"
                    )
                    .expect("objc methodInfo"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("Array.isArray(ObjC.methods('NSObject'))")
                    .expect("objc methods"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const methods = ObjC.methods('NSObject'); return methods.length === 0 || typeof methods[0].typeEncoding === 'string'; })()")
                    .expect("objc methods typeEncoding"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const methods = ObjC.methods('NSObject'); return methods.length === 0 || (typeof methods[0].returnTypeName === 'string' && Array.isArray(methods[0].argumentTypeNames) && typeof methods[0].methodTypeInfo === 'object'); })()")
                    .expect("objc methods decoded type info"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("Array.isArray(ObjC.findClasses('NSObject'))")
                    .expect("objc findClasses"),
                "true"
            );
            assert_eq!(
                runtime.eval("Array.isArray(ObjC.protocols())").expect("objc protocols"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("Array.isArray(ObjC.findProtocols('NS'))")
                    .expect("objc findProtocols"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("Array.isArray(ObjC.classProtocols('NSObject'))")
                    .expect("objc classProtocols"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const value = ObjC.classInfo('NSObject'); return value === null || (typeof value.className === 'string' && typeof value.isMetaClass === 'boolean' && typeof value.instanceSize === 'number'); })()")
                    .expect("objc classInfo"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const value = ObjC.protocolInfo('NSObject'); return value === null || (typeof value.protocolName === 'string' && Array.isArray(value.adoptedProtocols) && typeof value.propertyCount === 'number'); })()")
                    .expect("objc protocolInfo"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("Array.isArray(ObjC.protocolProtocols('NSObject'))")
                    .expect("objc protocolProtocols"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("Array.isArray(ObjC.protocolMethods('NSObject'))")
                    .expect("objc protocolMethods"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const methods = ObjC.protocolMethods('NSObject'); return methods.length === 0 || typeof methods[0].typeEncoding === 'string'; })()")
                    .expect("objc protocolMethods typeEncoding"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const methods = ObjC.protocolMethods('NSObject'); return methods.length === 0 || (typeof methods[0].returnTypeName === 'string' && Array.isArray(methods[0].argumentTypeNames) && typeof methods[0].methodTypeInfo === 'object'); })()")
                    .expect("objc protocolMethods decoded type info"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const value = ObjC.protocolMethodInfo('NSObject', 'description', false, false); return value === null || (typeof value.selector === 'string' && typeof value.typeEncoding === 'string' && typeof value.isRequired === 'boolean' && typeof value.isInstanceMethod === 'boolean'); })()")
                    .expect("objc protocolMethodInfo"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("Array.isArray(ObjC.protocolProperties('NSObject'))")
                    .expect("objc protocolProperties"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const value = ObjC.superclass('NSObject'); return ObjC.available ? (value === null || typeof value === 'string') : value === null; })()")
                    .expect("objc superclass"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("Array.isArray(ObjC.classChain('NSObject'))")
                    .expect("objc classChain"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("Array.isArray(ObjC.findMethods('NSObject', 'init'))")
                    .expect("objc findMethods"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("Array.isArray(ObjC.properties('NSObject'))")
                    .expect("objc properties"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("Array.isArray(ObjC.findProperties('NSObject', 'delegate'))")
                    .expect("objc findProperties"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const value = ObjC.protocolPropertyInfo('NSObject', 'description'); return value === null || (typeof value.name === 'string' && typeof value.attributes === 'string'); })()")
                    .expect("objc protocolPropertyInfo"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const value = ObjC.propertyInfo('NSObject', 'description'); return value === null || (typeof value.name === 'string' && typeof value.attributes === 'string' && typeof value.isClassProperty === 'boolean'); })()")
                    .expect("objc propertyInfo"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const value = ObjC.ivarInfo('NSObject', '_isa'); return value === null || (typeof value.name === 'string' && typeof value.typeEncoding === 'string' && typeof value.offset === 'number'); })()")
                    .expect("objc ivarInfo"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("Array.isArray(ObjC.ivars('NSObject'))")
                    .expect("objc ivars"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const ivars = ObjC.ivars('NSObject'); return ivars.length === 0 || (typeof ivars[0].typeName === 'string' && typeof ivars[0].typeInfo === 'object'); })()")
                    .expect("objc ivars decoded type info"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("Array.isArray(ObjC.findIvars('NSObject', 'delegate'))")
                    .expect("objc findIvars"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("Array.isArray(ObjC.findMethodOwners('init'))")
                    .expect("objc findMethodOwners"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("ObjC.selectorName(0) === null")
                    .expect("objc selectorName"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("ObjC.objectClassName(0) === null")
                    .expect("objc objectClassName"),
                "true"
            );
            let pac_available = if has_pac_support() { "true" } else { "false" };
            assert_eq!(runtime.eval("PAC.available").expect("pac available"), pac_available);
            assert_eq!(runtime.eval("typeof PAC.strip").expect("pac strip type"), "function");
            assert_eq!(
                runtime.eval("typeof PAC.stripData").expect("pac stripData type"),
                "function"
            );
            assert_eq!(
                runtime.eval("typeof PAC.isProcessArm64e").expect("pac arm64e type"),
                "function"
            );
            assert_eq!(
                runtime.eval("typeof PAC.isImageArm64e").expect("pac image arm64e type"),
                "function"
            );
            assert_eq!(
                runtime.eval("typeof PAC.arm64eImages").expect("pac arm64e images type"),
                "function"
            );
            assert_eq!(
                runtime
                    .eval("PAC.strip(ptr('0x1234')).toString()")
                    .expect("pac strip value"),
                "0x1234"
            );
            assert_eq!(
                runtime
                    .eval("PAC.isImageArm64e('libsystem_malloc.dylib') === null || PAC.isImageArm64e('libsystem_malloc.dylib') === false || PAC.isImageArm64e('libsystem_malloc.dylib') === true")
                    .expect("pac image arm64e value"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("Array.isArray(PAC.arm64eImages())")
                    .expect("pac arm64e images"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const images = PAC.arm64eImages(); return images.length === 0 || (typeof images[0].name === 'string' && typeof images[0].path === 'string' && (typeof images[0].size === 'number' || typeof images[0].size === 'bigint')); })()")
                    .expect("pac arm64e image shape"),
                "true"
            );
            let swift_available = if has_swift_support() { "true" } else { "false" };
            assert_eq!(
                runtime.eval("Swift.available").expect("swift available"),
                swift_available
            );
            assert_eq!(
                runtime.eval("typeof Swift.demangle").expect("swift demangle type"),
                "function"
            );
            assert_eq!(
                runtime
                    .eval("(function() { return typeof Swift.symbols === 'function' && typeof Swift.protocols === 'function' && typeof Swift.conformances === 'function' && typeof Swift.metadata === 'function' && typeof Swift.vtable === 'function' && typeof Swift.witnessTable === 'function' && typeof Swift.typeLayout === 'function' && typeof Swift.types === 'function' && typeof Swift.typeKinds === 'function' && typeof Swift.typesOfKind === 'function' && typeof Swift.methodOwners === 'function' && typeof Swift.typeMethods === 'function' && typeof Swift.methods === 'function'; })()")
                    .expect("swift alias types"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("typeof Swift.findProtocols")
                    .expect("swift findProtocols type"),
                "function"
            );
            assert_eq!(
                runtime
                    .eval("typeof Swift.findConformances")
                    .expect("swift findConformances type"),
                "function"
            );
            assert_eq!(
                runtime
                    .eval("typeof Swift.findMetadata")
                    .expect("swift findMetadata type"),
                "function"
            );
            assert_eq!(
                runtime
                    .eval("typeof Swift.metadataInfo")
                    .expect("swift metadataInfo type"),
                "function"
            );
            assert_eq!(
                runtime.eval("typeof Swift.findVtable").expect("swift findVtable type"),
                "function"
            );
            assert_eq!(
                runtime.eval("typeof Swift.vtableInfo").expect("swift vtableInfo type"),
                "function"
            );
            assert_eq!(
                runtime
                    .eval("typeof Swift.findWitnessTable")
                    .expect("swift findWitnessTable type"),
                "function"
            );
            assert_eq!(
                runtime
                    .eval("typeof Swift.witnessTableInfo")
                    .expect("swift witnessTableInfo type"),
                "function"
            );
            assert_eq!(
                runtime
                    .eval("typeof Swift.findTypeLayout")
                    .expect("swift findTypeLayout type"),
                "function"
            );
            assert_eq!(
                runtime
                    .eval("typeof Swift.typeLayoutInfo")
                    .expect("swift typeLayoutInfo type"),
                "function"
            );
            assert_eq!(
                runtime
                    .eval("typeof Swift.findSymbols")
                    .expect("swift findSymbols type"),
                "function"
            );
            assert_eq!(
                runtime.eval("typeof Swift.symbolInfo").expect("swift symbolInfo type"),
                "function"
            );
            assert_eq!(
                runtime.eval("typeof Swift.findTypes").expect("swift findTypes type"),
                "function"
            );
            assert_eq!(
                runtime
                    .eval("typeof Swift.findTypesOfKind")
                    .expect("swift findTypesOfKind type"),
                "function"
            );
            assert_eq!(
                runtime
                    .eval("typeof Swift.findMethodOwners")
                    .expect("swift findMethodOwners type"),
                "function"
            );
            assert_eq!(
                runtime
                    .eval("typeof Swift.typeSourceKinds")
                    .expect("swift typeSourceKinds type"),
                "function"
            );
            assert_eq!(
                runtime
                    .eval("typeof Swift.findTypeMethods")
                    .expect("swift findTypeMethods type"),
                "function"
            );
            assert_eq!(
                runtime
                    .eval("typeof Swift.findMethods")
                    .expect("swift findMethods type"),
                "function"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() { const value = Swift.demangle('$s4Demo6methodyyF'); return value === null || value.indexOf('Demo') !== -1 || value.indexOf('method') !== -1; })()"
                    )
                    .expect("swift demangle"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("Array.isArray(Swift.findProtocols())")
                    .expect("swift findProtocols"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("Array.isArray(Swift.findConformances('ViewController'))")
                    .expect("swift findConformances"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("Array.isArray(Swift.findMetadata('ViewController'))")
                    .expect("swift findMetadata"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const value = Swift.metadataInfo('ViewController'); return value === null || (typeof value.name === 'string' && typeof value.sourceKind === 'string' && typeof value.sourceSymbolName === 'string'); })()")
                    .expect("swift metadataInfo"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("Array.isArray(Swift.findVtable('ViewController'))")
                    .expect("swift findVtable"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const value = Swift.vtableInfo('ViewController', 'viewDidLoad'); return value === null || (typeof value.typeName === 'string' && typeof value.memberName === 'string' && typeof value.isDispatchThunk === 'boolean'); })()")
                    .expect("swift vtableInfo"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("Array.isArray(Swift.findWitnessTable('Renderable'))")
                    .expect("swift findWitnessTable"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const value = Swift.witnessTableInfo('ViewController', 'Renderable'); return value === null || (typeof value.typeName === 'string' && typeof value.protocolName === 'string' && typeof value.isAccessor === 'boolean'); })()")
                    .expect("swift witnessTableInfo"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("Array.isArray(Swift.findTypeLayout('ViewController'))")
                    .expect("swift findTypeLayout"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const value = Swift.typeLayoutInfo('ViewController'); return value === null || (typeof value.name === 'string' && Array.isArray(value.metadata) && typeof value.vtableEntries.length === 'number' && typeof value.witnessTables.length === 'number'); })()")
                    .expect("swift typeLayoutInfo"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("Array.isArray(Swift.findSymbols('ViewController'))")
                    .expect("swift findSymbols"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const value = Swift.symbolInfo('ViewController'); return value === null || (typeof value.name === 'string' && typeof value.moduleName === 'string' && typeof value.address === 'object'); })()")
                    .expect("swift symbolInfo"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("Array.isArray(Swift.findTypes('ViewController'))")
                    .expect("swift findTypes"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const types = Swift.findTypes('ViewController'); return types.length === 0 || ('sourceAddress' in types[0] && 'sourceOffset' in types[0] && 'sourceKind' in types[0]); })()")
                    .expect("swift findTypes source location"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("Array.isArray(Swift.findTypesOfKind('metadata-accessor', 'ViewController'))")
                    .expect("swift findTypesOfKind"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("Array.isArray(Swift.findMethodOwners('viewDidLoad'))")
                    .expect("swift findMethodOwners"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("Array.isArray(Swift.typeSourceKinds())")
                    .expect("swift typeSourceKinds"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("Array.isArray(Swift.findTypeMethods('ViewController'))")
                    .expect("swift findTypeMethods"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("Array.isArray(Swift.findMethods('ViewController', 'viewDidLoad'))")
                    .expect("swift findMethods"),
                "true"
            );
            assert_eq!(
                runtime.eval("Array.isArray(Swift.typeKinds())").expect("swift typeKinds"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("Array.isArray(Swift.types('ViewController'))")
                    .expect("swift types alias"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("Array.isArray(Module.enumerateModules())")
                    .expect("enumerate modules"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const modules = Module.enumerateModules(); return modules.length === 0 || (typeof modules[0].name === 'string' && typeof modules[0].path === 'string' && (typeof modules[0].size === 'number' || typeof modules[0].size === 'bigint')); })()")
                    .expect("enumerate modules shape"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() { const value = Module.findBaseAddress('libobjc.A.dylib'); return value === null || value.toString().indexOf('0x') === 0; })()"
                    )
                    .expect("find base"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("DebugSymbol.fromAddress(0) === null")
                    .expect("debug symbol missing"),
                "true"
            );
        }

        #[test]
        fn module_finds_exports() {
            let _guard = test_lock().lock().unwrap_or_else(|e| e.into_inner());
            let mut runtime = QuickJsRuntime::new();
            runtime.initialize().expect("init runtime");

            assert_eq!(
                runtime
                    .eval("Module.findExportByName(null, 'malloc') !== null")
                    .expect("find export"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("Module.findExportByName(null, '__ios_rustfrida_symbol_that_does_not_exist__') === null")
                    .expect("missing export"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("DebugSymbol.fromAddress(Module.findExportByName(null, 'malloc')).moduleName.length > 0")
                    .expect("debug symbol module name"),
                "true"
            );
        }

        #[test]
        fn bootstrap_script_uses_unavailable_interceptor_fallback_messages() {
            let runtime = QuickJsRuntime::new();
            let bootstrap = runtime.bootstrap_script();
            assert!(!bootstrap.contains("not implemented on iOS yet"));
            assert!(bootstrap.contains("Interceptor.attach() is unavailable in this build"));
            assert!(bootstrap.contains("Interceptor.detachAll() is unavailable in this build"));
        }

        #[test]
        fn native_hook_helpers_are_bootstrapped() {
            let _guard = test_lock().lock().unwrap_or_else(|e| e.into_inner());
            let mut runtime = QuickJsRuntime::new();
            runtime.initialize().expect("init runtime");

            assert_eq!(
                runtime
                    .eval("typeof __iosRustFridaNativeHooks.describeCall")
                    .expect("native hook helper type"),
                "function"
            );
            assert_eq!(
                runtime
                    .eval("typeof __iosRustFridaNativeHooks.installTrace")
                    .expect("native hook installTrace type"),
                "function"
            );
            assert_eq!(
                runtime
                    .eval("typeof __iosRustFridaNativeHooks.installStalker")
                    .expect("native hook installStalker type"),
                "function"
            );

            let bytes = b"hello.txt\0";
            let addr = bytes.as_ptr() as usize;
            let script = format!(
                "JSON.stringify(__iosRustFridaNativeHooks.describeCall('open', {{ x0: ptr('0x{addr:x}'), x1: 0x201, x2: 0o644 }}))"
            );
            let rendered = runtime.eval(&script).expect("describe open call");
            assert!(rendered.contains("path="));
            assert!(rendered.contains("flags=O_WRONLY|O_CREAT"));
            assert!(rendered.contains("mode=0o644"));
        }

        #[test]
        fn native_detect_hook_environment_is_bootstrapped() {
            let _guard = test_lock().lock().unwrap_or_else(|e| e.into_inner());
            let mut runtime = QuickJsRuntime::new();
            runtime.initialize().expect("init runtime");

            assert_eq!(
                runtime
                    .eval("typeof Native.detectHookEnvironment")
                    .expect("native detect hook env type"),
                "function"
            );
            assert_eq!(
                runtime.eval("typeof Native.images").expect("native images type"),
                "function"
            );
            assert_eq!(
                runtime.eval("typeof Native.export").expect("native export type"),
                "function"
            );
            assert_eq!(
                runtime.eval("typeof Native.base").expect("native base type"),
                "function"
            );
            assert_eq!(
                runtime
                    .eval("typeof Native.mainImage")
                    .expect("native mainImage type"),
                "function"
            );
            assert_eq!(
                runtime.eval("typeof Native.image").expect("native image type"),
                "function"
            );
            assert_eq!(
                runtime.eval("typeof Native.symbol").expect("native symbol type"),
                "function"
            );
            assert_eq!(
                runtime
                    .eval("(function() { return typeof Native.symbols === 'function' && typeof Native.exports === 'function' && typeof Native.dependencies === 'function' && typeof Native.encryptionInfo === 'function' && typeof Native.dyldInfo === 'function' && typeof Native.entryPoint === 'function' && typeof Native.sourceVersion === 'function' && typeof Native.buildVersion === 'function' && typeof Native.dylinker === 'function' && typeof Native.installName === 'function' && typeof Native.linkedit === 'function' && typeof Native.functionStarts === 'function' && typeof Native.codeSignature === 'function' && typeof Native.dataInCode === 'function' && typeof Native.exportsTrie === 'function' && typeof Native.chainedFixups === 'function' && typeof Native.uuid === 'function' && typeof Native.rpaths === 'function' && typeof Native.imports === 'function' && typeof Native.segments === 'function' && typeof Native.sections === 'function' && typeof Native.loadCommands === 'function'; })()")
                    .expect("native alias types"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("typeof Native.findSymbols")
                    .expect("native find symbols type"),
                "function"
            );
            assert_eq!(
                runtime
                    .eval("typeof Native.symbolInfo")
                    .expect("native symbol info type"),
                "function"
            );
            assert_eq!(
                runtime
                    .eval("typeof Native.findExports")
                    .expect("native find exports type"),
                "function"
            );
            assert_eq!(
                runtime
                    .eval("typeof Native.exportInfo")
                    .expect("native export info type"),
                "function"
            );
            assert_eq!(
                runtime
                    .eval("typeof Native.imageInfo")
                    .expect("native image info type"),
                "function"
            );
            assert_eq!(
                runtime
                    .eval("typeof Native.findSegments")
                    .expect("native find segments type"),
                "function"
            );
            assert_eq!(
                runtime
                    .eval("typeof Native.findSections")
                    .expect("native find sections type"),
                "function"
            );
            assert_eq!(
                runtime
                    .eval("typeof Native.findLoadCommands")
                    .expect("native find load commands type"),
                "function"
            );
            assert_eq!(
                runtime
                    .eval("typeof Native.importInfo")
                    .expect("native import info type"),
                "function"
            );
            assert_eq!(
                runtime.eval("typeof Native.rpathInfo").expect("native rpath info type"),
                "function"
            );
            assert_eq!(
                runtime
                    .eval("typeof Native.dependencyInfo")
                    .expect("native dependency info type"),
                "function"
            );
            assert_eq!(
                runtime
                    .eval("Array.isArray(Native.detectHookEnvironment().backends)")
                    .expect("native hook env backends"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("Array.isArray(Native.detectHookEnvironment().recommendations)")
                    .expect("native hook env recommendations"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("Array.isArray(Native.findSymbols('malloc'))")
                    .expect("native find symbols"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("Array.isArray(Native.symbols('malloc'))")
                    .expect("native symbols alias"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const value = Native.symbolInfo('malloc'); return value === null || (typeof value.name === 'string' && typeof value.moduleName === 'string' && typeof value.address === 'object'); })()")
                    .expect("native symbolInfo"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("Array.isArray(Native.findExports('libsystem_malloc.dylib'))")
                    .expect("native find exports"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("Array.isArray(Native.exports('libsystem_malloc.dylib'))")
                    .expect("native exports alias"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const value = Native.exportInfo('libsystem_malloc.dylib', 'malloc'); return value === null || (typeof value.name === 'string' && typeof value.moduleName === 'string' && typeof value.address === 'object'); })()")
                    .expect("native exportInfo"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const value = Native.imageInfo('libsystem_malloc.dylib'); return value === null || (typeof value.name === 'string' && typeof value.path === 'string' && typeof value.base === 'object' && (typeof value.size === 'number' || typeof value.size === 'bigint')); })()")
                    .expect("native imageInfo"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const values = Native.images(); return Array.isArray(values) && (values.length === 0 || (typeof values[0].name === 'string' && typeof values[0].path === 'string' && typeof values[0].base === 'object' && (typeof values[0].size === 'number' || typeof values[0].size === 'bigint'))); })()")
                    .expect("native images"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const value = Native.export(null, 'malloc'); return value === null || value.toString().indexOf('0x') === 0; })()")
                    .expect("native export"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const value = Native.base('libsystem_malloc.dylib'); return value === null || value.toString().indexOf('0x') === 0; })()")
                    .expect("native base"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const value = Native.mainImage(); return value === null || (typeof value.name === 'string' && typeof value.path === 'string' && typeof value.base === 'object' && (typeof value.size === 'number' || typeof value.size === 'bigint')); })()")
                    .expect("native mainImage"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const address = Module.findExportByName(null, 'malloc'); if (address === null) { return true; } const value = Native.image(address); return value === null || (typeof value.name === 'string' && typeof value.path === 'string' && typeof value.base === 'object' && (typeof value.size === 'number' || typeof value.size === 'bigint')); })()")
                    .expect("native image"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const address = Module.findExportByName(null, 'malloc'); if (address === null) { return true; } const value = Native.symbol(address); return value === null || (typeof value.moduleName === 'string' && (value.name === null || typeof value.name === 'string') && typeof value.moduleBase === 'object'); })()")
                    .expect("native symbol"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const value = Native.importInfo('libsystem_malloc.dylib', 'malloc'); return value === null || (typeof value.name === 'string' && typeof value.moduleName === 'string' && typeof value.dylibOrdinal === 'number'); })()")
                    .expect("native importInfo"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const value = Native.rpathInfo('libsystem_malloc.dylib', '@loader_path'); return value === null || (typeof value.path === 'string' && typeof value.moduleName === 'string'); })()")
                    .expect("native rpathInfo"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const value = Native.dependencyInfo('libsystem_malloc.dylib', 'libSystem.B.dylib'); return value === null || (typeof value.path === 'string' && typeof value.kind === 'string' && typeof value.ordinal === 'number'); })()")
                    .expect("native dependencyInfo"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("Array.isArray(Native.findSegments('libsystem_malloc.dylib'))")
                    .expect("native find segments"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("Array.isArray(Native.segments('libsystem_malloc.dylib'))")
                    .expect("native segments alias"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("Array.isArray(Native.findSections('libsystem_malloc.dylib'))")
                    .expect("native find sections"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("typeof Native.sectionInfo")
                    .expect("native section info type"),
                "function"
            );
            assert_eq!(
                runtime
                    .eval("typeof Native.segmentInfo")
                    .expect("native segment info type"),
                "function"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const value = Native.sectionInfo('libsystem_malloc.dylib', '__TEXT', '__text'); return value === null || (typeof value.segmentName === 'string' && typeof value.name === 'string' && typeof value.addr === 'object'); })()")
                    .expect("native sectionInfo"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const value = Native.segmentInfo('libsystem_malloc.dylib', '__TEXT'); return value === null || (typeof value.name === 'string' && typeof value.moduleName === 'string' && typeof value.vmaddr === 'object'); })()")
                    .expect("native segmentInfo"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("Array.isArray(Native.findLoadCommands('libsystem_malloc.dylib'))")
                    .expect("native find load commands"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("Array.isArray(Native.loadCommands('libsystem_malloc.dylib'))")
                    .expect("native load commands alias"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("typeof Native.loadCommandInfo")
                    .expect("native load command info type"),
                "function"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const commands = Native.findLoadCommands('libsystem_malloc.dylib'); return commands.length === 0 || ('detail' in commands[0]); })()")
                    .expect("native load command detail property"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const value = Native.loadCommandInfo('libsystem_malloc.dylib', 'LC_UUID'); return value === null || (typeof value.name === 'string' && typeof value.moduleName === 'string' && typeof value.cmd === 'number'); })()")
                    .expect("native loadCommandInfo"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("typeof Native.detectHookEnvironment().strategy")
                    .expect("native hook env strategy"),
                "string"
            );
        }

        #[test]
        fn controller_helpers_are_bootstrapped() {
            let _guard = test_lock().lock().unwrap_or_else(|e| e.into_inner());
            let mut runtime = QuickJsRuntime::new();
            runtime.initialize().expect("init runtime");

            assert_eq!(
                runtime
                    .eval("typeof __iosRustFridaControllerApi.installHfl")
                    .expect("controller hfl helper type"),
                "function"
            );
            assert_eq!(
                runtime
                    .eval("typeof __iosRustFridaControllerApi.detachHflHooks")
                    .expect("controller hfl detach helper type"),
                "function"
            );
            assert_eq!(
                runtime
                    .eval("typeof __iosRustFridaControllerApi.installObjcHook")
                    .expect("controller objc hook helper type"),
                "function"
            );
            assert_eq!(
                runtime
                    .eval("typeof __iosRustFridaControllerApi.detachObjcHooks")
                    .expect("controller objc detach helper type"),
                "function"
            );
            assert_eq!(
                runtime
                    .eval("typeof __iosRustFridaControllerApi.installObjcTrace")
                    .expect("controller objc trace helper type"),
                "function"
            );
            assert_eq!(
                runtime
                    .eval("typeof __iosRustFridaControllerApi.installObjcStalker")
                    .expect("controller objc stalker helper type"),
                "function"
            );
            assert_eq!(
                runtime
                    .eval("typeof __iosRustFridaControllerApi.installNativeTrace")
                    .expect("controller native trace helper type"),
                "function"
            );
            assert_eq!(
                runtime
                    .eval("typeof __iosRustFridaControllerApi.installNativeTraceExport")
                    .expect("controller native trace export helper type"),
                "function"
            );
            assert_eq!(
                runtime
                    .eval("typeof __iosRustFridaControllerApi.installNativeTraceAddress")
                    .expect("controller native trace address helper type"),
                "function"
            );
            assert_eq!(
                runtime
                    .eval("typeof __iosRustFridaControllerApi.installNativeStalker")
                    .expect("controller native stalker helper type"),
                "function"
            );
            assert_eq!(
                runtime
                    .eval("typeof __iosRustFridaControllerApi.installNativeStalkerExport")
                    .expect("controller native stalker export helper type"),
                "function"
            );
            assert_eq!(
                runtime
                    .eval("typeof __iosRustFridaControllerApi.installNativeStalkerAddress")
                    .expect("controller native stalker address helper type"),
                "function"
            );
            assert_eq!(
                runtime
                    .eval("typeof __iosRustFridaControllerApi.dispatch")
                    .expect("controller dispatch helper type"),
                "function"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() { const previousBase = Module.findBaseAddress; const previousAttach = Interceptor.attach; Module.findBaseAddress = function() { return ptr('0x180000000'); }; Interceptor.attach = function() { return { detach() {} }; }; try { const result = __iosRustFridaControllerApi.dispatchResult({ kind: 'hfl.install', moduleName: 'UIKit', offsetHex: '0x1234' }); return result.kind === 'hfl.install' && result.currentKey === 'UIKit+0x1234' && result.currentTarget && result.currentTarget.key === 'UIKit+0x1234' && result.count === 1 && result.replacedCount === 0; } finally { Module.findBaseAddress = previousBase; Interceptor.attach = previousAttach; globalThis.__iosRustFridaHfl = {}; globalThis.__iosRustFridaHflCurrentKey = null; } })()"
                    )
                    .expect("controller hfl install result includes current target"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() { const previousBase = Module.findBaseAddress; const previousAttach = Interceptor.attach; Module.findBaseAddress = function() { return ptr('0x180000000'); }; Interceptor.attach = function() { return { detach() {} }; }; try { const text = __iosRustFridaControllerApi.dispatch({ kind: 'hfl.install', moduleName: 'UIKit', offsetHex: '0x1234' }); return text.indexOf('hfl installed: UIKit+0x1234') === 0 && text.indexOf('UIKit+0x1234 current=on') !== -1; } finally { Module.findBaseAddress = previousBase; Interceptor.attach = previousAttach; globalThis.__iosRustFridaHfl = {}; globalThis.__iosRustFridaHflCurrentKey = null; } })()"
                    )
                    .expect("controller hfl install text renders current target"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() { const previousClassExists = ObjC.classExists; const previousMethodImp = ObjC.methodImp; const previousAttach = Interceptor.attach; ObjC.classExists = function() { return true; }; ObjC.methodImp = function() { return ptr('0x18000abcd'); }; Interceptor.attach = function() { return { detach() {} }; }; try { const result = __iosRustFridaControllerApi.dispatchResult({ kind: 'objc.hook.install', className: 'UIViewController', selectorName: 'viewDidLoad', isClassMethod: false }); return result.kind === 'objc.hook.install' && result.currentKey === '-[UIViewController viewDidLoad]' && result.currentTarget && result.currentTarget.key === '-[UIViewController viewDidLoad]' && result.count === 1 && result.replacedCount === 0; } finally { ObjC.classExists = previousClassExists; ObjC.methodImp = previousMethodImp; Interceptor.attach = previousAttach; globalThis.__iosRustFridaObjcHooks = {}; globalThis.__iosRustFridaObjcHooksCurrentKey = null; } })()"
                    )
                    .expect("controller objc hook install result includes current target"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() { const previousClassExists = ObjC.classExists; const previousMethodImp = ObjC.methodImp; const previousAttach = Interceptor.attach; ObjC.classExists = function() { return true; }; ObjC.methodImp = function() { return ptr('0x18000abcd'); }; Interceptor.attach = function() { return { detach() {} }; }; try { const text = __iosRustFridaControllerApi.dispatch({ kind: 'objc.hook.install', className: 'UIViewController', selectorName: 'viewDidLoad', isClassMethod: false }); return text.indexOf('jhook installed: -[UIViewController viewDidLoad]') === 0 && text.indexOf('-[UIViewController viewDidLoad] current=on') !== -1; } finally { ObjC.classExists = previousClassExists; ObjC.methodImp = previousMethodImp; Interceptor.attach = previousAttach; globalThis.__iosRustFridaObjcHooks = {}; globalThis.__iosRustFridaObjcHooksCurrentKey = null; } })()"
                    )
                    .expect("controller objc hook install text renders current target"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() { const previousFindMethods = Swift.findMethods; const previousAttach = Interceptor.attach; Swift.findMethods = function() { return [{ address: ptr('0x18000beef'), name: '$s4MyApp14ViewControllerC11viewDidLoadyyF', demangledName: 'MyApp.ViewController.viewDidLoad()', moduleName: 'MyApp' }]; }; Interceptor.attach = function() { return { detach() {} }; }; try { const result = __iosRustFridaControllerApi.dispatchResult({ kind: 'swift.hook.install', moduleName: 'MyApp', typeName: 'ViewController', methodQuery: 'viewDidLoad' }); return result.kind === 'swift.hook.install' && result.currentKey === 'MyApp::ViewController::viewDidLoad' && result.currentTarget && result.currentTarget.key === 'MyApp::ViewController::viewDidLoad' && result.count === 1 && result.activeCount === 1 && Array.isArray(result.resolvedTargets) && result.resolvedTargets.length === 1 && result.replacedCount === 0; } finally { Swift.findMethods = previousFindMethods; Interceptor.attach = previousAttach; globalThis.__iosRustFridaSwiftHooks = {}; globalThis.__iosRustFridaSwiftHooksCurrentKey = null; } })()"
                    )
                    .expect("controller swift hook install result includes current target"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() { const previousFindMethods = Swift.findMethods; const previousAttach = Interceptor.attach; Swift.findMethods = function() { return [{ address: ptr('0x18000beef'), name: '$s4MyApp14ViewControllerC11viewDidLoadyyF', demangledName: 'MyApp.ViewController.viewDidLoad()', moduleName: 'MyApp' }]; }; Interceptor.attach = function() { return { detach() {} }; }; try { const text = __iosRustFridaControllerApi.dispatch({ kind: 'swift.hook.install', moduleName: 'MyApp', typeName: 'ViewController', methodQuery: 'viewDidLoad' }); return text.indexOf('shook installed: MyApp::ViewController::viewDidLoad') === 0 && text.indexOf('MyApp::ViewController::viewDidLoad current=on count=1') !== -1; } finally { Swift.findMethods = previousFindMethods; Interceptor.attach = previousAttach; globalThis.__iosRustFridaSwiftHooks = {}; globalThis.__iosRustFridaSwiftHooksCurrentKey = null; } })()"
                    )
                    .expect("controller swift hook install text renders current target"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() { const helper = __iosRustFridaNativeHooks; const previous = helper.installTraceResult; helper.installTraceResult = function(spec) { return { action: 'install', active: true, currentKey: 'trace-export:*:malloc', currentSession: { key: 'trace-export:*:malloc', label: '*!malloc', filter: null, targetAddress: '0x180006000', targetKind: 'export', targetSymbol: 'malloc', moduleName: null, symbolName: 'malloc', objcMode: null }, sessionCount: 2, sessions: [{ key: 'objc-trace:UIView', label: 'objc_msgSend', filter: 'UIView', targetAddress: '0x180004000', targetKind: 'export', targetSymbol: 'objc_msgSend', moduleName: null, symbolName: 'objc_msgSend', objcMode: 'trace' }, { key: 'trace-export:*:malloc', label: '*!malloc', filter: null, targetAddress: '0x180006000', targetKind: 'export', targetSymbol: 'malloc', moduleName: null, symbolName: 'malloc', objcMode: null }], targetKind: 'export', targetAddress: '0x180006000', targetSymbol: 'malloc', moduleName: null, symbolName: 'malloc', resolvedLabel: '*!malloc', templateArgs: null, templateRet: null, key: 'trace-export:*:malloc', replacedCount: 0, replacedLabel: null, replacedSessionCount: 0, replacedSession: null, replacedSessions: [], message: 'trace installed: *!malloc (hook logs flush on the next JS command)' }; }; try { const result = __iosRustFridaControllerApi.dispatchResult({ kind: 'native.trace.install', target: { kind: 'export', moduleName: null, symbolName: 'malloc' } }); return result.kind === 'native.trace.install' && result.scope === 'trace' && result.target && result.target.kind === 'export' && result.target.symbolName === 'malloc' && result.currentKey === 'trace-export:*:malloc' && result.currentSession && result.currentSession.key === 'trace-export:*:malloc' && result.sessionCount === 2 && Array.isArray(result.sessions) && result.sessions.length === 2 && result.replacedSession === null && Array.isArray(result.replacedSessions) && result.replacedSessions.length === 0; } finally { helper.installTraceResult = previous; } })()"
                    )
                    .expect("controller trace install result includes registry snapshot"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() { const helper = __iosRustFridaNativeHooks; const previous = helper.installTraceResult; helper.installTraceResult = function(spec) { return { action: 'install', active: true, currentKey: 'trace-export:*:malloc', currentSession: { key: 'trace-export:*:malloc', label: '*!malloc', filter: null, targetAddress: '0x180006000', targetKind: 'export', targetSymbol: 'malloc', moduleName: null, symbolName: 'malloc', objcMode: null }, sessionCount: 2, sessions: [{ key: 'objc-trace:UIView', label: 'objc_msgSend', filter: 'UIView', targetAddress: '0x180004000', targetKind: 'export', targetSymbol: 'objc_msgSend', moduleName: null, symbolName: 'objc_msgSend', objcMode: 'trace' }, { key: 'trace-export:*:malloc', label: '*!malloc', filter: null, targetAddress: '0x180006000', targetKind: 'export', targetSymbol: 'malloc', moduleName: null, symbolName: 'malloc', objcMode: null }], targetKind: 'export', targetAddress: '0x180006000', targetSymbol: 'malloc', moduleName: null, symbolName: 'malloc', resolvedLabel: '*!malloc', templateArgs: null, templateRet: null, key: 'trace-export:*:malloc', replacedCount: 0, replacedLabel: null, replacedSessionCount: 0, replacedSession: null, replacedSessions: [], message: 'trace installed: *!malloc (hook logs flush on the next JS command)' }; }; try { const text = __iosRustFridaControllerApi.dispatch({ kind: 'native.trace.install', target: { kind: 'export', moduleName: null, symbolName: 'malloc' } }); return text.indexOf('trace installed: *!malloc') === 0 && text.indexOf('key=objc-trace:UIView') !== -1 && text.indexOf('key=trace-export:*:malloc current=on') !== -1; } finally { helper.installTraceResult = previous; } })()"
                    )
                    .expect("controller trace install text renders sessions"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() { const helper = __iosRustFridaNativeHooks; const previous = helper.installStalkerResult; helper.installStalkerResult = function(spec) { return { action: 'install', active: true, currentKey: 'objc-stalker:UIView', currentSession: { key: 'objc-stalker:UIView', label: 'objc_msgSend + objc_msgSendSuper2', filter: 'UIView', targetAddress: '0x180005000', secondaryTargetAddress: '0x180005100', targetKind: 'export', targetSymbol: 'objc_msgSend', moduleName: null, symbolName: 'objc_msgSend', objcMode: 'stalker', superEnabled: true, count: 2 }, sessionCount: 1, sessions: [{ key: 'objc-stalker:UIView', label: 'objc_msgSend + objc_msgSendSuper2', filter: 'UIView', targetAddress: '0x180005000', secondaryTargetAddress: '0x180005100', targetKind: 'export', targetSymbol: 'objc_msgSend', moduleName: null, symbolName: 'objc_msgSend', objcMode: 'stalker', superEnabled: true, count: 2 }], targetKind: 'export', targetAddress: '0x180005000', secondaryTargetAddress: '0x180005100', targetSymbol: 'objc_msgSend', moduleName: null, symbolName: 'objc_msgSend', resolvedLabel: 'objc_msgSend + objc_msgSendSuper2', objcMode: 'stalker', superEnabled: true, filter: 'UIView', count: 2, key: 'objc-stalker:UIView', replacedCount: 0, replacedLabel: null, replacedSessionCount: 0, replacedSession: null, replacedSessions: [], message: 'stalker installed: objc_msgSend + objc_msgSendSuper2 filter=UIView (hook logs flush on the next JS command)' }; }; try { const result = __iosRustFridaControllerApi.dispatchResult({ kind: 'objc.stalker.install', filter: 'UIView' }); return result.kind === 'objc.stalker.install' && result.scope === 'stalker' && result.currentKey === 'objc-stalker:UIView' && result.currentSession && result.currentSession.key === 'objc-stalker:UIView' && result.sessionCount === 1 && Array.isArray(result.sessions) && result.sessions.length === 1 && result.sessions[0].secondaryTargetAddress === '0x180005100' && result.replacedSession === null && Array.isArray(result.replacedSessions) && result.replacedSessions.length === 0; } finally { helper.installStalkerResult = previous; } })()"
                    )
                    .expect("controller stalker install result includes registry snapshot"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() { const helper = __iosRustFridaNativeHooks; const previous = helper.installStalkerResult; helper.installStalkerResult = function(spec) { return { action: 'install', active: true, currentKey: 'objc-stalker:UIView', currentSession: { key: 'objc-stalker:UIView', label: 'objc_msgSend + objc_msgSendSuper2', filter: 'UIView', targetAddress: '0x180005000', secondaryTargetAddress: '0x180005100', targetKind: 'export', targetSymbol: 'objc_msgSend', moduleName: null, symbolName: 'objc_msgSend', objcMode: 'stalker', superEnabled: true, count: 2 }, sessionCount: 1, sessions: [{ key: 'objc-stalker:UIView', label: 'objc_msgSend + objc_msgSendSuper2', filter: 'UIView', targetAddress: '0x180005000', secondaryTargetAddress: '0x180005100', targetKind: 'export', targetSymbol: 'objc_msgSend', moduleName: null, symbolName: 'objc_msgSend', objcMode: 'stalker', superEnabled: true, count: 2 }], targetKind: 'export', targetAddress: '0x180005000', secondaryTargetAddress: '0x180005100', targetSymbol: 'objc_msgSend', moduleName: null, symbolName: 'objc_msgSend', resolvedLabel: 'objc_msgSend + objc_msgSendSuper2', objcMode: 'stalker', superEnabled: true, filter: 'UIView', count: 2, key: 'objc-stalker:UIView', replacedCount: 0, replacedLabel: null, replacedSessionCount: 0, replacedSession: null, replacedSessions: [], message: 'stalker installed: objc_msgSend + objc_msgSendSuper2 filter=UIView (hook logs flush on the next JS command)' }; }; try { const text = __iosRustFridaControllerApi.dispatch({ kind: 'objc.stalker.install', filter: 'UIView' }); return text.indexOf('stalker installed: objc_msgSend + objc_msgSendSuper2 filter=UIView') === 0 && text.indexOf('key=objc-stalker:UIView current=on') !== -1 && text.indexOf('super=on') !== -1; } finally { helper.installStalkerResult = previous; } })()"
                    )
                    .expect("controller stalker install text renders sessions"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("typeof __iosRustFridaControllerApi.dispatchResult")
                    .expect("controller dispatch result helper type"),
                "function"
            );
            assert_eq!(
                runtime
                    .eval("typeof __iosRustFridaAgentApi.handle")
                    .expect("agent api helper type"),
                "function"
            );
            assert_eq!(
                runtime
                    .eval("typeof __iosRustFridaControllerApi.stopTrace")
                    .expect("controller stop trace helper type"),
                "function"
            );
            assert_eq!(
                runtime
                    .eval("typeof __iosRustFridaControllerApi.traceStatus")
                    .expect("controller trace status helper type"),
                "function"
            );
            assert_eq!(
                runtime
                    .eval("typeof __iosRustFridaNativeHooks.stopTraceResult")
                    .expect("native hook stop trace result helper type"),
                "function"
            );
            assert_eq!(
                runtime
                    .eval("typeof __iosRustFridaControllerApi.stopStalker")
                    .expect("controller stop stalker helper type"),
                "function"
            );
            assert_eq!(
                runtime
                    .eval("typeof __iosRustFridaControllerApi.stalkerStatus")
                    .expect("controller stalker status helper type"),
                "function"
            );
            assert_eq!(
                runtime
                    .eval("typeof __iosRustFridaNativeHooks.stopStalkerResult")
                    .expect("native hook stop stalker result helper type"),
                "function"
            );
            assert_eq!(
                runtime
                    .eval("typeof __iosRustFridaControllerApi.installSwiftHook")
                    .expect("controller swift hook helper type"),
                "function"
            );
            assert_eq!(
                runtime
                    .eval("typeof __iosRustFridaControllerApi.detachSwiftHooks")
                    .expect("controller swift detach helper type"),
                "function"
            );
            assert_eq!(
                runtime
                    .eval("JSON.stringify(__iosRustFridaControllerApi.dispatchResult({ kind: 'hfl.stop' }))")
                    .expect("controller hfl stop result"),
                "{\"kind\":\"hfl.stop\",\"action\":\"stop\",\"scope\":\"hfl\",\"active\":false,\"targeted\":false,\"requestedKey\":null,\"count\":0,\"keys\":[],\"targets\":[],\"targetMatched\":true,\"matchedTargetCount\":0,\"matchedTargets\":[],\"detachedTargetCount\":0,\"detachedTargets\":[],\"message\":\"hfl detached: 0\"}"
            );
            assert_eq!(
                runtime
                    .eval("JSON.stringify(__iosRustFridaControllerApi.dispatchResult({ kind: 'hfl.status' }))")
                    .expect("controller hfl status result"),
                "{\"kind\":\"hfl.status\",\"action\":\"status\",\"active\":false,\"count\":0,\"keys\":[],\"targets\":[],\"currentKey\":null,\"currentTarget\":null,\"message\":\"hfl inactive\"}"
            );
            assert_eq!(
                runtime
                    .eval("JSON.stringify(__iosRustFridaControllerApi.dispatchResult({ kind: 'objc.hook.status' }))")
                    .expect("controller objc hook status result"),
                "{\"kind\":\"objc.hook.status\",\"action\":\"status\",\"active\":false,\"count\":0,\"keys\":[],\"targets\":[],\"currentKey\":null,\"currentTarget\":null,\"message\":\"jhook inactive\"}"
            );
            assert_eq!(
                runtime
                    .eval("JSON.stringify(__iosRustFridaControllerApi.dispatchResult({ kind: 'trace.status' }))")
                    .expect("controller trace status result"),
                "{\"active\":false,\"count\":0,\"sessionCount\":0,\"sessions\":[],\"currentKey\":null,\"currentSession\":null,\"label\":null,\"filter\":null,\"targetAddress\":null,\"targetKind\":null,\"targetSymbol\":null,\"moduleName\":null,\"symbolName\":null,\"objcMode\":null,\"message\":\"trace inactive\",\"kind\":\"trace.status\",\"action\":\"status\",\"scope\":\"trace\"}"
            );
            assert_eq!(
                runtime
                    .eval("JSON.stringify(__iosRustFridaControllerApi.dispatchResult({ kind: 'stalker.status' }))")
                    .expect("controller stalker status result"),
                "{\"active\":false,\"count\":0,\"sessionCount\":0,\"sessions\":[],\"currentKey\":null,\"currentSession\":null,\"label\":null,\"filter\":null,\"targetAddress\":null,\"secondaryTargetAddress\":null,\"targetKind\":null,\"targetSymbol\":null,\"moduleName\":null,\"symbolName\":null,\"objcMode\":null,\"superEnabled\":false,\"message\":\"stalker inactive\",\"kind\":\"stalker.status\",\"action\":\"status\",\"scope\":\"stalker\"}"
            );
            assert_eq!(
                runtime
                    .eval("JSON.stringify(__iosRustFridaControllerApi.dispatchResult({ kind: 'swift.hook.status' }))")
                    .expect("controller swift hook status result"),
                "{\"kind\":\"swift.hook.status\",\"action\":\"status\",\"active\":false,\"count\":0,\"keys\":[],\"targets\":[],\"currentKey\":null,\"currentTarget\":null,\"message\":\"shook inactive\"}"
            );
            assert_eq!(
                runtime
                    .eval("__iosRustFridaControllerApi.dispatch({ kind: 'hfl.status' })")
                    .expect("controller hfl status text"),
                "hfl inactive"
            );
            assert_eq!(
                runtime
                    .eval("__iosRustFridaControllerApi.dispatch({ kind: 'objc.hook.status' })")
                    .expect("controller objc hook status text"),
                "jhook inactive"
            );
            assert_eq!(
                runtime
                    .eval("__iosRustFridaControllerApi.dispatch({ kind: 'trace.status' })")
                    .expect("controller trace status text"),
                "trace inactive"
            );
            assert_eq!(
                runtime
                    .eval("__iosRustFridaControllerApi.dispatch({ kind: 'stalker.status' })")
                    .expect("controller stalker status text"),
                "stalker inactive"
            );
            assert_eq!(
                runtime
                    .eval("__iosRustFridaControllerApi.dispatch({ kind: 'swift.hook.status' })")
                    .expect("controller swift hook status text"),
                "shook inactive"
            );
            assert_eq!(
                runtime
                    .eval("(function() { globalThis.__iosRustFridaHfl = { 'libobjc.A.dylib+0x1234': { moduleName: 'libobjc.A.dylib', offsetHex: '0x1234', target: '0x180001234' } }; return JSON.stringify(__iosRustFridaControllerApi.dispatchResult({ kind: 'hfl.status' })); })()")
                    .expect("controller populated hfl status result"),
                "{\"kind\":\"hfl.status\",\"action\":\"status\",\"active\":true,\"count\":1,\"keys\":[\"libobjc.A.dylib+0x1234\"],\"targets\":[{\"key\":\"libobjc.A.dylib+0x1234\",\"moduleName\":\"libobjc.A.dylib\",\"offsetHex\":\"0x1234\",\"target\":\"0x180001234\"}],\"currentKey\":\"libobjc.A.dylib+0x1234\",\"currentTarget\":{\"key\":\"libobjc.A.dylib+0x1234\",\"moduleName\":\"libobjc.A.dylib\",\"offsetHex\":\"0x1234\",\"target\":\"0x180001234\"},\"message\":\"hfl active: 1\"}"
            );
            assert_eq!(
                runtime
                    .eval("(function() { globalThis.__iosRustFridaHfl = { 'libobjc.A.dylib+0x1234': { moduleName: 'libobjc.A.dylib', offsetHex: '0x1234', target: '0x180001234' } }; return __iosRustFridaControllerApi.dispatch({ kind: 'hfl.status' }); })()")
                    .expect("controller populated hfl status text"),
                "hfl active: 1\n - libobjc.A.dylib+0x1234 current=on target=0x180001234"
            );
            assert_eq!(
                runtime
                    .eval("(function() { globalThis.__iosRustFridaObjcHooks = { '-[UIViewController viewDidLoad]': { className: 'UIViewController', selectorName: 'viewDidLoad', isClassMethod: false, target: '0x18000abcd' } }; return JSON.stringify(__iosRustFridaControllerApi.dispatchResult({ kind: 'objc.hook.status' })); })()")
                    .expect("controller populated objc hook status result"),
                "{\"kind\":\"objc.hook.status\",\"action\":\"status\",\"active\":true,\"count\":1,\"keys\":[\"-[UIViewController viewDidLoad]\"],\"targets\":[{\"key\":\"-[UIViewController viewDidLoad]\",\"className\":\"UIViewController\",\"selectorName\":\"viewDidLoad\",\"isClassMethod\":false,\"target\":\"0x18000abcd\"}],\"currentKey\":\"-[UIViewController viewDidLoad]\",\"currentTarget\":{\"key\":\"-[UIViewController viewDidLoad]\",\"className\":\"UIViewController\",\"selectorName\":\"viewDidLoad\",\"isClassMethod\":false,\"target\":\"0x18000abcd\"},\"message\":\"jhook active: 1\"}"
            );
            assert_eq!(
                runtime
                    .eval("(function() { globalThis.__iosRustFridaObjcHooks = { '-[UIViewController viewDidLoad]': { className: 'UIViewController', selectorName: 'viewDidLoad', isClassMethod: false, target: '0x18000abcd' } }; return __iosRustFridaControllerApi.dispatch({ kind: 'objc.hook.status' }); })()")
                    .expect("controller populated objc hook status text"),
                "jhook active: 1\n - -[UIViewController viewDidLoad] current=on target=0x18000abcd"
            );
            assert_eq!(
                runtime
                    .eval("(function() { globalThis.__iosRustFridaTrace = { label: 'objc_msgSend', targetAddress: '0x180004000', targetKind: 'export', targetSymbol: 'objc_msgSend', filter: 'UIView', objcMode: 'trace' }; return __iosRustFridaControllerApi.dispatch({ kind: 'trace.status' }); })()")
                    .expect("controller populated trace status text"),
                "trace active: objc_msgSend\n - key=objc-trace:UIView current=on target=0x180004000 kind=export symbol=objc_msgSend filter=UIView objcMode=trace"
            );
            assert_eq!(
                runtime
                    .eval("(function() { globalThis.__iosRustFridaTraceRegistry = { 'objc-trace:UIView': { label: 'objc_msgSend', targetAddress: '0x180004000', targetKind: 'export', targetSymbol: 'objc_msgSend', moduleName: null, symbolName: 'objc_msgSend', filter: 'UIView', objcMode: 'trace' }, 'trace-export:*:malloc': { label: '*!malloc', targetAddress: '0x180006000', targetKind: 'export', targetSymbol: 'malloc', moduleName: null, symbolName: 'malloc', objcMode: null } }; globalThis.__iosRustFridaTraceCurrentKey = 'trace-export:*:malloc'; return __iosRustFridaControllerApi.dispatch({ kind: 'trace.status' }); })()")
                    .expect("controller multi trace status text"),
                "trace active: 2\n - key=objc-trace:UIView target=0x180004000 kind=export symbol=objc_msgSend filter=UIView objcMode=trace\n - key=trace-export:*:malloc current=on target=0x180006000 kind=export symbol=malloc"
            );
            assert_eq!(
                runtime
                    .eval("(function() { globalThis.__iosRustFridaStalker = { handles: [{}, {}], label: 'objc_msgSend + objc_msgSendSuper2', targetAddress: '0x180005000', secondaryTargetAddress: '0x180005100', targetKind: 'export', targetSymbol: 'objc_msgSend', filter: 'UIView', objcMode: 'stalker', superEnabled: true }; return __iosRustFridaControllerApi.dispatch({ kind: 'stalker.status' }); })()")
                    .expect("controller populated stalker status text"),
                "stalker active: objc_msgSend + objc_msgSendSuper2\n - key=objc-stalker:UIView current=on target=0x180005000 secondary=0x180005100 kind=export symbol=objc_msgSend filter=UIView objcMode=stalker super=on"
            );
            assert_eq!(
                runtime
                    .eval("(function() { globalThis.__iosRustFridaSwiftHooks = { 'MyApp::ViewController::viewDidLoad': { moduleName: 'MyApp', typeName: 'ViewController', methodQuery: 'viewDidLoad', targets: [{ address: '0x18000beef', name: '$s4MyApp14ViewControllerC11viewDidLoadyyF', demangledName: 'MyApp.ViewController.viewDidLoad()', moduleName: 'MyApp' }] } }; return JSON.stringify(__iosRustFridaControllerApi.dispatchResult({ kind: 'swift.hook.status' })); })()")
                    .expect("controller populated swift hook status result"),
                "{\"kind\":\"swift.hook.status\",\"action\":\"status\",\"active\":true,\"count\":1,\"keys\":[\"MyApp::ViewController::viewDidLoad\"],\"targets\":[{\"key\":\"MyApp::ViewController::viewDidLoad\",\"moduleName\":\"MyApp\",\"typeName\":\"ViewController\",\"methodQuery\":\"viewDidLoad\",\"count\":1,\"targets\":[{\"address\":\"0x18000beef\",\"name\":\"$s4MyApp14ViewControllerC11viewDidLoadyyF\",\"demangledName\":\"MyApp.ViewController.viewDidLoad()\",\"moduleName\":\"MyApp\"}]}],\"currentKey\":\"MyApp::ViewController::viewDidLoad\",\"currentTarget\":{\"key\":\"MyApp::ViewController::viewDidLoad\",\"moduleName\":\"MyApp\",\"typeName\":\"ViewController\",\"methodQuery\":\"viewDidLoad\",\"count\":1,\"targets\":[{\"address\":\"0x18000beef\",\"name\":\"$s4MyApp14ViewControllerC11viewDidLoadyyF\",\"demangledName\":\"MyApp.ViewController.viewDidLoad()\",\"moduleName\":\"MyApp\"}]},\"message\":\"shook active: 1\"}"
            );
            assert_eq!(
                runtime
                    .eval("(function() { globalThis.__iosRustFridaSwiftHooks = { 'MyApp::ViewController::viewDidLoad': { moduleName: 'MyApp', typeName: 'ViewController', methodQuery: 'viewDidLoad', targets: [{ address: '0x18000beef', name: '$s4MyApp14ViewControllerC11viewDidLoadyyF', demangledName: 'MyApp.ViewController.viewDidLoad()', moduleName: 'MyApp' }] } }; return __iosRustFridaControllerApi.dispatch({ kind: 'swift.hook.status' }); })()")
                    .expect("controller populated swift hook status text"),
                "shook active: 1\n - MyApp::ViewController::viewDidLoad current=on count=1\n   - address=0x18000beef name=MyApp.ViewController.viewDidLoad() module=MyApp"
            );
            assert_eq!(
                runtime
                    .eval("(function() { globalThis.__iosRustFridaHfl = { 'libobjc.A.dylib+0x1234': { moduleName: 'libobjc.A.dylib', offsetHex: '0x1234', target: '0x180001234' } }; return JSON.stringify(__iosRustFridaControllerApi.dispatchResult({ kind: 'hfl.stop' })); })()")
                    .expect("controller populated hfl stop result"),
                "{\"kind\":\"hfl.stop\",\"action\":\"stop\",\"scope\":\"hfl\",\"active\":true,\"targeted\":false,\"requestedKey\":null,\"count\":0,\"keys\":[\"libobjc.A.dylib+0x1234\"],\"targets\":[{\"key\":\"libobjc.A.dylib+0x1234\",\"moduleName\":\"libobjc.A.dylib\",\"offsetHex\":\"0x1234\",\"target\":\"0x180001234\"}],\"targetMatched\":true,\"matchedTargetCount\":1,\"matchedTargets\":[{\"key\":\"libobjc.A.dylib+0x1234\",\"moduleName\":\"libobjc.A.dylib\",\"offsetHex\":\"0x1234\",\"target\":\"0x180001234\"}],\"detachedTargetCount\":1,\"detachedTargets\":[{\"key\":\"libobjc.A.dylib+0x1234\",\"moduleName\":\"libobjc.A.dylib\",\"offsetHex\":\"0x1234\",\"target\":\"0x180001234\"}],\"message\":\"hfl detached: 0\"}"
            );
            assert_eq!(
                runtime
                    .eval("(function() { globalThis.__iosRustFridaHfl = { 'libobjc.A.dylib+0x1234': { moduleName: 'libobjc.A.dylib', offsetHex: '0x1234', target: '0x180001234' } }; return __iosRustFridaControllerApi.dispatch({ kind: 'hfl.stop' }); })()")
                    .expect("controller populated hfl stop text"),
                "hfl detached: 0\n - libobjc.A.dylib+0x1234 target=0x180001234"
            );
            assert_eq!(
                runtime
                    .eval("(function() { globalThis.__iosRustFridaHfl = { 'libobjc.A.dylib+0x1234': { moduleName: 'libobjc.A.dylib', offsetHex: '0x1234', target: '0x180001234' }, 'UIKit+0x2222': { moduleName: 'UIKit', offsetHex: '0x2222', target: '0x180002222' } }; return JSON.stringify(__iosRustFridaControllerApi.dispatchResult({ kind: 'hfl.stop', moduleName: 'UIKit', offsetHex: '0x2222' })); })()")
                    .expect("controller targeted hfl stop result"),
                "{\"kind\":\"hfl.stop\",\"action\":\"stop\",\"scope\":\"hfl\",\"active\":true,\"targeted\":true,\"requestedKey\":\"UIKit+0x2222\",\"count\":0,\"keys\":[\"UIKit+0x2222\"],\"targets\":[{\"key\":\"UIKit+0x2222\",\"moduleName\":\"UIKit\",\"offsetHex\":\"0x2222\",\"target\":\"0x180002222\"}],\"targetMatched\":true,\"matchedTargetCount\":1,\"matchedTargets\":[{\"key\":\"UIKit+0x2222\",\"moduleName\":\"UIKit\",\"offsetHex\":\"0x2222\",\"target\":\"0x180002222\"}],\"detachedTargetCount\":1,\"detachedTargets\":[{\"key\":\"UIKit+0x2222\",\"moduleName\":\"UIKit\",\"offsetHex\":\"0x2222\",\"target\":\"0x180002222\"}],\"message\":\"hfl detached: 0 for UIKit+0x2222\"}"
            );
            assert_eq!(
                runtime
                    .eval("(function() { globalThis.__iosRustFridaHfl = { 'libobjc.A.dylib+0x1234': { moduleName: 'libobjc.A.dylib', offsetHex: '0x1234', target: '0x180001234' }, 'UIKit+0x2222': { moduleName: 'UIKit', offsetHex: '0x2222', target: '0x180002222' } }; return __iosRustFridaControllerApi.dispatch({ kind: 'hfl.stop', moduleName: 'UIKit', offsetHex: '0x2222' }); })()")
                    .expect("controller targeted hfl stop text"),
                "hfl detached: 0 for UIKit+0x2222\n - UIKit+0x2222 target=0x180002222"
            );
            assert_eq!(
                runtime
                    .eval("(function() { globalThis.__iosRustFridaTraceRegistry = {}; globalThis.__iosRustFridaTraceCurrentKey = null; globalThis.__iosRustFridaTrace = {}; return JSON.stringify(__iosRustFridaControllerApi.dispatchResult({ kind: 'trace.stop' })); })()")
                    .expect("controller trace stop result"),
                "{\"active\":false,\"count\":0,\"sessionCount\":0,\"sessions\":[],\"selectorMatched\":true,\"matchedSessionCount\":0,\"matchedSessions\":[],\"detachedSessionCount\":0,\"detachedSessions\":[],\"label\":null,\"filter\":null,\"targetAddress\":null,\"targetKind\":null,\"targetSymbol\":null,\"moduleName\":null,\"symbolName\":null,\"objcMode\":null,\"message\":\"trace stopped\",\"kind\":\"trace.stop\",\"action\":\"stop\",\"scope\":\"trace\"}"
            );
            assert_eq!(
                runtime
                    .eval("(function() { globalThis.__iosRustFridaTrace = { label: 'objc_msgSend', targetAddress: '0x180004000', targetKind: 'export', targetSymbol: 'objc_msgSend', filter: 'UIView', objcMode: 'trace' }; return __iosRustFridaControllerApi.dispatch({ kind: 'trace.stop' }); })()")
                    .expect("controller populated trace stop text"),
                "trace stopped: objc_msgSend detached=0\n - key=objc-trace:UIView target=0x180004000 kind=export symbol=objc_msgSend filter=UIView objcMode=trace"
            );
            assert_eq!(
                runtime
                    .eval("(function() { globalThis.__iosRustFridaTraceRegistry = { 'objc-trace:UIView': { label: 'objc_msgSend', targetAddress: '0x180004000', targetKind: 'export', targetSymbol: 'objc_msgSend', moduleName: null, symbolName: 'objc_msgSend', filter: 'UIView', objcMode: 'trace' }, 'trace-export:*:malloc': { label: '*!malloc', targetAddress: '0x180006000', targetKind: 'export', targetSymbol: 'malloc', moduleName: null, symbolName: 'malloc', objcMode: null } }; globalThis.__iosRustFridaTraceCurrentKey = 'trace-export:*:malloc'; return JSON.stringify(__iosRustFridaControllerApi.dispatchResult({ kind: 'trace.stop' })); })()")
                    .expect("controller multi trace stop result"),
                "{\"active\":true,\"count\":0,\"sessionCount\":2,\"sessions\":[{\"key\":\"objc-trace:UIView\",\"label\":\"objc_msgSend\",\"filter\":\"UIView\",\"targetAddress\":\"0x180004000\",\"targetKind\":\"export\",\"targetSymbol\":\"objc_msgSend\",\"moduleName\":null,\"symbolName\":\"objc_msgSend\",\"objcMode\":\"trace\"},{\"key\":\"trace-export:*:malloc\",\"label\":\"*!malloc\",\"filter\":null,\"targetAddress\":\"0x180006000\",\"targetKind\":\"export\",\"targetSymbol\":\"malloc\",\"moduleName\":null,\"symbolName\":\"malloc\",\"objcMode\":null}],\"selectorMatched\":true,\"matchedSessionCount\":2,\"matchedSessions\":[{\"key\":\"objc-trace:UIView\",\"label\":\"objc_msgSend\",\"filter\":\"UIView\",\"targetAddress\":\"0x180004000\",\"targetKind\":\"export\",\"targetSymbol\":\"objc_msgSend\",\"moduleName\":null,\"symbolName\":\"objc_msgSend\",\"objcMode\":\"trace\"},{\"key\":\"trace-export:*:malloc\",\"label\":\"*!malloc\",\"filter\":null,\"targetAddress\":\"0x180006000\",\"targetKind\":\"export\",\"targetSymbol\":\"malloc\",\"moduleName\":null,\"symbolName\":\"malloc\",\"objcMode\":null}],\"detachedSessionCount\":2,\"detachedSessions\":[{\"key\":\"objc-trace:UIView\",\"label\":\"objc_msgSend\",\"filter\":\"UIView\",\"targetAddress\":\"0x180004000\",\"targetKind\":\"export\",\"targetSymbol\":\"objc_msgSend\",\"moduleName\":null,\"symbolName\":\"objc_msgSend\",\"objcMode\":\"trace\"},{\"key\":\"trace-export:*:malloc\",\"label\":\"*!malloc\",\"filter\":null,\"targetAddress\":\"0x180006000\",\"targetKind\":\"export\",\"targetSymbol\":\"malloc\",\"moduleName\":null,\"symbolName\":\"malloc\",\"objcMode\":null}],\"label\":\"*!malloc\",\"filter\":null,\"targetAddress\":\"0x180006000\",\"targetKind\":\"export\",\"targetSymbol\":\"malloc\",\"moduleName\":null,\"symbolName\":\"malloc\",\"objcMode\":null,\"message\":\"trace stopped: *!malloc detached=0\",\"kind\":\"trace.stop\",\"action\":\"stop\",\"scope\":\"trace\"}"
            );
            assert_eq!(
                runtime
                    .eval("(function() { globalThis.__iosRustFridaTrace = { label: 'objc_msgSend', targetAddress: '0x180004000', targetKind: 'export', targetSymbol: 'objc_msgSend', moduleName: null, symbolName: 'objc_msgSend', filter: 'UIView', objcMode: 'trace' }; return JSON.stringify(__iosRustFridaControllerApi.dispatchResult({ kind: 'trace.stop', target: { kind: 'export', moduleName: null, symbolName: 'malloc' } })); })()")
                    .expect("controller targeted trace stop mismatch result"),
                "{\"active\":true,\"count\":1,\"sessionCount\":1,\"sessions\":[{\"key\":\"objc-trace:UIView\",\"label\":\"objc_msgSend\",\"filter\":\"UIView\",\"targetAddress\":\"0x180004000\",\"targetKind\":\"export\",\"targetSymbol\":\"objc_msgSend\",\"moduleName\":null,\"symbolName\":\"objc_msgSend\",\"objcMode\":\"trace\"}],\"currentKey\":\"objc-trace:UIView\",\"currentSession\":{\"key\":\"objc-trace:UIView\",\"label\":\"objc_msgSend\",\"filter\":\"UIView\",\"targetAddress\":\"0x180004000\",\"targetKind\":\"export\",\"targetSymbol\":\"objc_msgSend\",\"moduleName\":null,\"symbolName\":\"objc_msgSend\",\"objcMode\":\"trace\"},\"label\":\"objc_msgSend\",\"filter\":\"UIView\",\"targetAddress\":\"0x180004000\",\"targetKind\":\"export\",\"targetSymbol\":\"objc_msgSend\",\"moduleName\":null,\"symbolName\":\"objc_msgSend\",\"objcMode\":\"trace\",\"message\":\"trace stop skipped: selector mismatch\",\"selectorMatched\":false,\"matchedSessionCount\":0,\"matchedSessions\":[],\"detachedSessionCount\":0,\"detachedSessions\":[],\"kind\":\"trace.stop\",\"action\":\"stop\",\"scope\":\"trace\"}"
            );
            assert_eq!(
                runtime
                    .eval("(function() { globalThis.__iosRustFridaTrace = { label: 'objc_msgSend', targetAddress: '0x180004000', targetKind: 'export', targetSymbol: 'objc_msgSend', moduleName: null, symbolName: 'objc_msgSend', filter: 'UIView', objcMode: 'trace' }; return JSON.stringify(__iosRustFridaControllerApi.dispatchResult({ kind: 'trace.stop', target: { kind: 'export', moduleName: null, symbolName: 'objc_msgSend' }, filter: 'UIView' })); })()")
                    .expect("controller targeted trace stop match result"),
                "{\"active\":true,\"count\":0,\"sessionCount\":1,\"sessions\":[{\"key\":\"objc-trace:UIView\",\"label\":\"objc_msgSend\",\"filter\":\"UIView\",\"targetAddress\":\"0x180004000\",\"targetKind\":\"export\",\"targetSymbol\":\"objc_msgSend\",\"moduleName\":null,\"symbolName\":\"objc_msgSend\",\"objcMode\":\"trace\"}],\"selectorMatched\":true,\"matchedSessionCount\":1,\"matchedSessions\":[{\"key\":\"objc-trace:UIView\",\"label\":\"objc_msgSend\",\"filter\":\"UIView\",\"targetAddress\":\"0x180004000\",\"targetKind\":\"export\",\"targetSymbol\":\"objc_msgSend\",\"moduleName\":null,\"symbolName\":\"objc_msgSend\",\"objcMode\":\"trace\"}],\"detachedSessionCount\":1,\"detachedSessions\":[{\"key\":\"objc-trace:UIView\",\"label\":\"objc_msgSend\",\"filter\":\"UIView\",\"targetAddress\":\"0x180004000\",\"targetKind\":\"export\",\"targetSymbol\":\"objc_msgSend\",\"moduleName\":null,\"symbolName\":\"objc_msgSend\",\"objcMode\":\"trace\"}],\"label\":\"objc_msgSend\",\"filter\":\"UIView\",\"targetAddress\":\"0x180004000\",\"targetKind\":\"export\",\"targetSymbol\":\"objc_msgSend\",\"moduleName\":null,\"symbolName\":\"objc_msgSend\",\"objcMode\":\"trace\",\"message\":\"trace stopped: objc_msgSend detached=0\",\"kind\":\"trace.stop\",\"action\":\"stop\",\"scope\":\"trace\"}"
            );
            assert_eq!(
                runtime
                    .eval("(function() { globalThis.__iosRustFridaStalkerRegistry = {}; globalThis.__iosRustFridaStalkerCurrentKey = null; globalThis.__iosRustFridaStalker = {}; return JSON.stringify(__iosRustFridaControllerApi.dispatchResult({ kind: 'stalker.stop' })); })()")
                    .expect("controller stalker stop result"),
                "{\"active\":false,\"count\":0,\"sessionCount\":0,\"sessions\":[],\"selectorMatched\":true,\"matchedSessionCount\":0,\"matchedSessions\":[],\"detachedSessionCount\":0,\"detachedSessions\":[],\"label\":null,\"filter\":null,\"targetAddress\":null,\"secondaryTargetAddress\":null,\"targetKind\":null,\"targetSymbol\":null,\"moduleName\":null,\"symbolName\":null,\"objcMode\":null,\"superEnabled\":false,\"message\":\"stalker stopped\",\"kind\":\"stalker.stop\",\"action\":\"stop\",\"scope\":\"stalker\"}"
            );
            assert_eq!(
                runtime
                    .eval("(function() { globalThis.__iosRustFridaStalker = { handles: [{}, {}], label: 'objc_msgSend + objc_msgSendSuper2', targetAddress: '0x180005000', secondaryTargetAddress: '0x180005100', targetKind: 'export', targetSymbol: 'objc_msgSend', filter: 'UIView', objcMode: 'stalker', superEnabled: true }; return __iosRustFridaControllerApi.dispatch({ kind: 'stalker.stop' }); })()")
                    .expect("controller populated stalker stop text"),
                "stalker stopped: objc_msgSend + objc_msgSendSuper2 detached=0\n - key=objc-stalker:UIView target=0x180005000 secondary=0x180005100 kind=export symbol=objc_msgSend filter=UIView objcMode=stalker super=on"
            );
            assert_eq!(
                runtime
                    .eval("(function() { globalThis.__iosRustFridaStalkerRegistry = { 'objc-stalker:UIView': { handles: [{}, {}], label: 'objc_msgSend + objc_msgSendSuper2', targetAddress: '0x180005000', secondaryTargetAddress: '0x180005100', targetKind: 'export', targetSymbol: 'objc_msgSend', moduleName: null, symbolName: 'objc_msgSend', filter: 'UIView', objcMode: 'stalker', superEnabled: true }, 'stalker-export:*:malloc': { handles: [{}], label: '*!malloc', targetAddress: '0x180007000', secondaryTargetAddress: null, targetKind: 'export', targetSymbol: 'malloc', moduleName: null, symbolName: 'malloc', objcMode: null, superEnabled: false } }; globalThis.__iosRustFridaStalkerCurrentKey = 'stalker-export:*:malloc'; return JSON.stringify(__iosRustFridaControllerApi.dispatchResult({ kind: 'stalker.stop' })); })()")
                    .expect("controller multi stalker stop result"),
                "{\"active\":true,\"count\":0,\"sessionCount\":2,\"sessions\":[{\"key\":\"objc-stalker:UIView\",\"label\":\"objc_msgSend + objc_msgSendSuper2\",\"filter\":\"UIView\",\"targetAddress\":\"0x180005000\",\"secondaryTargetAddress\":\"0x180005100\",\"targetKind\":\"export\",\"targetSymbol\":\"objc_msgSend\",\"moduleName\":null,\"symbolName\":\"objc_msgSend\",\"objcMode\":\"stalker\",\"superEnabled\":true,\"count\":2},{\"key\":\"stalker-export:*:malloc\",\"label\":\"*!malloc\",\"filter\":null,\"targetAddress\":\"0x180007000\",\"secondaryTargetAddress\":null,\"targetKind\":\"export\",\"targetSymbol\":\"malloc\",\"moduleName\":null,\"symbolName\":\"malloc\",\"objcMode\":null,\"superEnabled\":false,\"count\":1}],\"selectorMatched\":true,\"matchedSessionCount\":2,\"matchedSessions\":[{\"key\":\"objc-stalker:UIView\",\"label\":\"objc_msgSend + objc_msgSendSuper2\",\"filter\":\"UIView\",\"targetAddress\":\"0x180005000\",\"secondaryTargetAddress\":\"0x180005100\",\"targetKind\":\"export\",\"targetSymbol\":\"objc_msgSend\",\"moduleName\":null,\"symbolName\":\"objc_msgSend\",\"objcMode\":\"stalker\",\"superEnabled\":true,\"count\":2},{\"key\":\"stalker-export:*:malloc\",\"label\":\"*!malloc\",\"filter\":null,\"targetAddress\":\"0x180007000\",\"secondaryTargetAddress\":null,\"targetKind\":\"export\",\"targetSymbol\":\"malloc\",\"moduleName\":null,\"symbolName\":\"malloc\",\"objcMode\":null,\"superEnabled\":false,\"count\":1}],\"detachedSessionCount\":2,\"detachedSessions\":[{\"key\":\"objc-stalker:UIView\",\"label\":\"objc_msgSend + objc_msgSendSuper2\",\"filter\":\"UIView\",\"targetAddress\":\"0x180005000\",\"secondaryTargetAddress\":\"0x180005100\",\"targetKind\":\"export\",\"targetSymbol\":\"objc_msgSend\",\"moduleName\":null,\"symbolName\":\"objc_msgSend\",\"objcMode\":\"stalker\",\"superEnabled\":true,\"count\":2},{\"key\":\"stalker-export:*:malloc\",\"label\":\"*!malloc\",\"filter\":null,\"targetAddress\":\"0x180007000\",\"secondaryTargetAddress\":null,\"targetKind\":\"export\",\"targetSymbol\":\"malloc\",\"moduleName\":null,\"symbolName\":\"malloc\",\"objcMode\":null,\"superEnabled\":false,\"count\":1}],\"label\":\"*!malloc\",\"filter\":null,\"targetAddress\":\"0x180007000\",\"secondaryTargetAddress\":null,\"targetKind\":\"export\",\"targetSymbol\":\"malloc\",\"moduleName\":null,\"symbolName\":\"malloc\",\"objcMode\":null,\"superEnabled\":false,\"message\":\"stalker stopped: *!malloc detached=0\",\"kind\":\"stalker.stop\",\"action\":\"stop\",\"scope\":\"stalker\"}"
            );
            assert_eq!(
                runtime
                    .eval("(function() { globalThis.__iosRustFridaStalker = { handles: [{}], label: 'objc_msgSend', targetAddress: '0x180005000', secondaryTargetAddress: null, targetKind: 'export', targetSymbol: 'objc_msgSend', moduleName: null, symbolName: 'objc_msgSend', filter: 'UIView', objcMode: 'stalker', superEnabled: false }; return JSON.stringify(__iosRustFridaControllerApi.dispatchResult({ kind: 'stalker.stop', target: { kind: 'address', address: '0x180005999' } })); })()")
                    .expect("controller targeted stalker stop mismatch result"),
                "{\"active\":true,\"count\":1,\"sessionCount\":1,\"sessions\":[{\"key\":\"objc-stalker:UIView\",\"label\":\"objc_msgSend\",\"filter\":\"UIView\",\"targetAddress\":\"0x180005000\",\"secondaryTargetAddress\":null,\"targetKind\":\"export\",\"targetSymbol\":\"objc_msgSend\",\"moduleName\":null,\"symbolName\":\"objc_msgSend\",\"objcMode\":\"stalker\",\"superEnabled\":false,\"count\":1}],\"currentKey\":\"objc-stalker:UIView\",\"currentSession\":{\"key\":\"objc-stalker:UIView\",\"label\":\"objc_msgSend\",\"filter\":\"UIView\",\"targetAddress\":\"0x180005000\",\"secondaryTargetAddress\":null,\"targetKind\":\"export\",\"targetSymbol\":\"objc_msgSend\",\"moduleName\":null,\"symbolName\":\"objc_msgSend\",\"objcMode\":\"stalker\",\"superEnabled\":false,\"count\":1},\"label\":\"objc_msgSend\",\"filter\":\"UIView\",\"targetAddress\":\"0x180005000\",\"secondaryTargetAddress\":null,\"targetKind\":\"export\",\"targetSymbol\":\"objc_msgSend\",\"moduleName\":null,\"symbolName\":\"objc_msgSend\",\"objcMode\":\"stalker\",\"superEnabled\":false,\"message\":\"stalker stop skipped: selector mismatch\",\"selectorMatched\":false,\"matchedSessionCount\":0,\"matchedSessions\":[],\"detachedSessionCount\":0,\"detachedSessions\":[],\"kind\":\"stalker.stop\",\"action\":\"stop\",\"scope\":\"stalker\"}"
            );
            assert_eq!(
                runtime
                    .eval("(function() { globalThis.__iosRustFridaStalker = { handles: [{}], label: 'objc_msgSend', targetAddress: '0x180005000', secondaryTargetAddress: null, targetKind: 'export', targetSymbol: 'objc_msgSend', moduleName: null, symbolName: 'objc_msgSend', filter: 'UIView', objcMode: 'stalker', superEnabled: false }; return JSON.stringify(__iosRustFridaControllerApi.dispatchResult({ kind: 'stalker.stop', target: { kind: 'export', moduleName: null, symbolName: 'objc_msgSend' }, filter: 'UIView' })); })()")
                    .expect("controller targeted stalker stop match result"),
                "{\"active\":true,\"count\":0,\"sessionCount\":1,\"sessions\":[{\"key\":\"objc-stalker:UIView\",\"label\":\"objc_msgSend\",\"filter\":\"UIView\",\"targetAddress\":\"0x180005000\",\"secondaryTargetAddress\":null,\"targetKind\":\"export\",\"targetSymbol\":\"objc_msgSend\",\"moduleName\":null,\"symbolName\":\"objc_msgSend\",\"objcMode\":\"stalker\",\"superEnabled\":false,\"count\":1}],\"selectorMatched\":true,\"matchedSessionCount\":1,\"matchedSessions\":[{\"key\":\"objc-stalker:UIView\",\"label\":\"objc_msgSend\",\"filter\":\"UIView\",\"targetAddress\":\"0x180005000\",\"secondaryTargetAddress\":null,\"targetKind\":\"export\",\"targetSymbol\":\"objc_msgSend\",\"moduleName\":null,\"symbolName\":\"objc_msgSend\",\"objcMode\":\"stalker\",\"superEnabled\":false,\"count\":1}],\"detachedSessionCount\":1,\"detachedSessions\":[{\"key\":\"objc-stalker:UIView\",\"label\":\"objc_msgSend\",\"filter\":\"UIView\",\"targetAddress\":\"0x180005000\",\"secondaryTargetAddress\":null,\"targetKind\":\"export\",\"targetSymbol\":\"objc_msgSend\",\"moduleName\":null,\"symbolName\":\"objc_msgSend\",\"objcMode\":\"stalker\",\"superEnabled\":false,\"count\":1}],\"label\":\"objc_msgSend\",\"filter\":\"UIView\",\"targetAddress\":\"0x180005000\",\"secondaryTargetAddress\":null,\"targetKind\":\"export\",\"targetSymbol\":\"objc_msgSend\",\"moduleName\":null,\"symbolName\":\"objc_msgSend\",\"objcMode\":\"stalker\",\"superEnabled\":false,\"message\":\"stalker stopped: objc_msgSend detached=0\",\"kind\":\"stalker.stop\",\"action\":\"stop\",\"scope\":\"stalker\"}"
            );
            assert_eq!(
                runtime
                    .eval("(function() { globalThis.__iosRustFridaObjcHooks = { '-[UIViewController viewDidLoad]': { className: 'UIViewController', selectorName: 'viewDidLoad', isClassMethod: false, target: '0x18000abcd' } }; return JSON.stringify(__iosRustFridaControllerApi.dispatchResult({ kind: 'objc.hook.stop' })); })()")
                    .expect("controller populated objc hook stop result"),
                "{\"kind\":\"objc.hook.stop\",\"action\":\"stop\",\"scope\":\"objc-hook\",\"active\":true,\"targeted\":false,\"requestedKey\":null,\"count\":0,\"keys\":[\"-[UIViewController viewDidLoad]\"],\"targets\":[{\"key\":\"-[UIViewController viewDidLoad]\",\"className\":\"UIViewController\",\"selectorName\":\"viewDidLoad\",\"isClassMethod\":false,\"target\":\"0x18000abcd\"}],\"targetMatched\":true,\"matchedTargetCount\":1,\"matchedTargets\":[{\"key\":\"-[UIViewController viewDidLoad]\",\"className\":\"UIViewController\",\"selectorName\":\"viewDidLoad\",\"isClassMethod\":false,\"target\":\"0x18000abcd\"}],\"detachedTargetCount\":1,\"detachedTargets\":[{\"key\":\"-[UIViewController viewDidLoad]\",\"className\":\"UIViewController\",\"selectorName\":\"viewDidLoad\",\"isClassMethod\":false,\"target\":\"0x18000abcd\"}],\"message\":\"jhook detached: 0\"}"
            );
            assert_eq!(
                runtime
                    .eval("(function() { globalThis.__iosRustFridaObjcHooks = { '-[UIViewController viewDidLoad]': { className: 'UIViewController', selectorName: 'viewDidLoad', isClassMethod: false, target: '0x18000abcd' } }; return __iosRustFridaControllerApi.dispatch({ kind: 'objc.hook.stop' }); })()")
                    .expect("controller populated objc hook stop text"),
                "jhook detached: 0\n - -[UIViewController viewDidLoad] target=0x18000abcd"
            );
            assert_eq!(
                runtime
                    .eval("(function() { globalThis.__iosRustFridaObjcHooks = { '+[NSString string]': { className: 'NSString', selectorName: 'string', isClassMethod: true, target: '0x18000dcba' }, '-[UIViewController viewDidLoad]': { className: 'UIViewController', selectorName: 'viewDidLoad', isClassMethod: false, target: '0x18000abcd' } }; return JSON.stringify(__iosRustFridaControllerApi.dispatchResult({ kind: 'objc.hook.stop', className: 'NSString', selectorName: 'string', isClassMethod: true })); })()")
                    .expect("controller targeted objc hook stop result"),
                "{\"kind\":\"objc.hook.stop\",\"action\":\"stop\",\"scope\":\"objc-hook\",\"active\":true,\"targeted\":true,\"requestedKey\":\"+[NSString string]\",\"count\":0,\"keys\":[\"+[NSString string]\"],\"targets\":[{\"key\":\"+[NSString string]\",\"className\":\"NSString\",\"selectorName\":\"string\",\"isClassMethod\":true,\"target\":\"0x18000dcba\"}],\"targetMatched\":true,\"matchedTargetCount\":1,\"matchedTargets\":[{\"key\":\"+[NSString string]\",\"className\":\"NSString\",\"selectorName\":\"string\",\"isClassMethod\":true,\"target\":\"0x18000dcba\"}],\"detachedTargetCount\":1,\"detachedTargets\":[{\"key\":\"+[NSString string]\",\"className\":\"NSString\",\"selectorName\":\"string\",\"isClassMethod\":true,\"target\":\"0x18000dcba\"}],\"message\":\"jhook detached: 0 for +[NSString string]\"}"
            );
            assert_eq!(
                runtime
                    .eval("(function() { globalThis.__iosRustFridaSwiftHooks = { 'MyApp::ViewController::viewDidLoad': { moduleName: 'MyApp', typeName: 'ViewController', methodQuery: 'viewDidLoad', targets: [{ address: '0x18000beef', name: '$s4MyApp14ViewControllerC11viewDidLoadyyF', demangledName: 'MyApp.ViewController.viewDidLoad()', moduleName: 'MyApp' }] } }; return JSON.stringify(__iosRustFridaControllerApi.dispatchResult({ kind: 'swift.hook.stop' })); })()")
                    .expect("controller populated swift hook stop result"),
                "{\"kind\":\"swift.hook.stop\",\"action\":\"stop\",\"scope\":\"swift-hook\",\"active\":true,\"targeted\":false,\"requestedKey\":null,\"count\":0,\"keys\":[\"MyApp::ViewController::viewDidLoad\"],\"targets\":[{\"key\":\"MyApp::ViewController::viewDidLoad\",\"moduleName\":\"MyApp\",\"typeName\":\"ViewController\",\"methodQuery\":\"viewDidLoad\",\"count\":1,\"targets\":[{\"address\":\"0x18000beef\",\"name\":\"$s4MyApp14ViewControllerC11viewDidLoadyyF\",\"demangledName\":\"MyApp.ViewController.viewDidLoad()\",\"moduleName\":\"MyApp\"}]}],\"targetMatched\":true,\"matchedTargetCount\":1,\"matchedTargets\":[{\"key\":\"MyApp::ViewController::viewDidLoad\",\"moduleName\":\"MyApp\",\"typeName\":\"ViewController\",\"methodQuery\":\"viewDidLoad\",\"count\":1,\"targets\":[{\"address\":\"0x18000beef\",\"name\":\"$s4MyApp14ViewControllerC11viewDidLoadyyF\",\"demangledName\":\"MyApp.ViewController.viewDidLoad()\",\"moduleName\":\"MyApp\"}]}],\"detachedTargetCount\":1,\"detachedTargets\":[{\"key\":\"MyApp::ViewController::viewDidLoad\",\"moduleName\":\"MyApp\",\"typeName\":\"ViewController\",\"methodQuery\":\"viewDidLoad\",\"count\":1,\"targets\":[{\"address\":\"0x18000beef\",\"name\":\"$s4MyApp14ViewControllerC11viewDidLoadyyF\",\"demangledName\":\"MyApp.ViewController.viewDidLoad()\",\"moduleName\":\"MyApp\"}]}],\"message\":\"shook detached: 0\"}"
            );
            assert_eq!(
                runtime
                    .eval("(function() { globalThis.__iosRustFridaSwiftHooks = { 'MyApp::ViewController::viewDidLoad': { moduleName: 'MyApp', typeName: 'ViewController', methodQuery: 'viewDidLoad', targets: [{ address: '0x18000beef', name: '$s4MyApp14ViewControllerC11viewDidLoadyyF', demangledName: 'MyApp.ViewController.viewDidLoad()', moduleName: 'MyApp' }] } }; return __iosRustFridaControllerApi.dispatch({ kind: 'swift.hook.stop' }); })()")
                    .expect("controller populated swift hook stop text"),
                "shook detached: 0\n - MyApp::ViewController::viewDidLoad count=1\n   - address=0x18000beef name=MyApp.ViewController.viewDidLoad() module=MyApp"
            );
            assert_eq!(
                runtime
                    .eval("(function() { globalThis.__iosRustFridaSwiftHooks = { 'MyApp::ViewController::viewDidLoad': { moduleName: 'MyApp', typeName: 'ViewController', methodQuery: 'viewDidLoad', targets: [{ address: '0x18000beef', name: '$s4MyApp14ViewControllerC11viewDidLoadyyF', demangledName: 'MyApp.ViewController.viewDidLoad()', moduleName: 'MyApp' }] }, '*::Other::load': { moduleName: null, typeName: 'Other', methodQuery: 'load', targets: [{ address: '0x18000feed', name: '$s5Other4loadyyF', demangledName: 'Other.load()', moduleName: null }] } }; return JSON.stringify(__iosRustFridaControllerApi.dispatchResult({ kind: 'swift.hook.stop', moduleName: 'MyApp', typeName: 'ViewController', methodQuery: 'viewDidLoad' })); })()")
                    .expect("controller targeted swift hook stop result"),
                "{\"kind\":\"swift.hook.stop\",\"action\":\"stop\",\"scope\":\"swift-hook\",\"active\":true,\"targeted\":true,\"requestedKey\":\"MyApp::ViewController::viewDidLoad\",\"count\":0,\"keys\":[\"MyApp::ViewController::viewDidLoad\"],\"targets\":[{\"key\":\"MyApp::ViewController::viewDidLoad\",\"moduleName\":\"MyApp\",\"typeName\":\"ViewController\",\"methodQuery\":\"viewDidLoad\",\"count\":1,\"targets\":[{\"address\":\"0x18000beef\",\"name\":\"$s4MyApp14ViewControllerC11viewDidLoadyyF\",\"demangledName\":\"MyApp.ViewController.viewDidLoad()\",\"moduleName\":\"MyApp\"}]}],\"targetMatched\":true,\"matchedTargetCount\":1,\"matchedTargets\":[{\"key\":\"MyApp::ViewController::viewDidLoad\",\"moduleName\":\"MyApp\",\"typeName\":\"ViewController\",\"methodQuery\":\"viewDidLoad\",\"count\":1,\"targets\":[{\"address\":\"0x18000beef\",\"name\":\"$s4MyApp14ViewControllerC11viewDidLoadyyF\",\"demangledName\":\"MyApp.ViewController.viewDidLoad()\",\"moduleName\":\"MyApp\"}]}],\"detachedTargetCount\":1,\"detachedTargets\":[{\"key\":\"MyApp::ViewController::viewDidLoad\",\"moduleName\":\"MyApp\",\"typeName\":\"ViewController\",\"methodQuery\":\"viewDidLoad\",\"count\":1,\"targets\":[{\"address\":\"0x18000beef\",\"name\":\"$s4MyApp14ViewControllerC11viewDidLoadyyF\",\"demangledName\":\"MyApp.ViewController.viewDidLoad()\",\"moduleName\":\"MyApp\"}]}],\"message\":\"shook detached: 0 for MyApp::ViewController::viewDidLoad\"}"
            );
        }

        #[test]
        fn agent_helpers_route_basic_queries() {
            let _guard = test_lock().lock().unwrap_or_else(|e| e.into_inner());
            let mut runtime = QuickJsRuntime::new();
            runtime.initialize().expect("init runtime");

            assert_eq!(
                runtime
                    .eval(
                        "(function() { const text = __iosRustFridaAgentApi.handle('objc.classes'); const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'objc.classes', filter: null }); return text === result.text && result.count === result.classes.length && result.text === result.classes.join('\\n'); })()"
                    )
                    .expect("agent objc classes"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() { const text = __iosRustFridaAgentApi.handle('objc.protocols'); const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'objc.protocols', filter: null }); return text === result.text && result.count === result.protocols.length && result.text === result.protocols.join('\\n'); })()"
                    )
                    .expect("agent objc protocols"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const value = __iosRustFridaAgentApi.handle('objc.classes NSObject'); return value === '' || value.indexOf('NSObject') !== -1; })()")
                    .expect("agent objc classes filtered"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const value = __iosRustFridaAgentApi.handle('objc.protocols NS'); return value === '' || value.indexOf('NS') !== -1; })()")
                    .expect("agent objc protocols filtered"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("__iosRustFridaAgentApi.handle('pac.strip 0x1234')")
                    .expect("agent pac strip"),
                "0x1234"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const value = __iosRustFridaAgentApi.handle('pac.image libsystem_malloc.dylib'); return value === '<null>' || value === 'true' || value === 'false'; })()")
                    .expect("agent pac image"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const value = __iosRustFridaAgentApi.handle('pac.images'); return value === '' || value.indexOf('slide=') !== -1; })()")
                    .expect("agent pac images"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() { const value = __iosRustFridaAgentApi.handle('objc.classInfo NSObject meta'); const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'objc.class_info', className: 'NSObject', isMetaClass: true }); return value === result.text && (result.classInfo === null || result.classInfo.isMetaClass === true); })()"
                    )
                    .expect("agent objc classInfo"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() { const value = __iosRustFridaAgentApi.handle('objc.protocolInfo NSObject'); const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'objc.protocol_info', protocolName: 'NSObject' }); return value === result.text && (result.protocolInfo === null || (result.protocolInfo.protocolName === 'NSObject' && Array.isArray(result.protocolInfo.adoptedProtocols))); })()"
                    )
                    .expect("agent objc protocolInfo"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() { const value = __iosRustFridaAgentApi.handle('objc.classProtocols NSObject'); const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'objc.class_protocols', className: 'NSObject' }); return value === result.text && result.count === result.protocols.length; })()"
                    )
                    .expect("agent objc classProtocols"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() { const value = __iosRustFridaAgentApi.handle('objc.protocolProtocols NSObject'); const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'objc.protocol_protocols', protocolName: 'NSObject' }); return value === result.text && result.count === result.protocols.length; })()"
                    )
                    .expect("agent objc protocolProtocols"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() { const value = __iosRustFridaAgentApi.handle('objc.protocolMethods NSObject optional class'); const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'objc.protocol_methods', protocolName: 'NSObject', isRequired: false, isInstanceMethod: false }); return value === result.text && result.count === result.methods.length; })()"
                    )
                    .expect("agent objc protocolMethods"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() { const value = __iosRustFridaAgentApi.handle('objc.protocolMethodInfo NSObject description optional class'); const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'objc.protocol_method_info', protocolName: 'NSObject', selectorName: 'description', isRequired: false, isInstanceMethod: false }); return value === result.text && (result.methodInfo === null || (result.methodInfo.selector === 'description' && typeof result.methodInfo.typeEncoding === 'string')); })()"
                    )
                    .expect("agent objc protocolMethodInfo"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() { const value = __iosRustFridaAgentApi.handle('objc.protocolProperties NSObject'); const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'objc.protocol_properties', protocolName: 'NSObject' }); return value === result.text && result.count === result.properties.length; })()"
                    )
                    .expect("agent objc protocolProperties"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() { const value = __iosRustFridaAgentApi.handle('objc.protocolPropertyInfo NSObject description'); const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'objc.protocol_property_info', protocolName: 'NSObject', propertyName: 'description' }); return value === result.text && (result.propertyInfo === null || (result.propertyInfo.name === 'description' && typeof result.propertyInfo.attributes === 'string')); })()"
                    )
                    .expect("agent objc protocolPropertyInfo"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() { const value = __iosRustFridaAgentApi.handle('objc.superclass NSObject'); const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'objc.superclass', className: 'NSObject' }); return value === result.text && (result.superclass === null || typeof result.superclass === 'string'); })()"
                    )
                    .expect("agent objc superclass"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() { const value = __iosRustFridaAgentApi.handle('objc.classChain NSObject'); const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'objc.class_chain', className: 'NSObject' }); return value === result.text && result.count === result.chain.length; })()"
                    )
                    .expect("agent objc classChain"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() { const value = __iosRustFridaAgentApi.handle('objc.properties NSObject meta delegate'); const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'objc.properties', className: 'NSObject', isClassProperty: true, filter: 'delegate' }); return value === result.text && result.count === result.properties.length; })()"
                    )
                    .expect("agent objc properties"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() { const value = __iosRustFridaAgentApi.handle('objc.propertyInfo NSObject description'); const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'objc.property_info', className: 'NSObject', propertyName: 'description', isClassProperty: false }); return value === result.text && (result.propertyInfo === null || (result.propertyInfo.name === 'description' && typeof result.propertyInfo.attributes === 'string')); })()"
                    )
                    .expect("agent objc propertyInfo"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() { const value = __iosRustFridaAgentApi.handle('objc.ivarInfo NSObject _isa'); const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'objc.ivar_info', className: 'NSObject', ivarName: '_isa' }); return value === result.text && (result.ivarInfo === null || (result.ivarInfo.name === '_isa' && typeof result.ivarInfo.typeEncoding === 'string')); })()"
                    )
                    .expect("agent objc ivarInfo"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() { const value = __iosRustFridaAgentApi.handle('objc.ivars NSObject delegate'); const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'objc.ivars', className: 'NSObject', filter: 'delegate' }); return value === result.text && result.count === result.ivars.length; })()"
                    )
                    .expect("agent objc ivars"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() { const value = __iosRustFridaAgentApi.handle('objc.classImage NSObject'); return value === '<null>' || value.indexOf('/') !== -1; })()"
                    )
                    .expect("agent objc classImage"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() { const value = __iosRustFridaAgentApi.handle('objc.methodImage NSObject init'); return value === '<null>' || value.indexOf('/') !== -1; })()"
                    )
                    .expect("agent objc methodImage"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() { const value = __iosRustFridaAgentApi.handle('objc.methodInfo NSObject init'); const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'objc.method_info', className: 'NSObject', selectorName: 'init', isClassMethod: false }); return value === result.text && (result.methodInfo === null || (result.methodInfo.selector === 'init' && typeof result.methodInfo.imp === 'string')); })()"
                    )
                    .expect("agent objc methodInfo"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("__iosRustFridaAgentApi.handle('objc.selectorName 0x0')")
                    .expect("agent objc selectorName"),
                "<null>"
            );
            assert_eq!(
                runtime
                    .eval("__iosRustFridaAgentApi.handle('objc.objectClassName 0x0')")
                    .expect("agent objc objectClassName"),
                "<null>"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const value = __iosRustFridaAgentApi.handle('objc.methodOwners init'); return value === '' || value.indexOf(' init') !== -1; })()")
                    .expect("agent objc method owners"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const value = Swift.protocolInfo('Renderable'); return value === null || (typeof value.name === 'string' && typeof value.moduleName === 'string' && typeof value.sourceKind === 'string'); })()")
                    .expect("swift protocolInfo"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const value = Swift.conformanceInfo('ViewController', 'Renderable'); return value === null || (typeof value.typeName === 'string' && typeof value.protocolName === 'string' && typeof value.moduleName === 'string'); })()")
                    .expect("swift conformanceInfo"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const value = Swift.typeInfo('ViewController'); return value === null || (typeof value.name === 'string' && typeof value.moduleName === 'string' && typeof value.sourceKind === 'string'); })()")
                    .expect("swift typeInfo"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const value = Swift.methodInfo('ViewController', 'viewDidLoad'); return value === null || (typeof value.name === 'string' && typeof value.moduleName === 'string' && typeof value.address === 'object'); })()")
                    .expect("swift methodInfo"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const value = __iosRustFridaAgentApi.handle('swift.protocols'); return value === '' || value.indexOf('[protocol-') !== -1; })()")
                    .expect("agent swift protocols"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const value = __iosRustFridaAgentApi.handle('swift.protocolInfo Renderable'); const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'swift.protocol_info', moduleName: null, protocolName: 'Renderable' }); return value === result.text && (result.protocolInfo === null || (result.protocolInfo.name === 'Renderable' && typeof result.protocolInfo.sourceKind === 'string')); })()")
                    .expect("agent swift protocolInfo"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const value = __iosRustFridaAgentApi.handle('swift.conformanceInfo ViewController Renderable'); const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'swift.conformance_info', moduleName: null, typeName: 'ViewController', protocolName: 'Renderable' }); return value === result.text && (result.conformanceInfo === null || (result.conformanceInfo.typeName === 'ViewController' && result.conformanceInfo.protocolName === 'Renderable')); })()")
                    .expect("agent swift conformanceInfo"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const value = __iosRustFridaAgentApi.handle('swift.typeInfo ViewController'); const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'swift.type_info', moduleName: null, typeName: 'ViewController' }); return value === result.text && (result.typeInfo === null || (result.typeInfo.name === 'ViewController' && typeof result.typeInfo.sourceKind === 'string')); })()")
                    .expect("agent swift typeInfo"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const value = __iosRustFridaAgentApi.handle('swift.methodInfo ViewController viewDidLoad'); const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'swift.method_info', moduleName: null, typeName: 'ViewController', methodName: 'viewDidLoad' }); return value === result.text && (result.methodInfo === null || (typeof result.methodInfo.name === 'string' && typeof result.methodInfo.offsetHex === 'string')); })()")
                    .expect("agent swift methodInfo"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const value = __iosRustFridaAgentApi.handle('swift.symbolInfo ViewController'); const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'swift.symbol_info', moduleName: null, symbolName: 'ViewController' }); return value === result.text && (result.symbolInfo === null || typeof result.symbolInfo.name === 'string'); })()")
                    .expect("agent swift symbolInfo"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const value = __iosRustFridaAgentApi.handle('swift.conformances ViewController'); return value === '' || value.indexOf(' : ') !== -1; })()")
                    .expect("agent swift conformances"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const value = __iosRustFridaAgentApi.handle('swift.metadata ViewController'); return value === '' || value.indexOf('[metadata') !== -1 || value.indexOf('[nominal-descriptor]') !== -1; })()")
                    .expect("agent swift metadata"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const value = __iosRustFridaAgentApi.handle('swift.metadataInfo ViewController'); const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'swift.metadata_info', moduleName: null, typeName: 'ViewController' }); return value === result.text && (result.metadataInfo === null || result.metadataInfo.name === 'ViewController'); })()")
                    .expect("agent swift metadata info"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const value = __iosRustFridaAgentApi.handle('swift.vtable ViewController'); return value === '' || value.indexOf('ViewController.') !== -1; })()")
                    .expect("agent swift vtable"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const value = __iosRustFridaAgentApi.handle('swift.vtableInfo ViewController viewDidLoad'); const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'swift.vtable_info', moduleName: null, typeName: 'ViewController', memberName: 'viewDidLoad' }); return value === result.text && (result.vtableInfo === null || (result.vtableInfo.typeName === 'ViewController' && result.vtableInfo.memberName === 'viewDidLoad')); })()")
                    .expect("agent swift vtable info"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const value = __iosRustFridaAgentApi.handle('swift.witnessTable Renderable'); return value === '' || value.indexOf('Renderable') !== -1; })()")
                    .expect("agent swift witness table"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const value = __iosRustFridaAgentApi.handle('swift.witnessTableInfo ViewController Renderable'); const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'swift.witness_table_info', moduleName: null, typeName: 'ViewController', protocolName: 'Renderable' }); return value === result.text && (result.witnessTableInfo === null || (result.witnessTableInfo.typeName === 'ViewController' && result.witnessTableInfo.protocolName === 'Renderable')); })()")
                    .expect("agent swift witness table info"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const value = __iosRustFridaAgentApi.handle('swift.typeLayout ViewController'); return value === '' || value.indexOf('metadata=') !== -1; })()")
                    .expect("agent swift type layout"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const value = __iosRustFridaAgentApi.handle('swift.typeLayoutInfo ViewController'); const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'swift.type_layout_info', moduleName: null, typeName: 'ViewController' }); return value === result.text && (result.typeLayout === null || (result.typeLayout.name === 'ViewController' && typeof result.typeLayout.vtableCount === 'number')); })()")
                    .expect("agent swift type layout info"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() { const value = __iosRustFridaAgentApi.handle('swift.demangle $s4Demo6methodyyF'); return value === '<unavailable>' || value.indexOf('Demo') !== -1 || value.indexOf('method') !== -1; })()"
                    )
                    .expect("agent swift demangle"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const value = __iosRustFridaAgentApi.handle('swift.types ViewController'); return value === '' || value.indexOf('ViewController') !== -1; })()")
                    .expect("agent swift types"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const value = __iosRustFridaAgentApi.handle('swift.typeKinds'); return value.indexOf('metadata-accessor') !== -1; })()")
                    .expect("agent swift type kinds"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("typeof __iosRustFridaAgentApi.handleSpecResult")
                    .expect("agent handleSpecResult type"),
                "function"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() { const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'pac.available' }); return result.kind === 'pac.available' && result.available === PAC.available && result.text === String(PAC.available); })()"
                    )
                    .expect("agent pac available result"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() { const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'objc.classes', filter: null }); return result.kind === 'objc.classes' && result.filter === null && result.count === result.classes.length && result.text === result.classes.join('\\n'); })()"
                    )
                    .expect("agent objc classes result"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() { const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'objc.protocols', filter: null }); return result.kind === 'objc.protocols' && result.filter === null && result.count === result.protocols.length && result.text === result.protocols.join('\\n'); })()"
                    )
                    .expect("agent objc protocols result"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() { const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'objc.class_info', className: 'NSObject', isMetaClass: true }); return result.kind === 'objc.class_info' && result.className === 'NSObject' && result.isMetaClass === true && ((result.classInfo === null && result.text === '<null>') || (typeof result.classInfo.classPointer === 'string' && result.classInfo.isMetaClass === true && typeof result.classInfo.instanceSize === 'number' && result.text === result.classInfo.text)); })()"
                    )
                    .expect("agent objc classInfo result"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() { const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'objc.protocol_info', protocolName: 'NSObject' }); return result.kind === 'objc.protocol_info' && result.protocolName === 'NSObject' && ((result.protocolInfo === null && result.text === '<null>') || (typeof result.protocolInfo.protocolPointer === 'string' && Array.isArray(result.protocolInfo.adoptedProtocols) && typeof result.protocolInfo.propertyCount === 'number' && result.text === result.protocolInfo.text)); })()"
                    )
                    .expect("agent objc protocolInfo result"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() { const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'objc.class_protocols', className: 'NSObject' }); return result.kind === 'objc.class_protocols' && result.className === 'NSObject' && result.count === result.protocols.length && result.text === result.protocols.join('\\n'); })()"
                    )
                    .expect("agent objc classProtocols result"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() { const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'objc.method_info', className: 'NSObject', selectorName: 'init', isClassMethod: false }); return result.kind === 'objc.method_info' && result.className === 'NSObject' && result.selectorName === 'init' && result.isClassMethod === false && ((result.methodInfo === null && result.text === '<null>') || (typeof result.methodInfo.methodPointer === 'string' && typeof result.methodInfo.imp === 'string' && typeof result.methodInfo.typeEncoding === 'string' && result.text === result.methodInfo.text)); })()"
                    )
                    .expect("agent objc methodInfo result"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() { const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'objc.protocol_protocols', protocolName: 'NSObject' }); return result.kind === 'objc.protocol_protocols' && result.protocolName === 'NSObject' && result.count === result.protocols.length && result.text === result.protocols.join('\\n'); })()"
                    )
                    .expect("agent objc protocolProtocols result"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() { const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'objc.protocol_methods', protocolName: 'NSObject', isRequired: false, isInstanceMethod: false }); return result.kind === 'objc.protocol_methods' && result.protocolName === 'NSObject' && result.isRequired === false && result.isInstanceMethod === false && result.count === result.methods.length && (result.methods.length === 0 || (typeof result.methods[0].typeEncoding === 'string' && typeof result.methods[0].returnTypeName === 'string' && Array.isArray(result.methods[0].argumentTypeNames) && typeof result.methods[0].methodTypeInfo === 'object')) && result.text === result.methods.map((method) => method.text).join('\\n'); })()"
                    )
                    .expect("agent objc protocolMethods result"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() { const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'objc.protocol_method_info', protocolName: 'NSObject', selectorName: 'description', isRequired: false, isInstanceMethod: false }); return result.kind === 'objc.protocol_method_info' && result.protocolName === 'NSObject' && result.selectorName === 'description' && result.isRequired === false && result.isInstanceMethod === false && ((result.methodInfo === null && result.text === '<null>') || (typeof result.methodInfo.typeEncoding === 'string' && typeof result.methodInfo.returnTypeName === 'string' && Array.isArray(result.methodInfo.argumentTypeNames) && typeof result.methodInfo.methodTypeInfo === 'object' && result.text === result.methodInfo.text)); })()"
                    )
                    .expect("agent objc protocolMethodInfo result"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() { const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'objc.protocol_properties', protocolName: 'NSObject' }); return result.kind === 'objc.protocol_properties' && result.protocolName === 'NSObject' && result.count === result.properties.length && (result.properties.length === 0 || (typeof result.properties[0].typeEncoding === 'string' && typeof result.properties[0].typeName === 'string' && Array.isArray(result.properties[0].objectProtocols) && typeof result.properties[0].typeInfo === 'object' && typeof result.properties[0].attributeInfo === 'object')) && result.text === result.properties.map((property) => property.text).join('\\n'); })()"
                    )
                    .expect("agent objc protocolProperties result"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() { const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'objc.protocol_property_info', protocolName: 'NSObject', propertyName: 'description' }); return result.kind === 'objc.protocol_property_info' && result.protocolName === 'NSObject' && result.propertyName === 'description' && ((result.propertyInfo === null && result.text === '<null>') || (typeof result.propertyInfo.propertyPointer === 'string' && typeof result.propertyInfo.typeEncoding === 'string' && typeof result.propertyInfo.typeName === 'string' && Array.isArray(result.propertyInfo.objectProtocols) && typeof result.propertyInfo.attributeInfo === 'object' && result.text === result.propertyInfo.text)); })()"
                    )
                    .expect("agent objc protocolPropertyInfo result"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() { const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'objc.superclass', className: 'NSObject' }); return result.kind === 'objc.superclass' && result.className === 'NSObject' && ((result.superclass === null && result.text === '<null>') || (typeof result.superclass === 'string' && result.text === result.superclass)); })()"
                    )
                    .expect("agent objc superclass result"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() { const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'objc.class_chain', className: 'NSObject' }); return result.kind === 'objc.class_chain' && result.className === 'NSObject' && result.count === result.chain.length && result.text === result.chain.join('\\n'); })()"
                    )
                    .expect("agent objc classChain result"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() { const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'objc.properties', className: 'NSObject', isClassProperty: true, filter: 'delegate' }); return result.kind === 'objc.properties' && result.className === 'NSObject' && result.isClassProperty === true && result.filter === 'delegate' && result.count === result.properties.length && (result.properties.length === 0 || (typeof result.properties[0].typeEncoding === 'string' && typeof result.properties[0].typeName === 'string' && Array.isArray(result.properties[0].objectProtocols) && typeof result.properties[0].typeInfo === 'object' && typeof result.properties[0].attributeInfo === 'object')) && result.text === result.properties.map((property) => property.text).join('\\n'); })()"
                    )
                    .expect("agent objc properties result"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() { const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'objc.property_info', className: 'NSObject', propertyName: 'description', isClassProperty: false }); return result.kind === 'objc.property_info' && result.className === 'NSObject' && result.propertyName === 'description' && result.isClassProperty === false && ((result.propertyInfo === null && result.text === '<null>') || (typeof result.propertyInfo.propertyPointer === 'string' && typeof result.propertyInfo.typeEncoding === 'string' && typeof result.propertyInfo.typeName === 'string' && Array.isArray(result.propertyInfo.objectProtocols) && typeof result.propertyInfo.attributeInfo === 'object' && result.text === result.propertyInfo.text)); })()"
                    )
                    .expect("agent objc propertyInfo result"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() { const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'objc.ivar_info', className: 'NSObject', ivarName: '_isa' }); return result.kind === 'objc.ivar_info' && result.className === 'NSObject' && result.ivarName === '_isa' && ((result.ivarInfo === null && result.text === '<null>') || (typeof result.ivarInfo.ivarPointer === 'string' && typeof result.ivarInfo.offsetHex === 'string' && typeof result.ivarInfo.typeName === 'string' && typeof result.ivarInfo.typeInfo === 'object' && result.text === result.ivarInfo.text)); })()"
                    )
                    .expect("agent objc ivarInfo result"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() { const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'objc.ivars', className: 'NSObject', filter: 'delegate' }); return result.kind === 'objc.ivars' && result.className === 'NSObject' && result.filter === 'delegate' && result.count === result.ivars.length && result.text === result.ivars.map((ivar) => ivar.text).join('\\n') && (result.ivars.length === 0 || (typeof result.ivars[0].offsetHex === 'string' && typeof result.ivars[0].typeName === 'string' && typeof result.ivars[0].typeInfo === 'object')); })()"
                    )
                    .expect("agent objc ivars result"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const value = __iosRustFridaAgentApi.handle('swift.typesOfKind metadata-accessor ViewController'); return value === '' || value.indexOf('[metadata-accessor]') !== -1; })()")
                    .expect("agent swift types of kind"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() { const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'native.base', moduleName: 'libsystem_malloc.dylib' }); return result.kind === 'native.base' && result.moduleName === 'libsystem_malloc.dylib' && (result.base === null || typeof result.base === 'string'); })()"
                    )
                    .expect("agent native base result"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() { const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'native.main_image' }); return result.kind === 'native.main_image' && (result.image === null || (typeof result.image.name === 'string' && result.image.name.length !== 0)); })()"
                    )
                    .expect("agent native main image result"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() { const address = Module.findExportByName(null, 'malloc'); if (address === null) { return true; } const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'native.image', address: address.toString() }); return result.kind === 'native.image' && result.address === address.toString() && ((result.image === null && result.text === '<null>') || (typeof result.image.name === 'string' && typeof result.image.path === 'string' && typeof result.image.base === 'string' && typeof result.image.sizeHex === 'string' && result.text === result.image.text)); })()"
                    )
                    .expect("agent native image result"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() { const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'native.symbols', moduleName: null, query: 'malloc' }); return result.kind === 'native.symbols' && result.count === result.symbols.length && (result.symbols.length === 0 || (typeof result.symbols[0].moduleBase === 'string' && typeof result.symbols[0].offsetHex === 'string')); })()"
                    )
                    .expect("agent native symbols result"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() { const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'native.export', moduleName: null, symbolName: 'malloc' }); return result.kind === 'native.export' && result.symbolName === 'malloc' && ((result.address === null && result.symbol === null && result.text === '<null>') || (typeof result.address === 'string' && typeof result.symbol.moduleName === 'string' && result.text === result.symbol.text)); })()"
                    )
                    .expect("agent native export result"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() { const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'native.symbol_info', moduleName: null, symbolName: 'malloc' }); return result.kind === 'native.symbol_info' && result.symbolName === 'malloc' && ((result.symbolInfo === null && result.text === '<null>') || (typeof result.symbolInfo.moduleBase === 'string' && typeof result.symbolInfo.name === 'string' && typeof result.symbolInfo.offsetHex === 'string' && result.text === result.symbolInfo.text)); })()"
                    )
                    .expect("agent native symbolInfo result"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() { const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'native.image_info', moduleName: 'libsystem_malloc.dylib' }); return result.kind === 'native.image_info' && result.moduleName === 'libsystem_malloc.dylib' && ((result.image === null && result.text === '<null>') || (typeof result.image.name === 'string' && typeof result.image.path === 'string' && typeof result.image.base === 'string' && typeof result.image.sizeHex === 'string' && result.text === result.image.text)); })()"
                    )
                    .expect("agent native imageInfo result"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() { const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'native.export_info', moduleName: 'libsystem_malloc.dylib', symbolName: 'malloc' }); return result.kind === 'native.export_info' && result.moduleName === 'libsystem_malloc.dylib' && result.symbolName === 'malloc' && ((result.exportInfo === null && result.text === '<null>') || (typeof result.exportInfo.moduleBase === 'string' && typeof result.exportInfo.name === 'string' && typeof result.exportInfo.offsetHex === 'string' && result.text === result.exportInfo.text)); })()"
                    )
                    .expect("agent native exportInfo result"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() { const main = __iosRustFridaAgentApi.handleSpecResult({ kind: 'native.main_image' }); if (main.image === null) { return true; } const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'native.dependencies', moduleName: main.image.name, query: null }); return result.kind === 'native.dependencies' && result.count === result.dependencies.length && (result.dependencies.length === 0 || (typeof result.dependencies[0].ordinal === 'number' && typeof result.dependencies[0].kind === 'string')); })()"
                    )
                    .expect("agent native dependencies result"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() { const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'native.dependency_info', moduleName: 'libsystem_malloc.dylib', pathOrName: 'libSystem.B.dylib' }); return result.kind === 'native.dependency_info' && result.moduleName === 'libsystem_malloc.dylib' && result.pathOrName === 'libSystem.B.dylib' && ((result.dependencyInfo === null && result.text === '<null>') || (typeof result.dependencyInfo.moduleBase === 'string' && typeof result.dependencyInfo.ordinal === 'number' && typeof result.dependencyInfo.kind === 'string' && result.text === result.dependencyInfo.text)); })()"
                    )
                    .expect("agent native dependencyInfo result"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() { const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'native.segment_info', moduleName: 'libsystem_malloc.dylib', segmentName: '__TEXT' }); return result.kind === 'native.segment_info' && result.moduleName === 'libsystem_malloc.dylib' && result.segmentName === '__TEXT' && ((result.segmentInfo === null && result.text === '<null>') || (typeof result.segmentInfo.moduleBase === 'string' && typeof result.segmentInfo.name === 'string' && typeof result.segmentInfo.vmsizeHex === 'string' && result.text === result.segmentInfo.text)); })()"
                    )
                    .expect("agent native segmentInfo result"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() { const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'native.section_info', moduleName: 'libsystem_malloc.dylib', segmentName: '__TEXT', sectionName: '__text' }); return result.kind === 'native.section_info' && result.moduleName === 'libsystem_malloc.dylib' && result.segmentName === '__TEXT' && result.sectionName === '__text' && ((result.sectionInfo === null && result.text === '<null>') || (typeof result.sectionInfo.moduleBase === 'string' && typeof result.sectionInfo.segmentName === 'string' && typeof result.sectionInfo.offsetHex === 'string' && result.text === result.sectionInfo.text)); })()"
                    )
                    .expect("agent native sectionInfo result"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() { const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'native.load_command_info', moduleName: 'libsystem_malloc.dylib', commandOrIndex: 'LC_UUID' }); return result.kind === 'native.load_command_info' && result.moduleName === 'libsystem_malloc.dylib' && result.commandOrIndex === 'LC_UUID' && ((result.loadCommandInfo === null && result.text === '<null>') || (typeof result.loadCommandInfo.moduleBase === 'string' && typeof result.loadCommandInfo.name === 'string' && typeof result.loadCommandInfo.cmdHex === 'string' && result.text === result.loadCommandInfo.text)); })()"
                    )
                    .expect("agent native loadCommandInfo result"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() { const main = __iosRustFridaAgentApi.handleSpecResult({ kind: 'native.main_image' }); if (main.image === null) { return true; } const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'native.encryption_info', moduleName: main.image.name }); return result.kind === 'native.encryption_info' && (result.encryptionInfo === null || (typeof result.encryptionInfo.cryptoffHex === 'string' && typeof result.encryptionInfo.cryptid === 'number')); })()"
                    )
                    .expect("agent native encryption info result"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() { const main = __iosRustFridaAgentApi.handleSpecResult({ kind: 'native.main_image' }); if (main.image === null) { return true; } const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'native.source_version', moduleName: main.image.name }); return result.kind === 'native.source_version' && (result.sourceVersion === null || typeof result.sourceVersion.version === 'string'); })()"
                    )
                    .expect("agent native source version result"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() { const main = __iosRustFridaAgentApi.handleSpecResult({ kind: 'native.main_image' }); if (main.image === null) { return true; } const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'native.entry_point', moduleName: main.image.name }); return result.kind === 'native.entry_point' && (result.entryPoint === null || (typeof result.entryPoint.entryoffHex === 'string' && typeof result.entryPoint.stacksizeHex === 'string')); })()"
                    )
                    .expect("agent native entry point result"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() { const main = __iosRustFridaAgentApi.handleSpecResult({ kind: 'native.main_image' }); if (main.image === null) { return true; } const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'native.dyld_info', moduleName: main.image.name }); return result.kind === 'native.dyld_info' && (result.dyldInfo === null || (typeof result.dyldInfo.commandName === 'string' && typeof result.dyldInfo.rebaseOffHex === 'string' && typeof result.dyldInfo.exportSizeHex === 'string')); })()"
                    )
                    .expect("agent native dyld info result"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() { const main = __iosRustFridaAgentApi.handleSpecResult({ kind: 'native.main_image' }); if (main.image === null) { return true; } const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'native.linkedit', moduleName: main.image.name }); return result.kind === 'native.linkedit' && (result.linkedit === null || (typeof result.linkedit.vmaddr === 'string' && typeof result.linkedit.vmsizeHex === 'string' && typeof result.linkedit.computedBase === 'string')); })()"
                    )
                    .expect("agent native linkedit result"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() { const main = __iosRustFridaAgentApi.handleSpecResult({ kind: 'native.main_image' }); if (main.image === null) { return true; } const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'native.function_starts', moduleName: main.image.name }); return result.kind === 'native.function_starts' && (result.functionStarts === null || (typeof result.functionStarts.dataoffHex === 'string' && typeof result.functionStarts.count === 'number' && Array.isArray(result.functionStarts.starts))); })()"
                    )
                    .expect("agent native function starts result"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() { const main = __iosRustFridaAgentApi.handleSpecResult({ kind: 'native.main_image' }); if (main.image === null) { return true; } const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'native.code_signature', moduleName: main.image.name }); return result.kind === 'native.code_signature' && (result.codeSignature === null || (typeof result.codeSignature.dataoffHex === 'string' && typeof result.codeSignature.datasizeHex === 'string' && (result.codeSignature.magicHex === null || typeof result.codeSignature.magicHex === 'string'))); })()"
                    )
                    .expect("agent native code signature result"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() { const main = __iosRustFridaAgentApi.handleSpecResult({ kind: 'native.main_image' }); if (main.image === null) { return true; } const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'native.data_in_code', moduleName: main.image.name }); return result.kind === 'native.data_in_code' && (result.dataInCode === null || (typeof result.dataInCode.dataoffHex === 'string' && typeof result.dataInCode.count === 'number' && Array.isArray(result.dataInCode.entries))); })()"
                    )
                    .expect("agent native data in code result"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() { const main = __iosRustFridaAgentApi.handleSpecResult({ kind: 'native.main_image' }); if (main.image === null) { return true; } const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'native.exports_trie', moduleName: main.image.name }); return result.kind === 'native.exports_trie' && (result.exportsTrie === null || (typeof result.exportsTrie.dataoffHex === 'string' && typeof result.exportsTrie.count === 'number' && Array.isArray(result.exportsTrie.entries))); })()"
                    )
                    .expect("agent native exports trie result"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() { const main = __iosRustFridaAgentApi.handleSpecResult({ kind: 'native.main_image' }); if (main.image === null) { return true; } const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'native.chained_fixups', moduleName: main.image.name }); return result.kind === 'native.chained_fixups' && (result.chainedFixups === null || (typeof result.chainedFixups.dataoffHex === 'string' && typeof result.chainedFixups.segmentCount === 'number' && Array.isArray(result.chainedFixups.segments) && Array.isArray(result.chainedFixups.imports))); })()"
                    )
                    .expect("agent native chained fixups result"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() { const main = __iosRustFridaAgentApi.handleSpecResult({ kind: 'native.main_image' }); if (main.image === null) { return true; } const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'native.build_version', moduleName: main.image.name }); return result.kind === 'native.build_version' && (result.buildVersion === null || (typeof result.buildVersion.platform === 'string' && Array.isArray(result.buildVersion.tools))); })()"
                    )
                    .expect("agent native build version result"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() { const main = __iosRustFridaAgentApi.handleSpecResult({ kind: 'native.main_image' }); if (main.image === null) { return true; } const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'native.dylinker', moduleName: main.image.name }); return result.kind === 'native.dylinker' && (result.dylinker === null || (typeof result.dylinker.path === 'string' && typeof result.dylinker.kind === 'string')); })()"
                    )
                    .expect("agent native dylinker result"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() { const main = __iosRustFridaAgentApi.handleSpecResult({ kind: 'native.main_image' }); if (main.image === null) { return true; } const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'native.install_name', moduleName: main.image.name }); return result.kind === 'native.install_name' && (result.installName === null || (typeof result.installName.path === 'string' && typeof result.installName.currentVersion === 'string')); })()"
                    )
                    .expect("agent native install name result"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() { const main = __iosRustFridaAgentApi.handleSpecResult({ kind: 'native.main_image' }); if (main.image === null) { return true; } const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'native.uuid', moduleName: main.image.name }); return result.kind === 'native.uuid' && (result.imageUuid === null || (typeof result.imageUuid.uuid === 'string' && result.imageUuid.uuid.length !== 0)); })()"
                    )
                    .expect("agent native uuid result"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() { const main = __iosRustFridaAgentApi.handleSpecResult({ kind: 'native.main_image' }); if (main.image === null) { return true; } const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'native.rpaths', moduleName: main.image.name, query: null }); return result.kind === 'native.rpaths' && result.count === result.rpaths.length && (result.rpaths.length === 0 || typeof result.rpaths[0].path === 'string'); })()"
                    )
                    .expect("agent native rpaths result"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() { const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'native.rpath_info', moduleName: 'libsystem_malloc.dylib', path: '@loader_path' }); return result.kind === 'native.rpath_info' && result.moduleName === 'libsystem_malloc.dylib' && result.path === '@loader_path' && ((result.rpathInfo === null && result.text === '<null>') || (typeof result.rpathInfo.moduleBase === 'string' && typeof result.rpathInfo.path === 'string' && result.text === result.rpathInfo.text)); })()"
                    )
                    .expect("agent native rpathInfo result"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() { const main = __iosRustFridaAgentApi.handleSpecResult({ kind: 'native.main_image' }); if (main.image === null) { return true; } const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'native.imports', moduleName: main.image.name, query: null }); return result.kind === 'native.imports' && result.count === result.imports.length && (result.imports.length === 0 || (typeof result.imports[0].dylibOrdinal === 'number' && typeof result.imports[0].weakImport === 'boolean')); })()"
                    )
                    .expect("agent native imports result"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() { const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'native.import_info', moduleName: 'libsystem_malloc.dylib', symbolName: 'malloc' }); return result.kind === 'native.import_info' && result.moduleName === 'libsystem_malloc.dylib' && result.symbolName === 'malloc' && ((result.importInfo === null && result.text === '<null>') || (typeof result.importInfo.moduleBase === 'string' && typeof result.importInfo.dylibOrdinal === 'number' && typeof result.importInfo.weakImport === 'boolean' && result.text === result.importInfo.text)); })()"
                    )
                    .expect("agent native importInfo result"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const value = __iosRustFridaAgentApi.handle('swift.methodOwners viewDidLoad'); return value === '' || value.indexOf('[member]') !== -1; })()")
                    .expect("agent swift method owners"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'swift.protocol_info', moduleName: null, protocolName: 'Renderable' }); return result.kind === 'swift.protocol_info' && result.protocolName === 'Renderable' && ((result.protocolInfo === null && result.text === '<null>') || (typeof result.protocolInfo.moduleBase === 'string' && typeof result.protocolInfo.sourceSymbolName === 'string' && typeof result.protocolInfo.sourceOffsetHex === 'string' && result.text === result.protocolInfo.text)); })()")
                    .expect("agent swift protocolInfo result"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'swift.conformance_info', moduleName: null, typeName: 'ViewController', protocolName: 'Renderable' }); return result.kind === 'swift.conformance_info' && result.typeName === 'ViewController' && result.protocolName === 'Renderable' && ((result.conformanceInfo === null && result.text === '<null>') || (typeof result.conformanceInfo.moduleBase === 'string' && typeof result.conformanceInfo.sourceSymbolName === 'string' && typeof result.conformanceInfo.sourceOffsetHex === 'string' && result.text === result.conformanceInfo.text)); })()")
                    .expect("agent swift conformanceInfo result"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'swift.type_info', moduleName: null, typeName: 'ViewController' }); return result.kind === 'swift.type_info' && result.typeName === 'ViewController' && ((result.typeInfo === null && result.text === '<null>') || (typeof result.typeInfo.moduleBase === 'string' && typeof result.typeInfo.sourceSymbolName === 'string' && typeof result.typeInfo.sourceOffsetHex === 'string' && result.text === result.typeInfo.text)); })()")
                    .expect("agent swift typeInfo result"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'swift.method_info', moduleName: null, typeName: 'ViewController', methodName: 'viewDidLoad' }); return result.kind === 'swift.method_info' && result.typeName === 'ViewController' && result.methodName === 'viewDidLoad' && ((result.methodInfo === null && result.text === '<null>') || (typeof result.methodInfo.moduleBase === 'string' && typeof result.methodInfo.name === 'string' && typeof result.methodInfo.offsetHex === 'string' && result.text === result.methodInfo.text)); })()")
                    .expect("agent swift methodInfo result"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'swift.symbol_info', moduleName: null, symbolName: 'ViewController' }); return result.kind === 'swift.symbol_info' && result.symbolName === 'ViewController' && ((result.symbolInfo === null && result.text === '<null>') || (typeof result.symbolInfo.moduleBase === 'string' && typeof result.symbolInfo.name === 'string' && typeof result.symbolInfo.offsetHex === 'string' && result.text === result.symbolInfo.text)); })()")
                    .expect("agent swift symbolInfo result"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'swift.protocols', moduleName: null, query: null }); return result.kind === 'swift.protocols' && result.query === null && result.count === result.protocols.length && (result.protocols.length === 0 || (typeof result.protocols[0].moduleBase === 'string' && typeof result.protocols[0].sourceSymbolName === 'string' && typeof result.protocols[0].sourceOffsetHex === 'string')); })()")
                    .expect("agent swift protocols result"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'swift.conformances', moduleName: null, query: 'ViewController' }); return result.kind === 'swift.conformances' && result.query === 'ViewController' && result.count === result.conformances.length && (result.conformances.length === 0 || (typeof result.conformances[0].moduleBase === 'string' && typeof result.conformances[0].sourceSymbolName === 'string' && typeof result.conformances[0].sourceOffsetHex === 'string' && typeof result.conformances[0].protocolName === 'string')); })()")
                    .expect("agent swift conformances result"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'swift.metadata', moduleName: null, query: 'ViewController' }); return result.kind === 'swift.metadata' && result.query === 'ViewController' && result.count === result.metadata.length && (result.metadata.length === 0 || (typeof result.metadata[0].moduleBase === 'string' && typeof result.metadata[0].sourceSymbolName === 'string' && typeof result.metadata[0].sourceOffsetHex === 'string' && typeof result.metadata[0].sourceKind === 'string')); })()")
                    .expect("agent swift metadata result"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'swift.metadata_info', moduleName: null, typeName: 'ViewController' }); return result.kind === 'swift.metadata_info' && result.typeName === 'ViewController' && ((result.metadataInfo === null && result.text === '<null>') || (typeof result.metadataInfo.moduleBase === 'string' && typeof result.metadataInfo.sourceSymbolName === 'string' && typeof result.metadataInfo.sourceOffsetHex === 'string' && typeof result.metadataInfo.sourceKind === 'string' && result.text === result.metadataInfo.text)); })()")
                    .expect("agent swift metadata info result"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'swift.vtable', moduleName: null, query: 'ViewController' }); return result.kind === 'swift.vtable' && result.query === 'ViewController' && result.count === result.entries.length && (result.entries.length === 0 || (typeof result.entries[0].moduleBase === 'string' && typeof result.entries[0].memberName === 'string' && typeof result.entries[0].offsetHex === 'string' && typeof result.entries[0].isDispatchThunk === 'boolean')); })()")
                    .expect("agent swift vtable result"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'swift.vtable_info', moduleName: null, typeName: 'ViewController', memberName: 'viewDidLoad' }); return result.kind === 'swift.vtable_info' && result.typeName === 'ViewController' && result.memberName === 'viewDidLoad' && ((result.vtableInfo === null && result.text === '<null>') || (typeof result.vtableInfo.moduleBase === 'string' && typeof result.vtableInfo.memberName === 'string' && typeof result.vtableInfo.offsetHex === 'string' && typeof result.vtableInfo.isDispatchThunk === 'boolean' && result.text === result.vtableInfo.text)); })()")
                    .expect("agent swift vtable info result"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'swift.witness_table', moduleName: null, query: 'Renderable' }); return result.kind === 'swift.witness_table' && result.query === 'Renderable' && result.count === result.entries.length && (result.entries.length === 0 || (typeof result.entries[0].moduleBase === 'string' && typeof result.entries[0].protocolName === 'string' && typeof result.entries[0].offsetHex === 'string' && typeof result.entries[0].isAccessor === 'boolean')); })()")
                    .expect("agent swift witness table result"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'swift.witness_table_info', moduleName: null, typeName: 'ViewController', protocolName: 'Renderable' }); return result.kind === 'swift.witness_table_info' && result.typeName === 'ViewController' && result.protocolName === 'Renderable' && ((result.witnessTableInfo === null && result.text === '<null>') || (typeof result.witnessTableInfo.moduleBase === 'string' && typeof result.witnessTableInfo.protocolName === 'string' && typeof result.witnessTableInfo.offsetHex === 'string' && typeof result.witnessTableInfo.isAccessor === 'boolean' && result.text === result.witnessTableInfo.text)); })()")
                    .expect("agent swift witness table info result"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'swift.type_layout', moduleName: null, query: 'ViewController' }); return result.kind === 'swift.type_layout' && result.query === 'ViewController' && result.count === result.layouts.length && (result.layouts.length === 0 || (typeof result.layouts[0].moduleBase === 'string' && Array.isArray(result.layouts[0].metadata) && typeof result.layouts[0].vtableCount === 'number' && typeof result.layouts[0].witnessTableCount === 'number')); })()")
                    .expect("agent swift type layout result"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'swift.type_layout_info', moduleName: null, typeName: 'ViewController' }); return result.kind === 'swift.type_layout_info' && result.typeName === 'ViewController' && ((result.typeLayout === null && result.text === '<null>') || (typeof result.typeLayout.moduleBase === 'string' && Array.isArray(result.typeLayout.metadata) && typeof result.typeLayout.vtableCount === 'number' && typeof result.typeLayout.witnessTableCount === 'number' && result.text === result.typeLayout.text)); })()")
                    .expect("agent swift type layout info result"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() { const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'swift.types', moduleName: null, query: 'ViewController' }); return result.kind === 'swift.types' && result.count === result.types.length && (result.types.length === 0 || (typeof result.types[0].moduleBase === 'string' && typeof result.types[0].sourceSymbolName === 'string' && typeof result.types[0].sourceOffsetHex === 'string')); })()"
                    )
                    .expect("agent swift types result"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const value = __iosRustFridaAgentApi.handle('swift.typeMethods ViewController'); return value === '' || value.indexOf('ViewController') !== -1; })()")
                    .expect("agent swift type methods"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("__iosRustFridaAgentApi.handle('native.hookenv').indexOf('active=') !== -1")
                    .expect("agent native hook env"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const value = __iosRustFridaAgentApi.handle('native.hookenv'); return value.indexOf('advice ') !== -1 || value.indexOf('warning ') !== -1 || value.indexOf('active=<none>') !== -1; })()")
                    .expect("agent native hook env advice"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const main = __iosRustFridaAgentApi.handle('native.mainImage'); if (main === '<null>') { return true; } const path = main.split(' ').slice(2).join(' '); const base = path.split('/').filter(Boolean).pop() || path; const resolved = __iosRustFridaAgentApi.handle('native.base ' + base); return resolved.indexOf('0x') === 0; })()")
                    .expect("agent native base"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const value = __iosRustFridaAgentApi.handle('native.mainImage'); return value === '<null>' || value.indexOf('slide=') !== -1; })()")
                    .expect("agent native main image"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const main = __iosRustFridaAgentApi.handle('native.mainImage'); if (main === '<null>') { return true; } const path = main.split(' ').slice(2).join(' '); const base = path.split('/').filter(Boolean).pop() || path; const filtered = __iosRustFridaAgentApi.handle('native.images ' + base); return filtered.indexOf(base) !== -1; })()")
                    .expect("agent native images filtered"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const malloc = Module.findExportByName(null, 'malloc'); return __iosRustFridaAgentApi.handle('native.image ' + malloc.toString()).indexOf('slide=') !== -1; })()")
                    .expect("agent native image by address"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const value = __iosRustFridaAgentApi.handle('native.imageInfo libsystem_malloc.dylib'); return value === '<null>' || value.indexOf('slide=') !== -1; })()")
                    .expect("agent native imageInfo"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const malloc = Module.findExportByName(null, 'malloc'); return __iosRustFridaAgentApi.handle('native.symbol ' + malloc.toString()).indexOf('malloc') !== -1; })()")
                    .expect("agent native symbol by address"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const value = __iosRustFridaAgentApi.handle('native.symbols malloc'); return value === '' || value.indexOf('malloc') !== -1; })()")
                    .expect("agent native symbols by query"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const value = __iosRustFridaAgentApi.handle('native.symbolInfo malloc'); const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'native.symbol_info', moduleName: null, symbolName: 'malloc' }); return value === result.text && (result.symbolInfo === null || result.symbolInfo.name.indexOf('malloc') !== -1); })()")
                    .expect("agent native symbolInfo"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const value = __iosRustFridaAgentApi.handle('native.exports libsystem_malloc.dylib -- malloc'); return value === '' || value.indexOf('malloc') !== -1; })()")
                    .expect("agent native exports by query"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const main = __iosRustFridaAgentApi.handle('native.mainImage'); if (main === '<null>') { return true; } const path = main.split(' ').slice(2).join(' '); const base = path.split('/').filter(Boolean).pop() || path; const value = __iosRustFridaAgentApi.handle('native.dependencies ' + base); return value === '' || value.indexOf('/') !== -1; })()")
                    .expect("agent native dependencies"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const value = __iosRustFridaAgentApi.handle('native.dependencyInfo libsystem_malloc.dylib -- libSystem.B.dylib'); const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'native.dependency_info', moduleName: 'libsystem_malloc.dylib', pathOrName: 'libSystem.B.dylib' }); return value === result.text && (result.dependencyInfo === null || result.dependencyInfo.path.indexOf('libSystem.B.dylib') !== -1); })()")
                    .expect("agent native dependencyInfo"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const main = __iosRustFridaAgentApi.handle('native.mainImage'); if (main === '<null>') { return true; } const path = main.split(' ').slice(2).join(' '); const base = path.split('/').filter(Boolean).pop() || path; const value = __iosRustFridaAgentApi.handle('native.encryptionInfo ' + base); return value === '<null>' || value.indexOf('cryptoff=') !== -1; })()")
                    .expect("agent native encryption info"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const main = __iosRustFridaAgentApi.handle('native.mainImage'); if (main === '<null>') { return true; } const path = main.split(' ').slice(2).join(' '); const base = path.split('/').filter(Boolean).pop() || path; const value = __iosRustFridaAgentApi.handle('native.sourceVersion ' + base); return value === '<null>' || value.indexOf('version=') !== -1; })()")
                    .expect("agent native source version"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const main = __iosRustFridaAgentApi.handle('native.mainImage'); if (main === '<null>') { return true; } const path = main.split(' ').slice(2).join(' '); const base = path.split('/').filter(Boolean).pop() || path; const value = __iosRustFridaAgentApi.handle('native.entryPoint ' + base); return value === '<null>' || value.indexOf('entryoff=') !== -1; })()")
                    .expect("agent native entry point"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const main = __iosRustFridaAgentApi.handle('native.mainImage'); if (main === '<null>') { return true; } const path = main.split(' ').slice(2).join(' '); const base = path.split('/').filter(Boolean).pop() || path; const value = __iosRustFridaAgentApi.handle('native.dyldInfo ' + base); return value === '<null>' || value.indexOf('rebase=') !== -1; })()")
                    .expect("agent native dyld info"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const main = __iosRustFridaAgentApi.handle('native.mainImage'); if (main === '<null>') { return true; } const path = main.split(' ').slice(2).join(' '); const base = path.split('/').filter(Boolean).pop() || path; const value = __iosRustFridaAgentApi.handle('native.linkedit ' + base); return value === '<null>' || value.indexOf('vmaddr=') !== -1; })()")
                    .expect("agent native linkedit"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const main = __iosRustFridaAgentApi.handle('native.mainImage'); if (main === '<null>') { return true; } const path = main.split(' ').slice(2).join(' '); const base = path.split('/').filter(Boolean).pop() || path; const value = __iosRustFridaAgentApi.handle('native.functionStarts ' + base); return value === '<null>' || value.indexOf('count=') !== -1; })()")
                    .expect("agent native function starts"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const main = __iosRustFridaAgentApi.handle('native.mainImage'); if (main === '<null>') { return true; } const path = main.split(' ').slice(2).join(' '); const base = path.split('/').filter(Boolean).pop() || path; const value = __iosRustFridaAgentApi.handle('native.codeSignature ' + base); return value === '<null>' || value.indexOf('dataoff=') !== -1; })()")
                    .expect("agent native code signature"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const main = __iosRustFridaAgentApi.handle('native.mainImage'); if (main === '<null>') { return true; } const path = main.split(' ').slice(2).join(' '); const base = path.split('/').filter(Boolean).pop() || path; const value = __iosRustFridaAgentApi.handle('native.dataInCode ' + base); return value === '<null>' || value.indexOf('count=') !== -1; })()")
                    .expect("agent native data in code"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const main = __iosRustFridaAgentApi.handle('native.mainImage'); if (main === '<null>') { return true; } const path = main.split(' ').slice(2).join(' '); const base = path.split('/').filter(Boolean).pop() || path; const value = __iosRustFridaAgentApi.handle('native.exportsTrie ' + base); return value === '<null>' || value.indexOf('count=') !== -1; })()")
                    .expect("agent native exports trie"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const main = __iosRustFridaAgentApi.handle('native.mainImage'); if (main === '<null>') { return true; } const path = main.split(' ').slice(2).join(' '); const base = path.split('/').filter(Boolean).pop() || path; const value = __iosRustFridaAgentApi.handle('native.chainedFixups ' + base); return value === '<null>' || value.indexOf('segmentCount=') !== -1; })()")
                    .expect("agent native chained fixups"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const main = __iosRustFridaAgentApi.handle('native.mainImage'); if (main === '<null>') { return true; } const path = main.split(' ').slice(2).join(' '); const base = path.split('/').filter(Boolean).pop() || path; const value = __iosRustFridaAgentApi.handle('native.buildVersion ' + base); return value === '<null>' || value.indexOf('platform=') !== -1; })()")
                    .expect("agent native build version"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const main = __iosRustFridaAgentApi.handle('native.mainImage'); if (main === '<null>') { return true; } const path = main.split(' ').slice(2).join(' '); const base = path.split('/').filter(Boolean).pop() || path; const value = __iosRustFridaAgentApi.handle('native.dylinker ' + base); return value === '<null>' || value.indexOf('/') !== -1; })()")
                    .expect("agent native dylinker"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const main = __iosRustFridaAgentApi.handle('native.mainImage'); if (main === '<null>') { return true; } const path = main.split(' ').slice(2).join(' '); const base = path.split('/').filter(Boolean).pop() || path; const value = __iosRustFridaAgentApi.handle('native.installName ' + base); return value === '<null>' || value.indexOf('/') !== -1; })()")
                    .expect("agent native install name"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const main = __iosRustFridaAgentApi.handle('native.mainImage'); if (main === '<null>') { return true; } const path = main.split(' ').slice(2).join(' '); const base = path.split('/').filter(Boolean).pop() || path; const value = __iosRustFridaAgentApi.handle('native.uuid ' + base); return value === '<null>' || value.indexOf('-') !== -1; })()")
                    .expect("agent native uuid"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const main = __iosRustFridaAgentApi.handle('native.mainImage'); if (main === '<null>') { return true; } const path = main.split(' ').slice(2).join(' '); const base = path.split('/').filter(Boolean).pop() || path; const value = __iosRustFridaAgentApi.handle('native.rpaths ' + base); return value === '' || value.indexOf('@') !== -1 || value.indexOf('/') !== -1; })()")
                    .expect("agent native rpaths"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const value = __iosRustFridaAgentApi.handle('native.rpathInfo libsystem_malloc.dylib -- @loader_path'); const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'native.rpath_info', moduleName: 'libsystem_malloc.dylib', path: '@loader_path' }); return value === result.text && (result.rpathInfo === null || result.rpathInfo.path === '@loader_path'); })()")
                    .expect("agent native rpathInfo"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const main = __iosRustFridaAgentApi.handle('native.mainImage'); if (main === '<null>') { return true; } const path = main.split(' ').slice(2).join(' '); const base = path.split('/').filter(Boolean).pop() || path; const value = __iosRustFridaAgentApi.handle('native.imports ' + base); return value === '' || value.indexOf('!') !== -1; })()")
                    .expect("agent native imports"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const value = __iosRustFridaAgentApi.handle('native.importInfo libsystem_malloc.dylib -- malloc'); const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'native.import_info', moduleName: 'libsystem_malloc.dylib', symbolName: 'malloc' }); return value === result.text && (result.importInfo === null || result.importInfo.name.indexOf('malloc') !== -1); })()")
                    .expect("agent native importInfo"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const value = __iosRustFridaAgentApi.handle('native.exportInfo libsystem_malloc.dylib -- malloc'); const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'native.export_info', moduleName: 'libsystem_malloc.dylib', symbolName: 'malloc' }); return value === result.text && (result.exportInfo === null || result.exportInfo.name.indexOf('malloc') !== -1); })()")
                    .expect("agent native exportInfo"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const main = __iosRustFridaAgentApi.handle('native.mainImage'); if (main === '<null>') { return true; } const path = main.split(' ').slice(2).join(' '); const base = path.split('/').filter(Boolean).pop() || path; const value = __iosRustFridaAgentApi.handle('native.segments ' + base); return value === '' || value.indexOf('vmaddr=') !== -1; })()")
                    .expect("agent native segments"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const value = __iosRustFridaAgentApi.handle('native.segmentInfo libsystem_malloc.dylib -- __TEXT'); const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'native.segment_info', moduleName: 'libsystem_malloc.dylib', segmentName: '__TEXT' }); return value === result.text && (result.segmentInfo === null || result.segmentInfo.name === '__TEXT'); })()")
                    .expect("agent native segmentInfo"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const main = __iosRustFridaAgentApi.handle('native.mainImage'); if (main === '<null>') { return true; } const path = main.split(' ').slice(2).join(' '); const base = path.split('/').filter(Boolean).pop() || path; const value = __iosRustFridaAgentApi.handle('native.sections ' + base); return value === '' || value.indexOf('addr=') !== -1; })()")
                    .expect("agent native sections"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const value = __iosRustFridaAgentApi.handle('native.sectionInfo libsystem_malloc.dylib -- __TEXT __text'); const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'native.section_info', moduleName: 'libsystem_malloc.dylib', segmentName: '__TEXT', sectionName: '__text' }); return value === result.text && (result.sectionInfo === null || (result.sectionInfo.segmentName === '__TEXT' && result.sectionInfo.name === '__text')); })()")
                    .expect("agent native sectionInfo"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const main = __iosRustFridaAgentApi.handle('native.mainImage'); if (main === '<null>') { return true; } const path = main.split(' ').slice(2).join(' '); const base = path.split('/').filter(Boolean).pop() || path; const value = __iosRustFridaAgentApi.handle('native.loadcmds ' + base); return value === '' || value.indexOf('cmd=0x') !== -1; })()")
                    .expect("agent native load commands"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const value = __iosRustFridaAgentApi.handle('native.loadCommandInfo libsystem_malloc.dylib -- LC_UUID'); const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'native.load_command_info', moduleName: 'libsystem_malloc.dylib', commandOrIndex: 'LC_UUID' }); return value === result.text && (result.loadCommandInfo === null || result.loadCommandInfo.name === 'LC_UUID'); })()")
                    .expect("agent native loadCommandInfo"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("__iosRustFridaAgentApi.handle('native.export malloc').indexOf('malloc') !== -1")
                    .expect("agent native export"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const value = __iosRustFridaAgentApi.handleSpec({ kind: 'native.export', moduleName: null, symbolName: 'malloc' }); const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'native.export', moduleName: null, symbolName: 'malloc' }); return value === result.text; })()")
                    .expect("agent spec native export"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const value = __iosRustFridaAgentApi.handleSpec({ kind: 'native.symbol_info', moduleName: null, symbolName: 'malloc' }); const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'native.symbol_info', moduleName: null, symbolName: 'malloc' }); return value === result.text; })()")
                    .expect("agent spec native symbolInfo"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const value = __iosRustFridaAgentApi.handleSpec({ kind: 'native.image_info', moduleName: 'libsystem_malloc.dylib' }); const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'native.image_info', moduleName: 'libsystem_malloc.dylib' }); return value === result.text; })()")
                    .expect("agent spec native imageInfo"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const value = __iosRustFridaAgentApi.handleSpec({ kind: 'native.export_info', moduleName: 'libsystem_malloc.dylib', symbolName: 'malloc' }); const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'native.export_info', moduleName: 'libsystem_malloc.dylib', symbolName: 'malloc' }); return value === result.text; })()")
                    .expect("agent spec native exportInfo"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const value = __iosRustFridaAgentApi.handleSpec({ kind: 'native.import_info', moduleName: 'libsystem_malloc.dylib', symbolName: 'malloc' }); const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'native.import_info', moduleName: 'libsystem_malloc.dylib', symbolName: 'malloc' }); return value === result.text; })()")
                    .expect("agent spec native importInfo"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const value = __iosRustFridaAgentApi.handleSpec({ kind: 'native.dependency_info', moduleName: 'libsystem_malloc.dylib', pathOrName: 'libSystem.B.dylib' }); const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'native.dependency_info', moduleName: 'libsystem_malloc.dylib', pathOrName: 'libSystem.B.dylib' }); return value === result.text; })()")
                    .expect("agent spec native dependencyInfo"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const value = __iosRustFridaAgentApi.handleSpec({ kind: 'native.load_command_info', moduleName: 'libsystem_malloc.dylib', commandOrIndex: 'LC_UUID' }); const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'native.load_command_info', moduleName: 'libsystem_malloc.dylib', commandOrIndex: 'LC_UUID' }); return value === result.text; })()")
                    .expect("agent spec native loadCommandInfo"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const value = __iosRustFridaAgentApi.handleSpec({ kind: 'native.segment_info', moduleName: 'libsystem_malloc.dylib', segmentName: '__TEXT' }); const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'native.segment_info', moduleName: 'libsystem_malloc.dylib', segmentName: '__TEXT' }); return value === result.text; })()")
                    .expect("agent spec native segmentInfo"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const value = __iosRustFridaAgentApi.handleSpec({ kind: 'native.section_info', moduleName: 'libsystem_malloc.dylib', segmentName: '__TEXT', sectionName: '__text' }); const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'native.section_info', moduleName: 'libsystem_malloc.dylib', segmentName: '__TEXT', sectionName: '__text' }); return value === result.text; })()")
                    .expect("agent spec native sectionInfo"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const malloc = Module.findExportByName(null, 'malloc'); const info = DebugSymbol.fromAddress(malloc); if (info === null || !info.moduleName) { return true; } return __iosRustFridaAgentApi.handle('native.export ' + info.moduleName + ' -- malloc').indexOf('malloc') !== -1; })()")
                    .expect("agent native export with module"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("__iosRustFridaAgentApi.handleSpec({ kind: 'pac.strip', address: '0x1234' })")
                    .expect("agent spec pac strip"),
                "0x1234"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const value = __iosRustFridaAgentApi.handleSpec({ kind: 'objc.classes', filter: 'NSObject' }); return value === '' || value.indexOf('NSObject') !== -1; })()")
                    .expect("agent spec objc classes filtered"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const value = __iosRustFridaAgentApi.handleSpec({ kind: 'objc.protocols', filter: 'NS' }); return value === '' || value.indexOf('NS') !== -1; })()")
                    .expect("agent spec objc protocols filtered"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const value = __iosRustFridaAgentApi.handleSpec({ kind: 'objc.class_protocols', className: 'NSObject' }); const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'objc.class_protocols', className: 'NSObject' }); return value === result.text; })()")
                    .expect("agent spec objc classProtocols"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const value = __iosRustFridaAgentApi.handleSpec({ kind: 'objc.class_info', className: 'NSObject', isMetaClass: true }); const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'objc.class_info', className: 'NSObject', isMetaClass: true }); return value === result.text; })()")
                    .expect("agent spec objc classInfo"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const value = __iosRustFridaAgentApi.handleSpec({ kind: 'objc.protocol_protocols', protocolName: 'NSObject' }); const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'objc.protocol_protocols', protocolName: 'NSObject' }); return value === result.text; })()")
                    .expect("agent spec objc protocolProtocols"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const value = __iosRustFridaAgentApi.handleSpec({ kind: 'objc.protocol_methods', protocolName: 'NSObject', isRequired: false, isInstanceMethod: false }); const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'objc.protocol_methods', protocolName: 'NSObject', isRequired: false, isInstanceMethod: false }); return value === result.text; })()")
                    .expect("agent spec objc protocolMethods"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const value = __iosRustFridaAgentApi.handleSpec({ kind: 'objc.protocol_method_info', protocolName: 'NSObject', selectorName: 'description', isRequired: false, isInstanceMethod: false }); const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'objc.protocol_method_info', protocolName: 'NSObject', selectorName: 'description', isRequired: false, isInstanceMethod: false }); return value === result.text; })()")
                    .expect("agent spec objc protocolMethodInfo"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const value = __iosRustFridaAgentApi.handleSpec({ kind: 'objc.protocol_properties', protocolName: 'NSObject' }); const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'objc.protocol_properties', protocolName: 'NSObject' }); return value === result.text; })()")
                    .expect("agent spec objc protocolProperties"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const value = __iosRustFridaAgentApi.handleSpec({ kind: 'objc.protocol_property_info', protocolName: 'NSObject', propertyName: 'description' }); const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'objc.protocol_property_info', protocolName: 'NSObject', propertyName: 'description' }); return value === result.text; })()")
                    .expect("agent spec objc protocolPropertyInfo"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const value = __iosRustFridaAgentApi.handleSpec({ kind: 'objc.superclass', className: 'NSObject' }); const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'objc.superclass', className: 'NSObject' }); return value === result.text; })()")
                    .expect("agent spec objc superclass"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const value = __iosRustFridaAgentApi.handleSpec({ kind: 'objc.class_chain', className: 'NSObject' }); const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'objc.class_chain', className: 'NSObject' }); return value === result.text; })()")
                    .expect("agent spec objc classChain"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const value = __iosRustFridaAgentApi.handleSpec({ kind: 'objc.properties', className: 'NSObject', isClassProperty: true, filter: 'delegate' }); const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'objc.properties', className: 'NSObject', isClassProperty: true, filter: 'delegate' }); return value === result.text; })()")
                    .expect("agent spec objc properties"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const value = __iosRustFridaAgentApi.handleSpec({ kind: 'objc.property_info', className: 'NSObject', propertyName: 'description', isClassProperty: false }); const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'objc.property_info', className: 'NSObject', propertyName: 'description', isClassProperty: false }); return value === result.text; })()")
                    .expect("agent spec objc propertyInfo"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const value = __iosRustFridaAgentApi.handleSpec({ kind: 'objc.ivar_info', className: 'NSObject', ivarName: '_isa' }); const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'objc.ivar_info', className: 'NSObject', ivarName: '_isa' }); return value === result.text; })()")
                    .expect("agent spec objc ivarInfo"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const value = __iosRustFridaAgentApi.handleSpec({ kind: 'objc.ivars', className: 'NSObject', filter: 'delegate' }); const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'objc.ivars', className: 'NSObject', filter: 'delegate' }); return value === result.text; })()")
                    .expect("agent spec objc ivars"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const value = __iosRustFridaAgentApi.handleSpec({ kind: 'swift.protocol_info', moduleName: null, protocolName: 'Renderable' }); const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'swift.protocol_info', moduleName: null, protocolName: 'Renderable' }); return value === result.text; })()")
                    .expect("agent spec swift protocolInfo"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const value = __iosRustFridaAgentApi.handleSpec({ kind: 'swift.conformance_info', moduleName: null, typeName: 'ViewController', protocolName: 'Renderable' }); const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'swift.conformance_info', moduleName: null, typeName: 'ViewController', protocolName: 'Renderable' }); return value === result.text; })()")
                    .expect("agent spec swift conformanceInfo"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const value = __iosRustFridaAgentApi.handleSpec({ kind: 'swift.type_info', moduleName: null, typeName: 'ViewController' }); const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'swift.type_info', moduleName: null, typeName: 'ViewController' }); return value === result.text; })()")
                    .expect("agent spec swift typeInfo"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const value = __iosRustFridaAgentApi.handleSpec({ kind: 'swift.method_info', moduleName: null, typeName: 'ViewController', methodName: 'viewDidLoad' }); const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'swift.method_info', moduleName: null, typeName: 'ViewController', methodName: 'viewDidLoad' }); return value === result.text; })()")
                    .expect("agent spec swift methodInfo"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const value = __iosRustFridaAgentApi.handleSpec({ kind: 'swift.symbol_info', moduleName: null, symbolName: 'ViewController' }); const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'swift.symbol_info', moduleName: null, symbolName: 'ViewController' }); return value === result.text; })()")
                    .expect("agent spec swift symbolInfo"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const value = __iosRustFridaAgentApi.handleSpec({ kind: 'swift.protocols', moduleName: null, query: null }); const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'swift.protocols', moduleName: null, query: null }); return value === result.text; })()")
                    .expect("agent spec swift protocols"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const value = __iosRustFridaAgentApi.handleSpec({ kind: 'swift.conformances', moduleName: null, query: 'ViewController' }); const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'swift.conformances', moduleName: null, query: 'ViewController' }); return value === result.text; })()")
                    .expect("agent spec swift conformances"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const value = __iosRustFridaAgentApi.handleSpec({ kind: 'swift.metadata', moduleName: null, query: 'ViewController' }); const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'swift.metadata', moduleName: null, query: 'ViewController' }); return value === result.text; })()")
                    .expect("agent spec swift metadata"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const value = __iosRustFridaAgentApi.handleSpec({ kind: 'swift.metadata_info', moduleName: null, typeName: 'ViewController' }); const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'swift.metadata_info', moduleName: null, typeName: 'ViewController' }); return value === result.text; })()")
                    .expect("agent spec swift metadata info"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const value = __iosRustFridaAgentApi.handleSpec({ kind: 'swift.vtable', moduleName: null, query: 'ViewController' }); const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'swift.vtable', moduleName: null, query: 'ViewController' }); return value === result.text; })()")
                    .expect("agent spec swift vtable"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const value = __iosRustFridaAgentApi.handleSpec({ kind: 'swift.vtable_info', moduleName: null, typeName: 'ViewController', memberName: 'viewDidLoad' }); const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'swift.vtable_info', moduleName: null, typeName: 'ViewController', memberName: 'viewDidLoad' }); return value === result.text; })()")
                    .expect("agent spec swift vtable info"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const value = __iosRustFridaAgentApi.handleSpec({ kind: 'swift.witness_table', moduleName: null, query: 'Renderable' }); const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'swift.witness_table', moduleName: null, query: 'Renderable' }); return value === result.text; })()")
                    .expect("agent spec swift witness table"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const value = __iosRustFridaAgentApi.handleSpec({ kind: 'swift.witness_table_info', moduleName: null, typeName: 'ViewController', protocolName: 'Renderable' }); const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'swift.witness_table_info', moduleName: null, typeName: 'ViewController', protocolName: 'Renderable' }); return value === result.text; })()")
                    .expect("agent spec swift witness table info"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const value = __iosRustFridaAgentApi.handleSpec({ kind: 'swift.type_layout', moduleName: null, query: 'ViewController' }); const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'swift.type_layout', moduleName: null, query: 'ViewController' }); return value === result.text; })()")
                    .expect("agent spec swift type layout"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const value = __iosRustFridaAgentApi.handleSpec({ kind: 'swift.type_layout_info', moduleName: null, typeName: 'ViewController' }); const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'swift.type_layout_info', moduleName: null, typeName: 'ViewController' }); return value === result.text; })()")
                    .expect("agent spec swift type layout info"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const value = __iosRustFridaAgentApi.handleSpec({ kind: 'swift.type_kinds' }); return value.indexOf('metadata-accessor') !== -1; })()")
                    .expect("agent spec swift type kinds"),
                "true"
            );
        }

        #[test]
        fn memory_reads_and_writes_buffer() {
            let _guard = test_lock().lock().unwrap_or_else(|e| e.into_inner());
            let mut runtime = QuickJsRuntime::new();
            runtime.initialize().expect("init runtime");

            let page_size = 0x1000usize;
            let mapping = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    page_size,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_ANON,
                    -1,
                    0,
                )
            };
            assert_ne!(mapping, libc::MAP_FAILED, "mmap test buffer");

            let addr = mapping as usize;
            unsafe {
                std::ptr::copy_nonoverlapping([0x11u8, 0x22, 0x33, 0x44, 0, 0, 0, 0].as_ptr(), mapping as *mut u8, 8);
            }

            let read_script = format!("Memory.readU16(ptr('0x{addr:x}')).toString()");
            assert_eq!(runtime.eval(&read_script).expect("read memory"), "8721");

            let write_script =
                format!("Memory.writeU32(ptr('0x{addr:x}'), 0x55667788); Memory.readU32(ptr('0x{addr:x}')).toString()");
            assert_eq!(runtime.eval(&write_script).expect("write memory"), "1432778632");
            let bytes = unsafe { std::slice::from_raw_parts(mapping as *const u8, 8) };
            assert_eq!(bytes[..4], [0x88, 0x77, 0x66, 0x55]);
            unsafe {
                libc::munmap(mapping, page_size);
            }
        }

        #[test]
        fn call_native_invokes_strlen() {
            let _guard = test_lock().lock().unwrap_or_else(|e| e.into_inner());
            let mut runtime = QuickJsRuntime::new();
            runtime.initialize().expect("init runtime");

            let bytes = b"hello\0";
            let addr = bytes.as_ptr() as usize;
            let script = format!("callNative(Module.findExportByName(null, 'strlen'), ptr('0x{addr:x}')).toString()");
            assert_eq!(runtime.eval(&script).expect("call native strlen"), "5");
        }

        #[test]
        fn cleanup_resets_runtime_state() {
            let _guard = test_lock().lock().unwrap_or_else(|e| e.into_inner());
            let mut runtime = QuickJsRuntime::new();
            runtime.initialize().expect("init runtime");
            runtime.eval("console.log('hi'); 1 + 1").expect("eval before cleanup");
            assert_eq!(runtime.cleanup().expect("cleanup runtime"), "cleaned up");
            assert_eq!(runtime.status(), &super::RuntimeStatus::Cold);
            assert!(runtime.take_pending_logs().is_empty());
            let err = runtime.eval("1 + 1").expect_err("eval after cleanup must fail");
            assert!(err.to_string().contains("not initialized"));
        }
    }
}

#[cfg(quickjs_runtime_stub)]
mod imp {
    use super::RuntimeStatus;
    use common::{Error, Result};
    use std::collections::BTreeSet;

    pub struct QuickJsRuntime {
        status: RuntimeStatus,
        builtins: BTreeSet<&'static str>,
        last_script: Option<String>,
    }

    impl Default for QuickJsRuntime {
        fn default() -> Self {
            Self::new()
        }
    }

    impl QuickJsRuntime {
        pub fn new() -> Self {
            Self {
                status: RuntimeStatus::Cold,
                builtins: BTreeSet::from([
                    "callNative",
                    "console",
                    "DebugSymbol",
                    "hook",
                    "Interceptor",
                    "Memory",
                    "Module",
                    "Native",
                    "ObjC",
                    "PAC",
                    "Swift",
                    "ptr",
                    "unhook",
                ]),
                last_script: None,
            }
        }

        pub fn status(&self) -> &RuntimeStatus {
            &self.status
        }

        pub fn initialize(&mut self) -> Result<String> {
            Err(Error::Unsupported(
                "quickjs backend is stubbed for this target/build host; build on macOS or provide an Apple SDK-backed C toolchain to compile the real QuickJS runtime".into(),
            ))
        }

        pub fn eval(&mut self, script: &str) -> Result<String> {
            self.last_script = Some(script.trim().to_string());
            Err(Error::Unsupported(
                "quickjs backend is stubbed for this target/build host; build on macOS or provide an Apple SDK-backed C toolchain to compile the real QuickJS runtime".into(),
            ))
        }

        pub fn cleanup(&mut self) -> Result<String> {
            if self.status != RuntimeStatus::Ready {
                return Err(Error::State("quickjs runtime is not initialized".into()));
            }

            self.status = RuntimeStatus::Cold;
            self.last_script = None;
            Ok("cleaned up".into())
        }

        pub fn complete(&self, prefix: &str) -> Vec<String> {
            self.builtins
                .iter()
                .filter(|item| item.starts_with(prefix))
                .map(|item| item.to_string())
                .collect()
        }

        pub fn take_pending_logs(&mut self) -> Vec<String> {
            Vec::new()
        }

        pub fn bootstrap_script(&self) -> String {
            String::new()
        }
    }
}

#[cfg(quickjs_runtime_stub)]
pub use imp::QuickJsRuntime;
#[cfg(not(quickjs_runtime_stub))]
pub use imp::{JSRuntime, QuickJsRuntime};
