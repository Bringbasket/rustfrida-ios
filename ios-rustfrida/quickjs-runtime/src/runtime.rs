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
                        "(function() { const value = ObjC.methodInfo('NSObject', 'init'); return value === null || (typeof value.selector === 'string' && Array.isArray(value.selectorParts) && typeof value.selectorPartCount === 'number' && typeof value.hasSelectorArguments === 'boolean' && typeof value.isUnarySelector === 'boolean' && typeof value.isKeywordSelector === 'boolean' && typeof value.typeEncoding === 'string' && typeof value.isClassMethod === 'boolean'); })()"
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
                    .eval("(function() { const methods = ObjC.methods('NSObject'); return methods.length === 0 || (typeof methods[0].returnTypeName === 'string' && Array.isArray(methods[0].argumentTypeNames) && typeof methods[0].methodTypeInfo === 'object' && Array.isArray(methods[0].selectorParts) && typeof methods[0].selectorPartCount === 'number' && typeof methods[0].hasSelectorArguments === 'boolean' && typeof methods[0].isUnarySelector === 'boolean' && typeof methods[0].isKeywordSelector === 'boolean'); })()")
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
                runtime
                    .eval("Array.isArray(ObjC.classes('NSObject'))")
                    .expect("objc classes filtered"),
                "true"
            );
            assert_eq!(
                runtime.eval("Array.isArray(ObjC.protocols())").expect("objc protocols"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("Array.isArray(ObjC.protocols('NS'))")
                    .expect("objc protocols filtered"),
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
                    .eval("Array.isArray(ObjC.classProtocols('NSObject', 'NS'))")
                    .expect("objc classProtocols filtered"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const value = ObjC.classInfo('NSObject'); return value === null || (typeof value.className === 'string' && typeof value.isMetaClass === 'boolean' && typeof value.instanceSize === 'number' && typeof value.protocolCount === 'number' && typeof value.instancePropertyCount === 'number' && typeof value.classPropertyCount === 'number' && typeof value.ivarCount === 'number' && typeof value.instanceMethodCount === 'number' && typeof value.classMethodCount === 'number' && typeof value.totalPropertyCount === 'number' && typeof value.totalMethodCount === 'number' && typeof value.hasSuperclass === 'boolean' && typeof value.isRootClass === 'boolean' && typeof value.hasProtocols === 'boolean' && typeof value.hasProperties === 'boolean' && typeof value.hasIvars === 'boolean' && typeof value.hasMethods === 'boolean' && typeof value.hasImagePath === 'boolean'); })()")
                    .expect("objc classInfo"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const value = ObjC.protocolInfo('NSObject'); return value === null || (typeof value.protocolName === 'string' && Array.isArray(value.adoptedProtocols) && typeof value.propertyCount === 'number' && typeof value.totalMethodCount === 'number' && typeof value.adoptedProtocolCount === 'number' && typeof value.hasRequiredMethods === 'boolean' && typeof value.hasOptionalMethods === 'boolean' && typeof value.hasInstanceMethods === 'boolean' && typeof value.hasClassMethods === 'boolean' && typeof value.hasProperties === 'boolean' && typeof value.hasAdoptedProtocols === 'boolean' && typeof value.hasImagePath === 'boolean'); })()")
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
                    .eval("Array.isArray(ObjC.protocolProtocols('NSObject', 'NS'))")
                    .expect("objc protocolProtocols filtered"),
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
                    .eval("(function() { const methods = ObjC.protocolMethods('NSObject'); return methods.length === 0 || (typeof methods[0].returnTypeName === 'string' && Array.isArray(methods[0].argumentTypeNames) && typeof methods[0].methodTypeInfo === 'object' && Array.isArray(methods[0].selectorParts) && typeof methods[0].selectorPartCount === 'number' && typeof methods[0].hasSelectorArguments === 'boolean' && typeof methods[0].isUnarySelector === 'boolean' && typeof methods[0].isKeywordSelector === 'boolean'); })()")
                    .expect("objc protocolMethods decoded type info"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const value = ObjC.protocolMethodInfo('NSObject', 'description', false, false); return value === null || (typeof value.selector === 'string' && Array.isArray(value.selectorParts) && typeof value.selectorPartCount === 'number' && typeof value.hasSelectorArguments === 'boolean' && typeof value.isUnarySelector === 'boolean' && typeof value.isKeywordSelector === 'boolean' && typeof value.typeEncoding === 'string' && typeof value.isRequired === 'boolean' && typeof value.isInstanceMethod === 'boolean'); })()")
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
                    .eval("(function() { const value = ObjC.classChain('NSObject'); return Array.isArray(value) && (value.length === 0 || typeof value[0] === 'string'); })()")
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
                    .eval("(function() { const value = ObjC.protocolPropertyInfo('NSObject', 'description'); return value === null || (typeof value.name === 'string' && typeof value.attributes === 'string' && typeof value.isReadwrite === 'boolean' && typeof value.isAtomic === 'boolean' && typeof value.isStrong === 'boolean' && typeof value.isCopy === 'boolean' && typeof value.isWeak === 'boolean' && typeof value.isAssign === 'boolean' && typeof value.hasCustomGetter === 'boolean' && typeof value.hasCustomSetter === 'boolean' && typeof value.hasAccessorCustomization === 'boolean' && typeof value.hasAccessorNames === 'boolean' && typeof value.hasGetterName === 'boolean' && typeof value.hasSetterName === 'boolean' && typeof value.hasBackingIvar === 'boolean' && typeof value.hasOldStyleTypeEncoding === 'boolean' && typeof value.hasOwnershipModifier === 'boolean' && typeof value.hasTypeEncoding === 'boolean' && typeof value.hasTypeName === 'boolean' && typeof value.hasTypeInfo === 'boolean' && typeof value.hasObjectClassName === 'boolean' && typeof value.hasObjectProtocols === 'boolean' && typeof value.hasParsedTokens === 'boolean' && typeof value.objectProtocolCount === 'number' && typeof value.parsedTokenCount === 'number'); })()")
                    .expect("objc protocolPropertyInfo"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const value = ObjC.propertyInfo('NSObject', 'description'); return value === null || (typeof value.name === 'string' && typeof value.attributes === 'string' && typeof value.isClassProperty === 'boolean' && typeof value.isReadwrite === 'boolean' && typeof value.isAtomic === 'boolean' && typeof value.isStrong === 'boolean' && typeof value.isCopy === 'boolean' && typeof value.isWeak === 'boolean' && typeof value.isAssign === 'boolean' && typeof value.hasCustomGetter === 'boolean' && typeof value.hasCustomSetter === 'boolean' && typeof value.hasAccessorCustomization === 'boolean' && typeof value.hasAccessorNames === 'boolean' && typeof value.hasGetterName === 'boolean' && typeof value.hasSetterName === 'boolean' && typeof value.hasBackingIvar === 'boolean' && typeof value.hasOldStyleTypeEncoding === 'boolean' && typeof value.hasOwnershipModifier === 'boolean' && typeof value.hasTypeEncoding === 'boolean' && typeof value.hasTypeName === 'boolean' && typeof value.hasTypeInfo === 'boolean' && typeof value.hasObjectClassName === 'boolean' && typeof value.hasObjectProtocols === 'boolean' && typeof value.hasParsedTokens === 'boolean' && typeof value.objectProtocolCount === 'number' && typeof value.parsedTokenCount === 'number'); })()")
                    .expect("objc propertyInfo"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const value = ObjC.ivarInfo('NSObject', '_isa'); return value === null || (typeof value.name === 'string' && typeof value.typeEncoding === 'string' && typeof value.offset === 'number' && typeof value.kind === 'string' && Array.isArray(value.qualifiers) && Array.isArray(value.qualifierNames) && typeof value.qualifierCount === 'number' && typeof value.hasQualifiers === 'boolean' && typeof value.objectProtocolCount === 'number' && typeof value.hasObjectClassName === 'boolean' && (value.pointeeTypeName === null || typeof value.pointeeTypeName === 'string') && typeof value.hasPointeeType === 'boolean' && typeof value.isPointer === 'boolean' && typeof value.isArray === 'boolean' && (value.arrayCount === null || typeof value.arrayCount === 'number') && (value.memberName === null || typeof value.memberName === 'string') && typeof value.hasMemberName === 'boolean'); })()")
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
                    .eval("(function() { const ivars = ObjC.ivars('NSObject'); return ivars.length === 0 || (typeof ivars[0].typeName === 'string' && typeof ivars[0].typeInfo === 'object' && typeof ivars[0].kind === 'string' && typeof ivars[0].qualifierCount === 'number' && typeof ivars[0].hasQualifiers === 'boolean' && typeof ivars[0].objectProtocolCount === 'number' && typeof ivars[0].hasObjectClassName === 'boolean' && (ivars[0].pointeeTypeName === null || typeof ivars[0].pointeeTypeName === 'string') && typeof ivars[0].hasPointeeType === 'boolean' && typeof ivars[0].isPointer === 'boolean' && typeof ivars[0].isArray === 'boolean' && (ivars[0].arrayCount === null || typeof ivars[0].arrayCount === 'number') && (ivars[0].memberName === null || typeof ivars[0].memberName === 'string') && typeof ivars[0].hasMemberName === 'boolean'); })()")
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
                    .eval("Array.isArray(ObjC.methods('NSObject', 'init'))")
                    .expect("objc methods filtered"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("Array.isArray(ObjC.properties('NSObject', 'delegate'))")
                    .expect("objc properties filtered"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("Array.isArray(ObjC.ivars('NSObject', 'delegate'))")
                    .expect("objc ivars filtered direct"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("Array.isArray(ObjC.protocolMethods('NSObject', false, false, 'description'))")
                    .expect("objc protocolMethods filtered"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("Array.isArray(ObjC.protocolProperties('NSObject', 'description'))")
                    .expect("objc protocolProperties filtered"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("typeof ObjC.methodOwners")
                    .expect("objc methodOwners type"),
                "function"
            );
            assert_eq!(
                runtime
                    .eval("Array.isArray(ObjC.methodOwners('init'))")
                    .expect("objc methodOwners"),
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
                    .eval("(function() { const report = Native.detectHookEnvironment(); return typeof report.conflictState === 'string' && typeof report.riskLevel === 'string' && typeof report.coexistenceLayerAvailable === 'boolean' && typeof report.loadedBackendCount === 'number' && typeof report.filesystemOnlyBackendCount === 'number' && typeof report.loadedImageCount === 'number' && typeof report.filesystemPathCount === 'number' && typeof report.bootstrapInjectionAllowed === 'boolean' && typeof report.queryCommandsAllowed === 'boolean' && typeof report.hookInstallCommandsAllowed === 'boolean' && typeof report.hookStatusCommandsAllowed === 'boolean' && typeof report.hookStopCommandsAllowed === 'boolean'; })()")
                    .expect("native hook env summary fields"),
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
                        "(function() { const previousMethods = Swift.methods; const previousAttach = Interceptor.attach; Swift.methods = function() { return [{ address: ptr('0x18000beef'), name: '$s4MyApp14ViewControllerC11viewDidLoadyyF', demangledName: 'MyApp.ViewController.viewDidLoad()', moduleName: 'MyApp' }]; }; Interceptor.attach = function() { return { detach() {} }; }; try { const result = __iosRustFridaControllerApi.dispatchResult({ kind: 'swift.hook.install', moduleName: 'MyApp', typeName: 'ViewController', methodQuery: 'viewDidLoad' }); return result.kind === 'swift.hook.install' && result.currentKey === 'MyApp::ViewController::viewDidLoad' && result.currentTarget && result.currentTarget.key === 'MyApp::ViewController::viewDidLoad' && result.count === 1 && result.activeCount === 1 && Array.isArray(result.resolvedTargets) && result.resolvedTargets.length === 1 && result.replacedCount === 0; } finally { Swift.methods = previousMethods; Interceptor.attach = previousAttach; globalThis.__iosRustFridaSwiftHooks = {}; globalThis.__iosRustFridaSwiftHooksCurrentKey = null; } })()"
                    )
                    .expect("controller swift hook install result includes current target"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() { const previousMethods = Swift.methods; const previousAttach = Interceptor.attach; Swift.methods = function() { return [{ address: ptr('0x18000beef'), name: '$s4MyApp14ViewControllerC11viewDidLoadyyF', demangledName: 'MyApp.ViewController.viewDidLoad()', moduleName: 'MyApp' }]; }; Interceptor.attach = function() { return { detach() {} }; }; try { const text = __iosRustFridaControllerApi.dispatch({ kind: 'swift.hook.install', moduleName: 'MyApp', typeName: 'ViewController', methodQuery: 'viewDidLoad' }); return text.indexOf('shook installed: MyApp::ViewController::viewDidLoad') === 0 && text.indexOf('MyApp::ViewController::viewDidLoad current=on count=1') !== -1; } finally { Swift.methods = previousMethods; Interceptor.attach = previousAttach; globalThis.__iosRustFridaSwiftHooks = {}; globalThis.__iosRustFridaSwiftHooksCurrentKey = null; } })()"
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
                        "(function() { const text = __iosRustFridaAgentApi.handle('objc.protocols'); const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'objc.protocols', filter: null }); return text === result.text && result.count === result.protocols.length && typeof result.hasFilter === 'boolean' && typeof result.hasProtocols === 'boolean' && (result.firstProtocol === null || typeof result.firstProtocol === 'string') && (result.lastProtocol === null || typeof result.lastProtocol === 'string') && result.text === result.protocols.join('\\n'); })()"
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
                    .eval("(function() { const value = __iosRustFridaAgentApi.handle('objc.findClasses NSObject'); const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'objc.classes', filter: 'NSObject' }); return value === result.text && result.filter === 'NSObject'; })()")
                    .expect("agent objc findClasses"),
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
                    .eval("(function() { const value = __iosRustFridaAgentApi.handle('objc.findProtocols NS'); const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'objc.protocols', filter: 'NS' }); return value === result.text && result.filter === 'NS'; })()")
                    .expect("agent objc findProtocols"),
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
                        "(function() { const value = __iosRustFridaAgentApi.handle('objc.classInfo NSObject meta'); const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'objc.class_info', className: 'NSObject', isMetaClass: true }); return value === result.text && typeof result.hasClassInfo === 'boolean' && typeof result.resolved === 'boolean' && ((result.classInfo === null && result.hasClassInfo === false && result.resolved === false && result.resolvedClassName === null && result.hasSuperclass === false && result.superclassName === null && result.isRootClass === false && result.hasProtocols === false && result.hasProperties === false && result.hasIvars === false && result.hasMethods === false && result.hasImagePath === false && result.imagePath === null && result.protocolCount === 0 && result.totalPropertyCount === 0 && result.totalMethodCount === 0) || (result.classInfo.isMetaClass === true && result.hasClassInfo === true && result.resolved === true && result.resolvedClassName === result.classInfo.className && result.hasSuperclass === (result.classInfo.hasSuperclass === true) && result.superclassName === result.classInfo.superclassName && result.isRootClass === (result.classInfo.isRootClass === true) && result.hasProtocols === (result.classInfo.hasProtocols === true) && result.hasProperties === (result.classInfo.hasProperties === true) && result.hasIvars === (result.classInfo.hasIvars === true) && result.hasMethods === (result.classInfo.hasMethods === true) && result.hasImagePath === (result.classInfo.hasImagePath === true) && result.imagePath === result.classInfo.imagePath && result.protocolCount === result.classInfo.protocolCount && result.totalPropertyCount === result.classInfo.totalPropertyCount && result.totalMethodCount === result.classInfo.totalMethodCount)); })()"
                    )
                    .expect("agent objc classInfo"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() { const value = __iosRustFridaAgentApi.handle('objc.protocolInfo NSObject'); const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'objc.protocol_info', protocolName: 'NSObject' }); return value === result.text && typeof result.hasProtocolInfo === 'boolean' && typeof result.resolved === 'boolean' && ((result.protocolInfo === null && result.hasProtocolInfo === false && result.resolved === false && result.resolvedProtocolName === null && result.hasAdoptedProtocols === false && result.hasRequiredMethods === false && result.hasOptionalMethods === false && result.hasInstanceMethods === false && result.hasClassMethods === false && result.hasProperties === false && result.hasImagePath === false && result.imagePath === null && result.adoptedProtocolCount === 0 && result.totalMethodCount === 0 && result.propertyCount === 0) || (result.protocolInfo.protocolName === 'NSObject' && Array.isArray(result.protocolInfo.adoptedProtocols) && result.hasProtocolInfo === true && result.resolved === true && result.resolvedProtocolName === result.protocolInfo.protocolName && result.hasAdoptedProtocols === (result.protocolInfo.hasAdoptedProtocols === true) && result.hasRequiredMethods === (result.protocolInfo.hasRequiredMethods === true) && result.hasOptionalMethods === (result.protocolInfo.hasOptionalMethods === true) && result.hasInstanceMethods === (result.protocolInfo.hasInstanceMethods === true) && result.hasClassMethods === (result.protocolInfo.hasClassMethods === true) && result.hasProperties === (result.protocolInfo.hasProperties === true) && result.hasImagePath === (result.protocolInfo.hasImagePath === true) && result.imagePath === result.protocolInfo.imagePath && result.adoptedProtocolCount === result.protocolInfo.adoptedProtocolCount && result.totalMethodCount === result.protocolInfo.totalMethodCount && result.propertyCount === result.protocolInfo.propertyCount)); })()"
                    )
                    .expect("agent objc protocolInfo"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() { const value = __iosRustFridaAgentApi.handle('objc.classProtocols NSObject NS'); const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'objc.class_protocols', className: 'NSObject', filter: 'NS' }); return value === result.text && result.filter === 'NS' && result.hasFilter === true && typeof result.hasProtocols === 'boolean' && (result.firstProtocol === null || typeof result.firstProtocol === 'string') && (result.lastProtocol === null || typeof result.lastProtocol === 'string') && result.count === result.protocols.length; })()"
                    )
                    .expect("agent objc classProtocols"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() { const value = __iosRustFridaAgentApi.handle('objc.protocolProtocols NSObject NS'); const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'objc.protocol_protocols', protocolName: 'NSObject', filter: 'NS' }); return value === result.text && result.filter === 'NS' && result.hasFilter === true && typeof result.hasProtocols === 'boolean' && (result.firstProtocol === null || typeof result.firstProtocol === 'string') && (result.lastProtocol === null || typeof result.lastProtocol === 'string') && result.count === result.protocols.length; })()"
                    )
                    .expect("agent objc protocolProtocols"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() { const value = __iosRustFridaAgentApi.handle('objc.protocolMethods NSObject optional class description'); const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'objc.protocol_methods', protocolName: 'NSObject', isRequired: false, isInstanceMethod: false, filter: 'description' }); return value === result.text && result.filter === 'description' && result.count === result.methods.length; })()"
                    )
                    .expect("agent objc protocolMethods"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() { const value = __iosRustFridaAgentApi.handle('objc.protocolMethodInfo NSObject description optional class'); const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'objc.protocol_method_info', protocolName: 'NSObject', selectorName: 'description', isRequired: false, isInstanceMethod: false }); return value === result.text && typeof result.hasMethodInfo === 'boolean' && typeof result.resolved === 'boolean' && ((result.methodInfo === null && result.hasMethodInfo === false && result.resolved === false && result.resolvedSelector === null && result.imagePath === null && result.hasSelectorArguments === false && result.isUnarySelector === false && result.isKeywordSelector === false && result.hasExplicitArguments === false && result.returnsVoid === false && result.returnsObject === false && result.returnsBlock === false) || (result.methodInfo.selector === 'description' && typeof result.methodInfo.typeEncoding === 'string' && result.hasMethodInfo === true && result.resolved === true && result.resolvedSelector === result.methodInfo.selector && result.imagePath === result.methodInfo.imagePath && result.hasSelectorArguments === (result.methodInfo.hasSelectorArguments === true) && result.isUnarySelector === (result.methodInfo.isUnarySelector === true) && result.isKeywordSelector === (result.methodInfo.isKeywordSelector === true) && result.hasExplicitArguments === (result.methodInfo.hasExplicitArguments === true) && result.returnsVoid === (result.methodInfo.returnsVoid === true) && result.returnsObject === (result.methodInfo.returnsObject === true) && result.returnsBlock === (result.methodInfo.returnsBlock === true))); })()"
                    )
                    .expect("agent objc protocolMethodInfo"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() { const value = __iosRustFridaAgentApi.handle('objc.protocolProperties NSObject description'); const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'objc.protocol_properties', protocolName: 'NSObject', filter: 'description' }); return value === result.text && result.filter === 'description' && result.count === result.properties.length; })()"
                    )
                    .expect("agent objc protocolProperties"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() { const value = __iosRustFridaAgentApi.handle('objc.protocolPropertyInfo NSObject description'); const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'objc.protocol_property_info', protocolName: 'NSObject', propertyName: 'description' }); return value === result.text && typeof result.hasPropertyInfo === 'boolean' && typeof result.resolved === 'boolean' && ((result.propertyInfo === null && result.hasPropertyInfo === false && result.resolved === false && result.resolvedName === null && result.typeName === null && result.ownership === null && result.objectClassName === null && result.hasAccessorCustomization === false && result.hasObjectProtocols === false && result.hasTypeInfo === false && result.isObject === false && result.isBlock === false && result.imagePath === null) || (result.propertyInfo.name === 'description' && typeof result.propertyInfo.attributes === 'string' && result.hasPropertyInfo === true && result.resolved === true && result.resolvedName === result.propertyInfo.name && result.typeName === result.propertyInfo.typeName && result.ownership === result.propertyInfo.ownership && result.objectClassName === result.propertyInfo.objectClassName && result.hasAccessorCustomization === (result.propertyInfo.hasAccessorCustomization === true) && result.hasObjectProtocols === (result.propertyInfo.hasObjectProtocols === true) && result.hasTypeInfo === (result.propertyInfo.hasTypeInfo === true) && result.isObject === (result.propertyInfo.isObject === true) && result.isBlock === (result.propertyInfo.isBlock === true) && result.imagePath === result.propertyInfo.imagePath)); })()"
                    )
                    .expect("agent objc protocolPropertyInfo"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() { const value = __iosRustFridaAgentApi.handle('objc.superclass NSObject'); const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'objc.superclass', className: 'NSObject' }); return value === result.text && typeof result.classExists === 'boolean' && typeof result.resolved === 'boolean' && ((result.superclass === null && result.classExists === false && result.resolved === false && result.resolvedSuperclassName === null && result.hasSuperclass === false && result.isRootClass === false) || (result.superclass === null && result.classExists === true && result.resolved === true && result.resolvedSuperclassName === null && result.hasSuperclass === false && result.isRootClass === true) || (typeof result.superclass === 'string' && result.classExists === true && result.resolved === true && result.resolvedSuperclassName === result.superclass && result.hasSuperclass === true && result.isRootClass === false)); })()"
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
                        "(function() { const value = __iosRustFridaAgentApi.handle('objc.propertyInfo NSObject description'); const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'objc.property_info', className: 'NSObject', propertyName: 'description', isClassProperty: false }); return value === result.text && typeof result.hasPropertyInfo === 'boolean' && typeof result.resolved === 'boolean' && ((result.propertyInfo === null && result.hasPropertyInfo === false && result.resolved === false && result.resolvedName === null && result.typeName === null && result.ownership === null && result.objectClassName === null && result.hasAccessorCustomization === false && result.hasObjectProtocols === false && result.hasTypeInfo === false && result.isObject === false && result.isBlock === false && result.imagePath === null) || (result.propertyInfo.name === 'description' && typeof result.propertyInfo.attributes === 'string' && result.hasPropertyInfo === true && result.resolved === true && result.resolvedName === result.propertyInfo.name && result.typeName === result.propertyInfo.typeName && result.ownership === result.propertyInfo.ownership && result.objectClassName === result.propertyInfo.objectClassName && result.hasAccessorCustomization === (result.propertyInfo.hasAccessorCustomization === true) && result.hasObjectProtocols === (result.propertyInfo.hasObjectProtocols === true) && result.hasTypeInfo === (result.propertyInfo.hasTypeInfo === true) && result.isObject === (result.propertyInfo.isObject === true) && result.isBlock === (result.propertyInfo.isBlock === true) && result.imagePath === result.propertyInfo.imagePath)); })()"
                    )
                    .expect("agent objc propertyInfo"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() { const value = __iosRustFridaAgentApi.handle('objc.ivarInfo NSObject _isa'); const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'objc.ivar_info', className: 'NSObject', ivarName: '_isa' }); return value === result.text && typeof result.hasIvarInfo === 'boolean' && typeof result.resolved === 'boolean' && ((result.ivarInfo === null && result.hasIvarInfo === false && result.resolved === false && result.resolvedName === null && result.typeName === null && result.kindName === null && result.objectClassName === null && result.hasQualifiers === false && result.hasPointeeType === false && result.isPointer === false && result.isArray === false && result.memberName === null && result.imagePath === null) || (result.ivarInfo.name === '_isa' && typeof result.ivarInfo.typeEncoding === 'string' && result.hasIvarInfo === true && result.resolved === true && result.resolvedName === result.ivarInfo.name && result.typeName === result.ivarInfo.typeName && result.kindName === result.ivarInfo.kind && result.objectClassName === result.ivarInfo.objectClassName && result.hasQualifiers === (result.ivarInfo.hasQualifiers === true) && result.hasPointeeType === (result.ivarInfo.hasPointeeType === true) && result.isPointer === (result.ivarInfo.isPointer === true) && result.isArray === (result.ivarInfo.isArray === true) && result.memberName === result.ivarInfo.memberName && result.imagePath === result.ivarInfo.imagePath)); })()"
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
                        "(function() { const value = __iosRustFridaAgentApi.handle('objc.findMethods NSObject init'); const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'objc.methods', className: 'NSObject', isClassMethod: false, filter: 'init' }); return value === result.text && result.filter === 'init' && result.count === result.methods.length; })()"
                    )
                    .expect("agent objc findMethods"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() { const value = __iosRustFridaAgentApi.handle('objc.classExists NSObject'); const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'objc.class_exists', className: 'NSObject' }); return value === result.text && result.resolved === true && result.exists === (result.resolvedClassName !== null); })()"
                    )
                    .expect("agent objc classExists"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() { const value = __iosRustFridaAgentApi.handle('objc.selector init'); const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'objc.selector', selectorName: 'init' }); return value === result.text && typeof result.hasPointer === 'boolean' && typeof result.resolved === 'boolean' && ((result.pointer === null && result.hasPointer === false && result.resolved === false && result.resolvedSelectorName === null && result.resolvedPointer === null && result.text === '<null>') || (typeof result.pointer === 'string' && result.hasPointer === true && result.resolved === true && result.resolvedSelectorName === 'init' && result.resolvedPointer === result.pointer)); })()"
                    )
                    .expect("agent objc selector"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() { const value = __iosRustFridaAgentApi.handle('objc.classImage NSObject'); const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'objc.class_image', className: 'NSObject' }); return value === result.text && typeof result.hasImagePath === 'boolean' && typeof result.resolved === 'boolean' && ((result.imagePath === null && result.hasImagePath === false && result.resolved === false && result.resolvedImagePath === null) || (typeof result.imagePath === 'string' && result.hasImagePath === true && result.resolved === true && result.resolvedImagePath === result.imagePath)); })()"
                    )
                    .expect("agent objc classImage"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() { const value = __iosRustFridaAgentApi.handle('objc.methodImage NSObject init'); const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'objc.method_image', className: 'NSObject', selectorName: 'init', isClassMethod: false }); return value === result.text && typeof result.hasImagePath === 'boolean' && typeof result.resolved === 'boolean' && ((result.imagePath === null && result.hasImagePath === false && result.resolved === false && result.resolvedImagePath === null) || (typeof result.imagePath === 'string' && result.hasImagePath === true && result.resolved === true && result.resolvedImagePath === result.imagePath)); })()"
                    )
                    .expect("agent objc methodImage"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() { const value = __iosRustFridaAgentApi.handle('objc.methodImp NSObject init'); const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'objc.method_imp', className: 'NSObject', selectorName: 'init', isClassMethod: false }); return value === result.text && typeof result.hasImp === 'boolean' && typeof result.resolved === 'boolean' && ((result.imp === null && result.hasImp === false && result.resolved === false && result.resolvedImp === null) || (typeof result.imp === 'string' && result.hasImp === true && result.resolved === true && result.resolvedImp === result.imp)); })()"
                    )
                    .expect("agent objc methodImp"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() { const value = __iosRustFridaAgentApi.handle('objc.methodInfo NSObject init'); const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'objc.method_info', className: 'NSObject', selectorName: 'init', isClassMethod: false }); return value === result.text && typeof result.hasMethodInfo === 'boolean' && typeof result.resolved === 'boolean' && ((result.methodInfo === null && result.hasMethodInfo === false && result.resolved === false && result.resolvedSelector === null && result.imagePath === null && result.hasSelectorArguments === false && result.isUnarySelector === false && result.isKeywordSelector === false && result.hasExplicitArguments === false && result.returnsVoid === false && result.returnsObject === false && result.returnsBlock === false) || (result.methodInfo.selector === 'init' && typeof result.methodInfo.imp === 'string' && result.hasMethodInfo === true && result.resolved === true && result.resolvedSelector === result.methodInfo.selector && result.imagePath === result.methodInfo.imagePath && result.hasSelectorArguments === (result.methodInfo.hasSelectorArguments === true) && result.isUnarySelector === (result.methodInfo.isUnarySelector === true) && result.isKeywordSelector === (result.methodInfo.isKeywordSelector === true) && result.hasExplicitArguments === (result.methodInfo.hasExplicitArguments === true) && result.returnsVoid === (result.methodInfo.returnsVoid === true) && result.returnsObject === (result.methodInfo.returnsObject === true) && result.returnsBlock === (result.methodInfo.returnsBlock === true))); })()"
                    )
                    .expect("agent objc methodInfo"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() { const value = __iosRustFridaAgentApi.handle('objc.selectorName 0x0'); const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'objc.selector_name', selector: '0x0' }); return value === result.text && result.name === null && result.hasName === false && result.resolved === false && result.resolvedName === null; })()"
                    )
                    .expect("agent objc selectorName"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() { const value = __iosRustFridaAgentApi.handle('objc.objectClassName 0x0'); const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'objc.object_class_name', object: '0x0' }); return value === result.text && result.className === null && result.hasClassName === false && result.resolved === false && result.resolvedClassName === null; })()"
                    )
                    .expect("agent objc objectClassName"),
                "true"
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
                    .eval("(function() { const value = __iosRustFridaAgentApi.handle('swift.findProtocols Renderable'); const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'swift.protocols', moduleName: null, query: 'Renderable' }); return value === result.text && result.query === 'Renderable' && result.count === result.protocols.length; })()")
                    .expect("agent swift findProtocols"),
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
                        "(function() { const value = __iosRustFridaAgentApi.handle('swift.available'); const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'swift.available' }); return value === result.text && result.available === Swift.available && result.resolved === true; })()"
                    )
                    .expect("agent swift available"),
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
                    .eval(
                        "(function() { const value = __iosRustFridaAgentApi.handle('swift.demangle $s4Demo6methodyyF'); const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'swift.demangle', symbol: '$s4Demo6methodyyF' }); return value === result.text && ((result.demangled === null && result.resolved === false && result.resolvedSymbol === null && result.text === '<unavailable>') || (typeof result.demangled === 'string' && result.resolved === true && result.resolvedSymbol === result.demangled)); })()"
                    )
                    .expect("agent swift demangle result"),
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
                    .eval("(function() { const value = __iosRustFridaAgentApi.handle('swift.findTypes ViewController'); const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'swift.types', moduleName: null, query: 'ViewController' }); return value === result.text && result.query === 'ViewController' && result.count === result.types.length; })()")
                    .expect("agent swift findTypes"),
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
                        "(function() { const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'pac.available' }); return result.kind === 'pac.available' && result.available === PAC.available && result.resolved === true && result.text === String(PAC.available); })()"
                    )
                    .expect("agent pac available result"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() { const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'pac.arm64e' }); return result.kind === 'pac.arm64e' && typeof result.arm64e === 'boolean' && result.resolved === true && result.text === String(result.arm64e); })()"
                    )
                    .expect("agent pac arm64e result"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() { const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'pac.image', moduleName: 'libsystem_malloc.dylib' }); return result.kind === 'pac.image' && result.moduleName === 'libsystem_malloc.dylib' && typeof result.hasImage === 'boolean' && typeof result.resolved === 'boolean' && ((result.arm64e === null && result.hasImage === false && result.resolved === false && result.resolvedModuleName === null && result.text === '<null>') || (typeof result.arm64e === 'boolean' && result.hasImage === true && result.resolved === true && result.resolvedModuleName === result.moduleName && result.text === String(result.arm64e))); })()"
                    )
                    .expect("agent pac image result"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() { const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'pac.strip', address: '0x1234' }); return result.kind === 'pac.strip' && result.address === '0x1234' && result.resolved === true && typeof result.changed === 'boolean' && result.strippedAddress === result.stripped && result.text === result.stripped; })()"
                    )
                    .expect("agent pac strip result"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() { const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'pac.stripdata', address: '0x1234' }); return result.kind === 'pac.stripdata' && result.address === '0x1234' && result.resolved === true && typeof result.changed === 'boolean' && result.strippedAddress === result.stripped && result.text === result.stripped; })()"
                    )
                    .expect("agent pac stripdata result"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() { const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'pac.images', filter: null }); return result.kind === 'pac.images' && result.filter === null && result.hasFilter === false && result.count === result.images.length && typeof result.hasImages === 'boolean' && ((result.images.length === 0 && result.hasImages === false && result.firstImageName === null && result.lastImageName === null) || (result.hasImages === true && typeof result.firstImageName === 'string' && typeof result.lastImageName === 'string' && typeof result.images[0].path === 'string')); })()"
                    )
                    .expect("agent pac images result"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() {
                            const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'objc.classes', filter: null });
                            if (result.kind !== 'objc.classes' || result.filter !== null || result.hasFilter !== false) {
                                return false;
                            }
                            if (result.count !== result.classes.length || typeof result.hasClasses !== 'boolean') {
                                return false;
                            }
                            if (typeof result.uniqueImagePathCount !== 'number' ||
                                    typeof result.classesWithImagePathCount !== 'number' ||
                                    typeof result.rootClassCount !== 'number' ||
                                    typeof result.classesWithProtocolsCount !== 'number' ||
                                    typeof result.classesWithPropertiesCount !== 'number' ||
                                    typeof result.classesWithIvarsCount !== 'number' ||
                                    typeof result.classesWithMethodsCount !== 'number' ||
                                    !Array.isArray(result.imagePaths)) {
                                return false;
                            }
                            if (result.classes.length === 0) {
                                return result.hasClasses === false &&
                                    result.firstClass === null &&
                                    result.lastClass === null;
                            }
                            const imageSummary = result.imagePaths.length === 0 ? null : result.imagePaths[0];
                            return result.hasClasses === true &&
                                typeof result.firstClass === 'string' &&
                                typeof result.lastClass === 'string' &&
                                result.text === result.classes.join('\\n') &&
                                (result.firstImagePath === null || typeof result.firstImagePath === 'string') &&
                                (result.lastImagePath === null || typeof result.lastImagePath === 'string') &&
                                (imageSummary === null || (
                                    typeof imageSummary.imagePath === 'string' &&
                                    typeof imageSummary.count === 'number' &&
                                    typeof imageSummary.firstClass === 'string' &&
                                    typeof imageSummary.lastClass === 'string'
                                ));
                        })()"
                    )
                    .expect("agent objc classes result"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() {
                            const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'objc.protocols', filter: null });
                            if (result.kind !== 'objc.protocols' || result.filter !== null || result.hasFilter !== false) {
                                return false;
                            }
                            if (result.count !== result.protocols.length || typeof result.hasProtocols !== 'boolean') {
                                return false;
                            }
                            if (typeof result.uniqueImagePathCount !== 'number' ||
                                    typeof result.protocolsWithImagePathCount !== 'number' ||
                                    typeof result.protocolsWithAdoptedProtocolsCount !== 'number' ||
                                    typeof result.protocolsWithRequiredMethodsCount !== 'number' ||
                                    typeof result.protocolsWithOptionalMethodsCount !== 'number' ||
                                    typeof result.protocolsWithInstanceMethodsCount !== 'number' ||
                                    typeof result.protocolsWithClassMethodsCount !== 'number' ||
                                    typeof result.protocolsWithPropertiesCount !== 'number' ||
                                    typeof result.totalAdoptedProtocolCount !== 'number' ||
                                    typeof result.totalRequiredMethodCount !== 'number' ||
                                    typeof result.totalOptionalMethodCount !== 'number' ||
                                    typeof result.totalPropertyCount !== 'number' ||
                                    !Array.isArray(result.imagePaths)) {
                                return false;
                            }
                            if (result.protocols.length === 0) {
                                return result.hasProtocols === false &&
                                    result.firstProtocol === null &&
                                    result.lastProtocol === null;
                            }
                            const imageSummary = result.imagePaths.length === 0 ? null : result.imagePaths[0];
                            return result.hasProtocols === true &&
                                typeof result.firstProtocol === 'string' &&
                                typeof result.lastProtocol === 'string' &&
                                result.text === result.protocols.join('\\n') &&
                                (result.firstImagePath === null || typeof result.firstImagePath === 'string') &&
                                (result.lastImagePath === null || typeof result.lastImagePath === 'string') &&
                                (imageSummary === null || (
                                    typeof imageSummary.imagePath === 'string' &&
                                    typeof imageSummary.count === 'number' &&
                                    typeof imageSummary.firstProtocol === 'string' &&
                                    typeof imageSummary.lastProtocol === 'string'
                                ));
                        })()"
                    )
                    .expect("agent objc protocols result"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() { const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'objc.class_info', className: 'NSObject', isMetaClass: true }); return result.kind === 'objc.class_info' && result.className === 'NSObject' && result.isMetaClass === true && typeof result.hasClassInfo === 'boolean' && typeof result.resolved === 'boolean' && ((result.classInfo === null && result.hasClassInfo === false && result.resolved === false && result.resolvedClassName === null && result.hasSuperclass === false && result.superclassName === null && result.isRootClass === false && result.hasProtocols === false && result.hasProperties === false && result.hasIvars === false && result.hasMethods === false && result.hasImagePath === false && result.imagePath === null && result.protocolCount === 0 && result.totalPropertyCount === 0 && result.totalMethodCount === 0 && result.text === '<null>') || (typeof result.classInfo.classPointer === 'string' && result.classInfo.isMetaClass === true && typeof result.classInfo.instanceSize === 'number' && typeof result.classInfo.protocolCount === 'number' && typeof result.classInfo.totalPropertyCount === 'number' && typeof result.classInfo.totalMethodCount === 'number' && result.hasClassInfo === true && result.resolved === true && result.resolvedClassName === result.classInfo.className && result.hasSuperclass === (result.classInfo.hasSuperclass === true) && result.superclassName === result.classInfo.superclassName && result.isRootClass === (result.classInfo.isRootClass === true) && result.hasProtocols === (result.classInfo.hasProtocols === true) && result.hasProperties === (result.classInfo.hasProperties === true) && result.hasIvars === (result.classInfo.hasIvars === true) && result.hasMethods === (result.classInfo.hasMethods === true) && result.hasImagePath === (result.classInfo.hasImagePath === true) && result.imagePath === result.classInfo.imagePath && result.protocolCount === result.classInfo.protocolCount && result.totalPropertyCount === result.classInfo.totalPropertyCount && result.totalMethodCount === result.classInfo.totalMethodCount && result.text === result.classInfo.text)); })()"
                    )
                    .expect("agent objc classInfo result"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() { const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'objc.protocol_info', protocolName: 'NSObject' }); return result.kind === 'objc.protocol_info' && result.protocolName === 'NSObject' && typeof result.hasProtocolInfo === 'boolean' && typeof result.resolved === 'boolean' && ((result.protocolInfo === null && result.hasProtocolInfo === false && result.resolved === false && result.resolvedProtocolName === null && result.hasAdoptedProtocols === false && result.hasRequiredMethods === false && result.hasOptionalMethods === false && result.hasInstanceMethods === false && result.hasClassMethods === false && result.hasProperties === false && result.hasImagePath === false && result.imagePath === null && result.adoptedProtocolCount === 0 && result.totalMethodCount === 0 && result.propertyCount === 0 && result.text === '<null>') || (typeof result.protocolInfo.protocolPointer === 'string' && Array.isArray(result.protocolInfo.adoptedProtocols) && typeof result.protocolInfo.propertyCount === 'number' && typeof result.protocolInfo.totalMethodCount === 'number' && typeof result.protocolInfo.adoptedProtocolCount === 'number' && typeof result.protocolInfo.hasRequiredMethods === 'boolean' && typeof result.protocolInfo.hasOptionalMethods === 'boolean' && typeof result.protocolInfo.hasInstanceMethods === 'boolean' && typeof result.protocolInfo.hasClassMethods === 'boolean' && typeof result.protocolInfo.hasProperties === 'boolean' && typeof result.protocolInfo.hasAdoptedProtocols === 'boolean' && result.hasProtocolInfo === true && result.resolved === true && result.resolvedProtocolName === result.protocolInfo.protocolName && result.hasAdoptedProtocols === (result.protocolInfo.hasAdoptedProtocols === true) && result.hasRequiredMethods === (result.protocolInfo.hasRequiredMethods === true) && result.hasOptionalMethods === (result.protocolInfo.hasOptionalMethods === true) && result.hasInstanceMethods === (result.protocolInfo.hasInstanceMethods === true) && result.hasClassMethods === (result.protocolInfo.hasClassMethods === true) && result.hasProperties === (result.protocolInfo.hasProperties === true) && result.hasImagePath === (result.protocolInfo.hasImagePath === true) && result.imagePath === result.protocolInfo.imagePath && result.adoptedProtocolCount === result.protocolInfo.adoptedProtocolCount && result.totalMethodCount === result.protocolInfo.totalMethodCount && result.propertyCount === result.protocolInfo.propertyCount && result.text === result.protocolInfo.text)); })()"
                    )
                    .expect("agent objc protocolInfo result"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() {
                            const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'objc.class_protocols', className: 'NSObject', filter: 'NS' });
                            if (result.kind !== 'objc.class_protocols' || result.className !== 'NSObject' || result.filter !== 'NS' || result.hasFilter !== true) {
                                return false;
                            }
                            if (result.count !== result.protocols.length || typeof result.hasProtocols !== 'boolean') {
                                return false;
                            }
                            return typeof result.uniqueImagePathCount === 'number' &&
                                typeof result.protocolsWithImagePathCount === 'number' &&
                                typeof result.protocolsWithAdoptedProtocolsCount === 'number' &&
                                typeof result.protocolsWithRequiredMethodsCount === 'number' &&
                                typeof result.protocolsWithOptionalMethodsCount === 'number' &&
                                typeof result.protocolsWithInstanceMethodsCount === 'number' &&
                                typeof result.protocolsWithClassMethodsCount === 'number' &&
                                typeof result.protocolsWithPropertiesCount === 'number' &&
                                typeof result.totalAdoptedProtocolCount === 'number' &&
                                typeof result.totalRequiredMethodCount === 'number' &&
                                typeof result.totalOptionalMethodCount === 'number' &&
                                typeof result.totalPropertyCount === 'number' &&
                                Array.isArray(result.imagePaths) &&
                                result.text === result.protocols.join('\\n') &&
                                (result.firstProtocol === null || typeof result.firstProtocol === 'string') &&
                                (result.lastProtocol === null || typeof result.lastProtocol === 'string') &&
                                (result.firstImagePath === null || typeof result.firstImagePath === 'string') &&
                                (result.lastImagePath === null || typeof result.lastImagePath === 'string');
                        })()"
                    )
                    .expect("agent objc classProtocols result"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() { const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'objc.method_info', className: 'NSObject', selectorName: 'init', isClassMethod: false }); return result.kind === 'objc.method_info' && result.className === 'NSObject' && result.selectorName === 'init' && result.isClassMethod === false && typeof result.hasMethodInfo === 'boolean' && typeof result.resolved === 'boolean' && ((result.methodInfo === null && result.hasMethodInfo === false && result.resolved === false && result.resolvedSelector === null && result.imagePath === null && result.hasSelectorArguments === false && result.isUnarySelector === false && result.isKeywordSelector === false && result.hasExplicitArguments === false && result.returnsVoid === false && result.returnsObject === false && result.returnsBlock === false && result.text === '<null>') || (typeof result.methodInfo.methodPointer === 'string' && typeof result.methodInfo.imp === 'string' && typeof result.methodInfo.typeEncoding === 'string' && Array.isArray(result.methodInfo.selectorParts) && typeof result.methodInfo.selectorPartCount === 'number' && typeof result.methodInfo.hasSelectorArguments === 'boolean' && typeof result.methodInfo.isUnarySelector === 'boolean' && typeof result.methodInfo.isKeywordSelector === 'boolean' && typeof result.methodInfo.hasExplicitArguments === 'boolean' && typeof result.methodInfo.hiddenArgumentCount === 'number' && typeof result.methodInfo.returnsVoid === 'boolean' && typeof result.methodInfo.returnsObject === 'boolean' && typeof result.methodInfo.returnsBlock === 'boolean' && result.hasMethodInfo === true && result.resolved === true && result.resolvedSelector === result.methodInfo.selector && result.imagePath === result.methodInfo.imagePath && result.hasSelectorArguments === (result.methodInfo.hasSelectorArguments === true) && result.isUnarySelector === (result.methodInfo.isUnarySelector === true) && result.isKeywordSelector === (result.methodInfo.isKeywordSelector === true) && result.hasExplicitArguments === (result.methodInfo.hasExplicitArguments === true) && result.returnsVoid === (result.methodInfo.returnsVoid === true) && result.returnsObject === (result.methodInfo.returnsObject === true) && result.returnsBlock === (result.methodInfo.returnsBlock === true) && result.text === result.methodInfo.text)); })()"
                    )
                    .expect("agent objc methodInfo result"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() {
                            const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'objc.protocol_protocols', protocolName: 'NSObject', filter: 'NS' });
                            if (result.kind !== 'objc.protocol_protocols' || result.protocolName !== 'NSObject' || result.filter !== 'NS' || result.hasFilter !== true) {
                                return false;
                            }
                            if (result.count !== result.protocols.length || typeof result.hasProtocols !== 'boolean') {
                                return false;
                            }
                            return typeof result.uniqueImagePathCount === 'number' &&
                                typeof result.protocolsWithImagePathCount === 'number' &&
                                typeof result.protocolsWithAdoptedProtocolsCount === 'number' &&
                                typeof result.protocolsWithRequiredMethodsCount === 'number' &&
                                typeof result.protocolsWithOptionalMethodsCount === 'number' &&
                                typeof result.protocolsWithInstanceMethodsCount === 'number' &&
                                typeof result.protocolsWithClassMethodsCount === 'number' &&
                                typeof result.protocolsWithPropertiesCount === 'number' &&
                                typeof result.totalAdoptedProtocolCount === 'number' &&
                                typeof result.totalRequiredMethodCount === 'number' &&
                                typeof result.totalOptionalMethodCount === 'number' &&
                                typeof result.totalPropertyCount === 'number' &&
                                Array.isArray(result.imagePaths) &&
                                result.text === result.protocols.join('\\n') &&
                                (result.firstProtocol === null || typeof result.firstProtocol === 'string') &&
                                (result.lastProtocol === null || typeof result.lastProtocol === 'string') &&
                                (result.firstImagePath === null || typeof result.firstImagePath === 'string') &&
                                (result.lastImagePath === null || typeof result.lastImagePath === 'string');
                        })()"
                    )
                    .expect("agent objc protocolProtocols result"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() {
                            const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'objc.protocol_methods', protocolName: 'NSObject', isRequired: false, isInstanceMethod: false, filter: 'description' });
                            if (result.kind !== 'objc.protocol_methods' || result.protocolName !== 'NSObject' || result.isRequired !== false || result.isInstanceMethod !== false || result.filter !== 'description' || result.hasFilter !== true) {
                                return false;
                            }
                            if (result.count !== result.methods.length || typeof result.hasMethods !== 'boolean') {
                                return false;
                            }
                            if (typeof result.uniqueSelectorCount !== 'number' ||
                                    typeof result.uniqueReturnTypeCount !== 'number' ||
                                    typeof result.keywordSelectorCount !== 'number' ||
                                    typeof result.unarySelectorCount !== 'number' ||
                                    typeof result.explicitArgumentMethodCount !== 'number' ||
                                    typeof result.hiddenArgumentMethodCount !== 'number' ||
                                    typeof result.returnsVoidCount !== 'number' ||
                                    typeof result.returnsObjectCount !== 'number' ||
                                    typeof result.returnsBlockCount !== 'number' ||
                                    typeof result.totalExplicitArgumentCount !== 'number' ||
                                    typeof result.totalHiddenArgumentCount !== 'number' ||
                                    typeof result.maxSelectorPartCount !== 'number' ||
                                    typeof result.maxExplicitArgumentCount !== 'number' ||
                                    !Array.isArray(result.selectors) ||
                                    !Array.isArray(result.returnTypes)) {
                                return false;
                            }
                            if (result.methods.length === 0) {
                                return result.hasMethods === false &&
                                    result.firstSelector === null &&
                                    result.lastSelector === null;
                            }
                            const method = result.methods[0];
                            const selectorSummary = result.selectors.length === 0 ? null : result.selectors[0];
                            const returnTypeSummary = result.returnTypes.length === 0 ? null : result.returnTypes[0];
                            return result.hasMethods === true &&
                                typeof result.firstSelector === 'string' &&
                                typeof result.lastSelector === 'string' &&
                                typeof method.typeEncoding === 'string' &&
                                typeof method.returnTypeName === 'string' &&
                                Array.isArray(method.argumentTypeNames) &&
                                typeof method.methodTypeInfo === 'object' &&
                                Array.isArray(method.selectorParts) &&
                                typeof method.selectorPartCount === 'number' &&
                                typeof method.hasSelectorArguments === 'boolean' &&
                                typeof method.isUnarySelector === 'boolean' &&
                                typeof method.isKeywordSelector === 'boolean' &&
                                typeof method.hasExplicitArguments === 'boolean' &&
                                typeof method.hiddenArgumentCount === 'number' &&
                                typeof method.returnsVoid === 'boolean' &&
                                typeof method.returnsObject === 'boolean' &&
                                typeof method.returnsBlock === 'boolean' &&
                                (selectorSummary === null || (
                                    typeof selectorSummary.selector === 'string' &&
                                    typeof selectorSummary.count === 'number' &&
                                    typeof selectorSummary.returnTypeName === 'string' &&
                                    typeof selectorSummary.keywordSelector === 'boolean' &&
                                    typeof selectorSummary.isRequired === 'boolean' &&
                                    typeof selectorSummary.isInstanceMethod === 'boolean'
                                )) &&
                                (returnTypeSummary === null || (
                                    typeof returnTypeSummary.returnTypeName === 'string' &&
                                    typeof returnTypeSummary.count === 'number' &&
                                    typeof returnTypeSummary.firstSelector === 'string' &&
                                    typeof returnTypeSummary.lastSelector === 'string' &&
                                    typeof returnTypeSummary.returnsObject === 'boolean' &&
                                    typeof returnTypeSummary.returnsBlock === 'boolean'
                                )) &&
                                result.text === result.methods.map((method) => method.text).join('\\n');
                        })()"
                    )
                    .expect("agent objc protocolMethods result"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() { const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'objc.protocol_method_info', protocolName: 'NSObject', selectorName: 'description', isRequired: false, isInstanceMethod: false }); return result.kind === 'objc.protocol_method_info' && result.protocolName === 'NSObject' && result.selectorName === 'description' && result.isRequired === false && result.isInstanceMethod === false && typeof result.hasMethodInfo === 'boolean' && typeof result.resolved === 'boolean' && ((result.methodInfo === null && result.hasMethodInfo === false && result.resolved === false && result.resolvedSelector === null && result.imagePath === null && result.hasSelectorArguments === false && result.isUnarySelector === false && result.isKeywordSelector === false && result.hasExplicitArguments === false && result.returnsVoid === false && result.returnsObject === false && result.returnsBlock === false && result.text === '<null>') || (typeof result.methodInfo.typeEncoding === 'string' && typeof result.methodInfo.returnTypeName === 'string' && Array.isArray(result.methodInfo.argumentTypeNames) && typeof result.methodInfo.methodTypeInfo === 'object' && Array.isArray(result.methodInfo.selectorParts) && typeof result.methodInfo.selectorPartCount === 'number' && typeof result.methodInfo.hasSelectorArguments === 'boolean' && typeof result.methodInfo.isUnarySelector === 'boolean' && typeof result.methodInfo.isKeywordSelector === 'boolean' && typeof result.methodInfo.hasExplicitArguments === 'boolean' && typeof result.methodInfo.hiddenArgumentCount === 'number' && typeof result.methodInfo.returnsVoid === 'boolean' && typeof result.methodInfo.returnsObject === 'boolean' && typeof result.methodInfo.returnsBlock === 'boolean' && result.hasMethodInfo === true && result.resolved === true && result.resolvedSelector === result.methodInfo.selector && result.imagePath === result.methodInfo.imagePath && result.hasSelectorArguments === (result.methodInfo.hasSelectorArguments === true) && result.isUnarySelector === (result.methodInfo.isUnarySelector === true) && result.isKeywordSelector === (result.methodInfo.isKeywordSelector === true) && result.hasExplicitArguments === (result.methodInfo.hasExplicitArguments === true) && result.returnsVoid === (result.methodInfo.returnsVoid === true) && result.returnsObject === (result.methodInfo.returnsObject === true) && result.returnsBlock === (result.methodInfo.returnsBlock === true) && result.text === result.methodInfo.text)); })()"
                    )
                    .expect("agent objc protocolMethodInfo result"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() {
                            const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'objc.protocol_properties', protocolName: 'NSObject', filter: 'description' });
                            if (result.kind !== 'objc.protocol_properties' || result.protocolName !== 'NSObject' || result.filter !== 'description' || result.hasFilter !== true) {
                                return false;
                            }
                            if (result.count !== result.properties.length || typeof result.hasProperties !== 'boolean') {
                                return false;
                            }
                            if (typeof result.uniqueOwnershipCount !== 'number' ||
                                    typeof result.uniqueObjectClassCount !== 'number' ||
                                    typeof result.readonlyPropertyCount !== 'number' ||
                                    typeof result.readwritePropertyCount !== 'number' ||
                                    typeof result.atomicPropertyCount !== 'number' ||
                                    typeof result.nonatomicPropertyCount !== 'number' ||
                                    typeof result.dynamicPropertyCount !== 'number' ||
                                    typeof result.strongPropertyCount !== 'number' ||
                                    typeof result.copyPropertyCount !== 'number' ||
                                    typeof result.weakPropertyCount !== 'number' ||
                                    typeof result.assignPropertyCount !== 'number' ||
                                    typeof result.objectPropertyCount !== 'number' ||
                                    typeof result.blockPropertyCount !== 'number' ||
                                    typeof result.propertiesWithAccessorCustomizationCount !== 'number' ||
                                    typeof result.propertiesWithBackingIvarCount !== 'number' ||
                                    typeof result.propertiesWithObjectProtocolsCount !== 'number' ||
                                    typeof result.propertiesWithTypeInfoCount !== 'number' ||
                                    typeof result.propertiesWithParsedTokensCount !== 'number' ||
                                    typeof result.totalObjectProtocolCount !== 'number' ||
                                    !Array.isArray(result.ownerships) ||
                                    !Array.isArray(result.objectClasses)) {
                                return false;
                            }
                            if (result.properties.length === 0) {
                                return result.hasProperties === false &&
                                    result.firstProperty === null &&
                                    result.lastProperty === null;
                            }
                            const ownershipSummary = result.ownerships.length === 0 ? null : result.ownerships[0];
                            const objectClassSummary = result.objectClasses.length === 0 ? null : result.objectClasses[0];
                            return result.hasProperties === true &&
                                typeof result.firstProperty === 'string' &&
                                typeof result.lastProperty === 'string' &&
                                result.text === result.properties.map((property) => property.text).join('\\n') &&
                                (result.firstObjectClassName === null || typeof result.firstObjectClassName === 'string') &&
                                (result.lastObjectClassName === null || typeof result.lastObjectClassName === 'string') &&
                                (ownershipSummary === null || (
                                    typeof ownershipSummary.ownership === 'string' &&
                                    typeof ownershipSummary.count === 'number' &&
                                    typeof ownershipSummary.firstProperty === 'string' &&
                                    typeof ownershipSummary.lastProperty === 'string'
                                )) &&
                                (objectClassSummary === null || (
                                    typeof objectClassSummary.objectClassName === 'string' &&
                                    typeof objectClassSummary.count === 'number' &&
                                    typeof objectClassSummary.firstProperty === 'string' &&
                                    typeof objectClassSummary.lastProperty === 'string'
                                )) &&
                                typeof result.properties[0].typeEncoding === 'string' &&
                                typeof result.properties[0].typeName === 'string' &&
                                Array.isArray(result.properties[0].objectProtocols) &&
                                typeof result.properties[0].typeInfo === 'object' &&
                                typeof result.properties[0].attributeInfo === 'object' &&
                                typeof result.properties[0].isReadwrite === 'boolean' &&
                                typeof result.properties[0].isAtomic === 'boolean' &&
                                typeof result.properties[0].isStrong === 'boolean' &&
                                typeof result.properties[0].isCopy === 'boolean' &&
                                typeof result.properties[0].isWeak === 'boolean' &&
                                typeof result.properties[0].isAssign === 'boolean' &&
                                typeof result.properties[0].hasAccessorNames === 'boolean' &&
                                typeof result.properties[0].hasOwnershipModifier === 'boolean' &&
                                typeof result.properties[0].hasTypeInfo === 'boolean' &&
                                typeof result.properties[0].hasObjectClassName === 'boolean' &&
                                typeof result.properties[0].hasObjectProtocols === 'boolean' &&
                                typeof result.properties[0].hasParsedTokens === 'boolean';
                        })()"
                    )
                    .expect("agent objc protocolProperties result"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() { const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'objc.protocol_property_info', protocolName: 'NSObject', propertyName: 'description' }); return result.kind === 'objc.protocol_property_info' && result.protocolName === 'NSObject' && result.propertyName === 'description' && typeof result.hasPropertyInfo === 'boolean' && typeof result.resolved === 'boolean' && ((result.propertyInfo === null && result.hasPropertyInfo === false && result.resolved === false && result.resolvedName === null && result.typeName === null && result.ownership === null && result.objectClassName === null && result.hasAccessorCustomization === false && result.hasObjectProtocols === false && result.hasTypeInfo === false && result.isObject === false && result.isBlock === false && result.imagePath === null && result.text === '<null>') || (typeof result.propertyInfo.propertyPointer === 'string' && typeof result.propertyInfo.typeEncoding === 'string' && typeof result.propertyInfo.typeName === 'string' && Array.isArray(result.propertyInfo.objectProtocols) && typeof result.propertyInfo.attributeInfo === 'object' && typeof result.propertyInfo.isReadwrite === 'boolean' && typeof result.propertyInfo.isAtomic === 'boolean' && typeof result.propertyInfo.isStrong === 'boolean' && typeof result.propertyInfo.isCopy === 'boolean' && typeof result.propertyInfo.isWeak === 'boolean' && typeof result.propertyInfo.isAssign === 'boolean' && typeof result.propertyInfo.hasAccessorCustomization === 'boolean' && typeof result.propertyInfo.hasAccessorNames === 'boolean' && typeof result.propertyInfo.hasGetterName === 'boolean' && typeof result.propertyInfo.hasSetterName === 'boolean' && typeof result.propertyInfo.hasBackingIvar === 'boolean' && typeof result.propertyInfo.hasOldStyleTypeEncoding === 'boolean' && typeof result.propertyInfo.hasOwnershipModifier === 'boolean' && typeof result.propertyInfo.hasTypeEncoding === 'boolean' && typeof result.propertyInfo.hasTypeName === 'boolean' && typeof result.propertyInfo.hasTypeInfo === 'boolean' && typeof result.propertyInfo.hasObjectClassName === 'boolean' && typeof result.propertyInfo.hasObjectProtocols === 'boolean' && typeof result.propertyInfo.hasParsedTokens === 'boolean' && typeof result.propertyInfo.objectProtocolCount === 'number' && typeof result.propertyInfo.parsedTokenCount === 'number' && result.hasPropertyInfo === true && result.resolved === true && result.resolvedName === result.propertyInfo.name && result.typeName === result.propertyInfo.typeName && result.ownership === result.propertyInfo.ownership && result.objectClassName === result.propertyInfo.objectClassName && result.hasAccessorCustomization === (result.propertyInfo.hasAccessorCustomization === true) && result.hasObjectProtocols === (result.propertyInfo.hasObjectProtocols === true) && result.hasTypeInfo === (result.propertyInfo.hasTypeInfo === true) && result.isObject === (result.propertyInfo.isObject === true) && result.isBlock === (result.propertyInfo.isBlock === true) && result.imagePath === result.propertyInfo.imagePath && result.text === result.propertyInfo.text)); })()"
                    )
                    .expect("agent objc protocolPropertyInfo result"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() { const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'objc.superclass', className: 'NSObject' }); return result.kind === 'objc.superclass' && result.className === 'NSObject' && typeof result.classExists === 'boolean' && typeof result.resolved === 'boolean' && typeof result.hasSuperclass === 'boolean' && typeof result.isRootClass === 'boolean' && ((result.superclass === null && result.classExists === false && result.resolved === false && result.resolvedSuperclassName === null && result.hasSuperclass === false && result.isRootClass === false && result.text === '<null>') || (result.superclass === null && result.classExists === true && result.resolved === true && result.resolvedSuperclassName === null && result.hasSuperclass === false && result.isRootClass === true && result.text === '<null>') || (typeof result.superclass === 'string' && result.classExists === true && result.resolved === true && result.resolvedSuperclassName === result.superclass && result.hasSuperclass === true && result.isRootClass === false && result.text === result.superclass)); })()"
                    )
                    .expect("agent objc superclass result"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() { const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'objc.class_image', className: 'NSObject' }); return result.kind === 'objc.class_image' && result.className === 'NSObject' && typeof result.hasImagePath === 'boolean' && typeof result.resolved === 'boolean' && ((result.imagePath === null && result.hasImagePath === false && result.resolved === false && result.resolvedImagePath === null && result.text === '<null>') || (typeof result.imagePath === 'string' && result.hasImagePath === true && result.resolved === true && result.resolvedImagePath === result.imagePath && result.text === result.imagePath)); })()"
                    )
                    .expect("agent objc classImage result"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() { const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'objc.method_image', className: 'NSObject', selectorName: 'init', isClassMethod: false }); return result.kind === 'objc.method_image' && result.className === 'NSObject' && result.selectorName === 'init' && result.isClassMethod === false && typeof result.hasImagePath === 'boolean' && typeof result.resolved === 'boolean' && ((result.imagePath === null && result.hasImagePath === false && result.resolved === false && result.resolvedImagePath === null && result.text === '<null>') || (typeof result.imagePath === 'string' && result.hasImagePath === true && result.resolved === true && result.resolvedImagePath === result.imagePath && result.text === result.imagePath)); })()"
                    )
                    .expect("agent objc methodImage result"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() { const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'objc.method_imp', className: 'NSObject', selectorName: 'init', isClassMethod: false }); return result.kind === 'objc.method_imp' && result.className === 'NSObject' && result.selectorName === 'init' && result.isClassMethod === false && typeof result.hasImp === 'boolean' && typeof result.resolved === 'boolean' && ((result.imp === null && result.hasImp === false && result.resolved === false && result.resolvedImp === null && result.text === '<null>') || (typeof result.imp === 'string' && result.hasImp === true && result.resolved === true && result.resolvedImp === result.imp && result.text === result.imp)); })()"
                    )
                    .expect("agent objc methodImp result"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() { const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'objc.selector_name', selector: '0x0' }); return result.kind === 'objc.selector_name' && result.selector === '0x0' && result.name === null && result.hasName === false && result.resolved === false && result.resolvedName === null && result.text === '<null>'; })()"
                    )
                    .expect("agent objc selectorName result"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() { const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'objc.object_class_name', object: '0x0' }); return result.kind === 'objc.object_class_name' && result.object === '0x0' && result.className === null && result.hasClassName === false && result.resolved === false && result.resolvedClassName === null && result.text === '<null>'; })()"
                    )
                    .expect("agent objc objectClassName result"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() {
                            const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'objc.class_chain', className: 'NSObject' });
                            if (result.kind !== 'objc.class_chain' || result.className !== 'NSObject') {
                                return false;
                            }
                            if (result.count !== result.chain.length || result.depth !== result.chain.length) {
                                return false;
                            }
                            if (typeof result.hasChain !== 'boolean' ||
                                    typeof result.includesSelf !== 'boolean' ||
                                    typeof result.uniqueImagePathCount !== 'number' ||
                                    typeof result.classesWithImagePathCount !== 'number' ||
                                    typeof result.rootClassCount !== 'number' ||
                                    typeof result.classesWithProtocolsCount !== 'number' ||
                                    typeof result.classesWithPropertiesCount !== 'number' ||
                                    typeof result.classesWithIvarsCount !== 'number' ||
                                    typeof result.classesWithMethodsCount !== 'number' ||
                                    typeof result.totalProtocolCount !== 'number' ||
                                    typeof result.totalPropertyCount !== 'number' ||
                                    typeof result.totalIvarCount !== 'number' ||
                                    typeof result.totalMethodCount !== 'number' ||
                                    typeof result.totalInstanceSize !== 'number' ||
                                    !Array.isArray(result.imagePaths)) {
                                return false;
                            }
                            if (result.chain.length === 0) {
                                return result.hasChain === false && result.rootClass === null;
                            }
                            const imageSummary = result.imagePaths.length === 0 ? null : result.imagePaths[0];
                            return result.hasChain === true &&
                                typeof result.rootClass === 'string' &&
                                result.text === result.chain.join('\\n') &&
                                (result.firstImagePath === null || typeof result.firstImagePath === 'string') &&
                                (result.lastImagePath === null || typeof result.lastImagePath === 'string') &&
                                (imageSummary === null || (
                                    typeof imageSummary.imagePath === 'string' &&
                                    typeof imageSummary.count === 'number' &&
                                    typeof imageSummary.firstClass === 'string' &&
                                    typeof imageSummary.lastClass === 'string'
                                ));
                        })()"
                    )
                    .expect("agent objc classChain result"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() {
                            const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'objc.properties', className: 'NSObject', isClassProperty: true, filter: 'delegate' });
                            if (result.kind !== 'objc.properties' || result.className !== 'NSObject' || result.isClassProperty !== true || result.filter !== 'delegate' || result.hasFilter !== true) {
                                return false;
                            }
                            if (result.count !== result.properties.length || typeof result.hasProperties !== 'boolean') {
                                return false;
                            }
                            if (typeof result.uniqueOwnershipCount !== 'number' ||
                                    typeof result.uniqueObjectClassCount !== 'number' ||
                                    typeof result.readonlyPropertyCount !== 'number' ||
                                    typeof result.readwritePropertyCount !== 'number' ||
                                    typeof result.atomicPropertyCount !== 'number' ||
                                    typeof result.nonatomicPropertyCount !== 'number' ||
                                    typeof result.dynamicPropertyCount !== 'number' ||
                                    typeof result.strongPropertyCount !== 'number' ||
                                    typeof result.copyPropertyCount !== 'number' ||
                                    typeof result.weakPropertyCount !== 'number' ||
                                    typeof result.assignPropertyCount !== 'number' ||
                                    typeof result.objectPropertyCount !== 'number' ||
                                    typeof result.blockPropertyCount !== 'number' ||
                                    typeof result.propertiesWithAccessorCustomizationCount !== 'number' ||
                                    typeof result.propertiesWithBackingIvarCount !== 'number' ||
                                    typeof result.propertiesWithObjectProtocolsCount !== 'number' ||
                                    typeof result.propertiesWithTypeInfoCount !== 'number' ||
                                    typeof result.propertiesWithParsedTokensCount !== 'number' ||
                                    typeof result.totalObjectProtocolCount !== 'number' ||
                                    !Array.isArray(result.ownerships) ||
                                    !Array.isArray(result.objectClasses)) {
                                return false;
                            }
                            if (result.properties.length === 0) {
                                return result.hasProperties === false &&
                                    result.firstProperty === null &&
                                    result.lastProperty === null;
                            }
                            const ownershipSummary = result.ownerships.length === 0 ? null : result.ownerships[0];
                            const objectClassSummary = result.objectClasses.length === 0 ? null : result.objectClasses[0];
                            return result.hasProperties === true &&
                                typeof result.firstProperty === 'string' &&
                                typeof result.lastProperty === 'string' &&
                                result.text === result.properties.map((property) => property.text).join('\\n') &&
                                (result.firstObjectClassName === null || typeof result.firstObjectClassName === 'string') &&
                                (result.lastObjectClassName === null || typeof result.lastObjectClassName === 'string') &&
                                (ownershipSummary === null || (
                                    typeof ownershipSummary.ownership === 'string' &&
                                    typeof ownershipSummary.count === 'number' &&
                                    typeof ownershipSummary.firstProperty === 'string' &&
                                    typeof ownershipSummary.lastProperty === 'string'
                                )) &&
                                (objectClassSummary === null || (
                                    typeof objectClassSummary.objectClassName === 'string' &&
                                    typeof objectClassSummary.count === 'number' &&
                                    typeof objectClassSummary.firstProperty === 'string' &&
                                    typeof objectClassSummary.lastProperty === 'string'
                                )) &&
                                typeof result.properties[0].typeEncoding === 'string' &&
                                typeof result.properties[0].typeName === 'string' &&
                                Array.isArray(result.properties[0].objectProtocols) &&
                                typeof result.properties[0].typeInfo === 'object' &&
                                typeof result.properties[0].attributeInfo === 'object' &&
                                typeof result.properties[0].isReadwrite === 'boolean' &&
                                typeof result.properties[0].isAtomic === 'boolean' &&
                                typeof result.properties[0].isStrong === 'boolean' &&
                                typeof result.properties[0].isCopy === 'boolean' &&
                                typeof result.properties[0].isWeak === 'boolean' &&
                                typeof result.properties[0].isAssign === 'boolean' &&
                                typeof result.properties[0].hasAccessorNames === 'boolean' &&
                                typeof result.properties[0].hasOwnershipModifier === 'boolean' &&
                                typeof result.properties[0].hasTypeInfo === 'boolean' &&
                                typeof result.properties[0].hasObjectClassName === 'boolean' &&
                                typeof result.properties[0].hasObjectProtocols === 'boolean' &&
                                typeof result.properties[0].hasParsedTokens === 'boolean';
                        })()"
                    )
                    .expect("agent objc properties result"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() { const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'objc.property_info', className: 'NSObject', propertyName: 'description', isClassProperty: false }); return result.kind === 'objc.property_info' && result.className === 'NSObject' && result.propertyName === 'description' && result.isClassProperty === false && typeof result.hasPropertyInfo === 'boolean' && typeof result.resolved === 'boolean' && ((result.propertyInfo === null && result.hasPropertyInfo === false && result.resolved === false && result.resolvedName === null && result.typeName === null && result.ownership === null && result.objectClassName === null && result.hasAccessorCustomization === false && result.hasObjectProtocols === false && result.hasTypeInfo === false && result.isObject === false && result.isBlock === false && result.imagePath === null && result.text === '<null>') || (typeof result.propertyInfo.propertyPointer === 'string' && typeof result.propertyInfo.typeEncoding === 'string' && typeof result.propertyInfo.typeName === 'string' && Array.isArray(result.propertyInfo.objectProtocols) && typeof result.propertyInfo.attributeInfo === 'object' && typeof result.propertyInfo.isReadwrite === 'boolean' && typeof result.propertyInfo.isAtomic === 'boolean' && typeof result.propertyInfo.isStrong === 'boolean' && typeof result.propertyInfo.isCopy === 'boolean' && typeof result.propertyInfo.isWeak === 'boolean' && typeof result.propertyInfo.isAssign === 'boolean' && typeof result.propertyInfo.hasAccessorCustomization === 'boolean' && typeof result.propertyInfo.hasAccessorNames === 'boolean' && typeof result.propertyInfo.hasGetterName === 'boolean' && typeof result.propertyInfo.hasSetterName === 'boolean' && typeof result.propertyInfo.hasBackingIvar === 'boolean' && typeof result.propertyInfo.hasOldStyleTypeEncoding === 'boolean' && typeof result.propertyInfo.hasOwnershipModifier === 'boolean' && typeof result.propertyInfo.hasTypeEncoding === 'boolean' && typeof result.propertyInfo.hasTypeName === 'boolean' && typeof result.propertyInfo.hasTypeInfo === 'boolean' && typeof result.propertyInfo.hasObjectClassName === 'boolean' && typeof result.propertyInfo.hasObjectProtocols === 'boolean' && typeof result.propertyInfo.hasParsedTokens === 'boolean' && typeof result.propertyInfo.objectProtocolCount === 'number' && typeof result.propertyInfo.parsedTokenCount === 'number' && result.hasPropertyInfo === true && result.resolved === true && result.resolvedName === result.propertyInfo.name && result.typeName === result.propertyInfo.typeName && result.ownership === result.propertyInfo.ownership && result.objectClassName === result.propertyInfo.objectClassName && result.hasAccessorCustomization === (result.propertyInfo.hasAccessorCustomization === true) && result.hasObjectProtocols === (result.propertyInfo.hasObjectProtocols === true) && result.hasTypeInfo === (result.propertyInfo.hasTypeInfo === true) && result.isObject === (result.propertyInfo.isObject === true) && result.isBlock === (result.propertyInfo.isBlock === true) && result.imagePath === result.propertyInfo.imagePath && result.text === result.propertyInfo.text)); })()"
                    )
                    .expect("agent objc propertyInfo result"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() { const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'objc.ivar_info', className: 'NSObject', ivarName: '_isa' }); return result.kind === 'objc.ivar_info' && result.className === 'NSObject' && result.ivarName === '_isa' && typeof result.hasIvarInfo === 'boolean' && typeof result.resolved === 'boolean' && ((result.ivarInfo === null && result.hasIvarInfo === false && result.resolved === false && result.resolvedName === null && result.typeName === null && result.kindName === null && result.objectClassName === null && result.hasQualifiers === false && result.hasPointeeType === false && result.isPointer === false && result.isArray === false && result.memberName === null && result.imagePath === null && result.text === '<null>') || (typeof result.ivarInfo.ivarPointer === 'string' && typeof result.ivarInfo.offsetHex === 'string' && typeof result.ivarInfo.typeName === 'string' && typeof result.ivarInfo.typeInfo === 'object' && typeof result.ivarInfo.kind === 'string' && Array.isArray(result.ivarInfo.qualifiers) && Array.isArray(result.ivarInfo.qualifierNames) && typeof result.ivarInfo.qualifierCount === 'number' && typeof result.ivarInfo.hasQualifiers === 'boolean' && typeof result.ivarInfo.objectProtocolCount === 'number' && typeof result.ivarInfo.hasObjectClassName === 'boolean' && (result.ivarInfo.pointeeTypeName === null || typeof result.ivarInfo.pointeeTypeName === 'string') && typeof result.ivarInfo.hasPointeeType === 'boolean' && typeof result.ivarInfo.isPointer === 'boolean' && typeof result.ivarInfo.isArray === 'boolean' && (result.ivarInfo.arrayCount === null || typeof result.ivarInfo.arrayCount === 'number') && (result.ivarInfo.memberName === null || typeof result.ivarInfo.memberName === 'string') && typeof result.ivarInfo.hasMemberName === 'boolean' && result.hasIvarInfo === true && result.resolved === true && result.resolvedName === result.ivarInfo.name && result.typeName === result.ivarInfo.typeName && result.kindName === result.ivarInfo.kind && result.objectClassName === result.ivarInfo.objectClassName && result.hasQualifiers === (result.ivarInfo.hasQualifiers === true) && result.hasPointeeType === (result.ivarInfo.hasPointeeType === true) && result.isPointer === (result.ivarInfo.isPointer === true) && result.isArray === (result.ivarInfo.isArray === true) && result.memberName === result.ivarInfo.memberName && result.imagePath === result.ivarInfo.imagePath && result.text === result.ivarInfo.text)); })()"
                    )
                    .expect("agent objc ivarInfo result"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() {
                            const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'objc.ivars', className: 'NSObject', filter: 'delegate' });
                            if (result.kind !== 'objc.ivars' || result.className !== 'NSObject' || result.filter !== 'delegate' || result.hasFilter !== true) {
                                return false;
                            }
                            if (result.count !== result.ivars.length || typeof result.hasIvars !== 'boolean') {
                                return false;
                            }
                            if (typeof result.uniqueKindCount !== 'number' ||
                                    typeof result.uniqueObjectClassCount !== 'number' ||
                                    typeof result.totalQualifierCount !== 'number' ||
                                    typeof result.totalObjectProtocolCount !== 'number' ||
                                    typeof result.pointerIvarCount !== 'number' ||
                                    typeof result.arrayIvarCount !== 'number' ||
                                    typeof result.objectIvarCount !== 'number' ||
                                    typeof result.blockIvarCount !== 'number' ||
                                    typeof result.ivarsWithQualifiersCount !== 'number' ||
                                    typeof result.ivarsWithObjectProtocolsCount !== 'number' ||
                                    typeof result.ivarsWithObjectClassCount !== 'number' ||
                                    typeof result.ivarsWithPointeeTypeCount !== 'number' ||
                                    typeof result.ivarsWithMemberNameCount !== 'number' ||
                                    !Array.isArray(result.kinds) ||
                                    !Array.isArray(result.objectClasses)) {
                                return false;
                            }
                            if (result.ivars.length === 0) {
                                return result.hasIvars === false &&
                                    result.firstIvar === null &&
                                    result.lastIvar === null &&
                                    result.minOffsetHex === null &&
                                    result.maxOffsetHex === null;
                            }
                            const kindSummary = result.kinds.length === 0 ? null : result.kinds[0];
                            const objectClassSummary = result.objectClasses.length === 0 ? null : result.objectClasses[0];
                            return result.hasIvars === true &&
                                typeof result.firstIvar === 'string' &&
                                typeof result.lastIvar === 'string' &&
                                typeof result.minOffsetHex === 'string' &&
                                typeof result.maxOffsetHex === 'string' &&
                                result.text === result.ivars.map((ivar) => ivar.text).join('\\n') &&
                                (result.firstObjectClassName === null || typeof result.firstObjectClassName === 'string') &&
                                (result.lastObjectClassName === null || typeof result.lastObjectClassName === 'string') &&
                                (kindSummary === null || (
                                    typeof kindSummary.kind === 'string' &&
                                    typeof kindSummary.count === 'number' &&
                                    typeof kindSummary.firstIvar === 'string' &&
                                    typeof kindSummary.lastIvar === 'string'
                                )) &&
                                (objectClassSummary === null || (
                                    typeof objectClassSummary.objectClassName === 'string' &&
                                    typeof objectClassSummary.count === 'number' &&
                                    typeof objectClassSummary.firstIvar === 'string' &&
                                    typeof objectClassSummary.lastIvar === 'string'
                                )) &&
                                typeof result.ivars[0].offsetHex === 'string' &&
                                typeof result.ivars[0].typeName === 'string' &&
                                typeof result.ivars[0].typeInfo === 'object' &&
                                typeof result.ivars[0].kind === 'string' &&
                                Array.isArray(result.ivars[0].qualifiers) &&
                                Array.isArray(result.ivars[0].qualifierNames) &&
                                typeof result.ivars[0].qualifierCount === 'number' &&
                                typeof result.ivars[0].hasQualifiers === 'boolean' &&
                                typeof result.ivars[0].objectProtocolCount === 'number' &&
                                typeof result.ivars[0].hasObjectClassName === 'boolean' &&
                                (result.ivars[0].pointeeTypeName === null || typeof result.ivars[0].pointeeTypeName === 'string') &&
                                typeof result.ivars[0].hasPointeeType === 'boolean' &&
                                typeof result.ivars[0].isPointer === 'boolean' &&
                                typeof result.ivars[0].isArray === 'boolean' &&
                                (result.ivars[0].arrayCount === null || typeof result.ivars[0].arrayCount === 'number') &&
                                (result.ivars[0].memberName === null || typeof result.ivars[0].memberName === 'string') &&
                                typeof result.ivars[0].hasMemberName === 'boolean';
                        })()"
                    )
                    .expect("agent objc ivars result"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() {
                            const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'objc.methods', className: 'NSObject', isClassMethod: false, filter: 'init' });
                            if (result.kind !== 'objc.methods' || result.className !== 'NSObject' || result.isClassMethod !== false || result.filter !== 'init' || result.hasFilter !== true) {
                                return false;
                            }
                            if (result.count !== result.methods.length || typeof result.hasMethods !== 'boolean') {
                                return false;
                            }
                            if (typeof result.uniqueSelectorCount !== 'number' ||
                                    typeof result.uniqueReturnTypeCount !== 'number' ||
                                    typeof result.keywordSelectorCount !== 'number' ||
                                    typeof result.unarySelectorCount !== 'number' ||
                                    typeof result.explicitArgumentMethodCount !== 'number' ||
                                    typeof result.hiddenArgumentMethodCount !== 'number' ||
                                    typeof result.returnsVoidCount !== 'number' ||
                                    typeof result.returnsObjectCount !== 'number' ||
                                    typeof result.returnsBlockCount !== 'number' ||
                                    typeof result.totalExplicitArgumentCount !== 'number' ||
                                    typeof result.totalHiddenArgumentCount !== 'number' ||
                                    typeof result.maxSelectorPartCount !== 'number' ||
                                    typeof result.maxExplicitArgumentCount !== 'number' ||
                                    !Array.isArray(result.selectors) ||
                                    !Array.isArray(result.returnTypes)) {
                                return false;
                            }
                            if (result.methods.length === 0) {
                                return result.hasMethods === false &&
                                    result.firstSelector === null &&
                                    result.lastSelector === null;
                            }
                            const method = result.methods[0];
                            const selectorSummary = result.selectors.length === 0 ? null : result.selectors[0];
                            const returnTypeSummary = result.returnTypes.length === 0 ? null : result.returnTypes[0];
                            return result.hasMethods === true &&
                                typeof result.firstSelector === 'string' &&
                                typeof result.lastSelector === 'string' &&
                                typeof method.typeEncoding === 'string' &&
                                typeof method.returnTypeName === 'string' &&
                                Array.isArray(method.argumentTypeNames) &&
                                typeof method.methodTypeInfo === 'object' &&
                                Array.isArray(method.selectorParts) &&
                                typeof method.selectorPartCount === 'number' &&
                                typeof method.hasSelectorArguments === 'boolean' &&
                                typeof method.hasExplicitArguments === 'boolean' &&
                                typeof method.hasHiddenArguments === 'boolean' &&
                                typeof method.returnsVoid === 'boolean' &&
                                typeof method.returnsObject === 'boolean' &&
                                typeof method.returnsBlock === 'boolean' &&
                                (selectorSummary === null || (
                                    typeof selectorSummary.selector === 'string' &&
                                    typeof selectorSummary.count === 'number' &&
                                    typeof selectorSummary.firstImp === 'string' &&
                                    typeof selectorSummary.lastImp === 'string' &&
                                    typeof selectorSummary.returnTypeName === 'string' &&
                                    typeof selectorSummary.keywordSelector === 'boolean'
                                )) &&
                                (returnTypeSummary === null || (
                                    typeof returnTypeSummary.returnTypeName === 'string' &&
                                    typeof returnTypeSummary.count === 'number' &&
                                    typeof returnTypeSummary.firstSelector === 'string' &&
                                    typeof returnTypeSummary.lastSelector === 'string' &&
                                    typeof returnTypeSummary.returnsObject === 'boolean' &&
                                    typeof returnTypeSummary.returnsBlock === 'boolean'
                                ));
                        })()"
                    )
                    .expect("agent objc methods result"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() {
                            const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'objc.method_owners', query: 'init', isClassMethod: false });
                            if (result.kind !== 'objc.method_owners' || result.query !== 'init' || result.isClassMethod !== false || result.hasQuery !== true) {
                                return false;
                            }
                            if (result.count !== result.methods.length || typeof result.hasMethods !== 'boolean') {
                                return false;
                            }
                            if (typeof result.uniqueOwnerCount !== 'number' ||
                                    typeof result.uniqueSelectorCount !== 'number' ||
                                    typeof result.keywordSelectorCount !== 'number' ||
                                    typeof result.unarySelectorCount !== 'number' ||
                                    typeof result.explicitArgumentMethodCount !== 'number' ||
                                    typeof result.returnsVoidCount !== 'number' ||
                                    typeof result.returnsObjectCount !== 'number' ||
                                    typeof result.returnsBlockCount !== 'number' ||
                                    !Array.isArray(result.owners) ||
                                    !Array.isArray(result.selectors)) {
                                return false;
                            }
                            if (result.methods.length === 0) {
                                return result.hasMethods === false &&
                                    result.firstOwner === null &&
                                    result.lastOwner === null &&
                                    result.firstSelector === null &&
                                    result.lastSelector === null;
                            }
                            const method = result.methods[0];
                            const ownerSummary = result.owners.length === 0 ? null : result.owners[0];
                            const selectorSummary = result.selectors.length === 0 ? null : result.selectors[0];
                            return result.hasMethods === true &&
                                typeof result.firstOwner === 'string' &&
                                typeof result.lastOwner === 'string' &&
                                typeof result.firstSelector === 'string' &&
                                typeof result.lastSelector === 'string' &&
                                typeof method.className === 'string' &&
                                typeof method.selector === 'string' &&
                                typeof method.returnTypeName === 'string' &&
                                Array.isArray(method.argumentTypeNames) &&
                                typeof method.hasExplicitArguments === 'boolean' &&
                                typeof method.returnsVoid === 'boolean' &&
                                typeof method.returnsObject === 'boolean' &&
                                typeof method.returnsBlock === 'boolean' &&
                                (ownerSummary === null || (
                                    typeof ownerSummary.className === 'string' &&
                                    typeof ownerSummary.count === 'number' &&
                                    typeof ownerSummary.firstSelector === 'string' &&
                                    typeof ownerSummary.lastSelector === 'string' &&
                                    typeof ownerSummary.keywordSelectorCount === 'number'
                                )) &&
                                (selectorSummary === null || (
                                    typeof selectorSummary.selector === 'string' &&
                                    typeof selectorSummary.count === 'number' &&
                                    typeof selectorSummary.firstOwner === 'string' &&
                                    typeof selectorSummary.lastOwner === 'string' &&
                                    typeof selectorSummary.keywordSelector === 'boolean'
                                ));
                        })()"
                    )
                    .expect("agent objc method owners result"),
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
                        "(function() { const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'native.base', moduleName: 'libsystem_malloc.dylib' }); return result.kind === 'native.base' && result.moduleName === 'libsystem_malloc.dylib' && typeof result.hasBase === 'boolean' && typeof result.resolved === 'boolean' && ((result.base === null && result.hasBase === false && result.resolved === false && result.resolvedBase === null && result.text === '<null>') || (typeof result.base === 'string' && result.hasBase === true && result.resolved === true && result.resolvedBase === result.base && result.text === result.base)); })()"
                    )
                    .expect("agent native base result"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() { const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'native.main_image' }); return result.kind === 'native.main_image' && typeof result.hasImage === 'boolean' && typeof result.resolved === 'boolean' && ((result.image === null && result.hasImage === false && result.resolved === false && result.imageName === null && result.imagePath === null && result.resolvedImageName === null && result.resolvedImagePath === null && result.resolvedBase === null && result.text === '<null>') || (result.hasImage === true && result.resolved === true && typeof result.imageName === 'string' && typeof result.imagePath === 'string' && typeof result.resolvedImageName === 'string' && typeof result.resolvedImagePath === 'string' && typeof result.resolvedBase === 'string' && typeof result.image.name === 'string' && result.image.name.length !== 0 && result.resolvedImageName === result.image.name && result.resolvedImagePath === result.image.path && result.resolvedBase === result.image.base && result.text === result.image.text)); })()"
                    )
                    .expect("agent native main image result"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() { const address = Module.findExportByName(null, 'malloc'); if (address === null) { return true; } const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'native.image', address: address.toString() }); return result.kind === 'native.image' && result.address === address.toString() && typeof result.hasImage === 'boolean' && typeof result.resolved === 'boolean' && ((result.image === null && result.hasImage === false && result.resolved === false && result.imageName === null && result.imagePath === null && result.resolvedImageName === null && result.resolvedImagePath === null && result.resolvedBase === null && result.text === '<null>') || (result.hasImage === true && result.resolved === true && typeof result.imageName === 'string' && typeof result.imagePath === 'string' && typeof result.resolvedImageName === 'string' && typeof result.resolvedImagePath === 'string' && typeof result.resolvedBase === 'string' && typeof result.image.name === 'string' && typeof result.image.path === 'string' && typeof result.image.base === 'string' && typeof result.image.sizeHex === 'string' && result.resolvedImageName === result.image.name && result.resolvedImagePath === result.image.path && result.resolvedBase === result.image.base && result.text === result.image.text)); })()"
                    )
                    .expect("agent native image result"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() { const malloc = Module.findExportByName(null, 'malloc'); if (malloc === null) { return true; } const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'native.symbol', address: malloc.toString() }); return result.kind === 'native.symbol' && result.address === malloc.toString() && typeof result.resolved === 'boolean' && typeof result.hasName === 'boolean' && typeof result.hasModuleName === 'boolean' && result.resolvedAddress === result.symbol.address && result.resolvedName === result.symbol.name && result.resolvedModuleName === result.symbol.moduleName && result.resolved === (result.symbol.resolved === true) && result.hasName === (result.symbol.name !== null) && result.hasModuleName === (result.symbol.moduleName !== null) && result.text === result.symbol.text; })()"
                    )
                    .expect("agent native symbol result"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() {
                            const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'native.images', filter: 'malloc' });
                            if (result.kind !== 'native.images' || result.filter !== 'malloc' || result.hasFilter !== true) {
                                return false;
                            }
                            if (result.count !== result.images.length || typeof result.hasImages !== 'boolean') {
                                return false;
                            }
                            if (typeof result.uniqueImageCount !== 'number' ||
                                    typeof result.uniquePathKindCount !== 'number' ||
                                    typeof result.systemImageCount !== 'number' ||
                                    typeof result.appImageCount !== 'number' ||
                                    typeof result.jailbreakImageCount !== 'number' ||
                                    !Array.isArray(result.imageNames) ||
                                    !Array.isArray(result.pathKinds)) {
                                return false;
                            }
                            if (result.images.length === 0) {
                                return result.hasImages === false &&
                                    result.firstImageName === null &&
                                    result.lastImageName === null;
                            }
                            const image = result.images[0];
                            const imageNameSummary = result.imageNames.length === 0 ? null : result.imageNames[0];
                            const pathKindSummary = result.pathKinds.length === 0 ? null : result.pathKinds[0];
                            return result.hasImages === true &&
                                typeof result.firstImageName === 'string' &&
                                typeof result.lastImageName === 'string' &&
                                typeof result.firstPathKind === 'string' &&
                                typeof result.lastPathKind === 'string' &&
                                typeof image.path === 'string' &&
                                typeof image.hasPath === 'boolean' &&
                                typeof image.name === 'string' &&
                                typeof image.hasName === 'boolean' &&
                                typeof image.directoryPath === 'string' &&
                                typeof image.hasDirectoryPath === 'boolean' &&
                                typeof image.pathKind === 'string' &&
                                typeof image.isSystemPath === 'boolean' &&
                                typeof image.isAppPath === 'boolean' &&
                                typeof image.isJailbreakPath === 'boolean' &&
                                typeof image.sizeHex === 'string' &&
                                (imageNameSummary === null || (
                                    typeof imageNameSummary.name === 'string' &&
                                    typeof imageNameSummary.count === 'number' &&
                                    typeof imageNameSummary.firstPath === 'string' &&
                                    typeof imageNameSummary.lastPath === 'string'
                                )) &&
                                (pathKindSummary === null || (
                                    typeof pathKindSummary.pathKind === 'string' &&
                                    typeof pathKindSummary.count === 'number' &&
                                    typeof pathKindSummary.firstImageName === 'string' &&
                                    typeof pathKindSummary.lastImageName === 'string'
                                ));
                        })()"
                    )
                    .expect("agent native images result"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() {
                            const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'native.symbols', moduleName: null, query: 'malloc' });
                            if (result.kind !== 'native.symbols' || result.query !== 'malloc' || result.hasQuery !== true) {
                                return false;
                            }
                            if (result.count !== result.symbols.length || typeof result.hasSymbols !== 'boolean') {
                                return false;
                            }
                            if (typeof result.uniqueModuleCount !== 'number' ||
                                    typeof result.uniqueSymbolCount !== 'number' ||
                                    !Array.isArray(result.symbolNames)) {
                                return false;
                            }
                            if (result.symbols.length === 0) {
                                return result.hasSymbols === false &&
                                    result.firstSymbolName === null &&
                                    result.lastSymbolName === null;
                            }
                            const symbol = result.symbols[0];
                            const symbolSummary = result.symbolNames.length === 0 ? null : result.symbolNames[0];
                            return result.hasSymbols === true &&
                                typeof result.firstSymbolName === 'string' &&
                                typeof result.lastSymbolName === 'string' &&
                                typeof result.firstModuleName === 'string' &&
                                typeof result.lastModuleName === 'string' &&
                                typeof symbol.moduleBase === 'string' &&
                                typeof symbol.offsetHex === 'string' &&
                                typeof symbol.hasModuleName === 'boolean' &&
                                typeof symbol.hasName === 'boolean' &&
                                (symbolSummary === null || (
                                    typeof symbolSummary.symbolName === 'string' &&
                                    typeof symbolSummary.count === 'number' &&
                                    typeof symbolSummary.firstModuleName === 'string' &&
                                    typeof symbolSummary.lastModuleName === 'string'
                                ));
                        })()"
                    )
                    .expect("agent native symbols result"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() { const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'native.export', moduleName: null, symbolName: 'malloc' }); return result.kind === 'native.export' && result.symbolName === 'malloc' && typeof result.hasAddress === 'boolean' && typeof result.hasSymbol === 'boolean' && typeof result.resolved === 'boolean' && typeof result.hasName === 'boolean' && typeof result.hasModuleName === 'boolean' && ((result.address === null && result.symbol === null && result.hasAddress === false && result.hasSymbol === false && result.resolved === false && result.resolvedName === null && result.resolvedModuleName === null && result.resolvedAddress === null && result.hasName === false && result.hasModuleName === false && result.text === '<null>') || (typeof result.address === 'string' && result.hasAddress === true && result.hasSymbol === true && result.resolved === (result.symbol.resolved === true) && result.resolvedName === result.symbol.name && result.resolvedModuleName === result.symbol.moduleName && result.resolvedAddress === result.symbol.address && result.hasName === (result.symbol.name !== null) && result.hasModuleName === (result.symbol.moduleName !== null) && result.text === result.symbol.text)); })()"
                    )
                    .expect("agent native export result"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() {
                            const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'native.exports', moduleName: 'libsystem_malloc.dylib', query: 'malloc' });
                            if (result.kind !== 'native.exports' || result.moduleName !== 'libsystem_malloc.dylib' || result.query !== 'malloc' || result.hasQuery !== true) {
                                return false;
                            }
                            if (result.count !== result.symbols.length || typeof result.hasSymbols !== 'boolean') {
                                return false;
                            }
                            if (typeof result.uniqueModuleCount !== 'number' ||
                                    typeof result.uniqueSymbolCount !== 'number' ||
                                    !Array.isArray(result.symbolNames)) {
                                return false;
                            }
                            if (result.symbols.length === 0) {
                                return result.hasSymbols === false &&
                                    result.firstSymbolName === null &&
                                    result.lastSymbolName === null;
                            }
                            const symbol = result.symbols[0];
                            const symbolSummary = result.symbolNames.length === 0 ? null : result.symbolNames[0];
                            return result.hasSymbols === true &&
                                typeof result.firstSymbolName === 'string' &&
                                typeof result.lastSymbolName === 'string' &&
                                typeof result.firstModuleName === 'string' &&
                                typeof result.lastModuleName === 'string' &&
                                typeof symbol.moduleBase === 'string' &&
                                typeof symbol.offsetHex === 'string' &&
                                typeof symbol.hasModuleName === 'boolean' &&
                                typeof symbol.hasName === 'boolean' &&
                                (symbolSummary === null || (
                                    typeof symbolSummary.symbolName === 'string' &&
                                    typeof symbolSummary.count === 'number' &&
                                    typeof symbolSummary.firstModuleName === 'string' &&
                                    typeof symbolSummary.lastModuleName === 'string'
                                ));
                        })()"
                    )
                    .expect("agent native exports result"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() { const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'native.symbol_info', moduleName: null, symbolName: 'malloc' }); return result.kind === 'native.symbol_info' && result.symbolName === 'malloc' && typeof result.hasSymbolInfo === 'boolean' && typeof result.resolved === 'boolean' && typeof result.hasAddress === 'boolean' && ((result.symbolInfo === null && result.hasSymbolInfo === false && result.resolved === false && result.resolvedName === null && result.resolvedModuleName === null && result.resolvedAddress === null && result.hasAddress === false && result.text === '<null>') || (typeof result.symbolInfo.moduleBase === 'string' && typeof result.symbolInfo.name === 'string' && typeof result.symbolInfo.offsetHex === 'string' && result.hasSymbolInfo === true && result.resolved === true && typeof result.resolvedName === 'string' && typeof result.resolvedModuleName === 'string' && typeof result.resolvedAddress === 'string' && result.hasAddress === true && result.resolvedName === result.symbolInfo.name && result.resolvedModuleName === result.symbolInfo.moduleName && result.resolvedAddress === result.symbolInfo.address && result.text === result.symbolInfo.text)); })()"
                    )
                    .expect("agent native symbolInfo result"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() { const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'native.image_info', moduleName: 'libsystem_malloc.dylib' }); return result.kind === 'native.image_info' && result.moduleName === 'libsystem_malloc.dylib' && typeof result.hasImage === 'boolean' && typeof result.resolved === 'boolean' && ((result.image === null && result.hasImage === false && result.resolved === false && result.imageName === null && result.imagePath === null && result.resolvedImageName === null && result.resolvedImagePath === null && result.resolvedBase === null && result.text === '<null>') || (result.hasImage === true && result.resolved === true && typeof result.imageName === 'string' && typeof result.imagePath === 'string' && typeof result.resolvedImageName === 'string' && typeof result.resolvedImagePath === 'string' && typeof result.resolvedBase === 'string' && typeof result.image.name === 'string' && typeof result.image.path === 'string' && typeof result.image.base === 'string' && typeof result.image.sizeHex === 'string' && result.resolvedImageName === result.image.name && result.resolvedImagePath === result.image.path && result.resolvedBase === result.image.base && result.text === result.image.text)); })()"
                    )
                    .expect("agent native imageInfo result"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() { const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'native.export_info', moduleName: 'libsystem_malloc.dylib', symbolName: 'malloc' }); return result.kind === 'native.export_info' && result.moduleName === 'libsystem_malloc.dylib' && result.symbolName === 'malloc' && typeof result.hasExportInfo === 'boolean' && typeof result.resolved === 'boolean' && typeof result.hasAddress === 'boolean' && ((result.exportInfo === null && result.hasExportInfo === false && result.resolved === false && result.resolvedName === null && result.resolvedModuleName === null && result.resolvedAddress === null && result.hasAddress === false && result.text === '<null>') || (typeof result.exportInfo.moduleBase === 'string' && typeof result.exportInfo.name === 'string' && typeof result.exportInfo.hasModuleName === 'boolean' && typeof result.exportInfo.hasName === 'boolean' && typeof result.exportInfo.offsetHex === 'string' && result.hasExportInfo === true && result.resolved === true && typeof result.resolvedName === 'string' && typeof result.resolvedModuleName === 'string' && typeof result.resolvedAddress === 'string' && result.hasAddress === true && result.resolvedName === result.exportInfo.name && result.resolvedModuleName === result.exportInfo.moduleName && result.resolvedAddress === result.exportInfo.address && result.text === result.exportInfo.text)); })()"
                    )
                    .expect("agent native exportInfo result"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() { const main = __iosRustFridaAgentApi.handleSpecResult({ kind: 'native.main_image' }); if (main.image === null) { return true; } const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'native.dependencies', moduleName: main.image.name, query: null }); return result.kind === 'native.dependencies' && result.hasQuery === false && result.count === result.dependencies.length && typeof result.hasDependencies === 'boolean' && ((result.dependencies.length === 0 && result.hasDependencies === false && result.firstDependencyName === null && result.lastDependencyName === null) || (result.hasDependencies === true && typeof result.firstDependencyName === 'string' && typeof result.lastDependencyName === 'string' && typeof result.dependencies[0].ordinal === 'number' && typeof result.dependencies[0].kind === 'string' && typeof result.dependencies[0].hasPath === 'boolean' && typeof result.dependencies[0].hasName === 'boolean' && typeof result.dependencies[0].isWeakDependency === 'boolean' && typeof result.dependencies[0].isReexportDependency === 'boolean' && typeof result.dependencies[0].isUpwardDependency === 'boolean' && typeof result.dependencies[0].isLoadDependency === 'boolean' && typeof result.dependencies[0].versionMismatch === 'boolean' && typeof result.dependencies[0].hasTimestamp === 'boolean')); })()"
                    )
                    .expect("agent native dependencies result"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() { const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'native.dependency_info', moduleName: 'libsystem_malloc.dylib', pathOrName: 'libSystem.B.dylib' }); return result.kind === 'native.dependency_info' && result.moduleName === 'libsystem_malloc.dylib' && result.pathOrName === 'libSystem.B.dylib' && typeof result.hasDependencyInfo === 'boolean' && typeof result.resolved === 'boolean' && typeof result.hasTimestamp === 'boolean' && typeof result.versionMismatch === 'boolean' && ((result.dependencyInfo === null && result.hasDependencyInfo === false && result.resolved === false && result.resolvedName === null && result.resolvedPath === null && result.resolvedModuleName === null && result.kindName === null && result.hasTimestamp === false && result.versionMismatch === false && result.text === '<null>') || (typeof result.dependencyInfo.moduleBase === 'string' && typeof result.dependencyInfo.ordinal === 'number' && typeof result.dependencyInfo.kind === 'string' && typeof result.dependencyInfo.hasPath === 'boolean' && typeof result.dependencyInfo.hasName === 'boolean' && typeof result.dependencyInfo.isWeakDependency === 'boolean' && typeof result.dependencyInfo.isReexportDependency === 'boolean' && typeof result.dependencyInfo.isUpwardDependency === 'boolean' && typeof result.dependencyInfo.isLoadDependency === 'boolean' && typeof result.dependencyInfo.versionMismatch === 'boolean' && typeof result.dependencyInfo.hasTimestamp === 'boolean' && result.hasDependencyInfo === true && result.resolved === true && typeof result.resolvedName === 'string' && typeof result.resolvedPath === 'string' && typeof result.resolvedModuleName === 'string' && typeof result.kindName === 'string' && result.hasTimestamp === (result.dependencyInfo.hasTimestamp === true) && result.versionMismatch === (result.dependencyInfo.versionMismatch === true) && result.resolvedName === result.dependencyInfo.name && result.resolvedPath === result.dependencyInfo.path && result.resolvedModuleName === result.dependencyInfo.moduleName && result.kindName === result.dependencyInfo.kind && result.text === result.dependencyInfo.text)); })()"
                    )
                    .expect("agent native dependencyInfo result"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        r#"(function() {
                            const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'native.segments', moduleName: 'libsystem_malloc.dylib' });
                            if (!(result.kind === 'native.segments'
                                && result.moduleName === 'libsystem_malloc.dylib'
                                && result.count === result.segments.length
                                && typeof result.hasSegments === 'boolean'
                                && (result.firstSegmentVmaddr === null || typeof result.firstSegmentVmaddr === 'string')
                                && (result.lastSegmentVmaddr === null || typeof result.lastSegmentVmaddr === 'string')
                                && typeof result.totalVmSizeHex === 'string'
                                && typeof result.totalFileSizeHex === 'string'
                                && (result.largestVmSegmentName === null || typeof result.largestVmSegmentName === 'string')
                                && (result.largestVmSegmentSizeHex === null || typeof result.largestVmSegmentSizeHex === 'string')
                                && (result.largestFileSegmentName === null || typeof result.largestFileSegmentName === 'string')
                                && (result.largestFileSegmentSizeHex === null || typeof result.largestFileSegmentSizeHex === 'string')
                                && typeof result.fileBackedSegmentCount === 'number'
                                && typeof result.hasFileBackedSegments === 'boolean'
                                && typeof result.zeroFillSegmentCount === 'number'
                                && typeof result.hasZeroFillSegments === 'boolean'
                                && typeof result.readableSegmentCount === 'number'
                                && typeof result.hasReadableSegments === 'boolean'
                                && typeof result.writableSegmentCount === 'number'
                                && typeof result.hasWritableSegments === 'boolean'
                                && typeof result.executableSegmentCount === 'number'
                                && typeof result.hasExecutableSegments === 'boolean'
                                && typeof result.uniqueProtectionCount === 'number'
                                && Array.isArray(result.protections))) {
                                return false;
                            }
                            if (result.segments.length === 0) {
                                return result.hasSegments === false && result.firstSegmentName === null && result.lastSegmentName === null;
                            }
                            if (!(result.hasSegments === true
                                && typeof result.firstSegmentName === 'string'
                                && typeof result.lastSegmentName === 'string')) {
                                return false;
                            }
                            const segment = result.segments[0];
                            if (!(typeof segment.name === 'string'
                                && typeof segment.hasName === 'boolean'
                                && typeof segment.vmsizeHex === 'string'
                                && typeof segment.vmEnd === 'string'
                                && typeof segment.fileoffHex === 'string'
                                && typeof segment.filesizeHex === 'string'
                                && typeof segment.fileEndHex === 'string'
                                && typeof segment.hasVmRange === 'boolean'
                                && typeof segment.hasFileData === 'boolean'
                                && typeof segment.isEmpty === 'boolean'
                                && typeof segment.isZeroFillLike === 'boolean'
                                && typeof segment.vmSizeMatchesFileSize === 'boolean'
                                && typeof segment.maxprotFlags === 'string'
                                && typeof segment.initprotFlags === 'string'
                                && typeof segment.isReadable === 'boolean'
                                && typeof segment.isWritable === 'boolean'
                                && typeof segment.isExecutable === 'boolean'
                                && typeof segment.maxReadable === 'boolean'
                                && typeof segment.maxWritable === 'boolean'
                                && typeof segment.maxExecutable === 'boolean')) {
                                return false;
                            }
                            if (result.protections.length !== 0) {
                                const protection = result.protections[0];
                                if (!(typeof protection.initprotFlags === 'string'
                                    && typeof protection.maxprotFlags === 'string'
                                    && typeof protection.count === 'number'
                                    && typeof protection.firstSegmentName === 'string'
                                    && typeof protection.lastSegmentName === 'string'
                                    && typeof protection.readableCount === 'number'
                                    && typeof protection.writableCount === 'number'
                                    && typeof protection.executableCount === 'number')) {
                                    return false;
                                }
                            }
                            return true;
                        })()"#
                    )
                    .expect("agent native segments result"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() { const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'native.segment_info', moduleName: 'libsystem_malloc.dylib', segmentName: '__TEXT' }); return result.kind === 'native.segment_info' && result.moduleName === 'libsystem_malloc.dylib' && result.segmentName === '__TEXT' && typeof result.hasSegmentInfo === 'boolean' && typeof result.resolved === 'boolean' && typeof result.hasVmRange === 'boolean' && typeof result.hasFileData === 'boolean' && typeof result.isEmpty === 'boolean' && typeof result.isReadable === 'boolean' && typeof result.isWritable === 'boolean' && typeof result.isExecutable === 'boolean' && ((result.segmentInfo === null && result.hasSegmentInfo === false && result.resolved === false && result.resolvedName === null && result.resolvedModuleName === null && result.hasVmRange === false && result.hasFileData === false && result.isEmpty === false && result.isReadable === false && result.isWritable === false && result.isExecutable === false && result.text === '<null>') || (typeof result.segmentInfo.moduleBase === 'string' && typeof result.segmentInfo.name === 'string' && typeof result.segmentInfo.vmsizeHex === 'string' && result.hasSegmentInfo === true && result.resolved === true && typeof result.resolvedName === 'string' && typeof result.resolvedModuleName === 'string' && result.resolvedName === result.segmentInfo.name && result.resolvedModuleName === result.segmentInfo.moduleName && result.hasVmRange === (result.segmentInfo.hasVmRange === true) && result.hasFileData === (result.segmentInfo.hasFileData === true) && result.isEmpty === (result.segmentInfo.isEmpty === true) && result.isReadable === (result.segmentInfo.isReadable === true) && result.isWritable === (result.segmentInfo.isWritable === true) && result.isExecutable === (result.segmentInfo.isExecutable === true) && result.text === result.segmentInfo.text)); })()"
                    )
                    .expect("agent native segmentInfo result"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        r#"(function() {
                            const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'native.sections', moduleName: 'libsystem_malloc.dylib' });
                            if (!(result.kind === 'native.sections'
                                && result.moduleName === 'libsystem_malloc.dylib'
                                && result.count === result.sections.length
                                && typeof result.hasSections === 'boolean'
                                && (result.firstSectionFullName === null || typeof result.firstSectionFullName === 'string')
                                && (result.lastSectionFullName === null || typeof result.lastSectionFullName === 'string')
                                && typeof result.totalSizeHex === 'string'
                                && typeof result.nonEmptySectionCount === 'number'
                                && typeof result.hasNonEmptySections === 'boolean'
                                && typeof result.zeroFillSectionCount === 'number'
                                && typeof result.hasZeroFillSections === 'boolean'
                                && typeof result.cstringSectionCount === 'number'
                                && typeof result.hasCStringSections === 'boolean'
                                && typeof result.symbolPointerSectionCount === 'number'
                                && typeof result.hasSymbolPointerSections === 'boolean'
                                && typeof result.uniqueSegmentCount === 'number'
                                && typeof result.uniqueSectionTypeCount === 'number'
                                && (result.largestSectionName === null || typeof result.largestSectionName === 'string')
                                && (result.largestSectionFullName === null || typeof result.largestSectionFullName === 'string')
                                && (result.largestSectionSizeHex === null || typeof result.largestSectionSizeHex === 'string')
                                && Array.isArray(result.segments)
                                && Array.isArray(result.sectionTypes))) {
                                return false;
                            }
                            if (result.sections.length === 0) {
                                return result.hasSections === false && result.firstSectionName === null && result.lastSectionName === null;
                            }
                            if (!(result.hasSections === true
                                && typeof result.firstSectionName === 'string'
                                && typeof result.lastSectionName === 'string')) {
                                return false;
                            }
                            const section = result.sections[0];
                            if (!(typeof section.segmentName === 'string'
                                && typeof section.name === 'string'
                                && typeof section.fullName === 'string'
                                && typeof section.hasSegmentName === 'boolean'
                                && typeof section.hasName === 'boolean'
                                && typeof section.addr === 'string'
                                && typeof section.sizeHex === 'string'
                                && typeof section.endAddr === 'string'
                                && typeof section.offsetHex === 'string'
                                && typeof section.alignPower === 'number'
                                && typeof section.alignmentBytesHex === 'string'
                                && typeof section.flagsHex === 'string'
                                && typeof section.sectionType === 'number'
                                && typeof section.sectionTypeName === 'string'
                                && typeof section.sectionAttributesHex === 'string'
                                && typeof section.hasData === 'boolean'
                                && typeof section.isEmpty === 'boolean'
                                && typeof section.isZeroFillLike === 'boolean'
                                && typeof section.isCStringLike === 'boolean'
                                && typeof section.isSymbolPointers === 'boolean')) {
                                return false;
                            }
                            if (result.segments.length !== 0) {
                                const segment = result.segments[0];
                                if (!(typeof segment.segmentName === 'string'
                                    && typeof segment.count === 'number'
                                    && typeof segment.totalSizeHex === 'string'
                                    && typeof segment.firstSectionName === 'string'
                                    && typeof segment.lastSectionName === 'string'
                                    && typeof segment.zeroFillCount === 'number'
                                    && typeof segment.cstringCount === 'number'
                                    && typeof segment.symbolPointerCount === 'number')) {
                                    return false;
                                }
                            }
                            if (result.sectionTypes.length !== 0) {
                                const type = result.sectionTypes[0];
                                if (!(typeof type.sectionType === 'number'
                                    && typeof type.sectionTypeName === 'string'
                                    && typeof type.count === 'number'
                                    && typeof type.totalSizeHex === 'string'
                                    && typeof type.firstFullName === 'string'
                                    && typeof type.lastFullName === 'string'
                                    && typeof type.firstSegmentName === 'string'
                                    && typeof type.lastSegmentName === 'string')) {
                                    return false;
                                }
                            }
                            return true;
                        })()"#
                    )
                    .expect("agent native sections result"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() { const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'native.section_info', moduleName: 'libsystem_malloc.dylib', segmentName: '__TEXT', sectionName: '__text' }); return result.kind === 'native.section_info' && result.moduleName === 'libsystem_malloc.dylib' && result.segmentName === '__TEXT' && result.sectionName === '__text' && typeof result.hasSectionInfo === 'boolean' && typeof result.resolved === 'boolean' && typeof result.hasData === 'boolean' && typeof result.isZeroFillLike === 'boolean' && typeof result.isCStringLike === 'boolean' && typeof result.isSymbolPointers === 'boolean' && ((result.sectionInfo === null && result.hasSectionInfo === false && result.resolved === false && result.resolvedSegmentName === null && result.resolvedSectionName === null && result.resolvedFullName === null && result.resolvedModuleName === null && result.sectionTypeName === null && result.hasData === false && result.isZeroFillLike === false && result.isCStringLike === false && result.isSymbolPointers === false && result.text === '<null>') || (typeof result.sectionInfo.moduleBase === 'string' && typeof result.sectionInfo.segmentName === 'string' && typeof result.sectionInfo.offsetHex === 'string' && result.hasSectionInfo === true && result.resolved === true && typeof result.resolvedSegmentName === 'string' && typeof result.resolvedSectionName === 'string' && typeof result.resolvedFullName === 'string' && typeof result.resolvedModuleName === 'string' && typeof result.sectionTypeName === 'string' && result.resolvedSegmentName === result.sectionInfo.segmentName && result.resolvedSectionName === result.sectionInfo.name && result.resolvedFullName === result.sectionInfo.fullName && result.resolvedModuleName === result.sectionInfo.moduleName && result.sectionTypeName === result.sectionInfo.sectionTypeName && result.hasData === (result.sectionInfo.hasData === true) && result.isZeroFillLike === (result.sectionInfo.isZeroFillLike === true) && result.isCStringLike === (result.sectionInfo.isCStringLike === true) && result.isSymbolPointers === (result.sectionInfo.isSymbolPointers === true) && result.text === result.sectionInfo.text)); })()"
                    )
                    .expect("agent native sectionInfo result"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        r#"(function() {
                            const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'native.load_commands', moduleName: 'libsystem_malloc.dylib' });
                            if (!(result.kind === 'native.load_commands'
                                && result.moduleName === 'libsystem_malloc.dylib'
                                && result.count === result.commands.length
                                && typeof result.hasCommands === 'boolean'
                                && (result.firstCommandIndex === null || typeof result.firstCommandIndex === 'number')
                                && (result.lastCommandIndex === null || typeof result.lastCommandIndex === 'number')
                                && (result.firstCommandOffsetHex === null || typeof result.firstCommandOffsetHex === 'string')
                                && (result.lastCommandOffsetHex === null || typeof result.lastCommandOffsetHex === 'string')
                                && typeof result.totalCommandSizeHex === 'string'
                                && typeof result.averageCommandSize === 'number'
                                && (result.largestCommandName === null || typeof result.largestCommandName === 'string')
                                && (result.largestCommandSize === null || typeof result.largestCommandSize === 'number')
                                && (result.largestCommandIndex === null || typeof result.largestCommandIndex === 'number')
                                && (result.smallestCommandName === null || typeof result.smallestCommandName === 'string')
                                && (result.smallestCommandSize === null || typeof result.smallestCommandSize === 'number')
                                && (result.smallestCommandIndex === null || typeof result.smallestCommandIndex === 'number')
                                && typeof result.reqDyldCommandCount === 'number'
                                && typeof result.hasReqDyldCommands === 'boolean'
                                && typeof result.detailedCommandCount === 'number'
                                && typeof result.hasDetailedCommands === 'boolean'
                                && typeof result.uniqueCommandNameCount === 'number'
                                && typeof result.hasDuplicateCommandNames === 'boolean'
                                && Array.isArray(result.commandKinds))) {
                                return false;
                            }
                            if (result.commands.length === 0) {
                                return result.hasCommands === false && result.firstCommandName === null && result.lastCommandName === null;
                            }
                            if (!(result.hasCommands === true
                                && typeof result.firstCommandName === 'string'
                                && typeof result.lastCommandName === 'string')) {
                                return false;
                            }
                            const command = result.commands[0];
                            if (!(typeof command.name === 'string'
                                && typeof command.hasName === 'boolean'
                                && typeof command.cmdHex === 'string'
                                && typeof command.cmdBaseHex === 'string'
                                && typeof command.isReqDyld === 'boolean'
                                && typeof command.cmdsize === 'number'
                                && typeof command.hasPayload === 'boolean'
                                && typeof command.offsetHex === 'string'
                                && typeof command.endOffsetHex === 'string'
                                && typeof command.hasDetail === 'boolean')) {
                                return false;
                            }
                            if (result.commandKinds.length !== 0) {
                                const kind = result.commandKinds[0];
                                if (!(typeof kind.name === 'string'
                                    && typeof kind.count === 'number'
                                    && typeof kind.firstIndex === 'number'
                                    && typeof kind.lastIndex === 'number'
                                    && typeof kind.firstOffsetHex === 'string'
                                    && typeof kind.lastOffsetHex === 'string'
                                    && typeof kind.hasDetail === 'boolean'
                                    && typeof kind.reqDyldCount === 'number')) {
                                    return false;
                                }
                            }
                            return true;
                        })()"#
                    )
                    .expect("agent native load commands result"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() { const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'native.load_command_info', moduleName: 'libsystem_malloc.dylib', commandOrIndex: 'LC_UUID' }); return result.kind === 'native.load_command_info' && result.moduleName === 'libsystem_malloc.dylib' && result.commandOrIndex === 'LC_UUID' && typeof result.hasLoadCommandInfo === 'boolean' && typeof result.resolved === 'boolean' && typeof result.isReqDyld === 'boolean' && typeof result.hasPayload === 'boolean' && typeof result.hasDetail === 'boolean' && ((result.loadCommandInfo === null && result.hasLoadCommandInfo === false && result.resolved === false && result.resolvedName === null && result.resolvedIndex === null && result.resolvedModuleName === null && result.isReqDyld === false && result.hasPayload === false && result.hasDetail === false && result.text === '<null>') || (typeof result.loadCommandInfo.moduleBase === 'string' && typeof result.loadCommandInfo.name === 'string' && typeof result.loadCommandInfo.cmdHex === 'string' && result.hasLoadCommandInfo === true && result.resolved === true && typeof result.resolvedName === 'string' && typeof result.resolvedIndex === 'number' && typeof result.resolvedModuleName === 'string' && result.resolvedName === result.loadCommandInfo.name && result.resolvedIndex === result.loadCommandInfo.index && result.resolvedModuleName === result.loadCommandInfo.moduleName && result.isReqDyld === (result.loadCommandInfo.isReqDyld === true) && result.hasPayload === (result.loadCommandInfo.hasPayload === true) && result.hasDetail === (result.loadCommandInfo.hasDetail === true) && result.text === result.loadCommandInfo.text)); })()"
                    )
                    .expect("agent native loadCommandInfo result"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() { const main = __iosRustFridaAgentApi.handleSpecResult({ kind: 'native.main_image' }); if (main.image === null) { return true; } const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'native.encryption_info', moduleName: main.image.name }); return result.kind === 'native.encryption_info' && typeof result.hasEncryptionInfo === 'boolean' && typeof result.resolved === 'boolean' && typeof result.hasEncryptedRange === 'boolean' && ((result.encryptionInfo === null && result.hasEncryptionInfo === false && result.resolved === false && result.resolvedModuleName === null && result.cryptid === null && result.hasEncryptedRange === false && result.text === '<null>') || (typeof result.encryptionInfo.cryptoffHex === 'string' && typeof result.encryptionInfo.cryptid === 'number' && result.hasEncryptionInfo === true && result.resolved === true && typeof result.resolvedModuleName === 'string' && typeof result.cryptid === 'number' && result.resolvedModuleName === result.encryptionInfo.moduleName && result.cryptid === result.encryptionInfo.cryptid && result.hasEncryptedRange === (result.encryptionInfo.cryptid !== 0) && result.text === result.encryptionInfo.text)); })()"
                    )
                    .expect("agent native encryption info result"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() { const main = __iosRustFridaAgentApi.handleSpecResult({ kind: 'native.main_image' }); if (main.image === null) { return true; } const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'native.source_version', moduleName: main.image.name }); return result.kind === 'native.source_version' && typeof result.hasSourceVersion === 'boolean' && typeof result.resolved === 'boolean' && typeof result.hasVersion === 'boolean' && ((result.sourceVersion === null && result.hasSourceVersion === false && result.resolved === false && result.resolvedModuleName === null && result.version === null && result.hasVersion === false && result.text === '<null>') || (typeof result.sourceVersion.version === 'string' && result.hasSourceVersion === true && result.resolved === true && typeof result.resolvedModuleName === 'string' && typeof result.version === 'string' && result.resolvedModuleName === result.sourceVersion.moduleName && result.version === result.sourceVersion.version && result.hasVersion === (result.sourceVersion.version.length !== 0) && result.text === result.sourceVersion.text)); })()"
                    )
                    .expect("agent native source version result"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() { const main = __iosRustFridaAgentApi.handleSpecResult({ kind: 'native.main_image' }); if (main.image === null) { return true; } const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'native.entry_point', moduleName: main.image.name }); return result.kind === 'native.entry_point' && typeof result.hasEntryPoint === 'boolean' && typeof result.resolved === 'boolean' && ((result.entryPoint === null && result.hasEntryPoint === false && result.resolved === false && result.resolvedModuleName === null && result.entryoffHex === null && result.stacksizeHex === null && result.text === '<null>') || (typeof result.entryPoint.entryoffHex === 'string' && typeof result.entryPoint.stacksizeHex === 'string' && result.hasEntryPoint === true && result.resolved === true && typeof result.resolvedModuleName === 'string' && typeof result.entryoffHex === 'string' && typeof result.stacksizeHex === 'string' && result.resolvedModuleName === result.entryPoint.moduleName && result.entryoffHex === result.entryPoint.entryoffHex && result.stacksizeHex === result.entryPoint.stacksizeHex && result.text === result.entryPoint.text)); })()"
                    )
                    .expect("agent native entry point result"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() { const main = __iosRustFridaAgentApi.handleSpecResult({ kind: 'native.main_image' }); if (main.image === null) { return true; } const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'native.dyld_info', moduleName: main.image.name }); return result.kind === 'native.dyld_info' && typeof result.hasDyldInfo === 'boolean' && typeof result.resolved === 'boolean' && typeof result.totalRegionCount === 'number' && typeof result.regionCount === 'number' && typeof result.hasRegions === 'boolean' && typeof result.hasRebaseInfo === 'boolean' && typeof result.hasBindInfo === 'boolean' && typeof result.hasWeakBindInfo === 'boolean' && typeof result.hasLazyBindInfo === 'boolean' && typeof result.hasExportInfo === 'boolean' && typeof result.hasAnyBindInfo === 'boolean' && ((result.dyldInfo === null && result.hasDyldInfo === false && result.resolved === false && result.commandName === null && result.totalRegionCount === 0 && result.regionCount === 0 && result.hasRegions === false && result.hasRebaseInfo === false && result.hasBindInfo === false && result.hasWeakBindInfo === false && result.hasLazyBindInfo === false && result.hasExportInfo === false && result.hasAnyBindInfo === false && result.text === '<null>') || (typeof result.commandName === 'string' && typeof result.dyldInfo.commandName === 'string' && typeof result.dyldInfo.commandRequiresDyld === 'boolean' && typeof result.dyldInfo.rebaseOffHex === 'string' && typeof result.dyldInfo.rebaseEndHex === 'string' && typeof result.dyldInfo.hasRebaseInfo === 'boolean' && typeof result.dyldInfo.bindEndHex === 'string' && typeof result.dyldInfo.hasBindInfo === 'boolean' && typeof result.dyldInfo.weakBindEndHex === 'string' && typeof result.dyldInfo.hasWeakBindInfo === 'boolean' && typeof result.dyldInfo.lazyBindEndHex === 'string' && typeof result.dyldInfo.hasLazyBindInfo === 'boolean' && typeof result.dyldInfo.exportSizeHex === 'string' && typeof result.dyldInfo.exportEndHex === 'string' && typeof result.dyldInfo.hasExportInfo === 'boolean' && typeof result.dyldInfo.hasAnyBindInfo === 'boolean' && typeof result.dyldInfo.totalRegionCount === 'number' && typeof result.dyldInfo.regionCount === 'number' && typeof result.dyldInfo.hasRegions === 'boolean' && result.hasDyldInfo === true && result.resolved === true && result.commandName === result.dyldInfo.commandName && result.totalRegionCount === result.dyldInfo.totalRegionCount && result.regionCount === result.dyldInfo.regionCount && result.hasRegions === (result.dyldInfo.hasRegions === true) && result.hasRebaseInfo === (result.dyldInfo.hasRebaseInfo === true) && result.hasBindInfo === (result.dyldInfo.hasBindInfo === true) && result.hasWeakBindInfo === (result.dyldInfo.hasWeakBindInfo === true) && result.hasLazyBindInfo === (result.dyldInfo.hasLazyBindInfo === true) && result.hasExportInfo === (result.dyldInfo.hasExportInfo === true) && result.hasAnyBindInfo === (result.dyldInfo.hasAnyBindInfo === true) && (result.dyldInfo.firstRegionName === null || typeof result.dyldInfo.firstRegionName === 'string') && (result.dyldInfo.lastRegionName === null || typeof result.dyldInfo.lastRegionName === 'string') && (result.dyldInfo.largestRegionName === null || typeof result.dyldInfo.largestRegionName === 'string') && (result.dyldInfo.largestRegionSizeHex === null || typeof result.dyldInfo.largestRegionSizeHex === 'string') && Array.isArray(result.dyldInfo.nonEmptyRegionNames) && Array.isArray(result.dyldInfo.regions) && result.dyldInfo.totalRegionCount === result.dyldInfo.regions.length && typeof result.dyldInfo.totalSizeHex === 'string' && (result.dyldInfo.regions.length === 0 || (typeof result.dyldInfo.regions[0].name === 'string' && typeof result.dyldInfo.regions[0].offsetHex === 'string' && typeof result.dyldInfo.regions[0].sizeHex === 'string' && typeof result.dyldInfo.regions[0].endHex === 'string' && typeof result.dyldInfo.regions[0].hasData === 'boolean' && typeof result.dyldInfo.regions[0].isEmpty === 'boolean')) && result.text === result.dyldInfo.text)); })()"
                    )
                    .expect("agent native dyld info result"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() { const main = __iosRustFridaAgentApi.handleSpecResult({ kind: 'native.main_image' }); if (main.image === null) { return true; } const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'native.linkedit', moduleName: main.image.name }); return result.kind === 'native.linkedit' && typeof result.hasLinkedit === 'boolean' && typeof result.resolved === 'boolean' && typeof result.tableCount === 'number' && typeof result.hasTables === 'boolean' && typeof result.hasSymtab === 'boolean' && typeof result.hasStrtab === 'boolean' && typeof result.hasIndirectSymbols === 'boolean' && ((result.linkedit === null && result.hasLinkedit === false && result.resolved === false && result.tableCount === 0 && result.hasTables === false && result.firstTableName === null && result.lastTableName === null && result.hasSymtab === false && result.hasStrtab === false && result.hasIndirectSymbols === false && result.text === '<null>') || (typeof result.linkedit.vmaddr === 'string' && typeof result.linkedit.vmsizeHex === 'string' && typeof result.linkedit.vmEnd === 'string' && typeof result.linkedit.fileoffHex === 'string' && typeof result.linkedit.filesizeHex === 'string' && typeof result.linkedit.fileEndHex === 'string' && typeof result.linkedit.computedBase === 'string' && typeof result.linkedit.computedEnd === 'string' && typeof result.linkedit.hasSymtab === 'boolean' && (result.linkedit.symtabAddress === null || typeof result.linkedit.symtabAddress === 'string') && typeof result.linkedit.hasStrtab === 'boolean' && (result.linkedit.strtabAddress === null || typeof result.linkedit.strtabAddress === 'string') && typeof result.linkedit.hasIndirectSymbols === 'boolean' && (result.linkedit.indirectsymAddress === null || typeof result.linkedit.indirectsymAddress === 'string') && typeof result.linkedit.totalTableCount === 'number' && typeof result.linkedit.tableCount === 'number' && typeof result.linkedit.hasTables === 'boolean' && result.hasLinkedit === true && result.resolved === true && result.tableCount === result.linkedit.tableCount && result.hasTables === (result.linkedit.hasTables === true) && result.firstTableName === result.linkedit.firstTableName && result.lastTableName === result.linkedit.lastTableName && result.hasSymtab === (result.linkedit.hasSymtab === true) && result.hasStrtab === (result.linkedit.hasStrtab === true) && result.hasIndirectSymbols === (result.linkedit.hasIndirectSymbols === true) && Array.isArray(result.linkedit.tableNames) && Array.isArray(result.linkedit.nonEmptyTableNames) && (result.linkedit.firstTableName === null || typeof result.linkedit.firstTableName === 'string') && (result.linkedit.lastTableName === null || typeof result.linkedit.lastTableName === 'string') && Array.isArray(result.linkedit.tables) && result.linkedit.totalTableCount === result.linkedit.tables.length && (result.linkedit.tables.length === 0 || (typeof result.linkedit.tables[0].name === 'string' && (result.linkedit.tables[0].offsetHex === null || typeof result.linkedit.tables[0].offsetHex === 'string') && (result.linkedit.tables[0].address === null || typeof result.linkedit.tables[0].address === 'string') && (result.linkedit.tables[0].count === null || typeof result.linkedit.tables[0].count === 'number') && (result.linkedit.tables[0].sizeHex === null || typeof result.linkedit.tables[0].sizeHex === 'string') && typeof result.linkedit.tables[0].isPresent === 'boolean')) && result.text === result.linkedit.text)); })()"
                    )
                    .expect("agent native linkedit result"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() { const main = __iosRustFridaAgentApi.handleSpecResult({ kind: 'native.main_image' }); if (main.image === null) { return true; } const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'native.function_starts', moduleName: main.image.name }); return result.kind === 'native.function_starts' && typeof result.hasFunctionStarts === 'boolean' && typeof result.resolved === 'boolean' && typeof result.startCount === 'number' && typeof result.hasStarts === 'boolean' && typeof result.gapCount === 'number' && typeof result.hasGaps === 'boolean' && ((result.functionStarts === null && result.hasFunctionStarts === false && result.resolved === false && result.startCount === 0 && result.hasStarts === false && result.gapCount === 0 && result.hasGaps === false && result.firstStartOffsetHex === null && result.lastStartOffsetHex === null && result.text === '<null>') || (typeof result.functionStarts.dataoffHex === 'string' && typeof result.functionStarts.dataEnd === 'string' && typeof result.functionStarts.count === 'number' && typeof result.functionStarts.hasStarts === 'boolean' && (result.functionStarts.firstStartOffsetHex === null || typeof result.functionStarts.firstStartOffsetHex === 'string') && (result.functionStarts.firstStartAddress === null || typeof result.functionStarts.firstStartAddress === 'string') && (result.functionStarts.lastStartOffsetHex === null || typeof result.functionStarts.lastStartOffsetHex === 'string') && (result.functionStarts.lastStartAddress === null || typeof result.functionStarts.lastStartAddress === 'string') && typeof result.functionStarts.totalSpanHex === 'string' && typeof result.functionStarts.gapCount === 'number' && typeof result.functionStarts.hasGaps === 'boolean' && result.hasFunctionStarts === true && result.resolved === true && result.startCount === result.functionStarts.count && result.hasStarts === (result.functionStarts.hasStarts === true) && result.gapCount === result.functionStarts.gapCount && result.hasGaps === (result.functionStarts.hasGaps === true) && result.firstStartOffsetHex === result.functionStarts.firstStartOffsetHex && result.lastStartOffsetHex === result.functionStarts.lastStartOffsetHex && (result.functionStarts.firstGapHex === null || typeof result.functionStarts.firstGapHex === 'string') && (result.functionStarts.lastGapHex === null || typeof result.functionStarts.lastGapHex === 'string') && (result.functionStarts.largestGapHex === null || typeof result.functionStarts.largestGapHex === 'string') && Array.isArray(result.functionStarts.starts) && result.text === result.functionStarts.text)); })()"
                    )
                    .expect("agent native function starts result"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() { const main = __iosRustFridaAgentApi.handleSpecResult({ kind: 'native.main_image' }); if (main.image === null) { return true; } const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'native.code_signature', moduleName: main.image.name }); return result.kind === 'native.code_signature' && typeof result.hasCodeSignature === 'boolean' && typeof result.resolved === 'boolean' && typeof result.hasData === 'boolean' && typeof result.hasMagic === 'boolean' && typeof result.hasBlobLength === 'boolean' && typeof result.isSuperBlob === 'boolean' && typeof result.isDetachedSignature === 'boolean' && typeof result.isBlobWrapper === 'boolean' && typeof result.isCodeDirectory === 'boolean' && typeof result.isEntitlements === 'boolean' && ((result.codeSignature === null && result.hasCodeSignature === false && result.resolved === false && result.blobKind === null && result.magicCategory === null && result.hasData === false && result.hasMagic === false && result.hasBlobLength === false && result.isSuperBlob === false && result.isDetachedSignature === false && result.isBlobWrapper === false && result.isCodeDirectory === false && result.isEntitlements === false && result.text === '<null>') || (typeof result.codeSignature.dataoffHex === 'string' && typeof result.codeSignature.datasizeHex === 'string' && typeof result.codeSignature.dataEnd === 'string' && typeof result.codeSignature.hasMagic === 'boolean' && typeof result.codeSignature.hasMagicName === 'boolean' && typeof result.codeSignature.knownMagic === 'boolean' && typeof result.codeSignature.magicCategory === 'string' && typeof result.codeSignature.blobKind === 'string' && (result.codeSignature.magicHex === null || typeof result.codeSignature.magicHex === 'string') && (result.codeSignature.lengthHex === null || typeof result.codeSignature.lengthHex === 'string') && typeof result.codeSignature.hasCount === 'boolean' && typeof result.codeSignature.hasData === 'boolean' && typeof result.codeSignature.hasBlobLength === 'boolean' && (result.codeSignature.blobLengthMatchesDataSize === null || typeof result.codeSignature.blobLengthMatchesDataSize === 'boolean') && typeof result.codeSignature.blobLengthRelation === 'string' && typeof result.codeSignature.isSuperBlob === 'boolean' && (result.codeSignature.countMatchesSuperBlob === null || typeof result.codeSignature.countMatchesSuperBlob === 'boolean') && typeof result.codeSignature.isDetachedSignature === 'boolean' && typeof result.codeSignature.isBlobWrapper === 'boolean' && typeof result.codeSignature.isCodeDirectory === 'boolean' && typeof result.codeSignature.isEntitlements === 'boolean' && result.hasCodeSignature === true && result.resolved === true && result.blobKind === result.codeSignature.blobKind && result.magicCategory === result.codeSignature.magicCategory && result.hasData === (result.codeSignature.hasData === true) && result.hasMagic === (result.codeSignature.hasMagic === true) && result.hasBlobLength === (result.codeSignature.hasBlobLength === true) && result.isSuperBlob === (result.codeSignature.isSuperBlob === true) && result.isDetachedSignature === (result.codeSignature.isDetachedSignature === true) && result.isBlobWrapper === (result.codeSignature.isBlobWrapper === true) && result.isCodeDirectory === (result.codeSignature.isCodeDirectory === true) && result.isEntitlements === (result.codeSignature.isEntitlements === true) && result.text === result.codeSignature.text)); })()"
                    )
                    .expect("agent native code signature result"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() { const main = __iosRustFridaAgentApi.handleSpecResult({ kind: 'native.main_image' }); if (main.image === null) { return true; } const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'native.data_in_code', moduleName: main.image.name }); return result.kind === 'native.data_in_code' && typeof result.hasDataInCode === 'boolean' && typeof result.resolved === 'boolean' && typeof result.entryCount === 'number' && typeof result.hasEntries === 'boolean' && typeof result.uniqueKindCount === 'number' && typeof result.hasDataEntries === 'boolean' && typeof result.hasJumpTables === 'boolean' && typeof result.hasUnknownKinds === 'boolean' && ((result.dataInCode === null && result.hasDataInCode === false && result.resolved === false && result.entryCount === 0 && result.hasEntries === false && result.uniqueKindCount === 0 && result.hasDataEntries === false && result.hasJumpTables === false && result.hasUnknownKinds === false && result.text === '<null>') || (typeof result.dataInCode.dataoffHex === 'string' && typeof result.dataInCode.dataEnd === 'string' && typeof result.dataInCode.count === 'number' && typeof result.dataInCode.hasEntries === 'boolean' && typeof result.dataInCode.hasData === 'boolean' && typeof result.dataInCode.totalEntryLength === 'string' && typeof result.dataInCode.totalSpanHex === 'string' && (result.dataInCode.firstEntryOffsetHex === null || typeof result.dataInCode.firstEntryOffsetHex === 'string') && (result.dataInCode.firstEntryAddress === null || typeof result.dataInCode.firstEntryAddress === 'string') && (result.dataInCode.firstKindName === null || typeof result.dataInCode.firstKindName === 'string') && (result.dataInCode.lastEntryOffsetHex === null || typeof result.dataInCode.lastEntryOffsetHex === 'string') && (result.dataInCode.lastEntryAddress === null || typeof result.dataInCode.lastEntryAddress === 'string') && (result.dataInCode.lastKindName === null || typeof result.dataInCode.lastKindName === 'string') && (result.dataInCode.largestEntryOffsetHex === null || typeof result.dataInCode.largestEntryOffsetHex === 'string') && (result.dataInCode.largestEntryAddress === null || typeof result.dataInCode.largestEntryAddress === 'string') && (result.dataInCode.largestEntryLength === null || typeof result.dataInCode.largestEntryLength === 'number') && typeof result.dataInCode.uniqueKindCount === 'number' && typeof result.dataInCode.hasMultipleKinds === 'boolean' && typeof result.dataInCode.dataEntryCount === 'number' && typeof result.dataInCode.hasDataEntries === 'boolean' && typeof result.dataInCode.jumpTableEntryCount === 'number' && typeof result.dataInCode.hasJumpTables === 'boolean' && typeof result.dataInCode.unknownEntryCount === 'number' && typeof result.dataInCode.hasUnknownKinds === 'boolean' && result.hasDataInCode === true && result.resolved === true && result.entryCount === result.dataInCode.count && result.hasEntries === (result.dataInCode.hasEntries === true) && result.uniqueKindCount === result.dataInCode.uniqueKindCount && result.hasDataEntries === (result.dataInCode.hasDataEntries === true) && result.hasJumpTables === (result.dataInCode.hasJumpTables === true) && result.hasUnknownKinds === (result.dataInCode.hasUnknownKinds === true) && Array.isArray(result.dataInCode.kinds) && Array.isArray(result.dataInCode.entries) && (result.dataInCode.entries.length === 0 || (typeof result.dataInCode.entries[0].endOffsetHex === 'string' && typeof result.dataInCode.entries[0].endAddress === 'string' && typeof result.dataInCode.entries[0].hasKnownKind === 'boolean' && typeof result.dataInCode.entries[0].isData === 'boolean' && typeof result.dataInCode.entries[0].isJumpTable === 'boolean' && typeof result.dataInCode.entries[0].isAbsJumpTable === 'boolean')) && (result.dataInCode.kinds.length === 0 || (typeof result.dataInCode.kinds[0].totalLengthHex === 'string' && typeof result.dataInCode.kinds[0].hasKnownKind === 'boolean' && typeof result.dataInCode.kinds[0].isData === 'boolean' && typeof result.dataInCode.kinds[0].isJumpTable === 'boolean' && typeof result.dataInCode.kinds[0].isAbsJumpTable === 'boolean')) && result.text === result.dataInCode.text)); })()"
                    )
                    .expect("agent native data in code result"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() { const main = __iosRustFridaAgentApi.handleSpecResult({ kind: 'native.main_image' }); if (main.image === null) { return true; } const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'native.exports_trie', moduleName: main.image.name }); return result.kind === 'native.exports_trie' && typeof result.hasExportsTrie === 'boolean' && typeof result.resolved === 'boolean' && typeof result.entryCount === 'number' && typeof result.hasEntries === 'boolean' && typeof result.uniqueKindCount === 'number' && typeof result.hasAddressEntries === 'boolean' && typeof result.hasOffsetEntries === 'boolean' && typeof result.hasImportNames === 'boolean' && typeof result.hasResolvers === 'boolean' && typeof result.hasReexports === 'boolean' && typeof result.hasStubAndResolvers === 'boolean' && typeof result.hasWeakDefinitions === 'boolean' && ((result.exportsTrie === null && result.hasExportsTrie === false && result.resolved === false && result.entryCount === 0 && result.hasEntries === false && result.uniqueKindCount === 0 && result.hasAddressEntries === false && result.hasOffsetEntries === false && result.hasImportNames === false && result.hasResolvers === false && result.hasReexports === false && result.hasStubAndResolvers === false && result.hasWeakDefinitions === false && result.text === '<null>') || (typeof result.exportsTrie.dataoffHex === 'string' && typeof result.exportsTrie.dataEnd === 'string' && typeof result.exportsTrie.count === 'number' && typeof result.exportsTrie.hasEntries === 'boolean' && typeof result.exportsTrie.hasData === 'boolean' && (result.exportsTrie.firstExportName === null || typeof result.exportsTrie.firstExportName === 'string') && (result.exportsTrie.firstKind === null || typeof result.exportsTrie.firstKind === 'string') && (result.exportsTrie.lastExportName === null || typeof result.exportsTrie.lastExportName === 'string') && (result.exportsTrie.lastKind === null || typeof result.exportsTrie.lastKind === 'string') && (result.exportsTrie.longestExportName === null || typeof result.exportsTrie.longestExportName === 'string') && (result.exportsTrie.longestExportNameLength === null || typeof result.exportsTrie.longestExportNameLength === 'number') && typeof result.exportsTrie.uniqueKindCount === 'number' && typeof result.exportsTrie.hasMultipleKinds === 'boolean' && typeof result.exportsTrie.addressEntryCount === 'number' && typeof result.exportsTrie.hasAddressEntries === 'boolean' && (result.exportsTrie.lowestAddress === null || typeof result.exportsTrie.lowestAddress === 'string') && (result.exportsTrie.highestAddress === null || typeof result.exportsTrie.highestAddress === 'string') && typeof result.exportsTrie.addressSpanHex === 'string' && typeof result.exportsTrie.offsetEntryCount === 'number' && typeof result.exportsTrie.hasOffsetEntries === 'boolean' && (result.exportsTrie.lowestOffsetHex === null || typeof result.exportsTrie.lowestOffsetHex === 'string') && (result.exportsTrie.highestOffsetHex === null || typeof result.exportsTrie.highestOffsetHex === 'string') && typeof result.exportsTrie.offsetSpanHex === 'string' && typeof result.exportsTrie.importNameCount === 'number' && typeof result.exportsTrie.hasImportNames === 'boolean' && typeof result.exportsTrie.resolverCount === 'number' && typeof result.exportsTrie.hasResolvers === 'boolean' && typeof result.exportsTrie.reexportCount === 'number' && typeof result.exportsTrie.hasReexports === 'boolean' && typeof result.exportsTrie.stubAndResolverCount === 'number' && typeof result.exportsTrie.hasStubAndResolvers === 'boolean' && typeof result.exportsTrie.weakDefinitionCount === 'number' && typeof result.exportsTrie.hasWeakDefinitions === 'boolean' && result.hasExportsTrie === true && result.resolved === true && result.entryCount === result.exportsTrie.count && result.hasEntries === (result.exportsTrie.hasEntries === true) && result.uniqueKindCount === result.exportsTrie.uniqueKindCount && result.hasAddressEntries === (result.exportsTrie.hasAddressEntries === true) && result.hasOffsetEntries === (result.exportsTrie.hasOffsetEntries === true) && result.hasImportNames === (result.exportsTrie.hasImportNames === true) && result.hasResolvers === (result.exportsTrie.hasResolvers === true) && result.hasReexports === (result.exportsTrie.hasReexports === true) && result.hasStubAndResolvers === (result.exportsTrie.hasStubAndResolvers === true) && result.hasWeakDefinitions === (result.exportsTrie.hasWeakDefinitions === true) && Array.isArray(result.exportsTrie.kinds) && Array.isArray(result.exportsTrie.entries) && (result.exportsTrie.kinds.length === 0 || (typeof result.exportsTrie.kinds[0].count === 'number' && typeof result.exportsTrie.kinds[0].firstExportName === 'string' && typeof result.exportsTrie.kinds[0].lastExportName === 'string' && typeof result.exportsTrie.kinds[0].hasAddress === 'boolean' && typeof result.exportsTrie.kinds[0].hasOffset === 'boolean' && typeof result.exportsTrie.kinds[0].hasImportName === 'boolean')) && (result.exportsTrie.entries.length === 0 || (typeof result.exportsTrie.entries[0].nameLength === 'number' && typeof result.exportsTrie.entries[0].hasName === 'boolean' && typeof result.exportsTrie.entries[0].hasOther === 'boolean' && typeof result.exportsTrie.entries[0].otherRole === 'string' && typeof result.exportsTrie.entries[0].hasResolver === 'boolean')) && result.text === result.exportsTrie.text)); })()"
                    )
                    .expect("agent native exports trie result"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        r#"(function() {
                            const main = __iosRustFridaAgentApi.handleSpecResult({ kind: 'native.main_image' });
                            if (main.image === null) {
                                return true;
                            }
                            const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'native.chained_fixups', moduleName: main.image.name });
                            if (result.kind !== 'native.chained_fixups') {
                                return false;
                            }
                            if (result.chainedFixups === null) {
                                return result.hasChainedFixups === false &&
                                    result.resolved === false &&
                                    result.segmentCount === 0 &&
                                    result.hasSegments === false &&
                                    result.segmentWithFixupsCount === 0 &&
                                    result.hasSegmentsWithFixups === false &&
                                    result.pointerFormatCount === 0 &&
                                    result.hasMultiplePointerFormats === false &&
                                    result.importCount === 0 &&
                                    result.hasImports === false &&
                                    result.namedImportCount === 0 &&
                                    result.hasNamedImports === false &&
                                    result.weakImportCount === 0 &&
                                    result.hasWeakImports === false &&
                                    result.addendImportCount === 0 &&
                                    result.hasAddendImports === false &&
                                    result.negativeAddendImportCount === 0 &&
                                    result.hasNegativeAddends === false;
                            }
                            const fixups = result.chainedFixups;
                            if (!(typeof result.hasChainedFixups === 'boolean'
                                && typeof result.resolved === 'boolean'
                                && typeof result.segmentCount === 'number'
                                && typeof result.hasSegments === 'boolean'
                                && typeof result.segmentWithFixupsCount === 'number'
                                && typeof result.hasSegmentsWithFixups === 'boolean'
                                && typeof result.pointerFormatCount === 'number'
                                && typeof result.hasMultiplePointerFormats === 'boolean'
                                && typeof result.importCount === 'number'
                                && typeof result.hasImports === 'boolean'
                                && typeof result.namedImportCount === 'number'
                                && typeof result.hasNamedImports === 'boolean'
                                && typeof result.weakImportCount === 'number'
                                && typeof result.hasWeakImports === 'boolean'
                                && typeof result.addendImportCount === 'number'
                                && typeof result.hasAddendImports === 'boolean'
                                && typeof result.negativeAddendImportCount === 'number'
                                && typeof result.hasNegativeAddends === 'boolean'
                                && result.hasChainedFixups === true
                                && result.resolved === true
                                && result.segmentCount === fixups.segmentCount
                                && result.hasSegments === (fixups.hasSegments === true)
                                && result.segmentWithFixupsCount === fixups.segmentWithFixupsCount
                                && result.hasSegmentsWithFixups === (fixups.hasSegmentsWithFixups === true)
                                && result.pointerFormatCount === fixups.pointerFormatCount
                                && result.hasMultiplePointerFormats === (fixups.hasMultiplePointerFormats === true)
                                && result.importCount === fixups.importCount
                                && result.hasImports === (fixups.hasImports === true)
                                && result.namedImportCount === fixups.namedImportCount
                                && result.hasNamedImports === (fixups.hasNamedImports === true)
                                && result.weakImportCount === fixups.weakImportCount
                                && result.hasWeakImports === (fixups.hasWeakImports === true)
                                && result.addendImportCount === fixups.addendImportCount
                                && result.hasAddendImports === (fixups.hasAddendImports === true)
                                && result.negativeAddendImportCount === fixups.negativeAddendImportCount
                                && result.hasNegativeAddends === (fixups.hasNegativeAddends === true)
                                && typeof fixups.dataoffHex === 'string'
                                && typeof fixups.dataEnd === 'string'
                                && typeof fixups.hasData === 'boolean'
                                && typeof fixups.startsAddress === 'string'
                                && typeof fixups.importsAddress === 'string'
                                && typeof fixups.symbolsAddress === 'string'
                                && typeof fixups.startsBeforeImports === 'boolean'
                                && typeof fixups.importsBeforeSymbols === 'boolean'
                                && typeof fixups.offsetsMonotonic === 'boolean'
                                && typeof fixups.startsToImportsDeltaHex === 'string'
                                && typeof fixups.importsToSymbolsDeltaHex === 'string'
                                && typeof fixups.segmentCount === 'number'
                                && typeof fixups.hasSegments === 'boolean'
                                && (fixups.firstSegmentIndex === null || typeof fixups.firstSegmentIndex === 'number')
                                && (fixups.lastSegmentIndex === null || typeof fixups.lastSegmentIndex === 'number')
                                && typeof fixups.totalPageCount === 'number'
                                && typeof fixups.totalFixupPageCount === 'number'
                                && typeof fixups.totalMultiStartPageCount === 'number'
                                && typeof fixups.totalChainStartCount === 'number'
                                && typeof fixups.segmentWithFixupsCount === 'number'
                                && typeof fixups.hasSegmentsWithFixups === 'boolean'
                                && (fixups.largestSegmentIndex === null || typeof fixups.largestSegmentIndex === 'number')
                                && (fixups.largestSegmentSizeHex === null || typeof fixups.largestSegmentSizeHex === 'string')
                                && typeof fixups.pointerFormatCount === 'number'
                                && typeof fixups.hasMultiplePointerFormats === 'boolean'
                                && (fixups.firstPointerFormatName === null || typeof fixups.firstPointerFormatName === 'string')
                                && (fixups.lastPointerFormatName === null || typeof fixups.lastPointerFormatName === 'string')
                                && (fixups.dominantPointerFormatName === null || typeof fixups.dominantPointerFormatName === 'string')
                                && typeof fixups.importCount === 'number'
                                && typeof fixups.hasImports === 'boolean'
                                && (fixups.firstImportName === null || typeof fixups.firstImportName === 'string')
                                && (fixups.lastImportName === null || typeof fixups.lastImportName === 'string')
                                && typeof fixups.namedImportCount === 'number'
                                && typeof fixups.hasNamedImports === 'boolean'
                                && typeof fixups.weakImportCount === 'number'
                                && typeof fixups.hasWeakImports === 'boolean'
                                && typeof fixups.addendImportCount === 'number'
                                && typeof fixups.hasAddendImports === 'boolean'
                                && typeof fixups.negativeAddendImportCount === 'number'
                                && typeof fixups.hasNegativeAddends === 'boolean'
                                && typeof fixups.uniqueLibOrdinalCount === 'number'
                                && (fixups.firstLibOrdinal === null || typeof fixups.firstLibOrdinal === 'number')
                                && (fixups.lastLibOrdinal === null || typeof fixups.lastLibOrdinal === 'number')
                                && Array.isArray(fixups.pointerFormats)
                                && Array.isArray(fixups.libOrdinals)
                                && Array.isArray(fixups.segments)
                                && Array.isArray(fixups.imports))) {
                                return false;
                            }
                            if (fixups.segments.length !== 0) {
                                const segment = fixups.segments[0];
                                if (!(typeof segment.hasFixupPages === 'boolean'
                                    && (segment.firstPageIndex === null || typeof segment.firstPageIndex === 'number')
                                    && (segment.lastPageIndex === null || typeof segment.lastPageIndex === 'number')
                                    && (segment.firstFixupPageIndex === null || typeof segment.firstFixupPageIndex === 'number')
                                    && (segment.lastFixupPageIndex === null || typeof segment.lastFixupPageIndex === 'number')
                                    && typeof segment.pageWithFixupsCount === 'number'
                                    && typeof segment.multiStartPageCount === 'number'
                                    && typeof segment.chainStartCount === 'number'
                                    && (segment.largestPageIndex === null || typeof segment.largestPageIndex === 'number')
                                    && (segment.largestPageStartCount === null || typeof segment.largestPageStartCount === 'number'))) {
                                    return false;
                                }
                                if (segment.pages.length !== 0) {
                                    const page = segment.pages[0];
                                    if (!(typeof page.hasPageStart === 'boolean'
                                        && typeof page.chainStartCount === 'number'
                                        && typeof page.hasChainStarts === 'boolean'
                                        && typeof page.effectiveStartCount === 'number'
                                        && (page.firstChainStartHex === null || typeof page.firstChainStartHex === 'string')
                                        && (page.lastChainStartHex === null || typeof page.lastChainStartHex === 'string'))) {
                                        return false;
                                    }
                                }
                            }
                            if (fixups.imports.length !== 0) {
                                const imp = fixups.imports[0];
                                if (!(typeof imp.hasName === 'boolean'
                                    && typeof imp.nameLength === 'number'
                                    && typeof imp.hasAddend === 'boolean'
                                    && typeof imp.addendSign === 'string')) {
                                    return false;
                                }
                            }
                            if (fixups.pointerFormats.length !== 0) {
                                const format = fixups.pointerFormats[0];
                                if (!(typeof format.count === 'number'
                                    && (format.firstSegmentIndex === null || typeof format.firstSegmentIndex === 'number')
                                    && (format.lastSegmentIndex === null || typeof format.lastSegmentIndex === 'number')
                                    && typeof format.totalPageCount === 'number'
                                    && typeof format.totalFixupPageCount === 'number')) {
                                    return false;
                                }
                            }
                            if (fixups.libOrdinals.length !== 0) {
                                const ordinal = fixups.libOrdinals[0];
                                if (!(typeof ordinal.libOrdinal === 'number'
                                    && typeof ordinal.count === 'number'
                                    && typeof ordinal.weakImportCount === 'number'
                                    && typeof ordinal.namedImportCount === 'number'
                                    && typeof ordinal.addendImportCount === 'number')) {
                                    return false;
                                }
                            }
                            return true;
                        })()"#
                    )
                    .expect("agent native chained fixups result"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() { const main = __iosRustFridaAgentApi.handleSpecResult({ kind: 'native.main_image' }); if (main.image === null) { return true; } const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'native.build_version', moduleName: main.image.name }); return result.kind === 'native.build_version' && typeof result.hasBuildVersion === 'boolean' && typeof result.resolved === 'boolean' && typeof result.hasTools === 'boolean' && typeof result.toolCount === 'number' && ((result.buildVersion === null && result.hasBuildVersion === false && result.resolved === false && result.resolvedModuleName === null && result.platform === null && result.hasTools === false && result.firstTool === null && result.lastTool === null && result.toolCount === 0 && result.text === '<null>') || (typeof result.buildVersion.platform === 'string' && typeof result.buildVersion.hasTools === 'boolean' && (result.buildVersion.firstTool === null || typeof result.buildVersion.firstTool === 'string') && (result.buildVersion.lastTool === null || typeof result.buildVersion.lastTool === 'string') && Array.isArray(result.buildVersion.tools) && result.hasBuildVersion === true && result.resolved === true && typeof result.resolvedModuleName === 'string' && typeof result.platform === 'string' && result.resolvedModuleName === result.buildVersion.moduleName && result.platform === result.buildVersion.platform && result.hasTools === (result.buildVersion.hasTools === true) && result.firstTool === result.buildVersion.firstTool && result.lastTool === result.buildVersion.lastTool && result.toolCount === result.buildVersion.tools.length && result.text === result.buildVersion.text)); })()"
                    )
                    .expect("agent native build version result"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() { const main = __iosRustFridaAgentApi.handleSpecResult({ kind: 'native.main_image' }); if (main.image === null) { return true; } const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'native.dylinker', moduleName: main.image.name }); return result.kind === 'native.dylinker' && typeof result.hasDylinker === 'boolean' && typeof result.resolved === 'boolean' && typeof result.hasPath === 'boolean' && ((result.dylinker === null && result.hasDylinker === false && result.resolved === false && result.resolvedModuleName === null && result.resolvedName === null && result.resolvedPath === null && result.kindName === null && result.hasPath === false && result.text === '<null>') || (typeof result.dylinker.path === 'string' && typeof result.dylinker.name === 'string' && typeof result.dylinker.hasPath === 'boolean' && typeof result.dylinker.kind === 'string' && result.hasDylinker === true && result.resolved === true && typeof result.resolvedModuleName === 'string' && typeof result.resolvedName === 'string' && typeof result.resolvedPath === 'string' && typeof result.kindName === 'string' && result.resolvedModuleName === result.dylinker.moduleName && result.resolvedName === result.dylinker.name && result.resolvedPath === result.dylinker.path && result.kindName === result.dylinker.kind && result.hasPath === (result.dylinker.hasPath === true) && result.text === result.dylinker.text)); })()"
                    )
                    .expect("agent native dylinker result"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() { const main = __iosRustFridaAgentApi.handleSpecResult({ kind: 'native.main_image' }); if (main.image === null) { return true; } const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'native.install_name', moduleName: main.image.name }); return result.kind === 'native.install_name' && typeof result.hasInstallName === 'boolean' && typeof result.resolved === 'boolean' && typeof result.hasPath === 'boolean' && typeof result.hasTimestamp === 'boolean' && typeof result.versionMismatch === 'boolean' && ((result.installName === null && result.hasInstallName === false && result.resolved === false && result.resolvedModuleName === null && result.resolvedName === null && result.resolvedPath === null && result.hasPath === false && result.hasTimestamp === false && result.versionMismatch === false && result.text === '<null>') || (typeof result.installName.path === 'string' && typeof result.installName.name === 'string' && typeof result.installName.hasPath === 'boolean' && typeof result.installName.currentVersion === 'string' && typeof result.installName.compatibilityVersion === 'string' && typeof result.installName.hasTimestamp === 'boolean' && typeof result.installName.versionMismatch === 'boolean' && result.hasInstallName === true && result.resolved === true && typeof result.resolvedModuleName === 'string' && typeof result.resolvedName === 'string' && typeof result.resolvedPath === 'string' && result.resolvedModuleName === result.installName.moduleName && result.resolvedName === result.installName.name && result.resolvedPath === result.installName.path && result.hasPath === (result.installName.hasPath === true) && result.hasTimestamp === (result.installName.hasTimestamp === true) && result.versionMismatch === (result.installName.versionMismatch === true) && result.text === result.installName.text)); })()"
                    )
                    .expect("agent native install name result"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() { const main = __iosRustFridaAgentApi.handleSpecResult({ kind: 'native.main_image' }); if (main.image === null) { return true; } const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'native.uuid', moduleName: main.image.name }); return result.kind === 'native.uuid' && typeof result.hasUuid === 'boolean' && typeof result.resolved === 'boolean' && ((result.imageUuid === null && result.hasUuid === false && result.resolved === false && result.resolvedModuleName === null && result.uuid === null && result.text === '<null>') || (typeof result.imageUuid.uuid === 'string' && result.imageUuid.uuid.length !== 0 && result.hasUuid === true && result.resolved === true && typeof result.resolvedModuleName === 'string' && typeof result.uuid === 'string' && result.resolvedModuleName === result.imageUuid.moduleName && result.uuid === result.imageUuid.uuid && result.text === result.imageUuid.text)); })()"
                    )
                    .expect("agent native uuid result"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() { const main = __iosRustFridaAgentApi.handleSpecResult({ kind: 'native.main_image' }); if (main.image === null) { return true; } const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'native.rpaths', moduleName: main.image.name, query: null }); return result.kind === 'native.rpaths' && result.hasQuery === false && result.count === result.rpaths.length && typeof result.hasRpaths === 'boolean' && ((result.rpaths.length === 0 && result.hasRpaths === false && result.firstRpath === null && result.lastRpath === null) || (result.hasRpaths === true && typeof result.firstRpath === 'string' && typeof result.lastRpath === 'string' && typeof result.rpaths[0].path === 'string')); })()"
                    )
                    .expect("agent native rpaths result"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() { const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'native.rpath_info', moduleName: 'libsystem_malloc.dylib', path: '@loader_path' }); return result.kind === 'native.rpath_info' && result.moduleName === 'libsystem_malloc.dylib' && result.path === '@loader_path' && typeof result.hasRpathInfo === 'boolean' && typeof result.resolved === 'boolean' && ((result.rpathInfo === null && result.hasRpathInfo === false && result.resolved === false && result.resolvedPath === null && result.resolvedModuleName === null && result.text === '<null>') || (typeof result.rpathInfo.moduleBase === 'string' && typeof result.rpathInfo.path === 'string' && result.hasRpathInfo === true && result.resolved === true && typeof result.resolvedPath === 'string' && typeof result.resolvedModuleName === 'string' && result.resolvedPath === result.rpathInfo.path && result.resolvedModuleName === result.rpathInfo.moduleName && result.text === result.rpathInfo.text)); })()"
                    )
                    .expect("agent native rpathInfo result"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        r#"(function() {
                            const main = __iosRustFridaAgentApi.handleSpecResult({ kind: 'native.main_image' });
                            if (main.image === null) {
                                return true;
                            }
                            const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'native.imports', moduleName: main.image.name, query: null });
                            if (!(result.kind === 'native.imports'
                                && result.hasQuery === false
                                && result.count === result.imports.length
                                && typeof result.hasImports === 'boolean'
                                && (result.firstSource === null || typeof result.firstSource === 'string')
                                && (result.lastSource === null || typeof result.lastSource === 'string')
                                && (result.longestImportName === null || typeof result.longestImportName === 'string')
                                && (result.longestImportNameLength === null || typeof result.longestImportNameLength === 'number')
                                && typeof result.weakImportCount === 'number'
                                && typeof result.hasWeakImports === 'boolean'
                                && typeof result.ordinalOnlyCount === 'number'
                                && typeof result.hasOrdinalOnlyImports === 'boolean'
                                && typeof result.mainExecutableImportCount === 'number'
                                && typeof result.hasMainExecutableImports === 'boolean'
                                && typeof result.flatLookupImportCount === 'number'
                                && typeof result.hasFlatLookupImports === 'boolean'
                                && typeof result.selfImportCount === 'number'
                                && typeof result.hasSelfImports === 'boolean'
                                && typeof result.uniqueDylibOrdinalCount === 'number'
                                && typeof result.uniqueSourceCount === 'number'
                                && Array.isArray(result.dylibSources))) {
                                return false;
                            }
                            if (result.imports.length === 0) {
                                return result.hasImports === false && result.firstImportName === null && result.lastImportName === null;
                            }
                            if (!(result.hasImports === true
                                && typeof result.firstImportName === 'string'
                                && typeof result.lastImportName === 'string')) {
                                return false;
                            }
                            const imp = result.imports[0];
                            if (!(typeof imp.dylibOrdinal === 'number'
                                && typeof imp.weakImport === 'boolean'
                                && typeof imp.hasName === 'boolean'
                                && typeof imp.hasNormalizedName === 'boolean'
                                && typeof imp.nameLength === 'number'
                                && typeof imp.hasDylibName === 'boolean'
                                && typeof imp.usesOrdinalOnly === 'boolean'
                                && typeof imp.isMainExecutableImport === 'boolean'
                                && typeof imp.isFlatLookupImport === 'boolean'
                                && typeof imp.isSelfImport === 'boolean'
                                && typeof imp.sourceKind === 'string'
                                && typeof imp.source === 'string')) {
                                return false;
                            }
                            if (result.dylibSources.length !== 0) {
                                const source = result.dylibSources[0];
                                if (!(typeof source.source === 'string'
                                    && typeof source.sourceKind === 'string'
                                    && typeof source.dylibOrdinal === 'number'
                                    && typeof source.hasDylibName === 'boolean'
                                    && typeof source.usesOrdinalOnly === 'boolean'
                                    && typeof source.count === 'number'
                                    && typeof source.weakImportCount === 'number'
                                    && typeof source.firstImportName === 'string'
                                    && typeof source.lastImportName === 'string')) {
                                    return false;
                                }
                            }
                            return true;
                        })()"#
                    )
                    .expect("agent native imports result"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() { const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'native.import_info', moduleName: 'libsystem_malloc.dylib', symbolName: 'malloc' }); return result.kind === 'native.import_info' && result.moduleName === 'libsystem_malloc.dylib' && result.symbolName === 'malloc' && typeof result.hasImportInfo === 'boolean' && typeof result.resolved === 'boolean' && typeof result.weakImport === 'boolean' && ((result.importInfo === null && result.hasImportInfo === false && result.resolved === false && result.resolvedName === null && result.resolvedNormalizedName === null && result.resolvedModuleName === null && result.source === null && result.sourceKind === null && result.weakImport === false && result.text === '<null>') || (typeof result.importInfo.moduleBase === 'string' && typeof result.importInfo.dylibOrdinal === 'number' && typeof result.importInfo.weakImport === 'boolean' && typeof result.importInfo.hasName === 'boolean' && typeof result.importInfo.hasDylibName === 'boolean' && typeof result.importInfo.usesOrdinalOnly === 'boolean' && typeof result.importInfo.isMainExecutableImport === 'boolean' && typeof result.importInfo.isFlatLookupImport === 'boolean' && typeof result.importInfo.source === 'string' && result.hasImportInfo === true && result.resolved === true && typeof result.resolvedName === 'string' && typeof result.resolvedNormalizedName === 'string' && typeof result.resolvedModuleName === 'string' && typeof result.source === 'string' && typeof result.sourceKind === 'string' && result.weakImport === (result.importInfo.weakImport === true) && result.resolvedName === result.importInfo.name && result.resolvedNormalizedName === result.importInfo.normalizedName && result.resolvedModuleName === result.importInfo.moduleName && result.source === result.importInfo.source && result.sourceKind === result.importInfo.sourceKind && result.text === result.importInfo.text)); })()"
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
                    .eval("(function() { const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'swift.protocol_info', moduleName: null, protocolName: 'Renderable' }); return result.kind === 'swift.protocol_info' && result.protocolName === 'Renderable' && typeof result.hasProtocolInfo === 'boolean' && typeof result.resolved === 'boolean' && typeof result.hasSourceKind === 'boolean' && ((result.protocolInfo === null && result.hasProtocolInfo === false && result.resolved === false && result.resolvedName === null && result.resolvedModuleName === null && result.sourceKind === null && result.text === '<null>') || (result.hasProtocolInfo === true && result.resolved === true && typeof result.resolvedName === 'string' && typeof result.resolvedModuleName === 'string' && typeof result.protocolInfo.moduleBase === 'string' && typeof result.protocolInfo.sourceSymbolName === 'string' && typeof result.protocolInfo.sourceOffsetHex === 'string' && result.hasSourceKind === (result.protocolInfo.hasSourceKind === true) && result.sourceKind === result.protocolInfo.sourceKind && result.text === result.protocolInfo.text)); })()")
                    .expect("agent swift protocolInfo result"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'swift.conformance_info', moduleName: null, typeName: 'ViewController', protocolName: 'Renderable' }); return result.kind === 'swift.conformance_info' && result.typeName === 'ViewController' && result.protocolName === 'Renderable' && typeof result.hasConformanceInfo === 'boolean' && typeof result.resolved === 'boolean' && typeof result.hasSourceKind === 'boolean' && ((result.conformanceInfo === null && result.hasConformanceInfo === false && result.resolved === false && result.resolvedTypeName === null && result.resolvedProtocolName === null && result.resolvedModuleName === null && result.sourceKind === null && result.text === '<null>') || (result.hasConformanceInfo === true && result.resolved === true && typeof result.resolvedTypeName === 'string' && typeof result.resolvedProtocolName === 'string' && typeof result.resolvedModuleName === 'string' && typeof result.conformanceInfo.moduleBase === 'string' && typeof result.conformanceInfo.sourceSymbolName === 'string' && typeof result.conformanceInfo.sourceOffsetHex === 'string' && result.hasSourceKind === (result.conformanceInfo.hasSourceKind === true) && result.sourceKind === result.conformanceInfo.sourceKind && result.text === result.conformanceInfo.text)); })()")
                    .expect("agent swift conformanceInfo result"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'swift.type_info', moduleName: null, typeName: 'ViewController' }); return result.kind === 'swift.type_info' && result.typeName === 'ViewController' && typeof result.hasTypeInfo === 'boolean' && typeof result.resolved === 'boolean' && typeof result.hasSourceKind === 'boolean' && ((result.typeInfo === null && result.hasTypeInfo === false && result.resolved === false && result.resolvedName === null && result.resolvedModuleName === null && result.sourceKind === null && result.text === '<null>') || (result.hasTypeInfo === true && result.resolved === true && typeof result.resolvedName === 'string' && typeof result.resolvedModuleName === 'string' && typeof result.typeInfo.moduleBase === 'string' && typeof result.typeInfo.sourceSymbolName === 'string' && typeof result.typeInfo.sourceOffsetHex === 'string' && result.hasSourceKind === (result.typeInfo.hasSourceKind === true) && result.sourceKind === result.typeInfo.sourceKind && result.text === result.typeInfo.text)); })()")
                    .expect("agent swift typeInfo result"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'swift.method_info', moduleName: null, typeName: 'ViewController', methodName: 'viewDidLoad' }); return result.kind === 'swift.method_info' && result.typeName === 'ViewController' && result.methodName === 'viewDidLoad' && typeof result.hasMethodInfo === 'boolean' && typeof result.resolved === 'boolean' && ((result.methodInfo === null && result.hasMethodInfo === false && result.resolved === false && result.resolvedName === null && result.resolvedModuleName === null && result.resolvedDemangledName === null && result.text === '<null>') || (result.hasMethodInfo === true && result.resolved === true && typeof result.resolvedName === 'string' && typeof result.resolvedModuleName === 'string' && typeof result.methodInfo.moduleBase === 'string' && typeof result.methodInfo.name === 'string' && typeof result.methodInfo.offsetHex === 'string' && result.resolvedName === result.methodInfo.name && result.resolvedModuleName === result.methodInfo.moduleName && result.resolvedDemangledName === result.methodInfo.demangledName && result.text === result.methodInfo.text)); })()")
                    .expect("agent swift methodInfo result"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'swift.symbol_info', moduleName: null, symbolName: 'ViewController' }); return result.kind === 'swift.symbol_info' && result.symbolName === 'ViewController' && typeof result.hasSymbolInfo === 'boolean' && typeof result.resolved === 'boolean' && ((result.symbolInfo === null && result.hasSymbolInfo === false && result.resolved === false && result.resolvedName === null && result.resolvedModuleName === null && result.resolvedDemangledName === null && result.text === '<null>') || (result.hasSymbolInfo === true && result.resolved === true && typeof result.resolvedName === 'string' && typeof result.resolvedModuleName === 'string' && typeof result.symbolInfo.moduleBase === 'string' && typeof result.symbolInfo.name === 'string' && typeof result.symbolInfo.offsetHex === 'string' && result.resolvedName === result.symbolInfo.name && result.resolvedModuleName === result.symbolInfo.moduleName && result.resolvedDemangledName === result.symbolInfo.demangledName && result.text === result.symbolInfo.text)); })()")
                    .expect("agent swift symbolInfo result"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() {
                            const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'swift.symbols', moduleName: null, query: 'ViewController' });
                            if (result.kind !== 'swift.symbols' || result.query !== 'ViewController' || result.hasQuery !== true) {
                                return false;
                            }
                            if (result.count !== result.symbols.length || typeof result.hasSymbols !== 'boolean') {
                                return false;
                            }
                            if (typeof result.uniqueModuleCount !== 'number' ||
                                    typeof result.uniqueSymbolCount !== 'number' ||
                                    typeof result.demangledCount !== 'number' ||
                                    typeof result.hasDemangledSymbols !== 'boolean' ||
                                    !Array.isArray(result.symbolNames)) {
                                return false;
                            }
                            if (result.symbols.length === 0) {
                                return result.hasSymbols === false &&
                                    result.firstSymbolName === null &&
                                    result.lastSymbolName === null;
                            }
                            const symbol = result.symbols[0];
                            const symbolSummary = result.symbolNames.length === 0 ? null : result.symbolNames[0];
                            return result.hasSymbols === true &&
                                typeof result.firstSymbolName === 'string' &&
                                typeof result.lastSymbolName === 'string' &&
                                typeof result.firstModuleName === 'string' &&
                                typeof result.lastModuleName === 'string' &&
                                typeof symbol.moduleBase === 'string' &&
                                typeof symbol.name === 'string' &&
                                typeof symbol.hasName === 'boolean' &&
                                typeof symbol.hasDemangledName === 'boolean' &&
                                typeof symbol.offsetHex === 'string' &&
                                (symbolSummary === null || (
                                    typeof symbolSummary.symbolName === 'string' &&
                                    typeof symbolSummary.count === 'number' &&
                                    typeof symbolSummary.firstModuleName === 'string' &&
                                    typeof symbolSummary.lastModuleName === 'string' &&
                                    typeof symbolSummary.hasDemangledName === 'boolean'
                                ));
                        })()"
                    )
                    .expect("agent swift symbols result"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'swift.protocols', moduleName: null, query: null }); return result.kind === 'swift.protocols' && result.query === null && result.hasQuery === false && result.count === result.protocols.length && typeof result.hasProtocols === 'boolean' && typeof result.uniqueModuleCount === 'number' && typeof result.uniqueSourceKindCount === 'number' && typeof result.sourceDemangledCount === 'number' && typeof result.hasSourceDemangledProtocols === 'boolean' && Array.isArray(result.sourceKinds) && ((result.protocols.length === 0 && result.hasProtocols === false && result.firstProtocol === null && result.lastProtocol === null) || (result.hasProtocols === true && typeof result.firstProtocol === 'string' && typeof result.lastProtocol === 'string' && typeof result.firstModuleName === 'string' && typeof result.lastModuleName === 'string' && typeof result.protocols[0].moduleBase === 'string' && typeof result.protocols[0].hasName === 'boolean' && typeof result.protocols[0].hasSourceKind === 'boolean' && typeof result.protocols[0].hasSourceSymbolName === 'boolean' && typeof result.protocols[0].hasSourceDemangledName === 'boolean' && typeof result.protocols[0].sourceSymbolName === 'string' && typeof result.protocols[0].sourceOffsetHex === 'string' && (result.sourceKinds.length === 0 || (typeof result.sourceKinds[0].sourceKind === 'string' && typeof result.sourceKinds[0].count === 'number' && typeof result.sourceKinds[0].firstProtocol === 'string' && typeof result.sourceKinds[0].lastProtocol === 'string')))); })()")
                    .expect("agent swift protocols result"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'swift.conformances', moduleName: null, query: 'ViewController' }); return result.kind === 'swift.conformances' && result.query === 'ViewController' && result.hasQuery === true && result.count === result.conformances.length && typeof result.hasConformances === 'boolean' && typeof result.uniqueProtocolCount === 'number' && typeof result.uniqueModuleCount === 'number' && typeof result.uniqueSourceKindCount === 'number' && typeof result.sourceDemangledCount === 'number' && typeof result.hasSourceDemangledConformances === 'boolean' && Array.isArray(result.protocols) && Array.isArray(result.sourceKinds) && ((result.conformances.length === 0 && result.hasConformances === false && result.firstTypeName === null && result.lastTypeName === null) || (result.hasConformances === true && typeof result.firstTypeName === 'string' && typeof result.lastTypeName === 'string' && typeof result.firstProtocolName === 'string' && typeof result.lastProtocolName === 'string' && typeof result.conformances[0].moduleBase === 'string' && typeof result.conformances[0].hasTypeName === 'boolean' && typeof result.conformances[0].hasProtocolName === 'boolean' && typeof result.conformances[0].hasSourceKind === 'boolean' && typeof result.conformances[0].hasSourceSymbolName === 'boolean' && typeof result.conformances[0].hasSourceDemangledName === 'boolean' && typeof result.conformances[0].sourceSymbolName === 'string' && typeof result.conformances[0].sourceOffsetHex === 'string' && typeof result.conformances[0].protocolName === 'string' && (result.protocols.length === 0 || (typeof result.protocols[0].protocolName === 'string' && typeof result.protocols[0].count === 'number' && typeof result.protocols[0].firstTypeName === 'string' && typeof result.protocols[0].lastTypeName === 'string')) && (result.sourceKinds.length === 0 || (typeof result.sourceKinds[0].sourceKind === 'string' && typeof result.sourceKinds[0].count === 'number' && typeof result.sourceKinds[0].firstTypeName === 'string' && typeof result.sourceKinds[0].lastTypeName === 'string')))); })()")
                    .expect("agent swift conformances result"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'swift.metadata', moduleName: null, query: 'ViewController' }); return result.kind === 'swift.metadata' && result.query === 'ViewController' && result.hasQuery === true && result.count === result.metadata.length && typeof result.hasMetadata === 'boolean' && typeof result.uniqueModuleCount === 'number' && typeof result.uniqueSourceKindCount === 'number' && typeof result.sourceDemangledCount === 'number' && typeof result.hasSourceDemangledMetadata === 'boolean' && Array.isArray(result.sourceKinds) && ((result.metadata.length === 0 && result.hasMetadata === false && result.firstTypeName === null && result.lastTypeName === null) || (result.hasMetadata === true && typeof result.firstTypeName === 'string' && typeof result.lastTypeName === 'string' && typeof result.firstModuleName === 'string' && typeof result.lastModuleName === 'string' && typeof result.metadata[0].moduleBase === 'string' && typeof result.metadata[0].hasName === 'boolean' && typeof result.metadata[0].hasSourceKind === 'boolean' && typeof result.metadata[0].hasSourceSymbolName === 'boolean' && typeof result.metadata[0].hasSourceDemangledName === 'boolean' && typeof result.metadata[0].sourceSymbolName === 'string' && typeof result.metadata[0].sourceOffsetHex === 'string' && typeof result.metadata[0].sourceKind === 'string' && (result.sourceKinds.length === 0 || (typeof result.sourceKinds[0].sourceKind === 'string' && typeof result.sourceKinds[0].count === 'number' && typeof result.sourceKinds[0].firstTypeName === 'string' && typeof result.sourceKinds[0].lastTypeName === 'string')))); })()")
                    .expect("agent swift metadata result"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'swift.metadata_info', moduleName: null, typeName: 'ViewController' }); return result.kind === 'swift.metadata_info' && result.typeName === 'ViewController' && typeof result.hasMetadataInfo === 'boolean' && typeof result.resolved === 'boolean' && typeof result.hasSourceKind === 'boolean' && ((result.metadataInfo === null && result.hasMetadataInfo === false && result.resolved === false && result.resolvedName === null && result.resolvedModuleName === null && result.sourceKind === null && result.text === '<null>') || (result.hasMetadataInfo === true && result.resolved === true && typeof result.resolvedName === 'string' && typeof result.resolvedModuleName === 'string' && typeof result.metadataInfo.moduleBase === 'string' && typeof result.metadataInfo.sourceSymbolName === 'string' && typeof result.metadataInfo.sourceOffsetHex === 'string' && result.hasSourceKind === (result.metadataInfo.hasSourceKind === true) && result.sourceKind === result.metadataInfo.sourceKind && result.text === result.metadataInfo.text)); })()")
                    .expect("agent swift metadata info result"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() {
                            const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'swift.vtable', moduleName: null, query: 'ViewController' });
                            if (result.kind !== 'swift.vtable' || result.query !== 'ViewController' || result.hasQuery !== true) {
                                return false;
                            }
                            if (result.count !== result.entries.length || typeof result.hasEntries !== 'boolean') {
                                return false;
                            }
                            if (typeof result.uniqueTypeCount !== 'number' ||
                                    typeof result.uniqueModuleCount !== 'number' ||
                                    typeof result.uniqueSourceKindCount !== 'number' ||
                                    typeof result.dispatchThunkCount !== 'number' ||
                                    typeof result.hasDispatchThunks !== 'boolean' ||
                                    typeof result.demangledCount !== 'number' ||
                                    typeof result.hasDemangledEntries !== 'boolean' ||
                                    !Array.isArray(result.types) ||
                                    !Array.isArray(result.sourceKinds)) {
                                return false;
                            }
                            if (result.entries.length === 0) {
                                return result.hasEntries === false &&
                                    result.firstTypeName === null &&
                                    result.lastTypeName === null &&
                                    result.firstMemberName === null &&
                                    result.lastMemberName === null;
                            }
                            const entry = result.entries[0];
                            const typeSummary = result.types.length === 0 ? null : result.types[0];
                            const sourceSummary = result.sourceKinds.length === 0 ? null : result.sourceKinds[0];
                            return result.hasEntries === true &&
                                typeof result.firstTypeName === 'string' &&
                                typeof result.lastTypeName === 'string' &&
                                typeof result.firstMemberName === 'string' &&
                                typeof result.lastMemberName === 'string' &&
                                typeof result.firstModuleName === 'string' &&
                                typeof result.lastModuleName === 'string' &&
                                typeof entry.moduleBase === 'string' &&
                                typeof entry.typeName === 'string' &&
                                typeof entry.hasTypeName === 'boolean' &&
                                typeof entry.memberName === 'string' &&
                                typeof entry.hasMemberName === 'boolean' &&
                                typeof entry.memberKey === 'string' &&
                                typeof entry.hasName === 'boolean' &&
                                typeof entry.hasDemangledName === 'boolean' &&
                                typeof entry.hasSourceKind === 'boolean' &&
                                typeof entry.offsetHex === 'string' &&
                                typeof entry.isDispatchThunk === 'boolean' &&
                                (typeSummary === null || (
                                    typeof typeSummary.typeName === 'string' &&
                                    typeof typeSummary.count === 'number' &&
                                    typeof typeSummary.firstMemberName === 'string' &&
                                    typeof typeSummary.lastMemberName === 'string' &&
                                    typeof typeSummary.dispatchThunkCount === 'number'
                                )) &&
                                (sourceSummary === null || (
                                    typeof sourceSummary.sourceKind === 'string' &&
                                    typeof sourceSummary.count === 'number' &&
                                    typeof sourceSummary.firstTypeName === 'string' &&
                                    typeof sourceSummary.lastTypeName === 'string' &&
                                    typeof sourceSummary.firstMemberName === 'string' &&
                                    typeof sourceSummary.lastMemberName === 'string'
                                ));
                        })()"
                    )
                    .expect("agent swift vtable result"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'swift.vtable_info', moduleName: null, typeName: 'ViewController', memberName: 'viewDidLoad' }); return result.kind === 'swift.vtable_info' && result.typeName === 'ViewController' && result.memberName === 'viewDidLoad' && typeof result.hasVtableInfo === 'boolean' && typeof result.resolved === 'boolean' && typeof result.hasSourceKind === 'boolean' && typeof result.isDispatchThunk === 'boolean' && ((result.vtableInfo === null && result.hasVtableInfo === false && result.resolved === false && result.resolvedTypeName === null && result.resolvedMemberName === null && result.resolvedModuleName === null && result.resolvedName === null && result.resolvedDemangledName === null && result.sourceKind === null && result.isDispatchThunk === false && result.text === '<null>') || (result.hasVtableInfo === true && result.resolved === true && typeof result.resolvedTypeName === 'string' && typeof result.resolvedMemberName === 'string' && typeof result.resolvedModuleName === 'string' && typeof result.resolvedName === 'string' && typeof result.vtableInfo.moduleBase === 'string' && typeof result.vtableInfo.memberName === 'string' && typeof result.vtableInfo.offsetHex === 'string' && typeof result.vtableInfo.isDispatchThunk === 'boolean' && result.hasSourceKind === (result.vtableInfo.hasSourceKind === true) && result.sourceKind === result.vtableInfo.sourceKind && result.isDispatchThunk === (result.vtableInfo.isDispatchThunk === true) && result.resolvedTypeName === result.vtableInfo.typeName && result.resolvedMemberName === result.vtableInfo.memberName && result.resolvedModuleName === result.vtableInfo.moduleName && result.resolvedName === result.vtableInfo.name && result.resolvedDemangledName === result.vtableInfo.demangledName && result.text === result.vtableInfo.text)); })()")
                    .expect("agent swift vtable info result"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() {
                            const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'swift.witness_table', moduleName: null, query: 'Renderable' });
                            if (result.kind !== 'swift.witness_table' || result.query !== 'Renderable' || result.hasQuery !== true) {
                                return false;
                            }
                            if (result.count !== result.entries.length || typeof result.hasEntries !== 'boolean') {
                                return false;
                            }
                            if (typeof result.uniqueTypeCount !== 'number' ||
                                    typeof result.uniqueProtocolCount !== 'number' ||
                                    typeof result.uniqueModuleCount !== 'number' ||
                                    typeof result.uniqueSourceKindCount !== 'number' ||
                                    typeof result.accessorCount !== 'number' ||
                                    typeof result.hasAccessors !== 'boolean' ||
                                    typeof result.demangledCount !== 'number' ||
                                    typeof result.hasDemangledEntries !== 'boolean' ||
                                    !Array.isArray(result.protocols) ||
                                    !Array.isArray(result.sourceKinds)) {
                                return false;
                            }
                            if (result.entries.length === 0) {
                                return result.hasEntries === false &&
                                    result.firstTypeName === null &&
                                    result.lastTypeName === null &&
                                    result.firstProtocolName === null &&
                                    result.lastProtocolName === null;
                            }
                            const entry = result.entries[0];
                            const protocolSummary = result.protocols.length === 0 ? null : result.protocols[0];
                            const sourceSummary = result.sourceKinds.length === 0 ? null : result.sourceKinds[0];
                            return result.hasEntries === true &&
                                typeof result.firstTypeName === 'string' &&
                                typeof result.lastTypeName === 'string' &&
                                typeof result.firstProtocolName === 'string' &&
                                typeof result.lastProtocolName === 'string' &&
                                typeof result.firstModuleName === 'string' &&
                                typeof result.lastModuleName === 'string' &&
                                typeof entry.moduleBase === 'string' &&
                                typeof entry.typeName === 'string' &&
                                typeof entry.hasTypeName === 'boolean' &&
                                typeof entry.protocolName === 'string' &&
                                typeof entry.hasProtocolName === 'boolean' &&
                                typeof entry.witnessKey === 'string' &&
                                typeof entry.hasName === 'boolean' &&
                                typeof entry.hasDemangledName === 'boolean' &&
                                typeof entry.hasSourceKind === 'boolean' &&
                                typeof entry.offsetHex === 'string' &&
                                typeof entry.isAccessor === 'boolean' &&
                                (protocolSummary === null || (
                                    typeof protocolSummary.protocolName === 'string' &&
                                    typeof protocolSummary.count === 'number' &&
                                    typeof protocolSummary.firstTypeName === 'string' &&
                                    typeof protocolSummary.lastTypeName === 'string' &&
                                    typeof protocolSummary.accessorCount === 'number'
                                )) &&
                                (sourceSummary === null || (
                                    typeof sourceSummary.sourceKind === 'string' &&
                                    typeof sourceSummary.count === 'number' &&
                                    typeof sourceSummary.firstTypeName === 'string' &&
                                    typeof sourceSummary.lastTypeName === 'string' &&
                                    typeof sourceSummary.firstProtocolName === 'string' &&
                                    typeof sourceSummary.lastProtocolName === 'string'
                                ));
                        })()"
                    )
                    .expect("agent swift witness table result"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'swift.witness_table_info', moduleName: null, typeName: 'ViewController', protocolName: 'Renderable' }); return result.kind === 'swift.witness_table_info' && result.typeName === 'ViewController' && result.protocolName === 'Renderable' && typeof result.hasWitnessTableInfo === 'boolean' && typeof result.resolved === 'boolean' && typeof result.hasSourceKind === 'boolean' && typeof result.isAccessor === 'boolean' && ((result.witnessTableInfo === null && result.hasWitnessTableInfo === false && result.resolved === false && result.resolvedTypeName === null && result.resolvedProtocolName === null && result.resolvedModuleName === null && result.resolvedName === null && result.resolvedDemangledName === null && result.sourceKind === null && result.isAccessor === false && result.text === '<null>') || (result.hasWitnessTableInfo === true && result.resolved === true && typeof result.resolvedTypeName === 'string' && typeof result.resolvedProtocolName === 'string' && typeof result.resolvedModuleName === 'string' && typeof result.resolvedName === 'string' && typeof result.witnessTableInfo.moduleBase === 'string' && typeof result.witnessTableInfo.protocolName === 'string' && typeof result.witnessTableInfo.offsetHex === 'string' && typeof result.witnessTableInfo.isAccessor === 'boolean' && result.hasSourceKind === (result.witnessTableInfo.hasSourceKind === true) && result.sourceKind === result.witnessTableInfo.sourceKind && result.isAccessor === (result.witnessTableInfo.isAccessor === true) && result.resolvedTypeName === result.witnessTableInfo.typeName && result.resolvedProtocolName === result.witnessTableInfo.protocolName && result.resolvedModuleName === result.witnessTableInfo.moduleName && result.resolvedName === result.witnessTableInfo.name && result.resolvedDemangledName === result.witnessTableInfo.demangledName && result.text === result.witnessTableInfo.text)); })()")
                    .expect("agent swift witness table info result"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() {
                            const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'swift.type_layout', moduleName: null, query: 'ViewController' });
                            if (result.kind !== 'swift.type_layout' || result.query !== 'ViewController' || result.hasQuery !== true) {
                                return false;
                            }
                            if (result.count !== result.layouts.length || typeof result.hasLayouts !== 'boolean') {
                                return false;
                            }
                            if (typeof result.uniqueModuleCount !== 'number' ||
                                    typeof result.layoutsWithMetadataCount !== 'number' ||
                                    typeof result.layoutsWithMetadataAccessorsCount !== 'number' ||
                                    typeof result.layoutsWithNominalDescriptorsCount !== 'number' ||
                                    typeof result.layoutsWithMetadataCachesCount !== 'number' ||
                                    typeof result.layoutsWithAssociatedTypeDescriptorsCount !== 'number' ||
                                    typeof result.layoutsWithVtableEntriesCount !== 'number' ||
                                    typeof result.layoutsWithWitnessTablesCount !== 'number' ||
                                    typeof result.metadataEntryCount !== 'number' ||
                                    typeof result.metadataAccessorEntryCount !== 'number' ||
                                    typeof result.nominalDescriptorEntryCount !== 'number' ||
                                    typeof result.metadataCacheEntryCount !== 'number' ||
                                    typeof result.associatedTypeDescriptorEntryCount !== 'number' ||
                                    typeof result.vtableEntryCount !== 'number' ||
                                    typeof result.witnessTableEntryCount !== 'number') {
                                return false;
                            }
                            if (result.layouts.length === 0) {
                                return result.hasLayouts === false &&
                                    result.firstTypeName === null &&
                                    result.lastTypeName === null;
                            }
                            const layout = result.layouts[0];
                            return result.hasLayouts === true &&
                                typeof result.firstTypeName === 'string' &&
                                typeof result.lastTypeName === 'string' &&
                                typeof result.firstModuleName === 'string' &&
                                typeof result.lastModuleName === 'string' &&
                                typeof layout.moduleBase === 'string' &&
                                typeof layout.name === 'string' &&
                                typeof layout.hasName === 'boolean' &&
                                Array.isArray(layout.metadata) &&
                                typeof layout.hasMetadata === 'boolean' &&
                                (layout.firstMetadataName === null || typeof layout.firstMetadataName === 'string') &&
                                (layout.lastMetadataName === null || typeof layout.lastMetadataName === 'string') &&
                                typeof layout.hasVtableEntries === 'boolean' &&
                                (layout.firstVtableMemberName === null || typeof layout.firstVtableMemberName === 'string') &&
                                (layout.lastVtableMemberName === null || typeof layout.lastVtableMemberName === 'string') &&
                                typeof layout.hasWitnessTables === 'boolean' &&
                                (layout.firstWitnessProtocolName === null || typeof layout.firstWitnessProtocolName === 'string') &&
                                (layout.lastWitnessProtocolName === null || typeof layout.lastWitnessProtocolName === 'string') &&
                                typeof layout.metadataCount === 'number' &&
                                typeof layout.metadataAccessorCount === 'number' &&
                                typeof layout.nominalDescriptorCount === 'number' &&
                                typeof layout.metadataCacheCount === 'number' &&
                                typeof layout.associatedTypeDescriptorCount === 'number' &&
                                typeof layout.vtableCount === 'number' &&
                                typeof layout.witnessTableCount === 'number';
                        })()"
                    )
                    .expect("agent swift type layout result"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'swift.type_layout_info', moduleName: null, typeName: 'ViewController' }); return result.kind === 'swift.type_layout_info' && result.typeName === 'ViewController' && typeof result.hasTypeLayout === 'boolean' && typeof result.resolved === 'boolean' && typeof result.hasMetadata === 'boolean' && typeof result.hasMetadataAccessors === 'boolean' && typeof result.hasNominalDescriptors === 'boolean' && typeof result.hasMetadataCaches === 'boolean' && typeof result.hasAssociatedTypeDescriptors === 'boolean' && typeof result.hasVtableEntries === 'boolean' && typeof result.hasWitnessTables === 'boolean' && typeof result.metadataCount === 'number' && typeof result.metadataAccessorCount === 'number' && typeof result.nominalDescriptorCount === 'number' && typeof result.metadataCacheCount === 'number' && typeof result.associatedTypeDescriptorCount === 'number' && typeof result.vtableCount === 'number' && typeof result.witnessTableCount === 'number' && ((result.typeLayout === null && result.hasTypeLayout === false && result.resolved === false && result.resolvedName === null && result.resolvedModuleName === null && result.metadataCount === 0 && result.metadataAccessorCount === 0 && result.nominalDescriptorCount === 0 && result.metadataCacheCount === 0 && result.associatedTypeDescriptorCount === 0 && result.vtableCount === 0 && result.witnessTableCount === 0 && result.text === '<null>') || (result.hasTypeLayout === true && result.resolved === true && typeof result.resolvedName === 'string' && typeof result.resolvedModuleName === 'string' && typeof result.typeLayout.moduleBase === 'string' && Array.isArray(result.typeLayout.metadata) && typeof result.typeLayout.hasMetadata === 'boolean' && (result.typeLayout.firstMetadataName === null || typeof result.typeLayout.firstMetadataName === 'string') && (result.typeLayout.lastMetadataName === null || typeof result.typeLayout.lastMetadataName === 'string') && typeof result.typeLayout.hasMetadataAccessors === 'boolean' && typeof result.typeLayout.hasNominalDescriptors === 'boolean' && typeof result.typeLayout.hasMetadataCaches === 'boolean' && typeof result.typeLayout.hasAssociatedTypeDescriptors === 'boolean' && typeof result.typeLayout.hasVtableEntries === 'boolean' && typeof result.typeLayout.hasWitnessTables === 'boolean' && typeof result.typeLayout.vtableCount === 'number' && typeof result.typeLayout.witnessTableCount === 'number' && result.resolvedName === result.typeLayout.name && result.resolvedModuleName === result.typeLayout.moduleName && result.hasMetadata === (result.typeLayout.hasMetadata === true) && result.hasMetadataAccessors === (result.typeLayout.hasMetadataAccessors === true) && result.hasNominalDescriptors === (result.typeLayout.hasNominalDescriptors === true) && result.hasMetadataCaches === (result.typeLayout.hasMetadataCaches === true) && result.hasAssociatedTypeDescriptors === (result.typeLayout.hasAssociatedTypeDescriptors === true) && result.hasVtableEntries === (result.typeLayout.hasVtableEntries === true) && result.hasWitnessTables === (result.typeLayout.hasWitnessTables === true) && result.metadataCount === result.typeLayout.metadataCount && result.metadataAccessorCount === result.typeLayout.metadataAccessorCount && result.nominalDescriptorCount === result.typeLayout.nominalDescriptorCount && result.metadataCacheCount === result.typeLayout.metadataCacheCount && result.associatedTypeDescriptorCount === result.typeLayout.associatedTypeDescriptorCount && result.vtableCount === result.typeLayout.vtableCount && result.witnessTableCount === result.typeLayout.witnessTableCount && result.text === result.typeLayout.text)); })()")
                    .expect("agent swift type layout info result"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() {
                            const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'swift.types', moduleName: null, query: 'ViewController' });
                            if (result.kind !== 'swift.types' || result.query !== 'ViewController' || result.hasQuery !== true) {
                                return false;
                            }
                            if (result.count !== result.types.length || typeof result.hasTypes !== 'boolean') {
                                return false;
                            }
                            if (typeof result.uniqueModuleCount !== 'number' ||
                                    typeof result.uniqueSourceKindCount !== 'number' ||
                                    typeof result.sourceDemangledCount !== 'number' ||
                                    typeof result.hasSourceDemangledTypes !== 'boolean' ||
                                    !Array.isArray(result.sourceKinds)) {
                                return false;
                            }
                            if (result.types.length === 0) {
                                return result.hasTypes === false &&
                                    result.firstTypeName === null &&
                                    result.lastTypeName === null;
                            }
                            const typeInfo = result.types[0];
                            const sourceSummary = result.sourceKinds.length === 0 ? null : result.sourceKinds[0];
                            return result.hasTypes === true &&
                                typeof result.firstTypeName === 'string' &&
                                typeof result.lastTypeName === 'string' &&
                                typeof result.firstModuleName === 'string' &&
                                typeof result.lastModuleName === 'string' &&
                                typeof typeInfo.moduleBase === 'string' &&
                                typeof typeInfo.sourceSymbolName === 'string' &&
                                typeof typeInfo.sourceOffsetHex === 'string' &&
                                typeof typeInfo.hasName === 'boolean' &&
                                typeof typeInfo.hasSourceKind === 'boolean' &&
                                typeof typeInfo.hasSourceSymbolName === 'boolean' &&
                                typeof typeInfo.hasSourceDemangledName === 'boolean' &&
                                (sourceSummary === null || (
                                    typeof sourceSummary.sourceKind === 'string' &&
                                    typeof sourceSummary.count === 'number' &&
                                    typeof sourceSummary.firstTypeName === 'string' &&
                                    typeof sourceSummary.lastTypeName === 'string'
                                ));
                        })()"
                    )
                    .expect("agent swift types result"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'swift.type_kinds' }); if (result.kind !== 'swift.type_kinds' || result.count !== result.kinds.length || typeof result.hasKinds !== 'boolean' || typeof result.uniquePrefixCount !== 'number' || typeof result.metadataKindCount !== 'number' || typeof result.nominalKindCount !== 'number' || typeof result.protocolKindCount !== 'number' || typeof result.witnessKindCount !== 'number' || typeof result.accessorKindCount !== 'number' || typeof result.vtableKindCount !== 'number' || !Array.isArray(result.prefixes)) { return false; } if (result.kinds.length === 0) { return result.hasKinds === false && result.firstKind === null && result.lastKind === null; } const prefixSummary = result.prefixes.length === 0 ? null : result.prefixes[0]; return result.hasKinds === true && typeof result.firstKind === 'string' && typeof result.lastKind === 'string' && result.text === result.kinds.join('\\n') && (prefixSummary === null || (typeof prefixSummary.prefix === 'string' && typeof prefixSummary.count === 'number' && typeof prefixSummary.firstKind === 'string' && typeof prefixSummary.lastKind === 'string')); })()")
                    .expect("agent swift type kinds result"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() {
                            const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'swift.types_of_kind', moduleName: null, sourceKind: 'metadata-accessor', query: 'ViewController' });
                            if (result.kind !== 'swift.types_of_kind' || result.sourceKind !== 'metadata-accessor' || result.query !== 'ViewController' || result.hasQuery !== true) {
                                return false;
                            }
                            if (result.count !== result.types.length || typeof result.hasTypes !== 'boolean') {
                                return false;
                            }
                            if (typeof result.uniqueModuleCount !== 'number' ||
                                    typeof result.uniqueSourceKindCount !== 'number' ||
                                    typeof result.sourceDemangledCount !== 'number' ||
                                    typeof result.hasSourceDemangledTypes !== 'boolean' ||
                                    !Array.isArray(result.sourceKinds)) {
                                return false;
                            }
                            if (result.types.length === 0) {
                                return result.hasTypes === false &&
                                    result.firstTypeName === null &&
                                    result.lastTypeName === null;
                            }
                            const typeInfo = result.types[0];
                            const sourceSummary = result.sourceKinds.length === 0 ? null : result.sourceKinds[0];
                            return result.hasTypes === true &&
                                typeof result.firstTypeName === 'string' &&
                                typeof result.lastTypeName === 'string' &&
                                typeof result.firstModuleName === 'string' &&
                                typeof result.lastModuleName === 'string' &&
                                typeof typeInfo.moduleBase === 'string' &&
                                typeof typeInfo.hasName === 'boolean' &&
                                typeof typeInfo.hasSourceKind === 'boolean' &&
                                typeof typeInfo.hasSourceSymbolName === 'boolean' &&
                                typeof typeInfo.hasSourceDemangledName === 'boolean' &&
                                (sourceSummary === null || (
                                    typeof sourceSummary.sourceKind === 'string' &&
                                    typeof sourceSummary.count === 'number' &&
                                    typeof sourceSummary.firstTypeName === 'string' &&
                                    typeof sourceSummary.lastTypeName === 'string'
                                ));
                        })()"
                    )
                    .expect("agent swift types of kind result"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() {
                            const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'swift.method_owners', moduleName: null, query: 'viewDidLoad' });
                            if (result.kind !== 'swift.method_owners' || result.query !== 'viewDidLoad' || result.hasQuery !== true) {
                                return false;
                            }
                            if (result.count !== result.owners.length || typeof result.hasOwners !== 'boolean') {
                                return false;
                            }
                            if (typeof result.uniqueModuleCount !== 'number' ||
                                    typeof result.uniqueSourceKindCount !== 'number' ||
                                    typeof result.sourceDemangledCount !== 'number' ||
                                    typeof result.hasSourceDemangledOwners !== 'boolean' ||
                                    !Array.isArray(result.sourceKinds)) {
                                return false;
                            }
                            if (result.owners.length === 0) {
                                return result.hasOwners === false &&
                                    result.firstOwnerName === null &&
                                    result.lastOwnerName === null;
                            }
                            const owner = result.owners[0];
                            const sourceSummary = result.sourceKinds.length === 0 ? null : result.sourceKinds[0];
                            return result.hasOwners === true &&
                                typeof result.firstOwnerName === 'string' &&
                                typeof result.lastOwnerName === 'string' &&
                                typeof result.firstModuleName === 'string' &&
                                typeof result.lastModuleName === 'string' &&
                                typeof owner.moduleBase === 'string' &&
                                typeof owner.hasName === 'boolean' &&
                                typeof owner.hasSourceKind === 'boolean' &&
                                typeof owner.hasSourceSymbolName === 'boolean' &&
                                typeof owner.hasSourceDemangledName === 'boolean' &&
                                typeof owner.sourceSymbolName === 'string' &&
                                typeof owner.sourceOffsetHex === 'string' &&
                                (sourceSummary === null || (
                                    typeof sourceSummary.sourceKind === 'string' &&
                                    typeof sourceSummary.count === 'number' &&
                                    typeof sourceSummary.firstOwnerName === 'string' &&
                                    typeof sourceSummary.lastOwnerName === 'string'
                                ));
                        })()"
                    )
                    .expect("agent swift method owners result"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() {
                            const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'swift.type_methods', moduleName: null, query: 'ViewController' });
                            if (result.kind !== 'swift.type_methods' || result.query !== 'ViewController' || result.hasQuery !== true) {
                                return false;
                            }
                            if (result.count !== result.methods.length || typeof result.hasMethods !== 'boolean') {
                                return false;
                            }
                            if (typeof result.uniqueModuleCount !== 'number' ||
                                    typeof result.uniqueMethodCount !== 'number' ||
                                    typeof result.demangledCount !== 'number' ||
                                    typeof result.hasDemangledMethods !== 'boolean' ||
                                    !Array.isArray(result.methodNames)) {
                                return false;
                            }
                            if (result.methods.length === 0) {
                                return result.hasMethods === false &&
                                    result.firstMethodName === null &&
                                    result.lastMethodName === null;
                            }
                            const method = result.methods[0];
                            const methodSummary = result.methodNames.length === 0 ? null : result.methodNames[0];
                            return result.hasMethods === true &&
                                typeof result.firstMethodName === 'string' &&
                                typeof result.lastMethodName === 'string' &&
                                typeof result.firstModuleName === 'string' &&
                                typeof result.lastModuleName === 'string' &&
                                typeof method.moduleBase === 'string' &&
                                typeof method.name === 'string' &&
                                typeof method.hasName === 'boolean' &&
                                typeof method.hasDemangledName === 'boolean' &&
                                typeof method.offsetHex === 'string' &&
                                (methodSummary === null || (
                                    typeof methodSummary.methodName === 'string' &&
                                    typeof methodSummary.count === 'number' &&
                                    typeof methodSummary.firstModuleName === 'string' &&
                                    typeof methodSummary.lastModuleName === 'string' &&
                                    typeof methodSummary.hasDemangledName === 'boolean'
                                ));
                        })()"
                    )
                    .expect("agent swift type methods result"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval(
                        "(function() {
                            const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'swift.methods', moduleName: null, typeName: 'ViewController', methodQuery: 'viewDidLoad' });
                            if (result.kind !== 'swift.methods' || result.typeName !== 'ViewController' || result.methodQuery !== 'viewDidLoad' || result.hasMethodQuery !== true) {
                                return false;
                            }
                            if (result.count !== result.methods.length || typeof result.hasMethods !== 'boolean') {
                                return false;
                            }
                            if (typeof result.uniqueModuleCount !== 'number' ||
                                    typeof result.uniqueMethodCount !== 'number' ||
                                    typeof result.demangledCount !== 'number' ||
                                    typeof result.hasDemangledMethods !== 'boolean' ||
                                    !Array.isArray(result.methodNames)) {
                                return false;
                            }
                            if (result.methods.length === 0) {
                                return result.hasMethods === false &&
                                    result.firstMethodName === null &&
                                    result.lastMethodName === null;
                            }
                            const method = result.methods[0];
                            const methodSummary = result.methodNames.length === 0 ? null : result.methodNames[0];
                            return result.hasMethods === true &&
                                typeof result.firstMethodName === 'string' &&
                                typeof result.lastMethodName === 'string' &&
                                typeof result.firstModuleName === 'string' &&
                                typeof result.lastModuleName === 'string' &&
                                typeof method.moduleBase === 'string' &&
                                typeof method.name === 'string' &&
                                typeof method.hasName === 'boolean' &&
                                typeof method.hasDemangledName === 'boolean' &&
                                typeof method.offsetHex === 'string' &&
                                (methodSummary === null || (
                                    typeof methodSummary.methodName === 'string' &&
                                    typeof methodSummary.count === 'number' &&
                                    typeof methodSummary.firstModuleName === 'string' &&
                                    typeof methodSummary.lastModuleName === 'string' &&
                                    typeof methodSummary.hasDemangledName === 'boolean'
                                ));
                        })()"
                    )
                    .expect("agent swift methods result"),
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
                    .eval("(function() { const value = __iosRustFridaAgentApi.handle('swift.findMethods ViewController viewDidLoad'); const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'swift.methods', moduleName: null, typeName: 'ViewController', methodQuery: 'viewDidLoad' }); return value === result.text && result.typeName === 'ViewController' && result.methodQuery === 'viewDidLoad' && result.count === result.methods.length; })()")
                    .expect("agent swift findMethods"),
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
                    .eval("(function() { const value = __iosRustFridaAgentApi.handle('native.hookenv'); return value.indexOf('conflict_state=') !== -1 && value.indexOf('risk_level=') !== -1 && value.indexOf('loaded_backend_count=') !== -1 && value.indexOf('hook_install_commands_allowed=') !== -1 && value.indexOf('query_commands_allowed=') !== -1; })()")
                    .expect("agent native hook env summary"),
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
                    .eval("(function() { const value = __iosRustFridaAgentApi.handle('native.findSymbols malloc'); const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'native.symbols', moduleName: null, query: 'malloc' }); return value === result.text && result.query === 'malloc' && result.count === result.symbols.length; })()")
                    .expect("agent native findSymbols"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const main = __iosRustFridaAgentApi.handle('native.mainImage'); if (main === '<null>') { return true; } const path = main.split(' ').slice(2).join(' '); const base = path.split('/').filter(Boolean).pop() || path; const value = __iosRustFridaAgentApi.handle('native.findDyldInfo ' + base); const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'native.dyld_info', moduleName: base }); return value === result.text && (result.dyldInfo === null || (typeof result.dyldInfo.commandName === 'string' && Array.isArray(result.dyldInfo.regions) && result.dyldInfo.totalRegionCount === result.dyldInfo.regions.length)); })()")
                    .expect("agent native findDyldInfo"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const main = __iosRustFridaAgentApi.handle('native.mainImage'); if (main === '<null>') { return true; } const path = main.split(' ').slice(2).join(' '); const base = path.split('/').filter(Boolean).pop() || path; const value = __iosRustFridaAgentApi.handle('native.findLoadCommands ' + base); const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'native.load_commands', moduleName: base }); return value === result.text && result.count === result.commands.length; })()")
                    .expect("agent native findLoadCommands"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const value = __iosRustFridaAgentApi.handle('native.findImports libsystem_malloc.dylib -- malloc'); const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'native.imports', moduleName: 'libsystem_malloc.dylib', query: 'malloc' }); return value === result.text && result.moduleName === 'libsystem_malloc.dylib' && result.query === 'malloc' && result.count === result.imports.length; })()")
                    .expect("agent native findImports"),
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
                    .eval("(function() { const value = __iosRustFridaAgentApi.handleSpec({ kind: 'pac.image', moduleName: 'libsystem_malloc.dylib' }); const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'pac.image', moduleName: 'libsystem_malloc.dylib' }); return value === result.text; })()")
                    .expect("agent spec pac image"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const malloc = Module.findExportByName(null, 'malloc'); if (malloc === null) { return true; } const value = __iosRustFridaAgentApi.handleSpec({ kind: 'native.symbol', address: malloc.toString() }); const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'native.symbol', address: malloc.toString() }); return value === result.text; })()")
                    .expect("agent spec native symbol"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const value = __iosRustFridaAgentApi.handleSpec({ kind: 'native.base', moduleName: 'libsystem_malloc.dylib' }); const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'native.base', moduleName: 'libsystem_malloc.dylib' }); return value === result.text; })()")
                    .expect("agent spec native base"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const value = __iosRustFridaAgentApi.handleSpec({ kind: 'swift.available' }); const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'swift.available' }); return value === result.text; })()")
                    .expect("agent spec swift available"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const value = __iosRustFridaAgentApi.handleSpec({ kind: 'swift.demangle', symbol: '$s4Demo6methodyyF' }); const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'swift.demangle', symbol: '$s4Demo6methodyyF' }); return value === result.text; })()")
                    .expect("agent spec swift demangle"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const value = __iosRustFridaAgentApi.handleSpec({ kind: 'objc.class_exists', className: 'NSObject' }); const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'objc.class_exists', className: 'NSObject' }); return value === result.text; })()")
                    .expect("agent spec objc classExists"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const value = __iosRustFridaAgentApi.handleSpec({ kind: 'objc.selector', selectorName: 'init' }); const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'objc.selector', selectorName: 'init' }); return value === result.text; })()")
                    .expect("agent spec objc selector"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'objc.class_exists', className: 'NSObject' }); return result.kind === 'objc.class_exists' && result.className === 'NSObject' && result.resolved === true && result.exists === (result.resolvedClassName !== null) && result.text === String(result.exists); })()")
                    .expect("agent objc classExists result"),
                "true"
            );
            assert_eq!(
                runtime
                    .eval("(function() { const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'objc.selector', selectorName: 'init' }); return result.kind === 'objc.selector' && result.selectorName === 'init' && typeof result.hasPointer === 'boolean' && typeof result.resolved === 'boolean' && ((result.pointer === null && result.hasPointer === false && result.resolved === false && result.resolvedSelectorName === null && result.resolvedPointer === null && result.text === '<null>') || (typeof result.pointer === 'string' && result.hasPointer === true && result.resolved === true && result.resolvedSelectorName === 'init' && result.resolvedPointer === result.pointer && result.text === result.pointer)); })()")
                    .expect("agent objc selector result"),
                "true"
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
                    .eval("(function() { const value = __iosRustFridaAgentApi.handleSpec({ kind: 'objc.class_protocols', className: 'NSObject', filter: 'NS' }); const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'objc.class_protocols', className: 'NSObject', filter: 'NS' }); return value === result.text; })()")
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
                    .eval("(function() { const value = __iosRustFridaAgentApi.handleSpec({ kind: 'objc.protocol_protocols', protocolName: 'NSObject', filter: 'NS' }); const result = __iosRustFridaAgentApi.handleSpecResult({ kind: 'objc.protocol_protocols', protocolName: 'NSObject', filter: 'NS' }); return value === result.text; })()")
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
