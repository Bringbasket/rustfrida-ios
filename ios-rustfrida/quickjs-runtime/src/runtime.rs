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
                runtime.eval("typeof ObjC.methodImp").expect("objc methodImp type"),
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
                    .eval("Array.isArray(ObjC.methods('NSObject'))")
                    .expect("objc methods"),
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
                    .eval("Array.isArray(ObjC.findMethods('NSObject', 'init'))")
                    .expect("objc findMethods"),
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
                    .eval("typeof Swift.findSymbols")
                    .expect("swift findSymbols type"),
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
                    .eval("Array.isArray(Swift.findSymbols('ViewController'))")
                    .expect("swift findSymbols"),
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
                runtime
                    .eval("Array.isArray(Module.enumerateModules())")
                    .expect("enumerate modules"),
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
                runtime
                    .eval("typeof Native.findSymbols")
                    .expect("native find symbols type"),
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
                    .eval("Array.isArray(Native.findExports('libsystem_malloc.dylib'))")
                    .expect("native find exports"),
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
                    .eval("Array.isArray(Native.findSections('libsystem_malloc.dylib'))")
                    .expect("native find sections"),
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
                    .eval("(function() { const commands = Native.findLoadCommands('libsystem_malloc.dylib'); return commands.length === 0 || ('detail' in commands[0]); })()")
                    .expect("native load command detail property"),
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
                "{\"kind\":\"hfl.stop\",\"action\":\"stop\",\"scope\":\"hfl\",\"count\":0,\"message\":\"hfl detached: 0\"}"
            );
            assert_eq!(
                runtime
                    .eval("JSON.stringify(__iosRustFridaControllerApi.dispatchResult({ kind: 'hfl.status' }))")
                    .expect("controller hfl status result"),
                "{\"kind\":\"hfl.status\",\"action\":\"status\",\"active\":false,\"count\":0,\"keys\":[],\"targets\":[],\"message\":\"hfl inactive\"}"
            );
            assert_eq!(
                runtime
                    .eval("JSON.stringify(__iosRustFridaControllerApi.dispatchResult({ kind: 'objc.hook.status' }))")
                    .expect("controller objc hook status result"),
                "{\"kind\":\"objc.hook.status\",\"action\":\"status\",\"active\":false,\"count\":0,\"keys\":[],\"targets\":[],\"message\":\"jhook inactive\"}"
            );
            assert_eq!(
                runtime
                    .eval("JSON.stringify(__iosRustFridaControllerApi.dispatchResult({ kind: 'trace.status' }))")
                    .expect("controller trace status result"),
                "{\"active\":false,\"count\":0,\"label\":null,\"filter\":null,\"targetAddress\":null,\"targetKind\":null,\"targetSymbol\":null,\"moduleName\":null,\"symbolName\":null,\"objcMode\":null,\"message\":\"trace inactive\",\"kind\":\"trace.status\",\"action\":\"status\",\"scope\":\"trace\"}"
            );
            assert_eq!(
                runtime
                    .eval("JSON.stringify(__iosRustFridaControllerApi.dispatchResult({ kind: 'stalker.status' }))")
                    .expect("controller stalker status result"),
                "{\"active\":false,\"count\":0,\"label\":null,\"filter\":null,\"targetAddress\":null,\"secondaryTargetAddress\":null,\"targetKind\":null,\"targetSymbol\":null,\"moduleName\":null,\"symbolName\":null,\"objcMode\":null,\"superEnabled\":false,\"message\":\"stalker inactive\",\"kind\":\"stalker.status\",\"action\":\"status\",\"scope\":\"stalker\"}"
            );
            assert_eq!(
                runtime
                    .eval("JSON.stringify(__iosRustFridaControllerApi.dispatchResult({ kind: 'swift.hook.status' }))")
                    .expect("controller swift hook status result"),
                "{\"kind\":\"swift.hook.status\",\"action\":\"status\",\"active\":false,\"count\":0,\"keys\":[],\"targets\":[],\"message\":\"shook inactive\"}"
            );
            assert_eq!(
                runtime
                    .eval("(function() { globalThis.__iosRustFridaHfl = { 'libobjc.A.dylib+0x1234': { moduleName: 'libobjc.A.dylib', offsetHex: '0x1234', target: '0x180001234' } }; return JSON.stringify(__iosRustFridaControllerApi.dispatchResult({ kind: 'hfl.status' })); })()")
                    .expect("controller populated hfl status result"),
                "{\"kind\":\"hfl.status\",\"action\":\"status\",\"active\":true,\"count\":1,\"keys\":[\"libobjc.A.dylib+0x1234\"],\"targets\":[{\"key\":\"libobjc.A.dylib+0x1234\",\"moduleName\":\"libobjc.A.dylib\",\"offsetHex\":\"0x1234\",\"target\":\"0x180001234\"}],\"message\":\"hfl active: 1\"}"
            );
            assert_eq!(
                runtime
                    .eval("(function() { globalThis.__iosRustFridaObjcHooks = { '-[UIViewController viewDidLoad]': { className: 'UIViewController', selectorName: 'viewDidLoad', isClassMethod: false, target: '0x18000abcd' } }; return JSON.stringify(__iosRustFridaControllerApi.dispatchResult({ kind: 'objc.hook.status' })); })()")
                    .expect("controller populated objc hook status result"),
                "{\"kind\":\"objc.hook.status\",\"action\":\"status\",\"active\":true,\"count\":1,\"keys\":[\"-[UIViewController viewDidLoad]\"],\"targets\":[{\"key\":\"-[UIViewController viewDidLoad]\",\"className\":\"UIViewController\",\"selectorName\":\"viewDidLoad\",\"isClassMethod\":false,\"target\":\"0x18000abcd\"}],\"message\":\"jhook active: 1\"}"
            );
            assert_eq!(
                runtime
                    .eval("(function() { globalThis.__iosRustFridaSwiftHooks = { 'MyApp::ViewController::viewDidLoad': { moduleName: 'MyApp', typeName: 'ViewController', methodQuery: 'viewDidLoad', targets: [{ address: '0x18000beef', name: '$s4MyApp14ViewControllerC11viewDidLoadyyF', demangledName: 'MyApp.ViewController.viewDidLoad()', moduleName: 'MyApp' }] } }; return JSON.stringify(__iosRustFridaControllerApi.dispatchResult({ kind: 'swift.hook.status' })); })()")
                    .expect("controller populated swift hook status result"),
                "{\"kind\":\"swift.hook.status\",\"action\":\"status\",\"active\":true,\"count\":1,\"keys\":[\"MyApp::ViewController::viewDidLoad\"],\"targets\":[{\"key\":\"MyApp::ViewController::viewDidLoad\",\"moduleName\":\"MyApp\",\"typeName\":\"ViewController\",\"methodQuery\":\"viewDidLoad\",\"count\":1,\"targets\":[{\"address\":\"0x18000beef\",\"name\":\"$s4MyApp14ViewControllerC11viewDidLoadyyF\",\"demangledName\":\"MyApp.ViewController.viewDidLoad()\",\"moduleName\":\"MyApp\"}]}],\"message\":\"shook active: 1\"}"
            );
            assert_eq!(
                runtime
                    .eval("JSON.stringify(__iosRustFridaControllerApi.dispatchResult({ kind: 'trace.stop' }))")
                    .expect("controller trace stop result"),
                "{\"active\":false,\"count\":0,\"label\":null,\"filter\":null,\"targetAddress\":null,\"targetKind\":null,\"targetSymbol\":null,\"moduleName\":null,\"symbolName\":null,\"objcMode\":null,\"message\":\"trace stopped\",\"kind\":\"trace.stop\",\"action\":\"stop\",\"scope\":\"trace\"}"
            );
            assert_eq!(
                runtime
                    .eval("JSON.stringify(__iosRustFridaControllerApi.dispatchResult({ kind: 'stalker.stop' }))")
                    .expect("controller stalker stop result"),
                "{\"active\":false,\"count\":0,\"label\":null,\"filter\":null,\"targetAddress\":null,\"secondaryTargetAddress\":null,\"targetKind\":null,\"targetSymbol\":null,\"moduleName\":null,\"symbolName\":null,\"objcMode\":null,\"superEnabled\":false,\"message\":\"stalker stopped\",\"kind\":\"stalker.stop\",\"action\":\"stop\",\"scope\":\"stalker\"}"
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
                    .eval("(function() { const value = __iosRustFridaAgentApi.handle('objc.classes NSObject'); return value === '' || value.indexOf('NSObject') !== -1; })()")
                    .expect("agent objc classes filtered"),
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
                    .eval("(function() { const value = __iosRustFridaAgentApi.handle('swift.typesOfKind metadata-accessor ViewController'); return value === '' || value.indexOf('[metadata-accessor]') !== -1; })()")
                    .expect("agent swift types of kind"),
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
                    .eval("(function() { const value = __iosRustFridaAgentApi.handle('native.exports libsystem_malloc.dylib -- malloc'); return value === '' || value.indexOf('malloc') !== -1; })()")
                    .expect("agent native exports by query"),
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
                    .eval("(function() { const main = __iosRustFridaAgentApi.handle('native.mainImage'); if (main === '<null>') { return true; } const path = main.split(' ').slice(2).join(' '); const base = path.split('/').filter(Boolean).pop() || path; const value = __iosRustFridaAgentApi.handle('native.sections ' + base); return value === '' || value.indexOf('addr=') !== -1; })()")
                    .expect("agent native sections"),
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
                    .eval("__iosRustFridaAgentApi.handle('native.export malloc').indexOf('malloc') !== -1")
                    .expect("agent native export"),
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
