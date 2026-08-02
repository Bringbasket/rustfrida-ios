//! The iOS CModule compiler/linker/load implementation.
//!
//! Apple builds embed the repository's TinyCC `libtcc` entry point. Source is
//! compiled to the target architecture, relocated into a MAP_JIT allocation,
//! and exposed as a QuickJS object with exported function pointers. Non-Apple
//! builds retain validation and host syntax preflight, but never allocate or
//! execute generated code.

use crate::context::JSContext;
use crate::ffi;
#[cfg(quickjs_cmodule)]
use crate::ptr::create_native_pointer;
use crate::ptr::get_native_pointer_addr;
use crate::util::{add_cfunction_to_object, js_throw_internal_error, js_throw_type_error};
use crate::value::JSValue;
use std::collections::BTreeSet;
use std::error::Error;
use std::fmt;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

#[cfg(quickjs_cmodule)]
use std::collections::HashMap;
#[cfg(quickjs_cmodule)]
use std::ffi::{c_char, c_int, c_void, CStr, CString};
#[cfg(quickjs_cmodule)]
use std::ptr;
#[cfg(quickjs_cmodule)]
use std::sync::atomic::{AtomicU32, Ordering};

const CMODULE_BOOTSTRAP: &str = r#"
(function () {
    'use strict';
    const nativeCompile = globalThis.__iosCModuleCompile;
    const nativeCapabilities = globalThis.__iosCModuleCapabilities;

    function CModule(source, symbols) {
        if (!(this instanceof CModule)) {
            return new CModule(source, symbols);
        }
        if (arguments.length < 1 || arguments.length > 2) {
            throw new TypeError('CModule(source[, symbols]) requires one or two arguments');
        }
        if (symbols !== undefined && symbols !== null && typeof symbols !== 'object') {
            throw new TypeError('CModule symbols must be an object when provided');
        }
        const entries = symbols === undefined || symbols === null
            ? []
            : Object.keys(symbols).map(function (name) { return [name, symbols[name]]; });
        return nativeCompile(source, entries);
    }

    const snapshot = nativeCapabilities();
    Object.defineProperties(CModule, {
        available: { value: snapshot.available, enumerable: true },
        platform: { value: snapshot.platform, enumerable: true },
        backend: { value: snapshot.backend, enumerable: true }
    });
    CModule.capabilities = nativeCapabilities;
    CModule.status = nativeCapabilities;
    CModule.info = nativeCapabilities;
    CModule.lastError = function () { return nativeCapabilities().reason; };

    globalThis.CModule = CModule;
    delete globalThis.__iosCModuleCompile;
    delete globalThis.__iosCModuleCapabilities;
})();
"#;

/// Maximum source accepted by the request validator.
pub const MAX_SOURCE_BYTES: usize = 1024 * 1024;

/// Maximum number of imported symbols accepted by the request validator.
pub const MAX_IMPORTS: usize = 4096;

/// Maximum UTF-8 byte length of one imported symbol name.
pub const MAX_SYMBOL_NAME_BYTES: usize = 256;

/// A host compiler adapter used for deterministic source diagnostics.
///
/// This adapter deliberately stops at `-fsyntax-only`. It is useful on the
/// development host for checking CModule input and compiler diagnostics, but
/// it never produces executable memory and is never advertised as the iOS
/// CModule backend.
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostCompilerAdapter {
    program: PathBuf,
}

#[allow(dead_code)]
impl HostCompilerAdapter {
    /// Creates an adapter for one compiler executable. The executable is
    /// probed when [`Self::check_syntax`] is called.
    pub fn new(program: impl Into<PathBuf>) -> Self {
        Self {
            program: program.into(),
        }
    }

    /// Finds a host compiler without changing the iOS capability snapshot.
    pub fn detect() -> Option<Self> {
        if cfg!(all(target_os = "ios", target_vendor = "apple")) {
            return None;
        }

        let configured = std::env::var_os("IOS_CMODULE_HOST_CC")
            .or_else(|| std::env::var_os("CC"))
            .map(PathBuf::from);
        let mut candidates =
            configured
                .into_iter()
                .chain([PathBuf::from("cc"), PathBuf::from("clang"), PathBuf::from("gcc")]);

        candidates
            .find(|program| {
                Command::new(program)
                    .arg("--version")
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status()
                    .map(|status| status.success())
                    .unwrap_or(false)
            })
            .map(Self::new)
    }

    pub fn program(&self) -> &Path {
        &self.program
    }

    /// Runs a host-only syntax check for a validated request.
    pub fn check_syntax(&self, request: &CModuleRequest) -> Result<HostCompileReport, CModuleError> {
        let mut child = Command::new(&self.program)
            .args(["-x", "c", "-std=c11", "-fsyntax-only", "-Werror", "-"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|error| CModuleError::HostCompilerUnavailable {
                compiler: self.program.display().to_string(),
                reason: error.to_string(),
            })?;

        let Some(mut stdin) = child.stdin.take() else {
            return Err(CModuleError::HostCompilerUnavailable {
                compiler: self.program.display().to_string(),
                reason: "host compiler stdin was not available".into(),
            });
        };
        stdin
            .write_all(request.source.as_bytes())
            .map_err(|error| CModuleError::HostCompilerUnavailable {
                compiler: self.program.display().to_string(),
                reason: format!("failed to write source: {error}"),
            })?;
        drop(stdin);

        let output = child
            .wait_with_output()
            .map_err(|error| CModuleError::HostCompilerUnavailable {
                compiler: self.program.display().to_string(),
                reason: error.to_string(),
            })?;
        let diagnostics = if output.stderr.is_empty() {
            String::from_utf8_lossy(&output.stdout).into_owned()
        } else {
            String::from_utf8_lossy(&output.stderr).into_owned()
        };
        if !output.status.success() {
            return Err(CModuleError::HostCompilationFailed {
                compiler: self.program.display().to_string(),
                diagnostics,
            });
        }

        Ok(HostCompileReport {
            compiler: self.program.display().to_string(),
            source_bytes: request.source.len(),
            import_count: request.imports.len(),
            diagnostics,
        })
    }
}

/// Result of a host compiler syntax check. It is not an executable CModule.
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostCompileReport {
    pub compiler: String,
    pub source_bytes: usize,
    pub import_count: usize,
    pub diagnostics: String,
}

/// Backend state exposed by [`CModuleCapabilities`].
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CModuleBackend {
    /// The Apple-targeted TinyCC in-memory compiler and linker.
    TinyCc,
    /// No compiler/linker backend is built for this target.
    Unavailable,
}

#[allow(dead_code)]
impl CModuleBackend {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TinyCc => "tinycc-macho",
            Self::Unavailable => "unavailable",
        }
    }
}

/// The stable, non-optimistic CModule feature model for iOS.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CModuleCapabilities {
    pub platform: &'static str,
    pub backend: CModuleBackend,
    pub available: bool,
    pub compiler: bool,
    pub linker: bool,
    pub jit: bool,
    pub source_compilation: bool,
    pub executable_memory: bool,
    pub symbol_imports: bool,
    pub symbol_exports: bool,
    pub find_symbol_by_name: bool,
    pub metadata_disposal: bool,
    pub reason: &'static str,
}

#[allow(dead_code)]
impl CModuleCapabilities {
    /// Returns the capability snapshot used by the iOS runtime.
    pub const fn ios() -> Self {
        #[cfg(quickjs_cmodule)]
        {
            return Self {
                platform: "ios",
                backend: CModuleBackend::TinyCc,
                available: true,
                compiler: true,
                linker: true,
                jit: true,
                source_compilation: true,
                executable_memory: true,
                symbol_imports: true,
                symbol_exports: true,
                find_symbol_by_name: true,
                metadata_disposal: true,
                reason: "Apple TinyCC Mach-O in-memory compiler/linker is available",
            };
        }

        #[cfg(not(quickjs_cmodule))]
        Self {
            platform: "ios",
            backend: CModuleBackend::Unavailable,
            available: false,
            compiler: false,
            linker: false,
            jit: false,
            source_compilation: false,
            executable_memory: false,
            symbol_imports: false,
            symbol_exports: false,
            find_symbol_by_name: false,
            metadata_disposal: false,
            reason: "iOS CModule has no compiler, linker, or executable-memory backend",
        }
    }

    pub const fn backend_name(self) -> &'static str {
        self.backend.as_str()
    }

    pub const fn supports_compilation(self) -> bool {
        self.available && self.compiler && self.linker && self.source_compilation && self.executable_memory
    }
}

#[allow(dead_code)]
impl Default for CModuleCapabilities {
    fn default() -> Self {
        Self::ios()
    }
}

/// One address supplied to a CModule as an imported symbol.
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CModuleImport {
    name: String,
    address: u64,
}

#[allow(dead_code)]
impl CModuleImport {
    /// Creates and validates an imported symbol descriptor.
    pub fn new(name: impl Into<String>, address: u64) -> Result<Self, CModuleError> {
        let name = name.into();
        validate_symbol_name(&name)?;
        Ok(Self { name, address })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub const fn address(&self) -> u64 {
        self.address
    }
}

/// Validated input for a future CModule compiler backend.
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CModuleRequest {
    source: String,
    imports: Vec<CModuleImport>,
}

#[allow(dead_code)]
impl CModuleRequest {
    /// Validates source and imports without invoking a compiler.
    pub fn new<I>(source: impl Into<String>, imports: I) -> Result<Self, CModuleError>
    where
        I: IntoIterator<Item = CModuleImport>,
    {
        let source = source.into();
        validate_source(&source)?;

        let mut seen = BTreeSet::new();
        let mut imports_out = Vec::new();
        for (index, import) in imports.into_iter().enumerate() {
            if index >= MAX_IMPORTS {
                return Err(CModuleError::TooManyImports {
                    count: index + 1,
                    max: MAX_IMPORTS,
                });
            }
            validate_symbol_name(&import.name)?;
            if !seen.insert(import.name.clone()) {
                return Err(CModuleError::DuplicateImport(import.name));
            }
            imports_out.push(import);
        }

        Ok(Self {
            source,
            imports: imports_out,
        })
    }

    /// Convenience constructor for the pointer-shaped symbol map used by the
    /// Android CModule API.
    pub fn from_pairs(source: impl Into<String>, pairs: &[(&str, u64)]) -> Result<Self, CModuleError> {
        let imports = pairs
            .iter()
            .map(|(name, address)| CModuleImport::new(*name, *address))
            .collect::<Result<Vec<_>, _>>()?;
        Self::new(source, imports)
    }

    pub fn source(&self) -> &str {
        &self.source
    }

    pub fn imports(&self) -> &[CModuleImport] {
        &self.imports
    }
}

/// Result of preparing validated input for the current iOS backend.
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CModulePlan {
    request: CModuleRequest,
    capabilities: CModuleCapabilities,
}

#[allow(dead_code)]
impl CModulePlan {
    pub fn request(&self) -> &CModuleRequest {
        &self.request
    }

    pub const fn capabilities(&self) -> CModuleCapabilities {
        self.capabilities
    }

    /// Compiles and relocates the validated request on Apple builds.
    pub fn compile(self) -> Result<CModuleArtifact, CModuleError> {
        #[cfg(quickjs_cmodule)]
        {
            return Ok(CModuleArtifact {
                module: compile_request(&self.request)?,
            });
        }

        #[cfg(not(quickjs_cmodule))]
        {
            let _ = self.request;
            Err(CModuleError::BackendUnavailable {
                backend: self.capabilities.backend_name(),
                reason: self.capabilities.reason,
            })
        }
    }
}

/// A relocated CModule artifact. The allocation remains live until this value
/// is dropped, which also releases TinyCC metadata and the JIT mapping.
#[allow(dead_code)]
#[derive(Debug)]
pub struct CModuleArtifact {
    #[cfg(quickjs_cmodule)]
    module: Box<CompiledModule>,
    #[cfg(not(quickjs_cmodule))]
    _private: (),
}

impl CModuleArtifact {
    #[cfg(quickjs_cmodule)]
    pub fn base(&self) -> u64 {
        self.module.code as u64
    }

    #[cfg(quickjs_cmodule)]
    pub const fn size(&self) -> usize {
        self.module.code_size
    }

    #[cfg(quickjs_cmodule)]
    pub fn find_symbol_by_name(&self, name: &str) -> Option<u64> {
        self.module
            .symbols
            .iter()
            .find(|(symbol, _)| symbol == name)
            .map(|(_, address)| *address)
    }

    #[cfg(quickjs_cmodule)]
    fn into_module(self) -> Box<CompiledModule> {
        self.module
    }
}

#[cfg(quickjs_cmodule)]
type TccErrorFunc = unsafe extern "C" fn(*mut c_void, *const c_char);
#[cfg(quickjs_cmodule)]
type TccCppLoadFunc = unsafe extern "C" fn(*mut c_void, *const c_char, *mut c_int) -> *const c_char;
#[cfg(quickjs_cmodule)]
type TccResolveFunc = unsafe extern "C" fn(*mut c_void, *const c_char) -> *mut c_void;
#[cfg(quickjs_cmodule)]
type TccSymbolFunc = unsafe extern "C" fn(*mut c_void, *const c_char, *const c_void);

#[cfg(quickjs_cmodule)]
#[repr(C)]
struct TccState {
    _private: [u8; 0],
}

#[cfg(quickjs_cmodule)]
unsafe extern "C" {
    fn tcc_new() -> *mut TccState;
    fn tcc_delete(state: *mut TccState);
    fn tcc_set_error_func(state: *mut TccState, opaque: *mut c_void, func: Option<TccErrorFunc>);
    fn tcc_set_cpp_load_func(state: *mut TccState, opaque: *mut c_void, func: Option<TccCppLoadFunc>);
    fn tcc_set_linker_resolve_func(state: *mut TccState, opaque: *mut c_void, func: Option<TccResolveFunc>);
    fn tcc_set_options(state: *mut TccState, options: *const c_char);
    fn tcc_set_output_type(state: *mut TccState, output_type: c_int) -> c_int;
    fn tcc_add_symbol(state: *mut TccState, name: *const c_char, value: *const c_void) -> c_int;
    fn tcc_compile_string(state: *mut TccState, source: *const c_char) -> c_int;
    fn tcc_relocate(state: *mut TccState, ptr: *mut c_void) -> c_int;
    fn tcc_get_symbol(state: *mut TccState, name: *const c_char) -> *mut c_void;
    fn tcc_list_symbols(state: *mut TccState, opaque: *mut c_void, callback: Option<TccSymbolFunc>);
    fn rf_cmodule_clear_cache(start: *mut c_void, end: *mut c_void);
}

#[cfg(quickjs_cmodule)]
const TCC_OUTPUT_MEMORY: c_int = 1;
#[cfg(quickjs_cmodule)]
const CMODULE_MAP_JIT: libc::c_int = 0x800;
#[cfg(quickjs_cmodule)]
const CMODULE_CLASS_NAME: &[u8] = b"CModule\0";
#[cfg(quickjs_cmodule)]
static CMODULE_CLASS_ID: AtomicU32 = AtomicU32::new(0);

#[cfg(quickjs_cmodule)]
#[derive(Debug)]
struct CompileContext {
    errors: String,
    imports: HashMap<String, u64>,
}

#[cfg(quickjs_cmodule)]
#[derive(Debug)]
struct CompiledModule {
    state: *mut TccState,
    code: *mut c_void,
    map_size: usize,
    code_size: usize,
    symbols: Vec<(String, u64)>,
}

#[cfg(quickjs_cmodule)]
impl Drop for CompiledModule {
    fn drop(&mut self) {
        unsafe {
            if !self.state.is_null() {
                tcc_delete(self.state);
            }
            if !self.code.is_null() && self.map_size != 0 {
                libc::munmap(self.code, self.map_size);
            }
        }
    }
}

#[cfg(quickjs_cmodule)]
fn page_align_len(len: usize) -> Option<usize> {
    let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    let page = if page > 0 { page as usize } else { 4096 };
    len.checked_add(page - 1).map(|value| value & !(page - 1))
}

#[cfg(quickjs_cmodule)]
const STDINT_H: &[u8] = br#"
#ifndef _RF_STDINT_H
#define _RF_STDINT_H
typedef signed char int8_t;
typedef unsigned char uint8_t;
typedef signed short int16_t;
typedef unsigned short uint16_t;
typedef signed int int32_t;
typedef unsigned int uint32_t;
typedef signed long long int64_t;
typedef unsigned long long uint64_t;
typedef signed long intptr_t;
typedef unsigned long uintptr_t;
#endif
"#;

#[cfg(quickjs_cmodule)]
const STDDEF_H: &[u8] = br#"
#ifndef _RF_STDDEF_H
#define _RF_STDDEF_H
typedef unsigned long size_t;
typedef signed long ssize_t;
typedef signed long ptrdiff_t;
#ifndef NULL
#define NULL ((void *)0)
#endif
#endif
"#;

#[cfg(quickjs_cmodule)]
const STDBOOL_H: &[u8] = br#"
#ifndef _RF_STDBOOL_H
#define _RF_STDBOOL_H
#define bool _Bool
#define true 1
#define false 0
#endif
"#;

#[cfg(quickjs_cmodule)]
const STRING_H: &[u8] = br#"
#ifndef _RF_STRING_H
#define _RF_STRING_H
#include <stddef.h>
void *memcpy(void *dst, const void *src, size_t n);
void *memmove(void *dst, const void *src, size_t n);
void *memset(void *dst, int c, size_t n);
int memcmp(const void *a, const void *b, size_t n);
size_t strlen(const char *s);
#endif
"#;

#[cfg(quickjs_cmodule)]
const STDLIB_H: &[u8] = br#"
#ifndef _RF_STDLIB_H
#define _RF_STDLIB_H
#include <stddef.h>
void *malloc(size_t size);
void *calloc(size_t count, size_t size);
void *realloc(void *ptr, size_t size);
void free(void *ptr);
#endif
"#;

#[cfg(quickjs_cmodule)]
const RFHOOK_H: &[u8] = br#"
#ifndef _RF_HOOK_H
#define _RF_HOOK_H
#include <stdint.h>
#include <stddef.h>
typedef struct {
    uint64_t x[31];
    uint64_t sp;
    uint64_t pc;
    uint64_t nzcv;
    void *trampoline;
    uint64_t d[8];
} HookContext;
typedef HookContext RfHookContext;
typedef void (*RfHookCallback)(HookContext *ctx, void *user_data);
uint64_t hook_invoke_trampoline(HookContext *ctx, void *trampoline);
static inline uint64_t rf_arg(HookContext *ctx, unsigned index) {
    return index < 31u ? ctx->x[index] : 0;
}
static inline void *rf_arg_ptr(HookContext *ctx, unsigned index) {
    return (void *)(uintptr_t)rf_arg(ctx, index);
}
static inline void rf_set_arg(HookContext *ctx, unsigned index, uint64_t value) {
    if (index < 31u) ctx->x[index] = value;
}
static inline uint64_t rf_call_orig(HookContext *ctx) {
    uint64_t result = hook_invoke_trampoline(ctx, ctx->trampoline);
    ctx->x[0] = result;
    return result;
}
#endif
"#;

#[cfg(quickjs_cmodule)]
const PRELUDE: &str = "#include <stdint.h>\n#include <stddef.h>\n#include <stdbool.h>\n#include <string.h>\n#include <stdlib.h>\n#include <rfhook.h>\n";

#[cfg(quickjs_cmodule)]
unsafe fn header_bytes(path: *const c_char) -> Option<&'static [u8]> {
    if path.is_null() {
        return None;
    }
    let raw = CStr::from_ptr(path).to_string_lossy();
    match raw.strip_prefix("/rf/").unwrap_or(raw.as_ref()) {
        "stdint.h" => Some(STDINT_H),
        "stddef.h" => Some(STDDEF_H),
        "stdbool.h" => Some(STDBOOL_H),
        "string.h" => Some(STRING_H),
        "stdlib.h" => Some(STDLIB_H),
        "rfhook.h" => Some(RFHOOK_H),
        _ => None,
    }
}

#[cfg(quickjs_cmodule)]
unsafe extern "C" fn cpp_load(_opaque: *mut c_void, path: *const c_char, len: *mut c_int) -> *const c_char {
    match header_bytes(path) {
        Some(bytes) => {
            if !len.is_null() {
                *len = bytes.len() as c_int;
            }
            bytes.as_ptr() as *const c_char
        }
        None => ptr::null(),
    }
}

#[cfg(quickjs_cmodule)]
unsafe extern "C" fn append_error(opaque: *mut c_void, message: *const c_char) {
    if opaque.is_null() || message.is_null() {
        return;
    }
    let context = &mut *(opaque as *mut CompileContext);
    if !context.errors.is_empty() {
        context.errors.push('\n');
    }
    context.errors.push_str(&CStr::from_ptr(message).to_string_lossy());
}

#[cfg(quickjs_cmodule)]
unsafe extern "C" fn resolve_symbol(opaque: *mut c_void, name: *const c_char) -> *mut c_void {
    if name.is_null() {
        return ptr::null_mut();
    }
    let symbol = CStr::from_ptr(name).to_string_lossy();
    if !opaque.is_null() {
        let context = &mut *(opaque as *mut CompileContext);
        if let Some(address) = context.imports.get(symbol.as_ref()) {
            return *address as *mut c_void;
        }
    }
    let Ok(symbol) = CString::new(symbol.as_ref()) else {
        return ptr::null_mut();
    };
    libc::dlsym(libc::RTLD_DEFAULT, symbol.as_ptr())
}

#[cfg(quickjs_cmodule)]
unsafe extern "C" fn collect_symbol(opaque: *mut c_void, name: *const c_char, value: *const c_void) {
    if opaque.is_null() || name.is_null() || value.is_null() {
        return;
    }
    let symbols = &mut *(opaque as *mut Vec<(String, u64)>);
    let raw_name = CStr::from_ptr(name).to_string_lossy();
    if raw_name.is_empty() || raw_name.starts_with('.') || raw_name.starts_with('$') {
        return;
    }
    let name = raw_name.strip_prefix('_').unwrap_or(raw_name.as_ref());
    if !name.is_empty() {
        symbols.push((name.to_owned(), value as u64));
    }
}

#[cfg(quickjs_cmodule)]
fn compile_request(request: &CModuleRequest) -> Result<Box<CompiledModule>, CModuleError> {
    let mut context = CompileContext {
        errors: String::new(),
        imports: request
            .imports
            .iter()
            .map(|import| (import.name.clone(), import.address))
            .collect(),
    };
    let state = unsafe { tcc_new() };
    if state.is_null() {
        return Err(CModuleError::CompilationFailed("tcc_new failed".into()));
    }
    let fail = |message: String| CModuleError::CompilationFailed(message);

    unsafe {
        tcc_set_error_func(state, &mut context as *mut _ as *mut c_void, Some(append_error));
        tcc_set_cpp_load_func(state, ptr::null_mut(), Some(cpp_load));
        tcc_set_linker_resolve_func(state, &mut context as *mut _ as *mut c_void, Some(resolve_symbol));
        let options = CString::new("-Wall -Werror -isystem /rf -nostdinc -nostdlib").unwrap();
        tcc_set_options(state, options.as_ptr());
        if tcc_set_output_type(state, TCC_OUTPUT_MEMORY) < 0 {
            tcc_delete(state);
            return Err(fail("tcc_set_output_type failed".into()));
        }
        for import in &request.imports {
            let name = CString::new(import.name.as_str()).map_err(|_| CModuleError::SymbolNameContainsNul)?;
            if tcc_add_symbol(state, name.as_ptr(), import.address as *const c_void) < 0 {
                tcc_delete(state);
                return Err(fail(format!("failed to add import `{}`", import.name)));
            }
        }
        let combined = CString::new(format!(
            "#line 1 \"rf_cmodule.c\"\n{PRELUDE}\n#line 1 \"module.c\"\n{}",
            request.source
        ))
        .map_err(|_| CModuleError::SourceContainsNul)?;
        if tcc_compile_string(state, combined.as_ptr()) < 0 || !context.errors.is_empty() {
            let error = if context.errors.is_empty() {
                "unknown compiler error".into()
            } else {
                context.errors.clone()
            };
            tcc_delete(state);
            return Err(fail(error));
        }
        let required = tcc_relocate(state, ptr::null_mut());
        if required <= 0 {
            let error = if context.errors.is_empty() {
                "relocation size query failed".into()
            } else {
                context.errors.clone()
            };
            tcc_delete(state);
            return Err(CModuleError::LinkFailed(error));
        }
        let code_size = required as usize;
        let Some(map_size) = page_align_len(code_size) else {
            tcc_delete(state);
            return Err(CModuleError::LinkFailed("JIT mapping size overflow".into()));
        };
        let mapping = libc::mmap(
            ptr::null_mut(),
            map_size,
            libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
            libc::MAP_PRIVATE | libc::MAP_ANON | CMODULE_MAP_JIT,
            -1,
            0,
        );
        if mapping == libc::MAP_FAILED {
            tcc_delete(state);
            return Err(CModuleError::ExecutableMemoryFailed(
                std::io::Error::last_os_error().to_string(),
            ));
        }
        context.errors.clear();
        if tcc_relocate(state, mapping) < 0 || !context.errors.is_empty() {
            let error = if context.errors.is_empty() {
                "relocation failed".into()
            } else {
                context.errors.clone()
            };
            libc::munmap(mapping, map_size);
            tcc_delete(state);
            return Err(CModuleError::LinkFailed(error));
        }
        rf_cmodule_clear_cache(mapping, (mapping as usize + code_size) as *mut c_void);
        let mut symbols: Vec<(String, u64)> = Vec::new();
        tcc_list_symbols(state, &mut symbols as *mut _ as *mut c_void, Some(collect_symbol));
        symbols.sort_by(|left, right| left.0.cmp(&right.0));
        symbols.dedup_by(|left, right| left.0 == right.0);
        for (name, address) in &mut symbols {
            if let Ok(name) = CString::new(name.as_str()) {
                let resolved = tcc_get_symbol(state, name.as_ptr());
                if !resolved.is_null() {
                    *address = resolved as u64;
                }
            }
        }
        Ok(Box::new(CompiledModule {
            state,
            code: mapping,
            map_size,
            code_size,
            symbols,
        }))
    }
}

/// Validates input and creates a backend-specific compilation plan.
#[allow(dead_code)]
pub fn prepare(source: impl Into<String>, imports: &[(&str, u64)]) -> Result<CModulePlan, CModuleError> {
    let request = CModuleRequest::from_pairs(source, imports)?;
    Ok(CModulePlan {
        request,
        capabilities: CModuleCapabilities::ios(),
    })
}

/// Validates a request and enters the current backend boundary.
#[allow(dead_code)]
pub fn compile(source: impl Into<String>, imports: &[(&str, u64)]) -> Result<CModuleArtifact, CModuleError> {
    prepare(source, imports)?.compile()
}

/// Performs host compiler diagnostics without entering the iOS CModule
/// backend. This is intentionally separate from [`compile`]: a successful
/// result only means that the source parses on the host compiler.
#[allow(dead_code)]
pub fn host_preflight(source: impl Into<String>, imports: &[(&str, u64)]) -> Result<HostCompileReport, CModuleError> {
    let request = CModuleRequest::from_pairs(source, imports)?;
    let adapter = HostCompilerAdapter::detect().ok_or_else(|| CModuleError::HostCompilerUnavailable {
        compiler: "auto-detect".into(),
        reason: "no host C compiler was found".into(),
    })?;
    adapter.check_syntax(&request)
}

/// Returns the iOS CModule capability snapshot without touching QuickJS.
#[allow(dead_code)]
pub const fn capabilities() -> CModuleCapabilities {
    CModuleCapabilities::ios()
}

unsafe fn capabilities_to_js(ctx: *mut ffi::JSContext) -> ffi::JSValue {
    let capabilities = capabilities();
    let result = JSValue(ffi::JS_NewObject(ctx));
    result.set_property(ctx, "platform", JSValue::string(ctx, capabilities.platform));
    result.set_property(ctx, "backend", JSValue::string(ctx, capabilities.backend_name()));
    result.set_property(ctx, "available", JSValue::bool(capabilities.available));
    result.set_property(ctx, "compiler", JSValue::bool(capabilities.compiler));
    result.set_property(ctx, "linker", JSValue::bool(capabilities.linker));
    result.set_property(ctx, "jit", JSValue::bool(capabilities.jit));
    result.set_property(
        ctx,
        "compilationSupported",
        JSValue::bool(capabilities.supports_compilation()),
    );
    result.set_property(ctx, "sourceCompilation", JSValue::bool(capabilities.source_compilation));
    result.set_property(ctx, "executableMemory", JSValue::bool(capabilities.executable_memory));
    result.set_property(ctx, "symbolImports", JSValue::bool(capabilities.symbol_imports));
    result.set_property(ctx, "symbolExports", JSValue::bool(capabilities.symbol_exports));
    result.set_property(ctx, "findSymbolByName", JSValue::bool(capabilities.find_symbol_by_name));
    result.set_property(ctx, "metadataDisposal", JSValue::bool(capabilities.metadata_disposal));
    result.set_property(ctx, "reason", JSValue::string(ctx, capabilities.reason));
    result.raw()
}

unsafe extern "C" fn js_cmodule_capabilities(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    capabilities_to_js(ctx)
}

#[cfg(quickjs_cmodule)]
unsafe extern "C" fn cmodule_finalizer(_runtime: *mut ffi::JSRuntime, value: ffi::JSValue) {
    let class_id = CMODULE_CLASS_ID.load(Ordering::Relaxed);
    if class_id == 0 {
        return;
    }
    let opaque = ffi::JS_GetOpaque(value, class_id);
    if !opaque.is_null() {
        drop(Box::from_raw(opaque as *mut CompiledModule));
    }
}

#[cfg(quickjs_cmodule)]
unsafe fn cmodule_class_id(ctx: *mut ffi::JSContext) -> Result<u32, &'static str> {
    let mut class_id = CMODULE_CLASS_ID.load(Ordering::Acquire);
    if class_id == 0 {
        let mut candidate = 0;
        candidate = ffi::JS_NewClassID(&mut candidate);
        class_id = match CMODULE_CLASS_ID.compare_exchange(0, candidate, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => candidate,
            Err(existing) => existing,
        };
    }
    let runtime = ffi::JS_GetRuntime(ctx);
    if ffi::JS_IsRegisteredClass(runtime, class_id) == 0 {
        let class_def = ffi::JSClassDef {
            class_name: CMODULE_CLASS_NAME.as_ptr() as *const _,
            finalizer: Some(cmodule_finalizer),
            gc_mark: None,
            call: None,
            exotic: ptr::null_mut(),
        };
        if ffi::JS_NewClass(runtime, class_id, &class_def) != 0 {
            return Err("failed to register QuickJS CModule class");
        }
    }
    Ok(class_id)
}

#[cfg(quickjs_cmodule)]
unsafe extern "C" fn cmodule_find_symbol(
    ctx: *mut ffi::JSContext,
    this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 1 {
        return js_throw_type_error(ctx, "findSymbolByName(name) requires a name");
    }
    let class_id = CMODULE_CLASS_ID.load(Ordering::Acquire);
    let opaque = ffi::JS_GetOpaque(this, class_id);
    if opaque.is_null() {
        return js_throw_type_error(ctx, "CModule receiver is invalid");
    }
    let Some(name) = JSValue(*argv).to_string(ctx) else {
        return js_throw_type_error(ctx, "symbol name must be a string");
    };
    let module = &*(opaque as *const CompiledModule);
    match module
        .symbols
        .iter()
        .find(|(symbol, _)| symbol == &name)
        .map(|(_, address)| *address)
    {
        Some(address) => create_native_pointer(ctx, address).raw(),
        None => JSValue::null().raw(),
    }
}

#[cfg(quickjs_cmodule)]
unsafe extern "C" fn cmodule_drop_metadata(
    ctx: *mut ffi::JSContext,
    this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let class_id = CMODULE_CLASS_ID.load(Ordering::Acquire);
    let opaque = ffi::JS_GetOpaque(this, class_id);
    if opaque.is_null() {
        return js_throw_type_error(ctx, "CModule receiver is invalid");
    }
    let module = &mut *(opaque as *mut CompiledModule);
    if !module.state.is_null() {
        tcc_delete(module.state);
        module.state = ptr::null_mut();
    }
    JSValue::undefined().raw()
}

#[cfg(quickjs_cmodule)]
unsafe fn compiled_module_to_js(ctx: *mut ffi::JSContext, module: Box<CompiledModule>) -> ffi::JSValue {
    let class_id = match cmodule_class_id(ctx) {
        Ok(class_id) => class_id,
        Err(error) => return js_throw_internal_error(ctx, error),
    };
    let value = ffi::JS_NewObjectClass(ctx, class_id as i32);
    if ffi::qjs_is_exception(value) != 0 {
        return value;
    }
    let raw = Box::into_raw(module);
    let module = &*raw;
    ffi::JS_SetOpaque(value, raw as *mut c_void);
    for (name, address) in &module.symbols {
        JSValue(value).set_property(ctx, name, create_native_pointer(ctx, *address));
    }
    JSValue(value).set_property(ctx, "base", create_native_pointer(ctx, module.code as u64));
    JSValue(value).set_property(
        ctx,
        "size",
        JSValue::int(module.code_size.min(i32::MAX as usize) as i32),
    );
    add_cfunction_to_object(ctx, value, "findSymbolByName", cmodule_find_symbol, 1);
    add_cfunction_to_object(ctx, value, "dropMetadata", cmodule_drop_metadata, 0);
    value
}

unsafe fn js_array_length(ctx: *mut ffi::JSContext, value: JSValue, usage: &str) -> Result<usize, ffi::JSValue> {
    if ffi::JS_IsArray(ctx, value.raw()) != 1 {
        return Err(js_throw_type_error(ctx, usage));
    }
    let length = value.get_property(ctx, "length");
    let parsed = length.to_u64(ctx).and_then(|length| usize::try_from(length).ok());
    length.free(ctx);
    parsed.ok_or_else(|| js_throw_type_error(ctx, usage))
}

unsafe fn js_import_address(ctx: *mut ffi::JSContext, value: JSValue, index: usize) -> Result<u64, ffi::JSValue> {
    if let Some(address) = get_native_pointer_addr(value) {
        return Ok(address);
    }
    if value.is_int() || value.is_float() || ffi::qjs_is_big_int(ctx, value.raw()) != 0 {
        let mut address = 0u64;
        if ffi::qjs_value_to_u64(ctx, &mut address, value.raw()) == 0 {
            return Ok(address);
        }
    }
    Err(js_throw_type_error(
        ctx,
        &format!("CModule import {index} address must be a NativePointer, integer Number, or BigInt"),
    ))
}

unsafe extern "C" fn js_cmodule_compile(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc != 2 || !JSValue(*argv).is_string() {
        return js_throw_type_error(ctx, "CModule source must be a string");
    }
    let Some(source) = JSValue(*argv).to_string(ctx) else {
        return js_throw_type_error(ctx, "CModule source must be a string");
    };
    let entries = JSValue(*argv.add(1));
    let count = match js_array_length(ctx, entries, "CModule symbols must be an object") {
        Ok(count) => count,
        Err(error) => return error,
    };
    if count > MAX_IMPORTS {
        return js_throw_type_error(ctx, &format!("CModule has {count} imports; maximum is {MAX_IMPORTS}"));
    }

    let mut imports = Vec::with_capacity(count);
    for index in 0..count {
        let pair = JSValue(ffi::JS_GetPropertyUint32(ctx, entries.raw(), index as u32));
        match js_array_length(ctx, pair, "CModule symbol entries must be [name, address] pairs") {
            Ok(2) => {}
            Ok(_) => {
                pair.free(ctx);
                return js_throw_type_error(ctx, "CModule symbol entries must be [name, address] pairs");
            }
            Err(error) => {
                pair.free(ctx);
                return error;
            }
        }
        let name = JSValue(ffi::JS_GetPropertyUint32(ctx, pair.raw(), 0));
        let address = JSValue(ffi::JS_GetPropertyUint32(ctx, pair.raw(), 1));
        let parsed = if !name.is_string() {
            Err(js_throw_type_error(ctx, "CModule import names must be strings"))
        } else if let Some(name) = name.to_string(ctx) {
            js_import_address(ctx, address, index).map(|address| (name, address))
        } else {
            Err(js_throw_type_error(ctx, "CModule import names must be strings"))
        };
        name.free(ctx);
        address.free(ctx);
        pair.free(ctx);
        match parsed {
            Ok(import) => imports.push(import),
            Err(error) => return error,
        }
    }

    let import_pairs = imports
        .iter()
        .map(|(name, address)| (name.as_str(), *address))
        .collect::<Vec<_>>();
    match compile(source, &import_pairs) {
        Ok(artifact) => {
            #[cfg(quickjs_cmodule)]
            {
                return compiled_module_to_js(ctx, artifact.into_module());
            }
            #[cfg(not(quickjs_cmodule))]
            {
                let _ = artifact;
                js_throw_internal_error(ctx, "CModule compiler returned an artifact without a load backend")
            }
        }
        Err(error) if error.code() == "backend-unavailable" => js_throw_internal_error(ctx, &error.to_string()),
        Err(error) => js_throw_type_error(ctx, &error.to_string()),
    }
}

pub(crate) fn register_cmodule_api(ctx: &JSContext) -> Result<(), String> {
    let global = ctx.global_object();
    unsafe {
        add_cfunction_to_object(
            ctx.as_ptr(),
            global.raw(),
            "__iosCModuleCapabilities",
            js_cmodule_capabilities,
            0,
        );
        add_cfunction_to_object(ctx.as_ptr(), global.raw(), "__iosCModuleCompile", js_cmodule_compile, 2);
    }
    global.free(ctx.as_ptr());
    let value = ctx.eval(CMODULE_BOOTSTRAP, "<cmodule-bootstrap>")?;
    value.free(ctx.as_ptr());
    Ok(())
}

fn validate_source(source: &str) -> Result<(), CModuleError> {
    if source.trim().is_empty() {
        return Err(CModuleError::EmptySource);
    }
    if source.len() > MAX_SOURCE_BYTES {
        return Err(CModuleError::SourceTooLarge {
            size: source.len(),
            max: MAX_SOURCE_BYTES,
        });
    }
    if source.as_bytes().contains(&0) {
        return Err(CModuleError::SourceContainsNul);
    }
    Ok(())
}

fn validate_symbol_name(name: &str) -> Result<(), CModuleError> {
    if name.is_empty() {
        return Err(CModuleError::EmptySymbolName);
    }
    if name.len() > MAX_SYMBOL_NAME_BYTES {
        return Err(CModuleError::SymbolNameTooLong {
            size: name.len(),
            max: MAX_SYMBOL_NAME_BYTES,
        });
    }
    if name.as_bytes().contains(&0) {
        return Err(CModuleError::SymbolNameContainsNul);
    }
    Ok(())
}

/// Errors produced before a compiler backend is entered, or at its boundary.
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CModuleError {
    EmptySource,
    SourceContainsNul,
    SourceTooLarge {
        size: usize,
        max: usize,
    },
    EmptySymbolName,
    SymbolNameContainsNul,
    SymbolNameTooLong {
        size: usize,
        max: usize,
    },
    DuplicateImport(String),
    TooManyImports {
        count: usize,
        max: usize,
    },
    BackendUnavailable {
        backend: &'static str,
        reason: &'static str,
    },
    HostCompilerUnavailable {
        compiler: String,
        reason: String,
    },
    HostCompilationFailed {
        compiler: String,
        diagnostics: String,
    },
    CompilationFailed(String),
    LinkFailed(String),
    ExecutableMemoryFailed(String),
}

impl CModuleError {
    pub const fn code(&self) -> &'static str {
        match self {
            Self::EmptySource => "empty-source",
            Self::SourceContainsNul => "source-nul",
            Self::SourceTooLarge { .. } => "source-too-large",
            Self::EmptySymbolName => "empty-symbol-name",
            Self::SymbolNameContainsNul => "symbol-nul",
            Self::SymbolNameTooLong { .. } => "symbol-too-long",
            Self::DuplicateImport(_) => "duplicate-import",
            Self::TooManyImports { .. } => "too-many-imports",
            Self::BackendUnavailable { .. } => "backend-unavailable",
            Self::HostCompilerUnavailable { .. } => "host-compiler-unavailable",
            Self::HostCompilationFailed { .. } => "host-compilation-failed",
            Self::CompilationFailed(_) => "compilation-failed",
            Self::LinkFailed(_) => "link-failed",
            Self::ExecutableMemoryFailed(_) => "executable-memory-failed",
        }
    }
}

impl fmt::Display for CModuleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptySource => f.write_str("CModule source must contain non-whitespace text"),
            Self::SourceContainsNul => f.write_str("CModule source contains a NUL byte"),
            Self::SourceTooLarge { size, max } => {
                write!(f, "CModule source is {size} bytes; maximum is {max} bytes")
            }
            Self::EmptySymbolName => f.write_str("CModule import name must not be empty"),
            Self::SymbolNameContainsNul => f.write_str("CModule import name contains a NUL byte"),
            Self::SymbolNameTooLong { size, max } => {
                write!(f, "CModule import name is {size} bytes; maximum is {max} bytes")
            }
            Self::DuplicateImport(name) => write!(f, "CModule import name is duplicated: {name}"),
            Self::TooManyImports { count, max } => {
                write!(f, "CModule has {count} imports; maximum is {max}")
            }
            Self::BackendUnavailable { backend, reason } => {
                write!(f, "CModule backend `{backend}` is unavailable: {reason}")
            }
            Self::HostCompilerUnavailable { compiler, reason } => {
                write!(f, "CModule host compiler `{compiler}` is unavailable: {reason}")
            }
            Self::HostCompilationFailed { compiler, diagnostics } => write!(
                f,
                "CModule host compiler `{compiler}` rejected the source: {diagnostics}"
            ),
            Self::CompilationFailed(reason) => write!(f, "CModule compilation failed: {reason}"),
            Self::LinkFailed(reason) => write!(f, "CModule linking failed: {reason}"),
            Self::ExecutableMemoryFailed(reason) => {
                write!(f, "CModule executable memory allocation failed: {reason}")
            }
        }
    }
}

impl Error for CModuleError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ptr::register_ptr;
    use crate::runtime::JSRuntime;

    #[cfg(not(quickjs_cmodule))]
    #[test]
    fn ios_capabilities_are_explicitly_unavailable() {
        let caps = capabilities();
        assert_eq!(caps.platform, "ios");
        assert_eq!(caps.backend, CModuleBackend::Unavailable);
        assert!(!caps.available);
        assert!(!caps.supports_compilation());
        assert!(!caps.compiler);
        assert!(!caps.linker);
        assert!(!caps.jit);
        assert!(!caps.source_compilation);
        assert!(!caps.executable_memory);
        assert!(!caps.symbol_imports);
        assert!(!caps.symbol_exports);
        assert!(!caps.find_symbol_by_name);
        assert!(!caps.metadata_disposal);
        assert_eq!(caps.backend_name(), "unavailable");
    }

    #[cfg(quickjs_cmodule)]
    #[test]
    fn ios_capabilities_report_tinycc_backend() {
        let caps = capabilities();
        assert_eq!(caps.platform, "ios");
        assert_eq!(caps.backend, CModuleBackend::TinyCc);
        assert_eq!(caps.backend_name(), "tinycc-macho");
        assert!(caps.available);
        assert!(caps.supports_compilation());
        assert!(caps.symbol_imports);
        assert!(caps.symbol_exports);
        assert!(caps.find_symbol_by_name);
        assert!(caps.metadata_disposal);
    }

    #[test]
    fn valid_request_preserves_source_and_imports() {
        let request = CModuleRequest::from_pairs("int answer(void) { return 42; }", &[("host_fn", 0x1234)])
            .expect("valid request");
        assert_eq!(request.source, "int answer(void) { return 42; }");
        assert_eq!(request.source.len(), 31);
        assert_eq!(request.imports.len(), 1);
        assert_eq!(request.imports[0].name, "host_fn");
        assert_eq!(request.imports[0].address, 0x1234);
    }

    #[test]
    fn validation_rejects_empty_and_nul_source() {
        assert_eq!(
            CModuleRequest::from_pairs(" \n\t", &[]).unwrap_err().code(),
            "empty-source"
        );
        assert_eq!(
            CModuleRequest::from_pairs("return\0value", &[]).unwrap_err().code(),
            "source-nul"
        );
    }

    #[test]
    fn validation_rejects_oversized_source_and_symbol_names() {
        let source = "x".repeat(MAX_SOURCE_BYTES + 1);
        assert!(matches!(
            CModuleRequest::from_pairs(source, &[]),
            Err(CModuleError::SourceTooLarge { .. })
        ));

        let name = "x".repeat(MAX_SYMBOL_NAME_BYTES + 1);
        assert!(matches!(
            CModuleImport::new(name, 1),
            Err(CModuleError::SymbolNameTooLong { .. })
        ));
        assert_eq!(CModuleImport::new("a\0b", 1).unwrap_err().code(), "symbol-nul");
        assert_eq!(CModuleImport::new("", 1).unwrap_err().code(), "empty-symbol-name");
    }

    #[test]
    fn validation_rejects_duplicate_and_excessive_imports() {
        let duplicate = CModuleRequest::from_pairs("int main;", &[("same", 1), ("same", 2)]).unwrap_err();
        assert_eq!(duplicate.code(), "duplicate-import");

        let imports = (0..=MAX_IMPORTS)
            .map(|index| CModuleImport::new(format!("symbol_{index}"), index as u64).unwrap())
            .collect::<Vec<_>>();
        let error = CModuleRequest::new("int main;", imports).unwrap_err();
        assert!(matches!(error, CModuleError::TooManyImports { .. }));
    }

    #[cfg(not(quickjs_cmodule))]
    #[test]
    fn compile_validates_before_reporting_backend_boundary() {
        let invalid = prepare("", &[]).unwrap_err();
        assert_eq!(invalid.code(), "empty-source");

        let plan = prepare("int answer(void) { return 42; }", &[]).expect("validated plan");
        assert_eq!(plan.capabilities.backend_name(), "unavailable");
        let error = plan.compile().unwrap_err();
        assert_eq!(error.code(), "backend-unavailable");
        assert!(error.to_string().contains("compiler"));
        assert_eq!(compile("int answer;", &[]).unwrap_err().code(), "backend-unavailable");
    }

    #[cfg(quickjs_cmodule)]
    extern "C" fn host_increment(value: i32) -> i32 {
        value + 1
    }

    #[cfg(quickjs_cmodule)]
    #[test]
    fn tinycc_compiles_exports_and_releases_the_mapping() {
        let artifact = compile(
            "extern int host_increment(int value); int answer(void) { return host_increment(41); }",
            &[("host_increment", host_increment as *const () as usize as u64)],
        )
        .expect("compile CModule");
        assert_ne!(artifact.base(), 0);
        assert!(artifact.size() > 0);
        let address = artifact.find_symbol_by_name("answer").expect("answer export");
        let answer: unsafe extern "C" fn() -> i32 = unsafe { std::mem::transmute(address as usize) };
        assert_eq!(unsafe { answer() }, 42);
        drop(artifact);
    }

    #[cfg(not(quickjs_cmodule))]
    #[test]
    fn quickjs_surface_validates_then_reports_backend_boundary() {
        let runtime = JSRuntime::new().expect("create runtime");
        let context = runtime.new_context().expect("create context");
        register_ptr(&context);
        register_cmodule_api(&context).expect("register CModule");

        let value = context
            .eval(
                "CModule.available === false && CModule.capabilities().compiler === false && CModule.status().backend === 'unavailable'",
                "<cmodule-test>",
            )
            .expect("query capabilities");
        assert_eq!(value.to_bool(), Some(true));
        value.free(context.as_ptr());

        let error = match context.eval(
            "new CModule('int answer;', { host_fn: ptr('0x1234') })",
            "<cmodule-test>",
        ) {
            Ok(value) => {
                value.free(context.as_ptr());
                panic!("CModule construction unexpectedly succeeded");
            }
            Err(error) => error,
        };
        assert!(error.contains("no compiler"));
    }

    #[cfg(quickjs_cmodule)]
    #[test]
    fn quickjs_surface_constructs_a_tinycc_module() {
        let runtime = JSRuntime::new().expect("create runtime");
        let context = runtime.new_context().expect("create context");
        register_ptr(&context);
        register_cmodule_api(&context).expect("register CModule");

        let value = context
            .eval(
                "const m = new CModule('int answer(void) { return 42; }'); CModule.available && String(m.findSymbolByName('answer')) === String(m.answer)",
                "<cmodule-test>",
            )
            .expect("compile CModule from QuickJS");
        assert_eq!(value.to_bool(), Some(true));
        value.free(context.as_ptr());
    }
}
