//! Dynamic execution boundary for hook backends that are already loaded.
//!
//! Symbol resolution is intentionally image-scoped and uses `RTLD_NOLOAD` on
//! Apple targets. A backend operation is executable only when its exact public
//! C ABI symbol was resolved from that loaded image. Calls are not
//! transactional: native failures and missing trampoline results may follow a
//! partial install, so those errors expose an explicit uncertain-state marker.

#![cfg_attr(not(native_api_apple_hook_backend), allow(dead_code))]

use std::ffi::c_void;
use std::fmt;
use std::ptr::NonNull;
use std::sync::atomic::{AtomicU64, Ordering};

#[cfg(native_api_apple_hook_backend)]
use std::ffi::{CStr, CString};
#[cfg(native_api_apple_hook_backend)]
use std::sync::Arc;

pub const ELLEKIT_ABI_SOURCE: &str = "https://github.com/opa334/ElleKit/blob/4825b072168d06d04cad2a4dd6b62b9c9322a0c0/ellekit/Languages/C/Hook.swift#L27";
pub const SUBSTRATE_ABI_SOURCE: &str =
    "https://github.com/comex/substitute/blob/95f2beda374625dd503bfb51a758b6f6ced57887/substrate/substrate.h#L80";
pub const SUBSTITUTE_ABI_SOURCE: &str =
    "https://github.com/comex/substitute/blob/95f2beda374625dd503bfb51a758b6f6ced57887/lib/substitute.h#L89-L154";
pub const LIBHOOKER_ABI_SOURCE: &str = "https://github.com/coolstar/libhooker/blob/4f85a68daebaf7456c66e1f55184dca118022397/libhooker/include/libhooker.h#L188-L248";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ExternalHookBackendKind {
    ElleKit,
    Substrate,
    Substitute,
    Libhooker,
    Unknown,
}

impl ExternalHookBackendKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ElleKit => "ellekit",
            Self::Substrate => "substrate",
            Self::Substitute => "substitute",
            Self::Libhooker => "libhooker",
            Self::Unknown => "unknown",
        }
    }

    pub const fn is_known(self) -> bool {
        !matches!(self, Self::Unknown)
    }
}

/// Conservatively classify an image path or backend id.
///
/// Matching is performed on the final image component instead of substring
/// matches so loaders and unrelated images remain `Unknown`.
pub fn parse_backend_image(value: &str) -> ExternalHookBackendKind {
    let component = value
        .trim()
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase();
    let component = [".dylib", ".framework", ".bundle"]
        .iter()
        .find_map(|suffix| component.strip_suffix(suffix))
        .unwrap_or(&component);
    let component = component.strip_prefix("lib").unwrap_or(component);

    match component {
        "ellekit" => ExternalHookBackendKind::ElleKit,
        "substrate" | "cydia-substrate" | "cydiasubstrate" | "mobile-substrate" | "mobilesubstrate" => {
            ExternalHookBackendKind::Substrate
        }
        "substitute" => ExternalHookBackendKind::Substitute,
        "hooker" => ExternalHookBackendKind::Libhooker,
        _ => ExternalHookBackendKind::Unknown,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ExternalHookOperation {
    Install,
    Replace,
    Uninstall,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CapabilityProbeState {
    Resolved,
    ImageNotLoaded,
    ImageHandleUnavailable,
    SymbolMissing,
    PublicAbiUnavailable,
    UnknownBackend,
    PlatformUnavailable,
}

impl CapabilityProbeState {
    pub const fn executable(self) -> bool {
        matches!(self, Self::Resolved)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperationCapabilityProbe {
    pub operation: ExternalHookOperation,
    pub required_symbol: Option<&'static str>,
    pub state: CapabilityProbeState,
    pub executable: bool,
}

impl OperationCapabilityProbe {
    fn new(
        operation: ExternalHookOperation,
        required_symbol: Option<&'static str>,
        state: CapabilityProbeState,
    ) -> Self {
        Self {
            operation,
            required_symbol,
            state,
            executable: state.executable(),
        }
    }

    pub const fn executable_now(&self) -> bool {
        self.executable && self.state.executable()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedSymbolProbe {
    pub name: &'static str,
    pub address: Option<usize>,
    pub abi_source: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HookBackendCapabilityProbe {
    pub install: OperationCapabilityProbe,
    pub replace: OperationCapabilityProbe,
    pub uninstall: OperationCapabilityProbe,
}

impl HookBackendCapabilityProbe {
    pub fn for_operation(&self, operation: ExternalHookOperation) -> &OperationCapabilityProbe {
        match operation {
            ExternalHookOperation::Install => &self.install,
            ExternalHookOperation::Replace => &self.replace,
            ExternalHookOperation::Uninstall => &self.uninstall,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HookBackendProbe {
    pub backend: ExternalHookBackendKind,
    pub image_name: String,
    pub loaded: bool,
    pub image_handle_opened: bool,
    pub symbols: Vec<ResolvedSymbolProbe>,
    pub capabilities: HookBackendCapabilityProbe,
}

impl HookBackendProbe {
    pub fn executable(&self, operation: ExternalHookOperation) -> bool {
        self.loaded && self.image_handle_opened && self.capabilities.for_operation(operation).executable_now()
    }

    pub fn public_uninstall_available(&self) -> bool {
        self.executable(ExternalHookOperation::Uninstall)
    }
}

#[derive(Debug, Clone, Copy)]
struct HookSymbolSpec {
    name: &'static str,
    abi_source: &'static str,
}

const ELLEKIT_HOOK: HookSymbolSpec = HookSymbolSpec {
    name: "EKHookFunction",
    abi_source: ELLEKIT_ABI_SOURCE,
};
const SUBSTRATE_HOOK: HookSymbolSpec = HookSymbolSpec {
    name: "MSHookFunction",
    abi_source: SUBSTRATE_ABI_SOURCE,
};
const SUBSTITUTE_HOOK: HookSymbolSpec = HookSymbolSpec {
    name: "substitute_hook_functions",
    abi_source: SUBSTITUTE_ABI_SOURCE,
};
const LIBHOOKER_HOOK: HookSymbolSpec = HookSymbolSpec {
    name: "LHHookFunctions",
    abi_source: LIBHOOKER_ABI_SOURCE,
};

const fn hook_symbol_spec(backend: ExternalHookBackendKind) -> Option<HookSymbolSpec> {
    match backend {
        ExternalHookBackendKind::ElleKit => Some(ELLEKIT_HOOK),
        ExternalHookBackendKind::Substrate => Some(SUBSTRATE_HOOK),
        ExternalHookBackendKind::Substitute => Some(SUBSTITUTE_HOOK),
        ExternalHookBackendKind::Libhooker => Some(LIBHOOKER_HOOK),
        ExternalHookBackendKind::Unknown => None,
    }
}

fn probe_with_lookup<F>(
    backend: ExternalHookBackendKind,
    image_name: impl Into<String>,
    loaded: bool,
    image_handle_opened: bool,
    mut lookup: F,
) -> HookBackendProbe
where
    F: FnMut(&'static str) -> Option<usize>,
{
    let image_name = image_name.into();
    let Some(spec) = hook_symbol_spec(backend) else {
        let capability =
            |operation| OperationCapabilityProbe::new(operation, None, CapabilityProbeState::UnknownBackend);
        return HookBackendProbe {
            backend,
            image_name,
            loaded,
            image_handle_opened,
            symbols: Vec::new(),
            capabilities: HookBackendCapabilityProbe {
                install: capability(ExternalHookOperation::Install),
                replace: capability(ExternalHookOperation::Replace),
                uninstall: capability(ExternalHookOperation::Uninstall),
            },
        };
    };

    let address = (loaded && image_handle_opened).then(|| lookup(spec.name)).flatten();
    let state = if !loaded {
        CapabilityProbeState::ImageNotLoaded
    } else if !image_handle_opened {
        CapabilityProbeState::ImageHandleUnavailable
    } else if address.is_some() {
        CapabilityProbeState::Resolved
    } else {
        CapabilityProbeState::SymbolMissing
    };

    HookBackendProbe {
        backend,
        image_name,
        loaded,
        image_handle_opened,
        symbols: vec![ResolvedSymbolProbe {
            name: spec.name,
            address,
            abi_source: spec.abi_source,
        }],
        capabilities: HookBackendCapabilityProbe {
            install: OperationCapabilityProbe::new(ExternalHookOperation::Install, Some(spec.name), state),
            replace: OperationCapabilityProbe::new(ExternalHookOperation::Replace, Some(spec.name), state),
            uninstall: OperationCapabilityProbe::new(
                ExternalHookOperation::Uninstall,
                None,
                CapabilityProbeState::PublicAbiUnavailable,
            ),
        },
    }
}

/// Build a deterministic probe from a synthetic or previously captured symbol
/// table. This is the host-test boundary for the Apple resolver.
fn probe_backend_from_symbols(
    backend: ExternalHookBackendKind,
    image_name: impl Into<String>,
    loaded: bool,
    image_handle_opened: bool,
    symbols: &[(&str, usize)],
) -> HookBackendProbe {
    probe_with_lookup(backend, image_name, loaded, image_handle_opened, |name| {
        symbols
            .iter()
            .find_map(|(candidate, address)| (*candidate == name && *address != 0).then_some(*address))
    })
}

/// C ABI: `void *EKHookFunction(void *, void *, _Bool)`.
pub type ElleKitHookFunction = unsafe extern "C" fn(*mut c_void, *mut c_void, bool) -> *mut c_void;

/// C ABI: `void MSHookFunction(void *, void *, void **)`.
pub type SubstrateHookFunction = unsafe extern "C" fn(*mut c_void, *mut c_void, *mut *mut c_void);

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SubstituteFunctionHook {
    pub function: *mut c_void,
    pub replacement: *mut c_void,
    pub old_ptr: *mut *mut c_void,
    pub options: libc::c_int,
}

/// C ABI from `substitute.h`; the opaque record is represented as `c_void`.
pub type SubstituteHookFunctions =
    unsafe extern "C" fn(*const SubstituteFunctionHook, usize, *mut *mut c_void, libc::c_int) -> libc::c_int;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct LibhookerFunctionHookOptions {
    pub options: libc::c_int,
    pub jmp_reg: libc::c_int,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct LibhookerFunctionHook {
    pub function: *mut c_void,
    pub replacement: *mut c_void,
    pub oldptr: *mut *mut c_void,
    pub options: *mut LibhookerFunctionHookOptions,
}

/// C ABI: `int LHHookFunctions(const struct LHFunctionHook *, int)`.
pub type LibhookerHookFunctions = unsafe extern "C" fn(*const LibhookerFunctionHook, libc::c_int) -> libc::c_int;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HookBackendFfiError {
    PlatformUnavailable,
    ImageNotLoaded(String),
    UnknownBackend(String),
    ImageHandleUnavailable(String),
    SymbolUnavailable {
        backend: ExternalHookBackendKind,
        symbol: &'static str,
    },
    CapabilityUnavailable {
        backend: ExternalHookBackendKind,
        operation: ExternalHookOperation,
    },
    HandleBackendMismatch {
        token: u64,
        handle_backend: ExternalHookBackendKind,
        resolver_backend: ExternalHookBackendKind,
    },
    NativeUninstallUnavailable {
        backend: ExternalHookBackendKind,
        token: u64,
    },
    HandleReleased {
        token: u64,
    },
    NullTarget,
    NullReplacement,
    OriginalUnavailable {
        backend: ExternalHookBackendKind,
        operation: ExternalHookOperation,
    },
    NativeCallFailed {
        backend: ExternalHookBackendKind,
        code: libc::c_int,
    },
}

impl fmt::Display for HookBackendFfiError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PlatformUnavailable => {
                formatter.write_str("external hook backend FFI is only active on Apple targets")
            }
            Self::ImageNotLoaded(image) => write!(formatter, "hook backend image is not loaded: {image}"),
            Self::UnknownBackend(image) => write!(formatter, "hook backend image is not recognized: {image}"),
            Self::ImageHandleUnavailable(image) => {
                write!(
                    formatter,
                    "loaded hook backend image has no RTLD_NOLOAD handle: {image}"
                )
            }
            Self::SymbolUnavailable { backend, symbol } => {
                write!(
                    formatter,
                    "{} hook backend symbol is unresolved: {symbol}",
                    backend.as_str()
                )
            }
            Self::CapabilityUnavailable { backend, operation } => {
                write!(
                    formatter,
                    "{} backend has no resolved public ABI for {operation:?}",
                    backend.as_str()
                )
            }
            Self::HandleBackendMismatch {
                token,
                handle_backend,
                resolver_backend,
            } => write!(
                formatter,
                "hook token {token} belongs to {}, not resolver {}",
                handle_backend.as_str(),
                resolver_backend.as_str()
            ),
            Self::NativeUninstallUnavailable { backend, token } => write!(
                formatter,
                "{} backend exposes no public native uninstall ABI for hook token {token}; the target remains installed and handle ownership is unchanged",
                backend.as_str()
            ),
            Self::HandleReleased { token } => write!(
                formatter,
                "hook token {token} was already released; no native uninstall was performed"
            ),
            Self::NullTarget => formatter.write_str("hook target pointer is null"),
            Self::NullReplacement => formatter.write_str("hook replacement pointer is null"),
            Self::OriginalUnavailable { backend, operation } => write!(
                formatter,
                "{} backend returned no original trampoline for {operation:?}; the operation may already be applied",
                backend.as_str()
            ),
            Self::NativeCallFailed { backend, code } => {
                write!(formatter, "{} backend call returned {code}", backend.as_str())
            }
        }
    }
}

impl std::error::Error for HookBackendFfiError {}

impl HookBackendFfiError {
    /// Whether the backend may have modified the target before returning this
    /// error. Callers should reconcile hook state before retrying these cases.
    pub const fn target_state_uncertain(&self) -> bool {
        matches!(self, Self::OriginalUnavailable { .. } | Self::NativeCallFailed { .. })
    }
}

static NEXT_HOOK_TOKEN: AtomicU64 = AtomicU64::new(1);

fn allocate_hook_token() -> u64 {
    NEXT_HOOK_TOKEN
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |token| token.checked_add(1))
        .expect("external hook token space exhausted")
}

#[derive(Debug)]
pub struct HookExecutionResult {
    /// Process-local identity for this successful install/replace operation.
    pub token: u64,
    pub backend: ExternalHookBackendKind,
    pub operation: ExternalHookOperation,
    pub original: Option<NonNull<c_void>>,
    pub native_result: Option<libc::c_int>,
    target: NonNull<c_void>,
    replacement: NonNull<c_void>,
    handle_released: bool,
    #[cfg(native_api_apple_hook_backend)]
    image_handle: Option<Arc<AppleImageHandle>>,
}

impl HookExecutionResult {
    fn new(
        token: u64,
        backend: ExternalHookBackendKind,
        operation: ExternalHookOperation,
        target: NonNull<c_void>,
        replacement: NonNull<c_void>,
        original: NonNull<c_void>,
        native_result: Option<libc::c_int>,
    ) -> Self {
        Self {
            token,
            backend,
            operation,
            original: Some(original),
            native_result,
            target,
            replacement,
            handle_released: false,
            #[cfg(native_api_apple_hook_backend)]
            image_handle: None,
        }
    }

    #[cfg(native_api_apple_hook_backend)]
    fn with_image_handle(mut self, image_handle: Arc<AppleImageHandle>) -> Self {
        self.image_handle = Some(image_handle);
        self
    }

    /// The trampoline is diagnostic/call-through state, not an uninstall ABI.
    pub const fn has_original_trampoline(&self) -> bool {
        self.original.is_some()
    }

    pub const fn target(&self) -> NonNull<c_void> {
        self.target
    }

    pub const fn replacement(&self) -> NonNull<c_void> {
        self.replacement
    }

    /// Whether this handle still owns the extra `RTLD_NOLOAD` image lease.
    /// This says nothing about whether the target remains hooked.
    pub const fn handle_released(&self) -> bool {
        self.handle_released
    }

    pub const fn native_uninstall_available(&self) -> bool {
        false
    }

    /// Release adapter-owned resources. The target remains hooked because the
    /// supported third-party public ABIs expose no native uninstall operation.
    /// Returns `true` exactly once and `false` on subsequent calls.
    pub fn release(&mut self) -> bool {
        if self.handle_released {
            return false;
        }
        self.handle_released = true;
        #[cfg(native_api_apple_hook_backend)]
        {
            self.image_handle = None;
        }
        true
    }

    /// Request native uninstall without changing ownership on failure.
    ///
    /// The currently supported backend ABIs have no verified native uninstall
    /// entry point. The error explicitly preserves the fact that the target
    /// remains installed; callers may separately choose `release`.
    pub fn uninstall(&mut self) -> Result<(), HookBackendFfiError> {
        if self.handle_released {
            return Err(HookBackendFfiError::HandleReleased { token: self.token });
        }
        Err(HookBackendFfiError::NativeUninstallUnavailable {
            backend: self.backend,
            token: self.token,
        })
    }

    #[cfg(test)]
    pub(crate) fn synthetic(
        backend: ExternalHookBackendKind,
        operation: ExternalHookOperation,
        target: usize,
        replacement: usize,
        original: usize,
    ) -> Self {
        Self::new(
            allocate_hook_token(),
            backend,
            operation,
            NonNull::new(target as *mut c_void).expect("synthetic target must be non-null"),
            NonNull::new(replacement as *mut c_void).expect("synthetic replacement must be non-null"),
            NonNull::new(original as *mut c_void).expect("synthetic original must be non-null"),
            None,
        )
    }
}

#[cfg(native_api_apple_hook_backend)]
#[derive(Clone, Copy)]
enum HookEntryPoint {
    ElleKit(ElleKitHookFunction),
    Substrate(SubstrateHookFunction),
    Substitute(SubstituteHookFunctions),
    Libhooker(LibhookerHookFunctions),
}

#[cfg(native_api_apple_hook_backend)]
#[derive(Debug)]
struct AppleImageHandle(NonNull<c_void>);

#[cfg(native_api_apple_hook_backend)]
impl Drop for AppleImageHandle {
    fn drop(&mut self) {
        unsafe {
            libc::dlclose(self.0.as_ptr());
        }
    }
}

pub struct ResolvedHookBackend {
    probe: HookBackendProbe,
    #[cfg(native_api_apple_hook_backend)]
    image_handle: Arc<AppleImageHandle>,
    #[cfg(native_api_apple_hook_backend)]
    entry: HookEntryPoint,
}

impl ResolvedHookBackend {
    pub fn probe(&self) -> &HookBackendProbe {
        &self.probe
    }

    pub fn backend(&self) -> ExternalHookBackendKind {
        self.probe.backend
    }

    pub fn supports(&self, operation: ExternalHookOperation) -> bool {
        self.probe.executable(operation)
    }

    pub fn public_uninstall_available(&self) -> bool {
        self.probe.public_uninstall_available()
    }

    /// Install a hook through the exact entry point captured by the probe.
    ///
    /// # Safety
    ///
    /// `target` and `replacement` must be valid code pointers for the selected
    /// backend. The caller must also satisfy backend-specific threading rules.
    pub unsafe fn install(
        &self,
        target: *mut c_void,
        replacement: *mut c_void,
    ) -> Result<HookExecutionResult, HookBackendFfiError> {
        unsafe { self.execute(ExternalHookOperation::Install, target, replacement) }
    }

    /// Replace a function through the exact entry point captured by the probe.
    ///
    /// # Safety
    ///
    /// The pointer and threading requirements are the same as for `install`.
    pub unsafe fn replace(
        &self,
        target: *mut c_void,
        replacement: *mut c_void,
    ) -> Result<HookExecutionResult, HookBackendFfiError> {
        unsafe { self.execute(ExternalHookOperation::Replace, target, replacement) }
    }

    pub fn uninstall(&self, handle: &mut HookExecutionResult) -> Result<(), HookBackendFfiError> {
        if handle.backend != self.backend() {
            return Err(HookBackendFfiError::HandleBackendMismatch {
                token: handle.token,
                handle_backend: handle.backend,
                resolver_backend: self.backend(),
            });
        }
        handle.uninstall()
    }

    unsafe fn execute(
        &self,
        operation: ExternalHookOperation,
        target: *mut c_void,
        replacement: *mut c_void,
    ) -> Result<HookExecutionResult, HookBackendFfiError> {
        if !self.supports(operation) {
            return Err(HookBackendFfiError::CapabilityUnavailable {
                backend: self.backend(),
                operation,
            });
        }
        if target.is_null() {
            return Err(HookBackendFfiError::NullTarget);
        }
        if replacement.is_null() {
            return Err(HookBackendFfiError::NullReplacement);
        }

        #[cfg(native_api_apple_hook_backend)]
        {
            let _keep_image_loaded = &self.image_handle;
            let token = allocate_hook_token();
            let target_ptr = NonNull::new(target).expect("target was checked above");
            let replacement_ptr = NonNull::new(replacement).expect("replacement was checked above");
            let mut original = std::ptr::null_mut();
            let native_result = match self.entry {
                HookEntryPoint::ElleKit(hook) => {
                    original = unsafe { hook(target, replacement, false) };
                    None
                }
                HookEntryPoint::Substrate(hook) => {
                    unsafe { hook(target, replacement, &mut original) };
                    None
                }
                HookEntryPoint::Substitute(hook) => {
                    let descriptor = SubstituteFunctionHook {
                        function: target,
                        replacement,
                        old_ptr: &mut original,
                        options: 0,
                    };
                    let status = unsafe { hook(&descriptor, 1, std::ptr::null_mut(), 0) };
                    if status != 0 {
                        return Err(HookBackendFfiError::NativeCallFailed {
                            backend: self.backend(),
                            code: status,
                        });
                    }
                    Some(status)
                }
                HookEntryPoint::Libhooker(hook) => {
                    let descriptor = LibhookerFunctionHook {
                        function: target,
                        replacement,
                        oldptr: &mut original,
                        options: std::ptr::null_mut(),
                    };
                    let hooked_count = unsafe { hook(&descriptor, 1) };
                    if hooked_count != 1 {
                        return Err(HookBackendFfiError::NativeCallFailed {
                            backend: self.backend(),
                            code: hooked_count,
                        });
                    }
                    Some(hooked_count)
                }
            };

            let original = NonNull::new(original).ok_or(HookBackendFfiError::OriginalUnavailable {
                backend: self.backend(),
                operation,
            })?;

            Ok(HookExecutionResult::new(
                token,
                self.backend(),
                operation,
                target_ptr,
                replacement_ptr,
                original,
                native_result,
            )
            .with_image_handle(Arc::clone(&self.image_handle)))
        }

        #[cfg(not(native_api_apple_hook_backend))]
        {
            let _ = (operation, target, replacement);
            Err(HookBackendFfiError::PlatformUnavailable)
        }
    }
}

#[cfg(native_api_apple_hook_backend)]
extern "C" {
    fn _dyld_image_count() -> u32;
    fn _dyld_get_image_name(image_index: u32) -> *const libc::c_char;
}

#[cfg(native_api_apple_hook_backend)]
fn loaded_image_names() -> Vec<String> {
    let count = unsafe { _dyld_image_count() };
    let mut images = Vec::with_capacity(count as usize);
    for index in 0..count {
        let name = unsafe { _dyld_get_image_name(index) };
        if !name.is_null() {
            images.push(unsafe { CStr::from_ptr(name) }.to_string_lossy().into_owned());
        }
    }
    images
}

#[cfg(native_api_apple_hook_backend)]
fn find_loaded_image(requested: &str) -> Option<String> {
    let images = loaded_image_names();
    if let Some(exact) = images.iter().find(|image| image.as_str() == requested) {
        return Some(exact.clone());
    }

    let requested_name = requested.rsplit('/').next()?;
    let mut basename_matches = images
        .into_iter()
        .filter(|image| image.rsplit('/').next() == Some(requested_name));
    let result = basename_matches.next()?;
    basename_matches.next().is_none().then_some(result)
}

#[cfg(native_api_apple_hook_backend)]
fn open_loaded_image(image_name: &str) -> Option<AppleImageHandle> {
    let image_name = CString::new(image_name).ok()?;
    let flags = libc::RTLD_LAZY | libc::RTLD_LOCAL | libc::RTLD_NOLOAD;
    let handle = unsafe { libc::dlopen(image_name.as_ptr(), flags) };
    NonNull::new(handle).map(AppleImageHandle)
}

#[cfg(native_api_apple_hook_backend)]
fn image_component(path: &str) -> Option<&str> {
    path.rsplit(['/', '\\'])
        .next()
        .filter(|component| !component.is_empty())
}

#[cfg(native_api_apple_hook_backend)]
fn symbol_belongs_to_image(image_name: &str, symbol: NonNull<c_void>) -> bool {
    let mut info: libc::Dl_info = unsafe { std::mem::zeroed() };
    if unsafe { libc::dladdr(symbol.as_ptr() as *const c_void, &mut info) } == 0 || info.dli_fname.is_null() {
        return false;
    }
    let owner = unsafe { CStr::from_ptr(info.dli_fname) }.to_string_lossy();
    owner == image_name || image_component(owner.as_ref()) == image_component(image_name)
}

#[cfg(native_api_apple_hook_backend)]
fn lookup_symbol(image_name: &str, handle: &AppleImageHandle, name: &'static str) -> Option<NonNull<c_void>> {
    let name = CString::new(name).ok()?;
    let symbol = NonNull::new(unsafe { libc::dlsym(handle.0.as_ptr(), name.as_ptr()) })?;
    symbol_belongs_to_image(image_name, symbol).then_some(symbol)
}

#[cfg(native_api_apple_hook_backend)]
fn probe_loaded_image(image_name: String) -> HookBackendProbe {
    let backend = parse_backend_image(&image_name);
    let Some(handle) = open_loaded_image(&image_name) else {
        return probe_with_lookup(backend, image_name, true, false, |_| None);
    };
    probe_with_lookup(backend, image_name.clone(), true, true, |name| {
        lookup_symbol(&image_name, &handle, name).map(|address| address.as_ptr() as usize)
    })
}

/// Probe one image without loading a new backend into the process.
pub fn probe_loaded_backend_image(image_name: &str) -> HookBackendProbe {
    #[cfg(native_api_apple_hook_backend)]
    {
        if let Some(loaded_image) = find_loaded_image(image_name) {
            return probe_loaded_image(loaded_image);
        }
        return probe_with_lookup(parse_backend_image(image_name), image_name, false, false, |_| None);
    }

    #[cfg(not(native_api_apple_hook_backend))]
    {
        let backend = parse_backend_image(image_name);
        let mut probe = probe_with_lookup(backend, image_name, false, false, |_| None);
        for capability in [
            &mut probe.capabilities.install,
            &mut probe.capabilities.replace,
            &mut probe.capabilities.uninstall,
        ] {
            capability.state = CapabilityProbeState::PlatformUnavailable;
            capability.executable = false;
        }
        probe
    }
}

/// Enumerate known loaded backend images. Unrecognized images are available
/// through `probe_loaded_backend_image` and are never inferred as executable.
pub fn probe_loaded_hook_backends() -> Vec<HookBackendProbe> {
    #[cfg(native_api_apple_hook_backend)]
    {
        let mut images = loaded_image_names()
            .into_iter()
            .filter(|image| parse_backend_image(image).is_known())
            .collect::<Vec<_>>();
        images.sort();
        images.dedup();
        return images.into_iter().map(probe_loaded_image).collect();
    }

    #[cfg(not(native_api_apple_hook_backend))]
    {
        Vec::new()
    }
}

/// Resolve an execution handle for one already-loaded image.
pub fn resolve_loaded_hook_backend(image_name: &str) -> Result<ResolvedHookBackend, HookBackendFfiError> {
    #[cfg(native_api_apple_hook_backend)]
    {
        let loaded_image =
            find_loaded_image(image_name).ok_or_else(|| HookBackendFfiError::ImageNotLoaded(image_name.to_owned()))?;
        let backend = parse_backend_image(&loaded_image);
        let spec =
            hook_symbol_spec(backend).ok_or_else(|| HookBackendFfiError::UnknownBackend(loaded_image.clone()))?;
        let image_handle = Arc::new(
            open_loaded_image(&loaded_image)
                .ok_or_else(|| HookBackendFfiError::ImageHandleUnavailable(loaded_image.clone()))?,
        );
        let symbol =
            lookup_symbol(&loaded_image, &image_handle, spec.name).ok_or(HookBackendFfiError::SymbolUnavailable {
                backend,
                symbol: spec.name,
            })?;
        let address = symbol.as_ptr() as usize;
        let probe = probe_backend_from_symbols(backend, &loaded_image, true, true, &[(spec.name, address)]);

        let entry = unsafe {
            match backend {
                ExternalHookBackendKind::ElleKit => {
                    HookEntryPoint::ElleKit(std::mem::transmute::<*mut c_void, ElleKitHookFunction>(symbol.as_ptr()))
                }
                ExternalHookBackendKind::Substrate => HookEntryPoint::Substrate(std::mem::transmute::<
                    *mut c_void,
                    SubstrateHookFunction,
                >(symbol.as_ptr())),
                ExternalHookBackendKind::Substitute => HookEntryPoint::Substitute(std::mem::transmute::<
                    *mut c_void,
                    SubstituteHookFunctions,
                >(symbol.as_ptr())),
                ExternalHookBackendKind::Libhooker => HookEntryPoint::Libhooker(std::mem::transmute::<
                    *mut c_void,
                    LibhookerHookFunctions,
                >(symbol.as_ptr())),
                ExternalHookBackendKind::Unknown => unreachable!("unknown backend was rejected before resolution"),
            }
        };

        return Ok(ResolvedHookBackend {
            probe,
            image_handle,
            entry,
        });
    }

    #[cfg(not(native_api_apple_hook_backend))]
    {
        let _ = image_name;
        Err(HookBackendFfiError::PlatformUnavailable)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::{align_of, size_of};

    #[test]
    fn parser_accepts_exact_backend_image_names() {
        let cases = [
            ("/usr/lib/libellekit.dylib", ExternalHookBackendKind::ElleKit),
            ("ElleKit.framework", ExternalHookBackendKind::ElleKit),
            (
                "/Library/Frameworks/CydiaSubstrate.framework/CydiaSubstrate",
                ExternalHookBackendKind::Substrate,
            ),
            ("MobileSubstrate.dylib", ExternalHookBackendKind::Substrate),
            ("libsubstitute.dylib", ExternalHookBackendKind::Substitute),
            ("/usr/lib/libhooker.dylib", ExternalHookBackendKind::Libhooker),
        ];

        for (image, expected) in cases {
            assert_eq!(parse_backend_image(image), expected, "{image}");
        }
    }

    #[test]
    fn parser_does_not_promote_loader_or_substring_matches() {
        for image in [
            "substitute-loader.dylib",
            "ellekit-helper.dylib",
            "my-libhooker-test.dylib",
            "",
        ] {
            assert_eq!(parse_backend_image(image), ExternalHookBackendKind::Unknown, "{image}");
        }
    }

    #[test]
    fn exact_resolved_symbol_enables_install_and_replace_only() {
        let backends = [
            (ExternalHookBackendKind::ElleKit, ELLEKIT_HOOK),
            (ExternalHookBackendKind::Substrate, SUBSTRATE_HOOK),
            (ExternalHookBackendKind::Substitute, SUBSTITUTE_HOOK),
            (ExternalHookBackendKind::Libhooker, LIBHOOKER_HOOK),
        ];

        for (backend, spec) in backends {
            let probe = probe_backend_from_symbols(backend, backend.as_str(), true, true, &[(spec.name, 0x1000)]);
            assert!(probe.executable(ExternalHookOperation::Install));
            assert!(probe.executable(ExternalHookOperation::Replace));
            assert!(!probe.executable(ExternalHookOperation::Uninstall));
            assert!(!probe.public_uninstall_available());
            assert_eq!(
                probe.capabilities.uninstall.state,
                CapabilityProbeState::PublicAbiUnavailable
            );
            assert_eq!(probe.symbols[0].abi_source, spec.abi_source);
        }
    }

    #[test]
    fn missing_or_zero_symbol_is_never_executable() {
        for symbols in [&[][..], &[("MSHookFunction", 0)][..]] {
            let probe = probe_backend_from_symbols(
                ExternalHookBackendKind::Substrate,
                "libsubstrate.dylib",
                true,
                true,
                symbols,
            );
            assert_eq!(probe.capabilities.install.state, CapabilityProbeState::SymbolMissing);
            assert!(!probe.executable(ExternalHookOperation::Install));
            assert!(!probe.executable(ExternalHookOperation::Replace));
        }
    }

    #[test]
    fn successful_probe_requires_a_loaded_image_and_open_handle() {
        let probe = probe_backend_from_symbols(
            ExternalHookBackendKind::Substrate,
            "libsubstrate.dylib",
            true,
            true,
            &[("MSHookFunction", 0x1000)],
        );
        assert!(probe.executable(ExternalHookOperation::Install));

        let mut no_handle = probe.clone();
        no_handle.image_handle_opened = false;
        assert!(!no_handle.executable(ExternalHookOperation::Install));

        let mut no_symbol = probe;
        no_symbol.capabilities.install.executable = false;
        assert!(!no_symbol.executable(ExternalHookOperation::Install));
    }

    #[test]
    fn missing_original_is_a_reconciliation_error() {
        let error = HookBackendFfiError::OriginalUnavailable {
            backend: ExternalHookBackendKind::ElleKit,
            operation: ExternalHookOperation::Replace,
        };
        assert!(error.to_string().contains("may already be applied"));
        assert!(error.target_state_uncertain());
        assert!(HookBackendFfiError::NativeCallFailed {
            backend: ExternalHookBackendKind::Libhooker,
            code: 0,
        }
        .target_state_uncertain());
        assert!(!HookBackendFfiError::NullTarget.target_state_uncertain());
    }

    #[test]
    fn successful_hook_handle_has_stable_identity_and_addresses() {
        let first = HookExecutionResult::synthetic(
            ExternalHookBackendKind::ElleKit,
            ExternalHookOperation::Install,
            0x1000,
            0x2000,
            0x3000,
        );
        let second = HookExecutionResult::synthetic(
            ExternalHookBackendKind::ElleKit,
            ExternalHookOperation::Replace,
            0x1000,
            0x4000,
            0x5000,
        );

        assert_ne!(first.token, 0);
        assert_ne!(first.token, second.token);
        assert_eq!(first.token, first.token);
        assert_eq!(first.target().as_ptr() as usize, 0x1000);
        assert_eq!(first.replacement().as_ptr() as usize, 0x2000);
        assert!(first.has_original_trampoline());
        assert!(!first.native_uninstall_available());
        assert!(!first.handle_released());
    }

    #[test]
    fn unsupported_uninstall_is_repeatable_and_release_is_idempotent() {
        let mut handle = HookExecutionResult::synthetic(
            ExternalHookBackendKind::Substrate,
            ExternalHookOperation::Install,
            0x1000,
            0x2000,
            0x3000,
        );
        let expected = HookBackendFfiError::NativeUninstallUnavailable {
            backend: ExternalHookBackendKind::Substrate,
            token: handle.token,
        };

        assert_eq!(handle.uninstall(), Err(expected.clone()));
        assert_eq!(handle.uninstall(), Err(expected));
        assert!(!handle.handle_released());
        assert!(handle.release());
        assert!(handle.handle_released());
        assert!(!handle.release());
        assert_eq!(
            handle.uninstall(),
            Err(HookBackendFfiError::HandleReleased { token: handle.token })
        );
    }

    #[test]
    fn image_and_handle_state_gate_symbol_resolution() {
        let symbol = [("MSHookFunction", 0x1000)];
        let unloaded = probe_backend_from_symbols(
            ExternalHookBackendKind::Substrate,
            "libsubstrate.dylib",
            false,
            false,
            &symbol,
        );
        assert_eq!(
            unloaded.capabilities.install.state,
            CapabilityProbeState::ImageNotLoaded
        );

        let no_handle = probe_backend_from_symbols(
            ExternalHookBackendKind::Substrate,
            "libsubstrate.dylib",
            true,
            false,
            &symbol,
        );
        assert_eq!(
            no_handle.capabilities.install.state,
            CapabilityProbeState::ImageHandleUnavailable
        );
        assert!(no_handle.symbols[0].address.is_none());
    }

    #[test]
    fn unknown_backend_reports_probe_without_execution_capabilities() {
        let probe = probe_backend_from_symbols(
            ExternalHookBackendKind::Unknown,
            "custom-hook.dylib",
            true,
            true,
            &[("MSHookFunction", 0x1000), ("LHHookFunctions", 0x2000)],
        );

        assert!(probe.symbols.is_empty());
        for operation in [
            ExternalHookOperation::Install,
            ExternalHookOperation::Replace,
            ExternalHookOperation::Uninstall,
        ] {
            assert_eq!(
                probe.capabilities.for_operation(operation).state,
                CapabilityProbeState::UnknownBackend
            );
            assert!(!probe.executable(operation));
        }
    }

    #[test]
    fn backend_symbols_are_not_interchangeable() {
        let probe = probe_backend_from_symbols(
            ExternalHookBackendKind::Substitute,
            "libsubstitute.dylib",
            true,
            true,
            &[("MSHookFunction", 0x1000)],
        );
        assert_eq!(probe.capabilities.install.state, CapabilityProbeState::SymbolMissing);
    }

    #[test]
    fn ffi_struct_layouts_match_public_c_headers() {
        assert_eq!(size_of::<LibhookerFunctionHookOptions>(), size_of::<libc::c_int>() * 2);
        assert_eq!(align_of::<LibhookerFunctionHookOptions>(), align_of::<libc::c_int>());

        let pointer_bytes = size_of::<*mut c_void>();
        let expected_substitute =
            (pointer_bytes * 3 + size_of::<libc::c_int>()).div_ceil(pointer_bytes) * pointer_bytes;
        assert_eq!(size_of::<SubstituteFunctionHook>(), expected_substitute);
        assert_eq!(align_of::<SubstituteFunctionHook>(), pointer_bytes);
        assert_eq!(size_of::<LibhookerFunctionHook>(), pointer_bytes * 4);
        assert_eq!(align_of::<LibhookerFunctionHook>(), pointer_bytes);
    }

    #[cfg(not(native_api_apple_hook_backend))]
    #[test]
    fn host_runtime_probe_stays_non_executable() {
        let probe = probe_loaded_backend_image("libhooker.dylib");
        assert_eq!(
            probe.capabilities.install.state,
            CapabilityProbeState::PlatformUnavailable
        );
        assert!(!probe.executable(ExternalHookOperation::Install));
        assert!(probe_loaded_hook_backends().is_empty());
        assert!(matches!(
            resolve_loaded_hook_backend("libhooker.dylib"),
            Err(HookBackendFfiError::PlatformUnavailable)
        ));
    }
}
