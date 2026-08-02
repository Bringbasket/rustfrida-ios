mod build_version;
mod chained_fixups;
mod code_signature;
mod data_in_code;
mod deps;
mod dyld_info;
mod dylinker;
mod encryption_info;
mod entry_point;
mod exports;
mod exports_trie;
mod function_starts;
mod hook_backend_adapter;
mod hook_backend_ffi;
mod imports;
mod injection;
mod install_name;
mod jailbreak;
mod linkedit;
mod loadcmds;
#[cfg(any(target_os = "ios", target_os = "macos"))]
mod mach;
mod pac;
mod rpaths;
mod sections;
mod segments;
mod source_version;
mod stalker;
mod swift;
mod symbols;
mod uuid;

use common::Result;
use std::path::Path;

pub use build_version::{
    find_image_build_version, image_build_version_support_available, ImageBuildTool, ImageBuildVersion,
};
pub use chained_fixups::{
    find_image_chained_fixups, image_chained_fixups_support_available, ImageChainedFixups, ImageChainedFixupsImport,
    ImageChainedFixupsPage, ImageChainedFixupsSegment,
};
pub use code_signature::{find_image_code_signature, image_code_signature_support_available, ImageCodeSignature};
pub use data_in_code::{
    find_image_data_in_code, image_data_in_code_support_available, ImageDataInCode, ImageDataInCodeEntry,
};
pub use deps::{
    dependency_path_or_name_matches, find_image_dependencies, image_dependency_support_available, ImageDependency,
};
pub use dyld_info::{find_image_dyld_info, image_dyld_info_support_available, ImageDyldInfo};
pub use dylinker::{find_image_dylinker, image_dylinker_support_available, ImageDylinker};
pub use encryption_info::{find_image_encryption_info, image_encryption_info_support_available, ImageEncryptionInfo};
pub use entry_point::{find_image_entry_point, image_entry_point_support_available, ImageEntryPoint};
pub use exports::{find_image_exports, native_export_support_available};
pub use exports_trie::{
    find_image_exports_trie, image_exports_trie_support_available, ImageExportsTrie, ImageExportsTrieEntry,
};
pub use function_starts::{
    find_image_function_starts, image_function_starts_support_available, ImageFunctionStart, ImageFunctionStarts,
};
pub use hook_backend_adapter::{
    bind_external_hook_backend, decide_hook_backend_adapter, execute_external_hook_backend, AdapterCommandMode,
    AdapterDecision, AdapterDecisionInput, AdapterKind, AdapterOverride, AdapterPolicy, BackendPresence,
    CapabilityLevel, DecisionOutcome, DecisionReasonCode, ExecutionBoundary, ExternalHookExecutionError,
    HookBackendCapabilities, HookBackendKind, HookOperation, RecommendedAction,
};
pub use hook_backend_ffi::{
    parse_backend_image, probe_loaded_backend_image, probe_loaded_hook_backends, resolve_loaded_hook_backend,
    CapabilityProbeState, ExternalHookBackendKind, ExternalHookOperation, HookBackendCapabilityProbe,
    HookBackendFfiError, HookBackendProbe, HookExecutionResult, OperationCapabilityProbe, ResolvedHookBackend,
    ResolvedSymbolProbe, ELLEKIT_ABI_SOURCE, LIBHOOKER_ABI_SOURCE, SUBSTITUTE_ABI_SOURCE, SUBSTRATE_ABI_SOURCE,
};
pub use imports::{find_image_imports, image_import_support_available, ImageImport};
pub use injection::{
    Arm64ThreadLaunch, Arm64ThreadState, BootstrapImage, BootstrapResultReport, BootstrapStatus, InjectionPlan,
    InjectionStage, InjectionStep, InjectionTarget, InjectionTrace, LoaderSymbolRole, MachInjector,
    RemoteProtectionOutcome, RemoteThreadTerminationOutcome, ResolvedLoaderSymbol, ThreadBootstrapKind,
    ThreadCreatePlan,
};
pub use install_name::{find_image_install_name, image_install_name_support_available, ImageInstallName};
pub use jailbreak::{
    current_hook_policy, detect_hook_environment, hook_coexistence_layer_status,
    hook_coexistence_layer_status_for_mode, hook_environment_recommendations, hook_environment_recommended_actions,
    resolve_hook_strategy, HookBackendInfo, HookCoexistenceLayerStatus, HookEnvironmentReport, HookPolicy,
    HookRecommendedAction, HookStrategyDecision,
};
pub use linkedit::{find_image_linkedit_info, image_linkedit_info_support_available, ImageLinkeditInfo};
pub use loadcmds::{find_image_load_commands, image_load_command_support_available, ImageLoadCommand};
pub use pac::{
    current_process_uses_arm64e, enumerate_arm64e_images, image_uses_arm64e, normalize_code_pointer,
    pac_support_available, strip_code_pointer, strip_data_pointer,
};
pub use rpaths::{find_image_rpaths, image_rpath_support_available, rpath_path_or_name_matches, ImageRpath};
pub use sections::{find_image_sections, image_section_support_available, section_name_matches, ImageSection};
pub use segments::{find_image_segments, image_segment_support_available, segment_name_matches, ImageSegment};
pub use source_version::{find_image_source_version, image_source_version_support_available, ImageSourceVersion};
pub use stalker::{
    current_stalker_thread_id, ios_stalker_capabilities, stalker_backend_status, stalker_event_sink,
    stalker_flush_thread, stalker_follow_thread, stalker_garbage_collect_thread, stalker_unfollow_thread,
    StalkerBackendStatus, StalkerCapabilities, StalkerConfig, StalkerEvent, StalkerEventKind, StalkerEventMask,
    StalkerRange, StalkerSession, StalkerSessionState, StalkerThreadStatus, DEFAULT_STALKER_QUEUE_CAPACITY,
    IOS_STALKER_MISSING_OPERATIONS, MAX_STALKER_QUEUE_CAPACITY,
};
pub use swift::{
    find_swift_conformances, find_swift_metadata, find_swift_method_owners, find_swift_methods, find_swift_protocols,
    find_swift_symbols, find_swift_type_layouts, find_swift_type_methods, find_swift_types, find_swift_types_of_kind,
    find_swift_vtable, find_swift_witness_tables, inspect_swift_live_object, swift_conformance_names_match,
    swift_demangle_symbol, swift_member_name_matches, swift_protocol_name_matches, swift_support_available,
    swift_type_name_matches, swift_type_source_kinds, SwiftConformance, SwiftLiveObjectInfo, SwiftObjectOwnership,
    SwiftProtocol, SwiftSymbol, SwiftType, SwiftTypeLayout, SwiftVtableEntry, SwiftWitnessTable,
};
pub use symbols::{
    find_image_symbols, find_native_symbols, native_symbol_support_available, ImageSymbol, NativeSymbol,
};
pub use uuid::{find_image_uuid, image_uuid_support_available, ImageUuid};

pub const DEFAULT_BOOTSTRAP_WAIT_MS: u64 = 3_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InjectionEnvironmentReport {
    pub dry_run: bool,
    pub bootstrap_wait_ms: Option<u64>,
    pub hook_policy: HookPolicy,
    pub hook_strategy: HookStrategyDecision,
    pub hook_environment: HookEnvironmentReport,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InjectionTargetPreflightReport {
    pub main_image: Option<ImageInfo>,
    pub target_images: Vec<ImageInfo>,
    pub target_image_count: usize,
    pub target_uses_arm64e: Option<bool>,
    pub thread_bootstrap_kind: ThreadBootstrapKind,
    pub thread_bootstrap_label: String,
    pub thread_bootstrap_address: usize,
    pub thread_bootstrap_raw_address: usize,
    pub thread_bootstrap_canonicalized: bool,
    pub target_hook_environment: HookEnvironmentReport,
    pub target_hook_strategy: HookStrategyDecision,
    pub resolved_loader_symbols: Vec<ResolvedLoaderSymbol>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageInfo {
    pub name: String,
    pub base: usize,
    pub slide: isize,
    pub size: usize,
}

#[derive(Debug, Clone)]
pub struct SymbolInfo {
    pub module_name: String,
    pub module_base: usize,
    pub symbol_name: Option<String>,
    pub symbol_address: Option<usize>,
    pub offset: usize,
}

#[cfg_attr(not(any(target_os = "ios", target_os = "macos")), allow(dead_code))]
fn image_name_matches(module_name: &str, image_name: &str) -> bool {
    if image_name == module_name {
        return true;
    }

    let module_basename = Path::new(module_name).file_name().and_then(|name| name.to_str());
    let image_basename = Path::new(image_name).file_name().and_then(|name| name.to_str());

    match (module_basename, image_basename) {
        (Some(module_basename), Some(image_basename)) => module_basename == image_basename,
        _ => false,
    }
}

#[cfg_attr(not(any(target_os = "ios", target_os = "macos")), allow(dead_code))]
fn rebase_loader_symbols_to_images(
    source_symbols: &[ResolvedLoaderSymbol],
    target_images: &[ImageInfo],
) -> Result<Vec<ResolvedLoaderSymbol>> {
    let mut rebased = Vec::with_capacity(source_symbols.len());
    for symbol in source_symbols {
        let target_image = target_images
            .iter()
            .find(|image| image_name_matches(&symbol.module_name, &image.name))
            .ok_or_else(|| {
                common::Error::State(format!(
                    "failed to locate target image '{}' for loader symbol {}",
                    symbol.module_name, symbol.symbol_name
                ))
            })?;

        rebased.push(ResolvedLoaderSymbol {
            role: symbol.role,
            symbol_name: symbol.symbol_name.clone(),
            module_name: target_image.name.clone(),
            module_base: target_image.base,
            raw_address: target_image.base.checked_add(symbol.offset).ok_or_else(|| {
                common::Error::State(format!(
                    "rebased address overflow for loader symbol {} at base 0x{:x} + offset 0x{:x}",
                    symbol.symbol_name, target_image.base, symbol.offset
                ))
            })?,
            address: target_image.base.checked_add(symbol.offset).ok_or_else(|| {
                common::Error::State(format!(
                    "rebased address overflow for loader symbol {} at base 0x{:x} + offset 0x{:x}",
                    symbol.symbol_name, target_image.base, symbol.offset
                ))
            })?,
            offset: symbol.offset,
        });
    }
    Ok(rebased)
}

impl MachInjector {
    pub fn plan(&self, target: &InjectionTarget) -> Result<InjectionPlan> {
        platform::plan(target)
    }

    pub fn preflight(&self, target: &InjectionTarget) -> Result<InjectionTargetPreflightReport> {
        platform::preflight(target)
    }

    pub fn inject_trace_with_preflight(
        &self,
        target: &InjectionTarget,
        preflight: &InjectionTargetPreflightReport,
    ) -> Result<InjectionTrace> {
        platform::inject_trace_with_preflight(target, preflight)
    }

    pub fn inject_trace(&self, target: &InjectionTarget) -> Result<InjectionTrace> {
        platform::inject_trace(target)
    }

    pub fn inject(&self, target: &InjectionTarget) -> Result<()> {
        self.inject_trace(target).map(|_| ())
    }
}

pub fn enumerate_images() -> Result<Vec<ImageInfo>> {
    platform::enumerate_images()
}

pub fn find_image_by_name(module_name: &str) -> Result<Option<ImageInfo>> {
    platform::find_image_by_name(module_name)
}

pub fn find_image_by_address(address: usize) -> Result<Option<ImageInfo>> {
    platform::find_image_by_address(address)
}

pub fn find_export_by_name(module_name: Option<&str>, symbol_name: &str) -> Result<Option<usize>> {
    platform::find_export_by_name(module_name, symbol_name)
}

pub fn find_symbol_by_address(address: usize) -> Result<Option<SymbolInfo>> {
    platform::find_symbol_by_address(address)
}

pub fn probe_injection_environment() -> Result<InjectionEnvironmentReport> {
    let hook_policy = current_hook_policy();
    let hook_environment = detect_hook_environment()?;
    let hook_strategy = resolve_hook_strategy()?;

    Ok(InjectionEnvironmentReport {
        dry_run: dry_run_remote_injection_enabled(),
        bootstrap_wait_ms: configured_bootstrap_wait_timeout_ms(),
        hook_policy,
        hook_strategy,
        hook_environment,
    })
}

pub(crate) fn dry_run_remote_injection_enabled() -> bool {
    parse_bool_env("IOS_RUSTFRIDA_DRY_RUN")
}

pub(crate) fn configured_bootstrap_wait_timeout_ms() -> Option<u64> {
    match std::env::var("IOS_RUSTFRIDA_BOOTSTRAP_WAIT_MS") {
        Ok(value) => match value.trim().parse::<u64>() {
            Ok(0) => None,
            Ok(milliseconds) => Some(milliseconds),
            Err(_) => Some(DEFAULT_BOOTSTRAP_WAIT_MS),
        },
        Err(_) => Some(DEFAULT_BOOTSTRAP_WAIT_MS),
    }
}

fn parse_bool_env(name: &str) -> bool {
    std::env::var(name)
        .map(|value| matches!(value.trim(), "1" | "true" | "TRUE" | "yes" | "YES"))
        .unwrap_or(false)
}

#[cfg_attr(not(any(target_os = "ios", target_os = "macos")), allow(dead_code))]
pub(crate) fn arm64e_pthread_fallback_allowed() -> bool {
    parse_bool_env("IOS_RUSTFRIDA_ALLOW_ARM64E_PTHREAD_FALLBACK")
}

#[cfg_attr(not(any(target_os = "ios", target_os = "macos")), allow(dead_code))]
fn format_hook_environment_brief(report: &HookEnvironmentReport) -> String {
    let active = report.active_backend.as_deref().unwrap_or("<none>");
    let mut backend_summaries = report
        .backends
        .iter()
        .map(|backend| {
            format!(
                "{}(loaded_images={},filesystem_paths={})",
                backend.id,
                backend.loaded_images.len(),
                backend.filesystem_paths.len()
            )
        })
        .collect::<Vec<_>>();
    backend_summaries.sort();
    let backends = if backend_summaries.is_empty() {
        "<none>".to_string()
    } else {
        backend_summaries.join(",")
    };

    format!(
        "active={} backends={} warnings={}",
        active,
        backends,
        report.warnings.len()
    )
}

fn loader_symbol_offset_from_canonical_address(
    symbol_name: &str,
    raw_address: usize,
    canonical_address: usize,
    image_base: usize,
) -> Result<usize> {
    canonical_address.checked_sub(image_base).ok_or_else(|| {
        common::Error::State(format!(
            "resolved loader symbol {symbol_name} raw=0x{raw_address:x} canonical=0x{canonical_address:x}, but its base 0x{image_base:x} was greater than the canonical address"
        ))
    })
}

#[cfg_attr(not(any(target_os = "ios", target_os = "macos")), allow(dead_code))]
pub(crate) fn validate_thread_bootstrap_symbol_for_target(
    target_uses_arm64e: Option<bool>,
    symbol: &ResolvedLoaderSymbol,
) -> Result<()> {
    if !matches!(target_uses_arm64e, Some(true)) {
        return Ok(());
    }

    if symbol.symbol_name == "pthread_create_from_mach_thread" {
        return Ok(());
    }

    if arm64e_pthread_fallback_allowed() {
        return Ok(());
    }

    Err(common::Error::State(format!(
        "arm64e target resolved thread bootstrap kind={} symbol='{}' at 0x{:x}; require pthread_create_from_mach_thread or set IOS_RUSTFRIDA_ALLOW_ARM64E_PTHREAD_FALLBACK=1 to force pthread_create",
        symbol
            .thread_bootstrap_kind()
            .unwrap_or(ThreadBootstrapKind::Other)
            .as_str(),
        symbol.symbol_name,
        symbol.address
    )))
}

#[cfg(any(target_os = "ios", target_os = "macos"))]
mod platform {
    use std::ffi::{CStr, CString};
    use std::mem::size_of;
    use std::os::raw::{c_char, c_void};

    use common::Result;

    use crate::jailbreak::resolve_hook_strategy_for_report;
    use crate::{
        current_hook_policy, dry_run_remote_injection_enabled, image_name_matches,
        injection::{build_injection_plan, LoaderSymbolRole, ResolvedLoaderSymbol},
        mach, normalize_code_pointer, ImageInfo, InjectionPlan, InjectionTarget, InjectionTrace, SymbolInfo,
    };

    extern "C" {
        fn _dyld_image_count() -> u32;
        fn _dyld_get_image_name(index: u32) -> *const c_char;
        fn _dyld_get_image_header(index: u32) -> *const c_void;
        fn _dyld_get_image_vmaddr_slide(index: u32) -> isize;
    }

    const LC_SEGMENT_64: u32 = 0x19;
    const MH_MAGIC_64: u32 = 0xfeedfacf;

    #[repr(C)]
    struct MachHeader64 {
        magic: u32,
        cputype: i32,
        cpusubtype: i32,
        filetype: u32,
        ncmds: u32,
        sizeofcmds: u32,
        flags: u32,
        reserved: u32,
    }

    #[repr(C)]
    struct LoadCommand {
        cmd: u32,
        cmdsize: u32,
    }

    #[repr(C)]
    struct SegmentCommand64 {
        cmd: u32,
        cmdsize: u32,
        segname: [u8; 16],
        vmaddr: u64,
        vmsize: u64,
        fileoff: u64,
        filesize: u64,
        maxprot: i32,
        initprot: i32,
        nsects: u32,
        flags: u32,
    }

    fn make_cstring(raw: &str, label: &str) -> Result<CString> {
        CString::new(raw).map_err(|_| common::Error::InvalidArgument(format!("{label} contains an interior NUL byte")))
    }

    fn format_injection_trace_context(trace: &InjectionTrace) -> String {
        let mut summary = format!(
            "arm64e={} code=0x{:x}/{} alloc={} protect={} data=0x{:x}/{} alloc={} protect={} stack=0x{:x}/{} thread_bootstrap_kind={} thread_bootstrap={} flavor={} count={} pc=0x{:x} sp=0x{:x} x2=0x{:x} x3=0x{:x} timed_out={} thread_termination={} resources_persist={}",
            trace
                .target_uses_arm64e
                .map(|value| value.to_string())
                .unwrap_or_else(|| "unknown".into()),
            trace.payload_address,
            trace.payload_size,
            trace.payload_allocated_size,
            trace.code_protection.as_str(),
            trace.data_address,
            trace.data_size,
            trace.data_allocated_size,
            trace.data_protection.as_str(),
            trace.stack_address,
            trace.stack_size,
            trace.thread_bootstrap_kind.as_str(),
            trace.thread_bootstrap_label,
            trace.thread_plan.flavor,
            trace.thread_plan.count,
            trace.thread_plan.state.pc,
            trace.thread_plan.state.sp,
            trace.thread_plan.state.x[2],
            trace.thread_plan.state.x[3],
            trace.bootstrap_timed_out,
            trace.thread_termination.as_str(),
            trace.resources_persist
        );

        if let Some(thread_port) = trace.thread_port {
            summary.push_str(&format!(
                " thread_port={} thread_port_deallocated={}",
                thread_port, trace.thread_port_deallocated
            ));
        }

        summary
    }

    unsafe fn lookup_symbol(handle: *mut c_void, symbol: &CStr) -> Option<usize> {
        let addr = libc::dlsym(handle, symbol.as_ptr());
        if addr.is_null() {
            None
        } else {
            Some(addr as usize)
        }
    }

    unsafe fn header_ptr_after_header(header: &MachHeader64) -> *const u8 {
        (header as *const MachHeader64).add(1) as *const u8
    }

    fn image_runtime_size(base: usize, slide: isize) -> usize {
        let header = base as *const MachHeader64;
        if header.is_null() {
            return 0;
        }

        let header = unsafe { &*header };
        if header.magic != MH_MAGIC_64 {
            return 0;
        }

        let mut command_ptr = unsafe { header_ptr_after_header(header) };
        let mut min_runtime_start = None::<u128>;
        let mut max_runtime_end = None::<u128>;
        let command_region_size = header.sizeofcmds as usize;
        let mut consumed = 0usize;

        for _ in 0..header.ncmds {
            if consumed.saturating_add(size_of::<LoadCommand>()) > command_region_size {
                break;
            }

            let load = unsafe { &*(command_ptr as *const LoadCommand) };
            let command_size = load.cmdsize as usize;
            if command_size < size_of::<LoadCommand>() || consumed.saturating_add(command_size) > command_region_size {
                break;
            }

            if load.cmd == LC_SEGMENT_64 {
                if command_size < size_of::<SegmentCommand64>() {
                    consumed += command_size;
                    command_ptr = unsafe { command_ptr.add(command_size) };
                    continue;
                }

                let segment = unsafe { &*(command_ptr as *const SegmentCommand64) };
                let runtime_start = i128::from(segment.vmaddr) + (slide as i128);
                let runtime_end = runtime_start + i128::from(segment.vmsize);
                if runtime_start >= 0 && runtime_end >= runtime_start {
                    let runtime_start = runtime_start as u128;
                    let runtime_end = runtime_end as u128;
                    min_runtime_start = Some(
                        min_runtime_start
                            .map(|current| current.min(runtime_start))
                            .unwrap_or(runtime_start),
                    );
                    max_runtime_end = Some(
                        max_runtime_end
                            .map(|current| current.max(runtime_end))
                            .unwrap_or(runtime_end),
                    );
                }
            }

            consumed += command_size;
            command_ptr = unsafe { command_ptr.add(command_size) };
        }

        match (min_runtime_start, max_runtime_end) {
            (Some(start), Some(end)) if end >= start => end
                .checked_sub(start)
                .and_then(|value| usize::try_from(value).ok())
                .unwrap_or(0),
            _ => 0,
        }
    }

    fn symbol_info_from_dl_info(address: usize, info: libc::Dl_info) -> Option<SymbolInfo> {
        if info.dli_fname.is_null() || info.dli_fbase.is_null() {
            return None;
        }

        let module_name = unsafe { CStr::from_ptr(info.dli_fname) }.to_string_lossy().into_owned();
        let module_base = info.dli_fbase as usize;
        let symbol_name = if info.dli_sname.is_null() {
            None
        } else {
            Some(unsafe { CStr::from_ptr(info.dli_sname) }.to_string_lossy().into_owned())
        };
        let symbol_address = (!info.dli_saddr.is_null()).then_some(info.dli_saddr as usize);
        let offset = symbol_address
            .filter(|symbol_address| address >= *symbol_address)
            .map(|symbol_address| address - symbol_address)
            .or_else(|| (address >= module_base).then_some(address - module_base))
            .unwrap_or(0);

        Some(SymbolInfo {
            module_name,
            module_base,
            symbol_name,
            symbol_address,
            offset,
        })
    }

    pub fn enumerate_images() -> Result<Vec<ImageInfo>> {
        let count = unsafe { _dyld_image_count() };
        let mut images = Vec::with_capacity(count as usize);
        for index in 0..count {
            let name_ptr = unsafe { _dyld_get_image_name(index) };
            if name_ptr.is_null() {
                continue;
            }
            let name = unsafe { CStr::from_ptr(name_ptr) }.to_string_lossy().into_owned();
            let base = unsafe { _dyld_get_image_header(index) } as usize;
            let slide = unsafe { _dyld_get_image_vmaddr_slide(index) };
            let size = image_runtime_size(base, slide);
            images.push(ImageInfo {
                name,
                base,
                slide,
                size,
            });
        }
        Ok(images)
    }

    pub fn find_image_by_name(module_name: &str) -> Result<Option<ImageInfo>> {
        let module_name = module_name.trim();
        if module_name.is_empty() {
            return Err(common::Error::InvalidArgument("module name must not be empty".into()));
        }

        Ok(enumerate_images()?
            .into_iter()
            .find(|image| image_name_matches(module_name, &image.name)))
    }

    pub fn plan(target: &InjectionTarget) -> Result<InjectionPlan> {
        let plan = build_injection_plan(target)?;
        let loader_symbols = resolve_loader_symbols()?;
        plan.with_loader_symbols(loader_symbols)
    }

    pub fn preflight(target: &InjectionTarget) -> Result<crate::InjectionTargetPreflightReport> {
        let plan = plan(target)?;
        mach::preflight_target(target, &plan)
    }

    pub fn inject_trace_with_preflight(
        target: &InjectionTarget,
        preflight: &crate::InjectionTargetPreflightReport,
    ) -> Result<InjectionTrace> {
        let plan = plan(target)?;
        inject_trace_inner(target, &plan, Some(preflight))
    }

    pub fn inject_trace(target: &InjectionTarget) -> Result<InjectionTrace> {
        let plan = plan(target)?;
        inject_trace_inner(target, &plan, None)
    }

    fn inject_trace_inner(
        target: &InjectionTarget,
        plan: &InjectionPlan,
        preflight: Option<&crate::InjectionTargetPreflightReport>,
    ) -> Result<InjectionTrace> {
        let injection_environment = crate::probe_injection_environment()?;
        if !injection_environment.hook_strategy.bootstrap_injection_allowed() {
            let reason = injection_environment
                .hook_strategy
                .reason
                .as_deref()
                .unwrap_or("no reason provided");
            return Err(common::Error::State(format!(
                "hook strategy blocked injection: policy={} strategy={} reason={} hook_env={}",
                injection_environment.hook_policy.as_str(),
                injection_environment.hook_strategy.strategy,
                reason,
                crate::format_hook_environment_brief(&injection_environment.hook_environment)
            )));
        }

        let (target_hook_environment, target_hook_strategy) = match preflight {
            Some(preflight) => (
                preflight.target_hook_environment.clone(),
                preflight.target_hook_strategy.clone(),
            ),
            None => {
                let target_hook_environment = mach::probe_remote_hook_environment_for_pid(target.pid)?;
                let target_hook_strategy =
                    resolve_hook_strategy_for_report(&target_hook_environment, current_hook_policy());
                (target_hook_environment, target_hook_strategy)
            }
        };
        if !target_hook_strategy.bootstrap_injection_allowed() {
            let reason = target_hook_strategy.reason.as_deref().unwrap_or("no reason provided");
            return Err(common::Error::State(format!(
                "target hook strategy blocked injection for pid {}: policy={} strategy={} reason={} hook_env={}",
                target.pid,
                target_hook_strategy.policy.as_str(),
                target_hook_strategy.strategy,
                reason,
                crate::format_hook_environment_brief(&target_hook_environment)
            )));
        }

        if dry_run_remote_injection_enabled() {
            let write_trace = match preflight {
                Some(preflight) => mach::dry_run_write_bootstrap_with_preflight(plan, preflight)?,
                None => mach::dry_run_write_bootstrap(target, plan)?,
            };
            let pending_stages = [crate::InjectionStage::StartRemoteThread.as_str()].join(" -> ");
            return Err(common::Error::Unsupported(format!(
                "remote bootstrap write for pid {} prepared code=0x{:x}/{} alloc={} protect={} data=0x{:x}/{} alloc={} protect={} stack=0x{:x}/{} arm64e={} thread_bootstrap_kind={} thread_bootstrap={} flavor={} count={} pc=0x{:x} sp=0x{:x} x2=0x{:x} x3=0x{:x} cleaned_up={}; pending stages: {}; unset IOS_RUSTFRIDA_DRY_RUN to start the remote thread",
                target.pid,
                write_trace.payload_address,
                write_trace.payload_size,
                write_trace.payload_allocated_size,
                write_trace.code_protection.as_str(),
                write_trace.data_address,
                write_trace.data_size,
                write_trace.data_allocated_size,
                write_trace.data_protection.as_str(),
                write_trace.stack_address,
                write_trace.stack_size,
                write_trace
                    .target_uses_arm64e
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "unknown".into()),
                write_trace.thread_bootstrap_kind.as_str(),
                write_trace.thread_bootstrap_label,
                write_trace.thread_plan.flavor,
                write_trace.thread_plan.count,
                write_trace.thread_plan.state.pc,
                write_trace.thread_plan.state.sp,
                write_trace.thread_plan.state.x[2],
                write_trace.thread_plan.state.x[3],
                write_trace.cleaned_up,
                pending_stages
            )));
        }

        let start_trace = match preflight {
            Some(preflight) => mach::start_remote_thread_with_preflight(plan, preflight)?,
            None => mach::start_remote_thread(target, plan)?,
        };
        if let Some(report) = start_trace.bootstrap_report {
            if report.status.is_failure() {
                let hint = report
                    .status
                    .diagnostic_hint()
                    .map(|hint| format!(" hint={hint}"))
                    .unwrap_or_default();
                return Err(common::Error::State(format!(
                    "remote bootstrap failed: status={} raw={} dylib_handle=0x{:x} entry=0x{:x} socket_fd={} entry_return={}{} {}",
                    report.status.as_str(),
                    report.status_raw,
                    report.dylib_handle,
                    report.entry_address,
                    report.socket_fd,
                    report.entry_return,
                    hint,
                    format_injection_trace_context(&start_trace)
                )));
            }

            if matches!(report.status, crate::BootstrapStatus::EntryReturned) && report.entry_return != 0 {
                let hint = report
                    .status
                    .diagnostic_hint()
                    .map(|hint| format!(" hint={hint}"))
                    .unwrap_or_default();
                return Err(common::Error::State(format!(
                    "agent entry returned {} before controller handshake: dylib_handle=0x{:x} entry=0x{:x} socket_fd={}{} {}",
                    report.entry_return,
                    report.dylib_handle,
                    report.entry_address,
                    report.socket_fd,
                    hint,
                    format_injection_trace_context(&start_trace)
                )));
            }
        }
        Ok(start_trace)
    }

    pub fn find_image_by_address(address: usize) -> Result<Option<ImageInfo>> {
        let address = normalize_code_pointer(address);
        let mut info = std::mem::MaybeUninit::<libc::Dl_info>::zeroed();
        let result = unsafe { libc::dladdr(address as *const c_void, info.as_mut_ptr()) };
        if result == 0 {
            return Ok(None);
        }

        let info = unsafe { info.assume_init() };
        if info.dli_fname.is_null() || info.dli_fbase.is_null() {
            return Ok(None);
        }

        let name = unsafe { CStr::from_ptr(info.dli_fname) }.to_string_lossy().into_owned();
        if let Some(image) = enumerate_images()?
            .into_iter()
            .find(|image| image_name_matches(&name, &image.name))
        {
            return Ok(Some(image));
        }

        Ok(Some(ImageInfo {
            name,
            base: info.dli_fbase as usize,
            slide: 0,
            size: 0,
        }))
    }

    pub fn find_export_by_name(module_name: Option<&str>, symbol_name: &str) -> Result<Option<usize>> {
        if symbol_name.trim().is_empty() {
            return Err(common::Error::InvalidArgument("symbol name must not be empty".into()));
        }

        let symbol = make_cstring(symbol_name, "symbol name")?;

        let handle = if let Some(module_name) = module_name {
            let Some(image_name) = enumerate_images()?
                .into_iter()
                .find(|image| image_name_matches(module_name, &image.name))
                .map(|image| image.name)
            else {
                return Ok(None);
            };

            let image_name = make_cstring(&image_name, "module name")?;
            let handle = unsafe { libc::dlopen(image_name.as_ptr(), libc::RTLD_LAZY) };
            if handle.is_null() {
                return Ok(None);
            }
            handle
        } else {
            libc::RTLD_DEFAULT
        };

        let addr = unsafe { lookup_symbol(handle, symbol.as_c_str()) };
        if module_name.is_some() {
            unsafe {
                libc::dlclose(handle);
            }
        }

        Ok(addr)
    }

    pub fn find_symbol_by_address(address: usize) -> Result<Option<SymbolInfo>> {
        let address = normalize_code_pointer(address);
        let mut info = std::mem::MaybeUninit::<libc::Dl_info>::zeroed();
        let result = unsafe { libc::dladdr(address as *const c_void, info.as_mut_ptr()) };
        if result == 0 {
            return Ok(None);
        }

        Ok(symbol_info_from_dl_info(address, unsafe { info.assume_init() }))
    }

    fn resolve_loader_symbols() -> Result<Vec<ResolvedLoaderSymbol>> {
        resolve_loader_symbols_for_specs(&[
            (LoaderSymbolRole::Dlopen, &["dlopen"]),
            (LoaderSymbolRole::Dlsym, &["dlsym"]),
            (LoaderSymbolRole::Socket, &["socket"]),
            (LoaderSymbolRole::Connect, &["connect"]),
            (
                LoaderSymbolRole::ThreadBootstrap,
                &["pthread_create_from_mach_thread", "pthread_create"],
            ),
        ])
    }

    fn resolve_loader_symbols_for_specs(
        specs: &[(LoaderSymbolRole, &'static [&'static str])],
    ) -> Result<Vec<ResolvedLoaderSymbol>> {
        let mut resolved = Vec::with_capacity(specs.len());
        for (role, symbol_names) in specs {
            let mut resolved_symbol = None;
            for symbol_name in *symbol_names {
                if let Some(address) = find_export_by_name(None, symbol_name)? {
                    resolved_symbol = Some((*symbol_name, address));
                    break;
                }
            }
            let (symbol_name, address) = resolved_symbol.ok_or_else(|| {
                common::Error::State(format!(
                    "failed to resolve loader symbol candidates {}",
                    symbol_names.join(", ")
                ))
            })?;
            let canonical_address = normalize_code_pointer(address);
            let image = find_image_by_address(canonical_address)?.ok_or_else(|| {
                common::Error::State(format!(
                    "resolved loader symbol {symbol_name} raw=0x{address:x} canonical=0x{canonical_address:x}, but could not identify its image"
                ))
            })?;
            let offset = crate::loader_symbol_offset_from_canonical_address(
                symbol_name,
                address,
                canonical_address,
                image.base,
            )?;

            resolved.push(ResolvedLoaderSymbol {
                role: *role,
                symbol_name: symbol_name.into(),
                module_name: image.name,
                module_base: image.base,
                raw_address: address,
                address: canonical_address,
                offset,
            });
        }
        Ok(resolved)
    }
}

#[cfg(all(unix, not(any(target_os = "ios", target_os = "macos"))))]
mod platform {
    use std::ffi::{CStr, CString};
    use std::os::raw::c_void;

    use common::Result;

    use crate::{
        injection::{build_injection_plan, LoaderSymbolRole, ResolvedLoaderSymbol},
        normalize_code_pointer, ImageInfo, InjectionPlan, InjectionTarget, InjectionTrace, SymbolInfo,
    };

    fn make_cstring(raw: &str, label: &str) -> Result<CString> {
        CString::new(raw).map_err(|_| common::Error::InvalidArgument(format!("{label} contains an interior NUL byte")))
    }

    unsafe fn lookup_symbol(handle: *mut c_void, symbol: &CStr) -> Option<usize> {
        let addr = libc::dlsym(handle, symbol.as_ptr());
        if addr.is_null() {
            None
        } else {
            Some(addr as usize)
        }
    }

    fn symbol_info_from_dl_info(address: usize, info: libc::Dl_info) -> Option<SymbolInfo> {
        if info.dli_fname.is_null() || info.dli_fbase.is_null() {
            return None;
        }

        let module_name = unsafe { CStr::from_ptr(info.dli_fname) }.to_string_lossy().into_owned();
        let module_base = info.dli_fbase as usize;
        let symbol_name = if info.dli_sname.is_null() {
            None
        } else {
            Some(unsafe { CStr::from_ptr(info.dli_sname) }.to_string_lossy().into_owned())
        };
        let symbol_address = (!info.dli_saddr.is_null()).then_some(info.dli_saddr as usize);
        let offset = symbol_address
            .filter(|symbol_address| address >= *symbol_address)
            .map(|symbol_address| address - symbol_address)
            .or_else(|| (address >= module_base).then_some(address - module_base))
            .unwrap_or(0);

        Some(SymbolInfo {
            module_name,
            module_base,
            symbol_name,
            symbol_address,
            offset,
        })
    }

    pub fn enumerate_images() -> Result<Vec<ImageInfo>> {
        Err(common::Error::Unsupported(
            "dyld image enumeration is only available on Apple targets".into(),
        ))
    }

    pub fn find_image_by_name(module_name: &str) -> Result<Option<ImageInfo>> {
        if module_name.trim().is_empty() {
            return Err(common::Error::InvalidArgument("module name must not be empty".into()));
        }

        Err(common::Error::Unsupported(
            "image lookup by module name is only available on Apple targets".into(),
        ))
    }

    pub fn plan(target: &InjectionTarget) -> Result<InjectionPlan> {
        let plan = build_injection_plan(target)?;
        let loader_symbols = resolve_loader_symbols()?;
        plan.with_loader_symbols(loader_symbols)
    }

    pub fn preflight(_target: &InjectionTarget) -> Result<crate::InjectionTargetPreflightReport> {
        Err(common::Error::Unsupported(
            "Mach injection preflight is only available on Apple targets".into(),
        ))
    }

    pub fn inject_trace_with_preflight(
        _target: &InjectionTarget,
        _preflight: &crate::InjectionTargetPreflightReport,
    ) -> Result<InjectionTrace> {
        Err(common::Error::Unsupported(
            "Mach injection preflight is only available on Apple targets".into(),
        ))
    }

    pub fn inject_trace(target: &InjectionTarget) -> Result<InjectionTrace> {
        let _ = plan(target)?;
        Err(common::Error::Unsupported(
            "Mach injection is only available on Apple targets".into(),
        ))
    }

    pub fn find_image_by_address(address: usize) -> Result<Option<ImageInfo>> {
        let address = normalize_code_pointer(address);
        let mut info = std::mem::MaybeUninit::<libc::Dl_info>::zeroed();
        let result = unsafe { libc::dladdr(address as *const c_void, info.as_mut_ptr()) };
        if result == 0 {
            return Ok(None);
        }

        let info = unsafe { info.assume_init() };
        if info.dli_fname.is_null() || info.dli_fbase.is_null() {
            return Ok(None);
        }

        let name = unsafe { CStr::from_ptr(info.dli_fname) }.to_string_lossy().into_owned();
        Ok(Some(ImageInfo {
            name,
            base: info.dli_fbase as usize,
            slide: 0,
            size: 0,
        }))
    }

    pub fn find_export_by_name(module_name: Option<&str>, symbol_name: &str) -> Result<Option<usize>> {
        if symbol_name.trim().is_empty() {
            return Err(common::Error::InvalidArgument("symbol name must not be empty".into()));
        }

        let symbol = make_cstring(symbol_name, "symbol name")?;

        let handle = if let Some(module_name) = module_name {
            let module_name = make_cstring(module_name, "module name")?;
            let handle = unsafe { libc::dlopen(module_name.as_ptr(), libc::RTLD_LAZY) };
            if handle.is_null() {
                return Ok(None);
            }
            handle
        } else {
            libc::RTLD_DEFAULT
        };

        let addr = unsafe { lookup_symbol(handle, symbol.as_c_str()) };
        if module_name.is_some() {
            unsafe {
                libc::dlclose(handle);
            }
        }

        Ok(addr)
    }

    pub fn find_symbol_by_address(address: usize) -> Result<Option<SymbolInfo>> {
        let address = normalize_code_pointer(address);
        let mut info = std::mem::MaybeUninit::<libc::Dl_info>::zeroed();
        let result = unsafe { libc::dladdr(address as *const c_void, info.as_mut_ptr()) };
        if result == 0 {
            return Ok(None);
        }

        Ok(symbol_info_from_dl_info(address, unsafe { info.assume_init() }))
    }

    fn resolve_loader_symbols() -> Result<Vec<ResolvedLoaderSymbol>> {
        resolve_loader_symbols_for_specs(&[
            (LoaderSymbolRole::Dlopen, &["dlopen"]),
            (LoaderSymbolRole::Dlsym, &["dlsym"]),
            (LoaderSymbolRole::Socket, &["socket"]),
            (LoaderSymbolRole::Connect, &["connect"]),
            (LoaderSymbolRole::ThreadBootstrap, &["pthread_create"]),
        ])
    }

    fn resolve_loader_symbols_for_specs(
        specs: &[(LoaderSymbolRole, &'static [&'static str])],
    ) -> Result<Vec<ResolvedLoaderSymbol>> {
        let mut resolved = Vec::with_capacity(specs.len());
        for (role, symbol_names) in specs {
            let mut resolved_symbol = None;
            for symbol_name in *symbol_names {
                if let Some(address) = find_export_by_name(None, symbol_name)? {
                    resolved_symbol = Some((*symbol_name, address));
                    break;
                }
            }
            let (symbol_name, address) = resolved_symbol.ok_or_else(|| {
                common::Error::State(format!(
                    "failed to resolve loader symbol candidates {}",
                    symbol_names.join(", ")
                ))
            })?;
            let canonical_address = normalize_code_pointer(address);
            let image = find_image_by_address(canonical_address)?.ok_or_else(|| {
                common::Error::State(format!(
                    "resolved loader symbol {symbol_name} raw=0x{address:x} canonical=0x{canonical_address:x}, but could not identify its image"
                ))
            })?;
            let offset = crate::loader_symbol_offset_from_canonical_address(
                symbol_name,
                address,
                canonical_address,
                image.base,
            )?;

            resolved.push(ResolvedLoaderSymbol {
                role: *role,
                symbol_name: symbol_name.into(),
                module_name: image.name,
                module_base: image.base,
                raw_address: address,
                address: canonical_address,
                offset,
            });
        }
        Ok(resolved)
    }
}

#[cfg(not(unix))]
mod platform {
    use common::Result;

    use crate::{injection::build_injection_plan, ImageInfo, InjectionPlan, InjectionTarget, InjectionTrace};

    pub fn enumerate_images() -> Result<Vec<ImageInfo>> {
        Err(common::Error::Unsupported(
            "dyld image enumeration is only available on Apple targets".into(),
        ))
    }

    pub fn find_image_by_name(module_name: &str) -> Result<Option<ImageInfo>> {
        if module_name.trim().is_empty() {
            return Err(common::Error::InvalidArgument("module name must not be empty".into()));
        }

        Err(common::Error::Unsupported(
            "image lookup by module name is only available on Apple targets".into(),
        ))
    }

    pub fn plan(target: &InjectionTarget) -> Result<InjectionPlan> {
        build_injection_plan(target)
    }

    pub fn preflight(_target: &InjectionTarget) -> Result<crate::InjectionTargetPreflightReport> {
        Err(common::Error::Unsupported(
            "Mach injection preflight is only available on Apple targets".into(),
        ))
    }

    pub fn inject_trace_with_preflight(
        _target: &InjectionTarget,
        _preflight: &crate::InjectionTargetPreflightReport,
    ) -> Result<InjectionTrace> {
        Err(common::Error::Unsupported(
            "Mach injection preflight is only available on Apple targets".into(),
        ))
    }

    pub fn inject_trace(target: &InjectionTarget) -> Result<InjectionTrace> {
        let _ = plan(target)?;
        Err(common::Error::Unsupported(
            "Mach injection is only available on Apple targets".into(),
        ))
    }

    pub fn find_image_by_address(_address: usize) -> Result<Option<ImageInfo>> {
        Err(common::Error::Unsupported(
            "image lookup by address is only available on Apple targets".into(),
        ))
    }

    pub fn find_export_by_name(_module_name: Option<&str>, _symbol_name: &str) -> Result<Option<usize>> {
        Err(common::Error::Unsupported(
            "export lookup is only available on Unix-like targets".into(),
        ))
    }

    pub fn find_symbol_by_address(_address: usize) -> Result<Option<SymbolInfo>> {
        Err(common::Error::Unsupported(
            "symbol lookup by address is only available on Unix-like targets".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use common::DEFAULT_AGENT_PATH;

    use super::{
        find_export_by_name, find_image_by_name, find_symbol_by_address, format_hook_environment_brief,
        loader_symbol_offset_from_canonical_address, rebase_loader_symbols_to_images,
        validate_thread_bootstrap_symbol_for_target, HookBackendInfo, HookEnvironmentReport, ImageInfo,
        InjectionTarget, LoaderSymbolRole, MachInjector, ResolvedLoaderSymbol,
    };

    #[test]
    fn image_name_matching_accepts_full_path_and_basename() {
        assert!(find_image_by_name("").is_err());
        assert!(super::image_name_matches(
            "libsystem_malloc.dylib",
            "/usr/lib/system/libsystem_malloc.dylib"
        ));
        assert!(super::image_name_matches(
            "/usr/lib/system/libsystem_malloc.dylib",
            "/usr/lib/system/libsystem_malloc.dylib"
        ));
    }

    #[cfg(unix)]
    #[test]
    fn resolves_export_from_current_process() {
        let addr = find_export_by_name(None, "malloc").expect("resolve malloc");
        assert!(addr.is_some());
    }

    #[cfg(unix)]
    #[test]
    fn returns_none_for_missing_export() {
        let addr =
            find_export_by_name(None, "__ios_rustfrida_symbol_that_does_not_exist__").expect("resolve missing symbol");
        assert!(addr.is_none());
    }

    #[cfg(unix)]
    #[test]
    fn resolves_symbol_from_current_process_address() {
        let malloc = find_export_by_name(None, "malloc")
            .expect("resolve malloc")
            .expect("malloc address");
        let symbol = find_symbol_by_address(malloc).expect("find symbol by address");
        let symbol = symbol.expect("symbol info");
        assert!(!symbol.module_name.is_empty());
        assert!(symbol.symbol_address.is_some());
    }

    #[cfg(unix)]
    #[test]
    fn plan_resolves_loader_symbols() {
        let injector = MachInjector;
        let plan = injector
            .plan(&InjectionTarget {
                pid: 123,
                dylib_path: DEFAULT_AGENT_PATH.into(),
                entry_symbol: "ios_agent_entry".into(),
                socket_path: "/tmp/ios-rustfrida.sock".into(),
            })
            .expect("build plan");

        assert!(!plan.loader_symbols().is_empty());
        assert!(plan
            .loader_symbols()
            .iter()
            .any(|item| item.role == LoaderSymbolRole::Dlopen));
        assert!(plan
            .loader_symbols()
            .iter()
            .any(|item| item.role == LoaderSymbolRole::Dlsym));
        assert!(plan
            .loader_symbols()
            .iter()
            .any(|item| item.role == LoaderSymbolRole::Socket));
        assert!(plan
            .loader_symbols()
            .iter()
            .any(|item| item.role == LoaderSymbolRole::Connect));
        assert!(plan
            .loader_symbols()
            .iter()
            .all(|item| item.address >= item.module_base));
    }

    #[test]
    fn rebases_loader_symbols_against_target_images() {
        let source_symbols = vec![
            ResolvedLoaderSymbol {
                role: LoaderSymbolRole::Dlopen,
                symbol_name: "dlopen".into(),
                module_name: "/usr/lib/libdyld.dylib".into(),
                module_base: 0x1000,
                raw_address: 0x1234,
                address: 0x1234,
                offset: 0x234,
            },
            ResolvedLoaderSymbol {
                role: LoaderSymbolRole::ThreadBootstrap,
                symbol_name: "pthread_create_from_mach_thread".into(),
                module_name: "/usr/lib/system/libsystem_pthread.dylib".into(),
                module_base: 0x2000,
                raw_address: 0x2abc,
                address: 0x2abc,
                offset: 0xabc,
            },
        ];
        let target_images = vec![
            ImageInfo {
                name: "/private/preboot/Cryptexes/OS/usr/lib/libdyld.dylib".into(),
                base: 0x1800_0000_0,
                slide: 0,
                size: 0x20000,
            },
            ImageInfo {
                name: "/usr/lib/system/libsystem_pthread.dylib".into(),
                base: 0x1801_0000_0,
                slide: 0,
                size: 0x30000,
            },
        ];

        let rebased = rebase_loader_symbols_to_images(&source_symbols, &target_images).expect("rebase loader symbols");
        assert_eq!(rebased[0].raw_address, 0x1800_0023_4);
        assert_eq!(rebased[0].address, 0x1800_0023_4);
        assert_eq!(rebased[1].raw_address, 0x1801_00ab_c);
        assert_eq!(rebased[1].address, 0x1801_00ab_c);
    }

    #[test]
    fn loader_symbol_offset_uses_canonical_code_pointer() {
        let offset = loader_symbol_offset_from_canonical_address(
            "pthread_create_from_mach_thread",
            0xabcd_0001_8000_1234,
            0x1800_1234,
            0x1800_0000,
        )
        .expect("canonical offset");

        assert_eq!(offset, 0x1234);
    }

    #[test]
    fn arm64e_thread_bootstrap_fallback_is_rejected_without_override() {
        let symbol = ResolvedLoaderSymbol {
            role: LoaderSymbolRole::ThreadBootstrap,
            symbol_name: "pthread_create".into(),
            module_name: "/usr/lib/system/libsystem_pthread.dylib".into(),
            module_base: 0x1801_0000_0,
            raw_address: 0x1801_0abc,
            address: 0x1801_0abc,
            offset: 0xabc,
        };

        let err = validate_thread_bootstrap_symbol_for_target(Some(true), &symbol).expect_err("fallback rejected");
        assert!(err.to_string().contains("IOS_RUSTFRIDA_ALLOW_ARM64E_PTHREAD_FALLBACK"));
    }

    #[test]
    fn arm64e_thread_bootstrap_preferred_symbol_is_allowed() {
        let symbol = ResolvedLoaderSymbol {
            role: LoaderSymbolRole::ThreadBootstrap,
            symbol_name: "pthread_create_from_mach_thread".into(),
            module_name: "/usr/lib/system/libsystem_pthread.dylib".into(),
            module_base: 0x1801_0000_0,
            raw_address: 0x1801_0abc,
            address: 0x1801_0abc,
            offset: 0xabc,
        };

        validate_thread_bootstrap_symbol_for_target(Some(true), &symbol).expect("preferred symbol allowed");
    }

    #[test]
    fn hook_environment_brief_reports_backend_counts() {
        let summary = format_hook_environment_brief(&HookEnvironmentReport {
            active_backend: Some("ellekit".into()),
            backends: vec![
                HookBackendInfo {
                    id: "substrate".into(),
                    display_name: "Cydia Substrate".into(),
                    loaded_images: vec!["/usr/lib/libsubstrate.dylib".into()],
                    filesystem_paths: Vec::new(),
                },
                HookBackendInfo {
                    id: "ellekit".into(),
                    display_name: "ElleKit".into(),
                    loaded_images: vec!["/usr/lib/libellekit.dylib".into()],
                    filesystem_paths: vec!["/usr/lib/libellekit.dylib".into()],
                },
            ],
            warnings: vec!["multiple hook ecosystems are loaded".into()],
        });

        assert!(summary.contains("active=ellekit"));
        assert!(summary.contains("ellekit(loaded_images=1,filesystem_paths=1)"));
        assert!(summary.contains("substrate(loaded_images=1,filesystem_paths=0)"));
        assert!(summary.contains("warnings=1"));
    }

    #[test]
    fn hook_environment_brief_handles_empty_report() {
        let summary = format_hook_environment_brief(&HookEnvironmentReport {
            active_backend: None,
            backends: Vec::new(),
            warnings: Vec::new(),
        });

        assert_eq!(summary, "active=<none> backends=<none> warnings=0");
    }
}
