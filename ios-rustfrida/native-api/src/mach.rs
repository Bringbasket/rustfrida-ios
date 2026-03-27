use std::ffi::CStr;
use std::thread;
use std::time::{Duration, Instant};

use common::{Error, Result};

use crate::{
    configured_bootstrap_wait_timeout_ms, current_hook_policy, rebase_loader_symbols_to_images,
    validate_thread_bootstrap_symbol_for_target, BootstrapImage, BootstrapResultReport, BootstrapStatus,
    HookEnvironmentReport, ImageInfo, InjectionPlan, InjectionTarget, InjectionTargetPreflightReport,
    InjectionTrace, LoaderSymbolRole, RemoteProtectionOutcome, RemoteThreadTerminationOutcome,
    ResolvedLoaderSymbol, ThreadBootstrapKind, ThreadCreatePlan,
};
use crate::jailbreak::{detect_hook_environment_from_image_names, resolve_hook_strategy_for_report};

type KernReturn = i32;
type MachPort = u32;
type Task = MachPort;
type ThreadAct = MachPort;
type MachVmAddress = u64;
type MachVmSize = u64;
type VmOffset = usize;
type MachMsgTypeNumber = u32;
type Integer = i32;
type VmProt = i32;

const KERN_SUCCESS: KernReturn = 0;
const KERN_INVALID_ADDRESS: KernReturn = 1;
const KERN_PROTECTION_FAILURE: KernReturn = 2;
const KERN_NO_SPACE: KernReturn = 3;
const KERN_INVALID_ARGUMENT: KernReturn = 4;
const KERN_FAILURE: KernReturn = 5;
const KERN_RESOURCE_SHORTAGE: KernReturn = 6;
const KERN_NOT_RECEIVER: KernReturn = 7;
const KERN_NO_ACCESS: KernReturn = 8;
const KERN_MEMORY_FAILURE: KernReturn = 9;
const KERN_MEMORY_ERROR: KernReturn = 10;
const TASK_DYLD_INFO: u32 = 17;
const VM_FLAGS_ANYWHERE: i32 = 1;
const VM_PROT_READ: VmProt = 1;
const VM_PROT_WRITE: VmProt = 2;
const VM_PROT_EXECUTE: VmProt = 4;
const VM_PROT_BOOTSTRAP_CODE: VmProt = VM_PROT_READ | VM_PROT_EXECUTE;
const VM_PROT_BOOTSTRAP_DATA: VmProt = VM_PROT_READ | VM_PROT_WRITE;
const MAX_REMOTE_CSTRING_LEN: usize = 4096;
const REMOTE_CSTRING_CHUNK: usize = 256;
const BOOTSTRAP_STATUS_POLL_INTERVAL: Duration = Duration::from_millis(25);
const MH_MAGIC_64: u32 = 0xfeedfacf;
const CPU_TYPE_ARM64: i32 = 0x0100000c;
const CPU_SUBTYPE_ARM64E: i32 = 2;

extern "C" {
    static mach_task_self_: MachPort;

    fn task_for_pid(target_tport: MachPort, pid: libc::c_int, task: *mut Task) -> KernReturn;
    fn task_info(
        target_task: Task,
        flavor: u32,
        task_info_out: *mut Integer,
        task_info_out_count: *mut MachMsgTypeNumber,
    ) -> KernReturn;
    fn mach_vm_allocate(target: Task, address: *mut MachVmAddress, size: MachVmSize, flags: i32) -> KernReturn;
    fn mach_vm_read_overwrite(
        target_task: Task,
        address: MachVmAddress,
        size: MachVmSize,
        data: MachVmAddress,
        outsize: *mut MachVmSize,
    ) -> KernReturn;
    fn mach_vm_write(target: Task, address: MachVmAddress, data: VmOffset, data_count: MachMsgTypeNumber)
        -> KernReturn;
    fn mach_vm_protect(
        target_task: Task,
        address: MachVmAddress,
        size: MachVmSize,
        set_maximum: i32,
        new_protection: VmProt,
    ) -> KernReturn;
    fn mach_vm_deallocate(target: Task, address: MachVmAddress, size: MachVmSize) -> KernReturn;
    fn thread_create_running(
        task: Task,
        flavor: u32,
        new_state: *const u32,
        new_state_count: MachMsgTypeNumber,
        child_act: *mut ThreadAct,
    ) -> KernReturn;
    fn thread_terminate(target_act: ThreadAct) -> KernReturn;
    fn mach_port_deallocate(task: MachPort, name: MachPort) -> KernReturn;
    fn mach_error_string(error_value: KernReturn) -> *const libc::c_char;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootstrapWriteTrace {
    pub payload_address: u64,
    pub payload_size: usize,
    pub payload_allocated_size: usize,
    pub data_address: u64,
    pub data_size: usize,
    pub data_allocated_size: usize,
    pub stack_address: u64,
    pub stack_size: usize,
    pub target_uses_arm64e: Option<bool>,
    pub code_protection: RemoteProtectionOutcome,
    pub data_protection: RemoteProtectionOutcome,
    pub thread_bootstrap_kind: ThreadBootstrapKind,
    pub thread_bootstrap_label: String,
    pub thread_plan: ThreadCreatePlan,
    pub cleaned_up: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct MachTask {
    raw: Task,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RemoteAllocation {
    task: MachTask,
    address: MachVmAddress,
    size: MachVmSize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PreparedRemoteBootstrap {
    task: MachTask,
    code: RemoteAllocation,
    data: RemoteAllocation,
    stack: RemoteAllocation,
    bootstrap: BootstrapImage,
    target_uses_arm64e: Option<bool>,
    code_protection: RemoteProtectionOutcome,
    data_protection: RemoteProtectionOutcome,
    thread_bootstrap_kind: ThreadBootstrapKind,
    thread_bootstrap_label: String,
    thread_plan: ThreadCreatePlan,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PreparedThreadBootstrap {
    kind: ThreadBootstrapKind,
    label: String,
    entry_pc: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RemoteTargetAnalysis {
    remote_image_count: usize,
    main_image: Option<ImageInfo>,
    remote_images: Vec<ImageInfo>,
    target_uses_arm64e: Option<bool>,
    remote_loader_symbols: Vec<ResolvedLoaderSymbol>,
    thread_bootstrap: PreparedThreadBootstrap,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct TaskDyldInfo {
    all_image_info_addr: u64,
    all_image_info_size: u64,
    all_image_info_format: i32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct DyldAllImageInfosHeader {
    version: u32,
    info_array_count: u32,
    info_array: u64,
    notification: u64,
    process_detached_from_shared_region: u8,
    lib_system_initialized: u8,
    padding: [u8; 6],
    dyld_image_load_address: u64,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct DyldImageInfo {
    image_load_address: u64,
    image_file_path: u64,
    image_file_mod_date: u64,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
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

impl MachTask {
    fn for_pid(pid: i32) -> Result<Self> {
        let mut task = 0;
        let kr = unsafe { task_for_pid(mach_task_self_, pid as libc::c_int, &mut task) };
        if kr != KERN_SUCCESS {
            return Err(mach_error("task_for_pid", kr));
        }
        Ok(Self { raw: task })
    }
}

impl RemoteAllocation {
    fn allocate(task: MachTask, size: usize) -> Result<Self> {
        let size = page_align_up(size as MachVmSize)?;
        let mut address = 0;
        let kr = unsafe { mach_vm_allocate(task.raw, &mut address, size, VM_FLAGS_ANYWHERE) };
        if kr != KERN_SUCCESS {
            return Err(mach_error("mach_vm_allocate", kr));
        }

        Ok(Self { task, address, size })
    }

    fn write(&self, bytes: &[u8]) -> Result<()> {
        if bytes.len() > u32::MAX as usize {
            return Err(Error::InvalidArgument(
                "bootstrap image exceeds mach_vm_write size limit".into(),
            ));
        }

        let kr = unsafe {
            mach_vm_write(
                self.task.raw,
                self.address,
                bytes.as_ptr() as VmOffset,
                bytes.len() as MachMsgTypeNumber,
            )
        };
        if kr != KERN_SUCCESS {
            return Err(mach_error("mach_vm_write", kr));
        }
        Ok(())
    }

    fn deallocate(self) -> Result<()> {
        let kr = unsafe { mach_vm_deallocate(self.task.raw, self.address, self.size) };
        if kr != KERN_SUCCESS {
            return Err(mach_error("mach_vm_deallocate", kr));
        }
        Ok(())
    }

    fn protect(&self, protection: VmProt) -> Result<RemoteProtectionOutcome> {
        let set_maximum = unsafe { mach_vm_protect(self.task.raw, self.address, self.size, 1, protection) };
        let kr = unsafe { mach_vm_protect(self.task.raw, self.address, self.size, 0, protection) };
        if set_maximum == KERN_SUCCESS && kr == KERN_SUCCESS {
            return Ok(RemoteProtectionOutcome::SetMaximumAndCurrent);
        }

        if set_maximum != KERN_SUCCESS && kr == KERN_SUCCESS {
            return Ok(RemoteProtectionOutcome::CurrentOnlyFallback);
        }

        if set_maximum != KERN_SUCCESS {
            return Err(Error::State(format!(
                "{}; fallback current protection also failed: {}",
                mach_error_message("mach_vm_protect(set_maximum)", set_maximum),
                mach_error_message("mach_vm_protect", kr)
            )));
        }

        Err(mach_error("mach_vm_protect", kr))
    }
}

pub fn dry_run_write_bootstrap(target: &InjectionTarget, plan: &InjectionPlan) -> Result<BootstrapWriteTrace> {
    let prepared = prepare_remote_bootstrap(target, plan)?;
    build_bootstrap_write_trace(prepared)
}

pub fn dry_run_write_bootstrap_with_preflight(
    plan: &InjectionPlan,
    preflight: &InjectionTargetPreflightReport,
) -> Result<BootstrapWriteTrace> {
    let prepared = prepare_remote_bootstrap_with_preflight(plan, preflight)?;
    build_bootstrap_write_trace(prepared)
}

fn build_bootstrap_write_trace(prepared: PreparedRemoteBootstrap) -> Result<BootstrapWriteTrace> {
    let payload_address = prepared.code.address;
    let payload_size = prepared.bootstrap.code_size();
    let payload_allocated_size = prepared.code.size as usize;
    let data_address = prepared.data.address;
    let data_size = prepared.bootstrap.data_size();
    let data_allocated_size = prepared.data.size as usize;
    let stack_address = prepared.stack.address;
    let stack_size = prepared.stack.size as usize;
    let target_uses_arm64e = prepared.target_uses_arm64e;
    let code_protection = prepared.code_protection;
    let data_protection = prepared.data_protection;
    let thread_bootstrap_kind = prepared.thread_bootstrap_kind;
    let thread_bootstrap_label = prepared.thread_bootstrap_label.clone();
    let thread_plan = prepared.thread_plan;
    cleanup_prepared_bootstrap(prepared)?;

    Ok(BootstrapWriteTrace {
        payload_address,
        payload_size,
        payload_allocated_size,
        data_address,
        data_size,
        data_allocated_size,
        stack_address,
        stack_size,
        target_uses_arm64e,
        code_protection,
        data_protection,
        thread_bootstrap_kind,
        thread_bootstrap_label,
        thread_plan,
        cleaned_up: true,
    })
}

pub fn preflight_target(target: &InjectionTarget, plan: &InjectionPlan) -> Result<InjectionTargetPreflightReport> {
    let task = MachTask::for_pid(target.pid)?;
    let analysis = analyze_remote_target(task, plan.loader_symbols())?;
    let target_hook_environment = probe_remote_hook_environment(task)?;
    let target_hook_strategy = resolve_hook_strategy_for_report(&target_hook_environment, current_hook_policy());
    let thread_entry = analysis
        .remote_loader_symbols
        .iter()
        .find(|symbol| symbol.role == LoaderSymbolRole::ThreadBootstrap)
        .ok_or_else(|| Error::State("missing rebased thread bootstrap loader symbol".into()))?;

    Ok(InjectionTargetPreflightReport {
        main_image: analysis.main_image,
        target_images: analysis.remote_images,
        target_image_count: analysis.remote_image_count,
        target_uses_arm64e: analysis.target_uses_arm64e,
        thread_bootstrap_kind: analysis.thread_bootstrap.kind,
        thread_bootstrap_label: analysis.thread_bootstrap.label,
        thread_bootstrap_address: thread_entry.address,
        thread_bootstrap_raw_address: thread_entry.raw_address,
        thread_bootstrap_canonicalized: thread_entry.is_canonicalized(),
        target_hook_environment,
        target_hook_strategy,
        resolved_loader_symbols: analysis.remote_loader_symbols,
    })
}

pub fn probe_remote_hook_environment_for_pid(pid: i32) -> Result<HookEnvironmentReport> {
    let task = MachTask::for_pid(pid)?;
    probe_remote_hook_environment(task)
}

pub fn start_remote_thread(target: &InjectionTarget, plan: &InjectionPlan) -> Result<InjectionTrace> {
    let prepared = prepare_remote_bootstrap(target, plan)?;
    build_start_remote_thread_trace(prepared)
}

pub fn start_remote_thread_with_preflight(
    plan: &InjectionPlan,
    preflight: &InjectionTargetPreflightReport,
) -> Result<InjectionTrace> {
    let prepared = prepare_remote_bootstrap_with_preflight(plan, preflight)?;
    build_start_remote_thread_trace(prepared)
}

fn build_start_remote_thread_trace(prepared: PreparedRemoteBootstrap) -> Result<InjectionTrace> {
    let payload_address = prepared.code.address;
    let payload_size = prepared.bootstrap.code_size();
    let payload_allocated_size = prepared.code.size as usize;
    let data_address = prepared.data.address;
    let data_size = prepared.bootstrap.data_size();
    let data_allocated_size = prepared.data.size as usize;
    let stack_address = prepared.stack.address;
    let stack_size = prepared.stack.size as usize;
    let target_uses_arm64e = prepared.target_uses_arm64e;
    let code_protection = prepared.code_protection;
    let data_protection = prepared.data_protection;
    let thread_bootstrap_kind = prepared.thread_bootstrap_kind;
    let thread_bootstrap_label = prepared.thread_bootstrap_label.clone();
    let thread_plan = prepared.thread_plan;

    let mut thread_port = 0;
    let kr = unsafe {
        thread_create_running(
            prepared.task.raw,
            thread_plan.flavor,
            &thread_plan.state as *const _ as *const u32,
            thread_plan.count,
            &mut thread_port,
        )
    };
    if kr != KERN_SUCCESS {
        cleanup_prepared_bootstrap(prepared)?;
        return Err(mach_error("thread_create_running", kr));
    }

    let (bootstrap_report, bootstrap_timed_out) = wait_for_bootstrap_result(&prepared, bootstrap_wait_timeout())?;
    let should_cleanup_resources = bootstrap_report
        .map(|report| report.status.is_failure() || matches!(report.status, BootstrapStatus::EntryReturned))
        .unwrap_or(false);
    let thread_termination = if should_cleanup_resources {
        if unsafe { thread_terminate(thread_port) } == KERN_SUCCESS {
            RemoteThreadTerminationOutcome::Terminated
        } else {
            RemoteThreadTerminationOutcome::Failed
        }
    } else {
        RemoteThreadTerminationOutcome::NotAttempted
    };
    let resources_persist = !should_cleanup_resources;

    if should_cleanup_resources {
        cleanup_prepared_bootstrap(prepared)?;
    }
    let thread_port_deallocated = unsafe { mach_port_deallocate(mach_task_self_, thread_port) == KERN_SUCCESS };

    Ok(InjectionTrace {
        payload_address,
        payload_size,
        payload_allocated_size,
        data_address,
        data_size,
        data_allocated_size,
        stack_address,
        stack_size,
        target_uses_arm64e,
        code_protection,
        data_protection,
        thread_bootstrap_kind,
        thread_bootstrap_label,
        thread_plan,
        thread_port: Some(thread_port),
        thread_termination,
        thread_port_deallocated,
        resources_persist,
        bootstrap_report,
        bootstrap_timed_out,
    })
}

fn prepare_remote_bootstrap(target: &InjectionTarget, plan: &InjectionPlan) -> Result<PreparedRemoteBootstrap> {
    let task = MachTask::for_pid(target.pid)?;
    let analysis = analyze_remote_target(task, plan.loader_symbols())?;
    prepare_remote_bootstrap_with_analysis(task, plan, analysis)
}

fn prepare_remote_bootstrap_with_preflight(
    plan: &InjectionPlan,
    preflight: &InjectionTargetPreflightReport,
) -> Result<PreparedRemoteBootstrap> {
    let task = MachTask::for_pid(plan.target.pid)?;
    prepare_remote_bootstrap_with_analysis(task, plan, analysis_from_preflight(preflight))
}

fn prepare_remote_bootstrap_with_analysis(
    task: MachTask,
    plan: &InjectionPlan,
    analysis: RemoteTargetAnalysis,
) -> Result<PreparedRemoteBootstrap> {
    let remote_bootstrap = rebind_bootstrap(plan.bootstrap(), &analysis.remote_loader_symbols)?;

    let code = RemoteAllocation::allocate(task, remote_bootstrap.code_size())?;
    let data = match RemoteAllocation::allocate(task, remote_bootstrap.data_size()) {
        Ok(data) => data,
        Err(err) => {
            let _ = code.deallocate();
            return Err(err);
        }
    };
    let stack = match RemoteAllocation::allocate(task, remote_bootstrap.stack_size() as usize) {
        Ok(stack) => stack,
        Err(err) => {
            let _ = data.deallocate();
            let _ = code.deallocate();
            return Err(err);
        }
    };

    let thread_plan = remote_bootstrap
        .thread_launch(
            code.address,
            data.address,
            stack.address,
            analysis.thread_bootstrap.entry_pc,
        )
        .thread_state();

    if let Err(err) = code.write(remote_bootstrap.code_bytes()) {
        let _ = stack.deallocate();
        let _ = data.deallocate();
        let _ = code.deallocate();
        return Err(err);
    }
    if let Err(err) = data.write(remote_bootstrap.data_bytes()) {
        let _ = stack.deallocate();
        let _ = data.deallocate();
        let _ = code.deallocate();
        return Err(err);
    }
    let code_protection = match code.protect(VM_PROT_BOOTSTRAP_CODE) {
        Ok(outcome) => outcome,
        Err(err) => {
            let _ = stack.deallocate();
            let _ = data.deallocate();
            let _ = code.deallocate();
            return Err(err);
        }
    };
    let data_protection = match data.protect(VM_PROT_BOOTSTRAP_DATA) {
        Ok(outcome) => outcome,
        Err(err) => {
            let _ = stack.deallocate();
            let _ = data.deallocate();
            let _ = code.deallocate();
            return Err(err);
        }
    };

    Ok(PreparedRemoteBootstrap {
        task,
        code,
        data,
        stack,
        bootstrap: remote_bootstrap,
        target_uses_arm64e: analysis.target_uses_arm64e,
        code_protection,
        data_protection,
        thread_bootstrap_kind: analysis.thread_bootstrap.kind,
        thread_bootstrap_label: analysis.thread_bootstrap.label,
        thread_plan,
    })
}

fn analyze_remote_target(task: MachTask, loader_symbols: &[ResolvedLoaderSymbol]) -> Result<RemoteTargetAnalysis> {
    let remote_images = enumerate_remote_images(task)?;
    let remote_image_count = remote_images.len();
    let main_image = remote_images.first().cloned();
    let remote_loader_symbols = resolve_target_loader_symbols_from_images(loader_symbols, &remote_images)?;
    let target_uses_arm64e = detect_remote_arm64e(task, &remote_images)?;
    let thread_bootstrap = prepare_thread_bootstrap(&remote_loader_symbols, target_uses_arm64e)?;

    Ok(RemoteTargetAnalysis {
        remote_image_count,
        main_image,
        remote_images,
        target_uses_arm64e,
        remote_loader_symbols,
        thread_bootstrap,
    })
}

fn analysis_from_preflight(preflight: &InjectionTargetPreflightReport) -> RemoteTargetAnalysis {
    RemoteTargetAnalysis {
        remote_image_count: preflight.target_image_count,
        main_image: preflight.main_image.clone(),
        remote_images: preflight.target_images.clone(),
        target_uses_arm64e: preflight.target_uses_arm64e,
        remote_loader_symbols: preflight.resolved_loader_symbols.clone(),
        thread_bootstrap: PreparedThreadBootstrap {
            kind: preflight.thread_bootstrap_kind,
            label: preflight.thread_bootstrap_label.clone(),
            entry_pc: preflight.thread_bootstrap_address as u64,
        },
    }
}

fn prepare_thread_bootstrap(
    remote_loader_symbols: &[ResolvedLoaderSymbol],
    target_uses_arm64e: Option<bool>,
) -> Result<PreparedThreadBootstrap> {
    let thread_entry = remote_loader_symbols
        .iter()
        .find(|symbol| symbol.role == LoaderSymbolRole::ThreadBootstrap)
        .ok_or_else(|| Error::State("missing rebased thread bootstrap loader symbol".into()))?;
    validate_thread_bootstrap_symbol_for_target(target_uses_arm64e, thread_entry)?;

    Ok(PreparedThreadBootstrap {
        kind: thread_entry
            .thread_bootstrap_kind()
            .unwrap_or(ThreadBootstrapKind::Other),
        label: format!(
            "{}!{}+0x{:x}",
            thread_entry.module_name, thread_entry.symbol_name, thread_entry.offset
        ),
        entry_pc: thread_entry.address as u64,
    })
}

fn wait_for_bootstrap_result(
    prepared: &PreparedRemoteBootstrap,
    timeout: Option<Duration>,
) -> Result<(Option<BootstrapResultReport>, bool)> {
    let Some(timeout) = timeout else {
        return Ok((None, false));
    };

    let deadline = Instant::now() + timeout;
    loop {
        let report = read_bootstrap_report(prepared)?;
        if !matches!(report.status, BootstrapStatus::Pending) {
            return Ok((Some(report), false));
        }
        if Instant::now() >= deadline {
            return Ok((Some(report), true));
        }
        thread::sleep(BOOTSTRAP_STATUS_POLL_INTERVAL);
    }
}

fn read_bootstrap_report(prepared: &PreparedRemoteBootstrap) -> Result<BootstrapResultReport> {
    let base = prepared.data.address;
    let bootstrap = &prepared.bootstrap;
    let status_raw = read_struct::<u32>(
        prepared.task,
        base + bootstrap.data_relative_offset(bootstrap.status_offset),
    )?;
    let dylib_handle = read_struct::<u64>(
        prepared.task,
        base + bootstrap.data_relative_offset(bootstrap.dylib_handle_offset),
    )?;
    let entry_address = read_struct::<u64>(
        prepared.task,
        base + bootstrap.data_relative_offset(bootstrap.entry_address_result_offset),
    )?;
    let socket_fd = read_struct::<i32>(
        prepared.task,
        base + bootstrap.data_relative_offset(bootstrap.socket_fd_offset),
    )?;
    let entry_return = read_struct::<i32>(
        prepared.task,
        base + bootstrap.data_relative_offset(bootstrap.entry_return_offset),
    )?;

    Ok(BootstrapResultReport {
        status: BootstrapStatus::from_raw(status_raw),
        status_raw,
        dylib_handle,
        entry_address,
        socket_fd,
        entry_return,
    })
}

fn cleanup_prepared_bootstrap(prepared: PreparedRemoteBootstrap) -> Result<()> {
    let code_cleanup = prepared.code.deallocate();
    let data_cleanup = prepared.data.deallocate();
    let stack_cleanup = prepared.stack.deallocate();
    code_cleanup?;
    data_cleanup?;
    stack_cleanup?;
    Ok(())
}

fn resolve_target_loader_symbols_from_images(
    source_symbols: &[ResolvedLoaderSymbol],
    remote_images: &[ImageInfo],
) -> Result<Vec<ResolvedLoaderSymbol>> {
    rebase_loader_symbols_to_images(source_symbols, remote_images)
}

fn detect_remote_arm64e(task: MachTask, remote_images: &[ImageInfo]) -> Result<Option<bool>> {
    let Some(main_image) = remote_images.first() else {
        return Ok(None);
    };

    let header = read_struct::<MachHeader64>(task, main_image.base as u64)?;
    if header.magic != MH_MAGIC_64 || header.cputype != CPU_TYPE_ARM64 {
        return Ok(Some(false));
    }

    Ok(Some((header.cpusubtype & 0xff) == CPU_SUBTYPE_ARM64E))
}

fn rebind_bootstrap(bootstrap: &BootstrapImage, loader_symbols: &[ResolvedLoaderSymbol]) -> Result<BootstrapImage> {
    let mut rebound = bootstrap.clone();
    let dlopen = loader_symbols
        .iter()
        .find(|symbol| symbol.role == LoaderSymbolRole::Dlopen)
        .ok_or_else(|| Error::State("missing rebased dlopen symbol".into()))?;
    let dlsym = loader_symbols
        .iter()
        .find(|symbol| symbol.role == LoaderSymbolRole::Dlsym)
        .ok_or_else(|| Error::State("missing rebased dlsym symbol".into()))?;
    let socket = loader_symbols
        .iter()
        .find(|symbol| symbol.role == LoaderSymbolRole::Socket)
        .ok_or_else(|| Error::State("missing rebased socket symbol".into()))?;
    let connect = loader_symbols
        .iter()
        .find(|symbol| symbol.role == LoaderSymbolRole::Connect)
        .ok_or_else(|| Error::State("missing rebased connect symbol".into()))?;

    write_u64(
        &mut rebound.bytes,
        rebound.dlopen_ptr_offset as usize,
        dlopen.address as u64,
    );
    write_u64(
        &mut rebound.bytes,
        rebound.dlsym_ptr_offset as usize,
        dlsym.address as u64,
    );
    write_u64(
        &mut rebound.bytes,
        rebound.socket_ptr_offset as usize,
        socket.address as u64,
    );
    write_u64(
        &mut rebound.bytes,
        rebound.connect_ptr_offset as usize,
        connect.address as u64,
    );
    Ok(rebound)
}

fn enumerate_remote_images(task: MachTask) -> Result<Vec<ImageInfo>> {
    let dyld_info = read_task_dyld_info(task)?;
    let all_images = read_struct::<DyldAllImageInfosHeader>(task, dyld_info.all_image_info_addr)?;
    let image_infos = read_array::<DyldImageInfo>(task, all_images.info_array, all_images.info_array_count as usize)?;

    let mut images = Vec::with_capacity(image_infos.len());
    for image in image_infos {
        if image.image_load_address == 0 || image.image_file_path == 0 {
            continue;
        }

        let name = read_cstring(task, image.image_file_path, MAX_REMOTE_CSTRING_LEN)?;
        images.push(ImageInfo {
            name,
            base: image.image_load_address as usize,
            slide: 0,
            size: 0,
        });
    }
    Ok(images)
}

fn probe_remote_hook_environment(task: MachTask) -> Result<HookEnvironmentReport> {
    let image_names = enumerate_remote_images(task)?
        .into_iter()
        .map(|image| image.name)
        .collect::<Vec<_>>();
    Ok(detect_hook_environment_from_image_names(&image_names))
}

fn read_task_dyld_info(task: MachTask) -> Result<TaskDyldInfo> {
    let mut info = TaskDyldInfo {
        all_image_info_addr: 0,
        all_image_info_size: 0,
        all_image_info_format: 0,
    };
    let mut count = (std::mem::size_of::<TaskDyldInfo>() / std::mem::size_of::<Integer>()) as MachMsgTypeNumber;
    let kr = unsafe {
        task_info(
            task.raw,
            TASK_DYLD_INFO,
            &mut info as *mut _ as *mut Integer,
            &mut count,
        )
    };
    if kr != KERN_SUCCESS {
        return Err(mach_error("task_info(TASK_DYLD_INFO)", kr));
    }
    if info.all_image_info_addr == 0 {
        return Err(Error::State("target task did not expose dyld image info".into()));
    }
    Ok(info)
}

fn read_struct<T: Copy>(task: MachTask, address: u64) -> Result<T> {
    let mut value = std::mem::MaybeUninit::<T>::uninit();
    let size = std::mem::size_of::<T>() as u64;
    let mut outsize = 0u64;
    let kr = unsafe {
        mach_vm_read_overwrite(
            task.raw,
            address,
            size,
            value.as_mut_ptr() as MachVmAddress,
            &mut outsize,
        )
    };
    if kr != KERN_SUCCESS {
        return Err(mach_error("mach_vm_read_overwrite", kr));
    }
    if outsize != size {
        return Err(Error::State(format!(
            "mach_vm_read_overwrite returned {} bytes, expected {}",
            outsize, size
        )));
    }
    Ok(unsafe { value.assume_init() })
}

fn read_bytes(task: MachTask, address: u64, size: usize) -> Result<Vec<u8>> {
    let mut bytes = vec![0u8; size];
    let mut outsize = 0u64;
    let kr = unsafe {
        mach_vm_read_overwrite(
            task.raw,
            address,
            size as u64,
            bytes.as_mut_ptr() as MachVmAddress,
            &mut outsize,
        )
    };
    if kr != KERN_SUCCESS {
        return Err(mach_error("mach_vm_read_overwrite", kr));
    }
    if outsize != size as u64 {
        return Err(Error::State(format!(
            "mach_vm_read_overwrite returned {} bytes, expected {}",
            outsize, size
        )));
    }
    Ok(bytes)
}

fn read_array<T: Copy>(task: MachTask, address: u64, count: usize) -> Result<Vec<T>> {
    let size = std::mem::size_of::<T>()
        .checked_mul(count)
        .ok_or_else(|| Error::State("remote array size overflow".into()))?;
    let bytes = read_bytes(task, address, size)?;
    let mut values = Vec::with_capacity(count);
    for index in 0..count {
        let start = index * std::mem::size_of::<T>();
        let value = unsafe { std::ptr::read_unaligned(bytes[start..].as_ptr() as *const T) };
        values.push(value);
    }
    Ok(values)
}

fn read_cstring(task: MachTask, address: u64, max_len: usize) -> Result<String> {
    let mut bytes = Vec::new();
    let mut cursor = address;
    while bytes.len() < max_len {
        let chunk_len = std::cmp::min(REMOTE_CSTRING_CHUNK, max_len - bytes.len());
        let chunk = read_bytes(task, cursor, chunk_len)?;
        if let Some(pos) = chunk.iter().position(|byte| *byte == 0) {
            bytes.extend_from_slice(&chunk[..pos]);
            return Ok(String::from_utf8_lossy(&bytes).into_owned());
        }
        bytes.extend_from_slice(&chunk);
        cursor += chunk_len as u64;
    }
    Err(Error::State(format!(
        "remote C string at 0x{address:x} exceeded {} bytes",
        max_len
    )))
}

fn write_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn page_size() -> MachVmSize {
    let value = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if value <= 0 {
        0x1000
    } else {
        value as MachVmSize
    }
}

fn page_align_up(value: MachVmSize) -> Result<MachVmSize> {
    let alignment = page_size();
    let remainder = value % alignment;
    if remainder == 0 {
        return Ok(value);
    }
    value
        .checked_add(alignment - remainder)
        .ok_or_else(|| Error::State(format!("page alignment overflow for allocation size 0x{value:x}")))
}

fn mach_error_message(stage: &str, kr: KernReturn) -> String {
    let message = unsafe {
        let ptr = mach_error_string(kr);
        if ptr.is_null() {
            None
        } else {
            Some(CStr::from_ptr(ptr).to_string_lossy().into_owned())
        }
    };
    let kern_label = kern_return_label(kr).unwrap_or("unknown");

    match message {
        Some(message) if !message.trim().is_empty() => {
            format!("{stage} failed: {message} ({kr:#x}, {kern_label})")
        }
        _ => format!("{stage} failed with kern_return_t={kr:#x} ({kern_label})"),
    }
}

fn mach_error(stage: &str, kr: KernReturn) -> Error {
    let base = mach_error_message(stage, kr);
    let mut details = Vec::new();
    if let Some(hint) = mach_failure_hint(stage, kr) {
        details.push(hint);
    }
    if stage == "task_for_pid" {
        details.push(
            "verify jailbreak/root context, task_for_pid entitlement/exception, and that the target process is not protected by platform restrictions",
        );
    }

    if details.is_empty() {
        Error::State(base)
    } else {
        Error::State(format!("{base}; {}", details.join("; ")))
    }
}

fn kern_return_label(kr: KernReturn) -> Option<&'static str> {
    match kr {
        KERN_SUCCESS => Some("success"),
        KERN_INVALID_ADDRESS => Some("invalid-address"),
        KERN_PROTECTION_FAILURE => Some("protection-failure"),
        KERN_NO_SPACE => Some("no-space"),
        KERN_INVALID_ARGUMENT => Some("invalid-argument"),
        KERN_FAILURE => Some("failure"),
        KERN_RESOURCE_SHORTAGE => Some("resource-shortage"),
        KERN_NOT_RECEIVER => Some("not-receiver"),
        KERN_NO_ACCESS => Some("no-access"),
        KERN_MEMORY_FAILURE => Some("memory-failure"),
        KERN_MEMORY_ERROR => Some("memory-error"),
        _ => None,
    }
}

fn mach_failure_hint(stage: &str, kr: KernReturn) -> Option<&'static str> {
    match stage {
        "task_for_pid" => match kr {
            KERN_FAILURE => Some(
                "task port acquisition was denied by the kernel; this usually means missing entitlement/exception handling or a platform-protected target",
            ),
            KERN_NO_ACCESS | KERN_PROTECTION_FAILURE => Some(
                "task port access was blocked; check jailbreak privilege escalation, platform binary restrictions, and whether the target is protected",
            ),
            KERN_INVALID_ARGUMENT => Some(
                "the target pid or task_for_pid arguments were rejected; confirm the process still exists and that the pid is correct",
            ),
            _ => None,
        },
        "mach_vm_allocate" => match kr {
            KERN_NO_SPACE | KERN_RESOURCE_SHORTAGE => Some(
                "remote allocation failed due to address-space pressure or resource shortage; retry with a smaller target or after freeing memory",
            ),
            KERN_NO_ACCESS | KERN_PROTECTION_FAILURE => Some(
                "remote allocation was blocked by the target task's protection state; check jailbreak privileges and platform protection",
            ),
            _ => None,
        },
        "mach_vm_write" => match kr {
            KERN_PROTECTION_FAILURE | KERN_NO_ACCESS => Some(
                "remote memory write was blocked; verify the target task port is usable and that the allocated pages are writable",
            ),
            KERN_INVALID_ADDRESS => Some(
                "remote memory write targeted an invalid address; check earlier allocation and bootstrap layout calculations",
            ),
            _ => None,
        },
        "mach_vm_read_overwrite" => match kr {
            KERN_PROTECTION_FAILURE | KERN_NO_ACCESS => Some(
                "remote memory read was blocked; the target task may be protected or the address may not be readable",
            ),
            KERN_INVALID_ADDRESS | KERN_MEMORY_ERROR | KERN_MEMORY_FAILURE => Some(
                "remote memory read hit an invalid or unmapped address; the target's dyld/image metadata may have changed or the task port may be stale",
            ),
            _ => None,
        },
        "mach_vm_protect" | "mach_vm_protect(set_maximum)" => match kr {
            KERN_PROTECTION_FAILURE | KERN_NO_ACCESS => Some(
                "remote page protection change was denied; some targets reject executable or writable transitions even with a task port",
            ),
            KERN_INVALID_ADDRESS => Some(
                "remote page protection targeted an invalid range; verify page alignment and allocation bookkeeping",
            ),
            _ => None,
        },
        "thread_create_running" => match kr {
            KERN_FAILURE | KERN_NO_ACCESS | KERN_PROTECTION_FAILURE => Some(
                "remote thread creation was denied; check task privileges, platform protection, and whether the chosen bootstrap entry is acceptable for this target",
            ),
            KERN_INVALID_ARGUMENT => Some(
                "remote thread state was rejected; verify the bootstrap register layout and thread state flavor/count",
            ),
            _ => None,
        },
        "task_info(TASK_DYLD_INFO)" => match kr {
            KERN_FAILURE | KERN_NO_ACCESS | KERN_PROTECTION_FAILURE => Some(
                "reading remote dyld metadata was denied; preflight cannot continue until the task port has sufficient access",
            ),
            _ => None,
        },
        _ => None,
    }
}

fn bootstrap_wait_timeout() -> Option<Duration> {
    configured_bootstrap_wait_timeout_ms().map(Duration::from_millis)
}

#[cfg(test)]
mod tests {
    use super::{
        kern_return_label, mach_error, mach_error_message, mach_failure_hint, KERN_FAILURE, KERN_INVALID_ARGUMENT,
        KERN_NO_SPACE, KERN_PROTECTION_FAILURE,
    };

    #[test]
    fn kern_return_labels_cover_common_codes() {
        assert_eq!(kern_return_label(KERN_FAILURE), Some("failure"));
        assert_eq!(kern_return_label(KERN_NO_SPACE), Some("no-space"));
    }

    #[test]
    fn mach_error_for_task_for_pid_includes_specific_hint() {
        let rendered = mach_error("task_for_pid", KERN_FAILURE).to_string();
        assert!(rendered.contains("failure"));
        assert!(rendered.contains("task port acquisition was denied by the kernel"));
        assert!(rendered.contains("task_for_pid entitlement/exception"));
    }

    #[test]
    fn mach_error_for_thread_creation_includes_register_hint() {
        let rendered = mach_error("thread_create_running", KERN_INVALID_ARGUMENT).to_string();
        assert!(rendered.contains("invalid-argument"));
        assert!(rendered.contains("thread state was rejected"));
    }

    #[test]
    fn mach_vm_protect_hint_mentions_page_protection() {
        let hint = mach_failure_hint("mach_vm_protect", KERN_PROTECTION_FAILURE).expect("protect hint");
        assert!(hint.contains("page protection change was denied"));
        let message = mach_error_message("mach_vm_protect", KERN_PROTECTION_FAILURE);
        assert!(message.contains("protection-failure"));
    }
}
