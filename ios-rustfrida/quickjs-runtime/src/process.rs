use crate::context::JSContext;
use crate::ffi;
use crate::ptr::{create_native_pointer, get_native_pointer_addr};
use crate::util::{
    add_cfunction_to_object, js_throw_internal_error, js_throw_type_error, js_u64_to_js_number_or_bigint,
    require_string_arg,
};
use crate::value::JSValue;
#[cfg(any(target_os = "ios", target_os = "macos"))]
use native_api::{enumerate_images, find_image_by_address};
#[cfg(any(target_os = "linux", target_os = "android"))]
use std::collections::BTreeMap;
use std::path::Path;

#[derive(Clone, Debug, PartialEq, Eq)]
struct ProcessModule {
    name: String,
    path: String,
    base: u64,
    size: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ProcessRange {
    base: u64,
    size: u64,
    protection: String,
    path: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ProcessThread {
    id: u64,
    name: Option<String>,
    state: String,
}

fn process_arch_name() -> &'static str {
    #[cfg(target_arch = "aarch64")]
    {
        "arm64"
    }
    #[cfg(target_arch = "arm")]
    {
        "arm"
    }
    #[cfg(target_arch = "x86_64")]
    {
        "x64"
    }
    #[cfg(target_arch = "x86")]
    {
        "ia32"
    }
    #[cfg(not(any(
        target_arch = "aarch64",
        target_arch = "arm",
        target_arch = "x86_64",
        target_arch = "x86"
    )))]
    {
        std::env::consts::ARCH
    }
}

fn process_platform_name() -> &'static str {
    #[cfg(any(target_os = "ios", target_os = "macos"))]
    {
        "darwin"
    }
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        "linux"
    }
    #[cfg(not(any(target_os = "ios", target_os = "macos", target_os = "linux", target_os = "android")))]
    {
        std::env::consts::OS
    }
}

fn process_page_size() -> i32 {
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if page_size > 0 {
        page_size as i32
    } else {
        4096
    }
}

fn normalized_module_path(path: &str) -> &str {
    path.strip_suffix(" (deleted)").unwrap_or(path)
}

fn module_basename(path: &str) -> &str {
    Path::new(normalized_module_path(path))
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(path)
}

fn module_name_matches(module: &ProcessModule, query: &str) -> bool {
    let query = query.trim();
    if query.is_empty() {
        return false;
    }

    let path = normalized_module_path(&module.path);
    module.name == query || path == query || module.name.starts_with(&format!("{query}.")) || path.ends_with(query)
}

#[cfg(any(target_os = "ios", target_os = "macos"))]
fn process_modules() -> Vec<ProcessModule> {
    enumerate_images()
        .unwrap_or_default()
        .into_iter()
        .map(|image| ProcessModule {
            name: module_basename(&image.name).to_string(),
            path: image.name,
            base: image.base as u64,
            size: image.size as u64,
        })
        .collect()
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn process_modules() -> Vec<ProcessModule> {
    let Some(maps) = crate::memory::read_proc_self_maps() else {
        return Vec::new();
    };

    let mut ranges = BTreeMap::<String, (u64, u64)>::new();
    for entry in crate::memory::proc_maps_entries(&maps) {
        let Some(path) = entry.path else {
            continue;
        };
        if !normalized_module_path(path).starts_with('/') {
            continue;
        }

        ranges
            .entry(path.to_string())
            .and_modify(|(base, end)| {
                *base = (*base).min(entry.start);
                *end = (*end).max(entry.end);
            })
            .or_insert((entry.start, entry.end));
    }

    let mut modules = ranges
        .into_iter()
        .map(|(path, (base, end))| ProcessModule {
            name: module_basename(&path).to_string(),
            path,
            base,
            size: end.saturating_sub(base),
        })
        .collect::<Vec<_>>();
    modules.sort_by_key(|module| module.base);
    modules
}

#[cfg(not(any(target_os = "ios", target_os = "macos", target_os = "linux", target_os = "android")))]
fn process_modules() -> Vec<ProcessModule> {
    Vec::new()
}

fn process_main_module() -> Option<ProcessModule> {
    let modules = process_modules();
    let executable = std::env::current_exe().ok();
    if let Some(executable) = executable.as_ref().and_then(|path| path.to_str()) {
        if let Some(module) = modules
            .iter()
            .find(|module| normalized_module_path(&module.path) == executable)
        {
            return Some(module.clone());
        }
        if let Some(name) = Path::new(executable).file_name().and_then(|name| name.to_str()) {
            if let Some(module) = modules.iter().find(|module| module.name == name) {
                return Some(module.clone());
            }
        }
    }

    modules.into_iter().next()
}

fn process_find_module_by_name(name: &str) -> Option<ProcessModule> {
    process_modules()
        .into_iter()
        .find(|module| module_name_matches(module, name))
}

#[cfg(any(target_os = "ios", target_os = "macos"))]
fn process_find_module_by_address(address: u64) -> Option<ProcessModule> {
    find_image_by_address(address as usize)
        .ok()
        .flatten()
        .map(|image| ProcessModule {
            name: module_basename(&image.name).to_string(),
            path: image.name,
            base: image.base as u64,
            size: image.size as u64,
        })
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn process_find_module_by_address(address: u64) -> Option<ProcessModule> {
    let maps = crate::memory::read_proc_self_maps()?;
    let path = crate::memory::proc_maps_entries(&maps)
        .find(|entry| entry.contains(address))?
        .path?;
    process_modules().into_iter().find(|module| module.path == path)
}

#[cfg(not(any(target_os = "ios", target_os = "macos", target_os = "linux", target_os = "android")))]
fn process_find_module_by_address(address: u64) -> Option<ProcessModule> {
    process_modules()
        .into_iter()
        .find(|module| address >= module.base && address < module.base.saturating_add(module.size))
}

fn protection_matches(actual: &str, filter: &str) -> bool {
    let actual = actual.as_bytes();
    let filter = filter.as_bytes();
    filter.len() == 3
        && actual.len() >= 3
        && (0..3).all(|index| filter[index] == b'-' || filter[index] == actual[index])
}

fn coalesce_ranges(ranges: Vec<ProcessRange>) -> Vec<ProcessRange> {
    let mut output: Vec<ProcessRange> = Vec::with_capacity(ranges.len());
    for range in ranges {
        if let Some(previous) = output.last_mut() {
            let adjacent = previous.base.checked_add(previous.size) == Some(range.base);
            if adjacent && previous.protection == range.protection && previous.path == range.path {
                previous.size = previous.size.saturating_add(range.size);
                continue;
            }
        }
        output.push(range);
    }
    output
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn platform_process_ranges() -> Vec<ProcessRange> {
    let Some(maps) = crate::memory::read_proc_self_maps() else {
        return Vec::new();
    };

    crate::memory::proc_maps_entries(&maps)
        .filter_map(|entry| {
            let protection = entry.perms.get(..3)?.to_string();
            Some(ProcessRange {
                base: entry.start,
                size: entry.end.saturating_sub(entry.start),
                protection,
                path: entry.path.map(str::to_string),
            })
        })
        .collect()
}

#[cfg(any(target_os = "ios", target_os = "macos"))]
// XNU's vm_region.h wraps this ABI structure in #pragma pack(push, 4).
#[repr(C, packed(4))]
#[derive(Default)]
struct VmRegionSubmapInfo64 {
    protection: libc::vm_prot_t,
    max_protection: libc::vm_prot_t,
    inheritance: libc::vm_inherit_t,
    offset: libc::memory_object_offset_t,
    user_tag: libc::c_uint,
    pages_resident: libc::c_uint,
    pages_shared_now_private: libc::c_uint,
    pages_swapped_out: libc::c_uint,
    pages_dirtied: libc::c_uint,
    ref_count: libc::c_uint,
    shadow_depth: libc::c_ushort,
    external_pager: libc::c_uchar,
    share_mode: libc::c_uchar,
    is_submap: libc::boolean_t,
    behavior: libc::c_int,
    object_id: libc::c_uint,
    user_wired_count: libc::c_ushort,
    flags: libc::c_ushort,
    pages_reusable: libc::c_uint,
    object_id_full: u64,
}

#[cfg(any(target_os = "ios", target_os = "macos"))]
const _: [(); 80] = [(); std::mem::size_of::<VmRegionSubmapInfo64>()];

#[cfg(any(target_os = "ios", target_os = "macos"))]
const VM_REGION_SUBMAP_INFO_COUNT_64: libc::mach_msg_type_number_t = (std::mem::size_of::<VmRegionSubmapInfo64>()
    / std::mem::size_of::<libc::natural_t>())
    as libc::mach_msg_type_number_t;
#[cfg(any(target_os = "ios", target_os = "macos"))]
const CS_OPS_STATUS: libc::c_uint = 0;
#[cfg(any(target_os = "ios", target_os = "macos"))]
const CS_DEBUGGED: u32 = 0x1000_0000;

#[cfg(any(target_os = "ios", target_os = "macos"))]
extern "C" {
    static mach_task_self_: libc::mach_port_t;

    fn mach_vm_region_recurse(
        target_task: libc::vm_map_t,
        address: *mut libc::mach_vm_address_t,
        size: *mut libc::mach_vm_size_t,
        nesting_depth: *mut libc::natural_t,
        info: *mut libc::integer_t,
        info_count: *mut libc::mach_msg_type_number_t,
    ) -> libc::kern_return_t;
    fn mach_port_deallocate(task: libc::mach_port_t, name: libc::mach_port_t) -> libc::kern_return_t;
    fn csops(pid: libc::pid_t, ops: libc::c_uint, useraddr: *mut libc::c_void, usersize: libc::size_t) -> libc::c_int;
}

#[cfg(any(target_os = "ios", target_os = "macos"))]
fn protection_from_mach(flags: libc::vm_prot_t) -> String {
    let mut protection = String::with_capacity(3);
    protection.push(if flags & 1 != 0 { 'r' } else { '-' });
    protection.push(if flags & 2 != 0 { 'w' } else { '-' });
    protection.push(if flags & 4 != 0 { 'x' } else { '-' });
    protection
}

#[cfg(any(target_os = "ios", target_os = "macos"))]
fn darwin_region_path(address: u64) -> Option<String> {
    let mut buffer = [0u8; 4096];
    let length = unsafe {
        libc::proc_regionfilename(
            libc::getpid(),
            address,
            buffer.as_mut_ptr() as *mut libc::c_void,
            buffer.len() as u32,
        )
    };
    if length <= 0 {
        return None;
    }
    let length = (length as usize).min(buffer.len());
    let length = buffer[..length].iter().position(|&byte| byte == 0).unwrap_or(length);
    let path = String::from_utf8_lossy(&buffer[..length]).into_owned();
    (!path.is_empty()).then_some(path)
}

#[cfg(any(target_os = "ios", target_os = "macos"))]
fn platform_process_ranges() -> Vec<ProcessRange> {
    let modules = process_modules();
    let mut ranges = Vec::new();
    let mut cursor = 0u64;
    let mut nesting_depth = 0;

    loop {
        let mut address = cursor;
        let mut size = 0u64;
        let mut info = VmRegionSubmapInfo64::default();
        let mut info_count = VM_REGION_SUBMAP_INFO_COUNT_64;
        let result = unsafe {
            mach_vm_region_recurse(
                mach_task_self_,
                &mut address,
                &mut size,
                &mut nesting_depth,
                &mut info as *mut VmRegionSubmapInfo64 as *mut libc::integer_t,
                &mut info_count,
            )
        };
        if result != 0 || size == 0 {
            break;
        }
        if info.is_submap != 0 {
            let Some(next_depth) = nesting_depth.checked_add(1) else {
                break;
            };
            nesting_depth = next_depth;
            cursor = address;
            continue;
        }

        let end = address.saturating_add(size);
        let path = darwin_region_path(address).or_else(|| {
            modules
                .iter()
                .find(|module| {
                    let module_end = module.base.saturating_add(module.size);
                    address < module_end && module.base < end
                })
                .map(|module| module.path.clone())
        });
        ranges.push(ProcessRange {
            base: address,
            size,
            protection: protection_from_mach(info.protection),
            path,
        });

        let Some(next) = address.checked_add(size) else {
            break;
        };
        if next <= cursor {
            break;
        }
        cursor = next;
    }

    ranges
}

#[cfg(not(any(target_os = "ios", target_os = "macos", target_os = "linux", target_os = "android")))]
fn platform_process_ranges() -> Vec<ProcessRange> {
    Vec::new()
}

fn process_ranges(protection: Option<&str>, coalesce: bool) -> Vec<ProcessRange> {
    let ranges = platform_process_ranges()
        .into_iter()
        .filter(|range| {
            protection
                .map(|filter| protection_matches(&range.protection, filter))
                .unwrap_or(true)
        })
        .collect::<Vec<_>>();
    if coalesce {
        coalesce_ranges(ranges)
    } else {
        ranges
    }
}

fn process_find_range_by_address(address: u64) -> Option<ProcessRange> {
    platform_process_ranges()
        .into_iter()
        .find(|range| address >= range.base && address < range.base.saturating_add(range.size))
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn process_current_thread_id() -> u64 {
    let tid = unsafe { libc::syscall(libc::SYS_gettid) };
    if tid > 0 {
        tid as u64
    } else {
        0
    }
}

#[cfg(any(target_os = "ios", target_os = "macos"))]
fn process_current_thread_id() -> u64 {
    let mut thread_id = 0u64;
    let result = unsafe { libc::pthread_threadid_np(std::ptr::null_mut(), &mut thread_id) };
    if result == 0 {
        thread_id
    } else {
        0
    }
}

#[cfg(not(any(target_os = "ios", target_os = "macos", target_os = "linux", target_os = "android")))]
fn process_current_thread_id() -> u64 {
    0
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn linux_thread_state(tid: u64) -> String {
    let Ok(status) = std::fs::read_to_string(format!("/proc/self/task/{tid}/status")) else {
        return "unknown".to_string();
    };
    let state = status
        .lines()
        .find_map(|line| line.strip_prefix("State:"))
        .and_then(|state| state.trim().as_bytes().first().copied());
    match state {
        Some(b'R') => "running",
        Some(b'T') | Some(b't') => "stopped",
        Some(b'S') | Some(b'I') => "waiting",
        Some(b'D') => "uninterruptible",
        Some(b'Z') | Some(b'X') | Some(b'x') | Some(b'K') | Some(b'W') | Some(b'P') => "halted",
        _ => "unknown",
    }
    .to_string()
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn process_threads() -> Vec<ProcessThread> {
    let Ok(entries) = std::fs::read_dir("/proc/self/task") else {
        return Vec::new();
    };
    let mut threads = entries
        .flatten()
        .filter_map(|entry| entry.file_name().to_str()?.parse::<u64>().ok())
        .map(|tid| {
            let name = std::fs::read_to_string(format!("/proc/self/task/{tid}/comm"))
                .ok()
                .map(|name| name.trim_end().to_string())
                .filter(|name| !name.is_empty());
            ProcessThread {
                id: tid,
                name,
                state: linux_thread_state(tid),
            }
        })
        .collect::<Vec<_>>();
    threads.sort_by_key(|thread| thread.id);
    threads
}

#[cfg(any(target_os = "ios", target_os = "macos"))]
fn darwin_thread_state(state: libc::integer_t) -> &'static str {
    match state {
        libc::TH_STATE_RUNNING => "running",
        libc::TH_STATE_STOPPED => "stopped",
        libc::TH_STATE_WAITING => "waiting",
        libc::TH_STATE_UNINTERRUPTIBLE => "uninterruptible",
        libc::TH_STATE_HALTED => "halted",
        _ => "unknown",
    }
}

#[cfg(any(target_os = "ios", target_os = "macos"))]
fn process_threads() -> Vec<ProcessThread> {
    let task = unsafe { mach_task_self_ };
    let mut thread_list: libc::thread_act_array_t = std::ptr::null_mut();
    let mut thread_count = 0;
    if unsafe { libc::task_threads(task, &mut thread_list, &mut thread_count) } != 0 || thread_list.is_null() {
        return Vec::new();
    }

    let ports = unsafe { std::slice::from_raw_parts(thread_list, thread_count as usize) };
    let mut threads = Vec::with_capacity(ports.len());
    for &thread in ports {
        let mut identifier = unsafe { std::mem::zeroed::<libc::thread_identifier_info_data_t>() };
        let mut identifier_count = libc::THREAD_IDENTIFIER_INFO_COUNT;
        let identifier_result = unsafe {
            libc::thread_info(
                thread,
                libc::THREAD_IDENTIFIER_INFO as libc::thread_flavor_t,
                &mut identifier as *mut libc::thread_identifier_info_data_t as libc::thread_info_t,
                &mut identifier_count,
            )
        };

        let mut basic = unsafe { std::mem::zeroed::<libc::thread_basic_info_data_t>() };
        let mut basic_count = libc::THREAD_BASIC_INFO_COUNT;
        let basic_result = unsafe {
            libc::thread_info(
                thread,
                libc::THREAD_BASIC_INFO as libc::thread_flavor_t,
                &mut basic as *mut libc::thread_basic_info_data_t as libc::thread_info_t,
                &mut basic_count,
            )
        };

        let mut extended = unsafe { std::mem::zeroed::<libc::thread_extended_info_data_t>() };
        let mut extended_count = libc::THREAD_EXTENDED_INFO_COUNT;
        let extended_result = unsafe {
            libc::thread_info(
                thread,
                libc::THREAD_EXTENDED_INFO as libc::thread_flavor_t,
                &mut extended as *mut libc::thread_extended_info_data_t as libc::thread_info_t,
                &mut extended_count,
            )
        };
        let name = if extended_result == 0 {
            let length = extended
                .pth_name
                .iter()
                .position(|&byte| byte == 0)
                .unwrap_or(extended.pth_name.len());
            let bytes = extended.pth_name[..length]
                .iter()
                .map(|&byte| byte as u8)
                .collect::<Vec<_>>();
            let name = String::from_utf8_lossy(&bytes).into_owned();
            (!name.is_empty()).then_some(name)
        } else {
            None
        };

        threads.push(ProcessThread {
            id: if identifier_result == 0 {
                identifier.thread_id
            } else {
                thread as u64
            },
            name,
            state: if basic_result == 0 {
                darwin_thread_state(basic.run_state).to_string()
            } else {
                "unknown".to_string()
            },
        });

        unsafe {
            mach_port_deallocate(task, thread);
        }
    }

    let allocation_size = (thread_count as usize).saturating_mul(std::mem::size_of::<libc::thread_act_t>());
    unsafe {
        libc::vm_deallocate(task, thread_list as libc::vm_address_t, allocation_size);
    }
    threads.sort_by_key(|thread| thread.id);
    threads
}

#[cfg(not(any(target_os = "ios", target_os = "macos", target_os = "linux", target_os = "android")))]
fn process_threads() -> Vec<ProcessThread> {
    Vec::new()
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn is_debugger_attached() -> bool {
    let Ok(status) = std::fs::read_to_string("/proc/self/status") else {
        return false;
    };
    status.lines().any(|line| {
        line.strip_prefix("TracerPid:")
            .and_then(|pid| pid.trim().parse::<u32>().ok())
            .unwrap_or(0)
            != 0
    })
}

#[cfg(any(target_os = "ios", target_os = "macos"))]
fn is_debugger_attached() -> bool {
    let mut flags = 0u32;
    let result = unsafe {
        csops(
            libc::getpid(),
            CS_OPS_STATUS,
            &mut flags as *mut u32 as *mut libc::c_void,
            std::mem::size_of::<u32>(),
        )
    };
    result == 0 && flags & CS_DEBUGGED != 0
}

#[cfg(not(any(target_os = "ios", target_os = "macos", target_os = "linux", target_os = "android")))]
fn is_debugger_attached() -> bool {
    false
}

fn process_current_dir() -> String {
    std::env::current_dir()
        .ok()
        .map(|path| path.to_string_lossy().into_owned())
        .unwrap_or_else(|| "/".to_string())
}

fn process_home_dir() -> String {
    std::env::var("HOME").unwrap_or_else(|_| "/".to_string())
}

fn process_tmp_dir() -> String {
    std::env::var("TMPDIR").unwrap_or_else(|_| {
        if cfg!(target_os = "android") {
            "/data/local/tmp".to_string()
        } else {
            "/tmp".to_string()
        }
    })
}

unsafe fn pointer_arg(
    ctx: *mut ffi::JSContext,
    argc: i32,
    argv: *mut ffi::JSValue,
    usage: &str,
) -> Result<u64, ffi::JSValue> {
    if argc < 1 {
        return Err(js_throw_type_error(ctx, usage));
    }
    let value = JSValue(*argv);
    if let Some(address) = get_native_pointer_addr(value) {
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

unsafe fn module_to_js(ctx: *mut ffi::JSContext, module: &ProcessModule) -> ffi::JSValue {
    let object = JSValue(ffi::JS_NewObject(ctx));
    object.set_property(ctx, "name", JSValue::string(ctx, &module.name));
    object.set_property(ctx, "path", JSValue::string(ctx, &module.path));
    object.set_property(ctx, "base", create_native_pointer(ctx, module.base));
    object.set_property(ctx, "size", JSValue(js_u64_to_js_number_or_bigint(ctx, module.size)));
    object.raw()
}

unsafe fn range_to_js(ctx: *mut ffi::JSContext, range: &ProcessRange) -> ffi::JSValue {
    let object = JSValue(ffi::JS_NewObject(ctx));
    object.set_property(ctx, "base", create_native_pointer(ctx, range.base));
    object.set_property(ctx, "size", JSValue(js_u64_to_js_number_or_bigint(ctx, range.size)));
    object.set_property(ctx, "protection", JSValue::string(ctx, &range.protection));
    if let Some(path) = range.path.as_ref() {
        let file = JSValue(ffi::JS_NewObject(ctx));
        file.set_property(ctx, "path", JSValue::string(ctx, path));
        object.set_property(ctx, "file", file);
    }
    object.raw()
}

unsafe fn thread_to_js(ctx: *mut ffi::JSContext, thread: &ProcessThread) -> ffi::JSValue {
    let object = JSValue(ffi::JS_NewObject(ctx));
    object.set_property(ctx, "id", JSValue(js_u64_to_js_number_or_bigint(ctx, thread.id)));
    if let Some(name) = thread.name.as_ref() {
        object.set_property(ctx, "name", JSValue::string(ctx, name));
    }
    object.set_property(ctx, "state", JSValue::string(ctx, &thread.state));
    object.raw()
}

unsafe fn parse_range_options(
    ctx: *mut ffi::JSContext,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> Result<(Option<String>, bool), ffi::JSValue> {
    if argc < 1 {
        return Ok((None, false));
    }
    let argument = JSValue(*argv);
    if argument.is_null() || argument.is_undefined() {
        return Ok((None, false));
    }
    if argument.is_string() {
        return argument
            .to_string(ctx)
            .map(|protection| (Some(protection), false))
            .ok_or_else(|| js_throw_type_error(ctx, "Process.enumerateRanges: invalid protection string"));
    }
    if !argument.is_object() {
        return Err(js_throw_type_error(
            ctx,
            "Process.enumerateRanges(protection | { protection, coalesce }) expected a string or object",
        ));
    }

    let protection_value = argument.get_property(ctx, "protection");
    let protection = if protection_value.is_null() || protection_value.is_undefined() {
        None
    } else if protection_value.is_string() {
        protection_value.to_string(ctx)
    } else {
        protection_value.free(ctx);
        return Err(js_throw_type_error(
            ctx,
            "Process.enumerateRanges: protection must be a string",
        ));
    };
    protection_value.free(ctx);

    let coalesce_value = argument.get_property(ctx, "coalesce");
    let coalesce = coalesce_value.to_bool().unwrap_or(false);
    coalesce_value.free(ctx);
    Ok((protection, coalesce))
}

unsafe extern "C" fn js_process_enumerate_modules(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let array = ffi::JS_NewArray(ctx);
    for (index, module) in process_modules().iter().enumerate() {
        ffi::JS_SetPropertyUint32(ctx, array, index as u32, module_to_js(ctx, module));
    }
    array
}

unsafe extern "C" fn js_process_find_module_by_name(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let name = match require_string_arg(
        ctx,
        argc,
        argv,
        0,
        "Process.findModuleByName(name) requires 1 string argument",
    ) {
        Ok(name) => name,
        Err(error) => return error,
    };
    process_find_module_by_name(&name)
        .map(|module| module_to_js(ctx, &module))
        .unwrap_or_else(|| JSValue::null().raw())
}

unsafe extern "C" fn js_process_get_module_by_name(
    ctx: *mut ffi::JSContext,
    this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let result = js_process_find_module_by_name(ctx, this, argc, argv);
    let value = JSValue(result);
    if value.is_exception() || !value.is_null() {
        result
    } else {
        js_throw_internal_error(ctx, "Process.getModuleByName: module not found")
    }
}

unsafe extern "C" fn js_process_find_module_by_address(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let address = match pointer_arg(
        ctx,
        argc,
        argv,
        "Process.findModuleByAddress(address) requires 1 pointer-like argument",
    ) {
        Ok(address) => address,
        Err(error) => return error,
    };
    process_find_module_by_address(address)
        .map(|module| module_to_js(ctx, &module))
        .unwrap_or_else(|| JSValue::null().raw())
}

unsafe extern "C" fn js_process_get_module_by_address(
    ctx: *mut ffi::JSContext,
    this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let result = js_process_find_module_by_address(ctx, this, argc, argv);
    let value = JSValue(result);
    if value.is_exception() || !value.is_null() {
        result
    } else {
        js_throw_internal_error(ctx, "Process.getModuleByAddress: module not found")
    }
}

unsafe extern "C" fn js_process_enumerate_ranges(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let (protection, coalesce) = match parse_range_options(ctx, argc, argv) {
        Ok(options) => options,
        Err(error) => return error,
    };
    let array = ffi::JS_NewArray(ctx);
    for (index, range) in process_ranges(protection.as_deref(), coalesce).iter().enumerate() {
        ffi::JS_SetPropertyUint32(ctx, array, index as u32, range_to_js(ctx, range));
    }
    array
}

unsafe extern "C" fn js_process_find_range_by_address(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let address = match pointer_arg(
        ctx,
        argc,
        argv,
        "Process.findRangeByAddress(address) requires 1 pointer-like argument",
    ) {
        Ok(address) => address,
        Err(error) => return error,
    };
    process_find_range_by_address(address)
        .map(|range| range_to_js(ctx, &range))
        .unwrap_or_else(|| JSValue::null().raw())
}

unsafe extern "C" fn js_process_get_range_by_address(
    ctx: *mut ffi::JSContext,
    this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let result = js_process_find_range_by_address(ctx, this, argc, argv);
    let value = JSValue(result);
    if value.is_exception() || !value.is_null() {
        result
    } else {
        js_throw_internal_error(ctx, "Process.getRangeByAddress: range not found")
    }
}

unsafe extern "C" fn js_process_enumerate_malloc_ranges(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    ffi::JS_NewArray(ctx)
}

unsafe extern "C" fn js_process_get_current_dir(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    JSValue::string(ctx, &process_current_dir()).raw()
}

unsafe extern "C" fn js_process_get_home_dir(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    JSValue::string(ctx, &process_home_dir()).raw()
}

unsafe extern "C" fn js_process_get_tmp_dir(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    JSValue::string(ctx, &process_tmp_dir()).raw()
}

unsafe extern "C" fn js_process_get_current_thread_id(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    js_u64_to_js_number_or_bigint(ctx, process_current_thread_id())
}

unsafe extern "C" fn js_process_is_debugger_attached(
    _ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    JSValue::bool(is_debugger_attached()).raw()
}

unsafe extern "C" fn js_process_enumerate_threads(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let array = ffi::JS_NewArray(ctx);
    for (index, thread) in process_threads().iter().enumerate() {
        ffi::JS_SetPropertyUint32(ctx, array, index as u32, thread_to_js(ctx, thread));
    }
    array
}

pub(crate) fn register_process_api(ctx: &JSContext) {
    let global = ctx.global_object();
    let process = ctx.new_object();
    unsafe {
        let ctx_ptr = ctx.as_ptr();
        process.set_property(ctx_ptr, "id", JSValue::int(libc::getpid()));
        process.set_property(ctx_ptr, "arch", JSValue::string(ctx_ptr, process_arch_name()));
        process.set_property(ctx_ptr, "platform", JSValue::string(ctx_ptr, process_platform_name()));
        process.set_property(
            ctx_ptr,
            "pointerSize",
            JSValue::int(std::mem::size_of::<usize>() as i32),
        );
        process.set_property(ctx_ptr, "pageSize", JSValue::int(process_page_size()));
        process.set_property(ctx_ptr, "codeSigningPolicy", JSValue::string(ctx_ptr, "optional"));
        process.set_property(
            ctx_ptr,
            "mainModule",
            process_main_module()
                .map(|module| JSValue(module_to_js(ctx_ptr, &module)))
                .unwrap_or_else(JSValue::null),
        );

        let object = process.raw();
        add_cfunction_to_object(ctx_ptr, object, "enumerateModules", js_process_enumerate_modules, 0);
        add_cfunction_to_object(ctx_ptr, object, "findModuleByName", js_process_find_module_by_name, 1);
        add_cfunction_to_object(ctx_ptr, object, "getModuleByName", js_process_get_module_by_name, 1);
        add_cfunction_to_object(
            ctx_ptr,
            object,
            "findModuleByAddress",
            js_process_find_module_by_address,
            1,
        );
        add_cfunction_to_object(
            ctx_ptr,
            object,
            "getModuleByAddress",
            js_process_get_module_by_address,
            1,
        );
        add_cfunction_to_object(ctx_ptr, object, "enumerateRanges", js_process_enumerate_ranges, 1);
        add_cfunction_to_object(
            ctx_ptr,
            object,
            "findRangeByAddress",
            js_process_find_range_by_address,
            1,
        );
        add_cfunction_to_object(ctx_ptr, object, "getRangeByAddress", js_process_get_range_by_address, 1);
        add_cfunction_to_object(
            ctx_ptr,
            object,
            "enumerateMallocRanges",
            js_process_enumerate_malloc_ranges,
            0,
        );
        add_cfunction_to_object(ctx_ptr, object, "getCurrentDir", js_process_get_current_dir, 0);
        add_cfunction_to_object(ctx_ptr, object, "getHomeDir", js_process_get_home_dir, 0);
        add_cfunction_to_object(ctx_ptr, object, "getTmpDir", js_process_get_tmp_dir, 0);
        add_cfunction_to_object(
            ctx_ptr,
            object,
            "getCurrentThreadId",
            js_process_get_current_thread_id,
            0,
        );
        add_cfunction_to_object(
            ctx_ptr,
            object,
            "isDebuggerAttached",
            js_process_is_debugger_attached,
            0,
        );
        add_cfunction_to_object(ctx_ptr, object, "enumerateThreads", js_process_enumerate_threads, 0);
    }

    global.set_property(ctx.as_ptr(), "Process", process);
    global.free(ctx.as_ptr());
}
