use crate::context::JSContext;
use crate::ffi;
use crate::ptr::{create_native_pointer, get_native_pointer_addr};
use crate::util::{add_cfunction_to_object, js_throw_internal_error, js_throw_range_error, js_throw_type_error};
use crate::value::JSValue;
use std::sync::Mutex;

const MAX_ALLOCATION_SIZE: usize = 256 * 1024 * 1024;
const MAX_RUNTIME_ALLOCATION_BYTES: usize = 512 * 1024 * 1024;
const MAX_RUNTIME_ALLOCATIONS: usize = 4096;
const MAX_UTF8_STRING_BYTES: usize = 16 * 1024 * 1024;
const MAX_BYTE_SEQUENCE_SIZE: usize = 256 * 1024 * 1024;
const MAX_CSTRING_LEN: usize = 4096;

struct OwnedAllocation {
    runtime: usize,
    bytes: Box<[u8]>,
}

struct AllocationRegistry {
    entries: Vec<OwnedAllocation>,
}

impl AllocationRegistry {
    const fn new() -> Self {
        Self { entries: Vec::new() }
    }

    fn insert(&mut self, runtime: usize, bytes: Box<[u8]>) -> Result<u64, &'static str> {
        let mut runtime_entries = self.entries.iter().filter(|entry| entry.runtime == runtime);
        let allocation_count = runtime_entries.clone().count();
        if allocation_count >= MAX_RUNTIME_ALLOCATIONS {
            return Err("allocation count limit exceeded");
        }

        let runtime_bytes = runtime_entries.try_fold(0usize, |total, entry| total.checked_add(entry.bytes.len()));
        let Some(new_total) = runtime_bytes.and_then(|total| total.checked_add(bytes.len())) else {
            return Err("allocation size overflow");
        };
        if new_total > MAX_RUNTIME_ALLOCATION_BYTES {
            return Err("runtime allocation limit exceeded (max 512MB)");
        }

        self.entries
            .try_reserve(1)
            .map_err(|_| "unable to grow allocation registry")?;
        let address = bytes.as_ptr() as usize as u64;
        self.entries.push(OwnedAllocation { runtime, bytes });
        Ok(address)
    }

    fn cleanup_runtime(&mut self, runtime: usize) {
        self.entries.retain(|entry| entry.runtime != runtime);
    }

    #[cfg(test)]
    fn runtime_stats(&self, runtime: usize) -> (usize, usize) {
        self.entries
            .iter()
            .filter(|entry| entry.runtime == runtime)
            .fold((0usize, 0usize), |(count, bytes), entry| {
                (count + 1, bytes + entry.bytes.len())
            })
    }
}

static OWNED_ALLOCATIONS: Mutex<AllocationRegistry> = Mutex::new(AllocationRegistry::new());

/// Releases allocations owned by one QuickJS runtime. Runtime cleanup must call
/// this before destroying that runtime; NativePointer GC intentionally does not
/// release allocations because aliases may still reference the same address.
#[allow(dead_code)]
pub(crate) fn cleanup_memory_allocations(runtime: *mut ffi::JSRuntime) {
    if runtime.is_null() {
        return;
    }
    OWNED_ALLOCATIONS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .cleanup_runtime(runtime as usize);
}

pub(crate) fn register_memory_api(ctx: &JSContext) {
    let global = ctx.global_object();
    let memory = ctx.new_object();

    unsafe {
        let ctx_ptr = ctx.as_ptr();
        let obj = memory.raw();
        add_cfunction_to_object(ctx_ptr, obj, "alloc", memory_alloc, 1);
        add_cfunction_to_object(ctx_ptr, obj, "allocUtf8String", memory_alloc_utf8_string, 1);
        add_cfunction_to_object(ctx_ptr, obj, "protect", memory_protect, 3);
        add_cfunction_to_object(ctx_ptr, obj, "flushCodeCache", memory_flush_code_cache, 2);
        add_cfunction_to_object(ctx_ptr, obj, "readU8", memory_read_u8, 1);
        add_cfunction_to_object(ctx_ptr, obj, "readU16", memory_read_u16, 1);
        add_cfunction_to_object(ctx_ptr, obj, "readU32", memory_read_u32, 1);
        add_cfunction_to_object(ctx_ptr, obj, "readU64", memory_read_u64, 1);
        add_cfunction_to_object(ctx_ptr, obj, "readPointer", memory_read_pointer, 1);
        add_cfunction_to_object(ctx_ptr, obj, "readCString", memory_read_cstring, 1);
        add_cfunction_to_object(ctx_ptr, obj, "readUtf8String", memory_read_utf8_string, 1);
        add_cfunction_to_object(ctx_ptr, obj, "readByteArray", memory_read_byte_array, 2);
        add_cfunction_to_object(ctx_ptr, obj, "writeU8", memory_write_u8, 2);
        add_cfunction_to_object(ctx_ptr, obj, "writeU16", memory_write_u16, 2);
        add_cfunction_to_object(ctx_ptr, obj, "writeU32", memory_write_u32, 2);
        add_cfunction_to_object(ctx_ptr, obj, "writeU64", memory_write_u64, 2);
        add_cfunction_to_object(ctx_ptr, obj, "writePointer", memory_write_pointer, 2);
        add_cfunction_to_object(ctx_ptr, obj, "writeBytes", memory_write_bytes, 2);
        add_cfunction_to_object(ctx_ptr, obj, "writest", memory_writest, 2);
    }

    global.set_property(ctx.as_ptr(), "Memory", memory);
    global.free(ctx.as_ptr());
}

pub(crate) unsafe fn register_native_pointer_memory_methods(ctx: *mut ffi::JSContext, prototype: ffi::JSValue) {
    add_cfunction_to_object(ctx, prototype, "readU8", memory_read_u8, 0);
    add_cfunction_to_object(ctx, prototype, "readU16", memory_read_u16, 0);
    add_cfunction_to_object(ctx, prototype, "readU32", memory_read_u32, 0);
    add_cfunction_to_object(ctx, prototype, "readU64", memory_read_u64, 0);
    add_cfunction_to_object(ctx, prototype, "readPointer", memory_read_pointer, 0);
    add_cfunction_to_object(ctx, prototype, "readCString", memory_read_cstring, 0);
    add_cfunction_to_object(ctx, prototype, "readUtf8String", memory_read_utf8_string, 0);
    add_cfunction_to_object(ctx, prototype, "readByteArray", memory_read_byte_array, 1);
    add_cfunction_to_object(ctx, prototype, "writeU8", memory_write_u8, 1);
    add_cfunction_to_object(ctx, prototype, "writeU16", memory_write_u16, 1);
    add_cfunction_to_object(ctx, prototype, "writeU32", memory_write_u32, 1);
    add_cfunction_to_object(ctx, prototype, "writeU64", memory_write_u64, 1);
    add_cfunction_to_object(ctx, prototype, "writePointer", memory_write_pointer, 1);
    add_cfunction_to_object(ctx, prototype, "writeBytes", memory_write_bytes, 1);
    add_cfunction_to_object(ctx, prototype, "protect", memory_protect, 2);
    add_cfunction_to_object(ctx, prototype, "flushCodeCache", memory_flush_code_cache, 1);
    add_cfunction_to_object(ctx, prototype, "writest", memory_writest, 1);
}

unsafe fn address_and_remaining_args(
    ctx: *mut ffi::JSContext,
    this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> Option<(u64, *mut ffi::JSValue, i32)> {
    if let Some(address) = get_native_pointer_addr(JSValue(this)) {
        return Some((address, argv, argc));
    }
    if argc < 1 {
        return None;
    }
    let address = get_addr_from_arg(ctx, JSValue(*argv))?;
    Some((address, argv.add(1), argc - 1))
}

unsafe fn get_addr_from_arg(ctx: *mut ffi::JSContext, value: JSValue) -> Option<u64> {
    get_native_pointer_addr(value).or_else(|| value.to_u64(ctx))
}

unsafe fn exact_i64(ctx: *mut ffi::JSContext, value: JSValue) -> Option<i64> {
    if value.is_int() {
        return value.to_i64(ctx);
    }
    if value.is_float() {
        let number = value.to_float()?;
        if !number.is_finite() || number.fract() != 0.0 || number < i64::MIN as f64 || number > i64::MAX as f64 {
            return None;
        }
        return Some(number as i64);
    }
    if ffi::qjs_is_big_int(ctx, value.raw()) != 0 {
        return value.to_i64(ctx);
    }
    None
}

unsafe fn positive_size(ctx: *mut ffi::JSContext, value: JSValue, api: &str) -> Result<usize, ffi::JSValue> {
    let Some(size) = exact_i64(ctx, value) else {
        return Err(js_throw_type_error(ctx, &format!("{api}: size must be an integer")));
    };
    if size <= 0 {
        return Err(js_throw_range_error(ctx, &format!("{api}: size must be positive")));
    }
    usize::try_from(size).map_err(|_| js_throw_range_error(ctx, &format!("{api}: size is too large")))
}

fn allocate_zeroed(size: usize) -> Result<Box<[u8]>, ()> {
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(size).map_err(|_| ())?;
    bytes.resize(size, 0);
    Ok(bytes.into_boxed_slice())
}

unsafe fn create_owned_pointer(ctx: *mut ffi::JSContext, bytes: Box<[u8]>) -> ffi::JSValue {
    let address = bytes.as_ptr() as usize as u64;
    let pointer = create_native_pointer(ctx, address);
    if pointer.is_exception() {
        return pointer.raw();
    }

    let runtime = ffi::JS_GetRuntime(ctx) as usize;
    let result = OWNED_ALLOCATIONS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .insert(runtime, bytes);
    match result {
        Ok(registered_address) if registered_address == address => pointer.raw(),
        Ok(_) => {
            pointer.free(ctx);
            js_throw_internal_error(ctx, "Memory allocation registry address mismatch")
        }
        Err(message) => {
            pointer.free(ctx);
            js_throw_range_error(ctx, &format!("Memory allocation failed: {message}"))
        }
    }
}

pub(crate) unsafe extern "C" fn memory_alloc(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 1 {
        return js_throw_type_error(ctx, "Memory.alloc() requires a size");
    }
    let size = match positive_size(ctx, JSValue(*argv), "Memory.alloc()") {
        Ok(size) => size,
        Err(error) => return error,
    };
    if size > MAX_ALLOCATION_SIZE {
        return js_throw_range_error(ctx, "Memory.alloc(): size exceeds 256MB");
    }
    let bytes = match allocate_zeroed(size) {
        Ok(bytes) => bytes,
        Err(()) => return js_throw_internal_error(ctx, "Memory.alloc(): out of memory"),
    };
    create_owned_pointer(ctx, bytes)
}

pub(crate) unsafe extern "C" fn memory_alloc_utf8_string(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 1 {
        return js_throw_type_error(ctx, "Memory.allocUtf8String() requires a string");
    }
    let value = JSValue(*argv);
    if !value.is_string() {
        return js_throw_type_error(ctx, "Memory.allocUtf8String(): argument must be a string");
    }
    let Some(string) = value.to_string(ctx) else {
        return js_throw_type_error(ctx, "Memory.allocUtf8String(): invalid string");
    };
    if string.len() > MAX_UTF8_STRING_BYTES {
        return js_throw_range_error(ctx, "Memory.allocUtf8String(): string exceeds 16MB");
    }
    let Some(total) = string.len().checked_add(1) else {
        return js_throw_range_error(ctx, "Memory.allocUtf8String(): string size overflow");
    };
    let mut bytes = Vec::new();
    if bytes.try_reserve_exact(total).is_err() {
        return js_throw_internal_error(ctx, "Memory.allocUtf8String(): out of memory");
    }
    bytes.extend_from_slice(string.as_bytes());
    bytes.push(0);
    create_owned_pointer(ctx, bytes.into_boxed_slice())
}

macro_rules! define_memory_read {
    ($name:ident, $js_name:literal, $rust_type:ty, $size:expr, $convert:expr) => {
        pub(crate) unsafe extern "C" fn $name(
            ctx: *mut ffi::JSContext,
            this: ffi::JSValue,
            argc: i32,
            argv: *mut ffi::JSValue,
        ) -> ffi::JSValue {
            let Some((address, _, _)) = address_and_remaining_args(ctx, this, argc, argv) else {
                return js_throw_type_error(ctx, concat!($js_name, "() requires a pointer"));
            };
            if !is_addr_accessible(address, $size) {
                return js_throw_range_error(ctx, concat!($js_name, "(): invalid memory address"));
            }
            let value = std::ptr::read_unaligned(address as *const $rust_type);
            $convert(ctx, value)
        }
    };
}

define_memory_read!(memory_read_u8, "readU8", u8, 1, |_, value: u8| JSValue::int(
    value as i32
)
.raw());
define_memory_read!(memory_read_u16, "readU16", u16, 2, |_, value: u16| JSValue::int(
    value as i32
)
.raw());
define_memory_read!(memory_read_u32, "readU32", u32, 4, |ctx, value: u32| {
    ffi::JS_NewBigUint64(ctx, value as u64)
});
define_memory_read!(memory_read_u64, "readU64", u64, 8, |ctx, value: u64| {
    ffi::JS_NewBigUint64(ctx, value)
});
define_memory_read!(memory_read_pointer, "readPointer", u64, 8, |ctx, value: u64| {
    create_native_pointer(ctx, value).raw()
});

macro_rules! define_memory_write {
    ($name:ident, $js_name:literal, $rust_type:ty, $size:expr, $extract:expr) => {
        pub(crate) unsafe extern "C" fn $name(
            ctx: *mut ffi::JSContext,
            this: ffi::JSValue,
            argc: i32,
            argv: *mut ffi::JSValue,
        ) -> ffi::JSValue {
            let Some((address, remaining, remaining_count)) = address_and_remaining_args(ctx, this, argc, argv) else {
                return js_throw_type_error(ctx, concat!($js_name, "() requires a pointer"));
            };
            if remaining_count < 1 {
                return js_throw_type_error(ctx, concat!($js_name, "() requires a value"));
            }
            let value: $rust_type = match $extract(ctx, JSValue(*remaining)) {
                Some(value) => value,
                None => return js_throw_type_error(ctx, concat!($js_name, "(): invalid numeric value")),
            };
            if let Err(message) = write_with_perm(address, $size, || {
                std::ptr::write_unaligned(address as *mut $rust_type, value);
            }) {
                return js_throw_range_error(ctx, &format!(concat!($js_name, "(): {}"), message));
            }
            JSValue::undefined().raw()
        }
    };
}

define_memory_write!(memory_write_u8, "writeU8", u8, 1, |ctx, value| {
    exact_i64(ctx, value).map(|value| value as u8)
});
define_memory_write!(memory_write_u16, "writeU16", u16, 2, |ctx, value| {
    exact_i64(ctx, value).map(|value| value as u16)
});
define_memory_write!(memory_write_u32, "writeU32", u32, 4, |ctx, value| {
    exact_i64(ctx, value).map(|value| value as u32)
});
define_memory_write!(memory_write_u64, "writeU64", u64, 8, |ctx, value| {
    if let Some(pointer) = get_native_pointer_addr(value) {
        Some(pointer)
    } else if value.is_int() || value.is_float() || ffi::qjs_is_big_int(ctx, value.raw()) != 0 {
        let mut converted = 0u64;
        (ffi::qjs_value_to_u64(ctx, &mut converted, value.raw()) == 0).then_some(converted)
    } else {
        None
    }
});

pub(crate) unsafe extern "C" fn memory_write_pointer(
    ctx: *mut ffi::JSContext,
    this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    memory_write_u64(ctx, this, argc, argv)
}

pub(crate) unsafe extern "C" fn memory_read_cstring(
    ctx: *mut ffi::JSContext,
    this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let Some((address, _, _)) = address_and_remaining_args(ctx, this, argc, argv) else {
        return js_throw_type_error(ctx, "readCString() requires a pointer");
    };
    if !is_addr_accessible(address, 1) {
        return js_throw_range_error(ctx, "readCString(): invalid memory address");
    }

    let page_size = system_page_size().unwrap_or(4096) as u64;
    let mut length = 0usize;
    while length < MAX_CSTRING_LEN {
        let Some(byte_address) = address.checked_add(length as u64) else {
            return js_throw_range_error(ctx, "readCString(): address overflow");
        };
        if byte_address == address || byte_address % page_size == 0 {
            if !is_addr_accessible(byte_address, 1) {
                return js_throw_range_error(ctx, "readCString(): unreadable memory before terminator");
            }
        }
        if *(byte_address as *const u8) == 0 {
            let bytes = std::slice::from_raw_parts(address as *const u8, length);
            return JSValue::string(ctx, &String::from_utf8_lossy(bytes)).raw();
        }
        length += 1;
    }
    js_throw_range_error(ctx, "readCString(): string exceeds 4096-byte limit")
}

pub(crate) unsafe extern "C" fn memory_read_utf8_string(
    ctx: *mut ffi::JSContext,
    this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    memory_read_cstring(ctx, this, argc, argv)
}

pub(crate) unsafe extern "C" fn memory_read_byte_array(
    ctx: *mut ffi::JSContext,
    this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let Some((address, remaining, remaining_count)) = address_and_remaining_args(ctx, this, argc, argv) else {
        return js_throw_type_error(ctx, "readByteArray() requires a pointer");
    };
    if remaining_count < 1 {
        return js_throw_type_error(ctx, "readByteArray() requires a length");
    }
    let length = match exact_i64(ctx, JSValue(*remaining)) {
        Some(length) if length >= 0 => length as usize,
        Some(_) => return js_throw_range_error(ctx, "readByteArray(): length must be non-negative"),
        None => return js_throw_type_error(ctx, "readByteArray(): length must be an integer"),
    };
    if length > MAX_BYTE_SEQUENCE_SIZE {
        return js_throw_range_error(ctx, "readByteArray(): length exceeds 256MB");
    }
    if length == 0 {
        return ffi::JS_NewArrayBufferCopy(ctx, std::ptr::NonNull::<u8>::dangling().as_ptr(), 0);
    }
    if !is_addr_accessible(address, length) {
        return js_throw_range_error(ctx, "readByteArray(): invalid memory address");
    }
    ffi::JS_NewArrayBufferCopy(ctx, address as *const u8, length)
}

fn byte_from_number(number: f64) -> Option<u8> {
    if number.is_finite() && number.fract() == 0.0 && (0.0..=255.0).contains(&number) {
        Some(number as u8)
    } else {
        None
    }
}

unsafe fn clear_pending_exception(ctx: *mut ffi::JSContext) {
    let exception = ffi::JS_GetException(ctx);
    ffi::qjs_free_value(ctx, exception);
}

unsafe fn extract_bytes(ctx: *mut ffi::JSContext, value: JSValue) -> Result<Vec<u8>, ffi::JSValue> {
    let mut size = 0usize;
    let buffer = ffi::JS_GetArrayBuffer(ctx, &mut size, value.raw());
    if !buffer.is_null() {
        if size > MAX_BYTE_SEQUENCE_SIZE {
            return Err(js_throw_range_error(ctx, "writeBytes(): byte sequence exceeds 256MB"));
        }
        return Ok(std::slice::from_raw_parts(buffer, size).to_vec());
    }
    clear_pending_exception(ctx);

    let mut byte_offset = 0usize;
    let mut byte_length = 0usize;
    let mut bytes_per_element = 0usize;
    let typed_buffer = ffi::JS_GetTypedArrayBuffer(
        ctx,
        value.raw(),
        &mut byte_offset,
        &mut byte_length,
        &mut bytes_per_element,
    );
    if ffi::qjs_is_exception(typed_buffer) == 0 {
        let typed_buffer_value = JSValue(typed_buffer);
        let result = if byte_length > MAX_BYTE_SEQUENCE_SIZE {
            Err(js_throw_range_error(ctx, "writeBytes(): byte sequence exceeds 256MB"))
        } else if byte_length == 0 {
            Ok(Vec::new())
        } else {
            let mut buffer_size = 0usize;
            let buffer = ffi::JS_GetArrayBuffer(ctx, &mut buffer_size, typed_buffer);
            match byte_offset.checked_add(byte_length) {
                Some(end) if !buffer.is_null() && end <= buffer_size => {
                    Ok(std::slice::from_raw_parts(buffer.add(byte_offset), byte_length).to_vec())
                }
                _ => Err(js_throw_range_error(
                    ctx,
                    "writeBytes(): invalid or detached TypedArray",
                )),
            }
        };
        typed_buffer_value.free(ctx);
        return result;
    }
    clear_pending_exception(ctx);

    if ffi::JS_IsArray(ctx, value.raw()) != 0 {
        let length_atom = ffi::JS_NewAtom(ctx, b"length\0".as_ptr() as *const _);
        let length_value = JSValue(ffi::qjs_get_property(ctx, value.raw(), length_atom));
        ffi::JS_FreeAtom(ctx, length_atom);
        let length = length_value.to_i64(ctx);
        length_value.free(ctx);
        let Some(length) = length else {
            return Err(js_throw_type_error(ctx, "writeBytes(): invalid array length"));
        };
        if length < 0 {
            return Err(js_throw_range_error(
                ctx,
                "writeBytes(): array length must be non-negative",
            ));
        }
        let length = usize::try_from(length)
            .map_err(|_| js_throw_range_error(ctx, "writeBytes(): array length is too large"))?;
        if length > MAX_BYTE_SEQUENCE_SIZE {
            return Err(js_throw_range_error(ctx, "writeBytes(): byte sequence exceeds 256MB"));
        }

        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(length)
            .map_err(|_| js_throw_internal_error(ctx, "writeBytes(): out of memory"))?;
        for index in 0..length {
            let element = JSValue(ffi::JS_GetPropertyUint32(ctx, value.raw(), index as u32));
            let byte = if element.is_int() || element.is_float() {
                element.to_float().and_then(byte_from_number)
            } else {
                None
            };
            element.free(ctx);
            match byte {
                Some(byte) => bytes.push(byte),
                None => {
                    return Err(js_throw_type_error(
                        ctx,
                        "writeBytes(): array elements must be integers in the range 0..255",
                    ));
                }
            }
        }
        return Ok(bytes);
    }

    Err(js_throw_type_error(
        ctx,
        "writeBytes(): bytes must be an ArrayBuffer, TypedArray, or Array<number>",
    ))
}

pub(crate) unsafe extern "C" fn memory_write_bytes(
    ctx: *mut ffi::JSContext,
    this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let Some((address, remaining, remaining_count)) = address_and_remaining_args(ctx, this, argc, argv) else {
        return js_throw_type_error(ctx, "writeBytes() requires a pointer");
    };
    if remaining_count < 1 {
        return js_throw_type_error(ctx, "writeBytes() requires bytes");
    }
    let bytes = match extract_bytes(ctx, JSValue(*remaining)) {
        Ok(bytes) => bytes,
        Err(error) => return error,
    };
    if bytes.is_empty() {
        return JSValue::undefined().raw();
    }
    if let Err(message) = write_with_perm(address, bytes.len(), || {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), address as *mut u8, bytes.len());
    }) {
        return js_throw_range_error(ctx, &format!("writeBytes(): {message}"));
    }
    if let Err(message) = flush_instruction_cache(address, bytes.len()) {
        return js_throw_internal_error(ctx, &format!("writeBytes(): {message}"));
    }
    JSValue::undefined().raw()
}

pub(crate) unsafe extern "C" fn memory_writest(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    js_throw_internal_error(
        ctx,
        "writest() is unsupported on iOS; it requires the Android RECOMP stealth-2 backend",
    )
}

fn parse_protection(protection: &str) -> Result<i32, &'static str> {
    let bytes = protection.as_bytes();
    if bytes.len() != 3
        || !matches!(bytes[0], b'r' | b'-')
        || !matches!(bytes[1], b'w' | b'-')
        || !matches!(bytes[2], b'x' | b'-')
    {
        return Err("protection must be exactly three positional characters such as rw-, r-x, or ---");
    }
    let mut flags = 0;
    if bytes[0] == b'r' {
        flags |= libc::PROT_READ;
    }
    if bytes[1] == b'w' {
        flags |= libc::PROT_WRITE;
    }
    if bytes[2] == b'x' {
        flags |= libc::PROT_EXEC;
    }
    Ok(flags)
}

fn system_page_size() -> Option<usize> {
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    usize::try_from(page_size).ok().filter(|size| size.is_power_of_two())
}

fn checked_address_range(address: u64, size: usize) -> Option<(usize, usize)> {
    if address == 0 || size == 0 {
        return None;
    }
    let start = usize::try_from(address).ok()?;
    let end = start.checked_add(size)?;
    (end > start).then_some((start, end))
}

fn align_up(value: usize, alignment: usize) -> Option<usize> {
    let remainder = value & (alignment - 1);
    if remainder == 0 {
        Some(value)
    } else {
        value.checked_add(alignment - remainder)
    }
}

fn aligned_page_range(address: u64, size: usize, page_size: usize) -> Result<(usize, usize), &'static str> {
    if !page_size.is_power_of_two() {
        return Err("invalid system page size");
    }
    let (start, end) = checked_address_range(address, size).ok_or("address range overflow or empty range")?;
    let page_start = start & !(page_size - 1);
    let page_end = align_up(end, page_size).ok_or("page-aligned range overflow")?;
    let page_length = page_end.checked_sub(page_start).ok_or("page range underflow")?;
    if page_length == 0 || page_length % page_size != 0 {
        return Err("invalid page-aligned range");
    }
    Ok((page_start, page_length))
}

pub(crate) unsafe extern "C" fn memory_protect(
    ctx: *mut ffi::JSContext,
    this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let Some((address, remaining, remaining_count)) = address_and_remaining_args(ctx, this, argc, argv) else {
        return js_throw_type_error(ctx, "protect() requires a pointer");
    };
    if remaining_count < 2 {
        return js_throw_type_error(ctx, "protect() requires size and protection");
    }
    let size = match positive_size(ctx, JSValue(*remaining), "protect()") {
        Ok(size) => size,
        Err(error) => return error,
    };
    let protection_value = JSValue(*remaining.add(1));
    if !protection_value.is_string() {
        return js_throw_type_error(ctx, "protect(): protection must be a string");
    }
    let Some(protection) = protection_value.to_string(ctx) else {
        return js_throw_type_error(ctx, "protect(): invalid protection string");
    };
    let flags = match parse_protection(&protection) {
        Ok(flags) => flags,
        Err(message) => return js_throw_type_error(ctx, &format!("protect(): {message}")),
    };
    let Some(page_size) = system_page_size() else {
        return js_throw_internal_error(ctx, "protect(): unable to determine system page size");
    };
    let (page_start, page_length) = match aligned_page_range(address, size, page_size) {
        Ok(range) => range,
        Err(message) => return js_throw_range_error(ctx, &format!("protect(): {message}")),
    };
    let page_end = match page_start.checked_add(page_length) {
        Some(end) => end,
        None => return js_throw_range_error(ctx, "protect(): page range overflow"),
    };
    let regions = match query_protection_regions(page_start, page_end) {
        Ok(regions) => regions,
        Err(message) => return js_throw_range_error(ctx, &format!("protect(): {message}")),
    };
    if let Err(message) = apply_region_protection(&regions, flags) {
        return js_throw_range_error(ctx, &format!("protect(): {message}"));
    }
    JSValue::bool(true).raw()
}

pub(crate) unsafe extern "C" fn memory_flush_code_cache(
    ctx: *mut ffi::JSContext,
    this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let Some((address, remaining, remaining_count)) = address_and_remaining_args(ctx, this, argc, argv) else {
        return js_throw_type_error(ctx, "flushCodeCache() requires a pointer");
    };
    if remaining_count < 1 {
        return js_throw_type_error(ctx, "flushCodeCache() requires a size");
    }
    let size = match positive_size(ctx, JSValue(*remaining), "flushCodeCache()") {
        Ok(size) => size,
        Err(error) => return error,
    };
    if checked_address_range(address, size).is_none() {
        return js_throw_range_error(ctx, "flushCodeCache(): address range overflow");
    }
    if !is_range_mapped(address, size) {
        return js_throw_range_error(ctx, "flushCodeCache(): invalid memory address");
    }
    match flush_instruction_cache(address, size) {
        Ok(()) => JSValue::undefined().raw(),
        Err(message) => js_throw_internal_error(ctx, &format!("flushCodeCache(): {message}")),
    }
}

#[cfg(any(target_os = "ios", target_os = "macos"))]
extern "C" {
    fn sys_icache_invalidate(start: *mut libc::c_void, length: libc::size_t);
}

#[cfg(all(
    any(target_os = "linux", target_os = "android"),
    any(target_arch = "arm", target_arch = "aarch64")
))]
extern "C" {
    fn __clear_cache(start: *mut libc::c_void, end: *mut libc::c_void);
}

unsafe fn flush_instruction_cache(address: u64, size: usize) -> Result<(), &'static str> {
    let (start, end) = checked_address_range(address, size).ok_or("address range overflow or empty range")?;

    #[cfg(any(target_os = "ios", target_os = "macos"))]
    {
        sys_icache_invalidate(start as *mut libc::c_void, size);
        return Ok(());
    }

    #[cfg(all(
        any(target_os = "linux", target_os = "android"),
        any(target_arch = "arm", target_arch = "aarch64")
    ))]
    {
        __clear_cache(start as *mut libc::c_void, end as *mut libc::c_void);
        return Ok(());
    }

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        let _ = (start, end);
        // x86 has coherent instruction and data caches; no cache operation is required.
        return Ok(());
    }

    #[allow(unreachable_code)]
    Err("instruction-cache invalidation is unsupported on this platform")
}

/// Finalizes a writable code-cache mapping for instruction fetch.
///
/// The cache is invalidated while the mapping is still writable, then the
/// complete page-aligned range is transitioned to read/execute protection.
/// `apply_region_protection()` keeps the operation transactional: if any
/// region fails to change, already-changed regions are restored to their
/// original protection.
pub(crate) fn finalize_code_cache_mapping(address: u64, size: usize) -> Result<(), String> {
    if checked_address_range(address, size).is_none() {
        return Err("address range overflow or empty range".to_string());
    }
    unsafe {
        flush_instruction_cache(address, size)
            .map_err(|message| format!("instruction-cache invalidation failed: {message}"))?;
    }

    let page_size = system_page_size().ok_or_else(|| "unable to determine system page size".to_string())?;
    let (page_start, page_length) = aligned_page_range(address, size, page_size).map_err(str::to_string)?;
    let page_end = page_start
        .checked_add(page_length)
        .ok_or_else(|| "page range overflow".to_string())?;
    let regions = query_protection_regions(page_start, page_end)?;
    apply_region_protection(&regions, libc::PROT_READ | libc::PROT_EXEC)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ProtectionRegion {
    start: usize,
    end: usize,
    protection: i32,
    max_protection: Option<i32>,
}

/// Own a same-length target-memory rewrite until it is explicitly rolled back.
///
/// Construction snapshots both the original bytes and the page-region
/// protections. Applying and rolling back use the existing W^X transition and
/// instruction-cache flush path, so a failed write keeps the owner armed for a
/// later retry instead of silently claiming that memory was restored.
#[allow(dead_code)]
pub(crate) struct TargetMemoryPatch {
    address: u64,
    original: Box<[u8]>,
    replacement: Box<[u8]>,
    regions: Vec<ProtectionRegion>,
    applied: bool,
}

/// The same-process W^X patch path is available whenever this runtime module
/// is compiled. Public Stalker commit readiness still depends on its thread
/// suspend, quiescence, and branch-range prerequisites.
pub(crate) const fn target_memory_patch_available() -> bool {
    true
}

pub(crate) fn target_memory_matches(address: u64, expected: &[u8]) -> Result<bool, String> {
    let (actual, _) = snapshot_target_memory(address, expected.len())?;
    Ok(actual.as_ref() == expected)
}

fn snapshot_target_memory(address: u64, size: usize) -> Result<(Box<[u8]>, Vec<ProtectionRegion>), String> {
    if size == 0 {
        return Err("target-memory snapshot must not be empty".to_string());
    }
    let page_size = system_page_size().ok_or_else(|| "unable to determine system page size".to_string())?;
    let (page_start, page_length) = aligned_page_range(address, size, page_size).map_err(str::to_string)?;
    let page_end = page_start
        .checked_add(page_length)
        .ok_or_else(|| "page range overflow".to_string())?;
    let regions = query_protection_regions(page_start, page_end)?;
    if regions.iter().any(|region| region.protection & libc::PROT_READ == 0) {
        return Err("target-memory snapshot requires readable target memory".to_string());
    }
    let mut bytes = vec![0_u8; size];
    unsafe {
        std::ptr::copy_nonoverlapping(address as *const u8, bytes.as_mut_ptr(), bytes.len());
    }
    Ok((bytes.into_boxed_slice(), regions))
}

#[allow(dead_code)]
impl TargetMemoryPatch {
    pub(crate) fn prepare(address: u64, replacement: &[u8]) -> Result<Self, String> {
        if replacement.is_empty() {
            return Err("target-memory patch must not be empty".to_string());
        }
        let (original, regions) = snapshot_target_memory(address, replacement.len())?;
        Ok(Self {
            address,
            original,
            replacement: replacement.to_vec().into_boxed_slice(),
            regions,
            applied: false,
        })
    }

    pub(crate) const fn address(&self) -> u64 {
        self.address
    }

    pub(crate) const fn len(&self) -> usize {
        self.replacement.len()
    }

    pub(crate) const fn is_applied(&self) -> bool {
        self.applied
    }

    pub(crate) fn original_bytes(&self) -> &[u8] {
        &self.original
    }

    pub(crate) fn apply(&mut self) -> Result<bool, String> {
        if self.applied {
            return Ok(false);
        }
        self.applied = true;
        write_patch_bytes(&self.regions, self.address, &self.replacement)
            .map(|()| true)
            .map_err(|error| error)
    }

    pub(crate) fn rollback(&mut self) -> Result<bool, String> {
        if !self.applied {
            return Ok(false);
        }
        write_patch_bytes(&self.regions, self.address, &self.original)?;
        self.applied = false;
        Ok(true)
    }
}

#[allow(dead_code)]
impl Drop for TargetMemoryPatch {
    fn drop(&mut self) {
        if self.applied {
            let _ = self.rollback();
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn query_protection_regions(start: usize, end: usize) -> Result<Vec<ProtectionRegion>, String> {
    let maps = read_proc_self_maps().ok_or_else(|| "unable to read /proc/self/maps".to_string())?;
    let mut regions = Vec::new();
    let mut cursor = start;
    for entry in proc_maps_entries(&maps).filter(|entry| entry.end > start as u64 && entry.start < end as u64) {
        let entry_start = usize::try_from(entry.start).map_err(|_| "mapping address does not fit usize")?;
        let entry_end = usize::try_from(entry.end).map_err(|_| "mapping address does not fit usize")?;
        if entry_end <= cursor {
            continue;
        }
        if entry_start > cursor {
            return Err(format!("unmapped gap at {cursor:#x}"));
        }
        let region_end = entry_end.min(end);
        regions.push(ProtectionRegion {
            start: cursor,
            end: region_end,
            protection: entry.prot_flags(),
            max_protection: None,
        });
        cursor = region_end;
        if cursor == end {
            break;
        }
    }
    if cursor != end {
        return Err(format!("unmapped memory at {cursor:#x}"));
    }
    Ok(regions)
}

#[cfg(any(target_os = "ios", target_os = "macos"))]
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
const _: [(); 76] = [(); std::mem::size_of::<VmRegionSubmapInfo64>()];

#[cfg(any(target_os = "ios", target_os = "macos"))]
const VM_REGION_SUBMAP_INFO_COUNT_64: libc::mach_msg_type_number_t = (std::mem::size_of::<VmRegionSubmapInfo64>()
    / std::mem::size_of::<libc::natural_t>())
    as libc::mach_msg_type_number_t;

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

    fn mach_vm_protect(
        target_task: libc::vm_map_t,
        address: libc::mach_vm_address_t,
        size: libc::mach_vm_size_t,
        set_maximum: libc::boolean_t,
        new_protection: libc::vm_prot_t,
    ) -> libc::kern_return_t;
}

#[cfg(any(target_os = "ios", target_os = "macos"))]
fn darwin_region_at(cursor: usize) -> Result<ProtectionRegion, String> {
    let mut nesting_depth = 0;
    loop {
        let mut address = cursor as libc::mach_vm_address_t;
        let mut size = 0 as libc::mach_vm_size_t;
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
            return Err(format!(
                "mach_vm_region_recurse failed at {cursor:#x}: kern_return={result}"
            ));
        }
        if info.is_submap != 0 {
            nesting_depth = nesting_depth
                .checked_add(1)
                .ok_or_else(|| "Mach VM nesting depth overflow".to_string())?;
            continue;
        }
        let start = usize::try_from(address).map_err(|_| "Mach region start does not fit usize")?;
        let size = usize::try_from(size).map_err(|_| "Mach region size does not fit usize")?;
        let end = start
            .checked_add(size)
            .ok_or_else(|| "Mach region range overflow".to_string())?;
        if start > cursor || end <= cursor {
            return Err(format!("unmapped gap at {cursor:#x}"));
        }
        return Ok(ProtectionRegion {
            start,
            end,
            protection: info.protection,
            max_protection: Some(info.max_protection),
        });
    }
}

#[cfg(any(target_os = "ios", target_os = "macos"))]
fn query_protection_regions(start: usize, end: usize) -> Result<Vec<ProtectionRegion>, String> {
    let mut cursor = start;
    let mut regions = Vec::new();
    while cursor < end {
        let region = darwin_region_at(cursor)?;
        let region_end = region.end.min(end);
        regions.push(ProtectionRegion {
            start: cursor,
            end: region_end,
            ..region
        });
        if region_end <= cursor {
            return Err("Mach region query made no progress".to_string());
        }
        cursor = region_end;
    }
    Ok(regions)
}

#[cfg(not(any(target_os = "linux", target_os = "android", target_os = "ios", target_os = "macos")))]
fn query_protection_regions(_start: usize, _end: usize) -> Result<Vec<ProtectionRegion>, String> {
    Err("memory-region protection queries are unsupported on this platform".to_string())
}

#[cfg(target_arch = "aarch64")]
pub(crate) fn is_executable_address(address: u64) -> bool {
    let Ok(start) = usize::try_from(address) else {
        return false;
    };
    let Some(end) = start.checked_add(1) else {
        return false;
    };
    query_protection_regions(start, end).is_ok_and(|regions| {
        !regions.is_empty() && regions.iter().all(|region| region.protection & libc::PROT_EXEC != 0)
    })
}

fn set_region_protection(region: ProtectionRegion, protection: i32) -> Result<(), String> {
    let length = region
        .end
        .checked_sub(region.start)
        .ok_or_else(|| "invalid protection region".to_string())?;
    if length == 0 {
        return Err("empty protection region".to_string());
    }
    if unsafe { libc::mprotect(region.start as *mut libc::c_void, length, protection) } == 0 {
        return Ok(());
    }
    let mprotect_error = std::io::Error::last_os_error();

    #[cfg(any(target_os = "ios", target_os = "macos"))]
    {
        let result = unsafe {
            mach_vm_protect(
                mach_task_self_,
                region.start as libc::mach_vm_address_t,
                length as libc::mach_vm_size_t,
                0,
                protection as libc::vm_prot_t,
            )
        };
        if result == 0 {
            return Ok(());
        }
        return Err(format!(
            "mprotect failed: {mprotect_error}; mach_vm_protect kern_return={result}"
        ));
    }

    #[cfg(not(any(target_os = "ios", target_os = "macos")))]
    Err(format!("mprotect failed: {mprotect_error}"))
}

fn restore_regions(regions: &[ProtectionRegion]) -> Result<(), String> {
    let mut failures = Vec::new();
    for region in regions.iter().rev() {
        let mut last_error = None;
        for _ in 0..3 {
            match set_region_protection(*region, region.protection) {
                Ok(()) => {
                    last_error = None;
                    break;
                }
                Err(error) => last_error = Some(error),
            }
        }
        if let Some(error) = last_error {
            failures.push(format!("{:#x}..{:#x}: {error}", region.start, region.end));
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "failed to restore original memory protection: {}",
            failures.join("; ")
        ))
    }
}

fn apply_region_protection(regions: &[ProtectionRegion], protection: i32) -> Result<(), String> {
    for region in regions {
        if region.max_protection.is_some_and(|maximum| protection & !maximum != 0) {
            return Err(format!(
                "protection exceeds region maximum at {:#x}..{:#x}",
                region.start, region.end
            ));
        }
    }

    let mut changed = Vec::new();
    for region in regions {
        if region.protection == protection {
            continue;
        }
        if let Err(error) = set_region_protection(*region, protection) {
            let rollback = restore_regions(&changed);
            return Err(match rollback {
                Ok(()) => format!(
                    "unable to protect region {:#x}..{:#x}: {error}",
                    region.start, region.end
                ),
                Err(rollback_error) => format!(
                    "unable to protect region {:#x}..{:#x}: {error}; {rollback_error}",
                    region.start, region.end
                ),
            });
        }
        changed.push(*region);
    }
    Ok(())
}

fn regions_cover_range(regions: &[ProtectionRegion], address: u64, size: usize) -> bool {
    let Some((start, end)) = checked_address_range(address, size) else {
        return false;
    };
    let mut cursor = start;
    for region in regions {
        if region.end <= cursor {
            continue;
        }
        if region.start > cursor {
            return false;
        }
        cursor = region.end.min(end);
        if cursor == end {
            return true;
        }
    }
    false
}

fn make_regions_writable(regions: &[ProtectionRegion]) -> Result<Vec<ProtectionRegion>, String> {
    for region in regions {
        if region.protection & libc::PROT_WRITE == 0
            && region
                .max_protection
                .is_some_and(|maximum| maximum & libc::PROT_WRITE == 0)
        {
            return Err(format!(
                "region {:#x}..{:#x} cannot be made writable",
                region.start, region.end
            ));
        }
    }

    let mut changed = Vec::new();
    for region in regions {
        if region.protection & libc::PROT_WRITE != 0 {
            continue;
        }
        let with_write = region.protection | libc::PROT_WRITE;
        let changed_result = set_region_protection(*region, with_write).or_else(|first_error| {
            if region.protection & libc::PROT_EXEC == 0 {
                return Err(first_error);
            }
            let writable_non_executable = (region.protection | libc::PROT_READ | libc::PROT_WRITE) & !libc::PROT_EXEC;
            set_region_protection(*region, writable_non_executable)
                .map_err(|second_error| format!("{first_error}; W^X fallback failed: {second_error}"))
        });
        if let Err(error) = changed_result {
            let rollback = restore_regions(&changed);
            return Err(match rollback {
                Ok(()) => format!(
                    "unable to make region {:#x}..{:#x} writable: {error}",
                    region.start, region.end
                ),
                Err(rollback_error) => format!(
                    "unable to make region {:#x}..{:#x} writable: {error}; {rollback_error}",
                    region.start, region.end
                ),
            });
        }
        changed.push(*region);
    }
    Ok(changed)
}

fn write_patch_bytes(regions: &[ProtectionRegion], address: u64, bytes: &[u8]) -> Result<(), String> {
    if bytes.is_empty() {
        return Err("target-memory patch must not be empty".to_string());
    }
    if !regions_cover_range(regions, address, bytes.len()) {
        return Err("target-memory patch range is outside its prepared mapping".to_string());
    }
    let page_start = regions.first().map(|region| region.start).unwrap_or_default();
    let page_end = regions.last().map(|region| region.end).unwrap_or_default();
    let current_regions = query_protection_regions(page_start, page_end)?;
    if current_regions != regions {
        return Err("target-memory mapping or protection changed after preparation".to_string());
    }
    let changed = make_regions_writable(regions)?;
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), address as *mut u8, bytes.len());
    }
    let write_result = unsafe { flush_instruction_cache(address, bytes.len()) }
        .map_err(|message| format!("instruction-cache invalidation failed: {message}"));
    let restore_result = restore_regions(&changed);
    match (write_result, restore_result) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(write_error), Ok(())) => Err(write_error),
        (Ok(()), Err(restore_error)) => Err(restore_error),
        (Err(write_error), Err(restore_error)) => Err(format!("{write_error}; {restore_error}")),
    }
}

unsafe fn write_with_perm(address: u64, size: usize, write: impl FnOnce()) -> Result<(), String> {
    let page_size = system_page_size().ok_or_else(|| "unable to determine system page size".to_string())?;
    let (page_start, page_length) = aligned_page_range(address, size, page_size).map_err(str::to_string)?;
    let page_end = page_start
        .checked_add(page_length)
        .ok_or_else(|| "page range overflow".to_string())?;
    let regions = query_protection_regions(page_start, page_end)?;

    for region in &regions {
        if region.protection & libc::PROT_WRITE == 0
            && region.max_protection.is_some_and(|max| max & libc::PROT_WRITE == 0)
        {
            return Err(format!(
                "region {:#x}..{:#x} cannot be made writable",
                region.start, region.end
            ));
        }
    }

    let mut changed = Vec::new();
    for region in regions {
        if region.protection & libc::PROT_WRITE != 0 {
            continue;
        }
        let with_write = region.protection | libc::PROT_WRITE;
        let changed_result = set_region_protection(region, with_write).or_else(|first_error| {
            if region.protection & libc::PROT_EXEC == 0 {
                return Err(first_error);
            }
            let writable_non_executable = (region.protection | libc::PROT_READ | libc::PROT_WRITE) & !libc::PROT_EXEC;
            set_region_protection(region, writable_non_executable)
                .map_err(|second_error| format!("{first_error}; W^X fallback failed: {second_error}"))
        });
        if let Err(error) = changed_result {
            let rollback = restore_regions(&changed);
            return Err(match rollback {
                Ok(()) => format!(
                    "unable to make region {:#x}..{:#x} writable: {error}",
                    region.start, region.end
                ),
                Err(rollback_error) => format!(
                    "unable to make region {:#x}..{:#x} writable: {error}; {rollback_error}",
                    region.start, region.end
                ),
            });
        }
        changed.push(region);
    }

    write();
    restore_regions(&changed)
}

#[cfg_attr(not(any(target_os = "linux", target_os = "android")), allow(dead_code))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ProcMapEntry<'a> {
    pub(crate) start: u64,
    pub(crate) end: u64,
    pub(crate) perms: &'a str,
    pub(crate) path: Option<&'a str>,
}

#[cfg_attr(not(any(target_os = "linux", target_os = "android")), allow(dead_code))]
impl ProcMapEntry<'_> {
    pub(crate) fn contains(&self, addr: u64) -> bool {
        addr >= self.start && addr < self.end
    }

    fn prot_flags(&self) -> i32 {
        let permissions = self.perms.as_bytes();
        let mut protection = 0;
        if permissions.first() == Some(&b'r') {
            protection |= libc::PROT_READ;
        }
        if permissions.get(1) == Some(&b'w') {
            protection |= libc::PROT_WRITE;
        }
        if permissions.get(2) == Some(&b'x') {
            protection |= libc::PROT_EXEC;
        }
        protection
    }
}

#[cfg_attr(not(any(target_os = "linux", target_os = "android")), allow(dead_code))]
pub(crate) fn read_proc_self_maps() -> Option<String> {
    let bytes = std::fs::read("/proc/self/maps").ok()?;
    Some(String::from_utf8(bytes).unwrap_or_else(|error| String::from_utf8_lossy(error.as_bytes()).into_owned()))
}

#[cfg_attr(not(any(target_os = "linux", target_os = "android")), allow(dead_code))]
fn parse_proc_map_line(line: &str) -> Option<ProcMapEntry<'_>> {
    let mut fields = line.split_whitespace();
    let range = fields.next()?;
    let perms = fields.next()?;
    let _offset = fields.next()?;
    let _device = fields.next()?;
    let _inode = fields.next()?;
    let path = fields.next();
    let mut bounds = range.splitn(2, '-');
    let start = u64::from_str_radix(bounds.next()?, 16).ok()?;
    let end = u64::from_str_radix(bounds.next()?, 16).ok()?;
    Some(ProcMapEntry {
        start,
        end,
        perms,
        path,
    })
}

#[cfg_attr(not(any(target_os = "linux", target_os = "android")), allow(dead_code))]
pub(crate) fn proc_maps_entries(maps: &str) -> impl Iterator<Item = ProcMapEntry<'_>> + '_ {
    maps.lines().filter_map(parse_proc_map_line)
}

pub(crate) fn is_addr_accessible(address: u64, size: usize) -> bool {
    let Some((start, end)) = checked_address_range(address, size) else {
        return false;
    };

    #[cfg(any(target_os = "linux", target_os = "android", target_os = "ios", target_os = "macos"))]
    {
        return query_protection_regions(start, end)
            .is_ok_and(|regions| regions.iter().all(|region| region.protection & libc::PROT_READ != 0));
    }

    #[cfg(not(any(target_os = "linux", target_os = "android", target_os = "ios", target_os = "macos")))]
    unsafe {
        let Some(page_size) = system_page_size() else {
            return false;
        };
        let page_start = start & !(page_size - 1);
        let Ok(region_length) = end.checked_sub(page_start).ok_or(()) else {
            return false;
        };
        let page_count = match region_length.checked_add(page_size - 1) {
            Some(length) => length / page_size,
            None => return false,
        };
        let mut residency = vec![0u8; page_count];
        libc::mincore(
            page_start as *mut libc::c_void,
            region_length,
            residency.as_mut_ptr() as *mut _,
        ) == 0
    }
}

fn is_range_mapped(address: u64, size: usize) -> bool {
    let Some((start, end)) = checked_address_range(address, size) else {
        return false;
    };

    #[cfg(any(target_os = "linux", target_os = "android", target_os = "ios", target_os = "macos"))]
    {
        return query_protection_regions(start, end).is_ok();
    }

    #[cfg(not(any(target_os = "linux", target_os = "android", target_os = "ios", target_os = "macos")))]
    {
        is_addr_accessible(address, size)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        aligned_page_range, byte_from_number, checked_address_range, cleanup_memory_allocations, is_addr_accessible,
        parse_protection, read_proc_self_maps, register_memory_api, target_memory_matches, AllocationRegistry,
        TargetMemoryPatch,
    };

    #[test]
    fn parses_strict_protection_strings() {
        assert_eq!(parse_protection("---"), Ok(libc::PROT_NONE));
        assert_eq!(parse_protection("rw-"), Ok(libc::PROT_READ | libc::PROT_WRITE));
        assert_eq!(parse_protection("r-x"), Ok(libc::PROT_READ | libc::PROT_EXEC));
        assert_eq!(
            parse_protection("rwx"),
            Ok(libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC)
        );
        for invalid in ["", "rw", "rwx-", "wrx", "Rwx", "r--x", "abc"] {
            assert!(parse_protection(invalid).is_err(), "accepted {invalid:?}");
        }
    }

    #[test]
    fn validates_and_aligns_ranges_without_overflow() {
        assert_eq!(checked_address_range(0, 1), None);
        assert_eq!(checked_address_range(u64::MAX, 1), None);
        assert_eq!(aligned_page_range(0x1003, 0x1000, 0x1000), Ok((0x1000, 0x2000)));
        assert_eq!(aligned_page_range(0x2000, 0x1000, 0x1000), Ok((0x2000, 0x1000)));
        assert!(aligned_page_range(u64::MAX - 1, 8, 0x1000).is_err());
        assert!(aligned_page_range(0x1000, 1, 3000).is_err());
    }

    #[test]
    fn validates_array_number_bytes() {
        assert_eq!(byte_from_number(0.0), Some(0));
        assert_eq!(byte_from_number(255.0), Some(255));
        for invalid in [-1.0, 256.0, 1.5, f64::NAN, f64::INFINITY] {
            assert_eq!(byte_from_number(invalid), None);
        }
    }

    #[test]
    fn registry_cleans_only_the_selected_runtime() {
        let mut registry = AllocationRegistry::new();
        let first = vec![0u8; 8].into_boxed_slice();
        let second = vec![0u8; 16].into_boxed_slice();
        assert!(registry.insert(1, first).is_ok());
        assert!(registry.insert(2, second).is_ok());
        assert_eq!(registry.runtime_stats(1), (1, 8));
        assert_eq!(registry.runtime_stats(2), (1, 16));
        registry.cleanup_runtime(1);
        assert_eq!(registry.runtime_stats(1), (0, 0));
        assert_eq!(registry.runtime_stats(2), (1, 16));
    }

    #[test]
    fn p0_memory_bindings_round_trip_in_quickjs() {
        let runtime = crate::JSRuntime::new().expect("create QuickJS runtime");
        let context = runtime.new_context().expect("create QuickJS context");
        crate::ptr::register_ptr(&context);
        register_memory_api(&context);

        let result = context
            .eval(
                r#"
                (() => {
                    const p = Memory.alloc(16);
                    Memory.writeBytes(p, [0x78, 0x56, 0x34, 0x12]);
                    p.add(4).writeBytes(new Uint8Array([1, 2, 3, 4]));
                    Memory.writeBytes(p.add(8), new Uint8Array([5, 6]).buffer);
                    Memory.flushCodeCache(p, 16);

                    const text = Memory.allocUtf8String('hello');
                    let writestUnsupported = false;
                    try {
                        p.writest([]);
                    } catch (error) {
                        writestUnsupported = String(error).includes('Android RECOMP stealth-2');
                    }

                    return p.readU32() === 0x12345678n &&
                        p.add(4).readU32() === 0x04030201n &&
                        text.readUtf8String() === 'hello' &&
                        typeof p.protect === 'function' &&
                        writestUnsupported;
                })()
                "#,
                "<memory-p0-test>",
            )
            .expect("evaluate Memory P0 API test");
        assert_eq!(result.to_bool(), Some(true));
        result.free(context.as_ptr());

        cleanup_memory_allocations(runtime.as_ptr());
    }

    #[test]
    fn proc_maps_available_on_linux_host() {
        if cfg!(any(target_os = "linux", target_os = "android")) {
            assert!(read_proc_self_maps().is_some());
        }
    }

    #[test]
    fn null_address_is_not_accessible() {
        assert!(!is_addr_accessible(0, 1));
    }

    #[test]
    fn target_memory_patch_applies_and_rolls_back_original_bytes() {
        let mut target = vec![0x11_u8, 0x22, 0x33, 0x44].into_boxed_slice();
        let address = target.as_mut_ptr() as u64;
        let mut patch = TargetMemoryPatch::prepare(address, &[0xaa, 0xbb, 0xcc, 0xdd]).expect("prepare patch");
        assert_eq!(patch.address(), address);
        assert_eq!(patch.len(), 4);
        assert!(!patch.is_applied());
        assert!(patch.apply().expect("apply patch"));
        assert!(patch.is_applied());
        assert_eq!(&*target, &[0xaa, 0xbb, 0xcc, 0xdd]);
        assert!(!patch.apply().expect("idempotent apply"));
        assert!(patch.rollback().expect("rollback patch"));
        assert!(!patch.is_applied());
        assert_eq!(&*target, &[0x11, 0x22, 0x33, 0x44]);
        assert!(!patch.rollback().expect("idempotent rollback"));
    }

    #[test]
    fn target_memory_match_checks_the_complete_source_snapshot() {
        let mut target = vec![0x1f_u8, 0x20, 0x03, 0xd5, 0xc0, 0x03, 0x5f, 0xd6].into_boxed_slice();
        let address = target.as_mut_ptr() as u64;
        let expected = target.to_vec();

        assert!(target_memory_matches(address, &expected).expect("matching snapshot"));
        target[4] ^= 0xff;
        assert!(!target_memory_matches(address, &expected).expect("mismatched snapshot"));
    }
}
