use crate::context::JSContext;
use crate::ffi;
use crate::ptr::{create_native_pointer, get_native_pointer_addr};
use crate::util::{add_cfunction_to_object, js_throw_range_error, js_throw_type_error};
use crate::value::JSValue;

pub(crate) fn register_memory_api(ctx: &JSContext) {
    let global = ctx.global_object();
    let memory = ctx.new_object();

    unsafe {
        let ctx_ptr = ctx.as_ptr();
        let obj = memory.raw();
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
    }

    global.set_property(ctx.as_ptr(), "Memory", memory);
    global.free(ctx.as_ptr());
}

macro_rules! define_memory_read {
    ($name:ident, $rust_type:ty, $size:expr, $convert:expr) => {
        unsafe extern "C" fn $name(
            ctx: *mut ffi::JSContext,
            _this: ffi::JSValue,
            argc: i32,
            argv: *mut ffi::JSValue,
        ) -> ffi::JSValue {
            if argc < 1 {
                return js_throw_type_error(ctx, concat!(stringify!($name), " requires 1 argument"));
            }

            let addr = match get_addr_from_arg(ctx, JSValue(*argv)) {
                Some(addr) => addr,
                None => return js_throw_type_error(ctx, "invalid pointer"),
            };

            if !is_addr_accessible(addr, $size) {
                return js_throw_range_error(ctx, "invalid memory address");
            }

            let value = std::ptr::read_unaligned(addr as *const $rust_type);
            $convert(ctx, value)
        }
    };
}

macro_rules! define_memory_write {
    ($name:ident, $rust_type:ty, $size:expr, $extract:expr) => {
        unsafe extern "C" fn $name(
            ctx: *mut ffi::JSContext,
            _this: ffi::JSValue,
            argc: i32,
            argv: *mut ffi::JSValue,
        ) -> ffi::JSValue {
            if argc < 2 {
                return js_throw_type_error(ctx, concat!(stringify!($name), " requires 2 arguments"));
            }

            let addr = match get_addr_from_arg(ctx, JSValue(*argv)) {
                Some(addr) => addr,
                None => return js_throw_type_error(ctx, "invalid pointer"),
            };

            if !is_addr_accessible(addr, $size) {
                return js_throw_range_error(ctx, "invalid memory address");
            }

            let value: $rust_type = match $extract(ctx, JSValue(*argv.add(1))) {
                Some(value) => value,
                None => return js_throw_type_error(ctx, "invalid numeric value"),
            };

            if !write_with_perm(addr, $size, || {
                std::ptr::write_unaligned(addr as *mut $rust_type, value);
            }) {
                return js_throw_range_error(ctx, "unable to make target memory writable");
            }

            JSValue::undefined().raw()
        }
    };
}

define_memory_read!(memory_read_u8, u8, 1, |_, value: u8| JSValue::int(value as i32).raw());
define_memory_read!(memory_read_u16, u16, 2, |_, value: u16| JSValue::int(value as i32)
    .raw());
define_memory_read!(memory_read_u32, u32, 4, |ctx, value: u32| ffi::JS_NewBigUint64(
    ctx,
    value as u64
));
define_memory_read!(memory_read_u64, u64, 8, |ctx, value: u64| ffi::JS_NewBigUint64(
    ctx, value
));
define_memory_read!(memory_read_pointer, u64, 8, |ctx, value: u64| create_native_pointer(
    ctx, value
)
.raw());

define_memory_write!(memory_write_u8, u8, 1, |ctx: *mut ffi::JSContext, value: JSValue| {
    value.to_i64(ctx).map(|value| value as u8)
});
define_memory_write!(memory_write_u16, u16, 2, |ctx: *mut ffi::JSContext, value: JSValue| {
    value.to_i64(ctx).map(|value| value as u16)
});
define_memory_write!(memory_write_u32, u32, 4, |ctx: *mut ffi::JSContext, value: JSValue| {
    value.to_i64(ctx).map(|value| value as u32)
});
define_memory_write!(memory_write_u64, u64, 8, |ctx: *mut ffi::JSContext, value: JSValue| {
    if let Some(pointer) = get_native_pointer_addr(value) {
        Some(pointer)
    } else {
        value.to_u64(ctx)
    }
});

unsafe extern "C" fn memory_write_pointer(
    ctx: *mut ffi::JSContext,
    this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    memory_write_u64(ctx, this, argc, argv)
}

unsafe extern "C" fn memory_read_cstring(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 1 {
        return js_throw_type_error(ctx, "readCString() requires 1 argument");
    }

    let addr = match get_addr_from_arg(ctx, JSValue(*argv)) {
        Some(addr) => addr,
        None => return js_throw_type_error(ctx, "invalid pointer"),
    };
    if !is_addr_accessible(addr, 1) {
        return js_throw_range_error(ctx, "invalid memory address");
    }

    const MAX_CSTRING_LEN: usize = 4096;
    const PAGE_SIZE: u64 = 4096;
    let mut len = 0usize;
    let mut next_page_check = (addr + PAGE_SIZE) & !(PAGE_SIZE - 1);
    while len < MAX_CSTRING_LEN {
        let byte_addr = addr + len as u64;
        if byte_addr >= next_page_check {
            if !is_addr_accessible(byte_addr, 1) {
                break;
            }
            next_page_check = (byte_addr + PAGE_SIZE) & !(PAGE_SIZE - 1);
        }

        if *(byte_addr as *const u8) == 0 {
            break;
        }
        len += 1;
    }

    if len >= MAX_CSTRING_LEN {
        return js_throw_range_error(ctx, "readCString(): string exceeds 4096-byte limit");
    }

    let slice = std::slice::from_raw_parts(addr as *const u8, len);
    let value = String::from_utf8_lossy(slice);
    JSValue::string(ctx, &value).raw()
}

unsafe extern "C" fn memory_read_utf8_string(
    ctx: *mut ffi::JSContext,
    this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    memory_read_cstring(ctx, this, argc, argv)
}

unsafe extern "C" fn memory_read_byte_array(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 2 {
        return js_throw_type_error(ctx, "readByteArray() requires 2 arguments");
    }

    let addr = match get_addr_from_arg(ctx, JSValue(*argv)) {
        Some(addr) => addr,
        None => return js_throw_type_error(ctx, "invalid pointer"),
    };

    let Some(length) = JSValue(*argv.add(1)).to_i64(ctx) else {
        return js_throw_type_error(ctx, "readByteArray(): length must be numeric");
    };
    if length <= 0 {
        return js_throw_range_error(ctx, "readByteArray(): length must be positive");
    }
    if length > 1024 * 1024 * 1024 {
        return js_throw_range_error(ctx, "readByteArray(): length exceeds 1GB");
    }

    let length = length as usize;
    if !is_addr_accessible(addr, length) {
        return js_throw_range_error(ctx, "invalid memory address");
    }

    let slice = std::slice::from_raw_parts(addr as *const u8, length);
    ffi::JS_NewArrayBufferCopy(ctx, slice.as_ptr(), length)
}

unsafe fn get_addr_from_arg(ctx: *mut ffi::JSContext, value: JSValue) -> Option<u64> {
    get_native_pointer_addr(value).or_else(|| value.to_u64(ctx))
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn get_page_prot(addr: u64) -> Option<i32> {
    let maps = read_proc_self_maps()?;
    let prot = proc_maps_entries(&maps)
        .find(|entry| entry.contains(addr))
        .map(|entry| entry.prot_flags());
    prot
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn get_page_prot(_addr: u64) -> Option<i32> {
    None
}

unsafe fn write_with_perm(addr: u64, size: usize, write_fn: impl FnOnce()) -> bool {
    let page_size = 0x1000usize;
    let start_page = (addr as usize) & !(page_size - 1);
    let end_page = ((addr as usize) + size - 1) & !(page_size - 1);
    let mprotect_len = if start_page == end_page {
        page_size
    } else {
        (end_page - start_page) + page_size
    };

    if let Some(orig_prot) = get_page_prot(addr) {
        if (orig_prot & libc::PROT_WRITE) != 0 {
            write_fn();
            return true;
        }

        if libc::mprotect(
            start_page as *mut libc::c_void,
            mprotect_len,
            orig_prot | libc::PROT_WRITE,
        ) != 0
        {
            return false;
        }

        write_fn();
        let _ = libc::mprotect(start_page as *mut libc::c_void, mprotect_len, orig_prot);
        return true;
    }

    let prot = libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC;
    if libc::mprotect(start_page as *mut libc::c_void, mprotect_len, prot) != 0 {
        return false;
    }
    write_fn();
    true
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ProcMapEntry<'a> {
    start: u64,
    end: u64,
    perms: &'a str,
    path: Option<&'a str>,
}

impl ProcMapEntry<'_> {
    fn contains(&self, addr: u64) -> bool {
        addr >= self.start && addr < self.end
    }

    fn prot_flags(&self) -> i32 {
        let perms = self.perms.as_bytes();
        let mut prot = 0i32;
        if perms.first() == Some(&b'r') {
            prot |= libc::PROT_READ;
        }
        if perms.get(1) == Some(&b'w') {
            prot |= libc::PROT_WRITE;
        }
        if perms.get(2) == Some(&b'x') {
            prot |= libc::PROT_EXEC;
        }
        prot
    }
}

fn read_proc_self_maps() -> Option<String> {
    let bytes = std::fs::read("/proc/self/maps").ok()?;
    Some(String::from_utf8(bytes).unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned()))
}

fn parse_proc_map_line(line: &str) -> Option<ProcMapEntry<'_>> {
    let mut fields = line.split_whitespace();
    let range = fields.next()?;
    let perms = fields.next()?;
    let _offset = fields.next()?;
    let _dev = fields.next()?;
    let _inode = fields.next()?;
    let path = fields.next();

    let mut parts = range.splitn(2, '-');
    let start = u64::from_str_radix(parts.next()?, 16).ok()?;
    let end = u64::from_str_radix(parts.next()?, 16).ok()?;

    Some(ProcMapEntry {
        start,
        end,
        perms,
        path,
    })
}

fn proc_maps_entries(maps: &str) -> impl Iterator<Item = ProcMapEntry<'_>> + '_ {
    maps.lines().filter_map(parse_proc_map_line)
}

fn is_addr_accessible(addr: u64, size: usize) -> bool {
    if addr == 0 || size == 0 {
        return false;
    }

    unsafe {
        const PAGE_SIZE: usize = 0x1000;
        let page_addr = (addr as usize) & !(PAGE_SIZE - 1);
        let end = match (addr as usize).checked_add(size) {
            Some(end) => end,
            None => return false,
        };
        let region_len = end.saturating_sub(page_addr);
        let pages = (region_len + PAGE_SIZE - 1) / PAGE_SIZE;
        let mut vec = vec![0u8; pages];
        libc::mincore(page_addr as *mut libc::c_void, region_len, vec.as_mut_ptr() as *mut _) == 0
    }
}

#[cfg(test)]
mod tests {
    use super::{is_addr_accessible, read_proc_self_maps};

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
}
