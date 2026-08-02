//! Frida-compatible synchronous File API.

use crate::context::JSContext;
use crate::ffi;
use crate::util::{add_cfunction_to_object, js_throw_internal_error, js_throw_range_error, js_throw_type_error};
use crate::value::JSValue;
use std::ffi::CString;
use std::io::{Read, Write};
use std::sync::atomic::{AtomicU32, Ordering};

static FILE_CLASS_ID: AtomicU32 = AtomicU32::new(0);
const FILE_CLASS_NAME: &[u8] = b"File\0";
const DEFAULT_READ_CHUNK_SIZE: usize = 8192;

struct FridaFile {
    fp: *mut libc::FILE,
}

impl FridaFile {
    fn is_closed(&self) -> bool {
        self.fp.is_null()
    }
}

unsafe extern "C" fn file_finalizer(_rt: *mut ffi::JSRuntime, val: ffi::JSValue) {
    let class_id = FILE_CLASS_ID.load(Ordering::Relaxed);
    if class_id == 0 {
        return;
    }

    let opaque = ffi::JS_GetOpaque(val, class_id);
    if opaque.is_null() {
        return;
    }

    let mut state = Box::from_raw(opaque as *mut FridaFile);
    if !state.fp.is_null() {
        libc::fclose(state.fp);
        state.fp = std::ptr::null_mut();
    }
}

fn get_or_init_file_class_id(ctx: *mut ffi::JSContext) -> u32 {
    let mut class_id = FILE_CLASS_ID.load(Ordering::Relaxed);
    if class_id == 0 {
        let mut new_id = 0;
        new_id = unsafe { ffi::JS_NewClassID(&mut new_id) };
        match FILE_CLASS_ID.compare_exchange(0, new_id, Ordering::SeqCst, Ordering::Relaxed) {
            Ok(_) => class_id = new_id,
            Err(existing) => class_id = existing,
        }
    }

    unsafe {
        let runtime = ffi::JS_GetRuntime(ctx);
        let class_def = ffi::JSClassDef {
            class_name: FILE_CLASS_NAME.as_ptr() as *const _,
            finalizer: Some(file_finalizer),
            gc_mark: None,
            call: None,
            exotic: std::ptr::null_mut(),
        };
        let _ = ffi::JS_NewClass(runtime, class_id, &class_def);
    }

    class_id
}

unsafe fn get_file_state(ctx: *mut ffi::JSContext, this: ffi::JSValue) -> Result<*mut FridaFile, ffi::JSValue> {
    let class_id = FILE_CLASS_ID.load(Ordering::Relaxed);
    if class_id == 0 {
        return Err(js_throw_type_error(ctx, "Not a File"));
    }

    let opaque = ffi::JS_GetOpaque(this, class_id);
    if opaque.is_null() {
        return Err(js_throw_type_error(ctx, "Not a File"));
    }

    let state = opaque as *mut FridaFile;
    if (&*state).is_closed() {
        return Err(js_throw_type_error(ctx, "File is closed"));
    }
    Ok(state)
}

unsafe fn required_string_arg(
    ctx: *mut ffi::JSContext,
    argc: i32,
    argv: *mut ffi::JSValue,
    index: usize,
    message: &str,
) -> Result<String, ffi::JSValue> {
    if argc <= index as i32 {
        return Err(js_throw_type_error(ctx, message));
    }
    JSValue(*argv.add(index))
        .to_string(ctx)
        .ok_or_else(|| js_throw_type_error(ctx, message))
}

fn cstring_arg(ctx: *mut ffi::JSContext, value: &str, what: &str) -> Result<CString, ffi::JSValue> {
    CString::new(value).map_err(|_| js_throw_type_error(ctx, &format!("{what} must not contain NUL bytes")))
}

fn io_error(ctx: *mut ffi::JSContext, action: &str, detail: impl AsRef<str>) -> ffi::JSValue {
    js_throw_internal_error(ctx, &format!("File.{action} failed: {}", detail.as_ref()))
}

fn errno_error(ctx: *mut ffi::JSContext, action: &str) -> ffi::JSValue {
    io_error(ctx, action, std::io::Error::last_os_error().to_string())
}

unsafe fn extract_bytes(ctx: *mut ffi::JSContext, val: JSValue) -> Result<Vec<u8>, ffi::JSValue> {
    let mut size = 0;
    let buf_ptr = ffi::JS_GetArrayBuffer(ctx, &mut size, val.raw());
    if !buf_ptr.is_null() {
        return Ok(std::slice::from_raw_parts(buf_ptr, size).to_vec());
    }

    let mut byte_offset = 0;
    let mut byte_length = 0;
    let mut bytes_per_element = 0;
    let typed_array_buffer = ffi::JS_GetTypedArrayBuffer(
        ctx,
        val.raw(),
        &mut byte_offset,
        &mut byte_length,
        &mut bytes_per_element,
    );
    if ffi::qjs_is_exception(typed_array_buffer) != 0 {
        let exception = ffi::JS_GetException(ctx);
        ffi::qjs_free_value(ctx, exception);
    } else {
        let typed_array_buffer_value = JSValue(typed_array_buffer);
        let mut result = None;
        if byte_length == 0 {
            result = Some(Vec::new());
        } else {
            let mut buffer_size = 0;
            let buffer_ptr = ffi::JS_GetArrayBuffer(ctx, &mut buffer_size, typed_array_buffer);
            if !buffer_ptr.is_null() && byte_offset + byte_length <= buffer_size {
                result = Some(std::slice::from_raw_parts(buffer_ptr.add(byte_offset), byte_length).to_vec());
            }
        }
        typed_array_buffer_value.free(ctx);
        if let Some(bytes) = result {
            return Ok(bytes);
        }
    }

    if ffi::JS_IsArray(ctx, val.raw()) != 0 {
        let length_atom = ffi::JS_NewAtom(ctx, b"length\0".as_ptr() as *const _);
        let length_value_raw = ffi::qjs_get_property(ctx, val.raw(), length_atom);
        ffi::JS_FreeAtom(ctx, length_atom);
        let length_value = JSValue(length_value_raw);
        let length = length_value.to_i64(ctx).unwrap_or(0);
        length_value.free(ctx);
        if length < 0 {
            return Err(js_throw_range_error(ctx, "byte array length must be non-negative"));
        }

        let mut bytes = Vec::with_capacity(length as usize);
        for index in 0..length as usize {
            let element = JSValue(ffi::JS_GetPropertyUint32(ctx, val.raw(), index as u32));
            let byte = match element.to_i64(ctx) {
                Some(value) if (0..=255).contains(&value) => value as u8,
                _ => {
                    element.free(ctx);
                    return Err(js_throw_type_error(
                        ctx,
                        "byte array elements must be integers in the range 0..255",
                    ));
                }
            };
            element.free(ctx);
            bytes.push(byte);
        }
        return Ok(bytes);
    }

    Err(js_throw_type_error(
        ctx,
        "data must be an ArrayBuffer, TypedArray, or Array<number>",
    ))
}

unsafe fn parse_size_arg(
    ctx: *mut ffi::JSContext,
    argc: i32,
    argv: *mut ffi::JSValue,
    index: usize,
) -> Result<Option<usize>, ffi::JSValue> {
    if argc <= index as i32 {
        return Ok(None);
    }
    let arg = JSValue(*argv.add(index));
    if arg.is_undefined() || arg.is_null() {
        return Ok(None);
    }
    let raw = arg
        .to_i64(ctx)
        .ok_or_else(|| js_throw_type_error(ctx, "size must be a number"))?;
    if raw < 0 {
        return Err(js_throw_range_error(ctx, "size must be non-negative"));
    }
    Ok(Some(raw as usize))
}

unsafe fn read_from_file(
    ctx: *mut ffi::JSContext,
    state: &mut FridaFile,
    size: Option<usize>,
) -> Result<Vec<u8>, ffi::JSValue> {
    let mut output = Vec::new();

    if let Some(size) = size {
        output.resize(size, 0);
        let count = if size == 0 {
            0
        } else {
            libc::fread(output.as_mut_ptr() as *mut libc::c_void, 1, size, state.fp)
        };
        output.truncate(count);
        if count < size && libc::ferror(state.fp) != 0 {
            return Err(errno_error(ctx, "read"));
        }
        return Ok(output);
    }

    let mut buffer = vec![0u8; DEFAULT_READ_CHUNK_SIZE];
    loop {
        let count = libc::fread(buffer.as_mut_ptr() as *mut libc::c_void, 1, buffer.len(), state.fp);
        if count > 0 {
            output.extend_from_slice(&buffer[..count]);
        }
        if count < buffer.len() {
            if libc::ferror(state.fp) != 0 {
                return Err(errno_error(ctx, "read"));
            }
            break;
        }
    }

    Ok(output)
}

unsafe fn seek_back(
    ctx: *mut ffi::JSContext,
    state: &mut FridaFile,
    count: usize,
    action: &str,
) -> Result<(), ffi::JSValue> {
    if count != 0 && libc::fseek(state.fp, -(count as libc::c_long), libc::SEEK_CUR) != 0 {
        return Err(errno_error(ctx, action));
    }
    Ok(())
}

unsafe extern "C" fn file_read_all_bytes(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let path = match required_string_arg(ctx, argc, argv, 0, "File.readAllBytes(path) requires a path") {
        Ok(value) => value,
        Err(error) => return error,
    };

    match std::fs::read(path) {
        Ok(bytes) => ffi::JS_NewArrayBufferCopy(ctx, bytes.as_ptr(), bytes.len()),
        Err(error) => io_error(ctx, "readAllBytes", error.to_string()),
    }
}

unsafe extern "C" fn file_read_all_text(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let path = match required_string_arg(ctx, argc, argv, 0, "File.readAllText(path) requires a path") {
        Ok(value) => value,
        Err(error) => return error,
    };

    let mut file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(error) => return io_error(ctx, "readAllText", error.to_string()),
    };
    let mut text = String::new();
    match file.read_to_string(&mut text) {
        Ok(_) => JSValue::string(ctx, &text).raw(),
        Err(error) => io_error(ctx, "readAllText", error.to_string()),
    }
}

unsafe extern "C" fn file_write_all_bytes(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let path = match required_string_arg(ctx, argc, argv, 0, "File.writeAllBytes(path, data) requires a path") {
        Ok(value) => value,
        Err(error) => return error,
    };
    if argc < 2 {
        return js_throw_type_error(ctx, "File.writeAllBytes(path, data) requires data");
    }
    let bytes = match extract_bytes(ctx, JSValue(*argv.add(1))) {
        Ok(bytes) => bytes,
        Err(error) => return error,
    };

    match std::fs::write(path, bytes) {
        Ok(()) => JSValue::undefined().raw(),
        Err(error) => io_error(ctx, "writeAllBytes", error.to_string()),
    }
}

unsafe extern "C" fn file_write_all_text(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let path = match required_string_arg(ctx, argc, argv, 0, "File.writeAllText(path, text) requires a path") {
        Ok(value) => value,
        Err(error) => return error,
    };
    let text = match required_string_arg(ctx, argc, argv, 1, "File.writeAllText(path, text) requires text") {
        Ok(value) => value,
        Err(error) => return error,
    };

    match std::fs::File::create(path).and_then(|mut file| file.write_all(text.as_bytes())) {
        Ok(()) => JSValue::undefined().raw(),
        Err(error) => io_error(ctx, "writeAllText", error.to_string()),
    }
}

unsafe extern "C" fn file_constructor(
    ctx: *mut ffi::JSContext,
    _new_target: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let path = match required_string_arg(ctx, argc, argv, 0, "new File(filePath, mode) requires filePath") {
        Ok(value) => value,
        Err(error) => return error,
    };
    let mode = match required_string_arg(ctx, argc, argv, 1, "new File(filePath, mode) requires mode") {
        Ok(value) => value,
        Err(error) => return error,
    };

    let c_path = match cstring_arg(ctx, &path, "filePath") {
        Ok(value) => value,
        Err(error) => return error,
    };
    let c_mode = match cstring_arg(ctx, &mode, "mode") {
        Ok(value) => value,
        Err(error) => return error,
    };

    let fp = libc::fopen(c_path.as_ptr(), c_mode.as_ptr());
    if fp.is_null() {
        return errno_error(ctx, "open");
    }

    let class_id = get_or_init_file_class_id(ctx);
    let object = ffi::JS_NewObjectClass(ctx, class_id as i32);
    if ffi::qjs_is_exception(object) != 0 {
        libc::fclose(fp);
        return object;
    }

    let state = Box::into_raw(Box::new(FridaFile { fp }));
    ffi::JS_SetOpaque(object, state as *mut _);
    object
}

unsafe extern "C" fn file_tell(
    ctx: *mut ffi::JSContext,
    this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let state = match get_file_state(ctx, this) {
        Ok(state) => &mut *state,
        Err(error) => return error,
    };
    let position = libc::ftell(state.fp);
    if position < 0 {
        return errno_error(ctx, "tell");
    }
    ffi::qjs_new_int64(ctx, position as i64)
}

unsafe extern "C" fn file_seek(
    ctx: *mut ffi::JSContext,
    this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let state = match get_file_state(ctx, this) {
        Ok(state) => &mut *state,
        Err(error) => return error,
    };
    if argc < 1 {
        return js_throw_type_error(ctx, "seek(offset[, whence]) requires offset");
    }
    let offset = match JSValue(*argv).to_i64(ctx) {
        Some(value) => value,
        None => return js_throw_type_error(ctx, "offset must be a number"),
    };
    let whence = if argc >= 2 {
        match JSValue(*argv.add(1)).to_i64(ctx) {
            Some(value) => value as i32,
            None => return js_throw_type_error(ctx, "whence must be a number"),
        }
    } else {
        libc::SEEK_SET
    };

    let result = libc::fseek(state.fp, offset as libc::c_long, whence);
    if result != 0 {
        return errno_error(ctx, "seek");
    }
    ffi::qjs_new_int64(ctx, result as i64)
}

unsafe extern "C" fn file_read_bytes(
    ctx: *mut ffi::JSContext,
    this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let state = match get_file_state(ctx, this) {
        Ok(state) => &mut *state,
        Err(error) => return error,
    };
    let size = match parse_size_arg(ctx, argc, argv, 0) {
        Ok(value) => value,
        Err(error) => return error,
    };
    match read_from_file(ctx, state, size) {
        Ok(bytes) => ffi::JS_NewArrayBufferCopy(ctx, bytes.as_ptr(), bytes.len()),
        Err(error) => error,
    }
}

unsafe extern "C" fn file_read_text(
    ctx: *mut ffi::JSContext,
    this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let state = match get_file_state(ctx, this) {
        Ok(state) => &mut *state,
        Err(error) => return error,
    };
    let size = match parse_size_arg(ctx, argc, argv, 0) {
        Ok(value) => value,
        Err(error) => return error,
    };
    let bytes = match read_from_file(ctx, state, size) {
        Ok(bytes) => bytes,
        Err(error) => return error,
    };
    match String::from_utf8(bytes) {
        Ok(text) => JSValue::string(ctx, &text).raw(),
        Err(error) => {
            if let Err(seek_error) = seek_back(ctx, state, error.as_bytes().len(), "readText") {
                return seek_error;
            }
            io_error(ctx, "readText", error.to_string())
        }
    }
}

unsafe extern "C" fn file_read_line(
    ctx: *mut ffi::JSContext,
    this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let state = match get_file_state(ctx, this) {
        Ok(state) => &mut *state,
        Err(error) => return error,
    };

    let mut line = Vec::new();
    loop {
        let mut byte = 0u8;
        let count = libc::fread(&mut byte as *mut u8 as *mut libc::c_void, 1, 1, state.fp);
        if count == 1 {
            line.push(byte);
            if byte == b'\n' {
                break;
            }
            continue;
        }
        if libc::ferror(state.fp) != 0 {
            return errno_error(ctx, "readLine");
        }
        break;
    }

    match String::from_utf8(line) {
        Ok(text) => JSValue::string(ctx, &text).raw(),
        Err(error) => {
            if let Err(seek_error) = seek_back(ctx, state, error.as_bytes().len(), "readLine") {
                return seek_error;
            }
            io_error(ctx, "readLine", error.to_string())
        }
    }
}

unsafe extern "C" fn file_write(
    ctx: *mut ffi::JSContext,
    this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let state = match get_file_state(ctx, this) {
        Ok(state) => &mut *state,
        Err(error) => return error,
    };
    if argc < 1 {
        return js_throw_type_error(ctx, "write(data) requires data");
    }

    let arg = JSValue(*argv);
    let bytes = if arg.is_string() {
        match arg.to_string(ctx) {
            Some(value) => value.into_bytes(),
            None => return js_throw_type_error(ctx, "data string is invalid"),
        }
    } else {
        match extract_bytes(ctx, arg) {
            Ok(bytes) => bytes,
            Err(error) => return error,
        }
    };

    if !bytes.is_empty() {
        let count = libc::fwrite(bytes.as_ptr() as *const libc::c_void, 1, bytes.len(), state.fp);
        if count != bytes.len() {
            return errno_error(ctx, "write");
        }
    }

    JSValue::undefined().raw()
}

unsafe extern "C" fn file_flush(
    ctx: *mut ffi::JSContext,
    this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let state = match get_file_state(ctx, this) {
        Ok(state) => &mut *state,
        Err(error) => return error,
    };
    if libc::fflush(state.fp) != 0 {
        return errno_error(ctx, "flush");
    }
    JSValue::undefined().raw()
}

unsafe extern "C" fn file_close(
    ctx: *mut ffi::JSContext,
    this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let class_id = FILE_CLASS_ID.load(Ordering::Relaxed);
    if class_id == 0 {
        return js_throw_type_error(ctx, "Not a File");
    }
    let opaque = ffi::JS_GetOpaque(this, class_id);
    if opaque.is_null() {
        return js_throw_type_error(ctx, "Not a File");
    }
    let state = &mut *(opaque as *mut FridaFile);
    if state.fp.is_null() {
        return JSValue::undefined().raw();
    }

    let fp = state.fp;
    state.fp = std::ptr::null_mut();
    if libc::fclose(fp) != 0 {
        return errno_error(ctx, "close");
    }
    JSValue::undefined().raw()
}

unsafe fn add_int_property(ctx: *mut ffi::JSContext, object: ffi::JSValue, name: &str, value: i32) {
    let name = CString::new(name).unwrap();
    ffi::JS_DefinePropertyValueStr(
        ctx,
        object,
        name.as_ptr(),
        JSValue::int(value).raw(),
        ffi::JS_PROP_C_W_E as i32,
    );
}

/// Register the global Frida-compatible File constructor.
pub fn register_file_api(ctx: &JSContext) {
    let global = ctx.global_object();

    unsafe {
        let ctx_ptr = ctx.as_ptr();
        let class_id = get_or_init_file_class_id(ctx_ptr);

        let prototype = ffi::JS_NewObject(ctx_ptr);
        add_cfunction_to_object(ctx_ptr, prototype, "tell", file_tell, 0);
        add_cfunction_to_object(ctx_ptr, prototype, "seek", file_seek, 2);
        add_cfunction_to_object(ctx_ptr, prototype, "readBytes", file_read_bytes, 1);
        add_cfunction_to_object(ctx_ptr, prototype, "readText", file_read_text, 1);
        add_cfunction_to_object(ctx_ptr, prototype, "readLine", file_read_line, 0);
        add_cfunction_to_object(ctx_ptr, prototype, "write", file_write, 1);
        add_cfunction_to_object(ctx_ptr, prototype, "flush", file_flush, 0);
        add_cfunction_to_object(ctx_ptr, prototype, "close", file_close, 0);

        let constructor_name = CString::new("File").unwrap();
        let constructor = ffi::JS_NewCFunction2(
            ctx_ptr,
            Some(file_constructor),
            constructor_name.as_ptr(),
            2,
            ffi::JSCFunctionEnum_JS_CFUNC_constructor,
            0,
        );
        add_cfunction_to_object(ctx_ptr, constructor, "readAllBytes", file_read_all_bytes, 1);
        add_cfunction_to_object(ctx_ptr, constructor, "readAllText", file_read_all_text, 1);
        add_cfunction_to_object(ctx_ptr, constructor, "writeAllBytes", file_write_all_bytes, 2);
        add_cfunction_to_object(ctx_ptr, constructor, "writeAllText", file_write_all_text, 2);
        add_int_property(ctx_ptr, constructor, "SEEK_SET", libc::SEEK_SET);
        add_int_property(ctx_ptr, constructor, "SEEK_CUR", libc::SEEK_CUR);
        add_int_property(ctx_ptr, constructor, "SEEK_END", libc::SEEK_END);

        ffi::JS_SetConstructor(ctx_ptr, constructor, prototype);
        ffi::JS_SetClassProto(ctx_ptr, class_id, prototype);
        global.set_property(ctx_ptr, "File", JSValue(constructor));
    }

    global.free(ctx.as_ptr());
}
