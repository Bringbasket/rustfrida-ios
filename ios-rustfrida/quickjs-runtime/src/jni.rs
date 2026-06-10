use crate::context::JSContext;
use crate::ffi;
use crate::memory::is_addr_accessible;
use crate::ptr::{create_native_pointer, get_native_pointer_addr};
use crate::util::{add_cfunction_to_object, js_throw_internal_error, js_throw_range_error, js_throw_type_error};
use crate::value::JSValue;

const JNI_UNSUPPORTED_REASON: &str =
    "Jni/JNIEnv APIs are Android-only; use ObjC, Swift, Native, and Interceptor APIs on iOS";

const JNI_FUNCTION_NAMES: &[&str] = &[
    "DefineClass",
    "FindClass",
    "FromReflectedMethod",
    "FromReflectedField",
    "ToReflectedMethod",
    "GetSuperclass",
    "IsAssignableFrom",
    "ToReflectedField",
    "Throw",
    "ThrowNew",
    "ExceptionOccurred",
    "ExceptionDescribe",
    "ExceptionClear",
    "FatalError",
    "PushLocalFrame",
    "PopLocalFrame",
    "NewGlobalRef",
    "DeleteGlobalRef",
    "DeleteLocalRef",
    "IsSameObject",
    "NewLocalRef",
    "EnsureLocalCapacity",
    "AllocObject",
    "NewObjectA",
    "GetObjectClass",
    "IsInstanceOf",
    "GetMethodID",
    "CallObjectMethodA",
    "CallBooleanMethodA",
    "CallByteMethodA",
    "CallCharMethodA",
    "CallShortMethodA",
    "CallIntMethodA",
    "CallLongMethodA",
    "CallFloatMethodA",
    "CallDoubleMethodA",
    "CallVoidMethodA",
    "CallNonvirtualObjectMethodA",
    "CallNonvirtualBooleanMethodA",
    "CallNonvirtualIntMethodA",
    "CallNonvirtualLongMethodA",
    "CallNonvirtualFloatMethodA",
    "CallNonvirtualDoubleMethodA",
    "CallNonvirtualVoidMethodA",
    "GetFieldID",
    "GetObjectField",
    "GetBooleanField",
    "GetByteField",
    "GetCharField",
    "GetShortField",
    "GetIntField",
    "GetLongField",
    "GetFloatField",
    "GetDoubleField",
    "GetStaticMethodID",
    "CallStaticObjectMethodA",
    "CallStaticBooleanMethodA",
    "CallStaticByteMethodA",
    "CallStaticCharMethodA",
    "CallStaticShortMethodA",
    "CallStaticIntMethodA",
    "CallStaticLongMethodA",
    "CallStaticFloatMethodA",
    "CallStaticDoubleMethodA",
    "CallStaticVoidMethodA",
    "GetStaticFieldID",
    "GetStaticObjectField",
    "GetStaticBooleanField",
    "GetStaticByteField",
    "GetStaticCharField",
    "GetStaticShortField",
    "GetStaticIntField",
    "GetStaticLongField",
    "GetStaticFloatField",
    "GetStaticDoubleField",
    "NewStringUTF",
    "GetStringUTFChars",
    "ReleaseStringUTFChars",
    "GetArrayLength",
    "NewObjectArray",
    "GetObjectArrayElement",
    "SetObjectArrayElement",
    "RegisterNatives",
    "UnregisterNatives",
    "MonitorEnter",
    "MonitorExit",
    "GetJavaVM",
    "ExceptionCheck",
    "GetObjectRefType",
];

const JNI_FUNCTION_INDEXES: &[i32] = &[
    5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 30, 31, 32, 33, 36, 39, 42,
    45, 48, 51, 54, 57, 60, 63, 66, 69, 81, 84, 87, 90, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 113, 116, 119,
    122, 125, 128, 131, 134, 137, 140, 143, 144, 145, 146, 147, 148, 149, 150, 151, 152, 153, 167, 169, 170, 171, 172,
    173, 174, 215, 216, 217, 218, 219, 228, 232,
];

unsafe fn set_string_array_property(ctx: *mut ffi::JSContext, object: &JSValue, name: &str, items: &[&str]) {
    let array = ffi::JS_NewArray(ctx);
    for (index, item) in items.iter().enumerate() {
        ffi::JS_SetPropertyUint32(ctx, array, index as u32, JSValue::string(ctx, item).raw());
    }
    object.set_property(ctx, name, JSValue(array));
}

unsafe fn jni_status_object(ctx: *mut ffi::JSContext) -> JSValue {
    let result = JSValue(ffi::JS_NewObject(ctx));
    result.set_property(ctx, "available", JSValue::bool(false));
    result.set_property(ctx, "platform", JSValue::string(ctx, "ios"));
    result.set_property(ctx, "backend", JSValue::string(ctx, "unsupported-ios"));
    result.set_property(ctx, "androidReferenceBackend", JSValue::string(ctx, "JNIEnv"));
    result.set_property(
        ctx,
        "androidReferencePath",
        JSValue::string(ctx, "rustFrida-master/quickjs-hook/src/jsapi/jni"),
    );
    result.set_property(ctx, "iosAlternativeRuntime", JSValue::string(ctx, "ObjC/Swift"));
    result.set_property(ctx, "compatible", JSValue::bool(false));
    result.set_property(ctx, "threadEnvAvailable", JSValue::bool(false));
    result.set_property(ctx, "recommendedPath", JSValue::string(ctx, "objc-swift-native"));
    result.set_property(ctx, "lastError", JSValue::string(ctx, JNI_UNSUPPORTED_REASON));
    result.set_property(ctx, "helperEnvAvailable", JSValue::bool(false));
    result.set_property(ctx, "functionAddressAvailable", JSValue::bool(false));
    result.set_property(ctx, "functionTableAvailable", JSValue::bool(false));
    result.set_property(ctx, "metadataTableAvailable", JSValue::bool(true));
    result.set_property(ctx, "supportedFunctionCount", JSValue::int(0));
    result.set_property(
        ctx,
        "unsupportedFunctionCount",
        JSValue::int(JNI_FUNCTION_NAMES.len() as i32),
    );
    result.set_property(ctx, "tableEntryCount", JSValue::int(JNI_FUNCTION_NAMES.len() as i32));
    set_string_array_property(
        ctx,
        &result,
        "recommendedApis",
        &[
            "ObjC.objectClassName",
            "ObjC.classInfo",
            "ObjC.methodInfo",
            "Swift.typeInfo",
            "Native.symbol",
            "Interceptor.attach",
        ],
    );
    set_string_array_property(
        ctx,
        &result,
        "unsupportedMethods",
        &[
            "_threadEnv",
            "_className",
            "_getObjectClass",
            "_getSuperclass",
            "_isSameObject",
            "_isInstanceOf",
            "_getObjectClassName",
            "_readJString",
            "addr",
            "call",
        ],
    );
    result.set_property(ctx, "functionMetadataAvailable", JSValue::bool(true));
    result.set_property(ctx, "helperStructReadersAvailable", JSValue::bool(true));
    set_string_array_property(
        ctx,
        &result,
        "supportedHelpers",
        &[
            "Jni.helper.structs.JNINativeMethod.read",
            "Jni.helper.structs.JNINativeMethod.readArray",
            "Jni.helper.structs.jvalue.read",
            "Jni.helper.structs.jvalue.readArray",
        ],
    );
    set_string_array_property(ctx, &result, "jniFunctionNames", JNI_FUNCTION_NAMES);
    result.set_property(ctx, "jniFunctionCount", JSValue::int(JNI_FUNCTION_NAMES.len() as i32));
    result
}

unsafe extern "C" fn js_jni_status(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    jni_status_object(ctx).raw()
}

unsafe extern "C" fn js_jni_last_error(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    JSValue::string(ctx, JNI_UNSUPPORTED_REASON).raw()
}

unsafe extern "C" fn js_jni_false(
    _ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    JSValue::bool(false).raw()
}

fn jni_function_index_by_name(name: &str) -> Option<i32> {
    JNI_FUNCTION_NAMES
        .iter()
        .position(|candidate| *candidate == name)
        .and_then(|index| JNI_FUNCTION_INDEXES.get(index).copied())
}

unsafe fn jni_function_entry_object(ctx: *mut ffi::JSContext, name: &str, index: i32) -> JSValue {
    let entry = JSValue(ffi::JS_NewObject(ctx));
    entry.set_property(ctx, "name", JSValue::string(ctx, name));
    entry.set_property(ctx, "index", JSValue::int(index));
    entry.set_property(ctx, "address", JSValue::null());
    entry.set_property(ctx, "available", JSValue::bool(false));
    entry.set_property(ctx, "platform", JSValue::string(ctx, "ios"));
    entry.set_property(ctx, "backend", JSValue::string(ctx, "unsupported-ios"));
    entry
}

unsafe fn jni_function_entries_array(ctx: *mut ffi::JSContext) -> JSValue {
    let array = ffi::JS_NewArray(ctx);
    for (position, name) in JNI_FUNCTION_NAMES.iter().enumerate() {
        let index = JNI_FUNCTION_INDEXES.get(position).copied().unwrap_or(position as i32);
        ffi::JS_SetPropertyUint32(
            ctx,
            array,
            position as u32,
            jni_function_entry_object(ctx, name, index).raw(),
        );
    }
    JSValue(array)
}

unsafe fn jni_function_table_object(ctx: *mut ffi::JSContext) -> JSValue {
    let table = JSValue(ffi::JS_NewObject(ctx));
    for (position, name) in JNI_FUNCTION_NAMES.iter().enumerate() {
        let index = JNI_FUNCTION_INDEXES.get(position).copied().unwrap_or(position as i32);
        table.set_property(ctx, name, jni_function_entry_object(ctx, name, index));
    }
    table
}

unsafe extern "C" fn js_jni_entries(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    jni_function_entries_array(ctx).raw()
}

unsafe extern "C" fn js_jni_find_function(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 1 {
        return js_throw_type_error(ctx, "Jni.find(name) requires 1 JNI function name argument");
    }
    let Some(name) = JSValue(*argv).to_string(ctx) else {
        return js_throw_type_error(ctx, "Jni.find(name) requires a string JNI function name");
    };
    match jni_function_index_by_name(&name) {
        Some(index) => jni_function_entry_object(ctx, &name, index).raw(),
        None => JSValue::null().raw(),
    }
}

unsafe extern "C" fn js_jni_null(
    _ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    JSValue::null().raw()
}

unsafe extern "C" fn js_jni_unsupported(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    js_throw_internal_error(ctx, JNI_UNSUPPORTED_REASON)
}

unsafe fn pointer_arg_to_u64(ctx: *mut ffi::JSContext, value: JSValue, usage: &str) -> Result<u64, ffi::JSValue> {
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

unsafe fn require_pointer_arg(
    ctx: *mut ffi::JSContext,
    argc: i32,
    argv: *mut ffi::JSValue,
    usage: &str,
) -> Result<u64, ffi::JSValue> {
    if argc < 1 {
        return Err(js_throw_type_error(ctx, usage));
    }
    pointer_arg_to_u64(ctx, JSValue(*argv), usage)
}

unsafe fn require_count_arg(
    ctx: *mut ffi::JSContext,
    argc: i32,
    argv: *mut ffi::JSValue,
    usage: &str,
) -> Result<usize, ffi::JSValue> {
    if argc < 2 {
        return Err(js_throw_type_error(ctx, usage));
    }
    let Some(count) = JSValue(*argv.add(1)).to_i64(ctx) else {
        return Err(js_throw_type_error(ctx, usage));
    };
    if count < 0 {
        return Err(js_throw_range_error(ctx, "count must be non-negative"));
    }
    Ok(count as usize)
}

unsafe fn read_u8_checked(ctx: *mut ffi::JSContext, address: u64) -> Result<u8, ffi::JSValue> {
    if !is_addr_accessible(address, 1) {
        return Err(js_throw_range_error(ctx, "invalid memory address"));
    }
    Ok(std::ptr::read_unaligned(address as *const u8))
}

unsafe fn read_u16_checked(ctx: *mut ffi::JSContext, address: u64) -> Result<u16, ffi::JSValue> {
    if !is_addr_accessible(address, 2) {
        return Err(js_throw_range_error(ctx, "invalid memory address"));
    }
    Ok(std::ptr::read_unaligned(address as *const u16))
}

unsafe fn read_u32_checked(ctx: *mut ffi::JSContext, address: u64) -> Result<u32, ffi::JSValue> {
    if !is_addr_accessible(address, 4) {
        return Err(js_throw_range_error(ctx, "invalid memory address"));
    }
    Ok(std::ptr::read_unaligned(address as *const u32))
}

unsafe fn read_u64_checked(ctx: *mut ffi::JSContext, address: u64) -> Result<u64, ffi::JSValue> {
    if !is_addr_accessible(address, 8) {
        return Err(js_throw_range_error(ctx, "invalid memory address"));
    }
    Ok(std::ptr::read_unaligned(address as *const u64))
}

unsafe fn read_cstring_optional(ctx: *mut ffi::JSContext, address: u64) -> Result<Option<String>, ffi::JSValue> {
    if address == 0 {
        return Ok(None);
    }
    if !is_addr_accessible(address, 1) {
        return Ok(None);
    }

    const MAX_CSTRING_LEN: usize = 4096;
    const PAGE_SIZE: u64 = 4096;
    let mut len = 0usize;
    let mut next_page_check = (address + PAGE_SIZE) & !(PAGE_SIZE - 1);
    while len < MAX_CSTRING_LEN {
        let byte_addr = address + len as u64;
        if byte_addr >= next_page_check {
            if !is_addr_accessible(byte_addr, 1) {
                break;
            }
            next_page_check = (byte_addr + PAGE_SIZE) & !(PAGE_SIZE - 1);
        }
        if *(byte_addr as *const u8) == 0 {
            let slice = std::slice::from_raw_parts(address as *const u8, len);
            return Ok(Some(String::from_utf8_lossy(slice).into_owned()));
        }
        len += 1;
    }

    Err(js_throw_range_error(
        ctx,
        "CString exceeds 4096-byte limit or crosses unreadable memory",
    ))
}

unsafe fn read_jni_native_method_object(ctx: *mut ffi::JSContext, address: u64) -> Result<JSValue, ffi::JSValue> {
    let name_ptr = read_u64_checked(ctx, address)?;
    let sig_ptr = read_u64_checked(ctx, address + 8)?;
    let fn_ptr = read_u64_checked(ctx, address + 16)?;

    let result = JSValue(ffi::JS_NewObject(ctx));
    result.set_property(ctx, "address", create_native_pointer(ctx, address));
    result.set_property(ctx, "namePtr", create_native_pointer(ctx, name_ptr));
    result.set_property(ctx, "sigPtr", create_native_pointer(ctx, sig_ptr));
    result.set_property(ctx, "fnPtr", create_native_pointer(ctx, fn_ptr));
    match read_cstring_optional(ctx, name_ptr)? {
        Some(value) => result.set_property(ctx, "name", JSValue::string(ctx, &value)),
        None => result.set_property(ctx, "name", JSValue::null()),
    };
    match read_cstring_optional(ctx, sig_ptr)? {
        Some(value) => result.set_property(ctx, "sig", JSValue::string(ctx, &value)),
        None => result.set_property(ctx, "sig", JSValue::null()),
    };
    Ok(result)
}

unsafe extern "C" fn js_jni_native_method_read(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let address = match require_pointer_arg(
        ctx,
        argc,
        argv,
        "Jni.helper.structs.JNINativeMethod.read(address) requires 1 address argument",
    ) {
        Ok(value) => value,
        Err(err) => return err,
    };
    match read_jni_native_method_object(ctx, address) {
        Ok(value) => value.raw(),
        Err(err) => err,
    }
}

unsafe extern "C" fn js_jni_native_method_read_array(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let address = match require_pointer_arg(
        ctx,
        argc,
        argv,
        "Jni.helper.structs.JNINativeMethod.readArray(address, count) requires address and count",
    ) {
        Ok(value) => value,
        Err(err) => return err,
    };
    let count = match require_count_arg(
        ctx,
        argc,
        argv,
        "Jni.helper.structs.JNINativeMethod.readArray(address, count) requires address and count",
    ) {
        Ok(value) => value,
        Err(err) => return err,
    };

    let array = ffi::JS_NewArray(ctx);
    for index in 0..count {
        let item = match read_jni_native_method_object(ctx, address + (index as u64 * 24)) {
            Ok(value) => value.raw(),
            Err(err) => return err,
        };
        ffi::JS_SetPropertyUint32(ctx, array, index as u32, item);
    }
    array
}

fn parse_jni_type_sequence(
    signature: &str,
    start: usize,
    end_char: Option<char>,
) -> Result<(Vec<String>, usize), String> {
    let chars: Vec<char> = signature.chars().collect();
    let mut output = Vec::new();
    let mut index = start;

    while index < chars.len() && end_char.map(|end| chars[index] != end).unwrap_or(true) {
        let begin = index;
        while index < chars.len() && chars[index] == '[' {
            index += 1;
        }
        if index >= chars.len() {
            return Err(format!("Invalid JNI signature: {signature}"));
        }
        if chars[index] == 'L' {
            index += 1;
            while index < chars.len() && chars[index] != ';' {
                index += 1;
            }
            if index >= chars.len() {
                return Err(format!("Invalid JNI signature: {signature}"));
            }
            index += 1;
        } else {
            index += 1;
        }
        output.push(chars[begin..index].iter().collect());
    }

    Ok((output, index))
}

fn normalize_jni_type_list_from_string(signature: &str) -> Result<Vec<String>, String> {
    if !signature.starts_with('(') {
        return Ok(vec![signature.to_string()]);
    }

    let (params, index) = parse_jni_type_sequence(signature, 1, Some(')'))?;
    if signature.chars().nth(index) != Some(')') {
        return Err(format!("Invalid JNI signature: {signature}"));
    }
    Ok(params)
}

unsafe fn normalize_jni_type_list(ctx: *mut ffi::JSContext, value: JSValue) -> Result<Vec<String>, ffi::JSValue> {
    if value.is_string() {
        let Some(signature) = value.to_string(ctx) else {
            return Err(js_throw_type_error(ctx, "Expected JNI signature string or type array"));
        };
        return normalize_jni_type_list_from_string(&signature).map_err(|err| js_throw_type_error(ctx, &err));
    }

    if !value.is_object() {
        return Err(js_throw_type_error(ctx, "Expected JNI signature string or type array"));
    }

    let length_value = value.get_property(ctx, "length");
    let length = length_value.to_i64(ctx).unwrap_or(0);
    length_value.free(ctx);
    if length < 0 {
        return Err(js_throw_range_error(ctx, "type array length must be non-negative"));
    }

    let mut types = Vec::with_capacity(length as usize);
    for index in 0..length {
        let item = value.get_property(ctx, &index.to_string());
        let Some(jni_type) = item.to_string(ctx) else {
            item.free(ctx);
            return Err(js_throw_type_error(ctx, "JNI type array entries must be strings"));
        };
        item.free(ctx);
        types.push(jni_type);
    }
    Ok(types)
}

unsafe fn read_jvalue(ctx: *mut ffi::JSContext, address: u64, jni_type: &str) -> Result<ffi::JSValue, ffi::JSValue> {
    let tag = jni_type.chars().next().unwrap_or('L');
    match tag {
        'Z' => Ok(JSValue::bool(read_u8_checked(ctx, address)? != 0).raw()),
        'B' => Ok(JSValue::int(read_u8_checked(ctx, address)? as i8 as i32).raw()),
        'C' => Ok(JSValue::int(read_u16_checked(ctx, address)? as i32).raw()),
        'S' => Ok(JSValue::int(read_u16_checked(ctx, address)? as i16 as i32).raw()),
        'I' => Ok(JSValue::int(read_u32_checked(ctx, address)? as i32).raw()),
        'J' => Ok(ffi::JS_NewBigInt64(ctx, read_u64_checked(ctx, address)? as i64)),
        'F' => Ok(JSValue::float(f32::from_bits(read_u32_checked(ctx, address)?) as f64).raw()),
        'D' => Ok(JSValue::float(f64::from_bits(read_u64_checked(ctx, address)?)).raw()),
        _ => Ok(create_native_pointer(ctx, read_u64_checked(ctx, address)?).raw()),
    }
}

unsafe extern "C" fn js_jvalue_read(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let address = match require_pointer_arg(
        ctx,
        argc,
        argv,
        "Jni.helper.structs.jvalue.read(address, jniType) requires address and type",
    ) {
        Ok(value) => value,
        Err(err) => return err,
    };
    let jni_type = if argc >= 2 {
        match JSValue(*argv.add(1)).to_string(ctx) {
            Some(value) => value,
            None => {
                return js_throw_type_error(
                    ctx,
                    "Jni.helper.structs.jvalue.read(address, jniType) requires jniType string",
                )
            }
        }
    } else {
        "Ljava/lang/Object;".to_string()
    };
    match read_jvalue(ctx, address, &jni_type) {
        Ok(value) => value,
        Err(err) => err,
    }
}

unsafe extern "C" fn js_jvalue_read_array(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let address = match require_pointer_arg(
        ctx,
        argc,
        argv,
        "Jni.helper.structs.jvalue.readArray(address, typesOrSig) requires address and JNI signature or type array",
    ) {
        Ok(value) => value,
        Err(err) => return err,
    };
    if argc < 2 {
        return js_throw_type_error(
            ctx,
            "Jni.helper.structs.jvalue.readArray(address, typesOrSig) requires address and JNI signature or type array",
        );
    }
    let types = match normalize_jni_type_list(ctx, JSValue(*argv.add(1))) {
        Ok(value) => value,
        Err(err) => return err,
    };

    let array = ffi::JS_NewArray(ctx);
    for (index, jni_type) in types.iter().enumerate() {
        let item = match read_jvalue(ctx, address + (index as u64 * 8), jni_type) {
            Ok(value) => value,
            Err(err) => return err,
        };
        ffi::JS_SetPropertyUint32(ctx, array, index as u32, item);
    }
    array
}

unsafe fn jni_helper_object(ctx: *mut ffi::JSContext) -> JSValue {
    let helper = JSValue(ffi::JS_NewObject(ctx));
    helper.set_property(ctx, "pointerSize", JSValue::int(8));

    let sizeof = JSValue(ffi::JS_NewObject(ctx));
    sizeof.set_property(ctx, "pointer", JSValue::int(8));
    sizeof.set_property(ctx, "jvalue", JSValue::int(8));
    sizeof.set_property(ctx, "JNINativeMethod", JSValue::int(24));
    helper.set_property(ctx, "sizeof", sizeof);

    let env = JSValue(ffi::JS_NewObject(ctx));
    env.set_property(ctx, "ptr", JSValue::null());
    for name in [
        "getObjectClass",
        "getSuperclass",
        "isSameObject",
        "isInstanceOf",
        "exceptionCheck",
        "exceptionOccurred",
        "exceptionClear",
        "readJString",
        "getClassName",
        "getObjectClassName",
    ] {
        add_cfunction_to_object(ctx, env.raw(), name, js_jni_unsupported, 0);
    }
    helper.set_property(ctx, "env", env);

    let structs = JSValue(ffi::JS_NewObject(ctx));
    for struct_name in ["JNINativeMethod", "jvalue"] {
        let structure = JSValue(ffi::JS_NewObject(ctx));
        structure.set_property(
            ctx,
            "size",
            JSValue::int(if struct_name == "JNINativeMethod" { 24 } else { 8 }),
        );
        if struct_name == "JNINativeMethod" {
            add_cfunction_to_object(ctx, structure.raw(), "read", js_jni_native_method_read, 1);
            add_cfunction_to_object(ctx, structure.raw(), "readArray", js_jni_native_method_read_array, 2);
        } else {
            add_cfunction_to_object(ctx, structure.raw(), "read", js_jvalue_read, 2);
            add_cfunction_to_object(ctx, structure.raw(), "readArray", js_jvalue_read_array, 2);
        }
        structs.set_property(ctx, struct_name, structure);
    }
    helper.set_property(ctx, "structs", structs);
    helper
}

pub(crate) fn register_jni_api(ctx: &JSContext) {
    let global = ctx.global_object();
    let jni = ctx.new_object();

    unsafe {
        let ctx_ptr = ctx.as_ptr();
        jni.set_property(ctx_ptr, "available", JSValue::bool(false));
        jni.set_property(ctx_ptr, "platform", JSValue::string(ctx_ptr, "ios"));
        jni.set_property(ctx_ptr, "backend", JSValue::string(ctx_ptr, "unsupported-ios"));
        jni.set_property(ctx_ptr, "androidReferenceBackend", JSValue::string(ctx_ptr, "JNIEnv"));
        jni.set_property(ctx_ptr, "iosAlternativeRuntime", JSValue::string(ctx_ptr, "ObjC/Swift"));
        jni.set_property(ctx_ptr, "compatible", JSValue::bool(false));
        jni.set_property(
            ctx_ptr,
            "lastErrorText",
            JSValue::string(ctx_ptr, JNI_UNSUPPORTED_REASON),
        );

        add_cfunction_to_object(ctx_ptr, jni.raw(), "status", js_jni_status, 0);
        add_cfunction_to_object(ctx_ptr, jni.raw(), "info", js_jni_status, 0);
        add_cfunction_to_object(ctx_ptr, jni.raw(), "lastError", js_jni_last_error, 0);
        add_cfunction_to_object(ctx_ptr, jni.raw(), "isAvailable", js_jni_false, 0);
        add_cfunction_to_object(ctx_ptr, jni.raw(), "_threadEnv", js_jni_null, 0);
        add_cfunction_to_object(ctx_ptr, jni.raw(), "entries", js_jni_entries, 0);
        add_cfunction_to_object(ctx_ptr, jni.raw(), "functions", js_jni_entries, 0);
        add_cfunction_to_object(ctx_ptr, jni.raw(), "find", js_jni_find_function, 1);
        add_cfunction_to_object(ctx_ptr, jni.raw(), "function", js_jni_find_function, 1);
        jni.set_property(ctx_ptr, "table", jni_function_table_object(ctx_ptr));
        jni.set_property(ctx_ptr, "helper", jni_helper_object(ctx_ptr));
        set_string_array_property(ctx_ptr, &jni, "jniFunctionNames", JNI_FUNCTION_NAMES);

        for name in [
            "_className",
            "_getObjectClass",
            "_getSuperclass",
            "_isSameObject",
            "_isInstanceOf",
            "_getObjectClassName",
            "_readJString",
            "addr",
            "call",
        ] {
            add_cfunction_to_object(ctx_ptr, jni.raw(), name, js_jni_unsupported, 0);
        }
        for name in JNI_FUNCTION_NAMES {
            add_cfunction_to_object(ctx_ptr, jni.raw(), name, js_jni_unsupported, 0);
        }
    }

    global.set_property(ctx.as_ptr(), "Jni", jni);
    global.free(ctx.as_ptr());
}
