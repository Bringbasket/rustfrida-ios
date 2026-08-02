//! QuickJS wrappers for the bounded `objc-api` object bridge.
//!
//! The wrapper owns one retained Objective-C reference. `dispose()` and the
//! QuickJS finalizer share an `Option`, so the reference is released exactly
//! once. Apple message dispatch is contained by the Objective-C shim in
//! `objc-api`; invalid native pointers and ABI mismatches remain caller-owned.

use crate::context::JSContext;
use crate::ffi;
use crate::ptr::{create_native_pointer, get_native_pointer_addr};
use crate::util::{
    add_cfunction_to_object, js_i64_to_js_number_or_bigint, js_throw_internal_error, js_throw_range_error,
    js_throw_type_error, js_u64_to_js_number_or_bigint,
};
use crate::value::JSValue;
use objc_api::{
    BridgeError, IvarAccess, ObjcClass, ObjcObject, ObjcSelector, ObjectBridge, PendingObjcClass, PropertyKvo,
    PropertyOwnership, ScalarKind, ScalarValue, SynthesizedPropertyOptions, MAX_MESSAGE_ARGUMENTS,
    MAX_SYNTHESIZED_PROPERTY_NAME_LENGTH,
};
use std::sync::atomic::{AtomicU32, Ordering};

static OBJC_RECEIVER_CLASS_ID: AtomicU32 = AtomicU32::new(0);
const OBJC_RECEIVER_CLASS_NAME: &[u8] = b"IOSRustFridaObjCReceiver\0";
const JS_MAX_SAFE_INTEGER: f64 = ((1u64 << 53) - 1) as f64;
const MAX_DYNAMIC_IVARS: usize = 128;
const MAX_DYNAMIC_METHODS: usize = 256;
const MAX_DYNAMIC_PROPERTIES: usize = 128;

const SCALAR_TYPE_NAMES: &[&str] = &[
    "void", "bool", "i8", "u8", "i16", "u16", "i32", "u32", "i64", "u64", "isize", "usize", "pointer",
];
const PROPERTY_OWNERSHIP_NAMES: &[&str] = &["assign", "retain", "copy", "weak"];
const PROPERTY_ATOMICITY_NAMES: &[&str] = &["nonatomic", "atomic"];
const PROPERTY_KVO_MODES: &[&str] = &["automatic", "manual"];

const RECEIVER_METHOD_NAMES: &[&str] = &[
    "send",
    "sendUnchecked",
    "getProperty",
    "setProperty",
    "readIvar",
    "writeIvar",
    "writeIvarRaw",
    "ivarAddress",
    "toPointer",
    "kind",
    "dispose",
    "toString",
    "toJSON",
];

#[derive(Debug)]
struct DynamicIvarSpec {
    name: String,
    size: usize,
    alignment: usize,
    type_encoding: String,
}

#[derive(Debug)]
struct DynamicMethodSpec {
    selector: String,
    implementation: usize,
    type_encoding: String,
    class_method: bool,
}

#[derive(Debug)]
struct DynamicPropertySpec {
    name: String,
    type_encoding: String,
    read_only: bool,
    ownership: PropertyOwnership,
    atomic: bool,
    kvo: PropertyKvo,
    getter: Option<String>,
    setter: Option<String>,
}

#[derive(Debug)]
struct DynamicClassSpec {
    name: String,
    superclass: String,
    ivars: Vec<DynamicIvarSpec>,
    methods: Vec<DynamicMethodSpec>,
    properties: Vec<DynamicPropertySpec>,
}

enum OwnedReceiver {
    Object(ObjcObject),
    Class(ObjcClass),
}

impl OwnedReceiver {
    fn raw(&self) -> usize {
        match self {
            Self::Object(object) => object.as_raw(),
            Self::Class(class) => class.as_raw(),
        }
    }

    fn kind(&self) -> &'static str {
        match self {
            Self::Object(_) => "object",
            Self::Class(_) => "class",
        }
    }
}

struct ReceiverState {
    receiver: Option<OwnedReceiver>,
}

unsafe extern "C" fn receiver_finalizer(_runtime: *mut ffi::JSRuntime, value: ffi::JSValue) {
    let class_id = OBJC_RECEIVER_CLASS_ID.load(Ordering::Acquire);
    if class_id == 0 {
        return;
    }
    let opaque = unsafe { ffi::JS_GetOpaque(value, class_id) };
    if !opaque.is_null() {
        unsafe { drop(Box::from_raw(opaque as *mut ReceiverState)) };
    }
}

fn get_or_init_receiver_class_id(ctx: *mut ffi::JSContext) -> Result<u32, String> {
    let mut class_id = OBJC_RECEIVER_CLASS_ID.load(Ordering::Acquire);
    if class_id == 0 {
        let mut candidate = 0u32;
        candidate = unsafe { ffi::JS_NewClassID(&mut candidate) };
        match OBJC_RECEIVER_CLASS_ID.compare_exchange(0, candidate, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => class_id = candidate,
            Err(existing) => class_id = existing,
        }
    }

    unsafe {
        let runtime = ffi::JS_GetRuntime(ctx);
        if ffi::JS_IsRegisteredClass(runtime, class_id) == 0 {
            let class_def = ffi::JSClassDef {
                class_name: OBJC_RECEIVER_CLASS_NAME.as_ptr() as *const _,
                finalizer: Some(receiver_finalizer),
                gc_mark: None,
                call: None,
                exotic: std::ptr::null_mut(),
            };
            if ffi::JS_NewClass(runtime, class_id, &class_def) != 0 {
                return Err("failed to register QuickJS Objective-C receiver class".into());
            }
        }
    }
    Ok(class_id)
}

unsafe fn receiver_state(ctx: *mut ffi::JSContext, value: ffi::JSValue) -> Result<*mut ReceiverState, ffi::JSValue> {
    let class_id = OBJC_RECEIVER_CLASS_ID.load(Ordering::Acquire);
    if class_id == 0 {
        return Err(js_throw_type_error(ctx, "value is not an ObjC object wrapper"));
    }
    let opaque = unsafe { ffi::JS_GetOpaque(value, class_id) };
    if opaque.is_null() {
        return Err(js_throw_type_error(ctx, "value is not an ObjC object wrapper"));
    }
    let state = opaque as *mut ReceiverState;
    if unsafe { (&*state).receiver.is_none() } {
        return Err(js_throw_type_error(ctx, "ObjC object wrapper has been disposed"));
    }
    Ok(state)
}

fn receiver_raw(value: JSValue) -> Option<usize> {
    let class_id = OBJC_RECEIVER_CLASS_ID.load(Ordering::Acquire);
    if class_id == 0 {
        return None;
    }
    let opaque = unsafe { ffi::JS_GetOpaque(value.raw(), class_id) };
    if opaque.is_null() {
        return None;
    }
    let state = unsafe { &*(opaque as *const ReceiverState) };
    state.receiver.as_ref().map(OwnedReceiver::raw)
}

unsafe fn create_receiver_wrapper(ctx: *mut ffi::JSContext, receiver: OwnedReceiver) -> ffi::JSValue {
    let class_id = match get_or_init_receiver_class_id(ctx) {
        Ok(class_id) => class_id,
        Err(error) => return js_throw_internal_error(ctx, &error),
    };
    let object = unsafe { ffi::JS_NewObjectClass(ctx, class_id as i32) };
    if unsafe { ffi::qjs_is_exception(object) } != 0 {
        return object;
    }

    let state = Box::into_raw(Box::new(ReceiverState {
        receiver: Some(receiver),
    }));
    unsafe { ffi::JS_SetOpaque(object, state.cast()) };
    object
}

/// Retains a scanned Objective-C object before exposing it to JavaScript.
/// The receiver finalizer owns the resulting `ObjcObject` reference.
pub(crate) unsafe fn create_retained_object_wrapper(
    ctx: *mut ffi::JSContext,
    raw: usize,
) -> Result<ffi::JSValue, BridgeError> {
    let object = unsafe { ObjectBridge::new().retain_object(raw)? };
    Ok(unsafe { create_receiver_wrapper(ctx, OwnedReceiver::Object(object)) })
}

fn parse_scalar_kind(name: &str) -> Result<ScalarKind, String> {
    let normalized = name.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "void" => Ok(ScalarKind::Void),
        "bool" | "boolean" => Ok(ScalarKind::Bool),
        "i8" | "int8" | "int8_t" | "char" | "schar" => Ok(ScalarKind::I8),
        "u8" | "uint8" | "uint8_t" | "uchar" => Ok(ScalarKind::U8),
        "i16" | "int16" | "int16_t" | "short" => Ok(ScalarKind::I16),
        "u16" | "uint16" | "uint16_t" | "ushort" => Ok(ScalarKind::U16),
        "i32" | "int32" | "int32_t" | "int" => Ok(ScalarKind::I32),
        "u32" | "uint32" | "uint32_t" | "uint" => Ok(ScalarKind::U32),
        "i64" | "int64" | "int64_t" | "long" | "longlong" => Ok(ScalarKind::I64),
        "u64" | "uint64" | "uint64_t" | "ulong" | "ulonglong" => Ok(ScalarKind::U64),
        "isize" | "ssize_t" | "nsinteger" => Ok(ScalarKind::Isize),
        "usize" | "size_t" | "nsuinteger" => Ok(ScalarKind::Usize),
        "pointer" | "ptr" | "id" | "class" | "sel" => Ok(ScalarKind::Pointer),
        "float" | "double" => Err(format!(
            "Objective-C object dispatch does not support {normalized}; use scalar integer/pointer types"
        )),
        name if name.starts_with('{') || name.starts_with('[') || name.starts_with('(') => {
            Err("Objective-C object dispatch does not support aggregate values".into())
        }
        "..." => Err("Objective-C object dispatch does not support variadic arguments".into()),
        _ => Err(format!("unknown Objective-C scalar type: {name}")),
    }
}

unsafe fn required_string(
    ctx: *mut ffi::JSContext,
    argc: i32,
    argv: *mut ffi::JSValue,
    index: usize,
    usage: &str,
) -> Result<String, ffi::JSValue> {
    if argc <= index as i32 {
        return Err(js_throw_type_error(ctx, usage));
    }
    let value = JSValue(unsafe { *argv.add(index) });
    if !value.is_string() {
        return Err(js_throw_type_error(ctx, usage));
    }
    value.to_string(ctx).ok_or_else(|| js_throw_type_error(ctx, usage))
}

fn parse_integer(ctx: *mut ffi::JSContext, value: JSValue, label: &str) -> Result<i128, String> {
    if unsafe { ffi::qjs_is_big_int(ctx, value.raw()) } != 0 {
        let text = value
            .to_string(ctx)
            .ok_or_else(|| format!("{label} BigInt conversion failed"))?;
        return text
            .parse::<i128>()
            .map_err(|_| format!("{label} BigInt is outside the supported 64-bit range"));
    }
    if !value.is_int() && !value.is_float() {
        return Err(format!("{label} must be an integer Number or BigInt"));
    }
    let number = value
        .to_float()
        .ok_or_else(|| format!("{label} number conversion failed"))?;
    if !number.is_finite() || number.fract() != 0.0 {
        return Err(format!("{label} must be a finite integer"));
    }
    if number.abs() > JS_MAX_SAFE_INTEGER {
        return Err(format!(
            "{label} Number exceeds the safe integer range; use BigInt or NativePointer"
        ));
    }
    Ok(number as i128)
}

fn integer_in_range(
    ctx: *mut ffi::JSContext,
    value: JSValue,
    label: &str,
    min: i128,
    max: i128,
) -> Result<i128, String> {
    let value = parse_integer(ctx, value, label)?;
    if value < min || value > max {
        return Err(format!("{label} is outside {min}..={max}"));
    }
    Ok(value)
}

fn pointer_value(ctx: *mut ffi::JSContext, value: JSValue, label: &str) -> Result<usize, String> {
    if let Some(raw) = receiver_raw(value) {
        return Ok(raw);
    }
    if let Some(raw) = get_native_pointer_addr(value) {
        return usize::try_from(raw).map_err(|_| format!("{label} does not fit the target pointer width"));
    }
    let raw = integer_in_range(ctx, value, label, 0, u64::MAX as i128)
        .map_err(|error| format!("{label} expected a pointer-like value: {error}"))? as u64;
    usize::try_from(raw).map_err(|_| format!("{label} does not fit the target pointer width"))
}

unsafe fn object_string_property(
    ctx: *mut ffi::JSContext,
    object: JSValue,
    name: &str,
    label: &str,
) -> Result<String, ffi::JSValue> {
    let value = object.get_property(ctx, name);
    if value.is_exception() {
        return Err(value.raw());
    }
    if !value.is_string() {
        value.free(ctx);
        return Err(js_throw_type_error(ctx, &format!("{label} must be a string")));
    }
    let result = value
        .to_string(ctx)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| js_throw_type_error(ctx, &format!("{label} must be a non-empty string")));
    value.free(ctx);
    result
}

unsafe fn object_usize_property(
    ctx: *mut ffi::JSContext,
    object: JSValue,
    name: &str,
    label: &str,
) -> Result<usize, ffi::JSValue> {
    let value = object.get_property(ctx, name);
    if value.is_exception() {
        return Err(value.raw());
    }
    let result = integer_in_range(ctx, value, label, 0, usize::MAX as i128)
        .and_then(|value| usize::try_from(value).map_err(|_| format!("{label} does not fit usize")))
        .map_err(|error| js_throw_type_error(ctx, &error));
    value.free(ctx);
    result
}

unsafe fn object_pointer_property(
    ctx: *mut ffi::JSContext,
    object: JSValue,
    name: &str,
    label: &str,
) -> Result<usize, ffi::JSValue> {
    let value = object.get_property(ctx, name);
    if value.is_exception() {
        return Err(value.raw());
    }
    let result = pointer_value(ctx, value, label).map_err(|error| js_throw_type_error(ctx, &error));
    value.free(ctx);
    result
}

unsafe fn object_optional_bool_property(
    ctx: *mut ffi::JSContext,
    object: JSValue,
    name: &str,
    label: &str,
) -> Result<bool, ffi::JSValue> {
    let value = object.get_property(ctx, name);
    if value.is_exception() {
        return Err(value.raw());
    }
    let result = if value.is_null() || value.is_undefined() {
        Ok(false)
    } else {
        value
            .to_bool()
            .ok_or_else(|| js_throw_type_error(ctx, &format!("{label} must be a boolean")))
    };
    value.free(ctx);
    result
}

unsafe fn object_optional_string_property(
    ctx: *mut ffi::JSContext,
    object: JSValue,
    name: &str,
    label: &str,
) -> Result<Option<String>, ffi::JSValue> {
    let value = object.get_property(ctx, name);
    if value.is_exception() {
        return Err(value.raw());
    }
    let result = if value.is_null() || value.is_undefined() {
        Ok(None)
    } else if !value.is_string() {
        Err(js_throw_type_error(ctx, &format!("{label} must be a string")))
    } else {
        value
            .to_string(ctx)
            .filter(|value| !value.trim().is_empty())
            .map(Some)
            .ok_or_else(|| js_throw_type_error(ctx, &format!("{label} must be a non-empty string")))
    };
    value.free(ctx);
    result
}

unsafe fn array_property(
    ctx: *mut ffi::JSContext,
    object: JSValue,
    name: &str,
    label: &str,
    maximum: usize,
) -> Result<Option<(JSValue, usize)>, ffi::JSValue> {
    let value = object.get_property(ctx, name);
    if value.is_exception() {
        return Err(value.raw());
    }
    if value.is_null() || value.is_undefined() {
        value.free(ctx);
        return Ok(None);
    }
    if ffi::JS_IsArray(ctx, value.raw()) != 1 {
        value.free(ctx);
        return Err(js_throw_type_error(ctx, &format!("{label} must be an array")));
    }
    let length_value = value.get_property(ctx, "length");
    let length = length_value.to_u64(ctx).unwrap_or(u64::MAX);
    length_value.free(ctx);
    let length = usize::try_from(length).unwrap_or(usize::MAX);
    if length > maximum {
        value.free(ctx);
        return Err(js_throw_range_error(
            ctx,
            &format!("{label} accepts at most {maximum} entries"),
        ));
    }
    Ok(Some((value, length)))
}

unsafe fn parse_dynamic_class_spec(ctx: *mut ffi::JSContext, value: JSValue) -> Result<DynamicClassSpec, ffi::JSValue> {
    if !value.is_object() || ffi::JS_IsArray(ctx, value.raw()) == 1 {
        return Err(js_throw_type_error(ctx, "ObjC.registerClass(spec) requires an object"));
    }
    let name = object_string_property(ctx, value, "name", "ObjC.registerClass spec.name")?;
    let superclass = object_string_property(ctx, value, "superclass", "ObjC.registerClass spec.superclass")?;

    let mut ivars = Vec::new();
    if let Some((array, length)) =
        array_property(ctx, value, "ivars", "ObjC.registerClass spec.ivars", MAX_DYNAMIC_IVARS)?
    {
        for index in 0..length {
            let item = JSValue(ffi::JS_GetPropertyUint32(ctx, array.raw(), index as u32));
            if item.is_exception() {
                array.free(ctx);
                return Err(item.raw());
            }
            let parsed = (|| {
                if !item.is_object() || ffi::JS_IsArray(ctx, item.raw()) == 1 {
                    return Err(js_throw_type_error(
                        ctx,
                        &format!("ObjC.registerClass spec.ivars[{index}] must be an object"),
                    ));
                }
                Ok(DynamicIvarSpec {
                    name: object_string_property(
                        ctx,
                        item,
                        "name",
                        &format!("ObjC.registerClass spec.ivars[{index}].name"),
                    )?,
                    size: object_usize_property(
                        ctx,
                        item,
                        "size",
                        &format!("ObjC.registerClass spec.ivars[{index}].size"),
                    )?,
                    alignment: object_usize_property(
                        ctx,
                        item,
                        "alignment",
                        &format!("ObjC.registerClass spec.ivars[{index}].alignment"),
                    )?,
                    type_encoding: object_string_property(
                        ctx,
                        item,
                        "typeEncoding",
                        &format!("ObjC.registerClass spec.ivars[{index}].typeEncoding"),
                    )?,
                })
            })();
            item.free(ctx);
            match parsed {
                Ok(parsed) => ivars.push(parsed),
                Err(error) => {
                    array.free(ctx);
                    return Err(error);
                }
            }
        }
        array.free(ctx);
    }

    let mut methods = Vec::new();
    if let Some((array, length)) = array_property(
        ctx,
        value,
        "methods",
        "ObjC.registerClass spec.methods",
        MAX_DYNAMIC_METHODS,
    )? {
        for index in 0..length {
            let item = JSValue(ffi::JS_GetPropertyUint32(ctx, array.raw(), index as u32));
            if item.is_exception() {
                array.free(ctx);
                return Err(item.raw());
            }
            let parsed = (|| {
                if !item.is_object() || ffi::JS_IsArray(ctx, item.raw()) == 1 {
                    return Err(js_throw_type_error(
                        ctx,
                        &format!("ObjC.registerClass spec.methods[{index}] must be an object"),
                    ));
                }
                Ok(DynamicMethodSpec {
                    selector: object_string_property(
                        ctx,
                        item,
                        "selector",
                        &format!("ObjC.registerClass spec.methods[{index}].selector"),
                    )?,
                    implementation: object_pointer_property(
                        ctx,
                        item,
                        "implementation",
                        &format!("ObjC.registerClass spec.methods[{index}].implementation"),
                    )?,
                    type_encoding: object_string_property(
                        ctx,
                        item,
                        "typeEncoding",
                        &format!("ObjC.registerClass spec.methods[{index}].typeEncoding"),
                    )?,
                    class_method: object_optional_bool_property(
                        ctx,
                        item,
                        "classMethod",
                        &format!("ObjC.registerClass spec.methods[{index}].classMethod"),
                    )?,
                })
            })();
            item.free(ctx);
            match parsed {
                Ok(parsed) => methods.push(parsed),
                Err(error) => {
                    array.free(ctx);
                    return Err(error);
                }
            }
        }
        array.free(ctx);
    }

    let mut properties = Vec::new();
    if let Some((array, length)) = array_property(
        ctx,
        value,
        "properties",
        "ObjC.registerClass spec.properties",
        MAX_DYNAMIC_PROPERTIES,
    )? {
        for index in 0..length {
            let item = JSValue(ffi::JS_GetPropertyUint32(ctx, array.raw(), index as u32));
            if item.is_exception() {
                array.free(ctx);
                return Err(item.raw());
            }
            let parsed = (|| {
                if !item.is_object() || ffi::JS_IsArray(ctx, item.raw()) == 1 {
                    return Err(js_throw_type_error(
                        ctx,
                        &format!("ObjC.registerClass spec.properties[{index}] must be an object"),
                    ));
                }
                let name = validated_property_name(
                    ctx,
                    item,
                    "name",
                    &format!("ObjC.registerClass spec.properties[{index}].name"),
                )?;
                let type_encoding = object_string_property(
                    ctx,
                    item,
                    "typeEncoding",
                    &format!("ObjC.registerClass spec.properties[{index}].typeEncoding"),
                )?;
                let read_only = object_optional_bool_property(
                    ctx,
                    item,
                    "readOnly",
                    &format!("ObjC.registerClass spec.properties[{index}].readOnly"),
                )?;
                let ownership = match object_optional_string_property(
                        ctx,
                        item,
                        "ownership",
                        &format!("ObjC.registerClass spec.properties[{index}].ownership"),
                    )?
                    .as_deref()
                    .unwrap_or("assign")
                    .trim()
                    .to_ascii_lowercase()
                    .as_str()
                    {
                        "assign" => PropertyOwnership::Assign,
                        "retain" | "strong" => PropertyOwnership::Retain,
                        "copy" => PropertyOwnership::Copy,
                        "weak" => PropertyOwnership::Weak,
                        other => {
                            return Err(js_throw_type_error(
                                ctx,
                                &format!(
                                    "ObjC.registerClass spec.properties[{index}].ownership must be assign, retain, strong, copy, or weak; got {other:?}"
                                ),
                            ))
                        }
                    };
                let atomic = object_optional_bool_property(
                    ctx,
                    item,
                    "atomic",
                    &format!("ObjC.registerClass spec.properties[{index}].atomic"),
                )?;
                let kvo = match object_optional_string_property(
                    ctx,
                    item,
                    "kvo",
                    &format!("ObjC.registerClass spec.properties[{index}].kvo"),
                )?
                .as_deref()
                .unwrap_or("automatic")
                {
                    "automatic" => PropertyKvo::Automatic,
                    "manual" => PropertyKvo::Manual,
                    other => {
                        return Err(js_throw_type_error(
                            ctx,
                            &format!(
                                "ObjC.registerClass spec.properties[{index}].kvo must be automatic or manual; got {other:?}"
                            ),
                        ))
                    }
                };
                let getter = validated_property_getter(
                    ctx,
                    item,
                    "getter",
                    &format!("ObjC.registerClass spec.properties[{index}].getter"),
                )?;
                let setter = validated_property_setter(
                    ctx,
                    item,
                    "setter",
                    &format!("ObjC.registerClass spec.properties[{index}].setter"),
                )?;
                if read_only && setter.is_some() {
                    return Err(js_throw_type_error(
                        ctx,
                        &format!(
                            "ObjC.registerClass spec.properties[{index}] readOnly=true conflicts with an explicit setter"
                        ),
                    ));
                }
                if read_only && matches!(kvo, PropertyKvo::Manual) {
                    return Err(js_throw_type_error(
                        ctx,
                        &format!(
                            "ObjC.registerClass spec.properties[{index}] readOnly=true conflicts with kvo='manual'"
                        ),
                    ));
                }
                Ok(DynamicPropertySpec {
                    name,
                    type_encoding,
                    read_only,
                    ownership,
                    atomic,
                    kvo,
                    getter,
                    setter,
                })
            })();
            item.free(ctx);
            match parsed {
                Ok(parsed) => properties.push(parsed),
                Err(error) => {
                    array.free(ctx);
                    return Err(error);
                }
            }
        }
        array.free(ctx);
    }

    Ok(DynamicClassSpec {
        name,
        superclass,
        ivars,
        methods,
        properties,
    })
}

unsafe fn validated_property_name(
    ctx: *mut ffi::JSContext,
    object: JSValue,
    property: &str,
    label: &str,
) -> Result<String, ffi::JSValue> {
    let name = object_string_property(ctx, object, property, label)?;
    let mut characters = name.chars();
    let valid_first = characters
        .next()
        .map(|character| character == '_' || character.is_ascii_alphabetic())
        .unwrap_or(false);
    let valid_rest = characters.all(|character| character == '_' || character.is_ascii_alphanumeric());
    if !valid_first || !valid_rest {
        return Err(js_throw_type_error(
            ctx,
            &format!("invalid property name `{name}`: expected an ASCII identifier without ':' or whitespace"),
        ));
    }
    if name.len() > MAX_SYNTHESIZED_PROPERTY_NAME_LENGTH {
        return Err(js_throw_range_error(ctx, "property name exceeds 255 bytes"));
    }
    Ok(name)
}

unsafe fn validated_property_getter(
    ctx: *mut ffi::JSContext,
    object: JSValue,
    property: &str,
    label: &str,
) -> Result<Option<String>, ffi::JSValue> {
    let getter = object_optional_string_property(ctx, object, property, label)?;
    if getter.as_deref().is_some_and(|getter| getter.contains(',')) {
        return Err(js_throw_type_error(
            ctx,
            &format!("{label} selector must not contain ','"),
        ));
    }
    if getter.as_deref().is_some_and(|getter| getter.contains(':')) {
        return Err(js_throw_type_error(
            ctx,
            &format!("{label} selector must not contain ':'"),
        ));
    }
    Ok(getter)
}

unsafe fn validated_property_setter(
    ctx: *mut ffi::JSContext,
    object: JSValue,
    property: &str,
    label: &str,
) -> Result<Option<String>, ffi::JSValue> {
    let setter = object_optional_string_property(ctx, object, property, label)?;
    if setter.as_deref().is_some_and(|setter| setter.contains(',')) {
        return Err(js_throw_type_error(
            ctx,
            &format!("{label} selector must not contain ','"),
        ));
    }
    if setter
        .as_deref()
        .is_some_and(|setter| setter == ":" || !setter.ends_with(':') || setter[..setter.len() - 1].contains(':'))
    {
        return Err(js_throw_type_error(
            ctx,
            &format!("{label} selector must contain exactly one trailing ':'"),
        ));
    }
    Ok(setter)
}

fn scalar_value_from_js(
    ctx: *mut ffi::JSContext,
    value: JSValue,
    kind: ScalarKind,
    label: &str,
) -> Result<ScalarValue, String> {
    match kind {
        ScalarKind::Void => Err(format!("{label} must not use void type")),
        ScalarKind::Bool => value
            .to_bool()
            .map(ScalarValue::Bool)
            .ok_or_else(|| format!("{label} must be a boolean")),
        ScalarKind::I8 => integer_in_range(ctx, value, label, i8::MIN as i128, i8::MAX as i128)
            .map(|value| ScalarValue::I8(value as i8)),
        ScalarKind::U8 => integer_in_range(ctx, value, label, u8::MIN as i128, u8::MAX as i128)
            .map(|value| ScalarValue::U8(value as u8)),
        ScalarKind::I16 => integer_in_range(ctx, value, label, i16::MIN as i128, i16::MAX as i128)
            .map(|value| ScalarValue::I16(value as i16)),
        ScalarKind::U16 => integer_in_range(ctx, value, label, u16::MIN as i128, u16::MAX as i128)
            .map(|value| ScalarValue::U16(value as u16)),
        ScalarKind::I32 => integer_in_range(ctx, value, label, i32::MIN as i128, i32::MAX as i128)
            .map(|value| ScalarValue::I32(value as i32)),
        ScalarKind::U32 => integer_in_range(ctx, value, label, u32::MIN as i128, u32::MAX as i128)
            .map(|value| ScalarValue::U32(value as u32)),
        ScalarKind::I64 => integer_in_range(ctx, value, label, i64::MIN as i128, i64::MAX as i128)
            .map(|value| ScalarValue::I64(value as i64)),
        ScalarKind::U64 => integer_in_range(ctx, value, label, u64::MIN as i128, u64::MAX as i128)
            .map(|value| ScalarValue::U64(value as u64)),
        ScalarKind::Isize => integer_in_range(ctx, value, label, isize::MIN as i128, isize::MAX as i128)
            .map(|value| ScalarValue::Isize(value as isize)),
        ScalarKind::Usize => integer_in_range(ctx, value, label, usize::MIN as i128, usize::MAX as i128)
            .map(|value| ScalarValue::Usize(value as usize)),
        ScalarKind::Pointer => pointer_value(ctx, value, label).map(ScalarValue::Pointer),
    }
}

unsafe fn parse_argument_descriptor(
    ctx: *mut ffi::JSContext,
    value: JSValue,
    index: usize,
) -> Result<ScalarValue, ffi::JSValue> {
    if !value.is_object() {
        return Err(js_throw_type_error(
            ctx,
            &format!("ObjC.send argument {index} must be an object with type and value properties"),
        ));
    }

    let type_value = value.get_property(ctx, "type");
    if type_value.is_exception() {
        return Err(type_value.raw());
    }
    if !type_value.is_string() {
        type_value.free(ctx);
        return Err(js_throw_type_error(
            ctx,
            &format!("ObjC.send argument {index}.type must be a string"),
        ));
    }
    let type_name = type_value.to_string(ctx).unwrap_or_default();
    type_value.free(ctx);
    let kind = match parse_scalar_kind(&type_name) {
        Ok(kind) if kind != ScalarKind::Void => kind,
        Ok(_) => {
            return Err(js_throw_type_error(
                ctx,
                &format!("ObjC.send argument {index} must not use void type"),
            ))
        }
        Err(error) => {
            return Err(js_throw_type_error(
                ctx,
                &format!("ObjC.send argument {index}: {error}"),
            ))
        }
    };

    let argument_value = value.get_property(ctx, "value");
    if argument_value.is_exception() {
        return Err(argument_value.raw());
    }
    let parsed = scalar_value_from_js(ctx, argument_value, kind, &format!("ObjC.send argument {index}.value"));
    argument_value.free(ctx);
    parsed.map_err(|error| js_throw_type_error(ctx, &error))
}

unsafe fn parse_message_arguments(
    ctx: *mut ffi::JSContext,
    value: Option<JSValue>,
) -> Result<Vec<ScalarValue>, ffi::JSValue> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    if value.is_null() || value.is_undefined() {
        return Ok(Vec::new());
    }
    if unsafe { ffi::JS_IsArray(ctx, value.raw()) } != 1 {
        return Err(js_throw_type_error(
            ctx,
            "ObjC.send third argument must be an array of { type, value } descriptors",
        ));
    }

    let length_value = value.get_property(ctx, "length");
    let length = length_value.to_u64(ctx).unwrap_or(u64::MAX);
    length_value.free(ctx);
    let length = usize::try_from(length).unwrap_or(usize::MAX);
    if length > MAX_MESSAGE_ARGUMENTS {
        return Err(js_throw_range_error(
            ctx,
            &format!("ObjC.send accepts at most {MAX_MESSAGE_ARGUMENTS} explicit arguments"),
        ));
    }

    let mut arguments = Vec::with_capacity(length);
    for index in 0..length {
        let element = JSValue(unsafe { ffi::JS_GetPropertyUint32(ctx, value.raw(), index as u32) });
        if element.is_exception() {
            return Err(element.raw());
        }
        let parsed = unsafe { parse_argument_descriptor(ctx, element, index) };
        element.free(ctx);
        arguments.push(parsed?);
    }
    Ok(arguments)
}

fn scalar_to_js(ctx: *mut ffi::JSContext, value: ScalarValue) -> ffi::JSValue {
    unsafe {
        match value {
            ScalarValue::Void => JSValue::undefined().raw(),
            ScalarValue::Bool(value) => JSValue::bool(value).raw(),
            ScalarValue::I8(value) => JSValue::int(value as i32).raw(),
            ScalarValue::U8(value) => JSValue::int(value as i32).raw(),
            ScalarValue::I16(value) => JSValue::int(value as i32).raw(),
            ScalarValue::U16(value) => JSValue::int(value as i32).raw(),
            ScalarValue::I32(value) => JSValue::int(value).raw(),
            ScalarValue::U32(value) => js_u64_to_js_number_or_bigint(ctx, value as u64),
            ScalarValue::I64(value) => js_i64_to_js_number_or_bigint(ctx, value),
            ScalarValue::U64(value) => js_u64_to_js_number_or_bigint(ctx, value),
            ScalarValue::Isize(value) => js_i64_to_js_number_or_bigint(ctx, value as i64),
            ScalarValue::Usize(value) => js_u64_to_js_number_or_bigint(ctx, value as u64),
            ScalarValue::Pointer(value) => create_native_pointer(ctx, value as u64).raw(),
        }
    }
}

fn bridge_error(ctx: *mut ffi::JSContext, operation: &str, error: BridgeError) -> ffi::JSValue {
    let message = format!("{operation}: {error}");
    match error {
        BridgeError::NullPointer
        | BridgeError::MisalignedObjectPointer { .. }
        | BridgeError::InvalidName { .. }
        | BridgeError::TooManyArguments { .. }
        | BridgeError::VoidArgument { .. }
        | BridgeError::ValueOutOfRange { .. }
        | BridgeError::IvarTypeMismatch { .. }
        | BridgeError::UnsupportedPropertyOwnership { .. }
        | BridgeError::NullImplementation => js_throw_type_error(ctx, &message),
        BridgeError::InvalidMemoryRange { .. }
        | BridgeError::IvarOutOfBounds { .. }
        | BridgeError::InvalidIvarLayout { .. } => js_throw_range_error(ctx, &message),
        BridgeError::PlatformUnavailable
        | BridgeError::InvalidObjectPointer { .. }
        | BridgeError::ClassNotFound(_)
        | BridgeError::IvarNotFound(_)
        | BridgeError::ObjectiveCException(_)
        | BridgeError::ShimContractViolation { .. }
        | BridgeError::ClassAllocationFailed(_)
        | BridgeError::ClassMutationFailed { .. }
        | BridgeError::UnsupportedPropertyType { .. }
        | BridgeError::ExceptionContainmentUnavailable => js_throw_internal_error(ctx, &message),
    }
}

unsafe extern "C" fn js_objc_object(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 1 {
        return js_throw_type_error(ctx, "ObjC.object(pointer) requires one pointer-like argument");
    }
    let raw = match pointer_value(ctx, JSValue(unsafe { *argv }), "ObjC.object pointer") {
        Ok(raw) => raw,
        Err(error) => return js_throw_type_error(ctx, &error),
    };
    // The bridge validates mapping/class shape and retains before the JS
    // wrapper becomes visible. The user-supplied raw pointer remains an unsafe
    // trust boundary by design.
    match unsafe { ObjectBridge::new().retain_object(raw) } {
        Ok(object) => unsafe { create_receiver_wrapper(ctx, OwnedReceiver::Object(object)) },
        Err(error) => bridge_error(ctx, "ObjC.object", error),
    }
}

unsafe extern "C" fn js_objc_class(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let name = match unsafe { required_string(ctx, argc, argv, 0, "ObjC.class(name) requires one class-name string") } {
        Ok(name) => name,
        Err(error) => return error,
    };
    match ObjectBridge::new().require_class(&name) {
        Ok(class) => unsafe { create_receiver_wrapper(ctx, OwnedReceiver::Class(class)) },
        Err(error) => bridge_error(ctx, "ObjC.class", error),
    }
}

fn register_dynamic_class(spec: DynamicClassSpec) -> Result<ObjcClass, BridgeError> {
    let bridge = ObjectBridge::new();
    let mut pending: PendingObjcClass = bridge.allocate_subclass(&spec.superclass, &spec.name)?;
    for ivar in spec.ivars {
        pending.add_ivar(&ivar.name, ivar.size, ivar.alignment, &ivar.type_encoding)?;
    }
    for property in spec.properties {
        let mut options = SynthesizedPropertyOptions::new(property.read_only, property.ownership)
            .with_atomic(property.atomic)
            .with_kvo(property.kvo);
        if let Some(getter) = property.getter {
            options = options.with_getter(getter);
        }
        if let Some(setter) = property.setter {
            options = options.with_setter(setter);
        }
        pending.add_synthesized_property_with_options(&property.name, &property.type_encoding, options)?;
    }
    for method in spec.methods {
        let selector = bridge.register_selector(&method.selector)?;
        if method.class_method {
            unsafe { pending.add_class_method(selector, method.implementation, &method.type_encoding) }?;
        } else {
            unsafe { pending.add_method(selector, method.implementation, &method.type_encoding) }?;
        }
    }
    pending.register()
}

unsafe extern "C" fn js_objc_register_class(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 1 {
        return js_throw_type_error(ctx, "ObjC.registerClass(spec) requires an object");
    }
    let spec = match unsafe { parse_dynamic_class_spec(ctx, JSValue(*argv)) } {
        Ok(spec) => spec,
        Err(error) => return error,
    };
    match register_dynamic_class(spec) {
        Ok(class) => unsafe { create_receiver_wrapper(ctx, OwnedReceiver::Class(class)) },
        Err(error) => bridge_error(ctx, "ObjC.registerClass", error),
    }
}

unsafe extern "C" fn receiver_send(
    ctx: *mut ffi::JSContext,
    this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let state = match unsafe { receiver_state(ctx, this) } {
        Ok(state) => unsafe { &*state },
        Err(error) => return error,
    };
    let selector_name = match unsafe {
        required_string(
            ctx,
            argc,
            argv,
            0,
            "ObjC receiver.send(selector, returnType[, arguments]) requires a selector string",
        )
    } {
        Ok(name) => name,
        Err(error) => return error,
    };
    let return_type = match unsafe {
        required_string(
            ctx,
            argc,
            argv,
            1,
            "ObjC receiver.send(selector, returnType[, arguments]) requires a return-type string",
        )
    } {
        Ok(name) => name,
        Err(error) => return error,
    };
    let return_kind = match parse_scalar_kind(&return_type) {
        Ok(kind) => kind,
        Err(error) => return js_throw_type_error(ctx, &format!("ObjC.send return type: {error}")),
    };
    let argument_value = (argc >= 3).then(|| JSValue(unsafe { *argv.add(2) }));
    let arguments = match unsafe { parse_message_arguments(ctx, argument_value) } {
        Ok(arguments) => arguments,
        Err(error) => return error,
    };
    let selector = match ObjcSelector::register(&selector_name) {
        Ok(selector) => selector,
        Err(error) => return bridge_error(ctx, "ObjC.send selector", error),
    };

    let receiver = state.receiver.as_ref().expect("receiver_state checked active receiver");
    let result = match receiver {
        OwnedReceiver::Object(object) => unsafe { object.send_unchecked_exceptions(selector, &arguments, return_kind) },
        OwnedReceiver::Class(class) => unsafe { class.send_unchecked_exceptions(selector, &arguments, return_kind) },
    };
    match result {
        Ok(value) => scalar_to_js(ctx, value),
        Err(error) => bridge_error(ctx, "ObjC.send", error),
    }
}

fn property_setter_selector(property_name: &str) -> Result<String, String> {
    let property_name = property_name.trim();
    if property_name.is_empty() {
        return Err("Objective-C property name must not be empty".into());
    }
    if property_name.contains(':') || property_name.chars().any(char::is_whitespace) {
        return Err("Objective-C property name must not contain ':' or whitespace".into());
    }
    let mut characters = property_name.chars();
    let first = characters.next().expect("non-empty property name");
    let uppercase = first.to_uppercase().collect::<String>();
    Ok(format!("set{uppercase}{}:", characters.as_str()))
}

unsafe fn dispatch_property(
    ctx: *mut ffi::JSContext,
    state: &ReceiverState,
    selector_name: &str,
    arguments: &[ScalarValue],
    return_kind: ScalarKind,
    operation: &str,
) -> ffi::JSValue {
    let selector = match ObjcSelector::register(selector_name) {
        Ok(selector) => selector,
        Err(error) => return bridge_error(ctx, operation, error),
    };
    let receiver = state.receiver.as_ref().expect("receiver_state checked active receiver");
    let result = match receiver {
        OwnedReceiver::Object(object) => unsafe { object.send_unchecked_exceptions(selector, arguments, return_kind) },
        OwnedReceiver::Class(class) => unsafe { class.send_unchecked_exceptions(selector, arguments, return_kind) },
    };
    match result {
        Ok(value) => scalar_to_js(ctx, value),
        Err(error) => bridge_error(ctx, operation, error),
    }
}

unsafe extern "C" fn receiver_get_property(
    ctx: *mut ffi::JSContext,
    this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let state = match unsafe { receiver_state(ctx, this) } {
        Ok(state) => unsafe { &*state },
        Err(error) => return error,
    };
    let usage = "ObjC receiver.getProperty(name, type) requires property-name and return-type strings";
    let name = match unsafe { required_string(ctx, argc, argv, 0, usage) } {
        Ok(name) if !name.trim().is_empty() => name,
        Ok(_) => return js_throw_type_error(ctx, "Objective-C property name must not be empty"),
        Err(error) => return error,
    };
    let type_name = match unsafe { required_string(ctx, argc, argv, 1, usage) } {
        Ok(type_name) => type_name,
        Err(error) => return error,
    };
    let return_kind = match parse_scalar_kind(&type_name) {
        Ok(ScalarKind::Void) => return js_throw_type_error(ctx, "ObjC.getProperty return type must not be void"),
        Ok(kind) => kind,
        Err(error) => return js_throw_type_error(ctx, &format!("ObjC.getProperty return type: {error}")),
    };
    unsafe { dispatch_property(ctx, state, name.trim(), &[], return_kind, "ObjC.getProperty") }
}

unsafe extern "C" fn receiver_set_property(
    ctx: *mut ffi::JSContext,
    this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let state = match unsafe { receiver_state(ctx, this) } {
        Ok(state) => unsafe { &*state },
        Err(error) => return error,
    };
    let usage = "ObjC receiver.setProperty(name, type, value) requires property-name/type strings and a value";
    let name = match unsafe { required_string(ctx, argc, argv, 0, usage) } {
        Ok(name) => name,
        Err(error) => return error,
    };
    let type_name = match unsafe { required_string(ctx, argc, argv, 1, usage) } {
        Ok(type_name) => type_name,
        Err(error) => return error,
    };
    if argc < 3 {
        return js_throw_type_error(ctx, usage);
    }
    let kind = match parse_scalar_kind(&type_name) {
        Ok(ScalarKind::Void) => return js_throw_type_error(ctx, "ObjC.setProperty value type must not be void"),
        Ok(kind) => kind,
        Err(error) => return js_throw_type_error(ctx, &format!("ObjC.setProperty value type: {error}")),
    };
    let selector_name = match property_setter_selector(&name) {
        Ok(selector_name) => selector_name,
        Err(error) => return js_throw_type_error(ctx, &error),
    };
    let value = match scalar_value_from_js(ctx, JSValue(unsafe { *argv.add(2) }), kind, "ObjC.setProperty value") {
        Ok(value) => value,
        Err(error) => return js_throw_type_error(ctx, &error),
    };
    unsafe {
        dispatch_property(
            ctx,
            state,
            &selector_name,
            &[value],
            ScalarKind::Void,
            "ObjC.setProperty",
        )
    }
}

unsafe fn receiver_object<'a>(
    ctx: *mut ffi::JSContext,
    state: &'a ReceiverState,
    operation: &str,
) -> Result<&'a ObjcObject, ffi::JSValue> {
    match state.receiver.as_ref() {
        Some(OwnedReceiver::Object(object)) => Ok(object),
        Some(OwnedReceiver::Class(_)) => Err(js_throw_type_error(
            ctx,
            &format!("{operation} requires an ObjC.object wrapper, not ObjC.class"),
        )),
        None => Err(js_throw_type_error(ctx, "ObjC object wrapper has been disposed")),
    }
}

fn normalized_encoding(encoding: &str) -> &str {
    encoding.trim_start_matches(['r', 'n', 'N', 'o', 'O', 'R', 'V'])
}

fn ivar_encoding_matches(kind: ScalarKind, encoding: &str) -> bool {
    let encoding = normalized_encoding(encoding);
    match kind {
        ScalarKind::Void => false,
        ScalarKind::Bool => matches!(encoding.as_bytes().first(), Some(b'B' | b'c')),
        ScalarKind::I8 => encoding.starts_with('c'),
        ScalarKind::U8 => encoding.starts_with('C'),
        ScalarKind::I16 => encoding.starts_with('s'),
        ScalarKind::U16 => encoding.starts_with('S'),
        ScalarKind::I32 => encoding.starts_with('i'),
        ScalarKind::U32 => encoding.starts_with('I'),
        ScalarKind::I64 | ScalarKind::Isize => encoding.starts_with('q') || encoding.starts_with('l'),
        ScalarKind::U64 | ScalarKind::Usize => encoding.starts_with('Q') || encoding.starts_with('L'),
        ScalarKind::Pointer => matches!(encoding.as_bytes().first(), Some(b'@' | b'#' | b':' | b'^' | b'*')),
    }
}

fn ivar_kind(
    ctx: *mut ffi::JSContext,
    name: &str,
    type_name: &str,
    encoding: Option<&str>,
) -> Result<ScalarKind, ffi::JSValue> {
    let kind = parse_scalar_kind(type_name).map_err(|error| js_throw_type_error(ctx, &format!("{name}: {error}")))?;
    if kind == ScalarKind::Void {
        return Err(js_throw_type_error(
            ctx,
            &format!("{name}: void is not a valid ivar type"),
        ));
    }
    if let Some(encoding) = encoding {
        if !ivar_encoding_matches(kind, encoding) {
            return Err(js_throw_type_error(
                ctx,
                &format!("{name}: requested {type_name} does not match Objective-C encoding {encoding}"),
            ));
        }
    }
    Ok(kind)
}

unsafe fn required_ivar_inputs(
    ctx: *mut ffi::JSContext,
    argc: i32,
    argv: *mut ffi::JSValue,
    usage: &str,
) -> Result<(String, String, ScalarKind), ffi::JSValue> {
    let name = unsafe { required_string(ctx, argc, argv, 0, usage) }?;
    let type_name = unsafe { required_string(ctx, argc, argv, 1, usage) }?;
    let kind = ivar_kind(ctx, &name, &type_name, None)?;
    Ok((name, type_name, kind))
}

unsafe extern "C" fn receiver_read_ivar(
    ctx: *mut ffi::JSContext,
    this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let state = match unsafe { receiver_state(ctx, this) } {
        Ok(state) => unsafe { &*state },
        Err(error) => return error,
    };
    let object = match unsafe { receiver_object(ctx, state, "ObjC.readIvar") } {
        Ok(object) => object,
        Err(error) => return error,
    };
    let (name, type_name, kind) = match unsafe {
        required_ivar_inputs(
            ctx,
            argc,
            argv,
            "ObjC receiver.readIvar(name, type) requires two strings",
        )
    } {
        Ok(inputs) => inputs,
        Err(error) => return error,
    };
    let width = kind.width().expect("void ivar type rejected");
    let slot = match object.ivar_address(&name, width, IvarAccess::Read) {
        Ok(slot) => slot,
        Err(error) => return bridge_error(ctx, "ObjC.readIvar", error),
    };
    if let Err(error) = ivar_kind(ctx, &name, &type_name, slot.type_encoding.as_deref()) {
        return error;
    }
    match object.read_ivar(&name, kind) {
        Ok(value) => scalar_to_js(ctx, value),
        Err(error) => bridge_error(ctx, "ObjC.readIvar", error),
    }
}

unsafe extern "C" fn receiver_write_ivar(
    ctx: *mut ffi::JSContext,
    this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let state = match unsafe { receiver_state(ctx, this) } {
        Ok(state) => unsafe { &*state },
        Err(error) => return error,
    };
    let object = match unsafe { receiver_object(ctx, state, "ObjC.writeIvar") } {
        Ok(object) => object,
        Err(error) => return error,
    };
    let (name, type_name, kind) = match unsafe {
        required_ivar_inputs(
            ctx,
            argc,
            argv,
            "ObjC receiver.writeIvar(name, type, value) requires name/type strings and a value",
        )
    } {
        Ok(inputs) => inputs,
        Err(error) => return error,
    };
    if argc < 3 {
        return js_throw_type_error(
            ctx,
            "ObjC receiver.writeIvar(name, type, value) requires name/type strings and a value",
        );
    }
    let width = kind.width().expect("void ivar type rejected");
    let slot = match object.ivar_address(&name, width, IvarAccess::Write) {
        Ok(slot) => slot,
        Err(error) => return bridge_error(ctx, "ObjC.writeIvar", error),
    };
    if let Err(error) = ivar_kind(ctx, &name, &type_name, slot.type_encoding.as_deref()) {
        return error;
    }
    let value = match scalar_value_from_js(ctx, JSValue(unsafe { *argv.add(2) }), kind, "ObjC.writeIvar value") {
        Ok(value) => value,
        Err(error) => return js_throw_type_error(ctx, &error),
    };
    match unsafe { object.write_ivar(&name, value) } {
        Ok(()) => JSValue::undefined().raw(),
        Err(error) => bridge_error(ctx, "ObjC.writeIvar", error),
    }
}

unsafe extern "C" fn receiver_ivar_address(
    ctx: *mut ffi::JSContext,
    this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let state = match unsafe { receiver_state(ctx, this) } {
        Ok(state) => unsafe { &*state },
        Err(error) => return error,
    };
    let object = match unsafe { receiver_object(ctx, state, "ObjC.ivarAddress") } {
        Ok(object) => object,
        Err(error) => return error,
    };
    let (name, type_name, kind) = match unsafe {
        required_ivar_inputs(
            ctx,
            argc,
            argv,
            "ObjC receiver.ivarAddress(name, type[, access]) requires name/type strings",
        )
    } {
        Ok(inputs) => inputs,
        Err(error) => return error,
    };
    let access = if argc < 3 {
        IvarAccess::Read
    } else {
        let access_name = match unsafe {
            required_string(
                ctx,
                argc,
                argv,
                2,
                "ObjC receiver.ivarAddress access must be 'read' or 'write'",
            )
        } {
            Ok(access) => access,
            Err(error) => return error,
        };
        match access_name.trim().to_ascii_lowercase().as_str() {
            "read" => IvarAccess::Read,
            "write" => IvarAccess::Write,
            _ => return js_throw_type_error(ctx, "ObjC receiver.ivarAddress access must be 'read' or 'write'"),
        }
    };
    let slot = match object.ivar_address(&name, kind.width().expect("void ivar type rejected"), access) {
        Ok(slot) => slot,
        Err(error) => return bridge_error(ctx, "ObjC.ivarAddress", error),
    };
    if let Err(error) = ivar_kind(ctx, &name, &type_name, slot.type_encoding.as_deref()) {
        return error;
    }
    create_native_pointer(ctx, slot.address as u64).raw()
}

unsafe extern "C" fn receiver_to_pointer(
    ctx: *mut ffi::JSContext,
    this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let state = match unsafe { receiver_state(ctx, this) } {
        Ok(state) => unsafe { &*state },
        Err(error) => return error,
    };
    let receiver = state.receiver.as_ref().expect("receiver_state checked active receiver");
    create_native_pointer(ctx, receiver.raw() as u64).raw()
}

unsafe extern "C" fn receiver_kind(
    ctx: *mut ffi::JSContext,
    this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let state = match unsafe { receiver_state(ctx, this) } {
        Ok(state) => unsafe { &*state },
        Err(error) => return error,
    };
    JSValue::string(
        ctx,
        state
            .receiver
            .as_ref()
            .expect("receiver_state checked active receiver")
            .kind(),
    )
    .raw()
}

unsafe extern "C" fn receiver_dispose(
    ctx: *mut ffi::JSContext,
    this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let class_id = OBJC_RECEIVER_CLASS_ID.load(Ordering::Acquire);
    if class_id == 0 {
        return js_throw_type_error(ctx, "value is not an ObjC object wrapper");
    }
    let opaque = unsafe { ffi::JS_GetOpaque(this, class_id) };
    if opaque.is_null() {
        return js_throw_type_error(ctx, "value is not an ObjC object wrapper");
    }
    let state = unsafe { &mut *(opaque as *mut ReceiverState) };
    state.receiver.take();
    JSValue::undefined().raw()
}

unsafe extern "C" fn receiver_to_string(
    ctx: *mut ffi::JSContext,
    this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let state = match unsafe { receiver_state(ctx, this) } {
        Ok(state) => unsafe { &*state },
        Err(error) => return error,
    };
    let receiver = state.receiver.as_ref().expect("receiver_state checked active receiver");
    JSValue::string(ctx, &format!("<ObjC.{} {:#x}>", receiver.kind(), receiver.raw())).raw()
}

unsafe fn set_string_array_property(ctx: *mut ffi::JSContext, object: ffi::JSValue, name: &str, values: &[&str]) {
    let array = unsafe { ffi::JS_NewArray(ctx) };
    for (index, value) in values.iter().enumerate() {
        unsafe { ffi::JS_SetPropertyUint32(ctx, array, index as u32, JSValue::string(ctx, value).raw()) };
    }
    JSValue(object).set_property(ctx, name, JSValue(array));
}

/// Adds `ObjC.object`, `ObjC.class`, bridge metadata, and the shared receiver
/// prototype to an existing `ObjC` namespace object.
pub(crate) fn register_objc_object_api(ctx: &JSContext, objc: ffi::JSValue) -> Result<(), String> {
    let class_id = get_or_init_receiver_class_id(ctx.as_ptr())?;
    unsafe {
        let ctx_ptr = ctx.as_ptr();
        let prototype = ffi::JS_NewObject(ctx_ptr);
        if ffi::qjs_is_exception(prototype) != 0 {
            return Err("failed to allocate QuickJS Objective-C receiver prototype".into());
        }
        add_cfunction_to_object(ctx_ptr, prototype, "send", receiver_send, 3);
        add_cfunction_to_object(ctx_ptr, prototype, "sendUnchecked", receiver_send, 3);
        add_cfunction_to_object(ctx_ptr, prototype, "getProperty", receiver_get_property, 2);
        add_cfunction_to_object(ctx_ptr, prototype, "setProperty", receiver_set_property, 3);
        add_cfunction_to_object(ctx_ptr, prototype, "readIvar", receiver_read_ivar, 2);
        add_cfunction_to_object(ctx_ptr, prototype, "writeIvar", receiver_write_ivar, 3);
        add_cfunction_to_object(ctx_ptr, prototype, "writeIvarRaw", receiver_write_ivar, 3);
        add_cfunction_to_object(ctx_ptr, prototype, "ivarAddress", receiver_ivar_address, 3);
        add_cfunction_to_object(ctx_ptr, prototype, "toPointer", receiver_to_pointer, 0);
        add_cfunction_to_object(ctx_ptr, prototype, "kind", receiver_kind, 0);
        add_cfunction_to_object(ctx_ptr, prototype, "dispose", receiver_dispose, 0);
        add_cfunction_to_object(ctx_ptr, prototype, "toString", receiver_to_string, 0);
        add_cfunction_to_object(ctx_ptr, prototype, "toJSON", receiver_to_string, 0);
        let bridge = ObjectBridge::new();
        let capabilities = bridge.capabilities();
        let exception_boundary = if capabilities.catches_objc_exceptions {
            "contained-by-apple-shim"
        } else {
            "platform-unavailable"
        };
        JSValue(prototype).set_property(
            ctx_ptr,
            "exceptionBoundary",
            JSValue::string(ctx_ptr, exception_boundary),
        );
        JSValue(prototype).set_property(
            ctx_ptr,
            "ivarWriteSemantics",
            JSValue::string(ctx_ptr, "raw-no-arc-barrier"),
        );
        ffi::JS_SetClassProto(ctx_ptr, class_id, prototype);

        add_cfunction_to_object(ctx_ptr, objc, "object", js_objc_object, 1);
        add_cfunction_to_object(ctx_ptr, objc, "class", js_objc_class, 1);
        add_cfunction_to_object(ctx_ptr, objc, "registerClass", js_objc_register_class, 1);

        let status = ffi::JS_NewObject(ctx_ptr);
        JSValue(status).set_property(ctx_ptr, "available", JSValue::bool(capabilities.available));
        JSValue(status).set_property(
            ctx_ptr,
            "exceptionBoundary",
            JSValue::string(ctx_ptr, exception_boundary),
        );
        JSValue(status).set_property(
            ctx_ptr,
            "maxArguments",
            JSValue::int(capabilities.max_message_arguments as i32),
        );
        JSValue(status).set_property(
            ctx_ptr,
            "catchesExceptions",
            JSValue::bool(capabilities.catches_objc_exceptions),
        );
        JSValue(status).set_property(
            ctx_ptr,
            "acceptsTaggedPointers",
            JSValue::bool(capabilities.accepts_tagged_object_pointers),
        );
        JSValue(status).set_property(
            ctx_ptr,
            "scalarAndPointerDispatch",
            JSValue::bool(capabilities.supports_scalar_and_pointer_dispatch),
        );
        JSValue(status).set_property(
            ctx_ptr,
            "rawIvarAccess",
            JSValue::bool(capabilities.supports_raw_ivar_access),
        );
        JSValue(status).set_property(
            ctx_ptr,
            "propertyAccessors",
            JSValue::bool(capabilities.supports_property_accessors),
        );
        set_string_array_property(ctx_ptr, status, "propertyOwnership", PROPERTY_OWNERSHIP_NAMES);
        set_string_array_property(ctx_ptr, status, "propertyAtomicity", PROPERTY_ATOMICITY_NAMES);
        set_string_array_property(ctx_ptr, status, "propertyKvoModes", PROPERTY_KVO_MODES);
        JSValue(status).set_property(
            ctx_ptr,
            "dynamicClassRegistration",
            JSValue::bool(capabilities.supports_dynamic_class_registration),
        );
        JSValue(status).set_property(
            ctx_ptr,
            "dynamicPropertySynthesis",
            JSValue::bool(capabilities.supports_dynamic_property_synthesis),
        );
        JSValue(status).set_property(ctx_ptr, "ownership", JSValue::string(ctx_ptr, "retained-finalizer"));
        JSValue(status).set_property(
            ctx_ptr,
            "ivarWriteSemantics",
            JSValue::string(ctx_ptr, "raw-no-arc-barrier"),
        );
        set_string_array_property(ctx_ptr, status, "scalarTypes", SCALAR_TYPE_NAMES);
        set_string_array_property(ctx_ptr, status, "receiverMethods", RECEIVER_METHOD_NAMES);
        JSValue(objc).set_property(ctx_ptr, "objectBridge", JSValue(status));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ptr::register_ptr;
    use crate::runtime::JSRuntime;

    fn with_context(test: impl FnOnce(&JSContext)) {
        let runtime = JSRuntime::new().expect("create QuickJS runtime");
        let context = runtime.new_context().expect("create QuickJS context");
        register_ptr(&context);
        let objc = context.new_object();
        register_objc_object_api(&context, objc.raw()).expect("register ObjC object bridge");
        let global = context.global_object();
        global.set_property(context.as_ptr(), "ObjC", objc);
        global.free(context.as_ptr());
        test(&context);
    }

    fn eval_error(context: &JSContext, script: &str) -> String {
        match context.eval(script, "<objc-object-test>") {
            Ok(value) => {
                value.free(context.as_ptr());
                panic!("ObjC object expression unexpectedly succeeded")
            }
            Err(error) => error,
        }
    }

    #[test]
    fn parses_bounded_scalar_and_pointer_types() {
        assert_eq!(parse_scalar_kind("bool"), Ok(ScalarKind::Bool));
        assert_eq!(parse_scalar_kind("NSInteger"), Ok(ScalarKind::Isize));
        assert_eq!(parse_scalar_kind("uint32_t"), Ok(ScalarKind::U32));
        assert_eq!(parse_scalar_kind("id"), Ok(ScalarKind::Pointer));
        assert!(parse_scalar_kind("double")
            .unwrap_err()
            .contains("does not support double"));
        assert!(parse_scalar_kind("{Pair=ii}").unwrap_err().contains("aggregate"));
        assert!(parse_scalar_kind("...").unwrap_err().contains("variadic"));
    }

    #[test]
    fn matches_objc_ivar_encodings_conservatively() {
        assert!(ivar_encoding_matches(ScalarKind::Bool, "B"));
        assert!(ivar_encoding_matches(ScalarKind::I32, "ri"));
        assert!(ivar_encoding_matches(ScalarKind::Pointer, "@\"NSObject\""));
        assert!(ivar_encoding_matches(ScalarKind::Pointer, "^v"));
        assert!(!ivar_encoding_matches(ScalarKind::U32, "i"));
        assert!(!ivar_encoding_matches(ScalarKind::Pointer, "{Pair=ii}"));
    }

    #[test]
    fn property_setter_selectors_follow_objc_naming() {
        assert_eq!(property_setter_selector("title"), Ok("setTitle:".into()));
        assert_eq!(property_setter_selector("URL"), Ok("setURL:".into()));
        assert!(property_setter_selector(" ").unwrap_err().contains("must not be empty"));
        assert!(property_setter_selector("set:value")
            .unwrap_err()
            .contains("must not contain"));
    }

    #[test]
    fn javascript_registration_exposes_the_contract() {
        with_context(|context| {
            let value = context
                .eval(
                    "(function () { const b = ObjC.objectBridge; return typeof ObjC.object === 'function' && typeof ObjC.class === 'function' && typeof ObjC.registerClass === 'function' && b.acceptsTaggedPointers === false && b.maxArguments === 6 && b.ownership === 'retained-finalizer' && b.ivarWriteSemantics === 'raw-no-arc-barrier' && b.propertyOwnership.join(',') === 'assign,retain,copy,weak' && b.propertyAtomicity.join(',') === 'nonatomic,atomic' && b.propertyKvoModes.join(',') === 'automatic,manual' && b.scalarTypes.includes('pointer') && b.receiverMethods.includes('dispose') && b.receiverMethods.includes('getProperty') && b.receiverMethods.includes('setProperty'); })()",
                    "<objc-object-test>",
                )
                .expect("inspect ObjC object contract");
            assert_eq!(value.to_bool(), Some(true));
            value.free(context.as_ptr());

            let capabilities = ObjectBridge::new().capabilities();
            let exception_boundary = if capabilities.catches_objc_exceptions {
                "contained-by-apple-shim"
            } else {
                "platform-unavailable"
            };
            let platform_contract = format!(
                "(function () {{ const b = ObjC.objectBridge; return b.available === {available} && b.exceptionBoundary === '{exception_boundary}' && b.catchesExceptions === {catches_exceptions} && b.scalarAndPointerDispatch === {scalar_dispatch} && b.rawIvarAccess === {raw_ivar_access} && b.propertyAccessors === {property_accessors} && b.dynamicClassRegistration === {dynamic_class_registration} && b.dynamicPropertySynthesis === {dynamic_property_synthesis}; }})()",
                available = capabilities.available,
                catches_exceptions = capabilities.catches_objc_exceptions,
                scalar_dispatch = capabilities.supports_scalar_and_pointer_dispatch,
                raw_ivar_access = capabilities.supports_raw_ivar_access,
                property_accessors = capabilities.supports_property_accessors,
                dynamic_class_registration = capabilities.supports_dynamic_class_registration,
                dynamic_property_synthesis = capabilities.supports_dynamic_property_synthesis,
            );
            let platform_value = context
                .eval(&platform_contract, "<objc-object-platform-test>")
                .expect("inspect platform ObjC object capabilities");
            assert_eq!(platform_value.to_bool(), Some(true));
            platform_value.free(context.as_ptr());
        });
    }

    #[test]
    fn javascript_argument_descriptors_are_typed_and_bounded() {
        with_context(|context| {
            let descriptors = context
                .eval(
                    "[{ type: 'i32', value: -7 }, { type: 'pointer', value: ptr('0x1234') }, { type: 'bool', value: true }]",
                    "<objc-object-test>",
                )
                .expect("create argument descriptors");
            let parsed = unsafe { parse_message_arguments(context.as_ptr(), Some(descriptors)) }
                .unwrap_or_else(|_| panic!("parse argument descriptors"));
            assert_eq!(
                parsed,
                vec![
                    ScalarValue::I32(-7),
                    ScalarValue::Pointer(0x1234),
                    ScalarValue::Bool(true),
                ]
            );
            descriptors.free(context.as_ptr());

            let too_many = context
                .eval(
                    "Array.from({ length: 7 }, () => ({ type: 'i32', value: 0 }))",
                    "<objc-object-test>",
                )
                .expect("create oversized descriptor array");
            let error = unsafe { parse_message_arguments(context.as_ptr(), Some(too_many)) }
                .expect_err("argument limit must be enforced");
            assert!(JSValue(error).is_exception());
            too_many.free(context.as_ptr());
            assert!(context.get_exception().contains("at most 6"));
        });
    }

    #[test]
    fn dynamic_class_spec_is_fully_validated_before_platform_dispatch() {
        with_context(|context| {
            assert!(eval_error(context, "ObjC.registerClass(null)").contains("requires an object"));
            assert!(
                eval_error(context, "ObjC.registerClass({ name: '', superclass: 'NSObject' })")
                    .contains("non-empty string")
            );
            assert!(eval_error(
                context,
                "ObjC.registerClass({ name: 'DemoClass', superclass: 'NSObject', ivars: [{ name: 'value', size: 8, alignment: 8 }] })"
            )
            .contains("typeEncoding must be a string"));
            assert!(eval_error(
                context,
                "ObjC.registerClass({ name: 'DemoClass', superclass: 'NSObject', methods: [{ selector: 'run', implementation: {}, typeEncoding: 'v@:' }] })"
            )
            .contains("pointer-like"));
            assert!(eval_error(
                context,
                "ObjC.registerClass({ name: 'DemoClass', superclass: 'NSObject', ivars: Array.from({ length: 129 }, function () { return {}; }) })"
            )
            .contains("at most 128"));
            assert!(eval_error(
                context,
                "ObjC.registerClass({ name: 'DemoClass', superclass: 'NSObject', properties: [{ name: 'bad-name', typeEncoding: 'i' }] })"
            )
            .contains("invalid property name"));
            assert!(eval_error(
                context,
                "ObjC.registerClass({ name: 'DemoClass', superclass: 'NSObject', properties: [{ name: 'a'.repeat(256), typeEncoding: 'i' }] })"
            )
            .contains("property name exceeds 255 bytes"));
            assert!(eval_error(
                context,
                "ObjC.registerClass({ name: 'DemoClass', superclass: 'NSObject', properties: [{ name: 'title', typeEncoding: '@', ownership: 'borrow' }] })"
            )
            .contains("ownership must be assign, retain, strong, copy, or weak"));
            assert!(eval_error(
                context,
                "ObjC.registerClass({ name: 'DemoClass', superclass: 'NSObject', properties: Array.from({ length: 129 }, function () { return {}; }) })"
            )
            .contains("at most 128"));
        });
    }

    #[test]
    fn dynamic_property_accessors_are_parsed_and_validated_on_host() {
        with_context(|context| {
            let value = context
                .eval(
                    "({ name: 'DemoClass', superclass: 'NSObject', properties: [{ name: 'ready', typeEncoding: 'B', atomic: true, kvo: 'manual', getter: 'isReady', setter: 'markReady:' }, { name: 'count', typeEncoding: 'i' }] })",
                    "<objc-object-test>",
                )
                .expect("create dynamic class property spec");
            let spec = unsafe { parse_dynamic_class_spec(context.as_ptr(), value) }
                .unwrap_or_else(|_| panic!("parse dynamic class property spec: {}", context.get_exception()));
            value.free(context.as_ptr());
            assert_eq!(spec.properties.len(), 2);
            assert!(spec.properties[0].atomic);
            assert_eq!(spec.properties[0].getter.as_deref(), Some("isReady"));
            assert_eq!(spec.properties[0].setter.as_deref(), Some("markReady:"));
            assert_eq!(spec.properties[0].kvo, PropertyKvo::Manual);
            assert!(!spec.properties[1].atomic);
            assert_eq!(spec.properties[1].kvo, PropertyKvo::Automatic);

            assert!(eval_error(
                context,
                "ObjC.registerClass({ name: 'DemoClass', superclass: 'NSObject', properties: [{ name: 'ready', typeEncoding: 'B', atomic: 'yes' }] })"
            )
            .contains("ObjC.registerClass spec.properties[0].atomic must be a boolean"));

            assert!(eval_error(
                context,
                "ObjC.registerClass({ name: 'DemoClass', superclass: 'NSObject', properties: [{ name: 'ready', typeEncoding: 'B', kvo: true }] })"
            )
            .contains("ObjC.registerClass spec.properties[0].kvo must be a string"));
            assert!(eval_error(
                context,
                "ObjC.registerClass({ name: 'DemoClass', superclass: 'NSObject', properties: [{ name: 'ready', typeEncoding: 'B', kvo: 'disabled' }] })"
            )
            .contains("ObjC.registerClass spec.properties[0].kvo must be automatic or manual"));
            assert!(eval_error(
                context,
                "ObjC.registerClass({ name: 'DemoClass', superclass: 'NSObject', properties: [{ name: 'ready', typeEncoding: 'B', readOnly: true, kvo: 'manual' }] })"
            )
            .contains("readOnly=true conflicts with kvo='manual'"));

            assert!(eval_error(
                context,
                "ObjC.registerClass({ name: 'DemoClass', superclass: 'NSObject', properties: [{ name: 'ready', typeEncoding: 'B', getter: 'isReady:' }] })"
            )
            .contains("getter selector must not contain ':'"));
            assert!(eval_error(
                context,
                "ObjC.registerClass({ name: 'DemoClass', superclass: 'NSObject', properties: [{ name: 'ready', typeEncoding: 'B', getter: 'is,Ready' }] })"
            )
            .contains("getter selector must not contain ','"));
            assert!(eval_error(
                context,
                "ObjC.registerClass({ name: 'DemoClass', superclass: 'NSObject', properties: [{ name: 'ready', typeEncoding: 'B', setter: 'markReady' }] })"
            )
            .contains("setter selector must contain exactly one trailing ':'"));
            assert!(eval_error(
                context,
                "ObjC.registerClass({ name: 'DemoClass', superclass: 'NSObject', properties: [{ name: 'ready', typeEncoding: 'B', setter: 'mark:Ready:' }] })"
            )
            .contains("setter selector must contain exactly one trailing ':'"));
            assert!(eval_error(
                context,
                "ObjC.registerClass({ name: 'DemoClass', superclass: 'NSObject', properties: [{ name: 'ready', typeEncoding: 'B', setter: 'mark,Ready:' }] })"
            )
            .contains("setter selector must not contain ','"));
            assert!(eval_error(
                context,
                "ObjC.registerClass({ name: 'DemoClass', superclass: 'NSObject', properties: [{ name: 'ready', typeEncoding: 'B', readOnly: true, setter: 'markReady:' }] })"
            )
            .contains("readOnly=true conflicts with an explicit setter"));
        });
    }

    #[cfg(not(any(target_os = "ios", target_os = "macos")))]
    #[test]
    fn non_apple_registration_reports_stable_errors_after_validation() {
        with_context(|context| {
            assert!(eval_error(context, "ObjC.object(ptr('0'))").contains("object pointer is null"));
            assert!(eval_error(context, "ObjC.object(ptr('0x1001'))").contains("tagged pointers"));
            assert!(eval_error(context, "ObjC.object(ptr('0x1000'))").contains("only available on Apple targets"));
            assert!(eval_error(context, "ObjC.class('NSObject')").contains("only available on Apple targets"));
            assert!(eval_error(context, "ObjC.object({})").contains("pointer-like"));
            assert!(eval_error(context, "ObjC.class(123)").contains("class-name string"));
            assert!(eval_error(
                context,
                "ObjC.registerClass({ name: 'IOSRustFridaHostClass', superclass: 'NSObject', ivars: [], methods: [] })"
            )
            .contains("only available on Apple targets"));
            assert!(eval_error(
                context,
                "ObjC.registerClass({ name: 'IOSRustFridaWeakHostClass', superclass: 'NSObject', properties: [{ name: 'delegate', typeEncoding: '@', ownership: 'weak' }] })"
            )
            .contains("only available on Apple targets"));
        });
    }
}
