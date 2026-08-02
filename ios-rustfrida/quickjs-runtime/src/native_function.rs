use crate::context::JSContext;
use crate::ffi;
use crate::ptr::{create_native_pointer, get_native_pointer_addr};
use crate::util::{add_cfunction_to_object, js_throw_internal_error, js_throw_range_error, js_throw_type_error};
use crate::value::JSValue;
use native_api::normalize_code_pointer;

const GPR_ARGUMENT_COUNT: usize = 8;
const FPR_ARGUMENT_COUNT: usize = 8;
const MAX_STACK_ARGUMENTS: usize = 256;
const MAX_ARGUMENTS: usize = GPR_ARGUMENT_COUNT + FPR_ARGUMENT_COUNT + MAX_STACK_ARGUMENTS;
const MIN_CALL_TARGET: u64 = 0x1_0000;
const JS_MAX_SAFE_INTEGER: f64 = 9_007_199_254_740_991.0;

const NATIVE_FUNCTION_BOOTSTRAP: &str = r#"
(function () {
    'use strict';
    const validate = globalThis.__iosNativeFunctionValidate;
    const invoke = globalThis.__iosNativeFunctionInvoke;

    globalThis.NativeFunction = function NativeFunction(address, returnType, argumentTypes) {
        if (arguments.length !== 3) {
            throw new TypeError('NativeFunction(address, returnType, argumentTypes) requires exactly 3 arguments; variadic/options forms are unsupported');
        }
        if (!Array.isArray(argumentTypes)) {
            throw new TypeError('NativeFunction: argumentTypes must be an array');
        }

        const types = argumentTypes.slice();
        const normalizedAddress = validate(address, returnType, types);
        const fn = function () {
            if (arguments.length !== types.length) {
                throw new TypeError('NativeFunction: expected ' + types.length + ' arguments, got ' + arguments.length);
            }
            return invoke(normalizedAddress, returnType, types, Array.prototype.slice.call(arguments));
        };

        Object.defineProperties(fn, {
            address: { value: normalizedAddress, enumerable: true },
            returnType: { value: returnType, enumerable: true },
            argumentTypes: { value: Object.freeze(types.slice()), enumerable: true }
        });
        fn.toString = function () {
            return 'NativeFunction(' + String(normalizedAddress) + ', ' + returnType + ', [' + types.join(', ') + '])';
        };
        return fn;
    };

    delete globalThis.__iosNativeFunctionValidate;
    delete globalThis.__iosNativeFunctionInvoke;
})();
"#;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NativeType {
    Void,
    Bool,
    Signed(u8),
    Unsigned(u8),
    Pointer,
    Float32,
    Float64,
}

impl NativeType {
    fn parse(name: &str) -> Result<Self, String> {
        match name {
            "void" => Ok(Self::Void),
            "bool" => Ok(Self::Bool),
            "char" | "int8" => Ok(Self::Signed(8)),
            "uchar" | "uint8" => Ok(Self::Unsigned(8)),
            "short" | "int16" => Ok(Self::Signed(16)),
            "ushort" | "uint16" => Ok(Self::Unsigned(16)),
            "int" | "int32" => Ok(Self::Signed(32)),
            "uint" | "uint32" => Ok(Self::Unsigned(32)),
            "long" | "int64" | "ssize_t" => Ok(Self::Signed(64)),
            "ulong" | "uint64" | "size_t" => Ok(Self::Unsigned(64)),
            "pointer" => Ok(Self::Pointer),
            "float" => Ok(Self::Float32),
            "double" => Ok(Self::Float64),
            "..." | "variadic" => {
                Err("NativeFunction: variadic signatures are unsupported by the iOS AAPCS64 backend".into())
            }
            name if name.starts_with('{') || name.starts_with('[') => {
                Err("NativeFunction: struct and array-by-value types are unsupported by the iOS AAPCS64 backend".into())
            }
            _ => Err(format!("NativeFunction: unknown type '{name}'")),
        }
    }

    fn is_argument(self) -> bool {
        !matches!(self, Self::Void)
    }

    fn uses_fpr(self) -> bool {
        matches!(self, Self::Float32 | Self::Float64)
    }

    fn stack_size(self) -> usize {
        match self {
            Self::Bool | Self::Signed(8) | Self::Unsigned(8) => 1,
            Self::Signed(16) | Self::Unsigned(16) => 2,
            Self::Signed(32) | Self::Unsigned(32) | Self::Float32 => 4,
            Self::Signed(64) | Self::Unsigned(64) | Self::Pointer | Self::Float64 => 8,
            Self::Void | Self::Signed(_) | Self::Unsigned(_) => 0,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ArgumentLocation {
    Gpr(usize),
    Fpr(usize),
    Stack(usize),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Signature {
    return_type: NativeType,
    argument_types: Vec<NativeType>,
    placement: Vec<ArgumentLocation>,
    stack_count: usize,
    stack_size: usize,
}

impl Signature {
    fn new(return_type: NativeType, argument_types: Vec<NativeType>) -> Result<Self, String> {
        if argument_types.len() > MAX_ARGUMENTS {
            return Err(format!(
                "NativeFunction: too many arguments ({} > {MAX_ARGUMENTS})",
                argument_types.len()
            ));
        }
        if argument_types.iter().any(|ty| !ty.is_argument()) {
            return Err("NativeFunction: 'void' can only be the return type".into());
        }

        let mut gpr_count = 0;
        let mut fpr_count = 0;
        let mut stack_count = 0;
        let mut stack_size: usize = 0;
        let placement = argument_types
            .iter()
            .map(|ty| {
                if ty.uses_fpr() && fpr_count < FPR_ARGUMENT_COUNT {
                    let location = ArgumentLocation::Fpr(fpr_count);
                    fpr_count += 1;
                    location
                } else if !ty.uses_fpr() && gpr_count < GPR_ARGUMENT_COUNT {
                    let location = ArgumentLocation::Gpr(gpr_count);
                    gpr_count += 1;
                    location
                } else {
                    let size = ty.stack_size();
                    stack_size = stack_size.div_ceil(size) * size;
                    let location = ArgumentLocation::Stack(stack_size);
                    stack_size += size;
                    stack_count += 1;
                    location
                }
            })
            .collect::<Vec<_>>();
        if stack_count > MAX_STACK_ARGUMENTS {
            return Err(format!(
                "NativeFunction: too many arguments ({} total, {stack_count} stack arguments > {MAX_STACK_ARGUMENTS})",
                argument_types.len()
            ));
        }

        Ok(Self {
            return_type,
            argument_types,
            placement,
            stack_count,
            stack_size,
        })
    }
}

fn parse_integer_text(text: &str) -> Option<u64> {
    let text = text.trim();
    if text.is_empty() {
        return None;
    }

    let (negative, unsigned) = match text.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, text.strip_prefix('+').unwrap_or(text)),
    };
    let (radix, digits) = unsigned
        .strip_prefix("0x")
        .or_else(|| unsigned.strip_prefix("0X"))
        .map(|digits| (16, digits))
        .unwrap_or((10, unsigned));
    if digits.is_empty() {
        return None;
    }

    let magnitude = u128::from_str_radix(digits, radix).ok()?;
    if negative {
        if magnitude > (i64::MAX as u128) + 1 {
            return None;
        }
        if magnitude == (i64::MAX as u128) + 1 {
            Some(i64::MIN as u64)
        } else {
            Some((-(magnitude as i64)) as u64)
        }
    } else {
        u64::try_from(magnitude).ok()
    }
}

fn normalize_argument_bits(raw: u64, ty: NativeType) -> u64 {
    match ty {
        NativeType::Void => 0,
        NativeType::Bool => u64::from(raw != 0),
        NativeType::Signed(bits @ (8 | 16)) => signed_result(raw, bits) as i32 as u32 as u64,
        NativeType::Signed(32) | NativeType::Unsigned(32) => raw & 0xffff_ffff,
        NativeType::Unsigned(bits @ (8 | 16)) => raw & ((1u64 << bits) - 1),
        NativeType::Signed(_) | NativeType::Unsigned(_) | NativeType::Pointer => raw,
        NativeType::Float32 | NativeType::Float64 => raw,
    }
}

fn floating_argument_bits(value: f64, ty: NativeType) -> u64 {
    match ty {
        NativeType::Float32 => (value as f32).to_bits() as u64,
        NativeType::Float64 => value.to_bits(),
        _ => 0,
    }
}

fn write_stack_argument(stack: &mut [u8], offset: usize, ty: NativeType, bits: u64) {
    let size = ty.stack_size();
    stack[offset..offset + size].copy_from_slice(&bits.to_le_bytes()[..size]);
}

fn signed_result(raw: u64, bits: u8) -> i64 {
    if bits == 64 {
        return raw as i64;
    }
    let shift = 64 - bits;
    ((raw << shift) as i64) >> shift
}

unsafe fn require_type_name(ctx: *mut ffi::JSContext, value: JSValue, position: &str) -> Result<String, ffi::JSValue> {
    if !value.is_string() {
        return Err(js_throw_type_error(
            ctx,
            &format!(
                "NativeFunction: {position} type must be a string; struct and array-by-value types are unsupported"
            ),
        ));
    }
    value
        .to_string(ctx)
        .ok_or_else(|| js_throw_type_error(ctx, &format!("NativeFunction: invalid {position} type")))
}

unsafe fn require_array_length(ctx: *mut ffi::JSContext, value: JSValue, usage: &str) -> Result<usize, ffi::JSValue> {
    if ffi::JS_IsArray(ctx, value.raw()) != 1 {
        return Err(js_throw_type_error(ctx, usage));
    }
    let length = value.get_property(ctx, "length");
    let parsed = length.to_u64(ctx);
    length.free(ctx);
    let Some(length) = parsed.and_then(|length| usize::try_from(length).ok()) else {
        return Err(js_throw_type_error(ctx, usage));
    };
    Ok(length)
}

unsafe fn parse_signature(
    ctx: *mut ffi::JSContext,
    return_value: JSValue,
    argument_values: JSValue,
) -> Result<Signature, ffi::JSValue> {
    let return_name = require_type_name(ctx, return_value, "return")?;
    let return_type = NativeType::parse(&return_name).map_err(|message| js_throw_type_error(ctx, &message))?;
    let count = require_array_length(ctx, argument_values, "NativeFunction: argumentTypes must be an array")?;
    if count > MAX_ARGUMENTS {
        return Err(js_throw_range_error(
            ctx,
            &format!("NativeFunction: too many arguments ({count} > {MAX_ARGUMENTS})"),
        ));
    }

    let mut types = Vec::with_capacity(count);
    for index in 0..count {
        let raw = ffi::JS_GetPropertyUint32(ctx, argument_values.raw(), index as u32);
        let value = JSValue(raw);
        let name = match require_type_name(ctx, value, &format!("argument {index}")) {
            Ok(name) => name,
            Err(err) => {
                value.free(ctx);
                return Err(err);
            }
        };
        value.free(ctx);
        let ty = NativeType::parse(&name).map_err(|message| js_throw_type_error(ctx, &message))?;
        types.push(ty);
    }

    Signature::new(return_type, types).map_err(|message| js_throw_type_error(ctx, &message))
}

unsafe fn extract_call_target(ctx: *mut ffi::JSContext, value: JSValue) -> Result<u64, ffi::JSValue> {
    let address = if let Some(address) = get_native_pointer_addr(value) {
        address
    } else if value.is_int() || value.is_float() || ffi::qjs_is_big_int(ctx, value.raw()) != 0 {
        let mut address = 0u64;
        if ffi::qjs_value_to_u64(ctx, &mut address, value.raw()) != 0 {
            return Err(js_throw_type_error(
                ctx,
                "NativeFunction: address must be a NativePointer, integer Number, or BigInt",
            ));
        }
        address
    } else {
        return Err(js_throw_type_error(
            ctx,
            "NativeFunction: address must be a NativePointer, integer Number, or BigInt",
        ));
    };

    let address = normalize_code_pointer(address as usize) as u64;
    if address < MIN_CALL_TARGET {
        return Err(js_throw_range_error(
            ctx,
            "NativeFunction: address is null or below the minimum callable address",
        ));
    }
    Ok(address)
}

unsafe fn value_to_integer_bits(
    ctx: *mut ffi::JSContext,
    value: JSValue,
    ty: NativeType,
    index: usize,
) -> Result<u64, ffi::JSValue> {
    let raw = if value.is_null() || value.is_undefined() {
        0
    } else if let Some(address) = get_native_pointer_addr(value) {
        address
    } else if let Some(value) = value.to_bool() {
        u64::from(value)
    } else if value.is_int() {
        value.to_int().unwrap_or_default() as i64 as u64
    } else if value.is_float() {
        let number = value.to_float().unwrap_or(f64::NAN);
        if !number.is_finite() || number.fract() != 0.0 || number.abs() > JS_MAX_SAFE_INTEGER {
            return Err(js_throw_type_error(
                ctx,
                &format!("NativeFunction: argument {index} must be a finite integer; use BigInt for 64-bit values"),
            ));
        }
        if number < 0.0 {
            (number as i64) as u64
        } else {
            number as u64
        }
    } else if value.is_string() || ffi::qjs_is_big_int(ctx, value.raw()) != 0 {
        let text = value
            .to_string(ctx)
            .ok_or_else(|| js_throw_type_error(ctx, &format!("NativeFunction: argument {index} is not an integer")))?;
        parse_integer_text(&text).ok_or_else(|| {
            js_throw_type_error(
                ctx,
                &format!("NativeFunction: argument {index} is outside the supported 64-bit integer range"),
            )
        })?
    } else {
        return Err(js_throw_type_error(
            ctx,
            &format!(
                "NativeFunction: argument {index} must be an integer, boolean, string, BigInt, NativePointer, null, or undefined"
            ),
        ));
    };

    Ok(normalize_argument_bits(raw, ty))
}

unsafe fn value_to_floating_bits(
    ctx: *mut ffi::JSContext,
    value: JSValue,
    ty: NativeType,
    index: usize,
) -> Result<u64, ffi::JSValue> {
    let number = if value.is_null() || value.is_undefined() {
        0.0
    } else if let Some(value) = value.to_bool() {
        if value {
            1.0
        } else {
            0.0
        }
    } else if let Some(value) = value.to_float() {
        value
    } else if value.is_string() || ffi::qjs_is_big_int(ctx, value.raw()) != 0 {
        let text = value
            .to_string(ctx)
            .ok_or_else(|| js_throw_type_error(ctx, &format!("NativeFunction: argument {index} is not numeric")))?;
        match text.trim() {
            "Infinity" | "+Infinity" => f64::INFINITY,
            "-Infinity" => f64::NEG_INFINITY,
            text => text.parse::<f64>().map_err(|_| {
                js_throw_type_error(
                    ctx,
                    &format!("NativeFunction: argument {index} cannot be converted to float/double"),
                )
            })?,
        }
    } else {
        return Err(js_throw_type_error(
            ctx,
            &format!(
                "NativeFunction: argument {index} must be a Number, BigInt, boolean, string, null, or undefined for float/double"
            ),
        ));
    };

    Ok(floating_argument_bits(number, ty))
}

#[cfg(all(target_arch = "aarch64", target_vendor = "apple"))]
#[derive(Default)]
#[repr(C)]
struct NativeCallResult {
    gpr: u64,
    fpr: u64,
}

#[cfg(all(target_arch = "aarch64", target_vendor = "apple"))]
unsafe fn marshal_return(ctx: *mut ffi::JSContext, ty: NativeType, raw: NativeCallResult) -> ffi::JSValue {
    match ty {
        NativeType::Void => JSValue::undefined().raw(),
        NativeType::Bool => JSValue::bool(raw.gpr & 0xff != 0).raw(),
        NativeType::Signed(bits @ (8 | 16 | 32)) => ffi::qjs_new_int32(ctx, signed_result(raw.gpr, bits) as i32),
        NativeType::Unsigned(bits @ (8 | 16)) => {
            ffi::qjs_new_uint32(ctx, normalize_argument_bits(raw.gpr, NativeType::Unsigned(bits)) as u32)
        }
        NativeType::Unsigned(32) => ffi::qjs_new_uint32(ctx, raw.gpr as u32),
        NativeType::Signed(64) => ffi::JS_NewBigInt64(ctx, raw.gpr as i64),
        NativeType::Unsigned(64) => ffi::JS_NewBigUint64(ctx, raw.gpr),
        NativeType::Pointer if raw.gpr == 0 => JSValue::null().raw(),
        NativeType::Pointer => create_native_pointer(ctx, raw.gpr).raw(),
        NativeType::Float32 => ffi::qjs_new_float64(ctx, f32::from_bits(raw.fpr as u32) as f64),
        NativeType::Float64 => ffi::qjs_new_float64(ctx, f64::from_bits(raw.fpr)),
        NativeType::Signed(_) | NativeType::Unsigned(_) => {
            js_throw_internal_error(ctx, "NativeFunction: invalid integer return width")
        }
    }
}

unsafe extern "C" fn js_native_function_validate(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc != 3 {
        return js_throw_type_error(
            ctx,
            "NativeFunction(address, returnType, argumentTypes) requires exactly 3 arguments",
        );
    }
    let address = match extract_call_target(ctx, JSValue(*argv)) {
        Ok(address) => address,
        Err(err) => return err,
    };
    if let Err(err) = parse_signature(ctx, JSValue(*argv.add(1)), JSValue(*argv.add(2))) {
        return err;
    }
    create_native_pointer(ctx, address).raw()
}

unsafe extern "C" fn js_native_function_invoke(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc != 4 {
        return js_throw_type_error(ctx, "NativeFunction internal invocation requires 4 arguments");
    }

    let address = match extract_call_target(ctx, JSValue(*argv)) {
        Ok(address) => address,
        Err(err) => return err,
    };
    let signature = match parse_signature(ctx, JSValue(*argv.add(1)), JSValue(*argv.add(2))) {
        Ok(signature) => signature,
        Err(err) => return err,
    };
    let values = JSValue(*argv.add(3));
    let value_count = match require_array_length(ctx, values, "NativeFunction: invocation arguments must be an array") {
        Ok(count) => count,
        Err(err) => return err,
    };
    if value_count != signature.argument_types.len() {
        return js_throw_type_error(
            ctx,
            &format!(
                "NativeFunction: expected {} arguments, got {value_count}",
                signature.argument_types.len()
            ),
        );
    }

    let mut gpr = [0u64; GPR_ARGUMENT_COUNT];
    let mut fpr = [0u64; FPR_ARGUMENT_COUNT];
    let mut stack = vec![0u8; signature.stack_size];
    for (index, (ty, location)) in signature
        .argument_types
        .iter()
        .copied()
        .zip(signature.placement.iter().copied())
        .enumerate()
    {
        let raw = ffi::JS_GetPropertyUint32(ctx, values.raw(), index as u32);
        let value = JSValue(raw);
        let bits = match if ty.uses_fpr() {
            value_to_floating_bits(ctx, value, ty, index)
        } else {
            value_to_integer_bits(ctx, value, ty, index)
        } {
            Ok(bits) => bits,
            Err(err) => {
                value.free(ctx);
                return err;
            }
        };
        value.free(ctx);
        match location {
            ArgumentLocation::Gpr(slot) => gpr[slot] = bits,
            ArgumentLocation::Fpr(slot) => fpr[slot] = bits,
            ArgumentLocation::Stack(offset) => write_stack_argument(&mut stack, offset, ty, bits),
        }
    }

    #[cfg(all(target_arch = "aarch64", target_vendor = "apple"))]
    {
        if !crate::memory::is_executable_address(address) {
            return js_throw_range_error(ctx, "NativeFunction: address is not in an executable memory region");
        }

        unsafe extern "C" {
            fn ios_native_call_aapcs64(
                target: *const core::ffi::c_void,
                gpr: *const u64,
                fpr: *const u64,
                stack: *const u8,
                stack_size: usize,
                result: *mut NativeCallResult,
            );
        }

        let mut raw = NativeCallResult::default();
        ios_native_call_aapcs64(
            address as usize as *const core::ffi::c_void,
            gpr.as_ptr(),
            fpr.as_ptr(),
            stack.as_ptr(),
            stack.len(),
            &mut raw,
        );
        return marshal_return(ctx, signature.return_type, raw);
    }

    #[cfg(not(all(target_arch = "aarch64", target_vendor = "apple")))]
    {
        let _ = (address, gpr, fpr, stack);
        js_throw_internal_error(
            ctx,
            "NativeFunction invocation is unsupported on this platform; the iOS backend requires Apple AArch64",
        )
    }
}

pub(crate) fn register_native_function_api(ctx: &JSContext) -> Result<(), String> {
    let global = ctx.global_object();
    unsafe {
        add_cfunction_to_object(
            ctx.as_ptr(),
            global.raw(),
            "__iosNativeFunctionValidate",
            js_native_function_validate,
            3,
        );
        add_cfunction_to_object(
            ctx.as_ptr(),
            global.raw(),
            "__iosNativeFunctionInvoke",
            js_native_function_invoke,
            4,
        );
    }
    global.free(ctx.as_ptr());

    let value = ctx.eval(NATIVE_FUNCTION_BOOTSTRAP, "<native-function-bootstrap>")?;
    value.free(ctx.as_ptr());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ptr::register_ptr;
    use crate::runtime::JSRuntime;

    #[test]
    fn parses_supported_scalar_types() {
        assert_eq!(NativeType::parse("void"), Ok(NativeType::Void));
        assert_eq!(NativeType::parse("bool"), Ok(NativeType::Bool));
        assert_eq!(NativeType::parse("char"), Ok(NativeType::Signed(8)));
        assert_eq!(NativeType::parse("ushort"), Ok(NativeType::Unsigned(16)));
        assert_eq!(NativeType::parse("int32"), Ok(NativeType::Signed(32)));
        assert_eq!(NativeType::parse("size_t"), Ok(NativeType::Unsigned(64)));
        assert_eq!(NativeType::parse("pointer"), Ok(NativeType::Pointer));
        assert_eq!(NativeType::parse("float"), Ok(NativeType::Float32));
        assert_eq!(NativeType::parse("double"), Ok(NativeType::Float64));
    }

    #[test]
    fn rejects_unsupported_abi_classes_explicitly() {
        assert!(NativeType::parse("...").unwrap_err().contains("variadic"));
        assert!(NativeType::parse("{Pair=ii}").unwrap_err().contains("struct"));
        assert!(NativeType::parse("wat").unwrap_err().contains("unknown type"));
    }

    #[test]
    fn places_first_eight_values_in_gprs_and_overflow_on_stack() {
        let signature =
            Signature::new(NativeType::Unsigned(64), vec![NativeType::Unsigned(64); 11]).expect("valid signature");
        assert_eq!(signature.placement[0], ArgumentLocation::Gpr(0));
        assert_eq!(signature.placement[7], ArgumentLocation::Gpr(7));
        assert_eq!(signature.placement[8], ArgumentLocation::Stack(0));
        assert_eq!(signature.placement[10], ArgumentLocation::Stack(16));
        assert_eq!(signature.stack_count, 3);
        assert_eq!(signature.stack_size, 24);
    }

    #[test]
    fn allocates_gprs_and_fprs_independently_then_spills_in_declaration_order() {
        let interleaved = Signature::new(
            NativeType::Signed(32),
            vec![
                NativeType::Signed(32),
                NativeType::Float32,
                NativeType::Signed(32),
                NativeType::Float64,
            ],
        )
        .expect("valid interleaved signature");
        assert_eq!(
            interleaved.placement,
            vec![
                ArgumentLocation::Gpr(0),
                ArgumentLocation::Fpr(0),
                ArgumentLocation::Gpr(1),
                ArgumentLocation::Fpr(1),
            ]
        );

        let mut types = vec![NativeType::Float32; FPR_ARGUMENT_COUNT];
        types.extend(vec![NativeType::Unsigned(64); GPR_ARGUMENT_COUNT]);
        types.extend([NativeType::Float64, NativeType::Unsigned(64), NativeType::Float32]);
        let signature = Signature::new(NativeType::Float64, types).expect("valid mixed signature");

        assert_eq!(signature.placement[0], ArgumentLocation::Fpr(0));
        assert_eq!(signature.placement[7], ArgumentLocation::Fpr(7));
        assert_eq!(signature.placement[8], ArgumentLocation::Gpr(0));
        assert_eq!(signature.placement[15], ArgumentLocation::Gpr(7));
        assert_eq!(signature.placement[16], ArgumentLocation::Stack(0));
        assert_eq!(signature.placement[17], ArgumentLocation::Stack(8));
        assert_eq!(signature.placement[18], ArgumentLocation::Stack(16));
        assert_eq!(signature.stack_count, 3);
        assert_eq!(signature.stack_size, 20);
    }

    #[test]
    fn packs_spilled_scalars_using_apple_arm64_stack_alignment() {
        let mut types = vec![NativeType::Unsigned(64); GPR_ARGUMENT_COUNT];
        types.extend([
            NativeType::Signed(8),
            NativeType::Signed(16),
            NativeType::Signed(32),
            NativeType::Signed(64),
        ]);
        types.extend(vec![NativeType::Float64; FPR_ARGUMENT_COUNT]);
        types.extend([NativeType::Float32, NativeType::Float64, NativeType::Signed(8)]);
        let signature = Signature::new(NativeType::Float64, types).expect("valid packed signature");

        assert_eq!(signature.placement[8], ArgumentLocation::Stack(0));
        assert_eq!(signature.placement[9], ArgumentLocation::Stack(2));
        assert_eq!(signature.placement[10], ArgumentLocation::Stack(4));
        assert_eq!(signature.placement[11], ArgumentLocation::Stack(8));
        assert_eq!(signature.placement[20], ArgumentLocation::Stack(16));
        assert_eq!(signature.placement[21], ArgumentLocation::Stack(24));
        assert_eq!(signature.placement[22], ArgumentLocation::Stack(32));
        assert_eq!(signature.stack_size, 33);
    }

    #[test]
    fn enforces_stack_limit_and_void_argument_rule() {
        let too_many = Signature::new(NativeType::Void, vec![NativeType::Unsigned(64); MAX_ARGUMENTS + 1]).unwrap_err();
        assert!(too_many.contains("too many arguments"));
        let too_many_stack = Signature::new(
            NativeType::Void,
            vec![NativeType::Unsigned(64); GPR_ARGUMENT_COUNT + MAX_STACK_ARGUMENTS + 1],
        )
        .unwrap_err();
        assert!(too_many_stack.contains("stack arguments"));
        assert!(Signature::new(NativeType::Void, vec![NativeType::Void])
            .unwrap_err()
            .contains("return type"));
    }

    #[test]
    fn integer_coercion_helpers_preserve_aapcs64_bit_patterns() {
        assert_eq!(parse_integer_text("-1"), Some(u64::MAX));
        assert_eq!(parse_integer_text("0xffffffffffffffff"), Some(u64::MAX));
        assert_eq!(normalize_argument_bits(u64::MAX, NativeType::Signed(8)), 0xffff_ffff);
        assert_eq!(normalize_argument_bits(u64::MAX, NativeType::Unsigned(8)), 0xff);
        assert_eq!(normalize_argument_bits(2, NativeType::Bool), 1);
        assert_eq!(signed_result(0xff, 8), -1);
        assert_eq!(signed_result(0xffff_ffff, 32), -1);
        assert_eq!(
            floating_argument_bits(1.5, NativeType::Float32),
            (1.5f32).to_bits() as u64
        );
        assert_eq!(floating_argument_bits(-2.25, NativeType::Float64), (-2.25f64).to_bits());
        assert_eq!(
            floating_argument_bits(-0.0, NativeType::Float32),
            (-0.0f32).to_bits() as u64
        );
        assert_eq!(
            floating_argument_bits(f64::INFINITY, NativeType::Float64),
            f64::INFINITY.to_bits()
        );
        assert_eq!(
            floating_argument_bits(f64::NEG_INFINITY, NativeType::Float64),
            f64::NEG_INFINITY.to_bits()
        );
        assert!((floating_argument_bits(f64::NAN, NativeType::Float64) & 0x7ff0_0000_0000_0000) != 0);

        let rounded = 1.0 + f64::EPSILON;
        assert_eq!(
            floating_argument_bits(rounded, NativeType::Float32),
            1.0f32.to_bits() as u64
        );

        let mut stack = [0u8; 8];
        write_stack_argument(&mut stack, 2, NativeType::Signed(16), 0xabcd);
        write_stack_argument(&mut stack, 4, NativeType::Float32, 1.5f32.to_bits() as u64);
        assert_eq!(stack, [0, 0, 0xcd, 0xab, 0, 0, 0xc0, 0x3f]);
    }

    fn with_context(test: impl FnOnce(&JSContext)) {
        let runtime = JSRuntime::new().expect("create QuickJS runtime");
        let context = runtime.new_context().expect("create QuickJS context");
        register_ptr(&context);
        register_native_function_api(&context).expect("register NativeFunction");
        test(&context);
    }

    fn eval_error(context: &JSContext, script: &str) -> String {
        match context.eval(script, "<native-function-test>") {
            Ok(value) => {
                value.free(context.as_ptr());
                panic!("NativeFunction expression unexpectedly succeeded")
            }
            Err(error) => error,
        }
    }

    #[test]
    fn javascript_constructor_validates_and_exposes_metadata() {
        with_context(|context| {
            let value = context
                .eval(
                    "(function () { const f = new NativeFunction(ptr('0x10000'), 'double', ['pointer', 'float']); return typeof f === 'function' && f.returnType === 'double' && f.argumentTypes.join(',') === 'pointer,float' && typeof globalThis.__iosNativeFunctionInvoke === 'undefined'; })()",
                    "<native-function-test>",
                )
                .expect("construct NativeFunction");
            assert_eq!(value.to_bool(), Some(true));
            value.free(context.as_ptr());

            let error = eval_error(context, "new NativeFunction(ptr('0x10000'), 'int', [['int', 'int']])");
            assert!(error.contains("struct and array-by-value"));
        });
    }

    #[cfg(not(all(target_arch = "aarch64", target_vendor = "apple")))]
    #[test]
    fn non_apple_aarch64_invocation_reports_stable_unsupported_after_validation() {
        with_context(|context| {
            let error = eval_error(context, "new NativeFunction(ptr('0x10000'), 'uint64', ['uint64'])(1n)");
            assert!(error.contains("requires Apple AArch64"));

            let error = eval_error(context, "new NativeFunction(ptr('0x10000'), 'int', ['int'])({})");
            assert!(error.contains("argument 0 must be an integer"));

            let error = eval_error(context, "new NativeFunction(ptr('0x10000'), 'double', ['float'])({})");
            assert!(error.contains("for float/double"));
        });
    }
}
