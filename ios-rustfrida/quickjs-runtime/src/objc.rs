use crate::context::JSContext;
use crate::ffi;
use crate::objc_object::{create_retained_object_wrapper, register_objc_object_api};
use crate::ptr::create_native_pointer;
use crate::util::{
    add_cfunction_to_object, js_throw_internal_error, js_throw_type_error, js_u64_to_js_number_or_bigint,
    require_string_arg,
};
use crate::value::JSValue;
use common::Error as CommonError;
use objc_api::{
    ObjcApi, ObjcClassInfo, ObjcIvarDetail, ObjcIvarInfo, ObjcMethodDetail, ObjcMethodInfo, ObjcPropertyDetail,
    ObjcPropertyInfo, ObjcProtocolInfo, ObjcProtocolMethodDetail, ObjcProtocolMethodInfo, ObjcProtocolPropertyDetail,
    ObjcProtocolPropertyInfo, DEFAULT_MAX_INSTANCE_COUNT, MAX_INSTANCE_COUNT,
};

unsafe fn pointer_arg_to_u64(ctx: *mut ffi::JSContext, value: JSValue, usage: &str) -> Result<u64, ffi::JSValue> {
    if let Some(address) = crate::ptr::get_native_pointer_addr(value) {
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

unsafe fn parse_optional_filter_arg(
    ctx: *mut ffi::JSContext,
    value: JSValue,
    usage: &str,
) -> Result<Option<String>, ffi::JSValue> {
    if value.is_null() || value.is_undefined() {
        return Ok(None);
    }
    if value.is_string() {
        return Ok(value.to_string(ctx));
    }
    Err(js_throw_type_error(ctx, usage))
}

unsafe fn parse_objc_bool_and_query_args(
    ctx: *mut ffi::JSContext,
    argc: i32,
    argv: *mut ffi::JSValue,
    start_index: usize,
    bool_name: &str,
    query_usage: &str,
) -> Result<(bool, Option<String>), ffi::JSValue> {
    let mut flag = false;
    let mut query = None;

    for index in start_index..(argc as usize) {
        let value = JSValue(*argv.add(index));
        if value.is_null() || value.is_undefined() {
            continue;
        }
        if value.is_bool() {
            flag = value.to_bool().unwrap_or(false);
            continue;
        }
        if value.is_string() {
            query = value.to_string(ctx);
            continue;
        }
        return Err(js_throw_type_error(
            ctx,
            &format!("{query_usage}; expected {bool_name} to be a boolean and query to be a string when provided"),
        ));
    }

    Ok((flag, query))
}

fn parse_choose_max_count(ctx: *mut ffi::JSContext, value: JSValue) -> Result<usize, String> {
    if unsafe { ffi::qjs_is_big_int(ctx, value.raw()) } != 0 {
        let signed = value
            .to_i64(ctx)
            .ok_or_else(|| "ObjC.choose options.maxCount must fit a non-negative integer".to_string())?;
        if signed < 0 {
            return Err("ObjC.choose options.maxCount must be non-negative".into());
        }
        return usize::try_from(signed).map_err(|_| "ObjC.choose options.maxCount is out of range".into());
    }

    let number = value
        .to_float()
        .ok_or_else(|| "ObjC.choose options.maxCount must be an integer Number or BigInt".to_string())?;
    if !number.is_finite() || number.fract() != 0.0 || number < 0.0 {
        return Err("ObjC.choose options.maxCount must be a non-negative finite integer".into());
    }
    if number > MAX_INSTANCE_COUNT as f64 {
        return Err(format!("ObjC.choose options.maxCount must be <= {MAX_INSTANCE_COUNT}"));
    }
    Ok(number as usize)
}

unsafe fn parse_choose_options(ctx: *mut ffi::JSContext, value: JSValue) -> Result<(bool, usize), ffi::JSValue> {
    if value.is_null() || value.is_undefined() {
        return Ok((false, DEFAULT_MAX_INSTANCE_COUNT));
    }
    if !value.is_object() {
        return Err(js_throw_type_error(
            ctx,
            "ObjC.choose options must be an object when provided",
        ));
    }

    let include_value = value.get_property(ctx, "includeSubclasses");
    if include_value.is_exception() {
        return Err(include_value.raw());
    }
    let include_subclasses = if include_value.is_null() || include_value.is_undefined() {
        false
    } else {
        match include_value.to_bool() {
            Some(flag) => flag,
            None => {
                include_value.free(ctx);
                return Err(js_throw_type_error(
                    ctx,
                    "ObjC.choose options.includeSubclasses must be a boolean",
                ));
            }
        }
    };
    include_value.free(ctx);

    let max_value = value.get_property(ctx, "maxCount");
    if max_value.is_exception() {
        return Err(max_value.raw());
    }
    if max_value.is_null() || max_value.is_undefined() {
        max_value.free(ctx);
        return Ok((include_subclasses, DEFAULT_MAX_INSTANCE_COUNT));
    }
    let max_count = parse_choose_max_count(ctx, max_value)
        .and_then(|max_count| {
            if max_count > MAX_INSTANCE_COUNT {
                Err(format!("ObjC.choose options.maxCount must be <= {MAX_INSTANCE_COUNT}"))
            } else {
                Ok(max_count)
            }
        })
        .map_err(|message| js_throw_type_error(ctx, &message));
    max_value.free(ctx);
    max_count.map(|max_count| (include_subclasses, max_count))
}

fn choose_instances(class_name: &str, include_subclasses: bool, max_count: usize) -> Result<Vec<usize>, CommonError> {
    ObjcApi::new().choose_instances(class_name, include_subclasses, max_count)
}

unsafe extern "C" fn js_objc_choose_sync(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let class_name = match require_string_arg(
        ctx,
        argc,
        argv,
        0,
        "ObjC.chooseSync(className[, options]) requires a class-name string",
    ) {
        Ok(value) if !value.trim().is_empty() => value,
        Ok(_) => return js_throw_type_error(ctx, "ObjC.chooseSync className must not be empty"),
        Err(err) => return err,
    };
    let options = if argc >= 2 {
        JSValue(*argv.add(1))
    } else {
        JSValue::undefined()
    };
    let (include_subclasses, max_count) = match parse_choose_options(ctx, options) {
        Ok(value) => value,
        Err(err) => return err,
    };

    let instances = match choose_instances(&class_name, include_subclasses, max_count) {
        Ok(instances) => instances,
        Err(CommonError::Unsupported(_)) => Vec::new(),
        Err(CommonError::InvalidArgument(message)) => return js_throw_type_error(ctx, &message),
        Err(err) => return js_throw_internal_error(ctx, &err.to_string()),
    };

    let array = ffi::JS_NewArray(ctx);
    let mut output_index = 0u32;
    for raw in instances {
        let wrapper = match create_retained_object_wrapper(ctx, raw) {
            Ok(wrapper) => wrapper,
            Err(_) => continue,
        };
        if JSValue(wrapper).is_exception() {
            JSValue(array).free(ctx);
            return wrapper;
        }
        if ffi::JS_SetPropertyUint32(ctx, array, output_index, wrapper) < 0 {
            JSValue(array).free(ctx);
            return ffi::JS_GetException(ctx);
        }
        output_index = output_index.saturating_add(1);
    }
    array
}

unsafe extern "C" fn js_objc_choose(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let class_name = match require_string_arg(
        ctx,
        argc,
        argv,
        0,
        "ObjC.choose(className, callbacks[, options]) requires a class-name string",
    ) {
        Ok(value) if !value.trim().is_empty() => value,
        Ok(_) => return js_throw_type_error(ctx, "ObjC.choose className must not be empty"),
        Err(err) => return err,
    };
    if argc < 2 {
        return js_throw_type_error(ctx, "ObjC.choose(className, callbacks) requires a callbacks object");
    }
    let callbacks = JSValue(*argv.add(1));
    if !callbacks.is_object() {
        return js_throw_type_error(ctx, "ObjC.choose callbacks must be an object");
    }
    let on_match = callbacks.get_property(ctx, "onMatch");
    if on_match.is_exception() {
        return on_match.raw();
    }
    if !on_match.is_function(ctx) {
        on_match.free(ctx);
        return js_throw_type_error(ctx, "ObjC.choose callbacks.onMatch must be a function");
    }
    let on_complete_value = callbacks.get_property(ctx, "onComplete");
    if on_complete_value.is_exception() {
        on_match.free(ctx);
        return on_complete_value.raw();
    }
    let on_complete = if on_complete_value.is_null() || on_complete_value.is_undefined() {
        on_complete_value.free(ctx);
        None
    } else if on_complete_value.is_function(ctx) {
        Some(on_complete_value)
    } else {
        on_match.free(ctx);
        on_complete_value.free(ctx);
        return js_throw_type_error(ctx, "ObjC.choose callbacks.onComplete must be a function when provided");
    };

    let options = if argc >= 3 {
        JSValue(*argv.add(2))
    } else {
        JSValue::undefined()
    };
    let (include_subclasses, max_count) = match parse_choose_options(ctx, options) {
        Ok(value) => value,
        Err(err) => {
            on_match.free(ctx);
            if let Some(on_complete) = on_complete {
                on_complete.free(ctx);
            }
            return err;
        }
    };

    let instances = match choose_instances(&class_name, include_subclasses, max_count) {
        Ok(instances) => instances,
        Err(CommonError::Unsupported(_)) => Vec::new(),
        Err(CommonError::InvalidArgument(message)) => {
            on_match.free(ctx);
            if let Some(on_complete) = on_complete {
                on_complete.free(ctx);
            }
            return js_throw_type_error(ctx, &message);
        }
        Err(err) => {
            on_match.free(ctx);
            if let Some(on_complete) = on_complete {
                on_complete.free(ctx);
            }
            return js_throw_internal_error(ctx, &err.to_string());
        }
    };

    for raw in instances {
        let wrapper = match create_retained_object_wrapper(ctx, raw) {
            Ok(wrapper) => wrapper,
            Err(_) => continue,
        };
        if JSValue(wrapper).is_exception() {
            on_match.free(ctx);
            if let Some(on_complete) = on_complete {
                on_complete.free(ctx);
            }
            return wrapper;
        }
        let mut args = [wrapper];
        let result_raw = ffi::JS_Call(ctx, on_match.raw(), callbacks.raw(), 1, args.as_mut_ptr());
        JSValue(wrapper).free(ctx);
        let result = JSValue(result_raw);
        if result.is_exception() {
            on_match.free(ctx);
            if let Some(on_complete) = on_complete {
                on_complete.free(ctx);
            }
            return result_raw;
        }
        let stop = result.is_string() && result.to_string(ctx).as_deref() == Some("stop");
        result.free(ctx);
        if stop {
            break;
        }
    }

    on_match.free(ctx);
    if let Some(on_complete) = on_complete {
        let result_raw = ffi::JS_Call(ctx, on_complete.raw(), callbacks.raw(), 0, std::ptr::null_mut());
        on_complete.free(ctx);
        let result = JSValue(result_raw);
        if result.is_exception() {
            return result_raw;
        }
        result.free(ctx);
    }
    JSValue::undefined().raw()
}

unsafe extern "C" fn js_objc_classes(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let query = if argc < 1 {
        None
    } else {
        let value = JSValue(*argv);
        if value.is_null() || value.is_undefined() {
            None
        } else {
            match value.to_string(ctx) {
                Some(query) => Some(query),
                None => {
                    return js_throw_type_error(
                        ctx,
                        "ObjC.classes([query]) expected query to be a string when provided",
                    )
                }
            }
        }
    };

    let classes = match query {
        Some(query) => ObjcApi::new().find_classes(&query),
        None => ObjcApi::new().enumerate_classes(),
    };

    let classes = match classes {
        Ok(classes) => classes,
        Err(CommonError::Unsupported(_)) => return ffi::JS_NewArray(ctx),
        Err(CommonError::InvalidArgument(message)) => return js_throw_type_error(ctx, &message),
        Err(err) => return js_throw_internal_error(ctx, &err.to_string()),
    };

    let array = ffi::JS_NewArray(ctx);
    for (index, name) in classes.iter().enumerate() {
        ffi::JS_SetPropertyUint32(ctx, array, index as u32, JSValue::string(ctx, name).raw());
    }
    array
}

unsafe extern "C" fn js_objc_find_classes(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let query = match require_string_arg(ctx, argc, argv, 0, "ObjC.findClasses(query) requires 1 string argument") {
        Ok(value) => value,
        Err(err) => return err,
    };

    let classes = match ObjcApi::new().find_classes(&query) {
        Ok(classes) => classes,
        Err(CommonError::Unsupported(_)) => return ffi::JS_NewArray(ctx),
        Err(CommonError::InvalidArgument(message)) => return js_throw_type_error(ctx, &message),
        Err(err) => return js_throw_internal_error(ctx, &err.to_string()),
    };

    let array = ffi::JS_NewArray(ctx);
    for (index, name) in classes.iter().enumerate() {
        ffi::JS_SetPropertyUint32(ctx, array, index as u32, JSValue::string(ctx, name).raw());
    }
    array
}

unsafe extern "C" fn js_objc_protocols(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let query = if argc < 1 {
        None
    } else {
        let value = JSValue(*argv);
        if value.is_null() || value.is_undefined() {
            None
        } else {
            match value.to_string(ctx) {
                Some(query) => Some(query),
                None => {
                    return js_throw_type_error(
                        ctx,
                        "ObjC.protocols([query]) expected query to be a string when provided",
                    )
                }
            }
        }
    };

    let protocols = match query {
        Some(query) => ObjcApi::new().find_protocols(&query),
        None => ObjcApi::new().enumerate_protocols(),
    };

    let protocols = match protocols {
        Ok(protocols) => protocols,
        Err(CommonError::Unsupported(_)) => return ffi::JS_NewArray(ctx),
        Err(CommonError::InvalidArgument(message)) => return js_throw_type_error(ctx, &message),
        Err(err) => return js_throw_internal_error(ctx, &err.to_string()),
    };

    let array = ffi::JS_NewArray(ctx);
    for (index, name) in protocols.iter().enumerate() {
        ffi::JS_SetPropertyUint32(ctx, array, index as u32, JSValue::string(ctx, name).raw());
    }
    array
}

unsafe extern "C" fn js_objc_find_protocols(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let query = match require_string_arg(
        ctx,
        argc,
        argv,
        0,
        "ObjC.findProtocols(query) requires 1 string argument",
    ) {
        Ok(value) => value,
        Err(err) => return err,
    };

    let protocols = match ObjcApi::new().find_protocols(&query) {
        Ok(protocols) => protocols,
        Err(CommonError::Unsupported(_)) => return ffi::JS_NewArray(ctx),
        Err(CommonError::InvalidArgument(message)) => return js_throw_type_error(ctx, &message),
        Err(err) => return js_throw_internal_error(ctx, &err.to_string()),
    };

    let array = ffi::JS_NewArray(ctx);
    for (index, name) in protocols.iter().enumerate() {
        ffi::JS_SetPropertyUint32(ctx, array, index as u32, JSValue::string(ctx, name).raw());
    }
    array
}

unsafe extern "C" fn js_objc_class_protocols(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let class_name = match require_string_arg(
        ctx,
        argc,
        argv,
        0,
        "ObjC.classProtocols(className[, query]) requires 1 string argument",
    ) {
        Ok(value) => value,
        Err(err) => return err,
    };
    let query = if argc >= 2 {
        match parse_optional_filter_arg(
            ctx,
            JSValue(*argv.add(1)),
            "ObjC.classProtocols(className[, query]) expected query to be a string when provided",
        ) {
            Ok(value) => value,
            Err(err) => return err,
        }
    } else {
        None
    };

    let protocols = match query {
        Some(query) => ObjcApi::new().find_class_protocols(&class_name, &query),
        None => ObjcApi::new().class_protocols(&class_name),
    };

    let protocols = match protocols {
        Ok(protocols) => protocols,
        Err(CommonError::Unsupported(_)) => return ffi::JS_NewArray(ctx),
        Err(CommonError::InvalidArgument(message)) => return js_throw_type_error(ctx, &message),
        Err(err) => return js_throw_internal_error(ctx, &err.to_string()),
    };

    let array = ffi::JS_NewArray(ctx);
    for (index, name) in protocols.iter().enumerate() {
        ffi::JS_SetPropertyUint32(ctx, array, index as u32, JSValue::string(ctx, name).raw());
    }
    array
}

unsafe extern "C" fn js_objc_protocol_owners(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let protocol_name = match require_string_arg(
        ctx,
        argc,
        argv,
        0,
        "ObjC.protocolOwners(protocolName[, query]) requires 1 string argument",
    ) {
        Ok(value) => value,
        Err(err) => return err,
    };
    let query = if argc >= 2 {
        match parse_optional_filter_arg(
            ctx,
            JSValue(*argv.add(1)),
            "ObjC.protocolOwners(protocolName[, query]) expected query to be a string when provided",
        ) {
            Ok(value) => value,
            Err(err) => return err,
        }
    } else {
        None
    };

    let owners = match query {
        Some(query) => ObjcApi::new().find_protocol_owners(&protocol_name, &query),
        None => ObjcApi::new().protocol_owners(&protocol_name),
    };

    let owners = match owners {
        Ok(owners) => owners,
        Err(CommonError::Unsupported(_)) => return ffi::JS_NewArray(ctx),
        Err(CommonError::InvalidArgument(message)) => return js_throw_type_error(ctx, &message),
        Err(err) => return js_throw_internal_error(ctx, &err.to_string()),
    };

    let array = ffi::JS_NewArray(ctx);
    for (index, name) in owners.iter().enumerate() {
        ffi::JS_SetPropertyUint32(ctx, array, index as u32, JSValue::string(ctx, name).raw());
    }
    array
}

unsafe extern "C" fn js_objc_protocol_protocols(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let protocol_name = match require_string_arg(
        ctx,
        argc,
        argv,
        0,
        "ObjC.protocolProtocols(protocolName[, query]) requires 1 string argument",
    ) {
        Ok(value) => value,
        Err(err) => return err,
    };
    let query = if argc >= 2 {
        match parse_optional_filter_arg(
            ctx,
            JSValue(*argv.add(1)),
            "ObjC.protocolProtocols(protocolName[, query]) expected query to be a string when provided",
        ) {
            Ok(value) => value,
            Err(err) => return err,
        }
    } else {
        None
    };

    let protocols = match query {
        Some(query) => ObjcApi::new().find_protocol_protocols(&protocol_name, &query),
        None => ObjcApi::new().protocol_protocols(&protocol_name),
    };

    let protocols = match protocols {
        Ok(protocols) => protocols,
        Err(CommonError::Unsupported(_)) => return ffi::JS_NewArray(ctx),
        Err(CommonError::InvalidArgument(message)) => return js_throw_type_error(ctx, &message),
        Err(err) => return js_throw_internal_error(ctx, &err.to_string()),
    };

    let array = ffi::JS_NewArray(ctx);
    for (index, name) in protocols.iter().enumerate() {
        ffi::JS_SetPropertyUint32(ctx, array, index as u32, JSValue::string(ctx, name).raw());
    }
    array
}

unsafe extern "C" fn js_objc_protocol_info(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let protocol_name = match require_string_arg(
        ctx,
        argc,
        argv,
        0,
        "ObjC.protocolInfo(protocolName) requires 1 string argument",
    ) {
        Ok(value) => value,
        Err(err) => return err,
    };

    match ObjcApi::new().protocol_info(&protocol_name) {
        Ok(Some(info)) => objc_protocol_info_to_js(ctx, &info),
        Ok(None) | Err(CommonError::Unsupported(_)) => JSValue::null().raw(),
        Err(CommonError::InvalidArgument(message)) => js_throw_type_error(ctx, &message),
        Err(err) => js_throw_internal_error(ctx, &err.to_string()),
    }
}

unsafe extern "C" fn js_objc_superclass(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let class_name = match require_string_arg(
        ctx,
        argc,
        argv,
        0,
        "ObjC.superclass(className) requires 1 string argument",
    ) {
        Ok(value) => value,
        Err(err) => return err,
    };

    match ObjcApi::new().superclass(&class_name) {
        Ok(Some(name)) => JSValue::string(ctx, &name).raw(),
        Ok(None) | Err(CommonError::Unsupported(_)) => JSValue::null().raw(),
        Err(CommonError::InvalidArgument(message)) => js_throw_type_error(ctx, &message),
        Err(err) => js_throw_internal_error(ctx, &err.to_string()),
    }
}

unsafe extern "C" fn js_objc_class_chain(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let class_name = match require_string_arg(
        ctx,
        argc,
        argv,
        0,
        "ObjC.classChain(className) requires 1 string argument",
    ) {
        Ok(value) => value,
        Err(err) => return err,
    };

    let chain = match ObjcApi::new().class_chain(&class_name) {
        Ok(chain) => chain,
        Err(CommonError::Unsupported(_)) => return ffi::JS_NewArray(ctx),
        Err(CommonError::InvalidArgument(message)) => return js_throw_type_error(ctx, &message),
        Err(err) => return js_throw_internal_error(ctx, &err.to_string()),
    };

    let array = ffi::JS_NewArray(ctx);
    for (index, name) in chain.iter().enumerate() {
        ffi::JS_SetPropertyUint32(ctx, array, index as u32, JSValue::string(ctx, name).raw());
    }
    array
}

unsafe extern "C" fn js_objc_class_info(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let class_name = match require_string_arg(
        ctx,
        argc,
        argv,
        0,
        "ObjC.classInfo(className[, isMetaClass]) requires 1 string argument",
    ) {
        Ok(value) => value,
        Err(err) => return err,
    };
    let is_meta_class = if argc >= 2 {
        JSValue(*argv.add(1)).to_bool().unwrap_or(false)
    } else {
        false
    };

    match ObjcApi::new().class_info(&class_name, is_meta_class) {
        Ok(Some(info)) => objc_class_info_to_js(ctx, &info),
        Ok(None) | Err(CommonError::Unsupported(_)) => JSValue::null().raw(),
        Err(CommonError::InvalidArgument(message)) => js_throw_type_error(ctx, &message),
        Err(err) => js_throw_internal_error(ctx, &err.to_string()),
    }
}

unsafe extern "C" fn js_objc_class_exists(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let name = match require_string_arg(ctx, argc, argv, 0, "ObjC.classExists(name) requires 1 string argument") {
        Ok(value) => value,
        Err(err) => return err,
    };

    JSValue::bool(ObjcApi::new().class_exists(&name)).raw()
}

unsafe extern "C" fn js_objc_protocol_exists(
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
        "ObjC.protocolExists(name) requires 1 string argument",
    ) {
        Ok(value) => value,
        Err(err) => return err,
    };

    JSValue::bool(ObjcApi::new().protocol_exists(&name)).raw()
}

unsafe extern "C" fn js_objc_class_conforms(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let class_name = match require_string_arg(
        ctx,
        argc,
        argv,
        0,
        "ObjC.classConforms(className, protocolName) requires 2 string arguments",
    ) {
        Ok(value) => value,
        Err(err) => return err,
    };
    let protocol_name = match require_string_arg(
        ctx,
        argc,
        argv,
        1,
        "ObjC.classConforms(className, protocolName) requires 2 string arguments",
    ) {
        Ok(value) => value,
        Err(err) => return err,
    };

    JSValue::bool(ObjcApi::new().class_conforms_to_protocol(&class_name, &protocol_name)).raw()
}

unsafe extern "C" fn js_objc_protocol_conforms(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let protocol_name = match require_string_arg(
        ctx,
        argc,
        argv,
        0,
        "ObjC.protocolConforms(protocolName, parentProtocolName) requires 2 string arguments",
    ) {
        Ok(value) => value,
        Err(err) => return err,
    };
    let parent_protocol_name = match require_string_arg(
        ctx,
        argc,
        argv,
        1,
        "ObjC.protocolConforms(protocolName, parentProtocolName) requires 2 string arguments",
    ) {
        Ok(value) => value,
        Err(err) => return err,
    };

    JSValue::bool(ObjcApi::new().protocol_conforms_to_protocol(&protocol_name, &parent_protocol_name)).raw()
}

unsafe extern "C" fn js_objc_selector(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let name = match require_string_arg(ctx, argc, argv, 0, "ObjC.selector(name) requires 1 string argument") {
        Ok(value) => value,
        Err(err) => return err,
    };

    match ObjcApi::new().selector(&name) {
        Ok(selector) => create_native_pointer(ctx, selector as u64).raw(),
        Err(CommonError::Unsupported(_)) => JSValue::null().raw(),
        Err(CommonError::InvalidArgument(message)) => js_throw_type_error(ctx, &message),
        Err(err) => js_throw_internal_error(ctx, &err.to_string()),
    }
}

unsafe extern "C" fn js_objc_method_imp(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let class_name = match require_string_arg(
        ctx,
        argc,
        argv,
        0,
        "ObjC.methodImp(className, selectorName[, isClassMethod]) requires 2 string arguments",
    ) {
        Ok(value) => value,
        Err(err) => return err,
    };
    let selector_name = match require_string_arg(
        ctx,
        argc,
        argv,
        1,
        "ObjC.methodImp(className, selectorName[, isClassMethod]) requires 2 string arguments",
    ) {
        Ok(value) => value,
        Err(err) => return err,
    };
    let is_class_method = if argc >= 3 {
        JSValue(*argv.add(2)).to_bool().unwrap_or(false)
    } else {
        false
    };

    match ObjcApi::new().method_imp(&class_name, &selector_name, is_class_method) {
        Ok(Some(address)) => create_native_pointer(ctx, address as u64).raw(),
        Ok(None) | Err(CommonError::Unsupported(_)) => JSValue::null().raw(),
        Err(CommonError::InvalidArgument(message)) => js_throw_type_error(ctx, &message),
        Err(err) => js_throw_internal_error(ctx, &err.to_string()),
    }
}

unsafe extern "C" fn js_objc_method_info(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let class_name = match require_string_arg(
        ctx,
        argc,
        argv,
        0,
        "ObjC.methodInfo(className, selectorName[, isClassMethod]) requires 2 string arguments",
    ) {
        Ok(value) => value,
        Err(err) => return err,
    };
    let selector_name = match require_string_arg(
        ctx,
        argc,
        argv,
        1,
        "ObjC.methodInfo(className, selectorName[, isClassMethod]) requires 2 string arguments",
    ) {
        Ok(value) => value,
        Err(err) => return err,
    };
    let is_class_method = if argc >= 3 {
        JSValue(*argv.add(2)).to_bool().unwrap_or(false)
    } else {
        false
    };

    match ObjcApi::new().method_info(&class_name, &selector_name, is_class_method) {
        Ok(Some(info)) => objc_method_detail_to_js(ctx, &info),
        Ok(None) | Err(CommonError::Unsupported(_)) => JSValue::null().raw(),
        Err(CommonError::InvalidArgument(message)) => js_throw_type_error(ctx, &message),
        Err(err) => js_throw_internal_error(ctx, &err.to_string()),
    }
}

unsafe extern "C" fn js_objc_class_image(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let class_name = match require_string_arg(
        ctx,
        argc,
        argv,
        0,
        "ObjC.classImage(className) requires 1 string argument",
    ) {
        Ok(value) => value,
        Err(err) => return err,
    };

    match ObjcApi::new().class_image(&class_name) {
        Ok(Some(path)) => JSValue::string(ctx, &path).raw(),
        Ok(None) | Err(CommonError::Unsupported(_)) => JSValue::null().raw(),
        Err(CommonError::InvalidArgument(message)) => js_throw_type_error(ctx, &message),
        Err(err) => js_throw_internal_error(ctx, &err.to_string()),
    }
}

unsafe extern "C" fn js_objc_protocol_image(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let protocol_name = match require_string_arg(
        ctx,
        argc,
        argv,
        0,
        "ObjC.protocolImage(protocolName) requires 1 string argument",
    ) {
        Ok(value) => value,
        Err(err) => return err,
    };

    match ObjcApi::new().protocol_image(&protocol_name) {
        Ok(Some(path)) => JSValue::string(ctx, &path).raw(),
        Ok(None) | Err(CommonError::Unsupported(_)) => JSValue::null().raw(),
        Err(CommonError::InvalidArgument(message)) => js_throw_type_error(ctx, &message),
        Err(err) => js_throw_internal_error(ctx, &err.to_string()),
    }
}

unsafe extern "C" fn js_objc_property_info(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let class_name = match require_string_arg(
        ctx,
        argc,
        argv,
        0,
        "ObjC.propertyInfo(className, propertyName[, isClassProperty]) requires 2 string arguments",
    ) {
        Ok(value) => value,
        Err(err) => return err,
    };
    let property_name = match require_string_arg(
        ctx,
        argc,
        argv,
        1,
        "ObjC.propertyInfo(className, propertyName[, isClassProperty]) requires 2 string arguments",
    ) {
        Ok(value) => value,
        Err(err) => return err,
    };
    let is_class_property = if argc >= 3 {
        JSValue(*argv.add(2)).to_bool().unwrap_or(false)
    } else {
        false
    };

    match ObjcApi::new().property_info(&class_name, &property_name, is_class_property) {
        Ok(Some(info)) => objc_property_detail_to_js(ctx, &info),
        Ok(None) | Err(CommonError::Unsupported(_)) => JSValue::null().raw(),
        Err(CommonError::InvalidArgument(message)) => js_throw_type_error(ctx, &message),
        Err(err) => js_throw_internal_error(ctx, &err.to_string()),
    }
}

unsafe extern "C" fn js_objc_ivar_info(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let class_name = match require_string_arg(
        ctx,
        argc,
        argv,
        0,
        "ObjC.ivarInfo(className, ivarName) requires 2 string arguments",
    ) {
        Ok(value) => value,
        Err(err) => return err,
    };
    let ivar_name = match require_string_arg(
        ctx,
        argc,
        argv,
        1,
        "ObjC.ivarInfo(className, ivarName) requires 2 string arguments",
    ) {
        Ok(value) => value,
        Err(err) => return err,
    };

    match ObjcApi::new().ivar_info(&class_name, &ivar_name) {
        Ok(Some(info)) => objc_ivar_detail_to_js(ctx, &info),
        Ok(None) | Err(CommonError::Unsupported(_)) => JSValue::null().raw(),
        Err(CommonError::InvalidArgument(message)) => js_throw_type_error(ctx, &message),
        Err(err) => js_throw_internal_error(ctx, &err.to_string()),
    }
}

unsafe extern "C" fn js_objc_method_image(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let class_name = match require_string_arg(
        ctx,
        argc,
        argv,
        0,
        "ObjC.methodImage(className, selectorName[, isClassMethod]) requires 2 string arguments",
    ) {
        Ok(value) => value,
        Err(err) => return err,
    };
    let selector_name = match require_string_arg(
        ctx,
        argc,
        argv,
        1,
        "ObjC.methodImage(className, selectorName[, isClassMethod]) requires 2 string arguments",
    ) {
        Ok(value) => value,
        Err(err) => return err,
    };
    let is_class_method = if argc >= 3 {
        JSValue(*argv.add(2)).to_bool().unwrap_or(false)
    } else {
        false
    };

    match ObjcApi::new().method_image(&class_name, &selector_name, is_class_method) {
        Ok(Some(path)) => JSValue::string(ctx, &path).raw(),
        Ok(None) | Err(CommonError::Unsupported(_)) => JSValue::null().raw(),
        Err(CommonError::InvalidArgument(message)) => js_throw_type_error(ctx, &message),
        Err(err) => js_throw_internal_error(ctx, &err.to_string()),
    }
}

unsafe fn objc_method_to_js(ctx: *mut ffi::JSContext, method: &ObjcMethodInfo) -> ffi::JSValue {
    let object = JSValue(ffi::JS_NewObject(ctx));
    object.set_property(ctx, "className", JSValue::string(ctx, &method.class_name));
    object.set_property(ctx, "selector", JSValue::string(ctx, &method.selector_name));
    object.set_property(ctx, "imp", create_native_pointer(ctx, method.imp as u64));
    object.set_property(ctx, "typeEncoding", JSValue::string(ctx, &method.type_encoding));
    object.set_property(ctx, "isClassMethod", JSValue::bool(method.is_class_method));
    object.raw()
}

unsafe fn objc_method_detail_to_js(ctx: *mut ffi::JSContext, method: &ObjcMethodDetail) -> ffi::JSValue {
    let object = JSValue(ffi::JS_NewObject(ctx));
    object.set_property(ctx, "className", JSValue::string(ctx, &method.class_name));
    object.set_property(ctx, "selector", JSValue::string(ctx, &method.selector_name));
    object.set_property(
        ctx,
        "methodPointer",
        create_native_pointer(ctx, method.method_pointer as u64),
    );
    object.set_property(ctx, "imp", create_native_pointer(ctx, method.imp as u64));
    object.set_property(ctx, "typeEncoding", JSValue::string(ctx, &method.type_encoding));
    object.set_property(ctx, "isClassMethod", JSValue::bool(method.is_class_method));
    match &method.image_path {
        Some(path) => object.set_property(ctx, "imagePath", JSValue::string(ctx, path)),
        None => object.set_property(ctx, "imagePath", JSValue::null()),
    };
    object.raw()
}

unsafe fn objc_class_info_to_js(ctx: *mut ffi::JSContext, info: &ObjcClassInfo) -> ffi::JSValue {
    let object = JSValue(ffi::JS_NewObject(ctx));
    object.set_property(ctx, "className", JSValue::string(ctx, &info.class_name));
    object.set_property(
        ctx,
        "classPointer",
        create_native_pointer(ctx, info.class_pointer as u64),
    );
    object.set_property(ctx, "isMetaClass", JSValue::bool(info.is_meta_class));
    match &info.superclass_name {
        Some(name) => object.set_property(ctx, "superclassName", JSValue::string(ctx, name)),
        None => object.set_property(ctx, "superclassName", JSValue::null()),
    };
    match info.superclass_pointer {
        Some(pointer) => object.set_property(ctx, "superclassPointer", create_native_pointer(ctx, pointer as u64)),
        None => object.set_property(ctx, "superclassPointer", JSValue::null()),
    };
    object.set_property(
        ctx,
        "instanceSize",
        JSValue(js_u64_to_js_number_or_bigint(ctx, info.instance_size as u64)),
    );
    object.set_property(
        ctx,
        "protocolCount",
        JSValue(js_u64_to_js_number_or_bigint(ctx, info.protocol_count as u64)),
    );
    object.set_property(
        ctx,
        "instancePropertyCount",
        JSValue(js_u64_to_js_number_or_bigint(ctx, info.instance_property_count as u64)),
    );
    object.set_property(
        ctx,
        "classPropertyCount",
        JSValue(js_u64_to_js_number_or_bigint(ctx, info.class_property_count as u64)),
    );
    object.set_property(
        ctx,
        "ivarCount",
        JSValue(js_u64_to_js_number_or_bigint(ctx, info.ivar_count as u64)),
    );
    object.set_property(
        ctx,
        "instanceMethodCount",
        JSValue(js_u64_to_js_number_or_bigint(ctx, info.instance_method_count as u64)),
    );
    object.set_property(
        ctx,
        "classMethodCount",
        JSValue(js_u64_to_js_number_or_bigint(ctx, info.class_method_count as u64)),
    );
    match &info.image_path {
        Some(path) => object.set_property(ctx, "imagePath", JSValue::string(ctx, path)),
        None => object.set_property(ctx, "imagePath", JSValue::null()),
    };
    object.raw()
}

unsafe fn objc_protocol_info_to_js(ctx: *mut ffi::JSContext, info: &ObjcProtocolInfo) -> ffi::JSValue {
    let object = JSValue(ffi::JS_NewObject(ctx));
    object.set_property(ctx, "protocolName", JSValue::string(ctx, &info.protocol_name));
    object.set_property(
        ctx,
        "protocolPointer",
        create_native_pointer(ctx, info.protocol_pointer as u64),
    );
    let adopted_protocols = ffi::JS_NewArray(ctx);
    for (index, name) in info.adopted_protocols.iter().enumerate() {
        ffi::JS_SetPropertyUint32(ctx, adopted_protocols, index as u32, JSValue::string(ctx, name).raw());
    }
    object.set_property(ctx, "adoptedProtocols", JSValue(adopted_protocols));
    object.set_property(
        ctx,
        "requiredInstanceMethodCount",
        JSValue(js_u64_to_js_number_or_bigint(
            ctx,
            info.required_instance_method_count as u64,
        )),
    );
    object.set_property(
        ctx,
        "requiredClassMethodCount",
        JSValue(js_u64_to_js_number_or_bigint(
            ctx,
            info.required_class_method_count as u64,
        )),
    );
    object.set_property(
        ctx,
        "optionalInstanceMethodCount",
        JSValue(js_u64_to_js_number_or_bigint(
            ctx,
            info.optional_instance_method_count as u64,
        )),
    );
    object.set_property(
        ctx,
        "optionalClassMethodCount",
        JSValue(js_u64_to_js_number_or_bigint(
            ctx,
            info.optional_class_method_count as u64,
        )),
    );
    object.set_property(
        ctx,
        "propertyCount",
        JSValue(js_u64_to_js_number_or_bigint(ctx, info.property_count as u64)),
    );
    let total_method_count = info.required_instance_method_count
        + info.required_class_method_count
        + info.optional_instance_method_count
        + info.optional_class_method_count;
    object.set_property(
        ctx,
        "totalMethodCount",
        JSValue(js_u64_to_js_number_or_bigint(ctx, total_method_count as u64)),
    );
    object.set_property(
        ctx,
        "adoptedProtocolCount",
        JSValue(js_u64_to_js_number_or_bigint(ctx, info.adopted_protocols.len() as u64)),
    );
    object.set_property(
        ctx,
        "hasRequiredMethods",
        JSValue::bool((info.required_instance_method_count + info.required_class_method_count) != 0),
    );
    object.set_property(
        ctx,
        "hasOptionalMethods",
        JSValue::bool((info.optional_instance_method_count + info.optional_class_method_count) != 0),
    );
    object.set_property(
        ctx,
        "hasInstanceMethods",
        JSValue::bool((info.required_instance_method_count + info.optional_instance_method_count) != 0),
    );
    object.set_property(
        ctx,
        "hasClassMethods",
        JSValue::bool((info.required_class_method_count + info.optional_class_method_count) != 0),
    );
    object.set_property(ctx, "hasProperties", JSValue::bool(info.property_count != 0));
    object.set_property(
        ctx,
        "hasAdoptedProtocols",
        JSValue::bool(!info.adopted_protocols.is_empty()),
    );
    match &info.image_path {
        Some(path) => object.set_property(ctx, "imagePath", JSValue::string(ctx, path)),
        None => object.set_property(ctx, "imagePath", JSValue::null()),
    };
    object.raw()
}

unsafe fn objc_property_to_js(ctx: *mut ffi::JSContext, property: &ObjcPropertyInfo) -> ffi::JSValue {
    let object = JSValue(ffi::JS_NewObject(ctx));
    object.set_property(ctx, "className", JSValue::string(ctx, &property.class_name));
    object.set_property(ctx, "name", JSValue::string(ctx, &property.property_name));
    object.set_property(ctx, "attributes", JSValue::string(ctx, &property.attributes));
    object.set_property(ctx, "isClassProperty", JSValue::bool(property.is_class_property));
    object.raw()
}

unsafe fn objc_property_detail_to_js(ctx: *mut ffi::JSContext, property: &ObjcPropertyDetail) -> ffi::JSValue {
    let object = JSValue(ffi::JS_NewObject(ctx));
    object.set_property(ctx, "className", JSValue::string(ctx, &property.class_name));
    object.set_property(ctx, "name", JSValue::string(ctx, &property.property_name));
    object.set_property(ctx, "attributes", JSValue::string(ctx, &property.attributes));
    object.set_property(ctx, "isClassProperty", JSValue::bool(property.is_class_property));
    object.set_property(
        ctx,
        "propertyPointer",
        create_native_pointer(ctx, property.property_pointer as u64),
    );
    match &property.image_path {
        Some(path) => object.set_property(ctx, "imagePath", JSValue::string(ctx, path)),
        None => object.set_property(ctx, "imagePath", JSValue::null()),
    };
    object.raw()
}

unsafe fn objc_ivar_to_js(ctx: *mut ffi::JSContext, ivar: &ObjcIvarInfo) -> ffi::JSValue {
    let object = JSValue(ffi::JS_NewObject(ctx));
    object.set_property(ctx, "className", JSValue::string(ctx, &ivar.class_name));
    object.set_property(ctx, "name", JSValue::string(ctx, &ivar.ivar_name));
    object.set_property(ctx, "typeEncoding", JSValue::string(ctx, &ivar.type_encoding));
    object.set_property(
        ctx,
        "offset",
        JSValue(js_u64_to_js_number_or_bigint(ctx, ivar.offset as u64)),
    );
    object.raw()
}

unsafe fn objc_ivar_detail_to_js(ctx: *mut ffi::JSContext, ivar: &ObjcIvarDetail) -> ffi::JSValue {
    let object = JSValue(ffi::JS_NewObject(ctx));
    object.set_property(ctx, "className", JSValue::string(ctx, &ivar.class_name));
    object.set_property(ctx, "name", JSValue::string(ctx, &ivar.ivar_name));
    object.set_property(ctx, "typeEncoding", JSValue::string(ctx, &ivar.type_encoding));
    object.set_property(
        ctx,
        "offset",
        JSValue(js_u64_to_js_number_or_bigint(ctx, ivar.offset as u64)),
    );
    object.set_property(ctx, "ivarPointer", create_native_pointer(ctx, ivar.ivar_pointer as u64));
    match &ivar.image_path {
        Some(path) => object.set_property(ctx, "imagePath", JSValue::string(ctx, path)),
        None => object.set_property(ctx, "imagePath", JSValue::null()),
    };
    object.raw()
}

unsafe fn objc_protocol_method_to_js(ctx: *mut ffi::JSContext, method: &ObjcProtocolMethodInfo) -> ffi::JSValue {
    let object = JSValue(ffi::JS_NewObject(ctx));
    object.set_property(ctx, "protocolName", JSValue::string(ctx, &method.protocol_name));
    object.set_property(ctx, "selector", JSValue::string(ctx, &method.selector_name));
    object.set_property(ctx, "typeEncoding", JSValue::string(ctx, &method.type_encoding));
    object.set_property(ctx, "isRequired", JSValue::bool(method.is_required));
    object.set_property(ctx, "isInstanceMethod", JSValue::bool(method.is_instance_method));
    object.raw()
}

unsafe fn objc_protocol_method_detail_to_js(
    ctx: *mut ffi::JSContext,
    method: &ObjcProtocolMethodDetail,
) -> ffi::JSValue {
    let object = JSValue(ffi::JS_NewObject(ctx));
    object.set_property(ctx, "protocolName", JSValue::string(ctx, &method.protocol_name));
    object.set_property(ctx, "selector", JSValue::string(ctx, &method.selector_name));
    object.set_property(ctx, "typeEncoding", JSValue::string(ctx, &method.type_encoding));
    object.set_property(ctx, "isRequired", JSValue::bool(method.is_required));
    object.set_property(ctx, "isInstanceMethod", JSValue::bool(method.is_instance_method));
    match &method.image_path {
        Some(path) => object.set_property(ctx, "imagePath", JSValue::string(ctx, path)),
        None => object.set_property(ctx, "imagePath", JSValue::null()),
    };
    object.raw()
}

unsafe fn objc_protocol_property_to_js(ctx: *mut ffi::JSContext, property: &ObjcProtocolPropertyInfo) -> ffi::JSValue {
    let object = JSValue(ffi::JS_NewObject(ctx));
    object.set_property(ctx, "protocolName", JSValue::string(ctx, &property.protocol_name));
    object.set_property(ctx, "name", JSValue::string(ctx, &property.property_name));
    object.set_property(ctx, "attributes", JSValue::string(ctx, &property.attributes));
    object.raw()
}

unsafe fn objc_protocol_property_detail_to_js(
    ctx: *mut ffi::JSContext,
    property: &ObjcProtocolPropertyDetail,
) -> ffi::JSValue {
    let object = JSValue(ffi::JS_NewObject(ctx));
    object.set_property(ctx, "protocolName", JSValue::string(ctx, &property.protocol_name));
    object.set_property(ctx, "name", JSValue::string(ctx, &property.property_name));
    object.set_property(ctx, "attributes", JSValue::string(ctx, &property.attributes));
    object.set_property(
        ctx,
        "propertyPointer",
        create_native_pointer(ctx, property.property_pointer as u64),
    );
    match &property.image_path {
        Some(path) => object.set_property(ctx, "imagePath", JSValue::string(ctx, path)),
        None => object.set_property(ctx, "imagePath", JSValue::null()),
    };
    object.raw()
}

unsafe extern "C" fn js_objc_protocol_methods(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let protocol_name = match require_string_arg(
        ctx,
        argc,
        argv,
        0,
        "ObjC.protocolMethods(protocolName[, isRequired[, isInstanceMethod]][, query]) requires 1 string argument",
    ) {
        Ok(value) => value,
        Err(err) => return err,
    };
    let mut is_required = true;
    let mut is_instance_method = true;
    let mut bool_count = 0usize;
    let mut query = None;
    for index in 1..(argc as usize) {
        let value = JSValue(*argv.add(index));
        if value.is_null() || value.is_undefined() {
            continue;
        }
        if value.is_bool() {
            match bool_count {
                0 => is_required = value.to_bool().unwrap_or(true),
                1 => is_instance_method = value.to_bool().unwrap_or(true),
                _ => {
                    return js_throw_type_error(
                        ctx,
                        "ObjC.protocolMethods(protocolName[, isRequired[, isInstanceMethod]][, query]); expected at most two boolean flags before the optional query string",
                    )
                }
            }
            bool_count += 1;
            continue;
        }
        if value.is_string() {
            query = value.to_string(ctx);
            continue;
        }
        return js_throw_type_error(
            ctx,
            "ObjC.protocolMethods(protocolName[, isRequired[, isInstanceMethod]][, query]); expected isRequired/isInstanceMethod to be booleans and query to be a string when provided",
        );
    }

    let methods = match query {
        Some(query) => ObjcApi::new().find_protocol_methods(&protocol_name, &query, is_required, is_instance_method),
        None => ObjcApi::new().protocol_methods(&protocol_name, is_required, is_instance_method),
    };

    let methods = match methods {
        Ok(methods) => methods,
        Err(CommonError::Unsupported(_)) => return ffi::JS_NewArray(ctx),
        Err(CommonError::InvalidArgument(message)) => return js_throw_type_error(ctx, &message),
        Err(err) => return js_throw_internal_error(ctx, &err.to_string()),
    };

    let array = ffi::JS_NewArray(ctx);
    for (index, method) in methods.iter().enumerate() {
        ffi::JS_SetPropertyUint32(ctx, array, index as u32, objc_protocol_method_to_js(ctx, method));
    }
    array
}

unsafe extern "C" fn js_objc_protocol_properties(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let protocol_name = match require_string_arg(
        ctx,
        argc,
        argv,
        0,
        "ObjC.protocolProperties(protocolName[, query]) requires 1 string argument",
    ) {
        Ok(value) => value,
        Err(err) => return err,
    };
    let query = if argc >= 2 {
        match parse_optional_filter_arg(
            ctx,
            JSValue(*argv.add(1)),
            "ObjC.protocolProperties(protocolName[, query]) expected query to be a string when provided",
        ) {
            Ok(value) => value,
            Err(err) => return err,
        }
    } else {
        None
    };

    let properties = match query {
        Some(query) => ObjcApi::new().find_protocol_properties(&protocol_name, &query),
        None => ObjcApi::new().protocol_properties(&protocol_name),
    };

    let properties = match properties {
        Ok(properties) => properties,
        Err(CommonError::Unsupported(_)) => return ffi::JS_NewArray(ctx),
        Err(CommonError::InvalidArgument(message)) => return js_throw_type_error(ctx, &message),
        Err(err) => return js_throw_internal_error(ctx, &err.to_string()),
    };

    let array = ffi::JS_NewArray(ctx);
    for (index, property) in properties.iter().enumerate() {
        ffi::JS_SetPropertyUint32(ctx, array, index as u32, objc_protocol_property_to_js(ctx, property));
    }
    array
}

unsafe extern "C" fn js_objc_protocol_method_info(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let protocol_name = match require_string_arg(
        ctx,
        argc,
        argv,
        0,
        "ObjC.protocolMethodInfo(protocolName, selectorName[, isRequired[, isInstanceMethod]]) requires 2 string arguments",
    ) {
        Ok(value) => value,
        Err(err) => return err,
    };
    let selector_name = match require_string_arg(
        ctx,
        argc,
        argv,
        1,
        "ObjC.protocolMethodInfo(protocolName, selectorName[, isRequired[, isInstanceMethod]]) requires 2 string arguments",
    ) {
        Ok(value) => value,
        Err(err) => return err,
    };
    let is_required = if argc >= 3 {
        JSValue(*argv.add(2)).to_bool().unwrap_or(true)
    } else {
        true
    };
    let is_instance_method = if argc >= 4 {
        JSValue(*argv.add(3)).to_bool().unwrap_or(true)
    } else {
        true
    };

    match ObjcApi::new().protocol_method_info(&protocol_name, &selector_name, is_required, is_instance_method) {
        Ok(Some(info)) => objc_protocol_method_detail_to_js(ctx, &info),
        Ok(None) | Err(CommonError::Unsupported(_)) => JSValue::null().raw(),
        Err(CommonError::InvalidArgument(message)) => js_throw_type_error(ctx, &message),
        Err(err) => js_throw_internal_error(ctx, &err.to_string()),
    }
}

unsafe extern "C" fn js_objc_protocol_property_info(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let protocol_name = match require_string_arg(
        ctx,
        argc,
        argv,
        0,
        "ObjC.protocolPropertyInfo(protocolName, propertyName) requires 2 string arguments",
    ) {
        Ok(value) => value,
        Err(err) => return err,
    };
    let property_name = match require_string_arg(
        ctx,
        argc,
        argv,
        1,
        "ObjC.protocolPropertyInfo(protocolName, propertyName) requires 2 string arguments",
    ) {
        Ok(value) => value,
        Err(err) => return err,
    };

    match ObjcApi::new().protocol_property_info(&protocol_name, &property_name) {
        Ok(Some(info)) => objc_protocol_property_detail_to_js(ctx, &info),
        Ok(None) | Err(CommonError::Unsupported(_)) => JSValue::null().raw(),
        Err(CommonError::InvalidArgument(message)) => js_throw_type_error(ctx, &message),
        Err(err) => js_throw_internal_error(ctx, &err.to_string()),
    }
}

unsafe extern "C" fn js_objc_methods(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let class_name = match require_string_arg(
        ctx,
        argc,
        argv,
        0,
        "ObjC.methods(className[, isClassMethod][, query]) requires 1 string argument",
    ) {
        Ok(value) => value,
        Err(err) => return err,
    };
    let (is_class_method, query) = match parse_objc_bool_and_query_args(
        ctx,
        argc,
        argv,
        1,
        "isClassMethod",
        "ObjC.methods(className[, isClassMethod][, query])",
    ) {
        Ok(value) => value,
        Err(err) => return err,
    };

    let methods = match query {
        Some(query) => ObjcApi::new().find_methods(&class_name, &query, is_class_method),
        None => ObjcApi::new().enumerate_methods(&class_name, is_class_method),
    };

    let methods = match methods {
        Ok(methods) => methods,
        Err(CommonError::Unsupported(_)) => return ffi::JS_NewArray(ctx),
        Err(CommonError::InvalidArgument(message)) => return js_throw_type_error(ctx, &message),
        Err(err) => return js_throw_internal_error(ctx, &err.to_string()),
    };

    let array = ffi::JS_NewArray(ctx);
    for (index, method) in methods.iter().enumerate() {
        ffi::JS_SetPropertyUint32(ctx, array, index as u32, objc_method_to_js(ctx, method));
    }
    array
}

unsafe extern "C" fn js_objc_find_methods(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let class_name = match require_string_arg(
        ctx,
        argc,
        argv,
        0,
        "ObjC.findMethods(className, query[, isClassMethod]) requires 2 string arguments",
    ) {
        Ok(value) => value,
        Err(err) => return err,
    };
    let query = match require_string_arg(
        ctx,
        argc,
        argv,
        1,
        "ObjC.findMethods(className, query[, isClassMethod]) requires 2 string arguments",
    ) {
        Ok(value) => value,
        Err(err) => return err,
    };
    let is_class_method = if argc >= 3 {
        JSValue(*argv.add(2)).to_bool().unwrap_or(false)
    } else {
        false
    };

    let methods = match ObjcApi::new().find_methods(&class_name, &query, is_class_method) {
        Ok(methods) => methods,
        Err(CommonError::Unsupported(_)) => return ffi::JS_NewArray(ctx),
        Err(CommonError::InvalidArgument(message)) => return js_throw_type_error(ctx, &message),
        Err(err) => return js_throw_internal_error(ctx, &err.to_string()),
    };

    let array = ffi::JS_NewArray(ctx);
    for (index, method) in methods.iter().enumerate() {
        ffi::JS_SetPropertyUint32(ctx, array, index as u32, objc_method_to_js(ctx, method));
    }
    array
}

unsafe extern "C" fn js_objc_properties(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let class_name = match require_string_arg(
        ctx,
        argc,
        argv,
        0,
        "ObjC.properties(className[, isClassProperty][, query]) requires 1 string argument",
    ) {
        Ok(value) => value,
        Err(err) => return err,
    };
    let (is_class_property, query) = match parse_objc_bool_and_query_args(
        ctx,
        argc,
        argv,
        1,
        "isClassProperty",
        "ObjC.properties(className[, isClassProperty][, query])",
    ) {
        Ok(value) => value,
        Err(err) => return err,
    };

    let properties = match query {
        Some(query) => ObjcApi::new().find_properties(&class_name, &query, is_class_property),
        None => ObjcApi::new().enumerate_properties(&class_name, is_class_property),
    };

    let properties = match properties {
        Ok(properties) => properties,
        Err(CommonError::Unsupported(_)) => return ffi::JS_NewArray(ctx),
        Err(CommonError::InvalidArgument(message)) => return js_throw_type_error(ctx, &message),
        Err(err) => return js_throw_internal_error(ctx, &err.to_string()),
    };

    let array = ffi::JS_NewArray(ctx);
    for (index, property) in properties.iter().enumerate() {
        ffi::JS_SetPropertyUint32(ctx, array, index as u32, objc_property_to_js(ctx, property));
    }
    array
}

unsafe extern "C" fn js_objc_find_properties(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let class_name = match require_string_arg(
        ctx,
        argc,
        argv,
        0,
        "ObjC.findProperties(className, query[, isClassProperty]) requires 2 string arguments",
    ) {
        Ok(value) => value,
        Err(err) => return err,
    };
    let query = match require_string_arg(
        ctx,
        argc,
        argv,
        1,
        "ObjC.findProperties(className, query[, isClassProperty]) requires 2 string arguments",
    ) {
        Ok(value) => value,
        Err(err) => return err,
    };
    let is_class_property = if argc >= 3 {
        JSValue(*argv.add(2)).to_bool().unwrap_or(false)
    } else {
        false
    };

    let properties = match ObjcApi::new().find_properties(&class_name, &query, is_class_property) {
        Ok(properties) => properties,
        Err(CommonError::Unsupported(_)) => return ffi::JS_NewArray(ctx),
        Err(CommonError::InvalidArgument(message)) => return js_throw_type_error(ctx, &message),
        Err(err) => return js_throw_internal_error(ctx, &err.to_string()),
    };

    let array = ffi::JS_NewArray(ctx);
    for (index, property) in properties.iter().enumerate() {
        ffi::JS_SetPropertyUint32(ctx, array, index as u32, objc_property_to_js(ctx, property));
    }
    array
}

unsafe extern "C" fn js_objc_ivars(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let class_name = match require_string_arg(
        ctx,
        argc,
        argv,
        0,
        "ObjC.ivars(className[, query]) requires 1 string argument",
    ) {
        Ok(value) => value,
        Err(err) => return err,
    };
    let query = if argc >= 2 {
        match parse_optional_filter_arg(
            ctx,
            JSValue(*argv.add(1)),
            "ObjC.ivars(className[, query]) expected query to be a string when provided",
        ) {
            Ok(value) => value,
            Err(err) => return err,
        }
    } else {
        None
    };

    let ivars = match query {
        Some(query) => ObjcApi::new().find_ivars(&class_name, &query),
        None => ObjcApi::new().enumerate_ivars(&class_name),
    };

    let ivars = match ivars {
        Ok(ivars) => ivars,
        Err(CommonError::Unsupported(_)) => return ffi::JS_NewArray(ctx),
        Err(CommonError::InvalidArgument(message)) => return js_throw_type_error(ctx, &message),
        Err(err) => return js_throw_internal_error(ctx, &err.to_string()),
    };

    let array = ffi::JS_NewArray(ctx);
    for (index, ivar) in ivars.iter().enumerate() {
        ffi::JS_SetPropertyUint32(ctx, array, index as u32, objc_ivar_to_js(ctx, ivar));
    }
    array
}

unsafe extern "C" fn js_objc_find_ivars(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let class_name = match require_string_arg(
        ctx,
        argc,
        argv,
        0,
        "ObjC.findIvars(className, query) requires 2 string arguments",
    ) {
        Ok(value) => value,
        Err(err) => return err,
    };
    let query = match require_string_arg(
        ctx,
        argc,
        argv,
        1,
        "ObjC.findIvars(className, query) requires 2 string arguments",
    ) {
        Ok(value) => value,
        Err(err) => return err,
    };

    let ivars = match ObjcApi::new().find_ivars(&class_name, &query) {
        Ok(ivars) => ivars,
        Err(CommonError::Unsupported(_)) => return ffi::JS_NewArray(ctx),
        Err(CommonError::InvalidArgument(message)) => return js_throw_type_error(ctx, &message),
        Err(err) => return js_throw_internal_error(ctx, &err.to_string()),
    };

    let array = ffi::JS_NewArray(ctx);
    for (index, ivar) in ivars.iter().enumerate() {
        ffi::JS_SetPropertyUint32(ctx, array, index as u32, objc_ivar_to_js(ctx, ivar));
    }
    array
}

unsafe extern "C" fn js_objc_find_method_owners(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let query = match require_string_arg(
        ctx,
        argc,
        argv,
        0,
        "ObjC.findMethodOwners(query[, isClassMethod]) requires 1 string argument",
    ) {
        Ok(value) => value,
        Err(err) => return err,
    };
    let is_class_method = if argc >= 2 {
        JSValue(*argv.add(1)).to_bool().unwrap_or(false)
    } else {
        false
    };

    let methods = match ObjcApi::new().find_method_owners(&query, is_class_method) {
        Ok(methods) => methods,
        Err(CommonError::Unsupported(_)) => return ffi::JS_NewArray(ctx),
        Err(CommonError::InvalidArgument(message)) => return js_throw_type_error(ctx, &message),
        Err(err) => return js_throw_internal_error(ctx, &err.to_string()),
    };

    let array = ffi::JS_NewArray(ctx);
    for (index, method) in methods.iter().enumerate() {
        ffi::JS_SetPropertyUint32(ctx, array, index as u32, objc_method_to_js(ctx, method));
    }
    array
}

unsafe extern "C" fn js_objc_selector_name(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 1 {
        return js_throw_type_error(ctx, "ObjC.selectorName(selector) requires 1 selector argument");
    }

    let selector = match pointer_arg_to_u64(
        ctx,
        JSValue(*argv),
        "ObjC.selectorName(selector) expected a pointer-like selector argument",
    ) {
        Ok(value) => value,
        Err(err) => return err,
    };

    match ObjcApi::new().selector_name(selector as usize) {
        Ok(Some(name)) => JSValue::string(ctx, &name).raw(),
        Ok(None) | Err(CommonError::Unsupported(_)) => JSValue::null().raw(),
        Err(CommonError::InvalidArgument(message)) => js_throw_type_error(ctx, &message),
        Err(err) => js_throw_internal_error(ctx, &err.to_string()),
    }
}

unsafe extern "C" fn js_objc_object_class_name(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 1 {
        return js_throw_type_error(ctx, "ObjC.objectClassName(object) requires 1 object argument");
    }

    let object = match pointer_arg_to_u64(
        ctx,
        JSValue(*argv),
        "ObjC.objectClassName(object) expected a pointer-like object argument",
    ) {
        Ok(value) => value,
        Err(err) => return err,
    };

    match ObjcApi::new().object_class_name(object as usize) {
        Ok(Some(name)) => JSValue::string(ctx, &name).raw(),
        Ok(None) | Err(CommonError::Unsupported(_)) => JSValue::null().raw(),
        Err(CommonError::InvalidArgument(message)) => js_throw_type_error(ctx, &message),
        Err(err) => js_throw_internal_error(ctx, &err.to_string()),
    }
}

pub(crate) fn register_objc_api(ctx: &JSContext) -> Result<(), String> {
    let global = ctx.global_object();
    let objc = ctx.new_object();
    let api = ObjcApi::new();

    objc.set_property(ctx.as_ptr(), "available", JSValue::bool(api.is_available()));

    unsafe {
        let ctx_ptr = ctx.as_ptr();
        add_cfunction_to_object(ctx_ptr, objc.raw(), "classes", js_objc_classes, 1);
        add_cfunction_to_object(ctx_ptr, objc.raw(), "findClasses", js_objc_find_classes, 1);
        add_cfunction_to_object(ctx_ptr, objc.raw(), "chooseSync", js_objc_choose_sync, 2);
        add_cfunction_to_object(ctx_ptr, objc.raw(), "choose", js_objc_choose, 3);
        add_cfunction_to_object(ctx_ptr, objc.raw(), "protocols", js_objc_protocols, 1);
        add_cfunction_to_object(ctx_ptr, objc.raw(), "findProtocols", js_objc_find_protocols, 1);
        add_cfunction_to_object(ctx_ptr, objc.raw(), "classProtocols", js_objc_class_protocols, 1);
        add_cfunction_to_object(ctx_ptr, objc.raw(), "findClassProtocols", js_objc_class_protocols, 2);
        add_cfunction_to_object(ctx_ptr, objc.raw(), "protocolOwners", js_objc_protocol_owners, 1);
        add_cfunction_to_object(ctx_ptr, objc.raw(), "findProtocolOwners", js_objc_protocol_owners, 2);
        add_cfunction_to_object(ctx_ptr, objc.raw(), "protocolInfo", js_objc_protocol_info, 1);
        add_cfunction_to_object(ctx_ptr, objc.raw(), "findProtocolInfo", js_objc_protocol_info, 1);
        add_cfunction_to_object(ctx_ptr, objc.raw(), "protocolProtocols", js_objc_protocol_protocols, 1);
        add_cfunction_to_object(
            ctx_ptr,
            objc.raw(),
            "findProtocolProtocols",
            js_objc_protocol_protocols,
            2,
        );
        add_cfunction_to_object(ctx_ptr, objc.raw(), "protocolMethods", js_objc_protocol_methods, 3);
        add_cfunction_to_object(ctx_ptr, objc.raw(), "findProtocolMethods", js_objc_protocol_methods, 4);
        add_cfunction_to_object(
            ctx_ptr,
            objc.raw(),
            "protocolMethodInfo",
            js_objc_protocol_method_info,
            4,
        );
        add_cfunction_to_object(
            ctx_ptr,
            objc.raw(),
            "findProtocolMethodInfo",
            js_objc_protocol_method_info,
            4,
        );
        add_cfunction_to_object(
            ctx_ptr,
            objc.raw(),
            "protocolProperties",
            js_objc_protocol_properties,
            1,
        );
        add_cfunction_to_object(
            ctx_ptr,
            objc.raw(),
            "findProtocolProperties",
            js_objc_protocol_properties,
            2,
        );
        add_cfunction_to_object(
            ctx_ptr,
            objc.raw(),
            "protocolPropertyInfo",
            js_objc_protocol_property_info,
            2,
        );
        add_cfunction_to_object(
            ctx_ptr,
            objc.raw(),
            "findProtocolPropertyInfo",
            js_objc_protocol_property_info,
            2,
        );
        add_cfunction_to_object(ctx_ptr, objc.raw(), "superclass", js_objc_superclass, 1);
        add_cfunction_to_object(ctx_ptr, objc.raw(), "findSuperclass", js_objc_superclass, 1);
        add_cfunction_to_object(ctx_ptr, objc.raw(), "classChain", js_objc_class_chain, 1);
        add_cfunction_to_object(ctx_ptr, objc.raw(), "findClassChain", js_objc_class_chain, 1);
        add_cfunction_to_object(ctx_ptr, objc.raw(), "classInfo", js_objc_class_info, 2);
        add_cfunction_to_object(ctx_ptr, objc.raw(), "findClassInfo", js_objc_class_info, 2);
        add_cfunction_to_object(ctx_ptr, objc.raw(), "classExists", js_objc_class_exists, 1);
        add_cfunction_to_object(ctx_ptr, objc.raw(), "findClassExists", js_objc_class_exists, 1);
        add_cfunction_to_object(ctx_ptr, objc.raw(), "protocolExists", js_objc_protocol_exists, 1);
        add_cfunction_to_object(ctx_ptr, objc.raw(), "findProtocolExists", js_objc_protocol_exists, 1);
        add_cfunction_to_object(ctx_ptr, objc.raw(), "classConforms", js_objc_class_conforms, 2);
        add_cfunction_to_object(ctx_ptr, objc.raw(), "findClassConforms", js_objc_class_conforms, 2);
        add_cfunction_to_object(ctx_ptr, objc.raw(), "protocolConforms", js_objc_protocol_conforms, 2);
        add_cfunction_to_object(
            ctx_ptr,
            objc.raw(),
            "findProtocolConforms",
            js_objc_protocol_conforms,
            2,
        );
        add_cfunction_to_object(ctx_ptr, objc.raw(), "selector", js_objc_selector, 1);
        add_cfunction_to_object(ctx_ptr, objc.raw(), "findSelector", js_objc_selector, 1);
        add_cfunction_to_object(ctx_ptr, objc.raw(), "methodImp", js_objc_method_imp, 3);
        add_cfunction_to_object(ctx_ptr, objc.raw(), "findMethodImp", js_objc_method_imp, 3);
        add_cfunction_to_object(ctx_ptr, objc.raw(), "methodInfo", js_objc_method_info, 3);
        add_cfunction_to_object(ctx_ptr, objc.raw(), "findMethodInfo", js_objc_method_info, 3);
        add_cfunction_to_object(ctx_ptr, objc.raw(), "classImage", js_objc_class_image, 1);
        add_cfunction_to_object(ctx_ptr, objc.raw(), "findClassImage", js_objc_class_image, 1);
        add_cfunction_to_object(ctx_ptr, objc.raw(), "protocolImage", js_objc_protocol_image, 1);
        add_cfunction_to_object(ctx_ptr, objc.raw(), "findProtocolImage", js_objc_protocol_image, 1);
        add_cfunction_to_object(ctx_ptr, objc.raw(), "propertyInfo", js_objc_property_info, 3);
        add_cfunction_to_object(ctx_ptr, objc.raw(), "findPropertyInfo", js_objc_property_info, 3);
        add_cfunction_to_object(ctx_ptr, objc.raw(), "ivarInfo", js_objc_ivar_info, 2);
        add_cfunction_to_object(ctx_ptr, objc.raw(), "findIvarInfo", js_objc_ivar_info, 2);
        add_cfunction_to_object(ctx_ptr, objc.raw(), "methodImage", js_objc_method_image, 3);
        add_cfunction_to_object(ctx_ptr, objc.raw(), "findMethodImage", js_objc_method_image, 3);
        add_cfunction_to_object(ctx_ptr, objc.raw(), "methods", js_objc_methods, 2);
        add_cfunction_to_object(ctx_ptr, objc.raw(), "findMethods", js_objc_find_methods, 3);
        add_cfunction_to_object(ctx_ptr, objc.raw(), "properties", js_objc_properties, 2);
        add_cfunction_to_object(ctx_ptr, objc.raw(), "findProperties", js_objc_find_properties, 3);
        add_cfunction_to_object(ctx_ptr, objc.raw(), "ivars", js_objc_ivars, 1);
        add_cfunction_to_object(ctx_ptr, objc.raw(), "findIvars", js_objc_find_ivars, 2);
        add_cfunction_to_object(ctx_ptr, objc.raw(), "findMethodOwners", js_objc_find_method_owners, 2);
        add_cfunction_to_object(ctx_ptr, objc.raw(), "methodOwners", js_objc_find_method_owners, 2);
        add_cfunction_to_object(ctx_ptr, objc.raw(), "selectorName", js_objc_selector_name, 1);
        add_cfunction_to_object(ctx_ptr, objc.raw(), "findSelectorName", js_objc_selector_name, 1);
        add_cfunction_to_object(ctx_ptr, objc.raw(), "objectClassName", js_objc_object_class_name, 1);
        add_cfunction_to_object(ctx_ptr, objc.raw(), "findObjectClassName", js_objc_object_class_name, 1);
    }

    register_objc_object_api(ctx, objc.raw())?;

    global.set_property(ctx.as_ptr(), "ObjC", objc);
    global.free(ctx.as_ptr());
    Ok(())
}
