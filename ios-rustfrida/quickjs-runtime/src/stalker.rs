use crate::context::JSContext;
use crate::ffi;
use crate::util::{
    add_cfunction_to_object, js_throw_internal_error, js_throw_range_error, js_throw_type_error,
    js_u64_to_js_number_or_bigint, set_js_u64_property,
};
use crate::value::JSValue;
use native_api::{
    current_stalker_thread_id, ios_stalker_capabilities, stalker_backend_status, stalker_event_sink,
    stalker_flush_thread, stalker_follow_thread, stalker_garbage_collect_thread, stalker_unfollow_thread,
    StalkerConfig, StalkerEvent, StalkerEventMask, StalkerRange, StalkerSession, StalkerSessionState,
};

const DEFAULT_TRANSFORM_MAX_INSTRUCTIONS: usize = 256;
const MAX_TRANSFORM_INSTRUCTIONS: usize = 4096;
const DEFAULT_GENERATED_EVENT_CAPACITY: usize = 4096;
const MAX_GENERATED_EVENT_CAPACITY: usize = 1_000_000;

fn stalker_error(ctx: *mut ffi::JSContext, error: common::Error) -> ffi::JSValue {
    match error {
        common::Error::InvalidArgument(message) => js_throw_type_error(ctx, &message),
        other => js_throw_internal_error(ctx, &other.to_string()),
    }
}

unsafe fn js_thread_id(
    ctx: *mut ffi::JSContext,
    argc: i32,
    argv: *mut ffi::JSValue,
    index: usize,
) -> Result<u64, ffi::JSValue> {
    if argc <= index as i32 {
        let current = current_stalker_thread_id();
        if current == 0 {
            return Err(js_throw_internal_error(ctx, "failed to resolve current pthread id"));
        }
        return Ok(current);
    }
    let value = JSValue(*argv.add(index));
    let parsed = if value.is_string() {
        let text = value.to_string(ctx).unwrap_or_default();
        let text = text.trim();
        if let Some(hex) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
            u64::from_str_radix(hex, 16).ok()
        } else {
            text.parse::<u64>().ok()
        }
    } else {
        value.to_u64(ctx)
    };
    match parsed.filter(|thread_id| *thread_id != 0) {
        Some(thread_id) => Ok(thread_id),
        None => Err(js_throw_type_error(
            ctx,
            "Stalker thread id must be a non-zero integer or string",
        )),
    }
}

unsafe fn js_options_config(
    ctx: *mut ffi::JSContext,
    argc: i32,
    argv: *mut ffi::JSValue,
    index: usize,
) -> Result<StalkerConfig, ffi::JSValue> {
    if argc <= index as i32 {
        return Ok(StalkerConfig::default());
    }
    let options = JSValue(*argv.add(index));
    if options.is_undefined() || options.is_null() {
        return Ok(StalkerConfig::default());
    }
    if !options.is_object() {
        return Err(js_throw_type_error(ctx, "Stalker.follow options must be an object"));
    }

    let mut config = StalkerConfig::default();
    let event_mask = options.get_property(ctx, "events");
    if !event_mask.is_undefined() && !event_mask.is_null() {
        let bits = event_mask
            .to_u64(ctx)
            .and_then(|value| u32::try_from(value).ok())
            .ok_or_else(|| js_throw_type_error(ctx, "Stalker.follow options.events must be a 32-bit mask"))?;
        config.event_mask = StalkerEventMask::from_bits(bits);
    }
    let queue_capacity = options.get_property(ctx, "queueCapacity");
    if !queue_capacity.is_undefined() {
        config.queue_capacity = queue_capacity
            .to_u64(ctx)
            .and_then(|value| usize::try_from(value).ok())
            .ok_or_else(|| js_throw_type_error(ctx, "Stalker.follow options.queueCapacity must be an integer"))?;
    }
    let trust_threshold = options.get_property(ctx, "trustThreshold");
    if !trust_threshold.is_undefined() {
        config.trust_threshold = trust_threshold
            .to_i64(ctx)
            .and_then(|value| i32::try_from(value).ok())
            .ok_or_else(|| js_throw_type_error(ctx, "Stalker.follow options.trustThreshold must be an int32"))?;
    }
    let ranges = options.get_property(ctx, "exclude");
    if !ranges.is_undefined() && !ranges.is_null() {
        let length = ranges.get_property(ctx, "length").to_u64(ctx).unwrap_or(0);
        for index in 0..length {
            let item = JSValue(ffi::JS_GetPropertyUint32(ctx, ranges.raw(), index as u32));
            let start = item.get_property(ctx, "start").to_u64(ctx);
            let end = item.get_property(ctx, "end").to_u64(ctx);
            let (Some(start), Some(end)) = (start, end) else {
                item.free(ctx);
                return Err(js_throw_type_error(
                    ctx,
                    "Stalker.follow options.exclude entries need start/end",
                ));
            };
            let range = StalkerRange::new(start, end).map_err(|error| stalker_error(ctx, error))?;
            config.exclude_ranges.push(range);
            item.free(ctx);
        }
    }
    Ok(config)
}

unsafe fn js_nonnegative_u64(ctx: *mut ffi::JSContext, value: JSValue, usage: &str) -> Result<u64, ffi::JSValue> {
    if value.is_string() {
        let text = value.to_string(ctx).unwrap_or_default();
        let text = text.trim();
        let parsed = if let Some(hex) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
            u64::from_str_radix(hex, 16).ok()
        } else {
            text.parse::<u64>().ok()
        };
        return parsed.ok_or_else(|| js_throw_type_error(ctx, usage));
    }

    if value.is_int() || value.is_float() {
        let Some(number) = value.to_float() else {
            return Err(js_throw_type_error(ctx, usage));
        };
        if !number.is_finite() || number < 0.0 || number.fract() != 0.0 || number > u64::MAX as f64 {
            return Err(js_throw_type_error(ctx, usage));
        }
        return Ok(number as u64);
    }

    if ffi::qjs_is_big_int(ctx, value.raw()) != 0 {
        let text = value.to_string(ctx).unwrap_or_default();
        if text.trim_start().starts_with('-') {
            return Err(js_throw_type_error(ctx, usage));
        }
        return text.trim().parse::<u64>().map_err(|_| js_throw_type_error(ctx, usage));
    }

    Err(js_throw_type_error(ctx, usage))
}

unsafe fn js_byte_input(ctx: *mut ffi::JSContext, value: JSValue) -> Result<Vec<u8>, ffi::JSValue> {
    if !value.is_object() {
        return Err(js_throw_type_error(
            ctx,
            "Stalker.transform bytes must be an array-like object",
        ));
    }
    let length_value = value.get_property(ctx, "length");
    let length = js_nonnegative_u64(
        ctx,
        length_value,
        "Stalker.transform bytes length must be a non-negative integer",
    )
    .and_then(|length| {
        usize::try_from(length).map_err(|_| js_throw_range_error(ctx, "Stalker.transform bytes length is too large"))
    });
    length_value.free(ctx);
    let length = length?;
    if length == 0 || length % 4 != 0 {
        return Err(js_throw_type_error(
            ctx,
            "Stalker.transform bytes must contain complete ARM64 instructions",
        ));
    }
    if length / 4 > MAX_TRANSFORM_INSTRUCTIONS {
        return Err(js_throw_range_error(
            ctx,
            "Stalker.transform input exceeds the bounded instruction limit",
        ));
    }

    let mut bytes = Vec::with_capacity(length);
    for index in 0..length {
        let item = JSValue(ffi::JS_GetPropertyUint32(ctx, value.raw(), index as u32));
        let byte = match js_nonnegative_u64(ctx, item, "Stalker.transform bytes must contain integer bytes") {
            Ok(byte) if byte <= u8::MAX as u64 => byte as u8,
            Ok(_) => {
                item.free(ctx);
                return Err(js_throw_type_error(
                    ctx,
                    "Stalker.transform byte must be between 0 and 255",
                ));
            }
            Err(error) => {
                item.free(ctx);
                return Err(error);
            }
        };
        item.free(ctx);
        bytes.push(byte);
    }
    Ok(bytes)
}

unsafe fn js_transform_options(
    ctx: *mut ffi::JSContext,
    value: Option<JSValue>,
) -> Result<(StalkerEventMask, usize, usize), ffi::JSValue> {
    let Some(options) = value else {
        return Ok((
            StalkerEventMask::default(),
            DEFAULT_TRANSFORM_MAX_INSTRUCTIONS,
            DEFAULT_GENERATED_EVENT_CAPACITY,
        ));
    };
    if options.is_undefined() || options.is_null() {
        return Ok((
            StalkerEventMask::default(),
            DEFAULT_TRANSFORM_MAX_INSTRUCTIONS,
            DEFAULT_GENERATED_EVENT_CAPACITY,
        ));
    }
    if !options.is_object() {
        return Err(js_throw_type_error(ctx, "Stalker transform options must be an object"));
    }

    let event_value = options.get_property(ctx, "events");
    let event_mask = if event_value.is_undefined() || event_value.is_null() {
        StalkerEventMask::default()
    } else {
        let bits = js_nonnegative_u64(ctx, event_value, "Stalker transform events must be a 32-bit mask")?;
        if bits > u32::MAX as u64 {
            event_value.free(ctx);
            return Err(js_throw_type_error(
                ctx,
                "Stalker transform events must be a 32-bit mask",
            ));
        }
        StalkerEventMask::from_bits(bits as u32)
    };
    event_value.free(ctx);

    let max_instructions_value = options.get_property(ctx, "maxInstructions");
    let max_instructions = if max_instructions_value.is_undefined() || max_instructions_value.is_null() {
        DEFAULT_TRANSFORM_MAX_INSTRUCTIONS
    } else {
        let value = js_nonnegative_u64(
            ctx,
            max_instructions_value,
            "Stalker transform maxInstructions must be an integer",
        )?;
        usize::try_from(value)
            .map_err(|_| js_throw_range_error(ctx, "Stalker transform maxInstructions is too large"))?
    };
    max_instructions_value.free(ctx);
    if max_instructions == 0 || max_instructions > MAX_TRANSFORM_INSTRUCTIONS {
        return Err(js_throw_range_error(
            ctx,
            "Stalker transform maxInstructions must be between 1 and 4096",
        ));
    }

    let max_events_value = options.get_property(ctx, "maxEvents");
    let max_events = if max_events_value.is_undefined() || max_events_value.is_null() {
        DEFAULT_GENERATED_EVENT_CAPACITY
    } else {
        let value = js_nonnegative_u64(ctx, max_events_value, "Stalker transform maxEvents must be an integer")?;
        usize::try_from(value).map_err(|_| js_throw_range_error(ctx, "Stalker transform maxEvents is too large"))?
    };
    max_events_value.free(ctx);
    if max_events == 0 || max_events > MAX_GENERATED_EVENT_CAPACITY {
        return Err(js_throw_range_error(
            ctx,
            "Stalker transform maxEvents must be between 1 and 1000000",
        ));
    }

    Ok((event_mask, max_instructions, max_events))
}

unsafe fn js_execution_steps(ctx: *mut ffi::JSContext, value: JSValue) -> Result<Vec<(u64, u64, i32)>, ffi::JSValue> {
    if value.is_undefined() || value.is_null() {
        return Ok(Vec::new());
    }
    if !value.is_object() {
        return Err(js_throw_type_error(
            ctx,
            "Stalker execution trace must be an array-like object",
        ));
    }
    let length_value = value.get_property(ctx, "length");
    let length =
        js_nonnegative_u64(ctx, length_value, "Stalker execution trace length must be an integer").and_then(|length| {
            usize::try_from(length)
                .map_err(|_| js_throw_range_error(ctx, "Stalker execution trace length is too large"))
        });
    length_value.free(ctx);
    let length = length?;
    if length > MAX_GENERATED_EVENT_CAPACITY {
        return Err(js_throw_range_error(
            ctx,
            "Stalker execution trace exceeds the bounded event limit",
        ));
    }

    let mut steps = Vec::with_capacity(length);
    for index in 0..length {
        let item = JSValue(ffi::JS_GetPropertyUint32(ctx, value.raw(), index as u32));
        let (address, target, depth) = if item.is_object() {
            let address_value = item.get_property(ctx, "address");
            let address = js_nonnegative_u64(ctx, address_value, "Stalker execution step needs an address");
            address_value.free(ctx);
            let address = match address {
                Ok(address) => address,
                Err(error) => {
                    item.free(ctx);
                    return Err(error);
                }
            };

            let target_value = item.get_property(ctx, "target");
            let target = if target_value.is_undefined() || target_value.is_null() {
                0
            } else {
                match js_nonnegative_u64(ctx, target_value, "Stalker execution step target must be an integer") {
                    Ok(target) => target,
                    Err(error) => {
                        target_value.free(ctx);
                        item.free(ctx);
                        return Err(error);
                    }
                }
            };
            target_value.free(ctx);

            let depth_value = item.get_property(ctx, "depth");
            let depth = if depth_value.is_undefined() || depth_value.is_null() {
                0
            } else {
                match depth_value.to_i64(ctx).and_then(|depth| i32::try_from(depth).ok()) {
                    Some(depth) => depth,
                    None => {
                        depth_value.free(ctx);
                        item.free(ctx);
                        return Err(js_throw_type_error(ctx, "Stalker execution step depth must be int32"));
                    }
                }
            };
            depth_value.free(ctx);
            (address, target, depth)
        } else {
            let address = match js_nonnegative_u64(ctx, item, "Stalker execution step needs an address") {
                Ok(address) => address,
                Err(error) => {
                    item.free(ctx);
                    return Err(error);
                }
            };
            (address, 0, 0)
        };
        item.free(ctx);
        steps.push((address, target, depth));
    }
    Ok(steps)
}

unsafe fn stalker_thread_status_to_js(
    ctx: *mut ffi::JSContext,
    status: &native_api::StalkerThreadStatus,
) -> ffi::JSValue {
    let result = JSValue(ffi::JS_NewObject(ctx));
    set_js_u64_property(ctx, result.raw(), "threadId", status.thread_id);
    result.set_property(
        ctx,
        "state",
        JSValue::string(
            ctx,
            match status.state {
                StalkerSessionState::Idle => "idle",
                StalkerSessionState::Following => "following",
                StalkerSessionState::Deactivated => "deactivated",
            },
        ),
    );
    result.set_property(ctx, "mode", JSValue::string(ctx, "event-sink-only"));
    result.set_property(ctx, "staticOnly", JSValue::bool(false));
    result.set_property(ctx, "instrumented", JSValue::bool(false));
    result.set_property(ctx, "targetThreadInstrumented", JSValue::bool(false));
    result.set_property(ctx, "targetThreadInstructionRewrite", JSValue::bool(false));
    result.set_property(ctx, "queuedEvents", JSValue::int(status.queued_events as i32));
    set_js_u64_property(ctx, result.raw(), "droppedEvents", status.dropped_events);
    result.raw()
}

unsafe fn stalker_status_to_js(ctx: *mut ffi::JSContext) -> ffi::JSValue {
    let status = stalker_backend_status();
    let result = JSValue(ffi::JS_NewObject(ctx));
    result.set_property(ctx, "backend", JSValue::string(ctx, status.backend));
    result.set_property(ctx, "mode", JSValue::string(ctx, status.mode));
    result.set_property(ctx, "active", JSValue::bool(status.active));
    result.set_property(ctx, "staticOnly", JSValue::bool(false));
    result.set_property(ctx, "instrumented", JSValue::bool(false));
    result.set_property(ctx, "targetThreadInstrumented", JSValue::bool(false));
    result.set_property(ctx, "targetThreadInstructionRewrite", JSValue::bool(false));
    result.set_property(ctx, "sessionCount", JSValue::int(status.session_count as i32));
    let threads = ffi::JS_NewArray(ctx);
    for (index, thread) in status.threads.iter().enumerate() {
        ffi::JS_SetPropertyUint32(ctx, threads, index as u32, stalker_thread_status_to_js(ctx, thread));
    }
    result.set_property(ctx, "threads", JSValue(threads));
    result.raw()
}

unsafe extern "C" fn js_stalker_thread_id(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let thread_id = current_stalker_thread_id();
    if thread_id == 0 {
        return js_throw_internal_error(ctx, "failed to resolve current pthread id");
    }
    crate::util::js_u64_to_js_number_or_bigint(ctx, thread_id)
}

unsafe extern "C" fn js_stalker_follow(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let thread_index = if argc > 0 && JSValue(*argv).is_object() {
        None
    } else {
        Some(0)
    };
    let thread_id = match thread_index {
        Some(index) => match js_thread_id(ctx, argc, argv, index) {
            Ok(value) => value,
            Err(error) => return error,
        },
        None => match js_thread_id(ctx, 0, std::ptr::null_mut(), 0) {
            Ok(value) => value,
            Err(error) => return error,
        },
    };
    let options_index = if thread_index.is_some() { 1 } else { 0 };
    let config = match js_options_config(ctx, argc, argv, options_index) {
        Ok(config) => config,
        Err(error) => return error,
    };
    match stalker_follow_thread(thread_id, config) {
        Ok(status) => stalker_thread_status_to_js(ctx, &status),
        Err(error) => stalker_error(ctx, error),
    }
}

unsafe extern "C" fn js_stalker_unfollow(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let thread_id = match js_thread_id(ctx, argc, argv, 0) {
        Ok(value) => value,
        Err(error) => return error,
    };
    match stalker_unfollow_thread(thread_id) {
        Ok(status) => stalker_thread_status_to_js(ctx, &status),
        Err(error) => stalker_error(ctx, error),
    }
}

unsafe fn stalker_event_to_js(ctx: *mut ffi::JSContext, event: &StalkerEvent) -> ffi::JSValue {
    let result = JSValue(ffi::JS_NewObject(ctx));
    result.set_property(ctx, "type", JSValue::string(ctx, event.kind().as_str()));
    match event {
        StalkerEvent::Call {
            location,
            target,
            depth,
        }
        | StalkerEvent::Ret {
            location,
            target,
            depth,
        } => {
            set_js_u64_property(ctx, result.raw(), "location", *location);
            set_js_u64_property(ctx, result.raw(), "target", *target);
            result.set_property(ctx, "depth", JSValue::int(*depth));
        }
        StalkerEvent::Exec { location } => set_js_u64_property(ctx, result.raw(), "location", *location),
        StalkerEvent::Block { start, end } | StalkerEvent::Compile { start, end } => {
            set_js_u64_property(ctx, result.raw(), "start", *start);
            set_js_u64_property(ctx, result.raw(), "end", *end);
        }
    }
    result.raw()
}

unsafe fn stalker_capabilities_to_js_detailed(ctx: *mut ffi::JSContext) -> ffi::JSValue {
    let capabilities = ios_stalker_capabilities();
    let result = JSValue(ffi::JS_NewObject(ctx));
    result.set_property(ctx, "platform", JSValue::string(ctx, capabilities.platform));
    result.set_property(ctx, "backend", JSValue::string(ctx, capabilities.backend));
    result.set_property(ctx, "mode", JSValue::string(ctx, capabilities.mode));
    result.set_property(ctx, "available", JSValue::bool(capabilities.available));
    result.set_property(ctx, "instructionLevel", JSValue::bool(capabilities.instruction_level));
    result.set_property(ctx, "basicBlockEvents", JSValue::bool(capabilities.basic_block_events));
    result.set_property(ctx, "eventSink", JSValue::bool(capabilities.event_sink));
    result.set_property(ctx, "threadFollow", JSValue::bool(capabilities.thread_follow));
    result.set_property(
        ctx,
        "targetFunctionHook",
        JSValue::bool(capabilities.target_function_hook),
    );
    result.set_property(ctx, "callReturnHook", JSValue::bool(capabilities.call_return_hook));
    result.set_property(ctx, "excludeRanges", JSValue::bool(capabilities.exclude_ranges));
    result.set_property(ctx, "flush", JSValue::bool(capabilities.flush));
    result.set_property(ctx, "garbageCollect", JSValue::bool(capabilities.garbage_collect));
    result.set_property(
        ctx,
        "memoryAccessEvents",
        JSValue::bool(capabilities.memory_access_events),
    );
    result.set_property(ctx, "staticParse", JSValue::bool(capabilities.static_parse));
    result.set_property(
        ctx,
        "boundedBasicBlockTransform",
        JSValue::bool(capabilities.bounded_basic_block_transform),
    );
    result.set_property(ctx, "eventGeneration", JSValue::bool(capabilities.event_generation));
    result.set_property(
        ctx,
        "eventGenerationMode",
        JSValue::string(ctx, capabilities.event_generation_mode),
    );
    result.set_property(ctx, "transformMode", JSValue::string(ctx, capabilities.transform_mode));
    result.set_property(
        ctx,
        "targetThreadInstrumentation",
        JSValue::bool(capabilities.target_thread_instrumentation),
    );
    result.set_property(
        ctx,
        "targetThreadInstructionRewrite",
        JSValue::bool(capabilities.target_thread_instruction_rewrite),
    );
    result.set_property(ctx, "instrumented", JSValue::bool(capabilities.instrumented));
    let missing_operations: Vec<String> = capabilities
        .missing_operations
        .iter()
        .map(|item| (*item).to_string())
        .collect();
    let missing = ffi::JS_NewArray(ctx);
    for (index, item) in missing_operations.iter().enumerate() {
        ffi::JS_SetPropertyUint32(ctx, missing, index as u32, JSValue::string(ctx, item).raw());
    }
    result.set_property(ctx, "missingOperations", JSValue(missing));
    result.raw()
}

unsafe extern "C" fn js_stalker_transform_capabilities(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    stalker_capabilities_to_js_detailed(ctx)
}

unsafe fn stalker_transform_to_js(
    ctx: *mut ffi::JSContext,
    start: u64,
    input_byte_count: usize,
    max_instructions: usize,
    event_mask: StalkerEventMask,
    transformed: (
        Vec<(u64, u32, &'static str, Option<u64>)>,
        u64,
        usize,
        usize,
        bool,
        bool,
        Option<&'static str>,
    ),
) -> ffi::JSValue {
    let (
        instructions,
        end,
        input_instruction_count,
        instruction_count,
        limit_reached,
        stopped_at_terminator,
        terminator,
    ) = transformed;
    let result = JSValue(ffi::JS_NewObject(ctx));
    result.set_property(ctx, "api", JSValue::string(ctx, "Stalker"));
    result.set_property(ctx, "backend", JSValue::string(ctx, "arm64-bounded-transform-plan"));
    result.set_property(ctx, "source", JSValue::string(ctx, "bounded-basic-block-transform"));
    result.set_property(ctx, "mode", JSValue::string(ctx, "static-only"));
    result.set_property(ctx, "staticOnly", JSValue::bool(true));
    result.set_property(ctx, "instrumented", JSValue::bool(false));
    result.set_property(ctx, "executionObserved", JSValue::bool(false));
    result.set_property(ctx, "targetThreadInstrumented", JSValue::bool(false));
    result.set_property(ctx, "targetThreadInstructionRewrite", JSValue::bool(false));
    result.set_property(ctx, "rewritesTargetMemory", JSValue::bool(false));
    result.set_property(ctx, "bounded", JSValue::bool(true));
    set_js_u64_property(ctx, result.raw(), "start", start);
    set_js_u64_property(ctx, result.raw(), "end", end);
    result.set_property(
        ctx,
        "inputByteCount",
        JSValue(js_u64_to_js_number_or_bigint(ctx, input_byte_count as u64)),
    );
    result.set_property(
        ctx,
        "inputInstructionCount",
        JSValue(js_u64_to_js_number_or_bigint(ctx, input_instruction_count as u64)),
    );
    result.set_property(
        ctx,
        "instructionCount",
        JSValue(js_u64_to_js_number_or_bigint(ctx, instruction_count as u64)),
    );
    result.set_property(
        ctx,
        "maxInstructions",
        JSValue(js_u64_to_js_number_or_bigint(ctx, max_instructions as u64)),
    );
    result.set_property(ctx, "limitReached", JSValue::bool(limit_reached));
    result.set_property(ctx, "stoppedAtTerminator", JSValue::bool(stopped_at_terminator));
    match terminator {
        Some(value) => result.set_property(ctx, "terminator", JSValue::string(ctx, value)),
        None => result.set_property(ctx, "terminator", JSValue::null()),
    };

    let instruction_array = ffi::JS_NewArray(ctx);
    let points_array = ffi::JS_NewArray(ctx);
    let mut point_index = 0u32;
    for (index, (address, word, kind, direct_target)) in instructions.iter().enumerate() {
        let instruction = JSValue(ffi::JS_NewObject(ctx));
        set_js_u64_property(ctx, instruction.raw(), "address", *address);
        set_js_u64_property(ctx, instruction.raw(), "word", *word as u64);
        instruction.set_property(ctx, "kind", JSValue::string(ctx, kind));
        instruction.set_property(ctx, "kept", JSValue::bool(true));
        instruction.set_property(
            ctx,
            "terminatesBlock",
            JSValue::bool(matches!(
                *kind,
                "b" | "b.cond" | "cbz/cbnz" | "tbz/tbnz" | "br" | "ret" | "exception"
            )),
        );
        match direct_target {
            Some(target) => {
                set_js_u64_property(ctx, instruction.raw(), "directTarget", *target);
            }
            None => {
                instruction.set_property(ctx, "directTarget", JSValue::null());
            }
        };
        ffi::JS_SetPropertyUint32(ctx, instruction_array, index as u32, instruction.raw());

        if event_mask.contains(native_api::StalkerEventKind::Exec) {
            let point = JSValue(ffi::JS_NewObject(ctx));
            point.set_property(ctx, "type", JSValue::string(ctx, "exec"));
            set_js_u64_property(ctx, point.raw(), "location", *address);
            point.set_property(ctx, "instructionIndex", JSValue::int(index as i32));
            ffi::JS_SetPropertyUint32(ctx, points_array, point_index, point.raw());
            point_index = point_index.saturating_add(1);
        }
        if (*kind == "bl" || *kind == "blr") && event_mask.contains(native_api::StalkerEventKind::Call) {
            let point = JSValue(ffi::JS_NewObject(ctx));
            point.set_property(ctx, "type", JSValue::string(ctx, "call"));
            set_js_u64_property(ctx, point.raw(), "location", *address);
            match direct_target {
                Some(target) => {
                    set_js_u64_property(ctx, point.raw(), "target", *target);
                }
                None => {
                    point.set_property(ctx, "target", JSValue::null());
                }
            };
            point.set_property(ctx, "instructionIndex", JSValue::int(index as i32));
            ffi::JS_SetPropertyUint32(ctx, points_array, point_index, point.raw());
            point_index = point_index.saturating_add(1);
        }
        if *kind == "ret" && event_mask.contains(native_api::StalkerEventKind::Ret) {
            let point = JSValue(ffi::JS_NewObject(ctx));
            point.set_property(ctx, "type", JSValue::string(ctx, "ret"));
            set_js_u64_property(ctx, point.raw(), "location", *address);
            point.set_property(ctx, "instructionIndex", JSValue::int(index as i32));
            ffi::JS_SetPropertyUint32(ctx, points_array, point_index, point.raw());
            point_index = point_index.saturating_add(1);
        }
    }
    if event_mask.contains(native_api::StalkerEventKind::Block) {
        let point = JSValue(ffi::JS_NewObject(ctx));
        point.set_property(ctx, "type", JSValue::string(ctx, "block"));
        set_js_u64_property(ctx, point.raw(), "start", start);
        set_js_u64_property(ctx, point.raw(), "end", end);
        point.set_property(ctx, "requiresExecution", JSValue::bool(true));
        ffi::JS_SetPropertyUint32(ctx, points_array, point_index, point.raw());
        point_index = point_index.saturating_add(1);
    }
    if event_mask.contains(native_api::StalkerEventKind::Compile) {
        let point = JSValue(ffi::JS_NewObject(ctx));
        point.set_property(ctx, "type", JSValue::string(ctx, "compile"));
        set_js_u64_property(ctx, point.raw(), "start", start);
        set_js_u64_property(ctx, point.raw(), "end", end);
        point.set_property(ctx, "requiresExecution", JSValue::bool(false));
        ffi::JS_SetPropertyUint32(ctx, points_array, point_index, point.raw());
    }
    result.set_property(ctx, "instructions", JSValue(instruction_array));
    result.set_property(ctx, "instrumentationPoints", JSValue(points_array));
    result.raw()
}

unsafe fn stalker_generation_to_js(
    ctx: *mut ffi::JSContext,
    transform: ffi::JSValue,
    events: &[StalkerEvent],
    attempted_events: usize,
    dropped_events: usize,
    execution_observed: bool,
    max_events: usize,
) -> ffi::JSValue {
    let result = JSValue(transform);
    result.set_property(ctx, "backend", JSValue::string(ctx, "arm64-bounded-event-generator"));
    result.set_property(
        ctx,
        "source",
        JSValue::string(ctx, "bounded-basic-block-event-generation"),
    );
    result.set_property(ctx, "mode", JSValue::string(ctx, "event-generation"));
    result.set_property(ctx, "staticOnly", JSValue::bool(false));
    result.set_property(ctx, "instrumented", JSValue::bool(false));
    result.set_property(ctx, "executionObserved", JSValue::bool(execution_observed));
    result.set_property(ctx, "targetThreadInstrumented", JSValue::bool(false));
    result.set_property(ctx, "targetThreadInstructionRewrite", JSValue::bool(false));
    result.set_property(
        ctx,
        "eventGenerationMode",
        JSValue::string(ctx, "caller-supplied-execution-trace"),
    );
    result.set_property(
        ctx,
        "attemptedEvents",
        JSValue(js_u64_to_js_number_or_bigint(ctx, attempted_events as u64)),
    );
    result.set_property(
        ctx,
        "generatedEvents",
        JSValue(js_u64_to_js_number_or_bigint(ctx, events.len() as u64)),
    );
    result.set_property(
        ctx,
        "droppedEvents",
        JSValue(js_u64_to_js_number_or_bigint(ctx, dropped_events as u64)),
    );
    result.set_property(
        ctx,
        "maxEvents",
        JSValue(js_u64_to_js_number_or_bigint(ctx, max_events as u64)),
    );
    let array = ffi::JS_NewArray(ctx);
    for (index, event) in events.iter().enumerate() {
        ffi::JS_SetPropertyUint32(ctx, array, index as u32, stalker_event_to_js(ctx, event));
    }
    result.set_property(ctx, "events", JSValue(array));
    result.raw()
}

unsafe extern "C" fn js_stalker_transform(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 2 {
        return js_throw_type_error(ctx, "Stalker.transform(bytes, start, options) requires bytes and start");
    }
    let bytes = match js_byte_input(ctx, JSValue(*argv)) {
        Ok(bytes) => bytes,
        Err(error) => return error,
    };
    let start = match js_nonnegative_u64(ctx, JSValue(*argv.add(1)), "Stalker.transform start must be an address") {
        Ok(start) => start,
        Err(error) => return error,
    };
    let options = if argc > 2 { Some(JSValue(*argv.add(2))) } else { None };
    let (event_mask, max_instructions, _) = match js_transform_options(ctx, options) {
        Ok(options) => options,
        Err(error) => return error,
    };
    let transformed = match StalkerSession::transform_basic_block(start, &bytes, max_instructions) {
        Ok(transformed) => transformed,
        Err(error) => return stalker_error(ctx, error),
    };
    stalker_transform_to_js(ctx, start, bytes.len(), max_instructions, event_mask, transformed)
}

unsafe extern "C" fn js_stalker_generate_events(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 3 {
        return js_throw_type_error(
            ctx,
            "Stalker.generateEvents(bytes, start, execution, options) requires bytes, start and execution",
        );
    }
    let bytes = match js_byte_input(ctx, JSValue(*argv)) {
        Ok(bytes) => bytes,
        Err(error) => return error,
    };
    let start = match js_nonnegative_u64(
        ctx,
        JSValue(*argv.add(1)),
        "Stalker.generateEvents start must be an address",
    ) {
        Ok(start) => start,
        Err(error) => return error,
    };
    let execution = match js_execution_steps(ctx, JSValue(*argv.add(2))) {
        Ok(execution) => execution,
        Err(error) => return error,
    };
    let options = if argc > 3 { Some(JSValue(*argv.add(3))) } else { None };
    let (event_mask, max_instructions, max_events) = match js_transform_options(ctx, options) {
        Ok(options) => options,
        Err(error) => return error,
    };
    let transformed = match StalkerSession::transform_basic_block(start, &bytes, max_instructions) {
        Ok(transformed) => transformed,
        Err(error) => return stalker_error(ctx, error),
    };
    let generated = match StalkerSession::generate_basic_block_events(
        start,
        &bytes,
        max_instructions,
        &execution,
        event_mask,
        max_events,
    ) {
        Ok(generated) => generated,
        Err(error) => return stalker_error(ctx, error),
    };
    let transform_value = stalker_transform_to_js(ctx, start, bytes.len(), max_instructions, event_mask, transformed);
    stalker_generation_to_js(
        ctx,
        transform_value,
        &generated.0,
        generated.1,
        generated.2,
        generated.3,
        max_events,
    )
}

unsafe extern "C" fn js_stalker_flush(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let thread_id = match js_thread_id(ctx, argc, argv, 0) {
        Ok(value) => value,
        Err(error) => return error,
    };
    let events = match stalker_flush_thread(thread_id) {
        Ok(events) => events,
        Err(error) => return stalker_error(ctx, error),
    };
    let array = ffi::JS_NewArray(ctx);
    for (index, event) in events.iter().enumerate() {
        ffi::JS_SetPropertyUint32(ctx, array, index as u32, stalker_event_to_js(ctx, event));
    }
    array
}

unsafe extern "C" fn js_stalker_garbage_collect(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let thread_id = match js_thread_id(ctx, argc, argv, 0) {
        Ok(value) => value,
        Err(error) => return error,
    };
    match stalker_garbage_collect_thread(thread_id) {
        Ok(result) => JSValue::bool(result).raw(),
        Err(error) => stalker_error(ctx, error),
    }
}

unsafe extern "C" fn js_stalker_status(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    stalker_status_to_js(ctx)
}

unsafe extern "C" fn js_stalker_record_event(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 2 {
        return js_throw_type_error(ctx, "Native.stalkerRecordEvent(thread, event) requires two arguments");
    }
    let thread_id = match js_thread_id(ctx, argc, argv, 0) {
        Ok(value) => value,
        Err(error) => return error,
    };
    let input = JSValue(*argv.add(1));
    let kind = input.get_property(ctx, "type").to_string(ctx).unwrap_or_default();
    let event = match kind.as_str() {
        "call" | "ret" => {
            let location = input.get_property(ctx, "location").to_u64(ctx);
            let target = input.get_property(ctx, "target").to_u64(ctx);
            let depth = input
                .get_property(ctx, "depth")
                .to_i64(ctx)
                .and_then(|value| i32::try_from(value).ok());
            match (location, target, depth) {
                (Some(location), Some(target), Some(depth)) if kind == "call" => StalkerEvent::Call {
                    location,
                    target,
                    depth,
                },
                (Some(location), Some(target), Some(depth)) => StalkerEvent::Ret {
                    location,
                    target,
                    depth,
                },
                _ => return js_throw_type_error(ctx, "call/ret event needs location, target and int32 depth"),
            }
        }
        "exec" => match input.get_property(ctx, "location").to_u64(ctx) {
            Some(location) => StalkerEvent::Exec { location },
            None => return js_throw_type_error(ctx, "exec event needs location"),
        },
        "block" | "compile" => {
            let start = input.get_property(ctx, "start").to_u64(ctx);
            let end = input.get_property(ctx, "end").to_u64(ctx);
            match (start, end) {
                (Some(start), Some(end)) if kind == "block" => StalkerEvent::Block { start, end },
                (Some(start), Some(end)) => StalkerEvent::Compile { start, end },
                _ => return js_throw_type_error(ctx, "block/compile event needs start and end"),
            }
        }
        _ => return js_throw_type_error(ctx, "event type must be call, ret, exec, block or compile"),
    };
    match stalker_event_sink(thread_id, event) {
        Ok(recorded) => JSValue::bool(recorded).raw(),
        Err(error) => stalker_error(ctx, error),
    }
}

const STALKER_BOOTSTRAP: &str = r#"
globalThis.Stalker = globalThis.Stalker || (function() {
    const missingOperations = [
        'Transformer',
        'target-thread Transformer',
        'target-thread Exec/Block/Compile events',
        'memory access events'
    ];

    const captureState = {
        enabled: false,
        maxEvents: 4096,
        events: [],
        dropped: 0
    };

    function addressNumber(value) {
        let result;
        if (typeof value === 'bigint') {
            result = Number(value);
        } else if (typeof value === 'string') {
            result = Number(value.trim());
        } else {
            result = Number(value);
        }
        if (!Number.isSafeInteger(result) || result < 0) {
            throw new TypeError('ARM64 address must be a non-negative safe integer');
        }
        return result;
    }

    function hexAddress(value) {
        return '0x' + value.toString(16);
    }

    function readByteInput(input) {
        if (input === null || input === undefined || input.length === undefined) {
            throw new TypeError('Stalker.parse(bytes, start) requires an array-like byte input');
        }
        const length = Number(input.length);
        if (!Number.isSafeInteger(length) || length <= 0 || length % 4 !== 0) {
            throw new TypeError('ARM64 byte input must contain one or more complete instructions');
        }
        const bytes = [];
        for (let i = 0; i < length; i++) {
            const value = Number(input[i]);
            if (!Number.isInteger(value) || value < 0 || value > 255) {
                throw new TypeError('ARM64 byte input contains a value outside 0..255');
            }
            bytes.push(value);
        }
        return bytes;
    }

    function signExtend(value, bits) {
        const boundary = Math.pow(2, bits - 1);
        const modulus = Math.pow(2, bits);
        return value >= boundary ? value - modulus : value;
    }

    function decodeWord(address, word) {
        const uword = word >>> 0;
        let kind = 'other';
        let directTarget = null;
        if (((uword & 0xfffffc1f) >>> 0) === 0xd65f0000) {
            kind = 'ret';
        } else if (((uword & 0xfffffc1f) >>> 0) === 0xd61f0000) {
            kind = 'br';
        } else if (((uword & 0xfffffc1f) >>> 0) === 0xd63f0000) {
            kind = 'blr';
        } else if (uword === 0xd69f03e0 || uword === 0xd6bf03e0 || ((uword & 0xffe0001f) >>> 0) === 0xd4000001) {
            kind = 'exception';
        } else if (((uword & 0xfc000000) >>> 0) === 0x94000000) {
            kind = 'bl';
            directTarget = address + signExtend(uword & 0x03ffffff, 26) * 4;
        } else if (((uword & 0x7c000000) >>> 0) === 0x14000000) {
            kind = 'b';
            directTarget = address + signExtend(uword & 0x03ffffff, 26) * 4;
        } else if (((uword & 0xff000010) >>> 0) === 0x54000000) {
            kind = 'b.cond';
            directTarget = address + signExtend((uword >>> 5) & 0x0007ffff, 19) * 4;
        } else if (((uword & 0x7f000000) >>> 0) === 0x34000000) {
            kind = 'cbz/cbnz';
            directTarget = address + signExtend((uword >>> 5) & 0x0007ffff, 19) * 4;
        } else if (((uword & 0x7f000000) >>> 0) === 0x36000000) {
            kind = 'tbz/tbnz';
            directTarget = address + signExtend((uword >>> 5) & 0x00003fff, 14) * 4;
        }
        return {
            address: hexAddress(address),
            word: '0x' + uword.toString(16).padStart(8, '0'),
            kind,
            directTarget: directTarget === null ? null : hexAddress(directTarget),
            terminatesBlock: ['b', 'b.cond', 'cbz/cbnz', 'tbz/tbnz', 'br', 'ret', 'exception'].indexOf(kind) !== -1
        };
    }

    function parseArm64(bytesInput, startInput, options) {
        const start = addressNumber(startInput === undefined ? 0 : startInput);
        if (start % 4 !== 0) {
            throw new TypeError('ARM64 start address must be 4-byte aligned');
        }
        const bytes = readByteInput(bytesInput);
        const requested = options && options.maxInstructions !== undefined
            ? Number(options.maxInstructions)
            : bytes.length / 4;
        if (!Number.isSafeInteger(requested) || requested <= 0) {
            throw new TypeError('ARM64 maxInstructions must be a positive integer');
        }
        const limit = Math.min(requested, bytes.length / 4);
        const instructions = [];
        const blocks = [];
        let blockStart = start;
        for (let index = 0; index < limit; index++) {
            const offset = index * 4;
            const word = (bytes[offset] | (bytes[offset + 1] << 8) | (bytes[offset + 2] << 16) | (bytes[offset + 3] << 24)) >>> 0;
            const address = start + offset;
            const instruction = decodeWord(address, word);
            instructions.push(instruction);
            if (instruction.terminatesBlock) {
                blocks.push({
                    start: hexAddress(blockStart),
                    end: hexAddress(address + 4),
                    terminator: instruction.kind
                });
                blockStart = address + 4;
            }
        }
        if (blockStart < start + limit * 4) {
            blocks.push({
                start: hexAddress(blockStart),
                end: hexAddress(start + limit * 4),
                terminator: null
            });
        }
        return {
            api: 'Stalker',
            backend: 'arm64-static-decoder',
            source: 'static-decode',
            mode: 'static-only',
            staticOnly: true,
            instrumented: false,
            executionObserved: false,
            targetThreadInstrumented: false,
            targetThreadInstructionRewrite: false,
            start: hexAddress(start),
            end: hexAddress(start + limit * 4),
            instructionCount: instructions.length,
            instructions,
            blocks
        };
    }

    function captureLog(args) {
        if (!captureState.enabled) {
            return;
        }
        let message = '';
        for (let i = 0; i < args.length; i++) {
            if (i !== 0) message += ' ';
            message += String(args[i]);
        }
        if (message.indexOf('[stalker] ') !== 0) {
            return;
        }
        const body = message.slice(10);
        const match = body.match(/^( *)(->|<-) (.*)$/);
        if (!match) {
            return;
        }
        const depth = Math.floor(match[1].length / 2);
        const event = {
            type: match[2] === '->' ? 'call' : 'ret',
            depth,
            label: match[3],
            raw: message
        };
        if (captureState.events.length >= captureState.maxEvents) {
            captureState.dropped++;
            return;
        }
        captureState.events.push(event);
    }

    function captureStatus() {
        return {
            active: captureState.enabled,
            count: captureState.events.length,
            dropped: captureState.dropped,
            maxEvents: captureState.maxEvents,
            source: 'function-level-hook-log',
            instructionLevel: false
        };
    }

    function captureStart(options) {
        const maxEvents = options && options.maxEvents !== undefined ? Number(options.maxEvents) : 4096;
        if (!Number.isSafeInteger(maxEvents) || maxEvents <= 0 || maxEvents > 1000000) {
            throw new TypeError('Stalker.captureStart maxEvents must be between 1 and 1000000');
        }
        captureState.maxEvents = maxEvents;
        captureState.events = [];
        captureState.dropped = 0;
        captureState.enabled = true;
        return captureStatus();
    }

    function captureStop() {
        captureState.enabled = false;
        return captureStatus();
    }

    function captureFlush() {
        const events = captureState.events.slice();
        captureState.events = [];
        return events;
    }

    if (globalThis.console && typeof globalThis.console.log === 'function') {
        const originalConsoleLog = globalThis.console.log;
        globalThis.console.log = function() {
            captureLog(arguments);
            return originalConsoleLog.apply(this, arguments);
        };
    }

    function capabilities() {
        const native = globalThis.Native && typeof globalThis.Native.stalkerTransformCapabilities === 'function'
            ? globalThis.Native.stalkerTransformCapabilities()
            : globalThis.Native && typeof globalThis.Native.stalkerCapabilities === 'function'
                ? globalThis.Native.stalkerCapabilities()
            : {
                platform: 'ios',
                backend: 'apple-pthread-event-sink',
                mode: 'thread-follow-event-sink',
                available: true,
                instructionLevel: false,
                basicBlockEvents: false,
                eventSink: true,
                threadFollow: true,
                targetFunctionHook: true,
                callReturnHook: true,
                excludeRanges: true,
                flush: true,
                garbageCollect: true,
                memoryAccessEvents: false,
                staticDecoder: true,
                functionLevelEventCapture: true,
                dynamicInstructionEvents: false,
                staticParse: true,
                boundedBasicBlockTransform: true,
                eventGeneration: true,
                eventGenerationMode: 'caller-supplied-execution-trace',
                transformMode: 'static-only',
                targetThreadInstrumentation: false,
                targetThreadInstructionRewrite: false,
                instrumented: false,
                missingOperations: missingOperations
            };
        return Object.assign({}, native, {
            api: 'Stalker',
            androidReference: 'Frida Gum Stalker',
            functionLevelFallback: native.targetFunctionHook === true,
            instructionLevel: native.instructionLevel === true,
            staticDecoder: true,
            functionLevelEventCapture: true,
            dynamicInstructionEvents: native.dynamicInstructionEvents === true,
            staticParse: native.staticParse === true,
            boundedBasicBlockTransform: native.boundedBasicBlockTransform === true,
            eventGeneration: native.eventGeneration === true,
            eventGenerationMode: native.eventGenerationMode || null,
            transformMode: native.transformMode || 'static-only',
            targetThreadInstrumentation: native.targetThreadInstrumentation === true,
            targetThreadInstructionRewrite: native.targetThreadInstructionRewrite === true,
            instrumented: native.instrumented === true,
            missingOperations: Array.isArray(native.missingOperations)
                ? native.missingOperations.slice()
                : missingOperations.slice()
        });
    }

    function nativeStalker() {
        if (!globalThis.Native) {
            throw new Error('Stalker native backend is not registered');
        }
        return globalThis.Native;
    }

    function threadId(value) {
        if (value === undefined || value === null) {
            return nativeStalker().stalkerThreadId();
        }
        return value;
    }

    function follow(threadOrOptions, maybeOptions) {
        const hasThread = threadOrOptions !== undefined &&
            (typeof threadOrOptions !== 'object' || threadOrOptions === null);
        const thread = hasThread ? threadOrOptions : undefined;
        const options = hasThread ? (maybeOptions || {}) : (threadOrOptions || {});
        return nativeStalker().stalkerFollow(threadId(thread), options);
    }

    function unfollow(thread) {
        return nativeStalker().stalkerUnfollow(threadId(thread));
    }

    function flush(thread) {
        return nativeStalker().stalkerFlush(threadId(thread));
    }

    function garbageCollect(thread) {
        return nativeStalker().stalkerGarbageCollect(threadId(thread));
    }

    function exclude(range) {
        if (range === undefined || range === null || range.start === undefined || range.end === undefined) {
            throw new TypeError('Stalker.exclude(range) requires {start, end}; pass it in follow options.exclude');
        }
        return {start: range.start, end: range.end};
    }

    function recordEvent(thread, event) {
        if (event === undefined) {
            event = thread;
            thread = undefined;
        }
        return nativeStalker().stalkerRecordEvent(threadId(thread), event);
    }

    function transform(bytes, start, options) {
        if (start === undefined) {
            start = 0;
        }
        return nativeStalker().stalkerTransform(bytes, start, options || {});
    }

    function generateEvents(bytes, start, execution, options) {
        if (start === undefined) {
            start = 0;
        }
        if (execution === undefined || execution === null) {
            execution = [];
        }
        return nativeStalker().stalkerGenerateEvents(bytes, start, execution, options || {});
    }

    function recordBlock(thread, bytes, start, execution, options) {
        const generated = generateEvents(bytes, start, execution, options);
        const targetThread = threadId(thread);
        let accepted = 0;
        let notQueued = 0;
        for (let index = 0; index < generated.events.length; index++) {
            if (nativeStalker().stalkerRecordEvent(targetThread, generated.events[index])) {
                accepted++;
            } else {
                notQueued++;
            }
        }
        return Object.assign({}, generated, {
            mode: 'event-sink-only',
            staticOnly: false,
            instrumented: false,
            targetThreadInstrumented: false,
            submittedEvents: generated.events.length,
            acceptedEvents: accepted,
            notQueuedEvents: notQueued
        });
    }

    function fallbackStatus() {
        return {
            active: false,
            count: 0,
            sessionCount: 0,
            sessions: [],
            currentKey: null,
            currentSession: null,
            message: 'stalker inactive'
        };
    }

    function status() {
        let state = fallbackStatus();
        const helper = globalThis.__iosRustFridaNativeHooks;
        const native = globalThis.Native;
        if (native && typeof native.stalkerStatus === 'function') {
            try {
                state = native.stalkerStatus();
            } catch (_) {
                state = fallbackStatus();
            }
        }
        if (helper && typeof helper.currentStalkerStateResult === 'function') {
            try {
                state = helper.currentStalkerStateResult();
            } catch (_) {
                state = fallbackStatus();
            }
        }
        return Object.assign({}, state, {
            api: 'Stalker',
            backend: capabilities().backend,
            mode: capabilities().mode,
            staticOnly: false,
            instrumented: false,
            targetThreadInstrumented: false,
            targetThreadInstructionRewrite: false,
            capabilities: capabilities(),
            eventCapture: captureStatus()
        });
    }

    function stopFunctionLevelFallback() {
        const native = globalThis.Native;
        if (native && typeof native.stalkerStatus === 'function') {
            const current = native.stalkerStatus();
            if (current.active && Array.isArray(current.threads)) {
                const currentThread = native.stalkerThreadId();
                const ownsCurrentThread = current.threads.some(function (entry) {
                    return entry && String(entry.threadId) === String(currentThread) && entry.state === 'following';
                });
                if (ownsCurrentThread) {
                    return native.stalkerUnfollow(currentThread);
                }
            }
        }
        const helper = globalThis.__iosRustFridaNativeHooks;
        if (!helper || typeof helper.stopStalkerResult !== 'function') {
            return fallbackStatus();
        }
        return helper.stopStalkerResult();
    }

    return {
        available: true,
        platform: 'ios',
        backend: 'apple-pthread-event-sink',
        androidReference: 'Frida Gum Stalker',
        capabilities: capabilities,
        status: status,
        info: status,
        lastError: function() { return null; },
        follow: follow,
        unfollow: unfollow,
        exclude: exclude,
        flush: flush,
        garbageCollect: garbageCollect,
        recordEvent: recordEvent,
        parse: parseArm64,
        transform: transform,
        transformBasicBlock: transform,
        generateEvents: generateEvents,
        recordBlock: recordBlock,
        captureStart: captureStart,
        captureStop: captureStop,
        captureStatus: captureStatus,
        captureFlush: captureFlush,
        stop: stopFunctionLevelFallback,
        functionLevelStatus: status,
        functionLevelStop: stopFunctionLevelFallback
    };
})();
"#;

pub(crate) fn register_stalker_api(ctx: &JSContext) -> Result<(), String> {
    let native = ctx.get_global_property("Native");
    if native.is_object() {
        unsafe {
            add_cfunction_to_object(ctx.as_ptr(), native.raw(), "stalkerThreadId", js_stalker_thread_id, 0);
            add_cfunction_to_object(ctx.as_ptr(), native.raw(), "stalkerFollow", js_stalker_follow, 2);
            add_cfunction_to_object(ctx.as_ptr(), native.raw(), "stalkerUnfollow", js_stalker_unfollow, 1);
            add_cfunction_to_object(ctx.as_ptr(), native.raw(), "stalkerFlush", js_stalker_flush, 1);
            add_cfunction_to_object(
                ctx.as_ptr(),
                native.raw(),
                "stalkerGarbageCollect",
                js_stalker_garbage_collect,
                1,
            );
            add_cfunction_to_object(ctx.as_ptr(), native.raw(), "stalkerStatus", js_stalker_status, 0);
            add_cfunction_to_object(
                ctx.as_ptr(),
                native.raw(),
                "stalkerRecordEvent",
                js_stalker_record_event,
                2,
            );
            add_cfunction_to_object(
                ctx.as_ptr(),
                native.raw(),
                "stalkerTransformCapabilities",
                js_stalker_transform_capabilities,
                0,
            );
            add_cfunction_to_object(ctx.as_ptr(), native.raw(), "stalkerTransform", js_stalker_transform, 3);
            add_cfunction_to_object(
                ctx.as_ptr(),
                native.raw(),
                "stalkerGenerateEvents",
                js_stalker_generate_events,
                4,
            );
        }
    }
    native.free(ctx.as_ptr());
    let value = ctx.eval(STALKER_BOOTSTRAP, "<stalker-api>")?;
    value.free(ctx.as_ptr());
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::runtime::QuickJsRuntime;
    use std::sync::Mutex;

    fn test_lock() -> &'static Mutex<()> {
        crate::runtime::test_runtime_lock()
    }

    #[test]
    fn public_stalker_surface_reports_instruction_backend_boundary() {
        let _guard = test_lock().lock().unwrap_or_else(|e| e.into_inner());
        let mut runtime = QuickJsRuntime::new();
        runtime.initialize().expect("init runtime");
        assert_eq!(runtime.eval("typeof Stalker.follow").unwrap(), "function");
        assert_eq!(
            runtime.eval("Stalker.capabilities().instructionLevel").unwrap(),
            "false"
        );
        assert_eq!(runtime.eval("Stalker.capabilities().threadFollow").unwrap(), "true");
        assert_eq!(runtime.eval("Stalker.capabilities().eventSink").unwrap(), "true");
        assert_eq!(runtime.eval("Stalker.status().api").unwrap(), "Stalker");
        assert!(runtime.eval("Stalker.follow(1).state").is_ok());
        assert!(runtime.eval("Stalker.unfollow(1).state").is_ok());
    }

    #[test]
    fn function_level_fallback_can_be_stopped_without_claiming_follow_support() {
        let _guard = test_lock().lock().unwrap_or_else(|e| e.into_inner());
        let mut runtime = QuickJsRuntime::new();
        runtime.initialize().expect("init runtime");
        assert_eq!(runtime.eval("Stalker.functionLevelStop().active").unwrap(), "false");
        assert_eq!(runtime.eval("Stalker.capabilities().threadFollow").unwrap(), "true");
    }

    #[test]
    fn registration_exposes_status_function() {
        let _guard = test_lock().lock().unwrap_or_else(|e| e.into_inner());
        let mut runtime = QuickJsRuntime::new();
        runtime.initialize().expect("init runtime");
        assert_eq!(runtime.eval("typeof Stalker.status").unwrap(), "function");
    }

    #[test]
    fn parse_exposes_arm64_static_basic_block_boundaries() {
        let _guard = test_lock().lock().unwrap_or_else(|e| e.into_inner());
        let mut runtime = QuickJsRuntime::new();
        runtime.initialize().expect("init runtime");
        let result = runtime
            .eval(
                "JSON.stringify(Stalker.parse([0x20,0x00,0x80,0xd2,0x02,0x00,0x00,0x94,0xc0,0x03,0x5f,0xd6], 0x2000))",
            )
            .expect("parse");
        assert!(result.contains("\"backend\":\"arm64-static-decoder\""));
        assert!(result.contains("\"executionObserved\":false"));
        assert!(result.contains("\"instructionCount\":3"));
        assert!(result.contains("\"kind\":\"bl\""));
        assert!(result.contains("\"terminator\":\"ret\""));
    }

    #[test]
    fn bounded_transform_and_event_generation_are_explicitly_non_instrumented() {
        let _guard = test_lock().lock().unwrap_or_else(|e| e.into_inner());
        let mut runtime = QuickJsRuntime::new();
        runtime.initialize().expect("init runtime");
        let transform = runtime
            .eval(
                "JSON.stringify(Stalker.transform([0x20,0x00,0x80,0xd2,0x02,0x00,0x00,0x94,0xc0,0x03,0x5f,0xd6], 0x2000, {events: 31, maxInstructions: 16}))",
            )
            .expect("transform");
        assert!(transform.contains("\"backend\":\"arm64-bounded-transform-plan\""));
        assert!(transform.contains("\"mode\":\"static-only\""));
        assert!(transform.contains("\"staticOnly\":true"));
        assert!(transform.contains("\"instrumented\":false"));
        assert!(transform.contains("\"targetThreadInstrumented\":false"));
        assert!(transform.contains("\"instrumentationPoints\""));

        let generated = runtime
            .eval(
                "JSON.stringify(Stalker.generateEvents([0x20,0x00,0x80,0xd2,0x02,0x00,0x00,0x94,0xc0,0x03,0x5f,0xd6], 0x2000, [{address:0x2000},{address:0x2004},{address:0x2008,target:0x3000,depth:1}], {events:31, maxEvents: 32}))",
            )
            .expect("generate events");
        assert!(generated.contains("\"backend\":\"arm64-bounded-event-generator\""));
        assert!(generated.contains("\"mode\":\"event-generation\""));
        assert!(generated.contains("\"executionObserved\":true"));
        assert!(generated.contains("\"targetThreadInstrumented\":false"));
        assert!(generated.contains("\"type\":\"compile\""));
        assert!(generated.contains("\"type\":\"block\""));
        assert!(generated.contains("\"type\":\"call\""));
        assert!(generated.contains("\"type\":\"ret\""));
    }

    #[test]
    fn record_block_submits_generated_events_to_the_existing_bounded_sink() {
        let _guard = test_lock().lock().unwrap_or_else(|e| e.into_inner());
        let mut runtime = QuickJsRuntime::new();
        runtime.initialize().expect("init runtime");
        let result = runtime
            .eval(
                "(function() { const t = 778; Stalker.follow(t, {events: 12, queueCapacity: 8}); const r = Stalker.recordBlock(t, [0x20,0x00,0x80,0xd2,0xc0,0x03,0x5f,0xd6], 0x4000, [{address:0x4000},{address:0x4004}], {events: 12, maxEvents: 8}); const e = Stalker.flush(t); Stalker.unfollow(t); Stalker.garbageCollect(t); return JSON.stringify({r:r, events:e}); })()",
            )
            .expect("record block");
        assert!(result.contains("\"acceptedEvents\":3"));
        assert!(result.contains("\"notQueuedEvents\":0"));
        assert!(result.contains("\"type\":\"block\""));
        assert!(result.contains("\"type\":\"exec\""));
    }

    #[test]
    fn capability_report_exposes_static_subset_without_promoting_follow_to_instrumentation() {
        let _guard = test_lock().lock().unwrap_or_else(|e| e.into_inner());
        let mut runtime = QuickJsRuntime::new();
        runtime.initialize().expect("init runtime");
        assert_eq!(runtime.eval("Stalker.capabilities().staticParse").unwrap(), "true");
        assert_eq!(
            runtime
                .eval("Stalker.capabilities().boundedBasicBlockTransform")
                .unwrap(),
            "true"
        );
        assert_eq!(runtime.eval("Stalker.capabilities().eventGeneration").unwrap(), "true");
        assert_eq!(
            runtime.eval("Stalker.capabilities().transformMode").unwrap(),
            "static-only"
        );
        assert_eq!(runtime.eval("Stalker.capabilities().instrumented").unwrap(), "false");
        assert_eq!(
            runtime
                .eval("Stalker.capabilities().targetThreadInstrumentation")
                .unwrap(),
            "false"
        );
        assert_eq!(runtime.eval("typeof Native.stalkerTransform").unwrap(), "function");
    }

    #[test]
    fn capture_collects_only_function_level_stalker_logs() {
        let _guard = test_lock().lock().unwrap_or_else(|e| e.into_inner());
        let mut runtime = QuickJsRuntime::new();
        runtime.initialize().expect("init runtime");
        assert_eq!(
            runtime.eval("Stalker.captureStart({maxEvents: 2}).active").unwrap(),
            "true"
        );
        runtime.eval("console.log('[stalker]   -> target'); console.log('[stalker]     <- target ret=0x0'); console.log('[trace] ignored')").expect("emit logs");
        let result = runtime.eval("JSON.stringify(Stalker.captureFlush())").expect("flush");
        assert!(result.contains("\"type\":\"call\""));
        assert!(result.contains("\"type\":\"ret\""));
        assert_eq!(runtime.eval("Stalker.captureStatus().count").unwrap(), "0");
        assert_eq!(
            runtime.eval("Stalker.capabilities().dynamicInstructionEvents").unwrap(),
            "false"
        );
    }

    #[test]
    fn native_thread_follow_sink_flush_and_gc_are_executable() {
        let _guard = test_lock().lock().unwrap_or_else(|e| e.into_inner());
        let mut runtime = QuickJsRuntime::new();
        runtime.initialize().expect("init runtime");
        let result = runtime
            .eval("(function() { const t = 77; Stalker.follow(t, {events: 7, queueCapacity: 4}); Native.stalkerRecordEvent(t, {type: 'call', location: 0x1000, target: 0x2000, depth: 0}); return JSON.stringify(Stalker.flush(t)); })()")
            .expect("flush event sink");
        assert!(result.contains("\"type\":\"call\""));
        assert_eq!(runtime.eval("Stalker.unfollow(77).state").unwrap(), "idle");
        assert_eq!(runtime.eval("Stalker.garbageCollect(77)").unwrap(), "true");
    }
}
