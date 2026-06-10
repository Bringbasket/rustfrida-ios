use crate::context::JSContext;
use crate::ffi;
use crate::ptr::{create_native_pointer, get_native_pointer_addr};
use crate::util::{
    add_cfunction_to_object, js_i64_to_js_number_or_bigint, js_throw_internal_error, js_u64_to_js_number_or_bigint,
};
use crate::value::JSValue;
use native_api::{
    dependency_path_or_name_matches, detect_hook_environment, enumerate_images, find_export_by_name,
    find_image_build_version, find_image_by_address, find_image_by_name, find_image_chained_fixups,
    find_image_code_signature, find_image_data_in_code, find_image_dependencies, find_image_dyld_info,
    find_image_dylinker, find_image_encryption_info, find_image_entry_point, find_image_exports,
    find_image_exports_trie, find_image_function_starts, find_image_imports, find_image_install_name,
    find_image_linkedit_info, find_image_load_commands, find_image_rpaths, find_image_sections, find_image_segments,
    find_image_source_version, find_image_uuid, find_native_symbols, find_symbol_by_address,
    hook_coexistence_layer_status, hook_environment_recommendations, hook_environment_recommended_actions,
    image_build_version_support_available, image_chained_fixups_support_available,
    image_code_signature_support_available, image_data_in_code_support_available, image_dependency_support_available,
    image_dyld_info_support_available, image_dylinker_support_available, image_encryption_info_support_available,
    image_entry_point_support_available, image_exports_trie_support_available, image_function_starts_support_available,
    image_import_support_available, image_install_name_support_available, image_linkedit_info_support_available,
    image_load_command_support_available, image_rpath_support_available, image_section_support_available,
    image_segment_support_available, image_source_version_support_available, image_uuid_support_available,
    native_export_support_available, native_symbol_support_available, resolve_hook_strategy,
    rpath_path_or_name_matches, section_name_matches, segment_name_matches,
};
use std::collections::BTreeMap;
use std::path::Path;

unsafe fn set_string_array_property(ctx: *mut ffi::JSContext, obj: ffi::JSValue, name: &str, items: &[String]) {
    let array = ffi::JS_NewArray(ctx);
    for (index, item) in items.iter().enumerate() {
        ffi::JS_SetPropertyUint32(ctx, array, index as u32, JSValue::string(ctx, item).raw());
    }
    JSValue(obj).set_property(ctx, name, JSValue(array));
}

unsafe fn string_vec_to_js_array(ctx: *mut ffi::JSContext, items: &[String]) -> ffi::JSValue {
    let array = ffi::JS_NewArray(ctx);
    for (index, item) in items.iter().enumerate() {
        ffi::JS_SetPropertyUint32(ctx, array, index as u32, JSValue::string(ctx, item).raw());
    }
    array
}

unsafe fn instrumentation_capability_to_js(ctx: *mut ffi::JSContext) -> ffi::JSValue {
    let result = JSValue(ffi::JS_NewObject(ctx));
    let recommended_commands = vec![
        "trace <target>".to_string(),
        "stalker <target>".to_string(),
        "hfl <module> <offset>".to_string(),
        "jhook <class> <selector> [meta]".to_string(),
        "shook <type> <method>".to_string(),
    ];
    let unsupported_qbdi_apis = vec![
        "qbdi.newVM".to_string(),
        "qbdi.run".to_string(),
        "qbdi.call".to_string(),
        "qbdi.getGPR/setGPR".to_string(),
        "qbdi.registerTraceCallbacks".to_string(),
    ];

    result.set_property(ctx, "platform", JSValue::string(ctx, "ios"));
    result.set_property(ctx, "backend", JSValue::string(ctx, "arm64-hook-engine"));
    result.set_property(ctx, "backendDisplayName", JSValue::string(ctx, "ARM64 hook engine"));
    result.set_property(ctx, "androidReferenceBackend", JSValue::string(ctx, "QBDI"));
    result.set_property(
        ctx,
        "androidReferencePath",
        JSValue::string(
            ctx,
            "rustFrida-master/qbdi-helper + quickjs-hook/src/jsapi/hook_api/qbdi.rs",
        ),
    );
    result.set_property(ctx, "qbdiCompatible", JSValue::bool(false));
    result.set_property(ctx, "qbdiAvailable", JSValue::bool(false));
    result.set_property(ctx, "qbdiApiPorted", JSValue::bool(false));
    result.set_property(ctx, "inlineHookAvailable", JSValue::bool(true));
    result.set_property(ctx, "traceAvailable", JSValue::bool(true));
    result.set_property(ctx, "stalkerAvailable", JSValue::bool(true));
    result.set_property(ctx, "hflAvailable", JSValue::bool(true));
    result.set_property(ctx, "virtualStackAvailable", JSValue::bool(false));
    result.set_property(ctx, "registerStateApiAvailable", JSValue::bool(false));
    result.set_property(ctx, "memoryAccessTraceAvailable", JSValue::bool(false));
    result.set_property(
        ctx,
        "recommendedPath",
        JSValue::string(ctx, "trace-stalker-inline-hook"),
    );
    result.set_property(
        ctx,
        "summary",
        JSValue::string(
            ctx,
            "Android QBDI VM APIs are not ported to iOS; use ARM64 hook engine based trace/stalker/HFL/JHook/Shook flows.",
        ),
    );
    result.set_property(
        ctx,
        "recommendedCommands",
        JSValue(string_vec_to_js_array(ctx, &recommended_commands)),
    );
    result.set_property(
        ctx,
        "unsupportedQbdiApis",
        JSValue(string_vec_to_js_array(ctx, &unsupported_qbdi_apis)),
    );
    result.raw()
}

unsafe fn js_array_first(item: JSValue, ctx: *mut ffi::JSContext) -> JSValue {
    item.get_property(ctx, "0")
}

unsafe fn js_array_last(item: JSValue, ctx: *mut ffi::JSContext) -> JSValue {
    let length = item.get_property(ctx, "length").to_int().unwrap_or(0);
    if length <= 0 {
        JSValue::null()
    } else {
        item.get_property(ctx, &(length - 1).to_string())
    }
}

unsafe fn set_phase_ready_aliases(
    ctx: *mut ffi::JSContext,
    ready_value: &JSValue,
    prefix: &str,
    phase_entry: &JSValue,
    include_first_last_error_codes: bool,
    include_detailed_command_json_template: bool,
) {
    let phase_field = format!("{prefix}");
    let error_code_count_field = format!("{prefix}ErrorCodeCount");
    let error_codes_field = format!("{prefix}ErrorCodes");
    let error_code_first_field = format!("{prefix}ErrorCodeFirst");
    let error_code_last_field = format!("{prefix}ErrorCodeLast");
    let escalation_key_count_field = format!("{prefix}EscalationKeyCount");
    let escalation_keys_field = format!("{prefix}EscalationKeys");
    let primary_escalation_key_field = format!("{prefix}PrimaryEscalationKey");
    let template_count_field = format!("{prefix}TemplateCount");
    let templates_field = format!("{prefix}Templates");
    let template_field = format!("{prefix}Template");
    let command_json_template_count_field = format!("{prefix}CommandJsonTemplateCount");
    let command_json_eligible_template_count_field = format!("{prefix}CommandJsonEligibleTemplateCount");
    let command_json_templates_field = format!("{prefix}CommandJsonTemplates");
    let command_json_template_field = format!("{prefix}CommandJsonTemplate");
    let command_json_template_command_field = format!("{prefix}CommandJsonTemplateCommand");

    let is_present = !(phase_entry.is_null() || phase_entry.is_undefined());
    let empty_strings = JSValue(ffi::JS_NewArray(ctx));

    if is_present {
        ready_value.set_property(ctx, &phase_field, phase_entry.dup(ctx));
        ready_value.set_property(
            ctx,
            &error_code_count_field,
            phase_entry.get_property(ctx, "errorCodeCount"),
        );
        let error_codes = phase_entry.get_property(ctx, "errorCodes");
        ready_value.set_property(ctx, &error_codes_field, error_codes.dup(ctx));
        if include_first_last_error_codes {
            ready_value.set_property(ctx, &error_code_first_field, js_array_first(error_codes.dup(ctx), ctx));
            ready_value.set_property(ctx, &error_code_last_field, js_array_last(error_codes, ctx));
        }
        ready_value.set_property(
            ctx,
            &escalation_key_count_field,
            phase_entry.get_property(ctx, "escalationKeyCount"),
        );
        let escalation_keys = phase_entry.get_property(ctx, "escalationKeys");
        ready_value.set_property(ctx, &escalation_keys_field, escalation_keys.dup(ctx));
        ready_value.set_property(ctx, &primary_escalation_key_field, js_array_first(escalation_keys, ctx));
        ready_value.set_property(
            ctx,
            &template_count_field,
            phase_entry.get_property(ctx, "templateCount"),
        );
        let templates = phase_entry.get_property(ctx, "templates");
        ready_value.set_property(ctx, &templates_field, templates.dup(ctx));
        ready_value.set_property(ctx, &template_field, js_array_first(templates, ctx));
        ready_value.set_property(
            ctx,
            &command_json_template_count_field,
            phase_entry.get_property(ctx, "commandJsonTemplateCount"),
        );
        ready_value.set_property(
            ctx,
            &command_json_eligible_template_count_field,
            phase_entry.get_property(ctx, "commandJsonEligibleTemplateCount"),
        );
        let command_json_templates = phase_entry.get_property(ctx, "commandJsonTemplates");
        let command_json_template = js_array_first(command_json_templates.dup(ctx), ctx);
        ready_value.set_property(ctx, &command_json_templates_field, command_json_templates);
        ready_value.set_property(ctx, &command_json_template_field, command_json_template.dup(ctx));
        ready_value.set_property(
            ctx,
            &command_json_template_command_field,
            command_json_template.get_property(ctx, "command"),
        );
        if include_detailed_command_json_template {
            ready_value.set_property(
                ctx,
                &format!("{prefix}CommandJsonTemplateRisk"),
                command_json_template.get_property(ctx, "risk"),
            );
            ready_value.set_property(
                ctx,
                &format!("{prefix}CommandJsonTemplatePlaceholderCount"),
                command_json_template.get_property(ctx, "placeholderCount"),
            );
            ready_value.set_property(
                ctx,
                &format!("{prefix}CommandJsonTemplatePlaceholders"),
                command_json_template.get_property(ctx, "placeholders"),
            );
            ready_value.set_property(
                ctx,
                &format!("{prefix}CommandJsonTemplateCliArgs"),
                command_json_template.get_property(ctx, "cliArgs"),
            );
            ready_value.set_property(
                ctx,
                &format!("{prefix}CommandJsonTemplateKind"),
                command_json_template.get_property(ctx, "kind"),
            );
            ready_value.set_property(
                ctx,
                &format!("{prefix}CommandJsonTemplatePhase"),
                command_json_template.get_property(ctx, "phase"),
            );
            ready_value.set_property(
                ctx,
                &format!("{prefix}CommandJsonTemplateErrorCode"),
                command_json_template.get_property(ctx, "errorCode"),
            );
            ready_value.set_property(
                ctx,
                &format!("{prefix}CommandJsonTemplateTimeoutErrorCode"),
                command_json_template.get_property(ctx, "timeoutErrorCode"),
            );
            ready_value.set_property(
                ctx,
                &format!("{prefix}CommandJsonTemplateRetryable"),
                command_json_template.get_property(ctx, "retryable"),
            );
            ready_value.set_property(
                ctx,
                &format!("{prefix}CommandJsonTemplateMaxSuggestedRetries"),
                command_json_template.get_property(ctx, "maxSuggestedRetries"),
            );
            ready_value.set_property(
                ctx,
                &format!("{prefix}CommandJsonTemplateRetryDelayHintMs"),
                command_json_template.get_property(ctx, "retryDelayHintMs"),
            );
            ready_value.set_property(
                ctx,
                &format!("{prefix}CommandJsonTemplateTimeoutHintMs"),
                command_json_template.get_property(ctx, "timeoutHintMs"),
            );
            ready_value.set_property(
                ctx,
                &format!("{prefix}CommandJsonTemplateTimeoutAction"),
                command_json_template.get_property(ctx, "timeoutAction"),
            );
            ready_value.set_property(
                ctx,
                &format!("{prefix}CommandJsonTemplateCommandJsonEligible"),
                command_json_template.get_property(ctx, "commandJsonEligible"),
            );
        }
    } else {
        ready_value.set_property(ctx, &phase_field, JSValue::null());
        ready_value.set_property(ctx, &error_code_count_field, JSValue::null());
        ready_value.set_property(ctx, &error_codes_field, empty_strings.dup(ctx));
        if include_first_last_error_codes {
            ready_value.set_property(ctx, &error_code_first_field, JSValue::null());
            ready_value.set_property(ctx, &error_code_last_field, JSValue::null());
        }
        ready_value.set_property(ctx, &escalation_key_count_field, JSValue::null());
        ready_value.set_property(ctx, &escalation_keys_field, empty_strings.dup(ctx));
        ready_value.set_property(ctx, &primary_escalation_key_field, JSValue::null());
        ready_value.set_property(ctx, &template_count_field, JSValue::null());
        ready_value.set_property(ctx, &templates_field, empty_strings.dup(ctx));
        ready_value.set_property(ctx, &template_field, JSValue::null());
        ready_value.set_property(ctx, &command_json_template_count_field, JSValue::null());
        ready_value.set_property(ctx, &command_json_eligible_template_count_field, JSValue::null());
        ready_value.set_property(ctx, &command_json_templates_field, JSValue(ffi::JS_NewArray(ctx)));
        ready_value.set_property(ctx, &command_json_template_field, JSValue::null());
        ready_value.set_property(ctx, &command_json_template_command_field, JSValue::null());
        if include_detailed_command_json_template {
            ready_value.set_property(ctx, &format!("{prefix}CommandJsonTemplateRisk"), JSValue::null());
            ready_value.set_property(
                ctx,
                &format!("{prefix}CommandJsonTemplatePlaceholderCount"),
                JSValue::null(),
            );
            ready_value.set_property(
                ctx,
                &format!("{prefix}CommandJsonTemplatePlaceholders"),
                JSValue(ffi::JS_NewArray(ctx)),
            );
            ready_value.set_property(
                ctx,
                &format!("{prefix}CommandJsonTemplateCliArgs"),
                JSValue(ffi::JS_NewArray(ctx)),
            );
            ready_value.set_property(ctx, &format!("{prefix}CommandJsonTemplateKind"), JSValue::null());
            ready_value.set_property(ctx, &format!("{prefix}CommandJsonTemplatePhase"), JSValue::null());
            ready_value.set_property(ctx, &format!("{prefix}CommandJsonTemplateErrorCode"), JSValue::null());
            ready_value.set_property(
                ctx,
                &format!("{prefix}CommandJsonTemplateTimeoutErrorCode"),
                JSValue::null(),
            );
            ready_value.set_property(ctx, &format!("{prefix}CommandJsonTemplateRetryable"), JSValue::null());
            ready_value.set_property(
                ctx,
                &format!("{prefix}CommandJsonTemplateMaxSuggestedRetries"),
                JSValue::null(),
            );
            ready_value.set_property(
                ctx,
                &format!("{prefix}CommandJsonTemplateRetryDelayHintMs"),
                JSValue::null(),
            );
            ready_value.set_property(
                ctx,
                &format!("{prefix}CommandJsonTemplateTimeoutHintMs"),
                JSValue::null(),
            );
            ready_value.set_property(
                ctx,
                &format!("{prefix}CommandJsonTemplateTimeoutAction"),
                JSValue::null(),
            );
            ready_value.set_property(
                ctx,
                &format!("{prefix}CommandJsonTemplateCommandJsonEligible"),
                JSValue::null(),
            );
        }
    }
}

unsafe fn get_property_or_null(ctx: *mut ffi::JSContext, source: &JSValue, name: &str) -> JSValue {
    if source.is_null() || source.is_undefined() || source.is_exception() {
        return JSValue::null();
    }

    let value = source.get_property(ctx, name);
    if value.is_exception() {
        value.free(ctx);
        JSValue::null()
    } else {
        value
    }
}

unsafe fn set_property_aliases(ctx: *mut ffi::JSContext, target: &JSValue, source: &JSValue, aliases: &[(&str, &str)]) {
    if source.is_null() || source.is_undefined() || source.is_exception() {
        for (target_key, _) in aliases {
            target.set_property(ctx, target_key, JSValue::null());
        }
        return;
    }

    for (target_key, source_key) in aliases {
        target.set_property(ctx, target_key, get_property_or_null(ctx, source, source_key));
    }
}

unsafe fn set_nested_property_aliases(
    ctx: *mut ffi::JSContext,
    target: &JSValue,
    source: &JSValue,
    aliases: &[(&str, &str, &str)],
) {
    if source.is_null() || source.is_undefined() || source.is_exception() {
        for (target_key, _, _) in aliases {
            target.set_property(ctx, target_key, JSValue::null());
        }
        return;
    }

    for (target_key, container_key, nested_key) in aliases {
        let container = get_property_or_null(ctx, source, container_key);
        if container.is_null() || container.is_undefined() || container.is_exception() {
            target.set_property(ctx, target_key, JSValue::null());
        } else {
            target.set_property(ctx, target_key, get_property_or_null(ctx, &container, nested_key));
        }
        container.free(ctx);
    }
}

unsafe fn hook_recommended_action_to_js(
    ctx: *mut ffi::JSContext,
    action: &native_api::HookRecommendedAction,
) -> JSValue {
    let item = JSValue(ffi::JS_NewObject(ctx));
    item.set_property(ctx, "commandGroup", JSValue::string(ctx, &action.command_group));
    item.set_property(ctx, "actionKey", JSValue::string(ctx, &action.action_key));
    item.set_property(ctx, "priority", JSValue::int(action.priority as i32));
    item.set_property(ctx, "allowed", JSValue::bool(action.allowed));
    item.set_property(ctx, "blockedBy", JSValue::string(ctx, hook_action_blocked_by(action)));
    item.set_property(ctx, "branch", JSValue::string(ctx, hook_action_branch(action)));
    item.set_property(ctx, "status", JSValue::string(ctx, &action.status));
    item.set_property(ctx, "recommendation", JSValue::string(ctx, &action.recommendation));
    match &action.reason {
        Some(reason) => item.set_property(ctx, "reason", JSValue::string(ctx, reason)),
        None => item.set_property(ctx, "reason", JSValue::null()),
    };
    item
}

fn hook_automation_suggested_sequence(preferred_path: &str) -> Vec<String> {
    let commands: &[&str] = match preferred_path {
        "inline-safe" => &[
            "native.hookenv",
            "trace status",
            "trace <objc-filter|native-target>",
            "stalker <objc-filter|native-target>",
        ],
        "inline-cautious" => &[
            "native.hookenv",
            "controller --preflight-only --preflight-json --pid <pid>",
            "trace status",
            "trace <objc-filter|native-target> # caution-filesystem-only-backend-artifacts",
            "stalker <objc-filter|native-target> # caution-filesystem-only-backend-artifacts",
        ],
        "inline-risky" => &[
            "native.hookenv",
            "trace status",
            "trace <objc-filter|native-target> # risky-with-external-backend",
            "stalker <objc-filter|native-target> # risky-with-external-backend",
        ],
        "query-only" => &[
            "native.hookenv",
            "objc.classes <filter>",
            "native.images <filter>",
            "swift.types <filter>",
        ],
        "cleanup-only" => &[
            "trace status",
            "stalker status",
            "jhook status",
            "shook status",
            "hfl status",
            "trace stop",
            "stalker stop",
            "jhook stop",
            "shook stop",
            "hfl stop",
        ],
        _ => &[
            "native.hookenv",
            "controller --preflight-only --preflight-json",
            "check IOS_RUSTFRIDA_HOOK_POLICY and retry",
        ],
    };

    commands.iter().map(|item| (*item).to_string()).collect::<Vec<_>>()
}

fn hook_action_command_templates(action_key: &str, preferred_path: &str) -> Vec<String> {
    let templates: &[&str] = match action_key {
        "hook.bootstrap" => &[
            "native.hookenv",
            "controller --preflight-only --preflight-json --pid <pid>",
            "controller --inject-json --pid <pid>",
        ],
        "hook.query" => &[
            "objc.classes <filter>",
            "native.images <filter>",
            "swift.types <filter>",
        ],
        "hook.install" => match preferred_path {
            "inline-risky" => &[
                "trace <objc-filter|native-target> # risky-with-external-backend",
                "stalker <objc-filter|native-target> # risky-with-external-backend",
                "jhook <class> <selector> [meta] # risky-with-external-backend",
                "shook <type> <method> # risky-with-external-backend",
                "hfl <module> <offset> # risky-with-external-backend",
            ],
            "inline-cautious" => &[
                "trace <objc-filter|native-target> # caution-filesystem-only-backend-artifacts",
                "stalker <objc-filter|native-target> # caution-filesystem-only-backend-artifacts",
                "jhook <class> <selector> [meta] # caution-filesystem-only-backend-artifacts",
                "shook <type> <method> # caution-filesystem-only-backend-artifacts",
                "hfl <module> <offset> # caution-filesystem-only-backend-artifacts",
            ],
            "inline-safe" => &[
                "trace <objc-filter|native-target>",
                "stalker <objc-filter|native-target>",
                "jhook <class> <selector> [meta]",
                "shook <type> <method>",
                "hfl <module> <offset>",
            ],
            _ => &[],
        },
        "hook.status" => &[
            "trace status",
            "stalker status",
            "jhook status",
            "shook status",
            "hfl status",
        ],
        "hook.stop" => &["trace stop", "stalker stop", "jhook stop", "shook stop", "hfl stop"],
        _ => &[],
    };

    templates.iter().map(|item| (*item).to_string()).collect::<Vec<_>>()
}

fn hook_action_prerequisites(action_key: &str) -> &'static [&'static str] {
    match action_key {
        "hook.install" => &["hook.bootstrap"],
        "hook.stop" => &["hook.status"],
        _ => &[],
    }
}

fn hook_effective_action_order(action_key: &str) -> usize {
    match action_key {
        "hook.query" => 0,
        "hook.bootstrap" => 1,
        "hook.install" => 2,
        "hook.status" => 3,
        "hook.stop" => 4,
        _ => usize::MAX,
    }
}

fn hook_action_mode_rank(command_mode: &str, action_key: &str) -> u8 {
    match command_mode {
        "cleanup-only" => match action_key {
            "hook.status" => 0,
            "hook.stop" => 1,
            "hook.bootstrap" => 2,
            "hook.query" => 3,
            "hook.install" => 4,
            _ => 5,
        },
        "query-only" => match action_key {
            "hook.query" => 0,
            "hook.status" => 1,
            "hook.stop" => 2,
            "hook.bootstrap" => 3,
            "hook.install" => 4,
            _ => 5,
        },
        _ => match action_key {
            "hook.query" => 0,
            "hook.bootstrap" => 1,
            "hook.install" => 2,
            "hook.status" => 3,
            "hook.stop" => 4,
            _ => 5,
        },
    }
}

fn hook_action_blocked_by(action: &native_api::HookRecommendedAction) -> &'static str {
    if action.allowed {
        "none"
    } else {
        "policy"
    }
}

fn normalize_command_template_for_cli(template: &str) -> String {
    template
        .split(" #")
        .next()
        .map(str::trim)
        .unwrap_or_default()
        .to_string()
}

fn command_template_placeholders(command: &str) -> Vec<String> {
    command
        .split_whitespace()
        .filter_map(|token| {
            let trimmed = token.trim_matches(|ch: char| ch == ',' || ch == ';');
            if trimmed.starts_with('<') && trimmed.ends_with('>') && trimmed.len() > 2 {
                Some(trimmed.to_string())
            } else {
                None
            }
        })
        .collect::<Vec<_>>()
}

fn command_template_risk(template: &str) -> &'static str {
    if template.contains("# risky-with-external-backend") {
        "risky-with-external-backend"
    } else if template.contains("# caution-filesystem-only-backend-artifacts") {
        "cautious-filesystem-only-backend-artifacts"
    } else {
        "normal"
    }
}

fn command_template_phase(command: &str) -> &'static str {
    if command.starts_with("controller --preflight-only") {
        "preflight"
    } else if command.starts_with("controller --inject-json") {
        "inject"
    } else if command == "native.hookenv" {
        "diagnose"
    } else if command.starts_with("trace status")
        || command.starts_with("stalker status")
        || command.starts_with("jhook status")
        || command.starts_with("shook status")
        || command.starts_with("hfl status")
        || command.starts_with("trace stop")
        || command.starts_with("stalker stop")
        || command.starts_with("jhook stop")
        || command.starts_with("shook stop")
        || command.starts_with("hfl stop")
    {
        "cleanup"
    } else if command.starts_with("objc.")
        || command.starts_with("native.images")
        || command.starts_with("swift.")
        || command.starts_with("pac.")
    {
        "query"
    } else if command.starts_with("trace ")
        || command.starts_with("stalker ")
        || command.starts_with("jhook ")
        || command.starts_with("shook ")
        || command.starts_with("hfl ")
    {
        "hook-install"
    } else {
        "general"
    }
}

fn phase_retry_policy(phase: &str) -> (bool, u32, u64) {
    match phase {
        "diagnose" => (true, 1, 250),
        "preflight" => (true, 2, 500),
        "query" => (true, 1, 250),
        "cleanup" => (true, 1, 250),
        "inject" => (false, 0, 0),
        "hook-install" => (false, 0, 0),
        _ => (false, 0, 0),
    }
}

fn phase_timeout_policy(phase: &str) -> (u64, &'static str) {
    match phase {
        "diagnose" => (4000, "refresh-hook-environment-and-retry"),
        "preflight" => (8000, "re-run-preflight-or-switch-to-query-only"),
        "query" => (5000, "narrow-query-filter-and-retry"),
        "cleanup" => (6000, "retry-cleanup-or-escalate-to-preflight"),
        "inject" => (12000, "abort-injection-and-run-preflight"),
        "hook-install" => (12000, "stop-hook-install-and-switch-to-query-only"),
        _ => (5000, "abort-and-escalate"),
    }
}

fn phase_failure_code(phase: &str) -> &'static str {
    match phase {
        "diagnose" => "hook-fallback-diagnose-failed",
        "preflight" => "hook-fallback-preflight-failed",
        "query" => "hook-fallback-query-failed",
        "cleanup" => "hook-fallback-cleanup-failed",
        "inject" => "hook-fallback-inject-failed",
        "hook-install" => "hook-fallback-hook-install-failed",
        _ => "hook-fallback-general-failed",
    }
}

fn phase_timeout_error_code(phase: &str) -> &'static str {
    match phase {
        "diagnose" => "hook-fallback-diagnose-timeout",
        "preflight" => "hook-fallback-preflight-timeout",
        "query" => "hook-fallback-query-timeout",
        "cleanup" => "hook-fallback-cleanup-timeout",
        "inject" => "hook-fallback-inject-timeout",
        "hook-install" => "hook-fallback-hook-install-timeout",
        _ => "hook-fallback-general-timeout",
    }
}

unsafe fn hook_command_json_template_to_js(ctx: *mut ffi::JSContext, template: &str) -> ffi::JSValue {
    let command = normalize_command_template_for_cli(template);
    let placeholders = command_template_placeholders(&command);
    let risk = command_template_risk(template);
    let phase = command_template_phase(&command);
    let (retryable, max_suggested_retries, retry_delay_hint_ms) = phase_retry_policy(phase);
    let (timeout_hint_ms, timeout_action) = phase_timeout_policy(phase);
    let error_code = phase_failure_code(phase);
    let timeout_error_code = phase_timeout_error_code(phase);
    let result = JSValue(ffi::JS_NewObject(ctx));

    result.set_property(ctx, "command", JSValue::string(ctx, &command));
    result.set_property(ctx, "risk", JSValue::string(ctx, risk));
    result.set_property(ctx, "phase", JSValue::string(ctx, phase));
    result.set_property(ctx, "retryable", JSValue::bool(retryable));
    result.set_property(ctx, "maxSuggestedRetries", JSValue::int(max_suggested_retries as i32));
    result.set_property(
        ctx,
        "retryDelayHintMs",
        JSValue(js_u64_to_js_number_or_bigint(ctx, retry_delay_hint_ms)),
    );
    result.set_property(
        ctx,
        "timeoutHintMs",
        JSValue(js_u64_to_js_number_or_bigint(ctx, timeout_hint_ms)),
    );
    result.set_property(ctx, "timeoutAction", JSValue::string(ctx, timeout_action));
    result.set_property(ctx, "errorCode", JSValue::string(ctx, error_code));
    result.set_property(ctx, "timeoutErrorCode", JSValue::string(ctx, timeout_error_code));
    result.set_property(ctx, "placeholderCount", JSValue::int(placeholders.len() as i32));
    set_string_array_property(ctx, result.raw(), "placeholders", &placeholders);

    if let Some(controller_args) = command.strip_prefix("controller ") {
        let cli_args = controller_args
            .split_whitespace()
            .map(|token| token.to_string())
            .collect::<Vec<_>>();
        result.set_property(ctx, "kind", JSValue::string(ctx, "controller-cli"));
        result.set_property(ctx, "commandJsonEligible", JSValue::bool(false));
        set_string_array_property(ctx, result.raw(), "cliArgs", &cli_args);
    } else {
        let cli_args = vec![
            "--pid".to_string(),
            "<pid>".to_string(),
            "--command".to_string(),
            command.clone(),
            "--command-json".to_string(),
        ];
        result.set_property(ctx, "kind", JSValue::string(ctx, "runtime-command"));
        result.set_property(ctx, "commandJsonEligible", JSValue::bool(true));
        set_string_array_property(ctx, result.raw(), "cliArgs", &cli_args);
    }

    result.raw()
}

fn hook_action_preferred_path(action_key: &str) -> &'static str {
    match action_key {
        "hook.query" => "query",
        "hook.bootstrap" => "bootstrap",
        "hook.install" => "install",
        "hook.status" => "status",
        "hook.stop" => "stop",
        _ => "unknown",
    }
}

unsafe fn hook_step_from_command_json_template_to_js(
    ctx: *mut ffi::JSContext,
    source: &str,
    action: &native_api::HookRecommendedAction,
    ready_to_run: bool,
    index: usize,
    template: ffi::JSValue,
) -> ffi::JSValue {
    let item = JSValue(ffi::JS_NewObject(ctx));
    let template_value = JSValue(template);

    item.set_property(ctx, "source", JSValue::string(ctx, source));
    item.set_property(
        ctx,
        "id",
        JSValue::string(ctx, &format!("{source}:{}:{index}", action.action_key)),
    );
    item.set_property(ctx, "actionKey", JSValue::string(ctx, &action.action_key));
    item.set_property(ctx, "commandGroup", JSValue::string(ctx, &action.command_group));
    item.set_property(ctx, "allowed", JSValue::bool(action.allowed));
    item.set_property(ctx, "blockedBy", JSValue::string(ctx, hook_action_blocked_by(action)));
    item.set_property(ctx, "branch", JSValue::string(ctx, hook_action_branch(action)));
    match &action.reason {
        Some(reason) => item.set_property(ctx, "reason", JSValue::string(ctx, reason)),
        None => item.set_property(ctx, "reason", JSValue::null()),
    };
    item.set_property(
        ctx,
        "preferredPath",
        JSValue::string(ctx, hook_action_preferred_path(&action.action_key)),
    );
    item.set_property(ctx, "command", template_value.get_property(ctx, "command"));
    item.set_property(ctx, "phase", template_value.get_property(ctx, "phase"));
    item.set_property(ctx, "readyToRun", JSValue::bool(ready_to_run));
    item.set_property(ctx, "requiresFallback", JSValue::bool(!ready_to_run));
    item.set_property(ctx, "commandJsonTemplate", template_value.dup(ctx));
    item.set_property(ctx, "kind", template_value.get_property(ctx, "kind"));
    item.set_property(
        ctx,
        "commandJsonEligible",
        template_value.get_property(ctx, "commandJsonEligible"),
    );
    item.set_property(
        ctx,
        "commandJsonTemplateEligible",
        template_value.get_property(ctx, "commandJsonEligible"),
    );
    item.set_property(ctx, "retryable", template_value.get_property(ctx, "retryable"));
    item.set_property(
        ctx,
        "maxSuggestedRetries",
        template_value.get_property(ctx, "maxSuggestedRetries"),
    );
    item.set_property(
        ctx,
        "retryDelayHintMs",
        template_value.get_property(ctx, "retryDelayHintMs"),
    );
    item.set_property(ctx, "timeoutHintMs", template_value.get_property(ctx, "timeoutHintMs"));
    item.set_property(ctx, "timeoutAction", template_value.get_property(ctx, "timeoutAction"));
    item.set_property(ctx, "errorCode", template_value.get_property(ctx, "errorCode"));
    item.set_property(
        ctx,
        "timeoutErrorCode",
        template_value.get_property(ctx, "timeoutErrorCode"),
    );
    item.set_property(ctx, "risk", template_value.get_property(ctx, "risk"));
    item.set_property(
        ctx,
        "placeholderCount",
        template_value.get_property(ctx, "placeholderCount"),
    );
    item.set_property(ctx, "placeholders", template_value.get_property(ctx, "placeholders"));
    item.set_property(ctx, "cliArgs", template_value.get_property(ctx, "cliArgs"));

    item.raw()
}

fn hook_fallback_templates(suggested_sequence: &[String]) -> Vec<String> {
    suggested_sequence
        .iter()
        .filter(|command| !command.trim_start().starts_with("check "))
        .cloned()
        .collect::<Vec<_>>()
}

unsafe fn hook_fallback_step_from_command_json_template_to_js(
    ctx: *mut ffi::JSContext,
    index: usize,
    template: ffi::JSValue,
) -> ffi::JSValue {
    let item = JSValue(ffi::JS_NewObject(ctx));
    let template_value = JSValue(template);

    item.set_property(ctx, "index", JSValue::int(index as i32));
    item.set_property(ctx, "source", JSValue::string(ctx, "fallback-plan"));
    item.set_property(ctx, "id", JSValue::string(ctx, &format!("fallback-plan:{index}")));
    item.set_property(ctx, "actionKey", JSValue::null());
    item.set_property(ctx, "commandGroup", JSValue::null());
    item.set_property(ctx, "allowed", JSValue::null());
    item.set_property(ctx, "blockedBy", JSValue::null());
    item.set_property(ctx, "branch", JSValue::null());
    item.set_property(ctx, "reason", JSValue::null());
    item.set_property(ctx, "preferredPath", template_value.get_property(ctx, "phase"));
    item.set_property(ctx, "command", template_value.get_property(ctx, "command"));
    item.set_property(ctx, "phase", template_value.get_property(ctx, "phase"));
    item.set_property(ctx, "readyToRun", JSValue::bool(true));
    item.set_property(ctx, "requiresFallback", JSValue::bool(true));
    item.set_property(ctx, "commandJsonTemplate", template_value.dup(ctx));
    item.set_property(ctx, "kind", template_value.get_property(ctx, "kind"));
    item.set_property(
        ctx,
        "commandJsonEligible",
        template_value.get_property(ctx, "commandJsonEligible"),
    );
    item.set_property(
        ctx,
        "commandJsonTemplateEligible",
        template_value.get_property(ctx, "commandJsonEligible"),
    );
    item.set_property(ctx, "retryable", template_value.get_property(ctx, "retryable"));
    item.set_property(
        ctx,
        "maxSuggestedRetries",
        template_value.get_property(ctx, "maxSuggestedRetries"),
    );
    item.set_property(
        ctx,
        "retryDelayHintMs",
        template_value.get_property(ctx, "retryDelayHintMs"),
    );
    item.set_property(ctx, "timeoutHintMs", template_value.get_property(ctx, "timeoutHintMs"));
    item.set_property(ctx, "timeoutAction", template_value.get_property(ctx, "timeoutAction"));
    item.set_property(ctx, "errorCode", template_value.get_property(ctx, "errorCode"));
    item.set_property(
        ctx,
        "timeoutErrorCode",
        template_value.get_property(ctx, "timeoutErrorCode"),
    );
    item.set_property(ctx, "risk", template_value.get_property(ctx, "risk"));
    item.set_property(
        ctx,
        "placeholderCount",
        template_value.get_property(ctx, "placeholderCount"),
    );
    item.set_property(ctx, "placeholders", template_value.get_property(ctx, "placeholders"));
    item.set_property(ctx, "cliArgs", template_value.get_property(ctx, "cliArgs"));

    item.raw()
}

unsafe fn hook_command_json_template_array_to_js(
    ctx: *mut ffi::JSContext,
    templates: &[String],
) -> (ffi::JSValue, usize) {
    let array = ffi::JS_NewArray(ctx);
    let mut eligible_count = 0usize;
    for (index, template) in templates.iter().enumerate() {
        let entry = JSValue(hook_command_json_template_to_js(ctx, template));
        if entry
            .get_property(ctx, "commandJsonEligible")
            .to_bool()
            .unwrap_or(false)
        {
            eligible_count += 1;
        }
        ffi::JS_SetPropertyUint32(ctx, array, index as u32, entry.raw());
    }
    (array, eligible_count)
}

unsafe fn hook_escalation_recommendation_to_js(
    ctx: *mut ffi::JSContext,
    key: &str,
    condition: &str,
    phase: &str,
    reason: &str,
    note: Option<&str>,
    templates: &[String],
    on_error_codes: &[String],
) -> ffi::JSValue {
    let item = JSValue(ffi::JS_NewObject(ctx));
    let (command_json_templates, command_json_eligible_template_count) =
        hook_command_json_template_array_to_js(ctx, templates);

    item.set_property(ctx, "key", JSValue::string(ctx, key));
    item.set_property(ctx, "condition", JSValue::string(ctx, condition));
    item.set_property(ctx, "phase", JSValue::string(ctx, phase));
    item.set_property(ctx, "reason", JSValue::string(ctx, reason));
    match note {
        Some(value) => item.set_property(ctx, "note", JSValue::string(ctx, value)),
        None => item.set_property(ctx, "note", JSValue::null()),
    };
    item.set_property(ctx, "onErrorCodeCount", JSValue::int(on_error_codes.len() as i32));
    item.set_property(
        ctx,
        "onErrorCodes",
        JSValue(string_vec_to_js_array(ctx, on_error_codes)),
    );
    item.set_property(ctx, "templateCount", JSValue::int(templates.len() as i32));
    set_string_array_property(ctx, item.raw(), "templates", templates);
    item.set_property(ctx, "commandJsonTemplateCount", JSValue::int(templates.len() as i32));
    item.set_property(ctx, "commandJsonTemplates", JSValue(command_json_templates));
    item.set_property(
        ctx,
        "commandJsonEligibleTemplateCount",
        JSValue::int(command_json_eligible_template_count as i32),
    );

    item.raw()
}

fn hook_action_branch(action: &native_api::HookRecommendedAction) -> &'static str {
    if action.allowed {
        "run"
    } else {
        "skip-policy"
    }
}

fn hook_action_ready_to_run(
    actions: &[native_api::HookRecommendedAction],
    action: &native_api::HookRecommendedAction,
) -> bool {
    action.allowed
        && hook_action_prerequisites(&action.action_key).iter().all(|required| {
            actions
                .iter()
                .find(|candidate| candidate.action_key == *required)
                .map(|candidate| candidate.allowed)
                .unwrap_or(true)
        })
}

unsafe fn hook_next_action_plan_to_js(
    ctx: *mut ffi::JSContext,
    actions: &[native_api::HookRecommendedAction],
    action: &native_api::HookRecommendedAction,
    templates: &[String],
) -> ffi::JSValue {
    let plan = JSValue(ffi::JS_NewObject(ctx));
    let prerequisite_action_keys = hook_action_prerequisites(&action.action_key)
        .iter()
        .map(|item| (*item).to_string())
        .collect::<Vec<_>>();
    let blocked_prerequisite_action_keys = prerequisite_action_keys
        .iter()
        .filter(|required| {
            actions
                .iter()
                .find(|candidate| candidate.action_key == required.as_str())
                .map(|candidate| !candidate.allowed)
                .unwrap_or(false)
        })
        .cloned()
        .collect::<Vec<_>>();
    let command_json_templates_array = ffi::JS_NewArray(ctx);
    let mut command_json_template_count = 0usize;
    let mut command_json_eligible_count = 0usize;

    for (index, template) in templates.iter().enumerate() {
        let entry = JSValue(hook_command_json_template_to_js(ctx, template));
        if entry
            .get_property(ctx, "commandJsonEligible")
            .to_bool()
            .unwrap_or(false)
        {
            command_json_eligible_count += 1;
        }
        ffi::JS_SetPropertyUint32(ctx, command_json_templates_array, index as u32, entry.raw());
        command_json_template_count += 1;
    }

    plan.set_property(ctx, "actionKey", JSValue::string(ctx, &action.action_key));
    plan.set_property(ctx, "commandGroup", JSValue::string(ctx, &action.command_group));
    plan.set_property(ctx, "allowed", JSValue::bool(action.allowed));
    plan.set_property(ctx, "blockedBy", JSValue::string(ctx, hook_action_blocked_by(action)));
    plan.set_property(ctx, "status", JSValue::string(ctx, &action.status));
    plan.set_property(ctx, "priority", JSValue::int(action.priority as i32));
    plan.set_property(ctx, "recommendation", JSValue::string(ctx, &action.recommendation));
    plan.set_property(ctx, "branch", JSValue::string(ctx, hook_action_branch(action)));
    plan.set_property(
        ctx,
        "readyToRun",
        JSValue::bool(hook_action_ready_to_run(actions, action)),
    );
    plan.set_property(
        ctx,
        "prerequisiteCount",
        JSValue::int(prerequisite_action_keys.len() as i32),
    );
    set_string_array_property(ctx, plan.raw(), "prerequisiteActionKeys", &prerequisite_action_keys);
    plan.set_property(
        ctx,
        "blockedPrerequisiteCount",
        JSValue::int(blocked_prerequisite_action_keys.len() as i32),
    );
    set_string_array_property(
        ctx,
        plan.raw(),
        "blockedPrerequisiteActionKeys",
        &blocked_prerequisite_action_keys,
    );
    plan.set_property(ctx, "templateCount", JSValue::int(templates.len() as i32));
    set_string_array_property(ctx, plan.raw(), "templates", templates);
    plan.set_property(
        ctx,
        "commandJsonTemplateCount",
        JSValue::int(command_json_template_count as i32),
    );
    plan.set_property(
        ctx,
        "commandJsonEligibleTemplateCount",
        JSValue::int(command_json_eligible_count as i32),
    );
    plan.set_property(ctx, "commandJsonTemplates", JSValue(command_json_templates_array));
    match &action.reason {
        Some(reason) => plan.set_property(ctx, "reason", JSValue::string(ctx, reason)),
        None => plan.set_property(ctx, "reason", JSValue::null()),
    };

    plan.raw()
}

unsafe fn hook_backend_adaptation_step_from_command_json_template_to_js(
    ctx: *mut ffi::JSContext,
    group_key: &str,
    allowed: bool,
    reason: &str,
    index: usize,
    template: ffi::JSValue,
) -> ffi::JSValue {
    let item = JSValue(ffi::JS_NewObject(ctx));
    let template_value = JSValue(template);
    let blocked_by = if allowed { "none" } else { "both" };
    let branch = if allowed { "run" } else { "blocked" };

    item.set_property(ctx, "index", JSValue::int(index as i32));
    item.set_property(
        ctx,
        "id",
        JSValue::string(ctx, &format!("backend-adaptation-preferred-group:{group_key}:{index}")),
    );
    item.set_property(
        ctx,
        "source",
        JSValue::string(ctx, "backend-adaptation-preferred-group"),
    );
    item.set_property(ctx, "actionKey", JSValue::null());
    item.set_property(ctx, "commandGroup", JSValue::string(ctx, group_key));
    item.set_property(ctx, "allowed", JSValue::bool(allowed));
    item.set_property(ctx, "blockedBy", JSValue::string(ctx, blocked_by));
    item.set_property(ctx, "branch", JSValue::string(ctx, branch));
    item.set_property(ctx, "reason", JSValue::string(ctx, reason));
    item.set_property(ctx, "preferredPath", JSValue::string(ctx, group_key));
    item.set_property(ctx, "readyToRun", JSValue::bool(allowed));
    item.set_property(ctx, "requiresFallback", JSValue::bool(false));
    item.set_property(ctx, "command", template_value.get_property(ctx, "command"));
    if group_key == "none" {
        item.set_property(ctx, "phase", JSValue::null());
    } else {
        item.set_property(ctx, "phase", JSValue::string(ctx, group_key));
    }
    item.set_property(
        ctx,
        "commandJsonEligible",
        template_value.get_property(ctx, "commandJsonEligible"),
    );
    item.set_property(ctx, "commandJsonTemplate", template_value.dup(ctx));
    item.set_property(
        ctx,
        "commandJsonTemplateCommand",
        template_value.get_property(ctx, "command"),
    );
    item.set_property(ctx, "commandJsonTemplateKind", template_value.get_property(ctx, "kind"));
    item.set_property(
        ctx,
        "commandJsonTemplateEligible",
        template_value.get_property(ctx, "commandJsonEligible"),
    );
    item.set_property(ctx, "kind", template_value.get_property(ctx, "kind"));
    item.set_property(ctx, "retryable", template_value.get_property(ctx, "retryable"));
    item.set_property(
        ctx,
        "maxSuggestedRetries",
        template_value.get_property(ctx, "maxSuggestedRetries"),
    );
    item.set_property(
        ctx,
        "retryDelayHintMs",
        template_value.get_property(ctx, "retryDelayHintMs"),
    );
    item.set_property(ctx, "timeoutHintMs", template_value.get_property(ctx, "timeoutHintMs"));
    item.set_property(ctx, "timeoutAction", template_value.get_property(ctx, "timeoutAction"));
    item.set_property(ctx, "errorCode", template_value.get_property(ctx, "errorCode"));
    item.set_property(
        ctx,
        "timeoutErrorCode",
        template_value.get_property(ctx, "timeoutErrorCode"),
    );
    item.set_property(ctx, "risk", template_value.get_property(ctx, "risk"));
    item.set_property(
        ctx,
        "placeholderCount",
        template_value.get_property(ctx, "placeholderCount"),
    );
    item.set_property(ctx, "placeholders", template_value.get_property(ctx, "placeholders"));
    item.set_property(ctx, "cliArgs", template_value.get_property(ctx, "cliArgs"));

    item.raw()
}

fn hook_backend_adaptation_topology_kind(
    loaded_backend_count: usize,
    filesystem_only_backend_count: usize,
) -> &'static str {
    if loaded_backend_count > 1 {
        "split-loaded"
    } else if loaded_backend_count == 1 {
        "shared-loaded"
    } else if filesystem_only_backend_count > 0 {
        "filesystem-only"
    } else {
        "clean"
    }
}

fn hook_backend_adaptation_alignment(topology_kind: &str) -> &'static str {
    match topology_kind {
        "clean" => "clean",
        "filesystem-only" => "filesystem-only",
        "shared-loaded" => "shared",
        "split-loaded" => "split",
        _ => "unknown",
    }
}

fn hook_backend_adaptation_mode(topology_kind: &str) -> &'static str {
    match topology_kind {
        "clean" => "no-adaptation-needed",
        "filesystem-only" => "preflight-before-inline",
        "shared-loaded" => "shared-runtime-query-first",
        "split-loaded" => "runtime-alignment-required",
        _ => "unknown",
    }
}

fn hook_backend_adaptation_summary(recommended_action_bias: &str, topology_kind: &str) -> &'static str {
    match recommended_action_bias {
        "blocked" => "no compatible hook path is currently available",
        "cleanup" => {
            "current policy only allows cleanup or status commands; stop existing hooks before retrying"
        }
        "preflight" => {
            "only filesystem backend artifacts were detected; run preflight before inline install"
        }
        "install" => "no external backend runtime pressure is active; inline install can proceed directly",
        "query" => match topology_kind {
            "shared-loaded" => {
                "an external backend runtime is already loaded in this process; query first before changing hook state"
            }
            "split-loaded" => {
                "multiple external backend runtimes are loaded in this process; stay query-first until hook state is aligned"
            }
            _ => "query-first adaptation is recommended before changing hook state",
        },
        _ => "observe backend state before choosing an adaptation path",
    }
}

unsafe fn hook_single_process_backend_matrix_entry_to_js(
    ctx: *mut ffi::JSContext,
    backend: &native_api::HookBackendInfo,
) -> ffi::JSValue {
    let item = JSValue(ffi::JS_NewObject(ctx));
    let controller_loaded = !backend.loaded_images.is_empty();
    let controller_present_on_filesystem = !backend.filesystem_paths.is_empty();
    let visible_in_controller = controller_loaded || controller_present_on_filesystem;
    let filesystem_only_in_either = !controller_loaded && controller_present_on_filesystem;
    let visibility = if visible_in_controller { "controller" } else { "none" };
    let loaded_by = if controller_loaded { "controller" } else { "none" };

    item.set_property(ctx, "id", JSValue::string(ctx, &backend.id));
    item.set_property(ctx, "displayName", JSValue::string(ctx, &backend.display_name));
    item.set_property(ctx, "visibility", JSValue::string(ctx, visibility));
    item.set_property(ctx, "loadedBy", JSValue::string(ctx, loaded_by));
    item.set_property(ctx, "visibleInController", JSValue::bool(visible_in_controller));
    item.set_property(ctx, "visibleInTarget", JSValue::bool(false));
    item.set_property(ctx, "controllerLoaded", JSValue::bool(controller_loaded));
    item.set_property(ctx, "targetLoaded", JSValue::bool(false));
    item.set_property(
        ctx,
        "controllerPresentOnFilesystem",
        JSValue::bool(controller_present_on_filesystem),
    );
    item.set_property(ctx, "targetPresentOnFilesystem", JSValue::bool(false));
    item.set_property(
        ctx,
        "controllerLoadedImageCount",
        JSValue::int(backend.loaded_images.len() as i32),
    );
    item.set_property(ctx, "targetLoadedImageCount", JSValue::int(0));
    item.set_property(
        ctx,
        "controllerFilesystemPathCount",
        JSValue::int(backend.filesystem_paths.len() as i32),
    );
    item.set_property(ctx, "targetFilesystemPathCount", JSValue::int(0));
    item.set_property(ctx, "filesystemOnlyInEither", JSValue::bool(filesystem_only_in_either));

    item.raw()
}

unsafe fn hook_single_process_backend_matrix_to_js(
    ctx: *mut ffi::JSContext,
    report: &native_api::HookEnvironmentReport,
) -> ffi::JSValue {
    let result = JSValue(ffi::JS_NewObject(ctx));
    let entries = ffi::JS_NewArray(ctx);
    let mut visible_backend_ids = Vec::new();
    let mut loaded_only_in_controller_backend_ids = Vec::new();
    let mut filesystem_only_backend_ids = Vec::new();
    let mut loaded_in_controller_count = 0usize;
    let mut filesystem_only_in_either_count = 0usize;
    let empty_ids: Vec<String> = Vec::new();

    for (index, backend) in report.backends.iter().enumerate() {
        let controller_loaded = !backend.loaded_images.is_empty();
        let controller_present_on_filesystem = !backend.filesystem_paths.is_empty();
        let visible_in_controller = controller_loaded || controller_present_on_filesystem;
        let filesystem_only_in_either = !controller_loaded && controller_present_on_filesystem;

        if visible_in_controller {
            visible_backend_ids.push(backend.id.clone());
        }
        if controller_loaded {
            loaded_in_controller_count += 1;
            loaded_only_in_controller_backend_ids.push(backend.id.clone());
        }
        if filesystem_only_in_either {
            filesystem_only_in_either_count += 1;
            filesystem_only_backend_ids.push(backend.id.clone());
        }

        ffi::JS_SetPropertyUint32(
            ctx,
            entries,
            index as u32,
            hook_single_process_backend_matrix_entry_to_js(ctx, backend),
        );
    }

    let topology = JSValue(ffi::JS_NewObject(ctx));
    let topology_kind = if loaded_in_controller_count > 0 {
        "controller-loaded-only"
    } else if filesystem_only_in_either_count > 0 {
        "filesystem-only"
    } else {
        "clean"
    };
    topology.set_property(ctx, "kind", JSValue::string(ctx, topology_kind));
    topology.set_property(ctx, "sharedVisibility", JSValue::bool(false));
    topology.set_property(
        ctx,
        "controllerOnlyVisibility",
        JSValue::bool(!visible_backend_ids.is_empty()),
    );
    topology.set_property(ctx, "targetOnlyVisibility", JSValue::bool(false));
    topology.set_property(ctx, "sharedLoadedRuntime", JSValue::bool(false));
    topology.set_property(
        ctx,
        "controllerOnlyLoadedRuntime",
        JSValue::bool(!loaded_only_in_controller_backend_ids.is_empty()),
    );
    topology.set_property(ctx, "targetOnlyLoadedRuntime", JSValue::bool(false));
    topology.set_property(
        ctx,
        "filesystemOnlyArtifacts",
        JSValue::bool(!filesystem_only_backend_ids.is_empty()),
    );

    result.set_property(ctx, "entryCount", JSValue::int(report.backends.len() as i32));
    result.set_property(ctx, "entries", JSValue(entries));
    result.set_property(
        ctx,
        "loadedInControllerCount",
        JSValue::int(loaded_in_controller_count as i32),
    );
    result.set_property(ctx, "loadedInTargetCount", JSValue::int(0));
    result.set_property(ctx, "loadedInBothCount", JSValue::int(0));
    result.set_property(
        ctx,
        "filesystemOnlyInEitherCount",
        JSValue::int(filesystem_only_in_either_count as i32),
    );
    set_string_array_property(ctx, result.raw(), "sharedBackendIds", &empty_ids);
    set_string_array_property(ctx, result.raw(), "controllerOnlyBackendIds", &visible_backend_ids);
    set_string_array_property(ctx, result.raw(), "targetOnlyBackendIds", &empty_ids);
    set_string_array_property(ctx, result.raw(), "loadedInBothBackendIds", &empty_ids);
    set_string_array_property(
        ctx,
        result.raw(),
        "loadedOnlyInControllerBackendIds",
        &loaded_only_in_controller_backend_ids,
    );
    set_string_array_property(ctx, result.raw(), "loadedOnlyInTargetBackendIds", &empty_ids);
    set_string_array_property(
        ctx,
        result.raw(),
        "filesystemOnlyBackendIds",
        &filesystem_only_backend_ids,
    );
    result.set_property(ctx, "topology", topology);

    result.raw()
}

unsafe fn hook_set_command_template_group_properties(
    ctx: *mut ffi::JSContext,
    target: &JSValue,
    prefix: &str,
    templates: &[String],
) {
    let templates_key = format!("{prefix}Templates");
    let template_count_key = format!("{prefix}TemplateCount");
    let command_json_templates_key = format!("{prefix}CommandJsonTemplates");
    let command_json_template_count_key = format!("{prefix}CommandJsonTemplateCount");
    let command_json_eligible_template_count_key = format!("{prefix}CommandJsonEligibleTemplateCount");
    let command_json_templates = ffi::JS_NewArray(ctx);
    let mut command_json_eligible_count = 0usize;

    set_string_array_property(ctx, target.raw(), &templates_key, templates);
    target.set_property(ctx, &template_count_key, JSValue::int(templates.len() as i32));
    for (index, template) in templates.iter().enumerate() {
        let entry = JSValue(hook_command_json_template_to_js(ctx, template));
        if entry
            .get_property(ctx, "commandJsonEligible")
            .to_bool()
            .unwrap_or(false)
        {
            command_json_eligible_count += 1;
        }
        ffi::JS_SetPropertyUint32(ctx, command_json_templates, index as u32, entry.raw());
    }
    target.set_property(
        ctx,
        &command_json_template_count_key,
        JSValue::int(templates.len() as i32),
    );
    target.set_property(
        ctx,
        &command_json_eligible_template_count_key,
        JSValue::int(command_json_eligible_count as i32),
    );
    target.set_property(ctx, &command_json_templates_key, JSValue(command_json_templates));
}

unsafe fn hook_command_template_group_to_js(
    ctx: *mut ffi::JSContext,
    group_key: &str,
    templates: &[String],
) -> ffi::JSValue {
    let group = JSValue(ffi::JS_NewObject(ctx));
    let command_json_templates = ffi::JS_NewArray(ctx);
    let mut command_json_eligible_count = 0usize;

    group.set_property(ctx, "groupKey", JSValue::string(ctx, group_key));
    set_string_array_property(ctx, group.raw(), "templates", templates);
    group.set_property(ctx, "templateCount", JSValue::int(templates.len() as i32));
    for (index, template) in templates.iter().enumerate() {
        let entry = JSValue(hook_command_json_template_to_js(ctx, template));
        if entry
            .get_property(ctx, "commandJsonEligible")
            .to_bool()
            .unwrap_or(false)
        {
            command_json_eligible_count += 1;
        }
        ffi::JS_SetPropertyUint32(ctx, command_json_templates, index as u32, entry.raw());
    }
    group.set_property(ctx, "commandJsonTemplateCount", JSValue::int(templates.len() as i32));
    group.set_property(
        ctx,
        "commandJsonEligibleTemplateCount",
        JSValue::int(command_json_eligible_count as i32),
    );
    group.set_property(ctx, "commandJsonTemplates", JSValue(command_json_templates));
    match templates.first() {
        Some(template) => {
            let primary_command_json_template = JSValue(hook_command_json_template_to_js(ctx, template));
            group.set_property(
                ctx,
                "primaryCommandJsonTemplateCommand",
                primary_command_json_template.get_property(ctx, "command"),
            );
            group.set_property(
                ctx,
                "primaryCommandJsonTemplateKind",
                primary_command_json_template.get_property(ctx, "kind"),
            );
            group.set_property(
                ctx,
                "primaryCommandJsonTemplateEligible",
                primary_command_json_template.get_property(ctx, "commandJsonEligible"),
            );
            group.set_property(ctx, "primaryCommandJsonTemplate", primary_command_json_template);
        }
        None => {
            group.set_property(ctx, "primaryCommandJsonTemplate", JSValue::null());
            group.set_property(ctx, "primaryCommandJsonTemplateCommand", JSValue::null());
            group.set_property(ctx, "primaryCommandJsonTemplateKind", JSValue::null());
            group.set_property(ctx, "primaryCommandJsonTemplateEligible", JSValue::null());
        }
    }

    group.raw()
}

unsafe fn hook_backend_specific_recommendation_to_js(
    ctx: *mut ffi::JSContext,
    backend: &native_api::HookBackendInfo,
    scope: &str,
    state: &str,
    loaded_by: &str,
    suggested_group_key: &str,
    suggested_phase: &str,
    reason: &str,
    priority: u8,
    templates: &[String],
) -> ffi::JSValue {
    let item = JSValue(ffi::JS_NewObject(ctx));
    let (command_json_templates, command_json_eligible_template_count) =
        hook_command_json_template_array_to_js(ctx, templates);

    item.set_property(ctx, "backendId", JSValue::string(ctx, &backend.id));
    item.set_property(ctx, "displayName", JSValue::string(ctx, &backend.display_name));
    item.set_property(ctx, "scope", JSValue::string(ctx, scope));
    item.set_property(ctx, "state", JSValue::string(ctx, state));
    item.set_property(ctx, "visibleInController", JSValue::null());
    item.set_property(ctx, "visibleInTarget", JSValue::null());
    item.set_property(ctx, "loadedBy", JSValue::string(ctx, loaded_by));
    item.set_property(ctx, "suggestedGroupKey", JSValue::string(ctx, suggested_group_key));
    item.set_property(ctx, "suggestedPhase", JSValue::string(ctx, suggested_phase));
    item.set_property(ctx, "reason", JSValue::string(ctx, reason));
    item.set_property(ctx, "priority", JSValue::int(priority as i32));
    item.set_property(ctx, "templateCount", JSValue::int(templates.len() as i32));
    set_string_array_property(ctx, item.raw(), "templates", templates);
    item.set_property(ctx, "commandJsonTemplateCount", JSValue::int(templates.len() as i32));
    item.set_property(ctx, "commandJsonTemplates", JSValue(command_json_templates));
    item.set_property(
        ctx,
        "commandJsonEligibleTemplateCount",
        JSValue::int(command_json_eligible_template_count as i32),
    );
    match templates.first() {
        Some(template) => {
            let primary = JSValue(hook_command_json_template_to_js(ctx, template));
            item.set_property(
                ctx,
                "primaryCommandJsonTemplateCommand",
                primary.get_property(ctx, "command"),
            );
            item.set_property(ctx, "primaryCommandJsonTemplateKind", primary.get_property(ctx, "kind"));
            item.set_property(
                ctx,
                "primaryCommandJsonTemplateEligible",
                primary.get_property(ctx, "commandJsonEligible"),
            );
            item.set_property(ctx, "primaryCommandJsonTemplate", primary);
        }
        None => {
            item.set_property(ctx, "primaryCommandJsonTemplate", JSValue::null());
            item.set_property(ctx, "primaryCommandJsonTemplateCommand", JSValue::null());
            item.set_property(ctx, "primaryCommandJsonTemplateKind", JSValue::null());
            item.set_property(ctx, "primaryCommandJsonTemplateEligible", JSValue::null());
        }
    }

    item.raw()
}

fn hook_conflict_resolution_phase_retry_policy(phase: &str) -> (bool, u32, u64) {
    match phase {
        "preflight" => (true, 2, 500),
        "query" => (true, 1, 250),
        "cleanup" => (true, 1, 250),
        _ => (false, 0, 0),
    }
}

fn hook_conflict_resolution_phase_timeout_policy(phase: &str) -> (u64, &'static str) {
    match phase {
        "preflight" => (8000, "re-run-preflight-or-switch-to-query-only"),
        "query" => (5000, "narrow-query-filter-and-retry"),
        "cleanup" => (6000, "retry-cleanup-or-escalate-to-preflight"),
        _ => (5000, "abort-and-escalate"),
    }
}

fn hook_conflict_resolution_phase_failure_code(phase: &str) -> &'static str {
    match phase {
        "preflight" => "hook-fallback-preflight-failed",
        "query" => "hook-fallback-query-failed",
        "cleanup" => "hook-fallback-cleanup-failed",
        _ => "hook-fallback-general-failed",
    }
}

fn hook_conflict_resolution_phase_timeout_error_code(phase: &str) -> &'static str {
    match phase {
        "preflight" => "hook-fallback-preflight-timeout",
        "query" => "hook-fallback-query-timeout",
        "cleanup" => "hook-fallback-cleanup-timeout",
        _ => "hook-fallback-general-timeout",
    }
}

fn hook_conflict_resolution_steps_for_group(group_key: &str) -> Vec<(&'static str, &'static str, &'static str)> {
    match group_key {
        "query" => vec![
            (
                "query",
                "query",
                "use runtime queries first to inspect the mismatched backend states in this process",
            ),
            (
                "preflight",
                "preflight",
                "refresh diagnostics after querying before attempting to realign backend runtimes",
            ),
        ],
        "preflight" => vec![
            (
                "preflight",
                "preflight",
                "refresh diagnostics before choosing a runtime alignment action",
            ),
            (
                "query",
                "query",
                "use runtime queries after preflight to confirm backend visibility and scope",
            ),
        ],
        "cleanup" => vec![(
            "cleanup",
            "cleanup",
            "clean up active hook state before attempting to realign backend runtimes",
        )],
        _ => Vec::new(),
    }
}

fn hook_backend_templates_for_group<'a>(
    group_key: &str,
    query_templates: &'a [String],
    preflight_templates: &'a [String],
    cleanup_templates: &'a [String],
) -> &'a [String] {
    match group_key {
        "query" => query_templates,
        "preflight" => preflight_templates,
        "cleanup" => cleanup_templates,
        _ => &[],
    }
}

unsafe fn hook_backend_conflict_resolution_chain_entry_to_js(
    ctx: *mut ffi::JSContext,
    index: usize,
    group_key: &str,
    phase: &str,
    reason: &str,
    templates: &[String],
) -> ffi::JSValue {
    let item = JSValue(ffi::JS_NewObject(ctx));
    let (command_json_templates, command_json_eligible_template_count) =
        hook_command_json_template_array_to_js(ctx, templates);
    let (retryable, max_suggested_retries, retry_delay_hint_ms) = hook_conflict_resolution_phase_retry_policy(phase);
    let (timeout_hint_ms, timeout_action) = hook_conflict_resolution_phase_timeout_policy(phase);

    item.set_property(
        ctx,
        "id",
        JSValue::string(ctx, &format!("conflict-resolution:{group_key}:{index}")),
    );
    item.set_property(ctx, "index", JSValue::int(index as i32));
    item.set_property(ctx, "groupKey", JSValue::string(ctx, group_key));
    item.set_property(ctx, "phase", JSValue::string(ctx, phase));
    item.set_property(ctx, "reason", JSValue::string(ctx, reason));
    item.set_property(ctx, "retryable", JSValue::bool(retryable));
    item.set_property(ctx, "maxSuggestedRetries", JSValue::int(max_suggested_retries as i32));
    item.set_property(
        ctx,
        "retryDelayHintMs",
        JSValue(js_u64_to_js_number_or_bigint(ctx, retry_delay_hint_ms as u64)),
    );
    item.set_property(
        ctx,
        "timeoutHintMs",
        JSValue(js_u64_to_js_number_or_bigint(ctx, timeout_hint_ms)),
    );
    item.set_property(ctx, "timeoutAction", JSValue::string(ctx, timeout_action));
    item.set_property(
        ctx,
        "errorCode",
        JSValue::string(ctx, hook_conflict_resolution_phase_failure_code(phase)),
    );
    item.set_property(
        ctx,
        "timeoutErrorCode",
        JSValue::string(ctx, hook_conflict_resolution_phase_timeout_error_code(phase)),
    );
    item.set_property(ctx, "templateCount", JSValue::int(templates.len() as i32));
    set_string_array_property(ctx, item.raw(), "templates", templates);
    item.set_property(ctx, "commandJsonTemplateCount", JSValue::int(templates.len() as i32));
    item.set_property(ctx, "commandJsonTemplates", JSValue(command_json_templates));
    item.set_property(
        ctx,
        "commandJsonEligibleTemplateCount",
        JSValue::int(command_json_eligible_template_count as i32),
    );

    item.raw()
}

unsafe fn hook_conflict_resolution_routing_to_js(
    ctx: *mut ffi::JSContext,
    steps: &[(&str, &str, &str)],
    query_templates: &[String],
    preflight_templates: &[String],
    cleanup_templates: &[String],
) -> ffi::JSValue {
    use std::collections::BTreeMap;

    struct PhaseRoutingSummary {
        error_codes: Vec<String>,
        escalation_keys: Vec<String>,
        templates: Vec<String>,
    }

    if steps.is_empty() {
        return JSValue::null().raw();
    }

    let routing = JSValue(ffi::JS_NewObject(ctx));
    let phase_retry_policies = ffi::JS_NewArray(ctx);
    let phase_timeout_policies = ffi::JS_NewArray(ctx);
    let phase_error_codes = ffi::JS_NewArray(ctx);
    let escalation_recommendations = ffi::JS_NewArray(ctx);

    let mut error_code_routing_candidates = BTreeMap::<String, (String, String, Vec<String>)>::new();
    let mut phase_summaries = BTreeMap::<String, PhaseRoutingSummary>::new();

    for (index, (group_key, phase, reason)) in steps.iter().enumerate() {
        let templates =
            hook_backend_templates_for_group(group_key, query_templates, preflight_templates, cleanup_templates);
        let (retryable, max_suggested_retries, retry_delay_hint_ms) =
            hook_conflict_resolution_phase_retry_policy(phase);
        let (timeout_hint_ms, timeout_action) = hook_conflict_resolution_phase_timeout_policy(phase);
        let error_code = hook_conflict_resolution_phase_failure_code(phase).to_string();
        let timeout_error_code = hook_conflict_resolution_phase_timeout_error_code(phase).to_string();
        let escalation_key = format!("conflict-{group_key}");

        let phase_summary = phase_summaries
            .entry((*phase).to_string())
            .or_insert_with(|| PhaseRoutingSummary {
                error_codes: Vec::new(),
                escalation_keys: Vec::new(),
                templates: Vec::new(),
            });
        for code in [&error_code, &timeout_error_code] {
            if !phase_summary.error_codes.iter().any(|item| item == code) {
                phase_summary.error_codes.push(code.clone());
            }
        }
        if !phase_summary.escalation_keys.iter().any(|item| item == &escalation_key) {
            phase_summary.escalation_keys.push(escalation_key.clone());
        }
        for template in templates {
            if !phase_summary.templates.iter().any(|item| item == template) {
                phase_summary.templates.push(template.clone());
            }
        }

        let retry_policy = JSValue(ffi::JS_NewObject(ctx));
        retry_policy.set_property(ctx, "phase", JSValue::string(ctx, phase));
        retry_policy.set_property(ctx, "retryable", JSValue::bool(retryable));
        retry_policy.set_property(ctx, "maxSuggestedRetries", JSValue::int(max_suggested_retries as i32));
        retry_policy.set_property(
            ctx,
            "retryDelayHintMs",
            JSValue(js_u64_to_js_number_or_bigint(ctx, retry_delay_hint_ms as u64)),
        );
        retry_policy.set_property(
            ctx,
            "timeoutHintMs",
            JSValue(js_u64_to_js_number_or_bigint(ctx, timeout_hint_ms)),
        );
        retry_policy.set_property(ctx, "timeoutAction", JSValue::string(ctx, timeout_action));
        retry_policy.set_property(ctx, "errorCode", JSValue::string(ctx, &error_code));
        retry_policy.set_property(ctx, "timeoutErrorCode", JSValue::string(ctx, &timeout_error_code));
        ffi::JS_SetPropertyUint32(ctx, phase_retry_policies, index as u32, retry_policy.raw());

        let timeout_policy = JSValue(ffi::JS_NewObject(ctx));
        timeout_policy.set_property(ctx, "phase", JSValue::string(ctx, phase));
        timeout_policy.set_property(
            ctx,
            "timeoutHintMs",
            JSValue(js_u64_to_js_number_or_bigint(ctx, timeout_hint_ms)),
        );
        timeout_policy.set_property(ctx, "timeoutAction", JSValue::string(ctx, timeout_action));
        timeout_policy.set_property(ctx, "errorCode", JSValue::string(ctx, &error_code));
        timeout_policy.set_property(ctx, "timeoutErrorCode", JSValue::string(ctx, &timeout_error_code));
        ffi::JS_SetPropertyUint32(ctx, phase_timeout_policies, index as u32, timeout_policy.raw());

        let error_codes = JSValue(ffi::JS_NewObject(ctx));
        error_codes.set_property(ctx, "phase", JSValue::string(ctx, phase));
        error_codes.set_property(ctx, "errorCode", JSValue::string(ctx, &error_code));
        error_codes.set_property(ctx, "timeoutErrorCode", JSValue::string(ctx, &timeout_error_code));
        ffi::JS_SetPropertyUint32(ctx, phase_error_codes, index as u32, error_codes.raw());

        let recommendation = JSValue(hook_escalation_recommendation_to_js(
            ctx,
            &escalation_key,
            &format!("phase-{phase}-failed"),
            phase,
            reason,
            None,
            templates,
            &[error_code.clone(), timeout_error_code.clone()],
        ));
        ffi::JS_SetPropertyUint32(ctx, escalation_recommendations, index as u32, recommendation.raw());

        for code in [error_code, timeout_error_code] {
            error_code_routing_candidates
                .entry(code)
                .or_insert_with(|| (escalation_key.clone(), (*phase).to_string(), templates.to_vec()));
        }
    }

    let error_code_routing = JSValue(ffi::JS_NewObject(ctx));
    let error_code_routing_entries = ffi::JS_NewArray(ctx);
    let error_code_routing_resolved = JSValue(ffi::JS_NewObject(ctx));
    for (entry_index, (error_code, (escalation_key, phase, templates))) in
        error_code_routing_candidates.iter().enumerate()
    {
        let (command_json_templates, _) = hook_command_json_template_array_to_js(ctx, templates);
        let resolved = JSValue(ffi::JS_NewObject(ctx));
        resolved.set_property(ctx, "escalationKey", JSValue::string(ctx, escalation_key));
        resolved.set_property(ctx, "effectiveEscalationKey", JSValue::string(ctx, escalation_key));
        resolved.set_property(ctx, "phase", JSValue::string(ctx, phase));
        resolved.set_property(ctx, "effectivePhase", JSValue::string(ctx, phase));
        resolved.set_property(ctx, "templateCount", JSValue::int(templates.len() as i32));
        set_string_array_property(ctx, resolved.raw(), "templates", templates);
        resolved.set_property(ctx, "commandJsonTemplateCount", JSValue::int(templates.len() as i32));
        resolved.set_property(ctx, "commandJsonTemplates", JSValue(command_json_templates));

        error_code_routing.set_property(ctx, error_code, JSValue::string(ctx, escalation_key));
        error_code_routing_resolved.set_property(ctx, error_code, resolved.dup(ctx));

        let entry = JSValue(ffi::JS_NewObject(ctx));
        entry.set_property(ctx, "errorCode", JSValue::string(ctx, error_code));
        entry.set_property(ctx, "candidateCount", JSValue::int(1));
        entry.set_property(
            ctx,
            "candidateEscalationKeys",
            JSValue(string_vec_to_js_array(ctx, &[escalation_key.clone()])),
        );
        entry.set_property(ctx, "recommendedEscalationKey", JSValue::string(ctx, escalation_key));
        entry.set_property(ctx, "effectiveEscalationKey", JSValue::string(ctx, escalation_key));
        entry.set_property(ctx, "matchConfidence", JSValue::string(ctx, "exact"));
        entry.set_property(ctx, "resolvedFrom", JSValue::string(ctx, "errorCodeRouting"));
        entry.set_property(ctx, "recommendedPhase", JSValue::string(ctx, phase));
        entry.set_property(ctx, "effectivePhase", JSValue::string(ctx, phase));
        entry.set_property(ctx, "templateCount", JSValue::int(templates.len() as i32));
        entry.set_property(ctx, "commandJsonTemplateCount", JSValue::int(templates.len() as i32));
        ffi::JS_SetPropertyUint32(ctx, error_code_routing_entries, entry_index as u32, entry.raw());
        resolved.free(ctx);
    }

    let (default_group_key, default_phase, _) = steps[0];
    let default_templates = hook_backend_templates_for_group(
        default_group_key,
        query_templates,
        preflight_templates,
        cleanup_templates,
    );
    let default_escalation_key = format!("conflict-{default_group_key}");
    let (default_command_json_templates, _) = hook_command_json_template_array_to_js(ctx, default_templates);

    let default_value = JSValue(ffi::JS_NewObject(ctx));
    default_value.set_property(ctx, "matchConfidence", JSValue::string(ctx, "default"));
    default_value.set_property(
        ctx,
        "resolvedFrom",
        JSValue::string(ctx, "defaultRecommendedEscalationKey"),
    );
    default_value.set_property(ctx, "escalationKey", JSValue::string(ctx, &default_escalation_key));
    default_value.set_property(
        ctx,
        "effectiveEscalationKey",
        JSValue::string(ctx, &default_escalation_key),
    );
    default_value.set_property(ctx, "phase", JSValue::string(ctx, default_phase));
    default_value.set_property(ctx, "effectivePhase", JSValue::string(ctx, default_phase));
    default_value.set_property(ctx, "templateCount", JSValue::int(default_templates.len() as i32));
    set_string_array_property(ctx, default_value.raw(), "templates", default_templates);
    default_value.set_property(
        ctx,
        "commandJsonTemplateCount",
        JSValue::int(default_templates.len() as i32),
    );
    default_value.set_property(ctx, "commandJsonTemplates", JSValue(default_command_json_templates));

    let routing_decision = JSValue(ffi::JS_NewObject(ctx));
    routing_decision.set_property(ctx, "lookupKey", JSValue::string(ctx, "errorCode"));
    routing_decision.set_property(ctx, "policy", JSValue::string(ctx, "index-then-default"));
    routing_decision.set_property(
        ctx,
        "outputShape",
        JSValue::string(ctx, "{ escalationKey, effectiveEscalationKey, phase, effectivePhase }"),
    );
    routing_decision.set_property(
        ctx,
        "entryCount",
        JSValue::int(error_code_routing_candidates.len() as i32),
    );
    routing_decision.set_property(ctx, "entries", JSValue(error_code_routing_entries).dup(ctx));
    routing_decision.set_property(
        ctx,
        "defaultRecommendedEscalationKey",
        JSValue::string(ctx, &default_escalation_key),
    );
    routing_decision.set_property(ctx, "defaultRecommendedPhase", JSValue::string(ctx, default_phase));
    routing_decision.set_property(
        ctx,
        "defaultEffectiveEscalationKey",
        JSValue::string(ctx, &default_escalation_key),
    );
    routing_decision.set_property(ctx, "defaultEffectivePhase", JSValue::string(ctx, default_phase));
    routing_decision.set_property(
        ctx,
        "defaultRecommendedTemplateCount",
        JSValue::int(default_templates.len() as i32),
    );
    set_string_array_property(
        ctx,
        routing_decision.raw(),
        "defaultRecommendedTemplates",
        default_templates,
    );
    routing_decision.set_property(
        ctx,
        "defaultRecommendedCommandJsonTemplateCount",
        JSValue::int(default_templates.len() as i32),
    );
    routing_decision.set_property(
        ctx,
        "defaultRecommendedCommandJsonTemplates",
        default_value.get_property(ctx, "commandJsonTemplates"),
    );
    routing_decision.set_property(ctx, "default", default_value.dup(ctx));

    let ready_value = JSValue(ffi::JS_NewObject(ctx));
    ready_value.set_property(ctx, "lookupRule", JSValue::string(ctx, "index[errorCode] || default"));
    ready_value.set_property(
        ctx,
        "entryCount",
        JSValue::int(error_code_routing_candidates.len() as i32),
    );
    ready_value.set_property(ctx, "index", error_code_routing_resolved.dup(ctx));
    ready_value.set_property(ctx, "default", default_value.dup(ctx));
    ready_value.set_property(
        ctx,
        "defaultEscalationKey",
        JSValue::string(ctx, &default_escalation_key),
    );
    ready_value.set_property(
        ctx,
        "defaultEffectiveEscalationKey",
        JSValue::string(ctx, &default_escalation_key),
    );
    ready_value.set_property(ctx, "defaultPhase", JSValue::string(ctx, default_phase));
    ready_value.set_property(ctx, "defaultEffectivePhase", JSValue::string(ctx, default_phase));
    ready_value.set_property(
        ctx,
        "defaultTemplateCount",
        JSValue::int(default_templates.len() as i32),
    );
    set_string_array_property(ctx, ready_value.raw(), "defaultTemplates", default_templates);
    let (ready_default_command_json_templates, _) = hook_command_json_template_array_to_js(ctx, default_templates);
    ready_value.set_property(
        ctx,
        "defaultCommandJsonTemplateCount",
        JSValue::int(default_templates.len() as i32),
    );
    ready_value.set_property(
        ctx,
        "defaultCommandJsonTemplates",
        JSValue(ready_default_command_json_templates),
    );
    let default_templates_alias = ready_value.get_property(ctx, "defaultTemplates");
    ready_value.set_property(ctx, "defaultTemplate", js_array_first(default_templates_alias, ctx));
    let default_command_json_templates_alias = ready_value.get_property(ctx, "defaultCommandJsonTemplates");
    let default_command_json_template = js_array_first(default_command_json_templates_alias, ctx);
    ready_value.set_property(
        ctx,
        "defaultCommandJsonTemplate",
        default_command_json_template.dup(ctx),
    );
    ready_value.set_property(
        ctx,
        "defaultCommandJsonTemplateCommand",
        default_command_json_template.get_property(ctx, "command"),
    );
    ready_value.set_property(
        ctx,
        "defaultCommandJsonTemplateKind",
        default_command_json_template.get_property(ctx, "kind"),
    );
    ready_value.set_property(
        ctx,
        "defaultCommandJsonTemplatePhase",
        default_command_json_template.get_property(ctx, "phase"),
    );
    ready_value.set_property(
        ctx,
        "defaultCommandJsonTemplateErrorCode",
        default_command_json_template.get_property(ctx, "errorCode"),
    );
    ready_value.set_property(
        ctx,
        "defaultCommandJsonTemplateEligible",
        default_command_json_template.get_property(ctx, "commandJsonEligible"),
    );
    default_command_json_template.free(ctx);

    let resolve_index = JSValue(ffi::JS_NewObject(ctx));
    let known_error_codes = error_code_routing_candidates.keys().cloned().collect::<Vec<_>>();
    for error_code in &known_error_codes {
        let Some((escalation_key, phase, _)) = error_code_routing_candidates.get(error_code) else {
            continue;
        };
        let effective = error_code_routing_resolved.get_property(ctx, error_code);
        let resolved = JSValue(ffi::JS_NewObject(ctx));
        resolved.set_property(ctx, "matched", JSValue::bool(true));
        resolved.set_property(ctx, "usedDefault", JSValue::bool(false));
        resolved.set_property(ctx, "reason", JSValue::string(ctx, "matched-error-code"));
        resolved.set_property(ctx, "effectivePhase", JSValue::string(ctx, phase));
        resolved.set_property(ctx, "effectiveEscalationKey", JSValue::string(ctx, escalation_key));
        resolved.set_property(ctx, "effective", effective);
        resolve_index.set_property(ctx, error_code, resolved);
    }

    let resolve_default = JSValue(ffi::JS_NewObject(ctx));
    resolve_default.set_property(ctx, "matched", JSValue::bool(false));
    resolve_default.set_property(ctx, "usedDefault", JSValue::bool(true));
    resolve_default.set_property(ctx, "reason", JSValue::string(ctx, "missing-error-code"));
    resolve_default.set_property(ctx, "effectivePhase", JSValue::string(ctx, default_phase));
    resolve_default.set_property(
        ctx,
        "effectiveEscalationKey",
        JSValue::string(ctx, &default_escalation_key),
    );
    resolve_default.set_property(ctx, "effective", default_value.dup(ctx));

    let resolve_examples = JSValue(ffi::JS_NewObject(ctx));
    match known_error_codes.first() {
        Some(error_code) => {
            resolve_examples.set_property(ctx, "knownErrorCode", JSValue::string(ctx, error_code));
            resolve_examples.set_property(ctx, "knownResult", resolve_index.get_property(ctx, error_code));
        }
        None => {
            resolve_examples.set_property(ctx, "knownErrorCode", JSValue::null());
            resolve_examples.set_property(ctx, "knownResult", JSValue::null());
        }
    }
    resolve_examples.set_property(ctx, "missingErrorCode", JSValue::string(ctx, "hook-fallback-unknown"));
    resolve_examples.set_property(ctx, "missingResult", resolve_default.dup(ctx));
    let query_only_error_code = "hook-fallback-hook-install-failed";
    let query_only_blocked_by = "shared-process-conflict";
    let query_only_result = resolve_index.get_property(ctx, query_only_error_code);
    let query_only_result_available = !(query_only_result.is_null() || query_only_result.is_undefined());
    let query_only_example = JSValue(ffi::JS_NewObject(ctx));
    query_only_example.set_property(ctx, "errorCode", JSValue::string(ctx, query_only_error_code));
    query_only_example.set_property(ctx, "blockedBy", JSValue::string(ctx, query_only_blocked_by));
    query_only_example.set_property(ctx, "blockedBySource", JSValue::string(ctx, query_only_blocked_by));
    query_only_example.set_property(ctx, "isBlocked", JSValue::bool(true));
    query_only_example.set_property(ctx, "available", JSValue::bool(query_only_result_available));
    if query_only_result_available {
        let effective_key = query_only_result.get_property(ctx, "effectiveEscalationKey");
        query_only_example.set_property(ctx, "matched", query_only_result.get_property(ctx, "matched"));
        query_only_example.set_property(ctx, "usedDefault", query_only_result.get_property(ctx, "usedDefault"));
        query_only_example.set_property(ctx, "reason", query_only_result.get_property(ctx, "reason"));
        query_only_example.set_property(
            ctx,
            "effectivePhase",
            query_only_result.get_property(ctx, "effectivePhase"),
        );
        query_only_example.set_property(ctx, "effectiveEscalationKey", effective_key.dup(ctx));
        query_only_example.set_property(ctx, "result", query_only_result.dup(ctx));
        query_only_example.set_property(
            ctx,
            "wouldUseQueryOnlyPath",
            JSValue::bool(effective_key.to_string(ctx).as_deref() == Some("query-only-path")),
        );
        effective_key.free(ctx);
    } else {
        query_only_example.set_property(ctx, "matched", JSValue::bool(false));
        query_only_example.set_property(ctx, "usedDefault", JSValue::bool(true));
        query_only_example.set_property(ctx, "reason", JSValue::string(ctx, "missing-error-code"));
        query_only_example.set_property(ctx, "effectivePhase", JSValue::null());
        query_only_example.set_property(ctx, "effectiveEscalationKey", JSValue::null());
        query_only_example.set_property(ctx, "result", JSValue::null());
        query_only_example.set_property(ctx, "wouldUseQueryOnlyPath", JSValue::bool(false));
    }
    resolve_examples.set_property(ctx, "queryOnlyInstallFailure", query_only_example.dup(ctx));

    let resolve_value = JSValue(ffi::JS_NewObject(ctx));
    resolve_value.set_property(ctx, "lookupKey", JSValue::string(ctx, "errorCode"));
    resolve_value.set_property(ctx, "policy", JSValue::string(ctx, "index[errorCode] || default"));
    resolve_value.set_property(ctx, "outputShape", JSValue::string(ctx, "effective"));
    resolve_value.set_property(ctx, "index", resolve_index);
    resolve_value.set_property(ctx, "default", resolve_default);
    resolve_value.set_property(ctx, "examples", resolve_examples);
    ready_value.set_property(ctx, "resolve", resolve_value.dup(ctx));
    ready_value.set_property(ctx, "resolveLookupKey", JSValue::string(ctx, "errorCode"));
    ready_value.set_property(
        ctx,
        "resolvePolicy",
        JSValue::string(ctx, "index[errorCode] || default"),
    );
    ready_value.set_property(ctx, "resolveOutputShape", JSValue::string(ctx, "effective"));
    ready_value.set_property(ctx, "resolveIndex", resolve_value.get_property(ctx, "index"));
    ready_value.set_property(ctx, "resolveIndexEntries", resolve_value.get_property(ctx, "index"));
    ready_value.set_property(ctx, "resolveDefault", resolve_value.get_property(ctx, "default"));
    ready_value.set_property(ctx, "resolveExamples", resolve_value.get_property(ctx, "examples"));
    ready_value.set_property(
        ctx,
        "resolveErrorCodeCount",
        JSValue::int(known_error_codes.len() as i32),
    );
    ready_value.set_property(ctx, "resolveIndexCount", JSValue::int(known_error_codes.len() as i32));
    ready_value.set_property(ctx, "resolveKnownCount", JSValue::int(known_error_codes.len() as i32));
    ready_value.set_property(
        ctx,
        "resolveKnownErrorCodes",
        JSValue(string_vec_to_js_array(ctx, &known_error_codes)),
    );
    ready_value.set_property(
        ctx,
        "resolveDefaultMatched",
        resolve_default.get_property(ctx, "matched"),
    );
    ready_value.set_property(
        ctx,
        "resolveDefaultUsedDefault",
        resolve_default.get_property(ctx, "usedDefault"),
    );
    ready_value.set_property(ctx, "resolveDefaultReason", resolve_default.get_property(ctx, "reason"));
    ready_value.set_property(
        ctx,
        "resolveDefaultEffective",
        resolve_default.get_property(ctx, "effective"),
    );
    ready_value.set_property(
        ctx,
        "resolveDefaultEffectivePhase",
        resolve_default.get_property(ctx, "effectivePhase"),
    );
    ready_value.set_property(
        ctx,
        "resolveDefaultEffectiveEscalationKey",
        resolve_default.get_property(ctx, "effectiveEscalationKey"),
    );
    ready_value.set_property(
        ctx,
        "resolveExampleKnownErrorCode",
        resolve_examples.get_property(ctx, "knownErrorCode"),
    );
    let resolve_known_result = resolve_examples.get_property(ctx, "knownResult");
    ready_value.set_property(ctx, "resolveExampleKnownResult", resolve_known_result.dup(ctx));
    if resolve_known_result.is_null() || resolve_known_result.is_undefined() {
        ready_value.set_property(ctx, "resolveExampleKnownResultEffective", JSValue::null());
        ready_value.set_property(ctx, "resolveExampleKnownResultEffectivePhase", JSValue::null());
        ready_value.set_property(ctx, "resolveExampleKnownResultEffectiveEscalationKey", JSValue::null());
    } else {
        ready_value.set_property(
            ctx,
            "resolveExampleKnownResultEffective",
            resolve_known_result.get_property(ctx, "effective"),
        );
        ready_value.set_property(
            ctx,
            "resolveExampleKnownResultEffectivePhase",
            resolve_known_result.get_property(ctx, "effectivePhase"),
        );
        ready_value.set_property(
            ctx,
            "resolveExampleKnownResultEffectiveEscalationKey",
            resolve_known_result.get_property(ctx, "effectiveEscalationKey"),
        );
    }
    resolve_known_result.free(ctx);
    ready_value.set_property(
        ctx,
        "resolveExampleMissingErrorCode",
        resolve_examples.get_property(ctx, "missingErrorCode"),
    );
    let resolve_missing_result = resolve_examples.get_property(ctx, "missingResult");
    ready_value.set_property(ctx, "resolveExampleMissingResult", resolve_missing_result.dup(ctx));
    if resolve_missing_result.is_null() || resolve_missing_result.is_undefined() {
        ready_value.set_property(ctx, "resolveExampleMissingResultEffective", JSValue::null());
        ready_value.set_property(ctx, "resolveExampleMissingResultEffectivePhase", JSValue::null());
        ready_value.set_property(
            ctx,
            "resolveExampleMissingResultEffectiveEscalationKey",
            JSValue::null(),
        );
    } else {
        ready_value.set_property(
            ctx,
            "resolveExampleMissingResultEffective",
            resolve_missing_result.get_property(ctx, "effective"),
        );
        ready_value.set_property(
            ctx,
            "resolveExampleMissingResultEffectivePhase",
            resolve_missing_result.get_property(ctx, "effectivePhase"),
        );
        ready_value.set_property(
            ctx,
            "resolveExampleMissingResultEffectiveEscalationKey",
            resolve_missing_result.get_property(ctx, "effectiveEscalationKey"),
        );
    }
    ready_value.set_property(
        ctx,
        "resolveExampleMissingReason",
        resolve_missing_result.get_property(ctx, "reason"),
    );
    resolve_missing_result.free(ctx);
    ready_value.set_property(
        ctx,
        "resolveExampleQueryOnlyInstallFailure",
        query_only_example.dup(ctx),
    );
    ready_value.set_property(
        ctx,
        "resolveExampleQueryOnlyErrorCode",
        query_only_example.get_property(ctx, "errorCode"),
    );
    ready_value.set_property(
        ctx,
        "resolveExampleQueryOnlyBlockedBy",
        query_only_example.get_property(ctx, "blockedBy"),
    );
    ready_value.set_property(
        ctx,
        "resolveExampleQueryOnlyBlockedBySource",
        query_only_example.get_property(ctx, "blockedBySource"),
    );
    ready_value.set_property(
        ctx,
        "resolveExampleQueryOnlyIsBlocked",
        query_only_example.get_property(ctx, "isBlocked"),
    );
    ready_value.set_property(
        ctx,
        "resolveExampleQueryOnlyAvailable",
        query_only_example.get_property(ctx, "available"),
    );
    ready_value.set_property(
        ctx,
        "resolveExampleQueryOnlyMatched",
        query_only_example.get_property(ctx, "matched"),
    );
    ready_value.set_property(
        ctx,
        "resolveExampleQueryOnlyUsedDefault",
        query_only_example.get_property(ctx, "usedDefault"),
    );
    ready_value.set_property(
        ctx,
        "resolveExampleQueryOnlyReason",
        query_only_example.get_property(ctx, "reason"),
    );
    ready_value.set_property(
        ctx,
        "resolveExampleQueryOnlyEffectivePhase",
        query_only_example.get_property(ctx, "effectivePhase"),
    );
    ready_value.set_property(
        ctx,
        "resolveExampleQueryOnlyEffectiveEscalationKey",
        query_only_example.get_property(ctx, "effectiveEscalationKey"),
    );
    ready_value.set_property(
        ctx,
        "resolveExampleQueryOnlyWouldUsePath",
        query_only_example.get_property(ctx, "wouldUseQueryOnlyPath"),
    );
    let query_only_example_result = query_only_example.get_property(ctx, "result");
    ready_value.set_property(ctx, "resolveExampleQueryOnlyResult", query_only_example_result.dup(ctx));
    if query_only_example_result.is_null() || query_only_example_result.is_undefined() {
        ready_value.set_property(ctx, "resolveExampleQueryOnlyResultEffective", JSValue::null());
        ready_value.set_property(ctx, "resolveExampleQueryOnlyResultMatched", JSValue::null());
        ready_value.set_property(ctx, "resolveExampleQueryOnlyResultUsedDefault", JSValue::null());
        ready_value.set_property(ctx, "resolveExampleQueryOnlyResultReason", JSValue::null());
        ready_value.set_property(ctx, "resolveExampleQueryOnlyResultEffectivePhase", JSValue::null());
        ready_value.set_property(
            ctx,
            "resolveExampleQueryOnlyResultEffectiveEscalationKey",
            JSValue::null(),
        );
    } else {
        ready_value.set_property(
            ctx,
            "resolveExampleQueryOnlyResultEffective",
            query_only_example_result.get_property(ctx, "effective"),
        );
        ready_value.set_property(
            ctx,
            "resolveExampleQueryOnlyResultMatched",
            query_only_example_result.get_property(ctx, "matched"),
        );
        ready_value.set_property(
            ctx,
            "resolveExampleQueryOnlyResultUsedDefault",
            query_only_example_result.get_property(ctx, "usedDefault"),
        );
        ready_value.set_property(
            ctx,
            "resolveExampleQueryOnlyResultReason",
            query_only_example_result.get_property(ctx, "reason"),
        );
        ready_value.set_property(
            ctx,
            "resolveExampleQueryOnlyResultEffectivePhase",
            query_only_example_result.get_property(ctx, "effectivePhase"),
        );
        ready_value.set_property(
            ctx,
            "resolveExampleQueryOnlyResultEffectiveEscalationKey",
            query_only_example_result.get_property(ctx, "effectiveEscalationKey"),
        );
    }
    query_only_example_result.free(ctx);

    let phase_entries = ffi::JS_NewArray(ctx);
    let phase_index = JSValue(ffi::JS_NewObject(ctx));
    let mut known_phases = Vec::<String>::new();
    for (entry_index, (phase, summary)) in phase_summaries.iter().enumerate() {
        let phase_entry = JSValue(ffi::JS_NewObject(ctx));
        let (phase_command_json_templates, phase_command_json_eligible_template_count) =
            hook_command_json_template_array_to_js(ctx, &summary.templates);
        phase_entry.set_property(ctx, "phase", JSValue::string(ctx, phase));
        phase_entry.set_property(ctx, "errorCodeCount", JSValue::int(summary.error_codes.len() as i32));
        phase_entry.set_property(
            ctx,
            "errorCodes",
            JSValue(string_vec_to_js_array(ctx, &summary.error_codes)),
        );
        phase_entry.set_property(
            ctx,
            "escalationKeyCount",
            JSValue::int(summary.escalation_keys.len() as i32),
        );
        phase_entry.set_property(
            ctx,
            "escalationKeys",
            JSValue(string_vec_to_js_array(ctx, &summary.escalation_keys)),
        );
        phase_entry.set_property(ctx, "templateCount", JSValue::int(summary.templates.len() as i32));
        set_string_array_property(ctx, phase_entry.raw(), "templates", &summary.templates);
        phase_entry.set_property(
            ctx,
            "commandJsonTemplateCount",
            JSValue::int(summary.templates.len() as i32),
        );
        phase_entry.set_property(
            ctx,
            "commandJsonEligibleTemplateCount",
            JSValue::int(phase_command_json_eligible_template_count as i32),
        );
        phase_entry.set_property(ctx, "commandJsonTemplates", JSValue(phase_command_json_templates));
        ffi::JS_SetPropertyUint32(ctx, phase_entries, entry_index as u32, phase_entry.dup(ctx).raw());
        phase_index.set_property(ctx, phase, phase_entry);
        known_phases.push(phase.clone());
    }

    let phase_query = phase_index.get_property(ctx, "query");
    if phase_query.is_null() || phase_query.is_undefined() {
        ready_value.set_property(ctx, "phaseQuery", JSValue::null());
    } else {
        ready_value.set_property(ctx, "phaseQuery", phase_query);
    }
    let phase_preflight = phase_index.get_property(ctx, "preflight");
    if phase_preflight.is_null() || phase_preflight.is_undefined() {
        ready_value.set_property(ctx, "phasePreflight", JSValue::null());
    } else {
        ready_value.set_property(ctx, "phasePreflight", phase_preflight);
    }
    let phase_cleanup = phase_index.get_property(ctx, "cleanup");
    if phase_cleanup.is_null() || phase_cleanup.is_undefined() {
        ready_value.set_property(ctx, "phaseCleanup", JSValue::null());
    } else {
        ready_value.set_property(ctx, "phaseCleanup", phase_cleanup);
    }

    let phase_resolve_index = JSValue(ffi::JS_NewObject(ctx));
    for phase in &known_phases {
        let phase_entry = phase_index.get_property(ctx, phase);
        let primary_escalation_key = phase_summaries
            .get(phase)
            .and_then(|summary| summary.escalation_keys.first())
            .cloned();
        let resolved = JSValue(ffi::JS_NewObject(ctx));
        resolved.set_property(ctx, "matched", JSValue::bool(true));
        resolved.set_property(ctx, "usedDefault", JSValue::bool(false));
        resolved.set_property(ctx, "reason", JSValue::string(ctx, "matched-phase"));
        resolved.set_property(ctx, "effectivePhase", JSValue::string(ctx, phase));
        match primary_escalation_key {
            Some(ref value) => {
                resolved.set_property(ctx, "effectiveEscalationKey", JSValue::string(ctx, value));
            }
            None => {
                resolved.set_property(ctx, "effectiveEscalationKey", JSValue::null());
            }
        }
        resolved.set_property(ctx, "effective", phase_entry);
        phase_resolve_index.set_property(ctx, phase, resolved);
    }

    let default_phase_entry = phase_index.get_property(ctx, default_phase);
    let phase_resolve_default = JSValue(ffi::JS_NewObject(ctx));
    phase_resolve_default.set_property(ctx, "matched", JSValue::bool(false));
    phase_resolve_default.set_property(ctx, "usedDefault", JSValue::bool(true));
    phase_resolve_default.set_property(ctx, "reason", JSValue::string(ctx, "missing-phase"));
    if default_phase_entry.is_null() || default_phase_entry.is_undefined() {
        phase_resolve_default.set_property(ctx, "effectivePhase", JSValue::string(ctx, default_phase));
        phase_resolve_default.set_property(
            ctx,
            "effectiveEscalationKey",
            JSValue::string(ctx, &default_escalation_key),
        );
        phase_resolve_default.set_property(ctx, "effective", JSValue::null());
    } else {
        let effective_escalation_key = phase_summaries
            .get(default_phase)
            .and_then(|summary| summary.escalation_keys.first())
            .cloned();
        phase_resolve_default.set_property(ctx, "effectivePhase", JSValue::string(ctx, default_phase));
        match effective_escalation_key {
            Some(ref value) => {
                phase_resolve_default.set_property(ctx, "effectiveEscalationKey", JSValue::string(ctx, value));
            }
            None => {
                phase_resolve_default.set_property(ctx, "effectiveEscalationKey", JSValue::null());
            }
        }
        phase_resolve_default.set_property(ctx, "effective", default_phase_entry);
    }

    let phase_resolve_examples = JSValue(ffi::JS_NewObject(ctx));
    match known_phases.first() {
        Some(phase) => {
            phase_resolve_examples.set_property(ctx, "knownPhase", JSValue::string(ctx, phase));
            phase_resolve_examples.set_property(ctx, "knownResult", phase_resolve_index.get_property(ctx, phase));
        }
        None => {
            phase_resolve_examples.set_property(ctx, "knownPhase", JSValue::null());
            phase_resolve_examples.set_property(ctx, "knownResult", JSValue::null());
        }
    }
    phase_resolve_examples.set_property(ctx, "missingPhase", JSValue::string(ctx, "unknown"));
    phase_resolve_examples.set_property(ctx, "missingResult", phase_resolve_default.dup(ctx));
    let query_only_phase = "query";
    let query_only_phase_result = phase_resolve_index.get_property(ctx, query_only_phase);
    let query_only_phase_available = !(query_only_phase_result.is_null() || query_only_phase_result.is_undefined());
    let query_only_phase_example = JSValue(ffi::JS_NewObject(ctx));
    query_only_phase_example.set_property(ctx, "sourceErrorCode", JSValue::string(ctx, query_only_error_code));
    query_only_phase_example.set_property(ctx, "phase", JSValue::string(ctx, query_only_phase));
    query_only_phase_example.set_property(ctx, "blockedBy", JSValue::string(ctx, query_only_blocked_by));
    query_only_phase_example.set_property(ctx, "blockedBySource", JSValue::string(ctx, query_only_blocked_by));
    query_only_phase_example.set_property(ctx, "isBlocked", JSValue::bool(true));
    query_only_phase_example.set_property(ctx, "available", JSValue::bool(query_only_phase_available));
    if query_only_phase_available {
        let effective_phase = query_only_phase_result.get_property(ctx, "effectivePhase");
        query_only_phase_example.set_property(ctx, "matched", query_only_phase_result.get_property(ctx, "matched"));
        query_only_phase_example.set_property(
            ctx,
            "usedDefault",
            query_only_phase_result.get_property(ctx, "usedDefault"),
        );
        query_only_phase_example.set_property(ctx, "reason", query_only_phase_result.get_property(ctx, "reason"));
        query_only_phase_example.set_property(ctx, "effectivePhase", effective_phase.dup(ctx));
        query_only_phase_example.set_property(
            ctx,
            "effectiveEscalationKey",
            query_only_phase_result.get_property(ctx, "effectiveEscalationKey"),
        );
        query_only_phase_example.set_property(ctx, "result", query_only_phase_result.dup(ctx));
        query_only_phase_example.set_property(
            ctx,
            "wouldUseQueryPhase",
            JSValue::bool(effective_phase.to_string(ctx).as_deref() == Some(query_only_phase)),
        );
        effective_phase.free(ctx);
    } else {
        query_only_phase_example.set_property(ctx, "matched", JSValue::bool(false));
        query_only_phase_example.set_property(ctx, "usedDefault", JSValue::bool(true));
        query_only_phase_example.set_property(ctx, "reason", JSValue::string(ctx, "missing-phase"));
        query_only_phase_example.set_property(ctx, "effectivePhase", JSValue::null());
        query_only_phase_example.set_property(ctx, "effectiveEscalationKey", JSValue::null());
        query_only_phase_example.set_property(ctx, "result", JSValue::null());
        query_only_phase_example.set_property(ctx, "wouldUseQueryPhase", JSValue::bool(false));
    }
    phase_resolve_examples.set_property(ctx, "queryOnlyInstallFailure", query_only_phase_example.dup(ctx));

    let phase_resolve_value = JSValue(ffi::JS_NewObject(ctx));
    phase_resolve_value.set_property(ctx, "lookupKey", JSValue::string(ctx, "phase"));
    phase_resolve_value.set_property(ctx, "policy", JSValue::string(ctx, "phaseIndex[phase] || default"));
    phase_resolve_value.set_property(ctx, "outputShape", JSValue::string(ctx, "effective"));
    phase_resolve_value.set_property(ctx, "index", phase_resolve_index);
    phase_resolve_value.set_property(ctx, "default", phase_resolve_default);
    phase_resolve_value.set_property(ctx, "examples", phase_resolve_examples);
    ready_value.set_property(ctx, "phaseResolve", phase_resolve_value.dup(ctx));
    ready_value.set_property(ctx, "phaseResolveLookupKey", JSValue::string(ctx, "phase"));
    ready_value.set_property(
        ctx,
        "phaseResolvePolicy",
        JSValue::string(ctx, "phaseIndex[phase] || default"),
    );
    ready_value.set_property(ctx, "phaseResolveOutputShape", JSValue::string(ctx, "effective"));
    ready_value.set_property(ctx, "phaseResolveIndex", phase_resolve_value.get_property(ctx, "index"));
    ready_value.set_property(
        ctx,
        "phaseResolveIndexEntries",
        phase_resolve_value.get_property(ctx, "index"),
    );
    ready_value.set_property(
        ctx,
        "phaseResolveDefault",
        phase_resolve_value.get_property(ctx, "default"),
    );
    ready_value.set_property(
        ctx,
        "phaseResolveExamples",
        phase_resolve_value.get_property(ctx, "examples"),
    );
    ready_value.set_property(ctx, "phaseResolvePhaseCount", JSValue::int(known_phases.len() as i32));
    ready_value.set_property(ctx, "phaseResolveIndexCount", JSValue::int(known_phases.len() as i32));
    ready_value.set_property(ctx, "phaseResolveKnownCount", JSValue::int(known_phases.len() as i32));
    ready_value.set_property(
        ctx,
        "phaseResolveKnownPhases",
        JSValue(string_vec_to_js_array(ctx, &known_phases)),
    );
    ready_value.set_property(
        ctx,
        "phaseResolveDefaultMatched",
        phase_resolve_default.get_property(ctx, "matched"),
    );
    ready_value.set_property(
        ctx,
        "phaseResolveDefaultUsedDefault",
        phase_resolve_default.get_property(ctx, "usedDefault"),
    );
    ready_value.set_property(
        ctx,
        "phaseResolveDefaultReason",
        phase_resolve_default.get_property(ctx, "reason"),
    );
    ready_value.set_property(
        ctx,
        "phaseResolveDefaultEffective",
        phase_resolve_default.get_property(ctx, "effective"),
    );
    ready_value.set_property(
        ctx,
        "phaseResolveDefaultEffectivePhase",
        phase_resolve_default.get_property(ctx, "effectivePhase"),
    );
    ready_value.set_property(
        ctx,
        "phaseResolveDefaultEffectiveEscalationKey",
        phase_resolve_default.get_property(ctx, "effectiveEscalationKey"),
    );
    ready_value.set_property(
        ctx,
        "phaseResolveExampleKnownPhase",
        phase_resolve_examples.get_property(ctx, "knownPhase"),
    );
    let phase_resolve_known_result = phase_resolve_examples.get_property(ctx, "knownResult");
    ready_value.set_property(
        ctx,
        "phaseResolveExampleKnownResult",
        phase_resolve_known_result.dup(ctx),
    );
    if phase_resolve_known_result.is_null() || phase_resolve_known_result.is_undefined() {
        ready_value.set_property(ctx, "phaseResolveExampleKnownResultEffective", JSValue::null());
        ready_value.set_property(ctx, "phaseResolveExampleKnownResultEffectivePhase", JSValue::null());
        ready_value.set_property(
            ctx,
            "phaseResolveExampleKnownResultEffectiveEscalationKey",
            JSValue::null(),
        );
    } else {
        ready_value.set_property(
            ctx,
            "phaseResolveExampleKnownResultEffective",
            phase_resolve_known_result.get_property(ctx, "effective"),
        );
        ready_value.set_property(
            ctx,
            "phaseResolveExampleKnownResultEffectivePhase",
            phase_resolve_known_result.get_property(ctx, "effectivePhase"),
        );
        ready_value.set_property(
            ctx,
            "phaseResolveExampleKnownResultEffectiveEscalationKey",
            phase_resolve_known_result.get_property(ctx, "effectiveEscalationKey"),
        );
    }
    ready_value.set_property(
        ctx,
        "phaseResolveExampleKnownReason",
        phase_resolve_known_result.get_property(ctx, "reason"),
    );
    phase_resolve_known_result.free(ctx);
    ready_value.set_property(
        ctx,
        "phaseResolveExampleMissingPhase",
        phase_resolve_examples.get_property(ctx, "missingPhase"),
    );
    let phase_resolve_missing_result = phase_resolve_examples.get_property(ctx, "missingResult");
    ready_value.set_property(
        ctx,
        "phaseResolveExampleMissingResult",
        phase_resolve_missing_result.dup(ctx),
    );
    if phase_resolve_missing_result.is_null() || phase_resolve_missing_result.is_undefined() {
        ready_value.set_property(ctx, "phaseResolveExampleMissingResultEffective", JSValue::null());
        ready_value.set_property(ctx, "phaseResolveExampleMissingResultEffectivePhase", JSValue::null());
        ready_value.set_property(
            ctx,
            "phaseResolveExampleMissingResultEffectiveEscalationKey",
            JSValue::null(),
        );
    } else {
        ready_value.set_property(
            ctx,
            "phaseResolveExampleMissingResultEffective",
            phase_resolve_missing_result.get_property(ctx, "effective"),
        );
        ready_value.set_property(
            ctx,
            "phaseResolveExampleMissingResultEffectivePhase",
            phase_resolve_missing_result.get_property(ctx, "effectivePhase"),
        );
        ready_value.set_property(
            ctx,
            "phaseResolveExampleMissingResultEffectiveEscalationKey",
            phase_resolve_missing_result.get_property(ctx, "effectiveEscalationKey"),
        );
    }
    phase_resolve_missing_result.free(ctx);
    ready_value.set_property(
        ctx,
        "phaseResolveExampleQueryOnlyInstallFailure",
        query_only_phase_example.dup(ctx),
    );
    ready_value.set_property(
        ctx,
        "phaseResolveExampleQueryOnlySourceErrorCode",
        query_only_phase_example.get_property(ctx, "sourceErrorCode"),
    );
    ready_value.set_property(
        ctx,
        "phaseResolveExampleQueryOnlyPhase",
        query_only_phase_example.get_property(ctx, "phase"),
    );
    ready_value.set_property(
        ctx,
        "phaseResolveExampleQueryOnlyBlockedBy",
        query_only_phase_example.get_property(ctx, "blockedBy"),
    );
    ready_value.set_property(
        ctx,
        "phaseResolveExampleQueryOnlyBlockedBySource",
        query_only_phase_example.get_property(ctx, "blockedBySource"),
    );
    ready_value.set_property(
        ctx,
        "phaseResolveExampleQueryOnlyIsBlocked",
        query_only_phase_example.get_property(ctx, "isBlocked"),
    );
    ready_value.set_property(
        ctx,
        "phaseResolveExampleQueryOnlyAvailable",
        query_only_phase_example.get_property(ctx, "available"),
    );
    ready_value.set_property(
        ctx,
        "phaseResolveExampleQueryOnlyMatched",
        query_only_phase_example.get_property(ctx, "matched"),
    );
    ready_value.set_property(
        ctx,
        "phaseResolveExampleQueryOnlyUsedDefault",
        query_only_phase_example.get_property(ctx, "usedDefault"),
    );
    ready_value.set_property(
        ctx,
        "phaseResolveExampleQueryOnlyReason",
        query_only_phase_example.get_property(ctx, "reason"),
    );
    ready_value.set_property(
        ctx,
        "phaseResolveExampleQueryOnlyEffectivePhase",
        query_only_phase_example.get_property(ctx, "effectivePhase"),
    );
    ready_value.set_property(
        ctx,
        "phaseResolveExampleQueryOnlyEffectiveEscalationKey",
        query_only_phase_example.get_property(ctx, "effectiveEscalationKey"),
    );
    ready_value.set_property(
        ctx,
        "phaseResolveExampleQueryOnlyWouldUsePhase",
        query_only_phase_example.get_property(ctx, "wouldUseQueryPhase"),
    );
    let query_only_phase_example_result = query_only_phase_example.get_property(ctx, "result");
    ready_value.set_property(
        ctx,
        "phaseResolveExampleQueryOnlyResult",
        query_only_phase_example_result.dup(ctx),
    );
    if query_only_phase_example_result.is_null() || query_only_phase_example_result.is_undefined() {
        ready_value.set_property(ctx, "phaseResolveExampleQueryOnlyResultEffective", JSValue::null());
        ready_value.set_property(ctx, "phaseResolveExampleQueryOnlyResultMatched", JSValue::null());
        ready_value.set_property(ctx, "phaseResolveExampleQueryOnlyResultUsedDefault", JSValue::null());
        ready_value.set_property(ctx, "phaseResolveExampleQueryOnlyResultReason", JSValue::null());
        ready_value.set_property(ctx, "phaseResolveExampleQueryOnlyResultEffectivePhase", JSValue::null());
        ready_value.set_property(
            ctx,
            "phaseResolveExampleQueryOnlyResultEffectiveEscalationKey",
            JSValue::null(),
        );
    } else {
        ready_value.set_property(
            ctx,
            "phaseResolveExampleQueryOnlyResultEffective",
            query_only_phase_example_result.get_property(ctx, "effective"),
        );
        ready_value.set_property(
            ctx,
            "phaseResolveExampleQueryOnlyResultMatched",
            query_only_phase_example_result.get_property(ctx, "matched"),
        );
        ready_value.set_property(
            ctx,
            "phaseResolveExampleQueryOnlyResultUsedDefault",
            query_only_phase_example_result.get_property(ctx, "usedDefault"),
        );
        ready_value.set_property(
            ctx,
            "phaseResolveExampleQueryOnlyResultReason",
            query_only_phase_example_result.get_property(ctx, "reason"),
        );
        ready_value.set_property(
            ctx,
            "phaseResolveExampleQueryOnlyResultEffectivePhase",
            query_only_phase_example_result.get_property(ctx, "effectivePhase"),
        );
        ready_value.set_property(
            ctx,
            "phaseResolveExampleQueryOnlyResultEffectiveEscalationKey",
            query_only_phase_example_result.get_property(ctx, "effectiveEscalationKey"),
        );
    }
    query_only_phase_example_result.free(ctx);
    ready_value.set_property(
        ctx,
        "queryOnlyErrorCode",
        query_only_example.get_property(ctx, "errorCode"),
    );
    ready_value.set_property(
        ctx,
        "queryOnlySourceErrorCode",
        query_only_phase_example.get_property(ctx, "sourceErrorCode"),
    );
    ready_value.set_property(
        ctx,
        "queryOnlyBlockedBy",
        query_only_example.get_property(ctx, "blockedBy"),
    );
    ready_value.set_property(
        ctx,
        "queryOnlyResolveBlockedBy",
        query_only_example.get_property(ctx, "blockedBy"),
    );
    ready_value.set_property(
        ctx,
        "queryOnlyBlockedBySource",
        query_only_example.get_property(ctx, "blockedBySource"),
    );
    ready_value.set_property(
        ctx,
        "queryOnlyResolveBlockedBySource",
        query_only_example.get_property(ctx, "blockedBySource"),
    );
    ready_value.set_property(
        ctx,
        "queryOnlyIsBlocked",
        query_only_example.get_property(ctx, "isBlocked"),
    );
    ready_value.set_property(
        ctx,
        "queryOnlyResolveIsBlocked",
        query_only_example.get_property(ctx, "isBlocked"),
    );
    ready_value.set_property(
        ctx,
        "queryOnlyPhase",
        query_only_phase_example.get_property(ctx, "phase"),
    );
    ready_value.set_property(
        ctx,
        "queryOnlyPhaseResolveSourceErrorCode",
        query_only_phase_example.get_property(ctx, "sourceErrorCode"),
    );
    ready_value.set_property(
        ctx,
        "queryOnlyPhaseResolvePhase",
        query_only_phase_example.get_property(ctx, "phase"),
    );
    ready_value.set_property(
        ctx,
        "queryOnlyPhaseResolveBlockedBy",
        query_only_phase_example.get_property(ctx, "blockedBy"),
    );
    ready_value.set_property(
        ctx,
        "queryOnlyPhaseResolveBlockedBySource",
        query_only_phase_example.get_property(ctx, "blockedBySource"),
    );
    ready_value.set_property(
        ctx,
        "queryOnlyPhaseResolveIsBlocked",
        query_only_phase_example.get_property(ctx, "isBlocked"),
    );
    ready_value.set_property(
        ctx,
        "queryOnlyPhaseResolveAvailable",
        query_only_phase_example.get_property(ctx, "available"),
    );
    ready_value.set_property(
        ctx,
        "queryOnlyAvailable",
        query_only_example.get_property(ctx, "available"),
    );
    ready_value.set_property(
        ctx,
        "queryOnlyResolveAvailable",
        query_only_example.get_property(ctx, "available"),
    );
    ready_value.set_property(ctx, "queryOnlyMatched", query_only_example.get_property(ctx, "matched"));
    ready_value.set_property(
        ctx,
        "queryOnlyResolveMatched",
        query_only_example.get_property(ctx, "matched"),
    );
    ready_value.set_property(
        ctx,
        "queryOnlyPhaseResolveMatched",
        query_only_phase_example.get_property(ctx, "matched"),
    );
    ready_value.set_property(
        ctx,
        "queryOnlyUsedDefault",
        query_only_example.get_property(ctx, "usedDefault"),
    );
    ready_value.set_property(
        ctx,
        "queryOnlyResolveUsedDefault",
        query_only_example.get_property(ctx, "usedDefault"),
    );
    ready_value.set_property(
        ctx,
        "queryOnlyPhaseResolveUsedDefault",
        query_only_phase_example.get_property(ctx, "usedDefault"),
    );
    ready_value.set_property(ctx, "queryOnlyReason", query_only_example.get_property(ctx, "reason"));
    ready_value.set_property(
        ctx,
        "queryOnlyResolveReason",
        query_only_example.get_property(ctx, "reason"),
    );
    ready_value.set_property(
        ctx,
        "queryOnlyPhaseResolveReason",
        query_only_phase_example.get_property(ctx, "reason"),
    );
    ready_value.set_property(
        ctx,
        "queryOnlyEffectivePhase",
        query_only_example.get_property(ctx, "effectivePhase"),
    );
    ready_value.set_property(
        ctx,
        "queryOnlyResolveEffectivePhase",
        query_only_example.get_property(ctx, "effectivePhase"),
    );
    ready_value.set_property(
        ctx,
        "queryOnlyPhaseResolveEffectivePhase",
        query_only_phase_example.get_property(ctx, "effectivePhase"),
    );
    ready_value.set_property(
        ctx,
        "queryOnlyEffectiveEscalationKey",
        query_only_example.get_property(ctx, "effectiveEscalationKey"),
    );
    ready_value.set_property(
        ctx,
        "queryOnlyResolveEffectiveEscalationKey",
        query_only_example.get_property(ctx, "effectiveEscalationKey"),
    );
    ready_value.set_property(
        ctx,
        "queryOnlyPhaseResolveEffectiveEscalationKey",
        query_only_phase_example.get_property(ctx, "effectiveEscalationKey"),
    );
    ready_value.set_property(
        ctx,
        "queryOnlyWouldUsePath",
        query_only_example.get_property(ctx, "wouldUseQueryOnlyPath"),
    );
    ready_value.set_property(
        ctx,
        "queryOnlyResolveWouldUsePath",
        query_only_example.get_property(ctx, "wouldUseQueryOnlyPath"),
    );
    ready_value.set_property(
        ctx,
        "queryOnlyWouldUsePhase",
        query_only_phase_example.get_property(ctx, "wouldUseQueryPhase"),
    );
    ready_value.set_property(
        ctx,
        "queryOnlyPhaseResolveWouldUsePhase",
        query_only_phase_example.get_property(ctx, "wouldUseQueryPhase"),
    );
    let query_only_result_alias = query_only_example.get_property(ctx, "result");
    let query_only_result_alias_effective =
        if query_only_result_alias.is_null() || query_only_result_alias.is_undefined() {
            JSValue::null()
        } else {
            query_only_result_alias.get_property(ctx, "effective")
        };
    ready_value.set_property(ctx, "queryOnlyResult", query_only_result_alias.dup(ctx));
    ready_value.set_property(
        ctx,
        "queryOnlyResultEffective",
        query_only_result_alias_effective.dup(ctx),
    );
    ready_value.set_property(
        ctx,
        "queryOnlyResultMatched",
        query_only_example.get_property(ctx, "matched"),
    );
    ready_value.set_property(
        ctx,
        "queryOnlyResultUsedDefault",
        query_only_example.get_property(ctx, "usedDefault"),
    );
    ready_value.set_property(
        ctx,
        "queryOnlyResultReason",
        query_only_example.get_property(ctx, "reason"),
    );
    ready_value.set_property(
        ctx,
        "queryOnlyResultEffectivePhase",
        query_only_example.get_property(ctx, "effectivePhase"),
    );
    ready_value.set_property(
        ctx,
        "queryOnlyResultEffectiveEscalationKey",
        query_only_example.get_property(ctx, "effectiveEscalationKey"),
    );
    ready_value.set_property(ctx, "queryOnlyResolveResult", query_only_result_alias.dup(ctx));
    ready_value.set_property(
        ctx,
        "queryOnlyResolveResultEffective",
        query_only_result_alias_effective.dup(ctx),
    );
    ready_value.set_property(
        ctx,
        "queryOnlyResolveResultMatched",
        query_only_example.get_property(ctx, "matched"),
    );
    ready_value.set_property(
        ctx,
        "queryOnlyResolveResultUsedDefault",
        query_only_example.get_property(ctx, "usedDefault"),
    );
    ready_value.set_property(
        ctx,
        "queryOnlyResolveResultReason",
        query_only_example.get_property(ctx, "reason"),
    );
    ready_value.set_property(
        ctx,
        "queryOnlyResolveResultEffectivePhase",
        query_only_example.get_property(ctx, "effectivePhase"),
    );
    ready_value.set_property(
        ctx,
        "queryOnlyResolveResultEffectiveEscalationKey",
        query_only_example.get_property(ctx, "effectiveEscalationKey"),
    );
    let query_only_phase_result_alias = query_only_phase_example.get_property(ctx, "result");
    let query_only_phase_result_alias_effective =
        if query_only_phase_result_alias.is_null() || query_only_phase_result_alias.is_undefined() {
            JSValue::null()
        } else {
            query_only_phase_result_alias.get_property(ctx, "effective")
        };
    ready_value.set_property(
        ctx,
        "queryOnlyPhaseResolveResult",
        query_only_phase_result_alias.dup(ctx),
    );
    ready_value.set_property(
        ctx,
        "queryOnlyPhaseResolveResultEffective",
        query_only_phase_result_alias_effective.dup(ctx),
    );
    ready_value.set_property(
        ctx,
        "queryOnlyPhaseResolveResultMatched",
        query_only_phase_example.get_property(ctx, "matched"),
    );
    ready_value.set_property(
        ctx,
        "queryOnlyPhaseResolveResultUsedDefault",
        query_only_phase_example.get_property(ctx, "usedDefault"),
    );
    ready_value.set_property(
        ctx,
        "queryOnlyPhaseResolveResultReason",
        query_only_phase_example.get_property(ctx, "reason"),
    );
    ready_value.set_property(
        ctx,
        "queryOnlyPhaseResolveResultEffectivePhase",
        query_only_phase_example.get_property(ctx, "effectivePhase"),
    );
    ready_value.set_property(
        ctx,
        "queryOnlyPhaseResolveResultEffectiveEscalationKey",
        query_only_phase_example.get_property(ctx, "effectiveEscalationKey"),
    );
    query_only_result_alias.free(ctx);
    query_only_result_alias_effective.free(ctx);
    query_only_phase_result_alias.free(ctx);
    query_only_phase_result_alias_effective.free(ctx);
    query_only_phase_result.free(ctx);
    query_only_result.free(ctx);

    ready_value.set_property(ctx, "phaseCount", JSValue::int(known_phases.len() as i32));
    ready_value.set_property(ctx, "phases", JSValue(phase_entries));
    ready_value.set_property(ctx, "phaseIndex", phase_index.dup(ctx));
    if let Some(first_phase) = known_phases.first() {
        ready_value.set_property(ctx, "phaseFirst", phase_index.get_property(ctx, first_phase));
    } else {
        ready_value.set_property(ctx, "phaseFirst", JSValue::null());
    }
    if let Some(last_phase) = known_phases.last() {
        ready_value.set_property(ctx, "phaseLast", phase_index.get_property(ctx, last_phase));
    } else {
        ready_value.set_property(ctx, "phaseLast", JSValue::null());
    }
    let phase_query_alias = phase_index.get_property(ctx, "query");
    let phase_preflight_alias = phase_index.get_property(ctx, "preflight");
    let phase_cleanup_alias = phase_index.get_property(ctx, "cleanup");
    set_phase_ready_aliases(ctx, &ready_value, "phaseQuery", &phase_query_alias, false, false);
    set_phase_ready_aliases(ctx, &ready_value, "phasePreflight", &phase_preflight_alias, true, true);
    set_phase_ready_aliases(ctx, &ready_value, "phaseCleanup", &phase_cleanup_alias, false, false);
    routing_decision.set_property(ctx, "ready", ready_value);
    resolve_value.free(ctx);
    phase_resolve_value.free(ctx);
    phase_index.free(ctx);
    default_value.free(ctx);

    routing.set_property(ctx, "phaseRetryPolicyCount", JSValue::int(steps.len() as i32));
    routing.set_property(ctx, "phaseRetryPolicies", JSValue(phase_retry_policies));
    routing.set_property(ctx, "phaseTimeoutPolicyCount", JSValue::int(steps.len() as i32));
    routing.set_property(ctx, "phaseTimeoutPolicies", JSValue(phase_timeout_policies));
    routing.set_property(ctx, "phaseErrorCodeCount", JSValue::int(steps.len() as i32));
    routing.set_property(ctx, "phaseErrorCodes", JSValue(phase_error_codes));
    routing.set_property(ctx, "escalationRecommendationCount", JSValue::int(steps.len() as i32));
    routing.set_property(ctx, "escalationRecommendations", JSValue(escalation_recommendations));
    routing.set_property(
        ctx,
        "suggestedEscalationKey",
        JSValue::string(ctx, &default_escalation_key),
    );
    routing.set_property(
        ctx,
        "errorCodeRoutingCount",
        JSValue::int(error_code_routing_candidates.len() as i32),
    );
    routing.set_property(ctx, "errorCodeRouting", error_code_routing);
    routing.set_property(
        ctx,
        "errorCodeRoutingResolvedCount",
        JSValue::int(error_code_routing_candidates.len() as i32),
    );
    routing.set_property(ctx, "errorCodeRoutingResolved", error_code_routing_resolved);
    routing.set_property(ctx, "errorCodeRoutingEntries", JSValue(error_code_routing_entries));
    routing.set_property(ctx, "routingDecision", routing_decision);

    routing.raw()
}

unsafe fn hook_backend_conflict_pair_to_js(
    ctx: *mut ffi::JSContext,
    left_backend: &native_api::HookBackendInfo,
    right_backend: &native_api::HookBackendInfo,
    suggested_group_key: &str,
    suggested_phase: &str,
    resolution_reason: &str,
    query_templates: &[String],
    preflight_templates: &[String],
    cleanup_templates: &[String],
) -> ffi::JSValue {
    let item = JSValue(ffi::JS_NewObject(ctx));
    let templates = hook_backend_templates_for_group(
        suggested_group_key,
        query_templates,
        preflight_templates,
        cleanup_templates,
    );
    let (command_json_templates, command_json_eligible_template_count) =
        hook_command_json_template_array_to_js(ctx, templates);
    let pair_key = format!("{}->{}", left_backend.id, right_backend.id);
    let resolution_chain = ffi::JS_NewArray(ctx);
    let resolution_steps = hook_conflict_resolution_steps_for_group(suggested_group_key);
    for (index, (group_key, phase, reason)) in resolution_steps.iter().enumerate() {
        let step_templates =
            hook_backend_templates_for_group(group_key, query_templates, preflight_templates, cleanup_templates);
        let entry = JSValue(hook_backend_conflict_resolution_chain_entry_to_js(
            ctx,
            index,
            group_key,
            phase,
            reason,
            step_templates,
        ));
        ffi::JS_SetPropertyUint32(ctx, resolution_chain, index as u32, entry.raw());
    }

    item.set_property(ctx, "pairKey", JSValue::string(ctx, &pair_key));
    item.set_property(ctx, "scope", JSValue::string(ctx, "shared-process"));
    item.set_property(
        ctx,
        "reason",
        JSValue::string(ctx, "multiple external backend runtimes are loaded in this process"),
    );
    item.set_property(ctx, "firstBackendId", JSValue::string(ctx, &left_backend.id));
    item.set_property(
        ctx,
        "firstBackendDisplayName",
        JSValue::string(ctx, &left_backend.display_name),
    );
    item.set_property(ctx, "secondBackendId", JSValue::string(ctx, &right_backend.id));
    item.set_property(
        ctx,
        "secondBackendDisplayName",
        JSValue::string(ctx, &right_backend.display_name),
    );
    item.set_property(
        ctx,
        "backendIds",
        JSValue(string_vec_to_js_array(
            ctx,
            &[left_backend.id.clone(), right_backend.id.clone()],
        )),
    );
    item.set_property(
        ctx,
        "backendDisplayNames",
        JSValue(string_vec_to_js_array(
            ctx,
            &[left_backend.display_name.clone(), right_backend.display_name.clone()],
        )),
    );
    item.set_property(ctx, "suggestedGroupKey", JSValue::string(ctx, suggested_group_key));
    item.set_property(ctx, "suggestedPhase", JSValue::string(ctx, suggested_phase));
    item.set_property(ctx, "resolutionReason", JSValue::string(ctx, resolution_reason));
    item.set_property(ctx, "templateCount", JSValue::int(templates.len() as i32));
    set_string_array_property(ctx, item.raw(), "templates", templates);
    item.set_property(ctx, "commandJsonTemplateCount", JSValue::int(templates.len() as i32));
    item.set_property(ctx, "commandJsonTemplates", JSValue(command_json_templates));
    item.set_property(
        ctx,
        "commandJsonEligibleTemplateCount",
        JSValue::int(command_json_eligible_template_count as i32),
    );
    match templates.first() {
        Some(template) => {
            let primary = JSValue(hook_command_json_template_to_js(ctx, template));
            item.set_property(
                ctx,
                "primaryCommandJsonTemplateCommand",
                primary.get_property(ctx, "command"),
            );
            item.set_property(ctx, "primaryCommandJsonTemplateKind", primary.get_property(ctx, "kind"));
            item.set_property(
                ctx,
                "primaryCommandJsonTemplateEligible",
                primary.get_property(ctx, "commandJsonEligible"),
            );
            item.set_property(ctx, "primaryCommandJsonTemplate", primary);
        }
        None => {
            item.set_property(ctx, "primaryCommandJsonTemplate", JSValue::null());
            item.set_property(ctx, "primaryCommandJsonTemplateCommand", JSValue::null());
            item.set_property(ctx, "primaryCommandJsonTemplateKind", JSValue::null());
            item.set_property(ctx, "primaryCommandJsonTemplateEligible", JSValue::null());
        }
    }
    item.set_property(ctx, "resolutionChainCount", JSValue::int(resolution_steps.len() as i32));
    item.set_property(ctx, "resolutionChain", JSValue(resolution_chain));

    item.raw()
}

unsafe fn hook_backend_conflict_resolution_step_to_js(
    ctx: *mut ffi::JSContext,
    preferred_path: &str,
    index: usize,
    group_key: &str,
    phase: &str,
    reason: &str,
    templates: &[String],
) -> ffi::JSValue {
    let item = JSValue(ffi::JS_NewObject(ctx));
    let allowed = group_key != "none";
    let blocked_by = if allowed { "none" } else { "both" };
    let branch = if allowed { "run" } else { "blocked" };
    let (retryable, max_suggested_retries, retry_delay_hint_ms) = hook_conflict_resolution_phase_retry_policy(phase);
    let (timeout_hint_ms, timeout_action) = hook_conflict_resolution_phase_timeout_policy(phase);
    let command_json_template = match templates.first() {
        Some(template) => JSValue(hook_command_json_template_to_js(ctx, template)),
        None => JSValue::null(),
    };

    item.set_property(ctx, "index", JSValue::int(index as i32));
    item.set_property(
        ctx,
        "id",
        JSValue::string(ctx, &format!("preferred-conflict-resolution:{index}")),
    );
    item.set_property(
        ctx,
        "source",
        JSValue::string(ctx, "preferred-conflict-resolution-chain"),
    );
    item.set_property(ctx, "actionKey", JSValue::null());
    item.set_property(ctx, "commandGroup", JSValue::string(ctx, "conflict-resolution"));
    item.set_property(ctx, "allowed", JSValue::bool(allowed));
    item.set_property(ctx, "blockedBy", JSValue::string(ctx, blocked_by));
    item.set_property(ctx, "branch", JSValue::string(ctx, branch));
    item.set_property(ctx, "reason", JSValue::string(ctx, reason));
    item.set_property(ctx, "preferredPath", JSValue::string(ctx, preferred_path));
    item.set_property(ctx, "readyToRun", JSValue::bool(allowed));
    item.set_property(ctx, "requiresFallback", JSValue::bool(false));
    if command_json_template.is_null() {
        item.set_property(ctx, "command", JSValue::null());
        item.set_property(ctx, "commandJsonEligible", JSValue::null());
        item.set_property(ctx, "commandJsonTemplate", JSValue::null());
        item.set_property(ctx, "commandJsonTemplateCommand", JSValue::null());
        item.set_property(ctx, "commandJsonTemplateKind", JSValue::null());
        item.set_property(ctx, "commandJsonTemplateEligible", JSValue::null());
        item.set_property(ctx, "kind", JSValue::null());
        item.set_property(ctx, "risk", JSValue::null());
        item.set_property(ctx, "placeholderCount", JSValue::null());
        item.set_property(ctx, "placeholders", JSValue::null());
        item.set_property(ctx, "cliArgs", JSValue::null());
    } else {
        item.set_property(ctx, "command", command_json_template.get_property(ctx, "command"));
        item.set_property(
            ctx,
            "commandJsonEligible",
            command_json_template.get_property(ctx, "commandJsonEligible"),
        );
        item.set_property(ctx, "commandJsonTemplate", command_json_template.dup(ctx));
        item.set_property(
            ctx,
            "commandJsonTemplateCommand",
            command_json_template.get_property(ctx, "command"),
        );
        item.set_property(
            ctx,
            "commandJsonTemplateKind",
            command_json_template.get_property(ctx, "kind"),
        );
        item.set_property(
            ctx,
            "commandJsonTemplateEligible",
            command_json_template.get_property(ctx, "commandJsonEligible"),
        );
        item.set_property(ctx, "kind", command_json_template.get_property(ctx, "kind"));
        item.set_property(ctx, "risk", command_json_template.get_property(ctx, "risk"));
        item.set_property(
            ctx,
            "placeholderCount",
            command_json_template.get_property(ctx, "placeholderCount"),
        );
        item.set_property(
            ctx,
            "placeholders",
            command_json_template.get_property(ctx, "placeholders"),
        );
        item.set_property(ctx, "cliArgs", command_json_template.get_property(ctx, "cliArgs"));
        command_json_template.free(ctx);
    }
    item.set_property(ctx, "phase", JSValue::string(ctx, phase));
    item.set_property(ctx, "retryable", JSValue::bool(retryable));
    item.set_property(ctx, "maxSuggestedRetries", JSValue::int(max_suggested_retries as i32));
    item.set_property(
        ctx,
        "retryDelayHintMs",
        JSValue(js_u64_to_js_number_or_bigint(ctx, retry_delay_hint_ms as u64)),
    );
    item.set_property(
        ctx,
        "timeoutHintMs",
        JSValue(js_u64_to_js_number_or_bigint(ctx, timeout_hint_ms)),
    );
    item.set_property(ctx, "timeoutAction", JSValue::string(ctx, timeout_action));
    item.set_property(
        ctx,
        "errorCode",
        JSValue::string(ctx, hook_conflict_resolution_phase_failure_code(phase)),
    );
    item.set_property(
        ctx,
        "timeoutErrorCode",
        JSValue::string(ctx, hook_conflict_resolution_phase_timeout_error_code(phase)),
    );

    item.raw()
}

unsafe fn report_to_js(ctx: *mut ffi::JSContext, report: &native_api::HookEnvironmentReport) -> ffi::JSValue {
    let result = JSValue(ffi::JS_NewObject(ctx));
    let decision = resolve_hook_strategy().ok();
    let command_mode = decision.as_ref().map(|item| item.command_mode()).unwrap_or("allowed");
    let loaded_backend_count = report.loaded_backend_count();
    let filesystem_only_backend_count = report.filesystem_only_backend_count();
    let loaded_image_count = report.loaded_image_count();
    let filesystem_path_count = report.filesystem_path_count();
    let single_external_backend_loaded = loaded_backend_count == 1;
    let multiple_external_backends_loaded = loaded_backend_count > 1;
    let conflict_state = report.conflict_state();
    let backend_pressure = if loaded_backend_count > 0 {
        "controller"
    } else if filesystem_only_backend_count > 0 {
        "filesystem-only"
    } else {
        "none"
    };
    let topology_kind = hook_backend_adaptation_topology_kind(loaded_backend_count, filesystem_only_backend_count);
    let risk_level = match command_mode {
        "blocked" => "blocked",
        "cleanup-only" => "cleanup-only",
        "query-only" => "query-only",
        _ if loaded_backend_count > 0 => "risky",
        _ if filesystem_only_backend_count > 0 => "cautious",
        _ => "normal",
    };
    let coexistence_mode = match command_mode {
        "allowed" => {
            if loaded_backend_count > 0 {
                "inline-risky"
            } else if filesystem_only_backend_count > 0 {
                "inline-cautious"
            } else {
                "inline-safe"
            }
        }
        "query-only" => "query-only",
        "cleanup-only" => "cleanup-only",
        "blocked" => "blocked",
        _ => "unknown",
    };
    let coexistence_recommendation = match coexistence_mode {
        "inline-safe" => "inline hooks are allowed and no external backend is loaded",
        "inline-cautious" => "filesystem-only backend artifacts were detected; preflight before hook-install",
        "inline-risky" => {
            "external backend already loaded; prefer query/status first, then inline install only if necessary"
        }
        "query-only" => "current policy blocks hook-install; stay on query commands",
        "cleanup-only" => "only status/stop commands are allowed under current policy",
        "blocked" => "no hook command group is currently allowed",
        _ => "hook strategy is unavailable; run native.hookenv and preflight for guidance",
    };
    let requires_cleanup_phase = command_mode == "cleanup-only";
    let requires_preflight =
        topology_kind == "filesystem-only" || matches!(coexistence_mode, "inline-cautious" | "inline-risky");
    let requires_query_phase = matches!(coexistence_mode, "query-only" | "inline-risky")
        || matches!(topology_kind, "shared-loaded" | "split-loaded");
    let inline_install_ready_now = topology_kind == "clean" && coexistence_mode == "inline-safe";
    let backend_adaptation_alignment = hook_backend_adaptation_alignment(topology_kind);
    let backend_adaptation_mode = hook_backend_adaptation_mode(topology_kind);
    let backend_adaptation_bias = if command_mode == "blocked" {
        "blocked"
    } else if requires_cleanup_phase {
        "cleanup"
    } else if topology_kind == "filesystem-only" {
        "preflight"
    } else if inline_install_ready_now {
        "install"
    } else if requires_query_phase {
        "query"
    } else {
        "observe"
    };
    let backend_adaptation_summary = hook_backend_adaptation_summary(backend_adaptation_bias, topology_kind);
    let query_templates = hook_action_command_templates("hook.query", coexistence_mode);
    let preflight_templates = vec![
        "native.hookenv".to_string(),
        "controller --preflight-only --preflight-json --pid <pid>".to_string(),
    ];
    let cleanup_templates = {
        let mut templates = hook_action_command_templates("hook.status", coexistence_mode);
        templates.extend(hook_action_command_templates("hook.stop", coexistence_mode));
        templates
    };
    let install_templates = hook_action_command_templates("hook.install", coexistence_mode);
    let preferred_group_key = match backend_adaptation_bias {
        "query" => "query",
        "preflight" => "preflight",
        "cleanup" => "cleanup",
        "install" => "install",
        _ => "none",
    };
    let preferred_templates = match preferred_group_key {
        "query" => query_templates.clone(),
        "preflight" => preflight_templates.clone(),
        "cleanup" => cleanup_templates.clone(),
        "install" => install_templates.clone(),
        _ => Vec::new(),
    };
    let shared_loaded_backend_ids = report
        .backends
        .iter()
        .filter(|backend| !backend.loaded_images.is_empty())
        .map(|backend| backend.id.clone())
        .collect::<Vec<_>>();
    let shared_loaded_backend_display_names = report
        .backends
        .iter()
        .filter(|backend| !backend.loaded_images.is_empty())
        .map(|backend| backend.display_name.clone())
        .collect::<Vec<_>>();
    let backend_ids = report
        .backends
        .iter()
        .map(|backend| backend.id.clone())
        .collect::<Vec<_>>();
    let backend_display_names = report
        .backends
        .iter()
        .map(|backend| backend.display_name.clone())
        .collect::<Vec<_>>();
    let filesystem_only_backend_ids = report
        .backends
        .iter()
        .filter(|backend| backend.loaded_images.is_empty() && !backend.filesystem_paths.is_empty())
        .map(|backend| backend.id.clone())
        .collect::<Vec<_>>();
    let filesystem_only_backend_display_names = report
        .backends
        .iter()
        .filter(|backend| backend.loaded_images.is_empty() && !backend.filesystem_paths.is_empty())
        .map(|backend| backend.display_name.clone())
        .collect::<Vec<_>>();
    let active_backend_display_name = report.active_backend.as_ref().and_then(|active_backend| {
        report
            .backends
            .iter()
            .find(|backend| backend.id == *active_backend)
            .map(|backend| backend.display_name.clone())
    });
    let empty_backend_ids: Vec<String> = Vec::new();
    let backend_specific_recommendations = ffi::JS_NewArray(ctx);
    let mut backend_specific_recommendation_count = 0usize;
    let mut preferred_backend_recommendation: Option<JSValue> = None;
    let mut preferred_conflict_backend_pair: Option<JSValue> = None;
    let backend_adaptation_allowed = preferred_group_key != "none";
    let backend_adaptation = JSValue(ffi::JS_NewObject(ctx));
    backend_adaptation.set_property(ctx, "mode", JSValue::string(ctx, backend_adaptation_mode));
    backend_adaptation.set_property(ctx, "alignment", JSValue::string(ctx, backend_adaptation_alignment));
    backend_adaptation.set_property(
        ctx,
        "recommendedActionBias",
        JSValue::string(ctx, backend_adaptation_bias),
    );
    backend_adaptation.set_property(ctx, "summary", JSValue::string(ctx, backend_adaptation_summary));
    backend_adaptation.set_property(ctx, "topologyKind", JSValue::string(ctx, topology_kind));
    backend_adaptation.set_property(ctx, "source", JSValue::string(ctx, "native-hookenv-single-process"));
    backend_adaptation.set_property(ctx, "requiresQueryPhase", JSValue::bool(requires_query_phase));
    backend_adaptation.set_property(ctx, "requiresPreflight", JSValue::bool(requires_preflight));
    backend_adaptation.set_property(ctx, "requiresCleanupPhase", JSValue::bool(requires_cleanup_phase));
    backend_adaptation.set_property(ctx, "inlineInstallReadyNow", JSValue::bool(inline_install_ready_now));
    backend_adaptation.set_property(ctx, "preferredGroupKey", JSValue::string(ctx, preferred_group_key));
    backend_adaptation.set_property(
        ctx,
        "sharedLoadedBackendCount",
        JSValue::int(shared_loaded_backend_ids.len() as i32),
    );
    backend_adaptation.set_property(ctx, "controllerLoadedOnlyBackendCount", JSValue::int(0));
    backend_adaptation.set_property(ctx, "targetLoadedOnlyBackendCount", JSValue::int(0));
    backend_adaptation.set_property(
        ctx,
        "filesystemOnlyBackendCount",
        JSValue::int(filesystem_only_backend_ids.len() as i32),
    );
    set_string_array_property(
        ctx,
        backend_adaptation.raw(),
        "sharedLoadedBackendIds",
        &shared_loaded_backend_ids,
    );
    set_string_array_property(
        ctx,
        backend_adaptation.raw(),
        "controllerLoadedOnlyBackendIds",
        &empty_backend_ids,
    );
    set_string_array_property(
        ctx,
        backend_adaptation.raw(),
        "targetLoadedOnlyBackendIds",
        &empty_backend_ids,
    );
    set_string_array_property(
        ctx,
        backend_adaptation.raw(),
        "filesystemOnlyBackendIds",
        &filesystem_only_backend_ids,
    );
    hook_set_command_template_group_properties(ctx, &backend_adaptation, "query", &query_templates);
    hook_set_command_template_group_properties(ctx, &backend_adaptation, "preflight", &preflight_templates);
    hook_set_command_template_group_properties(ctx, &backend_adaptation, "cleanup", &cleanup_templates);
    hook_set_command_template_group_properties(ctx, &backend_adaptation, "install", &install_templates);
    hook_set_command_template_group_properties(ctx, &backend_adaptation, "preferred", &preferred_templates);
    backend_adaptation.set_property(
        ctx,
        "queryGroup",
        JSValue(hook_command_template_group_to_js(ctx, "query", &query_templates)),
    );
    backend_adaptation.set_property(
        ctx,
        "preflightGroup",
        JSValue(hook_command_template_group_to_js(
            ctx,
            "preflight",
            &preflight_templates,
        )),
    );
    backend_adaptation.set_property(
        ctx,
        "cleanupGroup",
        JSValue(hook_command_template_group_to_js(ctx, "cleanup", &cleanup_templates)),
    );
    backend_adaptation.set_property(
        ctx,
        "installGroup",
        JSValue(hook_command_template_group_to_js(ctx, "install", &install_templates)),
    );
    backend_adaptation.set_property(
        ctx,
        "preferredGroup",
        JSValue(hook_command_template_group_to_js(
            ctx,
            preferred_group_key,
            &preferred_templates,
        )),
    );
    let mut backend_recommendation_entries = report
        .backends
        .iter()
        .filter_map(|backend| {
            let has_loaded_runtime = !backend.loaded_images.is_empty();
            let has_filesystem_artifact = !backend.filesystem_paths.is_empty();
            if !has_loaded_runtime && !has_filesystem_artifact {
                return None;
            }
            let (scope, state, loaded_by, suggested_group_key, suggested_phase, reason, priority, templates) =
                if command_mode == "cleanup-only" {
                    (
                        if has_loaded_runtime { "shared" } else { "filesystem-only" },
                        if has_loaded_runtime {
                            "loaded-runtime"
                        } else {
                            "filesystem-artifact"
                        },
                        if has_loaded_runtime { "self" } else { "filesystem-only" },
                        "cleanup",
                        "cleanup",
                        "current policy only allows cleanup or status commands before retrying hook install",
                        0u8,
                        cleanup_templates.clone(),
                    )
                } else if has_filesystem_artifact && !has_loaded_runtime {
                    (
                        "filesystem-only",
                        "filesystem-artifact",
                        "filesystem-only",
                        "preflight",
                        "preflight",
                        "filesystem artifact detected for this backend; refresh diagnostics before inline install",
                        1u8,
                        preflight_templates.clone(),
                    )
                } else {
                    (
                        "shared",
                        "loaded-runtime",
                        "self",
                        "query",
                        "query",
                        if multiple_external_backends_loaded {
                            "multiple external backend runtimes are loaded in this process; inspect this backend before changing hook state"
                        } else {
                            "this backend runtime is loaded in the current process; query first before changing hook state"
                        },
                        2u8,
                        query_templates.clone(),
                    )
                };
            Some((
                suggested_group_key == preferred_group_key,
                priority,
                backend.id.clone(),
                hook_backend_specific_recommendation_to_js(
                    ctx,
                    backend,
                    scope,
                    state,
                    loaded_by,
                    suggested_group_key,
                    suggested_phase,
                    reason,
                    priority,
                    &templates,
                ),
            ))
        })
        .collect::<Vec<_>>();
    backend_recommendation_entries
        .sort_by(|left, right| (!left.0, left.1, left.2.as_str()).cmp(&(!right.0, right.1, right.2.as_str())));
    for (index, (_, _, _, item)) in backend_recommendation_entries.iter().enumerate() {
        let item_value = JSValue(*item);
        if index == 0 {
            preferred_backend_recommendation = Some(item_value.dup(ctx));
        }
        ffi::JS_SetPropertyUint32(ctx, backend_specific_recommendations, index as u32, item_value.raw());
        backend_specific_recommendation_count += 1;
    }
    backend_adaptation.set_property(
        ctx,
        "backendSpecificRecommendationCount",
        JSValue::int(backend_specific_recommendation_count as i32),
    );
    backend_adaptation.set_property(
        ctx,
        "backendSpecificRecommendations",
        JSValue(backend_specific_recommendations),
    );
    match &preferred_backend_recommendation {
        Some(item) => backend_adaptation.set_property(ctx, "preferredBackendRecommendation", item.dup(ctx)),
        None => backend_adaptation.set_property(ctx, "preferredBackendRecommendation", JSValue::null()),
    };
    match &preferred_backend_recommendation {
        Some(item) => {
            backend_adaptation.set_property(ctx, "preferredBackendId", item.get_property(ctx, "backendId"));
            backend_adaptation.set_property(
                ctx,
                "preferredBackendDisplayName",
                item.get_property(ctx, "displayName"),
            );
            backend_adaptation.set_property(ctx, "preferredBackendScope", item.get_property(ctx, "scope"));
            backend_adaptation.set_property(ctx, "preferredBackendState", item.get_property(ctx, "state"));
            backend_adaptation.set_property(ctx, "preferredBackendLoadedBy", item.get_property(ctx, "loadedBy"));
            backend_adaptation.set_property(
                ctx,
                "preferredBackendVisibleInController",
                item.get_property(ctx, "visibleInController"),
            );
            backend_adaptation.set_property(
                ctx,
                "preferredBackendVisibleInTarget",
                item.get_property(ctx, "visibleInTarget"),
            );
            backend_adaptation.set_property(
                ctx,
                "preferredBackendSuggestedGroupKey",
                item.get_property(ctx, "suggestedGroupKey"),
            );
            backend_adaptation.set_property(
                ctx,
                "preferredBackendSuggestedPhase",
                item.get_property(ctx, "suggestedPhase"),
            );
            backend_adaptation.set_property(ctx, "preferredBackendReason", item.get_property(ctx, "reason"));
            backend_adaptation.set_property(ctx, "preferredBackendTemplates", item.get_property(ctx, "templates"));
            backend_adaptation.set_property(
                ctx,
                "preferredBackendTemplateCount",
                item.get_property(ctx, "templateCount"),
            );
            backend_adaptation.set_property(
                ctx,
                "preferredBackendCommandJsonTemplates",
                item.get_property(ctx, "commandJsonTemplates"),
            );
            backend_adaptation.set_property(
                ctx,
                "preferredBackendCommandJsonTemplateCount",
                item.get_property(ctx, "commandJsonTemplateCount"),
            );
            backend_adaptation.set_property(
                ctx,
                "preferredBackendCommandJsonEligibleTemplateCount",
                item.get_property(ctx, "commandJsonEligibleTemplateCount"),
            );
            backend_adaptation.set_property(
                ctx,
                "preferredBackendPrimaryCommandJsonTemplate",
                item.get_property(ctx, "primaryCommandJsonTemplate"),
            );
            backend_adaptation.set_property(
                ctx,
                "preferredBackendPrimaryCommandJsonTemplateCommand",
                item.get_property(ctx, "primaryCommandJsonTemplateCommand"),
            );
            backend_adaptation.set_property(
                ctx,
                "preferredBackendPrimaryCommandJsonTemplateKind",
                item.get_property(ctx, "primaryCommandJsonTemplateKind"),
            );
            backend_adaptation.set_property(
                ctx,
                "preferredBackendPrimaryCommandJsonTemplateEligible",
                item.get_property(ctx, "primaryCommandJsonTemplateEligible"),
            );
        }
        None => {
            for key in [
                "preferredBackendId",
                "preferredBackendDisplayName",
                "preferredBackendScope",
                "preferredBackendState",
                "preferredBackendLoadedBy",
                "preferredBackendVisibleInController",
                "preferredBackendVisibleInTarget",
                "preferredBackendSuggestedGroupKey",
                "preferredBackendSuggestedPhase",
                "preferredBackendReason",
                "preferredBackendTemplates",
                "preferredBackendTemplateCount",
                "preferredBackendCommandJsonTemplates",
                "preferredBackendCommandJsonTemplateCount",
                "preferredBackendCommandJsonEligibleTemplateCount",
                "preferredBackendPrimaryCommandJsonTemplate",
                "preferredBackendPrimaryCommandJsonTemplateCommand",
                "preferredBackendPrimaryCommandJsonTemplateKind",
                "preferredBackendPrimaryCommandJsonTemplateEligible",
            ] {
                backend_adaptation.set_property(ctx, key, JSValue::null());
            }
        }
    }
    let conflict_resolution_group_key = if command_mode == "blocked" {
        "none"
    } else if requires_cleanup_phase {
        "cleanup"
    } else if preferred_group_key == "preflight" {
        "preflight"
    } else {
        "query"
    };
    let conflict_resolution_phase = match conflict_resolution_group_key {
        "preflight" => "preflight",
        "cleanup" => "cleanup",
        "query" => "query",
        _ => "blocked",
    };
    let conflict_resolution_reason = match conflict_resolution_group_key {
        "preflight" => "refresh diagnostics before attempting to realign backend runtimes in this process",
        "cleanup" => "clean up active hook state before attempting to realign backend runtimes",
        "query" => "keep the flow query-first until backend runtimes in this process are aligned",
        _ => "no compatible conflict resolution path is currently available",
    };
    let conflict_resolution_steps = hook_conflict_resolution_steps_for_group(conflict_resolution_group_key);
    let conflict_backend_pairs = ffi::JS_NewArray(ctx);
    let mut conflict_backend_pair_count = 0usize;
    let loaded_backends = report
        .backends
        .iter()
        .filter(|backend| !backend.loaded_images.is_empty())
        .collect::<Vec<_>>();
    for left_index in 0..loaded_backends.len() {
        for right_index in (left_index + 1)..loaded_backends.len() {
            let left_backend = loaded_backends[left_index];
            let right_backend = loaded_backends[right_index];
            let pair = JSValue(hook_backend_conflict_pair_to_js(
                ctx,
                left_backend,
                right_backend,
                conflict_resolution_group_key,
                conflict_resolution_phase,
                conflict_resolution_reason,
                &query_templates,
                &preflight_templates,
                &cleanup_templates,
            ));
            if conflict_backend_pair_count == 0 {
                preferred_conflict_backend_pair = Some(pair.dup(ctx));
            }
            ffi::JS_SetPropertyUint32(
                ctx,
                conflict_backend_pairs,
                conflict_backend_pair_count as u32,
                pair.raw(),
            );
            conflict_backend_pair_count += 1;
        }
    }
    backend_adaptation.set_property(
        ctx,
        "conflictBackendPairCount",
        JSValue::int(conflict_backend_pair_count as i32),
    );
    backend_adaptation.set_property(ctx, "conflictBackendPairs", JSValue(conflict_backend_pairs));
    match &preferred_conflict_backend_pair {
        Some(item) => backend_adaptation.set_property(ctx, "preferredConflictBackendPair", item.dup(ctx)),
        None => backend_adaptation.set_property(ctx, "preferredConflictBackendPair", JSValue::null()),
    };
    let topology_requires_conflict_resolution = matches!(topology_kind, "shared-loaded" | "split-loaded");
    let preferred_conflict_resolution_plan = if topology_requires_conflict_resolution
        && conflict_resolution_group_key != "none"
        && !conflict_resolution_steps.is_empty()
    {
        let templates = match conflict_resolution_group_key {
            "query" => query_templates.clone(),
            "preflight" => preflight_templates.clone(),
            "cleanup" => cleanup_templates.clone(),
            _ => Vec::new(),
        };
        let (command_json_templates, command_json_eligible_template_count) =
            hook_command_json_template_array_to_js(ctx, &templates);
        let resolution_chain = ffi::JS_NewArray(ctx);
        for (index, (group_key, phase, reason)) in conflict_resolution_steps.iter().enumerate() {
            let step_templates =
                hook_backend_templates_for_group(group_key, &query_templates, &preflight_templates, &cleanup_templates);
            let entry = JSValue(hook_backend_conflict_resolution_chain_entry_to_js(
                ctx,
                index,
                group_key,
                phase,
                reason,
                step_templates,
            ));
            ffi::JS_SetPropertyUint32(ctx, resolution_chain, index as u32, entry.raw());
        }
        let plan = JSValue(ffi::JS_NewObject(ctx));
        plan.set_property(
            ctx,
            "suggestedGroupKey",
            JSValue::string(ctx, conflict_resolution_group_key),
        );
        plan.set_property(
            ctx,
            "resolutionReason",
            JSValue::string(ctx, conflict_resolution_reason),
        );
        plan.set_property(ctx, "templates", JSValue(string_vec_to_js_array(ctx, &templates)));
        plan.set_property(ctx, "templateCount", JSValue::int(templates.len() as i32));
        plan.set_property(ctx, "commandJsonTemplates", JSValue(command_json_templates));
        plan.set_property(ctx, "commandJsonTemplateCount", JSValue::int(templates.len() as i32));
        plan.set_property(
            ctx,
            "commandJsonEligibleTemplateCount",
            JSValue::int(command_json_eligible_template_count as i32),
        );
        plan.set_property(ctx, "resolutionChain", JSValue(resolution_chain));
        plan.set_property(
            ctx,
            "resolutionChainCount",
            JSValue::int(conflict_resolution_steps.len() as i32),
        );
        plan.set_property(
            ctx,
            "source",
            JSValue::string(
                ctx,
                if preferred_conflict_backend_pair.is_some() {
                    "conflict-backend-pair"
                } else {
                    "topology"
                },
            ),
        );
        Some(plan)
    } else {
        None
    };
    match &preferred_conflict_backend_pair {
        Some(item) => {
            backend_adaptation.set_property(
                ctx,
                "preferredConflictBackendPairKey",
                item.get_property(ctx, "pairKey"),
            );
            backend_adaptation.set_property(
                ctx,
                "preferredConflictBackendPairScope",
                item.get_property(ctx, "scope"),
            );
            backend_adaptation.set_property(
                ctx,
                "preferredConflictBackendPairReason",
                item.get_property(ctx, "reason"),
            );
            backend_adaptation.set_property(ctx, "preferredConflictBackendIds", item.get_property(ctx, "backendIds"));
            backend_adaptation.set_property(
                ctx,
                "preferredConflictBackendDisplayNames",
                item.get_property(ctx, "backendDisplayNames"),
            );
            backend_adaptation.set_property(
                ctx,
                "preferredConflictBackendPairTemplates",
                item.get_property(ctx, "templates"),
            );
            backend_adaptation.set_property(
                ctx,
                "preferredConflictBackendPairTemplateCount",
                item.get_property(ctx, "templateCount"),
            );
            backend_adaptation.set_property(
                ctx,
                "preferredConflictBackendPairCommandJsonTemplates",
                item.get_property(ctx, "commandJsonTemplates"),
            );
            backend_adaptation.set_property(
                ctx,
                "preferredConflictBackendPairCommandJsonTemplateCount",
                item.get_property(ctx, "commandJsonTemplateCount"),
            );
            backend_adaptation.set_property(
                ctx,
                "preferredConflictBackendPairCommandJsonEligibleTemplateCount",
                item.get_property(ctx, "commandJsonEligibleTemplateCount"),
            );
            backend_adaptation.set_property(
                ctx,
                "preferredConflictBackendPairPrimaryCommandJsonTemplate",
                item.get_property(ctx, "primaryCommandJsonTemplate"),
            );
            backend_adaptation.set_property(
                ctx,
                "preferredConflictBackendPairPrimaryCommandJsonTemplateCommand",
                item.get_property(ctx, "primaryCommandJsonTemplateCommand"),
            );
            backend_adaptation.set_property(
                ctx,
                "preferredConflictBackendPairPrimaryCommandJsonTemplateKind",
                item.get_property(ctx, "primaryCommandJsonTemplateKind"),
            );
            backend_adaptation.set_property(
                ctx,
                "preferredConflictBackendPairPrimaryCommandJsonTemplateEligible",
                item.get_property(ctx, "primaryCommandJsonTemplateEligible"),
            );
        }
        None => {
            for key in [
                "preferredConflictBackendPairKey",
                "preferredConflictBackendPairScope",
                "preferredConflictBackendPairReason",
                "preferredConflictBackendIds",
                "preferredConflictBackendDisplayNames",
                "preferredConflictBackendPairTemplates",
                "preferredConflictBackendPairTemplateCount",
                "preferredConflictBackendPairCommandJsonTemplates",
                "preferredConflictBackendPairCommandJsonTemplateCount",
                "preferredConflictBackendPairCommandJsonEligibleTemplateCount",
                "preferredConflictBackendPairPrimaryCommandJsonTemplate",
                "preferredConflictBackendPairPrimaryCommandJsonTemplateCommand",
                "preferredConflictBackendPairPrimaryCommandJsonTemplateKind",
                "preferredConflictBackendPairPrimaryCommandJsonTemplateEligible",
                "preferredConflictResolutionGroupKey",
                "preferredConflictResolutionReason",
                "preferredConflictResolutionTemplates",
                "preferredConflictResolutionTemplateCount",
                "preferredConflictResolutionCommandJsonTemplates",
                "preferredConflictResolutionCommandJsonTemplateCount",
                "preferredConflictResolutionCommandJsonEligibleTemplateCount",
                "preferredConflictResolutionChain",
                "preferredConflictResolutionChainCount",
                "preferredConflictResolutionPhaseOrder",
                "preferredConflictResolutionRetryableStepCount",
                "preferredConflictResolutionTotalRetryBudget",
                "preferredConflictResolutionTerminationPolicy",
                "preferredConflictResolutionRouting",
            ] {
                backend_adaptation.set_property(ctx, key, JSValue::null());
            }
        }
    }
    match &preferred_conflict_resolution_plan {
        Some(item) => {
            backend_adaptation.set_property(
                ctx,
                "preferredConflictResolutionGroupKey",
                item.get_property(ctx, "suggestedGroupKey"),
            );
            backend_adaptation.set_property(
                ctx,
                "preferredConflictResolutionReason",
                item.get_property(ctx, "resolutionReason"),
            );
            backend_adaptation.set_property(
                ctx,
                "preferredConflictResolutionTemplates",
                item.get_property(ctx, "templates"),
            );
            backend_adaptation.set_property(
                ctx,
                "preferredConflictResolutionTemplateCount",
                item.get_property(ctx, "templateCount"),
            );
            backend_adaptation.set_property(
                ctx,
                "preferredConflictResolutionCommandJsonTemplates",
                item.get_property(ctx, "commandJsonTemplates"),
            );
            backend_adaptation.set_property(
                ctx,
                "preferredConflictResolutionCommandJsonTemplateCount",
                item.get_property(ctx, "commandJsonTemplateCount"),
            );
            backend_adaptation.set_property(
                ctx,
                "preferredConflictResolutionCommandJsonEligibleTemplateCount",
                item.get_property(ctx, "commandJsonEligibleTemplateCount"),
            );
            backend_adaptation.set_property(
                ctx,
                "preferredConflictResolutionChain",
                item.get_property(ctx, "resolutionChain"),
            );
            backend_adaptation.set_property(
                ctx,
                "preferredConflictResolutionChainCount",
                item.get_property(ctx, "resolutionChainCount"),
            );
            let phase_order = conflict_resolution_steps
                .iter()
                .map(|(_, phase, _)| (*phase).to_string())
                .collect::<Vec<_>>();
            let retryable_step_count = conflict_resolution_steps
                .iter()
                .filter(|(_, phase, _)| hook_conflict_resolution_phase_retry_policy(phase).0)
                .count();
            let total_retry_budget = conflict_resolution_steps
                .iter()
                .map(|(_, phase, _)| hook_conflict_resolution_phase_retry_policy(phase).1 as u64)
                .sum::<u64>();
            let termination_policy = JSValue(ffi::JS_NewObject(ctx));
            termination_policy.set_property(ctx, "mode", JSValue::string(ctx, "phase-retry-budget"));
            termination_policy.set_property(
                ctx,
                "terminateWhen",
                JSValue::string(ctx, "all-retryable-conflict-resolution-steps-exhausted"),
            );
            termination_policy.set_property(
                ctx,
                "escalateWhen",
                JSValue::string(ctx, "non-retryable-conflict-step-failed-or-budget-exhausted"),
            );
            termination_policy.set_property(
                ctx,
                "timeoutEscalateWhen",
                JSValue::string(ctx, "phase-timeout-exceeded"),
            );
            termination_policy.set_property(ctx, "retryableStepCount", JSValue::int(retryable_step_count as i32));
            termination_policy.set_property(
                ctx,
                "totalRetryBudget",
                JSValue(js_u64_to_js_number_or_bigint(ctx, total_retry_budget)),
            );
            backend_adaptation.set_property(
                ctx,
                "preferredConflictResolutionPhaseOrder",
                JSValue(string_vec_to_js_array(ctx, &phase_order)),
            );
            backend_adaptation.set_property(
                ctx,
                "preferredConflictResolutionRetryableStepCount",
                JSValue::int(retryable_step_count as i32),
            );
            backend_adaptation.set_property(
                ctx,
                "preferredConflictResolutionTotalRetryBudget",
                JSValue(js_u64_to_js_number_or_bigint(ctx, total_retry_budget)),
            );
            backend_adaptation.set_property(ctx, "preferredConflictResolutionTerminationPolicy", termination_policy);
            backend_adaptation.set_property(
                ctx,
                "preferredConflictResolutionRouting",
                JSValue(hook_conflict_resolution_routing_to_js(
                    ctx,
                    &conflict_resolution_steps,
                    &query_templates,
                    &preflight_templates,
                    &cleanup_templates,
                )),
            );
        }
        None => {
            for key in [
                "preferredConflictResolutionGroupKey",
                "preferredConflictResolutionReason",
                "preferredConflictResolutionTemplates",
                "preferredConflictResolutionTemplateCount",
                "preferredConflictResolutionCommandJsonTemplates",
                "preferredConflictResolutionCommandJsonTemplateCount",
                "preferredConflictResolutionCommandJsonEligibleTemplateCount",
                "preferredConflictResolutionChain",
                "preferredConflictResolutionChainCount",
                "preferredConflictResolutionPhaseOrder",
                "preferredConflictResolutionRetryableStepCount",
                "preferredConflictResolutionTotalRetryBudget",
                "preferredConflictResolutionTerminationPolicy",
                "preferredConflictResolutionRouting",
            ] {
                backend_adaptation.set_property(ctx, key, JSValue::null());
            }
        }
    }
    let has_preferred_conflict_resolution_plan = preferred_conflict_resolution_plan.is_some();
    let backend_adaptation_step_chain = ffi::JS_NewArray(ctx);
    let mut backend_adaptation_retry_budget = 0u64;
    let mut backend_adaptation_phase_order = Vec::new();
    let mut backend_adaptation_retryable_step_count = 0usize;
    let backend_adaptation_execution_kind = if has_preferred_conflict_resolution_plan {
        "conflict-resolution"
    } else {
        "preferred-group"
    };
    let backend_adaptation_step_chain_source = if has_preferred_conflict_resolution_plan
        && conflict_resolution_group_key != "none"
        && !conflict_resolution_steps.is_empty()
    {
        for (index, (group_key, phase, reason)) in conflict_resolution_steps.iter().enumerate() {
            let templates =
                hook_backend_templates_for_group(group_key, &query_templates, &preflight_templates, &cleanup_templates);
            let step = JSValue(hook_backend_conflict_resolution_step_to_js(
                ctx,
                conflict_resolution_group_key,
                index,
                group_key,
                phase,
                reason,
                templates,
            ));
            backend_adaptation_retry_budget += step
                .get_property(ctx, "maxSuggestedRetries")
                .to_i64(ctx)
                .unwrap_or(0)
                .max(0) as u64;
            if step.get_property(ctx, "retryable").to_bool().unwrap_or(false) {
                backend_adaptation_retryable_step_count += 1;
            }
            backend_adaptation_phase_order.push((*phase).to_string());
            ffi::JS_SetPropertyUint32(ctx, backend_adaptation_step_chain, index as u32, step.raw());
        }
        Some("preferred-conflict-resolution-chain")
    } else if backend_adaptation_allowed && !preferred_templates.is_empty() {
        for (index, template) in preferred_templates.iter().enumerate() {
            let template_value = JSValue(hook_command_json_template_to_js(ctx, template));
            let step = JSValue(hook_backend_adaptation_step_from_command_json_template_to_js(
                ctx,
                preferred_group_key,
                backend_adaptation_allowed,
                backend_adaptation_summary,
                index,
                template_value.raw(),
            ));
            template_value.free(ctx);
            backend_adaptation_retry_budget += step
                .get_property(ctx, "maxSuggestedRetries")
                .to_i64(ctx)
                .unwrap_or(0)
                .max(0) as u64;
            if step.get_property(ctx, "retryable").to_bool().unwrap_or(false) {
                backend_adaptation_retryable_step_count += 1;
            }
            if preferred_group_key != "none" {
                backend_adaptation_phase_order.push(preferred_group_key.to_string());
            }
            ffi::JS_SetPropertyUint32(ctx, backend_adaptation_step_chain, index as u32, step.raw());
        }
        Some("backend-adaptation-preferred-group")
    } else {
        None
    };
    let backend_adaptation_step_chain_count = if backend_adaptation_step_chain_source.is_some() {
        if has_preferred_conflict_resolution_plan
            && conflict_resolution_group_key != "none"
            && !conflict_resolution_steps.is_empty()
        {
            conflict_resolution_steps.len()
        } else {
            preferred_templates.len()
        }
    } else {
        0
    };
    let backend_adaptation_execution_summary = if let Some(source) = backend_adaptation_step_chain_source {
        let summary = JSValue(ffi::JS_NewObject(ctx));
        let selected_step = JSValue(ffi::JS_GetPropertyUint32(ctx, backend_adaptation_step_chain, 0));
        summary.set_property(ctx, "kind", JSValue::string(ctx, backend_adaptation_execution_kind));
        summary.set_property(ctx, "source", JSValue::string(ctx, source));
        summary.set_property(ctx, "mode", JSValue::string(ctx, backend_adaptation_mode));
        summary.set_property(ctx, "alignment", JSValue::string(ctx, backend_adaptation_alignment));
        summary.set_property(ctx, "preferredGroupKey", JSValue::string(ctx, preferred_group_key));
        summary.set_property(ctx, "selectedId", selected_step.get_property(ctx, "id"));
        summary.set_property(ctx, "selectedSource", selected_step.get_property(ctx, "source"));
        summary.set_property(ctx, "selectedActionKey", selected_step.get_property(ctx, "actionKey"));
        summary.set_property(ctx, "selectedAllowed", selected_step.get_property(ctx, "allowed"));
        summary.set_property(ctx, "selectedBlockedBy", selected_step.get_property(ctx, "blockedBy"));
        summary.set_property(ctx, "selectedBranch", selected_step.get_property(ctx, "branch"));
        summary.set_property(ctx, "selectedPhase", selected_step.get_property(ctx, "phase"));
        summary.set_property(ctx, "selectedCommand", selected_step.get_property(ctx, "command"));
        summary.set_property(ctx, "selectedReason", selected_step.get_property(ctx, "reason"));
        summary.set_property(
            ctx,
            "selectedPreferredPath",
            selected_step.get_property(ctx, "preferredPath"),
        );
        summary.set_property(
            ctx,
            "selectedCommandGroup",
            selected_step.get_property(ctx, "commandGroup"),
        );
        summary.set_property(ctx, "selectedRetryable", selected_step.get_property(ctx, "retryable"));
        summary.set_property(ctx, "selectedErrorCode", selected_step.get_property(ctx, "errorCode"));
        summary.set_property(
            ctx,
            "selectedTimeoutErrorCode",
            selected_step.get_property(ctx, "timeoutErrorCode"),
        );
        summary.set_property(
            ctx,
            "selectedTimeoutAction",
            selected_step.get_property(ctx, "timeoutAction"),
        );
        summary.set_property(ctx, "selectedReadyToRun", selected_step.get_property(ctx, "readyToRun"));
        summary.set_property(
            ctx,
            "selectedRequiresFallback",
            selected_step.get_property(ctx, "requiresFallback"),
        );
        summary.set_property(
            ctx,
            "selectedCommandJsonEligible",
            selected_step.get_property(ctx, "commandJsonEligible"),
        );
        summary.set_property(
            ctx,
            "selectedCommandJsonTemplate",
            selected_step.get_property(ctx, "commandJsonTemplate"),
        );
        summary.set_property(
            ctx,
            "selectedCommandJsonTemplateCommand",
            selected_step.get_property(ctx, "commandJsonTemplateCommand"),
        );
        summary.set_property(
            ctx,
            "selectedCommandJsonTemplateKind",
            selected_step.get_property(ctx, "commandJsonTemplateKind"),
        );
        summary.set_property(ctx, "selectedKind", selected_step.get_property(ctx, "kind"));
        summary.set_property(
            ctx,
            "selectedMaxSuggestedRetries",
            selected_step.get_property(ctx, "maxSuggestedRetries"),
        );
        summary.set_property(
            ctx,
            "selectedRetryDelayHintMs",
            selected_step.get_property(ctx, "retryDelayHintMs"),
        );
        summary.set_property(
            ctx,
            "selectedTimeoutHintMs",
            selected_step.get_property(ctx, "timeoutHintMs"),
        );
        summary.set_property(ctx, "selectedRisk", selected_step.get_property(ctx, "risk"));
        summary.set_property(
            ctx,
            "selectedPlaceholderCount",
            selected_step.get_property(ctx, "placeholderCount"),
        );
        summary.set_property(
            ctx,
            "selectedPlaceholders",
            selected_step.get_property(ctx, "placeholders"),
        );
        summary.set_property(ctx, "selectedCliArgs", selected_step.get_property(ctx, "cliArgs"));
        summary.set_property(
            ctx,
            "chainCount",
            JSValue::int(backend_adaptation_step_chain_count as i32),
        );
        summary.set_property(
            ctx,
            "phaseOrder",
            JSValue(string_vec_to_js_array(ctx, &backend_adaptation_phase_order)),
        );
        summary.set_property(
            ctx,
            "retryableStepCount",
            JSValue::int(backend_adaptation_retryable_step_count as i32),
        );
        summary.set_property(ctx, "hasConflictPair", JSValue::bool(conflict_backend_pair_count > 0));
        summary.set_property(ctx, "requiresQueryPhase", JSValue::bool(requires_query_phase));
        summary.set_property(ctx, "requiresPreflight", JSValue::bool(requires_preflight));
        summary.set_property(ctx, "requiresCleanupPhase", JSValue::bool(requires_cleanup_phase));
        summary.set_property(ctx, "inlineInstallReadyNow", JSValue::bool(inline_install_ready_now));
        summary.set_property(
            ctx,
            "retryBudget",
            JSValue(js_u64_to_js_number_or_bigint(ctx, backend_adaptation_retry_budget)),
        );
        selected_step.free(ctx);
        Some(summary)
    } else {
        None
    };
    if let Some(item) = &preferred_backend_recommendation {
        item.free(ctx);
    }
    if let Some(item) = &preferred_conflict_backend_pair {
        item.free(ctx);
    }
    match &backend_adaptation_execution_summary {
        Some(summary) => backend_adaptation.set_property(ctx, "executionSummary", summary.dup(ctx)),
        None => backend_adaptation.set_property(ctx, "executionSummary", JSValue::null()),
    };
    match &backend_adaptation_execution_summary {
        Some(summary) => {
            backend_adaptation.set_property(ctx, "executionKind", summary.get_property(ctx, "kind"));
            backend_adaptation.set_property(ctx, "executionSource", summary.get_property(ctx, "source"));
            backend_adaptation.set_property(ctx, "executionMode", summary.get_property(ctx, "mode"));
            backend_adaptation.set_property(ctx, "executionAlignment", summary.get_property(ctx, "alignment"));
            backend_adaptation.set_property(
                ctx,
                "executionPreferredGroupKey",
                summary.get_property(ctx, "preferredGroupKey"),
            );
            backend_adaptation.set_property(ctx, "executionSelectedId", summary.get_property(ctx, "selectedId"));
            backend_adaptation.set_property(
                ctx,
                "executionSelectedSource",
                summary.get_property(ctx, "selectedSource"),
            );
            backend_adaptation.set_property(
                ctx,
                "executionSelectedActionKey",
                summary.get_property(ctx, "selectedActionKey"),
            );
            backend_adaptation.set_property(
                ctx,
                "executionSelectedAllowed",
                summary.get_property(ctx, "selectedAllowed"),
            );
            backend_adaptation.set_property(
                ctx,
                "executionSelectedBlockedBy",
                summary.get_property(ctx, "selectedBlockedBy"),
            );
            backend_adaptation.set_property(
                ctx,
                "executionSelectedBranch",
                summary.get_property(ctx, "selectedBranch"),
            );
            backend_adaptation.set_property(
                ctx,
                "executionSelectedPhase",
                summary.get_property(ctx, "selectedPhase"),
            );
            backend_adaptation.set_property(
                ctx,
                "executionSelectedCommand",
                summary.get_property(ctx, "selectedCommand"),
            );
            backend_adaptation.set_property(
                ctx,
                "executionSelectedReason",
                summary.get_property(ctx, "selectedReason"),
            );
            backend_adaptation.set_property(
                ctx,
                "executionSelectedPreferredPath",
                summary.get_property(ctx, "selectedPreferredPath"),
            );
            backend_adaptation.set_property(
                ctx,
                "executionSelectedCommandGroup",
                summary.get_property(ctx, "selectedCommandGroup"),
            );
            backend_adaptation.set_property(
                ctx,
                "executionSelectedRetryable",
                summary.get_property(ctx, "selectedRetryable"),
            );
            backend_adaptation.set_property(
                ctx,
                "executionSelectedErrorCode",
                summary.get_property(ctx, "selectedErrorCode"),
            );
            backend_adaptation.set_property(
                ctx,
                "executionSelectedTimeoutErrorCode",
                summary.get_property(ctx, "selectedTimeoutErrorCode"),
            );
            backend_adaptation.set_property(
                ctx,
                "executionSelectedTimeoutAction",
                summary.get_property(ctx, "selectedTimeoutAction"),
            );
            backend_adaptation.set_property(
                ctx,
                "executionSelectedReadyToRun",
                summary.get_property(ctx, "selectedReadyToRun"),
            );
            backend_adaptation.set_property(
                ctx,
                "executionSelectedRequiresFallback",
                summary.get_property(ctx, "selectedRequiresFallback"),
            );
            backend_adaptation.set_property(
                ctx,
                "executionSelectedCommandJsonEligible",
                summary.get_property(ctx, "selectedCommandJsonEligible"),
            );
            backend_adaptation.set_property(
                ctx,
                "executionSelectedCommandJsonTemplate",
                summary.get_property(ctx, "selectedCommandJsonTemplate"),
            );
            backend_adaptation.set_property(
                ctx,
                "executionSelectedCommandJsonTemplateCommand",
                summary.get_property(ctx, "selectedCommandJsonTemplateCommand"),
            );
            backend_adaptation.set_property(
                ctx,
                "executionSelectedCommandJsonTemplateKind",
                summary.get_property(ctx, "selectedCommandJsonTemplateKind"),
            );
            backend_adaptation.set_property(ctx, "executionSelectedKind", summary.get_property(ctx, "selectedKind"));
            backend_adaptation.set_property(
                ctx,
                "executionSelectedMaxSuggestedRetries",
                summary.get_property(ctx, "selectedMaxSuggestedRetries"),
            );
            backend_adaptation.set_property(
                ctx,
                "executionSelectedRetryDelayHintMs",
                summary.get_property(ctx, "selectedRetryDelayHintMs"),
            );
            backend_adaptation.set_property(
                ctx,
                "executionSelectedTimeoutHintMs",
                summary.get_property(ctx, "selectedTimeoutHintMs"),
            );
            backend_adaptation.set_property(ctx, "executionSelectedRisk", summary.get_property(ctx, "selectedRisk"));
            backend_adaptation.set_property(
                ctx,
                "executionSelectedPlaceholderCount",
                summary.get_property(ctx, "selectedPlaceholderCount"),
            );
            backend_adaptation.set_property(
                ctx,
                "executionSelectedPlaceholders",
                summary.get_property(ctx, "selectedPlaceholders"),
            );
            backend_adaptation.set_property(
                ctx,
                "executionSelectedCliArgs",
                summary.get_property(ctx, "selectedCliArgs"),
            );
            backend_adaptation.set_property(ctx, "executionChainCount", summary.get_property(ctx, "chainCount"));
            backend_adaptation.set_property(ctx, "executionPhaseOrder", summary.get_property(ctx, "phaseOrder"));
            backend_adaptation.set_property(
                ctx,
                "executionRetryableStepCount",
                summary.get_property(ctx, "retryableStepCount"),
            );
            backend_adaptation.set_property(
                ctx,
                "executionHasConflictPair",
                summary.get_property(ctx, "hasConflictPair"),
            );
            backend_adaptation.set_property(
                ctx,
                "executionRequiresQueryPhase",
                summary.get_property(ctx, "requiresQueryPhase"),
            );
            backend_adaptation.set_property(
                ctx,
                "executionRequiresPreflight",
                summary.get_property(ctx, "requiresPreflight"),
            );
            backend_adaptation.set_property(
                ctx,
                "executionRequiresCleanupPhase",
                summary.get_property(ctx, "requiresCleanupPhase"),
            );
            backend_adaptation.set_property(
                ctx,
                "executionInlineInstallReadyNow",
                summary.get_property(ctx, "inlineInstallReadyNow"),
            );
            backend_adaptation.set_property(ctx, "executionRetryBudget", summary.get_property(ctx, "retryBudget"));
        }
        None => {
            for key in [
                "executionKind",
                "executionSource",
                "executionMode",
                "executionAlignment",
                "executionPreferredGroupKey",
                "executionSelectedId",
                "executionSelectedSource",
                "executionSelectedActionKey",
                "executionSelectedAllowed",
                "executionSelectedBlockedBy",
                "executionSelectedBranch",
                "executionSelectedPhase",
                "executionSelectedCommand",
                "executionSelectedReason",
                "executionSelectedPreferredPath",
                "executionSelectedCommandGroup",
                "executionSelectedRetryable",
                "executionSelectedErrorCode",
                "executionSelectedTimeoutErrorCode",
                "executionSelectedTimeoutAction",
                "executionSelectedReadyToRun",
                "executionSelectedRequiresFallback",
                "executionSelectedCommandJsonEligible",
                "executionSelectedCommandJsonTemplate",
                "executionSelectedCommandJsonTemplateCommand",
                "executionSelectedCommandJsonTemplateKind",
                "executionSelectedKind",
                "executionSelectedMaxSuggestedRetries",
                "executionSelectedRetryDelayHintMs",
                "executionSelectedTimeoutHintMs",
                "executionSelectedRisk",
                "executionSelectedPlaceholderCount",
                "executionSelectedPlaceholders",
                "executionSelectedCliArgs",
                "executionChainCount",
                "executionRetryableStepCount",
                "executionHasConflictPair",
                "executionRequiresQueryPhase",
                "executionRequiresPreflight",
                "executionRequiresCleanupPhase",
                "executionInlineInstallReadyNow",
                "executionRetryBudget",
            ] {
                backend_adaptation.set_property(ctx, key, JSValue::null());
            }
            backend_adaptation.set_property(ctx, "executionPhaseOrder", JSValue(ffi::JS_NewArray(ctx)));
        }
    }
    if let Some(summary) = &backend_adaptation_execution_summary {
        summary.free(ctx);
    }
    if let Some(source) = backend_adaptation_step_chain_source {
        let next_step = JSValue(ffi::JS_GetPropertyUint32(ctx, backend_adaptation_step_chain, 0));
        backend_adaptation.set_property(ctx, "nextStep", next_step.dup(ctx));
        backend_adaptation.set_property(ctx, "nextStepId", next_step.get_property(ctx, "id"));
        backend_adaptation.set_property(ctx, "nextStepSource", next_step.get_property(ctx, "source"));
        backend_adaptation.set_property(ctx, "nextStepActionKey", next_step.get_property(ctx, "actionKey"));
        backend_adaptation.set_property(ctx, "nextStepCommandGroup", next_step.get_property(ctx, "commandGroup"));
        backend_adaptation.set_property(ctx, "nextStepAllowed", next_step.get_property(ctx, "allowed"));
        backend_adaptation.set_property(ctx, "nextStepBlockedBy", next_step.get_property(ctx, "blockedBy"));
        backend_adaptation.set_property(ctx, "nextStepBranch", next_step.get_property(ctx, "branch"));
        backend_adaptation.set_property(ctx, "nextStepReason", next_step.get_property(ctx, "reason"));
        backend_adaptation.set_property(
            ctx,
            "nextStepPreferredPath",
            next_step.get_property(ctx, "preferredPath"),
        );
        backend_adaptation.set_property(ctx, "nextStepCommand", next_step.get_property(ctx, "command"));
        backend_adaptation.set_property(ctx, "nextStepPhase", next_step.get_property(ctx, "phase"));
        backend_adaptation.set_property(ctx, "nextStepKind", next_step.get_property(ctx, "kind"));
        backend_adaptation.set_property(
            ctx,
            "nextStepCommandJsonEligible",
            next_step.get_property(ctx, "commandJsonEligible"),
        );
        backend_adaptation.set_property(
            ctx,
            "nextStepCommandJsonTemplate",
            next_step.get_property(ctx, "commandJsonTemplate"),
        );
        backend_adaptation.set_property(
            ctx,
            "nextStepCommandJsonTemplateCommand",
            next_step.get_property(ctx, "commandJsonTemplateCommand"),
        );
        backend_adaptation.set_property(
            ctx,
            "nextStepCommandJsonTemplateKind",
            next_step.get_property(ctx, "commandJsonTemplateKind"),
        );
        backend_adaptation.set_property(ctx, "nextStepRetryable", next_step.get_property(ctx, "retryable"));
        backend_adaptation.set_property(
            ctx,
            "nextStepMaxSuggestedRetries",
            next_step.get_property(ctx, "maxSuggestedRetries"),
        );
        backend_adaptation.set_property(
            ctx,
            "nextStepRetryDelayHintMs",
            next_step.get_property(ctx, "retryDelayHintMs"),
        );
        backend_adaptation.set_property(
            ctx,
            "nextStepTimeoutHintMs",
            next_step.get_property(ctx, "timeoutHintMs"),
        );
        backend_adaptation.set_property(
            ctx,
            "nextStepTimeoutAction",
            next_step.get_property(ctx, "timeoutAction"),
        );
        backend_adaptation.set_property(ctx, "nextStepErrorCode", next_step.get_property(ctx, "errorCode"));
        backend_adaptation.set_property(
            ctx,
            "nextStepTimeoutErrorCode",
            next_step.get_property(ctx, "timeoutErrorCode"),
        );
        backend_adaptation.set_property(ctx, "nextStepRisk", next_step.get_property(ctx, "risk"));
        backend_adaptation.set_property(
            ctx,
            "nextStepPlaceholderCount",
            next_step.get_property(ctx, "placeholderCount"),
        );
        backend_adaptation.set_property(ctx, "nextStepPlaceholders", next_step.get_property(ctx, "placeholders"));
        backend_adaptation.set_property(ctx, "nextStepCliArgs", next_step.get_property(ctx, "cliArgs"));
        backend_adaptation.set_property(ctx, "nextStepReadyToRun", next_step.get_property(ctx, "readyToRun"));
        backend_adaptation.set_property(
            ctx,
            "nextStepRequiresFallback",
            next_step.get_property(ctx, "requiresFallback"),
        );
        backend_adaptation.set_property(ctx, "stepChainSource", JSValue::string(ctx, source));
        backend_adaptation.set_property(
            ctx,
            "stepChainLimit",
            JSValue::int(backend_adaptation_step_chain_count as i32),
        );
        backend_adaptation.set_property(
            ctx,
            "stepChainCount",
            JSValue::int(backend_adaptation_step_chain_count as i32),
        );
        backend_adaptation.set_property(ctx, "stepChain", JSValue(backend_adaptation_step_chain));
        backend_adaptation.set_property(ctx, "stepChainTruncated", JSValue::bool(false));
        backend_adaptation.set_property(ctx, "activeStep", next_step);
        let active_step = backend_adaptation.get_property(ctx, "activeStep");
        backend_adaptation.set_property(ctx, "activeStepSource", active_step.get_property(ctx, "source"));
        backend_adaptation.set_property(ctx, "activeStepAllowed", active_step.get_property(ctx, "allowed"));
        backend_adaptation.set_property(ctx, "activeStepBlockedBy", active_step.get_property(ctx, "blockedBy"));
        backend_adaptation.set_property(ctx, "activeStepBranch", active_step.get_property(ctx, "branch"));
        backend_adaptation.set_property(ctx, "activeStepReason", active_step.get_property(ctx, "reason"));
        backend_adaptation.set_property(
            ctx,
            "activeStepPreferredPath",
            active_step.get_property(ctx, "preferredPath"),
        );
        backend_adaptation.set_property(ctx, "activeStepActionKey", active_step.get_property(ctx, "actionKey"));
        backend_adaptation.set_property(
            ctx,
            "activeStepCommandGroup",
            active_step.get_property(ctx, "commandGroup"),
        );
        backend_adaptation.set_property(ctx, "activeStepId", active_step.get_property(ctx, "id"));
        backend_adaptation.set_property(ctx, "activeStepCommand", active_step.get_property(ctx, "command"));
        backend_adaptation.set_property(ctx, "activeStepPhase", active_step.get_property(ctx, "phase"));
        backend_adaptation.set_property(ctx, "activeStepReadyToRun", active_step.get_property(ctx, "readyToRun"));
        backend_adaptation.set_property(
            ctx,
            "activeStepRequiresFallback",
            active_step.get_property(ctx, "requiresFallback"),
        );
        backend_adaptation.set_property(ctx, "activeStepKind", active_step.get_property(ctx, "kind"));
        backend_adaptation.set_property(
            ctx,
            "activeStepCommandJsonEligible",
            active_step.get_property(ctx, "commandJsonEligible"),
        );
        backend_adaptation.set_property(
            ctx,
            "activeStepCommandJsonTemplate",
            active_step.get_property(ctx, "commandJsonTemplate"),
        );
        backend_adaptation.set_property(
            ctx,
            "activeStepCommandJsonTemplateCommand",
            active_step.get_property(ctx, "commandJsonTemplateCommand"),
        );
        backend_adaptation.set_property(
            ctx,
            "activeStepCommandJsonTemplateKind",
            active_step.get_property(ctx, "commandJsonTemplateKind"),
        );
        backend_adaptation.set_property(ctx, "activeStepRetryable", active_step.get_property(ctx, "retryable"));
        backend_adaptation.set_property(
            ctx,
            "activeStepMaxSuggestedRetries",
            active_step.get_property(ctx, "maxSuggestedRetries"),
        );
        backend_adaptation.set_property(
            ctx,
            "activeStepRetryDelayHintMs",
            active_step.get_property(ctx, "retryDelayHintMs"),
        );
        backend_adaptation.set_property(
            ctx,
            "activeStepTimeoutHintMs",
            active_step.get_property(ctx, "timeoutHintMs"),
        );
        backend_adaptation.set_property(
            ctx,
            "activeStepTimeoutAction",
            active_step.get_property(ctx, "timeoutAction"),
        );
        backend_adaptation.set_property(ctx, "activeStepErrorCode", active_step.get_property(ctx, "errorCode"));
        backend_adaptation.set_property(
            ctx,
            "activeStepTimeoutErrorCode",
            active_step.get_property(ctx, "timeoutErrorCode"),
        );
        backend_adaptation.set_property(ctx, "activeStepRisk", active_step.get_property(ctx, "risk"));
        backend_adaptation.set_property(
            ctx,
            "activeStepPlaceholderCount",
            active_step.get_property(ctx, "placeholderCount"),
        );
        backend_adaptation.set_property(
            ctx,
            "activeStepPlaceholders",
            active_step.get_property(ctx, "placeholders"),
        );
        backend_adaptation.set_property(ctx, "activeStepCliArgs", active_step.get_property(ctx, "cliArgs"));
        active_step.free(ctx);
    } else {
        for key in [
            "nextStep",
            "nextStepId",
            "nextStepSource",
            "nextStepActionKey",
            "nextStepCommandGroup",
            "nextStepAllowed",
            "nextStepBlockedBy",
            "nextStepBranch",
            "nextStepReason",
            "nextStepPreferredPath",
            "nextStepCommand",
            "nextStepPhase",
            "nextStepKind",
            "nextStepCommandJsonEligible",
            "nextStepCommandJsonTemplate",
            "nextStepCommandJsonTemplateCommand",
            "nextStepCommandJsonTemplateKind",
            "nextStepRetryable",
            "nextStepMaxSuggestedRetries",
            "nextStepRetryDelayHintMs",
            "nextStepTimeoutHintMs",
            "nextStepTimeoutAction",
            "nextStepErrorCode",
            "nextStepTimeoutErrorCode",
            "nextStepRisk",
            "nextStepPlaceholderCount",
            "nextStepPlaceholders",
            "nextStepCliArgs",
            "nextStepReadyToRun",
            "nextStepRequiresFallback",
            "stepChainSource",
            "stepChainLimit",
            "stepChainCount",
            "stepChain",
            "stepChainTruncated",
            "activeStep",
            "activeStepSource",
            "activeStepAllowed",
            "activeStepBlockedBy",
            "activeStepBranch",
            "activeStepReason",
            "activeStepPreferredPath",
            "activeStepActionKey",
            "activeStepCommandGroup",
            "activeStepId",
            "activeStepCommand",
            "activeStepPhase",
            "activeStepReadyToRun",
            "activeStepRequiresFallback",
            "activeStepKind",
            "activeStepCommandJsonEligible",
            "activeStepCommandJsonTemplate",
            "activeStepCommandJsonTemplateCommand",
            "activeStepCommandJsonTemplateKind",
            "activeStepRetryable",
            "activeStepMaxSuggestedRetries",
            "activeStepRetryDelayHintMs",
            "activeStepTimeoutHintMs",
            "activeStepTimeoutAction",
            "activeStepErrorCode",
            "activeStepTimeoutErrorCode",
            "activeStepRisk",
            "activeStepPlaceholderCount",
            "activeStepPlaceholders",
            "activeStepCliArgs",
        ] {
            backend_adaptation.set_property(ctx, key, JSValue::null());
        }
    }
    if has_preferred_conflict_resolution_plan {
        backend_adaptation.set_property(
            ctx,
            "preferredConflictResolutionNextStep",
            backend_adaptation.get_property(ctx, "nextStep"),
        );
        backend_adaptation.set_property(
            ctx,
            "preferredConflictResolutionNextStepId",
            backend_adaptation.get_property(ctx, "nextStepId"),
        );
        backend_adaptation.set_property(
            ctx,
            "preferredConflictResolutionNextStepSource",
            backend_adaptation.get_property(ctx, "nextStepSource"),
        );
        backend_adaptation.set_property(
            ctx,
            "preferredConflictResolutionNextStepCommand",
            backend_adaptation.get_property(ctx, "nextStepCommand"),
        );
        backend_adaptation.set_property(
            ctx,
            "preferredConflictResolutionNextStepReason",
            backend_adaptation.get_property(ctx, "nextStepReason"),
        );
        backend_adaptation.set_property(
            ctx,
            "preferredConflictResolutionNextStepPreferredPath",
            backend_adaptation.get_property(ctx, "nextStepPreferredPath"),
        );
        backend_adaptation.set_property(
            ctx,
            "preferredConflictResolutionNextStepPhase",
            backend_adaptation.get_property(ctx, "nextStepPhase"),
        );
        backend_adaptation.set_property(
            ctx,
            "preferredConflictResolutionNextStepKind",
            backend_adaptation.get_property(ctx, "nextStepKind"),
        );
        backend_adaptation.set_property(
            ctx,
            "preferredConflictResolutionNextStepCommandJsonEligible",
            backend_adaptation.get_property(ctx, "nextStepCommandJsonEligible"),
        );
        backend_adaptation.set_property(
            ctx,
            "preferredConflictResolutionNextStepCommandJsonTemplate",
            backend_adaptation.get_property(ctx, "nextStepCommandJsonTemplate"),
        );
        backend_adaptation.set_property(
            ctx,
            "preferredConflictResolutionNextStepCommandJsonTemplateCommand",
            backend_adaptation.get_property(ctx, "nextStepCommandJsonTemplateCommand"),
        );
        backend_adaptation.set_property(
            ctx,
            "preferredConflictResolutionNextStepCommandJsonTemplateKind",
            backend_adaptation.get_property(ctx, "nextStepCommandJsonTemplateKind"),
        );
        backend_adaptation.set_property(
            ctx,
            "preferredConflictResolutionNextStepRetryable",
            backend_adaptation.get_property(ctx, "nextStepRetryable"),
        );
        backend_adaptation.set_property(
            ctx,
            "preferredConflictResolutionNextStepMaxSuggestedRetries",
            backend_adaptation.get_property(ctx, "nextStepMaxSuggestedRetries"),
        );
        backend_adaptation.set_property(
            ctx,
            "preferredConflictResolutionNextStepRetryDelayHintMs",
            backend_adaptation.get_property(ctx, "nextStepRetryDelayHintMs"),
        );
        backend_adaptation.set_property(
            ctx,
            "preferredConflictResolutionNextStepTimeoutHintMs",
            backend_adaptation.get_property(ctx, "nextStepTimeoutHintMs"),
        );
        backend_adaptation.set_property(
            ctx,
            "preferredConflictResolutionNextStepTimeoutAction",
            backend_adaptation.get_property(ctx, "nextStepTimeoutAction"),
        );
        backend_adaptation.set_property(
            ctx,
            "preferredConflictResolutionNextStepErrorCode",
            backend_adaptation.get_property(ctx, "nextStepErrorCode"),
        );
        backend_adaptation.set_property(
            ctx,
            "preferredConflictResolutionNextStepTimeoutErrorCode",
            backend_adaptation.get_property(ctx, "nextStepTimeoutErrorCode"),
        );
        backend_adaptation.set_property(
            ctx,
            "preferredConflictResolutionNextStepRisk",
            backend_adaptation.get_property(ctx, "nextStepRisk"),
        );
        backend_adaptation.set_property(
            ctx,
            "preferredConflictResolutionNextStepPlaceholderCount",
            backend_adaptation.get_property(ctx, "nextStepPlaceholderCount"),
        );
        backend_adaptation.set_property(
            ctx,
            "preferredConflictResolutionNextStepPlaceholders",
            backend_adaptation.get_property(ctx, "nextStepPlaceholders"),
        );
        backend_adaptation.set_property(
            ctx,
            "preferredConflictResolutionNextStepCliArgs",
            backend_adaptation.get_property(ctx, "nextStepCliArgs"),
        );
        backend_adaptation.set_property(
            ctx,
            "preferredConflictResolutionNextStepReadyToRun",
            backend_adaptation.get_property(ctx, "nextStepReadyToRun"),
        );
        backend_adaptation.set_property(
            ctx,
            "preferredConflictResolutionNextStepRequiresFallback",
            backend_adaptation.get_property(ctx, "nextStepRequiresFallback"),
        );
        backend_adaptation.set_property(
            ctx,
            "preferredConflictResolutionStepChainSource",
            backend_adaptation.get_property(ctx, "stepChainSource"),
        );
        backend_adaptation.set_property(
            ctx,
            "preferredConflictResolutionStepChainLimit",
            backend_adaptation.get_property(ctx, "stepChainLimit"),
        );
        backend_adaptation.set_property(
            ctx,
            "preferredConflictResolutionStepChainCount",
            backend_adaptation.get_property(ctx, "stepChainCount"),
        );
        backend_adaptation.set_property(
            ctx,
            "preferredConflictResolutionStepChain",
            backend_adaptation.get_property(ctx, "stepChain"),
        );
        backend_adaptation.set_property(
            ctx,
            "preferredConflictResolutionStepChainTruncated",
            backend_adaptation.get_property(ctx, "stepChainTruncated"),
        );
        backend_adaptation.set_property(
            ctx,
            "preferredConflictResolutionActiveStep",
            backend_adaptation.get_property(ctx, "activeStep"),
        );
        backend_adaptation.set_property(
            ctx,
            "preferredConflictResolutionActiveStepSource",
            backend_adaptation.get_property(ctx, "activeStepSource"),
        );
        backend_adaptation.set_property(
            ctx,
            "preferredConflictResolutionActiveStepAllowed",
            backend_adaptation.get_property(ctx, "activeStepAllowed"),
        );
        backend_adaptation.set_property(
            ctx,
            "preferredConflictResolutionActiveStepBlockedBy",
            backend_adaptation.get_property(ctx, "activeStepBlockedBy"),
        );
        backend_adaptation.set_property(
            ctx,
            "preferredConflictResolutionActiveStepBranch",
            backend_adaptation.get_property(ctx, "activeStepBranch"),
        );
        backend_adaptation.set_property(
            ctx,
            "preferredConflictResolutionActiveStepReason",
            backend_adaptation.get_property(ctx, "activeStepReason"),
        );
        backend_adaptation.set_property(
            ctx,
            "preferredConflictResolutionActiveStepPreferredPath",
            backend_adaptation.get_property(ctx, "activeStepPreferredPath"),
        );
        backend_adaptation.set_property(
            ctx,
            "preferredConflictResolutionActiveStepActionKey",
            backend_adaptation.get_property(ctx, "activeStepActionKey"),
        );
        backend_adaptation.set_property(
            ctx,
            "preferredConflictResolutionActiveStepCommandGroup",
            backend_adaptation.get_property(ctx, "activeStepCommandGroup"),
        );
        backend_adaptation.set_property(
            ctx,
            "preferredConflictResolutionActiveStepId",
            backend_adaptation.get_property(ctx, "activeStepId"),
        );
        backend_adaptation.set_property(
            ctx,
            "preferredConflictResolutionActiveStepCommand",
            backend_adaptation.get_property(ctx, "activeStepCommand"),
        );
        backend_adaptation.set_property(
            ctx,
            "preferredConflictResolutionActiveStepPhase",
            backend_adaptation.get_property(ctx, "activeStepPhase"),
        );
        backend_adaptation.set_property(
            ctx,
            "preferredConflictResolutionActiveStepCommandJsonEligible",
            backend_adaptation.get_property(ctx, "activeStepCommandJsonEligible"),
        );
        backend_adaptation.set_property(
            ctx,
            "preferredConflictResolutionActiveStepCommandJsonTemplate",
            backend_adaptation.get_property(ctx, "activeStepCommandJsonTemplate"),
        );
        backend_adaptation.set_property(
            ctx,
            "preferredConflictResolutionActiveStepCommandJsonTemplateCommand",
            backend_adaptation.get_property(ctx, "activeStepCommandJsonTemplateCommand"),
        );
        backend_adaptation.set_property(
            ctx,
            "preferredConflictResolutionActiveStepCommandJsonTemplateKind",
            backend_adaptation.get_property(ctx, "activeStepCommandJsonTemplateKind"),
        );
        backend_adaptation.set_property(
            ctx,
            "preferredConflictResolutionActiveStepReadyToRun",
            backend_adaptation.get_property(ctx, "activeStepReadyToRun"),
        );
        backend_adaptation.set_property(
            ctx,
            "preferredConflictResolutionActiveStepRequiresFallback",
            backend_adaptation.get_property(ctx, "activeStepRequiresFallback"),
        );
        backend_adaptation.set_property(
            ctx,
            "preferredConflictResolutionActiveStepKind",
            backend_adaptation.get_property(ctx, "activeStepKind"),
        );
        backend_adaptation.set_property(
            ctx,
            "preferredConflictResolutionActiveStepRetryable",
            backend_adaptation.get_property(ctx, "activeStepRetryable"),
        );
        backend_adaptation.set_property(
            ctx,
            "preferredConflictResolutionActiveStepMaxSuggestedRetries",
            backend_adaptation.get_property(ctx, "activeStepMaxSuggestedRetries"),
        );
        backend_adaptation.set_property(
            ctx,
            "preferredConflictResolutionActiveStepRetryDelayHintMs",
            backend_adaptation.get_property(ctx, "activeStepRetryDelayHintMs"),
        );
        backend_adaptation.set_property(
            ctx,
            "preferredConflictResolutionActiveStepTimeoutHintMs",
            backend_adaptation.get_property(ctx, "activeStepTimeoutHintMs"),
        );
        backend_adaptation.set_property(
            ctx,
            "preferredConflictResolutionActiveStepTimeoutAction",
            backend_adaptation.get_property(ctx, "activeStepTimeoutAction"),
        );
        backend_adaptation.set_property(
            ctx,
            "preferredConflictResolutionActiveStepErrorCode",
            backend_adaptation.get_property(ctx, "activeStepErrorCode"),
        );
        backend_adaptation.set_property(
            ctx,
            "preferredConflictResolutionActiveStepTimeoutErrorCode",
            backend_adaptation.get_property(ctx, "activeStepTimeoutErrorCode"),
        );
        backend_adaptation.set_property(
            ctx,
            "preferredConflictResolutionActiveStepRisk",
            backend_adaptation.get_property(ctx, "activeStepRisk"),
        );
        backend_adaptation.set_property(
            ctx,
            "preferredConflictResolutionActiveStepPlaceholderCount",
            backend_adaptation.get_property(ctx, "activeStepPlaceholderCount"),
        );
        backend_adaptation.set_property(
            ctx,
            "preferredConflictResolutionActiveStepPlaceholders",
            backend_adaptation.get_property(ctx, "activeStepPlaceholders"),
        );
        backend_adaptation.set_property(
            ctx,
            "preferredConflictResolutionActiveStepCliArgs",
            backend_adaptation.get_property(ctx, "activeStepCliArgs"),
        );
    } else {
        for key in [
            "preferredConflictResolutionNextStep",
            "preferredConflictResolutionNextStepId",
            "preferredConflictResolutionNextStepSource",
            "preferredConflictResolutionNextStepCommand",
            "preferredConflictResolutionNextStepReason",
            "preferredConflictResolutionNextStepPreferredPath",
            "preferredConflictResolutionNextStepPhase",
            "preferredConflictResolutionNextStepKind",
            "preferredConflictResolutionNextStepCommandJsonEligible",
            "preferredConflictResolutionNextStepCommandJsonTemplate",
            "preferredConflictResolutionNextStepCommandJsonTemplateCommand",
            "preferredConflictResolutionNextStepCommandJsonTemplateKind",
            "preferredConflictResolutionNextStepRetryable",
            "preferredConflictResolutionNextStepMaxSuggestedRetries",
            "preferredConflictResolutionNextStepRetryDelayHintMs",
            "preferredConflictResolutionNextStepTimeoutHintMs",
            "preferredConflictResolutionNextStepTimeoutAction",
            "preferredConflictResolutionNextStepErrorCode",
            "preferredConflictResolutionNextStepTimeoutErrorCode",
            "preferredConflictResolutionNextStepRisk",
            "preferredConflictResolutionNextStepPlaceholderCount",
            "preferredConflictResolutionNextStepPlaceholders",
            "preferredConflictResolutionNextStepCliArgs",
            "preferredConflictResolutionNextStepReadyToRun",
            "preferredConflictResolutionNextStepRequiresFallback",
            "preferredConflictResolutionStepChainSource",
            "preferredConflictResolutionStepChainLimit",
            "preferredConflictResolutionStepChainCount",
            "preferredConflictResolutionStepChain",
            "preferredConflictResolutionStepChainTruncated",
            "preferredConflictResolutionActiveStep",
            "preferredConflictResolutionActiveStepSource",
            "preferredConflictResolutionActiveStepAllowed",
            "preferredConflictResolutionActiveStepBlockedBy",
            "preferredConflictResolutionActiveStepBranch",
            "preferredConflictResolutionActiveStepReason",
            "preferredConflictResolutionActiveStepPreferredPath",
            "preferredConflictResolutionActiveStepActionKey",
            "preferredConflictResolutionActiveStepCommandGroup",
            "preferredConflictResolutionActiveStepId",
            "preferredConflictResolutionActiveStepCommand",
            "preferredConflictResolutionActiveStepPhase",
            "preferredConflictResolutionActiveStepReadyToRun",
            "preferredConflictResolutionActiveStepRequiresFallback",
            "preferredConflictResolutionActiveStepKind",
            "preferredConflictResolutionActiveStepCommandJsonEligible",
            "preferredConflictResolutionActiveStepCommandJsonTemplate",
            "preferredConflictResolutionActiveStepCommandJsonTemplateCommand",
            "preferredConflictResolutionActiveStepCommandJsonTemplateKind",
            "preferredConflictResolutionActiveStepRetryable",
            "preferredConflictResolutionActiveStepMaxSuggestedRetries",
            "preferredConflictResolutionActiveStepRetryDelayHintMs",
            "preferredConflictResolutionActiveStepTimeoutHintMs",
            "preferredConflictResolutionActiveStepTimeoutAction",
            "preferredConflictResolutionActiveStepErrorCode",
            "preferredConflictResolutionActiveStepTimeoutErrorCode",
            "preferredConflictResolutionActiveStepRisk",
            "preferredConflictResolutionActiveStepPlaceholderCount",
            "preferredConflictResolutionActiveStepPlaceholders",
            "preferredConflictResolutionActiveStepCliArgs",
        ] {
            backend_adaptation.set_property(ctx, key, JSValue::null());
        }
    }

    let preferred_conflict_resolution_routing =
        get_property_or_null(ctx, &backend_adaptation, "preferredConflictResolutionRouting");
    let preferred_conflict_resolution_routing_decision =
        get_property_or_null(ctx, &preferred_conflict_resolution_routing, "routingDecision");
    let preferred_conflict_resolution_ready =
        get_property_or_null(ctx, &preferred_conflict_resolution_routing_decision, "ready");
    set_property_aliases(
        ctx,
        &backend_adaptation,
        &preferred_conflict_resolution_routing,
        &[(
            "preferredConflictResolutionSuggestedEscalationKey",
            "suggestedEscalationKey",
        )],
    );
    set_property_aliases(
        ctx,
        &backend_adaptation,
        &preferred_conflict_resolution_ready,
        &[
            (
                "preferredConflictResolutionDefaultEscalationKey",
                "defaultEscalationKey",
            ),
            (
                "preferredConflictResolutionDefaultEffectiveEscalationKey",
                "defaultEffectiveEscalationKey",
            ),
            ("preferredConflictResolutionDefaultPhase", "defaultPhase"),
            (
                "preferredConflictResolutionDefaultEffectivePhase",
                "defaultEffectivePhase",
            ),
            (
                "preferredConflictResolutionDefaultTemplateCount",
                "defaultTemplateCount",
            ),
            ("preferredConflictResolutionDefaultTemplates", "defaultTemplates"),
            ("preferredConflictResolutionDefaultTemplate", "defaultTemplate"),
            (
                "preferredConflictResolutionDefaultCommandJsonTemplateCount",
                "defaultCommandJsonTemplateCount",
            ),
            (
                "preferredConflictResolutionDefaultCommandJsonEligibleTemplateCount",
                "defaultCommandJsonEligibleTemplateCount",
            ),
            (
                "preferredConflictResolutionDefaultCommandJsonTemplates",
                "defaultCommandJsonTemplates",
            ),
            (
                "preferredConflictResolutionDefaultCommandJsonTemplate",
                "defaultCommandJsonTemplate",
            ),
            (
                "preferredConflictResolutionDefaultCommandJsonTemplateCommand",
                "defaultCommandJsonTemplateCommand",
            ),
            (
                "preferredConflictResolutionDefaultCommandJsonTemplateKind",
                "defaultCommandJsonTemplateKind",
            ),
            (
                "preferredConflictResolutionDefaultCommandJsonTemplatePhase",
                "defaultCommandJsonTemplatePhase",
            ),
            (
                "preferredConflictResolutionDefaultCommandJsonTemplateErrorCode",
                "defaultCommandJsonTemplateErrorCode",
            ),
            (
                "preferredConflictResolutionDefaultCommandJsonTemplateEligible",
                "defaultCommandJsonTemplateEligible",
            ),
            ("preferredConflictResolutionPhaseCount", "phaseCount"),
            ("preferredConflictResolutionPhaseFirst", "phaseFirst"),
            ("preferredConflictResolutionPhaseLast", "phaseLast"),
            ("preferredConflictResolutionResolve", "resolve"),
            ("preferredConflictResolutionResolveIndex", "resolveIndex"),
            ("preferredConflictResolutionResolveIndexEntries", "resolveIndexEntries"),
            ("preferredConflictResolutionResolveDefault", "resolveDefault"),
            (
                "preferredConflictResolutionResolveDefaultEffective",
                "resolveDefaultEffective",
            ),
            ("preferredConflictResolutionResolveExamples", "resolveExamples"),
            ("preferredConflictResolutionResolveKnownCount", "resolveKnownCount"),
            ("preferredConflictResolutionResolveIndexCount", "resolveIndexCount"),
            (
                "preferredConflictResolutionResolveDefaultReason",
                "resolveDefaultReason",
            ),
            (
                "preferredConflictResolutionResolveDefaultMatched",
                "resolveDefaultMatched",
            ),
            (
                "preferredConflictResolutionResolveDefaultUsedDefault",
                "resolveDefaultUsedDefault",
            ),
            (
                "preferredConflictResolutionResolveDefaultEffectivePhase",
                "resolveDefaultEffectivePhase",
            ),
            (
                "preferredConflictResolutionResolveDefaultEffectiveEscalationKey",
                "resolveDefaultEffectiveEscalationKey",
            ),
            (
                "preferredConflictResolutionResolveExampleKnownErrorCode",
                "resolveExampleKnownErrorCode",
            ),
            (
                "preferredConflictResolutionResolveExampleKnownResult",
                "resolveExampleKnownResult",
            ),
            (
                "preferredConflictResolutionResolveExampleKnownResultEffective",
                "resolveExampleKnownResultEffective",
            ),
            (
                "preferredConflictResolutionResolveExampleKnownMatched",
                "resolveExampleKnownMatched",
            ),
            (
                "preferredConflictResolutionResolveExampleKnownUsedDefault",
                "resolveExampleKnownUsedDefault",
            ),
            (
                "preferredConflictResolutionResolveExampleKnownReason",
                "resolveExampleKnownReason",
            ),
            (
                "preferredConflictResolutionResolveExampleKnownEffectivePhase",
                "resolveExampleKnownEffectivePhase",
            ),
            (
                "preferredConflictResolutionResolveExampleKnownEffectiveEscalationKey",
                "resolveExampleKnownEffectiveEscalationKey",
            ),
            (
                "preferredConflictResolutionResolveExampleKnownResultEffectivePhase",
                "resolveExampleKnownResultEffectivePhase",
            ),
            (
                "preferredConflictResolutionResolveExampleKnownResultEffectiveEscalationKey",
                "resolveExampleKnownResultEffectiveEscalationKey",
            ),
            (
                "preferredConflictResolutionResolveExampleMissingResultEffectivePhase",
                "resolveExampleMissingResultEffectivePhase",
            ),
            (
                "preferredConflictResolutionResolveExampleMissingResult",
                "resolveExampleMissingResult",
            ),
            (
                "preferredConflictResolutionResolveExampleMissingResultEffective",
                "resolveExampleMissingResultEffective",
            ),
            (
                "preferredConflictResolutionResolveExampleMissingMatched",
                "resolveExampleMissingMatched",
            ),
            (
                "preferredConflictResolutionResolveExampleMissingUsedDefault",
                "resolveExampleMissingUsedDefault",
            ),
            (
                "preferredConflictResolutionResolveExampleMissingReason",
                "resolveExampleMissingReason",
            ),
            (
                "preferredConflictResolutionResolveExampleMissingEffectivePhase",
                "resolveExampleMissingEffectivePhase",
            ),
            (
                "preferredConflictResolutionResolveExampleMissingEffectiveEscalationKey",
                "resolveExampleMissingEffectiveEscalationKey",
            ),
            (
                "preferredConflictResolutionResolveExampleMissingResultEffectiveEscalationKey",
                "resolveExampleMissingResultEffectiveEscalationKey",
            ),
            (
                "preferredConflictResolutionResolveExampleQueryOnlyErrorCode",
                "resolveExampleQueryOnlyErrorCode",
            ),
            (
                "preferredConflictResolutionResolveExampleQueryOnlyInstallFailure",
                "resolveExampleQueryOnlyInstallFailure",
            ),
            (
                "preferredConflictResolutionResolveExampleQueryOnlyBlockedBy",
                "resolveExampleQueryOnlyBlockedBy",
            ),
            (
                "preferredConflictResolutionResolveExampleQueryOnlyBlockedBySource",
                "resolveExampleQueryOnlyBlockedBySource",
            ),
            (
                "preferredConflictResolutionResolveExampleQueryOnlyIsBlocked",
                "resolveExampleQueryOnlyIsBlocked",
            ),
            (
                "preferredConflictResolutionResolveExampleQueryOnlyAvailable",
                "resolveExampleQueryOnlyAvailable",
            ),
            (
                "preferredConflictResolutionResolveExampleQueryOnlyMatched",
                "resolveExampleQueryOnlyMatched",
            ),
            (
                "preferredConflictResolutionResolveExampleQueryOnlyUsedDefault",
                "resolveExampleQueryOnlyUsedDefault",
            ),
            (
                "preferredConflictResolutionResolveExampleQueryOnlyReason",
                "resolveExampleQueryOnlyReason",
            ),
            (
                "preferredConflictResolutionResolveExampleQueryOnlyEffectivePhase",
                "resolveExampleQueryOnlyEffectivePhase",
            ),
            (
                "preferredConflictResolutionResolveExampleQueryOnlyEffectiveEscalationKey",
                "resolveExampleQueryOnlyEffectiveEscalationKey",
            ),
            (
                "preferredConflictResolutionResolveExampleQueryOnlyWouldUsePath",
                "resolveExampleQueryOnlyWouldUsePath",
            ),
            (
                "preferredConflictResolutionResolveExampleQueryOnlyResult",
                "resolveExampleQueryOnlyResult",
            ),
            (
                "preferredConflictResolutionResolveExampleQueryOnlyResultEffective",
                "resolveExampleQueryOnlyResultEffective",
            ),
            (
                "preferredConflictResolutionResolveExampleQueryOnlyResultEffectivePhase",
                "resolveExampleQueryOnlyResultEffectivePhase",
            ),
            (
                "preferredConflictResolutionResolveExampleQueryOnlyResultEffectiveEscalationKey",
                "resolveExampleQueryOnlyResultEffectiveEscalationKey",
            ),
            ("preferredConflictResolutionResolveKnownResult", "resolveKnownResult"),
            (
                "preferredConflictResolutionResolveKnownResultEffective",
                "resolveKnownResultEffective",
            ),
            (
                "preferredConflictResolutionResolveKnownEffective",
                "resolveKnownEffective",
            ),
            ("preferredConflictResolutionResolveKnownMatched", "resolveKnownMatched"),
            (
                "preferredConflictResolutionResolveKnownUsedDefault",
                "resolveKnownUsedDefault",
            ),
            ("preferredConflictResolutionResolveKnownReason", "resolveKnownReason"),
            (
                "preferredConflictResolutionResolveKnownEffectivePhase",
                "resolveKnownEffectivePhase",
            ),
            (
                "preferredConflictResolutionResolveKnownEffectiveEscalationKey",
                "resolveKnownEffectiveEscalationKey",
            ),
            (
                "preferredConflictResolutionResolveMissingResult",
                "resolveMissingResult",
            ),
            (
                "preferredConflictResolutionResolveMissingResultEffective",
                "resolveMissingResultEffective",
            ),
            (
                "preferredConflictResolutionResolveMissingEffective",
                "resolveMissingEffective",
            ),
            (
                "preferredConflictResolutionResolveMissingMatched",
                "resolveMissingMatched",
            ),
            (
                "preferredConflictResolutionResolveMissingUsedDefault",
                "resolveMissingUsedDefault",
            ),
            (
                "preferredConflictResolutionResolveMissingReason",
                "resolveMissingReason",
            ),
            (
                "preferredConflictResolutionResolveMissingEffectivePhase",
                "resolveMissingEffectivePhase",
            ),
            (
                "preferredConflictResolutionResolveMissingEffectiveEscalationKey",
                "resolveMissingEffectiveEscalationKey",
            ),
            ("preferredConflictResolutionQueryOnlyErrorCode", "queryOnlyErrorCode"),
            (
                "preferredConflictResolutionQueryOnlySourceErrorCode",
                "queryOnlySourceErrorCode",
            ),
            ("preferredConflictResolutionQueryOnlyBlockedBy", "queryOnlyBlockedBy"),
            (
                "preferredConflictResolutionQueryOnlyBlockedBySource",
                "queryOnlyBlockedBySource",
            ),
            ("preferredConflictResolutionQueryOnlyIsBlocked", "queryOnlyIsBlocked"),
            ("preferredConflictResolutionQueryOnlyPhase", "queryOnlyPhase"),
            ("preferredConflictResolutionQueryOnlyAvailable", "queryOnlyAvailable"),
            ("preferredConflictResolutionQueryOnlyMatched", "queryOnlyMatched"),
            (
                "preferredConflictResolutionQueryOnlyUsedDefault",
                "queryOnlyUsedDefault",
            ),
            ("preferredConflictResolutionQueryOnlyReason", "queryOnlyReason"),
            (
                "preferredConflictResolutionQueryOnlyEffectivePhase",
                "queryOnlyEffectivePhase",
            ),
            (
                "preferredConflictResolutionQueryOnlyEffectiveEscalationKey",
                "queryOnlyEffectiveEscalationKey",
            ),
            (
                "preferredConflictResolutionQueryOnlyWouldUsePath",
                "queryOnlyWouldUsePath",
            ),
            (
                "preferredConflictResolutionQueryOnlyWouldUsePhase",
                "queryOnlyWouldUsePhase",
            ),
            ("preferredConflictResolutionQueryOnlyResult", "queryOnlyResult"),
            (
                "preferredConflictResolutionQueryOnlyResultEffective",
                "queryOnlyResultEffective",
            ),
            (
                "preferredConflictResolutionQueryOnlyResultMatched",
                "queryOnlyResultMatched",
            ),
            (
                "preferredConflictResolutionQueryOnlyResultUsedDefault",
                "queryOnlyResultUsedDefault",
            ),
            (
                "preferredConflictResolutionQueryOnlyResultReason",
                "queryOnlyResultReason",
            ),
            (
                "preferredConflictResolutionQueryOnlyResultEffectivePhase",
                "queryOnlyResultEffectivePhase",
            ),
            (
                "preferredConflictResolutionQueryOnlyResultEffectiveEscalationKey",
                "queryOnlyResultEffectiveEscalationKey",
            ),
            (
                "preferredConflictResolutionQueryOnlyResolveBlockedBy",
                "queryOnlyResolveBlockedBy",
            ),
            (
                "preferredConflictResolutionQueryOnlyResolveBlockedBySource",
                "queryOnlyResolveBlockedBySource",
            ),
            (
                "preferredConflictResolutionQueryOnlyResolveIsBlocked",
                "queryOnlyResolveIsBlocked",
            ),
            (
                "preferredConflictResolutionQueryOnlyResolveAvailable",
                "queryOnlyResolveAvailable",
            ),
            (
                "preferredConflictResolutionQueryOnlyResolveMatched",
                "queryOnlyResolveMatched",
            ),
            (
                "preferredConflictResolutionQueryOnlyResolveUsedDefault",
                "queryOnlyResolveUsedDefault",
            ),
            (
                "preferredConflictResolutionQueryOnlyResolveReason",
                "queryOnlyResolveReason",
            ),
            (
                "preferredConflictResolutionQueryOnlyResolveEffectivePhase",
                "queryOnlyResolveEffectivePhase",
            ),
            (
                "preferredConflictResolutionQueryOnlyResolveEffectiveEscalationKey",
                "queryOnlyResolveEffectiveEscalationKey",
            ),
            (
                "preferredConflictResolutionQueryOnlyResolveWouldUsePath",
                "queryOnlyResolveWouldUsePath",
            ),
            (
                "preferredConflictResolutionQueryOnlyResolveResult",
                "queryOnlyResolveResult",
            ),
            (
                "preferredConflictResolutionQueryOnlyResolveResultEffective",
                "queryOnlyResolveResultEffective",
            ),
            (
                "preferredConflictResolutionQueryOnlyResolveResultMatched",
                "queryOnlyResolveResultMatched",
            ),
            (
                "preferredConflictResolutionQueryOnlyResolveResultUsedDefault",
                "queryOnlyResolveResultUsedDefault",
            ),
            (
                "preferredConflictResolutionQueryOnlyResolveResultReason",
                "queryOnlyResolveResultReason",
            ),
            (
                "preferredConflictResolutionQueryOnlyResolveResultEffectivePhase",
                "queryOnlyResolveResultEffectivePhase",
            ),
            (
                "preferredConflictResolutionQueryOnlyResolveResultEffectiveEscalationKey",
                "queryOnlyResolveResultEffectiveEscalationKey",
            ),
            (
                "preferredConflictResolutionPhaseResolveKnownCount",
                "phaseResolveKnownCount",
            ),
            ("preferredConflictResolutionPhaseResolve", "phaseResolve"),
            ("preferredConflictResolutionPhaseResolveIndex", "phaseResolveIndex"),
            (
                "preferredConflictResolutionPhaseResolveIndexEntries",
                "phaseResolveIndexEntries",
            ),
            ("preferredConflictResolutionPhaseResolveDefault", "phaseResolveDefault"),
            (
                "preferredConflictResolutionPhaseResolveDefaultEffective",
                "phaseResolveDefaultEffective",
            ),
            (
                "preferredConflictResolutionPhaseResolveExamples",
                "phaseResolveExamples",
            ),
            (
                "preferredConflictResolutionPhaseResolveIndexCount",
                "phaseResolveIndexCount",
            ),
            (
                "preferredConflictResolutionPhaseResolveDefaultReason",
                "phaseResolveDefaultReason",
            ),
            (
                "preferredConflictResolutionPhaseResolveDefaultMatched",
                "phaseResolveDefaultMatched",
            ),
            (
                "preferredConflictResolutionPhaseResolveDefaultUsedDefault",
                "phaseResolveDefaultUsedDefault",
            ),
            (
                "preferredConflictResolutionPhaseResolveDefaultEffectivePhase",
                "phaseResolveDefaultEffectivePhase",
            ),
            (
                "preferredConflictResolutionPhaseResolveDefaultEffectiveEscalationKey",
                "phaseResolveDefaultEffectiveEscalationKey",
            ),
            (
                "preferredConflictResolutionPhaseResolveExampleKnownPhase",
                "phaseResolveExampleKnownPhase",
            ),
            (
                "preferredConflictResolutionPhaseResolveExampleKnownResult",
                "phaseResolveExampleKnownResult",
            ),
            (
                "preferredConflictResolutionPhaseResolveExampleKnownResultEffective",
                "phaseResolveExampleKnownResultEffective",
            ),
            (
                "preferredConflictResolutionPhaseResolveExampleKnownMatched",
                "phaseResolveExampleKnownMatched",
            ),
            (
                "preferredConflictResolutionPhaseResolveExampleKnownUsedDefault",
                "phaseResolveExampleKnownUsedDefault",
            ),
            (
                "preferredConflictResolutionPhaseResolveExampleKnownResultEffectivePhase",
                "phaseResolveExampleKnownResultEffectivePhase",
            ),
            (
                "preferredConflictResolutionPhaseResolveExampleKnownEffectivePhase",
                "phaseResolveExampleKnownEffectivePhase",
            ),
            (
                "preferredConflictResolutionPhaseResolveExampleKnownEffectiveEscalationKey",
                "phaseResolveExampleKnownEffectiveEscalationKey",
            ),
            (
                "preferredConflictResolutionPhaseResolveExampleKnownResultEffectiveEscalationKey",
                "phaseResolveExampleKnownResultEffectiveEscalationKey",
            ),
            (
                "preferredConflictResolutionPhaseResolveExampleKnownReason",
                "phaseResolveExampleKnownReason",
            ),
            (
                "preferredConflictResolutionPhaseResolveExampleMissingResultEffectivePhase",
                "phaseResolveExampleMissingResultEffectivePhase",
            ),
            (
                "preferredConflictResolutionPhaseResolveExampleMissingResult",
                "phaseResolveExampleMissingResult",
            ),
            (
                "preferredConflictResolutionPhaseResolveExampleMissingResultEffective",
                "phaseResolveExampleMissingResultEffective",
            ),
            (
                "preferredConflictResolutionPhaseResolveExampleMissingMatched",
                "phaseResolveExampleMissingMatched",
            ),
            (
                "preferredConflictResolutionPhaseResolveExampleMissingUsedDefault",
                "phaseResolveExampleMissingUsedDefault",
            ),
            (
                "preferredConflictResolutionPhaseResolveExampleMissingReason",
                "phaseResolveExampleMissingReason",
            ),
            (
                "preferredConflictResolutionPhaseResolveExampleMissingEffectivePhase",
                "phaseResolveExampleMissingEffectivePhase",
            ),
            (
                "preferredConflictResolutionPhaseResolveExampleMissingEffectiveEscalationKey",
                "phaseResolveExampleMissingEffectiveEscalationKey",
            ),
            (
                "preferredConflictResolutionPhaseResolveExampleMissingResultEffectiveEscalationKey",
                "phaseResolveExampleMissingResultEffectiveEscalationKey",
            ),
            (
                "preferredConflictResolutionPhaseResolveExampleQueryOnlySourceErrorCode",
                "phaseResolveExampleQueryOnlySourceErrorCode",
            ),
            (
                "preferredConflictResolutionPhaseResolveExampleQueryOnlyInstallFailure",
                "phaseResolveExampleQueryOnlyInstallFailure",
            ),
            (
                "preferredConflictResolutionPhaseResolveExampleQueryOnlyPhase",
                "phaseResolveExampleQueryOnlyPhase",
            ),
            (
                "preferredConflictResolutionPhaseResolveExampleQueryOnlyBlockedBy",
                "phaseResolveExampleQueryOnlyBlockedBy",
            ),
            (
                "preferredConflictResolutionPhaseResolveExampleQueryOnlyBlockedBySource",
                "phaseResolveExampleQueryOnlyBlockedBySource",
            ),
            (
                "preferredConflictResolutionPhaseResolveExampleQueryOnlyIsBlocked",
                "phaseResolveExampleQueryOnlyIsBlocked",
            ),
            (
                "preferredConflictResolutionPhaseResolveExampleQueryOnlyAvailable",
                "phaseResolveExampleQueryOnlyAvailable",
            ),
            (
                "preferredConflictResolutionPhaseResolveExampleQueryOnlyMatched",
                "phaseResolveExampleQueryOnlyMatched",
            ),
            (
                "preferredConflictResolutionPhaseResolveExampleQueryOnlyUsedDefault",
                "phaseResolveExampleQueryOnlyUsedDefault",
            ),
            (
                "preferredConflictResolutionPhaseResolveExampleQueryOnlyReason",
                "phaseResolveExampleQueryOnlyReason",
            ),
            (
                "preferredConflictResolutionPhaseResolveExampleQueryOnlyEffectivePhase",
                "phaseResolveExampleQueryOnlyEffectivePhase",
            ),
            (
                "preferredConflictResolutionPhaseResolveExampleQueryOnlyEffectiveEscalationKey",
                "phaseResolveExampleQueryOnlyEffectiveEscalationKey",
            ),
            (
                "preferredConflictResolutionPhaseResolveExampleQueryOnlyWouldUsePhase",
                "phaseResolveExampleQueryOnlyWouldUsePhase",
            ),
            (
                "preferredConflictResolutionPhaseResolveExampleQueryOnlyResult",
                "phaseResolveExampleQueryOnlyResult",
            ),
            (
                "preferredConflictResolutionPhaseResolveExampleQueryOnlyResultEffective",
                "phaseResolveExampleQueryOnlyResultEffective",
            ),
            (
                "preferredConflictResolutionPhaseResolveExampleQueryOnlyResultEffectivePhase",
                "phaseResolveExampleQueryOnlyResultEffectivePhase",
            ),
            (
                "preferredConflictResolutionPhaseResolveExampleQueryOnlyResultEffectiveEscalationKey",
                "phaseResolveExampleQueryOnlyResultEffectiveEscalationKey",
            ),
            (
                "preferredConflictResolutionPhaseResolveKnownResult",
                "phaseResolveKnownResult",
            ),
            (
                "preferredConflictResolutionPhaseResolveKnownResultEffective",
                "phaseResolveKnownResultEffective",
            ),
            (
                "preferredConflictResolutionPhaseResolveKnownEffective",
                "phaseResolveKnownEffective",
            ),
            (
                "preferredConflictResolutionPhaseResolveKnownMatched",
                "phaseResolveKnownMatched",
            ),
            (
                "preferredConflictResolutionPhaseResolveKnownUsedDefault",
                "phaseResolveKnownUsedDefault",
            ),
            (
                "preferredConflictResolutionPhaseResolveKnownReason",
                "phaseResolveKnownReason",
            ),
            (
                "preferredConflictResolutionPhaseResolveKnownEffectivePhase",
                "phaseResolveKnownEffectivePhase",
            ),
            (
                "preferredConflictResolutionPhaseResolveKnownEffectiveEscalationKey",
                "phaseResolveKnownEffectiveEscalationKey",
            ),
            (
                "preferredConflictResolutionPhaseResolveMissingResult",
                "phaseResolveMissingResult",
            ),
            (
                "preferredConflictResolutionPhaseResolveMissingResultEffective",
                "phaseResolveMissingResultEffective",
            ),
            (
                "preferredConflictResolutionPhaseResolveMissingEffective",
                "phaseResolveMissingEffective",
            ),
            (
                "preferredConflictResolutionPhaseResolveMissingMatched",
                "phaseResolveMissingMatched",
            ),
            (
                "preferredConflictResolutionPhaseResolveMissingUsedDefault",
                "phaseResolveMissingUsedDefault",
            ),
            (
                "preferredConflictResolutionPhaseResolveMissingReason",
                "phaseResolveMissingReason",
            ),
            (
                "preferredConflictResolutionPhaseResolveMissingEffectivePhase",
                "phaseResolveMissingEffectivePhase",
            ),
            (
                "preferredConflictResolutionPhaseResolveMissingEffectiveEscalationKey",
                "phaseResolveMissingEffectiveEscalationKey",
            ),
            (
                "preferredConflictResolutionQueryOnlyPhaseResolveSourceErrorCode",
                "queryOnlyPhaseResolveSourceErrorCode",
            ),
            (
                "preferredConflictResolutionQueryOnlyPhaseResolvePhase",
                "queryOnlyPhaseResolvePhase",
            ),
            (
                "preferredConflictResolutionQueryOnlyPhaseResolveBlockedBy",
                "queryOnlyPhaseResolveBlockedBy",
            ),
            (
                "preferredConflictResolutionQueryOnlyPhaseResolveBlockedBySource",
                "queryOnlyPhaseResolveBlockedBySource",
            ),
            (
                "preferredConflictResolutionQueryOnlyPhaseResolveIsBlocked",
                "queryOnlyPhaseResolveIsBlocked",
            ),
            (
                "preferredConflictResolutionQueryOnlyPhaseResolveAvailable",
                "queryOnlyPhaseResolveAvailable",
            ),
            (
                "preferredConflictResolutionQueryOnlyPhaseResolveMatched",
                "queryOnlyPhaseResolveMatched",
            ),
            (
                "preferredConflictResolutionQueryOnlyPhaseResolveUsedDefault",
                "queryOnlyPhaseResolveUsedDefault",
            ),
            (
                "preferredConflictResolutionQueryOnlyPhaseResolveReason",
                "queryOnlyPhaseResolveReason",
            ),
            (
                "preferredConflictResolutionQueryOnlyPhaseResolveEffectivePhase",
                "queryOnlyPhaseResolveEffectivePhase",
            ),
            (
                "preferredConflictResolutionQueryOnlyPhaseResolveEffectiveEscalationKey",
                "queryOnlyPhaseResolveEffectiveEscalationKey",
            ),
            (
                "preferredConflictResolutionQueryOnlyPhaseResolveWouldUsePhase",
                "queryOnlyPhaseResolveWouldUsePhase",
            ),
            (
                "preferredConflictResolutionQueryOnlyPhaseResolveResult",
                "queryOnlyPhaseResolveResult",
            ),
            (
                "preferredConflictResolutionQueryOnlyPhaseResolveResultEffective",
                "queryOnlyPhaseResolveResultEffective",
            ),
            (
                "preferredConflictResolutionQueryOnlyPhaseResolveResultMatched",
                "queryOnlyPhaseResolveResultMatched",
            ),
            (
                "preferredConflictResolutionQueryOnlyPhaseResolveResultUsedDefault",
                "queryOnlyPhaseResolveResultUsedDefault",
            ),
            (
                "preferredConflictResolutionQueryOnlyPhaseResolveResultReason",
                "queryOnlyPhaseResolveResultReason",
            ),
            (
                "preferredConflictResolutionQueryOnlyPhaseResolveResultEffectivePhase",
                "queryOnlyPhaseResolveResultEffectivePhase",
            ),
            (
                "preferredConflictResolutionQueryOnlyPhaseResolveResultEffectiveEscalationKey",
                "queryOnlyPhaseResolveResultEffectiveEscalationKey",
            ),
            (
                "preferredConflictResolutionPhaseQueryCommandJsonTemplateCommand",
                "phaseQueryCommandJsonTemplateCommand",
            ),
            ("preferredConflictResolutionPhaseQuery", "phaseQuery"),
            (
                "preferredConflictResolutionPhaseQueryErrorCodeCount",
                "phaseQueryErrorCodeCount",
            ),
            (
                "preferredConflictResolutionPhaseQueryEscalationKeyCount",
                "phaseQueryEscalationKeyCount",
            ),
            (
                "preferredConflictResolutionPhaseQueryEscalationKeys",
                "phaseQueryEscalationKeys",
            ),
            (
                "preferredConflictResolutionPhaseQueryPrimaryEscalationKey",
                "phaseQueryPrimaryEscalationKey",
            ),
            (
                "preferredConflictResolutionPhaseQueryTemplateCount",
                "phaseQueryTemplateCount",
            ),
            ("preferredConflictResolutionPhaseQueryTemplates", "phaseQueryTemplates"),
            ("preferredConflictResolutionPhaseQueryTemplate", "phaseQueryTemplate"),
            (
                "preferredConflictResolutionPhaseQueryCommandJsonTemplateCount",
                "phaseQueryCommandJsonTemplateCount",
            ),
            (
                "preferredConflictResolutionPhaseQueryCommandJsonEligibleTemplateCount",
                "phaseQueryCommandJsonEligibleTemplateCount",
            ),
            (
                "preferredConflictResolutionPhaseQueryCommandJsonTemplates",
                "phaseQueryCommandJsonTemplates",
            ),
            (
                "preferredConflictResolutionPhaseQueryCommandJsonTemplate",
                "phaseQueryCommandJsonTemplate",
            ),
            (
                "preferredConflictResolutionPhasePreflightCommandJsonTemplateCommand",
                "phasePreflightCommandJsonTemplateCommand",
            ),
            ("preferredConflictResolutionPhasePreflight", "phasePreflight"),
            (
                "preferredConflictResolutionPhasePreflightErrorCodeCount",
                "phasePreflightErrorCodeCount",
            ),
            (
                "preferredConflictResolutionPhasePreflightEscalationKeyCount",
                "phasePreflightEscalationKeyCount",
            ),
            (
                "preferredConflictResolutionPhasePreflightEscalationKeys",
                "phasePreflightEscalationKeys",
            ),
            (
                "preferredConflictResolutionPhasePreflightPrimaryEscalationKey",
                "phasePreflightPrimaryEscalationKey",
            ),
            (
                "preferredConflictResolutionPhasePreflightTemplateCount",
                "phasePreflightTemplateCount",
            ),
            (
                "preferredConflictResolutionPhasePreflightTemplates",
                "phasePreflightTemplates",
            ),
            (
                "preferredConflictResolutionPhasePreflightTemplate",
                "phasePreflightTemplate",
            ),
            (
                "preferredConflictResolutionPhasePreflightCommandJsonTemplateCount",
                "phasePreflightCommandJsonTemplateCount",
            ),
            (
                "preferredConflictResolutionPhasePreflightCommandJsonEligibleTemplateCount",
                "phasePreflightCommandJsonEligibleTemplateCount",
            ),
            (
                "preferredConflictResolutionPhasePreflightCommandJsonTemplates",
                "phasePreflightCommandJsonTemplates",
            ),
            (
                "preferredConflictResolutionPhasePreflightCommandJsonTemplate",
                "phasePreflightCommandJsonTemplate",
            ),
            ("preferredConflictResolutionPhaseCleanup", "phaseCleanup"),
            (
                "preferredConflictResolutionPhaseCleanupErrorCodeCount",
                "phaseCleanupErrorCodeCount",
            ),
            (
                "preferredConflictResolutionPhaseCleanupErrorCodes",
                "phaseCleanupErrorCodes",
            ),
            (
                "preferredConflictResolutionPhaseCleanupEscalationKeyCount",
                "phaseCleanupEscalationKeyCount",
            ),
            (
                "preferredConflictResolutionPhaseCleanupEscalationKeys",
                "phaseCleanupEscalationKeys",
            ),
            (
                "preferredConflictResolutionPhaseCleanupPrimaryEscalationKey",
                "phaseCleanupPrimaryEscalationKey",
            ),
            (
                "preferredConflictResolutionPhaseCleanupTemplateCount",
                "phaseCleanupTemplateCount",
            ),
            (
                "preferredConflictResolutionPhaseCleanupTemplates",
                "phaseCleanupTemplates",
            ),
            (
                "preferredConflictResolutionPhaseCleanupTemplate",
                "phaseCleanupTemplate",
            ),
            (
                "preferredConflictResolutionPhaseCleanupCommandJsonTemplateCount",
                "phaseCleanupCommandJsonTemplateCount",
            ),
            (
                "preferredConflictResolutionPhaseCleanupCommandJsonTemplates",
                "phaseCleanupCommandJsonTemplates",
            ),
            (
                "preferredConflictResolutionPhaseCleanupCommandJsonTemplate",
                "phaseCleanupCommandJsonTemplate",
            ),
            (
                "preferredConflictResolutionPhaseCleanupCommandJsonTemplateCommand",
                "phaseCleanupCommandJsonTemplateCommand",
            ),
        ],
    );
    set_nested_property_aliases(
        ctx,
        &backend_adaptation,
        &preferred_conflict_resolution_ready,
        &[
            ("preferredConflictResolutionPhaseFirstName", "phaseFirst", "phase"),
            ("preferredConflictResolutionPhaseLastName", "phaseLast", "phase"),
            (
                "preferredConflictResolutionPhaseQueryCommandJsonTemplateKind",
                "phaseQueryCommandJsonTemplate",
                "kind",
            ),
            (
                "preferredConflictResolutionPhaseQueryCommandJsonTemplateEligible",
                "phaseQueryCommandJsonTemplate",
                "commandJsonEligible",
            ),
            (
                "preferredConflictResolutionPhasePreflightCommandJsonTemplateKind",
                "phasePreflightCommandJsonTemplate",
                "kind",
            ),
            (
                "preferredConflictResolutionPhasePreflightCommandJsonTemplateEligible",
                "phasePreflightCommandJsonTemplate",
                "commandJsonEligible",
            ),
            (
                "preferredConflictResolutionPhaseCleanupCommandJsonTemplateKind",
                "phaseCleanupCommandJsonTemplate",
                "kind",
            ),
            (
                "preferredConflictResolutionPhaseCleanupCommandJsonTemplateEligible",
                "phaseCleanupCommandJsonTemplate",
                "commandJsonEligible",
            ),
        ],
    );
    preferred_conflict_resolution_ready.free(ctx);
    preferred_conflict_resolution_routing_decision.free(ctx);
    preferred_conflict_resolution_routing.free(ctx);

    match &report.active_backend {
        Some(active) => result.set_property(ctx, "activeBackend", JSValue::string(ctx, active)),
        None => result.set_property(ctx, "activeBackend", JSValue::null()),
    };
    match &active_backend_display_name {
        Some(display_name) => result.set_property(ctx, "activeBackendDisplayName", JSValue::string(ctx, display_name)),
        None => result.set_property(ctx, "activeBackendDisplayName", JSValue::null()),
    };
    result.set_property(ctx, "conflictState", JSValue::string(ctx, conflict_state));
    result.set_property(ctx, "riskLevel", JSValue::string(ctx, risk_level));
    result.set_property(ctx, "baseCommandMode", JSValue::string(ctx, command_mode));
    result.set_property(ctx, "effectiveCommandMode", JSValue::string(ctx, command_mode));
    result.set_property(ctx, "commandMode", JSValue::string(ctx, command_mode));
    result.set_property(ctx, "coexistenceMode", JSValue::string(ctx, coexistence_mode));
    result.set_property(ctx, "preferredPath", JSValue::string(ctx, coexistence_mode));
    result.set_property(ctx, "autoDowngradedToQueryOnly", JSValue::bool(false));
    result.set_property(ctx, "autoDowngradeReason", JSValue::null());
    result.set_property(ctx, "instrumentation", JSValue(instrumentation_capability_to_js(ctx)));
    result.set_property(ctx, "instrumentationBackend", JSValue::string(ctx, "arm64-hook-engine"));
    result.set_property(
        ctx,
        "instrumentationBackendDisplayName",
        JSValue::string(ctx, "ARM64 hook engine"),
    );
    result.set_property(
        ctx,
        "androidReferenceInstrumentationBackend",
        JSValue::string(ctx, "QBDI"),
    );
    result.set_property(ctx, "qbdiCompatible", JSValue::bool(false));
    result.set_property(ctx, "qbdiAvailable", JSValue::bool(false));
    result.set_property(ctx, "traceAvailable", JSValue::bool(true));
    result.set_property(ctx, "stalkerAvailable", JSValue::bool(true));
    result.set_property(
        ctx,
        "recommendedInstrumentationPath",
        JSValue::string(ctx, "trace-stalker-inline-hook"),
    );
    result.set_property(ctx, "backendAdaptation", backend_adaptation);
    result.set_property(
        ctx,
        "backendAdaptationMode",
        JSValue::string(ctx, backend_adaptation_mode),
    );
    result.set_property(
        ctx,
        "backendAdaptationAlignment",
        JSValue::string(ctx, backend_adaptation_alignment),
    );
    result.set_property(
        ctx,
        "backendAdaptationBias",
        JSValue::string(ctx, backend_adaptation_bias),
    );
    result.set_property(
        ctx,
        "backendAdaptationSummary",
        JSValue::string(ctx, backend_adaptation_summary),
    );
    result.set_property(
        ctx,
        "coexistenceRecommendation",
        JSValue::string(ctx, coexistence_recommendation),
    );
    let coexistence_layer = hook_coexistence_layer_status(report, decision.as_ref());
    result.set_property(
        ctx,
        "coexistenceLayerAvailable",
        JSValue::bool(coexistence_layer.available),
    );
    result.set_property(
        ctx,
        "coexistenceLayerRequired",
        JSValue::bool(coexistence_layer.required),
    );
    result.set_property(
        ctx,
        "coexistenceLayerStatus",
        JSValue::string(ctx, coexistence_layer.status),
    );
    result.set_property(
        ctx,
        "coexistenceLayerPreferredPhase",
        JSValue::string(ctx, coexistence_layer.preferred_phase),
    );
    result.set_property(
        ctx,
        "coexistenceLayerSummary",
        JSValue::string(ctx, coexistence_layer.summary),
    );
    match coexistence_layer.recommended_action_key {
        Some(action_key) => result.set_property(
            ctx,
            "coexistenceLayerRecommendedActionKey",
            JSValue::string(ctx, action_key),
        ),
        None => result.set_property(ctx, "coexistenceLayerRecommendedActionKey", JSValue::null()),
    };
    result.set_property(ctx, "backendPressure", JSValue::string(ctx, backend_pressure));
    result.set_property(ctx, "externalBackendLoaded", JSValue::bool(loaded_backend_count > 0));
    result.set_property(
        ctx,
        "singleExternalBackendLoaded",
        JSValue::bool(single_external_backend_loaded),
    );
    result.set_property(
        ctx,
        "multipleExternalBackendsLoaded",
        JSValue::bool(multiple_external_backends_loaded),
    );
    result.set_property(
        ctx,
        "filesystemOnlyBackendDetected",
        JSValue::bool(filesystem_only_backend_count > 0),
    );
    result.set_property(ctx, "backendCount", JSValue::int(backend_ids.len() as i32));
    result.set_property(ctx, "loadedBackendCount", JSValue::int(loaded_backend_count as i32));
    result.set_property(
        ctx,
        "loadedExternalBackendCount",
        JSValue::int(loaded_backend_count as i32),
    );
    result.set_property(
        ctx,
        "filesystemOnlyBackendCount",
        JSValue::int(filesystem_only_backend_count as i32),
    );
    set_string_array_property(ctx, result.raw(), "backendIds", &backend_ids);
    set_string_array_property(ctx, result.raw(), "backendDisplayNames", &backend_display_names);
    set_string_array_property(ctx, result.raw(), "loadedBackendIds", &shared_loaded_backend_ids);
    set_string_array_property(
        ctx,
        result.raw(),
        "loadedBackendDisplayNames",
        &shared_loaded_backend_display_names,
    );
    set_string_array_property(
        ctx,
        result.raw(),
        "filesystemOnlyBackendIds",
        &filesystem_only_backend_ids,
    );
    set_string_array_property(
        ctx,
        result.raw(),
        "filesystemOnlyBackendDisplayNames",
        &filesystem_only_backend_display_names,
    );
    result.set_property(ctx, "loadedImageCount", JSValue::int(loaded_image_count as i32));
    result.set_property(ctx, "filesystemPathCount", JSValue::int(filesystem_path_count as i32));

    if let Some(decision) = &decision {
        result.set_property(ctx, "policy", JSValue::string(ctx, decision.policy.as_str()));
        result.set_property(ctx, "strategy", JSValue::string(ctx, &decision.strategy));
        result.set_property(
            ctx,
            "commandModeSource",
            JSValue::string(ctx, decision.command_mode_source()),
        );
        result.set_property(
            ctx,
            "backendPressure",
            JSValue::string(ctx, decision.backend_pressure()),
        );
        result.set_property(ctx, "inlineHookRisk", JSValue::string(ctx, decision.inline_hook_risk()));
        result.set_property(
            ctx,
            "coexistenceRequired",
            JSValue::bool(decision.coexistence_required()),
        );
        result.set_property(ctx, "policyForced", JSValue::bool(decision.policy_forced()));
        result.set_property(ctx, "topologyForced", JSValue::bool(decision.topology_forced()));
        result.set_property(ctx, "filesystemCaution", JSValue::bool(decision.filesystem_caution()));
        result.set_property(ctx, "allowed", JSValue::bool(decision.allowed));
        result.set_property(ctx, "inlineHooksAllowed", JSValue::bool(decision.inline_hooks_allowed));
        result.set_property(
            ctx,
            "bootstrapInjectionAllowed",
            JSValue::bool(decision.bootstrap_injection_allowed()),
        );
        result.set_property(
            ctx,
            "queryCommandsAllowed",
            JSValue::bool(decision.query_commands_allowed()),
        );
        result.set_property(
            ctx,
            "hookInstallCommandsAllowed",
            JSValue::bool(decision.hook_install_commands_allowed()),
        );
        result.set_property(
            ctx,
            "hookInstallAllowed",
            JSValue::bool(decision.hook_install_commands_allowed()),
        );
        result.set_property(
            ctx,
            "hookStatusCommandsAllowed",
            JSValue::bool(decision.hook_status_commands_allowed()),
        );
        result.set_property(
            ctx,
            "hookStatusAllowed",
            JSValue::bool(decision.hook_status_commands_allowed()),
        );
        result.set_property(
            ctx,
            "hookStopCommandsAllowed",
            JSValue::bool(decision.hook_stop_commands_allowed()),
        );
        result.set_property(
            ctx,
            "hookStopAllowed",
            JSValue::bool(decision.hook_stop_commands_allowed()),
        );
        match &decision.reason {
            Some(reason) => result.set_property(ctx, "reason", JSValue::string(ctx, reason)),
            None => result.set_property(ctx, "reason", JSValue::null()),
        };
    } else {
        result.set_property(ctx, "policy", JSValue::string(ctx, "warn"));
        result.set_property(ctx, "strategy", JSValue::null());
        result.set_property(ctx, "commandModeSource", JSValue::string(ctx, "none"));
        result.set_property(ctx, "backendPressure", JSValue::string(ctx, "none"));
        result.set_property(ctx, "inlineHookRisk", JSValue::string(ctx, "safe"));
        result.set_property(ctx, "coexistenceRequired", JSValue::bool(false));
        result.set_property(ctx, "policyForced", JSValue::bool(false));
        result.set_property(ctx, "topologyForced", JSValue::bool(false));
        result.set_property(ctx, "filesystemCaution", JSValue::bool(false));
        result.set_property(ctx, "allowed", JSValue::bool(true));
        result.set_property(ctx, "inlineHooksAllowed", JSValue::bool(true));
        result.set_property(ctx, "bootstrapInjectionAllowed", JSValue::bool(true));
        result.set_property(ctx, "queryCommandsAllowed", JSValue::bool(true));
        result.set_property(ctx, "hookInstallCommandsAllowed", JSValue::bool(true));
        result.set_property(ctx, "hookInstallAllowed", JSValue::bool(true));
        result.set_property(ctx, "hookStatusCommandsAllowed", JSValue::bool(true));
        result.set_property(ctx, "hookStatusAllowed", JSValue::bool(true));
        result.set_property(ctx, "hookStopCommandsAllowed", JSValue::bool(true));
        result.set_property(ctx, "hookStopAllowed", JSValue::bool(true));
        result.set_property(ctx, "reason", JSValue::null());
    }

    let warnings = ffi::JS_NewArray(ctx);
    for (index, warning) in report.warnings.iter().enumerate() {
        ffi::JS_SetPropertyUint32(ctx, warnings, index as u32, JSValue::string(ctx, warning).raw());
    }
    result.set_property(ctx, "warnings", JSValue(warnings));

    let recommendations = ffi::JS_NewArray(ctx);
    for (index, recommendation) in hook_environment_recommendations(report, decision.as_ref())
        .iter()
        .enumerate()
    {
        ffi::JS_SetPropertyUint32(
            ctx,
            recommendations,
            index as u32,
            JSValue::string(ctx, recommendation).raw(),
        );
    }
    result.set_property(ctx, "recommendations", JSValue(recommendations));

    let recommended_actions_vec = hook_environment_recommended_actions(report, decision.as_ref());
    let allowed_action_count = recommended_actions_vec.iter().filter(|action| action.allowed).count();
    let blocked_action_count = recommended_actions_vec.len().saturating_sub(allowed_action_count);
    let mut ordered_action_indices = (0..recommended_actions_vec.len()).collect::<Vec<_>>();
    ordered_action_indices.sort_by_key(|index| {
        let action = &recommended_actions_vec[*index];
        (
            hook_action_mode_rank(command_mode, &action.action_key),
            action.priority,
            hook_effective_action_order(&action.action_key),
        )
    });
    let next_action_index = ordered_action_indices
        .iter()
        .copied()
        .find(|index| recommended_actions_vec[*index].allowed);
    let blocked_action_index = ordered_action_indices
        .iter()
        .copied()
        .find(|index| !recommended_actions_vec[*index].allowed);
    let selected_action_index = next_action_index.or(blocked_action_index);
    let next_action = selected_action_index.map(|index| &recommended_actions_vec[index]);
    let next_ready_action_index = ordered_action_indices
        .iter()
        .copied()
        .find(|index| hook_action_ready_to_run(&recommended_actions_vec, &recommended_actions_vec[*index]));
    let next_action_ready_to_run = next_action.map(|action| hook_action_ready_to_run(&recommended_actions_vec, action));
    let branch_execution_order = ordered_action_indices
        .iter()
        .map(|index| recommended_actions_vec[*index].action_key.clone())
        .collect::<Vec<_>>();
    let ready_branch_count = ordered_action_indices
        .iter()
        .filter(|index| hook_action_ready_to_run(&recommended_actions_vec, &recommended_actions_vec[**index]))
        .count();
    let blocked_branch_count = ordered_action_indices.len().saturating_sub(ready_branch_count);
    let suggested_sequence = hook_automation_suggested_sequence(coexistence_mode);
    let command_templates = ffi::JS_NewArray(ctx);
    let install_action = recommended_actions_vec
        .iter()
        .find(|action| action.action_key == "hook.install");
    result.set_property(
        ctx,
        "recommendedActionCount",
        JSValue::int(recommended_actions_vec.len() as i32),
    );
    result.set_property(ctx, "allowedActionCount", JSValue::int(allowed_action_count as i32));
    result.set_property(ctx, "blockedActionCount", JSValue::int(blocked_action_count as i32));
    result.set_property(ctx, "readyBranchCount", JSValue::int(ready_branch_count as i32));
    result.set_property(ctx, "blockedBranchCount", JSValue::int(blocked_branch_count as i32));
    set_string_array_property(ctx, result.raw(), "branchExecutionOrder", &branch_execution_order);
    match next_ready_action_index {
        Some(index) => result.set_property(
            ctx,
            "nextReadyActionKey",
            JSValue::string(ctx, &recommended_actions_vec[index].action_key),
        ),
        None => result.set_property(ctx, "nextReadyActionKey", JSValue::null()),
    };
    match next_action_index {
        Some(index) => result.set_property(
            ctx,
            "nextRunnableActionKey",
            JSValue::string(ctx, &recommended_actions_vec[index].action_key),
        ),
        None => result.set_property(ctx, "nextRunnableActionKey", JSValue::null()),
    };
    match blocked_action_index {
        Some(index) => result.set_property(
            ctx,
            "nextBlockedActionKey",
            JSValue::string(ctx, &recommended_actions_vec[index].action_key),
        ),
        None => result.set_property(ctx, "nextBlockedActionKey", JSValue::null()),
    };
    result.set_property(
        ctx,
        "hasSuggestedSequence",
        JSValue::bool(!suggested_sequence.is_empty()),
    );
    match install_action {
        Some(action) => {
            result.set_property(
                ctx,
                "installBlockedBy",
                JSValue::string(ctx, hook_action_blocked_by(action)),
            );
            result.set_property(
                ctx,
                "installRecommendation",
                JSValue::string(ctx, &action.recommendation),
            );
        }
        None => {
            result.set_property(ctx, "installBlockedBy", JSValue::null());
            result.set_property(ctx, "installRecommendation", JSValue::null());
        }
    }
    set_string_array_property(ctx, result.raw(), "suggestedSequence", &suggested_sequence);
    for (index, action) in recommended_actions_vec.iter().enumerate() {
        let templates = hook_action_command_templates(&action.action_key, coexistence_mode);
        let item = JSValue(ffi::JS_NewObject(ctx));
        item.set_property(ctx, "actionKey", JSValue::string(ctx, &action.action_key));
        item.set_property(ctx, "commandGroup", JSValue::string(ctx, &action.command_group));
        item.set_property(ctx, "templateCount", JSValue::int(templates.len() as i32));
        set_string_array_property(ctx, item.raw(), "templates", &templates);
        let command_json_templates_array = ffi::JS_NewArray(ctx);
        for (template_index, template) in templates.iter().enumerate() {
            ffi::JS_SetPropertyUint32(
                ctx,
                command_json_templates_array,
                template_index as u32,
                hook_command_json_template_to_js(ctx, template),
            );
        }
        item.set_property(ctx, "commandJsonTemplateCount", JSValue::int(templates.len() as i32));
        item.set_property(ctx, "commandJsonTemplates", JSValue(command_json_templates_array));
        ffi::JS_SetPropertyUint32(ctx, command_templates, index as u32, item.raw());
    }
    result.set_property(ctx, "commandTemplates", JSValue(command_templates));
    match next_action {
        Some(action) => {
            let next_action_templates = hook_action_command_templates(&action.action_key, coexistence_mode);
            let next_action_command_json_templates = next_action_templates
                .iter()
                .map(|template| hook_command_json_template_to_js(ctx, template))
                .collect::<Vec<_>>();
            let next_action_command_json_eligible_count = next_action_command_json_templates
                .iter()
                .filter(|entry| {
                    JSValue(**entry)
                        .get_property(ctx, "commandJsonEligible")
                        .to_bool()
                        .unwrap_or(false)
                })
                .count();
            let next_action_command_json_templates_array = ffi::JS_NewArray(ctx);
            let next_action_ready_to_run = next_action_ready_to_run.unwrap_or(false);
            let next_step_chain_limit = 3usize;
            let next_step_chain = ffi::JS_NewArray(ctx);
            let next_step_chain_count = next_action_command_json_templates.len().min(next_step_chain_limit);
            let next_step_chain_truncated = next_action_command_json_templates.len() > next_step_chain_limit;
            let mut first_step: Option<ffi::JSValue> = None;
            for (index, entry) in next_action_command_json_templates.iter().enumerate() {
                ffi::JS_SetPropertyUint32(ctx, next_action_command_json_templates_array, index as u32, *entry);
                if index < next_step_chain_limit {
                    let step = JSValue(hook_step_from_command_json_template_to_js(
                        ctx,
                        "next-action",
                        action,
                        next_action_ready_to_run,
                        index,
                        *entry,
                    ));
                    if index == 0 {
                        first_step = Some(step.dup(ctx).raw());
                    }
                    ffi::JS_SetPropertyUint32(ctx, next_step_chain, index as u32, step.raw());
                }
            }
            result.set_property(ctx, "nextAction", hook_recommended_action_to_js(ctx, action));
            result.set_property(
                ctx,
                "nextActionCommandGroup",
                JSValue::string(ctx, &action.command_group),
            );
            result.set_property(ctx, "nextActionKey", JSValue::string(ctx, &action.action_key));
            result.set_property(ctx, "nextActionPriority", JSValue::int(action.priority as i32));
            result.set_property(ctx, "nextActionAllowed", JSValue::bool(action.allowed));
            result.set_property(
                ctx,
                "nextActionBlockedBy",
                JSValue::string(ctx, hook_action_blocked_by(action)),
            );
            result.set_property(
                ctx,
                "nextActionBranch",
                JSValue::string(ctx, hook_action_branch(action)),
            );
            result.set_property(ctx, "nextActionStatus", JSValue::string(ctx, &action.status));
            result.set_property(
                ctx,
                "nextActionRecommendation",
                JSValue::string(ctx, &action.recommendation),
            );
            result.set_property(ctx, "nextActionReadyToRun", JSValue::bool(next_action_ready_to_run));
            result.set_property(
                ctx,
                "nextActionTemplateCount",
                JSValue::int(next_action_templates.len() as i32),
            );
            set_string_array_property(ctx, result.raw(), "nextActionTemplates", &next_action_templates);
            result.set_property(
                ctx,
                "nextActionCommandJsonTemplateCount",
                JSValue::int(next_action_command_json_templates.len() as i32),
            );
            result.set_property(
                ctx,
                "nextActionCommandJsonEligibleTemplateCount",
                JSValue::int(next_action_command_json_eligible_count as i32),
            );
            result.set_property(
                ctx,
                "nextActionCommandJsonTemplates",
                JSValue(next_action_command_json_templates_array),
            );
            result.set_property(
                ctx,
                "nextActionPlan",
                JSValue(hook_next_action_plan_to_js(
                    ctx,
                    &recommended_actions_vec,
                    action,
                    &next_action_templates,
                )),
            );
            match first_step {
                Some(step_raw) => {
                    let step = JSValue(step_raw);
                    let next_step_command_json_template = step.get_property(ctx, "commandJsonTemplate");
                    result.set_property(ctx, "nextStep", step.dup(ctx));
                    result.set_property(ctx, "nextStepSource", JSValue::string(ctx, "next-action"));
                    result.set_property(ctx, "nextStepId", step.get_property(ctx, "id"));
                    result.set_property(ctx, "nextStepActionKey", step.get_property(ctx, "actionKey"));
                    result.set_property(ctx, "nextStepCommandGroup", step.get_property(ctx, "commandGroup"));
                    result.set_property(ctx, "nextStepAllowed", step.get_property(ctx, "allowed"));
                    result.set_property(ctx, "nextStepBlockedBy", step.get_property(ctx, "blockedBy"));
                    result.set_property(ctx, "nextStepBranch", step.get_property(ctx, "branch"));
                    result.set_property(ctx, "nextStepReason", step.get_property(ctx, "reason"));
                    result.set_property(ctx, "nextStepPreferredPath", step.get_property(ctx, "preferredPath"));
                    result.set_property(ctx, "nextStepCommand", step.get_property(ctx, "command"));
                    result.set_property(ctx, "nextStepPhase", step.get_property(ctx, "phase"));
                    result.set_property(
                        ctx,
                        "nextStepCommandJsonEligible",
                        step.get_property(ctx, "commandJsonEligible"),
                    );
                    result.set_property(
                        ctx,
                        "nextStepCommandJsonTemplateEligible",
                        step.get_property(ctx, "commandJsonTemplateEligible"),
                    );
                    result.set_property(
                        ctx,
                        "nextStepCommandJsonTemplate",
                        next_step_command_json_template.dup(ctx),
                    );
                    result.set_property(
                        ctx,
                        "nextStepCommandJsonTemplateCommand",
                        next_step_command_json_template.get_property(ctx, "command"),
                    );
                    result.set_property(
                        ctx,
                        "nextStepCommandJsonTemplateKind",
                        next_step_command_json_template.get_property(ctx, "kind"),
                    );
                    result.set_property(ctx, "nextStepKind", step.get_property(ctx, "kind"));
                    result.set_property(ctx, "nextStepRetryable", step.get_property(ctx, "retryable"));
                    result.set_property(
                        ctx,
                        "nextStepMaxSuggestedRetries",
                        step.get_property(ctx, "maxSuggestedRetries"),
                    );
                    result.set_property(
                        ctx,
                        "nextStepRetryDelayHintMs",
                        step.get_property(ctx, "retryDelayHintMs"),
                    );
                    result.set_property(ctx, "nextStepTimeoutHintMs", step.get_property(ctx, "timeoutHintMs"));
                    result.set_property(ctx, "nextStepTimeoutAction", step.get_property(ctx, "timeoutAction"));
                    result.set_property(ctx, "nextStepErrorCode", step.get_property(ctx, "errorCode"));
                    result.set_property(
                        ctx,
                        "nextStepTimeoutErrorCode",
                        step.get_property(ctx, "timeoutErrorCode"),
                    );
                    result.set_property(ctx, "nextStepRisk", step.get_property(ctx, "risk"));
                    result.set_property(
                        ctx,
                        "nextStepPlaceholderCount",
                        step.get_property(ctx, "placeholderCount"),
                    );
                    result.set_property(ctx, "nextStepPlaceholders", step.get_property(ctx, "placeholders"));
                    result.set_property(ctx, "nextStepCliArgs", step.get_property(ctx, "cliArgs"));
                    result.set_property(ctx, "nextStepReadyToRun", step.get_property(ctx, "readyToRun"));
                    result.set_property(
                        ctx,
                        "nextStepRequiresFallback",
                        step.get_property(ctx, "requiresFallback"),
                    );
                    next_step_command_json_template.free(ctx);
                    let active_step_command_json_template = step.get_property(ctx, "commandJsonTemplate");
                    result.set_property(ctx, "activeStep", step.dup(ctx));
                    result.set_property(ctx, "activeStepSource", JSValue::string(ctx, "next-action"));
                    result.set_property(ctx, "activeStepAllowed", step.get_property(ctx, "allowed"));
                    result.set_property(ctx, "activeStepBlockedBy", step.get_property(ctx, "blockedBy"));
                    result.set_property(ctx, "activeStepBranch", step.get_property(ctx, "branch"));
                    result.set_property(ctx, "activeStepReason", step.get_property(ctx, "reason"));
                    result.set_property(ctx, "activeStepPreferredPath", step.get_property(ctx, "preferredPath"));
                    result.set_property(ctx, "activeStepActionKey", step.get_property(ctx, "actionKey"));
                    result.set_property(ctx, "activeStepCommandGroup", step.get_property(ctx, "commandGroup"));
                    result.set_property(ctx, "activeStepId", step.get_property(ctx, "id"));
                    result.set_property(ctx, "activeStepCommand", step.get_property(ctx, "command"));
                    result.set_property(ctx, "activeStepPhase", step.get_property(ctx, "phase"));
                    result.set_property(ctx, "activeStepReadyToRun", step.get_property(ctx, "readyToRun"));
                    result.set_property(
                        ctx,
                        "activeStepRequiresFallback",
                        step.get_property(ctx, "requiresFallback"),
                    );
                    result.set_property(ctx, "activeStepKind", step.get_property(ctx, "kind"));
                    result.set_property(
                        ctx,
                        "activeStepCommandJsonEligible",
                        step.get_property(ctx, "commandJsonEligible"),
                    );
                    result.set_property(
                        ctx,
                        "activeStepCommandJsonTemplateEligible",
                        step.get_property(ctx, "commandJsonTemplateEligible"),
                    );
                    result.set_property(
                        ctx,
                        "activeStepCommandJsonTemplate",
                        active_step_command_json_template.dup(ctx),
                    );
                    result.set_property(
                        ctx,
                        "activeStepCommandJsonTemplateCommand",
                        active_step_command_json_template.get_property(ctx, "command"),
                    );
                    result.set_property(
                        ctx,
                        "activeStepCommandJsonTemplateKind",
                        active_step_command_json_template.get_property(ctx, "kind"),
                    );
                    result.set_property(ctx, "activeStepRetryable", step.get_property(ctx, "retryable"));
                    result.set_property(
                        ctx,
                        "activeStepMaxSuggestedRetries",
                        step.get_property(ctx, "maxSuggestedRetries"),
                    );
                    result.set_property(
                        ctx,
                        "activeStepRetryDelayHintMs",
                        step.get_property(ctx, "retryDelayHintMs"),
                    );
                    result.set_property(ctx, "activeStepTimeoutHintMs", step.get_property(ctx, "timeoutHintMs"));
                    result.set_property(ctx, "activeStepTimeoutAction", step.get_property(ctx, "timeoutAction"));
                    result.set_property(ctx, "activeStepErrorCode", step.get_property(ctx, "errorCode"));
                    result.set_property(
                        ctx,
                        "activeStepTimeoutErrorCode",
                        step.get_property(ctx, "timeoutErrorCode"),
                    );
                    result.set_property(ctx, "activeStepRisk", step.get_property(ctx, "risk"));
                    result.set_property(
                        ctx,
                        "activeStepPlaceholderCount",
                        step.get_property(ctx, "placeholderCount"),
                    );
                    result.set_property(ctx, "activeStepPlaceholders", step.get_property(ctx, "placeholders"));
                    result.set_property(ctx, "activeStepCliArgs", step.get_property(ctx, "cliArgs"));
                    active_step_command_json_template.free(ctx);
                    step.free(ctx);
                }
                None => {
                    result.set_property(ctx, "nextStep", JSValue::null());
                    result.set_property(ctx, "nextStepSource", JSValue::null());
                    result.set_property(ctx, "nextStepId", JSValue::null());
                    result.set_property(ctx, "nextStepActionKey", JSValue::null());
                    result.set_property(ctx, "nextStepCommandGroup", JSValue::null());
                    result.set_property(ctx, "nextStepAllowed", JSValue::null());
                    result.set_property(ctx, "nextStepBlockedBy", JSValue::null());
                    result.set_property(ctx, "nextStepBranch", JSValue::null());
                    result.set_property(ctx, "nextStepReason", JSValue::null());
                    result.set_property(ctx, "nextStepPreferredPath", JSValue::null());
                    result.set_property(ctx, "nextStepCommand", JSValue::null());
                    result.set_property(ctx, "nextStepPhase", JSValue::null());
                    result.set_property(ctx, "nextStepCommandJsonEligible", JSValue::null());
                    result.set_property(ctx, "nextStepCommandJsonTemplateEligible", JSValue::null());
                    result.set_property(ctx, "nextStepCommandJsonTemplate", JSValue::null());
                    result.set_property(ctx, "nextStepCommandJsonTemplateCommand", JSValue::null());
                    result.set_property(ctx, "nextStepCommandJsonTemplateKind", JSValue::null());
                    result.set_property(ctx, "nextStepKind", JSValue::null());
                    result.set_property(ctx, "nextStepRetryable", JSValue::null());
                    result.set_property(ctx, "nextStepMaxSuggestedRetries", JSValue::null());
                    result.set_property(ctx, "nextStepRetryDelayHintMs", JSValue::null());
                    result.set_property(ctx, "nextStepTimeoutHintMs", JSValue::null());
                    result.set_property(ctx, "nextStepTimeoutAction", JSValue::null());
                    result.set_property(ctx, "nextStepErrorCode", JSValue::null());
                    result.set_property(ctx, "nextStepTimeoutErrorCode", JSValue::null());
                    result.set_property(ctx, "nextStepRisk", JSValue::null());
                    result.set_property(ctx, "nextStepPlaceholderCount", JSValue::null());
                    result.set_property(ctx, "nextStepPlaceholders", JSValue::null());
                    result.set_property(ctx, "nextStepCliArgs", JSValue::null());
                    result.set_property(ctx, "nextStepReadyToRun", JSValue::null());
                    result.set_property(ctx, "nextStepRequiresFallback", JSValue::null());
                    result.set_property(ctx, "activeStep", JSValue::null());
                    result.set_property(ctx, "activeStepSource", JSValue::null());
                    result.set_property(ctx, "activeStepAllowed", JSValue::null());
                    result.set_property(ctx, "activeStepBlockedBy", JSValue::null());
                    result.set_property(ctx, "activeStepBranch", JSValue::null());
                    result.set_property(ctx, "activeStepReason", JSValue::null());
                    result.set_property(ctx, "activeStepPreferredPath", JSValue::null());
                    result.set_property(ctx, "activeStepActionKey", JSValue::null());
                    result.set_property(ctx, "activeStepCommandGroup", JSValue::null());
                    result.set_property(ctx, "activeStepId", JSValue::null());
                    result.set_property(ctx, "activeStepCommand", JSValue::null());
                    result.set_property(ctx, "activeStepPhase", JSValue::null());
                    result.set_property(ctx, "activeStepReadyToRun", JSValue::null());
                    result.set_property(ctx, "activeStepRequiresFallback", JSValue::null());
                    result.set_property(ctx, "activeStepKind", JSValue::null());
                    result.set_property(ctx, "activeStepCommandJsonEligible", JSValue::null());
                    result.set_property(ctx, "activeStepCommandJsonTemplateEligible", JSValue::null());
                    result.set_property(ctx, "activeStepCommandJsonTemplate", JSValue::null());
                    result.set_property(ctx, "activeStepCommandJsonTemplateCommand", JSValue::null());
                    result.set_property(ctx, "activeStepCommandJsonTemplateKind", JSValue::null());
                    result.set_property(ctx, "activeStepRetryable", JSValue::null());
                    result.set_property(ctx, "activeStepMaxSuggestedRetries", JSValue::null());
                    result.set_property(ctx, "activeStepRetryDelayHintMs", JSValue::null());
                    result.set_property(ctx, "activeStepTimeoutHintMs", JSValue::null());
                    result.set_property(ctx, "activeStepTimeoutAction", JSValue::null());
                    result.set_property(ctx, "activeStepErrorCode", JSValue::null());
                    result.set_property(ctx, "activeStepTimeoutErrorCode", JSValue::null());
                    result.set_property(ctx, "activeStepRisk", JSValue::null());
                    result.set_property(ctx, "activeStepPlaceholderCount", JSValue::null());
                    result.set_property(ctx, "activeStepPlaceholders", JSValue::null());
                    result.set_property(ctx, "activeStepCliArgs", JSValue::null());
                }
            }
            result.set_property(ctx, "nextStepChainSource", JSValue::string(ctx, "next-action"));
            result.set_property(ctx, "nextStepChainLimit", JSValue::int(next_step_chain_limit as i32));
            result.set_property(ctx, "nextStepChainCount", JSValue::int(next_step_chain_count as i32));
            result.set_property(ctx, "nextStepChainTruncated", JSValue::bool(next_step_chain_truncated));
            result.set_property(ctx, "nextStepChain", JSValue(next_step_chain));
            match &action.reason {
                Some(reason) => result.set_property(ctx, "nextActionReason", JSValue::string(ctx, reason)),
                None => result.set_property(ctx, "nextActionReason", JSValue::null()),
            };
        }
        None => {
            result.set_property(ctx, "nextAction", JSValue::null());
            result.set_property(ctx, "nextActionCommandGroup", JSValue::null());
            result.set_property(ctx, "nextActionKey", JSValue::null());
            result.set_property(ctx, "nextActionPriority", JSValue::null());
            result.set_property(ctx, "nextActionAllowed", JSValue::null());
            result.set_property(ctx, "nextActionBlockedBy", JSValue::null());
            result.set_property(ctx, "nextActionBranch", JSValue::null());
            result.set_property(ctx, "nextActionStatus", JSValue::null());
            result.set_property(ctx, "nextActionRecommendation", JSValue::null());
            result.set_property(ctx, "nextActionReason", JSValue::null());
            result.set_property(ctx, "nextActionTemplateCount", JSValue::int(0));
            set_string_array_property(ctx, result.raw(), "nextActionTemplates", &[]);
            result.set_property(ctx, "nextActionCommandJsonTemplateCount", JSValue::int(0));
            result.set_property(ctx, "nextActionCommandJsonEligibleTemplateCount", JSValue::int(0));
            let next_action_command_json_templates = ffi::JS_NewArray(ctx);
            result.set_property(
                ctx,
                "nextActionCommandJsonTemplates",
                JSValue(next_action_command_json_templates),
            );
            result.set_property(ctx, "nextActionPlan", JSValue::null());
            result.set_property(ctx, "nextActionReadyToRun", JSValue::null());
            result.set_property(ctx, "nextStep", JSValue::null());
            result.set_property(ctx, "nextStepSource", JSValue::null());
            result.set_property(ctx, "nextStepId", JSValue::null());
            result.set_property(ctx, "nextStepActionKey", JSValue::null());
            result.set_property(ctx, "nextStepCommandGroup", JSValue::null());
            result.set_property(ctx, "nextStepAllowed", JSValue::null());
            result.set_property(ctx, "nextStepBlockedBy", JSValue::null());
            result.set_property(ctx, "nextStepBranch", JSValue::null());
            result.set_property(ctx, "nextStepReason", JSValue::null());
            result.set_property(ctx, "nextStepPreferredPath", JSValue::null());
            result.set_property(ctx, "nextStepCommand", JSValue::null());
            result.set_property(ctx, "nextStepPhase", JSValue::null());
            result.set_property(ctx, "nextStepCommandJsonEligible", JSValue::null());
            result.set_property(ctx, "nextStepCommandJsonTemplateEligible", JSValue::null());
            result.set_property(ctx, "nextStepCommandJsonTemplate", JSValue::null());
            result.set_property(ctx, "nextStepCommandJsonTemplateCommand", JSValue::null());
            result.set_property(ctx, "nextStepCommandJsonTemplateKind", JSValue::null());
            result.set_property(ctx, "nextStepKind", JSValue::null());
            result.set_property(ctx, "nextStepRetryable", JSValue::null());
            result.set_property(ctx, "nextStepMaxSuggestedRetries", JSValue::null());
            result.set_property(ctx, "nextStepRetryDelayHintMs", JSValue::null());
            result.set_property(ctx, "nextStepTimeoutHintMs", JSValue::null());
            result.set_property(ctx, "nextStepTimeoutAction", JSValue::null());
            result.set_property(ctx, "nextStepErrorCode", JSValue::null());
            result.set_property(ctx, "nextStepTimeoutErrorCode", JSValue::null());
            result.set_property(ctx, "nextStepRisk", JSValue::null());
            result.set_property(ctx, "nextStepPlaceholderCount", JSValue::null());
            result.set_property(ctx, "nextStepPlaceholders", JSValue::null());
            result.set_property(ctx, "nextStepCliArgs", JSValue::null());
            result.set_property(ctx, "nextStepReadyToRun", JSValue::null());
            result.set_property(ctx, "nextStepRequiresFallback", JSValue::null());
            result.set_property(ctx, "nextStepChainSource", JSValue::null());
            result.set_property(ctx, "nextStepChainLimit", JSValue::int(0));
            result.set_property(ctx, "nextStepChainCount", JSValue::int(0));
            result.set_property(ctx, "nextStepChainTruncated", JSValue::bool(false));
            let next_step_chain = ffi::JS_NewArray(ctx);
            result.set_property(ctx, "nextStepChain", JSValue(next_step_chain));
            result.set_property(ctx, "activeStep", JSValue::null());
            result.set_property(ctx, "activeStepSource", JSValue::null());
            result.set_property(ctx, "activeStepAllowed", JSValue::null());
            result.set_property(ctx, "activeStepBlockedBy", JSValue::null());
            result.set_property(ctx, "activeStepBranch", JSValue::null());
            result.set_property(ctx, "activeStepReason", JSValue::null());
            result.set_property(ctx, "activeStepPreferredPath", JSValue::null());
            result.set_property(ctx, "activeStepActionKey", JSValue::null());
            result.set_property(ctx, "activeStepCommandGroup", JSValue::null());
            result.set_property(ctx, "activeStepId", JSValue::null());
            result.set_property(ctx, "activeStepCommand", JSValue::null());
            result.set_property(ctx, "activeStepPhase", JSValue::null());
            result.set_property(ctx, "activeStepReadyToRun", JSValue::null());
            result.set_property(ctx, "activeStepRequiresFallback", JSValue::null());
            result.set_property(ctx, "activeStepKind", JSValue::null());
            result.set_property(ctx, "activeStepCommandJsonEligible", JSValue::null());
            result.set_property(ctx, "activeStepCommandJsonTemplateEligible", JSValue::null());
            result.set_property(ctx, "activeStepCommandJsonTemplate", JSValue::null());
            result.set_property(ctx, "activeStepCommandJsonTemplateCommand", JSValue::null());
            result.set_property(ctx, "activeStepCommandJsonTemplateKind", JSValue::null());
            result.set_property(ctx, "activeStepRetryable", JSValue::null());
            result.set_property(ctx, "activeStepMaxSuggestedRetries", JSValue::null());
            result.set_property(ctx, "activeStepRetryDelayHintMs", JSValue::null());
            result.set_property(ctx, "activeStepTimeoutHintMs", JSValue::null());
            result.set_property(ctx, "activeStepTimeoutAction", JSValue::null());
            result.set_property(ctx, "activeStepErrorCode", JSValue::null());
            result.set_property(ctx, "activeStepTimeoutErrorCode", JSValue::null());
            result.set_property(ctx, "activeStepRisk", JSValue::null());
            result.set_property(ctx, "activeStepPlaceholderCount", JSValue::null());
            result.set_property(ctx, "activeStepPlaceholders", JSValue::null());
            result.set_property(ctx, "activeStepCliArgs", JSValue::null());
        }
    }

    if next_action_ready_to_run == Some(false) {
        let fallback_templates = hook_fallback_templates(&suggested_sequence);
        let fallback_command_json_templates = fallback_templates
            .iter()
            .map(|template| hook_command_json_template_to_js(ctx, template))
            .collect::<Vec<_>>();
        let fallback_command_json_templates_array = ffi::JS_NewArray(ctx);
        let fallback_steps = ffi::JS_NewArray(ctx);
        let fallback_next_step_chain = ffi::JS_NewArray(ctx);
        let fallback_step_limit = 3usize;
        let fallback_step_count = fallback_command_json_templates.len().min(fallback_step_limit);
        let fallback_step_truncated = fallback_command_json_templates.len() > fallback_step_limit;
        let mut fallback_first_step: Option<ffi::JSValue> = None;
        let mut phase_order = Vec::<String>::new();
        let mut retryable_step_count = 0usize;
        let mut total_retry_budget = 0usize;

        for (index, entry) in fallback_command_json_templates.iter().enumerate() {
            ffi::JS_SetPropertyUint32(ctx, fallback_command_json_templates_array, index as u32, *entry);
            let entry_value = JSValue(*entry);
            let phase = entry_value
                .get_property(ctx, "phase")
                .to_string(ctx)
                .unwrap_or_default();
            if !phase.is_empty() && !phase_order.iter().any(|item| item == &phase) {
                phase_order.push(phase);
            }
            if entry_value.get_property(ctx, "retryable").to_bool().unwrap_or(false) {
                retryable_step_count += 1;
            }
            total_retry_budget += entry_value
                .get_property(ctx, "maxSuggestedRetries")
                .to_i64(ctx)
                .unwrap_or(0)
                .max(0) as usize;
            let step = JSValue(hook_fallback_step_from_command_json_template_to_js(ctx, index, *entry));
            if index == 0 {
                fallback_first_step = Some(step.dup(ctx).raw());
            }
            ffi::JS_SetPropertyUint32(ctx, fallback_steps, index as u32, step.dup(ctx).raw());
            if index < fallback_step_limit {
                ffi::JS_SetPropertyUint32(ctx, fallback_next_step_chain, index as u32, step.dup(ctx).raw());
            }
            step.free(ctx);
        }

        let phase_retry_policies = ffi::JS_NewArray(ctx);
        let phase_timeout_policies = ffi::JS_NewArray(ctx);
        let phase_error_codes = ffi::JS_NewArray(ctx);
        let escalation_recommendations = ffi::JS_NewArray(ctx);
        for (index, phase) in phase_order.iter().enumerate() {
            let (retryable, max_suggested_retries, retry_delay_hint_ms) = phase_retry_policy(phase);
            let (timeout_hint_ms, timeout_action) = phase_timeout_policy(phase);
            let error_code = phase_failure_code(phase);
            let timeout_error_code = phase_timeout_error_code(phase);

            let retry_policy = JSValue(ffi::JS_NewObject(ctx));
            retry_policy.set_property(ctx, "phase", JSValue::string(ctx, phase));
            retry_policy.set_property(ctx, "retryable", JSValue::bool(retryable));
            retry_policy.set_property(ctx, "maxSuggestedRetries", JSValue::int(max_suggested_retries as i32));
            retry_policy.set_property(
                ctx,
                "retryDelayHintMs",
                JSValue(js_u64_to_js_number_or_bigint(ctx, retry_delay_hint_ms)),
            );
            retry_policy.set_property(
                ctx,
                "timeoutHintMs",
                JSValue(js_u64_to_js_number_or_bigint(ctx, timeout_hint_ms)),
            );
            retry_policy.set_property(ctx, "timeoutAction", JSValue::string(ctx, timeout_action));
            retry_policy.set_property(ctx, "errorCode", JSValue::string(ctx, error_code));
            retry_policy.set_property(ctx, "timeoutErrorCode", JSValue::string(ctx, timeout_error_code));
            ffi::JS_SetPropertyUint32(ctx, phase_retry_policies, index as u32, retry_policy.raw());

            let timeout_policy = JSValue(ffi::JS_NewObject(ctx));
            timeout_policy.set_property(ctx, "phase", JSValue::string(ctx, phase));
            timeout_policy.set_property(
                ctx,
                "timeoutHintMs",
                JSValue(js_u64_to_js_number_or_bigint(ctx, timeout_hint_ms)),
            );
            timeout_policy.set_property(ctx, "timeoutAction", JSValue::string(ctx, timeout_action));
            timeout_policy.set_property(ctx, "errorCode", JSValue::string(ctx, error_code));
            timeout_policy.set_property(ctx, "timeoutErrorCode", JSValue::string(ctx, timeout_error_code));
            ffi::JS_SetPropertyUint32(ctx, phase_timeout_policies, index as u32, timeout_policy.raw());

            let phase_error = JSValue(ffi::JS_NewObject(ctx));
            phase_error.set_property(ctx, "phase", JSValue::string(ctx, phase));
            phase_error.set_property(ctx, "errorCode", JSValue::string(ctx, error_code));
            phase_error.set_property(ctx, "timeoutErrorCode", JSValue::string(ctx, timeout_error_code));
            ffi::JS_SetPropertyUint32(ctx, phase_error_codes, index as u32, phase_error.raw());
        }

        let mut escalation_specs = vec![(
            "preflight-refresh".to_string(),
            "always".to_string(),
            "preflight".to_string(),
            "refresh target context and diagnostics before changing hook policy or retrying injection".to_string(),
            None,
            vec!["controller --preflight-only --preflight-json --pid <pid>".to_string()],
            vec![
                "hook-fallback-preflight-failed".to_string(),
                "hook-fallback-inject-failed".to_string(),
                "hook-fallback-preflight-timeout".to_string(),
                "hook-fallback-inject-timeout".to_string(),
            ],
        )];

        if recommended_actions_vec
            .iter()
            .any(|action| action.action_key == "hook.query" && action.allowed)
        {
            escalation_specs.push((
                "query-only-path".to_string(),
                "query-commands-allowed".to_string(),
                "query".to_string(),
                "switch to query-only diagnostics path when inline hook actions are blocked".to_string(),
                None,
                vec![
                    "native.hookenv".to_string(),
                    "objc.classes <filter>".to_string(),
                    "native.images <filter>".to_string(),
                    "swift.types <filter>".to_string(),
                ],
                vec![
                    "hook-fallback-query-failed".to_string(),
                    "hook-fallback-query-timeout".to_string(),
                    "hook-fallback-hook-install-failed".to_string(),
                    "hook-fallback-hook-install-timeout".to_string(),
                ],
            ));
        }

        if next_action.map(|action| !action.allowed).unwrap_or(false) {
            escalation_specs.push((
                "policy-review".to_string(),
                "selected-next-action-blocked".to_string(),
                "diagnose".to_string(),
                "hook policy blocked the selected next action; inspect environment summary and adjust policy before retrying"
                    .to_string(),
                Some(
                    "review IOS_RUSTFRIDA_HOOK_POLICY / target hook backend and retry with preflight-only first"
                        .to_string(),
                ),
                vec!["native.hookenv".to_string()],
                vec![
                    "hook-fallback-diagnose-failed".to_string(),
                    "hook-fallback-diagnose-timeout".to_string(),
                ],
            ));
        }

        for (index, (key, condition, phase, reason, note, templates, on_error_codes)) in
            escalation_specs.iter().enumerate()
        {
            ffi::JS_SetPropertyUint32(
                ctx,
                escalation_recommendations,
                index as u32,
                hook_escalation_recommendation_to_js(
                    ctx,
                    key,
                    condition,
                    phase,
                    reason,
                    note.as_deref(),
                    templates,
                    on_error_codes,
                ),
            );
        }

        let escalation_recommendation_count = escalation_specs.len();
        let mut error_code_routing_candidates = BTreeMap::<String, Vec<usize>>::new();
        for (spec_index, (_, _, _, _, _, _, on_error_codes)) in escalation_specs.iter().enumerate() {
            for error_code in on_error_codes {
                let candidates = error_code_routing_candidates.entry(error_code.clone()).or_default();
                if !candidates.iter().any(|candidate| candidate == &spec_index) {
                    candidates.push(spec_index);
                }
            }
        }
        let error_code_routing = JSValue(ffi::JS_NewObject(ctx));
        let error_code_routing_entries = ffi::JS_NewArray(ctx);
        let error_code_routing_resolved = JSValue(ffi::JS_NewObject(ctx));
        for (entry_index, (error_code, candidate_indices)) in error_code_routing_candidates.iter().enumerate() {
            let recommended = candidate_indices.first().and_then(|index| escalation_specs.get(*index));
            let candidate_keys = candidate_indices
                .iter()
                .filter_map(|index| escalation_specs.get(*index).map(|spec| spec.0.clone()))
                .collect::<Vec<_>>();

            let recommended_escalation_key = recommended.map(|spec| spec.0.as_str());
            let recommended_phase = recommended.map(|spec| spec.2.as_str());
            let recommended_templates = recommended.map(|spec| spec.5.clone()).unwrap_or_default();
            let (recommended_command_json_templates, recommended_command_json_eligible_template_count) =
                hook_command_json_template_array_to_js(ctx, &recommended_templates);

            if let Some(key) = recommended_escalation_key {
                error_code_routing.set_property(ctx, error_code, JSValue::string(ctx, key));
            }

            let entry = JSValue(ffi::JS_NewObject(ctx));
            entry.set_property(ctx, "errorCode", JSValue::string(ctx, error_code));
            entry.set_property(ctx, "candidateCount", JSValue::int(candidate_keys.len() as i32));
            entry.set_property(
                ctx,
                "candidateEscalationKeys",
                JSValue(string_vec_to_js_array(ctx, &candidate_keys)),
            );
            match recommended_escalation_key {
                Some(value) => {
                    entry.set_property(ctx, "recommendedEscalationKey", JSValue::string(ctx, value));
                    entry.set_property(ctx, "effectiveEscalationKey", JSValue::string(ctx, value));
                }
                None => {
                    entry.set_property(ctx, "recommendedEscalationKey", JSValue::null());
                    entry.set_property(ctx, "effectiveEscalationKey", JSValue::null());
                }
            }
            entry.set_property(ctx, "matchConfidence", JSValue::string(ctx, "exact"));
            entry.set_property(ctx, "resolvedFrom", JSValue::string(ctx, "errorCodeRouting"));
            match recommended_phase {
                Some(value) => {
                    entry.set_property(ctx, "recommendedPhase", JSValue::string(ctx, value));
                    entry.set_property(ctx, "effectivePhase", JSValue::string(ctx, value));
                }
                None => {
                    entry.set_property(ctx, "recommendedPhase", JSValue::null());
                    entry.set_property(ctx, "effectivePhase", JSValue::null());
                }
            }
            entry.set_property(
                ctx,
                "recommendedTemplateCount",
                JSValue::int(recommended_templates.len() as i32),
            );
            set_string_array_property(ctx, entry.raw(), "recommendedTemplates", &recommended_templates);
            entry.set_property(
                ctx,
                "recommendedCommandJsonTemplateCount",
                JSValue::int(recommended_templates.len() as i32),
            );
            entry.set_property(
                ctx,
                "recommendedCommandJsonTemplates",
                JSValue(recommended_command_json_templates),
            );
            entry.set_property(
                ctx,
                "recommendedCommandJsonEligibleTemplateCount",
                JSValue::int(recommended_command_json_eligible_template_count as i32),
            );
            ffi::JS_SetPropertyUint32(ctx, error_code_routing_entries, entry_index as u32, entry.raw());

            let resolved = JSValue(ffi::JS_NewObject(ctx));
            match recommended_escalation_key {
                Some(value) => {
                    resolved.set_property(ctx, "escalationKey", JSValue::string(ctx, value));
                    resolved.set_property(ctx, "effectiveEscalationKey", JSValue::string(ctx, value));
                }
                None => {
                    resolved.set_property(ctx, "escalationKey", JSValue::null());
                    resolved.set_property(ctx, "effectiveEscalationKey", JSValue::null());
                }
            }
            match recommended_phase {
                Some(value) => {
                    resolved.set_property(ctx, "phase", JSValue::string(ctx, value));
                    resolved.set_property(ctx, "effectivePhase", JSValue::string(ctx, value));
                }
                None => {
                    resolved.set_property(ctx, "phase", JSValue::null());
                    resolved.set_property(ctx, "effectivePhase", JSValue::null());
                }
            }
            resolved.set_property(ctx, "matchConfidence", JSValue::string(ctx, "exact"));
            resolved.set_property(ctx, "resolvedFrom", JSValue::string(ctx, "errorCodeRouting"));
            resolved.set_property(ctx, "templateCount", JSValue::int(recommended_templates.len() as i32));
            set_string_array_property(ctx, resolved.raw(), "templates", &recommended_templates);
            let (resolved_command_json_templates, _) =
                hook_command_json_template_array_to_js(ctx, &recommended_templates);
            resolved.set_property(
                ctx,
                "commandJsonTemplateCount",
                JSValue::int(recommended_templates.len() as i32),
            );
            resolved.set_property(ctx, "commandJsonTemplates", JSValue(resolved_command_json_templates));
            error_code_routing_resolved.set_property(ctx, error_code, resolved);
        }
        let routing_decision = JSValue(ffi::JS_NewObject(ctx));
        routing_decision.set_property(ctx, "lookupKey", JSValue::string(ctx, "errorCode"));
        routing_decision.set_property(
            ctx,
            "policy",
            JSValue::string(ctx, "first-candidate-by-escalation-order"),
        );
        routing_decision.set_property(
            ctx,
            "entryCount",
            JSValue::int(error_code_routing_candidates.len() as i32),
        );
        routing_decision.set_property(ctx, "entries", JSValue(error_code_routing_entries).dup(ctx));

        match escalation_specs.first() {
            Some((key, _, phase, _, _, templates, _)) => {
                let (default_command_json_templates, default_command_json_eligible_template_count) =
                    hook_command_json_template_array_to_js(ctx, templates);
                routing_decision.set_property(ctx, "defaultRecommendedEscalationKey", JSValue::string(ctx, key));
                routing_decision.set_property(ctx, "defaultRecommendedPhase", JSValue::string(ctx, phase));
                routing_decision.set_property(ctx, "defaultEffectiveEscalationKey", JSValue::string(ctx, key));
                routing_decision.set_property(ctx, "defaultEffectivePhase", JSValue::string(ctx, phase));
                routing_decision.set_property(
                    ctx,
                    "defaultRecommendedTemplateCount",
                    JSValue::int(templates.len() as i32),
                );
                set_string_array_property(ctx, routing_decision.raw(), "defaultRecommendedTemplates", templates);
                routing_decision.set_property(
                    ctx,
                    "defaultRecommendedCommandJsonTemplateCount",
                    JSValue::int(templates.len() as i32),
                );
                routing_decision.set_property(
                    ctx,
                    "defaultRecommendedCommandJsonTemplates",
                    JSValue(default_command_json_templates).dup(ctx),
                );

                let default_value = JSValue(ffi::JS_NewObject(ctx));
                default_value.set_property(ctx, "recommendedEscalationKey", JSValue::string(ctx, key));
                default_value.set_property(ctx, "matchConfidence", JSValue::string(ctx, "default"));
                default_value.set_property(
                    ctx,
                    "resolvedFrom",
                    JSValue::string(ctx, "defaultRecommendedEscalationKey"),
                );
                default_value.set_property(ctx, "recommendedPhase", JSValue::string(ctx, phase));
                default_value.set_property(ctx, "effectivePhase", JSValue::string(ctx, phase));
                default_value.set_property(ctx, "effectiveEscalationKey", JSValue::string(ctx, key));
                default_value.set_property(ctx, "recommendedTemplateCount", JSValue::int(templates.len() as i32));
                set_string_array_property(ctx, default_value.raw(), "recommendedTemplates", templates);
                default_value.set_property(
                    ctx,
                    "recommendedCommandJsonTemplateCount",
                    JSValue::int(templates.len() as i32),
                );
                default_value.set_property(
                    ctx,
                    "recommendedCommandJsonTemplates",
                    JSValue(default_command_json_templates),
                );
                default_value.set_property(
                    ctx,
                    "recommendedCommandJsonEligibleTemplateCount",
                    JSValue::int(default_command_json_eligible_template_count as i32),
                );
                routing_decision.set_property(ctx, "default", default_value);

                let ready_value = JSValue(ffi::JS_NewObject(ctx));
                ready_value.set_property(ctx, "lookupRule", JSValue::string(ctx, "index[errorCode] || default"));
                ready_value.set_property(ctx, "resolveLookupKey", JSValue::string(ctx, "errorCode"));
                ready_value.set_property(ctx, "resolvePolicy", JSValue::string(ctx, "index-then-default"));
                ready_value.set_property(
                    ctx,
                    "resolveOutputShape",
                    JSValue::string(
                        ctx,
                        "{ matched, usedDefault, reason, effectivePhase, effectiveEscalationKey, effective }",
                    ),
                );
                ready_value.set_property(ctx, "index", error_code_routing_resolved.dup(ctx));
                let ready_default = JSValue(ffi::JS_NewObject(ctx));
                ready_default.set_property(ctx, "escalationKey", JSValue::string(ctx, key));
                ready_default.set_property(ctx, "effectiveEscalationKey", JSValue::string(ctx, key));
                ready_default.set_property(ctx, "phase", JSValue::string(ctx, phase));
                ready_default.set_property(ctx, "effectivePhase", JSValue::string(ctx, phase));
                ready_default.set_property(ctx, "templateCount", JSValue::int(templates.len() as i32));
                set_string_array_property(ctx, ready_default.raw(), "templates", templates);
                let (ready_default_command_json_templates, _) = hook_command_json_template_array_to_js(ctx, templates);
                ready_default.set_property(ctx, "commandJsonTemplateCount", JSValue::int(templates.len() as i32));
                ready_default.set_property(
                    ctx,
                    "commandJsonTemplates",
                    JSValue(ready_default_command_json_templates),
                );
                ready_default.set_property(ctx, "matchConfidence", JSValue::string(ctx, "default"));
                ready_default.set_property(
                    ctx,
                    "resolvedFrom",
                    JSValue::string(ctx, "defaultRecommendedEscalationKey"),
                );

                let resolve_index = JSValue(ffi::JS_NewObject(ctx));
                let mut example_known_error_code: Option<String> = None;
                for (error_code, candidate_indices) in error_code_routing_candidates.iter() {
                    let recommended = candidate_indices.first().and_then(|index| escalation_specs.get(*index));
                    let Some((effective_key, _, effective_phase, _, _, effective_templates, _)) = recommended else {
                        continue;
                    };
                    let effective = JSValue(ffi::JS_NewObject(ctx));
                    effective.set_property(ctx, "escalationKey", JSValue::string(ctx, effective_key));
                    effective.set_property(ctx, "effectiveEscalationKey", JSValue::string(ctx, effective_key));
                    effective.set_property(ctx, "phase", JSValue::string(ctx, effective_phase));
                    effective.set_property(ctx, "effectivePhase", JSValue::string(ctx, effective_phase));
                    effective.set_property(ctx, "templateCount", JSValue::int(effective_templates.len() as i32));
                    set_string_array_property(ctx, effective.raw(), "templates", effective_templates);
                    let (effective_command_json_templates, _) =
                        hook_command_json_template_array_to_js(ctx, effective_templates);
                    effective.set_property(
                        ctx,
                        "commandJsonTemplateCount",
                        JSValue::int(effective_templates.len() as i32),
                    );
                    effective.set_property(ctx, "commandJsonTemplates", JSValue(effective_command_json_templates));
                    effective.set_property(ctx, "matchConfidence", JSValue::string(ctx, "exact"));
                    effective.set_property(ctx, "resolvedFrom", JSValue::string(ctx, "errorCodeRouting"));

                    let resolved = JSValue(ffi::JS_NewObject(ctx));
                    resolved.set_property(ctx, "matched", JSValue::bool(true));
                    resolved.set_property(ctx, "usedDefault", JSValue::bool(false));
                    resolved.set_property(ctx, "reason", JSValue::string(ctx, "matched-error-code"));
                    resolved.set_property(ctx, "effectivePhase", JSValue::string(ctx, effective_phase));
                    resolved.set_property(ctx, "effectiveEscalationKey", JSValue::string(ctx, effective_key));
                    resolved.set_property(ctx, "effective", effective);
                    resolve_index.set_property(ctx, error_code, resolved);
                    if example_known_error_code.is_none() {
                        example_known_error_code = Some(error_code.clone());
                    }
                }

                let resolve_default = JSValue(ffi::JS_NewObject(ctx));
                resolve_default.set_property(ctx, "matched", JSValue::bool(false));
                resolve_default.set_property(ctx, "usedDefault", JSValue::bool(true));
                resolve_default.set_property(ctx, "reason", JSValue::string(ctx, "missing-error-code"));
                resolve_default.set_property(ctx, "effectivePhase", JSValue::string(ctx, phase));
                resolve_default.set_property(ctx, "effectiveEscalationKey", JSValue::string(ctx, key));
                resolve_default.set_property(ctx, "effective", ready_default.dup(ctx));

                let resolve_examples = JSValue(ffi::JS_NewObject(ctx));
                let known_error_codes = error_code_routing_candidates.keys().cloned().collect::<Vec<_>>();
                match example_known_error_code {
                    Some(ref error_code) => {
                        resolve_examples.set_property(ctx, "knownErrorCode", JSValue::string(ctx, error_code));
                        resolve_examples.set_property(ctx, "knownResult", resolve_index.get_property(ctx, error_code));
                    }
                    None => {
                        resolve_examples.set_property(ctx, "knownErrorCode", JSValue::null());
                        resolve_examples.set_property(ctx, "knownResult", JSValue::null());
                    }
                }
                let known_result = resolve_examples.get_property(ctx, "knownResult");
                let known_effective = known_result.get_property(ctx, "effective");
                resolve_examples.set_property(
                    ctx,
                    "knownEffectivePhase",
                    known_result.get_property(ctx, "effectivePhase"),
                );
                resolve_examples.set_property(
                    ctx,
                    "knownEffectiveEscalationKey",
                    known_result.get_property(ctx, "effectiveEscalationKey"),
                );
                resolve_examples.set_property(ctx, "missingErrorCode", JSValue::string(ctx, "hook-fallback-unknown"));
                resolve_examples.set_property(ctx, "missingResult", resolve_default.dup(ctx));
                resolve_examples.set_property(
                    ctx,
                    "missingEffectivePhase",
                    resolve_default.get_property(ctx, "effectivePhase"),
                );
                resolve_examples.set_property(
                    ctx,
                    "missingEffectiveEscalationKey",
                    resolve_default.get_property(ctx, "effectiveEscalationKey"),
                );

                let query_only_error_code = "hook-fallback-hook-install-failed";
                let query_only_result = resolve_index.get_property(ctx, query_only_error_code);
                let query_only_blocked_by = recommended_actions_vec
                    .iter()
                    .find(|action| action.action_key == "hook.install")
                    .map(|action| hook_action_blocked_by(action).to_string())
                    .unwrap_or_else(|| "none".to_string());
                let query_only_available = !query_only_result.is_null() && !query_only_result.is_undefined();
                let query_only_example = JSValue(ffi::JS_NewObject(ctx));
                query_only_example.set_property(ctx, "errorCode", JSValue::string(ctx, query_only_error_code));
                query_only_example.set_property(ctx, "blockedBy", JSValue::string(ctx, &query_only_blocked_by));
                query_only_example.set_property(
                    ctx,
                    "blockedBySource",
                    JSValue::string(
                        ctx,
                        if query_only_blocked_by == "none" {
                            "none"
                        } else {
                            &query_only_blocked_by
                        },
                    ),
                );
                query_only_example.set_property(ctx, "isBlocked", JSValue::bool(query_only_blocked_by != "none"));
                query_only_example.set_property(ctx, "available", JSValue::bool(query_only_available));
                if query_only_available {
                    query_only_example.set_property(ctx, "matched", query_only_result.get_property(ctx, "matched"));
                    query_only_example.set_property(
                        ctx,
                        "usedDefault",
                        query_only_result.get_property(ctx, "usedDefault"),
                    );
                    query_only_example.set_property(ctx, "reason", query_only_result.get_property(ctx, "reason"));
                    query_only_example.set_property(
                        ctx,
                        "effectivePhase",
                        query_only_result.get_property(ctx, "effectivePhase"),
                    );
                    query_only_example.set_property(
                        ctx,
                        "effectiveEscalationKey",
                        query_only_result.get_property(ctx, "effectiveEscalationKey"),
                    );
                    query_only_example.set_property(ctx, "result", query_only_result.dup(ctx));
                    query_only_example.set_property(
                        ctx,
                        "wouldUseQueryOnlyPath",
                        JSValue::bool(
                            query_only_result
                                .get_property(ctx, "effectiveEscalationKey")
                                .to_string(ctx)
                                .as_deref()
                                == Some("query-only-path"),
                        ),
                    );
                } else {
                    query_only_example.set_property(ctx, "matched", JSValue::bool(false));
                    query_only_example.set_property(ctx, "usedDefault", JSValue::bool(true));
                    query_only_example.set_property(ctx, "reason", JSValue::string(ctx, "missing-error-code"));
                    query_only_example.set_property(ctx, "effectivePhase", JSValue::null());
                    query_only_example.set_property(ctx, "effectiveEscalationKey", JSValue::null());
                    query_only_example.set_property(ctx, "result", JSValue::null());
                    query_only_example.set_property(ctx, "wouldUseQueryOnlyPath", JSValue::bool(false));
                }
                resolve_examples.set_property(ctx, "queryOnlyInstallFailure", query_only_example);

                ready_value.set_property(ctx, "resolveIndex", resolve_index.dup(ctx));
                ready_value.set_property(ctx, "resolveIndexEntries", resolve_index);
                ready_value.set_property(ctx, "resolveDefault", resolve_default.dup(ctx));
                ready_value.set_property(ctx, "resolveExamples", resolve_examples);
                ready_value.set_property(
                    ctx,
                    "resolveExampleKnownErrorCode",
                    resolve_examples.get_property(ctx, "knownErrorCode"),
                );
                ready_value.set_property(
                    ctx,
                    "resolveExampleKnownResult",
                    resolve_examples.get_property(ctx, "knownResult"),
                );
                ready_value.set_property(ctx, "resolveExampleKnownResultEffective", known_effective.dup(ctx));
                ready_value.set_property(
                    ctx,
                    "resolveExampleKnownResultEffectivePhase",
                    known_result.get_property(ctx, "effectivePhase"),
                );
                ready_value.set_property(
                    ctx,
                    "resolveExampleKnownResultEffectiveEscalationKey",
                    known_result.get_property(ctx, "effectiveEscalationKey"),
                );
                ready_value.set_property(
                    ctx,
                    "resolveExampleKnownMatched",
                    known_result.get_property(ctx, "matched"),
                );
                ready_value.set_property(
                    ctx,
                    "resolveExampleKnownUsedDefault",
                    known_result.get_property(ctx, "usedDefault"),
                );
                ready_value.set_property(
                    ctx,
                    "resolveExampleKnownReason",
                    known_result.get_property(ctx, "reason"),
                );
                ready_value.set_property(
                    ctx,
                    "resolveExampleKnownEffectivePhase",
                    resolve_examples.get_property(ctx, "knownEffectivePhase"),
                );
                ready_value.set_property(
                    ctx,
                    "resolveExampleKnownEffectiveEscalationKey",
                    resolve_examples.get_property(ctx, "knownEffectiveEscalationKey"),
                );
                ready_value.set_property(
                    ctx,
                    "resolveExampleMissingErrorCode",
                    resolve_examples.get_property(ctx, "missingErrorCode"),
                );
                let missing_result = resolve_examples.get_property(ctx, "missingResult");
                let missing_effective = missing_result.get_property(ctx, "effective");
                ready_value.set_property(ctx, "resolveExampleMissingResult", missing_result.dup(ctx));
                ready_value.set_property(ctx, "resolveExampleMissingResultEffective", missing_effective.dup(ctx));
                ready_value.set_property(
                    ctx,
                    "resolveExampleMissingResultEffectivePhase",
                    missing_result.get_property(ctx, "effectivePhase"),
                );
                ready_value.set_property(
                    ctx,
                    "resolveExampleMissingResultEffectiveEscalationKey",
                    missing_result.get_property(ctx, "effectiveEscalationKey"),
                );
                ready_value.set_property(
                    ctx,
                    "resolveExampleMissingMatched",
                    missing_result.get_property(ctx, "matched"),
                );
                ready_value.set_property(
                    ctx,
                    "resolveExampleMissingUsedDefault",
                    missing_result.get_property(ctx, "usedDefault"),
                );
                ready_value.set_property(
                    ctx,
                    "resolveExampleMissingReason",
                    missing_result.get_property(ctx, "reason"),
                );
                ready_value.set_property(
                    ctx,
                    "resolveExampleMissingEffectivePhase",
                    resolve_examples.get_property(ctx, "missingEffectivePhase"),
                );
                ready_value.set_property(
                    ctx,
                    "resolveExampleMissingEffectiveEscalationKey",
                    resolve_examples.get_property(ctx, "missingEffectiveEscalationKey"),
                );
                let query_only_example = resolve_examples.get_property(ctx, "queryOnlyInstallFailure");
                let query_only_result = query_only_example.get_property(ctx, "result");
                let query_only_result_effective = query_only_result.get_property(ctx, "effective");
                ready_value.set_property(
                    ctx,
                    "resolveExampleQueryOnlyInstallFailure",
                    query_only_example.dup(ctx),
                );
                ready_value.set_property(
                    ctx,
                    "resolveExampleQueryOnlyErrorCode",
                    query_only_example.get_property(ctx, "errorCode"),
                );
                ready_value.set_property(
                    ctx,
                    "resolveExampleQueryOnlyBlockedBy",
                    query_only_example.get_property(ctx, "blockedBy"),
                );
                ready_value.set_property(
                    ctx,
                    "resolveExampleQueryOnlyBlockedBySource",
                    query_only_example.get_property(ctx, "blockedBySource"),
                );
                ready_value.set_property(
                    ctx,
                    "resolveExampleQueryOnlyIsBlocked",
                    query_only_example.get_property(ctx, "isBlocked"),
                );
                ready_value.set_property(
                    ctx,
                    "resolveExampleQueryOnlyAvailable",
                    query_only_example.get_property(ctx, "available"),
                );
                ready_value.set_property(
                    ctx,
                    "resolveExampleQueryOnlyMatched",
                    query_only_example.get_property(ctx, "matched"),
                );
                ready_value.set_property(
                    ctx,
                    "resolveExampleQueryOnlyUsedDefault",
                    query_only_example.get_property(ctx, "usedDefault"),
                );
                ready_value.set_property(
                    ctx,
                    "resolveExampleQueryOnlyReason",
                    query_only_example.get_property(ctx, "reason"),
                );
                ready_value.set_property(
                    ctx,
                    "resolveExampleQueryOnlyEffectivePhase",
                    query_only_example.get_property(ctx, "effectivePhase"),
                );
                ready_value.set_property(
                    ctx,
                    "resolveExampleQueryOnlyEffectiveEscalationKey",
                    query_only_example.get_property(ctx, "effectiveEscalationKey"),
                );
                ready_value.set_property(
                    ctx,
                    "resolveExampleQueryOnlyWouldUsePath",
                    query_only_example.get_property(ctx, "wouldUseQueryOnlyPath"),
                );
                ready_value.set_property(ctx, "resolveExampleQueryOnlyResult", query_only_result.dup(ctx));
                ready_value.set_property(
                    ctx,
                    "resolveExampleQueryOnlyResultEffective",
                    query_only_result_effective.dup(ctx),
                );
                ready_value.set_property(
                    ctx,
                    "resolveExampleQueryOnlyResultMatched",
                    query_only_result.get_property(ctx, "matched"),
                );
                ready_value.set_property(
                    ctx,
                    "resolveExampleQueryOnlyResultUsedDefault",
                    query_only_result.get_property(ctx, "usedDefault"),
                );
                ready_value.set_property(
                    ctx,
                    "resolveExampleQueryOnlyResultReason",
                    query_only_result.get_property(ctx, "reason"),
                );
                ready_value.set_property(
                    ctx,
                    "resolveExampleQueryOnlyResultEffectivePhase",
                    query_only_result.get_property(ctx, "effectivePhase"),
                );
                ready_value.set_property(
                    ctx,
                    "resolveExampleQueryOnlyResultEffectiveEscalationKey",
                    query_only_result.get_property(ctx, "effectiveEscalationKey"),
                );
                ready_value.set_property(
                    ctx,
                    "resolveErrorCodeCount",
                    JSValue::int(known_error_codes.len() as i32),
                );
                ready_value.set_property(ctx, "resolveIndexCount", JSValue::int(known_error_codes.len() as i32));
                ready_value.set_property(ctx, "resolveKnownCount", JSValue::int(known_error_codes.len() as i32));
                ready_value.set_property(ctx, "resolveKnownTotal", JSValue::int(known_error_codes.len() as i32));
                ready_value.set_property(ctx, "resolveKnownAmount", JSValue::int(known_error_codes.len() as i32));
                ready_value.set_property(ctx, "resolveKnownVolume", JSValue::int(known_error_codes.len() as i32));
                ready_value.set_property(
                    ctx,
                    "resolveKnownMagnitude",
                    JSValue::int(known_error_codes.len() as i32),
                );
                ready_value.set_property(ctx, "resolveKnownSize", JSValue::int(known_error_codes.len() as i32));
                ready_value.set_property(ctx, "resolveKnownLength", JSValue::int(known_error_codes.len() as i32));
                ready_value.set_property(
                    ctx,
                    "resolveKnownErrorCodes",
                    JSValue(string_vec_to_js_array(ctx, &known_error_codes)),
                );
                ready_value.set_property(
                    ctx,
                    "resolveKnownEntries",
                    JSValue(string_vec_to_js_array(ctx, &known_error_codes)),
                );
                ready_value.set_property(
                    ctx,
                    "resolveKnownList",
                    JSValue(string_vec_to_js_array(ctx, &known_error_codes)),
                );
                ready_value.set_property(
                    ctx,
                    "resolveKnownEntriesCount",
                    JSValue::int(known_error_codes.len() as i32),
                );
                ready_value.set_property(
                    ctx,
                    "resolveKnownErrorCodesCount",
                    JSValue::int(known_error_codes.len() as i32),
                );
                match known_error_codes.first() {
                    Some(value) => {
                        ready_value.set_property(ctx, "resolveKnownErrorCodeFirst", JSValue::string(ctx, value));
                        ready_value.set_property(ctx, "resolveKnownErrorCodesFirst", JSValue::string(ctx, value));
                        ready_value.set_property(ctx, "resolveKnownEntriesFirst", JSValue::string(ctx, value));
                        ready_value.set_property(ctx, "resolveKnownFirst", JSValue::string(ctx, value));
                        ready_value.set_property(ctx, "resolveIndexFirst", JSValue::string(ctx, value));
                    }
                    None => {
                        ready_value.set_property(ctx, "resolveKnownErrorCodeFirst", JSValue::null());
                        ready_value.set_property(ctx, "resolveKnownErrorCodesFirst", JSValue::null());
                        ready_value.set_property(ctx, "resolveKnownEntriesFirst", JSValue::null());
                        ready_value.set_property(ctx, "resolveKnownFirst", JSValue::null());
                        ready_value.set_property(ctx, "resolveIndexFirst", JSValue::null());
                    }
                }
                match known_error_codes.last() {
                    Some(value) => {
                        ready_value.set_property(ctx, "resolveKnownErrorCodeLast", JSValue::string(ctx, value));
                        ready_value.set_property(ctx, "resolveKnownErrorCodesLast", JSValue::string(ctx, value));
                        ready_value.set_property(ctx, "resolveKnownEntriesLast", JSValue::string(ctx, value));
                        ready_value.set_property(ctx, "resolveKnownLast", JSValue::string(ctx, value));
                        ready_value.set_property(ctx, "resolveIndexLast", JSValue::string(ctx, value));
                    }
                    None => {
                        ready_value.set_property(ctx, "resolveKnownErrorCodeLast", JSValue::null());
                        ready_value.set_property(ctx, "resolveKnownErrorCodesLast", JSValue::null());
                        ready_value.set_property(ctx, "resolveKnownEntriesLast", JSValue::null());
                        ready_value.set_property(ctx, "resolveKnownLast", JSValue::null());
                        ready_value.set_property(ctx, "resolveIndexLast", JSValue::null());
                    }
                }
                ready_value.set_property(
                    ctx,
                    "resolveMissingErrorCodeHint",
                    JSValue::string(ctx, "hook-fallback-unknown"),
                );
                ready_value.set_property(ctx, "resolveMissingHint", JSValue::string(ctx, "hook-fallback-unknown"));
                ready_value.set_property(
                    ctx,
                    "resolveDefaultMatched",
                    resolve_default.get_property(ctx, "matched"),
                );
                ready_value.set_property(
                    ctx,
                    "resolveDefaultUsedDefault",
                    resolve_default.get_property(ctx, "usedDefault"),
                );
                ready_value.set_property(ctx, "resolveDefaultReason", resolve_default.get_property(ctx, "reason"));
                ready_value.set_property(
                    ctx,
                    "resolveDefaultEffective",
                    resolve_default.get_property(ctx, "effective"),
                );
                ready_value.set_property(
                    ctx,
                    "resolveDefaultEffectivePhase",
                    resolve_default.get_property(ctx, "effectivePhase"),
                );
                ready_value.set_property(
                    ctx,
                    "resolveDefaultEffectiveEscalationKey",
                    resolve_default.get_property(ctx, "effectiveEscalationKey"),
                );
                ready_value.set_property(
                    ctx,
                    "resolveKnownErrorCode",
                    resolve_examples.get_property(ctx, "knownErrorCode"),
                );
                ready_value.set_property(
                    ctx,
                    "resolveKnownResult",
                    resolve_examples.get_property(ctx, "knownResult"),
                );
                ready_value.set_property(ctx, "resolveKnownResultEffective", known_effective.dup(ctx));
                ready_value.set_property(ctx, "resolveKnownEffective", known_effective);
                ready_value.set_property(ctx, "resolveKnownMatched", known_result.get_property(ctx, "matched"));
                ready_value.set_property(
                    ctx,
                    "resolveKnownUsedDefault",
                    known_result.get_property(ctx, "usedDefault"),
                );
                ready_value.set_property(ctx, "resolveKnownReason", known_result.get_property(ctx, "reason"));
                ready_value.set_property(
                    ctx,
                    "resolveKnownEffectivePhase",
                    resolve_examples.get_property(ctx, "knownEffectivePhase"),
                );
                ready_value.set_property(
                    ctx,
                    "resolveKnownEffectiveEscalationKey",
                    resolve_examples.get_property(ctx, "knownEffectiveEscalationKey"),
                );
                ready_value.set_property(
                    ctx,
                    "resolveMissingErrorCode",
                    resolve_examples.get_property(ctx, "missingErrorCode"),
                );
                ready_value.set_property(ctx, "resolveMissingResult", missing_result.dup(ctx));
                ready_value.set_property(ctx, "resolveMissingResultEffective", missing_effective.dup(ctx));
                ready_value.set_property(
                    ctx,
                    "resolveMissingMatched",
                    missing_result.get_property(ctx, "matched"),
                );
                ready_value.set_property(
                    ctx,
                    "resolveMissingUsedDefault",
                    missing_result.get_property(ctx, "usedDefault"),
                );
                ready_value.set_property(ctx, "resolveMissingReason", missing_result.get_property(ctx, "reason"));
                ready_value.set_property(
                    ctx,
                    "resolveMissingEffectivePhase",
                    resolve_examples.get_property(ctx, "missingEffectivePhase"),
                );
                ready_value.set_property(
                    ctx,
                    "resolveMissingEffectiveEscalationKey",
                    resolve_examples.get_property(ctx, "missingEffectiveEscalationKey"),
                );
                ready_value.set_property(
                    ctx,
                    "entryCount",
                    JSValue::int(error_code_routing_candidates.len() as i32),
                );
                ready_value.set_property(
                    ctx,
                    "defaultEscalationKey",
                    ready_default.get_property(ctx, "escalationKey"),
                );
                ready_value.set_property(
                    ctx,
                    "defaultEffectiveEscalationKey",
                    ready_default.get_property(ctx, "effectiveEscalationKey"),
                );
                ready_value.set_property(ctx, "defaultPhase", ready_default.get_property(ctx, "phase"));
                ready_value.set_property(
                    ctx,
                    "defaultEffectivePhase",
                    ready_default.get_property(ctx, "effectivePhase"),
                );
                ready_value.set_property(
                    ctx,
                    "defaultTemplateCount",
                    ready_default.get_property(ctx, "templateCount"),
                );
                ready_value.set_property(ctx, "defaultTemplates", ready_default.get_property(ctx, "templates"));
                ready_value.set_property(
                    ctx,
                    "defaultTemplate",
                    ready_default.get_property(ctx, "templates").get_property(ctx, "0"),
                );
                ready_value.set_property(
                    ctx,
                    "defaultCommandJsonTemplateCount",
                    ready_default.get_property(ctx, "commandJsonTemplateCount"),
                );
                ready_value.set_property(
                    ctx,
                    "defaultCommandJsonTemplates",
                    ready_default.get_property(ctx, "commandJsonTemplates"),
                );
                let ready_default_command_json_template = ready_default
                    .get_property(ctx, "commandJsonTemplates")
                    .get_property(ctx, "0");
                ready_value.set_property(
                    ctx,
                    "defaultCommandJsonTemplate",
                    ready_default_command_json_template.dup(ctx),
                );
                ready_value.set_property(
                    ctx,
                    "defaultCommandJsonTemplateCommand",
                    ready_default_command_json_template.get_property(ctx, "command"),
                );
                ready_value.set_property(
                    ctx,
                    "defaultCommandJsonTemplateRisk",
                    ready_default_command_json_template.get_property(ctx, "risk"),
                );
                ready_value.set_property(
                    ctx,
                    "defaultCommandJsonTemplatePlaceholderCount",
                    ready_default_command_json_template.get_property(ctx, "placeholderCount"),
                );
                ready_value.set_property(
                    ctx,
                    "defaultCommandJsonTemplatePlaceholders",
                    ready_default_command_json_template.get_property(ctx, "placeholders"),
                );
                ready_value.set_property(
                    ctx,
                    "defaultCommandJsonTemplateCliArgs",
                    ready_default_command_json_template.get_property(ctx, "cliArgs"),
                );
                ready_value.set_property(
                    ctx,
                    "defaultCommandJsonTemplateKind",
                    ready_default_command_json_template.get_property(ctx, "kind"),
                );
                ready_value.set_property(
                    ctx,
                    "defaultCommandJsonTemplatePhase",
                    ready_default_command_json_template.get_property(ctx, "phase"),
                );
                ready_value.set_property(
                    ctx,
                    "defaultCommandJsonTemplateErrorCode",
                    ready_default_command_json_template.get_property(ctx, "errorCode"),
                );
                ready_value.set_property(
                    ctx,
                    "defaultCommandJsonTemplateTimeoutErrorCode",
                    ready_default_command_json_template.get_property(ctx, "timeoutErrorCode"),
                );
                ready_value.set_property(
                    ctx,
                    "defaultCommandJsonTemplateRetryable",
                    ready_default_command_json_template.get_property(ctx, "retryable"),
                );
                ready_value.set_property(
                    ctx,
                    "defaultCommandJsonTemplateMaxSuggestedRetries",
                    ready_default_command_json_template.get_property(ctx, "maxSuggestedRetries"),
                );
                ready_value.set_property(
                    ctx,
                    "defaultCommandJsonTemplateRetryDelayHintMs",
                    ready_default_command_json_template.get_property(ctx, "retryDelayHintMs"),
                );
                ready_value.set_property(
                    ctx,
                    "defaultCommandJsonTemplateTimeoutHintMs",
                    ready_default_command_json_template.get_property(ctx, "timeoutHintMs"),
                );
                ready_value.set_property(
                    ctx,
                    "defaultCommandJsonTemplateTimeoutAction",
                    ready_default_command_json_template.get_property(ctx, "timeoutAction"),
                );
                ready_value.set_property(
                    ctx,
                    "defaultCommandJsonTemplateCommandJsonEligible",
                    ready_default_command_json_template.get_property(ctx, "commandJsonEligible"),
                );
                ready_value.set_property(
                    ctx,
                    "defaultMatchConfidence",
                    ready_default.get_property(ctx, "matchConfidence"),
                );
                ready_value.set_property(
                    ctx,
                    "defaultResolvedFrom",
                    ready_default.get_property(ctx, "resolvedFrom"),
                );

                let resolve_value = JSValue(ffi::JS_NewObject(ctx));
                resolve_value.set_property(ctx, "lookupKey", JSValue::string(ctx, "errorCode"));
                resolve_value.set_property(ctx, "policy", JSValue::string(ctx, "index-then-default"));
                resolve_value.set_property(
                    ctx,
                    "outputShape",
                    JSValue::string(
                        ctx,
                        "{ matched, usedDefault, reason, effectivePhase, effectiveEscalationKey, effective }",
                    ),
                );
                resolve_value.set_property(ctx, "index", ready_value.get_property(ctx, "resolveIndex"));
                resolve_value.set_property(ctx, "default", ready_value.get_property(ctx, "resolveDefault"));
                resolve_value.set_property(ctx, "examples", ready_value.get_property(ctx, "resolveExamples"));
                resolve_value.set_property(
                    ctx,
                    "queryOnlyErrorCode",
                    query_only_example.get_property(ctx, "errorCode"),
                );
                resolve_value.set_property(
                    ctx,
                    "queryOnlyBlockedBy",
                    query_only_example.get_property(ctx, "blockedBy"),
                );
                resolve_value.set_property(
                    ctx,
                    "queryOnlyBlockedBySource",
                    query_only_example.get_property(ctx, "blockedBySource"),
                );
                resolve_value.set_property(
                    ctx,
                    "queryOnlyIsBlocked",
                    query_only_example.get_property(ctx, "isBlocked"),
                );
                resolve_value.set_property(
                    ctx,
                    "queryOnlyAvailable",
                    query_only_example.get_property(ctx, "available"),
                );
                resolve_value.set_property(ctx, "queryOnlyMatched", query_only_example.get_property(ctx, "matched"));
                resolve_value.set_property(
                    ctx,
                    "queryOnlyUsedDefault",
                    query_only_example.get_property(ctx, "usedDefault"),
                );
                resolve_value.set_property(ctx, "queryOnlyReason", query_only_example.get_property(ctx, "reason"));
                resolve_value.set_property(
                    ctx,
                    "queryOnlyEffectivePhase",
                    query_only_example.get_property(ctx, "effectivePhase"),
                );
                resolve_value.set_property(
                    ctx,
                    "queryOnlyEffectiveEscalationKey",
                    query_only_example.get_property(ctx, "effectiveEscalationKey"),
                );
                resolve_value.set_property(
                    ctx,
                    "queryOnlyWouldUsePath",
                    query_only_example.get_property(ctx, "wouldUseQueryOnlyPath"),
                );
                resolve_value.set_property(ctx, "queryOnlyResult", query_only_result.dup(ctx));
                resolve_value.set_property(ctx, "queryOnlyResultEffective", query_only_result_effective.dup(ctx));
                resolve_value.set_property(
                    ctx,
                    "queryOnlyResultMatched",
                    query_only_result.get_property(ctx, "matched"),
                );
                resolve_value.set_property(
                    ctx,
                    "queryOnlyResultUsedDefault",
                    query_only_result.get_property(ctx, "usedDefault"),
                );
                resolve_value.set_property(
                    ctx,
                    "queryOnlyResultReason",
                    query_only_result.get_property(ctx, "reason"),
                );
                resolve_value.set_property(
                    ctx,
                    "queryOnlyResultEffectivePhase",
                    query_only_result.get_property(ctx, "effectivePhase"),
                );
                resolve_value.set_property(
                    ctx,
                    "queryOnlyResultEffectiveEscalationKey",
                    query_only_result.get_property(ctx, "effectiveEscalationKey"),
                );
                ready_value.set_property(ctx, "resolve", resolve_value.dup(ctx));

                let mut phase_error_codes = BTreeMap::<String, Vec<String>>::new();
                let mut phase_escalation_keys = BTreeMap::<String, Vec<String>>::new();
                let mut phase_templates = BTreeMap::<String, Vec<String>>::new();
                for (error_code, candidate_indices) in error_code_routing_candidates.iter() {
                    let recommended = candidate_indices.first().and_then(|index| escalation_specs.get(*index));
                    let Some((effective_key, _, effective_phase, _, _, effective_templates, _)) = recommended else {
                        continue;
                    };
                    phase_error_codes
                        .entry(effective_phase.clone())
                        .or_default()
                        .push(error_code.clone());
                    let keys = phase_escalation_keys.entry(effective_phase.clone()).or_default();
                    if !keys.iter().any(|item| item == effective_key) {
                        keys.push(effective_key.clone());
                    }
                    let templates = phase_templates.entry(effective_phase.clone()).or_default();
                    for template in effective_templates.iter() {
                        if !templates.iter().any(|item| item == template) {
                            templates.push(template.clone());
                        }
                    }
                }

                let phases = JSValue(ffi::JS_NewArray(ctx));
                let phase_index = JSValue(ffi::JS_NewObject(ctx));
                let mut known_phases = Vec::<String>::new();
                let mut example_known_phase: Option<String> = None;
                for (phase_name, error_codes) in phase_error_codes.iter() {
                    let escalation_keys = phase_escalation_keys.get(phase_name).cloned().unwrap_or_default();
                    let templates = phase_templates.get(phase_name).cloned().unwrap_or_default();
                    let (command_json_templates, _) = hook_command_json_template_array_to_js(ctx, &templates);
                    let phase_entry = JSValue(ffi::JS_NewObject(ctx));
                    phase_entry.set_property(ctx, "phase", JSValue::string(ctx, phase_name));
                    phase_entry.set_property(ctx, "errorCodeCount", JSValue::int(error_codes.len() as i32));
                    phase_entry.set_property(ctx, "errorCodes", JSValue(string_vec_to_js_array(ctx, error_codes)));
                    phase_entry.set_property(ctx, "escalationKeyCount", JSValue::int(escalation_keys.len() as i32));
                    phase_entry.set_property(
                        ctx,
                        "escalationKeys",
                        JSValue(string_vec_to_js_array(ctx, &escalation_keys)),
                    );
                    phase_entry.set_property(ctx, "templateCount", JSValue::int(templates.len() as i32));
                    phase_entry.set_property(ctx, "templates", JSValue(string_vec_to_js_array(ctx, &templates)));
                    phase_entry.set_property(ctx, "commandJsonTemplateCount", JSValue::int(templates.len() as i32));
                    phase_entry.set_property(ctx, "commandJsonTemplates", JSValue(command_json_templates));
                    ffi::JS_SetPropertyUint32(ctx, phases.raw(), known_phases.len() as u32, phase_entry.dup(ctx).raw());
                    phase_index.set_property(ctx, phase_name, phase_entry);
                    known_phases.push(phase_name.clone());
                    if example_known_phase.is_none() {
                        example_known_phase = Some(phase_name.clone());
                    }
                }

                let phase_preflight = phase_index.get_property(ctx, "preflight");
                let phase_diagnose = phase_index.get_property(ctx, "diagnose");
                let phase_cleanup = phase_index.get_property(ctx, "cleanup");
                let phase_query = phase_index.get_property(ctx, "query");

                let phase_resolve_index = JSValue(ffi::JS_NewObject(ctx));
                for phase_name in known_phases.iter() {
                    let phase_entry = phase_index.get_property(ctx, phase_name);
                    let phase_effective_key = phase_entry.get_property(ctx, "escalationKeys").get_property(ctx, "0");
                    let phase_resolved = JSValue(ffi::JS_NewObject(ctx));
                    phase_resolved.set_property(ctx, "matched", JSValue::bool(true));
                    phase_resolved.set_property(ctx, "usedDefault", JSValue::bool(false));
                    phase_resolved.set_property(ctx, "reason", JSValue::string(ctx, "matched-phase"));
                    phase_resolved.set_property(ctx, "effectivePhase", phase_entry.get_property(ctx, "phase"));
                    phase_resolved.set_property(ctx, "effectiveEscalationKey", phase_effective_key);
                    phase_resolved.set_property(ctx, "effective", phase_entry);
                    phase_resolve_index.set_property(ctx, phase_name, phase_resolved);
                }

                let default_phase = ready_default.get_property(ctx, "effectivePhase");
                let default_phase_name = default_phase.to_string(ctx).filter(|value| !value.is_empty());
                let phase_resolve_default_effective = match default_phase_name.as_deref() {
                    Some(value) => phase_index.get_property(ctx, value),
                    None => JSValue::null(),
                };
                let phase_resolve_default_effective_phase =
                    if phase_resolve_default_effective.is_null() || phase_resolve_default_effective.is_undefined() {
                        ready_default.get_property(ctx, "effectivePhase")
                    } else {
                        phase_resolve_default_effective.get_property(ctx, "phase")
                    };
                let phase_resolve_default_effective_key =
                    if phase_resolve_default_effective.is_null() || phase_resolve_default_effective.is_undefined() {
                        ready_default.get_property(ctx, "effectiveEscalationKey")
                    } else {
                        let key = phase_resolve_default_effective
                            .get_property(ctx, "escalationKeys")
                            .get_property(ctx, "0");
                        if key.is_null() || key.is_undefined() {
                            ready_default.get_property(ctx, "effectiveEscalationKey")
                        } else {
                            key
                        }
                    };
                let phase_resolve_default = JSValue(ffi::JS_NewObject(ctx));
                phase_resolve_default.set_property(ctx, "matched", JSValue::bool(false));
                phase_resolve_default.set_property(ctx, "usedDefault", JSValue::bool(true));
                phase_resolve_default.set_property(ctx, "reason", JSValue::string(ctx, "missing-phase"));
                phase_resolve_default.set_property(ctx, "effectivePhase", phase_resolve_default_effective_phase);
                phase_resolve_default.set_property(ctx, "effectiveEscalationKey", phase_resolve_default_effective_key);
                phase_resolve_default.set_property(ctx, "effective", phase_resolve_default_effective.dup(ctx));

                let phase_resolve_examples = JSValue(ffi::JS_NewObject(ctx));
                match example_known_phase.as_ref() {
                    Some(phase_name) => {
                        phase_resolve_examples.set_property(ctx, "knownPhase", JSValue::string(ctx, phase_name));
                        phase_resolve_examples.set_property(
                            ctx,
                            "knownResult",
                            phase_resolve_index.get_property(ctx, phase_name),
                        );
                    }
                    None => {
                        phase_resolve_examples.set_property(ctx, "knownPhase", JSValue::null());
                        phase_resolve_examples.set_property(ctx, "knownResult", JSValue::null());
                    }
                }
                let phase_known_result = phase_resolve_examples.get_property(ctx, "knownResult");
                let phase_known_effective = phase_known_result.get_property(ctx, "effective");
                let phase_known_effective_key =
                    if phase_known_effective.is_null() || phase_known_effective.is_undefined() {
                        phase_known_result.get_property(ctx, "effectiveEscalationKey")
                    } else {
                        let key = phase_known_effective
                            .get_property(ctx, "escalationKeys")
                            .get_property(ctx, "0");
                        if key.is_null() || key.is_undefined() {
                            phase_known_result.get_property(ctx, "effectiveEscalationKey")
                        } else {
                            key
                        }
                    };
                phase_resolve_examples.set_property(
                    ctx,
                    "knownEffectivePhase",
                    phase_known_effective.get_property(ctx, "phase"),
                );
                phase_resolve_examples.set_property(ctx, "knownEffectiveEscalationKey", phase_known_effective_key);
                phase_resolve_examples.set_property(ctx, "missingPhase", JSValue::string(ctx, "unknown"));
                phase_resolve_examples.set_property(ctx, "missingResult", phase_resolve_default.dup(ctx));
                phase_resolve_examples.set_property(
                    ctx,
                    "missingEffectivePhase",
                    phase_resolve_default
                        .get_property(ctx, "effective")
                        .get_property(ctx, "phase"),
                );
                let phase_missing_effective = phase_resolve_default.get_property(ctx, "effective");
                let phase_missing_effective_key =
                    if phase_missing_effective.is_null() || phase_missing_effective.is_undefined() {
                        phase_resolve_default.get_property(ctx, "effectiveEscalationKey")
                    } else {
                        let key = phase_missing_effective
                            .get_property(ctx, "escalationKeys")
                            .get_property(ctx, "0");
                        if key.is_null() || key.is_undefined() {
                            phase_resolve_default.get_property(ctx, "effectiveEscalationKey")
                        } else {
                            key
                        }
                    };
                phase_resolve_examples.set_property(ctx, "missingEffectiveEscalationKey", phase_missing_effective_key);

                let query_only_phase =
                    if query_only_result_effective.is_null() || query_only_result_effective.is_undefined() {
                        JSValue::null()
                    } else {
                        query_only_result_effective.get_property(ctx, "phase")
                    };
                let query_only_phase_name = query_only_phase.to_string(ctx).filter(|value| !value.is_empty());
                let query_only_phase_result = match query_only_phase_name.as_deref() {
                    Some(value) => phase_resolve_index.get_property(ctx, value),
                    None => JSValue::null(),
                };
                let query_only_phase_available =
                    !(query_only_phase_result.is_null() || query_only_phase_result.is_undefined());
                let query_only_phase_effective = if query_only_phase_available {
                    query_only_phase_result.get_property(ctx, "effective")
                } else {
                    JSValue::null()
                };
                let query_only_phase_effective_key =
                    if query_only_phase_effective.is_null() || query_only_phase_effective.is_undefined() {
                        JSValue::null()
                    } else {
                        query_only_phase_effective
                            .get_property(ctx, "escalationKeys")
                            .get_property(ctx, "0")
                    };
                let query_only_phase_example = JSValue(ffi::JS_NewObject(ctx));
                query_only_phase_example.set_property(
                    ctx,
                    "sourceErrorCode",
                    query_only_example.get_property(ctx, "errorCode"),
                );
                query_only_phase_example.set_property(
                    ctx,
                    "blockedBy",
                    query_only_example.get_property(ctx, "blockedBy"),
                );
                query_only_phase_example.set_property(
                    ctx,
                    "blockedBySource",
                    query_only_example.get_property(ctx, "blockedBySource"),
                );
                query_only_phase_example.set_property(
                    ctx,
                    "isBlocked",
                    query_only_example.get_property(ctx, "isBlocked"),
                );
                query_only_phase_example.set_property(ctx, "phase", query_only_phase);
                query_only_phase_example.set_property(ctx, "available", JSValue::bool(query_only_phase_available));
                if query_only_phase_available {
                    query_only_phase_example.set_property(
                        ctx,
                        "matched",
                        query_only_phase_result.get_property(ctx, "matched"),
                    );
                    query_only_phase_example.set_property(
                        ctx,
                        "usedDefault",
                        query_only_phase_result.get_property(ctx, "usedDefault"),
                    );
                    query_only_phase_example.set_property(
                        ctx,
                        "reason",
                        query_only_phase_result.get_property(ctx, "reason"),
                    );
                    query_only_phase_example.set_property(
                        ctx,
                        "effectivePhase",
                        query_only_phase_effective.get_property(ctx, "phase"),
                    );
                    query_only_phase_example.set_property(
                        ctx,
                        "effectiveEscalationKey",
                        query_only_phase_effective_key,
                    );
                    query_only_phase_example.set_property(ctx, "result", query_only_phase_result.dup(ctx));
                    query_only_phase_example.set_property(
                        ctx,
                        "wouldUseQueryPhase",
                        JSValue::bool(
                            query_only_phase_effective
                                .get_property(ctx, "phase")
                                .to_string(ctx)
                                .as_deref()
                                == Some("query"),
                        ),
                    );
                } else {
                    query_only_phase_example.set_property(ctx, "matched", JSValue::bool(false));
                    query_only_phase_example.set_property(ctx, "usedDefault", JSValue::bool(true));
                    query_only_phase_example.set_property(ctx, "reason", JSValue::string(ctx, "missing-phase"));
                    query_only_phase_example.set_property(ctx, "effectivePhase", JSValue::null());
                    query_only_phase_example.set_property(ctx, "effectiveEscalationKey", JSValue::null());
                    query_only_phase_example.set_property(ctx, "result", JSValue::null());
                    query_only_phase_example.set_property(ctx, "wouldUseQueryPhase", JSValue::bool(false));
                }
                phase_resolve_examples.set_property(ctx, "queryOnlyInstallFailure", query_only_phase_example.dup(ctx));

                let phase_resolve_value = JSValue(ffi::JS_NewObject(ctx));
                phase_resolve_value.set_property(ctx, "lookupKey", JSValue::string(ctx, "phase"));
                phase_resolve_value.set_property(ctx, "policy", JSValue::string(ctx, "index-then-defaultPhase"));
                phase_resolve_value.set_property(
                    ctx,
                    "outputShape",
                    JSValue::string(
                        ctx,
                        "{ matched, usedDefault, reason, effectivePhase, effectiveEscalationKey, effective }",
                    ),
                );
                phase_resolve_value.set_property(ctx, "phaseCount", JSValue::int(known_phases.len() as i32));
                phase_resolve_value.set_property(
                    ctx,
                    "knownPhases",
                    JSValue(string_vec_to_js_array(ctx, &known_phases)),
                );
                phase_resolve_value.set_property(
                    ctx,
                    "knownEntries",
                    JSValue(string_vec_to_js_array(ctx, &known_phases)),
                );
                phase_resolve_value.set_property(ctx, "knownList", JSValue(string_vec_to_js_array(ctx, &known_phases)));
                phase_resolve_value.set_property(ctx, "knownEntriesCount", JSValue::int(known_phases.len() as i32));
                phase_resolve_value.set_property(ctx, "knownPhasesCount", JSValue::int(known_phases.len() as i32));
                match known_phases.first() {
                    Some(value) => {
                        phase_resolve_value.set_property(ctx, "knownPhaseFirst", JSValue::string(ctx, value));
                        phase_resolve_value.set_property(ctx, "knownPhasesFirst", JSValue::string(ctx, value));
                        phase_resolve_value.set_property(ctx, "knownEntriesFirst", JSValue::string(ctx, value));
                        phase_resolve_value.set_property(ctx, "knownFirst", JSValue::string(ctx, value));
                    }
                    None => {
                        phase_resolve_value.set_property(ctx, "knownPhaseFirst", JSValue::null());
                        phase_resolve_value.set_property(ctx, "knownPhasesFirst", JSValue::null());
                        phase_resolve_value.set_property(ctx, "knownEntriesFirst", JSValue::null());
                        phase_resolve_value.set_property(ctx, "knownFirst", JSValue::null());
                    }
                }
                match known_phases.last() {
                    Some(value) => {
                        phase_resolve_value.set_property(ctx, "knownPhaseLast", JSValue::string(ctx, value));
                        phase_resolve_value.set_property(ctx, "knownPhasesLast", JSValue::string(ctx, value));
                        phase_resolve_value.set_property(ctx, "knownEntriesLast", JSValue::string(ctx, value));
                        phase_resolve_value.set_property(ctx, "knownLast", JSValue::string(ctx, value));
                    }
                    None => {
                        phase_resolve_value.set_property(ctx, "knownPhaseLast", JSValue::null());
                        phase_resolve_value.set_property(ctx, "knownPhasesLast", JSValue::null());
                        phase_resolve_value.set_property(ctx, "knownEntriesLast", JSValue::null());
                        phase_resolve_value.set_property(ctx, "knownLast", JSValue::null());
                    }
                }
                phase_resolve_value.set_property(ctx, "defaultPhase", default_phase.dup(ctx));
                phase_resolve_value.set_property(
                    ctx,
                    "missingPhaseHint",
                    JSValue::string(ctx, "if phase is not in knownPhases, use phaseResolve.default"),
                );
                phase_resolve_value.set_property(
                    ctx,
                    "defaultMatched",
                    phase_resolve_default.get_property(ctx, "matched"),
                );
                phase_resolve_value.set_property(
                    ctx,
                    "defaultUsedDefault",
                    phase_resolve_default.get_property(ctx, "usedDefault"),
                );
                phase_resolve_value.set_property(
                    ctx,
                    "defaultReason",
                    phase_resolve_default.get_property(ctx, "reason"),
                );
                phase_resolve_value.set_property(
                    ctx,
                    "defaultEffectivePhase",
                    phase_resolve_default.get_property(ctx, "effectivePhase"),
                );
                phase_resolve_value.set_property(
                    ctx,
                    "defaultEffectiveEscalationKey",
                    phase_resolve_default.get_property(ctx, "effectiveEscalationKey"),
                );
                phase_resolve_value.set_property(
                    ctx,
                    "knownPhase",
                    phase_resolve_examples.get_property(ctx, "knownPhase"),
                );
                phase_resolve_value.set_property(
                    ctx,
                    "knownResult",
                    phase_resolve_examples.get_property(ctx, "knownResult"),
                );
                phase_resolve_value.set_property(
                    ctx,
                    "knownEffectivePhase",
                    phase_resolve_examples.get_property(ctx, "knownEffectivePhase"),
                );
                phase_resolve_value.set_property(
                    ctx,
                    "knownEffectiveEscalationKey",
                    phase_resolve_examples.get_property(ctx, "knownEffectiveEscalationKey"),
                );
                phase_resolve_value.set_property(
                    ctx,
                    "missingPhase",
                    phase_resolve_examples.get_property(ctx, "missingPhase"),
                );
                phase_resolve_value.set_property(
                    ctx,
                    "missingResult",
                    phase_resolve_examples.get_property(ctx, "missingResult"),
                );
                phase_resolve_value.set_property(
                    ctx,
                    "missingEffectivePhase",
                    phase_resolve_examples.get_property(ctx, "missingEffectivePhase"),
                );
                phase_resolve_value.set_property(
                    ctx,
                    "missingEffectiveEscalationKey",
                    phase_resolve_examples.get_property(ctx, "missingEffectiveEscalationKey"),
                );
                phase_resolve_value.set_property(ctx, "index", phase_resolve_index.dup(ctx));
                phase_resolve_value.set_property(ctx, "default", phase_resolve_default.dup(ctx));
                phase_resolve_value.set_property(ctx, "examples", phase_resolve_examples.dup(ctx));
                let query_only_phase_result = query_only_phase_example.get_property(ctx, "result");
                let query_only_phase_result_effective = query_only_phase_result.get_property(ctx, "effective");
                phase_resolve_value.set_property(
                    ctx,
                    "queryOnlySourceErrorCode",
                    query_only_phase_example.get_property(ctx, "sourceErrorCode"),
                );
                phase_resolve_value.set_property(
                    ctx,
                    "queryOnlyBlockedBy",
                    query_only_phase_example.get_property(ctx, "blockedBy"),
                );
                phase_resolve_value.set_property(
                    ctx,
                    "queryOnlyBlockedBySource",
                    query_only_phase_example.get_property(ctx, "blockedBySource"),
                );
                phase_resolve_value.set_property(
                    ctx,
                    "queryOnlyIsBlocked",
                    query_only_phase_example.get_property(ctx, "isBlocked"),
                );
                phase_resolve_value.set_property(
                    ctx,
                    "queryOnlyPhase",
                    query_only_phase_example.get_property(ctx, "phase"),
                );
                phase_resolve_value.set_property(
                    ctx,
                    "queryOnlyAvailable",
                    query_only_phase_example.get_property(ctx, "available"),
                );
                phase_resolve_value.set_property(
                    ctx,
                    "queryOnlyMatched",
                    query_only_phase_example.get_property(ctx, "matched"),
                );
                phase_resolve_value.set_property(
                    ctx,
                    "queryOnlyUsedDefault",
                    query_only_phase_example.get_property(ctx, "usedDefault"),
                );
                phase_resolve_value.set_property(
                    ctx,
                    "queryOnlyReason",
                    query_only_phase_example.get_property(ctx, "reason"),
                );
                phase_resolve_value.set_property(
                    ctx,
                    "queryOnlyEffectivePhase",
                    query_only_phase_example.get_property(ctx, "effectivePhase"),
                );
                phase_resolve_value.set_property(
                    ctx,
                    "queryOnlyEffectiveEscalationKey",
                    query_only_phase_example.get_property(ctx, "effectiveEscalationKey"),
                );
                phase_resolve_value.set_property(
                    ctx,
                    "queryOnlyWouldUsePhase",
                    query_only_phase_example.get_property(ctx, "wouldUseQueryPhase"),
                );
                phase_resolve_value.set_property(ctx, "queryOnlyResult", query_only_phase_result.dup(ctx));
                phase_resolve_value.set_property(
                    ctx,
                    "queryOnlyResultEffective",
                    query_only_phase_result_effective.dup(ctx),
                );
                phase_resolve_value.set_property(
                    ctx,
                    "queryOnlyResultMatched",
                    query_only_phase_result.get_property(ctx, "matched"),
                );
                phase_resolve_value.set_property(
                    ctx,
                    "queryOnlyResultUsedDefault",
                    query_only_phase_result.get_property(ctx, "usedDefault"),
                );
                phase_resolve_value.set_property(
                    ctx,
                    "queryOnlyResultReason",
                    query_only_phase_result.get_property(ctx, "reason"),
                );
                phase_resolve_value.set_property(
                    ctx,
                    "queryOnlyResultEffectivePhase",
                    query_only_phase_result.get_property(ctx, "effectivePhase"),
                );
                phase_resolve_value.set_property(
                    ctx,
                    "queryOnlyResultEffectiveEscalationKey",
                    query_only_phase_result.get_property(ctx, "effectiveEscalationKey"),
                );

                ready_value.set_property(ctx, "phaseResolveLookupKey", JSValue::string(ctx, "phase"));
                ready_value.set_property(
                    ctx,
                    "phaseResolvePolicy",
                    JSValue::string(ctx, "index-then-defaultPhase"),
                );
                ready_value.set_property(
                    ctx,
                    "phaseResolveOutputShape",
                    JSValue::string(
                        ctx,
                        "{ matched, usedDefault, reason, effectivePhase, effectiveEscalationKey, effective }",
                    ),
                );
                ready_value.set_property(ctx, "phaseResolveIndex", phase_resolve_index.dup(ctx));
                ready_value.set_property(ctx, "phaseResolveIndexEntries", phase_resolve_index.dup(ctx));
                ready_value.set_property(ctx, "phaseResolveDefault", phase_resolve_default.dup(ctx));
                ready_value.set_property(ctx, "phaseResolveExamples", phase_resolve_examples.dup(ctx));
                ready_value.set_property(ctx, "phaseResolvePhaseCount", JSValue::int(known_phases.len() as i32));
                ready_value.set_property(ctx, "phaseResolveIndexCount", JSValue::int(known_phases.len() as i32));
                ready_value.set_property(ctx, "phaseResolveKnownCount", JSValue::int(known_phases.len() as i32));
                ready_value.set_property(ctx, "phaseResolveKnownTotal", JSValue::int(known_phases.len() as i32));
                ready_value.set_property(ctx, "phaseResolveKnownAmount", JSValue::int(known_phases.len() as i32));
                ready_value.set_property(ctx, "phaseResolveKnownVolume", JSValue::int(known_phases.len() as i32));
                ready_value.set_property(
                    ctx,
                    "phaseResolveKnownMagnitude",
                    JSValue::int(known_phases.len() as i32),
                );
                ready_value.set_property(ctx, "phaseResolveKnownSize", JSValue::int(known_phases.len() as i32));
                ready_value.set_property(ctx, "phaseResolveKnownLength", JSValue::int(known_phases.len() as i32));
                ready_value.set_property(
                    ctx,
                    "phaseResolveKnownPhases",
                    JSValue(string_vec_to_js_array(ctx, &known_phases)),
                );
                ready_value.set_property(
                    ctx,
                    "phaseResolveKnownEntries",
                    JSValue(string_vec_to_js_array(ctx, &known_phases)),
                );
                ready_value.set_property(
                    ctx,
                    "phaseResolveKnownList",
                    JSValue(string_vec_to_js_array(ctx, &known_phases)),
                );
                ready_value.set_property(
                    ctx,
                    "phaseResolveKnownEntriesCount",
                    JSValue::int(known_phases.len() as i32),
                );
                ready_value.set_property(
                    ctx,
                    "phaseResolveKnownPhasesCount",
                    JSValue::int(known_phases.len() as i32),
                );
                match known_phases.first() {
                    Some(value) => {
                        ready_value.set_property(ctx, "phaseResolveKnownPhaseFirst", JSValue::string(ctx, value));
                        ready_value.set_property(ctx, "phaseResolveKnownEntriesFirst", JSValue::string(ctx, value));
                        ready_value.set_property(ctx, "phaseResolveKnownPhasesFirst", JSValue::string(ctx, value));
                        ready_value.set_property(ctx, "phaseResolveKnownFirst", JSValue::string(ctx, value));
                        ready_value.set_property(ctx, "phaseResolveIndexFirst", JSValue::string(ctx, value));
                    }
                    None => {
                        ready_value.set_property(ctx, "phaseResolveKnownPhaseFirst", JSValue::null());
                        ready_value.set_property(ctx, "phaseResolveKnownEntriesFirst", JSValue::null());
                        ready_value.set_property(ctx, "phaseResolveKnownPhasesFirst", JSValue::null());
                        ready_value.set_property(ctx, "phaseResolveKnownFirst", JSValue::null());
                        ready_value.set_property(ctx, "phaseResolveIndexFirst", JSValue::null());
                    }
                }
                match known_phases.last() {
                    Some(value) => {
                        ready_value.set_property(ctx, "phaseResolveKnownPhaseLast", JSValue::string(ctx, value));
                        ready_value.set_property(ctx, "phaseResolveKnownEntriesLast", JSValue::string(ctx, value));
                        ready_value.set_property(ctx, "phaseResolveKnownPhasesLast", JSValue::string(ctx, value));
                        ready_value.set_property(ctx, "phaseResolveKnownLast", JSValue::string(ctx, value));
                        ready_value.set_property(ctx, "phaseResolveIndexLast", JSValue::string(ctx, value));
                    }
                    None => {
                        ready_value.set_property(ctx, "phaseResolveKnownPhaseLast", JSValue::null());
                        ready_value.set_property(ctx, "phaseResolveKnownEntriesLast", JSValue::null());
                        ready_value.set_property(ctx, "phaseResolveKnownPhasesLast", JSValue::null());
                        ready_value.set_property(ctx, "phaseResolveKnownLast", JSValue::null());
                        ready_value.set_property(ctx, "phaseResolveIndexLast", JSValue::null());
                    }
                }
                ready_value.set_property(
                    ctx,
                    "phaseResolveMissingPhaseHint",
                    JSValue::string(ctx, "if phase is not in knownPhases, use phaseResolve.default"),
                );
                ready_value.set_property(
                    ctx,
                    "phaseResolveMissingHint",
                    JSValue::string(ctx, "if phase is not in knownPhases, use phaseResolve.default"),
                );
                ready_value.set_property(ctx, "phaseResolveDefaultPhase", default_phase.dup(ctx));
                ready_value.set_property(
                    ctx,
                    "phaseResolveDefaultMatched",
                    phase_resolve_default.get_property(ctx, "matched"),
                );
                ready_value.set_property(
                    ctx,
                    "phaseResolveDefaultUsedDefault",
                    phase_resolve_default.get_property(ctx, "usedDefault"),
                );
                ready_value.set_property(
                    ctx,
                    "phaseResolveDefaultReason",
                    phase_resolve_default.get_property(ctx, "reason"),
                );
                ready_value.set_property(
                    ctx,
                    "phaseResolveDefaultEffective",
                    phase_resolve_default.get_property(ctx, "effective"),
                );
                ready_value.set_property(
                    ctx,
                    "phaseResolveDefaultEffectivePhase",
                    phase_resolve_default.get_property(ctx, "effectivePhase"),
                );
                ready_value.set_property(
                    ctx,
                    "phaseResolveDefaultEffectiveEscalationKey",
                    phase_resolve_default.get_property(ctx, "effectiveEscalationKey"),
                );
                ready_value.set_property(
                    ctx,
                    "phaseResolveExampleKnownPhase",
                    phase_resolve_examples.get_property(ctx, "knownPhase"),
                );
                ready_value.set_property(
                    ctx,
                    "phaseResolveExampleKnownResult",
                    phase_resolve_examples.get_property(ctx, "knownResult"),
                );
                ready_value.set_property(
                    ctx,
                    "phaseResolveExampleKnownResultEffective",
                    phase_known_effective.dup(ctx),
                );
                ready_value.set_property(
                    ctx,
                    "phaseResolveExampleKnownResultEffectivePhase",
                    phase_known_result.get_property(ctx, "effectivePhase"),
                );
                ready_value.set_property(
                    ctx,
                    "phaseResolveExampleKnownResultEffectiveEscalationKey",
                    phase_known_result.get_property(ctx, "effectiveEscalationKey"),
                );
                ready_value.set_property(
                    ctx,
                    "phaseResolveExampleKnownMatched",
                    phase_known_result.get_property(ctx, "matched"),
                );
                ready_value.set_property(
                    ctx,
                    "phaseResolveExampleKnownUsedDefault",
                    phase_known_result.get_property(ctx, "usedDefault"),
                );
                ready_value.set_property(
                    ctx,
                    "phaseResolveExampleKnownReason",
                    phase_known_result.get_property(ctx, "reason"),
                );
                ready_value.set_property(
                    ctx,
                    "phaseResolveExampleKnownEffectivePhase",
                    phase_resolve_examples.get_property(ctx, "knownEffectivePhase"),
                );
                ready_value.set_property(
                    ctx,
                    "phaseResolveExampleKnownEffectiveEscalationKey",
                    phase_resolve_examples.get_property(ctx, "knownEffectiveEscalationKey"),
                );
                let phase_missing_result = phase_resolve_examples.get_property(ctx, "missingResult");
                let phase_missing_result_effective = phase_missing_result.get_property(ctx, "effective");
                ready_value.set_property(
                    ctx,
                    "phaseResolveExampleMissingPhase",
                    phase_resolve_examples.get_property(ctx, "missingPhase"),
                );
                ready_value.set_property(ctx, "phaseResolveExampleMissingResult", phase_missing_result.dup(ctx));
                ready_value.set_property(
                    ctx,
                    "phaseResolveExampleMissingResultEffective",
                    phase_missing_result_effective.dup(ctx),
                );
                ready_value.set_property(
                    ctx,
                    "phaseResolveExampleMissingResultEffectivePhase",
                    phase_missing_result.get_property(ctx, "effectivePhase"),
                );
                ready_value.set_property(
                    ctx,
                    "phaseResolveExampleMissingResultEffectiveEscalationKey",
                    phase_missing_result.get_property(ctx, "effectiveEscalationKey"),
                );
                ready_value.set_property(
                    ctx,
                    "phaseResolveExampleMissingMatched",
                    phase_missing_result.get_property(ctx, "matched"),
                );
                ready_value.set_property(
                    ctx,
                    "phaseResolveExampleMissingUsedDefault",
                    phase_missing_result.get_property(ctx, "usedDefault"),
                );
                ready_value.set_property(
                    ctx,
                    "phaseResolveExampleMissingReason",
                    phase_missing_result.get_property(ctx, "reason"),
                );
                ready_value.set_property(
                    ctx,
                    "phaseResolveExampleMissingEffectivePhase",
                    phase_resolve_examples.get_property(ctx, "missingEffectivePhase"),
                );
                ready_value.set_property(
                    ctx,
                    "phaseResolveExampleMissingEffectiveEscalationKey",
                    phase_resolve_examples.get_property(ctx, "missingEffectiveEscalationKey"),
                );
                ready_value.set_property(
                    ctx,
                    "phaseResolveKnownPhase",
                    phase_resolve_examples.get_property(ctx, "knownPhase"),
                );
                ready_value.set_property(
                    ctx,
                    "phaseResolveKnownResult",
                    phase_resolve_examples.get_property(ctx, "knownResult"),
                );
                ready_value.set_property(ctx, "phaseResolveKnownResultEffective", phase_known_effective.dup(ctx));
                ready_value.set_property(ctx, "phaseResolveKnownEffective", phase_known_effective.dup(ctx));
                ready_value.set_property(
                    ctx,
                    "phaseResolveKnownMatched",
                    phase_known_result.get_property(ctx, "matched"),
                );
                ready_value.set_property(
                    ctx,
                    "phaseResolveKnownUsedDefault",
                    phase_known_result.get_property(ctx, "usedDefault"),
                );
                ready_value.set_property(
                    ctx,
                    "phaseResolveKnownReason",
                    phase_known_result.get_property(ctx, "reason"),
                );
                ready_value.set_property(
                    ctx,
                    "phaseResolveKnownEffectivePhase",
                    phase_resolve_examples.get_property(ctx, "knownEffectivePhase"),
                );
                ready_value.set_property(
                    ctx,
                    "phaseResolveKnownEffectiveEscalationKey",
                    phase_resolve_examples.get_property(ctx, "knownEffectiveEscalationKey"),
                );
                ready_value.set_property(
                    ctx,
                    "phaseResolveMissingPhase",
                    phase_resolve_examples.get_property(ctx, "missingPhase"),
                );
                ready_value.set_property(ctx, "phaseResolveMissingResult", phase_missing_result.dup(ctx));
                ready_value.set_property(
                    ctx,
                    "phaseResolveMissingResultEffective",
                    phase_missing_result_effective.dup(ctx),
                );
                ready_value.set_property(
                    ctx,
                    "phaseResolveMissingEffective",
                    phase_missing_result_effective.dup(ctx),
                );
                ready_value.set_property(
                    ctx,
                    "phaseResolveMissingMatched",
                    phase_missing_result.get_property(ctx, "matched"),
                );
                ready_value.set_property(
                    ctx,
                    "phaseResolveMissingUsedDefault",
                    phase_missing_result.get_property(ctx, "usedDefault"),
                );
                ready_value.set_property(
                    ctx,
                    "phaseResolveMissingReason",
                    phase_missing_result.get_property(ctx, "reason"),
                );
                ready_value.set_property(
                    ctx,
                    "phaseResolveMissingEffectivePhase",
                    phase_resolve_examples.get_property(ctx, "missingEffectivePhase"),
                );
                ready_value.set_property(
                    ctx,
                    "phaseResolveMissingEffectiveEscalationKey",
                    phase_resolve_examples.get_property(ctx, "missingEffectiveEscalationKey"),
                );
                ready_value.set_property(
                    ctx,
                    "queryOnlyPhaseResolveSourceErrorCode",
                    query_only_phase_example.get_property(ctx, "sourceErrorCode"),
                );
                ready_value.set_property(
                    ctx,
                    "queryOnlyPhaseResolvePhase",
                    query_only_phase_example.get_property(ctx, "phase"),
                );
                ready_value.set_property(
                    ctx,
                    "queryOnlyPhaseResolveBlockedBy",
                    query_only_phase_example.get_property(ctx, "blockedBy"),
                );
                ready_value.set_property(
                    ctx,
                    "queryOnlyPhaseResolveBlockedBySource",
                    query_only_phase_example.get_property(ctx, "blockedBySource"),
                );
                ready_value.set_property(
                    ctx,
                    "queryOnlyPhaseResolveIsBlocked",
                    query_only_phase_example.get_property(ctx, "isBlocked"),
                );
                ready_value.set_property(
                    ctx,
                    "queryOnlyPhaseResolveAvailable",
                    query_only_phase_example.get_property(ctx, "available"),
                );
                ready_value.set_property(
                    ctx,
                    "queryOnlyPhaseResolveMatched",
                    query_only_phase_example.get_property(ctx, "matched"),
                );
                ready_value.set_property(
                    ctx,
                    "queryOnlyPhaseResolveUsedDefault",
                    query_only_phase_example.get_property(ctx, "usedDefault"),
                );
                ready_value.set_property(
                    ctx,
                    "queryOnlyPhaseResolveReason",
                    query_only_phase_example.get_property(ctx, "reason"),
                );
                ready_value.set_property(
                    ctx,
                    "queryOnlyPhaseResolveEffectivePhase",
                    query_only_phase_example.get_property(ctx, "effectivePhase"),
                );
                ready_value.set_property(
                    ctx,
                    "queryOnlyPhaseResolveEffectiveEscalationKey",
                    query_only_phase_example.get_property(ctx, "effectiveEscalationKey"),
                );
                ready_value.set_property(
                    ctx,
                    "queryOnlyPhaseResolveWouldUsePhase",
                    query_only_phase_example.get_property(ctx, "wouldUseQueryPhase"),
                );
                let query_only_phase_example_result = query_only_phase_example.get_property(ctx, "result");
                let query_only_phase_example_result_effective =
                    query_only_phase_example_result.get_property(ctx, "effective");
                ready_value.set_property(
                    ctx,
                    "queryOnlyPhaseResolveResult",
                    query_only_phase_example_result.dup(ctx),
                );
                ready_value.set_property(
                    ctx,
                    "queryOnlyPhaseResolveResultEffective",
                    query_only_phase_example_result_effective.dup(ctx),
                );
                ready_value.set_property(
                    ctx,
                    "queryOnlyPhaseResolveResultMatched",
                    query_only_phase_example_result.get_property(ctx, "matched"),
                );
                ready_value.set_property(
                    ctx,
                    "queryOnlyPhaseResolveResultUsedDefault",
                    query_only_phase_example_result.get_property(ctx, "usedDefault"),
                );
                ready_value.set_property(
                    ctx,
                    "queryOnlyPhaseResolveResultReason",
                    query_only_phase_example_result.get_property(ctx, "reason"),
                );
                ready_value.set_property(
                    ctx,
                    "queryOnlyPhaseResolveResultEffectivePhase",
                    query_only_phase_example_result.get_property(ctx, "effectivePhase"),
                );
                ready_value.set_property(
                    ctx,
                    "queryOnlyPhaseResolveResultEffectiveEscalationKey",
                    query_only_phase_example_result.get_property(ctx, "effectiveEscalationKey"),
                );
                ready_value.set_property(
                    ctx,
                    "queryOnlyErrorCode",
                    resolve_value.get_property(ctx, "queryOnlyErrorCode"),
                );
                ready_value.set_property(
                    ctx,
                    "queryOnlySourceErrorCode",
                    phase_resolve_value.get_property(ctx, "queryOnlySourceErrorCode"),
                );
                ready_value.set_property(
                    ctx,
                    "queryOnlyBlockedBy",
                    resolve_value.get_property(ctx, "queryOnlyBlockedBy"),
                );
                ready_value.set_property(
                    ctx,
                    "queryOnlyResolveBlockedBy",
                    resolve_value.get_property(ctx, "queryOnlyBlockedBy"),
                );
                ready_value.set_property(
                    ctx,
                    "queryOnlyBlockedBySource",
                    resolve_value.get_property(ctx, "queryOnlyBlockedBySource"),
                );
                ready_value.set_property(
                    ctx,
                    "queryOnlyResolveBlockedBySource",
                    resolve_value.get_property(ctx, "queryOnlyBlockedBySource"),
                );
                ready_value.set_property(
                    ctx,
                    "queryOnlyIsBlocked",
                    resolve_value.get_property(ctx, "queryOnlyIsBlocked"),
                );
                ready_value.set_property(
                    ctx,
                    "queryOnlyResolveIsBlocked",
                    resolve_value.get_property(ctx, "queryOnlyIsBlocked"),
                );
                ready_value.set_property(
                    ctx,
                    "queryOnlyPhase",
                    phase_resolve_value.get_property(ctx, "queryOnlyPhase"),
                );
                ready_value.set_property(
                    ctx,
                    "queryOnlyPhaseResolveSourceErrorCode",
                    phase_resolve_value.get_property(ctx, "queryOnlySourceErrorCode"),
                );
                ready_value.set_property(
                    ctx,
                    "queryOnlyPhaseResolvePhase",
                    phase_resolve_value.get_property(ctx, "queryOnlyPhase"),
                );
                ready_value.set_property(
                    ctx,
                    "queryOnlyPhaseResolveBlockedBy",
                    phase_resolve_value.get_property(ctx, "queryOnlyBlockedBy"),
                );
                ready_value.set_property(
                    ctx,
                    "queryOnlyPhaseResolveBlockedBySource",
                    phase_resolve_value.get_property(ctx, "queryOnlyBlockedBySource"),
                );
                ready_value.set_property(
                    ctx,
                    "queryOnlyPhaseResolveIsBlocked",
                    phase_resolve_value.get_property(ctx, "queryOnlyIsBlocked"),
                );
                ready_value.set_property(
                    ctx,
                    "queryOnlyPhaseResolveAvailable",
                    phase_resolve_value.get_property(ctx, "queryOnlyAvailable"),
                );
                ready_value.set_property(
                    ctx,
                    "queryOnlyAvailable",
                    resolve_value.get_property(ctx, "queryOnlyAvailable"),
                );
                ready_value.set_property(
                    ctx,
                    "queryOnlyResolveAvailable",
                    resolve_value.get_property(ctx, "queryOnlyAvailable"),
                );
                ready_value.set_property(
                    ctx,
                    "queryOnlyMatched",
                    resolve_value.get_property(ctx, "queryOnlyMatched"),
                );
                ready_value.set_property(
                    ctx,
                    "queryOnlyResolveMatched",
                    resolve_value.get_property(ctx, "queryOnlyMatched"),
                );
                ready_value.set_property(
                    ctx,
                    "queryOnlyUsedDefault",
                    resolve_value.get_property(ctx, "queryOnlyUsedDefault"),
                );
                ready_value.set_property(
                    ctx,
                    "queryOnlyResolveUsedDefault",
                    resolve_value.get_property(ctx, "queryOnlyUsedDefault"),
                );
                ready_value.set_property(
                    ctx,
                    "queryOnlyReason",
                    resolve_value.get_property(ctx, "queryOnlyReason"),
                );
                ready_value.set_property(
                    ctx,
                    "queryOnlyResolveReason",
                    resolve_value.get_property(ctx, "queryOnlyReason"),
                );
                ready_value.set_property(
                    ctx,
                    "queryOnlyEffectivePhase",
                    resolve_value.get_property(ctx, "queryOnlyEffectivePhase"),
                );
                ready_value.set_property(
                    ctx,
                    "queryOnlyResolveEffectivePhase",
                    resolve_value.get_property(ctx, "queryOnlyEffectivePhase"),
                );
                ready_value.set_property(
                    ctx,
                    "queryOnlyEffectiveEscalationKey",
                    resolve_value.get_property(ctx, "queryOnlyEffectiveEscalationKey"),
                );
                ready_value.set_property(
                    ctx,
                    "queryOnlyResolveEffectiveEscalationKey",
                    resolve_value.get_property(ctx, "queryOnlyEffectiveEscalationKey"),
                );
                ready_value.set_property(
                    ctx,
                    "queryOnlyWouldUsePath",
                    resolve_value.get_property(ctx, "queryOnlyWouldUsePath"),
                );
                ready_value.set_property(
                    ctx,
                    "queryOnlyResolveWouldUsePath",
                    resolve_value.get_property(ctx, "queryOnlyWouldUsePath"),
                );
                ready_value.set_property(
                    ctx,
                    "queryOnlyWouldUsePhase",
                    phase_resolve_value.get_property(ctx, "queryOnlyWouldUsePhase"),
                );
                ready_value.set_property(
                    ctx,
                    "queryOnlyPhaseResolveWouldUsePhase",
                    phase_resolve_value.get_property(ctx, "queryOnlyWouldUsePhase"),
                );
                ready_value.set_property(
                    ctx,
                    "queryOnlyResult",
                    resolve_value.get_property(ctx, "queryOnlyResult"),
                );
                ready_value.set_property(
                    ctx,
                    "queryOnlyResultEffective",
                    resolve_value.get_property(ctx, "queryOnlyResultEffective"),
                );
                ready_value.set_property(
                    ctx,
                    "queryOnlyResultMatched",
                    resolve_value.get_property(ctx, "queryOnlyResultMatched"),
                );
                ready_value.set_property(
                    ctx,
                    "queryOnlyResultUsedDefault",
                    resolve_value.get_property(ctx, "queryOnlyResultUsedDefault"),
                );
                ready_value.set_property(
                    ctx,
                    "queryOnlyResultReason",
                    resolve_value.get_property(ctx, "queryOnlyResultReason"),
                );
                ready_value.set_property(
                    ctx,
                    "queryOnlyResultEffectivePhase",
                    resolve_value.get_property(ctx, "queryOnlyResultEffectivePhase"),
                );
                ready_value.set_property(
                    ctx,
                    "queryOnlyResultEffectiveEscalationKey",
                    resolve_value.get_property(ctx, "queryOnlyResultEffectiveEscalationKey"),
                );
                ready_value.set_property(
                    ctx,
                    "queryOnlyResolveResult",
                    resolve_value.get_property(ctx, "queryOnlyResult"),
                );
                ready_value.set_property(
                    ctx,
                    "queryOnlyResolveResultEffective",
                    resolve_value.get_property(ctx, "queryOnlyResultEffective"),
                );
                ready_value.set_property(
                    ctx,
                    "queryOnlyResolveResultMatched",
                    resolve_value.get_property(ctx, "queryOnlyResultMatched"),
                );
                ready_value.set_property(
                    ctx,
                    "queryOnlyResolveResultUsedDefault",
                    resolve_value.get_property(ctx, "queryOnlyResultUsedDefault"),
                );
                ready_value.set_property(
                    ctx,
                    "queryOnlyResolveResultReason",
                    resolve_value.get_property(ctx, "queryOnlyResultReason"),
                );
                ready_value.set_property(
                    ctx,
                    "queryOnlyResolveResultEffectivePhase",
                    resolve_value.get_property(ctx, "queryOnlyResultEffectivePhase"),
                );
                ready_value.set_property(
                    ctx,
                    "queryOnlyResolveResultEffectiveEscalationKey",
                    resolve_value.get_property(ctx, "queryOnlyResultEffectiveEscalationKey"),
                );

                ready_value.set_property(ctx, "phaseCount", JSValue::int(known_phases.len() as i32));
                ready_value.set_property(ctx, "phases", phases);
                match known_phases.first() {
                    Some(value) => ready_value.set_property(ctx, "phaseFirst", JSValue::string(ctx, value)),
                    None => ready_value.set_property(ctx, "phaseFirst", JSValue::null()),
                };
                match known_phases.last() {
                    Some(value) => ready_value.set_property(ctx, "phaseLast", JSValue::string(ctx, value)),
                    None => ready_value.set_property(ctx, "phaseLast", JSValue::null()),
                };
                ready_value.set_property(ctx, "phaseIndex", phase_index);
                set_phase_ready_aliases(ctx, &ready_value, "phaseQuery", &phase_query, false, false);
                set_phase_ready_aliases(ctx, &ready_value, "phasePreflight", &phase_preflight, true, true);
                set_phase_ready_aliases(ctx, &ready_value, "phaseDiagnose", &phase_diagnose, true, true);
                set_phase_ready_aliases(ctx, &ready_value, "phaseCleanup", &phase_cleanup, false, false);
                ready_value.set_property(ctx, "phaseResolve", phase_resolve_value.dup(ctx));
                ready_value.set_property(ctx, "defaultPhase", default_phase);
                ready_value.set_property(ctx, "default", ready_default);
                routing_decision.set_property(ctx, "ready", ready_value);
            }
            None => {
                routing_decision.set_property(ctx, "defaultRecommendedEscalationKey", JSValue::null());
                routing_decision.set_property(ctx, "defaultRecommendedPhase", JSValue::null());
                routing_decision.set_property(ctx, "defaultEffectiveEscalationKey", JSValue::null());
                routing_decision.set_property(ctx, "defaultEffectivePhase", JSValue::null());
                routing_decision.set_property(ctx, "defaultRecommendedTemplateCount", JSValue::int(0));
                routing_decision.set_property(ctx, "defaultRecommendedTemplates", JSValue(ffi::JS_NewArray(ctx)));
                routing_decision.set_property(ctx, "defaultRecommendedCommandJsonTemplateCount", JSValue::int(0));
                routing_decision.set_property(
                    ctx,
                    "defaultRecommendedCommandJsonTemplates",
                    JSValue(ffi::JS_NewArray(ctx)),
                );
                routing_decision.set_property(ctx, "default", JSValue::null());
                let ready_value = JSValue(ffi::JS_NewObject(ctx));
                ready_value.set_property(ctx, "lookupRule", JSValue::string(ctx, "index[errorCode] || default"));
                ready_value.set_property(ctx, "resolveLookupKey", JSValue::string(ctx, "errorCode"));
                ready_value.set_property(ctx, "resolvePolicy", JSValue::string(ctx, "index-then-default"));
                ready_value.set_property(
                    ctx,
                    "resolveOutputShape",
                    JSValue::string(
                        ctx,
                        "{ matched, usedDefault, reason, effectivePhase, effectiveEscalationKey, effective }",
                    ),
                );
                let empty_object = JSValue(ffi::JS_NewObject(ctx));
                ready_value.set_property(ctx, "index", empty_object.dup(ctx));
                ready_value.set_property(ctx, "resolveIndex", empty_object.dup(ctx));
                ready_value.set_property(ctx, "resolveIndexEntries", empty_object);
                ready_value.set_property(ctx, "default", JSValue::null());
                ready_value.set_property(ctx, "resolveDefault", JSValue::null());
                ready_value.set_property(ctx, "resolveExamples", JSValue::null());
                ready_value.set_property(ctx, "resolve", JSValue::null());
                ready_value.set_property(ctx, "phaseResolveLookupKey", JSValue::string(ctx, "phase"));
                ready_value.set_property(
                    ctx,
                    "phaseResolvePolicy",
                    JSValue::string(ctx, "index-then-defaultPhase"),
                );
                ready_value.set_property(
                    ctx,
                    "phaseResolveOutputShape",
                    JSValue::string(
                        ctx,
                        "{ matched, usedDefault, reason, effectivePhase, effectiveEscalationKey, effective }",
                    ),
                );
                let empty_phase_object = JSValue(ffi::JS_NewObject(ctx));
                ready_value.set_property(ctx, "phaseResolveIndex", empty_phase_object.dup(ctx));
                ready_value.set_property(ctx, "phaseResolveIndexEntries", empty_phase_object.dup(ctx));
                ready_value.set_property(ctx, "phaseIndex", empty_phase_object.dup(ctx));
                ready_value.set_property(ctx, "phaseResolve", JSValue::null());
                ready_value.set_property(ctx, "phaseResolveDefault", JSValue::null());
                ready_value.set_property(ctx, "phaseResolveExamples", JSValue::null());
                ready_value.set_property(ctx, "phases", JSValue(ffi::JS_NewArray(ctx)));
                ready_value.set_property(ctx, "phaseCount", JSValue::int(0));
                ready_value.set_property(ctx, "phaseFirst", JSValue::null());
                ready_value.set_property(ctx, "phaseLast", JSValue::null());
                set_phase_ready_aliases(ctx, &ready_value, "phaseQuery", &JSValue::null(), false, false);
                set_phase_ready_aliases(ctx, &ready_value, "phasePreflight", &JSValue::null(), true, true);
                set_phase_ready_aliases(ctx, &ready_value, "phaseDiagnose", &JSValue::null(), true, true);
                set_phase_ready_aliases(ctx, &ready_value, "phaseCleanup", &JSValue::null(), false, false);
                ready_value.set_property(ctx, "defaultPhase", JSValue::null());
                routing_decision.set_property(ctx, "ready", ready_value);
            }
        }

        let retryable_phase_count = phase_order.iter().filter(|phase| phase_retry_policy(phase).0).count();
        let non_retryable_phase_count = phase_order.len().saturating_sub(retryable_phase_count);
        let termination_policy = JSValue(ffi::JS_NewObject(ctx));
        termination_policy.set_property(ctx, "mode", JSValue::string(ctx, "phase-retry-budget"));
        termination_policy.set_property(
            ctx,
            "terminateWhen",
            JSValue::string(ctx, "all-retryable-steps-exhausted"),
        );
        termination_policy.set_property(
            ctx,
            "escalateWhen",
            JSValue::string(ctx, "non-retryable-step-failed-or-retry-budget-exhausted"),
        );
        termination_policy.set_property(
            ctx,
            "timeoutEscalateWhen",
            JSValue::string(ctx, "phase-timeout-exceeded"),
        );
        termination_policy.set_property(ctx, "retryablePhaseCount", JSValue::int(retryable_phase_count as i32));
        termination_policy.set_property(
            ctx,
            "nonRetryablePhaseCount",
            JSValue::int(non_retryable_phase_count as i32),
        );
        termination_policy.set_property(ctx, "retryableStepCount", JSValue::int(retryable_step_count as i32));
        termination_policy.set_property(ctx, "totalRetryBudget", JSValue::int(total_retry_budget as i32));

        let fallback_plan = JSValue(ffi::JS_NewObject(ctx));
        fallback_plan.set_property(ctx, "trigger", JSValue::string(ctx, "next-action-not-ready"));
        match next_action {
            Some(action) => {
                fallback_plan.set_property(ctx, "reason", JSValue::string(ctx, &action.recommendation));
                fallback_plan.set_property(ctx, "fromActionKey", JSValue::string(ctx, &action.action_key));
            }
            None => {
                fallback_plan.set_property(ctx, "reason", JSValue::null());
                fallback_plan.set_property(ctx, "fromActionKey", JSValue::null());
            }
        }
        fallback_plan.set_property(ctx, "toActionKey", JSValue::null());
        fallback_plan.set_property(ctx, "usesSuggestedSequence", JSValue::bool(true));
        fallback_plan.set_property(ctx, "templateCount", JSValue::int(fallback_templates.len() as i32));
        set_string_array_property(ctx, fallback_plan.raw(), "templates", &fallback_templates);
        fallback_plan.set_property(ctx, "phaseCount", JSValue::int(phase_order.len() as i32));
        set_string_array_property(ctx, fallback_plan.raw(), "phaseOrder", &phase_order);
        fallback_plan.set_property(ctx, "phaseRetryPolicyCount", JSValue::int(phase_order.len() as i32));
        fallback_plan.set_property(ctx, "phaseRetryPolicies", JSValue(phase_retry_policies));
        fallback_plan.set_property(ctx, "phaseTimeoutPolicyCount", JSValue::int(phase_order.len() as i32));
        fallback_plan.set_property(ctx, "phaseTimeoutPolicies", JSValue(phase_timeout_policies));
        fallback_plan.set_property(ctx, "phaseErrorCodeCount", JSValue::int(phase_order.len() as i32));
        fallback_plan.set_property(ctx, "phaseErrorCodes", JSValue(phase_error_codes));
        fallback_plan.set_property(ctx, "terminationPolicy", termination_policy);
        fallback_plan.set_property(
            ctx,
            "stepCount",
            JSValue::int(fallback_command_json_templates.len() as i32),
        );
        fallback_plan.set_property(ctx, "retryableStepCount", JSValue::int(retryable_step_count as i32));
        fallback_plan.set_property(ctx, "totalRetryBudget", JSValue::int(total_retry_budget as i32));
        fallback_plan.set_property(ctx, "steps", JSValue(fallback_steps));
        fallback_plan.set_property(
            ctx,
            "escalationRecommendationCount",
            JSValue::int(escalation_recommendation_count as i32),
        );
        fallback_plan.set_property(ctx, "escalationRecommendations", JSValue(escalation_recommendations));
        match escalation_specs.first() {
            Some((key, _, _, _, _, _, _)) => {
                fallback_plan.set_property(ctx, "suggestedEscalationKey", JSValue::string(ctx, key))
            }
            None => fallback_plan.set_property(ctx, "suggestedEscalationKey", JSValue::null()),
        };
        fallback_plan.set_property(
            ctx,
            "errorCodeRoutingCount",
            JSValue::int(error_code_routing_candidates.len() as i32),
        );
        fallback_plan.set_property(ctx, "errorCodeRouting", error_code_routing);
        fallback_plan.set_property(
            ctx,
            "errorCodeRoutingResolvedCount",
            JSValue::int(error_code_routing_candidates.len() as i32),
        );
        fallback_plan.set_property(ctx, "errorCodeRoutingResolved", error_code_routing_resolved);
        fallback_plan.set_property(ctx, "errorCodeRoutingEntries", JSValue(error_code_routing_entries));
        fallback_plan.set_property(ctx, "routingDecision", routing_decision);
        fallback_plan.set_property(
            ctx,
            "commandJsonTemplateCount",
            JSValue::int(fallback_command_json_templates.len() as i32),
        );
        fallback_plan.set_property(
            ctx,
            "commandJsonEligibleTemplateCount",
            JSValue::int(
                fallback_command_json_templates
                    .iter()
                    .filter(|entry| {
                        JSValue(**entry)
                            .get_property(ctx, "commandJsonEligible")
                            .to_bool()
                            .unwrap_or(false)
                    })
                    .count() as i32,
            ),
        );
        fallback_plan.set_property(
            ctx,
            "commandJsonTemplates",
            JSValue(fallback_command_json_templates_array),
        );

        match fallback_first_step {
            Some(step_raw) => {
                let step = JSValue(step_raw);
                let next_step_command_json_template = step.get_property(ctx, "commandJsonTemplate");
                fallback_plan.set_property(ctx, "nextStep", step.dup(ctx));
                fallback_plan.set_property(ctx, "nextStepId", step.get_property(ctx, "id"));
                fallback_plan.set_property(ctx, "nextStepSource", step.get_property(ctx, "source"));
                fallback_plan.set_property(ctx, "nextStepActionKey", step.get_property(ctx, "actionKey"));
                fallback_plan.set_property(ctx, "nextStepCommandGroup", step.get_property(ctx, "commandGroup"));
                fallback_plan.set_property(ctx, "nextStepAllowed", step.get_property(ctx, "allowed"));
                fallback_plan.set_property(ctx, "nextStepBlockedBy", step.get_property(ctx, "blockedBy"));
                fallback_plan.set_property(ctx, "nextStepBranch", step.get_property(ctx, "branch"));
                fallback_plan.set_property(ctx, "nextStepReason", step.get_property(ctx, "reason"));
                fallback_plan.set_property(ctx, "nextStepPreferredPath", step.get_property(ctx, "preferredPath"));
                fallback_plan.set_property(ctx, "nextStepCommand", step.get_property(ctx, "command"));
                fallback_plan.set_property(ctx, "nextStepPhase", step.get_property(ctx, "phase"));
                fallback_plan.set_property(
                    ctx,
                    "nextStepCommandJsonEligible",
                    step.get_property(ctx, "commandJsonEligible"),
                );
                fallback_plan.set_property(
                    ctx,
                    "nextStepCommandJsonTemplateEligible",
                    step.get_property(ctx, "commandJsonTemplateEligible"),
                );
                fallback_plan.set_property(
                    ctx,
                    "nextStepCommandJsonTemplate",
                    next_step_command_json_template.dup(ctx),
                );
                fallback_plan.set_property(
                    ctx,
                    "nextStepCommandJsonTemplateCommand",
                    next_step_command_json_template.get_property(ctx, "command"),
                );
                fallback_plan.set_property(
                    ctx,
                    "nextStepCommandJsonTemplateKind",
                    next_step_command_json_template.get_property(ctx, "kind"),
                );
                fallback_plan.set_property(ctx, "nextStepKind", step.get_property(ctx, "kind"));
                fallback_plan.set_property(ctx, "nextStepRetryable", step.get_property(ctx, "retryable"));
                fallback_plan.set_property(
                    ctx,
                    "nextStepMaxSuggestedRetries",
                    step.get_property(ctx, "maxSuggestedRetries"),
                );
                fallback_plan.set_property(
                    ctx,
                    "nextStepRetryDelayHintMs",
                    step.get_property(ctx, "retryDelayHintMs"),
                );
                fallback_plan.set_property(ctx, "nextStepTimeoutHintMs", step.get_property(ctx, "timeoutHintMs"));
                fallback_plan.set_property(ctx, "nextStepTimeoutAction", step.get_property(ctx, "timeoutAction"));
                fallback_plan.set_property(ctx, "nextStepErrorCode", step.get_property(ctx, "errorCode"));
                fallback_plan.set_property(
                    ctx,
                    "nextStepTimeoutErrorCode",
                    step.get_property(ctx, "timeoutErrorCode"),
                );
                fallback_plan.set_property(ctx, "nextStepRisk", step.get_property(ctx, "risk"));
                fallback_plan.set_property(
                    ctx,
                    "nextStepPlaceholderCount",
                    step.get_property(ctx, "placeholderCount"),
                );
                fallback_plan.set_property(ctx, "nextStepPlaceholders", step.get_property(ctx, "placeholders"));
                fallback_plan.set_property(ctx, "nextStepCliArgs", step.get_property(ctx, "cliArgs"));
                next_step_command_json_template.free(ctx);
                fallback_plan.set_property(ctx, "nextStepChainSource", JSValue::string(ctx, "fallback-plan"));
                fallback_plan.set_property(ctx, "nextStepChainLimit", JSValue::int(fallback_step_limit as i32));
                fallback_plan.set_property(ctx, "nextStepChainCount", JSValue::int(fallback_step_count as i32));
                fallback_plan.set_property(ctx, "nextStepChainTruncated", JSValue::bool(fallback_step_truncated));
                fallback_plan.set_property(ctx, "nextStepChain", JSValue(fallback_next_step_chain));
                let active_step_command_json_template = step.get_property(ctx, "commandJsonTemplate");
                fallback_plan.set_property(ctx, "activeStep", step.dup(ctx));
                fallback_plan.set_property(ctx, "activeStepSource", step.get_property(ctx, "source"));
                fallback_plan.set_property(ctx, "activeStepAllowed", step.get_property(ctx, "allowed"));
                fallback_plan.set_property(ctx, "activeStepBlockedBy", step.get_property(ctx, "blockedBy"));
                fallback_plan.set_property(ctx, "activeStepBranch", step.get_property(ctx, "branch"));
                fallback_plan.set_property(ctx, "activeStepReason", step.get_property(ctx, "reason"));
                fallback_plan.set_property(ctx, "activeStepPreferredPath", step.get_property(ctx, "preferredPath"));
                fallback_plan.set_property(ctx, "activeStepActionKey", step.get_property(ctx, "actionKey"));
                fallback_plan.set_property(ctx, "activeStepCommandGroup", step.get_property(ctx, "commandGroup"));
                fallback_plan.set_property(ctx, "activeStepId", step.get_property(ctx, "id"));
                fallback_plan.set_property(ctx, "activeStepCommand", step.get_property(ctx, "command"));
                fallback_plan.set_property(ctx, "activeStepPhase", step.get_property(ctx, "phase"));
                fallback_plan.set_property(ctx, "activeStepReadyToRun", step.get_property(ctx, "readyToRun"));
                fallback_plan.set_property(
                    ctx,
                    "activeStepRequiresFallback",
                    step.get_property(ctx, "requiresFallback"),
                );
                fallback_plan.set_property(ctx, "activeStepKind", step.get_property(ctx, "kind"));
                fallback_plan.set_property(
                    ctx,
                    "activeStepCommandJsonEligible",
                    step.get_property(ctx, "commandJsonEligible"),
                );
                fallback_plan.set_property(
                    ctx,
                    "activeStepCommandJsonTemplateEligible",
                    step.get_property(ctx, "commandJsonTemplateEligible"),
                );
                fallback_plan.set_property(
                    ctx,
                    "activeStepCommandJsonTemplate",
                    active_step_command_json_template.dup(ctx),
                );
                fallback_plan.set_property(
                    ctx,
                    "activeStepCommandJsonTemplateCommand",
                    active_step_command_json_template.get_property(ctx, "command"),
                );
                fallback_plan.set_property(
                    ctx,
                    "activeStepCommandJsonTemplateKind",
                    active_step_command_json_template.get_property(ctx, "kind"),
                );
                fallback_plan.set_property(ctx, "activeStepRetryable", step.get_property(ctx, "retryable"));
                fallback_plan.set_property(
                    ctx,
                    "activeStepMaxSuggestedRetries",
                    step.get_property(ctx, "maxSuggestedRetries"),
                );
                fallback_plan.set_property(
                    ctx,
                    "activeStepRetryDelayHintMs",
                    step.get_property(ctx, "retryDelayHintMs"),
                );
                fallback_plan.set_property(ctx, "activeStepTimeoutHintMs", step.get_property(ctx, "timeoutHintMs"));
                fallback_plan.set_property(ctx, "activeStepTimeoutAction", step.get_property(ctx, "timeoutAction"));
                fallback_plan.set_property(ctx, "activeStepErrorCode", step.get_property(ctx, "errorCode"));
                fallback_plan.set_property(
                    ctx,
                    "activeStepTimeoutErrorCode",
                    step.get_property(ctx, "timeoutErrorCode"),
                );
                fallback_plan.set_property(ctx, "activeStepRisk", step.get_property(ctx, "risk"));
                fallback_plan.set_property(
                    ctx,
                    "activeStepPlaceholderCount",
                    step.get_property(ctx, "placeholderCount"),
                );
                fallback_plan.set_property(ctx, "activeStepPlaceholders", step.get_property(ctx, "placeholders"));
                fallback_plan.set_property(ctx, "activeStepCliArgs", step.get_property(ctx, "cliArgs"));
                active_step_command_json_template.free(ctx);
                step.free(ctx);
            }
            None => {
                fallback_plan.set_property(ctx, "nextStep", JSValue::null());
                fallback_plan.set_property(ctx, "nextStepId", JSValue::null());
                fallback_plan.set_property(ctx, "nextStepSource", JSValue::null());
                fallback_plan.set_property(ctx, "nextStepActionKey", JSValue::null());
                fallback_plan.set_property(ctx, "nextStepCommandGroup", JSValue::null());
                fallback_plan.set_property(ctx, "nextStepAllowed", JSValue::null());
                fallback_plan.set_property(ctx, "nextStepBlockedBy", JSValue::null());
                fallback_plan.set_property(ctx, "nextStepBranch", JSValue::null());
                fallback_plan.set_property(ctx, "nextStepReason", JSValue::null());
                fallback_plan.set_property(ctx, "nextStepPreferredPath", JSValue::null());
                fallback_plan.set_property(ctx, "nextStepCommand", JSValue::null());
                fallback_plan.set_property(ctx, "nextStepPhase", JSValue::null());
                fallback_plan.set_property(ctx, "nextStepCommandJsonEligible", JSValue::null());
                fallback_plan.set_property(ctx, "nextStepCommandJsonTemplateEligible", JSValue::null());
                fallback_plan.set_property(ctx, "nextStepCommandJsonTemplate", JSValue::null());
                fallback_plan.set_property(ctx, "nextStepCommandJsonTemplateCommand", JSValue::null());
                fallback_plan.set_property(ctx, "nextStepCommandJsonTemplateKind", JSValue::null());
                fallback_plan.set_property(ctx, "nextStepKind", JSValue::null());
                fallback_plan.set_property(ctx, "nextStepRetryable", JSValue::null());
                fallback_plan.set_property(ctx, "nextStepMaxSuggestedRetries", JSValue::null());
                fallback_plan.set_property(ctx, "nextStepRetryDelayHintMs", JSValue::null());
                fallback_plan.set_property(ctx, "nextStepTimeoutHintMs", JSValue::null());
                fallback_plan.set_property(ctx, "nextStepTimeoutAction", JSValue::null());
                fallback_plan.set_property(ctx, "nextStepErrorCode", JSValue::null());
                fallback_plan.set_property(ctx, "nextStepTimeoutErrorCode", JSValue::null());
                fallback_plan.set_property(ctx, "nextStepRisk", JSValue::null());
                fallback_plan.set_property(ctx, "nextStepPlaceholderCount", JSValue::null());
                fallback_plan.set_property(ctx, "nextStepPlaceholders", JSValue::null());
                fallback_plan.set_property(ctx, "nextStepCliArgs", JSValue::null());
                fallback_plan.set_property(ctx, "nextStepChainSource", JSValue::null());
                fallback_plan.set_property(ctx, "nextStepChainLimit", JSValue::int(0));
                fallback_plan.set_property(ctx, "nextStepChainCount", JSValue::int(0));
                fallback_plan.set_property(ctx, "nextStepChainTruncated", JSValue::bool(false));
                let next_step_chain = ffi::JS_NewArray(ctx);
                fallback_plan.set_property(ctx, "nextStepChain", JSValue(next_step_chain));
                fallback_plan.set_property(ctx, "activeStep", JSValue::null());
                fallback_plan.set_property(ctx, "activeStepSource", JSValue::null());
                fallback_plan.set_property(ctx, "activeStepAllowed", JSValue::null());
                fallback_plan.set_property(ctx, "activeStepBlockedBy", JSValue::null());
                fallback_plan.set_property(ctx, "activeStepBranch", JSValue::null());
                fallback_plan.set_property(ctx, "activeStepReason", JSValue::null());
                fallback_plan.set_property(ctx, "activeStepPreferredPath", JSValue::null());
                fallback_plan.set_property(ctx, "activeStepActionKey", JSValue::null());
                fallback_plan.set_property(ctx, "activeStepCommandGroup", JSValue::null());
                fallback_plan.set_property(ctx, "activeStepId", JSValue::null());
                fallback_plan.set_property(ctx, "activeStepCommand", JSValue::null());
                fallback_plan.set_property(ctx, "activeStepPhase", JSValue::null());
                fallback_plan.set_property(ctx, "activeStepReadyToRun", JSValue::null());
                fallback_plan.set_property(ctx, "activeStepRequiresFallback", JSValue::null());
                fallback_plan.set_property(ctx, "activeStepKind", JSValue::null());
                fallback_plan.set_property(ctx, "activeStepCommandJsonEligible", JSValue::null());
                fallback_plan.set_property(ctx, "activeStepCommandJsonTemplateEligible", JSValue::null());
                fallback_plan.set_property(ctx, "activeStepCommandJsonTemplate", JSValue::null());
                fallback_plan.set_property(ctx, "activeStepCommandJsonTemplateCommand", JSValue::null());
                fallback_plan.set_property(ctx, "activeStepCommandJsonTemplateKind", JSValue::null());
                fallback_plan.set_property(ctx, "activeStepRetryable", JSValue::null());
                fallback_plan.set_property(ctx, "activeStepMaxSuggestedRetries", JSValue::null());
                fallback_plan.set_property(ctx, "activeStepRetryDelayHintMs", JSValue::null());
                fallback_plan.set_property(ctx, "activeStepTimeoutHintMs", JSValue::null());
                fallback_plan.set_property(ctx, "activeStepTimeoutAction", JSValue::null());
                fallback_plan.set_property(ctx, "activeStepErrorCode", JSValue::null());
                fallback_plan.set_property(ctx, "activeStepTimeoutErrorCode", JSValue::null());
                fallback_plan.set_property(ctx, "activeStepRisk", JSValue::null());
                fallback_plan.set_property(ctx, "activeStepPlaceholderCount", JSValue::null());
                fallback_plan.set_property(ctx, "activeStepPlaceholders", JSValue::null());
                fallback_plan.set_property(ctx, "activeStepCliArgs", JSValue::null());
            }
        }
        fallback_plan.set_property(ctx, "steps", JSValue(fallback_steps));
        result.set_property(ctx, "hasFallbackPlan", JSValue::bool(true));
        result.set_property(ctx, "fallbackPlan", fallback_plan.dup(ctx));
        result.set_property(ctx, "nextStep", fallback_plan.get_property(ctx, "nextStep"));
        result.set_property(ctx, "nextStepId", fallback_plan.get_property(ctx, "nextStepId"));
        result.set_property(ctx, "nextStepSource", fallback_plan.get_property(ctx, "nextStepSource"));
        result.set_property(
            ctx,
            "nextStepActionKey",
            fallback_plan.get_property(ctx, "nextStepActionKey"),
        );
        result.set_property(
            ctx,
            "nextStepCommandGroup",
            fallback_plan.get_property(ctx, "nextStepCommandGroup"),
        );
        result.set_property(
            ctx,
            "nextStepAllowed",
            fallback_plan.get_property(ctx, "nextStepAllowed"),
        );
        result.set_property(
            ctx,
            "nextStepBlockedBy",
            fallback_plan.get_property(ctx, "nextStepBlockedBy"),
        );
        result.set_property(ctx, "nextStepReason", fallback_plan.get_property(ctx, "nextStepReason"));
        result.set_property(
            ctx,
            "nextStepPreferredPath",
            fallback_plan.get_property(ctx, "nextStepPreferredPath"),
        );
        result.set_property(ctx, "nextStepBranch", fallback_plan.get_property(ctx, "nextStepBranch"));
        result.set_property(
            ctx,
            "nextStepCommand",
            fallback_plan.get_property(ctx, "nextStepCommand"),
        );
        result.set_property(ctx, "nextStepPhase", fallback_plan.get_property(ctx, "nextStepPhase"));
        result.set_property(
            ctx,
            "nextStepCommandJsonEligible",
            fallback_plan.get_property(ctx, "nextStepCommandJsonEligible"),
        );
        result.set_property(
            ctx,
            "nextStepCommandJsonTemplateEligible",
            fallback_plan.get_property(ctx, "nextStepCommandJsonTemplateEligible"),
        );
        result.set_property(
            ctx,
            "nextStepCommandJsonTemplate",
            fallback_plan.get_property(ctx, "nextStepCommandJsonTemplate"),
        );
        result.set_property(
            ctx,
            "nextStepCommandJsonTemplateCommand",
            fallback_plan.get_property(ctx, "nextStepCommandJsonTemplateCommand"),
        );
        result.set_property(
            ctx,
            "nextStepCommandJsonTemplateKind",
            fallback_plan.get_property(ctx, "nextStepCommandJsonTemplateKind"),
        );
        result.set_property(ctx, "nextStepKind", fallback_plan.get_property(ctx, "nextStepKind"));
        result.set_property(
            ctx,
            "nextStepRetryable",
            fallback_plan.get_property(ctx, "nextStepRetryable"),
        );
        result.set_property(
            ctx,
            "nextStepMaxSuggestedRetries",
            fallback_plan.get_property(ctx, "nextStepMaxSuggestedRetries"),
        );
        result.set_property(
            ctx,
            "nextStepRetryDelayHintMs",
            fallback_plan.get_property(ctx, "nextStepRetryDelayHintMs"),
        );
        result.set_property(
            ctx,
            "nextStepTimeoutHintMs",
            fallback_plan.get_property(ctx, "nextStepTimeoutHintMs"),
        );
        result.set_property(
            ctx,
            "nextStepTimeoutAction",
            fallback_plan.get_property(ctx, "nextStepTimeoutAction"),
        );
        result.set_property(
            ctx,
            "nextStepErrorCode",
            fallback_plan.get_property(ctx, "nextStepErrorCode"),
        );
        result.set_property(
            ctx,
            "nextStepTimeoutErrorCode",
            fallback_plan.get_property(ctx, "nextStepTimeoutErrorCode"),
        );
        result.set_property(ctx, "nextStepRisk", fallback_plan.get_property(ctx, "nextStepRisk"));
        result.set_property(
            ctx,
            "nextStepPlaceholderCount",
            fallback_plan.get_property(ctx, "nextStepPlaceholderCount"),
        );
        result.set_property(
            ctx,
            "nextStepPlaceholders",
            fallback_plan.get_property(ctx, "nextStepPlaceholders"),
        );
        result.set_property(
            ctx,
            "nextStepCliArgs",
            fallback_plan.get_property(ctx, "nextStepCliArgs"),
        );
        result.set_property(
            ctx,
            "nextStepReadyToRun",
            fallback_plan.get_property(ctx, "activeStepReadyToRun"),
        );
        result.set_property(
            ctx,
            "nextStepRequiresFallback",
            fallback_plan.get_property(ctx, "activeStepRequiresFallback"),
        );
        result.set_property(
            ctx,
            "nextStepChainSource",
            fallback_plan.get_property(ctx, "nextStepChainSource"),
        );
        result.set_property(
            ctx,
            "nextStepChainLimit",
            fallback_plan.get_property(ctx, "nextStepChainLimit"),
        );
        result.set_property(
            ctx,
            "nextStepChainCount",
            fallback_plan.get_property(ctx, "nextStepChainCount"),
        );
        result.set_property(
            ctx,
            "nextStepChainTruncated",
            fallback_plan.get_property(ctx, "nextStepChainTruncated"),
        );
        result.set_property(ctx, "nextStepChain", fallback_plan.get_property(ctx, "nextStepChain"));
        result.set_property(ctx, "activeStep", fallback_plan.get_property(ctx, "activeStep"));
        result.set_property(
            ctx,
            "activeStepSource",
            fallback_plan.get_property(ctx, "activeStepSource"),
        );
        result.set_property(
            ctx,
            "activeStepAllowed",
            fallback_plan.get_property(ctx, "activeStepAllowed"),
        );
        result.set_property(
            ctx,
            "activeStepBlockedBy",
            fallback_plan.get_property(ctx, "activeStepBlockedBy"),
        );
        result.set_property(
            ctx,
            "activeStepReason",
            fallback_plan.get_property(ctx, "activeStepReason"),
        );
        result.set_property(
            ctx,
            "activeStepPreferredPath",
            fallback_plan.get_property(ctx, "activeStepPreferredPath"),
        );
        result.set_property(
            ctx,
            "activeStepBranch",
            fallback_plan.get_property(ctx, "activeStepBranch"),
        );
        result.set_property(
            ctx,
            "activeStepActionKey",
            fallback_plan.get_property(ctx, "activeStepActionKey"),
        );
        result.set_property(
            ctx,
            "activeStepCommandGroup",
            fallback_plan.get_property(ctx, "activeStepCommandGroup"),
        );
        result.set_property(ctx, "activeStepId", fallback_plan.get_property(ctx, "activeStepId"));
        result.set_property(
            ctx,
            "activeStepCommand",
            fallback_plan.get_property(ctx, "activeStepCommand"),
        );
        result.set_property(
            ctx,
            "activeStepPhase",
            fallback_plan.get_property(ctx, "activeStepPhase"),
        );
        result.set_property(
            ctx,
            "activeStepReadyToRun",
            fallback_plan.get_property(ctx, "activeStepReadyToRun"),
        );
        result.set_property(
            ctx,
            "activeStepRequiresFallback",
            fallback_plan.get_property(ctx, "activeStepRequiresFallback"),
        );
        result.set_property(ctx, "activeStepKind", fallback_plan.get_property(ctx, "activeStepKind"));
        result.set_property(
            ctx,
            "activeStepCommandJsonEligible",
            fallback_plan.get_property(ctx, "activeStepCommandJsonEligible"),
        );
        result.set_property(
            ctx,
            "activeStepCommandJsonTemplateEligible",
            fallback_plan.get_property(ctx, "activeStepCommandJsonTemplateEligible"),
        );
        result.set_property(
            ctx,
            "activeStepCommandJsonTemplate",
            fallback_plan.get_property(ctx, "activeStepCommandJsonTemplate"),
        );
        result.set_property(
            ctx,
            "activeStepCommandJsonTemplateCommand",
            fallback_plan.get_property(ctx, "activeStepCommandJsonTemplateCommand"),
        );
        result.set_property(
            ctx,
            "activeStepCommandJsonTemplateKind",
            fallback_plan.get_property(ctx, "activeStepCommandJsonTemplateKind"),
        );
        result.set_property(
            ctx,
            "activeStepRetryable",
            fallback_plan.get_property(ctx, "activeStepRetryable"),
        );
        result.set_property(
            ctx,
            "activeStepMaxSuggestedRetries",
            fallback_plan.get_property(ctx, "activeStepMaxSuggestedRetries"),
        );
        result.set_property(
            ctx,
            "activeStepRetryDelayHintMs",
            fallback_plan.get_property(ctx, "activeStepRetryDelayHintMs"),
        );
        result.set_property(
            ctx,
            "activeStepTimeoutHintMs",
            fallback_plan.get_property(ctx, "activeStepTimeoutHintMs"),
        );
        result.set_property(
            ctx,
            "activeStepTimeoutAction",
            fallback_plan.get_property(ctx, "activeStepTimeoutAction"),
        );
        result.set_property(
            ctx,
            "activeStepErrorCode",
            fallback_plan.get_property(ctx, "activeStepErrorCode"),
        );
        result.set_property(
            ctx,
            "activeStepTimeoutErrorCode",
            fallback_plan.get_property(ctx, "activeStepTimeoutErrorCode"),
        );
        result.set_property(ctx, "activeStepRisk", fallback_plan.get_property(ctx, "activeStepRisk"));
        result.set_property(
            ctx,
            "activeStepPlaceholderCount",
            fallback_plan.get_property(ctx, "activeStepPlaceholderCount"),
        );
        result.set_property(
            ctx,
            "activeStepPlaceholders",
            fallback_plan.get_property(ctx, "activeStepPlaceholders"),
        );
        result.set_property(
            ctx,
            "activeStepCliArgs",
            fallback_plan.get_property(ctx, "activeStepCliArgs"),
        );
    } else {
        result.set_property(ctx, "hasFallbackPlan", JSValue::bool(false));
        result.set_property(ctx, "fallbackPlan", JSValue::null());
    }

    let action_branches = ffi::JS_NewArray(ctx);
    for (entry_index, action_index) in ordered_action_indices.iter().enumerate() {
        let action = &recommended_actions_vec[*action_index];
        let templates = hook_action_command_templates(&action.action_key, coexistence_mode);
        let command_json_templates = templates
            .iter()
            .map(|template| hook_command_json_template_to_js(ctx, template))
            .collect::<Vec<_>>();
        let command_json_eligible_template_count = command_json_templates
            .iter()
            .filter(|entry| {
                JSValue(**entry)
                    .get_property(ctx, "commandJsonEligible")
                    .to_bool()
                    .unwrap_or(false)
            })
            .count();
        let prerequisites = hook_action_prerequisites(&action.action_key)
            .iter()
            .map(|item| (*item).to_string())
            .collect::<Vec<_>>();
        let blocked_prerequisites = prerequisites
            .iter()
            .filter(|required| {
                recommended_actions_vec
                    .iter()
                    .find(|candidate| candidate.action_key == required.as_str())
                    .map(|candidate| !candidate.allowed)
                    .unwrap_or(false)
            })
            .cloned()
            .collect::<Vec<_>>();
        let branch = JSValue(ffi::JS_NewObject(ctx));
        let command_json_templates_array = ffi::JS_NewArray(ctx);
        for (template_index, template) in command_json_templates.iter().enumerate() {
            ffi::JS_SetPropertyUint32(ctx, command_json_templates_array, template_index as u32, *template);
        }
        branch.set_property(ctx, "actionKey", JSValue::string(ctx, &action.action_key));
        branch.set_property(ctx, "commandGroup", JSValue::string(ctx, &action.command_group));
        branch.set_property(ctx, "allowed", JSValue::bool(action.allowed));
        branch.set_property(ctx, "branch", JSValue::string(ctx, hook_action_branch(action)));
        branch.set_property(ctx, "blockedBy", JSValue::string(ctx, hook_action_blocked_by(action)));
        branch.set_property(
            ctx,
            "executionRank",
            JSValue::int(hook_action_mode_rank(command_mode, &action.action_key) as i32),
        );
        branch.set_property(ctx, "executionIndex", JSValue::int(entry_index as i32));
        branch.set_property(ctx, "priority", JSValue::int(action.priority as i32));
        branch.set_property(ctx, "recommendation", JSValue::string(ctx, &action.recommendation));
        branch.set_property(
            ctx,
            "selectedAsNext",
            JSValue::bool(selected_action_index == Some(*action_index)),
        );
        branch.set_property(ctx, "prerequisiteCount", JSValue::int(prerequisites.len() as i32));
        set_string_array_property(ctx, branch.raw(), "prerequisiteActionKeys", &prerequisites);
        branch.set_property(
            ctx,
            "blockedPrerequisiteCount",
            JSValue::int(blocked_prerequisites.len() as i32),
        );
        set_string_array_property(
            ctx,
            branch.raw(),
            "blockedPrerequisiteActionKeys",
            &blocked_prerequisites,
        );
        branch.set_property(
            ctx,
            "readyToRun",
            JSValue::bool(hook_action_ready_to_run(&recommended_actions_vec, action)),
        );
        branch.set_property(ctx, "templateCount", JSValue::int(templates.len() as i32));
        set_string_array_property(ctx, branch.raw(), "templates", &templates);
        branch.set_property(
            ctx,
            "commandJsonTemplateCount",
            JSValue::int(command_json_templates.len() as i32),
        );
        branch.set_property(
            ctx,
            "commandJsonEligibleTemplateCount",
            JSValue::int(command_json_eligible_template_count as i32),
        );
        branch.set_property(ctx, "commandJsonTemplates", JSValue(command_json_templates_array));
        ffi::JS_SetPropertyUint32(ctx, action_branches, entry_index as u32, branch.raw());
    }
    result.set_property(ctx, "actionBranches", JSValue(action_branches));

    let recommended_actions = ffi::JS_NewArray(ctx);
    for (index, action) in recommended_actions_vec.iter().enumerate() {
        ffi::JS_SetPropertyUint32(
            ctx,
            recommended_actions,
            index as u32,
            hook_recommended_action_to_js(ctx, action).raw(),
        );
    }
    result.set_property(ctx, "recommendedActions", JSValue(recommended_actions));

    let backends = ffi::JS_NewArray(ctx);
    for (index, backend) in report.backends.iter().enumerate() {
        let item = JSValue(ffi::JS_NewObject(ctx));
        item.set_property(ctx, "id", JSValue::string(ctx, &backend.id));
        item.set_property(ctx, "name", JSValue::string(ctx, &backend.display_name));
        item.set_property(ctx, "displayName", JSValue::string(ctx, &backend.display_name));
        item.set_property(ctx, "loaded", JSValue::bool(!backend.loaded_images.is_empty()));
        item.set_property(
            ctx,
            "loadedImageCount",
            JSValue::int(backend.loaded_images.len() as i32),
        );
        item.set_property(
            ctx,
            "presentOnFilesystem",
            JSValue::bool(!backend.filesystem_paths.is_empty()),
        );
        item.set_property(
            ctx,
            "filesystemOnly",
            JSValue::bool(backend.loaded_images.is_empty() && !backend.filesystem_paths.is_empty()),
        );
        item.set_property(
            ctx,
            "filesystemPathCount",
            JSValue::int(backend.filesystem_paths.len() as i32),
        );
        set_string_array_property(ctx, item.raw(), "loadedImages", &backend.loaded_images);
        set_string_array_property(ctx, item.raw(), "filesystemPaths", &backend.filesystem_paths);
        ffi::JS_SetPropertyUint32(ctx, backends, index as u32, item.raw());
    }
    result.set_property(ctx, "backends", JSValue(backends));
    result.set_property(
        ctx,
        "backendMatrix",
        JSValue(hook_single_process_backend_matrix_to_js(ctx, report)),
    );

    result.raw()
}

unsafe fn native_symbol_to_js(ctx: *mut ffi::JSContext, symbol: &native_api::NativeSymbol) -> ffi::JSValue {
    let result = JSValue(ffi::JS_NewObject(ctx));
    result.set_property(ctx, "moduleName", JSValue::string(ctx, &symbol.module_name));
    result.set_property(ctx, "moduleBase", create_native_pointer(ctx, symbol.module_base as u64));
    result.set_property(ctx, "name", JSValue::string(ctx, &symbol.symbol_name));
    result.set_property(ctx, "address", create_native_pointer(ctx, symbol.address as u64));
    result.set_property(ctx, "offset", JSValue(ffi::JS_NewBigUint64(ctx, symbol.offset as u64)));
    result.raw()
}

unsafe fn symbol_info_to_js(ctx: *mut ffi::JSContext, symbol: &native_api::SymbolInfo) -> ffi::JSValue {
    let object = JSValue(ffi::JS_NewObject(ctx));
    object.set_property(ctx, "moduleName", JSValue::string(ctx, &symbol.module_name));
    object.set_property(ctx, "moduleBase", create_native_pointer(ctx, symbol.module_base as u64));
    object.set_property(ctx, "offset", JSValue(ffi::JS_NewBigUint64(ctx, symbol.offset as u64)));

    match &symbol.symbol_name {
        Some(symbol_name) => object.set_property(ctx, "name", JSValue::string(ctx, symbol_name)),
        None => object.set_property(ctx, "name", JSValue::null()),
    };

    match symbol.symbol_address {
        Some(symbol_address) => object.set_property(ctx, "address", create_native_pointer(ctx, symbol_address as u64)),
        None => object.set_property(ctx, "address", JSValue::null()),
    };

    object.raw()
}

unsafe fn image_info_to_js(ctx: *mut ffi::JSContext, image: &native_api::ImageInfo) -> ffi::JSValue {
    let result = JSValue(ffi::JS_NewObject(ctx));
    let basename = Path::new(&image.name)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(&image.name);
    result.set_property(ctx, "name", JSValue::string(ctx, basename));
    result.set_property(ctx, "path", JSValue::string(ctx, &image.name));
    result.set_property(ctx, "base", create_native_pointer(ctx, image.base as u64));
    result.set_property(
        ctx,
        "slide",
        JSValue(js_i64_to_js_number_or_bigint(ctx, image.slide as i64)),
    );
    result.set_property(
        ctx,
        "size",
        JSValue(js_u64_to_js_number_or_bigint(ctx, image.size as u64)),
    );
    result.raw()
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

    Err(crate::util::js_throw_type_error(ctx, usage))
}

unsafe fn image_import_to_js(ctx: *mut ffi::JSContext, import: &native_api::ImageImport) -> ffi::JSValue {
    let result = JSValue(ffi::JS_NewObject(ctx));
    result.set_property(ctx, "moduleName", JSValue::string(ctx, &import.module_name));
    result.set_property(ctx, "moduleBase", create_native_pointer(ctx, import.module_base as u64));
    result.set_property(ctx, "name", JSValue::string(ctx, &import.symbol_name));
    result.set_property(ctx, "dylibOrdinal", JSValue::int(import.dylib_ordinal as i32));
    match &import.dylib_name {
        Some(name) => result.set_property(ctx, "dylibName", JSValue::string(ctx, name)),
        None => result.set_property(ctx, "dylibName", JSValue::null()),
    };
    result.set_property(ctx, "weakImport", JSValue::bool(import.weak_import));
    result.raw()
}

unsafe fn image_dependency_to_js(ctx: *mut ffi::JSContext, dependency: &native_api::ImageDependency) -> ffi::JSValue {
    let result = JSValue(ffi::JS_NewObject(ctx));
    result.set_property(ctx, "moduleName", JSValue::string(ctx, &dependency.module_name));
    result.set_property(
        ctx,
        "moduleBase",
        create_native_pointer(ctx, dependency.module_base as u64),
    );
    result.set_property(ctx, "ordinal", JSValue::int(dependency.ordinal as i32));
    result.set_property(ctx, "path", JSValue::string(ctx, &dependency.path));
    result.set_property(ctx, "kind", JSValue::string(ctx, &dependency.kind));
    result.set_property(
        ctx,
        "currentVersion",
        JSValue(ffi::qjs_new_uint32(ctx, dependency.current_version)),
    );
    result.set_property(
        ctx,
        "compatibilityVersion",
        JSValue(ffi::qjs_new_uint32(ctx, dependency.compatibility_version)),
    );
    result.set_property(
        ctx,
        "timestamp",
        JSValue(ffi::qjs_new_uint32(ctx, dependency.timestamp)),
    );
    result.raw()
}

unsafe fn image_encryption_info_to_js(
    ctx: *mut ffi::JSContext,
    encryption_info: &native_api::ImageEncryptionInfo,
) -> ffi::JSValue {
    let result = JSValue(ffi::JS_NewObject(ctx));
    result.set_property(ctx, "moduleName", JSValue::string(ctx, &encryption_info.module_name));
    result.set_property(
        ctx,
        "moduleBase",
        create_native_pointer(ctx, encryption_info.module_base as u64),
    );
    result.set_property(
        ctx,
        "cryptoff",
        JSValue(ffi::qjs_new_uint32(ctx, encryption_info.cryptoff)),
    );
    result.set_property(
        ctx,
        "cryptsize",
        JSValue(ffi::qjs_new_uint32(ctx, encryption_info.cryptsize)),
    );
    result.set_property(
        ctx,
        "cryptid",
        JSValue(ffi::qjs_new_uint32(ctx, encryption_info.cryptid)),
    );
    result.raw()
}

unsafe fn image_entry_point_to_js(ctx: *mut ffi::JSContext, entry_point: &native_api::ImageEntryPoint) -> ffi::JSValue {
    let result = JSValue(ffi::JS_NewObject(ctx));
    result.set_property(ctx, "moduleName", JSValue::string(ctx, &entry_point.module_name));
    result.set_property(
        ctx,
        "moduleBase",
        create_native_pointer(ctx, entry_point.module_base as u64),
    );
    result.set_property(
        ctx,
        "entryoff",
        JSValue(ffi::JS_NewBigUint64(ctx, entry_point.entryoff)),
    );
    result.set_property(
        ctx,
        "stacksize",
        JSValue(ffi::JS_NewBigUint64(ctx, entry_point.stacksize)),
    );
    result.raw()
}

unsafe fn image_dyld_info_to_js(ctx: *mut ffi::JSContext, dyld_info: &native_api::ImageDyldInfo) -> ffi::JSValue {
    let result = JSValue(ffi::JS_NewObject(ctx));
    result.set_property(ctx, "moduleName", JSValue::string(ctx, &dyld_info.module_name));
    result.set_property(
        ctx,
        "moduleBase",
        create_native_pointer(ctx, dyld_info.module_base as u64),
    );
    result.set_property(ctx, "command", JSValue(ffi::qjs_new_uint32(ctx, dyld_info.command)));
    result.set_property(ctx, "commandName", JSValue::string(ctx, &dyld_info.command_name));
    result.set_property(
        ctx,
        "rebaseOff",
        JSValue(ffi::qjs_new_uint32(ctx, dyld_info.rebase_off)),
    );
    result.set_property(
        ctx,
        "rebaseSize",
        JSValue(ffi::qjs_new_uint32(ctx, dyld_info.rebase_size)),
    );
    result.set_property(ctx, "bindOff", JSValue(ffi::qjs_new_uint32(ctx, dyld_info.bind_off)));
    result.set_property(ctx, "bindSize", JSValue(ffi::qjs_new_uint32(ctx, dyld_info.bind_size)));
    result.set_property(
        ctx,
        "weakBindOff",
        JSValue(ffi::qjs_new_uint32(ctx, dyld_info.weak_bind_off)),
    );
    result.set_property(
        ctx,
        "weakBindSize",
        JSValue(ffi::qjs_new_uint32(ctx, dyld_info.weak_bind_size)),
    );
    result.set_property(
        ctx,
        "lazyBindOff",
        JSValue(ffi::qjs_new_uint32(ctx, dyld_info.lazy_bind_off)),
    );
    result.set_property(
        ctx,
        "lazyBindSize",
        JSValue(ffi::qjs_new_uint32(ctx, dyld_info.lazy_bind_size)),
    );
    result.set_property(
        ctx,
        "exportOff",
        JSValue(ffi::qjs_new_uint32(ctx, dyld_info.export_off)),
    );
    result.set_property(
        ctx,
        "exportSize",
        JSValue(ffi::qjs_new_uint32(ctx, dyld_info.export_size)),
    );
    result.raw()
}

unsafe fn image_source_version_to_js(
    ctx: *mut ffi::JSContext,
    source_version: &native_api::ImageSourceVersion,
) -> ffi::JSValue {
    let result = JSValue(ffi::JS_NewObject(ctx));
    result.set_property(ctx, "moduleName", JSValue::string(ctx, &source_version.module_name));
    result.set_property(
        ctx,
        "moduleBase",
        create_native_pointer(ctx, source_version.module_base as u64),
    );
    result.set_property(ctx, "version", JSValue::string(ctx, &source_version.version));
    result.raw()
}

unsafe fn image_build_version_to_js(
    ctx: *mut ffi::JSContext,
    build_version: &native_api::ImageBuildVersion,
) -> ffi::JSValue {
    let result = JSValue(ffi::JS_NewObject(ctx));
    result.set_property(ctx, "moduleName", JSValue::string(ctx, &build_version.module_name));
    result.set_property(
        ctx,
        "moduleBase",
        create_native_pointer(ctx, build_version.module_base as u64),
    );
    result.set_property(ctx, "platform", JSValue::string(ctx, &build_version.platform));
    result.set_property(ctx, "minOs", JSValue::string(ctx, &build_version.min_os));
    result.set_property(ctx, "sdk", JSValue::string(ctx, &build_version.sdk));

    let tools = ffi::JS_NewArray(ctx);
    for (index, tool) in build_version.tools.iter().enumerate() {
        let item = JSValue(ffi::JS_NewObject(ctx));
        item.set_property(ctx, "tool", JSValue::string(ctx, &tool.tool));
        item.set_property(ctx, "version", JSValue::string(ctx, &tool.version));
        ffi::JS_SetPropertyUint32(ctx, tools, index as u32, item.raw());
    }
    result.set_property(ctx, "tools", JSValue(tools));
    result.raw()
}

unsafe fn image_dylinker_to_js(ctx: *mut ffi::JSContext, dylinker: &native_api::ImageDylinker) -> ffi::JSValue {
    let result = JSValue(ffi::JS_NewObject(ctx));
    result.set_property(ctx, "moduleName", JSValue::string(ctx, &dylinker.module_name));
    result.set_property(
        ctx,
        "moduleBase",
        create_native_pointer(ctx, dylinker.module_base as u64),
    );
    result.set_property(ctx, "path", JSValue::string(ctx, &dylinker.path));
    result.set_property(ctx, "kind", JSValue::string(ctx, &dylinker.kind));
    result.raw()
}

unsafe fn image_install_name_to_js(
    ctx: *mut ffi::JSContext,
    install_name: &native_api::ImageInstallName,
) -> ffi::JSValue {
    let result = JSValue(ffi::JS_NewObject(ctx));
    result.set_property(ctx, "moduleName", JSValue::string(ctx, &install_name.module_name));
    result.set_property(
        ctx,
        "moduleBase",
        create_native_pointer(ctx, install_name.module_base as u64),
    );
    result.set_property(ctx, "path", JSValue::string(ctx, &install_name.path));
    result.set_property(
        ctx,
        "currentVersion",
        JSValue(ffi::qjs_new_uint32(ctx, install_name.current_version)),
    );
    result.set_property(
        ctx,
        "compatibilityVersion",
        JSValue(ffi::qjs_new_uint32(ctx, install_name.compatibility_version)),
    );
    result.set_property(
        ctx,
        "timestamp",
        JSValue(ffi::qjs_new_uint32(ctx, install_name.timestamp)),
    );
    result.raw()
}

unsafe fn image_linkedit_info_to_js(
    ctx: *mut ffi::JSContext,
    linkedit: &native_api::ImageLinkeditInfo,
) -> ffi::JSValue {
    let result = JSValue(ffi::JS_NewObject(ctx));
    result.set_property(ctx, "moduleName", JSValue::string(ctx, &linkedit.module_name));
    result.set_property(
        ctx,
        "moduleBase",
        create_native_pointer(ctx, linkedit.module_base as u64),
    );
    result.set_property(ctx, "vmaddr", create_native_pointer(ctx, linkedit.vmaddr));
    result.set_property(ctx, "vmsize", JSValue(ffi::JS_NewBigUint64(ctx, linkedit.vmsize)));
    result.set_property(ctx, "fileoff", JSValue(ffi::JS_NewBigUint64(ctx, linkedit.fileoff)));
    result.set_property(ctx, "filesize", JSValue(ffi::JS_NewBigUint64(ctx, linkedit.filesize)));
    result.set_property(
        ctx,
        "computedBase",
        create_native_pointer(ctx, linkedit.computed_base as u64),
    );
    match linkedit.symoff {
        Some(value) => result.set_property(ctx, "symoff", JSValue(ffi::qjs_new_uint32(ctx, value))),
        None => result.set_property(ctx, "symoff", JSValue::null()),
    };
    match linkedit.nsyms {
        Some(value) => result.set_property(ctx, "nsyms", JSValue(ffi::qjs_new_uint32(ctx, value))),
        None => result.set_property(ctx, "nsyms", JSValue::null()),
    };
    match linkedit.stroff {
        Some(value) => result.set_property(ctx, "stroff", JSValue(ffi::qjs_new_uint32(ctx, value))),
        None => result.set_property(ctx, "stroff", JSValue::null()),
    };
    match linkedit.strsize {
        Some(value) => result.set_property(ctx, "strsize", JSValue(ffi::qjs_new_uint32(ctx, value))),
        None => result.set_property(ctx, "strsize", JSValue::null()),
    };
    match linkedit.indirectsymoff {
        Some(value) => result.set_property(ctx, "indirectsymoff", JSValue(ffi::qjs_new_uint32(ctx, value))),
        None => result.set_property(ctx, "indirectsymoff", JSValue::null()),
    };
    match linkedit.nindirectsyms {
        Some(value) => result.set_property(ctx, "nindirectsyms", JSValue(ffi::qjs_new_uint32(ctx, value))),
        None => result.set_property(ctx, "nindirectsyms", JSValue::null()),
    };
    result.raw()
}

unsafe fn image_function_start_to_js(
    ctx: *mut ffi::JSContext,
    function_start: &native_api::ImageFunctionStart,
) -> ffi::JSValue {
    let result = JSValue(ffi::JS_NewObject(ctx));
    result.set_property(ctx, "offset", JSValue(ffi::JS_NewBigUint64(ctx, function_start.offset)));
    result.set_property(
        ctx,
        "address",
        create_native_pointer(ctx, function_start.address as u64),
    );
    result.raw()
}

unsafe fn image_function_starts_to_js(
    ctx: *mut ffi::JSContext,
    function_starts: &native_api::ImageFunctionStarts,
) -> ffi::JSValue {
    let result = JSValue(ffi::JS_NewObject(ctx));
    result.set_property(ctx, "moduleName", JSValue::string(ctx, &function_starts.module_name));
    result.set_property(
        ctx,
        "moduleBase",
        create_native_pointer(ctx, function_starts.module_base as u64),
    );
    result.set_property(
        ctx,
        "dataoff",
        JSValue(ffi::qjs_new_uint32(ctx, function_starts.dataoff)),
    );
    result.set_property(
        ctx,
        "datasize",
        JSValue(ffi::qjs_new_uint32(ctx, function_starts.datasize)),
    );
    result.set_property(
        ctx,
        "linkeditBase",
        create_native_pointer(ctx, function_starts.linkedit_base as u64),
    );
    result.set_property(
        ctx,
        "dataAddress",
        create_native_pointer(ctx, function_starts.data_address as u64),
    );
    let starts = ffi::JS_NewArray(ctx);
    for (index, item) in function_starts.starts.iter().enumerate() {
        ffi::JS_SetPropertyUint32(ctx, starts, index as u32, image_function_start_to_js(ctx, item));
    }
    result.set_property(ctx, "starts", JSValue(starts));
    result.raw()
}

unsafe fn image_code_signature_to_js(
    ctx: *mut ffi::JSContext,
    code_signature: &native_api::ImageCodeSignature,
) -> ffi::JSValue {
    let result = JSValue(ffi::JS_NewObject(ctx));
    result.set_property(ctx, "moduleName", JSValue::string(ctx, &code_signature.module_name));
    result.set_property(
        ctx,
        "moduleBase",
        create_native_pointer(ctx, code_signature.module_base as u64),
    );
    result.set_property(
        ctx,
        "dataoff",
        JSValue(ffi::qjs_new_uint32(ctx, code_signature.dataoff)),
    );
    result.set_property(
        ctx,
        "datasize",
        JSValue(ffi::qjs_new_uint32(ctx, code_signature.datasize)),
    );
    result.set_property(
        ctx,
        "linkeditBase",
        create_native_pointer(ctx, code_signature.linkedit_base as u64),
    );
    result.set_property(
        ctx,
        "dataAddress",
        create_native_pointer(ctx, code_signature.data_address as u64),
    );
    match code_signature.magic {
        Some(value) => result.set_property(ctx, "magic", JSValue(ffi::qjs_new_uint32(ctx, value))),
        None => result.set_property(ctx, "magic", JSValue::null()),
    };
    match &code_signature.magic_name {
        Some(value) => result.set_property(ctx, "magicName", JSValue::string(ctx, value)),
        None => result.set_property(ctx, "magicName", JSValue::null()),
    };
    match code_signature.length {
        Some(value) => result.set_property(ctx, "length", JSValue(ffi::qjs_new_uint32(ctx, value))),
        None => result.set_property(ctx, "length", JSValue::null()),
    };
    match code_signature.count {
        Some(value) => result.set_property(ctx, "count", JSValue(ffi::qjs_new_uint32(ctx, value))),
        None => result.set_property(ctx, "count", JSValue::null()),
    };
    result.raw()
}

unsafe fn image_data_in_code_entry_to_js(
    ctx: *mut ffi::JSContext,
    entry: &native_api::ImageDataInCodeEntry,
) -> ffi::JSValue {
    let result = JSValue(ffi::JS_NewObject(ctx));
    result.set_property(ctx, "offset", JSValue(ffi::qjs_new_uint32(ctx, entry.offset)));
    result.set_property(ctx, "address", create_native_pointer(ctx, entry.address as u64));
    result.set_property(ctx, "length", JSValue::int(entry.length as i32));
    result.set_property(ctx, "kind", JSValue::int(entry.kind as i32));
    result.set_property(ctx, "kindName", JSValue::string(ctx, &entry.kind_name));
    result.raw()
}

unsafe fn image_data_in_code_to_js(
    ctx: *mut ffi::JSContext,
    data_in_code: &native_api::ImageDataInCode,
) -> ffi::JSValue {
    let result = JSValue(ffi::JS_NewObject(ctx));
    result.set_property(ctx, "moduleName", JSValue::string(ctx, &data_in_code.module_name));
    result.set_property(
        ctx,
        "moduleBase",
        create_native_pointer(ctx, data_in_code.module_base as u64),
    );
    result.set_property(ctx, "dataoff", JSValue(ffi::qjs_new_uint32(ctx, data_in_code.dataoff)));
    result.set_property(
        ctx,
        "datasize",
        JSValue(ffi::qjs_new_uint32(ctx, data_in_code.datasize)),
    );
    result.set_property(
        ctx,
        "linkeditBase",
        create_native_pointer(ctx, data_in_code.linkedit_base as u64),
    );
    result.set_property(
        ctx,
        "dataAddress",
        create_native_pointer(ctx, data_in_code.data_address as u64),
    );
    let entries = ffi::JS_NewArray(ctx);
    for (index, item) in data_in_code.entries.iter().enumerate() {
        ffi::JS_SetPropertyUint32(ctx, entries, index as u32, image_data_in_code_entry_to_js(ctx, item));
    }
    result.set_property(ctx, "entries", JSValue(entries));
    result.raw()
}

unsafe fn image_exports_trie_entry_to_js(
    ctx: *mut ffi::JSContext,
    entry: &native_api::ImageExportsTrieEntry,
) -> ffi::JSValue {
    let result = JSValue(ffi::JS_NewObject(ctx));
    result.set_property(ctx, "name", JSValue::string(ctx, &entry.name));
    result.set_property(ctx, "flags", JSValue(ffi::JS_NewBigUint64(ctx, entry.flags)));
    result.set_property(ctx, "kind", JSValue::string(ctx, &entry.kind));
    match entry.address {
        Some(value) => result.set_property(ctx, "address", create_native_pointer(ctx, value as u64)),
        None => result.set_property(ctx, "address", JSValue::null()),
    };
    match entry.offset {
        Some(value) => result.set_property(ctx, "offset", JSValue(ffi::JS_NewBigUint64(ctx, value))),
        None => result.set_property(ctx, "offset", JSValue::null()),
    };
    match entry.other {
        Some(value) => result.set_property(ctx, "other", JSValue(ffi::JS_NewBigUint64(ctx, value))),
        None => result.set_property(ctx, "other", JSValue::null()),
    };
    match &entry.import_name {
        Some(value) => result.set_property(ctx, "importName", JSValue::string(ctx, value)),
        None => result.set_property(ctx, "importName", JSValue::null()),
    };
    result.set_property(ctx, "isWeakDefinition", JSValue::bool(entry.is_weak_definition));
    result.set_property(ctx, "isReexport", JSValue::bool(entry.is_reexport));
    result.set_property(ctx, "isStubAndResolver", JSValue::bool(entry.is_stub_and_resolver));
    result.raw()
}

unsafe fn image_exports_trie_to_js(
    ctx: *mut ffi::JSContext,
    exports_trie: &native_api::ImageExportsTrie,
) -> ffi::JSValue {
    let result = JSValue(ffi::JS_NewObject(ctx));
    result.set_property(ctx, "moduleName", JSValue::string(ctx, &exports_trie.module_name));
    result.set_property(
        ctx,
        "moduleBase",
        create_native_pointer(ctx, exports_trie.module_base as u64),
    );
    result.set_property(ctx, "dataoff", JSValue(ffi::qjs_new_uint32(ctx, exports_trie.dataoff)));
    result.set_property(
        ctx,
        "datasize",
        JSValue(ffi::qjs_new_uint32(ctx, exports_trie.datasize)),
    );
    result.set_property(
        ctx,
        "linkeditBase",
        create_native_pointer(ctx, exports_trie.linkedit_base as u64),
    );
    result.set_property(
        ctx,
        "dataAddress",
        create_native_pointer(ctx, exports_trie.data_address as u64),
    );
    let entries = ffi::JS_NewArray(ctx);
    for (index, item) in exports_trie.entries.iter().enumerate() {
        ffi::JS_SetPropertyUint32(ctx, entries, index as u32, image_exports_trie_entry_to_js(ctx, item));
    }
    result.set_property(ctx, "entries", JSValue(entries));
    result.raw()
}

unsafe fn image_chained_fixups_page_to_js(
    ctx: *mut ffi::JSContext,
    page: &native_api::ImageChainedFixupsPage,
) -> ffi::JSValue {
    let result = JSValue(ffi::JS_NewObject(ctx));
    result.set_property(ctx, "pageIndex", JSValue::int(page.page_index as i32));
    result.set_property(ctx, "hasFixups", JSValue::bool(page.has_fixups));
    match page.page_start {
        Some(value) => result.set_property(ctx, "pageStart", JSValue::int(value as i32)),
        None => result.set_property(ctx, "pageStart", JSValue::null()),
    };
    result.set_property(ctx, "usesMultipleStarts", JSValue::bool(page.uses_multiple_starts));
    let chain_starts = ffi::JS_NewArray(ctx);
    for (index, item) in page.chain_starts.iter().enumerate() {
        ffi::JS_SetPropertyUint32(ctx, chain_starts, index as u32, JSValue::int(*item as i32).raw());
    }
    result.set_property(ctx, "chainStarts", JSValue(chain_starts));
    result.raw()
}

unsafe fn image_chained_fixups_segment_to_js(
    ctx: *mut ffi::JSContext,
    segment: &native_api::ImageChainedFixupsSegment,
) -> ffi::JSValue {
    let result = JSValue(ffi::JS_NewObject(ctx));
    result.set_property(ctx, "segmentIndex", JSValue::int(segment.segment_index as i32));
    result.set_property(
        ctx,
        "offsetInStarts",
        JSValue(ffi::qjs_new_uint32(ctx, segment.offset_in_starts)),
    );
    result.set_property(ctx, "size", JSValue(ffi::qjs_new_uint32(ctx, segment.size)));
    result.set_property(ctx, "pageSize", JSValue::int(segment.page_size as i32));
    result.set_property(ctx, "pointerFormat", JSValue::int(segment.pointer_format as i32));
    result.set_property(
        ctx,
        "pointerFormatName",
        JSValue::string(ctx, &segment.pointer_format_name),
    );
    result.set_property(
        ctx,
        "segmentOffset",
        JSValue(ffi::JS_NewBigUint64(ctx, segment.segment_offset)),
    );
    result.set_property(
        ctx,
        "maxValidPointer",
        JSValue(ffi::qjs_new_uint32(ctx, segment.max_valid_pointer)),
    );
    result.set_property(ctx, "pageCount", JSValue::int(segment.page_count as i32));
    result.set_property(ctx, "fixupPageCount", JSValue::int(segment.fixup_page_count as i32));
    result.set_property(ctx, "multiPageCount", JSValue::int(segment.multi_page_count as i32));
    let pages = ffi::JS_NewArray(ctx);
    for (index, item) in segment.pages.iter().enumerate() {
        ffi::JS_SetPropertyUint32(ctx, pages, index as u32, image_chained_fixups_page_to_js(ctx, item));
    }
    result.set_property(ctx, "pages", JSValue(pages));
    result.raw()
}

unsafe fn image_chained_fixups_import_to_js(
    ctx: *mut ffi::JSContext,
    import: &native_api::ImageChainedFixupsImport,
) -> ffi::JSValue {
    let result = JSValue(ffi::JS_NewObject(ctx));
    result.set_property(ctx, "index", JSValue::int(import.index as i32));
    result.set_property(
        ctx,
        "libOrdinalRaw",
        JSValue(ffi::JS_NewBigUint64(ctx, import.lib_ordinal_raw)),
    );
    result.set_property(ctx, "libOrdinal", JSValue::int(import.lib_ordinal as i32));
    result.set_property(ctx, "weakImport", JSValue::bool(import.weak_import));
    result.set_property(ctx, "nameOffset", JSValue(ffi::qjs_new_uint32(ctx, import.name_offset)));
    match &import.name {
        Some(value) => result.set_property(ctx, "name", JSValue::string(ctx, value)),
        None => result.set_property(ctx, "name", JSValue::null()),
    };
    match import.addend {
        Some(value) => result.set_property(ctx, "addend", JSValue(ffi::JS_NewBigInt64(ctx, value))),
        None => result.set_property(ctx, "addend", JSValue::null()),
    };
    result.raw()
}

unsafe fn image_chained_fixups_to_js(
    ctx: *mut ffi::JSContext,
    chained_fixups: &native_api::ImageChainedFixups,
) -> ffi::JSValue {
    let result = JSValue(ffi::JS_NewObject(ctx));
    result.set_property(ctx, "moduleName", JSValue::string(ctx, &chained_fixups.module_name));
    result.set_property(
        ctx,
        "moduleBase",
        create_native_pointer(ctx, chained_fixups.module_base as u64),
    );
    result.set_property(
        ctx,
        "dataoff",
        JSValue(ffi::qjs_new_uint32(ctx, chained_fixups.dataoff)),
    );
    result.set_property(
        ctx,
        "datasize",
        JSValue(ffi::qjs_new_uint32(ctx, chained_fixups.datasize)),
    );
    result.set_property(
        ctx,
        "linkeditBase",
        create_native_pointer(ctx, chained_fixups.linkedit_base as u64),
    );
    result.set_property(
        ctx,
        "dataAddress",
        create_native_pointer(ctx, chained_fixups.data_address as u64),
    );
    result.set_property(
        ctx,
        "fixupsVersion",
        JSValue(ffi::qjs_new_uint32(ctx, chained_fixups.fixups_version)),
    );
    result.set_property(
        ctx,
        "startsOffset",
        JSValue(ffi::qjs_new_uint32(ctx, chained_fixups.starts_offset)),
    );
    result.set_property(
        ctx,
        "importsOffset",
        JSValue(ffi::qjs_new_uint32(ctx, chained_fixups.imports_offset)),
    );
    result.set_property(
        ctx,
        "symbolsOffset",
        JSValue(ffi::qjs_new_uint32(ctx, chained_fixups.symbols_offset)),
    );
    result.set_property(
        ctx,
        "importsCount",
        JSValue(ffi::qjs_new_uint32(ctx, chained_fixups.imports_count)),
    );
    result.set_property(
        ctx,
        "importsFormat",
        JSValue(ffi::qjs_new_uint32(ctx, chained_fixups.imports_format)),
    );
    result.set_property(
        ctx,
        "importsFormatName",
        JSValue::string(ctx, &chained_fixups.imports_format_name),
    );
    result.set_property(
        ctx,
        "symbolsFormat",
        JSValue(ffi::qjs_new_uint32(ctx, chained_fixups.symbols_format)),
    );
    result.set_property(
        ctx,
        "symbolsFormatName",
        JSValue::string(ctx, &chained_fixups.symbols_format_name),
    );
    let segments = ffi::JS_NewArray(ctx);
    for (index, item) in chained_fixups.segments.iter().enumerate() {
        ffi::JS_SetPropertyUint32(
            ctx,
            segments,
            index as u32,
            image_chained_fixups_segment_to_js(ctx, item),
        );
    }
    result.set_property(ctx, "segments", JSValue(segments));
    let imports = ffi::JS_NewArray(ctx);
    for (index, item) in chained_fixups.imports.iter().enumerate() {
        ffi::JS_SetPropertyUint32(ctx, imports, index as u32, image_chained_fixups_import_to_js(ctx, item));
    }
    result.set_property(ctx, "imports", JSValue(imports));
    result.raw()
}

unsafe fn image_uuid_to_js(ctx: *mut ffi::JSContext, image_uuid: &native_api::ImageUuid) -> ffi::JSValue {
    let result = JSValue(ffi::JS_NewObject(ctx));
    result.set_property(ctx, "moduleName", JSValue::string(ctx, &image_uuid.module_name));
    result.set_property(
        ctx,
        "moduleBase",
        create_native_pointer(ctx, image_uuid.module_base as u64),
    );
    result.set_property(ctx, "uuid", JSValue::string(ctx, &image_uuid.uuid));
    result.raw()
}

unsafe fn image_rpath_to_js(ctx: *mut ffi::JSContext, rpath: &native_api::ImageRpath) -> ffi::JSValue {
    let result = JSValue(ffi::JS_NewObject(ctx));
    result.set_property(ctx, "moduleName", JSValue::string(ctx, &rpath.module_name));
    result.set_property(ctx, "moduleBase", create_native_pointer(ctx, rpath.module_base as u64));
    result.set_property(ctx, "path", JSValue::string(ctx, &rpath.path));
    result.raw()
}

unsafe fn image_segment_to_js(ctx: *mut ffi::JSContext, segment: &native_api::ImageSegment) -> ffi::JSValue {
    let result = JSValue(ffi::JS_NewObject(ctx));
    result.set_property(ctx, "moduleName", JSValue::string(ctx, &segment.module_name));
    result.set_property(
        ctx,
        "moduleBase",
        create_native_pointer(ctx, segment.module_base as u64),
    );
    result.set_property(ctx, "name", JSValue::string(ctx, &segment.segment_name));
    result.set_property(ctx, "vmaddr", create_native_pointer(ctx, segment.vmaddr as u64));
    result.set_property(ctx, "vmsize", JSValue(ffi::JS_NewBigUint64(ctx, segment.vmsize as u64)));
    result.set_property(
        ctx,
        "fileoff",
        JSValue(ffi::JS_NewBigUint64(ctx, segment.fileoff as u64)),
    );
    result.set_property(
        ctx,
        "filesize",
        JSValue(ffi::JS_NewBigUint64(ctx, segment.filesize as u64)),
    );
    result.set_property(ctx, "maxprot", JSValue::int(segment.maxprot));
    result.set_property(ctx, "initprot", JSValue::int(segment.initprot));
    result.raw()
}

unsafe fn image_section_to_js(ctx: *mut ffi::JSContext, section: &native_api::ImageSection) -> ffi::JSValue {
    let result = JSValue(ffi::JS_NewObject(ctx));
    result.set_property(ctx, "moduleName", JSValue::string(ctx, &section.module_name));
    result.set_property(
        ctx,
        "moduleBase",
        create_native_pointer(ctx, section.module_base as u64),
    );
    result.set_property(ctx, "segmentName", JSValue::string(ctx, &section.segment_name));
    result.set_property(ctx, "name", JSValue::string(ctx, &section.section_name));
    result.set_property(ctx, "addr", create_native_pointer(ctx, section.addr as u64));
    result.set_property(ctx, "size", JSValue(ffi::JS_NewBigUint64(ctx, section.size as u64)));
    result.set_property(ctx, "offset", JSValue::int(section.offset as i32));
    result.set_property(ctx, "align", JSValue::int(section.align as i32));
    result.set_property(ctx, "flags", JSValue::int(section.flags as i32));
    result.raw()
}

unsafe fn image_load_command_to_js(ctx: *mut ffi::JSContext, command: &native_api::ImageLoadCommand) -> ffi::JSValue {
    let result = JSValue(ffi::JS_NewObject(ctx));
    result.set_property(ctx, "moduleName", JSValue::string(ctx, &command.module_name));
    result.set_property(
        ctx,
        "moduleBase",
        create_native_pointer(ctx, command.module_base as u64),
    );
    result.set_property(ctx, "index", JSValue(ffi::qjs_new_uint32(ctx, command.index as u32)));
    result.set_property(ctx, "cmd", JSValue(ffi::qjs_new_uint32(ctx, command.command)));
    result.set_property(ctx, "cmdsize", JSValue(ffi::qjs_new_uint32(ctx, command.command_size)));
    result.set_property(
        ctx,
        "offset",
        JSValue(ffi::JS_NewBigUint64(ctx, command.command_offset as u64)),
    );
    result.set_property(ctx, "name", JSValue::string(ctx, &command.command_name));
    match &command.detail {
        Some(detail) => result.set_property(ctx, "detail", JSValue::string(ctx, detail)),
        None => result.set_property(ctx, "detail", JSValue::null()),
    };
    result.raw()
}

unsafe extern "C" fn js_native_detect_hook_environment(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    match detect_hook_environment() {
        Ok(report) => report_to_js(ctx, &report),
        Err(err) => js_throw_internal_error(ctx, &err.to_string()),
    }
}

unsafe extern "C" fn js_native_find_symbols(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 1 {
        return crate::util::js_throw_type_error(
            ctx,
            "Native.findSymbols(query[, moduleName]) requires at least 1 string argument",
        );
    }

    let query = match JSValue(*argv).to_string(ctx) {
        Some(value) if !value.trim().is_empty() => value,
        _ => {
            return crate::util::js_throw_type_error(
                ctx,
                "Native.findSymbols(query[, moduleName]) requires query to be a non-empty string",
            )
        }
    };

    let module_name = if argc >= 2 {
        let value = JSValue(*argv.add(1));
        if value.is_null() || value.is_undefined() {
            None
        } else {
            match value.to_string(ctx) {
                Some(module_name) => Some(module_name),
                None => {
                    return crate::util::js_throw_type_error(
                        ctx,
                        "Native.findSymbols(query[, moduleName]) expected moduleName to be a string when provided",
                    )
                }
            }
        }
    } else {
        None
    };

    let symbols = match find_native_symbols(module_name.as_deref(), &query) {
        Ok(symbols) => symbols,
        Err(common::Error::Unsupported(_)) => return ffi::JS_NewArray(ctx),
        Err(common::Error::InvalidArgument(message)) => return crate::util::js_throw_type_error(ctx, &message),
        Err(err) => return js_throw_internal_error(ctx, &err.to_string()),
    };

    let array = ffi::JS_NewArray(ctx);
    for (index, symbol) in symbols.iter().enumerate() {
        ffi::JS_SetPropertyUint32(ctx, array, index as u32, native_symbol_to_js(ctx, symbol));
    }
    array
}

unsafe extern "C" fn js_native_symbol_info(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 1 {
        return crate::util::js_throw_type_error(
            ctx,
            "Native.symbolInfo(symbolName[, moduleName]) requires at least 1 string argument",
        );
    }

    let symbol_name = match JSValue(*argv).to_string(ctx) {
        Some(value) if !value.trim().is_empty() => value,
        _ => {
            return crate::util::js_throw_type_error(
                ctx,
                "Native.symbolInfo(symbolName[, moduleName]) requires symbolName to be a non-empty string",
            )
        }
    };

    let module_name =
        if argc >= 2 {
            let value = JSValue(*argv.add(1));
            if value.is_null() || value.is_undefined() {
                None
            } else {
                match value.to_string(ctx) {
                    Some(module_name) => Some(module_name),
                    None => return crate::util::js_throw_type_error(
                        ctx,
                        "Native.symbolInfo(symbolName[, moduleName]) expected moduleName to be a string when provided",
                    ),
                }
            }
        } else {
            None
        };

    let normalized_symbol_name = symbol_name.strip_prefix('_').unwrap_or(&symbol_name);
    let symbols = match find_native_symbols(module_name.as_deref(), &symbol_name) {
        Ok(symbols) => symbols,
        Err(common::Error::Unsupported(_)) => return JSValue::null().raw(),
        Err(common::Error::InvalidArgument(message)) => return crate::util::js_throw_type_error(ctx, &message),
        Err(err) => return js_throw_internal_error(ctx, &err.to_string()),
    };

    match symbols.into_iter().find(|symbol| {
        symbol.symbol_name == symbol_name
            || symbol.symbol_name.strip_prefix('_').unwrap_or(&symbol.symbol_name) == normalized_symbol_name
    }) {
        Some(symbol) => native_symbol_to_js(ctx, &symbol),
        None => JSValue::null().raw(),
    }
}

unsafe extern "C" fn js_native_images(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let filter = if argc >= 1 {
        match JSValue(*argv).to_string(ctx) {
            Some(value) => {
                let trimmed = value.trim();
                if trimmed.is_empty() {
                    None
                } else {
                    Some(trimmed.to_lowercase())
                }
            }
            None => {
                return crate::util::js_throw_type_error(
                    ctx,
                    "Native.images([filter]) expected filter to be a string when provided",
                )
            }
        }
    } else {
        None
    };

    match enumerate_images() {
        Ok(images) => {
            let array = ffi::JS_NewArray(ctx);
            let mut index = 0u32;
            for image in images {
                let haystack = image.name.to_lowercase();
                if filter.as_ref().is_some_and(|value| !haystack.contains(value)) {
                    continue;
                }
                ffi::JS_SetPropertyUint32(ctx, array, index, image_info_to_js(ctx, &image));
                index += 1;
            }
            array
        }
        Err(common::Error::Unsupported(_)) => ffi::JS_NewArray(ctx),
        Err(err) => js_throw_internal_error(ctx, &err.to_string()),
    }
}

unsafe extern "C" fn js_native_symbol(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 1 {
        return crate::util::js_throw_type_error(ctx, "Native.symbol(address) requires 1 address argument");
    }

    let address = match pointer_arg_to_u64(
        ctx,
        JSValue(*argv),
        "Native.symbol(address) expected a pointer-like value",
    ) {
        Ok(value) => value,
        Err(err) => return err,
    };

    match find_symbol_by_address(address as usize) {
        Ok(Some(symbol)) => symbol_info_to_js(ctx, &symbol),
        Ok(None) | Err(common::Error::Unsupported(_)) => JSValue::null().raw(),
        Err(err) => js_throw_internal_error(ctx, &err.to_string()),
    }
}

unsafe extern "C" fn js_native_export(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 2 {
        return crate::util::js_throw_type_error(
            ctx,
            "Native.export(moduleNameOrNull, symbolName) requires 2 arguments",
        );
    }

    let module_name =
        {
            let value = JSValue(*argv);
            if value.is_null() || value.is_undefined() {
                None
            } else if value.is_string() {
                match value.to_string(ctx) {
                    Some(value) => Some(value),
                    None => return crate::util::js_throw_type_error(
                        ctx,
                        "Native.export(moduleNameOrNull, symbolName) expected moduleNameOrNull to be a string or null",
                    ),
                }
            } else {
                return crate::util::js_throw_type_error(
                    ctx,
                    "Native.export(moduleNameOrNull, symbolName) expected moduleNameOrNull to be a string or null",
                );
            }
        };

    let symbol_name = match JSValue(*argv.add(1)).to_string(ctx) {
        Some(value) if !value.trim().is_empty() => value,
        _ => {
            return crate::util::js_throw_type_error(
                ctx,
                "Native.export(moduleNameOrNull, symbolName) requires symbolName to be a non-empty string",
            )
        }
    };

    match find_export_by_name(module_name.as_deref(), &symbol_name) {
        Ok(Some(address)) => create_native_pointer(ctx, address as u64).raw(),
        Ok(None) | Err(common::Error::Unsupported(_)) => JSValue::null().raw(),
        Err(common::Error::InvalidArgument(message)) => crate::util::js_throw_type_error(ctx, &message),
        Err(err) => js_throw_internal_error(ctx, &err.to_string()),
    }
}

unsafe extern "C" fn js_native_base(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 1 {
        return crate::util::js_throw_type_error(ctx, "Native.base(moduleName) requires 1 string argument");
    }

    let module_name = match JSValue(*argv).to_string(ctx) {
        Some(value) if !value.trim().is_empty() => value,
        _ => {
            return crate::util::js_throw_type_error(
                ctx,
                "Native.base(moduleName) requires moduleName to be a non-empty string",
            )
        }
    };

    match find_image_by_name(&module_name) {
        Ok(Some(image)) => create_native_pointer(ctx, image.base as u64).raw(),
        Ok(None) | Err(common::Error::Unsupported(_)) => JSValue::null().raw(),
        Err(common::Error::InvalidArgument(message)) => crate::util::js_throw_type_error(ctx, &message),
        Err(err) => js_throw_internal_error(ctx, &err.to_string()),
    }
}

unsafe extern "C" fn js_native_main_image(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    match enumerate_images() {
        Ok(images) => images
            .into_iter()
            .next()
            .map(|image| image_info_to_js(ctx, &image))
            .unwrap_or_else(|| JSValue::null().raw()),
        Err(common::Error::Unsupported(_)) => JSValue::null().raw(),
        Err(err) => js_throw_internal_error(ctx, &err.to_string()),
    }
}

unsafe extern "C" fn js_native_image(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 1 {
        return crate::util::js_throw_type_error(ctx, "Native.image(address) requires 1 address argument");
    }

    let address = match pointer_arg_to_u64(
        ctx,
        JSValue(*argv),
        "Native.image(address) expected a pointer-like value",
    ) {
        Ok(value) => value,
        Err(err) => return err,
    };

    match find_image_by_address(address as usize) {
        Ok(Some(image)) => image_info_to_js(ctx, &image),
        Ok(None) | Err(common::Error::Unsupported(_)) => JSValue::null().raw(),
        Err(err) => js_throw_internal_error(ctx, &err.to_string()),
    }
}

unsafe extern "C" fn js_native_image_info(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 1 {
        return crate::util::js_throw_type_error(ctx, "Native.imageInfo(moduleName) requires 1 string argument");
    }

    let module_name = match JSValue(*argv).to_string(ctx) {
        Some(value) if !value.trim().is_empty() => value,
        _ => {
            return crate::util::js_throw_type_error(
                ctx,
                "Native.imageInfo(moduleName) requires moduleName to be a non-empty string",
            )
        }
    };

    match find_image_by_name(&module_name) {
        Ok(Some(image)) => image_info_to_js(ctx, &image),
        Ok(None) | Err(common::Error::Unsupported(_)) => JSValue::null().raw(),
        Err(common::Error::InvalidArgument(message)) => crate::util::js_throw_type_error(ctx, &message),
        Err(err) => js_throw_internal_error(ctx, &err.to_string()),
    }
}

unsafe extern "C" fn js_native_find_exports(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 1 {
        return crate::util::js_throw_type_error(
            ctx,
            "Native.findExports(moduleName[, query]) requires at least 1 string argument",
        );
    }

    let module_name = match JSValue(*argv).to_string(ctx) {
        Some(value) if !value.trim().is_empty() => value,
        _ => {
            return crate::util::js_throw_type_error(
                ctx,
                "Native.findExports(moduleName[, query]) requires moduleName to be a non-empty string",
            )
        }
    };

    let query = if argc >= 2 {
        let value = JSValue(*argv.add(1));
        if value.is_null() || value.is_undefined() {
            None
        } else {
            match value.to_string(ctx) {
                Some(query) if !query.trim().is_empty() => Some(query),
                Some(_) => None,
                None => {
                    return crate::util::js_throw_type_error(
                        ctx,
                        "Native.findExports(moduleName[, query]) expected query to be a string when provided",
                    )
                }
            }
        }
    } else {
        None
    };

    let symbols = match find_image_exports(&module_name, query.as_deref()) {
        Ok(symbols) => symbols,
        Err(common::Error::Unsupported(_)) => return ffi::JS_NewArray(ctx),
        Err(common::Error::InvalidArgument(message)) => return crate::util::js_throw_type_error(ctx, &message),
        Err(err) => return js_throw_internal_error(ctx, &err.to_string()),
    };

    let array = ffi::JS_NewArray(ctx);
    for (index, symbol) in symbols.iter().enumerate() {
        ffi::JS_SetPropertyUint32(ctx, array, index as u32, native_symbol_to_js(ctx, symbol));
    }
    array
}

unsafe extern "C" fn js_native_export_info(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 2 {
        return crate::util::js_throw_type_error(
            ctx,
            "Native.exportInfo(moduleName, symbolName) requires 2 string arguments",
        );
    }

    let module_name = match JSValue(*argv).to_string(ctx) {
        Some(value) if !value.trim().is_empty() => value,
        _ => {
            return crate::util::js_throw_type_error(
                ctx,
                "Native.exportInfo(moduleName, symbolName) requires moduleName to be a non-empty string",
            )
        }
    };

    let symbol_name = match JSValue(*argv.add(1)).to_string(ctx) {
        Some(value) if !value.trim().is_empty() => value,
        _ => {
            return crate::util::js_throw_type_error(
                ctx,
                "Native.exportInfo(moduleName, symbolName) requires symbolName to be a non-empty string",
            )
        }
    };

    let normalized_symbol_name = symbol_name.strip_prefix('_').unwrap_or(&symbol_name);
    let exports = match find_image_exports(&module_name, Some(&symbol_name)) {
        Ok(exports) => exports,
        Err(common::Error::Unsupported(_)) => return JSValue::null().raw(),
        Err(common::Error::InvalidArgument(message)) => return crate::util::js_throw_type_error(ctx, &message),
        Err(err) => return js_throw_internal_error(ctx, &err.to_string()),
    };

    match exports.into_iter().find(|export| {
        export.symbol_name == symbol_name
            || export.symbol_name.strip_prefix('_').unwrap_or(&export.symbol_name) == normalized_symbol_name
    }) {
        Some(export) => native_symbol_to_js(ctx, &export),
        None => JSValue::null().raw(),
    }
}

unsafe extern "C" fn js_native_find_imports(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 1 {
        return crate::util::js_throw_type_error(
            ctx,
            "Native.findImports(moduleName[, query]) requires at least 1 string argument",
        );
    }

    let module_name = match JSValue(*argv).to_string(ctx) {
        Some(value) if !value.trim().is_empty() => value,
        _ => {
            return crate::util::js_throw_type_error(
                ctx,
                "Native.findImports(moduleName[, query]) requires moduleName to be a non-empty string",
            )
        }
    };

    let query = if argc >= 2 {
        let value = JSValue(*argv.add(1));
        if value.is_null() || value.is_undefined() {
            None
        } else {
            match value.to_string(ctx) {
                Some(query) if !query.trim().is_empty() => Some(query),
                Some(_) => None,
                None => {
                    return crate::util::js_throw_type_error(
                        ctx,
                        "Native.findImports(moduleName[, query]) expected query to be a string when provided",
                    )
                }
            }
        }
    } else {
        None
    };

    let imports = match find_image_imports(&module_name, query.as_deref()) {
        Ok(imports) => imports,
        Err(common::Error::Unsupported(_)) => return ffi::JS_NewArray(ctx),
        Err(common::Error::InvalidArgument(message)) => return crate::util::js_throw_type_error(ctx, &message),
        Err(err) => return js_throw_internal_error(ctx, &err.to_string()),
    };

    let array = ffi::JS_NewArray(ctx);
    for (index, import) in imports.iter().enumerate() {
        ffi::JS_SetPropertyUint32(ctx, array, index as u32, image_import_to_js(ctx, import));
    }
    array
}

unsafe extern "C" fn js_native_find_dependencies(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 1 {
        return crate::util::js_throw_type_error(
            ctx,
            "Native.findDependencies(moduleName[, query]) requires at least 1 string argument",
        );
    }

    let module_name = match JSValue(*argv).to_string(ctx) {
        Some(value) if !value.trim().is_empty() => value,
        _ => {
            return crate::util::js_throw_type_error(
                ctx,
                "Native.findDependencies(moduleName[, query]) requires moduleName to be a non-empty string",
            )
        }
    };

    let query = if argc >= 2 {
        let value = JSValue(*argv.add(1));
        if value.is_null() || value.is_undefined() {
            None
        } else {
            match value.to_string(ctx) {
                Some(query) if !query.trim().is_empty() => Some(query),
                Some(_) => None,
                None => {
                    return crate::util::js_throw_type_error(
                        ctx,
                        "Native.findDependencies(moduleName[, query]) expected query to be a string when provided",
                    )
                }
            }
        }
    } else {
        None
    };

    let dependencies = match find_image_dependencies(&module_name, query.as_deref()) {
        Ok(dependencies) => dependencies,
        Err(common::Error::Unsupported(_)) => return ffi::JS_NewArray(ctx),
        Err(common::Error::InvalidArgument(message)) => return crate::util::js_throw_type_error(ctx, &message),
        Err(err) => return js_throw_internal_error(ctx, &err.to_string()),
    };

    let array = ffi::JS_NewArray(ctx);
    for (index, dependency) in dependencies.iter().enumerate() {
        ffi::JS_SetPropertyUint32(ctx, array, index as u32, image_dependency_to_js(ctx, dependency));
    }
    array
}

unsafe extern "C" fn js_native_dependency_info(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 2 {
        return crate::util::js_throw_type_error(
            ctx,
            "Native.dependencyInfo(moduleName, pathOrName) requires 2 string arguments",
        );
    }

    let module_name = match JSValue(*argv).to_string(ctx) {
        Some(value) if !value.trim().is_empty() => value,
        _ => {
            return crate::util::js_throw_type_error(
                ctx,
                "Native.dependencyInfo(moduleName, pathOrName) requires moduleName to be a non-empty string",
            )
        }
    };

    let path_or_name = match JSValue(*argv.add(1)).to_string(ctx) {
        Some(value) if !value.trim().is_empty() => value,
        _ => {
            return crate::util::js_throw_type_error(
                ctx,
                "Native.dependencyInfo(moduleName, pathOrName) requires pathOrName to be a non-empty string",
            )
        }
    };

    let dependencies = match find_image_dependencies(&module_name, Some(&path_or_name)) {
        Ok(dependencies) => dependencies,
        Err(common::Error::Unsupported(_)) => return JSValue::null().raw(),
        Err(common::Error::InvalidArgument(message)) => return crate::util::js_throw_type_error(ctx, &message),
        Err(err) => return js_throw_internal_error(ctx, &err.to_string()),
    };

    match dependencies
        .into_iter()
        .find(|dependency| dependency_path_or_name_matches(&dependency.path, &path_or_name))
    {
        Some(dependency) => image_dependency_to_js(ctx, &dependency),
        None => JSValue::null().raw(),
    }
}

unsafe extern "C" fn js_native_find_encryption_info(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 1 {
        return crate::util::js_throw_type_error(
            ctx,
            "Native.findEncryptionInfo(moduleName) requires 1 string argument",
        );
    }

    let module_name = match JSValue(*argv).to_string(ctx) {
        Some(value) if !value.trim().is_empty() => value,
        _ => {
            return crate::util::js_throw_type_error(
                ctx,
                "Native.findEncryptionInfo(moduleName) requires moduleName to be a non-empty string",
            )
        }
    };

    match find_image_encryption_info(&module_name) {
        Ok(Some(encryption_info)) => image_encryption_info_to_js(ctx, &encryption_info),
        Ok(None) | Err(common::Error::Unsupported(_)) => JSValue::null().raw(),
        Err(common::Error::InvalidArgument(message)) => crate::util::js_throw_type_error(ctx, &message),
        Err(err) => js_throw_internal_error(ctx, &err.to_string()),
    }
}

unsafe extern "C" fn js_native_find_entry_point(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 1 {
        return crate::util::js_throw_type_error(ctx, "Native.findEntryPoint(moduleName) requires 1 string argument");
    }

    let module_name = match JSValue(*argv).to_string(ctx) {
        Some(value) if !value.trim().is_empty() => value,
        _ => {
            return crate::util::js_throw_type_error(
                ctx,
                "Native.findEntryPoint(moduleName) requires moduleName to be a non-empty string",
            )
        }
    };

    match find_image_entry_point(&module_name) {
        Ok(Some(entry_point)) => image_entry_point_to_js(ctx, &entry_point),
        Ok(None) | Err(common::Error::Unsupported(_)) => JSValue::null().raw(),
        Err(common::Error::InvalidArgument(message)) => crate::util::js_throw_type_error(ctx, &message),
        Err(err) => js_throw_internal_error(ctx, &err.to_string()),
    }
}

unsafe extern "C" fn js_native_find_dyld_info(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 1 {
        return crate::util::js_throw_type_error(ctx, "Native.findDyldInfo(moduleName) requires 1 string argument");
    }

    let module_name = match JSValue(*argv).to_string(ctx) {
        Some(value) if !value.trim().is_empty() => value,
        _ => {
            return crate::util::js_throw_type_error(
                ctx,
                "Native.findDyldInfo(moduleName) requires moduleName to be a non-empty string",
            )
        }
    };

    match find_image_dyld_info(&module_name) {
        Ok(Some(dyld_info)) => image_dyld_info_to_js(ctx, &dyld_info),
        Ok(None) | Err(common::Error::Unsupported(_)) => JSValue::null().raw(),
        Err(common::Error::InvalidArgument(message)) => crate::util::js_throw_type_error(ctx, &message),
        Err(err) => js_throw_internal_error(ctx, &err.to_string()),
    }
}

unsafe extern "C" fn js_native_find_source_version(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 1 {
        return crate::util::js_throw_type_error(
            ctx,
            "Native.findSourceVersion(moduleName) requires 1 string argument",
        );
    }

    let module_name = match JSValue(*argv).to_string(ctx) {
        Some(value) if !value.trim().is_empty() => value,
        _ => {
            return crate::util::js_throw_type_error(
                ctx,
                "Native.findSourceVersion(moduleName) requires moduleName to be a non-empty string",
            )
        }
    };

    match find_image_source_version(&module_name) {
        Ok(Some(source_version)) => image_source_version_to_js(ctx, &source_version),
        Ok(None) | Err(common::Error::Unsupported(_)) => JSValue::null().raw(),
        Err(common::Error::InvalidArgument(message)) => crate::util::js_throw_type_error(ctx, &message),
        Err(err) => js_throw_internal_error(ctx, &err.to_string()),
    }
}

unsafe extern "C" fn js_native_find_build_version(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 1 {
        return crate::util::js_throw_type_error(ctx, "Native.findBuildVersion(moduleName) requires 1 string argument");
    }

    let module_name = match JSValue(*argv).to_string(ctx) {
        Some(value) if !value.trim().is_empty() => value,
        _ => {
            return crate::util::js_throw_type_error(
                ctx,
                "Native.findBuildVersion(moduleName) requires moduleName to be a non-empty string",
            )
        }
    };

    match find_image_build_version(&module_name) {
        Ok(Some(build_version)) => image_build_version_to_js(ctx, &build_version),
        Ok(None) | Err(common::Error::Unsupported(_)) => JSValue::null().raw(),
        Err(common::Error::InvalidArgument(message)) => crate::util::js_throw_type_error(ctx, &message),
        Err(err) => js_throw_internal_error(ctx, &err.to_string()),
    }
}

unsafe extern "C" fn js_native_find_dylinker(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 1 {
        return crate::util::js_throw_type_error(ctx, "Native.findDylinker(moduleName) requires 1 string argument");
    }

    let module_name = match JSValue(*argv).to_string(ctx) {
        Some(value) if !value.trim().is_empty() => value,
        _ => {
            return crate::util::js_throw_type_error(
                ctx,
                "Native.findDylinker(moduleName) requires moduleName to be a non-empty string",
            )
        }
    };

    match find_image_dylinker(&module_name) {
        Ok(Some(dylinker)) => image_dylinker_to_js(ctx, &dylinker),
        Ok(None) | Err(common::Error::Unsupported(_)) => JSValue::null().raw(),
        Err(common::Error::InvalidArgument(message)) => crate::util::js_throw_type_error(ctx, &message),
        Err(err) => js_throw_internal_error(ctx, &err.to_string()),
    }
}

unsafe extern "C" fn js_native_find_install_name(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 1 {
        return crate::util::js_throw_type_error(ctx, "Native.findInstallName(moduleName) requires 1 string argument");
    }

    let module_name = match JSValue(*argv).to_string(ctx) {
        Some(value) if !value.trim().is_empty() => value,
        _ => {
            return crate::util::js_throw_type_error(
                ctx,
                "Native.findInstallName(moduleName) requires moduleName to be a non-empty string",
            )
        }
    };

    match find_image_install_name(&module_name) {
        Ok(Some(install_name)) => image_install_name_to_js(ctx, &install_name),
        Ok(None) | Err(common::Error::Unsupported(_)) => JSValue::null().raw(),
        Err(common::Error::InvalidArgument(message)) => crate::util::js_throw_type_error(ctx, &message),
        Err(err) => js_throw_internal_error(ctx, &err.to_string()),
    }
}

unsafe extern "C" fn js_native_find_linkedit(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 1 {
        return crate::util::js_throw_type_error(ctx, "Native.findLinkedit(moduleName) requires 1 string argument");
    }

    let module_name = match JSValue(*argv).to_string(ctx) {
        Some(value) if !value.trim().is_empty() => value,
        _ => {
            return crate::util::js_throw_type_error(
                ctx,
                "Native.findLinkedit(moduleName) requires moduleName to be a non-empty string",
            )
        }
    };

    match find_image_linkedit_info(&module_name) {
        Ok(Some(linkedit)) => image_linkedit_info_to_js(ctx, &linkedit),
        Ok(None) | Err(common::Error::Unsupported(_)) => JSValue::null().raw(),
        Err(common::Error::InvalidArgument(message)) => crate::util::js_throw_type_error(ctx, &message),
        Err(err) => js_throw_internal_error(ctx, &err.to_string()),
    }
}

unsafe extern "C" fn js_native_find_function_starts(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 1 {
        return crate::util::js_throw_type_error(
            ctx,
            "Native.findFunctionStarts(moduleName) requires 1 string argument",
        );
    }

    let module_name = match JSValue(*argv).to_string(ctx) {
        Some(value) if !value.trim().is_empty() => value,
        _ => {
            return crate::util::js_throw_type_error(
                ctx,
                "Native.findFunctionStarts(moduleName) requires moduleName to be a non-empty string",
            )
        }
    };

    match find_image_function_starts(&module_name) {
        Ok(Some(function_starts)) => image_function_starts_to_js(ctx, &function_starts),
        Ok(None) | Err(common::Error::Unsupported(_)) => JSValue::null().raw(),
        Err(common::Error::InvalidArgument(message)) => crate::util::js_throw_type_error(ctx, &message),
        Err(err) => js_throw_internal_error(ctx, &err.to_string()),
    }
}

unsafe extern "C" fn js_native_find_code_signature(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 1 {
        return crate::util::js_throw_type_error(
            ctx,
            "Native.findCodeSignature(moduleName) requires 1 string argument",
        );
    }

    let module_name = match JSValue(*argv).to_string(ctx) {
        Some(value) if !value.trim().is_empty() => value,
        _ => {
            return crate::util::js_throw_type_error(
                ctx,
                "Native.findCodeSignature(moduleName) requires moduleName to be a non-empty string",
            )
        }
    };

    match find_image_code_signature(&module_name) {
        Ok(Some(code_signature)) => image_code_signature_to_js(ctx, &code_signature),
        Ok(None) | Err(common::Error::Unsupported(_)) => JSValue::null().raw(),
        Err(common::Error::InvalidArgument(message)) => crate::util::js_throw_type_error(ctx, &message),
        Err(err) => js_throw_internal_error(ctx, &err.to_string()),
    }
}

unsafe extern "C" fn js_native_find_data_in_code(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 1 {
        return crate::util::js_throw_type_error(ctx, "Native.findDataInCode(moduleName) requires 1 string argument");
    }

    let module_name = match JSValue(*argv).to_string(ctx) {
        Some(value) if !value.trim().is_empty() => value,
        _ => {
            return crate::util::js_throw_type_error(
                ctx,
                "Native.findDataInCode(moduleName) requires moduleName to be a non-empty string",
            )
        }
    };

    match find_image_data_in_code(&module_name) {
        Ok(Some(data_in_code)) => image_data_in_code_to_js(ctx, &data_in_code),
        Ok(None) | Err(common::Error::Unsupported(_)) => JSValue::null().raw(),
        Err(common::Error::InvalidArgument(message)) => crate::util::js_throw_type_error(ctx, &message),
        Err(err) => js_throw_internal_error(ctx, &err.to_string()),
    }
}

unsafe extern "C" fn js_native_find_exports_trie(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 1 {
        return crate::util::js_throw_type_error(ctx, "Native.findExportsTrie(moduleName) requires 1 string argument");
    }

    let module_name = match JSValue(*argv).to_string(ctx) {
        Some(value) if !value.trim().is_empty() => value,
        _ => {
            return crate::util::js_throw_type_error(
                ctx,
                "Native.findExportsTrie(moduleName) requires moduleName to be a non-empty string",
            )
        }
    };

    match find_image_exports_trie(&module_name) {
        Ok(Some(exports_trie)) => image_exports_trie_to_js(ctx, &exports_trie),
        Ok(None) | Err(common::Error::Unsupported(_)) => JSValue::null().raw(),
        Err(common::Error::InvalidArgument(message)) => crate::util::js_throw_type_error(ctx, &message),
        Err(err) => js_throw_internal_error(ctx, &err.to_string()),
    }
}

unsafe extern "C" fn js_native_find_chained_fixups(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 1 {
        return crate::util::js_throw_type_error(
            ctx,
            "Native.findChainedFixups(moduleName) requires 1 string argument",
        );
    }

    let module_name = match JSValue(*argv).to_string(ctx) {
        Some(value) if !value.trim().is_empty() => value,
        _ => {
            return crate::util::js_throw_type_error(
                ctx,
                "Native.findChainedFixups(moduleName) requires moduleName to be a non-empty string",
            )
        }
    };

    match find_image_chained_fixups(&module_name) {
        Ok(Some(chained_fixups)) => image_chained_fixups_to_js(ctx, &chained_fixups),
        Ok(None) | Err(common::Error::Unsupported(_)) => JSValue::null().raw(),
        Err(common::Error::InvalidArgument(message)) => crate::util::js_throw_type_error(ctx, &message),
        Err(err) => js_throw_internal_error(ctx, &err.to_string()),
    }
}

unsafe extern "C" fn js_native_find_uuid(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 1 {
        return crate::util::js_throw_type_error(ctx, "Native.findUuid(moduleName) requires 1 string argument");
    }

    let module_name = match JSValue(*argv).to_string(ctx) {
        Some(value) if !value.trim().is_empty() => value,
        _ => {
            return crate::util::js_throw_type_error(
                ctx,
                "Native.findUuid(moduleName) requires moduleName to be a non-empty string",
            )
        }
    };

    match find_image_uuid(&module_name) {
        Ok(Some(image_uuid)) => image_uuid_to_js(ctx, &image_uuid),
        Ok(None) | Err(common::Error::Unsupported(_)) => JSValue::null().raw(),
        Err(common::Error::InvalidArgument(message)) => crate::util::js_throw_type_error(ctx, &message),
        Err(err) => js_throw_internal_error(ctx, &err.to_string()),
    }
}

unsafe extern "C" fn js_native_find_rpaths(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 1 {
        return crate::util::js_throw_type_error(
            ctx,
            "Native.findRpaths(moduleName[, query]) requires at least 1 string argument",
        );
    }

    let module_name = match JSValue(*argv).to_string(ctx) {
        Some(value) if !value.trim().is_empty() => value,
        _ => {
            return crate::util::js_throw_type_error(
                ctx,
                "Native.findRpaths(moduleName[, query]) requires moduleName to be a non-empty string",
            )
        }
    };

    let query = if argc >= 2 {
        let value = JSValue(*argv.add(1));
        if value.is_null() || value.is_undefined() {
            None
        } else {
            match value.to_string(ctx) {
                Some(query) if !query.trim().is_empty() => Some(query),
                Some(_) => None,
                None => {
                    return crate::util::js_throw_type_error(
                        ctx,
                        "Native.findRpaths(moduleName[, query]) expected query to be a string when provided",
                    )
                }
            }
        }
    } else {
        None
    };

    let rpaths = match find_image_rpaths(&module_name, query.as_deref()) {
        Ok(rpaths) => rpaths,
        Err(common::Error::Unsupported(_)) => return ffi::JS_NewArray(ctx),
        Err(common::Error::InvalidArgument(message)) => return crate::util::js_throw_type_error(ctx, &message),
        Err(err) => return js_throw_internal_error(ctx, &err.to_string()),
    };

    let array = ffi::JS_NewArray(ctx);
    for (index, rpath) in rpaths.iter().enumerate() {
        ffi::JS_SetPropertyUint32(ctx, array, index as u32, image_rpath_to_js(ctx, rpath));
    }
    array
}

unsafe extern "C" fn js_native_rpath_info(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 2 {
        return crate::util::js_throw_type_error(ctx, "Native.rpathInfo(moduleName, path) requires 2 string arguments");
    }

    let module_name = match JSValue(*argv).to_string(ctx) {
        Some(value) if !value.trim().is_empty() => value,
        _ => {
            return crate::util::js_throw_type_error(
                ctx,
                "Native.rpathInfo(moduleName, path) requires moduleName to be a non-empty string",
            )
        }
    };

    let path = match JSValue(*argv.add(1)).to_string(ctx) {
        Some(value) if !value.trim().is_empty() => value,
        _ => {
            return crate::util::js_throw_type_error(
                ctx,
                "Native.rpathInfo(moduleName, path) requires path to be a non-empty string",
            )
        }
    };

    let rpaths = match find_image_rpaths(&module_name, Some(&path)) {
        Ok(rpaths) => rpaths,
        Err(common::Error::Unsupported(_)) => return JSValue::null().raw(),
        Err(common::Error::InvalidArgument(message)) => return crate::util::js_throw_type_error(ctx, &message),
        Err(err) => return js_throw_internal_error(ctx, &err.to_string()),
    };

    match rpaths
        .into_iter()
        .find(|rpath| rpath_path_or_name_matches(&rpath.path, &path))
    {
        Some(rpath) => image_rpath_to_js(ctx, &rpath),
        None => JSValue::null().raw(),
    }
}

unsafe extern "C" fn js_native_import_info(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 2 {
        return crate::util::js_throw_type_error(
            ctx,
            "Native.importInfo(moduleName, symbolName) requires 2 string arguments",
        );
    }

    let module_name = match JSValue(*argv).to_string(ctx) {
        Some(value) if !value.trim().is_empty() => value,
        _ => {
            return crate::util::js_throw_type_error(
                ctx,
                "Native.importInfo(moduleName, symbolName) requires moduleName to be a non-empty string",
            )
        }
    };

    let symbol_name = match JSValue(*argv.add(1)).to_string(ctx) {
        Some(value) if !value.trim().is_empty() => value,
        _ => {
            return crate::util::js_throw_type_error(
                ctx,
                "Native.importInfo(moduleName, symbolName) requires symbolName to be a non-empty string",
            )
        }
    };

    let normalized_symbol_name = symbol_name.strip_prefix('_').unwrap_or(&symbol_name);
    let imports = match find_image_imports(&module_name, Some(&symbol_name)) {
        Ok(imports) => imports,
        Err(common::Error::Unsupported(_)) => return JSValue::null().raw(),
        Err(common::Error::InvalidArgument(message)) => return crate::util::js_throw_type_error(ctx, &message),
        Err(err) => return js_throw_internal_error(ctx, &err.to_string()),
    };

    match imports.into_iter().find(|imp| {
        imp.symbol_name == symbol_name
            || imp.symbol_name.strip_prefix('_').unwrap_or(&imp.symbol_name) == normalized_symbol_name
    }) {
        Some(import) => image_import_to_js(ctx, &import),
        None => JSValue::null().raw(),
    }
}

unsafe extern "C" fn js_native_find_segments(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 1 {
        return crate::util::js_throw_type_error(ctx, "Native.findSegments(moduleName) requires 1 string argument");
    }

    let module_name = match JSValue(*argv).to_string(ctx) {
        Some(value) if !value.trim().is_empty() => value,
        _ => {
            return crate::util::js_throw_type_error(
                ctx,
                "Native.findSegments(moduleName) requires moduleName to be a non-empty string",
            )
        }
    };

    let segments = match find_image_segments(&module_name) {
        Ok(segments) => segments,
        Err(common::Error::Unsupported(_)) => return ffi::JS_NewArray(ctx),
        Err(common::Error::InvalidArgument(message)) => return crate::util::js_throw_type_error(ctx, &message),
        Err(err) => return js_throw_internal_error(ctx, &err.to_string()),
    };

    let array = ffi::JS_NewArray(ctx);
    for (index, segment) in segments.iter().enumerate() {
        ffi::JS_SetPropertyUint32(ctx, array, index as u32, image_segment_to_js(ctx, segment));
    }
    array
}

unsafe extern "C" fn js_native_find_sections(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 1 {
        return crate::util::js_throw_type_error(ctx, "Native.findSections(moduleName) requires 1 string argument");
    }

    let module_name = match JSValue(*argv).to_string(ctx) {
        Some(value) if !value.trim().is_empty() => value,
        _ => {
            return crate::util::js_throw_type_error(
                ctx,
                "Native.findSections(moduleName) requires moduleName to be a non-empty string",
            )
        }
    };

    let sections = match find_image_sections(&module_name) {
        Ok(sections) => sections,
        Err(common::Error::Unsupported(_)) => return ffi::JS_NewArray(ctx),
        Err(common::Error::InvalidArgument(message)) => return crate::util::js_throw_type_error(ctx, &message),
        Err(err) => return js_throw_internal_error(ctx, &err.to_string()),
    };

    let array = ffi::JS_NewArray(ctx);
    for (index, section) in sections.iter().enumerate() {
        ffi::JS_SetPropertyUint32(ctx, array, index as u32, image_section_to_js(ctx, section));
    }
    array
}

unsafe extern "C" fn js_native_segment_info(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 2 {
        return crate::util::js_throw_type_error(
            ctx,
            "Native.segmentInfo(moduleName, segmentName) requires 2 string arguments",
        );
    }

    let module_name = match JSValue(*argv).to_string(ctx) {
        Some(value) if !value.trim().is_empty() => value,
        _ => {
            return crate::util::js_throw_type_error(
                ctx,
                "Native.segmentInfo(moduleName, segmentName) requires moduleName to be a non-empty string",
            )
        }
    };

    let segment_name = match JSValue(*argv.add(1)).to_string(ctx) {
        Some(value) if !value.trim().is_empty() => value,
        _ => {
            return crate::util::js_throw_type_error(
                ctx,
                "Native.segmentInfo(moduleName, segmentName) requires segmentName to be a non-empty string",
            )
        }
    };

    let segments = match find_image_segments(&module_name) {
        Ok(segments) => segments,
        Err(common::Error::Unsupported(_)) => return JSValue::null().raw(),
        Err(common::Error::InvalidArgument(message)) => return crate::util::js_throw_type_error(ctx, &message),
        Err(err) => return js_throw_internal_error(ctx, &err.to_string()),
    };

    match segments
        .into_iter()
        .find(|segment| segment_name_matches(&segment.segment_name, &segment_name))
    {
        Some(segment) => image_segment_to_js(ctx, &segment),
        None => JSValue::null().raw(),
    }
}

unsafe extern "C" fn js_native_find_load_commands(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 1 {
        return crate::util::js_throw_type_error(ctx, "Native.findLoadCommands(moduleName) requires 1 string argument");
    }

    let module_name = match JSValue(*argv).to_string(ctx) {
        Some(value) if !value.trim().is_empty() => value,
        _ => {
            return crate::util::js_throw_type_error(
                ctx,
                "Native.findLoadCommands(moduleName) requires moduleName to be a non-empty string",
            )
        }
    };

    let commands = match find_image_load_commands(&module_name) {
        Ok(commands) => commands,
        Err(common::Error::Unsupported(_)) => return ffi::JS_NewArray(ctx),
        Err(common::Error::InvalidArgument(message)) => return crate::util::js_throw_type_error(ctx, &message),
        Err(err) => return js_throw_internal_error(ctx, &err.to_string()),
    };

    let array = ffi::JS_NewArray(ctx);
    for (index, command) in commands.iter().enumerate() {
        ffi::JS_SetPropertyUint32(ctx, array, index as u32, image_load_command_to_js(ctx, command));
    }
    array
}

unsafe extern "C" fn js_native_section_info(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 3 {
        return crate::util::js_throw_type_error(
            ctx,
            "Native.sectionInfo(moduleName, segmentName, sectionName) requires 3 string arguments",
        );
    }

    let module_name =
        match JSValue(*argv).to_string(ctx) {
            Some(value) if !value.trim().is_empty() => value,
            _ => return crate::util::js_throw_type_error(
                ctx,
                "Native.sectionInfo(moduleName, segmentName, sectionName) requires moduleName to be a non-empty string",
            ),
        };

    let segment_name = match JSValue(*argv.add(1)).to_string(ctx) {
        Some(value) if !value.trim().is_empty() => value,
        _ => return crate::util::js_throw_type_error(
            ctx,
            "Native.sectionInfo(moduleName, segmentName, sectionName) requires segmentName to be a non-empty string",
        ),
    };

    let section_name = match JSValue(*argv.add(2)).to_string(ctx) {
        Some(value) if !value.trim().is_empty() => value,
        _ => return crate::util::js_throw_type_error(
            ctx,
            "Native.sectionInfo(moduleName, segmentName, sectionName) requires sectionName to be a non-empty string",
        ),
    };

    let sections = match find_image_sections(&module_name) {
        Ok(sections) => sections,
        Err(common::Error::Unsupported(_)) => return JSValue::null().raw(),
        Err(common::Error::InvalidArgument(message)) => return crate::util::js_throw_type_error(ctx, &message),
        Err(err) => return js_throw_internal_error(ctx, &err.to_string()),
    };

    match sections.into_iter().find(|section| {
        section_name_matches(
            &section.segment_name,
            &section.section_name,
            &segment_name,
            &section_name,
        )
    }) {
        Some(section) => image_section_to_js(ctx, &section),
        None => JSValue::null().raw(),
    }
}

fn parse_load_command_query(query: &str) -> Option<u64> {
    let trimmed = query.trim();
    if trimmed.is_empty() {
        return None;
    }

    if let Some(hex) = trimmed.strip_prefix("0x").or_else(|| trimmed.strip_prefix("0X")) {
        return u64::from_str_radix(hex, 16).ok();
    }

    trimmed.parse::<u64>().ok()
}

fn normalize_load_command_name_for_query(name: &str) -> String {
    let trimmed = name.trim();
    let without_prefix = trimmed
        .strip_prefix("LC_")
        .or_else(|| trimmed.strip_prefix("lc_"))
        .or_else(|| trimmed.strip_prefix("LC-"))
        .or_else(|| trimmed.strip_prefix("lc-"))
        .unwrap_or(trimmed);
    let without_required = without_prefix.strip_suffix("_REQ_DYLD").unwrap_or(without_prefix);
    without_required
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .map(|ch| ch.to_ascii_lowercase())
        .collect()
}

fn load_command_matches_query(command: &native_api::ImageLoadCommand, query: &str) -> bool {
    let trimmed = query.trim();
    if trimmed.is_empty() {
        return false;
    }

    if let Some(value) = parse_load_command_query(trimmed) {
        if command.index as u64 == value {
            return true;
        }

        let raw = command.command as u64;
        let masked = (command.command & !0x8000_0000) as u64;
        if raw == value || masked == value {
            return true;
        }
    }

    command.command_name.eq_ignore_ascii_case(trimmed)
        || normalize_load_command_name_for_query(&command.command_name)
            == normalize_load_command_name_for_query(trimmed)
}

unsafe extern "C" fn js_native_load_command_info(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 2 {
        return crate::util::js_throw_type_error(
            ctx,
            "Native.loadCommandInfo(moduleName, commandOrIndex) requires 2 arguments",
        );
    }

    let module_name = match JSValue(*argv).to_string(ctx) {
        Some(value) if !value.trim().is_empty() => value,
        _ => {
            return crate::util::js_throw_type_error(
                ctx,
                "Native.loadCommandInfo(moduleName, commandOrIndex) requires moduleName to be a non-empty string",
            )
        }
    };

    let query = match JSValue(*argv.add(1)).to_string(ctx) {
        Some(value) if !value.trim().is_empty() => value,
        _ => {
            return crate::util::js_throw_type_error(
                ctx,
                "Native.loadCommandInfo(moduleName, commandOrIndex) requires commandOrIndex to be a non-empty string or number",
            )
        }
    };

    let commands = match find_image_load_commands(&module_name) {
        Ok(commands) => commands,
        Err(common::Error::Unsupported(_)) => return JSValue::null().raw(),
        Err(common::Error::InvalidArgument(message)) => return crate::util::js_throw_type_error(ctx, &message),
        Err(err) => return js_throw_internal_error(ctx, &err.to_string()),
    };

    match commands
        .into_iter()
        .find(|command| load_command_matches_query(command, &query))
    {
        Some(command) => image_load_command_to_js(ctx, &command),
        None => JSValue::null().raw(),
    }
}

pub(crate) fn register_native_api(ctx: &JSContext) {
    let global = ctx.global_object();
    let native = ctx.new_object();
    native.set_property(ctx.as_ptr(), "platform", JSValue::string(ctx.as_ptr(), "ios"));
    native.set_property(ctx.as_ptr(), "backend", JSValue::string(ctx.as_ptr(), "mach"));
    native.set_property(ctx.as_ptr(), "instrumentation", unsafe {
        JSValue(instrumentation_capability_to_js(ctx.as_ptr()))
    });
    native.set_property(
        ctx.as_ptr(),
        "instrumentationBackend",
        JSValue::string(ctx.as_ptr(), "arm64-hook-engine"),
    );
    native.set_property(
        ctx.as_ptr(),
        "androidReferenceInstrumentationBackend",
        JSValue::string(ctx.as_ptr(), "QBDI"),
    );
    native.set_property(ctx.as_ptr(), "qbdiCompatible", JSValue::bool(false));
    native.set_property(ctx.as_ptr(), "qbdiAvailable", JSValue::bool(false));
    native.set_property(ctx.as_ptr(), "traceAvailable", JSValue::bool(true));
    native.set_property(ctx.as_ptr(), "stalkerAvailable", JSValue::bool(true));
    native.set_property(
        ctx.as_ptr(),
        "recommendedInstrumentationPath",
        JSValue::string(ctx.as_ptr(), "trace-stalker-inline-hook"),
    );
    native.set_property(
        ctx.as_ptr(),
        "symbolSupportAvailable",
        JSValue::bool(native_symbol_support_available()),
    );
    native.set_property(
        ctx.as_ptr(),
        "exportSupportAvailable",
        JSValue::bool(native_export_support_available()),
    );
    native.set_property(
        ctx.as_ptr(),
        "dependencySupportAvailable",
        JSValue::bool(image_dependency_support_available()),
    );
    native.set_property(
        ctx.as_ptr(),
        "encryptionInfoSupportAvailable",
        JSValue::bool(image_encryption_info_support_available()),
    );
    native.set_property(
        ctx.as_ptr(),
        "dyldInfoSupportAvailable",
        JSValue::bool(image_dyld_info_support_available()),
    );
    native.set_property(
        ctx.as_ptr(),
        "entryPointSupportAvailable",
        JSValue::bool(image_entry_point_support_available()),
    );
    native.set_property(
        ctx.as_ptr(),
        "sourceVersionSupportAvailable",
        JSValue::bool(image_source_version_support_available()),
    );
    native.set_property(
        ctx.as_ptr(),
        "buildVersionSupportAvailable",
        JSValue::bool(image_build_version_support_available()),
    );
    native.set_property(
        ctx.as_ptr(),
        "dylinkerSupportAvailable",
        JSValue::bool(image_dylinker_support_available()),
    );
    native.set_property(
        ctx.as_ptr(),
        "installNameSupportAvailable",
        JSValue::bool(image_install_name_support_available()),
    );
    native.set_property(
        ctx.as_ptr(),
        "linkeditSupportAvailable",
        JSValue::bool(image_linkedit_info_support_available()),
    );
    native.set_property(
        ctx.as_ptr(),
        "functionStartsSupportAvailable",
        JSValue::bool(image_function_starts_support_available()),
    );
    native.set_property(
        ctx.as_ptr(),
        "codeSignatureSupportAvailable",
        JSValue::bool(image_code_signature_support_available()),
    );
    native.set_property(
        ctx.as_ptr(),
        "dataInCodeSupportAvailable",
        JSValue::bool(image_data_in_code_support_available()),
    );
    native.set_property(
        ctx.as_ptr(),
        "exportsTrieSupportAvailable",
        JSValue::bool(image_exports_trie_support_available()),
    );
    native.set_property(
        ctx.as_ptr(),
        "chainedFixupsSupportAvailable",
        JSValue::bool(image_chained_fixups_support_available()),
    );
    native.set_property(
        ctx.as_ptr(),
        "uuidSupportAvailable",
        JSValue::bool(image_uuid_support_available()),
    );

    native.set_property(
        ctx.as_ptr(),
        "rpathSupportAvailable",
        JSValue::bool(image_rpath_support_available()),
    );
    native.set_property(
        ctx.as_ptr(),
        "importSupportAvailable",
        JSValue::bool(image_import_support_available()),
    );
    native.set_property(
        ctx.as_ptr(),
        "segmentSupportAvailable",
        JSValue::bool(image_segment_support_available()),
    );
    native.set_property(
        ctx.as_ptr(),
        "sectionSupportAvailable",
        JSValue::bool(image_section_support_available()),
    );
    native.set_property(
        ctx.as_ptr(),
        "loadCommandSupportAvailable",
        JSValue::bool(image_load_command_support_available()),
    );

    unsafe {
        add_cfunction_to_object(
            ctx.as_ptr(),
            native.raw(),
            "detectHookEnvironment",
            js_native_detect_hook_environment,
            0,
        );
        add_cfunction_to_object(ctx.as_ptr(), native.raw(), "images", js_native_images, 1);
        add_cfunction_to_object(ctx.as_ptr(), native.raw(), "export", js_native_export, 2);
        add_cfunction_to_object(ctx.as_ptr(), native.raw(), "base", js_native_base, 1);
        add_cfunction_to_object(ctx.as_ptr(), native.raw(), "findBase", js_native_base, 1);
        add_cfunction_to_object(ctx.as_ptr(), native.raw(), "mainImage", js_native_main_image, 0);
        add_cfunction_to_object(ctx.as_ptr(), native.raw(), "findMainImage", js_native_main_image, 0);
        add_cfunction_to_object(ctx.as_ptr(), native.raw(), "image", js_native_image, 1);
        add_cfunction_to_object(ctx.as_ptr(), native.raw(), "findImage", js_native_image, 1);
        add_cfunction_to_object(ctx.as_ptr(), native.raw(), "symbol", js_native_symbol, 1);
        add_cfunction_to_object(ctx.as_ptr(), native.raw(), "findSymbol", js_native_symbol, 1);
        add_cfunction_to_object(ctx.as_ptr(), native.raw(), "findSymbols", js_native_find_symbols, 2);
        add_cfunction_to_object(ctx.as_ptr(), native.raw(), "symbols", js_native_find_symbols, 2);
        add_cfunction_to_object(ctx.as_ptr(), native.raw(), "symbolInfo", js_native_symbol_info, 2);
        add_cfunction_to_object(ctx.as_ptr(), native.raw(), "findSymbolInfo", js_native_symbol_info, 2);
        add_cfunction_to_object(ctx.as_ptr(), native.raw(), "imageInfo", js_native_image_info, 1);
        add_cfunction_to_object(ctx.as_ptr(), native.raw(), "findImageInfo", js_native_image_info, 1);
        add_cfunction_to_object(ctx.as_ptr(), native.raw(), "findExports", js_native_find_exports, 2);
        add_cfunction_to_object(ctx.as_ptr(), native.raw(), "exports", js_native_find_exports, 2);
        add_cfunction_to_object(ctx.as_ptr(), native.raw(), "exportInfo", js_native_export_info, 2);
        add_cfunction_to_object(ctx.as_ptr(), native.raw(), "findExportInfo", js_native_export_info, 2);
        add_cfunction_to_object(
            ctx.as_ptr(),
            native.raw(),
            "findDependencies",
            js_native_find_dependencies,
            2,
        );
        add_cfunction_to_object(
            ctx.as_ptr(),
            native.raw(),
            "dependencies",
            js_native_find_dependencies,
            2,
        );
        add_cfunction_to_object(
            ctx.as_ptr(),
            native.raw(),
            "dependencyInfo",
            js_native_dependency_info,
            2,
        );
        add_cfunction_to_object(
            ctx.as_ptr(),
            native.raw(),
            "findDependencyInfo",
            js_native_dependency_info,
            2,
        );
        add_cfunction_to_object(
            ctx.as_ptr(),
            native.raw(),
            "findEncryptionInfo",
            js_native_find_encryption_info,
            1,
        );
        add_cfunction_to_object(
            ctx.as_ptr(),
            native.raw(),
            "encryptionInfo",
            js_native_find_encryption_info,
            1,
        );
        add_cfunction_to_object(ctx.as_ptr(), native.raw(), "findDyldInfo", js_native_find_dyld_info, 1);
        add_cfunction_to_object(ctx.as_ptr(), native.raw(), "dyldInfo", js_native_find_dyld_info, 1);
        add_cfunction_to_object(
            ctx.as_ptr(),
            native.raw(),
            "findEntryPoint",
            js_native_find_entry_point,
            1,
        );
        add_cfunction_to_object(ctx.as_ptr(), native.raw(), "entryPoint", js_native_find_entry_point, 1);
        add_cfunction_to_object(
            ctx.as_ptr(),
            native.raw(),
            "findSourceVersion",
            js_native_find_source_version,
            1,
        );
        add_cfunction_to_object(
            ctx.as_ptr(),
            native.raw(),
            "sourceVersion",
            js_native_find_source_version,
            1,
        );
        add_cfunction_to_object(
            ctx.as_ptr(),
            native.raw(),
            "findBuildVersion",
            js_native_find_build_version,
            1,
        );
        add_cfunction_to_object(
            ctx.as_ptr(),
            native.raw(),
            "buildVersion",
            js_native_find_build_version,
            1,
        );
        add_cfunction_to_object(ctx.as_ptr(), native.raw(), "findDylinker", js_native_find_dylinker, 1);
        add_cfunction_to_object(ctx.as_ptr(), native.raw(), "dylinker", js_native_find_dylinker, 1);
        add_cfunction_to_object(
            ctx.as_ptr(),
            native.raw(),
            "findInstallName",
            js_native_find_install_name,
            1,
        );
        add_cfunction_to_object(
            ctx.as_ptr(),
            native.raw(),
            "installName",
            js_native_find_install_name,
            1,
        );
        add_cfunction_to_object(ctx.as_ptr(), native.raw(), "findLinkedit", js_native_find_linkedit, 1);
        add_cfunction_to_object(ctx.as_ptr(), native.raw(), "linkedit", js_native_find_linkedit, 1);
        add_cfunction_to_object(
            ctx.as_ptr(),
            native.raw(),
            "findFunctionStarts",
            js_native_find_function_starts,
            1,
        );
        add_cfunction_to_object(
            ctx.as_ptr(),
            native.raw(),
            "functionStarts",
            js_native_find_function_starts,
            1,
        );
        add_cfunction_to_object(
            ctx.as_ptr(),
            native.raw(),
            "findCodeSignature",
            js_native_find_code_signature,
            1,
        );
        add_cfunction_to_object(
            ctx.as_ptr(),
            native.raw(),
            "codeSignature",
            js_native_find_code_signature,
            1,
        );
        add_cfunction_to_object(
            ctx.as_ptr(),
            native.raw(),
            "findDataInCode",
            js_native_find_data_in_code,
            1,
        );
        add_cfunction_to_object(ctx.as_ptr(), native.raw(), "dataInCode", js_native_find_data_in_code, 1);
        add_cfunction_to_object(
            ctx.as_ptr(),
            native.raw(),
            "findExportsTrie",
            js_native_find_exports_trie,
            1,
        );
        add_cfunction_to_object(
            ctx.as_ptr(),
            native.raw(),
            "exportsTrie",
            js_native_find_exports_trie,
            1,
        );
        add_cfunction_to_object(
            ctx.as_ptr(),
            native.raw(),
            "findChainedFixups",
            js_native_find_chained_fixups,
            1,
        );
        add_cfunction_to_object(
            ctx.as_ptr(),
            native.raw(),
            "chainedFixups",
            js_native_find_chained_fixups,
            1,
        );
        add_cfunction_to_object(ctx.as_ptr(), native.raw(), "findUuid", js_native_find_uuid, 1);
        add_cfunction_to_object(ctx.as_ptr(), native.raw(), "uuid", js_native_find_uuid, 1);
        add_cfunction_to_object(ctx.as_ptr(), native.raw(), "findRpaths", js_native_find_rpaths, 2);
        add_cfunction_to_object(ctx.as_ptr(), native.raw(), "rpaths", js_native_find_rpaths, 2);
        add_cfunction_to_object(ctx.as_ptr(), native.raw(), "rpathInfo", js_native_rpath_info, 2);
        add_cfunction_to_object(ctx.as_ptr(), native.raw(), "findRpathInfo", js_native_rpath_info, 2);
        add_cfunction_to_object(ctx.as_ptr(), native.raw(), "findImports", js_native_find_imports, 2);
        add_cfunction_to_object(ctx.as_ptr(), native.raw(), "imports", js_native_find_imports, 2);
        add_cfunction_to_object(ctx.as_ptr(), native.raw(), "importInfo", js_native_import_info, 2);
        add_cfunction_to_object(ctx.as_ptr(), native.raw(), "findImportInfo", js_native_import_info, 2);
        add_cfunction_to_object(ctx.as_ptr(), native.raw(), "findSegments", js_native_find_segments, 1);
        add_cfunction_to_object(ctx.as_ptr(), native.raw(), "segments", js_native_find_segments, 1);
        add_cfunction_to_object(ctx.as_ptr(), native.raw(), "segmentInfo", js_native_segment_info, 2);
        add_cfunction_to_object(ctx.as_ptr(), native.raw(), "findSegmentInfo", js_native_segment_info, 2);
        add_cfunction_to_object(ctx.as_ptr(), native.raw(), "findSections", js_native_find_sections, 1);
        add_cfunction_to_object(ctx.as_ptr(), native.raw(), "sections", js_native_find_sections, 1);
        add_cfunction_to_object(ctx.as_ptr(), native.raw(), "sectionInfo", js_native_section_info, 3);
        add_cfunction_to_object(ctx.as_ptr(), native.raw(), "findSectionInfo", js_native_section_info, 3);
        add_cfunction_to_object(
            ctx.as_ptr(),
            native.raw(),
            "loadCommandInfo",
            js_native_load_command_info,
            2,
        );
        add_cfunction_to_object(
            ctx.as_ptr(),
            native.raw(),
            "findLoadCommandInfo",
            js_native_load_command_info,
            2,
        );
        add_cfunction_to_object(
            ctx.as_ptr(),
            native.raw(),
            "findLoadCommands",
            js_native_find_load_commands,
            1,
        );
        add_cfunction_to_object(
            ctx.as_ptr(),
            native.raw(),
            "loadCommands",
            js_native_find_load_commands,
            1,
        );
    }

    global.set_property(ctx.as_ptr(), "Native", native);
    global.free(ctx.as_ptr());
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_load_command(name: &str, command: u32, index: usize) -> native_api::ImageLoadCommand {
        native_api::ImageLoadCommand {
            module_name: "Demo".to_string(),
            module_base: 0x1000,
            index,
            command,
            command_size: 0x30,
            command_offset: 0x20,
            command_name: name.to_string(),
            detail: Some("raw".to_string()),
        }
    }

    #[test]
    fn load_command_query_matches_normalized_names_numbers_and_indexes() {
        let dyld = sample_load_command("LC_DYLD_INFO_ONLY", 0x8000_0022, 7);
        assert!(load_command_matches_query(&dyld, "LC_DYLD_INFO_ONLY"));
        assert!(load_command_matches_query(&dyld, "dyld_info_only"));
        assert!(load_command_matches_query(&dyld, "dyld-info-only"));
        assert!(load_command_matches_query(&dyld, "0x80000022"));
        assert!(load_command_matches_query(&dyld, "0x22"));
        assert!(load_command_matches_query(&dyld, "7"));

        let uuid = sample_load_command("LC_UUID", 0x1b, 2);
        assert!(load_command_matches_query(&uuid, "uuid"));
        assert!(load_command_matches_query(&uuid, "LC-UUID"));
        assert!(!load_command_matches_query(&uuid, "dyld_info_only"));
    }
}
