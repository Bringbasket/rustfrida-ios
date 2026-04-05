use crate::context::JSContext;
use crate::ffi;
use crate::ptr::{create_native_pointer, get_native_pointer_addr};
use crate::util::{
    add_cfunction_to_object, js_i64_to_js_number_or_bigint, js_throw_internal_error, js_u64_to_js_number_or_bigint,
};
use crate::value::JSValue;
use native_api::{
    detect_hook_environment, enumerate_images, find_export_by_name, find_image_build_version, find_image_by_address,
    find_image_by_name, find_image_chained_fixups, find_image_code_signature, find_image_data_in_code,
    find_image_dependencies, find_image_dyld_info, find_image_dylinker, find_image_encryption_info,
    find_image_entry_point, find_image_exports, find_image_exports_trie, find_image_function_starts,
    find_image_imports, find_image_install_name, find_image_linkedit_info, find_image_load_commands, find_image_rpaths,
    find_image_sections, find_image_segments, find_image_source_version, find_image_uuid, find_native_symbols,
    find_symbol_by_address, hook_coexistence_layer_status, hook_environment_recommendations,
    hook_environment_recommended_actions, image_build_version_support_available,
    image_chained_fixups_support_available, image_code_signature_support_available,
    image_data_in_code_support_available, image_dependency_support_available, image_dyld_info_support_available,
    image_dylinker_support_available, image_encryption_info_support_available, image_entry_point_support_available,
    image_exports_trie_support_available, image_function_starts_support_available, image_import_support_available,
    image_install_name_support_available, image_linkedit_info_support_available, image_load_command_support_available,
    image_rpath_support_available, image_section_support_available, image_segment_support_available,
    image_source_version_support_available, image_uuid_support_available, native_export_support_available,
    native_symbol_support_available, resolve_hook_strategy,
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

unsafe fn hook_recommended_action_to_js(
    ctx: *mut ffi::JSContext,
    action: &native_api::HookRecommendedAction,
) -> JSValue {
    let item = JSValue(ffi::JS_NewObject(ctx));
    item.set_property(ctx, "commandGroup", JSValue::string(ctx, &action.command_group));
    item.set_property(ctx, "actionKey", JSValue::string(ctx, &action.action_key));
    item.set_property(ctx, "priority", JSValue::int(action.priority as i32));
    item.set_property(ctx, "allowed", JSValue::bool(action.allowed));
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
    item.set_property(
        ctx,
        "timeoutHintMs",
        template_value.get_property(ctx, "timeoutHintMs"),
    );
    item.set_property(
        ctx,
        "timeoutAction",
        template_value.get_property(ctx, "timeoutAction"),
    );
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
    item.set_property(
        ctx,
        "placeholders",
        template_value.get_property(ctx, "placeholders"),
    );
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
    item.set_property(ctx, "onErrorCodes", JSValue(string_vec_to_js_array(ctx, on_error_codes)));
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

    match &report.active_backend {
        Some(active) => result.set_property(ctx, "activeBackend", JSValue::string(ctx, active)),
        None => result.set_property(ctx, "activeBackend", JSValue::null()),
    };
    result.set_property(ctx, "conflictState", JSValue::string(ctx, conflict_state));
    result.set_property(ctx, "riskLevel", JSValue::string(ctx, risk_level));
    result.set_property(ctx, "commandMode", JSValue::string(ctx, command_mode));
    result.set_property(ctx, "coexistenceMode", JSValue::string(ctx, coexistence_mode));
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
        "coexistenceLayerStatus",
        JSValue::string(ctx, coexistence_layer.status),
    );
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
    result.set_property(ctx, "loadedBackendCount", JSValue::int(loaded_backend_count as i32));
    result.set_property(
        ctx,
        "filesystemOnlyBackendCount",
        JSValue::int(filesystem_only_backend_count as i32),
    );
    result.set_property(ctx, "loadedImageCount", JSValue::int(loaded_image_count as i32));
    result.set_property(ctx, "filesystemPathCount", JSValue::int(filesystem_path_count as i32));

    if let Some(decision) = &decision {
        result.set_property(ctx, "policy", JSValue::string(ctx, decision.policy.as_str()));
        result.set_property(ctx, "strategy", JSValue::string(ctx, &decision.strategy));
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
            "hookStatusCommandsAllowed",
            JSValue::bool(decision.hook_status_commands_allowed()),
        );
        result.set_property(
            ctx,
            "hookStopCommandsAllowed",
            JSValue::bool(decision.hook_stop_commands_allowed()),
        );
        match &decision.reason {
            Some(reason) => result.set_property(ctx, "reason", JSValue::string(ctx, reason)),
            None => result.set_property(ctx, "reason", JSValue::null()),
        };
    } else {
        result.set_property(ctx, "policy", JSValue::string(ctx, "warn"));
        result.set_property(ctx, "strategy", JSValue::null());
        result.set_property(ctx, "allowed", JSValue::bool(true));
        result.set_property(ctx, "inlineHooksAllowed", JSValue::bool(true));
        result.set_property(ctx, "bootstrapInjectionAllowed", JSValue::bool(true));
        result.set_property(ctx, "queryCommandsAllowed", JSValue::bool(true));
        result.set_property(ctx, "hookInstallCommandsAllowed", JSValue::bool(true));
        result.set_property(ctx, "hookStatusCommandsAllowed", JSValue::bool(true));
        result.set_property(ctx, "hookStopCommandsAllowed", JSValue::bool(true));
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
    set_string_array_property(ctx, result.raw(), "suggestedSequence", &suggested_sequence);
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
                    result.set_property(ctx, "nextStep", step.dup(ctx));
                    result.set_property(ctx, "nextStepSource", JSValue::string(ctx, "next-action"));
                    result.set_property(ctx, "nextStepId", step.get_property(ctx, "id"));
                    result.set_property(ctx, "nextStepActionKey", step.get_property(ctx, "actionKey"));
                    result.set_property(ctx, "nextStepCommandGroup", step.get_property(ctx, "commandGroup"));
                    result.set_property(ctx, "nextStepAllowed", step.get_property(ctx, "allowed"));
                    result.set_property(ctx, "nextStepBlockedBy", step.get_property(ctx, "blockedBy"));
                    result.set_property(ctx, "nextStepBranch", step.get_property(ctx, "branch"));
                    result.set_property(ctx, "nextStepCommand", step.get_property(ctx, "command"));
                    result.set_property(ctx, "nextStepPhase", step.get_property(ctx, "phase"));
                    result.set_property(
                        ctx,
                        "nextStepCommandJsonEligible",
                        step.get_property(ctx, "commandJsonEligible"),
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
                    result.set_property(ctx, "activeStep", step.dup(ctx));
                    result.set_property(ctx, "activeStepSource", JSValue::string(ctx, "next-action"));
                    result.set_property(ctx, "activeStepAllowed", step.get_property(ctx, "allowed"));
                    result.set_property(ctx, "activeStepBlockedBy", step.get_property(ctx, "blockedBy"));
                    result.set_property(ctx, "activeStepBranch", step.get_property(ctx, "branch"));
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
                    result.set_property(ctx, "nextStepCommand", JSValue::null());
                    result.set_property(ctx, "nextStepPhase", JSValue::null());
                    result.set_property(ctx, "nextStepCommandJsonEligible", JSValue::null());
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
                    result.set_property(ctx, "activeStepActionKey", JSValue::null());
                    result.set_property(ctx, "activeStepCommandGroup", JSValue::null());
                    result.set_property(ctx, "activeStepId", JSValue::null());
                    result.set_property(ctx, "activeStepCommand", JSValue::null());
                    result.set_property(ctx, "activeStepPhase", JSValue::null());
                    result.set_property(ctx, "activeStepReadyToRun", JSValue::null());
                    result.set_property(ctx, "activeStepRequiresFallback", JSValue::null());
                    result.set_property(ctx, "activeStepKind", JSValue::null());
                    result.set_property(ctx, "activeStepCommandJsonEligible", JSValue::null());
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
            result.set_property(ctx, "nextStepCommand", JSValue::null());
            result.set_property(ctx, "nextStepPhase", JSValue::null());
            result.set_property(ctx, "nextStepCommandJsonEligible", JSValue::null());
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
            result.set_property(ctx, "activeStepActionKey", JSValue::null());
            result.set_property(ctx, "activeStepCommandGroup", JSValue::null());
            result.set_property(ctx, "activeStepId", JSValue::null());
            result.set_property(ctx, "activeStepCommand", JSValue::null());
            result.set_property(ctx, "activeStepPhase", JSValue::null());
            result.set_property(ctx, "activeStepReadyToRun", JSValue::null());
            result.set_property(ctx, "activeStepRequiresFallback", JSValue::null());
            result.set_property(ctx, "activeStepKind", JSValue::null());
            result.set_property(ctx, "activeStepCommandJsonEligible", JSValue::null());
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
            if entry_value
                .get_property(ctx, "retryable")
                .to_bool()
                .unwrap_or(false)
            {
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
                let candidates = error_code_routing_candidates
                    .entry(error_code.clone())
                    .or_default();
                if !candidates.iter().any(|candidate| candidate == &spec_index) {
                    candidates.push(spec_index);
                }
            }
        }
        let error_code_routing = JSValue(ffi::JS_NewObject(ctx));
        let error_code_routing_entries = ffi::JS_NewArray(ctx);
        let error_code_routing_resolved = JSValue(ffi::JS_NewObject(ctx));
        for (entry_index, (error_code, candidate_indices)) in error_code_routing_candidates.iter().enumerate() {
            let recommended = candidate_indices
                .first()
                .and_then(|index| escalation_specs.get(*index));
            let candidate_keys = candidate_indices
                .iter()
                .filter_map(|index| escalation_specs.get(*index).map(|spec| spec.0.clone()))
                .collect::<Vec<_>>();

            let recommended_escalation_key = recommended.map(|spec| spec.0.as_str());
            let recommended_phase = recommended.map(|spec| spec.2.as_str());
            let recommended_templates = recommended
                .map(|spec| spec.5.clone())
                .unwrap_or_default();
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
            let (resolved_command_json_templates, _) = hook_command_json_template_array_to_js(ctx, &recommended_templates);
            resolved.set_property(
                ctx,
                "commandJsonTemplateCount",
                JSValue::int(recommended_templates.len() as i32),
            );
            resolved.set_property(
                ctx,
                "commandJsonTemplates",
                JSValue(resolved_command_json_templates),
            );
            error_code_routing_resolved.set_property(ctx, error_code, resolved);
        }

        let retryable_phase_count = phase_order
            .iter()
            .filter(|phase| phase_retry_policy(phase).0)
            .count();
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
        termination_policy.set_property(
            ctx,
            "retryablePhaseCount",
            JSValue::int(retryable_phase_count as i32),
        );
        termination_policy.set_property(
            ctx,
            "nonRetryablePhaseCount",
            JSValue::int(non_retryable_phase_count as i32),
        );
        termination_policy.set_property(
            ctx,
            "retryableStepCount",
            JSValue::int(retryable_step_count as i32),
        );
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
        fallback_plan.set_property(ctx, "stepCount", JSValue::int(fallback_command_json_templates.len() as i32));
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
        fallback_plan.set_property(
            ctx,
            "errorCodeRoutingEntries",
            JSValue(error_code_routing_entries),
        );
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
                fallback_plan.set_property(ctx, "nextStep", step.dup(ctx));
                fallback_plan.set_property(ctx, "nextStepId", step.get_property(ctx, "id"));
                fallback_plan.set_property(ctx, "nextStepSource", step.get_property(ctx, "source"));
                fallback_plan.set_property(ctx, "nextStepActionKey", step.get_property(ctx, "actionKey"));
                fallback_plan.set_property(ctx, "nextStepCommandGroup", step.get_property(ctx, "commandGroup"));
                fallback_plan.set_property(ctx, "nextStepAllowed", step.get_property(ctx, "allowed"));
                fallback_plan.set_property(ctx, "nextStepBlockedBy", step.get_property(ctx, "blockedBy"));
                fallback_plan.set_property(ctx, "nextStepBranch", step.get_property(ctx, "branch"));
                fallback_plan.set_property(ctx, "nextStepCommand", step.get_property(ctx, "command"));
                fallback_plan.set_property(ctx, "nextStepPhase", step.get_property(ctx, "phase"));
                fallback_plan.set_property(
                    ctx,
                    "nextStepCommandJsonEligible",
                    step.get_property(ctx, "commandJsonEligible"),
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
                fallback_plan.set_property(
                    ctx,
                    "nextStepTimeoutHintMs",
                    step.get_property(ctx, "timeoutHintMs"),
                );
                fallback_plan.set_property(
                    ctx,
                    "nextStepTimeoutAction",
                    step.get_property(ctx, "timeoutAction"),
                );
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
                fallback_plan.set_property(
                    ctx,
                    "nextStepPlaceholders",
                    step.get_property(ctx, "placeholders"),
                );
                fallback_plan.set_property(ctx, "nextStepCliArgs", step.get_property(ctx, "cliArgs"));
                fallback_plan.set_property(ctx, "nextStepChainSource", JSValue::string(ctx, "fallback-plan"));
                fallback_plan.set_property(ctx, "nextStepChainLimit", JSValue::int(fallback_step_limit as i32));
                fallback_plan.set_property(ctx, "nextStepChainCount", JSValue::int(fallback_step_count as i32));
                fallback_plan.set_property(
                    ctx,
                    "nextStepChainTruncated",
                    JSValue::bool(fallback_step_truncated),
                );
                fallback_plan.set_property(ctx, "nextStepChain", JSValue(fallback_next_step_chain));
                fallback_plan.set_property(ctx, "activeStep", step.dup(ctx));
                fallback_plan.set_property(ctx, "activeStepSource", step.get_property(ctx, "source"));
                fallback_plan.set_property(ctx, "activeStepAllowed", step.get_property(ctx, "allowed"));
                fallback_plan.set_property(
                    ctx,
                    "activeStepBlockedBy",
                    step.get_property(ctx, "blockedBy"),
                );
                fallback_plan.set_property(ctx, "activeStepBranch", step.get_property(ctx, "branch"));
                fallback_plan.set_property(
                    ctx,
                    "activeStepActionKey",
                    step.get_property(ctx, "actionKey"),
                );
                fallback_plan.set_property(
                    ctx,
                    "activeStepCommandGroup",
                    step.get_property(ctx, "commandGroup"),
                );
                fallback_plan.set_property(ctx, "activeStepId", step.get_property(ctx, "id"));
                fallback_plan.set_property(
                    ctx,
                    "activeStepCommand",
                    step.get_property(ctx, "command"),
                );
                fallback_plan.set_property(ctx, "activeStepPhase", step.get_property(ctx, "phase"));
                fallback_plan.set_property(
                    ctx,
                    "activeStepReadyToRun",
                    step.get_property(ctx, "readyToRun"),
                );
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
                    "activeStepRetryable",
                    step.get_property(ctx, "retryable"),
                );
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
                fallback_plan.set_property(
                    ctx,
                    "activeStepTimeoutHintMs",
                    step.get_property(ctx, "timeoutHintMs"),
                );
                fallback_plan.set_property(
                    ctx,
                    "activeStepTimeoutAction",
                    step.get_property(ctx, "timeoutAction"),
                );
                fallback_plan.set_property(
                    ctx,
                    "activeStepErrorCode",
                    step.get_property(ctx, "errorCode"),
                );
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
                fallback_plan.set_property(
                    ctx,
                    "activeStepPlaceholders",
                    step.get_property(ctx, "placeholders"),
                );
                fallback_plan.set_property(ctx, "activeStepCliArgs", step.get_property(ctx, "cliArgs"));
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
                fallback_plan.set_property(ctx, "nextStepCommand", JSValue::null());
                fallback_plan.set_property(ctx, "nextStepPhase", JSValue::null());
                fallback_plan.set_property(ctx, "nextStepCommandJsonEligible", JSValue::null());
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
                fallback_plan.set_property(ctx, "activeStepActionKey", JSValue::null());
                fallback_plan.set_property(ctx, "activeStepCommandGroup", JSValue::null());
                fallback_plan.set_property(ctx, "activeStepId", JSValue::null());
                fallback_plan.set_property(ctx, "activeStepCommand", JSValue::null());
                fallback_plan.set_property(ctx, "activeStepPhase", JSValue::null());
                fallback_plan.set_property(ctx, "activeStepReadyToRun", JSValue::null());
                fallback_plan.set_property(ctx, "activeStepRequiresFallback", JSValue::null());
                fallback_plan.set_property(ctx, "activeStepKind", JSValue::null());
                fallback_plan.set_property(ctx, "activeStepCommandJsonEligible", JSValue::null());
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
        result.set_property(ctx, "nextStepActionKey", fallback_plan.get_property(ctx, "nextStepActionKey"));
        result.set_property(
            ctx,
            "nextStepCommandGroup",
            fallback_plan.get_property(ctx, "nextStepCommandGroup"),
        );
        result.set_property(ctx, "nextStepAllowed", fallback_plan.get_property(ctx, "nextStepAllowed"));
        result.set_property(
            ctx,
            "nextStepBlockedBy",
            fallback_plan.get_property(ctx, "nextStepBlockedBy"),
        );
        result.set_property(ctx, "nextStepBranch", fallback_plan.get_property(ctx, "nextStepBranch"));
        result.set_property(ctx, "nextStepCommand", fallback_plan.get_property(ctx, "nextStepCommand"));
        result.set_property(ctx, "nextStepPhase", fallback_plan.get_property(ctx, "nextStepPhase"));
        result.set_property(
            ctx,
            "nextStepCommandJsonEligible",
            fallback_plan.get_property(ctx, "nextStepCommandJsonEligible"),
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
        result.set_property(ctx, "nextStepErrorCode", fallback_plan.get_property(ctx, "nextStepErrorCode"));
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
        result.set_property(ctx, "nextStepCliArgs", fallback_plan.get_property(ctx, "nextStepCliArgs"));
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
        result.set_property(ctx, "activeStepSource", fallback_plan.get_property(ctx, "activeStepSource"));
        result.set_property(ctx, "activeStepAllowed", fallback_plan.get_property(ctx, "activeStepAllowed"));
        result.set_property(
            ctx,
            "activeStepBlockedBy",
            fallback_plan.get_property(ctx, "activeStepBlockedBy"),
        );
        result.set_property(ctx, "activeStepBranch", fallback_plan.get_property(ctx, "activeStepBranch"));
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
        result.set_property(ctx, "activeStepCommand", fallback_plan.get_property(ctx, "activeStepCommand"));
        result.set_property(ctx, "activeStepPhase", fallback_plan.get_property(ctx, "activeStepPhase"));
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
        result.set_property(ctx, "activeStepCliArgs", fallback_plan.get_property(ctx, "activeStepCliArgs"));
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
            "filesystemPathCount",
            JSValue::int(backend.filesystem_paths.len() as i32),
        );
        set_string_array_property(ctx, item.raw(), "loadedImages", &backend.loaded_images);
        set_string_array_property(ctx, item.raw(), "filesystemPaths", &backend.filesystem_paths);
        ffi::JS_SetPropertyUint32(ctx, backends, index as u32, item.raw());
    }
    result.set_property(ctx, "backends", JSValue(backends));

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

    match dependencies.into_iter().find(|dependency| {
        dependency.path == path_or_name
            || dependency
                .path
                .rsplit('/')
                .next()
                .map(|name| name == path_or_name)
                .unwrap_or(false)
    }) {
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

    match rpaths.into_iter().find(|rpath| rpath.path == path) {
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
        .find(|segment| segment.segment_name == segment_name)
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

    match sections
        .into_iter()
        .find(|section| section.segment_name == segment_name && section.section_name == section_name)
    {
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
        add_cfunction_to_object(ctx.as_ptr(), native.raw(), "mainImage", js_native_main_image, 0);
        add_cfunction_to_object(ctx.as_ptr(), native.raw(), "image", js_native_image, 1);
        add_cfunction_to_object(ctx.as_ptr(), native.raw(), "symbol", js_native_symbol, 1);
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
