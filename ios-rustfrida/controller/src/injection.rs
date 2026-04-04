use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::{self, ErrorKind, IsTerminal, Write},
    path::{Path, PathBuf},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use common::{
    decode_event, read_frame, write_frame, AgentCommand, AgentEvent, ControllerConfig, Error, Hello, InjectionMode,
    Result, DEFAULT_AGENT_PATH, DEFAULT_AGENT_PATH_ROOTFUL, FRAME_KIND_CMD, FRAME_KIND_CMD_JSON,
    LEGACY_AGENT_PATH_ROOTFUL,
};
use native_api::{
    enumerate_images, hook_coexistence_layer_status, hook_coexistence_layer_status_for_mode,
    hook_environment_recommendations, hook_environment_recommended_actions,
    probe_injection_environment, BootstrapStatus,
    InjectionEnvironmentReport, InjectionPlan, InjectionTarget, InjectionTargetPreflightReport, InjectionTrace,
    LoaderSymbolRole, MachInjector, ResolvedLoaderSymbol,
};
use serde_json::{json, Map, Value};

use crate::launch::spawn_target;

const DARWIN_SOCKADDR_UN_PATH_MAX: usize = 103;
const SOCKET_ACCEPT_POLL_INTERVAL: Duration = Duration::from_millis(25);
const CONTROLLER_PROMPT: &str = "iosrf> ";
const JS_PROMPT: &str = "js> ";

#[cfg(unix)]
use std::os::unix::net::{UnixListener, UnixStream};

#[cfg(unix)]
enum EvalReply {
    Ok(String),
    Err(String),
}

#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CommandOutcomeKind {
    Eval,
    Complete,
    Log,
}

#[cfg(unix)]
impl CommandOutcomeKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Eval => "eval",
            Self::Complete => "complete",
            Self::Log => "log",
        }
    }
}

#[cfg(unix)]
#[derive(Debug, Clone)]
struct CommandOutcome {
    command: String,
    kind: CommandOutcomeKind,
    ok: bool,
    payload: Option<String>,
    items: Vec<String>,
    error: Option<String>,
    logs: Vec<String>,
}

#[cfg(unix)]
#[derive(Debug, Clone, PartialEq, Eq)]
struct DoctorCheck {
    id: &'static str,
    status: &'static str,
    fatal: bool,
    summary: String,
    detail: Option<String>,
}

#[cfg(unix)]
#[derive(Debug, Clone, PartialEq, Eq)]
struct DoctorReport {
    ready: bool,
    warning_count: usize,
    failure_count: usize,
    checks: Vec<DoctorCheck>,
}

#[cfg(unix)]
struct CommandJsonContext<'a> {
    config: &'a ControllerConfig,
    pid: i32,
    socket_path: &'a str,
    plan: &'a InjectionPlan,
    injection_environment: &'a InjectionEnvironmentReport,
    doctor: &'a DoctorReport,
    preflight: &'a InjectionTargetPreflightReport,
    trace: Option<&'a InjectionTrace>,
    hello: Option<&'a Hello>,
    ping: Option<&'a str>,
    hook_environment_notice: Option<&'a str>,
    hook_environment_checked: bool,
    jsinit_result: Option<&'a str>,
    loadjs_result: Option<&'a str>,
}

#[cfg(unix)]
impl CommandOutcome {
    fn eval(command: &str, reply: EvalReply, logs: Vec<String>) -> Self {
        match reply {
            EvalReply::Ok(payload) => Self {
                command: command.into(),
                kind: CommandOutcomeKind::Eval,
                ok: true,
                payload: Some(payload),
                items: Vec::new(),
                error: None,
                logs,
            },
            EvalReply::Err(error) => Self {
                command: command.into(),
                kind: CommandOutcomeKind::Eval,
                ok: false,
                payload: None,
                items: Vec::new(),
                error: Some(error),
                logs,
            },
        }
    }

    fn complete(command: &str, items: Vec<String>, logs: Vec<String>) -> Self {
        Self {
            command: command.into(),
            kind: CommandOutcomeKind::Complete,
            ok: true,
            payload: None,
            items,
            error: None,
            logs,
        }
    }

    fn log(command: &str, payload: String, logs: Vec<String>) -> Self {
        Self {
            command: command.into(),
            kind: CommandOutcomeKind::Log,
            ok: true,
            payload: Some(payload),
            items: Vec::new(),
            error: None,
            logs,
        }
    }
}

#[cfg(unix)]
struct ControllerSocket {
    path: PathBuf,
    listener: UnixListener,
}

#[cfg(unix)]
impl ControllerSocket {
    fn bind_path(path: PathBuf) -> Result<Self> {
        validate_socket_path(&path)?;

        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)?;
            }
        }

        remove_socket_file_if_present(&path)?;
        let listener = UnixListener::bind(&path)?;
        listener.set_nonblocking(true)?;

        Ok(Self { path, listener })
    }

    fn accept(&self, timeout: Duration) -> Result<UnixStream> {
        let deadline = Instant::now() + timeout;
        loop {
            match self.listener.accept() {
                Ok((stream, _)) => {
                    stream.set_read_timeout(Some(timeout))?;
                    stream.set_write_timeout(Some(timeout))?;
                    return Ok(stream);
                }
                Err(err) if err.kind() == ErrorKind::WouldBlock => {
                    if Instant::now() >= deadline {
                        return Err(Error::State(format!(
                            "timed out waiting {}s for agent to connect to {}",
                            timeout.as_secs(),
                            self.path.display()
                        )));
                    }
                    thread::sleep(SOCKET_ACCEPT_POLL_INTERVAL);
                }
                Err(err) => return Err(err.into()),
            }
        }
    }
}

#[cfg(unix)]
impl Drop for ControllerSocket {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

#[cfg(unix)]
fn render_loader_symbol(symbol: &ResolvedLoaderSymbol) -> String {
    let thread_bootstrap_kind = symbol
        .thread_bootstrap_kind()
        .map(|kind| format!(" kind={}", kind.as_str()))
        .unwrap_or_default();
    if symbol.is_canonicalized() {
        format!(
            " - [{}] {}{} => raw=0x{:x} canonical=0x{:x} {} + 0x{:x}",
            symbol.role.as_str(),
            symbol.symbol_name,
            thread_bootstrap_kind,
            symbol.raw_address,
            symbol.address,
            symbol.module_name,
            symbol.offset
        )
    } else {
        format!(
            " - [{}] {}{} => 0x{:x} {} + 0x{:x}",
            symbol.role.as_str(),
            symbol.symbol_name,
            thread_bootstrap_kind,
            symbol.address,
            symbol.module_name,
            symbol.offset
        )
    }
}

#[cfg(unix)]
fn injection_mode_label(mode: InjectionMode) -> &'static str {
    match mode {
        InjectionMode::Attach => "attach",
        InjectionMode::Spawn => "spawn",
    }
}

#[cfg(unix)]
fn json_hex_u64(value: u64) -> String {
    format!("0x{value:x}")
}

#[cfg(unix)]
fn json_hex_usize(value: usize) -> String {
    format!("0x{value:x}")
}

#[cfg(unix)]
fn json_hex_isize(value: isize) -> String {
    if value < 0 {
        format!("-0x{:x}", value.unsigned_abs())
    } else {
        format!("0x{:x}", value as usize)
    }
}

#[cfg(unix)]
fn image_info_to_json(image: &native_api::ImageInfo) -> Value {
    let name = Path::new(&image.name)
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or(&image.name);
    json!({
        "name": name,
        "path": image.name,
        "base": image.base,
        "baseHex": json_hex_usize(image.base),
        "slide": image.slide,
        "slideHex": json_hex_isize(image.slide),
        "size": image.size,
        "sizeHex": json_hex_usize(image.size),
    })
}

#[cfg(unix)]
fn image_name_matches(module_name: &str, image_name: &str) -> bool {
    if image_name == module_name {
        return true;
    }

    let module_basename = Path::new(module_name).file_name().and_then(|name| name.to_str());
    let image_basename = Path::new(image_name).file_name().and_then(|name| name.to_str());

    match (module_basename, image_basename) {
        (Some(module_basename), Some(image_basename)) => module_basename == image_basename,
        _ => false,
    }
}

#[cfg(unix)]
fn hook_backend_to_json(backend: &native_api::HookBackendInfo) -> Value {
    json!({
        "id": backend.id,
        "displayName": backend.display_name,
        "loaded": !backend.loaded_images.is_empty(),
        "presentOnFilesystem": !backend.filesystem_paths.is_empty(),
        "loadedImageCount": backend.loaded_images.len(),
        "filesystemPathCount": backend.filesystem_paths.len(),
        "loadedImages": backend.loaded_images,
        "filesystemPaths": backend.filesystem_paths,
    })
}

#[cfg(unix)]
fn hook_strategy_to_json(strategy: &native_api::HookStrategyDecision) -> Value {
    json!({
        "policy": strategy.policy.as_str(),
        "strategy": strategy.strategy,
        "commandMode": strategy.command_mode(),
        "allowed": strategy.allowed,
        "inlineHooksAllowed": strategy.inline_hooks_allowed,
        "bootstrapInjectionAllowed": strategy.bootstrap_injection_allowed(),
        "queryCommandsAllowed": strategy.query_commands_allowed(),
        "hookInstallCommandsAllowed": strategy.hook_install_commands_allowed(),
        "hookStatusCommandsAllowed": strategy.hook_status_commands_allowed(),
        "hookStopCommandsAllowed": strategy.hook_stop_commands_allowed(),
        "reason": strategy.reason,
    })
}

#[cfg(unix)]
fn hook_strategy_capabilities_to_json(strategy: &native_api::HookStrategyDecision) -> Value {
    json!({
        "bootstrapInjectionAllowed": strategy.bootstrap_injection_allowed(),
        "queryCommandsAllowed": strategy.query_commands_allowed(),
        "hookInstallCommandsAllowed": strategy.hook_install_commands_allowed(),
        "hookStatusCommandsAllowed": strategy.hook_status_commands_allowed(),
        "hookStopCommandsAllowed": strategy.hook_stop_commands_allowed(),
    })
}

#[cfg(unix)]
fn hook_shortcut_entry_to_json(
    strategy: &native_api::HookStrategyDecision,
    recommended_actions: &[native_api::HookRecommendedAction],
) -> Value {
    json!({
        "policy": strategy.policy.as_str(),
        "strategy": strategy.strategy,
        "commandMode": strategy.command_mode(),
        "reason": strategy.reason,
        "capabilities": hook_strategy_capabilities_to_json(strategy),
        "recommendedActions": recommended_actions
            .iter()
            .map(hook_recommended_action_to_json)
            .collect::<Vec<_>>(),
    })
}

#[cfg(unix)]
#[derive(Debug, Clone, PartialEq, Eq)]
struct HookEffectiveAction {
    action_key: &'static str,
    command_group: &'static str,
    allowed: bool,
    blocked_by: &'static str,
    priority: u8,
    controller_allowed: bool,
    target_allowed: bool,
    controller_priority: u8,
    target_priority: u8,
    recommendation: String,
    controller_reason: Option<String>,
    target_reason: Option<String>,
}

#[cfg(unix)]
const HOOK_EFFECTIVE_ACTIONS: &[(&str, &str)] = &[
    ("hook.query", "query"),
    ("hook.bootstrap", "bootstrap"),
    ("hook.install", "hook-install"),
    ("hook.status", "hook-status"),
    ("hook.stop", "hook-stop"),
];

#[cfg(unix)]
fn hook_effective_action(
    action_key: &'static str,
    command_group: &'static str,
    controller_action: Option<&native_api::HookRecommendedAction>,
    target_action: Option<&native_api::HookRecommendedAction>,
) -> HookEffectiveAction {
    let controller_allowed = controller_action.map(|item| item.allowed).unwrap_or(true);
    let target_allowed = target_action.map(|item| item.allowed).unwrap_or(true);
    let allowed = controller_allowed && target_allowed;
    let blocked_by = match (controller_allowed, target_allowed) {
        (true, true) => "none",
        (false, true) => "controller",
        (true, false) => "target",
        (false, false) => "both",
    };

    let controller_priority = controller_action.map(|item| item.priority).unwrap_or(0);
    let target_priority = target_action.map(|item| item.priority).unwrap_or(0);
    let priority = if allowed {
        controller_priority.max(target_priority)
    } else {
        controller_priority.max(target_priority).max(1)
    };

    let recommendation = match blocked_by {
        "controller" => controller_action
            .map(|item| item.recommendation.clone())
            .unwrap_or_else(|| "blocked by controller hook policy".into()),
        "target" => target_action
            .map(|item| item.recommendation.clone())
            .unwrap_or_else(|| "blocked by target hook policy".into()),
        "both" => "blocked by both controller and target hook policies; inspect each side recommendation for details"
            .into(),
        _ => controller_action
            .or(target_action)
            .map(|item| item.recommendation.clone())
            .unwrap_or_else(|| "allowed under current hook policies".into()),
    };

    HookEffectiveAction {
        action_key,
        command_group,
        allowed,
        blocked_by,
        priority,
        controller_allowed,
        target_allowed,
        controller_priority,
        target_priority,
        recommendation,
        controller_reason: controller_action.and_then(|item| item.reason.clone()),
        target_reason: target_action.and_then(|item| item.reason.clone()),
    }
}

#[cfg(unix)]
fn hook_effective_actions(
    controller_actions: &[native_api::HookRecommendedAction],
    target_actions: &[native_api::HookRecommendedAction],
) -> Vec<HookEffectiveAction> {
    HOOK_EFFECTIVE_ACTIONS
        .iter()
        .map(|(action_key, command_group)| {
            let controller_action = controller_actions.iter().find(|item| item.action_key == *action_key);
            let target_action = target_actions.iter().find(|item| item.action_key == *action_key);
            hook_effective_action(action_key, command_group, controller_action, target_action)
        })
        .collect::<Vec<_>>()
}

#[cfg(unix)]
fn hook_effective_actions_to_json(actions: &[HookEffectiveAction]) -> Value {
    Value::Array(
        actions
            .iter()
            .map(|item| {
                json!({
                    "actionKey": item.action_key,
                    "commandGroup": item.command_group,
                    "allowed": item.allowed,
                    "status": if item.allowed { "allowed" } else { "blocked" },
                    "blockedBy": item.blocked_by,
                    "priority": item.priority,
                    "controllerAllowed": item.controller_allowed,
                    "targetAllowed": item.target_allowed,
                    "controllerPriority": item.controller_priority,
                    "targetPriority": item.target_priority,
                    "recommendation": item.recommendation,
                    "controllerReason": item.controller_reason,
                    "targetReason": item.target_reason,
                })
            })
            .collect::<Vec<_>>(),
    )
}

#[cfg(unix)]
fn hook_effective_allowed_for(actions: &[HookEffectiveAction], action_key: &str) -> bool {
    actions
        .iter()
        .find(|item| item.action_key == action_key)
        .map(|item| item.allowed)
        .unwrap_or(true)
}

#[cfg(unix)]
fn hook_effective_command_mode(actions: &[HookEffectiveAction]) -> &'static str {
    let query_commands_allowed = hook_effective_allowed_for(actions, "hook.query");
    let hook_install_commands_allowed = hook_effective_allowed_for(actions, "hook.install");
    let hook_status_commands_allowed = hook_effective_allowed_for(actions, "hook.status");
    let hook_stop_commands_allowed = hook_effective_allowed_for(actions, "hook.stop");
    if hook_install_commands_allowed {
        "allowed"
    } else if query_commands_allowed {
        "query-only"
    } else if hook_status_commands_allowed || hook_stop_commands_allowed {
        "cleanup-only"
    } else {
        "blocked"
    }
}

#[cfg(unix)]
const HOOK_MODE_AUTO_DOWNGRADE_REASON_SPLIT_BACKEND_LOADED: &str =
    "split-loaded-external-backends-without-shared-runtime";

#[cfg(unix)]
fn hook_command_mode_with_backend_pressure(
    base_command_mode: &'static str,
    loaded_in_controller_count: u64,
    loaded_in_target_count: u64,
    loaded_in_both_count: u64,
) -> (&'static str, bool, Option<&'static str>) {
    if base_command_mode == "allowed"
        && loaded_in_controller_count > 0
        && loaded_in_target_count > 0
        && loaded_in_both_count == 0
    {
        (
            "query-only",
            true,
            Some(HOOK_MODE_AUTO_DOWNGRADE_REASON_SPLIT_BACKEND_LOADED),
        )
    } else {
        (base_command_mode, false, None)
    }
}

#[cfg(unix)]
fn hook_effective_to_json(actions: &[HookEffectiveAction]) -> Value {
    let allowed_for = |action_key: &str| {
        hook_effective_allowed_for(actions, action_key)
    };
    let bootstrap_injection_allowed = allowed_for("hook.bootstrap");
    let query_commands_allowed = allowed_for("hook.query");
    let hook_install_commands_allowed = allowed_for("hook.install");
    let hook_status_commands_allowed = allowed_for("hook.status");
    let hook_stop_commands_allowed = allowed_for("hook.stop");
    let command_mode = hook_effective_command_mode(actions);

    let allowed_action_count = actions.iter().filter(|item| item.allowed).count();
    let blocked_action_count = actions.len().saturating_sub(allowed_action_count);
    let blocked_by_controller_count = actions
        .iter()
        .filter(|item| matches!(item.blocked_by, "controller" | "both"))
        .count();
    let blocked_by_target_count = actions
        .iter()
        .filter(|item| matches!(item.blocked_by, "target" | "both"))
        .count();
    let blocked_by_both_count = actions.iter().filter(|item| item.blocked_by == "both").count();
    let highest_priority = actions.iter().map(|item| item.priority).max().unwrap_or(0);

    json!({
        "commandMode": command_mode,
        "capabilities": {
            "bootstrapInjectionAllowed": bootstrap_injection_allowed,
            "queryCommandsAllowed": query_commands_allowed,
            "hookInstallCommandsAllowed": hook_install_commands_allowed,
            "hookStatusCommandsAllowed": hook_status_commands_allowed,
            "hookStopCommandsAllowed": hook_stop_commands_allowed,
        },
        "allowedActionCount": allowed_action_count,
        "blockedActionCount": blocked_action_count,
        "highestPriority": highest_priority,
        "blockedBySummary": {
            "controller": blocked_by_controller_count,
            "target": blocked_by_target_count,
            "both": blocked_by_both_count,
        },
    })
}

#[cfg(unix)]
fn hook_coexistence_to_json(actions: &[HookEffectiveAction], backend_matrix: &Value) -> Value {
    let base_command_mode = hook_effective_command_mode(actions);
    let loaded_in_controller_count = json_u64_field(backend_matrix, "loadedInControllerCount");
    let loaded_in_target_count = json_u64_field(backend_matrix, "loadedInTargetCount");
    let loaded_in_both_count = json_u64_field(backend_matrix, "loadedInBothCount");
    let filesystem_only_in_either_count = json_u64_field(backend_matrix, "filesystemOnlyInEitherCount");
    let shared_backend_count = json_array_len(backend_matrix, "sharedBackendIds");
    let total_loaded_backend_count =
        loaded_in_controller_count + loaded_in_target_count - loaded_in_both_count;
    let (command_mode, auto_downgraded_to_query_only, auto_downgrade_reason) =
        hook_command_mode_with_backend_pressure(
            base_command_mode,
            loaded_in_controller_count,
            loaded_in_target_count,
            loaded_in_both_count,
        );

    let backend_pressure = if loaded_in_controller_count > 0 && loaded_in_target_count > 0 {
        "both"
    } else if loaded_in_controller_count > 0 {
        "controller"
    } else if loaded_in_target_count > 0 {
        "target"
    } else if filesystem_only_in_either_count > 0 {
        "filesystem-only"
    } else {
        "none"
    };

    let mode = match command_mode {
        "allowed" => {
            if backend_pressure == "none" {
                "inline-safe"
            } else if backend_pressure == "filesystem-only" {
                "inline-cautious"
            } else {
                "inline-risky"
            }
        }
        "query-only" => "query-only",
        "cleanup-only" => "cleanup-only",
        _ => "blocked",
    };
    let strategy = match mode {
        "inline-safe" => "internal-inline-preferred",
        "inline-cautious" => "filesystem-candidate-cautious",
        "inline-risky" => "external-backend-coexist-risky",
        "query-only" => "query-only-fallback",
        "cleanup-only" => "cleanup-only-fallback",
        _ => "blocked-no-compatible-path",
    };
    let risk_level = match mode {
        "blocked" => "blocked",
        "cleanup-only" => "high",
        "inline-cautious" => "cautious",
        "query-only" => "elevated",
        "inline-risky" => "elevated",
        _ => "normal",
    };

    let mode_rank = |action_key: &str| -> u8 {
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
                "hook.bootstrap" => 1,
                "hook.status" => 2,
                "hook.stop" => 3,
                "hook.install" => 4,
                _ => 5,
            },
            "blocked" => match action_key {
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
    };

    let recommended_action = actions
        .iter()
        .filter(|item| item.allowed)
        .min_by_key(|item| (mode_rank(item.action_key), item.priority, hook_effective_action_order(item.action_key)))
        .or_else(|| {
            actions
                .iter()
                .filter(|item| !item.allowed)
                .min_by_key(|item| {
                    (mode_rank(item.action_key), item.priority, hook_effective_action_order(item.action_key))
                })
        });

    let preferred_path = mode;
    let next_action_templates = recommended_action
        .map(|item| hook_action_command_templates(item.action_key, preferred_path))
        .unwrap_or_default();
    let next_action_command_json_templates = next_action_templates
        .iter()
        .map(|template| command_json_template_entry(template))
        .collect::<Vec<_>>();
    let next_step_command = next_action_templates.first().cloned();
    let next_step_command_json_template = next_action_command_json_templates.first().cloned();
    let next_step_phase = next_step_command_json_template
        .as_ref()
        .and_then(|entry| entry.get("phase"))
        .and_then(Value::as_str)
        .map(ToOwned::to_owned);
    let next_step_command_json_eligible = next_step_command_json_template
        .as_ref()
        .and_then(|entry| entry.get("commandJsonEligible"))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let next_step_id = recommended_action.and_then(|item| {
        next_step_command
            .as_ref()
            .map(|_| format!("next-action:{}:0", item.action_key))
    });
    let next_step = recommended_action
        .map(|item| {
            json!({
                "id": next_step_id.clone(),
                "actionKey": item.action_key,
                "commandGroup": item.command_group,
                "allowed": item.allowed,
                "branch": hook_automation_branch(item),
                "reason": item.recommendation,
                "preferredPath": preferred_path,
                "readyToRun": item.allowed,
                "requiresFallback": !item.allowed,
                "command": next_step_command.clone(),
                "phase": next_step_phase.clone(),
                "commandJsonEligible": next_step_command_json_eligible,
                "commandJsonTemplate": next_step_command_json_template.clone(),
            })
        })
        .unwrap_or(Value::Null);
    let next_step_chain_limit = 3usize;
    let next_step_chain = recommended_action
        .map(|item| {
            next_action_command_json_templates
                .iter()
                .take(next_step_chain_limit)
                .enumerate()
                .map(|(index, entry)| {
                    json!({
                        "id": format!("next-action:{}:{}", item.action_key, index),
                        "index": index,
                        "source": "next-action",
                        "actionKey": item.action_key,
                        "commandGroup": item.command_group,
                        "allowed": item.allowed,
                        "blockedBy": item.blocked_by,
                        "branch": hook_automation_branch(item),
                        "command": entry.get("command").cloned().unwrap_or(Value::Null),
                        "phase": entry.get("phase").cloned().unwrap_or(Value::Null),
                        "readyToRun": item.allowed,
                        "requiresFallback": !item.allowed,
                        "kind": entry.get("kind").cloned().unwrap_or(Value::Null),
                        "commandJsonEligible": entry
                            .get("commandJsonEligible")
                            .cloned()
                            .unwrap_or(Value::Null),
                        "retryable": entry.get("retryable").cloned().unwrap_or(Value::Null),
                        "maxSuggestedRetries": entry
                            .get("maxSuggestedRetries")
                            .cloned()
                            .unwrap_or(Value::Null),
                        "retryDelayHintMs": entry
                            .get("retryDelayHintMs")
                            .cloned()
                            .unwrap_or(Value::Null),
                        "timeoutHintMs": entry
                            .get("timeoutHintMs")
                            .cloned()
                            .unwrap_or(Value::Null),
                        "timeoutAction": entry
                            .get("timeoutAction")
                            .cloned()
                            .unwrap_or(Value::Null),
                        "errorCode": entry.get("errorCode").cloned().unwrap_or(Value::Null),
                        "timeoutErrorCode": entry
                            .get("timeoutErrorCode")
                            .cloned()
                            .unwrap_or(Value::Null),
                        "risk": entry.get("risk").cloned().unwrap_or(Value::Null),
                        "placeholderCount": entry
                            .get("placeholderCount")
                            .cloned()
                            .unwrap_or(Value::Null),
                        "placeholders": entry
                            .get("placeholders")
                            .cloned()
                            .unwrap_or(Value::Null),
                        "cliArgs": entry.get("cliArgs").cloned().unwrap_or(Value::Null),
                    })
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let next_step_chain_source = if recommended_action.is_some() {
        "next-action"
    } else {
        "none"
    };
    let active_step = next_step_chain.first();
    let next_step_chain_truncated = next_action_command_json_templates.len() > next_step_chain_limit;

    let install_action = actions.iter().find(|item| item.action_key == "hook.install");
    let external_backend_loaded = loaded_in_controller_count > 0 || loaded_in_target_count > 0;
    let single_external_backend_loaded = total_loaded_backend_count == 1;
    let multiple_external_backends_loaded = total_loaded_backend_count > 1;
    let controller_multiple_external_backends_loaded = loaded_in_controller_count > 1;
    let target_multiple_external_backends_loaded = loaded_in_target_count > 1;
    let coexistence_layer = hook_coexistence_layer_status_for_mode(
        Some(command_mode),
        external_backend_loaded,
        filesystem_only_in_either_count > 0,
    );

    json!({
        "mode": mode,
        "strategy": strategy,
        "riskLevel": risk_level,
        "coexistenceLayerAvailable": coexistence_layer.available,
        "coexistenceLayerStatus": coexistence_layer.status,
        "baseCommandMode": base_command_mode,
        "effectiveCommandMode": command_mode,
        "commandMode": command_mode,
        "autoDowngradedToQueryOnly": auto_downgraded_to_query_only,
        "autoDowngradeReason": auto_downgrade_reason,
        "backendPressure": backend_pressure,
        "externalBackendLoaded": external_backend_loaded,
        "singleExternalBackendLoaded": single_external_backend_loaded,
        "multipleExternalBackendsLoaded": multiple_external_backends_loaded,
        "externalBackendInController": loaded_in_controller_count > 0,
        "externalBackendInTarget": loaded_in_target_count > 0,
        "controllerMultipleExternalBackendsLoaded": controller_multiple_external_backends_loaded,
        "targetMultipleExternalBackendsLoaded": target_multiple_external_backends_loaded,
        "sharedExternalBackend": shared_backend_count > 0,
        "loadedExternalBackendCount": total_loaded_backend_count,
        "filesystemOnlyBackendDetected": filesystem_only_in_either_count > 0,
        "preferredPath": preferred_path,
        "queryCommandsAllowed": hook_effective_allowed_for(actions, "hook.query"),
        "hookInstallAllowed": hook_effective_allowed_for(actions, "hook.install"),
        "hookStatusAllowed": hook_effective_allowed_for(actions, "hook.status"),
        "hookStopAllowed": hook_effective_allowed_for(actions, "hook.stop"),
        "installBlockedBy": install_action.map(|item| item.blocked_by),
        "installRecommendation": install_action.map(|item| item.recommendation.clone()),
        "nextActionKey": recommended_action.map(|item| item.action_key),
        "nextActionAllowed": recommended_action.map(|item| item.allowed),
        "nextActionBlockedBy": recommended_action.map(|item| item.blocked_by),
        "nextActionBranch": recommended_action.map(hook_automation_branch),
        "nextActionReadyToRun": recommended_action.map(|item| item.allowed),
        "nextActionReason": recommended_action.map(|item| item.recommendation.clone()),
        "nextStepId": next_step_id,
        "nextStepActionKey": recommended_action.map(|item| item.action_key),
        "nextStepCommandGroup": recommended_action.map(|item| item.command_group),
        "nextStepAllowed": recommended_action.map(|item| item.allowed),
        "nextStepBlockedBy": recommended_action.map(|item| item.blocked_by),
        "nextStepBranch": recommended_action.map(hook_automation_branch),
        "nextStepCommand": next_step_command,
        "nextStepPhase": next_step_phase,
        "nextStepCommandJsonEligible": recommended_action.map(|_| next_step_command_json_eligible),
        "nextStepKind": next_step_command_json_template
            .as_ref()
            .and_then(|entry| entry.get("kind"))
            .cloned(),
        "nextStepRetryable": next_step_command_json_template
            .as_ref()
            .and_then(|entry| entry.get("retryable"))
            .cloned(),
        "nextStepMaxSuggestedRetries": next_step_command_json_template
            .as_ref()
            .and_then(|entry| entry.get("maxSuggestedRetries"))
            .cloned(),
        "nextStepRetryDelayHintMs": next_step_command_json_template
            .as_ref()
            .and_then(|entry| entry.get("retryDelayHintMs"))
            .cloned(),
        "nextStepTimeoutHintMs": next_step_command_json_template
            .as_ref()
            .and_then(|entry| entry.get("timeoutHintMs"))
            .cloned(),
        "nextStepTimeoutAction": next_step_command_json_template
            .as_ref()
            .and_then(|entry| entry.get("timeoutAction"))
            .cloned(),
        "nextStepErrorCode": next_step_command_json_template
            .as_ref()
            .and_then(|entry| entry.get("errorCode"))
            .cloned(),
        "nextStepTimeoutErrorCode": next_step_command_json_template
            .as_ref()
            .and_then(|entry| entry.get("timeoutErrorCode"))
            .cloned(),
        "nextStepRisk": next_step_command_json_template
            .as_ref()
            .and_then(|entry| entry.get("risk"))
            .cloned(),
        "nextStepPlaceholderCount": next_step_command_json_template
            .as_ref()
            .and_then(|entry| entry.get("placeholderCount"))
            .cloned(),
        "nextStepPlaceholders": next_step_command_json_template
            .as_ref()
            .and_then(|entry| entry.get("placeholders"))
            .cloned(),
        "nextStepCliArgs": next_step_command_json_template
            .as_ref()
            .and_then(|entry| entry.get("cliArgs"))
            .cloned(),
        "nextStepReadyToRun": recommended_action.map(|item| item.allowed),
        "nextStepRequiresFallback": recommended_action.map(|item| !item.allowed),
        "nextStep": next_step,
        "nextStepChainSource": next_step_chain_source,
        "nextStepChainLimit": next_step_chain_limit,
        "nextStepChainCount": next_step_chain.len(),
        "nextStepChain": next_step_chain,
        "nextStepChainTruncated": next_step_chain_truncated,
        "activeStep": active_step.cloned().unwrap_or(Value::Null),
        "activeStepSource": next_step_chain_source,
        "activeStepAllowed": active_step
            .and_then(|entry| entry.get("allowed"))
            .cloned()
            .unwrap_or(Value::Null),
        "activeStepBlockedBy": active_step
            .and_then(|entry| entry.get("blockedBy"))
            .cloned()
            .unwrap_or(Value::Null),
        "activeStepBranch": active_step
            .and_then(|entry| entry.get("branch"))
            .cloned()
            .unwrap_or(Value::Null),
        "activeStepActionKey": active_step
            .and_then(|entry| entry.get("actionKey"))
            .cloned()
            .unwrap_or(Value::Null),
        "activeStepCommandGroup": active_step
            .and_then(|entry| entry.get("commandGroup"))
            .cloned()
            .unwrap_or(Value::Null),
        "activeStepId": active_step
            .and_then(|entry| entry.get("id"))
            .cloned()
            .unwrap_or(Value::Null),
        "activeStepCommand": active_step
            .and_then(|entry| entry.get("command"))
            .cloned()
            .unwrap_or(Value::Null),
        "activeStepPhase": active_step
            .and_then(|entry| entry.get("phase"))
            .cloned()
            .unwrap_or(Value::Null),
        "activeStepReadyToRun": active_step
            .and_then(|entry| entry.get("readyToRun"))
            .cloned()
            .unwrap_or(Value::Null),
        "activeStepRequiresFallback": active_step
            .and_then(|entry| entry.get("requiresFallback"))
            .cloned()
            .unwrap_or(Value::Null),
        "activeStepKind": active_step
            .and_then(|entry| entry.get("kind"))
            .cloned()
            .unwrap_or(Value::Null),
        "activeStepCommandJsonEligible": active_step
            .and_then(|entry| entry.get("commandJsonEligible"))
            .cloned()
            .unwrap_or(Value::Null),
        "activeStepRetryable": active_step
            .and_then(|entry| entry.get("retryable"))
            .cloned()
            .unwrap_or(Value::Null),
        "activeStepMaxSuggestedRetries": active_step
            .and_then(|entry| entry.get("maxSuggestedRetries"))
            .cloned()
            .unwrap_or(Value::Null),
        "activeStepRetryDelayHintMs": active_step
            .and_then(|entry| entry.get("retryDelayHintMs"))
            .cloned()
            .unwrap_or(Value::Null),
        "activeStepTimeoutHintMs": active_step
            .and_then(|entry| entry.get("timeoutHintMs"))
            .cloned()
            .unwrap_or(Value::Null),
        "activeStepTimeoutAction": active_step
            .and_then(|entry| entry.get("timeoutAction"))
            .cloned()
            .unwrap_or(Value::Null),
        "activeStepErrorCode": active_step
            .and_then(|entry| entry.get("errorCode"))
            .cloned()
            .unwrap_or(Value::Null),
        "activeStepTimeoutErrorCode": active_step
            .and_then(|entry| entry.get("timeoutErrorCode"))
            .cloned()
            .unwrap_or(Value::Null),
        "activeStepRisk": active_step
            .and_then(|entry| entry.get("risk"))
            .cloned()
            .unwrap_or(Value::Null),
        "activeStepPlaceholderCount": active_step
            .and_then(|entry| entry.get("placeholderCount"))
            .cloned()
            .unwrap_or(Value::Null),
        "activeStepPlaceholders": active_step
            .and_then(|entry| entry.get("placeholders"))
            .cloned()
            .unwrap_or(Value::Null),
        "activeStepCliArgs": active_step
            .and_then(|entry| entry.get("cliArgs"))
            .cloned()
            .unwrap_or(Value::Null),
        "nextActionTemplateCount": next_action_templates.len(),
        "nextActionTemplates": next_action_templates,
        "nextActionCommandJsonTemplateCount": next_action_command_json_templates.len(),
        "nextActionCommandJsonEligibleTemplateCount": command_json_eligible_count(&next_action_command_json_templates),
        "nextActionCommandJsonTemplates": next_action_command_json_templates,
    })
}

#[cfg(unix)]
fn hook_effective_action_order(action_key: &str) -> usize {
    HOOK_EFFECTIVE_ACTIONS
        .iter()
        .position(|(key, _)| *key == action_key)
        .unwrap_or(usize::MAX)
}

#[cfg(unix)]
fn hook_action_command_group(action_key: &str) -> Option<&'static str> {
    HOOK_EFFECTIVE_ACTIONS
        .iter()
        .find(|(key, _)| *key == action_key)
        .map(|(_, command_group)| *command_group)
}

#[cfg(unix)]
fn hook_automation_branch(action: &HookEffectiveAction) -> &'static str {
    if action.allowed {
        "run"
    } else {
        match action.blocked_by {
            "controller" => "skip-controller-policy",
            "target" => "skip-target-policy",
            "both" => "skip-both-policies",
            _ => "skip-policy",
        }
    }
}

#[cfg(unix)]
fn json_u64_field(value: &Value, key: &str) -> u64 {
    value.get(key).and_then(Value::as_u64).unwrap_or(0)
}

#[cfg(unix)]
fn json_array_len(value: &Value, key: &str) -> usize {
    value.get(key).and_then(Value::as_array).map_or(0, Vec::len)
}

#[cfg(unix)]
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

#[cfg(unix)]
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
        "hook.stop" => &[
            "trace stop",
            "stalker stop",
            "jhook stop",
            "shook stop",
            "hfl stop",
        ],
        _ => &[],
    };

    templates.iter().map(|item| (*item).to_string()).collect::<Vec<_>>()
}

#[cfg(unix)]
fn hook_action_prerequisites(action_key: &str) -> &'static [&'static str] {
    match action_key {
        "hook.install" => &["hook.bootstrap"],
        "hook.stop" => &["hook.status"],
        _ => &[],
    }
}

#[cfg(unix)]
fn normalize_command_template_for_cli(template: &str) -> String {
    template
        .split(" #")
        .next()
        .map(str::trim)
        .unwrap_or_default()
        .to_string()
}

#[cfg(unix)]
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

#[cfg(unix)]
fn command_template_risk(template: &str) -> &'static str {
    if template.contains("# risky-with-external-backend") {
        "risky-with-external-backend"
    } else if template.contains("# caution-filesystem-only-backend-artifacts") {
        "cautious-filesystem-only-backend-artifacts"
    } else {
        "normal"
    }
}

#[cfg(unix)]
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

#[cfg(unix)]
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

#[cfg(unix)]
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

#[cfg(unix)]
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

#[cfg(unix)]
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

#[cfg(unix)]
fn command_json_template_entry(template: &str) -> Value {
    let command = normalize_command_template_for_cli(template);
    let placeholders = command_template_placeholders(&command);
    let risk = command_template_risk(template);
    let phase = command_template_phase(&command);
    let (retryable, max_suggested_retries, retry_delay_hint_ms) = phase_retry_policy(phase);
    let (timeout_hint_ms, timeout_action) = phase_timeout_policy(phase);
    let error_code = phase_failure_code(phase);
    let timeout_error_code = phase_timeout_error_code(phase);

    if let Some(controller_args) = command.strip_prefix("controller ") {
        let cli_args = controller_args
            .split_whitespace()
            .map(|token| token.to_string())
            .collect::<Vec<_>>();

        json!({
            "command": command,
            "kind": "controller-cli",
            "commandJsonEligible": false,
            "risk": risk,
            "phase": phase,
            "retryable": retryable,
            "maxSuggestedRetries": max_suggested_retries,
            "retryDelayHintMs": retry_delay_hint_ms,
            "timeoutHintMs": timeout_hint_ms,
            "timeoutAction": timeout_action,
            "errorCode": error_code,
            "timeoutErrorCode": timeout_error_code,
            "placeholderCount": placeholders.len(),
            "placeholders": placeholders,
            "cliArgs": cli_args,
        })
    } else {
        let command_for_cli = command.clone();
        json!({
            "command": command,
            "kind": "runtime-command",
            "commandJsonEligible": true,
            "risk": risk,
            "phase": phase,
            "retryable": retryable,
            "maxSuggestedRetries": max_suggested_retries,
            "retryDelayHintMs": retry_delay_hint_ms,
            "timeoutHintMs": timeout_hint_ms,
            "timeoutAction": timeout_action,
            "errorCode": error_code,
            "timeoutErrorCode": timeout_error_code,
            "placeholderCount": placeholders.len(),
            "placeholders": placeholders,
            "cliArgs": ["--pid", "<pid>", "--command", command_for_cli, "--command-json"],
        })
    }
}

#[cfg(unix)]
fn command_json_eligible_count(command_json_templates: &[Value]) -> usize {
    command_json_templates
        .iter()
        .filter(|entry| {
            entry
                .get("commandJsonEligible")
                .and_then(Value::as_bool)
                .unwrap_or(false)
        })
        .count()
}

#[cfg(unix)]
fn command_phase_order(command_json_templates: &[Value]) -> Vec<String> {
    let mut phases = Vec::<String>::new();
    for entry in command_json_templates {
        let Some(phase) = entry.get("phase").and_then(Value::as_str) else {
            continue;
        };
        if !phases.iter().any(|existing| existing == phase) {
            phases.push(phase.to_string());
        }
    }
    phases
}

#[cfg(unix)]
fn hook_automation_to_json(actions: &[HookEffectiveAction], backend_matrix: &Value) -> Value {
    let base_command_mode = hook_effective_command_mode(actions);
    let loaded_in_controller_count = json_u64_field(backend_matrix, "loadedInControllerCount");
    let loaded_in_target_count = json_u64_field(backend_matrix, "loadedInTargetCount");
    let loaded_in_both_count = json_u64_field(backend_matrix, "loadedInBothCount");
    let filesystem_only_in_either_count = json_u64_field(backend_matrix, "filesystemOnlyInEitherCount");
    let shared_backend_count = json_array_len(backend_matrix, "sharedBackendIds");
    let total_loaded_backend_count =
        loaded_in_controller_count + loaded_in_target_count - loaded_in_both_count;
    let single_external_backend_loaded = total_loaded_backend_count == 1;
    let multiple_external_backends_loaded = total_loaded_backend_count > 1;
    let (command_mode, auto_downgraded_to_query_only, auto_downgrade_reason) =
        hook_command_mode_with_backend_pressure(
            base_command_mode,
            loaded_in_controller_count,
            loaded_in_target_count,
            loaded_in_both_count,
        );

    let backend_pressure = if loaded_in_controller_count > 0 && loaded_in_target_count > 0 {
        "both"
    } else if loaded_in_controller_count > 0 {
        "controller"
    } else if loaded_in_target_count > 0 {
        "target"
    } else if filesystem_only_in_either_count > 0 {
        "filesystem-only"
    } else {
        "none"
    };

    let preferred_path = match command_mode {
        "allowed" => {
            if backend_pressure == "none" {
                "inline-safe"
            } else if backend_pressure == "filesystem-only" {
                "inline-cautious"
            } else {
                "inline-risky"
            }
        }
        "query-only" => "query-only",
        "cleanup-only" => "cleanup-only",
        _ => "blocked",
    };

    let mode_rank = |action_key: &str| -> u8 {
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
    };

    let next_action = actions
        .iter()
        .filter(|item| item.allowed)
        .min_by_key(|item| (mode_rank(item.action_key), item.priority, hook_effective_action_order(item.action_key)));
    let blocked_action = actions
        .iter()
        .filter(|item| !item.allowed)
        .min_by_key(|item| (mode_rank(item.action_key), item.priority, hook_effective_action_order(item.action_key)));

    let selected_action = next_action.or(blocked_action);
    let is_action_allowed = |action_key: &str| -> bool {
        actions
            .iter()
            .find(|item| item.action_key == action_key)
            .map(|item| item.allowed)
            .unwrap_or(true)
    };
    let mut ordered_actions = actions.iter().collect::<Vec<_>>();
    ordered_actions.sort_by_key(|item| (mode_rank(item.action_key), item.priority, hook_effective_action_order(item.action_key)));

    let next_action_key = selected_action.map(|item| item.action_key).map(ToOwned::to_owned);
    let next_runnable_action_key = next_action.map(|item| item.action_key).map(ToOwned::to_owned);
    let next_blocked_action_key = blocked_action.map(|item| item.action_key).map(ToOwned::to_owned);
    let next_action_reason = selected_action.map(|item| item.recommendation.clone());
    let branch_execution_order = ordered_actions
        .iter()
        .map(|item| item.action_key.to_string())
        .collect::<Vec<_>>();
    let next_ready_action_key = ordered_actions
        .iter()
        .find(|item| {
            let blocked_prerequisite_count = hook_action_prerequisites(item.action_key)
                .iter()
                .filter(|action_key| !is_action_allowed(action_key))
                .count();
            item.allowed && blocked_prerequisite_count == 0
        })
        .map(|item| item.action_key)
        .map(ToOwned::to_owned);
    let suggested_sequence = hook_automation_suggested_sequence(preferred_path);
    let command_templates = HOOK_EFFECTIVE_ACTIONS
        .iter()
        .map(|(action_key, command_group)| {
            let templates = hook_action_command_templates(action_key, preferred_path);
            let command_json_templates = templates
                .iter()
                .map(|template| command_json_template_entry(template))
                .collect::<Vec<_>>();
            json!({
                "actionKey": action_key,
                "commandGroup": command_group,
                "templateCount": templates.len(),
                "templates": templates,
                "commandJsonTemplateCount": command_json_templates.len(),
                "commandJsonTemplates": command_json_templates,
            })
        })
        .collect::<Vec<_>>();
    let next_action_templates = next_action_key
        .as_deref()
        .map(|action_key| hook_action_command_templates(action_key, preferred_path))
        .unwrap_or_default();
    let next_action_command_json_templates = next_action_templates
        .iter()
        .map(|template| command_json_template_entry(template))
        .collect::<Vec<_>>();
    let next_step_command = next_action_templates.first().cloned();
    let next_step_command_json_template = next_action_command_json_templates.first().cloned();
    let next_step_phase = next_step_command_json_template
        .as_ref()
        .and_then(|entry| entry.get("phase"))
        .and_then(Value::as_str)
        .map(ToOwned::to_owned);
    let next_step_command_json_eligible = next_step_command_json_template
        .as_ref()
        .and_then(|entry| entry.get("commandJsonEligible"))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let next_action_prerequisites = selected_action
        .map(|item| {
            hook_action_prerequisites(item.action_key)
                .iter()
                .map(|action_key| (*action_key).to_string())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let next_action_blocked_prerequisites = next_action_prerequisites
        .iter()
        .filter(|action_key| !is_action_allowed(action_key))
        .cloned()
        .collect::<Vec<_>>();
    let next_action_ready_to_run = selected_action
        .map(|item| item.allowed && next_action_blocked_prerequisites.is_empty())
        .unwrap_or(false);
    let fallback_action_key = if next_action_ready_to_run {
        None
    } else {
        next_ready_action_key.clone()
    };
    let fallback_action_command_group = fallback_action_key
        .as_deref()
        .and_then(hook_action_command_group)
        .map(ToOwned::to_owned);
    let fallback_reason = if next_action_ready_to_run {
        None
    } else if selected_action.is_none() {
        Some("no candidate action was selected; use fallback guidance to recover".to_string())
    } else if selected_action.is_some_and(|item| !item.allowed) {
        Some("selected next action is blocked by hook policy; use fallback guidance to recover".to_string())
    } else if !next_action_blocked_prerequisites.is_empty() {
        Some("selected next action has blocked prerequisites; use fallback guidance to recover".to_string())
    } else {
        Some("selected next action is not ready; use fallback guidance to recover".to_string())
    };
    let fallback_templates = if next_action_ready_to_run {
        Vec::new()
    } else if let Some(action_key) = fallback_action_key.as_deref() {
        hook_action_command_templates(action_key, preferred_path)
    } else {
        suggested_sequence
            .iter()
            .filter(|command| !command.starts_with("check "))
            .cloned()
            .collect::<Vec<_>>()
    };
    let fallback_command_json_templates = fallback_templates
        .iter()
        .map(|template| command_json_template_entry(template))
        .collect::<Vec<_>>();
    let fallback_eligible_command_json_template_count = command_json_eligible_count(&fallback_command_json_templates);
    let fallback_phase_order = command_phase_order(&fallback_command_json_templates);
    let fallback_steps = fallback_command_json_templates
        .iter()
        .enumerate()
        .map(|(index, entry)| {
            json!({
                "id": format!("fallback-plan:{index}"),
                "index": index,
                "source": "fallback-plan",
                "actionKey": fallback_action_key.clone(),
                "commandGroup": fallback_action_command_group.clone(),
                "allowed": Value::Null,
                "blockedBy": Value::Null,
                "branch": Value::Null,
                "phase": entry.get("phase").cloned().unwrap_or(Value::Null),
                "command": entry.get("command").cloned().unwrap_or(Value::Null),
                "readyToRun": true,
                "requiresFallback": true,
                "kind": entry.get("kind").cloned().unwrap_or(Value::Null),
                "commandJsonEligible": entry.get("commandJsonEligible").cloned().unwrap_or(Value::Null),
                "risk": entry.get("risk").cloned().unwrap_or(Value::Null),
                "retryable": entry.get("retryable").cloned().unwrap_or(Value::Null),
                "maxSuggestedRetries": entry.get("maxSuggestedRetries").cloned().unwrap_or(Value::Null),
                "retryDelayHintMs": entry.get("retryDelayHintMs").cloned().unwrap_or(Value::Null),
                "timeoutHintMs": entry.get("timeoutHintMs").cloned().unwrap_or(Value::Null),
                "timeoutAction": entry.get("timeoutAction").cloned().unwrap_or(Value::Null),
                "errorCode": entry.get("errorCode").cloned().unwrap_or(Value::Null),
                "timeoutErrorCode": entry.get("timeoutErrorCode").cloned().unwrap_or(Value::Null),
                "placeholderCount": entry.get("placeholderCount").cloned().unwrap_or(Value::Null),
                "placeholders": entry.get("placeholders").cloned().unwrap_or(Value::Null),
                "cliArgs": entry.get("cliArgs").cloned().unwrap_or(Value::Null),
            })
        })
        .collect::<Vec<_>>();
    let fallback_retryable_step_count = fallback_steps
        .iter()
        .filter(|step| step.get("retryable").and_then(Value::as_bool).unwrap_or(false))
        .count();
    let next_step_id = selected_action.and_then(|item| {
        next_step_command
            .as_ref()
            .map(|_| format!("next-action:{}:0", item.action_key))
    });
    let next_step = selected_action
        .map(|item| {
            json!({
                "id": next_step_id.clone(),
                "actionKey": item.action_key,
                "commandGroup": item.command_group,
                "allowed": item.allowed,
                "branch": hook_automation_branch(item),
                "blockedBy": item.blocked_by,
                "reason": item.recommendation,
                "preferredPath": preferred_path,
                "readyToRun": next_action_ready_to_run,
                "requiresFallback": !next_action_ready_to_run,
                "fallbackActionKey": fallback_action_key,
                "command": next_step_command.clone(),
                "phase": next_step_phase.clone(),
                "commandJsonEligible": next_step_command_json_eligible,
                "commandJsonTemplate": next_step_command_json_template.clone(),
            })
        })
        .unwrap_or(Value::Null);
    let next_step_chain_limit = 3usize;
    let next_step_chain = if next_action_ready_to_run {
        selected_action
            .and_then(|item| {
                next_step_command.as_ref().map(|command| {
                    json!({
                        "id": format!("next-action:{}:0", item.action_key),
                        "index": 0,
                        "source": "next-action",
                        "actionKey": item.action_key,
                        "commandGroup": item.command_group,
                        "allowed": item.allowed,
                        "blockedBy": item.blocked_by,
                        "branch": hook_automation_branch(item),
                        "command": command,
                        "phase": next_step_phase,
                        "readyToRun": true,
                        "requiresFallback": false,
                        "commandJsonEligible": next_step_command_json_eligible,
                        "kind": next_step_command_json_template
                            .as_ref()
                            .and_then(|entry| entry.get("kind"))
                            .cloned()
                            .unwrap_or(Value::Null),
                        "retryable": next_step_command_json_template
                            .as_ref()
                            .and_then(|entry| entry.get("retryable"))
                            .cloned()
                            .unwrap_or(Value::Null),
                        "maxSuggestedRetries": next_step_command_json_template
                            .as_ref()
                            .and_then(|entry| entry.get("maxSuggestedRetries"))
                            .cloned()
                            .unwrap_or(Value::Null),
                        "retryDelayHintMs": next_step_command_json_template
                            .as_ref()
                            .and_then(|entry| entry.get("retryDelayHintMs"))
                            .cloned()
                            .unwrap_or(Value::Null),
                        "timeoutHintMs": next_step_command_json_template
                            .as_ref()
                            .and_then(|entry| entry.get("timeoutHintMs"))
                            .cloned()
                            .unwrap_or(Value::Null),
                        "timeoutAction": next_step_command_json_template
                            .as_ref()
                            .and_then(|entry| entry.get("timeoutAction"))
                            .cloned()
                            .unwrap_or(Value::Null),
                        "errorCode": next_step_command_json_template
                            .as_ref()
                            .and_then(|entry| entry.get("errorCode"))
                            .cloned()
                            .unwrap_or(Value::Null),
                        "timeoutErrorCode": next_step_command_json_template
                            .as_ref()
                            .and_then(|entry| entry.get("timeoutErrorCode"))
                            .cloned()
                            .unwrap_or(Value::Null),
                        "risk": next_step_command_json_template
                            .as_ref()
                            .and_then(|entry| entry.get("risk"))
                            .cloned()
                            .unwrap_or(Value::Null),
                        "placeholderCount": next_step_command_json_template
                            .as_ref()
                            .and_then(|entry| entry.get("placeholderCount"))
                            .cloned()
                            .unwrap_or(Value::Null),
                        "placeholders": next_step_command_json_template
                            .as_ref()
                            .and_then(|entry| entry.get("placeholders"))
                            .cloned()
                            .unwrap_or(Value::Null),
                        "cliArgs": next_step_command_json_template
                            .as_ref()
                            .and_then(|entry| entry.get("cliArgs"))
                            .cloned()
                            .unwrap_or(Value::Null),
                    })
                })
            })
            .into_iter()
            .collect::<Vec<_>>()
    } else {
        fallback_command_json_templates
            .iter()
            .take(next_step_chain_limit)
            .enumerate()
            .map(|(index, entry)| {
                json!({
                    "id": format!("fallback-plan:{index}"),
                    "index": index,
                    "source": "fallback-plan",
                    "actionKey": fallback_action_key.clone(),
                    "commandGroup": fallback_action_command_group.clone(),
                    "allowed": Value::Null,
                    "blockedBy": Value::Null,
                    "branch": Value::Null,
                    "command": entry.get("command").cloned().unwrap_or(Value::Null),
                    "phase": entry.get("phase").cloned().unwrap_or(Value::Null),
                    "readyToRun": true,
                    "requiresFallback": true,
                    "kind": entry.get("kind").cloned().unwrap_or(Value::Null),
                    "commandJsonEligible": entry
                        .get("commandJsonEligible")
                        .cloned()
                        .unwrap_or(Value::Null),
                    "retryable": entry.get("retryable").cloned().unwrap_or(Value::Null),
                    "maxSuggestedRetries": entry
                        .get("maxSuggestedRetries")
                        .cloned()
                        .unwrap_or(Value::Null),
                    "retryDelayHintMs": entry
                        .get("retryDelayHintMs")
                        .cloned()
                        .unwrap_or(Value::Null),
                    "timeoutHintMs": entry
                        .get("timeoutHintMs")
                        .cloned()
                        .unwrap_or(Value::Null),
                    "timeoutAction": entry
                        .get("timeoutAction")
                        .cloned()
                        .unwrap_or(Value::Null),
                    "errorCode": entry.get("errorCode").cloned().unwrap_or(Value::Null),
                    "timeoutErrorCode": entry
                        .get("timeoutErrorCode")
                        .cloned()
                        .unwrap_or(Value::Null),
                    "risk": entry.get("risk").cloned().unwrap_or(Value::Null),
                    "placeholderCount": entry
                        .get("placeholderCount")
                        .cloned()
                        .unwrap_or(Value::Null),
                    "placeholders": entry
                        .get("placeholders")
                        .cloned()
                        .unwrap_or(Value::Null),
                    "cliArgs": entry.get("cliArgs").cloned().unwrap_or(Value::Null),
                })
            })
            .collect::<Vec<_>>()
    };
    let next_step_chain_source = if next_action_ready_to_run {
        "next-action"
    } else if fallback_command_json_templates.is_empty() {
        "none"
    } else {
        "fallback-plan"
    };
    let active_step = next_step_chain.first();
    let next_step_chain_truncated =
        !next_action_ready_to_run && fallback_command_json_templates.len() > next_step_chain_limit;
    let fallback_total_retry_budget = fallback_steps
        .iter()
        .map(|step| step.get("maxSuggestedRetries").and_then(Value::as_u64).unwrap_or(0))
        .sum::<u64>();
    let fallback_phase_retry_policies = fallback_phase_order
        .iter()
        .map(|phase| {
            let (retryable, max_suggested_retries, retry_delay_hint_ms) = phase_retry_policy(phase);
            let (timeout_hint_ms, timeout_action) = phase_timeout_policy(phase);
            let error_code = phase_failure_code(phase);
            let timeout_error_code = phase_timeout_error_code(phase);
            json!({
                "phase": phase,
                "retryable": retryable,
                "maxSuggestedRetries": max_suggested_retries,
                "retryDelayHintMs": retry_delay_hint_ms,
                "timeoutHintMs": timeout_hint_ms,
                "timeoutAction": timeout_action,
                "errorCode": error_code,
                "timeoutErrorCode": timeout_error_code,
            })
        })
        .collect::<Vec<_>>();
    let fallback_retryable_phase_count = fallback_phase_retry_policies
        .iter()
        .filter(|policy| policy.get("retryable").and_then(Value::as_bool).unwrap_or(false))
        .count();
    let fallback_non_retryable_phase_count =
        fallback_phase_retry_policies.len().saturating_sub(fallback_retryable_phase_count);
    let fallback_termination_policy = json!({
        "mode": "phase-retry-budget",
        "terminateWhen": "all-retryable-steps-exhausted",
        "escalateWhen": "non-retryable-step-failed-or-retry-budget-exhausted",
        "timeoutEscalateWhen": "phase-timeout-exceeded",
        "retryablePhaseCount": fallback_retryable_phase_count,
        "nonRetryablePhaseCount": fallback_non_retryable_phase_count,
        "retryableStepCount": fallback_retryable_step_count,
        "totalRetryBudget": fallback_total_retry_budget,
    });
    let fallback_phase_error_codes = fallback_phase_order
        .iter()
        .map(|phase| {
            json!({
                "phase": phase,
                "errorCode": phase_failure_code(phase),
                "timeoutErrorCode": phase_timeout_error_code(phase),
            })
        })
        .collect::<Vec<_>>();
    let mut escalation_recommendations = Vec::<Value>::new();
    let escalation_preflight_templates = vec!["controller --preflight-only --preflight-json --pid <pid>".to_string()];
    let escalation_preflight_command_json_templates = escalation_preflight_templates
        .iter()
        .map(|template| command_json_template_entry(template))
        .collect::<Vec<_>>();
    let escalation_preflight_error_codes = vec![
        "hook-fallback-preflight-failed",
        "hook-fallback-inject-failed",
        "hook-fallback-preflight-timeout",
        "hook-fallback-inject-timeout",
    ];
    escalation_recommendations.push(json!({
        "key": "preflight-refresh",
        "condition": "always",
        "phase": "preflight",
        "reason": "refresh target context and diagnostics before changing hook policy or retrying injection",
        "onErrorCodeCount": escalation_preflight_error_codes.len(),
        "onErrorCodes": escalation_preflight_error_codes,
        "templateCount": escalation_preflight_templates.len(),
        "templates": escalation_preflight_templates,
        "commandJsonTemplateCount": escalation_preflight_command_json_templates.len(),
        "commandJsonTemplates": escalation_preflight_command_json_templates.clone(),
        "commandJsonEligibleTemplateCount": command_json_eligible_count(&escalation_preflight_command_json_templates),
    }));
    if hook_effective_allowed_for(actions, "hook.query") {
        let escalation_query_templates = vec![
            "native.hookenv".to_string(),
            "objc.classes <filter>".to_string(),
            "native.images <filter>".to_string(),
            "swift.types <filter>".to_string(),
        ];
        let escalation_query_command_json_templates = escalation_query_templates
            .iter()
            .map(|template| command_json_template_entry(template))
            .collect::<Vec<_>>();
        let escalation_query_error_codes = vec![
            "hook-fallback-query-failed",
            "hook-fallback-query-timeout",
            "hook-fallback-hook-install-failed",
            "hook-fallback-hook-install-timeout",
        ];
        escalation_recommendations.push(json!({
            "key": "query-only-path",
            "condition": "query-commands-allowed",
            "phase": "query",
            "reason": "switch to query-only diagnostics path when inline hook actions are blocked",
            "onErrorCodeCount": escalation_query_error_codes.len(),
            "onErrorCodes": escalation_query_error_codes,
            "templateCount": escalation_query_templates.len(),
            "templates": escalation_query_templates,
            "commandJsonTemplateCount": escalation_query_command_json_templates.len(),
            "commandJsonTemplates": escalation_query_command_json_templates.clone(),
            "commandJsonEligibleTemplateCount": command_json_eligible_count(&escalation_query_command_json_templates),
        }));
    }
    if selected_action.is_some_and(|item| !item.allowed) {
        let escalation_policy_templates = vec!["native.hookenv".to_string()];
        let escalation_policy_command_json_templates = escalation_policy_templates
            .iter()
            .map(|template| command_json_template_entry(template))
            .collect::<Vec<_>>();
        let escalation_policy_error_codes = vec![
            "hook-fallback-diagnose-failed",
            "hook-fallback-diagnose-timeout",
        ];
        escalation_recommendations.push(json!({
            "key": "policy-review",
            "condition": "selected-next-action-blocked",
            "phase": "diagnose",
            "reason": "hook policy blocked the selected next action; inspect environment summary and adjust policy before retrying",
            "note": "review IOS_RUSTFRIDA_HOOK_POLICY / target hook backend and retry with preflight-only first",
            "onErrorCodeCount": escalation_policy_error_codes.len(),
            "onErrorCodes": escalation_policy_error_codes,
            "templateCount": escalation_policy_templates.len(),
            "templates": escalation_policy_templates,
            "commandJsonTemplateCount": escalation_policy_command_json_templates.len(),
            "commandJsonTemplates": escalation_policy_command_json_templates.clone(),
            "commandJsonEligibleTemplateCount": command_json_eligible_count(&escalation_policy_command_json_templates),
        }));
    }
    let mut error_code_routing_candidates = BTreeMap::<String, Vec<String>>::new();
    for recommendation in &escalation_recommendations {
        let Some(key) = recommendation.get("key").and_then(Value::as_str) else {
            continue;
        };
        if key.is_empty() {
            continue;
        }
        let Some(error_codes) = recommendation.get("onErrorCodes").and_then(Value::as_array) else {
            continue;
        };
        for error_code in error_codes {
            let Some(error_code) = error_code.as_str() else {
                continue;
            };
            if error_code.is_empty() {
                continue;
            }
            let candidates = error_code_routing_candidates.entry(error_code.to_string()).or_default();
            if !candidates.iter().any(|candidate| candidate == key) {
                candidates.push(key.to_string());
            }
        }
    }
    let error_code_routing = error_code_routing_candidates
        .iter()
        .fold(Map::<String, Value>::new(), |mut map, (error_code, candidates)| {
            if let Some(first) = candidates.first() {
                map.insert(error_code.clone(), Value::String(first.clone()));
            }
            map
        });
    let escalation_recommendation_by_key = escalation_recommendations
        .iter()
        .filter_map(|recommendation| {
            recommendation
                .get("key")
                .and_then(Value::as_str)
                .filter(|key| !key.is_empty())
                .map(|key| (key.to_string(), recommendation.clone()))
        })
        .collect::<BTreeMap<_, _>>();
    let error_code_routing_entries = error_code_routing_candidates
        .iter()
        .map(|(error_code, candidates)| {
            let recommended = candidates
                .first()
                .and_then(|key| escalation_recommendation_by_key.get(key));
            let recommended_escalation_key = candidates.first().cloned();
            let recommended_phase = recommended
                .and_then(|item| item.get("phase"))
                .cloned()
                .unwrap_or(Value::Null);

            json!({
                "errorCode": error_code,
                "candidateCount": candidates.len(),
                "candidateEscalationKeys": candidates,
                "recommendedEscalationKey": recommended_escalation_key.clone(),
                "effectiveEscalationKey": recommended_escalation_key,
                "matchConfidence": "exact",
                "resolvedFrom": "errorCodeRouting",
                "recommendedPhase": recommended_phase.clone(),
                "effectivePhase": recommended_phase,
                "recommendedTemplateCount": recommended
                    .and_then(|item| item.get("templateCount"))
                    .cloned()
                    .unwrap_or(Value::Null),
                "recommendedTemplates": recommended
                    .and_then(|item| item.get("templates"))
                    .cloned()
                    .unwrap_or(json!([])),
                "recommendedCommandJsonTemplateCount": recommended
                    .and_then(|item| item.get("commandJsonTemplateCount"))
                    .cloned()
                    .unwrap_or(Value::Null),
                "recommendedCommandJsonTemplates": recommended
                    .and_then(|item| item.get("commandJsonTemplates"))
                    .cloned()
                    .unwrap_or(json!([])),
            })
        })
        .collect::<Vec<_>>();
    let error_code_routing_resolved = error_code_routing_entries
        .iter()
        .filter_map(|entry| {
            entry
                .get("errorCode")
                .and_then(Value::as_str)
                .map(|error_code| {
                    (
                        error_code.to_string(),
                        json!({
                            "escalationKey": entry
                                .get("recommendedEscalationKey")
                                .cloned()
                                .unwrap_or(Value::Null),
                            "phase": entry
                                .get("recommendedPhase")
                                .cloned()
                                .unwrap_or(Value::Null),
                            "effectiveEscalationKey": entry
                                .get("effectiveEscalationKey")
                                .cloned()
                                .unwrap_or(Value::Null),
                            "effectivePhase": entry
                                .get("effectivePhase")
                                .cloned()
                                .unwrap_or(Value::Null),
                            "matchConfidence": entry
                                .get("matchConfidence")
                                .cloned()
                                .unwrap_or(Value::Null),
                            "resolvedFrom": entry
                                .get("resolvedFrom")
                                .cloned()
                                .unwrap_or(Value::Null),
                            "templateCount": entry
                                .get("recommendedTemplateCount")
                                .cloned()
                                .unwrap_or(Value::Null),
                            "templates": entry
                                .get("recommendedTemplates")
                                .cloned()
                                .unwrap_or(json!([])),
                            "commandJsonTemplateCount": entry
                                .get("recommendedCommandJsonTemplateCount")
                                .cloned()
                                .unwrap_or(Value::Null),
                            "commandJsonTemplates": entry
                                .get("recommendedCommandJsonTemplates")
                                .cloned()
                                .unwrap_or(json!([])),
                        }),
                    )
                })
        })
        .fold(Map::<String, Value>::new(), |mut map, (error_code, value)| {
            map.insert(error_code, value);
            map
        });
    let routing_decision_index = error_code_routing_entries
        .iter()
        .filter_map(|entry| {
            entry
                .get("errorCode")
                .and_then(Value::as_str)
                .map(|error_code| {
                    (
                        error_code.to_string(),
                        json!({
                            "recommendedEscalationKey": entry
                                .get("recommendedEscalationKey")
                                .cloned()
                                .unwrap_or(Value::Null),
                            "effectiveEscalationKey": entry
                                .get("effectiveEscalationKey")
                                .cloned()
                                .unwrap_or(Value::Null),
                            "matchConfidence": entry
                                .get("matchConfidence")
                                .cloned()
                                .unwrap_or(Value::Null),
                            "resolvedFrom": entry
                                .get("resolvedFrom")
                                .cloned()
                                .unwrap_or(Value::Null),
                            "recommendedPhase": entry
                                .get("recommendedPhase")
                                .cloned()
                                .unwrap_or(Value::Null),
                            "effectivePhase": entry
                                .get("effectivePhase")
                                .cloned()
                                .unwrap_or(Value::Null),
                            "recommendedTemplateCount": entry
                                .get("recommendedTemplateCount")
                                .cloned()
                                .unwrap_or(Value::Null),
                            "recommendedTemplates": entry
                                .get("recommendedTemplates")
                                .cloned()
                                .unwrap_or(json!([])),
                            "recommendedCommandJsonTemplateCount": entry
                                .get("recommendedCommandJsonTemplateCount")
                                .cloned()
                                .unwrap_or(Value::Null),
                            "recommendedCommandJsonTemplates": entry
                                .get("recommendedCommandJsonTemplates")
                                .cloned()
                                .unwrap_or(json!([])),
                        }),
                    )
                })
        })
        .fold(Map::<String, Value>::new(), |mut map, (error_code, value)| {
            map.insert(error_code, value);
            map
        });
    let default_recommendation = escalation_recommendations.first().cloned();
    let default_recommended_escalation_key = default_recommendation
        .as_ref()
        .and_then(|item| item.get("key"))
        .and_then(Value::as_str)
        .map(ToOwned::to_owned);
    let routing_decision_default = default_recommendation
        .map(|item| {
            let recommended_phase = item.get("phase").cloned().unwrap_or(Value::Null);
            json!({
                "recommendedEscalationKey": default_recommended_escalation_key.clone(),
                "matchConfidence": "default",
                "resolvedFrom": "defaultRecommendedEscalationKey",
                "recommendedPhase": recommended_phase.clone(),
                "effectivePhase": recommended_phase,
                "effectiveEscalationKey": default_recommended_escalation_key.clone(),
                "recommendedTemplateCount": item.get("templateCount").cloned().unwrap_or(Value::Null),
                "recommendedTemplates": item.get("templates").cloned().unwrap_or(json!([])),
                "recommendedCommandJsonTemplateCount": item
                    .get("commandJsonTemplateCount")
                    .cloned()
                    .unwrap_or(Value::Null),
                "recommendedCommandJsonTemplates": item
                    .get("commandJsonTemplates")
                    .cloned()
                    .unwrap_or(json!([])),
            })
        })
        .unwrap_or(Value::Null);
    let routing_decision_ready_index = routing_decision_index
        .iter()
        .fold(Map::<String, Value>::new(), |mut map, (error_code, decision)| {
            let escalation_key = decision
                .get("recommendedEscalationKey")
                .cloned()
                .unwrap_or(Value::Null);
            let phase = decision
                .get("recommendedPhase")
                .cloned()
                .unwrap_or(Value::Null);
            map.insert(
                error_code.clone(),
                json!({
                    "escalationKey": escalation_key.clone(),
                    "phase": phase.clone(),
                    "effectiveEscalationKey": escalation_key,
                    "effectivePhase": phase,
                    "templateCount": decision
                        .get("recommendedTemplateCount")
                        .cloned()
                        .unwrap_or(Value::Null),
                    "templates": decision
                        .get("recommendedTemplates")
                        .cloned()
                        .unwrap_or(json!([])),
                    "commandJsonTemplateCount": decision
                        .get("recommendedCommandJsonTemplateCount")
                        .cloned()
                        .unwrap_or(Value::Null),
                    "commandJsonTemplates": decision
                        .get("recommendedCommandJsonTemplates")
                        .cloned()
                        .unwrap_or(json!([])),
                    "matchConfidence": decision
                        .get("matchConfidence")
                        .cloned()
                        .unwrap_or(Value::Null),
                    "resolvedFrom": decision
                        .get("resolvedFrom")
                        .cloned()
                        .unwrap_or(Value::Null),
                }),
            );
            map
        });
    let routing_decision_ready_default = json!({
        "escalationKey": routing_decision_default
            .get("recommendedEscalationKey")
            .cloned()
            .unwrap_or(Value::Null),
        "effectiveEscalationKey": routing_decision_default
            .get("effectiveEscalationKey")
            .cloned()
            .unwrap_or_else(|| {
                routing_decision_default
                    .get("recommendedEscalationKey")
                    .cloned()
                    .unwrap_or(Value::Null)
            }),
        "phase": routing_decision_default
            .get("recommendedPhase")
            .cloned()
            .unwrap_or(Value::Null),
        "effectivePhase": routing_decision_default
            .get("effectivePhase")
            .cloned()
            .unwrap_or_else(|| {
                routing_decision_default
                    .get("recommendedPhase")
                    .cloned()
                    .unwrap_or(Value::Null)
            }),
        "templateCount": routing_decision_default
            .get("recommendedTemplateCount")
            .cloned()
            .unwrap_or(Value::Null),
        "templates": routing_decision_default
            .get("recommendedTemplates")
            .cloned()
            .unwrap_or(json!([])),
        "commandJsonTemplateCount": routing_decision_default
            .get("recommendedCommandJsonTemplateCount")
            .cloned()
            .unwrap_or(Value::Null),
        "commandJsonTemplates": routing_decision_default
            .get("recommendedCommandJsonTemplates")
            .cloned()
            .unwrap_or(json!([])),
        "matchConfidence": routing_decision_default
            .get("matchConfidence")
            .cloned()
            .unwrap_or(Value::Null),
        "resolvedFrom": routing_decision_default
            .get("resolvedFrom")
            .cloned()
            .unwrap_or(Value::Null),
    });
    let routing_decision_ready_resolve_index = routing_decision_ready_index
        .iter()
        .fold(Map::<String, Value>::new(), |mut map, (error_code, decision)| {
            let effective_phase = decision
                .get("phase")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned);
            let effective_escalation_key = decision
                .get("escalationKey")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned)
                .or_else(|| {
                    decision
                        .get("escalationKeys")
                        .and_then(Value::as_array)
                        .and_then(|keys| keys.first())
                        .and_then(Value::as_str)
                        .map(ToOwned::to_owned)
                });
            map.insert(
                error_code.clone(),
                json!({
                    "matched": true,
                    "usedDefault": false,
                    "reason": "matched-error-code",
                    "effectivePhase": effective_phase,
                    "effectiveEscalationKey": effective_escalation_key,
                    "effective": decision,
                }),
            );
            map
        });
    let routing_decision_ready_resolve_default_effective_phase = routing_decision_ready_default
        .get("phase")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned);
    let routing_decision_ready_resolve_default_effective_escalation_key = routing_decision_ready_default
        .get("escalationKey")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .or_else(|| {
            routing_decision_ready_default
                .get("escalationKeys")
                .and_then(Value::as_array)
                .and_then(|keys| keys.first())
                .and_then(Value::as_str)
                .map(ToOwned::to_owned)
        });
    let routing_decision_ready_resolve_default = json!({
        "matched": false,
        "usedDefault": true,
        "reason": "missing-error-code",
        "effectivePhase": routing_decision_ready_resolve_default_effective_phase,
        "effectiveEscalationKey": routing_decision_ready_resolve_default_effective_escalation_key,
        "effective": routing_decision_ready_default,
    });
    let routing_decision_ready_resolve_default_matched = routing_decision_ready_resolve_default
        .get("matched")
        .cloned()
        .unwrap_or(Value::Null);
    let routing_decision_ready_resolve_default_used_default = routing_decision_ready_resolve_default
        .get("usedDefault")
        .cloned()
        .unwrap_or(Value::Null);
    let routing_decision_ready_resolve_default_reason = routing_decision_ready_resolve_default
        .get("reason")
        .cloned()
        .unwrap_or(Value::Null);
    let routing_decision_ready_resolve_default_effective_phase_alias =
        routing_decision_ready_resolve_default
            .get("effectivePhase")
            .cloned()
            .unwrap_or(Value::Null);
    let routing_decision_ready_resolve_default_effective_escalation_key_alias =
        routing_decision_ready_resolve_default
            .get("effectiveEscalationKey")
            .cloned()
            .unwrap_or(Value::Null);
    let routing_decision_ready_known_error_codes = routing_decision_ready_index
        .keys()
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>();
    let routing_decision_ready_example_known_error_code = routing_decision_ready_known_error_codes.first().cloned();
    let routing_decision_ready_example_known_error_result = routing_decision_ready_example_known_error_code
        .as_ref()
        .and_then(|error_code| routing_decision_ready_resolve_index.get(error_code))
        .cloned()
        .unwrap_or(Value::Null);
    let routing_decision_ready_example_known_effective_phase = routing_decision_ready_example_known_error_result
        .get("effective")
        .and_then(|entry| entry.get("phase"))
        .and_then(Value::as_str)
        .map(ToOwned::to_owned);
    let routing_decision_ready_example_known_effective_escalation_key = routing_decision_ready_example_known_error_result
        .get("effective")
        .and_then(|entry| entry.get("escalationKey"))
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .or_else(|| {
            routing_decision_ready_example_known_error_result
                .get("effective")
                .and_then(|entry| entry.get("escalationKeys"))
                .and_then(Value::as_array)
                .and_then(|keys| keys.first())
                .and_then(Value::as_str)
                .map(ToOwned::to_owned)
        });
    let routing_decision_ready_example_missing_error_code = "hook-fallback-unknown";
    let routing_decision_ready_example_missing_effective_phase = routing_decision_ready_resolve_default
        .get("effective")
        .and_then(|entry| entry.get("phase"))
        .and_then(Value::as_str)
        .map(ToOwned::to_owned);
    let routing_decision_ready_example_missing_effective_escalation_key = routing_decision_ready_resolve_default
        .get("effective")
        .and_then(|entry| entry.get("escalationKey"))
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .or_else(|| {
            routing_decision_ready_resolve_default
                .get("effective")
                .and_then(|entry| entry.get("escalationKeys"))
                .and_then(Value::as_array)
                .and_then(|keys| keys.first())
                .and_then(Value::as_str)
                .map(ToOwned::to_owned)
        });
    let routing_decision_ready_example_query_only_error_code = "hook-fallback-hook-install-failed";
    let routing_decision_ready_example_query_only_result = routing_decision_ready_resolve_index
        .get(routing_decision_ready_example_query_only_error_code)
        .cloned();
    let routing_decision_ready_example_query_only_blocked_by = actions
        .iter()
        .find(|item| item.action_key == "hook.install")
        .map(|item| item.blocked_by.to_string());
    let routing_decision_ready_example_query_only_blocked_by_source = routing_decision_ready_example_query_only_blocked_by
        .clone()
        .unwrap_or_else(|| "none".to_string());
    let routing_decision_ready_example_query_only_is_blocked =
        routing_decision_ready_example_query_only_blocked_by_source != "none";
    let routing_decision_ready_example_query_only_available = routing_decision_ready_example_query_only_result.is_some();
    let routing_decision_ready_example_query_only_matched = routing_decision_ready_example_query_only_result
        .as_ref()
        .and_then(|entry| entry.get("matched"))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let routing_decision_ready_example_query_only_used_default = routing_decision_ready_example_query_only_result
        .as_ref()
        .and_then(|entry| entry.get("usedDefault"))
        .and_then(Value::as_bool)
        .unwrap_or(!routing_decision_ready_example_query_only_available);
    let routing_decision_ready_example_query_only_reason = routing_decision_ready_example_query_only_result
        .as_ref()
        .and_then(|entry| entry.get("reason"))
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .or_else(|| {
            (!routing_decision_ready_example_query_only_available).then(|| "missing-error-code".to_string())
        });
    let routing_decision_ready_example_query_only_phase = routing_decision_ready_example_query_only_result
        .as_ref()
        .and_then(|entry| entry.get("effective"))
        .and_then(|entry| entry.get("phase"))
        .and_then(Value::as_str)
        .map(ToOwned::to_owned);
    let routing_decision_ready_example_query_only_effective_escalation_key = routing_decision_ready_example_query_only_result
        .as_ref()
        .and_then(|entry| entry.get("effective"))
        .and_then(|entry| entry.get("escalationKey"))
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .or_else(|| {
            routing_decision_ready_example_query_only_result
                .as_ref()
                .and_then(|entry| entry.get("effective"))
                .and_then(|entry| entry.get("escalationKeys"))
                .and_then(Value::as_array)
                .and_then(|keys| keys.first())
                .and_then(Value::as_str)
                .map(ToOwned::to_owned)
        });
    let routing_decision_ready_example_query_only_would_use_query_path = routing_decision_ready_example_query_only_result
        .as_ref()
        .and_then(|entry| entry.get("effective"))
        .and_then(|entry| entry.get("escalationKey"))
        .and_then(Value::as_str)
        .is_some_and(|key| key == "query-only-path");
    let routing_decision_ready_resolve_examples = json!({
        "knownErrorCode": routing_decision_ready_example_known_error_code,
        "knownResult": routing_decision_ready_example_known_error_result,
        "knownEffectivePhase": routing_decision_ready_example_known_effective_phase,
        "knownEffectiveEscalationKey": routing_decision_ready_example_known_effective_escalation_key,
        "missingErrorCode": routing_decision_ready_example_missing_error_code,
        "missingResult": routing_decision_ready_resolve_default.clone(),
        "missingEffectivePhase": routing_decision_ready_example_missing_effective_phase,
        "missingEffectiveEscalationKey": routing_decision_ready_example_missing_effective_escalation_key,
        "queryOnlyInstallFailure": {
            "errorCode": routing_decision_ready_example_query_only_error_code,
            "blockedBy": routing_decision_ready_example_query_only_blocked_by,
            "blockedBySource": routing_decision_ready_example_query_only_blocked_by_source,
            "isBlocked": routing_decision_ready_example_query_only_is_blocked,
            "available": routing_decision_ready_example_query_only_available,
            "matched": routing_decision_ready_example_query_only_matched,
            "usedDefault": routing_decision_ready_example_query_only_used_default,
            "reason": routing_decision_ready_example_query_only_reason,
            "effectivePhase": routing_decision_ready_example_query_only_phase,
            "effectiveEscalationKey": routing_decision_ready_example_query_only_effective_escalation_key,
            "result": routing_decision_ready_example_query_only_result.unwrap_or(Value::Null),
            "wouldUseQueryOnlyPath": routing_decision_ready_example_query_only_would_use_query_path,
        },
    });
    let routing_decision_ready_resolve_query_only_example = routing_decision_ready_resolve_examples
        .get("queryOnlyInstallFailure")
        .cloned()
        .unwrap_or(Value::Null);
    let routing_decision_ready_phase_groups = routing_decision_ready_index
        .iter()
        .fold(BTreeMap::<String, Vec<String>>::new(), |mut groups, (error_code, decision)| {
            let phase = decision
                .get("phase")
                .and_then(Value::as_str)
                .filter(|phase| !phase.is_empty())
                .unwrap_or("unknown")
                .to_string();
            groups.entry(phase).or_default().push(error_code.clone());
            groups
        });
    let routing_decision_ready_phase_entries = routing_decision_ready_phase_groups
        .iter()
        .map(|(phase, error_codes)| {
            let mut escalation_keys = Vec::<String>::new();
            let mut templates = BTreeSet::<String>::new();
            let mut command_json_templates = Vec::<Value>::new();
            let mut command_json_template_keys = BTreeSet::<String>::new();

            for error_code in error_codes {
                let Some(decision) = routing_decision_ready_index.get(error_code) else {
                    continue;
                };
                if let Some(escalation_key) = decision
                    .get("escalationKey")
                    .and_then(Value::as_str)
                    .filter(|key| !key.is_empty())
                    .map(ToOwned::to_owned)
                {
                    if !escalation_keys.contains(&escalation_key) {
                        escalation_keys.push(escalation_key);
                    }
                }
                if let Some(decision_templates) = decision.get("templates").and_then(Value::as_array) {
                    for template in decision_templates {
                        if let Some(template) = template.as_str() {
                            templates.insert(template.to_string());
                        }
                    }
                }
                if let Some(decision_command_json_templates) =
                    decision.get("commandJsonTemplates").and_then(Value::as_array)
                {
                    for template in decision_command_json_templates {
                        let key = template
                            .get("command")
                            .and_then(Value::as_str)
                            .filter(|command| !command.is_empty())
                            .map(ToOwned::to_owned)
                            .unwrap_or_else(|| template.to_string());
                        if command_json_template_keys.insert(key) {
                            command_json_templates.push(template.clone());
                        }
                    }
                }
            }

            let templates = templates.into_iter().collect::<Vec<_>>();
            json!({
                "phase": phase,
                "errorCodeCount": error_codes.len(),
                "errorCodes": error_codes,
                "escalationKeyCount": escalation_keys.len(),
                "escalationKeys": escalation_keys,
                "templateCount": templates.len(),
                "templates": templates,
                "commandJsonTemplateCount": command_json_templates.len(),
                "commandJsonTemplates": command_json_templates,
            })
        })
        .collect::<Vec<_>>();
    let routing_decision_ready_phase_index = routing_decision_ready_phase_entries
        .iter()
        .filter_map(|entry| {
            entry
                .get("phase")
                .and_then(Value::as_str)
                .map(|phase| (phase.to_string(), entry.clone()))
        })
        .fold(Map::<String, Value>::new(), |mut map, (phase, entry)| {
            map.insert(phase, entry);
            map
        });
    let routing_decision_ready_default_phase = routing_decision_ready_default
        .get("phase")
        .cloned()
        .unwrap_or(Value::Null);
    let routing_decision_ready_phase_preflight = routing_decision_ready_phase_index
        .get("preflight")
        .cloned()
        .unwrap_or(Value::Null);
    let routing_decision_ready_phase_diagnose = routing_decision_ready_phase_index
        .get("diagnose")
        .cloned()
        .unwrap_or(Value::Null);
    let routing_decision_ready_phase_resolve_index = routing_decision_ready_phase_index
        .iter()
        .fold(Map::<String, Value>::new(), |mut map, (phase, entry)| {
            let effective_phase = entry
                .get("phase")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned);
            let effective_escalation_key = entry
                .get("escalationKey")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned)
                .or_else(|| {
                    entry
                        .get("escalationKeys")
                        .and_then(Value::as_array)
                        .and_then(|keys| keys.first())
                        .and_then(Value::as_str)
                        .map(ToOwned::to_owned)
                });
            map.insert(
                phase.clone(),
                json!({
                    "matched": true,
                    "usedDefault": false,
                    "reason": "matched-phase",
                    "effectivePhase": effective_phase,
                    "effectiveEscalationKey": effective_escalation_key,
                    "effective": entry,
                }),
            );
            map
        });
    let routing_decision_ready_known_phases = routing_decision_ready_phase_index
        .keys()
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>();
    let routing_decision_ready_example_known_phase = routing_decision_ready_known_phases.first().cloned();
    let routing_decision_ready_phase_resolve_default_effective = routing_decision_ready_default_phase
        .as_str()
        .and_then(|phase| routing_decision_ready_phase_index.get(phase).cloned())
        .unwrap_or(Value::Null);
    let routing_decision_ready_phase_resolve_default = json!({
        "matched": false,
        "usedDefault": true,
        "reason": "missing-phase",
        "effectivePhase": routing_decision_ready_phase_resolve_default_effective
            .get("phase")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned),
        "effectiveEscalationKey": routing_decision_ready_phase_resolve_default_effective
            .get("escalationKey")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
            .or_else(|| {
                routing_decision_ready_phase_resolve_default_effective
                    .get("escalationKeys")
                    .and_then(Value::as_array)
                    .and_then(|keys| keys.first())
                    .and_then(Value::as_str)
                    .map(ToOwned::to_owned)
            }),
        "effective": routing_decision_ready_phase_resolve_default_effective,
    });
    let routing_decision_ready_phase_resolve_default_matched = routing_decision_ready_phase_resolve_default
        .get("matched")
        .cloned()
        .unwrap_or(Value::Null);
    let routing_decision_ready_phase_resolve_default_used_default = routing_decision_ready_phase_resolve_default
        .get("usedDefault")
        .cloned()
        .unwrap_or(Value::Null);
    let routing_decision_ready_phase_resolve_default_reason = routing_decision_ready_phase_resolve_default
        .get("reason")
        .cloned()
        .unwrap_or(Value::Null);
    let routing_decision_ready_phase_resolve_default_effective_phase_alias =
        routing_decision_ready_phase_resolve_default
            .get("effectivePhase")
            .cloned()
            .unwrap_or(Value::Null);
    let routing_decision_ready_phase_resolve_default_effective_escalation_key_alias =
        routing_decision_ready_phase_resolve_default
            .get("effectiveEscalationKey")
            .cloned()
            .unwrap_or(Value::Null);
    let routing_decision_ready_example_query_only_phase_result = routing_decision_ready_example_query_only_phase
        .as_ref()
        .and_then(|phase| routing_decision_ready_phase_resolve_index.get(phase))
        .cloned();
    let routing_decision_ready_example_query_only_phase_available =
        routing_decision_ready_example_query_only_phase_result.is_some();
    let routing_decision_ready_example_query_only_phase_matched = routing_decision_ready_example_query_only_phase_result
        .as_ref()
        .and_then(|entry| entry.get("matched"))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let routing_decision_ready_example_query_only_phase_used_default = routing_decision_ready_example_query_only_phase_result
        .as_ref()
        .and_then(|entry| entry.get("usedDefault"))
        .and_then(Value::as_bool)
        .unwrap_or(!routing_decision_ready_example_query_only_phase_available);
    let routing_decision_ready_example_query_only_phase_reason = routing_decision_ready_example_query_only_phase_result
        .as_ref()
        .and_then(|entry| entry.get("reason"))
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .or_else(|| {
            (!routing_decision_ready_example_query_only_phase_available).then(|| "missing-phase".to_string())
        });
    let routing_decision_ready_example_query_only_would_use_query_phase = routing_decision_ready_example_query_only_phase_result
        .as_ref()
        .and_then(|entry| entry.get("effective"))
        .and_then(|entry| entry.get("phase"))
        .and_then(Value::as_str)
        .is_some_and(|phase| phase == "query");
    let routing_decision_ready_example_known_phase_result = routing_decision_ready_example_known_phase
        .as_ref()
        .and_then(|phase| routing_decision_ready_phase_resolve_index.get(phase))
        .cloned()
        .unwrap_or(Value::Null);
    let routing_decision_ready_example_known_phase_effective_phase = routing_decision_ready_example_known_phase_result
        .get("effective")
        .and_then(|entry| entry.get("phase"))
        .and_then(Value::as_str)
        .map(ToOwned::to_owned);
    let routing_decision_ready_example_known_phase_effective_escalation_key = routing_decision_ready_example_known_phase_result
        .get("effective")
        .and_then(|entry| entry.get("escalationKey"))
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .or_else(|| {
            routing_decision_ready_example_known_phase_result
                .get("effective")
                .and_then(|entry| entry.get("escalationKeys"))
                .and_then(Value::as_array)
                .and_then(|keys| keys.first())
                .and_then(Value::as_str)
                .map(ToOwned::to_owned)
        });
    let routing_decision_ready_example_missing_phase = "unknown";
    let routing_decision_ready_example_missing_phase_effective_phase = routing_decision_ready_phase_resolve_default
        .get("effective")
        .and_then(|entry| entry.get("phase"))
        .and_then(Value::as_str)
        .map(ToOwned::to_owned);
    let routing_decision_ready_example_missing_phase_effective_escalation_key = routing_decision_ready_phase_resolve_default
        .get("effective")
        .and_then(|entry| entry.get("escalationKey"))
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .or_else(|| {
            routing_decision_ready_phase_resolve_default
                .get("effective")
                .and_then(|entry| entry.get("escalationKeys"))
                .and_then(Value::as_array)
                .and_then(|keys| keys.first())
                .and_then(Value::as_str)
                .map(ToOwned::to_owned)
        });
    let routing_decision_ready_phase_resolve_examples = json!({
        "knownPhase": routing_decision_ready_example_known_phase,
        "knownResult": routing_decision_ready_example_known_phase_result,
        "knownEffectivePhase": routing_decision_ready_example_known_phase_effective_phase,
        "knownEffectiveEscalationKey": routing_decision_ready_example_known_phase_effective_escalation_key,
        "missingPhase": routing_decision_ready_example_missing_phase,
        "missingResult": routing_decision_ready_phase_resolve_default.clone(),
        "missingEffectivePhase": routing_decision_ready_example_missing_phase_effective_phase,
        "missingEffectiveEscalationKey": routing_decision_ready_example_missing_phase_effective_escalation_key,
        "queryOnlyInstallFailure": {
            "sourceErrorCode": routing_decision_ready_example_query_only_error_code,
            "blockedBy": routing_decision_ready_example_query_only_blocked_by,
            "blockedBySource": routing_decision_ready_example_query_only_blocked_by_source,
            "isBlocked": routing_decision_ready_example_query_only_is_blocked,
            "phase": routing_decision_ready_example_query_only_phase,
            "available": routing_decision_ready_example_query_only_phase_available,
            "matched": routing_decision_ready_example_query_only_phase_matched,
            "usedDefault": routing_decision_ready_example_query_only_phase_used_default,
            "reason": routing_decision_ready_example_query_only_phase_reason,
            "effectivePhase": routing_decision_ready_example_query_only_phase_result
                .as_ref()
                .and_then(|entry| entry.get("effective"))
                .and_then(|entry| entry.get("phase"))
                .and_then(Value::as_str)
                .map(ToOwned::to_owned),
            "effectiveEscalationKey": routing_decision_ready_example_query_only_phase_result
                .as_ref()
                .and_then(|entry| entry.get("effective"))
                .and_then(|entry| entry.get("escalationKey"))
                .and_then(Value::as_str)
                .map(ToOwned::to_owned)
                .or_else(|| {
                    routing_decision_ready_example_query_only_phase_result
                        .as_ref()
                        .and_then(|entry| entry.get("effective"))
                        .and_then(|entry| entry.get("escalationKeys"))
                        .and_then(Value::as_array)
                        .and_then(|keys| keys.first())
                        .and_then(Value::as_str)
                        .map(ToOwned::to_owned)
                }),
            "result": routing_decision_ready_example_query_only_phase_result.unwrap_or(Value::Null),
            "wouldUseQueryPhase": routing_decision_ready_example_query_only_would_use_query_phase,
        },
    });
    let routing_decision_ready_phase_resolve_query_only_example = routing_decision_ready_phase_resolve_examples
        .get("queryOnlyInstallFailure")
        .cloned()
        .unwrap_or(Value::Null);
    let routing_decision_ready_resolve = json!({
        "lookupKey": "errorCode",
        "policy": "index-then-default",
        "outputShape": "{ matched, usedDefault, reason, effectivePhase, effectiveEscalationKey, effective }",
        "errorCodeCount": routing_decision_ready_known_error_codes.len(),
        "knownErrorCodes": routing_decision_ready_known_error_codes.clone(),
        "knownEntries": routing_decision_ready_known_error_codes.clone(),
        "knownList": routing_decision_ready_known_error_codes.clone(),
        "knownEntriesCount": routing_decision_ready_known_error_codes.len(),
        "knownErrorCodesCount": routing_decision_ready_known_error_codes.len(),
        "knownErrorCodeFirst": routing_decision_ready_known_error_codes.first(),
        "knownErrorCodesFirst": routing_decision_ready_known_error_codes.first(),
        "knownEntriesFirst": routing_decision_ready_known_error_codes.first(),
        "knownFirst": routing_decision_ready_known_error_codes.first(),
        "knownErrorCodeLast": routing_decision_ready_known_error_codes.last(),
        "knownErrorCodesLast": routing_decision_ready_known_error_codes.last(),
        "knownEntriesLast": routing_decision_ready_known_error_codes.last(),
        "knownLast": routing_decision_ready_known_error_codes.last(),
        "missingErrorCodeHint": "if errorCode is not in knownErrorCodes, use resolve.default",
        "defaultMatched": routing_decision_ready_resolve_default_matched,
        "defaultUsedDefault": routing_decision_ready_resolve_default_used_default,
        "defaultReason": routing_decision_ready_resolve_default_reason,
        "defaultEffectivePhase": routing_decision_ready_resolve_default_effective_phase_alias,
        "defaultEffectiveEscalationKey": routing_decision_ready_resolve_default_effective_escalation_key_alias,
        "knownErrorCode": routing_decision_ready_example_known_error_code,
        "knownResult": routing_decision_ready_example_known_error_result,
        "knownEffectivePhase": routing_decision_ready_example_known_effective_phase,
        "knownEffectiveEscalationKey": routing_decision_ready_example_known_effective_escalation_key,
        "missingErrorCode": routing_decision_ready_example_missing_error_code,
        "missingResult": routing_decision_ready_resolve_default.clone(),
        "missingEffectivePhase": routing_decision_ready_example_missing_effective_phase,
        "missingEffectiveEscalationKey": routing_decision_ready_example_missing_effective_escalation_key,
        "queryOnlyErrorCode": routing_decision_ready_resolve_query_only_example
            .get("errorCode")
            .cloned()
            .unwrap_or(Value::Null),
        "queryOnlyBlockedBy": routing_decision_ready_resolve_query_only_example
            .get("blockedBy")
            .cloned()
            .unwrap_or(Value::Null),
        "queryOnlyBlockedBySource": routing_decision_ready_resolve_query_only_example
            .get("blockedBySource")
            .cloned()
            .unwrap_or(Value::Null),
        "queryOnlyIsBlocked": routing_decision_ready_resolve_query_only_example
            .get("isBlocked")
            .cloned()
            .unwrap_or(Value::Null),
        "queryOnlyAvailable": routing_decision_ready_resolve_query_only_example
            .get("available")
            .cloned()
            .unwrap_or(Value::Null),
        "queryOnlyMatched": routing_decision_ready_resolve_query_only_example
            .get("matched")
            .cloned()
            .unwrap_or(Value::Null),
        "queryOnlyUsedDefault": routing_decision_ready_resolve_query_only_example
            .get("usedDefault")
            .cloned()
            .unwrap_or(Value::Null),
        "queryOnlyReason": routing_decision_ready_resolve_query_only_example
            .get("reason")
            .cloned()
            .unwrap_or(Value::Null),
        "queryOnlyEffectivePhase": routing_decision_ready_resolve_query_only_example
            .get("effectivePhase")
            .cloned()
            .unwrap_or(Value::Null),
        "queryOnlyEffectiveEscalationKey": routing_decision_ready_resolve_query_only_example
            .get("effectiveEscalationKey")
            .cloned()
            .unwrap_or(Value::Null),
        "queryOnlyWouldUsePath": routing_decision_ready_resolve_query_only_example
            .get("wouldUseQueryOnlyPath")
            .cloned()
            .unwrap_or(Value::Null),
        "queryOnlyResult": routing_decision_ready_resolve_query_only_example
            .get("result")
            .cloned()
            .unwrap_or(Value::Null),
        "index": routing_decision_ready_resolve_index,
        "default": routing_decision_ready_resolve_default,
        "examples": routing_decision_ready_resolve_examples,
    });
    let routing_decision_ready_phase_resolve = json!({
        "lookupKey": "phase",
        "policy": "index-then-defaultPhase",
        "outputShape": "{ matched, usedDefault, reason, effectivePhase, effectiveEscalationKey, effective }",
        "phaseCount": routing_decision_ready_known_phases.len(),
        "knownPhases": routing_decision_ready_known_phases.clone(),
        "knownEntries": routing_decision_ready_known_phases.clone(),
        "knownList": routing_decision_ready_known_phases.clone(),
        "knownEntriesCount": routing_decision_ready_known_phases.len(),
        "knownPhasesCount": routing_decision_ready_known_phases.len(),
        "knownPhaseFirst": routing_decision_ready_known_phases.first(),
        "knownPhasesFirst": routing_decision_ready_known_phases.first(),
        "knownEntriesFirst": routing_decision_ready_known_phases.first(),
        "knownFirst": routing_decision_ready_known_phases.first(),
        "knownPhaseLast": routing_decision_ready_known_phases.last(),
        "knownPhasesLast": routing_decision_ready_known_phases.last(),
        "knownEntriesLast": routing_decision_ready_known_phases.last(),
        "knownLast": routing_decision_ready_known_phases.last(),
        "defaultPhase": routing_decision_ready_default_phase.clone(),
        "missingPhaseHint": "if phase is not in knownPhases, use phaseResolve.default",
        "defaultMatched": routing_decision_ready_phase_resolve_default_matched,
        "defaultUsedDefault": routing_decision_ready_phase_resolve_default_used_default,
        "defaultReason": routing_decision_ready_phase_resolve_default_reason,
        "defaultEffectivePhase": routing_decision_ready_phase_resolve_default_effective_phase_alias,
        "defaultEffectiveEscalationKey": routing_decision_ready_phase_resolve_default_effective_escalation_key_alias,
        "knownPhase": routing_decision_ready_example_known_phase,
        "knownResult": routing_decision_ready_example_known_phase_result,
        "knownEffectivePhase": routing_decision_ready_example_known_phase_effective_phase,
        "knownEffectiveEscalationKey": routing_decision_ready_example_known_phase_effective_escalation_key,
        "missingPhase": routing_decision_ready_example_missing_phase,
        "missingResult": routing_decision_ready_phase_resolve_default.clone(),
        "missingEffectivePhase": routing_decision_ready_example_missing_phase_effective_phase,
        "missingEffectiveEscalationKey": routing_decision_ready_example_missing_phase_effective_escalation_key,
        "queryOnlySourceErrorCode": routing_decision_ready_phase_resolve_query_only_example
            .get("sourceErrorCode")
            .cloned()
            .unwrap_or(Value::Null),
        "queryOnlyBlockedBy": routing_decision_ready_phase_resolve_query_only_example
            .get("blockedBy")
            .cloned()
            .unwrap_or(Value::Null),
        "queryOnlyBlockedBySource": routing_decision_ready_phase_resolve_query_only_example
            .get("blockedBySource")
            .cloned()
            .unwrap_or(Value::Null),
        "queryOnlyIsBlocked": routing_decision_ready_phase_resolve_query_only_example
            .get("isBlocked")
            .cloned()
            .unwrap_or(Value::Null),
        "queryOnlyPhase": routing_decision_ready_phase_resolve_query_only_example
            .get("phase")
            .cloned()
            .unwrap_or(Value::Null),
        "queryOnlyAvailable": routing_decision_ready_phase_resolve_query_only_example
            .get("available")
            .cloned()
            .unwrap_or(Value::Null),
        "queryOnlyMatched": routing_decision_ready_phase_resolve_query_only_example
            .get("matched")
            .cloned()
            .unwrap_or(Value::Null),
        "queryOnlyUsedDefault": routing_decision_ready_phase_resolve_query_only_example
            .get("usedDefault")
            .cloned()
            .unwrap_or(Value::Null),
        "queryOnlyReason": routing_decision_ready_phase_resolve_query_only_example
            .get("reason")
            .cloned()
            .unwrap_or(Value::Null),
        "queryOnlyEffectivePhase": routing_decision_ready_phase_resolve_query_only_example
            .get("effectivePhase")
            .cloned()
            .unwrap_or(Value::Null),
        "queryOnlyEffectiveEscalationKey": routing_decision_ready_phase_resolve_query_only_example
            .get("effectiveEscalationKey")
            .cloned()
            .unwrap_or(Value::Null),
        "queryOnlyWouldUsePhase": routing_decision_ready_phase_resolve_query_only_example
            .get("wouldUseQueryPhase")
            .cloned()
            .unwrap_or(Value::Null),
        "queryOnlyResult": routing_decision_ready_phase_resolve_query_only_example
            .get("result")
            .cloned()
            .unwrap_or(Value::Null),
        "index": routing_decision_ready_phase_resolve_index,
        "default": routing_decision_ready_phase_resolve_default,
        "examples": routing_decision_ready_phase_resolve_examples,
    });
    let routing_decision_ready = json!({
        "lookupRule": "index[errorCode] || default",
        "entryCount": error_code_routing_entries.len(),
        "index": routing_decision_ready_index,
        "defaultEscalationKey": routing_decision_ready_default
            .get("escalationKey")
            .cloned()
            .unwrap_or(Value::Null),
        "defaultEffectiveEscalationKey": routing_decision_ready_default
            .get("effectiveEscalationKey")
            .cloned()
            .unwrap_or(Value::Null),
        "defaultPhase": routing_decision_ready_default
            .get("phase")
            .cloned()
            .unwrap_or(Value::Null),
        "defaultEffectivePhase": routing_decision_ready_default
            .get("effectivePhase")
            .cloned()
            .unwrap_or(Value::Null),
        "defaultTemplateCount": routing_decision_ready_default
            .get("templateCount")
            .cloned()
            .unwrap_or(Value::Null),
        "defaultTemplates": routing_decision_ready_default
            .get("templates")
            .cloned()
            .unwrap_or(json!([])),
        "defaultTemplate": routing_decision_ready_default
            .get("templates")
            .and_then(Value::as_array)
            .and_then(|templates| templates.first())
            .cloned()
            .unwrap_or(Value::Null),
        "defaultCommandJsonTemplateCount": routing_decision_ready_default
            .get("commandJsonTemplateCount")
            .cloned()
            .unwrap_or(Value::Null),
        "defaultCommandJsonTemplates": routing_decision_ready_default
            .get("commandJsonTemplates")
            .cloned()
            .unwrap_or(json!([])),
        "defaultCommandJsonTemplate": routing_decision_ready_default
            .get("commandJsonTemplates")
            .and_then(Value::as_array)
            .and_then(|templates| templates.first())
            .cloned()
            .unwrap_or(Value::Null),
        "defaultCommandJsonTemplateCommand": routing_decision_ready_default
            .get("commandJsonTemplates")
            .and_then(Value::as_array)
            .and_then(|templates| templates.first())
            .and_then(|template| template.get("command"))
            .cloned()
            .unwrap_or(Value::Null),
        "defaultCommandJsonTemplateRisk": routing_decision_ready_default
            .get("commandJsonTemplates")
            .and_then(Value::as_array)
            .and_then(|templates| templates.first())
            .and_then(|template| template.get("risk"))
            .cloned()
            .unwrap_or(Value::Null),
        "defaultCommandJsonTemplatePlaceholderCount": routing_decision_ready_default
            .get("commandJsonTemplates")
            .and_then(Value::as_array)
            .and_then(|templates| templates.first())
            .and_then(|template| template.get("placeholderCount"))
            .cloned()
            .unwrap_or(Value::Null),
        "defaultCommandJsonTemplatePlaceholders": routing_decision_ready_default
            .get("commandJsonTemplates")
            .and_then(Value::as_array)
            .and_then(|templates| templates.first())
            .and_then(|template| template.get("placeholders"))
            .cloned()
            .unwrap_or(json!([])),
        "defaultCommandJsonTemplateCliArgs": routing_decision_ready_default
            .get("commandJsonTemplates")
            .and_then(Value::as_array)
            .and_then(|templates| templates.first())
            .and_then(|template| template.get("cliArgs"))
            .cloned()
            .unwrap_or(json!([])),
        "defaultCommandJsonTemplateKind": routing_decision_ready_default
            .get("commandJsonTemplates")
            .and_then(Value::as_array)
            .and_then(|templates| templates.first())
            .and_then(|template| template.get("kind"))
            .cloned()
            .unwrap_or(Value::Null),
        "defaultCommandJsonTemplatePhase": routing_decision_ready_default
            .get("commandJsonTemplates")
            .and_then(Value::as_array)
            .and_then(|templates| templates.first())
            .and_then(|template| template.get("phase"))
            .cloned()
            .unwrap_or(Value::Null),
        "defaultCommandJsonTemplateErrorCode": routing_decision_ready_default
            .get("commandJsonTemplates")
            .and_then(Value::as_array)
            .and_then(|templates| templates.first())
            .and_then(|template| template.get("errorCode"))
            .cloned()
            .unwrap_or(Value::Null),
        "defaultCommandJsonTemplateTimeoutErrorCode": routing_decision_ready_default
            .get("commandJsonTemplates")
            .and_then(Value::as_array)
            .and_then(|templates| templates.first())
            .and_then(|template| template.get("timeoutErrorCode"))
            .cloned()
            .unwrap_or(Value::Null),
        "defaultCommandJsonTemplateRetryable": routing_decision_ready_default
            .get("commandJsonTemplates")
            .and_then(Value::as_array)
            .and_then(|templates| templates.first())
            .and_then(|template| template.get("retryable"))
            .cloned()
            .unwrap_or(Value::Null),
        "defaultCommandJsonTemplateMaxSuggestedRetries": routing_decision_ready_default
            .get("commandJsonTemplates")
            .and_then(Value::as_array)
            .and_then(|templates| templates.first())
            .and_then(|template| template.get("maxSuggestedRetries"))
            .cloned()
            .unwrap_or(Value::Null),
        "defaultCommandJsonTemplateRetryDelayHintMs": routing_decision_ready_default
            .get("commandJsonTemplates")
            .and_then(Value::as_array)
            .and_then(|templates| templates.first())
            .and_then(|template| template.get("retryDelayHintMs"))
            .cloned()
            .unwrap_or(Value::Null),
        "defaultCommandJsonTemplateTimeoutHintMs": routing_decision_ready_default
            .get("commandJsonTemplates")
            .and_then(Value::as_array)
            .and_then(|templates| templates.first())
            .and_then(|template| template.get("timeoutHintMs"))
            .cloned()
            .unwrap_or(Value::Null),
        "defaultCommandJsonTemplateTimeoutAction": routing_decision_ready_default
            .get("commandJsonTemplates")
            .and_then(Value::as_array)
            .and_then(|templates| templates.first())
            .and_then(|template| template.get("timeoutAction"))
            .cloned()
            .unwrap_or(Value::Null),
        "defaultCommandJsonTemplateCommandJsonEligible": routing_decision_ready_default
            .get("commandJsonTemplates")
            .and_then(Value::as_array)
            .and_then(|templates| templates.first())
            .and_then(|template| template.get("commandJsonEligible"))
            .cloned()
            .unwrap_or(Value::Null),
        "defaultMatchConfidence": routing_decision_ready_default
            .get("matchConfidence")
            .cloned()
            .unwrap_or(Value::Null),
        "defaultResolvedFrom": routing_decision_ready_default
            .get("resolvedFrom")
            .cloned()
            .unwrap_or(Value::Null),
        "resolveLookupKey": routing_decision_ready_resolve
            .get("lookupKey")
            .cloned()
            .unwrap_or(Value::Null),
        "resolvePolicy": routing_decision_ready_resolve
            .get("policy")
            .cloned()
            .unwrap_or(Value::Null),
        "resolveOutputShape": routing_decision_ready_resolve
            .get("outputShape")
            .cloned()
            .unwrap_or(Value::Null),
        "resolveIndex": routing_decision_ready_resolve
            .get("index")
            .cloned()
            .unwrap_or(json!({})),
        "resolveIndexEntries": routing_decision_ready_resolve
            .get("index")
            .cloned()
            .unwrap_or(json!({})),
        "resolveDefault": routing_decision_ready_resolve
            .get("default")
            .cloned()
            .unwrap_or(Value::Null),
        "resolveExamples": routing_decision_ready_resolve
            .get("examples")
            .cloned()
            .unwrap_or(json!({})),
        "resolveExampleKnownErrorCode": routing_decision_ready_resolve
            .get("examples")
            .and_then(|examples| examples.get("knownErrorCode"))
            .cloned()
            .unwrap_or(Value::Null),
        "resolveExampleKnownResult": routing_decision_ready_resolve
            .get("examples")
            .and_then(|examples| examples.get("knownResult"))
            .cloned()
            .unwrap_or(Value::Null),
        "resolveExampleKnownResultEffective": routing_decision_ready_resolve
            .get("examples")
            .and_then(|examples| examples.get("knownResult"))
            .and_then(|result| result.get("effective"))
            .cloned()
            .unwrap_or(Value::Null),
        "resolveExampleKnownResultEffectivePhase": routing_decision_ready_resolve
            .get("examples")
            .and_then(|examples| examples.get("knownResult"))
            .and_then(|result| result.get("effectivePhase"))
            .cloned()
            .unwrap_or(Value::Null),
        "resolveExampleKnownResultEffectiveEscalationKey": routing_decision_ready_resolve
            .get("examples")
            .and_then(|examples| examples.get("knownResult"))
            .and_then(|result| result.get("effectiveEscalationKey"))
            .cloned()
            .unwrap_or(Value::Null),
        "resolveExampleKnownMatched": routing_decision_ready_resolve
            .get("examples")
            .and_then(|examples| examples.get("knownResult"))
            .and_then(|result| result.get("matched"))
            .cloned()
            .unwrap_or(Value::Null),
        "resolveExampleKnownUsedDefault": routing_decision_ready_resolve
            .get("examples")
            .and_then(|examples| examples.get("knownResult"))
            .and_then(|result| result.get("usedDefault"))
            .cloned()
            .unwrap_or(Value::Null),
        "resolveExampleKnownReason": routing_decision_ready_resolve
            .get("examples")
            .and_then(|examples| examples.get("knownResult"))
            .and_then(|result| result.get("reason"))
            .cloned()
            .unwrap_or(Value::Null),
        "resolveExampleKnownEffectivePhase": routing_decision_ready_resolve
            .get("examples")
            .and_then(|examples| examples.get("knownEffectivePhase"))
            .cloned()
            .unwrap_or(Value::Null),
        "resolveExampleKnownEffectiveEscalationKey": routing_decision_ready_resolve
            .get("examples")
            .and_then(|examples| examples.get("knownEffectiveEscalationKey"))
            .cloned()
            .unwrap_or(Value::Null),
        "resolveExampleMissingErrorCode": routing_decision_ready_resolve
            .get("examples")
            .and_then(|examples| examples.get("missingErrorCode"))
            .cloned()
            .unwrap_or(Value::Null),
        "resolveExampleMissingResult": routing_decision_ready_resolve
            .get("examples")
            .and_then(|examples| examples.get("missingResult"))
            .cloned()
            .unwrap_or(Value::Null),
        "resolveExampleMissingResultEffective": routing_decision_ready_resolve
            .get("examples")
            .and_then(|examples| examples.get("missingResult"))
            .and_then(|result| result.get("effective"))
            .cloned()
            .unwrap_or(Value::Null),
        "resolveExampleMissingResultEffectivePhase": routing_decision_ready_resolve
            .get("examples")
            .and_then(|examples| examples.get("missingResult"))
            .and_then(|result| result.get("effectivePhase"))
            .cloned()
            .unwrap_or(Value::Null),
        "resolveExampleMissingResultEffectiveEscalationKey": routing_decision_ready_resolve
            .get("examples")
            .and_then(|examples| examples.get("missingResult"))
            .and_then(|result| result.get("effectiveEscalationKey"))
            .cloned()
            .unwrap_or(Value::Null),
        "resolveExampleMissingMatched": routing_decision_ready_resolve
            .get("examples")
            .and_then(|examples| examples.get("missingResult"))
            .and_then(|result| result.get("matched"))
            .cloned()
            .unwrap_or(Value::Null),
        "resolveExampleMissingUsedDefault": routing_decision_ready_resolve
            .get("examples")
            .and_then(|examples| examples.get("missingResult"))
            .and_then(|result| result.get("usedDefault"))
            .cloned()
            .unwrap_or(Value::Null),
        "resolveExampleMissingReason": routing_decision_ready_resolve
            .get("examples")
            .and_then(|examples| examples.get("missingResult"))
            .and_then(|result| result.get("reason"))
            .cloned()
            .unwrap_or(Value::Null),
        "resolveExampleMissingEffectivePhase": routing_decision_ready_resolve
            .get("examples")
            .and_then(|examples| examples.get("missingEffectivePhase"))
            .cloned()
            .unwrap_or(Value::Null),
        "resolveExampleMissingEffectiveEscalationKey": routing_decision_ready_resolve
            .get("examples")
            .and_then(|examples| examples.get("missingEffectiveEscalationKey"))
            .cloned()
            .unwrap_or(Value::Null),
        "resolveExampleQueryOnlyInstallFailure": routing_decision_ready_resolve
            .get("examples")
            .and_then(|examples| examples.get("queryOnlyInstallFailure"))
            .cloned()
            .unwrap_or(Value::Null),
        "resolveExampleQueryOnlyErrorCode": routing_decision_ready_resolve
            .get("examples")
            .and_then(|examples| examples.get("queryOnlyInstallFailure"))
            .and_then(|example| example.get("errorCode"))
            .cloned()
            .unwrap_or(Value::Null),
        "resolveExampleQueryOnlyBlockedBy": routing_decision_ready_resolve
            .get("examples")
            .and_then(|examples| examples.get("queryOnlyInstallFailure"))
            .and_then(|example| example.get("blockedBy"))
            .cloned()
            .unwrap_or(Value::Null),
        "resolveExampleQueryOnlyBlockedBySource": routing_decision_ready_resolve
            .get("examples")
            .and_then(|examples| examples.get("queryOnlyInstallFailure"))
            .and_then(|example| example.get("blockedBySource"))
            .cloned()
            .unwrap_or(Value::Null),
        "resolveExampleQueryOnlyIsBlocked": routing_decision_ready_resolve
            .get("examples")
            .and_then(|examples| examples.get("queryOnlyInstallFailure"))
            .and_then(|example| example.get("isBlocked"))
            .cloned()
            .unwrap_or(Value::Null),
        "resolveExampleQueryOnlyAvailable": routing_decision_ready_resolve
            .get("examples")
            .and_then(|examples| examples.get("queryOnlyInstallFailure"))
            .and_then(|example| example.get("available"))
            .cloned()
            .unwrap_or(Value::Null),
        "resolveExampleQueryOnlyMatched": routing_decision_ready_resolve
            .get("examples")
            .and_then(|examples| examples.get("queryOnlyInstallFailure"))
            .and_then(|example| example.get("matched"))
            .cloned()
            .unwrap_or(Value::Null),
        "resolveExampleQueryOnlyUsedDefault": routing_decision_ready_resolve
            .get("examples")
            .and_then(|examples| examples.get("queryOnlyInstallFailure"))
            .and_then(|example| example.get("usedDefault"))
            .cloned()
            .unwrap_or(Value::Null),
        "resolveExampleQueryOnlyReason": routing_decision_ready_resolve
            .get("examples")
            .and_then(|examples| examples.get("queryOnlyInstallFailure"))
            .and_then(|example| example.get("reason"))
            .cloned()
            .unwrap_or(Value::Null),
        "resolveExampleQueryOnlyEffectivePhase": routing_decision_ready_resolve
            .get("examples")
            .and_then(|examples| examples.get("queryOnlyInstallFailure"))
            .and_then(|example| example.get("effectivePhase"))
            .cloned()
            .unwrap_or(Value::Null),
        "resolveExampleQueryOnlyEffectiveEscalationKey": routing_decision_ready_resolve
            .get("examples")
            .and_then(|examples| examples.get("queryOnlyInstallFailure"))
            .and_then(|example| example.get("effectiveEscalationKey"))
            .cloned()
            .unwrap_or(Value::Null),
        "resolveExampleQueryOnlyWouldUsePath": routing_decision_ready_resolve
            .get("examples")
            .and_then(|examples| examples.get("queryOnlyInstallFailure"))
            .and_then(|example| example.get("wouldUseQueryOnlyPath"))
            .cloned()
            .unwrap_or(Value::Null),
        "resolveExampleQueryOnlyResult": routing_decision_ready_resolve
            .get("examples")
            .and_then(|examples| examples.get("queryOnlyInstallFailure"))
            .and_then(|example| example.get("result"))
            .cloned()
            .unwrap_or(Value::Null),
        "resolveExampleQueryOnlyResultEffective": routing_decision_ready_resolve
            .get("examples")
            .and_then(|examples| examples.get("queryOnlyInstallFailure"))
            .and_then(|example| example.get("result"))
            .and_then(|result| result.get("effective"))
            .cloned()
            .unwrap_or(Value::Null),
        "resolveExampleQueryOnlyResultMatched": routing_decision_ready_resolve
            .get("examples")
            .and_then(|examples| examples.get("queryOnlyInstallFailure"))
            .and_then(|example| example.get("result"))
            .and_then(|result| result.get("matched"))
            .cloned()
            .unwrap_or(Value::Null),
        "resolveExampleQueryOnlyResultUsedDefault": routing_decision_ready_resolve
            .get("examples")
            .and_then(|examples| examples.get("queryOnlyInstallFailure"))
            .and_then(|example| example.get("result"))
            .and_then(|result| result.get("usedDefault"))
            .cloned()
            .unwrap_or(Value::Null),
        "resolveExampleQueryOnlyResultReason": routing_decision_ready_resolve
            .get("examples")
            .and_then(|examples| examples.get("queryOnlyInstallFailure"))
            .and_then(|example| example.get("result"))
            .and_then(|result| result.get("reason"))
            .cloned()
            .unwrap_or(Value::Null),
        "resolveExampleQueryOnlyResultEffectivePhase": routing_decision_ready_resolve
            .get("examples")
            .and_then(|examples| examples.get("queryOnlyInstallFailure"))
            .and_then(|example| example.get("result"))
            .and_then(|result| result.get("effectivePhase"))
            .cloned()
            .unwrap_or(Value::Null),
        "resolveExampleQueryOnlyResultEffectiveEscalationKey": routing_decision_ready_resolve
            .get("examples")
            .and_then(|examples| examples.get("queryOnlyInstallFailure"))
            .and_then(|example| example.get("result"))
            .and_then(|result| result.get("effectiveEscalationKey"))
            .cloned()
            .unwrap_or(Value::Null),
        "resolveErrorCodeCount": routing_decision_ready_resolve
            .get("errorCodeCount")
            .cloned()
            .unwrap_or(Value::Null),
        "resolveIndexCount": routing_decision_ready_resolve
            .get("errorCodeCount")
            .cloned()
            .unwrap_or(Value::Null),
        "resolveKnownCount": routing_decision_ready_resolve
            .get("errorCodeCount")
            .cloned()
            .unwrap_or(Value::Null),
        "resolveKnownTotal": routing_decision_ready_resolve
            .get("errorCodeCount")
            .cloned()
            .unwrap_or(Value::Null),
        "resolveKnownAmount": routing_decision_ready_resolve
            .get("errorCodeCount")
            .cloned()
            .unwrap_or(Value::Null),
        "resolveKnownVolume": routing_decision_ready_resolve
            .get("errorCodeCount")
            .cloned()
            .unwrap_or(Value::Null),
        "resolveKnownMagnitude": routing_decision_ready_resolve
            .get("errorCodeCount")
            .cloned()
            .unwrap_or(Value::Null),
        "resolveKnownSize": routing_decision_ready_resolve
            .get("errorCodeCount")
            .cloned()
            .unwrap_or(Value::Null),
        "resolveKnownLength": routing_decision_ready_resolve
            .get("errorCodeCount")
            .cloned()
            .unwrap_or(Value::Null),
        "resolveKnownErrorCodes": routing_decision_ready_resolve
            .get("knownErrorCodes")
            .cloned()
            .unwrap_or(json!([])),
        "resolveKnownEntries": routing_decision_ready_resolve
            .get("knownErrorCodes")
            .cloned()
            .unwrap_or(json!([])),
        "resolveKnownList": routing_decision_ready_resolve
            .get("knownErrorCodes")
            .cloned()
            .unwrap_or(json!([])),
        "resolveKnownEntriesCount": routing_decision_ready_resolve
            .get("knownErrorCodes")
            .and_then(Value::as_array)
            .map(|codes| json!(codes.len()))
            .unwrap_or(Value::Null),
        "resolveKnownErrorCodesCount": routing_decision_ready_resolve
            .get("knownErrorCodes")
            .and_then(Value::as_array)
            .map(|codes| json!(codes.len()))
            .unwrap_or(Value::Null),
        "resolveKnownErrorCodeFirst": routing_decision_ready_resolve
            .get("knownErrorCodes")
            .and_then(Value::as_array)
            .and_then(|codes| codes.first())
            .cloned()
            .unwrap_or(Value::Null),
        "resolveKnownErrorCodesFirst": routing_decision_ready_resolve
            .get("knownErrorCodes")
            .and_then(Value::as_array)
            .and_then(|codes| codes.first())
            .cloned()
            .unwrap_or(Value::Null),
        "resolveKnownEntriesFirst": routing_decision_ready_resolve
            .get("knownErrorCodes")
            .and_then(Value::as_array)
            .and_then(|codes| codes.first())
            .cloned()
            .unwrap_or(Value::Null),
        "resolveKnownFirst": routing_decision_ready_resolve
            .get("knownErrorCodes")
            .and_then(Value::as_array)
            .and_then(|codes| codes.first())
            .cloned()
            .unwrap_or(Value::Null),
        "resolveIndexFirst": routing_decision_ready_resolve
            .get("knownErrorCodes")
            .and_then(Value::as_array)
            .and_then(|codes| codes.first())
            .cloned()
            .unwrap_or(Value::Null),
        "resolveKnownErrorCodeLast": routing_decision_ready_resolve
            .get("knownErrorCodes")
            .and_then(Value::as_array)
            .and_then(|codes| codes.last())
            .cloned()
            .unwrap_or(Value::Null),
        "resolveKnownErrorCodesLast": routing_decision_ready_resolve
            .get("knownErrorCodes")
            .and_then(Value::as_array)
            .and_then(|codes| codes.last())
            .cloned()
            .unwrap_or(Value::Null),
        "resolveKnownEntriesLast": routing_decision_ready_resolve
            .get("knownErrorCodes")
            .and_then(Value::as_array)
            .and_then(|codes| codes.last())
            .cloned()
            .unwrap_or(Value::Null),
        "resolveKnownLast": routing_decision_ready_resolve
            .get("knownErrorCodes")
            .and_then(Value::as_array)
            .and_then(|codes| codes.last())
            .cloned()
            .unwrap_or(Value::Null),
        "resolveIndexLast": routing_decision_ready_resolve
            .get("knownErrorCodes")
            .and_then(Value::as_array)
            .and_then(|codes| codes.last())
            .cloned()
            .unwrap_or(Value::Null),
        "resolveMissingErrorCodeHint": routing_decision_ready_resolve
            .get("missingErrorCodeHint")
            .cloned()
            .unwrap_or(Value::Null),
        "resolveMissingHint": routing_decision_ready_resolve
            .get("missingErrorCodeHint")
            .cloned()
            .unwrap_or(Value::Null),
        "resolveDefaultMatched": routing_decision_ready_resolve
            .get("defaultMatched")
            .cloned()
            .unwrap_or(Value::Null),
        "resolveDefaultUsedDefault": routing_decision_ready_resolve
            .get("defaultUsedDefault")
            .cloned()
            .unwrap_or(Value::Null),
        "resolveDefaultReason": routing_decision_ready_resolve
            .get("defaultReason")
            .cloned()
            .unwrap_or(Value::Null),
        "resolveDefaultEffective": routing_decision_ready_resolve
            .get("default")
            .and_then(|result| result.get("effective"))
            .cloned()
            .unwrap_or(Value::Null),
        "resolveDefaultEffectivePhase": routing_decision_ready_resolve
            .get("defaultEffectivePhase")
            .cloned()
            .unwrap_or(Value::Null),
        "resolveDefaultEffectiveEscalationKey": routing_decision_ready_resolve
            .get("defaultEffectiveEscalationKey")
            .cloned()
            .unwrap_or(Value::Null),
        "resolveKnownErrorCode": routing_decision_ready_resolve
            .get("knownErrorCode")
            .cloned()
            .unwrap_or(Value::Null),
        "resolveKnownResult": routing_decision_ready_resolve
            .get("knownResult")
            .cloned()
            .unwrap_or(Value::Null),
        "resolveKnownResultEffective": routing_decision_ready_resolve
            .get("knownResult")
            .and_then(|result| result.get("effective"))
            .cloned()
            .unwrap_or(Value::Null),
        "resolveKnownEffective": routing_decision_ready_resolve
            .get("knownResult")
            .and_then(|result| result.get("effective"))
            .cloned()
            .unwrap_or(Value::Null),
        "resolveKnownMatched": routing_decision_ready_resolve
            .get("knownResult")
            .and_then(|result| result.get("matched"))
            .cloned()
            .unwrap_or(Value::Null),
        "resolveKnownUsedDefault": routing_decision_ready_resolve
            .get("knownResult")
            .and_then(|result| result.get("usedDefault"))
            .cloned()
            .unwrap_or(Value::Null),
        "resolveKnownReason": routing_decision_ready_resolve
            .get("knownResult")
            .and_then(|result| result.get("reason"))
            .cloned()
            .unwrap_or(Value::Null),
        "resolveKnownEffectivePhase": routing_decision_ready_resolve
            .get("knownEffectivePhase")
            .cloned()
            .unwrap_or(Value::Null),
        "resolveKnownEffectiveEscalationKey": routing_decision_ready_resolve
            .get("knownEffectiveEscalationKey")
            .cloned()
            .unwrap_or(Value::Null),
        "resolveMissingErrorCode": routing_decision_ready_resolve
            .get("missingErrorCode")
            .cloned()
            .unwrap_or(Value::Null),
        "resolveMissingResult": routing_decision_ready_resolve
            .get("missingResult")
            .cloned()
            .unwrap_or(Value::Null),
        "resolveMissingResultEffective": routing_decision_ready_resolve
            .get("missingResult")
            .and_then(|result| result.get("effective"))
            .cloned()
            .unwrap_or(Value::Null),
        "resolveMissingEffective": routing_decision_ready_resolve
            .get("missingResult")
            .and_then(|result| result.get("effective"))
            .cloned()
            .unwrap_or(Value::Null),
        "resolveMissingMatched": routing_decision_ready_resolve
            .get("missingResult")
            .and_then(|result| result.get("matched"))
            .cloned()
            .unwrap_or(Value::Null),
        "resolveMissingUsedDefault": routing_decision_ready_resolve
            .get("missingResult")
            .and_then(|result| result.get("usedDefault"))
            .cloned()
            .unwrap_or(Value::Null),
        "resolveMissingReason": routing_decision_ready_resolve
            .get("missingResult")
            .and_then(|result| result.get("reason"))
            .cloned()
            .unwrap_or(Value::Null),
        "resolveMissingEffectivePhase": routing_decision_ready_resolve
            .get("missingEffectivePhase")
            .cloned()
            .unwrap_or(Value::Null),
        "resolveMissingEffectiveEscalationKey": routing_decision_ready_resolve
            .get("missingEffectiveEscalationKey")
            .cloned()
            .unwrap_or(Value::Null),
        "phaseResolveLookupKey": routing_decision_ready_phase_resolve
            .get("lookupKey")
            .cloned()
            .unwrap_or(Value::Null),
        "phaseResolvePolicy": routing_decision_ready_phase_resolve
            .get("policy")
            .cloned()
            .unwrap_or(Value::Null),
        "phaseResolveOutputShape": routing_decision_ready_phase_resolve
            .get("outputShape")
            .cloned()
            .unwrap_or(Value::Null),
        "phaseResolveIndex": routing_decision_ready_phase_resolve
            .get("index")
            .cloned()
            .unwrap_or(json!({})),
        "phaseResolveIndexEntries": routing_decision_ready_phase_resolve
            .get("index")
            .cloned()
            .unwrap_or(json!({})),
        "phaseResolveDefault": routing_decision_ready_phase_resolve
            .get("default")
            .cloned()
            .unwrap_or(Value::Null),
        "phaseResolveExamples": routing_decision_ready_phase_resolve
            .get("examples")
            .cloned()
            .unwrap_or(json!({})),
        "phaseResolveExampleKnownPhase": routing_decision_ready_phase_resolve
            .get("examples")
            .and_then(|examples| examples.get("knownPhase"))
            .cloned()
            .unwrap_or(Value::Null),
        "phaseResolveExampleKnownResult": routing_decision_ready_phase_resolve
            .get("examples")
            .and_then(|examples| examples.get("knownResult"))
            .cloned()
            .unwrap_or(Value::Null),
        "phaseResolveExampleKnownResultEffective": routing_decision_ready_phase_resolve
            .get("examples")
            .and_then(|examples| examples.get("knownResult"))
            .and_then(|result| result.get("effective"))
            .cloned()
            .unwrap_or(Value::Null),
        "phaseResolveExampleKnownResultEffectivePhase": routing_decision_ready_phase_resolve
            .get("examples")
            .and_then(|examples| examples.get("knownResult"))
            .and_then(|result| result.get("effectivePhase"))
            .cloned()
            .unwrap_or(Value::Null),
        "phaseResolveExampleKnownResultEffectiveEscalationKey": routing_decision_ready_phase_resolve
            .get("examples")
            .and_then(|examples| examples.get("knownResult"))
            .and_then(|result| result.get("effectiveEscalationKey"))
            .cloned()
            .unwrap_or(Value::Null),
        "phaseResolveExampleKnownMatched": routing_decision_ready_phase_resolve
            .get("examples")
            .and_then(|examples| examples.get("knownResult"))
            .and_then(|result| result.get("matched"))
            .cloned()
            .unwrap_or(Value::Null),
        "phaseResolveExampleKnownUsedDefault": routing_decision_ready_phase_resolve
            .get("examples")
            .and_then(|examples| examples.get("knownResult"))
            .and_then(|result| result.get("usedDefault"))
            .cloned()
            .unwrap_or(Value::Null),
        "phaseResolveExampleKnownReason": routing_decision_ready_phase_resolve
            .get("examples")
            .and_then(|examples| examples.get("knownResult"))
            .and_then(|result| result.get("reason"))
            .cloned()
            .unwrap_or(Value::Null),
        "phaseResolveExampleKnownEffectivePhase": routing_decision_ready_phase_resolve
            .get("examples")
            .and_then(|examples| examples.get("knownEffectivePhase"))
            .cloned()
            .unwrap_or(Value::Null),
        "phaseResolveExampleKnownEffectiveEscalationKey": routing_decision_ready_phase_resolve
            .get("examples")
            .and_then(|examples| examples.get("knownEffectiveEscalationKey"))
            .cloned()
            .unwrap_or(Value::Null),
        "phaseResolveExampleMissingPhase": routing_decision_ready_phase_resolve
            .get("examples")
            .and_then(|examples| examples.get("missingPhase"))
            .cloned()
            .unwrap_or(Value::Null),
        "phaseResolveExampleMissingResult": routing_decision_ready_phase_resolve
            .get("examples")
            .and_then(|examples| examples.get("missingResult"))
            .cloned()
            .unwrap_or(Value::Null),
        "phaseResolveExampleMissingResultEffective": routing_decision_ready_phase_resolve
            .get("examples")
            .and_then(|examples| examples.get("missingResult"))
            .and_then(|result| result.get("effective"))
            .cloned()
            .unwrap_or(Value::Null),
        "phaseResolveExampleMissingResultEffectivePhase": routing_decision_ready_phase_resolve
            .get("examples")
            .and_then(|examples| examples.get("missingResult"))
            .and_then(|result| result.get("effectivePhase"))
            .cloned()
            .unwrap_or(Value::Null),
        "phaseResolveExampleMissingResultEffectiveEscalationKey":
            routing_decision_ready_phase_resolve
                .get("examples")
                .and_then(|examples| examples.get("missingResult"))
                .and_then(|result| result.get("effectiveEscalationKey"))
                .cloned()
                .unwrap_or(Value::Null),
        "phaseResolveExampleMissingMatched": routing_decision_ready_phase_resolve
            .get("examples")
            .and_then(|examples| examples.get("missingResult"))
            .and_then(|result| result.get("matched"))
            .cloned()
            .unwrap_or(Value::Null),
        "phaseResolveExampleMissingUsedDefault": routing_decision_ready_phase_resolve
            .get("examples")
            .and_then(|examples| examples.get("missingResult"))
            .and_then(|result| result.get("usedDefault"))
            .cloned()
            .unwrap_or(Value::Null),
        "phaseResolveExampleMissingReason": routing_decision_ready_phase_resolve
            .get("examples")
            .and_then(|examples| examples.get("missingResult"))
            .and_then(|result| result.get("reason"))
            .cloned()
            .unwrap_or(Value::Null),
        "phaseResolveExampleMissingEffectivePhase": routing_decision_ready_phase_resolve
            .get("examples")
            .and_then(|examples| examples.get("missingEffectivePhase"))
            .cloned()
            .unwrap_or(Value::Null),
        "phaseResolveExampleMissingEffectiveEscalationKey": routing_decision_ready_phase_resolve
            .get("examples")
            .and_then(|examples| examples.get("missingEffectiveEscalationKey"))
            .cloned()
            .unwrap_or(Value::Null),
        "phaseResolveExampleQueryOnlyInstallFailure": routing_decision_ready_phase_resolve
            .get("examples")
            .and_then(|examples| examples.get("queryOnlyInstallFailure"))
            .cloned()
            .unwrap_or(Value::Null),
        "phaseResolveExampleQueryOnlySourceErrorCode": routing_decision_ready_phase_resolve
            .get("examples")
            .and_then(|examples| examples.get("queryOnlyInstallFailure"))
            .and_then(|example| example.get("sourceErrorCode"))
            .cloned()
            .unwrap_or(Value::Null),
        "phaseResolveExampleQueryOnlyPhase": routing_decision_ready_phase_resolve
            .get("examples")
            .and_then(|examples| examples.get("queryOnlyInstallFailure"))
            .and_then(|example| example.get("phase"))
            .cloned()
            .unwrap_or(Value::Null),
        "phaseResolveExampleQueryOnlyBlockedBy": routing_decision_ready_phase_resolve
            .get("examples")
            .and_then(|examples| examples.get("queryOnlyInstallFailure"))
            .and_then(|example| example.get("blockedBy"))
            .cloned()
            .unwrap_or(Value::Null),
        "phaseResolveExampleQueryOnlyBlockedBySource": routing_decision_ready_phase_resolve
            .get("examples")
            .and_then(|examples| examples.get("queryOnlyInstallFailure"))
            .and_then(|example| example.get("blockedBySource"))
            .cloned()
            .unwrap_or(Value::Null),
        "phaseResolveExampleQueryOnlyIsBlocked": routing_decision_ready_phase_resolve
            .get("examples")
            .and_then(|examples| examples.get("queryOnlyInstallFailure"))
            .and_then(|example| example.get("isBlocked"))
            .cloned()
            .unwrap_or(Value::Null),
        "phaseResolveExampleQueryOnlyAvailable": routing_decision_ready_phase_resolve
            .get("examples")
            .and_then(|examples| examples.get("queryOnlyInstallFailure"))
            .and_then(|example| example.get("available"))
            .cloned()
            .unwrap_or(Value::Null),
        "phaseResolveExampleQueryOnlyMatched": routing_decision_ready_phase_resolve
            .get("examples")
            .and_then(|examples| examples.get("queryOnlyInstallFailure"))
            .and_then(|example| example.get("matched"))
            .cloned()
            .unwrap_or(Value::Null),
        "phaseResolveExampleQueryOnlyUsedDefault": routing_decision_ready_phase_resolve
            .get("examples")
            .and_then(|examples| examples.get("queryOnlyInstallFailure"))
            .and_then(|example| example.get("usedDefault"))
            .cloned()
            .unwrap_or(Value::Null),
        "phaseResolveExampleQueryOnlyReason": routing_decision_ready_phase_resolve
            .get("examples")
            .and_then(|examples| examples.get("queryOnlyInstallFailure"))
            .and_then(|example| example.get("reason"))
            .cloned()
            .unwrap_or(Value::Null),
        "phaseResolveExampleQueryOnlyEffectivePhase": routing_decision_ready_phase_resolve
            .get("examples")
            .and_then(|examples| examples.get("queryOnlyInstallFailure"))
            .and_then(|example| example.get("effectivePhase"))
            .cloned()
            .unwrap_or(Value::Null),
        "phaseResolveExampleQueryOnlyEffectiveEscalationKey": routing_decision_ready_phase_resolve
            .get("examples")
            .and_then(|examples| examples.get("queryOnlyInstallFailure"))
            .and_then(|example| example.get("effectiveEscalationKey"))
            .cloned()
            .unwrap_or(Value::Null),
        "phaseResolveExampleQueryOnlyWouldUsePhase": routing_decision_ready_phase_resolve
            .get("examples")
            .and_then(|examples| examples.get("queryOnlyInstallFailure"))
            .and_then(|example| example.get("wouldUseQueryPhase"))
            .cloned()
            .unwrap_or(Value::Null),
        "phaseResolveExampleQueryOnlyResult": routing_decision_ready_phase_resolve
            .get("examples")
            .and_then(|examples| examples.get("queryOnlyInstallFailure"))
            .and_then(|example| example.get("result"))
            .cloned()
            .unwrap_or(Value::Null),
        "phaseResolveExampleQueryOnlyResultEffective": routing_decision_ready_phase_resolve
            .get("examples")
            .and_then(|examples| examples.get("queryOnlyInstallFailure"))
            .and_then(|example| example.get("result"))
            .and_then(|result| result.get("effective"))
            .cloned()
            .unwrap_or(Value::Null),
        "phaseResolveExampleQueryOnlyResultMatched": routing_decision_ready_phase_resolve
            .get("examples")
            .and_then(|examples| examples.get("queryOnlyInstallFailure"))
            .and_then(|example| example.get("result"))
            .and_then(|result| result.get("matched"))
            .cloned()
            .unwrap_or(Value::Null),
        "phaseResolveExampleQueryOnlyResultUsedDefault": routing_decision_ready_phase_resolve
            .get("examples")
            .and_then(|examples| examples.get("queryOnlyInstallFailure"))
            .and_then(|example| example.get("result"))
            .and_then(|result| result.get("usedDefault"))
            .cloned()
            .unwrap_or(Value::Null),
        "phaseResolveExampleQueryOnlyResultReason": routing_decision_ready_phase_resolve
            .get("examples")
            .and_then(|examples| examples.get("queryOnlyInstallFailure"))
            .and_then(|example| example.get("result"))
            .and_then(|result| result.get("reason"))
            .cloned()
            .unwrap_or(Value::Null),
        "phaseResolveExampleQueryOnlyResultEffectivePhase": routing_decision_ready_phase_resolve
            .get("examples")
            .and_then(|examples| examples.get("queryOnlyInstallFailure"))
            .and_then(|example| example.get("result"))
            .and_then(|result| result.get("effectivePhase"))
            .cloned()
            .unwrap_or(Value::Null),
        "phaseResolveExampleQueryOnlyResultEffectiveEscalationKey": routing_decision_ready_phase_resolve
            .get("examples")
            .and_then(|examples| examples.get("queryOnlyInstallFailure"))
            .and_then(|example| example.get("result"))
            .and_then(|result| result.get("effectiveEscalationKey"))
            .cloned()
            .unwrap_or(Value::Null),
        "phaseResolvePhaseCount": routing_decision_ready_phase_resolve
            .get("phaseCount")
            .cloned()
            .unwrap_or(Value::Null),
        "phaseResolveIndexCount": routing_decision_ready_phase_resolve
            .get("phaseCount")
            .cloned()
            .unwrap_or(Value::Null),
        "phaseResolveKnownCount": routing_decision_ready_phase_resolve
            .get("phaseCount")
            .cloned()
            .unwrap_or(Value::Null),
        "phaseResolveKnownTotal": routing_decision_ready_phase_resolve
            .get("phaseCount")
            .cloned()
            .unwrap_or(Value::Null),
        "phaseResolveKnownAmount": routing_decision_ready_phase_resolve
            .get("phaseCount")
            .cloned()
            .unwrap_or(Value::Null),
        "phaseResolveKnownVolume": routing_decision_ready_phase_resolve
            .get("phaseCount")
            .cloned()
            .unwrap_or(Value::Null),
        "phaseResolveKnownMagnitude": routing_decision_ready_phase_resolve
            .get("phaseCount")
            .cloned()
            .unwrap_or(Value::Null),
        "phaseResolveKnownSize": routing_decision_ready_phase_resolve
            .get("phaseCount")
            .cloned()
            .unwrap_or(Value::Null),
        "phaseResolveKnownLength": routing_decision_ready_phase_resolve
            .get("phaseCount")
            .cloned()
            .unwrap_or(Value::Null),
        "phaseResolveKnownPhases": routing_decision_ready_phase_resolve
            .get("knownPhases")
            .cloned()
            .unwrap_or(json!([])),
        "phaseResolveKnownEntries": routing_decision_ready_phase_resolve
            .get("knownPhases")
            .cloned()
            .unwrap_or(json!([])),
        "phaseResolveKnownList": routing_decision_ready_phase_resolve
            .get("knownPhases")
            .cloned()
            .unwrap_or(json!([])),
        "phaseResolveKnownEntriesCount": routing_decision_ready_phase_resolve
            .get("knownPhases")
            .and_then(Value::as_array)
            .map(|phases| json!(phases.len()))
            .unwrap_or(Value::Null),
        "phaseResolveKnownPhasesCount": routing_decision_ready_phase_resolve
            .get("knownPhases")
            .and_then(Value::as_array)
            .map(|phases| json!(phases.len()))
            .unwrap_or(Value::Null),
        "phaseResolveKnownPhaseFirst": routing_decision_ready_phase_resolve
            .get("knownPhases")
            .and_then(Value::as_array)
            .and_then(|phases| phases.first())
            .cloned()
            .unwrap_or(Value::Null),
        "phaseResolveKnownPhasesFirst": routing_decision_ready_phase_resolve
            .get("knownPhases")
            .and_then(Value::as_array)
            .and_then(|phases| phases.first())
            .cloned()
            .unwrap_or(Value::Null),
        "phaseResolveKnownEntriesFirst": routing_decision_ready_phase_resolve
            .get("knownPhases")
            .and_then(Value::as_array)
            .and_then(|phases| phases.first())
            .cloned()
            .unwrap_or(Value::Null),
        "phaseResolveKnownFirst": routing_decision_ready_phase_resolve
            .get("knownPhases")
            .and_then(Value::as_array)
            .and_then(|phases| phases.first())
            .cloned()
            .unwrap_or(Value::Null),
        "phaseResolveIndexFirst": routing_decision_ready_phase_resolve
            .get("knownPhases")
            .and_then(Value::as_array)
            .and_then(|phases| phases.first())
            .cloned()
            .unwrap_or(Value::Null),
        "phaseResolveKnownPhaseLast": routing_decision_ready_phase_resolve
            .get("knownPhases")
            .and_then(Value::as_array)
            .and_then(|phases| phases.last())
            .cloned()
            .unwrap_or(Value::Null),
        "phaseResolveKnownPhasesLast": routing_decision_ready_phase_resolve
            .get("knownPhases")
            .and_then(Value::as_array)
            .and_then(|phases| phases.last())
            .cloned()
            .unwrap_or(Value::Null),
        "phaseResolveKnownEntriesLast": routing_decision_ready_phase_resolve
            .get("knownPhases")
            .and_then(Value::as_array)
            .and_then(|phases| phases.last())
            .cloned()
            .unwrap_or(Value::Null),
        "phaseResolveKnownLast": routing_decision_ready_phase_resolve
            .get("knownPhases")
            .and_then(Value::as_array)
            .and_then(|phases| phases.last())
            .cloned()
            .unwrap_or(Value::Null),
        "phaseResolveIndexLast": routing_decision_ready_phase_resolve
            .get("knownPhases")
            .and_then(Value::as_array)
            .and_then(|phases| phases.last())
            .cloned()
            .unwrap_or(Value::Null),
        "phaseResolveMissingPhaseHint": routing_decision_ready_phase_resolve
            .get("missingPhaseHint")
            .cloned()
            .unwrap_or(Value::Null),
        "phaseResolveMissingHint": routing_decision_ready_phase_resolve
            .get("missingPhaseHint")
            .cloned()
            .unwrap_or(Value::Null),
        "phaseResolveDefaultPhase": routing_decision_ready_phase_resolve
            .get("defaultPhase")
            .cloned()
            .unwrap_or(Value::Null),
        "phaseResolveDefaultMatched": routing_decision_ready_phase_resolve
            .get("defaultMatched")
            .cloned()
            .unwrap_or(Value::Null),
        "phaseResolveDefaultUsedDefault": routing_decision_ready_phase_resolve
            .get("defaultUsedDefault")
            .cloned()
            .unwrap_or(Value::Null),
        "phaseResolveDefaultReason": routing_decision_ready_phase_resolve
            .get("defaultReason")
            .cloned()
            .unwrap_or(Value::Null),
        "phaseResolveDefaultEffective": routing_decision_ready_phase_resolve
            .get("default")
            .and_then(|result| result.get("effective"))
            .cloned()
            .unwrap_or(Value::Null),
        "phaseResolveDefaultEffectivePhase": routing_decision_ready_phase_resolve
            .get("defaultEffectivePhase")
            .cloned()
            .unwrap_or(Value::Null),
        "phaseResolveDefaultEffectiveEscalationKey": routing_decision_ready_phase_resolve
            .get("defaultEffectiveEscalationKey")
            .cloned()
            .unwrap_or(Value::Null),
        "phaseResolveKnownPhase": routing_decision_ready_phase_resolve
            .get("knownPhase")
            .cloned()
            .unwrap_or(Value::Null),
        "phaseResolveKnownResult": routing_decision_ready_phase_resolve
            .get("knownResult")
            .cloned()
            .unwrap_or(Value::Null),
        "phaseResolveKnownResultEffective": routing_decision_ready_phase_resolve
            .get("knownResult")
            .and_then(|result| result.get("effective"))
            .cloned()
            .unwrap_or(Value::Null),
        "phaseResolveKnownEffective": routing_decision_ready_phase_resolve
            .get("knownResult")
            .and_then(|result| result.get("effective"))
            .cloned()
            .unwrap_or(Value::Null),
        "phaseResolveKnownMatched": routing_decision_ready_phase_resolve
            .get("knownResult")
            .and_then(|result| result.get("matched"))
            .cloned()
            .unwrap_or(Value::Null),
        "phaseResolveKnownUsedDefault": routing_decision_ready_phase_resolve
            .get("knownResult")
            .and_then(|result| result.get("usedDefault"))
            .cloned()
            .unwrap_or(Value::Null),
        "phaseResolveKnownReason": routing_decision_ready_phase_resolve
            .get("knownResult")
            .and_then(|result| result.get("reason"))
            .cloned()
            .unwrap_or(Value::Null),
        "phaseResolveKnownEffectivePhase": routing_decision_ready_phase_resolve
            .get("knownEffectivePhase")
            .cloned()
            .unwrap_or(Value::Null),
        "phaseResolveKnownEffectiveEscalationKey": routing_decision_ready_phase_resolve
            .get("knownEffectiveEscalationKey")
            .cloned()
            .unwrap_or(Value::Null),
        "phaseResolveMissingPhase": routing_decision_ready_phase_resolve
            .get("missingPhase")
            .cloned()
            .unwrap_or(Value::Null),
        "phaseResolveMissingResult": routing_decision_ready_phase_resolve
            .get("missingResult")
            .cloned()
            .unwrap_or(Value::Null),
        "phaseResolveMissingResultEffective": routing_decision_ready_phase_resolve
            .get("missingResult")
            .and_then(|result| result.get("effective"))
            .cloned()
            .unwrap_or(Value::Null),
        "phaseResolveMissingEffective": routing_decision_ready_phase_resolve
            .get("missingResult")
            .and_then(|result| result.get("effective"))
            .cloned()
            .unwrap_or(Value::Null),
        "phaseResolveMissingMatched": routing_decision_ready_phase_resolve
            .get("missingResult")
            .and_then(|result| result.get("matched"))
            .cloned()
            .unwrap_or(Value::Null),
        "phaseResolveMissingUsedDefault": routing_decision_ready_phase_resolve
            .get("missingResult")
            .and_then(|result| result.get("usedDefault"))
            .cloned()
            .unwrap_or(Value::Null),
        "phaseResolveMissingReason": routing_decision_ready_phase_resolve
            .get("missingResult")
            .and_then(|result| result.get("reason"))
            .cloned()
            .unwrap_or(Value::Null),
        "phaseResolveMissingEffectivePhase": routing_decision_ready_phase_resolve
            .get("missingEffectivePhase")
            .cloned()
            .unwrap_or(Value::Null),
        "phaseResolveMissingEffectiveEscalationKey": routing_decision_ready_phase_resolve
            .get("missingEffectiveEscalationKey")
            .cloned()
            .unwrap_or(Value::Null),
        "queryOnlyErrorCode": routing_decision_ready_resolve
            .get("queryOnlyErrorCode")
            .cloned()
            .unwrap_or(Value::Null),
        "queryOnlySourceErrorCode": routing_decision_ready_phase_resolve
            .get("queryOnlySourceErrorCode")
            .cloned()
            .unwrap_or(Value::Null),
        "queryOnlyBlockedBy": routing_decision_ready_resolve
            .get("queryOnlyBlockedBy")
            .cloned()
            .unwrap_or(Value::Null),
        "queryOnlyResolveBlockedBy": routing_decision_ready_resolve
            .get("queryOnlyBlockedBy")
            .cloned()
            .unwrap_or(Value::Null),
        "queryOnlyBlockedBySource": routing_decision_ready_resolve
            .get("queryOnlyBlockedBySource")
            .cloned()
            .unwrap_or(Value::Null),
        "queryOnlyResolveBlockedBySource": routing_decision_ready_resolve
            .get("queryOnlyBlockedBySource")
            .cloned()
            .unwrap_or(Value::Null),
        "queryOnlyIsBlocked": routing_decision_ready_resolve
            .get("queryOnlyIsBlocked")
            .cloned()
            .unwrap_or(Value::Null),
        "queryOnlyResolveIsBlocked": routing_decision_ready_resolve
            .get("queryOnlyIsBlocked")
            .cloned()
            .unwrap_or(Value::Null),
        "queryOnlyPhase": routing_decision_ready_phase_resolve
            .get("queryOnlyPhase")
            .cloned()
            .unwrap_or(Value::Null),
        "queryOnlyPhaseResolveSourceErrorCode": routing_decision_ready_phase_resolve
            .get("queryOnlySourceErrorCode")
            .cloned()
            .unwrap_or(Value::Null),
        "queryOnlyPhaseResolvePhase": routing_decision_ready_phase_resolve
            .get("queryOnlyPhase")
            .cloned()
            .unwrap_or(Value::Null),
        "queryOnlyPhaseResolveBlockedBy": routing_decision_ready_phase_resolve
            .get("queryOnlyBlockedBy")
            .cloned()
            .unwrap_or(Value::Null),
        "queryOnlyPhaseResolveBlockedBySource": routing_decision_ready_phase_resolve
            .get("queryOnlyBlockedBySource")
            .cloned()
            .unwrap_or(Value::Null),
        "queryOnlyPhaseResolveIsBlocked": routing_decision_ready_phase_resolve
            .get("queryOnlyIsBlocked")
            .cloned()
            .unwrap_or(Value::Null),
        "queryOnlyPhaseResolveAvailable": routing_decision_ready_phase_resolve
            .get("queryOnlyAvailable")
            .cloned()
            .unwrap_or(Value::Null),
        "queryOnlyPhaseResolveMatched": routing_decision_ready_phase_resolve
            .get("queryOnlyMatched")
            .cloned()
            .unwrap_or(Value::Null),
        "queryOnlyPhaseResolveUsedDefault": routing_decision_ready_phase_resolve
            .get("queryOnlyUsedDefault")
            .cloned()
            .unwrap_or(Value::Null),
        "queryOnlyPhaseResolveReason": routing_decision_ready_phase_resolve
            .get("queryOnlyReason")
            .cloned()
            .unwrap_or(Value::Null),
        "queryOnlyPhaseResolveEffectivePhase": routing_decision_ready_phase_resolve
            .get("queryOnlyEffectivePhase")
            .cloned()
            .unwrap_or(Value::Null),
        "queryOnlyPhaseResolveEffectiveEscalationKey": routing_decision_ready_phase_resolve
            .get("queryOnlyEffectiveEscalationKey")
            .cloned()
            .unwrap_or(Value::Null),
        "queryOnlyAvailable": routing_decision_ready_resolve
            .get("queryOnlyAvailable")
            .cloned()
            .unwrap_or(Value::Null),
        "queryOnlyResolveAvailable": routing_decision_ready_resolve
            .get("queryOnlyAvailable")
            .cloned()
            .unwrap_or(Value::Null),
        "queryOnlyMatched": routing_decision_ready_resolve
            .get("queryOnlyMatched")
            .cloned()
            .unwrap_or(Value::Null),
        "queryOnlyResolveMatched": routing_decision_ready_resolve
            .get("queryOnlyMatched")
            .cloned()
            .unwrap_or(Value::Null),
        "queryOnlyUsedDefault": routing_decision_ready_resolve
            .get("queryOnlyUsedDefault")
            .cloned()
            .unwrap_or(Value::Null),
        "queryOnlyResolveUsedDefault": routing_decision_ready_resolve
            .get("queryOnlyUsedDefault")
            .cloned()
            .unwrap_or(Value::Null),
        "queryOnlyReason": routing_decision_ready_resolve
            .get("queryOnlyReason")
            .cloned()
            .unwrap_or(Value::Null),
        "queryOnlyResolveReason": routing_decision_ready_resolve
            .get("queryOnlyReason")
            .cloned()
            .unwrap_or(Value::Null),
        "queryOnlyEffectivePhase": routing_decision_ready_resolve
            .get("queryOnlyEffectivePhase")
            .cloned()
            .unwrap_or(Value::Null),
        "queryOnlyResolveEffectivePhase": routing_decision_ready_resolve
            .get("queryOnlyEffectivePhase")
            .cloned()
            .unwrap_or(Value::Null),
        "queryOnlyEffectiveEscalationKey": routing_decision_ready_resolve
            .get("queryOnlyEffectiveEscalationKey")
            .cloned()
            .unwrap_or(Value::Null),
        "queryOnlyResolveEffectiveEscalationKey": routing_decision_ready_resolve
            .get("queryOnlyEffectiveEscalationKey")
            .cloned()
            .unwrap_or(Value::Null),
        "queryOnlyWouldUsePath": routing_decision_ready_resolve
            .get("queryOnlyWouldUsePath")
            .cloned()
            .unwrap_or(Value::Null),
        "queryOnlyResolveWouldUsePath": routing_decision_ready_resolve
            .get("queryOnlyWouldUsePath")
            .cloned()
            .unwrap_or(Value::Null),
        "queryOnlyWouldUsePhase": routing_decision_ready_phase_resolve
            .get("queryOnlyWouldUsePhase")
            .cloned()
            .unwrap_or(Value::Null),
        "queryOnlyPhaseResolveWouldUsePhase": routing_decision_ready_phase_resolve
            .get("queryOnlyWouldUsePhase")
            .cloned()
            .unwrap_or(Value::Null),
        "queryOnlyResolveResult": routing_decision_ready_resolve
            .get("queryOnlyResult")
            .cloned()
            .unwrap_or(Value::Null),
        "queryOnlyResolveResultEffective": routing_decision_ready_resolve
            .get("queryOnlyResult")
            .and_then(|result| result.get("effective"))
            .cloned()
            .unwrap_or(Value::Null),
        "queryOnlyResolveResultMatched": routing_decision_ready_resolve
            .get("queryOnlyResult")
            .and_then(|result| result.get("matched"))
            .cloned()
            .unwrap_or(Value::Null),
        "queryOnlyResolveResultUsedDefault": routing_decision_ready_resolve
            .get("queryOnlyResult")
            .and_then(|result| result.get("usedDefault"))
            .cloned()
            .unwrap_or(Value::Null),
        "queryOnlyResolveResultReason": routing_decision_ready_resolve
            .get("queryOnlyResult")
            .and_then(|result| result.get("reason"))
            .cloned()
            .unwrap_or(Value::Null),
        "queryOnlyResolveResultEffectivePhase": routing_decision_ready_resolve
            .get("queryOnlyResult")
            .and_then(|result| result.get("effectivePhase"))
            .cloned()
            .unwrap_or(Value::Null),
        "queryOnlyResolveResultEffectiveEscalationKey": routing_decision_ready_resolve
            .get("queryOnlyResult")
            .and_then(|result| result.get("effectiveEscalationKey"))
            .cloned()
            .unwrap_or(Value::Null),
        "queryOnlyPhaseResolveResult": routing_decision_ready_phase_resolve
            .get("queryOnlyResult")
            .cloned()
            .unwrap_or(Value::Null),
        "queryOnlyPhaseResolveResultEffective": routing_decision_ready_phase_resolve
            .get("queryOnlyResult")
            .and_then(|result| result.get("effective"))
            .cloned()
            .unwrap_or(Value::Null),
        "queryOnlyPhaseResolveResultMatched": routing_decision_ready_phase_resolve
            .get("queryOnlyResult")
            .and_then(|result| result.get("matched"))
            .cloned()
            .unwrap_or(Value::Null),
        "queryOnlyPhaseResolveResultUsedDefault": routing_decision_ready_phase_resolve
            .get("queryOnlyResult")
            .and_then(|result| result.get("usedDefault"))
            .cloned()
            .unwrap_or(Value::Null),
        "queryOnlyPhaseResolveResultReason": routing_decision_ready_phase_resolve
            .get("queryOnlyResult")
            .and_then(|result| result.get("reason"))
            .cloned()
            .unwrap_or(Value::Null),
        "queryOnlyPhaseResolveResultEffectivePhase": routing_decision_ready_phase_resolve
            .get("queryOnlyResult")
            .and_then(|result| result.get("effectivePhase"))
            .cloned()
            .unwrap_or(Value::Null),
        "queryOnlyPhaseResolveResultEffectiveEscalationKey": routing_decision_ready_phase_resolve
            .get("queryOnlyResult")
            .and_then(|result| result.get("effectiveEscalationKey"))
            .cloned()
            .unwrap_or(Value::Null),
        "default": routing_decision_ready_default,
        "resolve": routing_decision_ready_resolve,
        "phaseResolve": routing_decision_ready_phase_resolve,
        "phaseCount": routing_decision_ready_phase_entries.len(),
        "phases": routing_decision_ready_phase_entries,
        "phaseFirst": routing_decision_ready_phase_entries
            .first()
            .and_then(|entry| entry.get("phase"))
            .cloned()
            .unwrap_or(Value::Null),
        "phaseLast": routing_decision_ready_phase_entries
            .last()
            .and_then(|entry| entry.get("phase"))
            .cloned()
            .unwrap_or(Value::Null),
        "phaseIndex": routing_decision_ready_phase_index,
        "phasePreflight": routing_decision_ready_phase_preflight.clone(),
        "phasePreflightErrorCodeCount": routing_decision_ready_phase_preflight
            .get("errorCodeCount")
            .cloned()
            .unwrap_or(Value::Null),
        "phasePreflightErrorCodes": routing_decision_ready_phase_preflight
            .get("errorCodes")
            .cloned()
            .unwrap_or(json!([])),
        "phasePreflightErrorCodeFirst": routing_decision_ready_phase_preflight
            .get("errorCodes")
            .and_then(Value::as_array)
            .and_then(|codes| codes.first())
            .cloned()
            .unwrap_or(Value::Null),
        "phasePreflightErrorCodeLast": routing_decision_ready_phase_preflight
            .get("errorCodes")
            .and_then(Value::as_array)
            .and_then(|codes| codes.last())
            .cloned()
            .unwrap_or(Value::Null),
        "phasePreflightEscalationKeyCount": routing_decision_ready_phase_preflight
            .get("escalationKeyCount")
            .cloned()
            .unwrap_or(Value::Null),
        "phasePreflightEscalationKeys": routing_decision_ready_phase_preflight
            .get("escalationKeys")
            .cloned()
            .unwrap_or(json!([])),
        "phasePreflightPrimaryEscalationKey": routing_decision_ready_phase_preflight
            .get("escalationKeys")
            .and_then(Value::as_array)
            .and_then(|keys| keys.first())
            .cloned()
            .unwrap_or(Value::Null),
        "phasePreflightTemplateCount": routing_decision_ready_phase_preflight
            .get("templateCount")
            .cloned()
            .unwrap_or(Value::Null),
        "phasePreflightTemplates": routing_decision_ready_phase_preflight
            .get("templates")
            .cloned()
            .unwrap_or(json!([])),
        "phasePreflightTemplate": routing_decision_ready_phase_preflight
            .get("templates")
            .and_then(Value::as_array)
            .and_then(|templates| templates.first())
            .cloned()
            .unwrap_or(Value::Null),
        "phasePreflightCommandJsonTemplateCount": routing_decision_ready_phase_preflight
            .get("commandJsonTemplateCount")
            .cloned()
            .unwrap_or(Value::Null),
        "phasePreflightCommandJsonTemplates": routing_decision_ready_phase_preflight
            .get("commandJsonTemplates")
            .cloned()
            .unwrap_or(json!([])),
        "phasePreflightCommandJsonTemplate": routing_decision_ready_phase_preflight
            .get("commandJsonTemplates")
            .and_then(Value::as_array)
            .and_then(|templates| templates.first())
            .cloned()
            .unwrap_or(Value::Null),
        "phasePreflightCommandJsonTemplateCommand": routing_decision_ready_phase_preflight
            .get("commandJsonTemplates")
            .and_then(Value::as_array)
            .and_then(|templates| templates.first())
            .and_then(|template| template.get("command"))
            .cloned()
            .unwrap_or(Value::Null),
        "phasePreflightCommandJsonTemplateRisk": routing_decision_ready_phase_preflight
            .get("commandJsonTemplates")
            .and_then(Value::as_array)
            .and_then(|templates| templates.first())
            .and_then(|template| template.get("risk"))
            .cloned()
            .unwrap_or(Value::Null),
        "phasePreflightCommandJsonTemplatePlaceholderCount":
            routing_decision_ready_phase_preflight
                .get("commandJsonTemplates")
                .and_then(Value::as_array)
                .and_then(|templates| templates.first())
                .and_then(|template| template.get("placeholderCount"))
                .cloned()
                .unwrap_or(Value::Null),
        "phasePreflightCommandJsonTemplatePlaceholders": routing_decision_ready_phase_preflight
            .get("commandJsonTemplates")
            .and_then(Value::as_array)
            .and_then(|templates| templates.first())
            .and_then(|template| template.get("placeholders"))
            .cloned()
            .unwrap_or(json!([])),
        "phasePreflightCommandJsonTemplateCliArgs": routing_decision_ready_phase_preflight
            .get("commandJsonTemplates")
            .and_then(Value::as_array)
            .and_then(|templates| templates.first())
            .and_then(|template| template.get("cliArgs"))
            .cloned()
            .unwrap_or(json!([])),
        "phasePreflightCommandJsonTemplateKind": routing_decision_ready_phase_preflight
            .get("commandJsonTemplates")
            .and_then(Value::as_array)
            .and_then(|templates| templates.first())
            .and_then(|template| template.get("kind"))
            .cloned()
            .unwrap_or(Value::Null),
        "phasePreflightCommandJsonTemplatePhase": routing_decision_ready_phase_preflight
            .get("commandJsonTemplates")
            .and_then(Value::as_array)
            .and_then(|templates| templates.first())
            .and_then(|template| template.get("phase"))
            .cloned()
            .unwrap_or(Value::Null),
        "phasePreflightCommandJsonTemplateErrorCode": routing_decision_ready_phase_preflight
            .get("commandJsonTemplates")
            .and_then(Value::as_array)
            .and_then(|templates| templates.first())
            .and_then(|template| template.get("errorCode"))
            .cloned()
            .unwrap_or(Value::Null),
        "phasePreflightCommandJsonTemplateTimeoutErrorCode":
            routing_decision_ready_phase_preflight
                .get("commandJsonTemplates")
                .and_then(Value::as_array)
                .and_then(|templates| templates.first())
                .and_then(|template| template.get("timeoutErrorCode"))
                .cloned()
                .unwrap_or(Value::Null),
        "phasePreflightCommandJsonTemplateRetryable": routing_decision_ready_phase_preflight
            .get("commandJsonTemplates")
            .and_then(Value::as_array)
            .and_then(|templates| templates.first())
            .and_then(|template| template.get("retryable"))
            .cloned()
            .unwrap_or(Value::Null),
        "phasePreflightCommandJsonTemplateMaxSuggestedRetries":
            routing_decision_ready_phase_preflight
                .get("commandJsonTemplates")
                .and_then(Value::as_array)
                .and_then(|templates| templates.first())
                .and_then(|template| template.get("maxSuggestedRetries"))
                .cloned()
                .unwrap_or(Value::Null),
        "phasePreflightCommandJsonTemplateRetryDelayHintMs":
            routing_decision_ready_phase_preflight
                .get("commandJsonTemplates")
                .and_then(Value::as_array)
                .and_then(|templates| templates.first())
                .and_then(|template| template.get("retryDelayHintMs"))
                .cloned()
                .unwrap_or(Value::Null),
        "phasePreflightCommandJsonTemplateTimeoutHintMs":
            routing_decision_ready_phase_preflight
                .get("commandJsonTemplates")
                .and_then(Value::as_array)
                .and_then(|templates| templates.first())
                .and_then(|template| template.get("timeoutHintMs"))
                .cloned()
                .unwrap_or(Value::Null),
        "phasePreflightCommandJsonTemplateTimeoutAction": routing_decision_ready_phase_preflight
            .get("commandJsonTemplates")
            .and_then(Value::as_array)
            .and_then(|templates| templates.first())
            .and_then(|template| template.get("timeoutAction"))
            .cloned()
            .unwrap_or(Value::Null),
        "phasePreflightCommandJsonTemplateCommandJsonEligible":
            routing_decision_ready_phase_preflight
                .get("commandJsonTemplates")
                .and_then(Value::as_array)
                .and_then(|templates| templates.first())
                .and_then(|template| template.get("commandJsonEligible"))
                .cloned()
                .unwrap_or(Value::Null),
        "phaseDiagnose": routing_decision_ready_phase_diagnose.clone(),
        "phaseDiagnoseErrorCodeCount": routing_decision_ready_phase_diagnose
            .get("errorCodeCount")
            .cloned()
            .unwrap_or(Value::Null),
        "phaseDiagnoseErrorCodes": routing_decision_ready_phase_diagnose
            .get("errorCodes")
            .cloned()
            .unwrap_or(json!([])),
        "phaseDiagnoseErrorCodeFirst": routing_decision_ready_phase_diagnose
            .get("errorCodes")
            .and_then(Value::as_array)
            .and_then(|codes| codes.first())
            .cloned()
            .unwrap_or(Value::Null),
        "phaseDiagnoseErrorCodeLast": routing_decision_ready_phase_diagnose
            .get("errorCodes")
            .and_then(Value::as_array)
            .and_then(|codes| codes.last())
            .cloned()
            .unwrap_or(Value::Null),
        "phaseDiagnoseEscalationKeyCount": routing_decision_ready_phase_diagnose
            .get("escalationKeyCount")
            .cloned()
            .unwrap_or(Value::Null),
        "phaseDiagnoseEscalationKeys": routing_decision_ready_phase_diagnose
            .get("escalationKeys")
            .cloned()
            .unwrap_or(json!([])),
        "phaseDiagnosePrimaryEscalationKey": routing_decision_ready_phase_diagnose
            .get("escalationKeys")
            .and_then(Value::as_array)
            .and_then(|keys| keys.first())
            .cloned()
            .unwrap_or(Value::Null),
        "phaseDiagnoseTemplateCount": routing_decision_ready_phase_diagnose
            .get("templateCount")
            .cloned()
            .unwrap_or(Value::Null),
        "phaseDiagnoseTemplates": routing_decision_ready_phase_diagnose
            .get("templates")
            .cloned()
            .unwrap_or(json!([])),
        "phaseDiagnoseTemplate": routing_decision_ready_phase_diagnose
            .get("templates")
            .and_then(Value::as_array)
            .and_then(|templates| templates.first())
            .cloned()
            .unwrap_or(Value::Null),
        "phaseDiagnoseCommandJsonTemplateCount": routing_decision_ready_phase_diagnose
            .get("commandJsonTemplateCount")
            .cloned()
            .unwrap_or(Value::Null),
        "phaseDiagnoseCommandJsonTemplates": routing_decision_ready_phase_diagnose
            .get("commandJsonTemplates")
            .cloned()
            .unwrap_or(json!([])),
        "phaseDiagnoseCommandJsonTemplate": routing_decision_ready_phase_diagnose
            .get("commandJsonTemplates")
            .and_then(Value::as_array)
            .and_then(|templates| templates.first())
            .cloned()
            .unwrap_or(Value::Null),
        "phaseDiagnoseCommandJsonTemplateCommand": routing_decision_ready_phase_diagnose
            .get("commandJsonTemplates")
            .and_then(Value::as_array)
            .and_then(|templates| templates.first())
            .and_then(|template| template.get("command"))
            .cloned()
            .unwrap_or(Value::Null),
        "phaseDiagnoseCommandJsonTemplateRisk": routing_decision_ready_phase_diagnose
            .get("commandJsonTemplates")
            .and_then(Value::as_array)
            .and_then(|templates| templates.first())
            .and_then(|template| template.get("risk"))
            .cloned()
            .unwrap_or(Value::Null),
        "phaseDiagnoseCommandJsonTemplatePlaceholderCount":
            routing_decision_ready_phase_diagnose
                .get("commandJsonTemplates")
                .and_then(Value::as_array)
                .and_then(|templates| templates.first())
                .and_then(|template| template.get("placeholderCount"))
                .cloned()
                .unwrap_or(Value::Null),
        "phaseDiagnoseCommandJsonTemplatePlaceholders": routing_decision_ready_phase_diagnose
            .get("commandJsonTemplates")
            .and_then(Value::as_array)
            .and_then(|templates| templates.first())
            .and_then(|template| template.get("placeholders"))
            .cloned()
            .unwrap_or(json!([])),
        "phaseDiagnoseCommandJsonTemplateCliArgs": routing_decision_ready_phase_diagnose
            .get("commandJsonTemplates")
            .and_then(Value::as_array)
            .and_then(|templates| templates.first())
            .and_then(|template| template.get("cliArgs"))
            .cloned()
            .unwrap_or(json!([])),
        "phaseDiagnoseCommandJsonTemplateKind": routing_decision_ready_phase_diagnose
            .get("commandJsonTemplates")
            .and_then(Value::as_array)
            .and_then(|templates| templates.first())
            .and_then(|template| template.get("kind"))
            .cloned()
            .unwrap_or(Value::Null),
        "phaseDiagnoseCommandJsonTemplatePhase": routing_decision_ready_phase_diagnose
            .get("commandJsonTemplates")
            .and_then(Value::as_array)
            .and_then(|templates| templates.first())
            .and_then(|template| template.get("phase"))
            .cloned()
            .unwrap_or(Value::Null),
        "phaseDiagnoseCommandJsonTemplateErrorCode": routing_decision_ready_phase_diagnose
            .get("commandJsonTemplates")
            .and_then(Value::as_array)
            .and_then(|templates| templates.first())
            .and_then(|template| template.get("errorCode"))
            .cloned()
            .unwrap_or(Value::Null),
        "phaseDiagnoseCommandJsonTemplateTimeoutErrorCode":
            routing_decision_ready_phase_diagnose
                .get("commandJsonTemplates")
                .and_then(Value::as_array)
                .and_then(|templates| templates.first())
                .and_then(|template| template.get("timeoutErrorCode"))
                .cloned()
                .unwrap_or(Value::Null),
        "phaseDiagnoseCommandJsonTemplateRetryable": routing_decision_ready_phase_diagnose
            .get("commandJsonTemplates")
            .and_then(Value::as_array)
            .and_then(|templates| templates.first())
            .and_then(|template| template.get("retryable"))
            .cloned()
            .unwrap_or(Value::Null),
        "phaseDiagnoseCommandJsonTemplateMaxSuggestedRetries":
            routing_decision_ready_phase_diagnose
                .get("commandJsonTemplates")
                .and_then(Value::as_array)
                .and_then(|templates| templates.first())
                .and_then(|template| template.get("maxSuggestedRetries"))
                .cloned()
                .unwrap_or(Value::Null),
        "phaseDiagnoseCommandJsonTemplateRetryDelayHintMs":
            routing_decision_ready_phase_diagnose
                .get("commandJsonTemplates")
                .and_then(Value::as_array)
                .and_then(|templates| templates.first())
                .and_then(|template| template.get("retryDelayHintMs"))
                .cloned()
                .unwrap_or(Value::Null),
        "phaseDiagnoseCommandJsonTemplateTimeoutHintMs":
            routing_decision_ready_phase_diagnose
                .get("commandJsonTemplates")
                .and_then(Value::as_array)
                .and_then(|templates| templates.first())
                .and_then(|template| template.get("timeoutHintMs"))
                .cloned()
                .unwrap_or(Value::Null),
        "phaseDiagnoseCommandJsonTemplateTimeoutAction": routing_decision_ready_phase_diagnose
            .get("commandJsonTemplates")
            .and_then(Value::as_array)
            .and_then(|templates| templates.first())
            .and_then(|template| template.get("timeoutAction"))
            .cloned()
            .unwrap_or(Value::Null),
        "phaseDiagnoseCommandJsonTemplateCommandJsonEligible":
            routing_decision_ready_phase_diagnose
                .get("commandJsonTemplates")
                .and_then(Value::as_array)
                .and_then(|templates| templates.first())
                .and_then(|template| template.get("commandJsonEligible"))
                .cloned()
                .unwrap_or(Value::Null),
        "defaultPhase": routing_decision_ready_default_phase,
    });
    let routing_decision = json!({
        "lookupKey": "errorCode",
        "policy": "first-candidate-by-escalation-order",
        "entryCount": error_code_routing_entries.len(),
        "entries": error_code_routing_entries.clone(),
        "index": routing_decision_index,
        "defaultRecommendedEscalationKey": default_recommended_escalation_key,
        "defaultRecommendedPhase": routing_decision_default
            .get("recommendedPhase")
            .cloned()
            .unwrap_or(Value::Null),
        "defaultEffectiveEscalationKey": routing_decision_default
            .get("effectiveEscalationKey")
            .cloned()
            .unwrap_or(Value::Null),
        "defaultEffectivePhase": routing_decision_default
            .get("effectivePhase")
            .cloned()
            .unwrap_or(Value::Null),
        "defaultRecommendedTemplateCount": routing_decision_default
            .get("recommendedTemplateCount")
            .cloned()
            .unwrap_or(Value::Null),
        "defaultRecommendedTemplates": routing_decision_default
            .get("recommendedTemplates")
            .cloned()
            .unwrap_or(json!([])),
        "defaultRecommendedCommandJsonTemplateCount": routing_decision_default
            .get("recommendedCommandJsonTemplateCount")
            .cloned()
            .unwrap_or(Value::Null),
        "defaultRecommendedCommandJsonTemplates": routing_decision_default
            .get("recommendedCommandJsonTemplates")
            .cloned()
            .unwrap_or(json!([])),
        "default": routing_decision_default,
        "ready": routing_decision_ready,
    });
    let fallback_plan = if next_action_ready_to_run {
        Value::Null
    } else {
        let fallback_next_chain_step = next_step_chain.first();
        let fallback_next_plan_step = fallback_steps.first();
        json!({
            "trigger": "next-action-not-ready",
            "reason": fallback_reason,
            "fromActionKey": next_action_key,
            "toActionKey": fallback_action_key,
            "usesSuggestedSequence": fallback_action_key.is_none(),
            "templateCount": fallback_templates.len(),
            "templates": fallback_templates,
            "phaseCount": fallback_phase_order.len(),
            "phaseOrder": fallback_phase_order,
            "phaseRetryPolicyCount": fallback_phase_retry_policies.len(),
            "phaseRetryPolicies": fallback_phase_retry_policies,
            "phaseTimeoutPolicyCount": fallback_phase_retry_policies.len(),
            "phaseTimeoutPolicies": fallback_phase_retry_policies
                .iter()
                .map(|policy| {
                    json!({
                        "phase": policy.get("phase").cloned().unwrap_or(Value::Null),
                        "timeoutHintMs": policy.get("timeoutHintMs").cloned().unwrap_or(Value::Null),
                        "timeoutAction": policy.get("timeoutAction").cloned().unwrap_or(Value::Null),
                        "errorCode": policy.get("errorCode").cloned().unwrap_or(Value::Null),
                        "timeoutErrorCode": policy.get("timeoutErrorCode").cloned().unwrap_or(Value::Null),
                    })
                })
                .collect::<Vec<_>>(),
            "phaseErrorCodeCount": fallback_phase_error_codes.len(),
            "phaseErrorCodes": fallback_phase_error_codes,
            "terminationPolicy": fallback_termination_policy,
            "stepCount": fallback_steps.len(),
            "retryableStepCount": fallback_retryable_step_count,
            "totalRetryBudget": fallback_total_retry_budget,
            "steps": fallback_steps,
            "escalationRecommendationCount": escalation_recommendations.len(),
            "escalationRecommendations": escalation_recommendations.clone(),
            "suggestedEscalationKey": escalation_recommendations
                .first()
                .and_then(|item| item.get("key"))
                .and_then(Value::as_str)
                .map(ToOwned::to_owned),
            "errorCodeRoutingCount": error_code_routing_entries.len(),
            "errorCodeRouting": error_code_routing,
            "errorCodeRoutingResolvedCount": error_code_routing_resolved.len(),
            "errorCodeRoutingResolved": error_code_routing_resolved,
            "errorCodeRoutingEntries": error_code_routing_entries,
            "routingDecision": routing_decision,
            "commandJsonTemplateCount": fallback_command_json_templates.len(),
            "commandJsonTemplates": fallback_command_json_templates,
            "commandJsonEligibleTemplateCount": fallback_eligible_command_json_template_count,
            "nextStepId": fallback_next_chain_step
                .and_then(|entry| entry.get("id"))
                .cloned()
                .unwrap_or(Value::Null),
            "nextStepSource": fallback_next_chain_step
                .and_then(|entry| entry.get("source"))
                .cloned()
                .unwrap_or(Value::Null),
            "nextStepActionKey": fallback_next_chain_step
                .and_then(|entry| entry.get("actionKey"))
                .cloned()
                .unwrap_or(Value::Null),
            "nextStepCommandGroup": fallback_next_chain_step
                .and_then(|entry| entry.get("commandGroup"))
                .cloned()
                .unwrap_or(Value::Null),
            "nextStepAllowed": fallback_next_chain_step
                .and_then(|entry| entry.get("allowed"))
                .cloned()
                .unwrap_or(Value::Null),
            "nextStepBlockedBy": fallback_next_chain_step
                .and_then(|entry| entry.get("blockedBy"))
                .cloned()
                .unwrap_or(Value::Null),
            "nextStepBranch": fallback_next_chain_step
                .and_then(|entry| entry.get("branch"))
                .cloned()
                .unwrap_or(Value::Null),
            "nextStepCommand": fallback_next_plan_step
                .and_then(|entry| entry.get("command"))
                .cloned()
                .unwrap_or(Value::Null),
            "nextStepPhase": fallback_next_plan_step
                .and_then(|entry| entry.get("phase"))
                .cloned()
                .unwrap_or(Value::Null),
            "nextStepCommandJsonEligible": fallback_next_plan_step
                .and_then(|entry| entry.get("commandJsonEligible"))
                .cloned()
                .unwrap_or(Value::Null),
            "nextStepRetryable": fallback_next_plan_step
                .and_then(|entry| entry.get("retryable"))
                .cloned()
                .unwrap_or(Value::Null),
            "nextStepMaxSuggestedRetries": fallback_next_plan_step
                .and_then(|entry| entry.get("maxSuggestedRetries"))
                .cloned()
                .unwrap_or(Value::Null),
            "nextStepRetryDelayHintMs": fallback_next_plan_step
                .and_then(|entry| entry.get("retryDelayHintMs"))
                .cloned()
                .unwrap_or(Value::Null),
            "nextStepTimeoutHintMs": fallback_next_plan_step
                .and_then(|entry| entry.get("timeoutHintMs"))
                .cloned()
                .unwrap_or(Value::Null),
            "nextStepTimeoutAction": fallback_next_plan_step
                .and_then(|entry| entry.get("timeoutAction"))
                .cloned()
                .unwrap_or(Value::Null),
            "nextStepKind": fallback_next_plan_step
                .and_then(|entry| entry.get("kind"))
                .cloned()
                .unwrap_or(Value::Null),
            "nextStepErrorCode": fallback_next_plan_step
                .and_then(|entry| entry.get("errorCode"))
                .cloned()
                .unwrap_or(Value::Null),
            "nextStepTimeoutErrorCode": fallback_next_plan_step
                .and_then(|entry| entry.get("timeoutErrorCode"))
                .cloned()
                .unwrap_or(Value::Null),
            "nextStepRisk": fallback_next_plan_step
                .and_then(|entry| entry.get("risk"))
                .cloned()
                .unwrap_or(Value::Null),
            "nextStepPlaceholderCount": fallback_next_plan_step
                .and_then(|entry| entry.get("placeholderCount"))
                .cloned()
                .unwrap_or(Value::Null),
            "nextStepPlaceholders": fallback_next_plan_step
                .and_then(|entry| entry.get("placeholders"))
                .cloned()
                .unwrap_or(Value::Null),
            "nextStepCliArgs": fallback_next_plan_step
                .and_then(|entry| entry.get("cliArgs"))
                .cloned()
                .unwrap_or(Value::Null),
            "nextStepChainSource": next_step_chain_source,
            "nextStepChainLimit": next_step_chain_limit,
            "nextStepChainCount": next_step_chain.len(),
            "nextStepChain": next_step_chain.clone(),
            "nextStepChainTruncated": next_step_chain_truncated,
            "activeStep": fallback_next_chain_step.cloned().unwrap_or(Value::Null),
            "activeStepSource": fallback_next_chain_step
                .and_then(|entry| entry.get("source"))
                .cloned()
                .unwrap_or(Value::Null),
            "activeStepAllowed": fallback_next_chain_step
                .and_then(|entry| entry.get("allowed"))
                .cloned()
                .unwrap_or(Value::Null),
            "activeStepBlockedBy": fallback_next_chain_step
                .and_then(|entry| entry.get("blockedBy"))
                .cloned()
                .unwrap_or(Value::Null),
            "activeStepBranch": fallback_next_chain_step
                .and_then(|entry| entry.get("branch"))
                .cloned()
                .unwrap_or(Value::Null),
            "activeStepActionKey": fallback_next_chain_step
                .and_then(|entry| entry.get("actionKey"))
                .cloned()
                .unwrap_or(Value::Null),
            "activeStepCommandGroup": fallback_next_chain_step
                .and_then(|entry| entry.get("commandGroup"))
                .cloned()
                .unwrap_or(Value::Null),
            "activeStepId": fallback_next_chain_step
                .and_then(|entry| entry.get("id"))
                .cloned()
                .unwrap_or(Value::Null),
            "activeStepCommand": fallback_next_chain_step
                .and_then(|entry| entry.get("command"))
                .cloned()
                .unwrap_or(Value::Null),
            "activeStepPhase": fallback_next_chain_step
                .and_then(|entry| entry.get("phase"))
                .cloned()
                .unwrap_or(Value::Null),
            "activeStepReadyToRun": fallback_next_chain_step
                .and_then(|entry| entry.get("readyToRun"))
                .cloned()
                .unwrap_or(Value::Null),
            "activeStepRequiresFallback": fallback_next_chain_step
                .and_then(|entry| entry.get("requiresFallback"))
                .cloned()
                .unwrap_or(Value::Null),
            "activeStepKind": fallback_next_chain_step
                .and_then(|entry| entry.get("kind"))
                .cloned()
                .unwrap_or(Value::Null),
            "activeStepCommandJsonEligible": fallback_next_chain_step
                .and_then(|entry| entry.get("commandJsonEligible"))
                .cloned()
                .unwrap_or(Value::Null),
            "activeStepRetryable": fallback_next_chain_step
                .and_then(|entry| entry.get("retryable"))
                .cloned()
                .unwrap_or(Value::Null),
            "activeStepMaxSuggestedRetries": fallback_next_chain_step
                .and_then(|entry| entry.get("maxSuggestedRetries"))
                .cloned()
                .unwrap_or(Value::Null),
            "activeStepRetryDelayHintMs": fallback_next_chain_step
                .and_then(|entry| entry.get("retryDelayHintMs"))
                .cloned()
                .unwrap_or(Value::Null),
            "activeStepTimeoutHintMs": fallback_next_chain_step
                .and_then(|entry| entry.get("timeoutHintMs"))
                .cloned()
                .unwrap_or(Value::Null),
            "activeStepTimeoutAction": fallback_next_chain_step
                .and_then(|entry| entry.get("timeoutAction"))
                .cloned()
                .unwrap_or(Value::Null),
            "activeStepErrorCode": fallback_next_chain_step
                .and_then(|entry| entry.get("errorCode"))
                .cloned()
                .unwrap_or(Value::Null),
            "activeStepTimeoutErrorCode": fallback_next_chain_step
                .and_then(|entry| entry.get("timeoutErrorCode"))
                .cloned()
                .unwrap_or(Value::Null),
            "activeStepRisk": fallback_next_chain_step
                .and_then(|entry| entry.get("risk"))
                .cloned()
                .unwrap_or(Value::Null),
            "activeStepPlaceholderCount": fallback_next_chain_step
                .and_then(|entry| entry.get("placeholderCount"))
                .cloned()
                .unwrap_or(Value::Null),
            "activeStepPlaceholders": fallback_next_chain_step
                .and_then(|entry| entry.get("placeholders"))
                .cloned()
                .unwrap_or(Value::Null),
            "activeStepCliArgs": fallback_next_chain_step
                .and_then(|entry| entry.get("cliArgs"))
                .cloned()
                .unwrap_or(Value::Null),
        })
    };
    let next_action_plan = selected_action
        .map(|item| {
            json!({
                "actionKey": item.action_key,
                "commandGroup": item.command_group,
                "allowed": item.allowed,
                "blockedBy": item.blocked_by,
                "branch": hook_automation_branch(item),
                "priority": item.priority,
                "recommendation": item.recommendation,
                "prerequisiteCount": next_action_prerequisites.len(),
                "prerequisiteActionKeys": next_action_prerequisites.clone(),
                "blockedPrerequisiteCount": next_action_blocked_prerequisites.len(),
                "blockedPrerequisiteActionKeys": next_action_blocked_prerequisites.clone(),
                "readyToRun": next_action_ready_to_run,
                "templateCount": next_action_templates.len(),
                "templates": next_action_templates.clone(),
                "commandJsonTemplateCount": next_action_command_json_templates.len(),
                "commandJsonTemplates": next_action_command_json_templates.clone(),
            })
        })
        .unwrap_or(Value::Null);

    let action_branches = actions
        .iter()
        .map(|item| {
            let templates = hook_action_command_templates(item.action_key, preferred_path);
            let command_json_templates = templates
                .iter()
                .map(|template| command_json_template_entry(template))
                .collect::<Vec<_>>();
            let command_json_eligible_template_count = command_json_eligible_count(&command_json_templates);
            let selected_as_next = next_action_key
                .as_ref()
                .map(|action_key| action_key == item.action_key)
                .unwrap_or(false);
            let prerequisites = hook_action_prerequisites(item.action_key)
                .iter()
                .map(|action_key| (*action_key).to_string())
                .collect::<Vec<_>>();
            let blocked_prerequisites = prerequisites
                .iter()
                .filter(|action_key| !is_action_allowed(action_key))
                .cloned()
                .collect::<Vec<_>>();
            let ready_to_run = item.allowed && blocked_prerequisites.is_empty();
            let execution_rank = mode_rank(item.action_key);
            let execution_index = ordered_actions
                .iter()
                .position(|candidate| candidate.action_key == item.action_key)
                .unwrap_or(usize::MAX);

            json!({
                "actionKey": item.action_key,
                "commandGroup": item.command_group,
                "allowed": item.allowed,
                "branch": hook_automation_branch(item),
                "blockedBy": item.blocked_by,
                "executionRank": execution_rank,
                "executionIndex": execution_index,
                "priority": item.priority,
                "recommendation": item.recommendation,
                "selectedAsNext": selected_as_next,
                "prerequisiteCount": prerequisites.len(),
                "prerequisiteActionKeys": prerequisites,
                "blockedPrerequisiteCount": blocked_prerequisites.len(),
                "blockedPrerequisiteActionKeys": blocked_prerequisites,
                "readyToRun": ready_to_run,
                "templateCount": templates.len(),
                "templates": templates,
                "commandJsonTemplateCount": command_json_templates.len(),
                "commandJsonTemplates": command_json_templates,
                "commandJsonEligibleTemplateCount": command_json_eligible_template_count,
            })
        })
        .collect::<Vec<_>>();
    let ready_branch_count = action_branches
        .iter()
        .filter(|entry| entry.get("readyToRun").and_then(Value::as_bool).unwrap_or(false))
        .count();
    let blocked_branch_count = action_branches.len().saturating_sub(ready_branch_count);

    json!({
        "baseCommandMode": base_command_mode,
        "effectiveCommandMode": command_mode,
        "commandMode": command_mode,
        "autoDowngradedToQueryOnly": auto_downgraded_to_query_only,
        "autoDowngradeReason": auto_downgrade_reason,
        "preferredPath": preferred_path,
        "backendPressure": backend_pressure,
        "loadedExternalBackendCount": total_loaded_backend_count,
        "singleExternalBackendLoaded": single_external_backend_loaded,
        "multipleExternalBackendsLoaded": multiple_external_backends_loaded,
        "sharedBackendCount": shared_backend_count,
        "branchExecutionOrder": branch_execution_order,
        "readyBranchCount": ready_branch_count,
        "blockedBranchCount": blocked_branch_count,
        "nextActionKey": next_action_key,
        "nextReadyActionKey": next_ready_action_key,
        "nextRunnableActionKey": next_runnable_action_key,
        "nextBlockedActionKey": next_blocked_action_key,
        "nextActionReason": next_action_reason,
        "nextActionAllowed": selected_action.map(|item| item.allowed),
        "nextActionBlockedBy": selected_action.map(|item| item.blocked_by),
        "nextActionBranch": selected_action.map(hook_automation_branch),
        "nextActionReadyToRun": next_action_ready_to_run,
        "nextStepId": next_step_id,
        "nextStepActionKey": selected_action.map(|item| item.action_key),
        "nextStepCommandGroup": selected_action.map(|item| item.command_group),
        "nextStepAllowed": selected_action.map(|item| item.allowed),
        "nextStepBlockedBy": selected_action.map(|item| item.blocked_by),
        "nextStepBranch": selected_action.map(hook_automation_branch),
        "nextStepCommand": next_step_command,
        "nextStepPhase": next_step_phase,
        "nextStepCommandJsonEligible": selected_action.map(|_| next_step_command_json_eligible),
        "nextStepKind": next_step_command_json_template
            .as_ref()
            .and_then(|entry| entry.get("kind"))
            .cloned(),
        "nextStepRetryable": next_step_command_json_template
            .as_ref()
            .and_then(|entry| entry.get("retryable"))
            .cloned(),
        "nextStepMaxSuggestedRetries": next_step_command_json_template
            .as_ref()
            .and_then(|entry| entry.get("maxSuggestedRetries"))
            .cloned(),
        "nextStepRetryDelayHintMs": next_step_command_json_template
            .as_ref()
            .and_then(|entry| entry.get("retryDelayHintMs"))
            .cloned(),
        "nextStepTimeoutHintMs": next_step_command_json_template
            .as_ref()
            .and_then(|entry| entry.get("timeoutHintMs"))
            .cloned(),
        "nextStepTimeoutAction": next_step_command_json_template
            .as_ref()
            .and_then(|entry| entry.get("timeoutAction"))
            .cloned(),
        "nextStepErrorCode": next_step_command_json_template
            .as_ref()
            .and_then(|entry| entry.get("errorCode"))
            .cloned(),
        "nextStepTimeoutErrorCode": next_step_command_json_template
            .as_ref()
            .and_then(|entry| entry.get("timeoutErrorCode"))
            .cloned(),
        "nextStepRisk": next_step_command_json_template
            .as_ref()
            .and_then(|entry| entry.get("risk"))
            .cloned(),
        "nextStepPlaceholderCount": next_step_command_json_template
            .as_ref()
            .and_then(|entry| entry.get("placeholderCount"))
            .cloned(),
        "nextStepPlaceholders": next_step_command_json_template
            .as_ref()
            .and_then(|entry| entry.get("placeholders"))
            .cloned(),
        "nextStepCliArgs": next_step_command_json_template
            .as_ref()
            .and_then(|entry| entry.get("cliArgs"))
            .cloned(),
        "nextStepReadyToRun": selected_action.map(|_| next_action_ready_to_run),
        "nextStepRequiresFallback": selected_action.map(|_| !next_action_ready_to_run),
        "nextStep": next_step,
        "nextStepChainSource": next_step_chain_source,
        "nextStepChainLimit": next_step_chain_limit,
        "nextStepChainCount": next_step_chain.len(),
        "nextStepChain": next_step_chain,
        "nextStepChainTruncated": next_step_chain_truncated,
        "activeStep": active_step.cloned().unwrap_or(Value::Null),
        "activeStepSource": next_step_chain_source,
        "activeStepAllowed": active_step
            .and_then(|entry| entry.get("allowed"))
            .cloned()
            .unwrap_or(Value::Null),
        "activeStepBlockedBy": active_step
            .and_then(|entry| entry.get("blockedBy"))
            .cloned()
            .unwrap_or(Value::Null),
        "activeStepBranch": active_step
            .and_then(|entry| entry.get("branch"))
            .cloned()
            .unwrap_or(Value::Null),
        "activeStepActionKey": active_step
            .and_then(|entry| entry.get("actionKey"))
            .cloned()
            .unwrap_or(Value::Null),
        "activeStepCommandGroup": active_step
            .and_then(|entry| entry.get("commandGroup"))
            .cloned()
            .unwrap_or(Value::Null),
        "activeStepId": active_step
            .and_then(|entry| entry.get("id"))
            .cloned()
            .unwrap_or(Value::Null),
        "activeStepCommand": active_step
            .and_then(|entry| entry.get("command"))
            .cloned()
            .unwrap_or(Value::Null),
        "activeStepPhase": active_step
            .and_then(|entry| entry.get("phase"))
            .cloned()
            .unwrap_or(Value::Null),
        "activeStepReadyToRun": active_step
            .and_then(|entry| entry.get("readyToRun"))
            .cloned()
            .unwrap_or(Value::Null),
        "activeStepRequiresFallback": active_step
            .and_then(|entry| entry.get("requiresFallback"))
            .cloned()
            .unwrap_or(Value::Null),
        "activeStepKind": active_step
            .and_then(|entry| entry.get("kind"))
            .cloned()
            .unwrap_or(Value::Null),
        "activeStepCommandJsonEligible": active_step
            .and_then(|entry| entry.get("commandJsonEligible"))
            .cloned()
            .unwrap_or(Value::Null),
        "activeStepRetryable": active_step
            .and_then(|entry| entry.get("retryable"))
            .cloned()
            .unwrap_or(Value::Null),
        "activeStepMaxSuggestedRetries": active_step
            .and_then(|entry| entry.get("maxSuggestedRetries"))
            .cloned()
            .unwrap_or(Value::Null),
        "activeStepRetryDelayHintMs": active_step
            .and_then(|entry| entry.get("retryDelayHintMs"))
            .cloned()
            .unwrap_or(Value::Null),
        "activeStepTimeoutHintMs": active_step
            .and_then(|entry| entry.get("timeoutHintMs"))
            .cloned()
            .unwrap_or(Value::Null),
        "activeStepTimeoutAction": active_step
            .and_then(|entry| entry.get("timeoutAction"))
            .cloned()
            .unwrap_or(Value::Null),
        "activeStepErrorCode": active_step
            .and_then(|entry| entry.get("errorCode"))
            .cloned()
            .unwrap_or(Value::Null),
        "activeStepTimeoutErrorCode": active_step
            .and_then(|entry| entry.get("timeoutErrorCode"))
            .cloned()
            .unwrap_or(Value::Null),
        "activeStepRisk": active_step
            .and_then(|entry| entry.get("risk"))
            .cloned()
            .unwrap_or(Value::Null),
        "activeStepPlaceholderCount": active_step
            .and_then(|entry| entry.get("placeholderCount"))
            .cloned()
            .unwrap_or(Value::Null),
        "activeStepPlaceholders": active_step
            .and_then(|entry| entry.get("placeholders"))
            .cloned()
            .unwrap_or(Value::Null),
        "activeStepCliArgs": active_step
            .and_then(|entry| entry.get("cliArgs"))
            .cloned()
            .unwrap_or(Value::Null),
        "hasFallbackPlan": !next_action_ready_to_run,
        "fallbackPlan": fallback_plan,
        "nextActionPlan": next_action_plan,
        "hasSuggestedSequence": !suggested_sequence.is_empty(),
        "suggestedSequence": suggested_sequence,
        "commandTemplates": command_templates,
        "nextActionTemplateCount": next_action_templates.len(),
        "nextActionTemplates": next_action_templates,
        "nextActionCommandJsonTemplateCount": next_action_command_json_templates.len(),
        "nextActionCommandJsonTemplates": next_action_command_json_templates,
        "actionBranches": action_branches,
    })
}

#[cfg(unix)]
fn hook_shortcuts_to_json(
    injection_environment: &InjectionEnvironmentReport,
    preflight: &InjectionTargetPreflightReport,
) -> Value {
    let controller_actions = hook_environment_recommended_actions(
        &injection_environment.hook_environment,
        Some(&injection_environment.hook_strategy),
    );
    let target_actions =
        hook_environment_recommended_actions(&preflight.target_hook_environment, Some(&preflight.target_hook_strategy));
    let effective_actions = hook_effective_actions(&controller_actions, &target_actions);
    let backend_matrix =
        hook_backend_matrix_to_json(&injection_environment.hook_environment, &preflight.target_hook_environment);

    json!({
        "controller": hook_shortcut_entry_to_json(
            &injection_environment.hook_strategy,
            &controller_actions,
        ),
        "target": hook_shortcut_entry_to_json(
            &preflight.target_hook_strategy,
            &target_actions,
        ),
        "effectiveActions": hook_effective_actions_to_json(&effective_actions),
        "effective": hook_effective_to_json(&effective_actions),
        "backendMatrix": backend_matrix.clone(),
        "coexistence": hook_coexistence_to_json(&effective_actions, &backend_matrix),
        "automation": hook_automation_to_json(&effective_actions, &backend_matrix),
    })
}

#[cfg(unix)]
fn hook_recommended_action_to_json(action: &native_api::HookRecommendedAction) -> Value {
    json!({
        "commandGroup": action.command_group,
        "actionKey": action.action_key,
        "priority": action.priority,
        "allowed": action.allowed,
        "status": action.status,
        "recommendation": action.recommendation,
        "reason": action.reason,
    })
}

#[cfg(unix)]
fn hook_backend_matrix_entry_to_json(
    id: &str,
    display_name: &str,
    controller_backend: Option<&native_api::HookBackendInfo>,
    target_backend: Option<&native_api::HookBackendInfo>,
) -> Value {
    let controller_loaded = controller_backend.is_some_and(|backend| !backend.loaded_images.is_empty());
    let target_loaded = target_backend.is_some_and(|backend| !backend.loaded_images.is_empty());
    let controller_present_on_filesystem =
        controller_backend.is_some_and(|backend| !backend.filesystem_paths.is_empty());
    let target_present_on_filesystem = target_backend.is_some_and(|backend| !backend.filesystem_paths.is_empty());
    let visible_in_controller = controller_loaded || controller_present_on_filesystem;
    let visible_in_target = target_loaded || target_present_on_filesystem;
    let visibility = match (visible_in_controller, visible_in_target) {
        (true, true) => "both",
        (true, false) => "controller",
        (false, true) => "target",
        (false, false) => "none",
    };
    let loaded_by = match (controller_loaded, target_loaded) {
        (true, true) => "both",
        (true, false) => "controller",
        (false, true) => "target",
        (false, false) => "none",
    };

    json!({
        "id": id,
        "displayName": display_name,
        "visibility": visibility,
        "loadedBy": loaded_by,
        "visibleInController": visible_in_controller,
        "visibleInTarget": visible_in_target,
        "controllerLoaded": controller_loaded,
        "targetLoaded": target_loaded,
        "controllerPresentOnFilesystem": controller_present_on_filesystem,
        "targetPresentOnFilesystem": target_present_on_filesystem,
        "controllerLoadedImageCount": controller_backend.map_or(0, |backend| backend.loaded_images.len()),
        "targetLoadedImageCount": target_backend.map_or(0, |backend| backend.loaded_images.len()),
        "controllerFilesystemPathCount": controller_backend.map_or(0, |backend| backend.filesystem_paths.len()),
        "targetFilesystemPathCount": target_backend.map_or(0, |backend| backend.filesystem_paths.len()),
        "filesystemOnlyInEither": !controller_loaded
            && !target_loaded
            && (controller_present_on_filesystem || target_present_on_filesystem),
    })
}

#[cfg(unix)]
fn hook_backend_matrix_to_json(
    controller_report: &native_api::HookEnvironmentReport,
    target_report: &native_api::HookEnvironmentReport,
) -> Value {
    use std::collections::BTreeMap;

    let mut index = BTreeMap::new();
    for backend in &controller_report.backends {
        index
            .entry(backend.id.clone())
            .or_insert_with(|| backend.display_name.clone());
    }
    for backend in &target_report.backends {
        index
            .entry(backend.id.clone())
            .or_insert_with(|| backend.display_name.clone());
    }

    let mut entries = Vec::new();
    let mut shared_backend_ids = Vec::new();
    let mut controller_only_backend_ids = Vec::new();
    let mut target_only_backend_ids = Vec::new();
    let mut loaded_in_both_backend_ids = Vec::new();
    let mut filesystem_only_backend_ids = Vec::new();

    let mut loaded_in_controller_count = 0usize;
    let mut loaded_in_target_count = 0usize;
    let mut loaded_in_both_count = 0usize;
    let mut filesystem_only_in_either_count = 0usize;

    for (id, display_name) in index {
        let controller_backend = controller_report.backends.iter().find(|backend| backend.id == id);
        let target_backend = target_report.backends.iter().find(|backend| backend.id == id);
        let entry = hook_backend_matrix_entry_to_json(&id, &display_name, controller_backend, target_backend);

        let controller_loaded = entry["controllerLoaded"].as_bool().unwrap_or(false);
        let target_loaded = entry["targetLoaded"].as_bool().unwrap_or(false);
        let visible_in_controller = entry["visibleInController"].as_bool().unwrap_or(false);
        let visible_in_target = entry["visibleInTarget"].as_bool().unwrap_or(false);
        let filesystem_only = entry["filesystemOnlyInEither"].as_bool().unwrap_or(false);

        if controller_loaded {
            loaded_in_controller_count += 1;
        }
        if target_loaded {
            loaded_in_target_count += 1;
        }
        if controller_loaded && target_loaded {
            loaded_in_both_count += 1;
            loaded_in_both_backend_ids.push(id.clone());
        }
        if filesystem_only {
            filesystem_only_in_either_count += 1;
            filesystem_only_backend_ids.push(id.clone());
        }
        if visible_in_controller && visible_in_target {
            shared_backend_ids.push(id.clone());
        } else if visible_in_controller {
            controller_only_backend_ids.push(id.clone());
        } else if visible_in_target {
            target_only_backend_ids.push(id.clone());
        }

        entries.push(entry);
    }

    json!({
        "entryCount": entries.len(),
        "entries": entries,
        "loadedInControllerCount": loaded_in_controller_count,
        "loadedInTargetCount": loaded_in_target_count,
        "loadedInBothCount": loaded_in_both_count,
        "filesystemOnlyInEitherCount": filesystem_only_in_either_count,
        "sharedBackendIds": shared_backend_ids,
        "controllerOnlyBackendIds": controller_only_backend_ids,
        "targetOnlyBackendIds": target_only_backend_ids,
        "loadedInBothBackendIds": loaded_in_both_backend_ids,
        "filesystemOnlyBackendIds": filesystem_only_backend_ids,
    })
}

#[cfg(unix)]
fn hook_environment_to_json(
    report: &native_api::HookEnvironmentReport,
    strategy: Option<&native_api::HookStrategyDecision>,
) -> Value {
    let command_mode = strategy.map(|item| item.command_mode());
    let coexistence_mode = match command_mode {
        Some("allowed") => {
            if report.loaded_backend_count() > 0 {
                "inline-risky"
            } else if report.filesystem_only_backend_count() > 0 {
                "inline-cautious"
            } else {
                "inline-safe"
            }
        }
        Some("query-only") => "query-only",
        Some("cleanup-only") => "cleanup-only",
        Some("blocked") => "blocked",
        _ if report.loaded_backend_count() > 0 => "unknown-risky",
        _ if report.filesystem_only_backend_count() > 0 => "unknown-cautious",
        _ => "unknown",
    };
    let coexistence_recommendation = match coexistence_mode {
        "inline-safe" => "inline hooks are allowed and no external backend is loaded",
        "inline-cautious" => "filesystem-only backend artifacts were detected; preflight before hook-install",
        "inline-risky" => "external backend already loaded; prefer query/status first, then inline install only if necessary",
        "query-only" => "current policy blocks hook-install; stay on query commands",
        "cleanup-only" => "only status/stop commands are allowed under current policy",
        "blocked" => "no hook command group is currently allowed",
        "unknown-risky" => "external backend is loaded but strategy is unavailable; run preflight before hook-install",
        "unknown-cautious" => "backend filesystem artifacts are present; verify hook policy and run preflight",
        _ => "hook strategy is unavailable; run native.hookenv and preflight for guidance",
    };
    let coexistence_layer = hook_coexistence_layer_status(report, strategy);
    let loaded_backend_count = report.loaded_backend_count();
    let filesystem_only_backend_count = report.filesystem_only_backend_count();
    let risk_level = if let Some(strategy) = strategy {
        match strategy.command_mode() {
            "blocked" => "blocked",
            "cleanup-only" => "cleanup-only",
            "query-only" => "query-only",
            _ if loaded_backend_count > 0 => "risky",
            _ if filesystem_only_backend_count > 0 => "cautious",
            _ => "normal",
        }
    } else if loaded_backend_count > 0 {
        "risky"
    } else if filesystem_only_backend_count > 0 {
        "cautious"
    } else {
        "normal"
    };

    json!({
        "activeBackend": report.active_backend,
        "conflictState": report.conflict_state(),
        "riskLevel": risk_level,
        "commandMode": command_mode,
        "coexistenceMode": coexistence_mode,
        "coexistenceRecommendation": coexistence_recommendation,
        "coexistenceLayerAvailable": coexistence_layer.available,
        "coexistenceLayerStatus": coexistence_layer.status,
        "externalBackendLoaded": loaded_backend_count > 0,
        "singleExternalBackendLoaded": loaded_backend_count == 1,
        "multipleExternalBackendsLoaded": loaded_backend_count > 1,
        "filesystemOnlyBackendDetected": filesystem_only_backend_count > 0,
        "loadedBackendCount": loaded_backend_count,
        "filesystemOnlyBackendCount": filesystem_only_backend_count,
        "loadedImageCount": report.loaded_image_count(),
        "filesystemPathCount": report.filesystem_path_count(),
        "recommendedActions": hook_environment_recommended_actions(report, strategy)
            .iter()
            .map(hook_recommended_action_to_json)
            .collect::<Vec<_>>(),
        "backends": report.backends.iter().map(hook_backend_to_json).collect::<Vec<_>>(),
        "warnings": report.warnings,
    })
}

#[cfg(unix)]
fn injection_environment_to_json(report: &InjectionEnvironmentReport) -> Value {
    json!({
        "dryRun": report.dry_run,
        "bootstrapWaitMs": report.bootstrap_wait_ms,
        "hookPolicy": report.hook_policy.as_str(),
        "hookStrategy": hook_strategy_to_json(&report.hook_strategy),
        "hookEnvironment": hook_environment_to_json(&report.hook_environment, Some(&report.hook_strategy)),
        "recommendations": hook_environment_recommendations(&report.hook_environment, Some(&report.hook_strategy)),
    })
}

#[cfg(unix)]
fn loader_symbol_to_json(symbol: &ResolvedLoaderSymbol) -> Value {
    let thread_bootstrap_kind = symbol.thread_bootstrap_kind().map(|kind| kind.as_str());
    json!({
        "role": symbol.role.as_str(),
        "symbolName": symbol.symbol_name,
        "moduleName": symbol.module_name,
        "moduleBase": symbol.module_base,
        "moduleBaseHex": json_hex_usize(symbol.module_base),
        "rawAddress": symbol.raw_address,
        "rawAddressHex": json_hex_usize(symbol.raw_address),
        "address": symbol.address,
        "addressHex": json_hex_usize(symbol.address),
        "offset": symbol.offset,
        "offsetHex": json_hex_usize(symbol.offset),
        "canonicalized": symbol.is_canonicalized(),
        "threadBootstrapKind": thread_bootstrap_kind,
    })
}

#[cfg(unix)]
fn loader_symbol_checks_to_json(symbols: &[ResolvedLoaderSymbol], images: &[native_api::ImageInfo]) -> Value {
    let checks = symbols
        .iter()
        .map(|symbol| {
            let matched_image = images
                .iter()
                .find(|image| image_name_matches(&symbol.module_name, &image.name));
            let image_found = matched_image.is_some();
            let image_base_matches = matched_image
                .map(|image| image.base == symbol.module_base)
                .unwrap_or(false);
            let expected_address = matched_image.and_then(|image| image.base.checked_add(symbol.offset));
            let address_matches = expected_address
                .map(|expected| expected == symbol.address)
                .unwrap_or(false);

            json!({
                "role": symbol.role.as_str(),
                "symbolName": symbol.symbol_name,
                "moduleName": symbol.module_name,
                "imageFound": image_found,
                "imagePath": matched_image.map(|image| image.name.clone()),
                "imageBase": matched_image.map(|image| image.base),
                "imageBaseHex": matched_image.map(|image| json_hex_usize(image.base)),
                "moduleBaseMatchesImage": image_base_matches,
                "offset": symbol.offset,
                "offsetHex": json_hex_usize(symbol.offset),
                "address": symbol.address,
                "addressHex": json_hex_usize(symbol.address),
                "expectedAddress": expected_address,
                "expectedAddressHex": expected_address.map(json_hex_usize),
                "addressMatchesExpected": address_matches,
                "canonicalized": symbol.is_canonicalized(),
            })
        })
        .collect::<Vec<_>>();

    let image_found_count = checks
        .iter()
        .filter(|check| check["imageFound"].as_bool().unwrap_or(false))
        .count();
    let address_match_count = checks
        .iter()
        .filter(|check| check["addressMatchesExpected"].as_bool().unwrap_or(false))
        .count();

    json!({
        "total": checks.len(),
        "imageFoundCount": image_found_count,
        "addressMatchCount": address_match_count,
        "allImagesFound": image_found_count == checks.len(),
        "allAddressesMatch": address_match_count == checks.len(),
        "checks": checks,
    })
}

#[cfg(unix)]
fn injection_plan_to_json(plan: &InjectionPlan) -> Value {
    json!({
        "target": {
            "pid": plan.target.pid,
            "dylibPath": plan.target.dylib_path,
            "entrySymbol": plan.target.entry_symbol,
            "socketPath": plan.target.socket_path,
        },
        "bootstrap": {
            "totalSize": plan.bootstrap().len(),
            "codeSize": plan.bootstrap().code_size(),
            "dataSize": plan.bootstrap().data_size(),
            "routineOffset": plan.bootstrap().routine_offset(),
            "routineOffsetHex": format!("0x{:x}", plan.bootstrap().routine_offset()),
            "argsOffset": plan.bootstrap().args_offset(),
            "argsOffsetHex": format!("0x{:x}", plan.bootstrap().args_offset()),
            "stackSize": plan.bootstrap().stack_size(),
            "stackSizeHex": json_hex_u64(plan.bootstrap().stack_size()),
            "stackAlignment": plan.bootstrap().stack_alignment(),
            "stackAlignmentHex": json_hex_u64(plan.bootstrap().stack_alignment()),
        },
        "loaderSymbols": plan.loader_symbols().iter().map(loader_symbol_to_json).collect::<Vec<_>>(),
        "steps": plan.steps().iter().map(|step| {
            json!({
                "stage": step.stage.as_str(),
                "detail": step.detail,
            })
        }).collect::<Vec<_>>(),
    })
}

#[cfg(unix)]
fn injection_preflight_to_json(report: &InjectionTargetPreflightReport) -> Value {
    json!({
        "mainImage": report.main_image.as_ref().map(image_info_to_json),
        "targetImages": report.target_images.iter().map(image_info_to_json).collect::<Vec<_>>(),
        "targetImageCount": report.target_image_count,
        "loaderSymbolChecks": loader_symbol_checks_to_json(&report.resolved_loader_symbols, &report.target_images),
        "targetUsesArm64e": report.target_uses_arm64e,
        "threadBootstrapKind": report.thread_bootstrap_kind.as_str(),
        "threadBootstrapLabel": report.thread_bootstrap_label,
        "threadBootstrapAddress": report.thread_bootstrap_address,
        "threadBootstrapAddressHex": json_hex_usize(report.thread_bootstrap_address),
        "threadBootstrapRawAddress": report.thread_bootstrap_raw_address,
        "threadBootstrapRawAddressHex": json_hex_usize(report.thread_bootstrap_raw_address),
        "threadBootstrapCanonicalized": report.thread_bootstrap_canonicalized,
        "targetHookEnvironment": hook_environment_to_json(
            &report.target_hook_environment,
            Some(&report.target_hook_strategy),
        ),
        "targetHookStrategy": hook_strategy_to_json(&report.target_hook_strategy),
        "targetRecommendations": hook_environment_recommendations(
            &report.target_hook_environment,
            Some(&report.target_hook_strategy),
        ),
        "resolvedLoaderSymbols": report
            .resolved_loader_symbols
            .iter()
            .map(loader_symbol_to_json)
            .collect::<Vec<_>>(),
    })
}

#[cfg(unix)]
fn doctor_check_to_json(check: &DoctorCheck) -> Value {
    json!({
        "id": check.id,
        "status": check.status,
        "fatal": check.fatal,
        "summary": check.summary,
        "detail": check.detail,
    })
}

#[cfg(unix)]
fn doctor_report_to_json(report: &DoctorReport) -> Value {
    json!({
        "ready": report.ready,
        "warningCount": report.warning_count,
        "failureCount": report.failure_count,
        "checks": report.checks.iter().map(doctor_check_to_json).collect::<Vec<_>>(),
    })
}

#[cfg(unix)]
fn make_doctor_check(
    id: &'static str,
    status: &'static str,
    summary: impl Into<String>,
    detail: Option<String>,
) -> DoctorCheck {
    DoctorCheck {
        id,
        status,
        fatal: status == "fail",
        summary: summary.into(),
        detail,
    }
}

#[cfg(unix)]
fn summarize_agent_path(path: &str) -> (String, Option<String>) {
    let filename = Path::new(path)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("<unknown>");
    if path == DEFAULT_AGENT_PATH {
        (
            format!("agent path uses the rootless default {}", DEFAULT_AGENT_PATH),
            Some("recommended for modern rootless jailbreaks using the /var/jb prefix".into()),
        )
    } else if path == DEFAULT_AGENT_PATH_ROOTFUL {
        (
            format!("agent path uses the rootful default {}", DEFAULT_AGENT_PATH_ROOTFUL),
            Some("use this when the jailbreak exposes the traditional /usr/lib namespace".into()),
        )
    } else if path.starts_with("/var/jb/") {
        (
            format!("agent path uses a custom rootless location {}", path),
            Some(format!("filename={filename}")),
        )
    } else if path.starts_with("/usr/lib/") {
        (
            format!("agent path uses a custom rootful location {}", path),
            Some(format!("filename={filename}")),
        )
    } else {
        (
            format!("agent path uses a custom non-standard location {}", path),
            Some(format!(
                "verify the target process can resolve this path and that the dylib remains named {filename}"
            )),
        )
    }
}

#[cfg(unix)]
fn analyze_doctor_report(
    config: &ControllerConfig,
    pid: i32,
    socket_path: &Path,
    injection_environment: &InjectionEnvironmentReport,
    preflight: &InjectionTargetPreflightReport,
) -> DoctorReport {
    let mut checks = Vec::new();

    let (agent_path_summary, agent_path_detail) = summarize_agent_path(&config.agent_path);
    checks.push(make_doctor_check(
        "agent-path",
        "pass",
        agent_path_summary,
        agent_path_detail,
    ));

    let uses_legacy_agent_filename = Path::new(&config.agent_path)
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name == "agent.dylib");
    checks.push(if uses_legacy_agent_filename {
        make_doctor_check(
            "agent-filename",
            "warn",
            "agent path still uses the legacy filename agent.dylib",
            Some(format!(
                "rename or deploy it as libagent.dylib; recommended defaults are {} (rootless) or {} (rootful)",
                DEFAULT_AGENT_PATH, DEFAULT_AGENT_PATH_ROOTFUL
            )),
        )
    } else {
        make_doctor_check(
            "agent-filename",
            "pass",
            "agent filename is using the current libagent.dylib convention",
            None,
        )
    });

    let socket_path_text = socket_path.to_string_lossy().into_owned();
    let socket_status = match validate_socket_path(socket_path) {
        Ok(()) if socket_path_text.len() > 90 => make_doctor_check(
            "socket-path",
            "warn",
            format!(
                "socket path is valid but close to the Darwin limit ({} / {})",
                socket_path_text.len(),
                DARWIN_SOCKADDR_UN_PATH_MAX
            ),
            Some(socket_path_text.clone()),
        ),
        Ok(()) => make_doctor_check(
            "socket-path",
            "pass",
            format!(
                "socket path is valid for Darwin sockaddr_un ({} / {})",
                socket_path_text.len(),
                DARWIN_SOCKADDR_UN_PATH_MAX
            ),
            Some(socket_path_text.clone()),
        ),
        Err(err) => make_doctor_check("socket-path", "fail", "socket path is invalid", Some(err.to_string())),
    };
    checks.push(socket_status);

    checks.push(match &config.script_path {
        Some(script_path) => match fs::File::open(script_path) {
            Ok(_) => make_doctor_check(
                "script-path",
                "pass",
                format!("bootstrap script is readable: {}", script_path),
                None,
            ),
            Err(err) => make_doctor_check(
                "script-path",
                "fail",
                format!("bootstrap script cannot be opened: {}", script_path),
                Some(err.to_string()),
            ),
        },
        None => make_doctor_check("script-path", "pass", "no bootstrap script requested", None),
    });

    checks.push(if injection_environment.hook_strategy.bootstrap_injection_allowed() {
        let status = if injection_environment.hook_environment.backends.is_empty()
            && injection_environment.hook_environment.warnings.is_empty()
            && injection_environment.hook_strategy.hook_install_commands_allowed()
        {
            "pass"
        } else {
            "warn"
        };
        make_doctor_check(
            "controller-hook-strategy",
            status,
            format!(
                "controller hook strategy is {} ({}) query={} install={} status={} stop={}",
                injection_environment.hook_strategy.command_mode(),
                injection_environment.hook_strategy.strategy,
                injection_environment.hook_strategy.query_commands_allowed(),
                injection_environment.hook_strategy.hook_install_commands_allowed(),
                injection_environment.hook_strategy.hook_status_commands_allowed(),
                injection_environment.hook_strategy.hook_stop_commands_allowed()
            ),
            injection_environment.hook_strategy.reason.clone(),
        )
    } else {
        make_doctor_check(
            "controller-hook-strategy",
            "fail",
            format!(
                "controller hook strategy is blocked ({}) query={} install={} status={} stop={}",
                injection_environment.hook_strategy.strategy,
                injection_environment.hook_strategy.query_commands_allowed(),
                injection_environment.hook_strategy.hook_install_commands_allowed(),
                injection_environment.hook_strategy.hook_status_commands_allowed(),
                injection_environment.hook_strategy.hook_stop_commands_allowed()
            ),
            injection_environment.hook_strategy.reason.clone(),
        )
    });

    checks.push(if preflight.target_hook_strategy.bootstrap_injection_allowed() {
        let status = if preflight.target_hook_environment.backends.is_empty()
            && preflight.target_hook_environment.warnings.is_empty()
            && preflight.target_hook_strategy.hook_install_commands_allowed()
        {
            "pass"
        } else {
            "warn"
        };
        make_doctor_check(
            "target-hook-strategy",
            status,
            format!(
                "target hook strategy for pid {} is {} ({}) query={} install={} status={} stop={}",
                pid,
                preflight.target_hook_strategy.command_mode(),
                preflight.target_hook_strategy.strategy,
                preflight.target_hook_strategy.query_commands_allowed(),
                preflight.target_hook_strategy.hook_install_commands_allowed(),
                preflight.target_hook_strategy.hook_status_commands_allowed(),
                preflight.target_hook_strategy.hook_stop_commands_allowed()
            ),
            preflight.target_hook_strategy.reason.clone(),
        )
    } else {
        make_doctor_check(
            "target-hook-strategy",
            "fail",
            format!(
                "target hook strategy for pid {} is blocked ({}) query={} install={} status={} stop={}",
                pid,
                preflight.target_hook_strategy.strategy,
                preflight.target_hook_strategy.query_commands_allowed(),
                preflight.target_hook_strategy.hook_install_commands_allowed(),
                preflight.target_hook_strategy.hook_status_commands_allowed(),
                preflight.target_hook_strategy.hook_stop_commands_allowed()
            ),
            preflight.target_hook_strategy.reason.clone(),
        )
    });

    let loader_symbol_checks =
        loader_symbol_checks_to_json(&preflight.resolved_loader_symbols, &preflight.target_images);
    let loader_total = loader_symbol_checks["total"].as_u64().unwrap_or(0);
    let all_images_found = loader_symbol_checks["allImagesFound"].as_bool().unwrap_or(false);
    let all_addresses_match = loader_symbol_checks["allAddressesMatch"].as_bool().unwrap_or(false);
    checks.push(if loader_total == 0 {
        make_doctor_check(
            "loader-symbols",
            "fail",
            "no loader symbols were resolved for preflight",
            Some("injection cannot continue without dlopen/dlsym/socket/connect/thread bootstrap symbols".into()),
        )
    } else if all_images_found && all_addresses_match {
        make_doctor_check(
            "loader-symbols",
            "pass",
            format!("all {loader_total} rebased loader symbols match the target image list"),
            None,
        )
    } else {
        make_doctor_check(
            "loader-symbols",
            "fail",
            format!(
                "loader symbol rebasing is inconsistent (images_found={} addresses_match={} total={loader_total})",
                loader_symbol_checks["imageFoundCount"].as_u64().unwrap_or(0),
                loader_symbol_checks["addressMatchCount"].as_u64().unwrap_or(0),
            ),
            Some("check preflight.loaderSymbolChecks for per-symbol mismatches before attempting injection".into()),
        )
    });

    checks.push(match preflight.target_uses_arm64e {
        Some(true) if matches!(
            preflight.thread_bootstrap_kind,
            native_api::ThreadBootstrapKind::PthreadCreateFromMachThread
        ) => make_doctor_check(
            "thread-bootstrap",
            "pass",
            "arm64e target resolved the preferred pthread_create_from_mach_thread bootstrap",
            Some(preflight.thread_bootstrap_label.clone()),
        ),
        Some(true) => make_doctor_check(
            "thread-bootstrap",
            "fail",
            format!(
                "arm64e target would use fallback bootstrap {}",
                preflight.thread_bootstrap_kind.as_str()
            ),
            Some(
                "arm64e targets should use pthread_create_from_mach_thread; fallback pthread_create is rejected unless explicitly overridden".into(),
            ),
        ),
        Some(false) => make_doctor_check(
            "thread-bootstrap",
            "pass",
            format!(
                "non-arm64e target resolved thread bootstrap {}",
                preflight.thread_bootstrap_kind.as_str()
            ),
            Some(preflight.thread_bootstrap_label.clone()),
        ),
        None => make_doctor_check(
            "thread-bootstrap",
            "warn",
            format!(
                "target arm64e status is unknown; bootstrap kind is {}",
                preflight.thread_bootstrap_kind.as_str()
            ),
            Some(preflight.thread_bootstrap_label.clone()),
        ),
    });

    let warning_count = checks.iter().filter(|check| check.status == "warn").count();
    let failure_count = checks.iter().filter(|check| check.status == "fail").count();

    DoctorReport {
        ready: failure_count == 0,
        warning_count,
        failure_count,
        checks,
    }
}

#[cfg(unix)]
fn render_preflight_json(
    config: &ControllerConfig,
    pid: i32,
    socket_path: &str,
    plan: &InjectionPlan,
    injection_environment: &InjectionEnvironmentReport,
    preflight: &InjectionTargetPreflightReport,
    doctor: &DoctorReport,
) -> Value {
    json!({
        "mode": injection_mode_label(config.mode),
        "pid": pid,
        "preflightOnly": true,
        "socketPath": socket_path,
        "agentPath": config.agent_path,
        "entrySymbol": config.entry_symbol,
        "scriptPath": config.script_path,
        "hook": hook_shortcuts_to_json(injection_environment, preflight),
        "environment": injection_environment_to_json(injection_environment),
        "doctor": doctor_report_to_json(doctor),
        "plan": injection_plan_to_json(plan),
        "preflight": injection_preflight_to_json(preflight),
    })
}

#[cfg(unix)]
fn render_image_list_json(images: &[native_api::ImageInfo]) -> Value {
    json!({
        "imageCount": images.len(),
        "images": images.iter().map(image_info_to_json).collect::<Vec<_>>(),
    })
}

#[cfg(unix)]
fn hello_to_json(hello: &Hello) -> Value {
    json!({
        "platform": hello.platform,
        "arch": hello.arch,
        "runtime": hello.runtime,
        "transport": hello.transport,
    })
}

#[cfg(unix)]
fn bootstrap_report_to_json(report: &native_api::BootstrapResultReport) -> Value {
    json!({
        "status": report.status.as_str(),
        "statusRaw": report.status_raw,
        "isFailure": report.status.is_failure(),
        "diagnosticHint": report.status.diagnostic_hint(),
        "dylibHandle": report.dylib_handle,
        "dylibHandleHex": json_hex_u64(report.dylib_handle),
        "entryAddress": report.entry_address,
        "entryAddressHex": json_hex_u64(report.entry_address),
        "socketFd": report.socket_fd,
        "entryReturn": report.entry_return,
    })
}

#[cfg(unix)]
fn handshake_stage_label(
    script_requested: bool,
    hello: Option<&Hello>,
    ping: Option<&str>,
    hook_environment_checked: bool,
    jsinit_result: Option<&str>,
    loadjs_result: Option<&str>,
) -> &'static str {
    if hello.is_none() {
        return "awaiting-hello";
    }
    if ping.is_none() {
        return "awaiting-ping";
    }
    if !hook_environment_checked {
        return "awaiting-hook-environment";
    }
    if script_requested && jsinit_result.is_none() {
        return "awaiting-jsinit";
    }
    if script_requested && loadjs_result.is_none() {
        return "awaiting-loadjs";
    }
    "completed"
}

#[cfg(unix)]
fn stage_error(stage: &str, err: Error) -> Error {
    Error::State(format!("{stage} failed: {err}"))
}

#[cfg(unix)]
fn handshake_stage_index(stage: &str) -> usize {
    match stage {
        "awaiting-hello" => 0,
        "awaiting-ping" => 1,
        "awaiting-hook-environment" => 2,
        "awaiting-jsinit" => 3,
        "awaiting-loadjs" => 4,
        "completed" => 5,
        _ => usize::MAX,
    }
}

#[cfg(unix)]
fn handshake_step_status(completed: bool, configured: bool, current_stage: &str, pending_stage: &str) -> &'static str {
    if !configured {
        return "skipped";
    }
    if completed {
        return "succeeded";
    }
    if handshake_stage_index(current_stage) <= handshake_stage_index(pending_stage) {
        return "pending";
    }
    "failed"
}

#[cfg(unix)]
fn render_handshake_steps_json(
    script_requested: bool,
    hello: Option<&Hello>,
    ping: Option<&str>,
    hook_environment_checked: bool,
    jsinit_result: Option<&str>,
    loadjs_result: Option<&str>,
) -> Value {
    let current_stage = handshake_stage_label(
        script_requested,
        hello,
        ping,
        hook_environment_checked,
        jsinit_result,
        loadjs_result,
    );

    json!({
        "hello": handshake_step_status(hello.is_some(), true, current_stage, "awaiting-hello"),
        "ping": handshake_step_status(ping.is_some(), true, current_stage, "awaiting-ping"),
        "hookEnvironment": handshake_step_status(
            hook_environment_checked,
            true,
            current_stage,
            "awaiting-hook-environment"
        ),
        "jsInit": handshake_step_status(
            jsinit_result.is_some(),
            script_requested,
            current_stage,
            "awaiting-jsinit"
        ),
        "loadJs": handshake_step_status(
            loadjs_result.is_some(),
            script_requested,
            current_stage,
            "awaiting-loadjs"
        ),
    })
}

#[cfg(unix)]
fn parse_error_field(message: &str, key: &str) -> Option<String> {
    let marker = format!("{key}=");
    message
        .split(&marker)
        .nth(1)
        .and_then(|tail| {
            tail.split(|ch: char| ch.is_whitespace() || ch == ';' || ch == ',')
                .next()
        })
        .map(str::trim)
        .map(ToOwned::to_owned)
        .filter(|value| !value.is_empty())
}

#[cfg(unix)]
fn parse_error_field_with_boundaries(message: &str, key: &str, next_keys: &[&str]) -> Option<String> {
    let marker = format!("{key}=");
    let start = message.find(&marker)? + marker.len();
    let tail = &message[start..];
    let mut end = tail.len();

    for next_key in next_keys {
        let next_marker = format!(" {next_key}=");
        if let Some(index) = tail.find(&next_marker) {
            end = end.min(index);
        }
    }
    if let Some(index) = tail.find(';') {
        end = end.min(index);
    }
    if let Some(index) = tail.find(',') {
        end = end.min(index);
    }

    let value = tail[..end].trim();
    if value.is_empty() {
        None
    } else {
        Some(value.to_string())
    }
}

#[cfg(unix)]
fn parse_error_status_field(message: &str) -> Option<String> {
    parse_error_field(message, "status")
}

#[cfg(unix)]
fn parse_message_suffix_after_prefix(message: &str, prefix: &str) -> Option<String> {
    let (_, suffix) = message.split_once(prefix)?;
    let suffix = suffix.trim();
    if suffix.is_empty() {
        None
    } else {
        Some(suffix.to_string())
    }
}

#[cfg(unix)]
#[derive(Default)]
struct ParsedHookEffectiveBlockedDetails {
    action_key: Option<String>,
    command_group: Option<String>,
    blocked_by: Option<String>,
    command_mode: Option<String>,
    base_command_mode: Option<String>,
    effective_command_mode: Option<String>,
    auto_downgraded_to_query_only: Option<String>,
    auto_downgrade_reason: Option<String>,
    recommendation: Option<String>,
    coexistence_mode: Option<String>,
    backend_pressure: Option<String>,
    fallback_action_key: Option<String>,
    fallback_step_id: Option<String>,
    fallback_command: Option<String>,
    fallback_phase: Option<String>,
}

#[cfg(unix)]
fn compute_hook_fallback_available(
    fallback_action_key: Option<&str>,
    fallback_command: Option<&str>,
    fallback_phase: Option<&str>,
) -> Option<bool> {
    match (fallback_action_key, fallback_command, fallback_phase) {
        (Some(action_key), Some(command), Some(phase))
            if action_key != "<none>"
                && action_key != "unknown"
                && command != "<none>"
                && phase != "<none>"
                && phase != "unknown" =>
        {
            Some(true)
        }
        (Some(_), Some(_), Some(_)) => Some(false),
        _ => None,
    }
}

#[cfg(unix)]
fn parse_hook_effective_blocked_details(message: &str) -> ParsedHookEffectiveBlockedDetails {
    let fallback_action_key = parse_error_field(message, "fallbackActionKey");
    let fallback_step_id = parse_error_field(message, "fallbackStepId");
    let fallback_command = parse_error_field_with_boundaries(
        message,
        "fallbackCommand",
        &["fallbackPhase", "recommendation"],
    );
    let fallback_phase = parse_error_field(message, "fallbackPhase");

    ParsedHookEffectiveBlockedDetails {
        action_key: parse_error_field(message, "actionKey"),
        command_group: parse_error_field(message, "commandGroup"),
        blocked_by: parse_error_field(message, "blockedBy"),
        command_mode: parse_error_field(message, "commandMode"),
        base_command_mode: parse_error_field(message, "baseCommandMode"),
        effective_command_mode: parse_error_field(message, "effectiveCommandMode"),
        auto_downgraded_to_query_only: parse_error_field(message, "autoDowngradedToQueryOnly"),
        auto_downgrade_reason: parse_error_field(message, "autoDowngradeReason"),
        recommendation: parse_error_field_with_boundaries(message, "recommendation", &[]),
        coexistence_mode: parse_error_field(message, "coexistenceMode"),
        backend_pressure: parse_error_field(message, "backendPressure"),
        fallback_action_key,
        fallback_step_id,
        fallback_command,
        fallback_phase,
    }
}

#[cfg(unix)]
fn normalize_hook_blocked_by(value: Option<String>) -> Option<String> {
    match value.as_deref() {
        Some("none" | "controller" | "target" | "both" | "unknown") => value,
        Some(_) => Some("unknown".into()),
        None => None,
    }
}

#[cfg(unix)]
fn normalize_hook_command_mode(value: Option<String>) -> Option<String> {
    match value.as_deref() {
        Some("allowed" | "query-only" | "cleanup-only" | "blocked" | "unknown") => value,
        Some(_) => Some("unknown".into()),
        None => None,
    }
}

#[cfg(unix)]
fn parse_bool_token(value: Option<String>) -> Option<bool> {
    match value.as_deref() {
        Some("true") => Some(true),
        Some("false") => Some(false),
        _ => None,
    }
}

#[cfg(unix)]
fn normalize_hook_auto_downgrade_reason(value: Option<String>) -> Option<String> {
    match value.as_deref() {
        Some(
            HOOK_MODE_AUTO_DOWNGRADE_REASON_SPLIT_BACKEND_LOADED | "<none>" | "unknown",
        ) => value,
        Some(_) => Some("unknown".into()),
        None => None,
    }
}

#[cfg(unix)]
fn normalize_hook_action_key(value: Option<String>) -> Option<String> {
    match value.as_deref() {
        Some("hook.query" | "hook.bootstrap" | "hook.install" | "hook.status" | "hook.stop" | "<none>" | "unknown") => {
            value
        }
        Some(_) => Some("unknown".into()),
        None => None,
    }
}

#[cfg(unix)]
fn normalize_hook_command_group(value: Option<String>) -> Option<String> {
    match value.as_deref() {
        Some("query" | "bootstrap" | "hook-install" | "hook-status" | "hook-stop" | "unknown") => value,
        Some(_) => Some("unknown".into()),
        None => None,
    }
}

#[cfg(unix)]
fn normalize_hook_coexistence_mode(value: Option<String>) -> Option<String> {
    match value.as_deref() {
        Some(
            "inline-safe" | "inline-risky" | "query-only" | "cleanup-only" | "blocked" | "unknown",
        ) => value,
        Some(_) => Some("unknown".into()),
        None => None,
    }
}

#[cfg(unix)]
fn normalize_hook_backend_pressure(value: Option<String>) -> Option<String> {
    match value.as_deref() {
        Some("none" | "controller" | "target" | "both" | "unknown") => value,
        Some(_) => Some("unknown".into()),
        None => None,
    }
}

#[cfg(unix)]
fn normalize_hook_fallback_phase(value: Option<String>) -> Option<String> {
    match value.as_deref() {
        Some("preflight" | "diagnose" | "query" | "cleanup" | "inject" | "hook-install" | "unknown") => value,
        Some(_) => Some("unknown".into()),
        None => None,
    }
}

#[cfg(unix)]
fn is_valid_hook_fallback_step_id(value: &str) -> bool {
    !value.is_empty()
        && (value.starts_with("next-action:") || value.starts_with("fallback-plan:"))
        && value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, ':' | '-' | '.' | '_'))
}

#[cfg(unix)]
fn normalize_hook_fallback_step_id(value: Option<String>) -> Option<String> {
    match value {
        Some(value) if value == "<none>" || value == "unknown" => Some(value),
        Some(value) if is_valid_hook_fallback_step_id(&value) => Some(value),
        Some(_) => Some("unknown".into()),
        None => None,
    }
}

#[cfg(unix)]
fn push_unique_hint(hints: &mut Vec<String>, hint: impl Into<String>) {
    let hint = hint.into();
    if !hint.is_empty() && !hints.iter().any(|existing| existing == &hint) {
        hints.push(hint);
    }
}

#[cfg(unix)]
fn push_agent_path_hints(config: &ControllerConfig, hints: &mut Vec<String>) {
    let uses_legacy_agent_filename = Path::new(&config.agent_path)
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name == "agent.dylib");

    if uses_legacy_agent_filename {
        push_unique_hint(
            hints,
            format!(
                "agent path is still using the old filename agent.dylib (legacy example: {}); use {} on rootless jailbreaks or {} on rootful setups",
                LEGACY_AGENT_PATH_ROOTFUL, DEFAULT_AGENT_PATH, DEFAULT_AGENT_PATH_ROOTFUL
            ),
        );
    }
}

#[cfg(unix)]
fn extract_stage_error_message(error: Option<&Error>, stage: &str) -> Option<String> {
    let error = error?;
    let message = error.to_string();
    let prefix = format!("{stage} failed: ");
    message.split_once(&prefix).map(|(_, value)| value.to_string())
}

#[cfg(unix)]
fn failure_diagnostics_to_json(
    config: &ControllerConfig,
    trace: Option<&InjectionTrace>,
    hello: Option<&Hello>,
    ping: Option<&str>,
    hook_environment_checked: bool,
    jsinit_result: Option<&str>,
    loadjs_result: Option<&str>,
    error: Option<&Error>,
) -> Value {
    let Some(error) = error else {
        return Value::Null;
    };

    let message = error.to_string();
    let script_requested = config.script_path.is_some();
    let handshake_stage = handshake_stage_label(
        script_requested,
        hello,
        ping,
        hook_environment_checked,
        jsinit_result,
        loadjs_result,
    );

    let mut phase = "unknown".to_string();
    let mut code = "unknown".to_string();
    let mut bootstrap_status: Option<String> = None;
    let mut hints = Vec::new();
    let mut failed_step = None;
    let mut hook_action_key: Option<String> = None;
    let mut hook_command_group: Option<String> = None;
    let mut hook_blocked_by: Option<String> = None;
    let mut hook_command_mode: Option<String> = None;
    let mut hook_base_command_mode: Option<String> = None;
    let mut hook_effective_command_mode: Option<String> = None;
    let mut hook_auto_downgraded_to_query_only: Option<bool> = None;
    let mut hook_auto_downgrade_reason: Option<String> = None;
    let mut hook_recommendation: Option<String> = None;
    let mut coexistence_mode: Option<String> = None;
    let mut backend_pressure: Option<String> = None;
    let mut fallback_action_key: Option<String> = None;
    let mut fallback_step_id: Option<String> = None;
    let mut fallback_command: Option<String> = None;
    let mut fallback_phase: Option<String> = None;
    let mut hook_fallback_available: Option<bool> = None;

    if let Some(trace) = trace {
        if let Some(report) = trace.bootstrap_report.as_ref() {
            bootstrap_status = Some(report.status.as_str().to_string());
            if report.status.is_failure() {
                phase = "remote-bootstrap".into();
                code = report.status.as_str().into();
                if let Some(hint) = report.status.diagnostic_hint() {
                    push_unique_hint(&mut hints, hint);
                }
                if trace.bootstrap_timed_out {
                    push_unique_hint(
                        &mut hints,
                        "controller timed out while polling remote bootstrap status; verify the target thread was able to update the shared status block",
                    );
                }
            } else if matches!(report.status, BootstrapStatus::EntryReturned) {
                phase = "agent-entry".into();
                code = "entry-returned".into();
                if report.entry_return != 0 {
                    push_unique_hint(
                        &mut hints,
                        format!(
                            "agent entry returned non-zero before handshake: {}; inspect agent initialization and early runtime failures",
                            report.entry_return
                        ),
                    );
                }
                if let Some(hint) = report.status.diagnostic_hint() {
                    push_unique_hint(&mut hints, hint);
                }
            }
        }
    }

    if code == "unknown" {
        if message.contains("task_for_pid failed") {
            phase = "mach".into();
            code = "task-for-pid".into();
            push_unique_hint(
                &mut hints,
                "verify jailbreak/root context, task_for_pid entitlement or exception handling, and target platform protection",
            );
        } else if message.contains("mach_vm_allocate failed") {
            phase = "remote-memory".into();
            code = "mach-vm-allocate".into();
        } else if message.contains("mach_vm_write failed") {
            phase = "remote-memory".into();
            code = "mach-vm-write".into();
        } else if message.contains("mach_vm_protect(set_maximum) failed") || message.contains("mach_vm_protect failed")
        {
            phase = "remote-memory".into();
            code = "mach-vm-protect".into();
        } else if message.contains("mach_vm_read_overwrite failed") {
            phase = "preflight".into();
            code = "mach-vm-read".into();
        } else if message.contains("task_info(TASK_DYLD_INFO) failed") {
            phase = "preflight".into();
            code = "task-dyld-info".into();
        } else if message.contains("thread_create_running failed") {
            phase = "remote-thread".into();
            code = "thread-create-running".into();
        } else if message.contains("controller script read failed:") {
            phase = "script".into();
            code = "script-read".into();
            failed_step = Some("jsInit");
        } else if message.contains("controller socket bind failed:") {
            phase = "controller-socket".into();
            code = "bind-socket".into();
        } else if message.contains("agent hello failed:") {
            phase = "handshake".into();
            code = "agent-hello".into();
            failed_step = Some("hello");
        } else if message.contains("agent ping failed:") {
            phase = "handshake".into();
            code = "agent-ping".into();
            failed_step = Some("ping");
        } else if message.contains("agent hook environment query failed:") {
            phase = "handshake".into();
            code = "hook-environment".into();
            failed_step = Some("hookEnvironment");
        } else if message.contains("agent jsinit failed:") {
            phase = "script".into();
            code = "jsinit".into();
            failed_step = Some("jsInit");
        } else if message.contains("agent loadjs failed:") {
            phase = "script".into();
            code = "loadjs".into();
            failed_step = Some("loadJs");
        } else if message.contains("both hook strategies blocked injection") {
            phase = "hook-policy".into();
            code = "both-hook-policies-blocked".into();
            hook_blocked_by = Some("both".into());
            hook_recommendation = parse_message_suffix_after_prefix(
                &message,
                "both hook strategies blocked injection:",
            );
        } else if message.contains("target hook strategy blocked injection") {
            phase = "hook-policy".into();
            code = "target-hook-policy-blocked".into();
            hook_blocked_by = Some("target".into());
            hook_recommendation = parse_message_suffix_after_prefix(
                &message,
                "target hook strategy blocked injection:",
            );
        } else if message.contains("hook strategy blocked injection") {
            phase = "hook-policy".into();
            code = "controller-hook-policy-blocked".into();
            hook_blocked_by = Some("controller".into());
            hook_recommendation =
                parse_message_suffix_after_prefix(&message, "hook strategy blocked injection:");
        } else if message.contains("hook-effective-blocked") {
            phase = "hook-policy".into();
            let parsed = parse_hook_effective_blocked_details(&message);
            hook_action_key = normalize_hook_action_key(parsed.action_key);
            hook_command_group = normalize_hook_command_group(parsed.command_group);
            hook_blocked_by = normalize_hook_blocked_by(parsed.blocked_by).or_else(|| Some("unknown".into()));
            code = match hook_blocked_by.as_deref() {
                Some("controller") => "controller-hook-policy-blocked".into(),
                Some("target") => "target-hook-policy-blocked".into(),
                Some("both") => "both-hook-policies-blocked".into(),
                _ => "hook-effective-blocked".into(),
            };
            let legacy_command_mode = normalize_hook_command_mode(parsed.command_mode);
            hook_base_command_mode = normalize_hook_command_mode(parsed.base_command_mode);
            hook_effective_command_mode =
                normalize_hook_command_mode(parsed.effective_command_mode).or_else(|| legacy_command_mode.clone());
            hook_command_mode = hook_effective_command_mode
                .clone()
                .or_else(|| legacy_command_mode.clone());
            hook_auto_downgraded_to_query_only = parse_bool_token(parsed.auto_downgraded_to_query_only);
            hook_auto_downgrade_reason = normalize_hook_auto_downgrade_reason(parsed.auto_downgrade_reason);
            if let Some(mode) = hook_command_mode.as_deref() {
                push_unique_hint(
                    &mut hints,
                    format!("effective hook command mode during failure: {mode}"),
                );
            }
            hook_recommendation = parsed.recommendation;
            coexistence_mode = normalize_hook_coexistence_mode(parsed.coexistence_mode);
            backend_pressure = normalize_hook_backend_pressure(parsed.backend_pressure);
            fallback_action_key = normalize_hook_action_key(parsed.fallback_action_key);
            fallback_step_id = normalize_hook_fallback_step_id(parsed.fallback_step_id);
            fallback_command = parsed.fallback_command;
            fallback_phase = normalize_hook_fallback_phase(parsed.fallback_phase);
            hook_fallback_available = compute_hook_fallback_available(
                fallback_action_key.as_deref(),
                fallback_command.as_deref(),
                fallback_phase.as_deref(),
            );
        } else if message.contains("timed out waiting") {
            phase = "controller-socket".into();
            code = "agent-connect-timeout".into();
            push_unique_hint(
                &mut hints,
                "controller socket was listening but the agent never connected back in time; verify bootstrap connect path and socket visibility",
            );
        } else if message.contains("remote bootstrap failed:") {
            phase = "remote-bootstrap".into();
            code = "bootstrap-failed".into();
            if let Some(status) = parse_error_status_field(&message) {
                bootstrap_status = Some(status.clone());
                code = status;
            }
        } else if message.contains("agent entry returned") {
            phase = "agent-entry".into();
            code = "entry-returned".into();
        } else if message.contains("quickjs backend is stubbed") {
            phase = "runtime".into();
            code = "quickjs-stubbed".into();
        }
    }

    if code == "unknown" {
        match handshake_stage {
            "awaiting-hello" => {
                phase = "handshake".into();
                code = "agent-hello".into();
                failed_step = Some("hello");
            }
            "awaiting-ping" => {
                phase = "handshake".into();
                code = "agent-ping".into();
                failed_step = Some("ping");
            }
            "awaiting-hook-environment" => {
                phase = "handshake".into();
                code = "hook-environment".into();
                failed_step = Some("hookEnvironment");
            }
            "awaiting-jsinit" => {
                phase = "script".into();
                code = "jsinit".into();
                failed_step = Some("jsInit");
            }
            "awaiting-loadjs" => {
                phase = "script".into();
                code = "loadjs".into();
                failed_step = Some("loadJs");
            }
            _ => {}
        }
    }

    if failed_step.is_none() {
        failed_step = match handshake_stage {
            "awaiting-hello" => Some("hello"),
            "awaiting-ping" => Some("ping"),
            "awaiting-hook-environment" => Some("hookEnvironment"),
            "awaiting-jsinit" => Some("jsInit"),
            "awaiting-loadjs" => Some("loadJs"),
            _ => None,
        };
    }

    if phase == "hook-policy" {
        hook_action_key.get_or_insert_with(|| "unknown".into());
        hook_command_group.get_or_insert_with(|| "unknown".into());
        hook_blocked_by.get_or_insert_with(|| "unknown".into());
        hook_command_mode.get_or_insert_with(|| "unknown".into());
        hook_base_command_mode.get_or_insert_with(|| "unknown".into());
        hook_effective_command_mode.get_or_insert_with(|| "unknown".into());
        hook_auto_downgraded_to_query_only.get_or_insert(false);
        hook_auto_downgrade_reason.get_or_insert_with(|| "unknown".into());
        coexistence_mode.get_or_insert_with(|| "unknown".into());
        backend_pressure.get_or_insert_with(|| "unknown".into());
        fallback_action_key.get_or_insert_with(|| "unknown".into());
        fallback_step_id.get_or_insert_with(|| "unknown".into());
        fallback_phase.get_or_insert_with(|| "unknown".into());
        hook_fallback_available.get_or_insert(false);

        if let (Some(base_mode), Some(effective_mode)) = (
            hook_base_command_mode.as_deref(),
            hook_effective_command_mode.as_deref(),
        ) {
            if base_mode != "unknown" && effective_mode != "unknown" && base_mode != effective_mode {
                push_unique_hint(
                    &mut hints,
                    format!(
                        "hook command mode adjusted under backend pressure: base={base_mode}, effective={effective_mode}"
                    ),
                );
            }
        }

        if hook_auto_downgraded_to_query_only == Some(true) {
            let reason = hook_auto_downgrade_reason
                .as_deref()
                .filter(|value| !value.is_empty() && *value != "unknown" && *value != "<none>")
                .unwrap_or("unknown");
            push_unique_hint(
                &mut hints,
                format!("inline hook install path auto-downgraded to query-only: {reason}"),
            );
        }

        if hook_fallback_available == Some(true) {
            if let (Some(action_key), Some(command), Some(phase_label)) = (
                fallback_action_key.as_deref(),
                fallback_command.as_deref(),
                fallback_phase.as_deref(),
            ) {
                if action_key != "unknown"
                    && action_key != "<none>"
                    && phase_label != "unknown"
                    && phase_label != "<none>"
                    && !command.is_empty()
                    && command != "<none>"
                {
                    push_unique_hint(
                        &mut hints,
                        format!(
                            "fallback command available: action={action_key}, phase={phase_label}, command={command}, stepId={}",
                            fallback_step_id.as_deref().unwrap_or("unknown")
                        ),
                    );
                }
            }
        }
    }

    push_agent_path_hints(config, &mut hints);
    let hook_details_present = hook_action_key.is_some()
        || hook_command_group.is_some()
        || hook_blocked_by.is_some()
        || hook_command_mode.is_some()
        || hook_base_command_mode.is_some()
        || hook_effective_command_mode.is_some()
        || hook_auto_downgraded_to_query_only.is_some()
        || hook_auto_downgrade_reason.is_some()
        || hook_recommendation.is_some()
        || coexistence_mode.is_some()
        || backend_pressure.is_some()
        || fallback_action_key.is_some()
        || fallback_step_id.is_some()
        || fallback_command.is_some()
        || fallback_phase.is_some()
        || hook_fallback_available.is_some();
    let hook_diagnostics = if hook_details_present {
        json!({
            "actionKey": hook_action_key,
            "commandGroup": hook_command_group,
            "blockedBy": hook_blocked_by,
            "commandMode": hook_command_mode,
            "baseCommandMode": hook_base_command_mode,
            "effectiveCommandMode": hook_effective_command_mode,
            "autoDowngradedToQueryOnly": hook_auto_downgraded_to_query_only,
            "autoDowngradeReason": hook_auto_downgrade_reason,
            "recommendation": hook_recommendation,
            "coexistenceMode": coexistence_mode,
            "backendPressure": backend_pressure,
            "fallbackActionKey": fallback_action_key,
            "fallbackStepId": fallback_step_id,
            "fallbackCommand": fallback_command,
            "fallbackPhase": fallback_phase,
            "fallbackAvailable": hook_fallback_available,
        })
    } else {
        Value::Null
    };

    json!({
        "phase": phase,
        "code": code,
        "bootstrapStatus": bootstrap_status,
        "handshakeStage": handshake_stage,
        "failedStep": failed_step,
        "hookActionKey": hook_action_key.clone(),
        "hookCommandGroup": hook_command_group.clone(),
        "hookBlockedBy": hook_blocked_by.clone(),
        "hookCommandMode": hook_command_mode.clone(),
        "hookBaseCommandMode": hook_base_command_mode.clone(),
        "hookEffectiveCommandMode": hook_effective_command_mode.clone(),
        "hookAutoDowngradedToQueryOnly": hook_auto_downgraded_to_query_only,
        "hookAutoDowngradeReason": hook_auto_downgrade_reason.clone(),
        "hookRecommendation": hook_recommendation.clone(),
        "coexistenceMode": coexistence_mode.clone(),
        "backendPressure": backend_pressure.clone(),
        "fallbackActionKey": fallback_action_key.clone(),
        "fallbackStepId": fallback_step_id.clone(),
        "fallbackCommand": fallback_command.clone(),
        "fallbackPhase": fallback_phase.clone(),
        "hookFallbackAvailable": hook_fallback_available,
        "hook": hook_diagnostics,
        "hints": hints,
    })
}

#[cfg(unix)]
fn injection_trace_to_json(trace: &InjectionTrace) -> Value {
    json!({
        "payloadAddress": trace.payload_address,
        "payloadAddressHex": json_hex_u64(trace.payload_address),
        "payloadSize": trace.payload_size,
        "payloadAllocatedSize": trace.payload_allocated_size,
        "dataAddress": trace.data_address,
        "dataAddressHex": json_hex_u64(trace.data_address),
        "dataSize": trace.data_size,
        "dataAllocatedSize": trace.data_allocated_size,
        "stackAddress": trace.stack_address,
        "stackAddressHex": json_hex_u64(trace.stack_address),
        "stackSize": trace.stack_size,
        "targetUsesArm64e": trace.target_uses_arm64e,
        "codeProtection": trace.code_protection.as_str(),
        "dataProtection": trace.data_protection.as_str(),
        "threadBootstrapKind": trace.thread_bootstrap_kind.as_str(),
        "threadBootstrapLabel": trace.thread_bootstrap_label,
        "threadPlan": {
            "flavor": trace.thread_plan.flavor,
            "count": trace.thread_plan.count,
            "pc": trace.thread_plan.state.pc,
            "pcHex": json_hex_u64(trace.thread_plan.state.pc),
            "sp": trace.thread_plan.state.sp,
            "spHex": json_hex_u64(trace.thread_plan.state.sp),
            "x2": trace.thread_plan.state.x[2],
            "x2Hex": json_hex_u64(trace.thread_plan.state.x[2]),
            "x3": trace.thread_plan.state.x[3],
            "x3Hex": json_hex_u64(trace.thread_plan.state.x[3]),
        },
        "threadPort": trace.thread_port,
        "threadTermination": trace.thread_termination.as_str(),
        "threadPortDeallocated": trace.thread_port_deallocated,
        "resourcesPersist": trace.resources_persist,
        "bootstrapTimedOut": trace.bootstrap_timed_out,
        "bootstrapReport": trace.bootstrap_report.as_ref().map(bootstrap_report_to_json),
    })
}

#[cfg(unix)]
fn render_injection_result_json(
    config: &ControllerConfig,
    pid: i32,
    socket_path: &str,
    plan: &InjectionPlan,
    injection_environment: &InjectionEnvironmentReport,
    doctor: &DoctorReport,
    preflight: &InjectionTargetPreflightReport,
    trace: Option<&InjectionTrace>,
    hello: Option<&Hello>,
    ping: Option<&str>,
    hook_environment_notice: Option<&str>,
    hook_environment_checked: bool,
    jsinit_result: Option<&str>,
    loadjs_result: Option<&str>,
    agent_logs: &[String],
    error: Option<&Error>,
) -> Value {
    let (ok, error_kind, error_message) = match error {
        Some(err) => (
            false,
            Some(match err {
                Error::Io(_) => "io",
                Error::Protocol(_) => "protocol",
                Error::InvalidArgument(_) => "invalid-argument",
                Error::State(_) => "state",
                Error::Unsupported(_) => "unsupported",
            }),
            Some(err.to_string()),
        ),
        None => (true, None, None),
    };
    let handshake_stage = handshake_stage_label(
        config.script_path.is_some(),
        hello,
        ping,
        hook_environment_checked,
        jsinit_result,
        loadjs_result,
    );
    let hello_error = extract_stage_error_message(error, "agent hello");
    let ping_error = extract_stage_error_message(error, "agent ping");
    let hook_environment_error = extract_stage_error_message(error, "agent hook environment query");
    let jsinit_error = extract_stage_error_message(error, "agent jsinit");
    let loadjs_error = extract_stage_error_message(error, "agent loadjs");

    json!({
        "ok": ok,
        "errorKind": error_kind,
        "error": error_message,
        "mode": injection_mode_label(config.mode),
        "pid": pid,
        "socketPath": socket_path,
        "agentPath": config.agent_path,
        "entrySymbol": config.entry_symbol,
        "scriptPath": config.script_path,
        "hook": hook_shortcuts_to_json(injection_environment, preflight),
        "environment": injection_environment_to_json(injection_environment),
        "doctor": doctor_report_to_json(doctor),
        "plan": injection_plan_to_json(plan),
        "preflight": injection_preflight_to_json(preflight),
        "trace": trace.map(injection_trace_to_json),
        "diagnostics": failure_diagnostics_to_json(
            config,
            trace,
            hello,
            ping,
            hook_environment_checked,
            jsinit_result,
            loadjs_result,
            error,
        ),
        "handshake": {
            "stage": handshake_stage,
            "steps": render_handshake_steps_json(
                config.script_path.is_some(),
                hello,
                ping,
                hook_environment_checked,
                jsinit_result,
                loadjs_result,
            ),
            "errors": {
                "hello": hello_error,
                "ping": ping_error,
                "hookEnvironment": hook_environment_error,
                "jsInit": jsinit_error,
                "loadJs": loadjs_error,
            },
            "hello": hello.map(hello_to_json),
            "ping": ping,
            "hookEnvironmentNotice": hook_environment_notice,
            "hookEnvironmentChecked": hook_environment_checked,
            "script": {
                "jsInitResult": jsinit_result,
                "loadJsResult": loadjs_result,
            },
            "agentLogs": agent_logs,
        },
    })
}

#[cfg(unix)]
pub fn run_controller(config: &ControllerConfig, list_images: bool) -> Result<()> {
    if list_images {
        let images = enumerate_images()?;
        if config.list_images_json {
            let rendered = render_image_list_json(&images);
            println!(
                "{}",
                serde_json::to_string_pretty(&rendered)
                    .map_err(|err| Error::State(format!("failed to encode image list json: {err}")))?
            );
            return Ok(());
        }
        for image in images {
            println!("0x{:x} slide=0x{:x} {}", image.base, image.slide, image.name);
        }
        return Ok(());
    }

    let pid = match config.mode {
        InjectionMode::Attach => config.pid.expect("validated pid"),
        InjectionMode::Spawn => spawn_target(
            config.bundle_id.as_deref().expect("validated bundle id"),
            config.spawn_command.as_deref(),
        )?,
    };

    let socket_path_buf = resolve_socket_path(config, pid)?;
    let socket_path = socket_path_buf.to_string_lossy().into_owned();
    let injector = MachInjector;
    let target = InjectionTarget {
        pid,
        dylib_path: config.agent_path.clone(),
        entry_symbol: config.entry_symbol.clone(),
        socket_path: socket_path.clone(),
    };
    let injection_environment = probe_injection_environment()?;
    let plan = injector.plan(&target)?;
    let preflight = injector.preflight(&target)?;
    let doctor = analyze_doctor_report(config, pid, &socket_path_buf, &injection_environment, &preflight);

    let emit_inject_json = config.inject_json;
    let emit_command_json = config.command_json && config.command.is_some();

    if config.preflight_only && config.preflight_json {
        let rendered = render_preflight_json(
            config,
            pid,
            &socket_path,
            &plan,
            &injection_environment,
            &preflight,
            &doctor,
        );
        println!(
            "{}",
            serde_json::to_string_pretty(&rendered)
                .map_err(|err| Error::State(format!("failed to encode preflight json: {err}")))?
        );
        return Ok(());
    }

    if !(emit_inject_json || emit_command_json) {
        println!(
            "prepared Mach injection plan for pid {} (bootstrap {} bytes)",
            pid,
            plan.bootstrap().len()
        );
        print_injection_environment(&injection_environment);
        print_doctor_report(&doctor);
        print_injection_preflight(&preflight);
        println!("controller socket: {}", socket_path);
        println!(
            "bootstrap launch layout: code={} data={} routine=code+0x{:x} args=data+0x{:x} stack=0x{:x} align=0x{:x}",
            plan.bootstrap().code_size(),
            plan.bootstrap().data_size(),
            plan.bootstrap().routine_offset(),
            plan.bootstrap().data_relative_offset(plan.bootstrap().args_offset()),
            plan.bootstrap().stack_size(),
            plan.bootstrap().stack_alignment()
        );
        if !plan.loader_symbols().is_empty() {
            println!("resolved loader symbols:");
            for symbol in plan.loader_symbols() {
                println!("{}", render_loader_symbol(symbol));
            }
            if let Some(thread_entry) = plan
                .loader_symbols()
                .iter()
                .find(|symbol| symbol.role == LoaderSymbolRole::ThreadBootstrap)
            {
                println!(
                    "thread entry template: pc={} + 0x{:x}, x0=0, x1=0, x2=code+0x{:x}, x3=data+0x{:x}",
                    thread_entry.module_name,
                    thread_entry.offset,
                    plan.bootstrap().routine_offset(),
                    plan.bootstrap().data_relative_offset(plan.bootstrap().args_offset())
                );
            }
        }
        for step in plan.steps() {
            println!(" - [{}] {}", step.stage.as_str(), step.detail);
        }
    }

    if config.preflight_only {
        println!("preflight-only requested; skipping remote bootstrap, agent handshake, and interactive controller");
        return Ok(());
    }

    let script = if let Some(script_path) = &config.script_path {
        match fs::read_to_string(script_path) {
            Ok(script) => {
                if !emit_command_json {
                    println!("loaded bootstrap script from {} ({} bytes)", script_path, script.len());
                }
                Some(script)
            }
            Err(err) if emit_inject_json => {
                let error = stage_error("controller script read", err.into());
                let rendered = render_injection_result_json(
                    config,
                    pid,
                    &socket_path,
                    &plan,
                    &injection_environment,
                    &doctor,
                    &preflight,
                    None,
                    None,
                    None,
                    None,
                    false,
                    None,
                    None,
                    &[],
                    Some(&error),
                );
                println!(
                    "{}",
                    serde_json::to_string_pretty(&rendered)
                        .map_err(|encode_err| Error::State(format!("failed to encode injection json: {encode_err}")))?
                );
                return Ok(());
            }
            Err(err) if emit_command_json => {
                let command = config.command.as_deref().expect("command json requires command");
                let error = stage_error("controller script read", err.into());
                let rendered = render_command_error_json_with_context(
                    command,
                    &error,
                    &[],
                    &CommandJsonContext {
                        config,
                        pid,
                        socket_path: &socket_path,
                        plan: &plan,
                        injection_environment: &injection_environment,
                        doctor: &doctor,
                        preflight: &preflight,
                        trace: None,
                        hello: None,
                        ping: None,
                        hook_environment_notice: None,
                        hook_environment_checked: false,
                        jsinit_result: None,
                        loadjs_result: None,
                    },
                );
                println!(
                    "{}",
                    serde_json::to_string_pretty(&rendered)
                        .map_err(|encode_err| Error::State(format!("failed to encode command json: {encode_err}")))?
                );
                return Ok(());
            }
            Err(err) => return Err(err.into()),
        }
    } else {
        None
    };

    let socket = match ControllerSocket::bind_path(PathBuf::from(&socket_path)) {
        Ok(socket) => socket,
        Err(err) if emit_inject_json => {
            let error = stage_error("controller socket bind", err);
            let rendered = render_injection_result_json(
                config,
                pid,
                &socket_path,
                &plan,
                &injection_environment,
                &doctor,
                &preflight,
                None,
                None,
                None,
                None,
                false,
                None,
                None,
                &[],
                Some(&error),
            );
            println!(
                "{}",
                serde_json::to_string_pretty(&rendered)
                    .map_err(|encode_err| Error::State(format!("failed to encode injection json: {encode_err}")))?
            );
            return Ok(());
        }
        Err(err) if emit_command_json => {
            let command = config.command.as_deref().expect("command json requires command");
            let error = stage_error("controller socket bind", err);
            let rendered = render_command_error_json_with_context(
                command,
                &error,
                &[],
                &CommandJsonContext {
                    config,
                    pid,
                    socket_path: &socket_path,
                    plan: &plan,
                    injection_environment: &injection_environment,
                    doctor: &doctor,
                    preflight: &preflight,
                    trace: None,
                    hello: None,
                    ping: None,
                    hook_environment_notice: None,
                    hook_environment_checked: false,
                    jsinit_result: None,
                    loadjs_result: None,
                },
            );
            println!(
                "{}",
                serde_json::to_string_pretty(&rendered)
                    .map_err(|encode_err| Error::State(format!("failed to encode command json: {encode_err}")))?
            );
            return Ok(());
        }
        Err(err) => return Err(err),
    };
    let inject_trace = match injector.inject_trace_with_preflight(&target, &preflight) {
        Ok(trace) => trace,
        Err(err) if emit_inject_json => {
            let rendered = render_injection_result_json(
                config,
                pid,
                &socket_path,
                &plan,
                &injection_environment,
                &doctor,
                &preflight,
                None,
                None,
                None,
                None,
                false,
                None,
                None,
                &[],
                Some(&err),
            );
            println!(
                "{}",
                serde_json::to_string_pretty(&rendered)
                    .map_err(|encode_err| Error::State(format!("failed to encode injection json: {encode_err}")))?
            );
            return Ok(());
        }
        Err(err) if emit_command_json => {
            let command = config.command.as_deref().expect("command json requires command");
            let rendered = render_command_error_json_with_context(
                command,
                &err,
                &[],
                &CommandJsonContext {
                    config,
                    pid,
                    socket_path: &socket_path,
                    plan: &plan,
                    injection_environment: &injection_environment,
                    doctor: &doctor,
                    preflight: &preflight,
                    trace: None,
                    hello: None,
                    ping: None,
                    hook_environment_notice: None,
                    hook_environment_checked: false,
                    jsinit_result: None,
                    loadjs_result: None,
                },
            );
            println!(
                "{}",
                serde_json::to_string_pretty(&rendered)
                    .map_err(|encode_err| Error::State(format!("failed to encode command json: {encode_err}")))?
            );
            return Ok(());
        }
        Err(err) => return Err(err),
    };
    if !(emit_inject_json || emit_command_json) {
        print_injection_trace(&inject_trace);
    }

    let mut agent_logs = Vec::new();
    let mut hello_json = None;
    let mut ping_json = None;
    let mut hook_environment_notice = None;
    let mut hook_environment_checked_json = false;
    let mut jsinit_result_json = None;
    let mut loadjs_result_json = None;

    let mut stream = match socket.accept(Duration::from_secs(config.connect_timeout_secs)) {
        Ok(stream) => stream,
        Err(err) => {
            if emit_inject_json {
                let rendered = render_injection_result_json(
                    config,
                    pid,
                    &socket_path,
                    &plan,
                    &injection_environment,
                    &doctor,
                    &preflight,
                    Some(&inject_trace),
                    hello_json.as_ref(),
                    ping_json.as_deref(),
                    hook_environment_notice.as_deref(),
                    hook_environment_checked_json,
                    jsinit_result_json.as_deref(),
                    loadjs_result_json.as_deref(),
                    &agent_logs,
                    Some(&Error::State(format!(
                        "{}; bootstrap={}",
                        err,
                        render_bootstrap_summary(&inject_trace)
                    ))),
                );
                println!(
                    "{}",
                    serde_json::to_string_pretty(&rendered)
                        .map_err(|encode_err| Error::State(format!("failed to encode injection json: {encode_err}")))?
                );
                return Ok(());
            }
            if emit_command_json {
                let command = config.command.as_deref().expect("command json requires command");
                let error = Error::State(format!(
                    "{}; bootstrap={}",
                    err,
                    render_bootstrap_summary(&inject_trace)
                ));
                let rendered = render_command_error_json_with_context(
                    command,
                    &error,
                    &agent_logs,
                    &CommandJsonContext {
                        config,
                        pid,
                        socket_path: &socket_path,
                        plan: &plan,
                        injection_environment: &injection_environment,
                        doctor: &doctor,
                        preflight: &preflight,
                        trace: Some(&inject_trace),
                        hello: hello_json.as_ref(),
                        ping: ping_json.as_deref(),
                        hook_environment_notice: hook_environment_notice.as_deref(),
                        hook_environment_checked: hook_environment_checked_json,
                        jsinit_result: jsinit_result_json.as_deref(),
                        loadjs_result: loadjs_result_json.as_deref(),
                    },
                );
                println!(
                    "{}",
                    serde_json::to_string_pretty(&rendered)
                        .map_err(|encode_err| Error::State(format!("failed to encode command json: {encode_err}")))?
                );
                return Ok(());
            }
            return Err(Error::State(format!(
                "{}; bootstrap={}",
                err,
                render_bootstrap_summary(&inject_trace)
            )));
        }
    };
    if emit_inject_json {
        let result: Result<()> = (|| {
            let hello = expect_hello(&mut stream).map_err(|err| stage_error("agent hello", err))?;
            hello_json = Some(hello);

            ping_json = Some(
                expect_eval_ok_json_with_logs(&mut stream, &AgentCommand::Ping, Some(&mut agent_logs))
                    .map_err(|err| stage_error("agent ping", err))?,
            );
            hook_environment_notice = fetch_hook_environment_notice(&mut stream, Some(&mut agent_logs))
                .map_err(|err| stage_error("agent hook environment query", err))?;
            hook_environment_checked_json = true;

            if let Some(script) = script {
                jsinit_result_json = Some(
                    expect_eval_ok_json_with_logs(&mut stream, &AgentCommand::JsInit, Some(&mut agent_logs))
                        .map_err(|err| stage_error("agent jsinit", err))?,
                );
                loadjs_result_json = Some(
                    expect_eval_ok_json_with_logs(&mut stream, &AgentCommand::LoadJs { script }, Some(&mut agent_logs))
                        .map_err(|err| stage_error("agent loadjs", err))?,
                );
            }

            let _ = send_command_json(&mut stream, &AgentCommand::Exit);
            Ok(())
        })();

        let rendered = render_injection_result_json(
            config,
            pid,
            &socket_path,
            &plan,
            &injection_environment,
            &doctor,
            &preflight,
            Some(&inject_trace),
            hello_json.as_ref(),
            ping_json.as_deref(),
            hook_environment_notice.as_deref(),
            hook_environment_checked_json,
            jsinit_result_json.as_deref(),
            loadjs_result_json.as_deref(),
            &agent_logs,
            result.as_ref().err(),
        );
        println!(
            "{}",
            serde_json::to_string_pretty(&rendered)
                .map_err(|err| Error::State(format!("failed to encode injection json: {err}")))?
        );
        return Ok(());
    } else if emit_command_json {
        let command = config.command.as_deref().expect("command json requires command");
        let rendered: Value = match (|| -> Result<CommandOutcome> {
            let hello = expect_hello(&mut stream).map_err(|err| stage_error("agent hello", err))?;
            hello_json = Some(hello);
            let ping = expect_eval_ok_json_with_logs(&mut stream, &AgentCommand::Ping, Some(&mut agent_logs))
                .map_err(|err| stage_error("agent ping", err))?;
            ping_json = Some(ping);
            hook_environment_notice = fetch_hook_environment_notice(&mut stream, Some(&mut agent_logs))
                .map_err(|err| stage_error("agent hook environment query", err))?;
            hook_environment_checked_json = true;

            if let Some(script) = script {
                jsinit_result_json = Some(
                    expect_eval_ok_json_with_logs(&mut stream, &AgentCommand::JsInit, Some(&mut agent_logs))
                        .map_err(|err| stage_error("agent jsinit", err))?,
                );
                loadjs_result_json = Some(
                    expect_eval_ok_json_with_logs(&mut stream, &AgentCommand::LoadJs { script }, Some(&mut agent_logs))
                        .map_err(|err| stage_error("agent loadjs", err))?,
                );
            }

            let mut outcome = execute_single_command(&mut stream, command, true, &injection_environment, &preflight)?;
            if !agent_logs.is_empty() {
                let mut combined_logs = std::mem::take(&mut agent_logs);
                combined_logs.extend(outcome.logs);
                outcome.logs = combined_logs;
            }
            Ok(outcome)
        })() {
            Ok(outcome) => render_command_outcome_json(&outcome),
            Err(err) => render_command_error_json_with_context(
                command,
                &err,
                &agent_logs,
                &CommandJsonContext {
                    config,
                    pid,
                    socket_path: &socket_path,
                    plan: &plan,
                    injection_environment: &injection_environment,
                    doctor: &doctor,
                    preflight: &preflight,
                    trace: Some(&inject_trace),
                    hello: hello_json.as_ref(),
                    ping: ping_json.as_deref(),
                    hook_environment_notice: hook_environment_notice.as_deref(),
                    hook_environment_checked: hook_environment_checked_json,
                    jsinit_result: jsinit_result_json.as_deref(),
                    loadjs_result: loadjs_result_json.as_deref(),
                },
            ),
        };
        let _ = send_command_json(&mut stream, &AgentCommand::Exit);
        println!(
            "{}",
            serde_json::to_string_pretty(&rendered)
                .map_err(|err| Error::State(format!("failed to encode command json: {err}")))?
        );
        return Ok(());
    } else {
        let hello = expect_hello(&mut stream).map_err(|err| stage_error("agent hello", err))?;
        println!(
            "agent connected: platform={} arch={} runtime={} transport={}",
            hello.platform, hello.arch, hello.runtime, hello.transport
        );

        let ping =
            expect_eval_ok_json(&mut stream, &AgentCommand::Ping).map_err(|err| stage_error("agent ping", err))?;
        println!("agent ping => {}", ping);
        print_hook_environment_notice(&mut stream).map_err(|err| stage_error("agent hook environment query", err))?;

        if let Some(script) = script {
            let init_result = expect_eval_ok_json(&mut stream, &AgentCommand::JsInit)
                .map_err(|err| stage_error("agent jsinit", err))?;
            if !init_result.trim().is_empty() {
                print_reply_payload("jsinit", init_result.trim());
            }

            let load_result = expect_eval_ok_json(&mut stream, &AgentCommand::LoadJs { script: script.clone() })
                .map_err(|err| stage_error("agent loadjs", err))?;
            if !load_result.trim().is_empty() {
                print_reply_payload("loadjs", load_result.trim());
            }
        }
    }

    if let Some(command) = config.command.as_deref() {
        run_single_command(&mut stream, command, &injection_environment, &preflight)?;
        let _ = send_command_json(&mut stream, &AgentCommand::Exit);
        println!(
            "controller completed injection for pid {} using {}::{}",
            pid, config.agent_path, config.entry_symbol
        );
        return Ok(());
    }

    if io::stdin().is_terminal() {
        println!("interactive controller ready; type `help` for commands");
        run_controller_repl(&mut stream, &injection_environment, &preflight)?;
    } else {
        let _ = send_command_json(&mut stream, &AgentCommand::Exit);
    }

    println!(
        "controller completed injection for pid {} using {}::{}",
        pid, config.agent_path, config.entry_symbol
    );
    Ok(())
}

#[cfg(unix)]
fn print_injection_environment(report: &InjectionEnvironmentReport) {
    for line in render_injection_environment(report) {
        println!("{line}");
    }
}

#[cfg(unix)]
fn print_doctor_report(report: &DoctorReport) {
    println!(
        "doctor: ready={} warnings={} failures={}",
        report.ready, report.warning_count, report.failure_count
    );
    for check in &report.checks {
        println!(" - [{}] {}: {}", check.status, check.id, check.summary);
        if let Some(detail) = &check.detail {
            println!("   detail: {detail}");
        }
    }
}

#[cfg(unix)]
fn print_injection_preflight(report: &InjectionTargetPreflightReport) {
    let main_image = report
        .main_image
        .as_ref()
        .map(|image| format!("{}@0x{:x}", image.name, image.base))
        .unwrap_or_else(|| "<unknown>".into());
    println!("target images: count={} main={}", report.target_image_count, main_image);
    for image in report.target_images.iter().take(5) {
        println!(
            "target image: base=0x{:x} slide={} {}",
            image.base,
            if image.slide < 0 {
                format!("-0x{:x}", image.slide.unsigned_abs())
            } else {
                format!("0x{:x}", image.slide as usize)
            },
            image.name
        );
    }
    if report.target_images.len() > 5 {
        println!("target images: {} more not shown", report.target_images.len() - 5);
    }
    let loader_symbol_checks = loader_symbol_checks_to_json(&report.resolved_loader_symbols, &report.target_images);
    println!(
        "loader symbol checks: total={} image_found={} address_match={}",
        loader_symbol_checks["total"].as_u64().unwrap_or(0),
        loader_symbol_checks["imageFoundCount"].as_u64().unwrap_or(0),
        loader_symbol_checks["addressMatchCount"].as_u64().unwrap_or(0)
    );
    if !loader_symbol_checks["allAddressesMatch"].as_bool().unwrap_or(false) {
        for check in loader_symbol_checks["checks"].as_array().into_iter().flatten() {
            if !check["addressMatchesExpected"].as_bool().unwrap_or(false) {
                println!(
                    "loader symbol mismatch: {} expected={} actual={}",
                    check["symbolName"].as_str().unwrap_or("<unknown>"),
                    check["expectedAddressHex"].as_str().unwrap_or("<none>"),
                    check["addressHex"].as_str().unwrap_or("<none>")
                );
            }
        }
    }
    println!(
        "injection preflight: arm64e={} thread_bootstrap_kind={} thread_bootstrap={} address=0x{:x} raw=0x{:x} canonicalized={}",
        report
            .target_uses_arm64e
            .map(|value| value.to_string())
            .unwrap_or_else(|| "unknown".into()),
        report.thread_bootstrap_kind.as_str(),
        report.thread_bootstrap_label,
        report.thread_bootstrap_address,
        report.thread_bootstrap_raw_address,
        report.thread_bootstrap_canonicalized
    );
    println!(
        "target hook strategy: policy={} strategy={} command_mode={} allowed={} inline_hooks_allowed={} query_commands_allowed={} hook_install_commands_allowed={} hook_status_commands_allowed={} hook_stop_commands_allowed={}",
        report.target_hook_strategy.policy.as_str(),
        report.target_hook_strategy.strategy,
        report.target_hook_strategy.command_mode(),
        report.target_hook_strategy.allowed,
        report.target_hook_strategy.inline_hooks_allowed,
        report.target_hook_strategy.query_commands_allowed(),
        report.target_hook_strategy.hook_install_commands_allowed(),
        report.target_hook_strategy.hook_status_commands_allowed(),
        report.target_hook_strategy.hook_stop_commands_allowed()
    );
    if let Some(reason) = &report.target_hook_strategy.reason {
        println!("target hook strategy reason: {reason}");
    }
    let active_backend = report
        .target_hook_environment
        .active_backend
        .as_deref()
        .unwrap_or("<none>");
    println!(
        "target hook backends: active={} conflict_state={} loaded_backends={} filesystem_only_backends={} loaded_images={} filesystem_paths={}",
        active_backend,
        report.target_hook_environment.conflict_state(),
        report.target_hook_environment.loaded_backend_count(),
        report.target_hook_environment.filesystem_only_backend_count(),
        report.target_hook_environment.loaded_image_count(),
        report.target_hook_environment.filesystem_path_count()
    );
    for backend in &report.target_hook_environment.backends {
        println!(
            " - {} ({}) loaded={} filesystem={}",
            backend.id,
            backend.display_name,
            backend.loaded_images.len(),
            backend.filesystem_paths.len()
        );
    }
    for warning in &report.target_hook_environment.warnings {
        println!("target hook warning: {warning}");
    }
    for recommendation in
        hook_environment_recommendations(&report.target_hook_environment, Some(&report.target_hook_strategy))
    {
        println!("target hook advice: {recommendation}");
    }
}

#[cfg(unix)]
fn render_injection_environment(report: &InjectionEnvironmentReport) -> Vec<String> {
    let bootstrap_wait = report
        .bootstrap_wait_ms
        .map(|value| format!("{value}ms"))
        .unwrap_or_else(|| "disabled".into());
    let mut lines = vec![format!(
        "injection environment: dry_run={} bootstrap_wait={} hook_policy={} strategy={} command_mode={} allowed={} inline_hooks_allowed={} query_commands_allowed={} hook_install_commands_allowed={} hook_status_commands_allowed={} hook_stop_commands_allowed={}",
        report.dry_run,
        bootstrap_wait,
        report.hook_policy.as_str(),
        report.hook_strategy.strategy,
        report.hook_strategy.command_mode(),
        report.hook_strategy.allowed,
        report.hook_strategy.inline_hooks_allowed,
        report.hook_strategy.query_commands_allowed(),
        report.hook_strategy.hook_install_commands_allowed(),
        report.hook_strategy.hook_status_commands_allowed(),
        report.hook_strategy.hook_stop_commands_allowed()
    )];
    if let Some(reason) = &report.hook_strategy.reason {
        lines.push(format!("hook strategy reason: {reason}"));
    }

    let active_backend = report.hook_environment.active_backend.as_deref().unwrap_or("<none>");
    lines.push(format!(
        "hook backends: active={} conflict_state={} loaded_backends={} filesystem_only_backends={} loaded_images={} filesystem_paths={}",
        active_backend,
        report.hook_environment.conflict_state(),
        report.hook_environment.loaded_backend_count(),
        report.hook_environment.filesystem_only_backend_count(),
        report.hook_environment.loaded_image_count(),
        report.hook_environment.filesystem_path_count()
    ));
    for backend in &report.hook_environment.backends {
        lines.push(format!(
            " - {} ({}) loaded={} filesystem={}",
            backend.id,
            backend.display_name,
            backend.loaded_images.len(),
            backend.filesystem_paths.len()
        ));
    }
    for warning in &report.hook_environment.warnings {
        lines.push(format!("hook warning: {warning}"));
    }
    for recommendation in hook_environment_recommendations(&report.hook_environment, Some(&report.hook_strategy)) {
        lines.push(format!("hook advice: {recommendation}"));
    }
    lines
}

#[cfg(unix)]
fn print_injection_trace(trace: &InjectionTrace) {
    println!(
        "remote bootstrap: code=0x{:x}/{} alloc={} protect={} data=0x{:x}/{} alloc={} protect={} stack=0x{:x}/{} arm64e={} thread_bootstrap_kind={} thread_bootstrap={} flavor={} count={} pc=0x{:x} sp=0x{:x} x2=0x{:x} x3=0x{:x}",
        trace.payload_address,
        trace.payload_size,
        trace.payload_allocated_size,
        trace.code_protection.as_str(),
        trace.data_address,
        trace.data_size,
        trace.data_allocated_size,
        trace.data_protection.as_str(),
        trace.stack_address,
        trace.stack_size,
        trace
            .target_uses_arm64e
            .map(|value| value.to_string())
            .unwrap_or_else(|| "unknown".into()),
        trace.thread_bootstrap_kind.as_str(),
        trace.thread_bootstrap_label,
        trace.thread_plan.flavor,
        trace.thread_plan.count,
        trace.thread_plan.state.pc,
        trace.thread_plan.state.sp,
        trace.thread_plan.state.x[2],
        trace.thread_plan.state.x[3]
    );

    if let Some(thread_port) = trace.thread_port {
        println!(
            "remote thread: port={} termination={} deallocated={} resources_persist={}",
            thread_port,
            trace.thread_termination.as_str(),
            trace.thread_port_deallocated,
            trace.resources_persist
        );
    }

    if let Some(report) = trace.bootstrap_report {
        println!(
            "bootstrap report: status={} raw={} dylib_handle=0x{:x} entry=0x{:x} socket_fd={} entry_return={}",
            report.status.as_str(),
            report.status_raw,
            report.dylib_handle,
            report.entry_address,
            report.socket_fd,
            report.entry_return
        );
        if let Some(hint) = report.status.diagnostic_hint() {
            println!("bootstrap hint: {hint}");
        }

        if trace.bootstrap_timed_out && matches!(report.status, BootstrapStatus::Pending) {
            println!("bootstrap report: timed out while waiting for remote status transition");
        }
    } else if trace.bootstrap_timed_out {
        println!("bootstrap report: timed out before any remote status was available");
    }
}

#[cfg(unix)]
fn render_bootstrap_summary(trace: &InjectionTrace) -> String {
    match trace.bootstrap_report {
        Some(report) => format!(
            "status={} raw={} dylib_handle=0x{:x} entry=0x{:x} socket_fd={} entry_return={} hint={} timed_out={} thread_termination={} resources_persist={} arm64e={} code=0x{:x}/{} alloc={} protect={} data=0x{:x}/{} alloc={} protect={} stack=0x{:x}/{} thread_bootstrap_kind={} thread_bootstrap={} pc=0x{:x} sp=0x{:x} x2=0x{:x} x3=0x{:x}",
            report.status.as_str(),
            report.status_raw,
            report.dylib_handle,
            report.entry_address,
            report.socket_fd,
            report.entry_return,
            report.status.diagnostic_hint().unwrap_or("<none>"),
            trace.bootstrap_timed_out,
            trace.thread_termination.as_str(),
            trace.resources_persist,
            trace
                .target_uses_arm64e
                .map(|value| value.to_string())
                .unwrap_or_else(|| "unknown".into()),
            trace.payload_address,
            trace.payload_size,
            trace.payload_allocated_size,
            trace.code_protection.as_str(),
            trace.data_address,
            trace.data_size,
            trace.data_allocated_size,
            trace.data_protection.as_str(),
            trace.stack_address,
            trace.stack_size,
            trace.thread_bootstrap_kind.as_str(),
            trace.thread_bootstrap_label,
            trace.thread_plan.state.pc,
            trace.thread_plan.state.sp,
            trace.thread_plan.state.x[2],
            trace.thread_plan.state.x[3]
        ),
        None => format!(
            "status=<unavailable> timed_out={} thread_termination={} resources_persist={} arm64e={} code=0x{:x}/{} alloc={} protect={} data=0x{:x}/{} alloc={} protect={} stack=0x{:x}/{} thread_bootstrap_kind={} thread_bootstrap={} pc=0x{:x} sp=0x{:x} x2=0x{:x} x3=0x{:x}",
            trace.bootstrap_timed_out,
            trace.thread_termination.as_str(),
            trace.resources_persist,
            trace
                .target_uses_arm64e
                .map(|value| value.to_string())
                .unwrap_or_else(|| "unknown".into()),
            trace.payload_address,
            trace.payload_size,
            trace.payload_allocated_size,
            trace.code_protection.as_str(),
            trace.data_address,
            trace.data_size,
            trace.data_allocated_size,
            trace.data_protection.as_str(),
            trace.stack_address,
            trace.stack_size,
            trace.thread_bootstrap_kind.as_str(),
            trace.thread_bootstrap_label,
            trace.thread_plan.state.pc,
            trace.thread_plan.state.sp,
            trace.thread_plan.state.x[2],
            trace.thread_plan.state.x[3]
        ),
    }
}

#[cfg(not(unix))]
pub fn run_controller(_config: &ControllerConfig, _list_images: bool) -> Result<()> {
    Err(Error::Unsupported(
        "controller transport currently expects Unix domain sockets".into(),
    ))
}

#[cfg(unix)]
fn resolve_socket_path(config: &ControllerConfig, pid: i32) -> Result<PathBuf> {
    let path = if let Some(socket_path) = &config.socket_path {
        let path = PathBuf::from(socket_path);
        if path.is_absolute() {
            path
        } else {
            std::env::current_dir()?.join(path)
        }
    } else {
        PathBuf::from(default_socket_path(pid))
    };
    Ok(path)
}

#[cfg(unix)]
fn validate_socket_path(path: &Path) -> Result<()> {
    let path = path.to_string_lossy();
    if path.trim().is_empty() {
        return Err(Error::InvalidArgument("socket path must not be empty".into()));
    }
    if path.len() > DARWIN_SOCKADDR_UN_PATH_MAX {
        return Err(Error::InvalidArgument(format!(
            "socket path exceeds Darwin sockaddr_un limit ({} > {})",
            path.len(),
            DARWIN_SOCKADDR_UN_PATH_MAX
        )));
    }
    Ok(())
}

#[cfg(unix)]
fn default_socket_path(pid: i32) -> String {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;
    format!("/tmp/iosrf-{:x}-{:x}.sock", pid.max(0) as u32, stamp)
}

#[cfg(unix)]
fn remove_socket_file_if_present(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err.into()),
    }
}

#[cfg(unix)]
fn send_command(stream: &mut UnixStream, command: &str) -> Result<()> {
    write_frame(stream, FRAME_KIND_CMD, command.as_bytes())
}

#[cfg(unix)]
fn send_command_json(stream: &mut UnixStream, command: &AgentCommand) -> Result<()> {
    write_frame(stream, FRAME_KIND_CMD_JSON, &command.encode()?)
}

#[cfg(unix)]
fn expect_hello(stream: &mut UnixStream) -> Result<Hello> {
    match read_agent_event(stream, "waiting for agent hello")? {
        AgentEvent::Hello(hello) => Ok(hello),
        other => Err(Error::Protocol(format!(
            "expected HELLO frame, received {}",
            event_name(&other)
        ))),
    }
}

#[cfg(unix)]
fn wait_for_log_reply_with_logs(stream: &mut UnixStream, mut log_sink: Option<&mut Vec<String>>) -> Result<String> {
    loop {
        match read_agent_event(stream, "waiting for agent log reply")? {
            AgentEvent::Hello(_) => {}
            AgentEvent::Log(line) => {
                if let Some(sink) = log_sink.as_deref_mut() {
                    sink.push(line.clone());
                }
                return Ok(line);
            }
            AgentEvent::EvalOk(payload) => return Ok(payload),
            AgentEvent::EvalErr(payload) => return Err(Error::State(format!("agent command failed: {payload}"))),
            AgentEvent::Complete(_) => {}
        }
    }
}

#[cfg(unix)]
fn send_eval_command_with_logs(
    stream: &mut UnixStream,
    command: &str,
    log_sink: Option<&mut Vec<String>>,
) -> Result<EvalReply> {
    send_command(stream, command)?;
    read_eval_reply_with_logs(stream, log_sink)
}

#[cfg(unix)]
fn send_eval_command_json(stream: &mut UnixStream, command: &AgentCommand) -> Result<EvalReply> {
    send_eval_command_json_with_logs(stream, command, None)
}

#[cfg(unix)]
fn send_eval_command_json_with_logs(
    stream: &mut UnixStream,
    command: &AgentCommand,
    log_sink: Option<&mut Vec<String>>,
) -> Result<EvalReply> {
    send_command_json(stream, command)?;
    read_eval_reply_with_logs(stream, log_sink)
}

#[cfg(unix)]
fn read_eval_reply_with_logs(stream: &mut UnixStream, mut log_sink: Option<&mut Vec<String>>) -> Result<EvalReply> {
    loop {
        match read_agent_event(stream, "waiting for agent eval reply")? {
            AgentEvent::Hello(_) => {}
            AgentEvent::Log(line) => {
                if let Some(sink) = log_sink.as_deref_mut() {
                    sink.push(line);
                } else {
                    println!("[agent] {}", line);
                }
            }
            AgentEvent::EvalOk(payload) => return Ok(EvalReply::Ok(payload)),
            AgentEvent::EvalErr(payload) => return Ok(EvalReply::Err(payload)),
            AgentEvent::Complete(_) => {}
        }
    }
}

fn expect_eval_ok_json(stream: &mut UnixStream, command: &AgentCommand) -> Result<String> {
    expect_eval_ok_json_with_logs(stream, command, None)
}

#[cfg(unix)]
fn expect_eval_ok_json_with_logs(
    stream: &mut UnixStream,
    command: &AgentCommand,
    log_sink: Option<&mut Vec<String>>,
) -> Result<String> {
    send_command_json(stream, command)?;
    match read_eval_reply_with_logs(stream, log_sink)? {
        EvalReply::Ok(payload) => Ok(payload),
        EvalReply::Err(payload) => Err(Error::State(format!("agent command failed: {payload}"))),
    }
}

#[cfg(unix)]
fn print_hook_environment_notice(stream: &mut UnixStream) -> Result<()> {
    let Some(payload) = fetch_hook_environment_notice(stream, None)? else {
        return Ok(());
    };
    println!("hook environment:");
    for line in payload.lines() {
        println!("  {line}");
    }
    Ok(())
}

#[cfg(unix)]
fn fetch_hook_environment_notice(
    stream: &mut UnixStream,
    log_sink: Option<&mut Vec<String>>,
) -> Result<Option<String>> {
    let payload = expect_eval_ok_json_with_logs(
        stream,
        &AgentCommand::from_legacy("native.hookenv").expect("native.hookenv legacy spec"),
        log_sink,
    )?;
    if !hook_environment_requires_notice(&payload) {
        return Ok(None);
    }
    Ok(Some(payload))
}

#[cfg(unix)]
fn hook_environment_requires_notice(payload: &str) -> bool {
    let trimmed = payload.trim();
    if trimmed.is_empty() {
        return false;
    }
    let mut active_backend = "<none>";
    let mut has_actionable_lines = false;
    for line in trimmed.lines() {
        let line = line.trim();
        if let Some(value) = line.strip_prefix("active=") {
            active_backend = value.trim();
            continue;
        }
        if line.starts_with("backend ")
            || line.starts_with("warning ")
            || line.starts_with("advice ")
            || line.starts_with("reason=")
        {
            has_actionable_lines = true;
        }
    }
    active_backend != "<none>" || has_actionable_lines
}

fn send_complete_command_json_with_logs(
    stream: &mut UnixStream,
    command: &AgentCommand,
    label: &str,
    log_sink: Option<&mut Vec<String>>,
) -> Result<Vec<String>> {
    send_command_json(stream, command)?;
    read_complete_reply_with_logs(stream, label, log_sink)
}

fn read_complete_reply_with_logs(
    stream: &mut UnixStream,
    label: &str,
    mut log_sink: Option<&mut Vec<String>>,
) -> Result<Vec<String>> {
    loop {
        match read_agent_event(stream, "waiting for agent completion reply")? {
            AgentEvent::Hello(_) => {}
            AgentEvent::Log(line) => {
                if let Some(sink) = log_sink.as_deref_mut() {
                    sink.push(line);
                } else {
                    println!("[agent] {}", line);
                }
            }
            AgentEvent::Complete(items) => return Ok(items),
            AgentEvent::EvalOk(payload) => {
                return Err(Error::Protocol(format!(
                    "expected COMPLETE reply for `{label}`, received EVAL_OK: {payload}"
                )))
            }
            AgentEvent::EvalErr(payload) => return Err(Error::State(format!("agent command failed: {payload}"))),
        }
    }
}

#[cfg(unix)]
fn run_controller_repl(
    stream: &mut UnixStream,
    injection_environment: &InjectionEnvironmentReport,
    preflight: &InjectionTargetPreflightReport,
) -> Result<()> {
    print_controller_help();

    loop {
        let Some(line) = read_prompt_line(CONTROLLER_PROMPT)? else {
            let _ = send_command_json(stream, &AgentCommand::Exit);
            println!("leaving controller repl");
            return Ok(());
        };
        let command = line.trim();
        if command.is_empty() {
            continue;
        }

        match command {
            "help" => print_controller_help(),
            "quit" | "exit" => {
                if let Ok(reply) = send_log_request_json(stream, &AgentCommand::Exit) {
                    println!("{reply}");
                }
                return Ok(());
            }
            "jsrepl" => run_js_repl(stream)?,
            _ => run_single_command(stream, command, injection_environment, preflight)?,
        }
    }
}

#[cfg(unix)]
fn run_js_repl(stream: &mut UnixStream) -> Result<()> {
    let _ = expect_eval_ok_json(stream, &AgentCommand::JsInit)?;
    println!("entered js repl; each line is sent as `loadjs <line>`; `exit` returns to controller");

    loop {
        let Some(line) = read_prompt_line(JS_PROMPT)? else {
            println!("leaving js repl");
            return Ok(());
        };
        let script = line.trim();
        if script.is_empty() {
            continue;
        }
        if matches!(script, "exit" | "quit") {
            println!("leaving js repl");
            return Ok(());
        }

        match send_eval_command_json(stream, &AgentCommand::LoadJs { script: script.into() })? {
            EvalReply::Ok(payload) => print_eval_payload(&payload),
            EvalReply::Err(payload) => println!("[JS error] {payload}"),
        }
    }
}

#[cfg(unix)]
fn run_single_command(
    stream: &mut UnixStream,
    command: &str,
    injection_environment: &InjectionEnvironmentReport,
    preflight: &InjectionTargetPreflightReport,
) -> Result<()> {
    let outcome = execute_single_command(stream, command, false, injection_environment, preflight)?;
    print_command_outcome(&outcome);
    Ok(())
}

#[cfg(unix)]
fn execute_single_command(
    stream: &mut UnixStream,
    command: &str,
    capture_logs: bool,
    injection_environment: &InjectionEnvironmentReport,
    preflight: &InjectionTargetPreflightReport,
) -> Result<CommandOutcome> {
    match command {
        "help" => {
            return Err(Error::InvalidArgument(
                "`help` is only available in interactive controller mode".into(),
            ))
        }
        "jsrepl" => {
            return Err(Error::InvalidArgument(
                "`jsrepl` is interactive-only; use `--command 'jseval ...'` or REPL mode".into(),
            ))
        }
        _ => {}
    }

    ensure_inline_hooks_allowed_for_command(command, injection_environment, preflight)?;

    if is_stalker_command(command) {
        return execute_stalker_command(stream, command, capture_logs);
    }
    if is_trace_command(command) {
        return execute_trace_command(stream, command, capture_logs);
    }
    if is_jhook_command(command) {
        return execute_jhook_command(stream, command, capture_logs);
    }
    if is_shook_command(command) {
        return execute_shook_command(stream, command, capture_logs);
    }
    if is_hfl_command(command) {
        return execute_hfl_command(stream, command, capture_logs);
    }
    if is_log_command(command) {
        let mut logs = Vec::new();
        let payload = send_log_request_json_with_logs(
            stream,
            &AgentCommand::Exit,
            if capture_logs { Some(&mut logs) } else { None },
        )?;
        return Ok(CommandOutcome::log(command, payload, logs));
    }
    if is_complete_command(command) {
        let mut logs = Vec::new();
        let prefix = command.strip_prefix("jscomplete ").unwrap_or_default().to_string();
        let items = send_complete_command_json_with_logs(
            stream,
            &AgentCommand::JsComplete { prefix },
            command,
            if capture_logs { Some(&mut logs) } else { None },
        )?;
        return Ok(CommandOutcome::complete(command, items, logs));
    }

    if let Some(spec) = AgentCommand::from_legacy(command) {
        let mut logs = Vec::new();
        let command_spec = match (capture_logs, spec) {
            (true, AgentCommand::RuntimeDispatch { spec }) => AgentCommand::RuntimeDispatchResult { spec },
            (_, other) => other,
        };
        let reply =
            send_eval_command_json_with_logs(stream, &command_spec, if capture_logs { Some(&mut logs) } else { None })?;
        return Ok(CommandOutcome::eval(command, reply, logs));
    }

    let mut logs = Vec::new();
    let reply = send_eval_command_with_logs(stream, command, if capture_logs { Some(&mut logs) } else { None })?;
    Ok(CommandOutcome::eval(command, reply, logs))
}

fn send_log_request_json(stream: &mut UnixStream, command: &AgentCommand) -> Result<String> {
    send_log_request_json_with_logs(stream, command, None)
}

#[cfg(unix)]
fn send_log_request_json_with_logs(
    stream: &mut UnixStream,
    command: &AgentCommand,
    log_sink: Option<&mut Vec<String>>,
) -> Result<String> {
    send_command_json(stream, command)?;
    wait_for_log_reply_with_logs(stream, log_sink)
}

#[cfg(unix)]
fn is_log_command(command: &str) -> bool {
    matches!(command, "exit")
}

#[cfg(unix)]
fn is_complete_command(command: &str) -> bool {
    command.strip_prefix("jscomplete ").is_some()
}

#[cfg(unix)]
fn is_stalker_command(command: &str) -> bool {
    matches!(command.split_whitespace().next(), Some("stalker"))
}

#[cfg(unix)]
fn is_trace_command(command: &str) -> bool {
    matches!(command.split_whitespace().next(), Some("trace"))
}

#[cfg(unix)]
fn is_hfl_command(command: &str) -> bool {
    matches!(command.split_whitespace().next(), Some("hfl"))
}

#[cfg(unix)]
fn is_jhook_command(command: &str) -> bool {
    matches!(command.split_whitespace().next(), Some("jhook"))
}

#[cfg(unix)]
fn is_shook_command(command: &str) -> bool {
    matches!(command.split_whitespace().next(), Some("shook"))
}

#[cfg(unix)]
fn command_requires_inline_hooks(command: &str) -> bool {
    is_stalker_command(command)
        || is_trace_command(command)
        || is_jhook_command(command)
        || is_shook_command(command)
        || is_hfl_command(command)
}

#[cfg(unix)]
fn command_requests_inline_hook_install(command: &str) -> Result<bool> {
    if is_stalker_command(command) {
        return Ok(matches!(
            parse_stalker_command(command)?,
            StalkerCommand::InstallObjc { .. } | StalkerCommand::InstallNative { .. }
        ));
    }
    if is_trace_command(command) {
        return Ok(matches!(
            parse_trace_command(command)?,
            TraceCommand::InstallObjc { .. } | TraceCommand::InstallNative { .. }
        ));
    }
    if is_jhook_command(command) {
        return Ok(matches!(parse_jhook_command(command)?, ObjcHookCommand::Install(_)));
    }
    if is_shook_command(command) {
        return Ok(matches!(
            parse_shook_command(command)?,
            SwiftHookCommand::Install { .. }
        ));
    }
    if is_hfl_command(command) {
        return Ok(matches!(parse_hfl_command(command)?, HflCommand::Install { .. }));
    }
    Ok(false)
}

#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HookCommandCapability {
    Query,
    HookInstall,
    HookStatus,
    HookStop,
}

#[cfg(unix)]
impl HookCommandCapability {
    fn display_name(self) -> &'static str {
        match self {
            HookCommandCapability::Query => "query",
            HookCommandCapability::HookInstall => "hook-install",
            HookCommandCapability::HookStatus => "hook-status",
            HookCommandCapability::HookStop => "hook-stop",
        }
    }

    fn action_key(self) -> &'static str {
        match self {
            HookCommandCapability::Query => "hook.query",
            HookCommandCapability::HookInstall => "hook.install",
            HookCommandCapability::HookStatus => "hook.status",
            HookCommandCapability::HookStop => "hook.stop",
        }
    }
}

#[cfg(unix)]
fn command_required_capability(command: &str) -> Result<Option<HookCommandCapability>> {
    if is_log_command(command) || is_complete_command(command) {
        return Ok(None);
    }

    if is_stalker_command(command) {
        return Ok(Some(match parse_stalker_command(command)? {
            StalkerCommand::InstallObjc { .. } | StalkerCommand::InstallNative { .. } => {
                HookCommandCapability::HookInstall
            }
            StalkerCommand::Status => HookCommandCapability::HookStatus,
            StalkerCommand::StopAll | StalkerCommand::StopObjc { .. } | StalkerCommand::StopNative { .. } => {
                HookCommandCapability::HookStop
            }
        }));
    }
    if is_trace_command(command) {
        return Ok(Some(match parse_trace_command(command)? {
            TraceCommand::InstallObjc { .. } | TraceCommand::InstallNative { .. } => HookCommandCapability::HookInstall,
            TraceCommand::Status => HookCommandCapability::HookStatus,
            TraceCommand::StopAll | TraceCommand::StopObjc { .. } | TraceCommand::StopNative { .. } => {
                HookCommandCapability::HookStop
            }
        }));
    }
    if is_jhook_command(command) {
        return Ok(Some(match parse_jhook_command(command)? {
            ObjcHookCommand::Install(_) => HookCommandCapability::HookInstall,
            ObjcHookCommand::Status => HookCommandCapability::HookStatus,
            ObjcHookCommand::StopAll | ObjcHookCommand::Stop(_) => HookCommandCapability::HookStop,
        }));
    }
    if is_shook_command(command) {
        return Ok(Some(match parse_shook_command(command)? {
            SwiftHookCommand::Install { .. } => HookCommandCapability::HookInstall,
            SwiftHookCommand::Status => HookCommandCapability::HookStatus,
            SwiftHookCommand::StopAll | SwiftHookCommand::Stop { .. } => HookCommandCapability::HookStop,
        }));
    }
    if is_hfl_command(command) {
        return Ok(Some(match parse_hfl_command(command)? {
            HflCommand::Install { .. } => HookCommandCapability::HookInstall,
            HflCommand::Status => HookCommandCapability::HookStatus,
            HflCommand::StopAll | HflCommand::Stop { .. } => HookCommandCapability::HookStop,
        }));
    }

    Ok(Some(HookCommandCapability::Query))
}

#[cfg(unix)]
fn hook_strategy_allows_capability(
    strategy: &native_api::HookStrategyDecision,
    capability: HookCommandCapability,
) -> bool {
    match capability {
        HookCommandCapability::Query => strategy.query_commands_allowed(),
        HookCommandCapability::HookInstall => strategy.hook_install_commands_allowed(),
        HookCommandCapability::HookStatus => strategy.hook_status_commands_allowed(),
        HookCommandCapability::HookStop => strategy.hook_stop_commands_allowed(),
    }
}

#[cfg(unix)]
fn ensure_inline_hooks_allowed_for_command(
    command: &str,
    injection_environment: &InjectionEnvironmentReport,
    preflight: &InjectionTargetPreflightReport,
) -> Result<()> {
    let Some(capability) = command_required_capability(command)? else {
        return Ok(());
    };

    let controller_actions = hook_environment_recommended_actions(
        &injection_environment.hook_environment,
        Some(&injection_environment.hook_strategy),
    );
    let target_actions =
        hook_environment_recommended_actions(&preflight.target_hook_environment, Some(&preflight.target_hook_strategy));
    let effective_actions = hook_effective_actions(&controller_actions, &target_actions);
    let action_key = capability.action_key();
    let effective_action = effective_actions
        .iter()
        .find(|item| item.action_key == action_key)
        .cloned()
        .unwrap_or_else(|| {
            let controller_allowed = hook_strategy_allows_capability(&injection_environment.hook_strategy, capability);
            let target_allowed = hook_strategy_allows_capability(&preflight.target_hook_strategy, capability);
            let blocked_by = match (controller_allowed, target_allowed) {
                (true, true) => "none",
                (false, true) => "controller",
                (true, false) => "target",
                (false, false) => "both",
            };
            HookEffectiveAction {
                action_key,
                command_group: capability.display_name(),
                allowed: controller_allowed && target_allowed,
                blocked_by,
                priority: 0,
                controller_allowed,
                target_allowed,
                controller_priority: 0,
                target_priority: 0,
                recommendation: "allowed under current hook policies".into(),
                controller_reason: injection_environment.hook_strategy.reason.clone(),
                target_reason: preflight.target_hook_strategy.reason.clone(),
            }
        });
    if effective_action.allowed {
        return Ok(());
    }

    let reason = match capability {
        HookCommandCapability::HookInstall => {
            format!("`{command}` requires inline hooks, but the current hook policy forbids hook-install commands")
        }
        HookCommandCapability::HookStatus => {
            format!("`{command}` is a hook status command, but the current hook policy forbids hook-status commands")
        }
        HookCommandCapability::HookStop => {
            format!("`{command}` is a hook stop command, but the current hook policy forbids hook-stop commands")
        }
        HookCommandCapability::Query => {
            format!("`{command}` is a runtime query command, but the current hook policy forbids query commands")
        }
    };

    let mut blocked_details = Vec::new();
    if !effective_action.controller_allowed {
        let controller_reason = effective_action.controller_reason.clone().unwrap_or_else(|| {
            format!("controller hook strategy disables `{}` commands", capability.display_name())
        });
        blocked_details.push(format!(
            "controller policy={} strategy={}: {}",
            injection_environment.hook_strategy.policy.as_str(),
            injection_environment.hook_strategy.strategy,
            controller_reason
        ));
    }
    if !effective_action.target_allowed {
        let target_reason = effective_action
            .target_reason
            .clone()
            .unwrap_or_else(|| format!("target hook strategy disables `{}` commands", capability.display_name()));
        blocked_details.push(format!(
            "target policy={} strategy={}: {}",
            preflight.target_hook_strategy.policy.as_str(),
            preflight.target_hook_strategy.strategy,
            target_reason
        ));
    }

    let base_command_mode = hook_effective_command_mode(&effective_actions);
    let backend_matrix =
        hook_backend_matrix_to_json(&injection_environment.hook_environment, &preflight.target_hook_environment);
    let loaded_in_controller_count = json_u64_field(&backend_matrix, "loadedInControllerCount");
    let loaded_in_target_count = json_u64_field(&backend_matrix, "loadedInTargetCount");
    let loaded_in_both_count = json_u64_field(&backend_matrix, "loadedInBothCount");
    let (effective_command_mode, auto_downgraded_to_query_only, auto_downgrade_reason) =
        hook_command_mode_with_backend_pressure(
            base_command_mode,
            loaded_in_controller_count,
            loaded_in_target_count,
            loaded_in_both_count,
        );
    let command_mode = effective_command_mode;
    let coexistence = hook_coexistence_to_json(&effective_actions, &backend_matrix);
    let coexistence_mode = coexistence
        .get("mode")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let backend_pressure = coexistence
        .get("backendPressure")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let fallback_action_key = coexistence
        .get("nextActionKey")
        .and_then(Value::as_str)
        .unwrap_or("<none>");
    let fallback_step_id = coexistence
        .get("nextStep")
        .and_then(|value| value.get("id"))
        .and_then(Value::as_str)
        .unwrap_or("<none>");
    let fallback_command = coexistence
        .get("nextActionTemplates")
        .and_then(Value::as_array)
        .and_then(|templates| templates.first())
        .and_then(Value::as_str)
        .unwrap_or("<none>");
    let fallback_phase = coexistence
        .get("nextActionCommandJsonTemplates")
        .and_then(Value::as_array)
        .and_then(|templates| templates.first())
        .and_then(|entry| entry.get("phase"))
        .and_then(Value::as_str)
        .unwrap_or("<none>");
    let auto_downgrade_reason = auto_downgrade_reason.unwrap_or("<none>");
    let detail_text = if blocked_details.is_empty() {
        effective_action.recommendation.clone()
    } else {
        blocked_details.join("; ")
    };
    Err(Error::State(format!(
        "{reason}: hook-effective-blocked actionKey={} commandGroup={} blockedBy={} commandMode={} baseCommandMode={} effectiveCommandMode={} autoDowngradedToQueryOnly={} autoDowngradeReason={} coexistenceMode={} backendPressure={} fallbackActionKey={} fallbackStepId={} fallbackCommand={} fallbackPhase={}; recommendation={}; {}",
        effective_action.action_key,
        effective_action.command_group,
        effective_action.blocked_by,
        command_mode,
        base_command_mode,
        effective_command_mode,
        auto_downgraded_to_query_only,
        auto_downgrade_reason,
        coexistence_mode,
        backend_pressure,
        fallback_action_key,
        fallback_step_id,
        fallback_command,
        fallback_phase,
        effective_action.recommendation,
        detail_text
    )))
}

#[cfg(unix)]
fn execute_stalker_command(stream: &mut UnixStream, command: &str, capture_logs: bool) -> Result<CommandOutcome> {
    let stalker_command = parse_stalker_command(command)?;
    let mut logs = Vec::new();
    let _ = expect_eval_ok_json_with_logs(
        stream,
        &AgentCommand::JsInit,
        if capture_logs { Some(&mut logs) } else { None },
    )?;

    let spec = build_stalker_spec(&stalker_command);
    let dispatch = if capture_logs {
        AgentCommand::ControllerDispatchResult { spec }
    } else {
        AgentCommand::ControllerDispatch { spec }
    };
    let reply = send_eval_command_json_with_logs(stream, &dispatch, if capture_logs { Some(&mut logs) } else { None })?;

    Ok(CommandOutcome::eval(command, reply, logs))
}

#[cfg(unix)]
fn execute_trace_command(stream: &mut UnixStream, command: &str, capture_logs: bool) -> Result<CommandOutcome> {
    let trace_command = parse_trace_command(command)?;
    let mut logs = Vec::new();
    let _ = expect_eval_ok_json_with_logs(
        stream,
        &AgentCommand::JsInit,
        if capture_logs { Some(&mut logs) } else { None },
    )?;

    let spec = build_trace_spec(&trace_command);
    let dispatch = if capture_logs {
        AgentCommand::ControllerDispatchResult { spec }
    } else {
        AgentCommand::ControllerDispatch { spec }
    };
    let reply = send_eval_command_json_with_logs(stream, &dispatch, if capture_logs { Some(&mut logs) } else { None })?;

    Ok(CommandOutcome::eval(command, reply, logs))
}

#[cfg(unix)]
fn execute_jhook_command(stream: &mut UnixStream, command: &str, capture_logs: bool) -> Result<CommandOutcome> {
    let spec = parse_jhook_command(command)?;
    let mut logs = Vec::new();
    let _ = expect_eval_ok_json_with_logs(
        stream,
        &AgentCommand::JsInit,
        if capture_logs { Some(&mut logs) } else { None },
    )?;

    let dispatch = build_jhook_spec(&spec);
    let dispatch_command = if capture_logs {
        AgentCommand::ControllerDispatchResult { spec: dispatch }
    } else {
        AgentCommand::ControllerDispatch { spec: dispatch }
    };
    let reply = send_eval_command_json_with_logs(
        stream,
        &dispatch_command,
        if capture_logs { Some(&mut logs) } else { None },
    )?;

    Ok(CommandOutcome::eval(command, reply, logs))
}

#[cfg(unix)]
fn execute_shook_command(stream: &mut UnixStream, command: &str, capture_logs: bool) -> Result<CommandOutcome> {
    let spec = parse_shook_command(command)?;
    let mut logs = Vec::new();
    let _ = expect_eval_ok_json_with_logs(
        stream,
        &AgentCommand::JsInit,
        if capture_logs { Some(&mut logs) } else { None },
    )?;

    let dispatch = build_shook_spec(&spec);
    let dispatch_command = if capture_logs {
        AgentCommand::ControllerDispatchResult { spec: dispatch }
    } else {
        AgentCommand::ControllerDispatch { spec: dispatch }
    };
    let reply = send_eval_command_json_with_logs(
        stream,
        &dispatch_command,
        if capture_logs { Some(&mut logs) } else { None },
    )?;

    Ok(CommandOutcome::eval(command, reply, logs))
}

#[cfg(unix)]
fn execute_hfl_command(stream: &mut UnixStream, command: &str, capture_logs: bool) -> Result<CommandOutcome> {
    let spec = parse_hfl_command(command)?;
    let mut logs = Vec::new();
    let _ = expect_eval_ok_json_with_logs(
        stream,
        &AgentCommand::JsInit,
        if capture_logs { Some(&mut logs) } else { None },
    )?;

    let dispatch = build_hfl_spec(&spec);
    let dispatch_command = if capture_logs {
        AgentCommand::ControllerDispatchResult { spec: dispatch }
    } else {
        AgentCommand::ControllerDispatch { spec: dispatch }
    };
    let reply = send_eval_command_json_with_logs(
        stream,
        &dispatch_command,
        if capture_logs { Some(&mut logs) } else { None },
    )?;

    Ok(CommandOutcome::eval(command, reply, logs))
}

#[cfg(unix)]
fn parse_hfl_command(command: &str) -> Result<HflCommand> {
    const USAGE: &str = "hfl usage: hfl <module> <offset>|hfl status|hfl stop|hfl stop <module> <offset>";
    let mut parts = command.split_whitespace();
    match parts.next() {
        Some("hfl") => {}
        _ => return Err(Error::InvalidArgument(USAGE.into())),
    }

    let rest = parts.collect::<Vec<_>>();
    if rest.is_empty() {
        return Err(Error::InvalidArgument(USAGE.into()));
    }
    if rest.len() == 1 && matches!(rest[0], "status" | "state" | "show") {
        return Ok(HflCommand::Status);
    }
    if rest.len() == 1 && matches!(rest[0], "stop" | "off" | "disable") {
        return Ok(HflCommand::StopAll);
    }
    if rest.len() == 3 && matches!(rest[0], "stop" | "off" | "disable") {
        return Ok(HflCommand::Stop {
            module_name: rest[1].to_string(),
            offset: parse_offset_value(rest[2])?,
        });
    }
    if rest.len() != 2 {
        return Err(Error::InvalidArgument(USAGE.into()));
    }

    let offset = parse_offset_value(rest[1])?;
    Ok(HflCommand::Install {
        module_name: rest[0].to_string(),
        offset,
    })
}

#[cfg(unix)]
fn parse_offset_value(raw: &str) -> Result<u64> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(Error::InvalidArgument("hfl offset must not be empty".into()));
    }

    let (digits, radix) = if let Some(hex) = trimmed.strip_prefix("0x").or_else(|| trimmed.strip_prefix("0X")) {
        (hex, 16)
    } else {
        (trimmed, 10)
    };

    u64::from_str_radix(digits, radix).map_err(|_| Error::InvalidArgument(format!("invalid hfl offset `{trimmed}`")))
}

#[cfg(unix)]
#[derive(Debug, Clone, PartialEq, Eq)]
enum TraceCommand {
    InstallObjc { filter: Option<String> },
    InstallNative { target: NativeHookTarget },
    Status,
    StopAll,
    StopObjc { filter: Option<String> },
    StopNative { target: NativeHookTarget },
}

#[cfg(unix)]
#[derive(Debug, Clone, PartialEq, Eq)]
enum StalkerCommand {
    InstallObjc { filter: Option<String> },
    InstallNative { target: NativeHookTarget },
    Status,
    StopAll,
    StopObjc { filter: Option<String> },
    StopNative { target: NativeHookTarget },
}

#[cfg(unix)]
#[derive(Debug, Clone, PartialEq, Eq)]
struct ObjcHookSpec {
    class_name: String,
    selector_name: String,
    is_class_method: bool,
}

#[cfg(unix)]
#[derive(Debug, Clone, PartialEq, Eq)]
enum ObjcHookCommand {
    Install(ObjcHookSpec),
    Status,
    StopAll,
    Stop(ObjcHookSpec),
}

#[cfg(unix)]
#[derive(Debug, Clone, PartialEq, Eq)]
enum HflCommand {
    Install { module_name: String, offset: u64 },
    Status,
    StopAll,
    Stop { module_name: String, offset: u64 },
}

#[cfg(unix)]
#[derive(Debug, Clone, PartialEq, Eq)]
enum SwiftHookCommand {
    Install {
        module_name: Option<String>,
        type_name: String,
        method_query: String,
    },
    Status,
    StopAll,
    Stop {
        module_name: Option<String>,
        type_name: String,
        method_query: String,
    },
}

#[cfg(unix)]
#[derive(Debug, Clone, PartialEq, Eq)]
enum NativeHookTarget {
    Export {
        module_name: Option<String>,
        symbol_name: String,
        log_template: Option<NativeLogTemplate>,
    },
    Address {
        address: u64,
        log_template: Option<NativeLogTemplate>,
    },
}

#[cfg(unix)]
#[derive(Debug, Clone, PartialEq, Eq)]
struct NativeLogTemplate {
    arguments: Vec<NativeLogArgument>,
    return_value: Option<NativeLogReturn>,
}

#[cfg(unix)]
#[derive(Debug, Clone, PartialEq, Eq)]
struct NativeLogArgument {
    label: String,
    kind: NativeValueFormat,
}

#[cfg(unix)]
#[derive(Debug, Clone, PartialEq, Eq)]
struct NativeLogReturn {
    label: String,
    kind: NativeValueFormat,
}

#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NativeValueFormat {
    Ptr,
    CString,
    Fd,
    OpenFlags,
    AccessMode,
    Mode,
    Int,
    Uint,
    Hex,
    Size,
    SSize,
}

#[cfg(unix)]
impl NativeHookTarget {
    fn log_template(&self) -> Option<&NativeLogTemplate> {
        match self {
            NativeHookTarget::Export { log_template, .. } | NativeHookTarget::Address { log_template, .. } => {
                log_template.as_ref()
            }
        }
    }
}

#[cfg(unix)]
impl NativeValueFormat {
    fn as_str(self) -> &'static str {
        match self {
            NativeValueFormat::Ptr => "ptr",
            NativeValueFormat::CString => "cstr",
            NativeValueFormat::Fd => "fd",
            NativeValueFormat::OpenFlags => "openflags",
            NativeValueFormat::AccessMode => "access",
            NativeValueFormat::Mode => "mode",
            NativeValueFormat::Int => "int",
            NativeValueFormat::Uint => "uint",
            NativeValueFormat::Hex => "hex",
            NativeValueFormat::Size => "size",
            NativeValueFormat::SSize => "ssize",
        }
    }
}

#[cfg(unix)]
fn parse_stalker_command(command: &str) -> Result<StalkerCommand> {
    let rest = command
        .strip_prefix("stalker")
        .ok_or_else(|| {
            Error::InvalidArgument(
                "stalker usage: stalker [filter]|stalker native [module] <symbol> [-- template]|stalker addr <address> [-- template]|stalker status|stalker stop|stalker stop [filter]|stalker stop native [module] <symbol>|stalker stop addr <address>"
                    .into(),
            )
        })?
        .trim();

    if rest.is_empty() {
        return Ok(StalkerCommand::InstallObjc { filter: None });
    }

    if matches!(rest, "status" | "state" | "show") {
        return Ok(StalkerCommand::Status);
    }

    if matches!(rest, "stop" | "off" | "disable") {
        return Ok(StalkerCommand::StopAll);
    }
    if let Some(stop_rest) = rest
        .strip_prefix("stop ")
        .or_else(|| rest.strip_prefix("off "))
        .or_else(|| rest.strip_prefix("disable "))
    {
        let stop_rest = stop_rest.trim();
        if let Some(native_rest) = stop_rest.strip_prefix("native ") {
            return Ok(StalkerCommand::StopNative {
                target: parse_native_target(native_rest)?,
            });
        }
        if let Some(addr_rest) = stop_rest.strip_prefix("addr ") {
            return Ok(StalkerCommand::StopNative {
                target: parse_native_address_target(addr_rest)?,
            });
        }
        return Ok(StalkerCommand::StopObjc {
            filter: if stop_rest.is_empty() {
                None
            } else {
                Some(stop_rest.to_string())
            },
        });
    }

    if let Some(native_rest) = rest.strip_prefix("native ") {
        return Ok(StalkerCommand::InstallNative {
            target: parse_native_target(native_rest)?,
        });
    }

    if let Some(addr_rest) = rest.strip_prefix("addr ") {
        return Ok(StalkerCommand::InstallNative {
            target: parse_native_address_target(addr_rest)?,
        });
    }

    Ok(StalkerCommand::InstallObjc {
        filter: Some(rest.to_string()),
    })
}

#[cfg(unix)]
fn parse_trace_command(command: &str) -> Result<TraceCommand> {
    let rest = command
        .strip_prefix("trace")
        .ok_or_else(|| {
            Error::InvalidArgument(
                "trace usage: trace [filter]|trace native [module] <symbol> [-- template]|trace addr <address> [-- template]|trace status|trace stop|trace stop [filter]|trace stop native [module] <symbol>|trace stop addr <address>".into(),
            )
        })?
        .trim();

    if rest.is_empty() {
        return Ok(TraceCommand::InstallObjc { filter: None });
    }

    if matches!(rest, "status" | "state" | "show") {
        return Ok(TraceCommand::Status);
    }

    if matches!(rest, "stop" | "off" | "disable") {
        return Ok(TraceCommand::StopAll);
    }
    if let Some(stop_rest) = rest
        .strip_prefix("stop ")
        .or_else(|| rest.strip_prefix("off "))
        .or_else(|| rest.strip_prefix("disable "))
    {
        let stop_rest = stop_rest.trim();
        if let Some(native_rest) = stop_rest.strip_prefix("native ") {
            return Ok(TraceCommand::StopNative {
                target: parse_native_target(native_rest)?,
            });
        }
        if let Some(addr_rest) = stop_rest.strip_prefix("addr ") {
            return Ok(TraceCommand::StopNative {
                target: parse_native_address_target(addr_rest)?,
            });
        }
        return Ok(TraceCommand::StopObjc {
            filter: if stop_rest.is_empty() {
                None
            } else {
                Some(stop_rest.to_string())
            },
        });
    }

    if let Some(native_rest) = rest.strip_prefix("native ") {
        return Ok(TraceCommand::InstallNative {
            target: parse_native_target(native_rest)?,
        });
    }

    if let Some(addr_rest) = rest.strip_prefix("addr ") {
        return Ok(TraceCommand::InstallNative {
            target: parse_native_address_target(addr_rest)?,
        });
    }

    Ok(TraceCommand::InstallObjc {
        filter: Some(rest.to_string()),
    })
}

#[cfg(unix)]
fn parse_native_target(raw: &str) -> Result<NativeHookTarget> {
    let (target_part, template_part) = split_native_template(raw);
    let parts = target_part.split_whitespace().collect::<Vec<_>>();
    let log_template = parse_native_log_template(template_part)?;
    match parts.as_slice() {
        [symbol_name] => Ok(NativeHookTarget::Export {
            module_name: None,
            symbol_name: (*symbol_name).to_string(),
            log_template,
        }),
        [module_name, symbol_name] => Ok(NativeHookTarget::Export {
            module_name: if matches!(*module_name, "*" | "null" | "default") {
                None
            } else {
                Some((*module_name).to_string())
            },
            symbol_name: (*symbol_name).to_string(),
            log_template,
        }),
        _ => Err(Error::InvalidArgument(
            "native target usage: <symbol> or <module> <symbol>".into(),
        )),
    }
}

#[cfg(unix)]
fn parse_native_address_target(raw: &str) -> Result<NativeHookTarget> {
    let (address_part, template_part) = split_native_template(raw);
    Ok(NativeHookTarget::Address {
        address: parse_offset_value(address_part)?,
        log_template: parse_native_log_template(template_part)?,
    })
}

#[cfg(unix)]
fn split_native_template(raw: &str) -> (&str, Option<&str>) {
    if let Some((head, tail)) = raw.split_once(" -- ") {
        (head.trim(), Some(tail.trim()))
    } else if let Some(head) = raw.strip_suffix(" --") {
        (head.trim(), Some(""))
    } else {
        (raw.trim(), None)
    }
}

#[cfg(unix)]
fn parse_native_log_template(raw: Option<&str>) -> Result<Option<NativeLogTemplate>> {
    let Some(raw) = raw else {
        return Ok(None);
    };
    if raw.trim().is_empty() {
        return Err(Error::InvalidArgument(
            "native template must contain at least one token after `--`".into(),
        ));
    }

    let mut arguments = Vec::new();
    let mut return_value = None;
    for (index, token) in raw.split_whitespace().enumerate() {
        if let Some(kind) = token.strip_prefix("ret:").or_else(|| token.strip_prefix("ret=")) {
            if return_value.is_some() {
                return Err(Error::InvalidArgument(
                    "native template must not contain more than one return spec".into(),
                ));
            }
            return_value = Some(NativeLogReturn {
                label: "result".into(),
                kind: parse_native_value_format(kind)?,
            });
            continue;
        }

        let (label, kind) = if let Some((label, kind)) = token.split_once(':') {
            if label.trim().is_empty() {
                return Err(Error::InvalidArgument(format!(
                    "invalid native template token `{token}`"
                )));
            }
            (label.trim().to_string(), parse_native_value_format(kind)?)
        } else {
            (format!("x{index}"), parse_native_value_format(token)?)
        };

        arguments.push(NativeLogArgument { label, kind });
    }

    Ok(Some(NativeLogTemplate {
        arguments,
        return_value,
    }))
}

#[cfg(unix)]
fn parse_native_value_format(raw: &str) -> Result<NativeValueFormat> {
    match raw.trim() {
        "ptr" | "pointer" | "addr" => Ok(NativeValueFormat::Ptr),
        "cstr" | "cstring" | "str" => Ok(NativeValueFormat::CString),
        "fd" => Ok(NativeValueFormat::Fd),
        "openflags" | "oflags" => Ok(NativeValueFormat::OpenFlags),
        "access" | "amode" => Ok(NativeValueFormat::AccessMode),
        "mode" | "mode_t" => Ok(NativeValueFormat::Mode),
        "int" | "i64" => Ok(NativeValueFormat::Int),
        "uint" | "u64" | "dec" => Ok(NativeValueFormat::Uint),
        "hex" => Ok(NativeValueFormat::Hex),
        "size" | "size_t" => Ok(NativeValueFormat::Size),
        "ssize" | "ssize_t" => Ok(NativeValueFormat::SSize),
        other => Err(Error::InvalidArgument(format!(
            "unsupported native template type `{other}`; expected ptr|cstr|fd|openflags|access|mode|int|uint|hex|size|ssize"
        ))),
    }
}

#[cfg(unix)]
fn parse_jhook_command(command: &str) -> Result<ObjcHookCommand> {
    const USAGE: &str =
        "jhook usage: jhook <class> <selector> [meta]|jhook status|jhook stop|jhook stop <class> <selector> [meta]";
    let mut parts = command.split_whitespace();
    match parts.next() {
        Some("jhook") => {}
        _ => return Err(Error::InvalidArgument(USAGE.into())),
    }

    let rest = parts.collect::<Vec<_>>();
    if rest.is_empty() {
        return Err(Error::InvalidArgument(USAGE.into()));
    }
    if rest.len() == 1 && matches!(rest[0], "status" | "state" | "show") {
        return Ok(ObjcHookCommand::Status);
    }
    if rest.len() == 1 && matches!(rest[0], "stop" | "off" | "disable") {
        return Ok(ObjcHookCommand::StopAll);
    }
    if (3..=4).contains(&rest.len()) && matches!(rest[0], "stop" | "off" | "disable") {
        let is_class_method = match rest.get(3).copied() {
            None => false,
            Some(flag) if matches!(flag, "meta" | "class" | "+" | "cls") => true,
            Some(flag) if matches!(flag, "instance" | "-" | "inst") => false,
            Some(flag) => {
                return Err(Error::InvalidArgument(format!(
                    "invalid jhook mode `{flag}`; expected meta/class/+ or instance/-"
                )))
            }
        };
        return Ok(ObjcHookCommand::Stop(ObjcHookSpec {
            class_name: rest[1].to_string(),
            selector_name: rest[2].to_string(),
            is_class_method,
        }));
    }
    if !(2..=3).contains(&rest.len()) {
        return Err(Error::InvalidArgument(USAGE.into()));
    }

    let is_class_method = match rest.get(2).copied() {
        None => false,
        Some(flag) if matches!(flag, "meta" | "class" | "+" | "cls") => true,
        Some(flag) if matches!(flag, "instance" | "-" | "inst") => false,
        Some(flag) => {
            return Err(Error::InvalidArgument(format!(
                "invalid jhook mode `{flag}`; expected meta/class/+ or instance/-"
            )))
        }
    };

    Ok(ObjcHookCommand::Install(ObjcHookSpec {
        class_name: rest[0].to_string(),
        selector_name: rest[1].to_string(),
        is_class_method,
    }))
}

#[cfg(unix)]
fn parse_shook_command(command: &str) -> Result<SwiftHookCommand> {
    const USAGE: &str = "shook usage: shook <type> <method>|shook <module> -- <type> <method>|shook status|shook stop|shook stop <type> <method>|shook stop <module> -- <type> <method>";

    let mut parts = command.split_whitespace();
    match parts.next() {
        Some("shook") => {}
        _ => return Err(Error::InvalidArgument(USAGE.into())),
    }

    let rest = parts.collect::<Vec<_>>();
    if rest.is_empty() {
        return Err(Error::InvalidArgument(USAGE.into()));
    }
    if rest.len() == 1 && matches!(rest[0], "status" | "state" | "show") {
        return Ok(SwiftHookCommand::Status);
    }
    if rest.len() == 1 && matches!(rest[0], "stop" | "off" | "disable") {
        return Ok(SwiftHookCommand::StopAll);
    }
    if matches!(rest.first().copied(), Some("stop" | "off" | "disable")) {
        let stop_rest = &rest[1..];
        if stop_rest.is_empty() {
            return Err(Error::InvalidArgument(USAGE.into()));
        }
        if let Some(separator) = stop_rest.iter().position(|part| *part == "--") {
            if separator != 1 || stop_rest.len() != 4 {
                return Err(Error::InvalidArgument(USAGE.into()));
            }

            return Ok(SwiftHookCommand::Stop {
                module_name: Some(stop_rest[0].to_string()),
                type_name: stop_rest[2].to_string(),
                method_query: stop_rest[3].to_string(),
            });
        }

        if stop_rest.len() != 2 {
            return Err(Error::InvalidArgument(USAGE.into()));
        }

        return Ok(SwiftHookCommand::Stop {
            module_name: None,
            type_name: stop_rest[0].to_string(),
            method_query: stop_rest[1].to_string(),
        });
    }

    if let Some(separator) = rest.iter().position(|part| *part == "--") {
        if separator != 1 || rest.len() != 4 {
            return Err(Error::InvalidArgument(USAGE.into()));
        }

        return Ok(SwiftHookCommand::Install {
            module_name: Some(rest[0].to_string()),
            type_name: rest[2].to_string(),
            method_query: rest[3].to_string(),
        });
    }

    if rest.len() != 2 {
        return Err(Error::InvalidArgument(USAGE.into()));
    }

    Ok(SwiftHookCommand::Install {
        module_name: None,
        type_name: rest[0].to_string(),
        method_query: rest[1].to_string(),
    })
}

#[cfg(unix)]
fn build_stalker_spec(stalker_command: &StalkerCommand) -> Value {
    match stalker_command {
        StalkerCommand::Status => json!({ "kind": "stalker.status" }),
        StalkerCommand::StopAll => json!({ "kind": "stalker.stop" }),
        StalkerCommand::StopObjc { filter } => json!({
            "kind": "stalker.stop",
            "target": Value::Null,
            "filter": filter,
        }),
        StalkerCommand::StopNative { target } => json!({
            "kind": "stalker.stop",
            "target": build_native_target_spec(target),
            "filter": Value::Null,
        }),
        StalkerCommand::InstallObjc { filter } => json!({
            "kind": "objc.stalker.install",
            "filter": filter.as_deref().unwrap_or(""),
        }),
        StalkerCommand::InstallNative { target } => json!({
            "kind": "native.stalker.install",
            "target": build_native_target_spec(target),
        }),
    }
}

#[cfg(unix)]
fn build_trace_spec(trace_command: &TraceCommand) -> Value {
    match trace_command {
        TraceCommand::Status => json!({ "kind": "trace.status" }),
        TraceCommand::StopAll => json!({ "kind": "trace.stop" }),
        TraceCommand::StopObjc { filter } => json!({
            "kind": "trace.stop",
            "target": Value::Null,
            "filter": filter,
        }),
        TraceCommand::StopNative { target } => json!({
            "kind": "trace.stop",
            "target": build_native_target_spec(target),
            "filter": Value::Null,
        }),
        TraceCommand::InstallObjc { filter } => json!({
            "kind": "objc.trace.install",
            "filter": filter.as_deref().unwrap_or(""),
        }),
        TraceCommand::InstallNative { target } => json!({
            "kind": "native.trace.install",
            "target": build_native_target_spec(target),
        }),
    }
}

#[cfg(unix)]
fn build_native_template_spec(template: Option<&NativeLogTemplate>) -> (Value, Value) {
    let Some(template) = template else {
        return (Value::Null, Value::Null);
    };

    let args = Value::Array(
        template
            .arguments
            .iter()
            .map(|arg| json!({ "label": arg.label, "kind": arg.kind.as_str() }))
            .collect(),
    );

    let ret = template
        .return_value
        .as_ref()
        .map(|ret| json!({ "label": ret.label, "kind": ret.kind.as_str() }))
        .unwrap_or(Value::Null);

    (args, ret)
}

#[cfg(unix)]
fn build_native_target_spec(target: &NativeHookTarget) -> Value {
    let (template_args, template_ret) = build_native_template_spec(target.log_template());
    match target {
        NativeHookTarget::Export {
            module_name,
            symbol_name,
            ..
        } => json!({
            "kind": "export",
            "moduleName": module_name,
            "symbolName": symbol_name,
            "templateArgs": template_args,
            "templateRet": template_ret,
        }),
        NativeHookTarget::Address { address, .. } => json!({
            "kind": "address",
            "address": format!("0x{address:x}"),
            "templateArgs": template_args,
            "templateRet": template_ret,
        }),
    }
}

#[cfg(unix)]
fn build_hfl_spec(command: &HflCommand) -> Value {
    match command {
        HflCommand::Install { module_name, offset } => json!({
            "kind": "hfl.install",
            "moduleName": module_name,
            "offsetHex": format!("0x{offset:x}"),
        }),
        HflCommand::Status => json!({ "kind": "hfl.status" }),
        HflCommand::StopAll => json!({ "kind": "hfl.stop" }),
        HflCommand::Stop { module_name, offset } => json!({
            "kind": "hfl.stop",
            "moduleName": module_name,
            "offsetHex": format!("0x{offset:x}"),
        }),
    }
}

#[cfg(unix)]
fn build_jhook_spec(command: &ObjcHookCommand) -> Value {
    match command {
        ObjcHookCommand::Install(spec) => json!({
            "kind": "objc.hook.install",
            "className": spec.class_name,
            "selectorName": spec.selector_name,
            "isClassMethod": spec.is_class_method,
        }),
        ObjcHookCommand::Status => json!({ "kind": "objc.hook.status" }),
        ObjcHookCommand::StopAll => json!({ "kind": "objc.hook.stop" }),
        ObjcHookCommand::Stop(spec) => json!({
            "kind": "objc.hook.stop",
            "className": spec.class_name,
            "selectorName": spec.selector_name,
            "isClassMethod": spec.is_class_method,
        }),
    }
}

#[cfg(unix)]
fn build_shook_spec(command: &SwiftHookCommand) -> Value {
    match command {
        SwiftHookCommand::Install {
            module_name,
            type_name,
            method_query,
        } => json!({
            "kind": "swift.hook.install",
            "moduleName": module_name,
            "typeName": type_name,
            "methodQuery": method_query,
        }),
        SwiftHookCommand::Status => json!({ "kind": "swift.hook.status" }),
        SwiftHookCommand::StopAll => json!({ "kind": "swift.hook.stop" }),
        SwiftHookCommand::Stop {
            module_name,
            type_name,
            method_query,
        } => json!({
            "kind": "swift.hook.stop",
            "moduleName": module_name,
            "typeName": type_name,
            "methodQuery": method_query,
        }),
    }
}

#[cfg(unix)]
#[cfg(test)]
fn quote_js_string(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len() + 2);
    escaped.push('"');

    for ch in value.chars() {
        match ch {
            '\\' => escaped.push_str("\\\\"),
            '"' => escaped.push_str("\\\""),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            '\u{08}' => escaped.push_str("\\b"),
            '\u{0c}' => escaped.push_str("\\f"),
            ch if ch.is_control() => escaped.push_str(&format!("\\u{:04x}", ch as u32)),
            ch => escaped.push(ch),
        }
    }

    escaped.push('"');
    escaped
}

#[cfg(unix)]
fn read_prompt_line(prompt: &str) -> Result<Option<String>> {
    let mut stdout = io::stdout();
    write!(stdout, "{prompt}")?;
    stdout.flush()?;

    let mut line = String::new();
    let read = io::stdin().read_line(&mut line)?;
    if read == 0 {
        return Ok(None);
    }
    Ok(Some(line))
}

#[cfg(unix)]
fn print_controller_help() {
    println!("commands:");
    println!("  help");
    println!("  ping");
    println!("  stalker [filter]|stalker native [module] <symbol> [-- template]|stalker addr <address> [-- template]|stalker status|stalker stop|stalker stop [filter]|stalker stop native [module] <symbol>|stalker stop addr <address>");
    println!(
        "  trace [filter]|trace native [module] <symbol> [-- template]|trace addr <address> [-- template]|trace status|trace stop|trace stop [filter]|trace stop native [module] <symbol>|trace stop addr <address>"
    );
    println!("  hfl <module> <offset>|hfl status|hfl stop|hfl stop <module> <offset>");
    println!("  jhook <class> <selector> [meta]|jhook status|jhook stop|jhook stop <class> <selector> [meta]");
    println!("  shook <type> <method>|shook <module> -- <type> <method>|shook status|shook stop|shook stop <type> <method>|shook stop <module> -- <type> <method>");
    println!("  jsinit");
    println!("  jsclean");
    println!("  loadjs <script>");
    println!("  jseval <expr>");
    println!("  jscomplete <prefix>");
    println!("  jsrepl");
    println!("  objc.classes");
    println!("  objc.classes [filter]");
    println!("  objc.findClasses <query>");
    println!("  objc.protocols");
    println!("  objc.protocols [filter]");
    println!("  objc.classProtocols <class> [filter]");
    println!("  objc.findClassProtocols <class> <query>");
    println!("  objc.classInfo <class> [meta]");
    println!("  objc.protocolInfo <protocol>");
    println!("  objc.protocolProtocols <protocol> [filter]");
    println!("  objc.findProtocolProtocols <protocol> <query>");
    println!("  objc.protocolMethods <protocol> [required] [instance] [filter]");
    println!("  objc.findProtocolMethods <protocol> [required] [instance] <query>");
    println!("  objc.protocolMethodInfo <protocol> <selector> [required] [instance]");
    println!("  objc.protocolProperties <protocol> [filter]");
    println!("  objc.findProtocolProperties <protocol> <query>");
    println!("  objc.protocolPropertyInfo <protocol> <property>");
    println!("  objc.superclass <class>");
    println!("  objc.classChain <class>");
    println!("  objc.classExists <name>");
    println!("  objc.selector <name>");
    println!("  objc.classImage <class>");
    println!("  objc.selectorName <selector>");
    println!("  objc.objectClassName <object>");
    println!("  objc.methodImp <class> <selector> [meta]");
    println!("  objc.methodInfo <class> <selector> [meta]");
    println!("  objc.propertyInfo <class> <property> [meta]");
    println!("  objc.ivarInfo <class> <ivar>");
    println!("  objc.methodImage <class> <selector> [meta]");
    println!("  objc.methodOwners <selector> [meta]");
    println!("  objc.methods <class> [meta] [filter]");
    println!("  objc.properties <class> [meta] [filter]");
    println!("  objc.ivars <class> [filter]");
    println!("  objc.findClassInfo/findProtocolInfo/findProtocolMethodInfo/findProtocolPropertyInfo/findSuperclass/findClassChain/findClassImage/findMethodInfo/findMethodImage/findPropertyInfo/findIvarInfo/findSelectorName/findObjectClassName ... (info aliases)");
    println!("  objc.findMethods/findProperties/findIvars/findMethodOwners/findProtocols ... (query aliases)");
    println!("  native.base <module>");
    println!("  native.imageInfo <module>");
    println!("  native.export <symbol>|native.export <module> -- <symbol>");
    println!("  native.exports <module>|native.exports <module> -- <query>");
    println!("  native.exportInfo <module> -- <symbol>");
    println!("  native.dependencies <module>|native.dependencies <module> -- <query>");
    println!("  native.dependencyInfo <module> -- <path-or-name>");
    println!("  native.encryptionInfo <module>");
    println!("  native.entryPoint <module>");
    println!("  native.dyldInfo <module>");
    println!("  native.linkedit <module>");
    println!("  native.functionStarts <module>");
    println!("  native.codeSignature <module>");
    println!("  native.dataInCode <module>");
    println!("  native.exportsTrie <module>");
    println!("  native.chainedFixups <module>");
    println!("  native.sourceVersion <module>");
    println!("  native.buildVersion <module>");
    println!("  native.dylinker <module>");
    println!("  native.installName <module>");
    println!("  native.uuid <module>");
    println!("  native.rpaths <module>|native.rpaths <module> -- <query>");
    println!("  native.rpathInfo <module> -- <path>");
    println!("  native.imports <module>|native.imports <module> -- <query>");
    println!("  native.importInfo <module> -- <symbol>");
    println!("  native.loadcmds <module>|native.loadCommands <module>");
    println!("  native.loadCommandInfo <module> -- <name|cmd|index>");
    println!("  native.sections <module>");
    println!("  native.sectionInfo <module> -- <segment> <section>");
    println!("  native.segments <module>");
    println!("  native.segmentInfo <module> -- <segment>");
    println!("  native.symbolInfo <symbol>|native.symbolInfo <module> -- <symbol>");
    println!("  native.symbols <query>|native.symbols <module> -- <query>");
    println!("  native.findImageInfo/findSymbolInfo/findExportInfo/findDependencyInfo/findRpathInfo/findImportInfo/findSegmentInfo/findSectionInfo/findLoadCommandInfo ... (info aliases)");
    println!("  native.findSymbols/findExports/findDependencies/findEncryptionInfo/findEntryPoint/findDyldInfo/findLinkedit/findFunctionStarts/findCodeSignature/findDataInCode/findExportsTrie/findChainedFixups/findSourceVersion/findBuildVersion/findDylinker/findInstallName/findUuid/findRpaths/findImports/findSegments/findSections/findLoadCommands ... (aliases)");
    println!("  native.images [filter]");
    println!("  native.mainImage");
    println!("  native.image <address>");
    println!("  native.symbol <address>");
    println!("  native.hookenv|native.detectHookEnvironment");
    println!("  pac.available");
    println!("  pac.arm64e|pac.isProcessArm64e");
    println!("  pac.image <module>|pac.isImageArm64e <module>");
    println!("  pac.images [filter]|pac.arm64eImages [filter]");
    println!("  pac.strip <address>");
    println!("  pac.stripdata <address>|pac.stripData <address>");
    println!("  swift.available");
    println!("  swift.demangle <mangled-symbol>");
    println!("  swift.symbolInfo <symbol>|swift.symbolInfo <module> -- <symbol>");
    println!("  swift.protocolInfo <protocol>|swift.protocolInfo <module> -- <protocol>");
    println!("  swift.conformanceInfo <type> <protocol>|swift.conformanceInfo <module> -- <type> <protocol>");
    println!("  swift.typeInfo <type>|swift.typeInfo <module> -- <type>");
    println!("  swift.methodInfo <type> <method>|swift.methodInfo <module> -- <type> <method>");
    println!("  swift.protocols [query]|swift.protocols <module> -- <query>");
    println!("  swift.conformances <type>|swift.conformances <module> -- <type>");
    println!("  swift.metadata <type>|swift.metadata <module> -- <type>");
    println!("  swift.metadataInfo <type>|swift.metadataInfo <module> -- <type>");
    println!("  swift.vtable <type>|swift.vtable <module> -- <type>");
    println!("  swift.witnessTable <type|protocol>|swift.witnessTable <module> -- <type|protocol>");
    println!("  swift.witnessTableInfo <type> <protocol>|swift.witnessTableInfo <module> -- <type> <protocol>");
    println!("  swift.typeLayout <type>|swift.typeLayout <module> -- <type>");
    println!("  swift.typeLayoutInfo <type>|swift.typeLayoutInfo <module> -- <type>");
    println!("  swift.vtableInfo <type> <member>|swift.vtableInfo <module> -- <type> <member>");
    println!("  swift.symbols <query>|swift.symbols <module> -- <query>");
    println!("  swift.typeKinds|swift.typeSourceKinds");
    println!("  swift.methodOwners <method>|swift.methodOwners <module> -- <method>");
    println!("  swift.types <query>|swift.types <module> -- <query>");
    println!("  swift.typesOfKind <kind> <query>|swift.typesOfKind <module> -- <kind> <query>");
    println!("  swift.typeMethods <type>|swift.typeMethods <module> -- <type>");
    println!("  swift.methods <type> <method>|swift.methods <module> -- <type> <method>");
    println!("  swift.findSymbolInfo/findProtocolInfo/findConformanceInfo/findTypeInfo/findMethodInfo/findMetadataInfo/findVtableInfo/findWitnessTableInfo/findTypeLayoutInfo ... (info aliases)");
    println!("  swift.findSymbols/findProtocols/findConformances/findMetadata/findVtable/findWitnessTable/findTypeLayout/findTypes/findTypesOfKind/findMethodOwners/findTypeMethods/findMethods ... (query aliases)");
    println!("  exit");
}

#[cfg(unix)]
fn print_reply_payload(command: &str, payload: &str) {
    if payload.trim().is_empty() {
        return;
    }
    if command.starts_with("jseval ") || command == "jsinit" {
        print_eval_payload(payload);
        return;
    }
    if payload.contains('\n') {
        println!("{payload}");
    } else {
        println!("{payload}");
    }
}

#[cfg(unix)]
fn print_command_outcome(outcome: &CommandOutcome) {
    match outcome.kind {
        CommandOutcomeKind::Complete => {
            if outcome.items.is_empty() {
                println!("(no completions)");
            } else {
                for item in &outcome.items {
                    println!("{item}");
                }
            }
        }
        CommandOutcomeKind::Log => {
            if let Some(payload) = outcome.payload.as_deref() {
                println!("{payload}");
            }
        }
        CommandOutcomeKind::Eval => {
            if outcome.ok {
                if let Some(payload) = outcome.payload.as_deref() {
                    print_reply_payload(&outcome.command, payload);
                }
            } else if let Some(error) = outcome.error.as_deref() {
                println!("[error] {error}");
            }
        }
    }
}

#[cfg(unix)]
fn parse_payload_json(payload: &str) -> Option<Value> {
    let trimmed = payload.trim();
    if trimmed.is_empty() {
        return None;
    }
    serde_json::from_str(trimmed).ok()
}

#[cfg(unix)]
fn render_command_outcome_json(outcome: &CommandOutcome) -> Value {
    let payload_json = outcome.payload.as_deref().and_then(parse_payload_json);
    json!({
        "ok": outcome.ok,
        "command": outcome.command,
        "kind": outcome.kind.as_str(),
        "payload": outcome.payload,
        "payloadJson": payload_json,
        "items": outcome.items,
        "error": outcome.error,
        "logs": outcome.logs,
    })
}

#[cfg(unix)]
#[cfg_attr(not(test), allow(dead_code))]
fn render_command_error_json(command: &str, err: &Error, logs: &[String]) -> Value {
    json!({
        "ok": false,
        "command": command,
        "errorKind": match err {
            Error::Io(_) => "io",
            Error::Protocol(_) => "protocol",
            Error::InvalidArgument(_) => "invalid-argument",
            Error::State(_) => "state",
            Error::Unsupported(_) => "unsupported",
        },
        "error": err.to_string(),
        "logs": logs,
    })
}

#[cfg(unix)]
fn render_command_error_json_with_context(
    command: &str,
    err: &Error,
    logs: &[String],
    context: &CommandJsonContext<'_>,
) -> Value {
    let mut rendered = render_injection_result_json(
        context.config,
        context.pid,
        context.socket_path,
        context.plan,
        context.injection_environment,
        context.doctor,
        context.preflight,
        context.trace,
        context.hello,
        context.ping,
        context.hook_environment_notice,
        context.hook_environment_checked,
        context.jsinit_result,
        context.loadjs_result,
        logs,
        Some(err),
    )
    .as_object()
    .cloned()
    .unwrap_or_default();

    rendered.insert("command".into(), json!(command));
    rendered.insert("kind".into(), Value::Null);
    rendered.insert("payload".into(), Value::Null);
    rendered.insert("payloadJson".into(), Value::Null);
    rendered.insert("items".into(), Value::Array(Vec::new()));
    rendered.insert("logs".into(), json!(logs));

    Value::Object(rendered)
}

#[cfg(unix)]
fn print_eval_payload(payload: &str) {
    if payload.trim().is_empty() {
        return;
    }
    if payload.contains('\n') {
        println!("{payload}");
    } else {
        println!("=> {payload}");
    }
}

#[cfg(unix)]
fn read_agent_event(stream: &mut UnixStream, context: &str) -> Result<AgentEvent> {
    match read_frame(stream) {
        Ok((kind, payload)) => decode_event(kind, payload),
        Err(Error::Io(err)) if matches!(err.kind(), ErrorKind::TimedOut | ErrorKind::WouldBlock) => {
            Err(Error::State(format!("{context} timed out")))
        }
        Err(err) => Err(err),
    }
}

#[cfg(unix)]
fn event_name(event: &AgentEvent) -> &'static str {
    match event {
        AgentEvent::Hello(_) => "HELLO",
        AgentEvent::Log(_) => "LOG",
        AgentEvent::Complete(_) => "COMPLETE",
        AgentEvent::EvalOk(_) => "EVAL_OK",
        AgentEvent::EvalErr(_) => "EVAL_ERR",
    }
}

#[cfg(test)]
mod tests {
    use super::{
        analyze_doctor_report, build_hfl_spec, build_jhook_spec, build_shook_spec, build_stalker_spec,
        build_trace_spec, command_json_template_entry, command_requests_inline_hook_install,
        command_requires_inline_hooks, ensure_inline_hooks_allowed_for_command, hook_automation_to_json,
        hook_action_command_templates, hook_backend_matrix_to_json, hook_effective_actions,
        hook_effective_actions_to_json, hook_effective_to_json, hook_environment_requires_notice,
        parse_hfl_command, parse_jhook_command, parse_shook_command, parse_stalker_command,
        parse_trace_command, print_injection_preflight, quote_js_string, render_bootstrap_summary,
        render_command_error_json, render_command_error_json_with_context, render_command_outcome_json,
        render_image_list_json, render_injection_environment, render_injection_result_json, render_loader_symbol,
        render_preflight_json, CommandJsonContext, CommandOutcome, CommandOutcomeKind, HflCommand,
        HookEffectiveAction, NativeHookTarget, NativeLogArgument, NativeLogReturn, NativeLogTemplate,
        NativeValueFormat, ObjcHookCommand, StalkerCommand, SwiftHookCommand, TraceCommand,
    };
    use common::{
        AgentCommand, ControllerConfig, Error, Hello, InjectionMode, DEFAULT_AGENT_PATH, DEFAULT_AGENT_PATH_ROOTFUL,
        LEGACY_AGENT_PATH_ROOTFUL,
    };
    use native_api::{
        hook_environment_recommended_actions, Arm64ThreadState, BootstrapResultReport, BootstrapStatus,
        HookBackendInfo, HookEnvironmentReport, HookPolicy, HookStrategyDecision, InjectionEnvironmentReport,
        InjectionTarget, InjectionTargetPreflightReport, InjectionTrace, LoaderSymbolRole, MachInjector,
        RemoteProtectionOutcome, RemoteThreadTerminationOutcome, ResolvedLoaderSymbol, ThreadBootstrapKind,
        ThreadCreatePlan,
    };
    use serde_json::json;
    use std::path::Path;

    #[test]
    fn parse_hfl_accepts_hex_offset() {
        assert_eq!(
            parse_hfl_command("hfl libobjc.A.dylib 0x1234").expect("parse hfl"),
            HflCommand::Install {
                module_name: "libobjc.A.dylib".into(),
                offset: 0x1234,
            }
        );
    }

    #[test]
    fn parse_hfl_status() {
        assert_eq!(parse_hfl_command("hfl status").expect("parse hfl"), HflCommand::Status);
    }

    #[test]
    fn parse_hfl_targeted_stop() {
        assert_eq!(
            parse_hfl_command("hfl stop libobjc.A.dylib 0x1234").expect("parse hfl"),
            HflCommand::Stop {
                module_name: "libobjc.A.dylib".into(),
                offset: 0x1234,
            }
        );
    }

    #[test]
    fn legacy_agent_command_parsing_covers_controller_entrypoints() {
        assert_eq!(AgentCommand::from_legacy("ping"), Some(AgentCommand::Ping));
        assert_eq!(AgentCommand::from_legacy("jsinit"), Some(AgentCommand::JsInit));
        assert_eq!(AgentCommand::from_legacy("jsclean"), Some(AgentCommand::JsClean));
        assert_eq!(
            AgentCommand::from_legacy("loadjs console.log(1)"),
            Some(AgentCommand::LoadJs {
                script: "console.log(1)".into()
            })
        );
        assert_eq!(
            AgentCommand::from_legacy("objc.classes"),
            Some(AgentCommand::RuntimeDispatch {
                spec: json!({ "kind": "objc.classes", "filter": null })
            })
        );
        assert_eq!(
            AgentCommand::from_legacy("objc.protocols"),
            Some(AgentCommand::RuntimeDispatch {
                spec: json!({ "kind": "objc.protocols", "filter": null })
            })
        );
        assert_eq!(
            AgentCommand::from_legacy("objc.findClasses UIView"),
            Some(AgentCommand::RuntimeDispatch {
                spec: json!({
                    "kind": "objc.classes",
                    "filter": "UIView",
                })
            })
        );
        assert_eq!(
            AgentCommand::from_legacy("objc.findMethods UIView init"),
            Some(AgentCommand::RuntimeDispatch {
                spec: json!({
                    "kind": "objc.methods",
                    "className": "UIView",
                    "isClassMethod": false,
                    "filter": "init",
                })
            })
        );
        assert_eq!(
            AgentCommand::from_legacy("native.findSymbols malloc"),
            Some(AgentCommand::RuntimeDispatch {
                spec: json!({
                    "kind": "native.symbols",
                    "moduleName": null,
                    "query": "malloc",
                })
            })
        );
        assert_eq!(
            AgentCommand::from_legacy("native.findDyldInfo DemoBinary"),
            Some(AgentCommand::RuntimeDispatch {
                spec: json!({
                    "kind": "native.dyld_info",
                    "moduleName": "DemoBinary",
                })
            })
        );
        assert_eq!(
            AgentCommand::from_legacy("native.findLoadCommands DemoBinary"),
            Some(AgentCommand::RuntimeDispatch {
                spec: json!({
                    "kind": "native.load_commands",
                    "moduleName": "DemoBinary",
                })
            })
        );
        assert_eq!(
            AgentCommand::from_legacy("native.loadCommands DemoBinary"),
            Some(AgentCommand::RuntimeDispatch {
                spec: json!({
                    "kind": "native.load_commands",
                    "moduleName": "DemoBinary",
                })
            })
        );
        assert_eq!(
            AgentCommand::from_legacy("native.findImports DemoBinary -- malloc"),
            Some(AgentCommand::RuntimeDispatch {
                spec: json!({
                    "kind": "native.imports",
                    "moduleName": "DemoBinary",
                    "query": "malloc",
                })
            })
        );
        assert_eq!(
            AgentCommand::from_legacy("swift.findTypes ViewController"),
            Some(AgentCommand::RuntimeDispatch {
                spec: json!({
                    "kind": "swift.types",
                    "moduleName": null,
                    "query": "ViewController",
                })
            })
        );
        assert_eq!(
            AgentCommand::from_legacy("swift.findMethods ViewController viewDidLoad"),
            Some(AgentCommand::RuntimeDispatch {
                spec: json!({
                    "kind": "swift.methods",
                    "moduleName": null,
                    "typeName": "ViewController",
                    "methodQuery": "viewDidLoad",
                })
            })
        );
        assert_eq!(
            AgentCommand::from_legacy("swift.findProtocols Renderable"),
            Some(AgentCommand::RuntimeDispatch {
                spec: json!({
                    "kind": "swift.protocols",
                    "moduleName": null,
                    "query": "Renderable",
                })
            })
        );
        assert_eq!(
            AgentCommand::from_legacy("swift.findTypeInfo ViewController"),
            Some(AgentCommand::RuntimeDispatch {
                spec: json!({
                    "kind": "swift.type_info",
                    "moduleName": null,
                    "typeName": "ViewController",
                })
            })
        );
        assert_eq!(
            AgentCommand::from_legacy("swift.findMethodInfo ViewController viewDidLoad"),
            Some(AgentCommand::RuntimeDispatch {
                spec: json!({
                    "kind": "swift.method_info",
                    "moduleName": null,
                    "typeName": "ViewController",
                    "methodName": "viewDidLoad",
                })
            })
        );
        assert_eq!(
            AgentCommand::from_legacy("swift.findSymbolInfo ViewController"),
            Some(AgentCommand::RuntimeDispatch {
                spec: json!({
                    "kind": "swift.symbol_info",
                    "moduleName": null,
                    "symbolName": "ViewController",
                })
            })
        );
        assert!(matches!(
            AgentCommand::from_legacy("swift.types ViewController"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("objc.protocols NS"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert_eq!(
            AgentCommand::from_legacy("objc.classProtocols UIViewController"),
            Some(AgentCommand::RuntimeDispatch {
                spec: json!({
                    "kind": "objc.class_protocols",
                    "className": "UIViewController",
                    "filter": null,
                })
            })
        );
        assert_eq!(
            AgentCommand::from_legacy("objc.classProtocols UIViewController UI"),
            Some(AgentCommand::RuntimeDispatch {
                spec: json!({
                    "kind": "objc.class_protocols",
                    "className": "UIViewController",
                    "filter": "UI",
                })
            })
        );
        assert_eq!(
            AgentCommand::from_legacy("objc.findClassProtocols UIViewController UI"),
            Some(AgentCommand::RuntimeDispatch {
                spec: json!({
                    "kind": "objc.class_protocols",
                    "className": "UIViewController",
                    "filter": "UI",
                })
            })
        );
        assert_eq!(
            AgentCommand::from_legacy("objc.classInfo UIViewController meta"),
            Some(AgentCommand::RuntimeDispatch {
                spec: json!({
                    "kind": "objc.class_info",
                    "className": "UIViewController",
                    "isMetaClass": true,
                })
            })
        );
        assert!(matches!(
            AgentCommand::from_legacy("objc.findClassInfo UIViewController meta"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert_eq!(
            AgentCommand::from_legacy("objc.protocolInfo NSObject"),
            Some(AgentCommand::RuntimeDispatch {
                spec: json!({
                    "kind": "objc.protocol_info",
                    "protocolName": "NSObject",
                })
            })
        );
        assert!(matches!(
            AgentCommand::from_legacy("objc.findProtocolInfo NSObject"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert_eq!(
            AgentCommand::from_legacy("objc.protocolProtocols NSObject"),
            Some(AgentCommand::RuntimeDispatch {
                spec: json!({
                    "kind": "objc.protocol_protocols",
                    "protocolName": "NSObject",
                    "filter": null,
                })
            })
        );
        assert_eq!(
            AgentCommand::from_legacy("objc.protocolProtocols NSObject NS"),
            Some(AgentCommand::RuntimeDispatch {
                spec: json!({
                    "kind": "objc.protocol_protocols",
                    "protocolName": "NSObject",
                    "filter": "NS",
                })
            })
        );
        assert_eq!(
            AgentCommand::from_legacy("objc.findProtocolProtocols NSObject NS"),
            Some(AgentCommand::RuntimeDispatch {
                spec: json!({
                    "kind": "objc.protocol_protocols",
                    "protocolName": "NSObject",
                    "filter": "NS",
                })
            })
        );
        assert_eq!(
            AgentCommand::from_legacy("objc.protocolMethods NSObject optional class"),
            Some(AgentCommand::RuntimeDispatch {
                spec: json!({
                    "kind": "objc.protocol_methods",
                    "protocolName": "NSObject",
                    "isRequired": false,
                    "isInstanceMethod": false,
                    "filter": null,
                })
            })
        );
        assert_eq!(
            AgentCommand::from_legacy("objc.protocolMethods NSObject optional class description"),
            Some(AgentCommand::RuntimeDispatch {
                spec: json!({
                    "kind": "objc.protocol_methods",
                    "protocolName": "NSObject",
                    "isRequired": false,
                    "isInstanceMethod": false,
                    "filter": "description",
                })
            })
        );
        assert_eq!(
            AgentCommand::from_legacy("objc.findProtocolMethods NSObject optional class description"),
            Some(AgentCommand::RuntimeDispatch {
                spec: json!({
                    "kind": "objc.protocol_methods",
                    "protocolName": "NSObject",
                    "isRequired": false,
                    "isInstanceMethod": false,
                    "filter": "description",
                })
            })
        );
        assert_eq!(
            AgentCommand::from_legacy("objc.protocolMethodInfo NSObject description optional class"),
            Some(AgentCommand::RuntimeDispatch {
                spec: json!({
                    "kind": "objc.protocol_method_info",
                    "protocolName": "NSObject",
                    "selectorName": "description",
                    "isRequired": false,
                    "isInstanceMethod": false,
                })
            })
        );
        assert!(matches!(
            AgentCommand::from_legacy("objc.findProtocolMethodInfo NSObject description optional class"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert_eq!(
            AgentCommand::from_legacy("objc.protocolProperties NSObject"),
            Some(AgentCommand::RuntimeDispatch {
                spec: json!({
                    "kind": "objc.protocol_properties",
                    "protocolName": "NSObject",
                    "filter": null,
                })
            })
        );
        assert_eq!(
            AgentCommand::from_legacy("objc.protocolProperties NSObject description"),
            Some(AgentCommand::RuntimeDispatch {
                spec: json!({
                    "kind": "objc.protocol_properties",
                    "protocolName": "NSObject",
                    "filter": "description",
                })
            })
        );
        assert_eq!(
            AgentCommand::from_legacy("objc.findProtocolProperties NSObject description"),
            Some(AgentCommand::RuntimeDispatch {
                spec: json!({
                    "kind": "objc.protocol_properties",
                    "protocolName": "NSObject",
                    "filter": "description",
                })
            })
        );
        assert_eq!(
            AgentCommand::from_legacy("objc.protocolPropertyInfo NSObject description"),
            Some(AgentCommand::RuntimeDispatch {
                spec: json!({
                    "kind": "objc.protocol_property_info",
                    "protocolName": "NSObject",
                    "propertyName": "description",
                })
            })
        );
        assert!(matches!(
            AgentCommand::from_legacy("objc.findProtocolPropertyInfo NSObject description"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert_eq!(
            AgentCommand::from_legacy("objc.superclass UIViewController"),
            Some(AgentCommand::RuntimeDispatch {
                spec: json!({
                    "kind": "objc.superclass",
                    "className": "UIViewController",
                })
            })
        );
        assert!(matches!(
            AgentCommand::from_legacy("objc.findSuperclass UIViewController"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert_eq!(
            AgentCommand::from_legacy("objc.classChain UIViewController"),
            Some(AgentCommand::RuntimeDispatch {
                spec: json!({
                    "kind": "objc.class_chain",
                    "className": "UIViewController",
                })
            })
        );
        assert!(matches!(
            AgentCommand::from_legacy("objc.findClassChain UIViewController"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert_eq!(
            AgentCommand::from_legacy("objc.properties UIViewController meta delegate"),
            Some(AgentCommand::RuntimeDispatch {
                spec: json!({
                    "kind": "objc.properties",
                    "className": "UIViewController",
                    "isClassProperty": true,
                    "filter": "delegate",
                })
            })
        );
        assert_eq!(
            AgentCommand::from_legacy("objc.ivars UIViewController delegate"),
            Some(AgentCommand::RuntimeDispatch {
                spec: json!({
                    "kind": "objc.ivars",
                    "className": "UIViewController",
                    "filter": "delegate",
                })
            })
        );
        assert!(matches!(
            AgentCommand::from_legacy("objc.methodOwners viewDidLoad"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("objc.classImage UIViewController"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("objc.findClassImage UIViewController"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert_eq!(
            AgentCommand::from_legacy("objc.methodInfo UIViewController viewDidLoad"),
            Some(AgentCommand::RuntimeDispatch {
                spec: json!({
                    "kind": "objc.method_info",
                    "className": "UIViewController",
                    "selectorName": "viewDidLoad",
                    "isClassMethod": false,
                })
            })
        );
        assert!(matches!(
            AgentCommand::from_legacy("objc.findMethodInfo UIViewController viewDidLoad"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert_eq!(
            AgentCommand::from_legacy("objc.propertyInfo UIViewController view"),
            Some(AgentCommand::RuntimeDispatch {
                spec: json!({
                    "kind": "objc.property_info",
                    "className": "UIViewController",
                    "propertyName": "view",
                    "isClassProperty": false,
                })
            })
        );
        assert!(matches!(
            AgentCommand::from_legacy("objc.findPropertyInfo UIViewController view"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert_eq!(
            AgentCommand::from_legacy("objc.ivarInfo UIViewController _viewControllerFlags"),
            Some(AgentCommand::RuntimeDispatch {
                spec: json!({
                    "kind": "objc.ivar_info",
                    "className": "UIViewController",
                    "ivarName": "_viewControllerFlags",
                })
            })
        );
        assert!(matches!(
            AgentCommand::from_legacy("objc.findIvarInfo UIViewController _viewControllerFlags"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("objc.methodImage UIViewController viewDidLoad"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("objc.findMethodImage UIViewController viewDidLoad"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("objc.findSelectorName 0x1234"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("objc.findObjectClassName 0x1234"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("native.exports DemoBinary"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("native.imageInfo DemoBinary"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("native.findImageInfo DemoBinary"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("native.exportInfo DemoBinary -- malloc"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("native.findExportInfo DemoBinary -- malloc"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("native.dependencies DemoBinary"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("native.dependencyInfo DemoBinary -- libSystem.B.dylib"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("native.findDependencyInfo DemoBinary -- libSystem.B.dylib"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("native.encryptionInfo DemoBinary"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("native.entryPoint DemoBinary"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("native.dyldInfo DemoBinary"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("native.linkedit DemoBinary"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("native.functionStarts DemoBinary"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("native.codeSignature DemoBinary"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("native.dataInCode DemoBinary"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("native.exportsTrie DemoBinary"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("native.chainedFixups DemoBinary"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("native.sourceVersion DemoBinary"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("native.buildVersion DemoBinary"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("native.dylinker DemoBinary"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("native.installName DemoBinary"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("native.uuid DemoBinary"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("native.rpaths DemoBinary"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("native.rpathInfo DemoBinary -- @loader_path"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("native.findRpathInfo DemoBinary -- @loader_path"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("native.imports DemoBinary"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("native.importInfo DemoBinary -- malloc"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("native.findImportInfo DemoBinary -- malloc"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("native.symbolInfo DemoBinary -- malloc"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("native.findSymbolInfo DemoBinary -- malloc"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("native.loadCommandInfo DemoBinary -- LC_UUID"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("native.findLoadCommandInfo DemoBinary -- LC_UUID"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("native.sectionInfo DemoBinary -- __TEXT __text"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("native.findSectionInfo DemoBinary -- __TEXT __text"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("native.segmentInfo DemoBinary -- __TEXT"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("native.findSegmentInfo DemoBinary -- __TEXT"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("native.detectHookEnvironment"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("pac.isProcessArm64e"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("pac.isImageArm64e DemoBinary"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("pac.arm64eImages"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("pac.arm64eImages Demo"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("pac.stripData 0x1234"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("pac.image DemoBinary"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("pac.images"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("swift.protocolInfo Demo -- Renderable"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("swift.findProtocolInfo Demo -- Renderable"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("swift.conformanceInfo Demo -- ViewController Renderable"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("swift.findConformanceInfo Demo -- ViewController Renderable"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("swift.typeInfo Demo -- ViewController"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("swift.findTypeInfo Demo -- ViewController"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("swift.methodInfo Demo -- ViewController viewDidLoad"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("swift.findMethodInfo Demo -- ViewController viewDidLoad"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("swift.symbolInfo Demo -- ViewController"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("swift.findSymbolInfo Demo -- ViewController"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("swift.protocols"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("swift.conformances ViewController"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("swift.metadata ViewController"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("swift.metadataInfo Demo -- ViewController"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("swift.findMetadataInfo Demo -- ViewController"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("swift.vtable ViewController"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("swift.vtableInfo Demo -- ViewController viewDidLoad"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("swift.findVtableInfo Demo -- ViewController viewDidLoad"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("swift.witnessTable Renderable"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("swift.witnessTableInfo Demo -- ViewController Renderable"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("swift.findWitnessTableInfo Demo -- ViewController Renderable"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("swift.typeLayout ViewController"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("swift.typeLayoutInfo Demo -- ViewController"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("swift.findTypeLayoutInfo Demo -- ViewController"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("swift.typeMethods ViewController"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("swift.typesOfKind metadata-accessor ViewController"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("swift.typeSourceKinds"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("swift.typeKinds"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("swift.methodOwners viewDidLoad"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert_eq!(AgentCommand::from_legacy("trace UIViewController"), None);
    }

    #[test]
    fn command_requires_inline_hooks_only_for_hook_commands() {
        assert!(command_requires_inline_hooks("trace UIViewController"));
        assert!(command_requires_inline_hooks("stalker stop"));
        assert!(command_requires_inline_hooks("jhook UIViewController viewDidLoad"));
        assert!(command_requires_inline_hooks("shook Demo -- Foo bar"));
        assert!(command_requires_inline_hooks("hfl libobjc.A.dylib 0x1234"));
        assert!(!command_requires_inline_hooks("objc.classes UIView"));
        assert!(!command_requires_inline_hooks("objc.findClasses UIView"));
        assert!(!command_requires_inline_hooks("objc.protocols NS"));
        assert!(!command_requires_inline_hooks("objc.classProtocols UIView"));
        assert!(!command_requires_inline_hooks("objc.classProtocols UIView UI"));
        assert!(!command_requires_inline_hooks("objc.findClassProtocols UIView UI"));
        assert!(!command_requires_inline_hooks("objc.classInfo UIView meta"));
        assert!(!command_requires_inline_hooks("objc.findClassInfo UIView meta"));
        assert!(!command_requires_inline_hooks("objc.protocolInfo NSObject"));
        assert!(!command_requires_inline_hooks("objc.findProtocolInfo NSObject"));
        assert!(!command_requires_inline_hooks("objc.protocolProtocols NSObject"));
        assert!(!command_requires_inline_hooks("objc.protocolProtocols NSObject NS"));
        assert!(!command_requires_inline_hooks("objc.findProtocolProtocols NSObject NS"));
        assert!(!command_requires_inline_hooks(
            "objc.protocolMethods NSObject optional class"
        ));
        assert!(!command_requires_inline_hooks(
            "objc.protocolMethods NSObject optional class description"
        ));
        assert!(!command_requires_inline_hooks(
            "objc.findProtocolMethods NSObject optional class description"
        ));
        assert!(!command_requires_inline_hooks(
            "objc.protocolMethodInfo NSObject description optional class"
        ));
        assert!(!command_requires_inline_hooks(
            "objc.findProtocolMethodInfo NSObject description optional class"
        ));
        assert!(!command_requires_inline_hooks("objc.protocolProperties NSObject"));
        assert!(!command_requires_inline_hooks("objc.protocolProperties NSObject description"));
        assert!(!command_requires_inline_hooks(
            "objc.findProtocolProperties NSObject description"
        ));
        assert!(!command_requires_inline_hooks(
            "objc.protocolPropertyInfo NSObject description"
        ));
        assert!(!command_requires_inline_hooks(
            "objc.findProtocolPropertyInfo NSObject description"
        ));
        assert!(!command_requires_inline_hooks("objc.superclass UIView"));
        assert!(!command_requires_inline_hooks("objc.findSuperclass UIView"));
        assert!(!command_requires_inline_hooks("objc.classChain UIView"));
        assert!(!command_requires_inline_hooks("objc.findClassChain UIView"));
        assert!(!command_requires_inline_hooks("objc.properties UIView meta delegate"));
        assert!(!command_requires_inline_hooks("objc.propertyInfo UIView view"));
        assert!(!command_requires_inline_hooks("objc.findPropertyInfo UIView view"));
        assert!(!command_requires_inline_hooks("objc.ivarInfo UIView _viewFlags"));
        assert!(!command_requires_inline_hooks("objc.findIvarInfo UIView _viewFlags"));
        assert!(!command_requires_inline_hooks("objc.ivars UIView delegate"));
        assert!(!command_requires_inline_hooks("objc.findMethods UIView init"));
        assert!(!command_requires_inline_hooks("objc.methodInfo UIView viewDidLoad"));
        assert!(!command_requires_inline_hooks("objc.findMethodInfo UIView viewDidLoad"));
        assert!(!command_requires_inline_hooks("objc.findClassImage UIView"));
        assert!(!command_requires_inline_hooks("objc.findMethodImage UIView viewDidLoad"));
        assert!(!command_requires_inline_hooks("objc.findSelectorName 0x1234"));
        assert!(!command_requires_inline_hooks("objc.findObjectClassName 0x1234"));
        assert!(!command_requires_inline_hooks("native.imageInfo UIKit"));
        assert!(!command_requires_inline_hooks("native.findImageInfo UIKit"));
        assert!(!command_requires_inline_hooks("native.images UIKit"));
        assert!(!command_requires_inline_hooks("native.dependencies UIKit"));
        assert!(!command_requires_inline_hooks("native.findSymbols malloc"));
        assert!(!command_requires_inline_hooks("native.findDyldInfo UIKit"));
        assert!(!command_requires_inline_hooks("native.findLoadCommands UIKit"));
        assert!(!command_requires_inline_hooks("native.loadCommands UIKit"));
        assert!(!command_requires_inline_hooks("native.detectHookEnvironment"));
        assert!(!command_requires_inline_hooks("pac.isProcessArm64e"));
        assert!(!command_requires_inline_hooks("pac.isImageArm64e UIKit"));
        assert!(!command_requires_inline_hooks("pac.arm64eImages UIKit"));
        assert!(!command_requires_inline_hooks("pac.stripData 0x1234"));
        assert!(!command_requires_inline_hooks("native.findImports UIKit -- malloc"));
        assert!(!command_requires_inline_hooks("native.exportInfo UIKit -- malloc"));
        assert!(!command_requires_inline_hooks("native.findExportInfo UIKit -- malloc"));
        assert!(!command_requires_inline_hooks(
            "native.dependencyInfo UIKit -- libSystem.B.dylib"
        ));
        assert!(!command_requires_inline_hooks(
            "native.findDependencyInfo UIKit -- libSystem.B.dylib"
        ));
        assert!(!command_requires_inline_hooks("native.encryptionInfo UIKit"));
        assert!(!command_requires_inline_hooks("native.entryPoint UIKit"));
        assert!(!command_requires_inline_hooks("native.dyldInfo UIKit"));
        assert!(!command_requires_inline_hooks("native.linkedit UIKit"));
        assert!(!command_requires_inline_hooks("native.functionStarts UIKit"));
        assert!(!command_requires_inline_hooks("native.codeSignature UIKit"));
        assert!(!command_requires_inline_hooks("native.dataInCode UIKit"));
        assert!(!command_requires_inline_hooks("native.exportsTrie UIKit"));
        assert!(!command_requires_inline_hooks("native.chainedFixups UIKit"));
        assert!(!command_requires_inline_hooks("native.sourceVersion UIKit"));
        assert!(!command_requires_inline_hooks("native.buildVersion UIKit"));
        assert!(!command_requires_inline_hooks("native.dylinker UIKit"));
        assert!(!command_requires_inline_hooks("native.installName UIKit"));
        assert!(!command_requires_inline_hooks("native.uuid UIKit"));
        assert!(!command_requires_inline_hooks("native.rpaths UIKit"));
        assert!(!command_requires_inline_hooks("native.rpathInfo UIKit -- @loader_path"));
        assert!(!command_requires_inline_hooks("native.findRpathInfo UIKit -- @loader_path"));
        assert!(!command_requires_inline_hooks("native.imports UIKit"));
        assert!(!command_requires_inline_hooks("native.importInfo UIKit -- malloc"));
        assert!(!command_requires_inline_hooks("native.findImportInfo UIKit -- malloc"));
        assert!(!command_requires_inline_hooks(
            "native.loadCommandInfo UIKit -- LC_UUID"
        ));
        assert!(!command_requires_inline_hooks(
            "native.findLoadCommandInfo UIKit -- LC_UUID"
        ));
        assert!(!command_requires_inline_hooks(
            "native.sectionInfo UIKit -- __TEXT __text"
        ));
        assert!(!command_requires_inline_hooks(
            "native.findSectionInfo UIKit -- __TEXT __text"
        ));
        assert!(!command_requires_inline_hooks("native.segmentInfo UIKit -- __TEXT"));
        assert!(!command_requires_inline_hooks("native.findSegmentInfo UIKit -- __TEXT"));
        assert!(!command_requires_inline_hooks("native.symbolInfo malloc"));
        assert!(!command_requires_inline_hooks("native.findSymbolInfo malloc"));
        assert!(!command_requires_inline_hooks("swift.protocolInfo Renderable"));
        assert!(!command_requires_inline_hooks("swift.findProtocolInfo Renderable"));
        assert!(!command_requires_inline_hooks(
            "swift.conformanceInfo ViewController Renderable"
        ));
        assert!(!command_requires_inline_hooks(
            "swift.findConformanceInfo ViewController Renderable"
        ));
        assert!(!command_requires_inline_hooks("swift.typeInfo ViewController"));
        assert!(!command_requires_inline_hooks("swift.findTypeInfo ViewController"));
        assert!(!command_requires_inline_hooks(
            "swift.methodInfo ViewController viewDidLoad"
        ));
        assert!(!command_requires_inline_hooks(
            "swift.findMethodInfo ViewController viewDidLoad"
        ));
        assert!(!command_requires_inline_hooks("swift.symbolInfo ViewController"));
        assert!(!command_requires_inline_hooks("swift.findSymbolInfo ViewController"));
        assert!(!command_requires_inline_hooks("swift.protocols"));
        assert!(!command_requires_inline_hooks("swift.conformances ViewController"));
        assert!(!command_requires_inline_hooks("swift.metadata ViewController"));
        assert!(!command_requires_inline_hooks("swift.metadataInfo ViewController"));
        assert!(!command_requires_inline_hooks("swift.findMetadataInfo ViewController"));
        assert!(!command_requires_inline_hooks("swift.vtable ViewController"));
        assert!(!command_requires_inline_hooks(
            "swift.vtableInfo ViewController viewDidLoad"
        ));
        assert!(!command_requires_inline_hooks(
            "swift.findVtableInfo ViewController viewDidLoad"
        ));
        assert!(!command_requires_inline_hooks("swift.witnessTable Renderable"));
        assert!(!command_requires_inline_hooks(
            "swift.witnessTableInfo ViewController Renderable"
        ));
        assert!(!command_requires_inline_hooks(
            "swift.findWitnessTableInfo ViewController Renderable"
        ));
        assert!(!command_requires_inline_hooks("swift.typeLayout ViewController"));
        assert!(!command_requires_inline_hooks("swift.typeLayoutInfo ViewController"));
        assert!(!command_requires_inline_hooks("swift.findTypeLayoutInfo ViewController"));
        assert!(!command_requires_inline_hooks("swift.types ViewController"));
        assert!(!command_requires_inline_hooks("swift.findTypes ViewController"));
        assert!(!command_requires_inline_hooks(
            "swift.findMethods ViewController viewDidLoad"
        ));
    }

    #[test]
    fn command_requests_inline_hook_install_distinguishes_install_from_stop_and_status() {
        assert!(command_requests_inline_hook_install("trace UIViewController").expect("trace install"));
        assert!(command_requests_inline_hook_install("stalker native malloc").expect("stalker install"));
        assert!(command_requests_inline_hook_install("jhook UIViewController viewDidLoad").expect("jhook install"));
        assert!(command_requests_inline_hook_install("shook ViewController viewDidLoad").expect("shook install"));
        assert!(command_requests_inline_hook_install("hfl libobjc.A.dylib 0x1234").expect("hfl install"));
        assert!(!command_requests_inline_hook_install("trace stop").expect("trace stop"));
        assert!(!command_requests_inline_hook_install("trace stop native malloc").expect("trace targeted stop"));
        assert!(!command_requests_inline_hook_install("trace status").expect("trace status"));
        assert!(!command_requests_inline_hook_install("stalker status").expect("stalker status"));
        assert!(!command_requests_inline_hook_install("stalker stop addr 0x1234").expect("stalker targeted stop"));
        assert!(!command_requests_inline_hook_install("jhook status").expect("jhook status"));
        assert!(
            !command_requests_inline_hook_install("jhook stop UIViewController viewDidLoad")
                .expect("jhook targeted stop")
        );
        assert!(!command_requests_inline_hook_install("shook stop").expect("shook stop"));
        assert!(
            !command_requests_inline_hook_install("shook stop Demo -- ViewController viewDidLoad")
                .expect("shook targeted stop")
        );
        assert!(!command_requests_inline_hook_install("hfl status").expect("hfl status"));
        assert!(!command_requests_inline_hook_install("hfl stop libobjc.A.dylib 0x1234").expect("hfl targeted stop"));
    }

    #[test]
    fn query_only_hook_policy_still_allows_runtime_query_commands() {
        let environment = InjectionEnvironmentReport {
            dry_run: false,
            bootstrap_wait_ms: Some(3000),
            hook_policy: HookPolicy::QueryOnlyExternalLoaded,
            hook_strategy: HookStrategyDecision {
                policy: HookPolicy::QueryOnlyExternalLoaded,
                strategy: "query-only-external-loaded".into(),
                allowed: true,
                inline_hooks_allowed: false,
                reason: Some("controller query-only".into()),
            },
            hook_environment: HookEnvironmentReport {
                active_backend: Some("ellekit".into()),
                backends: vec![HookBackendInfo {
                    id: "ellekit".into(),
                    display_name: "ElleKit".into(),
                    loaded_images: vec!["/usr/lib/libellekit.dylib".into()],
                    filesystem_paths: vec![],
                }],
                warnings: vec!["external hook ecosystem detected".into()],
            },
        };
        let preflight = InjectionTargetPreflightReport {
            main_image: None,
            target_images: vec![],
            target_image_count: 0,
            target_uses_arm64e: Some(false),
            thread_bootstrap_kind: ThreadBootstrapKind::PthreadCreateFromMachThread,
            thread_bootstrap_label: "pthread_create_from_mach_thread".into(),
            thread_bootstrap_address: 0,
            thread_bootstrap_raw_address: 0,
            thread_bootstrap_canonicalized: false,
            target_hook_environment: HookEnvironmentReport {
                active_backend: None,
                backends: vec![],
                warnings: vec![],
            },
            target_hook_strategy: HookStrategyDecision {
                policy: HookPolicy::Warn,
                strategy: "internal-inline".into(),
                allowed: true,
                inline_hooks_allowed: true,
                reason: None,
            },
            resolved_loader_symbols: vec![],
        };

        ensure_inline_hooks_allowed_for_command("objc.classes UIView", &environment, &preflight)
            .expect("query command should stay allowed");
        ensure_inline_hooks_allowed_for_command("trace status", &environment, &preflight)
            .expect("status command should stay allowed");
        ensure_inline_hooks_allowed_for_command("trace stop", &environment, &preflight)
            .expect("stop command should stay allowed");
    }

    #[test]
    fn deny_hook_policy_allows_cleanup_commands_but_blocks_query_and_install() {
        let environment = InjectionEnvironmentReport {
            dry_run: false,
            bootstrap_wait_ms: Some(3000),
            hook_policy: HookPolicy::DenyExternalLoaded,
            hook_strategy: HookStrategyDecision {
                policy: HookPolicy::DenyExternalLoaded,
                strategy: "cleanup-only-external-loaded".into(),
                allowed: false,
                inline_hooks_allowed: false,
                reason: Some("controller cleanup-only".into()),
            },
            hook_environment: HookEnvironmentReport {
                active_backend: Some("ellekit".into()),
                backends: vec![HookBackendInfo {
                    id: "ellekit".into(),
                    display_name: "ElleKit".into(),
                    loaded_images: vec!["/usr/lib/libellekit.dylib".into()],
                    filesystem_paths: vec![],
                }],
                warnings: vec!["external hook ecosystem detected".into()],
            },
        };
        let preflight = InjectionTargetPreflightReport {
            main_image: None,
            target_images: vec![],
            target_image_count: 0,
            target_uses_arm64e: Some(false),
            thread_bootstrap_kind: ThreadBootstrapKind::PthreadCreateFromMachThread,
            thread_bootstrap_label: "pthread_create_from_mach_thread".into(),
            thread_bootstrap_address: 0,
            thread_bootstrap_raw_address: 0,
            thread_bootstrap_canonicalized: false,
            target_hook_environment: HookEnvironmentReport {
                active_backend: Some("substrate".into()),
                backends: vec![HookBackendInfo {
                    id: "substrate".into(),
                    display_name: "Cydia Substrate".into(),
                    loaded_images: vec!["/Library/MobileSubstrate/MobileSubstrate.dylib".into()],
                    filesystem_paths: vec![],
                }],
                warnings: vec!["external hook ecosystem detected".into()],
            },
            target_hook_strategy: HookStrategyDecision {
                policy: HookPolicy::DenyExternalLoaded,
                strategy: "cleanup-only-external-loaded".into(),
                allowed: false,
                inline_hooks_allowed: false,
                reason: Some("target cleanup-only".into()),
            },
            resolved_loader_symbols: vec![],
        };

        ensure_inline_hooks_allowed_for_command("trace status", &environment, &preflight)
            .expect("status command should stay allowed in cleanup-only mode");
        ensure_inline_hooks_allowed_for_command("trace stop", &environment, &preflight)
            .expect("stop command should stay allowed in cleanup-only mode");

        let query_err = ensure_inline_hooks_allowed_for_command("objc.classes UIView", &environment, &preflight)
            .expect_err("runtime query should be blocked in cleanup-only mode");
        assert!(query_err.to_string().contains("runtime query command"));
        assert!(query_err.to_string().contains("hook-effective-blocked"));
        assert!(query_err.to_string().contains("blockedBy=both"));
        assert!(query_err.to_string().contains("commandMode=cleanup-only"));
        assert!(query_err.to_string().contains("baseCommandMode=cleanup-only"));
        assert!(query_err.to_string().contains("effectiveCommandMode=cleanup-only"));
        assert!(query_err
            .to_string()
            .contains("autoDowngradedToQueryOnly=false"));
        assert!(query_err
            .to_string()
            .contains("autoDowngradeReason=<none>"));
        assert!(query_err.to_string().contains("coexistenceMode=cleanup-only"));
        assert!(query_err.to_string().contains("backendPressure=both"));
        assert!(query_err.to_string().contains("fallbackActionKey=hook.status"));
        assert!(query_err
            .to_string()
            .contains("fallbackStepId=next-action:hook.status:0"));
        assert!(query_err.to_string().contains("fallbackCommand=trace status"));
        assert!(query_err.to_string().contains("fallbackPhase=cleanup"));

        let install_err = ensure_inline_hooks_allowed_for_command("trace UIViewController", &environment, &preflight)
            .expect_err("hook install should be blocked in cleanup-only mode");
        assert!(install_err.to_string().contains("forbids hook-install commands"));
        assert!(install_err.to_string().contains("blockedBy=both"));
        assert!(install_err.to_string().contains("commandMode=cleanup-only"));
        assert!(install_err
            .to_string()
            .contains("baseCommandMode=cleanup-only"));
        assert!(install_err
            .to_string()
            .contains("effectiveCommandMode=cleanup-only"));
        assert!(install_err
            .to_string()
            .contains("autoDowngradedToQueryOnly=false"));
        assert!(install_err
            .to_string()
            .contains("autoDowngradeReason=<none>"));
        assert!(install_err.to_string().contains("coexistenceMode=cleanup-only"));
        assert!(install_err.to_string().contains("backendPressure=both"));
        assert!(install_err.to_string().contains("fallbackActionKey=hook.status"));
        assert!(install_err
            .to_string()
            .contains("fallbackStepId=next-action:hook.status:0"));
        assert!(install_err.to_string().contains("fallbackCommand=trace status"));
        assert!(install_err.to_string().contains("fallbackPhase=cleanup"));
    }

    #[test]
    fn query_only_hook_policy_blocks_hook_commands_before_dispatch() {
        let environment = InjectionEnvironmentReport {
            dry_run: false,
            bootstrap_wait_ms: Some(3000),
            hook_policy: HookPolicy::QueryOnlyExternalLoaded,
            hook_strategy: HookStrategyDecision {
                policy: HookPolicy::QueryOnlyExternalLoaded,
                strategy: "query-only-external-loaded".into(),
                allowed: true,
                inline_hooks_allowed: false,
                reason: Some("external backend already loaded in controller".into()),
            },
            hook_environment: HookEnvironmentReport {
                active_backend: Some("ellekit".into()),
                backends: vec![HookBackendInfo {
                    id: "ellekit".into(),
                    display_name: "ElleKit".into(),
                    loaded_images: vec!["/usr/lib/libellekit.dylib".into()],
                    filesystem_paths: vec![],
                }],
                warnings: vec!["external hook ecosystem detected".into()],
            },
        };
        let preflight = InjectionTargetPreflightReport {
            main_image: None,
            target_images: vec![],
            target_image_count: 0,
            target_uses_arm64e: Some(false),
            thread_bootstrap_kind: ThreadBootstrapKind::PthreadCreateFromMachThread,
            thread_bootstrap_label: "pthread_create_from_mach_thread".into(),
            thread_bootstrap_address: 0,
            thread_bootstrap_raw_address: 0,
            thread_bootstrap_canonicalized: false,
            target_hook_environment: HookEnvironmentReport {
                active_backend: Some("substrate".into()),
                backends: vec![HookBackendInfo {
                    id: "substrate".into(),
                    display_name: "Cydia Substrate".into(),
                    loaded_images: vec!["/Library/MobileSubstrate/MobileSubstrate.dylib".into()],
                    filesystem_paths: vec![],
                }],
                warnings: vec!["external hook ecosystem detected".into()],
            },
            target_hook_strategy: HookStrategyDecision {
                policy: HookPolicy::QueryOnlyExternalLoaded,
                strategy: "query-only-external-loaded".into(),
                allowed: true,
                inline_hooks_allowed: false,
                reason: Some("external backend already loaded in target".into()),
            },
            resolved_loader_symbols: vec![],
        };

        let err = ensure_inline_hooks_allowed_for_command("trace UIViewController", &environment, &preflight)
            .expect_err("hook command must be rejected before dispatch");
        let rendered = err.to_string();
        assert!(rendered.contains("requires inline hooks"));
        assert!(rendered.contains("query-only"));
        assert!(rendered.contains("hook-effective-blocked"));
        assert!(rendered.contains("blockedBy=both"));
        assert!(rendered.contains("commandMode=query-only"));
        assert!(rendered.contains("baseCommandMode=query-only"));
        assert!(rendered.contains("effectiveCommandMode=query-only"));
        assert!(rendered.contains("autoDowngradedToQueryOnly=false"));
        assert!(rendered.contains("autoDowngradeReason=<none>"));
        assert!(rendered.contains("coexistenceMode=query-only"));
        assert!(rendered.contains("backendPressure=both"));
        assert!(rendered.contains("fallbackActionKey=hook.query"));
        assert!(rendered.contains("fallbackStepId=next-action:hook.query:0"));
        assert!(rendered.contains("fallbackCommand=objc.classes <filter>"));
        assert!(rendered.contains("fallbackPhase=query"));
        assert!(rendered.contains("controller policy=query-only-external-loaded"));
        assert!(rendered.contains("target policy=query-only-external-loaded"));
    }

    #[test]
    fn parse_hfl_accepts_decimal_offset() {
        assert_eq!(
            parse_hfl_command("hfl libobjc.A.dylib 4660").expect("parse hfl"),
            HflCommand::Install {
                module_name: "libobjc.A.dylib".into(),
                offset: 4660,
            }
        );
    }

    #[test]
    fn parse_hfl_rejects_missing_arguments() {
        let err = parse_hfl_command("hfl libobjc.A.dylib").expect_err("missing args must fail");
        assert!(err.to_string().contains("hfl usage"));
    }

    #[test]
    fn quote_js_string_escapes_control_characters() {
        let quoted = quote_js_string("a\"b\\c\n");
        assert_eq!(quoted, "\"a\\\"b\\\\c\\n\"");
    }

    #[test]
    fn render_loader_symbol_includes_raw_and_canonical_when_needed() {
        let rendered = render_loader_symbol(&ResolvedLoaderSymbol {
            role: LoaderSymbolRole::ThreadBootstrap,
            symbol_name: "pthread_create_from_mach_thread".into(),
            module_name: "/usr/lib/system/libsystem_pthread.dylib".into(),
            module_base: 0x1801_0000_0,
            raw_address: 0xabcd_0001_8010_0abc,
            address: 0x1801_0abc,
            offset: 0xabc,
        });

        assert!(rendered.contains("kind=pthread-create-from-mach-thread"));
        assert!(rendered.contains("raw=0xabcd000180100abc"));
        assert!(rendered.contains("canonical=0x18010abc"));
    }

    #[test]
    fn print_injection_preflight_is_callable() {
        print_injection_preflight(&InjectionTargetPreflightReport {
            main_image: Some(native_api::ImageInfo {
                name: "/Applications/Test.app/Test".into(),
                base: 0x1000_0000_0,
                slide: 0,
                size: 0x4000,
            }),
            target_images: vec![
                native_api::ImageInfo {
                    name: "/Applications/Test.app/Test".into(),
                    base: 0x1000_0000_0,
                    slide: 0,
                    size: 0x4000,
                },
                native_api::ImageInfo {
                    name: "/usr/lib/libobjc.A.dylib".into(),
                    base: 0x1800_0000_0,
                    slide: 0,
                    size: 0x8000,
                },
            ],
            target_image_count: 42,
            target_uses_arm64e: Some(true),
            thread_bootstrap_kind: ThreadBootstrapKind::PthreadCreateFromMachThread,
            thread_bootstrap_label: "/usr/lib/system/libsystem_pthread.dylib!pthread_create_from_mach_thread+0xabc"
                .into(),
            thread_bootstrap_address: 0x1801_0abc,
            thread_bootstrap_raw_address: 0xabcd_0001_8010_0abc,
            thread_bootstrap_canonicalized: true,
            target_hook_environment: HookEnvironmentReport {
                active_backend: Some("ellekit".into()),
                backends: vec![HookBackendInfo {
                    id: "ellekit".into(),
                    display_name: "ElleKit".into(),
                    loaded_images: vec!["/usr/lib/libellekit.dylib".into()],
                    filesystem_paths: vec![],
                }],
                warnings: vec!["external hook ecosystem detected".into()],
            },
            target_hook_strategy: HookStrategyDecision {
                policy: HookPolicy::Warn,
                strategy: "internal-inline-risky".into(),
                allowed: true,
                inline_hooks_allowed: true,
                reason: Some("external hook backend is already loaded".into()),
            },
            resolved_loader_symbols: vec![],
        });
    }

    #[test]
    fn render_preflight_json_contains_environment_plan_and_preflight() {
        let config = ControllerConfig {
            mode: InjectionMode::Attach,
            pid: Some(42),
            bundle_id: None,
            spawn_command: None,
            command: None,
            command_json: false,
            list_images_json: false,
            preflight_only: true,
            preflight_json: true,
            inject_json: false,
            agent_path: DEFAULT_AGENT_PATH_ROOTFUL.into(),
            entry_symbol: "ios_agent_entry".into(),
            script_path: None,
            socket_path: Some("/tmp/iosrf.sock".into()),
            connect_timeout_secs: 15,
        };
        let plan = MachInjector
            .plan(&InjectionTarget {
                pid: 42,
                dylib_path: DEFAULT_AGENT_PATH_ROOTFUL.into(),
                entry_symbol: "ios_agent_entry".into(),
                socket_path: "/tmp/iosrf.sock".into(),
            })
            .expect("build plan");
        let environment = InjectionEnvironmentReport {
            dry_run: false,
            bootstrap_wait_ms: Some(3000),
            hook_policy: HookPolicy::Warn,
            hook_strategy: HookStrategyDecision {
                policy: HookPolicy::Warn,
                strategy: "internal-inline-risky".into(),
                allowed: true,
                inline_hooks_allowed: true,
                reason: Some("external hook backend is already loaded".into()),
            },
            hook_environment: HookEnvironmentReport {
                active_backend: Some("ellekit".into()),
                backends: vec![HookBackendInfo {
                    id: "ellekit".into(),
                    display_name: "ElleKit".into(),
                    loaded_images: vec!["/usr/lib/libellekit.dylib".into()],
                    filesystem_paths: vec![],
                }],
                warnings: vec!["external hook ecosystem detected".into()],
            },
        };
        let preflight = InjectionTargetPreflightReport {
            main_image: Some(native_api::ImageInfo {
                name: "/Applications/Test.app/Test".into(),
                base: 0x1000_0000,
                slide: 0,
                size: 0x4000,
            }),
            target_images: vec![
                native_api::ImageInfo {
                    name: "/Applications/Test.app/Test".into(),
                    base: 0x1000_0000,
                    slide: 0,
                    size: 0x4000,
                },
                native_api::ImageInfo {
                    name: "/usr/lib/libobjc.A.dylib".into(),
                    base: 0x1800_0000,
                    slide: 0,
                    size: 0x8000,
                },
            ],
            target_image_count: 7,
            target_uses_arm64e: Some(true),
            thread_bootstrap_kind: ThreadBootstrapKind::PthreadCreateFromMachThread,
            thread_bootstrap_label: "/usr/lib/system/libsystem_pthread.dylib!pthread_create_from_mach_thread+0x123"
                .into(),
            thread_bootstrap_address: 0x1800_0123,
            thread_bootstrap_raw_address: 0xabcd_0000_1800_0123,
            thread_bootstrap_canonicalized: true,
            target_hook_environment: environment.hook_environment.clone(),
            target_hook_strategy: environment.hook_strategy.clone(),
            resolved_loader_symbols: vec![ResolvedLoaderSymbol {
                role: LoaderSymbolRole::ThreadBootstrap,
                symbol_name: "pthread_create_from_mach_thread".into(),
                module_name: "/usr/lib/system/libsystem_pthread.dylib".into(),
                module_base: 0x1800_0000,
                raw_address: 0xabcd_0000_1800_0123,
                address: 0x1800_0123,
                offset: 0x123,
            }],
        };

        let doctor = analyze_doctor_report(&config, 42, Path::new("/tmp/iosrf.sock"), &environment, &preflight);
        let rendered = render_preflight_json(&config, 42, "/tmp/iosrf.sock", &plan, &environment, &preflight, &doctor);

        assert_eq!(rendered["mode"], "attach");
        assert_eq!(rendered["preflightOnly"], true);
        assert_eq!(rendered["environment"]["hookPolicy"], "warn");
        assert_eq!(rendered["environment"]["hookStrategy"]["commandMode"], "allowed");
        assert!(rendered["environment"]["hookEnvironment"]["recommendedActions"].is_array());
        assert_eq!(rendered["environment"]["hookEnvironment"]["coexistenceMode"], "inline-risky");
        assert_eq!(
            rendered["environment"]["hookEnvironment"]["coexistenceRecommendation"],
            "external backend already loaded; prefer query/status first, then inline install only if necessary"
        );
        assert_eq!(
            rendered["environment"]["hookEnvironment"]["coexistenceLayerStatus"],
            "missing-inline-risky"
        );
        assert_eq!(rendered["environment"]["hookEnvironment"]["coexistenceLayerAvailable"], false);
        assert_eq!(rendered["environment"]["hookEnvironment"]["externalBackendLoaded"], true);
        assert_eq!(rendered["environment"]["hookEnvironment"]["singleExternalBackendLoaded"], true);
        assert_eq!(
            rendered["environment"]["hookEnvironment"]["multipleExternalBackendsLoaded"],
            false
        );
        assert_eq!(rendered["doctor"]["ready"], false);
        assert_eq!(rendered["plan"]["target"]["pid"], 42);
        assert_eq!(rendered["plan"]["bootstrap"]["stackSizeHex"], json!("0x4000"));
        assert_eq!(
            rendered["preflight"]["targetImages"][1]["path"],
            "/usr/lib/libobjc.A.dylib"
        );
        assert_eq!(rendered["preflight"]["targetImages"][1]["name"], "libobjc.A.dylib");
        assert_eq!(rendered["preflight"]["targetImages"][1]["sizeHex"], json!("0x8000"));
        assert_eq!(rendered["preflight"]["loaderSymbolChecks"]["total"], 1);
        assert_eq!(rendered["preflight"]["loaderSymbolChecks"]["allImagesFound"], false);
        assert_eq!(rendered["preflight"]["loaderSymbolChecks"]["allAddressesMatch"], false);
        assert_eq!(rendered["preflight"]["targetUsesArm64e"], true);
        assert_eq!(
            rendered["preflight"]["resolvedLoaderSymbols"][0]["threadBootstrapKind"],
            "pthread-create-from-mach-thread"
        );
        assert_eq!(rendered["preflight"]["threadBootstrapAddressHex"], json!("0x18000123"));
    }

    #[test]
    fn render_image_list_json_contains_image_count_and_rows() {
        let rendered = render_image_list_json(&[
            native_api::ImageInfo {
                name: "/usr/lib/libobjc.A.dylib".into(),
                base: 0x1800_0000,
                slide: 0,
                size: 0x6000,
            },
            native_api::ImageInfo {
                name: "/usr/lib/libsystem_kernel.dylib".into(),
                base: 0x1810_0000,
                slide: 0x2000,
                size: 0x9000,
            },
        ]);

        assert_eq!(rendered["imageCount"], 2);
        assert_eq!(rendered["images"][0]["path"], "/usr/lib/libobjc.A.dylib");
        assert_eq!(rendered["images"][1]["baseHex"], json!("0x18100000"));
        assert_eq!(rendered["images"][1]["slideHex"], json!("0x2000"));
        assert_eq!(rendered["images"][1]["sizeHex"], json!("0x9000"));
    }

    #[test]
    fn render_command_outcome_json_parses_json_payload() {
        let rendered = render_command_outcome_json(&CommandOutcome {
            command: "objc.classes".into(),
            kind: CommandOutcomeKind::Eval,
            ok: true,
            payload: Some("{\"classes\":[\"UIView\"]}".into()),
            items: vec![],
            error: None,
            logs: vec!["runtime ready".into()],
        });

        assert_eq!(rendered["ok"], true);
        assert_eq!(rendered["command"], "objc.classes");
        assert_eq!(rendered["kind"], "eval");
        assert_eq!(rendered["payloadJson"]["classes"][0], "UIView");
        assert_eq!(rendered["logs"][0], "runtime ready");
    }

    #[test]
    fn render_command_error_json_contains_kind_message_and_logs() {
        let rendered = render_command_error_json(
            "trace stop",
            &Error::Unsupported("not available on this platform".into()),
            &["bootstrap pending".into()],
        );

        assert_eq!(rendered["ok"], false);
        assert_eq!(rendered["command"], "trace stop");
        assert_eq!(rendered["errorKind"], "unsupported");
        assert_eq!(rendered["logs"][0], "bootstrap pending");
    }

    #[test]
    fn render_command_error_json_with_context_contains_doctor_and_preflight() {
        let config = ControllerConfig {
            mode: InjectionMode::Attach,
            pid: Some(42),
            bundle_id: None,
            spawn_command: None,
            command: Some("objc.classes UIView".into()),
            command_json: true,
            list_images_json: false,
            preflight_only: false,
            preflight_json: false,
            inject_json: false,
            agent_path: LEGACY_AGENT_PATH_ROOTFUL.into(),
            entry_symbol: "ios_agent_entry".into(),
            script_path: None,
            socket_path: Some("/tmp/iosrf.sock".into()),
            connect_timeout_secs: 15,
        };
        let plan = MachInjector
            .plan(&InjectionTarget {
                pid: 42,
                dylib_path: DEFAULT_AGENT_PATH.into(),
                entry_symbol: "ios_agent_entry".into(),
                socket_path: "/tmp/iosrf.sock".into(),
            })
            .expect("build plan");
        let environment = InjectionEnvironmentReport {
            dry_run: false,
            bootstrap_wait_ms: Some(3000),
            hook_policy: HookPolicy::Warn,
            hook_strategy: HookStrategyDecision {
                policy: HookPolicy::Warn,
                strategy: "internal-inline".into(),
                allowed: true,
                inline_hooks_allowed: true,
                reason: None,
            },
            hook_environment: HookEnvironmentReport {
                active_backend: None,
                backends: vec![],
                warnings: vec![],
            },
        };
        let preflight = InjectionTargetPreflightReport {
            main_image: None,
            target_images: vec![],
            target_image_count: 0,
            target_uses_arm64e: Some(false),
            thread_bootstrap_kind: ThreadBootstrapKind::PthreadCreateFromMachThread,
            thread_bootstrap_label: "pthread_create_from_mach_thread".into(),
            thread_bootstrap_address: 0,
            thread_bootstrap_raw_address: 0,
            thread_bootstrap_canonicalized: false,
            target_hook_environment: HookEnvironmentReport {
                active_backend: None,
                backends: vec![],
                warnings: vec![],
            },
            target_hook_strategy: HookStrategyDecision {
                policy: HookPolicy::Warn,
                strategy: "internal-inline".into(),
                allowed: true,
                inline_hooks_allowed: true,
                reason: None,
            },
            resolved_loader_symbols: vec![],
        };
        let doctor = analyze_doctor_report(&config, 42, Path::new("/tmp/iosrf.sock"), &environment, &preflight);

        let rendered = render_command_error_json_with_context(
            "objc.classes UIView",
            &Error::State("controller socket bind failed: invalid argument".into()),
            &["bootstrap pending".into()],
            &CommandJsonContext {
                config: &config,
                pid: 42,
                socket_path: "/tmp/iosrf.sock",
                plan: &plan,
                injection_environment: &environment,
                doctor: &doctor,
                preflight: &preflight,
                trace: None,
                hello: None,
                ping: None,
                hook_environment_notice: None,
                hook_environment_checked: false,
                jsinit_result: None,
                loadjs_result: None,
            },
        );

        assert_eq!(rendered["ok"], false);
        assert_eq!(rendered["command"], "objc.classes UIView");
        assert_eq!(rendered["doctor"]["failureCount"], 1);
        assert!(rendered["preflight"].is_object());
        assert_eq!(rendered["hook"]["controller"]["commandMode"], "allowed");
        assert_eq!(rendered["hook"]["target"]["commandMode"], "allowed");
        assert!(rendered["hook"]["controller"]["recommendedActions"].is_array());
        assert!(rendered["hook"]["target"]["recommendedActions"].is_array());
        assert!(rendered["hook"]["effectiveActions"].is_array());
        assert_eq!(rendered["hook"]["controller"]["recommendedActions"][0]["commandGroup"], "query");
        assert_eq!(rendered["hook"]["controller"]["recommendedActions"][0]["actionKey"], "hook.query");
        assert_eq!(rendered["hook"]["controller"]["recommendedActions"][0]["priority"], 1);
        assert_eq!(rendered["hook"]["effectiveActions"][0]["actionKey"], "hook.query");
        assert_eq!(rendered["hook"]["effectiveActions"][0]["blockedBy"], "none");
        assert_eq!(rendered["hook"]["effective"]["commandMode"], "allowed");
        assert_eq!(rendered["hook"]["effective"]["blockedBySummary"]["controller"], 0);
        assert_eq!(rendered["hook"]["effective"]["blockedBySummary"]["target"], 0);
        assert_eq!(rendered["hook"]["effective"]["blockedBySummary"]["both"], 0);
        assert!(rendered["hook"]["backendMatrix"]["entries"].is_array());
        assert_eq!(rendered["hook"]["backendMatrix"]["entryCount"], 0);
        assert_eq!(rendered["hook"]["coexistence"]["mode"], "inline-safe");
        assert_eq!(rendered["hook"]["coexistence"]["strategy"], "internal-inline-preferred");
        assert_eq!(rendered["hook"]["coexistence"]["backendPressure"], "none");
        assert_eq!(rendered["hook"]["coexistence"]["externalBackendLoaded"], false);
        assert_eq!(rendered["hook"]["coexistence"]["singleExternalBackendLoaded"], false);
        assert_eq!(
            rendered["hook"]["coexistence"]["multipleExternalBackendsLoaded"],
            false
        );
        assert_eq!(rendered["hook"]["coexistence"]["loadedExternalBackendCount"], 0);
        assert_eq!(rendered["hook"]["coexistence"]["hookInstallAllowed"], true);
        assert_eq!(rendered["hook"]["coexistence"]["nextActionKey"], "hook.query");
        assert_eq!(rendered["hook"]["coexistence"]["nextActionAllowed"], true);
        assert_eq!(rendered["hook"]["coexistence"]["nextActionBlockedBy"], "none");
        assert_eq!(rendered["hook"]["coexistence"]["nextActionBranch"], "run");
        assert_eq!(rendered["hook"]["coexistence"]["nextActionReadyToRun"], true);
        assert_eq!(rendered["hook"]["coexistence"]["nextStepId"], "next-action:hook.query:0");
        assert_eq!(rendered["hook"]["coexistence"]["nextStepActionKey"], "hook.query");
        assert_eq!(rendered["hook"]["coexistence"]["nextStepCommandGroup"], "query");
        assert_eq!(rendered["hook"]["coexistence"]["nextStepAllowed"], true);
        assert_eq!(rendered["hook"]["coexistence"]["nextStepBlockedBy"], "none");
        assert_eq!(rendered["hook"]["coexistence"]["nextStepBranch"], "run");
        assert_eq!(rendered["hook"]["coexistence"]["nextStepCommand"], "objc.classes <filter>");
        assert_eq!(rendered["hook"]["coexistence"]["nextStepPhase"], "query");
        assert_eq!(rendered["hook"]["coexistence"]["nextStepCommandJsonEligible"], true);
        assert_eq!(rendered["hook"]["coexistence"]["nextStepReadyToRun"], true);
        assert_eq!(rendered["hook"]["coexistence"]["nextStepRequiresFallback"], false);
        assert_eq!(
            rendered["hook"]["coexistence"]["nextStep"]["id"],
            "next-action:hook.query:0"
        );
        assert_eq!(rendered["hook"]["coexistence"]["nextStep"]["actionKey"], "hook.query");
        assert_eq!(
            rendered["hook"]["coexistence"]["nextStep"]["command"],
            "objc.classes <filter>"
        );
        assert_eq!(rendered["hook"]["coexistence"]["nextStep"]["phase"], "query");
        assert_eq!(rendered["hook"]["coexistence"]["nextStep"]["readyToRun"], true);
        assert_eq!(
            rendered["hook"]["coexistence"]["nextStepKind"],
            rendered["hook"]["coexistence"]["nextStep"]["commandJsonTemplate"]["kind"]
        );
        assert_eq!(
            rendered["hook"]["coexistence"]["nextStepRetryable"],
            rendered["hook"]["coexistence"]["nextStep"]["commandJsonTemplate"]["retryable"]
        );
        assert_eq!(
            rendered["hook"]["coexistence"]["nextStepMaxSuggestedRetries"],
            rendered["hook"]["coexistence"]["nextStep"]["commandJsonTemplate"]["maxSuggestedRetries"]
        );
        assert_eq!(
            rendered["hook"]["coexistence"]["nextStepRetryDelayHintMs"],
            rendered["hook"]["coexistence"]["nextStep"]["commandJsonTemplate"]["retryDelayHintMs"]
        );
        assert_eq!(
            rendered["hook"]["coexistence"]["nextStepTimeoutHintMs"],
            rendered["hook"]["coexistence"]["nextStep"]["commandJsonTemplate"]["timeoutHintMs"]
        );
        assert_eq!(
            rendered["hook"]["coexistence"]["nextStepTimeoutAction"],
            rendered["hook"]["coexistence"]["nextStep"]["commandJsonTemplate"]["timeoutAction"]
        );
        assert_eq!(
            rendered["hook"]["coexistence"]["nextStepErrorCode"],
            rendered["hook"]["coexistence"]["nextStep"]["commandJsonTemplate"]["errorCode"]
        );
        assert_eq!(
            rendered["hook"]["coexistence"]["nextStepTimeoutErrorCode"],
            rendered["hook"]["coexistence"]["nextStep"]["commandJsonTemplate"]["timeoutErrorCode"]
        );
        assert_eq!(
            rendered["hook"]["coexistence"]["nextStepRisk"],
            rendered["hook"]["coexistence"]["nextStep"]["commandJsonTemplate"]["risk"]
        );
        assert_eq!(
            rendered["hook"]["coexistence"]["nextStepPlaceholderCount"],
            rendered["hook"]["coexistence"]["nextStep"]["commandJsonTemplate"]["placeholderCount"]
        );
        assert_eq!(
            rendered["hook"]["coexistence"]["nextStepPlaceholders"],
            rendered["hook"]["coexistence"]["nextStep"]["commandJsonTemplate"]["placeholders"]
        );
        assert_eq!(
            rendered["hook"]["coexistence"]["nextStepCliArgs"],
            rendered["hook"]["coexistence"]["nextStep"]["commandJsonTemplate"]["cliArgs"]
        );
        assert_eq!(rendered["hook"]["coexistence"]["activeStepSource"], "next-action");
        assert_eq!(
            rendered["hook"]["coexistence"]["activeStepAllowed"],
            rendered["hook"]["coexistence"]["nextStepChain"][0]["allowed"]
        );
        assert_eq!(
            rendered["hook"]["coexistence"]["activeStepBlockedBy"],
            rendered["hook"]["coexistence"]["nextStepChain"][0]["blockedBy"]
        );
        assert_eq!(
            rendered["hook"]["coexistence"]["activeStepBranch"],
            rendered["hook"]["coexistence"]["nextStepChain"][0]["branch"]
        );
        assert_eq!(
            rendered["hook"]["coexistence"]["activeStepActionKey"],
            rendered["hook"]["coexistence"]["activeStep"]["actionKey"]
        );
        assert_eq!(
            rendered["hook"]["coexistence"]["activeStepCommandGroup"],
            rendered["hook"]["coexistence"]["activeStep"]["commandGroup"]
        );
        assert_eq!(
            rendered["hook"]["coexistence"]["activeStep"]["id"],
            rendered["hook"]["coexistence"]["nextStepChain"][0]["id"]
        );
        assert_eq!(
            rendered["hook"]["coexistence"]["activeStep"]["command"],
            rendered["hook"]["coexistence"]["nextStepChain"][0]["command"]
        );
        assert_eq!(
            rendered["hook"]["coexistence"]["activeStepId"],
            "next-action:hook.query:0"
        );
        assert_eq!(
            rendered["hook"]["coexistence"]["activeStepCommand"],
            "objc.classes <filter>"
        );
        assert_eq!(rendered["hook"]["coexistence"]["activeStepPhase"], "query");
        assert_eq!(rendered["hook"]["coexistence"]["activeStepReadyToRun"], true);
        assert_eq!(
            rendered["hook"]["coexistence"]["activeStepRequiresFallback"],
            false
        );
        assert_eq!(
            rendered["hook"]["coexistence"]["activeStepKind"],
            rendered["hook"]["coexistence"]["nextStep"]["commandJsonTemplate"]["kind"]
        );
        assert_eq!(
            rendered["hook"]["coexistence"]["activeStepCommandJsonEligible"],
            rendered["hook"]["coexistence"]["nextStep"]["commandJsonTemplate"]["commandJsonEligible"]
        );
        assert_eq!(
            rendered["hook"]["coexistence"]["activeStepRetryable"],
            rendered["hook"]["coexistence"]["nextStep"]["commandJsonTemplate"]["retryable"]
        );
        assert_eq!(
            rendered["hook"]["coexistence"]["activeStepMaxSuggestedRetries"],
            rendered["hook"]["coexistence"]["nextStep"]["commandJsonTemplate"]["maxSuggestedRetries"]
        );
        assert_eq!(
            rendered["hook"]["coexistence"]["activeStepRetryDelayHintMs"],
            rendered["hook"]["coexistence"]["nextStep"]["commandJsonTemplate"]["retryDelayHintMs"]
        );
        assert_eq!(
            rendered["hook"]["coexistence"]["activeStepTimeoutHintMs"],
            rendered["hook"]["coexistence"]["nextStep"]["commandJsonTemplate"]["timeoutHintMs"]
        );
        assert_eq!(
            rendered["hook"]["coexistence"]["activeStepTimeoutAction"],
            rendered["hook"]["coexistence"]["nextStep"]["commandJsonTemplate"]["timeoutAction"]
        );
        assert_eq!(
            rendered["hook"]["coexistence"]["activeStepErrorCode"],
            rendered["hook"]["coexistence"]["nextStep"]["commandJsonTemplate"]["errorCode"]
        );
        assert_eq!(
            rendered["hook"]["coexistence"]["activeStepTimeoutErrorCode"],
            rendered["hook"]["coexistence"]["nextStep"]["commandJsonTemplate"]["timeoutErrorCode"]
        );
        assert_eq!(
            rendered["hook"]["coexistence"]["activeStepRisk"],
            rendered["hook"]["coexistence"]["nextStep"]["commandJsonTemplate"]["risk"]
        );
        assert_eq!(
            rendered["hook"]["coexistence"]["activeStepPlaceholderCount"],
            rendered["hook"]["coexistence"]["nextStep"]["commandJsonTemplate"]["placeholderCount"]
        );
        assert_eq!(
            rendered["hook"]["coexistence"]["activeStepPlaceholders"],
            rendered["hook"]["coexistence"]["nextStep"]["commandJsonTemplate"]["placeholders"]
        );
        assert_eq!(
            rendered["hook"]["coexistence"]["activeStepCliArgs"],
            rendered["hook"]["coexistence"]["nextStep"]["commandJsonTemplate"]["cliArgs"]
        );
        assert_eq!(rendered["hook"]["coexistence"]["nextStepChainSource"], "next-action");
        assert_eq!(rendered["hook"]["coexistence"]["nextStepChainLimit"], 3);
        assert_eq!(rendered["hook"]["coexistence"]["nextStepChainCount"], 3);
        assert_eq!(
            rendered["hook"]["coexistence"]["nextStepChain"][0]["id"],
            "next-action:hook.query:0"
        );
        assert_eq!(
            rendered["hook"]["coexistence"]["nextStepChain"][0]["actionKey"],
            "hook.query"
        );
        assert_eq!(
            rendered["hook"]["coexistence"]["nextStepChain"][0]["commandGroup"],
            "query"
        );
        assert_eq!(
            rendered["hook"]["coexistence"]["nextStepChain"][0]["command"],
            "objc.classes <filter>"
        );
        assert_eq!(rendered["hook"]["coexistence"]["nextStepChain"][0]["readyToRun"], true);
        assert_eq!(
            rendered["hook"]["coexistence"]["nextStepChain"][0]["requiresFallback"],
            false
        );
        assert_eq!(
            rendered["hook"]["coexistence"]["nextStepChain"][0]["kind"],
            rendered["hook"]["coexistence"]["nextStep"]["commandJsonTemplate"]["kind"]
        );
        assert_eq!(
            rendered["hook"]["coexistence"]["nextStepChain"][0]["retryable"],
            rendered["hook"]["coexistence"]["nextStep"]["commandJsonTemplate"]["retryable"]
        );
        assert_eq!(
            rendered["hook"]["coexistence"]["nextStepChain"][0]["maxSuggestedRetries"],
            rendered["hook"]["coexistence"]["nextStep"]["commandJsonTemplate"]["maxSuggestedRetries"]
        );
        assert_eq!(
            rendered["hook"]["coexistence"]["nextStepChain"][0]["retryDelayHintMs"],
            rendered["hook"]["coexistence"]["nextStep"]["commandJsonTemplate"]["retryDelayHintMs"]
        );
        assert_eq!(
            rendered["hook"]["coexistence"]["nextStepChain"][0]["timeoutHintMs"],
            rendered["hook"]["coexistence"]["nextStep"]["commandJsonTemplate"]["timeoutHintMs"]
        );
        assert_eq!(
            rendered["hook"]["coexistence"]["nextStepChain"][0]["timeoutAction"],
            rendered["hook"]["coexistence"]["nextStep"]["commandJsonTemplate"]["timeoutAction"]
        );
        assert_eq!(
            rendered["hook"]["coexistence"]["nextStepChain"][0]["errorCode"],
            rendered["hook"]["coexistence"]["nextStep"]["commandJsonTemplate"]["errorCode"]
        );
        assert_eq!(
            rendered["hook"]["coexistence"]["nextStepChain"][0]["timeoutErrorCode"],
            rendered["hook"]["coexistence"]["nextStep"]["commandJsonTemplate"]["timeoutErrorCode"]
        );
        assert_eq!(
            rendered["hook"]["coexistence"]["nextStepChain"][0]["risk"],
            rendered["hook"]["coexistence"]["nextStep"]["commandJsonTemplate"]["risk"]
        );
        assert_eq!(
            rendered["hook"]["coexistence"]["nextStepChain"][0]["placeholderCount"],
            rendered["hook"]["coexistence"]["nextStep"]["commandJsonTemplate"]["placeholderCount"]
        );
        assert_eq!(
            rendered["hook"]["coexistence"]["nextStepChain"][0]["placeholders"],
            rendered["hook"]["coexistence"]["nextStep"]["commandJsonTemplate"]["placeholders"]
        );
        assert_eq!(
            rendered["hook"]["coexistence"]["nextStepChain"][0]["cliArgs"],
            rendered["hook"]["coexistence"]["nextStep"]["commandJsonTemplate"]["cliArgs"]
        );
        assert_eq!(
            rendered["hook"]["coexistence"]["nextStepChain"][1]["id"],
            "next-action:hook.query:1"
        );
        assert_eq!(
            rendered["hook"]["coexistence"]["nextStepChain"][1]["command"],
            "native.images <filter>"
        );
        assert_eq!(
            rendered["hook"]["coexistence"]["nextStepChain"][2]["id"],
            "next-action:hook.query:2"
        );
        assert_eq!(
            rendered["hook"]["coexistence"]["nextStepChain"][2]["command"],
            "swift.types <filter>"
        );
        assert_eq!(
            rendered["hook"]["coexistence"]["nextStepChainTruncated"],
            false
        );
        assert_eq!(rendered["hook"]["automation"]["preferredPath"], "inline-safe");
        assert_eq!(rendered["hook"]["automation"]["backendPressure"], "none");
        assert_eq!(rendered["hook"]["automation"]["loadedExternalBackendCount"], 0);
        assert_eq!(rendered["hook"]["automation"]["singleExternalBackendLoaded"], false);
        assert_eq!(rendered["hook"]["automation"]["multipleExternalBackendsLoaded"], false);
        assert_eq!(rendered["hook"]["automation"]["branchExecutionOrder"][0], "hook.query");
        assert_eq!(rendered["hook"]["automation"]["readyBranchCount"], 5);
        assert_eq!(rendered["hook"]["automation"]["blockedBranchCount"], 0);
        assert_eq!(rendered["hook"]["automation"]["nextActionKey"], "hook.query");
        assert_eq!(rendered["hook"]["automation"]["nextReadyActionKey"], "hook.query");
        assert_eq!(rendered["hook"]["automation"]["nextRunnableActionKey"], "hook.query");
        assert!(rendered["hook"]["automation"]["nextBlockedActionKey"].is_null());
        assert_eq!(rendered["hook"]["automation"]["nextActionAllowed"], true);
        assert_eq!(rendered["hook"]["automation"]["nextActionBlockedBy"], "none");
        assert_eq!(rendered["hook"]["automation"]["nextActionBranch"], "run");
        assert_eq!(rendered["hook"]["automation"]["nextActionReadyToRun"], true);
        assert_eq!(rendered["hook"]["automation"]["nextStepId"], "next-action:hook.query:0");
        assert_eq!(rendered["hook"]["automation"]["nextStepActionKey"], "hook.query");
        assert_eq!(rendered["hook"]["automation"]["nextStepCommandGroup"], "query");
        assert_eq!(rendered["hook"]["automation"]["nextStepAllowed"], true);
        assert_eq!(rendered["hook"]["automation"]["nextStepBlockedBy"], "none");
        assert_eq!(rendered["hook"]["automation"]["nextStepBranch"], "run");
        assert_eq!(rendered["hook"]["automation"]["nextStepCommand"], "objc.classes <filter>");
        assert_eq!(rendered["hook"]["automation"]["nextStepPhase"], "query");
        assert_eq!(rendered["hook"]["automation"]["nextStepCommandJsonEligible"], true);
        assert_eq!(rendered["hook"]["automation"]["nextStepReadyToRun"], true);
        assert_eq!(rendered["hook"]["automation"]["nextStepRequiresFallback"], false);
        assert_eq!(rendered["hook"]["automation"]["activeStepSource"], "next-action");
        assert_eq!(
            rendered["hook"]["automation"]["activeStepAllowed"],
            rendered["hook"]["automation"]["nextStepChain"][0]["allowed"]
        );
        assert_eq!(
            rendered["hook"]["automation"]["activeStepBlockedBy"],
            rendered["hook"]["automation"]["nextStepChain"][0]["blockedBy"]
        );
        assert_eq!(
            rendered["hook"]["automation"]["activeStepBranch"],
            rendered["hook"]["automation"]["nextStepChain"][0]["branch"]
        );
        assert_eq!(
            rendered["hook"]["automation"]["activeStepActionKey"],
            rendered["hook"]["automation"]["activeStep"]["actionKey"]
        );
        assert_eq!(
            rendered["hook"]["automation"]["activeStepCommandGroup"],
            rendered["hook"]["automation"]["activeStep"]["commandGroup"]
        );
        assert_eq!(
            rendered["hook"]["automation"]["activeStep"]["id"],
            rendered["hook"]["automation"]["nextStepChain"][0]["id"]
        );
        assert_eq!(
            rendered["hook"]["automation"]["activeStep"]["command"],
            rendered["hook"]["automation"]["nextStepChain"][0]["command"]
        );
        assert_eq!(rendered["hook"]["automation"]["activeStepId"], "next-action:hook.query:0");
        assert_eq!(rendered["hook"]["automation"]["activeStepCommand"], "objc.classes <filter>");
        assert_eq!(rendered["hook"]["automation"]["activeStepPhase"], "query");
        assert_eq!(rendered["hook"]["automation"]["activeStepReadyToRun"], true);
        assert_eq!(
            rendered["hook"]["automation"]["activeStepRequiresFallback"],
            false
        );
        assert_eq!(rendered["hook"]["automation"]["activeStepCommandJsonEligible"], true);
        assert_eq!(
            rendered["hook"]["automation"]["activeStepRetryable"],
            rendered["hook"]["automation"]["nextStep"]["commandJsonTemplate"]["retryable"]
        );
        assert_eq!(
            rendered["hook"]["automation"]["activeStepMaxSuggestedRetries"],
            rendered["hook"]["automation"]["nextStep"]["commandJsonTemplate"]["maxSuggestedRetries"]
        );
        assert_eq!(
            rendered["hook"]["automation"]["activeStepRetryDelayHintMs"],
            rendered["hook"]["automation"]["nextStep"]["commandJsonTemplate"]["retryDelayHintMs"]
        );
        assert_eq!(
            rendered["hook"]["automation"]["activeStepTimeoutHintMs"],
            rendered["hook"]["automation"]["nextStep"]["commandJsonTemplate"]["timeoutHintMs"]
        );
        assert_eq!(
            rendered["hook"]["automation"]["activeStepTimeoutAction"],
            rendered["hook"]["automation"]["nextStep"]["commandJsonTemplate"]["timeoutAction"]
        );
        assert_eq!(
            rendered["hook"]["automation"]["activeStepErrorCode"],
            rendered["hook"]["automation"]["nextStep"]["commandJsonTemplate"]["errorCode"]
        );
        assert_eq!(
            rendered["hook"]["automation"]["activeStepTimeoutErrorCode"],
            rendered["hook"]["automation"]["nextStep"]["commandJsonTemplate"]["timeoutErrorCode"]
        );
        assert_eq!(
            rendered["hook"]["automation"]["activeStepRisk"],
            rendered["hook"]["automation"]["nextStep"]["commandJsonTemplate"]["risk"]
        );
        assert_eq!(
            rendered["hook"]["automation"]["activeStepPlaceholderCount"],
            rendered["hook"]["automation"]["nextStep"]["commandJsonTemplate"]["placeholderCount"]
        );
        assert_eq!(
            rendered["hook"]["automation"]["activeStepPlaceholders"],
            rendered["hook"]["automation"]["nextStep"]["commandJsonTemplate"]["placeholders"]
        );
        assert_eq!(
            rendered["hook"]["automation"]["activeStepCliArgs"],
            rendered["hook"]["automation"]["nextStep"]["commandJsonTemplate"]["cliArgs"]
        );
        assert_eq!(
            rendered["hook"]["automation"]["nextStep"]["id"],
            "next-action:hook.query:0"
        );
        assert_eq!(rendered["hook"]["automation"]["nextStep"]["actionKey"], "hook.query");
        assert_eq!(
            rendered["hook"]["automation"]["nextStep"]["command"],
            "objc.classes <filter>"
        );
        assert_eq!(rendered["hook"]["automation"]["nextStep"]["phase"], "query");
        assert_eq!(rendered["hook"]["automation"]["nextStep"]["readyToRun"], true);
        assert_eq!(
            rendered["hook"]["automation"]["nextStep"]["requiresFallback"],
            false
        );
        assert_eq!(
            rendered["hook"]["automation"]["nextStepKind"],
            rendered["hook"]["automation"]["nextStep"]["commandJsonTemplate"]["kind"]
        );
        assert_eq!(
            rendered["hook"]["automation"]["nextStepRetryable"],
            rendered["hook"]["automation"]["nextStep"]["commandJsonTemplate"]["retryable"]
        );
        assert_eq!(
            rendered["hook"]["automation"]["nextStepMaxSuggestedRetries"],
            rendered["hook"]["automation"]["nextStep"]["commandJsonTemplate"]["maxSuggestedRetries"]
        );
        assert_eq!(
            rendered["hook"]["automation"]["nextStepRetryDelayHintMs"],
            rendered["hook"]["automation"]["nextStep"]["commandJsonTemplate"]["retryDelayHintMs"]
        );
        assert_eq!(
            rendered["hook"]["automation"]["nextStepTimeoutHintMs"],
            rendered["hook"]["automation"]["nextStep"]["commandJsonTemplate"]["timeoutHintMs"]
        );
        assert_eq!(
            rendered["hook"]["automation"]["nextStepTimeoutAction"],
            rendered["hook"]["automation"]["nextStep"]["commandJsonTemplate"]["timeoutAction"]
        );
        assert_eq!(
            rendered["hook"]["automation"]["nextStepErrorCode"],
            rendered["hook"]["automation"]["nextStep"]["commandJsonTemplate"]["errorCode"]
        );
        assert_eq!(
            rendered["hook"]["automation"]["nextStepTimeoutErrorCode"],
            rendered["hook"]["automation"]["nextStep"]["commandJsonTemplate"]["timeoutErrorCode"]
        );
        assert_eq!(
            rendered["hook"]["automation"]["nextStepRisk"],
            rendered["hook"]["automation"]["nextStep"]["commandJsonTemplate"]["risk"]
        );
        assert_eq!(
            rendered["hook"]["automation"]["nextStepPlaceholderCount"],
            rendered["hook"]["automation"]["nextStep"]["commandJsonTemplate"]["placeholderCount"]
        );
        assert_eq!(
            rendered["hook"]["automation"]["nextStepPlaceholders"],
            rendered["hook"]["automation"]["nextStep"]["commandJsonTemplate"]["placeholders"]
        );
        assert_eq!(
            rendered["hook"]["automation"]["nextStepCliArgs"],
            rendered["hook"]["automation"]["nextStep"]["commandJsonTemplate"]["cliArgs"]
        );
        assert_eq!(rendered["hook"]["automation"]["nextStepChainSource"], "next-action");
        assert_eq!(rendered["hook"]["automation"]["nextStepChainLimit"], 3);
        assert_eq!(rendered["hook"]["automation"]["nextStepChainCount"], 1);
        assert_eq!(rendered["hook"]["automation"]["nextStepChain"][0]["source"], "next-action");
        assert_eq!(
            rendered["hook"]["automation"]["nextStepChain"][0]["id"],
            "next-action:hook.query:0"
        );
        assert_eq!(
            rendered["hook"]["automation"]["nextStepChain"][0]["actionKey"],
            "hook.query"
        );
        assert_eq!(
            rendered["hook"]["automation"]["nextStepChain"][0]["commandGroup"],
            "query"
        );
        assert_eq!(
            rendered["hook"]["automation"]["nextStepChain"][0]["command"],
            "objc.classes <filter>"
        );
        assert_eq!(rendered["hook"]["automation"]["nextStepChain"][0]["readyToRun"], true);
        assert_eq!(
            rendered["hook"]["automation"]["nextStepChain"][0]["requiresFallback"],
            false
        );
        assert_eq!(
            rendered["hook"]["automation"]["nextStepChainTruncated"],
            false
        );
        assert_eq!(rendered["hook"]["automation"]["hasFallbackPlan"], false);
        assert!(rendered["hook"]["automation"]["fallbackPlan"].is_null());
        assert_eq!(rendered["hook"]["automation"]["hasSuggestedSequence"], true);
        assert_eq!(rendered["hook"]["automation"]["suggestedSequence"][0], "native.hookenv");
        assert!(rendered["hook"]["automation"]["commandTemplates"].is_array());
        assert_eq!(rendered["hook"]["automation"]["commandTemplates"][0]["actionKey"], "hook.query");
        assert_eq!(
            rendered["hook"]["automation"]["nextActionPlan"]["actionKey"],
            "hook.query"
        );
        assert_eq!(rendered["hook"]["automation"]["nextActionPlan"]["allowed"], true);
        assert_eq!(rendered["hook"]["automation"]["nextActionPlan"]["branch"], "run");
        assert_eq!(rendered["hook"]["automation"]["nextActionPlan"]["readyToRun"], true);
        assert_eq!(
            rendered["hook"]["automation"]["nextActionPlan"]["prerequisiteCount"],
            0
        );
        assert_eq!(rendered["hook"]["automation"]["nextActionTemplateCount"], 3);
        assert_eq!(rendered["hook"]["automation"]["nextActionTemplates"][0], "objc.classes <filter>");
        assert_eq!(
            rendered["hook"]["automation"]["commandTemplates"][0]["commandJsonTemplateCount"],
            3
        );
        assert_eq!(
            rendered["hook"]["automation"]["commandTemplates"][0]["commandJsonTemplates"][0]["cliArgs"][4],
            "--command-json"
        );
        assert_eq!(
            rendered["hook"]["automation"]["commandTemplates"][0]["commandJsonTemplates"][0]["kind"],
            "runtime-command"
        );
        assert_eq!(
            rendered["hook"]["automation"]["commandTemplates"][0]["commandJsonTemplates"][0]["phase"],
            "query"
        );
        assert_eq!(
            rendered["hook"]["automation"]["commandTemplates"][0]["commandJsonTemplates"][0]["retryable"],
            true
        );
        assert_eq!(
            rendered["hook"]["automation"]["commandTemplates"][0]["commandJsonTemplates"][0]["maxSuggestedRetries"],
            1
        );
        assert_eq!(
            rendered["hook"]["automation"]["commandTemplates"][0]["commandJsonTemplates"][0]["retryDelayHintMs"],
            250
        );
        assert_eq!(
            rendered["hook"]["automation"]["commandTemplates"][0]["commandJsonTemplates"][0]["timeoutHintMs"],
            5000
        );
        assert_eq!(
            rendered["hook"]["automation"]["commandTemplates"][0]["commandJsonTemplates"][0]["timeoutAction"],
            "narrow-query-filter-and-retry"
        );
        assert_eq!(
            rendered["hook"]["automation"]["commandTemplates"][0]["commandJsonTemplates"][0]["errorCode"],
            "hook-fallback-query-failed"
        );
        assert_eq!(
            rendered["hook"]["automation"]["commandTemplates"][0]["commandJsonTemplates"][0]["timeoutErrorCode"],
            "hook-fallback-query-timeout"
        );
        assert_eq!(
            rendered["hook"]["automation"]["commandTemplates"][0]["commandJsonTemplates"][0]["commandJsonEligible"],
            true
        );
        assert_eq!(
            rendered["hook"]["automation"]["commandTemplates"][0]["commandJsonTemplates"][0]["placeholderCount"],
            1
        );
        assert_eq!(
            rendered["hook"]["automation"]["commandTemplates"][0]["commandJsonTemplates"][0]["placeholders"][0],
            "<filter>"
        );
        assert_eq!(rendered["hook"]["automation"]["nextActionCommandJsonTemplateCount"], 3);
        assert_eq!(
            rendered["hook"]["automation"]["nextActionCommandJsonTemplates"][0]["cliArgs"][2],
            "--command"
        );
        assert!(rendered["hook"]["automation"]["actionBranches"].is_array());
        assert_eq!(
            rendered["hook"]["automation"]["actionBranches"][0]["actionKey"],
            "hook.query"
        );
        assert_eq!(
            rendered["hook"]["automation"]["actionBranches"][0]["selectedAsNext"],
            true
        );
        assert_eq!(
            rendered["hook"]["automation"]["actionBranches"][0]["templateCount"],
            3
        );
        assert_eq!(
            rendered["hook"]["automation"]["actionBranches"][0]["commandJsonTemplateCount"],
            3
        );
        assert_eq!(
            rendered["hook"]["automation"]["actionBranches"][0]["commandJsonEligibleTemplateCount"],
            3
        );
        assert_eq!(rendered["hook"]["automation"]["actionBranches"][0]["executionRank"], 0);
        assert_eq!(rendered["hook"]["automation"]["actionBranches"][0]["executionIndex"], 0);
        assert_eq!(rendered["hook"]["automation"]["actionBranches"][0]["readyToRun"], true);
        assert_eq!(
            rendered["hook"]["automation"]["actionBranches"][2]["actionKey"],
            "hook.install"
        );
        assert_eq!(
            rendered["hook"]["automation"]["actionBranches"][2]["prerequisiteActionKeys"][0],
            "hook.bootstrap"
        );
        assert_eq!(
            rendered["hook"]["automation"]["actionBranches"][2]["blockedPrerequisiteCount"],
            0
        );
        assert_eq!(rendered["hook"]["automation"]["actionBranches"][2]["readyToRun"], true);
        assert_eq!(
            rendered["hook"]["controller"]["capabilities"]["hookInstallCommandsAllowed"],
            true
        );
        assert_eq!(rendered["environment"]["hookStrategy"]["commandMode"], "allowed");
        assert!(rendered["environment"]["hookEnvironment"]["recommendedActions"].is_array());
        assert_eq!(rendered["environment"]["hookEnvironment"]["coexistenceMode"], "inline-safe");
        assert_eq!(
            rendered["environment"]["hookEnvironment"]["coexistenceRecommendation"],
            "inline hooks are allowed and no external backend is loaded"
        );
        assert_eq!(
            rendered["environment"]["hookEnvironment"]["coexistenceLayerStatus"],
            "not-required"
        );
        assert_eq!(rendered["environment"]["hookEnvironment"]["coexistenceLayerAvailable"], true);
        assert_eq!(rendered["environment"]["hookEnvironment"]["externalBackendLoaded"], false);
        assert_eq!(rendered["environment"]["hookEnvironment"]["singleExternalBackendLoaded"], false);
        assert_eq!(
            rendered["environment"]["hookEnvironment"]["multipleExternalBackendsLoaded"],
            false
        );
        assert_eq!(rendered["environment"]["hookStrategy"]["bootstrapInjectionAllowed"], true);
        assert_eq!(rendered["environment"]["hookStrategy"]["queryCommandsAllowed"], true);
        assert_eq!(rendered["environment"]["hookStrategy"]["hookInstallCommandsAllowed"], true);
        assert_eq!(rendered["preflight"]["targetHookEnvironment"]["conflictState"], "none");
        assert_eq!(rendered["preflight"]["targetHookEnvironment"]["riskLevel"], "normal");
        assert_eq!(rendered["preflight"]["targetHookEnvironment"]["coexistenceMode"], "inline-safe");
        assert_eq!(
            rendered["preflight"]["targetHookEnvironment"]["coexistenceRecommendation"],
            "inline hooks are allowed and no external backend is loaded"
        );
        assert_eq!(
            rendered["preflight"]["targetHookEnvironment"]["coexistenceLayerStatus"],
            "not-required"
        );
        assert_eq!(rendered["preflight"]["targetHookEnvironment"]["coexistenceLayerAvailable"], true);
        assert_eq!(rendered["preflight"]["targetHookEnvironment"]["loadedBackendCount"], 0);
        assert_eq!(
            rendered["preflight"]["targetHookEnvironment"]["singleExternalBackendLoaded"],
            false
        );
        assert_eq!(
            rendered["preflight"]["targetHookEnvironment"]["multipleExternalBackendsLoaded"],
            false
        );
        assert_eq!(rendered["diagnostics"]["code"], "bind-socket");
        assert!(rendered["diagnostics"]["hook"].is_null());
        assert_eq!(rendered["payload"], json!(null));
        assert_eq!(rendered["items"], json!([]));
        assert_eq!(rendered["logs"][0], "bootstrap pending");

        let hook_blocked_rendered = render_command_error_json_with_context(
            "trace UIViewController",
            &Error::State(
                "`trace UIViewController` requires inline hooks, but the current hook policy forbids hook-install commands: hook-effective-blocked actionKey=hook.install commandGroup=hook-install blockedBy=target commandMode=query-only baseCommandMode=query-only effectiveCommandMode=query-only autoDowngradedToQueryOnly=false autoDowngradeReason=<none> coexistenceMode=cleanup-only backendPressure=both fallbackActionKey=hook.status fallbackStepId=next-action:hook.status:0 fallbackCommand=trace status fallbackPhase=cleanup; recommendation=blocked by target hook policy".into(),
            ),
            &[],
            &CommandJsonContext {
                config: &config,
                pid: 42,
                socket_path: "/tmp/iosrf.sock",
                plan: &plan,
                injection_environment: &environment,
                doctor: &doctor,
                preflight: &preflight,
                trace: None,
                hello: None,
                ping: None,
                hook_environment_notice: None,
                hook_environment_checked: false,
                jsinit_result: None,
                loadjs_result: None,
            },
        );
        assert_eq!(hook_blocked_rendered["diagnostics"]["code"], "target-hook-policy-blocked");
        assert_eq!(hook_blocked_rendered["diagnostics"]["hook"]["actionKey"], "hook.install");
        assert_eq!(hook_blocked_rendered["diagnostics"]["hook"]["blockedBy"], "target");
        assert_eq!(hook_blocked_rendered["diagnostics"]["hook"]["baseCommandMode"], "query-only");
        assert_eq!(
            hook_blocked_rendered["diagnostics"]["hook"]["effectiveCommandMode"],
            "query-only"
        );
        assert_eq!(
            hook_blocked_rendered["diagnostics"]["hook"]["autoDowngradedToQueryOnly"],
            false
        );
        assert_eq!(
            hook_blocked_rendered["diagnostics"]["hook"]["autoDowngradeReason"],
            "<none>"
        );
        assert_eq!(
            hook_blocked_rendered["diagnostics"]["hook"]["fallbackStepId"],
            "next-action:hook.status:0"
        );
        assert_eq!(hook_blocked_rendered["diagnostics"]["hook"]["fallbackCommand"], "trace status");
        assert_eq!(hook_blocked_rendered["diagnostics"]["hook"]["fallbackAvailable"], true);
    }

    #[test]
    fn render_injection_result_json_contains_trace_and_handshake() {
        let config = ControllerConfig {
            mode: InjectionMode::Attach,
            pid: Some(42),
            bundle_id: None,
            spawn_command: None,
            command: None,
            command_json: false,
            list_images_json: false,
            preflight_only: false,
            preflight_json: false,
            inject_json: true,
            agent_path: DEFAULT_AGENT_PATH_ROOTFUL.into(),
            entry_symbol: "ios_agent_entry".into(),
            script_path: Some("/tmp/bootstrap.js".into()),
            socket_path: Some("/tmp/iosrf.sock".into()),
            connect_timeout_secs: 15,
        };
        let plan = MachInjector
            .plan(&InjectionTarget {
                pid: 42,
                dylib_path: DEFAULT_AGENT_PATH_ROOTFUL.into(),
                entry_symbol: "ios_agent_entry".into(),
                socket_path: "/tmp/iosrf.sock".into(),
            })
            .expect("build plan");
        let environment = InjectionEnvironmentReport {
            dry_run: false,
            bootstrap_wait_ms: Some(3000),
            hook_policy: HookPolicy::Warn,
            hook_strategy: HookStrategyDecision {
                policy: HookPolicy::Warn,
                strategy: "internal-inline-risky".into(),
                allowed: true,
                inline_hooks_allowed: true,
                reason: None,
            },
            hook_environment: HookEnvironmentReport {
                active_backend: None,
                backends: vec![],
                warnings: vec![],
            },
        };
        let preflight = InjectionTargetPreflightReport {
            main_image: Some(native_api::ImageInfo {
                name: "/Applications/Test.app/Test".into(),
                base: 0x1000_0000,
                slide: 0,
                size: 0x4000,
            }),
            target_images: vec![native_api::ImageInfo {
                name: "/Applications/Test.app/Test".into(),
                base: 0x1000_0000,
                slide: 0,
                size: 0x4000,
            }],
            target_image_count: 1,
            target_uses_arm64e: Some(false),
            thread_bootstrap_kind: ThreadBootstrapKind::PthreadCreateFromMachThread,
            thread_bootstrap_label: "/usr/lib/system/libsystem_pthread.dylib!pthread_create_from_mach_thread+0x123"
                .into(),
            thread_bootstrap_address: 0x1800_0123,
            thread_bootstrap_raw_address: 0x1800_0123,
            thread_bootstrap_canonicalized: false,
            target_hook_environment: HookEnvironmentReport {
                active_backend: None,
                backends: vec![],
                warnings: vec![],
            },
            target_hook_strategy: HookStrategyDecision {
                policy: HookPolicy::Warn,
                strategy: "internal-inline-safe".into(),
                allowed: true,
                inline_hooks_allowed: true,
                reason: None,
            },
            resolved_loader_symbols: vec![],
        };
        let trace = InjectionTrace {
            payload_address: 0x5000,
            payload_size: 0x100,
            payload_allocated_size: 0x1000,
            data_address: 0x7000,
            data_size: 0x80,
            data_allocated_size: 0x1000,
            stack_address: 0x9000,
            stack_size: 0x4000,
            target_uses_arm64e: Some(false),
            code_protection: RemoteProtectionOutcome::SetMaximumAndCurrent,
            data_protection: RemoteProtectionOutcome::CurrentOnlyFallback,
            thread_bootstrap_kind: ThreadBootstrapKind::PthreadCreateFromMachThread,
            thread_bootstrap_label: "/usr/lib/system/libsystem_pthread.dylib!pthread_create_from_mach_thread+0x123"
                .into(),
            thread_plan: ThreadCreatePlan {
                flavor: 6,
                count: 70,
                state: Arm64ThreadState {
                    x: [0; 29],
                    fp: 0,
                    lr: 0,
                    sp: 0xa000,
                    pc: 0x1800_0123,
                    cpsr: 0,
                    pad: 0,
                },
            },
            thread_port: Some(77),
            thread_termination: RemoteThreadTerminationOutcome::NotAttempted,
            thread_port_deallocated: true,
            resources_persist: true,
            bootstrap_report: Some(BootstrapResultReport {
                status: BootstrapStatus::AgentRunning,
                status_raw: 6,
                dylib_handle: 0x1234,
                entry_address: 0x5678,
                socket_fd: 9,
                entry_return: 0,
            }),
            bootstrap_timed_out: false,
        };
        let hello = Hello {
            platform: "ios".into(),
            arch: "aarch64".into(),
            runtime: "quickjs-runtime".into(),
            transport: "unix-fd".into(),
        };

        let doctor = analyze_doctor_report(&config, 42, Path::new("/tmp/iosrf.sock"), &environment, &preflight);
        let rendered = render_injection_result_json(
            &config,
            42,
            "/tmp/iosrf.sock",
            &plan,
            &environment,
            &doctor,
            &preflight,
            Some(&trace),
            Some(&hello),
            Some("pong"),
            Some("active=<none>"),
            true,
            Some("runtime ready"),
            Some("script loaded"),
            &["agent log line".into()],
            None,
        );

        assert_eq!(rendered["ok"], true);
        assert_eq!(rendered["hook"]["controller"]["commandMode"], "allowed");
        assert_eq!(rendered["hook"]["target"]["commandMode"], "allowed");
        assert!(rendered["hook"]["controller"]["recommendedActions"].is_array());
        assert!(rendered["hook"]["target"]["recommendedActions"].is_array());
        assert!(rendered["hook"]["effectiveActions"].is_array());
        assert_eq!(rendered["hook"]["controller"]["recommendedActions"][0]["commandGroup"], "query");
        assert_eq!(rendered["hook"]["controller"]["recommendedActions"][0]["actionKey"], "hook.query");
        assert_eq!(rendered["hook"]["controller"]["recommendedActions"][0]["priority"], 1);
        assert_eq!(rendered["hook"]["effectiveActions"][0]["actionKey"], "hook.query");
        assert_eq!(rendered["hook"]["effectiveActions"][0]["blockedBy"], "none");
        assert_eq!(rendered["hook"]["effective"]["commandMode"], "allowed");
        assert_eq!(rendered["hook"]["effective"]["blockedBySummary"]["controller"], 0);
        assert_eq!(rendered["hook"]["effective"]["blockedBySummary"]["target"], 0);
        assert_eq!(rendered["hook"]["effective"]["blockedBySummary"]["both"], 0);
        assert!(rendered["hook"]["backendMatrix"]["entries"].is_array());
        assert_eq!(rendered["hook"]["backendMatrix"]["entryCount"], 0);
        assert_eq!(rendered["hook"]["coexistence"]["mode"], "inline-safe");
        assert_eq!(rendered["hook"]["coexistence"]["strategy"], "internal-inline-preferred");
        assert_eq!(rendered["hook"]["coexistence"]["backendPressure"], "none");
        assert_eq!(rendered["hook"]["coexistence"]["externalBackendLoaded"], false);
        assert_eq!(rendered["hook"]["coexistence"]["singleExternalBackendLoaded"], false);
        assert_eq!(
            rendered["hook"]["coexistence"]["multipleExternalBackendsLoaded"],
            false
        );
        assert_eq!(rendered["hook"]["coexistence"]["loadedExternalBackendCount"], 0);
        assert_eq!(rendered["hook"]["coexistence"]["hookInstallAllowed"], true);
        assert_eq!(rendered["hook"]["coexistence"]["nextActionKey"], "hook.query");
        assert_eq!(rendered["hook"]["coexistence"]["nextActionAllowed"], true);
        assert_eq!(rendered["hook"]["coexistence"]["nextActionBlockedBy"], "none");
        assert_eq!(rendered["hook"]["coexistence"]["nextActionBranch"], "run");
        assert_eq!(rendered["hook"]["coexistence"]["nextActionReadyToRun"], true);
        assert_eq!(rendered["hook"]["coexistence"]["nextStepId"], "next-action:hook.query:0");
        assert_eq!(rendered["hook"]["coexistence"]["nextStepActionKey"], "hook.query");
        assert_eq!(rendered["hook"]["coexistence"]["nextStepCommandGroup"], "query");
        assert_eq!(rendered["hook"]["coexistence"]["nextStepAllowed"], true);
        assert_eq!(rendered["hook"]["coexistence"]["nextStepBlockedBy"], "none");
        assert_eq!(rendered["hook"]["coexistence"]["nextStepBranch"], "run");
        assert_eq!(rendered["hook"]["coexistence"]["nextStepCommand"], "objc.classes <filter>");
        assert_eq!(rendered["hook"]["coexistence"]["nextStepPhase"], "query");
        assert_eq!(rendered["hook"]["coexistence"]["nextStepCommandJsonEligible"], true);
        assert_eq!(rendered["hook"]["coexistence"]["nextStepReadyToRun"], true);
        assert_eq!(rendered["hook"]["coexistence"]["nextStepRequiresFallback"], false);
        assert_eq!(
            rendered["hook"]["coexistence"]["nextStep"]["id"],
            "next-action:hook.query:0"
        );
        assert_eq!(rendered["hook"]["coexistence"]["nextStep"]["actionKey"], "hook.query");
        assert_eq!(
            rendered["hook"]["coexistence"]["nextStep"]["command"],
            "objc.classes <filter>"
        );
        assert_eq!(rendered["hook"]["coexistence"]["nextStep"]["phase"], "query");
        assert_eq!(rendered["hook"]["coexistence"]["nextStep"]["readyToRun"], true);
        assert_eq!(
            rendered["hook"]["coexistence"]["nextStepKind"],
            rendered["hook"]["coexistence"]["nextStep"]["commandJsonTemplate"]["kind"]
        );
        assert_eq!(
            rendered["hook"]["coexistence"]["nextStepRetryable"],
            rendered["hook"]["coexistence"]["nextStep"]["commandJsonTemplate"]["retryable"]
        );
        assert_eq!(
            rendered["hook"]["coexistence"]["nextStepMaxSuggestedRetries"],
            rendered["hook"]["coexistence"]["nextStep"]["commandJsonTemplate"]["maxSuggestedRetries"]
        );
        assert_eq!(
            rendered["hook"]["coexistence"]["nextStepRetryDelayHintMs"],
            rendered["hook"]["coexistence"]["nextStep"]["commandJsonTemplate"]["retryDelayHintMs"]
        );
        assert_eq!(
            rendered["hook"]["coexistence"]["nextStepTimeoutHintMs"],
            rendered["hook"]["coexistence"]["nextStep"]["commandJsonTemplate"]["timeoutHintMs"]
        );
        assert_eq!(
            rendered["hook"]["coexistence"]["nextStepTimeoutAction"],
            rendered["hook"]["coexistence"]["nextStep"]["commandJsonTemplate"]["timeoutAction"]
        );
        assert_eq!(
            rendered["hook"]["coexistence"]["nextStepErrorCode"],
            rendered["hook"]["coexistence"]["nextStep"]["commandJsonTemplate"]["errorCode"]
        );
        assert_eq!(
            rendered["hook"]["coexistence"]["nextStepTimeoutErrorCode"],
            rendered["hook"]["coexistence"]["nextStep"]["commandJsonTemplate"]["timeoutErrorCode"]
        );
        assert_eq!(
            rendered["hook"]["coexistence"]["nextStepRisk"],
            rendered["hook"]["coexistence"]["nextStep"]["commandJsonTemplate"]["risk"]
        );
        assert_eq!(
            rendered["hook"]["coexistence"]["nextStepPlaceholderCount"],
            rendered["hook"]["coexistence"]["nextStep"]["commandJsonTemplate"]["placeholderCount"]
        );
        assert_eq!(
            rendered["hook"]["coexistence"]["nextStepPlaceholders"],
            rendered["hook"]["coexistence"]["nextStep"]["commandJsonTemplate"]["placeholders"]
        );
        assert_eq!(
            rendered["hook"]["coexistence"]["nextStepCliArgs"],
            rendered["hook"]["coexistence"]["nextStep"]["commandJsonTemplate"]["cliArgs"]
        );
        assert_eq!(rendered["hook"]["coexistence"]["activeStepSource"], "next-action");
        assert_eq!(
            rendered["hook"]["coexistence"]["activeStepAllowed"],
            rendered["hook"]["coexistence"]["nextStepChain"][0]["allowed"]
        );
        assert_eq!(
            rendered["hook"]["coexistence"]["activeStepBlockedBy"],
            rendered["hook"]["coexistence"]["nextStepChain"][0]["blockedBy"]
        );
        assert_eq!(
            rendered["hook"]["coexistence"]["activeStepBranch"],
            rendered["hook"]["coexistence"]["nextStepChain"][0]["branch"]
        );
        assert_eq!(
            rendered["hook"]["coexistence"]["activeStepActionKey"],
            rendered["hook"]["coexistence"]["activeStep"]["actionKey"]
        );
        assert_eq!(
            rendered["hook"]["coexistence"]["activeStepCommandGroup"],
            rendered["hook"]["coexistence"]["activeStep"]["commandGroup"]
        );
        assert_eq!(
            rendered["hook"]["coexistence"]["activeStep"]["id"],
            rendered["hook"]["coexistence"]["nextStepChain"][0]["id"]
        );
        assert_eq!(
            rendered["hook"]["coexistence"]["activeStep"]["command"],
            rendered["hook"]["coexistence"]["nextStepChain"][0]["command"]
        );
        assert_eq!(
            rendered["hook"]["coexistence"]["activeStepId"],
            "next-action:hook.query:0"
        );
        assert_eq!(
            rendered["hook"]["coexistence"]["activeStepCommand"],
            "objc.classes <filter>"
        );
        assert_eq!(rendered["hook"]["coexistence"]["activeStepPhase"], "query");
        assert_eq!(rendered["hook"]["coexistence"]["activeStepReadyToRun"], true);
        assert_eq!(
            rendered["hook"]["coexistence"]["activeStepRequiresFallback"],
            false
        );
        assert_eq!(
            rendered["hook"]["coexistence"]["activeStepKind"],
            rendered["hook"]["coexistence"]["nextStep"]["commandJsonTemplate"]["kind"]
        );
        assert_eq!(
            rendered["hook"]["coexistence"]["activeStepCommandJsonEligible"],
            rendered["hook"]["coexistence"]["nextStep"]["commandJsonTemplate"]["commandJsonEligible"]
        );
        assert_eq!(
            rendered["hook"]["coexistence"]["activeStepRetryable"],
            rendered["hook"]["coexistence"]["nextStep"]["commandJsonTemplate"]["retryable"]
        );
        assert_eq!(
            rendered["hook"]["coexistence"]["activeStepMaxSuggestedRetries"],
            rendered["hook"]["coexistence"]["nextStep"]["commandJsonTemplate"]["maxSuggestedRetries"]
        );
        assert_eq!(
            rendered["hook"]["coexistence"]["activeStepRetryDelayHintMs"],
            rendered["hook"]["coexistence"]["nextStep"]["commandJsonTemplate"]["retryDelayHintMs"]
        );
        assert_eq!(
            rendered["hook"]["coexistence"]["activeStepTimeoutHintMs"],
            rendered["hook"]["coexistence"]["nextStep"]["commandJsonTemplate"]["timeoutHintMs"]
        );
        assert_eq!(
            rendered["hook"]["coexistence"]["activeStepTimeoutAction"],
            rendered["hook"]["coexistence"]["nextStep"]["commandJsonTemplate"]["timeoutAction"]
        );
        assert_eq!(
            rendered["hook"]["coexistence"]["activeStepErrorCode"],
            rendered["hook"]["coexistence"]["nextStep"]["commandJsonTemplate"]["errorCode"]
        );
        assert_eq!(
            rendered["hook"]["coexistence"]["activeStepTimeoutErrorCode"],
            rendered["hook"]["coexistence"]["nextStep"]["commandJsonTemplate"]["timeoutErrorCode"]
        );
        assert_eq!(
            rendered["hook"]["coexistence"]["activeStepRisk"],
            rendered["hook"]["coexistence"]["nextStep"]["commandJsonTemplate"]["risk"]
        );
        assert_eq!(
            rendered["hook"]["coexistence"]["activeStepPlaceholderCount"],
            rendered["hook"]["coexistence"]["nextStep"]["commandJsonTemplate"]["placeholderCount"]
        );
        assert_eq!(
            rendered["hook"]["coexistence"]["activeStepPlaceholders"],
            rendered["hook"]["coexistence"]["nextStep"]["commandJsonTemplate"]["placeholders"]
        );
        assert_eq!(
            rendered["hook"]["coexistence"]["activeStepCliArgs"],
            rendered["hook"]["coexistence"]["nextStep"]["commandJsonTemplate"]["cliArgs"]
        );
        assert_eq!(rendered["hook"]["coexistence"]["nextStepChainSource"], "next-action");
        assert_eq!(rendered["hook"]["coexistence"]["nextStepChainLimit"], 3);
        assert_eq!(rendered["hook"]["coexistence"]["nextStepChainCount"], 3);
        assert_eq!(
            rendered["hook"]["coexistence"]["nextStepChain"][0]["id"],
            "next-action:hook.query:0"
        );
        assert_eq!(
            rendered["hook"]["coexistence"]["nextStepChain"][0]["actionKey"],
            "hook.query"
        );
        assert_eq!(
            rendered["hook"]["coexistence"]["nextStepChain"][0]["commandGroup"],
            "query"
        );
        assert_eq!(
            rendered["hook"]["coexistence"]["nextStepChain"][0]["command"],
            "objc.classes <filter>"
        );
        assert_eq!(rendered["hook"]["coexistence"]["nextStepChain"][0]["readyToRun"], true);
        assert_eq!(
            rendered["hook"]["coexistence"]["nextStepChain"][0]["requiresFallback"],
            false
        );
        assert_eq!(
            rendered["hook"]["coexistence"]["nextStepChain"][0]["kind"],
            rendered["hook"]["coexistence"]["nextStep"]["commandJsonTemplate"]["kind"]
        );
        assert_eq!(
            rendered["hook"]["coexistence"]["nextStepChain"][0]["retryable"],
            rendered["hook"]["coexistence"]["nextStep"]["commandJsonTemplate"]["retryable"]
        );
        assert_eq!(
            rendered["hook"]["coexistence"]["nextStepChain"][0]["maxSuggestedRetries"],
            rendered["hook"]["coexistence"]["nextStep"]["commandJsonTemplate"]["maxSuggestedRetries"]
        );
        assert_eq!(
            rendered["hook"]["coexistence"]["nextStepChain"][0]["retryDelayHintMs"],
            rendered["hook"]["coexistence"]["nextStep"]["commandJsonTemplate"]["retryDelayHintMs"]
        );
        assert_eq!(
            rendered["hook"]["coexistence"]["nextStepChain"][0]["timeoutHintMs"],
            rendered["hook"]["coexistence"]["nextStep"]["commandJsonTemplate"]["timeoutHintMs"]
        );
        assert_eq!(
            rendered["hook"]["coexistence"]["nextStepChain"][0]["timeoutAction"],
            rendered["hook"]["coexistence"]["nextStep"]["commandJsonTemplate"]["timeoutAction"]
        );
        assert_eq!(
            rendered["hook"]["coexistence"]["nextStepChain"][0]["errorCode"],
            rendered["hook"]["coexistence"]["nextStep"]["commandJsonTemplate"]["errorCode"]
        );
        assert_eq!(
            rendered["hook"]["coexistence"]["nextStepChain"][0]["timeoutErrorCode"],
            rendered["hook"]["coexistence"]["nextStep"]["commandJsonTemplate"]["timeoutErrorCode"]
        );
        assert_eq!(
            rendered["hook"]["coexistence"]["nextStepChain"][0]["risk"],
            rendered["hook"]["coexistence"]["nextStep"]["commandJsonTemplate"]["risk"]
        );
        assert_eq!(
            rendered["hook"]["coexistence"]["nextStepChain"][0]["placeholderCount"],
            rendered["hook"]["coexistence"]["nextStep"]["commandJsonTemplate"]["placeholderCount"]
        );
        assert_eq!(
            rendered["hook"]["coexistence"]["nextStepChain"][0]["placeholders"],
            rendered["hook"]["coexistence"]["nextStep"]["commandJsonTemplate"]["placeholders"]
        );
        assert_eq!(
            rendered["hook"]["coexistence"]["nextStepChain"][0]["cliArgs"],
            rendered["hook"]["coexistence"]["nextStep"]["commandJsonTemplate"]["cliArgs"]
        );
        assert_eq!(
            rendered["hook"]["coexistence"]["nextStepChain"][1]["id"],
            "next-action:hook.query:1"
        );
        assert_eq!(
            rendered["hook"]["coexistence"]["nextStepChain"][1]["command"],
            "native.images <filter>"
        );
        assert_eq!(
            rendered["hook"]["coexistence"]["nextStepChain"][2]["id"],
            "next-action:hook.query:2"
        );
        assert_eq!(
            rendered["hook"]["coexistence"]["nextStepChain"][2]["command"],
            "swift.types <filter>"
        );
        assert_eq!(
            rendered["hook"]["coexistence"]["nextStepChainTruncated"],
            false
        );
        assert_eq!(rendered["hook"]["automation"]["preferredPath"], "inline-safe");
        assert_eq!(rendered["hook"]["automation"]["backendPressure"], "none");
        assert_eq!(rendered["hook"]["automation"]["loadedExternalBackendCount"], 0);
        assert_eq!(rendered["hook"]["automation"]["singleExternalBackendLoaded"], false);
        assert_eq!(rendered["hook"]["automation"]["multipleExternalBackendsLoaded"], false);
        assert_eq!(rendered["hook"]["automation"]["branchExecutionOrder"][0], "hook.query");
        assert_eq!(rendered["hook"]["automation"]["readyBranchCount"], 5);
        assert_eq!(rendered["hook"]["automation"]["blockedBranchCount"], 0);
        assert_eq!(rendered["hook"]["automation"]["nextActionKey"], "hook.query");
        assert_eq!(rendered["hook"]["automation"]["nextReadyActionKey"], "hook.query");
        assert_eq!(rendered["hook"]["automation"]["nextRunnableActionKey"], "hook.query");
        assert!(rendered["hook"]["automation"]["nextBlockedActionKey"].is_null());
        assert_eq!(rendered["hook"]["automation"]["nextActionAllowed"], true);
        assert_eq!(rendered["hook"]["automation"]["nextActionBlockedBy"], "none");
        assert_eq!(rendered["hook"]["automation"]["nextActionBranch"], "run");
        assert_eq!(rendered["hook"]["automation"]["nextActionReadyToRun"], true);
        assert_eq!(rendered["hook"]["automation"]["nextStepId"], "next-action:hook.query:0");
        assert_eq!(rendered["hook"]["automation"]["nextStepActionKey"], "hook.query");
        assert_eq!(rendered["hook"]["automation"]["nextStepCommandGroup"], "query");
        assert_eq!(rendered["hook"]["automation"]["nextStepAllowed"], true);
        assert_eq!(rendered["hook"]["automation"]["nextStepBlockedBy"], "none");
        assert_eq!(rendered["hook"]["automation"]["nextStepBranch"], "run");
        assert_eq!(rendered["hook"]["automation"]["nextStepCommand"], "objc.classes <filter>");
        assert_eq!(rendered["hook"]["automation"]["nextStepPhase"], "query");
        assert_eq!(rendered["hook"]["automation"]["nextStepCommandJsonEligible"], true);
        assert_eq!(rendered["hook"]["automation"]["nextStepReadyToRun"], true);
        assert_eq!(rendered["hook"]["automation"]["nextStepRequiresFallback"], false);
        assert_eq!(rendered["hook"]["automation"]["activeStepSource"], "next-action");
        assert_eq!(
            rendered["hook"]["automation"]["activeStepAllowed"],
            rendered["hook"]["automation"]["nextStepChain"][0]["allowed"]
        );
        assert_eq!(
            rendered["hook"]["automation"]["activeStepBlockedBy"],
            rendered["hook"]["automation"]["nextStepChain"][0]["blockedBy"]
        );
        assert_eq!(
            rendered["hook"]["automation"]["activeStepBranch"],
            rendered["hook"]["automation"]["nextStepChain"][0]["branch"]
        );
        assert_eq!(
            rendered["hook"]["automation"]["activeStepActionKey"],
            rendered["hook"]["automation"]["activeStep"]["actionKey"]
        );
        assert_eq!(
            rendered["hook"]["automation"]["activeStepCommandGroup"],
            rendered["hook"]["automation"]["activeStep"]["commandGroup"]
        );
        assert_eq!(
            rendered["hook"]["automation"]["activeStep"]["id"],
            rendered["hook"]["automation"]["nextStepChain"][0]["id"]
        );
        assert_eq!(
            rendered["hook"]["automation"]["activeStep"]["command"],
            rendered["hook"]["automation"]["nextStepChain"][0]["command"]
        );
        assert_eq!(rendered["hook"]["automation"]["activeStepId"], "next-action:hook.query:0");
        assert_eq!(rendered["hook"]["automation"]["activeStepCommand"], "objc.classes <filter>");
        assert_eq!(rendered["hook"]["automation"]["activeStepPhase"], "query");
        assert_eq!(rendered["hook"]["automation"]["activeStepReadyToRun"], true);
        assert_eq!(
            rendered["hook"]["automation"]["activeStepRequiresFallback"],
            false
        );
        assert_eq!(rendered["hook"]["automation"]["activeStepCommandJsonEligible"], true);
        assert_eq!(
            rendered["hook"]["automation"]["activeStepRetryable"],
            rendered["hook"]["automation"]["nextStep"]["commandJsonTemplate"]["retryable"]
        );
        assert_eq!(
            rendered["hook"]["automation"]["activeStepMaxSuggestedRetries"],
            rendered["hook"]["automation"]["nextStep"]["commandJsonTemplate"]["maxSuggestedRetries"]
        );
        assert_eq!(
            rendered["hook"]["automation"]["activeStepRetryDelayHintMs"],
            rendered["hook"]["automation"]["nextStep"]["commandJsonTemplate"]["retryDelayHintMs"]
        );
        assert_eq!(
            rendered["hook"]["automation"]["activeStepTimeoutHintMs"],
            rendered["hook"]["automation"]["nextStep"]["commandJsonTemplate"]["timeoutHintMs"]
        );
        assert_eq!(
            rendered["hook"]["automation"]["activeStepTimeoutAction"],
            rendered["hook"]["automation"]["nextStep"]["commandJsonTemplate"]["timeoutAction"]
        );
        assert_eq!(
            rendered["hook"]["automation"]["activeStepErrorCode"],
            rendered["hook"]["automation"]["nextStep"]["commandJsonTemplate"]["errorCode"]
        );
        assert_eq!(
            rendered["hook"]["automation"]["activeStepTimeoutErrorCode"],
            rendered["hook"]["automation"]["nextStep"]["commandJsonTemplate"]["timeoutErrorCode"]
        );
        assert_eq!(
            rendered["hook"]["automation"]["activeStepRisk"],
            rendered["hook"]["automation"]["nextStep"]["commandJsonTemplate"]["risk"]
        );
        assert_eq!(
            rendered["hook"]["automation"]["activeStepPlaceholderCount"],
            rendered["hook"]["automation"]["nextStep"]["commandJsonTemplate"]["placeholderCount"]
        );
        assert_eq!(
            rendered["hook"]["automation"]["activeStepPlaceholders"],
            rendered["hook"]["automation"]["nextStep"]["commandJsonTemplate"]["placeholders"]
        );
        assert_eq!(
            rendered["hook"]["automation"]["activeStepCliArgs"],
            rendered["hook"]["automation"]["nextStep"]["commandJsonTemplate"]["cliArgs"]
        );
        assert_eq!(
            rendered["hook"]["automation"]["nextStep"]["id"],
            "next-action:hook.query:0"
        );
        assert_eq!(rendered["hook"]["automation"]["nextStep"]["actionKey"], "hook.query");
        assert_eq!(
            rendered["hook"]["automation"]["nextStep"]["command"],
            "objc.classes <filter>"
        );
        assert_eq!(rendered["hook"]["automation"]["nextStep"]["phase"], "query");
        assert_eq!(rendered["hook"]["automation"]["nextStep"]["readyToRun"], true);
        assert_eq!(
            rendered["hook"]["automation"]["nextStep"]["requiresFallback"],
            false
        );
        assert_eq!(
            rendered["hook"]["automation"]["nextStepKind"],
            rendered["hook"]["automation"]["nextStep"]["commandJsonTemplate"]["kind"]
        );
        assert_eq!(
            rendered["hook"]["automation"]["nextStepRetryable"],
            rendered["hook"]["automation"]["nextStep"]["commandJsonTemplate"]["retryable"]
        );
        assert_eq!(
            rendered["hook"]["automation"]["nextStepMaxSuggestedRetries"],
            rendered["hook"]["automation"]["nextStep"]["commandJsonTemplate"]["maxSuggestedRetries"]
        );
        assert_eq!(
            rendered["hook"]["automation"]["nextStepRetryDelayHintMs"],
            rendered["hook"]["automation"]["nextStep"]["commandJsonTemplate"]["retryDelayHintMs"]
        );
        assert_eq!(
            rendered["hook"]["automation"]["nextStepTimeoutHintMs"],
            rendered["hook"]["automation"]["nextStep"]["commandJsonTemplate"]["timeoutHintMs"]
        );
        assert_eq!(
            rendered["hook"]["automation"]["nextStepTimeoutAction"],
            rendered["hook"]["automation"]["nextStep"]["commandJsonTemplate"]["timeoutAction"]
        );
        assert_eq!(
            rendered["hook"]["automation"]["nextStepErrorCode"],
            rendered["hook"]["automation"]["nextStep"]["commandJsonTemplate"]["errorCode"]
        );
        assert_eq!(
            rendered["hook"]["automation"]["nextStepTimeoutErrorCode"],
            rendered["hook"]["automation"]["nextStep"]["commandJsonTemplate"]["timeoutErrorCode"]
        );
        assert_eq!(
            rendered["hook"]["automation"]["nextStepRisk"],
            rendered["hook"]["automation"]["nextStep"]["commandJsonTemplate"]["risk"]
        );
        assert_eq!(
            rendered["hook"]["automation"]["nextStepPlaceholderCount"],
            rendered["hook"]["automation"]["nextStep"]["commandJsonTemplate"]["placeholderCount"]
        );
        assert_eq!(
            rendered["hook"]["automation"]["nextStepPlaceholders"],
            rendered["hook"]["automation"]["nextStep"]["commandJsonTemplate"]["placeholders"]
        );
        assert_eq!(
            rendered["hook"]["automation"]["nextStepCliArgs"],
            rendered["hook"]["automation"]["nextStep"]["commandJsonTemplate"]["cliArgs"]
        );
        assert_eq!(rendered["hook"]["automation"]["nextStepChainSource"], "next-action");
        assert_eq!(rendered["hook"]["automation"]["nextStepChainLimit"], 3);
        assert_eq!(rendered["hook"]["automation"]["nextStepChainCount"], 1);
        assert_eq!(rendered["hook"]["automation"]["nextStepChain"][0]["source"], "next-action");
        assert_eq!(
            rendered["hook"]["automation"]["nextStepChain"][0]["id"],
            "next-action:hook.query:0"
        );
        assert_eq!(
            rendered["hook"]["automation"]["nextStepChain"][0]["actionKey"],
            "hook.query"
        );
        assert_eq!(
            rendered["hook"]["automation"]["nextStepChain"][0]["commandGroup"],
            "query"
        );
        assert_eq!(
            rendered["hook"]["automation"]["nextStepChain"][0]["command"],
            "objc.classes <filter>"
        );
        assert_eq!(rendered["hook"]["automation"]["nextStepChain"][0]["readyToRun"], true);
        assert_eq!(
            rendered["hook"]["automation"]["nextStepChain"][0]["requiresFallback"],
            false
        );
        assert_eq!(
            rendered["hook"]["automation"]["nextStepChainTruncated"],
            false
        );
        assert_eq!(rendered["hook"]["automation"]["hasFallbackPlan"], false);
        assert!(rendered["hook"]["automation"]["fallbackPlan"].is_null());
        assert_eq!(rendered["hook"]["automation"]["hasSuggestedSequence"], true);
        assert_eq!(rendered["hook"]["automation"]["suggestedSequence"][0], "native.hookenv");
        assert!(rendered["hook"]["automation"]["commandTemplates"].is_array());
        assert_eq!(rendered["hook"]["automation"]["commandTemplates"][0]["actionKey"], "hook.query");
        assert_eq!(
            rendered["hook"]["automation"]["nextActionPlan"]["actionKey"],
            "hook.query"
        );
        assert_eq!(rendered["hook"]["automation"]["nextActionPlan"]["allowed"], true);
        assert_eq!(rendered["hook"]["automation"]["nextActionPlan"]["branch"], "run");
        assert_eq!(rendered["hook"]["automation"]["nextActionPlan"]["readyToRun"], true);
        assert_eq!(
            rendered["hook"]["automation"]["nextActionPlan"]["prerequisiteCount"],
            0
        );
        assert_eq!(rendered["hook"]["automation"]["nextActionTemplateCount"], 3);
        assert_eq!(rendered["hook"]["automation"]["nextActionTemplates"][0], "objc.classes <filter>");
        assert_eq!(
            rendered["hook"]["automation"]["commandTemplates"][0]["commandJsonTemplateCount"],
            3
        );
        assert_eq!(
            rendered["hook"]["automation"]["commandTemplates"][0]["commandJsonTemplates"][0]["cliArgs"][4],
            "--command-json"
        );
        assert_eq!(
            rendered["hook"]["automation"]["commandTemplates"][0]["commandJsonTemplates"][0]["kind"],
            "runtime-command"
        );
        assert_eq!(
            rendered["hook"]["automation"]["commandTemplates"][0]["commandJsonTemplates"][0]["phase"],
            "query"
        );
        assert_eq!(
            rendered["hook"]["automation"]["commandTemplates"][0]["commandJsonTemplates"][0]["retryable"],
            true
        );
        assert_eq!(
            rendered["hook"]["automation"]["commandTemplates"][0]["commandJsonTemplates"][0]["maxSuggestedRetries"],
            1
        );
        assert_eq!(
            rendered["hook"]["automation"]["commandTemplates"][0]["commandJsonTemplates"][0]["retryDelayHintMs"],
            250
        );
        assert_eq!(
            rendered["hook"]["automation"]["commandTemplates"][0]["commandJsonTemplates"][0]["timeoutHintMs"],
            5000
        );
        assert_eq!(
            rendered["hook"]["automation"]["commandTemplates"][0]["commandJsonTemplates"][0]["timeoutAction"],
            "narrow-query-filter-and-retry"
        );
        assert_eq!(
            rendered["hook"]["automation"]["commandTemplates"][0]["commandJsonTemplates"][0]["errorCode"],
            "hook-fallback-query-failed"
        );
        assert_eq!(
            rendered["hook"]["automation"]["commandTemplates"][0]["commandJsonTemplates"][0]["timeoutErrorCode"],
            "hook-fallback-query-timeout"
        );
        assert_eq!(
            rendered["hook"]["automation"]["commandTemplates"][0]["commandJsonTemplates"][0]["commandJsonEligible"],
            true
        );
        assert_eq!(
            rendered["hook"]["automation"]["commandTemplates"][0]["commandJsonTemplates"][0]["placeholderCount"],
            1
        );
        assert_eq!(
            rendered["hook"]["automation"]["commandTemplates"][0]["commandJsonTemplates"][0]["placeholders"][0],
            "<filter>"
        );
        assert_eq!(rendered["hook"]["automation"]["nextActionCommandJsonTemplateCount"], 3);
        assert_eq!(
            rendered["hook"]["automation"]["nextActionCommandJsonTemplates"][0]["cliArgs"][2],
            "--command"
        );
        assert!(rendered["hook"]["automation"]["actionBranches"].is_array());
        assert_eq!(
            rendered["hook"]["automation"]["actionBranches"][0]["actionKey"],
            "hook.query"
        );
        assert_eq!(
            rendered["hook"]["automation"]["actionBranches"][0]["selectedAsNext"],
            true
        );
        assert_eq!(
            rendered["hook"]["automation"]["actionBranches"][0]["templateCount"],
            3
        );
        assert_eq!(
            rendered["hook"]["automation"]["actionBranches"][0]["commandJsonTemplateCount"],
            3
        );
        assert_eq!(
            rendered["hook"]["automation"]["actionBranches"][0]["commandJsonEligibleTemplateCount"],
            3
        );
        assert_eq!(rendered["hook"]["automation"]["actionBranches"][0]["executionRank"], 0);
        assert_eq!(rendered["hook"]["automation"]["actionBranches"][0]["executionIndex"], 0);
        assert_eq!(rendered["hook"]["automation"]["actionBranches"][0]["readyToRun"], true);
        assert_eq!(rendered["trace"]["payloadAddressHex"], json!("0x5000"));
        assert_eq!(rendered["handshake"]["hello"]["arch"], "aarch64");
        assert_eq!(rendered["handshake"]["stage"], "completed");
        assert_eq!(rendered["handshake"]["steps"]["hello"], "succeeded");
        assert_eq!(rendered["handshake"]["steps"]["ping"], "succeeded");
        assert_eq!(rendered["handshake"]["steps"]["hookEnvironment"], "succeeded");
        assert_eq!(rendered["handshake"]["steps"]["jsInit"], "succeeded");
        assert_eq!(rendered["handshake"]["steps"]["loadJs"], "succeeded");
        assert!(rendered["handshake"]["errors"]["hello"].is_null());
        assert!(rendered["handshake"]["errors"]["jsInit"].is_null());
        assert_eq!(rendered["handshake"]["ping"], "pong");
        assert_eq!(rendered["handshake"]["script"]["loadJsResult"], "script loaded");
        assert_eq!(rendered["handshake"]["agentLogs"][0], "agent log line");
        assert!(rendered["diagnostics"].is_null());
    }

    #[test]
    fn hook_effective_actions_report_blocked_by_source() {
        let report = HookEnvironmentReport {
            active_backend: None,
            backends: vec![],
            warnings: vec![],
        };
        let controller_strategy = HookStrategyDecision {
            policy: HookPolicy::QueryOnlyExternalLoaded,
            strategy: "query-only-external-loaded".into(),
            allowed: true,
            inline_hooks_allowed: false,
            reason: Some("controller query-only".into()),
        };
        let target_strategy = HookStrategyDecision {
            policy: HookPolicy::DenyExternalLoaded,
            strategy: "cleanup-only-external-loaded".into(),
            allowed: false,
            inline_hooks_allowed: false,
            reason: Some("target cleanup-only".into()),
        };
        let controller_actions = hook_environment_recommended_actions(&report, Some(&controller_strategy));
        let target_actions = hook_environment_recommended_actions(&report, Some(&target_strategy));
        let effective_actions = hook_effective_actions(&controller_actions, &target_actions);

        let rendered = hook_effective_actions_to_json(&effective_actions);
        let actions = rendered.as_array().expect("effective action array");
        let find = |key: &str| {
            actions
                .iter()
                .find(|item| item["actionKey"] == key)
                .unwrap_or_else(|| panic!("missing action key {key}"))
        };

        let query = find("hook.query");
        assert_eq!(query["allowed"], false);
        assert_eq!(query["blockedBy"], "target");

        let install = find("hook.install");
        assert_eq!(install["allowed"], false);
        assert_eq!(install["blockedBy"], "both");

        let status = find("hook.status");
        assert_eq!(status["allowed"], true);
        assert_eq!(status["blockedBy"], "none");

        let effective = hook_effective_to_json(&effective_actions);
        assert_eq!(effective["commandMode"], "cleanup-only");
        assert_eq!(effective["blockedBySummary"]["controller"], 1);
        assert_eq!(effective["blockedBySummary"]["target"], 2);
        assert_eq!(effective["blockedBySummary"]["both"], 1);

        let backend_matrix = hook_backend_matrix_to_json(&report, &report);
        let automation = hook_automation_to_json(&effective_actions, &backend_matrix);
        assert_eq!(automation["preferredPath"], "cleanup-only");
        assert_eq!(automation["backendPressure"], "none");
        assert_eq!(automation["loadedExternalBackendCount"], 0);
        assert_eq!(automation["singleExternalBackendLoaded"], false);
        assert_eq!(automation["multipleExternalBackendsLoaded"], false);
        assert_eq!(automation["branchExecutionOrder"][0], "hook.status");
        assert_eq!(automation["nextActionKey"], "hook.status");
        assert_eq!(automation["nextReadyActionKey"], "hook.status");
        assert_eq!(automation["nextRunnableActionKey"], "hook.status");
        assert_eq!(automation["nextBlockedActionKey"], "hook.query");
        assert_eq!(automation["nextActionAllowed"], true);
        assert_eq!(automation["nextActionBlockedBy"], "none");
        assert_eq!(automation["nextActionBranch"], "run");
        assert_eq!(automation["nextActionReadyToRun"], true);
        assert_eq!(automation["nextStepId"], "next-action:hook.status:0");
        assert_eq!(automation["nextStepActionKey"], "hook.status");
        assert_eq!(automation["nextStepCommandGroup"], "hook-status");
        assert_eq!(automation["nextStepAllowed"], true);
        assert_eq!(automation["nextStepBlockedBy"], "none");
        assert_eq!(automation["nextStepBranch"], "run");
        assert_eq!(automation["nextStepCommand"], "trace status");
        assert_eq!(automation["nextStepPhase"], "cleanup");
        assert_eq!(automation["nextStepCommandJsonEligible"], true);
        assert_eq!(
            automation["nextStepKind"],
            automation["nextStep"]["commandJsonTemplate"]["kind"]
        );
        assert_eq!(
            automation["nextStepRetryable"],
            automation["nextStep"]["commandJsonTemplate"]["retryable"]
        );
        assert_eq!(
            automation["nextStepMaxSuggestedRetries"],
            automation["nextStep"]["commandJsonTemplate"]["maxSuggestedRetries"]
        );
        assert_eq!(
            automation["nextStepRetryDelayHintMs"],
            automation["nextStep"]["commandJsonTemplate"]["retryDelayHintMs"]
        );
        assert_eq!(
            automation["nextStepTimeoutHintMs"],
            automation["nextStep"]["commandJsonTemplate"]["timeoutHintMs"]
        );
        assert_eq!(
            automation["nextStepTimeoutAction"],
            automation["nextStep"]["commandJsonTemplate"]["timeoutAction"]
        );
        assert_eq!(
            automation["nextStepErrorCode"],
            automation["nextStep"]["commandJsonTemplate"]["errorCode"]
        );
        assert_eq!(
            automation["nextStepTimeoutErrorCode"],
            automation["nextStep"]["commandJsonTemplate"]["timeoutErrorCode"]
        );
        assert_eq!(
            automation["nextStepRisk"],
            automation["nextStep"]["commandJsonTemplate"]["risk"]
        );
        assert_eq!(
            automation["nextStepPlaceholderCount"],
            automation["nextStep"]["commandJsonTemplate"]["placeholderCount"]
        );
        assert_eq!(
            automation["nextStepPlaceholders"],
            automation["nextStep"]["commandJsonTemplate"]["placeholders"]
        );
        assert_eq!(
            automation["nextStepCliArgs"],
            automation["nextStep"]["commandJsonTemplate"]["cliArgs"]
        );
        assert_eq!(automation["nextStepReadyToRun"], true);
        assert_eq!(automation["nextStepRequiresFallback"], false);
        assert_eq!(automation["activeStepSource"], "next-action");
        assert_eq!(automation["activeStepAllowed"], true);
        assert_eq!(automation["activeStepBlockedBy"], "none");
        assert_eq!(automation["activeStepBranch"], "run");
        assert_eq!(
            automation["activeStepActionKey"],
            automation["activeStep"]["actionKey"]
        );
        assert_eq!(
            automation["activeStepCommandGroup"],
            automation["activeStep"]["commandGroup"]
        );
        assert_eq!(
            automation["activeStep"]["id"],
            automation["nextStepChain"][0]["id"]
        );
        assert_eq!(
            automation["activeStep"]["command"],
            automation["nextStepChain"][0]["command"]
        );
        assert_eq!(automation["activeStepId"], "next-action:hook.status:0");
        assert_eq!(automation["activeStepCommand"], "trace status");
        assert_eq!(automation["activeStepPhase"], "cleanup");
        assert_eq!(automation["activeStepReadyToRun"], true);
        assert_eq!(automation["activeStepRequiresFallback"], false);
        assert_eq!(automation["activeStepCommandJsonEligible"], true);
        assert_eq!(
            automation["activeStepRetryable"],
            automation["nextStep"]["commandJsonTemplate"]["retryable"]
        );
        assert_eq!(
            automation["activeStepMaxSuggestedRetries"],
            automation["nextStep"]["commandJsonTemplate"]["maxSuggestedRetries"]
        );
        assert_eq!(
            automation["activeStepRetryDelayHintMs"],
            automation["nextStep"]["commandJsonTemplate"]["retryDelayHintMs"]
        );
        assert_eq!(
            automation["activeStepTimeoutHintMs"],
            automation["nextStep"]["commandJsonTemplate"]["timeoutHintMs"]
        );
        assert_eq!(
            automation["activeStepTimeoutAction"],
            automation["nextStep"]["commandJsonTemplate"]["timeoutAction"]
        );
        assert_eq!(
            automation["activeStepErrorCode"],
            automation["nextStep"]["commandJsonTemplate"]["errorCode"]
        );
        assert_eq!(
            automation["activeStepTimeoutErrorCode"],
            automation["nextStep"]["commandJsonTemplate"]["timeoutErrorCode"]
        );
        assert_eq!(
            automation["activeStepRisk"],
            automation["nextStep"]["commandJsonTemplate"]["risk"]
        );
        assert_eq!(
            automation["activeStepPlaceholderCount"],
            automation["nextStep"]["commandJsonTemplate"]["placeholderCount"]
        );
        assert_eq!(
            automation["activeStepPlaceholders"],
            automation["nextStep"]["commandJsonTemplate"]["placeholders"]
        );
        assert_eq!(
            automation["activeStepCliArgs"],
            automation["nextStep"]["commandJsonTemplate"]["cliArgs"]
        );
        assert_eq!(automation["nextStep"]["id"], "next-action:hook.status:0");
        assert_eq!(automation["nextStep"]["actionKey"], "hook.status");
        assert_eq!(automation["nextStep"]["command"], "trace status");
        assert_eq!(automation["nextStep"]["phase"], "cleanup");
        assert_eq!(automation["nextStep"]["readyToRun"], true);
        assert_eq!(automation["nextStep"]["requiresFallback"], false);
        assert_eq!(automation["nextStepChainSource"], "next-action");
        assert_eq!(automation["nextStepChainLimit"], 3);
        assert_eq!(automation["nextStepChainCount"], 1);
        assert_eq!(automation["nextStepChain"][0]["source"], "next-action");
        assert_eq!(automation["nextStepChain"][0]["id"], "next-action:hook.status:0");
        assert_eq!(automation["nextStepChain"][0]["actionKey"], "hook.status");
        assert_eq!(automation["nextStepChain"][0]["commandGroup"], "hook-status");
        assert_eq!(automation["nextStepChain"][0]["command"], "trace status");
        assert_eq!(automation["nextStepChain"][0]["phase"], "cleanup");
        assert_eq!(automation["nextStepChain"][0]["readyToRun"], true);
        assert_eq!(automation["nextStepChain"][0]["requiresFallback"], false);
        assert_eq!(automation["nextStepChain"][0]["allowed"], true);
        assert_eq!(automation["nextStepChain"][0]["blockedBy"], "none");
        assert_eq!(automation["nextStepChain"][0]["branch"], "run");
        assert_eq!(automation["nextStepChainTruncated"], false);
        assert_eq!(automation["hasFallbackPlan"], false);
        assert!(automation["fallbackPlan"].is_null());
        assert_eq!(automation["hasSuggestedSequence"], true);
        assert_eq!(automation["suggestedSequence"][0], "trace status");
        assert_eq!(automation["nextActionPlan"]["actionKey"], "hook.status");
        assert_eq!(automation["nextActionPlan"]["allowed"], true);
        assert_eq!(automation["nextActionPlan"]["branch"], "run");
        assert_eq!(automation["nextActionPlan"]["readyToRun"], true);
        assert_eq!(automation["nextActionTemplateCount"], 5);
        assert_eq!(automation["nextActionTemplates"][0], "trace status");
        assert_eq!(automation["nextActionCommandJsonTemplateCount"], 5);
        assert_eq!(
            automation["nextActionCommandJsonTemplates"][0]["command"],
            "trace status"
        );
        let branches = automation["actionBranches"].as_array().expect("automation action branches");
        let query_branch = branches
            .iter()
            .find(|item| item["actionKey"] == "hook.query")
            .expect("query branch");
        assert_eq!(query_branch["branch"], "skip-target-policy");
        assert_eq!(query_branch["selectedAsNext"], false);
        assert_eq!(query_branch["readyToRun"], false);
        assert_eq!(query_branch["templateCount"], 3);
        assert_eq!(query_branch["commandJsonTemplateCount"], 3);
        assert_eq!(query_branch["commandJsonEligibleTemplateCount"], 3);
        let status_branch = branches
            .iter()
            .find(|item| item["actionKey"] == "hook.status")
            .expect("status branch");
        assert_eq!(status_branch["branch"], "run");
        assert_eq!(status_branch["selectedAsNext"], true);
        assert_eq!(status_branch["readyToRun"], true);
        assert_eq!(status_branch["templateCount"], 5);
        assert_eq!(status_branch["commandJsonTemplateCount"], 5);
        assert_eq!(status_branch["commandJsonEligibleTemplateCount"], 5);
    }

    #[test]
    fn hook_automation_emits_fallback_plan_when_next_action_not_ready() {
        let report = HookEnvironmentReport {
            active_backend: None,
            backends: vec![],
            warnings: vec![],
        };
        let backend_matrix = hook_backend_matrix_to_json(&report, &report);
        let actions = vec![
            HookEffectiveAction {
                action_key: "hook.query",
                command_group: "query",
                allowed: false,
                blocked_by: "both",
                priority: 1,
                controller_allowed: false,
                target_allowed: false,
                controller_priority: 1,
                target_priority: 1,
                recommendation: "query blocked".into(),
                controller_reason: Some("controller blocked query".into()),
                target_reason: Some("target blocked query".into()),
            },
            HookEffectiveAction {
                action_key: "hook.bootstrap",
                command_group: "bootstrap",
                allowed: false,
                blocked_by: "both",
                priority: 2,
                controller_allowed: false,
                target_allowed: false,
                controller_priority: 2,
                target_priority: 2,
                recommendation: "bootstrap blocked".into(),
                controller_reason: Some("controller blocked bootstrap".into()),
                target_reason: Some("target blocked bootstrap".into()),
            },
            HookEffectiveAction {
                action_key: "hook.install",
                command_group: "hook-install",
                allowed: false,
                blocked_by: "both",
                priority: 3,
                controller_allowed: false,
                target_allowed: false,
                controller_priority: 3,
                target_priority: 3,
                recommendation: "install blocked".into(),
                controller_reason: Some("controller blocked install".into()),
                target_reason: Some("target blocked install".into()),
            },
            HookEffectiveAction {
                action_key: "hook.status",
                command_group: "hook-status",
                allowed: false,
                blocked_by: "both",
                priority: 4,
                controller_allowed: false,
                target_allowed: false,
                controller_priority: 4,
                target_priority: 4,
                recommendation: "status blocked".into(),
                controller_reason: Some("controller blocked status".into()),
                target_reason: Some("target blocked status".into()),
            },
            HookEffectiveAction {
                action_key: "hook.stop",
                command_group: "hook-stop",
                allowed: false,
                blocked_by: "both",
                priority: 5,
                controller_allowed: false,
                target_allowed: false,
                controller_priority: 5,
                target_priority: 5,
                recommendation: "stop blocked".into(),
                controller_reason: Some("controller blocked stop".into()),
                target_reason: Some("target blocked stop".into()),
            },
        ];

        let automation = hook_automation_to_json(&actions, &backend_matrix);
        assert_eq!(automation["nextActionKey"], "hook.query");
        assert!(automation["nextReadyActionKey"].is_null());
        assert_eq!(automation["nextActionReadyToRun"], false);
        assert_eq!(automation["nextStepId"], "next-action:hook.query:0");
        assert_eq!(automation["nextStepActionKey"], "hook.query");
        assert_eq!(automation["nextStepCommandGroup"], "query");
        assert_eq!(automation["nextStepAllowed"], false);
        assert_eq!(automation["nextStepBlockedBy"], "both");
        assert_eq!(automation["nextStepBranch"], "skip-both-policies");
        assert_eq!(automation["nextStepCommand"], "objc.classes <filter>");
        assert_eq!(automation["nextStepPhase"], "query");
        assert_eq!(automation["nextStepCommandJsonEligible"], true);
        assert_eq!(
            automation["nextStepKind"],
            automation["nextStep"]["commandJsonTemplate"]["kind"]
        );
        assert_eq!(
            automation["nextStepRetryable"],
            automation["nextStep"]["commandJsonTemplate"]["retryable"]
        );
        assert_eq!(
            automation["nextStepMaxSuggestedRetries"],
            automation["nextStep"]["commandJsonTemplate"]["maxSuggestedRetries"]
        );
        assert_eq!(
            automation["nextStepRetryDelayHintMs"],
            automation["nextStep"]["commandJsonTemplate"]["retryDelayHintMs"]
        );
        assert_eq!(
            automation["nextStepTimeoutHintMs"],
            automation["nextStep"]["commandJsonTemplate"]["timeoutHintMs"]
        );
        assert_eq!(
            automation["nextStepTimeoutAction"],
            automation["nextStep"]["commandJsonTemplate"]["timeoutAction"]
        );
        assert_eq!(
            automation["nextStepErrorCode"],
            automation["nextStep"]["commandJsonTemplate"]["errorCode"]
        );
        assert_eq!(
            automation["nextStepTimeoutErrorCode"],
            automation["nextStep"]["commandJsonTemplate"]["timeoutErrorCode"]
        );
        assert_eq!(
            automation["nextStepRisk"],
            automation["nextStep"]["commandJsonTemplate"]["risk"]
        );
        assert_eq!(
            automation["nextStepPlaceholderCount"],
            automation["nextStep"]["commandJsonTemplate"]["placeholderCount"]
        );
        assert_eq!(
            automation["nextStepPlaceholders"],
            automation["nextStep"]["commandJsonTemplate"]["placeholders"]
        );
        assert_eq!(
            automation["nextStepCliArgs"],
            automation["nextStep"]["commandJsonTemplate"]["cliArgs"]
        );
        assert_eq!(automation["nextStepReadyToRun"], false);
        assert_eq!(automation["nextStepRequiresFallback"], true);
        assert_eq!(automation["activeStepSource"], "fallback-plan");
        assert_eq!(
            automation["activeStepAllowed"],
            automation["nextStepChain"][0]["allowed"]
        );
        assert_eq!(
            automation["activeStepBlockedBy"],
            automation["nextStepChain"][0]["blockedBy"]
        );
        assert_eq!(
            automation["activeStepBranch"],
            automation["nextStepChain"][0]["branch"]
        );
        assert_eq!(
            automation["activeStepActionKey"],
            automation["activeStep"]["actionKey"]
        );
        assert_eq!(
            automation["activeStepCommandGroup"],
            automation["activeStep"]["commandGroup"]
        );
        assert_eq!(
            automation["activeStep"]["id"],
            automation["nextStepChain"][0]["id"]
        );
        assert_eq!(
            automation["activeStep"]["command"],
            automation["nextStepChain"][0]["command"]
        );
        assert_eq!(automation["activeStepId"], "fallback-plan:0");
        assert_eq!(automation["activeStepCommand"], "native.hookenv");
        assert_eq!(automation["activeStepPhase"], "diagnose");
        assert_eq!(automation["activeStepReadyToRun"], true);
        assert_eq!(automation["activeStepRequiresFallback"], true);
        assert_eq!(automation["activeStepCommandJsonEligible"], true);
        assert_eq!(
            automation["activeStepRetryable"],
            automation["fallbackPlan"]["steps"][0]["retryable"]
        );
        assert_eq!(
            automation["activeStepMaxSuggestedRetries"],
            automation["fallbackPlan"]["steps"][0]["maxSuggestedRetries"]
        );
        assert_eq!(
            automation["activeStepRetryDelayHintMs"],
            automation["fallbackPlan"]["steps"][0]["retryDelayHintMs"]
        );
        assert_eq!(
            automation["activeStepTimeoutHintMs"],
            automation["fallbackPlan"]["steps"][0]["timeoutHintMs"]
        );
        assert_eq!(
            automation["activeStepTimeoutAction"],
            automation["fallbackPlan"]["steps"][0]["timeoutAction"]
        );
        assert_eq!(
            automation["activeStepErrorCode"],
            automation["fallbackPlan"]["steps"][0]["errorCode"]
        );
        assert_eq!(
            automation["activeStepTimeoutErrorCode"],
            automation["fallbackPlan"]["steps"][0]["timeoutErrorCode"]
        );
        assert_eq!(
            automation["activeStepRisk"],
            automation["fallbackPlan"]["steps"][0]["risk"]
        );
        assert_eq!(
            automation["activeStepPlaceholderCount"],
            automation["fallbackPlan"]["steps"][0]["placeholderCount"]
        );
        assert_eq!(
            automation["activeStepPlaceholders"],
            automation["fallbackPlan"]["steps"][0]["placeholders"]
        );
        assert_eq!(
            automation["activeStepCliArgs"],
            automation["fallbackPlan"]["steps"][0]["cliArgs"]
        );
        assert_eq!(automation["nextStep"]["id"], "next-action:hook.query:0");
        assert_eq!(automation["nextStep"]["actionKey"], "hook.query");
        assert_eq!(automation["nextStep"]["command"], "objc.classes <filter>");
        assert_eq!(automation["nextStep"]["phase"], "query");
        assert_eq!(automation["nextStep"]["readyToRun"], false);
        assert_eq!(automation["nextStep"]["requiresFallback"], true);
        assert_eq!(automation["nextStepChainSource"], "fallback-plan");
        assert_eq!(automation["nextStepChainLimit"], 3);
        assert_eq!(automation["nextStepChainCount"], 2);
        assert_eq!(automation["nextStepChain"][0]["source"], "fallback-plan");
        assert_eq!(automation["nextStepChain"][0]["id"], "fallback-plan:0");
        assert!(automation["nextStepChain"][0]["actionKey"].is_null());
        assert!(automation["nextStepChain"][0]["commandGroup"].is_null());
        assert!(automation["nextStepChain"][0]["allowed"].is_null());
        assert!(automation["nextStepChain"][0]["blockedBy"].is_null());
        assert!(automation["nextStepChain"][0]["branch"].is_null());
        assert_eq!(automation["nextStepChain"][0]["command"], "native.hookenv");
        assert_eq!(automation["nextStepChain"][0]["phase"], "diagnose");
        assert_eq!(automation["nextStepChain"][0]["readyToRun"], true);
        assert_eq!(automation["nextStepChain"][0]["requiresFallback"], true);
        assert_eq!(automation["nextStepChain"][1]["id"], "fallback-plan:1");
        assert!(automation["nextStepChain"][1]["actionKey"].is_null());
        assert!(automation["nextStepChain"][1]["commandGroup"].is_null());
        assert!(automation["nextStepChain"][1]["allowed"].is_null());
        assert!(automation["nextStepChain"][1]["blockedBy"].is_null());
        assert!(automation["nextStepChain"][1]["branch"].is_null());
        assert_eq!(automation["nextStepChain"][1]["command"], "controller --preflight-only --preflight-json");
        assert_eq!(automation["nextStepChain"][1]["phase"], "preflight");
        assert_eq!(automation["nextStepChain"][1]["readyToRun"], true);
        assert_eq!(automation["nextStepChain"][1]["requiresFallback"], true);
        assert_eq!(automation["nextStepChainTruncated"], false);
        assert_eq!(automation["hasFallbackPlan"], true);
        assert_eq!(automation["fallbackPlan"]["trigger"], "next-action-not-ready");
        assert_eq!(automation["fallbackPlan"]["fromActionKey"], "hook.query");
        assert!(automation["fallbackPlan"]["toActionKey"].is_null());
        assert_eq!(automation["fallbackPlan"]["usesSuggestedSequence"], true);
        assert_eq!(automation["fallbackPlan"]["templateCount"], 2);
        assert_eq!(automation["fallbackPlan"]["templates"][0], "native.hookenv");
        assert_eq!(
            automation["fallbackPlan"]["templates"][1],
            "controller --preflight-only --preflight-json"
        );
        assert_eq!(automation["fallbackPlan"]["steps"][0]["source"], "fallback-plan");
        assert_eq!(automation["fallbackPlan"]["steps"][0]["readyToRun"], true);
        assert_eq!(automation["fallbackPlan"]["steps"][0]["requiresFallback"], true);
        assert!(automation["fallbackPlan"]["steps"][0]["actionKey"].is_null());
        assert!(automation["fallbackPlan"]["steps"][0]["commandGroup"].is_null());
        assert_eq!(automation["fallbackPlan"]["steps"][1]["source"], "fallback-plan");
        assert_eq!(automation["fallbackPlan"]["steps"][1]["readyToRun"], true);
        assert_eq!(automation["fallbackPlan"]["steps"][1]["requiresFallback"], true);
        assert!(automation["fallbackPlan"]["steps"][1]["actionKey"].is_null());
        assert!(automation["fallbackPlan"]["steps"][1]["commandGroup"].is_null());
        assert_eq!(automation["fallbackPlan"]["phaseCount"], 2);
        assert_eq!(automation["fallbackPlan"]["phaseOrder"], json!(["diagnose", "preflight"]));
        assert_eq!(automation["fallbackPlan"]["nextStepChainSource"], "fallback-plan");
        assert_eq!(automation["fallbackPlan"]["nextStepChainLimit"], 3);
        assert_eq!(automation["fallbackPlan"]["nextStepChainCount"], 2);
        assert_eq!(automation["fallbackPlan"]["nextStepChain"][0]["id"], "fallback-plan:0");
        assert_eq!(automation["fallbackPlan"]["nextStepChain"][0]["command"], "native.hookenv");
        assert_eq!(automation["fallbackPlan"]["nextStepChain"][1]["id"], "fallback-plan:1");
        assert_eq!(
            automation["fallbackPlan"]["nextStepChain"][1]["command"],
            "controller --preflight-only --preflight-json"
        );
        assert_eq!(automation["fallbackPlan"]["nextStepChainTruncated"], false);
        assert_eq!(
            automation["fallbackPlan"]["activeStep"]["id"],
            automation["fallbackPlan"]["nextStepChain"][0]["id"]
        );
        assert_eq!(
            automation["fallbackPlan"]["activeStep"]["command"],
            automation["fallbackPlan"]["nextStepChain"][0]["command"]
        );
        assert_eq!(
            automation["fallbackPlan"]["activeStep"]["phase"],
            automation["fallbackPlan"]["nextStepChain"][0]["phase"]
        );
        assert_eq!(
            automation["fallbackPlan"]["steps"][0]["id"],
            automation["fallbackPlan"]["nextStepChain"][0]["id"]
        );
        assert_eq!(
            automation["fallbackPlan"]["steps"][0]["command"],
            automation["fallbackPlan"]["nextStepChain"][0]["command"]
        );
        assert_eq!(
            automation["fallbackPlan"]["steps"][0]["phase"],
            automation["fallbackPlan"]["nextStepChain"][0]["phase"]
        );
        assert_eq!(
            automation["fallbackPlan"]["activeStepSource"],
            automation["fallbackPlan"]["nextStepChain"][0]["source"]
        );
        assert_eq!(
            automation["fallbackPlan"]["activeStepAllowed"],
            automation["fallbackPlan"]["nextStepChain"][0]["allowed"]
        );
        assert_eq!(
            automation["fallbackPlan"]["activeStepBlockedBy"],
            automation["fallbackPlan"]["nextStepChain"][0]["blockedBy"]
        );
        assert_eq!(
            automation["fallbackPlan"]["activeStepBranch"],
            automation["fallbackPlan"]["nextStepChain"][0]["branch"]
        );
        assert_eq!(
            automation["fallbackPlan"]["activeStepActionKey"],
            automation["fallbackPlan"]["nextStepChain"][0]["actionKey"]
        );
        assert_eq!(
            automation["fallbackPlan"]["activeStepCommandGroup"],
            automation["fallbackPlan"]["nextStepChain"][0]["commandGroup"]
        );
        assert_eq!(
            automation["fallbackPlan"]["activeStepId"],
            automation["fallbackPlan"]["nextStepChain"][0]["id"]
        );
        assert_eq!(
            automation["fallbackPlan"]["activeStepCommand"],
            automation["fallbackPlan"]["nextStepChain"][0]["command"]
        );
        assert_eq!(
            automation["fallbackPlan"]["activeStepPhase"],
            automation["fallbackPlan"]["nextStepChain"][0]["phase"]
        );
        assert_eq!(
            automation["fallbackPlan"]["activeStepReadyToRun"],
            automation["fallbackPlan"]["nextStepChain"][0]["readyToRun"]
        );
        assert_eq!(
            automation["fallbackPlan"]["activeStepRequiresFallback"],
            automation["fallbackPlan"]["nextStepChain"][0]["requiresFallback"]
        );
        assert_eq!(
            automation["fallbackPlan"]["activeStepKind"],
            automation["fallbackPlan"]["nextStepChain"][0]["kind"]
        );
        assert_eq!(
            automation["fallbackPlan"]["activeStepCommandJsonEligible"],
            automation["fallbackPlan"]["nextStepChain"][0]["commandJsonEligible"]
        );
        assert_eq!(
            automation["fallbackPlan"]["activeStepRetryable"],
            automation["fallbackPlan"]["nextStepChain"][0]["retryable"]
        );
        assert_eq!(
            automation["fallbackPlan"]["activeStepMaxSuggestedRetries"],
            automation["fallbackPlan"]["nextStepChain"][0]["maxSuggestedRetries"]
        );
        assert_eq!(
            automation["fallbackPlan"]["activeStepRetryDelayHintMs"],
            automation["fallbackPlan"]["nextStepChain"][0]["retryDelayHintMs"]
        );
        assert_eq!(
            automation["fallbackPlan"]["activeStepTimeoutHintMs"],
            automation["fallbackPlan"]["nextStepChain"][0]["timeoutHintMs"]
        );
        assert_eq!(
            automation["fallbackPlan"]["activeStepTimeoutAction"],
            automation["fallbackPlan"]["nextStepChain"][0]["timeoutAction"]
        );
        assert_eq!(
            automation["fallbackPlan"]["activeStepErrorCode"],
            automation["fallbackPlan"]["nextStepChain"][0]["errorCode"]
        );
        assert_eq!(
            automation["fallbackPlan"]["activeStepTimeoutErrorCode"],
            automation["fallbackPlan"]["nextStepChain"][0]["timeoutErrorCode"]
        );
        assert_eq!(
            automation["fallbackPlan"]["activeStepRisk"],
            automation["fallbackPlan"]["nextStepChain"][0]["risk"]
        );
        assert_eq!(
            automation["fallbackPlan"]["activeStepPlaceholderCount"],
            automation["fallbackPlan"]["nextStepChain"][0]["placeholderCount"]
        );
        assert_eq!(
            automation["fallbackPlan"]["activeStepPlaceholders"],
            automation["fallbackPlan"]["nextStepChain"][0]["placeholders"]
        );
        assert_eq!(
            automation["fallbackPlan"]["activeStepCliArgs"],
            automation["fallbackPlan"]["nextStepChain"][0]["cliArgs"]
        );
        assert_eq!(automation["fallbackPlan"]["nextStepId"], "fallback-plan:0");
        assert_eq!(automation["fallbackPlan"]["nextStepSource"], "fallback-plan");
        assert!(automation["fallbackPlan"]["nextStepActionKey"].is_null());
        assert!(automation["fallbackPlan"]["nextStepCommandGroup"].is_null());
        assert!(automation["fallbackPlan"]["nextStepAllowed"].is_null());
        assert!(automation["fallbackPlan"]["nextStepBlockedBy"].is_null());
        assert!(automation["fallbackPlan"]["nextStepBranch"].is_null());
        assert_eq!(automation["fallbackPlan"]["nextStepCommand"], "native.hookenv");
        assert_eq!(automation["fallbackPlan"]["nextStepPhase"], "diagnose");
        assert_eq!(automation["fallbackPlan"]["nextStepCommandJsonEligible"], true);
        assert_eq!(automation["fallbackPlan"]["nextStepRetryable"], true);
        assert_eq!(
            automation["fallbackPlan"]["nextStepMaxSuggestedRetries"],
            automation["fallbackPlan"]["steps"][0]["maxSuggestedRetries"]
        );
        assert_eq!(
            automation["fallbackPlan"]["nextStepRetryDelayHintMs"],
            automation["fallbackPlan"]["steps"][0]["retryDelayHintMs"]
        );
        assert_eq!(
            automation["fallbackPlan"]["nextStepTimeoutHintMs"],
            automation["fallbackPlan"]["steps"][0]["timeoutHintMs"]
        );
        assert_eq!(
            automation["fallbackPlan"]["nextStepTimeoutAction"],
            automation["fallbackPlan"]["steps"][0]["timeoutAction"]
        );
        assert_eq!(
            automation["fallbackPlan"]["nextStepKind"],
            automation["fallbackPlan"]["steps"][0]["kind"]
        );
        assert_eq!(automation["fallbackPlan"]["nextStepErrorCode"], "hook-fallback-diagnose-failed");
        assert_eq!(
            automation["fallbackPlan"]["nextStepTimeoutErrorCode"],
            "hook-fallback-diagnose-timeout"
        );
        assert_eq!(
            automation["fallbackPlan"]["nextStepRisk"],
            automation["fallbackPlan"]["steps"][0]["risk"]
        );
        assert_eq!(
            automation["fallbackPlan"]["nextStepPlaceholderCount"],
            automation["fallbackPlan"]["steps"][0]["placeholderCount"]
        );
        assert_eq!(
            automation["fallbackPlan"]["nextStepPlaceholders"],
            automation["fallbackPlan"]["steps"][0]["placeholders"]
        );
        assert_eq!(
            automation["fallbackPlan"]["nextStepCliArgs"],
            automation["fallbackPlan"]["steps"][0]["cliArgs"]
        );
        assert_eq!(automation["fallbackPlan"]["phaseRetryPolicyCount"], 2);
        assert_eq!(automation["fallbackPlan"]["phaseRetryPolicies"][0]["phase"], "diagnose");
        assert_eq!(automation["fallbackPlan"]["phaseRetryPolicies"][0]["retryable"], true);
        assert_eq!(automation["fallbackPlan"]["phaseRetryPolicies"][0]["maxSuggestedRetries"], 1);
        assert_eq!(automation["fallbackPlan"]["phaseRetryPolicies"][0]["retryDelayHintMs"], 250);
        assert_eq!(automation["fallbackPlan"]["phaseRetryPolicies"][1]["phase"], "preflight");
        assert_eq!(automation["fallbackPlan"]["phaseRetryPolicies"][1]["retryable"], true);
        assert_eq!(automation["fallbackPlan"]["phaseRetryPolicies"][1]["maxSuggestedRetries"], 2);
        assert_eq!(automation["fallbackPlan"]["phaseRetryPolicies"][1]["retryDelayHintMs"], 500);
        assert_eq!(automation["fallbackPlan"]["phaseRetryPolicies"][0]["timeoutHintMs"], 4000);
        assert_eq!(
            automation["fallbackPlan"]["phaseRetryPolicies"][0]["timeoutAction"],
            "refresh-hook-environment-and-retry"
        );
        assert_eq!(automation["fallbackPlan"]["phaseRetryPolicies"][1]["timeoutHintMs"], 8000);
        assert_eq!(
            automation["fallbackPlan"]["phaseRetryPolicies"][1]["timeoutAction"],
            "re-run-preflight-or-switch-to-query-only"
        );
        assert_eq!(automation["fallbackPlan"]["phaseTimeoutPolicyCount"], 2);
        assert_eq!(automation["fallbackPlan"]["phaseTimeoutPolicies"][0]["phase"], "diagnose");
        assert_eq!(automation["fallbackPlan"]["phaseTimeoutPolicies"][0]["timeoutHintMs"], 4000);
        assert_eq!(
            automation["fallbackPlan"]["phaseTimeoutPolicies"][0]["timeoutAction"],
            "refresh-hook-environment-and-retry"
        );
        assert_eq!(automation["fallbackPlan"]["phaseTimeoutPolicies"][1]["phase"], "preflight");
        assert_eq!(automation["fallbackPlan"]["phaseTimeoutPolicies"][1]["timeoutHintMs"], 8000);
        assert_eq!(
            automation["fallbackPlan"]["phaseTimeoutPolicies"][1]["timeoutAction"],
            "re-run-preflight-or-switch-to-query-only"
        );
        assert_eq!(automation["fallbackPlan"]["phaseRetryPolicies"][0]["errorCode"], "hook-fallback-diagnose-failed");
        assert_eq!(
            automation["fallbackPlan"]["phaseRetryPolicies"][0]["timeoutErrorCode"],
            "hook-fallback-diagnose-timeout"
        );
        assert_eq!(automation["fallbackPlan"]["phaseRetryPolicies"][1]["errorCode"], "hook-fallback-preflight-failed");
        assert_eq!(
            automation["fallbackPlan"]["phaseRetryPolicies"][1]["timeoutErrorCode"],
            "hook-fallback-preflight-timeout"
        );
        assert_eq!(automation["fallbackPlan"]["phaseTimeoutPolicyCount"], 2);
        assert_eq!(automation["fallbackPlan"]["phaseErrorCodeCount"], 2);
        assert_eq!(automation["fallbackPlan"]["phaseErrorCodes"][0]["phase"], "diagnose");
        assert_eq!(
            automation["fallbackPlan"]["phaseErrorCodes"][0]["errorCode"],
            "hook-fallback-diagnose-failed"
        );
        assert_eq!(
            automation["fallbackPlan"]["phaseErrorCodes"][0]["timeoutErrorCode"],
            "hook-fallback-diagnose-timeout"
        );
        assert_eq!(automation["fallbackPlan"]["phaseErrorCodes"][1]["phase"], "preflight");
        assert_eq!(
            automation["fallbackPlan"]["phaseErrorCodes"][1]["errorCode"],
            "hook-fallback-preflight-failed"
        );
        assert_eq!(
            automation["fallbackPlan"]["phaseErrorCodes"][1]["timeoutErrorCode"],
            "hook-fallback-preflight-timeout"
        );
        assert_eq!(automation["fallbackPlan"]["terminationPolicy"]["mode"], "phase-retry-budget");
        assert_eq!(
            automation["fallbackPlan"]["terminationPolicy"]["terminateWhen"],
            "all-retryable-steps-exhausted"
        );
        assert_eq!(
            automation["fallbackPlan"]["terminationPolicy"]["escalateWhen"],
            "non-retryable-step-failed-or-retry-budget-exhausted"
        );
        assert_eq!(
            automation["fallbackPlan"]["terminationPolicy"]["timeoutEscalateWhen"],
            "phase-timeout-exceeded"
        );
        assert_eq!(automation["fallbackPlan"]["terminationPolicy"]["retryablePhaseCount"], 2);
        assert_eq!(automation["fallbackPlan"]["terminationPolicy"]["nonRetryablePhaseCount"], 0);
        assert_eq!(automation["fallbackPlan"]["terminationPolicy"]["retryableStepCount"], 2);
        assert_eq!(automation["fallbackPlan"]["terminationPolicy"]["totalRetryBudget"], 3);
        assert_eq!(automation["fallbackPlan"]["stepCount"], 2);
        assert_eq!(automation["fallbackPlan"]["retryableStepCount"], 2);
        assert_eq!(automation["fallbackPlan"]["totalRetryBudget"], 3);
        assert_eq!(automation["fallbackPlan"]["steps"][0]["id"], "fallback-plan:0");
        assert_eq!(automation["fallbackPlan"]["steps"][0]["phase"], "diagnose");
        assert_eq!(automation["fallbackPlan"]["steps"][0]["command"], "native.hookenv");
        assert_eq!(automation["fallbackPlan"]["steps"][0]["retryable"], true);
        assert_eq!(automation["fallbackPlan"]["steps"][0]["maxSuggestedRetries"], 1);
        assert_eq!(automation["fallbackPlan"]["steps"][0]["retryDelayHintMs"], 250);
        assert_eq!(automation["fallbackPlan"]["steps"][0]["timeoutHintMs"], 4000);
        assert_eq!(
            automation["fallbackPlan"]["steps"][0]["timeoutAction"],
            "refresh-hook-environment-and-retry"
        );
        assert_eq!(
            automation["fallbackPlan"]["steps"][0]["errorCode"],
            "hook-fallback-diagnose-failed"
        );
        assert_eq!(
            automation["fallbackPlan"]["steps"][0]["timeoutErrorCode"],
            "hook-fallback-diagnose-timeout"
        );
        assert_eq!(automation["fallbackPlan"]["steps"][1]["id"], "fallback-plan:1");
        assert_eq!(automation["fallbackPlan"]["steps"][1]["phase"], "preflight");
        assert_eq!(
            automation["fallbackPlan"]["steps"][1]["command"],
            "controller --preflight-only --preflight-json"
        );
        assert_eq!(automation["fallbackPlan"]["steps"][1]["retryable"], true);
        assert_eq!(automation["fallbackPlan"]["steps"][1]["maxSuggestedRetries"], 2);
        assert_eq!(automation["fallbackPlan"]["steps"][1]["retryDelayHintMs"], 500);
        assert_eq!(automation["fallbackPlan"]["steps"][1]["timeoutHintMs"], 8000);
        assert_eq!(
            automation["fallbackPlan"]["steps"][1]["timeoutAction"],
            "re-run-preflight-or-switch-to-query-only"
        );
        assert_eq!(
            automation["fallbackPlan"]["steps"][1]["errorCode"],
            "hook-fallback-preflight-failed"
        );
        assert_eq!(
            automation["fallbackPlan"]["steps"][1]["timeoutErrorCode"],
            "hook-fallback-preflight-timeout"
        );
        assert_eq!(automation["fallbackPlan"]["escalationRecommendationCount"], 2);
        assert_eq!(automation["fallbackPlan"]["suggestedEscalationKey"], "preflight-refresh");
        assert_eq!(automation["fallbackPlan"]["errorCodeRoutingCount"], 6);
        assert_eq!(
            automation["fallbackPlan"]["errorCodeRouting"]["hook-fallback-preflight-failed"],
            "preflight-refresh"
        );
        assert_eq!(
            automation["fallbackPlan"]["errorCodeRouting"]["hook-fallback-inject-timeout"],
            "preflight-refresh"
        );
        assert_eq!(
            automation["fallbackPlan"]["errorCodeRouting"]["hook-fallback-diagnose-timeout"],
            "policy-review"
        );
        assert_eq!(automation["fallbackPlan"]["errorCodeRoutingResolvedCount"], 6);
        assert_eq!(
            automation["fallbackPlan"]["errorCodeRoutingResolved"]["hook-fallback-preflight-failed"]["escalationKey"],
            "preflight-refresh"
        );
        assert_eq!(
            automation["fallbackPlan"]["errorCodeRoutingResolved"]["hook-fallback-preflight-failed"]["phase"],
            "preflight"
        );
        assert_eq!(
            automation["fallbackPlan"]["errorCodeRoutingResolved"]["hook-fallback-preflight-failed"]["effectiveEscalationKey"],
            "preflight-refresh"
        );
        assert_eq!(
            automation["fallbackPlan"]["errorCodeRoutingResolved"]["hook-fallback-preflight-failed"]["effectivePhase"],
            "preflight"
        );
        assert_eq!(
            automation["fallbackPlan"]["errorCodeRoutingResolved"]["hook-fallback-preflight-failed"]["templateCount"],
            1
        );
        assert_eq!(
            automation["fallbackPlan"]["errorCodeRoutingResolved"]["hook-fallback-preflight-failed"]["commandJsonTemplateCount"],
            1
        );
        assert_eq!(
            automation["fallbackPlan"]["errorCodeRoutingEntries"][0]["candidateCount"],
            1
        );
        assert_eq!(
            automation["fallbackPlan"]["errorCodeRoutingEntries"][0]["recommendedEscalationKey"],
            "policy-review"
        );
        assert_eq!(
            automation["fallbackPlan"]["errorCodeRoutingEntries"][0]["effectiveEscalationKey"],
            "policy-review"
        );
        assert_eq!(
            automation["fallbackPlan"]["errorCodeRoutingEntries"][0]["effectivePhase"],
            "diagnose"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["lookupKey"],
            "errorCode"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["policy"],
            "first-candidate-by-escalation-order"
        );
        assert_eq!(automation["fallbackPlan"]["routingDecision"]["entryCount"], 6);
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["defaultRecommendedEscalationKey"],
            "preflight-refresh"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["defaultRecommendedPhase"],
            "preflight"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["defaultEffectiveEscalationKey"],
            "preflight-refresh"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["defaultEffectivePhase"],
            "preflight"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["defaultRecommendedTemplateCount"],
            1
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["defaultRecommendedTemplates"][0],
            "controller --preflight-only --preflight-json --pid <pid>"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["defaultRecommendedCommandJsonTemplateCount"],
            1
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["defaultRecommendedCommandJsonTemplates"][0]["phase"],
            "preflight"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["default"]["recommendedEscalationKey"],
            "preflight-refresh"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["default"]["matchConfidence"],
            "default"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["default"]["resolvedFrom"],
            "defaultRecommendedEscalationKey"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["default"]["recommendedPhase"],
            "preflight"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["default"]["effectivePhase"],
            "preflight"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["default"]["effectiveEscalationKey"],
            "preflight-refresh"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["default"]["recommendedTemplateCount"],
            1
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["default"]["recommendedTemplates"][0],
            "controller --preflight-only --preflight-json --pid <pid>"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["default"]["recommendedCommandJsonTemplateCount"],
            1
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["default"]["recommendedCommandJsonTemplates"][0]["phase"],
            "preflight"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["lookupRule"],
            "index[errorCode] || default"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolveLookupKey"],
            "errorCode"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolvePolicy"],
            "index-then-default"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolveOutputShape"],
            "{ matched, usedDefault, reason, effectivePhase, effectiveEscalationKey, effective }"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolveIndex"]["hook-fallback-preflight-failed"]["reason"],
            "matched-error-code"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolveIndexEntries"],
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolveIndex"]
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolveDefault"]["reason"],
            "missing-error-code"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolveExamples"]["knownErrorCode"],
            "hook-fallback-diagnose-failed"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolveExampleKnownErrorCode"],
            "hook-fallback-diagnose-failed"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolveExampleKnownResult"]["reason"],
            "matched-error-code"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolveExampleKnownResultEffective"],
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolveExampleKnownResult"]
                ["effective"]
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolveExampleKnownResultEffective"]
                ["phase"],
            "diagnose"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolveExampleKnownResultEffective"]
                ["escalationKey"],
            "policy-review"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]
                ["resolveExampleKnownResultEffectivePhase"],
            "diagnose"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]
                ["resolveExampleKnownResultEffectiveEscalationKey"],
            "policy-review"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolveExampleKnownMatched"],
            true
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolveExampleKnownUsedDefault"],
            false
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolveExampleKnownReason"],
            "matched-error-code"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolveExampleKnownEffectivePhase"],
            "diagnose"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolveExampleKnownEffectiveEscalationKey"],
            "policy-review"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolveExampleMissingErrorCode"],
            "hook-fallback-unknown"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolveExampleMissingResult"]["reason"],
            "missing-error-code"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolveExampleMissingResultEffective"],
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolveExampleMissingResult"]
                ["effective"]
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolveExampleMissingResultEffective"]
                ["phase"],
            "preflight"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolveExampleMissingResultEffective"]
                ["escalationKey"],
            "preflight-refresh"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]
                ["resolveExampleMissingResultEffectivePhase"],
            "preflight"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]
                ["resolveExampleMissingResultEffectiveEscalationKey"],
            "preflight-refresh"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolveExampleMissingMatched"],
            false
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolveExampleMissingUsedDefault"],
            true
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolveExampleMissingReason"],
            "missing-error-code"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolveExampleMissingEffectivePhase"],
            "preflight"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolveExampleMissingEffectiveEscalationKey"],
            "preflight-refresh"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolveErrorCodeCount"],
            6
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolveIndexCount"],
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolveErrorCodeCount"]
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolveKnownCount"],
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolveErrorCodeCount"]
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolveKnownTotal"],
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolveKnownCount"]
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolveKnownAmount"],
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolveKnownCount"]
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolveKnownVolume"],
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolveKnownCount"]
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolveKnownMagnitude"],
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolveKnownCount"]
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolveKnownSize"],
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolveKnownCount"]
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolveKnownLength"],
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolveKnownCount"]
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolveKnownErrorCodes"][0],
            "hook-fallback-diagnose-failed"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolveKnownEntries"],
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolveKnownErrorCodes"]
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolveKnownList"],
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolveKnownErrorCodes"]
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolveKnownEntriesCount"],
            6
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolveKnownErrorCodesCount"],
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolveKnownEntriesCount"]
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolveKnownEntriesCount"],
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolveKnownCount"]
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolveKnownErrorCodes"][5],
            "hook-fallback-preflight-timeout"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolveKnownErrorCodeFirst"],
            "hook-fallback-diagnose-failed"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolveKnownEntriesFirst"],
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolveKnownErrorCodeFirst"]
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolveKnownErrorCodesFirst"],
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolveKnownErrorCodeFirst"]
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolveKnownFirst"],
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolveKnownErrorCodeFirst"]
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolveIndexFirst"],
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolveKnownErrorCodeFirst"]
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolveKnownErrorCodeLast"],
            "hook-fallback-preflight-timeout"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolveKnownEntriesLast"],
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolveKnownErrorCodeLast"]
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolveKnownErrorCodesLast"],
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolveKnownErrorCodeLast"]
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolveKnownLast"],
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolveKnownErrorCodeLast"]
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolveIndexLast"],
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolveKnownErrorCodeLast"]
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolveMissingErrorCodeHint"],
            "if errorCode is not in knownErrorCodes, use resolve.default"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolveMissingHint"],
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolveMissingErrorCodeHint"]
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolveDefaultMatched"],
            false
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolveDefaultUsedDefault"],
            true
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolveDefaultReason"],
            "missing-error-code"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolveDefaultEffective"],
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolveDefault"]["effective"]
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolveDefaultEffective"]["phase"],
            "preflight"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolveDefaultEffective"]
                ["escalationKey"],
            "preflight-refresh"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolveDefaultEffectivePhase"],
            "preflight"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolveDefaultEffectiveEscalationKey"],
            "preflight-refresh"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolveKnownErrorCode"],
            "hook-fallback-diagnose-failed"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolveKnownResult"]["reason"],
            "matched-error-code"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolveKnownResultEffective"],
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolveKnownResult"]["effective"]
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolveKnownResultEffective"]["phase"],
            "diagnose"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolveKnownEffective"],
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolveKnownResultEffective"]
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolveKnownResultEffective"]
                ["escalationKey"],
            "policy-review"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolveKnownMatched"],
            true
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolveKnownUsedDefault"],
            false
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolveKnownReason"],
            "matched-error-code"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolveKnownEffectivePhase"],
            "diagnose"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolveKnownEffectiveEscalationKey"],
            "policy-review"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolveMissingErrorCode"],
            "hook-fallback-unknown"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolveMissingResult"]["reason"],
            "missing-error-code"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolveMissingResultEffective"],
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolveMissingResult"]["effective"]
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolveMissingResultEffective"]
                ["phase"],
            "preflight"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolveMissingEffective"],
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolveMissingResultEffective"]
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolveMissingResultEffective"]
                ["escalationKey"],
            "preflight-refresh"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolveMissingMatched"],
            false
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolveMissingUsedDefault"],
            true
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolveMissingReason"],
            "missing-error-code"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolveMissingEffectivePhase"],
            "preflight"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolveMissingEffectiveEscalationKey"],
            "preflight-refresh"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolveLookupKey"],
            "phase"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolvePolicy"],
            "index-then-defaultPhase"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolveOutputShape"],
            "{ matched, usedDefault, reason, effectivePhase, effectiveEscalationKey, effective }"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolveIndex"]["preflight"]["reason"],
            "matched-phase"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolveIndexEntries"],
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolveIndex"]
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolveDefault"]["reason"],
            "missing-phase"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolveExamples"]["knownPhase"],
            "diagnose"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolveExampleKnownPhase"],
            "diagnose"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolveExampleKnownResult"]["reason"],
            "matched-phase"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolveExampleKnownResultEffective"],
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolveExampleKnownResult"]
                ["effective"]
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]
                ["phaseResolveExampleKnownResultEffective"]["phase"],
            "diagnose"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]
                ["phaseResolveExampleKnownResultEffective"]["escalationKeys"][0],
            "policy-review"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]
                ["phaseResolveExampleKnownResultEffectivePhase"],
            "diagnose"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]
                ["phaseResolveExampleKnownResultEffectiveEscalationKey"],
            "policy-review"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolveExampleKnownMatched"],
            true
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolveExampleKnownUsedDefault"],
            false
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolveExampleKnownReason"],
            "matched-phase"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolveExampleKnownEffectivePhase"],
            "diagnose"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolveExampleKnownEffectiveEscalationKey"],
            "policy-review"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolveExampleMissingPhase"],
            "unknown"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolveExampleMissingResult"]["reason"],
            "missing-phase"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolveExampleMissingResultEffective"],
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolveExampleMissingResult"]
                ["effective"]
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]
                ["phaseResolveExampleMissingResultEffective"]["phase"],
            "preflight"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]
                ["phaseResolveExampleMissingResultEffective"]["escalationKeys"][0],
            "preflight-refresh"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]
                ["phaseResolveExampleMissingResultEffectivePhase"],
            "preflight"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]
                ["phaseResolveExampleMissingResultEffectiveEscalationKey"],
            "preflight-refresh"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolveExampleMissingMatched"],
            false
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolveExampleMissingUsedDefault"],
            true
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolveExampleMissingReason"],
            "missing-phase"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolveExampleMissingEffectivePhase"],
            "preflight"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolveExampleMissingEffectiveEscalationKey"],
            "preflight-refresh"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolvePhaseCount"],
            2
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolveIndexCount"],
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolvePhaseCount"]
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolveKnownCount"],
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolvePhaseCount"]
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolveKnownTotal"],
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolveKnownCount"]
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolveKnownAmount"],
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolveKnownCount"]
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolveKnownVolume"],
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolveKnownCount"]
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolveKnownMagnitude"],
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolveKnownCount"]
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolveKnownSize"],
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolveKnownCount"]
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolveKnownLength"],
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolveKnownCount"]
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolveKnownPhases"][0],
            "diagnose"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolveKnownEntries"],
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolveKnownPhases"]
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolveKnownList"],
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolveKnownPhases"]
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolveKnownEntriesCount"],
            2
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolveKnownPhasesCount"],
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolveKnownEntriesCount"]
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolveKnownEntriesCount"],
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolveKnownCount"]
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolveKnownPhases"][1],
            "preflight"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolveKnownPhaseFirst"],
            "diagnose"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolveKnownEntriesFirst"],
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolveKnownPhaseFirst"]
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolveKnownPhasesFirst"],
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolveKnownPhaseFirst"]
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolveKnownFirst"],
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolveKnownPhaseFirst"]
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolveIndexFirst"],
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolveKnownPhaseFirst"]
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolveKnownPhaseLast"],
            "preflight"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolveKnownEntriesLast"],
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolveKnownPhaseLast"]
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolveKnownPhasesLast"],
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolveKnownPhaseLast"]
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolveKnownLast"],
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolveKnownPhaseLast"]
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolveIndexLast"],
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolveKnownPhaseLast"]
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolveMissingPhaseHint"],
            "if phase is not in knownPhases, use phaseResolve.default"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolveMissingHint"],
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolveMissingPhaseHint"]
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolveDefaultPhase"],
            "preflight"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolveDefaultMatched"],
            false
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolveDefaultUsedDefault"],
            true
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolveDefaultReason"],
            "missing-phase"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolveDefaultEffective"],
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolveDefault"]["effective"]
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolveDefaultEffective"]
                ["phase"],
            "preflight"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolveDefaultEffective"]
                ["escalationKeys"][0],
            "preflight-refresh"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolveDefaultEffectivePhase"],
            "preflight"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolveDefaultEffectiveEscalationKey"],
            "preflight-refresh"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolveKnownPhase"],
            "diagnose"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolveKnownResult"]["reason"],
            "matched-phase"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolveKnownResultEffective"],
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolveKnownResult"]["effective"]
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolveKnownResultEffective"]
                ["phase"],
            "diagnose"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolveKnownEffective"],
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolveKnownResultEffective"]
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolveKnownResultEffective"]
                ["escalationKeys"][0],
            "policy-review"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolveKnownMatched"],
            true
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolveKnownUsedDefault"],
            false
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolveKnownReason"],
            "matched-phase"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolveKnownEffectivePhase"],
            "diagnose"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolveKnownEffectiveEscalationKey"],
            "policy-review"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolveMissingPhase"],
            "unknown"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolveMissingResult"]["reason"],
            "missing-phase"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolveMissingResultEffective"],
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolveMissingResult"]
                ["effective"]
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]
                ["phaseResolveMissingResultEffective"]["phase"],
            "preflight"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolveMissingEffective"],
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolveMissingResultEffective"]
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]
                ["phaseResolveMissingResultEffective"]["escalationKeys"][0],
            "preflight-refresh"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolveMissingMatched"],
            false
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolveMissingUsedDefault"],
            true
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolveMissingReason"],
            "missing-phase"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolveMissingEffectivePhase"],
            "preflight"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolveMissingEffectiveEscalationKey"],
            "preflight-refresh"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["queryOnlyErrorCode"],
            "hook-fallback-hook-install-failed"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["queryOnlySourceErrorCode"],
            "hook-fallback-hook-install-failed"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["queryOnlyBlockedBy"],
            "both"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["queryOnlyResolveBlockedBy"],
            "both"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["queryOnlyBlockedBySource"],
            "both"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["queryOnlyResolveBlockedBySource"],
            "both"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["queryOnlyIsBlocked"],
            true
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["queryOnlyResolveIsBlocked"],
            true
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["queryOnlyPhase"],
            json!(null)
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["queryOnlyPhaseResolveSourceErrorCode"],
            "hook-fallback-hook-install-failed"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["queryOnlyPhaseResolvePhase"],
            json!(null)
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["queryOnlyPhaseResolveBlockedBy"],
            "both"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["queryOnlyPhaseResolveBlockedBySource"],
            "both"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["queryOnlyPhaseResolveIsBlocked"],
            true
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["queryOnlyPhaseResolveAvailable"],
            false
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["queryOnlyPhaseResolveMatched"],
            false
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["queryOnlyPhaseResolveUsedDefault"],
            true
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["queryOnlyPhaseResolveReason"],
            "missing-phase"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["queryOnlyPhaseResolveEffectivePhase"],
            json!(null)
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["queryOnlyPhaseResolveEffectiveEscalationKey"],
            json!(null)
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["queryOnlyAvailable"],
            false
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["queryOnlyResolveAvailable"],
            false
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["queryOnlyMatched"],
            false
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["queryOnlyResolveMatched"],
            false
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["queryOnlyUsedDefault"],
            true
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["queryOnlyResolveUsedDefault"],
            true
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["queryOnlyReason"],
            "missing-error-code"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["queryOnlyResolveReason"],
            "missing-error-code"
        );
        assert!(automation["fallbackPlan"]["routingDecision"]["ready"]["queryOnlyEffectivePhase"].is_null());
        assert!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["queryOnlyResolveEffectivePhase"]
                .is_null()
        );
        assert!(automation["fallbackPlan"]["routingDecision"]["ready"]["queryOnlyEffectiveEscalationKey"].is_null());
        assert!(
            automation["fallbackPlan"]["routingDecision"]["ready"]
                ["queryOnlyResolveEffectiveEscalationKey"]
                .is_null()
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["queryOnlyWouldUsePath"],
            false
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["queryOnlyResolveWouldUsePath"],
            false
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["queryOnlyWouldUsePhase"],
            false
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["queryOnlyPhaseResolveWouldUsePhase"],
            false
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["queryOnlyResolveResult"],
            json!(null)
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["queryOnlyResolveResultEffective"],
            json!(null)
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["queryOnlyResolveResultMatched"],
            json!(null)
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["queryOnlyResolveResultUsedDefault"],
            json!(null)
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["queryOnlyResolveResultReason"],
            json!(null)
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["queryOnlyResolveResultEffectivePhase"],
            json!(null)
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]
                ["queryOnlyResolveResultEffectiveEscalationKey"],
            json!(null)
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["queryOnlyPhaseResolveResult"],
            json!(null)
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["queryOnlyPhaseResolveResultEffective"],
            json!(null)
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["queryOnlyPhaseResolveResultMatched"],
            json!(null)
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["queryOnlyPhaseResolveResultUsedDefault"],
            json!(null)
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["queryOnlyPhaseResolveResultReason"],
            json!(null)
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["queryOnlyPhaseResolveResultEffectivePhase"],
            json!(null)
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]
                ["queryOnlyPhaseResolveResultEffectiveEscalationKey"],
            json!(null)
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["entryCount"],
            6
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseCount"],
            2
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseFirst"],
            "diagnose"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseLast"],
            "preflight"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["defaultPhase"],
            "preflight"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["defaultEscalationKey"],
            "preflight-refresh"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["defaultEffectiveEscalationKey"],
            "preflight-refresh"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["defaultEffectivePhase"],
            "preflight"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["defaultTemplateCount"],
            1
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["defaultTemplates"][0],
            "controller --preflight-only --preflight-json --pid <pid>"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["defaultTemplate"],
            "controller --preflight-only --preflight-json --pid <pid>"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["defaultCommandJsonTemplateCount"],
            1
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["defaultMatchConfidence"],
            "default"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["defaultResolvedFrom"],
            "defaultRecommendedEscalationKey"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["defaultCommandJsonTemplates"][0]["phase"],
            "preflight"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["defaultCommandJsonTemplate"]["phase"],
            "preflight"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["defaultCommandJsonTemplateCommand"],
            "controller --preflight-only --preflight-json --pid <pid>"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["defaultCommandJsonTemplateRisk"],
            "normal"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]
                ["defaultCommandJsonTemplatePlaceholderCount"],
            1
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["defaultCommandJsonTemplatePlaceholders"],
            json!(["<pid>"])
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["defaultCommandJsonTemplateCliArgs"],
            json!(["--preflight-only", "--preflight-json", "--pid", "<pid>"])
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["defaultCommandJsonTemplateKind"],
            "controller-cli"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["defaultCommandJsonTemplatePhase"],
            "preflight"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["defaultCommandJsonTemplateErrorCode"],
            "hook-fallback-preflight-failed"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]
                ["defaultCommandJsonTemplateTimeoutErrorCode"],
            "hook-fallback-preflight-timeout"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["defaultCommandJsonTemplateRetryable"],
            true
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]
                ["defaultCommandJsonTemplateMaxSuggestedRetries"],
            2
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]
                ["defaultCommandJsonTemplateRetryDelayHintMs"],
            500
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]
                ["defaultCommandJsonTemplateTimeoutHintMs"],
            8000
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]
                ["defaultCommandJsonTemplateTimeoutAction"],
            "re-run-preflight-or-switch-to-query-only"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]
                ["defaultCommandJsonTemplateCommandJsonEligible"],
            false
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["default"]["escalationKey"],
            "preflight-refresh"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["default"]["effectiveEscalationKey"],
            "preflight-refresh"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["default"]["phase"],
            "preflight"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["default"]["effectivePhase"],
            "preflight"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["default"]["templateCount"],
            1
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["default"]["templates"][0],
            "controller --preflight-only --preflight-json --pid <pid>"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["default"]["commandJsonTemplateCount"],
            1
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["default"]["matchConfidence"],
            "default"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["default"]["resolvedFrom"],
            "defaultRecommendedEscalationKey"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolve"]["lookupKey"],
            "errorCode"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolve"]["policy"],
            "index-then-default"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolve"]["outputShape"],
            "{ matched, usedDefault, reason, effectivePhase, effectiveEscalationKey, effective }"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolve"]["errorCodeCount"],
            6
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolve"]["knownEntries"],
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolve"]["knownErrorCodes"]
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolve"]["knownList"],
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolve"]["knownErrorCodes"]
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolve"]["knownEntriesCount"],
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolve"]["errorCodeCount"]
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolve"]["knownErrorCodesCount"],
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolve"]["errorCodeCount"]
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolve"]["knownErrorCodes"][0],
            "hook-fallback-diagnose-failed"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolve"]["knownErrorCodeFirst"],
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolve"]["knownErrorCodes"][0]
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolve"]["knownErrorCodesFirst"],
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolve"]["knownErrorCodes"][0]
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolve"]["knownEntriesFirst"],
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolve"]["knownErrorCodes"][0]
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolve"]["knownFirst"],
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolve"]["knownErrorCodes"][0]
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolve"]["knownErrorCodes"][5],
            "hook-fallback-preflight-timeout"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolve"]["knownErrorCodeLast"],
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolve"]["knownErrorCodes"][5]
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolve"]["knownErrorCodesLast"],
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolve"]["knownErrorCodes"][5]
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolve"]["knownEntriesLast"],
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolve"]["knownErrorCodes"][5]
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolve"]["knownLast"],
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolve"]["knownErrorCodes"][5]
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolve"]["missingErrorCodeHint"],
            "if errorCode is not in knownErrorCodes, use resolve.default"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolve"]["defaultMatched"],
            false
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolve"]["defaultUsedDefault"],
            true
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolve"]["defaultReason"],
            "missing-error-code"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolve"]["defaultEffectivePhase"],
            "preflight"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolve"]["defaultEffectiveEscalationKey"],
            "preflight-refresh"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolve"]["knownErrorCode"],
            "hook-fallback-diagnose-failed"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolve"]["knownResult"]["reason"],
            "matched-error-code"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolve"]["knownEffectivePhase"],
            "diagnose"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolve"]["knownEffectiveEscalationKey"],
            "policy-review"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolve"]["missingErrorCode"],
            "hook-fallback-unknown"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolve"]["missingResult"]["reason"],
            "missing-error-code"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolve"]["missingEffectivePhase"],
            "preflight"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolve"]["missingEffectiveEscalationKey"],
            "preflight-refresh"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolve"]["queryOnlyErrorCode"],
            "hook-fallback-hook-install-failed"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolve"]["queryOnlyBlockedBy"],
            "both"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolve"]["queryOnlyBlockedBySource"],
            "both"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolve"]["queryOnlyIsBlocked"],
            true
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolve"]["queryOnlyAvailable"],
            false
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolve"]["queryOnlyMatched"],
            false
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolve"]["queryOnlyUsedDefault"],
            true
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolve"]["queryOnlyReason"],
            "missing-error-code"
        );
        assert!(automation["fallbackPlan"]["routingDecision"]["ready"]["resolve"]["queryOnlyEffectivePhase"].is_null());
        assert!(automation["fallbackPlan"]["routingDecision"]["ready"]["resolve"]["queryOnlyEffectiveEscalationKey"].is_null());
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolve"]["queryOnlyWouldUsePath"],
            false
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolve"]["queryOnlyResult"],
            json!(null)
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolve"]["examples"]["knownErrorCode"],
            "hook-fallback-diagnose-failed"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolve"]["examples"]["knownResult"]["matched"],
            true
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolve"]["examples"]["knownResult"]["usedDefault"],
            false
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolve"]["examples"]["knownResult"]["reason"],
            "matched-error-code"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolve"]["examples"]["knownResult"]["effective"]["escalationKey"],
            "policy-review"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolve"]["examples"]["knownEffectivePhase"],
            "diagnose"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolve"]["examples"]["knownEffectiveEscalationKey"],
            "policy-review"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolve"]["examples"]["missingErrorCode"],
            "hook-fallback-unknown"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolve"]["examples"]["missingResult"]["reason"],
            "missing-error-code"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolve"]["examples"]["missingEffectivePhase"],
            "preflight"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolve"]["examples"]["missingEffectiveEscalationKey"],
            "preflight-refresh"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolve"]["examples"]["queryOnlyInstallFailure"]["errorCode"],
            "hook-fallback-hook-install-failed"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolve"]["examples"]["queryOnlyInstallFailure"]["blockedBy"],
            "both"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolve"]["examples"]["queryOnlyInstallFailure"]["blockedBySource"],
            "both"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolve"]["examples"]["queryOnlyInstallFailure"]["isBlocked"],
            true
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolve"]["examples"]["queryOnlyInstallFailure"]["available"],
            false
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolve"]["examples"]["queryOnlyInstallFailure"]["matched"],
            false
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolve"]["examples"]["queryOnlyInstallFailure"]["usedDefault"],
            true
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolve"]["examples"]["queryOnlyInstallFailure"]["reason"],
            "missing-error-code"
        );
        assert!(automation["fallbackPlan"]["routingDecision"]["ready"]["resolve"]["examples"]["queryOnlyInstallFailure"]["effectivePhase"].is_null());
        assert!(automation["fallbackPlan"]["routingDecision"]["ready"]["resolve"]["examples"]["queryOnlyInstallFailure"]["effectiveEscalationKey"].is_null());
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolve"]["examples"]["queryOnlyInstallFailure"]["result"],
            json!(null)
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolve"]["examples"]["queryOnlyInstallFailure"]["wouldUseQueryOnlyPath"],
            false
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolveExampleQueryOnlyErrorCode"],
            "hook-fallback-hook-install-failed"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolveExampleQueryOnlyBlockedBy"],
            "both"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolveExampleQueryOnlyBlockedBySource"],
            "both"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolveExampleQueryOnlyIsBlocked"],
            true
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolveExampleQueryOnlyAvailable"],
            false
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolveExampleQueryOnlyMatched"],
            false
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolveExampleQueryOnlyUsedDefault"],
            true
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolveExampleQueryOnlyReason"],
            "missing-error-code"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolveExampleQueryOnlyEffectivePhase"],
            json!(null)
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]
                ["resolveExampleQueryOnlyEffectiveEscalationKey"],
            json!(null)
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolveExampleQueryOnlyWouldUsePath"],
            false
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolveExampleQueryOnlyResult"],
            json!(null)
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]
                ["resolveExampleQueryOnlyResultEffective"],
            json!(null)
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolveExampleQueryOnlyResultMatched"],
            json!(null)
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolveExampleQueryOnlyResultUsedDefault"],
            json!(null)
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolveExampleQueryOnlyResultReason"],
            json!(null)
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolveExampleQueryOnlyResultEffectivePhase"],
            json!(null)
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]
                ["resolveExampleQueryOnlyResultEffectiveEscalationKey"],
            json!(null)
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolveExampleQueryOnlyInstallFailure"]["reason"],
            "missing-error-code"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolve"]["lookupKey"],
            "phase"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolve"]["policy"],
            "index-then-defaultPhase"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolve"]["outputShape"],
            "{ matched, usedDefault, reason, effectivePhase, effectiveEscalationKey, effective }"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolve"]["phaseCount"],
            2
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolve"]["knownEntries"],
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolve"]["knownPhases"]
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolve"]["knownList"],
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolve"]["knownPhases"]
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolve"]["knownEntriesCount"],
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolve"]["phaseCount"]
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolve"]["knownPhasesCount"],
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolve"]["phaseCount"]
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolve"]["knownPhases"][0],
            "diagnose"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolve"]["knownPhaseFirst"],
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolve"]["knownPhases"][0]
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolve"]["knownPhasesFirst"],
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolve"]["knownPhases"][0]
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolve"]["knownEntriesFirst"],
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolve"]["knownPhases"][0]
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolve"]["knownFirst"],
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolve"]["knownPhases"][0]
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolve"]["knownPhases"][1],
            "preflight"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolve"]["knownPhaseLast"],
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolve"]["knownPhases"][1]
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolve"]["knownPhasesLast"],
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolve"]["knownPhases"][1]
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolve"]["knownEntriesLast"],
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolve"]["knownPhases"][1]
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolve"]["knownLast"],
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolve"]["knownPhases"][1]
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolve"]["defaultPhase"],
            "preflight"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolve"]["missingPhaseHint"],
            "if phase is not in knownPhases, use phaseResolve.default"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolve"]["defaultMatched"],
            false
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolve"]["defaultUsedDefault"],
            true
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolve"]["defaultReason"],
            "missing-phase"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolve"]["defaultEffectivePhase"],
            "preflight"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolve"]["defaultEffectiveEscalationKey"],
            "preflight-refresh"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolve"]["knownPhase"],
            "diagnose"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolve"]["knownResult"]["reason"],
            "matched-phase"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolve"]["knownEffectivePhase"],
            "diagnose"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolve"]["knownEffectiveEscalationKey"],
            "policy-review"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolve"]["missingPhase"],
            "unknown"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolve"]["missingResult"]["reason"],
            "missing-phase"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolve"]["missingEffectivePhase"],
            "preflight"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolve"]["missingEffectiveEscalationKey"],
            "preflight-refresh"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolve"]["queryOnlySourceErrorCode"],
            "hook-fallback-hook-install-failed"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolve"]["queryOnlyBlockedBy"],
            "both"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolve"]["queryOnlyBlockedBySource"],
            "both"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolve"]["queryOnlyIsBlocked"],
            true
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolve"]["queryOnlyPhase"],
            json!(null)
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolve"]["queryOnlyAvailable"],
            false
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolve"]["queryOnlyMatched"],
            false
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolve"]["queryOnlyUsedDefault"],
            true
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolve"]["queryOnlyReason"],
            "missing-phase"
        );
        assert!(automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolve"]["queryOnlyEffectivePhase"].is_null());
        assert!(automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolve"]["queryOnlyEffectiveEscalationKey"].is_null());
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolve"]["queryOnlyWouldUsePhase"],
            false
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolve"]["queryOnlyResult"],
            json!(null)
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolve"]["examples"]["knownPhase"],
            "diagnose"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolve"]["examples"]["knownResult"]["matched"],
            true
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolve"]["examples"]["knownResult"]["usedDefault"],
            false
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolve"]["examples"]["knownResult"]["reason"],
            "matched-phase"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolve"]["examples"]["knownResult"]["effective"]["phase"],
            "diagnose"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolve"]["examples"]["knownEffectivePhase"],
            "diagnose"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolve"]["examples"]["knownEffectiveEscalationKey"],
            "policy-review"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolve"]["examples"]["missingPhase"],
            "unknown"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolve"]["examples"]["missingResult"]["reason"],
            "missing-phase"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolve"]["examples"]["missingEffectivePhase"],
            "preflight"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolve"]["examples"]["missingEffectiveEscalationKey"],
            "preflight-refresh"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolve"]["examples"]["queryOnlyInstallFailure"]["sourceErrorCode"],
            "hook-fallback-hook-install-failed"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolve"]["examples"]["queryOnlyInstallFailure"]["blockedBy"],
            "both"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolve"]["examples"]["queryOnlyInstallFailure"]["blockedBySource"],
            "both"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolve"]["examples"]["queryOnlyInstallFailure"]["isBlocked"],
            true
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolve"]["examples"]["queryOnlyInstallFailure"]["phase"],
            json!(null)
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolve"]["examples"]["queryOnlyInstallFailure"]["available"],
            false
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolve"]["examples"]["queryOnlyInstallFailure"]["matched"],
            false
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolve"]["examples"]["queryOnlyInstallFailure"]["usedDefault"],
            true
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolve"]["examples"]["queryOnlyInstallFailure"]["reason"],
            "missing-phase"
        );
        assert!(automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolve"]["examples"]["queryOnlyInstallFailure"]["effectivePhase"].is_null());
        assert!(automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolve"]["examples"]["queryOnlyInstallFailure"]["effectiveEscalationKey"].is_null());
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolve"]["examples"]["queryOnlyInstallFailure"]["result"],
            json!(null)
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolve"]["examples"]["queryOnlyInstallFailure"]["wouldUseQueryPhase"],
            false
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolveExampleQueryOnlySourceErrorCode"],
            "hook-fallback-hook-install-failed"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolveExampleQueryOnlyPhase"],
            json!(null)
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolveExampleQueryOnlyBlockedBy"],
            "both"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolveExampleQueryOnlyBlockedBySource"],
            "both"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolveExampleQueryOnlyIsBlocked"],
            true
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolveExampleQueryOnlyAvailable"],
            false
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolveExampleQueryOnlyMatched"],
            false
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolveExampleQueryOnlyUsedDefault"],
            true
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolveExampleQueryOnlyReason"],
            "missing-phase"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolveExampleQueryOnlyEffectivePhase"],
            json!(null)
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]
                ["phaseResolveExampleQueryOnlyEffectiveEscalationKey"],
            json!(null)
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolveExampleQueryOnlyWouldUsePhase"],
            false
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolveExampleQueryOnlyResult"],
            json!(null)
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]
                ["phaseResolveExampleQueryOnlyResultEffective"],
            json!(null)
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]
                ["phaseResolveExampleQueryOnlyResultMatched"],
            json!(null)
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]
                ["phaseResolveExampleQueryOnlyResultUsedDefault"],
            json!(null)
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolveExampleQueryOnlyResultReason"],
            json!(null)
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]
                ["phaseResolveExampleQueryOnlyResultEffectivePhase"],
            json!(null)
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]
                ["phaseResolveExampleQueryOnlyResultEffectiveEscalationKey"],
            json!(null)
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolveExampleQueryOnlyInstallFailure"]["reason"],
            "missing-phase"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolve"]["index"]["preflight"]["matched"],
            true
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolve"]["index"]["preflight"]["usedDefault"],
            false
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolve"]["index"]["preflight"]["reason"],
            "matched-phase"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolve"]["index"]["preflight"]["effectivePhase"],
            "preflight"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolve"]["index"]["preflight"]["effectiveEscalationKey"],
            "preflight-refresh"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolve"]["index"]["preflight"]["effective"]["errorCodeCount"],
            4
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolve"]["default"]["matched"],
            false
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolve"]["default"]["usedDefault"],
            true
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolve"]["default"]["reason"],
            "missing-phase"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolve"]["default"]["effectivePhase"],
            "preflight"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolve"]["default"]["effectiveEscalationKey"],
            "preflight-refresh"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolve"]["default"]["effective"]["phase"],
            "preflight"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolve"]["index"]["hook-fallback-preflight-failed"]["matched"],
            true
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolve"]["index"]["hook-fallback-preflight-failed"]["usedDefault"],
            false
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolve"]["index"]["hook-fallback-preflight-failed"]["reason"],
            "matched-error-code"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolve"]["index"]["hook-fallback-preflight-failed"]["effectivePhase"],
            "preflight"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolve"]["index"]["hook-fallback-preflight-failed"]["effectiveEscalationKey"],
            "preflight-refresh"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolve"]["index"]["hook-fallback-preflight-failed"]["effective"]["escalationKey"],
            "preflight-refresh"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolve"]["default"]["matched"],
            false
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolve"]["default"]["usedDefault"],
            true
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolve"]["default"]["reason"],
            "missing-error-code"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolve"]["default"]["effectivePhase"],
            "preflight"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolve"]["default"]["effectiveEscalationKey"],
            "preflight-refresh"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolve"]["default"]["effective"]["escalationKey"],
            "preflight-refresh"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["index"]["hook-fallback-preflight-failed"]["escalationKey"],
            "preflight-refresh"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["index"]["hook-fallback-preflight-failed"]["effectiveEscalationKey"],
            "preflight-refresh"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["index"]["hook-fallback-preflight-failed"]["phase"],
            "preflight"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["index"]["hook-fallback-preflight-failed"]["effectivePhase"],
            "preflight"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["index"]["hook-fallback-preflight-failed"]["templateCount"],
            1
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["index"]["hook-fallback-preflight-failed"]["commandJsonTemplateCount"],
            1
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["index"]["hook-fallback-preflight-failed"]["matchConfidence"],
            "exact"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["index"]["hook-fallback-preflight-failed"]["resolvedFrom"],
            "errorCodeRouting"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseIndex"]["preflight"]["errorCodeCount"],
            4
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseIndex"]["preflight"]["escalationKeyCount"],
            1
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseIndex"]["preflight"]["escalationKeys"][0],
            "preflight-refresh"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseIndex"]["preflight"]["templateCount"],
            1
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseIndex"]["preflight"]["templates"][0],
            "controller --preflight-only --preflight-json --pid <pid>"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseIndex"]["preflight"]["commandJsonTemplateCount"],
            1
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseIndex"]["diagnose"]["errorCodeCount"],
            2
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseIndex"]["diagnose"]["escalationKeyCount"],
            1
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseIndex"]["diagnose"]["escalationKeys"][0],
            "policy-review"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseIndex"]["diagnose"]["templateCount"],
            1
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseIndex"]["diagnose"]["templates"][0],
            "native.hookenv"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseIndex"]["diagnose"]["commandJsonTemplateCount"],
            1
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phasePreflight"]["phase"],
            "preflight"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phasePreflightErrorCodeCount"],
            4
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phasePreflightErrorCodes"][0],
            automation["fallbackPlan"]["routingDecision"]["ready"]["phasePreflightErrorCodeFirst"]
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phasePreflightErrorCodeFirst"],
            automation["fallbackPlan"]["routingDecision"]["ready"]["phasePreflightErrorCodes"][0]
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phasePreflightErrorCodeLast"],
            automation["fallbackPlan"]["routingDecision"]["ready"]["phasePreflightErrorCodes"][3]
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phasePreflightEscalationKeyCount"],
            1
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phasePreflightEscalationKeys"][0],
            "preflight-refresh"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phasePreflightPrimaryEscalationKey"],
            "preflight-refresh"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phasePreflightTemplateCount"],
            1
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phasePreflightTemplates"][0],
            "controller --preflight-only --preflight-json --pid <pid>"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phasePreflightTemplate"],
            "controller --preflight-only --preflight-json --pid <pid>"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phasePreflightCommandJsonTemplateCount"],
            1
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phasePreflightCommandJsonTemplates"][0]["phase"],
            "preflight"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phasePreflightCommandJsonTemplate"]["phase"],
            "preflight"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phasePreflightCommandJsonTemplateCommand"],
            "controller --preflight-only --preflight-json --pid <pid>"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phasePreflightCommandJsonTemplateRisk"],
            "normal"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]
                ["phasePreflightCommandJsonTemplatePlaceholderCount"],
            1
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]
                ["phasePreflightCommandJsonTemplatePlaceholders"],
            json!(["<pid>"])
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phasePreflightCommandJsonTemplateCliArgs"],
            json!(["--preflight-only", "--preflight-json", "--pid", "<pid>"])
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phasePreflightCommandJsonTemplateKind"],
            "controller-cli"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phasePreflightCommandJsonTemplatePhase"],
            "preflight"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]
                ["phasePreflightCommandJsonTemplateErrorCode"],
            "hook-fallback-preflight-failed"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]
                ["phasePreflightCommandJsonTemplateTimeoutErrorCode"],
            "hook-fallback-preflight-timeout"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]
                ["phasePreflightCommandJsonTemplateRetryable"],
            true
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]
                ["phasePreflightCommandJsonTemplateMaxSuggestedRetries"],
            2
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]
                ["phasePreflightCommandJsonTemplateRetryDelayHintMs"],
            500
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]
                ["phasePreflightCommandJsonTemplateTimeoutHintMs"],
            8000
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]
                ["phasePreflightCommandJsonTemplateTimeoutAction"],
            "re-run-preflight-or-switch-to-query-only"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]
                ["phasePreflightCommandJsonTemplateCommandJsonEligible"],
            false
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseDiagnose"]["phase"],
            "diagnose"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseDiagnoseErrorCodeCount"],
            2
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseDiagnoseErrorCodes"][0],
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseDiagnoseErrorCodeFirst"]
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseDiagnoseErrorCodeFirst"],
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseDiagnoseErrorCodes"][0]
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseDiagnoseErrorCodeLast"],
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseDiagnoseErrorCodes"][1]
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseDiagnoseEscalationKeyCount"],
            1
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseDiagnoseEscalationKeys"][0],
            "policy-review"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseDiagnosePrimaryEscalationKey"],
            "policy-review"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseDiagnoseTemplateCount"],
            1
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseDiagnoseTemplates"][0],
            "native.hookenv"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseDiagnoseTemplate"],
            "native.hookenv"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseDiagnoseCommandJsonTemplateCount"],
            1
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseDiagnoseCommandJsonTemplates"][0]["phase"],
            "diagnose"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseDiagnoseCommandJsonTemplate"]["phase"],
            "diagnose"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseDiagnoseCommandJsonTemplateCommand"],
            "native.hookenv"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseDiagnoseCommandJsonTemplateRisk"],
            "normal"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]
                ["phaseDiagnoseCommandJsonTemplatePlaceholderCount"],
            0
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]
                ["phaseDiagnoseCommandJsonTemplatePlaceholders"],
            json!([])
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseDiagnoseCommandJsonTemplateCliArgs"],
            json!(["--pid", "<pid>", "--command", "native.hookenv", "--command-json"])
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseDiagnoseCommandJsonTemplateKind"],
            "runtime-command"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseDiagnoseCommandJsonTemplatePhase"],
            "diagnose"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]
                ["phaseDiagnoseCommandJsonTemplateErrorCode"],
            "hook-fallback-diagnose-failed"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]
                ["phaseDiagnoseCommandJsonTemplateTimeoutErrorCode"],
            "hook-fallback-diagnose-timeout"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]
                ["phaseDiagnoseCommandJsonTemplateRetryable"],
            true
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]
                ["phaseDiagnoseCommandJsonTemplateMaxSuggestedRetries"],
            1
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]
                ["phaseDiagnoseCommandJsonTemplateRetryDelayHintMs"],
            250
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]
                ["phaseDiagnoseCommandJsonTemplateTimeoutHintMs"],
            4000
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]
                ["phaseDiagnoseCommandJsonTemplateTimeoutAction"],
            "refresh-hook-environment-and-retry"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]
                ["phaseDiagnoseCommandJsonTemplateCommandJsonEligible"],
            true
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["index"]["hook-fallback-preflight-failed"]["recommendedEscalationKey"],
            "preflight-refresh"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["index"]["hook-fallback-preflight-failed"]["effectiveEscalationKey"],
            "preflight-refresh"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["index"]["hook-fallback-preflight-failed"]["recommendedPhase"],
            "preflight"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["index"]["hook-fallback-preflight-failed"]["effectivePhase"],
            "preflight"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["index"]["hook-fallback-preflight-failed"]["matchConfidence"],
            "exact"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["index"]["hook-fallback-preflight-failed"]["resolvedFrom"],
            "errorCodeRouting"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["index"]["hook-fallback-preflight-failed"]["recommendedTemplateCount"],
            1
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["index"]["hook-fallback-preflight-failed"]["recommendedTemplates"][0],
            "controller --preflight-only --preflight-json --pid <pid>"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["index"]["hook-fallback-preflight-failed"]["recommendedCommandJsonTemplateCount"],
            1
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["index"]["hook-fallback-preflight-failed"]["recommendedCommandJsonTemplates"][0]["phase"],
            "preflight"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["index"]["hook-fallback-diagnose-timeout"]["recommendedEscalationKey"],
            "policy-review"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["entries"][0]["recommendedPhase"],
            "diagnose"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["entries"][0]["effectivePhase"],
            "diagnose"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["entries"][0]["effectiveEscalationKey"],
            "policy-review"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["entries"][0]["matchConfidence"],
            "exact"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["entries"][0]["resolvedFrom"],
            "errorCodeRouting"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["entries"][0]["recommendedTemplates"][0],
            "native.hookenv"
        );
        assert_eq!(automation["fallbackPlan"]["escalationRecommendations"][0]["key"], "preflight-refresh");
        assert_eq!(automation["fallbackPlan"]["escalationRecommendations"][0]["phase"], "preflight");
        assert_eq!(automation["fallbackPlan"]["escalationRecommendations"][0]["condition"], "always");
        assert_eq!(
            automation["fallbackPlan"]["escalationRecommendations"][0]["templates"][0],
            "controller --preflight-only --preflight-json --pid <pid>"
        );
        assert_eq!(
            automation["fallbackPlan"]["escalationRecommendations"][0]["commandJsonTemplates"][0]["kind"],
            "controller-cli"
        );
        assert_eq!(
            automation["fallbackPlan"]["escalationRecommendations"][0]["commandJsonTemplates"][0]["phase"],
            "preflight"
        );
        assert_eq!(
            automation["fallbackPlan"]["escalationRecommendations"][0]["commandJsonTemplates"][0]["retryable"],
            true
        );
        assert_eq!(
            automation["fallbackPlan"]["escalationRecommendations"][0]["commandJsonTemplates"][0]["maxSuggestedRetries"],
            2
        );
        assert_eq!(
            automation["fallbackPlan"]["escalationRecommendations"][0]["commandJsonTemplates"][0]["retryDelayHintMs"],
            500
        );
        assert_eq!(
            automation["fallbackPlan"]["escalationRecommendations"][0]["commandJsonTemplates"][0]["timeoutHintMs"],
            8000
        );
        assert_eq!(
            automation["fallbackPlan"]["escalationRecommendations"][0]["commandJsonTemplates"][0]["timeoutAction"],
            "re-run-preflight-or-switch-to-query-only"
        );
        assert_eq!(
            automation["fallbackPlan"]["escalationRecommendations"][0]["onErrorCodeCount"],
            4
        );
        assert_eq!(
            automation["fallbackPlan"]["escalationRecommendations"][0]["onErrorCodes"][0],
            "hook-fallback-preflight-failed"
        );
        assert_eq!(
            automation["fallbackPlan"]["escalationRecommendations"][0]["onErrorCodes"][2],
            "hook-fallback-preflight-timeout"
        );
        assert_eq!(automation["fallbackPlan"]["escalationRecommendations"][1]["key"], "policy-review");
        assert_eq!(automation["fallbackPlan"]["escalationRecommendations"][1]["phase"], "diagnose");
        assert_eq!(
            automation["fallbackPlan"]["escalationRecommendations"][1]["condition"],
            "selected-next-action-blocked"
        );
        assert_eq!(
            automation["fallbackPlan"]["escalationRecommendations"][1]["onErrorCodeCount"],
            2
        );
        assert_eq!(
            automation["fallbackPlan"]["escalationRecommendations"][1]["onErrorCodes"][0],
            "hook-fallback-diagnose-failed"
        );
        assert_eq!(
            automation["fallbackPlan"]["escalationRecommendations"][1]["onErrorCodes"][1],
            "hook-fallback-diagnose-timeout"
        );
        assert_eq!(
            automation["fallbackPlan"]["escalationRecommendations"][1]["commandJsonTemplates"][0]["phase"],
            "diagnose"
        );
        assert_eq!(
            automation["fallbackPlan"]["escalationRecommendations"][1]["commandJsonTemplates"][0]["retryable"],
            true
        );
        assert_eq!(automation["fallbackPlan"]["commandJsonTemplateCount"], 2);
        assert_eq!(automation["fallbackPlan"]["commandJsonEligibleTemplateCount"], 1);
        assert_eq!(
            automation["fallbackPlan"]["commandJsonTemplates"][0]["kind"],
            "runtime-command"
        );
        assert_eq!(
            automation["fallbackPlan"]["commandJsonTemplates"][0]["phase"],
            "diagnose"
        );
        assert_eq!(
            automation["fallbackPlan"]["commandJsonTemplates"][0]["retryable"],
            true
        );
        assert_eq!(
            automation["fallbackPlan"]["commandJsonTemplates"][0]["maxSuggestedRetries"],
            1
        );
        assert_eq!(
            automation["fallbackPlan"]["commandJsonTemplates"][0]["retryDelayHintMs"],
            250
        );
        assert_eq!(
            automation["fallbackPlan"]["commandJsonTemplates"][0]["timeoutHintMs"],
            4000
        );
        assert_eq!(
            automation["fallbackPlan"]["commandJsonTemplates"][0]["timeoutAction"],
            "refresh-hook-environment-and-retry"
        );
        assert_eq!(
            automation["fallbackPlan"]["commandJsonTemplates"][0]["errorCode"],
            "hook-fallback-diagnose-failed"
        );
        assert_eq!(
            automation["fallbackPlan"]["commandJsonTemplates"][0]["timeoutErrorCode"],
            "hook-fallback-diagnose-timeout"
        );
        assert_eq!(
            automation["fallbackPlan"]["commandJsonTemplates"][1]["kind"],
            "controller-cli"
        );
        assert_eq!(
            automation["fallbackPlan"]["commandJsonTemplates"][1]["phase"],
            "preflight"
        );
        assert_eq!(
            automation["fallbackPlan"]["commandJsonTemplates"][1]["retryable"],
            true
        );
        assert_eq!(
            automation["fallbackPlan"]["commandJsonTemplates"][1]["maxSuggestedRetries"],
            2
        );
        assert_eq!(
            automation["fallbackPlan"]["commandJsonTemplates"][1]["retryDelayHintMs"],
            500
        );
        assert_eq!(
            automation["fallbackPlan"]["commandJsonTemplates"][1]["timeoutHintMs"],
            8000
        );
        assert_eq!(
            automation["fallbackPlan"]["commandJsonTemplates"][1]["timeoutAction"],
            "re-run-preflight-or-switch-to-query-only"
        );
        assert_eq!(
            automation["fallbackPlan"]["commandJsonTemplates"][1]["errorCode"],
            "hook-fallback-preflight-failed"
        );
        assert_eq!(
            automation["fallbackPlan"]["commandJsonTemplates"][1]["timeoutErrorCode"],
            "hook-fallback-preflight-timeout"
        );
        assert_eq!(automation["readyBranchCount"], 0);
        assert_eq!(automation["blockedBranchCount"], 5);
    }

    #[test]
    fn hook_automation_query_only_example_resolves_install_failure() {
        let report = HookEnvironmentReport {
            active_backend: None,
            backends: vec![],
            warnings: vec![],
        };
        let backend_matrix = hook_backend_matrix_to_json(&report, &report);
        let actions = vec![
            HookEffectiveAction {
                action_key: "hook.bootstrap",
                command_group: "bootstrap",
                allowed: false,
                blocked_by: "both",
                priority: 2,
                controller_allowed: false,
                target_allowed: false,
                controller_priority: 2,
                target_priority: 2,
                recommendation: "bootstrap blocked".into(),
                controller_reason: Some("controller blocked bootstrap".into()),
                target_reason: Some("target blocked bootstrap".into()),
            },
            HookEffectiveAction {
                action_key: "hook.install",
                command_group: "hook-install",
                allowed: false,
                blocked_by: "both",
                priority: 3,
                controller_allowed: false,
                target_allowed: false,
                controller_priority: 3,
                target_priority: 3,
                recommendation: "install blocked".into(),
                controller_reason: Some("controller blocked install".into()),
                target_reason: Some("target blocked install".into()),
            },
            HookEffectiveAction {
                action_key: "hook.status",
                command_group: "hook-status",
                allowed: false,
                blocked_by: "both",
                priority: 4,
                controller_allowed: false,
                target_allowed: false,
                controller_priority: 4,
                target_priority: 4,
                recommendation: "status blocked".into(),
                controller_reason: Some("controller blocked status".into()),
                target_reason: Some("target blocked status".into()),
            },
            HookEffectiveAction {
                action_key: "hook.stop",
                command_group: "hook-stop",
                allowed: false,
                blocked_by: "both",
                priority: 5,
                controller_allowed: false,
                target_allowed: false,
                controller_priority: 5,
                target_priority: 5,
                recommendation: "stop blocked".into(),
                controller_reason: Some("controller blocked stop".into()),
                target_reason: Some("target blocked stop".into()),
            },
        ];

        let automation = hook_automation_to_json(&actions, &backend_matrix);
        assert_eq!(automation["hasFallbackPlan"], true);
        assert_eq!(
            automation["fallbackPlan"]["errorCodeRouting"]["hook-fallback-hook-install-failed"],
            "query-only-path"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolve"]["examples"]["queryOnlyInstallFailure"]["available"],
            true
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolve"]["examples"]["queryOnlyInstallFailure"]["matched"],
            true
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolve"]["examples"]["queryOnlyInstallFailure"]["usedDefault"],
            false
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolve"]["examples"]["queryOnlyInstallFailure"]["reason"],
            "matched-error-code"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolve"]["examples"]["queryOnlyInstallFailure"]["effectivePhase"],
            "query"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolve"]["examples"]["queryOnlyInstallFailure"]["effectiveEscalationKey"],
            "query-only-path"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolve"]["examples"]["queryOnlyInstallFailure"]["blockedBy"],
            "both"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolve"]["examples"]["queryOnlyInstallFailure"]["blockedBySource"],
            "both"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolve"]["examples"]["queryOnlyInstallFailure"]["isBlocked"],
            true
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolve"]["examples"]["queryOnlyInstallFailure"]["wouldUseQueryOnlyPath"],
            true
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolveExampleQueryOnlyErrorCode"],
            "hook-fallback-hook-install-failed"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolveExampleQueryOnlyBlockedBy"],
            "both"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolveExampleQueryOnlyBlockedBySource"],
            "both"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolveExampleQueryOnlyIsBlocked"],
            true
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolveExampleQueryOnlyAvailable"],
            true
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolveExampleQueryOnlyMatched"],
            true
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolveExampleQueryOnlyUsedDefault"],
            false
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolveExampleQueryOnlyReason"],
            "matched-error-code"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolveExampleQueryOnlyEffectivePhase"],
            "query"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]
                ["resolveExampleQueryOnlyEffectiveEscalationKey"],
            "query-only-path"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolveExampleQueryOnlyWouldUsePath"],
            true
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolveExampleQueryOnlyResult"]["effective"]["escalationKey"],
            "query-only-path"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]
                ["resolveExampleQueryOnlyResultEffective"],
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolveExampleQueryOnlyResult"]
                ["effective"]
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolveExampleQueryOnlyResultMatched"],
            true
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolveExampleQueryOnlyResultUsedDefault"],
            false
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolveExampleQueryOnlyResultReason"],
            "matched-error-code"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolveExampleQueryOnlyResultEffectivePhase"],
            "query"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]
                ["resolveExampleQueryOnlyResultEffectiveEscalationKey"],
            "query-only-path"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolveExampleQueryOnlyInstallFailure"]["reason"],
            "matched-error-code"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["queryOnlyErrorCode"],
            "hook-fallback-hook-install-failed"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["queryOnlySourceErrorCode"],
            "hook-fallback-hook-install-failed"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["queryOnlyBlockedBy"],
            "both"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["queryOnlyBlockedBySource"],
            "both"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["queryOnlyIsBlocked"],
            true
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["queryOnlyAvailable"],
            true
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["queryOnlyMatched"],
            true
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["queryOnlyUsedDefault"],
            false
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["queryOnlyReason"],
            "matched-error-code"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["queryOnlyEffectivePhase"],
            "query"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["queryOnlyEffectiveEscalationKey"],
            "query-only-path"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["queryOnlyWouldUsePath"],
            true
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["queryOnlyWouldUsePhase"],
            true
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["queryOnlyResolveResult"]["effective"]["escalationKey"],
            "query-only-path"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["queryOnlyResolveResultEffective"],
            automation["fallbackPlan"]["routingDecision"]["ready"]["queryOnlyResolveResult"]["effective"]
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["queryOnlyResolveResultMatched"],
            true
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["queryOnlyResolveResultUsedDefault"],
            false
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["queryOnlyResolveResultReason"],
            "matched-error-code"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["queryOnlyResolveResultEffectivePhase"],
            "query"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]
                ["queryOnlyResolveResultEffectiveEscalationKey"],
            "query-only-path"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["queryOnlyPhaseResolveResult"]["effective"]["phase"],
            "query"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["queryOnlyPhaseResolveResultEffective"],
            automation["fallbackPlan"]["routingDecision"]["ready"]["queryOnlyPhaseResolveResult"]
                ["effective"]
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["queryOnlyPhaseResolveResultMatched"],
            true
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["queryOnlyPhaseResolveResultUsedDefault"],
            false
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["queryOnlyPhaseResolveResultReason"],
            "matched-phase"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["queryOnlyPhaseResolveResultEffectivePhase"],
            "query"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]
                ["queryOnlyPhaseResolveResultEffectiveEscalationKey"],
            "query-only-path"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolve"]["queryOnlyWouldUsePath"],
            true
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolve"]["queryOnlyResult"]["effective"]["escalationKey"],
            "query-only-path"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolve"]["examples"]["queryOnlyInstallFailure"]["result"]["effective"]["escalationKey"],
            "query-only-path"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolve"]["examples"]["queryOnlyInstallFailure"]["sourceErrorCode"],
            "hook-fallback-hook-install-failed"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolve"]["examples"]["queryOnlyInstallFailure"]["phase"],
            "query"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolve"]["examples"]["queryOnlyInstallFailure"]["blockedBy"],
            "both"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolve"]["examples"]["queryOnlyInstallFailure"]["blockedBySource"],
            "both"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolve"]["examples"]["queryOnlyInstallFailure"]["isBlocked"],
            true
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolve"]["examples"]["queryOnlyInstallFailure"]["available"],
            true
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolve"]["examples"]["queryOnlyInstallFailure"]["matched"],
            true
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolve"]["examples"]["queryOnlyInstallFailure"]["usedDefault"],
            false
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolve"]["examples"]["queryOnlyInstallFailure"]["reason"],
            "matched-phase"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolve"]["examples"]["queryOnlyInstallFailure"]["effectivePhase"],
            "query"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolve"]["examples"]["queryOnlyInstallFailure"]["effectiveEscalationKey"],
            "query-only-path"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolve"]["examples"]["queryOnlyInstallFailure"]["wouldUseQueryPhase"],
            true
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolveExampleQueryOnlySourceErrorCode"],
            "hook-fallback-hook-install-failed"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolveExampleQueryOnlyPhase"],
            "query"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolveExampleQueryOnlyBlockedBy"],
            "both"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolveExampleQueryOnlyBlockedBySource"],
            "both"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolveExampleQueryOnlyIsBlocked"],
            true
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolveExampleQueryOnlyAvailable"],
            true
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolveExampleQueryOnlyMatched"],
            true
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolveExampleQueryOnlyUsedDefault"],
            false
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolveExampleQueryOnlyReason"],
            "matched-phase"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolveExampleQueryOnlyEffectivePhase"],
            "query"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]
                ["phaseResolveExampleQueryOnlyEffectiveEscalationKey"],
            "query-only-path"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolveExampleQueryOnlyWouldUsePhase"],
            true
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolveExampleQueryOnlyResult"]["effective"]["phase"],
            "query"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]
                ["phaseResolveExampleQueryOnlyResultEffective"],
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolveExampleQueryOnlyResult"]
                ["effective"]
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]
                ["phaseResolveExampleQueryOnlyResultMatched"],
            true
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]
                ["phaseResolveExampleQueryOnlyResultUsedDefault"],
            false
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolveExampleQueryOnlyResultReason"],
            "matched-phase"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]
                ["phaseResolveExampleQueryOnlyResultEffectivePhase"],
            "query"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]
                ["phaseResolveExampleQueryOnlyResultEffectiveEscalationKey"],
            "query-only-path"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolveExampleQueryOnlyInstallFailure"]["reason"],
            "matched-phase"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolve"]["queryOnlyWouldUsePhase"],
            true
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolve"]["queryOnlyResult"]["effective"]["phase"],
            "query"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolve"]["examples"]["queryOnlyInstallFailure"]["result"]["effective"]["phase"],
            "query"
        );
    }

    #[test]
    fn hook_automation_query_only_example_defaults_to_none_when_install_action_missing() {
        let report = HookEnvironmentReport {
            active_backend: None,
            backends: vec![],
            warnings: vec![],
        };
        let backend_matrix = hook_backend_matrix_to_json(&report, &report);
        let actions: Vec<HookEffectiveAction> = Vec::new();

        let automation = hook_automation_to_json(&actions, &backend_matrix);
        assert_eq!(automation["hasFallbackPlan"], true);
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolve"]["examples"]["queryOnlyInstallFailure"]["blockedBy"],
            json!(null)
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolve"]["queryOnlyBlockedBy"],
            json!(null)
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolve"]["examples"]["queryOnlyInstallFailure"]["blockedBySource"],
            "none"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolve"]["examples"]["queryOnlyInstallFailure"]["isBlocked"],
            false
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolve"]["examples"]["queryOnlyInstallFailure"]["available"],
            true
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolve"]["examples"]["queryOnlyInstallFailure"]["matched"],
            true
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolve"]["examples"]["queryOnlyInstallFailure"]["usedDefault"],
            false
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolve"]["examples"]["queryOnlyInstallFailure"]["reason"],
            "matched-error-code"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolve"]["examples"]["queryOnlyInstallFailure"]["effectivePhase"],
            "query"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolve"]["examples"]["queryOnlyInstallFailure"]["effectiveEscalationKey"],
            "query-only-path"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["resolve"]["examples"]["queryOnlyInstallFailure"]["wouldUseQueryOnlyPath"],
            true
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["queryOnlyErrorCode"],
            "hook-fallback-hook-install-failed"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["queryOnlySourceErrorCode"],
            "hook-fallback-hook-install-failed"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["queryOnlyBlockedBy"],
            json!(null)
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["queryOnlyBlockedBySource"],
            "none"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["queryOnlyIsBlocked"],
            false
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["queryOnlyAvailable"],
            true
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["queryOnlyMatched"],
            true
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["queryOnlyUsedDefault"],
            false
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["queryOnlyReason"],
            "matched-error-code"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["queryOnlyEffectivePhase"],
            "query"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["queryOnlyEffectiveEscalationKey"],
            "query-only-path"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["queryOnlyWouldUsePath"],
            true
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["queryOnlyWouldUsePhase"],
            true
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["queryOnlyResolveResult"]["effective"]["escalationKey"],
            "query-only-path"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["queryOnlyResolveResultEffective"],
            automation["fallbackPlan"]["routingDecision"]["ready"]["queryOnlyResolveResult"]["effective"]
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["queryOnlyPhaseResolveResult"]["effective"]["phase"],
            "query"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["queryOnlyPhaseResolveResultEffective"],
            automation["fallbackPlan"]["routingDecision"]["ready"]["queryOnlyPhaseResolveResult"]
                ["effective"]
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolve"]["examples"]["queryOnlyInstallFailure"]["phase"],
            "query"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolve"]["queryOnlyResult"]["effective"]["phase"],
            "query"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolve"]["examples"]["queryOnlyInstallFailure"]["blockedBySource"],
            "none"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolve"]["examples"]["queryOnlyInstallFailure"]["isBlocked"],
            false
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolve"]["examples"]["queryOnlyInstallFailure"]["available"],
            true
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolve"]["examples"]["queryOnlyInstallFailure"]["matched"],
            true
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolve"]["examples"]["queryOnlyInstallFailure"]["usedDefault"],
            false
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolve"]["examples"]["queryOnlyInstallFailure"]["reason"],
            "matched-phase"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolve"]["examples"]["queryOnlyInstallFailure"]["effectivePhase"],
            "query"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolve"]["examples"]["queryOnlyInstallFailure"]["effectiveEscalationKey"],
            "query-only-path"
        );
        assert_eq!(
            automation["fallbackPlan"]["routingDecision"]["ready"]["phaseResolve"]["examples"]["queryOnlyInstallFailure"]["wouldUseQueryPhase"],
            true
        );
    }

    #[test]
    fn hook_backend_matrix_reports_shared_and_side_specific_backends() {
        let controller_report = HookEnvironmentReport {
            active_backend: Some("ellekit".into()),
            backends: vec![
                HookBackendInfo {
                    id: "ellekit".into(),
                    display_name: "ElleKit".into(),
                    loaded_images: vec!["/var/jb/usr/lib/libellekit.dylib".into()],
                    filesystem_paths: vec![],
                },
                HookBackendInfo {
                    id: "substitute".into(),
                    display_name: "Substitute".into(),
                    loaded_images: vec![],
                    filesystem_paths: vec!["/var/jb/usr/lib/libsubstitute.dylib".into()],
                },
            ],
            warnings: vec![],
        };
        let target_report = HookEnvironmentReport {
            active_backend: Some("substrate".into()),
            backends: vec![
                HookBackendInfo {
                    id: "ellekit".into(),
                    display_name: "ElleKit".into(),
                    loaded_images: vec![],
                    filesystem_paths: vec!["/var/jb/usr/lib/libellekit.dylib".into()],
                },
                HookBackendInfo {
                    id: "substrate".into(),
                    display_name: "Cydia Substrate".into(),
                    loaded_images: vec!["/Library/MobileSubstrate/MobileSubstrate.dylib".into()],
                    filesystem_paths: vec![],
                },
            ],
            warnings: vec![],
        };

        let rendered = hook_backend_matrix_to_json(&controller_report, &target_report);
        assert_eq!(rendered["entryCount"], 3);
        assert_eq!(rendered["loadedInControllerCount"], 1);
        assert_eq!(rendered["loadedInTargetCount"], 1);
        assert_eq!(rendered["loadedInBothCount"], 0);
        assert_eq!(rendered["filesystemOnlyInEitherCount"], 1);
        assert_eq!(rendered["sharedBackendIds"], json!(["ellekit"]));
        assert_eq!(rendered["controllerOnlyBackendIds"], json!(["substitute"]));
        assert_eq!(rendered["targetOnlyBackendIds"], json!(["substrate"]));
        assert_eq!(rendered["filesystemOnlyBackendIds"], json!(["substitute"]));

        let entries = rendered["entries"].as_array().expect("matrix entries");
        let shared = entries
            .iter()
            .find(|entry| entry["id"] == "ellekit")
            .expect("ellekit entry");
        assert_eq!(shared["visibility"], "both");
        assert_eq!(shared["loadedBy"], "controller");

        let controller_strategy = HookStrategyDecision {
            policy: HookPolicy::Warn,
            strategy: "internal-inline-risky".into(),
            allowed: true,
            inline_hooks_allowed: true,
            reason: None,
        };
        let target_strategy = HookStrategyDecision {
            policy: HookPolicy::Warn,
            strategy: "internal-inline-risky".into(),
            allowed: true,
            inline_hooks_allowed: true,
            reason: None,
        };
        let controller_actions = hook_environment_recommended_actions(&controller_report, Some(&controller_strategy));
        let target_actions = hook_environment_recommended_actions(&target_report, Some(&target_strategy));
        let effective_actions = hook_effective_actions(&controller_actions, &target_actions);
        let coexistence = super::hook_coexistence_to_json(&effective_actions, &rendered);
        let automation = hook_automation_to_json(&effective_actions, &rendered);
        assert_eq!(coexistence["mode"], "query-only");
        assert_eq!(coexistence["strategy"], "query-only-fallback");
        assert_eq!(coexistence["riskLevel"], "elevated");
        assert_eq!(coexistence["baseCommandMode"], "allowed");
        assert_eq!(coexistence["effectiveCommandMode"], "query-only");
        assert_eq!(coexistence["commandMode"], "query-only");
        assert_eq!(coexistence["autoDowngradedToQueryOnly"], true);
        assert_eq!(
            coexistence["autoDowngradeReason"],
            "split-loaded-external-backends-without-shared-runtime"
        );
        assert_eq!(coexistence["backendPressure"], "both");
        assert_eq!(coexistence["externalBackendLoaded"], true);
        assert_eq!(coexistence["singleExternalBackendLoaded"], false);
        assert_eq!(coexistence["multipleExternalBackendsLoaded"], true);
        assert_eq!(coexistence["loadedExternalBackendCount"], 2);
        assert_eq!(coexistence["externalBackendInController"], true);
        assert_eq!(coexistence["externalBackendInTarget"], true);
        assert_eq!(coexistence["sharedExternalBackend"], true);
        assert_eq!(coexistence["hookInstallAllowed"], true);
        assert_eq!(coexistence["nextActionKey"], "hook.query");
        assert_eq!(coexistence["nextActionTemplateCount"], 3);
        assert_eq!(coexistence["nextActionTemplates"][0], "objc.classes <filter>");
        assert_eq!(automation["baseCommandMode"], "allowed");
        assert_eq!(automation["effectiveCommandMode"], "query-only");
        assert_eq!(automation["commandMode"], "query-only");
        assert_eq!(automation["autoDowngradedToQueryOnly"], true);
        assert_eq!(
            automation["autoDowngradeReason"],
            "split-loaded-external-backends-without-shared-runtime"
        );
        assert_eq!(automation["backendPressure"], "both");
        assert_eq!(automation["preferredPath"], "query-only");
        assert_eq!(automation["loadedExternalBackendCount"], 2);
        assert_eq!(automation["singleExternalBackendLoaded"], false);
        assert_eq!(automation["multipleExternalBackendsLoaded"], true);
        assert_eq!(automation["branchExecutionOrder"][0], "hook.query");
        assert_eq!(automation["nextActionKey"], "hook.query");
        assert_eq!(automation["nextReadyActionKey"], "hook.query");
        assert_eq!(automation["nextRunnableActionKey"], "hook.query");
        assert_eq!(automation["nextActionAllowed"], true);
        assert_eq!(automation["nextActionBlockedBy"], "none");
        assert_eq!(automation["nextActionBranch"], "run");
        assert_eq!(automation["nextActionReadyToRun"], true);
        assert_eq!(automation["hasFallbackPlan"], false);
        assert!(automation["fallbackPlan"].is_null());
        assert_eq!(automation["suggestedSequence"][0], "native.hookenv");
        assert!(automation["commandTemplates"].is_array());
        assert_eq!(automation["nextActionPlan"]["actionKey"], "hook.query");
        assert_eq!(automation["nextActionPlan"]["allowed"], true);
        assert_eq!(automation["nextActionPlan"]["branch"], "run");
        assert_eq!(automation["nextActionPlan"]["readyToRun"], true);
        assert_eq!(automation["nextActionTemplateCount"], 3);
        assert_eq!(automation["nextActionTemplates"][0], "objc.classes <filter>");
        assert_eq!(automation["nextActionCommandJsonTemplateCount"], 3);
        assert_eq!(
            automation["nextActionCommandJsonTemplates"][0]["command"],
            "objc.classes <filter>"
        );
        assert_eq!(automation["suggestedSequence"][2], "native.images <filter>");
        let templates = automation["commandTemplates"].as_array().expect("command templates");
        let install_templates = templates
            .iter()
            .find(|item| item["actionKey"] == "hook.install")
            .expect("hook.install templates");
        assert_eq!(install_templates["templateCount"], 0);
        assert_eq!(install_templates["commandJsonTemplateCount"], 0);
        assert_eq!(install_templates["templates"], json!([]));
        assert_eq!(install_templates["commandJsonTemplates"], json!([]));
        let branches = automation["actionBranches"].as_array().expect("automation branches");
        let install_branch = branches
            .iter()
            .find(|item| item["actionKey"] == "hook.install")
            .expect("hook.install branch");
        assert_eq!(install_branch["selectedAsNext"], false);
        assert_eq!(install_branch["templateCount"], 0);
        assert_eq!(install_branch["commandJsonTemplateCount"], 0);
        assert_eq!(install_branch["commandJsonEligibleTemplateCount"], 0);
        assert_eq!(install_branch["templates"], json!([]));
    }

    #[test]
    fn hook_backend_matrix_filesystem_only_prefers_inline_cautious_path() {
        let controller_report = HookEnvironmentReport {
            active_backend: None,
            backends: vec![HookBackendInfo {
                id: "libhooker".into(),
                display_name: "libhooker".into(),
                loaded_images: vec![],
                filesystem_paths: vec!["/var/jb/usr/lib/libhooker.dylib".into()],
            }],
            warnings: vec![],
        };
        let target_report = HookEnvironmentReport {
            active_backend: None,
            backends: vec![HookBackendInfo {
                id: "libhooker".into(),
                display_name: "libhooker".into(),
                loaded_images: vec![],
                filesystem_paths: vec!["/var/jb/usr/lib/libhooker.dylib".into()],
            }],
            warnings: vec![],
        };

        let rendered = hook_backend_matrix_to_json(&controller_report, &target_report);
        assert_eq!(rendered["loadedInControllerCount"], 0);
        assert_eq!(rendered["loadedInTargetCount"], 0);
        assert_eq!(rendered["filesystemOnlyInEitherCount"], 1);

        let strategy = HookStrategyDecision {
            policy: HookPolicy::Warn,
            strategy: "internal-inline-cautious".into(),
            allowed: true,
            inline_hooks_allowed: true,
            reason: Some("filesystem-only backend artifacts detected".into()),
        };
        let controller_actions = hook_environment_recommended_actions(&controller_report, Some(&strategy));
        let target_actions = hook_environment_recommended_actions(&target_report, Some(&strategy));
        let effective_actions = hook_effective_actions(&controller_actions, &target_actions);

        let coexistence = super::hook_coexistence_to_json(&effective_actions, &rendered);
        let automation = hook_automation_to_json(&effective_actions, &rendered);

        assert_eq!(coexistence["mode"], "inline-cautious");
        assert_eq!(coexistence["strategy"], "filesystem-candidate-cautious");
        assert_eq!(coexistence["riskLevel"], "cautious");
        assert_eq!(coexistence["backendPressure"], "filesystem-only");
        assert_eq!(coexistence["externalBackendLoaded"], false);
        assert_eq!(coexistence["singleExternalBackendLoaded"], false);
        assert_eq!(coexistence["multipleExternalBackendsLoaded"], false);
        assert_eq!(coexistence["loadedExternalBackendCount"], 0);

        assert_eq!(automation["preferredPath"], "inline-cautious");
        assert_eq!(automation["loadedExternalBackendCount"], 0);
        assert_eq!(automation["singleExternalBackendLoaded"], false);
        assert_eq!(automation["multipleExternalBackendsLoaded"], false);
        assert_eq!(automation["suggestedSequence"][1], "controller --preflight-only --preflight-json --pid <pid>");

        let templates = automation["commandTemplates"].as_array().expect("command templates");
        let install_templates = templates
            .iter()
            .find(|item| item["actionKey"] == "hook.install")
            .expect("hook.install templates");
        assert_eq!(install_templates["templateCount"], 5);
        assert_eq!(
            install_templates["commandJsonTemplates"][0]["risk"],
            "cautious-filesystem-only-backend-artifacts"
        );
        assert!(install_templates["templates"][0]
            .as_str()
            .unwrap_or_default()
            .contains("caution-filesystem-only-backend-artifacts"));
    }

    #[test]
    fn hook_bootstrap_templates_render_controller_cli_command_entries() {
        let templates = hook_action_command_templates("hook.bootstrap", "inline-safe");
        assert_eq!(templates.len(), 3);

        let entries = templates
            .iter()
            .map(|template| command_json_template_entry(template))
            .collect::<Vec<_>>();

        assert_eq!(entries[0]["command"], "native.hookenv");
        assert_eq!(entries[0]["kind"], "runtime-command");
        assert_eq!(entries[0]["commandJsonEligible"], true);
        assert_eq!(entries[0]["placeholderCount"], 0);
        assert_eq!(entries[0]["risk"], "normal");
        assert_eq!(entries[0]["phase"], "diagnose");
        assert_eq!(entries[0]["retryable"], true);
        assert_eq!(entries[0]["maxSuggestedRetries"], 1);
        assert_eq!(entries[0]["retryDelayHintMs"], 250);
        assert_eq!(entries[0]["timeoutHintMs"], 4000);
        assert_eq!(entries[0]["timeoutAction"], "refresh-hook-environment-and-retry");
        assert_eq!(entries[0]["errorCode"], "hook-fallback-diagnose-failed");
        assert_eq!(entries[0]["timeoutErrorCode"], "hook-fallback-diagnose-timeout");
        assert_eq!(entries[0]["cliArgs"][4], "--command-json");

        assert_eq!(
            entries[1]["command"],
            "controller --preflight-only --preflight-json --pid <pid>"
        );
        assert_eq!(entries[1]["kind"], "controller-cli");
        assert_eq!(entries[1]["commandJsonEligible"], false);
        assert_eq!(entries[1]["placeholderCount"], 1);
        assert_eq!(entries[1]["placeholders"][0], "<pid>");
        assert_eq!(entries[1]["phase"], "preflight");
        assert_eq!(entries[1]["retryable"], true);
        assert_eq!(entries[1]["maxSuggestedRetries"], 2);
        assert_eq!(entries[1]["retryDelayHintMs"], 500);
        assert_eq!(entries[1]["timeoutHintMs"], 8000);
        assert_eq!(entries[1]["timeoutAction"], "re-run-preflight-or-switch-to-query-only");
        assert_eq!(entries[1]["errorCode"], "hook-fallback-preflight-failed");
        assert_eq!(entries[1]["timeoutErrorCode"], "hook-fallback-preflight-timeout");
        assert_eq!(entries[1]["cliArgs"][0], "--preflight-only");
        assert_eq!(entries[1]["cliArgs"][1], "--preflight-json");
        assert_eq!(entries[1]["cliArgs"][2], "--pid");
        assert_eq!(entries[1]["cliArgs"][3], "<pid>");

        assert_eq!(entries[2]["command"], "controller --inject-json --pid <pid>");
        assert_eq!(entries[2]["kind"], "controller-cli");
        assert_eq!(entries[2]["commandJsonEligible"], false);
        assert_eq!(entries[2]["placeholderCount"], 1);
        assert_eq!(entries[2]["placeholders"][0], "<pid>");
        assert_eq!(entries[2]["phase"], "inject");
        assert_eq!(entries[2]["retryable"], false);
        assert_eq!(entries[2]["maxSuggestedRetries"], 0);
        assert_eq!(entries[2]["retryDelayHintMs"], 0);
        assert_eq!(entries[2]["timeoutHintMs"], 12000);
        assert_eq!(entries[2]["timeoutAction"], "abort-injection-and-run-preflight");
        assert_eq!(entries[2]["errorCode"], "hook-fallback-inject-failed");
        assert_eq!(entries[2]["timeoutErrorCode"], "hook-fallback-inject-timeout");
        assert_eq!(entries[2]["cliArgs"][0], "--inject-json");
        assert_eq!(entries[2]["cliArgs"][1], "--pid");
        assert_eq!(entries[2]["cliArgs"][2], "<pid>");
    }

    #[test]
    fn hook_install_templates_are_suppressed_when_path_is_not_inline() {
        assert_eq!(
            hook_action_command_templates("hook.install", "query-only"),
            Vec::<String>::new()
        );
        assert_eq!(
            hook_action_command_templates("hook.install", "cleanup-only"),
            Vec::<String>::new()
        );
        assert_eq!(
            hook_action_command_templates("hook.install", "blocked"),
            Vec::<String>::new()
        );
    }

    #[test]
    fn render_injection_result_json_classifies_task_for_pid_failure_without_trace() {
        let config = ControllerConfig {
            mode: InjectionMode::Attach,
            pid: Some(42),
            bundle_id: None,
            spawn_command: None,
            command: None,
            command_json: false,
            list_images_json: false,
            preflight_only: false,
            preflight_json: false,
            inject_json: true,
            agent_path: LEGACY_AGENT_PATH_ROOTFUL.into(),
            entry_symbol: "ios_agent_entry".into(),
            script_path: None,
            socket_path: None,
            connect_timeout_secs: 15,
        };

        let environment = InjectionEnvironmentReport {
            dry_run: false,
            bootstrap_wait_ms: Some(1000),
            hook_policy: HookPolicy::Warn,
            hook_strategy: HookStrategyDecision {
                policy: HookPolicy::Warn,
                strategy: "internal-inline".into(),
                allowed: true,
                inline_hooks_allowed: true,
                reason: None,
            },
            hook_environment: HookEnvironmentReport {
                active_backend: None,
                backends: vec![],
                warnings: vec![],
            },
        };
        let plan = MachInjector
            .plan(&InjectionTarget {
                pid: 42,
                dylib_path: DEFAULT_AGENT_PATH.into(),
                entry_symbol: "ios_agent_entry".into(),
                socket_path: "/tmp/iosrf.sock".into(),
            })
            .expect("plan");
        let preflight = InjectionTargetPreflightReport {
            main_image: None,
            target_images: vec![],
            target_image_count: 0,
            target_uses_arm64e: Some(false),
            thread_bootstrap_kind: ThreadBootstrapKind::PthreadCreateFromMachThread,
            thread_bootstrap_label: "pthread_create_from_mach_thread".into(),
            thread_bootstrap_address: 0,
            thread_bootstrap_raw_address: 0,
            thread_bootstrap_canonicalized: false,
            target_hook_environment: HookEnvironmentReport {
                active_backend: None,
                backends: vec![],
                warnings: vec![],
            },
            target_hook_strategy: HookStrategyDecision {
                policy: HookPolicy::Warn,
                strategy: "internal-inline".into(),
                allowed: true,
                inline_hooks_allowed: true,
                reason: None,
            },
            resolved_loader_symbols: vec![],
        };

        let doctor = analyze_doctor_report(&config, 42, Path::new("/tmp/iosrf.sock"), &environment, &preflight);
        let rendered = render_injection_result_json(
            &config,
            42,
            "/tmp/iosrf.sock",
            &plan,
            &environment,
            &doctor,
            &preflight,
            None,
            None,
            None,
            None,
            false,
            None,
            None,
            &[],
            Some(&Error::State(
                "task_for_pid failed: (os/kern) failure (0x5); verify jailbreak/root context, task_for_pid entitlement/exception, and that the target process is not protected by platform restrictions".into(),
            )),
        );

        assert_eq!(rendered["ok"], false);
        assert!(rendered["trace"].is_null());
        assert_eq!(rendered["diagnostics"]["phase"], "mach");
        assert_eq!(rendered["diagnostics"]["code"], "task-for-pid");
        assert!(rendered["diagnostics"]["hook"].is_null());
        assert_eq!(rendered["diagnostics"]["handshakeStage"], "awaiting-hello");
        assert_eq!(rendered["diagnostics"]["failedStep"], "hello");
        assert!(rendered["diagnostics"]["hints"]
            .as_array()
            .expect("hints array")
            .iter()
            .any(|item| item.as_str().unwrap_or_default().contains(LEGACY_AGENT_PATH_ROOTFUL)));
        assert!(rendered["handshake"]["errors"]["hello"].is_null());
        assert_eq!(rendered["handshake"]["steps"]["hello"], "pending");
        assert_eq!(rendered["handshake"]["steps"]["ping"], "pending");
        assert_eq!(rendered["handshake"]["steps"]["hookEnvironment"], "pending");
    }

    #[test]
    fn render_injection_result_json_classifies_thread_create_running_failure() {
        let config = ControllerConfig {
            mode: InjectionMode::Attach,
            pid: Some(42),
            bundle_id: None,
            spawn_command: None,
            command: None,
            command_json: false,
            list_images_json: false,
            preflight_only: false,
            preflight_json: false,
            inject_json: true,
            agent_path: DEFAULT_AGENT_PATH.into(),
            entry_symbol: "ios_agent_entry".into(),
            script_path: None,
            socket_path: None,
            connect_timeout_secs: 15,
        };

        let environment = InjectionEnvironmentReport {
            dry_run: false,
            bootstrap_wait_ms: Some(1000),
            hook_policy: HookPolicy::Warn,
            hook_strategy: HookStrategyDecision {
                policy: HookPolicy::Warn,
                strategy: "internal-inline".into(),
                allowed: true,
                inline_hooks_allowed: true,
                reason: None,
            },
            hook_environment: HookEnvironmentReport {
                active_backend: None,
                backends: vec![],
                warnings: vec![],
            },
        };
        let plan = MachInjector
            .plan(&InjectionTarget {
                pid: 42,
                dylib_path: DEFAULT_AGENT_PATH.into(),
                entry_symbol: "ios_agent_entry".into(),
                socket_path: "/tmp/iosrf.sock".into(),
            })
            .expect("plan");
        let preflight = InjectionTargetPreflightReport {
            main_image: None,
            target_images: vec![],
            target_image_count: 0,
            target_uses_arm64e: Some(false),
            thread_bootstrap_kind: ThreadBootstrapKind::PthreadCreateFromMachThread,
            thread_bootstrap_label: "pthread_create_from_mach_thread".into(),
            thread_bootstrap_address: 0,
            thread_bootstrap_raw_address: 0,
            thread_bootstrap_canonicalized: false,
            target_hook_environment: HookEnvironmentReport {
                active_backend: None,
                backends: vec![],
                warnings: vec![],
            },
            target_hook_strategy: HookStrategyDecision {
                policy: HookPolicy::Warn,
                strategy: "internal-inline".into(),
                allowed: true,
                inline_hooks_allowed: true,
                reason: None,
            },
            resolved_loader_symbols: vec![],
        };

        let doctor = analyze_doctor_report(&config, 42, Path::new("/tmp/iosrf.sock"), &environment, &preflight);
        let rendered = render_injection_result_json(
            &config,
            42,
            "/tmp/iosrf.sock",
            &plan,
            &environment,
            &doctor,
            &preflight,
            None,
            None,
            None,
            None,
            false,
            None,
            None,
            &[],
            Some(&Error::State(
                "thread_create_running failed: (os/kern) invalid argument (0x4, invalid-argument); remote thread state was rejected; verify the bootstrap register layout and thread state flavor/count".into(),
            )),
        );

        assert_eq!(rendered["diagnostics"]["phase"], "remote-thread");
        assert_eq!(rendered["diagnostics"]["code"], "thread-create-running");
        assert!(rendered["diagnostics"]["hook"].is_null());
    }

    #[test]
    fn render_injection_result_json_classifies_controller_script_read_failure() {
        let config = ControllerConfig {
            mode: InjectionMode::Attach,
            pid: Some(42),
            bundle_id: None,
            spawn_command: None,
            command: None,
            command_json: false,
            list_images_json: false,
            preflight_only: false,
            preflight_json: false,
            inject_json: true,
            agent_path: LEGACY_AGENT_PATH_ROOTFUL.into(),
            entry_symbol: "ios_agent_entry".into(),
            script_path: Some("/tmp/missing.js".into()),
            socket_path: None,
            connect_timeout_secs: 15,
        };

        let environment = InjectionEnvironmentReport {
            dry_run: false,
            bootstrap_wait_ms: Some(1000),
            hook_policy: HookPolicy::Warn,
            hook_strategy: HookStrategyDecision {
                policy: HookPolicy::Warn,
                strategy: "internal-inline".into(),
                allowed: true,
                inline_hooks_allowed: true,
                reason: None,
            },
            hook_environment: HookEnvironmentReport {
                active_backend: None,
                backends: vec![],
                warnings: vec![],
            },
        };
        let plan = MachInjector
            .plan(&InjectionTarget {
                pid: 42,
                dylib_path: DEFAULT_AGENT_PATH.into(),
                entry_symbol: "ios_agent_entry".into(),
                socket_path: "/tmp/iosrf.sock".into(),
            })
            .expect("plan");
        let preflight = InjectionTargetPreflightReport {
            main_image: None,
            target_images: vec![],
            target_image_count: 0,
            target_uses_arm64e: Some(false),
            thread_bootstrap_kind: ThreadBootstrapKind::PthreadCreateFromMachThread,
            thread_bootstrap_label: "pthread_create_from_mach_thread".into(),
            thread_bootstrap_address: 0,
            thread_bootstrap_raw_address: 0,
            thread_bootstrap_canonicalized: false,
            target_hook_environment: HookEnvironmentReport {
                active_backend: None,
                backends: vec![],
                warnings: vec![],
            },
            target_hook_strategy: HookStrategyDecision {
                policy: HookPolicy::Warn,
                strategy: "internal-inline".into(),
                allowed: true,
                inline_hooks_allowed: true,
                reason: None,
            },
            resolved_loader_symbols: vec![],
        };

        let doctor = analyze_doctor_report(&config, 42, Path::new("/tmp/iosrf.sock"), &environment, &preflight);
        let rendered = render_injection_result_json(
            &config,
            42,
            "/tmp/iosrf.sock",
            &plan,
            &environment,
            &doctor,
            &preflight,
            None,
            None,
            None,
            None,
            false,
            None,
            None,
            &[],
            Some(&Error::State(
                "controller script read failed: io error: No such file or directory".into(),
            )),
        );

        assert_eq!(rendered["diagnostics"]["phase"], "script");
        assert_eq!(rendered["diagnostics"]["code"], "script-read");
        assert!(rendered["diagnostics"]["hook"].is_null());
    }

    #[test]
    fn render_injection_result_json_classifies_controller_socket_bind_failure() {
        let config = ControllerConfig {
            mode: InjectionMode::Attach,
            pid: Some(42),
            bundle_id: None,
            spawn_command: None,
            command: None,
            command_json: false,
            list_images_json: false,
            preflight_only: false,
            preflight_json: false,
            inject_json: true,
            agent_path: LEGACY_AGENT_PATH_ROOTFUL.into(),
            entry_symbol: "ios_agent_entry".into(),
            script_path: None,
            socket_path: Some("/tmp/iosrf.sock".into()),
            connect_timeout_secs: 15,
        };

        let environment = InjectionEnvironmentReport {
            dry_run: false,
            bootstrap_wait_ms: Some(1000),
            hook_policy: HookPolicy::Warn,
            hook_strategy: HookStrategyDecision {
                policy: HookPolicy::Warn,
                strategy: "internal-inline".into(),
                allowed: true,
                inline_hooks_allowed: true,
                reason: None,
            },
            hook_environment: HookEnvironmentReport {
                active_backend: None,
                backends: vec![],
                warnings: vec![],
            },
        };
        let plan = MachInjector
            .plan(&InjectionTarget {
                pid: 42,
                dylib_path: DEFAULT_AGENT_PATH.into(),
                entry_symbol: "ios_agent_entry".into(),
                socket_path: "/tmp/iosrf.sock".into(),
            })
            .expect("plan");
        let preflight = InjectionTargetPreflightReport {
            main_image: None,
            target_images: vec![],
            target_image_count: 0,
            target_uses_arm64e: Some(false),
            thread_bootstrap_kind: ThreadBootstrapKind::PthreadCreateFromMachThread,
            thread_bootstrap_label: "pthread_create_from_mach_thread".into(),
            thread_bootstrap_address: 0,
            thread_bootstrap_raw_address: 0,
            thread_bootstrap_canonicalized: false,
            target_hook_environment: HookEnvironmentReport {
                active_backend: None,
                backends: vec![],
                warnings: vec![],
            },
            target_hook_strategy: HookStrategyDecision {
                policy: HookPolicy::Warn,
                strategy: "internal-inline".into(),
                allowed: true,
                inline_hooks_allowed: true,
                reason: None,
            },
            resolved_loader_symbols: vec![],
        };

        let doctor = analyze_doctor_report(&config, 42, Path::new("/tmp/iosrf.sock"), &environment, &preflight);
        let rendered = render_injection_result_json(
            &config,
            42,
            "/tmp/iosrf.sock",
            &plan,
            &environment,
            &doctor,
            &preflight,
            None,
            None,
            None,
            None,
            false,
            None,
            None,
            &[],
            Some(&Error::State(
                "controller socket bind failed: invalid argument: socket path exceeds Darwin sockaddr_un limit".into(),
            )),
        );

        assert_eq!(rendered["diagnostics"]["phase"], "controller-socket");
        assert_eq!(rendered["diagnostics"]["code"], "bind-socket");
        assert!(rendered["diagnostics"]["hook"].is_null());
    }

    #[test]
    fn render_injection_result_json_classifies_hook_effective_blocked_failure() {
        let config = ControllerConfig {
            mode: InjectionMode::Attach,
            pid: Some(42),
            bundle_id: None,
            spawn_command: None,
            command: None,
            command_json: false,
            list_images_json: false,
            preflight_only: false,
            preflight_json: false,
            inject_json: true,
            agent_path: DEFAULT_AGENT_PATH.into(),
            entry_symbol: "ios_agent_entry".into(),
            script_path: None,
            socket_path: None,
            connect_timeout_secs: 15,
        };

        let environment = InjectionEnvironmentReport {
            dry_run: false,
            bootstrap_wait_ms: Some(1000),
            hook_policy: HookPolicy::Warn,
            hook_strategy: HookStrategyDecision {
                policy: HookPolicy::Warn,
                strategy: "internal-inline".into(),
                allowed: true,
                inline_hooks_allowed: true,
                reason: None,
            },
            hook_environment: HookEnvironmentReport {
                active_backend: None,
                backends: vec![],
                warnings: vec![],
            },
        };
        let plan = MachInjector
            .plan(&InjectionTarget {
                pid: 42,
                dylib_path: DEFAULT_AGENT_PATH.into(),
                entry_symbol: "ios_agent_entry".into(),
                socket_path: "/tmp/iosrf.sock".into(),
            })
            .expect("plan");
        let preflight = InjectionTargetPreflightReport {
            main_image: None,
            target_images: vec![],
            target_image_count: 0,
            target_uses_arm64e: Some(false),
            thread_bootstrap_kind: ThreadBootstrapKind::PthreadCreateFromMachThread,
            thread_bootstrap_label: "pthread_create_from_mach_thread".into(),
            thread_bootstrap_address: 0,
            thread_bootstrap_raw_address: 0,
            thread_bootstrap_canonicalized: false,
            target_hook_environment: HookEnvironmentReport {
                active_backend: None,
                backends: vec![],
                warnings: vec![],
            },
            target_hook_strategy: HookStrategyDecision {
                policy: HookPolicy::Warn,
                strategy: "internal-inline".into(),
                allowed: true,
                inline_hooks_allowed: true,
                reason: None,
            },
            resolved_loader_symbols: vec![],
        };

        let doctor = analyze_doctor_report(&config, 42, Path::new("/tmp/iosrf.sock"), &environment, &preflight);
        let rendered = render_injection_result_json(
            &config,
            42,
            "/tmp/iosrf.sock",
            &plan,
            &environment,
            &doctor,
            &preflight,
            None,
            None,
            None,
            None,
            false,
            None,
            None,
            &[],
            Some(&Error::State(
                "`trace UIViewController` requires inline hooks, but the current hook policy forbids hook-install commands: hook-effective-blocked actionKey=hook.install commandGroup=hook-install blockedBy=target commandMode=query-only baseCommandMode=query-only effectiveCommandMode=query-only autoDowngradedToQueryOnly=false autoDowngradeReason=<none> coexistenceMode=cleanup-only backendPressure=both fallbackActionKey=hook.status fallbackStepId=next-action:hook.status:0 fallbackCommand=trace status fallbackPhase=cleanup; recommendation=blocked by target hook policy".into(),
            )),
        );

        assert_eq!(rendered["diagnostics"]["phase"], "hook-policy");
        assert_eq!(rendered["diagnostics"]["code"], "target-hook-policy-blocked");
        assert_eq!(rendered["diagnostics"]["hookActionKey"], "hook.install");
        assert_eq!(rendered["diagnostics"]["hookCommandGroup"], "hook-install");
        assert_eq!(rendered["diagnostics"]["hookBlockedBy"], "target");
        assert_eq!(rendered["diagnostics"]["hookCommandMode"], "query-only");
        assert_eq!(rendered["diagnostics"]["hookBaseCommandMode"], "query-only");
        assert_eq!(rendered["diagnostics"]["hookEffectiveCommandMode"], "query-only");
        assert_eq!(rendered["diagnostics"]["hookAutoDowngradedToQueryOnly"], false);
        assert_eq!(rendered["diagnostics"]["hookAutoDowngradeReason"], "<none>");
        assert_eq!(
            rendered["diagnostics"]["hookRecommendation"],
            "blocked by target hook policy"
        );
        assert_eq!(rendered["diagnostics"]["coexistenceMode"], "cleanup-only");
        assert_eq!(rendered["diagnostics"]["backendPressure"], "both");
        assert_eq!(rendered["diagnostics"]["fallbackActionKey"], "hook.status");
        assert_eq!(rendered["diagnostics"]["fallbackStepId"], "next-action:hook.status:0");
        assert_eq!(rendered["diagnostics"]["fallbackCommand"], "trace status");
        assert_eq!(rendered["diagnostics"]["fallbackPhase"], "cleanup");
        assert_eq!(rendered["diagnostics"]["hookFallbackAvailable"], true);
        assert_eq!(rendered["diagnostics"]["hook"]["actionKey"], "hook.install");
        assert_eq!(rendered["diagnostics"]["hook"]["commandGroup"], "hook-install");
        assert_eq!(rendered["diagnostics"]["hook"]["blockedBy"], "target");
        assert_eq!(rendered["diagnostics"]["hook"]["commandMode"], "query-only");
        assert_eq!(rendered["diagnostics"]["hook"]["baseCommandMode"], "query-only");
        assert_eq!(rendered["diagnostics"]["hook"]["effectiveCommandMode"], "query-only");
        assert_eq!(
            rendered["diagnostics"]["hook"]["autoDowngradedToQueryOnly"],
            false
        );
        assert_eq!(rendered["diagnostics"]["hook"]["autoDowngradeReason"], "<none>");
        assert_eq!(
            rendered["diagnostics"]["hook"]["recommendation"],
            "blocked by target hook policy"
        );
        assert_eq!(rendered["diagnostics"]["hook"]["coexistenceMode"], "cleanup-only");
        assert_eq!(rendered["diagnostics"]["hook"]["backendPressure"], "both");
        assert_eq!(rendered["diagnostics"]["hook"]["fallbackActionKey"], "hook.status");
        assert_eq!(
            rendered["diagnostics"]["hook"]["fallbackStepId"],
            "next-action:hook.status:0"
        );
        assert_eq!(rendered["diagnostics"]["hook"]["fallbackCommand"], "trace status");
        assert_eq!(rendered["diagnostics"]["hook"]["fallbackPhase"], "cleanup");
        assert_eq!(rendered["diagnostics"]["hook"]["fallbackAvailable"], true);
        assert!(rendered["diagnostics"]["hints"]
            .as_array()
            .expect("hints array")
            .iter()
            .any(|item| item
                .as_str()
                .unwrap_or_default()
                .contains("effective hook command mode during failure: query-only")));
        assert!(rendered["diagnostics"]["hints"]
            .as_array()
            .expect("hints array")
            .iter()
            .any(|item| item
                .as_str()
                .unwrap_or_default()
                .contains("fallback command available: action=hook.status, phase=cleanup, command=trace status, stepId=next-action:hook.status:0")));

        let auto_downgraded_rendered = render_injection_result_json(
            &config,
            42,
            "/tmp/iosrf.sock",
            &plan,
            &environment,
            &doctor,
            &preflight,
            None,
            None,
            None,
            None,
            false,
            None,
            None,
            &[],
            Some(&Error::State(
                "hook-effective-blocked actionKey=hook.install commandGroup=hook-install blockedBy=target commandMode=query-only baseCommandMode=allowed effectiveCommandMode=query-only autoDowngradedToQueryOnly=true autoDowngradeReason=split-loaded-external-backends-without-shared-runtime coexistenceMode=query-only backendPressure=both fallbackActionKey=hook.query fallbackStepId=next-action:hook.query:0 fallbackCommand=objc.classes <filter> fallbackPhase=query; recommendation=split backend downgrade".into(),
            )),
        );
        assert_eq!(
            auto_downgraded_rendered["diagnostics"]["hookBaseCommandMode"],
            "allowed"
        );
        assert_eq!(
            auto_downgraded_rendered["diagnostics"]["hookEffectiveCommandMode"],
            "query-only"
        );
        assert_eq!(
            auto_downgraded_rendered["diagnostics"]["hookAutoDowngradedToQueryOnly"],
            true
        );
        assert_eq!(
            auto_downgraded_rendered["diagnostics"]["hookAutoDowngradeReason"],
            "split-loaded-external-backends-without-shared-runtime"
        );
        assert_eq!(
            auto_downgraded_rendered["diagnostics"]["hook"]["baseCommandMode"],
            "allowed"
        );
        assert_eq!(
            auto_downgraded_rendered["diagnostics"]["hook"]["effectiveCommandMode"],
            "query-only"
        );
        assert_eq!(
            auto_downgraded_rendered["diagnostics"]["hook"]["autoDowngradedToQueryOnly"],
            true
        );
        assert_eq!(
            auto_downgraded_rendered["diagnostics"]["hook"]["autoDowngradeReason"],
            "split-loaded-external-backends-without-shared-runtime"
        );
        assert!(auto_downgraded_rendered["diagnostics"]["hints"]
            .as_array()
            .expect("hints array")
            .iter()
            .any(|item| item
                .as_str()
                .unwrap_or_default()
                .contains("hook command mode adjusted under backend pressure: base=allowed, effective=query-only")));
        assert!(auto_downgraded_rendered["diagnostics"]["hints"]
            .as_array()
            .expect("hints array")
            .iter()
            .any(|item| item
                .as_str()
                .unwrap_or_default()
                .contains("inline hook install path auto-downgraded to query-only: split-loaded-external-backends-without-shared-runtime")));

        let legacy_rendered = render_injection_result_json(
            &config,
            42,
            "/tmp/iosrf.sock",
            &plan,
            &environment,
            &doctor,
            &preflight,
            None,
            None,
            None,
            None,
            false,
            None,
            None,
            &[],
            Some(&Error::State("target hook strategy blocked injection: external backend already loaded in target".into())),
        );
        assert_eq!(legacy_rendered["diagnostics"]["phase"], "hook-policy");
        assert_eq!(legacy_rendered["diagnostics"]["code"], "target-hook-policy-blocked");
        assert_eq!(legacy_rendered["diagnostics"]["hookActionKey"], "unknown");
        assert_eq!(legacy_rendered["diagnostics"]["hookCommandGroup"], "unknown");
        assert_eq!(legacy_rendered["diagnostics"]["hookBlockedBy"], "target");
        assert_eq!(legacy_rendered["diagnostics"]["hookCommandMode"], "unknown");
        assert_eq!(legacy_rendered["diagnostics"]["hookBaseCommandMode"], "unknown");
        assert_eq!(legacy_rendered["diagnostics"]["hookEffectiveCommandMode"], "unknown");
        assert_eq!(legacy_rendered["diagnostics"]["hookAutoDowngradedToQueryOnly"], false);
        assert_eq!(legacy_rendered["diagnostics"]["hookAutoDowngradeReason"], "unknown");
        assert_eq!(
            legacy_rendered["diagnostics"]["hookRecommendation"],
            "external backend already loaded in target"
        );
        assert_eq!(legacy_rendered["diagnostics"]["coexistenceMode"], "unknown");
        assert_eq!(legacy_rendered["diagnostics"]["backendPressure"], "unknown");
        assert_eq!(legacy_rendered["diagnostics"]["fallbackActionKey"], "unknown");
        assert_eq!(legacy_rendered["diagnostics"]["fallbackStepId"], "unknown");
        assert_eq!(legacy_rendered["diagnostics"]["fallbackPhase"], "unknown");
        assert_eq!(legacy_rendered["diagnostics"]["hookFallbackAvailable"], false);
        assert_eq!(legacy_rendered["diagnostics"]["hook"]["actionKey"], "unknown");
        assert_eq!(legacy_rendered["diagnostics"]["hook"]["commandGroup"], "unknown");
        assert_eq!(legacy_rendered["diagnostics"]["hook"]["blockedBy"], "target");
        assert_eq!(legacy_rendered["diagnostics"]["hook"]["commandMode"], "unknown");
        assert_eq!(legacy_rendered["diagnostics"]["hook"]["baseCommandMode"], "unknown");
        assert_eq!(
            legacy_rendered["diagnostics"]["hook"]["effectiveCommandMode"],
            "unknown"
        );
        assert_eq!(
            legacy_rendered["diagnostics"]["hook"]["autoDowngradedToQueryOnly"],
            false
        );
        assert_eq!(
            legacy_rendered["diagnostics"]["hook"]["autoDowngradeReason"],
            "unknown"
        );
        assert_eq!(
            legacy_rendered["diagnostics"]["hook"]["recommendation"],
            "external backend already loaded in target"
        );
        assert_eq!(legacy_rendered["diagnostics"]["hook"]["coexistenceMode"], "unknown");
        assert_eq!(legacy_rendered["diagnostics"]["hook"]["backendPressure"], "unknown");
        assert_eq!(legacy_rendered["diagnostics"]["hook"]["fallbackActionKey"], "unknown");
        assert_eq!(legacy_rendered["diagnostics"]["hook"]["fallbackStepId"], "unknown");
        assert_eq!(legacy_rendered["diagnostics"]["hook"]["fallbackPhase"], "unknown");
        assert_eq!(legacy_rendered["diagnostics"]["hook"]["fallbackAvailable"], false);

        let legacy_both_rendered = render_injection_result_json(
            &config,
            42,
            "/tmp/iosrf.sock",
            &plan,
            &environment,
            &doctor,
            &preflight,
            None,
            None,
            None,
            None,
            false,
            None,
            None,
            &[],
            Some(&Error::State(
                "both hook strategies blocked injection: both sides are in query-only mode".into(),
            )),
        );
        assert_eq!(legacy_both_rendered["diagnostics"]["phase"], "hook-policy");
        assert_eq!(legacy_both_rendered["diagnostics"]["code"], "both-hook-policies-blocked");
        assert_eq!(legacy_both_rendered["diagnostics"]["hookActionKey"], "unknown");
        assert_eq!(legacy_both_rendered["diagnostics"]["hookCommandGroup"], "unknown");
        assert_eq!(legacy_both_rendered["diagnostics"]["hookBlockedBy"], "both");
        assert_eq!(legacy_both_rendered["diagnostics"]["hookCommandMode"], "unknown");
        assert_eq!(
            legacy_both_rendered["diagnostics"]["hookRecommendation"],
            "both sides are in query-only mode"
        );
        assert_eq!(legacy_both_rendered["diagnostics"]["coexistenceMode"], "unknown");
        assert_eq!(legacy_both_rendered["diagnostics"]["backendPressure"], "unknown");
        assert_eq!(legacy_both_rendered["diagnostics"]["fallbackActionKey"], "unknown");
        assert_eq!(legacy_both_rendered["diagnostics"]["fallbackPhase"], "unknown");
        assert_eq!(legacy_both_rendered["diagnostics"]["hookFallbackAvailable"], false);
        assert_eq!(legacy_both_rendered["diagnostics"]["hook"]["actionKey"], "unknown");
        assert_eq!(legacy_both_rendered["diagnostics"]["hook"]["commandGroup"], "unknown");
        assert_eq!(legacy_both_rendered["diagnostics"]["hook"]["blockedBy"], "both");
        assert_eq!(legacy_both_rendered["diagnostics"]["hook"]["commandMode"], "unknown");
        assert_eq!(
            legacy_both_rendered["diagnostics"]["hook"]["recommendation"],
            "both sides are in query-only mode"
        );
        assert_eq!(legacy_both_rendered["diagnostics"]["hook"]["coexistenceMode"], "unknown");
        assert_eq!(legacy_both_rendered["diagnostics"]["hook"]["backendPressure"], "unknown");
        assert_eq!(legacy_both_rendered["diagnostics"]["hook"]["fallbackActionKey"], "unknown");
        assert_eq!(legacy_both_rendered["diagnostics"]["hook"]["fallbackPhase"], "unknown");
        assert_eq!(legacy_both_rendered["diagnostics"]["hook"]["fallbackAvailable"], false);

        let legacy_controller_rendered = render_injection_result_json(
            &config,
            42,
            "/tmp/iosrf.sock",
            &plan,
            &environment,
            &doctor,
            &preflight,
            None,
            None,
            None,
            None,
            false,
            None,
            None,
            &[],
            Some(&Error::State(
                "hook strategy blocked injection: local controller backend mismatch".into(),
            )),
        );
        assert_eq!(legacy_controller_rendered["diagnostics"]["phase"], "hook-policy");
        assert_eq!(
            legacy_controller_rendered["diagnostics"]["code"],
            "controller-hook-policy-blocked"
        );
        assert_eq!(legacy_controller_rendered["diagnostics"]["hookActionKey"], "unknown");
        assert_eq!(legacy_controller_rendered["diagnostics"]["hookCommandGroup"], "unknown");
        assert_eq!(
            legacy_controller_rendered["diagnostics"]["hookBlockedBy"],
            "controller"
        );
        assert_eq!(legacy_controller_rendered["diagnostics"]["hookCommandMode"], "unknown");
        assert_eq!(
            legacy_controller_rendered["diagnostics"]["hookRecommendation"],
            "local controller backend mismatch"
        );
        assert_eq!(legacy_controller_rendered["diagnostics"]["coexistenceMode"], "unknown");
        assert_eq!(legacy_controller_rendered["diagnostics"]["backendPressure"], "unknown");
        assert_eq!(
            legacy_controller_rendered["diagnostics"]["fallbackActionKey"],
            "unknown"
        );
        assert_eq!(legacy_controller_rendered["diagnostics"]["fallbackPhase"], "unknown");
        assert_eq!(
            legacy_controller_rendered["diagnostics"]["hookFallbackAvailable"],
            false
        );
        assert_eq!(legacy_controller_rendered["diagnostics"]["hook"]["actionKey"], "unknown");
        assert_eq!(
            legacy_controller_rendered["diagnostics"]["hook"]["commandGroup"],
            "unknown"
        );
        assert_eq!(
            legacy_controller_rendered["diagnostics"]["hook"]["blockedBy"],
            "controller"
        );
        assert_eq!(
            legacy_controller_rendered["diagnostics"]["hook"]["commandMode"],
            "unknown"
        );
        assert_eq!(
            legacy_controller_rendered["diagnostics"]["hook"]["recommendation"],
            "local controller backend mismatch"
        );
        assert_eq!(
            legacy_controller_rendered["diagnostics"]["hook"]["coexistenceMode"],
            "unknown"
        );
        assert_eq!(
            legacy_controller_rendered["diagnostics"]["hook"]["backendPressure"],
            "unknown"
        );
        assert_eq!(
            legacy_controller_rendered["diagnostics"]["hook"]["fallbackActionKey"],
            "unknown"
        );
        assert_eq!(
            legacy_controller_rendered["diagnostics"]["hook"]["fallbackPhase"],
            "unknown"
        );
        assert_eq!(
            legacy_controller_rendered["diagnostics"]["hook"]["fallbackAvailable"],
            false
        );

        let missing_blocked_by_rendered = render_injection_result_json(
            &config,
            42,
            "/tmp/iosrf.sock",
            &plan,
            &environment,
            &doctor,
            &preflight,
            None,
            None,
            None,
            None,
            false,
            None,
            None,
            &[],
            Some(&Error::State(
                "hook-effective-blocked actionKey=hook.install commandGroup=hook-install commandMode=query-only; recommendation=missing blockedBy field".into(),
            )),
        );
        assert_eq!(missing_blocked_by_rendered["diagnostics"]["code"], "hook-effective-blocked");
        assert_eq!(missing_blocked_by_rendered["diagnostics"]["hookBlockedBy"], "unknown");
        assert_eq!(missing_blocked_by_rendered["diagnostics"]["hook"]["blockedBy"], "unknown");

        let invalid_blocked_by_rendered = render_injection_result_json(
            &config,
            42,
            "/tmp/iosrf.sock",
            &plan,
            &environment,
            &doctor,
            &preflight,
            None,
            None,
            None,
            None,
            false,
            None,
            None,
            &[],
            Some(&Error::State(
                "hook-effective-blocked actionKey=hook.install commandGroup=hook-install blockedBy=garbage commandMode=query-only; recommendation=invalid blockedBy".into(),
            )),
        );
        assert_eq!(invalid_blocked_by_rendered["diagnostics"]["code"], "hook-effective-blocked");
        assert_eq!(invalid_blocked_by_rendered["diagnostics"]["hookBlockedBy"], "unknown");
        assert_eq!(invalid_blocked_by_rendered["diagnostics"]["hook"]["blockedBy"], "unknown");

        let invalid_command_mode_rendered = render_injection_result_json(
            &config,
            42,
            "/tmp/iosrf.sock",
            &plan,
            &environment,
            &doctor,
            &preflight,
            None,
            None,
            None,
            None,
            false,
            None,
            None,
            &[],
            Some(&Error::State(
                "hook-effective-blocked actionKey=hook.install commandGroup=hook-install blockedBy=target commandMode=garbage coexistenceMode=weird backendPressure=strange fallbackActionKey=hook.status fallbackCommand=trace status fallbackPhase=oops; recommendation=invalid commandMode".into(),
            )),
        );
        assert_eq!(invalid_command_mode_rendered["diagnostics"]["code"], "target-hook-policy-blocked");
        assert_eq!(invalid_command_mode_rendered["diagnostics"]["hookBlockedBy"], "target");
        assert_eq!(invalid_command_mode_rendered["diagnostics"]["hookCommandMode"], "unknown");
        assert_eq!(invalid_command_mode_rendered["diagnostics"]["coexistenceMode"], "unknown");
        assert_eq!(invalid_command_mode_rendered["diagnostics"]["backendPressure"], "unknown");
        assert_eq!(invalid_command_mode_rendered["diagnostics"]["fallbackPhase"], "unknown");
        assert_eq!(invalid_command_mode_rendered["diagnostics"]["hookFallbackAvailable"], false);
        assert_eq!(invalid_command_mode_rendered["diagnostics"]["hook"]["blockedBy"], "target");
        assert_eq!(invalid_command_mode_rendered["diagnostics"]["hook"]["commandMode"], "unknown");
        assert_eq!(invalid_command_mode_rendered["diagnostics"]["hook"]["coexistenceMode"], "unknown");
        assert_eq!(invalid_command_mode_rendered["diagnostics"]["hook"]["backendPressure"], "unknown");
        assert_eq!(invalid_command_mode_rendered["diagnostics"]["hook"]["fallbackPhase"], "unknown");
        assert_eq!(invalid_command_mode_rendered["diagnostics"]["hook"]["fallbackAvailable"], false);

        let invalid_action_fields_rendered = render_injection_result_json(
            &config,
            42,
            "/tmp/iosrf.sock",
            &plan,
            &environment,
            &doctor,
            &preflight,
            None,
            None,
            None,
            None,
            false,
            None,
            None,
            &[],
            Some(&Error::State(
                "hook-effective-blocked actionKey=badkey commandGroup=weird blockedBy=target commandMode=query-only fallbackActionKey=oops fallbackCommand=trace status fallbackPhase=query; recommendation=invalid action metadata".into(),
            )),
        );
        assert_eq!(invalid_action_fields_rendered["diagnostics"]["code"], "target-hook-policy-blocked");
        assert_eq!(invalid_action_fields_rendered["diagnostics"]["hookActionKey"], "unknown");
        assert_eq!(invalid_action_fields_rendered["diagnostics"]["hookCommandGroup"], "unknown");
        assert_eq!(invalid_action_fields_rendered["diagnostics"]["fallbackActionKey"], "unknown");
        assert_eq!(invalid_action_fields_rendered["diagnostics"]["hookFallbackAvailable"], false);
        assert_eq!(invalid_action_fields_rendered["diagnostics"]["hook"]["actionKey"], "unknown");
        assert_eq!(invalid_action_fields_rendered["diagnostics"]["hook"]["commandGroup"], "unknown");
        assert_eq!(invalid_action_fields_rendered["diagnostics"]["hook"]["fallbackActionKey"], "unknown");
        assert_eq!(invalid_action_fields_rendered["diagnostics"]["hook"]["fallbackAvailable"], false);
    }

    #[test]
    fn render_injection_result_json_classifies_bootstrap_failure_from_trace() {
        let config = ControllerConfig {
            mode: InjectionMode::Attach,
            pid: Some(42),
            bundle_id: None,
            spawn_command: None,
            command: None,
            command_json: false,
            list_images_json: false,
            preflight_only: false,
            preflight_json: false,
            inject_json: true,
            agent_path: LEGACY_AGENT_PATH_ROOTFUL.into(),
            entry_symbol: "ios_agent_entry".into(),
            script_path: Some("/tmp/bootstrap.js".into()),
            socket_path: None,
            connect_timeout_secs: 15,
        };

        let environment = InjectionEnvironmentReport {
            dry_run: false,
            bootstrap_wait_ms: Some(1000),
            hook_policy: HookPolicy::Warn,
            hook_strategy: HookStrategyDecision {
                policy: HookPolicy::Warn,
                strategy: "internal-inline".into(),
                allowed: true,
                inline_hooks_allowed: true,
                reason: None,
            },
            hook_environment: HookEnvironmentReport {
                active_backend: None,
                backends: vec![],
                warnings: vec![],
            },
        };
        let plan = MachInjector
            .plan(&InjectionTarget {
                pid: 42,
                dylib_path: DEFAULT_AGENT_PATH.into(),
                entry_symbol: "ios_agent_entry".into(),
                socket_path: "/tmp/iosrf.sock".into(),
            })
            .expect("plan");
        let preflight = InjectionTargetPreflightReport {
            main_image: None,
            target_images: vec![],
            target_image_count: 0,
            target_uses_arm64e: Some(true),
            thread_bootstrap_kind: ThreadBootstrapKind::PthreadCreateFromMachThread,
            thread_bootstrap_label: "pthread_create_from_mach_thread".into(),
            thread_bootstrap_address: 0,
            thread_bootstrap_raw_address: 0,
            thread_bootstrap_canonicalized: false,
            target_hook_environment: HookEnvironmentReport {
                active_backend: None,
                backends: vec![],
                warnings: vec![],
            },
            target_hook_strategy: HookStrategyDecision {
                policy: HookPolicy::Warn,
                strategy: "internal-inline".into(),
                allowed: true,
                inline_hooks_allowed: true,
                reason: None,
            },
            resolved_loader_symbols: vec![],
        };
        let trace = InjectionTrace {
            payload_address: 0x2000,
            payload_size: 0x1000,
            payload_allocated_size: 0x2000,
            data_address: 0x2800,
            data_size: 0x400,
            data_allocated_size: 0x1000,
            stack_address: 0x3000,
            stack_size: 0x4000,
            target_uses_arm64e: Some(true),
            code_protection: RemoteProtectionOutcome::SetMaximumAndCurrent,
            data_protection: RemoteProtectionOutcome::CurrentOnlyFallback,
            thread_bootstrap_kind: ThreadBootstrapKind::PthreadCreateFromMachThread,
            thread_bootstrap_label: "pthread_create_from_mach_thread".into(),
            thread_plan: ThreadCreatePlan {
                flavor: 6,
                count: 68,
                state: Arm64ThreadState {
                    x: [0; 29],
                    fp: 0,
                    lr: 0,
                    sp: 0x7000,
                    pc: 0x5000,
                    cpsr: 0,
                    pad: 0,
                },
            },
            thread_port: Some(77),
            thread_termination: RemoteThreadTerminationOutcome::Terminated,
            thread_port_deallocated: true,
            resources_persist: false,
            bootstrap_report: Some(BootstrapResultReport {
                status: BootstrapStatus::ConnectFailed,
                status_raw: 5,
                dylib_handle: 0x1234,
                entry_address: 0x5678,
                socket_fd: 9,
                entry_return: -1,
            }),
            bootstrap_timed_out: true,
        };

        let doctor = analyze_doctor_report(&config, 42, Path::new("/tmp/iosrf.sock"), &environment, &preflight);
        let rendered = render_injection_result_json(
            &config,
            42,
            "/tmp/iosrf.sock",
            &plan,
            &environment,
            &doctor,
            &preflight,
            Some(&trace),
            None,
            None,
            None,
            false,
            None,
            None,
            &[],
            Some(&Error::State("remote bootstrap failed".into())),
        );

        assert_eq!(rendered["diagnostics"]["phase"], "remote-bootstrap");
        assert_eq!(rendered["diagnostics"]["code"], "connect-failed");
        assert!(rendered["diagnostics"]["hook"].is_null());
        assert_eq!(rendered["diagnostics"]["bootstrapStatus"], "connect-failed");
        assert_eq!(rendered["diagnostics"]["handshakeStage"], "awaiting-hello");
        assert_eq!(rendered["diagnostics"]["failedStep"], "hello");
        assert!(rendered["diagnostics"]["hints"]
            .as_array()
            .expect("hints array")
            .iter()
            .any(|item| item
                .as_str()
                .unwrap_or_default()
                .contains("connect failed from the target back to the controller socket")));
    }

    #[test]
    fn render_injection_result_json_classifies_jsinit_failure_from_stage_context() {
        let config = ControllerConfig {
            mode: InjectionMode::Attach,
            pid: Some(42),
            bundle_id: None,
            spawn_command: None,
            command: None,
            command_json: false,
            list_images_json: false,
            preflight_only: false,
            preflight_json: false,
            inject_json: true,
            agent_path: LEGACY_AGENT_PATH_ROOTFUL.into(),
            entry_symbol: "ios_agent_entry".into(),
            script_path: Some("/tmp/bootstrap.js".into()),
            socket_path: None,
            connect_timeout_secs: 15,
        };

        let environment = InjectionEnvironmentReport {
            dry_run: false,
            bootstrap_wait_ms: Some(1000),
            hook_policy: HookPolicy::Warn,
            hook_strategy: HookStrategyDecision {
                policy: HookPolicy::Warn,
                strategy: "internal-inline".into(),
                allowed: true,
                inline_hooks_allowed: true,
                reason: None,
            },
            hook_environment: HookEnvironmentReport {
                active_backend: None,
                backends: vec![],
                warnings: vec![],
            },
        };
        let plan = MachInjector
            .plan(&InjectionTarget {
                pid: 42,
                dylib_path: DEFAULT_AGENT_PATH.into(),
                entry_symbol: "ios_agent_entry".into(),
                socket_path: "/tmp/iosrf.sock".into(),
            })
            .expect("plan");
        let preflight = InjectionTargetPreflightReport {
            main_image: None,
            target_images: vec![],
            target_image_count: 0,
            target_uses_arm64e: Some(false),
            thread_bootstrap_kind: ThreadBootstrapKind::PthreadCreateFromMachThread,
            thread_bootstrap_label: "pthread_create_from_mach_thread".into(),
            thread_bootstrap_address: 0,
            thread_bootstrap_raw_address: 0,
            thread_bootstrap_canonicalized: false,
            target_hook_environment: HookEnvironmentReport {
                active_backend: None,
                backends: vec![],
                warnings: vec![],
            },
            target_hook_strategy: HookStrategyDecision {
                policy: HookPolicy::Warn,
                strategy: "internal-inline".into(),
                allowed: true,
                inline_hooks_allowed: true,
                reason: None,
            },
            resolved_loader_symbols: vec![],
        };
        let trace = InjectionTrace {
            payload_address: 0x2000,
            payload_size: 0x1000,
            payload_allocated_size: 0x2000,
            data_address: 0x2800,
            data_size: 0x400,
            data_allocated_size: 0x1000,
            stack_address: 0x3000,
            stack_size: 0x4000,
            target_uses_arm64e: Some(false),
            code_protection: RemoteProtectionOutcome::SetMaximumAndCurrent,
            data_protection: RemoteProtectionOutcome::CurrentOnlyFallback,
            thread_bootstrap_kind: ThreadBootstrapKind::PthreadCreateFromMachThread,
            thread_bootstrap_label: "pthread_create_from_mach_thread".into(),
            thread_plan: ThreadCreatePlan {
                flavor: 6,
                count: 68,
                state: Arm64ThreadState {
                    x: [0; 29],
                    fp: 0,
                    lr: 0,
                    sp: 0x7000,
                    pc: 0x5000,
                    cpsr: 0,
                    pad: 0,
                },
            },
            thread_port: Some(77),
            thread_termination: RemoteThreadTerminationOutcome::NotAttempted,
            thread_port_deallocated: true,
            resources_persist: true,
            bootstrap_report: Some(BootstrapResultReport {
                status: BootstrapStatus::AgentRunning,
                status_raw: 6,
                dylib_handle: 0x1234,
                entry_address: 0x5678,
                socket_fd: 9,
                entry_return: 0,
            }),
            bootstrap_timed_out: false,
        };
        let hello = Hello {
            platform: "ios".into(),
            arch: "aarch64".into(),
            runtime: "quickjs-runtime".into(),
            transport: "unix-fd".into(),
        };

        let doctor = analyze_doctor_report(&config, 42, Path::new("/tmp/iosrf.sock"), &environment, &preflight);
        let rendered = render_injection_result_json(
            &config,
            42,
            "/tmp/iosrf.sock",
            &plan,
            &environment,
            &doctor,
            &preflight,
            Some(&trace),
            Some(&hello),
            Some("pong"),
            Some("active=<none>"),
            true,
            None,
            None,
            &[],
            Some(&Error::State(
                "agent jsinit failed: agent command failed: reference error".into(),
            )),
        );

        assert_eq!(rendered["handshake"]["stage"], "awaiting-jsinit");
        assert_eq!(rendered["handshake"]["steps"]["hello"], "succeeded");
        assert_eq!(rendered["handshake"]["steps"]["ping"], "succeeded");
        assert_eq!(rendered["handshake"]["steps"]["hookEnvironment"], "succeeded");
        assert_eq!(rendered["handshake"]["steps"]["jsInit"], "pending");
        assert_eq!(rendered["handshake"]["steps"]["loadJs"], "pending");
        assert_eq!(rendered["diagnostics"]["phase"], "script");
        assert_eq!(rendered["diagnostics"]["code"], "jsinit");
        assert!(rendered["diagnostics"]["hook"].is_null());
        assert_eq!(rendered["diagnostics"]["handshakeStage"], "awaiting-jsinit");
        assert_eq!(rendered["diagnostics"]["failedStep"], "jsInit");
        assert_eq!(
            rendered["handshake"]["errors"]["jsInit"],
            "agent command failed: reference error"
        );
        assert!(rendered["handshake"]["errors"]["loadJs"].is_null());
    }

    #[test]
    fn build_hfl_spec_contains_target_installation_flow() {
        let spec = build_hfl_spec(&HflCommand::Install {
            module_name: "libobjc.A.dylib".into(),
            offset: 0x1234,
        });
        assert_eq!(
            spec,
            json!({
                "kind": "hfl.install",
                "moduleName": "libobjc.A.dylib",
                "offsetHex": "0x1234",
            })
        );

        let stop_spec = build_hfl_spec(&HflCommand::StopAll);
        assert_eq!(stop_spec, json!({ "kind": "hfl.stop" }));
        let targeted_stop_spec = build_hfl_spec(&HflCommand::Stop {
            module_name: "libobjc.A.dylib".into(),
            offset: 0x1234,
        });
        assert_eq!(
            targeted_stop_spec,
            json!({
                "kind": "hfl.stop",
                "moduleName": "libobjc.A.dylib",
                "offsetHex": "0x1234",
            })
        );
        let status_spec = build_hfl_spec(&HflCommand::Status);
        assert_eq!(status_spec, json!({ "kind": "hfl.status" }));
    }

    #[test]
    fn parse_trace_without_filter() {
        assert_eq!(
            parse_trace_command("trace").expect("parse trace"),
            TraceCommand::InstallObjc { filter: None }
        );
    }

    #[test]
    fn parse_trace_with_filter() {
        assert_eq!(
            parse_trace_command("trace viewDidLoad").expect("parse trace"),
            TraceCommand::InstallObjc {
                filter: Some("viewDidLoad".into())
            }
        );
    }

    #[test]
    fn parse_trace_native_symbol() {
        assert_eq!(
            parse_trace_command("trace native malloc").expect("parse trace"),
            TraceCommand::InstallNative {
                target: NativeHookTarget::Export {
                    module_name: None,
                    symbol_name: "malloc".into(),
                    log_template: None,
                }
            }
        );
    }

    #[test]
    fn parse_trace_native_module_symbol() {
        assert_eq!(
            parse_trace_command("trace native libsystem_kernel.dylib open").expect("parse trace"),
            TraceCommand::InstallNative {
                target: NativeHookTarget::Export {
                    module_name: Some("libsystem_kernel.dylib".into()),
                    symbol_name: "open".into(),
                    log_template: None,
                }
            }
        );
    }

    #[test]
    fn parse_trace_native_symbol_with_template() {
        assert_eq!(
            parse_trace_command("trace native open -- path:cstr flags:openflags mode:mode ret:fd")
                .expect("parse trace"),
            TraceCommand::InstallNative {
                target: NativeHookTarget::Export {
                    module_name: None,
                    symbol_name: "open".into(),
                    log_template: Some(NativeLogTemplate {
                        arguments: vec![
                            NativeLogArgument {
                                label: "path".into(),
                                kind: NativeValueFormat::CString,
                            },
                            NativeLogArgument {
                                label: "flags".into(),
                                kind: NativeValueFormat::OpenFlags,
                            },
                            NativeLogArgument {
                                label: "mode".into(),
                                kind: NativeValueFormat::Mode,
                            },
                        ],
                        return_value: Some(NativeLogReturn {
                            label: "result".into(),
                            kind: NativeValueFormat::Fd,
                        }),
                    }),
                }
            }
        );
    }

    #[test]
    fn parse_trace_addr() {
        assert_eq!(
            parse_trace_command("trace addr 0x1234").expect("parse trace"),
            TraceCommand::InstallNative {
                target: NativeHookTarget::Address {
                    address: 0x1234,
                    log_template: None,
                }
            }
        );
    }

    #[test]
    fn parse_trace_addr_with_template() {
        assert_eq!(
            parse_trace_command("trace addr 0x1234 -- cstr hex ret:ptr").expect("parse trace"),
            TraceCommand::InstallNative {
                target: NativeHookTarget::Address {
                    address: 0x1234,
                    log_template: Some(NativeLogTemplate {
                        arguments: vec![
                            NativeLogArgument {
                                label: "x0".into(),
                                kind: NativeValueFormat::CString,
                            },
                            NativeLogArgument {
                                label: "x1".into(),
                                kind: NativeValueFormat::Hex,
                            },
                        ],
                        return_value: Some(NativeLogReturn {
                            label: "result".into(),
                            kind: NativeValueFormat::Ptr,
                        }),
                    }),
                }
            }
        );
    }

    #[test]
    fn parse_trace_stop() {
        assert_eq!(
            parse_trace_command("trace stop").expect("parse trace"),
            TraceCommand::StopAll
        );
    }

    #[test]
    fn parse_trace_targeted_stop_native() {
        assert_eq!(
            parse_trace_command("trace stop native libsystem_kernel.dylib open").expect("parse trace"),
            TraceCommand::StopNative {
                target: NativeHookTarget::Export {
                    module_name: Some("libsystem_kernel.dylib".into()),
                    symbol_name: "open".into(),
                    log_template: None,
                }
            }
        );
    }

    #[test]
    fn parse_trace_targeted_stop_filter() {
        assert_eq!(
            parse_trace_command("trace stop UIViewController").expect("parse trace"),
            TraceCommand::StopObjc {
                filter: Some("UIViewController".into()),
            }
        );
    }

    #[test]
    fn parse_trace_status() {
        assert_eq!(
            parse_trace_command("trace status").expect("parse trace"),
            TraceCommand::Status
        );
    }

    #[test]
    fn build_trace_spec_contains_objc_msgsend_flow() {
        let spec = build_trace_spec(&TraceCommand::InstallObjc {
            filter: Some("viewDidLoad".into()),
        });
        assert_eq!(
            spec,
            json!({
                "kind": "objc.trace.install",
                "filter": "viewDidLoad",
            })
        );
        let status_spec = build_trace_spec(&TraceCommand::Status);
        assert_eq!(status_spec, json!({ "kind": "trace.status" }));
        let stop_spec = build_trace_spec(&TraceCommand::StopObjc {
            filter: Some("viewDidLoad".into()),
        });
        assert_eq!(
            stop_spec,
            json!({
                "kind": "trace.stop",
                "target": null,
                "filter": "viewDidLoad",
            })
        );
    }

    #[test]
    fn build_trace_spec_contains_native_resolution_flow() {
        let spec = build_trace_spec(&TraceCommand::InstallNative {
            target: NativeHookTarget::Export {
                module_name: Some("libsystem_kernel.dylib".into()),
                symbol_name: "open".into(),
                log_template: None,
            },
        });
        assert_eq!(
            spec,
            json!({
                "kind": "native.trace.install",
                "target": {
                    "kind": "export",
                    "moduleName": "libsystem_kernel.dylib",
                    "symbolName": "open",
                    "templateArgs": null,
                    "templateRet": null,
                }
            })
        );
        let stop_spec = build_trace_spec(&TraceCommand::StopNative {
            target: NativeHookTarget::Export {
                module_name: Some("libsystem_kernel.dylib".into()),
                symbol_name: "open".into(),
                log_template: None,
            },
        });
        assert_eq!(
            stop_spec,
            json!({
                "kind": "trace.stop",
                "target": {
                    "kind": "export",
                    "moduleName": "libsystem_kernel.dylib",
                    "symbolName": "open",
                    "templateArgs": null,
                    "templateRet": null,
                },
                "filter": null,
            })
        );
    }

    #[test]
    fn build_trace_spec_contains_custom_template_flow() {
        let spec = build_trace_spec(&TraceCommand::InstallNative {
            target: NativeHookTarget::Address {
                address: 0x1234,
                log_template: Some(NativeLogTemplate {
                    arguments: vec![
                        NativeLogArgument {
                            label: "path".into(),
                            kind: NativeValueFormat::CString,
                        },
                        NativeLogArgument {
                            label: "flags".into(),
                            kind: NativeValueFormat::OpenFlags,
                        },
                    ],
                    return_value: Some(NativeLogReturn {
                        label: "fd".into(),
                        kind: NativeValueFormat::Fd,
                    }),
                }),
            },
        });
        assert_eq!(
            spec,
            json!({
                "kind": "native.trace.install",
                "target": {
                    "kind": "address",
                    "address": "0x1234",
                    "templateArgs": [
                        { "label": "path", "kind": "cstr" },
                        { "label": "flags", "kind": "openflags" }
                    ],
                    "templateRet": { "label": "fd", "kind": "fd" },
                }
            })
        );
    }

    #[test]
    fn parse_stalker_without_filter() {
        assert_eq!(
            parse_stalker_command("stalker").expect("parse stalker"),
            StalkerCommand::InstallObjc { filter: None }
        );
    }

    #[test]
    fn parse_stalker_with_filter() {
        assert_eq!(
            parse_stalker_command("stalker UITableView").expect("parse stalker"),
            StalkerCommand::InstallObjc {
                filter: Some("UITableView".into())
            }
        );
    }

    #[test]
    fn parse_stalker_native_symbol() {
        assert_eq!(
            parse_stalker_command("stalker native malloc").expect("parse stalker"),
            StalkerCommand::InstallNative {
                target: NativeHookTarget::Export {
                    module_name: None,
                    symbol_name: "malloc".into(),
                    log_template: None,
                }
            }
        );
    }

    #[test]
    fn parse_stalker_addr() {
        assert_eq!(
            parse_stalker_command("stalker addr 0x1234").expect("parse stalker"),
            StalkerCommand::InstallNative {
                target: NativeHookTarget::Address {
                    address: 0x1234,
                    log_template: None,
                }
            }
        );
    }

    #[test]
    fn parse_stalker_native_symbol_with_template() {
        assert_eq!(
            parse_stalker_command("stalker native read -- fd:fd buf:ptr count:size ret:ssize").expect("parse stalker"),
            StalkerCommand::InstallNative {
                target: NativeHookTarget::Export {
                    module_name: None,
                    symbol_name: "read".into(),
                    log_template: Some(NativeLogTemplate {
                        arguments: vec![
                            NativeLogArgument {
                                label: "fd".into(),
                                kind: NativeValueFormat::Fd,
                            },
                            NativeLogArgument {
                                label: "buf".into(),
                                kind: NativeValueFormat::Ptr,
                            },
                            NativeLogArgument {
                                label: "count".into(),
                                kind: NativeValueFormat::Size,
                            },
                        ],
                        return_value: Some(NativeLogReturn {
                            label: "result".into(),
                            kind: NativeValueFormat::SSize,
                        }),
                    }),
                }
            }
        );
    }

    #[test]
    fn parse_stalker_stop() {
        assert_eq!(
            parse_stalker_command("stalker stop").expect("parse stalker"),
            StalkerCommand::StopAll
        );
    }

    #[test]
    fn parse_stalker_targeted_stop_native() {
        assert_eq!(
            parse_stalker_command("stalker stop addr 0x1234").expect("parse stalker"),
            StalkerCommand::StopNative {
                target: NativeHookTarget::Address {
                    address: 0x1234,
                    log_template: None,
                }
            }
        );
    }

    #[test]
    fn parse_stalker_targeted_stop_filter() {
        assert_eq!(
            parse_stalker_command("stalker stop UITableView").expect("parse stalker"),
            StalkerCommand::StopObjc {
                filter: Some("UITableView".into()),
            }
        );
    }

    #[test]
    fn parse_stalker_status() {
        assert_eq!(
            parse_stalker_command("stalker status").expect("parse stalker"),
            StalkerCommand::Status
        );
    }

    #[test]
    fn build_stalker_spec_contains_message_flow() {
        let spec = build_stalker_spec(&StalkerCommand::InstallObjc {
            filter: Some("viewDidLoad".into()),
        });
        assert_eq!(
            spec,
            json!({
                "kind": "objc.stalker.install",
                "filter": "viewDidLoad",
            })
        );
        let status_spec = build_stalker_spec(&StalkerCommand::Status);
        assert_eq!(status_spec, json!({ "kind": "stalker.status" }));
        let stop_spec = build_stalker_spec(&StalkerCommand::StopObjc {
            filter: Some("viewDidLoad".into()),
        });
        assert_eq!(
            stop_spec,
            json!({
                "kind": "stalker.stop",
                "target": null,
                "filter": "viewDidLoad",
            })
        );
    }

    #[test]
    fn build_stalker_spec_contains_native_resolution_flow() {
        let spec = build_stalker_spec(&StalkerCommand::InstallNative {
            target: NativeHookTarget::Address {
                address: 0x1234,
                log_template: None,
            },
        });
        assert_eq!(
            spec,
            json!({
                "kind": "native.stalker.install",
                "target": {
                    "kind": "address",
                    "address": "0x1234",
                    "templateArgs": null,
                    "templateRet": null,
                }
            })
        );
        let stop_spec = build_stalker_spec(&StalkerCommand::StopNative {
            target: NativeHookTarget::Address {
                address: 0x1234,
                log_template: None,
            },
        });
        assert_eq!(
            stop_spec,
            json!({
                "kind": "stalker.stop",
                "target": {
                    "kind": "address",
                    "address": "0x1234",
                    "templateArgs": null,
                    "templateRet": null,
                },
                "filter": null,
            })
        );
    }

    #[test]
    fn parse_jhook_defaults_to_instance_method() {
        assert_eq!(
            parse_jhook_command("jhook NSObject description").expect("parse jhook"),
            ObjcHookCommand::Install(super::ObjcHookSpec {
                class_name: "NSObject".into(),
                selector_name: "description".into(),
                is_class_method: false,
            })
        );
    }

    #[test]
    fn parse_jhook_accepts_meta_mode() {
        assert_eq!(
            parse_jhook_command("jhook NSString string meta").expect("parse jhook"),
            ObjcHookCommand::Install(super::ObjcHookSpec {
                class_name: "NSString".into(),
                selector_name: "string".into(),
                is_class_method: true,
            })
        );
    }

    #[test]
    fn parse_jhook_stop() {
        assert_eq!(
            parse_jhook_command("jhook stop").expect("parse jhook"),
            ObjcHookCommand::StopAll
        );
    }

    #[test]
    fn parse_jhook_targeted_stop() {
        assert_eq!(
            parse_jhook_command("jhook stop NSString string meta").expect("parse jhook"),
            ObjcHookCommand::Stop(super::ObjcHookSpec {
                class_name: "NSString".into(),
                selector_name: "string".into(),
                is_class_method: true,
            })
        );
    }

    #[test]
    fn parse_jhook_status() {
        assert_eq!(
            parse_jhook_command("jhook status").expect("parse jhook"),
            ObjcHookCommand::Status
        );
    }

    #[test]
    fn build_jhook_spec_contains_objc_hook_flow() {
        let command = parse_jhook_command("jhook UIViewController viewDidLoad").expect("parse jhook");
        let spec = build_jhook_spec(&command);
        assert_eq!(
            spec,
            json!({
                "kind": "objc.hook.install",
                "className": "UIViewController",
                "selectorName": "viewDidLoad",
                "isClassMethod": false,
            })
        );

        let stop_spec = build_jhook_spec(&ObjcHookCommand::StopAll);
        assert_eq!(stop_spec, json!({ "kind": "objc.hook.stop" }));
        let targeted_stop_spec = build_jhook_spec(&ObjcHookCommand::Stop(super::ObjcHookSpec {
            class_name: "UIViewController".into(),
            selector_name: "viewDidLoad".into(),
            is_class_method: false,
        }));
        assert_eq!(
            targeted_stop_spec,
            json!({
                "kind": "objc.hook.stop",
                "className": "UIViewController",
                "selectorName": "viewDidLoad",
                "isClassMethod": false,
            })
        );
        let status_spec = build_jhook_spec(&ObjcHookCommand::Status);
        assert_eq!(status_spec, json!({ "kind": "objc.hook.status" }));
    }

    #[test]
    fn parse_shook_defaults_to_install() {
        assert_eq!(
            parse_shook_command("shook ViewController viewDidLoad").expect("parse shook"),
            SwiftHookCommand::Install {
                module_name: None,
                type_name: "ViewController".into(),
                method_query: "viewDidLoad".into(),
            }
        );
    }

    #[test]
    fn parse_shook_accepts_module_separator() {
        assert_eq!(
            parse_shook_command("shook MyAppBinary -- ViewController viewDidLoad").expect("parse shook"),
            SwiftHookCommand::Install {
                module_name: Some("MyAppBinary".into()),
                type_name: "ViewController".into(),
                method_query: "viewDidLoad".into(),
            }
        );
    }

    #[test]
    fn parse_shook_stop() {
        assert_eq!(
            parse_shook_command("shook stop").expect("parse shook"),
            SwiftHookCommand::StopAll
        );
    }

    #[test]
    fn parse_shook_targeted_stop() {
        assert_eq!(
            parse_shook_command("shook stop MyAppBinary -- ViewController viewDidLoad").expect("parse shook"),
            SwiftHookCommand::Stop {
                module_name: Some("MyAppBinary".into()),
                type_name: "ViewController".into(),
                method_query: "viewDidLoad".into(),
            }
        );
    }

    #[test]
    fn parse_shook_status() {
        assert_eq!(
            parse_shook_command("shook status").expect("parse shook"),
            SwiftHookCommand::Status
        );
    }

    #[test]
    fn build_shook_spec_contains_swift_hook_flow() {
        let spec = build_shook_spec(&SwiftHookCommand::Install {
            module_name: Some("MyAppBinary".into()),
            type_name: "ViewController".into(),
            method_query: "viewDidLoad".into(),
        });
        assert_eq!(
            spec,
            json!({
                "kind": "swift.hook.install",
                "moduleName": "MyAppBinary",
                "typeName": "ViewController",
                "methodQuery": "viewDidLoad",
            })
        );

        let stop_spec = build_shook_spec(&SwiftHookCommand::StopAll);
        assert_eq!(stop_spec, json!({ "kind": "swift.hook.stop" }));
        let targeted_stop_spec = build_shook_spec(&SwiftHookCommand::Stop {
            module_name: Some("MyAppBinary".into()),
            type_name: "ViewController".into(),
            method_query: "viewDidLoad".into(),
        });
        assert_eq!(
            targeted_stop_spec,
            json!({
                "kind": "swift.hook.stop",
                "moduleName": "MyAppBinary",
                "typeName": "ViewController",
                "methodQuery": "viewDidLoad",
            })
        );
        let status_spec = build_shook_spec(&SwiftHookCommand::Status);
        assert_eq!(status_spec, json!({ "kind": "swift.hook.status" }));
    }

    #[test]
    fn hook_environment_notice_is_suppressed_when_nothing_is_detected() {
        assert!(!hook_environment_requires_notice("active=<none>"));
        assert!(!hook_environment_requires_notice(""));
        assert!(!hook_environment_requires_notice(
            "active=<none>\nconflict_state=none\nrisk_level=normal\npolicy=warn\nstrategy=internal-inline\ncommand_mode=allowed\nallowed=true\ninline_hooks_allowed=true\nbootstrap_injection_allowed=true\nquery_commands_allowed=true\nhook_install_commands_allowed=true\nhook_status_commands_allowed=true\nhook_stop_commands_allowed=true\ncoexistence_layer_available=false\nloaded_backend_count=0\nfilesystem_only_backend_count=0\nloaded_image_count=0\nfilesystem_path_count=0"
        ));
    }

    #[test]
    fn hook_environment_notice_is_printed_when_backend_or_warning_exists() {
        assert!(hook_environment_requires_notice(
            "active=ellekit\nbackend ellekit ElleKit\n  loaded /usr/lib/libellekit.dylib"
        ));
        assert!(hook_environment_requires_notice(
            "active=<none>\nbackend libhooker libhooker\n  fs /usr/lib/libhooker.dylib"
        ));
        assert!(hook_environment_requires_notice(
            "active=<none>\nwarning hook ecosystem files are present on disk"
        ));
    }

    #[test]
    fn render_injection_environment_contains_strategy_and_backends() {
        let lines = render_injection_environment(&InjectionEnvironmentReport {
            dry_run: true,
            bootstrap_wait_ms: Some(1500),
            hook_policy: HookPolicy::Warn,
            hook_strategy: HookStrategyDecision {
                policy: HookPolicy::Warn,
                strategy: "internal-inline-risky".into(),
                allowed: true,
                inline_hooks_allowed: true,
                reason: Some("external hook backend is already loaded".into()),
            },
            hook_environment: HookEnvironmentReport {
                active_backend: Some("ellekit".into()),
                backends: vec![HookBackendInfo {
                    id: "ellekit".into(),
                    display_name: "ElleKit".into(),
                    loaded_images: vec!["/usr/lib/libellekit.dylib".into()],
                    filesystem_paths: vec!["/usr/lib/libellekit.dylib".into()],
                }],
                warnings: vec!["multiple hook ecosystems are loaded".into()],
            },
        });

        assert!(lines[0].contains("dry_run=true"));
        assert!(lines[0].contains("bootstrap_wait=1500ms"));
        assert!(lines[0].contains("strategy=internal-inline-risky"));
        assert!(lines[0].contains("command_mode=allowed"));
        assert!(lines[0].contains("inline_hooks_allowed=true"));
        assert!(lines[0].contains("query_commands_allowed=true"));
        assert!(lines[0].contains("hook_install_commands_allowed=true"));
        assert!(lines
            .iter()
            .any(|line| line.contains("hook strategy reason: external hook backend is already loaded")));
        assert!(lines.iter().any(|line| line.contains("hook backends: active=ellekit conflict_state=external-loaded")));
        assert!(lines.iter().any(|line| line.contains("ElleKit")));
        assert!(lines
            .iter()
            .any(|line| line.contains("hook warning: multiple hook ecosystems are loaded")));
        assert!(lines.iter().any(|line| line.contains("hook advice:")));
    }

    #[test]
    fn bootstrap_summary_renders_remote_status_fields() {
        let trace = InjectionTrace {
            payload_address: 0x2000,
            payload_size: 0x1000,
            payload_allocated_size: 0x2000,
            data_address: 0x2800,
            data_size: 0x400,
            data_allocated_size: 0x1000,
            stack_address: 0x3000,
            stack_size: 0x4000,
            target_uses_arm64e: Some(true),
            code_protection: RemoteProtectionOutcome::SetMaximumAndCurrent,
            data_protection: RemoteProtectionOutcome::CurrentOnlyFallback,
            thread_bootstrap_kind: ThreadBootstrapKind::PthreadCreateFromMachThread,
            thread_bootstrap_label: "/usr/lib/system/libsystem_pthread.dylib!pthread_create_from_mach_thread+0xabc"
                .into(),
            thread_plan: ThreadCreatePlan {
                flavor: 6,
                count: 68,
                state: Arm64ThreadState {
                    x: [0; 29],
                    fp: 0,
                    lr: 0,
                    sp: 0x7000,
                    pc: 0x5000,
                    cpsr: 0,
                    pad: 0,
                },
            },
            thread_port: Some(77),
            thread_termination: RemoteThreadTerminationOutcome::Terminated,
            thread_port_deallocated: true,
            resources_persist: false,
            bootstrap_report: Some(BootstrapResultReport {
                status: BootstrapStatus::ConnectFailed,
                status_raw: 5,
                dylib_handle: 0x1234,
                entry_address: 0x5678,
                socket_fd: 9,
                entry_return: -1,
            }),
            bootstrap_timed_out: false,
        };

        let summary = render_bootstrap_summary(&trace);
        assert!(summary.contains("status=connect-failed"));
        assert!(summary.contains("raw=5"));
        assert!(summary.contains("socket_fd=9"));
        assert!(summary.contains("hint=connect failed from the target back to the controller socket"));
        assert!(summary.contains("thread_bootstrap_kind=pthread-create-from-mach-thread"));
        assert!(summary.contains("thread_termination=terminated"));
        assert!(summary.contains("resources_persist=false"));
        assert!(summary.contains("arm64e=true"));
        assert!(summary.contains("protect=set-maximum+current"));
        assert!(summary.contains("protect=current-only-fallback"));
        assert!(summary.contains(
            "thread_bootstrap=/usr/lib/system/libsystem_pthread.dylib!pthread_create_from_mach_thread+0xabc"
        ));
    }
}
