use std::{
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
    enumerate_images, hook_environment_recommendations, probe_injection_environment, BootstrapStatus,
    InjectionEnvironmentReport, InjectionPlan, InjectionTarget, InjectionTargetPreflightReport, InjectionTrace,
    LoaderSymbolRole, MachInjector, ResolvedLoaderSymbol,
};
use serde_json::{json, Value};

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
fn hook_environment_to_json(
    report: &native_api::HookEnvironmentReport,
    strategy: Option<&native_api::HookStrategyDecision>,
) -> Value {
    let risk_level = if let Some(strategy) = strategy {
        if !strategy.bootstrap_injection_allowed() {
            "blocked"
        } else if !strategy.hook_install_commands_allowed() {
            "query-only"
        } else if report.loaded_backend_count() > 0 {
            "risky"
        } else if report.filesystem_only_backend_count() > 0 {
            "cautious"
        } else {
            "normal"
        }
    } else if report.loaded_backend_count() > 0 {
        "risky"
    } else if report.filesystem_only_backend_count() > 0 {
        "cautious"
    } else {
        "normal"
    };

    json!({
        "activeBackend": report.active_backend,
        "conflictState": report.conflict_state(),
        "riskLevel": risk_level,
        "coexistenceLayerAvailable": false,
        "loadedBackendCount": report.loaded_backend_count(),
        "filesystemOnlyBackendCount": report.filesystem_only_backend_count(),
        "loadedImageCount": report.loaded_image_count(),
        "filesystemPathCount": report.filesystem_path_count(),
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
                if injection_environment.hook_strategy.hook_install_commands_allowed() {
                    "allowed"
                } else {
                    "query-only"
                },
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
                if preflight.target_hook_strategy.hook_install_commands_allowed() {
                    "allowed"
                } else {
                    "query-only"
                },
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
fn parse_error_status_field(message: &str) -> Option<String> {
    message
        .split("status=")
        .nth(1)
        .and_then(|tail| tail.split_whitespace().next())
        .map(|value| value.trim_end_matches(',').to_string())
        .filter(|value| !value.is_empty())
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
        } else if message.contains("target hook strategy blocked injection") {
            phase = "hook-policy".into();
            code = "target-hook-policy-blocked".into();
        } else if message.contains("hook strategy blocked injection") {
            phase = "hook-policy".into();
            code = "controller-hook-policy-blocked".into();
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

    push_agent_path_hints(config, &mut hints);

    json!({
        "phase": phase,
        "code": code,
        "bootstrapStatus": bootstrap_status,
        "handshakeStage": handshake_stage,
        "failedStep": failed_step,
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
        "target hook strategy: policy={} strategy={} allowed={} inline_hooks_allowed={} query_commands_allowed={} hook_install_commands_allowed={} hook_status_commands_allowed={} hook_stop_commands_allowed={}",
        report.target_hook_strategy.policy.as_str(),
        report.target_hook_strategy.strategy,
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
        "injection environment: dry_run={} bootstrap_wait={} hook_policy={} strategy={} allowed={} inline_hooks_allowed={} query_commands_allowed={} hook_install_commands_allowed={} hook_status_commands_allowed={} hook_stop_commands_allowed={}",
        report.dry_run,
        bootstrap_wait,
        report.hook_policy.as_str(),
        report.hook_strategy.strategy,
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
fn ensure_inline_hooks_allowed_for_command(
    command: &str,
    injection_environment: &InjectionEnvironmentReport,
    preflight: &InjectionTargetPreflightReport,
) -> Result<()> {
    if !command_requires_inline_hooks(command) {
        return Ok(());
    }
    if !command_requests_inline_hook_install(command)? {
        return Ok(());
    }

    let mut blocked_by = Vec::new();
    if !injection_environment.hook_strategy.hook_install_commands_allowed() {
        let reason = injection_environment
            .hook_strategy
            .reason
            .clone()
            .unwrap_or_else(|| "controller hook strategy disables ios-rustfrida inline hooks".into());
        blocked_by.push(format!(
            "controller policy={} strategy={}: {}",
            injection_environment.hook_strategy.policy.as_str(),
            injection_environment.hook_strategy.strategy,
            reason
        ));
    }
    if !preflight.target_hook_strategy.hook_install_commands_allowed() {
        let reason = preflight
            .target_hook_strategy
            .reason
            .clone()
            .unwrap_or_else(|| "target hook strategy disables ios-rustfrida inline hooks".into());
        blocked_by.push(format!(
            "target policy={} strategy={}: {}",
            preflight.target_hook_strategy.policy.as_str(),
            preflight.target_hook_strategy.strategy,
            reason
        ));
    }

    if blocked_by.is_empty() {
        return Ok(());
    }

    Err(Error::State(format!(
        "`{command}` requires inline hooks, but the current hook policy is query-only: {}",
        blocked_by.join("; ")
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
    println!("  objc.protocols");
    println!("  objc.protocols [filter]");
    println!("  objc.classProtocols <class>");
    println!("  objc.classInfo <class> [meta]");
    println!("  objc.protocolInfo <protocol>");
    println!("  objc.protocolProtocols <protocol>");
    println!("  objc.protocolMethods <protocol> [required] [instance] [filter]");
    println!("  objc.protocolMethodInfo <protocol> <selector> [required] [instance]");
    println!("  objc.protocolProperties <protocol> [filter]");
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
    println!("  native.loadcmds <module>");
    println!("  native.loadCommandInfo <module> -- <name|cmd|index>");
    println!("  native.sections <module>");
    println!("  native.sectionInfo <module> -- <segment> <section>");
    println!("  native.segments <module>");
    println!("  native.segmentInfo <module> -- <segment>");
    println!("  native.symbolInfo <symbol>|native.symbolInfo <module> -- <symbol>");
    println!("  native.symbols <query>|native.symbols <module> -- <query>");
    println!("  native.images [filter]");
    println!("  native.mainImage");
    println!("  native.image <address>");
    println!("  native.symbol <address>");
    println!("  native.hookenv");
    println!("  pac.available");
    println!("  pac.arm64e");
    println!("  pac.image <module>");
    println!("  pac.images [filter]");
    println!("  pac.strip <address>");
    println!("  pac.stripdata <address>");
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
    println!("  swift.typeKinds");
    println!("  swift.methodOwners <method>|swift.methodOwners <module> -- <method>");
    println!("  swift.types <query>|swift.types <module> -- <query>");
    println!("  swift.typesOfKind <kind> <query>|swift.typesOfKind <module> -- <kind> <query>");
    println!("  swift.typeMethods <type>|swift.typeMethods <module> -- <type>");
    println!("  swift.methods <type> <method>|swift.methods <module> -- <type> <method>");
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
        build_trace_spec, command_requests_inline_hook_install, command_requires_inline_hooks,
        ensure_inline_hooks_allowed_for_command, hook_environment_requires_notice, parse_hfl_command,
        parse_jhook_command, parse_shook_command, parse_stalker_command, parse_trace_command,
        print_injection_preflight, quote_js_string, render_bootstrap_summary, render_command_error_json,
        render_command_error_json_with_context, render_command_outcome_json, render_image_list_json,
        render_injection_environment, render_injection_result_json, render_loader_symbol, render_preflight_json,
        CommandJsonContext, CommandOutcome, CommandOutcomeKind, HflCommand, NativeHookTarget, NativeLogArgument,
        NativeLogReturn, NativeLogTemplate, NativeValueFormat, ObjcHookCommand, StalkerCommand, SwiftHookCommand,
        TraceCommand,
    };
    use common::{
        AgentCommand, ControllerConfig, Error, Hello, InjectionMode, DEFAULT_AGENT_PATH, DEFAULT_AGENT_PATH_ROOTFUL,
        LEGACY_AGENT_PATH_ROOTFUL,
    };
    use native_api::{
        Arm64ThreadState, BootstrapResultReport, BootstrapStatus, HookBackendInfo, HookEnvironmentReport, HookPolicy,
        HookStrategyDecision, InjectionEnvironmentReport, InjectionTarget, InjectionTargetPreflightReport,
        InjectionTrace, LoaderSymbolRole, MachInjector, RemoteProtectionOutcome, RemoteThreadTerminationOutcome,
        ResolvedLoaderSymbol, ThreadBootstrapKind, ThreadCreatePlan,
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
        assert_eq!(
            AgentCommand::from_legacy("objc.protocolInfo NSObject"),
            Some(AgentCommand::RuntimeDispatch {
                spec: json!({
                    "kind": "objc.protocol_info",
                    "protocolName": "NSObject",
                })
            })
        );
        assert_eq!(
            AgentCommand::from_legacy("objc.protocolProtocols NSObject"),
            Some(AgentCommand::RuntimeDispatch {
                spec: json!({
                    "kind": "objc.protocol_protocols",
                    "protocolName": "NSObject",
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
            AgentCommand::from_legacy("objc.protocolPropertyInfo NSObject description"),
            Some(AgentCommand::RuntimeDispatch {
                spec: json!({
                    "kind": "objc.protocol_property_info",
                    "protocolName": "NSObject",
                    "propertyName": "description",
                })
            })
        );
        assert_eq!(
            AgentCommand::from_legacy("objc.superclass UIViewController"),
            Some(AgentCommand::RuntimeDispatch {
                spec: json!({
                    "kind": "objc.superclass",
                    "className": "UIViewController",
                })
            })
        );
        assert_eq!(
            AgentCommand::from_legacy("objc.classChain UIViewController"),
            Some(AgentCommand::RuntimeDispatch {
                spec: json!({
                    "kind": "objc.class_chain",
                    "className": "UIViewController",
                })
            })
        );
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
            AgentCommand::from_legacy("objc.methodImage UIViewController viewDidLoad"),
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
            AgentCommand::from_legacy("native.exportInfo DemoBinary -- malloc"),
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
            AgentCommand::from_legacy("native.imports DemoBinary"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("native.importInfo DemoBinary -- malloc"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("native.symbolInfo DemoBinary -- malloc"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("native.loadCommandInfo DemoBinary -- LC_UUID"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("native.sectionInfo DemoBinary -- __TEXT __text"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("native.segmentInfo DemoBinary -- __TEXT"),
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
            AgentCommand::from_legacy("swift.conformanceInfo Demo -- ViewController Renderable"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("swift.typeInfo Demo -- ViewController"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("swift.methodInfo Demo -- ViewController viewDidLoad"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("swift.symbolInfo Demo -- ViewController"),
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
            AgentCommand::from_legacy("swift.vtable ViewController"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("swift.vtableInfo Demo -- ViewController viewDidLoad"),
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
            AgentCommand::from_legacy("swift.typeLayout ViewController"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("swift.typeLayoutInfo Demo -- ViewController"),
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
        assert!(!command_requires_inline_hooks("objc.protocols NS"));
        assert!(!command_requires_inline_hooks("objc.classProtocols UIView"));
        assert!(!command_requires_inline_hooks("objc.classInfo UIView meta"));
        assert!(!command_requires_inline_hooks("objc.protocolInfo NSObject"));
        assert!(!command_requires_inline_hooks("objc.protocolProtocols NSObject"));
        assert!(!command_requires_inline_hooks(
            "objc.protocolMethods NSObject optional class"
        ));
        assert!(!command_requires_inline_hooks(
            "objc.protocolMethods NSObject optional class description"
        ));
        assert!(!command_requires_inline_hooks(
            "objc.protocolMethodInfo NSObject description optional class"
        ));
        assert!(!command_requires_inline_hooks("objc.protocolProperties NSObject"));
        assert!(!command_requires_inline_hooks("objc.protocolProperties NSObject description"));
        assert!(!command_requires_inline_hooks(
            "objc.protocolPropertyInfo NSObject description"
        ));
        assert!(!command_requires_inline_hooks("objc.superclass UIView"));
        assert!(!command_requires_inline_hooks("objc.classChain UIView"));
        assert!(!command_requires_inline_hooks("objc.properties UIView meta delegate"));
        assert!(!command_requires_inline_hooks("objc.propertyInfo UIView view"));
        assert!(!command_requires_inline_hooks("objc.ivarInfo UIView _viewFlags"));
        assert!(!command_requires_inline_hooks("objc.ivars UIView delegate"));
        assert!(!command_requires_inline_hooks("objc.methodInfo UIView viewDidLoad"));
        assert!(!command_requires_inline_hooks("native.imageInfo UIKit"));
        assert!(!command_requires_inline_hooks("native.images UIKit"));
        assert!(!command_requires_inline_hooks("native.dependencies UIKit"));
        assert!(!command_requires_inline_hooks("native.exportInfo UIKit -- malloc"));
        assert!(!command_requires_inline_hooks(
            "native.dependencyInfo UIKit -- libSystem.B.dylib"
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
        assert!(!command_requires_inline_hooks("native.imports UIKit"));
        assert!(!command_requires_inline_hooks("native.importInfo UIKit -- malloc"));
        assert!(!command_requires_inline_hooks(
            "native.loadCommandInfo UIKit -- LC_UUID"
        ));
        assert!(!command_requires_inline_hooks(
            "native.sectionInfo UIKit -- __TEXT __text"
        ));
        assert!(!command_requires_inline_hooks("native.segmentInfo UIKit -- __TEXT"));
        assert!(!command_requires_inline_hooks("native.symbolInfo malloc"));
        assert!(!command_requires_inline_hooks("swift.protocolInfo Renderable"));
        assert!(!command_requires_inline_hooks(
            "swift.conformanceInfo ViewController Renderable"
        ));
        assert!(!command_requires_inline_hooks("swift.typeInfo ViewController"));
        assert!(!command_requires_inline_hooks(
            "swift.methodInfo ViewController viewDidLoad"
        ));
        assert!(!command_requires_inline_hooks("swift.symbolInfo ViewController"));
        assert!(!command_requires_inline_hooks("swift.protocols"));
        assert!(!command_requires_inline_hooks("swift.conformances ViewController"));
        assert!(!command_requires_inline_hooks("swift.metadata ViewController"));
        assert!(!command_requires_inline_hooks("swift.metadataInfo ViewController"));
        assert!(!command_requires_inline_hooks("swift.vtable ViewController"));
        assert!(!command_requires_inline_hooks(
            "swift.vtableInfo ViewController viewDidLoad"
        ));
        assert!(!command_requires_inline_hooks("swift.witnessTable Renderable"));
        assert!(!command_requires_inline_hooks(
            "swift.witnessTableInfo ViewController Renderable"
        ));
        assert!(!command_requires_inline_hooks("swift.typeLayout ViewController"));
        assert!(!command_requires_inline_hooks("swift.typeLayoutInfo ViewController"));
        assert!(!command_requires_inline_hooks("swift.types ViewController"));
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
        assert_eq!(rendered["environment"]["hookStrategy"]["bootstrapInjectionAllowed"], true);
        assert_eq!(rendered["environment"]["hookStrategy"]["queryCommandsAllowed"], true);
        assert_eq!(rendered["environment"]["hookStrategy"]["hookInstallCommandsAllowed"], true);
        assert_eq!(rendered["preflight"]["targetHookEnvironment"]["conflictState"], "none");
        assert_eq!(rendered["preflight"]["targetHookEnvironment"]["riskLevel"], "normal");
        assert_eq!(rendered["preflight"]["targetHookEnvironment"]["coexistenceLayerAvailable"], false);
        assert_eq!(rendered["preflight"]["targetHookEnvironment"]["loadedBackendCount"], 0);
        assert_eq!(rendered["payload"], json!(null));
        assert_eq!(rendered["items"], json!([]));
        assert_eq!(rendered["logs"][0], "bootstrap pending");
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
            "active=<none>\nconflict_state=none\nrisk_level=normal\npolicy=warn\nstrategy=internal-inline\nallowed=true\ninline_hooks_allowed=true\nbootstrap_injection_allowed=true\nquery_commands_allowed=true\nhook_install_commands_allowed=true\nhook_status_commands_allowed=true\nhook_stop_commands_allowed=true\ncoexistence_layer_available=false\nloaded_backend_count=0\nfilesystem_only_backend_count=0\nloaded_image_count=0\nfilesystem_path_count=0"
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
