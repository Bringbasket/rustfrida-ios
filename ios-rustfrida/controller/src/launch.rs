use common::{Error, Result};
use serde_json::Value;
use std::process::Command;
#[cfg(any(target_os = "ios", target_os = "macos"))]
use std::{thread, time::Duration};

const SPAWN_COMMAND_ENV: &str = "IOS_RUSTFRIDA_SPAWN_COMMAND";
const SPAWN_BUNDLE_ENV: &str = "IOS_RUSTFRIDA_BUNDLE_ID";
const SPAWN_PROTOCOL_MARKER: &str = "IOS_RUSTFRIDA_SPAWN_V1=";
pub(crate) const CONTROL_PID_ENV: &str = "IOS_RUSTFRIDA_CONTROL_PID";
pub(crate) const CONTROL_ACTION_ENV: &str = "IOS_RUSTFRIDA_CONTROL_ACTION";
pub(crate) const CONTROL_GATE_ID_ENV: &str = "IOS_RUSTFRIDA_CONTROL_GATE_ID";
pub(crate) const CONTROL_PROVIDER_ENV: &str = "IOS_RUSTFRIDA_CONTROL_PROVIDER";
pub(crate) const CONTROL_BUNDLE_ID_ENV: &str = "IOS_RUSTFRIDA_CONTROL_BUNDLE_ID";
const FRONTBOARD_GATE_PROTOCOL: &str = "ios-rustfrida.bundle-suspended-launcher.v2";
const GATE_STATUS_PROTOCOL: &str = "ios-rustfrida.bundle-gate-status.v1";
const GATE_STATUS_MARKER: &str = "IOS_RUSTFRIDA_GATE_STATUS_V1=";
const MAX_CONTROL_COMMAND_LEN: usize = 16 * 1024;
const MAX_GATE_ID_LEN: usize = 512;
const MAX_PROVIDER_NAME_LEN: usize = 256;
const MAX_CONTROL_BUNDLE_ID_LEN: usize = 512;
#[cfg(any(target_os = "ios", target_os = "macos"))]
const RECOVERY_RETRY_INTERVAL: Duration = Duration::from_millis(350);
#[cfg(any(target_os = "ios", target_os = "macos"))]
const RECOVERY_RETRY_COUNT: usize = 5;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SpawnInitialState {
    Running,
    Suspended,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SpawnControlSignal {
    Continue,
    Kill,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SpawnControlAction {
    Signal(SpawnControlSignal),
    Command(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SpawnControl {
    pub(crate) resume: SpawnControlAction,
    pub(crate) terminate: SpawnControlAction,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SpawnGate {
    SimulatorWaitForDebugger,
    FrontBoardScene(FrontBoardSceneGate),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FrontBoardSceneGate {
    pub(crate) bundle_id: String,
    pub(crate) gate_id: String,
    pub(crate) provider: String,
    pub(crate) status: SpawnControlAction,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SpawnGateState {
    Held,
    Released,
    Terminated,
}

impl SpawnControl {
    pub(crate) fn signals() -> Self {
        Self {
            resume: SpawnControlAction::Signal(SpawnControlSignal::Continue),
            terminate: SpawnControlAction::Signal(SpawnControlSignal::Kill),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SpawnedTarget {
    pub(crate) pid: i32,
    pub(crate) initial_state: SpawnInitialState,
    pub(crate) control: SpawnControl,
    pub(crate) gate: Option<SpawnGate>,
}

pub fn spawn_target(bundle_id: &str, spawn_command: Option<&str>) -> Result<i32> {
    spawn_target_with_state(bundle_id, spawn_command).map(|target| target.pid)
}

pub(crate) fn spawn_target_with_state(bundle_id: &str, spawn_command: Option<&str>) -> Result<SpawnedTarget> {
    if let Some(template) = resolve_spawn_command(spawn_command) {
        return run_shell_spawn_helper(bundle_id, &template);
    }

    #[cfg(any(target_os = "ios", target_os = "macos"))]
    {
        return try_builtin_spawn(bundle_id);
    }

    #[cfg(not(any(target_os = "ios", target_os = "macos")))]
    {
        Err(Error::Unsupported(format!(
            "spawn requires a helper command on this host; pass `--spawn-command '<shell>'` or set {SPAWN_COMMAND_ENV}"
        )))
    }
}

pub(crate) fn spawn_bundle_with_native_gate(bundle_id: &str, spawn_command: Option<&str>) -> Result<SpawnedTarget> {
    if let Some(template) = resolve_spawn_command(spawn_command) {
        let target = run_shell_spawn_helper(bundle_id, &template)?;
        if target.initial_state == SpawnInitialState::Suspended && target.gate.is_some() {
            return Ok(target);
        }

        cleanup_spawned_target(&target);
        return Err(Error::State(format!(
            "spawn helper launched `{bundle_id}` without a verified pre-user-code gate. Physical-device bundle suspension requires `{FRONTBOARD_GATE_PROTOCOL}` with a runtime-dynamic FrontBoard/scene capability and status control; post-launch SIGSTOP is not used"
        )));
    }

    #[cfg(any(target_os = "ios", target_os = "macos"))]
    {
        return try_builtin_native_gate(bundle_id);
    }

    #[cfg(not(any(target_os = "ios", target_os = "macos")))]
    {
        Err(Error::Unsupported(format!(
            "native bundle start-suspended gate is Apple-specific. Supply a `{FRONTBOARD_GATE_PROTOCOL}` provider through `--spawn-command '<shell>'` or {SPAWN_COMMAND_ENV}; post-launch SIGSTOP is not used"
        )))
    }
}

fn run_shell_spawn_helper(bundle_id: &str, template: &str) -> Result<SpawnedTarget> {
    let rendered = render_spawn_command(template, bundle_id)?;
    let output = run_shell(&rendered, Some((SPAWN_BUNDLE_ENV, bundle_id)))?;
    ensure_command_succeeded(bundle_id, "spawn helper", &output)?;

    match parse_spawn_protocol(bundle_id, &output.stdout, &output.stderr) {
        Ok(Some(target)) => return Ok(target),
        Ok(None) => {}
        Err(err) => {
            cleanup_reported_pid(&output.stdout, &output.stderr);
            return Err(err);
        }
    }

    let pid = extract_pid(&output.stdout)
        .or_else(|| extract_pid(&output.stderr))
        .ok_or_else(|| {
            Error::State(format!(
                "spawn helper did not report a pid for `{bundle_id}`. helper must print a pid line or `pid=<n>`. stdout: {} stderr: {}",
                display_command_output(&output.stdout),
                display_command_output(&output.stderr),
            ))
        })?;
    let state = match parse_spawn_initial_state(&output.stdout) {
        Ok(Some(state)) => Some(state),
        Ok(None) => parse_spawn_initial_state(&output.stderr)?,
        Err(err) => {
            cleanup_reported_pid(&output.stdout, &output.stderr);
            return Err(err);
        }
    };
    Ok(SpawnedTarget {
        pid,
        initial_state: state.unwrap_or(SpawnInitialState::Running),
        control: SpawnControl::signals(),
        gate: None,
    })
}

fn resolve_spawn_command(cli_command: Option<&str>) -> Option<String> {
    if let Some(command) = cli_command.map(str::trim).filter(|value| !value.is_empty()) {
        return Some(command.to_string());
    }

    if let Ok(command) = std::env::var(SPAWN_COMMAND_ENV) {
        let command = command.trim();
        if !command.is_empty() {
            return Some(command.to_string());
        }
    }

    None
}

#[cfg(any(target_os = "ios", target_os = "macos"))]
fn try_builtin_spawn(bundle_id: &str) -> Result<SpawnedTarget> {
    let mut errors = Vec::new();

    if command_exists("xcrun") {
        match run_command("xcrun", &simctl_launch_args(bundle_id)) {
            Ok(output) if output.status.success() => {
                if let Some(pid) = extract_pid_for_bundle(&output.stdout, bundle_id)
                    .or_else(|| extract_pid_for_bundle(&output.stderr, bundle_id))
                    .or_else(|| extract_pid(&output.stdout))
                    .or_else(|| extract_pid(&output.stderr))
                {
                    return Ok(SpawnedTarget {
                        pid,
                        initial_state: SpawnInitialState::Running,
                        control: SpawnControl::signals(),
                        gate: None,
                    });
                }
                errors.push(format!(
                    "xcrun simctl launch returned success without a PID. stdout: {} stderr: {}",
                    display_command_output(&output.stdout),
                    display_command_output(&output.stderr),
                ));
            }
            Ok(output) => errors.push(format!(
                "xcrun simctl launch failed with status {}. stdout: {} stderr: {}",
                output
                    .status
                    .code()
                    .map(|code| code.to_string())
                    .unwrap_or_else(|| "signal".into()),
                display_command_output(&output.stdout),
                display_command_output(&output.stderr),
            )),
            Err(err) => errors.push(format!("xcrun simctl launch: {err}")),
        }
    }

    if command_exists("uiopen") {
        match launch_and_recover_pid(bundle_id, "uiopen", &[bundle_id]) {
            Ok(pid) => return Ok(pid),
            Err(err) => errors.push(format!("uiopen: {err}")),
        }
    }

    if command_exists("open") {
        match launch_and_recover_pid(bundle_id, "open", &["-b", bundle_id]) {
            Ok(pid) => return Ok(pid),
            Err(err) => errors.push(format!("open -b: {err}")),
        }
    }

    Err(Error::Unsupported(format!(
        "spawn could not launch `{bundle_id}` with built-in Apple helpers. Tried xcrun simctl, uiopen, open -b. {} Use `--spawn-command '<shell>'` or set {SPAWN_COMMAND_ENV}",
        if errors.is_empty() {
            "No helper binary succeeded.".into()
        } else {
            format!("Failures: {}", errors.join("; "))
        }
    )))
}

#[cfg(any(target_os = "ios", target_os = "macos"))]
fn try_builtin_native_gate(bundle_id: &str) -> Result<SpawnedTarget> {
    if !command_exists("xcrun") {
        return Err(native_gate_provider_error(bundle_id, "xcrun is not present"));
    }

    let output = run_command("xcrun", &simctl_wait_for_debugger_args(bundle_id)).map_err(|err| {
        native_gate_provider_error(
            bundle_id,
            format!("xcrun simctl --wait-for-debugger could not start: {err}"),
        )
    })?;
    if !output.status.success() {
        return Err(native_gate_provider_error(
            bundle_id,
            format!(
                "xcrun simctl --wait-for-debugger failed with status {}; stdout: {}; stderr: {}",
                output
                    .status
                    .code()
                    .map(|code| code.to_string())
                    .unwrap_or_else(|| "signal".into()),
                display_command_output(&output.stdout),
                display_command_output(&output.stderr),
            ),
        ));
    }
    let pid = extract_pid_for_bundle(&output.stdout, bundle_id)
        .or_else(|| extract_pid_for_bundle(&output.stderr, bundle_id))
        .or_else(|| extract_pid(&output.stdout))
        .or_else(|| extract_pid(&output.stderr))
        .ok_or_else(|| {
            native_gate_provider_error(
                bundle_id,
                format!(
                    "xcrun simctl --wait-for-debugger returned success without a PID; stdout: {}; stderr: {}",
                    display_command_output(&output.stdout),
                    display_command_output(&output.stderr),
                ),
            )
        })?;

    Ok(SpawnedTarget {
        pid,
        initial_state: SpawnInitialState::Suspended,
        control: SpawnControl::signals(),
        gate: Some(SpawnGate::SimulatorWaitForDebugger),
    })
}

#[cfg(any(target_os = "ios", target_os = "macos"))]
fn native_gate_provider_error(bundle_id: &str, simulator_failure: impl std::fmt::Display) -> Error {
    Error::Unsupported(format!(
        "native pre-user-code gate unavailable for `{bundle_id}`: {simulator_failure}. Supply a `{FRONTBOARD_GATE_PROTOCOL}` runtime-dynamic FrontBoard/scene provider through `--spawn-command '<shell>'` or {SPAWN_COMMAND_ENV}; ordinary LaunchServices launch plus SIGSTOP was not attempted"
    ))
}

fn simctl_wait_for_debugger_args(bundle_id: &str) -> Vec<&str> {
    vec!["simctl", "launch", "--wait-for-debugger", "booted", bundle_id]
}

fn simctl_launch_args(bundle_id: &str) -> Vec<&str> {
    vec!["simctl", "launch", "booted", bundle_id]
}

#[cfg(any(target_os = "ios", target_os = "macos"))]
fn launch_and_recover_pid(bundle_id: &str, program: &str, args: &[&str]) -> Result<SpawnedTarget> {
    let output = run_command(program, args)?;
    ensure_command_succeeded(bundle_id, program, &output)?;

    if let Some(pid) = recover_pid_after_launch(bundle_id)? {
        return Ok(SpawnedTarget {
            pid,
            initial_state: SpawnInitialState::Running,
            control: SpawnControl::signals(),
            gate: None,
        });
    }

    Err(Error::State(format!(
        "{program} launched `{bundle_id}`, but pid recovery failed. stdout: {} stderr: {}",
        display_command_output(&output.stdout),
        display_command_output(&output.stderr),
    )))
}

#[cfg(any(target_os = "ios", target_os = "macos"))]
fn recover_pid_after_launch(bundle_id: &str) -> Result<Option<i32>> {
    for attempt in 0..RECOVERY_RETRY_COUNT {
        for command in launchctl_probe_commands(bundle_id)? {
            let output = run_shell(&command, None)?;
            if let Some(pid) = extract_pid(&output.stdout).or_else(|| extract_pid(&output.stderr)) {
                return Ok(Some(pid));
            }
        }

        let pgrep = run_command("pgrep", &["-f", bundle_id])?;
        if let Some(pid) = extract_pid(&output_last_nonempty_line(&pgrep.stdout)) {
            return Ok(Some(pid));
        }

        if attempt + 1 < RECOVERY_RETRY_COUNT {
            thread::sleep(RECOVERY_RETRY_INTERVAL);
        }
    }

    Ok(None)
}

#[cfg(any(target_os = "ios", target_os = "macos"))]
fn launchctl_probe_commands(bundle_id: &str) -> Result<Vec<String>> {
    validate_control_replacement("bundle_id", bundle_id, MAX_CONTROL_BUNDLE_ID_LEN)?;
    let bundle_id = shell_quote_replacement(bundle_id);
    Ok([
        format!("launchctl print gui/$(id -u)/{bundle_id} 2>/dev/null"),
        format!("launchctl print user/$(id -u)/{bundle_id} 2>/dev/null"),
        format!("launchctl print system/{bundle_id} 2>/dev/null"),
    ]
    .into_iter()
    .collect())
}

#[cfg(any(target_os = "ios", target_os = "macos"))]
fn output_last_nonempty_line(output: &str) -> String {
    output
        .lines()
        .rev()
        .find(|line| !line.trim().is_empty())
        .unwrap_or("")
        .trim()
        .to_string()
}

fn ensure_command_succeeded(bundle_id: &str, label: &str, output: &CommandOutput) -> Result<()> {
    if output.status.success() {
        return Ok(());
    }

    Err(Error::State(format!(
        "{label} failed for `{bundle_id}` with status {}. stdout: {} stderr: {}",
        output
            .status
            .code()
            .map(|code| code.to_string())
            .unwrap_or_else(|| "signal".into()),
        display_command_output(&output.stdout),
        display_command_output(&output.stderr),
    )))
}

#[cfg(any(target_os = "ios", target_os = "macos"))]
fn run_command(program: &str, args: &[&str]) -> Result<CommandOutput> {
    let output = Command::new(program).args(args).output()?;
    Ok(CommandOutput::from_std(output))
}

fn run_shell(script: &str, env: Option<(&str, &str)>) -> Result<CommandOutput> {
    let mut command = Command::new("sh");
    command.arg("-lc").arg(script);
    if let Some((key, value)) = env {
        command.env(key, value);
    }
    let output = command.output()?;
    Ok(CommandOutput::from_std(output))
}

#[cfg(any(target_os = "ios", target_os = "macos"))]
fn command_exists(program: &str) -> bool {
    Command::new("sh")
        .arg("-lc")
        .arg(format!("command -v {program} >/dev/null 2>&1"))
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

#[derive(Debug, Clone)]
struct CommandOutput {
    status: std::process::ExitStatus,
    stdout: String,
    stderr: String,
}

impl CommandOutput {
    fn from_std(output: std::process::Output) -> Self {
        Self {
            status: output.status,
            stdout: String::from_utf8_lossy(&output.stdout).trim().to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        }
    }
}

fn render_spawn_command(template: &str, bundle_id: &str) -> std::io::Result<String> {
    validate_control_replacement("bundle_id", bundle_id, MAX_CONTROL_BUNDLE_ID_LEN)?;
    let bundle_id = shell_quote_replacement(bundle_id);
    Ok(template
        .replace("{{bundle_id}}", &bundle_id)
        .replace("{bundle_id}", &bundle_id))
}

/// Render a provider control command without changing unknown tokens.
///
/// The gate fields are only substituted when a runtime-dynamic gate is
/// supplied. Keeping unknown or context-free tokens literal preserves the
/// shell-helper contract used by older providers; the environment carries
/// the same values for providers that prefer not to use templates.
pub(crate) fn render_control_command(
    template: &str,
    pid: i32,
    action: &str,
    gate: Option<&FrontBoardSceneGate>,
) -> std::io::Result<String> {
    if template.len() > MAX_CONTROL_COMMAND_LEN {
        return Err(invalid_control_context(format!(
            "control command exceeds {MAX_CONTROL_COMMAND_LEN} bytes"
        )));
    }
    if template.chars().any(|ch| matches!(ch, '\0' | '\r' | '\n')) {
        return Err(invalid_control_context("control command must be a single command line"));
    }

    let pid = pid.to_string();
    validate_control_replacement("pid", &pid, 32)?;
    validate_control_replacement("action", action, 32)?;
    if !matches!(action, "status" | "resume" | "terminate") {
        return Err(invalid_control_context(format!(
            "unsupported control action `{action}`"
        )));
    }
    if let Some(gate) = gate {
        validate_control_replacement("gate_id", &gate.gate_id, MAX_GATE_ID_LEN)?;
        validate_control_replacement("provider", &gate.provider, MAX_PROVIDER_NAME_LEN)?;
        validate_control_replacement("bundle_id", &gate.bundle_id, MAX_CONTROL_BUNDLE_ID_LEN)?;
    }

    let mut rendered = String::with_capacity(template.len());
    let mut cursor = 0;
    while cursor < template.len() {
        let rest = &template[cursor..];
        let token = if let Some(rest) = rest.strip_prefix("{{") {
            rest.find("}}").map(|end| (end + 4, &rest[..end]))
        } else if let Some(rest) = rest.strip_prefix('{') {
            rest.find('}').map(|end| (end + 2, &rest[..end]))
        } else {
            None
        };

        if let Some((token_len, name)) = token {
            let token = &template[cursor..cursor + token_len];
            if let Some(value) = control_placeholder_value(name, &pid, action, gate) {
                rendered.push_str(&shell_quote_replacement(value));
            } else {
                rendered.push_str(token);
            }
            cursor += token_len;
        } else {
            let character = rest.chars().next().expect("cursor is bounded by the template length");
            rendered.push(character);
            cursor += character.len_utf8();
        }
    }
    Ok(rendered)
}

/// Add the auditable control context to a shell helper command.
pub(crate) fn apply_control_command_environment(
    command: &mut Command,
    pid: i32,
    action: &str,
    gate: Option<&FrontBoardSceneGate>,
) -> std::io::Result<()> {
    let pid_value = pid.to_string();
    validate_control_replacement("pid", &pid_value, 32)?;
    validate_control_replacement("action", action, 32)?;
    if !matches!(action, "status" | "resume" | "terminate") {
        return Err(invalid_control_context(format!(
            "unsupported control action `{action}`"
        )));
    }

    command.env(CONTROL_PID_ENV, &pid_value).env(CONTROL_ACTION_ENV, action);
    match gate {
        Some(gate) => {
            validate_control_replacement("gate_id", &gate.gate_id, MAX_GATE_ID_LEN)?;
            validate_control_replacement("provider", &gate.provider, MAX_PROVIDER_NAME_LEN)?;
            validate_control_replacement("bundle_id", &gate.bundle_id, MAX_CONTROL_BUNDLE_ID_LEN)?;
            command
                .env(CONTROL_GATE_ID_ENV, &gate.gate_id)
                .env(CONTROL_PROVIDER_ENV, &gate.provider)
                .env(CONTROL_BUNDLE_ID_ENV, &gate.bundle_id);
        }
        None => {
            // Do not let inherited values create a false gate identity for a
            // legacy helper command that has no runtime-dynamic gate.
            command
                .env_remove(CONTROL_GATE_ID_ENV)
                .env_remove(CONTROL_PROVIDER_ENV)
                .env_remove(CONTROL_BUNDLE_ID_ENV);
        }
    }
    Ok(())
}

fn control_placeholder_value<'a>(
    name: &str,
    pid: &'a str,
    action: &'a str,
    gate: Option<&'a FrontBoardSceneGate>,
) -> Option<&'a str> {
    match name {
        "pid" => Some(pid),
        "action" => Some(action),
        "gate_id" => gate.map(|gate| gate.gate_id.as_str()),
        "provider" => gate.map(|gate| gate.provider.as_str()),
        "bundle_id" => gate.map(|gate| gate.bundle_id.as_str()),
        _ => None,
    }
}

fn validate_control_replacement(name: &str, value: &str, max_len: usize) -> std::io::Result<()> {
    if value.is_empty() || value.trim().is_empty() || value.len() > max_len || value.chars().any(char::is_control) {
        return Err(invalid_control_context(format!(
            "{name} replacement must be non-empty, control-free, and at most {max_len} bytes"
        )));
    }
    Ok(())
}

/// Keep ordinary identifiers readable while making values with shell syntax a
/// single literal word. The command template remains an explicit shell
/// program; only values supplied by the runtime are quoted here.
fn shell_quote_replacement(value: &str) -> String {
    if value.bytes().all(is_shell_literal_byte) {
        return value.to_owned();
    }

    let mut quoted = String::with_capacity(value.len() + 2);
    quoted.push('\'');
    for character in value.chars() {
        if character == '\'' {
            quoted.push_str("'\\''");
        } else {
            quoted.push(character);
        }
    }
    quoted.push('\'');
    quoted
}

fn is_shell_literal_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'_' | b'-' | b'.' | b'/' | b':' | b'@' | b'%' | b'+' | b',' | b'='
        )
}

fn invalid_control_context(message: impl Into<String>) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidInput, message.into())
}

fn parse_spawn_protocol(bundle_id: &str, stdout: &str, stderr: &str) -> Result<Option<SpawnedTarget>> {
    let markers = stdout
        .lines()
        .chain(stderr.lines())
        .filter_map(|line| line.trim().strip_prefix(SPAWN_PROTOCOL_MARKER))
        .collect::<Vec<_>>();
    if markers.is_empty() {
        return Ok(None);
    }
    if markers.len() != 1 {
        return Err(protocol_error(format!(
            "expected exactly one structured marker, found {}",
            markers.len()
        )));
    }

    let value = serde_json::from_str::<Value>(markers[0])
        .map_err(|err| protocol_error(format!("marker payload is not valid JSON: {err}")))?;
    let object = value
        .as_object()
        .ok_or_else(|| protocol_error("marker payload must be a JSON object"))?;
    let protocol = validate_spawn_protocol_target(object, bundle_id)?;

    let pid = object
        .get("pid")
        .and_then(Value::as_i64)
        .filter(|pid| (1..=i32::MAX as i64).contains(pid))
        .map(|pid| pid as i32)
        .ok_or_else(|| protocol_error("`pid` must be a positive 32-bit integer"))?;
    let initial_state = match object.get("state").and_then(Value::as_str) {
        Some("running") => SpawnInitialState::Running,
        Some("suspended") => SpawnInitialState::Suspended,
        Some(state) => {
            return Err(protocol_error(format!(
                "unsupported `state` value `{state}`; expected `running` or `suspended`"
            )));
        }
        None => return Err(protocol_error("`state` must be `running` or `suspended`")),
    };
    let control = parse_spawn_control(
        object
            .get("control")
            .ok_or_else(|| protocol_error("`control` is required"))?,
    )?;
    let gate = if protocol == Some(FRONTBOARD_GATE_PROTOCOL) {
        Some(parse_frontboard_scene_gate(object, bundle_id, &control)?)
    } else {
        if object.contains_key("gate") {
            return Err(protocol_error(format!(
                "`gate` requires protocol `{FRONTBOARD_GATE_PROTOCOL}`"
            )));
        }
        None
    };
    if initial_state == SpawnInitialState::Running && control != SpawnControl::signals() {
        return Err(protocol_error(
            "`state=running` must use SIGCONT/SIGKILL control; command control is only valid for a helper-held suspended target",
        ));
    }
    if gate.is_some() && initial_state != SpawnInitialState::Suspended {
        return Err(protocol_error(
            "FrontBoard/scene gate responses must report `state=suspended`",
        ));
    }

    Ok(Some(SpawnedTarget {
        pid,
        initial_state,
        control,
        gate,
    }))
}

fn validate_spawn_protocol_target<'a>(
    object: &'a serde_json::Map<String, Value>,
    expected_bundle_id: &str,
) -> Result<Option<&'a str>> {
    let protocol = optional_string_field(object, "protocol")?;
    if let Some(protocol) = protocol {
        if protocol != "ios-rustfrida.bundle-suspended-launcher.v1"
            && protocol != "ios-rustfrida.spawn.v1"
            && protocol != FRONTBOARD_GATE_PROTOCOL
        {
            return Err(protocol_error(format!("unsupported `protocol` value `{protocol}`")));
        }
    }
    let kind = match (
        optional_string_field(object, "kind")?,
        optional_string_field(object, "target")?,
    ) {
        (Some(kind), Some(target)) if kind != target => {
            return Err(protocol_error("`kind` and `target` report conflicting values"));
        }
        (Some(kind), _) | (_, Some(kind)) => Some(kind),
        (None, None) => None,
    };
    if let Some(kind) = kind {
        if kind != "bundle" && kind != "process" {
            return Err(protocol_error(format!(
                "unsupported target kind `{kind}`; expected `bundle` or `process`"
            )));
        }
    }
    let bundle_id = optional_string_field(object, "bundle_id")?;
    if let Some(bundle_id) = bundle_id {
        if bundle_id.trim().is_empty() || bundle_id.chars().any(|ch| matches!(ch, '\0' | '\r' | '\n')) {
            return Err(protocol_error("`bundle_id` must be a single non-empty string"));
        }
        if bundle_id != expected_bundle_id {
            return Err(protocol_error(format!(
                "`bundle_id` mismatch: expected `{expected_bundle_id}`, got `{bundle_id}`"
            )));
        }
    }
    if protocol == Some(FRONTBOARD_GATE_PROTOCOL) {
        if kind != Some("bundle") {
            return Err(protocol_error(format!(
                "protocol `{FRONTBOARD_GATE_PROTOCOL}` requires `kind=bundle`"
            )));
        }
        if bundle_id.is_none() {
            return Err(protocol_error(format!(
                "protocol `{FRONTBOARD_GATE_PROTOCOL}` requires the exact `bundle_id`"
            )));
        }
    }
    Ok(protocol)
}

fn optional_string_field<'a>(object: &'a serde_json::Map<String, Value>, key: &str) -> Result<Option<&'a str>> {
    match object.get(key) {
        Some(value) => value
            .as_str()
            .map(Some)
            .ok_or_else(|| protocol_error(format!("`{key}` must be a string"))),
        None => Ok(None),
    }
}

fn parse_frontboard_scene_gate(
    object: &serde_json::Map<String, Value>,
    bundle_id: &str,
    control: &SpawnControl,
) -> Result<SpawnGate> {
    if !matches!(control.resume, SpawnControlAction::Command(_))
        || !matches!(control.terminate, SpawnControlAction::Command(_))
    {
        return Err(protocol_error(
            "FrontBoard/scene gate lifecycle must use provider commands; PID signals do not prove or control the native gate",
        ));
    }

    let gate = object
        .get("gate")
        .and_then(Value::as_object)
        .ok_or_else(|| protocol_error("`gate` must be a JSON object"))?;
    require_gate_field(gate, "mechanism", "frontboard-scene")?;
    require_gate_field(gate, "resolution", "runtime-dynamic")?;
    require_gate_field(gate, "guarantee", "before-first-user-instruction")?;

    let gate_id = required_bounded_gate_string(gate, "id", MAX_GATE_ID_LEN)?;
    let provider = required_bounded_gate_string(gate, "provider", MAX_PROVIDER_NAME_LEN)?;
    let control_object = object
        .get("control")
        .and_then(Value::as_object)
        .ok_or_else(|| protocol_error("`control` must be a JSON object"))?;
    let status = parse_spawn_control_action(
        control_object
            .get("status")
            .ok_or_else(|| protocol_error("`control.status` is required for a FrontBoard/scene gate"))?,
        "status",
    )?;
    if !matches!(status, SpawnControlAction::Command(_)) {
        return Err(protocol_error(
            "`control.status` must be a provider command for a FrontBoard/scene gate",
        ));
    }

    Ok(SpawnGate::FrontBoardScene(FrontBoardSceneGate {
        bundle_id: bundle_id.to_string(),
        gate_id,
        provider,
        status,
    }))
}

fn require_gate_field(gate: &serde_json::Map<String, Value>, key: &str, expected: &str) -> Result<()> {
    let value = gate
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| protocol_error(format!("`gate.{key}` must be `{expected}`")))?;
    if value != expected {
        return Err(protocol_error(format!(
            "unsupported `gate.{key}` value `{value}`; expected `{expected}`"
        )));
    }
    Ok(())
}

fn required_bounded_gate_string(gate: &serde_json::Map<String, Value>, key: &str, max_len: usize) -> Result<String> {
    let value = gate
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| protocol_error(format!("`gate.{key}` must be a string")))?
        .trim();
    if value.is_empty() || value.len() > max_len || value.chars().any(char::is_control) {
        return Err(protocol_error(format!(
            "`gate.{key}` must be a non-empty control-free string of at most {max_len} bytes"
        )));
    }
    Ok(value.to_string())
}

fn parse_spawn_control(value: &Value) -> Result<SpawnControl> {
    let object = value
        .as_object()
        .ok_or_else(|| protocol_error("`control` must be a JSON object"))?;
    Ok(SpawnControl {
        resume: parse_spawn_control_action(
            object
                .get("resume")
                .ok_or_else(|| protocol_error("`control.resume` is required"))?,
            "resume",
        )?,
        terminate: parse_spawn_control_action(
            object
                .get("terminate")
                .ok_or_else(|| protocol_error("`control.terminate` is required"))?,
            "terminate",
        )?,
    })
}

fn parse_spawn_control_action(value: &Value, operation: &str) -> Result<SpawnControlAction> {
    let object = value
        .as_object()
        .ok_or_else(|| protocol_error(format!("`control.{operation}` must be a JSON object")))?;
    match (object.get("command"), object.get("signal")) {
        (Some(command), None) => {
            let command = command
                .as_str()
                .ok_or_else(|| protocol_error(format!("`control.{operation}.command` must be a string")))?
                .trim();
            if command.is_empty() {
                return Err(protocol_error(format!(
                    "`control.{operation}.command` must not be empty"
                )));
            }
            if command.len() > MAX_CONTROL_COMMAND_LEN {
                return Err(protocol_error(format!(
                    "`control.{operation}.command` exceeds {MAX_CONTROL_COMMAND_LEN} bytes"
                )));
            }
            if command.chars().any(|ch| matches!(ch, '\0' | '\r' | '\n')) {
                return Err(protocol_error(format!(
                    "`control.{operation}.command` must be a single command line"
                )));
            }
            Ok(SpawnControlAction::Command(command.to_string()))
        }
        (None, Some(signal)) => {
            let signal = signal
                .as_str()
                .ok_or_else(|| protocol_error(format!("`control.{operation}.signal` must be a string")))?;
            match (operation, signal.trim().to_ascii_uppercase().as_str()) {
                ("resume", "SIGCONT") => Ok(SpawnControlAction::Signal(SpawnControlSignal::Continue)),
                ("terminate", "SIGKILL") => Ok(SpawnControlAction::Signal(SpawnControlSignal::Kill)),
                _ => Err(protocol_error(format!(
                    "unsupported `control.{operation}.signal` value `{signal}`"
                ))),
            }
        }
        (Some(_), Some(_)) => Err(protocol_error(format!(
            "`control.{operation}` must choose exactly one of `command` or `signal`"
        ))),
        (None, None) => Err(protocol_error(format!(
            "`control.{operation}` must contain `command` or `signal`"
        ))),
    }
}

fn protocol_error(message: impl Into<String>) -> Error {
    Error::State(format!(
        "invalid {SPAWN_PROTOCOL_MARKER}<json> response: {}",
        message.into()
    ))
}

pub(crate) fn parse_spawn_gate_status(
    gate: &FrontBoardSceneGate,
    pid: i32,
    stdout: &str,
    stderr: &str,
) -> Result<SpawnGateState> {
    let markers = stdout
        .lines()
        .chain(stderr.lines())
        .filter_map(|line| line.trim().strip_prefix(GATE_STATUS_MARKER))
        .collect::<Vec<_>>();
    if markers.len() != 1 {
        return Err(gate_status_error(format!(
            "expected exactly one status marker, found {}",
            markers.len()
        )));
    }

    let value = serde_json::from_str::<Value>(markers[0])
        .map_err(|err| gate_status_error(format!("marker payload is not valid JSON: {err}")))?;
    let object = value
        .as_object()
        .ok_or_else(|| gate_status_error("marker payload must be a JSON object"))?;
    require_status_string(object, "protocol", GATE_STATUS_PROTOCOL)?;
    require_status_string(object, "bundle_id", &gate.bundle_id)?;
    let status_pid = object
        .get("pid")
        .and_then(Value::as_i64)
        .filter(|value| *value == pid as i64)
        .ok_or_else(|| gate_status_error(format!("`pid` must exactly match launched pid {pid}")))?;
    debug_assert_eq!(status_pid, pid as i64);

    let gate_object = object
        .get("gate")
        .and_then(Value::as_object)
        .ok_or_else(|| gate_status_error("`gate` must be a JSON object"))?;
    require_status_string(gate_object, "id", &gate.gate_id)?;
    require_status_string(gate_object, "provider", &gate.provider)?;
    require_status_string(gate_object, "mechanism", "frontboard-scene")?;
    require_status_string(gate_object, "resolution", "runtime-dynamic")?;
    require_status_string(gate_object, "guarantee", "before-first-user-instruction")?;

    match object.get("state").and_then(Value::as_str) {
        Some("held") => Ok(SpawnGateState::Held),
        Some("released") => Ok(SpawnGateState::Released),
        Some("terminated") => Ok(SpawnGateState::Terminated),
        Some(state) => Err(gate_status_error(format!(
            "unsupported `state` value `{state}`; expected `held`, `released`, or `terminated`"
        ))),
        None => Err(gate_status_error("`state` is required")),
    }
}

fn require_status_string(object: &serde_json::Map<String, Value>, key: &str, expected: &str) -> Result<()> {
    let actual = object
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| gate_status_error(format!("`{key}` must be a string")))?;
    if actual != expected {
        return Err(gate_status_error(format!(
            "`{key}` mismatch: expected `{expected}`, got `{actual}`"
        )));
    }
    Ok(())
}

fn gate_status_error(message: impl Into<String>) -> Error {
    Error::State(format!(
        "invalid {GATE_STATUS_MARKER}<json> response: {}",
        message.into()
    ))
}

fn extract_pid(output: &str) -> Option<i32> {
    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        if let Ok(pid) = trimmed.parse::<i32>() {
            if pid > 0 {
                return Some(pid);
            }
        }

        if let Some(pid) = extract_pid_from_marker(trimmed) {
            return Some(pid);
        }
    }

    None
}

fn extract_pid_for_bundle(output: &str, bundle_id: &str) -> Option<i32> {
    output.lines().find_map(|line| {
        let trimmed = line.trim();
        let rest = trimmed.strip_prefix(bundle_id)?;
        if !rest.starts_with(':') && !rest.chars().next().is_some_and(|ch| ch.is_ascii_whitespace()) {
            return None;
        }
        let rest = rest.trim_start_matches(|ch: char| ch == ':' || ch.is_ascii_whitespace());
        let digits: String = rest.chars().take_while(|ch| ch.is_ascii_digit()).collect();
        let pid = digits.parse::<i32>().ok()?;
        (pid > 0).then_some(pid)
    })
}

fn extract_pid_from_marker(line: &str) -> Option<i32> {
    let lower = line.to_ascii_lowercase();
    for (index, _) in lower.char_indices() {
        if !lower[index..].starts_with("pid") {
            continue;
        }
        if index > 0
            && lower[..index]
                .chars()
                .next_back()
                .is_some_and(|ch| ch.is_ascii_alphanumeric())
        {
            continue;
        }
        let mut rest = &line[index + "pid".len()..];
        rest = rest.trim_start_matches(|ch: char| ch.is_ascii_whitespace());
        rest = rest
            .strip_prefix('=')
            .or_else(|| rest.strip_prefix(':'))
            .unwrap_or(rest);
        rest = rest.trim_start_matches(|ch: char| ch.is_ascii_whitespace());
        let digits: String = rest.chars().take_while(|ch| ch.is_ascii_digit()).collect();
        if let Ok(pid) = digits.parse::<i32>() {
            if pid > 0 {
                return Some(pid);
            }
        }
    }

    None
}

fn parse_spawn_initial_state(output: &str) -> Result<Option<SpawnInitialState>> {
    let mut state = None;
    for line in output.lines() {
        for key in [
            "state",
            "scene",
            "scene_state",
            "activationstate",
            "activation_state",
            "lifecycle",
            "suspended",
            "startsuspended",
            "start_suspended",
            "start-suspended",
        ] {
            for value in extract_state_values(line, key) {
                let parsed = match (key, value.as_str()) {
                    ("state", "running")
                    | ("state", "foregroundactive")
                    | ("state", "foregroundinactive")
                    | ("state", "background")
                    | ("state", "fbsactivationstateforegroundactive")
                    | ("scene", "foregroundactive")
                    | ("scene", "foregroundinactive")
                    | ("scene", "background")
                    | ("scene_state", "foregroundactive")
                    | ("scene_state", "foregroundinactive")
                    | ("scene_state", "background")
                    | ("activationstate", "foregroundactive")
                    | ("activationstate", "foregroundinactive")
                    | ("activationstate", "background")
                    | ("activation_state", "foregroundactive")
                    | ("activation_state", "foregroundinactive")
                    | ("activation_state", "background")
                    | ("lifecycle", "running")
                    | ("suspended", "0")
                    | ("suspended", "false")
                    | ("startsuspended", "0")
                    | ("startsuspended", "false")
                    | ("start_suspended", "0")
                    | ("start_suspended", "false")
                    | ("start-suspended", "0")
                    | ("start-suspended", "false") => SpawnInitialState::Running,
                    ("state", "suspended")
                    | ("state", "fbsactivationstatesuspended")
                    | ("scene", "suspended")
                    | ("scene", "fbsactivationstatesuspended")
                    | ("scene_state", "suspended")
                    | ("scene_state", "fbsactivationstatesuspended")
                    | ("activationstate", "suspended")
                    | ("activationstate", "fbsactivationstatesuspended")
                    | ("activation_state", "suspended")
                    | ("activation_state", "fbsactivationstatesuspended")
                    | ("lifecycle", "held")
                    | ("lifecycle", "suspended")
                    | ("suspended", "1")
                    | ("suspended", "true")
                    | ("startsuspended", "1")
                    | ("startsuspended", "true")
                    | ("start_suspended", "1")
                    | ("start_suspended", "true")
                    | ("start-suspended", "1")
                    | ("start-suspended", "true") => SpawnInitialState::Suspended,
                    _ => {
                        return Err(Error::State(format!(
                            "spawn helper reported unsupported {key} state `{value}`"
                        )))
                    }
                };
                if let Some(previous) = state {
                    if previous != parsed {
                        return Err(Error::State(
                            "spawn helper reported conflicting initial process states".into(),
                        ));
                    }
                }
                state = Some(parsed);
            }
        }
    }
    Ok(state)
}

fn extract_state_values(line: &str, key: &str) -> Vec<String> {
    let lower = line.to_ascii_lowercase();
    let mut values = Vec::new();
    for (index, _) in lower.match_indices(key) {
        if index > 0
            && lower[..index]
                .chars()
                .next_back()
                .is_some_and(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '-')
        {
            continue;
        }
        let mut rest = &lower[index + key.len()..];
        rest = rest.trim_start_matches(|ch: char| ch.is_ascii_whitespace());
        let Some(delimiter) = rest.chars().next() else {
            continue;
        };
        if delimiter != '=' && delimiter != ':' {
            continue;
        }
        rest = rest[delimiter.len_utf8()..].trim_start_matches(|ch: char| ch.is_ascii_whitespace());
        let value = rest
            .trim_start_matches(|ch: char| ch == '"' || ch == '\'')
            .split(|ch: char| ch.is_ascii_whitespace() || ch == ',' || ch == '}' || ch == '"' || ch == '\'')
            .next()
            .unwrap_or("");
        if !value.is_empty() {
            values.push(value.to_string());
        }
    }
    values
}

fn cleanup_reported_pid(stdout: &str, stderr: &str) {
    let pid = extract_pid_from_protocol(stdout)
        .or_else(|| extract_pid_from_protocol(stderr))
        .or_else(|| extract_pid(stdout))
        .or_else(|| extract_pid(stderr));
    if let Some(pid) = pid {
        terminate_reported_pid(pid);
    }
}

fn cleanup_spawned_target(target: &SpawnedTarget) {
    match &target.control.terminate {
        SpawnControlAction::Signal(SpawnControlSignal::Kill) => terminate_reported_pid(target.pid),
        SpawnControlAction::Command(template) => {
            let gate = match target.gate.as_ref() {
                Some(SpawnGate::FrontBoardScene(gate)) => Some(gate),
                _ => None,
            };
            let status = render_control_command(template, target.pid, "terminate", gate).and_then(|rendered| {
                let mut command = Command::new("sh");
                command.arg("-lc").arg(rendered);
                apply_control_command_environment(&mut command, target.pid, "terminate", gate)?;
                command.status()
            });
            if !status.is_ok_and(|status| status.success()) {
                terminate_reported_pid(target.pid);
            }
        }
        SpawnControlAction::Signal(SpawnControlSignal::Continue) => terminate_reported_pid(target.pid),
    }
}

fn extract_pid_from_protocol(output: &str) -> Option<i32> {
    output.lines().find_map(|line| {
        let payload = line.trim().strip_prefix(SPAWN_PROTOCOL_MARKER)?;
        let value = serde_json::from_str::<Value>(payload).ok()?;
        let pid = value.get("pid")?.as_i64()?;
        (1..=i32::MAX as i64).contains(&pid).then_some(pid as i32)
    })
}

#[cfg(unix)]
fn terminate_reported_pid(pid: i32) {
    let _ = unsafe { libc::kill(pid, libc::SIGKILL) };
}

#[cfg(not(unix))]
fn terminate_reported_pid(_pid: i32) {}

fn display_command_output(output: &str) -> String {
    if output.is_empty() {
        "<empty>".into()
    } else {
        output.replace('\n', " | ")
    }
}

#[cfg(test)]
mod tests {
    use super::{
        extract_pid, extract_pid_for_bundle, parse_spawn_gate_status, parse_spawn_initial_state, parse_spawn_protocol,
        render_control_command, render_spawn_command, run_shell_spawn_helper, simctl_launch_args,
        simctl_wait_for_debugger_args, spawn_bundle_with_native_gate, FrontBoardSceneGate, SpawnControl,
        SpawnControlAction, SpawnControlSignal, SpawnGate, SpawnGateState, SpawnInitialState, MAX_GATE_ID_LEN,
    };

    #[test]
    fn builtin_simctl_spawn_prefers_the_suspended_launch_contract() {
        assert_eq!(
            simctl_wait_for_debugger_args("com.test.app"),
            vec!["simctl", "launch", "--wait-for-debugger", "booted", "com.test.app"]
        );
        assert_eq!(
            simctl_launch_args("com.test.app"),
            vec!["simctl", "launch", "booted", "com.test.app"]
        );
    }

    #[test]
    fn render_spawn_command_replaces_bundle_id_placeholders() {
        let command = render_spawn_command("uiopen {{bundle_id}} && echo pid:1234 # {bundle_id}", "com.test.app")
            .expect("spawn command rendering");
        assert!(command.contains("uiopen com.test.app"));
        assert!(command.contains("# com.test.app"));
    }

    #[test]
    fn render_control_command_replaces_gate_context_and_keeps_unknown_tokens() {
        let gate = FrontBoardSceneGate {
            bundle_id: "com.test.app".into(),
            gate_id: "scene-1".into(),
            provider: "device-provider".into(),
            status: SpawnControlAction::Command("gatectl status".into()),
        };
        let rendered = render_control_command(
            "gatectl --pid {{pid}} --gate {gate_id} --provider {{provider}} --bundle {bundle_id} --action {{action}} {future}",
            4321,
            "status",
            Some(&gate),
        )
        .expect("control context rendering");
        assert_eq!(
            rendered,
            "gatectl --pid 4321 --gate scene-1 --provider device-provider --bundle com.test.app --action status {future}"
        );
    }

    #[test]
    fn render_control_command_rejects_control_and_overlong_replacements() {
        let mut gate = FrontBoardSceneGate {
            bundle_id: "com.test.app".into(),
            gate_id: "scene-1".into(),
            provider: "device-provider".into(),
            status: SpawnControlAction::Command("gatectl status".into()),
        };
        gate.gate_id.push('\n');
        let error = render_control_command("gatectl {gate_id}", 4321, "status", Some(&gate))
            .expect_err("control character must be rejected");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
        assert!(error.to_string().contains("gate_id replacement"));

        gate.gate_id = "x".repeat(MAX_GATE_ID_LEN + 1);
        let error = render_control_command("gatectl {gate_id}", 4321, "status", Some(&gate))
            .expect_err("overlong gate identity must be rejected");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
        assert!(error.to_string().contains("at most 512 bytes"));
    }

    #[test]
    fn render_control_command_quotes_shell_syntax_without_executing_it() {
        use std::process::Command;

        let mut gate = FrontBoardSceneGate {
            bundle_id: "com.test.app".into(),
            gate_id: "scene;printf injected 'quoted'".into(),
            provider: "device provider".into(),
            status: SpawnControlAction::Command("gatectl status".into()),
        };
        let rendered = render_control_command("printf '%s\\n' {gate_id} {provider}", 4321, "status", Some(&gate))
            .expect("control command rendering");
        let output = Command::new("sh")
            .arg("-lc")
            .arg(&rendered)
            .output()
            .expect("shell execution");
        assert!(output.status.success());
        assert_eq!(
            String::from_utf8_lossy(&output.stdout),
            "scene;printf injected 'quoted'\ndevice provider\n"
        );
        assert!(rendered.contains("\\'"), "apostrophe must be shell-escaped: {rendered}");

        gate.bundle_id = "bundle;exit 7".into();
        let rendered =
            render_spawn_command("printf '%s\\n' {bundle_id}", &gate.bundle_id).expect("spawn command rendering");
        let output = Command::new("sh")
            .arg("-lc")
            .arg(&rendered)
            .output()
            .expect("shell execution");
        assert!(output.status.success());
        assert_eq!(String::from_utf8_lossy(&output.stdout), "bundle;exit 7\n");
    }

    #[test]
    fn extract_pid_accepts_plain_pid_line() {
        assert_eq!(extract_pid("1234\n"), Some(1234));
    }

    #[test]
    fn extract_pid_accepts_marker_line() {
        assert_eq!(extract_pid("launched ok pid=4321"), Some(4321));
        assert_eq!(extract_pid("PID: 5678"), Some(5678));
    }

    #[test]
    fn extract_pid_ignores_non_pid_output() {
        assert_eq!(extract_pid("launch ok\nno pid here"), None);
    }

    #[test]
    fn parse_spawn_state_accepts_explicit_suspended_marker() {
        assert_eq!(
            parse_spawn_initial_state("pid=1234 state=suspended").expect("state marker"),
            Some(SpawnInitialState::Suspended)
        );
        assert_eq!(
            parse_spawn_initial_state("pid=1234 start_suspended=true").expect("state marker"),
            Some(SpawnInitialState::Suspended)
        );
        assert_eq!(
            parse_spawn_initial_state("scene_state: FBSActivationStateSuspended").expect("scene marker"),
            Some(SpawnInitialState::Suspended)
        );
        assert_eq!(
            parse_spawn_initial_state("activationState = foregroundActive").expect("scene marker"),
            Some(SpawnInitialState::Running)
        );
        assert_eq!(
            parse_spawn_initial_state("lifecycle=held").expect("helper marker"),
            Some(SpawnInitialState::Suspended)
        );
    }

    #[test]
    fn absent_spawn_state_preserves_running_compatibility() {
        assert_eq!(parse_spawn_initial_state("pid=1234").expect("absent state"), None);
        assert_eq!(
            parse_spawn_initial_state("pid=1234 state=running").expect("state marker"),
            Some(SpawnInitialState::Running)
        );
    }

    #[test]
    fn pid_parser_accepts_simctl_and_launchctl_formats() {
        assert_eq!(extract_pid_for_bundle("com.test.app: 4321", "com.test.app"), Some(4321));
        assert_eq!(extract_pid("pid = 4322"), Some(4322));
        assert_eq!(extract_pid("pid: 4323"), Some(4323));
        assert_eq!(
            extract_pid_for_bundle("com.test.application: 4324", "com.test.app"),
            None
        );
    }

    #[test]
    fn state_parser_rejects_unknown_and_conflicting_markers() {
        assert!(parse_spawn_initial_state("state=blocked").is_err());
        assert!(parse_spawn_initial_state("state=running state=suspended").is_err());
        assert_eq!(
            parse_spawn_initial_state("state: suspended").expect("state marker"),
            Some(SpawnInitialState::Suspended)
        );
    }

    #[test]
    fn structured_protocol_accepts_runtime_dynamic_frontboard_gate() {
        let output = r#"IOS_RUSTFRIDA_SPAWN_V1={"protocol":"ios-rustfrida.bundle-suspended-launcher.v2","kind":"bundle","bundle_id":"com.test.app","pid":4321,"state":"suspended","gate":{"id":"scene-1","provider":"device-provider","mechanism":"frontboard-scene","resolution":"runtime-dynamic","guarantee":"before-first-user-instruction"},"control":{"status":{"command":"gatectl status --pid {pid}"},"resume":{"command":"gatectl resume --pid {pid}"},"terminate":{"command":"gatectl terminate --pid {pid}"}}}"#;
        let target = parse_spawn_protocol("com.test.app", output, "")
            .expect("valid structured protocol")
            .expect("structured marker");

        assert_eq!(target.pid, 4321);
        assert_eq!(target.initial_state, SpawnInitialState::Suspended);
        assert_eq!(
            target.control,
            SpawnControl {
                resume: SpawnControlAction::Command("gatectl resume --pid {pid}".into()),
                terminate: SpawnControlAction::Command("gatectl terminate --pid {pid}".into()),
            }
        );
        assert_eq!(
            target.gate,
            Some(SpawnGate::FrontBoardScene(super::FrontBoardSceneGate {
                bundle_id: "com.test.app".into(),
                gate_id: "scene-1".into(),
                provider: "device-provider".into(),
                status: SpawnControlAction::Command("gatectl status --pid {pid}".into()),
            }))
        );
    }

    #[test]
    fn structured_protocol_accepts_explicit_signal_control() {
        let output = r#"IOS_RUSTFRIDA_SPAWN_V1={"pid":4322,"state":"suspended","control":{"resume":{"signal":"SIGCONT"},"terminate":{"signal":"SIGKILL"}}}"#;
        let target = parse_spawn_protocol("com.test.app", "", output)
            .expect("valid structured protocol")
            .expect("structured marker");

        assert_eq!(target.control, SpawnControl::signals());
        assert_eq!(
            target.control.resume,
            SpawnControlAction::Signal(SpawnControlSignal::Continue)
        );
        assert_eq!(target.gate, None);
    }

    #[test]
    fn structured_protocol_rejects_invalid_pid_state_and_actions() {
        let invalid = [
            r#"IOS_RUSTFRIDA_SPAWN_V1={"pid":0,"state":"suspended","control":{"resume":{"signal":"SIGCONT"},"terminate":{"signal":"SIGKILL"}}}"#,
            r#"IOS_RUSTFRIDA_SPAWN_V1={"pid":12,"state":"blocked","control":{"resume":{"signal":"SIGCONT"},"terminate":{"signal":"SIGKILL"}}}"#,
            r#"IOS_RUSTFRIDA_SPAWN_V1={"pid":12,"state":"suspended","control":{"resume":{"signal":"SIGKILL"},"terminate":{"signal":"SIGKILL"}}}"#,
            r#"IOS_RUSTFRIDA_SPAWN_V1={"pid":12,"state":"running","control":{"resume":{"command":"gatectl resume"},"terminate":{"command":"gatectl terminate"}}}"#,
            r#"IOS_RUSTFRIDA_SPAWN_V1={"protocol":"unknown","pid":12,"state":"suspended","control":{"resume":{"signal":"SIGCONT"},"terminate":{"signal":"SIGKILL"}}}"#,
            r#"IOS_RUSTFRIDA_SPAWN_V1={"target":"service","pid":12,"state":"suspended","control":{"resume":{"signal":"SIGCONT"},"terminate":{"signal":"SIGKILL"}}}"#,
            "IOS_RUSTFRIDA_SPAWN_V1={\"bundle_id\":\" \",\"pid\":12,\"state\":\"suspended\",\"control\":{\"resume\":{\"signal\":\"SIGCONT\"},\"terminate\":{\"signal\":\"SIGKILL\"}}}",
        ];

        for output in invalid {
            assert!(
                parse_spawn_protocol("com.test.app", output, "").is_err(),
                "accepted {output}"
            );
        }
    }

    #[test]
    fn frontboard_protocol_rejects_missing_capability_wrong_bundle_and_pid_signals() {
        let invalid = [
            r#"IOS_RUSTFRIDA_SPAWN_V1={"protocol":"ios-rustfrida.bundle-suspended-launcher.v2","kind":"bundle","bundle_id":"com.other.app","pid":12,"state":"suspended","gate":{"id":"g","provider":"p","mechanism":"frontboard-scene","resolution":"runtime-dynamic","guarantee":"before-first-user-instruction"},"control":{"status":{"command":"gatectl status"},"resume":{"command":"gatectl resume"},"terminate":{"command":"gatectl terminate"}}}"#,
            r#"IOS_RUSTFRIDA_SPAWN_V1={"protocol":"ios-rustfrida.bundle-suspended-launcher.v2","kind":"bundle","bundle_id":"com.test.app","pid":12,"state":"suspended","gate":{"id":"g","provider":"p","mechanism":"frontboard-scene","resolution":"static-link","guarantee":"before-first-user-instruction"},"control":{"status":{"command":"gatectl status"},"resume":{"command":"gatectl resume"},"terminate":{"command":"gatectl terminate"}}}"#,
            r#"IOS_RUSTFRIDA_SPAWN_V1={"protocol":"ios-rustfrida.bundle-suspended-launcher.v2","kind":"bundle","bundle_id":"com.test.app","pid":12,"state":"suspended","gate":{"id":"g","provider":"p","mechanism":"frontboard-scene","resolution":"runtime-dynamic","guarantee":"before-first-user-instruction"},"control":{"status":{"command":"gatectl status"},"resume":{"signal":"SIGCONT"},"terminate":{"signal":"SIGKILL"}}}"#,
        ];

        for output in invalid {
            assert!(parse_spawn_protocol("com.test.app", output, "").is_err());
        }
    }

    #[test]
    fn frontboard_status_is_bound_to_bundle_pid_provider_and_gate_id() {
        let gate = super::FrontBoardSceneGate {
            bundle_id: "com.test.app".into(),
            gate_id: "scene-1".into(),
            provider: "device-provider".into(),
            status: SpawnControlAction::Command("gatectl status".into()),
        };
        let held = r#"IOS_RUSTFRIDA_GATE_STATUS_V1={"protocol":"ios-rustfrida.bundle-gate-status.v1","bundle_id":"com.test.app","pid":4321,"state":"held","gate":{"id":"scene-1","provider":"device-provider","mechanism":"frontboard-scene","resolution":"runtime-dynamic","guarantee":"before-first-user-instruction"}}"#;
        assert_eq!(
            parse_spawn_gate_status(&gate, 4321, held, "").expect("held gate"),
            SpawnGateState::Held
        );

        for invalid in [
            held.replace("\"pid\":4321", "\"pid\":4322"),
            held.replace("scene-1", "scene-2"),
            held.replace("runtime-dynamic", "static-link"),
            held.replace("\"state\":\"held\"", "\"state\":\"unknown\""),
        ] {
            assert!(parse_spawn_gate_status(&gate, 4321, &invalid, "").is_err());
        }
    }

    #[test]
    fn legacy_suspended_helper_keeps_signal_control() {
        let target =
            run_shell_spawn_helper("com.test.app", "printf 'pid=2469 state=suspended\\n'").expect("legacy helper");
        assert_eq!(target.pid, 2469);
        assert_eq!(target.initial_state, SpawnInitialState::Suspended);
        assert_eq!(target.control, SpawnControl::signals());
        assert_eq!(target.gate, None);
    }

    #[cfg(unix)]
    #[test]
    fn native_gate_rejects_and_terminates_legacy_pid_stop_claim() {
        use std::process::Command;

        let mut child = Command::new("sleep").arg("30").spawn().expect("sleep process");
        let pid = child.id();
        let command = format!("printf 'pid=%s state=suspended\\n' {}", pid);
        let error = spawn_bundle_with_native_gate("com.test.app", Some(&command)).expect_err("unverified gate");
        assert!(error.to_string().contains("without a verified pre-user-code gate"));
        std::thread::sleep(std::time::Duration::from_millis(10));
        let killed = child.try_wait().expect("child status").is_some();
        if !killed {
            let _ = unsafe { libc::kill(pid as i32, libc::SIGKILL) };
            let _ = child.wait();
        }
        assert!(killed, "unverified helper left pid {pid} alive");
    }

    #[cfg(unix)]
    #[test]
    fn malformed_helper_state_terminates_reported_process() {
        use std::process::Command;

        let mut child = Command::new("sleep").arg("30").spawn().expect("sleep process");
        let pid = child.id();
        let command = format!("printf 'pid=%s state=blocked\\n' {}", pid);
        let error = run_shell_spawn_helper("com.test.app", &command).expect_err("invalid state");
        assert!(error.to_string().contains("unsupported state"));
        std::thread::sleep(std::time::Duration::from_millis(10));
        let killed = child.try_wait().expect("child status").is_some();
        if !killed {
            let _ = unsafe { libc::kill(pid as i32, libc::SIGKILL) };
            let _ = child.wait();
        }
        assert!(killed, "helper failure left pid {pid} alive");
    }

    #[cfg(unix)]
    #[test]
    fn malformed_structured_helper_protocol_terminates_reported_process() {
        use std::process::Command;

        let mut child = Command::new("sleep").arg("30").spawn().expect("sleep process");
        let pid = child.id();
        let command = format!(
            "printf 'IOS_RUSTFRIDA_SPAWN_V1={{\"protocol\":\"unknown\",\"kind\":\"bundle\",\"pid\":{},\"state\":\"suspended\",\"control\":{{\"resume\":{{\"signal\":\"SIGCONT\"}},\"terminate\":{{\"signal\":\"SIGKILL\"}}}}}}\n'",
            pid
        );
        let error = run_shell_spawn_helper("com.test.app", &command).expect_err("invalid protocol");
        assert!(error.to_string().contains("unsupported `protocol`"));
        std::thread::sleep(std::time::Duration::from_millis(10));
        let killed = child.try_wait().expect("child status").is_some();
        if !killed {
            let _ = unsafe { libc::kill(pid as i32, libc::SIGKILL) };
            let _ = child.wait();
        }
        assert!(killed, "helper failure left pid {pid} alive");
    }

    #[test]
    fn spawn_target_runs_shell_helper() {
        let pid = super::spawn_target("com.test.app", Some("printf 'pid=2468\\n'")).expect("spawn helper");
        assert_eq!(pid, 2468);
    }
}
