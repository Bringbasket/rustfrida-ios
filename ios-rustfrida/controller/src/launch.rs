use common::{Error, Result};
use std::process::Command;
#[cfg(any(target_os = "ios", target_os = "macos"))]
use std::{thread, time::Duration};

const SPAWN_COMMAND_ENV: &str = "IOS_RUSTFRIDA_SPAWN_COMMAND";
const SPAWN_BUNDLE_ENV: &str = "IOS_RUSTFRIDA_BUNDLE_ID";
#[cfg(any(target_os = "ios", target_os = "macos"))]
const RECOVERY_RETRY_INTERVAL: Duration = Duration::from_millis(350);
#[cfg(any(target_os = "ios", target_os = "macos"))]
const RECOVERY_RETRY_COUNT: usize = 5;

pub fn spawn_target(bundle_id: &str, spawn_command: Option<&str>) -> Result<i32> {
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

fn run_shell_spawn_helper(bundle_id: &str, template: &str) -> Result<i32> {
    let rendered = render_spawn_command(template, bundle_id);
    let output = run_shell(&rendered, Some((SPAWN_BUNDLE_ENV, bundle_id)))?;
    ensure_command_succeeded(bundle_id, "spawn helper", &output)?;

    extract_pid(&output.stdout)
        .or_else(|| extract_pid(&output.stderr))
        .ok_or_else(|| {
            Error::State(format!(
                "spawn helper did not report a pid for `{bundle_id}`. helper must print a pid line or `pid=<n>`. stdout: {} stderr: {}",
                display_command_output(&output.stdout),
                display_command_output(&output.stderr),
            ))
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
fn try_builtin_spawn(bundle_id: &str) -> Result<i32> {
    if command_exists("xcrun") {
        let output = run_command("xcrun", &["simctl", "launch", "booted", bundle_id])?;
        if output.status.success() {
            if let Some(pid) = extract_pid(&output.stdout).or_else(|| extract_pid(&output.stderr)) {
                return Ok(pid);
            }
        }
    }

    let mut errors = Vec::new();

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
fn launch_and_recover_pid(bundle_id: &str, program: &str, args: &[&str]) -> Result<i32> {
    let output = run_command(program, args)?;
    ensure_command_succeeded(bundle_id, program, &output)?;

    if let Some(pid) = recover_pid_after_launch(bundle_id)? {
        return Ok(pid);
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
        for command in launchctl_probe_commands(bundle_id) {
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
fn launchctl_probe_commands(bundle_id: &str) -> Vec<String> {
    [
        format!("launchctl print gui/$(id -u)/{bundle_id} 2>/dev/null"),
        format!("launchctl print user/$(id -u)/{bundle_id} 2>/dev/null"),
        format!("launchctl print system/{bundle_id} 2>/dev/null"),
    ]
    .into_iter()
    .collect()
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

fn render_spawn_command(template: &str, bundle_id: &str) -> String {
    template
        .replace("{{bundle_id}}", bundle_id)
        .replace("{bundle_id}", bundle_id)
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

fn extract_pid_from_marker(line: &str) -> Option<i32> {
    const MARKERS: [&str; 6] = ["pid=", "pid:", "pid ", "PID=", "PID:", "PID "];

    for marker in MARKERS {
        let Some(rest) = line.split_once(marker).map(|(_, rest)| rest.trim()) else {
            continue;
        };

        let digits: String = rest.chars().take_while(|ch| ch.is_ascii_digit()).collect();
        if digits.is_empty() {
            continue;
        }

        if let Ok(pid) = digits.parse::<i32>() {
            if pid > 0 {
                return Some(pid);
            }
        }
    }

    None
}

fn display_command_output(output: &str) -> String {
    if output.is_empty() {
        "<empty>".into()
    } else {
        output.replace('\n', " | ")
    }
}

#[cfg(test)]
mod tests {
    use super::{extract_pid, render_spawn_command};

    #[test]
    fn render_spawn_command_replaces_bundle_id_placeholders() {
        let command = render_spawn_command("uiopen {{bundle_id}} && echo pid:1234 # {bundle_id}", "com.test.app");
        assert!(command.contains("uiopen com.test.app"));
        assert!(command.contains("# com.test.app"));
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
    fn spawn_target_runs_shell_helper() {
        let pid = super::spawn_target("com.test.app", Some("printf 'pid=2468\\n'")).expect("spawn helper");
        assert_eq!(pid, 2468);
    }
}
