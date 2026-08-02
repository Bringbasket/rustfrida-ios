//! Bounded ownership of a process held for pre-resume injection.
//!
//! Executable targets use the platform's earliest available stop point. Apple
//! uses `POSIX_SPAWN_START_SUSPENDED`; other Unix hosts stop between `fork` and
//! `exec` so the lifecycle can be exercised by host tests. Bundle targets only
//! accept a simulator debugger wait or a provider-verified FrontBoard/scene
//! gate that promises to hold before the first user instruction. A PID learned
//! after ordinary LaunchServices activation is never upgraded with SIGSTOP.

use std::{
    fmt, io,
    process::Command,
    thread,
    time::{Duration, Instant},
};

use common::{Error, Result};

use super::launch::{
    apply_control_command_environment, parse_spawn_gate_status, render_control_command, spawn_bundle_with_native_gate,
    FrontBoardSceneGate, SpawnControl, SpawnControlAction, SpawnControlSignal, SpawnGate, SpawnGateState,
    SpawnInitialState,
};

const DEFAULT_CONFIRMATION_TIMEOUT: Duration = Duration::from_secs(5);
const DEFAULT_POLL_INTERVAL: Duration = Duration::from_millis(10);
const MAX_CONFIRMATION_TIMEOUT: Duration = Duration::from_secs(60);
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SuspendedSpawnState {
    Suspending,
    Suspended,
    Running,
    Terminating,
    Terminated,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SuspendedSpawnOptions {
    pub confirmation_timeout: Duration,
    pub poll_interval: Duration,
}

impl Default for SuspendedSpawnOptions {
    fn default() -> Self {
        Self {
            confirmation_timeout: DEFAULT_CONFIRMATION_TIMEOUT,
            poll_interval: DEFAULT_POLL_INTERVAL,
        }
    }
}

impl SuspendedSpawnOptions {
    fn validate(self) -> Result<Self> {
        if self.confirmation_timeout.is_zero() {
            return Err(Error::InvalidArgument(
                "suspended-spawn confirmation timeout must be greater than zero".into(),
            ));
        }
        if self.confirmation_timeout > MAX_CONFIRMATION_TIMEOUT {
            return Err(Error::InvalidArgument(format!(
                "suspended-spawn confirmation timeout must not exceed {} seconds",
                MAX_CONFIRMATION_TIMEOUT.as_secs()
            )));
        }
        if self.poll_interval.is_zero() {
            return Err(Error::InvalidArgument(
                "suspended-spawn poll interval must be greater than zero".into(),
            ));
        }
        if self.poll_interval > self.confirmation_timeout {
            return Err(Error::InvalidArgument(
                "suspended-spawn poll interval must not exceed the confirmation timeout".into(),
            ));
        }
        Ok(self)
    }
}

pub(crate) struct SuspendedSpawn {
    pid: i32,
    state: SuspendedSpawnState,
    is_child: bool,
    options: SuspendedSpawnOptions,
    lifecycle_control: SpawnControl,
    gate: Option<SpawnGate>,
    released_to_caller: bool,
    control: Box<dyn ProcessControl>,
}

impl fmt::Debug for SuspendedSpawn {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SuspendedSpawn")
            .field("pid", &self.pid)
            .field("state", &self.state)
            .field("is_child", &self.is_child)
            .field("options", &self.options)
            .field("lifecycle_control", &self.lifecycle_control)
            .field("gate", &self.gate)
            .field("released_to_caller", &self.released_to_caller)
            .finish_non_exhaustive()
    }
}

impl SuspendedSpawn {
    pub(crate) fn launch_bundle(bundle_id: &str, spawn_command: Option<&str>) -> Result<Self> {
        Self::launch_bundle_with_options(bundle_id, spawn_command, SuspendedSpawnOptions::default())
    }

    pub(crate) fn launch_bundle_with_options(
        bundle_id: &str,
        spawn_command: Option<&str>,
        options: SuspendedSpawnOptions,
    ) -> Result<Self> {
        if bundle_id.trim().is_empty() {
            return Err(Error::InvalidArgument(
                "suspended-spawn bundle identifier must not be empty".into(),
            ));
        }
        let options = options.validate()?;
        let launched = spawn_bundle_with_native_gate(bundle_id, spawn_command)?;
        if launched.initial_state != SpawnInitialState::Suspended || launched.gate.is_none() {
            return Err(Error::State(format!(
                "native bundle gate invariant failed for `{bundle_id}`: launcher did not return a verified suspended target"
            )));
        }
        let mut spawned = Self::managed_with_lifecycle_control(
            launched.pid,
            SuspendedSpawnState::Suspended,
            false,
            options,
            launched.control,
            launched.gate,
        )?;
        spawned.confirm_initial_suspension()?;
        Ok(spawned)
    }

    #[allow(dead_code)]
    pub(crate) fn launch_executable(program: &str, arguments: &[&str]) -> Result<Self> {
        Self::launch_executable_with_options(program, arguments, SuspendedSpawnOptions::default())
    }

    pub(crate) fn launch_executable_with_options(
        program: &str,
        arguments: &[&str],
        options: SuspendedSpawnOptions,
    ) -> Result<Self> {
        let options = options.validate()?;
        let pid = platform_spawn_suspended(program, arguments)?;
        let mut spawned = Self::managed(pid, SuspendedSpawnState::Suspending, true, options)?;
        spawned.confirm_suspended()?;
        Ok(spawned)
    }

    pub(crate) fn pid(&self) -> i32 {
        self.pid
    }

    pub(crate) fn state(&self) -> SuspendedSpawnState {
        self.state
    }

    #[allow(dead_code)]
    pub(crate) fn refresh(&mut self) -> Result<SuspendedSpawnState> {
        let observation = self
            .observe()
            .map_err(|err| Error::State(format!("failed to inspect suspended-spawn pid {}: {err}", self.pid)))?;
        if observation != ProcessObservation::Exited {
            if let Some(SpawnGate::FrontBoardScene(gate)) = self.gate.clone() {
                self.apply_gate_state(self.query_frontboard_gate_state(&gate)?);
                return Ok(self.state);
            }
        }
        self.apply_observation(observation);
        Ok(self.state)
    }

    pub(crate) fn resume(&mut self) -> Result<()> {
        match self.state {
            SuspendedSpawnState::Running if self.released_to_caller => return Ok(()),
            SuspendedSpawnState::Running => {
                return Err(self.invalid_transition("resume", "gate acquisition did not complete"));
            }
            SuspendedSpawnState::Suspended => {}
            SuspendedSpawnState::Suspending => {
                return Err(self.invalid_transition("resume", "suspension has not been confirmed"));
            }
            SuspendedSpawnState::Terminating => {
                return Err(self.invalid_transition("resume", "termination is in progress"));
            }
            SuspendedSpawnState::Terminated => {
                return Err(self.invalid_transition("resume", "the process has terminated"));
            }
        }

        let control_gate = self.frontboard_gate().cloned();
        match self.control.perform_action(
            self.pid,
            ControlOperation::Resume,
            &self.lifecycle_control.resume,
            control_gate.as_ref(),
        ) {
            Ok(()) => {
                if let Some(SpawnGate::FrontBoardScene(gate)) = self.gate.clone() {
                    match self.query_frontboard_gate_state(&gate)? {
                        SpawnGateState::Released => {}
                        SpawnGateState::Held => {
                            return Err(Error::State(format!(
                                "FrontBoard/scene provider `{}` reported gate `{}` still held after resume for pid {}",
                                gate.provider, gate.gate_id, self.pid
                            )));
                        }
                        SpawnGateState::Terminated => {
                            self.state = SuspendedSpawnState::Terminated;
                            return Err(self.invalid_transition(
                                "resume",
                                "the FrontBoard/scene provider reported the target terminated",
                            ));
                        }
                    }
                }
                self.state = SuspendedSpawnState::Running;
                self.released_to_caller = true;
                Ok(())
            }
            Err(err) if is_no_such_process(&err) => {
                self.state = SuspendedSpawnState::Terminated;
                Err(self.invalid_transition("resume", "the process exited before the resume action completed"))
            }
            Err(err) => Err(Error::State(format!(
                "failed to resume suspended-spawn pid {}: {err}",
                self.pid
            ))),
        }
    }

    pub(crate) fn terminate(&mut self) -> Result<()> {
        if self.state == SuspendedSpawnState::Terminated {
            return Ok(());
        }
        self.released_to_caller = false;

        if self.state != SuspendedSpawnState::Terminating {
            let control_gate = self.frontboard_gate().cloned();
            match self.control.perform_action(
                self.pid,
                ControlOperation::Terminate,
                &self.lifecycle_control.terminate,
                control_gate.as_ref(),
            ) {
                Ok(()) => self.state = SuspendedSpawnState::Terminating,
                Err(err) if is_no_such_process(&err) => {
                    self.state = SuspendedSpawnState::Terminated;
                    return Ok(());
                }
                Err(err) => {
                    return Err(Error::State(format!(
                        "failed to terminate suspended-spawn pid {}: {err}",
                        self.pid
                    )));
                }
            }
        }

        match self.wait_for(|observation| observation == ProcessObservation::Exited)? {
            ProcessObservation::Exited => {
                self.state = SuspendedSpawnState::Terminated;
                Ok(())
            }
            observation => Err(Error::State(format!(
                "timed out after {:?} waiting for suspended-spawn pid {} to terminate; last observation: {}",
                self.options.confirmation_timeout,
                self.pid,
                observation.label()
            ))),
        }
    }

    fn managed(pid: i32, state: SuspendedSpawnState, is_child: bool, options: SuspendedSpawnOptions) -> Result<Self> {
        Self::managed_with_lifecycle_control(pid, state, is_child, options, SpawnControl::signals(), None)
    }

    fn managed_with_lifecycle_control(
        pid: i32,
        state: SuspendedSpawnState,
        is_child: bool,
        options: SuspendedSpawnOptions,
        lifecycle_control: SpawnControl,
        gate: Option<SpawnGate>,
    ) -> Result<Self> {
        if pid <= 0 {
            return Err(Error::State(format!(
                "suspended-spawn launcher returned invalid pid {pid}"
            )));
        }
        Ok(Self {
            pid,
            state,
            is_child,
            options,
            lifecycle_control,
            gate,
            released_to_caller: false,
            control: Box::new(SystemProcessControl),
        })
    }

    #[cfg(test)]
    fn managed_with_control(
        pid: i32,
        state: SuspendedSpawnState,
        is_child: bool,
        options: SuspendedSpawnOptions,
        control: Box<dyn ProcessControl>,
    ) -> Self {
        Self {
            pid,
            state,
            is_child,
            options,
            lifecycle_control: SpawnControl::signals(),
            gate: None,
            released_to_caller: false,
            control,
        }
    }

    #[cfg(test)]
    fn managed_with_lifecycle_and_control(
        pid: i32,
        state: SuspendedSpawnState,
        is_child: bool,
        options: SuspendedSpawnOptions,
        lifecycle_control: SpawnControl,
        control: Box<dyn ProcessControl>,
    ) -> Self {
        Self {
            pid,
            state,
            is_child,
            options,
            lifecycle_control,
            gate: None,
            released_to_caller: false,
            control,
        }
    }

    #[cfg(test)]
    fn managed_with_gate_and_control(
        pid: i32,
        state: SuspendedSpawnState,
        options: SuspendedSpawnOptions,
        lifecycle_control: SpawnControl,
        gate: SpawnGate,
        control: Box<dyn ProcessControl>,
    ) -> Self {
        Self {
            pid,
            state,
            is_child: false,
            options,
            lifecycle_control,
            gate: Some(gate),
            released_to_caller: false,
            control,
        }
    }

    fn confirm_suspended(&mut self) -> Result<()> {
        match self
            .wait_for(|observation| matches!(observation, ProcessObservation::Stopped | ProcessObservation::Exited))?
        {
            ProcessObservation::Stopped => {
                self.state = SuspendedSpawnState::Suspended;
                Ok(())
            }
            ProcessObservation::Exited => {
                self.state = SuspendedSpawnState::Terminated;
                Err(Error::State(format!(
                    "suspended-spawn pid {} exited before suspension was confirmed",
                    self.pid
                )))
            }
            observation => Err(Error::State(format!(
                "timed out after {:?} waiting for suspended-spawn pid {} to stop; last observation: {}",
                self.options.confirmation_timeout,
                self.pid,
                observation.label()
            ))),
        }
    }

    fn confirm_initial_suspension(&mut self) -> Result<()> {
        match self.gate.clone() {
            Some(SpawnGate::SimulatorWaitForDebugger) => self.confirm_suspended(),
            Some(SpawnGate::FrontBoardScene(gate)) => {
                let observation = self.observe().map_err(|err| {
                    Error::State(format!(
                        "failed to validate FrontBoard/scene gated pid {}: {err}",
                        self.pid
                    ))
                })?;
                if observation == ProcessObservation::Exited {
                    self.state = SuspendedSpawnState::Terminated;
                    return Err(Error::State(format!(
                        "FrontBoard/scene gated pid {} exited before control was acquired",
                        self.pid
                    )));
                }

                match self.query_frontboard_gate_state(&gate)? {
                    SpawnGateState::Held => {
                        self.state = SuspendedSpawnState::Suspended;
                        Ok(())
                    }
                    SpawnGateState::Released => {
                        self.state = SuspendedSpawnState::Running;
                        Err(Error::State(format!(
                            "FrontBoard/scene provider `{}` reported gate `{}` already released for pid {}; pre-user-code control was not acquired",
                            gate.provider, gate.gate_id, self.pid
                        )))
                    }
                    SpawnGateState::Terminated => {
                        self.state = SuspendedSpawnState::Terminated;
                        Err(Error::State(format!(
                            "FrontBoard/scene provider `{}` reported gated pid {} terminated before control was acquired",
                            gate.provider, self.pid
                        )))
                    }
                }
            }
            None => Err(Error::State(format!(
                "suspended bundle pid {} has no verified pre-user-code gate",
                self.pid
            ))),
        }
    }

    fn query_frontboard_gate_state(&self, gate: &FrontBoardSceneGate) -> Result<SpawnGateState> {
        let SpawnControlAction::Command(command) = &gate.status else {
            return Err(Error::State(format!(
                "FrontBoard/scene gate `{}` has no provider status command",
                gate.gate_id
            )));
        };
        let output =
            run_control_command_capture(self.pid, ControlOperation::Status, command, Some(gate)).map_err(|err| {
                Error::State(format!(
                    "failed to query FrontBoard/scene gate `{}` for pid {}: {err}",
                    gate.gate_id, self.pid
                ))
            })?;
        parse_spawn_gate_status(gate, self.pid, &output.stdout, &output.stderr)
    }

    fn apply_gate_state(&mut self, gate_state: SpawnGateState) {
        self.state = match gate_state {
            SpawnGateState::Held => SuspendedSpawnState::Suspended,
            SpawnGateState::Released => SuspendedSpawnState::Running,
            SpawnGateState::Terminated => SuspendedSpawnState::Terminated,
        };
    }

    fn wait_for(&self, predicate: impl Fn(ProcessObservation) -> bool) -> Result<ProcessObservation> {
        let deadline = Instant::now() + self.options.confirmation_timeout;
        loop {
            let observation = self
                .observe()
                .map_err(|err| Error::State(format!("failed to inspect suspended-spawn pid {}: {err}", self.pid)))?;
            if predicate(observation) || Instant::now() >= deadline {
                return Ok(observation);
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            thread::sleep(self.options.poll_interval.min(remaining));
        }
    }

    fn observe(&self) -> io::Result<ProcessObservation> {
        self.control.observe(self.pid, self.is_child)
    }

    fn frontboard_gate(&self) -> Option<&FrontBoardSceneGate> {
        match self.gate.as_ref() {
            Some(SpawnGate::FrontBoardScene(gate)) => Some(gate),
            _ => None,
        }
    }

    #[allow(dead_code)]
    fn apply_observation(&mut self, observation: ProcessObservation) {
        self.state = match observation {
            ProcessObservation::Exited => SuspendedSpawnState::Terminated,
            ProcessObservation::Stopped if self.state == SuspendedSpawnState::Terminating => {
                SuspendedSpawnState::Terminating
            }
            ProcessObservation::Stopped => SuspendedSpawnState::Suspended,
            ProcessObservation::Running if self.state == SuspendedSpawnState::Terminating => {
                SuspendedSpawnState::Terminating
            }
            ProcessObservation::Running => SuspendedSpawnState::Running,
        };
    }

    fn invalid_transition(&self, operation: &str, reason: &str) -> Error {
        Error::State(format!(
            "cannot {operation} suspended-spawn pid {} from state {:?}: {reason}",
            self.pid, self.state
        ))
    }
}

impl Drop for SuspendedSpawn {
    fn drop(&mut self) {
        if !self.released_to_caller && self.state != SuspendedSpawnState::Terminated {
            let control_gate = self.frontboard_gate().cloned();
            let _ = self.control.perform_action(
                self.pid,
                ControlOperation::Terminate,
                &self.lifecycle_control.terminate,
                control_gate.as_ref(),
            );
            self.state = SuspendedSpawnState::Terminating;
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ControlOperation {
    Status,
    Resume,
    Terminate,
}

impl ControlOperation {
    fn label(self) -> &'static str {
        match self {
            Self::Status => "status",
            Self::Resume => "resume",
            Self::Terminate => "terminate",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ControlSignal {
    Continue,
    Kill,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProcessObservation {
    Running,
    Stopped,
    Exited,
}

impl ProcessObservation {
    fn label(self) -> &'static str {
        match self {
            Self::Running => "running",
            Self::Stopped => "stopped",
            Self::Exited => "exited",
        }
    }
}

trait ProcessControl: Send + Sync {
    fn signal(&self, pid: i32, signal: ControlSignal) -> io::Result<()>;
    fn perform_action(
        &self,
        pid: i32,
        operation: ControlOperation,
        action: &SpawnControlAction,
        gate: Option<&FrontBoardSceneGate>,
    ) -> io::Result<()> {
        match action {
            SpawnControlAction::Signal(SpawnControlSignal::Continue) => self.signal(pid, ControlSignal::Continue),
            SpawnControlAction::Signal(SpawnControlSignal::Kill) => self.signal(pid, ControlSignal::Kill),
            SpawnControlAction::Command(command) => run_control_command(pid, operation, command, gate),
        }
    }
    fn observe(&self, pid: i32, is_child: bool) -> io::Result<ProcessObservation>;
}

struct SystemProcessControl;

#[cfg(unix)]
impl ProcessControl for SystemProcessControl {
    fn signal(&self, pid: i32, signal: ControlSignal) -> io::Result<()> {
        let raw_signal = match signal {
            ControlSignal::Continue => libc::SIGCONT,
            ControlSignal::Kill => libc::SIGKILL,
        };
        if unsafe { libc::kill(pid, raw_signal) } == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    fn observe(&self, pid: i32, is_child: bool) -> io::Result<ProcessObservation> {
        if is_child {
            if let Some(observation) = observe_child(pid)? {
                return Ok(observation);
            }
        }
        observe_process(pid)
    }
}

#[cfg(not(unix))]
impl ProcessControl for SystemProcessControl {
    fn signal(&self, _pid: i32, _signal: ControlSignal) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "process signals are unavailable on this host",
        ))
    }

    fn observe(&self, _pid: i32, _is_child: bool) -> io::Result<ProcessObservation> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "process observation is unavailable on this host",
        ))
    }
}

fn run_control_command(
    pid: i32,
    operation: ControlOperation,
    template: &str,
    gate: Option<&FrontBoardSceneGate>,
) -> io::Result<()> {
    run_control_command_capture(pid, operation, template, gate).map(|_| ())
}

struct ControlCommandOutput {
    stdout: String,
    stderr: String,
}

fn run_control_command_capture(
    pid: i32,
    operation: ControlOperation,
    template: &str,
    gate: Option<&FrontBoardSceneGate>,
) -> io::Result<ControlCommandOutput> {
    let rendered = render_control_command(template, pid, operation.label(), gate)?;
    let mut command = Command::new("sh");
    command.arg("-lc").arg(rendered);
    apply_control_command_environment(&mut command, pid, operation.label(), gate)?;
    let output = command.output()?;
    if output.status.success() {
        return Ok(ControlCommandOutput {
            stdout: String::from_utf8_lossy(&output.stdout).trim().to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        });
    }

    Err(io::Error::other(format!(
        "{} helper command failed with status {}; stdout: {}; stderr: {}",
        operation.label(),
        output
            .status
            .code()
            .map(|code| code.to_string())
            .unwrap_or_else(|| "signal".into()),
        display_control_output(&output.stdout),
        display_control_output(&output.stderr),
    )))
}

fn display_control_output(output: &[u8]) -> String {
    let output = String::from_utf8_lossy(output);
    let output = output.trim();
    if output.is_empty() {
        "<empty>".into()
    } else {
        output.replace('\n', " | ")
    }
}

#[cfg(unix)]
fn observe_child(pid: i32) -> io::Result<Option<ProcessObservation>> {
    let mut status = 0;
    let result = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG | libc::WUNTRACED | libc::WCONTINUED) };
    if result == pid {
        if libc::WIFEXITED(status) || libc::WIFSIGNALED(status) {
            return Ok(Some(ProcessObservation::Exited));
        }
        if libc::WIFSTOPPED(status) {
            return Ok(Some(ProcessObservation::Stopped));
        }
        return Ok(Some(ProcessObservation::Running));
    }
    if result == 0 {
        return Ok(None);
    }

    let err = io::Error::last_os_error();
    if err.raw_os_error() == Some(libc::ECHILD) {
        Ok(None)
    } else {
        Err(err)
    }
}

#[cfg(any(target_os = "ios", target_os = "macos"))]
fn observe_process(pid: i32) -> io::Result<ProcessObservation> {
    use std::{ffi::c_void, mem};

    #[link(name = "proc")]
    extern "C" {
        fn proc_pidinfo(
            pid: libc::c_int,
            flavor: libc::c_int,
            arg: u64,
            buffer: *mut c_void,
            buffer_size: libc::c_int,
        ) -> libc::c_int;
    }

    let mut info = unsafe { mem::zeroed::<libc::proc_bsdinfo>() };
    let info_size = mem::size_of::<libc::proc_bsdinfo>();
    let written = unsafe {
        proc_pidinfo(
            pid,
            libc::PROC_PIDTBSDINFO,
            0,
            (&mut info as *mut libc::proc_bsdinfo).cast::<c_void>(),
            info_size as libc::c_int,
        )
    };
    if written as usize == info_size {
        return Ok(match info.pbi_status {
            libc::SSTOP => ProcessObservation::Stopped,
            libc::SZOMB => ProcessObservation::Exited,
            _ => ProcessObservation::Running,
        });
    }
    observe_process_with_signal(pid)
}

#[cfg(all(unix, not(any(target_os = "ios", target_os = "macos"))))]
fn observe_process(pid: i32) -> io::Result<ProcessObservation> {
    #[cfg(target_os = "linux")]
    if let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat")) {
        if let Some(state) = stat
            .rfind(") ")
            .and_then(|offset| stat.as_bytes().get(offset + 2))
            .copied()
        {
            return Ok(match state {
                b'T' | b't' => ProcessObservation::Stopped,
                b'X' | b'Z' => ProcessObservation::Exited,
                _ => ProcessObservation::Running,
            });
        }
    }
    observe_process_with_signal(pid)
}

#[cfg(unix)]
fn observe_process_with_signal(pid: i32) -> io::Result<ProcessObservation> {
    if unsafe { libc::kill(pid, 0) } == 0 {
        return Ok(ProcessObservation::Running);
    }
    let err = io::Error::last_os_error();
    if is_no_such_process(&err) {
        Ok(ProcessObservation::Exited)
    } else {
        Err(err)
    }
}

#[cfg(any(target_os = "ios", target_os = "macos"))]
fn platform_spawn_suspended(program: &str, arguments: &[&str]) -> Result<i32> {
    use std::{ffi::c_char, ptr};

    extern "C" {
        static mut environ: *mut *mut c_char;
    }

    let values = spawn_argument_values(program, arguments)?;
    let mut argv = values.iter().map(|value| value.as_ptr().cast_mut()).collect::<Vec<_>>();
    argv.push(ptr::null_mut());
    let mut attributes: libc::posix_spawnattr_t = ptr::null_mut();
    let init_result = unsafe { libc::posix_spawnattr_init(&mut attributes) };
    if init_result != 0 {
        return Err(spawn_error("posix_spawnattr_init", init_result));
    }

    let flags = libc::POSIX_SPAWN_START_SUSPENDED as libc::c_short;
    let flags_result = unsafe { libc::posix_spawnattr_setflags(&mut attributes, flags) };
    if flags_result != 0 {
        unsafe { libc::posix_spawnattr_destroy(&mut attributes) };
        return Err(spawn_error("posix_spawnattr_setflags", flags_result));
    }

    let mut pid = 0;
    let spawn_result = unsafe {
        libc::posix_spawnp(
            &mut pid,
            values[0].as_ptr(),
            ptr::null(),
            &attributes,
            argv.as_ptr(),
            environ as *const *mut c_char,
        )
    };
    unsafe { libc::posix_spawnattr_destroy(&mut attributes) };
    if spawn_result != 0 {
        return Err(spawn_error("posix_spawnp", spawn_result));
    }
    Ok(pid)
}

#[cfg(all(unix, not(any(target_os = "ios", target_os = "macos"))))]
fn platform_spawn_suspended(program: &str, arguments: &[&str]) -> Result<i32> {
    let values = spawn_argument_values(program, arguments)?;
    let mut argv = values.iter().map(|value| value.as_ptr()).collect::<Vec<_>>();
    argv.push(std::ptr::null());
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(Error::State(format!(
            "fork failed while starting `{program}` suspended: {}",
            io::Error::last_os_error()
        )));
    }
    if pid == 0 {
        unsafe {
            if libc::raise(libc::SIGSTOP) != 0 {
                libc::_exit(126);
            }
            libc::execvp(values[0].as_ptr(), argv.as_ptr());
            libc::_exit(127);
        }
    }
    Ok(pid)
}

#[cfg(not(unix))]
fn platform_spawn_suspended(_program: &str, _arguments: &[&str]) -> Result<i32> {
    Err(Error::Unsupported(
        "start-suspended executable launch requires an Apple or Unix host".into(),
    ))
}

#[cfg(unix)]
fn spawn_argument_values(program: &str, arguments: &[&str]) -> Result<Vec<std::ffi::CString>> {
    use std::ffi::CString;

    if program.trim().is_empty() {
        return Err(Error::InvalidArgument(
            "suspended-spawn executable must not be empty".into(),
        ));
    }
    let mut values = Vec::with_capacity(arguments.len() + 1);
    values.push(
        CString::new(program)
            .map_err(|_| Error::InvalidArgument("suspended-spawn executable contains an interior NUL byte".into()))?,
    );
    for argument in arguments {
        values
            .push(CString::new(*argument).map_err(|_| {
                Error::InvalidArgument("suspended-spawn argument contains an interior NUL byte".into())
            })?);
    }
    Ok(values)
}

#[cfg(any(target_os = "ios", target_os = "macos"))]
fn spawn_error(operation: &str, error_code: i32) -> Error {
    Error::State(format!(
        "{operation} failed while starting an executable suspended: {}",
        io::Error::from_raw_os_error(error_code)
    ))
}

#[cfg(unix)]
fn is_no_such_process(err: &io::Error) -> bool {
    err.raw_os_error() == Some(libc::ESRCH)
}

#[cfg(not(unix))]
fn is_no_such_process(_err: &io::Error) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        io,
        sync::{Arc, Mutex},
        time::Duration,
    };

    use common::Error;

    use crate::launch::{FrontBoardSceneGate, SpawnControl, SpawnControlAction, SpawnGate};

    use super::{
        run_control_command_capture, ControlOperation, ControlSignal, ProcessControl, ProcessObservation,
        SuspendedSpawn, SuspendedSpawnOptions, SuspendedSpawnState, SystemProcessControl,
    };

    #[derive(Clone)]
    struct FakeProcessControl {
        signals: Arc<Mutex<Vec<ControlSignal>>>,
        actions: Arc<Mutex<Vec<(i32, ControlOperation, SpawnControlAction)>>>,
        observations: Arc<Mutex<VecDeque<ProcessObservation>>>,
        fallback: ProcessObservation,
    }

    impl FakeProcessControl {
        fn new(observations: impl IntoIterator<Item = ProcessObservation>) -> Self {
            Self {
                signals: Arc::new(Mutex::new(Vec::new())),
                actions: Arc::new(Mutex::new(Vec::new())),
                observations: Arc::new(Mutex::new(observations.into_iter().collect())),
                fallback: ProcessObservation::Running,
            }
        }

        fn with_fallback(mut self, fallback: ProcessObservation) -> Self {
            self.fallback = fallback;
            self
        }

        fn recorded_signals(&self) -> Vec<ControlSignal> {
            self.signals.lock().expect("signals lock").clone()
        }

        fn recorded_actions(&self) -> Vec<(i32, ControlOperation, SpawnControlAction)> {
            self.actions.lock().expect("actions lock").clone()
        }
    }

    impl ProcessControl for FakeProcessControl {
        fn signal(&self, _pid: i32, signal: ControlSignal) -> io::Result<()> {
            self.signals.lock().expect("signals lock").push(signal);
            Ok(())
        }

        fn perform_action(
            &self,
            pid: i32,
            operation: ControlOperation,
            action: &SpawnControlAction,
            _gate: Option<&FrontBoardSceneGate>,
        ) -> io::Result<()> {
            self.actions
                .lock()
                .expect("actions lock")
                .push((pid, operation, action.clone()));
            match action {
                SpawnControlAction::Signal(super::SpawnControlSignal::Continue) => {
                    self.signal(pid, ControlSignal::Continue)
                }
                SpawnControlAction::Signal(super::SpawnControlSignal::Kill) => self.signal(pid, ControlSignal::Kill),
                SpawnControlAction::Command(_) => Ok(()),
            }
        }

        fn observe(&self, _pid: i32, _is_child: bool) -> io::Result<ProcessObservation> {
            Ok(self
                .observations
                .lock()
                .expect("observations lock")
                .pop_front()
                .unwrap_or(self.fallback))
        }
    }

    fn short_options() -> SuspendedSpawnOptions {
        SuspendedSpawnOptions {
            confirmation_timeout: Duration::from_millis(10),
            poll_interval: Duration::from_millis(1),
        }
    }

    fn command_control() -> SpawnControl {
        SpawnControl {
            resume: SpawnControlAction::Command("gatectl resume --pid {pid}".into()),
            terminate: SpawnControlAction::Command("gatectl terminate --pid {pid}".into()),
        }
    }

    fn frontboard_gate(pid: i32, state: &str) -> SpawnGate {
        let status = format!(
            "printf '%s\\n' 'IOS_RUSTFRIDA_GATE_STATUS_V1={{\"protocol\":\"ios-rustfrida.bundle-gate-status.v1\",\"bundle_id\":\"com.test.app\",\"pid\":{pid},\"state\":\"{state}\",\"gate\":{{\"id\":\"scene-1\",\"provider\":\"test-provider\",\"mechanism\":\"frontboard-scene\",\"resolution\":\"runtime-dynamic\",\"guarantee\":\"before-first-user-instruction\"}}}}'"
        );
        SpawnGate::FrontBoardScene(FrontBoardSceneGate {
            bundle_id: "com.test.app".into(),
            gate_id: "scene-1".into(),
            provider: "test-provider".into(),
            status: SpawnControlAction::Command(status),
        })
    }

    #[test]
    fn options_reject_unbounded_or_busy_wait_settings() {
        for options in [
            SuspendedSpawnOptions {
                confirmation_timeout: Duration::ZERO,
                poll_interval: Duration::from_millis(1),
            },
            SuspendedSpawnOptions {
                confirmation_timeout: Duration::from_secs(61),
                poll_interval: Duration::from_millis(1),
            },
            SuspendedSpawnOptions {
                confirmation_timeout: Duration::from_secs(1),
                poll_interval: Duration::ZERO,
            },
            SuspendedSpawnOptions {
                confirmation_timeout: Duration::from_millis(1),
                poll_interval: Duration::from_millis(2),
            },
        ] {
            assert!(matches!(options.validate(), Err(Error::InvalidArgument(_))));
        }
    }

    #[test]
    fn frontboard_gate_accepts_live_pid_only_after_held_status() {
        let control = FakeProcessControl::new([ProcessObservation::Running]);
        let observer = control.clone();
        let mut spawned = SuspendedSpawn::managed_with_gate_and_control(
            40,
            SuspendedSpawnState::Suspended,
            short_options(),
            command_control(),
            frontboard_gate(40, "held"),
            Box::new(control),
        );

        spawned
            .confirm_initial_suspension()
            .expect("provider-held process validation");
        assert_eq!(spawned.state(), SuspendedSpawnState::Suspended);
        drop(spawned);
        assert_eq!(observer.recorded_actions().len(), 1);
        assert!(observer.recorded_signals().is_empty());
    }

    #[test]
    fn frontboard_resume_requires_provider_to_report_released() {
        let control = FakeProcessControl::new([]);
        let observer = control.clone();
        let mut spawned = SuspendedSpawn::managed_with_gate_and_control(
            40,
            SuspendedSpawnState::Suspended,
            short_options(),
            command_control(),
            frontboard_gate(40, "released"),
            Box::new(control),
        );

        spawned.resume().expect("provider resume command");
        assert_eq!(spawned.state(), SuspendedSpawnState::Running);
        assert_eq!(
            observer.recorded_actions(),
            vec![(
                40,
                ControlOperation::Resume,
                SpawnControlAction::Command("gatectl resume --pid {pid}".into()),
            )]
        );
    }

    #[test]
    fn frontboard_gate_rejects_released_initial_state() {
        let control = FakeProcessControl::new([ProcessObservation::Running]);
        let mut spawned = SuspendedSpawn::managed_with_gate_and_control(
            40,
            SuspendedSpawnState::Suspended,
            short_options(),
            command_control(),
            frontboard_gate(40, "released"),
            Box::new(control),
        );

        let error = spawned
            .confirm_initial_suspension()
            .expect_err("released gate must fail acquisition");
        assert!(error.to_string().contains("already released"));
        assert_eq!(spawned.state(), SuspendedSpawnState::Running);
    }

    #[test]
    fn simulator_debugger_gate_requires_an_observed_stop() {
        let control = FakeProcessControl::new([ProcessObservation::Stopped]);
        let observer = control.clone();
        let mut spawned = SuspendedSpawn::managed_with_gate_and_control(
            47,
            SuspendedSpawnState::Suspended,
            short_options(),
            SpawnControl::signals(),
            SpawnGate::SimulatorWaitForDebugger,
            Box::new(control),
        );

        spawned.confirm_initial_suspension().expect("simulator debugger stop");
        assert_eq!(spawned.state(), SuspendedSpawnState::Suspended);
        drop(spawned);
        assert_eq!(observer.recorded_signals(), vec![ControlSignal::Kill]);
    }

    #[test]
    fn helper_gate_dispatches_terminate_command_and_waits_for_exit() {
        let control = FakeProcessControl::new([ProcessObservation::Exited]);
        let observer = control.clone();
        let mut spawned = SuspendedSpawn::managed_with_lifecycle_and_control(
            41,
            SuspendedSpawnState::Suspended,
            false,
            short_options(),
            command_control(),
            Box::new(control),
        );

        spawned.terminate().expect("helper terminate command");
        assert_eq!(spawned.state(), SuspendedSpawnState::Terminated);
        assert_eq!(
            observer.recorded_actions(),
            vec![(
                41,
                ControlOperation::Terminate,
                SpawnControlAction::Command("gatectl terminate --pid {pid}".into()),
            )]
        );
        assert!(observer.recorded_signals().is_empty());
    }

    #[test]
    fn dropping_helper_gate_uses_declared_terminate_command() {
        let control = FakeProcessControl::new([]);
        let observer = control.clone();
        let spawned = SuspendedSpawn::managed_with_lifecycle_and_control(
            42,
            SuspendedSpawnState::Suspended,
            false,
            short_options(),
            command_control(),
            Box::new(control),
        );

        drop(spawned);
        assert_eq!(
            observer.recorded_actions(),
            vec![(
                42,
                ControlOperation::Terminate,
                SpawnControlAction::Command("gatectl terminate --pid {pid}".into()),
            )]
        );
        assert!(observer.recorded_signals().is_empty());
    }

    #[test]
    fn host_backend_supplies_control_pid_action_and_pid_template() {
        let action = SpawnControlAction::Command(
            "test \"$IOS_RUSTFRIDA_CONTROL_PID\" = 9876 && test \"$IOS_RUSTFRIDA_CONTROL_ACTION\" = resume && test \"{pid}\" = 9876"
                .into(),
        );

        SystemProcessControl
            .perform_action(9876, ControlOperation::Resume, &action, None)
            .expect("host helper control command");
    }

    #[test]
    fn host_backend_supplies_consistent_frontboard_context_for_all_operations() {
        let gate = FrontBoardSceneGate {
            bundle_id: "com.test.app".into(),
            gate_id: "scene-1".into(),
            provider: "test-provider".into(),
            status: SpawnControlAction::Command("gatectl status".into()),
        };
        let command = concat!(
            "printf '%s|%s|%s|%s|%s|%s\\n' ",
            "\"$IOS_RUSTFRIDA_CONTROL_PID\" ",
            "\"$IOS_RUSTFRIDA_CONTROL_ACTION\" ",
            "\"$IOS_RUSTFRIDA_CONTROL_GATE_ID\" ",
            "\"$IOS_RUSTFRIDA_CONTROL_PROVIDER\" ",
            "\"$IOS_RUSTFRIDA_CONTROL_BUNDLE_ID\" ",
            "\"{pid}|{action}|{gate_id}|{provider}|{bundle_id}\""
        );

        for (operation, label) in [
            (ControlOperation::Status, "status"),
            (ControlOperation::Resume, "resume"),
            (ControlOperation::Terminate, "terminate"),
        ] {
            let output =
                run_control_command_capture(9876, operation, command, Some(&gate)).expect("frontboard control context");
            assert_eq!(
                output.stdout,
                format!(
                    "9876|{label}|scene-1|test-provider|com.test.app|9876|{label}|scene-1|test-provider|com.test.app"
                )
            );
        }
    }

    #[test]
    fn resume_transitions_once_and_leaves_running_process_owned_by_caller() {
        let control = FakeProcessControl::new([]);
        let observer = control.clone();
        let mut spawned = SuspendedSpawn::managed_with_control(
            42,
            SuspendedSpawnState::Suspended,
            true,
            short_options(),
            Box::new(control),
        );

        spawned.resume().expect("resume");
        spawned.resume().expect("idempotent resume");
        assert_eq!(spawned.pid(), 42);
        assert_eq!(spawned.state(), SuspendedSpawnState::Running);
        drop(spawned);
        assert_eq!(observer.recorded_signals(), vec![ControlSignal::Continue]);
    }

    #[test]
    fn terminate_waits_for_exit_and_is_idempotent() {
        let control = FakeProcessControl::new([ProcessObservation::Running, ProcessObservation::Exited]);
        let observer = control.clone();
        let mut spawned = SuspendedSpawn::managed_with_control(
            43,
            SuspendedSpawnState::Suspended,
            true,
            short_options(),
            Box::new(control),
        );

        spawned.terminate().expect("terminate");
        spawned.terminate().expect("idempotent terminate");
        assert_eq!(spawned.state(), SuspendedSpawnState::Terminated);
        assert_eq!(observer.recorded_signals(), vec![ControlSignal::Kill]);
    }

    #[test]
    fn terminate_timeout_keeps_truthful_state_and_drop_retries_kill() {
        let control = FakeProcessControl::new([]).with_fallback(ProcessObservation::Running);
        let observer = control.clone();
        let mut spawned = SuspendedSpawn::managed_with_control(
            44,
            SuspendedSpawnState::Suspended,
            false,
            short_options(),
            Box::new(control),
        );

        assert!(matches!(spawned.terminate(), Err(Error::State(_))));
        assert_eq!(spawned.state(), SuspendedSpawnState::Terminating);
        drop(spawned);
        assert_eq!(
            observer.recorded_signals(),
            vec![ControlSignal::Kill, ControlSignal::Kill]
        );
    }

    #[test]
    fn dropping_unresumed_process_terminates_it() {
        let control = FakeProcessControl::new([]);
        let observer = control.clone();
        let spawned = SuspendedSpawn::managed_with_control(
            45,
            SuspendedSpawnState::Suspended,
            true,
            short_options(),
            Box::new(control),
        );
        drop(spawned);
        assert_eq!(observer.recorded_signals(), vec![ControlSignal::Kill]);
    }

    #[cfg(all(unix, not(any(target_os = "ios", target_os = "macos"))))]
    #[test]
    fn host_executable_is_stopped_before_exec_then_can_resume_and_terminate() {
        let mut spawned = SuspendedSpawn::launch_executable_with_options(
            "/bin/sleep",
            &["30"],
            SuspendedSpawnOptions {
                confirmation_timeout: Duration::from_secs(2),
                poll_interval: Duration::from_millis(2),
            },
        )
        .expect("launch suspended host process");

        assert!(spawned.pid() > 0);
        assert_eq!(spawned.state(), SuspendedSpawnState::Suspended);
        spawned.resume().expect("resume host process");
        assert_eq!(spawned.state(), SuspendedSpawnState::Running);
        spawned.terminate().expect("terminate host process");
        assert_eq!(spawned.state(), SuspendedSpawnState::Terminated);
    }
}
