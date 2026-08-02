//! Text runtime for the controller's bounded multi-session frontend.
//!
//! This module owns terminal-independent input/output and rendering. Platform
//! attach/spawn and raw agent command execution remain injected callbacks, so
//! the runtime can be exercised on a host without pretending to inject there.

use std::{
    fmt,
    io::{self, BufRead, Write},
    sync::{mpsc, Arc},
    thread::{self, JoinHandle},
    time::Duration,
};

use serde_json::Value;

use crate::{
    server::SessionRegistry,
    server_frontend::{
        parse_command, DetachReport, FrontendCommand, FrontendError, FrontendEvent, FrontendMode, HooksAction,
        ListedSession, ServerFrontend, SessionLauncher,
    },
    session::{ExternalHookRelease, ExternalHookSnapshot, Session, SessionCommandFailure, SessionId, SessionSnapshot},
};

const DEFAULT_COMMAND_TIMEOUT: Duration = Duration::from_secs(30);
const DEFAULT_HEALTH_CHECK_INTERVAL: Duration = Duration::from_secs(1);
const DEFAULT_HEALTH_CHECK_TIMEOUT: Duration = Duration::from_secs(1);
const SERVER_PROMPT: &str = "server> ";
const SESSION_HELP: &str = "\
back | server\n\
exit | quit\n\
help\n\
hooks status\n\
hooks release <token>\n\
hooks uninstall <token>\n\
all other input is routed to the active session command backend";

/// Adapter for text commands that are not server-management commands.
pub(crate) trait SessionCommandRouter: Send + Sync {
    fn execute(&self, session: Arc<Session>, command: &str, timeout: Duration) -> Result<Value, SessionCommandFailure>;
}

impl<F> SessionCommandRouter for F
where
    F: Fn(Arc<Session>, &str, Duration) -> Result<Value, SessionCommandFailure> + Send + Sync,
{
    fn execute(&self, session: Arc<Session>, command: &str, timeout: Duration) -> Result<Value, SessionCommandFailure> {
        self(session, command, timeout)
    }
}

/// Production router backed by the command transport installed on `Session`.
/// This keeps normal controller commands and `rpccall` on the same legacy
/// command path used by the single-session REPL.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct BackendSessionCommandRouter;

impl SessionCommandRouter for BackendSessionCommandRouter {
    fn execute(&self, session: Arc<Session>, command: &str, timeout: Duration) -> Result<Value, SessionCommandFailure> {
        session.execute_command(command, timeout)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ServerRuntimeOptions {
    pub command_timeout: Duration,
    pub show_prompts: bool,
    pub health_check_interval: Duration,
    pub health_check_timeout: Duration,
}

impl Default for ServerRuntimeOptions {
    fn default() -> Self {
        Self {
            command_timeout: DEFAULT_COMMAND_TIMEOUT,
            show_prompts: true,
            health_check_interval: DEFAULT_HEALTH_CHECK_INTERVAL,
            health_check_timeout: DEFAULT_HEALTH_CHECK_TIMEOUT,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ServerExitReason {
    ExitCommand,
    EndOfInput,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ServerRunSummary {
    pub reason: ServerExitReason,
    pub detached_sessions: usize,
}

pub(crate) struct ServerRuntime {
    frontend: Arc<ServerFrontend>,
    command_router: Arc<dyn SessionCommandRouter>,
    options: ServerRuntimeOptions,
}

/// Background monitor for long-lived agent connections. The monitor owns no
/// frontend state, so a session disappearing from the registry is enough to
/// make a later active-session lookup reconcile itself.
struct HealthMonitor {
    stop: Option<mpsc::Sender<()>>,
    handle: Option<JoinHandle<()>>,
    events: mpsc::Receiver<DetachReport>,
}

impl HealthMonitor {
    fn start(registry: Arc<SessionRegistry>, interval: Duration, timeout: Duration) -> io::Result<Self> {
        Self::start_inner(registry, None, interval, timeout)
    }

    fn start_for_frontend(frontend: Arc<ServerFrontend>, interval: Duration, timeout: Duration) -> io::Result<Self> {
        Self::start_inner(Arc::clone(frontend.registry()), Some(frontend), interval, timeout)
    }

    fn start_inner(
        registry: Arc<SessionRegistry>,
        frontend: Option<Arc<ServerFrontend>>,
        interval: Duration,
        timeout: Duration,
    ) -> io::Result<Self> {
        let (stop, worker_stop) = mpsc::channel();
        let (worker_events, events) = mpsc::channel();
        let interval = if interval.is_zero() {
            Duration::from_millis(1)
        } else {
            interval
        };
        let handle = thread::Builder::new()
            .name("iosrf-session-health".into())
            .spawn(move || health_loop(registry, frontend, worker_stop, worker_events, interval, timeout))?;
        Ok(Self {
            stop: Some(stop),
            handle: Some(handle),
            events,
        })
    }

    fn drain_events(&self) -> impl Iterator<Item = DetachReport> + '_ {
        self.events.try_iter()
    }
}

impl Drop for HealthMonitor {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

fn health_loop(
    registry: Arc<SessionRegistry>,
    frontend: Option<Arc<ServerFrontend>>,
    stop: mpsc::Receiver<()>,
    events: mpsc::Sender<DetachReport>,
    interval: Duration,
    timeout: Duration,
) {
    loop {
        match stop.recv_timeout(interval) {
            Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => break,
            Err(mpsc::RecvTimeoutError::Timeout) => {}
        }

        for session in registry.attached_sessions() {
            match session.health_check(timeout) {
                Ok(()) => {}
                Err(failure) if failure.is_transport_failure() => {
                    let report = match frontend.as_ref() {
                        Some(frontend) => frontend.reconcile_health_failure(&session, &failure),
                        None => registry
                            .reap_unhealthy(&session, &failure, timeout)
                            .map(DetachReport::from),
                    };
                    if let Some(report) = report {
                        let _ = events.send(report);
                    }
                }
                // Backends that only expose RPC or a custom command path may
                // keep the default probe. Their BadRequest is not a disconnect.
                Err(_) => {}
            }
        }
    }
}

impl ServerRuntime {
    pub(crate) fn new(frontend: Arc<ServerFrontend>, options: ServerRuntimeOptions) -> Self {
        Self::with_command_router(frontend, Arc::new(BackendSessionCommandRouter), options)
    }

    pub(crate) fn with_command_router(
        frontend: Arc<ServerFrontend>,
        command_router: Arc<dyn SessionCommandRouter>,
        options: ServerRuntimeOptions,
    ) -> Self {
        Self {
            frontend,
            command_router,
            options,
        }
    }

    pub(crate) fn run<R: BufRead, W: Write>(&self, input: &mut R, output: &mut W) -> io::Result<ServerRunSummary> {
        let health_monitor = HealthMonitor::start_for_frontend(
            Arc::clone(&self.frontend),
            self.options.health_check_interval,
            self.options.health_check_timeout,
        )?;
        let result = self.run_loop(input, output, &health_monitor);
        if result.is_err() {
            let _ = self.frontend.execute(FrontendCommand::Exit);
        }
        result
    }

    fn run_loop<R: BufRead, W: Write>(
        &self,
        input: &mut R,
        output: &mut W,
        health_monitor: &HealthMonitor,
    ) -> io::Result<ServerRunSummary> {
        let mut health_detached = 0;
        let mut exit_detached = 0;
        loop {
            health_detached += self.flush_health_events(health_monitor, output)?;
            if self.options.show_prompts {
                output.write_all(prompt_for(self.frontend.mode()).as_bytes())?;
                output.flush()?;
            }

            let mut line = String::new();
            if input.read_line(&mut line)? == 0 {
                return self.close_on_eof(output, health_monitor, health_detached);
            }
            let line = line.trim();
            if line.is_empty() {
                continue;
            }

            if let FrontendMode::Session(id) = self.frontend.mode() {
                if matches!(line, "exit" | "quit") {
                    match self.frontend.execute(FrontendCommand::Detach(id)) {
                        Ok(event) => write_rendered(output, render_frontend_event(&event))?,
                        Err(error) => write_rendered(output, render_frontend_error(&error))?,
                    }
                    continue;
                }
            }

            match parse_command(line) {
                Ok(command) => match self.frontend.execute(command) {
                    Ok(event) => {
                        let exit_requested = match &event {
                            FrontendEvent::ExitRequested { detached } => {
                                exit_detached += detached.iter().filter(|report| report.is_clean()).count();
                                true
                            }
                            _ => false,
                        };
                        write_rendered(output, render_frontend_event(&event))?;
                        if exit_requested && self.frontend.is_closed() {
                            return Ok(ServerRunSummary {
                                reason: ServerExitReason::ExitCommand,
                                detached_sessions: health_detached + exit_detached,
                            });
                        }
                    }
                    Err(error) => write_rendered(output, render_frontend_error(&error))?,
                },
                Err(crate::server_frontend::CommandParseError::UnknownCommand(_))
                    if matches!(self.frontend.mode(), FrontendMode::Session(_)) =>
                {
                    self.execute_session_command(line, output)?;
                }
                Err(error) => write_rendered(output, render_frontend_error(&FrontendError::Parse(error)))?,
            }
        }
    }

    fn execute_session_command<W: Write>(&self, command: &str, output: &mut W) -> io::Result<()> {
        let session = match self.frontend.active_session() {
            Ok(session) => session,
            Err(error) => {
                return write_rendered(output, render_frontend_error(&error));
            }
        };
        let id = session.id();
        let result = self
            .command_router
            .execute(Arc::clone(&session), command, self.options.command_timeout);
        match result {
            Ok(value) => write_rendered(output, render_session_result(id, &value)),
            Err(error) => {
                write_rendered(output, render_session_error(id, &error))?;
                if error.is_transport_failure() {
                    if let Some(report) = self.frontend.reconcile_command_transport_failure(&session, &error) {
                        write_rendered(output, format!("reconcile {}\n", render_detach_report(&report)))?;
                    }
                }
                Ok(())
            }
        }
    }

    fn close_on_eof<W: Write>(
        &self,
        output: &mut W,
        health_monitor: &HealthMonitor,
        mut health_detached: usize,
    ) -> io::Result<ServerRunSummary> {
        health_detached += self.flush_health_events(health_monitor, output)?;
        match self.frontend.execute(FrontendCommand::Exit) {
            Ok(event @ FrontendEvent::ExitRequested { .. }) => {
                let detached_sessions = match &event {
                    FrontendEvent::ExitRequested { detached } => {
                        detached.iter().filter(|report| report.is_clean()).count()
                    }
                    _ => unreachable!("matched exit event"),
                };
                write_rendered(output, render_frontend_event(&event))?;
                Ok(ServerRunSummary {
                    reason: ServerExitReason::EndOfInput,
                    detached_sessions: health_detached + detached_sessions,
                })
            }
            Ok(event) => {
                write_rendered(output, render_frontend_event(&event))?;
                Ok(ServerRunSummary {
                    reason: ServerExitReason::EndOfInput,
                    detached_sessions: 0,
                })
            }
            Err(FrontendError::Closed) => Ok(ServerRunSummary {
                reason: ServerExitReason::EndOfInput,
                detached_sessions: 0,
            }),
            Err(error) => {
                write_rendered(output, render_frontend_error(&error))?;
                Ok(ServerRunSummary {
                    reason: ServerExitReason::EndOfInput,
                    detached_sessions: 0,
                })
            }
        }
    }

    fn flush_health_events<W: Write>(&self, health_monitor: &HealthMonitor, output: &mut W) -> io::Result<usize> {
        let mut detached = 0;
        for report in health_monitor.drain_events() {
            if report.is_clean() {
                detached += 1;
            }
            write_rendered(output, format!("health {}\n", render_detach_report(&report)))?;
        }
        Ok(detached)
    }
}

/// Build a frontend from the supplied launcher and run it over arbitrary text
/// streams. This is the primary integration point for tests and embedders.
pub(crate) fn run_with_launcher<R: BufRead, W: Write>(
    registry: Arc<SessionRegistry>,
    launcher: Arc<dyn SessionLauncher>,
    options: ServerRuntimeOptions,
    input: &mut R,
    output: &mut W,
) -> io::Result<ServerRunSummary> {
    let frontend = Arc::new(ServerFrontend::new(registry, launcher));
    ServerRuntime::new(frontend, options).run(input, output)
}

pub(crate) fn run_with_launcher_and_router<R: BufRead, W: Write>(
    registry: Arc<SessionRegistry>,
    launcher: Arc<dyn SessionLauncher>,
    command_router: Arc<dyn SessionCommandRouter>,
    options: ServerRuntimeOptions,
    input: &mut R,
    output: &mut W,
) -> io::Result<ServerRunSummary> {
    let frontend = Arc::new(ServerFrontend::new(registry, launcher));
    ServerRuntime::with_command_router(frontend, command_router, options).run(input, output)
}

/// Standard-input runner kept separate from argument parsing and platform
/// setup. The main thread supplies concrete launcher and command callbacks.
pub(crate) fn run_stdio_with_launcher(
    registry: Arc<SessionRegistry>,
    launcher: Arc<dyn SessionLauncher>,
    options: ServerRuntimeOptions,
) -> io::Result<ServerRunSummary> {
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut input = stdin.lock();
    let mut output = stdout.lock();
    run_with_launcher(registry, launcher, options, &mut input, &mut output)
}

pub(crate) fn render_frontend_event(event: &FrontendEvent) -> String {
    match event {
        FrontendEvent::LaunchAccepted(snapshot) => format!("launch {}\n", render_snapshot(snapshot, false)),
        FrontendEvent::Sessions(sessions) => render_sessions(sessions),
        FrontendEvent::HooksStatus { session, hooks } => render_hooks_status(*session, hooks),
        FrontendEvent::HooksAction {
            session,
            action,
            result,
        } => render_hooks_action(*session, *action, result),
        FrontendEvent::ModeChanged { previous, current } => {
            format!("mode {} -> {}\n", render_mode(*previous), render_mode(*current))
        }
        FrontendEvent::Detached(report) => format!("detach {}\n", render_detach_report(report)),
        FrontendEvent::DetachedAll(reports) => render_report_group("detachall", reports),
        FrontendEvent::Help { mode, text } => {
            let help = match mode {
                FrontendMode::Server => *text,
                FrontendMode::Session(_) => SESSION_HELP,
            };
            format!("help mode={}\n{help}\n", render_mode(*mode))
        }
        FrontendEvent::ExitRequested { detached } => render_report_group("exit", detached),
    }
}

pub(crate) fn render_frontend_error(error: &FrontendError) -> String {
    match error {
        FrontendError::Hook(hook_error) => {
            let mut rendered = format!(
                "error: hooks session#{} action={} token={} error={}",
                hook_error.session,
                hook_error.action.as_str(),
                hook_error.token,
                quoted(&hook_error.error.to_string())
            );
            if let Some(snapshot) = &hook_error.snapshot {
                rendered.push(' ');
                rendered.push_str(&render_hook_snapshot(snapshot));
            }
            rendered.push('\n');
            rendered
        }
        _ => format!("error: {error}\n"),
    }
}

pub(crate) fn render_session_result(id: SessionId, value: &Value) -> String {
    format!("session #{id} result={}\n", compact_json(value))
}

pub(crate) fn render_session_error(id: SessionId, error: &SessionCommandFailure) -> String {
    format!("session #{id} error={value}\n", value = quoted(&error.to_string()))
}

fn render_sessions(sessions: &[ListedSession]) -> String {
    let mut rendered = format!("sessions count={}\n", sessions.len());
    for session in sessions {
        rendered.push_str(&render_snapshot(&session.snapshot, session.active));
        rendered.push('\n');
    }
    rendered
}

fn render_hooks_status(session: SessionId, hooks: &[ExternalHookSnapshot]) -> String {
    let mut rendered = format!("hooks session#{session} status count={}\n", hooks.len());
    for snapshot in hooks {
        rendered.push_str(&render_hook_snapshot(snapshot));
        rendered.push('\n');
    }
    rendered
}

fn render_hooks_action(session: SessionId, action: HooksAction, result: &ExternalHookRelease) -> String {
    format!(
        "hooks session#{session} action={} released_now={} {}\n",
        action.as_str(),
        result.released_now,
        render_hook_snapshot(&result.snapshot)
    )
}

fn render_hook_snapshot(snapshot: &ExternalHookSnapshot) -> String {
    let last_error = snapshot
        .last_error
        .as_deref()
        .map(quoted)
        .unwrap_or_else(|| "null".into());
    format!(
        "token={} backend={} operation={} ownership={} target_state={} native_uninstall={} last_error={last_error}",
        snapshot.token,
        snapshot.backend.as_str(),
        render_hook_operation(snapshot.operation),
        snapshot.ownership.as_status(),
        snapshot.target_state.as_status(),
        snapshot.native_uninstall.as_status(),
    )
}

fn render_hook_operation(operation: native_api::ExternalHookOperation) -> &'static str {
    match operation {
        native_api::ExternalHookOperation::Install => "install",
        native_api::ExternalHookOperation::Replace => "replace",
        native_api::ExternalHookOperation::Uninstall => "uninstall",
    }
}

fn render_report_group(operation: &str, reports: &[DetachReport]) -> String {
    let detached = reports.iter().filter(|report| report.is_clean()).count();
    let failed = reports.iter().filter(|report| report.failure.is_some()).count();
    let pending = reports.iter().filter(|report| !report.is_clean()).count();
    let mut rendered = format!("{operation} detached={detached}\n");
    for report in reports {
        rendered.push_str(&render_detach_report(report));
        rendered.push('\n');
    }
    if !reports.is_empty() {
        rendered.push_str(&format!(
            "{operation} summary attempted={} failed={failed} pending={pending}\n",
            reports.len()
        ));
    }
    rendered
}

fn render_detach_report(report: &DetachReport) -> String {
    let mut rendered = render_snapshot(&report.snapshot, false);
    if let Some(failure) = &report.failure {
        rendered.push_str(" detach_error=");
        rendered.push_str(&quoted(&failure.to_string()));
    }
    if !report.snapshot.external_hooks.is_empty() {
        rendered.push_str(" hooks=");
        rendered.push('[');
        for (index, hook) in report.snapshot.external_hooks.iter().enumerate() {
            if index > 0 {
                rendered.push(';');
            }
            rendered.push_str(&render_hook_snapshot(hook));
        }
        rendered.push(']');
    }
    rendered
}

fn render_snapshot(snapshot: &SessionSnapshot, active: bool) -> String {
    let pid = snapshot.pid.map_or_else(|| "-".into(), |pid| pid.to_string());
    let marker = if active { "*" } else { "-" };
    let mut rendered = format!(
        "{marker} #{} status={} pid={pid} label={}",
        snapshot.id,
        snapshot.status(),
        quoted(&snapshot.label)
    );
    if let Some(error) = &snapshot.last_error {
        rendered.push_str(" last_error=");
        rendered.push_str(&quoted(error));
    }
    rendered
}

fn render_mode(mode: FrontendMode) -> String {
    match mode {
        FrontendMode::Server => "server".into(),
        FrontendMode::Session(id) => format!("session#{id}"),
    }
}

fn prompt_for(mode: FrontendMode) -> String {
    match mode {
        FrontendMode::Server => SERVER_PROMPT.into(),
        FrontendMode::Session(id) => format!("session#{id}> "),
    }
}

fn quoted(value: &str) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| "\"<unrenderable>\"".into())
}

fn compact_json(value: &Value) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| "null".into())
}

fn write_rendered<W: Write>(output: &mut W, rendered: String) -> io::Result<()> {
    output.write_all(rendered.as_bytes())?;
    output.flush()
}

impl fmt::Debug for ServerRuntime {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ServerRuntime")
            .field("mode", &self.frontend.mode())
            .field("options", &self.options)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::{
        render_frontend_error, render_frontend_event, run_with_launcher, run_with_launcher_and_router, HealthMonitor,
        ServerExitReason, ServerRuntimeOptions, SessionCommandRouter,
    };
    use crate::{
        server::SessionRegistry,
        server_frontend::{
            AttachRequest, AttachTarget, DetachReport, FrontendCommand, FrontendError, FrontendEvent, FrontendMode,
            HookCommandError, HooksAction, LaunchReservation, LauncherFailure, ServerFrontend, SessionLauncher,
            SpawnRequest,
        },
        session::{
            ExternalHookNativeUninstall, ExternalHookOwnership, ExternalHookRelease, ExternalHookSnapshot,
            ExternalHookTargetState, SessionCommandBackend, SessionCommandFailure, SessionHookError, SessionSnapshot,
            SessionState,
        },
    };
    use native_api::ExternalHookOperation;
    use serde_json::{json, Value};
    use std::{
        io::Cursor,
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc, Mutex,
        },
        thread,
        time::{Duration, Instant},
    };

    #[derive(Default)]
    struct RecordingBackend {
        rpc_calls: Mutex<Vec<(String, Value)>>,
        commands: Mutex<Vec<String>>,
    }

    impl SessionCommandBackend for RecordingBackend {
        fn rpc_call(&self, method: &str, args: &Value, _timeout: Duration) -> Result<Value, SessionCommandFailure> {
            self.rpc_calls
                .lock()
                .expect("RPC calls")
                .push((method.into(), args.clone()));
            Ok(args.clone())
        }

        fn execute_command(&self, command: &str, _timeout: Duration) -> Result<Value, SessionCommandFailure> {
            self.commands.lock().expect("commands").push(command.into());
            match command {
                "rpccall echo [1,true]" => Ok(json!([1, true])),
                other => Ok(json!({ "command": other })),
            }
        }
    }

    struct ImmediateLauncher {
        backend: Arc<RecordingBackend>,
    }

    impl SessionLauncher for ImmediateLauncher {
        fn attach(&self, reservation: LaunchReservation, request: AttachRequest) -> Result<(), LauncherFailure> {
            let (pid, label) = match request.target {
                AttachTarget::Pid(pid) => (Some(pid), format!("pid-{pid}")),
                AttachTarget::Name(name) => (Some(500), name),
            };
            reservation
                .complete(pid, label, self.backend.clone())
                .map_err(|error| LauncherFailure::new(error.to_string()))
        }

        fn spawn(&self, reservation: LaunchReservation, request: SpawnRequest) -> Result<(), LauncherFailure> {
            reservation
                .complete(Some(600), request.target, self.backend.clone())
                .map_err(|error| LauncherFailure::new(error.to_string()))
        }
    }

    struct LatePublishingBackend {
        registry: Arc<SessionRegistry>,
        published: Arc<AtomicUsize>,
    }

    impl SessionCommandBackend for LatePublishingBackend {
        fn rpc_call(&self, _method: &str, args: &Value, _timeout: Duration) -> Result<Value, SessionCommandFailure> {
            Ok(args.clone())
        }

        fn detach(&self, _timeout: Duration) -> Result<(), SessionCommandFailure> {
            if self.published.fetch_add(1, Ordering::SeqCst) == 0 {
                self.registry
                    .attach(Some(99), "late-session", Arc::new(RecordingBackend::default()))
                    .expect("publish late session");
            }
            Ok(())
        }
    }

    struct LatePublishingLauncher {
        registry: Arc<SessionRegistry>,
        published: Arc<AtomicUsize>,
    }

    impl SessionLauncher for LatePublishingLauncher {
        fn attach(&self, reservation: LaunchReservation, request: AttachRequest) -> Result<(), LauncherFailure> {
            let pid = match request.target {
                AttachTarget::Pid(pid) => pid,
                AttachTarget::Name(_) => 42,
            };
            let backend: Arc<dyn SessionCommandBackend> = Arc::new(LatePublishingBackend {
                registry: Arc::clone(&self.registry),
                published: Arc::clone(&self.published),
            });
            reservation
                .complete(Some(pid), format!("pid-{pid}"), backend)
                .map_err(|error| LauncherFailure::new(error.to_string()))
        }

        fn spawn(&self, _reservation: LaunchReservation, _request: SpawnRequest) -> Result<(), LauncherFailure> {
            Err(LauncherFailure::new("unused"))
        }
    }

    fn run(
        input: &str,
        capacity: usize,
    ) -> (
        String,
        super::ServerRunSummary,
        Arc<SessionRegistry>,
        Arc<RecordingBackend>,
    ) {
        let registry = Arc::new(SessionRegistry::with_capacity(capacity).expect("registry"));
        let backend = Arc::new(RecordingBackend::default());
        let launcher: Arc<dyn SessionLauncher> = Arc::new(ImmediateLauncher {
            backend: backend.clone(),
        });
        let mut input = Cursor::new(input.as_bytes());
        let mut output = Vec::new();
        let summary = run_with_launcher(
            Arc::clone(&registry),
            launcher,
            ServerRuntimeOptions::default(),
            &mut input,
            &mut output,
        )
        .expect("run server runtime");
        (
            String::from_utf8(output).expect("UTF-8 output"),
            summary,
            registry,
            backend,
        )
    }

    fn run_with_router(
        input: &str,
        capacity: usize,
        router: Arc<dyn SessionCommandRouter>,
    ) -> (
        String,
        super::ServerRunSummary,
        Arc<SessionRegistry>,
        Arc<RecordingBackend>,
    ) {
        let registry = Arc::new(SessionRegistry::with_capacity(capacity).expect("registry"));
        let backend = Arc::new(RecordingBackend::default());
        let launcher: Arc<dyn SessionLauncher> = Arc::new(ImmediateLauncher {
            backend: backend.clone(),
        });
        let mut input = Cursor::new(input.as_bytes());
        let mut output = Vec::new();
        let summary = run_with_launcher_and_router(
            Arc::clone(&registry),
            launcher,
            router,
            ServerRuntimeOptions::default(),
            &mut input,
            &mut output,
        )
        .expect("run server runtime");
        (
            String::from_utf8(output).expect("UTF-8 output"),
            summary,
            registry,
            backend,
        )
    }

    #[test]
    fn runtime_retries_exit_when_a_clean_report_leaves_a_registry_owner() {
        let registry = Arc::new(SessionRegistry::with_capacity(2).expect("registry"));
        let published = Arc::new(AtomicUsize::new(0));
        let launcher: Arc<dyn SessionLauncher> = Arc::new(LatePublishingLauncher {
            registry: Arc::clone(&registry),
            published,
        });
        let mut input = Cursor::new("attach 42\nexit\nlist\nexit\n".as_bytes());
        let mut output = Vec::new();
        let summary = run_with_launcher(
            Arc::clone(&registry),
            launcher,
            ServerRuntimeOptions {
                health_check_interval: Duration::from_secs(60),
                ..ServerRuntimeOptions::default()
            },
            &mut input,
            &mut output,
        )
        .expect("run server runtime");

        assert_eq!(summary.reason, ServerExitReason::ExitCommand);
        assert_eq!(summary.detached_sessions, 2);
        assert!(registry.is_empty());
        let output = String::from_utf8(output).expect("UTF-8 output");
        assert!(output.contains("sessions count=1"));
        assert_eq!(output.matches("exit detached=").count(), 2);
    }

    #[test]
    fn hooks_rendering_preserves_idempotent_release_state() {
        let session = "1".parse().expect("session id");
        let event = FrontendEvent::HooksAction {
            session,
            action: HooksAction::Release,
            result: ExternalHookRelease {
                released_now: false,
                snapshot: ExternalHookSnapshot {
                    token: 77,
                    backend: native_api::ExternalHookBackendKind::ElleKit,
                    operation: ExternalHookOperation::Install,
                    ownership: ExternalHookOwnership::Released,
                    native_uninstall: ExternalHookNativeUninstall::Unavailable,
                    target_state: ExternalHookTargetState::Installed,
                    last_error: None,
                },
            },
        };
        let rendered = render_frontend_event(&event);
        assert!(rendered.contains("action=release released_now=false"));
        assert!(rendered.contains("token=77"));
        assert!(rendered.contains("ownership=released"));
        assert!(rendered.contains("target_state=installed"));
        assert!(rendered.contains("native_uninstall=unavailable"));
        assert!(rendered.contains("last_error=null"));
    }

    #[test]
    fn unavailable_uninstall_error_renders_preserved_owned_state() {
        let session = "1".parse().expect("session id");
        let snapshot = ExternalHookSnapshot {
            token: 78,
            backend: native_api::ExternalHookBackendKind::ElleKit,
            operation: ExternalHookOperation::Install,
            ownership: ExternalHookOwnership::Owned,
            native_uninstall: ExternalHookNativeUninstall::Unavailable,
            target_state: ExternalHookTargetState::Installed,
            last_error: Some(
                "native uninstall unavailable; target remains installed; ownership retained (ellekit)".into(),
            ),
        };
        let error = FrontendError::Hook(HookCommandError {
            session,
            action: HooksAction::Uninstall,
            token: 78,
            error: SessionHookError::NativeUninstallUnavailable {
                token: 78,
                backend: native_api::ExternalHookBackendKind::ElleKit,
            },
            snapshot: Some(snapshot),
        });
        let rendered = render_frontend_error(&error);
        assert!(rendered.contains("action=uninstall token=78"));
        assert!(rendered.contains("native uninstall is unavailable"));
        assert!(rendered.contains("ownership=owned"));
        assert!(rendered.contains("target_state=installed"));
        assert!(rendered.contains("native_uninstall=unavailable"));
        assert!(rendered.contains(
            "last_error=\"native uninstall unavailable; target remains installed; ownership retained (ellekit)\""
        ));
    }

    #[test]
    fn detach_group_rendering_reports_pending_cleanup_and_hook_state() {
        let event = FrontendEvent::DetachedAll(vec![DetachReport {
            snapshot: SessionSnapshot {
                id: "2".parse().expect("session id"),
                pid: Some(42),
                label: "pending".into(),
                state: SessionState::Failed,
                last_error: Some("transport lost; cleanup pending".into()),
                external_hooks: vec![ExternalHookSnapshot {
                    token: 90,
                    backend: native_api::ExternalHookBackendKind::Substrate,
                    operation: ExternalHookOperation::Replace,
                    ownership: ExternalHookOwnership::Owned,
                    native_uninstall: ExternalHookNativeUninstall::Unavailable,
                    target_state: ExternalHookTargetState::Installed,
                    last_error: Some("lease release failed".into()),
                }],
            },
            failure: Some(SessionCommandFailure::Unavailable("shutdown timed out".into())),
        }]);

        let rendered = render_frontend_event(&event);
        assert!(rendered.starts_with("detachall detached=0\n"));
        assert!(rendered.contains("status=failed"));
        assert!(rendered.contains("detach_error=\"session unavailable: shutdown timed out\""));
        assert!(rendered.contains("token=90 backend=substrate operation=replace ownership=owned"));
        assert!(rendered.contains("target_state=installed native_uninstall=unavailable"));
        assert!(rendered.ends_with("detachall summary attempted=1 failed=1 pending=1\n"));
    }

    #[test]
    fn session_mode_hooks_commands_use_frontend_path() {
        let (output, summary, registry, backend) = run("attach 42\nuse 1\nhooks status\nback\nexit\n", 1);
        assert!(output.contains("session#1> hooks session#1 status count=0\n"));
        assert_eq!(summary.reason, ServerExitReason::ExitCommand);
        assert!(registry.is_empty());
        assert!(backend.commands.lock().expect("commands").is_empty());
    }

    #[test]
    fn repl_runs_management_and_rpc_commands_with_stable_rendering() {
        let (output, summary, registry, backend) =
            run("attach 42\nuse 1\nrpccall echo [1,true]\nback\ndetach 1\nexit\n", 2);
        assert_eq!(
            output,
            "server> launch - #1 status=connected pid=42 label=\"pid-42\"\n\
server> mode server -> session#1\n\
session#1> session #1 result=[1,true]\n\
session#1> mode session#1 -> server\n\
server> detach - #1 status=disconnected pid=42 label=\"pid-42\"\n\
server> exit detached=0\n"
        );
        assert_eq!(summary.reason, ServerExitReason::ExitCommand);
        assert_eq!(summary.detached_sessions, 0);
        assert!(registry.is_empty());
        assert_eq!(
            backend.commands.lock().expect("commands").as_slice(),
            &["rpccall echo [1,true]"]
        );
        assert!(backend.rpc_calls.lock().expect("RPC calls").is_empty());
    }

    #[test]
    fn arbitrary_session_commands_use_injected_router_only_when_active() {
        let routed = Arc::new(Mutex::new(Vec::new()));
        let router: Arc<dyn SessionCommandRouter> = {
            let routed = Arc::clone(&routed);
            Arc::new(
                move |session: Arc<crate::session::Session>, command: &str, _timeout: Duration| {
                    routed
                        .lock()
                        .expect("routed")
                        .push((session.id().get(), command.to_string()));
                    Ok(json!({ "handled": command }))
                },
            )
        };
        let (output, _, _, _) = run_with_router(
            "unknown-server-command\nattach 7\nuse 1\nobjc.classes\ndetach\nback\nexit\n",
            2,
            router,
        );
        assert_eq!(routed.lock().expect("routed").as_slice(), &[(1, "objc.classes".into())]);
        assert!(output.contains("error: unknown server command `unknown-server-command`\n"));
        assert!(output.contains("session #1 result={\"handled\":\"objc.classes\"}\n"));
        assert!(output.contains("error: missing argument for `detach`; usage: detach <session-id>\n"));
    }

    #[test]
    fn exit_in_session_mode_detaches_that_session_but_keeps_server_running() {
        let (output, summary, registry, _) = run("spawn app\nuse 1\nexit\nlist\nexit\n", 1);
        assert!(output.contains("session#1> detach - #1 status=disconnected pid=600 label=\"app\"\n"));
        assert!(output.contains("server> sessions count=0\n"));
        assert_eq!(summary.reason, ServerExitReason::ExitCommand);
        assert!(registry.is_empty());
    }

    #[test]
    fn eof_detaches_reserved_sessions_and_reports_reason() {
        let (output, summary, registry, _) = run("attach 9\n", 1);
        assert_eq!(summary.reason, ServerExitReason::EndOfInput);
        assert_eq!(summary.detached_sessions, 1);
        assert!(output.contains("exit detached=1\n- #1 status=disconnected pid=9 label=\"pid-9\"\n"));
        assert!(registry.is_empty());
    }

    #[test]
    fn router_failure_is_rendered_and_the_repl_continues() {
        let router: Arc<dyn SessionCommandRouter> = Arc::new(
            |_session: Arc<crate::session::Session>, _command: &str, _timeout: Duration| {
                Err(SessionCommandFailure::Unavailable("transport offline".into()))
            },
        );
        let (output, summary, _, _) = run_with_router("attach 3\nuse 1\nping\nback\nexit\n", 1, router);
        assert!(output.contains("session #1 error=\"session unavailable: transport offline\"\n"));
        assert!(output.contains(
            "reconcile - #1 status=disconnected pid=3 label=\"pid-3\" last_error=\"command transport failed:"
        ));
        assert!(output.contains("error: no session is active\n"));
        assert_eq!(summary.reason, ServerExitReason::ExitCommand);
    }

    #[test]
    fn ordinary_commands_use_session_execute_command_backend() {
        let (output, _, _, backend) = run("attach 4\nuse 1\nnative.images\nback\nexit\n", 1);
        assert!(output.contains("session #1 result={\"command\":\"native.images\"}\n"));
        assert_eq!(
            backend.commands.lock().expect("commands").as_slice(),
            &["native.images"]
        );
        assert!(backend.rpc_calls.lock().expect("RPC calls").is_empty());
    }

    struct OfflineBackend {
        detach_count: AtomicUsize,
    }

    impl SessionCommandBackend for OfflineBackend {
        fn rpc_call(&self, _method: &str, _args: &Value, _timeout: Duration) -> Result<Value, SessionCommandFailure> {
            Err(SessionCommandFailure::Unavailable("agent socket closed".into()))
        }

        fn health_check(&self, _timeout: Duration) -> Result<(), SessionCommandFailure> {
            Err(SessionCommandFailure::Unavailable("agent socket closed".into()))
        }

        fn detach(&self, _timeout: Duration) -> Result<(), SessionCommandFailure> {
            self.detach_count.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    #[test]
    fn health_monitor_reaps_transport_failure_and_stops_cleanly() {
        let registry = Arc::new(SessionRegistry::with_capacity(1).expect("registry"));
        let backend = Arc::new(OfflineBackend {
            detach_count: AtomicUsize::new(0),
        });
        let session = registry.attach(Some(42), "offline", backend.clone()).expect("attach");
        let monitor = HealthMonitor::start(
            Arc::clone(&registry),
            Duration::from_millis(5),
            Duration::from_millis(10),
        )
        .expect("start health monitor");

        let deadline = Instant::now() + Duration::from_secs(1);
        while !registry.is_empty() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(5));
        }
        drop(monitor);

        assert!(registry.is_empty());
        assert_eq!(session.state(), crate::session::SessionState::Detached);
        assert!(session
            .snapshot()
            .last_error
            .as_deref()
            .is_some_and(|error| error.contains("health check failed")));
        assert_eq!(backend.detach_count.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn health_monitor_reconciles_active_frontend_and_emits_report() {
        let registry = Arc::new(SessionRegistry::with_capacity(1).expect("registry"));
        let backend = Arc::new(OfflineBackend {
            detach_count: AtomicUsize::new(0),
        });
        let session = registry.attach(Some(42), "offline", backend.clone()).expect("attach");
        let launcher: Arc<dyn SessionLauncher> = Arc::new(ImmediateLauncher {
            backend: Arc::new(RecordingBackend::default()),
        });
        let frontend = Arc::new(ServerFrontend::new(Arc::clone(&registry), launcher));
        frontend
            .execute(FrontendCommand::Use(session.id()))
            .expect("activate session");
        let monitor = HealthMonitor::start_for_frontend(
            Arc::clone(&frontend),
            Duration::from_millis(5),
            Duration::from_millis(10),
        )
        .expect("start health monitor");

        let deadline = Instant::now() + Duration::from_secs(1);
        let mut reports = Vec::new();
        while reports.is_empty() && Instant::now() < deadline {
            reports.extend(monitor.drain_events());
            thread::sleep(Duration::from_millis(5));
        }
        drop(monitor);

        assert!(registry.is_empty());
        assert_eq!(frontend.mode(), FrontendMode::Server);
        assert_eq!(reports.len(), 1);
        assert!(reports[0].is_clean());
        assert!(reports[0]
            .snapshot
            .last_error
            .as_deref()
            .is_some_and(|error| error.contains("health check failed")));
        assert_eq!(backend.detach_count.load(Ordering::SeqCst), 1);
    }
}
