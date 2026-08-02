//! Stateful command core for the bounded multi-session controller frontend.
//!
//! Terminal, HTTP, and platform injection details intentionally stay outside
//! this module. A caller parses and executes management commands here, then
//! renders the returned event for its own transport.

use std::{
    fmt,
    sync::{Arc, Mutex, MutexGuard},
    time::Duration,
};

use crate::{
    server::{DetachOutcome, SessionRegistry, SessionRegistryError},
    session::{
        ExternalHookRelease, ExternalHookSnapshot, Session, SessionCommandBackend, SessionCommandFailure,
        SessionHookError, SessionId, SessionSnapshot, SessionState, SessionTransitionError,
    },
};

const DEFAULT_DETACH_TIMEOUT: Duration = Duration::from_secs(1);

pub(crate) const SERVER_HELP: &str = "\
attach <pid|name> [-l script.js]\n\
spawn <bundle-id> [-l script.js]\n\
list | sessions\n\
use <session-id>\n\
hooks status|release <token>|uninstall <token> (active session)\n\
detach <session-id>\n\
detachall\n\
back\n\
help\n\
exit | quit";

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum AttachTarget {
    Pid(i32),
    Name(String),
}

impl AttachTarget {
    fn reservation_metadata(&self) -> (Option<i32>, String) {
        match self {
            Self::Pid(pid) => (Some(*pid), format!("PID:{pid}")),
            Self::Name(name) => (None, name.clone()),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AttachRequest {
    pub target: AttachTarget,
    pub script: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SpawnRequest {
    pub target: String,
    pub script: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum HooksCommand {
    Status,
    Release(u64),
    Uninstall(u64),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum FrontendCommand {
    Attach(AttachRequest),
    Spawn(SpawnRequest),
    Hooks(HooksCommand),
    List,
    Use(SessionId),
    Detach(SessionId),
    DetachAll,
    Back,
    Help,
    Exit,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum CommandParseError {
    Empty,
    UnknownCommand(String),
    MissingArgument {
        command: &'static str,
        usage: &'static str,
    },
    UnexpectedArgument {
        command: &'static str,
        value: String,
    },
    UnknownOption {
        command: &'static str,
        option: String,
    },
    MissingOptionValue {
        command: &'static str,
        option: String,
    },
    DuplicateOption {
        command: &'static str,
        option: &'static str,
    },
    InvalidTarget {
        command: &'static str,
        value: String,
        reason: String,
    },
    InvalidSessionId {
        value: String,
        reason: String,
    },
    UnknownHooksAction(String),
    InvalidHookToken {
        value: String,
        reason: String,
    },
    UnterminatedQuote(char),
    DanglingEscape,
}

impl fmt::Display for CommandParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("command is empty"),
            Self::UnknownCommand(command) => write!(formatter, "unknown server command `{command}`"),
            Self::MissingArgument { command, usage } => {
                write!(formatter, "missing argument for `{command}`; usage: {usage}")
            }
            Self::UnexpectedArgument { command, value } => {
                write!(formatter, "unexpected argument `{value}` for `{command}`")
            }
            Self::UnknownOption { command, option } => write!(formatter, "unknown option `{option}` for `{command}`"),
            Self::MissingOptionValue { command, option } => {
                write!(formatter, "option `{option}` for `{command}` requires a value")
            }
            Self::DuplicateOption { command, option } => {
                write!(
                    formatter,
                    "option `{option}` was provided more than once for `{command}`"
                )
            }
            Self::InvalidTarget { command, value, reason } => {
                write!(formatter, "invalid target `{value}` for `{command}`: {reason}")
            }
            Self::InvalidSessionId { value, reason } => write!(formatter, "invalid session ID `{value}`: {reason}"),
            Self::UnknownHooksAction(action) => {
                write!(
                    formatter,
                    "unknown hooks action `{action}`; usage: hooks status|release <token>|uninstall <token>"
                )
            }
            Self::InvalidHookToken { value, reason } => {
                write!(formatter, "invalid external hook token `{value}`: {reason}")
            }
            Self::UnterminatedQuote(quote) => write!(formatter, "unterminated `{quote}` quote"),
            Self::DanglingEscape => formatter.write_str("command ends with an incomplete escape"),
        }
    }
}

impl std::error::Error for CommandParseError {}

pub(crate) fn parse_command(line: &str) -> Result<FrontendCommand, CommandParseError> {
    let words = tokenize(line)?;
    let (command, args) = words.split_first().ok_or(CommandParseError::Empty)?;
    match command.as_str() {
        "attach" => parse_attach(args).map(FrontendCommand::Attach),
        "spawn" => parse_spawn(args).map(FrontendCommand::Spawn),
        "hooks" => parse_hooks(args).map(FrontendCommand::Hooks),
        "list" | "sessions" => {
            expect_no_args("list", args)?;
            Ok(FrontendCommand::List)
        }
        "use" => parse_session_id_arg("use", args).map(FrontendCommand::Use),
        "detach" => parse_session_id_arg("detach", args).map(FrontendCommand::Detach),
        "detachall" => {
            expect_no_args("detachall", args)?;
            Ok(FrontendCommand::DetachAll)
        }
        "back" | "server" => {
            expect_no_args("back", args)?;
            Ok(FrontendCommand::Back)
        }
        "help" => {
            expect_no_args("help", args)?;
            Ok(FrontendCommand::Help)
        }
        "exit" | "quit" => {
            expect_no_args("exit", args)?;
            Ok(FrontendCommand::Exit)
        }
        other => Err(CommandParseError::UnknownCommand(other.into())),
    }
}

fn parse_hooks(args: &[String]) -> Result<HooksCommand, CommandParseError> {
    let action = args.first().ok_or(CommandParseError::MissingArgument {
        command: "hooks",
        usage: "hooks status|release <token>|uninstall <token>",
    })?;
    match action.as_str() {
        "status" => {
            expect_no_args("hooks status", &args[1..])?;
            Ok(HooksCommand::Status)
        }
        "release" => parse_hooks_token("hooks release", "hooks release <token>", &args[1..]).map(HooksCommand::Release),
        "uninstall" => {
            parse_hooks_token("hooks uninstall", "hooks uninstall <token>", &args[1..]).map(HooksCommand::Uninstall)
        }
        other => Err(CommandParseError::UnknownHooksAction(other.into())),
    }
}

fn parse_hooks_token(command: &'static str, usage: &'static str, args: &[String]) -> Result<u64, CommandParseError> {
    let value = args
        .first()
        .ok_or(CommandParseError::MissingArgument { command, usage })?;
    if let Some(extra) = args.get(1) {
        return Err(CommandParseError::UnexpectedArgument {
            command,
            value: extra.clone(),
        });
    }
    let token = value
        .parse::<u64>()
        .map_err(|error| CommandParseError::InvalidHookToken {
            value: value.clone(),
            reason: error.to_string(),
        })?;
    if token == 0 {
        return Err(CommandParseError::InvalidHookToken {
            value: value.clone(),
            reason: "token must be greater than zero".into(),
        });
    }
    Ok(token)
}

fn parse_attach(args: &[String]) -> Result<AttachRequest, CommandParseError> {
    let (target, script) = parse_launch_args("attach", "attach <pid|name> [-l script.js]", args)?;
    let target = if target.bytes().all(|byte| byte.is_ascii_digit()) {
        let pid = target
            .parse::<i32>()
            .map_err(|error| CommandParseError::InvalidTarget {
                command: "attach",
                value: target.clone(),
                reason: error.to_string(),
            })?;
        if pid == 0 {
            return Err(CommandParseError::InvalidTarget {
                command: "attach",
                value: target,
                reason: "PID must be greater than zero".into(),
            });
        }
        AttachTarget::Pid(pid)
    } else {
        AttachTarget::Name(target)
    };
    Ok(AttachRequest { target, script })
}

fn parse_spawn(args: &[String]) -> Result<SpawnRequest, CommandParseError> {
    let (target, script) = parse_launch_args("spawn", "spawn <bundle-id> [-l script.js]", args)?;
    Ok(SpawnRequest { target, script })
}

fn parse_launch_args(
    command: &'static str,
    usage: &'static str,
    args: &[String],
) -> Result<(String, Option<String>), CommandParseError> {
    let mut target = None;
    let mut script = None;
    let mut positional_only = false;
    let mut index = 0;
    while index < args.len() {
        let value = &args[index];
        if !positional_only && value == "--" {
            positional_only = true;
            index += 1;
            continue;
        }
        if !positional_only && (value == "-l" || value == "--script") {
            if script.is_some() {
                return Err(CommandParseError::DuplicateOption {
                    command,
                    option: "--script",
                });
            }
            let next = args
                .get(index + 1)
                .ok_or_else(|| CommandParseError::MissingOptionValue {
                    command,
                    option: value.clone(),
                })?;
            if next.is_empty() {
                return Err(CommandParseError::MissingOptionValue {
                    command,
                    option: value.clone(),
                });
            }
            script = Some(next.clone());
            index += 2;
            continue;
        }
        if !positional_only {
            if let Some(value) = value.strip_prefix("--script=") {
                if script.is_some() {
                    return Err(CommandParseError::DuplicateOption {
                        command,
                        option: "--script",
                    });
                }
                if value.is_empty() {
                    return Err(CommandParseError::MissingOptionValue {
                        command,
                        option: "--script".into(),
                    });
                }
                script = Some(value.into());
                index += 1;
                continue;
            }
            if value.starts_with('-') {
                return Err(CommandParseError::UnknownOption {
                    command,
                    option: value.clone(),
                });
            }
        }
        if target.replace(value.clone()).is_some() {
            return Err(CommandParseError::UnexpectedArgument {
                command,
                value: value.clone(),
            });
        }
        index += 1;
    }

    let target = target.ok_or(CommandParseError::MissingArgument { command, usage })?;
    if target.is_empty() {
        return Err(CommandParseError::InvalidTarget {
            command,
            value: target,
            reason: "target must not be empty".into(),
        });
    }
    Ok((target, script))
}

fn parse_session_id_arg(command: &'static str, args: &[String]) -> Result<SessionId, CommandParseError> {
    let usage = match command {
        "use" => "use <session-id>",
        _ => "detach <session-id>",
    };
    let value = args
        .first()
        .ok_or(CommandParseError::MissingArgument { command, usage })?;
    if let Some(extra) = args.get(1) {
        return Err(CommandParseError::UnexpectedArgument {
            command,
            value: extra.clone(),
        });
    }
    value
        .parse::<SessionId>()
        .map_err(|error| CommandParseError::InvalidSessionId {
            value: value.clone(),
            reason: error.to_string(),
        })
}

fn expect_no_args(command: &'static str, args: &[String]) -> Result<(), CommandParseError> {
    match args.first() {
        Some(value) => Err(CommandParseError::UnexpectedArgument {
            command,
            value: value.clone(),
        }),
        None => Ok(()),
    }
}

fn tokenize(line: &str) -> Result<Vec<String>, CommandParseError> {
    let mut words = Vec::new();
    let mut current = String::new();
    let mut started = false;
    let mut quote = None;
    let mut escaped = false;

    for character in line.chars() {
        if escaped {
            current.push(character);
            started = true;
            escaped = false;
            continue;
        }
        match quote {
            Some('\'') => {
                if character == '\'' {
                    quote = None;
                } else {
                    current.push(character);
                }
                started = true;
            }
            Some('"') => {
                if character == '"' {
                    quote = None;
                } else if character == '\\' {
                    escaped = true;
                } else {
                    current.push(character);
                }
                started = true;
            }
            Some(_) => unreachable!("tokenizer only stores supported quote characters"),
            None if character.is_whitespace() => {
                if started {
                    words.push(std::mem::take(&mut current));
                    started = false;
                }
            }
            None if character == '\'' || character == '"' => {
                quote = Some(character);
                started = true;
            }
            None if character == '\\' => {
                escaped = true;
                started = true;
            }
            None => {
                current.push(character);
                started = true;
            }
        }
    }

    if escaped {
        return Err(CommandParseError::DanglingEscape);
    }
    if let Some(quote) = quote {
        return Err(CommandParseError::UnterminatedQuote(quote));
    }
    if started {
        words.push(current);
    }
    Ok(words)
}

/// A reservation is allocated before platform work starts, making the
/// registry's capacity limit authoritative even for concurrent launches.
/// Launchers may move a clone into a worker and complete it asynchronously.
#[derive(Clone)]
pub(crate) struct LaunchReservation {
    session: Arc<Session>,
}

impl LaunchReservation {
    fn new(session: Arc<Session>) -> Self {
        Self { session }
    }

    pub(crate) fn id(&self) -> SessionId {
        self.session.id()
    }

    pub(crate) fn snapshot(&self) -> SessionSnapshot {
        self.session.snapshot()
    }

    pub(crate) fn complete(
        &self,
        pid: Option<i32>,
        label: impl Into<String>,
        backend: Arc<dyn SessionCommandBackend>,
    ) -> Result<(), SessionTransitionError> {
        self.session.update_target(pid, label);
        self.session.complete_attach(backend)
    }

    pub(crate) fn fail(&self, message: impl Into<String>) -> Result<(), SessionTransitionError> {
        self.session.fail_attach(message)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LauncherFailure {
    message: String,
}

impl LauncherFailure {
    pub(crate) fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for LauncherFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for LauncherFailure {}

/// Platform adapter boundary. Returning `Ok` means launch ownership was
/// accepted; the callback may complete the reservation before returning or
/// retain it for asynchronous completion. Returning `Err` must mean no worker
/// retained the reservation, and the frontend records the session as failed.
pub(crate) trait SessionLauncher: Send + Sync {
    fn attach(&self, reservation: LaunchReservation, request: AttachRequest) -> Result<(), LauncherFailure>;

    fn spawn(&self, reservation: LaunchReservation, request: SpawnRequest) -> Result<(), LauncherFailure>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FrontendMode {
    Server,
    Session(SessionId),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ListedSession {
    pub snapshot: SessionSnapshot,
    pub active: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DetachReport {
    pub snapshot: SessionSnapshot,
    pub failure: Option<SessionCommandFailure>,
}

impl From<DetachOutcome> for DetachReport {
    fn from(outcome: DetachOutcome) -> Self {
        Self {
            snapshot: outcome.session.snapshot(),
            failure: outcome.failure,
        }
    }
}

impl DetachReport {
    pub(crate) fn is_clean(&self) -> bool {
        self.failure.is_none() && self.snapshot.state == SessionState::Detached
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum HooksAction {
    Release,
    Uninstall,
}

impl HooksAction {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Release => "release",
            Self::Uninstall => "uninstall",
        }
    }
}

#[derive(Debug)]
pub(crate) struct HookCommandError {
    pub session: SessionId,
    pub action: HooksAction,
    pub token: u64,
    pub error: SessionHookError,
    pub snapshot: Option<ExternalHookSnapshot>,
}

impl fmt::Display for HookCommandError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "hooks session#{} action={} token={} failed: {}",
            self.session,
            self.action.as_str(),
            self.token,
            self.error
        )
    }
}

impl std::error::Error for HookCommandError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum FrontendEvent {
    LaunchAccepted(SessionSnapshot),
    Sessions(Vec<ListedSession>),
    HooksStatus {
        session: SessionId,
        hooks: Vec<ExternalHookSnapshot>,
    },
    HooksAction {
        session: SessionId,
        action: HooksAction,
        result: ExternalHookRelease,
    },
    ModeChanged {
        previous: FrontendMode,
        current: FrontendMode,
    },
    Detached(DetachReport),
    DetachedAll(Vec<DetachReport>),
    Help {
        mode: FrontendMode,
        text: &'static str,
    },
    ExitRequested {
        detached: Vec<DetachReport>,
    },
}

#[derive(Debug)]
pub(crate) enum FrontendError {
    Parse(CommandParseError),
    Closed,
    SessionModeActive(SessionId),
    NoActiveSession,
    SessionNotFound(SessionId),
    SessionNotAttached { id: SessionId, state: SessionState },
    Registry(SessionRegistryError),
    LaunchFailed { id: SessionId, message: String },
    Hook(HookCommandError),
}

impl fmt::Display for FrontendError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Parse(error) => error.fmt(formatter),
            Self::Closed => formatter.write_str("server frontend has already exited"),
            Self::SessionModeActive(id) => write!(formatter, "session {id} is active; run `back` first"),
            Self::NoActiveSession => formatter.write_str("no session is active"),
            Self::SessionNotFound(id) => write!(formatter, "session {id} not found"),
            Self::SessionNotAttached { id, state } => {
                write!(formatter, "session {id} is {}, not connected", state.as_status())
            }
            Self::Registry(error) => error.fmt(formatter),
            Self::LaunchFailed { id, message } => write!(formatter, "session {id} launch failed: {message}"),
            Self::Hook(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for FrontendError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Parse(error) => Some(error),
            Self::Registry(error) => Some(error),
            Self::Hook(error) => Some(error),
            _ => None,
        }
    }
}

impl From<CommandParseError> for FrontendError {
    fn from(error: CommandParseError) -> Self {
        Self::Parse(error)
    }
}

impl From<SessionRegistryError> for FrontendError {
    fn from(error: SessionRegistryError) -> Self {
        match error {
            SessionRegistryError::NotFound(id) => Self::SessionNotFound(id),
            other => Self::Registry(other),
        }
    }
}

#[derive(Debug, Default)]
struct FrontendState {
    active: Option<SessionId>,
    closed: bool,
}

pub(crate) struct ServerFrontend {
    registry: Arc<SessionRegistry>,
    launcher: Arc<dyn SessionLauncher>,
    detach_timeout: Duration,
    state: Mutex<FrontendState>,
}

impl ServerFrontend {
    pub(crate) fn new(registry: Arc<SessionRegistry>, launcher: Arc<dyn SessionLauncher>) -> Self {
        Self::with_detach_timeout(registry, launcher, DEFAULT_DETACH_TIMEOUT)
    }

    pub(crate) fn with_detach_timeout(
        registry: Arc<SessionRegistry>,
        launcher: Arc<dyn SessionLauncher>,
        detach_timeout: Duration,
    ) -> Self {
        Self {
            registry,
            launcher,
            detach_timeout,
            state: Mutex::new(FrontendState::default()),
        }
    }

    pub(crate) fn registry(&self) -> &Arc<SessionRegistry> {
        &self.registry
    }

    pub(crate) fn mode(&self) -> FrontendMode {
        mode_of(lock(&self.state).active)
    }

    /// Return whether the frontend completed an exit after all registry owners
    /// were removed.  Runtime callers must check this state instead of
    /// inferring closure from a single detach report: a backend may publish a
    /// late session while an earlier detach is still in progress.
    pub(crate) fn is_closed(&self) -> bool {
        lock(&self.state).closed
    }

    /// Resolve the active session while holding the frontend state lock so a
    /// command router cannot accidentally fall back to an arbitrary registry
    /// entry. The returned `Arc` remains valid while detach waits on the
    /// session's command gate.
    pub(crate) fn active_session(&self) -> Result<Arc<Session>, FrontendError> {
        let mut state = lock(&self.state);
        ensure_open(&state)?;
        let id = state.active.ok_or(FrontendError::NoActiveSession)?;
        match self.registry.get(id) {
            Some(session) => Ok(session),
            None => {
                state.active = None;
                Err(FrontendError::SessionNotFound(id))
            }
        }
    }

    pub(crate) fn execute_line(&self, line: &str) -> Result<FrontendEvent, FrontendError> {
        self.execute(parse_command(line)?)
    }

    pub(crate) fn execute(&self, command: FrontendCommand) -> Result<FrontendEvent, FrontendError> {
        match command {
            FrontendCommand::Attach(request) => self.launch_attach(request),
            FrontendCommand::Spawn(request) => self.launch_spawn(request),
            FrontendCommand::Hooks(command) => self.hooks(command),
            FrontendCommand::List => self.list(),
            FrontendCommand::Use(id) => self.use_session(id),
            FrontendCommand::Detach(id) => self.detach(id),
            FrontendCommand::DetachAll => self.detach_all(),
            FrontendCommand::Back => self.back(),
            FrontendCommand::Help => self.help(),
            FrontendCommand::Exit => self.exit(),
        }
    }

    fn launch_attach(&self, request: AttachRequest) -> Result<FrontendEvent, FrontendError> {
        let (pid, label) = request.target.reservation_metadata();
        let reservation = self.reserve_launch(pid, label)?;
        self.finish_launch(&reservation, self.launcher.attach(reservation.clone(), request))
    }

    fn launch_spawn(&self, request: SpawnRequest) -> Result<FrontendEvent, FrontendError> {
        let reservation = self.reserve_launch(None, request.target.clone())?;
        self.finish_launch(&reservation, self.launcher.spawn(reservation.clone(), request))
    }

    fn hooks(&self, command: HooksCommand) -> Result<FrontendEvent, FrontendError> {
        let session = self.active_session()?;
        let session_id = session.id();
        match command {
            HooksCommand::Status => Ok(FrontendEvent::HooksStatus {
                session: session_id,
                hooks: session.external_hook_status(),
            }),
            HooksCommand::Release(token) => self.run_hook_action(&session, session_id, HooksAction::Release, token),
            HooksCommand::Uninstall(token) => self.run_hook_action(&session, session_id, HooksAction::Uninstall, token),
        }
    }

    fn run_hook_action(
        &self,
        session: &Session,
        session_id: SessionId,
        action: HooksAction,
        token: u64,
    ) -> Result<FrontendEvent, FrontendError> {
        let result = match action {
            HooksAction::Release => session.release_external_hook(token),
            HooksAction::Uninstall => session.uninstall_external_hook(token),
        };
        match result {
            Ok(result) => Ok(FrontendEvent::HooksAction {
                session: session_id,
                action,
                result,
            }),
            Err(error) => {
                let snapshot = session
                    .external_hook_status()
                    .into_iter()
                    .find(|snapshot| snapshot.token == token);
                Err(FrontendError::Hook(HookCommandError {
                    session: session_id,
                    action,
                    token,
                    error,
                    snapshot,
                }))
            }
        }
    }

    fn reserve_launch(&self, pid: Option<i32>, label: String) -> Result<LaunchReservation, FrontendError> {
        let state = lock(&self.state);
        ensure_open(&state)?;
        if let Some(id) = state.active {
            return Err(FrontendError::SessionModeActive(id));
        }
        let session = self.registry.reserve(pid, label)?;
        Ok(LaunchReservation::new(session))
    }

    fn finish_launch(
        &self,
        reservation: &LaunchReservation,
        result: Result<(), LauncherFailure>,
    ) -> Result<FrontendEvent, FrontendError> {
        match result {
            Ok(()) => Ok(FrontendEvent::LaunchAccepted(reservation.snapshot())),
            Err(error) => {
                let message = error.to_string();
                if reservation.snapshot().state == SessionState::Attaching {
                    let _ = reservation.fail(message.clone());
                }
                Err(FrontendError::LaunchFailed {
                    id: reservation.id(),
                    message,
                })
            }
        }
    }

    fn list(&self) -> Result<FrontendEvent, FrontendError> {
        let state = lock(&self.state);
        ensure_open(&state)?;
        let active = state.active;
        let sessions = self
            .registry
            .list()
            .into_iter()
            .map(|snapshot| ListedSession {
                active: active == Some(snapshot.id),
                snapshot,
            })
            .collect();
        Ok(FrontendEvent::Sessions(sessions))
    }

    fn use_session(&self, id: SessionId) -> Result<FrontendEvent, FrontendError> {
        let mut state = lock(&self.state);
        ensure_open(&state)?;
        if let Some(active) = state.active {
            return Err(FrontendError::SessionModeActive(active));
        }
        let session = self.registry.get(id).ok_or(FrontendError::SessionNotFound(id))?;
        let session_state = session.state();
        if session_state != SessionState::Attached {
            return Err(FrontendError::SessionNotAttached {
                id,
                state: session_state,
            });
        }
        state.active = Some(id);
        Ok(FrontendEvent::ModeChanged {
            previous: FrontendMode::Server,
            current: FrontendMode::Session(id),
        })
    }

    fn back(&self) -> Result<FrontendEvent, FrontendError> {
        let mut state = lock(&self.state);
        ensure_open(&state)?;
        let id = state.active.take().ok_or(FrontendError::NoActiveSession)?;
        Ok(FrontendEvent::ModeChanged {
            previous: FrontendMode::Session(id),
            current: FrontendMode::Server,
        })
    }

    fn detach(&self, id: SessionId) -> Result<FrontendEvent, FrontendError> {
        let mut state = lock(&self.state);
        ensure_open(&state)?;
        let outcome = match self.registry.detach(id, self.detach_timeout) {
            Ok(outcome) => outcome,
            Err(SessionRegistryError::NotFound(missing)) => {
                if state.active == Some(missing) {
                    state.active = None;
                }
                return Err(FrontendError::SessionNotFound(missing));
            }
            Err(error) => return Err(error.into()),
        };
        if outcome.is_clean() && state.active == Some(id) {
            state.active = None;
        }
        Ok(FrontendEvent::Detached(outcome.into()))
    }

    fn detach_all(&self) -> Result<FrontendEvent, FrontendError> {
        let mut state = lock(&self.state);
        ensure_open(&state)?;
        let reports: Vec<DetachReport> = self
            .registry
            .detach_all(self.detach_timeout)
            .into_iter()
            .map(DetachReport::from)
            .collect();
        reconcile_active_after_reports(&mut state, &self.registry, &reports);
        Ok(FrontendEvent::DetachedAll(reports))
    }

    fn help(&self) -> Result<FrontendEvent, FrontendError> {
        let state = lock(&self.state);
        ensure_open(&state)?;
        Ok(FrontendEvent::Help {
            mode: mode_of(state.active),
            text: SERVER_HELP,
        })
    }

    fn exit(&self) -> Result<FrontendEvent, FrontendError> {
        let mut state = lock(&self.state);
        ensure_open(&state)?;
        let detached: Vec<DetachReport> = self
            .registry
            .detach_all(self.detach_timeout)
            .into_iter()
            .map(DetachReport::from)
            .collect();
        reconcile_active_after_reports(&mut state, &self.registry, &detached);
        // Reports describe the snapshot taken by `detach_all`.  Check the
        // registry as well so a concurrently published owner cannot make the
        // REPL terminate while cleanup remains retryable.
        state.closed = detached.iter().all(DetachReport::is_clean) && self.registry.is_empty();
        Ok(FrontendEvent::ExitRequested { detached })
    }

    /// Reconcile a transport failure through the same retryable detach path as
    /// an explicit command. Health failures clear a stale active mode even
    /// when backend shutdown itself remains pending in the registry.
    pub(crate) fn reconcile_health_failure(
        &self,
        session: &Arc<Session>,
        failure: &SessionCommandFailure,
    ) -> Option<DetachReport> {
        let mut state = lock(&self.state);
        if state.active == Some(session.id()) {
            state.active = None;
        }
        self.registry
            .reap_unhealthy(session, failure, self.detach_timeout)
            .map(DetachReport::from)
    }

    pub(crate) fn reconcile_command_transport_failure(
        &self,
        session: &Arc<Session>,
        failure: &SessionCommandFailure,
    ) -> Option<DetachReport> {
        let mut state = lock(&self.state);
        if state.active == Some(session.id()) {
            state.active = None;
        }
        self.registry
            .reap_command_transport_failure(session, failure, self.detach_timeout)
            .map(DetachReport::from)
    }
}

fn ensure_open(state: &FrontendState) -> Result<(), FrontendError> {
    if state.closed {
        Err(FrontendError::Closed)
    } else {
        Ok(())
    }
}

fn mode_of(active: Option<SessionId>) -> FrontendMode {
    active.map_or(FrontendMode::Server, FrontendMode::Session)
}

fn reconcile_active_after_reports(state: &mut FrontendState, registry: &SessionRegistry, reports: &[DetachReport]) {
    let Some(active) = state.active else {
        return;
    };
    if reports
        .iter()
        .find(|report| report.snapshot.id == active)
        .is_some_and(DetachReport::is_clean)
        || registry.get(active).is_none()
    {
        state.active = None;
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[cfg(test)]
mod tests {
    use super::{
        parse_command, AttachRequest, AttachTarget, CommandParseError, DetachReport, FrontendCommand, FrontendError,
        FrontendEvent, FrontendMode, HooksCommand, LaunchReservation, LauncherFailure, ServerFrontend, SessionLauncher,
        SpawnRequest,
    };
    use crate::{
        server::{SessionRegistry, SessionRegistryError},
        session::{SessionCommandBackend, SessionCommandFailure, SessionState},
    };
    use serde_json::Value;
    use std::{
        collections::BTreeSet,
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc, Barrier, Mutex,
        },
        thread,
        time::Duration,
    };

    #[derive(Default)]
    struct Backend;

    impl SessionCommandBackend for Backend {
        fn rpc_call(&self, _method: &str, args: &Value, _timeout: Duration) -> Result<Value, SessionCommandFailure> {
            Ok(args.clone())
        }
    }

    #[derive(Default)]
    struct ImmediateLauncher {
        requests: Mutex<Vec<String>>,
    }

    impl SessionLauncher for ImmediateLauncher {
        fn attach(&self, reservation: LaunchReservation, request: AttachRequest) -> Result<(), LauncherFailure> {
            let (pid, label) = match &request.target {
                AttachTarget::Pid(pid) => (Some(*pid), format!("pid-{pid}")),
                AttachTarget::Name(name) => (Some(900), name.clone()),
            };
            self.requests.lock().expect("requests").push(label.clone());
            reservation
                .complete(pid, label, Arc::new(Backend))
                .map_err(|error| LauncherFailure::new(error.to_string()))
        }

        fn spawn(&self, reservation: LaunchReservation, request: SpawnRequest) -> Result<(), LauncherFailure> {
            self.requests.lock().expect("requests").push(request.target.clone());
            reservation
                .complete(Some(901), request.target, Arc::new(Backend))
                .map_err(|error| LauncherFailure::new(error.to_string()))
        }
    }

    fn frontend(capacity: usize) -> (Arc<SessionRegistry>, ServerFrontend) {
        let registry = Arc::new(SessionRegistry::with_capacity(capacity).expect("registry"));
        let launcher: Arc<dyn SessionLauncher> = Arc::new(ImmediateLauncher::default());
        let frontend = ServerFrontend::new(Arc::clone(&registry), launcher);
        (registry, frontend)
    }

    #[test]
    fn parser_supports_android_management_commands_and_quoting() {
        assert_eq!(
            parse_command("attach 'Spring Board' -l \"early hooks.js\"").expect("attach"),
            FrontendCommand::Attach(AttachRequest {
                target: AttachTarget::Name("Spring Board".into()),
                script: Some("early hooks.js".into()),
            })
        );
        assert_eq!(
            parse_command("spawn --script=boot.js com.example.app").expect("spawn"),
            FrontendCommand::Spawn(SpawnRequest {
                target: "com.example.app".into(),
                script: Some("boot.js".into()),
            })
        );
        assert_eq!(parse_command("sessions").expect("sessions"), FrontendCommand::List);
        assert_eq!(parse_command("server").expect("server"), FrontendCommand::Back);
        assert_eq!(parse_command("quit").expect("quit"), FrontendCommand::Exit);
        assert_eq!(
            parse_command("hooks status").expect("hooks status"),
            FrontendCommand::Hooks(HooksCommand::Status)
        );
        assert_eq!(
            parse_command("hooks release 77").expect("hooks release"),
            FrontendCommand::Hooks(HooksCommand::Release(77))
        );
        assert_eq!(
            parse_command("hooks uninstall 78").expect("hooks uninstall"),
            FrontendCommand::Hooks(HooksCommand::Uninstall(78))
        );
    }

    #[test]
    fn parser_rejects_ambiguous_or_incomplete_input() {
        assert!(matches!(parse_command(""), Err(CommandParseError::Empty)));
        assert!(matches!(
            parse_command("attach 0"),
            Err(CommandParseError::InvalidTarget { .. })
        ));
        assert!(matches!(
            parse_command("spawn app -l"),
            Err(CommandParseError::MissingOptionValue { .. })
        ));
        assert!(matches!(
            parse_command("attach a b"),
            Err(CommandParseError::UnexpectedArgument { .. })
        ));
        assert!(matches!(
            parse_command("use 0"),
            Err(CommandParseError::InvalidSessionId { .. })
        ));
        assert!(matches!(
            parse_command("spawn 'unterminated"),
            Err(CommandParseError::UnterminatedQuote('\''))
        ));
        assert!(matches!(
            parse_command("hooks release 0"),
            Err(CommandParseError::InvalidHookToken { .. })
        ));
        assert!(matches!(
            parse_command("hooks uninstall token"),
            Err(CommandParseError::InvalidHookToken { .. })
        ));
        assert!(matches!(
            parse_command("hooks unknown"),
            Err(CommandParseError::UnknownHooksAction(action)) if action == "unknown"
        ));
    }

    #[test]
    fn hooks_status_uses_the_active_session_and_returns_structured_event() {
        let (_registry, frontend) = frontend(1);
        let id = match frontend.execute_line("attach 42").expect("attach") {
            FrontendEvent::LaunchAccepted(snapshot) => snapshot.id,
            other => panic!("unexpected event: {other:?}"),
        };
        assert!(matches!(
            frontend.execute_line("hooks status"),
            Err(FrontendError::NoActiveSession)
        ));
        frontend.execute(FrontendCommand::Use(id)).expect("use");

        match frontend.execute_line("hooks status").expect("status") {
            FrontendEvent::HooksStatus { session, hooks } => {
                assert_eq!(session, id);
                assert!(hooks.is_empty());
            }
            other => panic!("unexpected event: {other:?}"),
        }
    }

    #[test]
    fn hooks_action_errors_keep_the_active_session_and_token_context() {
        let (_registry, frontend) = frontend(1);
        let id = match frontend.execute_line("attach 42").expect("attach") {
            FrontendEvent::LaunchAccepted(snapshot) => snapshot.id,
            other => panic!("unexpected event: {other:?}"),
        };
        frontend.execute(FrontendCommand::Use(id)).expect("use");

        match frontend.execute_line("hooks release 77") {
            Err(FrontendError::Hook(error)) => {
                assert_eq!(error.session, id);
                assert_eq!(error.action.as_str(), "release");
                assert_eq!(error.token, 77);
                assert!(error.snapshot.is_none());
            }
            other => panic!("unexpected result: {other:?}"),
        }
    }

    #[test]
    fn attach_spawn_list_and_active_mode_follow_state_machine() {
        let (registry, frontend) = frontend(4);
        let first = match frontend.execute_line("attach 42").expect("attach") {
            FrontendEvent::LaunchAccepted(snapshot) => snapshot,
            other => panic!("unexpected event: {other:?}"),
        };
        assert_eq!(first.pid, Some(42));
        assert_eq!(first.state, SessionState::Attached);

        let second = match frontend.execute_line("spawn com.example.app").expect("spawn") {
            FrontendEvent::LaunchAccepted(snapshot) => snapshot,
            other => panic!("unexpected event: {other:?}"),
        };
        assert_eq!(second.pid, Some(901));
        assert_eq!(registry.len(), 2);

        assert!(matches!(
            frontend.execute(FrontendCommand::Use(first.id)).expect("use"),
            FrontendEvent::ModeChanged {
                previous: FrontendMode::Server,
                current: FrontendMode::Session(id),
            } if id == first.id
        ));
        assert_eq!(frontend.mode(), FrontendMode::Session(first.id));
        assert!(matches!(
            frontend.execute_line("spawn another.app"),
            Err(FrontendError::SessionModeActive(id)) if id == first.id
        ));

        let listed = match frontend.execute_line("list").expect("list") {
            FrontendEvent::Sessions(sessions) => sessions,
            other => panic!("unexpected event: {other:?}"),
        };
        assert_eq!(listed.len(), 2);
        assert!(listed.iter().any(|entry| entry.snapshot.id == first.id && entry.active));
        assert!(listed
            .iter()
            .any(|entry| entry.snapshot.id == second.id && !entry.active));

        frontend.execute_line("back").expect("back");
        assert_eq!(frontend.mode(), FrontendMode::Server);
        assert!(matches!(
            frontend.execute_line("back"),
            Err(FrontendError::NoActiveSession)
        ));
    }

    struct DeferredLauncher {
        reservations: Mutex<Vec<LaunchReservation>>,
    }

    impl SessionLauncher for DeferredLauncher {
        fn attach(&self, reservation: LaunchReservation, _request: AttachRequest) -> Result<(), LauncherFailure> {
            self.reservations.lock().expect("reservations").push(reservation);
            Ok(())
        }

        fn spawn(&self, reservation: LaunchReservation, _request: SpawnRequest) -> Result<(), LauncherFailure> {
            self.reservations.lock().expect("reservations").push(reservation);
            Ok(())
        }
    }

    #[test]
    fn deferred_launcher_keeps_session_attaching_until_callback() {
        let registry = Arc::new(SessionRegistry::with_capacity(1).expect("registry"));
        let launcher = Arc::new(DeferredLauncher {
            reservations: Mutex::new(Vec::new()),
        });
        let frontend = ServerFrontend::new(Arc::clone(&registry), launcher.clone());

        let snapshot = match frontend.execute_line("spawn app").expect("spawn accepted") {
            FrontendEvent::LaunchAccepted(snapshot) => snapshot,
            other => panic!("unexpected event: {other:?}"),
        };
        assert_eq!(snapshot.state, SessionState::Attaching);
        assert!(matches!(
            frontend.execute(FrontendCommand::Use(snapshot.id)),
            Err(FrontendError::SessionNotAttached {
                state: SessionState::Attaching,
                ..
            })
        ));

        launcher.reservations.lock().expect("reservations")[0]
            .complete(Some(77), "app", Arc::new(Backend))
            .expect("complete callback");
        frontend
            .execute(FrontendCommand::Use(snapshot.id))
            .expect("use attached");
    }

    struct FailingLauncher;

    impl SessionLauncher for FailingLauncher {
        fn attach(&self, _reservation: LaunchReservation, _request: AttachRequest) -> Result<(), LauncherFailure> {
            Err(LauncherFailure::new("attach callback failed"))
        }

        fn spawn(&self, _reservation: LaunchReservation, _request: SpawnRequest) -> Result<(), LauncherFailure> {
            Err(LauncherFailure::new("spawn callback failed"))
        }
    }

    #[test]
    fn launcher_failure_is_recorded_and_remains_detachable() {
        let registry = Arc::new(SessionRegistry::with_capacity(1).expect("registry"));
        let frontend = ServerFrontend::new(Arc::clone(&registry), Arc::new(FailingLauncher));
        assert!(matches!(
            frontend.execute_line("attach target"),
            Err(FrontendError::LaunchFailed { .. })
        ));
        let failed = registry.list();
        assert_eq!(failed.len(), 1);
        assert_eq!(failed[0].state, SessionState::Failed);
        assert_eq!(failed[0].last_error.as_deref(), Some("attach callback failed"));
        frontend
            .execute(FrontendCommand::Detach(failed[0].id))
            .expect("detach failed launch");
        assert!(registry.is_empty());
    }

    #[test]
    fn detach_and_exit_clear_active_state_and_registry() {
        let (registry, frontend) = frontend(3);
        let first = match frontend.execute_line("attach 11").expect("attach") {
            FrontendEvent::LaunchAccepted(snapshot) => snapshot.id,
            other => panic!("unexpected event: {other:?}"),
        };
        frontend.execute(FrontendCommand::Use(first)).expect("use");
        frontend.execute(FrontendCommand::Detach(first)).expect("detach active");
        assert_eq!(frontend.mode(), FrontendMode::Server);

        frontend.execute_line("attach 12").expect("attach second");
        let detached = match frontend.execute_line("exit").expect("exit") {
            FrontendEvent::ExitRequested { detached } => detached,
            other => panic!("unexpected event: {other:?}"),
        };
        assert_eq!(detached.len(), 1);
        assert!(registry.is_empty());
        assert!(matches!(frontend.execute_line("list"), Err(FrontendError::Closed)));
    }

    #[test]
    fn active_lookup_clears_mode_after_external_registry_detach() {
        let (registry, frontend) = frontend(1);
        let id = match frontend.execute_line("attach 11").expect("attach") {
            FrontendEvent::LaunchAccepted(snapshot) => snapshot.id,
            other => panic!("unexpected event: {other:?}"),
        };
        frontend.execute(FrontendCommand::Use(id)).expect("use");
        registry.detach(id, Duration::from_secs(1)).expect("external detach");

        assert!(matches!(
            frontend.active_session(),
            Err(FrontendError::SessionNotFound(missing)) if missing == id
        ));
        assert_eq!(frontend.mode(), FrontendMode::Server);
    }

    struct RetryDetachBackend {
        attempts: AtomicUsize,
    }

    impl SessionCommandBackend for RetryDetachBackend {
        fn rpc_call(&self, _method: &str, args: &Value, _timeout: Duration) -> Result<Value, SessionCommandFailure> {
            Ok(args.clone())
        }

        fn detach(&self, _timeout: Duration) -> Result<(), SessionCommandFailure> {
            if self.attempts.fetch_add(1, Ordering::SeqCst) == 0 {
                Err(SessionCommandFailure::Unavailable(
                    "shutdown acknowledgement timed out".into(),
                ))
            } else {
                Ok(())
            }
        }
    }

    struct RetryDetachLauncher {
        backend: Arc<RetryDetachBackend>,
    }

    impl SessionLauncher for RetryDetachLauncher {
        fn attach(&self, reservation: LaunchReservation, request: AttachRequest) -> Result<(), LauncherFailure> {
            let pid = match request.target {
                AttachTarget::Pid(pid) => pid,
                AttachTarget::Name(_) => 900,
            };
            let backend: Arc<dyn SessionCommandBackend> = self.backend.clone();
            reservation
                .complete(Some(pid), format!("pid-{pid}"), backend)
                .map_err(|error| LauncherFailure::new(error.to_string()))
        }

        fn spawn(&self, reservation: LaunchReservation, request: SpawnRequest) -> Result<(), LauncherFailure> {
            let backend: Arc<dyn SessionCommandBackend> = self.backend.clone();
            reservation
                .complete(Some(901), request.target, backend)
                .map_err(|error| LauncherFailure::new(error.to_string()))
        }
    }

    fn retry_frontend() -> (Arc<SessionRegistry>, Arc<RetryDetachBackend>, ServerFrontend) {
        let registry = Arc::new(SessionRegistry::with_capacity(1).expect("registry"));
        let backend = Arc::new(RetryDetachBackend {
            attempts: AtomicUsize::new(0),
        });
        let launcher: Arc<dyn SessionLauncher> = Arc::new(RetryDetachLauncher {
            backend: backend.clone(),
        });
        let frontend = ServerFrontend::with_detach_timeout(Arc::clone(&registry), launcher, Duration::from_millis(10));
        (registry, backend, frontend)
    }

    #[test]
    fn failed_active_detach_keeps_mode_and_registry_owner_until_retry() {
        let (registry, backend, frontend) = retry_frontend();
        let id = match frontend.execute_line("attach 42").expect("attach") {
            FrontendEvent::LaunchAccepted(snapshot) => snapshot.id,
            other => panic!("unexpected event: {other:?}"),
        };
        frontend.execute(FrontendCommand::Use(id)).expect("use");

        let first = match frontend.execute(FrontendCommand::Detach(id)).expect("first detach") {
            FrontendEvent::Detached(report) => report,
            other => panic!("unexpected event: {other:?}"),
        };
        assert!(!first.is_clean());
        assert_eq!(frontend.mode(), FrontendMode::Session(id));
        assert!(registry.get(id).is_some());

        let second = match frontend.execute(FrontendCommand::Detach(id)).expect("retry detach") {
            FrontendEvent::Detached(report) => report,
            other => panic!("unexpected event: {other:?}"),
        };
        assert!(second.is_clean());
        assert_eq!(frontend.mode(), FrontendMode::Server);
        assert!(registry.is_empty());
        assert_eq!(backend.attempts.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn exit_remains_retryable_until_pending_cleanup_is_clean() {
        let (registry, backend, frontend) = retry_frontend();
        frontend.execute_line("spawn app").expect("spawn");

        let first = match frontend.execute_line("exit").expect("first exit") {
            FrontendEvent::ExitRequested { detached } => detached,
            other => panic!("unexpected event: {other:?}"),
        };
        assert_eq!(first.len(), 1);
        assert!(!first[0].is_clean());
        assert_eq!(registry.len(), 1);
        assert!(matches!(
            frontend.execute_line("list"),
            Ok(FrontendEvent::Sessions(sessions)) if sessions.len() == 1
        ));

        let second = match frontend.execute_line("exit").expect("retry exit") {
            FrontendEvent::ExitRequested { detached } => detached,
            other => panic!("unexpected event: {other:?}"),
        };
        assert!(second.iter().all(DetachReport::is_clean));
        assert!(registry.is_empty());
        assert_eq!(backend.attempts.load(Ordering::SeqCst), 2);
        assert!(matches!(frontend.execute_line("list"), Err(FrontendError::Closed)));
    }

    struct LatePublishingBackend {
        registry: Arc<SessionRegistry>,
        published: AtomicUsize,
    }

    impl SessionCommandBackend for LatePublishingBackend {
        fn rpc_call(&self, _method: &str, args: &Value, _timeout: Duration) -> Result<Value, SessionCommandFailure> {
            Ok(args.clone())
        }

        fn detach(&self, _timeout: Duration) -> Result<(), SessionCommandFailure> {
            if self.published.fetch_add(1, Ordering::SeqCst) == 0 {
                self.registry
                    .attach(Some(99), "late-session", Arc::new(Backend))
                    .expect("publish late session");
            }
            Ok(())
        }
    }

    #[test]
    fn exit_stays_open_when_registry_publishes_a_late_owner() {
        let registry = Arc::new(SessionRegistry::with_capacity(2).expect("registry"));
        let backend = Arc::new(LatePublishingBackend {
            registry: Arc::clone(&registry),
            published: AtomicUsize::new(0),
        });
        registry.attach(Some(42), "initial", backend).expect("attach initial");
        let frontend = ServerFrontend::new(Arc::clone(&registry), Arc::new(ImmediateLauncher::default()));

        let first = match frontend.execute_line("exit").expect("first exit") {
            FrontendEvent::ExitRequested { detached } => detached,
            other => panic!("unexpected event: {other:?}"),
        };
        assert!(first.iter().all(DetachReport::is_clean));
        assert!(!frontend.is_closed());
        assert_eq!(registry.len(), 1);
        assert!(matches!(frontend.execute_line("list"), Ok(FrontendEvent::Sessions(_))));

        let second = match frontend.execute_line("exit").expect("retry exit") {
            FrontendEvent::ExitRequested { detached } => detached,
            other => panic!("unexpected event: {other:?}"),
        };
        assert!(second.iter().all(DetachReport::is_clean));
        assert!(frontend.is_closed());
        assert!(registry.is_empty());
        assert!(matches!(frontend.execute_line("list"), Err(FrontendError::Closed)));
    }

    struct BarrierLauncher {
        barrier: Barrier,
    }

    impl SessionLauncher for BarrierLauncher {
        fn attach(&self, reservation: LaunchReservation, request: AttachRequest) -> Result<(), LauncherFailure> {
            self.barrier.wait();
            let pid = match request.target {
                AttachTarget::Pid(pid) => pid,
                AttachTarget::Name(_) => return Err(LauncherFailure::new("test requires PID")),
            };
            reservation
                .complete(Some(pid), format!("pid-{pid}"), Arc::new(Backend))
                .map_err(|error| LauncherFailure::new(error.to_string()))
        }

        fn spawn(&self, _reservation: LaunchReservation, _request: SpawnRequest) -> Result<(), LauncherFailure> {
            Err(LauncherFailure::new("unused"))
        }
    }

    #[test]
    fn concurrent_launches_reserve_capacity_before_callbacks_run() {
        const LIMIT: usize = 4;
        const WORKERS: usize = 16;
        let registry = Arc::new(SessionRegistry::with_capacity(LIMIT).expect("registry"));
        let launcher: Arc<dyn SessionLauncher> = Arc::new(BarrierLauncher {
            barrier: Barrier::new(LIMIT),
        });
        let frontend = Arc::new(ServerFrontend::new(Arc::clone(&registry), launcher));

        let workers = (1..=WORKERS)
            .map(|pid| {
                let frontend = Arc::clone(&frontend);
                thread::spawn(move || frontend.execute_line(&format!("attach {pid}")))
            })
            .collect::<Vec<_>>();
        let results = workers
            .into_iter()
            .map(|worker| worker.join().expect("worker"))
            .collect::<Vec<_>>();
        let accepted = results.iter().filter(|result| result.is_ok()).count();
        let capacity_errors = results
            .iter()
            .filter(|result| {
                matches!(
                    result,
                    Err(FrontendError::Registry(SessionRegistryError::CapacityReached {
                        limit: LIMIT
                    }))
                )
            })
            .count();
        let ids = registry
            .list()
            .into_iter()
            .map(|snapshot| snapshot.id.get())
            .collect::<BTreeSet<_>>();
        assert_eq!(accepted, LIMIT);
        assert_eq!(capacity_errors, WORKERS - LIMIT);
        assert_eq!(ids.len(), LIMIT);
        assert!(registry
            .list()
            .iter()
            .all(|snapshot| snapshot.state == SessionState::Attached));
    }
}
