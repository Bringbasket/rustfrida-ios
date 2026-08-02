//! Controller-side state and command boundary for one injected process.

use std::{
    collections::BTreeMap,
    fmt,
    num::ParseIntError,
    str::FromStr,
    sync::{Arc, Mutex, MutexGuard, RwLock, RwLockReadGuard, RwLockWriteGuard},
    time::Duration,
};

use common::command::{
    ExternalHookActionRequest, ExternalHookCommandOperation, ExternalHookErrorCode, ExternalHookExecuteRequest,
    ExternalHookOwnershipState as AgentHookOwnershipState, ExternalHookReceipt, ExternalHookReply,
    ExternalHookTargetState as AgentHookTargetState,
};
use common::AgentCommand;
use native_api::{
    AdapterCommandMode, AdapterDecision, AdapterKind, ExecutionBoundary, ExternalHookBackendKind,
    ExternalHookExecutionError, ExternalHookOperation, HookBackendFfiError, HookExecutionResult, HookOperation,
};
use serde_json::Value;

/// A stable, process-local session identifier.
///
/// IDs are allocated by `SessionRegistry` and are never reused during the
/// lifetime of that registry. Zero is reserved for the legacy single-session
/// controller path.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct SessionId(u64);

impl SessionId {
    pub(crate) const fn from_raw(raw: u64) -> Option<Self> {
        if raw == 0 {
            None
        } else {
            Some(Self(raw))
        }
    }

    pub(crate) const fn get(self) -> u64 {
        self.0
    }
}

impl fmt::Display for SessionId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

#[derive(Debug)]
pub(crate) enum ParseSessionIdError {
    InvalidInteger(ParseIntError),
    ReservedZero,
}

impl fmt::Display for ParseSessionIdError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidInteger(error) => write!(formatter, "invalid session ID: {error}"),
            Self::ReservedZero => formatter.write_str("session ID zero is reserved"),
        }
    }
}

impl std::error::Error for ParseSessionIdError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidInteger(error) => Some(error),
            Self::ReservedZero => None,
        }
    }
}

impl FromStr for SessionId {
    type Err = ParseSessionIdError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let raw = value.parse::<u64>().map_err(ParseSessionIdError::InvalidInteger)?;
        Self::from_raw(raw).ok_or(ParseSessionIdError::ReservedZero)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SessionState {
    Attaching,
    Attached,
    Detaching,
    Detached,
    Failed,
}

impl SessionState {
    /// Status spelling expected by the existing HTTP session representation.
    pub(crate) const fn as_status(self) -> &'static str {
        match self {
            Self::Attaching => "connecting",
            Self::Attached => "connected",
            Self::Detaching => "detaching",
            Self::Detached => "disconnected",
            Self::Failed => "failed",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SessionSnapshot {
    pub id: SessionId,
    pub pid: Option<i32>,
    pub label: String,
    pub state: SessionState,
    pub last_error: Option<String>,
    pub external_hooks: Vec<ExternalHookSnapshot>,
}

impl SessionSnapshot {
    pub(crate) const fn status(&self) -> &'static str {
        self.state.as_status()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ExternalHookOwnership {
    Owned,
    Released,
}

impl ExternalHookOwnership {
    pub(crate) const fn as_status(self) -> &'static str {
        match self {
            Self::Owned => "owned",
            Self::Released => "released",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ExternalHookTargetState {
    Installed,
    Restored,
}

impl ExternalHookTargetState {
    pub(crate) const fn as_status(self) -> &'static str {
        match self {
            Self::Installed => "installed",
            Self::Restored => "restored",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ExternalHookNativeUninstall {
    Available,
    Unavailable,
}

impl ExternalHookNativeUninstall {
    pub(crate) const fn as_status(self) -> &'static str {
        match self {
            Self::Available => "available",
            Self::Unavailable => "unavailable",
        }
    }
}

/// Controller-visible ownership state for one successful external adapter call.
/// The token is the identity returned by `HookExecutionResult`; the controller
/// never synthesizes or reuses it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ExternalHookSnapshot {
    pub token: u64,
    pub backend: ExternalHookBackendKind,
    pub operation: ExternalHookOperation,
    pub ownership: ExternalHookOwnership,
    pub native_uninstall: ExternalHookNativeUninstall,
    pub target_state: ExternalHookTargetState,
    pub last_error: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ExternalHookRelease {
    pub snapshot: ExternalHookSnapshot,
    pub released_now: bool,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct ExternalHookCleanupReport {
    pub attempted: usize,
    pub released: usize,
    pub already_released: usize,
    pub failed: usize,
    pub errors: Vec<String>,
}

impl ExternalHookCleanupReport {
    pub(crate) const fn is_clean(&self) -> bool {
        self.failed == 0
    }

    fn failure_message(&self) -> Option<String> {
        if self.errors.is_empty() {
            None
        } else {
            Some(format!(
                "external hook cleanup failed for {} handle(s): {}",
                self.failed,
                self.errors.join("; ")
            ))
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum SessionHookError {
    SessionNotReady {
        id: SessionId,
        state: SessionState,
    },
    InvalidToken,
    DuplicateToken(u64),
    NotFound(u64),
    InvalidHandle {
        token: u64,
        reason: &'static str,
    },
    Adapter {
        token: u64,
        message: String,
    },
    NativeUninstallUnavailable {
        token: u64,
        backend: ExternalHookBackendKind,
    },
    AlreadyReleased(u64),
    Execution {
        message: String,
        target_state_uncertain: bool,
    },
}

impl fmt::Display for SessionHookError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SessionNotReady { id, state } => {
                write!(formatter, "session {id} cannot own an external hook while {}", state.as_status())
            }
            Self::InvalidToken => formatter.write_str("external hook token must be non-zero"),
            Self::DuplicateToken(token) => write!(formatter, "external hook token {token} is already owned by this session"),
            Self::NotFound(token) => write!(formatter, "external hook token {token} is not owned by this session"),
            Self::InvalidHandle { token, reason } => write!(formatter, "external hook token {token} cannot be adopted: {reason}"),
            Self::Adapter { token, message } => write!(formatter, "external hook token {token} adapter operation failed: {message}"),
            Self::NativeUninstallUnavailable { token, backend } => write!(
                formatter,
                "external hook token {token} ({}) remains owned; native uninstall is unavailable and the target remains installed",
                backend.as_str()
            ),
            Self::AlreadyReleased(token) => write!(formatter, "external hook token {token} was already released"),
            Self::Execution {
                message,
                target_state_uncertain,
            } => write!(
                formatter,
                "external hook execution failed (target_state_uncertain={target_state_uncertain}): {message}"
            ),
        }
    }
}

impl std::error::Error for SessionHookError {}

/// Failure categories intentionally mirror `http_rpc::RpcFailure` so an
/// adapter can map them without inspecting error strings.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum SessionCommandFailure {
    BadRequest(String),
    Unavailable(String),
    Internal(String),
}

impl fmt::Display for SessionCommandFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadRequest(message) => write!(formatter, "bad request: {message}"),
            Self::Unavailable(message) => write!(formatter, "session unavailable: {message}"),
            Self::Internal(message) => write!(formatter, "session command failed: {message}"),
        }
    }
}

impl std::error::Error for SessionCommandFailure {}

impl SessionCommandFailure {
    /// Transport and framing failures mean that the long-lived agent stream
    /// is no longer usable. `BadRequest` is deliberately excluded because a
    /// backend may not implement controller-level health probes.
    pub(crate) const fn is_transport_failure(&self) -> bool {
        matches!(self, Self::Unavailable(_) | Self::Internal(_))
    }
}

/// Per-session command transport implemented by an attached agent connection.
///
/// A later adapter around `ActiveAgentRpcBackend` can move its current stream
/// lock and `AgentCommand::RpcCall` dispatch directly behind this interface.
pub(crate) trait SessionCommandBackend: Send + Sync {
    fn rpc_call(&self, method: &str, args: &Value, timeout: Duration) -> Result<Value, SessionCommandFailure>;

    /// Execute a typed external-hook command through the attached agent
    /// protocol. The active agent backend overrides this boundary; lightweight
    /// backends retain an explicit unsupported-command result by default.
    fn external_hook_command(
        &self,
        _command: &AgentCommand,
        _timeout: Duration,
    ) -> Result<Value, SessionCommandFailure> {
        Err(SessionCommandFailure::BadRequest(
            "this session backend does not support external hook commands".into(),
        ))
    }

    /// Execute one controller command against this session. This is separate
    /// from `rpc_call`: controller commands use the agent command protocol,
    /// while RPC calls address JavaScript `rpc.exports` methods.
    fn execute_command(&self, _command: &str, _timeout: Duration) -> Result<Value, SessionCommandFailure> {
        Err(SessionCommandFailure::BadRequest(
            "this session backend does not support controller commands".into(),
        ))
    }

    /// Probe the long-lived agent transport without requiring a new backend
    /// implementation. Production controller backends already support the
    /// legacy `ping` command; lightweight test or embedding backends can keep
    /// the default and report `BadRequest`, which the health monitor ignores.
    fn health_check(&self, timeout: Duration) -> Result<(), SessionCommandFailure> {
        self.execute_command("ping", timeout).map(|_| ())
    }

    /// Request backend shutdown. Backends without a shutdown frame may retain
    /// the default and rely on dropping their final connection reference.
    fn detach(&self, _timeout: Duration) -> Result<(), SessionCommandFailure> {
        Ok(())
    }
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct SessionTransitionError {
    pub id: SessionId,
    pub state: SessionState,
    pub operation: &'static str,
}

impl fmt::Display for SessionTransitionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "session {} cannot {} while {}",
            self.id,
            self.operation,
            self.state.as_status()
        )
    }
}

impl std::error::Error for SessionTransitionError {}

#[derive(Debug)]
struct SessionMetadata {
    pid: Option<i32>,
    label: String,
}

struct SessionLifecycle {
    state: SessionState,
    backend: Option<Arc<dyn SessionCommandBackend>>,
    backend_shutdown: bool,
    last_error: Option<String>,
    external_hooks: BTreeMap<u64, OwnedExternalHook>,
}

/// `HookExecutionResult` intentionally does not promise `Send` because it
/// carries opaque code pointers. The controller never dereferences those
/// pointers: it only serializes access to the adapter lease and calls the
/// public release/uninstall methods. Keeping that invariant here lets a
/// session move between the controller's worker and health threads without
/// inventing a native ABI or moving an in-flight call across threads.
struct ControllerOwnedHook(HookExecutionResult);

unsafe impl Send for ControllerOwnedHook {}

impl ControllerOwnedHook {
    fn token(&self) -> u64 {
        self.0.token
    }

    fn backend(&self) -> ExternalHookBackendKind {
        self.0.backend
    }

    fn operation(&self) -> ExternalHookOperation {
        self.0.operation
    }

    fn handle_released(&self) -> bool {
        self.0.handle_released()
    }

    fn native_uninstall_available(&self) -> bool {
        self.0.native_uninstall_available()
    }

    fn result_mut(&mut self) -> &mut HookExecutionResult {
        &mut self.0
    }

    fn release(&mut self) -> bool {
        self.0.release()
    }
}

impl Drop for ControllerOwnedHook {
    fn drop(&mut self) {
        let _ = self.release();
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
enum ExternalHookLeaseError {
    NativeUninstallUnavailable {
        token: u64,
        backend: ExternalHookBackendKind,
    },
    AlreadyReleased(u64),
    Adapter(String),
}

/// Session-owned lease abstraction. The native implementation below is the
/// only production implementation; keeping this boundary small makes cleanup
/// behavior testable without manufacturing opaque native code pointers.
trait ExternalHookLease: Send {
    fn token(&self) -> u64;
    fn backend(&self) -> ExternalHookBackendKind;
    fn operation(&self) -> ExternalHookOperation;
    fn request_id(&self) -> Option<&str> {
        None
    }
    fn remote_receipt(&self) -> Option<ExternalHookReceipt> {
        None
    }
    fn handle_released(&self) -> bool;
    fn native_uninstall_available(&self) -> bool;
    fn release(&mut self) -> Result<bool, ExternalHookLeaseError>;
    fn uninstall(&mut self) -> Result<(), ExternalHookLeaseError>;
}

struct NativeExternalHookLease {
    decision: AdapterDecision,
    handle: ControllerOwnedHook,
}

/// Controller-side lease for a hook whose native handle remains inside the
/// attached agent. The controller keeps the receipt and the command backend,
/// never a copy of the agent's opaque native handle.
struct RemoteExternalHookLease {
    backend: Arc<dyn SessionCommandBackend>,
    receipt: ExternalHookReceipt,
    timeout: Duration,
}

impl RemoteExternalHookLease {
    fn reply(&self, command: AgentCommand) -> Result<ExternalHookReply, ExternalHookLeaseError> {
        let payload = self
            .backend
            .external_hook_command(&command, self.timeout)
            .map_err(|error| ExternalHookLeaseError::Adapter(error.to_string()))?;
        serde_json::from_value(payload)
            .map_err(|error| ExternalHookLeaseError::Adapter(format!("invalid external hook reply: {error}")))
    }

    fn update_receipt(&mut self, receipt: ExternalHookReceipt) -> Result<(), ExternalHookLeaseError> {
        if receipt.request_id != self.receipt.request_id
            || receipt.owner_id != self.receipt.owner_id
            || receipt.token != self.receipt.token
        {
            return Err(ExternalHookLeaseError::Adapter(
                "external hook reply changed request, owner, or token identity".into(),
            ));
        }
        self.receipt = receipt;
        Ok(())
    }

    fn reply_error(
        &mut self,
        code: ExternalHookErrorCode,
        message: String,
        receipt: Option<ExternalHookReceipt>,
    ) -> ExternalHookLeaseError {
        if let Some(receipt) = receipt {
            let _ = self.update_receipt(receipt);
        }
        match code {
            ExternalHookErrorCode::NativeUninstallUnavailable => ExternalHookLeaseError::NativeUninstallUnavailable {
                token: self.receipt.token.unwrap_or_default(),
                backend: native_api::parse_backend_image(&self.receipt.backend),
            },
            ExternalHookErrorCode::AlreadyReleased => {
                ExternalHookLeaseError::AlreadyReleased(self.receipt.token.unwrap_or_default())
            }
            _ => ExternalHookLeaseError::Adapter(message),
        }
    }
}

impl ExternalHookLease for RemoteExternalHookLease {
    fn token(&self) -> u64 {
        self.receipt.token.unwrap_or_default()
    }

    fn backend(&self) -> ExternalHookBackendKind {
        native_api::parse_backend_image(&self.receipt.backend)
    }

    fn operation(&self) -> ExternalHookOperation {
        match self.receipt.operation {
            ExternalHookCommandOperation::Install => ExternalHookOperation::Install,
            ExternalHookCommandOperation::Replace => ExternalHookOperation::Replace,
        }
    }

    fn request_id(&self) -> Option<&str> {
        Some(&self.receipt.request_id)
    }

    fn remote_receipt(&self) -> Option<ExternalHookReceipt> {
        Some(self.receipt.clone())
    }

    fn handle_released(&self) -> bool {
        self.receipt.ownership == AgentHookOwnershipState::Released
    }

    fn native_uninstall_available(&self) -> bool {
        self.receipt.native_uninstall_available
    }

    fn release(&mut self) -> Result<bool, ExternalHookLeaseError> {
        if self.handle_released() {
            return Ok(false);
        }
        let reply = self.reply(AgentCommand::ExternalHookRelease {
            request: ExternalHookActionRequest {
                owner_id: self.receipt.owner_id.clone(),
                token: self.token(),
            },
        })?;
        match reply {
            ExternalHookReply::Release { receipt, changed } => {
                self.update_receipt(receipt)?;
                Ok(changed)
            }
            ExternalHookReply::Error {
                code, message, receipt, ..
            } => Err(self.reply_error(code, message, receipt)),
            other => Err(ExternalHookLeaseError::Adapter(format!(
                "unexpected external hook release reply: {other:?}"
            ))),
        }
    }

    fn uninstall(&mut self) -> Result<(), ExternalHookLeaseError> {
        let reply = self.reply(AgentCommand::ExternalHookUninstall {
            request: ExternalHookActionRequest {
                owner_id: self.receipt.owner_id.clone(),
                token: self.token(),
            },
        })?;
        match reply {
            ExternalHookReply::Uninstall { receipt, .. } => {
                self.update_receipt(receipt)?;
                Ok(())
            }
            ExternalHookReply::Error {
                code, message, receipt, ..
            } => Err(self.reply_error(code, message, receipt)),
            other => Err(ExternalHookLeaseError::Adapter(format!(
                "unexpected external hook uninstall reply: {other:?}"
            ))),
        }
    }
}

impl ExternalHookLease for NativeExternalHookLease {
    fn token(&self) -> u64 {
        self.handle.token()
    }

    fn backend(&self) -> ExternalHookBackendKind {
        self.handle.backend()
    }

    fn operation(&self) -> ExternalHookOperation {
        self.handle.operation()
    }

    fn handle_released(&self) -> bool {
        self.handle.handle_released()
    }

    fn native_uninstall_available(&self) -> bool {
        self.handle.native_uninstall_available()
    }

    fn release(&mut self) -> Result<bool, ExternalHookLeaseError> {
        self.decision
            .release_external_hook_handle(self.handle.result_mut())
            .map_err(|error| ExternalHookLeaseError::Adapter(error.to_string()))
    }

    fn uninstall(&mut self) -> Result<(), ExternalHookLeaseError> {
        match self.decision.uninstall_external_hook_handle(self.handle.result_mut()) {
            Ok(()) => Ok(()),
            Err(ExternalHookExecutionError::Backend(HookBackendFfiError::NativeUninstallUnavailable {
                backend,
                token,
            })) => Err(ExternalHookLeaseError::NativeUninstallUnavailable { token, backend }),
            Err(ExternalHookExecutionError::Backend(HookBackendFfiError::HandleReleased { token })) => {
                Err(ExternalHookLeaseError::AlreadyReleased(token))
            }
            Err(error) => Err(ExternalHookLeaseError::Adapter(error.to_string())),
        }
    }
}

struct OwnedExternalHook {
    lease: Box<dyn ExternalHookLease>,
    target_state: ExternalHookTargetState,
    last_error: Option<String>,
}

impl OwnedExternalHook {
    fn snapshot(&self) -> ExternalHookSnapshot {
        ExternalHookSnapshot {
            token: self.lease.token(),
            backend: self.lease.backend(),
            operation: self.lease.operation(),
            ownership: if self.lease.handle_released() {
                ExternalHookOwnership::Released
            } else {
                ExternalHookOwnership::Owned
            },
            native_uninstall: if self.lease.native_uninstall_available() {
                ExternalHookNativeUninstall::Available
            } else {
                ExternalHookNativeUninstall::Unavailable
            },
            target_state: self.target_state,
            last_error: self.last_error.clone(),
        }
    }
}

/// One controller session. The command gate allows concurrent reads while
/// ensuring detach waits for all in-flight calls and rejects all later calls.
pub(crate) struct Session {
    id: SessionId,
    metadata: RwLock<SessionMetadata>,
    command_gate: RwLock<()>,
    lifecycle: Mutex<SessionLifecycle>,
}

impl fmt::Debug for Session {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Session")
            .field("snapshot", &self.snapshot())
            .finish_non_exhaustive()
    }
}

impl Session {
    pub(crate) fn new(id: SessionId, pid: Option<i32>, label: impl Into<String>) -> Self {
        Self {
            id,
            metadata: RwLock::new(SessionMetadata {
                pid,
                label: label.into(),
            }),
            command_gate: RwLock::new(()),
            lifecycle: Mutex::new(SessionLifecycle {
                state: SessionState::Attaching,
                backend: None,
                backend_shutdown: false,
                last_error: None,
                external_hooks: BTreeMap::new(),
            }),
        }
    }

    pub(crate) const fn id(&self) -> SessionId {
        self.id
    }

    pub(crate) fn state(&self) -> SessionState {
        lock(&self.lifecycle).state
    }

    pub(crate) fn is_attached(&self) -> bool {
        self.state() == SessionState::Attached
    }

    pub(crate) fn snapshot(&self) -> SessionSnapshot {
        let metadata = read(&self.metadata);
        let lifecycle = lock(&self.lifecycle);
        SessionSnapshot {
            id: self.id,
            pid: metadata.pid,
            label: metadata.label.clone(),
            state: lifecycle.state,
            last_error: lifecycle.last_error.clone(),
            external_hooks: lifecycle
                .external_hooks
                .values()
                .map(OwnedExternalHook::snapshot)
                .collect(),
        }
    }

    /// Update target metadata while injection is still being prepared. This is
    /// useful for spawn flows where the PID is unavailable at reservation time.
    pub(crate) fn update_target(&self, pid: Option<i32>, label: impl Into<String>) {
        let mut metadata = write(&self.metadata);
        metadata.pid = pid;
        metadata.label = label.into();
    }

    pub(crate) fn complete_attach(
        &self,
        backend: Arc<dyn SessionCommandBackend>,
    ) -> Result<(), SessionTransitionError> {
        let _gate = write(&self.command_gate);
        let mut lifecycle = lock(&self.lifecycle);
        if lifecycle.state != SessionState::Attaching {
            return Err(self.transition_error(lifecycle.state, "complete attach"));
        }
        lifecycle.backend = Some(backend);
        lifecycle.backend_shutdown = false;
        lifecycle.state = SessionState::Attached;
        lifecycle.last_error = None;
        Ok(())
    }

    pub(crate) fn fail_attach(&self, message: impl Into<String>) -> Result<(), SessionTransitionError> {
        let _gate = write(&self.command_gate);
        let mut lifecycle = lock(&self.lifecycle);
        if lifecycle.state != SessionState::Attaching {
            return Err(self.transition_error(lifecycle.state, "fail attach"));
        }
        lifecycle.state = SessionState::Failed;
        lifecycle.backend_shutdown = true;
        lifecycle.last_error = Some(message.into());
        let cleanup = cleanup_external_hooks_locked(&mut lifecycle);
        append_cleanup_error(&mut lifecycle.last_error, &cleanup);
        Ok(())
    }

    /// Adopt a successful external adapter result at the controller/session
    /// boundary. The native token is retained exactly as returned by the
    /// adapter; no controller token is allocated or rewritten.
    pub(crate) fn adopt_external_hook(
        &self,
        decision: AdapterDecision,
        mut handle: HookExecutionResult,
    ) -> Result<u64, SessionHookError> {
        let _gate = write(&self.command_gate);
        let mut lifecycle = lock(&self.lifecycle);
        if !matches!(lifecycle.state, SessionState::Attaching | SessionState::Attached) {
            let state = lifecycle.state;
            handle.release();
            return Err(SessionHookError::SessionNotReady { id: self.id, state });
        }
        if let Err(error) = validate_external_hook_adoption(&decision, &handle) {
            let _ = handle.release();
            return Err(error);
        }
        if lifecycle.external_hooks.contains_key(&handle.token) {
            let token = handle.token;
            handle.release();
            return Err(SessionHookError::DuplicateToken(token));
        }
        let token = handle.token;
        lifecycle.external_hooks.insert(
            token,
            OwnedExternalHook {
                lease: Box::new(NativeExternalHookLease {
                    decision,
                    handle: ControllerOwnedHook(handle),
                }),
                target_state: ExternalHookTargetState::Installed,
                last_error: None,
            },
        );
        Ok(token)
    }

    /// Stable owner identity used by the agent-side external-hook registry.
    /// The delimiter is part of the wire contract and is accepted by the
    /// common command validator.
    pub(crate) fn external_hook_owner_id(&self) -> String {
        format!("session:{}", self.id)
    }

    /// Execute an external install/replace through the attached agent and
    /// adopt the returned receipt as a controller-owned remote lease.
    pub(crate) fn execute_external_hook(
        &self,
        request: ExternalHookExecuteRequest,
        timeout: Duration,
    ) -> Result<ExternalHookReceipt, SessionHookError> {
        request.validate().map_err(|error| SessionHookError::Execution {
            message: error.to_string(),
            target_state_uncertain: false,
        })?;
        if request.owner_id != self.external_hook_owner_id() {
            return Err(SessionHookError::InvalidHandle {
                token: 0,
                reason: "request owner_id does not match the session owner",
            });
        }

        let backend = {
            let _gate = read(&self.command_gate);
            let lifecycle = lock(&self.lifecycle);
            if lifecycle.state != SessionState::Attached {
                return Err(SessionHookError::SessionNotReady {
                    id: self.id,
                    state: lifecycle.state,
                });
            }
            if let Some(existing) = find_remote_receipt(&lifecycle, &request) {
                if remote_request_matches_receipt(&request, &existing) {
                    return Ok(existing);
                }
                return Err(SessionHookError::Execution {
                    message: format!(
                        "request_id `{}` is already bound to a different controller lease",
                        request.request_id
                    ),
                    target_state_uncertain: false,
                });
            }
            lifecycle
                .backend
                .as_ref()
                .cloned()
                .ok_or_else(|| SessionHookError::Execution {
                    message: format!("session {} has no command backend", self.id),
                    target_state_uncertain: false,
                })?
        };

        let reply_value = match backend.external_hook_command(
            &AgentCommand::ExternalHookExecute {
                request: request.clone(),
            },
            timeout.max(Duration::from_millis(1)),
        ) {
            Ok(value) => value,
            Err(failure) => {
                if failure.is_transport_failure() {
                    let _ = self.mark_command_transport_failure(&failure);
                }
                return Err(SessionHookError::Execution {
                    message: failure.to_string(),
                    target_state_uncertain: failure.is_transport_failure(),
                });
            }
        };
        let reply: ExternalHookReply =
            serde_json::from_value(reply_value).map_err(|error| SessionHookError::Execution {
                message: format!("invalid external hook execute reply: {error}"),
                target_state_uncertain: false,
            })?;

        let receipt = match reply {
            ExternalHookReply::Execute { receipt, .. } => receipt,
            ExternalHookReply::Error {
                code,
                message,
                token,
                receipt,
                ..
            } => {
                let target_state_uncertain = code == ExternalHookErrorCode::TargetStateUncertain
                    || receipt
                        .as_ref()
                        .is_some_and(|value| value.target_state == AgentHookTargetState::Uncertain);
                let detail = token
                    .map(|token| format!("token={token}: {message}"))
                    .unwrap_or(message);
                return Err(SessionHookError::Execution {
                    message: detail,
                    target_state_uncertain,
                });
            }
            other => {
                return Err(SessionHookError::Execution {
                    message: format!("unexpected external hook execute reply: {other:?}"),
                    target_state_uncertain: false,
                });
            }
        };
        let token = validate_remote_receipt(&request, &receipt)?;
        let lease = RemoteExternalHookLease {
            backend,
            receipt: receipt.clone(),
            timeout: timeout.max(Duration::from_millis(1)),
        };

        let _gate = write(&self.command_gate);
        let mut lifecycle = lock(&self.lifecycle);
        if let Some(existing) = find_remote_receipt(&lifecycle, &request) {
            if remote_request_matches_receipt(&request, &existing) {
                return Ok(existing);
            }
            return Err(SessionHookError::Execution {
                message: format!(
                    "request_id `{}` is already bound to a different controller lease",
                    request.request_id
                ),
                target_state_uncertain: false,
            });
        }
        insert_external_hook_locked(self.id, &mut lifecycle, Box::new(lease))?;
        debug_assert_eq!(
            lifecycle.external_hooks.get(&token).map(|hook| hook.lease.token()),
            Some(token)
        );
        Ok(receipt)
    }

    #[cfg(test)]
    fn adopt_external_hook_lease_for_test(&self, lease: Box<dyn ExternalHookLease>) -> Result<u64, SessionHookError> {
        let _gate = write(&self.command_gate);
        let mut lifecycle = lock(&self.lifecycle);
        insert_external_hook_locked(self.id, &mut lifecycle, lease)
    }

    /// Release only controller-owned resources. This does not claim that the
    /// third-party backend restored the target; current public ABIs leave the
    /// target installed after the lease is released.
    pub(crate) fn release_external_hook(&self, token: u64) -> Result<ExternalHookRelease, SessionHookError> {
        if token == 0 {
            return Err(SessionHookError::InvalidToken);
        }
        let _gate = write(&self.command_gate);
        let mut lifecycle = lock(&self.lifecycle);
        let hook = lifecycle
            .external_hooks
            .get_mut(&token)
            .ok_or(SessionHookError::NotFound(token))?;
        if hook.lease.handle_released() {
            return Ok(ExternalHookRelease {
                snapshot: hook.snapshot(),
                released_now: false,
            });
        }
        match hook.lease.release() {
            Ok(released_now) => {
                hook.last_error = None;
                Ok(ExternalHookRelease {
                    snapshot: hook.snapshot(),
                    released_now,
                })
            }
            Err(error) => {
                let message = lease_error_message(error);
                hook.last_error = Some(message.clone());
                Err(SessionHookError::Adapter { token, message })
            }
        }
    }

    /// Request native uninstall without guessing an ABI. When the adapter
    /// reports `NativeUninstallUnavailable`, ownership and target state remain
    /// unchanged so a later cleanup can still release the controller lease.
    pub(crate) fn uninstall_external_hook(&self, token: u64) -> Result<ExternalHookRelease, SessionHookError> {
        if token == 0 {
            return Err(SessionHookError::InvalidToken);
        }
        let _gate = write(&self.command_gate);
        let mut lifecycle = lock(&self.lifecycle);
        let hook = lifecycle
            .external_hooks
            .get_mut(&token)
            .ok_or(SessionHookError::NotFound(token))?;
        if hook.lease.handle_released() {
            if hook.target_state == ExternalHookTargetState::Restored {
                hook.last_error = None;
                return Ok(ExternalHookRelease {
                    snapshot: hook.snapshot(),
                    released_now: false,
                });
            }
            return Err(SessionHookError::AlreadyReleased(token));
        }
        match hook.lease.uninstall() {
            Ok(()) => {
                hook.target_state = ExternalHookTargetState::Restored;
                if hook.lease.handle_released() {
                    hook.last_error = None;
                    return Ok(ExternalHookRelease {
                        snapshot: hook.snapshot(),
                        released_now: true,
                    });
                }
                match hook.lease.release() {
                    Ok(released_now) => {
                        hook.last_error = None;
                        Ok(ExternalHookRelease {
                            snapshot: hook.snapshot(),
                            released_now,
                        })
                    }
                    Err(error) => {
                        let message = lease_error_message(error);
                        append_error(&mut hook.last_error, message.clone());
                        Err(SessionHookError::Adapter { token, message })
                    }
                }
            }
            Err(ExternalHookLeaseError::NativeUninstallUnavailable { backend, .. }) => {
                let message = format!(
                    "native uninstall unavailable; target remains installed; ownership retained ({})",
                    backend.as_str()
                );
                append_error(&mut hook.last_error, message);
                Err(SessionHookError::NativeUninstallUnavailable { token, backend })
            }
            Err(ExternalHookLeaseError::AlreadyReleased(..)) => Err(SessionHookError::AlreadyReleased(token)),
            Err(error) => {
                let message = lease_error_message(error);
                append_error(&mut hook.last_error, message.clone());
                Err(SessionHookError::Adapter { token, message })
            }
        }
    }

    pub(crate) fn external_hook_status(&self) -> Vec<ExternalHookSnapshot> {
        lock(&self.lifecycle)
            .external_hooks
            .values()
            .map(OwnedExternalHook::snapshot)
            .collect()
    }

    /// Release every controller-owned adapter lease. The report is deliberately
    /// non-fatal for the normal `NativeUninstallUnavailable` case: release is
    /// the supported cleanup operation and the target-installed state remains
    /// visible in each snapshot.
    pub(crate) fn cleanup_external_hooks(&self) -> ExternalHookCleanupReport {
        let _gate = write(&self.command_gate);
        let mut lifecycle = lock(&self.lifecycle);
        cleanup_external_hooks_locked(&mut lifecycle)
    }

    pub(crate) fn rpc_call(
        &self,
        method: &str,
        args: &Value,
        timeout: Duration,
    ) -> Result<Value, SessionCommandFailure> {
        if method.is_empty() || method.chars().any(char::is_whitespace) {
            return Err(SessionCommandFailure::BadRequest(
                "RPC method must be non-empty and contain no whitespace".into(),
            ));
        }

        let _gate = read(&self.command_gate);
        let backend = {
            let lifecycle = lock(&self.lifecycle);
            if lifecycle.state != SessionState::Attached {
                let detail = lifecycle
                    .last_error
                    .as_deref()
                    .map(|error| format!("{}: {error}", lifecycle.state.as_status()))
                    .unwrap_or_else(|| lifecycle.state.as_status().to_string());
                return Err(SessionCommandFailure::Unavailable(format!(
                    "session {} is {detail}",
                    self.id
                )));
            }
            lifecycle.backend.as_ref().cloned().ok_or_else(|| {
                SessionCommandFailure::Unavailable(format!("session {} has no command backend", self.id))
            })?
        };
        backend.rpc_call(method, args, timeout)
    }

    pub(crate) fn execute_command(&self, command: &str, timeout: Duration) -> Result<Value, SessionCommandFailure> {
        let command = command.trim();
        if command.is_empty() {
            return Err(SessionCommandFailure::BadRequest(
                "controller command must not be empty".into(),
            ));
        }

        let _gate = read(&self.command_gate);
        let backend = {
            let lifecycle = lock(&self.lifecycle);
            if lifecycle.state != SessionState::Attached {
                let detail = lifecycle
                    .last_error
                    .as_deref()
                    .map(|error| format!("{}: {error}", lifecycle.state.as_status()))
                    .unwrap_or_else(|| lifecycle.state.as_status().to_string());
                return Err(SessionCommandFailure::Unavailable(format!(
                    "session {} is {detail}",
                    self.id
                )));
            }
            lifecycle.backend.as_ref().cloned().ok_or_else(|| {
                SessionCommandFailure::Unavailable(format!("session {} has no command backend", self.id))
            })?
        };
        backend.execute_command(command, timeout)
    }

    /// Run a transport health probe while sharing the command gate with normal
    /// calls. This prevents a probe from interleaving protocol frames with an
    /// active command and makes detach wait for the probe as well.
    pub(crate) fn health_check(&self, timeout: Duration) -> Result<(), SessionCommandFailure> {
        let _gate = read(&self.command_gate);
        let backend = {
            let lifecycle = lock(&self.lifecycle);
            if lifecycle.state != SessionState::Attached {
                let detail = lifecycle
                    .last_error
                    .as_deref()
                    .map(|error| format!("{}: {error}", lifecycle.state.as_status()))
                    .unwrap_or_else(|| lifecycle.state.as_status().to_string());
                return Err(SessionCommandFailure::Unavailable(format!(
                    "session {} is {detail}",
                    self.id
                )));
            }
            lifecycle.backend.as_ref().cloned().ok_or_else(|| {
                SessionCommandFailure::Unavailable(format!("session {} has no command backend", self.id))
            })?
        };
        backend.health_check(timeout)
    }

    /// Record a transport failure before registry cleanup. The state remains
    /// observable through any existing `Arc<Session>` until detach completes.
    pub(crate) fn mark_unhealthy(&self, failure: &SessionCommandFailure) -> Result<(), SessionTransitionError> {
        self.mark_transport_failure("health check", failure)
    }

    pub(crate) fn mark_command_transport_failure(
        &self,
        failure: &SessionCommandFailure,
    ) -> Result<(), SessionTransitionError> {
        self.mark_transport_failure("command transport", failure)
    }

    fn mark_transport_failure(
        &self,
        source: &'static str,
        failure: &SessionCommandFailure,
    ) -> Result<(), SessionTransitionError> {
        let _gate = write(&self.command_gate);
        let mut lifecycle = lock(&self.lifecycle);
        match lifecycle.state {
            SessionState::Attached => {
                lifecycle.state = SessionState::Failed;
                append_error(&mut lifecycle.last_error, format!("{source} failed: {failure}"));
                let cleanup = cleanup_external_hooks_locked(&mut lifecycle);
                append_cleanup_error(&mut lifecycle.last_error, &cleanup);
                Ok(())
            }
            SessionState::Failed => {
                append_error(&mut lifecycle.last_error, format!("{source} failed: {failure}"));
                let cleanup = cleanup_external_hooks_locked(&mut lifecycle);
                append_cleanup_error(&mut lifecycle.last_error, &cleanup);
                Ok(())
            }
            state => Err(self.transition_error(state, "mark unhealthy")),
        }
    }

    /// Detach exactly once. The write gate waits for in-flight RPC calls before
    /// invoking backend shutdown and prevents new calls from entering.
    pub(crate) fn detach(&self, timeout: Duration) -> Result<(), SessionCommandFailure> {
        let _gate = write(&self.command_gate);
        let (backend, previous_state) = {
            let mut lifecycle = lock(&self.lifecycle);
            match lifecycle.state {
                SessionState::Attaching => {
                    let cleanup = cleanup_external_hooks_locked(&mut lifecycle);
                    lifecycle.state = SessionState::Detached;
                    lifecycle.backend_shutdown = true;
                    append_cleanup_error(&mut lifecycle.last_error, &cleanup);
                    return match cleanup.failure_message() {
                        Some(message) => {
                            lifecycle.state = SessionState::Failed;
                            Err(SessionCommandFailure::Internal(message))
                        }
                        None => Ok(()),
                    };
                }
                SessionState::Attached | SessionState::Failed => {
                    let previous_state = lifecycle.state;
                    lifecycle.state = SessionState::Detaching;
                    let backend = if lifecycle.backend_shutdown {
                        None
                    } else {
                        lifecycle.backend.take()
                    };
                    (backend, previous_state)
                }
                SessionState::Detaching | SessionState::Detached => return Ok(()),
            }
        };

        let detach_result = match backend.as_ref() {
            Some(backend) => backend.detach(timeout),
            None => Ok(()),
        };
        let mut lifecycle = lock(&self.lifecycle);
        let cleanup = cleanup_external_hooks_locked(&mut lifecycle);
        let cleanup_failure = cleanup.failure_message();
        let detach_succeeded = detach_result.is_ok();
        let combined_failure = match (detach_result, cleanup_failure) {
            (Ok(()), None) => None,
            (Err(detach), None) => Some(detach),
            (Ok(()), Some(cleanup)) => Some(SessionCommandFailure::Internal(cleanup)),
            (Err(detach), Some(cleanup)) => Some(SessionCommandFailure::Internal(format!("{detach}; {cleanup}"))),
        };
        match combined_failure {
            None => {
                lifecycle.state = SessionState::Detached;
                lifecycle.backend = None;
                lifecycle.backend_shutdown = true;
                if previous_state != SessionState::Failed {
                    lifecycle.last_error = None;
                }
                Ok(())
            }
            Some(failure) => {
                lifecycle.state = SessionState::Failed;
                if detach_succeeded {
                    lifecycle.backend_shutdown = true;
                    lifecycle.backend = None;
                } else if !lifecycle.backend_shutdown {
                    lifecycle.backend = backend;
                }
                append_error(&mut lifecycle.last_error, failure.to_string());
                Err(failure)
            }
        }
    }

    fn transition_error(&self, state: SessionState, operation: &'static str) -> SessionTransitionError {
        SessionTransitionError {
            id: self.id,
            state,
            operation,
        }
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        if let Ok(lifecycle) = self.lifecycle.get_mut() {
            for hook in lifecycle.external_hooks.values_mut() {
                let _ = hook.lease.release();
            }
        }
    }
}

fn append_cleanup_error(last_error: &mut Option<String>, cleanup: &ExternalHookCleanupReport) {
    if let Some(message) = cleanup.failure_message() {
        append_error(last_error, message);
    }
}

fn append_error(last_error: &mut Option<String>, message: impl Into<String>) {
    let message = message.into();
    *last_error = Some(match last_error.take() {
        Some(existing) => format!("{existing}; {message}"),
        None => message,
    });
}

fn cleanup_external_hooks_locked(lifecycle: &mut SessionLifecycle) -> ExternalHookCleanupReport {
    let mut report = ExternalHookCleanupReport::default();
    for hook in lifecycle.external_hooks.values_mut() {
        if hook.lease.handle_released() {
            report.already_released += 1;
            hook.last_error = None;
            continue;
        }
        report.attempted += 1;
        match hook.lease.release() {
            Ok(true) => {
                report.released += 1;
                hook.last_error = None;
            }
            Ok(false) => {
                report.already_released += 1;
                hook.last_error = None;
            }
            Err(error) => {
                report.failed += 1;
                let message = lease_error_message(error);
                append_error(&mut hook.last_error, message.clone());
                report.errors.push(format!("token {}: {message}", hook.lease.token()));
            }
        }
    }
    report
}

fn insert_external_hook_locked(
    id: SessionId,
    lifecycle: &mut SessionLifecycle,
    mut lease: Box<dyn ExternalHookLease>,
) -> Result<u64, SessionHookError> {
    if !matches!(lifecycle.state, SessionState::Attaching | SessionState::Attached) {
        let state = lifecycle.state;
        let _ = lease.release();
        return Err(SessionHookError::SessionNotReady { id, state });
    }
    let token = lease.token();
    if token == 0 {
        let _ = lease.release();
        return Err(SessionHookError::InvalidToken);
    }
    if lifecycle.external_hooks.contains_key(&token) {
        let _ = lease.release();
        return Err(SessionHookError::DuplicateToken(token));
    }
    lifecycle.external_hooks.insert(
        token,
        OwnedExternalHook {
            lease,
            target_state: ExternalHookTargetState::Installed,
            last_error: None,
        },
    );
    Ok(token)
}

fn lease_error_message(error: ExternalHookLeaseError) -> String {
    match error {
        ExternalHookLeaseError::NativeUninstallUnavailable { token, backend } => {
            format!("native uninstall unavailable for token {token} ({})", backend.as_str())
        }
        ExternalHookLeaseError::AlreadyReleased(token) => {
            format!("external hook token {token} was already released")
        }
        ExternalHookLeaseError::Adapter(message) => message,
    }
}

fn validate_external_hook_adoption(
    decision: &AdapterDecision,
    handle: &HookExecutionResult,
) -> Result<(), SessionHookError> {
    if handle.token == 0 {
        return Err(SessionHookError::InvalidToken);
    }
    if decision.execution_boundary != ExecutionBoundary::ExternalFfi
        || !decision.executable
        || !decision.policy_allowed
        || decision.command_mode != AdapterCommandMode::Allowed
    {
        return Err(SessionHookError::InvalidHandle {
            token: handle.token,
            reason: "decision is not an executable external FFI decision",
        });
    }
    let expected_backend = match decision.adapter {
        AdapterKind::ElleKit => ExternalHookBackendKind::ElleKit,
        AdapterKind::Substrate => ExternalHookBackendKind::Substrate,
        AdapterKind::Substitute => ExternalHookBackendKind::Substitute,
        AdapterKind::Libhooker => ExternalHookBackendKind::Libhooker,
        AdapterKind::InternalInline | AdapterKind::EnvironmentProbe | AdapterKind::None => {
            return Err(SessionHookError::InvalidHandle {
                token: handle.token,
                reason: "decision does not select an external adapter",
            });
        }
    };
    if handle.backend != expected_backend {
        return Err(SessionHookError::InvalidHandle {
            token: handle.token,
            reason: "handle backend does not match the selected adapter",
        });
    }
    let expected_operation = match decision.operation {
        HookOperation::Install | HookOperation::Attach => ExternalHookOperation::Install,
        HookOperation::Replace => ExternalHookOperation::Replace,
        HookOperation::Query | HookOperation::Uninstall | HookOperation::Cleanup => {
            return Err(SessionHookError::InvalidHandle {
                token: handle.token,
                reason: "decision operation does not produce an owned install handle",
            });
        }
    };
    if handle.operation != expected_operation {
        return Err(SessionHookError::InvalidHandle {
            token: handle.token,
            reason: "handle operation does not match the decision",
        });
    }
    Ok(())
}

fn validate_remote_receipt(
    request: &ExternalHookExecuteRequest,
    receipt: &ExternalHookReceipt,
) -> Result<u64, SessionHookError> {
    let token = receipt.token.ok_or(SessionHookError::InvalidHandle {
        token: 0,
        reason: "execute receipt does not contain a token",
    })?;
    if token == 0 {
        return Err(SessionHookError::InvalidToken);
    }
    if receipt.request_id != request.request_id || receipt.owner_id != request.owner_id {
        return Err(SessionHookError::InvalidHandle {
            token,
            reason: "execute receipt identity does not match the request",
        });
    }
    if receipt.backend_image != request.backend_image
        || receipt.target != request.target
        || receipt.replacement != request.replacement
        || receipt.operation != request.operation
    {
        return Err(SessionHookError::InvalidHandle {
            token,
            reason: "execute receipt target or operation does not match the request",
        });
    }
    if receipt.ownership != AgentHookOwnershipState::Owned || receipt.target_state != AgentHookTargetState::Installed {
        return Err(SessionHookError::InvalidHandle {
            token,
            reason: "execute receipt is not an owned installed hook",
        });
    }
    if !native_api::parse_backend_image(&receipt.backend).is_known() {
        return Err(SessionHookError::InvalidHandle {
            token,
            reason: "execute receipt selects an unknown backend",
        });
    }
    Ok(token)
}

fn remote_request_matches_receipt(request: &ExternalHookExecuteRequest, receipt: &ExternalHookReceipt) -> bool {
    receipt.request_id == request.request_id
        && receipt.owner_id == request.owner_id
        && receipt.backend_image == request.backend_image
        && receipt.operation == request.operation
        && receipt.target == request.target
        && receipt.replacement == request.replacement
}

fn find_remote_receipt(
    lifecycle: &SessionLifecycle,
    request: &ExternalHookExecuteRequest,
) -> Option<ExternalHookReceipt> {
    lifecycle.external_hooks.values().find_map(|hook| {
        (hook.lease.request_id() == Some(request.request_id.as_str()))
            .then(|| hook.lease.remote_receipt())
            .flatten()
    })
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn read<T>(lock: &RwLock<T>) -> RwLockReadGuard<'_, T> {
    lock.read().unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn write<T>(lock: &RwLock<T>) -> RwLockWriteGuard<'_, T> {
    lock.write().unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[cfg(test)]
mod tests {
    use super::{
        ExternalHookBackendKind, ExternalHookLease, ExternalHookLeaseError, ExternalHookOperation,
        ExternalHookOwnership, ExternalHookTargetState, Session, SessionCommandBackend, SessionCommandFailure,
        SessionHookError, SessionId, SessionState,
    };
    use common::command::{
        ExternalHookCommandOperation, ExternalHookExecuteRequest,
        ExternalHookOwnershipState as AgentHookOwnershipState, ExternalHookReceipt, ExternalHookReply,
        ExternalHookTargetState as AgentHookTargetState,
    };
    use common::AgentCommand;
    use serde_json::{json, Value};
    use std::{
        collections::VecDeque,
        sync::{
            atomic::{AtomicUsize, Ordering},
            mpsc, Arc, Mutex,
        },
        thread,
        time::Duration,
    };

    struct FakeHookLease {
        token: u64,
        backend: ExternalHookBackendKind,
        operation: ExternalHookOperation,
        released: bool,
        release_count: Arc<AtomicUsize>,
        uninstall_unavailable: bool,
        release_error: Option<String>,
    }

    impl ExternalHookLease for FakeHookLease {
        fn token(&self) -> u64 {
            self.token
        }

        fn backend(&self) -> ExternalHookBackendKind {
            self.backend
        }

        fn operation(&self) -> ExternalHookOperation {
            self.operation
        }

        fn handle_released(&self) -> bool {
            self.released
        }

        fn native_uninstall_available(&self) -> bool {
            false
        }

        fn release(&mut self) -> Result<bool, ExternalHookLeaseError> {
            if self.released {
                return Ok(false);
            }
            if let Some(message) = self.release_error.take() {
                return Err(ExternalHookLeaseError::Adapter(message));
            }
            self.released = true;
            self.release_count.fetch_add(1, Ordering::SeqCst);
            Ok(true)
        }

        fn uninstall(&mut self) -> Result<(), ExternalHookLeaseError> {
            if self.released {
                return Err(ExternalHookLeaseError::AlreadyReleased(self.token));
            }
            if self.uninstall_unavailable {
                return Err(ExternalHookLeaseError::NativeUninstallUnavailable {
                    token: self.token,
                    backend: self.backend,
                });
            }
            Ok(())
        }
    }

    fn fake_lease(token: u64) -> (Box<dyn ExternalHookLease>, Arc<AtomicUsize>) {
        let release_count = Arc::new(AtomicUsize::new(0));
        (
            Box::new(FakeHookLease {
                token,
                backend: ExternalHookBackendKind::ElleKit,
                operation: ExternalHookOperation::Install,
                released: false,
                release_count: Arc::clone(&release_count),
                uninstall_unavailable: true,
                release_error: None,
            }),
            release_count,
        )
    }

    fn configurable_fake_lease(
        token: u64,
        uninstall_unavailable: bool,
        release_error: Option<&str>,
    ) -> (Box<dyn ExternalHookLease>, Arc<AtomicUsize>) {
        let release_count = Arc::new(AtomicUsize::new(0));
        (
            Box::new(FakeHookLease {
                token,
                backend: ExternalHookBackendKind::ElleKit,
                operation: ExternalHookOperation::Install,
                released: false,
                release_count: Arc::clone(&release_count),
                uninstall_unavailable,
                release_error: release_error.map(str::to_owned),
            }),
            release_count,
        )
    }

    #[derive(Default)]
    struct RecordingBackend {
        calls: Mutex<Vec<String>>,
        detach_count: AtomicUsize,
    }

    impl SessionCommandBackend for RecordingBackend {
        fn rpc_call(&self, method: &str, args: &Value, _timeout: Duration) -> Result<Value, SessionCommandFailure> {
            self.calls.lock().expect("calls lock").push(method.into());
            Ok(args.clone())
        }

        fn execute_command(&self, command: &str, _timeout: Duration) -> Result<Value, SessionCommandFailure> {
            self.calls.lock().expect("calls lock").push(command.into());
            Ok(json!({ "command": command }))
        }

        fn detach(&self, _timeout: Duration) -> Result<(), SessionCommandFailure> {
            self.detach_count.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    struct RemoteBackend {
        replies: Mutex<VecDeque<Value>>,
        commands: Mutex<Vec<AgentCommand>>,
    }

    impl RemoteBackend {
        fn new(replies: impl IntoIterator<Item = Value>) -> Self {
            Self {
                replies: Mutex::new(replies.into_iter().collect()),
                commands: Mutex::new(Vec::new()),
            }
        }

        fn commands(&self) -> Vec<AgentCommand> {
            self.commands.lock().expect("commands lock").clone()
        }
    }

    impl SessionCommandBackend for RemoteBackend {
        fn rpc_call(&self, _method: &str, _args: &Value, _timeout: Duration) -> Result<Value, SessionCommandFailure> {
            Err(SessionCommandFailure::BadRequest(
                "RPC is not part of this fake backend".into(),
            ))
        }

        fn external_hook_command(
            &self,
            command: &AgentCommand,
            _timeout: Duration,
        ) -> Result<Value, SessionCommandFailure> {
            self.commands.lock().expect("commands lock").push(command.clone());
            self.replies
                .lock()
                .expect("replies lock")
                .pop_front()
                .ok_or_else(|| SessionCommandFailure::Unavailable("fake agent reply queue is empty".into()))
        }
    }

    fn remote_request(session_id: u64) -> ExternalHookExecuteRequest {
        ExternalHookExecuteRequest {
            request_id: "request-1".into(),
            owner_id: format!("session:{session_id}"),
            operation: ExternalHookCommandOperation::Replace,
            backend_image: "/var/jb/usr/lib/libellekit.dylib".into(),
            target: 0x1000,
            replacement: 0x2000,
        }
    }

    fn remote_receipt(request: &ExternalHookExecuteRequest, token: u64) -> ExternalHookReceipt {
        ExternalHookReceipt {
            request_id: request.request_id.clone(),
            owner_id: request.owner_id.clone(),
            token: Some(token),
            backend: "ellekit".into(),
            backend_image: request.backend_image.clone(),
            operation: request.operation,
            target: request.target,
            replacement: request.replacement,
            original: Some(0x3000),
            native_result: None,
            ownership: AgentHookOwnershipState::Owned,
            target_state: AgentHookTargetState::Installed,
            native_uninstall_available: true,
            last_error: None,
        }
    }

    fn remote_reply(value: ExternalHookReply) -> Value {
        serde_json::to_value(value).expect("external hook reply JSON")
    }

    #[test]
    fn session_id_round_trips_and_rejects_legacy_zero() {
        let id = "42".parse::<SessionId>().expect("session ID");
        assert_eq!(id.get(), 42);
        assert_eq!(id.to_string(), "42");
        assert!("0".parse::<SessionId>().is_err());
        assert!("invalid".parse::<SessionId>().is_err());
        assert_eq!(
            SessionCommandFailure::Internal("invalid JSON reply".into()).to_string(),
            "session command failed: invalid JSON reply"
        );
    }

    #[test]
    fn default_external_hook_command_boundary_is_explicitly_unsupported() {
        let backend = RecordingBackend::default();
        let error = backend
            .external_hook_command(&AgentCommand::Ping, Duration::from_secs(1))
            .expect_err("default backend boundary should report unsupported commands");
        assert!(matches!(
            error,
            SessionCommandFailure::BadRequest(message)
                if message.contains("does not support external hook commands")
        ));
    }

    #[test]
    fn remote_external_hook_receipt_is_adopted_and_uninstall_round_trips() {
        let request = remote_request(30);
        let receipt = remote_receipt(&request, 901);
        let mut restored = receipt.clone();
        restored.ownership = AgentHookOwnershipState::Released;
        restored.target_state = AgentHookTargetState::Restored;
        let backend = Arc::new(RemoteBackend::new([
            remote_reply(ExternalHookReply::Execute {
                receipt: receipt.clone(),
                replayed: false,
            }),
            remote_reply(ExternalHookReply::Uninstall {
                receipt: restored,
                changed: true,
            }),
        ]));
        let session = Session::new(SessionId::from_raw(30).expect("nonzero"), Some(42), "target");
        session.complete_attach(backend.clone()).expect("attach");

        let adopted = session
            .execute_external_hook(request.clone(), Duration::from_secs(1))
            .expect("remote execute");
        assert_eq!(adopted.token, Some(901));
        let snapshot = &session.snapshot().external_hooks[0];
        assert_eq!(snapshot.backend, ExternalHookBackendKind::ElleKit);
        assert_eq!(snapshot.operation, ExternalHookOperation::Replace);
        assert_eq!(snapshot.ownership, ExternalHookOwnership::Owned);

        let replayed = session
            .execute_external_hook(request.clone(), Duration::from_secs(1))
            .expect("controller-side idempotent replay");
        assert_eq!(replayed.token, Some(901));

        let result = session.uninstall_external_hook(901).expect("remote uninstall");
        assert!(result.released_now);
        assert_eq!(result.snapshot.ownership, ExternalHookOwnership::Released);
        assert_eq!(result.snapshot.target_state, ExternalHookTargetState::Restored);
        let second = session
            .uninstall_external_hook(901)
            .expect("idempotent remote uninstall");
        assert!(!second.released_now);

        let commands = backend.commands();
        assert!(matches!(
            &commands[0],
            AgentCommand::ExternalHookExecute { request: value } if value == &request
        ));
        assert!(matches!(
            &commands[1],
            AgentCommand::ExternalHookUninstall { request: value } if value.owner_id == "session:30" && value.token == 901
        ));
        assert_eq!(commands.len(), 2);
    }

    #[test]
    fn remote_external_hook_release_tracks_agent_receipt_and_rejects_owner_drift() {
        let request = remote_request(31);
        let receipt = remote_receipt(&request, 902);
        let mut released = receipt.clone();
        released.ownership = AgentHookOwnershipState::Released;
        let backend = Arc::new(RemoteBackend::new([
            remote_reply(ExternalHookReply::Execute {
                receipt,
                replayed: false,
            }),
            remote_reply(ExternalHookReply::Release {
                receipt: released,
                changed: true,
            }),
        ]));
        let session = Session::new(SessionId::from_raw(31).expect("nonzero"), Some(42), "target");
        session.complete_attach(backend.clone()).expect("attach");
        session
            .execute_external_hook(request.clone(), Duration::from_secs(1))
            .expect("remote execute");
        let result = session.release_external_hook(902).expect("remote release");
        assert!(result.released_now);
        assert_eq!(result.snapshot.ownership, ExternalHookOwnership::Released);
        assert_eq!(
            session.snapshot().external_hooks[0].target_state,
            ExternalHookTargetState::Installed
        );

        let mut mismatched = request;
        mismatched.owner_id = "session:999".into();
        let error = session
            .execute_external_hook(mismatched, Duration::from_secs(1))
            .expect_err("owner drift");
        assert!(matches!(error, SessionHookError::InvalidHandle { .. }));
        assert_eq!(backend.commands().len(), 2);
    }

    #[test]
    fn remote_external_hook_transport_failure_marks_session_failed() {
        let backend = Arc::new(RemoteBackend::new([]));
        let session = Session::new(SessionId::from_raw(32).expect("nonzero"), Some(42), "target");
        session.complete_attach(backend).expect("attach");
        let error = session
            .execute_external_hook(remote_request(32), Duration::from_secs(1))
            .expect_err("transport failure");
        assert!(matches!(
            error,
            SessionHookError::Execution {
                target_state_uncertain: true,
                ..
            }
        ));
        assert_eq!(session.state(), SessionState::Failed);
        assert!(session.snapshot().last_error.is_some());
    }

    #[test]
    fn attach_call_and_detach_follow_lifecycle() {
        let backend = Arc::new(RecordingBackend::default());
        let session = Session::new(SessionId::from_raw(1).expect("nonzero"), Some(42), "target");
        assert_eq!(session.state(), SessionState::Attaching);
        assert!(matches!(
            session.rpc_call("echo", &json!([]), Duration::from_secs(1)),
            Err(SessionCommandFailure::Unavailable(_))
        ));

        session.complete_attach(backend.clone()).expect("complete attach");
        assert_eq!(
            session
                .rpc_call("echo", &json!([1, 2]), Duration::from_secs(1))
                .expect("RPC call"),
            json!([1, 2])
        );
        assert_eq!(
            session
                .execute_command("native.images", Duration::from_secs(1))
                .expect("controller command"),
            json!({ "command": "native.images" })
        );
        assert!(matches!(
            session.execute_command("   ", Duration::from_secs(1)),
            Err(SessionCommandFailure::BadRequest(_))
        ));
        session.detach(Duration::from_secs(1)).expect("detach");
        session.detach(Duration::from_secs(1)).expect("idempotent detach");

        assert_eq!(session.state(), SessionState::Detached);
        assert_eq!(backend.detach_count.load(Ordering::SeqCst), 1);
        assert!(matches!(
            session.rpc_call("echo", &json!([]), Duration::from_secs(1)),
            Err(SessionCommandFailure::Unavailable(_))
        ));
    }

    #[test]
    fn external_hook_release_is_session_owned_and_idempotent() {
        let session = Session::new(SessionId::from_raw(20).expect("nonzero"), Some(42), "target");
        session
            .complete_attach(Arc::new(RecordingBackend::default()))
            .expect("attach");
        let (lease, release_count) = fake_lease(77);
        assert_eq!(session.adopt_external_hook_lease_for_test(lease), Ok(77));

        let owned = &session.snapshot().external_hooks[0];
        assert_eq!(owned.ownership, ExternalHookOwnership::Owned);
        assert_eq!(owned.target_state, ExternalHookTargetState::Installed);
        assert_eq!(owned.native_uninstall.as_status(), "unavailable");

        let first = session.release_external_hook(77).expect("first release");
        assert!(first.released_now);
        assert_eq!(first.snapshot.ownership, ExternalHookOwnership::Released);
        assert_eq!(first.snapshot.target_state, ExternalHookTargetState::Installed);
        let second = session.release_external_hook(77).expect("idempotent release");
        assert!(!second.released_now);
        assert_eq!(release_count.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn native_uninstall_unavailable_preserves_owned_target_until_release() {
        let session = Session::new(SessionId::from_raw(21).expect("nonzero"), Some(42), "target");
        session
            .complete_attach(Arc::new(RecordingBackend::default()))
            .expect("attach");
        let (lease, release_count) = fake_lease(78);
        session.adopt_external_hook_lease_for_test(lease).expect("adopt");

        assert!(matches!(
            session.uninstall_external_hook(78),
            Err(SessionHookError::NativeUninstallUnavailable {
                token: 78,
                backend: ExternalHookBackendKind::ElleKit,
            })
        ));
        let status = &session.snapshot().external_hooks[0];
        assert_eq!(status.ownership, ExternalHookOwnership::Owned);
        assert_eq!(status.target_state, ExternalHookTargetState::Installed);
        assert_eq!(release_count.load(Ordering::SeqCst), 0);

        session.release_external_hook(78).expect("lease release");
        assert_eq!(release_count.load(Ordering::SeqCst), 1);
        assert!(matches!(
            session.uninstall_external_hook(78),
            Err(SessionHookError::AlreadyReleased(78))
        ));
    }

    #[test]
    fn uninstall_is_idempotent_after_restoring_and_releasing() {
        let session = Session::new(SessionId::from_raw(24).expect("nonzero"), Some(42), "target");
        session
            .complete_attach(Arc::new(RecordingBackend::default()))
            .expect("attach");
        let (lease, release_count) = configurable_fake_lease(81, false, None);
        session.adopt_external_hook_lease_for_test(lease).expect("adopt");

        let first = session.uninstall_external_hook(81).expect("first uninstall");
        assert!(first.released_now);
        assert_eq!(first.snapshot.ownership, ExternalHookOwnership::Released);
        assert_eq!(first.snapshot.target_state, ExternalHookTargetState::Restored);

        let second = session.uninstall_external_hook(81).expect("idempotent uninstall");
        assert!(!second.released_now);
        assert_eq!(second.snapshot.ownership, ExternalHookOwnership::Released);
        assert_eq!(second.snapshot.target_state, ExternalHookTargetState::Restored);
        assert_eq!(release_count.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn uninstall_release_failure_is_visible_on_restored_hook() {
        let session = Session::new(SessionId::from_raw(25).expect("nonzero"), Some(42), "target");
        session
            .complete_attach(Arc::new(RecordingBackend::default()))
            .expect("attach");
        let (lease, release_count) = configurable_fake_lease(82, false, Some("lease release failed"));
        session.adopt_external_hook_lease_for_test(lease).expect("adopt");

        assert!(matches!(
            session.uninstall_external_hook(82),
            Err(SessionHookError::Adapter { token: 82, .. })
        ));
        let snapshot = &session.snapshot().external_hooks[0];
        assert_eq!(snapshot.ownership, ExternalHookOwnership::Owned);
        assert_eq!(snapshot.target_state, ExternalHookTargetState::Restored);
        assert!(snapshot
            .last_error
            .as_deref()
            .is_some_and(|error| error.contains("lease release failed")));
        assert_eq!(release_count.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn failed_attach_releases_pending_external_hooks() {
        let session = Session::new(SessionId::from_raw(22).expect("nonzero"), None, "spawn target");
        let (lease, release_count) = fake_lease(79);
        session
            .adopt_external_hook_lease_for_test(lease)
            .expect("adopt while attaching");
        session.fail_attach("bootstrap failed").expect("fail attach");
        assert_eq!(session.state(), SessionState::Failed);
        assert_eq!(release_count.load(Ordering::SeqCst), 1);
        assert_eq!(
            session.snapshot().external_hooks[0].ownership,
            ExternalHookOwnership::Released
        );
    }

    #[test]
    fn detach_releases_external_hooks_even_when_backend_shutdown_retries() {
        let backend = Arc::new(RetryDetachBackend {
            attempts: AtomicUsize::new(0),
        });
        let session = Session::new(SessionId::from_raw(23).expect("nonzero"), Some(42), "target");
        session.complete_attach(backend.clone()).expect("attach");
        let (lease, release_count) = fake_lease(80);
        session.adopt_external_hook_lease_for_test(lease).expect("adopt");

        assert!(session.detach(Duration::from_secs(1)).is_err());
        assert_eq!(session.state(), SessionState::Failed);
        assert_eq!(release_count.load(Ordering::SeqCst), 1);
        session.detach(Duration::from_secs(1)).expect("retry detach");
        assert_eq!(session.state(), SessionState::Detached);
        assert_eq!(release_count.load(Ordering::SeqCst), 1);
        assert_eq!(backend.attempts.load(Ordering::SeqCst), 2);
    }

    struct BlockingBackend {
        entered: mpsc::Sender<()>,
        release: Mutex<mpsc::Receiver<()>>,
        detached: mpsc::Sender<()>,
    }

    impl SessionCommandBackend for BlockingBackend {
        fn rpc_call(&self, _method: &str, _args: &Value, _timeout: Duration) -> Result<Value, SessionCommandFailure> {
            self.entered.send(()).expect("signal call entry");
            self.release.lock().expect("release lock").recv().expect("release call");
            Ok(json!(true))
        }

        fn detach(&self, _timeout: Duration) -> Result<(), SessionCommandFailure> {
            self.detached.send(()).expect("signal detach");
            Ok(())
        }
    }

    #[test]
    fn detach_waits_for_in_flight_command() {
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let (detached_tx, detached_rx) = mpsc::channel();
        let backend = Arc::new(BlockingBackend {
            entered: entered_tx,
            release: Mutex::new(release_rx),
            detached: detached_tx,
        });
        let session = Arc::new(Session::new(
            SessionId::from_raw(1).expect("nonzero"),
            Some(42),
            "target",
        ));
        session.complete_attach(backend).expect("complete attach");

        let caller_session = Arc::clone(&session);
        let caller = thread::spawn(move || caller_session.rpc_call("wait", &json!([]), Duration::from_secs(1)));
        entered_rx.recv().expect("call entered");

        let detach_session = Arc::clone(&session);
        let detacher = thread::spawn(move || detach_session.detach(Duration::from_secs(1)));
        assert!(detached_rx.recv_timeout(Duration::from_millis(50)).is_err());
        release_tx.send(()).expect("release command");

        assert_eq!(caller.join().expect("caller thread").expect("RPC result"), json!(true));
        detacher.join().expect("detach thread").expect("detach result");
        detached_rx.recv().expect("backend detached");
        assert_eq!(session.state(), SessionState::Detached);
    }

    #[test]
    fn failed_attach_retains_diagnostic() {
        let session = Session::new(SessionId::from_raw(7).expect("nonzero"), None, "spawn target");
        session.fail_attach("bootstrap timed out").expect("fail attach");
        let snapshot = session.snapshot();
        assert_eq!(snapshot.state, SessionState::Failed);
        assert_eq!(snapshot.last_error.as_deref(), Some("bootstrap timed out"));
        assert_eq!(snapshot.status(), "failed");
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

    #[test]
    fn failed_backend_detach_can_be_retried() {
        let backend = Arc::new(RetryDetachBackend {
            attempts: AtomicUsize::new(0),
        });
        let session = Session::new(SessionId::from_raw(9).expect("nonzero"), Some(42), "target");
        session.complete_attach(backend.clone()).expect("complete attach");

        assert!(matches!(
            session.detach(Duration::from_secs(1)),
            Err(SessionCommandFailure::Unavailable(_))
        ));
        assert_eq!(session.state(), SessionState::Failed);
        assert!(session.snapshot().last_error.is_some());

        session.detach(Duration::from_secs(1)).expect("retry detach");
        assert_eq!(session.state(), SessionState::Detached);
        assert_eq!(backend.attempts.load(Ordering::SeqCst), 2);
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
    fn health_failure_transitions_to_failed_then_detached_with_diagnostic() {
        let backend = Arc::new(OfflineBackend {
            detach_count: AtomicUsize::new(0),
        });
        let session = Session::new(SessionId::from_raw(11).expect("nonzero"), Some(42), "target");
        session.complete_attach(backend.clone()).expect("attach");

        let failure = session
            .health_check(Duration::from_millis(10))
            .expect_err("health failure");
        assert!(failure.is_transport_failure());
        session.mark_unhealthy(&failure).expect("mark unhealthy");
        assert_eq!(session.state(), SessionState::Failed);
        assert!(session
            .snapshot()
            .last_error
            .as_deref()
            .is_some_and(|error| error.contains("agent socket closed")));

        session.detach(Duration::from_millis(10)).expect("detach");
        let snapshot = session.snapshot();
        assert_eq!(snapshot.state, SessionState::Detached);
        assert!(snapshot
            .last_error
            .as_deref()
            .is_some_and(|error| error.contains("health check failed")));
        assert_eq!(backend.detach_count.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn health_and_cleanup_errors_are_appended_and_cleanup_clears_stale_hook_error() {
        let session = Session::new(SessionId::from_raw(26).expect("nonzero"), Some(42), "target");
        session
            .complete_attach(Arc::new(RecordingBackend::default()))
            .expect("attach");
        let (lease, release_count) = configurable_fake_lease(83, true, Some("cleanup release failed"));
        session.adopt_external_hook_lease_for_test(lease).expect("adopt");

        let health_failure = SessionCommandFailure::Unavailable("agent socket closed".into());
        session.mark_unhealthy(&health_failure).expect("mark unhealthy");
        let failed_snapshot = session.snapshot();
        let session_error = failed_snapshot.last_error.as_deref().expect("session error");
        assert!(session_error.contains("health check failed: session unavailable: agent socket closed"));
        assert!(session_error.contains("cleanup failed"));
        let hook_error = failed_snapshot.external_hooks[0]
            .last_error
            .as_deref()
            .expect("hook error");
        assert!(hook_error.contains("cleanup release failed"));
        assert_eq!(release_count.load(Ordering::SeqCst), 0);

        let report = session.cleanup_external_hooks();
        assert_eq!(report.failed, 0);
        assert_eq!(report.released, 1);
        let cleaned_snapshot = session.snapshot();
        assert_eq!(cleaned_snapshot.external_hooks[0].last_error, None);
        assert_eq!(release_count.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn cleanup_clears_stale_error_from_already_released_hook() {
        let session = Session::new(SessionId::from_raw(28).expect("nonzero"), Some(42), "target");
        session
            .complete_attach(Arc::new(RecordingBackend::default()))
            .expect("attach");
        let (lease, release_count) = configurable_fake_lease(84, false, None);
        session.adopt_external_hook_lease_for_test(lease).expect("adopt");
        session.release_external_hook(84).expect("release");

        {
            let mut lifecycle = super::lock(&session.lifecycle);
            lifecycle.external_hooks.get_mut(&84).expect("hook").last_error = Some("stale cleanup error".into());
        }

        let report = session.cleanup_external_hooks();
        assert_eq!(report.failed, 0);
        assert_eq!(report.already_released, 1);
        assert_eq!(session.snapshot().external_hooks[0].last_error, None);
        assert_eq!(release_count.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn detach_appends_shutdown_error_to_existing_health_reason() {
        let backend = Arc::new(RetryDetachBackend {
            attempts: AtomicUsize::new(0),
        });
        let session = Session::new(SessionId::from_raw(27).expect("nonzero"), Some(42), "target");
        session.complete_attach(backend).expect("attach");
        let health_failure = SessionCommandFailure::Unavailable("health transport lost".into());
        session.mark_unhealthy(&health_failure).expect("mark unhealthy");

        assert!(session.detach(Duration::from_secs(1)).is_err());
        let snapshot = session.snapshot();
        let error = snapshot.last_error.as_deref().expect("combined error");
        assert!(error.contains("health check failed: session unavailable: health transport lost"));
        assert!(error.contains("shutdown acknowledgement timed out"));
    }
}
