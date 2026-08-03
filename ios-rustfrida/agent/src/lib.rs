use common::command::{
    ExternalHookActionRequest, ExternalHookCommandOperation, ExternalHookErrorCode, ExternalHookExecuteRequest,
    ExternalHookOwnershipState, ExternalHookReceipt, ExternalHookReply, ExternalHookStatusRequest,
    ExternalHookTargetState,
};
use common::{
    read_frame, write_frame, AgentCommand, Error, Hello, Result, FRAME_KIND_CMD, FRAME_KIND_CMD_JSON,
    FRAME_KIND_COMPLETE, FRAME_KIND_EVAL_ERR, FRAME_KIND_EVAL_OK, FRAME_KIND_HELLO, FRAME_KIND_LOG,
};
use quickjs_runtime::{QuickJsRuntime, RuntimeStatus};
use serde_json::Value;

use native_api::{
    bind_external_hook_backend, current_hook_policy, current_process_uses_arm64e, decide_hook_backend_adapter,
    detect_hook_environment, execute_external_hook_backend, probe_loaded_backend_image, AdapterDecision,
    AdapterDecisionInput, AdapterOverride, AdapterPolicy, BackendPresence, ExternalHookExecutionError, HookBackendKind,
    HookExecutionResult, HookOperation,
};

use std::collections::BTreeMap;
use std::ffi::c_void;

#[cfg(unix)]
use std::os::unix::io::FromRawFd;
#[cfg(unix)]
use std::os::unix::net::UnixStream;

struct AgentState {
    runtime: QuickJsRuntime,
    external_hooks: ExternalHookRegistry,
}

impl AgentState {
    fn new() -> Self {
        Self {
            runtime: QuickJsRuntime::new(),
            external_hooks: ExternalHookRegistry::default(),
        }
    }

    fn run_js<F>(&mut self, op: F) -> AgentReply
    where
        F: FnOnce(&mut QuickJsRuntime) -> Result<String>,
    {
        let result = op(&mut self.runtime).map_err(|err| err.to_string());
        let logs = self.runtime.take_pending_logs();
        AgentReply::Eval { logs, result }
    }

    fn execute(&mut self, command: &str) -> Result<AgentReply> {
        if let Some(spec) = AgentCommand::from_legacy(command) {
            return self.execute_spec(spec);
        }

        Err(Error::InvalidArgument(format!("unknown agent command: {command}")))
    }

    fn execute_spec(&mut self, command: AgentCommand) -> Result<AgentReply> {
        match command {
            AgentCommand::Ping => Ok(AgentReply::Eval {
                logs: self.runtime.take_pending_logs(),
                result: Ok("pong".into()),
            }),
            AgentCommand::JsInit => Ok(self.run_js(|runtime| runtime.initialize())),
            AgentCommand::JsClean => Ok(self.run_js(|runtime| runtime.cleanup())),
            AgentCommand::LoadJs { script } | AgentCommand::JsEval { script } => {
                Ok(self.run_js(|runtime| runtime.eval(&script)))
            }
            AgentCommand::JsComplete { prefix } => Ok(AgentReply::Complete(self.runtime.complete(&prefix))),
            AgentCommand::RpcCall { method, args_json } => {
                Ok(self.run_js(|runtime| dispatch_agent_rpc(runtime, &method, &args_json)))
            }
            AgentCommand::RuntimeHandle { command } => {
                Ok(self.run_js(|runtime| eval_agent_runtime_command(runtime, &command)))
            }
            AgentCommand::RuntimeDispatch { spec } => {
                Ok(self.run_js(|runtime| eval_agent_runtime_spec(runtime, &spec)))
            }
            AgentCommand::RuntimeDispatchResult { spec } => {
                Ok(self.run_js(|runtime| eval_agent_runtime_spec_result(runtime, &spec)))
            }
            AgentCommand::ControllerDispatch { spec } => {
                Ok(self.run_js(|runtime| eval_controller_dispatch(runtime, &spec)))
            }
            AgentCommand::ControllerDispatchResult { spec } => {
                Ok(self.run_js(|runtime| eval_controller_dispatch_result(runtime, &spec)))
            }
            AgentCommand::ExternalHookExecute { request } => self.external_hook_execute(request),
            AgentCommand::ExternalHookStatus { request } => self.external_hook_status(request),
            AgentCommand::ExternalHookRelease { request } => self.external_hook_release(request),
            AgentCommand::ExternalHookUninstall { request } => self.external_hook_uninstall(request),
            AgentCommand::Exit => Ok(AgentReply::Log("bye".into())),
        }
    }

    fn external_hook_execute(&mut self, request: ExternalHookExecuteRequest) -> Result<AgentReply> {
        let reply = self.external_hooks.execute(request, &mut NativeExternalHookExecutor);
        reply_to_agent(reply)
    }

    fn external_hook_status(&self, request: ExternalHookStatusRequest) -> Result<AgentReply> {
        reply_to_agent(self.external_hooks.status(&request.owner_id))
    }

    fn external_hook_release(&mut self, request: ExternalHookActionRequest) -> Result<AgentReply> {
        reply_to_agent(self.external_hooks.release(&request.owner_id, request.token))
    }

    fn external_hook_uninstall(&mut self, request: ExternalHookActionRequest) -> Result<AgentReply> {
        reply_to_agent(self.external_hooks.uninstall(&request.owner_id, request.token))
    }
}

fn reply_to_agent(reply: ExternalHookReply) -> Result<AgentReply> {
    let payload = serde_json::to_string(&reply)
        .map_err(|error| Error::Protocol(format!("failed to encode external hook reply: {error}")))?;
    Ok(AgentReply::Eval {
        logs: Vec::new(),
        result: if reply.is_error() { Err(payload) } else { Ok(payload) },
    })
}

trait ExternalHookHandle {
    fn token(&self) -> u64;
    fn backend(&self) -> &'static str;
    fn original(&self) -> Option<u64>;
    fn native_result(&self) -> Option<i32>;
    fn native_uninstall_available(&self) -> bool;
    fn release(&mut self) -> std::result::Result<bool, String>;
    fn uninstall(&mut self) -> std::result::Result<(), HookLeaseActionError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum HookLeaseActionError {
    NativeUninstallUnavailable,
    AlreadyReleased,
    Adapter(String),
}

struct NativeExternalHookHandle {
    decision: AdapterDecision,
    result: HookExecutionResult,
}

impl ExternalHookHandle for NativeExternalHookHandle {
    fn token(&self) -> u64 {
        self.result.token
    }

    fn backend(&self) -> &'static str {
        self.result.backend.as_str()
    }

    fn original(&self) -> Option<u64> {
        self.result.original.map(|pointer| pointer.as_ptr() as usize as u64)
    }

    fn native_result(&self) -> Option<i32> {
        self.result.native_result
    }

    fn native_uninstall_available(&self) -> bool {
        self.result.native_uninstall_available()
    }

    fn release(&mut self) -> std::result::Result<bool, String> {
        self.decision
            .release_external_hook_handle(&mut self.result)
            .map_err(|error| error.to_string())
    }

    fn uninstall(&mut self) -> std::result::Result<(), HookLeaseActionError> {
        match self.decision.uninstall_external_hook_handle(&mut self.result) {
            Ok(()) => Ok(()),
            Err(ExternalHookExecutionError::Backend(native_api::HookBackendFfiError::NativeUninstallUnavailable {
                ..
            })) => Err(HookLeaseActionError::NativeUninstallUnavailable),
            Err(ExternalHookExecutionError::Backend(native_api::HookBackendFfiError::HandleReleased { .. })) => {
                Err(HookLeaseActionError::AlreadyReleased)
            }
            Err(error) => Err(HookLeaseActionError::Adapter(error.to_string())),
        }
    }
}

struct HookExecutionFailure {
    backend: String,
    message: String,
    target_state_uncertain: bool,
}

trait ExternalHookExecutor {
    fn execute(
        &mut self,
        request: &ExternalHookExecuteRequest,
    ) -> std::result::Result<Box<dyn ExternalHookHandle>, HookExecutionFailure>;
}

struct NativeExternalHookExecutor;

impl ExternalHookExecutor for NativeExternalHookExecutor {
    fn execute(
        &mut self,
        request: &ExternalHookExecuteRequest,
    ) -> std::result::Result<Box<dyn ExternalHookHandle>, HookExecutionFailure> {
        let operation = match request.operation {
            ExternalHookCommandOperation::Install => HookOperation::Install,
            ExternalHookCommandOperation::Replace => HookOperation::Replace,
        };
        let probe = probe_loaded_backend_image(&request.backend_image);
        let backend = HookBackendKind::from_id(probe.backend.as_str());
        if !probe.loaded {
            return Err(HookExecutionFailure {
                backend: backend.as_str().into(),
                message: format!("external hook backend image is not loaded: {}", request.backend_image),
                target_state_uncertain: false,
            });
        }

        let environment = detect_hook_environment().map_err(|error| HookExecutionFailure {
            backend: backend.as_str().into(),
            message: format!("failed to inspect hook environment: {error}"),
            target_state_uncertain: false,
        })?;
        let conflicting_backend_count = environment
            .backends
            .iter()
            .filter(|item| !item.loaded_images.is_empty() && HookBackendKind::from_id(&item.id) != backend)
            .count();
        let input = AdapterDecisionInput {
            operation,
            backend,
            presence: BackendPresence::Loaded,
            conflicting_backend_count,
            arm64e: current_process_uses_arm64e().ok(),
            policy: adapter_policy_for_current_process(),
            override_mode: AdapterOverride::None,
        };
        let decision = decide_hook_backend_adapter(input);
        if !decision.requested_operation_executable() {
            return Err(HookExecutionFailure {
                backend: backend.as_str().into(),
                message: format!(
                    "external hook decision blocked execution: reason={} action={}",
                    decision.reason_code.as_str(),
                    decision.recommended_action.as_str()
                ),
                target_state_uncertain: false,
            });
        }
        let (bound_decision, resolved) =
            bind_external_hook_backend(decision, &probe.image_name).map_err(|error| HookExecutionFailure {
                backend: backend.as_str().into(),
                message: error.to_string(),
                target_state_uncertain: error.target_state_uncertain(),
            })?;
        let target = request.target as usize as *mut c_void;
        let replacement = request.replacement as usize as *mut c_void;
        let result = unsafe { execute_external_hook_backend(&bound_decision, &resolved, target, replacement) }
            .map_err(|error| HookExecutionFailure {
                backend: backend.as_str().into(),
                message: error.to_string(),
                target_state_uncertain: error.target_state_uncertain(),
            })?;
        Ok(Box::new(NativeExternalHookHandle {
            decision: bound_decision,
            result,
        }))
    }
}

fn adapter_policy_for_current_process() -> AdapterPolicy {
    match current_hook_policy() {
        native_api::HookPolicy::Warn => AdapterPolicy::Conservative,
        native_api::HookPolicy::QueryOnlyExternalLoaded => AdapterPolicy::QueryOnly,
        native_api::HookPolicy::DenyExternalLoaded => AdapterPolicy::CleanupOnly,
    }
}

struct ExternalHookRecord {
    request: ExternalHookExecuteRequest,
    receipt: ExternalHookReceipt,
    handle: Option<Box<dyn ExternalHookHandle>>,
    cached_error: Option<(ExternalHookErrorCode, String)>,
}

#[derive(Default)]
struct ExternalHookRegistry {
    records: BTreeMap<String, ExternalHookRecord>,
    rejected: BTreeMap<String, (ExternalHookExecuteRequest, ExternalHookReply)>,
    tokens: BTreeMap<u64, String>,
}

impl ExternalHookRegistry {
    fn execute<E: ExternalHookExecutor>(
        &mut self,
        request: ExternalHookExecuteRequest,
        executor: &mut E,
    ) -> ExternalHookReply {
        if let Err(error) = request.validate() {
            return Self::error(
                ExternalHookErrorCode::ExecutionFailed,
                error.to_string(),
                Some(request.request_id),
                None,
                None,
                false,
            );
        }

        if let Some(record) = self.records.get(&request.request_id) {
            if record.request != request {
                return Self::error(
                    ExternalHookErrorCode::RequestIdConflict,
                    "request_id is already bound to a different external hook request".into(),
                    Some(request.request_id),
                    record.receipt.token,
                    Some(record.receipt.clone()),
                    true,
                );
            }
            return match &record.cached_error {
                Some((code, message)) => Self::error(
                    *code,
                    message.clone(),
                    Some(request.request_id),
                    record.receipt.token,
                    Some(record.receipt.clone()),
                    true,
                ),
                None => ExternalHookReply::Execute {
                    receipt: record.receipt.clone(),
                    replayed: true,
                },
            };
        }
        if let Some((previous, reply)) = self.rejected.get(&request.request_id) {
            if previous != &request {
                return Self::error(
                    ExternalHookErrorCode::RequestIdConflict,
                    "request_id is already bound to a different external hook request".into(),
                    Some(request.request_id),
                    None,
                    None,
                    true,
                );
            }
            return replay_error(reply);
        }

        match executor.execute(&request) {
            Ok(handle) => {
                let token = handle.token();
                if token == 0 || self.tokens.contains_key(&token) {
                    let mut handle = handle;
                    let _ = handle.release();
                    let request_id = request.request_id.clone();
                    let reply = Self::error(
                        ExternalHookErrorCode::DuplicateToken,
                        format!("external hook token {token} is already owned"),
                        Some(request_id.clone()),
                        Some(token),
                        None,
                        false,
                    );
                    self.rejected.insert(request_id, (request, reply.clone()));
                    return reply;
                }
                let receipt = receipt_for_handle(&request, handle.as_ref());
                self.tokens.insert(token, request.request_id.clone());
                self.records.insert(
                    request.request_id.clone(),
                    ExternalHookRecord {
                        request,
                        receipt: receipt.clone(),
                        handle: Some(handle),
                        cached_error: None,
                    },
                );
                ExternalHookReply::Execute {
                    receipt,
                    replayed: false,
                }
            }
            Err(failure) => {
                if failure.target_state_uncertain {
                    let receipt = ExternalHookReceipt {
                        request_id: request.request_id.clone(),
                        owner_id: request.owner_id.clone(),
                        token: None,
                        backend: failure.backend,
                        backend_image: request.backend_image.clone(),
                        operation: request.operation,
                        target: request.target,
                        replacement: request.replacement,
                        original: None,
                        native_result: None,
                        ownership: ExternalHookOwnershipState::Orphaned,
                        target_state: ExternalHookTargetState::Uncertain,
                        native_uninstall_available: false,
                        last_error: Some(failure.message.clone()),
                    };
                    let reply = Self::error(
                        ExternalHookErrorCode::TargetStateUncertain,
                        failure.message,
                        Some(request.request_id.clone()),
                        None,
                        Some(receipt.clone()),
                        false,
                    );
                    let request_id = request.request_id.clone();
                    self.records.insert(
                        request_id,
                        ExternalHookRecord {
                            request,
                            receipt,
                            handle: None,
                            cached_error: Some((ExternalHookErrorCode::TargetStateUncertain, reply_message(&reply))),
                        },
                    );
                    reply
                } else {
                    let reply = Self::error(
                        ExternalHookErrorCode::ExecutionFailed,
                        failure.message,
                        Some(request.request_id.clone()),
                        None,
                        None,
                        false,
                    );
                    let request_id = request.request_id.clone();
                    self.rejected.insert(request_id, (request, reply.clone()));
                    reply
                }
            }
        }
    }

    fn status(&self, owner_id: &str) -> ExternalHookReply {
        ExternalHookReply::Status {
            owner_id: owner_id.to_string(),
            hooks: self
                .records
                .values()
                .filter(|record| record.receipt.owner_id == owner_id)
                .map(|record| record.receipt.clone())
                .collect(),
        }
    }

    fn release(&mut self, owner_id: &str, token: u64) -> ExternalHookReply {
        let Some(request_id) = self.tokens.get(&token).cloned() else {
            return Self::error(
                ExternalHookErrorCode::NotFound,
                format!("external hook token {token} is not known"),
                None,
                Some(token),
                None,
                false,
            );
        };
        let record = self.records.get_mut(&request_id).expect("token index record");
        if record.receipt.owner_id != owner_id {
            return Self::error(
                ExternalHookErrorCode::OwnerMismatch,
                format!("external hook token {token} belongs to another owner"),
                Some(record.request.request_id.clone()),
                Some(token),
                Some(record.receipt.clone()),
                false,
            );
        }
        if record.receipt.ownership == ExternalHookOwnershipState::Released {
            return ExternalHookReply::Release {
                receipt: record.receipt.clone(),
                changed: false,
            };
        }
        if record.receipt.ownership == ExternalHookOwnershipState::Orphaned {
            return Self::error(
                ExternalHookErrorCode::TargetStateUncertain,
                "orphaned hook has no releasable handle; reconcile target state first".into(),
                Some(record.request.request_id.clone()),
                Some(token),
                Some(record.receipt.clone()),
                false,
            );
        }
        let Some(handle) = record.handle.as_mut() else {
            return Self::error(
                ExternalHookErrorCode::AdapterFailed,
                "owned hook record has no native handle".into(),
                Some(record.request.request_id.clone()),
                Some(token),
                Some(record.receipt.clone()),
                false,
            );
        };
        match handle.release() {
            Ok(changed) => {
                record.receipt.ownership = ExternalHookOwnershipState::Released;
                record.receipt.last_error = None;
                ExternalHookReply::Release {
                    receipt: record.receipt.clone(),
                    changed,
                }
            }
            Err(message) => {
                record.receipt.last_error = Some(message.clone());
                Self::error(
                    ExternalHookErrorCode::AdapterFailed,
                    message,
                    Some(record.request.request_id.clone()),
                    Some(token),
                    Some(record.receipt.clone()),
                    false,
                )
            }
        }
    }

    fn uninstall(&mut self, owner_id: &str, token: u64) -> ExternalHookReply {
        let Some(request_id) = self.tokens.get(&token).cloned() else {
            return Self::error(
                ExternalHookErrorCode::NotFound,
                format!("external hook token {token} is not known"),
                None,
                Some(token),
                None,
                false,
            );
        };
        let record = self.records.get_mut(&request_id).expect("token index record");
        if record.receipt.owner_id != owner_id {
            return Self::error(
                ExternalHookErrorCode::OwnerMismatch,
                format!("external hook token {token} belongs to another owner"),
                Some(record.request.request_id.clone()),
                Some(token),
                Some(record.receipt.clone()),
                false,
            );
        }
        if record.receipt.ownership == ExternalHookOwnershipState::Released {
            if record.receipt.target_state == ExternalHookTargetState::Restored {
                return ExternalHookReply::Uninstall {
                    receipt: record.receipt.clone(),
                    changed: false,
                };
            }
            return Self::error(
                ExternalHookErrorCode::AlreadyReleased,
                "external hook handle was released while the target remains installed".into(),
                Some(record.request.request_id.clone()),
                Some(token),
                Some(record.receipt.clone()),
                false,
            );
        }
        let Some(handle) = record.handle.as_mut() else {
            return Self::error(
                ExternalHookErrorCode::TargetStateUncertain,
                "orphaned hook has no native uninstall handle".into(),
                Some(record.request.request_id.clone()),
                Some(token),
                Some(record.receipt.clone()),
                false,
            );
        };
        match handle.uninstall() {
            Ok(()) => match handle.release() {
                Ok(_) => {
                    record.receipt.ownership = ExternalHookOwnershipState::Released;
                    record.receipt.target_state = ExternalHookTargetState::Restored;
                    record.receipt.last_error = None;
                    ExternalHookReply::Uninstall {
                        receipt: record.receipt.clone(),
                        changed: true,
                    }
                }
                Err(message) => {
                    record.receipt.target_state = ExternalHookTargetState::Restored;
                    record.receipt.last_error = Some(message.clone());
                    Self::error(
                        ExternalHookErrorCode::AdapterFailed,
                        message,
                        Some(record.request.request_id.clone()),
                        Some(token),
                        Some(record.receipt.clone()),
                        false,
                    )
                }
            },
            Err(HookLeaseActionError::NativeUninstallUnavailable) => {
                let message = "native uninstall is unavailable; target remains installed".to_string();
                record.receipt.last_error = Some(message.clone());
                Self::error(
                    ExternalHookErrorCode::NativeUninstallUnavailable,
                    message,
                    Some(record.request.request_id.clone()),
                    Some(token),
                    Some(record.receipt.clone()),
                    false,
                )
            }
            Err(HookLeaseActionError::AlreadyReleased) => {
                record.receipt.ownership = ExternalHookOwnershipState::Released;
                Self::error(
                    ExternalHookErrorCode::AlreadyReleased,
                    "external hook handle was already released".into(),
                    Some(record.request.request_id.clone()),
                    Some(token),
                    Some(record.receipt.clone()),
                    false,
                )
            }
            Err(HookLeaseActionError::Adapter(message)) => {
                record.receipt.last_error = Some(message.clone());
                Self::error(
                    ExternalHookErrorCode::AdapterFailed,
                    message,
                    Some(record.request.request_id.clone()),
                    Some(token),
                    Some(record.receipt.clone()),
                    false,
                )
            }
        }
    }

    fn error(
        code: ExternalHookErrorCode,
        message: String,
        request_id: Option<String>,
        token: Option<u64>,
        receipt: Option<ExternalHookReceipt>,
        replayed: bool,
    ) -> ExternalHookReply {
        ExternalHookReply::Error {
            code,
            message,
            request_id,
            token,
            receipt,
            replayed,
        }
    }
}

impl Drop for ExternalHookRegistry {
    fn drop(&mut self) {
        for record in self.records.values_mut() {
            if let Some(handle) = record.handle.as_mut() {
                let _ = handle.release();
            }
        }
    }
}

fn receipt_for_handle(request: &ExternalHookExecuteRequest, handle: &dyn ExternalHookHandle) -> ExternalHookReceipt {
    ExternalHookReceipt {
        request_id: request.request_id.clone(),
        owner_id: request.owner_id.clone(),
        token: Some(handle.token()),
        backend: handle.backend().into(),
        backend_image: request.backend_image.clone(),
        operation: request.operation,
        target: request.target,
        replacement: request.replacement,
        original: handle.original(),
        native_result: handle.native_result(),
        ownership: ExternalHookOwnershipState::Owned,
        target_state: ExternalHookTargetState::Installed,
        native_uninstall_available: handle.native_uninstall_available(),
        last_error: None,
    }
}

fn reply_message(reply: &ExternalHookReply) -> String {
    match reply {
        ExternalHookReply::Error { message, .. } => message.clone(),
        _ => String::new(),
    }
}

fn replay_error(reply: &ExternalHookReply) -> ExternalHookReply {
    match reply {
        ExternalHookReply::Error {
            code,
            message,
            request_id,
            token,
            receipt,
            ..
        } => ExternalHookReply::Error {
            code: *code,
            message: message.clone(),
            request_id: request_id.clone(),
            token: *token,
            receipt: receipt.clone(),
            replayed: true,
        },
        other => other.clone(),
    }
}

fn dispatch_agent_rpc(runtime: &mut QuickJsRuntime, method: &str, args_json: &str) -> Result<String> {
    if runtime.status() == &RuntimeStatus::Cold {
        let _ = runtime.initialize()?;
    }
    runtime.dispatch_rpc(method, args_json)
}

fn eval_agent_runtime_command(runtime: &mut QuickJsRuntime, command: &str) -> Result<String> {
    if runtime.status() == &RuntimeStatus::Cold {
        let _ = runtime.initialize()?;
    }

    let script = format!("__iosRustFridaAgentApi.handle({})", quote_js_string(command));
    runtime.eval(&script)
}

fn eval_agent_runtime_spec(runtime: &mut QuickJsRuntime, spec: &Value) -> Result<String> {
    if runtime.status() == &RuntimeStatus::Cold {
        let _ = runtime.initialize()?;
    }

    let script = format!("__iosRustFridaAgentApi.handleSpec({spec})");
    runtime.eval(&script)
}

fn eval_agent_runtime_spec_result(runtime: &mut QuickJsRuntime, spec: &Value) -> Result<String> {
    if runtime.status() == &RuntimeStatus::Cold {
        let _ = runtime.initialize()?;
    }

    let script = format!("JSON.stringify(__iosRustFridaAgentApi.handleSpecResult({spec}))");
    runtime.eval(&script)
}

fn eval_controller_dispatch(runtime: &mut QuickJsRuntime, spec: &Value) -> Result<String> {
    if runtime.status() == &RuntimeStatus::Cold {
        let _ = runtime.initialize()?;
    }

    let script = format!("__iosRustFridaControllerApi.dispatch({})", spec);
    runtime.eval(&script)
}

fn eval_controller_dispatch_result(runtime: &mut QuickJsRuntime, spec: &Value) -> Result<String> {
    if runtime.status() == &RuntimeStatus::Cold {
        let _ = runtime.initialize()?;
    }

    let script = format!("JSON.stringify(__iosRustFridaControllerApi.dispatchResult({}))", spec);
    runtime.eval(&script)
}

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

#[cfg(test)]
mod tests {
    use super::{AgentReply, AgentState};
    use common::command::{
        ExternalHookCommandOperation, ExternalHookErrorCode, ExternalHookExecuteRequest, ExternalHookOwnershipState,
        ExternalHookReceipt, ExternalHookReply, ExternalHookStatusRequest, ExternalHookTargetState,
    };
    use common::AgentCommand;

    #[test]
    fn legacy_commands_route_through_shared_parser() {
        assert!(matches!(
            AgentCommand::from_legacy("objc.classes"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("objc.protocols"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("objc.methodImp NSObject alloc meta"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("objc.classes NSObject"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("objc.protocols NS"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("objc.classProtocols NSObject"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("objc.classProtocols NSObject NS"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("objc.findClassProtocols NSObject NS"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("objc.classConforms NSObject NSCopying"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("objc.protocolExists NSCopying"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("objc.findProtocolExists NSCopying"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("objc.protocolImage NSCopying"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("objc.findProtocolImage NSCopying"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("objc.findClassConforms NSObject NSCopying"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("objc.protocolConforms NSCopying NSObject"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("objc.findProtocolConforms NSCopying NSObject"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("objc.protocolOwners NSObject"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("objc.findProtocolOwners NSObject NS"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("objc.classInfo NSObject meta"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("objc.protocolInfo NSObject"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("objc.protocolProtocols NSObject"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("objc.protocolProtocols NSObject NS"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("objc.findProtocolProtocols NSObject NS"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("objc.protocolMethods NSObject optional class"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("objc.protocolMethods NSObject optional class description"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("objc.findProtocolMethods NSObject optional class description"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("objc.protocolMethodInfo NSObject description optional class"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("objc.protocolProperties NSObject"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("objc.protocolProperties NSObject description"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("objc.findProtocolProperties NSObject description"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("objc.protocolPropertyInfo NSObject description"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("objc.superclass NSObject"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("objc.classChain NSObject"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("objc.classExists NSObject"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("objc.findClassExists NSObject"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("objc.selector init"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("objc.findSelector init"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("objc.findMethodImp NSObject init"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("objc.properties NSObject meta delegate"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("objc.ivars NSObject delegate"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("objc.selectorName 0x1234"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("objc.methodInfo NSObject init"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("objc.propertyInfo NSObject description"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("objc.ivarInfo NSObject _isa"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("objc.methodOwners init"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("objc.classImage NSObject"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("objc.methodImage NSObject init"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("objc.objectClassName 0x1234"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("native.base libsystem_malloc.dylib"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("native.findBase libsystem_malloc.dylib"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("native.imageInfo libsystem_malloc.dylib"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("native.export malloc"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("native.export libsystem_malloc.dylib -- malloc"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("native.exports libsystem_malloc.dylib"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("native.exportInfo libsystem_malloc.dylib -- malloc"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("native.dependencies libsystem_malloc.dylib"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("native.dependencyInfo libsystem_malloc.dylib -- libSystem.B.dylib"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("native.encryptionInfo libsystem_malloc.dylib"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("native.entryPoint libsystem_malloc.dylib"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("native.dyldInfo libsystem_malloc.dylib"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("native.linkedit libsystem_malloc.dylib"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("native.functionStarts libsystem_malloc.dylib"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("native.codeSignature libsystem_malloc.dylib"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("native.dataInCode libsystem_malloc.dylib"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("native.exportsTrie libsystem_malloc.dylib"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("native.chainedFixups libsystem_malloc.dylib"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("native.sourceVersion libsystem_malloc.dylib"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("native.buildVersion libsystem_malloc.dylib"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("native.dylinker libsystem_malloc.dylib"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("native.installName libsystem_malloc.dylib"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("native.uuid libsystem_malloc.dylib"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("native.rpaths libsystem_malloc.dylib"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("native.rpathInfo libsystem_malloc.dylib -- @loader_path"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("native.imports libsystem_malloc.dylib"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("native.importInfo libsystem_malloc.dylib -- malloc"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("native.symbols malloc"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("native.symbols libsystem_malloc.dylib -- malloc"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("native.symbolInfo malloc"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("native.segments libsystem_malloc.dylib"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("native.segmentInfo libsystem_malloc.dylib -- __TEXT"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("native.sections libsystem_malloc.dylib"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("native.sectionInfo libsystem_malloc.dylib -- __TEXT __text"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("native.loadCommands libsystem_malloc.dylib"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("native.loadcmds libsystem_malloc.dylib"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("native.loadCommandInfo libsystem_malloc.dylib -- LC_UUID"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("native.images"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("native.images libsystem"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("native.mainImage"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("native.findMainImage"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("native.image 0x1234"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("native.findImage 0x1234"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("native.symbol 0x1234"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("native.findSymbol 0x1234"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("pac.strip 0x1234"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("pac.stripData 0x1234"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("pac.isProcessArm64e"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("pac.isImageArm64e libsystem_malloc.dylib"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("pac.arm64eImages"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("pac.arm64eImages malloc"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("pac.image libsystem_malloc.dylib"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("pac.images"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("native.detectHookEnvironment"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("swift.methods Demo -- ViewController viewDidLoad"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("swift.protocolInfo Renderable"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("swift.conformanceInfo ViewController Renderable"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("swift.typeInfo ViewController"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("swift.methodInfo ViewController viewDidLoad"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("swift.symbolInfo ViewController"),
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
            AgentCommand::from_legacy("swift.metadataInfo ViewController"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("swift.typeLayoutInfo ViewController"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("swift.vtableInfo ViewController viewDidLoad"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("swift.vtable ViewController"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("swift.witnessTable Renderable"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("swift.witnessTableInfo ViewController Renderable"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("swift.typeLayout ViewController"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("swift.types ViewController"),
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
        assert!(matches!(AgentCommand::from_legacy("ping"), Some(AgentCommand::Ping)));
        assert!(matches!(
            AgentCommand::from_legacy("rpccall add [1,2]"),
            Some(AgentCommand::RpcCall { .. })
        ));
    }

    #[test]
    fn runtime_command_bootstraps_quickjs_on_demand() {
        let mut state = AgentState::new();
        match state.execute("pac.available").expect("execute pac.available") {
            AgentReply::Eval { result, .. } => assert!(matches!(result.as_deref(), Ok("true") | Ok("false"))),
            _ => panic!("unexpected agent reply"),
        }
    }

    #[test]
    fn quickjs_commands_preserve_structured_values_and_dispatch_rpc() {
        let mut state = AgentState::new();
        state.execute_spec(AgentCommand::JsInit).expect("initialize runtime");
        let expected = r#"{"object":{"flag":true},"array":[1,{"x":"y"}]}"#;

        match state
            .execute_spec(AgentCommand::LoadJs {
                script: "rpc.exports = { add(a, b) { return a + b; } }; ({ object: { flag: true }, array: [1, { x: 'y' }] })".into(),
            })
            .expect("load structured script")
        {
            AgentReply::Eval { result, .. } => assert_eq!(result.expect("LoadJs result"), expected),
            _ => panic!("unexpected agent reply"),
        }

        match state
            .execute_spec(AgentCommand::JsEval {
                script: "({ object: { flag: true }, array: [1, { x: 'y' }] })".into(),
            })
            .expect("evaluate structured expression")
        {
            AgentReply::Eval { result, .. } => assert_eq!(result.expect("JsEval result"), expected),
            _ => panic!("unexpected agent reply"),
        }

        match state.execute("rpccall add [19,23]").expect("dispatch RPC call") {
            AgentReply::Eval { result, .. } => assert_eq!(result.expect("RPC result"), "42"),
            _ => panic!("unexpected agent reply"),
        }
    }

    struct FakeHandle {
        token: u64,
        released: bool,
    }

    impl super::ExternalHookHandle for FakeHandle {
        fn token(&self) -> u64 {
            self.token
        }

        fn backend(&self) -> &'static str {
            "ellekit"
        }

        fn original(&self) -> Option<u64> {
            Some(0x3000)
        }

        fn native_result(&self) -> Option<i32> {
            None
        }

        fn native_uninstall_available(&self) -> bool {
            false
        }

        fn release(&mut self) -> std::result::Result<bool, String> {
            if self.released {
                return Ok(false);
            }
            self.released = true;
            Ok(true)
        }

        fn uninstall(&mut self) -> std::result::Result<(), super::HookLeaseActionError> {
            Err(super::HookLeaseActionError::NativeUninstallUnavailable)
        }
    }

    struct FakeExecutor {
        calls: usize,
        next: std::result::Result<Box<dyn super::ExternalHookHandle>, super::HookExecutionFailure>,
    }

    impl super::ExternalHookExecutor for FakeExecutor {
        fn execute(
            &mut self,
            _request: &ExternalHookExecuteRequest,
        ) -> std::result::Result<Box<dyn super::ExternalHookHandle>, super::HookExecutionFailure> {
            self.calls += 1;
            std::mem::replace(
                &mut self.next,
                Err(super::HookExecutionFailure {
                    backend: "ellekit".into(),
                    message: "fake executor exhausted".into(),
                    target_state_uncertain: false,
                }),
            )
        }
    }

    fn external_hook_request() -> ExternalHookExecuteRequest {
        ExternalHookExecuteRequest {
            request_id: "request-1".into(),
            owner_id: "session:1".into(),
            operation: ExternalHookCommandOperation::Replace,
            backend_image: "/var/jb/usr/lib/libellekit.dylib".into(),
            target: 0x1000,
            replacement: 0x2000,
        }
    }

    #[test]
    fn external_hook_registry_is_idempotent_and_owner_scoped() {
        let mut registry = super::ExternalHookRegistry::default();
        let mut executor = FakeExecutor {
            calls: 0,
            next: Ok(Box::new(FakeHandle {
                token: 77,
                released: false,
            })),
        };
        let request = external_hook_request();

        let first = registry.execute(request.clone(), &mut executor);
        assert!(matches!(first, ExternalHookReply::Execute { replayed: false, .. }));
        let replay = registry.execute(request, &mut executor);
        assert!(matches!(replay, ExternalHookReply::Execute { replayed: true, .. }));
        assert_eq!(executor.calls, 1);

        let denied = registry.release("session:other", 77);
        assert!(matches!(
            denied,
            ExternalHookReply::Error {
                code: ExternalHookErrorCode::OwnerMismatch,
                ..
            }
        ));
        let released = registry.release("session:1", 77);
        assert!(matches!(released, ExternalHookReply::Release { changed: true, .. }));
        let replayed_release = registry.release("session:1", 77);
        assert!(matches!(
            replayed_release,
            ExternalHookReply::Release { changed: false, .. }
        ));
        let uninstall = registry.uninstall("session:1", 77);
        assert!(matches!(
            uninstall,
            ExternalHookReply::Error {
                code: ExternalHookErrorCode::AlreadyReleased,
                ..
            }
        ));
    }

    #[test]
    fn uncertain_external_execution_is_retained_as_orphan_and_replayed() {
        let mut registry = super::ExternalHookRegistry::default();
        let mut executor = FakeExecutor {
            calls: 0,
            next: Err(super::HookExecutionFailure {
                backend: "ellekit".into(),
                message: "backend call may have modified target".into(),
                target_state_uncertain: true,
            }),
        };
        let request = external_hook_request();
        let first = registry.execute(request.clone(), &mut executor);
        assert!(matches!(
            first,
            ExternalHookReply::Error {
                code: ExternalHookErrorCode::TargetStateUncertain,
                receipt: Some(ExternalHookReceipt {
                    ownership: ExternalHookOwnershipState::Orphaned,
                    target_state: ExternalHookTargetState::Uncertain,
                    ..
                }),
                replayed: false,
                ..
            }
        ));
        let replay = registry.execute(request, &mut executor);
        assert!(matches!(
            replay,
            ExternalHookReply::Error {
                code: ExternalHookErrorCode::TargetStateUncertain,
                replayed: true,
                ..
            }
        ));
        assert_eq!(executor.calls, 1);
        let status = registry.status("session:1");
        assert!(matches!(
            status,
            ExternalHookReply::Status { hooks, .. }
                if hooks.len() == 1 && hooks[0].ownership == ExternalHookOwnershipState::Orphaned
        ));
    }

    #[test]
    fn external_hook_status_uses_the_existing_eval_json_frame() {
        let mut state = AgentState::new();
        let reply = state
            .execute_spec(AgentCommand::ExternalHookStatus {
                request: ExternalHookStatusRequest {
                    owner_id: "session:1".into(),
                },
            })
            .expect("status command");
        let AgentReply::Eval {
            result: Ok(payload), ..
        } = reply
        else {
            panic!("unexpected status reply");
        };
        let decoded: ExternalHookReply = serde_json::from_str(&payload).expect("status JSON");
        assert!(matches!(decoded, ExternalHookReply::Status { hooks, .. } if hooks.is_empty()));
    }
}

enum AgentReply {
    Log(String),
    Complete(Vec<String>),
    Eval {
        logs: Vec<String>,
        result: std::result::Result<String, String>,
    },
}

#[cfg(unix)]
fn send_reply(stream: &mut UnixStream, reply: AgentReply) -> Result<()> {
    match reply {
        AgentReply::Log(line) => write_frame(stream, FRAME_KIND_LOG, line.as_bytes()),
        AgentReply::Complete(items) => write_frame(stream, FRAME_KIND_COMPLETE, items.join("\t").as_bytes()),
        AgentReply::Eval { logs, result } => {
            for line in logs {
                write_frame(stream, FRAME_KIND_LOG, line.as_bytes())?;
            }

            match result {
                Ok(payload) => write_frame(stream, FRAME_KIND_EVAL_OK, payload.as_bytes()),
                Err(payload) => write_frame(stream, FRAME_KIND_EVAL_ERR, payload.as_bytes()),
            }
        }
    }
}

#[cfg(unix)]
fn run_agent_loop(fd: i32) -> Result<()> {
    let mut stream = unsafe { UnixStream::from_raw_fd(fd) };
    write_frame(&mut stream, FRAME_KIND_HELLO, &Hello::ios_default().encode())?;

    let mut state = AgentState::new();
    loop {
        let (kind, payload) = read_frame(&mut stream)?;
        match kind {
            FRAME_KIND_CMD => {
                let command = String::from_utf8(payload)
                    .map_err(|_| Error::Protocol("command payload is not valid utf-8".into()))?;
                let exit = command.trim() == "exit";
                match state.execute(command.trim()) {
                    Ok(reply) => send_reply(&mut stream, reply)?,
                    Err(err) => write_frame(&mut stream, FRAME_KIND_EVAL_ERR, err.to_string().as_bytes())?,
                }
                if exit {
                    break;
                }
            }
            FRAME_KIND_CMD_JSON => {
                let command = AgentCommand::decode(&payload)?;
                let exit = matches!(command, AgentCommand::Exit);
                match state.execute_spec(command) {
                    Ok(reply) => send_reply(&mut stream, reply)?,
                    Err(err) => write_frame(&mut stream, FRAME_KIND_EVAL_ERR, err.to_string().as_bytes())?,
                }
                if exit {
                    break;
                }
            }
            _ => {
                write_frame(&mut stream, FRAME_KIND_EVAL_ERR, b"unexpected frame kind")?;
            }
        }
    }
    Ok(())
}

#[cfg(not(unix))]
fn run_agent_loop(_fd: i32) -> Result<()> {
    Err(Error::Unsupported(
        "agent transport currently expects a Unix domain socket fd".into(),
    ))
}

#[no_mangle]
pub extern "C" fn ios_agent_entry(fd: i32) -> i32 {
    match run_agent_loop(fd) {
        Ok(()) => 0,
        Err(_) => -1,
    }
}
