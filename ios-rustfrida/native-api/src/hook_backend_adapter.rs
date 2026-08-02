//! Policy-only adapter selection for coexistence with external iOS hook backends.
//!
//! This module deliberately has no controller or platform dependencies. A caller
//! can translate an existing hook environment report into `AdapterDecisionInput`
//! and serialize the stable string values exposed by each enum.

use common::{Error, Result};
use std::ffi::c_void;
use std::fmt;

use crate::hook_backend_ffi::{
    resolve_loaded_hook_backend, ExternalHookBackendKind, ExternalHookOperation, HookBackendFfiError,
    HookExecutionResult, ResolvedHookBackend,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HookBackendKind {
    ElleKit,
    Substrate,
    Substitute,
    Libhooker,
    Unknown,
}

impl HookBackendKind {
    /// Parse a backend identifier emitted by a loader, image list, or path.
    ///
    /// Unknown identifiers intentionally return `None`: callers that need a
    /// conservative decision can use `from_id`, which maps them to `Unknown`.
    pub fn parse(value: &str) -> Option<Self> {
        let mut value = value.trim().to_ascii_lowercase();
        if let Some(component) = value.rsplit(['/', '\\']).next() {
            value = component.to_owned();
        }
        for suffix in [".dylib", ".framework", ".bundle"] {
            if let Some(stripped) = value.strip_suffix(suffix) {
                value = stripped.to_owned();
                break;
            }
        }
        let value = value.strip_prefix("lib").unwrap_or(&value);

        match value {
            "ellekit" => Some(Self::ElleKit),
            "substrate" | "cydia-substrate" | "cydiasubstrate" | "mobile-substrate" | "mobilesubstrate" => {
                Some(Self::Substrate)
            }
            "substitute" => Some(Self::Substitute),
            "hooker" => Some(Self::Libhooker),
            "unknown" => Some(Self::Unknown),
            _ => None,
        }
    }

    pub fn from_id(value: &str) -> Self {
        Self::parse(value).unwrap_or(Self::Unknown)
    }

    pub const fn is_known(self) -> bool {
        !matches!(self, Self::Unknown)
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ElleKit => "ellekit",
            Self::Substrate => "substrate",
            Self::Substitute => "substitute",
            Self::Libhooker => "libhooker",
            Self::Unknown => "unknown",
        }
    }

    pub const fn display_name(self) -> &'static str {
        match self {
            Self::ElleKit => "ElleKit",
            Self::Substrate => "Cydia Substrate",
            Self::Substitute => "Substitute",
            Self::Libhooker => "libhooker",
            Self::Unknown => "Unknown hook backend",
        }
    }

    pub const fn capabilities(self) -> HookBackendCapabilities {
        use CapabilityLevel::{Conditional, Supported, Unsupported};

        match self {
            Self::ElleKit => HookBackendCapabilities {
                query: Supported,
                install: Supported,
                uninstall: Unsupported,
                replace: Supported,
                arm64e: Supported,
            },
            Self::Substrate => HookBackendCapabilities {
                query: Supported,
                install: Supported,
                uninstall: Unsupported,
                replace: Supported,
                arm64e: Conditional,
            },
            Self::Substitute => HookBackendCapabilities {
                query: Supported,
                install: Supported,
                // substitute.h exposes a record pointer for a future undo
                // mechanism, but the referenced implementation is explicitly
                // unimplemented in the public ABI.
                uninstall: Unsupported,
                replace: Supported,
                arm64e: Conditional,
            },
            Self::Libhooker => HookBackendCapabilities {
                query: Supported,
                install: Supported,
                uninstall: Unsupported,
                replace: Supported,
                arm64e: Supported,
            },
            Self::Unknown => HookBackendCapabilities {
                query: Supported,
                install: Unsupported,
                uninstall: Unsupported,
                replace: Unsupported,
                arm64e: Conditional,
            },
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CapabilityLevel {
    Supported,
    Conditional,
    Unsupported,
}

impl CapabilityLevel {
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "supported" | "support" | "yes" => Some(Self::Supported),
            "conditional" | "condition" | "maybe" => Some(Self::Conditional),
            "unsupported" | "unavailable" | "no" => Some(Self::Unsupported),
            _ => None,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Supported => "supported",
            Self::Conditional => "conditional",
            Self::Unsupported => "unsupported",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HookBackendCapabilities {
    pub query: CapabilityLevel,
    pub install: CapabilityLevel,
    pub uninstall: CapabilityLevel,
    pub replace: CapabilityLevel,
    pub arm64e: CapabilityLevel,
}

impl HookBackendCapabilities {
    pub const fn for_operation(self, operation: HookOperation) -> CapabilityLevel {
        match operation {
            HookOperation::Query => self.query,
            HookOperation::Install | HookOperation::Attach => self.install,
            HookOperation::Uninstall | HookOperation::Cleanup => self.uninstall,
            HookOperation::Replace => self.replace,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HookOperation {
    Query,
    Install,
    Attach,
    Uninstall,
    Cleanup,
    Replace,
}

impl HookOperation {
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "query" | "status" | "inspect" | "info" => Some(Self::Query),
            "install" | "hook" | "hook-install" | "hook_install" => Some(Self::Install),
            "attach" | "interceptor.attach" | "interceptor-attach" | "interceptor_attach" => Some(Self::Attach),
            "uninstall" | "unhook" | "detach" | "interceptor.detach" => Some(Self::Uninstall),
            "cleanup" | "cleanup-only" | "cleanup_only" | "detach-all" | "detach_all" | "stop" => Some(Self::Cleanup),
            "replace" | "interceptor.replace" | "interceptor-replace" | "interceptor_replace" => Some(Self::Replace),
            _ => None,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Query => "query",
            Self::Install => "install",
            Self::Attach => "attach",
            Self::Uninstall => "uninstall",
            Self::Cleanup => "cleanup",
            Self::Replace => "replace",
        }
    }

    pub const fn is_write(self) -> bool {
        !matches!(self, Self::Query)
    }

    pub const fn is_cleanup(self) -> bool {
        matches!(self, Self::Uninstall | Self::Cleanup)
    }

    pub const fn is_install(self) -> bool {
        matches!(self, Self::Install | Self::Attach | Self::Replace)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BackendPresence {
    Absent,
    FilesystemOnly,
    Loaded,
}

impl BackendPresence {
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "absent" | "none" | "not-loaded" => Some(Self::Absent),
            "filesystem-only" | "filesystem_only" | "filesystem" | "on-disk" => Some(Self::FilesystemOnly),
            "loaded" | "runtime" | "in-process" => Some(Self::Loaded),
            _ => None,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Absent => "absent",
            Self::FilesystemOnly => "filesystem-only",
            Self::Loaded => "loaded",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AdapterPolicy {
    Conservative,
    PreferExternal,
    QueryOnly,
    DenyWrites,
    CleanupOnly,
}

impl AdapterPolicy {
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "conservative" | "warn" | "default" => Some(Self::Conservative),
            "prefer-external" | "prefer_external" | "external" => Some(Self::PreferExternal),
            "query-only" | "query_only" | "query-only-external-loaded" | "query_only_external_loaded" => {
                Some(Self::QueryOnly)
            }
            "deny-writes" | "deny_writes" => Some(Self::DenyWrites),
            "cleanup-only" | "cleanup_only" | "deny-external-loaded" | "deny_external_loaded" | "deny" => {
                Some(Self::CleanupOnly)
            }
            _ => None,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Conservative => "conservative",
            Self::PreferExternal => "prefer-external",
            Self::QueryOnly => "query-only",
            Self::DenyWrites => "deny-writes",
            Self::CleanupOnly => "cleanup-only",
        }
    }
}

impl Default for AdapterPolicy {
    fn default() -> Self {
        Self::Conservative
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AdapterKind {
    InternalInline,
    ElleKit,
    Substrate,
    Substitute,
    Libhooker,
    EnvironmentProbe,
    None,
}

impl AdapterKind {
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "internal-inline" | "internal_inline" | "internal" => Some(Self::InternalInline),
            "ellekit" => Some(Self::ElleKit),
            "substrate" => Some(Self::Substrate),
            "substitute" => Some(Self::Substitute),
            "libhooker" => Some(Self::Libhooker),
            "environment-probe" | "environment_probe" | "probe" => Some(Self::EnvironmentProbe),
            "none" => Some(Self::None),
            _ => None,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InternalInline => "internal-inline",
            Self::ElleKit => "ellekit",
            Self::Substrate => "substrate",
            Self::Substitute => "substitute",
            Self::Libhooker => "libhooker",
            Self::EnvironmentProbe => "environment-probe",
            Self::None => "none",
        }
    }

    pub const fn for_backend(backend: HookBackendKind) -> Self {
        match backend {
            HookBackendKind::ElleKit => Self::ElleKit,
            HookBackendKind::Substrate => Self::Substrate,
            HookBackendKind::Substitute => Self::Substitute,
            HookBackendKind::Libhooker => Self::Libhooker,
            HookBackendKind::Unknown => Self::None,
        }
    }

    pub const fn known_external(self) -> bool {
        matches!(
            self,
            Self::ElleKit | Self::Substrate | Self::Substitute | Self::Libhooker
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AdapterOverride {
    None,
    AllowConditional,
    Force(AdapterKind),
}

impl AdapterOverride {
    pub fn parse(value: &str) -> Option<Self> {
        let value = value.trim().to_ascii_lowercase();
        match value.as_str() {
            "" | "none" => Some(Self::None),
            "allow-conditional" | "allow_conditional" => Some(Self::AllowConditional),
            _ => {
                let adapter = value
                    .strip_prefix("force:")
                    .or_else(|| value.strip_prefix("force-adapter:"))
                    .and_then(AdapterKind::parse)?;
                adapter.known_external().then_some(Self::Force(adapter))
            }
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::AllowConditional => "allow-conditional",
            Self::Force(_) => "force-adapter",
        }
    }
}

impl Default for AdapterOverride {
    fn default() -> Self {
        Self::None
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdapterDecisionInput {
    pub operation: HookOperation,
    pub backend: HookBackendKind,
    pub presence: BackendPresence,
    /// Number of additional backends that conflict with `backend`.
    pub conflicting_backend_count: usize,
    pub arm64e: Option<bool>,
    pub policy: AdapterPolicy,
    pub override_mode: AdapterOverride,
}

impl AdapterDecisionInput {
    pub const fn conservative(operation: HookOperation, backend: HookBackendKind, presence: BackendPresence) -> Self {
        Self {
            operation,
            backend,
            presence,
            conflicting_backend_count: 0,
            arm64e: None,
            policy: AdapterPolicy::Conservative,
            override_mode: AdapterOverride::None,
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.presence != BackendPresence::Loaded && self.conflicting_backend_count != 0 {
            return Err(Error::InvalidArgument(
                "hook backend conflicts require a loaded primary backend".into(),
            ));
        }
        if self.presence == BackendPresence::Absent && self.backend.is_known() {
            return Err(Error::InvalidArgument(
                "an absent hook backend must use the unknown backend kind".into(),
            ));
        }
        if let AdapterOverride::Force(adapter) = self.override_mode {
            if !adapter.known_external() {
                return Err(Error::InvalidArgument(
                    "a forced hook adapter must name a known external backend".into(),
                ));
            }
            if self.presence != BackendPresence::Loaded {
                return Err(Error::InvalidArgument(
                    "a forced external hook adapter requires a loaded backend".into(),
                ));
            }
        }
        Ok(())
    }
}

/// Effective command surface after policy and topology are applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AdapterCommandMode {
    Allowed,
    QueryOnly,
    CleanupOnly,
    Blocked,
}

impl AdapterCommandMode {
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "allowed" | "allow" => Some(Self::Allowed),
            "query-only" | "query_only" => Some(Self::QueryOnly),
            "cleanup-only" | "cleanup_only" => Some(Self::CleanupOnly),
            "blocked" | "deny" | "denied" => Some(Self::Blocked),
            _ => None,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Allowed => "allowed",
            Self::QueryOnly => "query-only",
            Self::CleanupOnly => "cleanup-only",
            Self::Blocked => "blocked",
        }
    }

    pub const fn query_allowed(self) -> bool {
        matches!(self, Self::Allowed | Self::QueryOnly)
    }

    pub const fn install_allowed(self) -> bool {
        matches!(self, Self::Allowed)
    }

    pub const fn cleanup_allowed(self) -> bool {
        !matches!(self, Self::Blocked)
    }
}

/// The local execution surface represented by a policy decision.
///
/// External policy selection remains advisory until an image-scoped FFI probe
/// is bound with [`bind_external_hook_backend`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ExecutionBoundary {
    InternalInline,
    PreflightInternal,
    ExternalAdvisory,
    ExternalFfi,
    EnvironmentProbe,
    InternalCleanup,
    None,
}

impl ExecutionBoundary {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InternalInline => "internal-inline",
            Self::PreflightInternal => "preflight-internal",
            Self::ExternalAdvisory => "external-advisory",
            Self::ExternalFfi => "external-ffi",
            Self::EnvironmentProbe => "environment-probe",
            Self::InternalCleanup => "internal-cleanup",
            Self::None => "none",
        }
    }

    pub const fn executable_now(self) -> bool {
        matches!(
            self,
            Self::InternalInline | Self::ExternalFfi | Self::EnvironmentProbe | Self::InternalCleanup
        )
    }

    pub const fn requires_preflight(self) -> bool {
        matches!(self, Self::PreflightInternal)
    }
}

#[derive(Debug)]
pub enum ExternalHookExecutionError {
    PolicyDenied,
    InvalidDecision(&'static str),
    OperationUnsupported(HookOperation),
    AdapterMismatch {
        expected: HookBackendKind,
        probed: ExternalHookBackendKind,
    },
    HandleMismatch {
        token: u64,
        expected: HookBackendKind,
        actual: ExternalHookBackendKind,
    },
    ProbeNotExecutable(ExternalHookOperation),
    Backend(HookBackendFfiError),
}

impl fmt::Display for ExternalHookExecutionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PolicyDenied => formatter.write_str("external hook execution was denied by adapter policy"),
            Self::InvalidDecision(reason) => write!(formatter, "external hook decision is invalid: {reason}"),
            Self::OperationUnsupported(operation) => {
                write!(
                    formatter,
                    "external hook operation is not executable: {}",
                    operation.as_str()
                )
            }
            Self::AdapterMismatch { expected, probed } => write!(
                formatter,
                "external hook backend mismatch: decision selected {}, probe resolved {}",
                expected.as_str(),
                probed.as_str()
            ),
            Self::HandleMismatch {
                token,
                expected,
                actual,
            } => write!(
                formatter,
                "external hook token {token} belongs to {}, but the decision selected {}",
                actual.as_str(),
                expected.as_str()
            ),
            Self::ProbeNotExecutable(operation) => write!(
                formatter,
                "external hook probe did not resolve a public ABI for {operation:?}"
            ),
            Self::Backend(error) => write!(formatter, "external hook backend execution failed: {error}"),
        }
    }
}

impl std::error::Error for ExternalHookExecutionError {}

impl ExternalHookExecutionError {
    /// Whether a backend call may already have modified the target despite
    /// returning an error. All policy and identity failures happen preflight.
    pub const fn target_state_uncertain(&self) -> bool {
        match self {
            Self::Backend(error) => error.target_state_uncertain(),
            Self::PolicyDenied
            | Self::InvalidDecision(_)
            | Self::OperationUnsupported(_)
            | Self::AdapterMismatch { .. }
            | Self::HandleMismatch { .. }
            | Self::ProbeNotExecutable(_) => false,
        }
    }
}

impl From<HookBackendFfiError> for ExternalHookExecutionError {
    fn from(error: HookBackendFfiError) -> Self {
        Self::Backend(error)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DecisionOutcome {
    Allow,
    Deny,
    Degrade,
    QueryOnly,
}

impl DecisionOutcome {
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "allow" | "allowed" => Some(Self::Allow),
            "deny" | "denied" | "blocked" => Some(Self::Deny),
            "degrade" | "degraded" => Some(Self::Degrade),
            "query-only" | "query_only" => Some(Self::QueryOnly),
            _ => None,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
            Self::Degrade => "degrade",
            Self::QueryOnly => "query-only",
        }
    }

    pub const fn requested_operation_allowed(self) -> bool {
        matches!(self, Self::Allow | Self::Degrade)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DecisionReasonCode {
    InvalidInput,
    QueryAllowed,
    CleanupAllowed,
    NoExternalBackend,
    FilesystemOnly,
    MultipleBackends,
    UnknownBackend,
    PolicyQueryOnly,
    PolicyCleanupOnly,
    PolicyDenied,
    CapabilityConditional,
    CapabilityUnsupported,
    Arm64eUnknown,
    Arm64eConditional,
    Arm64eUnsupported,
    ExplicitOverride,
    KnownBackendSupported,
}

impl DecisionReasonCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidInput => "adapter.input.invalid",
            Self::QueryAllowed => "adapter.query.allowed",
            Self::CleanupAllowed => "adapter.cleanup.allowed",
            Self::NoExternalBackend => "adapter.backend.absent",
            Self::FilesystemOnly => "adapter.backend.filesystem_only",
            Self::MultipleBackends => "adapter.backend.multiple_conflict",
            Self::UnknownBackend => "adapter.backend.unknown",
            Self::PolicyQueryOnly => "adapter.policy.query_only",
            Self::PolicyCleanupOnly => "adapter.policy.cleanup_only",
            Self::PolicyDenied => "adapter.policy.denied",
            Self::CapabilityConditional => "adapter.capability.conditional",
            Self::CapabilityUnsupported => "adapter.capability.unsupported",
            Self::Arm64eUnknown => "adapter.arm64e.unknown",
            Self::Arm64eConditional => "adapter.arm64e.conditional",
            Self::Arm64eUnsupported => "adapter.arm64e.unsupported",
            Self::ExplicitOverride => "adapter.override.explicit",
            Self::KnownBackendSupported => "adapter.backend.supported",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RecommendedAction {
    ValidateInput,
    Proceed,
    UseSelectedAdapter,
    QueryEnvironment,
    PreflightThenUseInternal,
    RemoveBackendConflict,
    SelectKnownBackend,
    RequestExplicitOverride,
    ValidateArm64eThenProceed,
    DoNotProceed,
    UseForcedAdapter,
    CleanupOwnedHooks,
}

impl RecommendedAction {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ValidateInput => "validate-input",
            Self::Proceed => "proceed",
            Self::UseSelectedAdapter => "use-selected-adapter",
            Self::QueryEnvironment => "query-environment",
            Self::PreflightThenUseInternal => "preflight-then-use-internal",
            Self::RemoveBackendConflict => "remove-backend-conflict",
            Self::SelectKnownBackend => "select-known-backend",
            Self::RequestExplicitOverride => "request-explicit-override",
            Self::ValidateArm64eThenProceed => "validate-arm64e-then-proceed",
            Self::DoNotProceed => "do-not-proceed",
            Self::UseForcedAdapter => "use-forced-adapter",
            Self::CleanupOwnedHooks => "cleanup-owned-hooks",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdapterDecision {
    pub operation: HookOperation,
    pub backend: HookBackendKind,
    pub presence: BackendPresence,
    pub conflicting_backend_count: usize,
    pub arm64e: Option<bool>,
    pub policy: AdapterPolicy,
    pub override_mode: AdapterOverride,
    pub capability: CapabilityLevel,
    pub outcome: DecisionOutcome,
    pub reason_code: DecisionReasonCode,
    pub recommended_action: RecommendedAction,
    pub adapter: AdapterKind,
    pub command_mode: AdapterCommandMode,
    pub execution_boundary: ExecutionBoundary,
    pub policy_allowed: bool,
    pub executable: bool,
}

impl AdapterDecision {
    pub const fn requested_operation_allowed(self) -> bool {
        self.policy_allowed
    }

    pub const fn requested_operation_executable(self) -> bool {
        self.executable
    }

    pub const fn requires_preflight(self) -> bool {
        self.execution_boundary.requires_preflight()
    }

    pub const fn query_commands_allowed(self) -> bool {
        self.command_mode.query_allowed()
    }

    pub const fn hook_install_commands_allowed(self) -> bool {
        self.command_mode.install_allowed()
    }

    pub const fn cleanup_commands_allowed(self) -> bool {
        !matches!(self.policy, AdapterPolicy::DenyWrites) && self.command_mode.cleanup_allowed()
    }

    /// Release a successful external install/replace handle after validating
    /// that it belongs to this bound decision. This only releases adapter-owned
    /// resources and never claims that native code was restored.
    pub fn release_external_hook_handle(
        &self,
        handle: &mut HookExecutionResult,
    ) -> std::result::Result<bool, ExternalHookExecutionError> {
        validate_external_hook_handle(self, handle)?;
        Ok(handle.release())
    }

    /// Request native uninstall for a successful external hook handle.
    ///
    /// Current verified third-party ABIs expose no native uninstall entry
    /// point. Failure leaves ownership unchanged; callers may use the separate
    /// idempotent release method after accepting that the target remains hooked.
    pub fn uninstall_external_hook_handle(
        &self,
        handle: &mut HookExecutionResult,
    ) -> std::result::Result<(), ExternalHookExecutionError> {
        validate_external_hook_handle(self, handle)?;
        handle.uninstall().map_err(Into::into)
    }
}

fn external_backend_kind(backend: HookBackendKind) -> ExternalHookBackendKind {
    match backend {
        HookBackendKind::ElleKit => ExternalHookBackendKind::ElleKit,
        HookBackendKind::Substrate => ExternalHookBackendKind::Substrate,
        HookBackendKind::Substitute => ExternalHookBackendKind::Substitute,
        HookBackendKind::Libhooker => ExternalHookBackendKind::Libhooker,
        HookBackendKind::Unknown => ExternalHookBackendKind::Unknown,
    }
}

fn external_backend_kind_for_adapter(adapter: AdapterKind) -> Option<ExternalHookBackendKind> {
    match adapter {
        AdapterKind::ElleKit => Some(ExternalHookBackendKind::ElleKit),
        AdapterKind::Substrate => Some(ExternalHookBackendKind::Substrate),
        AdapterKind::Substitute => Some(ExternalHookBackendKind::Substitute),
        AdapterKind::Libhooker => Some(ExternalHookBackendKind::Libhooker),
        AdapterKind::InternalInline | AdapterKind::EnvironmentProbe | AdapterKind::None => None,
    }
}

fn hook_backend_kind_for_adapter(adapter: AdapterKind) -> Option<HookBackendKind> {
    match adapter {
        AdapterKind::ElleKit => Some(HookBackendKind::ElleKit),
        AdapterKind::Substrate => Some(HookBackendKind::Substrate),
        AdapterKind::Substitute => Some(HookBackendKind::Substitute),
        AdapterKind::Libhooker => Some(HookBackendKind::Libhooker),
        AdapterKind::InternalInline | AdapterKind::EnvironmentProbe | AdapterKind::None => None,
    }
}

fn selected_external_backend(
    decision: &AdapterDecision,
) -> std::result::Result<ExternalHookBackendKind, ExternalHookExecutionError> {
    let selected = external_backend_kind_for_adapter(decision.adapter).ok_or(
        ExternalHookExecutionError::InvalidDecision("adapter is not an external backend"),
    )?;

    match decision.override_mode {
        AdapterOverride::Force(adapter) if adapter == decision.adapter => {}
        AdapterOverride::Force(_) => {
            return Err(ExternalHookExecutionError::InvalidDecision(
                "forced adapter does not match the selected adapter",
            ));
        }
        AdapterOverride::None | AdapterOverride::AllowConditional => {
            if external_backend_kind(decision.backend) != selected {
                return Err(ExternalHookExecutionError::InvalidDecision(
                    "selected adapter does not match the probed backend",
                ));
            }
        }
    }

    Ok(selected)
}

fn validate_external_hook_handle(
    decision: &AdapterDecision,
    handle: &HookExecutionResult,
) -> std::result::Result<(), ExternalHookExecutionError> {
    let expected = validate_external_decision(decision, false)?;
    if handle.backend != expected {
        return Err(ExternalHookExecutionError::HandleMismatch {
            token: handle.token,
            expected: hook_backend_kind_for_adapter(decision.adapter).unwrap_or(decision.backend),
            actual: handle.backend,
        });
    }
    Ok(())
}

fn validate_external_decision(
    decision: &AdapterDecision,
    require_advisory_boundary: bool,
) -> std::result::Result<ExternalHookBackendKind, ExternalHookExecutionError> {
    if !decision.policy_allowed {
        return Err(ExternalHookExecutionError::PolicyDenied);
    }
    if require_advisory_boundary {
        if decision.execution_boundary != ExecutionBoundary::ExternalAdvisory || decision.executable {
            return Err(ExternalHookExecutionError::InvalidDecision(
                "binding requires a non-executable external advisory decision",
            ));
        }
    } else if decision.execution_boundary != ExecutionBoundary::ExternalFfi || !decision.executable {
        return Err(ExternalHookExecutionError::InvalidDecision(
            "execution requires an executable external FFI decision",
        ));
    }
    if decision.presence != BackendPresence::Loaded {
        return Err(ExternalHookExecutionError::InvalidDecision(
            "external FFI requires a loaded backend image",
        ));
    }
    if decision.conflicting_backend_count != 0 && !matches!(decision.override_mode, AdapterOverride::Force(_)) {
        return Err(ExternalHookExecutionError::InvalidDecision(
            "external FFI requires an explicit adapter selection when backends conflict",
        ));
    }
    if decision.command_mode != AdapterCommandMode::Allowed {
        return Err(ExternalHookExecutionError::InvalidDecision(
            "external FFI requires an allowed command mode",
        ));
    }
    selected_external_backend(decision)
}

fn external_operation(operation: HookOperation) -> Option<ExternalHookOperation> {
    match operation {
        HookOperation::Install | HookOperation::Attach => Some(ExternalHookOperation::Install),
        HookOperation::Replace => Some(ExternalHookOperation::Replace),
        HookOperation::Uninstall => Some(ExternalHookOperation::Uninstall),
        HookOperation::Query | HookOperation::Cleanup => None,
    }
}

/// Resolve an already-loaded backend and upgrade an advisory policy decision
/// to an executable FFI boundary. No image is loaded as a side effect.
pub fn bind_external_hook_backend(
    mut decision: AdapterDecision,
    image_name: &str,
) -> std::result::Result<(AdapterDecision, ResolvedHookBackend), ExternalHookExecutionError> {
    let expected = validate_external_decision(&decision, true)?;
    let operation = external_operation(decision.operation)
        .ok_or(ExternalHookExecutionError::OperationUnsupported(decision.operation))?;
    let backend = resolve_loaded_hook_backend(image_name)?;
    if backend.backend() != expected {
        return Err(ExternalHookExecutionError::AdapterMismatch {
            expected: hook_backend_kind_for_adapter(decision.adapter).unwrap_or(decision.backend),
            probed: backend.backend(),
        });
    }
    if !backend.supports(operation) {
        return Err(ExternalHookExecutionError::ProbeNotExecutable(operation));
    }
    decision.execution_boundary = ExecutionBoundary::ExternalFfi;
    decision.executable = true;
    Ok((decision, backend))
}

/// Execute a previously bound external backend decision.
///
/// # Safety
///
/// The target and replacement must be valid function pointers with a matching
/// ABI, and the caller must obey the selected backend's threading contract.
pub unsafe fn execute_external_hook_backend(
    decision: &AdapterDecision,
    backend: &ResolvedHookBackend,
    target: *mut c_void,
    replacement: *mut c_void,
) -> std::result::Result<HookExecutionResult, ExternalHookExecutionError> {
    let expected = validate_external_decision(decision, false)?;
    let operation = external_operation(decision.operation)
        .ok_or(ExternalHookExecutionError::OperationUnsupported(decision.operation))?;
    if backend.backend() != expected {
        return Err(ExternalHookExecutionError::AdapterMismatch {
            expected: hook_backend_kind_for_adapter(decision.adapter).unwrap_or(decision.backend),
            probed: backend.backend(),
        });
    }
    match operation {
        ExternalHookOperation::Install => unsafe { backend.install(target, replacement) }.map_err(Into::into),
        ExternalHookOperation::Replace => unsafe { backend.replace(target, replacement) }.map_err(Into::into),
        ExternalHookOperation::Uninstall => Err(ExternalHookExecutionError::OperationUnsupported(decision.operation)),
    }
}

pub fn decide_hook_backend_adapter(input: AdapterDecisionInput) -> AdapterDecision {
    if input.validate().is_err() {
        return decision(
            input,
            DecisionOutcome::Deny,
            DecisionReasonCode::InvalidInput,
            RecommendedAction::ValidateInput,
            AdapterKind::None,
            AdapterCommandMode::Blocked,
            ExecutionBoundary::None,
            CapabilityLevel::Unsupported,
        );
    }

    if input.policy == AdapterPolicy::CleanupOnly {
        if input.operation == HookOperation::Cleanup {
            return cleanup_decision(input, AdapterCommandMode::CleanupOnly);
        }
        return decision(
            input,
            DecisionOutcome::Deny,
            DecisionReasonCode::PolicyCleanupOnly,
            RecommendedAction::CleanupOwnedHooks,
            AdapterKind::None,
            AdapterCommandMode::CleanupOnly,
            ExecutionBoundary::None,
            requested_capability(input),
        );
    }

    if input.operation == HookOperation::Query {
        return query_decision(input);
    }

    if input.policy == AdapterPolicy::DenyWrites {
        return decision(
            input,
            DecisionOutcome::Deny,
            DecisionReasonCode::PolicyDenied,
            RecommendedAction::DoNotProceed,
            AdapterKind::None,
            AdapterCommandMode::QueryOnly,
            ExecutionBoundary::None,
            requested_capability(input),
        );
    }

    if input.policy == AdapterPolicy::QueryOnly {
        if input.operation == HookOperation::Cleanup {
            return cleanup_decision(input, AdapterCommandMode::QueryOnly);
        }
        return query_only(
            input,
            DecisionReasonCode::PolicyQueryOnly,
            RecommendedAction::QueryEnvironment,
        );
    }

    let forced_adapter = match input.override_mode {
        AdapterOverride::Force(adapter) if adapter.known_external() => Some(adapter),
        _ => None,
    };

    if input.conflicting_backend_count > 0 && forced_adapter.is_none() {
        if input.operation == HookOperation::Cleanup {
            return cleanup_decision(input, AdapterCommandMode::QueryOnly);
        }
        return query_only(
            input,
            DecisionReasonCode::MultipleBackends,
            RecommendedAction::RemoveBackendConflict,
        );
    }

    if input.presence == BackendPresence::Absent {
        if input.operation.is_cleanup() {
            return cleanup_decision(input, AdapterCommandMode::Allowed);
        }
        return decision(
            input,
            DecisionOutcome::Allow,
            DecisionReasonCode::NoExternalBackend,
            RecommendedAction::Proceed,
            AdapterKind::InternalInline,
            AdapterCommandMode::Allowed,
            ExecutionBoundary::InternalInline,
            CapabilityLevel::Supported,
        );
    }

    if input.presence == BackendPresence::FilesystemOnly {
        if input.operation == HookOperation::Cleanup {
            return cleanup_decision(input, AdapterCommandMode::Allowed);
        }
        if input.backend == HookBackendKind::Unknown {
            return query_only(
                input,
                DecisionReasonCode::UnknownBackend,
                RecommendedAction::SelectKnownBackend,
            );
        }

        if input.operation == HookOperation::Uninstall {
            return query_only(
                input,
                DecisionReasonCode::FilesystemOnly,
                RecommendedAction::QueryEnvironment,
            );
        }

        return decision(
            input,
            DecisionOutcome::Degrade,
            DecisionReasonCode::FilesystemOnly,
            RecommendedAction::PreflightThenUseInternal,
            AdapterKind::InternalInline,
            AdapterCommandMode::Allowed,
            ExecutionBoundary::PreflightInternal,
            CapabilityLevel::Supported,
        );
    }

    if input.operation == HookOperation::Cleanup {
        return cleanup_decision(input, AdapterCommandMode::Allowed);
    }

    let adapter = forced_adapter.unwrap_or_else(|| AdapterKind::for_backend(input.backend));
    if adapter == AdapterKind::None {
        return query_only(
            input,
            DecisionReasonCode::UnknownBackend,
            RecommendedAction::SelectKnownBackend,
        );
    }

    let backend = forced_adapter.and_then(backend_for_adapter).unwrap_or(input.backend);
    let capabilities = backend.capabilities();
    match capabilities.for_operation(input.operation) {
        CapabilityLevel::Unsupported => {
            return decision(
                input,
                DecisionOutcome::Deny,
                DecisionReasonCode::CapabilityUnsupported,
                RecommendedAction::DoNotProceed,
                adapter,
                AdapterCommandMode::Allowed,
                ExecutionBoundary::None,
                CapabilityLevel::Unsupported,
            );
        }
        CapabilityLevel::Conditional if !conditional_use_allowed(input) => {
            return query_only(
                input,
                DecisionReasonCode::CapabilityConditional,
                RecommendedAction::RequestExplicitOverride,
            );
        }
        CapabilityLevel::Supported | CapabilityLevel::Conditional => {}
    }

    if input.arm64e.is_none() && capabilities.arm64e != CapabilityLevel::Supported {
        if !conditional_use_allowed(input) {
            return query_only(
                input,
                DecisionReasonCode::Arm64eUnknown,
                RecommendedAction::RequestExplicitOverride,
            );
        }

        return decision(
            input,
            DecisionOutcome::Degrade,
            DecisionReasonCode::Arm64eUnknown,
            RecommendedAction::ValidateArm64eThenProceed,
            adapter,
            AdapterCommandMode::Allowed,
            ExecutionBoundary::ExternalAdvisory,
            capabilities.for_operation(input.operation),
        );
    }

    if input.arm64e == Some(true) {
        match capabilities.arm64e {
            CapabilityLevel::Unsupported => {
                return decision(
                    input,
                    DecisionOutcome::Deny,
                    DecisionReasonCode::Arm64eUnsupported,
                    RecommendedAction::DoNotProceed,
                    adapter,
                    AdapterCommandMode::Allowed,
                    ExecutionBoundary::None,
                    capabilities.for_operation(input.operation),
                );
            }
            CapabilityLevel::Conditional if !conditional_use_allowed(input) => {
                return query_only(
                    input,
                    DecisionReasonCode::Arm64eConditional,
                    RecommendedAction::RequestExplicitOverride,
                );
            }
            CapabilityLevel::Conditional => {
                return decision(
                    input,
                    DecisionOutcome::Degrade,
                    if forced_adapter.is_some() {
                        DecisionReasonCode::ExplicitOverride
                    } else {
                        DecisionReasonCode::Arm64eConditional
                    },
                    RecommendedAction::ValidateArm64eThenProceed,
                    adapter,
                    AdapterCommandMode::Allowed,
                    ExecutionBoundary::ExternalAdvisory,
                    capabilities.for_operation(input.operation),
                );
            }
            CapabilityLevel::Supported => {}
        }
    }

    if forced_adapter.is_some() {
        return decision(
            input,
            DecisionOutcome::Allow,
            DecisionReasonCode::ExplicitOverride,
            RecommendedAction::UseForcedAdapter,
            adapter,
            AdapterCommandMode::Allowed,
            ExecutionBoundary::ExternalAdvisory,
            capabilities.for_operation(input.operation),
        );
    }

    if capabilities.for_operation(input.operation) == CapabilityLevel::Conditional {
        return decision(
            input,
            DecisionOutcome::Degrade,
            DecisionReasonCode::CapabilityConditional,
            RecommendedAction::UseSelectedAdapter,
            adapter,
            AdapterCommandMode::Allowed,
            ExecutionBoundary::ExternalAdvisory,
            CapabilityLevel::Conditional,
        );
    }

    decision(
        input,
        DecisionOutcome::Allow,
        DecisionReasonCode::KnownBackendSupported,
        RecommendedAction::UseSelectedAdapter,
        adapter,
        AdapterCommandMode::Allowed,
        ExecutionBoundary::ExternalAdvisory,
        CapabilityLevel::Supported,
    )
}

fn query_decision(input: AdapterDecisionInput) -> AdapterDecision {
    let adapter = match input.presence {
        BackendPresence::Loaded if input.conflicting_backend_count == 0 => {
            let adapter = AdapterKind::for_backend(input.backend);
            if adapter == AdapterKind::None {
                AdapterKind::EnvironmentProbe
            } else {
                adapter
            }
        }
        _ => AdapterKind::EnvironmentProbe,
    };

    decision(
        input,
        DecisionOutcome::Allow,
        DecisionReasonCode::QueryAllowed,
        RecommendedAction::QueryEnvironment,
        adapter,
        query_command_mode(input),
        ExecutionBoundary::EnvironmentProbe,
        CapabilityLevel::Supported,
    )
}

fn cleanup_decision(input: AdapterDecisionInput, command_mode: AdapterCommandMode) -> AdapterDecision {
    decision(
        input,
        DecisionOutcome::Allow,
        DecisionReasonCode::CleanupAllowed,
        RecommendedAction::CleanupOwnedHooks,
        AdapterKind::InternalInline,
        command_mode,
        ExecutionBoundary::InternalCleanup,
        CapabilityLevel::Supported,
    )
}

fn query_command_mode(input: AdapterDecisionInput) -> AdapterCommandMode {
    if input.policy == AdapterPolicy::QueryOnly || input.policy == AdapterPolicy::DenyWrites {
        AdapterCommandMode::QueryOnly
    } else if input.conflicting_backend_count > 0
        || (input.presence == BackendPresence::Loaded && input.backend == HookBackendKind::Unknown)
    {
        AdapterCommandMode::QueryOnly
    } else {
        AdapterCommandMode::Allowed
    }
}

fn conditional_use_allowed(input: AdapterDecisionInput) -> bool {
    input.policy == AdapterPolicy::PreferExternal
        || matches!(
            input.override_mode,
            AdapterOverride::AllowConditional | AdapterOverride::Force(_)
        )
}

const fn backend_for_adapter(adapter: AdapterKind) -> Option<HookBackendKind> {
    match adapter {
        AdapterKind::ElleKit => Some(HookBackendKind::ElleKit),
        AdapterKind::Substrate => Some(HookBackendKind::Substrate),
        AdapterKind::Substitute => Some(HookBackendKind::Substitute),
        AdapterKind::Libhooker => Some(HookBackendKind::Libhooker),
        AdapterKind::InternalInline | AdapterKind::EnvironmentProbe | AdapterKind::None => None,
    }
}

fn query_only(
    input: AdapterDecisionInput,
    reason_code: DecisionReasonCode,
    recommended_action: RecommendedAction,
) -> AdapterDecision {
    decision(
        input,
        DecisionOutcome::QueryOnly,
        reason_code,
        recommended_action,
        AdapterKind::EnvironmentProbe,
        AdapterCommandMode::QueryOnly,
        ExecutionBoundary::EnvironmentProbe,
        requested_capability(input),
    )
}

fn requested_capability(input: AdapterDecisionInput) -> CapabilityLevel {
    input.backend.capabilities().for_operation(input.operation)
}

fn decision(
    input: AdapterDecisionInput,
    outcome: DecisionOutcome,
    reason_code: DecisionReasonCode,
    recommended_action: RecommendedAction,
    adapter: AdapterKind,
    command_mode: AdapterCommandMode,
    execution_boundary: ExecutionBoundary,
    capability: CapabilityLevel,
) -> AdapterDecision {
    let policy_allowed = outcome.requested_operation_allowed();
    AdapterDecision {
        operation: input.operation,
        backend: input.backend,
        presence: input.presence,
        conflicting_backend_count: input.conflicting_backend_count,
        arm64e: input.arm64e,
        policy: input.policy,
        override_mode: input.override_mode,
        capability,
        outcome,
        reason_code,
        recommended_action,
        adapter,
        command_mode,
        execution_boundary,
        policy_allowed,
        executable: policy_allowed && execution_boundary.executable_now(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn loaded(operation: HookOperation, backend: HookBackendKind) -> AdapterDecisionInput {
        AdapterDecisionInput::conservative(operation, backend, BackendPresence::Loaded)
    }

    fn bound(operation: HookOperation, backend: HookBackendKind) -> AdapterDecision {
        let mut decision = decide_hook_backend_adapter(loaded(operation, backend));
        decision.execution_boundary = ExecutionBoundary::ExternalFfi;
        decision.executable = true;
        decision
    }

    #[test]
    fn normalizes_known_backend_ids_and_capabilities() {
        assert_eq!(HookBackendKind::from_id("ElleKit"), HookBackendKind::ElleKit);
        assert_eq!(HookBackendKind::from_id("MobileSubstrate"), HookBackendKind::Substrate);
        assert_eq!(HookBackendKind::from_id("libsubstitute"), HookBackendKind::Substitute);
        assert_eq!(HookBackendKind::from_id("libhooker"), HookBackendKind::Libhooker);
        assert_eq!(
            HookBackendKind::parse("/var/jb/usr/lib/libellekit.dylib"),
            Some(HookBackendKind::ElleKit)
        );
        assert_eq!(HookBackendKind::from_id("other"), HookBackendKind::Unknown);
        assert_eq!(HookBackendKind::parse("other"), None);
        assert_eq!(
            HookBackendKind::Substrate.capabilities().arm64e,
            CapabilityLevel::Conditional
        );
        assert_eq!(
            HookBackendKind::Unknown.capabilities().install,
            CapabilityLevel::Unsupported
        );
    }

    #[test]
    fn public_uninstall_is_unsupported_for_every_external_backend() {
        for backend in [
            HookBackendKind::ElleKit,
            HookBackendKind::Substrate,
            HookBackendKind::Substitute,
            HookBackendKind::Libhooker,
        ] {
            assert_eq!(backend.capabilities().uninstall, CapabilityLevel::Unsupported);
        }
    }

    #[test]
    fn parses_upstream_operation_names_and_rejects_malformed_values() {
        assert_eq!(HookOperation::parse("Interceptor.attach"), Some(HookOperation::Attach));
        assert_eq!(
            HookOperation::parse("Interceptor.replace"),
            Some(HookOperation::Replace)
        );
        assert_eq!(HookOperation::parse("unhook"), Some(HookOperation::Uninstall));
        assert_eq!(HookOperation::parse("detach-all"), Some(HookOperation::Cleanup));
        assert_eq!(HookOperation::parse("execute"), None);

        assert_eq!(BackendPresence::parse("on-disk"), Some(BackendPresence::FilesystemOnly));
        assert_eq!(AdapterPolicy::parse("query_only"), Some(AdapterPolicy::QueryOnly));
        assert_eq!(
            AdapterPolicy::parse("deny-external-loaded"),
            Some(AdapterPolicy::CleanupOnly)
        );
        assert_eq!(
            AdapterOverride::parse("force:ellekit"),
            Some(AdapterOverride::Force(AdapterKind::ElleKit))
        );
        assert_eq!(AdapterOverride::parse("force:internal-inline"), None);
    }

    #[test]
    fn validates_state_topology_and_forced_adapter_inputs() {
        let absent_known = AdapterDecisionInput::conservative(
            HookOperation::Install,
            HookBackendKind::ElleKit,
            BackendPresence::Absent,
        );
        assert!(absent_known.validate().is_err());
        let invalid = decide_hook_backend_adapter(absent_known);
        assert_eq!(invalid.outcome, DecisionOutcome::Deny);
        assert_eq!(invalid.reason_code, DecisionReasonCode::InvalidInput);
        assert_eq!(invalid.backend, HookBackendKind::ElleKit);
        assert_eq!(invalid.presence, BackendPresence::Absent);

        let mut filesystem_conflict = AdapterDecisionInput::conservative(
            HookOperation::Install,
            HookBackendKind::ElleKit,
            BackendPresence::FilesystemOnly,
        );
        filesystem_conflict.conflicting_backend_count = 1;
        assert!(filesystem_conflict.validate().is_err());

        let mut invalid_force = loaded(HookOperation::Install, HookBackendKind::ElleKit);
        invalid_force.override_mode = AdapterOverride::Force(AdapterKind::EnvironmentProbe);
        assert!(invalid_force.validate().is_err());
    }

    #[test]
    fn single_loaded_backend_covers_query_install_uninstall_and_replace() {
        let query = decide_hook_backend_adapter(loaded(HookOperation::Query, HookBackendKind::ElleKit));
        assert_eq!(query.outcome, DecisionOutcome::Allow);
        assert_eq!(query.adapter, AdapterKind::ElleKit);
        assert_eq!(query.execution_boundary, ExecutionBoundary::EnvironmentProbe);
        assert!(query.requested_operation_executable());

        let install = decide_hook_backend_adapter(loaded(HookOperation::Install, HookBackendKind::ElleKit));
        assert_eq!(install.outcome, DecisionOutcome::Allow);
        assert_eq!(install.adapter, AdapterKind::ElleKit);
        assert_eq!(install.reason_code.as_str(), "adapter.backend.supported");
        assert_eq!(install.execution_boundary, ExecutionBoundary::ExternalAdvisory);
        assert!(install.requested_operation_allowed());
        assert!(!install.requested_operation_executable());

        let uninstall = decide_hook_backend_adapter(loaded(HookOperation::Uninstall, HookBackendKind::ElleKit));
        assert_eq!(uninstall.outcome, DecisionOutcome::Deny);
        assert_eq!(uninstall.reason_code, DecisionReasonCode::CapabilityUnsupported);

        let replace = decide_hook_backend_adapter(loaded(HookOperation::Replace, HookBackendKind::ElleKit));
        assert_eq!(replace.outcome, DecisionOutcome::Allow);
        assert_eq!(replace.adapter, AdapterKind::ElleKit);
        assert!(!replace.requested_operation_executable());

        let attach = decide_hook_backend_adapter(loaded(HookOperation::Attach, HookBackendKind::ElleKit));
        assert_eq!(attach.outcome, DecisionOutcome::Allow);
        assert_eq!(attach.capability, CapabilityLevel::Supported);
        assert_eq!(attach.execution_boundary.as_str(), "external-advisory");
    }

    #[test]
    fn no_external_backend_executes_on_internal_boundary() {
        let input = AdapterDecisionInput::conservative(
            HookOperation::Install,
            HookBackendKind::Unknown,
            BackendPresence::Absent,
        );
        let result = decide_hook_backend_adapter(input);

        assert_eq!(result.outcome, DecisionOutcome::Allow);
        assert_eq!(result.adapter, AdapterKind::InternalInline);
        assert_eq!(result.execution_boundary, ExecutionBoundary::InternalInline);
        assert!(result.requested_operation_executable());
        assert!(!result.requires_preflight());
    }

    #[test]
    fn filesystem_only_backend_degrades_writes_to_internal_after_preflight() {
        let input = AdapterDecisionInput::conservative(
            HookOperation::Install,
            HookBackendKind::Libhooker,
            BackendPresence::FilesystemOnly,
        );
        let result = decide_hook_backend_adapter(input);

        assert_eq!(result.outcome, DecisionOutcome::Degrade);
        assert!(result.requested_operation_allowed());
        assert_eq!(result.adapter, AdapterKind::InternalInline);
        assert_eq!(result.recommended_action, RecommendedAction::PreflightThenUseInternal);
        assert_eq!(result.execution_boundary, ExecutionBoundary::PreflightInternal);
        assert!(result.requires_preflight());
        assert!(!result.requested_operation_executable());
    }

    #[test]
    fn multiple_loaded_backends_are_query_only_by_default() {
        let mut input = loaded(HookOperation::Replace, HookBackendKind::ElleKit);
        input.conflicting_backend_count = 2;
        let result = decide_hook_backend_adapter(input);

        assert_eq!(result.outcome, DecisionOutcome::QueryOnly);
        assert!(!result.requested_operation_allowed());
        assert_eq!(result.reason_code, DecisionReasonCode::MultipleBackends);
        assert_eq!(result.adapter, AdapterKind::EnvironmentProbe);
        assert_eq!(result.command_mode, AdapterCommandMode::QueryOnly);
    }

    #[test]
    fn unknown_loaded_backend_is_never_allowed_to_write_by_default() {
        let result = decide_hook_backend_adapter(loaded(HookOperation::Install, HookBackendKind::Unknown));

        assert_eq!(result.outcome, DecisionOutcome::QueryOnly);
        assert_eq!(result.reason_code, DecisionReasonCode::UnknownBackend);
        assert_eq!(result.adapter, AdapterKind::EnvironmentProbe);
    }

    #[test]
    fn unknown_filesystem_only_backend_is_also_query_only() {
        let input = AdapterDecisionInput::conservative(
            HookOperation::Install,
            HookBackendKind::Unknown,
            BackendPresence::FilesystemOnly,
        );
        let result = decide_hook_backend_adapter(input);

        assert_eq!(result.outcome, DecisionOutcome::QueryOnly);
        assert_eq!(result.reason_code, DecisionReasonCode::UnknownBackend);
        assert_eq!(result.adapter, AdapterKind::EnvironmentProbe);
    }

    #[test]
    fn arm64e_conditional_backend_requires_explicit_policy_or_override() {
        let mut input = loaded(HookOperation::Replace, HookBackendKind::Substrate);
        input.arm64e = Some(true);
        let result = decide_hook_backend_adapter(input);

        assert_eq!(result.outcome, DecisionOutcome::QueryOnly);
        assert_eq!(result.reason_code, DecisionReasonCode::Arm64eConditional);
        assert_eq!(result.recommended_action, RecommendedAction::RequestExplicitOverride);
    }

    #[test]
    fn explicit_override_selects_one_adapter_during_conflict() {
        let mut input = loaded(HookOperation::Replace, HookBackendKind::Unknown);
        input.conflicting_backend_count = 2;
        input.arm64e = Some(true);
        input.override_mode = AdapterOverride::Force(AdapterKind::ElleKit);
        let result = decide_hook_backend_adapter(input);

        assert_eq!(result.outcome, DecisionOutcome::Allow);
        assert_eq!(result.reason_code, DecisionReasonCode::ExplicitOverride);
        assert_eq!(result.adapter, AdapterKind::ElleKit);
        assert_eq!(result.recommended_action, RecommendedAction::UseForcedAdapter);
        assert_eq!(result.execution_boundary, ExecutionBoundary::ExternalAdvisory);
        assert!(!result.requested_operation_executable());
    }

    #[test]
    fn query_only_policy_keeps_query_and_cleanup_but_blocks_install() {
        let query = {
            let mut input = loaded(HookOperation::Query, HookBackendKind::ElleKit);
            input.policy = AdapterPolicy::QueryOnly;
            decide_hook_backend_adapter(input)
        };
        assert_eq!(query.outcome, DecisionOutcome::Allow);
        assert_eq!(query.command_mode, AdapterCommandMode::QueryOnly);
        assert!(query.query_commands_allowed());
        assert!(query.cleanup_commands_allowed());
        assert!(!query.hook_install_commands_allowed());

        let cleanup = {
            let mut input = loaded(HookOperation::Cleanup, HookBackendKind::ElleKit);
            input.policy = AdapterPolicy::QueryOnly;
            decide_hook_backend_adapter(input)
        };
        assert_eq!(cleanup.outcome, DecisionOutcome::Allow);
        assert_eq!(cleanup.reason_code, DecisionReasonCode::CleanupAllowed);
        assert_eq!(cleanup.execution_boundary, ExecutionBoundary::InternalCleanup);
        assert!(cleanup.requested_operation_executable());

        let mut install = loaded(HookOperation::Install, HookBackendKind::ElleKit);
        install.policy = AdapterPolicy::QueryOnly;
        let blocked = decide_hook_backend_adapter(install);
        assert_eq!(blocked.outcome, DecisionOutcome::QueryOnly);
        assert!(!blocked.requested_operation_allowed());
    }

    #[test]
    fn cleanup_only_policy_blocks_external_uninstall_but_keeps_owned_cleanup() {
        for operation in [HookOperation::Query, HookOperation::Install, HookOperation::Replace] {
            let mut input = loaded(operation, HookBackendKind::ElleKit);
            input.policy = AdapterPolicy::CleanupOnly;
            let blocked = decide_hook_backend_adapter(input);
            assert_eq!(blocked.outcome, DecisionOutcome::Deny);
            assert_eq!(blocked.reason_code, DecisionReasonCode::PolicyCleanupOnly);
            assert_eq!(blocked.command_mode, AdapterCommandMode::CleanupOnly);
            assert!(!blocked.query_commands_allowed());
            assert!(!blocked.hook_install_commands_allowed());
            assert!(blocked.cleanup_commands_allowed());
        }

        let mut uninstall = loaded(HookOperation::Uninstall, HookBackendKind::ElleKit);
        uninstall.policy = AdapterPolicy::CleanupOnly;
        let uninstall = decide_hook_backend_adapter(uninstall);
        assert_eq!(uninstall.outcome, DecisionOutcome::Deny);
        assert_eq!(uninstall.capability, CapabilityLevel::Unsupported);
        assert!(!uninstall.requested_operation_executable());

        let mut cleanup = loaded(HookOperation::Cleanup, HookBackendKind::ElleKit);
        cleanup.policy = AdapterPolicy::CleanupOnly;
        let cleanup = decide_hook_backend_adapter(cleanup);
        assert_eq!(cleanup.outcome, DecisionOutcome::Allow);
        assert_eq!(cleanup.command_mode.as_str(), "cleanup-only");
        assert!(cleanup.requested_operation_executable());
    }

    #[test]
    fn deny_writes_policy_restricts_mutation_without_blocking_query() {
        let mut input = loaded(HookOperation::Install, HookBackendKind::ElleKit);
        input.policy = AdapterPolicy::DenyWrites;
        assert_eq!(decide_hook_backend_adapter(input).outcome, DecisionOutcome::Deny);

        input.operation = HookOperation::Query;
        assert_eq!(decide_hook_backend_adapter(input).outcome, DecisionOutcome::Allow);

        input.operation = HookOperation::Cleanup;
        let cleanup = decide_hook_backend_adapter(input);
        assert_eq!(cleanup.outcome, DecisionOutcome::Deny);
        assert!(!cleanup.cleanup_commands_allowed());
    }

    #[test]
    fn external_execution_mapping_is_bounded_to_install_attach_and_replace() {
        assert_eq!(
            external_operation(HookOperation::Install),
            Some(ExternalHookOperation::Install)
        );
        assert_eq!(
            external_operation(HookOperation::Attach),
            Some(ExternalHookOperation::Install)
        );
        assert_eq!(
            external_operation(HookOperation::Replace),
            Some(ExternalHookOperation::Replace)
        );
        assert_eq!(
            external_operation(HookOperation::Uninstall),
            Some(ExternalHookOperation::Uninstall)
        );
        assert_eq!(external_operation(HookOperation::Query), None);
        assert_eq!(external_operation(HookOperation::Cleanup), None);
        assert!(ExecutionBoundary::ExternalFfi.executable_now());
    }

    #[test]
    fn bound_decision_owns_idempotent_external_handle_release() {
        let decision = bound(HookOperation::Install, HookBackendKind::ElleKit);
        let mut handle = HookExecutionResult::synthetic(
            ExternalHookBackendKind::ElleKit,
            ExternalHookOperation::Install,
            0x1000,
            0x2000,
            0x3000,
        );
        let token = handle.token;

        assert!(decision
            .release_external_hook_handle(&mut handle)
            .expect("matching handle releases"));
        assert!(!decision
            .release_external_hook_handle(&mut handle)
            .expect("released handle is an idempotent no-op"));
        assert_eq!(handle.token, token);
        assert!(handle.handle_released());
    }

    #[test]
    fn external_uninstall_reports_missing_native_abi_without_releasing() {
        let decision = bound(HookOperation::Replace, HookBackendKind::Libhooker);
        let mut handle = HookExecutionResult::synthetic(
            ExternalHookBackendKind::Libhooker,
            ExternalHookOperation::Replace,
            0x1000,
            0x2000,
            0x3000,
        );

        for _ in 0..2 {
            let error = decision
                .uninstall_external_hook_handle(&mut handle)
                .expect_err("public native uninstall must remain unavailable");
            assert!(matches!(
                error,
                ExternalHookExecutionError::Backend(HookBackendFfiError::NativeUninstallUnavailable {
                    backend: ExternalHookBackendKind::Libhooker,
                    token,
                }) if token == handle.token
            ));
            assert!(!error.target_state_uncertain());
            assert!(!handle.handle_released());
        }
    }

    #[test]
    fn external_handle_backend_mismatch_is_preflight_and_preserves_ownership() {
        let decision = bound(HookOperation::Install, HookBackendKind::ElleKit);
        let mut handle = HookExecutionResult::synthetic(
            ExternalHookBackendKind::Substrate,
            ExternalHookOperation::Install,
            0x1000,
            0x2000,
            0x3000,
        );

        let error = decision
            .release_external_hook_handle(&mut handle)
            .expect_err("mismatched backend must be rejected before release");
        assert!(matches!(
            error,
            ExternalHookExecutionError::HandleMismatch {
                token,
                expected: HookBackendKind::ElleKit,
                actual: ExternalHookBackendKind::Substrate,
            } if token == handle.token
        ));
        assert!(!error.target_state_uncertain());
        assert!(!handle.handle_released());
    }

    #[test]
    fn forced_adapter_is_the_backend_identity_used_for_binding() {
        let mut input = loaded(HookOperation::Install, HookBackendKind::Unknown);
        input.override_mode = AdapterOverride::Force(AdapterKind::ElleKit);
        let decision = decide_hook_backend_adapter(input);

        assert_eq!(decision.adapter, AdapterKind::ElleKit);
        assert!(matches!(
            selected_external_backend(&decision),
            Ok(ExternalHookBackendKind::ElleKit)
        ));
    }

    #[test]
    fn binding_rejects_filesystem_only_and_already_executable_decisions() {
        let mut decision = decide_hook_backend_adapter(loaded(HookOperation::Install, HookBackendKind::ElleKit));
        decision.presence = BackendPresence::FilesystemOnly;
        assert!(matches!(
            validate_external_decision(&decision, true),
            Err(ExternalHookExecutionError::InvalidDecision(
                "external FFI requires a loaded backend image"
            ))
        ));

        let mut executable = decide_hook_backend_adapter(loaded(HookOperation::Install, HookBackendKind::ElleKit));
        executable.executable = true;
        assert!(matches!(
            validate_external_decision(&executable, true),
            Err(ExternalHookExecutionError::InvalidDecision(
                "binding requires a non-executable external advisory decision"
            ))
        ));
    }

    #[cfg(not(native_api_apple_hook_backend))]
    #[test]
    fn host_binding_reaches_the_platform_probe_without_claiming_execution() {
        let decision = decide_hook_backend_adapter(loaded(HookOperation::Install, HookBackendKind::ElleKit));
        assert!(decision.policy_allowed);
        assert_eq!(decision.execution_boundary, ExecutionBoundary::ExternalAdvisory);
        let error = match bind_external_hook_backend(decision, "libellekit.dylib") {
            Ok(_) => panic!("host unexpectedly resolved an Apple backend"),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            ExternalHookExecutionError::Backend(HookBackendFfiError::PlatformUnavailable)
        ));
    }

    #[cfg(not(native_api_apple_hook_backend))]
    #[test]
    fn host_binding_rejects_non_loaded_state_before_platform_resolution() {
        let mut decision = decide_hook_backend_adapter(loaded(HookOperation::Install, HookBackendKind::ElleKit));
        decision.presence = BackendPresence::FilesystemOnly;
        let error = match bind_external_hook_backend(decision, "libellekit.dylib") {
            Ok(_) => panic!("filesystem-only state unexpectedly bound an external backend"),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            ExternalHookExecutionError::InvalidDecision("external FFI requires a loaded backend image")
        ));
    }
}
