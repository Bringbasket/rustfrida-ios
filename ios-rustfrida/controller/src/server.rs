//! Bounded, concurrent session registry for controller server mode.

use std::{
    collections::BTreeMap,
    fmt,
    sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard},
    time::Duration,
};

use crate::session::{
    ExternalHookRelease, ExternalHookSnapshot, Session, SessionCommandBackend, SessionCommandFailure, SessionHookError,
    SessionId, SessionSnapshot, SessionTransitionError,
};
use common::command::{ExternalHookExecuteRequest, ExternalHookReceipt};

pub(crate) const DEFAULT_MAX_SESSIONS: usize = 32;

#[derive(Debug)]
pub(crate) enum SessionRegistryError {
    InvalidCapacity,
    CapacityReached { limit: usize },
    IdExhausted,
    NotFound(SessionId),
    Transition(SessionTransitionError),
    Hook(SessionHookError),
}

impl fmt::Display for SessionRegistryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidCapacity => formatter.write_str("session registry capacity must be greater than zero"),
            Self::CapacityReached { limit } => write!(formatter, "session registry capacity of {limit} reached"),
            Self::IdExhausted => formatter.write_str("session ID space exhausted"),
            Self::NotFound(id) => write!(formatter, "session {id} not found"),
            Self::Transition(error) => error.fmt(formatter),
            Self::Hook(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for SessionRegistryError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Transition(error) => Some(error),
            Self::Hook(error) => Some(error),
            _ => None,
        }
    }
}

impl From<SessionTransitionError> for SessionRegistryError {
    fn from(error: SessionTransitionError) -> Self {
        Self::Transition(error)
    }
}

impl From<SessionHookError> for SessionRegistryError {
    fn from(error: SessionHookError) -> Self {
        Self::Hook(error)
    }
}

#[derive(Debug)]
struct RegistryState {
    next_id: Option<u64>,
    sessions: BTreeMap<SessionId, Arc<Session>>,
}

/// Result of attempting to shut down a session. A failed outcome remains in the
/// registry so the backend and any controller-owned leases have a retry owner.
#[derive(Debug)]
pub(crate) struct DetachOutcome {
    pub session: Arc<Session>,
    pub failure: Option<SessionCommandFailure>,
}

impl DetachOutcome {
    pub(crate) fn is_clean(&self) -> bool {
        self.failure.is_none()
    }
}

/// Thread-safe registry with monotonically increasing, non-reused IDs.
pub(crate) struct SessionRegistry {
    max_sessions: usize,
    state: RwLock<RegistryState>,
}

impl fmt::Debug for SessionRegistry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SessionRegistry")
            .field("max_sessions", &self.max_sessions)
            .field("sessions", &self.list())
            .finish()
    }
}

impl Default for SessionRegistry {
    fn default() -> Self {
        Self::with_capacity(DEFAULT_MAX_SESSIONS).expect("default session capacity is nonzero")
    }
}

impl SessionRegistry {
    pub(crate) fn with_capacity(max_sessions: usize) -> Result<Self, SessionRegistryError> {
        if max_sessions == 0 {
            return Err(SessionRegistryError::InvalidCapacity);
        }
        Ok(Self {
            max_sessions,
            state: RwLock::new(RegistryState {
                next_id: Some(1),
                sessions: BTreeMap::new(),
            }),
        })
    }

    pub(crate) const fn capacity(&self) -> usize {
        self.max_sessions
    }

    pub(crate) fn len(&self) -> usize {
        read(&self.state).sessions.len()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Reserve an attaching session. The optional PID supports suspended-spawn
    /// workflows that learn their target PID after reserving a stable ID.
    pub(crate) fn reserve(
        &self,
        pid: Option<i32>,
        label: impl Into<String>,
    ) -> Result<Arc<Session>, SessionRegistryError> {
        let label = label.into();
        let mut state = write(&self.state);
        if state.sessions.len() >= self.max_sessions {
            return Err(SessionRegistryError::CapacityReached {
                limit: self.max_sessions,
            });
        }

        let raw_id = state.next_id.ok_or(SessionRegistryError::IdExhausted)?;
        let id = SessionId::from_raw(raw_id).ok_or(SessionRegistryError::IdExhausted)?;
        state.next_id = raw_id.checked_add(1);
        let session = Arc::new(Session::new(id, pid, label));
        state.sessions.insert(id, Arc::clone(&session));
        Ok(session)
    }

    /// Reserve and immediately publish an attached command backend.
    pub(crate) fn attach(
        &self,
        pid: Option<i32>,
        label: impl Into<String>,
        backend: Arc<dyn SessionCommandBackend>,
    ) -> Result<Arc<Session>, SessionRegistryError> {
        let session = self.reserve(pid, label)?;
        if let Err(error) = session.complete_attach(backend) {
            write(&self.state).sessions.remove(&session.id());
            return Err(error.into());
        }
        Ok(session)
    }

    pub(crate) fn fail_attach(
        &self,
        id: SessionId,
        message: impl Into<String>,
    ) -> Result<Arc<Session>, SessionRegistryError> {
        let session = self.get(id).ok_or(SessionRegistryError::NotFound(id))?;
        session.fail_attach(message)?;
        Ok(session)
    }

    /// Transfer a successful external adapter result into one session. The
    /// session keeps the native token and adapter decision together, so a
    /// registry detach can release the exact lease without reconstructing ABI
    /// details from a token alone.
    pub(crate) fn adopt_external_hook(
        &self,
        id: SessionId,
        decision: native_api::AdapterDecision,
        handle: native_api::HookExecutionResult,
    ) -> Result<u64, SessionRegistryError> {
        let session = self.get(id).ok_or(SessionRegistryError::NotFound(id))?;
        session.adopt_external_hook(decision, handle).map_err(Into::into)
    }

    pub(crate) fn execute_external_hook(
        &self,
        id: SessionId,
        request: ExternalHookExecuteRequest,
        timeout: Duration,
    ) -> Result<ExternalHookReceipt, SessionRegistryError> {
        let session = self.get(id).ok_or(SessionRegistryError::NotFound(id))?;
        session.execute_external_hook(request, timeout).map_err(Into::into)
    }

    pub(crate) fn release_external_hook(
        &self,
        id: SessionId,
        token: u64,
    ) -> Result<ExternalHookRelease, SessionRegistryError> {
        let session = self.get(id).ok_or(SessionRegistryError::NotFound(id))?;
        session.release_external_hook(token).map_err(Into::into)
    }

    pub(crate) fn uninstall_external_hook(
        &self,
        id: SessionId,
        token: u64,
    ) -> Result<ExternalHookRelease, SessionRegistryError> {
        let session = self.get(id).ok_or(SessionRegistryError::NotFound(id))?;
        session.uninstall_external_hook(token).map_err(Into::into)
    }

    pub(crate) fn external_hook_status(
        &self,
        id: SessionId,
    ) -> Result<Vec<ExternalHookSnapshot>, SessionRegistryError> {
        let session = self.get(id).ok_or(SessionRegistryError::NotFound(id))?;
        Ok(session.external_hook_status())
    }

    pub(crate) fn get(&self, id: SessionId) -> Option<Arc<Session>> {
        read(&self.state).sessions.get(&id).cloned()
    }

    pub(crate) fn find_by_pid(&self, pid: i32) -> Vec<Arc<Session>> {
        read(&self.state)
            .sessions
            .values()
            .filter(|session| session.snapshot().pid == Some(pid))
            .cloned()
            .collect()
    }

    /// Clone attached sessions for a health worker without holding the
    /// registry lock while a backend performs I/O.
    pub(crate) fn attached_sessions(&self) -> Vec<Arc<Session>> {
        read(&self.state)
            .sessions
            .values()
            .filter(|session| session.is_attached())
            .cloned()
            .collect()
    }

    /// Snapshots are sorted by ID because the registry uses a `BTreeMap`.
    pub(crate) fn list(&self) -> Vec<SessionSnapshot> {
        read(&self.state)
            .sessions
            .values()
            .map(|session| session.snapshot())
            .collect()
    }

    /// Shut down a session before removing it from future lookup. Failed
    /// shutdowns stay registered so a later detach can retry the backend and
    /// controller-owned lease cleanup.
    pub(crate) fn detach(&self, id: SessionId, timeout: Duration) -> Result<DetachOutcome, SessionRegistryError> {
        let session = self.get(id).ok_or(SessionRegistryError::NotFound(id))?;
        let failure = session.detach(timeout).err();
        if failure.is_none() {
            write(&self.state).sessions.remove(&id);
        }
        Ok(DetachOutcome { session, failure })
    }

    pub(crate) fn detach_all(&self, timeout: Duration) -> Vec<DetachOutcome> {
        let sessions = { read(&self.state).sessions.values().cloned().collect::<Vec<_>>() };
        sessions
            .into_iter()
            .map(|session| {
                let failure = session.detach(timeout).err();
                if failure.is_none() {
                    write(&self.state).sessions.remove(&session.id());
                }
                DetachOutcome { session, failure }
            })
            .collect()
    }

    /// Transition a session to `Failed`, then attempt the same retryable detach
    /// path used by an explicit command. Races with an explicit detach are
    /// benign: the first owner wins and a stale health observation is ignored.
    pub(crate) fn reap_unhealthy(
        &self,
        session: &Arc<Session>,
        failure: &SessionCommandFailure,
        timeout: Duration,
    ) -> Option<DetachOutcome> {
        session.mark_unhealthy(failure).ok()?;
        self.detach(session.id(), timeout).ok()
    }

    pub(crate) fn reap_command_transport_failure(
        &self,
        session: &Arc<Session>,
        failure: &SessionCommandFailure,
        timeout: Duration,
    ) -> Option<DetachOutcome> {
        session.mark_command_transport_failure(failure).ok()?;
        self.detach(session.id(), timeout).ok()
    }
}

fn read<T>(lock: &RwLock<T>) -> RwLockReadGuard<'_, T> {
    lock.read().unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn write<T>(lock: &RwLock<T>) -> RwLockWriteGuard<'_, T> {
    lock.write().unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[cfg(test)]
mod tests {
    use super::{SessionRegistry, SessionRegistryError};
    use crate::session::{SessionCommandBackend, SessionCommandFailure, SessionState};
    use common::command::{
        ExternalHookCommandOperation, ExternalHookExecuteRequest, ExternalHookOwnershipState, ExternalHookReply,
        ExternalHookTargetState,
    };
    use serde_json::Value;
    use std::{
        collections::{BTreeSet, VecDeque},
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc, Barrier, Mutex,
        },
        thread,
        time::Duration,
    };

    #[derive(Default)]
    struct Backend {
        detach_count: AtomicUsize,
    }

    impl SessionCommandBackend for Backend {
        fn rpc_call(&self, _method: &str, args: &Value, _timeout: Duration) -> Result<Value, SessionCommandFailure> {
            Ok(args.clone())
        }

        fn detach(&self, _timeout: Duration) -> Result<(), SessionCommandFailure> {
            self.detach_count.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    struct HookBackend {
        replies: Mutex<VecDeque<Value>>,
    }

    impl SessionCommandBackend for HookBackend {
        fn rpc_call(&self, _method: &str, _args: &Value, _timeout: Duration) -> Result<Value, SessionCommandFailure> {
            Err(SessionCommandFailure::BadRequest("RPC unavailable in hook test".into()))
        }

        fn external_hook_command(
            &self,
            _command: &common::AgentCommand,
            _timeout: Duration,
        ) -> Result<Value, SessionCommandFailure> {
            self.replies
                .lock()
                .expect("replies lock")
                .pop_front()
                .ok_or_else(|| SessionCommandFailure::Unavailable("missing hook reply".into()))
        }
    }

    struct RetryBackend {
        attempts: AtomicUsize,
    }

    impl SessionCommandBackend for RetryBackend {
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
    fn registry_is_bounded_and_does_not_reuse_ids() {
        let registry = SessionRegistry::with_capacity(2).expect("registry");
        assert_eq!(registry.capacity(), 2);
        let first = registry.reserve(Some(10), "first").expect("first session");
        let second = registry.reserve(Some(20), "second").expect("second session");
        assert!(matches!(
            registry.reserve(Some(30), "third"),
            Err(SessionRegistryError::CapacityReached { limit: 2 })
        ));

        registry
            .detach(first.id(), Duration::from_secs(1))
            .expect("detach first");
        let third = registry.reserve(Some(30), "third").expect("third session");
        assert_eq!(second.id().get(), 2);
        assert_eq!(third.id().get(), 3);
        assert!(registry.get(first.id()).is_none());
    }

    #[test]
    fn attached_sessions_support_lookup_listing_and_detach() {
        let registry = SessionRegistry::with_capacity(4).expect("registry");
        let backend = Arc::new(Backend::default());
        let session = registry
            .attach(Some(42), "target", backend.clone())
            .expect("attach session");

        assert!(session.is_attached());
        assert_eq!(registry.get(session.id()).expect("lookup").id(), session.id());
        assert_eq!(registry.find_by_pid(42).len(), 1);
        let listed = registry.list();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].state, SessionState::Attached);
        assert_eq!(listed[0].status(), "connected");

        let outcome = registry.detach(session.id(), Duration::from_secs(1)).expect("detach");
        assert!(outcome.is_clean());
        assert_eq!(outcome.session.id(), session.id());
        assert_eq!(backend.detach_count.load(Ordering::SeqCst), 1);
        assert!(registry.is_empty());
    }

    #[test]
    fn registry_external_hook_entry_adopts_agent_receipt() {
        let request = ExternalHookExecuteRequest {
            request_id: "request-1".into(),
            owner_id: "session:1".into(),
            operation: ExternalHookCommandOperation::Install,
            backend_image: "/var/jb/usr/lib/libellekit.dylib".into(),
            target: 0x1000,
            replacement: 0x2000,
        };
        let receipt = common::command::ExternalHookReceipt {
            request_id: request.request_id.clone(),
            owner_id: request.owner_id.clone(),
            token: Some(903),
            backend: "ellekit".into(),
            backend_image: request.backend_image.clone(),
            operation: request.operation,
            target: request.target,
            replacement: request.replacement,
            original: Some(0x3000),
            native_result: None,
            ownership: ExternalHookOwnershipState::Owned,
            target_state: ExternalHookTargetState::Installed,
            native_uninstall_available: false,
            last_error: None,
        };
        let backend = Arc::new(HookBackend {
            replies: Mutex::new(VecDeque::from([serde_json::to_value(ExternalHookReply::Execute {
                receipt,
                replayed: false,
            })
            .expect("reply JSON")])),
        });
        let registry = SessionRegistry::with_capacity(1).expect("registry");
        let session = registry.attach(None, "target", backend).expect("attach");
        let adopted = registry
            .execute_external_hook(session.id(), request, Duration::from_secs(1))
            .expect("registry execute");
        assert_eq!(adopted.token, Some(903));
        assert_eq!(registry.list()[0].external_hooks[0].token, 903);
    }

    #[test]
    fn failed_attach_remains_listable_until_detached() {
        let registry = SessionRegistry::with_capacity(1).expect("registry");
        let session = registry.reserve(None, "spawn target").expect("reserve");
        session.update_target(Some(99), "spawned target");
        registry
            .fail_attach(session.id(), "agent connection timed out")
            .expect("record failure");

        let listed = registry.list();
        assert_eq!(listed[0].pid, Some(99));
        assert_eq!(listed[0].label, "spawned target");
        assert_eq!(listed[0].state, SessionState::Failed);
        assert_eq!(listed[0].last_error.as_deref(), Some("agent connection timed out"));
    }

    #[test]
    fn concurrent_reservations_obey_capacity_and_allocate_unique_ids() {
        const WORKERS: usize = 24;
        const LIMIT: usize = 8;
        let registry = Arc::new(SessionRegistry::with_capacity(LIMIT).expect("registry"));
        let barrier = Arc::new(Barrier::new(WORKERS));
        let workers = (0..WORKERS)
            .map(|worker| {
                let registry = Arc::clone(&registry);
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    barrier.wait();
                    registry.reserve(Some(worker as i32), format!("target-{worker}"))
                })
            })
            .collect::<Vec<_>>();

        let sessions = workers
            .into_iter()
            .filter_map(|worker| worker.join().expect("worker thread").ok())
            .collect::<Vec<_>>();
        let ids = sessions
            .iter()
            .map(|session| session.id().get())
            .collect::<BTreeSet<_>>();
        assert_eq!(sessions.len(), LIMIT);
        assert_eq!(ids.len(), LIMIT);
        assert_eq!(registry.len(), LIMIT);
    }

    #[test]
    fn detach_all_removes_every_session_in_id_order() {
        let registry = SessionRegistry::with_capacity(3).expect("registry");
        for pid in 1..=3 {
            registry
                .attach(Some(pid), format!("target-{pid}"), Arc::new(Backend::default()))
                .expect("attach");
        }

        let outcomes = registry.detach_all(Duration::from_secs(1));
        let ids = outcomes
            .iter()
            .map(|outcome| outcome.session.id().get())
            .collect::<Vec<_>>();
        assert_eq!(ids, vec![1, 2, 3]);
        assert!(outcomes.iter().all(|outcome| outcome.is_clean()));
        assert!(registry.is_empty());
    }

    #[test]
    fn failed_detach_keeps_registry_owner_and_allows_retry() {
        let registry = SessionRegistry::with_capacity(1).expect("registry");
        let backend = Arc::new(RetryBackend {
            attempts: AtomicUsize::new(0),
        });
        let session = registry
            .attach(Some(42), "retry target", backend.clone())
            .expect("attach");

        let first = registry
            .detach(session.id(), Duration::from_secs(1))
            .expect("first detach attempt");
        assert!(!first.is_clean());
        assert_eq!(registry.get(session.id()).expect("failed owner").id(), session.id());
        assert_eq!(registry.len(), 1);
        assert!(matches!(
            registry.reserve(Some(43), "capacity remains occupied"),
            Err(SessionRegistryError::CapacityReached { limit: 1 })
        ));

        let second = registry
            .detach(session.id(), Duration::from_secs(1))
            .expect("retry detach");
        assert!(second.is_clean());
        assert!(registry.get(session.id()).is_none());
        assert!(registry.is_empty());
        assert_eq!(backend.attempts.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn detach_all_retains_only_failed_sessions_for_retry() {
        let registry = SessionRegistry::with_capacity(2).expect("registry");
        let retry_backend = Arc::new(RetryBackend {
            attempts: AtomicUsize::new(0),
        });
        let failed = registry
            .attach(Some(1), "failed", retry_backend.clone())
            .expect("failed session");
        let clean = registry
            .attach(Some(2), "clean", Arc::new(Backend::default()))
            .expect("clean session");

        let outcomes = registry.detach_all(Duration::from_secs(1));
        assert_eq!(outcomes.len(), 2);
        assert!(outcomes
            .iter()
            .any(|outcome| outcome.session.id() == clean.id() && outcome.is_clean()));
        assert!(outcomes
            .iter()
            .any(|outcome| outcome.session.id() == failed.id() && !outcome.is_clean()));
        assert!(registry.get(clean.id()).is_none());
        assert!(registry.get(failed.id()).is_some());
        assert_eq!(registry.len(), 1);

        let retry = registry
            .detach(failed.id(), Duration::from_secs(1))
            .expect("failed session retry");
        assert!(retry.is_clean());
        assert!(registry.is_empty());
        assert_eq!(retry_backend.attempts.load(Ordering::SeqCst), 2);
    }
}
