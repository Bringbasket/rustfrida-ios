//! Host-side Stalker contract for the iOS ARM64 backend.
//!
//! The Android reference uses Frida Gum's instruction transformer and event
//! sink.  The iOS subset below has three deliberately separate layers:
//! static ARM64 decoding, a bounded transform/event plan, and the existing
//! function-level thread event sink.  The plan can validate caller-supplied
//! execution steps and feed the bounded queue, but it does not rewrite target
//! memory or claim target-thread instruction instrumentation.

use common::{Error, Result};
use std::collections::BTreeMap;
use std::sync::{Mutex, OnceLock};

pub const DEFAULT_STALKER_QUEUE_CAPACITY: usize = 4096;
pub const MAX_STALKER_QUEUE_CAPACITY: usize = 1_000_000;
#[allow(dead_code)]
pub const DEFAULT_STALKER_TRANSFORM_MAX_INSTRUCTIONS: usize = 256;
pub const MAX_STALKER_TRANSFORM_INSTRUCTIONS: usize = 4096;
pub const DEFAULT_STALKER_GENERATED_EVENT_CAPACITY: usize = 4096;

const STALKER_TRANSFORM_MODE: &str = "static-only";
const STALKER_EVENT_GENERATION_MODE: &str = "caller-supplied-execution-trace";

fn stalker_registry() -> &'static Mutex<BTreeMap<u64, StalkerSession>> {
    static REGISTRY: OnceLock<Mutex<BTreeMap<u64, StalkerSession>>> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(BTreeMap::new()))
}

fn registry_lock() -> std::sync::MutexGuard<'static, BTreeMap<u64, StalkerSession>> {
    stalker_registry()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Return the OS thread identifier used by the Apple pthread APIs.
///
/// On Apple this is `pthread_threadid_np`, which is stable for the lifetime of
/// the thread and is the identifier accepted by the runtime's follow API.  The
/// host implementation uses the pthread handle so the same lifecycle can be
/// exercised by deterministic tests.
pub fn current_stalker_thread_id() -> u64 {
    #[cfg(any(target_os = "ios", target_os = "macos"))]
    {
        let mut thread_id = 0_u64;
        let result = unsafe { libc::pthread_threadid_np(0, &mut thread_id) };
        if result == 0 && thread_id != 0 {
            return thread_id;
        }
        return 0;
    }

    #[cfg(not(any(target_os = "ios", target_os = "macos")))]
    {
        unsafe { libc::pthread_self() as usize as u64 }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StalkerThreadStatus {
    pub thread_id: u64,
    pub state: StalkerSessionState,
    pub queued_events: usize,
    pub dropped_events: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StalkerBackendStatus {
    pub backend: &'static str,
    pub mode: &'static str,
    pub active: bool,
    pub session_count: usize,
    pub threads: Vec<StalkerThreadStatus>,
}

pub fn stalker_follow_thread(thread_id: u64, config: StalkerConfig) -> Result<StalkerThreadStatus> {
    if thread_id == 0 {
        return Err(Error::InvalidArgument("stalker thread id must be non-zero".into()));
    }
    let mut registry = registry_lock();
    if registry.contains_key(&thread_id) {
        return Err(Error::State(format!("stalker thread {thread_id} is already followed")));
    }
    let mut session = StalkerSession::new(config)?;
    session.follow(thread_id)?;
    let status = stalker_thread_status(thread_id, &session);
    registry.insert(thread_id, session);
    Ok(status)
}

pub fn stalker_unfollow_thread(thread_id: u64) -> Result<StalkerThreadStatus> {
    let mut registry = registry_lock();
    let mut session = registry
        .remove(&thread_id)
        .ok_or_else(|| Error::State(format!("stalker session is not following thread {thread_id}")))?;
    session.unfollow(thread_id)?;
    Ok(stalker_thread_status(thread_id, &session))
}

pub fn stalker_flush_thread(thread_id: u64) -> Result<Vec<StalkerEvent>> {
    let mut registry = registry_lock();
    let session = registry
        .get_mut(&thread_id)
        .ok_or_else(|| Error::State(format!("stalker session is not following thread {thread_id}")))?;
    Ok(session.flush())
}

pub fn stalker_garbage_collect_thread(thread_id: u64) -> Result<bool> {
    let mut registry = registry_lock();
    if let Some(session) = registry.get(&thread_id) {
        if session.state() != StalkerSessionState::Idle {
            return Err(Error::State(
                "stalker garbage collection requires an unfollowed session".into(),
            ));
        }
    }
    if let Some(mut session) = registry.remove(&thread_id) {
        return session.garbage_collect();
    }
    Ok(true)
}

/// The event sink used by the Apple hook/event boundary.
///
/// The current backend does not rewrite instructions, so this sink is fed by
/// an installed function hook, an explicit event producer, or the bounded
/// transform plan. It still provides a real, bounded, thread-keyed queue with
/// filtering, exclusion and drop accounting rather than a capability-only
/// status object.
pub fn stalker_event_sink(thread_id: u64, event: StalkerEvent) -> Result<bool> {
    let mut registry = registry_lock();
    let session = registry
        .get_mut(&thread_id)
        .ok_or_else(|| Error::State(format!("stalker session is not following thread {thread_id}")))?;
    Ok(session.record(event))
}

pub fn stalker_backend_status() -> StalkerBackendStatus {
    let registry = registry_lock();
    let threads = registry
        .iter()
        .map(|(thread_id, session)| stalker_thread_status(*thread_id, session))
        .collect::<Vec<_>>();
    StalkerBackendStatus {
        backend: "apple-pthread-event-sink",
        mode: "thread-follow-event-sink",
        active: !threads.is_empty(),
        session_count: threads.len(),
        threads,
    }
}

fn stalker_thread_status(thread_id: u64, session: &StalkerSession) -> StalkerThreadStatus {
    StalkerThreadStatus {
        thread_id,
        state: session.state(),
        queued_events: session.events().len(),
        dropped_events: session.dropped_events(),
    }
}

/// The subset of AArch64 control-flow instructions needed to split a
/// decoder-backed basic block.  This is intentionally a decoder contract,
/// rather than a claim that the current hook engine rewrites target code.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Arm64InstructionKind {
    Other,
    Branch,
    BranchLink,
    ConditionalBranch,
    CompareBranch,
    TestBranch,
    BranchRegister,
    BranchLinkRegister,
    Return,
    Exception,
}

#[allow(dead_code)]
impl Arm64InstructionKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Other => "other",
            Self::Branch => "b",
            Self::BranchLink => "bl",
            Self::ConditionalBranch => "b.cond",
            Self::CompareBranch => "cbz/cbnz",
            Self::TestBranch => "tbz/tbnz",
            Self::BranchRegister => "br",
            Self::BranchLinkRegister => "blr",
            Self::Return => "ret",
            Self::Exception => "exception",
        }
    }

    pub const fn ends_basic_block(self) -> bool {
        matches!(
            self,
            Self::Branch
                | Self::ConditionalBranch
                | Self::CompareBranch
                | Self::TestBranch
                | Self::BranchRegister
                | Self::Return
                | Self::Exception
        )
    }

    pub const fn is_call(self) -> bool {
        matches!(self, Self::BranchLink | Self::BranchLinkRegister)
    }

    pub const fn is_return(self) -> bool {
        matches!(self, Self::Return)
    }
}

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Arm64Instruction {
    pub address: u64,
    pub word: u32,
    pub kind: Arm64InstructionKind,
    pub direct_target: Option<u64>,
}

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Arm64BasicBlock {
    pub start: u64,
    pub end: u64,
    pub instructions: Vec<Arm64Instruction>,
    pub terminator: Option<Arm64InstructionKind>,
}

#[allow(dead_code)]
fn sign_extend(value: u64, bits: u32) -> i64 {
    let shift = 64 - bits;
    ((value << shift) as i64) >> shift
}

#[allow(dead_code)]
fn add_signed(address: u64, offset: i64) -> Option<u64> {
    if offset >= 0 {
        address.checked_add(offset as u64)
    } else {
        address.checked_sub(offset.unsigned_abs())
    }
}

/// Decode one little-endian ARM64 instruction word.
#[allow(dead_code)]
pub fn decode_arm64_instruction(address: u64, word: u32) -> Result<Arm64Instruction> {
    if address & 3 != 0 {
        return Err(Error::InvalidArgument(format!(
            "ARM64 instruction address must be 4-byte aligned: 0x{address:x}"
        )));
    }

    let kind = if word & 0xffff_fc1f == 0xd65f_0000 {
        Arm64InstructionKind::Return
    } else if word & 0xffff_fc1f == 0xd61f_0000 {
        Arm64InstructionKind::BranchRegister
    } else if word & 0xffff_fc1f == 0xd63f_0000 {
        Arm64InstructionKind::BranchLinkRegister
    } else if word == 0xd69f_03e0 || word == 0xd6bf_03e0 {
        Arm64InstructionKind::Exception
    } else if word & 0xffe0_001f == 0xd400_0001 {
        Arm64InstructionKind::Exception
    } else if word & 0xfc00_0000 == 0x9400_0000 {
        Arm64InstructionKind::BranchLink
    } else if word & 0x7c00_0000 == 0x1400_0000 {
        Arm64InstructionKind::Branch
    } else if word & 0xff00_0010 == 0x5400_0000 {
        Arm64InstructionKind::ConditionalBranch
    } else if word & 0x7f00_0000 == 0x3400_0000 {
        Arm64InstructionKind::CompareBranch
    } else if word & 0x7f00_0000 == 0x3600_0000 {
        Arm64InstructionKind::TestBranch
    } else {
        Arm64InstructionKind::Other
    };

    let direct_target = match kind {
        Arm64InstructionKind::Branch | Arm64InstructionKind::BranchLink => {
            add_signed(address, sign_extend((word & 0x03ff_ffff) as u64, 26) * 4)
        }
        Arm64InstructionKind::ConditionalBranch | Arm64InstructionKind::CompareBranch => {
            add_signed(address, sign_extend(((word >> 5) & 0x0007_ffff) as u64, 19) * 4)
        }
        Arm64InstructionKind::TestBranch => {
            add_signed(address, sign_extend(((word >> 5) & 0x0000_3fff) as u64, 14) * 4)
        }
        _ => None,
    };

    Ok(Arm64Instruction {
        address,
        word,
        kind,
        direct_target,
    })
}

/// Decode one statically bounded ARM64 basic block from little-endian bytes.
/// The result describes decoded control flow; it does not imply execution.
#[allow(dead_code)]
pub fn decode_arm64_basic_block(start: u64, bytes: &[u8], max_instructions: usize) -> Result<Arm64BasicBlock> {
    if start & 3 != 0 {
        return Err(Error::InvalidArgument(format!(
            "ARM64 basic-block address must be 4-byte aligned: 0x{start:x}"
        )));
    }
    if bytes.is_empty() || bytes.len() % 4 != 0 {
        return Err(Error::InvalidArgument(
            "ARM64 basic-block bytes must contain one or more complete instructions".into(),
        ));
    }
    if max_instructions == 0 {
        return Err(Error::InvalidArgument(
            "ARM64 instruction limit must be non-zero".into(),
        ));
    }

    let limit = (bytes.len() / 4).min(max_instructions);
    let mut instructions = Vec::with_capacity(limit);
    let mut terminator = None;
    for index in 0..limit {
        let offset = index * 4;
        let word = u32::from_le_bytes(bytes[offset..offset + 4].try_into().expect("four bytes"));
        let address = start
            .checked_add(offset as u64)
            .ok_or_else(|| Error::InvalidArgument("ARM64 basic-block address overflow".into()))?;
        let instruction = decode_arm64_instruction(address, word)?;
        let ends = instruction.kind.ends_basic_block();
        if ends {
            terminator = Some(instruction.kind);
        }
        instructions.push(instruction);
        if ends {
            break;
        }
    }

    let end = start
        .checked_add((instructions.len() * 4) as u64)
        .ok_or_else(|| Error::InvalidArgument("ARM64 basic-block end address overflow".into()))?;
    Ok(Arm64BasicBlock {
        start,
        end,
        instructions,
        terminator,
    })
}

#[derive(Debug, Clone)]
struct BoundedBasicBlockTransform {
    block: Arm64BasicBlock,
    input_instruction_count: usize,
    limit_reached: bool,
    stopped_at_terminator: bool,
}

fn validate_transform_limit(max_instructions: usize) -> Result<()> {
    if max_instructions == 0 || max_instructions > MAX_STALKER_TRANSFORM_INSTRUCTIONS {
        return Err(Error::InvalidArgument(format!(
            "stalker transform instruction limit must be between 1 and {MAX_STALKER_TRANSFORM_INSTRUCTIONS}"
        )));
    }
    Ok(())
}

fn build_bounded_basic_block_transform(
    start: u64,
    bytes: &[u8],
    max_instructions: usize,
) -> Result<BoundedBasicBlockTransform> {
    validate_transform_limit(max_instructions)?;
    if bytes.len() / 4 > MAX_STALKER_TRANSFORM_INSTRUCTIONS {
        return Err(Error::InvalidArgument(format!(
            "stalker transform input exceeds {MAX_STALKER_TRANSFORM_INSTRUCTIONS} instructions"
        )));
    }

    let input_instruction_count = bytes.len() / 4;
    let block = decode_arm64_basic_block(start, bytes, max_instructions)?;
    let stopped_at_terminator = block.terminator.is_some();
    let limit_reached = !stopped_at_terminator
        && block.instructions.len() < input_instruction_count
        && block.instructions.len() >= max_instructions;

    Ok(BoundedBasicBlockTransform {
        block,
        input_instruction_count,
        limit_reached,
        stopped_at_terminator,
    })
}

fn push_bounded_event(
    events: &mut Vec<StalkerEvent>,
    attempted_events: &mut usize,
    dropped_events: &mut usize,
    max_events: usize,
    event: StalkerEvent,
) {
    *attempted_events = attempted_events.saturating_add(1);
    if events.len() < max_events {
        events.push(event);
    } else {
        *dropped_events = dropped_events.saturating_add(1);
    }
}

fn generate_events_for_transform(
    transform: &BoundedBasicBlockTransform,
    execution_steps: &[(u64, u64, i32)],
    event_mask: StalkerEventMask,
    max_events: usize,
) -> Result<(Vec<StalkerEvent>, usize, usize, bool)> {
    if max_events == 0 || max_events > MAX_STALKER_QUEUE_CAPACITY {
        return Err(Error::InvalidArgument(format!(
            "stalker generated event limit must be between 1 and {MAX_STALKER_QUEUE_CAPACITY}"
        )));
    }

    let mut events = Vec::with_capacity(max_events.min(DEFAULT_STALKER_GENERATED_EVENT_CAPACITY).min(32));
    let mut attempted_events = 0usize;
    let mut dropped_events = 0usize;

    if event_mask.contains(StalkerEventKind::Compile) {
        push_bounded_event(
            &mut events,
            &mut attempted_events,
            &mut dropped_events,
            max_events,
            StalkerEvent::Compile {
                start: transform.block.start,
                end: transform.block.end,
            },
        );
    }

    let mut resolved_steps = Vec::with_capacity(execution_steps.len());
    for &(address, target, depth) in execution_steps {
        let instruction = transform
            .block
            .instructions
            .iter()
            .find(|instruction| instruction.address == address)
            .ok_or_else(|| {
                Error::InvalidArgument(format!(
                    "stalker execution step 0x{address:x} is outside transformed basic block"
                ))
            })?;
        resolved_steps.push((*instruction, target, depth));
    }

    let execution_observed = !resolved_steps.is_empty();
    if execution_observed && event_mask.contains(StalkerEventKind::Block) {
        push_bounded_event(
            &mut events,
            &mut attempted_events,
            &mut dropped_events,
            max_events,
            StalkerEvent::Block {
                start: transform.block.start,
                end: transform.block.end,
            },
        );
    }

    for (instruction, supplied_target, depth) in resolved_steps {
        if event_mask.contains(StalkerEventKind::Exec) {
            push_bounded_event(
                &mut events,
                &mut attempted_events,
                &mut dropped_events,
                max_events,
                StalkerEvent::Exec {
                    location: instruction.address,
                },
            );
        }

        if instruction.kind.is_call() && event_mask.contains(StalkerEventKind::Call) {
            let target = if supplied_target != 0 {
                supplied_target
            } else {
                instruction.direct_target.unwrap_or(0)
            };
            push_bounded_event(
                &mut events,
                &mut attempted_events,
                &mut dropped_events,
                max_events,
                StalkerEvent::Call {
                    location: instruction.address,
                    target,
                    depth,
                },
            );
        }

        if instruction.kind.is_return() && event_mask.contains(StalkerEventKind::Ret) {
            push_bounded_event(
                &mut events,
                &mut attempted_events,
                &mut dropped_events,
                max_events,
                StalkerEvent::Ret {
                    location: instruction.address,
                    target: supplied_target,
                    depth,
                },
            );
        }
    }

    Ok((events, attempted_events, dropped_events, execution_observed))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StalkerEventKind {
    Call,
    Ret,
    Exec,
    Block,
    Compile,
}

impl StalkerEventKind {
    pub const fn mask(self) -> StalkerEventMask {
        match self {
            Self::Call => StalkerEventMask::CALL,
            Self::Ret => StalkerEventMask::RET,
            Self::Exec => StalkerEventMask::EXEC,
            Self::Block => StalkerEventMask::BLOCK,
            Self::Compile => StalkerEventMask::COMPILE,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Call => "call",
            Self::Ret => "ret",
            Self::Exec => "exec",
            Self::Block => "block",
            Self::Compile => "compile",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StalkerEventMask(u32);

impl StalkerEventMask {
    pub const NONE: Self = Self(0);
    pub const CALL: Self = Self(1 << 0);
    pub const RET: Self = Self(1 << 1);
    pub const EXEC: Self = Self(1 << 2);
    pub const BLOCK: Self = Self(1 << 3);
    pub const COMPILE: Self = Self(1 << 4);
    pub const ALL: Self = Self(Self::CALL.0 | Self::RET.0 | Self::EXEC.0 | Self::BLOCK.0 | Self::COMPILE.0);

    pub const fn bits(self) -> u32 {
        self.0
    }

    pub const fn from_bits(bits: u32) -> Self {
        Self(bits)
    }

    pub const fn contains(self, event: StalkerEventKind) -> bool {
        self.0 & event.mask().0 != 0
    }

    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

impl Default for StalkerEventMask {
    fn default() -> Self {
        Self::CALL.union(Self::RET)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StalkerEvent {
    Call { location: u64, target: u64, depth: i32 },
    Ret { location: u64, target: u64, depth: i32 },
    Exec { location: u64 },
    Block { start: u64, end: u64 },
    Compile { start: u64, end: u64 },
}

impl StalkerEvent {
    pub const fn kind(&self) -> StalkerEventKind {
        match self {
            Self::Call { .. } => StalkerEventKind::Call,
            Self::Ret { .. } => StalkerEventKind::Ret,
            Self::Exec { .. } => StalkerEventKind::Exec,
            Self::Block { .. } => StalkerEventKind::Block,
            Self::Compile { .. } => StalkerEventKind::Compile,
        }
    }

    pub const fn address(&self) -> u64 {
        match self {
            Self::Call { location, .. } | Self::Ret { location, .. } | Self::Exec { location } => *location,
            Self::Block { start, .. } | Self::Compile { start, .. } => *start,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StalkerRange {
    pub start: u64,
    pub end: u64,
}

impl StalkerRange {
    pub fn new(start: u64, end: u64) -> Result<Self> {
        if start >= end {
            return Err(Error::InvalidArgument(format!(
                "stalker exclude range must be non-empty and ordered: 0x{start:x}..0x{end:x}"
            )));
        }
        Ok(Self { start, end })
    }

    pub const fn contains(self, address: u64) -> bool {
        address >= self.start && address < self.end
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StalkerConfig {
    pub event_mask: StalkerEventMask,
    pub queue_capacity: usize,
    pub trust_threshold: i32,
    pub exclude_ranges: Vec<StalkerRange>,
}

impl Default for StalkerConfig {
    fn default() -> Self {
        Self {
            event_mask: StalkerEventMask::default(),
            queue_capacity: DEFAULT_STALKER_QUEUE_CAPACITY,
            trust_threshold: 0,
            exclude_ranges: Vec::new(),
        }
    }
}

impl StalkerConfig {
    pub fn validate(&self) -> Result<()> {
        if self.queue_capacity == 0 || self.queue_capacity > MAX_STALKER_QUEUE_CAPACITY {
            return Err(Error::InvalidArgument(format!(
                "stalker queue capacity must be between 1 and {MAX_STALKER_QUEUE_CAPACITY}"
            )));
        }
        for range in &self.exclude_ranges {
            if range.start >= range.end {
                return Err(Error::InvalidArgument(
                    "stalker exclude range is empty or reversed".into(),
                ));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StalkerSessionState {
    Idle,
    Following,
    Deactivated,
}

#[derive(Debug, Clone)]
pub struct StalkerSession {
    config: StalkerConfig,
    state: StalkerSessionState,
    thread_id: Option<u64>,
    call_depth: i32,
    events: Vec<StalkerEvent>,
    dropped_events: u64,
}

impl StalkerSession {
    pub fn new(config: StalkerConfig) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            config,
            state: StalkerSessionState::Idle,
            thread_id: None,
            call_depth: 0,
            events: Vec::new(),
            dropped_events: 0,
        })
    }

    pub fn config(&self) -> &StalkerConfig {
        &self.config
    }

    pub const fn state(&self) -> StalkerSessionState {
        self.state
    }

    pub const fn thread_id(&self) -> Option<u64> {
        self.thread_id
    }

    pub const fn call_depth(&self) -> i32 {
        self.call_depth
    }

    pub const fn dropped_events(&self) -> u64 {
        self.dropped_events
    }

    pub fn events(&self) -> &[StalkerEvent] {
        &self.events
    }

    /// Build a bounded transform plan without modifying target memory.
    ///
    /// The tuple is intentionally made of plain values so the QuickJS bridge
    /// can consume this contract without exposing a second runtime ABI.  The
    /// plan is static-only: it describes kept instructions and the first
    /// terminator, but it does not install a transformer or follow a thread.
    pub fn transform_basic_block(
        start: u64,
        bytes: &[u8],
        max_instructions: usize,
    ) -> Result<(
        Vec<(u64, u32, &'static str, Option<u64>)>,
        u64,
        usize,
        usize,
        bool,
        bool,
        Option<&'static str>,
    )> {
        let transform = build_bounded_basic_block_transform(start, bytes, max_instructions)?;
        let instructions = transform
            .block
            .instructions
            .iter()
            .map(|instruction| {
                (
                    instruction.address,
                    instruction.word,
                    instruction.kind.as_str(),
                    instruction.direct_target,
                )
            })
            .collect();
        Ok((
            instructions,
            transform.block.end,
            transform.input_instruction_count,
            transform.block.instructions.len(),
            transform.limit_reached,
            transform.stopped_at_terminator,
            transform.block.terminator.map(Arm64InstructionKind::as_str),
        ))
    }

    /// Generate events from a transformed block and a caller-supplied
    /// execution trace.  The trace is validated against the transformed
    /// instruction addresses; no target thread is inspected or rewritten.
    pub fn generate_basic_block_events(
        start: u64,
        bytes: &[u8],
        max_instructions: usize,
        execution_steps: &[(u64, u64, i32)],
        event_mask: StalkerEventMask,
        max_events: usize,
    ) -> Result<(Vec<StalkerEvent>, usize, usize, bool)> {
        let transform = build_bounded_basic_block_transform(start, bytes, max_instructions)?;
        generate_events_for_transform(&transform, execution_steps, event_mask, max_events)
    }

    /// Feed the bounded event generator into this session's existing queue.
    /// The returned tuple is `(attempted, accepted, generator_dropped,
    /// queue_dropped, filtered, execution_observed)`.
    pub fn record_basic_block_execution(
        &mut self,
        start: u64,
        bytes: &[u8],
        max_instructions: usize,
        execution_steps: &[(u64, u64, i32)],
        max_events: usize,
    ) -> Result<(usize, usize, usize, usize, usize, bool)> {
        let (events, attempted, generator_dropped, execution_observed) = Self::generate_basic_block_events(
            start,
            bytes,
            max_instructions,
            execution_steps,
            self.config.event_mask,
            max_events,
        )?;
        let mut accepted = 0usize;
        let dropped_before = self.dropped_events;
        for event in events {
            if self.record(event) {
                accepted = accepted.saturating_add(1);
            }
        }
        let queue_dropped = (self.dropped_events - dropped_before) as usize;
        let filtered = attempted
            .saturating_sub(generator_dropped)
            .saturating_sub(accepted)
            .saturating_sub(queue_dropped);
        Ok((
            attempted,
            accepted,
            generator_dropped,
            queue_dropped,
            filtered,
            execution_observed,
        ))
    }

    pub fn follow(&mut self, thread_id: u64) -> Result<()> {
        if thread_id == 0 {
            return Err(Error::InvalidArgument("stalker thread id must be non-zero".into()));
        }
        if self.state != StalkerSessionState::Idle {
            return Err(Error::State(
                "stalker session must be idle before following a thread".into(),
            ));
        }
        self.thread_id = Some(thread_id);
        self.call_depth = 0;
        self.state = StalkerSessionState::Following;
        Ok(())
    }

    pub fn unfollow(&mut self, thread_id: u64) -> Result<()> {
        if self.thread_id != Some(thread_id) || self.state == StalkerSessionState::Idle {
            return Err(Error::State(format!(
                "stalker session is not following thread {thread_id}"
            )));
        }
        self.state = StalkerSessionState::Idle;
        self.thread_id = None;
        self.call_depth = 0;
        Ok(())
    }

    pub fn deactivate(&mut self) -> Result<()> {
        if self.state != StalkerSessionState::Following {
            return Err(Error::State("stalker session is not active".into()));
        }
        self.state = StalkerSessionState::Deactivated;
        Ok(())
    }

    pub fn activate(&mut self) -> Result<()> {
        if self.state != StalkerSessionState::Deactivated {
            return Err(Error::State("stalker session is not deactivated".into()));
        }
        self.state = StalkerSessionState::Following;
        Ok(())
    }

    /// Record an observed function entry from the function-level hook path.
    /// This is dynamic call/return telemetry and is deliberately separate from
    /// the static ARM64 decoder above.
    pub fn record_call(&mut self, location: u64, target: u64) -> bool {
        if self.state != StalkerSessionState::Following {
            return false;
        }
        let depth = self.call_depth;
        self.call_depth = self.call_depth.saturating_add(1);
        self.record(StalkerEvent::Call {
            location,
            target,
            depth,
        })
    }

    pub fn record_return(&mut self, location: u64, target: u64) -> bool {
        if self.state != StalkerSessionState::Following {
            return false;
        }
        self.call_depth = self.call_depth.saturating_sub(1).max(0);
        self.record(StalkerEvent::Ret {
            location,
            target,
            depth: self.call_depth,
        })
    }

    pub fn record(&mut self, event: StalkerEvent) -> bool {
        if self.state != StalkerSessionState::Following
            || !self.config.event_mask.contains(event.kind())
            || self
                .config
                .exclude_ranges
                .iter()
                .any(|range| range.contains(event.address()))
        {
            return false;
        }
        if self.events.len() >= self.config.queue_capacity {
            self.dropped_events = self.dropped_events.saturating_add(1);
            return false;
        }
        self.events.push(event);
        true
    }

    pub fn flush(&mut self) -> Vec<StalkerEvent> {
        std::mem::take(&mut self.events)
    }

    pub fn garbage_collect(&mut self) -> Result<bool> {
        if self.state != StalkerSessionState::Idle {
            return Err(Error::State(
                "stalker garbage collection requires an unfollowed session".into(),
            ));
        }
        self.events.clear();
        self.dropped_events = 0;
        self.call_depth = 0;
        Ok(true)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StalkerCapabilities {
    pub platform: &'static str,
    pub backend: &'static str,
    pub mode: &'static str,
    pub available: bool,
    pub instruction_level: bool,
    pub basic_block_events: bool,
    pub event_sink: bool,
    pub thread_follow: bool,
    pub target_function_hook: bool,
    pub call_return_hook: bool,
    pub exclude_ranges: bool,
    pub flush: bool,
    pub garbage_collect: bool,
    pub memory_access_events: bool,
    pub static_parse: bool,
    pub bounded_basic_block_transform: bool,
    pub event_generation: bool,
    pub event_generation_mode: &'static str,
    pub transform_mode: &'static str,
    pub target_thread_instrumentation: bool,
    pub target_thread_instruction_rewrite: bool,
    pub instrumented: bool,
    pub missing_operations: &'static [&'static str],
}

pub const IOS_STALKER_MISSING_OPERATIONS: &[&str] =
    &["Transformer", "Exec/Block/Compile events", "memory access events"];

pub const fn ios_stalker_capabilities() -> StalkerCapabilities {
    StalkerCapabilities {
        platform: "ios",
        backend: "apple-pthread-event-sink",
        mode: "thread-follow-event-sink",
        available: true,
        instruction_level: false,
        basic_block_events: false,
        event_sink: true,
        thread_follow: true,
        target_function_hook: true,
        call_return_hook: true,
        exclude_ranges: true,
        flush: true,
        garbage_collect: true,
        memory_access_events: false,
        static_parse: true,
        bounded_basic_block_transform: true,
        event_generation: true,
        event_generation_mode: STALKER_EVENT_GENERATION_MODE,
        transform_mode: STALKER_TRANSFORM_MODE,
        target_thread_instrumentation: false,
        target_thread_instruction_rewrite: false,
        instrumented: false,
        missing_operations: IOS_STALKER_MISSING_OPERATIONS,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arm64_decoder_classifies_direct_control_flow_and_targets() {
        let bl = decode_arm64_instruction(0x1000, 0x9400_0002).expect("BL");
        assert_eq!(bl.kind, Arm64InstructionKind::BranchLink);
        assert_eq!(bl.direct_target, Some(0x1008));

        let backward = decode_arm64_instruction(0x100c, 0x17ff_fffd).expect("B");
        assert_eq!(backward.kind, Arm64InstructionKind::Branch);
        assert_eq!(backward.direct_target, Some(0x1000));

        let ret = decode_arm64_instruction(0x1010, 0xd65f_03c0).expect("RET");
        assert_eq!(ret.kind, Arm64InstructionKind::Return);
        assert!(ret.direct_target.is_none());
    }

    #[test]
    fn arm64_decoder_stops_at_basic_block_terminator() {
        let bytes = [
            0x20, 0x00, 0x80, 0xd2, // mov x0, #1
            0x02, 0x00, 0x00, 0x94, // bl +0x8
            0xc0, 0x03, 0x5f, 0xd6, // ret
            0x00, 0x00, 0x80, 0xd2,
        ];
        let block = decode_arm64_basic_block(0x2000, &bytes, 16).expect("block");
        assert_eq!(block.start, 0x2000);
        assert_eq!(block.end, 0x200c);
        assert_eq!(block.instructions.len(), 3);
        assert_eq!(block.terminator, Some(Arm64InstructionKind::Return));
        assert_eq!(block.instructions[1].kind, Arm64InstructionKind::BranchLink);
    }

    #[test]
    fn arm64_decoder_rejects_unaligned_and_truncated_input() {
        assert!(decode_arm64_instruction(0x1002, 0xd503_201f).is_err());
        assert!(decode_arm64_basic_block(0x1000, &[0, 1, 2], 1).is_err());
        assert!(decode_arm64_basic_block(0x1000, &[0, 0, 0, 0], 0).is_err());
    }

    #[test]
    fn bounded_transform_reports_limit_and_terminator_without_instrumenting() {
        let bytes = [
            0x20, 0x00, 0x80, 0xd2, // mov x0, #1
            0x02, 0x00, 0x00, 0x94, // bl +0x8
            0xc0, 0x03, 0x5f, 0xd6, // ret
            0x00, 0x00, 0x80, 0xd2,
        ];
        let limited = StalkerSession::transform_basic_block(0x2000, &bytes, 2).expect("limited transform");
        assert_eq!(limited.0.len(), 2);
        assert_eq!(limited.1, 0x2008);
        assert_eq!(limited.2, 4);
        assert_eq!(limited.3, 2);
        assert!(limited.4);
        assert!(!limited.5);
        assert_eq!(limited.6, None);

        let complete = StalkerSession::transform_basic_block(0x2000, &bytes, 16).expect("complete transform");
        assert_eq!(complete.0.len(), 3);
        assert_eq!(complete.1, 0x200c);
        assert!(!complete.4);
        assert!(complete.5);
        assert_eq!(complete.6, Some("ret"));
    }

    #[test]
    fn bounded_event_generation_uses_supplied_execution_and_counts_drops() {
        let bytes = [
            0x20, 0x00, 0x80, 0xd2, // mov x0, #1
            0x02, 0x00, 0x00, 0x94, // bl +0x8
            0xc0, 0x03, 0x5f, 0xd6, // ret
        ];
        let steps = [(0x2000, 0, 0), (0x2004, 0, 0), (0x2008, 0x3000, 1)];
        let (events, attempted, dropped, observed) =
            StalkerSession::generate_basic_block_events(0x2000, &bytes, 16, &steps, StalkerEventMask::ALL, 4)
                .expect("event generation");
        assert!(observed);
        assert_eq!(attempted, 7); // compile + block + 3 exec + call + ret
        assert_eq!(events.len(), 4);
        assert_eq!(dropped, 3);
        assert_eq!(
            events[0],
            StalkerEvent::Compile {
                start: 0x2000,
                end: 0x200c
            }
        );
        assert_eq!(
            events[1],
            StalkerEvent::Block {
                start: 0x2000,
                end: 0x200c
            }
        );
        assert_eq!(events[2], StalkerEvent::Exec { location: 0x2000 });
        assert_eq!(events[3], StalkerEvent::Exec { location: 0x2004 });
    }

    #[test]
    fn generated_events_can_enter_existing_queue_without_claiming_target_instrumentation() {
        let bytes = [
            0x20, 0x00, 0x80, 0xd2, // mov x0, #1
            0xc0, 0x03, 0x5f, 0xd6, // ret
        ];
        let mut session = StalkerSession::new(StalkerConfig {
            event_mask: StalkerEventMask::EXEC.union(StalkerEventMask::BLOCK),
            queue_capacity: 1,
            ..StalkerConfig::default()
        })
        .expect("session");
        session.follow(123).expect("follow");
        let report = session
            .record_basic_block_execution(0x4000, &bytes, 16, &[(0x4000, 0, 0), (0x4004, 0, 0)], 16)
            .expect("record block");
        assert_eq!(report.0, 3); // block + two exec events
        assert_eq!(report.1, 1);
        assert_eq!(report.3, 2);
        assert!(report.5);
        assert!(!ios_stalker_capabilities().target_thread_instrumentation);
        assert!(!ios_stalker_capabilities().instrumented);
    }

    #[test]
    fn capability_report_distinguishes_hook_and_instruction_modes() {
        let capabilities = ios_stalker_capabilities();
        assert!(capabilities.available);
        assert!(capabilities.target_function_hook);
        assert!(capabilities.call_return_hook);
        assert!(!capabilities.instruction_level);
        assert!(!capabilities.basic_block_events);
        assert!(capabilities.static_parse);
        assert!(capabilities.bounded_basic_block_transform);
        assert!(capabilities.event_generation);
        assert_eq!(capabilities.transform_mode, "static-only");
        assert_eq!(capabilities.event_generation_mode, "caller-supplied-execution-trace");
        assert!(!capabilities.target_thread_instrumentation);
        assert!(!capabilities.target_thread_instruction_rewrite);
        assert!(!capabilities.instrumented);
        assert!(capabilities.missing_operations.contains(&"Transformer"));
    }

    #[test]
    fn event_kind_and_mask_match_gum_event_names() {
        let mask = StalkerEventMask::CALL.union(StalkerEventMask::BLOCK);
        assert!(mask.contains(StalkerEventKind::Call));
        assert!(mask.contains(StalkerEventKind::Block));
        assert!(!mask.contains(StalkerEventKind::Exec));
        assert_eq!(StalkerEventKind::Compile.as_str(), "compile");
    }

    #[test]
    fn session_filters_events_and_respects_excluded_ranges() {
        let config = StalkerConfig {
            event_mask: StalkerEventMask::CALL.union(StalkerEventMask::EXEC),
            exclude_ranges: vec![StalkerRange::new(0x2000, 0x3000).expect("range")],
            ..StalkerConfig::default()
        };
        let mut session = StalkerSession::new(config).expect("session");
        session.follow(42).expect("follow");
        assert!(session.record(StalkerEvent::Call {
            location: 0x1000,
            target: 0x1100,
            depth: 0,
        }));
        assert!(!session.record(StalkerEvent::Ret {
            location: 0x1000,
            target: 0x1100,
            depth: 0,
        }));
        assert!(!session.record(StalkerEvent::Exec { location: 0x2001 }));
        assert_eq!(session.events().len(), 1);
    }

    #[test]
    fn session_lifecycle_matches_follow_deactivate_activate_unfollow_gc() {
        let mut session = StalkerSession::new(StalkerConfig::default()).expect("session");
        assert_eq!(session.state(), StalkerSessionState::Idle);
        assert!(session.follow(7).is_ok());
        assert_eq!(session.state(), StalkerSessionState::Following);
        assert!(session.deactivate().is_ok());
        assert!(!session.record(StalkerEvent::Call {
            location: 1,
            target: 2,
            depth: 0,
        }));
        assert!(session.activate().is_ok());
        assert!(session.record(StalkerEvent::Call {
            location: 1,
            target: 2,
            depth: 0,
        }));
        assert!(session.unfollow(7).is_ok());
        assert!(session.garbage_collect().expect("gc"));
        assert!(session.events().is_empty());
    }

    #[test]
    fn session_queue_reports_drops_and_flushes_without_target_process() {
        let config = StalkerConfig {
            queue_capacity: 1,
            ..StalkerConfig::default()
        };
        let mut session = StalkerSession::new(config).expect("session");
        session.follow(9).expect("follow");
        assert!(session.record(StalkerEvent::Call {
            location: 1,
            target: 2,
            depth: 0,
        }));
        assert!(!session.record(StalkerEvent::Call {
            location: 3,
            target: 4,
            depth: 0,
        }));
        assert_eq!(session.dropped_events(), 1);
        assert_eq!(session.flush().len(), 1);
        assert!(session.events().is_empty());
    }

    #[test]
    fn session_collects_function_calls_with_stable_depth() {
        let mut session = StalkerSession::new(StalkerConfig {
            event_mask: StalkerEventMask::CALL.union(StalkerEventMask::RET),
            ..StalkerConfig::default()
        })
        .expect("session");
        session.follow(11).expect("follow");
        assert!(session.record_call(0x1000, 0x2000));
        assert_eq!(session.call_depth(), 1);
        assert!(session.record_call(0x2000, 0x3000));
        assert_eq!(session.call_depth(), 2);
        assert!(session.record_return(0x3000, 0x2000));
        assert_eq!(session.call_depth(), 1);
        assert_eq!(
            session.events()[0],
            StalkerEvent::Call {
                location: 0x1000,
                target: 0x2000,
                depth: 0
            }
        );
        assert_eq!(
            session.events()[2],
            StalkerEvent::Ret {
                location: 0x3000,
                target: 0x2000,
                depth: 1
            }
        );
    }

    #[test]
    fn invalid_config_and_thread_ids_have_stable_errors() {
        let invalid = StalkerConfig {
            queue_capacity: 0,
            ..StalkerConfig::default()
        };
        let err = StalkerSession::new(invalid).expect_err("invalid queue");
        assert!(err.to_string().contains("queue capacity"));
        let mut session = StalkerSession::new(StalkerConfig::default()).expect("session");
        let err = session.follow(0).expect_err("zero thread");
        assert!(err.to_string().contains("thread id"));
    }
}
