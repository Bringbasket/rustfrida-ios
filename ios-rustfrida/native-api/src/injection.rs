use common::{Error, Result};

const MAX_BOOTSTRAP_STRING_LEN: usize = 4096;
const DARWIN_AF_UNIX: u8 = 1;
const DARWIN_SOCK_STREAM: u32 = 1;
const DARWIN_SOCKADDR_UN_HEADER_LEN: usize = 2;
const DARWIN_SOCKADDR_UN_PATH_MAX: usize = 103;
const REMOTE_THREAD_STACK_SIZE: u64 = 0x4000;
const REMOTE_THREAD_STACK_ALIGNMENT: u64 = 16;
const RTLD_NOW: u32 = 2;
const ARM_THREAD_STATE64_FLAVOR: u32 = 6;

const BOOTSTRAP_STATUS_PENDING: u32 = 0;
const BOOTSTRAP_STATUS_DLOPEN_FAILED: u32 = 1;
const BOOTSTRAP_STATUS_DLSYM_FAILED: u32 = 2;
const BOOTSTRAP_STATUS_SOCKET_FAILED: u32 = 4;
const BOOTSTRAP_STATUS_CONNECT_FAILED: u32 = 5;
const BOOTSTRAP_STATUS_AGENT_RUNNING: u32 = 6;
const BOOTSTRAP_STATUS_ENTRY_RETURNED: u32 = 7;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootstrapStatus {
    Pending,
    DlopenFailed,
    DlsymFailed,
    SocketFailed,
    ConnectFailed,
    AgentRunning,
    EntryReturned,
    Unknown(u32),
}

impl BootstrapStatus {
    pub fn from_raw(raw: u32) -> Self {
        match raw {
            BOOTSTRAP_STATUS_PENDING => Self::Pending,
            BOOTSTRAP_STATUS_DLOPEN_FAILED => Self::DlopenFailed,
            BOOTSTRAP_STATUS_DLSYM_FAILED => Self::DlsymFailed,
            BOOTSTRAP_STATUS_SOCKET_FAILED => Self::SocketFailed,
            BOOTSTRAP_STATUS_CONNECT_FAILED => Self::ConnectFailed,
            BOOTSTRAP_STATUS_AGENT_RUNNING => Self::AgentRunning,
            BOOTSTRAP_STATUS_ENTRY_RETURNED => Self::EntryReturned,
            value => Self::Unknown(value),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::DlopenFailed => "dlopen-failed",
            Self::DlsymFailed => "dlsym-failed",
            Self::SocketFailed => "socket-failed",
            Self::ConnectFailed => "connect-failed",
            Self::AgentRunning => "agent-running",
            Self::EntryReturned => "entry-returned",
            Self::Unknown(_) => "unknown",
        }
    }

    pub fn is_failure(&self) -> bool {
        matches!(
            self,
            Self::DlopenFailed | Self::DlsymFailed | Self::SocketFailed | Self::ConnectFailed | Self::Unknown(_)
        )
    }

    pub fn diagnostic_hint(&self) -> Option<&'static str> {
        match self {
            Self::Pending => Some(
                "remote bootstrap never advanced past pending; check bootstrap wait timeout, remote thread startup, and whether the target blocked the injected thread before status writes",
            ),
            Self::DlopenFailed => Some(
                "dlopen failed inside the target; verify the dylib path exists in the target namespace, has compatible architecture/signing, and can be loaded under the target jailbreak environment",
            ),
            Self::DlsymFailed => Some(
                "dlsym failed after dlopen; verify the exported agent entry symbol name matches the built dylib and is not stripped",
            ),
            Self::SocketFailed => Some(
                "socket creation failed in the target; verify the target can use AF_UNIX sockets and that sandbox/platform restrictions are not blocking local socket creation",
            ),
            Self::ConnectFailed => Some(
                "connect failed from the target back to the controller socket; verify the socket path length, filesystem visibility, permissions, and that the controller is already listening",
            ),
            Self::AgentRunning => None,
            Self::EntryReturned => Some(
                "agent entry returned before controller handshake; inspect the agent initialization path and early runtime/bootstrap failures",
            ),
            Self::Unknown(_) => Some(
                "remote bootstrap reported an unknown status value; inspect the remote status block and confirm bootstrap code/data layout matches the built agent",
            ),
        }
    }
}

const ARM64_MOV_X19_X0: u32 = 0xAA00_03F3;
const ARM64_LDR_X8_ARGS_DLOPEN: u32 = 0xF940_0268;
const ARM64_LDR_W9_DYLIB_OFFSET: u32 = 0xB940_2269;
const ARM64_ADD_X0_X19_X9: u32 = 0x8B09_0260;
const ARM64_LDR_W1_RTLD_MODE: u32 = 0xB940_2E61;
const ARM64_BLR_X8: u32 = 0xD63F_0100;
const ARM64_CBZ_X0_DLOPEN_FAIL: u32 = 0xB400_0460;
const ARM64_MOV_X20_X0: u32 = 0xAA00_03F4;
const ARM64_STR_X0_DYLIB_HANDLE: u32 = 0xF900_2260;
const ARM64_LDR_X8_ARGS_DLSYM: u32 = 0xF940_0668;
const ARM64_LDR_W9_ENTRY_OFFSET: u32 = 0xB940_2669;
const ARM64_ADD_X1_X19_X9: u32 = 0x8B09_0261;
const ARM64_MOV_X0_X20: u32 = 0xAA14_03E0;
const ARM64_CBZ_X0_DLSYM_FAIL: u32 = 0xB400_03C0;
const ARM64_MOV_X21_X0: u32 = 0xAA00_03F5;
const ARM64_STR_X0_ENTRY_ADDRESS: u32 = 0xF900_2660;
const ARM64_LDR_X8_ARGS_SOCKET: u32 = 0xF940_0A68;
const ARM64_LDR_W0_SOCKET_DOMAIN: u32 = 0xB940_3260;
const ARM64_LDR_W1_SOCKET_TYPE: u32 = 0xB940_3661;
const ARM64_MOV_X2_XZR: u32 = 0xAA1F_03E2;
const ARM64_CMP_W0_ZERO: u32 = 0x7100_001F;
const ARM64_BLT_SOCKET_FAIL: u32 = 0x5400_030B;
const ARM64_STR_W0_SOCKET_FD: u32 = 0xB900_5260;
const ARM64_LDR_X8_ARGS_CONNECT: u32 = 0xF940_0E68;
const ARM64_LDR_W9_SOCKADDR_OFFSET: u32 = 0xB940_2A69;
const ARM64_LDR_W2_SOCKADDR_LEN: u32 = 0xB940_3A62;
const ARM64_CBNZ_W0_CONNECT_FAIL: u32 = 0x3500_0240;
const ARM64_MOV_W0_STATUS_AGENT_RUNNING: u32 = arm64_movz_w0(BOOTSTRAP_STATUS_AGENT_RUNNING);
const ARM64_STR_W0_STATUS: u32 = 0xB900_3E60;
const ARM64_BLR_X21: u32 = 0xD63F_02A0;
const ARM64_STR_W0_ENTRY_RETURN: u32 = 0xB900_5660;
const ARM64_MOV_W0_STATUS_ENTRY_RETURNED: u32 = arm64_movz_w0(BOOTSTRAP_STATUS_ENTRY_RETURNED);
const ARM64_RET: u32 = 0xD65F_03C0;
const ARM64_MOV_W0_STATUS_DLOPEN_FAILED: u32 = arm64_movz_w0(BOOTSTRAP_STATUS_DLOPEN_FAILED);
const ARM64_MOV_W0_STATUS_DLSYM_FAILED: u32 = arm64_movz_w0(BOOTSTRAP_STATUS_DLSYM_FAILED);
const ARM64_MOV_W0_STATUS_SOCKET_FAILED: u32 = arm64_movz_w0(BOOTSTRAP_STATUS_SOCKET_FAILED);
const ARM64_MOV_W0_STATUS_CONNECT_FAILED: u32 = arm64_movz_w0(BOOTSTRAP_STATUS_CONNECT_FAILED);

const BOOTSTRAP_ARGS_SIZE: u32 = 88;
const BOOTSTRAP_ARGS_DLOPEN_PTR_OFFSET: u32 = 0;
const BOOTSTRAP_ARGS_DLSYM_PTR_OFFSET: u32 = 8;
const BOOTSTRAP_ARGS_SOCKET_PTR_OFFSET: u32 = 16;
const BOOTSTRAP_ARGS_CONNECT_PTR_OFFSET: u32 = 24;
const BOOTSTRAP_ARGS_DYLIB_PATH_REL_OFFSET: u32 = 32;
const BOOTSTRAP_ARGS_ENTRY_SYMBOL_REL_OFFSET: u32 = 36;
const BOOTSTRAP_ARGS_SOCKADDR_REL_OFFSET: u32 = 40;
const BOOTSTRAP_ARGS_RTLD_MODE_OFFSET: u32 = 44;
const BOOTSTRAP_ARGS_SOCKET_DOMAIN_OFFSET: u32 = 48;
const BOOTSTRAP_ARGS_SOCKET_TYPE_OFFSET: u32 = 52;
const BOOTSTRAP_ARGS_SOCKADDR_LEN_OFFSET: u32 = 56;
const BOOTSTRAP_ARGS_STATUS_OFFSET: u32 = 60;
const BOOTSTRAP_ARGS_DYLIB_HANDLE_OFFSET: u32 = 64;
const BOOTSTRAP_ARGS_ENTRY_ADDRESS_OFFSET: u32 = 72;
const BOOTSTRAP_ARGS_SOCKET_FD_OFFSET: u32 = 80;
const BOOTSTRAP_ARGS_ENTRY_RETURN_OFFSET: u32 = 84;

const ARM64_BOOTSTRAP_CODE: [u32; 53] = [
    ARM64_MOV_X19_X0,
    ARM64_LDR_X8_ARGS_DLOPEN,
    ARM64_LDR_W9_DYLIB_OFFSET,
    ARM64_ADD_X0_X19_X9,
    ARM64_LDR_W1_RTLD_MODE,
    ARM64_BLR_X8,
    ARM64_CBZ_X0_DLOPEN_FAIL,
    ARM64_MOV_X20_X0,
    ARM64_STR_X0_DYLIB_HANDLE,
    ARM64_LDR_X8_ARGS_DLSYM,
    ARM64_LDR_W9_ENTRY_OFFSET,
    ARM64_ADD_X1_X19_X9,
    ARM64_MOV_X0_X20,
    ARM64_BLR_X8,
    ARM64_CBZ_X0_DLSYM_FAIL,
    ARM64_MOV_X21_X0,
    ARM64_STR_X0_ENTRY_ADDRESS,
    ARM64_LDR_X8_ARGS_SOCKET,
    ARM64_LDR_W0_SOCKET_DOMAIN,
    ARM64_LDR_W1_SOCKET_TYPE,
    ARM64_MOV_X2_XZR,
    ARM64_BLR_X8,
    ARM64_CMP_W0_ZERO,
    ARM64_BLT_SOCKET_FAIL,
    ARM64_MOV_X20_X0,
    ARM64_STR_W0_SOCKET_FD,
    ARM64_LDR_X8_ARGS_CONNECT,
    ARM64_MOV_X0_X20,
    ARM64_LDR_W9_SOCKADDR_OFFSET,
    ARM64_ADD_X1_X19_X9,
    ARM64_LDR_W2_SOCKADDR_LEN,
    ARM64_BLR_X8,
    ARM64_CBNZ_W0_CONNECT_FAIL,
    ARM64_MOV_W0_STATUS_AGENT_RUNNING,
    ARM64_STR_W0_STATUS,
    ARM64_MOV_X0_X20,
    ARM64_BLR_X21,
    ARM64_STR_W0_ENTRY_RETURN,
    ARM64_MOV_W0_STATUS_ENTRY_RETURNED,
    ARM64_STR_W0_STATUS,
    ARM64_RET,
    ARM64_MOV_W0_STATUS_DLOPEN_FAILED,
    ARM64_STR_W0_STATUS,
    ARM64_RET,
    ARM64_MOV_W0_STATUS_DLSYM_FAILED,
    ARM64_STR_W0_STATUS,
    ARM64_RET,
    ARM64_MOV_W0_STATUS_SOCKET_FAILED,
    ARM64_STR_W0_STATUS,
    ARM64_RET,
    ARM64_MOV_W0_STATUS_CONNECT_FAILED,
    ARM64_STR_W0_STATUS,
    ARM64_RET,
];

const fn arm64_movz_w0(imm16: u32) -> u32 {
    0x5280_0000 | ((imm16 & 0xffff) << 5)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InjectionTarget {
    pub pid: i32,
    pub dylib_path: String,
    pub entry_symbol: String,
    pub socket_path: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InjectionStage {
    AcquireTaskPort,
    AllocateRemoteMemory,
    WriteBootstrapImage,
    ResolveLoaderSymbols,
    ProtectRemoteMemory,
    StartRemoteThread,
}

impl InjectionStage {
    pub fn as_str(&self) -> &'static str {
        match self {
            InjectionStage::AcquireTaskPort => "acquire-task-port",
            InjectionStage::AllocateRemoteMemory => "allocate-remote-memory",
            InjectionStage::WriteBootstrapImage => "write-bootstrap-image",
            InjectionStage::ResolveLoaderSymbols => "resolve-loader-symbols",
            InjectionStage::ProtectRemoteMemory => "protect-remote-memory",
            InjectionStage::StartRemoteThread => "start-remote-thread",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InjectionStep {
    pub stage: InjectionStage,
    pub detail: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoaderSymbolRole {
    Dlopen,
    Dlsym,
    Socket,
    Connect,
    ThreadBootstrap,
}

impl LoaderSymbolRole {
    pub fn as_str(&self) -> &'static str {
        match self {
            LoaderSymbolRole::Dlopen => "dlopen",
            LoaderSymbolRole::Dlsym => "dlsym",
            LoaderSymbolRole::Socket => "socket",
            LoaderSymbolRole::Connect => "connect",
            LoaderSymbolRole::ThreadBootstrap => "thread-bootstrap",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedLoaderSymbol {
    pub role: LoaderSymbolRole,
    pub symbol_name: String,
    pub module_name: String,
    pub module_base: usize,
    pub raw_address: usize,
    pub address: usize,
    pub offset: usize,
}

impl ResolvedLoaderSymbol {
    pub fn is_canonicalized(&self) -> bool {
        self.raw_address != self.address
    }

    pub fn thread_bootstrap_kind(&self) -> Option<ThreadBootstrapKind> {
        if self.role != LoaderSymbolRole::ThreadBootstrap {
            return None;
        }
        Some(ThreadBootstrapKind::from_symbol_name(&self.symbol_name))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreadBootstrapKind {
    PthreadCreateFromMachThread,
    PthreadCreateFallback,
    Other,
}

impl ThreadBootstrapKind {
    pub fn from_symbol_name(symbol_name: &str) -> Self {
        match symbol_name {
            "pthread_create_from_mach_thread" => Self::PthreadCreateFromMachThread,
            "pthread_create" => Self::PthreadCreateFallback,
            _ => Self::Other,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::PthreadCreateFromMachThread => "pthread-create-from-mach-thread",
            Self::PthreadCreateFallback => "pthread-create-fallback",
            Self::Other => "other",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Arm64ThreadLaunch {
    pub pc: u64,
    pub sp: u64,
    pub lr: u64,
    pub x0: u64,
    pub x1: u64,
    pub x2: u64,
    pub x3: u64,
    pub stack_address: u64,
    pub stack_size: u64,
    pub bootstrap_address: u64,
    pub argument_address: u64,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Arm64ThreadState {
    pub x: [u64; 29],
    pub fp: u64,
    pub lr: u64,
    pub sp: u64,
    pub pc: u64,
    pub cpsr: u32,
    pub pad: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ThreadCreatePlan {
    pub flavor: u32,
    pub count: u32,
    pub state: Arm64ThreadState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BootstrapResultReport {
    pub status: BootstrapStatus,
    pub status_raw: u32,
    pub dylib_handle: u64,
    pub entry_address: u64,
    pub socket_fd: i32,
    pub entry_return: i32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemoteProtectionOutcome {
    SetMaximumAndCurrent,
    CurrentOnlyFallback,
}

impl RemoteProtectionOutcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SetMaximumAndCurrent => "set-maximum+current",
            Self::CurrentOnlyFallback => "current-only-fallback",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemoteThreadTerminationOutcome {
    NotAttempted,
    Terminated,
    Failed,
}

impl RemoteThreadTerminationOutcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NotAttempted => "not-attempted",
            Self::Terminated => "terminated",
            Self::Failed => "failed",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InjectionTrace {
    pub payload_address: u64,
    pub payload_size: usize,
    pub payload_allocated_size: usize,
    pub data_address: u64,
    pub data_size: usize,
    pub data_allocated_size: usize,
    pub stack_address: u64,
    pub stack_size: usize,
    pub target_uses_arm64e: Option<bool>,
    pub code_protection: RemoteProtectionOutcome,
    pub data_protection: RemoteProtectionOutcome,
    pub thread_bootstrap_kind: ThreadBootstrapKind,
    pub thread_bootstrap_label: String,
    pub thread_plan: ThreadCreatePlan,
    pub thread_port: Option<u32>,
    pub thread_termination: RemoteThreadTerminationOutcome,
    pub thread_port_deallocated: bool,
    pub resources_persist: bool,
    pub bootstrap_report: Option<BootstrapResultReport>,
    pub bootstrap_timed_out: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootstrapImage {
    pub(crate) bytes: Vec<u8>,
    pub(crate) dylib_path_offset: u32,
    pub(crate) dylib_path_len: u32,
    pub(crate) entry_symbol_offset: u32,
    pub(crate) entry_symbol_len: u32,
    pub(crate) sockaddr_offset: u32,
    pub(crate) sockaddr_len: u32,
    pub(crate) routine_offset: u32,
    pub(crate) args_offset: u32,
    pub(crate) dlopen_ptr_offset: u32,
    pub(crate) dlsym_ptr_offset: u32,
    pub(crate) socket_ptr_offset: u32,
    pub(crate) connect_ptr_offset: u32,
    pub(crate) status_offset: u32,
    pub(crate) dylib_handle_offset: u32,
    pub(crate) entry_address_result_offset: u32,
    pub(crate) socket_fd_offset: u32,
    pub(crate) entry_return_offset: u32,
    pub(crate) stack_size: u64,
    pub(crate) stack_alignment: u64,
}

impl BootstrapImage {
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    pub fn dylib_path_offset(&self) -> u32 {
        self.dylib_path_offset
    }

    pub fn entry_symbol_offset(&self) -> u32 {
        self.entry_symbol_offset
    }

    pub fn sockaddr_offset(&self) -> u32 {
        self.sockaddr_offset
    }

    pub fn sockaddr_len(&self) -> u32 {
        self.sockaddr_len
    }

    pub fn routine_offset(&self) -> u32 {
        self.routine_offset
    }

    pub fn args_offset(&self) -> u32 {
        self.args_offset
    }

    pub fn code_bytes(&self) -> &[u8] {
        &self.bytes[..self.args_offset as usize]
    }

    pub fn data_bytes(&self) -> &[u8] {
        &self.bytes[self.args_offset as usize..]
    }

    pub fn code_size(&self) -> usize {
        self.args_offset as usize
    }

    pub fn data_size(&self) -> usize {
        self.bytes.len() - self.args_offset as usize
    }

    pub fn data_relative_offset(&self, absolute_offset: u32) -> u64 {
        debug_assert!(absolute_offset >= self.args_offset);
        (absolute_offset - self.args_offset) as u64
    }

    pub fn stack_size(&self) -> u64 {
        self.stack_size
    }

    pub fn stack_alignment(&self) -> u64 {
        self.stack_alignment
    }

    pub fn thread_launch(
        &self,
        remote_routine_address: u64,
        remote_argument_address: u64,
        remote_stack_address: u64,
        thread_entry_pc: u64,
    ) -> Arm64ThreadLaunch {
        let stack_top = remote_stack_address + self.stack_size;
        Arm64ThreadLaunch {
            pc: thread_entry_pc,
            sp: align_down(stack_top, self.stack_alignment),
            lr: 0,
            x0: 0,
            x1: 0,
            x2: remote_routine_address + self.routine_offset as u64,
            x3: remote_argument_address,
            stack_address: remote_stack_address,
            stack_size: self.stack_size,
            bootstrap_address: remote_routine_address,
            argument_address: remote_argument_address,
        }
    }
}

impl Arm64ThreadLaunch {
    pub fn thread_state(&self) -> ThreadCreatePlan {
        let mut x = [0u64; 29];
        x[0] = self.x0;
        x[1] = self.x1;
        x[2] = self.x2;
        x[3] = self.x3;

        ThreadCreatePlan {
            flavor: ARM_THREAD_STATE64_FLAVOR,
            count: (std::mem::size_of::<Arm64ThreadState>() / std::mem::size_of::<u32>()) as u32,
            state: Arm64ThreadState {
                x,
                fp: 0,
                lr: self.lr,
                sp: self.sp,
                pc: self.pc,
                cpsr: 0,
                pad: 0,
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InjectionPlan {
    pub target: InjectionTarget,
    bootstrap: BootstrapImage,
    steps: Vec<InjectionStep>,
    loader_symbols: Vec<ResolvedLoaderSymbol>,
}

impl InjectionPlan {
    pub fn bootstrap(&self) -> &BootstrapImage {
        &self.bootstrap
    }

    pub fn steps(&self) -> &[InjectionStep] {
        &self.steps
    }

    pub fn loader_symbols(&self) -> &[ResolvedLoaderSymbol] {
        &self.loader_symbols
    }

    pub fn stage_names(&self) -> Vec<&'static str> {
        self.steps.iter().map(|step| step.stage.as_str()).collect()
    }

    pub(crate) fn with_loader_symbols(mut self, loader_symbols: Vec<ResolvedLoaderSymbol>) -> Result<Self> {
        bind_loader_symbols(&mut self.bootstrap, &loader_symbols)?;
        self.loader_symbols = loader_symbols;
        Ok(self)
    }
}

#[derive(Debug, Default, Clone)]
pub struct MachInjector;

pub(crate) fn build_injection_plan(target: &InjectionTarget) -> Result<InjectionPlan> {
    if target.pid <= 0 {
        return Err(Error::InvalidArgument("target pid must be greater than zero".into()));
    }

    let bootstrap = build_bootstrap_image(target)?;
    let steps = vec![
        InjectionStep {
            stage: InjectionStage::AcquireTaskPort,
            detail: format!("acquire Mach task port for pid {}", target.pid),
        },
        InjectionStep {
            stage: InjectionStage::AllocateRemoteMemory,
            detail: format!(
                "allocate {} bytes for bootstrap payload and 0x{:x} bytes for the remote thread stack",
                bootstrap.len(),
                bootstrap.stack_size()
            ),
        },
        InjectionStep {
            stage: InjectionStage::WriteBootstrapImage,
            detail: format!(
                "write ARM64 bootstrap stub plus argument block for '{}', '{}' and controller socket '{}'",
                target.dylib_path, target.entry_symbol, target.socket_path
            ),
        },
        InjectionStep {
            stage: InjectionStage::ResolveLoaderSymbols,
            detail: "resolve dlopen/dlsym and thread bootstrap symbols inside the target task".into(),
        },
        InjectionStep {
            stage: InjectionStage::ProtectRemoteMemory,
            detail: "set remote bootstrap payload protection to RWX so the injected ARM64 stub can execute and still update status fields".into(),
        },
        InjectionStep {
            stage: InjectionStage::StartRemoteThread,
            detail: format!(
                "start remote bootstrap thread that loads {} and connects back to {}",
                target.dylib_path, target.socket_path
            ),
        },
    ];

    Ok(InjectionPlan {
        target: target.clone(),
        bootstrap,
        steps,
        loader_symbols: Vec::new(),
    })
}

fn build_bootstrap_image(target: &InjectionTarget) -> Result<BootstrapImage> {
    validate_bootstrap_string("dylib path", &target.dylib_path)?;
    validate_bootstrap_string("entry symbol", &target.entry_symbol)?;
    validate_socket_path(&target.socket_path)?;
    let sockaddr = build_darwin_sockaddr_un(&target.socket_path)?;

    let mut bytes = encode_arm64_bootstrap_code();
    align_bytes(&mut bytes, 8);

    let args_offset = bytes.len() as u32;
    bytes.resize((args_offset + BOOTSTRAP_ARGS_SIZE) as usize, 0);

    let dylib_path_offset = bytes.len() as u32;
    bytes.extend_from_slice(target.dylib_path.as_bytes());
    bytes.push(0);

    let entry_symbol_offset = bytes.len() as u32;
    bytes.extend_from_slice(target.entry_symbol.as_bytes());
    bytes.push(0);

    let sockaddr_offset = bytes.len() as u32;
    bytes.extend_from_slice(&sockaddr);

    let dylib_path_rel = dylib_path_offset - args_offset;
    let entry_symbol_rel = entry_symbol_offset - args_offset;
    let sockaddr_rel = sockaddr_offset - args_offset;

    patch_u32(
        &mut bytes,
        (args_offset + BOOTSTRAP_ARGS_DYLIB_PATH_REL_OFFSET) as usize,
        dylib_path_rel,
    );
    patch_u32(
        &mut bytes,
        (args_offset + BOOTSTRAP_ARGS_ENTRY_SYMBOL_REL_OFFSET) as usize,
        entry_symbol_rel,
    );
    patch_u32(
        &mut bytes,
        (args_offset + BOOTSTRAP_ARGS_SOCKADDR_REL_OFFSET) as usize,
        sockaddr_rel,
    );
    patch_u32(
        &mut bytes,
        (args_offset + BOOTSTRAP_ARGS_RTLD_MODE_OFFSET) as usize,
        RTLD_NOW,
    );
    patch_u32(
        &mut bytes,
        (args_offset + BOOTSTRAP_ARGS_SOCKET_DOMAIN_OFFSET) as usize,
        DARWIN_AF_UNIX as u32,
    );
    patch_u32(
        &mut bytes,
        (args_offset + BOOTSTRAP_ARGS_SOCKET_TYPE_OFFSET) as usize,
        DARWIN_SOCK_STREAM,
    );
    patch_u32(
        &mut bytes,
        (args_offset + BOOTSTRAP_ARGS_SOCKADDR_LEN_OFFSET) as usize,
        sockaddr.len() as u32,
    );
    patch_u32(
        &mut bytes,
        (args_offset + BOOTSTRAP_ARGS_STATUS_OFFSET) as usize,
        BOOTSTRAP_STATUS_PENDING,
    );
    patch_i32(&mut bytes, (args_offset + BOOTSTRAP_ARGS_SOCKET_FD_OFFSET) as usize, -1);
    patch_i32(
        &mut bytes,
        (args_offset + BOOTSTRAP_ARGS_ENTRY_RETURN_OFFSET) as usize,
        -1,
    );

    Ok(BootstrapImage {
        bytes,
        dylib_path_offset,
        dylib_path_len: target.dylib_path.len() as u32,
        entry_symbol_offset,
        entry_symbol_len: target.entry_symbol.len() as u32,
        sockaddr_offset,
        sockaddr_len: sockaddr.len() as u32,
        routine_offset: 0,
        args_offset,
        dlopen_ptr_offset: args_offset + BOOTSTRAP_ARGS_DLOPEN_PTR_OFFSET,
        dlsym_ptr_offset: args_offset + BOOTSTRAP_ARGS_DLSYM_PTR_OFFSET,
        socket_ptr_offset: args_offset + BOOTSTRAP_ARGS_SOCKET_PTR_OFFSET,
        connect_ptr_offset: args_offset + BOOTSTRAP_ARGS_CONNECT_PTR_OFFSET,
        status_offset: args_offset + BOOTSTRAP_ARGS_STATUS_OFFSET,
        dylib_handle_offset: args_offset + BOOTSTRAP_ARGS_DYLIB_HANDLE_OFFSET,
        entry_address_result_offset: args_offset + BOOTSTRAP_ARGS_ENTRY_ADDRESS_OFFSET,
        socket_fd_offset: args_offset + BOOTSTRAP_ARGS_SOCKET_FD_OFFSET,
        entry_return_offset: args_offset + BOOTSTRAP_ARGS_ENTRY_RETURN_OFFSET,
        stack_size: REMOTE_THREAD_STACK_SIZE,
        stack_alignment: REMOTE_THREAD_STACK_ALIGNMENT,
    })
}

fn bind_loader_symbols(bootstrap: &mut BootstrapImage, loader_symbols: &[ResolvedLoaderSymbol]) -> Result<()> {
    let dlopen = require_loader_symbol(loader_symbols, LoaderSymbolRole::Dlopen)?;
    let dlsym = require_loader_symbol(loader_symbols, LoaderSymbolRole::Dlsym)?;
    let socket = require_loader_symbol(loader_symbols, LoaderSymbolRole::Socket)?;
    let connect = require_loader_symbol(loader_symbols, LoaderSymbolRole::Connect)?;
    let _thread_entry = require_loader_symbol(loader_symbols, LoaderSymbolRole::ThreadBootstrap)?;

    patch_u64(
        &mut bootstrap.bytes,
        bootstrap.dlopen_ptr_offset as usize,
        dlopen.address as u64,
    );
    patch_u64(
        &mut bootstrap.bytes,
        bootstrap.dlsym_ptr_offset as usize,
        dlsym.address as u64,
    );
    patch_u64(
        &mut bootstrap.bytes,
        bootstrap.socket_ptr_offset as usize,
        socket.address as u64,
    );
    patch_u64(
        &mut bootstrap.bytes,
        bootstrap.connect_ptr_offset as usize,
        connect.address as u64,
    );
    Ok(())
}

fn require_loader_symbol(
    loader_symbols: &[ResolvedLoaderSymbol],
    role: LoaderSymbolRole,
) -> Result<&ResolvedLoaderSymbol> {
    loader_symbols
        .iter()
        .find(|symbol| symbol.role == role)
        .ok_or_else(|| Error::State(format!("missing loader symbol for {}", role.as_str())))
}

fn validate_bootstrap_string(label: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        return Err(Error::InvalidArgument(format!("{label} must not be empty")));
    }
    if value.len() > MAX_BOOTSTRAP_STRING_LEN {
        return Err(Error::InvalidArgument(format!(
            "{label} exceeds {MAX_BOOTSTRAP_STRING_LEN} bytes"
        )));
    }
    if value.as_bytes().contains(&0) {
        return Err(Error::InvalidArgument(format!("{label} contains an interior NUL byte")));
    }
    Ok(())
}

fn validate_socket_path(value: &str) -> Result<()> {
    validate_bootstrap_string("socket path", value)?;
    if value.len() > DARWIN_SOCKADDR_UN_PATH_MAX {
        return Err(Error::InvalidArgument(format!(
            "socket path exceeds Darwin sockaddr_un limit ({})",
            DARWIN_SOCKADDR_UN_PATH_MAX
        )));
    }
    Ok(())
}

fn build_darwin_sockaddr_un(path: &str) -> Result<Vec<u8>> {
    validate_socket_path(path)?;

    let path_bytes = path.as_bytes();
    let sockaddr_len = DARWIN_SOCKADDR_UN_HEADER_LEN + path_bytes.len() + 1;
    let mut sockaddr = vec![0u8; sockaddr_len];
    sockaddr[0] = sockaddr_len as u8;
    sockaddr[1] = DARWIN_AF_UNIX;
    sockaddr[DARWIN_SOCKADDR_UN_HEADER_LEN..DARWIN_SOCKADDR_UN_HEADER_LEN + path_bytes.len()]
        .copy_from_slice(path_bytes);

    Ok(sockaddr)
}

fn encode_arm64_bootstrap_code() -> Vec<u8> {
    let mut bytes = Vec::with_capacity(ARM64_BOOTSTRAP_CODE.len() * 4);
    for word in ARM64_BOOTSTRAP_CODE {
        bytes.extend_from_slice(&word.to_le_bytes());
    }
    bytes
}

fn align_bytes(bytes: &mut Vec<u8>, alignment: usize) {
    let padding = (alignment - (bytes.len() % alignment)) % alignment;
    bytes.resize(bytes.len() + padding, 0);
}

fn patch_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn patch_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn patch_i32(bytes: &mut [u8], offset: usize, value: i32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn align_down(value: u64, alignment: u64) -> u64 {
    debug_assert!(alignment.is_power_of_two());
    value & !(alignment - 1)
}

#[cfg(test)]
mod tests {
    use common::DEFAULT_AGENT_PATH;

    use super::{
        align_down, build_injection_plan, Arm64ThreadLaunch, BootstrapStatus, InjectionStage, InjectionTarget,
        LoaderSymbolRole, ResolvedLoaderSymbol, ARM64_BOOTSTRAP_CODE, ARM_THREAD_STATE64_FLAVOR,
        BOOTSTRAP_ARGS_CONNECT_PTR_OFFSET, BOOTSTRAP_ARGS_DLOPEN_PTR_OFFSET, BOOTSTRAP_ARGS_DLSYM_PTR_OFFSET,
        BOOTSTRAP_ARGS_RTLD_MODE_OFFSET, BOOTSTRAP_ARGS_SOCKET_DOMAIN_OFFSET, BOOTSTRAP_ARGS_SOCKET_PTR_OFFSET,
        BOOTSTRAP_ARGS_SOCKET_TYPE_OFFSET, BOOTSTRAP_ARGS_STATUS_OFFSET, BOOTSTRAP_STATUS_PENDING, DARWIN_AF_UNIX,
        DARWIN_SOCKADDR_UN_HEADER_LEN, DARWIN_SOCK_STREAM, REMOTE_THREAD_STACK_ALIGNMENT,
    };

    fn read_u32(bytes: &[u8], offset: usize) -> u32 {
        u32::from_le_bytes(bytes[offset..offset + 4].try_into().expect("u32 bytes"))
    }

    fn read_u64(bytes: &[u8], offset: usize) -> u64 {
        u64::from_le_bytes(bytes[offset..offset + 8].try_into().expect("u64 bytes"))
    }

    fn test_target() -> InjectionTarget {
        InjectionTarget {
            pid: 123,
            dylib_path: DEFAULT_AGENT_PATH.into(),
            entry_symbol: "ios_agent_entry".into(),
            socket_path: "/tmp/ios-rustfrida.sock".into(),
        }
    }

    fn fake_loader_symbols() -> Vec<ResolvedLoaderSymbol> {
        vec![
            ResolvedLoaderSymbol {
                role: LoaderSymbolRole::Dlopen,
                symbol_name: "dlopen".into(),
                module_name: "/usr/lib/libdyld.dylib".into(),
                module_base: 0x1800_0000_0,
                raw_address: 0xabcd_0001_8000_1234,
                address: 0x1800_0123_4,
                offset: 0x1234,
            },
            ResolvedLoaderSymbol {
                role: LoaderSymbolRole::Dlsym,
                symbol_name: "dlsym".into(),
                module_name: "/usr/lib/libdyld.dylib".into(),
                module_base: 0x1800_0000_0,
                raw_address: 0xabcd_0001_8000_5678,
                address: 0x1800_0567_8,
                offset: 0x5678,
            },
            ResolvedLoaderSymbol {
                role: LoaderSymbolRole::Socket,
                symbol_name: "socket".into(),
                module_name: "/usr/lib/system/libsystem_kernel.dylib".into(),
                module_base: 0x1802_0000_0,
                raw_address: 0x1802_0222_0,
                address: 0x1802_0222_0,
                offset: 0x2220,
            },
            ResolvedLoaderSymbol {
                role: LoaderSymbolRole::Connect,
                symbol_name: "connect".into(),
                module_name: "/usr/lib/system/libsystem_kernel.dylib".into(),
                module_base: 0x1802_0000_0,
                raw_address: 0x1802_0333_0,
                address: 0x1802_0333_0,
                offset: 0x3330,
            },
            ResolvedLoaderSymbol {
                role: LoaderSymbolRole::ThreadBootstrap,
                symbol_name: "pthread_create_from_mach_thread".into(),
                module_name: "/usr/lib/system/libsystem_pthread.dylib".into(),
                module_base: 0x1801_0000_0,
                raw_address: 0x1801_0abc_0,
                address: 0x1801_0abc_0,
                offset: 0xabc0,
            },
        ]
    }

    #[test]
    fn builds_bootstrap_image_with_code_args_and_strings() {
        let target = test_target();
        let plan = build_injection_plan(&target).expect("build plan");
        let bootstrap = plan.bootstrap();
        assert!(!bootstrap.is_empty());
        assert_eq!(bootstrap.routine_offset(), 0);
        assert!(bootstrap.args_offset() as usize >= ARM64_BOOTSTRAP_CODE.len() * 4);
        assert_eq!(bootstrap.args_offset() as u64 % 8, 0);
        assert_eq!(bootstrap.stack_alignment(), REMOTE_THREAD_STACK_ALIGNMENT);

        let bytes = bootstrap.bytes();
        assert_eq!(read_u32(bytes, 0), ARM64_BOOTSTRAP_CODE[0]);
        assert_eq!(
            read_u32(
                bytes,
                (bootstrap.args_offset() + BOOTSTRAP_ARGS_RTLD_MODE_OFFSET) as usize
            ),
            2
        );
        assert_eq!(
            read_u32(
                bytes,
                (bootstrap.args_offset() + BOOTSTRAP_ARGS_SOCKET_DOMAIN_OFFSET) as usize
            ),
            DARWIN_AF_UNIX as u32
        );
        assert_eq!(
            read_u32(
                bytes,
                (bootstrap.args_offset() + BOOTSTRAP_ARGS_SOCKET_TYPE_OFFSET) as usize
            ),
            DARWIN_SOCK_STREAM
        );
        assert_eq!(
            read_u32(bytes, (bootstrap.args_offset() + BOOTSTRAP_ARGS_STATUS_OFFSET) as usize),
            BOOTSTRAP_STATUS_PENDING
        );
        assert_eq!(
            &bytes[bootstrap.dylib_path_offset() as usize
                ..bootstrap.dylib_path_offset() as usize + DEFAULT_AGENT_PATH.len()],
            DEFAULT_AGENT_PATH.as_bytes()
        );
        assert_eq!(
            &bytes[bootstrap.entry_symbol_offset() as usize..bootstrap.entry_symbol_offset() as usize + 15],
            b"ios_agent_entry"
        );
        assert_eq!(
            bytes[bootstrap.sockaddr_offset() as usize],
            bootstrap.sockaddr_len() as u8
        );
        assert_eq!(bytes[bootstrap.sockaddr_offset() as usize + 1], DARWIN_AF_UNIX);
        assert_eq!(
            &bytes[bootstrap.sockaddr_offset() as usize + DARWIN_SOCKADDR_UN_HEADER_LEN
                ..bootstrap.sockaddr_offset() as usize + DARWIN_SOCKADDR_UN_HEADER_LEN + target.socket_path.len()],
            target.socket_path.as_bytes()
        );
    }

    #[test]
    fn binds_loader_symbol_addresses_into_argument_block() {
        let loader_symbols = fake_loader_symbols();
        assert!(loader_symbols[0].is_canonicalized());
        assert!(loader_symbols[1].is_canonicalized());

        let plan = build_injection_plan(&test_target())
            .expect("build plan")
            .with_loader_symbols(loader_symbols)
            .expect("bind loader symbols");
        let bootstrap = plan.bootstrap();

        assert_eq!(
            read_u64(
                bootstrap.bytes(),
                (bootstrap.args_offset + BOOTSTRAP_ARGS_DLOPEN_PTR_OFFSET) as usize
            ),
            0x1800_0123_4
        );
        assert_eq!(
            read_u64(
                bootstrap.bytes(),
                (bootstrap.args_offset + BOOTSTRAP_ARGS_DLSYM_PTR_OFFSET) as usize
            ),
            0x1800_0567_8
        );
        assert_eq!(
            read_u64(
                bootstrap.bytes(),
                (bootstrap.args_offset + BOOTSTRAP_ARGS_SOCKET_PTR_OFFSET) as usize
            ),
            0x1802_0222_0
        );
        assert_eq!(
            read_u64(
                bootstrap.bytes(),
                (bootstrap.args_offset + BOOTSTRAP_ARGS_CONNECT_PTR_OFFSET) as usize
            ),
            0x1802_0333_0
        );
    }

    #[test]
    fn computes_thread_launch_registers() {
        let bootstrap = build_injection_plan(&test_target())
            .expect("build plan")
            .bootstrap()
            .clone();
        let launch = bootstrap.thread_launch(0x2000_0000_0, 0x2100_0000_0, 0x3000_0000_0, 0x1801_0abc_0);

        assert_eq!(
            launch,
            Arm64ThreadLaunch {
                pc: 0x1801_0abc_0,
                sp: align_down(0x3000_0000_0 + bootstrap.stack_size(), bootstrap.stack_alignment()),
                lr: 0,
                x0: 0,
                x1: 0,
                x2: 0x2000_0000_0,
                x3: 0x2100_0000_0,
                stack_address: 0x3000_0000_0,
                stack_size: bootstrap.stack_size(),
                bootstrap_address: 0x2000_0000_0,
                argument_address: 0x2100_0000_0,
            }
        );
    }

    #[test]
    fn converts_launch_to_arm_thread_state() {
        let launch = Arm64ThreadLaunch {
            pc: 0x1801_0abc_0,
            sp: 0x3000_3ff0,
            lr: 0,
            x0: 0,
            x1: 0,
            x2: 0x2000_0000_0,
            x3: 0x2000_0040_0,
            stack_address: 0x3000_0000_0,
            stack_size: 0x4000,
            bootstrap_address: 0x2000_0000_0,
            argument_address: 0x2000_0040_0,
        };

        let thread_plan = launch.thread_state();
        assert_eq!(thread_plan.flavor, ARM_THREAD_STATE64_FLAVOR);
        assert_eq!(thread_plan.count, 68);
        assert_eq!(thread_plan.state.pc, launch.pc);
        assert_eq!(thread_plan.state.sp, launch.sp);
        assert_eq!(thread_plan.state.x[2], launch.x2);
        assert_eq!(thread_plan.state.x[3], launch.x3);
        assert!(thread_plan.state.x[4..].iter().all(|value| *value == 0));
    }

    #[test]
    fn plan_contains_expected_stages() {
        let plan = build_injection_plan(&test_target()).expect("build plan");
        let stages = plan.steps().iter().map(|step| step.stage).collect::<Vec<_>>();
        assert_eq!(
            stages,
            vec![
                InjectionStage::AcquireTaskPort,
                InjectionStage::AllocateRemoteMemory,
                InjectionStage::WriteBootstrapImage,
                InjectionStage::ResolveLoaderSymbols,
                InjectionStage::ProtectRemoteMemory,
                InjectionStage::StartRemoteThread,
            ]
        );
    }

    #[test]
    fn rejects_empty_dylib_path() {
        let mut target = test_target();
        target.dylib_path.clear();
        let err = build_injection_plan(&target).expect_err("empty dylib path must fail");
        assert!(err.to_string().contains("dylib path must not be empty"));
    }

    #[test]
    fn rejects_empty_socket_path() {
        let mut target = test_target();
        target.socket_path.clear();
        let err = build_injection_plan(&target).expect_err("empty socket path must fail");
        assert!(err.to_string().contains("socket path must not be empty"));
    }

    #[test]
    fn decodes_bootstrap_status_values() {
        assert_eq!(
            BootstrapStatus::from_raw(BOOTSTRAP_STATUS_PENDING),
            BootstrapStatus::Pending
        );
        assert_eq!(BootstrapStatus::from_raw(6), BootstrapStatus::AgentRunning);
        assert_eq!(BootstrapStatus::from_raw(7), BootstrapStatus::EntryReturned);
        assert_eq!(BootstrapStatus::from_raw(99), BootstrapStatus::Unknown(99));
    }

    #[test]
    fn bootstrap_status_diagnostic_hints_cover_failure_cases() {
        assert!(BootstrapStatus::DlopenFailed
            .diagnostic_hint()
            .expect("dlopen hint")
            .contains("dylib path"));
        assert!(BootstrapStatus::DlsymFailed
            .diagnostic_hint()
            .expect("dlsym hint")
            .contains("entry symbol"));
        assert!(BootstrapStatus::ConnectFailed
            .diagnostic_hint()
            .expect("connect hint")
            .contains("controller is already listening"));
        assert!(BootstrapStatus::Unknown(99).diagnostic_hint().is_some());
        assert!(BootstrapStatus::AgentRunning.diagnostic_hint().is_none());
    }
}
