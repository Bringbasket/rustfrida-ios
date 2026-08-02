pub const DEFAULT_AGENT_PATH_ROOTLESS: &str = "/var/jb/usr/lib/libagent.dylib";
pub const DEFAULT_AGENT_PATH_ROOTFUL: &str = "/usr/lib/libagent.dylib";
pub const LEGACY_AGENT_PATH_ROOTFUL: &str = "/usr/lib/agent.dylib";
pub const DEFAULT_AGENT_PATH: &str = DEFAULT_AGENT_PATH_ROOTLESS;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InjectionMode {
    Attach,
    Spawn,
}

#[derive(Debug, Clone)]
pub struct ControllerConfig {
    pub mode: InjectionMode,
    pub pid: Option<i32>,
    pub bundle_id: Option<String>,
    pub spawn_command: Option<String>,
    pub command: Option<String>,
    pub command_json: bool,
    pub rpc_bind: Option<String>,
    pub list_images_json: bool,
    pub preflight_only: bool,
    pub preflight_json: bool,
    pub inject_json: bool,
    pub agent_path: String,
    pub entry_symbol: String,
    pub script_path: Option<String>,
    pub socket_path: Option<String>,
    pub connect_timeout_secs: u64,
}

impl ControllerConfig {
    pub fn validate(&self) -> crate::Result<()> {
        match self.mode {
            InjectionMode::Attach if self.pid.is_none() => {
                Err(crate::Error::InvalidArgument("attach mode requires --pid".into()))
            }
            InjectionMode::Spawn if self.bundle_id.is_none() => {
                Err(crate::Error::InvalidArgument("spawn mode requires --bundle-id".into()))
            }
            InjectionMode::Spawn if self.bundle_id.as_deref().is_some_and(|value| value.trim().is_empty()) => Err(
                crate::Error::InvalidArgument("spawn mode requires a non-empty --bundle-id".into()),
            ),
            _ => {
                if self.agent_path.trim().is_empty() {
                    return Err(crate::Error::InvalidArgument("agent path must not be empty".into()));
                }
                if self.entry_symbol.trim().is_empty() {
                    return Err(crate::Error::InvalidArgument("entry symbol must not be empty".into()));
                }
                if let Some(socket_path) = &self.socket_path {
                    if socket_path.trim().is_empty() {
                        return Err(crate::Error::InvalidArgument("socket path must not be empty".into()));
                    }
                }
                if let Some(command) = &self.command {
                    if command.trim().is_empty() {
                        return Err(crate::Error::InvalidArgument("command must not be empty".into()));
                    }
                }
                if let Some(rpc_bind) = &self.rpc_bind {
                    if rpc_bind.trim().is_empty() {
                        return Err(crate::Error::InvalidArgument(
                            "RPC bind address must not be empty".into(),
                        ));
                    }
                    if self.command.is_some() {
                        return Err(crate::Error::InvalidArgument(
                            "HTTP RPC server mode cannot be combined with a single command".into(),
                        ));
                    }
                }
                Ok(())
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct BootstrapConfig {
    pub entry_symbol: String,
    pub socket_name: String,
    pub dylib_path: String,
}

impl Default for BootstrapConfig {
    fn default() -> Self {
        Self {
            entry_symbol: "ios_agent_entry".into(),
            socket_name: "ios-rustfrida.sock".into(),
            dylib_path: DEFAULT_AGENT_PATH.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{ControllerConfig, InjectionMode, DEFAULT_AGENT_PATH};

    fn base_config() -> ControllerConfig {
        ControllerConfig {
            mode: InjectionMode::Attach,
            pid: Some(1234),
            bundle_id: None,
            spawn_command: None,
            command: None,
            command_json: false,
            rpc_bind: None,
            list_images_json: false,
            preflight_only: false,
            preflight_json: false,
            inject_json: false,
            agent_path: DEFAULT_AGENT_PATH.into(),
            entry_symbol: "ios_agent_entry".into(),
            script_path: None,
            socket_path: None,
            connect_timeout_secs: 15,
        }
    }

    #[test]
    fn validate_accepts_preflight_only_attach_config() {
        let mut config = base_config();
        config.preflight_only = true;
        assert!(config.validate().is_ok());
    }

    #[test]
    fn validate_rejects_spawn_without_bundle_id_even_in_preflight_only() {
        let mut config = base_config();
        config.mode = InjectionMode::Spawn;
        config.pid = None;
        config.preflight_only = true;

        let err = config.validate().expect_err("spawn mode still needs bundle id");
        assert!(err.to_string().contains("--bundle-id"));
    }

    #[test]
    fn validate_rejects_empty_command() {
        let mut config = base_config();
        config.command = Some("   ".into());

        let err = config.validate().expect_err("empty command should fail");
        assert!(err.to_string().contains("command must not be empty"));
    }

    #[test]
    fn validate_rejects_empty_rpc_bind_address() {
        let mut config = base_config();
        config.rpc_bind = Some("   ".into());

        let err = config.validate().expect_err("empty RPC bind should fail");
        assert!(err.to_string().contains("RPC bind address"));
    }

    #[test]
    fn validate_rejects_rpc_server_with_single_command() {
        let mut config = base_config();
        config.command = Some("native.images".into());
        config.rpc_bind = Some("127.0.0.1:9191".into());

        let err = config
            .validate()
            .expect_err("RPC server and single command should conflict");
        assert!(err.to_string().contains("cannot be combined"));
    }
}
