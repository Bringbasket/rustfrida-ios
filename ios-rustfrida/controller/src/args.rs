use clap::Parser;
use std::net::SocketAddr;

fn parse_pid(value: &str) -> Result<i32, String> {
    match value.parse::<i32>() {
        Ok(pid) if pid > 0 => Ok(pid),
        _ => Err("PID must be a positive integer".into()),
    }
}

fn parse_max_sessions(value: &str) -> Result<usize, String> {
    match value.parse::<usize>() {
        Ok(value) if value > 0 => Ok(value),
        _ => Err("maximum session count must be a positive integer".into()),
    }
}

#[derive(Debug, Parser)]
#[command(author, version, about = "iOS jailbreak edition of rustFrida controller")]
pub struct Args {
    /// Run the persistent multi-session server frontend.
    #[arg(
        long,
        conflicts_with_all = [
            "pid", "name", "bundle_id", "spawn", "command", "command_json",
            "list_images", "list_images_json", "preflight_only", "preflight_json",
            "inject_json", "rpc_port", "socket_path"
        ]
    )]
    pub server: bool,

    /// Maximum number of concurrently retained sessions in server mode.
    #[arg(long, default_value_t = 32, value_parser = parse_max_sessions, requires = "server")]
    pub max_sessions: usize,

    /// Attach to an exact PID.
    #[arg(
        long,
        value_name = "PID",
        value_parser = parse_pid,
        allow_hyphen_values = true,
        conflicts_with_all = ["name", "bundle_id", "spawn"]
    )]
    pub pid: Option<i32>,

    /// Attach to the unique process whose executable name or path matches exactly.
    #[arg(
        short = 'n',
        long,
        value_name = "PROCESS_NAME",
        conflicts_with_all = ["pid", "bundle_id", "spawn"]
    )]
    pub name: Option<String>,

    /// App bundle identifier used by spawn mode.
    #[arg(long, value_name = "BUNDLE_ID", conflicts_with_all = ["pid", "name"])]
    pub bundle_id: Option<String>,

    #[arg(long, requires = "bundle_id")]
    pub spawn: bool,

    #[arg(long, value_name = "SHELL", requires = "spawn")]
    pub spawn_command: Option<String>,

    #[arg(long, value_name = "FILE")]
    pub script: Option<String>,

    #[arg(
        long,
        value_name = "COMMAND",
        conflicts_with_all = ["list_images", "list_images_json", "preflight_only", "preflight_json", "inject_json"]
    )]
    pub command: Option<String>,

    #[arg(long, requires = "command")]
    pub command_json: bool,

    /// Start the HTTP RPC server for the connected agent.
    #[arg(
        long = "rpc-port",
        value_name = "PORT_OR_ADDR",
        value_parser = parse_rpc_bind,
        conflicts_with_all = [
            "command",
            "list_images",
            "list_images_json",
            "preflight_only",
            "preflight_json",
            "inject_json"
        ]
    )]
    pub rpc_port: Option<String>,

    #[arg(long, value_name = "PATH")]
    pub socket_path: Option<String>,

    #[arg(long)]
    pub list_images: bool,

    #[arg(long, requires = "list_images")]
    pub list_images_json: bool,

    #[arg(long)]
    pub preflight_only: bool,

    #[arg(long, requires = "preflight_only")]
    pub preflight_json: bool,

    #[arg(long, conflicts_with_all = ["list_images", "list_images_json", "preflight_only", "preflight_json"])]
    pub inject_json: bool,

    #[arg(long, value_name = "PATH")]
    pub agent_path: Option<String>,

    #[arg(long, default_value = "ios_agent_entry")]
    pub entry_symbol: String,

    #[arg(long, default_value_t = 15)]
    pub connect_timeout: u64,
}

pub fn parse_rpc_bind(value: &str) -> Result<String, String> {
    if value.contains(':') {
        let address = value
            .parse::<SocketAddr>()
            .map_err(|err| format!("invalid RPC bind address `{value}`: {err}"))?;
        if address.port() == 0 {
            return Err("RPC port must be between 1 and 65535".into());
        }
        return Ok(address.to_string());
    }

    let port = value
        .parse::<u16>()
        .map_err(|_| format!("invalid RPC port `{value}`; expected 1..65535 or HOST:PORT"))?;
    if port == 0 {
        return Err("RPC port must be between 1 and 65535".into());
    }
    Ok(format!("0.0.0.0:{port}"))
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::{parse_rpc_bind, Args};

    #[test]
    fn rpc_port_expands_to_wildcard_bind() {
        assert_eq!(parse_rpc_bind("9191").expect("port"), "0.0.0.0:9191");
    }

    #[test]
    fn rpc_address_is_preserved() {
        assert_eq!(
            parse_rpc_bind("127.0.0.1:9191").expect("IPv4 address"),
            "127.0.0.1:9191"
        );
        assert_eq!(parse_rpc_bind("[::1]:9191").expect("IPv6 address"), "[::1]:9191");
    }

    #[test]
    fn rpc_bind_rejects_invalid_or_zero_ports() {
        assert!(parse_rpc_bind("invalid").is_err());
        assert!(parse_rpc_bind("0").is_err());
        assert!(parse_rpc_bind("127.0.0.1:0").is_err());
    }

    #[test]
    fn cli_normalizes_rpc_port() {
        let args = Args::try_parse_from(["ios-rustfrida", "--pid", "42", "--rpc-port", "9191"]).expect("RPC CLI args");
        assert_eq!(args.rpc_port.as_deref(), Some("0.0.0.0:9191"));
    }

    #[test]
    fn cli_rejects_rpc_server_with_single_command() {
        let error = Args::try_parse_from([
            "ios-rustfrida",
            "--pid",
            "42",
            "--rpc-port",
            "9191",
            "--command",
            "native.images",
        ])
        .expect_err("RPC server and command should conflict");
        assert!(error.to_string().contains("cannot be used with"));
    }

    #[test]
    fn cli_accepts_process_name_attach() {
        let args = Args::try_parse_from(["ios-rustfrida", "--name", "SpringBoard"]).expect("name attach args");
        assert_eq!(args.name.as_deref(), Some("SpringBoard"));
        assert_eq!(args.pid, None);
        assert!(!args.spawn);
    }

    #[test]
    fn cli_rejects_non_positive_pid() {
        for pid in ["0", "-1", "not-a-pid"] {
            let error = Args::try_parse_from(["ios-rustfrida", "--pid", pid]).expect_err("invalid pid");
            assert!(error.to_string().contains("positive integer"));
        }
    }

    #[test]
    fn cli_target_selectors_are_mutually_exclusive() {
        for argv in [
            vec!["ios-rustfrida", "--pid", "42", "--name", "Demo"],
            vec!["ios-rustfrida", "--pid", "42", "--bundle-id", "com.example.demo"],
            vec!["ios-rustfrida", "--name", "Demo", "--bundle-id", "com.example.demo"],
            vec![
                "ios-rustfrida",
                "--name",
                "Demo",
                "--bundle-id",
                "com.example.demo",
                "--spawn",
            ],
        ] {
            let error = Args::try_parse_from(argv).expect_err("target selectors must conflict");
            assert!(error.to_string().contains("cannot be used with"));
        }
    }

    #[test]
    fn cli_accepts_server_and_session_limit() {
        let args = Args::try_parse_from(["ios-rustfrida", "--server", "--max-sessions", "8"]).expect("server args");
        assert!(args.server);
        assert_eq!(args.max_sessions, 8);
    }

    #[test]
    fn cli_rejects_server_with_process_target() {
        let error = Args::try_parse_from(["ios-rustfrida", "--server", "--pid", "42"])
            .expect_err("server and process target must conflict");
        assert!(error.to_string().contains("cannot be used with"));
    }
}
