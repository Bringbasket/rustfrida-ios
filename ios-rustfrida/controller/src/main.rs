#![recursion_limit = "2048"]

mod args;
mod http_rpc;
mod injection;
mod launch;
mod process_lookup;
mod server;
mod server_frontend;
mod server_runtime;
mod session;
mod suspended_spawn;

use args::Args;
use clap::Parser;
use common::{ControllerConfig, Error, InjectionMode, DEFAULT_AGENT_PATH};
use injection::{run_controller, ControllerSessionLauncher};
use serde_json::{json, Value};
use std::sync::Arc;

fn error_kind_label(err: &Error) -> &'static str {
    match err {
        Error::Io(_) => "io",
        Error::Protocol(_) => "protocol",
        Error::InvalidArgument(_) => "invalid-argument",
        Error::State(_) => "state",
        Error::Unsupported(_) => "unsupported",
    }
}

fn render_structured_error(err: &Error) -> Value {
    json!({
        "ok": false,
        "errorKind": error_kind_label(err),
        "error": err.to_string(),
    })
}

fn print_structured_error(err: &Error) {
    match serde_json::to_string_pretty(&render_structured_error(err)) {
        Ok(text) => println!("{text}"),
        Err(_) => eprintln!("{err}"),
    }
}

fn main() {
    let args = Args::parse();
    let structured_errors = args.list_images_json || args.preflight_json || args.inject_json || args.command_json;
    let result = run(args);

    if let Err(err) = result {
        if structured_errors {
            print_structured_error(&err);
        } else {
            eprintln!("{err}");
        }
        std::process::exit(1);
    }
}

fn run(args: Args) -> common::Result<()> {
    if args.server {
        return run_server(args);
    }

    let mode = if args.spawn {
        InjectionMode::Spawn
    } else {
        InjectionMode::Attach
    };
    let list_images = args.list_images;
    let pid = match args.name.as_deref() {
        Some(name) => Some(process_lookup::find_pid_by_name(name)?),
        None => args.pid,
    };
    let config = ControllerConfig {
        mode,
        pid,
        bundle_id: args.bundle_id,
        spawn_command: args.spawn_command,
        command: args.command,
        command_json: args.command_json,
        rpc_bind: args.rpc_port,
        list_images_json: args.list_images_json,
        preflight_only: args.preflight_only,
        preflight_json: args.preflight_json,
        inject_json: args.inject_json,
        agent_path: args.agent_path.unwrap_or_else(|| DEFAULT_AGENT_PATH.into()),
        entry_symbol: args.entry_symbol,
        script_path: args.script,
        socket_path: args.socket_path,
        connect_timeout_secs: args.connect_timeout,
    };

    if list_images {
        run_controller(&config, true)
    } else {
        config.validate().and_then(|_| run_controller(&config, false))
    }
}

fn run_server(args: Args) -> common::Result<()> {
    let config = ControllerConfig {
        mode: InjectionMode::Attach,
        pid: Some(1),
        bundle_id: None,
        spawn_command: None,
        command: None,
        command_json: false,
        rpc_bind: None,
        list_images_json: false,
        preflight_only: false,
        preflight_json: false,
        inject_json: false,
        agent_path: args.agent_path.unwrap_or_else(|| DEFAULT_AGENT_PATH.into()),
        entry_symbol: args.entry_symbol,
        script_path: None,
        socket_path: None,
        connect_timeout_secs: args.connect_timeout,
    };
    let registry = Arc::new(
        server::SessionRegistry::with_capacity(args.max_sessions)
            .map_err(|error| Error::State(format!("failed to create session registry: {error}")))?,
    );
    let launcher = Arc::new(ControllerSessionLauncher::from_config(&config));
    server_runtime::run_stdio_with_launcher(registry, launcher, server_runtime::ServerRuntimeOptions::default())
        .map(|_| ())
        .map_err(Error::Io)
}

#[cfg(test)]
mod tests {
    use super::render_structured_error;
    use common::Error;

    #[test]
    fn structured_error_json_contains_kind_and_message() {
        let rendered = render_structured_error(&Error::Unsupported("dyld image enumeration is unavailable".into()));
        assert_eq!(rendered["ok"], false);
        assert_eq!(rendered["errorKind"], "unsupported");
        assert!(rendered["error"]
            .as_str()
            .expect("error string")
            .contains("dyld image enumeration"));
    }
}
