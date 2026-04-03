#![recursion_limit = "512"]

mod args;
mod injection;
mod launch;

use args::Args;
use clap::Parser;
use common::{ControllerConfig, Error, InjectionMode, DEFAULT_AGENT_PATH};
use injection::run_controller;
use serde_json::{json, Value};

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
    let mode = if args.spawn {
        InjectionMode::Spawn
    } else {
        InjectionMode::Attach
    };
    let list_images = args.list_images;
    let config = ControllerConfig {
        mode,
        pid: args.pid,
        bundle_id: args.bundle_id,
        spawn_command: args.spawn_command,
        command: args.command,
        command_json: args.command_json,
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

    let result = if list_images {
        run_controller(&config, true)
    } else {
        config.validate().and_then(|_| run_controller(&config, false))
    };

    if let Err(err) = result {
        if args.list_images_json || args.preflight_json || args.inject_json || args.command_json {
            print_structured_error(&err);
        } else {
            eprintln!("{err}");
        }
        std::process::exit(1);
    }
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
