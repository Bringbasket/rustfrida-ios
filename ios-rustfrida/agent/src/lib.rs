use common::{
    read_frame, write_frame, AgentCommand, Error, Hello, Result, FRAME_KIND_CMD, FRAME_KIND_CMD_JSON,
    FRAME_KIND_COMPLETE, FRAME_KIND_EVAL_ERR, FRAME_KIND_EVAL_OK, FRAME_KIND_HELLO, FRAME_KIND_LOG,
};
use quickjs_runtime::{QuickJsRuntime, RuntimeStatus};
use serde_json::Value;

#[cfg(unix)]
use std::os::unix::io::FromRawFd;
#[cfg(unix)]
use std::os::unix::net::UnixStream;

struct AgentState {
    runtime: QuickJsRuntime,
}

impl AgentState {
    fn new() -> Self {
        Self {
            runtime: QuickJsRuntime::new(),
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
            AgentCommand::Exit => Ok(AgentReply::Log("bye".into())),
        }
    }
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
            AgentCommand::from_legacy("objc.protocolMethods NSObject optional class"),
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
            AgentCommand::from_legacy("native.sections libsystem_malloc.dylib"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("native.loadcmds libsystem_malloc.dylib"),
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
            AgentCommand::from_legacy("native.image 0x1234"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("native.symbol 0x1234"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("pac.strip 0x1234"),
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
            AgentCommand::from_legacy("swift.typeKinds"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("swift.methodOwners viewDidLoad"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(AgentCommand::from_legacy("ping"), Some(AgentCommand::Ping)));
    }

    #[test]
    fn runtime_command_bootstraps_quickjs_on_demand() {
        let mut state = AgentState::new();
        match state.execute("pac.available").expect("execute pac.available") {
            AgentReply::Eval { result, .. } => assert!(matches!(result.as_deref(), Ok("true") | Ok("false"))),
            _ => panic!("unexpected agent reply"),
        }
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
