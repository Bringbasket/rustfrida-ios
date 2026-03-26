use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{Error, Result};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AgentCommand {
    Ping,
    JsInit,
    JsClean,
    LoadJs { script: String },
    JsEval { script: String },
    JsComplete { prefix: String },
    RuntimeHandle { command: String },
    RuntimeDispatch { spec: Value },
    RuntimeDispatchResult { spec: Value },
    ControllerDispatch { spec: Value },
    ControllerDispatchResult { spec: Value },
    Exit,
}

impl AgentCommand {
    pub fn encode(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(|err| Error::Protocol(format!("failed to encode agent command: {err}")))
    }

    pub fn decode(payload: &[u8]) -> Result<Self> {
        serde_json::from_slice(payload).map_err(|err| Error::Protocol(format!("failed to decode agent command: {err}")))
    }

    pub fn from_legacy(command: &str) -> Option<Self> {
        if command == "ping" {
            return Some(Self::Ping);
        }
        if command == "jsinit" {
            return Some(Self::JsInit);
        }
        if command == "jsclean" {
            return Some(Self::JsClean);
        }
        if command == "exit" {
            return Some(Self::Exit);
        }
        if let Some(script) = command.strip_prefix("loadjs ") {
            return Some(Self::LoadJs {
                script: script.to_string(),
            });
        }
        if let Some(script) = command.strip_prefix("jseval ") {
            return Some(Self::JsEval {
                script: script.to_string(),
            });
        }
        if let Some(prefix) = command.strip_prefix("jscomplete ") {
            return Some(Self::JsComplete {
                prefix: prefix.to_string(),
            });
        }
        if let Some(spec) = parse_runtime_dispatch_legacy_command(command) {
            return Some(Self::RuntimeDispatch { spec });
        }
        if is_runtime_handle_legacy_command(command) {
            return Some(Self::RuntimeHandle {
                command: command.to_string(),
            });
        }
        None
    }
}

fn is_runtime_handle_legacy_command(command: &str) -> bool {
    matches!(
        command,
        "objc.classes"
            | "objc.protocols"
            | "native.images"
            | "native.mainImage"
            | "native.hookenv"
            | "pac.available"
            | "pac.arm64e"
            | "pac.images"
            | "swift.available"
            | "swift.typeKinds"
    ) || command.starts_with("objc.classExists ")
        || command.starts_with("objc.classProtocols ")
        || command.starts_with("objc.superclass ")
        || command.starts_with("objc.selector ")
        || command.starts_with("objc.classImage ")
        || command.starts_with("objc.methodImage ")
        || command.starts_with("objc.selectorName ")
        || command.starts_with("objc.objectClassName ")
        || command.starts_with("objc.methodImp ")
        || command.starts_with("objc.methods ")
        || command.starts_with("objc.properties ")
        || command.starts_with("objc.ivars ")
        || command.starts_with("objc.methodOwners ")
        || command.starts_with("objc.classes ")
        || command.starts_with("objc.protocols ")
        || command.starts_with("native.base ")
        || command.starts_with("native.export ")
        || command.starts_with("native.exports ")
        || command.starts_with("native.dependencies ")
        || command.starts_with("native.encryptionInfo ")
        || command.starts_with("native.entryPoint ")
        || command.starts_with("native.dyldInfo ")
        || command.starts_with("native.linkedit ")
        || command.starts_with("native.functionStarts ")
        || command.starts_with("native.codeSignature ")
        || command.starts_with("native.dataInCode ")
        || command.starts_with("native.exportsTrie ")
        || command.starts_with("native.chainedFixups ")
        || command.starts_with("native.sourceVersion ")
        || command.starts_with("native.buildVersion ")
        || command.starts_with("native.dylinker ")
        || command.starts_with("native.installName ")
        || command.starts_with("native.uuid ")
        || command.starts_with("native.rpaths ")
        || command.starts_with("native.imports ")
        || command.starts_with("native.images ")
        || command.starts_with("native.image ")
        || command.starts_with("native.loadcmds ")
        || command.starts_with("native.sections ")
        || command.starts_with("native.segments ")
        || command.starts_with("native.symbol ")
        || command.starts_with("native.symbols ")
        || command.starts_with("pac.images ")
        || command.starts_with("pac.image ")
        || command.starts_with("pac.strip ")
        || command.starts_with("pac.stripdata ")
        || command.starts_with("swift.demangle ")
        || command.starts_with("swift.symbols ")
        || command.starts_with("swift.methodOwners ")
        || command.starts_with("swift.typesOfKind ")
        || command.starts_with("swift.typeMethods ")
        || command.starts_with("swift.types ")
        || command.starts_with("swift.methods ")
}

fn parse_runtime_dispatch_legacy_command(command: &str) -> Option<Value> {
    match command {
        "objc.classes" => return Some(json!({ "kind": "objc.classes", "filter": null })),
        "objc.protocols" => return Some(json!({ "kind": "objc.protocols", "filter": null })),
        "native.images" => return Some(json!({ "kind": "native.images", "filter": null })),
        "native.mainImage" => return Some(json!({ "kind": "native.main_image" })),
        "native.hookenv" => return Some(json!({ "kind": "native.hook_environment" })),
        "pac.available" => return Some(json!({ "kind": "pac.available" })),
        "pac.arm64e" => return Some(json!({ "kind": "pac.arm64e" })),
        "pac.images" => return Some(json!({ "kind": "pac.images", "filter": null })),
        "swift.available" => return Some(json!({ "kind": "swift.available" })),
        "swift.typeKinds" => return Some(json!({ "kind": "swift.type_kinds" })),
        _ => {}
    }

    if let Some(filter) = command.strip_prefix("objc.classes ") {
        return Some(json!({
            "kind": "objc.classes",
            "filter": filter.trim(),
        }));
    }

    if let Some(filter) = command.strip_prefix("objc.protocols ") {
        return Some(json!({
            "kind": "objc.protocols",
            "filter": filter.trim(),
        }));
    }

    if let Some(class_name) = command.strip_prefix("objc.classExists ") {
        return Some(json!({
            "kind": "objc.class_exists",
            "className": class_name.trim(),
        }));
    }

    if let Some(class_name) = command.strip_prefix("objc.classProtocols ") {
        return Some(json!({
            "kind": "objc.class_protocols",
            "className": class_name.trim(),
        }));
    }

    if let Some(class_name) = command.strip_prefix("objc.superclass ") {
        return Some(json!({
            "kind": "objc.superclass",
            "className": class_name.trim(),
        }));
    }

    if let Some(selector_name) = command.strip_prefix("objc.selector ") {
        return Some(json!({
            "kind": "objc.selector",
            "selectorName": selector_name.trim(),
        }));
    }

    if let Some(raw) = command.strip_prefix("objc.methodImp ") {
        let (class_name, selector_name, is_class_method) = parse_objc_method_target(raw)?;
        return Some(json!({
            "kind": "objc.method_imp",
            "className": class_name,
            "selectorName": selector_name,
            "isClassMethod": is_class_method,
        }));
    }

    if let Some(class_name) = command.strip_prefix("objc.classImage ") {
        return Some(json!({
            "kind": "objc.class_image",
            "className": class_name.trim(),
        }));
    }

    if let Some(raw) = command.strip_prefix("objc.methodImage ") {
        let (class_name, selector_name, is_class_method) = parse_objc_method_target(raw)?;
        return Some(json!({
            "kind": "objc.method_image",
            "className": class_name,
            "selectorName": selector_name,
            "isClassMethod": is_class_method,
        }));
    }

    if let Some(selector) = command.strip_prefix("objc.selectorName ") {
        return Some(json!({
            "kind": "objc.selector_name",
            "selector": selector.trim(),
        }));
    }

    if let Some(object) = command.strip_prefix("objc.objectClassName ") {
        return Some(json!({
            "kind": "objc.object_class_name",
            "object": object.trim(),
        }));
    }

    if let Some(raw) = command.strip_prefix("objc.methods ") {
        let (class_name, is_class_method, filter) = parse_objc_methods(raw)?;
        return Some(json!({
            "kind": "objc.methods",
            "className": class_name,
            "isClassMethod": is_class_method,
            "filter": filter,
        }));
    }

    if let Some(raw) = command.strip_prefix("objc.properties ") {
        let (class_name, is_class_property, filter) = parse_objc_properties(raw)?;
        return Some(json!({
            "kind": "objc.properties",
            "className": class_name,
            "isClassProperty": is_class_property,
            "filter": filter,
        }));
    }

    if let Some(raw) = command.strip_prefix("objc.ivars ") {
        let (class_name, filter) = parse_objc_ivars(raw)?;
        return Some(json!({
            "kind": "objc.ivars",
            "className": class_name,
            "filter": filter,
        }));
    }

    if let Some(raw) = command.strip_prefix("objc.methodOwners ") {
        let (query, is_class_method) = parse_objc_method_owners(raw)?;
        return Some(json!({
            "kind": "objc.method_owners",
            "query": query,
            "isClassMethod": is_class_method,
        }));
    }

    if let Some(module_name) = command.strip_prefix("native.base ") {
        return Some(json!({
            "kind": "native.base",
            "moduleName": module_name.trim(),
        }));
    }

    if let Some(filter) = command.strip_prefix("native.images ") {
        return Some(json!({
            "kind": "native.images",
            "filter": filter.trim(),
        }));
    }

    if let Some(address) = command.strip_prefix("native.image ") {
        return Some(json!({
            "kind": "native.image",
            "address": address.trim(),
        }));
    }

    if let Some(address) = command.strip_prefix("native.symbol ") {
        return Some(json!({
            "kind": "native.symbol",
            "address": address.trim(),
        }));
    }

    if let Some(raw) = command.strip_prefix("native.export ") {
        let (module_name, symbol_name) = parse_native_export(raw)?;
        return Some(json!({
            "kind": "native.export",
            "moduleName": module_name,
            "symbolName": symbol_name,
        }));
    }

    if let Some(raw) = command.strip_prefix("native.symbols ") {
        let (module_name, query) = parse_module_query(raw)?;
        return Some(json!({
            "kind": "native.symbols",
            "moduleName": module_name,
            "query": query,
        }));
    }

    if let Some(raw) = command.strip_prefix("native.exports ") {
        let (module_name, query) = parse_native_exports(raw)?;
        return Some(json!({
            "kind": "native.exports",
            "moduleName": module_name,
            "query": query,
        }));
    }

    if let Some(raw) = command.strip_prefix("native.dependencies ") {
        let (module_name, query) = parse_native_exports(raw)?;
        return Some(json!({
            "kind": "native.dependencies",
            "moduleName": module_name,
            "query": query,
        }));
    }

    if let Some(module_name) = command.strip_prefix("native.encryptionInfo ") {
        let module_name = module_name.trim();
        if module_name.is_empty() {
            return None;
        }
        return Some(json!({
            "kind": "native.encryption_info",
            "moduleName": module_name,
        }));
    }

    if let Some(module_name) = command.strip_prefix("native.entryPoint ") {
        let module_name = module_name.trim();
        if module_name.is_empty() {
            return None;
        }
        return Some(json!({
            "kind": "native.entry_point",
            "moduleName": module_name,
        }));
    }

    if let Some(module_name) = command.strip_prefix("native.dyldInfo ") {
        let module_name = module_name.trim();
        if module_name.is_empty() {
            return None;
        }
        return Some(json!({
            "kind": "native.dyld_info",
            "moduleName": module_name,
        }));
    }

    if let Some(module_name) = command.strip_prefix("native.linkedit ") {
        let module_name = module_name.trim();
        if module_name.is_empty() {
            return None;
        }
        return Some(json!({
            "kind": "native.linkedit",
            "moduleName": module_name,
        }));
    }

    if let Some(module_name) = command.strip_prefix("native.functionStarts ") {
        let module_name = module_name.trim();
        if module_name.is_empty() {
            return None;
        }
        return Some(json!({
            "kind": "native.function_starts",
            "moduleName": module_name,
        }));
    }

    if let Some(module_name) = command.strip_prefix("native.codeSignature ") {
        let module_name = module_name.trim();
        if module_name.is_empty() {
            return None;
        }
        return Some(json!({
            "kind": "native.code_signature",
            "moduleName": module_name,
        }));
    }

    if let Some(module_name) = command.strip_prefix("native.dataInCode ") {
        let module_name = module_name.trim();
        if module_name.is_empty() {
            return None;
        }
        return Some(json!({
            "kind": "native.data_in_code",
            "moduleName": module_name,
        }));
    }

    if let Some(module_name) = command.strip_prefix("native.exportsTrie ") {
        let module_name = module_name.trim();
        if module_name.is_empty() {
            return None;
        }
        return Some(json!({
            "kind": "native.exports_trie",
            "moduleName": module_name,
        }));
    }

    if let Some(module_name) = command.strip_prefix("native.chainedFixups ") {
        let module_name = module_name.trim();
        if module_name.is_empty() {
            return None;
        }
        return Some(json!({
            "kind": "native.chained_fixups",
            "moduleName": module_name,
        }));
    }

    if let Some(module_name) = command.strip_prefix("native.sourceVersion ") {
        let module_name = module_name.trim();
        if module_name.is_empty() {
            return None;
        }
        return Some(json!({
            "kind": "native.source_version",
            "moduleName": module_name,
        }));
    }

    if let Some(module_name) = command.strip_prefix("native.buildVersion ") {
        let module_name = module_name.trim();
        if module_name.is_empty() {
            return None;
        }
        return Some(json!({
            "kind": "native.build_version",
            "moduleName": module_name,
        }));
    }

    if let Some(module_name) = command.strip_prefix("native.dylinker ") {
        let module_name = module_name.trim();
        if module_name.is_empty() {
            return None;
        }
        return Some(json!({
            "kind": "native.dylinker",
            "moduleName": module_name,
        }));
    }

    if let Some(module_name) = command.strip_prefix("native.installName ") {
        let module_name = module_name.trim();
        if module_name.is_empty() {
            return None;
        }
        return Some(json!({
            "kind": "native.install_name",
            "moduleName": module_name,
        }));
    }

    if let Some(module_name) = command.strip_prefix("native.uuid ") {
        let module_name = module_name.trim();
        if module_name.is_empty() {
            return None;
        }
        return Some(json!({
            "kind": "native.uuid",
            "moduleName": module_name,
        }));
    }

    if let Some(raw) = command.strip_prefix("native.rpaths ") {
        let (module_name, query) = parse_native_exports(raw)?;
        return Some(json!({
            "kind": "native.rpaths",
            "moduleName": module_name,
            "query": query,
        }));
    }

    if let Some(raw) = command.strip_prefix("native.imports ") {
        let (module_name, query) = parse_native_exports(raw)?;
        return Some(json!({
            "kind": "native.imports",
            "moduleName": module_name,
            "query": query,
        }));
    }

    if let Some(module_name) = command.strip_prefix("native.segments ") {
        return Some(json!({
            "kind": "native.segments",
            "moduleName": module_name.trim(),
        }));
    }

    if let Some(module_name) = command.strip_prefix("native.sections ") {
        return Some(json!({
            "kind": "native.sections",
            "moduleName": module_name.trim(),
        }));
    }

    if let Some(module_name) = command.strip_prefix("native.loadcmds ") {
        return Some(json!({
            "kind": "native.load_commands",
            "moduleName": module_name.trim(),
        }));
    }

    if let Some(module_name) = command.strip_prefix("pac.image ") {
        return Some(json!({
            "kind": "pac.image",
            "moduleName": module_name.trim(),
        }));
    }

    if let Some(filter) = command.strip_prefix("pac.images ") {
        return Some(json!({
            "kind": "pac.images",
            "filter": filter.trim(),
        }));
    }

    if let Some(address) = command.strip_prefix("pac.strip ") {
        return Some(json!({
            "kind": "pac.strip",
            "address": address.trim(),
        }));
    }

    if let Some(address) = command.strip_prefix("pac.stripdata ") {
        return Some(json!({
            "kind": "pac.stripdata",
            "address": address.trim(),
        }));
    }

    if let Some(symbol) = command.strip_prefix("swift.demangle ") {
        return Some(json!({
            "kind": "swift.demangle",
            "symbol": symbol.trim(),
        }));
    }

    if let Some(raw) = command.strip_prefix("swift.symbols ") {
        let (module_name, query) = parse_module_query(raw)?;
        return Some(json!({
            "kind": "swift.symbols",
            "moduleName": module_name,
            "query": query,
        }));
    }

    if let Some(raw) = command.strip_prefix("swift.types ") {
        let (module_name, query) = parse_module_query(raw)?;
        return Some(json!({
            "kind": "swift.types",
            "moduleName": module_name,
            "query": query,
        }));
    }

    if let Some(raw) = command.strip_prefix("swift.typesOfKind ") {
        let (module_name, source_kind, query) = parse_swift_type_kind_query(raw)?;
        return Some(json!({
            "kind": "swift.types_of_kind",
            "moduleName": module_name,
            "sourceKind": source_kind,
            "query": query,
        }));
    }

    if let Some(raw) = command.strip_prefix("swift.methodOwners ") {
        let (module_name, query) = parse_module_query(raw)?;
        return Some(json!({
            "kind": "swift.method_owners",
            "moduleName": module_name,
            "query": query,
        }));
    }

    if let Some(raw) = command.strip_prefix("swift.typeMethods ") {
        let (module_name, query) = parse_module_query(raw)?;
        return Some(json!({
            "kind": "swift.type_methods",
            "moduleName": module_name,
            "query": query,
        }));
    }

    if let Some(raw) = command.strip_prefix("swift.methods ") {
        let (module_name, type_name, method_query) = parse_swift_methods(raw)?;
        return Some(json!({
            "kind": "swift.methods",
            "moduleName": module_name,
            "typeName": type_name,
            "methodQuery": method_query,
        }));
    }

    None
}

fn parse_module_query(raw: &str) -> Option<(Option<String>, String)> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }

    let separator = " -- ";
    if let Some(index) = trimmed.find(separator) {
        let module_name = trimmed[..index].trim();
        let query = trimmed[index + separator.len()..].trim();
        if module_name.is_empty() || query.is_empty() {
            return None;
        }
        return Some((normalize_optional_module(module_name), query.to_string()));
    }

    Some((None, trimmed.to_string()))
}

fn parse_native_export(raw: &str) -> Option<(Option<String>, String)> {
    parse_module_query(raw)
}

fn parse_native_exports(raw: &str) -> Option<(String, Option<String>)> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }

    let separator = " -- ";
    if let Some(index) = trimmed.find(separator) {
        let module_name = trimmed[..index].trim();
        let query = trimmed[index + separator.len()..].trim();
        if module_name.is_empty() || query.is_empty() {
            return None;
        }
        return Some((module_name.to_string(), Some(query.to_string())));
    }

    Some((trimmed.to_string(), None))
}

fn parse_objc_method_target(raw: &str) -> Option<(String, String, bool)> {
    let parts = raw.split_whitespace().collect::<Vec<_>>();
    if parts.len() < 2 {
        return None;
    }

    let is_class_method = parts[2..].iter().any(|part| matches!(*part, "meta" | "class" | "+"));

    Some((parts[0].to_string(), parts[1].to_string(), is_class_method))
}

fn parse_objc_methods(raw: &str) -> Option<(String, bool, Option<String>)> {
    let parts = raw.split_whitespace().collect::<Vec<_>>();
    if parts.is_empty() {
        return None;
    }

    let mut is_class_method = false;
    let mut filter_parts = Vec::new();
    for part in parts.iter().skip(1) {
        if filter_parts.is_empty() && matches!(*part, "meta" | "class" | "+") {
            is_class_method = true;
            continue;
        }
        if filter_parts.is_empty() && matches!(*part, "instance" | "inst" | "-") {
            is_class_method = false;
            continue;
        }
        filter_parts.push((*part).to_string());
    }

    let filter = (!filter_parts.is_empty()).then(|| filter_parts.join(" "));
    Some((parts[0].to_string(), is_class_method, filter))
}

fn parse_objc_properties(raw: &str) -> Option<(String, bool, Option<String>)> {
    let parts = raw.split_whitespace().collect::<Vec<_>>();
    if parts.is_empty() {
        return None;
    }

    let mut is_class_property = false;
    let mut filter_parts = Vec::new();
    for part in parts.iter().skip(1) {
        if filter_parts.is_empty() && matches!(*part, "meta" | "class" | "+") {
            is_class_property = true;
            continue;
        }
        if filter_parts.is_empty() && matches!(*part, "instance" | "inst" | "-") {
            is_class_property = false;
            continue;
        }
        filter_parts.push((*part).to_string());
    }

    let filter = (!filter_parts.is_empty()).then(|| filter_parts.join(" "));
    Some((parts[0].to_string(), is_class_property, filter))
}

fn parse_objc_ivars(raw: &str) -> Option<(String, Option<String>)> {
    let parts = raw.split_whitespace().collect::<Vec<_>>();
    if parts.is_empty() {
        return None;
    }

    let filter = (parts.len() > 1).then(|| parts[1..].join(" "));
    Some((parts[0].to_string(), filter))
}

fn parse_objc_method_owners(raw: &str) -> Option<(String, bool)> {
    let parts = raw.split_whitespace().collect::<Vec<_>>();
    if parts.is_empty() {
        return None;
    }

    let mut is_class_method = false;
    let mut query_parts = Vec::new();
    for part in parts {
        if query_parts.is_empty() && matches!(part, "meta" | "class" | "+") {
            is_class_method = true;
            continue;
        }
        if query_parts.is_empty() && matches!(part, "instance" | "inst" | "-") {
            is_class_method = false;
            continue;
        }
        query_parts.push(part.to_string());
    }

    if query_parts.is_empty() {
        return None;
    }

    Some((query_parts.join(" "), is_class_method))
}

fn parse_swift_methods(raw: &str) -> Option<(Option<String>, String, String)> {
    let (module_name, query) = parse_module_query(raw)?;
    let parts = query.split_whitespace().collect::<Vec<_>>();
    if parts.len() < 2 {
        return None;
    }

    Some((module_name, parts[0].to_string(), parts[1..].join(" ")))
}

fn parse_swift_type_kind_query(raw: &str) -> Option<(Option<String>, String, String)> {
    let (module_name, query) = parse_module_query(raw)?;
    let parts = query.split_whitespace().collect::<Vec<_>>();
    if parts.len() < 2 {
        return None;
    }

    Some((module_name, parts[0].to_string(), parts[1..].join(" ")))
}

fn normalize_optional_module(value: &str) -> Option<String> {
    match value {
        "*" | "null" | "default" => None,
        _ => Some(value.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::AgentCommand;
    use serde_json::json;

    #[test]
    fn agent_command_roundtrip_json() {
        let command = AgentCommand::ControllerDispatch {
            spec: serde_json::json!({ "kind": "trace.stop" }),
        };
        let payload = command.encode().expect("encode");
        let decoded = AgentCommand::decode(&payload).expect("decode");
        assert_eq!(decoded, command);

        let result_command = AgentCommand::ControllerDispatchResult {
            spec: serde_json::json!({ "kind": "stalker.stop" }),
        };
        let payload = result_command.encode().expect("encode result");
        let decoded = AgentCommand::decode(&payload).expect("decode result");
        assert_eq!(decoded, result_command);

        let runtime_result_command = AgentCommand::RuntimeDispatchResult {
            spec: serde_json::json!({ "kind": "pac.available" }),
        };
        let payload = runtime_result_command.encode().expect("encode runtime result");
        let decoded = AgentCommand::decode(&payload).expect("decode runtime result");
        assert_eq!(decoded, runtime_result_command);
    }

    #[test]
    fn agent_command_parses_legacy_forms() {
        assert_eq!(AgentCommand::from_legacy("ping"), Some(AgentCommand::Ping));
        assert_eq!(AgentCommand::from_legacy("jsinit"), Some(AgentCommand::JsInit));
        assert_eq!(AgentCommand::from_legacy("jsclean"), Some(AgentCommand::JsClean));
        assert_eq!(
            AgentCommand::from_legacy("loadjs console.log(1)"),
            Some(AgentCommand::LoadJs {
                script: "console.log(1)".into()
            })
        );
        assert_eq!(
            AgentCommand::from_legacy("objc.classes"),
            Some(AgentCommand::RuntimeDispatch {
                spec: json!({ "kind": "objc.classes", "filter": null })
            })
        );
        assert_eq!(
            AgentCommand::from_legacy("objc.protocols"),
            Some(AgentCommand::RuntimeDispatch {
                spec: json!({ "kind": "objc.protocols", "filter": null })
            })
        );
        assert!(matches!(
            AgentCommand::from_legacy("native.base libsystem_malloc.dylib"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("native.symbols malloc"),
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
        assert_eq!(
            AgentCommand::from_legacy("native.linkedit libsystem_malloc.dylib"),
            Some(AgentCommand::RuntimeDispatch {
                spec: json!({
                    "kind": "native.linkedit",
                    "moduleName": "libsystem_malloc.dylib",
                })
            })
        );
        assert_eq!(
            AgentCommand::from_legacy("native.functionStarts libsystem_malloc.dylib"),
            Some(AgentCommand::RuntimeDispatch {
                spec: json!({
                    "kind": "native.function_starts",
                    "moduleName": "libsystem_malloc.dylib",
                })
            })
        );
        assert_eq!(
            AgentCommand::from_legacy("native.codeSignature libsystem_malloc.dylib"),
            Some(AgentCommand::RuntimeDispatch {
                spec: json!({
                    "kind": "native.code_signature",
                    "moduleName": "libsystem_malloc.dylib",
                })
            })
        );
        assert_eq!(
            AgentCommand::from_legacy("native.dataInCode libsystem_malloc.dylib"),
            Some(AgentCommand::RuntimeDispatch {
                spec: json!({
                    "kind": "native.data_in_code",
                    "moduleName": "libsystem_malloc.dylib",
                })
            })
        );
        assert_eq!(
            AgentCommand::from_legacy("native.exportsTrie libsystem_malloc.dylib"),
            Some(AgentCommand::RuntimeDispatch {
                spec: json!({
                    "kind": "native.exports_trie",
                    "moduleName": "libsystem_malloc.dylib",
                })
            })
        );
        assert_eq!(
            AgentCommand::from_legacy("native.chainedFixups libsystem_malloc.dylib"),
            Some(AgentCommand::RuntimeDispatch {
                spec: json!({
                    "kind": "native.chained_fixups",
                    "moduleName": "libsystem_malloc.dylib",
                })
            })
        );
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
            AgentCommand::from_legacy("native.imports libsystem_malloc.dylib"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("native.segments DemoBinary"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("native.sections DemoBinary"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("native.loadcmds DemoBinary"),
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
            AgentCommand::from_legacy("objc.classes NSObject"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("objc.protocols NS"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert_eq!(
            AgentCommand::from_legacy("objc.classProtocols NSObject"),
            Some(AgentCommand::RuntimeDispatch {
                spec: json!({
                    "kind": "objc.class_protocols",
                    "className": "NSObject",
                })
            })
        );
        assert_eq!(
            AgentCommand::from_legacy("objc.superclass NSObject"),
            Some(AgentCommand::RuntimeDispatch {
                spec: json!({
                    "kind": "objc.superclass",
                    "className": "NSObject",
                })
            })
        );
        assert_eq!(
            AgentCommand::from_legacy("objc.properties NSObject meta delegate"),
            Some(AgentCommand::RuntimeDispatch {
                spec: json!({
                    "kind": "objc.properties",
                    "className": "NSObject",
                    "isClassProperty": true,
                    "filter": "delegate",
                })
            })
        );
        assert_eq!(
            AgentCommand::from_legacy("objc.ivars NSObject delegate"),
            Some(AgentCommand::RuntimeDispatch {
                spec: json!({
                    "kind": "objc.ivars",
                    "className": "NSObject",
                    "filter": "delegate",
                })
            })
        );
        assert!(matches!(
            AgentCommand::from_legacy("objc.selectorName 0x1234"),
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
        assert_eq!(
            AgentCommand::from_legacy("jscomplete objc."),
            Some(AgentCommand::JsComplete { prefix: "objc.".into() })
        );
        assert_eq!(AgentCommand::from_legacy("trace UIViewController"), None);
    }

    #[test]
    fn malformed_runtime_commands_fall_back_to_text_handler() {
        assert_eq!(
            AgentCommand::from_legacy("swift.methods ViewController"),
            Some(AgentCommand::RuntimeHandle {
                command: "swift.methods ViewController".into(),
            })
        );
        assert_eq!(
            AgentCommand::from_legacy("native.export  "),
            Some(AgentCommand::RuntimeHandle {
                command: "native.export  ".into(),
            })
        );
        assert_eq!(
            AgentCommand::from_legacy("native.imports  "),
            Some(AgentCommand::RuntimeHandle {
                command: "native.imports  ".into(),
            })
        );
        assert_eq!(
            AgentCommand::from_legacy("native.dependencies  "),
            Some(AgentCommand::RuntimeHandle {
                command: "native.dependencies  ".into(),
            })
        );
        assert_eq!(
            AgentCommand::from_legacy("native.encryptionInfo  "),
            Some(AgentCommand::RuntimeHandle {
                command: "native.encryptionInfo  ".into(),
            })
        );
        assert_eq!(
            AgentCommand::from_legacy("native.entryPoint  "),
            Some(AgentCommand::RuntimeHandle {
                command: "native.entryPoint  ".into(),
            })
        );
        assert_eq!(
            AgentCommand::from_legacy("native.dyldInfo  "),
            Some(AgentCommand::RuntimeHandle {
                command: "native.dyldInfo  ".into(),
            })
        );
        assert_eq!(
            AgentCommand::from_legacy("native.linkedit  "),
            Some(AgentCommand::RuntimeHandle {
                command: "native.linkedit  ".into(),
            })
        );
        assert_eq!(
            AgentCommand::from_legacy("native.functionStarts  "),
            Some(AgentCommand::RuntimeHandle {
                command: "native.functionStarts  ".into(),
            })
        );
        assert_eq!(
            AgentCommand::from_legacy("native.codeSignature  "),
            Some(AgentCommand::RuntimeHandle {
                command: "native.codeSignature  ".into(),
            })
        );
        assert_eq!(
            AgentCommand::from_legacy("native.dataInCode  "),
            Some(AgentCommand::RuntimeHandle {
                command: "native.dataInCode  ".into(),
            })
        );
        assert_eq!(
            AgentCommand::from_legacy("native.exportsTrie  "),
            Some(AgentCommand::RuntimeHandle {
                command: "native.exportsTrie  ".into(),
            })
        );
        assert_eq!(
            AgentCommand::from_legacy("native.chainedFixups  "),
            Some(AgentCommand::RuntimeHandle {
                command: "native.chainedFixups  ".into(),
            })
        );
        assert_eq!(
            AgentCommand::from_legacy("native.sourceVersion  "),
            Some(AgentCommand::RuntimeHandle {
                command: "native.sourceVersion  ".into(),
            })
        );
        assert_eq!(
            AgentCommand::from_legacy("native.buildVersion  "),
            Some(AgentCommand::RuntimeHandle {
                command: "native.buildVersion  ".into(),
            })
        );
        assert_eq!(
            AgentCommand::from_legacy("native.dylinker  "),
            Some(AgentCommand::RuntimeHandle {
                command: "native.dylinker  ".into(),
            })
        );
        assert_eq!(
            AgentCommand::from_legacy("native.installName  "),
            Some(AgentCommand::RuntimeHandle {
                command: "native.installName  ".into(),
            })
        );
        assert_eq!(
            AgentCommand::from_legacy("native.uuid  "),
            Some(AgentCommand::RuntimeHandle {
                command: "native.uuid  ".into(),
            })
        );
        assert_eq!(
            AgentCommand::from_legacy("native.rpaths  "),
            Some(AgentCommand::RuntimeHandle {
                command: "native.rpaths  ".into(),
            })
        );
    }
}
