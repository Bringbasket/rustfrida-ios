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
            | "native.detectHookEnvironment"
            | "pac.available"
            | "pac.arm64e"
            | "pac.isProcessArm64e"
            | "pac.images"
            | "pac.arm64eImages"
            | "swift.available"
            | "swift.protocols"
            | "swift.typeSourceKinds"
            | "swift.typeKinds"
    ) || command.starts_with("objc.classExists ")
        || command.starts_with("objc.findClasses ")
        || command.starts_with("objc.classProtocols ")
        || command.starts_with("objc.findClassProtocols ")
        || command.starts_with("objc.classInfo ")
        || command.starts_with("objc.findClassInfo ")
        || command.starts_with("objc.protocolInfo ")
        || command.starts_with("objc.findProtocolInfo ")
        || command.starts_with("objc.protocolProtocols ")
        || command.starts_with("objc.findProtocolProtocols ")
        || command.starts_with("objc.protocolMethods ")
        || command.starts_with("objc.findProtocolMethods ")
        || command.starts_with("objc.protocolMethodInfo ")
        || command.starts_with("objc.findProtocolMethodInfo ")
        || command.starts_with("objc.protocolProperties ")
        || command.starts_with("objc.findProtocolProperties ")
        || command.starts_with("objc.protocolPropertyInfo ")
        || command.starts_with("objc.findProtocolPropertyInfo ")
        || command.starts_with("objc.superclass ")
        || command.starts_with("objc.findSuperclass ")
        || command.starts_with("objc.classChain ")
        || command.starts_with("objc.findClassChain ")
        || command.starts_with("objc.selector ")
        || command.starts_with("objc.classImage ")
        || command.starts_with("objc.findClassImage ")
        || command.starts_with("objc.methodImage ")
        || command.starts_with("objc.findMethodImage ")
        || command.starts_with("objc.methodInfo ")
        || command.starts_with("objc.findMethodInfo ")
        || command.starts_with("objc.propertyInfo ")
        || command.starts_with("objc.findPropertyInfo ")
        || command.starts_with("objc.selectorName ")
        || command.starts_with("objc.findSelectorName ")
        || command.starts_with("objc.objectClassName ")
        || command.starts_with("objc.findObjectClassName ")
        || command.starts_with("objc.methodImp ")
        || command.starts_with("objc.methods ")
        || command.starts_with("objc.findMethods ")
        || command.starts_with("objc.properties ")
        || command.starts_with("objc.findProperties ")
        || command.starts_with("objc.ivarInfo ")
        || command.starts_with("objc.findIvarInfo ")
        || command.starts_with("objc.ivars ")
        || command.starts_with("objc.findIvars ")
        || command.starts_with("objc.methodOwners ")
        || command.starts_with("objc.findMethodOwners ")
        || command.starts_with("objc.classes ")
        || command.starts_with("objc.protocols ")
        || command.starts_with("objc.findProtocols ")
        || command.starts_with("native.base ")
        || command.starts_with("native.imageInfo ")
        || command.starts_with("native.findImageInfo ")
        || command.starts_with("native.export ")
        || command.starts_with("native.exportInfo ")
        || command.starts_with("native.findExportInfo ")
        || command.starts_with("native.symbolInfo ")
        || command.starts_with("native.findSymbolInfo ")
        || command.starts_with("native.exports ")
        || command.starts_with("native.dependencies ")
        || command.starts_with("native.dependencyInfo ")
        || command.starts_with("native.findDependencyInfo ")
        || command.starts_with("native.encryptionInfo ")
        || command.starts_with("native.findEncryptionInfo ")
        || command.starts_with("native.entryPoint ")
        || command.starts_with("native.findEntryPoint ")
        || command.starts_with("native.dyldInfo ")
        || command.starts_with("native.findDyldInfo ")
        || command.starts_with("native.linkedit ")
        || command.starts_with("native.findLinkedit ")
        || command.starts_with("native.functionStarts ")
        || command.starts_with("native.findFunctionStarts ")
        || command.starts_with("native.codeSignature ")
        || command.starts_with("native.findCodeSignature ")
        || command.starts_with("native.dataInCode ")
        || command.starts_with("native.findDataInCode ")
        || command.starts_with("native.exportsTrie ")
        || command.starts_with("native.findExportsTrie ")
        || command.starts_with("native.chainedFixups ")
        || command.starts_with("native.findChainedFixups ")
        || command.starts_with("native.sourceVersion ")
        || command.starts_with("native.findSourceVersion ")
        || command.starts_with("native.buildVersion ")
        || command.starts_with("native.findBuildVersion ")
        || command.starts_with("native.dylinker ")
        || command.starts_with("native.findDylinker ")
        || command.starts_with("native.installName ")
        || command.starts_with("native.findInstallName ")
        || command.starts_with("native.uuid ")
        || command.starts_with("native.findUuid ")
        || command.starts_with("native.rpaths ")
        || command.starts_with("native.findRpaths ")
        || command.starts_with("native.rpathInfo ")
        || command.starts_with("native.findRpathInfo ")
        || command.starts_with("native.imports ")
        || command.starts_with("native.findImports ")
        || command.starts_with("native.importInfo ")
        || command.starts_with("native.findImportInfo ")
        || command.starts_with("native.images ")
        || command.starts_with("native.image ")
        || command.starts_with("native.loadcmds ")
        || command.starts_with("native.loadCommands ")
        || command.starts_with("native.findLoadCommands ")
        || command.starts_with("native.loadCommandInfo ")
        || command.starts_with("native.findLoadCommandInfo ")
        || command.starts_with("native.sections ")
        || command.starts_with("native.findSections ")
        || command.starts_with("native.sectionInfo ")
        || command.starts_with("native.findSectionInfo ")
        || command.starts_with("native.segments ")
        || command.starts_with("native.findSegments ")
        || command.starts_with("native.segmentInfo ")
        || command.starts_with("native.findSegmentInfo ")
        || command.starts_with("native.symbol ")
        || command.starts_with("native.symbols ")
        || command.starts_with("native.findSymbols ")
        || command.starts_with("native.findExports ")
        || command.starts_with("native.findDependencies ")
        || command.starts_with("pac.images ")
        || command.starts_with("pac.arm64eImages ")
        || command.starts_with("pac.image ")
        || command.starts_with("pac.isImageArm64e ")
        || command.starts_with("pac.strip ")
        || command.starts_with("pac.stripData ")
        || command.starts_with("pac.stripdata ")
        || command.starts_with("swift.demangle ")
        || command.starts_with("swift.symbolInfo ")
        || command.starts_with("swift.findSymbolInfo ")
        || command.starts_with("swift.protocolInfo ")
        || command.starts_with("swift.findProtocolInfo ")
        || command.starts_with("swift.conformanceInfo ")
        || command.starts_with("swift.findConformanceInfo ")
        || command.starts_with("swift.protocols ")
        || command.starts_with("swift.conformances ")
        || command.starts_with("swift.metadata ")
        || command.starts_with("swift.metadataInfo ")
        || command.starts_with("swift.findMetadataInfo ")
        || command.starts_with("swift.typeInfo ")
        || command.starts_with("swift.findTypeInfo ")
        || command.starts_with("swift.methodInfo ")
        || command.starts_with("swift.findMethodInfo ")
        || command.starts_with("swift.vtable ")
        || command.starts_with("swift.vtableInfo ")
        || command.starts_with("swift.findVtableInfo ")
        || command.starts_with("swift.witnessTable ")
        || command.starts_with("swift.witnessTableInfo ")
        || command.starts_with("swift.findWitnessTableInfo ")
        || command.starts_with("swift.typeLayout ")
        || command.starts_with("swift.typeLayoutInfo ")
        || command.starts_with("swift.findTypeLayoutInfo ")
        || command.starts_with("swift.symbols ")
        || command.starts_with("swift.methodOwners ")
        || command.starts_with("swift.typesOfKind ")
        || command.starts_with("swift.typeMethods ")
        || command.starts_with("swift.types ")
        || command.starts_with("swift.methods ")
        || command.starts_with("swift.findSymbols ")
        || command.starts_with("swift.findProtocols ")
        || command.starts_with("swift.findConformances ")
        || command.starts_with("swift.findMetadata ")
        || command.starts_with("swift.findVtable ")
        || command.starts_with("swift.findWitnessTable ")
        || command.starts_with("swift.findTypeLayout ")
        || command.starts_with("swift.findTypes ")
        || command.starts_with("swift.findTypesOfKind ")
        || command.starts_with("swift.findMethodOwners ")
        || command.starts_with("swift.findTypeMethods ")
        || command.starts_with("swift.findMethods ")
}

fn parse_runtime_dispatch_legacy_command(command: &str) -> Option<Value> {
    match command {
        "objc.classes" => return Some(json!({ "kind": "objc.classes", "filter": null })),
        "objc.protocols" => return Some(json!({ "kind": "objc.protocols", "filter": null })),
        "native.images" => return Some(json!({ "kind": "native.images", "filter": null })),
        "native.mainImage" => return Some(json!({ "kind": "native.main_image" })),
        "native.hookenv" => return Some(json!({ "kind": "native.hook_environment" })),
        "native.detectHookEnvironment" => return Some(json!({ "kind": "native.hook_environment" })),
        "pac.available" => return Some(json!({ "kind": "pac.available" })),
        "pac.arm64e" => return Some(json!({ "kind": "pac.arm64e" })),
        "pac.isProcessArm64e" => return Some(json!({ "kind": "pac.arm64e" })),
        "pac.images" => return Some(json!({ "kind": "pac.images", "filter": null })),
        "pac.arm64eImages" => return Some(json!({ "kind": "pac.images", "filter": null })),
        "swift.available" => return Some(json!({ "kind": "swift.available" })),
        "swift.protocols" => return Some(json!({ "kind": "swift.protocols", "moduleName": null, "query": null })),
        "swift.typeSourceKinds" => return Some(json!({ "kind": "swift.type_kinds" })),
        "swift.typeKinds" => return Some(json!({ "kind": "swift.type_kinds" })),
        _ => {}
    }

    if let Some(filter) = command.strip_prefix("objc.classes ") {
        return Some(json!({
            "kind": "objc.classes",
            "filter": filter.trim(),
        }));
    }

    if let Some(filter) = command.strip_prefix("objc.findClasses ") {
        let filter = filter.trim();
        if filter.is_empty() {
            return None;
        }
        return Some(json!({
            "kind": "objc.classes",
            "filter": filter,
        }));
    }

    if let Some(filter) = command.strip_prefix("objc.protocols ") {
        return Some(json!({
            "kind": "objc.protocols",
            "filter": filter.trim(),
        }));
    }

    if let Some(filter) = command.strip_prefix("objc.findProtocols ") {
        let filter = filter.trim();
        if filter.is_empty() {
            return None;
        }
        return Some(json!({
            "kind": "objc.protocols",
            "filter": filter,
        }));
    }

    if let Some(class_name) = command.strip_prefix("objc.classExists ") {
        return Some(json!({
            "kind": "objc.class_exists",
            "className": class_name.trim(),
        }));
    }

    if let Some(class_name) = command.strip_prefix("objc.classProtocols ") {
        let (class_name, filter) = parse_objc_protocol_list_owner(class_name)?;
        return Some(json!({
            "kind": "objc.class_protocols",
            "className": class_name,
            "filter": filter,
        }));
    }

    if let Some(class_name) = command.strip_prefix("objc.findClassProtocols ") {
        let (class_name, filter) = parse_objc_protocol_list_owner(class_name)?;
        return Some(json!({
            "kind": "objc.class_protocols",
            "className": class_name,
            "filter": filter,
        }));
    }

    if let Some(raw) = command.strip_prefix("objc.classInfo ") {
        let (class_name, is_meta_class) = parse_objc_class_info(raw)?;
        return Some(json!({
            "kind": "objc.class_info",
            "className": class_name,
            "isMetaClass": is_meta_class,
        }));
    }

    if let Some(raw) = command.strip_prefix("objc.findClassInfo ") {
        let (class_name, is_meta_class) = parse_objc_class_info(raw)?;
        return Some(json!({
            "kind": "objc.class_info",
            "className": class_name,
            "isMetaClass": is_meta_class,
        }));
    }

    if let Some(raw) = command.strip_prefix("objc.protocolInfo ") {
        let protocol_name = parse_objc_protocol_info(raw)?;
        return Some(json!({
            "kind": "objc.protocol_info",
            "protocolName": protocol_name,
        }));
    }

    if let Some(raw) = command.strip_prefix("objc.findProtocolInfo ") {
        let protocol_name = parse_objc_protocol_info(raw)?;
        return Some(json!({
            "kind": "objc.protocol_info",
            "protocolName": protocol_name,
        }));
    }

    if let Some(protocol_name) = command.strip_prefix("objc.protocolProtocols ") {
        let (protocol_name, filter) = parse_objc_protocol_list_owner(protocol_name)?;
        return Some(json!({
            "kind": "objc.protocol_protocols",
            "protocolName": protocol_name,
            "filter": filter,
        }));
    }

    if let Some(protocol_name) = command.strip_prefix("objc.findProtocolProtocols ") {
        let (protocol_name, filter) = parse_objc_protocol_list_owner(protocol_name)?;
        return Some(json!({
            "kind": "objc.protocol_protocols",
            "protocolName": protocol_name,
            "filter": filter,
        }));
    }

    if let Some(raw) = command.strip_prefix("objc.protocolMethods ") {
        let (protocol_name, is_required, is_instance_method, filter) = parse_objc_protocol_methods(raw)?;
        return Some(json!({
            "kind": "objc.protocol_methods",
            "protocolName": protocol_name,
            "isRequired": is_required,
            "isInstanceMethod": is_instance_method,
            "filter": filter,
        }));
    }

    if let Some(raw) = command.strip_prefix("objc.findProtocolMethods ") {
        let (protocol_name, is_required, is_instance_method, filter) = parse_objc_protocol_methods(raw)?;
        return Some(json!({
            "kind": "objc.protocol_methods",
            "protocolName": protocol_name,
            "isRequired": is_required,
            "isInstanceMethod": is_instance_method,
            "filter": filter,
        }));
    }

    if let Some(raw) = command.strip_prefix("objc.protocolMethodInfo ") {
        let (protocol_name, selector_name, is_required, is_instance_method) = parse_objc_protocol_method_info(raw)?;
        return Some(json!({
            "kind": "objc.protocol_method_info",
            "protocolName": protocol_name,
            "selectorName": selector_name,
            "isRequired": is_required,
            "isInstanceMethod": is_instance_method,
        }));
    }

    if let Some(raw) = command.strip_prefix("objc.findProtocolMethodInfo ") {
        let (protocol_name, selector_name, is_required, is_instance_method) = parse_objc_protocol_method_info(raw)?;
        return Some(json!({
            "kind": "objc.protocol_method_info",
            "protocolName": protocol_name,
            "selectorName": selector_name,
            "isRequired": is_required,
            "isInstanceMethod": is_instance_method,
        }));
    }

    if let Some(raw) = command.strip_prefix("objc.protocolProperties ") {
        let (protocol_name, filter) = parse_objc_protocol_properties(raw)?;
        return Some(json!({
            "kind": "objc.protocol_properties",
            "protocolName": protocol_name,
            "filter": filter,
        }));
    }

    if let Some(raw) = command.strip_prefix("objc.findProtocolProperties ") {
        let (protocol_name, filter) = parse_objc_protocol_properties(raw)?;
        return Some(json!({
            "kind": "objc.protocol_properties",
            "protocolName": protocol_name,
            "filter": filter,
        }));
    }

    if let Some(raw) = command.strip_prefix("objc.protocolPropertyInfo ") {
        let (protocol_name, property_name) = parse_objc_member_info(raw)?;
        return Some(json!({
            "kind": "objc.protocol_property_info",
            "protocolName": protocol_name,
            "propertyName": property_name,
        }));
    }

    if let Some(raw) = command.strip_prefix("objc.findProtocolPropertyInfo ") {
        let (protocol_name, property_name) = parse_objc_member_info(raw)?;
        return Some(json!({
            "kind": "objc.protocol_property_info",
            "protocolName": protocol_name,
            "propertyName": property_name,
        }));
    }

    if let Some(class_name) = command.strip_prefix("objc.superclass ") {
        return Some(json!({
            "kind": "objc.superclass",
            "className": class_name.trim(),
        }));
    }

    if let Some(class_name) = command.strip_prefix("objc.findSuperclass ") {
        return Some(json!({
            "kind": "objc.superclass",
            "className": class_name.trim(),
        }));
    }

    if let Some(class_name) = command.strip_prefix("objc.classChain ") {
        return Some(json!({
            "kind": "objc.class_chain",
            "className": class_name.trim(),
        }));
    }

    if let Some(class_name) = command.strip_prefix("objc.findClassChain ") {
        return Some(json!({
            "kind": "objc.class_chain",
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

    if let Some(raw) = command.strip_prefix("objc.methodInfo ") {
        let (class_name, selector_name, is_class_method) = parse_objc_method_target(raw)?;
        return Some(json!({
            "kind": "objc.method_info",
            "className": class_name,
            "selectorName": selector_name,
            "isClassMethod": is_class_method,
        }));
    }

    if let Some(raw) = command.strip_prefix("objc.findMethodInfo ") {
        let (class_name, selector_name, is_class_method) = parse_objc_method_target(raw)?;
        return Some(json!({
            "kind": "objc.method_info",
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

    if let Some(class_name) = command.strip_prefix("objc.findClassImage ") {
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

    if let Some(raw) = command.strip_prefix("objc.findMethodImage ") {
        let (class_name, selector_name, is_class_method) = parse_objc_method_target(raw)?;
        return Some(json!({
            "kind": "objc.method_image",
            "className": class_name,
            "selectorName": selector_name,
            "isClassMethod": is_class_method,
        }));
    }

    if let Some(raw) = command.strip_prefix("objc.propertyInfo ") {
        let (class_name, property_name, is_class_property) = parse_objc_method_target(raw)?;
        return Some(json!({
            "kind": "objc.property_info",
            "className": class_name,
            "propertyName": property_name,
            "isClassProperty": is_class_property,
        }));
    }

    if let Some(raw) = command.strip_prefix("objc.findPropertyInfo ") {
        let (class_name, property_name, is_class_property) = parse_objc_method_target(raw)?;
        return Some(json!({
            "kind": "objc.property_info",
            "className": class_name,
            "propertyName": property_name,
            "isClassProperty": is_class_property,
        }));
    }

    if let Some(selector) = command.strip_prefix("objc.selectorName ") {
        return Some(json!({
            "kind": "objc.selector_name",
            "selector": selector.trim(),
        }));
    }

    if let Some(selector) = command.strip_prefix("objc.findSelectorName ") {
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

    if let Some(object) = command.strip_prefix("objc.findObjectClassName ") {
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

    if let Some(raw) = command.strip_prefix("objc.findMethods ") {
        let (class_name, filter, is_class_method) = parse_objc_find_methods(raw)?;
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

    if let Some(raw) = command.strip_prefix("objc.findProperties ") {
        let (class_name, filter, is_class_property) = parse_objc_find_properties(raw)?;
        return Some(json!({
            "kind": "objc.properties",
            "className": class_name,
            "isClassProperty": is_class_property,
            "filter": filter,
        }));
    }

    if let Some(raw) = command.strip_prefix("objc.ivarInfo ") {
        let (class_name, ivar_name) = parse_objc_member_info(raw)?;
        return Some(json!({
            "kind": "objc.ivar_info",
            "className": class_name,
            "ivarName": ivar_name,
        }));
    }

    if let Some(raw) = command.strip_prefix("objc.findIvarInfo ") {
        let (class_name, ivar_name) = parse_objc_member_info(raw)?;
        return Some(json!({
            "kind": "objc.ivar_info",
            "className": class_name,
            "ivarName": ivar_name,
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

    if let Some(raw) = command.strip_prefix("objc.findIvars ") {
        let (class_name, filter) = parse_objc_find_ivars(raw)?;
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

    if let Some(raw) = command.strip_prefix("objc.findMethodOwners ") {
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

    if let Some(module_name) = command.strip_prefix("native.imageInfo ") {
        let module_name = module_name.trim();
        if module_name.is_empty() {
            return None;
        }
        return Some(json!({
            "kind": "native.image_info",
            "moduleName": module_name,
        }));
    }

    if let Some(module_name) = command.strip_prefix("native.findImageInfo ") {
        let module_name = module_name.trim();
        if module_name.is_empty() {
            return None;
        }
        return Some(json!({
            "kind": "native.image_info",
            "moduleName": module_name,
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

    if let Some(raw) = command.strip_prefix("native.findSymbols ") {
        let (module_name, query) = parse_module_query(raw)?;
        return Some(json!({
            "kind": "native.symbols",
            "moduleName": module_name,
            "query": query,
        }));
    }

    if let Some(raw) = command.strip_prefix("native.symbolInfo ") {
        let (module_name, symbol_name) = parse_module_query(raw)?;
        return Some(json!({
            "kind": "native.symbol_info",
            "moduleName": module_name,
            "symbolName": symbol_name,
        }));
    }

    if let Some(raw) = command.strip_prefix("native.findSymbolInfo ") {
        let (module_name, symbol_name) = parse_module_query(raw)?;
        return Some(json!({
            "kind": "native.symbol_info",
            "moduleName": module_name,
            "symbolName": symbol_name,
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

    if let Some(raw) = command.strip_prefix("native.findExports ") {
        let (module_name, query) = parse_native_exports(raw)?;
        return Some(json!({
            "kind": "native.exports",
            "moduleName": module_name,
            "query": query,
        }));
    }

    if let Some(raw) = command.strip_prefix("native.exportInfo ") {
        let (module_name, query) = parse_native_exports(raw)?;
        let symbol_name = query?;
        return Some(json!({
            "kind": "native.export_info",
            "moduleName": module_name,
            "symbolName": symbol_name,
        }));
    }

    if let Some(raw) = command.strip_prefix("native.findExportInfo ") {
        let (module_name, query) = parse_native_exports(raw)?;
        let symbol_name = query?;
        return Some(json!({
            "kind": "native.export_info",
            "moduleName": module_name,
            "symbolName": symbol_name,
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

    if let Some(raw) = command.strip_prefix("native.findDependencies ") {
        let (module_name, query) = parse_native_exports(raw)?;
        return Some(json!({
            "kind": "native.dependencies",
            "moduleName": module_name,
            "query": query,
        }));
    }

    if let Some(raw) = command.strip_prefix("native.dependencyInfo ") {
        let (module_name, query) = parse_native_exports(raw)?;
        let path_or_name = query?;
        return Some(json!({
            "kind": "native.dependency_info",
            "moduleName": module_name,
            "pathOrName": path_or_name,
        }));
    }

    if let Some(raw) = command.strip_prefix("native.findDependencyInfo ") {
        let (module_name, query) = parse_native_exports(raw)?;
        let path_or_name = query?;
        return Some(json!({
            "kind": "native.dependency_info",
            "moduleName": module_name,
            "pathOrName": path_or_name,
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

    if let Some(module_name) = command.strip_prefix("native.findEncryptionInfo ") {
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

    if let Some(module_name) = command.strip_prefix("native.findEntryPoint ") {
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

    if let Some(module_name) = command.strip_prefix("native.findDyldInfo ") {
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

    if let Some(module_name) = command.strip_prefix("native.findLinkedit ") {
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

    if let Some(module_name) = command.strip_prefix("native.findFunctionStarts ") {
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

    if let Some(module_name) = command.strip_prefix("native.findCodeSignature ") {
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

    if let Some(module_name) = command.strip_prefix("native.findDataInCode ") {
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

    if let Some(module_name) = command.strip_prefix("native.findExportsTrie ") {
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

    if let Some(module_name) = command.strip_prefix("native.findChainedFixups ") {
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

    if let Some(module_name) = command.strip_prefix("native.findSourceVersion ") {
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

    if let Some(module_name) = command.strip_prefix("native.findBuildVersion ") {
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

    if let Some(module_name) = command.strip_prefix("native.findDylinker ") {
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

    if let Some(module_name) = command.strip_prefix("native.findInstallName ") {
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

    if let Some(module_name) = command.strip_prefix("native.findUuid ") {
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

    if let Some(raw) = command.strip_prefix("native.findRpaths ") {
        let (module_name, query) = parse_native_exports(raw)?;
        return Some(json!({
            "kind": "native.rpaths",
            "moduleName": module_name,
            "query": query,
        }));
    }

    if let Some(raw) = command.strip_prefix("native.rpathInfo ") {
        let (module_name, query) = parse_native_exports(raw)?;
        let path = query?;
        return Some(json!({
            "kind": "native.rpath_info",
            "moduleName": module_name,
            "path": path,
        }));
    }

    if let Some(raw) = command.strip_prefix("native.findRpathInfo ") {
        let (module_name, query) = parse_native_exports(raw)?;
        let path = query?;
        return Some(json!({
            "kind": "native.rpath_info",
            "moduleName": module_name,
            "path": path,
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

    if let Some(raw) = command.strip_prefix("native.findImports ") {
        let (module_name, query) = parse_native_exports(raw)?;
        return Some(json!({
            "kind": "native.imports",
            "moduleName": module_name,
            "query": query,
        }));
    }

    if let Some(raw) = command.strip_prefix("native.importInfo ") {
        let (module_name, query) = parse_native_exports(raw)?;
        let symbol_name = query?;
        return Some(json!({
            "kind": "native.import_info",
            "moduleName": module_name,
            "symbolName": symbol_name,
        }));
    }

    if let Some(raw) = command.strip_prefix("native.findImportInfo ") {
        let (module_name, query) = parse_native_exports(raw)?;
        let symbol_name = query?;
        return Some(json!({
            "kind": "native.import_info",
            "moduleName": module_name,
            "symbolName": symbol_name,
        }));
    }

    if let Some(module_name) = command.strip_prefix("native.segments ") {
        return Some(json!({
            "kind": "native.segments",
            "moduleName": module_name.trim(),
        }));
    }

    if let Some(module_name) = command.strip_prefix("native.findSegments ") {
        return Some(json!({
            "kind": "native.segments",
            "moduleName": module_name.trim(),
        }));
    }

    if let Some(raw) = command.strip_prefix("native.segmentInfo ") {
        let (module_name, query) = parse_native_exports(raw)?;
        let segment_name = query?;
        return Some(json!({
            "kind": "native.segment_info",
            "moduleName": module_name,
            "segmentName": segment_name,
        }));
    }

    if let Some(raw) = command.strip_prefix("native.findSegmentInfo ") {
        let (module_name, query) = parse_native_exports(raw)?;
        let segment_name = query?;
        return Some(json!({
            "kind": "native.segment_info",
            "moduleName": module_name,
            "segmentName": segment_name,
        }));
    }

    if let Some(module_name) = command.strip_prefix("native.sections ") {
        return Some(json!({
            "kind": "native.sections",
            "moduleName": module_name.trim(),
        }));
    }

    if let Some(module_name) = command.strip_prefix("native.findSections ") {
        return Some(json!({
            "kind": "native.sections",
            "moduleName": module_name.trim(),
        }));
    }

    if let Some(raw) = command.strip_prefix("native.sectionInfo ") {
        let (module_name, query) = parse_native_exports(raw)?;
        let query = query?;
        let mut parts = query.split_whitespace();
        let segment_name = parts.next()?;
        let section_name = parts.next()?;
        if parts.next().is_some() {
            return None;
        }
        return Some(json!({
            "kind": "native.section_info",
            "moduleName": module_name,
            "segmentName": segment_name,
            "sectionName": section_name,
        }));
    }

    if let Some(raw) = command.strip_prefix("native.findSectionInfo ") {
        let (module_name, query) = parse_native_exports(raw)?;
        let query = query?;
        let mut parts = query.split_whitespace();
        let segment_name = parts.next()?;
        let section_name = parts.next()?;
        if parts.next().is_some() {
            return None;
        }
        return Some(json!({
            "kind": "native.section_info",
            "moduleName": module_name,
            "segmentName": segment_name,
            "sectionName": section_name,
        }));
    }

    if let Some(module_name) = command.strip_prefix("native.loadcmds ") {
        return Some(json!({
            "kind": "native.load_commands",
            "moduleName": module_name.trim(),
        }));
    }

    if let Some(module_name) = command.strip_prefix("native.loadCommands ") {
        return Some(json!({
            "kind": "native.load_commands",
            "moduleName": module_name.trim(),
        }));
    }

    if let Some(module_name) = command.strip_prefix("native.findLoadCommands ") {
        return Some(json!({
            "kind": "native.load_commands",
            "moduleName": module_name.trim(),
        }));
    }

    if let Some(raw) = command.strip_prefix("native.loadCommandInfo ") {
        let (module_name, query) = parse_native_exports(raw)?;
        let command_or_index = query?;
        return Some(json!({
            "kind": "native.load_command_info",
            "moduleName": module_name,
            "commandOrIndex": command_or_index,
        }));
    }

    if let Some(raw) = command.strip_prefix("native.findLoadCommandInfo ") {
        let (module_name, query) = parse_native_exports(raw)?;
        let command_or_index = query?;
        return Some(json!({
            "kind": "native.load_command_info",
            "moduleName": module_name,
            "commandOrIndex": command_or_index,
        }));
    }

    if let Some(module_name) = command.strip_prefix("pac.image ") {
        return Some(json!({
            "kind": "pac.image",
            "moduleName": module_name.trim(),
        }));
    }

    if let Some(module_name) = command.strip_prefix("pac.isImageArm64e ") {
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

    if let Some(filter) = command.strip_prefix("pac.arm64eImages ") {
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

    if let Some(address) = command.strip_prefix("pac.stripData ") {
        return Some(json!({
            "kind": "pac.stripdata",
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

    if let Some(raw) = command.strip_prefix("swift.protocolInfo ") {
        let (module_name, protocol_name) = parse_module_query(raw)?;
        return Some(json!({
            "kind": "swift.protocol_info",
            "moduleName": module_name,
            "protocolName": protocol_name,
        }));
    }

    if let Some(raw) = command.strip_prefix("swift.findProtocolInfo ") {
        let (module_name, protocol_name) = parse_module_query(raw)?;
        return Some(json!({
            "kind": "swift.protocol_info",
            "moduleName": module_name,
            "protocolName": protocol_name,
        }));
    }

    if let Some(raw) = command.strip_prefix("swift.conformanceInfo ") {
        let (module_name, query) = parse_module_query(raw)?;
        let parts = query.split_whitespace().collect::<Vec<_>>();
        if parts.len() < 2 {
            return None;
        }
        return Some(json!({
            "kind": "swift.conformance_info",
            "moduleName": module_name,
            "typeName": parts[0],
            "protocolName": parts[1..].join(" "),
        }));
    }

    if let Some(raw) = command.strip_prefix("swift.findConformanceInfo ") {
        let (module_name, query) = parse_module_query(raw)?;
        let parts = query.split_whitespace().collect::<Vec<_>>();
        if parts.len() < 2 {
            return None;
        }
        return Some(json!({
            "kind": "swift.conformance_info",
            "moduleName": module_name,
            "typeName": parts[0],
            "protocolName": parts[1..].join(" "),
        }));
    }

    if let Some(raw) = command.strip_prefix("swift.protocols ") {
        let (module_name, query) = parse_module_query(raw)?;
        return Some(json!({
            "kind": "swift.protocols",
            "moduleName": module_name,
            "query": query,
        }));
    }

    if let Some(raw) = command.strip_prefix("swift.conformances ") {
        let (module_name, query) = parse_module_query(raw)?;
        return Some(json!({
            "kind": "swift.conformances",
            "moduleName": module_name,
            "query": query,
        }));
    }

    if let Some(raw) = command.strip_prefix("swift.typeInfo ") {
        let (module_name, type_name) = parse_module_query(raw)?;
        return Some(json!({
            "kind": "swift.type_info",
            "moduleName": module_name,
            "typeName": type_name,
        }));
    }

    if let Some(raw) = command.strip_prefix("swift.findTypeInfo ") {
        let (module_name, type_name) = parse_module_query(raw)?;
        return Some(json!({
            "kind": "swift.type_info",
            "moduleName": module_name,
            "typeName": type_name,
        }));
    }

    if let Some(raw) = command.strip_prefix("swift.methodInfo ") {
        let (module_name, type_name, method_name) = parse_swift_methods(raw)?;
        return Some(json!({
            "kind": "swift.method_info",
            "moduleName": module_name,
            "typeName": type_name,
            "methodName": method_name,
        }));
    }

    if let Some(raw) = command.strip_prefix("swift.findMethodInfo ") {
        let (module_name, type_name, method_name) = parse_swift_methods(raw)?;
        return Some(json!({
            "kind": "swift.method_info",
            "moduleName": module_name,
            "typeName": type_name,
            "methodName": method_name,
        }));
    }

    if let Some(raw) = command.strip_prefix("swift.metadata ") {
        let (module_name, query) = parse_module_query(raw)?;
        return Some(json!({
            "kind": "swift.metadata",
            "moduleName": module_name,
            "query": query,
        }));
    }

    if let Some(raw) = command.strip_prefix("swift.metadataInfo ") {
        let (module_name, type_name) = parse_module_query(raw)?;
        return Some(json!({
            "kind": "swift.metadata_info",
            "moduleName": module_name,
            "typeName": type_name,
        }));
    }

    if let Some(raw) = command.strip_prefix("swift.findMetadataInfo ") {
        let (module_name, type_name) = parse_module_query(raw)?;
        return Some(json!({
            "kind": "swift.metadata_info",
            "moduleName": module_name,
            "typeName": type_name,
        }));
    }

    if let Some(raw) = command.strip_prefix("swift.vtable ") {
        let (module_name, query) = parse_module_query(raw)?;
        return Some(json!({
            "kind": "swift.vtable",
            "moduleName": module_name,
            "query": query,
        }));
    }

    if let Some(raw) = command.strip_prefix("swift.vtableInfo ") {
        let (module_name, type_name, member_name) = parse_swift_methods(raw)?;
        return Some(json!({
            "kind": "swift.vtable_info",
            "moduleName": module_name,
            "typeName": type_name,
            "memberName": member_name,
        }));
    }

    if let Some(raw) = command.strip_prefix("swift.findVtableInfo ") {
        let (module_name, type_name, member_name) = parse_swift_methods(raw)?;
        return Some(json!({
            "kind": "swift.vtable_info",
            "moduleName": module_name,
            "typeName": type_name,
            "memberName": member_name,
        }));
    }

    if let Some(raw) = command.strip_prefix("swift.witnessTable ") {
        let (module_name, query) = parse_module_query(raw)?;
        return Some(json!({
            "kind": "swift.witness_table",
            "moduleName": module_name,
            "query": query,
        }));
    }

    if let Some(raw) = command.strip_prefix("swift.witnessTableInfo ") {
        let (module_name, type_name, protocol_name) = parse_swift_methods(raw)?;
        return Some(json!({
            "kind": "swift.witness_table_info",
            "moduleName": module_name,
            "typeName": type_name,
            "protocolName": protocol_name,
        }));
    }

    if let Some(raw) = command.strip_prefix("swift.findWitnessTableInfo ") {
        let (module_name, type_name, protocol_name) = parse_swift_methods(raw)?;
        return Some(json!({
            "kind": "swift.witness_table_info",
            "moduleName": module_name,
            "typeName": type_name,
            "protocolName": protocol_name,
        }));
    }

    if let Some(raw) = command.strip_prefix("swift.typeLayout ") {
        let (module_name, query) = parse_module_query(raw)?;
        return Some(json!({
            "kind": "swift.type_layout",
            "moduleName": module_name,
            "query": query,
        }));
    }

    if let Some(raw) = command.strip_prefix("swift.typeLayoutInfo ") {
        let (module_name, type_name) = parse_module_query(raw)?;
        return Some(json!({
            "kind": "swift.type_layout_info",
            "moduleName": module_name,
            "typeName": type_name,
        }));
    }

    if let Some(raw) = command.strip_prefix("swift.findTypeLayoutInfo ") {
        let (module_name, type_name) = parse_module_query(raw)?;
        return Some(json!({
            "kind": "swift.type_layout_info",
            "moduleName": module_name,
            "typeName": type_name,
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

    if let Some(raw) = command.strip_prefix("swift.findSymbolInfo ") {
        let (module_name, symbol_name) = parse_module_query(raw)?;
        return Some(json!({
            "kind": "swift.symbol_info",
            "moduleName": module_name,
            "symbolName": symbol_name,
        }));
    }

    if let Some(raw) = command.strip_prefix("swift.findSymbols ") {
        let (module_name, query) = parse_module_query(raw)?;
        return Some(json!({
            "kind": "swift.symbols",
            "moduleName": module_name,
            "query": query,
        }));
    }

    if let Some(raw) = command.strip_prefix("swift.symbolInfo ") {
        let (module_name, symbol_name) = parse_module_query(raw)?;
        return Some(json!({
            "kind": "swift.symbol_info",
            "moduleName": module_name,
            "symbolName": symbol_name,
        }));
    }

    if let Some(raw) = command.strip_prefix("swift.findProtocols ") {
        let (module_name, query) = parse_module_query(raw)?;
        return Some(json!({
            "kind": "swift.protocols",
            "moduleName": module_name,
            "query": query,
        }));
    }

    if let Some(raw) = command.strip_prefix("swift.findConformances ") {
        let (module_name, query) = parse_module_query(raw)?;
        return Some(json!({
            "kind": "swift.conformances",
            "moduleName": module_name,
            "query": query,
        }));
    }

    if let Some(raw) = command.strip_prefix("swift.findMetadata ") {
        let (module_name, query) = parse_module_query(raw)?;
        return Some(json!({
            "kind": "swift.metadata",
            "moduleName": module_name,
            "query": query,
        }));
    }

    if let Some(raw) = command.strip_prefix("swift.findVtable ") {
        let (module_name, query) = parse_module_query(raw)?;
        return Some(json!({
            "kind": "swift.vtable",
            "moduleName": module_name,
            "query": query,
        }));
    }

    if let Some(raw) = command.strip_prefix("swift.findWitnessTable ") {
        let (module_name, query) = parse_module_query(raw)?;
        return Some(json!({
            "kind": "swift.witness_table",
            "moduleName": module_name,
            "query": query,
        }));
    }

    if let Some(raw) = command.strip_prefix("swift.findTypeLayout ") {
        let (module_name, query) = parse_module_query(raw)?;
        return Some(json!({
            "kind": "swift.type_layout",
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

    if let Some(raw) = command.strip_prefix("swift.findTypes ") {
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

    if let Some(raw) = command.strip_prefix("swift.findTypesOfKind ") {
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

    if let Some(raw) = command.strip_prefix("swift.findMethodOwners ") {
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

    if let Some(raw) = command.strip_prefix("swift.findTypeMethods ") {
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

    if let Some(raw) = command.strip_prefix("swift.findMethods ") {
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

fn parse_objc_class_info(raw: &str) -> Option<(String, bool)> {
    let parts: Vec<&str> = raw.split_whitespace().collect();
    if parts.is_empty() || parts.len() > 2 {
        return None;
    }
    let is_meta_class = if parts.len() == 2 {
        match parts[1] {
            "meta" | "class" | "+" => true,
            "instance" | "inst" | "-" => false,
            _ => return None,
        }
    } else {
        false
    };
    Some((parts[0].to_string(), is_meta_class))
}

fn parse_objc_protocol_info(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    Some(trimmed.to_string())
}

fn parse_objc_protocol_list_owner(raw: &str) -> Option<(String, Option<String>)> {
    let parts = raw.split_whitespace().collect::<Vec<_>>();
    if parts.is_empty() {
        return None;
    }

    let filter = (parts.len() > 1).then(|| parts[1..].join(" "));
    Some((parts[0].to_string(), filter))
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

fn parse_objc_find_methods(raw: &str) -> Option<(String, String, bool)> {
    let parts = raw.split_whitespace().collect::<Vec<_>>();
    if parts.len() < 2 {
        return None;
    }

    let mut is_class_method = false;
    let mut end = parts.len();
    if let Some(last) = parts.last() {
        match *last {
            "meta" | "class" | "+" => {
                is_class_method = true;
                end -= 1;
            }
            "instance" | "inst" | "-" => {
                is_class_method = false;
                end -= 1;
            }
            _ => {}
        }
    }

    if end <= 1 {
        return None;
    }

    Some((parts[0].to_string(), parts[1..end].join(" "), is_class_method))
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

fn parse_objc_find_properties(raw: &str) -> Option<(String, String, bool)> {
    let parts = raw.split_whitespace().collect::<Vec<_>>();
    if parts.len() < 2 {
        return None;
    }

    let mut is_class_property = false;
    let mut end = parts.len();
    if let Some(last) = parts.last() {
        match *last {
            "meta" | "class" | "+" => {
                is_class_property = true;
                end -= 1;
            }
            "instance" | "inst" | "-" => {
                is_class_property = false;
                end -= 1;
            }
            _ => {}
        }
    }

    if end <= 1 {
        return None;
    }

    Some((parts[0].to_string(), parts[1..end].join(" "), is_class_property))
}

fn parse_objc_ivars(raw: &str) -> Option<(String, Option<String>)> {
    let parts = raw.split_whitespace().collect::<Vec<_>>();
    if parts.is_empty() {
        return None;
    }

    let filter = (parts.len() > 1).then(|| parts[1..].join(" "));
    Some((parts[0].to_string(), filter))
}

fn parse_objc_find_ivars(raw: &str) -> Option<(String, String)> {
    let parts = raw.split_whitespace().collect::<Vec<_>>();
    if parts.len() < 2 {
        return None;
    }

    Some((parts[0].to_string(), parts[1..].join(" ")))
}

fn parse_objc_member_info(raw: &str) -> Option<(String, String)> {
    let parts = raw.split_whitespace().collect::<Vec<_>>();
    if parts.len() < 2 {
        return None;
    }
    Some((parts[0].to_string(), parts[1].to_string()))
}

fn parse_objc_protocol_methods(raw: &str) -> Option<(String, bool, bool, Option<String>)> {
    let parts = raw.split_whitespace().collect::<Vec<_>>();
    if parts.is_empty() {
        return None;
    }

    let mut is_required = true;
    let mut is_instance_method = true;
    let mut filter_parts = Vec::new();
    for part in parts.iter().skip(1) {
        if filter_parts.is_empty() {
            match *part {
                "required" | "req" => {
                    is_required = true;
                    continue;
                }
                "optional" | "opt" => {
                    is_required = false;
                    continue;
                }
                "instance" | "inst" | "-" => {
                    is_instance_method = true;
                    continue;
                }
                "class" | "meta" | "+" => {
                    is_instance_method = false;
                    continue;
                }
                _ => {}
            }
        }
        filter_parts.push((*part).to_string());
    }

    let filter = (!filter_parts.is_empty()).then(|| filter_parts.join(" "));
    Some((parts[0].to_string(), is_required, is_instance_method, filter))
}

fn parse_objc_protocol_properties(raw: &str) -> Option<(String, Option<String>)> {
    let parts = raw.split_whitespace().collect::<Vec<_>>();
    if parts.is_empty() {
        return None;
    }

    let filter = (parts.len() > 1).then(|| parts[1..].join(" "));
    Some((parts[0].to_string(), filter))
}

fn parse_objc_protocol_method_info(raw: &str) -> Option<(String, String, bool, bool)> {
    let parts = raw.split_whitespace().collect::<Vec<_>>();
    if parts.len() < 2 {
        return None;
    }

    let mut is_required = true;
    let mut is_instance_method = true;
    for part in parts.iter().skip(2) {
        match *part {
            "required" | "req" => is_required = true,
            "optional" | "opt" => is_required = false,
            "instance" | "inst" | "-" => is_instance_method = true,
            "class" | "meta" | "+" => is_instance_method = false,
            _ => return None,
        }
    }

    Some((
        parts[0].to_string(),
        parts[1].to_string(),
        is_required,
        is_instance_method,
    ))
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
            AgentCommand::from_legacy("native.imageInfo libsystem_malloc.dylib"),
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
            AgentCommand::from_legacy("native.exportInfo libsystem_malloc.dylib -- malloc"),
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
            AgentCommand::from_legacy("native.segments DemoBinary"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("native.segmentInfo DemoBinary -- __TEXT"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("native.sections DemoBinary"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("native.sectionInfo DemoBinary -- __TEXT __text"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("native.loadCommands DemoBinary"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("native.loadcmds DemoBinary"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("native.loadCommandInfo DemoBinary -- LC_UUID"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("native.detectHookEnvironment"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("pac.isProcessArm64e"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("pac.isImageArm64e libsystem_malloc.dylib"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("pac.arm64eImages"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("pac.arm64eImages malloc"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("pac.stripData 0x1234"),
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
                    "filter": null,
                })
            })
        );
        assert_eq!(
            AgentCommand::from_legacy("objc.classProtocols NSObject NS"),
            Some(AgentCommand::RuntimeDispatch {
                spec: json!({
                    "kind": "objc.class_protocols",
                    "className": "NSObject",
                    "filter": "NS",
                })
            })
        );
        assert_eq!(
            AgentCommand::from_legacy("objc.findClassProtocols NSObject NS"),
            Some(AgentCommand::RuntimeDispatch {
                spec: json!({
                    "kind": "objc.class_protocols",
                    "className": "NSObject",
                    "filter": "NS",
                })
            })
        );
        assert_eq!(
            AgentCommand::from_legacy("objc.classInfo NSObject meta"),
            Some(AgentCommand::RuntimeDispatch {
                spec: json!({
                    "kind": "objc.class_info",
                    "className": "NSObject",
                    "isMetaClass": true,
                })
            })
        );
        assert_eq!(
            AgentCommand::from_legacy("objc.protocolInfo NSObject"),
            Some(AgentCommand::RuntimeDispatch {
                spec: json!({
                    "kind": "objc.protocol_info",
                    "protocolName": "NSObject",
                })
            })
        );
        assert_eq!(
            AgentCommand::from_legacy("objc.protocolProtocols NSObject"),
            Some(AgentCommand::RuntimeDispatch {
                spec: json!({
                    "kind": "objc.protocol_protocols",
                    "protocolName": "NSObject",
                    "filter": null,
                })
            })
        );
        assert_eq!(
            AgentCommand::from_legacy("objc.protocolProtocols NSObject NS"),
            Some(AgentCommand::RuntimeDispatch {
                spec: json!({
                    "kind": "objc.protocol_protocols",
                    "protocolName": "NSObject",
                    "filter": "NS",
                })
            })
        );
        assert_eq!(
            AgentCommand::from_legacy("objc.findProtocolProtocols NSObject NS"),
            Some(AgentCommand::RuntimeDispatch {
                spec: json!({
                    "kind": "objc.protocol_protocols",
                    "protocolName": "NSObject",
                    "filter": "NS",
                })
            })
        );
        assert_eq!(
            AgentCommand::from_legacy("objc.protocolMethods NSObject optional class"),
            Some(AgentCommand::RuntimeDispatch {
                spec: json!({
                    "kind": "objc.protocol_methods",
                    "protocolName": "NSObject",
                    "isRequired": false,
                    "isInstanceMethod": false,
                    "filter": null,
                })
            })
        );
        assert_eq!(
            AgentCommand::from_legacy("objc.protocolMethods NSObject optional class description"),
            Some(AgentCommand::RuntimeDispatch {
                spec: json!({
                    "kind": "objc.protocol_methods",
                    "protocolName": "NSObject",
                    "isRequired": false,
                    "isInstanceMethod": false,
                    "filter": "description",
                })
            })
        );
        assert_eq!(
            AgentCommand::from_legacy("objc.findProtocolMethods NSObject optional class description"),
            Some(AgentCommand::RuntimeDispatch {
                spec: json!({
                    "kind": "objc.protocol_methods",
                    "protocolName": "NSObject",
                    "isRequired": false,
                    "isInstanceMethod": false,
                    "filter": "description",
                })
            })
        );
        assert_eq!(
            AgentCommand::from_legacy("objc.protocolMethodInfo NSObject description optional class"),
            Some(AgentCommand::RuntimeDispatch {
                spec: json!({
                    "kind": "objc.protocol_method_info",
                    "protocolName": "NSObject",
                    "selectorName": "description",
                    "isRequired": false,
                    "isInstanceMethod": false,
                })
            })
        );
        assert_eq!(
            AgentCommand::from_legacy("objc.protocolProperties NSObject"),
            Some(AgentCommand::RuntimeDispatch {
                spec: json!({
                    "kind": "objc.protocol_properties",
                    "protocolName": "NSObject",
                    "filter": null,
                })
            })
        );
        assert_eq!(
            AgentCommand::from_legacy("objc.protocolProperties NSObject description"),
            Some(AgentCommand::RuntimeDispatch {
                spec: json!({
                    "kind": "objc.protocol_properties",
                    "protocolName": "NSObject",
                    "filter": "description",
                })
            })
        );
        assert_eq!(
            AgentCommand::from_legacy("objc.findProtocolProperties NSObject description"),
            Some(AgentCommand::RuntimeDispatch {
                spec: json!({
                    "kind": "objc.protocol_properties",
                    "protocolName": "NSObject",
                    "filter": "description",
                })
            })
        );
        assert_eq!(
            AgentCommand::from_legacy("objc.protocolPropertyInfo NSObject description"),
            Some(AgentCommand::RuntimeDispatch {
                spec: json!({
                    "kind": "objc.protocol_property_info",
                    "protocolName": "NSObject",
                    "propertyName": "description",
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
            AgentCommand::from_legacy("objc.classChain NSObject"),
            Some(AgentCommand::RuntimeDispatch {
                spec: json!({
                    "kind": "objc.class_chain",
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
        assert_eq!(
            AgentCommand::from_legacy("objc.methodInfo NSObject init"),
            Some(AgentCommand::RuntimeDispatch {
                spec: json!({
                    "kind": "objc.method_info",
                    "className": "NSObject",
                    "selectorName": "init",
                    "isClassMethod": false,
                })
            })
        );
        assert_eq!(
            AgentCommand::from_legacy("objc.propertyInfo NSObject description"),
            Some(AgentCommand::RuntimeDispatch {
                spec: json!({
                    "kind": "objc.property_info",
                    "className": "NSObject",
                    "propertyName": "description",
                    "isClassProperty": false,
                })
            })
        );
        assert_eq!(
            AgentCommand::from_legacy("objc.ivarInfo NSObject _isa"),
            Some(AgentCommand::RuntimeDispatch {
                spec: json!({
                    "kind": "objc.ivar_info",
                    "className": "NSObject",
                    "ivarName": "_isa",
                })
            })
        );
        assert!(matches!(
            AgentCommand::from_legacy("objc.methodOwners init"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("objc.findClasses NSObject"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("objc.findMethods NSObject init"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("objc.findProperties NSObject delegate"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("objc.findIvars NSObject isa"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("objc.findMethodOwners init"),
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
            AgentCommand::from_legacy("swift.protocolInfo Renderable"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("swift.findProtocolInfo Renderable"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("swift.conformanceInfo ViewController Renderable"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("swift.findConformanceInfo ViewController Renderable"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("native.symbolInfo malloc"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("native.findSymbols malloc"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("native.findExports libobjc.A.dylib"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("native.findExports libobjc.A.dylib -- objc_msgSend"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("native.findDependencies libobjc.A.dylib"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("native.findDependencies libobjc.A.dylib -- libSystem.B.dylib"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("native.findDyldInfo libobjc.A.dylib"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("native.findLinkedit libobjc.A.dylib"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("native.findEncryptionInfo libobjc.A.dylib"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("native.findEntryPoint libobjc.A.dylib"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("native.findFunctionStarts libobjc.A.dylib"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("native.findCodeSignature libobjc.A.dylib"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("native.findDataInCode libobjc.A.dylib"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("native.findExportsTrie libobjc.A.dylib"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("native.findChainedFixups libobjc.A.dylib"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("native.findSourceVersion libobjc.A.dylib"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("native.findBuildVersion libobjc.A.dylib"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("native.findDylinker libobjc.A.dylib"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("native.findInstallName libobjc.A.dylib"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("native.findUuid libobjc.A.dylib"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("native.findLoadCommands libobjc.A.dylib"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("native.findImports libobjc.A.dylib"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("native.findImports libobjc.A.dylib -- malloc"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("native.findRpaths libobjc.A.dylib"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("native.findRpaths libobjc.A.dylib -- @loader_path"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("native.findSegments DemoBinary"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("native.findSections DemoBinary"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("swift.typeInfo ViewController"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("swift.findTypeInfo ViewController"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("swift.methodInfo ViewController viewDidLoad"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("swift.findMethodInfo ViewController viewDidLoad"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("swift.symbolInfo ViewController"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("swift.findSymbolInfo ViewController"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("swift.protocols"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("swift.protocols Renderable"),
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
            AgentCommand::from_legacy("swift.findMetadataInfo ViewController"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("swift.vtable ViewController"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("swift.vtableInfo ViewController viewDidLoad"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("swift.findVtableInfo ViewController viewDidLoad"),
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
            AgentCommand::from_legacy("swift.findWitnessTableInfo ViewController Renderable"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("swift.typeLayout ViewController"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("swift.typeLayoutInfo ViewController"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("swift.findTypeLayoutInfo ViewController"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("swift.types ViewController"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("swift.types Demo -- ViewController"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("swift.findTypes ViewController"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("swift.findTypes Demo -- ViewController"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("swift.symbols Demo -- ViewController"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("swift.findSymbols Demo -- ViewController"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("swift.typeMethods ViewController"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("swift.typeMethods Demo -- ViewController"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("swift.findTypeMethods ViewController"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("swift.findTypeMethods Demo -- ViewController"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("swift.typesOfKind metadata-accessor ViewController"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("swift.typesOfKind Demo -- metadata-accessor ViewController"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("swift.findTypesOfKind metadata-accessor ViewController"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("swift.findTypesOfKind Demo -- metadata-accessor ViewController"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("swift.typeSourceKinds"),
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
        assert!(matches!(
            AgentCommand::from_legacy("swift.methodOwners Demo -- viewDidLoad"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("swift.findMethodOwners viewDidLoad"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("swift.findMethodOwners Demo -- viewDidLoad"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("swift.methods Demo -- ViewController viewDidLoad"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("swift.findMethods Demo -- ViewController viewDidLoad"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("swift.findProtocols Renderable"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("swift.findConformances ViewController"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("swift.findMetadata ViewController"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("swift.findVtable ViewController"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("swift.findWitnessTable Renderable"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("swift.findTypeLayout ViewController"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("swift.findSymbols ViewController"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert!(matches!(
            AgentCommand::from_legacy("swift.findMethods ViewController viewDidLoad"),
            Some(AgentCommand::RuntimeDispatch { .. })
        ));
        assert_eq!(
            AgentCommand::from_legacy("jscomplete objc."),
            Some(AgentCommand::JsComplete { prefix: "objc.".into() })
        );
        assert_eq!(AgentCommand::from_legacy("trace UIViewController"), None);
    }

    #[test]
    fn native_find_info_aliases_match_canonical_specs() {
        let alias_pairs = [
            (
                "native.findImageInfo DemoBinary",
                "native.imageInfo DemoBinary",
            ),
            ("native.findSymbolInfo malloc", "native.symbolInfo malloc"),
            (
                "native.findSymbolInfo DemoBinary -- malloc",
                "native.symbolInfo DemoBinary -- malloc",
            ),
            (
                "native.findExportInfo DemoBinary -- malloc",
                "native.exportInfo DemoBinary -- malloc",
            ),
            (
                "native.findDependencyInfo DemoBinary -- libSystem.B.dylib",
                "native.dependencyInfo DemoBinary -- libSystem.B.dylib",
            ),
            (
                "native.findRpathInfo DemoBinary -- @loader_path",
                "native.rpathInfo DemoBinary -- @loader_path",
            ),
            (
                "native.findImportInfo DemoBinary -- malloc",
                "native.importInfo DemoBinary -- malloc",
            ),
            (
                "native.findSegmentInfo DemoBinary -- __TEXT",
                "native.segmentInfo DemoBinary -- __TEXT",
            ),
            (
                "native.findSectionInfo DemoBinary -- __TEXT __text",
                "native.sectionInfo DemoBinary -- __TEXT __text",
            ),
            (
                "native.findLoadCommandInfo DemoBinary -- LC_UUID",
                "native.loadCommandInfo DemoBinary -- LC_UUID",
            ),
            ("native.findDyldInfo DemoBinary", "native.dyldInfo DemoBinary"),
        ];

        for (alias, canonical) in alias_pairs {
            assert_eq!(
                AgentCommand::from_legacy(alias),
                AgentCommand::from_legacy(canonical),
                "alias {alias:?} should match canonical {canonical:?}"
            );
        }
    }

    #[test]
    fn objc_find_aliases_match_canonical_specs() {
        let alias_pairs = [
            ("objc.findClasses UIView", "objc.classes UIView"),
            ("objc.findProtocols NS", "objc.protocols NS"),
            (
                "objc.findClassProtocols UIViewController UI",
                "objc.classProtocols UIViewController UI",
            ),
            (
                "objc.findClassInfo UIViewController meta",
                "objc.classInfo UIViewController meta",
            ),
            ("objc.findProtocolInfo NSObject", "objc.protocolInfo NSObject"),
            (
                "objc.findProtocolProtocols NSObject NS",
                "objc.protocolProtocols NSObject NS",
            ),
            (
                "objc.findProtocolMethods NSObject optional class description",
                "objc.protocolMethods NSObject optional class description",
            ),
            (
                "objc.findProtocolMethodInfo NSObject description optional class",
                "objc.protocolMethodInfo NSObject description optional class",
            ),
            (
                "objc.findProtocolProperties NSObject description",
                "objc.protocolProperties NSObject description",
            ),
            (
                "objc.findProtocolPropertyInfo NSObject description",
                "objc.protocolPropertyInfo NSObject description",
            ),
            ("objc.findSuperclass UIViewController", "objc.superclass UIViewController"),
            ("objc.findClassChain UIViewController", "objc.classChain UIViewController"),
            (
                "objc.findMethodInfo UIViewController viewDidLoad",
                "objc.methodInfo UIViewController viewDidLoad",
            ),
            ("objc.findClassImage UIViewController", "objc.classImage UIViewController"),
            (
                "objc.findMethodImage UIViewController viewDidLoad",
                "objc.methodImage UIViewController viewDidLoad",
            ),
            (
                "objc.findPropertyInfo UIViewController view",
                "objc.propertyInfo UIViewController view",
            ),
            (
                "objc.findIvarInfo UIViewController _viewControllerFlags",
                "objc.ivarInfo UIViewController _viewControllerFlags",
            ),
            ("objc.findSelectorName 0x1234", "objc.selectorName 0x1234"),
            (
                "objc.findObjectClassName 0x1234",
                "objc.objectClassName 0x1234",
            ),
            ("objc.findMethods UIViewController viewDidLoad", "objc.methods UIViewController viewDidLoad"),
            ("objc.findProperties UIViewController view", "objc.properties UIViewController view"),
            ("objc.findIvars UIViewController view", "objc.ivars UIViewController view"),
            ("objc.findMethodOwners viewDidLoad", "objc.methodOwners viewDidLoad"),
        ];

        for (alias, canonical) in alias_pairs {
            assert_eq!(
                AgentCommand::from_legacy(alias),
                AgentCommand::from_legacy(canonical),
                "alias {alias:?} should match canonical {canonical:?}"
            );
        }
    }

    #[test]
    fn swift_find_aliases_match_canonical_specs() {
        let alias_pairs = [
            ("swift.findSymbols ViewController", "swift.symbols ViewController"),
            ("swift.findProtocols Renderable", "swift.protocols Renderable"),
            (
                "swift.findConformances ViewController",
                "swift.conformances ViewController",
            ),
            ("swift.findMetadata ViewController", "swift.metadata ViewController"),
            ("swift.findVtable ViewController", "swift.vtable ViewController"),
            ("swift.findWitnessTable Renderable", "swift.witnessTable Renderable"),
            ("swift.findTypeLayout ViewController", "swift.typeLayout ViewController"),
            ("swift.findTypes ViewController", "swift.types ViewController"),
            (
                "swift.findTypesOfKind metadata-accessor ViewController",
                "swift.typesOfKind metadata-accessor ViewController",
            ),
            (
                "swift.findMethodOwners viewDidLoad",
                "swift.methodOwners viewDidLoad",
            ),
            ("swift.findTypeMethods ViewController", "swift.typeMethods ViewController"),
            (
                "swift.findMethods ViewController viewDidLoad",
                "swift.methods ViewController viewDidLoad",
            ),
            ("swift.findProtocolInfo Renderable", "swift.protocolInfo Renderable"),
            (
                "swift.findConformanceInfo ViewController Renderable",
                "swift.conformanceInfo ViewController Renderable",
            ),
            ("swift.findTypeInfo ViewController", "swift.typeInfo ViewController"),
            (
                "swift.findMethodInfo ViewController viewDidLoad",
                "swift.methodInfo ViewController viewDidLoad",
            ),
            ("swift.findMetadataInfo ViewController", "swift.metadataInfo ViewController"),
            (
                "swift.findVtableInfo ViewController viewDidLoad",
                "swift.vtableInfo ViewController viewDidLoad",
            ),
            (
                "swift.findWitnessTableInfo ViewController Renderable",
                "swift.witnessTableInfo ViewController Renderable",
            ),
            (
                "swift.findTypeLayoutInfo ViewController",
                "swift.typeLayoutInfo ViewController",
            ),
            ("swift.findSymbolInfo ViewController", "swift.symbolInfo ViewController"),
            (
                "swift.findProtocolInfo Demo -- Renderable",
                "swift.protocolInfo Demo -- Renderable",
            ),
            (
                "swift.findConformanceInfo Demo -- ViewController Renderable",
                "swift.conformanceInfo Demo -- ViewController Renderable",
            ),
            (
                "swift.findTypeInfo Demo -- ViewController",
                "swift.typeInfo Demo -- ViewController",
            ),
            (
                "swift.findMethodInfo Demo -- ViewController viewDidLoad",
                "swift.methodInfo Demo -- ViewController viewDidLoad",
            ),
            (
                "swift.findMetadataInfo Demo -- ViewController",
                "swift.metadataInfo Demo -- ViewController",
            ),
            (
                "swift.findVtableInfo Demo -- ViewController viewDidLoad",
                "swift.vtableInfo Demo -- ViewController viewDidLoad",
            ),
            (
                "swift.findWitnessTableInfo Demo -- ViewController Renderable",
                "swift.witnessTableInfo Demo -- ViewController Renderable",
            ),
            (
                "swift.findTypeLayoutInfo Demo -- ViewController",
                "swift.typeLayoutInfo Demo -- ViewController",
            ),
            (
                "swift.findSymbolInfo Demo -- ViewController",
                "swift.symbolInfo Demo -- ViewController",
            ),
            ("swift.findSymbols Demo -- ViewController", "swift.symbols Demo -- ViewController"),
            ("swift.findProtocols Demo -- Renderable", "swift.protocols Demo -- Renderable"),
            (
                "swift.findConformances Demo -- ViewController",
                "swift.conformances Demo -- ViewController",
            ),
            ("swift.findMetadata Demo -- ViewController", "swift.metadata Demo -- ViewController"),
            ("swift.findVtable Demo -- ViewController", "swift.vtable Demo -- ViewController"),
            (
                "swift.findWitnessTable Demo -- Renderable",
                "swift.witnessTable Demo -- Renderable",
            ),
            (
                "swift.findTypeLayout Demo -- ViewController",
                "swift.typeLayout Demo -- ViewController",
            ),
            ("swift.findTypes Demo -- ViewController", "swift.types Demo -- ViewController"),
            (
                "swift.findTypesOfKind Demo -- metadata-accessor ViewController",
                "swift.typesOfKind Demo -- metadata-accessor ViewController",
            ),
            (
                "swift.findMethodOwners Demo -- viewDidLoad",
                "swift.methodOwners Demo -- viewDidLoad",
            ),
            (
                "swift.findTypeMethods Demo -- ViewController",
                "swift.typeMethods Demo -- ViewController",
            ),
            (
                "swift.findMethods Demo -- ViewController viewDidLoad",
                "swift.methods Demo -- ViewController viewDidLoad",
            ),
        ];

        for (alias, canonical) in alias_pairs {
            assert_eq!(
                AgentCommand::from_legacy(alias),
                AgentCommand::from_legacy(canonical),
                "alias {alias:?} should match canonical {canonical:?}"
            );
        }
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
            AgentCommand::from_legacy("swift.methodInfo ViewController"),
            Some(AgentCommand::RuntimeHandle {
                command: "swift.methodInfo ViewController".into(),
            })
        );
        assert_eq!(
            AgentCommand::from_legacy("swift.metadataInfo "),
            Some(AgentCommand::RuntimeHandle {
                command: "swift.metadataInfo ".into(),
            })
        );
        assert_eq!(
            AgentCommand::from_legacy("swift.symbolInfo "),
            Some(AgentCommand::RuntimeHandle {
                command: "swift.symbolInfo ".into(),
            })
        );
        assert_eq!(
            AgentCommand::from_legacy("swift.witnessTableInfo ViewController"),
            Some(AgentCommand::RuntimeHandle {
                command: "swift.witnessTableInfo ViewController".into(),
            })
        );
        assert_eq!(
            AgentCommand::from_legacy("native.export  "),
            Some(AgentCommand::RuntimeHandle {
                command: "native.export  ".into(),
            })
        );
        assert_eq!(
            AgentCommand::from_legacy("native.imageInfo  "),
            Some(AgentCommand::RuntimeHandle {
                command: "native.imageInfo  ".into(),
            })
        );
        assert_eq!(
            AgentCommand::from_legacy("native.symbolInfo "),
            Some(AgentCommand::RuntimeHandle {
                command: "native.symbolInfo ".into(),
            })
        );
        assert_eq!(
            AgentCommand::from_legacy("native.exportInfo libsystem_malloc.dylib"),
            Some(AgentCommand::RuntimeHandle {
                command: "native.exportInfo libsystem_malloc.dylib".into(),
            })
        );
        assert_eq!(
            AgentCommand::from_legacy("native.imports  "),
            Some(AgentCommand::RuntimeHandle {
                command: "native.imports  ".into(),
            })
        );
        assert_eq!(
            AgentCommand::from_legacy("native.importInfo libsystem_malloc.dylib"),
            Some(AgentCommand::RuntimeHandle {
                command: "native.importInfo libsystem_malloc.dylib".into(),
            })
        );
        assert_eq!(
            AgentCommand::from_legacy("native.dependencies  "),
            Some(AgentCommand::RuntimeHandle {
                command: "native.dependencies  ".into(),
            })
        );
        assert_eq!(
            AgentCommand::from_legacy("native.dependencyInfo libsystem_malloc.dylib"),
            Some(AgentCommand::RuntimeHandle {
                command: "native.dependencyInfo libsystem_malloc.dylib".into(),
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
            AgentCommand::from_legacy("objc.protocolInfo  "),
            Some(AgentCommand::RuntimeHandle {
                command: "objc.protocolInfo  ".into(),
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
        assert_eq!(
            AgentCommand::from_legacy("native.rpathInfo libsystem_malloc.dylib"),
            Some(AgentCommand::RuntimeHandle {
                command: "native.rpathInfo libsystem_malloc.dylib".into(),
            })
        );
        assert_eq!(
            AgentCommand::from_legacy("native.loadCommandInfo libsystem_malloc.dylib"),
            Some(AgentCommand::RuntimeHandle {
                command: "native.loadCommandInfo libsystem_malloc.dylib".into(),
            })
        );
        assert_eq!(
            AgentCommand::from_legacy("native.sectionInfo libsystem_malloc.dylib -- __TEXT"),
            Some(AgentCommand::RuntimeHandle {
                command: "native.sectionInfo libsystem_malloc.dylib -- __TEXT".into(),
            })
        );
        assert_eq!(
            AgentCommand::from_legacy("native.segmentInfo libsystem_malloc.dylib"),
            Some(AgentCommand::RuntimeHandle {
                command: "native.segmentInfo libsystem_malloc.dylib".into(),
            })
        );
    }
}
