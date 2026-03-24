pub(crate) fn bootstrap_controller_api() -> &'static str {
    r#"globalThis.__iosRustFridaControllerApi = globalThis.__iosRustFridaControllerApi || (function() {
function renderResult(result) {
    return result && result.message !== undefined ? String(result.message) : String(result);
}

function installHflResult(moduleName, offsetHex) {
    globalThis.__iosRustFridaHfl = globalThis.__iosRustFridaHfl || {};
    const key = moduleName + '+' + offsetHex;
    const base = Module.findBaseAddress(moduleName);
    if (base === null) {
        throw new Error('module not found: ' + moduleName);
    }
    const target = base.add(offsetHex);
    const existing = globalThis.__iosRustFridaHfl[key];
    if (existing && typeof existing.detach === 'function') {
        try { existing.detach(); } catch (_) {}
    }
    const handle = Interceptor.attach(target, {
        onEnter(ctx) {
            console.log('[hfl] hit ' + key + ' target=' + target.toString() + ' x0=' + ctx.x0.toString() + ' x1=' + ctx.x1.toString() + ' x2=' + ctx.x2.toString() + ' x3=' + ctx.x3.toString());
        },
        onLeave(ctx) {
            console.log('[hfl] ret ' + key + ' x0=' + ctx.x0.toString());
        }
    });
    globalThis.__iosRustFridaHfl[key] = handle;
    return {
        kind: 'hfl.install',
        action: 'install',
        moduleName,
        offsetHex,
        key,
        target: target.toString(),
        message: 'hfl installed: ' + key + ' => ' + target.toString() + ' (hook logs flush on the next JS command)',
    };
}

function installHfl(moduleName, offsetHex) {
    return renderResult(installHflResult(moduleName, offsetHex));
}

function detachHflHooksResult() {
    const state = globalThis.__iosRustFridaHfl || {};
    let count = 0;
    for (const key of Object.keys(state)) {
        const handle = state[key];
        if (handle && typeof handle.detach === 'function') {
            try { handle.detach(); count++; } catch (_) {}
        }
    }
    globalThis.__iosRustFridaHfl = {};
    return {
        kind: 'hfl.stop',
        action: 'stop',
        scope: 'hfl',
        count,
        message: 'hfl detached: ' + count,
    };
}

function detachHflHooks() {
    return renderResult(detachHflHooksResult());
}

function installObjcHookResult(className, selectorName, isClassMethod) {
    const prefix = isClassMethod ? '+' : '-';
    if (!ObjC.classExists(className)) {
        throw new Error('class not found: ' + className);
    }
    const imp = ObjC.methodImp(className, selectorName, isClassMethod);
    if (imp === null) {
        throw new Error('method not found: ' + prefix + '[' + className + ' ' + selectorName + ']');
    }
    globalThis.__iosRustFridaObjcHooks = globalThis.__iosRustFridaObjcHooks || {};
    const key = prefix + '[' + className + ' ' + selectorName + ']';
    const existing = globalThis.__iosRustFridaObjcHooks[key];
    if (existing && typeof existing.detach === 'function') {
        try { existing.detach(); } catch (_) {}
    }
    const handle = Interceptor.attach(imp, {
        onEnter(ctx) {
            console.log('[jhook] enter ' + key + ' self=' + ctx.x0.toString() + ' _cmd=' + ctx.x1.toString() + ' x2=' + ctx.x2.toString() + ' x3=' + ctx.x3.toString());
        },
        onLeave(ctx) {
            console.log('[jhook] leave ' + key + ' ret=' + ctx.x0.toString());
        }
    });
    globalThis.__iosRustFridaObjcHooks[key] = handle;
    return {
        kind: 'objc.hook.install',
        action: 'install',
        className,
        selectorName,
        isClassMethod: !!isClassMethod,
        key,
        target: imp.toString(),
        message: 'jhook installed: ' + key + ' => ' + imp.toString() + ' (hook logs flush on the next JS command)',
    };
}

function installObjcHook(className, selectorName, isClassMethod) {
    return renderResult(installObjcHookResult(className, selectorName, isClassMethod));
}

function detachObjcHooksResult() {
    const state = globalThis.__iosRustFridaObjcHooks || {};
    let count = 0;
    for (const key of Object.keys(state)) {
        const handle = state[key];
        if (handle && typeof handle.detach === 'function') {
            try { handle.detach(); count++; } catch (_) {}
        }
    }
    globalThis.__iosRustFridaObjcHooks = {};
    return {
        kind: 'objc.hook.stop',
        action: 'stop',
        scope: 'objc-hook',
        count,
        message: 'jhook detached: ' + count,
    };
}

function detachObjcHooks() {
    return renderResult(detachObjcHooksResult());
}

function requireNativeHookHelpers() {
    const helper = globalThis.__iosRustFridaNativeHooks;
    if (!helper) {
        throw new Error('native hook helpers are not initialized; run jsinit first');
    }
    return helper;
}

function installObjcTraceResult(filter) {
    const helper = requireNativeHookHelpers();
    const spec = {
        kind: 'export',
        moduleName: null,
        symbolName: 'objc_msgSend',
        templateArgs: null,
        templateRet: null,
        objcFilter: String(filter || ''),
        objcMode: 'trace',
    };
    const result = helper.installTraceResult(spec);
    result.kind = 'objc.trace.install';
    return result;
}

function installObjcTrace(filter) {
    return renderResult(installObjcTraceResult(filter));
}

function installObjcStalkerResult(filter) {
    const helper = requireNativeHookHelpers();
    const spec = {
        kind: 'export',
        moduleName: null,
        symbolName: 'objc_msgSend',
        templateArgs: null,
        templateRet: null,
        objcFilter: String(filter || ''),
        objcMode: 'stalker',
    };
    const result = helper.installStalkerResult(spec);
    result.kind = 'objc.stalker.install';
    return result;
}

function installObjcStalker(filter) {
    return renderResult(installObjcStalkerResult(filter));
}

function buildNativeSpec(kind, moduleName, symbolName, address, templateArgs, templateRet) {
    const spec = {
        kind,
        templateArgs: templateArgs || null,
        templateRet: templateRet || null,
    };
    if (kind === 'export') {
        spec.moduleName = moduleName;
        spec.symbolName = symbolName;
    } else if (kind === 'address') {
        spec.address = address;
    } else {
        throw new Error('unsupported native controller target kind: ' + String(kind));
    }
    return spec;
}

function installNativeTraceResult(spec) {
    const helper = requireNativeHookHelpers();
    const result = helper.installTraceResult(spec);
    result.kind = 'native.trace.install';
    result.target = spec;
    return result;
}

function installNativeTrace(spec) {
    return renderResult(installNativeTraceResult(spec));
}

function installNativeTraceExport(moduleName, symbolName, templateArgs, templateRet) {
    return installNativeTrace(buildNativeSpec('export', moduleName, symbolName, null, templateArgs, templateRet));
}

function installNativeTraceAddress(address, templateArgs, templateRet) {
    return installNativeTrace(buildNativeSpec('address', null, null, address, templateArgs, templateRet));
}

function installNativeStalkerResult(spec) {
    const helper = requireNativeHookHelpers();
    const result = helper.installStalkerResult(spec);
    result.kind = 'native.stalker.install';
    result.target = spec;
    return result;
}

function installNativeStalker(spec) {
    return renderResult(installNativeStalkerResult(spec));
}

function installNativeStalkerExport(moduleName, symbolName, templateArgs, templateRet) {
    return installNativeStalker(buildNativeSpec('export', moduleName, symbolName, null, templateArgs, templateRet));
}

function installNativeStalkerAddress(address, templateArgs, templateRet) {
    return installNativeStalker(buildNativeSpec('address', null, null, address, templateArgs, templateRet));
}

function stopTraceResult() {
    const result = requireNativeHookHelpers().stopTraceResult();
    result.kind = 'trace.stop';
    result.action = 'stop';
    result.scope = 'trace';
    return result;
}

function stopTrace() {
    return renderResult(stopTraceResult());
}

function stopStalkerResult() {
    const result = requireNativeHookHelpers().stopStalkerResult();
    result.kind = 'stalker.stop';
    result.action = 'stop';
    result.scope = 'stalker';
    return result;
}

function stopStalker() {
    return renderResult(stopStalkerResult());
}

function installSwiftHookResult(typeName, methodQuery, moduleName) {
    const matches = Swift.findMethods(typeName, methodQuery, moduleName);
    if (!Array.isArray(matches) || matches.length === 0) {
        const scope = moduleName ? (' in ' + moduleName) : '';
        throw new Error('swift method not found: ' + typeName + ' ' + methodQuery + scope);
    }
    globalThis.__iosRustFridaSwiftHooks = globalThis.__iosRustFridaSwiftHooks || {};
    const key = (moduleName || '*') + '::' + typeName + '::' + methodQuery;
    const existing = globalThis.__iosRustFridaSwiftHooks[key];
    if (Array.isArray(existing)) {
        for (const handle of existing) {
            if (handle && typeof handle.detach === 'function') {
                try { handle.detach(); } catch (_) {}
            }
        }
    }

    const handles = [];
    for (const match of matches) {
        const address = match.address;
        const label = (match.demangledName || match.name || (typeName + '.' + methodQuery));
        const handle = Interceptor.attach(address, {
            onEnter(ctx) {
                console.log('[shook] enter ' + label + ' x0=' + ctx.x0.toString() + ' x1=' + ctx.x1.toString() + ' x2=' + ctx.x2.toString() + ' x3=' + ctx.x3.toString());
            },
            onLeave(ctx) {
                console.log('[shook] leave ' + label + ' ret=' + ctx.x0.toString());
            }
        });
        handles.push(handle);
    }

    globalThis.__iosRustFridaSwiftHooks[key] = handles;
    return {
        kind: 'swift.hook.install',
        action: 'install',
        moduleName: moduleName === null || moduleName === undefined ? null : moduleName,
        typeName,
        methodQuery,
        key,
        count: matches.length,
        targets: matches.map((match) => ({
            address: match.address.toString(),
            name: match.name === undefined ? null : match.name,
            demangledName: match.demangledName === undefined ? null : match.demangledName,
            moduleName: match.moduleName === undefined ? null : match.moduleName,
        })),
        message: 'shook installed: ' + key + ' count=' + matches.length + ' (hook logs flush on the next JS command)',
    };
}

function installSwiftHook(typeName, methodQuery, moduleName) {
    return renderResult(installSwiftHookResult(typeName, methodQuery, moduleName));
}

function detachSwiftHooksResult() {
    const state = globalThis.__iosRustFridaSwiftHooks || {};
    let count = 0;
    for (const key of Object.keys(state)) {
        const handles = state[key];
        if (!Array.isArray(handles)) {
            continue;
        }
        for (const handle of handles) {
            if (handle && typeof handle.detach === 'function') {
                try { handle.detach(); count++; } catch (_) {}
            }
        }
    }
    globalThis.__iosRustFridaSwiftHooks = {};
    return {
        kind: 'swift.hook.stop',
        action: 'stop',
        scope: 'swift-hook',
        count,
        message: 'shook detached: ' + count,
    };
}

function detachSwiftHooks() {
    return renderResult(detachSwiftHooksResult());
}

function dispatchResult(command) {
    if (command === null || typeof command !== 'object') {
        throw new Error('controller command spec must be an object');
    }

    switch (String(command.kind || '')) {
    case 'hfl.install':
        return installHflResult(String(command.moduleName), String(command.offsetHex));
    case 'hfl.stop':
        return detachHflHooksResult();
    case 'objc.hook.install':
        return installObjcHookResult(String(command.className), String(command.selectorName), !!command.isClassMethod);
    case 'objc.hook.stop':
        return detachObjcHooksResult();
    case 'objc.trace.install':
        return installObjcTraceResult(command.filter === undefined ? '' : String(command.filter));
    case 'objc.stalker.install':
        return installObjcStalkerResult(command.filter === undefined ? '' : String(command.filter));
    case 'native.trace.install':
        return installNativeTraceResult(command.target);
    case 'native.stalker.install':
        return installNativeStalkerResult(command.target);
    case 'trace.stop':
        return stopTraceResult();
    case 'stalker.stop':
        return stopStalkerResult();
    case 'swift.hook.install':
        return installSwiftHookResult(
            String(command.typeName),
            String(command.methodQuery),
            command.moduleName === null || command.moduleName === undefined ? null : String(command.moduleName)
        );
    case 'swift.hook.stop':
        return detachSwiftHooksResult();
    default:
        throw new Error('unsupported controller command kind: ' + String(command.kind));
    }
}

function dispatch(command) {
    return renderResult(dispatchResult(command));
}

return {
    dispatch,
    dispatchResult,
    installHfl,
    detachHflHooks,
    installObjcHook,
    detachObjcHooks,
    installObjcTrace,
    installObjcStalker,
    installNativeTrace,
    installNativeTraceExport,
    installNativeTraceAddress,
    installNativeStalker,
    installNativeStalkerExport,
    installNativeStalkerAddress,
    stopTrace,
    stopStalker,
    installSwiftHook,
    detachSwiftHooks,
};
})();
"#
}
