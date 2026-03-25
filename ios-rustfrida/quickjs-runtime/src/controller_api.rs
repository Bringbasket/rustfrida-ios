pub(crate) fn bootstrap_controller_api() -> &'static str {
    r#"globalThis.__iosRustFridaControllerApi = globalThis.__iosRustFridaControllerApi || (function() {
function renderResult(result) {
    if (result && typeof result === 'object') {
        switch (String(result.kind || '')) {
        case 'hfl.status':
            return renderHflStatus(result);
        case 'objc.hook.status':
            return renderObjcHookStatus(result);
        case 'trace.status':
            return renderTraceStatus(result);
        case 'stalker.status':
            return renderStalkerStatus(result);
        case 'swift.hook.status':
            return renderSwiftHookStatus(result);
        default:
            break;
        }
    }
    return result && result.message !== undefined ? String(result.message) : String(result);
}

function appendDetail(parts, label, value) {
    if (value === null || value === undefined || value === '') {
        return;
    }
    parts.push(label + '=' + String(value));
}

function renderTargetListStatus(result, entries) {
    if (!result || !result.active) {
        return result && result.message !== undefined ? String(result.message) : String(result);
    }
    const lines = [String(result.message)];
    for (const entry of entries) {
        lines.push(' - ' + entry);
    }
    return lines.join('\n');
}

function renderHflStatus(result) {
    return renderTargetListStatus(
        result,
        Array.isArray(result.targets)
            ? result.targets.map((target) => {
                const parts = [String(target && target.key !== undefined ? target.key : '<unknown>')];
                appendDetail(parts, 'target', target ? target.target : null);
                return parts.join(' ');
            })
            : []
    );
}

function renderObjcHookStatus(result) {
    return renderTargetListStatus(
        result,
        Array.isArray(result.targets)
            ? result.targets.map((target) => {
                const parts = [String(target && target.key !== undefined ? target.key : '<unknown>')];
                appendDetail(parts, 'target', target ? target.target : null);
                return parts.join(' ');
            })
            : []
    );
}

function renderTraceLikeStatus(result, includeSecondaryTarget, includeSuperEnabled) {
    if (!result || !result.active) {
        return result && result.message !== undefined ? String(result.message) : String(result);
    }
    const detailParts = [];
    appendDetail(detailParts, 'target', result.targetAddress);
    if (includeSecondaryTarget) {
        appendDetail(detailParts, 'secondary', result.secondaryTargetAddress);
    }
    appendDetail(detailParts, 'kind', result.targetKind);
    appendDetail(detailParts, 'symbol', result.targetSymbol);
    appendDetail(detailParts, 'module', result.moduleName);
    appendDetail(detailParts, 'filter', result.filter);
    appendDetail(detailParts, 'objcMode', result.objcMode);
    if (includeSuperEnabled) {
        detailParts.push('super=' + (result.superEnabled ? 'on' : 'off'));
    }
    if (detailParts.length === 0) {
        return String(result.message);
    }
    return String(result.message) + '\n - ' + detailParts.join(' ');
}

function renderTraceStatus(result) {
    return renderTraceLikeStatus(result, false, false);
}

function renderStalkerStatus(result) {
    return renderTraceLikeStatus(result, true, true);
}

function renderSwiftHookStatus(result) {
    if (!result || !result.active) {
        return result && result.message !== undefined ? String(result.message) : String(result);
    }
    const lines = [String(result.message)];
    const entries = Array.isArray(result.targets) ? result.targets : [];
    for (const entry of entries) {
        const parts = [String(entry && entry.key !== undefined ? entry.key : '<unknown>')];
        appendDetail(parts, 'count', entry ? entry.count : null);
        lines.push(' - ' + parts.join(' '));
        const targets = entry && Array.isArray(entry.targets) ? entry.targets : [];
        for (const target of targets) {
            const targetParts = [];
            appendDetail(targetParts, 'address', target ? target.address : null);
            appendDetail(
                targetParts,
                'name',
                target && target.demangledName !== null && target.demangledName !== undefined
                    ? target.demangledName
                    : target
                        ? target.name
                        : null
            );
            appendDetail(targetParts, 'module', target ? target.moduleName : null);
            if (targetParts.length !== 0) {
                lines.push('   - ' + targetParts.join(' '));
            }
        }
    }
    return lines.join('\n');
}

function hflEntryToTarget(key, entry) {
    if (entry === null || typeof entry !== 'object') {
        return { key, moduleName: null, offsetHex: null, target: null };
    }
    return {
        key,
        moduleName: entry.moduleName === undefined ? null : entry.moduleName,
        offsetHex: entry.offsetHex === undefined ? null : entry.offsetHex,
        target: entry.target === undefined ? null : entry.target,
    };
}

function objcHookEntryToTarget(key, entry) {
    if (entry === null || typeof entry !== 'object') {
        return {
            key,
            className: null,
            selectorName: null,
            isClassMethod: null,
            target: null,
        };
    }
    return {
        key,
        className: entry.className === undefined ? null : entry.className,
        selectorName: entry.selectorName === undefined ? null : entry.selectorName,
        isClassMethod: entry.isClassMethod === undefined ? null : !!entry.isClassMethod,
        target: entry.target === undefined ? null : entry.target,
    };
}

function swiftHookEntryToTarget(key, entry) {
    if (entry === null || typeof entry !== 'object') {
        return {
            key,
            moduleName: null,
            typeName: null,
            methodQuery: null,
            count: 0,
            targets: [],
        };
    }
    return {
        key,
        moduleName: entry.moduleName === undefined ? null : entry.moduleName,
        typeName: entry.typeName === undefined ? null : entry.typeName,
        methodQuery: entry.methodQuery === undefined ? null : entry.methodQuery,
        count: Array.isArray(entry.targets) ? entry.targets.length : 0,
        targets: Array.isArray(entry.targets) ? entry.targets : [],
    };
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
    if (existing && existing.handle && typeof existing.handle.detach === 'function') {
        try { existing.handle.detach(); } catch (_) {}
    }
    const handle = Interceptor.attach(target, {
        onEnter(ctx) {
            console.log('[hfl] hit ' + key + ' target=' + target.toString() + ' x0=' + ctx.x0.toString() + ' x1=' + ctx.x1.toString() + ' x2=' + ctx.x2.toString() + ' x3=' + ctx.x3.toString());
        },
        onLeave(ctx) {
            console.log('[hfl] ret ' + key + ' x0=' + ctx.x0.toString());
        }
    });
    globalThis.__iosRustFridaHfl[key] = { handle, moduleName, offsetHex, target: target.toString() };
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

function currentHflHooksResult() {
    const state = globalThis.__iosRustFridaHfl || {};
    const keys = Object.keys(state);
    const targets = keys.map((key) => hflEntryToTarget(key, state[key]));
    return {
        kind: 'hfl.status',
        action: 'status',
        active: keys.length !== 0,
        count: keys.length,
        keys,
        targets,
        message: keys.length === 0 ? 'hfl inactive' : ('hfl active: ' + keys.length),
    };
}

function detachHflHooksResult() {
    const state = globalThis.__iosRustFridaHfl || {};
    const keys = Object.keys(state);
    const targets = keys.map((key) => hflEntryToTarget(key, state[key]));
    let count = 0;
    for (const key of keys) {
        const entry = state[key];
        const handle = entry && typeof entry === 'object' ? entry.handle : entry;
        if (handle && typeof handle.detach === 'function') {
            try { handle.detach(); count++; } catch (_) {}
        }
    }
    globalThis.__iosRustFridaHfl = {};
    return {
        kind: 'hfl.stop',
        action: 'stop',
        scope: 'hfl',
        active: keys.length !== 0,
        count,
        keys,
        targets,
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
    if (existing && existing.handle && typeof existing.handle.detach === 'function') {
        try { existing.handle.detach(); } catch (_) {}
    }
    const handle = Interceptor.attach(imp, {
        onEnter(ctx) {
            console.log('[jhook] enter ' + key + ' self=' + ctx.x0.toString() + ' _cmd=' + ctx.x1.toString() + ' x2=' + ctx.x2.toString() + ' x3=' + ctx.x3.toString());
        },
        onLeave(ctx) {
            console.log('[jhook] leave ' + key + ' ret=' + ctx.x0.toString());
        }
    });
    globalThis.__iosRustFridaObjcHooks[key] = {
        handle,
        className,
        selectorName,
        isClassMethod: !!isClassMethod,
        target: imp.toString(),
    };
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

function currentObjcHooksResult() {
    const state = globalThis.__iosRustFridaObjcHooks || {};
    const keys = Object.keys(state);
    const targets = keys.map((key) => objcHookEntryToTarget(key, state[key]));
    return {
        kind: 'objc.hook.status',
        action: 'status',
        active: keys.length !== 0,
        count: keys.length,
        keys,
        targets,
        message: keys.length === 0 ? 'jhook inactive' : ('jhook active: ' + keys.length),
    };
}

function detachObjcHooksResult() {
    const state = globalThis.__iosRustFridaObjcHooks || {};
    const keys = Object.keys(state);
    const targets = keys.map((key) => objcHookEntryToTarget(key, state[key]));
    let count = 0;
    for (const key of keys) {
        const entry = state[key];
        const handle = entry && typeof entry === 'object' ? entry.handle : entry;
        if (handle && typeof handle.detach === 'function') {
            try { handle.detach(); count++; } catch (_) {}
        }
    }
    globalThis.__iosRustFridaObjcHooks = {};
    return {
        kind: 'objc.hook.stop',
        action: 'stop',
        scope: 'objc-hook',
        active: keys.length !== 0,
        count,
        keys,
        targets,
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

function currentObjcTraceResult() {
    const result = requireNativeHookHelpers().currentTraceStateResult();
    result.kind = 'trace.status';
    result.action = 'status';
    result.scope = 'trace';
    return result;
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

function currentObjcStalkerResult() {
    const result = requireNativeHookHelpers().currentStalkerStateResult();
    result.kind = 'stalker.status';
    result.action = 'status';
    result.scope = 'stalker';
    return result;
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

function traceStatus() {
    return renderResult(currentObjcTraceResult());
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

function stalkerStatus() {
    return renderResult(currentObjcStalkerResult());
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
    if (existing && Array.isArray(existing.handles)) {
        for (const handle of existing.handles) {
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

    const targets = matches.map((match) => ({
        address: match.address.toString(),
        name: match.name === undefined ? null : match.name,
        demangledName: match.demangledName === undefined ? null : match.demangledName,
        moduleName: match.moduleName === undefined ? null : match.moduleName,
    }));
    globalThis.__iosRustFridaSwiftHooks[key] = {
        handles,
        moduleName: moduleName === null || moduleName === undefined ? null : moduleName,
        typeName,
        methodQuery,
        targets,
    };
    return {
        kind: 'swift.hook.install',
        action: 'install',
        moduleName: moduleName === null || moduleName === undefined ? null : moduleName,
        typeName,
        methodQuery,
        key,
        count: matches.length,
        targets,
        message: 'shook installed: ' + key + ' count=' + matches.length + ' (hook logs flush on the next JS command)',
    };
}

function installSwiftHook(typeName, methodQuery, moduleName) {
    return renderResult(installSwiftHookResult(typeName, methodQuery, moduleName));
}

function currentSwiftHooksResult() {
    const state = globalThis.__iosRustFridaSwiftHooks || {};
    const keys = Object.keys(state);
    const targets = keys.map((key) => swiftHookEntryToTarget(key, state[key]));
    return {
        kind: 'swift.hook.status',
        action: 'status',
        active: keys.length !== 0,
        count: targets.reduce((sum, item) => sum + item.count, 0),
        keys,
        targets,
        message: keys.length === 0 ? 'shook inactive' : ('shook active: ' + keys.length),
    };
}

function detachSwiftHooksResult() {
    const state = globalThis.__iosRustFridaSwiftHooks || {};
    const keys = Object.keys(state);
    const targets = keys.map((key) => swiftHookEntryToTarget(key, state[key]));
    let count = 0;
    for (const key of keys) {
        const entry = state[key];
        const handles = entry && Array.isArray(entry.handles) ? entry.handles : [];
        if (handles.length === 0) {
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
        active: keys.length !== 0,
        count,
        keys,
        targets,
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
    case 'hfl.status':
        return currentHflHooksResult();
    case 'hfl.stop':
        return detachHflHooksResult();
    case 'objc.hook.install':
        return installObjcHookResult(String(command.className), String(command.selectorName), !!command.isClassMethod);
    case 'objc.hook.status':
        return currentObjcHooksResult();
    case 'objc.hook.stop':
        return detachObjcHooksResult();
    case 'objc.trace.install':
        return installObjcTraceResult(command.filter === undefined ? '' : String(command.filter));
    case 'trace.status':
        return currentObjcTraceResult();
    case 'objc.stalker.install':
        return installObjcStalkerResult(command.filter === undefined ? '' : String(command.filter));
    case 'stalker.status':
        return currentObjcStalkerResult();
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
    case 'swift.hook.status':
        return currentSwiftHooksResult();
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
    traceStatus,
    stopStalker,
    stalkerStatus,
    installSwiftHook,
    detachSwiftHooks,
};
})();
"#
}
