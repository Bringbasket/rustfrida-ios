pub(crate) fn bootstrap_native_hooks() -> &'static str {
    r#"globalThis.__iosRustFridaNativeHooks = globalThis.__iosRustFridaNativeHooks || (function() {
const MAX_PREVIEW_STRING = 96;
const IOSRF_O_ACCMODE = 0x3;
const IOSRF_O_FLAG_BITS = [['O_WRONLY', 0x1], ['O_RDWR', 0x2], ['O_NONBLOCK', 0x4], ['O_APPEND', 0x8], ['O_SHLOCK', 0x10], ['O_EXLOCK', 0x20], ['O_ASYNC', 0x40], ['O_FSYNC', 0x80], ['O_NOFOLLOW', 0x100], ['O_CREAT', 0x200], ['O_TRUNC', 0x400], ['O_EXCL', 0x800], ['O_EVTONLY', 0x8000], ['O_NOCTTY', 0x20000], ['O_DIRECTORY', 0x100000], ['O_SYMLINK', 0x200000], ['O_CLOEXEC', 0x1000000]];
const IOSRF_ACCESS_MODE_BITS = [['R_OK', 4], ['W_OK', 2], ['X_OK', 1]];
const IOSRF_RTLD_BITS = [['RTLD_LAZY', 0x1], ['RTLD_NOW', 0x2], ['RTLD_LOCAL', 0x4], ['RTLD_GLOBAL', 0x8], ['RTLD_NOLOAD', 0x10], ['RTLD_NODELETE', 0x80], ['RTLD_FIRST', 0x100]];
function ptrValue(value) { return ptr(value); }
function normalizeSymbolName(name) { if (name === null || name === undefined) { return ''; } let normalized = String(name); while (normalized.startsWith('_')) { normalized = normalized.slice(1); } return normalized; }
function ptrToBigInt(value) { try { const numeric = ptrValue(value).toNumber(); return typeof numeric === 'bigint' ? numeric : BigInt(numeric); } catch (_) { return 0n; } }
function signed(value) { const raw = ptrToBigInt(value) & 0xffffffffffffffffn; return raw > 0x7fffffffffffffffn ? raw - 0x10000000000000000n : raw; }
function hex(value) { return '0x' + ptrToBigInt(value).toString(16); }
function dec(value) { return ptrToBigInt(value).toString(10); }
function symbolLabel(value) { try { const symbol = DebugSymbol.fromAddress(ptrValue(value)); if (symbol === null || symbol.name === null) { return null; } const offset = typeof symbol.offset === 'bigint' ? symbol.offset : BigInt(symbol.offset || 0); const suffix = offset === 0n ? '' : ('+0x' + offset.toString(16)); return symbol.moduleName + '!' + symbol.name + suffix; } catch (_) { return null; } }
function escapeString(value) { return JSON.stringify(value.length > MAX_PREVIEW_STRING ? value.slice(0, MAX_PREVIEW_STRING) + '...' : value); }
function cstringPreview(value) { try { const target = ptrValue(value); if (target.toString() === '0x0') { return null; } const text = Memory.readCString(target); if (text.length === 0) { return '\"\"'; } if (!/^[\x09\x0a\x0d\x20-\x7e]+$/.test(text)) { return null; } return escapeString(text); } catch (_) { return null; } }
function cstringOrPointer(value) { const text = cstringPreview(value); return text !== null ? text : ptrValue(value).toString(); }
function formatMode(value) { return '0o' + (ptrToBigInt(value) & 0xfffn).toString(8); }
function formatFd(value) { const fd = signed(value); if (fd === -2n) { return 'AT_FDCWD'; } return fd.toString(); }
function formatOpenFlags(value) { const raw = Number(ptrToBigInt(value) & 0xffffffffn); const access = ['O_RDONLY', 'O_WRONLY', 'O_RDWR'][raw & IOSRF_O_ACCMODE] || ('ACC=' + String(raw & IOSRF_O_ACCMODE)); const parts = [access]; for (const entry of IOSRF_O_FLAG_BITS) { if ((raw & entry[1]) !== 0 && !(entry[0] === 'O_WRONLY' && (raw & IOSRF_O_ACCMODE) === 1) && !(entry[0] === 'O_RDWR' && (raw & IOSRF_O_ACCMODE) === 2)) { parts.push(entry[0]); } } return parts.join('|') + ' (' + '0x' + raw.toString(16) + ')'; }
function formatAccessMode(value) { const raw = Number(ptrToBigInt(value) & 0xffffffffn); if (raw === 0) { return 'F_OK'; } const parts = []; for (const entry of IOSRF_ACCESS_MODE_BITS) { if ((raw & entry[1]) !== 0) { parts.push(entry[0]); } } return (parts.length === 0 ? String(raw) : parts.join('|')) + ' (' + '0x' + raw.toString(16) + ')'; }
function formatDlopenMode(value) { const raw = Number(ptrToBigInt(value) & 0xffffffffn); const parts = []; for (const entry of IOSRF_RTLD_BITS) { if ((raw & entry[1]) !== 0) { parts.push(entry[0]); } } return (parts.length === 0 ? String(raw) : parts.join('|')) + ' (' + '0x' + raw.toString(16) + ')'; }
function describePointerValue(value) { const target = ptrValue(value); let rendered = target.toString(); const label = symbolLabel(value); if (label !== null) { rendered += '<' + label + '>'; } const cstring = cstringPreview(value); if (cstring !== null) { rendered += ' str=' + cstring; } return rendered; }
function formatTypedValue(kind, value) { switch (kind) { case 'ptr': return describePointerValue(value); case 'cstr': return cstringOrPointer(value); case 'fd': return formatFd(value); case 'openflags': return formatOpenFlags(value); case 'access': return formatAccessMode(value); case 'mode': return formatMode(value); case 'int': case 'ssize': return signed(value).toString(); case 'uint': case 'size': return dec(value); case 'hex': return hex(value); default: return describePointerValue(value); } }
function formatRegister(name, value) { return name + '=' + describePointerValue(value); }
function formatRegisters(ctx, names) { const parts = []; for (const name of names) { parts.push(formatRegister(name, ctx[name])); } return parts.join(' '); }
function formatTemplateArgs(ctx, template) { if (!Array.isArray(template) || template.length === 0) { return null; } const parts = []; for (let i = 0; i < template.length; i++) { const spec = template[i]; const label = spec && typeof spec.label === 'string' && spec.label.length !== 0 ? spec.label : ('x' + i); const kind = spec && typeof spec.kind === 'string' ? spec.kind : 'ptr'; parts.push(label + '=' + formatTypedValue(kind, ctx['x' + i])); } return parts; }
function formatTemplateReturn(ctx, spec) { if (!spec || typeof spec !== 'object') { return null; } const label = typeof spec.label === 'string' && spec.label.length !== 0 ? spec.label : 'result'; const kind = typeof spec.kind === 'string' ? spec.kind : 'ptr'; return label + '=' + formatTypedValue(kind, ctx.x0); }
function describeCall(symbolName, ctx) { switch (normalizeSymbolName(symbolName)) { case 'open': case 'open$NOCANCEL': return ['path=' + cstringOrPointer(ctx.x0), 'flags=' + formatOpenFlags(ctx.x1), 'mode=' + formatMode(ctx.x2)]; case 'openat': case 'openat$NOCANCEL': return ['dirfd=' + formatFd(ctx.x0), 'path=' + cstringOrPointer(ctx.x1), 'flags=' + formatOpenFlags(ctx.x2), 'mode=' + formatMode(ctx.x3)]; case 'access': case 'faccessat': return ['path=' + cstringOrPointer(ctx.x0), 'mode=' + formatAccessMode(ctx.x1)]; case 'chdir': case 'mkdir': case 'rmdir': case 'unlink': case 'remove': return ['path=' + cstringOrPointer(ctx.x0)]; case 'rename': return ['old=' + cstringOrPointer(ctx.x0), 'new=' + cstringOrPointer(ctx.x1)]; case 'chmod': return ['path=' + cstringOrPointer(ctx.x0), 'mode=' + formatMode(ctx.x1)]; case 'stat': case 'lstat': return ['path=' + cstringOrPointer(ctx.x0), 'buf=' + formatRegister('x1', ctx.x1)]; case 'read': return ['fd=' + formatFd(ctx.x0), 'buf=' + formatRegister('x1', ctx.x1), 'count=' + dec(ctx.x2)]; case 'write': return ['fd=' + formatFd(ctx.x0), 'buf=' + formatRegister('x1', ctx.x1), 'count=' + dec(ctx.x2)]; case 'dlopen': return ['path=' + cstringOrPointer(ctx.x0), 'mode=' + formatDlopenMode(ctx.x1)]; case 'dlsym': return ['handle=' + formatRegister('x0', ctx.x0), 'symbol=' + cstringOrPointer(ctx.x1)]; case 'objc_getClass': case 'objc_lookUpClass': case 'sel_registerName': return ['name=' + cstringOrPointer(ctx.x0)]; case 'malloc': return ['size=' + dec(ctx.x0)]; case 'calloc': return ['count=' + dec(ctx.x0), 'size=' + dec(ctx.x1), 'total=' + (ptrToBigInt(ctx.x0) * ptrToBigInt(ctx.x1)).toString(10)]; case 'realloc': return ['ptr=' + formatRegister('x0', ctx.x0), 'size=' + dec(ctx.x1)]; case 'free': return ['ptr=' + formatRegister('x0', ctx.x0)]; case 'memcpy': case 'memmove': return ['dst=' + formatRegister('x0', ctx.x0), 'src=' + formatRegister('x1', ctx.x1), 'n=' + dec(ctx.x2)]; case 'memset': return ['dst=' + formatRegister('x0', ctx.x0), 'value=' + hex(ctx.x1), 'n=' + dec(ctx.x2)]; case 'strlen': case 'strdup': return ['s=' + cstringOrPointer(ctx.x0)]; case 'strcmp': case 'strncmp': return ['left=' + cstringOrPointer(ctx.x0), 'right=' + cstringOrPointer(ctx.x1)]; default: return null; } }
function describeReturn(symbolName, ctx) { switch (normalizeSymbolName(symbolName)) { case 'open': case 'open$NOCANCEL': case 'openat': case 'openat$NOCANCEL': case 'access': case 'chmod': case 'mkdir': case 'rmdir': case 'unlink': case 'remove': case 'rename': case 'chdir': case 'stat': case 'lstat': case 'read': case 'write': case 'strcmp': case 'strncmp': return 'result=' + signed(ctx.x0).toString(); case 'strlen': return 'result=' + dec(ctx.x0); case 'malloc': case 'calloc': case 'realloc': case 'strdup': case 'dlopen': case 'dlsym': case 'objc_getClass': case 'objc_lookUpClass': case 'sel_registerName': return 'result=' + formatRegister('x0', ctx.x0); case 'free': return 'result=void'; default: return null; } }
function resolveTarget(spec) {
    if (!spec || typeof spec !== 'object') {
        throw new Error('native hook target spec must be an object');
    }
    if (spec.kind === 'export') {
        const moduleName = spec.moduleName === undefined ? null : spec.moduleName;
        const symbolName = String(spec.symbolName || '');
        const target = Module.findExportByName(moduleName, symbolName);
        if (target === null) {
            throw new Error('export not found: ' + symbolName);
        }
        const targetLabel = (moduleName !== null ? moduleName + '!' : '') + symbolName;
        const targetSymbol = DebugSymbol.fromAddress(target);
        const resolvedLabel = targetSymbol && targetSymbol.name !== null ? targetLabel + ' => ' + targetSymbol.name : targetLabel;
        return { target, targetName: targetSymbol && targetSymbol.name !== null ? targetSymbol.name : symbolName, resolvedLabel };
    }
    if (spec.kind === 'address') {
        const target = ptr(spec.address);
        const targetSymbol = DebugSymbol.fromAddress(target);
        const resolvedLabel = targetSymbol && targetSymbol.name !== null ? (targetSymbol.moduleName + '!' + targetSymbol.name + '+0x' + targetSymbol.offset.toString(16)) : ('address ' + target.toString());
        return { target, targetName: targetSymbol && targetSymbol.name !== null ? targetSymbol.name : null, resolvedLabel };
    }
    throw new Error('unsupported native hook target kind: ' + String(spec.kind));
}
function isTraceStateLike(state) {
    return !!state && typeof state === 'object' && (!!state.label || !!state.targetAddress || !!state.objcMode || state.handle !== undefined);
}
function isStalkerStateLike(state) {
    return !!state && typeof state === 'object' && (
        !!state.label
        || !!state.targetAddress
        || !!state.objcMode
        || (Array.isArray(state.handles) && state.handles.length !== 0)
    );
}
function traceStateFilter(state) {
    return typeof state.filter === 'string' && state.filter.length !== 0 ? state.filter : null;
}
function traceStateKey(state) {
    const targetKind = normalizeNullableString(state.targetKind);
    const objcMode = normalizeNullableString(state.objcMode);
    const filter = traceStateFilter(state);
    if (objcMode === 'trace') {
        return 'objc-trace:' + (filter === null ? '*' : filter);
    }
    if (targetKind === 'export') {
        return 'trace-export:' + (normalizeModuleName(state.moduleName) || '*') + ':' + (normalizeNullableString(state.symbolName) || '?');
    }
    if (targetKind === 'address') {
        return 'trace-address:' + (normalizeAddress(state.targetAddress) || '0x0');
    }
    return 'trace-state:' + (normalizeNullableString(state.label) || '<unknown>');
}
function stalkerStateKey(state) {
    const targetKind = normalizeNullableString(state.targetKind);
    const objcMode = normalizeNullableString(state.objcMode);
    const filter = traceStateFilter(state);
    if (objcMode === 'stalker') {
        return 'objc-stalker:' + (filter === null ? '*' : filter);
    }
    if (targetKind === 'export') {
        return 'stalker-export:' + (normalizeModuleName(state.moduleName) || '*') + ':' + (normalizeNullableString(state.symbolName) || '?');
    }
    if (targetKind === 'address') {
        return 'stalker-address:' + (normalizeAddress(state.targetAddress) || '0x0');
    }
    return 'stalker-state:' + (normalizeNullableString(state.label) || '<unknown>');
}
function ensureTraceRegistry() {
    if (!globalThis.__iosRustFridaTraceRegistry || typeof globalThis.__iosRustFridaTraceRegistry !== 'object') {
        globalThis.__iosRustFridaTraceRegistry = {};
    }
    return globalThis.__iosRustFridaTraceRegistry;
}
function ensureStalkerRegistry() {
    if (!globalThis.__iosRustFridaStalkerRegistry || typeof globalThis.__iosRustFridaStalkerRegistry !== 'object') {
        globalThis.__iosRustFridaStalkerRegistry = {};
    }
    return globalThis.__iosRustFridaStalkerRegistry;
}
function listTraceEntries() {
    const registry = globalThis.__iosRustFridaTraceRegistry;
    if (registry && typeof registry === 'object' && Object.keys(registry).length !== 0) {
        return Object.keys(registry).map((key) => ({ key, state: registry[key] }));
    }
    const legacy = globalThis.__iosRustFridaTrace;
    if (isTraceStateLike(legacy)) {
        return [{ key: traceStateKey(legacy), state: legacy }];
    }
    return [];
}
function listStalkerEntries() {
    const registry = globalThis.__iosRustFridaStalkerRegistry;
    if (registry && typeof registry === 'object' && Object.keys(registry).length !== 0) {
        return Object.keys(registry).map((key) => ({ key, state: registry[key] }));
    }
    const legacy = globalThis.__iosRustFridaStalker;
    if (isStalkerStateLike(legacy)) {
        return [{ key: stalkerStateKey(legacy), state: legacy }];
    }
    return [];
}
function syncCurrentTraceState(preferredKey) {
    const entries = listTraceEntries();
    const activeKey = preferredKey && entries.some((entry) => entry.key === preferredKey)
        ? preferredKey
        : (entries.length === 0 ? null : entries[entries.length - 1].key);
    globalThis.__iosRustFridaTraceCurrentKey = activeKey;
    if (activeKey === null) {
        globalThis.__iosRustFridaTrace = {};
        return null;
    }
    const current = entries.find((entry) => entry.key === activeKey);
    globalThis.__iosRustFridaTrace = current ? current.state : {};
    return current || null;
}
function syncCurrentStalkerState(preferredKey) {
    const entries = listStalkerEntries();
    const activeKey = preferredKey && entries.some((entry) => entry.key === preferredKey)
        ? preferredKey
        : (entries.length === 0 ? null : entries[entries.length - 1].key);
    globalThis.__iosRustFridaStalkerCurrentKey = activeKey;
    if (activeKey === null) {
        globalThis.__iosRustFridaStalker = {};
        return null;
    }
    const current = entries.find((entry) => entry.key === activeKey);
    globalThis.__iosRustFridaStalker = current ? current.state : {};
    return current || null;
}
function removeTraceEntries(keys) {
    const registry = ensureTraceRegistry();
    const removed = [];
    let handleCount = 0;
    for (const key of keys) {
        const state = registry[key];
        if (!isTraceStateLike(state)) {
            continue;
        }
        if (state.handle && typeof state.handle.detach === 'function') {
            try { state.handle.detach(); handleCount++; } catch (_) {}
        }
        removed.push({ key, state });
        delete registry[key];
    }
    if (removed.length === 0 && isTraceStateLike(globalThis.__iosRustFridaTrace)) {
        const legacyKey = traceStateKey(globalThis.__iosRustFridaTrace);
        if (keys.indexOf(legacyKey) !== -1) {
            const legacy = globalThis.__iosRustFridaTrace;
            if (legacy.handle && typeof legacy.handle.detach === 'function') {
                try { legacy.handle.detach(); handleCount++; } catch (_) {}
            }
            removed.push({ key: legacyKey, state: legacy });
            globalThis.__iosRustFridaTrace = {};
        }
    }
    syncCurrentTraceState(null);
    return { removed, count: handleCount };
}
function removeStalkerEntries(keys) {
    const registry = ensureStalkerRegistry();
    const removed = [];
    let handleCount = 0;
    for (const key of keys) {
        const state = registry[key];
        if (!isStalkerStateLike(state)) {
            continue;
        }
        if (Array.isArray(state.handles)) {
            for (const handle of state.handles) {
                if (handle && typeof handle.detach === 'function') {
                    try { handle.detach(); handleCount++; } catch (_) {}
                }
            }
        }
        removed.push({ key, state });
        delete registry[key];
    }
    if (removed.length === 0 && isStalkerStateLike(globalThis.__iosRustFridaStalker)) {
        const legacyKey = stalkerStateKey(globalThis.__iosRustFridaStalker);
        if (keys.indexOf(legacyKey) !== -1) {
            const legacy = globalThis.__iosRustFridaStalker;
            if (Array.isArray(legacy.handles)) {
                for (const handle of legacy.handles) {
                    if (handle && typeof handle.detach === 'function') {
                        try { handle.detach(); handleCount++; } catch (_) {}
                    }
                }
            }
            removed.push({ key: legacyKey, state: legacy });
            globalThis.__iosRustFridaStalker = {};
        }
    }
    syncCurrentStalkerState(null);
    return { removed, count: handleCount };
}
function traceSessionResult(entry) {
    const state = entry.state;
    return {
        key: entry.key,
        label: state.label === undefined ? null : state.label,
        filter: traceStateFilter(state),
        targetAddress: state.targetAddress === undefined ? null : state.targetAddress,
        targetKind: state.targetKind === undefined ? null : state.targetKind,
        targetSymbol: state.targetSymbol === undefined ? null : state.targetSymbol,
        moduleName: state.moduleName === undefined ? null : state.moduleName,
        symbolName: state.symbolName === undefined ? null : state.symbolName,
        objcMode: state.objcMode === undefined ? null : state.objcMode,
    };
}
function stalkerSessionResult(entry) {
    const state = entry.state;
    return {
        key: entry.key,
        label: state.label === undefined ? null : state.label,
        filter: traceStateFilter(state),
        targetAddress: state.targetAddress === undefined ? null : state.targetAddress,
        secondaryTargetAddress: state.secondaryTargetAddress === undefined ? null : state.secondaryTargetAddress,
        targetKind: state.targetKind === undefined ? null : state.targetKind,
        targetSymbol: state.targetSymbol === undefined ? null : state.targetSymbol,
        moduleName: state.moduleName === undefined ? null : state.moduleName,
        symbolName: state.symbolName === undefined ? null : state.symbolName,
        objcMode: state.objcMode === undefined ? null : state.objcMode,
        superEnabled: !!state.superEnabled,
        count: Array.isArray(state.handles) ? state.handles.length : 0,
    };
}
function detachTraceState() {
    const entries = listTraceEntries();
    const removed = removeTraceEntries(entries.map((entry) => entry.key));
    return {
        active: removed.removed.length !== 0,
        count: removed.count,
        sessionCount: removed.removed.length,
        sessions: removed.removed.map(traceSessionResult),
        label: removed.removed.length === 0 ? null : (removed.removed[removed.removed.length - 1].state.label === undefined ? null : removed.removed[removed.removed.length - 1].state.label),
        filter: removed.removed.length === 0 ? null : traceStateFilter(removed.removed[removed.removed.length - 1].state),
        targetAddress: removed.removed.length === 0 ? null : (removed.removed[removed.removed.length - 1].state.targetAddress === undefined ? null : removed.removed[removed.removed.length - 1].state.targetAddress),
        targetKind: removed.removed.length === 0 ? null : (removed.removed[removed.removed.length - 1].state.targetKind === undefined ? null : removed.removed[removed.removed.length - 1].state.targetKind),
        targetSymbol: removed.removed.length === 0 ? null : (removed.removed[removed.removed.length - 1].state.targetSymbol === undefined ? null : removed.removed[removed.removed.length - 1].state.targetSymbol),
        moduleName: removed.removed.length === 0 ? null : (removed.removed[removed.removed.length - 1].state.moduleName === undefined ? null : removed.removed[removed.removed.length - 1].state.moduleName),
        symbolName: removed.removed.length === 0 ? null : (removed.removed[removed.removed.length - 1].state.symbolName === undefined ? null : removed.removed[removed.removed.length - 1].state.symbolName),
        objcMode: removed.removed.length === 0 ? null : (removed.removed[removed.removed.length - 1].state.objcMode === undefined ? null : removed.removed[removed.removed.length - 1].state.objcMode),
    };
}
function detachStalkerState() {
    const entries = listStalkerEntries();
    const removed = removeStalkerEntries(entries.map((entry) => entry.key));
    return {
        active: removed.removed.length !== 0,
        count: removed.count,
        sessionCount: removed.removed.length,
        sessions: removed.removed.map(stalkerSessionResult),
        label: removed.removed.length === 0 ? null : (removed.removed[removed.removed.length - 1].state.label === undefined ? null : removed.removed[removed.removed.length - 1].state.label),
        filter: removed.removed.length === 0 ? null : traceStateFilter(removed.removed[removed.removed.length - 1].state),
        targetAddress: removed.removed.length === 0 ? null : (removed.removed[removed.removed.length - 1].state.targetAddress === undefined ? null : removed.removed[removed.removed.length - 1].state.targetAddress),
        secondaryTargetAddress: removed.removed.length === 0 ? null : (removed.removed[removed.removed.length - 1].state.secondaryTargetAddress === undefined ? null : removed.removed[removed.removed.length - 1].state.secondaryTargetAddress),
        targetKind: removed.removed.length === 0 ? null : (removed.removed[removed.removed.length - 1].state.targetKind === undefined ? null : removed.removed[removed.removed.length - 1].state.targetKind),
        targetSymbol: removed.removed.length === 0 ? null : (removed.removed[removed.removed.length - 1].state.targetSymbol === undefined ? null : removed.removed[removed.removed.length - 1].state.targetSymbol),
        moduleName: removed.removed.length === 0 ? null : (removed.removed[removed.removed.length - 1].state.moduleName === undefined ? null : removed.removed[removed.removed.length - 1].state.moduleName),
        symbolName: removed.removed.length === 0 ? null : (removed.removed[removed.removed.length - 1].state.symbolName === undefined ? null : removed.removed[removed.removed.length - 1].state.symbolName),
        objcMode: removed.removed.length === 0 ? null : (removed.removed[removed.removed.length - 1].state.objcMode === undefined ? null : removed.removed[removed.removed.length - 1].state.objcMode),
        superEnabled: removed.removed.length === 0 ? false : !!removed.removed[removed.removed.length - 1].state.superEnabled,
    };
}
function normalizeNullableString(value) {
    if (value === null || value === undefined) {
        return null;
    }
    return String(value);
}
function normalizeModuleName(value) {
    const normalized = normalizeNullableString(value);
    if (normalized === null || normalized === '' || normalized === '*' || normalized === 'default' || normalized === 'null') {
        return null;
    }
    return normalized;
}
function normalizeAddress(value) {
    if (value === null || value === undefined) {
        return null;
    }
    try {
        return ptrValue(value).toString();
    } catch (_) {
        return String(value);
    }
}
function currentFilterValue(state) {
    return typeof state.filter === 'string' && state.filter.length !== 0 ? state.filter : null;
}
function stateMatchesTarget(state, target) {
    if (target === null || target === undefined) {
        return true;
    }
    if (target === null || typeof target !== 'object') {
        return false;
    }
    const requestedKind = normalizeNullableString(target.kind);
    const currentKind = normalizeNullableString(state.targetKind);
    if (requestedKind === null || currentKind === null || requestedKind !== currentKind) {
        return false;
    }
    if (requestedKind === 'export') {
        return normalizeModuleName(target.moduleName) === normalizeModuleName(state.moduleName)
            && normalizeNullableString(target.symbolName) === normalizeNullableString(state.symbolName);
    }
    if (requestedKind === 'address') {
        return normalizeAddress(target.address) === normalizeAddress(state.targetAddress);
    }
    return false;
}
function requestedSelectorMatchesState(state, target, filter) {
    const requestedFilter = normalizeNullableString(filter);
    const hasTarget = target !== null && target !== undefined;
    if (!hasTarget && requestedFilter === null) {
        return true;
    }
    if (requestedFilter !== null && requestedFilter !== currentFilterValue(state)) {
        return false;
    }
    return stateMatchesTarget(state, target);
}
function stopTraceResult(target, filter) {
    const entries = listTraceEntries();
    const matched = entries.filter((entry) => requestedSelectorMatchesState(entry.state, target, filter));
    if (entries.length !== 0 && matched.length === 0) {
        const current = currentTraceStateResult();
        current.message = 'trace stop skipped: selector mismatch';
        return current;
    }
    const detached = matched.length === entries.length
        ? detachTraceState()
        : (function() {
            const removed = removeTraceEntries(matched.map((entry) => entry.key));
            return {
                active: removed.removed.length !== 0,
                count: removed.count,
                sessionCount: removed.removed.length,
                sessions: removed.removed.map(traceSessionResult),
                label: removed.removed.length === 0 ? null : (removed.removed[removed.removed.length - 1].state.label === undefined ? null : removed.removed[removed.removed.length - 1].state.label),
                filter: removed.removed.length === 0 ? null : traceStateFilter(removed.removed[removed.removed.length - 1].state),
                targetAddress: removed.removed.length === 0 ? null : (removed.removed[removed.removed.length - 1].state.targetAddress === undefined ? null : removed.removed[removed.removed.length - 1].state.targetAddress),
                targetKind: removed.removed.length === 0 ? null : (removed.removed[removed.removed.length - 1].state.targetKind === undefined ? null : removed.removed[removed.removed.length - 1].state.targetKind),
                targetSymbol: removed.removed.length === 0 ? null : (removed.removed[removed.removed.length - 1].state.targetSymbol === undefined ? null : removed.removed[removed.removed.length - 1].state.targetSymbol),
                moduleName: removed.removed.length === 0 ? null : (removed.removed[removed.removed.length - 1].state.moduleName === undefined ? null : removed.removed[removed.removed.length - 1].state.moduleName),
                symbolName: removed.removed.length === 0 ? null : (removed.removed[removed.removed.length - 1].state.symbolName === undefined ? null : removed.removed[removed.removed.length - 1].state.symbolName),
                objcMode: removed.removed.length === 0 ? null : (removed.removed[removed.removed.length - 1].state.objcMode === undefined ? null : removed.removed[removed.removed.length - 1].state.objcMode),
            };
        })();
    return {
        active: detached.active,
        count: detached.count,
        sessionCount: detached.sessionCount === undefined ? detached.active ? 1 : 0 : detached.sessionCount,
        sessions: detached.sessions === undefined ? [] : detached.sessions,
        label: detached.label,
        filter: detached.filter,
        targetAddress: detached.targetAddress,
        targetKind: detached.targetKind,
        targetSymbol: detached.targetSymbol,
        moduleName: detached.moduleName,
        symbolName: detached.symbolName,
        objcMode: detached.objcMode,
        message: detached.active ? ('trace stopped: ' + (detached.label || '<unknown>') + ' detached=' + detached.count) : 'trace stopped',
    };
}
function stopTrace() {
    return stopTraceResult().message;
}
function currentTraceStateResult() {
    const entries = listTraceEntries();
    const current = syncCurrentTraceState(globalThis.__iosRustFridaTraceCurrentKey);
    const state = current ? current.state : {};
    const active = entries.length !== 0;
    return {
        active,
        count: entries.length,
        sessionCount: entries.length,
        sessions: entries.map(traceSessionResult),
        label: state.label === undefined ? null : state.label,
        filter: typeof state.filter === 'string' && state.filter.length !== 0 ? state.filter : null,
        targetAddress: state.targetAddress === undefined ? null : state.targetAddress,
        targetKind: state.targetKind === undefined ? null : state.targetKind,
        targetSymbol: state.targetSymbol === undefined ? null : state.targetSymbol,
        moduleName: state.moduleName === undefined ? null : state.moduleName,
        symbolName: state.symbolName === undefined ? null : state.symbolName,
        objcMode: state.objcMode === undefined ? null : state.objcMode,
        message: !active ? 'trace inactive' : (entries.length === 1 ? ('trace active: ' + (state.label || '<unknown>')) : ('trace active: ' + entries.length)),
    };
}
function replaceTraceEntry(state) {
    const key = traceStateKey(state);
    const removed = removeTraceEntries([key]);
    const registry = ensureTraceRegistry();
    registry[key] = state;
    syncCurrentTraceState(key);
    return {
        key,
        replacedCount: removed.count,
        replacedSessionCount: removed.removed.length,
        replacedLabel: removed.removed.length === 0 ? null : (removed.removed[removed.removed.length - 1].state.label === undefined ? null : removed.removed[removed.removed.length - 1].state.label),
    };
}
function stopStalkerResult(target, filter) {
    const entries = listStalkerEntries();
    const matched = entries.filter((entry) => requestedSelectorMatchesState(entry.state, target, filter));
    if (entries.length !== 0 && matched.length === 0) {
        const current = currentStalkerStateResult();
        current.message = 'stalker stop skipped: selector mismatch';
        return current;
    }
    const detached = matched.length === entries.length
        ? detachStalkerState()
        : (function() {
            const removed = removeStalkerEntries(matched.map((entry) => entry.key));
            return {
                active: removed.removed.length !== 0,
                count: removed.count,
                sessionCount: removed.removed.length,
                sessions: removed.removed.map(stalkerSessionResult),
                label: removed.removed.length === 0 ? null : (removed.removed[removed.removed.length - 1].state.label === undefined ? null : removed.removed[removed.removed.length - 1].state.label),
                filter: removed.removed.length === 0 ? null : traceStateFilter(removed.removed[removed.removed.length - 1].state),
                targetAddress: removed.removed.length === 0 ? null : (removed.removed[removed.removed.length - 1].state.targetAddress === undefined ? null : removed.removed[removed.removed.length - 1].state.targetAddress),
                secondaryTargetAddress: removed.removed.length === 0 ? null : (removed.removed[removed.removed.length - 1].state.secondaryTargetAddress === undefined ? null : removed.removed[removed.removed.length - 1].state.secondaryTargetAddress),
                targetKind: removed.removed.length === 0 ? null : (removed.removed[removed.removed.length - 1].state.targetKind === undefined ? null : removed.removed[removed.removed.length - 1].state.targetKind),
                targetSymbol: removed.removed.length === 0 ? null : (removed.removed[removed.removed.length - 1].state.targetSymbol === undefined ? null : removed.removed[removed.removed.length - 1].state.targetSymbol),
                moduleName: removed.removed.length === 0 ? null : (removed.removed[removed.removed.length - 1].state.moduleName === undefined ? null : removed.removed[removed.removed.length - 1].state.moduleName),
                symbolName: removed.removed.length === 0 ? null : (removed.removed[removed.removed.length - 1].state.symbolName === undefined ? null : removed.removed[removed.removed.length - 1].state.symbolName),
                objcMode: removed.removed.length === 0 ? null : (removed.removed[removed.removed.length - 1].state.objcMode === undefined ? null : removed.removed[removed.removed.length - 1].state.objcMode),
                superEnabled: removed.removed.length === 0 ? false : !!removed.removed[removed.removed.length - 1].state.superEnabled,
            };
        })();
    return {
        active: detached.active,
        count: detached.count,
        sessionCount: detached.sessionCount === undefined ? detached.active ? 1 : 0 : detached.sessionCount,
        sessions: detached.sessions === undefined ? [] : detached.sessions,
        label: detached.label,
        filter: detached.filter,
        targetAddress: detached.targetAddress,
        secondaryTargetAddress: detached.secondaryTargetAddress,
        targetKind: detached.targetKind,
        targetSymbol: detached.targetSymbol,
        moduleName: detached.moduleName,
        symbolName: detached.symbolName,
        objcMode: detached.objcMode,
        superEnabled: detached.superEnabled,
        message: detached.active ? ('stalker stopped: ' + (detached.label || '<unknown>') + ' detached=' + detached.count) : 'stalker stopped',
    };
}
function stopStalker() {
    return stopStalkerResult().message;
}
function currentStalkerStateResult() {
    const entries = listStalkerEntries();
    const current = syncCurrentStalkerState(globalThis.__iosRustFridaStalkerCurrentKey);
    const state = current ? current.state : {};
    const handleCount = entries.reduce((sum, entry) => sum + (Array.isArray(entry.state.handles) ? entry.state.handles.length : 0), 0);
    const active = entries.length !== 0;
    return {
        active,
        count: handleCount,
        sessionCount: entries.length,
        sessions: entries.map(stalkerSessionResult),
        label: state.label === undefined ? null : state.label,
        filter: typeof state.filter === 'string' && state.filter.length !== 0 ? state.filter : null,
        targetAddress: state.targetAddress === undefined ? null : state.targetAddress,
        secondaryTargetAddress: state.secondaryTargetAddress === undefined ? null : state.secondaryTargetAddress,
        targetKind: state.targetKind === undefined ? null : state.targetKind,
        targetSymbol: state.targetSymbol === undefined ? null : state.targetSymbol,
        moduleName: state.moduleName === undefined ? null : state.moduleName,
        symbolName: state.symbolName === undefined ? null : state.symbolName,
        objcMode: state.objcMode === undefined ? null : state.objcMode,
        superEnabled: !!state.superEnabled,
        message: !active ? 'stalker inactive' : (entries.length === 1 ? ('stalker active: ' + (state.label || '<unknown>')) : ('stalker active: ' + entries.length)),
    };
}
function replaceStalkerEntry(state) {
    const key = stalkerStateKey(state);
    const removed = removeStalkerEntries([key]);
    const registry = ensureStalkerRegistry();
    registry[key] = state;
    syncCurrentStalkerState(key);
    return {
        key,
        replacedCount: removed.count,
        replacedSessionCount: removed.removed.length,
        replacedLabel: removed.removed.length === 0 ? null : (removed.removed[removed.removed.length - 1].state.label === undefined ? null : removed.removed[removed.removed.length - 1].state.label),
    };
}
function installTraceResult(spec) {
    const objcFilter = spec && typeof spec.objcFilter === 'string' ? spec.objcFilter : '';
    if (spec && spec.objcMode === 'trace') {
        const target = Module.findExportByName(null, 'objc_msgSend');
        if (target === null) {
            throw new Error('objc_msgSend export not found');
        }
        const handle = Interceptor.attach(target, {
            onEnter(ctx) {
                try {
                    const selfPtr = ptr(ctx.x0);
                    const selPtr = ptr(ctx.x1);
                    const className = ObjC.objectClassName(selfPtr) || '<nil>';
                    const selectorName = ObjC.selectorName(selPtr) || '<unknown>';
                    const summary = className + ' ' + selectorName;
                    if (objcFilter.length !== 0 && summary.indexOf(objcFilter) === -1) {
                        return;
                    }
                    console.log('[trace] ' + summary + ' self=' + selfPtr.toString() + ' x2=' + ptr(ctx.x2).toString() + ' x3=' + ptr(ctx.x3).toString());
                } catch (e) {
                    console.log('[trace] error ' + String(e));
                }
            }
        });
        const state = {
            handle,
            filter: objcFilter,
            label: 'objc_msgSend',
            targetAddress: target.toString(),
            targetKind: 'export',
            targetSymbol: 'objc_msgSend',
            moduleName: null,
            symbolName: 'objc_msgSend',
            objcMode: 'trace',
        };
        const replaced = replaceTraceEntry(state);
        return {
            action: 'install',
            targetKind: 'export',
            targetAddress: target.toString(),
            targetSymbol: 'objc_msgSend',
            moduleName: null,
            symbolName: 'objc_msgSend',
            resolvedLabel: 'objc_msgSend',
            objcMode: 'trace',
            filter: objcFilter.length !== 0 ? objcFilter : null,
            key: replaced.key,
            replacedCount: replaced.replacedCount,
            replacedLabel: replaced.replacedLabel,
            replacedSessionCount: replaced.replacedSessionCount,
            message: 'trace installed: objc_msgSend' + (objcFilter.length !== 0 ? ' filter=' + objcFilter : '') + ' (hook logs flush on the next JS command)',
        };
    }

    const resolved = resolveTarget(spec);
    const templateArgs = spec && spec.templateArgs ? spec.templateArgs : null;
    const templateRet = spec && spec.templateRet ? spec.templateRet : null;
    const handle = Interceptor.attach(resolved.target, {
        onEnter(ctx) {
            try {
                const callDetails = formatTemplateArgs(ctx, templateArgs) || describeCall(resolved.targetName, ctx);
                const detailText = callDetails !== null ? ' args: ' + callDetails.join(' ') : '';
                console.log('[trace] ' + resolved.resolvedLabel + detailText + ' ' + formatRegisters(ctx, ['x0', 'x1', 'x2', 'x3', 'x4', 'x5']));
            } catch (e) {
                console.log('[trace] error ' + String(e));
            }
        },
        onLeave(ctx) {
            try {
                const retDetails = formatTemplateReturn(ctx, templateRet) || describeReturn(resolved.targetName, ctx);
                const detailText = retDetails !== null ? ' ' + retDetails : '';
                console.log('[trace] ret ' + resolved.resolvedLabel + detailText + ' ' + formatRegister('x0', ctx.x0));
            } catch (e) {
                console.log('[trace] error ' + String(e));
            }
        }
    });
    const state = {
        handle,
        label: resolved.resolvedLabel,
        targetAddress: resolved.target.toString(),
        targetKind: spec.kind === undefined ? null : spec.kind,
        targetSymbol: resolved.targetName === undefined ? null : resolved.targetName,
        moduleName: spec && spec.moduleName === undefined ? null : spec.moduleName,
        symbolName: spec && spec.symbolName === undefined ? null : spec.symbolName,
        objcMode: null,
    };
    const replaced = replaceTraceEntry(state);
    return {
        action: 'install',
        targetKind: spec.kind === undefined ? null : spec.kind,
        targetAddress: resolved.target.toString(),
        targetSymbol: resolved.targetName === undefined ? null : resolved.targetName,
        moduleName: spec && spec.moduleName === undefined ? null : spec.moduleName,
        symbolName: spec && spec.symbolName === undefined ? null : spec.symbolName,
        address: spec && spec.address === undefined ? null : spec.address,
        resolvedLabel: resolved.resolvedLabel,
        templateArgs,
        templateRet,
        key: replaced.key,
        replacedCount: replaced.replacedCount,
        replacedLabel: replaced.replacedLabel,
        replacedSessionCount: replaced.replacedSessionCount,
        message: 'trace installed: ' + resolved.resolvedLabel + ' (hook logs flush on the next JS command)',
    };
}
function installTrace(spec) {
    return installTraceResult(spec).message;
}
function installStalkerResult(spec) {
    const objcFilter = spec && typeof spec.objcFilter === 'string' ? spec.objcFilter : '';
    if (spec && spec.objcMode === 'stalker') {
        const msgSend = Module.findExportByName(null, 'objc_msgSend');
        if (msgSend === null) {
            throw new Error('objc_msgSend export not found');
        }
        const msgSendSuper = Module.findExportByName(null, 'objc_msgSendSuper2');
        const pthreadSelf = Module.findExportByName(null, 'pthread_self');
        const depths = {};
        const stacks = {};
        function currentThreadKey() { try { if (pthreadSelf === null) { return '0'; } return callNative(pthreadSelf).toString(); } catch (_) { return '0'; } }
        function indent(depth) { let s = ''; const capped = Math.min(depth, 32); for (let i = 0; i < capped; i++) s += '  '; return s; }
        function pushStack(tid, summary) { const stack = stacks[tid] || []; stack.push(summary); stacks[tid] = stack; const depth = depths[tid] || 0; depths[tid] = depth + 1; return depth; }
        function popStack(tid) { const stack = stacks[tid] || []; const depth = Math.max((depths[tid] || 1) - 1, 0); depths[tid] = depth; const summary = stack.length > 0 ? stack.pop() : '<unknown>'; stacks[tid] = stack; return { depth, summary }; }
        function install(target, isSuper) {
            return Interceptor.attach(target, {
                onEnter(ctx) {
                    try {
                        const tid = currentThreadKey();
                        const receiver = isSuper ? Memory.readPointer(ptr(ctx.x0)) : ptr(ctx.x0);
                        const selector = ptr(ctx.x1);
                        const className = ObjC.objectClassName(receiver) || '<nil>';
                        const selectorName = ObjC.selectorName(selector) || '<unknown>';
                        const summary = className + ' ' + selectorName + (isSuper ? ' [super]' : '');
                        if (objcFilter.length !== 0 && summary.indexOf(objcFilter) === -1) {
                            return;
                        }
                        const depth = pushStack(tid, summary);
                        console.log('[stalker] ' + indent(depth) + '-> ' + summary + ' self=' + receiver.toString());
                    } catch (e) {
                        console.log('[stalker] error ' + String(e));
                    }
                },
                onLeave(ctx) {
                    try {
                        const tid = currentThreadKey();
                        const result = popStack(tid);
                        if (objcFilter.length !== 0 && result.summary.indexOf(objcFilter) === -1) {
                            return;
                        }
                        console.log('[stalker] ' + indent(result.depth) + '<- ' + result.summary + ' ret=' + ptr(ctx.x0).toString());
                    } catch (e) {
                        console.log('[stalker] error ' + String(e));
                    }
                }
            });
        }
        const handles = [install(msgSend, false)];
        if (msgSendSuper !== null) {
            handles.push(install(msgSendSuper, true));
        }
        const state = {
            handles,
            filter: objcFilter,
            depths,
            stacks,
            label: msgSendSuper !== null ? 'objc_msgSend + objc_msgSendSuper2' : 'objc_msgSend',
            targetAddress: msgSend.toString(),
            secondaryTargetAddress: msgSendSuper === null ? null : msgSendSuper.toString(),
            targetKind: 'export',
            targetSymbol: 'objc_msgSend',
            moduleName: null,
            symbolName: 'objc_msgSend',
            objcMode: 'stalker',
            superEnabled: msgSendSuper !== null,
        };
        const replaced = replaceStalkerEntry(state);
        return {
            action: 'install',
            targetKind: 'export',
            targetAddress: msgSend.toString(),
            secondaryTargetAddress: msgSendSuper === null ? null : msgSendSuper.toString(),
            targetSymbol: 'objc_msgSend',
            moduleName: null,
            symbolName: 'objc_msgSend',
            resolvedLabel: msgSendSuper !== null ? 'objc_msgSend + objc_msgSendSuper2' : 'objc_msgSend',
            objcMode: 'stalker',
            superEnabled: msgSendSuper !== null,
            filter: objcFilter.length !== 0 ? objcFilter : null,
            count: handles.length,
            sessionCount: currentStalkerStateResult().sessionCount,
            key: replaced.key,
            replacedCount: replaced.replacedCount,
            replacedLabel: replaced.replacedLabel,
            replacedSessionCount: replaced.replacedSessionCount,
            message: 'stalker installed: objc_msgSend' + (msgSendSuper !== null ? ' + objc_msgSendSuper2' : '') + (objcFilter.length !== 0 ? ' filter=' + objcFilter : '') + ' (hook logs flush on the next JS command)',
        };
    }

    const resolved = resolveTarget(spec);
    const templateArgs = spec && spec.templateArgs ? spec.templateArgs : null;
    const templateRet = spec && spec.templateRet ? spec.templateRet : null;
    const pthreadSelf = Module.findExportByName(null, 'pthread_self');
    const depths = {};
    function currentThreadKey() { try { if (pthreadSelf === null) { return '0'; } return callNative(pthreadSelf).toString(); } catch (_) { return '0'; } }
    function indent(depth) { let s = ''; const capped = Math.min(depth, 32); for (let i = 0; i < capped; i++) s += '  '; return s; }
    const handle = Interceptor.attach(resolved.target, {
        onEnter(ctx) {
            try {
                const tid = currentThreadKey();
                const depth = depths[tid] || 0;
                depths[tid] = depth + 1;
                const callDetails = formatTemplateArgs(ctx, templateArgs) || describeCall(resolved.targetName, ctx);
                const detailText = callDetails !== null ? ' args: ' + callDetails.join(' ') : '';
                console.log('[stalker] ' + indent(depth) + '-> ' + resolved.resolvedLabel + detailText + ' ' + formatRegisters(ctx, ['x0', 'x1', 'x2', 'x3']));
            } catch (e) {
                console.log('[stalker] error ' + String(e));
            }
        },
        onLeave(ctx) {
            try {
                const tid = currentThreadKey();
                const depth = Math.max((depths[tid] || 1) - 1, 0);
                depths[tid] = depth;
                const retDetails = formatTemplateReturn(ctx, templateRet) || describeReturn(resolved.targetName, ctx);
                const detailText = retDetails !== null ? ' ' + retDetails : '';
                console.log('[stalker] ' + indent(depth) + '<- ' + resolved.resolvedLabel + detailText + ' ret=' + formatRegister('x0', ctx.x0));
            } catch (e) {
                console.log('[stalker] error ' + String(e));
            }
        }
    });
    const state = {
        handles: [handle],
        label: resolved.resolvedLabel,
        depths,
        targetAddress: resolved.target.toString(),
        secondaryTargetAddress: null,
        targetKind: spec.kind === undefined ? null : spec.kind,
        targetSymbol: resolved.targetName === undefined ? null : resolved.targetName,
        moduleName: spec && spec.moduleName === undefined ? null : spec.moduleName,
        symbolName: spec && spec.symbolName === undefined ? null : spec.symbolName,
        objcMode: null,
        superEnabled: false,
    };
    const replaced = replaceStalkerEntry(state);
    return {
        action: 'install',
        targetKind: spec.kind === undefined ? null : spec.kind,
        targetAddress: resolved.target.toString(),
        secondaryTargetAddress: null,
        targetSymbol: resolved.targetName === undefined ? null : resolved.targetName,
        moduleName: spec && spec.moduleName === undefined ? null : spec.moduleName,
        symbolName: spec && spec.symbolName === undefined ? null : spec.symbolName,
        address: spec && spec.address === undefined ? null : spec.address,
        resolvedLabel: resolved.resolvedLabel,
        templateArgs,
        templateRet,
        count: 1,
        sessionCount: currentStalkerStateResult().sessionCount,
        key: replaced.key,
        replacedCount: replaced.replacedCount,
        replacedLabel: replaced.replacedLabel,
        replacedSessionCount: replaced.replacedSessionCount,
        message: 'stalker installed: ' + resolved.resolvedLabel + ' (hook logs flush on the next JS command)',
    };
}
function installStalker(spec) {
    return installStalkerResult(spec).message;
}
return {
    cstringPreview,
    cstringOrPointer,
    describeCall,
    describeReturn,
    formatRegister,
    formatRegisters,
    formatTemplateArgs,
    formatTemplateReturn,
    formatTypedValue,
    installTraceResult,
    installStalkerResult,
    currentTraceStateResult,
    currentStalkerStateResult,
    stopTraceResult,
    stopStalkerResult,
    installTrace,
    installStalker,
    stopTrace,
    stopStalker,
};
})();
"#
}
