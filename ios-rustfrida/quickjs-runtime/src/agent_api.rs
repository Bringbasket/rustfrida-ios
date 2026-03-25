pub(crate) fn bootstrap_agent_api() -> &'static str {
    r#"globalThis.__iosRustFridaAgentApi = globalThis.__iosRustFridaAgentApi || (function() {
function splitModuleQuery(raw, usage) {
    const trimmed = String(raw || '').trim();
    if (trimmed.length === 0) {
        throw new Error(usage);
    }
    const separator = ' -- ';
    const index = trimmed.indexOf(separator);
    if (index === -1) {
        return { moduleName: null, query: trimmed };
    }

    const moduleName = trimmed.slice(0, index).trim();
    const query = trimmed.slice(index + separator.length).trim();
    if (moduleName.length === 0 || query.length === 0) {
        throw new Error(usage);
    }

    return {
        moduleName: moduleName === '*' || moduleName === 'null' || moduleName === 'default' ? null : moduleName,
        query,
    };
}

function splitSwiftMethods(raw, usage) {
    const parsed = splitModuleQuery(raw, usage);
    const parts = parsed.query.split(/\s+/).filter(Boolean);
    if (parts.length < 2) {
        throw new Error(usage);
    }
    return {
        moduleName: parsed.moduleName,
        typeName: parts[0],
        methodQuery: parts.slice(1).join(' '),
    };
}

function splitSwiftTypeKindQuery(raw, usage) {
    const parsed = splitModuleQuery(raw, usage);
    const parts = parsed.query.split(/\s+/).filter(Boolean);
    if (parts.length < 2) {
        throw new Error(usage);
    }
    return {
        moduleName: parsed.moduleName,
        sourceKind: parts[0],
        query: parts.slice(1).join(' '),
    };
}

function parseObjcMethodImp(raw) {
    const parts = String(raw || '').trim().split(/\s+/).filter(Boolean);
    if (parts.length < 2) {
        throw new Error('objc.methodImp usage: objc.methodImp <class> <selector> [meta]');
    }
    return {
        className: parts[0],
        selectorName: parts[1],
        isClassMethod: parts.slice(2).some((part) => part === 'meta' || part === 'class' || part === '+'),
    };
}

function parseObjcMethods(raw) {
    const parts = String(raw || '').trim().split(/\s+/).filter(Boolean);
    if (parts.length === 0) {
        throw new Error('objc.methods usage: objc.methods <class> [meta] [filter]');
    }
    let isClassMethod = false;
    const filterTokens = [];
    for (let i = 1; i < parts.length; i++) {
        const part = parts[i];
        if (filterTokens.length === 0 && (part === 'meta' || part === 'class' || part === '+')) {
            isClassMethod = true;
            continue;
        }
        if (filterTokens.length === 0 && (part === 'instance' || part === 'inst' || part === '-')) {
            isClassMethod = false;
            continue;
        }
        filterTokens.push(part);
    }
    return {
        className: parts[0],
        isClassMethod,
        filter: filterTokens.length === 0 ? null : filterTokens.join(' '),
    };
}

function parseObjcMethodOwners(raw) {
    const parts = String(raw || '').trim().split(/\s+/).filter(Boolean);
    if (parts.length === 0) {
        throw new Error('objc.methodOwners usage: objc.methodOwners <selector> [meta]');
    }
    let isClassMethod = false;
    const queryTokens = [];
    for (const part of parts) {
        if (queryTokens.length === 0 && (part === 'meta' || part === 'class' || part === '+')) {
            isClassMethod = true;
            continue;
        }
        if (queryTokens.length === 0 && (part === 'instance' || part === 'inst' || part === '-')) {
            isClassMethod = false;
            continue;
        }
        queryTokens.push(part);
    }
    if (queryTokens.length === 0) {
        throw new Error('objc.methodOwners usage: objc.methodOwners <selector> [meta]');
    }
    return {
        query: queryTokens.join(' '),
        isClassMethod,
    };
}

function formatSlide(value) {
    const raw = typeof value === 'bigint' ? value : BigInt(value || 0);
    return (raw < 0n ? '-0x' + (-raw).toString(16) : '0x' + raw.toString(16));
}

function parseAddressArg(raw, usage) {
    const trimmed = String(raw || '').trim();
    if (trimmed.length === 0) {
        throw new Error(usage);
    }
    return ptr(trimmed);
}

function formatImage(image) {
    return image.base.toString() + ' slide=' + formatSlide(image.slide) + ' ' + image.path;
}

function parseNativeExport(raw) {
    return splitModuleQuery(raw, 'native.export usage: native.export <symbol> | native.export <module> -- <symbol>');
}

function parseNativeExports(raw) {
    const trimmed = String(raw || '').trim();
    if (trimmed.length === 0) {
        throw new Error('native.exports usage: native.exports <module> | native.exports <module> -- <query>');
    }
    const separator = ' -- ';
    const index = trimmed.indexOf(separator);
    if (index === -1) {
        return { moduleName: trimmed, query: null };
    }

    const moduleName = trimmed.slice(0, index).trim();
    const query = trimmed.slice(index + separator.length).trim();
    if (moduleName.length === 0 || query.length === 0) {
        throw new Error('native.exports usage: native.exports <module> | native.exports <module> -- <query>');
    }

    return { moduleName, query };
}

function formatNativeSymbol(symbol) {
    return symbol.address.toString() + ' ' + symbol.moduleName + '!' + symbol.name + '+0x' + BigInt(symbol.offset || 0).toString(16);
}

function formatPackedVersion(value) {
    const raw = Number(value || 0);
    return String((raw >>> 16) & 0xffff) + '.' + String((raw >>> 8) & 0xff) + '.' + String(raw & 0xff);
}

function formatDependency(dep) {
    return [
        '#' + String(dep.ordinal || 0),
        String(dep.kind || 'load'),
        String(dep.path || ''),
        'current=' + formatPackedVersion(dep.currentVersion),
        'compat=' + formatPackedVersion(dep.compatibilityVersion),
    ].join(' ');
}

function formatEncryptionInfo(encryptionInfo) {
    return [
        'cryptoff=0x' + BigInt(encryptionInfo.cryptoff || 0).toString(16),
        'cryptsize=0x' + BigInt(encryptionInfo.cryptsize || 0).toString(16),
        'cryptid=' + String(encryptionInfo.cryptid || 0),
    ].join(' ');
}

function formatBuildVersion(buildVersion) {
    const tools = Array.isArray(buildVersion.tools) && buildVersion.tools.length !== 0
        ? buildVersion.tools.map((tool) => String(tool.tool || 'tool') + ':' + String(tool.version || '')).join(',')
        : 'none';
    return [
        'platform=' + String(buildVersion.platform || 'unknown'),
        'minos=' + String(buildVersion.minOs || ''),
        'sdk=' + String(buildVersion.sdk || ''),
        'tools=' + tools,
    ].join(' ');
}

function formatDylinker(dylinker) {
    return String(dylinker.kind || 'load') + ' ' + String(dylinker.path || '');
}

function formatInstallName(installName) {
    return [
        String(installName.path || ''),
        'current=' + formatPackedVersion(installName.currentVersion),
        'compat=' + formatPackedVersion(installName.compatibilityVersion),
        'timestamp=' + String(installName.timestamp || 0),
    ].join(' ');
}

function formatUuid(imageUuid) {
    return String(imageUuid.uuid || '');
}

function formatRpath(rpath) {
    return String(rpath.path || '');
}

function formatImport(imp) {
    const source = imp.dylibName === null || imp.dylibName === undefined ? ('ordinal=' + String(imp.dylibOrdinal || 0)) : String(imp.dylibName);
    return source + '!' + String(imp.name || '') + (imp.weakImport ? ' weak' : '');
}

function formatSegment(segment) {
    return [
        segment.name,
        'vmaddr=' + segment.vmaddr.toString(),
        'vmsize=0x' + BigInt(segment.vmsize || 0).toString(16),
        'fileoff=0x' + BigInt(segment.fileoff || 0).toString(16),
        'filesize=0x' + BigInt(segment.filesize || 0).toString(16),
        'maxprot=' + String(segment.maxprot),
        'initprot=' + String(segment.initprot),
    ].join(' ');
}

function formatSection(section) {
    return [
        section.segmentName + ',' + section.name,
        'addr=' + section.addr.toString(),
        'size=0x' + BigInt(section.size || 0).toString(16),
        'offset=0x' + BigInt(section.offset || 0).toString(16),
        'align=' + String(section.align),
        'flags=0x' + BigInt(section.flags || 0).toString(16),
    ].join(' ');
}

function formatLoadCommand(command) {
    const parts = [
        '#' + String(command.index),
        command.name,
        'cmd=0x' + BigInt(command.cmd || 0).toString(16),
        'cmdsize=' + String(command.cmdsize),
        'offset=0x' + BigInt(command.offset || 0).toString(16),
    ];
    if (command.detail !== null && command.detail !== undefined && String(command.detail).length !== 0) {
        parts.push(String(command.detail));
    }
    return parts.join(' ');
}

function formatSwiftSymbol(symbol) {
    const base = symbol.address.toString() + ' ' + symbol.moduleName + '!' + symbol.name;
    return symbol.demangledName === null || symbol.demangledName === undefined
        ? base
        : base + ' => ' + symbol.demangledName;
}

function formatSwiftType(typeInfo) {
    const base = typeInfo.sourceAddress.toString() + ' ' + typeInfo.moduleName + '!' + typeInfo.name + ' [' + String(typeInfo.sourceKind || 'symbol') + ']';
    return typeInfo.sourceDemangledName === null || typeInfo.sourceDemangledName === undefined
        ? base
        : base + ' <= ' + typeInfo.sourceDemangledName;
}

function formatObjcMethod(method) {
    const prefix = method.isClassMethod ? '+' : '-';
    return method.imp.toString() + ' ' + prefix + '[' + method.className + ' ' + method.selector + ']';
}

function formatDebugSymbol(symbol, rawAddress) {
    if (symbol === null || symbol === undefined) {
        return ptr(rawAddress).toString() + ' <unresolved>';
    }

    const moduleName = symbol.moduleName || '<unknown>';
    const symbolName = symbol.name || '<anonymous>';
    const moduleBase = symbol.moduleBase ? symbol.moduleBase.toString() : '0x0';
    const offset = typeof symbol.offset === 'bigint' ? symbol.offset : BigInt(symbol.offset || 0);
    return ptr(rawAddress).toString() + ' ' + moduleName + '!' + symbolName + '+0x' + offset.toString(16) + ' moduleBase=' + moduleBase;
}

function formatHookEnvironmentReport(report) {
    const lines = [];
    lines.push('active=' + (report.activeBackend === null || report.activeBackend === undefined ? '<none>' : report.activeBackend));
    lines.push('policy=' + String(report.policy));
    lines.push('strategy=' + String(report.strategy));
    lines.push('allowed=' + String(!!report.allowed));
    lines.push('inline_hooks_allowed=' + String(!!report.inlineHooksAllowed));
    if (report.reason !== null && report.reason !== undefined) {
        lines.push('reason=' + String(report.reason));
    }

    const backends = Array.isArray(report.backends) ? report.backends : [];
    for (const backend of backends) {
        lines.push('backend ' + backend.id + ' ' + backend.name);
        const loadedImages = Array.isArray(backend.loadedImages) ? backend.loadedImages : [];
        for (const image of loadedImages) {
            lines.push('  loaded ' + image);
        }
        const filesystemPaths = Array.isArray(backend.filesystemPaths) ? backend.filesystemPaths : [];
        for (const path of filesystemPaths) {
            lines.push('  fs ' + path);
        }
    }

    const warnings = Array.isArray(report.warnings) ? report.warnings : [];
    for (const warning of warnings) {
        lines.push('warning ' + warning);
    }

    const recommendations = Array.isArray(report.recommendations) ? report.recommendations : [];
    for (const recommendation of recommendations) {
        lines.push('advice ' + recommendation);
    }

    return lines.join('\n');
}

function normalizeImage(image) {
    if (image === null || image === undefined) {
        return null;
    }
    const path = String(image.path || image.name || '');
    const pathParts = path.split('/').filter(Boolean);
    return {
        path,
        name: pathParts.length === 0 ? path : pathParts[pathParts.length - 1],
        base: image.base.toString(),
        slide: formatSlide(image.slide),
        text: formatImage(image),
    };
}

function normalizeObjcMethod(method) {
    return {
        className: String(method.className || ''),
        selector: String(method.selector || ''),
        isClassMethod: !!method.isClassMethod,
        imp: method.imp.toString(),
        text: formatObjcMethod(method),
    };
}

function normalizeDebugSymbol(symbol, rawAddress) {
    const raw = ptr(rawAddress).toString();
    if (symbol === null || symbol === undefined) {
        return {
            address: raw,
            resolved: false,
            moduleName: null,
            name: null,
            moduleBase: null,
            offsetHex: null,
            text: formatDebugSymbol(symbol, rawAddress),
        };
    }

    const offset = typeof symbol.offset === 'bigint' ? symbol.offset : BigInt(symbol.offset || 0);
    return {
        address: raw,
        resolved: true,
        moduleName: symbol.moduleName === undefined ? null : symbol.moduleName,
        name: symbol.name === undefined ? null : symbol.name,
        moduleBase: symbol.moduleBase ? symbol.moduleBase.toString() : null,
        offsetHex: '0x' + offset.toString(16),
        text: formatDebugSymbol(symbol, rawAddress),
    };
}

function normalizeNativeSymbol(symbol) {
    const offset = typeof symbol.offset === 'bigint' ? symbol.offset : BigInt(symbol.offset || 0);
    return {
        moduleName: String(symbol.moduleName || ''),
        moduleBase: symbol.moduleBase ? symbol.moduleBase.toString() : null,
        name: String(symbol.name || ''),
        address: symbol.address.toString(),
        offsetHex: '0x' + offset.toString(16),
        text: formatNativeSymbol(symbol),
    };
}

function normalizeImport(imp) {
    return {
        moduleName: String(imp.moduleName || ''),
        moduleBase: imp.moduleBase ? imp.moduleBase.toString() : null,
        name: String(imp.name || ''),
        dylibOrdinal: Number(imp.dylibOrdinal || 0),
        dylibName: imp.dylibName === undefined ? null : imp.dylibName,
        weakImport: !!imp.weakImport,
        text: formatImport(imp),
    };
}

function normalizeDependency(dep) {
    const path = String(dep.path || '');
    const pathParts = path.split('/').filter(Boolean);
    return {
        moduleName: String(dep.moduleName || ''),
        moduleBase: dep.moduleBase ? dep.moduleBase.toString() : null,
        ordinal: Number(dep.ordinal || 0),
        path,
        name: pathParts.length === 0 ? path : pathParts[pathParts.length - 1],
        kind: String(dep.kind || 'load'),
        currentVersion: formatPackedVersion(dep.currentVersion),
        compatibilityVersion: formatPackedVersion(dep.compatibilityVersion),
        timestamp: Number(dep.timestamp || 0),
        text: formatDependency(dep),
    };
}

function normalizeEncryptionInfo(encryptionInfo) {
    return {
        moduleName: String(encryptionInfo.moduleName || ''),
        moduleBase: encryptionInfo.moduleBase ? encryptionInfo.moduleBase.toString() : null,
        cryptoffHex: '0x' + BigInt(encryptionInfo.cryptoff || 0).toString(16),
        cryptsizeHex: '0x' + BigInt(encryptionInfo.cryptsize || 0).toString(16),
        cryptid: Number(encryptionInfo.cryptid || 0),
        text: formatEncryptionInfo(encryptionInfo),
    };
}

function normalizeBuildVersion(buildVersion) {
    const tools = Array.isArray(buildVersion.tools)
        ? buildVersion.tools.map((tool) => ({
            tool: String(tool.tool || 'tool'),
            version: String(tool.version || ''),
        }))
        : [];
    return {
        moduleName: String(buildVersion.moduleName || ''),
        moduleBase: buildVersion.moduleBase ? buildVersion.moduleBase.toString() : null,
        platform: String(buildVersion.platform || 'unknown'),
        minOs: String(buildVersion.minOs || ''),
        sdk: String(buildVersion.sdk || ''),
        tools,
        text: formatBuildVersion(buildVersion),
    };
}

function normalizeDylinker(dylinker) {
    const path = String(dylinker.path || '');
    const pathParts = path.split('/').filter(Boolean);
    return {
        moduleName: String(dylinker.moduleName || ''),
        moduleBase: dylinker.moduleBase ? dylinker.moduleBase.toString() : null,
        path,
        name: pathParts.length === 0 ? path : pathParts[pathParts.length - 1],
        kind: String(dylinker.kind || 'load'),
        text: formatDylinker(dylinker),
    };
}

function normalizeInstallName(installName) {
    const path = String(installName.path || '');
    const pathParts = path.split('/').filter(Boolean);
    return {
        moduleName: String(installName.moduleName || ''),
        moduleBase: installName.moduleBase ? installName.moduleBase.toString() : null,
        path,
        name: pathParts.length === 0 ? path : pathParts[pathParts.length - 1],
        currentVersion: formatPackedVersion(installName.currentVersion),
        compatibilityVersion: formatPackedVersion(installName.compatibilityVersion),
        timestamp: Number(installName.timestamp || 0),
        text: formatInstallName(installName),
    };
}

function normalizeUuid(imageUuid) {
    return {
        moduleName: String(imageUuid.moduleName || ''),
        moduleBase: imageUuid.moduleBase ? imageUuid.moduleBase.toString() : null,
        uuid: String(imageUuid.uuid || ''),
        text: formatUuid(imageUuid),
    };
}

function normalizeRpath(rpath) {
    const path = String(rpath.path || '');
    return {
        moduleName: String(rpath.moduleName || ''),
        moduleBase: rpath.moduleBase ? rpath.moduleBase.toString() : null,
        path,
        text: formatRpath(rpath),
    };
}

function normalizeSegment(segment) {
    return {
        moduleName: String(segment.moduleName || ''),
        moduleBase: segment.moduleBase ? segment.moduleBase.toString() : null,
        name: String(segment.name || ''),
        vmaddr: segment.vmaddr.toString(),
        vmsizeHex: '0x' + BigInt(segment.vmsize || 0).toString(16),
        fileoffHex: '0x' + BigInt(segment.fileoff || 0).toString(16),
        filesizeHex: '0x' + BigInt(segment.filesize || 0).toString(16),
        maxprot: String(segment.maxprot),
        initprot: String(segment.initprot),
        text: formatSegment(segment),
    };
}

function normalizeSection(section) {
    return {
        moduleName: String(section.moduleName || ''),
        moduleBase: section.moduleBase ? section.moduleBase.toString() : null,
        segmentName: String(section.segmentName || ''),
        name: String(section.name || ''),
        addr: section.addr.toString(),
        sizeHex: '0x' + BigInt(section.size || 0).toString(16),
        offsetHex: '0x' + BigInt(section.offset || 0).toString(16),
        align: String(section.align),
        flagsHex: '0x' + BigInt(section.flags || 0).toString(16),
        text: formatSection(section),
    };
}

function normalizeLoadCommand(command) {
    return {
        moduleName: String(command.moduleName || ''),
        moduleBase: command.moduleBase ? command.moduleBase.toString() : null,
        index: Number(command.index || 0),
        name: String(command.name || ''),
        cmdHex: '0x' + BigInt(command.cmd || 0).toString(16),
        cmdsize: Number(command.cmdsize || 0),
        offsetHex: '0x' + BigInt(command.offset || 0).toString(16),
        detail: command.detail === undefined ? null : command.detail,
        text: formatLoadCommand(command),
    };
}

function normalizeSwiftSymbol(symbol) {
    const offset = typeof symbol.offset === 'bigint' ? symbol.offset : BigInt(symbol.offset || 0);
    return {
        moduleName: String(symbol.moduleName || ''),
        moduleBase: symbol.moduleBase ? symbol.moduleBase.toString() : null,
        name: String(symbol.name || ''),
        demangledName: symbol.demangledName === undefined ? null : symbol.demangledName,
        address: symbol.address.toString(),
        offsetHex: '0x' + offset.toString(16),
        text: formatSwiftSymbol(symbol),
    };
}

function normalizeSwiftType(typeInfo) {
    const sourceOffset = typeof typeInfo.sourceOffset === 'bigint' ? typeInfo.sourceOffset : BigInt(typeInfo.sourceOffset || 0);
    return {
        moduleName: String(typeInfo.moduleName || ''),
        moduleBase: typeInfo.moduleBase ? typeInfo.moduleBase.toString() : null,
        name: String(typeInfo.name || ''),
        sourceSymbolName: typeInfo.sourceSymbolName === undefined ? null : String(typeInfo.sourceSymbolName),
        sourceKind: typeInfo.sourceKind === undefined ? null : typeInfo.sourceKind,
        sourceAddress: typeInfo.sourceAddress.toString(),
        sourceOffsetHex: '0x' + sourceOffset.toString(16),
        sourceDemangledName: typeInfo.sourceDemangledName === undefined ? null : typeInfo.sourceDemangledName,
        text: formatSwiftType(typeInfo),
    };
}

function handleSpecResult(spec) {
    if (spec === null || typeof spec !== 'object') {
        throw new Error('agent command spec must be an object');
    }

    switch (String(spec.kind || '')) {
    case 'objc.classes': {
        const filter = spec.filter === null || spec.filter === undefined ? null : String(spec.filter).trim();
        const classes = (filter === null || filter.length === 0 ? ObjC.classes() : ObjC.findClasses(filter));
        return {
            kind: 'objc.classes',
            filter,
            count: classes.length,
            classes,
            text: classes.join('\n'),
        };
    }
    case 'objc.class_exists': {
        const className = String(spec.className || '');
        const exists = !!ObjC.classExists(className);
        return { kind: 'objc.class_exists', className, exists, text: String(exists) };
    }
    case 'objc.selector': {
        const selectorName = String(spec.selectorName || '');
        const pointer = ObjC.selector(selectorName).toString();
        return { kind: 'objc.selector', selectorName, pointer, text: pointer };
    }
    case 'objc.method_imp': {
        const className = String(spec.className || '');
        const selectorName = String(spec.selectorName || '');
        const isClassMethod = !!spec.isClassMethod;
        const imp = ObjC.methodImp(className, selectorName, isClassMethod);
        const pointer = imp === null ? null : imp.toString();
        return {
            kind: 'objc.method_imp',
            className,
            selectorName,
            isClassMethod,
            imp: pointer,
            text: pointer === null ? '<null>' : pointer,
        };
    }
    case 'objc.class_image': {
        const className = String(spec.className || '');
        const imagePath = ObjC.classImage(className);
        return {
            kind: 'objc.class_image',
            className,
            imagePath: imagePath === null ? null : String(imagePath),
            text: imagePath === null ? '<null>' : String(imagePath),
        };
    }
    case 'objc.method_image': {
        const className = String(spec.className || '');
        const selectorName = String(spec.selectorName || '');
        const isClassMethod = !!spec.isClassMethod;
        const imagePath = ObjC.methodImage(className, selectorName, isClassMethod);
        return {
            kind: 'objc.method_image',
            className,
            selectorName,
            isClassMethod,
            imagePath: imagePath === null ? null : String(imagePath),
            text: imagePath === null ? '<null>' : String(imagePath),
        };
    }
    case 'objc.selector_name': {
        const selector = parseAddressArg(spec.selector, 'objc.selectorName usage: objc.selectorName <selector>');
        const name = ObjC.selectorName(selector);
        return {
            kind: 'objc.selector_name',
            selector: selector.toString(),
            name: name === null ? null : String(name),
            text: name === null ? '<null>' : String(name),
        };
    }
    case 'objc.object_class_name': {
        const object = parseAddressArg(spec.object, 'objc.objectClassName usage: objc.objectClassName <object>');
        const className = ObjC.objectClassName(object);
        return {
            kind: 'objc.object_class_name',
            object: object.toString(),
            className: className === null ? null : String(className),
            text: className === null ? '<null>' : String(className),
        };
    }
    case 'objc.methods': {
        const className = String(spec.className || '');
        const isClassMethod = !!spec.isClassMethod;
        const filter = spec.filter === null || spec.filter === undefined ? null : String(spec.filter);
        const methods = (filter === null
            ? ObjC.methods(className, isClassMethod)
            : ObjC.findMethods(className, filter, isClassMethod)).map((method) => normalizeObjcMethod(method));
        return {
            kind: 'objc.methods',
            className,
            isClassMethod,
            filter,
            count: methods.length,
            methods,
            text: methods.map((method) => method.text).join('\n'),
        };
    }
    case 'objc.method_owners': {
        const query = String(spec.query || '');
        const isClassMethod = !!spec.isClassMethod;
        const methods = ObjC.findMethodOwners(query, isClassMethod).map((method) => normalizeObjcMethod(method));
        return {
            kind: 'objc.method_owners',
            query,
            isClassMethod,
            count: methods.length,
            methods,
            text: methods.map((method) => method.text).join('\n'),
        };
    }
    case 'native.images': {
        const filter = spec.filter === null || spec.filter === undefined ? null : String(spec.filter).trim().toLowerCase();
        const images = Module.enumerateModules()
            .filter((image) => filter === null || filter.length === 0 || String(image.path || image.name || '').toLowerCase().indexOf(filter) !== -1)
            .map((image) => normalizeImage(image));
        return { kind: 'native.images', filter, count: images.length, images, text: images.map((image) => image.text).join('\n') };
    }
    case 'native.base': {
        const moduleName = String(spec.moduleName || '');
        const base = Module.findBaseAddress(moduleName);
        return {
            kind: 'native.base',
            moduleName,
            base: base === null ? null : base.toString(),
            text: base === null ? '<null>' : base.toString(),
        };
    }
    case 'native.main_image': {
        const images = Module.enumerateModules();
        const image = images.length === 0 ? null : normalizeImage(images[0]);
        return { kind: 'native.main_image', image, text: image === null ? '<null>' : image.text };
    }
    case 'native.image': {
        const address = parseAddressArg(spec.address, 'native.image usage: native.image <address>');
        const image = Module.findByAddress(address);
        const normalized = image === null ? null : normalizeImage(image);
        return { kind: 'native.image', address: address.toString(), image: normalized, text: normalized === null ? '<null>' : normalized.text };
    }
    case 'native.symbol': {
        const address = parseAddressArg(spec.address, 'native.symbol usage: native.symbol <address>');
        const symbol = normalizeDebugSymbol(DebugSymbol.fromAddress(address), address);
        return { kind: 'native.symbol', address: address.toString(), symbol, text: symbol.text };
    }
    case 'native.export': {
        const moduleName = spec.moduleName === null || spec.moduleName === undefined ? null : String(spec.moduleName);
        const symbolName = String(spec.symbolName || '');
        const address = Module.findExportByName(moduleName, symbolName);
        const symbol = address === null ? null : normalizeDebugSymbol(DebugSymbol.fromAddress(address), address);
        return {
            kind: 'native.export',
            moduleName,
            symbolName,
            address: address === null ? null : address.toString(),
            symbol,
            text: symbol === null ? '<null>' : symbol.text,
        };
    }
    case 'native.symbols': {
        const moduleName = spec.moduleName === null || spec.moduleName === undefined ? null : String(spec.moduleName);
        const query = String(spec.query || '');
        const symbols = Native.findSymbols(query, moduleName).map((symbol) => normalizeNativeSymbol(symbol));
        return { kind: 'native.symbols', moduleName, query, count: symbols.length, symbols, text: symbols.map((symbol) => symbol.text).join('\n') };
    }
    case 'native.exports': {
        const moduleName = String(spec.moduleName || '');
        const query = spec.query === null || spec.query === undefined ? null : String(spec.query);
        const symbols = Native.findExports(moduleName, query).map((symbol) => normalizeNativeSymbol(symbol));
        return { kind: 'native.exports', moduleName, query, count: symbols.length, symbols, text: symbols.map((symbol) => symbol.text).join('\n') };
    }
    case 'native.dependencies': {
        const moduleName = String(spec.moduleName || '');
        const query = spec.query === null || spec.query === undefined ? null : String(spec.query);
        const dependencies = Native.findDependencies(moduleName, query).map((dependency) => normalizeDependency(dependency));
        return { kind: 'native.dependencies', moduleName, query, count: dependencies.length, dependencies, text: dependencies.map((dependency) => dependency.text).join('\n') };
    }
    case 'native.encryption_info': {
        const moduleName = String(spec.moduleName || '');
        const encryptionInfo = Native.findEncryptionInfo(moduleName);
        const normalized = encryptionInfo === null ? null : normalizeEncryptionInfo(encryptionInfo);
        return { kind: 'native.encryption_info', moduleName, encryptionInfo: normalized, text: normalized === null ? '<null>' : normalized.text };
    }
    case 'native.build_version': {
        const moduleName = String(spec.moduleName || '');
        const buildVersion = Native.findBuildVersion(moduleName);
        const normalized = buildVersion === null ? null : normalizeBuildVersion(buildVersion);
        return { kind: 'native.build_version', moduleName, buildVersion: normalized, text: normalized === null ? '<null>' : normalized.text };
    }
    case 'native.dylinker': {
        const moduleName = String(spec.moduleName || '');
        const dylinker = Native.findDylinker(moduleName);
        const normalized = dylinker === null ? null : normalizeDylinker(dylinker);
        return { kind: 'native.dylinker', moduleName, dylinker: normalized, text: normalized === null ? '<null>' : normalized.text };
    }
    case 'native.install_name': {
        const moduleName = String(spec.moduleName || '');
        const installName = Native.findInstallName(moduleName);
        const normalized = installName === null ? null : normalizeInstallName(installName);
        return { kind: 'native.install_name', moduleName, installName: normalized, text: normalized === null ? '<null>' : normalized.text };
    }
    case 'native.uuid': {
        const moduleName = String(spec.moduleName || '');
        const imageUuid = Native.findUuid(moduleName);
        const normalized = imageUuid === null ? null : normalizeUuid(imageUuid);
        return { kind: 'native.uuid', moduleName, imageUuid: normalized, text: normalized === null ? '<null>' : normalized.text };
    }
    case 'native.rpaths': {
        const moduleName = String(spec.moduleName || '');
        const query = spec.query === null || spec.query === undefined ? null : String(spec.query);
        const rpaths = Native.findRpaths(moduleName, query).map((rpath) => normalizeRpath(rpath));
        return { kind: 'native.rpaths', moduleName, query, count: rpaths.length, rpaths, text: rpaths.map((rpath) => rpath.text).join('\n') };
    }
    case 'native.imports': {
        const moduleName = String(spec.moduleName || '');
        const query = spec.query === null || spec.query === undefined ? null : String(spec.query);
        const imports = Native.findImports(moduleName, query).map((imp) => normalizeImport(imp));
        return { kind: 'native.imports', moduleName, query, count: imports.length, imports, text: imports.map((imp) => imp.text).join('\n') };
    }
    case 'native.segments': {
        const moduleName = String(spec.moduleName || '');
        const segments = Native.findSegments(moduleName).map((segment) => normalizeSegment(segment));
        return { kind: 'native.segments', moduleName, count: segments.length, segments, text: segments.map((segment) => segment.text).join('\n') };
    }
    case 'native.sections': {
        const moduleName = String(spec.moduleName || '');
        const sections = Native.findSections(moduleName).map((section) => normalizeSection(section));
        return { kind: 'native.sections', moduleName, count: sections.length, sections, text: sections.map((section) => section.text).join('\n') };
    }
    case 'native.load_commands': {
        const moduleName = String(spec.moduleName || '');
        const commands = Native.findLoadCommands(moduleName).map((command) => normalizeLoadCommand(command));
        return { kind: 'native.load_commands', moduleName, count: commands.length, commands, text: commands.map((command) => command.text).join('\n') };
    }
    case 'native.hook_environment': {
        const report = Native.detectHookEnvironment();
        return { kind: 'native.hook_environment', report, text: formatHookEnvironmentReport(report) };
    }
    case 'pac.available': {
        const available = !!PAC.available;
        return { kind: 'pac.available', available, text: String(available) };
    }
    case 'pac.arm64e': {
        const arm64e = !!PAC.isProcessArm64e();
        return { kind: 'pac.arm64e', arm64e, text: String(arm64e) };
    }
    case 'pac.image': {
        const moduleName = String(spec.moduleName || '');
        const arm64e = PAC.isImageArm64e(moduleName);
        return { kind: 'pac.image', moduleName, arm64e: arm64e === null ? null : !!arm64e, text: arm64e === null ? '<null>' : String(!!arm64e) };
    }
    case 'pac.images': {
        const filter = spec.filter === null || spec.filter === undefined ? null : String(spec.filter);
        const images = PAC.arm64eImages(filter).map((image) => normalizeImage(image));
        return { kind: 'pac.images', filter, count: images.length, images, text: images.map((image) => image.text).join('\n') };
    }
    case 'pac.strip': {
        const address = parseAddressArg(spec.address, 'pac.strip usage: pac.strip <address>');
        const stripped = PAC.strip(address).toString();
        return { kind: 'pac.strip', address: address.toString(), stripped, text: stripped };
    }
    case 'pac.stripdata': {
        const address = parseAddressArg(spec.address, 'pac.stripdata usage: pac.stripdata <address>');
        const stripped = PAC.stripData(address).toString();
        return { kind: 'pac.stripdata', address: address.toString(), stripped, text: stripped };
    }
    case 'swift.available': {
        const available = !!Swift.available;
        return { kind: 'swift.available', available, text: String(available) };
    }
    case 'swift.demangle': {
        const symbol = String(spec.symbol || '');
        const demangled = Swift.demangle(symbol);
        return { kind: 'swift.demangle', symbol, demangled: demangled === null || demangled === undefined ? null : String(demangled), text: demangled === null || demangled === undefined ? '<unavailable>' : String(demangled) };
    }
    case 'swift.symbols': {
        const moduleName = spec.moduleName === null || spec.moduleName === undefined ? null : String(spec.moduleName);
        const query = String(spec.query || '');
        const symbols = Swift.findSymbols(query, moduleName).map((symbol) => normalizeSwiftSymbol(symbol));
        return { kind: 'swift.symbols', moduleName, query, count: symbols.length, symbols, text: symbols.map((symbol) => symbol.text).join('\n') };
    }
    case 'swift.types': {
        const moduleName = spec.moduleName === null || spec.moduleName === undefined ? null : String(spec.moduleName);
        const query = String(spec.query || '');
        const types = Swift.findTypes(query, moduleName).map((typeInfo) => normalizeSwiftType(typeInfo));
        return { kind: 'swift.types', moduleName, query, count: types.length, types, text: types.map((typeInfo) => typeInfo.text).join('\n') };
    }
    case 'swift.type_kinds': {
        const kinds = Swift.typeSourceKinds();
        return { kind: 'swift.type_kinds', count: kinds.length, kinds, text: kinds.join('\n') };
    }
    case 'swift.types_of_kind': {
        const moduleName = spec.moduleName === null || spec.moduleName === undefined ? null : String(spec.moduleName);
        const sourceKind = String(spec.sourceKind || '');
        const query = String(spec.query || '');
        const types = Swift.findTypesOfKind(sourceKind, query, moduleName).map((typeInfo) => normalizeSwiftType(typeInfo));
        return { kind: 'swift.types_of_kind', moduleName, sourceKind, query, count: types.length, types, text: types.map((typeInfo) => typeInfo.text).join('\n') };
    }
    case 'swift.method_owners': {
        const moduleName = spec.moduleName === null || spec.moduleName === undefined ? null : String(spec.moduleName);
        const query = String(spec.query || '');
        const owners = Swift.findMethodOwners(query, moduleName).map((typeInfo) => normalizeSwiftType(typeInfo));
        return { kind: 'swift.method_owners', moduleName, query, count: owners.length, owners, text: owners.map((typeInfo) => typeInfo.text).join('\n') };
    }
    case 'swift.type_methods': {
        const moduleName = spec.moduleName === null || spec.moduleName === undefined ? null : String(spec.moduleName);
        const query = String(spec.query || '');
        const methods = Swift.findTypeMethods(query, moduleName).map((symbol) => normalizeSwiftSymbol(symbol));
        return { kind: 'swift.type_methods', moduleName, query, count: methods.length, methods, text: methods.map((symbol) => symbol.text).join('\n') };
    }
    case 'swift.methods': {
        const moduleName = spec.moduleName === null || spec.moduleName === undefined ? null : String(spec.moduleName);
        const typeName = String(spec.typeName || '');
        const methodQuery = String(spec.methodQuery || '');
        const methods = Swift.findMethods(typeName, methodQuery, moduleName).map((symbol) => normalizeSwiftSymbol(symbol));
        return { kind: 'swift.methods', moduleName, typeName, methodQuery, count: methods.length, methods, text: methods.map((symbol) => symbol.text).join('\n') };
    }
    default:
        throw new Error('unsupported agent helper command spec: ' + String(spec.kind));
    }
}

function handleSpec(spec) {
    return handleSpecResult(spec).text;
}

function legacyToSpec(command) {
    const trimmed = String(command || '').trim();

    if (trimmed === 'objc.classes') {
        return { kind: 'objc.classes', filter: null };
    }

    if (trimmed.startsWith('objc.classes ')) {
        return { kind: 'objc.classes', filter: trimmed.slice('objc.classes '.length) };
    }

    if (trimmed.startsWith('objc.classExists ')) {
        return { kind: 'objc.class_exists', className: trimmed.slice('objc.classExists '.length) };
    }

    if (trimmed.startsWith('objc.selector ')) {
        return { kind: 'objc.selector', selectorName: trimmed.slice('objc.selector '.length) };
    }

    if (trimmed.startsWith('objc.methodImp ')) {
        const parsed = parseObjcMethodImp(trimmed.slice('objc.methodImp '.length));
        return {
            kind: 'objc.method_imp',
            className: parsed.className,
            selectorName: parsed.selectorName,
            isClassMethod: parsed.isClassMethod,
        };
    }

    if (trimmed.startsWith('objc.classImage ')) {
        return { kind: 'objc.class_image', className: trimmed.slice('objc.classImage '.length) };
    }

    if (trimmed.startsWith('objc.methodImage ')) {
        const parsed = parseObjcMethodImp(trimmed.slice('objc.methodImage '.length));
        return {
            kind: 'objc.method_image',
            className: parsed.className,
            selectorName: parsed.selectorName,
            isClassMethod: parsed.isClassMethod,
        };
    }

    if (trimmed.startsWith('objc.selectorName ')) {
        return {
            kind: 'objc.selector_name',
            selector: trimmed.slice('objc.selectorName '.length),
        };
    }

    if (trimmed.startsWith('objc.objectClassName ')) {
        return {
            kind: 'objc.object_class_name',
            object: trimmed.slice('objc.objectClassName '.length),
        };
    }

    if (trimmed.startsWith('objc.methods ')) {
        const parsed = parseObjcMethods(trimmed.slice('objc.methods '.length));
        return {
            kind: 'objc.methods',
            className: parsed.className,
            isClassMethod: parsed.isClassMethod,
            filter: parsed.filter,
        };
    }

    if (trimmed.startsWith('objc.methodOwners ')) {
        const parsed = parseObjcMethodOwners(trimmed.slice('objc.methodOwners '.length));
        return {
            kind: 'objc.method_owners',
            query: parsed.query,
            isClassMethod: parsed.isClassMethod,
        };
    }

    if (trimmed === 'native.images') {
        return { kind: 'native.images', filter: null };
    }

    if (trimmed.startsWith('native.base ')) {
        const moduleName = trimmed.slice('native.base '.length).trim();
        if (moduleName.length === 0) {
            throw new Error('native.base usage: native.base <module>');
        }
        return { kind: 'native.base', moduleName };
    }

    if (trimmed.startsWith('native.images ')) {
        const filter = trimmed.slice('native.images '.length).trim().toLowerCase();
        if (filter.length === 0) {
            throw new Error('native.images usage: native.images [filter]');
        }
        return { kind: 'native.images', filter };
    }

    if (trimmed === 'native.mainImage') {
        return { kind: 'native.main_image' };
    }

    if (trimmed.startsWith('native.image ')) {
        return {
            kind: 'native.image',
            address: trimmed.slice('native.image '.length),
        };
    }

    if (trimmed.startsWith('native.symbol ')) {
        return {
            kind: 'native.symbol',
            address: trimmed.slice('native.symbol '.length),
        };
    }

    if (trimmed.startsWith('native.export ')) {
        const parsed = parseNativeExport(trimmed.slice('native.export '.length));
        return {
            kind: 'native.export',
            moduleName: parsed.moduleName,
            symbolName: parsed.query,
        };
    }

    if (trimmed.startsWith('native.symbols ')) {
        const parsed = splitModuleQuery(
            trimmed.slice('native.symbols '.length),
            'native.symbols usage: native.symbols <query> | native.symbols <module> -- <query>'
        );
        return {
            kind: 'native.symbols',
            moduleName: parsed.moduleName,
            query: parsed.query,
        };
    }

    if (trimmed.startsWith('native.exports ')) {
        const parsed = parseNativeExports(trimmed.slice('native.exports '.length));
        return {
            kind: 'native.exports',
            moduleName: parsed.moduleName,
            query: parsed.query,
        };
    }

    if (trimmed.startsWith('native.dependencies ')) {
        const parsed = parseNativeExports(trimmed.slice('native.dependencies '.length));
        return {
            kind: 'native.dependencies',
            moduleName: parsed.moduleName,
            query: parsed.query,
        };
    }

    if (trimmed.startsWith('native.encryptionInfo ')) {
        const moduleName = trimmed.slice('native.encryptionInfo '.length).trim();
        if (moduleName.length === 0) {
            throw new Error('native.encryptionInfo usage: native.encryptionInfo <module>');
        }
        return {
            kind: 'native.encryption_info',
            moduleName,
        };
    }

    if (trimmed.startsWith('native.buildVersion ')) {
        const moduleName = trimmed.slice('native.buildVersion '.length).trim();
        if (moduleName.length === 0) {
            throw new Error('native.buildVersion usage: native.buildVersion <module>');
        }
        return {
            kind: 'native.build_version',
            moduleName,
        };
    }

    if (trimmed.startsWith('native.dylinker ')) {
        const moduleName = trimmed.slice('native.dylinker '.length).trim();
        if (moduleName.length === 0) {
            throw new Error('native.dylinker usage: native.dylinker <module>');
        }
        return {
            kind: 'native.dylinker',
            moduleName,
        };
    }

    if (trimmed.startsWith('native.installName ')) {
        const moduleName = trimmed.slice('native.installName '.length).trim();
        if (moduleName.length === 0) {
            throw new Error('native.installName usage: native.installName <module>');
        }
        return {
            kind: 'native.install_name',
            moduleName,
        };
    }

    if (trimmed.startsWith('native.uuid ')) {
        const moduleName = trimmed.slice('native.uuid '.length).trim();
        if (moduleName.length === 0) {
            throw new Error('native.uuid usage: native.uuid <module>');
        }
        return {
            kind: 'native.uuid',
            moduleName,
        };
    }

    if (trimmed.startsWith('native.rpaths ')) {
        const parsed = parseNativeExports(trimmed.slice('native.rpaths '.length));
        return {
            kind: 'native.rpaths',
            moduleName: parsed.moduleName,
            query: parsed.query,
        };
    }

    if (trimmed.startsWith('native.imports ')) {
        const parsed = parseNativeExports(trimmed.slice('native.imports '.length));
        return {
            kind: 'native.imports',
            moduleName: parsed.moduleName,
            query: parsed.query,
        };
    }

    if (trimmed.startsWith('native.segments ')) {
        const moduleName = trimmed.slice('native.segments '.length).trim();
        if (moduleName.length === 0) {
            throw new Error('native.segments usage: native.segments <module>');
        }
        return { kind: 'native.segments', moduleName };
    }

    if (trimmed.startsWith('native.sections ')) {
        const moduleName = trimmed.slice('native.sections '.length).trim();
        if (moduleName.length === 0) {
            throw new Error('native.sections usage: native.sections <module>');
        }
        return { kind: 'native.sections', moduleName };
    }

    if (trimmed.startsWith('native.loadcmds ')) {
        const moduleName = trimmed.slice('native.loadcmds '.length).trim();
        if (moduleName.length === 0) {
            throw new Error('native.loadcmds usage: native.loadcmds <module>');
        }
        return { kind: 'native.load_commands', moduleName };
    }

    if (trimmed === 'native.hookenv') {
        return { kind: 'native.hook_environment' };
    }

    if (trimmed === 'pac.available') {
        return { kind: 'pac.available' };
    }

    if (trimmed === 'pac.arm64e') {
        return { kind: 'pac.arm64e' };
    }

    if (trimmed.startsWith('pac.image ')) {
        const moduleName = trimmed.slice('pac.image '.length).trim();
        if (moduleName.length === 0) {
            throw new Error('pac.image usage: pac.image <module>');
        }
        return { kind: 'pac.image', moduleName };
    }

    if (trimmed === 'pac.images') {
        return { kind: 'pac.images', filter: null };
    }

    if (trimmed.startsWith('pac.images ')) {
        const filter = trimmed.slice('pac.images '.length).trim();
        if (filter.length === 0) {
            throw new Error('pac.images usage: pac.images [filter]');
        }
        return { kind: 'pac.images', filter };
    }

    if (trimmed.startsWith('pac.stripdata ')) {
        return {
            kind: 'pac.stripdata',
            address: trimmed.slice('pac.stripdata '.length),
        };
    }

    if (trimmed.startsWith('pac.strip ')) {
        return {
            kind: 'pac.strip',
            address: trimmed.slice('pac.strip '.length),
        };
    }

    if (trimmed === 'swift.available') {
        return { kind: 'swift.available' };
    }

    if (trimmed.startsWith('swift.demangle ')) {
        const symbol = trimmed.slice('swift.demangle '.length).trim();
        if (symbol.length === 0) {
            throw new Error('swift.demangle usage: swift.demangle <mangled-symbol>');
        }
        return { kind: 'swift.demangle', symbol };
    }

    if (trimmed.startsWith('swift.symbols ')) {
        const usage = 'swift.symbols usage: swift.symbols <query> | swift.symbols <module> -- <query>';
        const parsed = splitModuleQuery(trimmed.slice('swift.symbols '.length), usage);
        return {
            kind: 'swift.symbols',
            moduleName: parsed.moduleName,
            query: parsed.query,
        };
    }

    if (trimmed.startsWith('swift.types ')) {
        const usage = 'swift.types usage: swift.types <query> | swift.types <module> -- <query>';
        const parsed = splitModuleQuery(trimmed.slice('swift.types '.length), usage);
        return {
            kind: 'swift.types',
            moduleName: parsed.moduleName,
            query: parsed.query,
        };
    }

    if (trimmed === 'swift.typeKinds') {
        return { kind: 'swift.type_kinds' };
    }

    if (trimmed.startsWith('swift.typesOfKind ')) {
        const usage = 'swift.typesOfKind usage: swift.typesOfKind <kind> <query> | swift.typesOfKind <module> -- <kind> <query>';
        const parsed = splitSwiftTypeKindQuery(trimmed.slice('swift.typesOfKind '.length), usage);
        return {
            kind: 'swift.types_of_kind',
            moduleName: parsed.moduleName,
            sourceKind: parsed.sourceKind,
            query: parsed.query,
        };
    }

    if (trimmed.startsWith('swift.methodOwners ')) {
        const usage = 'swift.methodOwners usage: swift.methodOwners <method> | swift.methodOwners <module> -- <method>';
        const parsed = splitModuleQuery(trimmed.slice('swift.methodOwners '.length), usage);
        return {
            kind: 'swift.method_owners',
            moduleName: parsed.moduleName,
            query: parsed.query,
        };
    }

    if (trimmed.startsWith('swift.typeMethods ')) {
        const usage = 'swift.typeMethods usage: swift.typeMethods <type> | swift.typeMethods <module> -- <type>';
        const parsed = splitModuleQuery(trimmed.slice('swift.typeMethods '.length), usage);
        return {
            kind: 'swift.type_methods',
            moduleName: parsed.moduleName,
            query: parsed.query,
        };
    }

    if (trimmed.startsWith('swift.methods ')) {
        const usage = 'swift.methods usage: swift.methods <type> <method> | swift.methods <module> -- <type> <method>';
        const parsed = splitSwiftMethods(trimmed.slice('swift.methods '.length), usage);
        return {
            kind: 'swift.methods',
            moduleName: parsed.moduleName,
            typeName: parsed.typeName,
            methodQuery: parsed.methodQuery,
        };
    }

    throw new Error('unsupported agent helper command: ' + trimmed);
}

function handle(command) {
    return handleSpec(legacyToSpec(command));
}

return {
    handle,
    handleSpec,
    handleSpecResult,
};
})();"#
}
