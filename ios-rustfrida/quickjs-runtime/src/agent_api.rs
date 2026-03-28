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

function parseObjcPropertyInfo(raw) {
    const parts = String(raw || '').trim().split(/\s+/).filter(Boolean);
    if (parts.length < 2) {
        throw new Error('objc.propertyInfo usage: objc.propertyInfo <class> <property> [meta]');
    }
    return {
        className: parts[0],
        propertyName: parts[1],
        isClassProperty: parts.slice(2).some((part) => part === 'meta' || part === 'class' || part === '+'),
    };
}

function parseObjcClassInfo(raw) {
    const parts = String(raw || '').trim().split(/\s+/).filter(Boolean);
    if (parts.length === 0) {
        throw new Error('objc.classInfo usage: objc.classInfo <class> [meta]');
    }
    if (parts.length > 2) {
        throw new Error('objc.classInfo usage: objc.classInfo <class> [meta]');
    }
    const isMetaClass = parts.length === 2
        ? (parts[1] === 'meta' || parts[1] === 'class' || parts[1] === '+')
        : false;
    if (parts.length === 2 && !isMetaClass && parts[1] !== 'instance' && parts[1] !== 'inst' && parts[1] !== '-') {
        throw new Error('objc.classInfo usage: objc.classInfo <class> [meta]');
    }
    return {
        className: parts[0],
        isMetaClass,
    };
}

function parseObjcProtocolInfo(raw) {
    const trimmed = String(raw || '').trim();
    if (trimmed.length === 0) {
        throw new Error('objc.protocolInfo usage: objc.protocolInfo <protocol>');
    }
    return {
        protocolName: trimmed,
    };
}

function parseObjcProtocolPropertyInfo(raw) {
    const parts = String(raw || '').trim().split(/\s+/).filter(Boolean);
    if (parts.length < 2) {
        throw new Error('objc.protocolPropertyInfo usage: objc.protocolPropertyInfo <protocol> <property>');
    }
    return {
        protocolName: parts[0],
        propertyName: parts[1],
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

function parseObjcFindMethods(raw) {
    const parts = String(raw || '').trim().split(/\s+/).filter(Boolean);
    if (parts.length < 2) {
        throw new Error('objc.findMethods usage: objc.findMethods <class> <query> [meta]');
    }
    let isClassMethod = false;
    let end = parts.length;
    const last = parts[parts.length - 1];
    if (last === 'meta' || last === 'class' || last === '+') {
        isClassMethod = true;
        end -= 1;
    } else if (last === 'instance' || last === 'inst' || last === '-') {
        isClassMethod = false;
        end -= 1;
    }
    if (end <= 1) {
        throw new Error('objc.findMethods usage: objc.findMethods <class> <query> [meta]');
    }
    return {
        className: parts[0],
        isClassMethod,
        filter: parts.slice(1, end).join(' '),
    };
}

function parseObjcProperties(raw) {
    const parts = String(raw || '').trim().split(/\s+/).filter(Boolean);
    if (parts.length === 0) {
        throw new Error('objc.properties usage: objc.properties <class> [meta] [filter]');
    }
    let isClassProperty = false;
    const filterTokens = [];
    for (let i = 1; i < parts.length; i++) {
        const part = parts[i];
        if (filterTokens.length === 0 && (part === 'meta' || part === 'class' || part === '+')) {
            isClassProperty = true;
            continue;
        }
        if (filterTokens.length === 0 && (part === 'instance' || part === 'inst' || part === '-')) {
            isClassProperty = false;
            continue;
        }
        filterTokens.push(part);
    }
    return {
        className: parts[0],
        isClassProperty,
        filter: filterTokens.length === 0 ? null : filterTokens.join(' '),
    };
}

function parseObjcFindProperties(raw) {
    const parts = String(raw || '').trim().split(/\s+/).filter(Boolean);
    if (parts.length < 2) {
        throw new Error('objc.findProperties usage: objc.findProperties <class> <query> [meta]');
    }
    let isClassProperty = false;
    let end = parts.length;
    const last = parts[parts.length - 1];
    if (last === 'meta' || last === 'class' || last === '+') {
        isClassProperty = true;
        end -= 1;
    } else if (last === 'instance' || last === 'inst' || last === '-') {
        isClassProperty = false;
        end -= 1;
    }
    if (end <= 1) {
        throw new Error('objc.findProperties usage: objc.findProperties <class> <query> [meta]');
    }
    return {
        className: parts[0],
        isClassProperty,
        filter: parts.slice(1, end).join(' '),
    };
}

function parseObjcIvars(raw) {
    const parts = String(raw || '').trim().split(/\s+/).filter(Boolean);
    if (parts.length === 0) {
        throw new Error('objc.ivars usage: objc.ivars <class> [filter]');
    }
    return {
        className: parts[0],
        filter: parts.length <= 1 ? null : parts.slice(1).join(' '),
    };
}

function parseObjcFindIvars(raw) {
    const parts = String(raw || '').trim().split(/\s+/).filter(Boolean);
    if (parts.length < 2) {
        throw new Error('objc.findIvars usage: objc.findIvars <class> <query>');
    }
    return {
        className: parts[0],
        filter: parts.slice(1).join(' '),
    };
}

function parseObjcIvarInfo(raw) {
    const parts = String(raw || '').trim().split(/\s+/).filter(Boolean);
    if (parts.length < 2) {
        throw new Error('objc.ivarInfo usage: objc.ivarInfo <class> <ivar>');
    }
    return {
        className: parts[0],
        ivarName: parts[1],
    };
}

function parseObjcProtocolMethods(raw) {
    const parts = String(raw || '').trim().split(/\s+/).filter(Boolean);
    if (parts.length === 0) {
        throw new Error('objc.protocolMethods usage: objc.protocolMethods <protocol> [required] [instance] [filter]');
    }
    let isRequired = true;
    let isInstanceMethod = true;
    const filterTokens = [];
    for (let i = 1; i < parts.length; i++) {
        const part = parts[i];
        if (filterTokens.length === 0) {
            if (part === 'required' || part === 'req') {
                isRequired = true;
                continue;
            }
            if (part === 'optional' || part === 'opt') {
                isRequired = false;
                continue;
            }
            if (part === 'instance' || part === 'inst' || part === '-') {
                isInstanceMethod = true;
                continue;
            }
            if (part === 'class' || part === 'meta' || part === '+') {
                isInstanceMethod = false;
                continue;
            }
        }
        filterTokens.push(part);
    }
    return {
        protocolName: parts[0],
        isRequired,
        isInstanceMethod,
        filter: filterTokens.length === 0 ? null : filterTokens.join(' '),
    };
}

function parseObjcProtocolProperties(raw) {
    const parts = String(raw || '').trim().split(/\s+/).filter(Boolean);
    if (parts.length === 0) {
        throw new Error('objc.protocolProperties usage: objc.protocolProperties <protocol> [filter]');
    }
    return {
        protocolName: parts[0],
        filter: parts.length <= 1 ? null : parts.slice(1).join(' '),
    };
}

function parseObjcClassProtocols(raw) {
    const parts = String(raw || '').trim().split(/\s+/).filter(Boolean);
    if (parts.length === 0) {
        throw new Error('objc.classProtocols usage: objc.classProtocols <class> [filter]');
    }
    return {
        className: parts[0],
        filter: parts.length <= 1 ? null : parts.slice(1).join(' '),
    };
}

function parseObjcProtocolProtocols(raw) {
    const parts = String(raw || '').trim().split(/\s+/).filter(Boolean);
    if (parts.length === 0) {
        throw new Error('objc.protocolProtocols usage: objc.protocolProtocols <protocol> [filter]');
    }
    return {
        protocolName: parts[0],
        filter: parts.length <= 1 ? null : parts.slice(1).join(' '),
    };
}

function parseObjcProtocolMethodInfo(raw) {
    const parts = String(raw || '').trim().split(/\s+/).filter(Boolean);
    if (parts.length < 2) {
        throw new Error('objc.protocolMethodInfo usage: objc.protocolMethodInfo <protocol> <selector> [required] [instance]');
    }
    let isRequired = true;
    let isInstanceMethod = true;
    for (let i = 2; i < parts.length; i++) {
        const part = parts[i];
        if (part === 'required' || part === 'req') {
            isRequired = true;
            continue;
        }
        if (part === 'optional' || part === 'opt') {
            isRequired = false;
            continue;
        }
        if (part === 'instance' || part === 'inst' || part === '-') {
            isInstanceMethod = true;
            continue;
        }
        if (part === 'class' || part === 'meta' || part === '+') {
            isInstanceMethod = false;
            continue;
        }
        throw new Error('objc.protocolMethodInfo usage: objc.protocolMethodInfo <protocol> <selector> [required] [instance]');
    }
    return {
        protocolName: parts[0],
        selectorName: parts[1],
        isRequired,
        isInstanceMethod,
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
    const size = image.sizeHex === undefined || image.sizeHex === null
        ? '0x' + BigInt(image.size || 0).toString(16)
        : String(image.sizeHex);
    return image.base.toString() + ' slide=' + formatSlide(image.slide) + ' size=' + size + ' ' + image.path;
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

function parseNativeSectionInfo(raw) {
    const parsed = parseNativeExports(raw);
    if (parsed.query === null) {
        throw new Error('native.sectionInfo usage: native.sectionInfo <module> -- <segment> <section>');
    }
    const parts = parsed.query.split(/\s+/).filter(Boolean);
    if (parts.length !== 2) {
        throw new Error('native.sectionInfo usage: native.sectionInfo <module> -- <segment> <section>');
    }
    return {
        moduleName: parsed.moduleName,
        segmentName: parts[0],
        sectionName: parts[1],
    };
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

function formatEntryPoint(entryPoint) {
    return [
        'entryoff=0x' + BigInt(entryPoint.entryoff || 0).toString(16),
        'stacksize=0x' + BigInt(entryPoint.stacksize || 0).toString(16),
    ].join(' ');
}

function formatHex(value) {
    return '0x' + BigInt(value || 0).toString(16);
}

function formatHexAdd(left, right) {
    return '0x' + (BigInt(left || 0) + BigInt(right || 0)).toString(16);
}

function formatDyldInfo(dyldInfo) {
    return [
        String(dyldInfo.commandName || 'LC_DYLD_INFO'),
        'rebase=' + formatHex(dyldInfo.rebaseOff) + '/' + formatHex(dyldInfo.rebaseSize),
        'bind=' + formatHex(dyldInfo.bindOff) + '/' + formatHex(dyldInfo.bindSize),
        'weak=' + formatHex(dyldInfo.weakBindOff) + '/' + formatHex(dyldInfo.weakBindSize),
        'lazy=' + formatHex(dyldInfo.lazyBindOff) + '/' + formatHex(dyldInfo.lazyBindSize),
        'export=' + formatHex(dyldInfo.exportOff) + '/' + formatHex(dyldInfo.exportSize),
    ].join(' ');
}

function normalizeDyldInfoRegion(name, offset, size) {
    const offsetValue = BigInt(offset || 0);
    const sizeValue = BigInt(size || 0);
    return {
        name,
        offsetHex: '0x' + offsetValue.toString(16),
        sizeHex: '0x' + sizeValue.toString(16),
        endHex: formatHexAdd(offset, size),
        hasData: sizeValue !== 0n,
        isEmpty: sizeValue === 0n,
    };
}

function formatLinkedit(linkedit) {
    const symtab = linkedit.symoff === null || linkedit.symoff === undefined
        ? 'symtab=<none>'
        : 'symtab=' + formatHex(linkedit.symoff) + '/' + String(linkedit.nsyms === null || linkedit.nsyms === undefined ? 0 : linkedit.nsyms);
    const strtab = linkedit.stroff === null || linkedit.stroff === undefined
        ? 'strtab=<none>'
        : 'strtab=' + formatHex(linkedit.stroff) + '/' + formatHex(linkedit.strsize === null || linkedit.strsize === undefined ? 0 : linkedit.strsize);
    const indirect = linkedit.indirectsymoff === null || linkedit.indirectsymoff === undefined
        ? 'indirect=<none>'
        : 'indirect=' + formatHex(linkedit.indirectsymoff) + '/' + String(linkedit.nindirectsyms === null || linkedit.nindirectsyms === undefined ? 0 : linkedit.nindirectsyms);
    return [
        'vmaddr=' + linkedit.vmaddr.toString(),
        'vmsize=' + formatHex(linkedit.vmsize),
        'fileoff=' + formatHex(linkedit.fileoff),
        'filesize=' + formatHex(linkedit.filesize),
        'base=' + linkedit.computedBase.toString(),
        'end=' + formatHexAdd(linkedit.computedBase, linkedit.filesize),
        symtab,
        strtab,
        indirect,
    ].join(' ');
}

function formatFunctionStart(functionStart) {
    return '+0x' + BigInt(functionStart.offset || 0).toString(16) + ' ' + functionStart.address.toString();
}

function formatFunctionStarts(functionStarts) {
    const starts = Array.isArray(functionStarts.starts) ? functionStarts.starts : [];
    const summary = [
        'dataoff=0x' + BigInt(functionStarts.dataoff || 0).toString(16),
        'datasize=0x' + BigInt(functionStarts.datasize || 0).toString(16),
        'linkeditBase=' + functionStarts.linkeditBase.toString(),
        'dataAddress=' + functionStarts.dataAddress.toString(),
        'count=' + String(starts.length),
    ].join(' ');
    return starts.length === 0
        ? summary
        : summary + '\n' + starts.map((functionStart) => formatFunctionStart(functionStart)).join('\n');
}

function formatCodeSignature(codeSignature) {
    return [
        'dataoff=0x' + BigInt(codeSignature.dataoff || 0).toString(16),
        'datasize=0x' + BigInt(codeSignature.datasize || 0).toString(16),
        'linkeditBase=' + codeSignature.linkeditBase.toString(),
        'dataAddress=' + codeSignature.dataAddress.toString(),
        'magic=' + (codeSignature.magicName === null || codeSignature.magicName === undefined
            ? '<none>'
            : '0x' + BigInt(codeSignature.magic || 0).toString(16) + ':' + String(codeSignature.magicName)),
        'length=' + (codeSignature.length === null || codeSignature.length === undefined
            ? '<none>'
            : '0x' + BigInt(codeSignature.length || 0).toString(16)),
        'count=' + (codeSignature.count === null || codeSignature.count === undefined
            ? '<none>'
            : String(codeSignature.count)),
    ].join(' ');
}

function formatDataInCodeEntry(entry) {
    return [
        '+0x' + BigInt(entry.offset || 0).toString(16),
        entry.address.toString(),
        'length=' + String(entry.length || 0),
        'kind=' + String(entry.kindName || entry.kind || 'unknown'),
    ].join(' ');
}

function formatDataInCode(dataInCode) {
    const entries = Array.isArray(dataInCode.entries) ? dataInCode.entries : [];
    const summary = [
        'dataoff=0x' + BigInt(dataInCode.dataoff || 0).toString(16),
        'datasize=0x' + BigInt(dataInCode.datasize || 0).toString(16),
        'linkeditBase=' + dataInCode.linkeditBase.toString(),
        'dataAddress=' + dataInCode.dataAddress.toString(),
        'count=' + String(entries.length),
    ].join(' ');
    return entries.length === 0
        ? summary
        : summary + '\n' + entries.map((entry) => formatDataInCodeEntry(entry)).join('\n');
}

function formatExportsTrieEntry(entry) {
    const parts = [String(entry.name || '')];
    if (entry.isReexport) {
        parts.push('reexport');
        parts.push('ordinal=' + String(entry.other === null || entry.other === undefined ? 0 : Number(entry.other)));
        parts.push('import=' + String(entry.importName || ''));
    } else {
        if (entry.offset !== null && entry.offset !== undefined) {
            parts.push('offset=0x' + BigInt(entry.offset).toString(16));
        }
        if (entry.address !== null && entry.address !== undefined) {
            parts.push('address=' + entry.address.toString());
        }
        if (entry.isStubAndResolver && entry.other !== null && entry.other !== undefined) {
            parts.push('resolver=0x' + BigInt(entry.other).toString(16));
        }
    }
    parts.push('flags=0x' + BigInt(entry.flags || 0).toString(16));
    parts.push('kind=' + String(entry.kind || 'unknown'));
    parts.push('weak=' + String(!!entry.isWeakDefinition));
    return parts.join(' ');
}

function formatExportsTrie(exportsTrie) {
    const entries = Array.isArray(exportsTrie.entries) ? exportsTrie.entries : [];
    const summary = [
        'dataoff=0x' + BigInt(exportsTrie.dataoff || 0).toString(16),
        'datasize=0x' + BigInt(exportsTrie.datasize || 0).toString(16),
        'linkeditBase=' + exportsTrie.linkeditBase.toString(),
        'dataAddress=' + exportsTrie.dataAddress.toString(),
        'count=' + String(entries.length),
    ].join(' ');
    return entries.length === 0
        ? summary
        : summary + '\n' + entries.map((entry) => formatExportsTrieEntry(entry)).join('\n');
}

function formatChainedFixupsSegment(segment) {
    return [
        'segment[' + String(segment.segmentIndex || 0) + ']',
        'format=' + String(segment.pointerFormatName || segment.pointerFormat || 'unknown'),
        'pageSize=0x' + BigInt(segment.pageSize || 0).toString(16),
        'segmentOffset=0x' + BigInt(segment.segmentOffset || 0).toString(16),
        'pageCount=' + String(segment.pageCount || 0),
        'fixupPages=' + String(segment.fixupPageCount || 0),
        'multiPages=' + String(segment.multiPageCount || 0),
    ].join(' ');
}

function formatChainedFixupsImport(imp) {
    const name = imp.name === null || imp.name === undefined
        ? '<symbols:' + ('0x' + BigInt(imp.nameOffset || 0).toString(16)) + '>'
        : String(imp.name);
    const addend = imp.addend === null || imp.addend === undefined ? '' : ' addend=' + imp.addend.toString();
    return [
        'import[' + String(imp.index || 0) + ']',
        name,
        'ordinal=' + String(imp.libOrdinal || 0),
        'weak=' + String(!!imp.weakImport),
    ].join(' ') + addend;
}

function formatChainedFixups(chainedFixups) {
    const segments = Array.isArray(chainedFixups.segments) ? chainedFixups.segments : [];
    const imports = Array.isArray(chainedFixups.imports) ? chainedFixups.imports : [];
    const lines = [[
        'dataoff=0x' + BigInt(chainedFixups.dataoff || 0).toString(16),
        'datasize=0x' + BigInt(chainedFixups.datasize || 0).toString(16),
        'linkeditBase=' + chainedFixups.linkeditBase.toString(),
        'dataAddress=' + chainedFixups.dataAddress.toString(),
        'version=' + String(chainedFixups.fixupsVersion || 0),
        'starts=0x' + BigInt(chainedFixups.startsOffset || 0).toString(16),
        'imports=0x' + BigInt(chainedFixups.importsOffset || 0).toString(16),
        'symbols=0x' + BigInt(chainedFixups.symbolsOffset || 0).toString(16),
        'importsFormat=' + String(chainedFixups.importsFormatName || chainedFixups.importsFormat || 'unknown'),
        'symbolsFormat=' + String(chainedFixups.symbolsFormatName || chainedFixups.symbolsFormat || 'unknown'),
        'segmentCount=' + String(segments.length),
        'importCount=' + String(imports.length),
    ].join(' ')];
    for (const segment of segments) {
        lines.push(formatChainedFixupsSegment(segment));
    }
    for (const imp of imports) {
        lines.push(formatChainedFixupsImport(imp));
    }
    return lines.join('\n');
}

function formatSourceVersion(sourceVersion) {
    return 'version=' + String(sourceVersion.version || '');
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

function formatSwiftProtocol(protocolInfo) {
    const base = protocolInfo.sourceAddress.toString() + ' ' + protocolInfo.moduleName + '!' + protocolInfo.name + ' [' + String(protocolInfo.sourceKind || 'symbol') + ']';
    return protocolInfo.sourceDemangledName === null || protocolInfo.sourceDemangledName === undefined
        ? base
        : base + ' <= ' + protocolInfo.sourceDemangledName;
}

function formatSwiftConformance(conformance) {
    const base = conformance.sourceAddress.toString() + ' ' + conformance.moduleName + '!' + conformance.typeName + ' : ' + conformance.protocolName + ' [' + String(conformance.sourceKind || 'symbol') + ']';
    return conformance.sourceDemangledName === null || conformance.sourceDemangledName === undefined
        ? base
        : base + ' <= ' + conformance.sourceDemangledName;
}

function formatSwiftVtableEntry(entry) {
    const base = entry.address.toString() + ' ' + entry.moduleName + '!' + entry.typeName + '.' + entry.memberName + ' [' + String(entry.sourceKind || 'member') + ']';
    return entry.demangledName === null || entry.demangledName === undefined
        ? base
        : base + ' <= ' + entry.demangledName;
}

function formatSwiftWitnessTable(entry) {
    const base = entry.address.toString() + ' ' + entry.moduleName + '!' + entry.typeName + ' : ' + entry.protocolName + ' [' + String(entry.sourceKind || 'protocol-witness-table') + ']';
    return entry.demangledName === null || entry.demangledName === undefined
        ? base
        : base + ' <= ' + entry.demangledName;
}

function formatSwiftTypeLayout(layout) {
    return layout.moduleName + '!' + layout.name
        + ' metadata=' + String(layout.metadataCount || 0)
        + ' accessor=' + String(layout.metadataAccessorCount || 0)
        + ' descriptor=' + String(layout.nominalDescriptorCount || 0)
        + ' cache=' + String(layout.metadataCacheCount || 0)
        + ' associated=' + String(layout.associatedTypeDescriptorCount || 0)
        + ' vtable=' + String(layout.vtableCount || 0)
        + ' witness=' + String(layout.witnessTableCount || 0);
}

function formatObjcMethod(method) {
    const prefix = method.isClassMethod ? '+' : '-';
    const details = [];
    if (method.signature && method.signature.length !== 0) {
        details.push('sig=' + method.signature);
    }
    details.push('args=' + String(method.explicitArgumentCount || 0));
    if (method.returnsVoid) {
        details.push('returns=void');
    } else if (method.returnsBlock) {
        details.push('returns=block');
    } else if (method.returnsObject) {
        details.push('returns=object');
    }
    if (method.typeEncoding.length !== 0) {
        details.push('types=' + method.typeEncoding);
    }
    return method.imp.toString() + ' ' + prefix + '[' + method.className + ' ' + method.selector + ']' + (details.length === 0 ? '' : ' ' + details.join(' '));
}

function formatObjcMethodInfo(method) {
    const prefix = method.isClassMethod ? '+' : '-';
    const details = ['method=' + method.methodPointer];
    if (method.signature && method.signature.length !== 0) {
        details.push('sig=' + method.signature);
    }
    details.push('args=' + String(method.explicitArgumentCount || 0));
    if (method.returnsVoid) {
        details.push('returns=void');
    } else if (method.returnsBlock) {
        details.push('returns=block');
    } else if (method.returnsObject) {
        details.push('returns=object');
    }
    if (method.typeEncoding.length !== 0) {
        details.push('types=' + method.typeEncoding);
    }
    if (method.imagePath !== null && method.imagePath !== undefined) {
        details.push('image=' + method.imagePath);
    }
    return method.imp.toString() + ' ' + prefix + '[' + method.className + ' ' + method.selector + ']' + ' ' + details.join(' ');
}

function formatObjcProtocolMethod(method) {
    const prefix = method.isInstanceMethod ? '-' : '+';
    const details = [method.isRequired ? 'required' : 'optional'];
    if (method.signature && method.signature.length !== 0) {
        details.push('sig=' + method.signature);
    }
    details.push('args=' + String(method.explicitArgumentCount || 0));
    if (method.returnsVoid) {
        details.push('returns=void');
    } else if (method.returnsBlock) {
        details.push('returns=block');
    } else if (method.returnsObject) {
        details.push('returns=object');
    }
    if (method.typeEncoding.length !== 0) {
        details.push('types=' + method.typeEncoding);
    }
    return prefix + '[' + method.protocolName + ' ' + method.selector + '] ' + details.join(' ');
}

function formatObjcProtocolMethodInfo(method) {
    const prefix = method.isInstanceMethod ? '-' : '+';
    const details = [method.isRequired ? 'required' : 'optional'];
    if (method.signature && method.signature.length !== 0) {
        details.push('sig=' + method.signature);
    }
    details.push('args=' + String(method.explicitArgumentCount || 0));
    if (method.returnsVoid) {
        details.push('returns=void');
    } else if (method.returnsBlock) {
        details.push('returns=block');
    } else if (method.returnsObject) {
        details.push('returns=object');
    }
    if (method.typeEncoding.length !== 0) {
        details.push('types=' + method.typeEncoding);
    }
    if (method.imagePath !== null && method.imagePath !== undefined) {
        details.push('image=' + method.imagePath);
    }
    return prefix + '[' + method.protocolName + ' ' + method.selector + '] ' + details.join(' ');
}

function formatObjcClassInfo(info) {
    const details = [
        info.classPointer,
        info.isMetaClass ? 'meta' : 'class',
        info.className,
        'size=' + String(info.instanceSize || 0),
        'protocols=' + String(info.protocolCount || 0),
        'instanceProperties=' + String(info.instancePropertyCount || 0),
        'classProperties=' + String(info.classPropertyCount || 0),
        'ivars=' + String(info.ivarCount || 0),
        'instanceMethods=' + String(info.instanceMethodCount || 0),
        'classMethods=' + String(info.classMethodCount || 0),
    ];
    if (info.superclassName !== null && info.superclassName !== undefined) {
        details.push('super=' + info.superclassName);
    }
    if (info.imagePath !== null && info.imagePath !== undefined) {
        details.push('image=' + info.imagePath);
    }
    return details.join(' ');
}

function formatObjcProtocolInfo(info) {
    const details = [
        info.protocolPointer,
        'protocol',
        info.protocolName,
        'adopted=' + String(info.adoptedProtocolCount || 0),
        'totalMethods=' + String(info.totalMethodCount || 0),
        'requiredInstance=' + String(info.requiredInstanceMethodCount || 0),
        'requiredClass=' + String(info.requiredClassMethodCount || 0),
        'optionalInstance=' + String(info.optionalInstanceMethodCount || 0),
        'optionalClass=' + String(info.optionalClassMethodCount || 0),
        'properties=' + String(info.propertyCount || 0),
    ];
    if (info.imagePath !== null && info.imagePath !== undefined) {
        details.push('image=' + info.imagePath);
    }
    return details.join(' ');
}

const OBJC_TYPE_QUALIFIER_NAMES = {
    r: 'const',
    n: 'in',
    N: 'inout',
    o: 'out',
    O: 'bycopy',
    R: 'byref',
    V: 'oneway',
};

const OBJC_SIMPLE_TYPE_NAMES = {
    c: 'char',
    i: 'int',
    s: 'short',
    l: 'long',
    q: 'long long',
    C: 'unsigned char',
    I: 'unsigned int',
    S: 'unsigned short',
    L: 'unsigned long',
    Q: 'unsigned long long',
    f: 'float',
    d: 'double',
    D: 'long double',
    B: 'bool',
    v: 'void',
    '*': 'char *',
    '#': 'Class',
    ':': 'SEL',
    '?': 'unknown',
};

function isObjcTypeQualifier(ch) {
    return Object.prototype.hasOwnProperty.call(OBJC_TYPE_QUALIFIER_NAMES, ch);
}

function findMatchingDelimiter(raw, start, openChar, closeChar) {
    let depth = 0;
    for (let i = start; i < raw.length; i++) {
        const ch = raw[i];
        if (ch === openChar) {
            depth += 1;
        } else if (ch === closeChar) {
            depth -= 1;
            if (depth === 0) {
                return i;
            }
        }
    }
    return raw.length - 1;
}

function parseObjcObjectTypeInner(inner) {
    const protocols = [];
    let objectClassName = inner;
    const firstProtocol = inner.indexOf('<');
    if (firstProtocol !== -1) {
        objectClassName = inner.slice(0, firstProtocol);
        const matches = inner.match(/<[^>]+>/g) || [];
        for (const match of matches) {
            const protocolName = match.slice(1, -1).trim();
            if (protocolName.length !== 0) {
                protocols.push(protocolName);
            }
        }
    }

    const className = objectClassName.trim();
    const displayName = protocols.length === 0
        ? (className.length === 0 ? 'id' : className + ' *')
        : (className.length === 0 ? 'id<' + protocols.join(', ') + '>' : className + '<' + protocols.join(', ') + '> *');
    return {
        displayName,
        objectClassName: className.length === 0 ? null : className,
        objectProtocols: protocols,
    };
}

function consumeObjcTypeEncoding(raw, start) {
    raw = String(raw || '');
    let index = start;
    const qualifiers = [];
    while (index < raw.length && isObjcTypeQualifier(raw[index])) {
        qualifiers.push(raw[index]);
        index += 1;
    }

    if (index >= raw.length) {
        return null;
    }

    const ch = raw[index];
    let kind = 'unknown';
    let displayName = 'unknown';
    let objectClassName = null;
    let objectProtocols = [];
    let isObject = false;
    let isBlock = false;
    let pointee = null;
    let arrayCount = null;
    let memberName = null;

    if (ch === '@') {
        isObject = true;
        kind = 'object';
        index += 1;
        if (index < raw.length && raw[index] === '?') {
            kind = 'block';
            isBlock = true;
            displayName = 'block';
            index += 1;
        } else if (index < raw.length && raw[index] === '"') {
            const endQuote = raw.indexOf('"', index + 1);
            const quoteEnd = endQuote === -1 ? raw.length - 1 : endQuote;
            const inner = raw.slice(index + 1, quoteEnd);
            const parsedObject = parseObjcObjectTypeInner(inner);
            displayName = parsedObject.displayName;
            objectClassName = parsedObject.objectClassName;
            objectProtocols = parsedObject.objectProtocols;
            index = quoteEnd + 1;
        } else {
            displayName = 'id';
        }
    } else if (ch === '^') {
        kind = 'pointer';
        const pointeeInfo = consumeObjcTypeEncoding(raw, index + 1);
        if (pointeeInfo === null) {
            displayName = 'void *';
            index += 1;
        } else {
            pointee = pointeeInfo.info;
            displayName = pointee.displayName + ' *';
            index = pointeeInfo.nextIndex;
        }
    } else if (ch === '[') {
        kind = 'array';
        index += 1;
        const countStart = index;
        while (index < raw.length && /[0-9]/.test(raw[index])) {
            index += 1;
        }
        arrayCount = index > countStart ? Number(raw.slice(countStart, index)) : null;
        const elementInfo = consumeObjcTypeEncoding(raw, index);
        if (elementInfo === null) {
            displayName = 'array';
        } else {
            pointee = elementInfo.info;
            displayName = pointee.displayName + '[' + String(arrayCount === null ? '' : arrayCount) + ']';
            index = elementInfo.nextIndex;
        }
        if (index < raw.length && raw[index] === ']') {
            index += 1;
        }
    } else if (ch === '{') {
        kind = 'struct';
        const end = findMatchingDelimiter(raw, index, '{', '}');
        const body = raw.slice(index + 1, end);
        const separator = body.indexOf('=');
        memberName = (separator === -1 ? body : body.slice(0, separator)).trim() || '?';
        displayName = 'struct ' + memberName;
        index = end + 1;
    } else if (ch === '(') {
        kind = 'union';
        const end = findMatchingDelimiter(raw, index, '(', ')');
        const body = raw.slice(index + 1, end);
        const separator = body.indexOf('=');
        memberName = (separator === -1 ? body : body.slice(0, separator)).trim() || '?';
        displayName = 'union ' + memberName;
        index = end + 1;
    } else if (ch === 'b') {
        kind = 'bitfield';
        index += 1;
        const digitsStart = index;
        while (index < raw.length && /[0-9]/.test(raw[index])) {
            index += 1;
        }
        const bits = raw.slice(digitsStart, index) || '?';
        displayName = 'bitfield(' + bits + ')';
    } else {
        kind = ch;
        displayName = OBJC_SIMPLE_TYPE_NAMES[ch] || ('unknown(' + ch + ')');
        index += 1;
    }

    const qualifierNames = qualifiers.map((qualifier) => OBJC_TYPE_QUALIFIER_NAMES[qualifier]).filter(Boolean);
    const qualifierPrefix = qualifierNames.length === 0 ? '' : qualifierNames.join(' ') + ' ';
    return {
        nextIndex: index,
        info: {
            raw: raw.slice(start, index),
            qualifiers,
            qualifierNames,
            kind,
            displayName: qualifierPrefix + displayName,
            isObject,
            isBlock,
            objectClassName,
            objectProtocols,
            pointee,
            arrayCount,
            memberName,
        },
    };
}

function parseObjcTypeEncodingInfo(typeEncoding) {
    const raw = String(typeEncoding || '');
    const parsed = consumeObjcTypeEncoding(raw, 0);
    if (parsed === null) {
        return {
            raw,
            qualifiers: [],
            qualifierNames: [],
            kind: 'unknown',
            displayName: raw.length === 0 ? '' : raw,
            isObject: false,
            isBlock: false,
            objectClassName: null,
            objectProtocols: [],
            pointee: null,
            arrayCount: null,
            memberName: null,
        };
    }
    const info = parsed.info;
    if (parsed.nextIndex !== raw.length) {
        info.trailingEncoding = raw.slice(parsed.nextIndex);
    }
    return info;
}

function parseObjcPropertyTypeEncoding(typeEncoding) {
    const info = parseObjcTypeEncodingInfo(typeEncoding);
    return {
        typeEncoding: String(typeEncoding || ''),
        typeName: info.displayName,
        typeInfo: info,
        isObject: info.isObject,
        isBlock: info.isBlock,
        objectClassName: info.objectClassName,
        objectProtocols: info.objectProtocols,
    };
}

function skipObjcMethodOffsetDigits(raw, start) {
    let index = start;
    while (index < raw.length && /[0-9]/.test(raw[index])) {
        index += 1;
    }
    return index;
}

function parseObjcMethodTypeEncoding(typeEncoding) {
    const raw = String(typeEncoding || '');
    const result = {
        raw,
        returnTypeEncoding: '',
        returnTypeName: '',
        returnTypeInfo: null,
        frameSize: null,
        argumentCount: 0,
        explicitArgumentCount: 0,
        argumentTypeEncodings: [],
        argumentTypeNames: [],
        argumentTypeInfos: [],
        hiddenArgumentTypeNames: [],
        signature: '',
    };

    if (raw.length === 0) {
        return result;
    }

    const returnType = consumeObjcTypeEncoding(raw, 0);
    if (returnType === null) {
        return result;
    }

    result.returnTypeEncoding = returnType.info.raw;
    result.returnTypeName = returnType.info.displayName;
    result.returnTypeInfo = returnType.info;

    let index = skipObjcMethodOffsetDigits(raw, returnType.nextIndex);
    if (index > returnType.nextIndex) {
        result.frameSize = Number(raw.slice(returnType.nextIndex, index));
    }

    while (index < raw.length) {
        const argumentType = consumeObjcTypeEncoding(raw, index);
        if (argumentType === null || argumentType.nextIndex <= index) {
            break;
        }
        result.argumentTypeEncodings.push(argumentType.info.raw);
        result.argumentTypeNames.push(argumentType.info.displayName);
        result.argumentTypeInfos.push(argumentType.info);
        index = skipObjcMethodOffsetDigits(raw, argumentType.nextIndex);
    }

    result.argumentCount = result.argumentTypeNames.length;
    result.explicitArgumentCount = Math.max(result.argumentCount - 2, 0);
    result.hiddenArgumentTypeNames = result.argumentTypeNames.slice(0, 2);
    const explicitArguments = result.argumentTypeNames.slice(2);
    result.signature = result.returnTypeName.length === 0
        ? ''
        : result.returnTypeName + ' (' + explicitArguments.join(', ') + ')';
    return result;
}

function parseObjcSelectorInfo(selector) {
    const raw = String(selector || '');
    const partCount = (raw.match(/:/g) || []).length;
    const parts = raw.length === 0
        ? []
        : raw.split(':').filter((part, index, array) => part.length !== 0 || index !== array.length - 1);
    return {
        raw,
        parts,
        partCount,
        hasArguments: partCount !== 0,
        isUnarySelector: partCount === 0,
        isKeywordSelector: partCount !== 0,
    };
}

function parseObjcPropertyAttributes(attributes) {
    const raw = String(attributes || '');
    const info = {
        raw,
        typeEncoding: '',
        typeName: '',
        typeInfo: null,
        oldStyleTypeEncoding: null,
        ownership: 'assign',
        isReadonly: false,
        isNonatomic: false,
        isDynamic: false,
        hasGetter: false,
        hasSetter: false,
        getterName: null,
        setterName: null,
        ivarName: null,
        parsedTokens: [],
        isObject: false,
        isBlock: false,
        objectClassName: null,
        objectProtocols: [],
    };

    if (raw.length === 0) {
        return info;
    }

    const tokens = raw.split(',');
    for (const token of tokens) {
        if (token.length === 0) {
            continue;
        }

        info.parsedTokens.push(token);
        if (token.startsWith('T')) {
            info.typeEncoding = token.slice(1);
            continue;
        }
        if (token === 'R') {
            info.isReadonly = true;
            continue;
        }
        if (token === 'C') {
            info.ownership = 'copy';
            continue;
        }
        if (token === '&') {
            info.ownership = 'strong';
            continue;
        }
        if (token === 'N') {
            info.isNonatomic = true;
            continue;
        }
        if (token.startsWith('G')) {
            info.hasGetter = true;
            info.getterName = token.slice(1) || null;
            continue;
        }
        if (token.startsWith('S')) {
            info.hasSetter = true;
            info.setterName = token.slice(1) || null;
            continue;
        }
        if (token === 'D') {
            info.isDynamic = true;
            continue;
        }
        if (token === 'W') {
            info.ownership = 'weak';
            continue;
        }
        if (token.startsWith('V')) {
            info.ivarName = token.slice(1) || null;
            continue;
        }
        if (token.startsWith('t')) {
            info.oldStyleTypeEncoding = token.slice(1) || null;
            continue;
        }
    }

    const parsedType = parseObjcPropertyTypeEncoding(info.typeEncoding);
    info.typeName = parsedType.typeName;
    info.typeInfo = parsedType.typeInfo;
    info.isObject = parsedType.isObject;
    info.isBlock = parsedType.isBlock;
    info.objectClassName = parsedType.objectClassName;
    info.objectProtocols = parsedType.objectProtocols;
    return info;
}

function formatObjcProtocolProperty(property) {
    const details = [];
    if (property.typeName && property.typeName.length !== 0) {
        details.push('type=' + property.typeName);
    }
    if (property.ownership !== 'assign') {
        details.push('ownership=' + property.ownership);
    }
    if (property.isReadonly) {
        details.push('readonly');
    }
    if (property.isNonatomic) {
        details.push('nonatomic');
    }
    if (property.isDynamic) {
        details.push('dynamic');
    }
    if (property.hasCustomGetter && property.getterName) {
        details.push('getter=' + property.getterName);
    }
    if (property.hasCustomSetter && property.setterName) {
        details.push('setter=' + property.setterName);
    }
    if (property.hasBackingIvar && property.ivarName) {
        details.push('ivar=' + property.ivarName);
    }
    if (property.attributes.length !== 0) {
        details.push('attrs=' + property.attributes);
    }
    return '@protocol(' + property.protocolName + ') ' + property.name + (details.length === 0 ? '' : ' ' + details.join(' '));
}

function formatObjcProperty(property) {
    const prefix = property.isClassProperty ? '+' : '-';
    const details = [];
    if (property.typeName && property.typeName.length !== 0) {
        details.push('type=' + property.typeName);
    }
    if (property.ownership !== 'assign') {
        details.push('ownership=' + property.ownership);
    }
    if (property.isReadonly) {
        details.push('readonly');
    }
    if (property.isNonatomic) {
        details.push('nonatomic');
    }
    if (property.isDynamic) {
        details.push('dynamic');
    }
    if (property.hasCustomGetter && property.getterName) {
        details.push('getter=' + property.getterName);
    }
    if (property.hasCustomSetter && property.setterName) {
        details.push('setter=' + property.setterName);
    }
    if (property.hasBackingIvar && property.ivarName) {
        details.push('ivar=' + property.ivarName);
    }
    if (property.attributes.length !== 0) {
        details.push('attrs=' + property.attributes);
    }
    return prefix + '[' + property.className + ' ' + property.name + ']' + (details.length === 0 ? '' : ' ' + details.join(' '));
}

function formatObjcPropertyInfo(property) {
    const prefix = property.isClassProperty ? '+' : '-';
    const details = ['property=' + property.propertyPointer];
    if (property.typeName && property.typeName.length !== 0) {
        details.push('type=' + property.typeName);
    }
    if (property.ownership !== 'assign') {
        details.push('ownership=' + property.ownership);
    }
    if (property.isReadonly) {
        details.push('readonly');
    }
    if (property.isNonatomic) {
        details.push('nonatomic');
    }
    if (property.isDynamic) {
        details.push('dynamic');
    }
    if (property.hasCustomGetter && property.getterName) {
        details.push('getter=' + property.getterName);
    }
    if (property.hasCustomSetter && property.setterName) {
        details.push('setter=' + property.setterName);
    }
    if (property.hasBackingIvar && property.ivarName) {
        details.push('ivar=' + property.ivarName);
    }
    if (property.attributes.length !== 0) {
        details.push('attrs=' + property.attributes);
    }
    if (property.imagePath !== null && property.imagePath !== undefined) {
        details.push('image=' + property.imagePath);
    }
    return prefix + '[' + property.className + ' ' + property.name + ']' + ' ' + details.join(' ');
}

function formatObjcProtocolPropertyInfo(property) {
    const details = ['property=' + property.propertyPointer];
    if (property.typeName && property.typeName.length !== 0) {
        details.push('type=' + property.typeName);
    }
    if (property.ownership !== 'assign') {
        details.push('ownership=' + property.ownership);
    }
    if (property.isReadonly) {
        details.push('readonly');
    }
    if (property.isNonatomic) {
        details.push('nonatomic');
    }
    if (property.isDynamic) {
        details.push('dynamic');
    }
    if (property.hasCustomGetter && property.getterName) {
        details.push('getter=' + property.getterName);
    }
    if (property.hasCustomSetter && property.setterName) {
        details.push('setter=' + property.setterName);
    }
    if (property.hasBackingIvar && property.ivarName) {
        details.push('ivar=' + property.ivarName);
    }
    if (property.attributes.length !== 0) {
        details.push('attrs=' + property.attributes);
    }
    if (property.imagePath !== null && property.imagePath !== undefined) {
        details.push('image=' + property.imagePath);
    }
    return '@protocol(' + property.protocolName + ') ' + property.name + ' ' + details.join(' ');
}

function formatObjcIvar(ivar) {
    const details = ['offset=' + '0x' + BigInt(ivar.offset || 0).toString(16)];
    const typeName = ivar.typeName || ivar.typeEncoding;
    if (typeName.length !== 0) {
        details.push('type=' + typeName);
    }
    if (ivar.hasQualifiers) {
        details.push('quals=' + String(ivar.qualifierCount || 0));
    }
    if (ivar.hasPointeeType && ivar.pointeeTypeName !== null) {
        details.push('ptr=' + ivar.pointeeTypeName);
    }
    if (ivar.isArray) {
        details.push('array=' + String(ivar.arrayCount === null ? '?' : ivar.arrayCount));
    }
    if (ivar.hasMemberName && ivar.memberName !== null) {
        details.push('member=' + ivar.memberName);
    }
    if (ivar.hasObjectClassName && ivar.objectClassName !== null) {
        details.push('class=' + ivar.objectClassName);
    }
    if ((ivar.objectProtocolCount || 0) !== 0) {
        details.push('protocols=' + String(ivar.objectProtocolCount || 0));
    }
    return ivar.className + ' ' + ivar.name + ' ' + details.join(' ');
}

function formatObjcIvarInfo(ivar) {
    const details = ['ivar=' + ivar.ivarPointer, 'offset=' + ivar.offsetHex];
    if (ivar.typeName && ivar.typeName.length !== 0) {
        details.push('type=' + ivar.typeName);
    }
    if (ivar.typeEncoding.length !== 0) {
        details.push('types=' + ivar.typeEncoding);
    }
    if (ivar.hasQualifiers) {
        details.push('quals=' + String(ivar.qualifierCount || 0));
    }
    if (ivar.hasPointeeType && ivar.pointeeTypeName !== null) {
        details.push('ptr=' + ivar.pointeeTypeName);
    }
    if (ivar.isArray) {
        details.push('array=' + String(ivar.arrayCount === null ? '?' : ivar.arrayCount));
    }
    if (ivar.hasMemberName && ivar.memberName !== null) {
        details.push('member=' + ivar.memberName);
    }
    if (ivar.hasObjectClassName && ivar.objectClassName !== null) {
        details.push('class=' + ivar.objectClassName);
    }
    if ((ivar.objectProtocolCount || 0) !== 0) {
        details.push('protocols=' + String(ivar.objectProtocolCount || 0));
    }
    if (ivar.imagePath !== null && ivar.imagePath !== undefined) {
        details.push('image=' + ivar.imagePath);
    }
    return ivar.className + ' ' + ivar.name + ' ' + details.join(' ');
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
    lines.push('conflict_state=' + String(report.conflictState));
    lines.push('risk_level=' + String(report.riskLevel));
    lines.push('policy=' + String(report.policy));
    lines.push('strategy=' + String(report.strategy));
    lines.push('allowed=' + String(!!report.allowed));
    lines.push('inline_hooks_allowed=' + String(!!report.inlineHooksAllowed));
    lines.push('bootstrap_injection_allowed=' + String(!!report.bootstrapInjectionAllowed));
    lines.push('query_commands_allowed=' + String(!!report.queryCommandsAllowed));
    lines.push('hook_install_commands_allowed=' + String(!!report.hookInstallCommandsAllowed));
    lines.push('hook_status_commands_allowed=' + String(!!report.hookStatusCommandsAllowed));
    lines.push('hook_stop_commands_allowed=' + String(!!report.hookStopCommandsAllowed));
    lines.push('coexistence_layer_available=' + String(!!report.coexistenceLayerAvailable));
    lines.push('loaded_backend_count=' + String(Number(report.loadedBackendCount || 0)));
    lines.push('filesystem_only_backend_count=' + String(Number(report.filesystemOnlyBackendCount || 0)));
    lines.push('loaded_image_count=' + String(Number(report.loadedImageCount || 0)));
    lines.push('filesystem_path_count=' + String(Number(report.filesystemPathCount || 0)));
    if (report.reason !== null && report.reason !== undefined) {
        lines.push('reason=' + String(report.reason));
    }

    const backends = Array.isArray(report.backends) ? report.backends : [];
    for (const backend of backends) {
        lines.push('backend ' + backend.id + ' ' + backend.name);
        lines.push('  counts loaded_images=' + String(Number(backend.loadedImageCount || 0)) + ' filesystem_paths=' + String(Number(backend.filesystemPathCount || 0)));
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
    const size = Number(image.size || 0);
    return {
        path,
        name: pathParts.length === 0 ? path : pathParts[pathParts.length - 1],
        base: image.base.toString(),
        slide: formatSlide(image.slide),
        size,
        sizeHex: '0x' + BigInt(image.size || 0).toString(16),
        text: formatImage(image),
    };
}

function normalizeObjcMethod(method) {
    const methodTypeInfo = parseObjcMethodTypeEncoding(method.typeEncoding);
    const selectorInfo = parseObjcSelectorInfo(method.selector);
    const hiddenArgumentCount = Array.isArray(methodTypeInfo.hiddenArgumentTypeNames) ? methodTypeInfo.hiddenArgumentTypeNames.length : 0;
    const normalized = {
        className: String(method.className || ''),
        selector: String(method.selector || ''),
        selectorParts: selectorInfo.parts,
        selectorPartCount: selectorInfo.partCount,
        hasSelectorArguments: selectorInfo.hasArguments,
        isUnarySelector: selectorInfo.isUnarySelector,
        isKeywordSelector: selectorInfo.isKeywordSelector,
        isClassMethod: !!method.isClassMethod,
        imp: method.imp.toString(),
        typeEncoding: String(method.typeEncoding || ''),
        returnTypeEncoding: methodTypeInfo.returnTypeEncoding,
        returnTypeName: methodTypeInfo.returnTypeName,
        returnTypeInfo: methodTypeInfo.returnTypeInfo,
        frameSize: methodTypeInfo.frameSize,
        argumentCount: methodTypeInfo.argumentCount,
        explicitArgumentCount: methodTypeInfo.explicitArgumentCount,
        argumentTypeEncodings: methodTypeInfo.argumentTypeEncodings,
        argumentTypeNames: methodTypeInfo.argumentTypeNames,
        argumentTypeInfos: methodTypeInfo.argumentTypeInfos,
        hiddenArgumentTypeNames: methodTypeInfo.hiddenArgumentTypeNames,
        hiddenArgumentCount,
        signature: methodTypeInfo.signature,
        methodTypeInfo,
        hasExplicitArguments: methodTypeInfo.explicitArgumentCount !== 0,
        hasHiddenArguments: hiddenArgumentCount !== 0,
        returnsVoid: methodTypeInfo.returnTypeEncoding === 'v',
        returnsObject: !!(methodTypeInfo.returnTypeInfo && methodTypeInfo.returnTypeInfo.isObject),
        returnsBlock: !!(methodTypeInfo.returnTypeInfo && methodTypeInfo.returnTypeInfo.isBlock),
    };
    normalized.text = formatObjcMethod(normalized);
    return normalized;
}

function normalizeObjcMethodInfo(method) {
    const methodTypeInfo = parseObjcMethodTypeEncoding(method.typeEncoding);
    const selectorInfo = parseObjcSelectorInfo(method.selector);
    const hiddenArgumentCount = Array.isArray(methodTypeInfo.hiddenArgumentTypeNames) ? methodTypeInfo.hiddenArgumentTypeNames.length : 0;
    const normalized = {
        className: String(method.className || ''),
        selector: String(method.selector || ''),
        selectorParts: selectorInfo.parts,
        selectorPartCount: selectorInfo.partCount,
        hasSelectorArguments: selectorInfo.hasArguments,
        isUnarySelector: selectorInfo.isUnarySelector,
        isKeywordSelector: selectorInfo.isKeywordSelector,
        isClassMethod: !!method.isClassMethod,
        methodPointer: method.methodPointer.toString(),
        imp: method.imp.toString(),
        typeEncoding: String(method.typeEncoding || ''),
        returnTypeEncoding: methodTypeInfo.returnTypeEncoding,
        returnTypeName: methodTypeInfo.returnTypeName,
        returnTypeInfo: methodTypeInfo.returnTypeInfo,
        frameSize: methodTypeInfo.frameSize,
        argumentCount: methodTypeInfo.argumentCount,
        explicitArgumentCount: methodTypeInfo.explicitArgumentCount,
        argumentTypeEncodings: methodTypeInfo.argumentTypeEncodings,
        argumentTypeNames: methodTypeInfo.argumentTypeNames,
        argumentTypeInfos: methodTypeInfo.argumentTypeInfos,
        hiddenArgumentTypeNames: methodTypeInfo.hiddenArgumentTypeNames,
        hiddenArgumentCount,
        signature: methodTypeInfo.signature,
        methodTypeInfo,
        hasExplicitArguments: methodTypeInfo.explicitArgumentCount !== 0,
        hasHiddenArguments: hiddenArgumentCount !== 0,
        returnsVoid: methodTypeInfo.returnTypeEncoding === 'v',
        returnsObject: !!(methodTypeInfo.returnTypeInfo && methodTypeInfo.returnTypeInfo.isObject),
        returnsBlock: !!(methodTypeInfo.returnTypeInfo && methodTypeInfo.returnTypeInfo.isBlock),
        imagePath: method.imagePath === undefined || method.imagePath === null ? null : String(method.imagePath),
    };
    normalized.text = formatObjcMethodInfo(normalized);
    return normalized;
}

function normalizeObjcClassInfo(info) {
    const instanceSize = Number(info.instanceSize || 0);
    const normalized = {
        className: String(info.className || ''),
        classPointer: info.classPointer.toString(),
        isMetaClass: !!info.isMetaClass,
        superclassName: info.superclassName === undefined || info.superclassName === null ? null : String(info.superclassName),
        superclassPointer: info.superclassPointer === undefined || info.superclassPointer === null ? null : info.superclassPointer.toString(),
        instanceSize,
        protocolCount: Number(info.protocolCount || 0),
        instancePropertyCount: Number(info.instancePropertyCount || 0),
        classPropertyCount: Number(info.classPropertyCount || 0),
        ivarCount: Number(info.ivarCount || 0),
        instanceMethodCount: Number(info.instanceMethodCount || 0),
        classMethodCount: Number(info.classMethodCount || 0),
        imagePath: info.imagePath === undefined || info.imagePath === null ? null : String(info.imagePath),
    };
    normalized.hasSuperclass = normalized.superclassName !== null;
    normalized.isRootClass = !normalized.hasSuperclass;
    normalized.hasProtocols = normalized.protocolCount !== 0;
    normalized.hasInstanceProperties = normalized.instancePropertyCount !== 0;
    normalized.hasClassProperties = normalized.classPropertyCount !== 0;
    normalized.hasProperties = normalized.hasInstanceProperties || normalized.hasClassProperties;
    normalized.hasIvars = normalized.ivarCount !== 0;
    normalized.hasInstanceMethods = normalized.instanceMethodCount !== 0;
    normalized.hasClassMethods = normalized.classMethodCount !== 0;
    normalized.hasMethods = normalized.hasInstanceMethods || normalized.hasClassMethods;
    normalized.hasImagePath = normalized.imagePath !== null;
    normalized.totalPropertyCount = normalized.instancePropertyCount + normalized.classPropertyCount;
    normalized.totalMethodCount = normalized.instanceMethodCount + normalized.classMethodCount;
    normalized.text = formatObjcClassInfo(normalized);
    return normalized;
}

function normalizeObjcProtocolInfo(info) {
    const adoptedProtocols = Array.isArray(info.adoptedProtocols)
        ? info.adoptedProtocols.map((name) => String(name))
        : [];
    const normalized = {
        protocolName: String(info.protocolName || ''),
        protocolPointer: info.protocolPointer.toString(),
        adoptedProtocols,
        adoptedProtocolCount: adoptedProtocols.length,
        requiredInstanceMethodCount: Number(info.requiredInstanceMethodCount || 0),
        requiredClassMethodCount: Number(info.requiredClassMethodCount || 0),
        optionalInstanceMethodCount: Number(info.optionalInstanceMethodCount || 0),
        optionalClassMethodCount: Number(info.optionalClassMethodCount || 0),
        propertyCount: Number(info.propertyCount || 0),
        imagePath: info.imagePath === undefined || info.imagePath === null ? null : String(info.imagePath),
    };
    normalized.totalMethodCount = normalized.requiredInstanceMethodCount
        + normalized.requiredClassMethodCount
        + normalized.optionalInstanceMethodCount
        + normalized.optionalClassMethodCount;
    normalized.hasRequiredMethods = (normalized.requiredInstanceMethodCount + normalized.requiredClassMethodCount) !== 0;
    normalized.hasOptionalMethods = (normalized.optionalInstanceMethodCount + normalized.optionalClassMethodCount) !== 0;
    normalized.hasInstanceMethods = (normalized.requiredInstanceMethodCount + normalized.optionalInstanceMethodCount) !== 0;
    normalized.hasClassMethods = (normalized.requiredClassMethodCount + normalized.optionalClassMethodCount) !== 0;
    normalized.hasProperties = normalized.propertyCount !== 0;
    normalized.hasAdoptedProtocols = normalized.adoptedProtocolCount !== 0;
    normalized.hasImagePath = normalized.imagePath !== null;
    normalized.text = formatObjcProtocolInfo(normalized);
    return normalized;
}

function normalizeObjcProtocolMethod(method) {
    const methodTypeInfo = parseObjcMethodTypeEncoding(method.typeEncoding);
    const selectorInfo = parseObjcSelectorInfo(method.selector);
    const hiddenArgumentCount = Array.isArray(methodTypeInfo.hiddenArgumentTypeNames) ? methodTypeInfo.hiddenArgumentTypeNames.length : 0;
    const normalized = {
        protocolName: String(method.protocolName || ''),
        selector: String(method.selector || ''),
        selectorParts: selectorInfo.parts,
        selectorPartCount: selectorInfo.partCount,
        hasSelectorArguments: selectorInfo.hasArguments,
        isUnarySelector: selectorInfo.isUnarySelector,
        isKeywordSelector: selectorInfo.isKeywordSelector,
        typeEncoding: String(method.typeEncoding || ''),
        returnTypeEncoding: methodTypeInfo.returnTypeEncoding,
        returnTypeName: methodTypeInfo.returnTypeName,
        returnTypeInfo: methodTypeInfo.returnTypeInfo,
        frameSize: methodTypeInfo.frameSize,
        argumentCount: methodTypeInfo.argumentCount,
        explicitArgumentCount: methodTypeInfo.explicitArgumentCount,
        argumentTypeEncodings: methodTypeInfo.argumentTypeEncodings,
        argumentTypeNames: methodTypeInfo.argumentTypeNames,
        argumentTypeInfos: methodTypeInfo.argumentTypeInfos,
        hiddenArgumentTypeNames: methodTypeInfo.hiddenArgumentTypeNames,
        hiddenArgumentCount,
        signature: methodTypeInfo.signature,
        methodTypeInfo,
        hasExplicitArguments: methodTypeInfo.explicitArgumentCount !== 0,
        hasHiddenArguments: hiddenArgumentCount !== 0,
        returnsVoid: methodTypeInfo.returnTypeEncoding === 'v',
        returnsObject: !!(methodTypeInfo.returnTypeInfo && methodTypeInfo.returnTypeInfo.isObject),
        returnsBlock: !!(methodTypeInfo.returnTypeInfo && methodTypeInfo.returnTypeInfo.isBlock),
        isRequired: !!method.isRequired,
        isInstanceMethod: !!method.isInstanceMethod,
    };
    normalized.text = formatObjcProtocolMethod(normalized);
    return normalized;
}

function normalizeObjcProtocolMethodInfo(method) {
    const methodTypeInfo = parseObjcMethodTypeEncoding(method.typeEncoding);
    const selectorInfo = parseObjcSelectorInfo(method.selector);
    const hiddenArgumentCount = Array.isArray(methodTypeInfo.hiddenArgumentTypeNames) ? methodTypeInfo.hiddenArgumentTypeNames.length : 0;
    const normalized = {
        protocolName: String(method.protocolName || ''),
        selector: String(method.selector || ''),
        selectorParts: selectorInfo.parts,
        selectorPartCount: selectorInfo.partCount,
        hasSelectorArguments: selectorInfo.hasArguments,
        isUnarySelector: selectorInfo.isUnarySelector,
        isKeywordSelector: selectorInfo.isKeywordSelector,
        typeEncoding: String(method.typeEncoding || ''),
        returnTypeEncoding: methodTypeInfo.returnTypeEncoding,
        returnTypeName: methodTypeInfo.returnTypeName,
        returnTypeInfo: methodTypeInfo.returnTypeInfo,
        frameSize: methodTypeInfo.frameSize,
        argumentCount: methodTypeInfo.argumentCount,
        explicitArgumentCount: methodTypeInfo.explicitArgumentCount,
        argumentTypeEncodings: methodTypeInfo.argumentTypeEncodings,
        argumentTypeNames: methodTypeInfo.argumentTypeNames,
        argumentTypeInfos: methodTypeInfo.argumentTypeInfos,
        hiddenArgumentTypeNames: methodTypeInfo.hiddenArgumentTypeNames,
        hiddenArgumentCount,
        signature: methodTypeInfo.signature,
        methodTypeInfo,
        hasExplicitArguments: methodTypeInfo.explicitArgumentCount !== 0,
        hasHiddenArguments: hiddenArgumentCount !== 0,
        returnsVoid: methodTypeInfo.returnTypeEncoding === 'v',
        returnsObject: !!(methodTypeInfo.returnTypeInfo && methodTypeInfo.returnTypeInfo.isObject),
        returnsBlock: !!(methodTypeInfo.returnTypeInfo && methodTypeInfo.returnTypeInfo.isBlock),
        isRequired: !!method.isRequired,
        isInstanceMethod: !!method.isInstanceMethod,
        imagePath: method.imagePath === undefined || method.imagePath === null ? null : String(method.imagePath),
    };
    normalized.text = formatObjcProtocolMethodInfo(normalized);
    return normalized;
}

function normalizeObjcProtocolProperty(property) {
    const attributeInfo = parseObjcPropertyAttributes(property.attributes);
    const objectProtocolCount = Array.isArray(attributeInfo.objectProtocols) ? attributeInfo.objectProtocols.length : 0;
    const parsedTokenCount = Array.isArray(attributeInfo.parsedTokens) ? attributeInfo.parsedTokens.length : 0;
    const normalized = {
        protocolName: String(property.protocolName || ''),
        name: String(property.name || ''),
        attributes: String(property.attributes || ''),
        typeEncoding: attributeInfo.typeEncoding,
        typeName: attributeInfo.typeName,
        typeInfo: attributeInfo.typeInfo,
        oldStyleTypeEncoding: attributeInfo.oldStyleTypeEncoding,
        ownership: attributeInfo.ownership,
        isReadonly: attributeInfo.isReadonly,
        isNonatomic: attributeInfo.isNonatomic,
        isDynamic: attributeInfo.isDynamic,
        isReadwrite: !attributeInfo.isReadonly,
        isAtomic: !attributeInfo.isNonatomic,
        isStrong: attributeInfo.ownership === 'strong',
        isCopy: attributeInfo.ownership === 'copy',
        isWeak: attributeInfo.ownership === 'weak',
        isAssign: attributeInfo.ownership === 'assign',
        getterName: attributeInfo.getterName,
        setterName: attributeInfo.setterName,
        ivarName: attributeInfo.ivarName,
        hasCustomGetter: attributeInfo.hasGetter,
        hasCustomSetter: attributeInfo.hasSetter,
        hasAccessorCustomization: attributeInfo.hasGetter || attributeInfo.hasSetter,
        hasAccessorNames: attributeInfo.getterName !== null || attributeInfo.setterName !== null,
        hasGetterName: attributeInfo.getterName !== null,
        hasSetterName: attributeInfo.setterName !== null,
        hasBackingIvar: attributeInfo.ivarName !== null,
        hasOldStyleTypeEncoding: attributeInfo.oldStyleTypeEncoding !== null,
        hasOwnershipModifier: attributeInfo.ownership !== 'assign',
        hasTypeEncoding: attributeInfo.typeEncoding.length !== 0,
        hasTypeName: attributeInfo.typeName.length !== 0,
        hasTypeInfo: attributeInfo.typeInfo !== null,
        isObject: attributeInfo.isObject,
        isBlock: attributeInfo.isBlock,
        objectClassName: attributeInfo.objectClassName,
        objectProtocols: attributeInfo.objectProtocols,
        objectProtocolCount,
        hasObjectClassName: attributeInfo.objectClassName !== null,
        hasObjectProtocols: objectProtocolCount !== 0,
        parsedTokenCount,
        hasParsedTokens: parsedTokenCount !== 0,
        attributeInfo,
    };
    normalized.text = formatObjcProtocolProperty(normalized);
    return normalized;
}

function normalizeObjcProperty(property) {
    const attributeInfo = parseObjcPropertyAttributes(property.attributes);
    const objectProtocolCount = Array.isArray(attributeInfo.objectProtocols) ? attributeInfo.objectProtocols.length : 0;
    const parsedTokenCount = Array.isArray(attributeInfo.parsedTokens) ? attributeInfo.parsedTokens.length : 0;
    const normalized = {
        className: String(property.className || ''),
        name: String(property.name || ''),
        attributes: String(property.attributes || ''),
        typeEncoding: attributeInfo.typeEncoding,
        typeName: attributeInfo.typeName,
        typeInfo: attributeInfo.typeInfo,
        oldStyleTypeEncoding: attributeInfo.oldStyleTypeEncoding,
        ownership: attributeInfo.ownership,
        isReadonly: attributeInfo.isReadonly,
        isNonatomic: attributeInfo.isNonatomic,
        isDynamic: attributeInfo.isDynamic,
        isReadwrite: !attributeInfo.isReadonly,
        isAtomic: !attributeInfo.isNonatomic,
        isStrong: attributeInfo.ownership === 'strong',
        isCopy: attributeInfo.ownership === 'copy',
        isWeak: attributeInfo.ownership === 'weak',
        isAssign: attributeInfo.ownership === 'assign',
        getterName: attributeInfo.getterName,
        setterName: attributeInfo.setterName,
        ivarName: attributeInfo.ivarName,
        hasCustomGetter: attributeInfo.hasGetter,
        hasCustomSetter: attributeInfo.hasSetter,
        hasAccessorCustomization: attributeInfo.hasGetter || attributeInfo.hasSetter,
        hasAccessorNames: attributeInfo.getterName !== null || attributeInfo.setterName !== null,
        hasGetterName: attributeInfo.getterName !== null,
        hasSetterName: attributeInfo.setterName !== null,
        hasBackingIvar: attributeInfo.ivarName !== null,
        hasOldStyleTypeEncoding: attributeInfo.oldStyleTypeEncoding !== null,
        hasOwnershipModifier: attributeInfo.ownership !== 'assign',
        hasTypeEncoding: attributeInfo.typeEncoding.length !== 0,
        hasTypeName: attributeInfo.typeName.length !== 0,
        hasTypeInfo: attributeInfo.typeInfo !== null,
        isObject: attributeInfo.isObject,
        isBlock: attributeInfo.isBlock,
        objectClassName: attributeInfo.objectClassName,
        objectProtocols: attributeInfo.objectProtocols,
        objectProtocolCount,
        hasObjectClassName: attributeInfo.objectClassName !== null,
        hasObjectProtocols: objectProtocolCount !== 0,
        parsedTokenCount,
        hasParsedTokens: parsedTokenCount !== 0,
        attributeInfo,
        isClassProperty: !!property.isClassProperty,
    };
    normalized.text = formatObjcProperty(normalized);
    return normalized;
}

function normalizeObjcPropertyInfo(property) {
    const attributeInfo = parseObjcPropertyAttributes(property.attributes);
    const objectProtocolCount = Array.isArray(attributeInfo.objectProtocols) ? attributeInfo.objectProtocols.length : 0;
    const parsedTokenCount = Array.isArray(attributeInfo.parsedTokens) ? attributeInfo.parsedTokens.length : 0;
    const normalized = {
        className: String(property.className || ''),
        name: String(property.name || ''),
        attributes: String(property.attributes || ''),
        typeEncoding: attributeInfo.typeEncoding,
        typeName: attributeInfo.typeName,
        typeInfo: attributeInfo.typeInfo,
        oldStyleTypeEncoding: attributeInfo.oldStyleTypeEncoding,
        ownership: attributeInfo.ownership,
        isReadonly: attributeInfo.isReadonly,
        isNonatomic: attributeInfo.isNonatomic,
        isDynamic: attributeInfo.isDynamic,
        isReadwrite: !attributeInfo.isReadonly,
        isAtomic: !attributeInfo.isNonatomic,
        isStrong: attributeInfo.ownership === 'strong',
        isCopy: attributeInfo.ownership === 'copy',
        isWeak: attributeInfo.ownership === 'weak',
        isAssign: attributeInfo.ownership === 'assign',
        getterName: attributeInfo.getterName,
        setterName: attributeInfo.setterName,
        ivarName: attributeInfo.ivarName,
        hasCustomGetter: attributeInfo.hasGetter,
        hasCustomSetter: attributeInfo.hasSetter,
        hasAccessorCustomization: attributeInfo.hasGetter || attributeInfo.hasSetter,
        hasAccessorNames: attributeInfo.getterName !== null || attributeInfo.setterName !== null,
        hasGetterName: attributeInfo.getterName !== null,
        hasSetterName: attributeInfo.setterName !== null,
        hasBackingIvar: attributeInfo.ivarName !== null,
        hasOldStyleTypeEncoding: attributeInfo.oldStyleTypeEncoding !== null,
        hasOwnershipModifier: attributeInfo.ownership !== 'assign',
        hasTypeEncoding: attributeInfo.typeEncoding.length !== 0,
        hasTypeName: attributeInfo.typeName.length !== 0,
        hasTypeInfo: attributeInfo.typeInfo !== null,
        isObject: attributeInfo.isObject,
        isBlock: attributeInfo.isBlock,
        objectClassName: attributeInfo.objectClassName,
        objectProtocols: attributeInfo.objectProtocols,
        objectProtocolCount,
        hasObjectClassName: attributeInfo.objectClassName !== null,
        hasObjectProtocols: objectProtocolCount !== 0,
        parsedTokenCount,
        hasParsedTokens: parsedTokenCount !== 0,
        attributeInfo,
        isClassProperty: !!property.isClassProperty,
        propertyPointer: property.propertyPointer.toString(),
        imagePath: property.imagePath === undefined || property.imagePath === null ? null : String(property.imagePath),
    };
    normalized.text = formatObjcPropertyInfo(normalized);
    return normalized;
}

function normalizeObjcProtocolPropertyInfo(property) {
    const attributeInfo = parseObjcPropertyAttributes(property.attributes);
    const objectProtocolCount = Array.isArray(attributeInfo.objectProtocols) ? attributeInfo.objectProtocols.length : 0;
    const parsedTokenCount = Array.isArray(attributeInfo.parsedTokens) ? attributeInfo.parsedTokens.length : 0;
    const normalized = {
        protocolName: String(property.protocolName || ''),
        name: String(property.name || ''),
        attributes: String(property.attributes || ''),
        typeEncoding: attributeInfo.typeEncoding,
        typeName: attributeInfo.typeName,
        typeInfo: attributeInfo.typeInfo,
        oldStyleTypeEncoding: attributeInfo.oldStyleTypeEncoding,
        ownership: attributeInfo.ownership,
        isReadonly: attributeInfo.isReadonly,
        isNonatomic: attributeInfo.isNonatomic,
        isDynamic: attributeInfo.isDynamic,
        isReadwrite: !attributeInfo.isReadonly,
        isAtomic: !attributeInfo.isNonatomic,
        isStrong: attributeInfo.ownership === 'strong',
        isCopy: attributeInfo.ownership === 'copy',
        isWeak: attributeInfo.ownership === 'weak',
        isAssign: attributeInfo.ownership === 'assign',
        getterName: attributeInfo.getterName,
        setterName: attributeInfo.setterName,
        ivarName: attributeInfo.ivarName,
        hasCustomGetter: attributeInfo.hasGetter,
        hasCustomSetter: attributeInfo.hasSetter,
        hasAccessorCustomization: attributeInfo.hasGetter || attributeInfo.hasSetter,
        hasAccessorNames: attributeInfo.getterName !== null || attributeInfo.setterName !== null,
        hasGetterName: attributeInfo.getterName !== null,
        hasSetterName: attributeInfo.setterName !== null,
        hasBackingIvar: attributeInfo.ivarName !== null,
        hasOldStyleTypeEncoding: attributeInfo.oldStyleTypeEncoding !== null,
        hasOwnershipModifier: attributeInfo.ownership !== 'assign',
        hasTypeEncoding: attributeInfo.typeEncoding.length !== 0,
        hasTypeName: attributeInfo.typeName.length !== 0,
        hasTypeInfo: attributeInfo.typeInfo !== null,
        isObject: attributeInfo.isObject,
        isBlock: attributeInfo.isBlock,
        objectClassName: attributeInfo.objectClassName,
        objectProtocols: attributeInfo.objectProtocols,
        objectProtocolCount,
        hasObjectClassName: attributeInfo.objectClassName !== null,
        hasObjectProtocols: objectProtocolCount !== 0,
        parsedTokenCount,
        hasParsedTokens: parsedTokenCount !== 0,
        attributeInfo,
        propertyPointer: property.propertyPointer.toString(),
        imagePath: property.imagePath === undefined || property.imagePath === null ? null : String(property.imagePath),
    };
    normalized.text = formatObjcProtocolPropertyInfo(normalized);
    return normalized;
}

function normalizeObjcIvar(ivar) {
    const offset = typeof ivar.offset === 'bigint' ? ivar.offset : BigInt(ivar.offset || 0);
    const typeInfo = parseObjcTypeEncodingInfo(ivar.typeEncoding);
    const qualifierCount = Array.isArray(typeInfo.qualifiers) ? typeInfo.qualifiers.length : 0;
    const objectProtocolCount = Array.isArray(typeInfo.objectProtocols) ? typeInfo.objectProtocols.length : 0;
    const pointeeTypeName = typeInfo.pointee && typeof typeInfo.pointee.displayName === 'string'
        ? typeInfo.pointee.displayName
        : null;
    const normalized = {
        className: String(ivar.className || ''),
        name: String(ivar.name || ''),
        typeEncoding: String(ivar.typeEncoding || ''),
        typeName: typeInfo.displayName,
        typeInfo,
        kind: String(typeInfo.kind || 'unknown'),
        qualifiers: Array.isArray(typeInfo.qualifiers) ? typeInfo.qualifiers : [],
        qualifierNames: Array.isArray(typeInfo.qualifierNames) ? typeInfo.qualifierNames : [],
        qualifierCount,
        hasQualifiers: qualifierCount !== 0,
        isObject: typeInfo.isObject,
        isBlock: typeInfo.isBlock,
        objectClassName: typeInfo.objectClassName,
        objectProtocols: typeInfo.objectProtocols,
        objectProtocolCount,
        hasObjectClassName: typeInfo.objectClassName !== null,
        pointeeTypeName,
        hasPointeeType: pointeeTypeName !== null,
        isPointer: typeInfo.kind === 'pointer',
        isArray: typeInfo.kind === 'array',
        arrayCount: typeof typeInfo.arrayCount === 'number' ? typeInfo.arrayCount : null,
        memberName: typeInfo.memberName,
        hasMemberName: typeInfo.memberName !== null,
        offset: offset.toString(),
        offsetHex: '0x' + offset.toString(16),
    };
    normalized.text = formatObjcIvar(normalized);
    return normalized;
}

function normalizeObjcIvarInfo(ivar) {
    const offset = typeof ivar.offset === 'bigint' ? ivar.offset : BigInt(ivar.offset || 0);
    const typeInfo = parseObjcTypeEncodingInfo(ivar.typeEncoding);
    const qualifierCount = Array.isArray(typeInfo.qualifiers) ? typeInfo.qualifiers.length : 0;
    const objectProtocolCount = Array.isArray(typeInfo.objectProtocols) ? typeInfo.objectProtocols.length : 0;
    const pointeeTypeName = typeInfo.pointee && typeof typeInfo.pointee.displayName === 'string'
        ? typeInfo.pointee.displayName
        : null;
    const normalized = {
        className: String(ivar.className || ''),
        name: String(ivar.name || ''),
        typeEncoding: String(ivar.typeEncoding || ''),
        typeName: typeInfo.displayName,
        typeInfo,
        kind: String(typeInfo.kind || 'unknown'),
        qualifiers: Array.isArray(typeInfo.qualifiers) ? typeInfo.qualifiers : [],
        qualifierNames: Array.isArray(typeInfo.qualifierNames) ? typeInfo.qualifierNames : [],
        qualifierCount,
        hasQualifiers: qualifierCount !== 0,
        isObject: typeInfo.isObject,
        isBlock: typeInfo.isBlock,
        objectClassName: typeInfo.objectClassName,
        objectProtocols: typeInfo.objectProtocols,
        objectProtocolCount,
        hasObjectClassName: typeInfo.objectClassName !== null,
        pointeeTypeName,
        hasPointeeType: pointeeTypeName !== null,
        isPointer: typeInfo.kind === 'pointer',
        isArray: typeInfo.kind === 'array',
        arrayCount: typeof typeInfo.arrayCount === 'number' ? typeInfo.arrayCount : null,
        memberName: typeInfo.memberName,
        hasMemberName: typeInfo.memberName !== null,
        offset: offset.toString(),
        offsetHex: '0x' + offset.toString(16),
        ivarPointer: ivar.ivarPointer.toString(),
        imagePath: ivar.imagePath === undefined || ivar.imagePath === null ? null : String(ivar.imagePath),
    };
    normalized.text = formatObjcIvarInfo(normalized);
    return normalized;
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
    const moduleName = String(symbol.moduleName || '');
    const name = String(symbol.name || '');
    return {
        moduleName,
        moduleBase: symbol.moduleBase ? symbol.moduleBase.toString() : null,
        name,
        hasModuleName: moduleName.length !== 0,
        hasName: name.length !== 0,
        address: symbol.address.toString(),
        offsetHex: '0x' + offset.toString(16),
        text: formatNativeSymbol(symbol),
    };
}

function normalizeImport(imp) {
    const name = String(imp.name || '');
    const dylibOrdinal = Number(imp.dylibOrdinal || 0);
    const dylibName = imp.dylibName === undefined || imp.dylibName === null ? null : String(imp.dylibName);
    return {
        moduleName: String(imp.moduleName || ''),
        moduleBase: imp.moduleBase ? imp.moduleBase.toString() : null,
        name,
        hasName: name.length !== 0,
        dylibOrdinal,
        dylibName,
        hasDylibName: dylibName !== null,
        usesOrdinalOnly: dylibName === null,
        isMainExecutableImport: dylibOrdinal === -1,
        isFlatLookupImport: dylibOrdinal === -2,
        weakImport: !!imp.weakImport,
        source: dylibName === null ? 'ordinal=' + String(dylibOrdinal) : dylibName,
        text: formatImport(imp),
    };
}

function normalizeDependency(dep) {
    const path = String(dep.path || '');
    const pathParts = path.split('/').filter(Boolean);
    const name = pathParts.length === 0 ? path : pathParts[pathParts.length - 1];
    const kind = String(dep.kind || 'load');
    const currentVersion = formatPackedVersion(dep.currentVersion);
    const compatibilityVersion = formatPackedVersion(dep.compatibilityVersion);
    const timestamp = Number(dep.timestamp || 0);
    return {
        moduleName: String(dep.moduleName || ''),
        moduleBase: dep.moduleBase ? dep.moduleBase.toString() : null,
        ordinal: Number(dep.ordinal || 0),
        path,
        hasPath: path.length !== 0,
        name,
        hasName: name.length !== 0,
        kind,
        isWeakDependency: kind === 'weak',
        isReexportDependency: kind === 'reexport',
        isUpwardDependency: kind === 'upward',
        isLoadDependency: kind === 'load',
        currentVersion,
        compatibilityVersion,
        versionMismatch: currentVersion !== compatibilityVersion,
        timestamp,
        hasTimestamp: timestamp !== 0,
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

function normalizeEntryPoint(entryPoint) {
    return {
        moduleName: String(entryPoint.moduleName || ''),
        moduleBase: entryPoint.moduleBase ? entryPoint.moduleBase.toString() : null,
        entryoffHex: '0x' + BigInt(entryPoint.entryoff || 0).toString(16),
        stacksizeHex: '0x' + BigInt(entryPoint.stacksize || 0).toString(16),
        text: formatEntryPoint(entryPoint),
    };
}

function normalizeDyldInfo(dyldInfo) {
    const regionSpecs = [
        { name: 'rebase', offset: dyldInfo.rebaseOff, size: dyldInfo.rebaseSize },
        { name: 'bind', offset: dyldInfo.bindOff, size: dyldInfo.bindSize },
        { name: 'weakBind', offset: dyldInfo.weakBindOff, size: dyldInfo.weakBindSize },
        { name: 'lazyBind', offset: dyldInfo.lazyBindOff, size: dyldInfo.lazyBindSize },
        { name: 'export', offset: dyldInfo.exportOff, size: dyldInfo.exportSize },
    ];
    const regions = regionSpecs.map((region) => normalizeDyldInfoRegion(region.name, region.offset, region.size));
    const nonEmptyRegions = regionSpecs.filter((region) => BigInt(region.size || 0) !== 0n);
    const rebaseSize = BigInt(dyldInfo.rebaseSize || 0);
    const bindSize = BigInt(dyldInfo.bindSize || 0);
    const weakBindSize = BigInt(dyldInfo.weakBindSize || 0);
    const lazyBindSize = BigInt(dyldInfo.lazyBindSize || 0);
    const exportSize = BigInt(dyldInfo.exportSize || 0);
    const regionCount = nonEmptyRegions.length;
    const totalSize = rebaseSize + bindSize + weakBindSize + lazyBindSize + exportSize;
    const firstRegion = nonEmptyRegions.length === 0 ? null : nonEmptyRegions[0];
    const lastRegion = nonEmptyRegions.length === 0 ? null : nonEmptyRegions[nonEmptyRegions.length - 1];
    const largestRegion = nonEmptyRegions.reduce((largest, region) => {
        if (largest === null) {
            return region;
        }
        return BigInt(region.size || 0) > BigInt(largest.size || 0) ? region : largest;
    }, null);
    return {
        moduleName: String(dyldInfo.moduleName || ''),
        moduleBase: dyldInfo.moduleBase ? dyldInfo.moduleBase.toString() : null,
        commandHex: '0x' + BigInt(dyldInfo.command || 0).toString(16),
        commandName: String(dyldInfo.commandName || 'LC_DYLD_INFO'),
        commandRequiresDyld: (Number(dyldInfo.command || 0) & 0x80000000) !== 0,
        rebaseOffHex: '0x' + BigInt(dyldInfo.rebaseOff || 0).toString(16),
        rebaseSizeHex: '0x' + BigInt(dyldInfo.rebaseSize || 0).toString(16),
        rebaseEndHex: formatHexAdd(dyldInfo.rebaseOff, dyldInfo.rebaseSize),
        hasRebaseInfo: rebaseSize !== 0n,
        bindOffHex: '0x' + BigInt(dyldInfo.bindOff || 0).toString(16),
        bindSizeHex: '0x' + BigInt(dyldInfo.bindSize || 0).toString(16),
        bindEndHex: formatHexAdd(dyldInfo.bindOff, dyldInfo.bindSize),
        hasBindInfo: bindSize !== 0n,
        weakBindOffHex: '0x' + BigInt(dyldInfo.weakBindOff || 0).toString(16),
        weakBindSizeHex: '0x' + BigInt(dyldInfo.weakBindSize || 0).toString(16),
        weakBindEndHex: formatHexAdd(dyldInfo.weakBindOff, dyldInfo.weakBindSize),
        hasWeakBindInfo: weakBindSize !== 0n,
        lazyBindOffHex: '0x' + BigInt(dyldInfo.lazyBindOff || 0).toString(16),
        lazyBindSizeHex: '0x' + BigInt(dyldInfo.lazyBindSize || 0).toString(16),
        lazyBindEndHex: formatHexAdd(dyldInfo.lazyBindOff, dyldInfo.lazyBindSize),
        hasLazyBindInfo: lazyBindSize !== 0n,
        exportOffHex: '0x' + BigInt(dyldInfo.exportOff || 0).toString(16),
        exportSizeHex: '0x' + BigInt(dyldInfo.exportSize || 0).toString(16),
        exportEndHex: formatHexAdd(dyldInfo.exportOff, dyldInfo.exportSize),
        hasExportInfo: exportSize !== 0n,
        hasAnyBindInfo: bindSize !== 0n || weakBindSize !== 0n || lazyBindSize !== 0n,
        totalRegionCount: regions.length,
        regionCount,
        hasRegions: regionCount !== 0,
        firstRegionName: firstRegion === null ? null : firstRegion.name,
        lastRegionName: lastRegion === null ? null : lastRegion.name,
        largestRegionName: largestRegion === null ? null : largestRegion.name,
        largestRegionSizeHex: largestRegion === null ? null : '0x' + BigInt(largestRegion.size || 0).toString(16),
        nonEmptyRegionNames: nonEmptyRegions.map((region) => region.name),
        regions,
        totalSizeHex: '0x' + totalSize.toString(16),
        text: formatDyldInfo(dyldInfo),
    };
}

function normalizeLinkeditTable(name, offset, address, count, size) {
    const hasOffset = offset !== null && offset !== undefined;
    const hasAddress = address !== null && address !== undefined;
    const hasCount = count !== null && count !== undefined;
    const hasSize = size !== null && size !== undefined;
    return {
        name,
        offsetHex: hasOffset ? '0x' + BigInt(offset).toString(16) : null,
        address: hasAddress ? String(address) : null,
        count: hasCount ? Number(count) : null,
        sizeHex: hasSize ? '0x' + BigInt(size).toString(16) : null,
        hasOffset,
        hasAddress,
        hasCount,
        hasSize,
        isPresent: hasOffset || hasAddress || hasCount || hasSize,
    };
}

function normalizeLinkedit(linkedit) {
    const symoff = linkedit.symoff === null || linkedit.symoff === undefined ? null : BigInt(linkedit.symoff);
    const stroff = linkedit.stroff === null || linkedit.stroff === undefined ? null : BigInt(linkedit.stroff);
    const indirectsymoff = linkedit.indirectsymoff === null || linkedit.indirectsymoff === undefined ? null : BigInt(linkedit.indirectsymoff);
    const tables = [
        normalizeLinkeditTable(
            'symtab',
            linkedit.symoff,
            symoff === null ? null : formatHexAdd(linkedit.computedBase, linkedit.symoff),
            linkedit.nsyms,
            null
        ),
        normalizeLinkeditTable(
            'strtab',
            linkedit.stroff,
            stroff === null ? null : formatHexAdd(linkedit.computedBase, linkedit.stroff),
            null,
            linkedit.strsize
        ),
        normalizeLinkeditTable(
            'indirectsym',
            linkedit.indirectsymoff,
            indirectsymoff === null ? null : formatHexAdd(linkedit.computedBase, linkedit.indirectsymoff),
            linkedit.nindirectsyms,
            null
        ),
    ];
    const presentTables = tables.filter((table) => table.isPresent);
    const firstTable = presentTables.length === 0 ? null : presentTables[0];
    const lastTable = presentTables.length === 0 ? null : presentTables[presentTables.length - 1];
    return {
        moduleName: String(linkedit.moduleName || ''),
        moduleBase: linkedit.moduleBase ? linkedit.moduleBase.toString() : null,
        vmaddr: linkedit.vmaddr.toString(),
        vmsizeHex: '0x' + BigInt(linkedit.vmsize || 0).toString(16),
        vmEnd: formatHexAdd(linkedit.vmaddr, linkedit.vmsize),
        fileoffHex: '0x' + BigInt(linkedit.fileoff || 0).toString(16),
        filesizeHex: '0x' + BigInt(linkedit.filesize || 0).toString(16),
        fileEndHex: formatHexAdd(linkedit.fileoff, linkedit.filesize),
        computedBase: linkedit.computedBase.toString(),
        computedEnd: formatHexAdd(linkedit.computedBase, linkedit.filesize),
        symoffHex: symoff === null ? null : '0x' + symoff.toString(16),
        nsyms: linkedit.nsyms === null || linkedit.nsyms === undefined ? null : Number(linkedit.nsyms),
        hasSymtab: symoff !== null,
        symtabAddress: symoff === null ? null : formatHexAdd(linkedit.computedBase, symoff),
        stroffHex: stroff === null ? null : '0x' + stroff.toString(16),
        strsizeHex: linkedit.strsize === null || linkedit.strsize === undefined ? null : '0x' + BigInt(linkedit.strsize).toString(16),
        hasStrtab: stroff !== null,
        strtabAddress: stroff === null ? null : formatHexAdd(linkedit.computedBase, stroff),
        indirectsymoffHex: indirectsymoff === null ? null : '0x' + indirectsymoff.toString(16),
        nindirectsyms: linkedit.nindirectsyms === null || linkedit.nindirectsyms === undefined ? null : Number(linkedit.nindirectsyms),
        hasIndirectSymbols: indirectsymoff !== null,
        indirectsymAddress: indirectsymoff === null ? null : formatHexAdd(linkedit.computedBase, indirectsymoff),
        totalTableCount: tables.length,
        tableCount: presentTables.length,
        hasTables: presentTables.length !== 0,
        tableNames: tables.map((table) => table.name),
        nonEmptyTableNames: presentTables.map((table) => table.name),
        firstTableName: firstTable === null ? null : firstTable.name,
        lastTableName: lastTable === null ? null : lastTable.name,
        tables,
        text: formatLinkedit(linkedit),
    };
}

function normalizeFunctionStart(functionStart) {
    return {
        offsetHex: '0x' + BigInt(functionStart.offset || 0).toString(16),
        address: functionStart.address.toString(),
        text: formatFunctionStart(functionStart),
    };
}

function normalizeFunctionStarts(functionStarts) {
    const starts = Array.isArray(functionStarts.starts)
        ? functionStarts.starts.map((functionStart) => normalizeFunctionStart(functionStart))
        : [];
    const firstStart = starts.length === 0 ? null : starts[0];
    const lastStart = starts.length === 0 ? null : starts[starts.length - 1];
    const gaps = [];
    for (let i = 1; i < starts.length; i++) {
        const previous = BigInt(starts[i - 1].offsetHex);
        const current = BigInt(starts[i].offsetHex);
        gaps.push({
            fromOffsetHex: starts[i - 1].offsetHex,
            toOffsetHex: starts[i].offsetHex,
            deltaHex: '0x' + (current - previous).toString(16),
        });
    }
    const firstGap = gaps.length === 0 ? null : gaps[0];
    const lastGap = gaps.length === 0 ? null : gaps[gaps.length - 1];
    const largestGap = gaps.reduce((largest, gap) => {
        if (largest === null) {
            return gap;
        }
        return BigInt(gap.deltaHex) > BigInt(largest.deltaHex) ? gap : largest;
    }, null);
    const totalSpan = firstStart === null || lastStart === null
        ? 0n
        : BigInt(lastStart.offsetHex) - BigInt(firstStart.offsetHex);
    return {
        moduleName: String(functionStarts.moduleName || ''),
        moduleBase: functionStarts.moduleBase ? functionStarts.moduleBase.toString() : null,
        dataoffHex: '0x' + BigInt(functionStarts.dataoff || 0).toString(16),
        datasizeHex: '0x' + BigInt(functionStarts.datasize || 0).toString(16),
        linkeditBase: functionStarts.linkeditBase.toString(),
        dataAddress: functionStarts.dataAddress.toString(),
        dataEnd: formatHexAdd(functionStarts.dataAddress, functionStarts.datasize),
        count: starts.length,
        hasStarts: starts.length !== 0,
        firstStartOffsetHex: firstStart === null ? null : firstStart.offsetHex,
        firstStartAddress: firstStart === null ? null : firstStart.address,
        lastStartOffsetHex: lastStart === null ? null : lastStart.offsetHex,
        lastStartAddress: lastStart === null ? null : lastStart.address,
        totalSpanHex: '0x' + totalSpan.toString(16),
        gapCount: gaps.length,
        hasGaps: gaps.length !== 0,
        firstGapHex: firstGap === null ? null : firstGap.deltaHex,
        lastGapHex: lastGap === null ? null : lastGap.deltaHex,
        largestGapHex: largestGap === null ? null : largestGap.deltaHex,
        firstGapFromOffsetHex: firstGap === null ? null : firstGap.fromOffsetHex,
        firstGapToOffsetHex: firstGap === null ? null : firstGap.toOffsetHex,
        lastGapFromOffsetHex: lastGap === null ? null : lastGap.fromOffsetHex,
        lastGapToOffsetHex: lastGap === null ? null : lastGap.toOffsetHex,
        starts,
        text: formatFunctionStarts(functionStarts),
    };
}

function normalizeCodeSignature(codeSignature) {
    const dataoff = BigInt(codeSignature.dataoff || 0);
    const datasize = BigInt(codeSignature.datasize || 0);
    const length = codeSignature.length === null || codeSignature.length === undefined ? null : BigInt(codeSignature.length);
    const magicName = codeSignature.magicName === undefined ? null : codeSignature.magicName;
    return {
        moduleName: String(codeSignature.moduleName || ''),
        moduleBase: codeSignature.moduleBase ? codeSignature.moduleBase.toString() : null,
        dataoffHex: '0x' + dataoff.toString(16),
        datasizeHex: '0x' + datasize.toString(16),
        linkeditBase: codeSignature.linkeditBase.toString(),
        dataAddress: codeSignature.dataAddress.toString(),
        dataEnd: formatHexAdd(codeSignature.dataAddress, codeSignature.datasize),
        magicHex: codeSignature.magic === null || codeSignature.magic === undefined ? null : '0x' + BigInt(codeSignature.magic).toString(16),
        magicName,
        hasMagic: magicName !== null,
        lengthHex: length === null ? null : '0x' + length.toString(16),
        count: codeSignature.count === null || codeSignature.count === undefined ? null : Number(codeSignature.count),
        hasBlobLength: length !== null,
        blobLengthMatchesDataSize: length === null ? null : length === datasize,
        isSuperBlob: magicName === 'CSMAGIC_EMBEDDED_SIGNATURE',
        text: formatCodeSignature(codeSignature),
    };
}

function normalizeDataInCodeEntry(entry) {
    return {
        offsetHex: '0x' + BigInt(entry.offset || 0).toString(16),
        address: entry.address.toString(),
        length: Number(entry.length || 0),
        kind: Number(entry.kind || 0),
        kindName: String(entry.kindName || 'DICE_KIND_UNKNOWN'),
        text: formatDataInCodeEntry(entry),
    };
}

function normalizeDataInCode(dataInCode) {
    const entries = Array.isArray(dataInCode.entries)
        ? dataInCode.entries.map((entry) => normalizeDataInCodeEntry(entry))
        : [];
    const firstEntry = entries.length === 0 ? null : entries[0];
    const lastEntry = entries.length === 0 ? null : entries[entries.length - 1];
    const totalEntryLength = entries.reduce((sum, entry) => sum + BigInt(entry.length || 0), 0n);
    return {
        moduleName: String(dataInCode.moduleName || ''),
        moduleBase: dataInCode.moduleBase ? dataInCode.moduleBase.toString() : null,
        dataoffHex: '0x' + BigInt(dataInCode.dataoff || 0).toString(16),
        datasizeHex: '0x' + BigInt(dataInCode.datasize || 0).toString(16),
        linkeditBase: dataInCode.linkeditBase.toString(),
        dataAddress: dataInCode.dataAddress.toString(),
        dataEnd: formatHexAdd(dataInCode.dataAddress, dataInCode.datasize),
        count: entries.length,
        hasEntries: entries.length !== 0,
        totalEntryLength: '0x' + totalEntryLength.toString(16),
        firstEntryOffsetHex: firstEntry === null ? null : firstEntry.offsetHex,
        firstEntryAddress: firstEntry === null ? null : firstEntry.address,
        lastEntryOffsetHex: lastEntry === null ? null : lastEntry.offsetHex,
        lastEntryAddress: lastEntry === null ? null : lastEntry.address,
        entries,
        text: formatDataInCode(dataInCode),
    };
}

function normalizeExportsTrieEntry(entry) {
    return {
        name: String(entry.name || ''),
        flagsHex: '0x' + BigInt(entry.flags || 0).toString(16),
        kind: String(entry.kind || 'unknown'),
        address: entry.address === null || entry.address === undefined ? null : entry.address.toString(),
        hasAddress: entry.address !== null && entry.address !== undefined,
        offsetHex: entry.offset === null || entry.offset === undefined ? null : '0x' + BigInt(entry.offset).toString(16),
        hasOffset: entry.offset !== null && entry.offset !== undefined,
        otherHex: entry.other === null || entry.other === undefined ? null : '0x' + BigInt(entry.other).toString(16),
        importName: entry.importName === null || entry.importName === undefined ? null : String(entry.importName),
        hasImportName: entry.importName !== null && entry.importName !== undefined,
        isWeakDefinition: !!entry.isWeakDefinition,
        isReexport: !!entry.isReexport,
        isStubAndResolver: !!entry.isStubAndResolver,
        hasResolver: entry.other !== null && entry.other !== undefined,
        text: formatExportsTrieEntry(entry),
    };
}

function normalizeExportsTrie(exportsTrie) {
    const entries = Array.isArray(exportsTrie.entries)
        ? exportsTrie.entries.map((entry) => normalizeExportsTrieEntry(entry))
        : [];
    const reexportCount = entries.filter((entry) => entry.isReexport).length;
    const stubAndResolverCount = entries.filter((entry) => entry.isStubAndResolver).length;
    const weakDefinitionCount = entries.filter((entry) => entry.isWeakDefinition).length;
    return {
        moduleName: String(exportsTrie.moduleName || ''),
        moduleBase: exportsTrie.moduleBase ? exportsTrie.moduleBase.toString() : null,
        dataoffHex: '0x' + BigInt(exportsTrie.dataoff || 0).toString(16),
        datasizeHex: '0x' + BigInt(exportsTrie.datasize || 0).toString(16),
        linkeditBase: exportsTrie.linkeditBase.toString(),
        dataAddress: exportsTrie.dataAddress.toString(),
        dataEnd: formatHexAdd(exportsTrie.dataAddress, exportsTrie.datasize),
        count: entries.length,
        hasEntries: entries.length !== 0,
        firstExportName: entries.length === 0 ? null : entries[0].name,
        lastExportName: entries.length === 0 ? null : entries[entries.length - 1].name,
        reexportCount,
        hasReexports: reexportCount !== 0,
        stubAndResolverCount,
        hasStubAndResolvers: stubAndResolverCount !== 0,
        weakDefinitionCount,
        hasWeakDefinitions: weakDefinitionCount !== 0,
        entries,
        text: formatExportsTrie(exportsTrie),
    };
}

function normalizeChainedFixupsPage(page) {
    const chainStarts = Array.isArray(page.chainStarts)
        ? page.chainStarts.map((value) => '0x' + BigInt(value || 0).toString(16))
        : [];
    return {
        pageIndex: Number(page.pageIndex || 0),
        hasFixups: !!page.hasFixups,
        pageStartHex: page.pageStart === null || page.pageStart === undefined ? null : '0x' + BigInt(page.pageStart).toString(16),
        usesMultipleStarts: !!page.usesMultipleStarts,
        chainStarts,
    };
}

function normalizeChainedFixupsSegment(segment) {
    const pages = Array.isArray(segment.pages)
        ? segment.pages.map((page) => normalizeChainedFixupsPage(page))
        : [];
    return {
        segmentIndex: Number(segment.segmentIndex || 0),
        offsetInStartsHex: '0x' + BigInt(segment.offsetInStarts || 0).toString(16),
        sizeHex: '0x' + BigInt(segment.size || 0).toString(16),
        pageSizeHex: '0x' + BigInt(segment.pageSize || 0).toString(16),
        pointerFormat: Number(segment.pointerFormat || 0),
        pointerFormatName: String(segment.pointerFormatName || 'DYLD_CHAINED_PTR_UNKNOWN'),
        segmentOffsetHex: '0x' + BigInt(segment.segmentOffset || 0).toString(16),
        maxValidPointerHex: '0x' + BigInt(segment.maxValidPointer || 0).toString(16),
        pageCount: Number(segment.pageCount || 0),
        fixupPageCount: Number(segment.fixupPageCount || 0),
        multiPageCount: Number(segment.multiPageCount || 0),
        hasPages: pages.length !== 0,
        firstPageIndex: pages.length === 0 ? null : pages[0].pageIndex,
        lastPageIndex: pages.length === 0 ? null : pages[pages.length - 1].pageIndex,
        pages,
        text: formatChainedFixupsSegment(segment),
    };
}

function normalizeChainedFixupsImport(imp) {
    return {
        index: Number(imp.index || 0),
        libOrdinalRawHex: '0x' + BigInt(imp.libOrdinalRaw || 0).toString(16),
        libOrdinal: Number(imp.libOrdinal || 0),
        weakImport: !!imp.weakImport,
        nameOffsetHex: '0x' + BigInt(imp.nameOffset || 0).toString(16),
        name: imp.name === null || imp.name === undefined ? null : String(imp.name),
        hasName: imp.name !== null && imp.name !== undefined,
        addend: imp.addend === null || imp.addend === undefined ? null : imp.addend.toString(),
        hasAddend: imp.addend !== null && imp.addend !== undefined,
        text: formatChainedFixupsImport(imp),
    };
}

function normalizeChainedFixups(chainedFixups) {
    const segments = Array.isArray(chainedFixups.segments)
        ? chainedFixups.segments.map((segment) => normalizeChainedFixupsSegment(segment))
        : [];
    const imports = Array.isArray(chainedFixups.imports)
        ? chainedFixups.imports.map((imp) => normalizeChainedFixupsImport(imp))
        : [];
    return {
        moduleName: String(chainedFixups.moduleName || ''),
        moduleBase: chainedFixups.moduleBase ? chainedFixups.moduleBase.toString() : null,
        dataoffHex: '0x' + BigInt(chainedFixups.dataoff || 0).toString(16),
        datasizeHex: '0x' + BigInt(chainedFixups.datasize || 0).toString(16),
        linkeditBase: chainedFixups.linkeditBase.toString(),
        dataAddress: chainedFixups.dataAddress.toString(),
        dataEnd: formatHexAdd(chainedFixups.dataAddress, chainedFixups.datasize),
        fixupsVersion: Number(chainedFixups.fixupsVersion || 0),
        startsOffsetHex: '0x' + BigInt(chainedFixups.startsOffset || 0).toString(16),
        startsAddress: formatHexAdd(chainedFixups.dataAddress, chainedFixups.startsOffset),
        importsOffsetHex: '0x' + BigInt(chainedFixups.importsOffset || 0).toString(16),
        importsAddress: formatHexAdd(chainedFixups.dataAddress, chainedFixups.importsOffset),
        symbolsOffsetHex: '0x' + BigInt(chainedFixups.symbolsOffset || 0).toString(16),
        symbolsAddress: formatHexAdd(chainedFixups.dataAddress, chainedFixups.symbolsOffset),
        importsCount: Number(chainedFixups.importsCount || 0),
        importsFormat: Number(chainedFixups.importsFormat || 0),
        importsFormatName: String(chainedFixups.importsFormatName || 'DYLD_CHAINED_IMPORT_UNKNOWN'),
        symbolsFormat: Number(chainedFixups.symbolsFormat || 0),
        symbolsFormatName: String(chainedFixups.symbolsFormatName || 'unknown'),
        segmentCount: segments.length,
        hasSegments: segments.length !== 0,
        firstSegmentIndex: segments.length === 0 ? null : segments[0].segmentIndex,
        lastSegmentIndex: segments.length === 0 ? null : segments[segments.length - 1].segmentIndex,
        importCount: imports.length,
        hasImports: imports.length !== 0,
        firstImportName: imports.length === 0 ? null : imports[0].name,
        lastImportName: imports.length === 0 ? null : imports[imports.length - 1].name,
        segments,
        imports,
        text: formatChainedFixups(chainedFixups),
    };
}

function normalizeSourceVersion(sourceVersion) {
    return {
        moduleName: String(sourceVersion.moduleName || ''),
        moduleBase: sourceVersion.moduleBase ? sourceVersion.moduleBase.toString() : null,
        version: String(sourceVersion.version || ''),
        text: formatSourceVersion(sourceVersion),
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
        hasTools: tools.length !== 0,
        firstTool: tools.length === 0 ? null : tools[0].tool,
        lastTool: tools.length === 0 ? null : tools[tools.length - 1].tool,
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
        hasPath: path.length !== 0,
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
        hasPath: path.length !== 0,
        currentVersion: formatPackedVersion(installName.currentVersion),
        compatibilityVersion: formatPackedVersion(installName.compatibilityVersion),
        timestamp: Number(installName.timestamp || 0),
        hasTimestamp: Number(installName.timestamp || 0) !== 0,
        versionMismatch: formatPackedVersion(installName.currentVersion) !== formatPackedVersion(installName.compatibilityVersion),
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

function normalizeSwiftProtocol(protocolInfo) {
    const sourceOffset = typeof protocolInfo.sourceOffset === 'bigint' ? protocolInfo.sourceOffset : BigInt(protocolInfo.sourceOffset || 0);
    return {
        moduleName: String(protocolInfo.moduleName || ''),
        moduleBase: protocolInfo.moduleBase ? protocolInfo.moduleBase.toString() : null,
        name: String(protocolInfo.name || ''),
        sourceSymbolName: protocolInfo.sourceSymbolName === undefined ? null : String(protocolInfo.sourceSymbolName),
        sourceKind: protocolInfo.sourceKind === undefined ? null : protocolInfo.sourceKind,
        sourceAddress: protocolInfo.sourceAddress.toString(),
        sourceOffsetHex: '0x' + sourceOffset.toString(16),
        sourceDemangledName: protocolInfo.sourceDemangledName === undefined ? null : protocolInfo.sourceDemangledName,
        text: formatSwiftProtocol(protocolInfo),
    };
}

function normalizeSwiftConformance(conformance) {
    const sourceOffset = typeof conformance.sourceOffset === 'bigint' ? conformance.sourceOffset : BigInt(conformance.sourceOffset || 0);
    return {
        moduleName: String(conformance.moduleName || ''),
        moduleBase: conformance.moduleBase ? conformance.moduleBase.toString() : null,
        typeName: String(conformance.typeName || ''),
        protocolName: String(conformance.protocolName || ''),
        sourceSymbolName: conformance.sourceSymbolName === undefined ? null : String(conformance.sourceSymbolName),
        sourceKind: conformance.sourceKind === undefined ? null : conformance.sourceKind,
        sourceAddress: conformance.sourceAddress.toString(),
        sourceOffsetHex: '0x' + sourceOffset.toString(16),
        sourceDemangledName: conformance.sourceDemangledName === undefined ? null : conformance.sourceDemangledName,
        text: formatSwiftConformance(conformance),
    };
}

function normalizeSwiftVtableEntry(entry) {
    const offset = typeof entry.offset === 'bigint' ? entry.offset : BigInt(entry.offset || 0);
    return {
        moduleName: String(entry.moduleName || ''),
        moduleBase: entry.moduleBase ? entry.moduleBase.toString() : null,
        typeName: String(entry.typeName || ''),
        memberName: String(entry.memberName || ''),
        name: String(entry.name || ''),
        demangledName: entry.demangledName === undefined ? null : entry.demangledName,
        sourceKind: entry.sourceKind === undefined ? null : entry.sourceKind,
        address: entry.address.toString(),
        offsetHex: '0x' + offset.toString(16),
        isDispatchThunk: !!entry.isDispatchThunk,
        text: formatSwiftVtableEntry(entry),
    };
}

function normalizeSwiftWitnessTable(entry) {
    const offset = typeof entry.offset === 'bigint' ? entry.offset : BigInt(entry.offset || 0);
    return {
        moduleName: String(entry.moduleName || ''),
        moduleBase: entry.moduleBase ? entry.moduleBase.toString() : null,
        typeName: String(entry.typeName || ''),
        protocolName: String(entry.protocolName || ''),
        name: String(entry.name || ''),
        demangledName: entry.demangledName === undefined ? null : entry.demangledName,
        sourceKind: entry.sourceKind === undefined ? null : entry.sourceKind,
        address: entry.address.toString(),
        offsetHex: '0x' + offset.toString(16),
        isAccessor: !!entry.isAccessor,
        text: formatSwiftWitnessTable(entry),
    };
}

function normalizeSwiftTypeLayout(layout) {
    const metadata = Array.isArray(layout.metadata)
        ? layout.metadata.map((typeInfo) => normalizeSwiftType(typeInfo))
        : [];
    const metadataAccessors = Array.isArray(layout.metadataAccessors)
        ? layout.metadataAccessors.map((typeInfo) => normalizeSwiftType(typeInfo))
        : [];
    const nominalDescriptors = Array.isArray(layout.nominalDescriptors)
        ? layout.nominalDescriptors.map((typeInfo) => normalizeSwiftType(typeInfo))
        : [];
    const metadataCaches = Array.isArray(layout.metadataCaches)
        ? layout.metadataCaches.map((typeInfo) => normalizeSwiftType(typeInfo))
        : [];
    const associatedTypeDescriptors = Array.isArray(layout.associatedTypeDescriptors)
        ? layout.associatedTypeDescriptors.map((typeInfo) => normalizeSwiftType(typeInfo))
        : [];
    const vtableEntries = Array.isArray(layout.vtableEntries)
        ? layout.vtableEntries.map((entry) => normalizeSwiftVtableEntry(entry))
        : [];
    const witnessTables = Array.isArray(layout.witnessTables)
        ? layout.witnessTables.map((entry) => normalizeSwiftWitnessTable(entry))
        : [];

    const normalized = {
        moduleName: String(layout.moduleName || ''),
        moduleBase: layout.moduleBase ? layout.moduleBase.toString() : null,
        name: String(layout.name || ''),
        metadata,
        hasMetadata: metadata.length !== 0,
        firstMetadataName: metadata.length === 0 ? null : metadata[0].name,
        lastMetadataName: metadata.length === 0 ? null : metadata[metadata.length - 1].name,
        metadataAccessors,
        hasMetadataAccessors: metadataAccessors.length !== 0,
        firstMetadataAccessorName: metadataAccessors.length === 0 ? null : metadataAccessors[0].name,
        lastMetadataAccessorName: metadataAccessors.length === 0 ? null : metadataAccessors[metadataAccessors.length - 1].name,
        nominalDescriptors,
        hasNominalDescriptors: nominalDescriptors.length !== 0,
        firstNominalDescriptorName: nominalDescriptors.length === 0 ? null : nominalDescriptors[0].name,
        lastNominalDescriptorName: nominalDescriptors.length === 0 ? null : nominalDescriptors[nominalDescriptors.length - 1].name,
        metadataCaches,
        hasMetadataCaches: metadataCaches.length !== 0,
        firstMetadataCacheName: metadataCaches.length === 0 ? null : metadataCaches[0].name,
        lastMetadataCacheName: metadataCaches.length === 0 ? null : metadataCaches[metadataCaches.length - 1].name,
        associatedTypeDescriptors,
        hasAssociatedTypeDescriptors: associatedTypeDescriptors.length !== 0,
        firstAssociatedTypeDescriptorName: associatedTypeDescriptors.length === 0 ? null : associatedTypeDescriptors[0].name,
        lastAssociatedTypeDescriptorName: associatedTypeDescriptors.length === 0 ? null : associatedTypeDescriptors[associatedTypeDescriptors.length - 1].name,
        vtableEntries,
        hasVtableEntries: vtableEntries.length !== 0,
        firstVtableMemberName: vtableEntries.length === 0 ? null : vtableEntries[0].memberName,
        lastVtableMemberName: vtableEntries.length === 0 ? null : vtableEntries[vtableEntries.length - 1].memberName,
        witnessTables,
        hasWitnessTables: witnessTables.length !== 0,
        firstWitnessProtocolName: witnessTables.length === 0 ? null : witnessTables[0].protocolName,
        lastWitnessProtocolName: witnessTables.length === 0 ? null : witnessTables[witnessTables.length - 1].protocolName,
        metadataCount: metadata.length,
        metadataAccessorCount: metadataAccessors.length,
        nominalDescriptorCount: nominalDescriptors.length,
        metadataCacheCount: metadataCaches.length,
        associatedTypeDescriptorCount: associatedTypeDescriptors.length,
        vtableCount: vtableEntries.length,
        witnessTableCount: witnessTables.length,
    };
    normalized.text = formatSwiftTypeLayout(normalized);
    return normalized;
}

function handleSpecResult(spec) {
    if (spec === null || typeof spec !== 'object') {
        throw new Error('agent command spec must be an object');
    }

    switch (String(spec.kind || '')) {
    case 'objc.classes': {
        const filter = spec.filter === null || spec.filter === undefined ? null : String(spec.filter).trim();
        const classes = ObjC.classes(filter);
        return {
            kind: 'objc.classes',
            filter,
            hasFilter: filter !== null && filter.length !== 0,
            count: classes.length,
            hasClasses: classes.length !== 0,
            firstClass: classes.length === 0 ? null : classes[0],
            lastClass: classes.length === 0 ? null : classes[classes.length - 1],
            classes,
            text: classes.join('\n'),
        };
    }
    case 'objc.protocols': {
        const filter = spec.filter === null || spec.filter === undefined ? null : String(spec.filter).trim();
        const protocols = ObjC.protocols(filter).map((name) => String(name));
        return {
            kind: 'objc.protocols',
            filter,
            hasFilter: filter !== null && filter.length !== 0,
            count: protocols.length,
            hasProtocols: protocols.length !== 0,
            firstProtocol: protocols.length === 0 ? null : protocols[0],
            lastProtocol: protocols.length === 0 ? null : protocols[protocols.length - 1],
            protocols,
            text: protocols.join('\n'),
        };
    }
    case 'objc.class_protocols': {
        const className = String(spec.className || '');
        const filter = spec.filter === null || spec.filter === undefined ? null : String(spec.filter);
        const protocols = ObjC.classProtocols(className, filter).map((name) => String(name));
        return {
            kind: 'objc.class_protocols',
            className,
            filter,
            hasFilter: filter !== null && filter.length !== 0,
            count: protocols.length,
            hasProtocols: protocols.length !== 0,
            firstProtocol: protocols.length === 0 ? null : protocols[0],
            lastProtocol: protocols.length === 0 ? null : protocols[protocols.length - 1],
            protocols,
            text: protocols.join('\n'),
        };
    }
    case 'objc.class_info': {
        const className = String(spec.className || '');
        const isMetaClass = !!spec.isMetaClass;
        const classInfo = ObjC.classInfo(className, isMetaClass);
        const normalized = classInfo === null ? null : normalizeObjcClassInfo(classInfo);
        return {
            kind: 'objc.class_info',
            className,
            isMetaClass,
            classInfo: normalized,
            text: normalized === null ? '<null>' : normalized.text,
        };
    }
    case 'objc.protocol_info': {
        const protocolName = String(spec.protocolName || '');
        const protocolInfo = ObjC.protocolInfo(protocolName);
        const normalized = protocolInfo === null ? null : normalizeObjcProtocolInfo(protocolInfo);
        return {
            kind: 'objc.protocol_info',
            protocolName,
            protocolInfo: normalized,
            text: normalized === null ? '<null>' : normalized.text,
        };
    }
    case 'objc.protocol_protocols': {
        const protocolName = String(spec.protocolName || '');
        const filter = spec.filter === null || spec.filter === undefined ? null : String(spec.filter);
        const protocols = ObjC.protocolProtocols(protocolName, filter).map((name) => String(name));
        return {
            kind: 'objc.protocol_protocols',
            protocolName,
            filter,
            hasFilter: filter !== null && filter.length !== 0,
            count: protocols.length,
            hasProtocols: protocols.length !== 0,
            firstProtocol: protocols.length === 0 ? null : protocols[0],
            lastProtocol: protocols.length === 0 ? null : protocols[protocols.length - 1],
            protocols,
            text: protocols.join('\n'),
        };
    }
    case 'objc.protocol_methods': {
        const protocolName = String(spec.protocolName || '');
        const isRequired = spec.isRequired === undefined ? true : !!spec.isRequired;
        const isInstanceMethod = spec.isInstanceMethod === undefined ? true : !!spec.isInstanceMethod;
        const filter = spec.filter === null || spec.filter === undefined ? null : String(spec.filter);
        const methods = ObjC.protocolMethods(protocolName, isRequired, isInstanceMethod, filter).map((method) => normalizeObjcProtocolMethod(method));
        return {
            kind: 'objc.protocol_methods',
            protocolName,
            isRequired,
            isInstanceMethod,
            filter,
            hasFilter: filter !== null && filter.length !== 0,
            count: methods.length,
            hasMethods: methods.length !== 0,
            firstSelector: methods.length === 0 ? null : methods[0].selector,
            lastSelector: methods.length === 0 ? null : methods[methods.length - 1].selector,
            methods,
            text: methods.map((method) => method.text).join('\n'),
        };
    }
    case 'objc.protocol_method_info': {
        const protocolName = String(spec.protocolName || '');
        const selectorName = String(spec.selectorName || '');
        const isRequired = spec.isRequired === undefined ? true : !!spec.isRequired;
        const isInstanceMethod = spec.isInstanceMethod === undefined ? true : !!spec.isInstanceMethod;
        const methodInfo = ObjC.protocolMethodInfo(protocolName, selectorName, isRequired, isInstanceMethod);
        const normalized = methodInfo === null ? null : normalizeObjcProtocolMethodInfo(methodInfo);
        return {
            kind: 'objc.protocol_method_info',
            protocolName,
            selectorName,
            isRequired,
            isInstanceMethod,
            methodInfo: normalized,
            text: normalized === null ? '<null>' : normalized.text,
        };
    }
    case 'objc.protocol_properties': {
        const protocolName = String(spec.protocolName || '');
        const filter = spec.filter === null || spec.filter === undefined ? null : String(spec.filter);
        const properties = ObjC.protocolProperties(protocolName, filter).map((property) => normalizeObjcProtocolProperty(property));
        return {
            kind: 'objc.protocol_properties',
            protocolName,
            filter,
            hasFilter: filter !== null && filter.length !== 0,
            count: properties.length,
            hasProperties: properties.length !== 0,
            firstProperty: properties.length === 0 ? null : properties[0].name,
            lastProperty: properties.length === 0 ? null : properties[properties.length - 1].name,
            properties,
            text: properties.map((property) => property.text).join('\n'),
        };
    }
    case 'objc.protocol_property_info': {
        const protocolName = String(spec.protocolName || '');
        const propertyName = String(spec.propertyName || '');
        const propertyInfo = ObjC.protocolPropertyInfo(protocolName, propertyName);
        const normalized = propertyInfo === null ? null : normalizeObjcProtocolPropertyInfo(propertyInfo);
        return {
            kind: 'objc.protocol_property_info',
            protocolName,
            propertyName,
            propertyInfo: normalized,
            text: normalized === null ? '<null>' : normalized.text,
        };
    }
    case 'objc.superclass': {
        const className = String(spec.className || '');
        const superclass = ObjC.superclass(className);
        const normalized = superclass === null ? null : String(superclass);
        return {
            kind: 'objc.superclass',
            className,
            superclass: normalized,
            hasSuperclass: normalized !== null,
            isRootClass: normalized === null,
            text: normalized === null ? '<null>' : normalized,
        };
    }
    case 'objc.class_chain': {
        const className = String(spec.className || '');
        const chain = ObjC.classChain(className).map((name) => String(name));
        const rootClass = chain.length === 0 ? null : chain[chain.length - 1];
        return {
            kind: 'objc.class_chain',
            className,
            count: chain.length,
            depth: chain.length,
            hasChain: chain.length !== 0,
            includesSelf: chain.length !== 0 && chain[0] === className,
            rootClass,
            chain,
            text: chain.join('\n'),
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
    case 'objc.method_info': {
        const className = String(spec.className || '');
        const selectorName = String(spec.selectorName || '');
        const isClassMethod = !!spec.isClassMethod;
        const methodInfo = ObjC.methodInfo(className, selectorName, isClassMethod);
        const normalized = methodInfo === null ? null : normalizeObjcMethodInfo(methodInfo);
        return {
            kind: 'objc.method_info',
            className,
            selectorName,
            isClassMethod,
            methodInfo: normalized,
            text: normalized === null ? '<null>' : normalized.text,
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
        const methods = ObjC.methods(className, isClassMethod, filter).map((method) => normalizeObjcMethod(method));
        return {
            kind: 'objc.methods',
            className,
            isClassMethod,
            filter,
            hasFilter: filter !== null && filter.length !== 0,
            count: methods.length,
            hasMethods: methods.length !== 0,
            firstSelector: methods.length === 0 ? null : methods[0].selector,
            lastSelector: methods.length === 0 ? null : methods[methods.length - 1].selector,
            methods,
            text: methods.map((method) => method.text).join('\n'),
        };
    }
    case 'objc.properties': {
        const className = String(spec.className || '');
        const isClassProperty = !!spec.isClassProperty;
        const filter = spec.filter === null || spec.filter === undefined ? null : String(spec.filter);
        const properties = ObjC.properties(className, isClassProperty, filter).map((property) => normalizeObjcProperty(property));
        return {
            kind: 'objc.properties',
            className,
            isClassProperty,
            filter,
            hasFilter: filter !== null && filter.length !== 0,
            count: properties.length,
            hasProperties: properties.length !== 0,
            firstProperty: properties.length === 0 ? null : properties[0].name,
            lastProperty: properties.length === 0 ? null : properties[properties.length - 1].name,
            properties,
            text: properties.map((property) => property.text).join('\n'),
        };
    }
    case 'objc.property_info': {
        const className = String(spec.className || '');
        const propertyName = String(spec.propertyName || '');
        const isClassProperty = !!spec.isClassProperty;
        const propertyInfo = ObjC.propertyInfo(className, propertyName, isClassProperty);
        const normalized = propertyInfo === null ? null : normalizeObjcPropertyInfo(propertyInfo);
        return {
            kind: 'objc.property_info',
            className,
            propertyName,
            isClassProperty,
            propertyInfo: normalized,
            text: normalized === null ? '<null>' : normalized.text,
        };
    }
    case 'objc.ivars': {
        const className = String(spec.className || '');
        const filter = spec.filter === null || spec.filter === undefined ? null : String(spec.filter);
        const ivars = ObjC.ivars(className, filter).map((ivar) => normalizeObjcIvar(ivar));
        return {
            kind: 'objc.ivars',
            className,
            filter,
            hasFilter: filter !== null && filter.length !== 0,
            count: ivars.length,
            hasIvars: ivars.length !== 0,
            firstIvar: ivars.length === 0 ? null : ivars[0].name,
            lastIvar: ivars.length === 0 ? null : ivars[ivars.length - 1].name,
            ivars,
            text: ivars.map((ivar) => ivar.text).join('\n'),
        };
    }
    case 'objc.ivar_info': {
        const className = String(spec.className || '');
        const ivarName = String(spec.ivarName || '');
        const ivarInfo = ObjC.ivarInfo(className, ivarName);
        const normalized = ivarInfo === null ? null : normalizeObjcIvarInfo(ivarInfo);
        return {
            kind: 'objc.ivar_info',
            className,
            ivarName,
            ivarInfo: normalized,
            text: normalized === null ? '<null>' : normalized.text,
        };
    }
    case 'objc.method_owners': {
        const query = String(spec.query || '');
        const isClassMethod = !!spec.isClassMethod;
        const methods = ObjC.methodOwners(query, isClassMethod).map((method) => normalizeObjcMethod(method));
        return {
            kind: 'objc.method_owners',
            query,
            isClassMethod,
            hasQuery: query.length !== 0,
            count: methods.length,
            hasMethods: methods.length !== 0,
            firstOwner: methods.length === 0 ? null : methods[0].className,
            lastOwner: methods.length === 0 ? null : methods[methods.length - 1].className,
            methods,
            text: methods.map((method) => method.text).join('\n'),
        };
    }
    case 'native.images': {
        const filter = spec.filter === null || spec.filter === undefined ? null : String(spec.filter).trim().toLowerCase();
        const images = Native.images(filter).map((image) => normalizeImage(image));
        return {
            kind: 'native.images',
            filter,
            hasFilter: filter !== null && filter.length !== 0,
            count: images.length,
            hasImages: images.length !== 0,
            firstImageName: images.length === 0 ? null : images[0].name,
            lastImageName: images.length === 0 ? null : images[images.length - 1].name,
            images,
            text: images.map((image) => image.text).join('\n'),
        };
    }
    case 'native.base': {
        const moduleName = String(spec.moduleName || '');
        const base = Native.base(moduleName);
        return {
            kind: 'native.base',
            moduleName,
            base: base === null ? null : base.toString(),
            text: base === null ? '<null>' : base.toString(),
        };
    }
    case 'native.image_info': {
        const moduleName = String(spec.moduleName || '');
        const image = Native.imageInfo(moduleName);
        const normalized = image === null ? null : normalizeImage(image);
        return { kind: 'native.image_info', moduleName, image: normalized, text: normalized === null ? '<null>' : normalized.text };
    }
    case 'native.main_image': {
        const imageValue = Native.mainImage();
        const image = imageValue === null ? null : normalizeImage(imageValue);
        return { kind: 'native.main_image', image, text: image === null ? '<null>' : image.text };
    }
    case 'native.image': {
        const address = parseAddressArg(spec.address, 'native.image usage: native.image <address>');
        const image = Native.image(address);
        const normalized = image === null ? null : normalizeImage(image);
        return { kind: 'native.image', address: address.toString(), image: normalized, text: normalized === null ? '<null>' : normalized.text };
    }
    case 'native.symbol': {
        const address = parseAddressArg(spec.address, 'native.symbol usage: native.symbol <address>');
        const symbol = normalizeDebugSymbol(Native.symbol(address), address);
        return { kind: 'native.symbol', address: address.toString(), symbol, text: symbol.text };
    }
    case 'native.export': {
        const moduleName = spec.moduleName === null || spec.moduleName === undefined ? null : String(spec.moduleName);
        const symbolName = String(spec.symbolName || '');
        const address = Native.export(moduleName, symbolName);
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
        const symbols = Native.symbols(query, moduleName).map((symbol) => normalizeNativeSymbol(symbol));
        return {
            kind: 'native.symbols',
            moduleName,
            query,
            hasQuery: query.length !== 0,
            count: symbols.length,
            hasSymbols: symbols.length !== 0,
            firstSymbolName: symbols.length === 0 ? null : symbols[0].name,
            lastSymbolName: symbols.length === 0 ? null : symbols[symbols.length - 1].name,
            symbols,
            text: symbols.map((symbol) => symbol.text).join('\n'),
        };
    }
    case 'native.symbol_info': {
        const moduleName = spec.moduleName === null || spec.moduleName === undefined ? null : String(spec.moduleName);
        const symbolName = String(spec.symbolName || '');
        const symbolInfo = Native.symbolInfo(symbolName, moduleName);
        const normalized = symbolInfo === null ? null : normalizeNativeSymbol(symbolInfo);
        return {
            kind: 'native.symbol_info',
            moduleName,
            symbolName,
            symbolInfo: normalized,
            text: normalized === null ? '<null>' : normalized.text,
        };
    }
    case 'native.exports': {
        const moduleName = String(spec.moduleName || '');
        const query = spec.query === null || spec.query === undefined ? null : String(spec.query);
        const symbols = Native.exports(moduleName, query).map((symbol) => normalizeNativeSymbol(symbol));
        return {
            kind: 'native.exports',
            moduleName,
            query,
            hasQuery: query !== null && query.length !== 0,
            count: symbols.length,
            hasSymbols: symbols.length !== 0,
            firstSymbolName: symbols.length === 0 ? null : symbols[0].name,
            lastSymbolName: symbols.length === 0 ? null : symbols[symbols.length - 1].name,
            symbols,
            text: symbols.map((symbol) => symbol.text).join('\n'),
        };
    }
    case 'native.export_info': {
        const moduleName = String(spec.moduleName || '');
        const symbolName = String(spec.symbolName || '');
        const exportInfo = Native.exportInfo(moduleName, symbolName);
        const normalized = exportInfo === null ? null : normalizeNativeSymbol(exportInfo);
        return {
            kind: 'native.export_info',
            moduleName,
            symbolName,
            exportInfo: normalized,
            text: normalized === null ? '<null>' : normalized.text,
        };
    }
    case 'native.dependencies': {
        const moduleName = String(spec.moduleName || '');
        const query = spec.query === null || spec.query === undefined ? null : String(spec.query);
        const dependencies = Native.dependencies(moduleName, query).map((dependency) => normalizeDependency(dependency));
        return {
            kind: 'native.dependencies',
            moduleName,
            query,
            hasQuery: query !== null && query.length !== 0,
            count: dependencies.length,
            hasDependencies: dependencies.length !== 0,
            firstDependencyName: dependencies.length === 0 ? null : dependencies[0].name,
            lastDependencyName: dependencies.length === 0 ? null : dependencies[dependencies.length - 1].name,
            dependencies,
            text: dependencies.map((dependency) => dependency.text).join('\n'),
        };
    }
    case 'native.dependency_info': {
        const moduleName = String(spec.moduleName || '');
        const pathOrName = String(spec.pathOrName || '');
        const dependencyInfo = Native.dependencyInfo(moduleName, pathOrName);
        const normalized = dependencyInfo === null ? null : normalizeDependency(dependencyInfo);
        return {
            kind: 'native.dependency_info',
            moduleName,
            pathOrName,
            dependencyInfo: normalized,
            text: normalized === null ? '<null>' : normalized.text,
        };
    }
    case 'native.encryption_info': {
        const moduleName = String(spec.moduleName || '');
        const encryptionInfo = Native.encryptionInfo(moduleName);
        const normalized = encryptionInfo === null ? null : normalizeEncryptionInfo(encryptionInfo);
        return { kind: 'native.encryption_info', moduleName, encryptionInfo: normalized, text: normalized === null ? '<null>' : normalized.text };
    }
    case 'native.entry_point': {
        const moduleName = String(spec.moduleName || '');
        const entryPoint = Native.entryPoint(moduleName);
        const normalized = entryPoint === null ? null : normalizeEntryPoint(entryPoint);
        return { kind: 'native.entry_point', moduleName, entryPoint: normalized, text: normalized === null ? '<null>' : normalized.text };
    }
    case 'native.dyld_info': {
        const moduleName = String(spec.moduleName || '');
        const dyldInfo = Native.dyldInfo(moduleName);
        const normalized = dyldInfo === null ? null : normalizeDyldInfo(dyldInfo);
        return { kind: 'native.dyld_info', moduleName, dyldInfo: normalized, text: normalized === null ? '<null>' : normalized.text };
    }
    case 'native.linkedit': {
        const moduleName = String(spec.moduleName || '');
        const linkedit = Native.linkedit(moduleName);
        const normalized = linkedit === null ? null : normalizeLinkedit(linkedit);
        return { kind: 'native.linkedit', moduleName, linkedit: normalized, text: normalized === null ? '<null>' : normalized.text };
    }
    case 'native.function_starts': {
        const moduleName = String(spec.moduleName || '');
        const functionStarts = Native.functionStarts(moduleName);
        const normalized = functionStarts === null ? null : normalizeFunctionStarts(functionStarts);
        return { kind: 'native.function_starts', moduleName, functionStarts: normalized, text: normalized === null ? '<null>' : normalized.text };
    }
    case 'native.code_signature': {
        const moduleName = String(spec.moduleName || '');
        const codeSignature = Native.codeSignature(moduleName);
        const normalized = codeSignature === null ? null : normalizeCodeSignature(codeSignature);
        return { kind: 'native.code_signature', moduleName, codeSignature: normalized, text: normalized === null ? '<null>' : normalized.text };
    }
    case 'native.data_in_code': {
        const moduleName = String(spec.moduleName || '');
        const dataInCode = Native.dataInCode(moduleName);
        const normalized = dataInCode === null ? null : normalizeDataInCode(dataInCode);
        return { kind: 'native.data_in_code', moduleName, dataInCode: normalized, text: normalized === null ? '<null>' : normalized.text };
    }
    case 'native.exports_trie': {
        const moduleName = String(spec.moduleName || '');
        const exportsTrie = Native.exportsTrie(moduleName);
        const normalized = exportsTrie === null ? null : normalizeExportsTrie(exportsTrie);
        return { kind: 'native.exports_trie', moduleName, exportsTrie: normalized, text: normalized === null ? '<null>' : normalized.text };
    }
    case 'native.chained_fixups': {
        const moduleName = String(spec.moduleName || '');
        const chainedFixups = Native.chainedFixups(moduleName);
        const normalized = chainedFixups === null ? null : normalizeChainedFixups(chainedFixups);
        return { kind: 'native.chained_fixups', moduleName, chainedFixups: normalized, text: normalized === null ? '<null>' : normalized.text };
    }
    case 'native.source_version': {
        const moduleName = String(spec.moduleName || '');
        const sourceVersion = Native.sourceVersion(moduleName);
        const normalized = sourceVersion === null ? null : normalizeSourceVersion(sourceVersion);
        return { kind: 'native.source_version', moduleName, sourceVersion: normalized, text: normalized === null ? '<null>' : normalized.text };
    }
    case 'native.build_version': {
        const moduleName = String(spec.moduleName || '');
        const buildVersion = Native.buildVersion(moduleName);
        const normalized = buildVersion === null ? null : normalizeBuildVersion(buildVersion);
        return { kind: 'native.build_version', moduleName, buildVersion: normalized, text: normalized === null ? '<null>' : normalized.text };
    }
    case 'native.dylinker': {
        const moduleName = String(spec.moduleName || '');
        const dylinker = Native.dylinker(moduleName);
        const normalized = dylinker === null ? null : normalizeDylinker(dylinker);
        return { kind: 'native.dylinker', moduleName, dylinker: normalized, text: normalized === null ? '<null>' : normalized.text };
    }
    case 'native.install_name': {
        const moduleName = String(spec.moduleName || '');
        const installName = Native.installName(moduleName);
        const normalized = installName === null ? null : normalizeInstallName(installName);
        return { kind: 'native.install_name', moduleName, installName: normalized, text: normalized === null ? '<null>' : normalized.text };
    }
    case 'native.uuid': {
        const moduleName = String(spec.moduleName || '');
        const imageUuid = Native.uuid(moduleName);
        const normalized = imageUuid === null ? null : normalizeUuid(imageUuid);
        return { kind: 'native.uuid', moduleName, imageUuid: normalized, text: normalized === null ? '<null>' : normalized.text };
    }
    case 'native.rpaths': {
        const moduleName = String(spec.moduleName || '');
        const query = spec.query === null || spec.query === undefined ? null : String(spec.query);
        const rpaths = Native.rpaths(moduleName, query).map((rpath) => normalizeRpath(rpath));
        return {
            kind: 'native.rpaths',
            moduleName,
            query,
            hasQuery: query !== null && query.length !== 0,
            count: rpaths.length,
            hasRpaths: rpaths.length !== 0,
            firstRpath: rpaths.length === 0 ? null : rpaths[0].path,
            lastRpath: rpaths.length === 0 ? null : rpaths[rpaths.length - 1].path,
            rpaths,
            text: rpaths.map((rpath) => rpath.text).join('\n'),
        };
    }
    case 'native.rpath_info': {
        const moduleName = String(spec.moduleName || '');
        const path = String(spec.path || '');
        const rpathInfo = Native.rpathInfo(moduleName, path);
        const normalized = rpathInfo === null ? null : normalizeRpath(rpathInfo);
        return {
            kind: 'native.rpath_info',
            moduleName,
            path,
            rpathInfo: normalized,
            text: normalized === null ? '<null>' : normalized.text,
        };
    }
    case 'native.imports': {
        const moduleName = String(spec.moduleName || '');
        const query = spec.query === null || spec.query === undefined ? null : String(spec.query);
        const imports = Native.imports(moduleName, query).map((imp) => normalizeImport(imp));
        return {
            kind: 'native.imports',
            moduleName,
            query,
            hasQuery: query !== null && query.length !== 0,
            count: imports.length,
            hasImports: imports.length !== 0,
            firstImportName: imports.length === 0 ? null : imports[0].name,
            lastImportName: imports.length === 0 ? null : imports[imports.length - 1].name,
            imports,
            text: imports.map((imp) => imp.text).join('\n'),
        };
    }
    case 'native.import_info': {
        const moduleName = String(spec.moduleName || '');
        const symbolName = String(spec.symbolName || '');
        const importInfo = Native.importInfo(moduleName, symbolName);
        const normalized = importInfo === null ? null : normalizeImport(importInfo);
        return {
            kind: 'native.import_info',
            moduleName,
            symbolName,
            importInfo: normalized,
            text: normalized === null ? '<null>' : normalized.text,
        };
    }
    case 'native.segments': {
        const moduleName = String(spec.moduleName || '');
        const segments = Native.segments(moduleName).map((segment) => normalizeSegment(segment));
        return {
            kind: 'native.segments',
            moduleName,
            count: segments.length,
            hasSegments: segments.length !== 0,
            firstSegmentName: segments.length === 0 ? null : segments[0].name,
            lastSegmentName: segments.length === 0 ? null : segments[segments.length - 1].name,
            segments,
            text: segments.map((segment) => segment.text).join('\n'),
        };
    }
    case 'native.segment_info': {
        const moduleName = String(spec.moduleName || '');
        const segmentName = String(spec.segmentName || '');
        const segmentInfo = Native.segmentInfo(moduleName, segmentName);
        const normalized = segmentInfo === null ? null : normalizeSegment(segmentInfo);
        return {
            kind: 'native.segment_info',
            moduleName,
            segmentName,
            segmentInfo: normalized,
            text: normalized === null ? '<null>' : normalized.text,
        };
    }
    case 'native.sections': {
        const moduleName = String(spec.moduleName || '');
        const sections = Native.sections(moduleName).map((section) => normalizeSection(section));
        return {
            kind: 'native.sections',
            moduleName,
            count: sections.length,
            hasSections: sections.length !== 0,
            firstSectionName: sections.length === 0 ? null : sections[0].name,
            lastSectionName: sections.length === 0 ? null : sections[sections.length - 1].name,
            sections,
            text: sections.map((section) => section.text).join('\n'),
        };
    }
    case 'native.section_info': {
        const moduleName = String(spec.moduleName || '');
        const segmentName = String(spec.segmentName || '');
        const sectionName = String(spec.sectionName || '');
        const sectionInfo = Native.sectionInfo(moduleName, segmentName, sectionName);
        const normalized = sectionInfo === null ? null : normalizeSection(sectionInfo);
        return {
            kind: 'native.section_info',
            moduleName,
            segmentName,
            sectionName,
            sectionInfo: normalized,
            text: normalized === null ? '<null>' : normalized.text,
        };
    }
    case 'native.load_commands': {
        const moduleName = String(spec.moduleName || '');
        const commands = Native.loadCommands(moduleName).map((command) => normalizeLoadCommand(command));
        return {
            kind: 'native.load_commands',
            moduleName,
            count: commands.length,
            hasCommands: commands.length !== 0,
            firstCommandName: commands.length === 0 ? null : commands[0].name,
            lastCommandName: commands.length === 0 ? null : commands[commands.length - 1].name,
            commands,
            text: commands.map((command) => command.text).join('\n'),
        };
    }
    case 'native.load_command_info': {
        const moduleName = String(spec.moduleName || '');
        const commandOrIndex = String(spec.commandOrIndex || '');
        const loadCommandInfo = Native.loadCommandInfo(moduleName, commandOrIndex);
        const normalized = loadCommandInfo === null ? null : normalizeLoadCommand(loadCommandInfo);
        return {
            kind: 'native.load_command_info',
            moduleName,
            commandOrIndex,
            loadCommandInfo: normalized,
            text: normalized === null ? '<null>' : normalized.text,
        };
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
        return {
            kind: 'pac.images',
            filter,
            hasFilter: filter !== null && filter.length !== 0,
            count: images.length,
            hasImages: images.length !== 0,
            firstImageName: images.length === 0 ? null : images[0].name,
            lastImageName: images.length === 0 ? null : images[images.length - 1].name,
            images,
            text: images.map((image) => image.text).join('\n'),
        };
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
        const symbols = Swift.symbols(query, moduleName).map((symbol) => normalizeSwiftSymbol(symbol));
        return {
            kind: 'swift.symbols',
            moduleName,
            query,
            hasQuery: query.length !== 0,
            count: symbols.length,
            hasSymbols: symbols.length !== 0,
            firstSymbolName: symbols.length === 0 ? null : symbols[0].name,
            lastSymbolName: symbols.length === 0 ? null : symbols[symbols.length - 1].name,
            symbols,
            text: symbols.map((symbol) => symbol.text).join('\n'),
        };
    }
    case 'swift.symbol_info': {
        const moduleName = spec.moduleName === null || spec.moduleName === undefined ? null : String(spec.moduleName);
        const symbolName = String(spec.symbolName || '');
        const symbolInfo = Swift.symbolInfo(symbolName, moduleName);
        const normalized = symbolInfo === null ? null : normalizeSwiftSymbol(symbolInfo);
        return {
            kind: 'swift.symbol_info',
            moduleName,
            symbolName,
            symbolInfo: normalized,
            text: normalized === null ? '<null>' : normalized.text,
        };
    }
    case 'swift.protocol_info': {
        const moduleName = spec.moduleName === null || spec.moduleName === undefined ? null : String(spec.moduleName);
        const protocolName = String(spec.protocolName || '');
        const protocolInfo = Swift.protocolInfo(protocolName, moduleName);
        const normalized = protocolInfo === null ? null : normalizeSwiftProtocol(protocolInfo);
        return {
            kind: 'swift.protocol_info',
            moduleName,
            protocolName,
            protocolInfo: normalized,
            text: normalized === null ? '<null>' : normalized.text,
        };
    }
    case 'swift.conformance_info': {
        const moduleName = spec.moduleName === null || spec.moduleName === undefined ? null : String(spec.moduleName);
        const typeName = String(spec.typeName || '');
        const protocolName = String(spec.protocolName || '');
        const conformanceInfo = Swift.conformanceInfo(typeName, protocolName, moduleName);
        const normalized = conformanceInfo === null ? null : normalizeSwiftConformance(conformanceInfo);
        return {
            kind: 'swift.conformance_info',
            moduleName,
            typeName,
            protocolName,
            conformanceInfo: normalized,
            text: normalized === null ? '<null>' : normalized.text,
        };
    }
    case 'swift.protocols': {
        const moduleName = spec.moduleName === null || spec.moduleName === undefined ? null : String(spec.moduleName);
        const query = spec.query === null || spec.query === undefined ? null : String(spec.query);
        const protocols = Swift.protocols(query, moduleName).map((protocolInfo) => normalizeSwiftProtocol(protocolInfo));
        return {
            kind: 'swift.protocols',
            moduleName,
            query,
            hasQuery: query !== null && query.length !== 0,
            count: protocols.length,
            hasProtocols: protocols.length !== 0,
            firstProtocol: protocols.length === 0 ? null : protocols[0].name,
            lastProtocol: protocols.length === 0 ? null : protocols[protocols.length - 1].name,
            protocols,
            text: protocols.map((protocolInfo) => protocolInfo.text).join('\n'),
        };
    }
    case 'swift.conformances': {
        const moduleName = spec.moduleName === null || spec.moduleName === undefined ? null : String(spec.moduleName);
        const query = String(spec.query || '');
        const conformances = Swift.conformances(query, moduleName).map((conformance) => normalizeSwiftConformance(conformance));
        return {
            kind: 'swift.conformances',
            moduleName,
            query,
            hasQuery: query.length !== 0,
            count: conformances.length,
            hasConformances: conformances.length !== 0,
            firstTypeName: conformances.length === 0 ? null : conformances[0].typeName,
            lastTypeName: conformances.length === 0 ? null : conformances[conformances.length - 1].typeName,
            conformances,
            text: conformances.map((conformance) => conformance.text).join('\n'),
        };
    }
    case 'swift.metadata': {
        const moduleName = spec.moduleName === null || spec.moduleName === undefined ? null : String(spec.moduleName);
        const query = String(spec.query || '');
        const metadata = Swift.metadata(query, moduleName).map((typeInfo) => normalizeSwiftType(typeInfo));
        return {
            kind: 'swift.metadata',
            moduleName,
            query,
            hasQuery: query.length !== 0,
            count: metadata.length,
            hasMetadata: metadata.length !== 0,
            firstTypeName: metadata.length === 0 ? null : metadata[0].name,
            lastTypeName: metadata.length === 0 ? null : metadata[metadata.length - 1].name,
            metadata,
            text: metadata.map((typeInfo) => typeInfo.text).join('\n'),
        };
    }
    case 'swift.metadata_info': {
        const moduleName = spec.moduleName === null || spec.moduleName === undefined ? null : String(spec.moduleName);
        const typeName = String(spec.typeName || '');
        const metadataInfo = Swift.metadataInfo(typeName, moduleName);
        const normalized = metadataInfo === null ? null : normalizeSwiftType(metadataInfo);
        return {
            kind: 'swift.metadata_info',
            moduleName,
            typeName,
            metadataInfo: normalized,
            text: normalized === null ? '<null>' : normalized.text,
        };
    }
    case 'swift.type_info': {
        const moduleName = spec.moduleName === null || spec.moduleName === undefined ? null : String(spec.moduleName);
        const typeName = String(spec.typeName || '');
        const typeInfo = Swift.typeInfo(typeName, moduleName);
        const normalized = typeInfo === null ? null : normalizeSwiftType(typeInfo);
        return {
            kind: 'swift.type_info',
            moduleName,
            typeName,
            typeInfo: normalized,
            text: normalized === null ? '<null>' : normalized.text,
        };
    }
    case 'swift.method_info': {
        const moduleName = spec.moduleName === null || spec.moduleName === undefined ? null : String(spec.moduleName);
        const typeName = String(spec.typeName || '');
        const methodName = String(spec.methodName || '');
        const methodInfo = Swift.methodInfo(typeName, methodName, moduleName);
        const normalized = methodInfo === null ? null : normalizeSwiftSymbol(methodInfo);
        return {
            kind: 'swift.method_info',
            moduleName,
            typeName,
            methodName,
            methodInfo: normalized,
            text: normalized === null ? '<null>' : normalized.text,
        };
    }
    case 'swift.vtable': {
        const moduleName = spec.moduleName === null || spec.moduleName === undefined ? null : String(spec.moduleName);
        const query = String(spec.query || '');
        const entries = Swift.vtable(query, moduleName).map((entry) => normalizeSwiftVtableEntry(entry));
        return {
            kind: 'swift.vtable',
            moduleName,
            query,
            hasQuery: query.length !== 0,
            count: entries.length,
            hasEntries: entries.length !== 0,
            firstMemberName: entries.length === 0 ? null : entries[0].memberName,
            lastMemberName: entries.length === 0 ? null : entries[entries.length - 1].memberName,
            entries,
            text: entries.map((entry) => entry.text).join('\n'),
        };
    }
    case 'swift.vtable_info': {
        const moduleName = spec.moduleName === null || spec.moduleName === undefined ? null : String(spec.moduleName);
        const typeName = String(spec.typeName || '');
        const memberName = String(spec.memberName || '');
        const vtableInfo = Swift.vtableInfo(typeName, memberName, moduleName);
        const normalized = vtableInfo === null ? null : normalizeSwiftVtableEntry(vtableInfo);
        return {
            kind: 'swift.vtable_info',
            moduleName,
            typeName,
            memberName,
            vtableInfo: normalized,
            text: normalized === null ? '<null>' : normalized.text,
        };
    }
    case 'swift.witness_table': {
        const moduleName = spec.moduleName === null || spec.moduleName === undefined ? null : String(spec.moduleName);
        const query = String(spec.query || '');
        const entries = Swift.witnessTable(query, moduleName).map((entry) => normalizeSwiftWitnessTable(entry));
        return {
            kind: 'swift.witness_table',
            moduleName,
            query,
            hasQuery: query.length !== 0,
            count: entries.length,
            hasEntries: entries.length !== 0,
            firstProtocolName: entries.length === 0 ? null : entries[0].protocolName,
            lastProtocolName: entries.length === 0 ? null : entries[entries.length - 1].protocolName,
            entries,
            text: entries.map((entry) => entry.text).join('\n'),
        };
    }
    case 'swift.witness_table_info': {
        const moduleName = spec.moduleName === null || spec.moduleName === undefined ? null : String(spec.moduleName);
        const typeName = String(spec.typeName || '');
        const protocolName = String(spec.protocolName || '');
        const witnessTableInfo = Swift.witnessTableInfo(typeName, protocolName, moduleName);
        const normalized = witnessTableInfo === null ? null : normalizeSwiftWitnessTable(witnessTableInfo);
        return {
            kind: 'swift.witness_table_info',
            moduleName,
            typeName,
            protocolName,
            witnessTableInfo: normalized,
            text: normalized === null ? '<null>' : normalized.text,
        };
    }
    case 'swift.type_layout': {
        const moduleName = spec.moduleName === null || spec.moduleName === undefined ? null : String(spec.moduleName);
        const query = String(spec.query || '');
        const layouts = Swift.typeLayout(query, moduleName).map((layout) => normalizeSwiftTypeLayout(layout));
        return {
            kind: 'swift.type_layout',
            moduleName,
            query,
            hasQuery: query.length !== 0,
            count: layouts.length,
            hasLayouts: layouts.length !== 0,
            firstTypeName: layouts.length === 0 ? null : layouts[0].name,
            lastTypeName: layouts.length === 0 ? null : layouts[layouts.length - 1].name,
            layouts,
            text: layouts.map((layout) => layout.text).join('\n'),
        };
    }
    case 'swift.type_layout_info': {
        const moduleName = spec.moduleName === null || spec.moduleName === undefined ? null : String(spec.moduleName);
        const typeName = String(spec.typeName || '');
        const typeLayout = Swift.typeLayoutInfo(typeName, moduleName);
        const normalized = typeLayout === null ? null : normalizeSwiftTypeLayout(typeLayout);
        return {
            kind: 'swift.type_layout_info',
            moduleName,
            typeName,
            typeLayout: normalized,
            text: normalized === null ? '<null>' : normalized.text,
        };
    }
    case 'swift.types': {
        const moduleName = spec.moduleName === null || spec.moduleName === undefined ? null : String(spec.moduleName);
        const query = String(spec.query || '');
        const types = Swift.types(query, moduleName).map((typeInfo) => normalizeSwiftType(typeInfo));
        return {
            kind: 'swift.types',
            moduleName,
            query,
            hasQuery: query.length !== 0,
            count: types.length,
            hasTypes: types.length !== 0,
            firstTypeName: types.length === 0 ? null : types[0].name,
            lastTypeName: types.length === 0 ? null : types[types.length - 1].name,
            types,
            text: types.map((typeInfo) => typeInfo.text).join('\n'),
        };
    }
    case 'swift.type_kinds': {
        const kinds = Swift.typeKinds();
        return {
            kind: 'swift.type_kinds',
            count: kinds.length,
            hasKinds: kinds.length !== 0,
            firstKind: kinds.length === 0 ? null : kinds[0],
            lastKind: kinds.length === 0 ? null : kinds[kinds.length - 1],
            kinds,
            text: kinds.join('\n'),
        };
    }
    case 'swift.types_of_kind': {
        const moduleName = spec.moduleName === null || spec.moduleName === undefined ? null : String(spec.moduleName);
        const sourceKind = String(spec.sourceKind || '');
        const query = String(spec.query || '');
        const types = Swift.typesOfKind(sourceKind, query, moduleName).map((typeInfo) => normalizeSwiftType(typeInfo));
        return {
            kind: 'swift.types_of_kind',
            moduleName,
            sourceKind,
            query,
            hasQuery: query.length !== 0,
            count: types.length,
            hasTypes: types.length !== 0,
            firstTypeName: types.length === 0 ? null : types[0].name,
            lastTypeName: types.length === 0 ? null : types[types.length - 1].name,
            types,
            text: types.map((typeInfo) => typeInfo.text).join('\n'),
        };
    }
    case 'swift.method_owners': {
        const moduleName = spec.moduleName === null || spec.moduleName === undefined ? null : String(spec.moduleName);
        const query = String(spec.query || '');
        const owners = Swift.methodOwners(query, moduleName).map((typeInfo) => normalizeSwiftType(typeInfo));
        return {
            kind: 'swift.method_owners',
            moduleName,
            query,
            hasQuery: query.length !== 0,
            count: owners.length,
            hasOwners: owners.length !== 0,
            firstOwnerName: owners.length === 0 ? null : owners[0].name,
            lastOwnerName: owners.length === 0 ? null : owners[owners.length - 1].name,
            owners,
            text: owners.map((typeInfo) => typeInfo.text).join('\n'),
        };
    }
    case 'swift.type_methods': {
        const moduleName = spec.moduleName === null || spec.moduleName === undefined ? null : String(spec.moduleName);
        const query = String(spec.query || '');
        const methods = Swift.typeMethods(query, moduleName).map((symbol) => normalizeSwiftSymbol(symbol));
        return {
            kind: 'swift.type_methods',
            moduleName,
            query,
            hasQuery: query.length !== 0,
            count: methods.length,
            hasMethods: methods.length !== 0,
            firstMethodName: methods.length === 0 ? null : methods[0].name,
            lastMethodName: methods.length === 0 ? null : methods[methods.length - 1].name,
            methods,
            text: methods.map((symbol) => symbol.text).join('\n'),
        };
    }
    case 'swift.methods': {
        const moduleName = spec.moduleName === null || spec.moduleName === undefined ? null : String(spec.moduleName);
        const typeName = String(spec.typeName || '');
        const methodQuery = String(spec.methodQuery || '');
        const methods = Swift.methods(typeName, methodQuery, moduleName).map((symbol) => normalizeSwiftSymbol(symbol));
        return {
            kind: 'swift.methods',
            moduleName,
            typeName,
            methodQuery,
            hasMethodQuery: methodQuery.length !== 0,
            count: methods.length,
            hasMethods: methods.length !== 0,
            firstMethodName: methods.length === 0 ? null : methods[0].name,
            lastMethodName: methods.length === 0 ? null : methods[methods.length - 1].name,
            methods,
            text: methods.map((symbol) => symbol.text).join('\n'),
        };
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

    if (trimmed.startsWith('objc.findClasses ')) {
        return { kind: 'objc.classes', filter: trimmed.slice('objc.findClasses '.length) };
    }

    if (trimmed === 'objc.protocols') {
        return { kind: 'objc.protocols', filter: null };
    }

    if (trimmed.startsWith('objc.protocols ')) {
        return { kind: 'objc.protocols', filter: trimmed.slice('objc.protocols '.length) };
    }

    if (trimmed.startsWith('objc.findProtocols ')) {
        return { kind: 'objc.protocols', filter: trimmed.slice('objc.findProtocols '.length) };
    }

    if (trimmed.startsWith('objc.classProtocols ')) {
        const parsed = parseObjcClassProtocols(trimmed.slice('objc.classProtocols '.length));
        return { kind: 'objc.class_protocols', className: parsed.className, filter: parsed.filter };
    }

    if (trimmed.startsWith('objc.classInfo ')) {
        const parsed = parseObjcClassInfo(trimmed.slice('objc.classInfo '.length));
        return { kind: 'objc.class_info', className: parsed.className, isMetaClass: parsed.isMetaClass };
    }

    if (trimmed.startsWith('objc.protocolInfo ')) {
        const parsed = parseObjcProtocolInfo(trimmed.slice('objc.protocolInfo '.length));
        return { kind: 'objc.protocol_info', protocolName: parsed.protocolName };
    }

    if (trimmed.startsWith('objc.protocolProtocols ')) {
        const parsed = parseObjcProtocolProtocols(trimmed.slice('objc.protocolProtocols '.length));
        return { kind: 'objc.protocol_protocols', protocolName: parsed.protocolName, filter: parsed.filter };
    }

    if (trimmed.startsWith('objc.protocolMethods ')) {
        const parsed = parseObjcProtocolMethods(trimmed.slice('objc.protocolMethods '.length));
        return {
            kind: 'objc.protocol_methods',
            protocolName: parsed.protocolName,
            isRequired: parsed.isRequired,
            isInstanceMethod: parsed.isInstanceMethod,
            filter: parsed.filter,
        };
    }

    if (trimmed.startsWith('objc.protocolMethodInfo ')) {
        const parsed = parseObjcProtocolMethodInfo(trimmed.slice('objc.protocolMethodInfo '.length));
        return {
            kind: 'objc.protocol_method_info',
            protocolName: parsed.protocolName,
            selectorName: parsed.selectorName,
            isRequired: parsed.isRequired,
            isInstanceMethod: parsed.isInstanceMethod,
        };
    }

    if (trimmed.startsWith('objc.protocolProperties ')) {
        const parsed = parseObjcProtocolProperties(trimmed.slice('objc.protocolProperties '.length));
        return {
            kind: 'objc.protocol_properties',
            protocolName: parsed.protocolName,
            filter: parsed.filter,
        };
    }

    if (trimmed.startsWith('objc.protocolPropertyInfo ')) {
        const parsed = parseObjcProtocolPropertyInfo(trimmed.slice('objc.protocolPropertyInfo '.length));
        return {
            kind: 'objc.protocol_property_info',
            protocolName: parsed.protocolName,
            propertyName: parsed.propertyName,
        };
    }

    if (trimmed.startsWith('objc.superclass ')) {
        return { kind: 'objc.superclass', className: trimmed.slice('objc.superclass '.length) };
    }

    if (trimmed.startsWith('objc.classChain ')) {
        return { kind: 'objc.class_chain', className: trimmed.slice('objc.classChain '.length) };
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

    if (trimmed.startsWith('objc.methodInfo ')) {
        const parsed = parseObjcMethodImp(trimmed.slice('objc.methodInfo '.length));
        return {
            kind: 'objc.method_info',
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

    if (trimmed.startsWith('objc.findMethods ')) {
        const parsed = parseObjcFindMethods(trimmed.slice('objc.findMethods '.length));
        return {
            kind: 'objc.methods',
            className: parsed.className,
            isClassMethod: parsed.isClassMethod,
            filter: parsed.filter,
        };
    }

    if (trimmed.startsWith('objc.properties ')) {
        const parsed = parseObjcProperties(trimmed.slice('objc.properties '.length));
        return {
            kind: 'objc.properties',
            className: parsed.className,
            isClassProperty: parsed.isClassProperty,
            filter: parsed.filter,
        };
    }

    if (trimmed.startsWith('objc.findProperties ')) {
        const parsed = parseObjcFindProperties(trimmed.slice('objc.findProperties '.length));
        return {
            kind: 'objc.properties',
            className: parsed.className,
            isClassProperty: parsed.isClassProperty,
            filter: parsed.filter,
        };
    }

    if (trimmed.startsWith('objc.propertyInfo ')) {
        const parsed = parseObjcPropertyInfo(trimmed.slice('objc.propertyInfo '.length));
        return {
            kind: 'objc.property_info',
            className: parsed.className,
            propertyName: parsed.propertyName,
            isClassProperty: parsed.isClassProperty,
        };
    }

    if (trimmed.startsWith('objc.ivars ')) {
        const parsed = parseObjcIvars(trimmed.slice('objc.ivars '.length));
        return {
            kind: 'objc.ivars',
            className: parsed.className,
            filter: parsed.filter,
        };
    }

    if (trimmed.startsWith('objc.findIvars ')) {
        const parsed = parseObjcFindIvars(trimmed.slice('objc.findIvars '.length));
        return {
            kind: 'objc.ivars',
            className: parsed.className,
            filter: parsed.filter,
        };
    }

    if (trimmed.startsWith('objc.ivarInfo ')) {
        const parsed = parseObjcIvarInfo(trimmed.slice('objc.ivarInfo '.length));
        return {
            kind: 'objc.ivar_info',
            className: parsed.className,
            ivarName: parsed.ivarName,
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

    if (trimmed.startsWith('objc.findMethodOwners ')) {
        const parsed = parseObjcMethodOwners(trimmed.slice('objc.findMethodOwners '.length));
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

    if (trimmed.startsWith('native.imageInfo ')) {
        const moduleName = trimmed.slice('native.imageInfo '.length).trim();
        if (moduleName.length === 0) {
            throw new Error('native.imageInfo usage: native.imageInfo <module>');
        }
        return { kind: 'native.image_info', moduleName };
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

    if (trimmed.startsWith('native.findSymbols ')) {
        const parsed = splitModuleQuery(
            trimmed.slice('native.findSymbols '.length),
            'native.findSymbols usage: native.findSymbols <query> | native.findSymbols <module> -- <query>'
        );
        return {
            kind: 'native.symbols',
            moduleName: parsed.moduleName,
            query: parsed.query,
        };
    }

    if (trimmed.startsWith('native.symbolInfo ')) {
        const parsed = splitModuleQuery(
            trimmed.slice('native.symbolInfo '.length),
            'native.symbolInfo usage: native.symbolInfo <symbol> | native.symbolInfo <module> -- <symbol>'
        );
        return {
            kind: 'native.symbol_info',
            moduleName: parsed.moduleName,
            symbolName: parsed.query,
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

    if (trimmed.startsWith('native.findExports ')) {
        const parsed = parseNativeExports(trimmed.slice('native.findExports '.length));
        return {
            kind: 'native.exports',
            moduleName: parsed.moduleName,
            query: parsed.query,
        };
    }

    if (trimmed.startsWith('native.exportInfo ')) {
        const parsed = parseNativeExports(trimmed.slice('native.exportInfo '.length));
        if (parsed.query === null) {
            throw new Error('native.exportInfo usage: native.exportInfo <module> -- <symbol>');
        }
        return {
            kind: 'native.export_info',
            moduleName: parsed.moduleName,
            symbolName: parsed.query,
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

    if (trimmed.startsWith('native.findDependencies ')) {
        const parsed = parseNativeExports(trimmed.slice('native.findDependencies '.length));
        return {
            kind: 'native.dependencies',
            moduleName: parsed.moduleName,
            query: parsed.query,
        };
    }

    if (trimmed.startsWith('native.dependencyInfo ')) {
        const parsed = parseNativeExports(trimmed.slice('native.dependencyInfo '.length));
        if (parsed.query === null) {
            throw new Error('native.dependencyInfo usage: native.dependencyInfo <module> -- <path-or-name>');
        }
        return {
            kind: 'native.dependency_info',
            moduleName: parsed.moduleName,
            pathOrName: parsed.query,
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

    if (trimmed.startsWith('native.findEncryptionInfo ')) {
        const moduleName = trimmed.slice('native.findEncryptionInfo '.length).trim();
        if (moduleName.length === 0) {
            throw new Error('native.findEncryptionInfo usage: native.findEncryptionInfo <module>');
        }
        return {
            kind: 'native.encryption_info',
            moduleName,
        };
    }

    if (trimmed.startsWith('native.entryPoint ')) {
        const moduleName = trimmed.slice('native.entryPoint '.length).trim();
        if (moduleName.length === 0) {
            throw new Error('native.entryPoint usage: native.entryPoint <module>');
        }
        return {
            kind: 'native.entry_point',
            moduleName,
        };
    }

    if (trimmed.startsWith('native.findEntryPoint ')) {
        const moduleName = trimmed.slice('native.findEntryPoint '.length).trim();
        if (moduleName.length === 0) {
            throw new Error('native.findEntryPoint usage: native.findEntryPoint <module>');
        }
        return {
            kind: 'native.entry_point',
            moduleName,
        };
    }

    if (trimmed.startsWith('native.dyldInfo ')) {
        const moduleName = trimmed.slice('native.dyldInfo '.length).trim();
        if (moduleName.length === 0) {
            throw new Error('native.dyldInfo usage: native.dyldInfo <module>');
        }
        return {
            kind: 'native.dyld_info',
            moduleName,
        };
    }

    if (trimmed.startsWith('native.findDyldInfo ')) {
        const moduleName = trimmed.slice('native.findDyldInfo '.length).trim();
        if (moduleName.length === 0) {
            throw new Error('native.findDyldInfo usage: native.findDyldInfo <module>');
        }
        return {
            kind: 'native.dyld_info',
            moduleName,
        };
    }

    if (trimmed.startsWith('native.linkedit ')) {
        const moduleName = trimmed.slice('native.linkedit '.length).trim();
        if (moduleName.length === 0) {
            throw new Error('native.linkedit usage: native.linkedit <module>');
        }
        return {
            kind: 'native.linkedit',
            moduleName,
        };
    }

    if (trimmed.startsWith('native.findLinkedit ')) {
        const moduleName = trimmed.slice('native.findLinkedit '.length).trim();
        if (moduleName.length === 0) {
            throw new Error('native.findLinkedit usage: native.findLinkedit <module>');
        }
        return {
            kind: 'native.linkedit',
            moduleName,
        };
    }

    if (trimmed.startsWith('native.functionStarts ')) {
        const moduleName = trimmed.slice('native.functionStarts '.length).trim();
        if (moduleName.length === 0) {
            throw new Error('native.functionStarts usage: native.functionStarts <module>');
        }
        return {
            kind: 'native.function_starts',
            moduleName,
        };
    }

    if (trimmed.startsWith('native.findFunctionStarts ')) {
        const moduleName = trimmed.slice('native.findFunctionStarts '.length).trim();
        if (moduleName.length === 0) {
            throw new Error('native.findFunctionStarts usage: native.findFunctionStarts <module>');
        }
        return {
            kind: 'native.function_starts',
            moduleName,
        };
    }

    if (trimmed.startsWith('native.codeSignature ')) {
        const moduleName = trimmed.slice('native.codeSignature '.length).trim();
        if (moduleName.length === 0) {
            throw new Error('native.codeSignature usage: native.codeSignature <module>');
        }
        return {
            kind: 'native.code_signature',
            moduleName,
        };
    }

    if (trimmed.startsWith('native.findCodeSignature ')) {
        const moduleName = trimmed.slice('native.findCodeSignature '.length).trim();
        if (moduleName.length === 0) {
            throw new Error('native.findCodeSignature usage: native.findCodeSignature <module>');
        }
        return {
            kind: 'native.code_signature',
            moduleName,
        };
    }

    if (trimmed.startsWith('native.dataInCode ')) {
        const moduleName = trimmed.slice('native.dataInCode '.length).trim();
        if (moduleName.length === 0) {
            throw new Error('native.dataInCode usage: native.dataInCode <module>');
        }
        return {
            kind: 'native.data_in_code',
            moduleName,
        };
    }

    if (trimmed.startsWith('native.findDataInCode ')) {
        const moduleName = trimmed.slice('native.findDataInCode '.length).trim();
        if (moduleName.length === 0) {
            throw new Error('native.findDataInCode usage: native.findDataInCode <module>');
        }
        return {
            kind: 'native.data_in_code',
            moduleName,
        };
    }

    if (trimmed.startsWith('native.exportsTrie ')) {
        const moduleName = trimmed.slice('native.exportsTrie '.length).trim();
        if (moduleName.length === 0) {
            throw new Error('native.exportsTrie usage: native.exportsTrie <module>');
        }
        return {
            kind: 'native.exports_trie',
            moduleName,
        };
    }

    if (trimmed.startsWith('native.findExportsTrie ')) {
        const moduleName = trimmed.slice('native.findExportsTrie '.length).trim();
        if (moduleName.length === 0) {
            throw new Error('native.findExportsTrie usage: native.findExportsTrie <module>');
        }
        return {
            kind: 'native.exports_trie',
            moduleName,
        };
    }

    if (trimmed.startsWith('native.chainedFixups ')) {
        const moduleName = trimmed.slice('native.chainedFixups '.length).trim();
        if (moduleName.length === 0) {
            throw new Error('native.chainedFixups usage: native.chainedFixups <module>');
        }
        return {
            kind: 'native.chained_fixups',
            moduleName,
        };
    }

    if (trimmed.startsWith('native.findChainedFixups ')) {
        const moduleName = trimmed.slice('native.findChainedFixups '.length).trim();
        if (moduleName.length === 0) {
            throw new Error('native.findChainedFixups usage: native.findChainedFixups <module>');
        }
        return {
            kind: 'native.chained_fixups',
            moduleName,
        };
    }

    if (trimmed.startsWith('native.sourceVersion ')) {
        const moduleName = trimmed.slice('native.sourceVersion '.length).trim();
        if (moduleName.length === 0) {
            throw new Error('native.sourceVersion usage: native.sourceVersion <module>');
        }
        return {
            kind: 'native.source_version',
            moduleName,
        };
    }

    if (trimmed.startsWith('native.findSourceVersion ')) {
        const moduleName = trimmed.slice('native.findSourceVersion '.length).trim();
        if (moduleName.length === 0) {
            throw new Error('native.findSourceVersion usage: native.findSourceVersion <module>');
        }
        return {
            kind: 'native.source_version',
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

    if (trimmed.startsWith('native.findBuildVersion ')) {
        const moduleName = trimmed.slice('native.findBuildVersion '.length).trim();
        if (moduleName.length === 0) {
            throw new Error('native.findBuildVersion usage: native.findBuildVersion <module>');
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

    if (trimmed.startsWith('native.findDylinker ')) {
        const moduleName = trimmed.slice('native.findDylinker '.length).trim();
        if (moduleName.length === 0) {
            throw new Error('native.findDylinker usage: native.findDylinker <module>');
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

    if (trimmed.startsWith('native.findInstallName ')) {
        const moduleName = trimmed.slice('native.findInstallName '.length).trim();
        if (moduleName.length === 0) {
            throw new Error('native.findInstallName usage: native.findInstallName <module>');
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

    if (trimmed.startsWith('native.findUuid ')) {
        const moduleName = trimmed.slice('native.findUuid '.length).trim();
        if (moduleName.length === 0) {
            throw new Error('native.findUuid usage: native.findUuid <module>');
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

    if (trimmed.startsWith('native.findRpaths ')) {
        const parsed = parseNativeExports(trimmed.slice('native.findRpaths '.length));
        return {
            kind: 'native.rpaths',
            moduleName: parsed.moduleName,
            query: parsed.query,
        };
    }

    if (trimmed.startsWith('native.rpathInfo ')) {
        const parsed = parseNativeExports(trimmed.slice('native.rpathInfo '.length));
        if (parsed.query === null) {
            throw new Error('native.rpathInfo usage: native.rpathInfo <module> -- <path>');
        }
        return {
            kind: 'native.rpath_info',
            moduleName: parsed.moduleName,
            path: parsed.query,
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

    if (trimmed.startsWith('native.findImports ')) {
        const parsed = parseNativeExports(trimmed.slice('native.findImports '.length));
        return {
            kind: 'native.imports',
            moduleName: parsed.moduleName,
            query: parsed.query,
        };
    }

    if (trimmed.startsWith('native.importInfo ')) {
        const parsed = parseNativeExports(trimmed.slice('native.importInfo '.length));
        if (parsed.query === null) {
            throw new Error('native.importInfo usage: native.importInfo <module> -- <symbol>');
        }
        return {
            kind: 'native.import_info',
            moduleName: parsed.moduleName,
            symbolName: parsed.query,
        };
    }

    if (trimmed.startsWith('native.segments ')) {
        const parsed = parseNativeExports(trimmed.slice('native.segments '.length));
        if (parsed.query !== null) {
            return {
                kind: 'native.segment_info',
                moduleName: parsed.moduleName,
                segmentName: parsed.query,
            };
        }
        return { kind: 'native.segments', moduleName: parsed.moduleName };
    }

    if (trimmed.startsWith('native.findSegments ')) {
        const parsed = parseNativeExports(trimmed.slice('native.findSegments '.length));
        if (parsed.query !== null) {
            return {
                kind: 'native.segment_info',
                moduleName: parsed.moduleName,
                segmentName: parsed.query,
            };
        }
        return { kind: 'native.segments', moduleName: parsed.moduleName };
    }

    if (trimmed.startsWith('native.segmentInfo ')) {
        const parsed = parseNativeExports(trimmed.slice('native.segmentInfo '.length));
        if (parsed.query === null) {
            throw new Error('native.segmentInfo usage: native.segmentInfo <module> -- <segment>');
        }
        return {
            kind: 'native.segment_info',
            moduleName: parsed.moduleName,
            segmentName: parsed.query,
        };
    }

    if (trimmed.startsWith('native.sections ')) {
        const moduleName = trimmed.slice('native.sections '.length).trim();
        if (moduleName.length === 0) {
            throw new Error('native.sections usage: native.sections <module>');
        }
        return { kind: 'native.sections', moduleName };
    }

    if (trimmed.startsWith('native.findSections ')) {
        const moduleName = trimmed.slice('native.findSections '.length).trim();
        if (moduleName.length === 0) {
            throw new Error('native.findSections usage: native.findSections <module>');
        }
        return { kind: 'native.sections', moduleName };
    }

    if (trimmed.startsWith('native.sectionInfo ')) {
        const parsed = parseNativeSectionInfo(trimmed.slice('native.sectionInfo '.length));
        return {
            kind: 'native.section_info',
            moduleName: parsed.moduleName,
            segmentName: parsed.segmentName,
            sectionName: parsed.sectionName,
        };
    }

    if (trimmed.startsWith('native.loadcmds ')) {
        const moduleName = trimmed.slice('native.loadcmds '.length).trim();
        if (moduleName.length === 0) {
            throw new Error('native.loadcmds usage: native.loadcmds <module>');
        }
        return { kind: 'native.load_commands', moduleName };
    }

    if (trimmed.startsWith('native.findLoadCommands ')) {
        const moduleName = trimmed.slice('native.findLoadCommands '.length).trim();
        if (moduleName.length === 0) {
            throw new Error('native.findLoadCommands usage: native.findLoadCommands <module>');
        }
        return { kind: 'native.load_commands', moduleName };
    }

    if (trimmed.startsWith('native.loadCommandInfo ')) {
        const parsed = parseNativeExports(trimmed.slice('native.loadCommandInfo '.length));
        if (parsed.query === null) {
            throw new Error('native.loadCommandInfo usage: native.loadCommandInfo <module> -- <name|cmd|index>');
        }
        return {
            kind: 'native.load_command_info',
            moduleName: parsed.moduleName,
            commandOrIndex: parsed.query,
        };
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

    if (trimmed.startsWith('swift.findSymbols ')) {
        const usage = 'swift.findSymbols usage: swift.findSymbols <query> | swift.findSymbols <module> -- <query>';
        const parsed = splitModuleQuery(trimmed.slice('swift.findSymbols '.length), usage);
        return {
            kind: 'swift.symbols',
            moduleName: parsed.moduleName,
            query: parsed.query,
        };
    }

    if (trimmed.startsWith('swift.symbolInfo ')) {
        const usage = 'swift.symbolInfo usage: swift.symbolInfo <symbol> | swift.symbolInfo <module> -- <symbol>';
        const parsed = splitModuleQuery(trimmed.slice('swift.symbolInfo '.length), usage);
        return {
            kind: 'swift.symbol_info',
            moduleName: parsed.moduleName,
            symbolName: parsed.query,
        };
    }

    if (trimmed === 'swift.protocols') {
        return { kind: 'swift.protocols', moduleName: null, query: null };
    }

    if (trimmed.startsWith('swift.protocolInfo ')) {
        const usage = 'swift.protocolInfo usage: swift.protocolInfo <protocol> | swift.protocolInfo <module> -- <protocol>';
        const parsed = splitModuleQuery(trimmed.slice('swift.protocolInfo '.length), usage);
        return {
            kind: 'swift.protocol_info',
            moduleName: parsed.moduleName,
            protocolName: parsed.query,
        };
    }

    if (trimmed.startsWith('swift.conformanceInfo ')) {
        const usage = 'swift.conformanceInfo usage: swift.conformanceInfo <type> <protocol> | swift.conformanceInfo <module> -- <type> <protocol>';
        const parsed = splitModuleQuery(trimmed.slice('swift.conformanceInfo '.length), usage);
        const parts = parsed.query.split(/\s+/).filter(Boolean);
        if (parts.length < 2) {
            throw new Error(usage);
        }
        return {
            kind: 'swift.conformance_info',
            moduleName: parsed.moduleName,
            typeName: parts[0],
            protocolName: parts.slice(1).join(' '),
        };
    }

    if (trimmed.startsWith('swift.protocols ')) {
        const usage = 'swift.protocols usage: swift.protocols [query] | swift.protocols <module> -- <query>';
        const parsed = splitModuleQuery(trimmed.slice('swift.protocols '.length), usage);
        return {
            kind: 'swift.protocols',
            moduleName: parsed.moduleName,
            query: parsed.query,
        };
    }

    if (trimmed.startsWith('swift.findProtocols ')) {
        const usage = 'swift.findProtocols usage: swift.findProtocols <query> | swift.findProtocols <module> -- <query>';
        const parsed = splitModuleQuery(trimmed.slice('swift.findProtocols '.length), usage);
        return {
            kind: 'swift.protocols',
            moduleName: parsed.moduleName,
            query: parsed.query,
        };
    }

    if (trimmed.startsWith('swift.conformances ')) {
        const usage = 'swift.conformances usage: swift.conformances <type> | swift.conformances <module> -- <type>';
        const parsed = splitModuleQuery(trimmed.slice('swift.conformances '.length), usage);
        return {
            kind: 'swift.conformances',
            moduleName: parsed.moduleName,
            query: parsed.query,
        };
    }

    if (trimmed.startsWith('swift.findConformances ')) {
        const usage = 'swift.findConformances usage: swift.findConformances <type> | swift.findConformances <module> -- <type>';
        const parsed = splitModuleQuery(trimmed.slice('swift.findConformances '.length), usage);
        return {
            kind: 'swift.conformances',
            moduleName: parsed.moduleName,
            query: parsed.query,
        };
    }

    if (trimmed.startsWith('swift.metadata ')) {
        const usage = 'swift.metadata usage: swift.metadata <type> | swift.metadata <module> -- <type>';
        const parsed = splitModuleQuery(trimmed.slice('swift.metadata '.length), usage);
        return {
            kind: 'swift.metadata',
            moduleName: parsed.moduleName,
            query: parsed.query,
        };
    }

    if (trimmed.startsWith('swift.findMetadata ')) {
        const usage = 'swift.findMetadata usage: swift.findMetadata <type> | swift.findMetadata <module> -- <type>';
        const parsed = splitModuleQuery(trimmed.slice('swift.findMetadata '.length), usage);
        return {
            kind: 'swift.metadata',
            moduleName: parsed.moduleName,
            query: parsed.query,
        };
    }

    if (trimmed.startsWith('swift.metadataInfo ')) {
        const usage = 'swift.metadataInfo usage: swift.metadataInfo <type> | swift.metadataInfo <module> -- <type>';
        const parsed = splitModuleQuery(trimmed.slice('swift.metadataInfo '.length), usage);
        return {
            kind: 'swift.metadata_info',
            moduleName: parsed.moduleName,
            typeName: parsed.query,
        };
    }

    if (trimmed.startsWith('swift.typeInfo ')) {
        const usage = 'swift.typeInfo usage: swift.typeInfo <type> | swift.typeInfo <module> -- <type>';
        const parsed = splitModuleQuery(trimmed.slice('swift.typeInfo '.length), usage);
        return {
            kind: 'swift.type_info',
            moduleName: parsed.moduleName,
            typeName: parsed.query,
        };
    }

    if (trimmed.startsWith('swift.methodInfo ')) {
        const usage = 'swift.methodInfo usage: swift.methodInfo <type> <method> | swift.methodInfo <module> -- <type> <method>';
        const parsed = splitSwiftMethods(trimmed.slice('swift.methodInfo '.length), usage);
        return {
            kind: 'swift.method_info',
            moduleName: parsed.moduleName,
            typeName: parsed.typeName,
            methodName: parsed.methodQuery,
        };
    }

    if (trimmed.startsWith('swift.vtable ')) {
        const usage = 'swift.vtable usage: swift.vtable <type> | swift.vtable <module> -- <type>';
        const parsed = splitModuleQuery(trimmed.slice('swift.vtable '.length), usage);
        return {
            kind: 'swift.vtable',
            moduleName: parsed.moduleName,
            query: parsed.query,
        };
    }

    if (trimmed.startsWith('swift.findVtable ')) {
        const usage = 'swift.findVtable usage: swift.findVtable <type> | swift.findVtable <module> -- <type>';
        const parsed = splitModuleQuery(trimmed.slice('swift.findVtable '.length), usage);
        return {
            kind: 'swift.vtable',
            moduleName: parsed.moduleName,
            query: parsed.query,
        };
    }

    if (trimmed.startsWith('swift.vtableInfo ')) {
        const usage = 'swift.vtableInfo usage: swift.vtableInfo <type> <member> | swift.vtableInfo <module> -- <type> <member>';
        const parsed = splitSwiftMethods(trimmed.slice('swift.vtableInfo '.length), usage);
        return {
            kind: 'swift.vtable_info',
            moduleName: parsed.moduleName,
            typeName: parsed.typeName,
            memberName: parsed.methodQuery,
        };
    }

    if (trimmed.startsWith('swift.witnessTable ')) {
        const usage = 'swift.witnessTable usage: swift.witnessTable <type|protocol> | swift.witnessTable <module> -- <type|protocol>';
        const parsed = splitModuleQuery(trimmed.slice('swift.witnessTable '.length), usage);
        return {
            kind: 'swift.witness_table',
            moduleName: parsed.moduleName,
            query: parsed.query,
        };
    }

    if (trimmed.startsWith('swift.findWitnessTable ')) {
        const usage = 'swift.findWitnessTable usage: swift.findWitnessTable <type|protocol> | swift.findWitnessTable <module> -- <type|protocol>';
        const parsed = splitModuleQuery(trimmed.slice('swift.findWitnessTable '.length), usage);
        return {
            kind: 'swift.witness_table',
            moduleName: parsed.moduleName,
            query: parsed.query,
        };
    }

    if (trimmed.startsWith('swift.witnessTableInfo ')) {
        const usage = 'swift.witnessTableInfo usage: swift.witnessTableInfo <type> <protocol> | swift.witnessTableInfo <module> -- <type> <protocol>';
        const parsed = splitSwiftMethods(trimmed.slice('swift.witnessTableInfo '.length), usage);
        return {
            kind: 'swift.witness_table_info',
            moduleName: parsed.moduleName,
            typeName: parsed.typeName,
            protocolName: parsed.methodQuery,
        };
    }

    if (trimmed.startsWith('swift.typeLayout ')) {
        const usage = 'swift.typeLayout usage: swift.typeLayout <type> | swift.typeLayout <module> -- <type>';
        const parsed = splitModuleQuery(trimmed.slice('swift.typeLayout '.length), usage);
        return {
            kind: 'swift.type_layout',
            moduleName: parsed.moduleName,
            query: parsed.query,
        };
    }

    if (trimmed.startsWith('swift.findTypeLayout ')) {
        const usage = 'swift.findTypeLayout usage: swift.findTypeLayout <type> | swift.findTypeLayout <module> -- <type>';
        const parsed = splitModuleQuery(trimmed.slice('swift.findTypeLayout '.length), usage);
        return {
            kind: 'swift.type_layout',
            moduleName: parsed.moduleName,
            query: parsed.query,
        };
    }

    if (trimmed.startsWith('swift.typeLayoutInfo ')) {
        const usage = 'swift.typeLayoutInfo usage: swift.typeLayoutInfo <type> | swift.typeLayoutInfo <module> -- <type>';
        const parsed = splitModuleQuery(trimmed.slice('swift.typeLayoutInfo '.length), usage);
        return {
            kind: 'swift.type_layout_info',
            moduleName: parsed.moduleName,
            typeName: parsed.query,
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

    if (trimmed.startsWith('swift.findTypes ')) {
        const usage = 'swift.findTypes usage: swift.findTypes <query> | swift.findTypes <module> -- <query>';
        const parsed = splitModuleQuery(trimmed.slice('swift.findTypes '.length), usage);
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

    if (trimmed.startsWith('swift.findTypesOfKind ')) {
        const usage = 'swift.findTypesOfKind usage: swift.findTypesOfKind <kind> <query> | swift.findTypesOfKind <module> -- <kind> <query>';
        const parsed = splitSwiftTypeKindQuery(trimmed.slice('swift.findTypesOfKind '.length), usage);
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

    if (trimmed.startsWith('swift.findMethodOwners ')) {
        const usage = 'swift.findMethodOwners usage: swift.findMethodOwners <method> | swift.findMethodOwners <module> -- <method>';
        const parsed = splitModuleQuery(trimmed.slice('swift.findMethodOwners '.length), usage);
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

    if (trimmed.startsWith('swift.findTypeMethods ')) {
        const usage = 'swift.findTypeMethods usage: swift.findTypeMethods <type> | swift.findTypeMethods <module> -- <type>';
        const parsed = splitModuleQuery(trimmed.slice('swift.findTypeMethods '.length), usage);
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

    if (trimmed.startsWith('swift.findMethods ')) {
        const usage = 'swift.findMethods usage: swift.findMethods <type> <method> | swift.findMethods <module> -- <type> <method>';
        const parsed = splitSwiftMethods(trimmed.slice('swift.findMethods '.length), usage);
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
