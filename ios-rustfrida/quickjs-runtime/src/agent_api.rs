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

function formatVmProtection(prot) {
    const value = Number(prot || 0);
    return [
        (value & 1) !== 0 ? 'r' : '-',
        (value & 2) !== 0 ? 'w' : '-',
        (value & 4) !== 0 ? 'x' : '-',
    ].join('');
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

function formatSectionType(flags) {
    const type = Number(flags || 0) & 0xff;
    switch (type) {
    case 0x0: return 'S_REGULAR';
    case 0x1: return 'S_ZEROFILL';
    case 0x2: return 'S_CSTRING_LITERALS';
    case 0x3: return 'S_4BYTE_LITERALS';
    case 0x4: return 'S_8BYTE_LITERALS';
    case 0x5: return 'S_LITERAL_POINTERS';
    case 0x6: return 'S_NON_LAZY_SYMBOL_POINTERS';
    case 0x7: return 'S_LAZY_SYMBOL_POINTERS';
    case 0x8: return 'S_SYMBOL_STUBS';
    case 0x9: return 'S_MOD_INIT_FUNC_POINTERS';
    case 0xa: return 'S_MOD_TERM_FUNC_POINTERS';
    case 0xb: return 'S_COALESCED';
    case 0xc: return 'S_GB_ZEROFILL';
    case 0xd: return 'S_INTERPOSING';
    case 0xe: return 'S_16BYTE_LITERALS';
    case 0xf: return 'S_DTRACE_DOF';
    case 0x10: return 'S_LAZY_DYLIB_SYMBOL_POINTERS';
    case 0x11: return 'S_THREAD_LOCAL_REGULAR';
    case 0x12: return 'S_THREAD_LOCAL_ZEROFILL';
    case 0x13: return 'S_THREAD_LOCAL_VARIABLES';
    case 0x14: return 'S_THREAD_LOCAL_VARIABLE_POINTERS';
    case 0x15: return 'S_THREAD_LOCAL_INIT_FUNCTION_POINTERS';
    case 0x16: return 'S_INIT_FUNC_OFFSETS';
    default: return 'S_UNKNOWN';
    }
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

function parseSwiftMetadataDemangledInfo(demangledName, fallbackName) {
    const trimmed = trimSwiftDemangledName(demangledName);
    const parsed = {
        name: fallbackName === null || fallbackName === undefined ? null : String(fallbackName),
        qualifiedName: null,
        hasQualifiedName: false,
        signature: trimmed,
        hasSignature: trimmed !== null,
        contextModuleName: null,
        hasContextModuleName: false,
        detailKind: trimmed === null ? null : 'symbol',
        isMetadata: false,
        isMetadataAccessor: false,
        isNominalDescriptor: false,
    };

    if (trimmed === null) {
        return parsed;
    }

    let rest = trimmed;
    const prefixes = [
        ['type metadata accessor for ', 'metadata-accessor'],
        ['type metadata for ', 'metadata'],
        ['full type metadata for ', 'metadata'],
        ['nominal type descriptor for ', 'nominal-descriptor'],
        ['type descriptor for ', 'type-descriptor'],
    ];
    for (const [prefix, kind] of prefixes) {
        if (rest.startsWith(prefix)) {
            parsed.detailKind = kind;
            parsed.isMetadata = kind === 'metadata' || kind === 'metadata-accessor';
            parsed.isMetadataAccessor = kind === 'metadata-accessor';
            parsed.isNominalDescriptor = kind === 'nominal-descriptor' || kind === 'type-descriptor';
            rest = rest.slice(prefix.length).trim();
            break;
        }
    }

    if (rest.length !== 0) {
        parsed.qualifiedName = rest;
        parsed.hasQualifiedName = true;
    }

    const fallback = parsed.name === null ? '' : String(parsed.name);
    if (fallback.length !== 0 && rest.endsWith('.' + fallback) && rest.length > fallback.length + 1) {
        parsed.contextModuleName = rest.slice(0, rest.length - fallback.length - 1);
        parsed.hasContextModuleName = parsed.contextModuleName.length !== 0;
        return parsed;
    }

    const dotIndex = rest.lastIndexOf('.');
    if (dotIndex !== -1) {
        const simpleName = rest.slice(dotIndex + 1).trim();
        const context = rest.slice(0, dotIndex).trim();
        if (simpleName.length !== 0) {
            parsed.name = simpleName;
        }
        if (context.length !== 0) {
            parsed.contextModuleName = context;
            parsed.hasContextModuleName = true;
        }
    } else if ((parsed.name === null || parsed.name.length === 0) && rest.length !== 0) {
        parsed.name = rest;
    }

    return parsed;
}

function formatSwiftMetadataFlags(info) {
    const flags = [];
    if (info.detailKind !== null && info.detailKind !== undefined && info.detailKind !== 'symbol') {
        flags.push('kind=' + info.detailKind);
    }
    if (info.hasContextModuleName) {
        flags.push('in=' + info.contextModuleName);
    }
    return flags.length === 0 ? '' : ' {' + flags.join(' ') + '}';
}

function formatNormalizedSwiftMetadata(typeInfo) {
    const base = typeInfo.sourceAddress + ' ' + typeInfo.moduleName + '!' + typeInfo.name + ' [' + String(typeInfo.sourceKind || 'symbol') + ']';
    const demangled = typeInfo.sourceDemangledName === null || typeInfo.sourceDemangledName === undefined
        ? ''
        : ' <= ' + typeInfo.sourceDemangledName;
    return base + demangled + formatSwiftMetadataFlags(typeInfo);
}

function formatNormalizedSwiftType(typeInfo) {
    const base = typeInfo.sourceAddress + ' ' + typeInfo.moduleName + '!' + typeInfo.name + ' [' + String(typeInfo.sourceKind || 'symbol') + ']';
    const demangled = typeInfo.sourceDemangledName === null || typeInfo.sourceDemangledName === undefined
        ? ''
        : ' <= ' + typeInfo.sourceDemangledName;
    return base + demangled + formatSwiftMetadataFlags(typeInfo);
}

function parseSwiftProtocolDemangledInfo(demangledName, fallbackName) {
    const trimmed = trimSwiftDemangledName(demangledName);
    const parsed = {
        name: fallbackName === null || fallbackName === undefined ? null : String(fallbackName),
        qualifiedName: null,
        hasQualifiedName: false,
        signature: trimmed,
        hasSignature: trimmed !== null,
        contextModuleName: null,
        hasContextModuleName: false,
        detailKind: trimmed === null ? null : 'symbol',
        isDescriptor: false,
    };

    if (trimmed === null) {
        return parsed;
    }

    let rest = trimmed;
    if (rest.startsWith('protocol descriptor for ')) {
        parsed.detailKind = 'descriptor';
        parsed.isDescriptor = true;
        rest = rest.slice('protocol descriptor for '.length).trim();
    }

    if (rest.length !== 0) {
        parsed.qualifiedName = rest;
        parsed.hasQualifiedName = true;
    }

    const fallback = parsed.name === null ? '' : String(parsed.name);
    if (fallback.length !== 0 && rest.endsWith('.' + fallback) && rest.length > fallback.length + 1) {
        parsed.contextModuleName = rest.slice(0, rest.length - fallback.length - 1);
        parsed.hasContextModuleName = parsed.contextModuleName.length !== 0;
        return parsed;
    }

    const dotIndex = rest.lastIndexOf('.');
    if (dotIndex !== -1) {
        const simpleName = rest.slice(dotIndex + 1).trim();
        const context = rest.slice(0, dotIndex).trim();
        if (simpleName.length !== 0) {
            parsed.name = simpleName;
        }
        if (context.length !== 0) {
            parsed.contextModuleName = context;
            parsed.hasContextModuleName = true;
        }
    } else if ((parsed.name === null || parsed.name.length === 0) && rest.length !== 0) {
        parsed.name = rest;
    }

    return parsed;
}

function formatSwiftProtocolFlags(info) {
    const flags = [];
    if (info.detailKind !== null && info.detailKind !== undefined && info.detailKind !== 'symbol') {
        flags.push('kind=' + info.detailKind);
    }
    if (info.hasContextModuleName) {
        flags.push('in=' + info.contextModuleName);
    }
    return flags.length === 0 ? '' : ' {' + flags.join(' ') + '}';
}

function formatNormalizedSwiftProtocol(protocolInfo) {
    const base = protocolInfo.sourceAddress + ' ' + protocolInfo.moduleName + '!' + protocolInfo.name + ' [' + String(protocolInfo.sourceKind || 'symbol') + ']';
    const demangled = protocolInfo.sourceDemangledName === null || protocolInfo.sourceDemangledName === undefined
        ? ''
        : ' <= ' + protocolInfo.sourceDemangledName;
    return base + demangled + formatSwiftProtocolFlags(protocolInfo);
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

function trimSwiftDemangledName(raw) {
    if (raw === null || raw === undefined) {
        return null;
    }
    const trimmed = String(raw).trim();
    return trimmed.length === 0 ? null : trimmed;
}

function parseSwiftConformanceDemangledInfo(demangledName, fallbackTypeName, fallbackProtocolName) {
    const trimmed = trimSwiftDemangledName(demangledName);
    const parsed = {
        typeName: fallbackTypeName === null || fallbackTypeName === undefined ? null : String(fallbackTypeName),
        protocolName: fallbackProtocolName === null || fallbackProtocolName === undefined ? null : String(fallbackProtocolName),
        signature: trimmed,
        hasSignature: trimmed !== null,
        relation: null,
        contextModuleName: null,
        hasContextModuleName: false,
        whereClause: null,
        hasWhereClause: false,
        detailKind: trimmed === null ? null : 'symbol',
        isDescriptor: false,
        isWitnessTable: false,
        isWitnessAccessor: false,
        isWitness: false,
    };

    if (trimmed === null) {
        return parsed;
    }

    let rest = trimmed;
    const prefixes = [
        ['protocol conformance descriptor for ', 'descriptor'],
        ['protocol witness table accessor for ', 'witness-table-accessor'],
        ['protocol witness table for ', 'witness-table'],
        ['protocol witness for ', 'witness'],
    ];
    for (const [prefix, kind] of prefixes) {
        if (rest.startsWith(prefix)) {
            parsed.detailKind = kind;
            parsed.isDescriptor = kind === 'descriptor';
            parsed.isWitnessTable = kind === 'witness-table' || kind === 'witness-table-accessor';
            parsed.isWitnessAccessor = kind === 'witness-table-accessor';
            parsed.isWitness = kind === 'witness';
            rest = rest.slice(prefix.length).trim();
            break;
        }
    }

    const inIndex = rest.lastIndexOf(' in ');
    if (inIndex !== -1) {
        const contextModuleName = rest.slice(inIndex + 4).trim();
        if (contextModuleName.length !== 0) {
            parsed.contextModuleName = contextModuleName;
            parsed.hasContextModuleName = true;
        }
        rest = rest.slice(0, inIndex).trim();
    }

    const whereIndex = rest.indexOf(' where ');
    if (whereIndex !== -1) {
        const whereClause = rest.slice(whereIndex + 7).trim();
        if (whereClause.length !== 0) {
            parsed.whereClause = whereClause;
            parsed.hasWhereClause = true;
        }
        rest = rest.slice(0, whereIndex).trim();
    }

    const pair = rest.split(' : ');
    if (pair.length >= 2) {
        parsed.typeName = pair.shift().trim() || parsed.typeName;
        parsed.protocolName = pair.join(' : ').trim() || parsed.protocolName;
    }

    if (parsed.typeName !== null && parsed.protocolName !== null) {
        parsed.relation = parsed.typeName + ' : ' + parsed.protocolName;
    }
    return parsed;
}

function formatSwiftConformanceFlags(info) {
    const flags = [];
    if (info.detailKind !== null && info.detailKind !== undefined && info.detailKind !== 'symbol') {
        flags.push('kind=' + info.detailKind);
    }
    if (info.hasContextModuleName) {
        flags.push('in=' + info.contextModuleName);
    }
    if (info.hasWhereClause) {
        flags.push('where=' + info.whereClause);
    }
    return flags.length === 0 ? '' : ' {' + flags.join(' ') + '}';
}

function formatNormalizedSwiftConformance(conformance) {
    const base = conformance.sourceAddress + ' ' + conformance.moduleName + '!' + conformance.typeName + ' : ' + conformance.protocolName + ' [' + String(conformance.sourceKind || 'symbol') + ']';
    const demangled = conformance.sourceDemangledName === null || conformance.sourceDemangledName === undefined
        ? ''
        : ' <= ' + conformance.sourceDemangledName;
    return base + demangled + formatSwiftConformanceFlags(conformance);
}

function formatNormalizedSwiftWitnessTable(entry) {
    const base = entry.address + ' ' + entry.moduleName + '!' + entry.typeName + ' : ' + entry.protocolName + ' [' + String(entry.sourceKind || 'protocol-witness-table') + ']';
    const demangled = entry.demangledName === null || entry.demangledName === undefined
        ? ''
        : ' <= ' + entry.demangledName;
    return base + demangled + formatSwiftConformanceFlags(entry);
}

function classifySwiftMemberKind(rawKind, memberName) {
    switch (rawKind) {
    case 'getter':
    case 'setter':
    case 'modify':
    case 'read':
    case 'unsafeAddressor':
    case 'unsafeMutableAddressor':
    case 'materializeForSet':
        return rawKind;
    case 'allocator':
    case 'initializer':
    case 'init':
        return 'constructor';
    case 'deallocator':
    case 'deinit':
        return 'destructor';
    default:
        break;
    }

    if (memberName === 'subscript') {
        return 'subscript';
    }
    if (memberName !== null && /^[=+\-*/%<>!&|^~?.]+$/.test(memberName)) {
        return 'operator';
    }
    return 'method';
}

function parseSwiftDemangledMemberInfo(demangledName, fallbackName, fallbackOwnerTypeName, fallbackMemberName, options) {
    const normalizedDemangledName = trimSwiftDemangledName(demangledName);
    const normalizedFallbackName = fallbackName === null || fallbackName === undefined ? null : String(fallbackName);
    const normalizedFallbackOwnerTypeName = fallbackOwnerTypeName === null || fallbackOwnerTypeName === undefined
        ? null
        : String(fallbackOwnerTypeName);
    const normalizedFallbackMemberName = fallbackMemberName === null || fallbackMemberName === undefined
        ? null
        : String(fallbackMemberName);
    const extra = options && typeof options === 'object' ? options : {};

    const parsed = {
        ownerTypeName: normalizedFallbackOwnerTypeName,
        memberName: normalizedFallbackMemberName,
        memberKind: normalizedFallbackMemberName === null ? 'symbol' : classifySwiftMemberKind(null, normalizedFallbackMemberName),
        signature: normalizedDemangledName,
        hasSignature: normalizedDemangledName !== null,
        resultTypeName: null,
        hasResultTypeName: false,
        isMember: normalizedFallbackOwnerTypeName !== null || normalizedFallbackMemberName !== null,
        isAccessor: false,
        isGetter: false,
        isSetter: false,
        isModifyAccessor: false,
        isReadAccessor: false,
        isConstructor: false,
        isDestructor: false,
        isSubscript: normalizedFallbackMemberName === 'subscript',
        isOperator: normalizedFallbackMemberName !== null && /^[=+\-*/%<>!&|^~?.]+$/.test(normalizedFallbackMemberName),
        isClosure: false,
        isStaticMember: false,
        isClassMember: false,
        isMutating: false,
        isDispatchThunk: extra.isDispatchThunk === true,
        isAsync: false,
        isThrowing: false,
        throwsKind: null,
    };

    if (normalizedDemangledName === null) {
        return parsed;
    }

    let signature = normalizedDemangledName;
    if (signature.startsWith('dispatch thunk of ')) {
        parsed.isDispatchThunk = true;
        signature = signature.slice('dispatch thunk of '.length).trim();
    }
    parsed.signature = signature;
    parsed.hasSignature = signature.length !== 0;

    let head = signature;
    const lastArrow = signature.lastIndexOf(' -> ');
    if (lastArrow !== -1) {
        parsed.resultTypeName = signature.slice(lastArrow + 4).trim() || null;
        head = signature.slice(0, lastArrow).trim();
    } else {
        const accessorColon = signature.lastIndexOf(' : ');
        if (accessorColon !== -1) {
            parsed.resultTypeName = signature.slice(accessorColon + 3).trim() || null;
            head = signature.slice(0, accessorColon).trim();
        }
    }
    parsed.hasResultTypeName = parsed.resultTypeName !== null;
    parsed.isAsync = /(^|\s)async(\s|$)/.test(head);
    if (/(^|\s)rethrows(\s|$)/.test(head)) {
        parsed.isThrowing = true;
        parsed.throwsKind = 'rethrows';
    } else if (/(^|\s)throws(\s|$)/.test(head)) {
        parsed.isThrowing = true;
        parsed.throwsKind = 'throws';
    }

    let qualifiedHead = head;
    for (const prefix of ['static ', 'class ', 'mutating ']) {
        if (qualifiedHead.startsWith(prefix)) {
            if (prefix === 'static ') {
                parsed.isStaticMember = true;
            } else if (prefix === 'class ') {
                parsed.isClassMember = true;
            } else if (prefix === 'mutating ') {
                parsed.isMutating = true;
            }
            qualifiedHead = qualifiedHead.slice(prefix.length).trim();
        }
    }

    if (qualifiedHead.includes('closure #')) {
        parsed.isClosure = true;
        parsed.isMember = true;
        parsed.memberKind = 'closure';
        const closureMatch = qualifiedHead.match(/(closure #[0-9]+)\s+in\s+(.+)$/);
        if (closureMatch) {
            parsed.memberName = closureMatch[1];
            const ownerMatch = closureMatch[2].match(/([A-Za-z0-9_$]+(?:\.[A-Za-z0-9_$]+)+)\.([^.]+?)(?:\(|$)/);
            if (ownerMatch) {
                parsed.ownerTypeName = ownerMatch[1];
            }
        } else if (parsed.memberName === null) {
            parsed.memberName = 'closure';
        }
        return parsed;
    }

    const strippedHead = qualifiedHead.replace(/\s+(async|throws|rethrows)\b/g, '').trim();
    let ownerTypeName = normalizedFallbackOwnerTypeName;
    let memberName = normalizedFallbackMemberName;
    let rawKind = null;
    let signatureHead = strippedHead;

    if (signatureHead.endsWith('.getter')) {
        rawKind = 'getter';
        signatureHead = signatureHead.slice(0, -'.getter'.length);
    } else if (signatureHead.endsWith('.setter')) {
        rawKind = 'setter';
        signatureHead = signatureHead.slice(0, -'.setter'.length);
    } else if (signatureHead.endsWith('.modify')) {
        rawKind = 'modify';
        signatureHead = signatureHead.slice(0, -'.modify'.length);
    } else if (signatureHead.endsWith('.read')) {
        rawKind = 'read';
        signatureHead = signatureHead.slice(0, -'.read'.length);
    } else if (signatureHead.endsWith('.unsafeAddressor')) {
        rawKind = 'unsafeAddressor';
        signatureHead = signatureHead.slice(0, -'.unsafeAddressor'.length);
    } else if (signatureHead.endsWith('.unsafeMutableAddressor')) {
        rawKind = 'unsafeMutableAddressor';
        signatureHead = signatureHead.slice(0, -'.unsafeMutableAddressor'.length);
    } else if (signatureHead.endsWith('.materializeForSet')) {
        rawKind = 'materializeForSet';
        signatureHead = signatureHead.slice(0, -'.materializeForSet'.length);
    }

    if (signatureHead.includes('.Type.')) {
        const parts = signatureHead.split('.Type.');
        if (parts.length === 2) {
            ownerTypeName = parts[0].trim() || ownerTypeName;
            const tail = parts[1].trim();
            const tailName = tail.includes('(') ? tail.slice(0, tail.indexOf('(')).trim() : tail;
            memberName = tailName.length === 0 ? memberName : tailName;
        }
    } else {
        const parts = signatureHead.split('.');
        if (parts.length >= 2) {
            const tail = parts[parts.length - 1].trim();
            const tailName = tail.includes('(') ? tail.slice(0, tail.indexOf('(')).trim() : tail;
            if (tailName.length !== 0) {
                memberName = tailName;
            }
            ownerTypeName = parts.slice(0, -1).join('.').trim() || ownerTypeName;
        }
    }

    if (memberName === 'init' || memberName === 'allocator' || memberName === 'initializer') {
        rawKind = memberName;
    } else if (memberName === 'deinit' || memberName === 'deallocator') {
        rawKind = memberName;
    }

    const memberKind = classifySwiftMemberKind(rawKind, memberName);
    parsed.ownerTypeName = ownerTypeName;
    parsed.memberName = memberName;
    parsed.memberKind = memberKind;
    parsed.isMember = ownerTypeName !== null || memberName !== null || memberKind !== 'symbol';
    parsed.isAccessor = ['getter', 'setter', 'modify', 'read', 'unsafeAddressor', 'unsafeMutableAddressor', 'materializeForSet'].includes(memberKind);
    parsed.isGetter = memberKind === 'getter';
    parsed.isSetter = memberKind === 'setter';
    parsed.isModifyAccessor = memberKind === 'modify';
    parsed.isReadAccessor = memberKind === 'read';
    parsed.isConstructor = memberKind === 'constructor';
    parsed.isDestructor = memberKind === 'destructor';
    parsed.isSubscript = parsed.isSubscript || memberKind === 'subscript';
    parsed.isOperator = parsed.isOperator || memberKind === 'operator';
    return parsed;
}

function formatSwiftMemberFlags(info) {
    const flags = [];
    if (info.memberKind !== null && info.memberKind !== undefined && info.memberKind !== 'symbol') {
        flags.push('kind=' + info.memberKind);
    }
    if (info.isDispatchThunk) {
        flags.push('dispatch-thunk');
    }
    if (info.isStaticMember) {
        flags.push('static');
    }
    if (info.isClassMember) {
        flags.push('class');
    }
    if (info.isMutating) {
        flags.push('mutating');
    }
    if (info.isAsync) {
        flags.push('async');
    }
    if (info.isThrowing) {
        flags.push(info.throwsKind || 'throws');
    }
    if (info.hasOwnerTypeName) {
        flags.push('owner=' + info.ownerTypeName);
    }
    if (info.hasResultTypeName) {
        flags.push('result=' + info.resultTypeName);
    }
    return flags.length === 0 ? '' : ' {' + flags.join(' ') + '}';
}

function formatNormalizedSwiftSymbol(symbol) {
    const base = symbol.address + ' ' + symbol.moduleName + '!' + symbol.name;
    const demangled = symbol.demangledName === null || symbol.demangledName === undefined
        ? ''
        : ' => ' + symbol.demangledName;
    return base + demangled + formatSwiftMemberFlags(symbol);
}

function formatNormalizedSwiftVtableEntry(entry) {
    const base = entry.address + ' ' + entry.moduleName + '!' + entry.typeName + '.' + entry.memberName + ' [' + String(entry.sourceKind || 'member') + ']';
    const demangled = entry.demangledName === null || entry.demangledName === undefined
        ? ''
        : ' <= ' + entry.demangledName;
    return base + demangled + formatSwiftMemberFlags(entry);
}

function summarizeSwiftMembers(items) {
    const ownerTypes = [];
    const memberKinds = [];
    const resultTypes = [];
    let parsedMemberCount = 0;
    let accessorCount = 0;
    let getterCount = 0;
    let setterCount = 0;
    let modifyAccessorCount = 0;
    let readAccessorCount = 0;
    let constructorCount = 0;
    let destructorCount = 0;
    let subscriptCount = 0;
    let operatorCount = 0;
    let closureCount = 0;
    let staticMemberCount = 0;
    let classMemberCount = 0;
    let mutatingMemberCount = 0;
    let asyncCount = 0;
    let throwingCount = 0;
    let dispatchThunkCount = 0;
    for (const item of items) {
        if (item.isMember) {
            parsedMemberCount += 1;
        }
        if (item.isAccessor) {
            accessorCount += 1;
        }
        if (item.isGetter) {
            getterCount += 1;
        }
        if (item.isSetter) {
            setterCount += 1;
        }
        if (item.isModifyAccessor) {
            modifyAccessorCount += 1;
        }
        if (item.isReadAccessor) {
            readAccessorCount += 1;
        }
        if (item.isConstructor) {
            constructorCount += 1;
        }
        if (item.isDestructor) {
            destructorCount += 1;
        }
        if (item.isSubscript) {
            subscriptCount += 1;
        }
        if (item.isOperator) {
            operatorCount += 1;
        }
        if (item.isClosure) {
            closureCount += 1;
        }
        if (item.isStaticMember) {
            staticMemberCount += 1;
        }
        if (item.isClassMember) {
            classMemberCount += 1;
        }
        if (item.isMutating) {
            mutatingMemberCount += 1;
        }
        if (item.isAsync) {
            asyncCount += 1;
        }
        if (item.isThrowing) {
            throwingCount += 1;
        }
        if (item.isDispatchThunk) {
            dispatchThunkCount += 1;
        }
        if (item.hasOwnerTypeName) {
            let summary = ownerTypes.find((entry) => entry.ownerTypeName === item.ownerTypeName);
            if (summary === undefined) {
                summary = {
                    ownerTypeName: item.ownerTypeName,
                    count: 0,
                    firstMemberName: item.memberName,
                    lastMemberName: item.memberName,
                };
                ownerTypes.push(summary);
            }
            summary.count += 1;
            summary.lastMemberName = item.memberName;
        }
        const memberKind = item.memberKind === null || item.memberKind === undefined ? 'symbol' : String(item.memberKind);
        let kindSummary = memberKinds.find((entry) => entry.memberKind === memberKind);
        if (kindSummary === undefined) {
            kindSummary = {
                memberKind,
                count: 0,
                firstMemberName: item.memberName,
                lastMemberName: item.memberName,
                asyncCount: 0,
                throwingCount: 0,
            };
            memberKinds.push(kindSummary);
        }
        kindSummary.count += 1;
        kindSummary.lastMemberName = item.memberName;
        if (item.isAsync) {
            kindSummary.asyncCount += 1;
        }
        if (item.isThrowing) {
            kindSummary.throwingCount += 1;
        }
        if (item.hasResultTypeName) {
            let resultTypeSummary = resultTypes.find((entry) => entry.resultTypeName === item.resultTypeName);
            if (resultTypeSummary === undefined) {
                resultTypeSummary = {
                    resultTypeName: item.resultTypeName,
                    count: 0,
                    firstMemberName: item.memberName,
                    lastMemberName: item.memberName,
                };
                resultTypes.push(resultTypeSummary);
            }
            resultTypeSummary.count += 1;
            resultTypeSummary.lastMemberName = item.memberName;
        }
    }
    return {
        parsedMemberCount,
        accessorCount,
        getterCount,
        setterCount,
        modifyAccessorCount,
        readAccessorCount,
        constructorCount,
        destructorCount,
        subscriptCount,
        operatorCount,
        closureCount,
        staticMemberCount,
        classMemberCount,
        mutatingMemberCount,
        asyncCount,
        throwingCount,
        dispatchThunkCount,
        uniqueOwnerTypeCount: ownerTypes.length,
        uniqueMemberKindCount: memberKinds.length,
        uniqueResultTypeCount: resultTypes.length,
        ownerTypes,
        memberKinds,
        resultTypes,
    };
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
    const name = pathParts.length === 0 ? path : pathParts[pathParts.length - 1];
    const directoryPath = pathParts.length <= 1 ? '' : '/' + pathParts.slice(0, -1).join('/');
    const size = Number(image.size || 0);
    let pathKind = 'other';
    if (path.length === 0) {
        pathKind = 'unknown';
    } else if (path.startsWith('/System/') || path.startsWith('/usr/lib/')) {
        pathKind = 'system';
    } else if (path.startsWith('/private/var/containers/') || path.startsWith('/var/containers/')) {
        pathKind = 'app';
    } else if (path.startsWith('/Applications/')) {
        pathKind = 'application';
    } else if (path.startsWith('/private/var/jb/') || path.startsWith('/var/jb/') || path.startsWith('/private/preboot/')) {
        pathKind = 'jailbreak';
    }
    return {
        path,
        hasPath: path.length !== 0,
        name,
        hasName: name.length !== 0,
        directoryPath,
        hasDirectoryPath: directoryPath.length !== 0,
        pathKind,
        isSystemPath: pathKind === 'system',
        isAppPath: pathKind === 'app' || pathKind === 'application',
        isJailbreakPath: pathKind === 'jailbreak',
        base: image.base.toString(),
        slide: formatSlide(image.slide),
        size,
        sizeHex: '0x' + BigInt(image.size || 0).toString(16),
        text: formatImage(image),
    };
}

function classifyLibraryPathKind(path) {
    if (path.length === 0) {
        return 'unknown';
    }
    if (path.startsWith('@loader_path/')) {
        return 'loader_path';
    }
    if (path.startsWith('@executable_path/')) {
        return 'executable_path';
    }
    if (path.startsWith('@rpath/')) {
        return 'rpath';
    }
    if (path.startsWith('/System/') || path.startsWith('/usr/lib/')) {
        return 'system';
    }
    if (path.startsWith('/private/var/containers/') || path.startsWith('/var/containers/')) {
        return 'app';
    }
    if (path.startsWith('/Applications/')) {
        return 'application';
    }
    if (path.startsWith('/private/var/jb/') || path.startsWith('/var/jb/') || path.startsWith('/private/preboot/')) {
        return 'jailbreak';
    }
    return 'other';
}

function splitVersionComponents(version) {
    const text = String(version || '');
    if (text.length === 0) {
        return [];
    }
    return text.split('.').map((part) => String(part));
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

function summarizeObjcMethods(methods) {
    const selectors = [];
    const returnTypes = [];
    let keywordSelectorCount = 0;
    let unarySelectorCount = 0;
    let explicitArgumentMethodCount = 0;
    let hiddenArgumentMethodCount = 0;
    let returnsVoidCount = 0;
    let returnsObjectCount = 0;
    let returnsBlockCount = 0;
    let totalExplicitArgumentCount = 0;
    let totalHiddenArgumentCount = 0;
    let maxSelectorPartCount = 0;
    let maxExplicitArgumentCount = 0;
    for (const method of methods) {
        totalExplicitArgumentCount += method.explicitArgumentCount;
        totalHiddenArgumentCount += method.hiddenArgumentCount;
        if (method.selectorPartCount > maxSelectorPartCount) {
            maxSelectorPartCount = method.selectorPartCount;
        }
        if (method.explicitArgumentCount > maxExplicitArgumentCount) {
            maxExplicitArgumentCount = method.explicitArgumentCount;
        }
        if (method.isKeywordSelector) {
            keywordSelectorCount += 1;
        }
        if (method.isUnarySelector) {
            unarySelectorCount += 1;
        }
        if (method.hasExplicitArguments) {
            explicitArgumentMethodCount += 1;
        }
        if (method.hasHiddenArguments) {
            hiddenArgumentMethodCount += 1;
        }
        if (method.returnsVoid) {
            returnsVoidCount += 1;
        }
        if (method.returnsObject) {
            returnsObjectCount += 1;
        }
        if (method.returnsBlock) {
            returnsBlockCount += 1;
        }
        let selectorSummary = selectors.find((item) => item.selector === method.selector);
        if (selectorSummary === undefined) {
            selectorSummary = {
                selector: method.selector,
                count: 0,
                firstImp: method.imp,
                lastImp: method.imp,
                returnTypeName: method.returnTypeName,
                keywordSelector: method.isKeywordSelector,
            };
            selectors.push(selectorSummary);
        }
        selectorSummary.count += 1;
        selectorSummary.lastImp = method.imp;
        let returnTypeSummary = returnTypes.find((item) => item.returnTypeName === method.returnTypeName);
        if (returnTypeSummary === undefined) {
            returnTypeSummary = {
                returnTypeName: method.returnTypeName,
                count: 0,
                firstSelector: method.selector,
                lastSelector: method.selector,
                returnsObject: method.returnsObject,
                returnsBlock: method.returnsBlock,
            };
            returnTypes.push(returnTypeSummary);
        }
        returnTypeSummary.count += 1;
        returnTypeSummary.lastSelector = method.selector;
    }
    return {
        uniqueSelectorCount: selectors.length,
        uniqueReturnTypeCount: returnTypes.length,
        keywordSelectorCount,
        unarySelectorCount,
        explicitArgumentMethodCount,
        hiddenArgumentMethodCount,
        returnsVoidCount,
        returnsObjectCount,
        returnsBlockCount,
        totalExplicitArgumentCount,
        totalHiddenArgumentCount,
        maxSelectorPartCount,
        maxExplicitArgumentCount,
        selectors,
        returnTypes,
    };
}

function summarizeObjcProtocolMethods(methods) {
    const selectors = [];
    const returnTypes = [];
    let keywordSelectorCount = 0;
    let unarySelectorCount = 0;
    let explicitArgumentMethodCount = 0;
    let hiddenArgumentMethodCount = 0;
    let returnsVoidCount = 0;
    let returnsObjectCount = 0;
    let returnsBlockCount = 0;
    let totalExplicitArgumentCount = 0;
    let totalHiddenArgumentCount = 0;
    let maxSelectorPartCount = 0;
    let maxExplicitArgumentCount = 0;
    for (const method of methods) {
        totalExplicitArgumentCount += method.explicitArgumentCount;
        totalHiddenArgumentCount += method.hiddenArgumentCount;
        if (method.selectorPartCount > maxSelectorPartCount) {
            maxSelectorPartCount = method.selectorPartCount;
        }
        if (method.explicitArgumentCount > maxExplicitArgumentCount) {
            maxExplicitArgumentCount = method.explicitArgumentCount;
        }
        if (method.isKeywordSelector) {
            keywordSelectorCount += 1;
        }
        if (method.isUnarySelector) {
            unarySelectorCount += 1;
        }
        if (method.hasExplicitArguments) {
            explicitArgumentMethodCount += 1;
        }
        if (method.hasHiddenArguments) {
            hiddenArgumentMethodCount += 1;
        }
        if (method.returnsVoid) {
            returnsVoidCount += 1;
        }
        if (method.returnsObject) {
            returnsObjectCount += 1;
        }
        if (method.returnsBlock) {
            returnsBlockCount += 1;
        }
        let selectorSummary = selectors.find((item) => item.selector === method.selector);
        if (selectorSummary === undefined) {
            selectorSummary = {
                selector: method.selector,
                count: 0,
                returnTypeName: method.returnTypeName,
                keywordSelector: method.isKeywordSelector,
                isRequired: method.isRequired,
                isInstanceMethod: method.isInstanceMethod,
            };
            selectors.push(selectorSummary);
        }
        selectorSummary.count += 1;
        let returnTypeSummary = returnTypes.find((item) => item.returnTypeName === method.returnTypeName);
        if (returnTypeSummary === undefined) {
            returnTypeSummary = {
                returnTypeName: method.returnTypeName,
                count: 0,
                firstSelector: method.selector,
                lastSelector: method.selector,
                returnsObject: method.returnsObject,
                returnsBlock: method.returnsBlock,
            };
            returnTypes.push(returnTypeSummary);
        }
        returnTypeSummary.count += 1;
        returnTypeSummary.lastSelector = method.selector;
    }
    return {
        uniqueSelectorCount: selectors.length,
        uniqueReturnTypeCount: returnTypes.length,
        keywordSelectorCount,
        unarySelectorCount,
        explicitArgumentMethodCount,
        hiddenArgumentMethodCount,
        returnsVoidCount,
        returnsObjectCount,
        returnsBlockCount,
        totalExplicitArgumentCount,
        totalHiddenArgumentCount,
        maxSelectorPartCount,
        maxExplicitArgumentCount,
        selectors,
        returnTypes,
    };
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

function summarizeObjcClassNames(classes) {
    const imagePaths = [];
    let classesWithImagePathCount = 0;
    let rootClassCount = 0;
    let classesWithProtocolsCount = 0;
    let classesWithPropertiesCount = 0;
    let classesWithIvarsCount = 0;
    let classesWithMethodsCount = 0;
    let firstImagePath = null;
    let lastImagePath = null;
    let totalProtocolCount = 0;
    let totalPropertyCount = 0;
    let totalIvarCount = 0;
    let totalMethodCount = 0;
    let totalInstanceSize = 0;
    for (const className of classes) {
        const info = ObjC.classInfo(className, false);
        const normalized = info === null ? null : normalizeObjcClassInfo(info);
        if (normalized === null) {
            continue;
        }
        totalProtocolCount += normalized.protocolCount;
        totalPropertyCount += normalized.totalPropertyCount;
        totalIvarCount += normalized.ivarCount;
        totalMethodCount += normalized.totalMethodCount;
        totalInstanceSize += normalized.instanceSize;
        if (normalized.hasImagePath) {
            classesWithImagePathCount += 1;
            if (firstImagePath === null) {
                firstImagePath = normalized.imagePath;
            }
            lastImagePath = normalized.imagePath;
            let imageSummary = imagePaths.find((item) => item.imagePath === normalized.imagePath);
            if (imageSummary === undefined) {
                imageSummary = {
                    imagePath: normalized.imagePath,
                    count: 0,
                    firstClass: normalized.className,
                    lastClass: normalized.className,
                };
                imagePaths.push(imageSummary);
            }
            imageSummary.count += 1;
            imageSummary.lastClass = normalized.className;
        }
        if (normalized.isRootClass) {
            rootClassCount += 1;
        }
        if (normalized.hasProtocols) {
            classesWithProtocolsCount += 1;
        }
        if (normalized.hasProperties) {
            classesWithPropertiesCount += 1;
        }
        if (normalized.hasIvars) {
            classesWithIvarsCount += 1;
        }
        if (normalized.hasMethods) {
            classesWithMethodsCount += 1;
        }
    }
    return {
        firstImagePath,
        lastImagePath,
        uniqueImagePathCount: imagePaths.length,
        classesWithImagePathCount,
        rootClassCount,
        classesWithProtocolsCount,
        classesWithPropertiesCount,
        classesWithIvarsCount,
        classesWithMethodsCount,
        totalProtocolCount,
        totalPropertyCount,
        totalIvarCount,
        totalMethodCount,
        totalInstanceSize,
        imagePaths,
    };
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

function summarizeObjcProtocols(protocols) {
    const imagePaths = [];
    let protocolsWithImagePathCount = 0;
    let protocolsWithAdoptedProtocolsCount = 0;
    let protocolsWithRequiredMethodsCount = 0;
    let protocolsWithOptionalMethodsCount = 0;
    let protocolsWithInstanceMethodsCount = 0;
    let protocolsWithClassMethodsCount = 0;
    let protocolsWithPropertiesCount = 0;
    let firstImagePath = null;
    let lastImagePath = null;
    let totalAdoptedProtocolCount = 0;
    let totalRequiredMethodCount = 0;
    let totalOptionalMethodCount = 0;
    let totalPropertyCount = 0;
    for (const protocolName of protocols) {
        const info = ObjC.protocolInfo(protocolName);
        const normalized = info === null ? null : normalizeObjcProtocolInfo(info);
        if (normalized === null) {
            continue;
        }
        totalAdoptedProtocolCount += normalized.adoptedProtocolCount;
        totalRequiredMethodCount += normalized.requiredInstanceMethodCount + normalized.requiredClassMethodCount;
        totalOptionalMethodCount += normalized.optionalInstanceMethodCount + normalized.optionalClassMethodCount;
        totalPropertyCount += normalized.propertyCount;
        if (normalized.hasImagePath) {
            protocolsWithImagePathCount += 1;
            if (firstImagePath === null) {
                firstImagePath = normalized.imagePath;
            }
            lastImagePath = normalized.imagePath;
            let imageSummary = imagePaths.find((item) => item.imagePath === normalized.imagePath);
            if (imageSummary === undefined) {
                imageSummary = {
                    imagePath: normalized.imagePath,
                    count: 0,
                    firstProtocol: normalized.protocolName,
                    lastProtocol: normalized.protocolName,
                };
                imagePaths.push(imageSummary);
            }
            imageSummary.count += 1;
            imageSummary.lastProtocol = normalized.protocolName;
        }
        if (normalized.hasAdoptedProtocols) {
            protocolsWithAdoptedProtocolsCount += 1;
        }
        if (normalized.hasRequiredMethods) {
            protocolsWithRequiredMethodsCount += 1;
        }
        if (normalized.hasOptionalMethods) {
            protocolsWithOptionalMethodsCount += 1;
        }
        if (normalized.hasInstanceMethods) {
            protocolsWithInstanceMethodsCount += 1;
        }
        if (normalized.hasClassMethods) {
            protocolsWithClassMethodsCount += 1;
        }
        if (normalized.hasProperties) {
            protocolsWithPropertiesCount += 1;
        }
    }
    return {
        firstImagePath,
        lastImagePath,
        uniqueImagePathCount: imagePaths.length,
        protocolsWithImagePathCount,
        protocolsWithAdoptedProtocolsCount,
        protocolsWithRequiredMethodsCount,
        protocolsWithOptionalMethodsCount,
        protocolsWithInstanceMethodsCount,
        protocolsWithClassMethodsCount,
        protocolsWithPropertiesCount,
        totalAdoptedProtocolCount,
        totalRequiredMethodCount,
        totalOptionalMethodCount,
        totalPropertyCount,
        imagePaths,
    };
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

function summarizeObjcProperties(properties) {
    const ownerships = [];
    const objectClasses = [];
    let readonlyPropertyCount = 0;
    let readwritePropertyCount = 0;
    let atomicPropertyCount = 0;
    let nonatomicPropertyCount = 0;
    let dynamicPropertyCount = 0;
    let strongPropertyCount = 0;
    let copyPropertyCount = 0;
    let weakPropertyCount = 0;
    let assignPropertyCount = 0;
    let objectPropertyCount = 0;
    let blockPropertyCount = 0;
    let propertiesWithAccessorCustomizationCount = 0;
    let propertiesWithBackingIvarCount = 0;
    let propertiesWithObjectProtocolsCount = 0;
    let propertiesWithTypeInfoCount = 0;
    let propertiesWithParsedTokensCount = 0;
    let totalObjectProtocolCount = 0;
    let firstObjectClassName = null;
    let lastObjectClassName = null;
    for (const property of properties) {
        totalObjectProtocolCount += property.objectProtocolCount;
        if (property.isReadonly) {
            readonlyPropertyCount += 1;
        }
        if (property.isReadwrite) {
            readwritePropertyCount += 1;
        }
        if (property.isAtomic) {
            atomicPropertyCount += 1;
        }
        if (property.isNonatomic) {
            nonatomicPropertyCount += 1;
        }
        if (property.isDynamic) {
            dynamicPropertyCount += 1;
        }
        if (property.isStrong) {
            strongPropertyCount += 1;
        }
        if (property.isCopy) {
            copyPropertyCount += 1;
        }
        if (property.isWeak) {
            weakPropertyCount += 1;
        }
        if (property.isAssign) {
            assignPropertyCount += 1;
        }
        if (property.isObject) {
            objectPropertyCount += 1;
        }
        if (property.isBlock) {
            blockPropertyCount += 1;
        }
        if (property.hasAccessorCustomization) {
            propertiesWithAccessorCustomizationCount += 1;
        }
        if (property.hasBackingIvar) {
            propertiesWithBackingIvarCount += 1;
        }
        if (property.hasObjectProtocols) {
            propertiesWithObjectProtocolsCount += 1;
        }
        if (property.hasTypeInfo) {
            propertiesWithTypeInfoCount += 1;
        }
        if (property.hasParsedTokens) {
            propertiesWithParsedTokensCount += 1;
        }
        let ownershipSummary = ownerships.find((item) => item.ownership === property.ownership);
        if (ownershipSummary === undefined) {
            ownershipSummary = {
                ownership: property.ownership,
                count: 0,
                firstProperty: property.name,
                lastProperty: property.name,
            };
            ownerships.push(ownershipSummary);
        }
        ownershipSummary.count += 1;
        ownershipSummary.lastProperty = property.name;
        if (property.hasObjectClassName) {
            if (firstObjectClassName === null) {
                firstObjectClassName = property.objectClassName;
            }
            lastObjectClassName = property.objectClassName;
            let objectClassSummary = objectClasses.find((item) => item.objectClassName === property.objectClassName);
            if (objectClassSummary === undefined) {
                objectClassSummary = {
                    objectClassName: property.objectClassName,
                    count: 0,
                    firstProperty: property.name,
                    lastProperty: property.name,
                };
                objectClasses.push(objectClassSummary);
            }
            objectClassSummary.count += 1;
            objectClassSummary.lastProperty = property.name;
        }
    }
    return {
        readonlyPropertyCount,
        readwritePropertyCount,
        atomicPropertyCount,
        nonatomicPropertyCount,
        dynamicPropertyCount,
        strongPropertyCount,
        copyPropertyCount,
        weakPropertyCount,
        assignPropertyCount,
        objectPropertyCount,
        blockPropertyCount,
        propertiesWithAccessorCustomizationCount,
        propertiesWithBackingIvarCount,
        propertiesWithObjectProtocolsCount,
        propertiesWithTypeInfoCount,
        propertiesWithParsedTokensCount,
        totalObjectProtocolCount,
        firstObjectClassName,
        lastObjectClassName,
        uniqueOwnershipCount: ownerships.length,
        uniqueObjectClassCount: objectClasses.length,
        ownerships,
        objectClasses,
    };
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

function summarizeObjcIvars(ivars) {
    const kinds = [];
    const objectClasses = [];
    let totalQualifierCount = 0;
    let totalObjectProtocolCount = 0;
    let pointerIvarCount = 0;
    let arrayIvarCount = 0;
    let objectIvarCount = 0;
    let blockIvarCount = 0;
    let ivarsWithQualifiersCount = 0;
    let ivarsWithObjectProtocolsCount = 0;
    let ivarsWithObjectClassCount = 0;
    let ivarsWithPointeeTypeCount = 0;
    let ivarsWithMemberNameCount = 0;
    let firstObjectClassName = null;
    let lastObjectClassName = null;
    let minOffset = null;
    let maxOffset = null;
    for (const ivar of ivars) {
        const offset = BigInt(ivar.offset);
        totalQualifierCount += ivar.qualifierCount;
        totalObjectProtocolCount += ivar.objectProtocolCount;
        if (minOffset === null || offset < minOffset) {
            minOffset = offset;
        }
        if (maxOffset === null || offset > maxOffset) {
            maxOffset = offset;
        }
        if (ivar.isPointer) {
            pointerIvarCount += 1;
        }
        if (ivar.isArray) {
            arrayIvarCount += 1;
        }
        if (ivar.isObject) {
            objectIvarCount += 1;
        }
        if (ivar.isBlock) {
            blockIvarCount += 1;
        }
        if (ivar.hasQualifiers) {
            ivarsWithQualifiersCount += 1;
        }
        if (ivar.objectProtocolCount !== 0) {
            ivarsWithObjectProtocolsCount += 1;
        }
        if (ivar.hasObjectClassName) {
            ivarsWithObjectClassCount += 1;
            if (firstObjectClassName === null) {
                firstObjectClassName = ivar.objectClassName;
            }
            lastObjectClassName = ivar.objectClassName;
            let objectClassSummary = objectClasses.find((item) => item.objectClassName === ivar.objectClassName);
            if (objectClassSummary === undefined) {
                objectClassSummary = {
                    objectClassName: ivar.objectClassName,
                    count: 0,
                    firstIvar: ivar.name,
                    lastIvar: ivar.name,
                };
                objectClasses.push(objectClassSummary);
            }
            objectClassSummary.count += 1;
            objectClassSummary.lastIvar = ivar.name;
        }
        if (ivar.hasPointeeType) {
            ivarsWithPointeeTypeCount += 1;
        }
        if (ivar.hasMemberName) {
            ivarsWithMemberNameCount += 1;
        }
        let kindSummary = kinds.find((item) => item.kind === ivar.kind);
        if (kindSummary === undefined) {
            kindSummary = {
                kind: ivar.kind,
                count: 0,
                firstIvar: ivar.name,
                lastIvar: ivar.name,
            };
            kinds.push(kindSummary);
        }
        kindSummary.count += 1;
        kindSummary.lastIvar = ivar.name;
    }
    return {
        totalQualifierCount,
        totalObjectProtocolCount,
        pointerIvarCount,
        arrayIvarCount,
        objectIvarCount,
        blockIvarCount,
        ivarsWithQualifiersCount,
        ivarsWithObjectProtocolsCount,
        ivarsWithObjectClassCount,
        ivarsWithPointeeTypeCount,
        ivarsWithMemberNameCount,
        firstObjectClassName,
        lastObjectClassName,
        minOffsetHex: minOffset === null ? null : '0x' + minOffset.toString(16),
        maxOffsetHex: maxOffset === null ? null : '0x' + maxOffset.toString(16),
        uniqueKindCount: kinds.length,
        uniqueObjectClassCount: objectClasses.length,
        kinds,
        objectClasses,
    };
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
    const normalizedName = name.startsWith('_') ? name.slice(1) : name;
    const dylibOrdinal = Number(imp.dylibOrdinal || 0);
    const dylibName = imp.dylibName === undefined || imp.dylibName === null ? null : String(imp.dylibName);
    const hasDylibName = dylibName !== null;
    const sourcePathKind = dylibName === null ? 'ordinal-only' : classifyLibraryPathKind(dylibName);
    const usesOrdinalOnly = dylibName === null;
    const isMainExecutableImport = dylibOrdinal === -1;
    const isFlatLookupImport = dylibOrdinal === -2;
    const isSelfImport = dylibOrdinal === 0 || dylibName === '<self>';
    const sourceKind = usesOrdinalOnly
        ? 'ordinal-only'
        : isMainExecutableImport || dylibName === '<main-executable>'
            ? 'main-executable'
            : isFlatLookupImport || dylibName === '<dynamic-lookup>'
                ? 'flat-lookup'
                : isSelfImport
                    ? 'self'
                    : 'dylib';
    const source = dylibName === null ? 'ordinal=' + String(dylibOrdinal) : dylibName;
    return {
        moduleName: String(imp.moduleName || ''),
        moduleBase: imp.moduleBase ? imp.moduleBase.toString() : null,
        name,
        normalizedName,
        hasName: name.length !== 0,
        hasNormalizedName: normalizedName.length !== 0,
        nameLength: name.length,
        dylibOrdinal,
        dylibName,
        hasDylibName,
        usesOrdinalOnly,
        isMainExecutableImport,
        isFlatLookupImport,
        isSelfImport,
        weakImport: !!imp.weakImport,
        sourceKind,
        source,
        sourcePathKind,
        isTokenSource: dylibName !== null && dylibName.startsWith('@'),
        usesLoaderPath: dylibName !== null && dylibName.startsWith('@loader_path'),
        usesExecutablePath: dylibName !== null && dylibName.startsWith('@executable_path'),
        usesRpathToken: dylibName !== null && dylibName.startsWith('@rpath'),
        text: formatImport(imp),
    };
}

function normalizeDependency(dep) {
    const path = String(dep.path || '');
    const pathParts = path.split('/').filter(Boolean);
    const name = pathParts.length === 0 ? path : pathParts[pathParts.length - 1];
    const pathKind = classifyLibraryPathKind(path);
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
        pathKind,
        isTokenPath: path.startsWith('@'),
        pathDepth: pathParts.length,
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
    const knownMagic = magicName !== null && magicName !== 'CSMAGIC_UNKNOWN';
    const blobLengthRelation = length === null
        ? 'missing'
        : length === datasize
            ? 'equal'
            : length < datasize
                ? 'smaller'
                : 'larger';
    const blobKind = magicName === null
        ? 'none'
        : magicName === 'CSMAGIC_BLOBWRAPPER'
            ? 'blob-wrapper'
            : magicName === 'CSMAGIC_EMBEDDED_SIGNATURE_OLD'
                ? 'embedded-signature-old'
                : magicName === 'CSMAGIC_REQUIREMENT'
                    ? 'requirement'
                    : magicName === 'CSMAGIC_REQUIREMENTS'
                        ? 'requirements'
                        : magicName === 'CSMAGIC_CODEDIRECTORY'
                            ? 'code-directory'
                            : magicName === 'CSMAGIC_EMBEDDED_ENTITLEMENTS'
                                ? 'entitlements'
                                : magicName === 'CSMAGIC_EMBEDDED_SIGNATURE'
                                    ? 'embedded-signature'
                                    : magicName === 'CSMAGIC_DETACHED_SIGNATURE'
                                        ? 'detached-signature'
                                        : magicName === 'CSMAGIC_EMBEDDED_ENTITLEMENTS_DER'
                                            ? 'entitlements-der'
                                            : magicName === 'CSMAGIC_EMBEDDED_LAUNCH_CONSTRAINT'
                                                ? 'launch-constraint'
                                                : 'unknown';
    const magicCategory = magicName === null
        ? 'none'
        : magicName === 'CSMAGIC_BLOBWRAPPER'
            ? 'wrapper'
            : magicName === 'CSMAGIC_EMBEDDED_SIGNATURE_OLD' || magicName === 'CSMAGIC_EMBEDDED_SIGNATURE' || magicName === 'CSMAGIC_DETACHED_SIGNATURE'
                ? 'signature'
                : magicName === 'CSMAGIC_REQUIREMENT' || magicName === 'CSMAGIC_REQUIREMENTS'
                    ? 'requirements'
                    : magicName === 'CSMAGIC_CODEDIRECTORY'
                        ? 'code-directory'
                        : magicName === 'CSMAGIC_EMBEDDED_ENTITLEMENTS' || magicName === 'CSMAGIC_EMBEDDED_ENTITLEMENTS_DER'
                            ? 'entitlements'
                            : magicName === 'CSMAGIC_EMBEDDED_LAUNCH_CONSTRAINT'
                                ? 'launch-constraint'
                                : 'unknown';
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
        hasMagicName: magicName !== null,
        knownMagic,
        magicCategory,
        blobKind,
        lengthHex: length === null ? null : '0x' + length.toString(16),
        count: codeSignature.count === null || codeSignature.count === undefined ? null : Number(codeSignature.count),
        hasCount: codeSignature.count !== null && codeSignature.count !== undefined,
        hasData: datasize !== 0n,
        hasBlobLength: length !== null,
        blobLengthMatchesDataSize: length === null ? null : length === datasize,
        blobLengthRelation,
        isSuperBlob: magicName === 'CSMAGIC_EMBEDDED_SIGNATURE',
        countMatchesSuperBlob: magicName === null ? null : (magicName === 'CSMAGIC_EMBEDDED_SIGNATURE' || magicName === 'CSMAGIC_DETACHED_SIGNATURE')
            ? codeSignature.count !== null && codeSignature.count !== undefined
            : codeSignature.count === null || codeSignature.count === undefined,
        isDetachedSignature: magicName === 'CSMAGIC_DETACHED_SIGNATURE',
        isBlobWrapper: magicName === 'CSMAGIC_BLOBWRAPPER',
        isCodeDirectory: magicName === 'CSMAGIC_CODEDIRECTORY',
        isEntitlements: magicName === 'CSMAGIC_EMBEDDED_ENTITLEMENTS' || magicName === 'CSMAGIC_EMBEDDED_ENTITLEMENTS_DER',
        text: formatCodeSignature(codeSignature),
    };
}

function normalizeDataInCodeEntry(entry) {
    const kindName = String(entry.kindName || 'DICE_KIND_UNKNOWN');
    const length = Number(entry.length || 0);
    return {
        offsetHex: '0x' + BigInt(entry.offset || 0).toString(16),
        address: entry.address.toString(),
        endOffsetHex: formatHexAdd(entry.offset, length),
        endAddress: formatHexAdd(entry.address, length),
        length,
        kind: Number(entry.kind || 0),
        kindName,
        hasKnownKind: kindName !== 'DICE_KIND_UNKNOWN',
        isData: kindName === 'DICE_KIND_DATA',
        isJumpTable: kindName === 'DICE_KIND_JUMP_TABLE8' || kindName === 'DICE_KIND_JUMP_TABLE16' || kindName === 'DICE_KIND_JUMP_TABLE32' || kindName === 'DICE_KIND_ABS_JUMP_TABLE32',
        isAbsJumpTable: kindName === 'DICE_KIND_ABS_JUMP_TABLE32',
        text: formatDataInCodeEntry(entry),
    };
}

function normalizeDataInCode(dataInCode) {
    const entries = Array.isArray(dataInCode.entries)
        ? dataInCode.entries.map((entry) => normalizeDataInCodeEntry(entry))
        : [];
    const firstEntry = entries.length === 0 ? null : entries[0];
    const lastEntry = entries.length === 0 ? null : entries[entries.length - 1];
    const largestEntry = entries.reduce((largest, entry) => {
        if (largest === null || entry.length > largest.length) {
            return entry;
        }
        return largest;
    }, null);
    const totalEntryLength = entries.reduce((sum, entry) => sum + BigInt(entry.length || 0), 0n);
    const totalSpan = entries.length === 0
        ? 0n
        : (BigInt(lastEntry.offsetHex) + BigInt(lastEntry.length || 0)) - BigInt(firstEntry.offsetHex);
    const kindSummaries = [];
    for (const entry of entries) {
        let summary = kindSummaries.find((item) => item.kind === entry.kind && item.kindName === entry.kindName);
        if (summary === undefined) {
            summary = {
                kind: entry.kind,
                kindName: entry.kindName,
                count: 0,
                totalLength: 0n,
                firstOffsetHex: entry.offsetHex,
                lastOffsetHex: entry.offsetHex,
                hasKnownKind: entry.hasKnownKind,
                isData: entry.isData,
                isJumpTable: entry.isJumpTable,
                isAbsJumpTable: entry.isAbsJumpTable,
            };
            kindSummaries.push(summary);
        }
        summary.count += 1;
        summary.totalLength += BigInt(entry.length || 0);
        summary.lastOffsetHex = entry.offsetHex;
    }
    const kinds = kindSummaries.map((summary) => ({
        kind: summary.kind,
        kindName: summary.kindName,
        count: summary.count,
        totalLengthHex: '0x' + summary.totalLength.toString(16),
        firstOffsetHex: summary.firstOffsetHex,
        lastOffsetHex: summary.lastOffsetHex,
        hasKnownKind: summary.hasKnownKind,
        isData: summary.isData,
        isJumpTable: summary.isJumpTable,
        isAbsJumpTable: summary.isAbsJumpTable,
    }));
    const dataEntryCount = entries.filter((entry) => entry.isData).length;
    const jumpTableEntryCount = entries.filter((entry) => entry.isJumpTable).length;
    const unknownEntryCount = entries.filter((entry) => !entry.hasKnownKind).length;
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
        hasData: BigInt(dataInCode.datasize || 0) !== 0n,
        totalEntryLength: '0x' + totalEntryLength.toString(16),
        totalSpanHex: '0x' + totalSpan.toString(16),
        firstEntryOffsetHex: firstEntry === null ? null : firstEntry.offsetHex,
        firstEntryAddress: firstEntry === null ? null : firstEntry.address,
        firstKindName: firstEntry === null ? null : firstEntry.kindName,
        lastEntryOffsetHex: lastEntry === null ? null : lastEntry.offsetHex,
        lastEntryAddress: lastEntry === null ? null : lastEntry.address,
        lastKindName: lastEntry === null ? null : lastEntry.kindName,
        largestEntryOffsetHex: largestEntry === null ? null : largestEntry.offsetHex,
        largestEntryAddress: largestEntry === null ? null : largestEntry.address,
        largestEntryLength: largestEntry === null ? null : largestEntry.length,
        uniqueKindCount: kinds.length,
        hasMultipleKinds: kinds.length > 1,
        dataEntryCount,
        hasDataEntries: dataEntryCount !== 0,
        jumpTableEntryCount,
        hasJumpTables: jumpTableEntryCount !== 0,
        unknownEntryCount,
        hasUnknownKinds: unknownEntryCount !== 0,
        kinds,
        entries,
        text: formatDataInCode(dataInCode),
    };
}

function normalizeExportsTrieEntry(entry) {
    const name = String(entry.name || '');
    const kind = String(entry.kind || 'unknown');
    const hasAddress = entry.address !== null && entry.address !== undefined;
    const hasOffset = entry.offset !== null && entry.offset !== undefined;
    const hasOther = entry.other !== null && entry.other !== undefined;
    const hasImportName = entry.importName !== null && entry.importName !== undefined;
    const otherRole = !hasOther
        ? 'none'
        : entry.isReexport
            ? 'reexport-ordinal'
            : entry.isStubAndResolver
                ? 'resolver-offset'
                : 'other';
    return {
        name,
        nameLength: name.length,
        hasName: name.length !== 0,
        flagsHex: '0x' + BigInt(entry.flags || 0).toString(16),
        kind,
        address: hasAddress ? entry.address.toString() : null,
        hasAddress,
        offsetHex: entry.offset === null || entry.offset === undefined ? null : '0x' + BigInt(entry.offset).toString(16),
        hasOffset,
        otherHex: entry.other === null || entry.other === undefined ? null : '0x' + BigInt(entry.other).toString(16),
        hasOther,
        otherRole,
        importName: entry.importName === null || entry.importName === undefined ? null : String(entry.importName),
        hasImportName,
        isWeakDefinition: !!entry.isWeakDefinition,
        isReexport: !!entry.isReexport,
        isStubAndResolver: !!entry.isStubAndResolver,
        hasResolver: !!entry.isStubAndResolver && hasOther,
        text: formatExportsTrieEntry(entry),
    };
}

function normalizeExportsTrie(exportsTrie) {
    const entries = Array.isArray(exportsTrie.entries)
        ? exportsTrie.entries.map((entry) => normalizeExportsTrieEntry(entry))
        : [];
    const entriesWithAddress = entries.filter((entry) => entry.hasAddress);
    const entriesWithOffset = entries.filter((entry) => entry.hasOffset);
    const entriesWithImportName = entries.filter((entry) => entry.hasImportName);
    const entriesWithResolver = entries.filter((entry) => entry.hasResolver);
    const reexportCount = entries.filter((entry) => entry.isReexport).length;
    const stubAndResolverCount = entries.filter((entry) => entry.isStubAndResolver).length;
    const weakDefinitionCount = entries.filter((entry) => entry.isWeakDefinition).length;
    const longestExport = entries.reduce((longest, entry) => {
        if (longest === null || entry.nameLength > longest.nameLength) {
            return entry;
        }
        return longest;
    }, null);
    const lowestAddressEntry = entriesWithAddress.reduce((lowest, entry) => {
        if (lowest === null || BigInt(entry.address) < BigInt(lowest.address)) {
            return entry;
        }
        return lowest;
    }, null);
    const highestAddressEntry = entriesWithAddress.reduce((highest, entry) => {
        if (highest === null || BigInt(entry.address) > BigInt(highest.address)) {
            return entry;
        }
        return highest;
    }, null);
    const lowestOffsetEntry = entriesWithOffset.reduce((lowest, entry) => {
        if (lowest === null || BigInt(entry.offsetHex) < BigInt(lowest.offsetHex)) {
            return entry;
        }
        return lowest;
    }, null);
    const highestOffsetEntry = entriesWithOffset.reduce((highest, entry) => {
        if (highest === null || BigInt(entry.offsetHex) > BigInt(highest.offsetHex)) {
            return entry;
        }
        return highest;
    }, null);
    const addressSpanHex = lowestAddressEntry === null || highestAddressEntry === null
        ? '0x0'
        : '0x' + (BigInt(highestAddressEntry.address) - BigInt(lowestAddressEntry.address)).toString(16);
    const offsetSpanHex = lowestOffsetEntry === null || highestOffsetEntry === null
        ? '0x0'
        : '0x' + (BigInt(highestOffsetEntry.offsetHex) - BigInt(lowestOffsetEntry.offsetHex)).toString(16);
    const kindSummaries = [];
    for (const entry of entries) {
        let summary = kindSummaries.find((item) => item.kind === entry.kind);
        if (summary === undefined) {
            summary = {
                kind: entry.kind,
                count: 0,
                firstExportName: entry.name,
                lastExportName: entry.name,
                hasAddress: false,
                hasOffset: false,
                hasImportName: false,
                weakDefinitionCount: 0,
                reexportCount: 0,
                stubAndResolverCount: 0,
            };
            kindSummaries.push(summary);
        }
        summary.count += 1;
        summary.lastExportName = entry.name;
        summary.hasAddress = summary.hasAddress || entry.hasAddress;
        summary.hasOffset = summary.hasOffset || entry.hasOffset;
        summary.hasImportName = summary.hasImportName || entry.hasImportName;
        if (entry.isWeakDefinition) {
            summary.weakDefinitionCount += 1;
        }
        if (entry.isReexport) {
            summary.reexportCount += 1;
        }
        if (entry.isStubAndResolver) {
            summary.stubAndResolverCount += 1;
        }
    }
    const kinds = kindSummaries.map((summary) => ({
        kind: summary.kind,
        count: summary.count,
        firstExportName: summary.firstExportName,
        lastExportName: summary.lastExportName,
        hasAddress: summary.hasAddress,
        hasOffset: summary.hasOffset,
        hasImportName: summary.hasImportName,
        weakDefinitionCount: summary.weakDefinitionCount,
        reexportCount: summary.reexportCount,
        stubAndResolverCount: summary.stubAndResolverCount,
    }));
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
        hasData: BigInt(exportsTrie.datasize || 0) !== 0n,
        firstExportName: entries.length === 0 ? null : entries[0].name,
        firstKind: entries.length === 0 ? null : entries[0].kind,
        lastExportName: entries.length === 0 ? null : entries[entries.length - 1].name,
        lastKind: entries.length === 0 ? null : entries[entries.length - 1].kind,
        longestExportName: longestExport === null ? null : longestExport.name,
        longestExportNameLength: longestExport === null ? null : longestExport.nameLength,
        uniqueKindCount: kinds.length,
        hasMultipleKinds: kinds.length > 1,
        kinds,
        addressEntryCount: entriesWithAddress.length,
        hasAddressEntries: entriesWithAddress.length !== 0,
        lowestAddress: lowestAddressEntry === null ? null : lowestAddressEntry.address,
        highestAddress: highestAddressEntry === null ? null : highestAddressEntry.address,
        addressSpanHex,
        offsetEntryCount: entriesWithOffset.length,
        hasOffsetEntries: entriesWithOffset.length !== 0,
        lowestOffsetHex: lowestOffsetEntry === null ? null : lowestOffsetEntry.offsetHex,
        highestOffsetHex: highestOffsetEntry === null ? null : highestOffsetEntry.offsetHex,
        offsetSpanHex,
        importNameCount: entriesWithImportName.length,
        hasImportNames: entriesWithImportName.length !== 0,
        resolverCount: entriesWithResolver.length,
        hasResolvers: entriesWithResolver.length !== 0,
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
    const hasPageStart = page.pageStart !== null && page.pageStart !== undefined;
    return {
        pageIndex: Number(page.pageIndex || 0),
        hasFixups: !!page.hasFixups,
        pageStartHex: page.pageStart === null || page.pageStart === undefined ? null : '0x' + BigInt(page.pageStart).toString(16),
        hasPageStart,
        usesMultipleStarts: !!page.usesMultipleStarts,
        chainStartCount: chainStarts.length,
        hasChainStarts: chainStarts.length !== 0,
        effectiveStartCount: chainStarts.length !== 0 ? chainStarts.length : (page.hasFixups ? 1 : 0),
        firstChainStartHex: chainStarts.length === 0 ? null : chainStarts[0],
        lastChainStartHex: chainStarts.length === 0 ? null : chainStarts[chainStarts.length - 1],
        chainStarts,
    };
}

function normalizeChainedFixupsSegment(segment) {
    const pages = Array.isArray(segment.pages)
        ? segment.pages.map((page) => normalizeChainedFixupsPage(page))
        : [];
    const fixupPages = pages.filter((page) => page.hasFixups);
    const multiStartPages = pages.filter((page) => page.usesMultipleStarts);
    const chainStartCount = pages.reduce((sum, page) => sum + Number(page.effectiveStartCount || 0), 0);
    const largestPage = pages.reduce((largest, page) => {
        if (largest === null || Number(page.effectiveStartCount || 0) > Number(largest.effectiveStartCount || 0)) {
            return page;
        }
        return largest;
    }, null);
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
        hasFixupPages: fixupPages.length !== 0,
        hasPages: pages.length !== 0,
        firstPageIndex: pages.length === 0 ? null : pages[0].pageIndex,
        lastPageIndex: pages.length === 0 ? null : pages[pages.length - 1].pageIndex,
        firstFixupPageIndex: fixupPages.length === 0 ? null : fixupPages[0].pageIndex,
        lastFixupPageIndex: fixupPages.length === 0 ? null : fixupPages[fixupPages.length - 1].pageIndex,
        pageWithFixupsCount: fixupPages.length,
        pageWithoutFixupsCount: pages.length - fixupPages.length,
        multiStartPageCount: multiStartPages.length,
        chainStartCount,
        largestPageIndex: largestPage === null ? null : largestPage.pageIndex,
        largestPageStartCount: largestPage === null ? null : Number(largestPage.effectiveStartCount || 0),
        pages,
        text: formatChainedFixupsSegment(segment),
    };
}

function normalizeChainedFixupsImport(imp) {
    const hasAddend = imp.addend !== null && imp.addend !== undefined;
    const hasName = imp.name !== null && imp.name !== undefined;
    return {
        index: Number(imp.index || 0),
        libOrdinalRawHex: '0x' + BigInt(imp.libOrdinalRaw || 0).toString(16),
        libOrdinal: Number(imp.libOrdinal || 0),
        weakImport: !!imp.weakImport,
        nameOffsetHex: '0x' + BigInt(imp.nameOffset || 0).toString(16),
        name: imp.name === null || imp.name === undefined ? null : String(imp.name),
        hasName,
        nameLength: hasName ? String(imp.name).length : 0,
        addend: imp.addend === null || imp.addend === undefined ? null : imp.addend.toString(),
        hasAddend,
        addendSign: !hasAddend ? 'none' : BigInt(imp.addend) === 0n ? 'zero' : BigInt(imp.addend) > 0n ? 'positive' : 'negative',
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
    const pointerFormatSummaries = [];
    for (const segment of segments) {
        let summary = pointerFormatSummaries.find((item) => item.pointerFormat === segment.pointerFormat);
        if (summary === undefined) {
            summary = {
                pointerFormat: segment.pointerFormat,
                pointerFormatName: segment.pointerFormatName,
                count: 0,
                segmentIndices: [],
                totalPageCount: 0,
                totalFixupPageCount: 0,
            };
            pointerFormatSummaries.push(summary);
        }
        summary.count += 1;
        summary.segmentIndices.push(segment.segmentIndex);
        summary.totalPageCount += segment.pageCount;
        summary.totalFixupPageCount += segment.fixupPageCount;
    }
    const pointerFormats = pointerFormatSummaries.map((summary) => ({
        pointerFormat: summary.pointerFormat,
        pointerFormatName: summary.pointerFormatName,
        count: summary.count,
        firstSegmentIndex: summary.segmentIndices.length === 0 ? null : summary.segmentIndices[0],
        lastSegmentIndex: summary.segmentIndices.length === 0 ? null : summary.segmentIndices[summary.segmentIndices.length - 1],
        totalPageCount: summary.totalPageCount,
        totalFixupPageCount: summary.totalFixupPageCount,
    }));
    const dominantPointerFormat = pointerFormats.reduce((dominant, summary) => {
        if (dominant === null || summary.count > dominant.count) {
            return summary;
        }
        return dominant;
    }, null);
    const totalPageCount = segments.reduce((sum, segment) => sum + Number(segment.pageCount || 0), 0);
    const totalFixupPageCount = segments.reduce((sum, segment) => sum + Number(segment.fixupPageCount || 0), 0);
    const totalMultiStartPageCount = segments.reduce((sum, segment) => sum + Number(segment.multiStartPageCount || 0), 0);
    const totalChainStartCount = segments.reduce((sum, segment) => sum + Number(segment.chainStartCount || 0), 0);
    const segmentsWithFixups = segments.filter((segment) => segment.hasFixupPages);
    const largestSegment = segments.reduce((largest, segment) => {
        if (largest === null || BigInt(segment.sizeHex) > BigInt(largest.sizeHex)) {
            return segment;
        }
        return largest;
    }, null);
    const namedImports = imports.filter((imp) => imp.hasName);
    const weakImports = imports.filter((imp) => imp.weakImport);
    const addendImports = imports.filter((imp) => imp.hasAddend);
    const negativeAddendImports = imports.filter((imp) => imp.addendSign === 'negative');
    const libOrdinalSummaries = [];
    for (const imp of imports) {
        let summary = libOrdinalSummaries.find((item) => item.libOrdinal === imp.libOrdinal);
        if (summary === undefined) {
            summary = {
                libOrdinal: imp.libOrdinal,
                count: 0,
                weakImportCount: 0,
                namedImportCount: 0,
                addendImportCount: 0,
            };
            libOrdinalSummaries.push(summary);
        }
        summary.count += 1;
        if (imp.weakImport) {
            summary.weakImportCount += 1;
        }
        if (imp.hasName) {
            summary.namedImportCount += 1;
        }
        if (imp.hasAddend) {
            summary.addendImportCount += 1;
        }
    }
    const libOrdinals = libOrdinalSummaries.map((summary) => ({
        libOrdinal: summary.libOrdinal,
        count: summary.count,
        weakImportCount: summary.weakImportCount,
        namedImportCount: summary.namedImportCount,
        addendImportCount: summary.addendImportCount,
    }));
    const startsOffset = BigInt(chainedFixups.startsOffset || 0);
    const importsOffset = BigInt(chainedFixups.importsOffset || 0);
    const symbolsOffset = BigInt(chainedFixups.symbolsOffset || 0);
    return {
        moduleName: String(chainedFixups.moduleName || ''),
        moduleBase: chainedFixups.moduleBase ? chainedFixups.moduleBase.toString() : null,
        dataoffHex: '0x' + BigInt(chainedFixups.dataoff || 0).toString(16),
        datasizeHex: '0x' + BigInt(chainedFixups.datasize || 0).toString(16),
        linkeditBase: chainedFixups.linkeditBase.toString(),
        dataAddress: chainedFixups.dataAddress.toString(),
        dataEnd: formatHexAdd(chainedFixups.dataAddress, chainedFixups.datasize),
        hasData: BigInt(chainedFixups.datasize || 0) !== 0n,
        fixupsVersion: Number(chainedFixups.fixupsVersion || 0),
        startsOffsetHex: '0x' + BigInt(chainedFixups.startsOffset || 0).toString(16),
        startsAddress: formatHexAdd(chainedFixups.dataAddress, chainedFixups.startsOffset),
        importsOffsetHex: '0x' + BigInt(chainedFixups.importsOffset || 0).toString(16),
        importsAddress: formatHexAdd(chainedFixups.dataAddress, chainedFixups.importsOffset),
        symbolsOffsetHex: '0x' + BigInt(chainedFixups.symbolsOffset || 0).toString(16),
        symbolsAddress: formatHexAdd(chainedFixups.dataAddress, chainedFixups.symbolsOffset),
        startsBeforeImports: startsOffset <= importsOffset,
        importsBeforeSymbols: importsOffset <= symbolsOffset,
        offsetsMonotonic: startsOffset <= importsOffset && importsOffset <= symbolsOffset,
        startsToImportsDeltaHex: '0x' + (importsOffset >= startsOffset ? importsOffset - startsOffset : startsOffset - importsOffset).toString(16),
        importsToSymbolsDeltaHex: '0x' + (symbolsOffset >= importsOffset ? symbolsOffset - importsOffset : importsOffset - symbolsOffset).toString(16),
        importsCount: Number(chainedFixups.importsCount || 0),
        importsFormat: Number(chainedFixups.importsFormat || 0),
        importsFormatName: String(chainedFixups.importsFormatName || 'DYLD_CHAINED_IMPORT_UNKNOWN'),
        symbolsFormat: Number(chainedFixups.symbolsFormat || 0),
        symbolsFormatName: String(chainedFixups.symbolsFormatName || 'unknown'),
        segmentCount: segments.length,
        hasSegments: segments.length !== 0,
        firstSegmentIndex: segments.length === 0 ? null : segments[0].segmentIndex,
        lastSegmentIndex: segments.length === 0 ? null : segments[segments.length - 1].segmentIndex,
        totalPageCount,
        totalFixupPageCount,
        totalMultiStartPageCount,
        totalChainStartCount,
        segmentWithFixupsCount: segmentsWithFixups.length,
        hasSegmentsWithFixups: segmentsWithFixups.length !== 0,
        largestSegmentIndex: largestSegment === null ? null : largestSegment.segmentIndex,
        largestSegmentSizeHex: largestSegment === null ? null : largestSegment.sizeHex,
        pointerFormatCount: pointerFormats.length,
        hasMultiplePointerFormats: pointerFormats.length > 1,
        firstPointerFormatName: segments.length === 0 ? null : segments[0].pointerFormatName,
        lastPointerFormatName: segments.length === 0 ? null : segments[segments.length - 1].pointerFormatName,
        dominantPointerFormatName: dominantPointerFormat === null ? null : dominantPointerFormat.pointerFormatName,
        pointerFormats,
        importCount: imports.length,
        hasImports: imports.length !== 0,
        firstImportName: imports.length === 0 ? null : imports[0].name,
        lastImportName: imports.length === 0 ? null : imports[imports.length - 1].name,
        namedImportCount: namedImports.length,
        hasNamedImports: namedImports.length !== 0,
        weakImportCount: weakImports.length,
        hasWeakImports: weakImports.length !== 0,
        addendImportCount: addendImports.length,
        hasAddendImports: addendImports.length !== 0,
        negativeAddendImportCount: negativeAddendImports.length,
        hasNegativeAddends: negativeAddendImports.length !== 0,
        uniqueLibOrdinalCount: libOrdinals.length,
        firstLibOrdinal: imports.length === 0 ? null : imports[0].libOrdinal,
        lastLibOrdinal: imports.length === 0 ? null : imports[imports.length - 1].libOrdinal,
        libOrdinals,
        segments,
        imports,
        text: formatChainedFixups(chainedFixups),
    };
}

function normalizeSourceVersion(sourceVersion) {
    const version = String(sourceVersion.version || '');
    const versionParts = splitVersionComponents(version);
    return {
        moduleName: String(sourceVersion.moduleName || ''),
        moduleBase: sourceVersion.moduleBase ? sourceVersion.moduleBase.toString() : null,
        version,
        hasVersion: version.length !== 0,
        versionPartCount: versionParts.length,
        majorVersion: versionParts.length === 0 ? null : versionParts[0],
        minorVersion: versionParts.length < 2 ? null : versionParts[1],
        patchVersion: versionParts.length < 3 ? null : versionParts[2],
        extraVersionCount: versionParts.length <= 3 ? 0 : versionParts.length - 3,
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
    const minOs = String(buildVersion.minOs || '');
    const sdk = String(buildVersion.sdk || '');
    const minOsParts = splitVersionComponents(minOs);
    const sdkParts = splitVersionComponents(sdk);
    return {
        moduleName: String(buildVersion.moduleName || ''),
        moduleBase: buildVersion.moduleBase ? buildVersion.moduleBase.toString() : null,
        platform: String(buildVersion.platform || 'unknown'),
        minOs,
        sdk,
        hasMinOs: minOs.length !== 0,
        hasSdk: sdk.length !== 0,
        minOsPartCount: minOsParts.length,
        sdkPartCount: sdkParts.length,
        hasTools: tools.length !== 0,
        firstTool: tools.length === 0 ? null : tools[0].tool,
        lastTool: tools.length === 0 ? null : tools[tools.length - 1].tool,
        firstToolVersion: tools.length === 0 ? null : tools[0].version,
        lastToolVersion: tools.length === 0 ? null : tools[tools.length - 1].version,
        uniqueToolCount: Array.from(new Set(tools.map((tool) => tool.tool))).length,
        toolNames: tools.map((tool) => tool.tool),
        tools,
        text: formatBuildVersion(buildVersion),
    };
}

function normalizeDylinker(dylinker) {
    const path = String(dylinker.path || '');
    const pathParts = path.split('/').filter(Boolean);
    const kind = String(dylinker.kind || 'load');
    return {
        moduleName: String(dylinker.moduleName || ''),
        moduleBase: dylinker.moduleBase ? dylinker.moduleBase.toString() : null,
        path,
        name: pathParts.length === 0 ? path : pathParts[pathParts.length - 1],
        hasName: (pathParts.length === 0 ? path : pathParts[pathParts.length - 1]).length !== 0,
        hasPath: path.length !== 0,
        pathKind: classifyLibraryPathKind(path),
        isTokenPath: path.startsWith('@'),
        usesLoaderPath: path.startsWith('@loader_path'),
        usesExecutablePath: path.startsWith('@executable_path'),
        usesRpathToken: path.startsWith('@rpath'),
        pathDepth: pathParts.length,
        kind,
        isWeakDylinker: kind === 'weak',
        isReexportDylinker: kind === 'reexport',
        isUpwardDylinker: kind === 'upward',
        isLoadDylinker: kind === 'load',
        text: formatDylinker(dylinker),
    };
}

function normalizeInstallName(installName) {
    const path = String(installName.path || '');
    const pathParts = path.split('/').filter(Boolean);
    const currentVersion = formatPackedVersion(installName.currentVersion);
    const compatibilityVersion = formatPackedVersion(installName.compatibilityVersion);
    return {
        moduleName: String(installName.moduleName || ''),
        moduleBase: installName.moduleBase ? installName.moduleBase.toString() : null,
        path,
        name: pathParts.length === 0 ? path : pathParts[pathParts.length - 1],
        hasName: (pathParts.length === 0 ? path : pathParts[pathParts.length - 1]).length !== 0,
        hasPath: path.length !== 0,
        pathKind: classifyLibraryPathKind(path),
        isTokenPath: path.startsWith('@'),
        usesLoaderPath: path.startsWith('@loader_path'),
        usesExecutablePath: path.startsWith('@executable_path'),
        usesRpathToken: path.startsWith('@rpath'),
        pathDepth: pathParts.length,
        currentVersion,
        compatibilityVersion,
        timestamp: Number(installName.timestamp || 0),
        hasTimestamp: Number(installName.timestamp || 0) !== 0,
        versionMismatch: currentVersion !== compatibilityVersion,
        text: formatInstallName(installName),
    };
}

function normalizeUuid(imageUuid) {
    const uuid = String(imageUuid.uuid || '');
    const normalizedUuid = uuid.toUpperCase();
    return {
        moduleName: String(imageUuid.moduleName || ''),
        moduleBase: imageUuid.moduleBase ? imageUuid.moduleBase.toString() : null,
        uuid,
        normalizedUuid,
        hasUuid: uuid.length !== 0,
        uuidLength: uuid.length,
        uuidSegmentCount: uuid.length === 0 ? 0 : uuid.split('-').length,
        text: formatUuid(imageUuid),
    };
}

function normalizeRpath(rpath) {
    const path = String(rpath.path || '');
    const pathParts = path.split('/').filter(Boolean);
    const pathKind = classifyLibraryPathKind(path);
    return {
        moduleName: String(rpath.moduleName || ''),
        moduleBase: rpath.moduleBase ? rpath.moduleBase.toString() : null,
        path,
        hasPath: path.length !== 0,
        pathKind,
        isTokenPath: path.startsWith('@'),
        usesLoaderPath: path.startsWith('@loader_path'),
        usesExecutablePath: path.startsWith('@executable_path'),
        usesRpathToken: path.startsWith('@rpath'),
        pathDepth: pathParts.length,
        text: formatRpath(rpath),
    };
}

function normalizeSegment(segment) {
    const name = String(segment.name || '');
    const vmsize = BigInt(segment.vmsize || 0);
    const filesize = BigInt(segment.filesize || 0);
    const initprot = Number(segment.initprot || 0);
    const maxprot = Number(segment.maxprot || 0);
    return {
        moduleName: String(segment.moduleName || ''),
        moduleBase: segment.moduleBase ? segment.moduleBase.toString() : null,
        name,
        hasName: name.length !== 0,
        vmaddr: segment.vmaddr.toString(),
        vmsizeHex: '0x' + vmsize.toString(16),
        vmEnd: formatHexAdd(segment.vmaddr, segment.vmsize),
        fileoffHex: '0x' + BigInt(segment.fileoff || 0).toString(16),
        filesizeHex: '0x' + filesize.toString(16),
        fileEndHex: formatHexAdd(segment.fileoff, segment.filesize),
        hasVmRange: vmsize !== 0n,
        hasFileData: filesize !== 0n,
        isEmpty: vmsize === 0n && filesize === 0n,
        isZeroFillLike: vmsize !== 0n && filesize === 0n,
        vmSizeMatchesFileSize: vmsize === filesize,
        maxprot: String(maxprot),
        maxprotFlags: formatVmProtection(maxprot),
        initprot: String(initprot),
        initprotFlags: formatVmProtection(initprot),
        isReadable: (initprot & 1) !== 0,
        isWritable: (initprot & 2) !== 0,
        isExecutable: (initprot & 4) !== 0,
        maxReadable: (maxprot & 1) !== 0,
        maxWritable: (maxprot & 2) !== 0,
        maxExecutable: (maxprot & 4) !== 0,
        text: formatSegment(segment),
    };
}

function normalizeSection(section) {
    const segmentName = String(section.segmentName || '');
    const name = String(section.name || '');
    const size = BigInt(section.size || 0);
    const alignPower = Number(section.align || 0);
    const flags = BigInt(section.flags || 0);
    const type = Number(flags & 0xffn);
    const typeName = formatSectionType(section.flags);
    const alignmentBytes = 1n << BigInt(alignPower);
    const isZeroFillLike = typeName === 'S_ZEROFILL' || typeName === 'S_GB_ZEROFILL' || typeName === 'S_THREAD_LOCAL_ZEROFILL';
    const isCStringLike = typeName === 'S_CSTRING_LITERALS';
    const isSymbolPointers = typeName === 'S_NON_LAZY_SYMBOL_POINTERS' || typeName === 'S_LAZY_SYMBOL_POINTERS' || typeName === 'S_LAZY_DYLIB_SYMBOL_POINTERS' || typeName === 'S_THREAD_LOCAL_VARIABLE_POINTERS';
    return {
        moduleName: String(section.moduleName || ''),
        moduleBase: section.moduleBase ? section.moduleBase.toString() : null,
        segmentName,
        name,
        fullName: segmentName + ',' + name,
        hasSegmentName: segmentName.length !== 0,
        hasName: name.length !== 0,
        addr: section.addr.toString(),
        sizeHex: '0x' + size.toString(16),
        endAddr: formatHexAdd(section.addr, section.size),
        offsetHex: '0x' + BigInt(section.offset || 0).toString(16),
        align: String(section.align),
        alignPower,
        alignmentBytesHex: '0x' + alignmentBytes.toString(16),
        flagsHex: '0x' + flags.toString(16),
        sectionType: type,
        sectionTypeName: typeName,
        sectionAttributesHex: '0x' + (flags & ~0xffn).toString(16),
        hasData: size !== 0n,
        isEmpty: size === 0n,
        isZeroFillLike,
        isCStringLike,
        isSymbolPointers,
        text: formatSection(section),
    };
}

function classifyLoadCommandFamily(name) {
    const commandName = String(name || '');
    if (commandName === 'LC_RPATH') {
        return 'rpath';
    }
    if (commandName === 'LC_UUID') {
        return 'uuid';
    }
    if (commandName === 'LC_MAIN') {
        return 'entry-point';
    }
    if (commandName === 'LC_BUILD_VERSION' || commandName === 'LC_SOURCE_VERSION' || commandName.startsWith('LC_VERSION_MIN_')) {
        return 'version';
    }
    if (commandName === 'LC_DYLD_INFO' || commandName === 'LC_DYLD_INFO_ONLY') {
        return 'dyld-info';
    }
    if (commandName === 'LC_CODE_SIGNATURE'
            || commandName === 'LC_SEGMENT_SPLIT_INFO'
            || commandName === 'LC_FUNCTION_STARTS'
            || commandName === 'LC_DATA_IN_CODE'
            || commandName === 'LC_DYLIB_CODE_SIGN_DRS'
            || commandName === 'LC_LINKER_OPTIMIZATION_HINT'
            || commandName === 'LC_DYLD_EXPORTS_TRIE'
            || commandName === 'LC_DYLD_CHAINED_FIXUPS') {
        return 'linkedit-data';
    }
    if (commandName.startsWith('LC_ENCRYPTION_INFO')) {
        return 'encryption';
    }
    if (commandName.startsWith('LC_SEGMENT')) {
        return 'segment';
    }
    if (commandName.indexOf('DYLINKER') !== -1) {
        return 'dylinker';
    }
    if (commandName.indexOf('DYLIB') !== -1) {
        return 'dylib';
    }
    return 'other';
}

function parseLoadCommandDetailMap(detail) {
    if (detail === null || detail === undefined) {
        return {};
    }
    const map = {};
    for (const token of String(detail).split(/\s+/).filter(Boolean)) {
        const equalsIndex = token.indexOf('=');
        if (equalsIndex <= 0) {
            continue;
        }
        map[token.slice(0, equalsIndex)] = token.slice(equalsIndex + 1);
    }
    return map;
}

function parseLoadCommandDetail(name, detail) {
    const commandName = String(name || '');
    const commandFamily = classifyLoadCommandFamily(commandName);
    const detailMap = parseLoadCommandDetailMap(detail);
    const path = detailMap.path === undefined
        ? (detailMap.name === undefined ? null : detailMap.name)
        : detailMap.path;
    const pathKind = path === null ? null : classifyLibraryPathKind(path);
    const tools = detailMap.tools === undefined || detailMap.tools === 'none'
        ? []
        : String(detailMap.tools).split(',').filter((item) => item.length !== 0);
    const dyldRegionSpecs = [
        ['rebase', detailMap.rebase],
        ['bind', detailMap.bind],
        ['weakBind', detailMap.weak],
        ['lazyBind', detailMap.lazy],
        ['export', detailMap.export],
    ];
    const dyldRegions = [];
    for (const [regionName, spec] of dyldRegionSpecs) {
        if (spec === undefined) {
            continue;
        }
        const slashIndex = spec.indexOf('/');
        const offset = slashIndex === -1 ? spec : spec.slice(0, slashIndex);
        const size = slashIndex === -1 ? '0x0' : spec.slice(slashIndex + 1);
        dyldRegions.push(normalizeDyldInfoRegion(regionName, offset, size));
    }
    const nonEmptyDyldRegions = dyldRegions.filter((region) => region.hasData);
    const hasPath = path !== null && path.length !== 0;
    const hasTimestamp = detailMap.timestamp !== undefined && detailMap.timestamp !== '0';
    const hasCurrentVersion = detailMap.current !== undefined;
    const hasCompatibilityVersion = detailMap.compat !== undefined;
    const hasVersion = detailMap.version !== undefined;
    const hasSdk = detailMap.sdk !== undefined;
    const hasMinOs = detailMap.minos !== undefined;
    const hasUuid = detailMap.uuid !== undefined;
    const hasDataRange = detailMap.dataoff !== undefined && detailMap.datasize !== undefined;
    const hasEntryPoint = detailMap.entryoff !== undefined;
    const hasEncryptedRange = detailMap.cryptoff !== undefined && detailMap.cryptsize !== undefined && detailMap.cryptid !== undefined;
    return {
        commandFamily,
        path,
        hasPath,
        pathKind,
        isTokenPath: hasPath && path.startsWith('@'),
        usesLoaderPath: hasPath && path.startsWith('@loader_path'),
        usesExecutablePath: hasPath && path.startsWith('@executable_path'),
        usesRpathToken: hasPath && path.startsWith('@rpath'),
        pathDepth: hasPath ? path.split('/').filter(Boolean).length : 0,
        currentVersion: hasCurrentVersion ? detailMap.current : null,
        hasCurrentVersion,
        compatibilityVersion: hasCompatibilityVersion ? detailMap.compat : null,
        hasCompatibilityVersion,
        timestamp: hasTimestamp ? Number(detailMap.timestamp) : null,
        hasTimestamp,
        versionMismatch: hasCurrentVersion && hasCompatibilityVersion && detailMap.current !== detailMap.compat,
        version: hasVersion ? detailMap.version : null,
        hasVersion,
        sdk: hasSdk ? detailMap.sdk : null,
        hasSdk,
        minOs: hasMinOs ? detailMap.minos : null,
        hasMinOs,
        platform: detailMap.platform === undefined ? null : detailMap.platform,
        tools,
        hasTools: tools.length !== 0,
        toolCount: tools.length,
        uniqueToolCount: Array.from(new Set(tools)).length,
        uuid: hasUuid ? detailMap.uuid : null,
        hasUuid,
        uuidLength: hasUuid ? String(detailMap.uuid).length : 0,
        dataoffHex: detailMap.dataoff === undefined ? null : detailMap.dataoff,
        datasizeHex: detailMap.datasize === undefined ? null : detailMap.datasize,
        dataEndHex: hasDataRange ? formatHexAdd(detailMap.dataoff, detailMap.datasize) : null,
        hasDataRange,
        entryoffHex: detailMap.entryoff === undefined ? null : detailMap.entryoff,
        stacksizeHex: detailMap.stacksize === undefined ? null : detailMap.stacksize,
        hasEntryPoint,
        cryptoffHex: detailMap.cryptoff === undefined ? null : detailMap.cryptoff,
        cryptsizeHex: detailMap.cryptsize === undefined ? null : detailMap.cryptsize,
        cryptid: detailMap.cryptid === undefined ? null : Number(detailMap.cryptid),
        hasEncryptedRange,
        dyldRegions,
        dyldRegionCount: dyldRegions.length,
        hasDyldRegions: dyldRegions.length !== 0,
        nonEmptyDyldRegionCount: nonEmptyDyldRegions.length,
        nonEmptyDyldRegionNames: nonEmptyDyldRegions.map((region) => region.name),
    };
}

function normalizeLoadCommand(command) {
    const name = String(command.name || '');
    const detail = command.detail === undefined ? null : command.detail;
    const cmd = BigInt(command.cmd || 0);
    const cmdsize = Number(command.cmdsize || 0);
    const offset = BigInt(command.offset || 0);
    const isReqDyld = (cmd & 0x80000000n) !== 0n;
    const parsedDetail = parseLoadCommandDetail(name, detail);
    return {
        moduleName: String(command.moduleName || ''),
        moduleBase: command.moduleBase ? command.moduleBase.toString() : null,
        index: Number(command.index || 0),
        name,
        hasName: name.length !== 0,
        commandFamily: parsedDetail.commandFamily,
        cmdHex: '0x' + cmd.toString(16),
        cmdBaseHex: '0x' + (cmd & 0x7fffffffn).toString(16),
        isReqDyld,
        cmdsize,
        hasPayload: cmdsize > 8,
        offsetHex: '0x' + offset.toString(16),
        endOffsetHex: '0x' + (offset + BigInt(cmdsize)).toString(16),
        detail,
        hasDetail: detail !== null && String(detail).length !== 0,
        path: parsedDetail.path,
        hasPath: parsedDetail.hasPath,
        pathKind: parsedDetail.pathKind,
        isTokenPath: parsedDetail.isTokenPath,
        usesLoaderPath: parsedDetail.usesLoaderPath,
        usesExecutablePath: parsedDetail.usesExecutablePath,
        usesRpathToken: parsedDetail.usesRpathToken,
        pathDepth: parsedDetail.pathDepth,
        currentVersion: parsedDetail.currentVersion,
        hasCurrentVersion: parsedDetail.hasCurrentVersion,
        compatibilityVersion: parsedDetail.compatibilityVersion,
        hasCompatibilityVersion: parsedDetail.hasCompatibilityVersion,
        timestamp: parsedDetail.timestamp,
        hasTimestamp: parsedDetail.hasTimestamp,
        versionMismatch: parsedDetail.versionMismatch,
        version: parsedDetail.version,
        hasVersion: parsedDetail.hasVersion,
        sdk: parsedDetail.sdk,
        hasSdk: parsedDetail.hasSdk,
        minOs: parsedDetail.minOs,
        hasMinOs: parsedDetail.hasMinOs,
        platform: parsedDetail.platform,
        tools: parsedDetail.tools,
        hasTools: parsedDetail.hasTools,
        toolCount: parsedDetail.toolCount,
        uniqueToolCount: parsedDetail.uniqueToolCount,
        uuid: parsedDetail.uuid,
        hasUuid: parsedDetail.hasUuid,
        uuidLength: parsedDetail.uuidLength,
        dataoffHex: parsedDetail.dataoffHex,
        datasizeHex: parsedDetail.datasizeHex,
        dataEndHex: parsedDetail.dataEndHex,
        hasDataRange: parsedDetail.hasDataRange,
        entryoffHex: parsedDetail.entryoffHex,
        stacksizeHex: parsedDetail.stacksizeHex,
        hasEntryPoint: parsedDetail.hasEntryPoint,
        cryptoffHex: parsedDetail.cryptoffHex,
        cryptsizeHex: parsedDetail.cryptsizeHex,
        cryptid: parsedDetail.cryptid,
        hasEncryptedRange: parsedDetail.hasEncryptedRange,
        dyldRegions: parsedDetail.dyldRegions,
        dyldRegionCount: parsedDetail.dyldRegionCount,
        hasDyldRegions: parsedDetail.hasDyldRegions,
        nonEmptyDyldRegionCount: parsedDetail.nonEmptyDyldRegionCount,
        nonEmptyDyldRegionNames: parsedDetail.nonEmptyDyldRegionNames,
        text: formatLoadCommand(command),
    };
}

function normalizeSwiftSymbol(symbol) {
    const offset = typeof symbol.offset === 'bigint' ? symbol.offset : BigInt(symbol.offset || 0);
    const name = String(symbol.name || '');
    const demangledName = symbol.demangledName === undefined ? null : symbol.demangledName;
    const memberInfo = parseSwiftDemangledMemberInfo(demangledName, name, null, null, { isDispatchThunk: false });
    const normalized = {
        moduleName: String(symbol.moduleName || ''),
        moduleBase: symbol.moduleBase ? symbol.moduleBase.toString() : null,
        name,
        hasName: name.length !== 0,
        demangledName,
        hasDemangledName: demangledName !== null && String(demangledName).length !== 0,
        address: symbol.address.toString(),
        offsetHex: '0x' + offset.toString(16),
        ownerTypeName: memberInfo.ownerTypeName,
        hasOwnerTypeName: memberInfo.ownerTypeName !== null,
        memberName: memberInfo.memberName,
        hasMemberName: memberInfo.memberName !== null,
        memberKind: memberInfo.memberKind,
        signature: memberInfo.signature,
        hasSignature: memberInfo.hasSignature,
        resultTypeName: memberInfo.resultTypeName,
        hasResultTypeName: memberInfo.hasResultTypeName,
        isMember: memberInfo.isMember,
        isAccessor: memberInfo.isAccessor,
        isGetter: memberInfo.isGetter,
        isSetter: memberInfo.isSetter,
        isModifyAccessor: memberInfo.isModifyAccessor,
        isReadAccessor: memberInfo.isReadAccessor,
        isConstructor: memberInfo.isConstructor,
        isDestructor: memberInfo.isDestructor,
        isSubscript: memberInfo.isSubscript,
        isOperator: memberInfo.isOperator,
        isClosure: memberInfo.isClosure,
        isStaticMember: memberInfo.isStaticMember,
        isClassMember: memberInfo.isClassMember,
        isMutating: memberInfo.isMutating,
        isDispatchThunk: memberInfo.isDispatchThunk,
        isAsync: memberInfo.isAsync,
        isThrowing: memberInfo.isThrowing,
        throwsKind: memberInfo.throwsKind,
    };
    normalized.text = formatNormalizedSwiftSymbol(normalized);
    return normalized;
}

function normalizeSwiftType(typeInfo) {
    const sourceOffset = typeof typeInfo.sourceOffset === 'bigint' ? typeInfo.sourceOffset : BigInt(typeInfo.sourceOffset || 0);
    const name = String(typeInfo.name || '');
    const sourceSymbolName = typeInfo.sourceSymbolName === undefined ? null : String(typeInfo.sourceSymbolName);
    const sourceKind = typeInfo.sourceKind === undefined ? null : typeInfo.sourceKind;
    const sourceDemangledName = typeInfo.sourceDemangledName === undefined ? null : typeInfo.sourceDemangledName;
    const parsed = parseSwiftMetadataDemangledInfo(sourceDemangledName, name);
    const normalized = {
        moduleName: String(typeInfo.moduleName || ''),
        moduleBase: typeInfo.moduleBase ? typeInfo.moduleBase.toString() : null,
        name: parsed.name === null ? name : parsed.name,
        hasName: (parsed.name === null ? name : parsed.name).length !== 0,
        qualifiedName: parsed.qualifiedName,
        hasQualifiedName: parsed.hasQualifiedName,
        sourceSymbolName,
        hasSourceSymbolName: sourceSymbolName !== null && sourceSymbolName.length !== 0,
        sourceKind,
        hasSourceKind: sourceKind !== null && String(sourceKind).length !== 0,
        sourceAddress: typeInfo.sourceAddress.toString(),
        sourceOffsetHex: '0x' + sourceOffset.toString(16),
        sourceDemangledName,
        hasSourceDemangledName: sourceDemangledName !== null && String(sourceDemangledName).length !== 0,
        signature: parsed.signature,
        hasSignature: parsed.hasSignature,
        contextModuleName: parsed.contextModuleName,
        hasContextModuleName: parsed.hasContextModuleName,
        detailKind: parsed.detailKind,
        hasDetailKind: parsed.detailKind !== null && String(parsed.detailKind).length !== 0,
        isMetadata: parsed.isMetadata,
        isMetadataAccessor: parsed.isMetadataAccessor,
        isNominalDescriptor: parsed.isNominalDescriptor,
    };
    normalized.text = formatNormalizedSwiftType(normalized);
    return normalized;
}

function summarizeSwiftTypeSourceBuckets(buckets) {
    const sourceKinds = [];
    const contextModules = [];
    const detailKinds = [];
    let typeSourceEntryCount = 0;
    let sourceDemangledCount = 0;

    function createBucketSummary(fieldName, fieldValue) {
        const summary = {
            count: 0,
            metadataCount: 0,
            metadataAccessorCount: 0,
            nominalDescriptorCount: 0,
            metadataCacheCount: 0,
            associatedTypeDescriptorCount: 0,
        };
        summary[fieldName] = fieldValue;
        return summary;
    }

    function accumulate(list, fieldName, fieldValue, bucketCountField) {
        let summary = list.find((item) => item[fieldName] === fieldValue);
        if (summary === undefined) {
            summary = createBucketSummary(fieldName, fieldValue);
            list.push(summary);
        }
        summary.count += 1;
        summary[bucketCountField] += 1;
    }

    for (const bucket of buckets) {
        const entries = Array.isArray(bucket.entries) ? bucket.entries : [];
        for (const typeInfo of entries) {
            typeSourceEntryCount += 1;
            if (typeInfo.hasSourceDemangledName) {
                sourceDemangledCount += 1;
            }
            const sourceKind = typeInfo.sourceKind === null ? '<none>' : String(typeInfo.sourceKind);
            accumulate(sourceKinds, 'sourceKind', sourceKind, bucket.countField);
            if (typeInfo.hasContextModuleName) {
                accumulate(contextModules, 'contextModuleName', typeInfo.contextModuleName, bucket.countField);
            }
            const detailKind = typeInfo.detailKind === null ? '<none>' : String(typeInfo.detailKind);
            accumulate(detailKinds, 'detailKind', detailKind, bucket.countField);
        }
    }

    return {
        typeSourceEntryCount,
        sourceDemangledCount,
        hasSourceDemangledTypes: sourceDemangledCount !== 0,
        uniqueSourceKindCount: sourceKinds.length,
        uniqueContextModuleCount: contextModules.length,
        uniqueDetailKindCount: detailKinds.length,
        sourceKinds,
        contextModules,
        detailKinds,
    };
}

function normalizeSwiftMetadata(typeInfo) {
    const sourceOffset = typeof typeInfo.sourceOffset === 'bigint' ? typeInfo.sourceOffset : BigInt(typeInfo.sourceOffset || 0);
    const name = String(typeInfo.name || '');
    const sourceSymbolName = typeInfo.sourceSymbolName === undefined ? null : String(typeInfo.sourceSymbolName);
    const sourceKind = typeInfo.sourceKind === undefined ? null : typeInfo.sourceKind;
    const sourceDemangledName = typeInfo.sourceDemangledName === undefined ? null : typeInfo.sourceDemangledName;
    const parsed = parseSwiftMetadataDemangledInfo(sourceDemangledName, name);
    const normalized = {
        moduleName: String(typeInfo.moduleName || ''),
        moduleBase: typeInfo.moduleBase ? typeInfo.moduleBase.toString() : null,
        name: parsed.name === null ? name : parsed.name,
        hasName: (parsed.name === null ? name : parsed.name).length !== 0,
        qualifiedName: parsed.qualifiedName,
        hasQualifiedName: parsed.hasQualifiedName,
        sourceSymbolName,
        hasSourceSymbolName: sourceSymbolName !== null && sourceSymbolName.length !== 0,
        sourceKind,
        hasSourceKind: sourceKind !== null && String(sourceKind).length !== 0,
        sourceAddress: typeInfo.sourceAddress.toString(),
        sourceOffsetHex: '0x' + sourceOffset.toString(16),
        sourceDemangledName,
        hasSourceDemangledName: sourceDemangledName !== null && String(sourceDemangledName).length !== 0,
        signature: parsed.signature,
        hasSignature: parsed.hasSignature,
        contextModuleName: parsed.contextModuleName,
        hasContextModuleName: parsed.hasContextModuleName,
        detailKind: parsed.detailKind,
        hasDetailKind: parsed.detailKind !== null && String(parsed.detailKind).length !== 0,
        isMetadata: parsed.isMetadata,
        isMetadataAccessor: parsed.isMetadataAccessor,
        isNominalDescriptor: parsed.isNominalDescriptor,
    };
    normalized.text = formatNormalizedSwiftMetadata(normalized);
    return normalized;
}

function normalizeSwiftProtocol(protocolInfo) {
    const sourceOffset = typeof protocolInfo.sourceOffset === 'bigint' ? protocolInfo.sourceOffset : BigInt(protocolInfo.sourceOffset || 0);
    const name = String(protocolInfo.name || '');
    const sourceSymbolName = protocolInfo.sourceSymbolName === undefined ? null : String(protocolInfo.sourceSymbolName);
    const sourceKind = protocolInfo.sourceKind === undefined ? null : protocolInfo.sourceKind;
    const sourceDemangledName = protocolInfo.sourceDemangledName === undefined ? null : protocolInfo.sourceDemangledName;
    const parsed = parseSwiftProtocolDemangledInfo(sourceDemangledName, name);
    const normalized = {
        moduleName: String(protocolInfo.moduleName || ''),
        moduleBase: protocolInfo.moduleBase ? protocolInfo.moduleBase.toString() : null,
        name: parsed.name === null ? name : parsed.name,
        hasName: (parsed.name === null ? name : parsed.name).length !== 0,
        qualifiedName: parsed.qualifiedName,
        hasQualifiedName: parsed.hasQualifiedName,
        sourceSymbolName,
        hasSourceSymbolName: sourceSymbolName !== null && sourceSymbolName.length !== 0,
        sourceKind,
        hasSourceKind: sourceKind !== null && String(sourceKind).length !== 0,
        sourceAddress: protocolInfo.sourceAddress.toString(),
        sourceOffsetHex: '0x' + sourceOffset.toString(16),
        sourceDemangledName,
        hasSourceDemangledName: sourceDemangledName !== null && String(sourceDemangledName).length !== 0,
        signature: parsed.signature,
        hasSignature: parsed.hasSignature,
        contextModuleName: parsed.contextModuleName,
        hasContextModuleName: parsed.hasContextModuleName,
        detailKind: parsed.detailKind,
        hasDetailKind: parsed.detailKind !== null && String(parsed.detailKind).length !== 0,
        isDescriptor: parsed.isDescriptor,
    };
    normalized.text = formatNormalizedSwiftProtocol(normalized);
    return normalized;
}

function normalizeSwiftConformance(conformance) {
    const sourceOffset = typeof conformance.sourceOffset === 'bigint' ? conformance.sourceOffset : BigInt(conformance.sourceOffset || 0);
    const typeName = String(conformance.typeName || '');
    const protocolName = String(conformance.protocolName || '');
    const sourceSymbolName = conformance.sourceSymbolName === undefined ? null : String(conformance.sourceSymbolName);
    const sourceKind = conformance.sourceKind === undefined ? null : conformance.sourceKind;
    const sourceDemangledName = conformance.sourceDemangledName === undefined ? null : conformance.sourceDemangledName;
    const parsed = parseSwiftConformanceDemangledInfo(sourceDemangledName, typeName, protocolName);
    const normalized = {
        moduleName: String(conformance.moduleName || ''),
        moduleBase: conformance.moduleBase ? conformance.moduleBase.toString() : null,
        typeName: parsed.typeName === null ? typeName : parsed.typeName,
        hasTypeName: (parsed.typeName === null ? typeName : parsed.typeName).length !== 0,
        protocolName: parsed.protocolName === null ? protocolName : parsed.protocolName,
        hasProtocolName: (parsed.protocolName === null ? protocolName : parsed.protocolName).length !== 0,
        sourceSymbolName,
        hasSourceSymbolName: sourceSymbolName !== null && sourceSymbolName.length !== 0,
        sourceKind,
        hasSourceKind: sourceKind !== null && String(sourceKind).length !== 0,
        sourceAddress: conformance.sourceAddress.toString(),
        sourceOffsetHex: '0x' + sourceOffset.toString(16),
        sourceDemangledName,
        hasSourceDemangledName: sourceDemangledName !== null && String(sourceDemangledName).length !== 0,
        signature: parsed.signature,
        hasSignature: parsed.hasSignature,
        relation: parsed.relation,
        hasRelation: parsed.relation !== null,
        contextModuleName: parsed.contextModuleName,
        hasContextModuleName: parsed.hasContextModuleName,
        whereClause: parsed.whereClause,
        hasWhereClause: parsed.hasWhereClause,
        detailKind: parsed.detailKind,
        hasDetailKind: parsed.detailKind !== null && String(parsed.detailKind).length !== 0,
        isDescriptor: parsed.isDescriptor,
        isWitnessTable: parsed.isWitnessTable,
        isWitnessAccessor: parsed.isWitnessAccessor,
        isWitness: parsed.isWitness,
    };
    normalized.text = formatNormalizedSwiftConformance(normalized);
    return normalized;
}

function normalizeSwiftVtableEntry(entry) {
    const offset = typeof entry.offset === 'bigint' ? entry.offset : BigInt(entry.offset || 0);
    const typeName = String(entry.typeName || '');
    const memberName = String(entry.memberName || '');
    const name = String(entry.name || '');
    const demangledName = entry.demangledName === undefined ? null : entry.demangledName;
    const sourceKind = entry.sourceKind === undefined ? null : entry.sourceKind;
    const memberInfo = parseSwiftDemangledMemberInfo(demangledName, name, typeName, memberName, { isDispatchThunk: !!entry.isDispatchThunk });
    const normalized = {
        moduleName: String(entry.moduleName || ''),
        moduleBase: entry.moduleBase ? entry.moduleBase.toString() : null,
        typeName,
        hasTypeName: typeName.length !== 0,
        memberName,
        hasMemberName: memberName.length !== 0,
        memberKey: typeName.length === 0 ? memberName : typeName + '.' + memberName,
        name,
        hasName: name.length !== 0,
        demangledName,
        hasDemangledName: demangledName !== null && String(demangledName).length !== 0,
        sourceKind,
        hasSourceKind: sourceKind !== null && String(sourceKind).length !== 0,
        address: entry.address.toString(),
        offsetHex: '0x' + offset.toString(16),
        isDispatchThunk: !!entry.isDispatchThunk,
        ownerTypeName: memberInfo.ownerTypeName,
        hasOwnerTypeName: memberInfo.ownerTypeName !== null,
        memberKind: memberInfo.memberKind,
        signature: memberInfo.signature,
        hasSignature: memberInfo.hasSignature,
        resultTypeName: memberInfo.resultTypeName,
        hasResultTypeName: memberInfo.hasResultTypeName,
        isMember: memberInfo.isMember,
        isAccessor: memberInfo.isAccessor,
        isGetter: memberInfo.isGetter,
        isSetter: memberInfo.isSetter,
        isModifyAccessor: memberInfo.isModifyAccessor,
        isReadAccessor: memberInfo.isReadAccessor,
        isConstructor: memberInfo.isConstructor,
        isDestructor: memberInfo.isDestructor,
        isSubscript: memberInfo.isSubscript,
        isOperator: memberInfo.isOperator,
        isClosure: memberInfo.isClosure,
        isStaticMember: memberInfo.isStaticMember,
        isClassMember: memberInfo.isClassMember,
        isMutating: memberInfo.isMutating,
        isAsync: memberInfo.isAsync,
        isThrowing: memberInfo.isThrowing,
        throwsKind: memberInfo.throwsKind,
    };
    normalized.text = formatNormalizedSwiftVtableEntry(normalized);
    return normalized;
}

function normalizeSwiftWitnessTable(entry) {
    const offset = typeof entry.offset === 'bigint' ? entry.offset : BigInt(entry.offset || 0);
    const typeName = String(entry.typeName || '');
    const protocolName = String(entry.protocolName || '');
    const name = String(entry.name || '');
    const demangledName = entry.demangledName === undefined ? null : entry.demangledName;
    const sourceKind = entry.sourceKind === undefined ? null : entry.sourceKind;
    const parsed = parseSwiftConformanceDemangledInfo(demangledName, typeName, protocolName);
    const normalized = {
        moduleName: String(entry.moduleName || ''),
        moduleBase: entry.moduleBase ? entry.moduleBase.toString() : null,
        typeName: parsed.typeName === null ? typeName : parsed.typeName,
        hasTypeName: (parsed.typeName === null ? typeName : parsed.typeName).length !== 0,
        protocolName: parsed.protocolName === null ? protocolName : parsed.protocolName,
        hasProtocolName: (parsed.protocolName === null ? protocolName : parsed.protocolName).length !== 0,
        witnessKey: (parsed.typeName === null ? typeName : parsed.typeName).length === 0
            ? (parsed.protocolName === null ? protocolName : parsed.protocolName)
            : (parsed.typeName === null ? typeName : parsed.typeName) + ':' + (parsed.protocolName === null ? protocolName : parsed.protocolName),
        name,
        hasName: name.length !== 0,
        demangledName,
        hasDemangledName: demangledName !== null && String(demangledName).length !== 0,
        sourceKind,
        hasSourceKind: sourceKind !== null && String(sourceKind).length !== 0,
        address: entry.address.toString(),
        offsetHex: '0x' + offset.toString(16),
        isAccessor: !!entry.isAccessor,
        signature: parsed.signature,
        hasSignature: parsed.hasSignature,
        relation: parsed.relation,
        hasRelation: parsed.relation !== null,
        contextModuleName: parsed.contextModuleName,
        hasContextModuleName: parsed.hasContextModuleName,
        whereClause: parsed.whereClause,
        hasWhereClause: parsed.hasWhereClause,
        detailKind: parsed.detailKind,
        hasDetailKind: parsed.detailKind !== null && String(parsed.detailKind).length !== 0,
        isDescriptor: parsed.isDescriptor,
        isWitnessTable: parsed.isWitnessTable,
        isWitnessAccessor: parsed.isWitnessAccessor,
        isWitness: parsed.isWitness,
    };
    normalized.text = formatNormalizedSwiftWitnessTable(normalized);
    return normalized;
}

function normalizeSwiftTypeLayout(layout) {
    const name = String(layout.name || '');
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
    const typeSourceSummary = summarizeSwiftTypeSourceBuckets([
        { entries: metadata, countField: 'metadataCount' },
        { entries: metadataAccessors, countField: 'metadataAccessorCount' },
        { entries: nominalDescriptors, countField: 'nominalDescriptorCount' },
        { entries: metadataCaches, countField: 'metadataCacheCount' },
        { entries: associatedTypeDescriptors, countField: 'associatedTypeDescriptorCount' },
    ]);
    const vtableSummary = summarizeSwiftMembers(vtableEntries);
    const witnessProtocols = [];
    const witnessSourceKinds = [];
    let witnessAccessorCount = 0;
    let witnessDemangledCount = 0;
    for (const witness of witnessTables) {
        if (witness.isAccessor) {
            witnessAccessorCount += 1;
        }
        if (witness.hasDemangledName) {
            witnessDemangledCount += 1;
        }
        let protocolSummary = witnessProtocols.find((entry) => entry.protocolName === witness.protocolName);
        if (protocolSummary === undefined) {
            protocolSummary = {
                protocolName: witness.protocolName,
                count: 0,
                firstTypeName: witness.typeName,
                lastTypeName: witness.typeName,
                accessorCount: 0,
            };
            witnessProtocols.push(protocolSummary);
        }
        protocolSummary.count += 1;
        protocolSummary.lastTypeName = witness.typeName;
        if (witness.isAccessor) {
            protocolSummary.accessorCount += 1;
        }
        const sourceKind = witness.sourceKind === null || witness.sourceKind === undefined ? '<none>' : String(witness.sourceKind);
        let sourceSummary = witnessSourceKinds.find((entry) => entry.sourceKind === sourceKind);
        if (sourceSummary === undefined) {
            sourceSummary = {
                sourceKind,
                count: 0,
                firstProtocolName: witness.protocolName,
                lastProtocolName: witness.protocolName,
                accessorCount: 0,
            };
            witnessSourceKinds.push(sourceSummary);
        }
        sourceSummary.count += 1;
        sourceSummary.lastProtocolName = witness.protocolName;
        if (witness.isAccessor) {
            sourceSummary.accessorCount += 1;
        }
    }

    const normalized = {
        moduleName: String(layout.moduleName || ''),
        moduleBase: layout.moduleBase ? layout.moduleBase.toString() : null,
        name,
        hasName: name.length !== 0,
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
        typeSourceEntryCount: typeSourceSummary.typeSourceEntryCount,
        sourceDemangledCount: typeSourceSummary.sourceDemangledCount,
        hasSourceDemangledTypes: typeSourceSummary.hasSourceDemangledTypes,
        uniqueSourceKindCount: typeSourceSummary.uniqueSourceKindCount,
        uniqueContextModuleCount: typeSourceSummary.uniqueContextModuleCount,
        uniqueDetailKindCount: typeSourceSummary.uniqueDetailKindCount,
        sourceKinds: typeSourceSummary.sourceKinds,
        contextModules: typeSourceSummary.contextModules,
        detailKinds: typeSourceSummary.detailKinds,
        vtableCount: vtableEntries.length,
        witnessTableCount: witnessTables.length,
        parsedVtableMemberCount: vtableSummary.parsedMemberCount,
        vtableAccessorCount: vtableSummary.accessorCount,
        vtableGetterCount: vtableSummary.getterCount,
        vtableSetterCount: vtableSummary.setterCount,
        vtableModifyAccessorCount: vtableSummary.modifyAccessorCount,
        vtableReadAccessorCount: vtableSummary.readAccessorCount,
        vtableConstructorCount: vtableSummary.constructorCount,
        vtableDestructorCount: vtableSummary.destructorCount,
        vtableSubscriptCount: vtableSummary.subscriptCount,
        vtableOperatorCount: vtableSummary.operatorCount,
        vtableClosureCount: vtableSummary.closureCount,
        vtableStaticMemberCount: vtableSummary.staticMemberCount,
        vtableClassMemberCount: vtableSummary.classMemberCount,
        vtableMutatingMemberCount: vtableSummary.mutatingMemberCount,
        vtableAsyncCount: vtableSummary.asyncCount,
        vtableThrowingCount: vtableSummary.throwingCount,
        vtableDispatchThunkCount: vtableSummary.dispatchThunkCount,
        uniqueVtableOwnerTypeCount: vtableSummary.uniqueOwnerTypeCount,
        uniqueVtableMemberKindCount: vtableSummary.uniqueMemberKindCount,
        uniqueVtableResultTypeCount: vtableSummary.uniqueResultTypeCount,
        vtableOwnerTypes: vtableSummary.ownerTypes,
        vtableMemberKinds: vtableSummary.memberKinds,
        vtableResultTypes: vtableSummary.resultTypes,
        witnessAccessorCount,
        witnessDemangledCount,
        uniqueWitnessProtocolCount: witnessProtocols.length,
        uniqueWitnessSourceKindCount: witnessSourceKinds.length,
        witnessProtocols,
        witnessSourceKinds,
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
        const summary = summarizeObjcClassNames(classes);
        return {
            kind: 'objc.classes',
            filter,
            hasFilter: filter !== null && filter.length !== 0,
            count: classes.length,
            hasClasses: classes.length !== 0,
            firstClass: classes.length === 0 ? null : classes[0],
            lastClass: classes.length === 0 ? null : classes[classes.length - 1],
            firstImagePath: summary.firstImagePath,
            lastImagePath: summary.lastImagePath,
            uniqueImagePathCount: summary.uniqueImagePathCount,
            classesWithImagePathCount: summary.classesWithImagePathCount,
            rootClassCount: summary.rootClassCount,
            classesWithProtocolsCount: summary.classesWithProtocolsCount,
            classesWithPropertiesCount: summary.classesWithPropertiesCount,
            classesWithIvarsCount: summary.classesWithIvarsCount,
            classesWithMethodsCount: summary.classesWithMethodsCount,
            imagePaths: summary.imagePaths,
            classes,
            text: classes.join('\n'),
        };
    }
    case 'objc.protocols': {
        const filter = spec.filter === null || spec.filter === undefined ? null : String(spec.filter).trim();
        const protocols = ObjC.protocols(filter).map((name) => String(name));
        const summary = summarizeObjcProtocols(protocols);
        return {
            kind: 'objc.protocols',
            filter,
            hasFilter: filter !== null && filter.length !== 0,
            count: protocols.length,
            hasProtocols: protocols.length !== 0,
            firstProtocol: protocols.length === 0 ? null : protocols[0],
            lastProtocol: protocols.length === 0 ? null : protocols[protocols.length - 1],
            firstImagePath: summary.firstImagePath,
            lastImagePath: summary.lastImagePath,
            uniqueImagePathCount: summary.uniqueImagePathCount,
            protocolsWithImagePathCount: summary.protocolsWithImagePathCount,
            protocolsWithAdoptedProtocolsCount: summary.protocolsWithAdoptedProtocolsCount,
            protocolsWithRequiredMethodsCount: summary.protocolsWithRequiredMethodsCount,
            protocolsWithOptionalMethodsCount: summary.protocolsWithOptionalMethodsCount,
            protocolsWithInstanceMethodsCount: summary.protocolsWithInstanceMethodsCount,
            protocolsWithClassMethodsCount: summary.protocolsWithClassMethodsCount,
            protocolsWithPropertiesCount: summary.protocolsWithPropertiesCount,
            totalAdoptedProtocolCount: summary.totalAdoptedProtocolCount,
            totalRequiredMethodCount: summary.totalRequiredMethodCount,
            totalOptionalMethodCount: summary.totalOptionalMethodCount,
            totalPropertyCount: summary.totalPropertyCount,
            imagePaths: summary.imagePaths,
            protocols,
            text: protocols.join('\n'),
        };
    }
    case 'objc.class_protocols': {
        const className = String(spec.className || '');
        const filter = spec.filter === null || spec.filter === undefined ? null : String(spec.filter);
        const protocols = ObjC.classProtocols(className, filter).map((name) => String(name));
        const summary = summarizeObjcProtocols(protocols);
        const classInfo = ObjC.classInfo(className, false);
        const normalizedClassInfo = classInfo === null ? null : normalizeObjcClassInfo(classInfo);
        return {
            kind: 'objc.class_protocols',
            className,
            filter,
            classInfo: normalizedClassInfo,
            hasClassInfo: normalizedClassInfo !== null,
            resolved: normalizedClassInfo !== null,
            resolvedClassName: normalizedClassInfo === null ? null : normalizedClassInfo.className,
            resolvedClassPointer: normalizedClassInfo === null ? null : normalizedClassInfo.classPointer,
            hasImagePath: normalizedClassInfo !== null && normalizedClassInfo.hasImagePath === true,
            imagePath: normalizedClassInfo === null ? null : normalizedClassInfo.imagePath,
            declaredProtocolCount: normalizedClassInfo === null ? 0 : normalizedClassInfo.protocolCount,
            ownerHasProtocols: normalizedClassInfo !== null && normalizedClassInfo.hasProtocols === true,
            ownerTotalPropertyCount: normalizedClassInfo === null ? 0 : normalizedClassInfo.totalPropertyCount,
            ownerTotalMethodCount: normalizedClassInfo === null ? 0 : normalizedClassInfo.totalMethodCount,
            hasFilter: filter !== null && filter.length !== 0,
            count: protocols.length,
            hasProtocols: protocols.length !== 0,
            firstProtocol: protocols.length === 0 ? null : protocols[0],
            lastProtocol: protocols.length === 0 ? null : protocols[protocols.length - 1],
            firstImagePath: summary.firstImagePath,
            lastImagePath: summary.lastImagePath,
            uniqueImagePathCount: summary.uniqueImagePathCount,
            protocolsWithImagePathCount: summary.protocolsWithImagePathCount,
            protocolsWithAdoptedProtocolsCount: summary.protocolsWithAdoptedProtocolsCount,
            protocolsWithRequiredMethodsCount: summary.protocolsWithRequiredMethodsCount,
            protocolsWithOptionalMethodsCount: summary.protocolsWithOptionalMethodsCount,
            protocolsWithInstanceMethodsCount: summary.protocolsWithInstanceMethodsCount,
            protocolsWithClassMethodsCount: summary.protocolsWithClassMethodsCount,
            protocolsWithPropertiesCount: summary.protocolsWithPropertiesCount,
            totalAdoptedProtocolCount: summary.totalAdoptedProtocolCount,
            totalRequiredMethodCount: summary.totalRequiredMethodCount,
            totalOptionalMethodCount: summary.totalOptionalMethodCount,
            totalPropertyCount: summary.totalPropertyCount,
            imagePaths: summary.imagePaths,
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
            hasClassInfo: normalized !== null,
            resolved: normalized !== null,
            resolvedClassName: normalized === null ? null : normalized.className,
            resolvedClassPointer: normalized === null ? null : normalized.classPointer,
            hasSuperclass: normalized !== null && normalized.hasSuperclass === true,
            superclassName: normalized === null ? null : normalized.superclassName,
            resolvedSuperclassPointer: normalized === null ? null : normalized.superclassPointer,
            isRootClass: normalized !== null && normalized.isRootClass === true,
            hasProtocols: normalized !== null && normalized.hasProtocols === true,
            hasProperties: normalized !== null && normalized.hasProperties === true,
            hasIvars: normalized !== null && normalized.hasIvars === true,
            hasMethods: normalized !== null && normalized.hasMethods === true,
            hasImagePath: normalized !== null && normalized.hasImagePath === true,
            imagePath: normalized === null ? null : normalized.imagePath,
            instanceSize: normalized === null ? 0 : normalized.instanceSize,
            protocolCount: normalized === null ? 0 : normalized.protocolCount,
            instancePropertyCount: normalized === null ? 0 : normalized.instancePropertyCount,
            classPropertyCount: normalized === null ? 0 : normalized.classPropertyCount,
            totalPropertyCount: normalized === null ? 0 : normalized.totalPropertyCount,
            ivarCount: normalized === null ? 0 : normalized.ivarCount,
            instanceMethodCount: normalized === null ? 0 : normalized.instanceMethodCount,
            classMethodCount: normalized === null ? 0 : normalized.classMethodCount,
            totalMethodCount: normalized === null ? 0 : normalized.totalMethodCount,
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
            hasProtocolInfo: normalized !== null,
            resolved: normalized !== null,
            resolvedProtocolName: normalized === null ? null : normalized.protocolName,
            resolvedProtocolPointer: normalized === null ? null : normalized.protocolPointer,
            hasAdoptedProtocols: normalized !== null && normalized.hasAdoptedProtocols === true,
            hasRequiredMethods: normalized !== null && normalized.hasRequiredMethods === true,
            hasOptionalMethods: normalized !== null && normalized.hasOptionalMethods === true,
            hasInstanceMethods: normalized !== null && normalized.hasInstanceMethods === true,
            hasClassMethods: normalized !== null && normalized.hasClassMethods === true,
            hasProperties: normalized !== null && normalized.hasProperties === true,
            hasImagePath: normalized !== null && normalized.hasImagePath === true,
            imagePath: normalized === null ? null : normalized.imagePath,
            adoptedProtocolCount: normalized === null ? 0 : normalized.adoptedProtocolCount,
            requiredInstanceMethodCount: normalized === null ? 0 : normalized.requiredInstanceMethodCount,
            requiredClassMethodCount: normalized === null ? 0 : normalized.requiredClassMethodCount,
            optionalInstanceMethodCount: normalized === null ? 0 : normalized.optionalInstanceMethodCount,
            optionalClassMethodCount: normalized === null ? 0 : normalized.optionalClassMethodCount,
            totalMethodCount: normalized === null ? 0 : normalized.totalMethodCount,
            propertyCount: normalized === null ? 0 : normalized.propertyCount,
            text: normalized === null ? '<null>' : normalized.text,
        };
    }
    case 'objc.protocol_protocols': {
        const protocolName = String(spec.protocolName || '');
        const filter = spec.filter === null || spec.filter === undefined ? null : String(spec.filter);
        const protocols = ObjC.protocolProtocols(protocolName, filter).map((name) => String(name));
        const summary = summarizeObjcProtocols(protocols);
        const protocolInfo = ObjC.protocolInfo(protocolName);
        const normalizedProtocolInfo = protocolInfo === null ? null : normalizeObjcProtocolInfo(protocolInfo);
        return {
            kind: 'objc.protocol_protocols',
            protocolName,
            filter,
            protocolInfo: normalizedProtocolInfo,
            hasProtocolInfo: normalizedProtocolInfo !== null,
            resolved: normalizedProtocolInfo !== null,
            resolvedProtocolName: normalizedProtocolInfo === null ? null : normalizedProtocolInfo.protocolName,
            resolvedProtocolPointer: normalizedProtocolInfo === null ? null : normalizedProtocolInfo.protocolPointer,
            hasImagePath: normalizedProtocolInfo !== null && normalizedProtocolInfo.hasImagePath === true,
            imagePath: normalizedProtocolInfo === null ? null : normalizedProtocolInfo.imagePath,
            adoptedProtocolCount: normalizedProtocolInfo === null ? 0 : normalizedProtocolInfo.adoptedProtocolCount,
            protocolTotalMethodCount: normalizedProtocolInfo === null ? 0 : normalizedProtocolInfo.totalMethodCount,
            protocolPropertyCount: normalizedProtocolInfo === null ? 0 : normalizedProtocolInfo.propertyCount,
            ownerHasAdoptedProtocols: normalizedProtocolInfo !== null && normalizedProtocolInfo.hasAdoptedProtocols === true,
            ownerHasMethods: normalizedProtocolInfo !== null && normalizedProtocolInfo.totalMethodCount !== 0,
            ownerHasProperties: normalizedProtocolInfo !== null && normalizedProtocolInfo.hasProperties === true,
            hasFilter: filter !== null && filter.length !== 0,
            count: protocols.length,
            hasProtocols: protocols.length !== 0,
            firstProtocol: protocols.length === 0 ? null : protocols[0],
            lastProtocol: protocols.length === 0 ? null : protocols[protocols.length - 1],
            firstImagePath: summary.firstImagePath,
            lastImagePath: summary.lastImagePath,
            uniqueImagePathCount: summary.uniqueImagePathCount,
            protocolsWithImagePathCount: summary.protocolsWithImagePathCount,
            protocolsWithAdoptedProtocolsCount: summary.protocolsWithAdoptedProtocolsCount,
            protocolsWithRequiredMethodsCount: summary.protocolsWithRequiredMethodsCount,
            protocolsWithOptionalMethodsCount: summary.protocolsWithOptionalMethodsCount,
            protocolsWithInstanceMethodsCount: summary.protocolsWithInstanceMethodsCount,
            protocolsWithClassMethodsCount: summary.protocolsWithClassMethodsCount,
            protocolsWithPropertiesCount: summary.protocolsWithPropertiesCount,
            totalAdoptedProtocolCount: summary.totalAdoptedProtocolCount,
            totalRequiredMethodCount: summary.totalRequiredMethodCount,
            totalOptionalMethodCount: summary.totalOptionalMethodCount,
            totalPropertyCount: summary.totalPropertyCount,
            imagePaths: summary.imagePaths,
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
        const summary = summarizeObjcProtocolMethods(methods);
        const protocolInfo = ObjC.protocolInfo(protocolName);
        const normalizedProtocolInfo = protocolInfo === null ? null : normalizeObjcProtocolInfo(protocolInfo);
        return {
            kind: 'objc.protocol_methods',
            protocolName,
            isRequired,
            isInstanceMethod,
            filter,
            protocolInfo: normalizedProtocolInfo,
            hasProtocolInfo: normalizedProtocolInfo !== null,
            resolved: normalizedProtocolInfo !== null,
            resolvedProtocolName: normalizedProtocolInfo === null ? null : normalizedProtocolInfo.protocolName,
            resolvedProtocolPointer: normalizedProtocolInfo === null ? null : normalizedProtocolInfo.protocolPointer,
            hasImagePath: normalizedProtocolInfo !== null && normalizedProtocolInfo.hasImagePath === true,
            imagePath: normalizedProtocolInfo === null ? null : normalizedProtocolInfo.imagePath,
            adoptedProtocolCount: normalizedProtocolInfo === null ? 0 : normalizedProtocolInfo.adoptedProtocolCount,
            protocolTotalMethodCount: normalizedProtocolInfo === null ? 0 : normalizedProtocolInfo.totalMethodCount,
            protocolPropertyCount: normalizedProtocolInfo === null ? 0 : normalizedProtocolInfo.propertyCount,
            ownerHasAdoptedProtocols: normalizedProtocolInfo !== null && normalizedProtocolInfo.hasAdoptedProtocols === true,
            ownerHasMethods: normalizedProtocolInfo !== null && normalizedProtocolInfo.totalMethodCount !== 0,
            ownerHasProperties: normalizedProtocolInfo !== null && normalizedProtocolInfo.hasProperties === true,
            hasFilter: filter !== null && filter.length !== 0,
            count: methods.length,
            hasMethods: methods.length !== 0,
            firstSelector: methods.length === 0 ? null : methods[0].selector,
            lastSelector: methods.length === 0 ? null : methods[methods.length - 1].selector,
            uniqueSelectorCount: summary.uniqueSelectorCount,
            uniqueReturnTypeCount: summary.uniqueReturnTypeCount,
            keywordSelectorCount: summary.keywordSelectorCount,
            unarySelectorCount: summary.unarySelectorCount,
            explicitArgumentMethodCount: summary.explicitArgumentMethodCount,
            hiddenArgumentMethodCount: summary.hiddenArgumentMethodCount,
            returnsVoidCount: summary.returnsVoidCount,
            returnsObjectCount: summary.returnsObjectCount,
            returnsBlockCount: summary.returnsBlockCount,
            totalExplicitArgumentCount: summary.totalExplicitArgumentCount,
            totalHiddenArgumentCount: summary.totalHiddenArgumentCount,
            maxSelectorPartCount: summary.maxSelectorPartCount,
            maxExplicitArgumentCount: summary.maxExplicitArgumentCount,
            selectors: summary.selectors,
            returnTypes: summary.returnTypes,
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
            hasMethodInfo: normalized !== null,
            resolved: normalized !== null,
            resolvedProtocolName: normalized === null ? null : normalized.protocolName,
            resolvedSelector: normalized === null ? null : normalized.selector,
            resolvedTypeEncoding: normalized === null ? null : normalized.typeEncoding,
            resolvedReturnTypeName: normalized === null ? null : normalized.returnTypeName,
            resolvedSignature: normalized === null ? null : normalized.signature,
            imagePath: normalized === null ? null : normalized.imagePath,
            resolvedImagePath: normalized === null ? null : normalized.imagePath,
            argumentCount: normalized === null ? 0 : normalized.argumentCount,
            explicitArgumentCount: normalized === null ? 0 : normalized.explicitArgumentCount,
            hiddenArgumentCount: normalized === null ? 0 : normalized.hiddenArgumentCount,
            selectorPartCount: normalized === null ? 0 : normalized.selectorPartCount,
            hasImagePath: normalized !== null && normalized.imagePath !== null,
            hasSelectorArguments: normalized !== null && normalized.hasSelectorArguments === true,
            isUnarySelector: normalized !== null && normalized.isUnarySelector === true,
            isKeywordSelector: normalized !== null && normalized.isKeywordSelector === true,
            hasExplicitArguments: normalized !== null && normalized.hasExplicitArguments === true,
            hasHiddenArguments: normalized !== null && normalized.hasHiddenArguments === true,
            returnsVoid: normalized !== null && normalized.returnsVoid === true,
            returnsObject: normalized !== null && normalized.returnsObject === true,
            returnsBlock: normalized !== null && normalized.returnsBlock === true,
            text: normalized === null ? '<null>' : normalized.text,
        };
    }
    case 'objc.protocol_properties': {
        const protocolName = String(spec.protocolName || '');
        const filter = spec.filter === null || spec.filter === undefined ? null : String(spec.filter);
        const properties = ObjC.protocolProperties(protocolName, filter).map((property) => normalizeObjcProtocolProperty(property));
        const summary = summarizeObjcProperties(properties);
        const protocolInfo = ObjC.protocolInfo(protocolName);
        const normalizedProtocolInfo = protocolInfo === null ? null : normalizeObjcProtocolInfo(protocolInfo);
        return {
            kind: 'objc.protocol_properties',
            protocolName,
            filter,
            protocolInfo: normalizedProtocolInfo,
            hasProtocolInfo: normalizedProtocolInfo !== null,
            resolved: normalizedProtocolInfo !== null,
            resolvedProtocolName: normalizedProtocolInfo === null ? null : normalizedProtocolInfo.protocolName,
            resolvedProtocolPointer: normalizedProtocolInfo === null ? null : normalizedProtocolInfo.protocolPointer,
            hasImagePath: normalizedProtocolInfo !== null && normalizedProtocolInfo.hasImagePath === true,
            imagePath: normalizedProtocolInfo === null ? null : normalizedProtocolInfo.imagePath,
            adoptedProtocolCount: normalizedProtocolInfo === null ? 0 : normalizedProtocolInfo.adoptedProtocolCount,
            protocolTotalMethodCount: normalizedProtocolInfo === null ? 0 : normalizedProtocolInfo.totalMethodCount,
            protocolPropertyCount: normalizedProtocolInfo === null ? 0 : normalizedProtocolInfo.propertyCount,
            ownerHasAdoptedProtocols: normalizedProtocolInfo !== null && normalizedProtocolInfo.hasAdoptedProtocols === true,
            ownerHasMethods: normalizedProtocolInfo !== null && normalizedProtocolInfo.totalMethodCount !== 0,
            ownerHasProperties: normalizedProtocolInfo !== null && normalizedProtocolInfo.hasProperties === true,
            hasFilter: filter !== null && filter.length !== 0,
            count: properties.length,
            hasProperties: properties.length !== 0,
            firstProperty: properties.length === 0 ? null : properties[0].name,
            lastProperty: properties.length === 0 ? null : properties[properties.length - 1].name,
            firstObjectClassName: summary.firstObjectClassName,
            lastObjectClassName: summary.lastObjectClassName,
            uniqueOwnershipCount: summary.uniqueOwnershipCount,
            uniqueObjectClassCount: summary.uniqueObjectClassCount,
            readonlyPropertyCount: summary.readonlyPropertyCount,
            readwritePropertyCount: summary.readwritePropertyCount,
            atomicPropertyCount: summary.atomicPropertyCount,
            nonatomicPropertyCount: summary.nonatomicPropertyCount,
            dynamicPropertyCount: summary.dynamicPropertyCount,
            strongPropertyCount: summary.strongPropertyCount,
            copyPropertyCount: summary.copyPropertyCount,
            weakPropertyCount: summary.weakPropertyCount,
            assignPropertyCount: summary.assignPropertyCount,
            objectPropertyCount: summary.objectPropertyCount,
            blockPropertyCount: summary.blockPropertyCount,
            propertiesWithAccessorCustomizationCount: summary.propertiesWithAccessorCustomizationCount,
            propertiesWithBackingIvarCount: summary.propertiesWithBackingIvarCount,
            propertiesWithObjectProtocolsCount: summary.propertiesWithObjectProtocolsCount,
            propertiesWithTypeInfoCount: summary.propertiesWithTypeInfoCount,
            propertiesWithParsedTokensCount: summary.propertiesWithParsedTokensCount,
            totalObjectProtocolCount: summary.totalObjectProtocolCount,
            ownerships: summary.ownerships,
            objectClasses: summary.objectClasses,
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
            hasPropertyInfo: normalized !== null,
            resolved: normalized !== null,
            resolvedProtocolName: normalized === null ? null : normalized.protocolName,
            resolvedName: normalized === null ? null : normalized.name,
            resolvedPropertyPointer: normalized === null ? null : normalized.propertyPointer,
            resolvedTypeName: normalized === null ? null : normalized.typeName,
            resolvedOwnership: normalized === null ? null : normalized.ownership,
            resolvedObjectClassName: normalized === null ? null : normalized.objectClassName,
            resolvedGetterName: normalized === null ? null : normalized.getterName,
            resolvedSetterName: normalized === null ? null : normalized.setterName,
            resolvedIvarName: normalized === null ? null : normalized.ivarName,
            typeName: normalized === null ? null : normalized.typeName,
            ownership: normalized === null ? null : normalized.ownership,
            objectClassName: normalized === null ? null : normalized.objectClassName,
            getterName: normalized === null ? null : normalized.getterName,
            setterName: normalized === null ? null : normalized.setterName,
            ivarName: normalized === null ? null : normalized.ivarName,
            objectProtocolCount: normalized === null ? 0 : normalized.objectProtocolCount,
            parsedTokenCount: normalized === null ? 0 : normalized.parsedTokenCount,
            hasAccessorCustomization: normalized !== null && normalized.hasAccessorCustomization === true,
            hasGetterName: normalized !== null && normalized.hasGetterName === true,
            hasSetterName: normalized !== null && normalized.hasSetterName === true,
            hasBackingIvar: normalized !== null && normalized.hasBackingIvar === true,
            hasObjectClassName: normalized !== null && normalized.hasObjectClassName === true,
            hasObjectProtocols: normalized !== null && normalized.hasObjectProtocols === true,
            hasTypeInfo: normalized !== null && normalized.hasTypeInfo === true,
            isObject: normalized !== null && normalized.isObject === true,
            isBlock: normalized !== null && normalized.isBlock === true,
            imagePath: normalized === null ? null : normalized.imagePath,
            resolvedImagePath: normalized === null ? null : normalized.imagePath,
            text: normalized === null ? '<null>' : normalized.text,
        };
    }
    case 'objc.superclass': {
        const className = String(spec.className || '');
        const classExists = !!ObjC.classExists(className);
        const superclass = ObjC.superclass(className);
        const normalized = superclass === null ? null : String(superclass);
        return {
            kind: 'objc.superclass',
            className,
            superclass: normalized,
            classExists,
            resolved: classExists,
            resolvedSuperclassName: normalized,
            hasSuperclass: normalized !== null,
            isRootClass: classExists && normalized === null,
            text: normalized === null ? '<null>' : normalized,
        };
    }
    case 'objc.class_chain': {
        const className = String(spec.className || '');
        const chain = ObjC.classChain(className).map((name) => String(name));
        const rootClass = chain.length === 0 ? null : chain[chain.length - 1];
        const summary = summarizeObjcClassNames(chain);
        return {
            kind: 'objc.class_chain',
            className,
            count: chain.length,
            depth: chain.length,
            hasChain: chain.length !== 0,
            includesSelf: chain.length !== 0 && chain[0] === className,
            rootClass,
            firstImagePath: summary.firstImagePath,
            lastImagePath: summary.lastImagePath,
            uniqueImagePathCount: summary.uniqueImagePathCount,
            classesWithImagePathCount: summary.classesWithImagePathCount,
            rootClassCount: summary.rootClassCount,
            classesWithProtocolsCount: summary.classesWithProtocolsCount,
            classesWithPropertiesCount: summary.classesWithPropertiesCount,
            classesWithIvarsCount: summary.classesWithIvarsCount,
            classesWithMethodsCount: summary.classesWithMethodsCount,
            totalProtocolCount: summary.totalProtocolCount,
            totalPropertyCount: summary.totalPropertyCount,
            totalIvarCount: summary.totalIvarCount,
            totalMethodCount: summary.totalMethodCount,
            totalInstanceSize: summary.totalInstanceSize,
            imagePaths: summary.imagePaths,
            chain,
            text: chain.join('\n'),
        };
    }
    case 'objc.class_exists': {
        const className = String(spec.className || '');
        const exists = !!ObjC.classExists(className);
        return {
            kind: 'objc.class_exists',
            className,
            exists,
            resolved: true,
            resolvedClassName: exists ? className : null,
            text: String(exists),
        };
    }
    case 'objc.selector': {
        const selectorName = String(spec.selectorName || '');
        const selector = ObjC.selector(selectorName);
        const pointer = selector === null ? null : selector.toString();
        return {
            kind: 'objc.selector',
            selectorName,
            pointer,
            hasPointer: pointer !== null,
            resolved: pointer !== null,
            resolvedSelectorName: pointer === null ? null : selectorName,
            resolvedPointer: pointer,
            text: pointer === null ? '<null>' : pointer,
        };
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
            hasImp: pointer !== null,
            resolved: pointer !== null,
            resolvedClassName: pointer === null ? null : className,
            resolvedSelectorName: pointer === null ? null : selectorName,
            resolvedImp: pointer,
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
            hasMethodInfo: normalized !== null,
            resolved: normalized !== null,
            resolvedClassName: normalized === null ? null : normalized.className,
            resolvedSelector: normalized === null ? null : normalized.selector,
            resolvedMethodPointer: normalized === null ? null : normalized.methodPointer,
            resolvedImp: normalized === null ? null : normalized.imp,
            resolvedTypeEncoding: normalized === null ? null : normalized.typeEncoding,
            resolvedReturnTypeName: normalized === null ? null : normalized.returnTypeName,
            resolvedSignature: normalized === null ? null : normalized.signature,
            imagePath: normalized === null ? null : normalized.imagePath,
            resolvedImagePath: normalized === null ? null : normalized.imagePath,
            argumentCount: normalized === null ? 0 : normalized.argumentCount,
            explicitArgumentCount: normalized === null ? 0 : normalized.explicitArgumentCount,
            hiddenArgumentCount: normalized === null ? 0 : normalized.hiddenArgumentCount,
            selectorPartCount: normalized === null ? 0 : normalized.selectorPartCount,
            hasImagePath: normalized !== null && normalized.imagePath !== null,
            hasSelectorArguments: normalized !== null && normalized.hasSelectorArguments === true,
            isUnarySelector: normalized !== null && normalized.isUnarySelector === true,
            isKeywordSelector: normalized !== null && normalized.isKeywordSelector === true,
            hasExplicitArguments: normalized !== null && normalized.hasExplicitArguments === true,
            hasHiddenArguments: normalized !== null && normalized.hasHiddenArguments === true,
            returnsVoid: normalized !== null && normalized.returnsVoid === true,
            returnsObject: normalized !== null && normalized.returnsObject === true,
            returnsBlock: normalized !== null && normalized.returnsBlock === true,
            text: normalized === null ? '<null>' : normalized.text,
        };
    }
    case 'objc.class_image': {
        const className = String(spec.className || '');
        const imagePath = ObjC.classImage(className);
        const normalized = imagePath === null ? null : String(imagePath);
        return {
            kind: 'objc.class_image',
            className,
            imagePath: normalized,
            hasImagePath: normalized !== null,
            resolved: normalized !== null,
            resolvedClassName: normalized === null ? null : className,
            resolvedImagePath: normalized,
            text: normalized === null ? '<null>' : normalized,
        };
    }
    case 'objc.method_image': {
        const className = String(spec.className || '');
        const selectorName = String(spec.selectorName || '');
        const isClassMethod = !!spec.isClassMethod;
        const imagePath = ObjC.methodImage(className, selectorName, isClassMethod);
        const normalized = imagePath === null ? null : String(imagePath);
        return {
            kind: 'objc.method_image',
            className,
            selectorName,
            isClassMethod,
            imagePath: normalized,
            hasImagePath: normalized !== null,
            resolved: normalized !== null,
            resolvedClassName: normalized === null ? null : className,
            resolvedSelectorName: normalized === null ? null : selectorName,
            resolvedImagePath: normalized,
            text: normalized === null ? '<null>' : normalized,
        };
    }
    case 'objc.selector_name': {
        const selector = parseAddressArg(spec.selector, 'objc.selectorName usage: objc.selectorName <selector>');
        const name = ObjC.selectorName(selector);
        const normalized = name === null ? null : String(name);
        return {
            kind: 'objc.selector_name',
            selector: selector.toString(),
            name: normalized,
            hasName: normalized !== null,
            resolved: normalized !== null,
            resolvedSelector: normalized === null ? null : selector.toString(),
            resolvedName: normalized,
            text: normalized === null ? '<null>' : normalized,
        };
    }
    case 'objc.object_class_name': {
        const object = parseAddressArg(spec.object, 'objc.objectClassName usage: objc.objectClassName <object>');
        const className = ObjC.objectClassName(object);
        const normalized = className === null ? null : String(className);
        return {
            kind: 'objc.object_class_name',
            object: object.toString(),
            className: normalized,
            hasClassName: normalized !== null,
            resolved: normalized !== null,
            resolvedObject: normalized === null ? null : object.toString(),
            resolvedClassName: normalized,
            text: normalized === null ? '<null>' : normalized,
        };
    }
    case 'objc.methods': {
        const className = String(spec.className || '');
        const isClassMethod = !!spec.isClassMethod;
        const filter = spec.filter === null || spec.filter === undefined ? null : String(spec.filter);
        const methods = ObjC.methods(className, isClassMethod, filter).map((method) => normalizeObjcMethod(method));
        const summary = summarizeObjcMethods(methods);
        const classInfo = ObjC.classInfo(className, isClassMethod);
        const normalizedClassInfo = classInfo === null ? null : normalizeObjcClassInfo(classInfo);
        return {
            kind: 'objc.methods',
            className,
            isClassMethod,
            filter,
            classInfo: normalizedClassInfo,
            hasClassInfo: normalizedClassInfo !== null,
            resolved: normalizedClassInfo !== null,
            resolvedClassName: normalizedClassInfo === null ? null : normalizedClassInfo.className,
            resolvedClassPointer: normalizedClassInfo === null ? null : normalizedClassInfo.classPointer,
            hasImagePath: normalizedClassInfo !== null && normalizedClassInfo.hasImagePath === true,
            imagePath: normalizedClassInfo === null ? null : normalizedClassInfo.imagePath,
            declaredProtocolCount: normalizedClassInfo === null ? 0 : normalizedClassInfo.protocolCount,
            ownerHasProtocols: normalizedClassInfo !== null && normalizedClassInfo.hasProtocols === true,
            ownerHasProperties: normalizedClassInfo !== null && normalizedClassInfo.hasProperties === true,
            ownerHasIvars: normalizedClassInfo !== null && normalizedClassInfo.hasIvars === true,
            ownerHasMethods: normalizedClassInfo !== null && normalizedClassInfo.hasMethods === true,
            ownerIvarCount: normalizedClassInfo === null ? 0 : normalizedClassInfo.ivarCount,
            ownerTotalPropertyCount: normalizedClassInfo === null ? 0 : normalizedClassInfo.totalPropertyCount,
            ownerTotalMethodCount: normalizedClassInfo === null ? 0 : normalizedClassInfo.totalMethodCount,
            hasFilter: filter !== null && filter.length !== 0,
            count: methods.length,
            hasMethods: methods.length !== 0,
            firstSelector: methods.length === 0 ? null : methods[0].selector,
            lastSelector: methods.length === 0 ? null : methods[methods.length - 1].selector,
            uniqueSelectorCount: summary.uniqueSelectorCount,
            uniqueReturnTypeCount: summary.uniqueReturnTypeCount,
            keywordSelectorCount: summary.keywordSelectorCount,
            unarySelectorCount: summary.unarySelectorCount,
            explicitArgumentMethodCount: summary.explicitArgumentMethodCount,
            hiddenArgumentMethodCount: summary.hiddenArgumentMethodCount,
            returnsVoidCount: summary.returnsVoidCount,
            returnsObjectCount: summary.returnsObjectCount,
            returnsBlockCount: summary.returnsBlockCount,
            totalExplicitArgumentCount: summary.totalExplicitArgumentCount,
            totalHiddenArgumentCount: summary.totalHiddenArgumentCount,
            maxSelectorPartCount: summary.maxSelectorPartCount,
            maxExplicitArgumentCount: summary.maxExplicitArgumentCount,
            selectors: summary.selectors,
            returnTypes: summary.returnTypes,
            methods,
            text: methods.map((method) => method.text).join('\n'),
        };
    }
    case 'objc.properties': {
        const className = String(spec.className || '');
        const isClassProperty = !!spec.isClassProperty;
        const filter = spec.filter === null || spec.filter === undefined ? null : String(spec.filter);
        const properties = ObjC.properties(className, isClassProperty, filter).map((property) => normalizeObjcProperty(property));
        const summary = summarizeObjcProperties(properties);
        const classInfo = ObjC.classInfo(className, isClassProperty);
        const normalizedClassInfo = classInfo === null ? null : normalizeObjcClassInfo(classInfo);
        return {
            kind: 'objc.properties',
            className,
            isClassProperty,
            filter,
            classInfo: normalizedClassInfo,
            hasClassInfo: normalizedClassInfo !== null,
            resolved: normalizedClassInfo !== null,
            resolvedClassName: normalizedClassInfo === null ? null : normalizedClassInfo.className,
            resolvedClassPointer: normalizedClassInfo === null ? null : normalizedClassInfo.classPointer,
            hasImagePath: normalizedClassInfo !== null && normalizedClassInfo.hasImagePath === true,
            imagePath: normalizedClassInfo === null ? null : normalizedClassInfo.imagePath,
            declaredProtocolCount: normalizedClassInfo === null ? 0 : normalizedClassInfo.protocolCount,
            ownerHasProtocols: normalizedClassInfo !== null && normalizedClassInfo.hasProtocols === true,
            ownerHasProperties: normalizedClassInfo !== null && normalizedClassInfo.hasProperties === true,
            ownerHasIvars: normalizedClassInfo !== null && normalizedClassInfo.hasIvars === true,
            ownerHasMethods: normalizedClassInfo !== null && normalizedClassInfo.hasMethods === true,
            ownerIvarCount: normalizedClassInfo === null ? 0 : normalizedClassInfo.ivarCount,
            ownerTotalPropertyCount: normalizedClassInfo === null ? 0 : normalizedClassInfo.totalPropertyCount,
            ownerTotalMethodCount: normalizedClassInfo === null ? 0 : normalizedClassInfo.totalMethodCount,
            hasFilter: filter !== null && filter.length !== 0,
            count: properties.length,
            hasProperties: properties.length !== 0,
            firstProperty: properties.length === 0 ? null : properties[0].name,
            lastProperty: properties.length === 0 ? null : properties[properties.length - 1].name,
            firstObjectClassName: summary.firstObjectClassName,
            lastObjectClassName: summary.lastObjectClassName,
            uniqueOwnershipCount: summary.uniqueOwnershipCount,
            uniqueObjectClassCount: summary.uniqueObjectClassCount,
            readonlyPropertyCount: summary.readonlyPropertyCount,
            readwritePropertyCount: summary.readwritePropertyCount,
            atomicPropertyCount: summary.atomicPropertyCount,
            nonatomicPropertyCount: summary.nonatomicPropertyCount,
            dynamicPropertyCount: summary.dynamicPropertyCount,
            strongPropertyCount: summary.strongPropertyCount,
            copyPropertyCount: summary.copyPropertyCount,
            weakPropertyCount: summary.weakPropertyCount,
            assignPropertyCount: summary.assignPropertyCount,
            objectPropertyCount: summary.objectPropertyCount,
            blockPropertyCount: summary.blockPropertyCount,
            propertiesWithAccessorCustomizationCount: summary.propertiesWithAccessorCustomizationCount,
            propertiesWithBackingIvarCount: summary.propertiesWithBackingIvarCount,
            propertiesWithObjectProtocolsCount: summary.propertiesWithObjectProtocolsCount,
            propertiesWithTypeInfoCount: summary.propertiesWithTypeInfoCount,
            propertiesWithParsedTokensCount: summary.propertiesWithParsedTokensCount,
            totalObjectProtocolCount: summary.totalObjectProtocolCount,
            ownerships: summary.ownerships,
            objectClasses: summary.objectClasses,
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
            hasPropertyInfo: normalized !== null,
            resolved: normalized !== null,
            resolvedClassName: normalized === null ? null : normalized.className,
            resolvedName: normalized === null ? null : normalized.name,
            resolvedPropertyPointer: normalized === null ? null : normalized.propertyPointer,
            resolvedTypeName: normalized === null ? null : normalized.typeName,
            resolvedOwnership: normalized === null ? null : normalized.ownership,
            resolvedObjectClassName: normalized === null ? null : normalized.objectClassName,
            resolvedGetterName: normalized === null ? null : normalized.getterName,
            resolvedSetterName: normalized === null ? null : normalized.setterName,
            resolvedIvarName: normalized === null ? null : normalized.ivarName,
            typeName: normalized === null ? null : normalized.typeName,
            ownership: normalized === null ? null : normalized.ownership,
            objectClassName: normalized === null ? null : normalized.objectClassName,
            getterName: normalized === null ? null : normalized.getterName,
            setterName: normalized === null ? null : normalized.setterName,
            ivarName: normalized === null ? null : normalized.ivarName,
            objectProtocolCount: normalized === null ? 0 : normalized.objectProtocolCount,
            parsedTokenCount: normalized === null ? 0 : normalized.parsedTokenCount,
            hasAccessorCustomization: normalized !== null && normalized.hasAccessorCustomization === true,
            hasGetterName: normalized !== null && normalized.hasGetterName === true,
            hasSetterName: normalized !== null && normalized.hasSetterName === true,
            hasBackingIvar: normalized !== null && normalized.hasBackingIvar === true,
            hasObjectClassName: normalized !== null && normalized.hasObjectClassName === true,
            hasObjectProtocols: normalized !== null && normalized.hasObjectProtocols === true,
            hasTypeInfo: normalized !== null && normalized.hasTypeInfo === true,
            isObject: normalized !== null && normalized.isObject === true,
            isBlock: normalized !== null && normalized.isBlock === true,
            imagePath: normalized === null ? null : normalized.imagePath,
            resolvedImagePath: normalized === null ? null : normalized.imagePath,
            text: normalized === null ? '<null>' : normalized.text,
        };
    }
    case 'objc.ivars': {
        const className = String(spec.className || '');
        const filter = spec.filter === null || spec.filter === undefined ? null : String(spec.filter);
        const ivars = ObjC.ivars(className, filter).map((ivar) => normalizeObjcIvar(ivar));
        const summary = summarizeObjcIvars(ivars);
        const classInfo = ObjC.classInfo(className, false);
        const normalizedClassInfo = classInfo === null ? null : normalizeObjcClassInfo(classInfo);
        return {
            kind: 'objc.ivars',
            className,
            filter,
            classInfo: normalizedClassInfo,
            hasClassInfo: normalizedClassInfo !== null,
            resolved: normalizedClassInfo !== null,
            resolvedClassName: normalizedClassInfo === null ? null : normalizedClassInfo.className,
            resolvedClassPointer: normalizedClassInfo === null ? null : normalizedClassInfo.classPointer,
            hasImagePath: normalizedClassInfo !== null && normalizedClassInfo.hasImagePath === true,
            imagePath: normalizedClassInfo === null ? null : normalizedClassInfo.imagePath,
            declaredProtocolCount: normalizedClassInfo === null ? 0 : normalizedClassInfo.protocolCount,
            ownerHasProtocols: normalizedClassInfo !== null && normalizedClassInfo.hasProtocols === true,
            ownerHasProperties: normalizedClassInfo !== null && normalizedClassInfo.hasProperties === true,
            ownerHasIvars: normalizedClassInfo !== null && normalizedClassInfo.hasIvars === true,
            ownerHasMethods: normalizedClassInfo !== null && normalizedClassInfo.hasMethods === true,
            ownerIvarCount: normalizedClassInfo === null ? 0 : normalizedClassInfo.ivarCount,
            ownerTotalPropertyCount: normalizedClassInfo === null ? 0 : normalizedClassInfo.totalPropertyCount,
            ownerTotalMethodCount: normalizedClassInfo === null ? 0 : normalizedClassInfo.totalMethodCount,
            hasFilter: filter !== null && filter.length !== 0,
            count: ivars.length,
            hasIvars: ivars.length !== 0,
            firstIvar: ivars.length === 0 ? null : ivars[0].name,
            lastIvar: ivars.length === 0 ? null : ivars[ivars.length - 1].name,
            firstObjectClassName: summary.firstObjectClassName,
            lastObjectClassName: summary.lastObjectClassName,
            minOffsetHex: summary.minOffsetHex,
            maxOffsetHex: summary.maxOffsetHex,
            uniqueKindCount: summary.uniqueKindCount,
            uniqueObjectClassCount: summary.uniqueObjectClassCount,
            totalQualifierCount: summary.totalQualifierCount,
            totalObjectProtocolCount: summary.totalObjectProtocolCount,
            pointerIvarCount: summary.pointerIvarCount,
            arrayIvarCount: summary.arrayIvarCount,
            objectIvarCount: summary.objectIvarCount,
            blockIvarCount: summary.blockIvarCount,
            ivarsWithQualifiersCount: summary.ivarsWithQualifiersCount,
            ivarsWithObjectProtocolsCount: summary.ivarsWithObjectProtocolsCount,
            ivarsWithObjectClassCount: summary.ivarsWithObjectClassCount,
            ivarsWithPointeeTypeCount: summary.ivarsWithPointeeTypeCount,
            ivarsWithMemberNameCount: summary.ivarsWithMemberNameCount,
            kinds: summary.kinds,
            objectClasses: summary.objectClasses,
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
            hasIvarInfo: normalized !== null,
            resolved: normalized !== null,
            resolvedClassName: normalized === null ? null : normalized.className,
            resolvedName: normalized === null ? null : normalized.name,
            resolvedIvarPointer: normalized === null ? null : normalized.ivarPointer,
            resolvedOffset: normalized === null ? null : normalized.offset,
            resolvedOffsetHex: normalized === null ? null : normalized.offsetHex,
            resolvedTypeName: normalized === null ? null : normalized.typeName,
            resolvedKindName: normalized === null ? null : normalized.kind,
            resolvedObjectClassName: normalized === null ? null : normalized.objectClassName,
            resolvedMemberName: normalized === null ? null : normalized.memberName,
            typeName: normalized === null ? null : normalized.typeName,
            kindName: normalized === null ? null : normalized.kind,
            objectClassName: normalized === null ? null : normalized.objectClassName,
            objectProtocolCount: normalized === null ? 0 : normalized.objectProtocolCount,
            arrayCount: normalized === null ? null : normalized.arrayCount,
            qualifierCount: normalized === null ? 0 : normalized.qualifierCount,
            hasQualifiers: normalized !== null && normalized.hasQualifiers === true,
            hasObjectClassName: normalized !== null && normalized.hasObjectClassName === true,
            hasPointeeType: normalized !== null && normalized.hasPointeeType === true,
            isPointer: normalized !== null && normalized.isPointer === true,
            isArray: normalized !== null && normalized.isArray === true,
            memberName: normalized === null ? null : normalized.memberName,
            hasMemberName: normalized !== null && normalized.hasMemberName === true,
            imagePath: normalized === null ? null : normalized.imagePath,
            resolvedImagePath: normalized === null ? null : normalized.imagePath,
            text: normalized === null ? '<null>' : normalized.text,
        };
    }
    case 'objc.method_owners': {
        const query = String(spec.query || '');
        const isClassMethod = !!spec.isClassMethod;
        const methods = ObjC.methodOwners(query, isClassMethod).map((method) => normalizeObjcMethod(method));
        const owners = [];
        const selectors = [];
        const ownerClassNames = [];
        let keywordSelectorCount = 0;
        let unarySelectorCount = 0;
        let explicitArgumentMethodCount = 0;
        let returnsVoidCount = 0;
        let returnsObjectCount = 0;
        let returnsBlockCount = 0;
        for (const method of methods) {
            if (method.isKeywordSelector) {
                keywordSelectorCount += 1;
            }
            if (method.isUnarySelector) {
                unarySelectorCount += 1;
            }
            if (method.hasExplicitArguments) {
                explicitArgumentMethodCount += 1;
            }
            if (method.returnsVoid) {
                returnsVoidCount += 1;
            }
            if (method.returnsObject) {
                returnsObjectCount += 1;
            }
            if (method.returnsBlock) {
                returnsBlockCount += 1;
            }
            let ownerSummary = owners.find((item) => item.className === method.className);
            if (ownerSummary === undefined) {
                ownerSummary = {
                    className: method.className,
                    count: 0,
                    firstSelector: method.selector,
                    lastSelector: method.selector,
                    keywordSelectorCount: 0,
                };
                owners.push(ownerSummary);
                ownerClassNames.push(method.className);
            }
            ownerSummary.count += 1;
            ownerSummary.lastSelector = method.selector;
            if (method.isKeywordSelector) {
                ownerSummary.keywordSelectorCount += 1;
            }
            let selectorSummary = selectors.find((item) => item.selector === method.selector);
            if (selectorSummary === undefined) {
                selectorSummary = {
                    selector: method.selector,
                    count: 0,
                    firstOwner: method.className,
                    lastOwner: method.className,
                    keywordSelector: method.isKeywordSelector,
                };
                selectors.push(selectorSummary);
            }
            selectorSummary.count += 1;
            selectorSummary.lastOwner = method.className;
        }
        const summary = summarizeObjcClassNames(ownerClassNames);
        return {
            kind: 'objc.method_owners',
            query,
            isClassMethod,
            hasQuery: query.length !== 0,
            count: methods.length,
            hasMethods: methods.length !== 0,
            firstOwner: methods.length === 0 ? null : methods[0].className,
            lastOwner: methods.length === 0 ? null : methods[methods.length - 1].className,
            firstSelector: methods.length === 0 ? null : methods[0].selector,
            lastSelector: methods.length === 0 ? null : methods[methods.length - 1].selector,
            uniqueOwnerCount: owners.length,
            uniqueSelectorCount: selectors.length,
            keywordSelectorCount,
            unarySelectorCount,
            explicitArgumentMethodCount,
            returnsVoidCount,
            returnsObjectCount,
            returnsBlockCount,
            firstImagePath: summary.firstImagePath,
            lastImagePath: summary.lastImagePath,
            uniqueImagePathCount: summary.uniqueImagePathCount,
            ownersWithImagePathCount: summary.classesWithImagePathCount,
            classesWithProtocolsCount: summary.classesWithProtocolsCount,
            classesWithPropertiesCount: summary.classesWithPropertiesCount,
            classesWithIvarsCount: summary.classesWithIvarsCount,
            classesWithMethodsCount: summary.classesWithMethodsCount,
            totalProtocolCount: summary.totalProtocolCount,
            totalPropertyCount: summary.totalPropertyCount,
            totalIvarCount: summary.totalIvarCount,
            totalMethodCount: summary.totalMethodCount,
            totalInstanceSize: summary.totalInstanceSize,
            imagePaths: summary.imagePaths,
            owners,
            selectors,
            methods,
            text: methods.map((method) => method.text).join('\n'),
        };
    }
    case 'native.images': {
        const filter = spec.filter === null || spec.filter === undefined ? null : String(spec.filter).trim().toLowerCase();
        const images = Native.images(filter).map((image) => normalizeImage(image));
        const imageNames = [];
        const pathKinds = [];
        let systemImageCount = 0;
        let appImageCount = 0;
        let jailbreakImageCount = 0;
        for (const image of images) {
            if (image.isSystemPath) {
                systemImageCount += 1;
            }
            if (image.isAppPath) {
                appImageCount += 1;
            }
            if (image.isJailbreakPath) {
                jailbreakImageCount += 1;
            }
            let imageNameSummary = imageNames.find((item) => item.name === image.name);
            if (imageNameSummary === undefined) {
                imageNameSummary = {
                    name: image.name,
                    count: 0,
                    firstPath: image.path,
                    lastPath: image.path,
                };
                imageNames.push(imageNameSummary);
            }
            imageNameSummary.count += 1;
            imageNameSummary.lastPath = image.path;
            let pathKindSummary = pathKinds.find((item) => item.pathKind === image.pathKind);
            if (pathKindSummary === undefined) {
                pathKindSummary = {
                    pathKind: image.pathKind,
                    count: 0,
                    firstImageName: image.name,
                    lastImageName: image.name,
                };
                pathKinds.push(pathKindSummary);
            }
            pathKindSummary.count += 1;
            pathKindSummary.lastImageName = image.name;
        }
        return {
            kind: 'native.images',
            filter,
            hasFilter: filter !== null && filter.length !== 0,
            count: images.length,
            hasImages: images.length !== 0,
            firstImageName: images.length === 0 ? null : images[0].name,
            lastImageName: images.length === 0 ? null : images[images.length - 1].name,
            firstImagePath: images.length === 0 ? null : images[0].path,
            lastImagePath: images.length === 0 ? null : images[images.length - 1].path,
            firstPathKind: images.length === 0 ? null : images[0].pathKind,
            lastPathKind: images.length === 0 ? null : images[images.length - 1].pathKind,
            uniqueImageCount: imageNames.length,
            uniquePathKindCount: pathKinds.length,
            systemImageCount,
            appImageCount,
            jailbreakImageCount,
            imageNames,
            pathKinds,
            images,
            text: images.map((image) => image.text).join('\n'),
        };
    }
    case 'native.base': {
        const moduleName = String(spec.moduleName || '');
        const base = Native.base(moduleName);
        const normalized = base === null ? null : base.toString();
        return {
            kind: 'native.base',
            moduleName,
            base: normalized,
            hasBase: normalized !== null,
            resolved: normalized !== null,
            resolvedModuleName: normalized === null ? null : moduleName,
            resolvedBase: normalized,
            text: normalized === null ? '<null>' : normalized,
        };
    }
    case 'native.image_info': {
        const moduleName = String(spec.moduleName || '');
        const image = Native.imageInfo(moduleName);
        const normalized = image === null ? null : normalizeImage(image);
        return {
            kind: 'native.image_info',
            moduleName,
            image: normalized,
            hasImage: normalized !== null,
            resolved: normalized !== null,
            imageName: normalized === null ? null : normalized.name,
            imagePath: normalized === null ? null : normalized.path,
            resolvedImageName: normalized === null ? null : normalized.name,
            resolvedImagePath: normalized === null ? null : normalized.path,
            directoryPath: normalized === null ? null : normalized.directoryPath,
            resolvedDirectoryPath: normalized === null ? null : normalized.directoryPath,
            pathKind: normalized === null ? null : normalized.pathKind,
            resolvedPathKind: normalized === null ? null : normalized.pathKind,
            resolvedBase: normalized === null ? null : normalized.base,
            slide: normalized === null ? null : normalized.slide,
            resolvedSlide: normalized === null ? null : normalized.slide,
            sizeHex: normalized === null ? null : normalized.sizeHex,
            resolvedSizeHex: normalized === null ? null : normalized.sizeHex,
            hasDirectoryPath: normalized !== null && normalized.hasDirectoryPath === true,
            isSystemPath: normalized !== null && normalized.isSystemPath === true,
            isAppPath: normalized !== null && normalized.isAppPath === true,
            isJailbreakPath: normalized !== null && normalized.isJailbreakPath === true,
            text: normalized === null ? '<null>' : normalized.text,
        };
    }
    case 'native.main_image': {
        const imageValue = Native.mainImage();
        const image = imageValue === null ? null : normalizeImage(imageValue);
        return {
            kind: 'native.main_image',
            image,
            hasImage: image !== null,
            resolved: image !== null,
            imageName: image === null ? null : image.name,
            imagePath: image === null ? null : image.path,
            resolvedImageName: image === null ? null : image.name,
            resolvedImagePath: image === null ? null : image.path,
            directoryPath: image === null ? null : image.directoryPath,
            resolvedDirectoryPath: image === null ? null : image.directoryPath,
            pathKind: image === null ? null : image.pathKind,
            resolvedPathKind: image === null ? null : image.pathKind,
            resolvedBase: image === null ? null : image.base,
            slide: image === null ? null : image.slide,
            resolvedSlide: image === null ? null : image.slide,
            sizeHex: image === null ? null : image.sizeHex,
            resolvedSizeHex: image === null ? null : image.sizeHex,
            hasDirectoryPath: image !== null && image.hasDirectoryPath === true,
            isSystemPath: image !== null && image.isSystemPath === true,
            isAppPath: image !== null && image.isAppPath === true,
            isJailbreakPath: image !== null && image.isJailbreakPath === true,
            text: image === null ? '<null>' : image.text,
        };
    }
    case 'native.image': {
        const address = parseAddressArg(spec.address, 'native.image usage: native.image <address>');
        const image = Native.image(address);
        const normalized = image === null ? null : normalizeImage(image);
        return {
            kind: 'native.image',
            address: address.toString(),
            image: normalized,
            hasImage: normalized !== null,
            resolved: normalized !== null,
            imageName: normalized === null ? null : normalized.name,
            imagePath: normalized === null ? null : normalized.path,
            resolvedImageName: normalized === null ? null : normalized.name,
            resolvedImagePath: normalized === null ? null : normalized.path,
            directoryPath: normalized === null ? null : normalized.directoryPath,
            resolvedDirectoryPath: normalized === null ? null : normalized.directoryPath,
            pathKind: normalized === null ? null : normalized.pathKind,
            resolvedPathKind: normalized === null ? null : normalized.pathKind,
            resolvedBase: normalized === null ? null : normalized.base,
            slide: normalized === null ? null : normalized.slide,
            resolvedSlide: normalized === null ? null : normalized.slide,
            sizeHex: normalized === null ? null : normalized.sizeHex,
            resolvedSizeHex: normalized === null ? null : normalized.sizeHex,
            hasDirectoryPath: normalized !== null && normalized.hasDirectoryPath === true,
            isSystemPath: normalized !== null && normalized.isSystemPath === true,
            isAppPath: normalized !== null && normalized.isAppPath === true,
            isJailbreakPath: normalized !== null && normalized.isJailbreakPath === true,
            text: normalized === null ? '<null>' : normalized.text,
        };
    }
    case 'native.symbol': {
        const address = parseAddressArg(spec.address, 'native.symbol usage: native.symbol <address>');
        const symbol = normalizeDebugSymbol(Native.symbol(address), address);
        return {
            kind: 'native.symbol',
            address: address.toString(),
            symbol,
            resolved: symbol.resolved === true,
            resolvedName: symbol.name,
            resolvedModuleName: symbol.moduleName,
            resolvedAddress: symbol.address,
            hasName: symbol.name !== null,
            hasModuleName: symbol.moduleName !== null,
            text: symbol.text,
        };
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
            hasAddress: address !== null,
            hasSymbol: symbol !== null,
            resolved: symbol !== null && symbol.resolved === true,
            resolvedName: symbol === null ? null : symbol.name,
            resolvedModuleName: symbol === null ? null : symbol.moduleName,
            resolvedAddress: symbol === null ? null : symbol.address,
            hasName: symbol !== null && symbol.name !== null,
            hasModuleName: symbol !== null && symbol.moduleName !== null,
            text: symbol === null ? '<null>' : symbol.text,
        };
    }
    case 'native.symbols': {
        const moduleName = spec.moduleName === null || spec.moduleName === undefined ? null : String(spec.moduleName);
        const query = String(spec.query || '');
        const symbols = Native.symbols(query, moduleName).map((symbol) => normalizeNativeSymbol(symbol));
        const moduleNames = new Set();
        const moduleSummaries = [];
        const symbolNames = [];
        for (const symbol of symbols) {
            moduleNames.add(symbol.moduleName);
            let moduleSummary = moduleSummaries.find((item) => item.moduleName === symbol.moduleName);
            if (moduleSummary === undefined) {
                moduleSummary = {
                    moduleName: symbol.moduleName,
                    count: 0,
                    firstSymbolName: symbol.name,
                    lastSymbolName: symbol.name,
                };
                moduleSummaries.push(moduleSummary);
            }
            moduleSummary.count += 1;
            moduleSummary.lastSymbolName = symbol.name;
            let summary = symbolNames.find((item) => item.symbolName === symbol.name);
            if (summary === undefined) {
                summary = {
                    symbolName: symbol.name,
                    count: 0,
                    firstModuleName: symbol.moduleName,
                    lastModuleName: symbol.moduleName,
                };
                symbolNames.push(summary);
            }
            summary.count += 1;
            summary.lastModuleName = symbol.moduleName;
        }
        return {
            kind: 'native.symbols',
            moduleName,
            query,
            hasQuery: query.length !== 0,
            count: symbols.length,
            hasSymbols: symbols.length !== 0,
            firstSymbolName: symbols.length === 0 ? null : symbols[0].name,
            lastSymbolName: symbols.length === 0 ? null : symbols[symbols.length - 1].name,
            firstModuleName: symbols.length === 0 ? null : symbols[0].moduleName,
            lastModuleName: symbols.length === 0 ? null : symbols[symbols.length - 1].moduleName,
            uniqueModuleCount: symbols.length === 0 ? 0 : moduleNames.size,
            uniqueSymbolCount: symbolNames.length,
            moduleNames: moduleSummaries,
            symbolNames,
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
            hasSymbolInfo: normalized !== null,
            resolved: normalized !== null,
            resolvedName: normalized === null ? null : normalized.name,
            resolvedModuleName: normalized === null ? null : normalized.moduleName,
            resolvedModuleBase: normalized === null ? null : normalized.moduleBase,
            resolvedAddress: normalized === null ? null : normalized.address,
            resolvedOffsetHex: normalized === null ? null : normalized.offsetHex,
            name: normalized === null ? null : normalized.name,
            moduleBase: normalized === null ? null : normalized.moduleBase,
            address: normalized === null ? null : normalized.address,
            offsetHex: normalized === null ? null : normalized.offsetHex,
            hasAddress: normalized !== null,
            hasName: normalized !== null && normalized.hasName === true,
            hasModuleName: normalized !== null && normalized.hasModuleName === true,
            text: normalized === null ? '<null>' : normalized.text,
        };
    }
    case 'native.exports': {
        const moduleName = String(spec.moduleName || '');
        const query = spec.query === null || spec.query === undefined ? null : String(spec.query);
        const symbols = Native.exports(moduleName, query).map((symbol) => normalizeNativeSymbol(symbol));
        const moduleNames = new Set();
        const moduleSummaries = [];
        const symbolNames = [];
        for (const symbol of symbols) {
            moduleNames.add(symbol.moduleName);
            let moduleSummary = moduleSummaries.find((item) => item.moduleName === symbol.moduleName);
            if (moduleSummary === undefined) {
                moduleSummary = {
                    moduleName: symbol.moduleName,
                    count: 0,
                    firstSymbolName: symbol.name,
                    lastSymbolName: symbol.name,
                };
                moduleSummaries.push(moduleSummary);
            }
            moduleSummary.count += 1;
            moduleSummary.lastSymbolName = symbol.name;
            let summary = symbolNames.find((item) => item.symbolName === symbol.name);
            if (summary === undefined) {
                summary = {
                    symbolName: symbol.name,
                    count: 0,
                    firstModuleName: symbol.moduleName,
                    lastModuleName: symbol.moduleName,
                };
                symbolNames.push(summary);
            }
            summary.count += 1;
            summary.lastModuleName = symbol.moduleName;
        }
        return {
            kind: 'native.exports',
            moduleName,
            query,
            hasQuery: query !== null && query.length !== 0,
            count: symbols.length,
            hasSymbols: symbols.length !== 0,
            firstSymbolName: symbols.length === 0 ? null : symbols[0].name,
            lastSymbolName: symbols.length === 0 ? null : symbols[symbols.length - 1].name,
            firstModuleName: symbols.length === 0 ? null : symbols[0].moduleName,
            lastModuleName: symbols.length === 0 ? null : symbols[symbols.length - 1].moduleName,
            uniqueModuleCount: symbols.length === 0 ? 0 : moduleNames.size,
            uniqueSymbolCount: symbolNames.length,
            moduleNames: moduleSummaries,
            symbolNames,
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
            hasExportInfo: normalized !== null,
            resolved: normalized !== null,
            resolvedName: normalized === null ? null : normalized.name,
            resolvedModuleName: normalized === null ? null : normalized.moduleName,
            resolvedModuleBase: normalized === null ? null : normalized.moduleBase,
            resolvedAddress: normalized === null ? null : normalized.address,
            resolvedOffsetHex: normalized === null ? null : normalized.offsetHex,
            name: normalized === null ? null : normalized.name,
            moduleBase: normalized === null ? null : normalized.moduleBase,
            address: normalized === null ? null : normalized.address,
            offsetHex: normalized === null ? null : normalized.offsetHex,
            hasAddress: normalized !== null,
            hasName: normalized !== null && normalized.hasName === true,
            hasModuleName: normalized !== null && normalized.hasModuleName === true,
            text: normalized === null ? '<null>' : normalized.text,
        };
    }
    case 'native.dependencies': {
        const moduleName = String(spec.moduleName || '');
        const query = spec.query === null || spec.query === undefined ? null : String(spec.query);
        const dependencies = Native.dependencies(moduleName, query).map((dependency) => normalizeDependency(dependency));
        const weakDependencies = dependencies.filter((dependency) => dependency.isWeakDependency);
        const reexportDependencies = dependencies.filter((dependency) => dependency.isReexportDependency);
        const upwardDependencies = dependencies.filter((dependency) => dependency.isUpwardDependency);
        const loadDependencies = dependencies.filter((dependency) => dependency.isLoadDependency);
        const timestampedDependencies = dependencies.filter((dependency) => dependency.hasTimestamp);
        const versionMismatchDependencies = dependencies.filter((dependency) => dependency.versionMismatch);
        const pathKindSummaries = [];
        const kindSummaries = [];
        const dependencyNames = [];
        for (const dependency of dependencies) {
            let pathKindSummary = pathKindSummaries.find((item) => item.pathKind === dependency.pathKind);
            if (pathKindSummary === undefined) {
                pathKindSummary = {
                    pathKind: dependency.pathKind,
                    count: 0,
                    firstDependencyName: dependency.name,
                    lastDependencyName: dependency.name,
                    firstPath: dependency.path,
                    lastPath: dependency.path,
                };
                pathKindSummaries.push(pathKindSummary);
            }
            pathKindSummary.count += 1;
            pathKindSummary.lastDependencyName = dependency.name;
            pathKindSummary.lastPath = dependency.path;
            let kindSummary = kindSummaries.find((item) => item.kind === dependency.kind);
            if (kindSummary === undefined) {
                kindSummary = {
                    kind: dependency.kind,
                    count: 0,
                    firstDependencyName: dependency.name,
                    lastDependencyName: dependency.name,
                    timestampedCount: 0,
                    versionMismatchCount: 0,
                };
                kindSummaries.push(kindSummary);
            }
            kindSummary.count += 1;
            kindSummary.lastDependencyName = dependency.name;
            if (dependency.hasTimestamp) {
                kindSummary.timestampedCount += 1;
            }
            if (dependency.versionMismatch) {
                kindSummary.versionMismatchCount += 1;
            }
            let dependencyNameSummary = dependencyNames.find((item) => item.dependencyName === dependency.name);
            if (dependencyNameSummary === undefined) {
                dependencyNameSummary = {
                    dependencyName: dependency.name,
                    count: 0,
                    firstPath: dependency.path,
                    lastPath: dependency.path,
                    firstKind: dependency.kind,
                    lastKind: dependency.kind,
                    timestampedCount: 0,
                    versionMismatchCount: 0,
                };
                dependencyNames.push(dependencyNameSummary);
            }
            dependencyNameSummary.count += 1;
            dependencyNameSummary.lastPath = dependency.path;
            dependencyNameSummary.lastKind = dependency.kind;
            if (dependency.hasTimestamp) {
                dependencyNameSummary.timestampedCount += 1;
            }
            if (dependency.versionMismatch) {
                dependencyNameSummary.versionMismatchCount += 1;
            }
        }
        return {
            kind: 'native.dependencies',
            moduleName,
            query,
            hasQuery: query !== null && query.length !== 0,
            count: dependencies.length,
            hasDependencies: dependencies.length !== 0,
            firstDependencyName: dependencies.length === 0 ? null : dependencies[0].name,
            lastDependencyName: dependencies.length === 0 ? null : dependencies[dependencies.length - 1].name,
            firstPath: dependencies.length === 0 ? null : dependencies[0].path,
            lastPath: dependencies.length === 0 ? null : dependencies[dependencies.length - 1].path,
            uniquePathKindCount: pathKindSummaries.length,
            uniqueKindCount: kindSummaries.length,
            uniqueDependencyNameCount: dependencyNames.length,
            weakDependencyCount: weakDependencies.length,
            hasWeakDependencies: weakDependencies.length !== 0,
            reexportDependencyCount: reexportDependencies.length,
            hasReexportDependencies: reexportDependencies.length !== 0,
            upwardDependencyCount: upwardDependencies.length,
            hasUpwardDependencies: upwardDependencies.length !== 0,
            loadDependencyCount: loadDependencies.length,
            hasLoadDependencies: loadDependencies.length !== 0,
            timestampedDependencyCount: timestampedDependencies.length,
            hasTimestampedDependencies: timestampedDependencies.length !== 0,
            versionMismatchCount: versionMismatchDependencies.length,
            hasVersionMismatches: versionMismatchDependencies.length !== 0,
            pathKinds: pathKindSummaries,
            kinds: kindSummaries,
            dependencyNames,
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
            hasDependencyInfo: normalized !== null,
            resolved: normalized !== null,
            resolvedName: normalized === null ? null : normalized.name,
            resolvedPath: normalized === null ? null : normalized.path,
            resolvedModuleName: normalized === null ? null : normalized.moduleName,
            resolvedModuleBase: normalized === null ? null : normalized.moduleBase,
            resolvedOrdinal: normalized === null ? null : normalized.ordinal,
            resolvedCurrentVersion: normalized === null ? null : normalized.currentVersion,
            resolvedCompatibilityVersion: normalized === null ? null : normalized.compatibilityVersion,
            name: normalized === null ? null : normalized.name,
            path: normalized === null ? null : normalized.path,
            pathKind: normalized === null ? null : normalized.pathKind,
            moduleBase: normalized === null ? null : normalized.moduleBase,
            ordinal: normalized === null ? null : normalized.ordinal,
            currentVersion: normalized === null ? null : normalized.currentVersion,
            compatibilityVersion: normalized === null ? null : normalized.compatibilityVersion,
            timestamp: normalized === null ? null : normalized.timestamp,
            kindName: normalized === null ? null : normalized.kind,
            isWeakDependency: normalized !== null && normalized.isWeakDependency === true,
            isReexportDependency: normalized !== null && normalized.isReexportDependency === true,
            isUpwardDependency: normalized !== null && normalized.isUpwardDependency === true,
            isLoadDependency: normalized !== null && normalized.isLoadDependency === true,
            hasTimestamp: normalized !== null && normalized.hasTimestamp === true,
            versionMismatch: normalized !== null && normalized.versionMismatch === true,
            text: normalized === null ? '<null>' : normalized.text,
        };
    }
    case 'native.encryption_info': {
        const moduleName = String(spec.moduleName || '');
        const encryptionInfo = Native.encryptionInfo(moduleName);
        const normalized = encryptionInfo === null ? null : normalizeEncryptionInfo(encryptionInfo);
        return {
            kind: 'native.encryption_info',
            moduleName,
            encryptionInfo: normalized,
            hasEncryptionInfo: normalized !== null,
            resolved: normalized !== null,
            resolvedModuleName: normalized === null ? null : normalized.moduleName,
            resolvedModuleBase: normalized === null ? null : normalized.moduleBase,
            resolvedCryptoffHex: normalized === null ? null : normalized.cryptoffHex,
            resolvedCryptsizeHex: normalized === null ? null : normalized.cryptsizeHex,
            cryptoffHex: normalized === null ? null : normalized.cryptoffHex,
            cryptsizeHex: normalized === null ? null : normalized.cryptsizeHex,
            cryptid: normalized === null ? null : normalized.cryptid,
            hasEncryptedRange: normalized !== null && normalized.cryptid !== 0,
            text: normalized === null ? '<null>' : normalized.text,
        };
    }
    case 'native.entry_point': {
        const moduleName = String(spec.moduleName || '');
        const entryPoint = Native.entryPoint(moduleName);
        const normalized = entryPoint === null ? null : normalizeEntryPoint(entryPoint);
        return {
            kind: 'native.entry_point',
            moduleName,
            entryPoint: normalized,
            hasEntryPoint: normalized !== null,
            resolved: normalized !== null,
            resolvedModuleName: normalized === null ? null : normalized.moduleName,
            resolvedModuleBase: normalized === null ? null : normalized.moduleBase,
            entryoffHex: normalized === null ? null : normalized.entryoffHex,
            stacksizeHex: normalized === null ? null : normalized.stacksizeHex,
            text: normalized === null ? '<null>' : normalized.text,
        };
    }
    case 'native.dyld_info': {
        const moduleName = String(spec.moduleName || '');
        const dyldInfo = Native.dyldInfo(moduleName);
        const normalized = dyldInfo === null ? null : normalizeDyldInfo(dyldInfo);
        return {
            kind: 'native.dyld_info',
            moduleName,
            dyldInfo: normalized,
            hasDyldInfo: normalized !== null,
            resolved: normalized !== null,
            resolvedModuleName: normalized === null ? null : normalized.moduleName,
            resolvedModuleBase: normalized === null ? null : normalized.moduleBase,
            moduleBase: normalized === null ? null : normalized.moduleBase,
            resolvedCommandHex: normalized === null ? null : normalized.commandHex,
            commandHex: normalized === null ? null : normalized.commandHex,
            commandName: normalized === null ? null : normalized.commandName,
            resolvedCommandName: normalized === null ? null : normalized.commandName,
            commandRequiresDyld: normalized !== null && normalized.commandRequiresDyld === true,
            resolvedRebaseOffHex: normalized === null ? null : normalized.rebaseOffHex,
            rebaseOffHex: normalized === null ? null : normalized.rebaseOffHex,
            resolvedRebaseSizeHex: normalized === null ? null : normalized.rebaseSizeHex,
            rebaseSizeHex: normalized === null ? null : normalized.rebaseSizeHex,
            resolvedRebaseEndHex: normalized === null ? null : normalized.rebaseEndHex,
            rebaseEndHex: normalized === null ? null : normalized.rebaseEndHex,
            resolvedBindOffHex: normalized === null ? null : normalized.bindOffHex,
            bindOffHex: normalized === null ? null : normalized.bindOffHex,
            resolvedBindSizeHex: normalized === null ? null : normalized.bindSizeHex,
            bindSizeHex: normalized === null ? null : normalized.bindSizeHex,
            resolvedBindEndHex: normalized === null ? null : normalized.bindEndHex,
            bindEndHex: normalized === null ? null : normalized.bindEndHex,
            resolvedWeakBindOffHex: normalized === null ? null : normalized.weakBindOffHex,
            weakBindOffHex: normalized === null ? null : normalized.weakBindOffHex,
            resolvedWeakBindSizeHex: normalized === null ? null : normalized.weakBindSizeHex,
            weakBindSizeHex: normalized === null ? null : normalized.weakBindSizeHex,
            resolvedWeakBindEndHex: normalized === null ? null : normalized.weakBindEndHex,
            weakBindEndHex: normalized === null ? null : normalized.weakBindEndHex,
            resolvedLazyBindOffHex: normalized === null ? null : normalized.lazyBindOffHex,
            lazyBindOffHex: normalized === null ? null : normalized.lazyBindOffHex,
            resolvedLazyBindSizeHex: normalized === null ? null : normalized.lazyBindSizeHex,
            lazyBindSizeHex: normalized === null ? null : normalized.lazyBindSizeHex,
            resolvedLazyBindEndHex: normalized === null ? null : normalized.lazyBindEndHex,
            lazyBindEndHex: normalized === null ? null : normalized.lazyBindEndHex,
            resolvedExportOffHex: normalized === null ? null : normalized.exportOffHex,
            exportOffHex: normalized === null ? null : normalized.exportOffHex,
            resolvedExportSizeHex: normalized === null ? null : normalized.exportSizeHex,
            exportSizeHex: normalized === null ? null : normalized.exportSizeHex,
            resolvedExportEndHex: normalized === null ? null : normalized.exportEndHex,
            exportEndHex: normalized === null ? null : normalized.exportEndHex,
            totalRegionCount: normalized === null ? 0 : normalized.totalRegionCount,
            regionCount: normalized === null ? 0 : normalized.regionCount,
            nonEmptyRegionCount: normalized === null ? 0 : normalized.nonEmptyRegionNames.length,
            hasRegions: normalized !== null && normalized.hasRegions === true,
            resolvedFirstRegionName: normalized === null ? null : normalized.firstRegionName,
            firstRegionName: normalized === null ? null : normalized.firstRegionName,
            resolvedLastRegionName: normalized === null ? null : normalized.lastRegionName,
            lastRegionName: normalized === null ? null : normalized.lastRegionName,
            resolvedLargestRegionName: normalized === null ? null : normalized.largestRegionName,
            largestRegionName: normalized === null ? null : normalized.largestRegionName,
            resolvedLargestRegionSizeHex: normalized === null ? null : normalized.largestRegionSizeHex,
            largestRegionSizeHex: normalized === null ? null : normalized.largestRegionSizeHex,
            nonEmptyRegionNames: normalized === null ? [] : normalized.nonEmptyRegionNames,
            regions: normalized === null ? [] : normalized.regions,
            resolvedTotalSizeHex: normalized === null ? null : normalized.totalSizeHex,
            totalSizeHex: normalized === null ? null : normalized.totalSizeHex,
            hasRebaseInfo: normalized !== null && normalized.hasRebaseInfo === true,
            hasBindInfo: normalized !== null && normalized.hasBindInfo === true,
            hasWeakBindInfo: normalized !== null && normalized.hasWeakBindInfo === true,
            hasLazyBindInfo: normalized !== null && normalized.hasLazyBindInfo === true,
            hasExportInfo: normalized !== null && normalized.hasExportInfo === true,
            hasAnyBindInfo: normalized !== null && normalized.hasAnyBindInfo === true,
            text: normalized === null ? '<null>' : normalized.text,
        };
    }
    case 'native.linkedit': {
        const moduleName = String(spec.moduleName || '');
        const linkedit = Native.linkedit(moduleName);
        const normalized = linkedit === null ? null : normalizeLinkedit(linkedit);
        return {
            kind: 'native.linkedit',
            moduleName,
            linkedit: normalized,
            hasLinkedit: normalized !== null,
            resolved: normalized !== null,
            resolvedModuleName: normalized === null ? null : normalized.moduleName,
            resolvedModuleBase: normalized === null ? null : normalized.moduleBase,
            moduleBase: normalized === null ? null : normalized.moduleBase,
            resolvedVmaddr: normalized === null ? null : normalized.vmaddr,
            vmaddr: normalized === null ? null : normalized.vmaddr,
            resolvedVmEnd: normalized === null ? null : normalized.vmEnd,
            vmEnd: normalized === null ? null : normalized.vmEnd,
            resolvedVmsizeHex: normalized === null ? null : normalized.vmsizeHex,
            vmsizeHex: normalized === null ? null : normalized.vmsizeHex,
            resolvedFileoffHex: normalized === null ? null : normalized.fileoffHex,
            fileoffHex: normalized === null ? null : normalized.fileoffHex,
            resolvedFilesizeHex: normalized === null ? null : normalized.filesizeHex,
            filesizeHex: normalized === null ? null : normalized.filesizeHex,
            resolvedFileEndHex: normalized === null ? null : normalized.fileEndHex,
            fileEndHex: normalized === null ? null : normalized.fileEndHex,
            resolvedComputedBase: normalized === null ? null : normalized.computedBase,
            computedBase: normalized === null ? null : normalized.computedBase,
            resolvedComputedEnd: normalized === null ? null : normalized.computedEnd,
            computedEnd: normalized === null ? null : normalized.computedEnd,
            resolvedSymoffHex: normalized === null ? null : normalized.symoffHex,
            symoffHex: normalized === null ? null : normalized.symoffHex,
            resolvedNsyms: normalized === null ? null : normalized.nsyms,
            nsyms: normalized === null ? null : normalized.nsyms,
            resolvedSymtabAddress: normalized === null ? null : normalized.symtabAddress,
            symtabAddress: normalized === null ? null : normalized.symtabAddress,
            resolvedStroffHex: normalized === null ? null : normalized.stroffHex,
            stroffHex: normalized === null ? null : normalized.stroffHex,
            resolvedStrsizeHex: normalized === null ? null : normalized.strsizeHex,
            strsizeHex: normalized === null ? null : normalized.strsizeHex,
            resolvedStrtabAddress: normalized === null ? null : normalized.strtabAddress,
            strtabAddress: normalized === null ? null : normalized.strtabAddress,
            resolvedIndirectsymoffHex: normalized === null ? null : normalized.indirectsymoffHex,
            indirectsymoffHex: normalized === null ? null : normalized.indirectsymoffHex,
            resolvedNindirectsyms: normalized === null ? null : normalized.nindirectsyms,
            nindirectsyms: normalized === null ? null : normalized.nindirectsyms,
            resolvedIndirectsymAddress: normalized === null ? null : normalized.indirectsymAddress,
            indirectsymAddress: normalized === null ? null : normalized.indirectsymAddress,
            totalTableCount: normalized === null ? 0 : normalized.totalTableCount,
            tableCount: normalized === null ? 0 : normalized.tableCount,
            hasTables: normalized !== null && normalized.hasTables === true,
            tableNames: normalized === null ? [] : normalized.tableNames,
            nonEmptyTableNames: normalized === null ? [] : normalized.nonEmptyTableNames,
            resolvedFirstTableName: normalized === null ? null : normalized.firstTableName,
            firstTableName: normalized === null ? null : normalized.firstTableName,
            resolvedLastTableName: normalized === null ? null : normalized.lastTableName,
            lastTableName: normalized === null ? null : normalized.lastTableName,
            tables: normalized === null ? [] : normalized.tables,
            hasSymtab: normalized !== null && normalized.hasSymtab === true,
            hasStrtab: normalized !== null && normalized.hasStrtab === true,
            hasIndirectSymbols: normalized !== null && normalized.hasIndirectSymbols === true,
            text: normalized === null ? '<null>' : normalized.text,
        };
    }
    case 'native.function_starts': {
        const moduleName = String(spec.moduleName || '');
        const functionStarts = Native.functionStarts(moduleName);
        const normalized = functionStarts === null ? null : normalizeFunctionStarts(functionStarts);
        return {
            kind: 'native.function_starts',
            moduleName,
            functionStarts: normalized,
            hasFunctionStarts: normalized !== null,
            resolved: normalized !== null,
            resolvedModuleName: normalized === null ? null : normalized.moduleName,
            resolvedModuleBase: normalized === null ? null : normalized.moduleBase,
            moduleBase: normalized === null ? null : normalized.moduleBase,
            resolvedDataoffHex: normalized === null ? null : normalized.dataoffHex,
            dataoffHex: normalized === null ? null : normalized.dataoffHex,
            resolvedDatasizeHex: normalized === null ? null : normalized.datasizeHex,
            datasizeHex: normalized === null ? null : normalized.datasizeHex,
            linkeditBase: normalized === null ? null : normalized.linkeditBase,
            resolvedDataAddress: normalized === null ? null : normalized.dataAddress,
            dataAddress: normalized === null ? null : normalized.dataAddress,
            resolvedDataEnd: normalized === null ? null : normalized.dataEnd,
            dataEnd: normalized === null ? null : normalized.dataEnd,
            startCount: normalized === null ? 0 : normalized.count,
            hasStarts: normalized !== null && normalized.hasStarts === true,
            firstStartOffsetHex: normalized === null ? null : normalized.firstStartOffsetHex,
            firstStartAddress: normalized === null ? null : normalized.firstStartAddress,
            lastStartOffsetHex: normalized === null ? null : normalized.lastStartOffsetHex,
            lastStartAddress: normalized === null ? null : normalized.lastStartAddress,
            totalSpanHex: normalized === null ? null : normalized.totalSpanHex,
            gapCount: normalized === null ? 0 : normalized.gapCount,
            hasGaps: normalized !== null && normalized.hasGaps === true,
            firstGapHex: normalized === null ? null : normalized.firstGapHex,
            lastGapHex: normalized === null ? null : normalized.lastGapHex,
            firstGapFromOffsetHex: normalized === null ? null : normalized.firstGapFromOffsetHex,
            firstGapToOffsetHex: normalized === null ? null : normalized.firstGapToOffsetHex,
            lastGapFromOffsetHex: normalized === null ? null : normalized.lastGapFromOffsetHex,
            lastGapToOffsetHex: normalized === null ? null : normalized.lastGapToOffsetHex,
            largestGapHex: normalized === null ? null : normalized.largestGapHex,
            text: normalized === null ? '<null>' : normalized.text,
        };
    }
    case 'native.code_signature': {
        const moduleName = String(spec.moduleName || '');
        const codeSignature = Native.codeSignature(moduleName);
        const normalized = codeSignature === null ? null : normalizeCodeSignature(codeSignature);
        return {
            kind: 'native.code_signature',
            moduleName,
            codeSignature: normalized,
            hasCodeSignature: normalized !== null,
            resolved: normalized !== null,
            resolvedModuleName: normalized === null ? null : normalized.moduleName,
            resolvedModuleBase: normalized === null ? null : normalized.moduleBase,
            moduleBase: normalized === null ? null : normalized.moduleBase,
            resolvedDataoffHex: normalized === null ? null : normalized.dataoffHex,
            dataoffHex: normalized === null ? null : normalized.dataoffHex,
            resolvedDatasizeHex: normalized === null ? null : normalized.datasizeHex,
            datasizeHex: normalized === null ? null : normalized.datasizeHex,
            linkeditBase: normalized === null ? null : normalized.linkeditBase,
            resolvedDataAddress: normalized === null ? null : normalized.dataAddress,
            dataAddress: normalized === null ? null : normalized.dataAddress,
            resolvedDataEnd: normalized === null ? null : normalized.dataEnd,
            dataEnd: normalized === null ? null : normalized.dataEnd,
            blobKind: normalized === null ? null : normalized.blobKind,
            magicCategory: normalized === null ? null : normalized.magicCategory,
            resolvedMagicHex: normalized === null ? null : normalized.magicHex,
            magicHex: normalized === null ? null : normalized.magicHex,
            resolvedMagicName: normalized === null ? null : normalized.magicName,
            magicName: normalized === null ? null : normalized.magicName,
            resolvedLengthHex: normalized === null ? null : normalized.lengthHex,
            lengthHex: normalized === null ? null : normalized.lengthHex,
            resolvedCount: normalized === null ? null : normalized.count,
            count: normalized === null ? null : normalized.count,
            hasData: normalized !== null && normalized.hasData === true,
            hasMagic: normalized !== null && normalized.hasMagic === true,
            knownMagic: normalized !== null && normalized.knownMagic === true,
            hasCount: normalized !== null && normalized.hasCount === true,
            hasBlobLength: normalized !== null && normalized.hasBlobLength === true,
            blobLengthMatchesDataSize: normalized === null ? null : normalized.blobLengthMatchesDataSize,
            blobLengthRelation: normalized === null ? null : normalized.blobLengthRelation,
            countMatchesSuperBlob: normalized !== null && normalized.countMatchesSuperBlob === true,
            isSuperBlob: normalized !== null && normalized.isSuperBlob === true,
            isDetachedSignature: normalized !== null && normalized.isDetachedSignature === true,
            isBlobWrapper: normalized !== null && normalized.isBlobWrapper === true,
            isCodeDirectory: normalized !== null && normalized.isCodeDirectory === true,
            isEntitlements: normalized !== null && normalized.isEntitlements === true,
            text: normalized === null ? '<null>' : normalized.text,
        };
    }
    case 'native.data_in_code': {
        const moduleName = String(spec.moduleName || '');
        const dataInCode = Native.dataInCode(moduleName);
        const normalized = dataInCode === null ? null : normalizeDataInCode(dataInCode);
        return {
            kind: 'native.data_in_code',
            moduleName,
            dataInCode: normalized,
            hasDataInCode: normalized !== null,
            resolved: normalized !== null,
            resolvedModuleName: normalized === null ? null : normalized.moduleName,
            resolvedModuleBase: normalized === null ? null : normalized.moduleBase,
            moduleBase: normalized === null ? null : normalized.moduleBase,
            resolvedDataoffHex: normalized === null ? null : normalized.dataoffHex,
            dataoffHex: normalized === null ? null : normalized.dataoffHex,
            resolvedDatasizeHex: normalized === null ? null : normalized.datasizeHex,
            datasizeHex: normalized === null ? null : normalized.datasizeHex,
            linkeditBase: normalized === null ? null : normalized.linkeditBase,
            resolvedDataAddress: normalized === null ? null : normalized.dataAddress,
            dataAddress: normalized === null ? null : normalized.dataAddress,
            resolvedDataEnd: normalized === null ? null : normalized.dataEnd,
            dataEnd: normalized === null ? null : normalized.dataEnd,
            entryCount: normalized === null ? 0 : normalized.count,
            hasEntries: normalized !== null && normalized.hasEntries === true,
            totalEntryLength: normalized === null ? null : normalized.totalEntryLength,
            firstEntryOffsetHex: normalized === null ? null : normalized.firstEntryOffsetHex,
            firstEntryAddress: normalized === null ? null : normalized.firstEntryAddress,
            firstKindName: normalized === null ? null : normalized.firstKindName,
            lastEntryOffsetHex: normalized === null ? null : normalized.lastEntryOffsetHex,
            lastEntryAddress: normalized === null ? null : normalized.lastEntryAddress,
            lastKindName: normalized === null ? null : normalized.lastKindName,
            largestEntryOffsetHex: normalized === null ? null : normalized.largestEntryOffsetHex,
            largestEntryAddress: normalized === null ? null : normalized.largestEntryAddress,
            largestEntryLength: normalized === null ? null : normalized.largestEntryLength,
            totalSpanHex: normalized === null ? null : normalized.totalSpanHex,
            uniqueKindCount: normalized === null ? 0 : normalized.uniqueKindCount,
            hasMultipleKinds: normalized !== null && normalized.hasMultipleKinds === true,
            dataEntryCount: normalized === null ? 0 : normalized.dataEntryCount,
            hasDataEntries: normalized !== null && normalized.hasDataEntries === true,
            jumpTableEntryCount: normalized === null ? 0 : normalized.jumpTableEntryCount,
            hasJumpTables: normalized !== null && normalized.hasJumpTables === true,
            unknownEntryCount: normalized === null ? 0 : normalized.unknownEntryCount,
            hasUnknownKinds: normalized !== null && normalized.hasUnknownKinds === true,
            kinds: normalized === null ? [] : normalized.kinds,
            text: normalized === null ? '<null>' : normalized.text,
        };
    }
    case 'native.exports_trie': {
        const moduleName = String(spec.moduleName || '');
        const exportsTrie = Native.exportsTrie(moduleName);
        const normalized = exportsTrie === null ? null : normalizeExportsTrie(exportsTrie);
        return {
            kind: 'native.exports_trie',
            moduleName,
            exportsTrie: normalized,
            hasExportsTrie: normalized !== null,
            resolved: normalized !== null,
            resolvedModuleName: normalized === null ? null : normalized.moduleName,
            resolvedModuleBase: normalized === null ? null : normalized.moduleBase,
            moduleBase: normalized === null ? null : normalized.moduleBase,
            resolvedDataoffHex: normalized === null ? null : normalized.dataoffHex,
            dataoffHex: normalized === null ? null : normalized.dataoffHex,
            resolvedDatasizeHex: normalized === null ? null : normalized.datasizeHex,
            datasizeHex: normalized === null ? null : normalized.datasizeHex,
            linkeditBase: normalized === null ? null : normalized.linkeditBase,
            resolvedDataAddress: normalized === null ? null : normalized.dataAddress,
            dataAddress: normalized === null ? null : normalized.dataAddress,
            resolvedDataEnd: normalized === null ? null : normalized.dataEnd,
            dataEnd: normalized === null ? null : normalized.dataEnd,
            entryCount: normalized === null ? 0 : normalized.count,
            hasEntries: normalized !== null && normalized.hasEntries === true,
            firstExportName: normalized === null ? null : normalized.firstExportName,
            firstKind: normalized === null ? null : normalized.firstKind,
            lastExportName: normalized === null ? null : normalized.lastExportName,
            lastKind: normalized === null ? null : normalized.lastKind,
            longestExportName: normalized === null ? null : normalized.longestExportName,
            longestExportNameLength: normalized === null ? null : normalized.longestExportNameLength,
            addressSpanHex: normalized === null ? null : normalized.addressSpanHex,
            offsetSpanHex: normalized === null ? null : normalized.offsetSpanHex,
            uniqueKindCount: normalized === null ? 0 : normalized.uniqueKindCount,
            hasMultipleKinds: normalized !== null && normalized.hasMultipleKinds === true,
            addressEntryCount: normalized === null ? 0 : normalized.addressEntryCount,
            hasAddressEntries: normalized !== null && normalized.hasAddressEntries === true,
            lowestAddress: normalized === null ? null : normalized.lowestAddress,
            highestAddress: normalized === null ? null : normalized.highestAddress,
            offsetEntryCount: normalized === null ? 0 : normalized.offsetEntryCount,
            hasOffsetEntries: normalized !== null && normalized.hasOffsetEntries === true,
            lowestOffsetHex: normalized === null ? null : normalized.lowestOffsetHex,
            highestOffsetHex: normalized === null ? null : normalized.highestOffsetHex,
            importNameCount: normalized === null ? 0 : normalized.importNameCount,
            hasImportNames: normalized !== null && normalized.hasImportNames === true,
            resolverCount: normalized === null ? 0 : normalized.resolverCount,
            hasResolvers: normalized !== null && normalized.hasResolvers === true,
            reexportCount: normalized === null ? 0 : normalized.reexportCount,
            hasReexports: normalized !== null && normalized.hasReexports === true,
            stubAndResolverCount: normalized === null ? 0 : normalized.stubAndResolverCount,
            hasStubAndResolvers: normalized !== null && normalized.hasStubAndResolvers === true,
            weakDefinitionCount: normalized === null ? 0 : normalized.weakDefinitionCount,
            hasWeakDefinitions: normalized !== null && normalized.hasWeakDefinitions === true,
            kinds: normalized === null ? [] : normalized.kinds,
            text: normalized === null ? '<null>' : normalized.text,
        };
    }
    case 'native.chained_fixups': {
        const moduleName = String(spec.moduleName || '');
        const chainedFixups = Native.chainedFixups(moduleName);
        const normalized = chainedFixups === null ? null : normalizeChainedFixups(chainedFixups);
        return {
            kind: 'native.chained_fixups',
            moduleName,
            chainedFixups: normalized,
            hasChainedFixups: normalized !== null,
            resolved: normalized !== null,
            resolvedModuleName: normalized === null ? null : normalized.moduleName,
            resolvedModuleBase: normalized === null ? null : normalized.moduleBase,
            moduleBase: normalized === null ? null : normalized.moduleBase,
            resolvedDataoffHex: normalized === null ? null : normalized.dataoffHex,
            dataoffHex: normalized === null ? null : normalized.dataoffHex,
            resolvedDatasizeHex: normalized === null ? null : normalized.datasizeHex,
            datasizeHex: normalized === null ? null : normalized.datasizeHex,
            linkeditBase: normalized === null ? null : normalized.linkeditBase,
            resolvedDataAddress: normalized === null ? null : normalized.dataAddress,
            dataAddress: normalized === null ? null : normalized.dataAddress,
            resolvedDataEnd: normalized === null ? null : normalized.dataEnd,
            dataEnd: normalized === null ? null : normalized.dataEnd,
            hasData: normalized !== null && normalized.hasData === true,
            fixupsVersion: normalized === null ? null : normalized.fixupsVersion,
            resolvedStartsOffsetHex: normalized === null ? null : normalized.startsOffsetHex,
            startsOffsetHex: normalized === null ? null : normalized.startsOffsetHex,
            resolvedImportsOffsetHex: normalized === null ? null : normalized.importsOffsetHex,
            importsOffsetHex: normalized === null ? null : normalized.importsOffsetHex,
            resolvedSymbolsOffsetHex: normalized === null ? null : normalized.symbolsOffsetHex,
            symbolsOffsetHex: normalized === null ? null : normalized.symbolsOffsetHex,
            resolvedStartsAddress: normalized === null ? null : normalized.startsAddress,
            startsAddress: normalized === null ? null : normalized.startsAddress,
            resolvedImportsAddress: normalized === null ? null : normalized.importsAddress,
            importsAddress: normalized === null ? null : normalized.importsAddress,
            resolvedSymbolsAddress: normalized === null ? null : normalized.symbolsAddress,
            symbolsAddress: normalized === null ? null : normalized.symbolsAddress,
            startsBeforeImports: normalized !== null && normalized.startsBeforeImports === true,
            importsBeforeSymbols: normalized !== null && normalized.importsBeforeSymbols === true,
            offsetsMonotonic: normalized !== null && normalized.offsetsMonotonic === true,
            startsToImportsDeltaHex: normalized === null ? null : normalized.startsToImportsDeltaHex,
            importsToSymbolsDeltaHex: normalized === null ? null : normalized.importsToSymbolsDeltaHex,
            importsCount: normalized === null ? null : normalized.importsCount,
            importsFormat: normalized === null ? null : normalized.importsFormat,
            importsFormatName: normalized === null ? null : normalized.importsFormatName,
            symbolsFormat: normalized === null ? null : normalized.symbolsFormat,
            symbolsFormatName: normalized === null ? null : normalized.symbolsFormatName,
            segmentCount: normalized === null ? 0 : normalized.segmentCount,
            hasSegments: normalized !== null && normalized.hasSegments === true,
            firstSegmentIndex: normalized === null ? null : normalized.firstSegmentIndex,
            lastSegmentIndex: normalized === null ? null : normalized.lastSegmentIndex,
            segmentWithFixupsCount: normalized === null ? 0 : normalized.segmentWithFixupsCount,
            hasSegmentsWithFixups: normalized !== null && normalized.hasSegmentsWithFixups === true,
            totalPageCount: normalized === null ? 0 : normalized.totalPageCount,
            totalFixupPageCount: normalized === null ? 0 : normalized.totalFixupPageCount,
            totalMultiStartPageCount: normalized === null ? 0 : normalized.totalMultiStartPageCount,
            totalChainStartCount: normalized === null ? 0 : normalized.totalChainStartCount,
            largestSegmentIndex: normalized === null ? null : normalized.largestSegmentIndex,
            largestSegmentSizeHex: normalized === null ? null : normalized.largestSegmentSizeHex,
            pointerFormatCount: normalized === null ? 0 : normalized.pointerFormatCount,
            hasMultiplePointerFormats: normalized !== null && normalized.hasMultiplePointerFormats === true,
            firstPointerFormatName: normalized === null ? null : normalized.firstPointerFormatName,
            lastPointerFormatName: normalized === null ? null : normalized.lastPointerFormatName,
            dominantPointerFormatName: normalized === null ? null : normalized.dominantPointerFormatName,
            pointerFormats: normalized === null ? [] : normalized.pointerFormats,
            importCount: normalized === null ? 0 : normalized.importCount,
            hasImports: normalized !== null && normalized.hasImports === true,
            firstImportName: normalized === null ? null : normalized.firstImportName,
            lastImportName: normalized === null ? null : normalized.lastImportName,
            namedImportCount: normalized === null ? 0 : normalized.namedImportCount,
            hasNamedImports: normalized !== null && normalized.hasNamedImports === true,
            weakImportCount: normalized === null ? 0 : normalized.weakImportCount,
            hasWeakImports: normalized !== null && normalized.hasWeakImports === true,
            addendImportCount: normalized === null ? 0 : normalized.addendImportCount,
            hasAddendImports: normalized !== null && normalized.hasAddendImports === true,
            negativeAddendImportCount: normalized === null ? 0 : normalized.negativeAddendImportCount,
            hasNegativeAddends: normalized !== null && normalized.hasNegativeAddends === true,
            uniqueLibOrdinalCount: normalized === null ? 0 : normalized.uniqueLibOrdinalCount,
            firstLibOrdinal: normalized === null ? null : normalized.firstLibOrdinal,
            lastLibOrdinal: normalized === null ? null : normalized.lastLibOrdinal,
            libOrdinals: normalized === null ? [] : normalized.libOrdinals,
            text: normalized === null ? '<null>' : normalized.text,
        };
    }
    case 'native.source_version': {
        const moduleName = String(spec.moduleName || '');
        const sourceVersion = Native.sourceVersion(moduleName);
        const normalized = sourceVersion === null ? null : normalizeSourceVersion(sourceVersion);
        return {
            kind: 'native.source_version',
            moduleName,
            sourceVersion: normalized,
            hasSourceVersion: normalized !== null,
            resolved: normalized !== null,
            resolvedModuleName: normalized === null ? null : normalized.moduleName,
            resolvedModuleBase: normalized === null ? null : normalized.moduleBase,
            resolvedVersion: normalized === null ? null : normalized.version,
            version: normalized === null ? null : normalized.version,
            hasVersion: normalized !== null && normalized.hasVersion === true,
            versionPartCount: normalized === null ? 0 : normalized.versionPartCount,
            majorVersion: normalized === null ? null : normalized.majorVersion,
            minorVersion: normalized === null ? null : normalized.minorVersion,
            patchVersion: normalized === null ? null : normalized.patchVersion,
            extraVersionCount: normalized === null ? 0 : normalized.extraVersionCount,
            text: normalized === null ? '<null>' : normalized.text,
        };
    }
    case 'native.build_version': {
        const moduleName = String(spec.moduleName || '');
        const buildVersion = Native.buildVersion(moduleName);
        const normalized = buildVersion === null ? null : normalizeBuildVersion(buildVersion);
        return {
            kind: 'native.build_version',
            moduleName,
            buildVersion: normalized,
            hasBuildVersion: normalized !== null,
            resolved: normalized !== null,
            resolvedModuleName: normalized === null ? null : normalized.moduleName,
            resolvedModuleBase: normalized === null ? null : normalized.moduleBase,
            resolvedPlatform: normalized === null ? null : normalized.platform,
            resolvedMinOs: normalized === null ? null : normalized.minOs,
            resolvedSdk: normalized === null ? null : normalized.sdk,
            platform: normalized === null ? null : normalized.platform,
            hasMinOs: normalized !== null && normalized.hasMinOs === true,
            hasSdk: normalized !== null && normalized.hasSdk === true,
            minOsPartCount: normalized === null ? 0 : normalized.minOsPartCount,
            sdkPartCount: normalized === null ? 0 : normalized.sdkPartCount,
            hasTools: normalized !== null && normalized.hasTools === true,
            firstTool: normalized === null ? null : normalized.firstTool,
            lastTool: normalized === null ? null : normalized.lastTool,
            firstToolVersion: normalized === null ? null : normalized.firstToolVersion,
            lastToolVersion: normalized === null ? null : normalized.lastToolVersion,
            toolCount: normalized === null ? 0 : normalized.tools.length,
            uniqueToolCount: normalized === null ? 0 : normalized.uniqueToolCount,
            toolNames: normalized === null ? [] : normalized.toolNames,
            tools: normalized === null ? [] : normalized.tools,
            text: normalized === null ? '<null>' : normalized.text,
        };
    }
    case 'native.dylinker': {
        const moduleName = String(spec.moduleName || '');
        const dylinker = Native.dylinker(moduleName);
        const normalized = dylinker === null ? null : normalizeDylinker(dylinker);
        return {
            kind: 'native.dylinker',
            moduleName,
            dylinker: normalized,
            hasDylinker: normalized !== null,
            resolved: normalized !== null,
            resolvedModuleName: normalized === null ? null : normalized.moduleName,
            resolvedModuleBase: normalized === null ? null : normalized.moduleBase,
            resolvedName: normalized === null ? null : normalized.name,
            resolvedPath: normalized === null ? null : normalized.path,
            resolvedPathKind: normalized === null ? null : normalized.pathKind,
            name: normalized === null ? null : normalized.name,
            path: normalized === null ? null : normalized.path,
            pathKind: normalized === null ? null : normalized.pathKind,
            kind: normalized === null ? null : normalized.kind,
            kindName: normalized === null ? null : normalized.kind,
            hasName: normalized !== null && normalized.hasName === true,
            hasPath: normalized !== null && normalized.hasPath === true,
            isTokenPath: normalized !== null && normalized.isTokenPath === true,
            usesLoaderPath: normalized !== null && normalized.usesLoaderPath === true,
            usesExecutablePath: normalized !== null && normalized.usesExecutablePath === true,
            usesRpathToken: normalized !== null && normalized.usesRpathToken === true,
            pathDepth: normalized === null ? 0 : normalized.pathDepth,
            isWeakDylinker: normalized !== null && normalized.isWeakDylinker === true,
            isReexportDylinker: normalized !== null && normalized.isReexportDylinker === true,
            isUpwardDylinker: normalized !== null && normalized.isUpwardDylinker === true,
            isLoadDylinker: normalized !== null && normalized.isLoadDylinker === true,
            text: normalized === null ? '<null>' : normalized.text,
        };
    }
    case 'native.install_name': {
        const moduleName = String(spec.moduleName || '');
        const installName = Native.installName(moduleName);
        const normalized = installName === null ? null : normalizeInstallName(installName);
        return {
            kind: 'native.install_name',
            moduleName,
            installName: normalized,
            hasInstallName: normalized !== null,
            resolved: normalized !== null,
            resolvedModuleName: normalized === null ? null : normalized.moduleName,
            resolvedModuleBase: normalized === null ? null : normalized.moduleBase,
            resolvedName: normalized === null ? null : normalized.name,
            resolvedPath: normalized === null ? null : normalized.path,
            resolvedPathKind: normalized === null ? null : normalized.pathKind,
            resolvedCurrentVersion: normalized === null ? null : normalized.currentVersion,
            resolvedCompatibilityVersion: normalized === null ? null : normalized.compatibilityVersion,
            resolvedTimestamp: normalized === null ? null : normalized.timestamp,
            name: normalized === null ? null : normalized.name,
            path: normalized === null ? null : normalized.path,
            pathKind: normalized === null ? null : normalized.pathKind,
            currentVersion: normalized === null ? null : normalized.currentVersion,
            compatibilityVersion: normalized === null ? null : normalized.compatibilityVersion,
            timestamp: normalized === null ? null : normalized.timestamp,
            hasName: normalized !== null && normalized.hasName === true,
            hasPath: normalized !== null && normalized.hasPath === true,
            isTokenPath: normalized !== null && normalized.isTokenPath === true,
            usesLoaderPath: normalized !== null && normalized.usesLoaderPath === true,
            usesExecutablePath: normalized !== null && normalized.usesExecutablePath === true,
            usesRpathToken: normalized !== null && normalized.usesRpathToken === true,
            pathDepth: normalized === null ? 0 : normalized.pathDepth,
            hasTimestamp: normalized !== null && normalized.hasTimestamp === true,
            versionMismatch: normalized !== null && normalized.versionMismatch === true,
            text: normalized === null ? '<null>' : normalized.text,
        };
    }
    case 'native.uuid': {
        const moduleName = String(spec.moduleName || '');
        const imageUuid = Native.uuid(moduleName);
        const normalized = imageUuid === null ? null : normalizeUuid(imageUuid);
        return {
            kind: 'native.uuid',
            moduleName,
            imageUuid: normalized,
            hasUuid: normalized !== null,
            resolved: normalized !== null,
            resolvedModuleName: normalized === null ? null : normalized.moduleName,
            resolvedModuleBase: normalized === null ? null : normalized.moduleBase,
            resolvedUuid: normalized === null ? null : normalized.uuid,
            uuid: normalized === null ? null : normalized.uuid,
            normalizedUuid: normalized === null ? null : normalized.normalizedUuid,
            uuidLength: normalized === null ? 0 : normalized.uuidLength,
            uuidSegmentCount: normalized === null ? 0 : normalized.uuidSegmentCount,
            text: normalized === null ? '<null>' : normalized.text,
        };
    }
    case 'native.rpaths': {
        const moduleName = String(spec.moduleName || '');
        const query = spec.query === null || spec.query === undefined ? null : String(spec.query);
        const rpaths = Native.rpaths(moduleName, query).map((rpath) => normalizeRpath(rpath));
        const tokenRpaths = rpaths.filter((rpath) => rpath.isTokenPath);
        const loaderPathRpaths = rpaths.filter((rpath) => rpath.usesLoaderPath);
        const executablePathRpaths = rpaths.filter((rpath) => rpath.usesExecutablePath);
        const rpathTokenRpaths = rpaths.filter((rpath) => rpath.usesRpathToken);
        const longestRpath = rpaths.reduce((longest, rpath) => {
            if (longest === null || rpath.path.length > longest.path.length) {
                return rpath;
            }
            return longest;
        }, null);
        const pathKindSummaries = [];
        const rpathPaths = [];
        for (const rpath of rpaths) {
            let summary = pathKindSummaries.find((item) => item.pathKind === rpath.pathKind);
            if (summary === undefined) {
                summary = {
                    pathKind: rpath.pathKind,
                    count: 0,
                    firstPath: rpath.path,
                    lastPath: rpath.path,
                    tokenPathCount: 0,
                };
                pathKindSummaries.push(summary);
            }
            summary.count += 1;
            summary.lastPath = rpath.path;
            if (rpath.isTokenPath) {
                summary.tokenPathCount += 1;
            }
            let rpathPathSummary = rpathPaths.find((item) => item.path === rpath.path);
            if (rpathPathSummary === undefined) {
                rpathPathSummary = {
                    path: rpath.path,
                    count: 0,
                    firstPathKind: rpath.pathKind,
                    lastPathKind: rpath.pathKind,
                    tokenPathCount: 0,
                    loaderPathCount: 0,
                    executablePathCount: 0,
                    rpathTokenCount: 0,
                };
                rpathPaths.push(rpathPathSummary);
            }
            rpathPathSummary.count += 1;
            rpathPathSummary.lastPathKind = rpath.pathKind;
            if (rpath.isTokenPath) {
                rpathPathSummary.tokenPathCount += 1;
            }
            if (rpath.usesLoaderPath) {
                rpathPathSummary.loaderPathCount += 1;
            }
            if (rpath.usesExecutablePath) {
                rpathPathSummary.executablePathCount += 1;
            }
            if (rpath.usesRpathToken) {
                rpathPathSummary.rpathTokenCount += 1;
            }
        }
        return {
            kind: 'native.rpaths',
            moduleName,
            query,
            hasQuery: query !== null && query.length !== 0,
            count: rpaths.length,
            hasRpaths: rpaths.length !== 0,
            firstRpath: rpaths.length === 0 ? null : rpaths[0].path,
            lastRpath: rpaths.length === 0 ? null : rpaths[rpaths.length - 1].path,
            firstPathKind: rpaths.length === 0 ? null : rpaths[0].pathKind,
            lastPathKind: rpaths.length === 0 ? null : rpaths[rpaths.length - 1].pathKind,
            uniqueRpathCount: rpathPaths.length,
            uniquePathKindCount: pathKindSummaries.length,
            tokenPathCount: tokenRpaths.length,
            hasTokenPaths: tokenRpaths.length !== 0,
            loaderPathCount: loaderPathRpaths.length,
            hasLoaderPaths: loaderPathRpaths.length !== 0,
            executablePathCount: executablePathRpaths.length,
            hasExecutablePaths: executablePathRpaths.length !== 0,
            rpathTokenCount: rpathTokenRpaths.length,
            hasRpathTokens: rpathTokenRpaths.length !== 0,
            longestRpath: longestRpath === null ? null : longestRpath.path,
            longestRpathLength: longestRpath === null ? null : longestRpath.path.length,
            rpathPaths,
            pathKinds: pathKindSummaries,
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
            hasRpathInfo: normalized !== null,
            resolved: normalized !== null,
            resolvedPath: normalized === null ? null : normalized.path,
            resolvedModuleName: normalized === null ? null : normalized.moduleName,
            resolvedModuleBase: normalized === null ? null : normalized.moduleBase,
            pathKind: normalized === null ? null : normalized.pathKind,
            moduleBase: normalized === null ? null : normalized.moduleBase,
            hasPath: normalized !== null && normalized.path.length !== 0,
            text: normalized === null ? '<null>' : normalized.text,
        };
    }
    case 'native.imports': {
        const moduleName = String(spec.moduleName || '');
        const query = spec.query === null || spec.query === undefined ? null : String(spec.query);
        const imports = Native.imports(moduleName, query).map((imp) => normalizeImport(imp));
        const weakImports = imports.filter((imp) => imp.weakImport);
        const ordinalOnlyImports = imports.filter((imp) => imp.usesOrdinalOnly);
        const mainExecutableImports = imports.filter((imp) => imp.isMainExecutableImport);
        const flatLookupImports = imports.filter((imp) => imp.isFlatLookupImport);
        const selfImports = imports.filter((imp) => imp.isSelfImport);
        const tokenSourceImports = imports.filter((imp) => imp.isTokenSource);
        const loaderPathImports = imports.filter((imp) => imp.usesLoaderPath);
        const executablePathImports = imports.filter((imp) => imp.usesExecutablePath);
        const rpathTokenImports = imports.filter((imp) => imp.usesRpathToken);
        const longestImport = imports.reduce((longest, imp) => {
            if (longest === null || imp.nameLength > longest.nameLength) {
                return imp;
            }
            return longest;
        }, null);
        const sourceSummaries = [];
        const sourceKindSummaries = [];
        const sourcePathKindSummaries = [];
        const importNames = [];
        const normalizedNames = [];
        for (const imp of imports) {
            let summary = sourceSummaries.find((item) => item.source === imp.source && item.sourceKind === imp.sourceKind);
            if (summary === undefined) {
                summary = {
                    source: imp.source,
                    sourceKind: imp.sourceKind,
                    dylibOrdinal: imp.dylibOrdinal,
                    hasDylibName: imp.hasDylibName,
                    usesOrdinalOnly: imp.usesOrdinalOnly,
                    count: 0,
                    weakImportCount: 0,
                    firstImportName: imp.name,
                    lastImportName: imp.name,
                };
                sourceSummaries.push(summary);
            }
            summary.count += 1;
            summary.lastImportName = imp.name;
            if (imp.weakImport) {
                summary.weakImportCount += 1;
            }
            let importNameSummary = importNames.find((item) => item.importName === imp.name);
            if (importNameSummary === undefined) {
                importNameSummary = {
                    importName: imp.name,
                    count: 0,
                    firstSource: imp.source,
                    lastSource: imp.source,
                    firstNormalizedName: imp.normalizedName,
                    lastNormalizedName: imp.normalizedName,
                    weakImportCount: 0,
                };
                importNames.push(importNameSummary);
            }
            importNameSummary.count += 1;
            importNameSummary.lastSource = imp.source;
            importNameSummary.lastNormalizedName = imp.normalizedName;
            if (imp.weakImport) {
                importNameSummary.weakImportCount += 1;
            }
            let sourceKindSummary = sourceKindSummaries.find((item) => item.sourceKind === imp.sourceKind);
            if (sourceKindSummary === undefined) {
                sourceKindSummary = {
                    sourceKind: imp.sourceKind,
                    count: 0,
                    firstImportName: imp.name,
                    lastImportName: imp.name,
                    weakImportCount: 0,
                    tokenSourceCount: 0,
                };
                sourceKindSummaries.push(sourceKindSummary);
            }
            sourceKindSummary.count += 1;
            sourceKindSummary.lastImportName = imp.name;
            if (imp.weakImport) {
                sourceKindSummary.weakImportCount += 1;
            }
            if (imp.isTokenSource) {
                sourceKindSummary.tokenSourceCount += 1;
            }
            let sourcePathKindSummary = sourcePathKindSummaries.find((item) => item.sourcePathKind === imp.sourcePathKind);
            if (sourcePathKindSummary === undefined) {
                sourcePathKindSummary = {
                    sourcePathKind: imp.sourcePathKind,
                    count: 0,
                    firstImportName: imp.name,
                    lastImportName: imp.name,
                    firstSource: imp.source,
                    lastSource: imp.source,
                };
                sourcePathKindSummaries.push(sourcePathKindSummary);
            }
            sourcePathKindSummary.count += 1;
            sourcePathKindSummary.lastImportName = imp.name;
            sourcePathKindSummary.lastSource = imp.source;
            let normalizedSummary = normalizedNames.find((item) => item.normalizedName === imp.normalizedName);
            if (normalizedSummary === undefined) {
                normalizedSummary = {
                    normalizedName: imp.normalizedName,
                    count: 0,
                    firstSource: imp.source,
                    lastSource: imp.source,
                    weakImportCount: 0,
                };
                normalizedNames.push(normalizedSummary);
            }
            normalizedSummary.count += 1;
            normalizedSummary.lastSource = imp.source;
            if (imp.weakImport) {
                normalizedSummary.weakImportCount += 1;
            }
        }
        const dylibSources = sourceSummaries.map((summary) => ({
            source: summary.source,
            sourceKind: summary.sourceKind,
            dylibOrdinal: summary.dylibOrdinal,
            hasDylibName: summary.hasDylibName,
            usesOrdinalOnly: summary.usesOrdinalOnly,
            count: summary.count,
            weakImportCount: summary.weakImportCount,
            firstImportName: summary.firstImportName,
            lastImportName: summary.lastImportName,
        }));
        return {
            kind: 'native.imports',
            moduleName,
            query,
            hasQuery: query !== null && query.length !== 0,
            count: imports.length,
            hasImports: imports.length !== 0,
            firstImportName: imports.length === 0 ? null : imports[0].name,
            lastImportName: imports.length === 0 ? null : imports[imports.length - 1].name,
            firstSource: imports.length === 0 ? null : imports[0].source,
            lastSource: imports.length === 0 ? null : imports[imports.length - 1].source,
            longestImportName: longestImport === null ? null : longestImport.name,
            longestImportNameLength: longestImport === null ? null : longestImport.nameLength,
            weakImportCount: weakImports.length,
            hasWeakImports: weakImports.length !== 0,
            ordinalOnlyCount: ordinalOnlyImports.length,
            hasOrdinalOnlyImports: ordinalOnlyImports.length !== 0,
            mainExecutableImportCount: mainExecutableImports.length,
            hasMainExecutableImports: mainExecutableImports.length !== 0,
            flatLookupImportCount: flatLookupImports.length,
            hasFlatLookupImports: flatLookupImports.length !== 0,
            selfImportCount: selfImports.length,
            hasSelfImports: selfImports.length !== 0,
            tokenSourceCount: tokenSourceImports.length,
            hasTokenSources: tokenSourceImports.length !== 0,
            loaderPathImportCount: loaderPathImports.length,
            hasLoaderPathImports: loaderPathImports.length !== 0,
            executablePathImportCount: executablePathImports.length,
            hasExecutablePathImports: executablePathImports.length !== 0,
            rpathTokenImportCount: rpathTokenImports.length,
            hasRpathTokenImports: rpathTokenImports.length !== 0,
            uniqueDylibOrdinalCount: Array.from(new Set(imports.map((imp) => imp.dylibOrdinal))).length,
            uniqueSourceCount: dylibSources.length,
            uniqueSourceKindCount: sourceKindSummaries.length,
            uniqueSourcePathKindCount: sourcePathKindSummaries.length,
            uniqueImportNameCount: importNames.length,
            uniqueNormalizedNameCount: normalizedNames.length,
            dylibSources,
            sourceKinds: sourceKindSummaries,
            sourcePathKinds: sourcePathKindSummaries,
            importNames,
            normalizedNames,
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
            hasImportInfo: normalized !== null,
            resolved: normalized !== null,
            resolvedName: normalized === null ? null : normalized.name,
            resolvedNormalizedName: normalized === null ? null : normalized.normalizedName,
            resolvedModuleName: normalized === null ? null : normalized.moduleName,
            resolvedModuleBase: normalized === null ? null : normalized.moduleBase,
            resolvedDylibOrdinal: normalized === null ? null : normalized.dylibOrdinal,
            resolvedDylibName: normalized === null ? null : normalized.dylibName,
            name: normalized === null ? null : normalized.name,
            normalizedName: normalized === null ? null : normalized.normalizedName,
            moduleBase: normalized === null ? null : normalized.moduleBase,
            dylibOrdinal: normalized === null ? null : normalized.dylibOrdinal,
            dylibName: normalized === null ? null : normalized.dylibName,
            source: normalized === null ? null : normalized.source,
            sourceKind: normalized === null ? null : normalized.sourceKind,
            hasDylibName: normalized !== null && normalized.hasDylibName === true,
            usesOrdinalOnly: normalized !== null && normalized.usesOrdinalOnly === true,
            isMainExecutableImport: normalized !== null && normalized.isMainExecutableImport === true,
            isFlatLookupImport: normalized !== null && normalized.isFlatLookupImport === true,
            isSelfImport: normalized !== null && normalized.isSelfImport === true,
            weakImport: normalized !== null && normalized.weakImport === true,
            text: normalized === null ? '<null>' : normalized.text,
        };
    }
    case 'native.segments': {
        const moduleName = String(spec.moduleName || '');
        const segments = Native.segments(moduleName).map((segment) => normalizeSegment(segment));
        const fileBackedSegments = segments.filter((segment) => segment.hasFileData);
        const zeroFillSegments = segments.filter((segment) => segment.isZeroFillLike);
        const readableSegments = segments.filter((segment) => segment.isReadable);
        const writableSegments = segments.filter((segment) => segment.isWritable);
        const executableSegments = segments.filter((segment) => segment.isExecutable);
        const totalVmSize = segments.reduce((sum, segment) => sum + BigInt(segment.vmsizeHex), 0n);
        const totalFileSize = segments.reduce((sum, segment) => sum + BigInt(segment.filesizeHex), 0n);
        const largestVmSegment = segments.reduce((largest, segment) => {
            if (largest === null || BigInt(segment.vmsizeHex) > BigInt(largest.vmsizeHex)) {
                return segment;
            }
            return largest;
        }, null);
        const largestFileSegment = segments.reduce((largest, segment) => {
            if (largest === null || BigInt(segment.filesizeHex) > BigInt(largest.filesizeHex)) {
                return segment;
            }
            return largest;
        }, null);
        const protectionSummaries = [];
        const segmentNames = [];
        for (const segment of segments) {
            let summary = protectionSummaries.find((item) => item.initprotFlags === segment.initprotFlags && item.maxprotFlags === segment.maxprotFlags);
            if (summary === undefined) {
                summary = {
                    initprotFlags: segment.initprotFlags,
                    maxprotFlags: segment.maxprotFlags,
                    count: 0,
                    firstSegmentName: segment.name,
                    lastSegmentName: segment.name,
                    readableCount: 0,
                    writableCount: 0,
                    executableCount: 0,
                };
                protectionSummaries.push(summary);
            }
            summary.count += 1;
            summary.lastSegmentName = segment.name;
            if (segment.isReadable) {
                summary.readableCount += 1;
            }
            if (segment.isWritable) {
                summary.writableCount += 1;
            }
            if (segment.isExecutable) {
                summary.executableCount += 1;
            }
            let segmentNameSummary = segmentNames.find((item) => item.segmentName === segment.name);
            if (segmentNameSummary === undefined) {
                segmentNameSummary = {
                    segmentName: segment.name,
                    count: 0,
                    firstVmaddr: segment.vmaddr,
                    lastVmaddr: segment.vmaddr,
                    firstFileoffHex: segment.fileoffHex,
                    lastFileoffHex: segment.fileoffHex,
                    readableCount: 0,
                    writableCount: 0,
                    executableCount: 0,
                };
                segmentNames.push(segmentNameSummary);
            }
            segmentNameSummary.count += 1;
            segmentNameSummary.lastVmaddr = segment.vmaddr;
            segmentNameSummary.lastFileoffHex = segment.fileoffHex;
            if (segment.isReadable) {
                segmentNameSummary.readableCount += 1;
            }
            if (segment.isWritable) {
                segmentNameSummary.writableCount += 1;
            }
            if (segment.isExecutable) {
                segmentNameSummary.executableCount += 1;
            }
        }
        return {
            kind: 'native.segments',
            moduleName,
            count: segments.length,
            hasSegments: segments.length !== 0,
            firstSegmentName: segments.length === 0 ? null : segments[0].name,
            lastSegmentName: segments.length === 0 ? null : segments[segments.length - 1].name,
            firstSegmentVmaddr: segments.length === 0 ? null : segments[0].vmaddr,
            lastSegmentVmaddr: segments.length === 0 ? null : segments[segments.length - 1].vmaddr,
            totalVmSizeHex: '0x' + totalVmSize.toString(16),
            totalFileSizeHex: '0x' + totalFileSize.toString(16),
            largestVmSegmentName: largestVmSegment === null ? null : largestVmSegment.name,
            largestVmSegmentSizeHex: largestVmSegment === null ? null : largestVmSegment.vmsizeHex,
            largestFileSegmentName: largestFileSegment === null ? null : largestFileSegment.name,
            largestFileSegmentSizeHex: largestFileSegment === null ? null : largestFileSegment.filesizeHex,
            fileBackedSegmentCount: fileBackedSegments.length,
            hasFileBackedSegments: fileBackedSegments.length !== 0,
            zeroFillSegmentCount: zeroFillSegments.length,
            hasZeroFillSegments: zeroFillSegments.length !== 0,
            readableSegmentCount: readableSegments.length,
            hasReadableSegments: readableSegments.length !== 0,
            writableSegmentCount: writableSegments.length,
            hasWritableSegments: writableSegments.length !== 0,
            executableSegmentCount: executableSegments.length,
            hasExecutableSegments: executableSegments.length !== 0,
            uniqueSegmentNameCount: segmentNames.length,
            uniqueProtectionCount: protectionSummaries.length,
            segmentNames,
            protections: protectionSummaries.map((summary) => ({
                initprotFlags: summary.initprotFlags,
                maxprotFlags: summary.maxprotFlags,
                count: summary.count,
                firstSegmentName: summary.firstSegmentName,
                lastSegmentName: summary.lastSegmentName,
                readableCount: summary.readableCount,
                writableCount: summary.writableCount,
                executableCount: summary.executableCount,
            })),
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
            hasSegmentInfo: normalized !== null,
            resolved: normalized !== null,
            resolvedName: normalized === null ? null : normalized.name,
            resolvedModuleName: normalized === null ? null : normalized.moduleName,
            resolvedModuleBase: normalized === null ? null : normalized.moduleBase,
            resolvedVmaddr: normalized === null ? null : normalized.vmaddr,
            resolvedVmEnd: normalized === null ? null : normalized.vmEnd,
            resolvedFileoffHex: normalized === null ? null : normalized.fileoffHex,
            resolvedFilesizeHex: normalized === null ? null : normalized.filesizeHex,
            resolvedInitprotFlags: normalized === null ? null : normalized.initprotFlags,
            resolvedMaxprotFlags: normalized === null ? null : normalized.maxprotFlags,
            name: normalized === null ? null : normalized.name,
            moduleBase: normalized === null ? null : normalized.moduleBase,
            vmaddr: normalized === null ? null : normalized.vmaddr,
            vmEnd: normalized === null ? null : normalized.vmEnd,
            fileoffHex: normalized === null ? null : normalized.fileoffHex,
            filesizeHex: normalized === null ? null : normalized.filesizeHex,
            initprotFlags: normalized === null ? null : normalized.initprotFlags,
            maxprotFlags: normalized === null ? null : normalized.maxprotFlags,
            hasVmRange: normalized !== null && normalized.hasVmRange === true,
            hasFileData: normalized !== null && normalized.hasFileData === true,
            isEmpty: normalized !== null && normalized.isEmpty === true,
            isReadable: normalized !== null && normalized.isReadable === true,
            isWritable: normalized !== null && normalized.isWritable === true,
            isExecutable: normalized !== null && normalized.isExecutable === true,
            text: normalized === null ? '<null>' : normalized.text,
        };
    }
    case 'native.sections': {
        const moduleName = String(spec.moduleName || '');
        const sections = Native.sections(moduleName).map((section) => normalizeSection(section));
        const zeroFillSections = sections.filter((section) => section.isZeroFillLike);
        const cstringSections = sections.filter((section) => section.isCStringLike);
        const symbolPointerSections = sections.filter((section) => section.isSymbolPointers);
        const nonEmptySections = sections.filter((section) => section.hasData);
        const totalSize = sections.reduce((sum, section) => sum + BigInt(section.sizeHex), 0n);
        const largestSection = sections.reduce((largest, section) => {
            if (largest === null || BigInt(section.sizeHex) > BigInt(largest.sizeHex)) {
                return section;
            }
            return largest;
        }, null);
        const segmentSummaries = [];
        const sectionNames = [];
        for (const section of sections) {
            let summary = segmentSummaries.find((item) => item.segmentName === section.segmentName);
            if (summary === undefined) {
                summary = {
                    segmentName: section.segmentName,
                    count: 0,
                    totalSize: 0n,
                    firstSectionName: section.name,
                    lastSectionName: section.name,
                    zeroFillCount: 0,
                    cstringCount: 0,
                    symbolPointerCount: 0,
                };
                segmentSummaries.push(summary);
            }
            summary.count += 1;
            summary.totalSize += BigInt(section.sizeHex);
            summary.lastSectionName = section.name;
            if (section.isZeroFillLike) {
                summary.zeroFillCount += 1;
            }
            if (section.isCStringLike) {
                summary.cstringCount += 1;
            }
            if (section.isSymbolPointers) {
                summary.symbolPointerCount += 1;
            }
            let sectionNameSummary = sectionNames.find((item) => item.sectionName === section.name);
            if (sectionNameSummary === undefined) {
                sectionNameSummary = {
                    sectionName: section.name,
                    count: 0,
                    firstSegmentName: section.segmentName,
                    lastSegmentName: section.segmentName,
                    firstFullName: section.fullName,
                    lastFullName: section.fullName,
                    zeroFillCount: 0,
                    cstringCount: 0,
                    symbolPointerCount: 0,
                };
                sectionNames.push(sectionNameSummary);
            }
            sectionNameSummary.count += 1;
            sectionNameSummary.lastSegmentName = section.segmentName;
            sectionNameSummary.lastFullName = section.fullName;
            if (section.isZeroFillLike) {
                sectionNameSummary.zeroFillCount += 1;
            }
            if (section.isCStringLike) {
                sectionNameSummary.cstringCount += 1;
            }
            if (section.isSymbolPointers) {
                sectionNameSummary.symbolPointerCount += 1;
            }
        }
        const sectionTypeSummaries = [];
        for (const section of sections) {
            let summary = sectionTypeSummaries.find((item) => item.sectionType === section.sectionType);
            if (summary === undefined) {
                summary = {
                    sectionType: section.sectionType,
                    sectionTypeName: section.sectionTypeName,
                    count: 0,
                    totalSize: 0n,
                    firstFullName: section.fullName,
                    lastFullName: section.fullName,
                    firstSegmentName: section.segmentName,
                    lastSegmentName: section.segmentName,
                };
                sectionTypeSummaries.push(summary);
            }
            summary.count += 1;
            summary.totalSize += BigInt(section.sizeHex);
            summary.lastFullName = section.fullName;
            summary.lastSegmentName = section.segmentName;
        }
        return {
            kind: 'native.sections',
            moduleName,
            count: sections.length,
            hasSections: sections.length !== 0,
            firstSectionName: sections.length === 0 ? null : sections[0].name,
            lastSectionName: sections.length === 0 ? null : sections[sections.length - 1].name,
            firstSectionFullName: sections.length === 0 ? null : sections[0].fullName,
            lastSectionFullName: sections.length === 0 ? null : sections[sections.length - 1].fullName,
            totalSizeHex: '0x' + totalSize.toString(16),
            nonEmptySectionCount: nonEmptySections.length,
            hasNonEmptySections: nonEmptySections.length !== 0,
            zeroFillSectionCount: zeroFillSections.length,
            hasZeroFillSections: zeroFillSections.length !== 0,
            cstringSectionCount: cstringSections.length,
            hasCStringSections: cstringSections.length !== 0,
            symbolPointerSectionCount: symbolPointerSections.length,
            hasSymbolPointerSections: symbolPointerSections.length !== 0,
            uniqueSegmentCount: segmentSummaries.length,
            uniqueSectionNameCount: sectionNames.length,
            uniqueSectionTypeCount: sectionTypeSummaries.length,
            largestSectionName: largestSection === null ? null : largestSection.name,
            largestSectionFullName: largestSection === null ? null : largestSection.fullName,
            largestSectionSizeHex: largestSection === null ? null : largestSection.sizeHex,
            sectionNames,
            segments: segmentSummaries.map((summary) => ({
                segmentName: summary.segmentName,
                count: summary.count,
                totalSizeHex: '0x' + summary.totalSize.toString(16),
                firstSectionName: summary.firstSectionName,
                lastSectionName: summary.lastSectionName,
                zeroFillCount: summary.zeroFillCount,
                cstringCount: summary.cstringCount,
                symbolPointerCount: summary.symbolPointerCount,
            })),
            sectionTypes: sectionTypeSummaries.map((summary) => ({
                sectionType: summary.sectionType,
                sectionTypeName: summary.sectionTypeName,
                count: summary.count,
                totalSizeHex: '0x' + summary.totalSize.toString(16),
                firstFullName: summary.firstFullName,
                lastFullName: summary.lastFullName,
                firstSegmentName: summary.firstSegmentName,
                lastSegmentName: summary.lastSegmentName,
            })),
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
            hasSectionInfo: normalized !== null,
            resolved: normalized !== null,
            resolvedSegmentName: normalized === null ? null : normalized.segmentName,
            resolvedSectionName: normalized === null ? null : normalized.name,
            resolvedFullName: normalized === null ? null : normalized.fullName,
            resolvedModuleName: normalized === null ? null : normalized.moduleName,
            resolvedModuleBase: normalized === null ? null : normalized.moduleBase,
            resolvedAddr: normalized === null ? null : normalized.addr,
            resolvedEndAddr: normalized === null ? null : normalized.endAddr,
            resolvedOffsetHex: normalized === null ? null : normalized.offsetHex,
            resolvedAlignmentBytesHex: normalized === null ? null : normalized.alignmentBytesHex,
            resolvedSectionType: normalized === null ? null : normalized.sectionType,
            sectionTypeName: normalized === null ? null : normalized.sectionTypeName,
            resolvedSectionTypeName: normalized === null ? null : normalized.sectionTypeName,
            name: normalized === null ? null : normalized.name,
            fullName: normalized === null ? null : normalized.fullName,
            moduleBase: normalized === null ? null : normalized.moduleBase,
            addr: normalized === null ? null : normalized.addr,
            endAddr: normalized === null ? null : normalized.endAddr,
            offsetHex: normalized === null ? null : normalized.offsetHex,
            alignmentBytesHex: normalized === null ? null : normalized.alignmentBytesHex,
            sectionType: normalized === null ? null : normalized.sectionType,
            hasData: normalized !== null && normalized.hasData === true,
            isZeroFillLike: normalized !== null && normalized.isZeroFillLike === true,
            isCStringLike: normalized !== null && normalized.isCStringLike === true,
            isSymbolPointers: normalized !== null && normalized.isSymbolPointers === true,
            text: normalized === null ? '<null>' : normalized.text,
        };
    }
    case 'native.load_commands': {
        const moduleName = String(spec.moduleName || '');
        const commands = Native.loadCommands(moduleName).map((command) => normalizeLoadCommand(command));
        const reqDyldCommands = commands.filter((command) => command.isReqDyld);
        const detailedCommands = commands.filter((command) => command.hasDetail);
        const pathCommands = commands.filter((command) => command.hasPath);
        const tokenPathCommands = commands.filter((command) => command.isTokenPath);
        const versionedCommands = commands.filter((command) => command.hasCurrentVersion || command.hasVersion || command.hasMinOs);
        const timestampedCommands = commands.filter((command) => command.hasTimestamp);
        const dataRangeCommands = commands.filter((command) => command.hasDataRange);
        const dyldRegionCommands = commands.filter((command) => command.hasDyldRegions);
        const largestCommand = commands.reduce((largest, command) => {
            if (largest === null || command.cmdsize > largest.cmdsize) {
                return command;
            }
            return largest;
        }, null);
        const smallestCommand = commands.reduce((smallest, command) => {
            if (smallest === null || command.cmdsize < smallest.cmdsize) {
                return command;
            }
            return smallest;
        }, null);
        const totalCommandSize = commands.reduce((sum, command) => sum + BigInt(command.cmdsize || 0), 0n);
        const commandKinds = [];
        const commandNames = [];
        const commandFamilies = [];
        for (const command of commands) {
            let summary = commandKinds.find((item) => item.name === command.name);
            if (summary === undefined) {
                summary = {
                    name: command.name,
                    count: 0,
                    firstIndex: command.index,
                    lastIndex: command.index,
                    firstOffsetHex: command.offsetHex,
                    lastOffsetHex: command.offsetHex,
                    hasDetail: false,
                    reqDyldCount: 0,
                };
                commandKinds.push(summary);
            }
            summary.count += 1;
            summary.lastIndex = command.index;
            summary.lastOffsetHex = command.offsetHex;
            summary.hasDetail = summary.hasDetail || command.hasDetail;
            if (command.isReqDyld) {
                summary.reqDyldCount += 1;
            }
            let commandNameSummary = commandNames.find((item) => item.commandName === command.name);
            if (commandNameSummary === undefined) {
                commandNameSummary = {
                    commandName: command.name,
                    count: 0,
                    firstIndex: command.index,
                    lastIndex: command.index,
                    firstOffsetHex: command.offsetHex,
                    lastOffsetHex: command.offsetHex,
                    hasDetail: false,
                    reqDyldCount: 0,
                };
                commandNames.push(commandNameSummary);
            }
            commandNameSummary.count += 1;
            commandNameSummary.lastIndex = command.index;
            commandNameSummary.lastOffsetHex = command.offsetHex;
            commandNameSummary.hasDetail = commandNameSummary.hasDetail || command.hasDetail;
            if (command.isReqDyld) {
                commandNameSummary.reqDyldCount += 1;
            }
            let familySummary = commandFamilies.find((item) => item.commandFamily === command.commandFamily);
            if (familySummary === undefined) {
                familySummary = {
                    commandFamily: command.commandFamily,
                    count: 0,
                    firstCommandName: command.name,
                    lastCommandName: command.name,
                    firstIndex: command.index,
                    lastIndex: command.index,
                    firstOffsetHex: command.offsetHex,
                    lastOffsetHex: command.offsetHex,
                    reqDyldCount: 0,
                    pathCount: 0,
                    versionedCount: 0,
                    dataRangeCount: 0,
                };
                commandFamilies.push(familySummary);
            }
            familySummary.count += 1;
            familySummary.lastCommandName = command.name;
            familySummary.lastIndex = command.index;
            familySummary.lastOffsetHex = command.offsetHex;
            if (command.isReqDyld) {
                familySummary.reqDyldCount += 1;
            }
            if (command.hasPath) {
                familySummary.pathCount += 1;
            }
            if (command.hasCurrentVersion || command.hasVersion || command.hasMinOs) {
                familySummary.versionedCount += 1;
            }
            if (command.hasDataRange) {
                familySummary.dataRangeCount += 1;
            }
        }
        const segmentCommandCount = commands.filter((command) => command.commandFamily === 'segment').length;
        const dylibCommandCount = commands.filter((command) => command.commandFamily === 'dylib').length;
        const dylinkerCommandCount = commands.filter((command) => command.commandFamily === 'dylinker').length;
        const rpathCommandCount = commands.filter((command) => command.commandFamily === 'rpath').length;
        const dyldInfoCommandCount = commands.filter((command) => command.commandFamily === 'dyld-info').length;
        const versionCommandCount = commands.filter((command) => command.commandFamily === 'version').length;
        const entryPointCommandCount = commands.filter((command) => command.commandFamily === 'entry-point').length;
        const encryptionCommandCount = commands.filter((command) => command.commandFamily === 'encryption').length;
        const uuidCommandCount = commands.filter((command) => command.commandFamily === 'uuid').length;
        const linkeditDataCommandCount = commands.filter((command) => command.commandFamily === 'linkedit-data').length;
        return {
            kind: 'native.load_commands',
            moduleName,
            count: commands.length,
            hasCommands: commands.length !== 0,
            firstCommandName: commands.length === 0 ? null : commands[0].name,
            lastCommandName: commands.length === 0 ? null : commands[commands.length - 1].name,
            firstCommandIndex: commands.length === 0 ? null : commands[0].index,
            lastCommandIndex: commands.length === 0 ? null : commands[commands.length - 1].index,
            firstCommandOffsetHex: commands.length === 0 ? null : commands[0].offsetHex,
            lastCommandOffsetHex: commands.length === 0 ? null : commands[commands.length - 1].offsetHex,
            totalCommandSizeHex: '0x' + totalCommandSize.toString(16),
            averageCommandSize: commands.length === 0 ? 0 : Number(totalCommandSize / BigInt(commands.length)),
            largestCommandName: largestCommand === null ? null : largestCommand.name,
            largestCommandSize: largestCommand === null ? null : largestCommand.cmdsize,
            largestCommandIndex: largestCommand === null ? null : largestCommand.index,
            smallestCommandName: smallestCommand === null ? null : smallestCommand.name,
            smallestCommandSize: smallestCommand === null ? null : smallestCommand.cmdsize,
            smallestCommandIndex: smallestCommand === null ? null : smallestCommand.index,
            reqDyldCommandCount: reqDyldCommands.length,
            hasReqDyldCommands: reqDyldCommands.length !== 0,
            detailedCommandCount: detailedCommands.length,
            hasDetailedCommands: detailedCommands.length !== 0,
            pathCommandCount: pathCommands.length,
            hasPathCommands: pathCommands.length !== 0,
            tokenPathCommandCount: tokenPathCommands.length,
            hasTokenPathCommands: tokenPathCommands.length !== 0,
            versionedCommandCount: versionedCommands.length,
            hasVersionedCommands: versionedCommands.length !== 0,
            timestampedCommandCount: timestampedCommands.length,
            hasTimestampedCommands: timestampedCommands.length !== 0,
            dataRangeCommandCount: dataRangeCommands.length,
            hasDataRangeCommands: dataRangeCommands.length !== 0,
            dyldRegionCommandCount: dyldRegionCommands.length,
            hasDyldRegionCommands: dyldRegionCommands.length !== 0,
            uniqueCommandFamilyCount: commandFamilies.length,
            segmentCommandCount,
            dylibCommandCount,
            dylinkerCommandCount,
            rpathCommandCount,
            dyldInfoCommandCount,
            versionCommandCount,
            entryPointCommandCount,
            encryptionCommandCount,
            uuidCommandCount,
            linkeditDataCommandCount,
            uniqueCommandNameCount: commandKinds.length,
            hasDuplicateCommandNames: commandKinds.some((item) => item.count > 1),
            commandFamilies,
            commandNames,
            commandKinds: commandKinds.map((summary) => ({
                name: summary.name,
                count: summary.count,
                firstIndex: summary.firstIndex,
                lastIndex: summary.lastIndex,
                firstOffsetHex: summary.firstOffsetHex,
                lastOffsetHex: summary.lastOffsetHex,
                hasDetail: summary.hasDetail,
                reqDyldCount: summary.reqDyldCount,
            })),
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
            hasLoadCommandInfo: normalized !== null,
            resolved: normalized !== null,
            resolvedName: normalized === null ? null : normalized.name,
            resolvedIndex: normalized === null ? null : normalized.index,
            resolvedModuleName: normalized === null ? null : normalized.moduleName,
            resolvedModuleBase: normalized === null ? null : normalized.moduleBase,
            resolvedCmdHex: normalized === null ? null : normalized.cmdHex,
            resolvedCmdBaseHex: normalized === null ? null : normalized.cmdBaseHex,
            resolvedOffsetHex: normalized === null ? null : normalized.offsetHex,
            resolvedEndOffsetHex: normalized === null ? null : normalized.endOffsetHex,
            resolvedDetail: normalized === null ? null : normalized.detail,
            resolvedCommandFamily: normalized === null ? null : normalized.commandFamily,
            resolvedPath: normalized === null ? null : normalized.path,
            resolvedPathKind: normalized === null ? null : normalized.pathKind,
            resolvedCurrentVersion: normalized === null ? null : normalized.currentVersion,
            resolvedCompatibilityVersion: normalized === null ? null : normalized.compatibilityVersion,
            resolvedTimestamp: normalized === null ? null : normalized.timestamp,
            resolvedVersion: normalized === null ? null : normalized.version,
            resolvedMinOs: normalized === null ? null : normalized.minOs,
            resolvedSdk: normalized === null ? null : normalized.sdk,
            resolvedPlatform: normalized === null ? null : normalized.platform,
            resolvedUuid: normalized === null ? null : normalized.uuid,
            resolvedDataoffHex: normalized === null ? null : normalized.dataoffHex,
            resolvedDatasizeHex: normalized === null ? null : normalized.datasizeHex,
            resolvedDataEndHex: normalized === null ? null : normalized.dataEndHex,
            resolvedEntryoffHex: normalized === null ? null : normalized.entryoffHex,
            resolvedStacksizeHex: normalized === null ? null : normalized.stacksizeHex,
            resolvedCryptoffHex: normalized === null ? null : normalized.cryptoffHex,
            resolvedCryptsizeHex: normalized === null ? null : normalized.cryptsizeHex,
            resolvedCryptid: normalized === null ? null : normalized.cryptid,
            name: normalized === null ? null : normalized.name,
            index: normalized === null ? null : normalized.index,
            moduleBase: normalized === null ? null : normalized.moduleBase,
            cmdHex: normalized === null ? null : normalized.cmdHex,
            cmdBaseHex: normalized === null ? null : normalized.cmdBaseHex,
            offsetHex: normalized === null ? null : normalized.offsetHex,
            endOffsetHex: normalized === null ? null : normalized.endOffsetHex,
            detail: normalized === null ? null : normalized.detail,
            commandFamily: normalized === null ? null : normalized.commandFamily,
            path: normalized === null ? null : normalized.path,
            pathKind: normalized === null ? null : normalized.pathKind,
            currentVersion: normalized === null ? null : normalized.currentVersion,
            compatibilityVersion: normalized === null ? null : normalized.compatibilityVersion,
            timestamp: normalized === null ? null : normalized.timestamp,
            version: normalized === null ? null : normalized.version,
            minOs: normalized === null ? null : normalized.minOs,
            sdk: normalized === null ? null : normalized.sdk,
            platform: normalized === null ? null : normalized.platform,
            tools: normalized === null ? [] : normalized.tools,
            uuid: normalized === null ? null : normalized.uuid,
            dataoffHex: normalized === null ? null : normalized.dataoffHex,
            datasizeHex: normalized === null ? null : normalized.datasizeHex,
            dataEndHex: normalized === null ? null : normalized.dataEndHex,
            entryoffHex: normalized === null ? null : normalized.entryoffHex,
            stacksizeHex: normalized === null ? null : normalized.stacksizeHex,
            cryptoffHex: normalized === null ? null : normalized.cryptoffHex,
            cryptsizeHex: normalized === null ? null : normalized.cryptsizeHex,
            cryptid: normalized === null ? null : normalized.cryptid,
            isReqDyld: normalized !== null && normalized.isReqDyld === true,
            hasPayload: normalized !== null && normalized.hasPayload === true,
            hasDetail: normalized !== null && normalized.hasDetail === true,
            hasPath: normalized !== null && normalized.hasPath === true,
            isTokenPath: normalized !== null && normalized.isTokenPath === true,
            usesLoaderPath: normalized !== null && normalized.usesLoaderPath === true,
            usesExecutablePath: normalized !== null && normalized.usesExecutablePath === true,
            usesRpathToken: normalized !== null && normalized.usesRpathToken === true,
            hasCurrentVersion: normalized !== null && normalized.hasCurrentVersion === true,
            hasCompatibilityVersion: normalized !== null && normalized.hasCompatibilityVersion === true,
            hasTimestamp: normalized !== null && normalized.hasTimestamp === true,
            versionMismatch: normalized !== null && normalized.versionMismatch === true,
            hasVersion: normalized !== null && normalized.hasVersion === true,
            hasMinOs: normalized !== null && normalized.hasMinOs === true,
            hasSdk: normalized !== null && normalized.hasSdk === true,
            hasTools: normalized !== null && normalized.hasTools === true,
            toolCount: normalized === null ? 0 : normalized.toolCount,
            uniqueToolCount: normalized === null ? 0 : normalized.uniqueToolCount,
            hasUuid: normalized !== null && normalized.hasUuid === true,
            uuidLength: normalized === null ? 0 : normalized.uuidLength,
            hasDataRange: normalized !== null && normalized.hasDataRange === true,
            hasEntryPoint: normalized !== null && normalized.hasEntryPoint === true,
            hasEncryptedRange: normalized !== null && normalized.hasEncryptedRange === true,
            hasDyldRegions: normalized !== null && normalized.hasDyldRegions === true,
            dyldRegionCount: normalized === null ? 0 : normalized.dyldRegionCount,
            nonEmptyDyldRegionCount: normalized === null ? 0 : normalized.nonEmptyDyldRegionCount,
            nonEmptyDyldRegionNames: normalized === null ? [] : normalized.nonEmptyDyldRegionNames,
            dyldRegions: normalized === null ? [] : normalized.dyldRegions,
            text: normalized === null ? '<null>' : normalized.text,
        };
    }
    case 'native.hook_environment': {
        const report = Native.detectHookEnvironment();
        return { kind: 'native.hook_environment', report, text: formatHookEnvironmentReport(report) };
    }
    case 'pac.available': {
        const available = !!PAC.available;
        return { kind: 'pac.available', available, resolved: true, resolvedAvailable: available, text: String(available) };
    }
    case 'pac.arm64e': {
        const arm64e = !!PAC.isProcessArm64e();
        return { kind: 'pac.arm64e', arm64e, resolved: true, resolvedArm64e: arm64e, text: String(arm64e) };
    }
    case 'pac.image': {
        const moduleName = String(spec.moduleName || '');
        const arm64e = PAC.isImageArm64e(moduleName);
        return {
            kind: 'pac.image',
            moduleName,
            arm64e: arm64e === null ? null : !!arm64e,
            hasImage: arm64e !== null,
            resolved: arm64e !== null,
            resolvedModuleName: arm64e === null ? null : moduleName,
            resolvedArm64e: arm64e === null ? null : !!arm64e,
            text: arm64e === null ? '<null>' : String(!!arm64e),
        };
    }
    case 'pac.images': {
        const filter = spec.filter === null || spec.filter === undefined ? null : String(spec.filter);
        const images = PAC.arm64eImages(filter).map((image) => normalizeImage(image));
        const imageNames = [];
        const pathKinds = [];
        let systemImageCount = 0;
        let appImageCount = 0;
        let jailbreakImageCount = 0;
        for (const image of images) {
            if (image.isSystemPath) {
                systemImageCount += 1;
            }
            if (image.isAppPath) {
                appImageCount += 1;
            }
            if (image.isJailbreakPath) {
                jailbreakImageCount += 1;
            }
            let imageNameSummary = imageNames.find((item) => item.name === image.name);
            if (imageNameSummary === undefined) {
                imageNameSummary = {
                    name: image.name,
                    count: 0,
                    firstPath: image.path,
                    lastPath: image.path,
                };
                imageNames.push(imageNameSummary);
            }
            imageNameSummary.count += 1;
            imageNameSummary.lastPath = image.path;
            let pathKindSummary = pathKinds.find((item) => item.pathKind === image.pathKind);
            if (pathKindSummary === undefined) {
                pathKindSummary = {
                    pathKind: image.pathKind,
                    count: 0,
                    firstImageName: image.name,
                    lastImageName: image.name,
                };
                pathKinds.push(pathKindSummary);
            }
            pathKindSummary.count += 1;
            pathKindSummary.lastImageName = image.name;
        }
        return {
            kind: 'pac.images',
            filter,
            hasFilter: filter !== null && filter.length !== 0,
            count: images.length,
            hasImages: images.length !== 0,
            firstImageName: images.length === 0 ? null : images[0].name,
            lastImageName: images.length === 0 ? null : images[images.length - 1].name,
            firstImagePath: images.length === 0 ? null : images[0].path,
            lastImagePath: images.length === 0 ? null : images[images.length - 1].path,
            firstPathKind: images.length === 0 ? null : images[0].pathKind,
            lastPathKind: images.length === 0 ? null : images[images.length - 1].pathKind,
            uniqueImageCount: imageNames.length,
            uniquePathKindCount: pathKinds.length,
            systemImageCount,
            appImageCount,
            jailbreakImageCount,
            imageNames,
            pathKinds,
            images,
            text: images.map((image) => image.text).join('\n'),
        };
    }
    case 'pac.strip': {
        const address = parseAddressArg(spec.address, 'pac.strip usage: pac.strip <address>');
        const stripped = PAC.strip(address).toString();
        return {
            kind: 'pac.strip',
            address: address.toString(),
            stripped,
            resolved: true,
            strippedAddress: stripped,
            changed: stripped !== address.toString(),
            text: stripped,
        };
    }
    case 'pac.stripdata': {
        const address = parseAddressArg(spec.address, 'pac.stripdata usage: pac.stripdata <address>');
        const stripped = PAC.stripData(address).toString();
        return {
            kind: 'pac.stripdata',
            address: address.toString(),
            stripped,
            resolved: true,
            strippedAddress: stripped,
            changed: stripped !== address.toString(),
            text: stripped,
        };
    }
    case 'swift.available': {
        const available = !!Swift.available;
        return { kind: 'swift.available', available, resolved: true, resolvedAvailable: available, text: String(available) };
    }
    case 'swift.demangle': {
        const symbol = String(spec.symbol || '');
        const demangled = Swift.demangle(symbol);
        const normalized = demangled === null || demangled === undefined ? null : String(demangled);
        return {
            kind: 'swift.demangle',
            symbol,
            demangled: normalized,
            hasDemangled: normalized !== null,
            resolved: normalized !== null,
            resolvedInputSymbol: normalized === null ? null : symbol,
            resolvedDemangled: normalized,
            resolvedSymbol: normalized,
            text: normalized === null ? '<unavailable>' : normalized,
        };
    }
    case 'swift.symbols': {
        const moduleName = spec.moduleName === null || spec.moduleName === undefined ? null : String(spec.moduleName);
        const query = String(spec.query || '');
        const symbols = Swift.symbols(query, moduleName).map((symbol) => normalizeSwiftSymbol(symbol));
        const memberSummary = summarizeSwiftMembers(symbols);
        const moduleNames = new Set();
        const moduleSummaries = [];
        const symbolNames = [];
        let demangledCount = 0;
        for (const symbol of symbols) {
            moduleNames.add(symbol.moduleName);
            if (symbol.hasDemangledName) {
                demangledCount += 1;
            }
            let moduleSummary = moduleSummaries.find((item) => item.moduleName === symbol.moduleName);
            if (moduleSummary === undefined) {
                moduleSummary = {
                    moduleName: symbol.moduleName,
                    count: 0,
                    firstSymbolName: symbol.name,
                    lastSymbolName: symbol.name,
                    demangledCount: 0,
                };
                moduleSummaries.push(moduleSummary);
            }
            moduleSummary.count += 1;
            moduleSummary.lastSymbolName = symbol.name;
            if (symbol.hasDemangledName) {
                moduleSummary.demangledCount += 1;
            }
            let summary = symbolNames.find((item) => item.symbolName === symbol.name);
            if (summary === undefined) {
                summary = {
                    symbolName: symbol.name,
                    count: 0,
                    firstModuleName: symbol.moduleName,
                    lastModuleName: symbol.moduleName,
                    hasDemangledName: false,
                };
                symbolNames.push(summary);
            }
            summary.count += 1;
            summary.lastModuleName = symbol.moduleName;
            if (symbol.hasDemangledName) {
                summary.hasDemangledName = true;
            }
        }
        return {
            kind: 'swift.symbols',
            moduleName,
            query,
            hasQuery: query.length !== 0,
            count: symbols.length,
            hasSymbols: symbols.length !== 0,
            firstSymbolName: symbols.length === 0 ? null : symbols[0].name,
            lastSymbolName: symbols.length === 0 ? null : symbols[symbols.length - 1].name,
            firstModuleName: symbols.length === 0 ? null : symbols[0].moduleName,
            lastModuleName: symbols.length === 0 ? null : symbols[symbols.length - 1].moduleName,
            uniqueModuleCount: symbols.length === 0 ? 0 : moduleNames.size,
            uniqueSymbolCount: symbolNames.length,
            demangledCount,
            hasDemangledSymbols: demangledCount !== 0,
            parsedMemberCount: memberSummary.parsedMemberCount,
            accessorCount: memberSummary.accessorCount,
            getterCount: memberSummary.getterCount,
            setterCount: memberSummary.setterCount,
            constructorCount: memberSummary.constructorCount,
            destructorCount: memberSummary.destructorCount,
            subscriptCount: memberSummary.subscriptCount,
            operatorCount: memberSummary.operatorCount,
            closureCount: memberSummary.closureCount,
            staticMemberCount: memberSummary.staticMemberCount,
            classMemberCount: memberSummary.classMemberCount,
            mutatingMemberCount: memberSummary.mutatingMemberCount,
            asyncCount: memberSummary.asyncCount,
            throwingCount: memberSummary.throwingCount,
            dispatchThunkCount: memberSummary.dispatchThunkCount,
            uniqueOwnerTypeCount: memberSummary.uniqueOwnerTypeCount,
            uniqueMemberKindCount: memberSummary.uniqueMemberKindCount,
            uniqueResultTypeCount: memberSummary.uniqueResultTypeCount,
            ownerTypes: memberSummary.ownerTypes,
            memberKinds: memberSummary.memberKinds,
            resultTypes: memberSummary.resultTypes,
            moduleNames: moduleSummaries,
            symbolNames,
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
            hasSymbolInfo: normalized !== null,
            resolved: normalized !== null,
            resolvedName: normalized === null ? null : normalized.name,
            resolvedModuleName: normalized === null ? null : normalized.moduleName,
            resolvedModuleBase: normalized === null ? null : normalized.moduleBase,
            resolvedDemangledName: normalized === null ? null : normalized.demangledName,
            resolvedAddress: normalized === null ? null : normalized.address,
            resolvedOffsetHex: normalized === null ? null : normalized.offsetHex,
            ownerTypeName: normalized === null ? null : normalized.ownerTypeName,
            memberName: normalized === null ? null : normalized.memberName,
            memberKind: normalized === null ? null : normalized.memberKind,
            signature: normalized === null ? null : normalized.signature,
            resultTypeName: normalized === null ? null : normalized.resultTypeName,
            hasName: normalized !== null && normalized.hasName === true,
            hasDemangledName: normalized !== null && normalized.hasDemangledName === true,
            hasOwnerTypeName: normalized !== null && normalized.hasOwnerTypeName === true,
            hasMemberName: normalized !== null && normalized.hasMemberName === true,
            hasSignature: normalized !== null && normalized.hasSignature === true,
            hasResultTypeName: normalized !== null && normalized.hasResultTypeName === true,
            isMember: normalized !== null && normalized.isMember === true,
            isAccessor: normalized !== null && normalized.isAccessor === true,
            isGetter: normalized !== null && normalized.isGetter === true,
            isSetter: normalized !== null && normalized.isSetter === true,
            isModifyAccessor: normalized !== null && normalized.isModifyAccessor === true,
            isReadAccessor: normalized !== null && normalized.isReadAccessor === true,
            isConstructor: normalized !== null && normalized.isConstructor === true,
            isDestructor: normalized !== null && normalized.isDestructor === true,
            isSubscript: normalized !== null && normalized.isSubscript === true,
            isOperator: normalized !== null && normalized.isOperator === true,
            isClosure: normalized !== null && normalized.isClosure === true,
            isStaticMember: normalized !== null && normalized.isStaticMember === true,
            isClassMember: normalized !== null && normalized.isClassMember === true,
            isMutating: normalized !== null && normalized.isMutating === true,
            isDispatchThunk: normalized !== null && normalized.isDispatchThunk === true,
            isAsync: normalized !== null && normalized.isAsync === true,
            isThrowing: normalized !== null && normalized.isThrowing === true,
            throwsKind: normalized === null ? null : normalized.throwsKind,
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
            hasProtocolInfo: normalized !== null,
            resolved: normalized !== null,
            resolvedName: normalized === null ? null : normalized.name,
            resolvedModuleName: normalized === null ? null : normalized.moduleName,
            resolvedModuleBase: normalized === null ? null : normalized.moduleBase,
            resolvedSourceSymbolName: normalized === null ? null : normalized.sourceSymbolName,
            resolvedSourceAddress: normalized === null ? null : normalized.sourceAddress,
            resolvedSourceOffsetHex: normalized === null ? null : normalized.sourceOffsetHex,
            resolvedSourceDemangledName: normalized === null ? null : normalized.sourceDemangledName,
            qualifiedName: normalized === null ? null : normalized.qualifiedName,
            signature: normalized === null ? null : normalized.signature,
            contextModuleName: normalized === null ? null : normalized.contextModuleName,
            detailKind: normalized === null ? null : normalized.detailKind,
            sourceKind: normalized === null ? null : normalized.sourceKind,
            hasName: normalized !== null && normalized.hasName === true,
            hasSourceKind: normalized !== null && normalized.hasSourceKind === true,
            hasSourceSymbolName: normalized !== null && normalized.hasSourceSymbolName === true,
            hasSourceDemangledName: normalized !== null && normalized.hasSourceDemangledName === true,
            hasQualifiedName: normalized !== null && normalized.hasQualifiedName === true,
            hasSignature: normalized !== null && normalized.hasSignature === true,
            hasContextModuleName: normalized !== null && normalized.hasContextModuleName === true,
            hasDetailKind: normalized !== null && normalized.hasDetailKind === true,
            isDescriptor: normalized !== null && normalized.isDescriptor === true,
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
            hasConformanceInfo: normalized !== null,
            resolved: normalized !== null,
            resolvedTypeName: normalized === null ? null : normalized.typeName,
            resolvedProtocolName: normalized === null ? null : normalized.protocolName,
            resolvedModuleName: normalized === null ? null : normalized.moduleName,
            resolvedModuleBase: normalized === null ? null : normalized.moduleBase,
            resolvedSourceSymbolName: normalized === null ? null : normalized.sourceSymbolName,
            resolvedSourceAddress: normalized === null ? null : normalized.sourceAddress,
            resolvedSourceOffsetHex: normalized === null ? null : normalized.sourceOffsetHex,
            resolvedSourceDemangledName: normalized === null ? null : normalized.sourceDemangledName,
            signature: normalized === null ? null : normalized.signature,
            relation: normalized === null ? null : normalized.relation,
            contextModuleName: normalized === null ? null : normalized.contextModuleName,
            whereClause: normalized === null ? null : normalized.whereClause,
            detailKind: normalized === null ? null : normalized.detailKind,
            sourceKind: normalized === null ? null : normalized.sourceKind,
            hasTypeName: normalized !== null && normalized.hasTypeName === true,
            hasProtocolName: normalized !== null && normalized.hasProtocolName === true,
            hasSourceKind: normalized !== null && normalized.hasSourceKind === true,
            hasSourceSymbolName: normalized !== null && normalized.hasSourceSymbolName === true,
            hasSourceDemangledName: normalized !== null && normalized.hasSourceDemangledName === true,
            hasSignature: normalized !== null && normalized.hasSignature === true,
            hasRelation: normalized !== null && normalized.hasRelation === true,
            hasContextModuleName: normalized !== null && normalized.hasContextModuleName === true,
            hasWhereClause: normalized !== null && normalized.hasWhereClause === true,
            hasDetailKind: normalized !== null && normalized.hasDetailKind === true,
            isDescriptor: normalized !== null && normalized.isDescriptor === true,
            isWitnessTable: normalized !== null && normalized.isWitnessTable === true,
            isWitnessAccessor: normalized !== null && normalized.isWitnessAccessor === true,
            isWitness: normalized !== null && normalized.isWitness === true,
            text: normalized === null ? '<null>' : normalized.text,
        };
    }
    case 'swift.protocols': {
        const moduleName = spec.moduleName === null || spec.moduleName === undefined ? null : String(spec.moduleName);
        const query = spec.query === null || spec.query === undefined ? null : String(spec.query);
        const protocols = Swift.protocols(query, moduleName).map((protocolInfo) => normalizeSwiftProtocol(protocolInfo));
        const sourceKinds = [];
        const moduleSummaries = [];
        const protocolNames = [];
        const contextModules = [];
        const detailKinds = [];
        const moduleNames = new Set();
        let demangledCount = 0;
        for (const protocol of protocols) {
            moduleNames.add(protocol.moduleName);
            if (protocol.hasSourceDemangledName) {
                demangledCount += 1;
            }
            let moduleSummary = moduleSummaries.find((item) => item.moduleName === protocol.moduleName);
            if (moduleSummary === undefined) {
                moduleSummary = {
                    moduleName: protocol.moduleName,
                    count: 0,
                    firstProtocol: protocol.name,
                    lastProtocol: protocol.name,
                    sourceDemangledCount: 0,
                };
                moduleSummaries.push(moduleSummary);
            }
            moduleSummary.count += 1;
            moduleSummary.lastProtocol = protocol.name;
            if (protocol.hasSourceDemangledName) {
                moduleSummary.sourceDemangledCount += 1;
            }
            let protocolSummary = protocolNames.find((item) => item.protocolName === protocol.name);
            if (protocolSummary === undefined) {
                protocolSummary = {
                    protocolName: protocol.name,
                    count: 0,
                    firstModuleName: protocol.moduleName,
                    lastModuleName: protocol.moduleName,
                    hasSourceDemangledName: false,
                };
                protocolNames.push(protocolSummary);
            }
            protocolSummary.count += 1;
            protocolSummary.lastModuleName = protocol.moduleName;
            if (protocol.hasSourceDemangledName) {
                protocolSummary.hasSourceDemangledName = true;
            }
            if (protocol.hasContextModuleName) {
                let contextSummary = contextModules.find((item) => item.contextModuleName === protocol.contextModuleName);
                if (contextSummary === undefined) {
                    contextSummary = {
                        contextModuleName: protocol.contextModuleName,
                        count: 0,
                        firstProtocol: protocol.name,
                        lastProtocol: protocol.name,
                    };
                    contextModules.push(contextSummary);
                }
                contextSummary.count += 1;
                contextSummary.lastProtocol = protocol.name;
            }
            const detailKind = protocol.detailKind === null ? '<none>' : String(protocol.detailKind);
            let detailSummary = detailKinds.find((item) => item.detailKind === detailKind);
            if (detailSummary === undefined) {
                detailSummary = {
                    detailKind,
                    count: 0,
                    firstProtocol: protocol.name,
                    lastProtocol: protocol.name,
                };
                detailKinds.push(detailSummary);
            }
            detailSummary.count += 1;
            detailSummary.lastProtocol = protocol.name;
            const key = protocol.sourceKind === null ? '<none>' : String(protocol.sourceKind);
            let summary = sourceKinds.find((item) => item.sourceKind === key);
            if (summary === undefined) {
                summary = {
                    sourceKind: key,
                    count: 0,
                    firstProtocol: protocol.name,
                    lastProtocol: protocol.name,
                };
                sourceKinds.push(summary);
            }
            summary.count += 1;
            summary.lastProtocol = protocol.name;
        }
        return {
            kind: 'swift.protocols',
            moduleName,
            query,
            hasQuery: query !== null && query.length !== 0,
            count: protocols.length,
            hasProtocols: protocols.length !== 0,
            firstProtocol: protocols.length === 0 ? null : protocols[0].name,
            lastProtocol: protocols.length === 0 ? null : protocols[protocols.length - 1].name,
            firstModuleName: protocols.length === 0 ? null : protocols[0].moduleName,
            lastModuleName: protocols.length === 0 ? null : protocols[protocols.length - 1].moduleName,
            uniqueModuleCount: protocols.length === 0 ? 0 : moduleNames.size,
            uniqueProtocolCount: protocolNames.length,
            uniqueSourceKindCount: sourceKinds.length,
            sourceDemangledCount: demangledCount,
            hasSourceDemangledProtocols: demangledCount !== 0,
            uniqueContextModuleCount: contextModules.length,
            uniqueDetailKindCount: detailKinds.length,
            moduleNames: moduleSummaries,
            protocolNames,
            contextModules,
            detailKinds,
            sourceKinds,
            protocols,
            text: protocols.map((protocolInfo) => protocolInfo.text).join('\n'),
        };
    }
    case 'swift.conformances': {
        const moduleName = spec.moduleName === null || spec.moduleName === undefined ? null : String(spec.moduleName);
        const query = String(spec.query || '');
        const conformances = Swift.conformances(query, moduleName).map((conformance) => normalizeSwiftConformance(conformance));
        const sourceKinds = [];
        const protocols = [];
        const typeSummaries = [];
        const moduleSummaries = [];
        const contextModules = [];
        const detailKinds = [];
        const moduleNames = new Set();
        const typeNames = new Set();
        let demangledCount = 0;
        let whereClauseCount = 0;
        for (const conformance of conformances) {
            moduleNames.add(conformance.moduleName);
            typeNames.add(conformance.typeName);
            if (conformance.hasSourceDemangledName) {
                demangledCount += 1;
            }
            if (conformance.hasWhereClause) {
                whereClauseCount += 1;
            }
            let typeSummary = typeSummaries.find((item) => item.typeName === conformance.typeName);
            if (typeSummary === undefined) {
                typeSummary = {
                    typeName: conformance.typeName,
                    count: 0,
                    firstProtocolName: conformance.protocolName,
                    lastProtocolName: conformance.protocolName,
                    firstModuleName: conformance.moduleName,
                    lastModuleName: conformance.moduleName,
                    hasSourceDemangledName: false,
                };
                typeSummaries.push(typeSummary);
            }
            typeSummary.count += 1;
            typeSummary.lastProtocolName = conformance.protocolName;
            typeSummary.lastModuleName = conformance.moduleName;
            if (conformance.hasSourceDemangledName) {
                typeSummary.hasSourceDemangledName = true;
            }
            let moduleSummary = moduleSummaries.find((item) => item.moduleName === conformance.moduleName);
            if (moduleSummary === undefined) {
                moduleSummary = {
                    moduleName: conformance.moduleName,
                    count: 0,
                    firstTypeName: conformance.typeName,
                    lastTypeName: conformance.typeName,
                    firstProtocolName: conformance.protocolName,
                    lastProtocolName: conformance.protocolName,
                    sourceDemangledCount: 0,
                };
                moduleSummaries.push(moduleSummary);
            }
            moduleSummary.count += 1;
            moduleSummary.lastTypeName = conformance.typeName;
            moduleSummary.lastProtocolName = conformance.protocolName;
            if (conformance.hasSourceDemangledName) {
                moduleSummary.sourceDemangledCount += 1;
            }
            let protocolSummary = protocols.find((item) => item.protocolName === conformance.protocolName);
            if (protocolSummary === undefined) {
                protocolSummary = {
                    protocolName: conformance.protocolName,
                    count: 0,
                    firstTypeName: conformance.typeName,
                    lastTypeName: conformance.typeName,
                };
                protocols.push(protocolSummary);
            }
            protocolSummary.count += 1;
            protocolSummary.lastTypeName = conformance.typeName;
            if (conformance.hasContextModuleName) {
                let contextSummary = contextModules.find((item) => item.contextModuleName === conformance.contextModuleName);
                if (contextSummary === undefined) {
                    contextSummary = {
                        contextModuleName: conformance.contextModuleName,
                        count: 0,
                        firstTypeName: conformance.typeName,
                        lastTypeName: conformance.typeName,
                        whereClauseCount: 0,
                    };
                    contextModules.push(contextSummary);
                }
                contextSummary.count += 1;
                contextSummary.lastTypeName = conformance.typeName;
                if (conformance.hasWhereClause) {
                    contextSummary.whereClauseCount += 1;
                }
            }
            const detailKind = conformance.detailKind === null ? '<none>' : String(conformance.detailKind);
            let detailSummary = detailKinds.find((item) => item.detailKind === detailKind);
            if (detailSummary === undefined) {
                detailSummary = {
                    detailKind,
                    count: 0,
                    firstTypeName: conformance.typeName,
                    lastTypeName: conformance.typeName,
                    whereClauseCount: 0,
                };
                detailKinds.push(detailSummary);
            }
            detailSummary.count += 1;
            detailSummary.lastTypeName = conformance.typeName;
            if (conformance.hasWhereClause) {
                detailSummary.whereClauseCount += 1;
            }
            const key = conformance.sourceKind === null ? '<none>' : String(conformance.sourceKind);
            let sourceSummary = sourceKinds.find((item) => item.sourceKind === key);
            if (sourceSummary === undefined) {
                sourceSummary = {
                    sourceKind: key,
                    count: 0,
                    firstTypeName: conformance.typeName,
                    lastTypeName: conformance.typeName,
                };
                sourceKinds.push(sourceSummary);
            }
            sourceSummary.count += 1;
            sourceSummary.lastTypeName = conformance.typeName;
        }
        return {
            kind: 'swift.conformances',
            moduleName,
            query,
            hasQuery: query.length !== 0,
            count: conformances.length,
            hasConformances: conformances.length !== 0,
            firstTypeName: conformances.length === 0 ? null : conformances[0].typeName,
            lastTypeName: conformances.length === 0 ? null : conformances[conformances.length - 1].typeName,
            firstProtocolName: conformances.length === 0 ? null : conformances[0].protocolName,
            lastProtocolName: conformances.length === 0 ? null : conformances[conformances.length - 1].protocolName,
            uniqueTypeCount: conformances.length === 0 ? 0 : typeNames.size,
            uniqueProtocolCount: protocols.length,
            uniqueModuleCount: conformances.length === 0 ? 0 : moduleNames.size,
            uniqueSourceKindCount: sourceKinds.length,
            sourceDemangledCount: demangledCount,
            hasSourceDemangledConformances: demangledCount !== 0,
            whereClauseCount,
            hasWhereClauses: whereClauseCount !== 0,
            uniqueContextModuleCount: contextModules.length,
            uniqueDetailKindCount: detailKinds.length,
            typeNames: typeSummaries,
            moduleNames: moduleSummaries,
            protocols,
            contextModules,
            detailKinds,
            sourceKinds,
            conformances,
            text: conformances.map((conformance) => conformance.text).join('\n'),
        };
    }
    case 'swift.metadata': {
        const moduleName = spec.moduleName === null || spec.moduleName === undefined ? null : String(spec.moduleName);
        const query = String(spec.query || '');
        const metadata = Swift.metadata(query, moduleName).map((typeInfo) => normalizeSwiftMetadata(typeInfo));
        const sourceKinds = [];
        const moduleSummaries = [];
        const typeSummaries = [];
        const contextModules = [];
        const detailKinds = [];
        const moduleNames = new Set();
        const typeNames = new Set();
        let demangledCount = 0;
        for (const typeInfo of metadata) {
            moduleNames.add(typeInfo.moduleName);
            typeNames.add(typeInfo.name);
            if (typeInfo.hasSourceDemangledName) {
                demangledCount += 1;
            }
            let moduleSummary = moduleSummaries.find((item) => item.moduleName === typeInfo.moduleName);
            if (moduleSummary === undefined) {
                moduleSummary = {
                    moduleName: typeInfo.moduleName,
                    count: 0,
                    firstTypeName: typeInfo.name,
                    lastTypeName: typeInfo.name,
                    sourceDemangledCount: 0,
                };
                moduleSummaries.push(moduleSummary);
            }
            moduleSummary.count += 1;
            moduleSummary.lastTypeName = typeInfo.name;
            if (typeInfo.hasSourceDemangledName) {
                moduleSummary.sourceDemangledCount += 1;
            }
            let typeSummary = typeSummaries.find((item) => item.typeName === typeInfo.name);
            if (typeSummary === undefined) {
                typeSummary = {
                    typeName: typeInfo.name,
                    count: 0,
                    firstModuleName: typeInfo.moduleName,
                    lastModuleName: typeInfo.moduleName,
                    hasSourceDemangledName: false,
                };
                typeSummaries.push(typeSummary);
            }
            typeSummary.count += 1;
            typeSummary.lastModuleName = typeInfo.moduleName;
            if (typeInfo.hasSourceDemangledName) {
                typeSummary.hasSourceDemangledName = true;
            }
            if (typeInfo.hasContextModuleName) {
                let contextSummary = contextModules.find((item) => item.contextModuleName === typeInfo.contextModuleName);
                if (contextSummary === undefined) {
                    contextSummary = {
                        contextModuleName: typeInfo.contextModuleName,
                        count: 0,
                        firstTypeName: typeInfo.name,
                        lastTypeName: typeInfo.name,
                    };
                    contextModules.push(contextSummary);
                }
                contextSummary.count += 1;
                contextSummary.lastTypeName = typeInfo.name;
            }
            const detailKind = typeInfo.detailKind === null ? '<none>' : String(typeInfo.detailKind);
            let detailSummary = detailKinds.find((item) => item.detailKind === detailKind);
            if (detailSummary === undefined) {
                detailSummary = {
                    detailKind,
                    count: 0,
                    firstTypeName: typeInfo.name,
                    lastTypeName: typeInfo.name,
                };
                detailKinds.push(detailSummary);
            }
            detailSummary.count += 1;
            detailSummary.lastTypeName = typeInfo.name;
            const key = typeInfo.sourceKind === null ? '<none>' : String(typeInfo.sourceKind);
            let summary = sourceKinds.find((item) => item.sourceKind === key);
            if (summary === undefined) {
                summary = {
                    sourceKind: key,
                    count: 0,
                    firstTypeName: typeInfo.name,
                    lastTypeName: typeInfo.name,
                };
                sourceKinds.push(summary);
            }
            summary.count += 1;
            summary.lastTypeName = typeInfo.name;
        }
        return {
            kind: 'swift.metadata',
            moduleName,
            query,
            hasQuery: query.length !== 0,
            count: metadata.length,
            hasMetadata: metadata.length !== 0,
            firstTypeName: metadata.length === 0 ? null : metadata[0].name,
            lastTypeName: metadata.length === 0 ? null : metadata[metadata.length - 1].name,
            firstModuleName: metadata.length === 0 ? null : metadata[0].moduleName,
            lastModuleName: metadata.length === 0 ? null : metadata[metadata.length - 1].moduleName,
            uniqueModuleCount: metadata.length === 0 ? 0 : moduleNames.size,
            uniqueTypeCount: metadata.length === 0 ? 0 : typeNames.size,
            uniqueSourceKindCount: sourceKinds.length,
            sourceDemangledCount: demangledCount,
            hasSourceDemangledMetadata: demangledCount !== 0,
            uniqueContextModuleCount: contextModules.length,
            uniqueDetailKindCount: detailKinds.length,
            moduleNames: moduleSummaries,
            typeNames: typeSummaries,
            contextModules,
            detailKinds,
            sourceKinds,
            metadata,
            text: metadata.map((typeInfo) => typeInfo.text).join('\n'),
        };
    }
    case 'swift.metadata_info': {
        const moduleName = spec.moduleName === null || spec.moduleName === undefined ? null : String(spec.moduleName);
        const typeName = String(spec.typeName || '');
        const metadataInfo = Swift.metadataInfo(typeName, moduleName);
        const normalized = metadataInfo === null ? null : normalizeSwiftMetadata(metadataInfo);
        return {
            kind: 'swift.metadata_info',
            moduleName,
            typeName,
            metadataInfo: normalized,
            hasMetadataInfo: normalized !== null,
            resolved: normalized !== null,
            resolvedName: normalized === null ? null : normalized.name,
            resolvedModuleName: normalized === null ? null : normalized.moduleName,
            resolvedModuleBase: normalized === null ? null : normalized.moduleBase,
            resolvedSourceSymbolName: normalized === null ? null : normalized.sourceSymbolName,
            resolvedSourceAddress: normalized === null ? null : normalized.sourceAddress,
            resolvedSourceOffsetHex: normalized === null ? null : normalized.sourceOffsetHex,
            resolvedSourceDemangledName: normalized === null ? null : normalized.sourceDemangledName,
            qualifiedName: normalized === null ? null : normalized.qualifiedName,
            signature: normalized === null ? null : normalized.signature,
            contextModuleName: normalized === null ? null : normalized.contextModuleName,
            detailKind: normalized === null ? null : normalized.detailKind,
            sourceKind: normalized === null ? null : normalized.sourceKind,
            hasName: normalized !== null && normalized.hasName === true,
            hasSourceKind: normalized !== null && normalized.hasSourceKind === true,
            hasSourceSymbolName: normalized !== null && normalized.hasSourceSymbolName === true,
            hasSourceDemangledName: normalized !== null && normalized.hasSourceDemangledName === true,
            hasQualifiedName: normalized !== null && normalized.hasQualifiedName === true,
            hasSignature: normalized !== null && normalized.hasSignature === true,
            hasContextModuleName: normalized !== null && normalized.hasContextModuleName === true,
            hasDetailKind: normalized !== null && normalized.hasDetailKind === true,
            isMetadata: normalized !== null && normalized.isMetadata === true,
            isMetadataAccessor: normalized !== null && normalized.isMetadataAccessor === true,
            isNominalDescriptor: normalized !== null && normalized.isNominalDescriptor === true,
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
            hasTypeInfo: normalized !== null,
            resolved: normalized !== null,
            resolvedName: normalized === null ? null : normalized.name,
            resolvedModuleName: normalized === null ? null : normalized.moduleName,
            resolvedModuleBase: normalized === null ? null : normalized.moduleBase,
            resolvedSourceSymbolName: normalized === null ? null : normalized.sourceSymbolName,
            resolvedSourceAddress: normalized === null ? null : normalized.sourceAddress,
            resolvedSourceOffsetHex: normalized === null ? null : normalized.sourceOffsetHex,
            resolvedSourceDemangledName: normalized === null ? null : normalized.sourceDemangledName,
            qualifiedName: normalized === null ? null : normalized.qualifiedName,
            signature: normalized === null ? null : normalized.signature,
            contextModuleName: normalized === null ? null : normalized.contextModuleName,
            detailKind: normalized === null ? null : normalized.detailKind,
            sourceKind: normalized === null ? null : normalized.sourceKind,
            hasName: normalized !== null && normalized.hasName === true,
            hasSourceKind: normalized !== null && normalized.hasSourceKind === true,
            hasSourceSymbolName: normalized !== null && normalized.hasSourceSymbolName === true,
            hasSourceDemangledName: normalized !== null && normalized.hasSourceDemangledName === true,
            hasQualifiedName: normalized !== null && normalized.hasQualifiedName === true,
            hasSignature: normalized !== null && normalized.hasSignature === true,
            hasContextModuleName: normalized !== null && normalized.hasContextModuleName === true,
            hasDetailKind: normalized !== null && normalized.hasDetailKind === true,
            isMetadata: normalized !== null && normalized.isMetadata === true,
            isMetadataAccessor: normalized !== null && normalized.isMetadataAccessor === true,
            isNominalDescriptor: normalized !== null && normalized.isNominalDescriptor === true,
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
            hasMethodInfo: normalized !== null,
            resolved: normalized !== null,
            resolvedName: normalized === null ? null : normalized.name,
            resolvedModuleName: normalized === null ? null : normalized.moduleName,
            resolvedModuleBase: normalized === null ? null : normalized.moduleBase,
            resolvedDemangledName: normalized === null ? null : normalized.demangledName,
            resolvedAddress: normalized === null ? null : normalized.address,
            resolvedOffsetHex: normalized === null ? null : normalized.offsetHex,
            ownerTypeName: normalized === null ? null : normalized.ownerTypeName,
            memberName: normalized === null ? null : normalized.memberName,
            memberKind: normalized === null ? null : normalized.memberKind,
            signature: normalized === null ? null : normalized.signature,
            resultTypeName: normalized === null ? null : normalized.resultTypeName,
            hasName: normalized !== null && normalized.hasName === true,
            hasDemangledName: normalized !== null && normalized.hasDemangledName === true,
            hasOwnerTypeName: normalized !== null && normalized.hasOwnerTypeName === true,
            hasMemberName: normalized !== null && normalized.hasMemberName === true,
            hasSignature: normalized !== null && normalized.hasSignature === true,
            hasResultTypeName: normalized !== null && normalized.hasResultTypeName === true,
            isMember: normalized !== null && normalized.isMember === true,
            isAccessor: normalized !== null && normalized.isAccessor === true,
            isGetter: normalized !== null && normalized.isGetter === true,
            isSetter: normalized !== null && normalized.isSetter === true,
            isModifyAccessor: normalized !== null && normalized.isModifyAccessor === true,
            isReadAccessor: normalized !== null && normalized.isReadAccessor === true,
            isConstructor: normalized !== null && normalized.isConstructor === true,
            isDestructor: normalized !== null && normalized.isDestructor === true,
            isSubscript: normalized !== null && normalized.isSubscript === true,
            isOperator: normalized !== null && normalized.isOperator === true,
            isClosure: normalized !== null && normalized.isClosure === true,
            isStaticMember: normalized !== null && normalized.isStaticMember === true,
            isClassMember: normalized !== null && normalized.isClassMember === true,
            isMutating: normalized !== null && normalized.isMutating === true,
            isDispatchThunk: normalized !== null && normalized.isDispatchThunk === true,
            isAsync: normalized !== null && normalized.isAsync === true,
            isThrowing: normalized !== null && normalized.isThrowing === true,
            throwsKind: normalized === null ? null : normalized.throwsKind,
            text: normalized === null ? '<null>' : normalized.text,
        };
    }
    case 'swift.vtable': {
        const moduleName = spec.moduleName === null || spec.moduleName === undefined ? null : String(spec.moduleName);
        const query = String(spec.query || '');
        const entries = Swift.vtable(query, moduleName).map((entry) => normalizeSwiftVtableEntry(entry));
        const memberSummary = summarizeSwiftMembers(entries);
        const sourceKinds = [];
        const memberNames = [];
        const types = [];
        const moduleSummaries = [];
        const moduleNames = new Set();
        const typeNames = new Set();
        const uniqueMemberNames = new Set();
        let dispatchThunkCount = 0;
        let demangledCount = 0;
        for (const entry of entries) {
            moduleNames.add(entry.moduleName);
            typeNames.add(entry.typeName);
            uniqueMemberNames.add(entry.memberName);
            if (entry.isDispatchThunk) {
                dispatchThunkCount += 1;
            }
            if (entry.hasDemangledName) {
                demangledCount += 1;
            }
            let moduleSummary = moduleSummaries.find((item) => item.moduleName === entry.moduleName);
            if (moduleSummary === undefined) {
                moduleSummary = {
                    moduleName: entry.moduleName,
                    count: 0,
                    firstTypeName: entry.typeName,
                    lastTypeName: entry.typeName,
                    firstMemberName: entry.memberName,
                    lastMemberName: entry.memberName,
                    dispatchThunkCount: 0,
                    demangledCount: 0,
                };
                moduleSummaries.push(moduleSummary);
            }
            moduleSummary.count += 1;
            moduleSummary.lastTypeName = entry.typeName;
            moduleSummary.lastMemberName = entry.memberName;
            if (entry.isDispatchThunk) {
                moduleSummary.dispatchThunkCount += 1;
            }
            if (entry.hasDemangledName) {
                moduleSummary.demangledCount += 1;
            }
            let typeSummary = types.find((item) => item.typeName === entry.typeName);
            if (typeSummary === undefined) {
                typeSummary = {
                    typeName: entry.typeName,
                    count: 0,
                    firstMemberName: entry.memberName,
                    lastMemberName: entry.memberName,
                    dispatchThunkCount: 0,
                };
                types.push(typeSummary);
            }
            typeSummary.count += 1;
            typeSummary.lastMemberName = entry.memberName;
            if (entry.isDispatchThunk) {
                typeSummary.dispatchThunkCount += 1;
            }
            let memberSummary = memberNames.find((item) => item.memberName === entry.memberName);
            if (memberSummary === undefined) {
                memberSummary = {
                    memberName: entry.memberName,
                    count: 0,
                    firstTypeName: entry.typeName,
                    lastTypeName: entry.typeName,
                    firstModuleName: entry.moduleName,
                    lastModuleName: entry.moduleName,
                    dispatchThunkCount: 0,
                    demangledCount: 0,
                };
                memberNames.push(memberSummary);
            }
            memberSummary.count += 1;
            memberSummary.lastTypeName = entry.typeName;
            memberSummary.lastModuleName = entry.moduleName;
            if (entry.isDispatchThunk) {
                memberSummary.dispatchThunkCount += 1;
            }
            if (entry.hasDemangledName) {
                memberSummary.demangledCount += 1;
            }
            const key = entry.sourceKind === null ? '<none>' : String(entry.sourceKind);
            let sourceSummary = sourceKinds.find((item) => item.sourceKind === key);
            if (sourceSummary === undefined) {
                sourceSummary = {
                    sourceKind: key,
                    count: 0,
                    firstTypeName: entry.typeName,
                    lastTypeName: entry.typeName,
                    firstMemberName: entry.memberName,
                    lastMemberName: entry.memberName,
                };
                sourceKinds.push(sourceSummary);
            }
            sourceSummary.count += 1;
            sourceSummary.lastTypeName = entry.typeName;
            sourceSummary.lastMemberName = entry.memberName;
        }
        return {
            kind: 'swift.vtable',
            moduleName,
            query,
            hasQuery: query.length !== 0,
            count: entries.length,
            hasEntries: entries.length !== 0,
            firstTypeName: entries.length === 0 ? null : entries[0].typeName,
            lastTypeName: entries.length === 0 ? null : entries[entries.length - 1].typeName,
            firstMemberName: entries.length === 0 ? null : entries[0].memberName,
            lastMemberName: entries.length === 0 ? null : entries[entries.length - 1].memberName,
            firstModuleName: entries.length === 0 ? null : entries[0].moduleName,
            lastModuleName: entries.length === 0 ? null : entries[entries.length - 1].moduleName,
            uniqueTypeCount: entries.length === 0 ? 0 : typeNames.size,
            uniqueMemberCount: entries.length === 0 ? 0 : uniqueMemberNames.size,
            uniqueModuleCount: entries.length === 0 ? 0 : moduleNames.size,
            uniqueSourceKindCount: sourceKinds.length,
            dispatchThunkCount,
            hasDispatchThunks: dispatchThunkCount !== 0,
            demangledCount,
            hasDemangledEntries: demangledCount !== 0,
            parsedMemberCount: memberSummary.parsedMemberCount,
            accessorCount: memberSummary.accessorCount,
            getterCount: memberSummary.getterCount,
            setterCount: memberSummary.setterCount,
            constructorCount: memberSummary.constructorCount,
            destructorCount: memberSummary.destructorCount,
            subscriptCount: memberSummary.subscriptCount,
            operatorCount: memberSummary.operatorCount,
            closureCount: memberSummary.closureCount,
            staticMemberCount: memberSummary.staticMemberCount,
            classMemberCount: memberSummary.classMemberCount,
            mutatingMemberCount: memberSummary.mutatingMemberCount,
            asyncCount: memberSummary.asyncCount,
            throwingCount: memberSummary.throwingCount,
            uniqueOwnerTypeCount: memberSummary.uniqueOwnerTypeCount,
            uniqueMemberKindCount: memberSummary.uniqueMemberKindCount,
            uniqueResultTypeCount: memberSummary.uniqueResultTypeCount,
            ownerTypes: memberSummary.ownerTypes,
            memberKinds: memberSummary.memberKinds,
            resultTypes: memberSummary.resultTypes,
            moduleNames: moduleSummaries,
            memberNames,
            types,
            sourceKinds,
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
            hasVtableInfo: normalized !== null,
            resolved: normalized !== null,
            resolvedTypeName: normalized === null ? null : normalized.typeName,
            resolvedMemberName: normalized === null ? null : normalized.memberName,
            resolvedMemberKey: normalized === null ? null : normalized.memberKey,
            resolvedModuleName: normalized === null ? null : normalized.moduleName,
            resolvedModuleBase: normalized === null ? null : normalized.moduleBase,
            resolvedName: normalized === null ? null : normalized.name,
            resolvedDemangledName: normalized === null ? null : normalized.demangledName,
            resolvedAddress: normalized === null ? null : normalized.address,
            resolvedOffsetHex: normalized === null ? null : normalized.offsetHex,
            ownerTypeName: normalized === null ? null : normalized.ownerTypeName,
            memberKind: normalized === null ? null : normalized.memberKind,
            signature: normalized === null ? null : normalized.signature,
            resultTypeName: normalized === null ? null : normalized.resultTypeName,
            sourceKind: normalized === null ? null : normalized.sourceKind,
            hasTypeName: normalized !== null && normalized.hasTypeName === true,
            hasMemberName: normalized !== null && normalized.hasMemberName === true,
            hasName: normalized !== null && normalized.hasName === true,
            hasSourceKind: normalized !== null && normalized.hasSourceKind === true,
            hasDemangledName: normalized !== null && normalized.hasDemangledName === true,
            hasOwnerTypeName: normalized !== null && normalized.hasOwnerTypeName === true,
            hasSignature: normalized !== null && normalized.hasSignature === true,
            hasResultTypeName: normalized !== null && normalized.hasResultTypeName === true,
            isMember: normalized !== null && normalized.isMember === true,
            isAccessor: normalized !== null && normalized.isAccessor === true,
            isGetter: normalized !== null && normalized.isGetter === true,
            isSetter: normalized !== null && normalized.isSetter === true,
            isModifyAccessor: normalized !== null && normalized.isModifyAccessor === true,
            isReadAccessor: normalized !== null && normalized.isReadAccessor === true,
            isConstructor: normalized !== null && normalized.isConstructor === true,
            isDestructor: normalized !== null && normalized.isDestructor === true,
            isSubscript: normalized !== null && normalized.isSubscript === true,
            isOperator: normalized !== null && normalized.isOperator === true,
            isClosure: normalized !== null && normalized.isClosure === true,
            isStaticMember: normalized !== null && normalized.isStaticMember === true,
            isClassMember: normalized !== null && normalized.isClassMember === true,
            isMutating: normalized !== null && normalized.isMutating === true,
            isDispatchThunk: normalized !== null && normalized.isDispatchThunk === true,
            isAsync: normalized !== null && normalized.isAsync === true,
            isThrowing: normalized !== null && normalized.isThrowing === true,
            throwsKind: normalized === null ? null : normalized.throwsKind,
            text: normalized === null ? '<null>' : normalized.text,
        };
    }
    case 'swift.witness_table': {
        const moduleName = spec.moduleName === null || spec.moduleName === undefined ? null : String(spec.moduleName);
        const query = String(spec.query || '');
        const entries = Swift.witnessTable(query, moduleName).map((entry) => normalizeSwiftWitnessTable(entry));
        const sourceKinds = [];
        const protocols = [];
        const typeSummaries = [];
        const witnessKeys = [];
        const moduleSummaries = [];
        const contextModules = [];
        const detailKinds = [];
        const moduleNames = new Set();
        const typeNames = new Set();
        const protocolNames = new Set();
        const uniqueWitnessKeys = new Set();
        let accessorCount = 0;
        let demangledCount = 0;
        let whereClauseCount = 0;
        for (const entry of entries) {
            moduleNames.add(entry.moduleName);
            typeNames.add(entry.typeName);
            protocolNames.add(entry.protocolName);
            uniqueWitnessKeys.add(entry.witnessKey);
            if (entry.isAccessor) {
                accessorCount += 1;
            }
            if (entry.hasDemangledName) {
                demangledCount += 1;
            }
            if (entry.hasWhereClause) {
                whereClauseCount += 1;
            }
            let typeSummary = typeSummaries.find((item) => item.typeName === entry.typeName);
            if (typeSummary === undefined) {
                typeSummary = {
                    typeName: entry.typeName,
                    count: 0,
                    firstProtocolName: entry.protocolName,
                    lastProtocolName: entry.protocolName,
                    firstModuleName: entry.moduleName,
                    lastModuleName: entry.moduleName,
                    accessorCount: 0,
                    demangledCount: 0,
                };
                typeSummaries.push(typeSummary);
            }
            typeSummary.count += 1;
            typeSummary.lastProtocolName = entry.protocolName;
            typeSummary.lastModuleName = entry.moduleName;
            if (entry.isAccessor) {
                typeSummary.accessorCount += 1;
            }
            if (entry.hasDemangledName) {
                typeSummary.demangledCount += 1;
            }
            let moduleSummary = moduleSummaries.find((item) => item.moduleName === entry.moduleName);
            if (moduleSummary === undefined) {
                moduleSummary = {
                    moduleName: entry.moduleName,
                    count: 0,
                    firstTypeName: entry.typeName,
                    lastTypeName: entry.typeName,
                    firstProtocolName: entry.protocolName,
                    lastProtocolName: entry.protocolName,
                    accessorCount: 0,
                    demangledCount: 0,
                };
                moduleSummaries.push(moduleSummary);
            }
            moduleSummary.count += 1;
            moduleSummary.lastTypeName = entry.typeName;
            moduleSummary.lastProtocolName = entry.protocolName;
            if (entry.isAccessor) {
                moduleSummary.accessorCount += 1;
            }
            if (entry.hasDemangledName) {
                moduleSummary.demangledCount += 1;
            }
            let protocolSummary = protocols.find((item) => item.protocolName === entry.protocolName);
            if (protocolSummary === undefined) {
                protocolSummary = {
                    protocolName: entry.protocolName,
                    count: 0,
                    firstTypeName: entry.typeName,
                    lastTypeName: entry.typeName,
                    accessorCount: 0,
                };
                protocols.push(protocolSummary);
            }
            protocolSummary.count += 1;
            protocolSummary.lastTypeName = entry.typeName;
            if (entry.isAccessor) {
                protocolSummary.accessorCount += 1;
            }
            let witnessKeySummary = witnessKeys.find((item) => item.witnessKey === entry.witnessKey);
            if (witnessKeySummary === undefined) {
                witnessKeySummary = {
                    witnessKey: entry.witnessKey,
                    count: 0,
                    firstModuleName: entry.moduleName,
                    lastModuleName: entry.moduleName,
                    accessorCount: 0,
                    demangledCount: 0,
                };
                witnessKeys.push(witnessKeySummary);
            }
            witnessKeySummary.count += 1;
            witnessKeySummary.lastModuleName = entry.moduleName;
            if (entry.isAccessor) {
                witnessKeySummary.accessorCount += 1;
            }
            if (entry.hasDemangledName) {
                witnessKeySummary.demangledCount += 1;
            }
            if (entry.hasContextModuleName) {
                let contextSummary = contextModules.find((item) => item.contextModuleName === entry.contextModuleName);
                if (contextSummary === undefined) {
                    contextSummary = {
                        contextModuleName: entry.contextModuleName,
                        count: 0,
                        firstProtocolName: entry.protocolName,
                        lastProtocolName: entry.protocolName,
                        accessorCount: 0,
                        whereClauseCount: 0,
                    };
                    contextModules.push(contextSummary);
                }
                contextSummary.count += 1;
                contextSummary.lastProtocolName = entry.protocolName;
                if (entry.isAccessor) {
                    contextSummary.accessorCount += 1;
                }
                if (entry.hasWhereClause) {
                    contextSummary.whereClauseCount += 1;
                }
            }
            const detailKind = entry.detailKind === null ? '<none>' : String(entry.detailKind);
            let detailSummary = detailKinds.find((item) => item.detailKind === detailKind);
            if (detailSummary === undefined) {
                detailSummary = {
                    detailKind,
                    count: 0,
                    firstProtocolName: entry.protocolName,
                    lastProtocolName: entry.protocolName,
                    accessorCount: 0,
                    whereClauseCount: 0,
                };
                detailKinds.push(detailSummary);
            }
            detailSummary.count += 1;
            detailSummary.lastProtocolName = entry.protocolName;
            if (entry.isAccessor) {
                detailSummary.accessorCount += 1;
            }
            if (entry.hasWhereClause) {
                detailSummary.whereClauseCount += 1;
            }
            const key = entry.sourceKind === null ? '<none>' : String(entry.sourceKind);
            let sourceSummary = sourceKinds.find((item) => item.sourceKind === key);
            if (sourceSummary === undefined) {
                sourceSummary = {
                    sourceKind: key,
                    count: 0,
                    firstTypeName: entry.typeName,
                    lastTypeName: entry.typeName,
                    firstProtocolName: entry.protocolName,
                    lastProtocolName: entry.protocolName,
                };
                sourceKinds.push(sourceSummary);
            }
            sourceSummary.count += 1;
            sourceSummary.lastTypeName = entry.typeName;
            sourceSummary.lastProtocolName = entry.protocolName;
        }
        return {
            kind: 'swift.witness_table',
            moduleName,
            query,
            hasQuery: query.length !== 0,
            count: entries.length,
            hasEntries: entries.length !== 0,
            firstTypeName: entries.length === 0 ? null : entries[0].typeName,
            lastTypeName: entries.length === 0 ? null : entries[entries.length - 1].typeName,
            firstProtocolName: entries.length === 0 ? null : entries[0].protocolName,
            lastProtocolName: entries.length === 0 ? null : entries[entries.length - 1].protocolName,
            firstModuleName: entries.length === 0 ? null : entries[0].moduleName,
            lastModuleName: entries.length === 0 ? null : entries[entries.length - 1].moduleName,
            uniqueTypeCount: entries.length === 0 ? 0 : typeNames.size,
            uniqueProtocolCount: entries.length === 0 ? 0 : protocolNames.size,
            uniqueWitnessKeyCount: entries.length === 0 ? 0 : uniqueWitnessKeys.size,
            uniqueModuleCount: entries.length === 0 ? 0 : moduleNames.size,
            uniqueSourceKindCount: sourceKinds.length,
            accessorCount,
            hasAccessors: accessorCount !== 0,
            demangledCount,
            hasDemangledEntries: demangledCount !== 0,
            whereClauseCount,
            hasWhereClauses: whereClauseCount !== 0,
            uniqueContextModuleCount: contextModules.length,
            uniqueDetailKindCount: detailKinds.length,
            typeNames: typeSummaries,
            moduleNames: moduleSummaries,
            protocols,
            witnessKeys,
            contextModules,
            detailKinds,
            sourceKinds,
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
            hasWitnessTableInfo: normalized !== null,
            resolved: normalized !== null,
            resolvedTypeName: normalized === null ? null : normalized.typeName,
            resolvedProtocolName: normalized === null ? null : normalized.protocolName,
            resolvedWitnessKey: normalized === null ? null : normalized.witnessKey,
            resolvedModuleName: normalized === null ? null : normalized.moduleName,
            resolvedModuleBase: normalized === null ? null : normalized.moduleBase,
            resolvedName: normalized === null ? null : normalized.name,
            resolvedDemangledName: normalized === null ? null : normalized.demangledName,
            resolvedAddress: normalized === null ? null : normalized.address,
            resolvedOffsetHex: normalized === null ? null : normalized.offsetHex,
            signature: normalized === null ? null : normalized.signature,
            relation: normalized === null ? null : normalized.relation,
            contextModuleName: normalized === null ? null : normalized.contextModuleName,
            whereClause: normalized === null ? null : normalized.whereClause,
            detailKind: normalized === null ? null : normalized.detailKind,
            sourceKind: normalized === null ? null : normalized.sourceKind,
            hasTypeName: normalized !== null && normalized.hasTypeName === true,
            hasProtocolName: normalized !== null && normalized.hasProtocolName === true,
            hasName: normalized !== null && normalized.hasName === true,
            hasSourceKind: normalized !== null && normalized.hasSourceKind === true,
            hasDemangledName: normalized !== null && normalized.hasDemangledName === true,
            hasSignature: normalized !== null && normalized.hasSignature === true,
            hasRelation: normalized !== null && normalized.hasRelation === true,
            hasContextModuleName: normalized !== null && normalized.hasContextModuleName === true,
            hasWhereClause: normalized !== null && normalized.hasWhereClause === true,
            hasDetailKind: normalized !== null && normalized.hasDetailKind === true,
            isDescriptor: normalized !== null && normalized.isDescriptor === true,
            isWitnessTable: normalized !== null && normalized.isWitnessTable === true,
            isWitnessAccessor: normalized !== null && normalized.isWitnessAccessor === true,
            isWitness: normalized !== null && normalized.isWitness === true,
            isAccessor: normalized !== null && normalized.isAccessor === true,
            text: normalized === null ? '<null>' : normalized.text,
        };
    }
    case 'swift.type_layout': {
        const moduleName = spec.moduleName === null || spec.moduleName === undefined ? null : String(spec.moduleName);
        const query = String(spec.query || '');
        const layouts = Swift.typeLayout(query, moduleName).map((layout) => normalizeSwiftTypeLayout(layout));
        const typeSourceBuckets = [];
        for (const layout of layouts) {
            typeSourceBuckets.push(
                { entries: layout.metadata, countField: 'metadataCount' },
                { entries: layout.metadataAccessors, countField: 'metadataAccessorCount' },
                { entries: layout.nominalDescriptors, countField: 'nominalDescriptorCount' },
                { entries: layout.metadataCaches, countField: 'metadataCacheCount' },
                { entries: layout.associatedTypeDescriptors, countField: 'associatedTypeDescriptorCount' },
            );
        }
        const typeSourceSummary = summarizeSwiftTypeSourceBuckets(typeSourceBuckets);
        const moduleSummaries = [];
        const typeSummaries = [];
        const moduleNames = new Set();
        let layoutsWithMetadataCount = 0;
        let layoutsWithMetadataAccessorsCount = 0;
        let layoutsWithNominalDescriptorsCount = 0;
        let layoutsWithMetadataCachesCount = 0;
        let layoutsWithAssociatedTypeDescriptorsCount = 0;
        let layoutsWithVtableEntriesCount = 0;
        let layoutsWithWitnessTablesCount = 0;
        let metadataEntryCount = 0;
        let metadataAccessorEntryCount = 0;
        let nominalDescriptorEntryCount = 0;
        let metadataCacheEntryCount = 0;
        let associatedTypeDescriptorEntryCount = 0;
        let vtableEntryCount = 0;
        let witnessTableEntryCount = 0;
        let vtableAccessorEntryCount = 0;
        let vtableGetterEntryCount = 0;
        let vtableSetterEntryCount = 0;
        let vtableConstructorEntryCount = 0;
        let vtableDestructorEntryCount = 0;
        let vtableStaticMemberEntryCount = 0;
        let vtableAsyncEntryCount = 0;
        let vtableThrowingEntryCount = 0;
        let witnessAccessorCount = 0;
        let layoutsWithSourceDemangledTypesCount = 0;
        let layoutsWithAccessorVtableEntriesCount = 0;
        let layoutsWithAsyncVtableEntriesCount = 0;
        let layoutsWithThrowingVtableEntriesCount = 0;
        let layoutsWithWitnessAccessorsCount = 0;
        for (const layout of layouts) {
            moduleNames.add(layout.moduleName);
            let moduleSummary = moduleSummaries.find((item) => item.moduleName === layout.moduleName);
            if (moduleSummary === undefined) {
                moduleSummary = {
                    moduleName: layout.moduleName,
                    count: 0,
                    firstTypeName: layout.name,
                    lastTypeName: layout.name,
                    layoutsWithMetadataCount: 0,
                    layoutsWithVtableEntriesCount: 0,
                    layoutsWithWitnessTablesCount: 0,
                    metadataEntryCount: 0,
                    vtableEntryCount: 0,
                    witnessTableEntryCount: 0,
                };
                moduleSummaries.push(moduleSummary);
            }
            moduleSummary.count += 1;
            moduleSummary.lastTypeName = layout.name;
            if (layout.hasMetadata) {
                moduleSummary.layoutsWithMetadataCount += 1;
            }
            if (layout.hasVtableEntries) {
                moduleSummary.layoutsWithVtableEntriesCount += 1;
            }
            if (layout.hasWitnessTables) {
                moduleSummary.layoutsWithWitnessTablesCount += 1;
            }
            moduleSummary.metadataEntryCount += layout.metadataCount;
            moduleSummary.vtableEntryCount += layout.vtableCount;
            moduleSummary.witnessTableEntryCount += layout.witnessTableCount;
            let typeSummary = typeSummaries.find((item) => item.typeName === layout.name);
            if (typeSummary === undefined) {
                typeSummary = {
                    typeName: layout.name,
                    count: 0,
                    firstModuleName: layout.moduleName,
                    lastModuleName: layout.moduleName,
                    metadataEntryCount: 0,
                    metadataAccessorEntryCount: 0,
                    nominalDescriptorEntryCount: 0,
                    metadataCacheEntryCount: 0,
                    associatedTypeDescriptorEntryCount: 0,
                    vtableEntryCount: 0,
                    witnessTableEntryCount: 0,
                };
                typeSummaries.push(typeSummary);
            }
            typeSummary.count += 1;
            typeSummary.lastModuleName = layout.moduleName;
            typeSummary.metadataEntryCount += layout.metadataCount;
            typeSummary.metadataAccessorEntryCount += layout.metadataAccessorCount;
            typeSummary.nominalDescriptorEntryCount += layout.nominalDescriptorCount;
            typeSummary.metadataCacheEntryCount += layout.metadataCacheCount;
            typeSummary.associatedTypeDescriptorEntryCount += layout.associatedTypeDescriptorCount;
            typeSummary.vtableEntryCount += layout.vtableCount;
            typeSummary.witnessTableEntryCount += layout.witnessTableCount;
            if (layout.hasMetadata) {
                layoutsWithMetadataCount += 1;
            }
            if (layout.hasMetadataAccessors) {
                layoutsWithMetadataAccessorsCount += 1;
            }
            if (layout.hasNominalDescriptors) {
                layoutsWithNominalDescriptorsCount += 1;
            }
            if (layout.hasMetadataCaches) {
                layoutsWithMetadataCachesCount += 1;
            }
            if (layout.hasAssociatedTypeDescriptors) {
                layoutsWithAssociatedTypeDescriptorsCount += 1;
            }
            if (layout.hasVtableEntries) {
                layoutsWithVtableEntriesCount += 1;
            }
            if (layout.hasWitnessTables) {
                layoutsWithWitnessTablesCount += 1;
            }
            metadataEntryCount += layout.metadataCount;
            metadataAccessorEntryCount += layout.metadataAccessorCount;
            nominalDescriptorEntryCount += layout.nominalDescriptorCount;
            metadataCacheEntryCount += layout.metadataCacheCount;
            associatedTypeDescriptorEntryCount += layout.associatedTypeDescriptorCount;
            vtableEntryCount += layout.vtableCount;
            witnessTableEntryCount += layout.witnessTableCount;
            vtableAccessorEntryCount += layout.vtableAccessorCount;
            vtableGetterEntryCount += layout.vtableGetterCount;
            vtableSetterEntryCount += layout.vtableSetterCount;
            vtableConstructorEntryCount += layout.vtableConstructorCount;
            vtableDestructorEntryCount += layout.vtableDestructorCount;
            vtableStaticMemberEntryCount += layout.vtableStaticMemberCount;
            vtableAsyncEntryCount += layout.vtableAsyncCount;
            vtableThrowingEntryCount += layout.vtableThrowingCount;
            witnessAccessorCount += layout.witnessAccessorCount;
            if (layout.hasSourceDemangledTypes) {
                layoutsWithSourceDemangledTypesCount += 1;
            }
            if (layout.vtableAccessorCount !== 0) {
                layoutsWithAccessorVtableEntriesCount += 1;
            }
            if (layout.vtableAsyncCount !== 0) {
                layoutsWithAsyncVtableEntriesCount += 1;
            }
            if (layout.vtableThrowingCount !== 0) {
                layoutsWithThrowingVtableEntriesCount += 1;
            }
            if (layout.witnessAccessorCount !== 0) {
                layoutsWithWitnessAccessorsCount += 1;
            }
        }
        return {
            kind: 'swift.type_layout',
            moduleName,
            query,
            hasQuery: query.length !== 0,
            count: layouts.length,
            hasLayouts: layouts.length !== 0,
            firstTypeName: layouts.length === 0 ? null : layouts[0].name,
            lastTypeName: layouts.length === 0 ? null : layouts[layouts.length - 1].name,
            firstModuleName: layouts.length === 0 ? null : layouts[0].moduleName,
            lastModuleName: layouts.length === 0 ? null : layouts[layouts.length - 1].moduleName,
            uniqueModuleCount: layouts.length === 0 ? 0 : moduleNames.size,
            layoutsWithMetadataCount,
            layoutsWithMetadataAccessorsCount,
            layoutsWithNominalDescriptorsCount,
            layoutsWithMetadataCachesCount,
            layoutsWithAssociatedTypeDescriptorsCount,
            layoutsWithVtableEntriesCount,
            layoutsWithWitnessTablesCount,
            metadataEntryCount,
            metadataAccessorEntryCount,
            nominalDescriptorEntryCount,
            metadataCacheEntryCount,
            associatedTypeDescriptorEntryCount,
            typeSourceEntryCount: typeSourceSummary.typeSourceEntryCount,
            sourceDemangledCount: typeSourceSummary.sourceDemangledCount,
            layoutsWithSourceDemangledTypesCount,
            uniqueSourceKindCount: typeSourceSummary.uniqueSourceKindCount,
            uniqueContextModuleCount: typeSourceSummary.uniqueContextModuleCount,
            uniqueDetailKindCount: typeSourceSummary.uniqueDetailKindCount,
            vtableEntryCount,
            witnessTableEntryCount,
            vtableAccessorEntryCount,
            vtableGetterEntryCount,
            vtableSetterEntryCount,
            vtableConstructorEntryCount,
            vtableDestructorEntryCount,
            vtableStaticMemberEntryCount,
            vtableAsyncEntryCount,
            vtableThrowingEntryCount,
            witnessAccessorCount,
            layoutsWithAccessorVtableEntriesCount,
            layoutsWithAsyncVtableEntriesCount,
            layoutsWithThrowingVtableEntriesCount,
            layoutsWithWitnessAccessorsCount,
            sourceKinds: typeSourceSummary.sourceKinds,
            contextModules: typeSourceSummary.contextModules,
            detailKinds: typeSourceSummary.detailKinds,
            moduleNames: moduleSummaries,
            typeNames: typeSummaries,
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
            hasTypeLayout: normalized !== null,
            resolved: normalized !== null,
            resolvedName: normalized === null ? null : normalized.name,
            resolvedModuleName: normalized === null ? null : normalized.moduleName,
            resolvedModuleBase: normalized === null ? null : normalized.moduleBase,
            hasName: normalized !== null && normalized.hasName === true,
            firstMetadataName: normalized === null ? null : normalized.firstMetadataName,
            lastMetadataName: normalized === null ? null : normalized.lastMetadataName,
            firstMetadataAccessorName: normalized === null ? null : normalized.firstMetadataAccessorName,
            lastMetadataAccessorName: normalized === null ? null : normalized.lastMetadataAccessorName,
            firstNominalDescriptorName: normalized === null ? null : normalized.firstNominalDescriptorName,
            lastNominalDescriptorName: normalized === null ? null : normalized.lastNominalDescriptorName,
            firstMetadataCacheName: normalized === null ? null : normalized.firstMetadataCacheName,
            lastMetadataCacheName: normalized === null ? null : normalized.lastMetadataCacheName,
            firstAssociatedTypeDescriptorName: normalized === null ? null : normalized.firstAssociatedTypeDescriptorName,
            lastAssociatedTypeDescriptorName: normalized === null ? null : normalized.lastAssociatedTypeDescriptorName,
            firstVtableMemberName: normalized === null ? null : normalized.firstVtableMemberName,
            lastVtableMemberName: normalized === null ? null : normalized.lastVtableMemberName,
            firstWitnessProtocolName: normalized === null ? null : normalized.firstWitnessProtocolName,
            lastWitnessProtocolName: normalized === null ? null : normalized.lastWitnessProtocolName,
            hasMetadata: normalized !== null && normalized.hasMetadata === true,
            hasMetadataAccessors: normalized !== null && normalized.hasMetadataAccessors === true,
            hasNominalDescriptors: normalized !== null && normalized.hasNominalDescriptors === true,
            hasMetadataCaches: normalized !== null && normalized.hasMetadataCaches === true,
            hasAssociatedTypeDescriptors: normalized !== null && normalized.hasAssociatedTypeDescriptors === true,
            hasVtableEntries: normalized !== null && normalized.hasVtableEntries === true,
            hasWitnessTables: normalized !== null && normalized.hasWitnessTables === true,
            metadataCount: normalized === null ? 0 : normalized.metadataCount,
            metadataAccessorCount: normalized === null ? 0 : normalized.metadataAccessorCount,
            nominalDescriptorCount: normalized === null ? 0 : normalized.nominalDescriptorCount,
            metadataCacheCount: normalized === null ? 0 : normalized.metadataCacheCount,
            associatedTypeDescriptorCount: normalized === null ? 0 : normalized.associatedTypeDescriptorCount,
            typeSourceEntryCount: normalized === null ? 0 : normalized.typeSourceEntryCount,
            sourceDemangledCount: normalized === null ? 0 : normalized.sourceDemangledCount,
            hasSourceDemangledTypes: normalized !== null && normalized.hasSourceDemangledTypes === true,
            uniqueSourceKindCount: normalized === null ? 0 : normalized.uniqueSourceKindCount,
            uniqueContextModuleCount: normalized === null ? 0 : normalized.uniqueContextModuleCount,
            uniqueDetailKindCount: normalized === null ? 0 : normalized.uniqueDetailKindCount,
            sourceKinds: normalized === null ? [] : normalized.sourceKinds,
            contextModules: normalized === null ? [] : normalized.contextModules,
            detailKinds: normalized === null ? [] : normalized.detailKinds,
            vtableCount: normalized === null ? 0 : normalized.vtableCount,
            witnessTableCount: normalized === null ? 0 : normalized.witnessTableCount,
            parsedVtableMemberCount: normalized === null ? 0 : normalized.parsedVtableMemberCount,
            vtableAccessorCount: normalized === null ? 0 : normalized.vtableAccessorCount,
            vtableGetterCount: normalized === null ? 0 : normalized.vtableGetterCount,
            vtableSetterCount: normalized === null ? 0 : normalized.vtableSetterCount,
            vtableModifyAccessorCount: normalized === null ? 0 : normalized.vtableModifyAccessorCount,
            vtableReadAccessorCount: normalized === null ? 0 : normalized.vtableReadAccessorCount,
            vtableConstructorCount: normalized === null ? 0 : normalized.vtableConstructorCount,
            vtableDestructorCount: normalized === null ? 0 : normalized.vtableDestructorCount,
            vtableSubscriptCount: normalized === null ? 0 : normalized.vtableSubscriptCount,
            vtableOperatorCount: normalized === null ? 0 : normalized.vtableOperatorCount,
            vtableClosureCount: normalized === null ? 0 : normalized.vtableClosureCount,
            vtableStaticMemberCount: normalized === null ? 0 : normalized.vtableStaticMemberCount,
            vtableClassMemberCount: normalized === null ? 0 : normalized.vtableClassMemberCount,
            vtableMutatingMemberCount: normalized === null ? 0 : normalized.vtableMutatingMemberCount,
            vtableAsyncCount: normalized === null ? 0 : normalized.vtableAsyncCount,
            vtableThrowingCount: normalized === null ? 0 : normalized.vtableThrowingCount,
            vtableDispatchThunkCount: normalized === null ? 0 : normalized.vtableDispatchThunkCount,
            uniqueVtableOwnerTypeCount: normalized === null ? 0 : normalized.uniqueVtableOwnerTypeCount,
            uniqueVtableMemberKindCount: normalized === null ? 0 : normalized.uniqueVtableMemberKindCount,
            uniqueVtableResultTypeCount: normalized === null ? 0 : normalized.uniqueVtableResultTypeCount,
            vtableOwnerTypes: normalized === null ? [] : normalized.vtableOwnerTypes,
            vtableMemberKinds: normalized === null ? [] : normalized.vtableMemberKinds,
            vtableResultTypes: normalized === null ? [] : normalized.vtableResultTypes,
            witnessAccessorCount: normalized === null ? 0 : normalized.witnessAccessorCount,
            witnessDemangledCount: normalized === null ? 0 : normalized.witnessDemangledCount,
            uniqueWitnessProtocolCount: normalized === null ? 0 : normalized.uniqueWitnessProtocolCount,
            uniqueWitnessSourceKindCount: normalized === null ? 0 : normalized.uniqueWitnessSourceKindCount,
            witnessProtocols: normalized === null ? [] : normalized.witnessProtocols,
            witnessSourceKinds: normalized === null ? [] : normalized.witnessSourceKinds,
            text: normalized === null ? '<null>' : normalized.text,
        };
    }
    case 'swift.types': {
        const moduleName = spec.moduleName === null || spec.moduleName === undefined ? null : String(spec.moduleName);
        const query = String(spec.query || '');
        const types = Swift.types(query, moduleName).map((typeInfo) => normalizeSwiftType(typeInfo));
        const sourceKinds = [];
        const moduleSummaries = [];
        const typeSummaries = [];
        const contextModules = [];
        const detailKinds = [];
        const moduleNames = new Set();
        const typeNames = new Set();
        let demangledCount = 0;
        for (const typeInfo of types) {
            moduleNames.add(typeInfo.moduleName);
            typeNames.add(typeInfo.name);
            if (typeInfo.hasSourceDemangledName) {
                demangledCount += 1;
            }
            let moduleSummary = moduleSummaries.find((item) => item.moduleName === typeInfo.moduleName);
            if (moduleSummary === undefined) {
                moduleSummary = {
                    moduleName: typeInfo.moduleName,
                    count: 0,
                    firstTypeName: typeInfo.name,
                    lastTypeName: typeInfo.name,
                    sourceDemangledCount: 0,
                };
                moduleSummaries.push(moduleSummary);
            }
            moduleSummary.count += 1;
            moduleSummary.lastTypeName = typeInfo.name;
            if (typeInfo.hasSourceDemangledName) {
                moduleSummary.sourceDemangledCount += 1;
            }
            let typeSummary = typeSummaries.find((item) => item.typeName === typeInfo.name);
            if (typeSummary === undefined) {
                typeSummary = {
                    typeName: typeInfo.name,
                    count: 0,
                    firstModuleName: typeInfo.moduleName,
                    lastModuleName: typeInfo.moduleName,
                    hasSourceDemangledName: false,
                };
                typeSummaries.push(typeSummary);
            }
            typeSummary.count += 1;
            typeSummary.lastModuleName = typeInfo.moduleName;
            if (typeInfo.hasSourceDemangledName) {
                typeSummary.hasSourceDemangledName = true;
            }
            if (typeInfo.hasContextModuleName) {
                let contextSummary = contextModules.find((item) => item.contextModuleName === typeInfo.contextModuleName);
                if (contextSummary === undefined) {
                    contextSummary = {
                        contextModuleName: typeInfo.contextModuleName,
                        count: 0,
                        firstTypeName: typeInfo.name,
                        lastTypeName: typeInfo.name,
                    };
                    contextModules.push(contextSummary);
                }
                contextSummary.count += 1;
                contextSummary.lastTypeName = typeInfo.name;
            }
            const detailKind = typeInfo.detailKind === null ? '<none>' : String(typeInfo.detailKind);
            let detailSummary = detailKinds.find((item) => item.detailKind === detailKind);
            if (detailSummary === undefined) {
                detailSummary = {
                    detailKind,
                    count: 0,
                    firstTypeName: typeInfo.name,
                    lastTypeName: typeInfo.name,
                };
                detailKinds.push(detailSummary);
            }
            detailSummary.count += 1;
            detailSummary.lastTypeName = typeInfo.name;
            const key = typeInfo.sourceKind === null ? '<none>' : String(typeInfo.sourceKind);
            let summary = sourceKinds.find((item) => item.sourceKind === key);
            if (summary === undefined) {
                summary = {
                    sourceKind: key,
                    count: 0,
                    firstTypeName: typeInfo.name,
                    lastTypeName: typeInfo.name,
                };
                sourceKinds.push(summary);
            }
            summary.count += 1;
            summary.lastTypeName = typeInfo.name;
        }
        return {
            kind: 'swift.types',
            moduleName,
            query,
            hasQuery: query.length !== 0,
            count: types.length,
            hasTypes: types.length !== 0,
            firstTypeName: types.length === 0 ? null : types[0].name,
            lastTypeName: types.length === 0 ? null : types[types.length - 1].name,
            firstModuleName: types.length === 0 ? null : types[0].moduleName,
            lastModuleName: types.length === 0 ? null : types[types.length - 1].moduleName,
            uniqueModuleCount: types.length === 0 ? 0 : moduleNames.size,
            uniqueTypeCount: types.length === 0 ? 0 : typeNames.size,
            uniqueSourceKindCount: sourceKinds.length,
            sourceDemangledCount: demangledCount,
            hasSourceDemangledTypes: demangledCount !== 0,
            uniqueContextModuleCount: contextModules.length,
            uniqueDetailKindCount: detailKinds.length,
            moduleNames: moduleSummaries,
            typeNames: typeSummaries,
            contextModules,
            detailKinds,
            sourceKinds,
            types,
            text: types.map((typeInfo) => typeInfo.text).join('\n'),
        };
    }
    case 'swift.type_kinds': {
        const kinds = Swift.typeKinds();
        const prefixes = [];
        let metadataKindCount = 0;
        let nominalKindCount = 0;
        let protocolKindCount = 0;
        let witnessKindCount = 0;
        let accessorKindCount = 0;
        let vtableKindCount = 0;
        for (const rawKind of kinds) {
            const kind = String(rawKind);
            const prefix = kind.indexOf('-') === -1 ? kind : kind.slice(0, kind.indexOf('-'));
            let summary = prefixes.find((item) => item.prefix === prefix);
            if (summary === undefined) {
                summary = {
                    prefix,
                    count: 0,
                    firstKind: kind,
                    lastKind: kind,
                };
                prefixes.push(summary);
            }
            summary.count += 1;
            summary.lastKind = kind;
            if (kind.indexOf('metadata') !== -1) {
                metadataKindCount += 1;
            }
            if (kind.indexOf('nominal') !== -1) {
                nominalKindCount += 1;
            }
            if (kind.indexOf('protocol') !== -1) {
                protocolKindCount += 1;
            }
            if (kind.indexOf('witness') !== -1) {
                witnessKindCount += 1;
            }
            if (kind.indexOf('accessor') !== -1) {
                accessorKindCount += 1;
            }
            if (kind.indexOf('vtable') !== -1) {
                vtableKindCount += 1;
            }
        }
        return {
            kind: 'swift.type_kinds',
            count: kinds.length,
            hasKinds: kinds.length !== 0,
            firstKind: kinds.length === 0 ? null : kinds[0],
            lastKind: kinds.length === 0 ? null : kinds[kinds.length - 1],
            uniquePrefixCount: prefixes.length,
            metadataKindCount,
            nominalKindCount,
            protocolKindCount,
            witnessKindCount,
            accessorKindCount,
            vtableKindCount,
            prefixes,
            kinds,
            text: kinds.join('\n'),
        };
    }
    case 'swift.types_of_kind': {
        const moduleName = spec.moduleName === null || spec.moduleName === undefined ? null : String(spec.moduleName);
        const sourceKind = String(spec.sourceKind || '');
        const query = String(spec.query || '');
        const types = Swift.typesOfKind(sourceKind, query, moduleName).map((typeInfo) => normalizeSwiftType(typeInfo));
        const sourceKinds = [];
        const moduleSummaries = [];
        const typeSummaries = [];
        const contextModules = [];
        const detailKinds = [];
        const moduleNames = new Set();
        const typeNames = new Set();
        let demangledCount = 0;
        for (const typeInfo of types) {
            moduleNames.add(typeInfo.moduleName);
            typeNames.add(typeInfo.name);
            if (typeInfo.hasSourceDemangledName) {
                demangledCount += 1;
            }
            let moduleSummary = moduleSummaries.find((item) => item.moduleName === typeInfo.moduleName);
            if (moduleSummary === undefined) {
                moduleSummary = {
                    moduleName: typeInfo.moduleName,
                    count: 0,
                    firstTypeName: typeInfo.name,
                    lastTypeName: typeInfo.name,
                    sourceDemangledCount: 0,
                };
                moduleSummaries.push(moduleSummary);
            }
            moduleSummary.count += 1;
            moduleSummary.lastTypeName = typeInfo.name;
            if (typeInfo.hasSourceDemangledName) {
                moduleSummary.sourceDemangledCount += 1;
            }
            let typeSummary = typeSummaries.find((item) => item.typeName === typeInfo.name);
            if (typeSummary === undefined) {
                typeSummary = {
                    typeName: typeInfo.name,
                    count: 0,
                    firstModuleName: typeInfo.moduleName,
                    lastModuleName: typeInfo.moduleName,
                    hasSourceDemangledName: false,
                };
                typeSummaries.push(typeSummary);
            }
            typeSummary.count += 1;
            typeSummary.lastModuleName = typeInfo.moduleName;
            if (typeInfo.hasSourceDemangledName) {
                typeSummary.hasSourceDemangledName = true;
            }
            if (typeInfo.hasContextModuleName) {
                let contextSummary = contextModules.find((item) => item.contextModuleName === typeInfo.contextModuleName);
                if (contextSummary === undefined) {
                    contextSummary = {
                        contextModuleName: typeInfo.contextModuleName,
                        count: 0,
                        firstTypeName: typeInfo.name,
                        lastTypeName: typeInfo.name,
                    };
                    contextModules.push(contextSummary);
                }
                contextSummary.count += 1;
                contextSummary.lastTypeName = typeInfo.name;
            }
            const detailKind = typeInfo.detailKind === null ? '<none>' : String(typeInfo.detailKind);
            let detailSummary = detailKinds.find((item) => item.detailKind === detailKind);
            if (detailSummary === undefined) {
                detailSummary = {
                    detailKind,
                    count: 0,
                    firstTypeName: typeInfo.name,
                    lastTypeName: typeInfo.name,
                };
                detailKinds.push(detailSummary);
            }
            detailSummary.count += 1;
            detailSummary.lastTypeName = typeInfo.name;
            const key = typeInfo.sourceKind === null ? '<none>' : String(typeInfo.sourceKind);
            let summary = sourceKinds.find((item) => item.sourceKind === key);
            if (summary === undefined) {
                summary = {
                    sourceKind: key,
                    count: 0,
                    firstTypeName: typeInfo.name,
                    lastTypeName: typeInfo.name,
                };
                sourceKinds.push(summary);
            }
            summary.count += 1;
            summary.lastTypeName = typeInfo.name;
        }
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
            firstModuleName: types.length === 0 ? null : types[0].moduleName,
            lastModuleName: types.length === 0 ? null : types[types.length - 1].moduleName,
            uniqueModuleCount: types.length === 0 ? 0 : moduleNames.size,
            uniqueTypeCount: types.length === 0 ? 0 : typeNames.size,
            uniqueSourceKindCount: sourceKinds.length,
            sourceDemangledCount: demangledCount,
            hasSourceDemangledTypes: demangledCount !== 0,
            uniqueContextModuleCount: contextModules.length,
            uniqueDetailKindCount: detailKinds.length,
            moduleNames: moduleSummaries,
            typeNames: typeSummaries,
            contextModules,
            detailKinds,
            sourceKinds,
            types,
            text: types.map((typeInfo) => typeInfo.text).join('\n'),
        };
    }
    case 'swift.method_owners': {
        const moduleName = spec.moduleName === null || spec.moduleName === undefined ? null : String(spec.moduleName);
        const query = String(spec.query || '');
        const owners = Swift.methodOwners(query, moduleName).map((typeInfo) => normalizeSwiftType(typeInfo));
        const sourceKinds = [];
        const ownerNames = [];
        const moduleSummaries = [];
        const contextModules = [];
        const detailKinds = [];
        const moduleNames = new Set();
        let demangledCount = 0;
        for (const owner of owners) {
            moduleNames.add(owner.moduleName);
            if (owner.hasSourceDemangledName) {
                demangledCount += 1;
            }
            let ownerSummary = ownerNames.find((item) => item.ownerName === owner.name);
            if (ownerSummary === undefined) {
                ownerSummary = {
                    ownerName: owner.name,
                    count: 0,
                    firstModuleName: owner.moduleName,
                    lastModuleName: owner.moduleName,
                    hasSourceDemangledName: false,
                };
                ownerNames.push(ownerSummary);
            }
            ownerSummary.count += 1;
            ownerSummary.lastModuleName = owner.moduleName;
            if (owner.hasSourceDemangledName) {
                ownerSummary.hasSourceDemangledName = true;
            }
            let moduleSummary = moduleSummaries.find((item) => item.moduleName === owner.moduleName);
            if (moduleSummary === undefined) {
                moduleSummary = {
                    moduleName: owner.moduleName,
                    count: 0,
                    firstOwnerName: owner.name,
                    lastOwnerName: owner.name,
                    sourceDemangledCount: 0,
                };
                moduleSummaries.push(moduleSummary);
            }
            moduleSummary.count += 1;
            moduleSummary.lastOwnerName = owner.name;
            if (owner.hasSourceDemangledName) {
                moduleSummary.sourceDemangledCount += 1;
            }
            if (owner.hasContextModuleName) {
                let contextSummary = contextModules.find((item) => item.contextModuleName === owner.contextModuleName);
                if (contextSummary === undefined) {
                    contextSummary = {
                        contextModuleName: owner.contextModuleName,
                        count: 0,
                        firstOwnerName: owner.name,
                        lastOwnerName: owner.name,
                    };
                    contextModules.push(contextSummary);
                }
                contextSummary.count += 1;
                contextSummary.lastOwnerName = owner.name;
            }
            const detailKind = owner.detailKind === null ? '<none>' : String(owner.detailKind);
            let detailSummary = detailKinds.find((item) => item.detailKind === detailKind);
            if (detailSummary === undefined) {
                detailSummary = {
                    detailKind,
                    count: 0,
                    firstOwnerName: owner.name,
                    lastOwnerName: owner.name,
                };
                detailKinds.push(detailSummary);
            }
            detailSummary.count += 1;
            detailSummary.lastOwnerName = owner.name;
            const key = owner.sourceKind === null ? '<none>' : String(owner.sourceKind);
            let summary = sourceKinds.find((item) => item.sourceKind === key);
            if (summary === undefined) {
                summary = {
                    sourceKind: key,
                    count: 0,
                    firstOwnerName: owner.name,
                    lastOwnerName: owner.name,
                };
                sourceKinds.push(summary);
            }
            summary.count += 1;
            summary.lastOwnerName = owner.name;
        }
        return {
            kind: 'swift.method_owners',
            moduleName,
            query,
            hasQuery: query.length !== 0,
            count: owners.length,
            hasOwners: owners.length !== 0,
            firstOwnerName: owners.length === 0 ? null : owners[0].name,
            lastOwnerName: owners.length === 0 ? null : owners[owners.length - 1].name,
            firstModuleName: owners.length === 0 ? null : owners[0].moduleName,
            lastModuleName: owners.length === 0 ? null : owners[owners.length - 1].moduleName,
            uniqueModuleCount: owners.length === 0 ? 0 : moduleNames.size,
            uniqueOwnerCount: ownerNames.length,
            uniqueSourceKindCount: sourceKinds.length,
            sourceDemangledCount: demangledCount,
            hasSourceDemangledOwners: demangledCount !== 0,
            uniqueContextModuleCount: contextModules.length,
            uniqueDetailKindCount: detailKinds.length,
            ownerNames,
            moduleNames: moduleSummaries,
            contextModules,
            detailKinds,
            sourceKinds,
            owners,
            text: owners.map((typeInfo) => typeInfo.text).join('\n'),
        };
    }
    case 'swift.type_methods': {
        const moduleName = spec.moduleName === null || spec.moduleName === undefined ? null : String(spec.moduleName);
        const query = String(spec.query || '');
        const methods = Swift.typeMethods(query, moduleName).map((symbol) => normalizeSwiftSymbol(symbol));
        const memberSummary = summarizeSwiftMembers(methods);
        const moduleNames = new Set();
        const moduleSummaries = [];
        const methodNames = [];
        let demangledCount = 0;
        for (const method of methods) {
            moduleNames.add(method.moduleName);
            if (method.hasDemangledName) {
                demangledCount += 1;
            }
            let moduleSummary = moduleSummaries.find((item) => item.moduleName === method.moduleName);
            if (moduleSummary === undefined) {
                moduleSummary = {
                    moduleName: method.moduleName,
                    count: 0,
                    firstMethodName: method.name,
                    lastMethodName: method.name,
                    demangledCount: 0,
                };
                moduleSummaries.push(moduleSummary);
            }
            moduleSummary.count += 1;
            moduleSummary.lastMethodName = method.name;
            if (method.hasDemangledName) {
                moduleSummary.demangledCount += 1;
            }
            let summary = methodNames.find((item) => item.methodName === method.name);
            if (summary === undefined) {
                summary = {
                    methodName: method.name,
                    count: 0,
                    firstModuleName: method.moduleName,
                    lastModuleName: method.moduleName,
                    hasDemangledName: false,
                };
                methodNames.push(summary);
            }
            summary.count += 1;
            summary.lastModuleName = method.moduleName;
            if (method.hasDemangledName) {
                summary.hasDemangledName = true;
            }
        }
        return {
            kind: 'swift.type_methods',
            moduleName,
            query,
            hasQuery: query.length !== 0,
            count: methods.length,
            hasMethods: methods.length !== 0,
            firstMethodName: methods.length === 0 ? null : methods[0].name,
            lastMethodName: methods.length === 0 ? null : methods[methods.length - 1].name,
            firstModuleName: methods.length === 0 ? null : methods[0].moduleName,
            lastModuleName: methods.length === 0 ? null : methods[methods.length - 1].moduleName,
            uniqueModuleCount: methods.length === 0 ? 0 : moduleNames.size,
            uniqueMethodCount: methodNames.length,
            demangledCount,
            hasDemangledMethods: demangledCount !== 0,
            parsedMemberCount: memberSummary.parsedMemberCount,
            accessorCount: memberSummary.accessorCount,
            getterCount: memberSummary.getterCount,
            setterCount: memberSummary.setterCount,
            constructorCount: memberSummary.constructorCount,
            destructorCount: memberSummary.destructorCount,
            subscriptCount: memberSummary.subscriptCount,
            operatorCount: memberSummary.operatorCount,
            closureCount: memberSummary.closureCount,
            staticMemberCount: memberSummary.staticMemberCount,
            classMemberCount: memberSummary.classMemberCount,
            mutatingMemberCount: memberSummary.mutatingMemberCount,
            asyncCount: memberSummary.asyncCount,
            throwingCount: memberSummary.throwingCount,
            dispatchThunkCount: memberSummary.dispatchThunkCount,
            uniqueOwnerTypeCount: memberSummary.uniqueOwnerTypeCount,
            uniqueMemberKindCount: memberSummary.uniqueMemberKindCount,
            uniqueResultTypeCount: memberSummary.uniqueResultTypeCount,
            ownerTypes: memberSummary.ownerTypes,
            memberKinds: memberSummary.memberKinds,
            resultTypes: memberSummary.resultTypes,
            moduleNames: moduleSummaries,
            methodNames,
            methods,
            text: methods.map((symbol) => symbol.text).join('\n'),
        };
    }
    case 'swift.methods': {
        const moduleName = spec.moduleName === null || spec.moduleName === undefined ? null : String(spec.moduleName);
        const typeName = String(spec.typeName || '');
        const methodQuery = String(spec.methodQuery || '');
        const methods = Swift.methods(typeName, methodQuery, moduleName).map((symbol) => normalizeSwiftSymbol(symbol));
        const memberSummary = summarizeSwiftMembers(methods);
        const moduleNames = new Set();
        const moduleSummaries = [];
        const methodNames = [];
        let demangledCount = 0;
        for (const method of methods) {
            moduleNames.add(method.moduleName);
            if (method.hasDemangledName) {
                demangledCount += 1;
            }
            let moduleSummary = moduleSummaries.find((item) => item.moduleName === method.moduleName);
            if (moduleSummary === undefined) {
                moduleSummary = {
                    moduleName: method.moduleName,
                    count: 0,
                    firstMethodName: method.name,
                    lastMethodName: method.name,
                    demangledCount: 0,
                };
                moduleSummaries.push(moduleSummary);
            }
            moduleSummary.count += 1;
            moduleSummary.lastMethodName = method.name;
            if (method.hasDemangledName) {
                moduleSummary.demangledCount += 1;
            }
            let summary = methodNames.find((item) => item.methodName === method.name);
            if (summary === undefined) {
                summary = {
                    methodName: method.name,
                    count: 0,
                    firstModuleName: method.moduleName,
                    lastModuleName: method.moduleName,
                    hasDemangledName: false,
                };
                methodNames.push(summary);
            }
            summary.count += 1;
            summary.lastModuleName = method.moduleName;
            if (method.hasDemangledName) {
                summary.hasDemangledName = true;
            }
        }
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
            firstModuleName: methods.length === 0 ? null : methods[0].moduleName,
            lastModuleName: methods.length === 0 ? null : methods[methods.length - 1].moduleName,
            uniqueModuleCount: methods.length === 0 ? 0 : moduleNames.size,
            uniqueMethodCount: methodNames.length,
            demangledCount,
            hasDemangledMethods: demangledCount !== 0,
            parsedMemberCount: memberSummary.parsedMemberCount,
            accessorCount: memberSummary.accessorCount,
            getterCount: memberSummary.getterCount,
            setterCount: memberSummary.setterCount,
            constructorCount: memberSummary.constructorCount,
            destructorCount: memberSummary.destructorCount,
            subscriptCount: memberSummary.subscriptCount,
            operatorCount: memberSummary.operatorCount,
            closureCount: memberSummary.closureCount,
            staticMemberCount: memberSummary.staticMemberCount,
            classMemberCount: memberSummary.classMemberCount,
            mutatingMemberCount: memberSummary.mutatingMemberCount,
            asyncCount: memberSummary.asyncCount,
            throwingCount: memberSummary.throwingCount,
            dispatchThunkCount: memberSummary.dispatchThunkCount,
            uniqueOwnerTypeCount: memberSummary.uniqueOwnerTypeCount,
            uniqueMemberKindCount: memberSummary.uniqueMemberKindCount,
            uniqueResultTypeCount: memberSummary.uniqueResultTypeCount,
            ownerTypes: memberSummary.ownerTypes,
            memberKinds: memberSummary.memberKinds,
            resultTypes: memberSummary.resultTypes,
            moduleNames: moduleSummaries,
            methodNames,
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

    if (trimmed.startsWith('objc.findClassProtocols ')) {
        const parsed = parseObjcClassProtocols(trimmed.slice('objc.findClassProtocols '.length));
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

    if (trimmed.startsWith('objc.findProtocolProtocols ')) {
        const parsed = parseObjcProtocolProtocols(trimmed.slice('objc.findProtocolProtocols '.length));
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

    if (trimmed.startsWith('objc.findProtocolMethods ')) {
        const parsed = parseObjcProtocolMethods(trimmed.slice('objc.findProtocolMethods '.length));
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

    if (trimmed.startsWith('objc.findProtocolProperties ')) {
        const parsed = parseObjcProtocolProperties(trimmed.slice('objc.findProtocolProperties '.length));
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

    if (trimmed.startsWith('native.loadCommands ')) {
        const moduleName = trimmed.slice('native.loadCommands '.length).trim();
        if (moduleName.length === 0) {
            throw new Error('native.loadCommands usage: native.loadCommands <module>');
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

    if (trimmed === 'native.hookenv' || trimmed === 'native.detectHookEnvironment') {
        return { kind: 'native.hook_environment' };
    }

    if (trimmed === 'pac.available') {
        return { kind: 'pac.available' };
    }

    if (trimmed === 'pac.arm64e' || trimmed === 'pac.isProcessArm64e') {
        return { kind: 'pac.arm64e' };
    }

    if (trimmed.startsWith('pac.image ')) {
        const moduleName = trimmed.slice('pac.image '.length).trim();
        if (moduleName.length === 0) {
            throw new Error('pac.image usage: pac.image <module>');
        }
        return { kind: 'pac.image', moduleName };
    }

    if (trimmed.startsWith('pac.isImageArm64e ')) {
        const moduleName = trimmed.slice('pac.isImageArm64e '.length).trim();
        if (moduleName.length === 0) {
            throw new Error('pac.isImageArm64e usage: pac.isImageArm64e <module>');
        }
        return { kind: 'pac.image', moduleName };
    }

    if (trimmed === 'pac.images' || trimmed === 'pac.arm64eImages') {
        return { kind: 'pac.images', filter: null };
    }

    if (trimmed.startsWith('pac.images ')) {
        const filter = trimmed.slice('pac.images '.length).trim();
        if (filter.length === 0) {
            throw new Error('pac.images usage: pac.images [filter]');
        }
        return { kind: 'pac.images', filter };
    }

    if (trimmed.startsWith('pac.arm64eImages ')) {
        const filter = trimmed.slice('pac.arm64eImages '.length).trim();
        if (filter.length === 0) {
            throw new Error('pac.arm64eImages usage: pac.arm64eImages [filter]');
        }
        return { kind: 'pac.images', filter };
    }

    if (trimmed.startsWith('pac.stripdata ')) {
        return {
            kind: 'pac.stripdata',
            address: trimmed.slice('pac.stripdata '.length),
        };
    }

    if (trimmed.startsWith('pac.stripData ')) {
        return {
            kind: 'pac.stripdata',
            address: trimmed.slice('pac.stripData '.length),
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

    if (trimmed === 'swift.typeKinds' || trimmed === 'swift.typeSourceKinds') {
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
