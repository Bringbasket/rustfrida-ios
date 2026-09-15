下面是一版可直接替换 `README.md` 的优化稿。重点是：把平台限制前置、按“快速开始 / 部署 / Controller / Runtime API / Hook 策略 / 注入 / 发布 / 边界”重组，并把大量历史性的“最近补了哪些字段”压缩为能力概览。更细的逐字段清单建议后续拆到 `docs/API_REFERENCE.md` 或 `CHANGELOG.md`。

---

# rustFrida iOS Branch

本分支只保留 iOS 越狱版实现。代码位于：

```text
ios-rustfrida/
├── common
├── controller
├── agent
├── quickjs-runtime
├── objc-api
└── native-api
```

> Android 版目录和根 workspace 已从该分支移除。

---

## 目录

- [平台支持](#平台支持)
- [快速开始](#快速开始)
- [部署与打包](#部署与打包)
- [Controller CLI](#controller-cli)
- [iOS Runtime 能力概览](#ios-runtime-能力概览)
- [Hook Backend 与策略](#hook-backend-与策略)
- [注入、Preflight 与 Spawn](#注入preflight-与-spawn)
- [JSON 输出与诊断](#json-输出与诊断)
- [CI 与发布](#ci-与发布)
- [已知边界与未完成项](#已知边界与未完成项)

---

## 平台支持

| 能力 | Linux / 通用主机 | Apple Host |
|---|---:|---:|
| `cargo test` | ✅ | ✅ |
| agent 打包 | ✅ | ✅ |
| `.deb` 生成 | ✅ | ✅ |
| `doctor-jailbreak.sh` | ✅ | ✅ |
| `deploy-agent-jailbreak.sh` | ✅ | ✅ |
| `install-agent-deb-jailbreak.sh` | ✅ | ✅ |
| controller `--list-images` | ❌ | ✅ |
| controller `--preflight-only` | ❌ | ✅ |
| controller `--inject-json` | ❌ | ✅ |
| controller `--command-json` | ❌ | ✅ |

说明：

- Linux 主机可做测试、agent 打包、`.deb` 生成、远端 doctor、部署和安装。
- Linux 主机不能执行 controller 的 dyld / Mach 注入 / preflight / runtime command 路径。
- 真机注入前体检、实际注入、一次性执行 runtime 命令，均需要 Apple host。
- Linux 上即使能编译出 controller CLI，相关能力也会返回 `unsupported`。

---

## 快速开始

```bash
cd ios-rustfrida
```

### Linux / 通用主机

```bash
# 单测
cargo test -p native-api --target x86_64-unknown-linux-gnu
cargo test -p objc-api --target x86_64-unknown-linux-gnu
cargo test -p quickjs-runtime --target x86_64-unknown-linux-gnu
cargo test -p agent --target x86_64-unknown-linux-gnu
cargo test -p controller --target x86_64-unknown-linux-gnu

# 越狱设备体检
scripts/doctor-jailbreak.sh root@iphone.local
scripts/doctor-jailbreak.sh --json root@iphone.local

# 部署 agent
scripts/deploy-agent-jailbreak.sh root@iphone.local
RUN_DOCTOR=json scripts/deploy-agent-jailbreak.sh root@iphone.local

# 打包 .deb
scripts/package-agent-deb.sh rootless
scripts/package-agent-deb.sh rootful

# 安装 .deb
scripts/install-agent-deb-jailbreak.sh root@iphone.local

# 打包发布产物
BUILD_DEB=1 scripts/package-artifacts.sh

# Apple cross build 检查
scripts/check-apple-cross-build.sh
```

### Apple Host

```bash
# Preflight
cargo run -p controller -- --pid 1234 --preflight-only
cargo run -p controller -- --name SpringBoard --preflight-only
cargo run -p controller -- --pid 1234 --preflight-only --preflight-json

# dyld 镜像
cargo run -p controller -- --list-images --list-images-json

# 注入
cargo run -p controller -- --pid 1234 --inject-json

# 单条命令
cargo run -p controller -- --pid 1234 --command "objc.classes UIView"
cargo run -p controller -- --pid 1234 --command "native.images UIKit" --command-json

# RPC
cargo run -p controller -- --pid 1234 --script rpc.js --command "rpccall add [20,22]"
cargo run -p controller -- --pid 1234 --script rpc.js --rpc-port 127.0.0.1:9191
curl http://127.0.0.1:9191/sessions
curl -X POST http://127.0.0.1:9191/rpc/1/add -d '[20,22]'
```

---

## 部署与打包

### 默认 agent 路径

| 场景 | 路径 |
|---|---|
| rootless | `/var/jb/usr/lib/libagent.dylib` |
| rootful | `/usr/lib/libagent.dylib` |
| 旧路径 | `/usr/lib/agent.dylib`，已废弃 |

如果设备是 rootful 或 agent 放在别处，启动时显式传入：

```bash
--agent-path <path>
```

### `.deb` 产物

常见命名：

```text
ios-rustfrida-agent_<version>_iphoneos-arm64_rootless.deb
ios-rustfrida-agent_<version>_iphoneos-arm64e_rootless.deb
ios-rustfrida-agent_<version>_iphoneos-arm_rootful.deb
```

安装选择：

- rootless 设备：优先 `..._iphoneos-arm64_rootless.deb`
- `iphoneos-arm64e` rootless 设备：优先 `..._iphoneos-arm64e_rootless.deb`
- rootful 设备：`..._iphoneos-arm_rootful.deb`

设备上安装：

```bash
dpkg -i <package>.deb
```

`scripts/install-agent-deb-jailbreak.sh` 会自动探测远端架构，并从 `dist/` 中选择匹配包。

### Doctor

```bash
scripts/doctor-jailbreak.sh <user@device> [remote-agent-path]
scripts/doctor-jailbreak.sh --json <user@device>
```

检查内容：

- rootless / rootful 布局
- agent 目录与文件
- legacy 文件名
- socket path 长度
- 常见 hook backend 文件
- agent 是否像 Mach-O 动态库
- 远端工具能否看见 `ios_agent_entry`

### Deploy

```bash
scripts/deploy-agent-jailbreak.sh <user@device>
```

默认推送 `libagent.dylib` 后自动执行 doctor。

```bash
RUN_DOCTOR=0    # 只推送，不体检
RUN_DOCTOR=json # 输出单个 deploy + doctor JSON
```

---

## Controller CLI

### Attach 目标

controller 支持：

```bash
--pid <PID>
--name <PROCESS_NAME>
--bundle-id <BUNDLE_ID>
--spawn
```

`--name` 与 `--pid` / `--bundle-id` / `--spawn` 互斥。Apple 端通过 libproc 枚举，并按 executable name、完整 path 或 basename 精确匹配；多命中、进程退出、PID 复用都会拒绝。非 Apple host 请使用 `--pid`。

### 常用命令

```bash
# Preflight
cargo run -p controller -- --pid 1234 --preflight-only
cargo run -p controller -- --name SpringBoard --preflight-only
cargo run -p controller -- --pid 1234 --preflight-only --preflight-json

# dyld 镜像
cargo run -p controller -- --list-images --list-images-json

# 注入 JSON
cargo run -p controller -- --pid 1234 --inject-json

# 单次 runtime 命令
cargo run -p controller -- --pid 1234 --command "objc.classes UIView"
cargo run -p controller -- --pid 1234 --command "native.images UIKit" --command-json

# RPC
cargo run -p controller -- --pid 1234 --script rpc.js --command "rpccall add [20,22]"
cargo run -p controller -- --pid 1234 --script rpc.js --rpc-port 127.0.0.1:9191
```

### HTTP RPC

`--rpc-port <PORT|ADDR>` 提供 Android 同名 HTTP 包装层：

```bash
GET  /health
GET  /sessions
POST /rpc/<session>/<method>
```

示例：

```bash
curl http://127.0.0.1:9191/sessions
curl -X POST http://127.0.0.1:9191/rpc/1/add -d '[20,22]'
```

支持：

- 有界并发 session registry
- 单调稳定 ID
- attach / detach 状态机
- 每 session 命令串行化
- 断开门控
- 后台 `ping` 健康探针自动回收
- transport failure 进入 registry reconcile / detach
- cleanup 可重试，连续失败达到上限后有界退出

`--server [--max-sessions N]` 支持动态：

```text
attach
spawn
list | sessions
use
detach
detachall
```

server `exit` 只有在本轮 detach 全部 clean 且 registry 为空时才关闭。

---

## iOS Runtime 能力概览

> README 只保留稳定能力概览。完整命令和字段清单建议放到 `docs/API_REFERENCE.md`。

### ObjC

支持：

- 类、selector、IMP、方法枚举
- 协议继承、协议方法、协议属性
- 属性、ivar、镜像、类链
- `classInfo / protocolInfo / methodInfo / propertyInfo / ivarInfo`
- `protocolMethodInfo / protocolPropertyInfo`
- `chooseSync / choose`
- `find*` 宽松匹配别名

常用：

```text
ObjC.classes([query])
ObjC.methods(className[, isClassMethod][, query])
ObjC.chooseSync(className[, options])
ObjC.choose(className, { onMatch, onComplete }[, options])
ObjC.findMethods(className, query[, isClassMethod])
ObjC.findMethodOwners(query[, isClassMethod])
ObjC.methodOwners(query[, isClassMethod])
ObjC.findClasses(query)
ObjC.protocols([query])
ObjC.classInfo(className[, isMetaClass])
ObjC.protocolInfo(protocolName)
ObjC.methodInfo(className, selectorName[, isClassMethod])
ObjC.propertyInfo(className, propertyName[, isClassProperty])
ObjC.ivarInfo(className, ivarName)
ObjC.classImage(className)
ObjC.methodImp(className, selectorName[, isClassMethod])
ObjC.selector(selectorName)
ObjC.selectorName(selector)
ObjC.objectClassName(object)
```

CLI 示例：

```text
objc.classes [filter]
objc.methods <class> [meta] [filter]
objc.methodImp <class> <selector> [meta]
objc.findMethodImp <class> <selector> [meta]
objc.methodInfo <class> <selector> [meta]
objc.classImage <class>
objc.methodImage <class> <selector> [meta]
objc.methodOwners <selector> [meta]
objc.findClasses <query>
objc.superclass <class>
objc.classChain <class>
objc.properties <class> [meta] [filter]
objc.propertyInfo <class> <property> [meta]
objc.ivars <class> [filter]
objc.ivarInfo <class> <ivar>
objc.protocols [filter]
objc.classConforms <class> <protocol>
objc.protocolConforms <protocol> <parent-protocol>
objc.classProtocols <class>
objc.protocolOwners <protocol> [filter]
objc.classExists <name>
objc.protocolExists <name>
objc.selector <name>
objc.protocolImage <protocol>
objc.classInfo <class> [meta]
objc.protocolInfo <protocol>
objc.protocolProtocols <protocol>
objc.protocolMethods <protocol> [required] [instance]
objc.protocolMethodInfo <protocol> <selector> [required] [instance]
objc.protocolProperties <protocol>
objc.protocolPropertyInfo <protocol> <property>
objc.selectorName <selector>
objc.objectClassName <object>
```

列表结果通常带结构化摘要，例如：

- `imagePathList / imagePaths`
- `uniqueSelectorCount / returnTypeNameList`
- `keywordSelectorCount / unarySelectorCount`
- `readonlyPropertyCount / strongPropertyCount`
- `uniqueKindCount / pointerIvarCount`
- owner 解析状态、顶层 `resolved*`、`has*`

### Swift

支持：

```text
Swift.demangle(symbolName)
Swift.protocols([query[, moduleName]])
Swift.protocolInfo(protocolName[, moduleName])
Swift.conformanceInfo(typeName, protocolName[, moduleName])
Swift.typeInfo(typeName[, moduleName])
Swift.methodInfo(typeName, methodName[, moduleName])
Swift.conformances(typeName[, moduleName])
Swift.metadata(typeName[, moduleName])
Swift.metadataInfo(typeName[, moduleName])
Swift.vtable(typeName[, moduleName])
Swift.vtableInfo(typeName, memberName[, moduleName])
Swift.witnessTable(query[, moduleName])
Swift.witnessTableInfo(typeName, protocolName[, moduleName])
Swift.typeLayout(typeName[, moduleName])
Swift.typeLayoutInfo(typeName[, moduleName])
Swift.types(query[, moduleName])
Swift.typeKinds()
Swift.typesOfKind(kind, query[, moduleName])
Swift.methodOwners(query[, moduleName])
Swift.typeMethods(query[, moduleName])
Swift.methods(typeName, methodQuery[, moduleName])
Swift.symbols(query[, moduleName])
Swift.symbolInfo(symbolName[, moduleName])
Swift.status() / Swift.capabilities() / Swift.lastError()
Swift.typeRepresentation(typeName)
Swift.objectRepresentation(typeName)
Swift.classifyAbiArgument(typeName) / Swift.abiArgument(typeName)
Swift.classifyAbiArguments(typeNames) / Swift.abiArguments(typeNames)
Swift.object(pointer[, metadata[, options]]) / Swift.metadataOf(object)
Swift.thinFunction(...) / Swift.invoke(...) / Swift.call(...)
```

CLI 示例：

```text
swift.types <query>
swift.types <module> -- <query>
swift.protocolInfo <protocol>
swift.protocolInfo <module> -- <protocol>
swift.conformanceInfo <type> <protocol>
swift.conformanceInfo <module> -- <type> <protocol>
swift.typeInfo <type>
swift.typeInfo <module> -- <type>
swift.methodInfo <type> <method>
swift.methodInfo <module> -- <type> <method>
swift.symbolInfo <symbol>
swift.symbolInfo <module> -- <symbol>
swift.protocols [query]
swift.protocols <module> -- <query>
swift.conformances <type>
swift.conformances <module> -- <type>
swift.metadata <type>
swift.metadata <module> -- <type>
swift.metadataInfo <type>
swift.metadataInfo <module> -- <type>
swift.vtable <type>
swift.vtable <module> -- <type>
swift.vtableInfo <type> <member>
swift.vtableInfo <module> -- <type> <member>
swift.witnessTable <type|protocol>
swift.witnessTable <module> -- <type|protocol>
swift.witnessTableInfo <type> <protocol>
swift.witnessTableInfo <module> -- <type> <protocol>
swift.typeLayout <type>
swift.typeLayout <module> -- <type>
swift.typeLayoutInfo <type>
swift.typeLayoutInfo <module> -- <type>
swift.typeKinds
swift.typeSourceKinds
swift.methodOwners <method>
swift.methodOwners <module> -- <method>
swift.typesOfKind <kind> <query>
swift.typesOfKind <module> -- <kind> <query>
swift.typeMethods <type>
swift.typeMethods <module> -- <type>
swift.methods <type> <method>
swift.methods <module> -- <type> <method>
```

Swift 查询支持模块限定、basename、大小写不敏感、部分名称、成员名子串等宽松匹配。单项查询通常提供：

- `resolved* / has*`
- `moduleBase`
- `sourceSymbolName / sourceOffsetHex / sourceDemangledName`
- `qualifiedName / signature / contextModuleName / detailKind`
- vtable / witness / type layout 的 accessor、ctor、async、throws 等摘要

### Native / Module

支持：

```text
Native.base(moduleName)
Native.findBase(moduleName)
Native.images([filter])
Native.export(moduleNameOrNull, symbolName)
Native.mainImage()
Native.findMainImage()
Native.image(address)
Native.findImage(address)
Native.symbol(address)
Native.findSymbol(address)
Native.findSymbols(query[, moduleName])
Native.symbols(query[, moduleName])
Native.findSymbolInfo(symbolName[, moduleName])
Native.symbolInfo(symbolName[, moduleName])
Native.findImageInfo(moduleName)
Native.imageInfo(moduleName)
Native.findExports(moduleName[, query])
Native.exports(moduleName[, query])
Native.findExportInfo(moduleName, symbolName)
Native.exportInfo(moduleName, symbolName)
Native.findDependencies(moduleName[, query])
Native.dependencies(moduleName[, query])
Native.findDependencyInfo(moduleName, pathOrName)
Native.dependencyInfo(moduleName, pathOrName)
Native.findEncryptionInfo(moduleName)
Native.encryptionInfo(moduleName)
Native.findEntryPoint(moduleName)
Native.entryPoint(moduleName)
Native.findDyldInfo(moduleName)
Native.dyldInfo(moduleName)
Native.findLinkedit(moduleName)
Native.linkedit(moduleName)
Native.findFunctionStarts(moduleName)
Native.functionStarts(moduleName)
Native.findCodeSignature(moduleName)
Native.codeSignature(moduleName)
Native.findDataInCode(moduleName)
Native.dataInCode(moduleName)
Native.findExportsTrie(moduleName)
Native.exportsTrie(moduleName)
Native.findChainedFixups(moduleName)
Native.chainedFixups(moduleName)
Native.findSourceVersion(moduleName)
Native.sourceVersion(moduleName)
Native.findBuildVersion(moduleName)
Native.buildVersion(moduleName)
Native.findDylinker(moduleName)
Native.dylinker(moduleName)
Native.findInstallName(moduleName)
Native.installName(moduleName)
Native.findUuid(moduleName)
Native.uuid(moduleName)
Native.findRpaths(moduleName[, query])
Native.rpaths(moduleName[, query])
Native.findRpathInfo(moduleName, path)
Native.rpathInfo(moduleName, path)
Native.findImports(moduleName[, query])
Native.imports(moduleName[, query])
Native.findImportInfo(moduleName, symbolName)
Native.importInfo(moduleName, symbolName)
Native.findSegments(moduleName)
Native.segments(moduleName)
Native.findSegmentInfo(moduleName, segmentName)
Native.segmentInfo(moduleName, segmentName)
Native.findSections(moduleName)
Native.sections(moduleName)
Native.findSectionInfo(moduleName, segmentName, sectionName)
Native.sectionInfo(moduleName, segmentName, sectionName)
Native.findLoadCommands(moduleName)
Native.loadCommands(moduleName)
Native.findLoadCommandInfo(moduleName, commandOrIndex)
Native.loadCommandInfo(moduleName, commandOrIndex)
```

`Module` 支持：

```text
Module.enumerateExports
Module.enumerateImports
Module.enumerateSymbols
Module.enumerateRanges
Module.load(path)  // Apple target；handle 按 QuickJS runtime 清理
```

CLI 示例：

```text
native.base <module>
native.findBase <module>
native.imageInfo <module>
native.export <symbol>
native.export <module> -- <symbol>
native.exports <module>
native.exports <module> -- <query>
native.exportInfo <module> -- <symbol>
native.dependencies <module>
native.dependencies <module> -- <query>
native.dependencyInfo <module> -- <path-or-name>
native.encryptionInfo <module>
native.entryPoint <module>
native.dyldInfo <module>
native.linkedit <module>
native.functionStarts <module>
native.codeSignature <module>
native.dataInCode <module>
native.exportsTrie <module>
native.chainedFixups <module>
native.sourceVersion <module>
native.buildVersion <module>
native.dylinker <module>
native.installName <module>
native.uuid <module>
native.rpaths <module>
native.rpaths <module> -- <query>
native.rpathInfo <module> -- <path>
native.imports <module>
native.imports <module> -- <query>
native.importInfo <module> -- <symbol>
native.loadcmds <module>
native.loadCommands <module>
native.loadCommandInfo <module> -- <name|cmd|index>
native.sections <module>
native.sectionInfo <module> -- <segment> <section>
native.segments <module>
native.segmentInfo <module> -- <segment>
native.symbolInfo <symbol>
native.symbolInfo <module> -- <symbol>
native.symbols <query>
native.symbols <module> -- <query>
native.images [filter]
native.mainImage
native.findMainImage
native.instrumentation
native.image <address>
native.findImage <address>
native.symbol <address>
native.findSymbol <address>
native.detectHookEnvironment
```

Mach-O load command raw 值来自 `native-api/src/macho_load_commands.rs`，保留 `LC_REQ_DYLD` 高位并使用 exact raw 比较。`LC_MAIN / LC_SOURCE_VERSION / LC_BUILD_VERSION / LC_FUNCTION_STARTS / LC_DYLD_EXPORTS_TRIE / LC_DYLD_CHAINED_FIXUPS` 等旧错位值已修正。

### Memory / NativePointer

支持：

```text
Memory.alloc
Memory.allocUtf8String
Memory.protect
Memory.flushCodeCache
Memory.writeBytes
NativePointer#read*
NativePointer#write*
NativePointer#writeBytes
NativePointer#protect
NativePointer#flushCodeCache
```

`Memory.writest / NativePointer#writest` 在 iOS 上明确返回 Android RECOMP-only unsupported。

分配按 QuickJS runtime 隔离，runtime cleanup 时统一释放。Apple 写入会按 Mach VM region 查询、临时改权、失败回滚并恢复原权限。

### NativeFunction / Interceptor / Native Hook

支持：

```text
new NativeFunction(address, returnType, argumentTypes)
hookNative(target, callbackPtr, userData?, mode?)
attachNative(target, callbackPtr, userData?, mode?)
attachNative(target, { onEnter?, onLeave?, data?, mode? })
Interceptor.attach
Interceptor.flush()
Hook.NORMAL / Hook.WXSHADOW / Hook.RECOMP
recompHook(ptr, callback)
diagAllocNear(ptr)
```

`NativeFunction` 支持：

- 整数
- bool
- pointer
- float
- double

结构体 / 数组按值、variadic 显式 unsupported。

`Interceptor.attach` 支持：

- `onEnter(args)`
- `onLeave(retval)`
- 共享 invocation `this`
- `retval.replace / toInt32 / toUInt32 / toString`
- thread-local invocation 栈处理递归

`Hook.RECOMP` / `recompHook()` 在 iOS 上明确返回 Android-only unsupported。`diagAllocNear()` 返回 iOS ARM64 hook engine 兼容诊断。

### Stalker

支持：

```text
Stalker.capabilities()
Stalker.status()
Stalker.info()
Stalker.functionLevelStatus()
Stalker.functionLevelStop()
Stalker.follow()
Stalker.pauseThread()
Stalker.resumeThread()
Stalker.unfollow()
Stalker.installCallout(thread, target[, stealth])
Stalker.transform()
Stalker.transformBasicBlock()
Stalker.planTargetThreadBlock()
Stalker.planTargetThreadRewrite()
Stalker.prepareTargetThreadRewrite()
Stalker.preflightTargetThreadRewrite()
Stalker.commitTargetThreadRewrite()
Stalker.generateEvents()
Stalker.recordBlock()
Stalker.relocate()
Stalker.layoutCodeCache()
Stalker.emitCodeCache()
Stalker.materializeCodeCache()
Stalker.finalizeCodeCache()
Stalker.executeCodeCache()
```

关键边界：

- `installCallout()` 安装 native ARM64 hook-engine callout，返回句柄含 `detach()`。
- 当前 callout 是函数级 `Call` / `Ret` 事件，不是指令级 transformer。
- `prepareTargetThreadRewrite()` 绑定 followed thread，并拥有 finalized RX code-cache transaction。
- 目标重写会在最后一个 relocated instruction 掉出时追加 `B sourceEnd`；terminal `B/BR/RET` 不需要 continuation。
- `BL/BLR` 因 LR preservation 未实现而拒绝。
- `preflightTargetThreadRewrite()` 报告 commit blockers，不改变 cache 或目标内存。
- `commitTargetThreadRewrite()` 组合 suspend、quiescence、source snapshot 验证、4-byte ARM64 entry branch、icache flush、resume 和 rollback owner。
- 普通 layout / emission / materialization 输出语义保持不变。
- 剩余边界：`BL/BLR` LR preservation、生产 transformer/callout、自动 instruction event backend、Apple 真机验收。

### CModule

支持：

```text
CModule(source[, symbols])
CModule.capabilities()
CModule.status()
CModule.info()
CModule.lastError()
```

Apple backend 已接入：

- TinyCC 编译
- Mach-O linker
- `MAP_JIT` executable mapping
- imports / exports
- `findSymbol`
- finalizer
- `dropMetadata`

已验证：

- ARM64 macOS host：TinyCC 编译、executable mapping、导出执行与释放。
- ARM64 iOS Simulator：CModule + `NativeFunction` 调用返回 `42`。

仍需验收：

- 物理设备 `MAP_JIT` / W^X 行为。
- Linux 普通构建继续按平台报告 `unavailable`。

### Process / File / RPC

`Process` 支持只读 API：

```text
Process.id / arch / platform / pageSize / pointerSize
Process.codeSigningPolicy / mainModule
Process.enumerateModules / findModuleByName / getModuleByName
Process.findModuleByAddress / getModuleByAddress
Process.enumerateRanges / findRangeByAddress / getRangeByAddress
Process.enumerateMallocRanges
Process.getCurrentDir / getHomeDir / getTmpDir
Process.getCurrentThreadId / isDebuggerAttached / enumerateThreads
```

`File` 支持：

```text
new File(filePath, mode)
File#tell / seek / readBytes / readText / readLine / write / flush / close
File.readAllBytes / readAllText / writeAllBytes / writeAllText
File.SEEK_SET / File.SEEK_CUR / File.SEEK_END
```

RPC 支持：

```text
rpc.exports = { method() { ... } }
rpc.export(name, fn)
rpccall <method> [args-json]
```

controller HTTP RPC 支持：

```text
GET  /health
GET  /sessions
POST /rpc/<session>/<method>
```

### Android 兼容探测层

为了兼容 Android 脚本的能力探测，iOS runtime 提供：

```text
Java.available / Java.status() / Java.lastError()
Jni.status / Jni.info / Jni.lastError
qbdi.status / qbdi.info / qbdi.methods / qbdi.lastError
Hook.NORMAL / Hook.WXSHADOW / Hook.RECOMP
```

这些入口在 iOS 上的语义：

- `Java.available = false`
- `Jni.available = false`
- QBDI VM 方法抛 unsupported
- `Hook.RECOMP` / `recompHook()` 抛 Android-only unsupported
- `diagAllocNear()` 返回 iOS ARM64 hook engine 兼容诊断

目标：让 Android 脚本先做能力探测，不因全局对象缺失直接失败。

---

## Hook Backend 与策略

### 支持探测的 backend

- ElleKit
- Substrate
- Substitute
- libhooker

文件系统探测同时覆盖 rootful 和 rootless 常见路径前缀，包括 `/usr/lib` 和 `/var/jb/...`。

### 策略

环境变量：

```bash
IOS_RUSTFRIDA_HOOK_POLICY=warn
IOS_RUSTFRIDA_HOOK_POLICY=deny-external-loaded
IOS_RUSTFRIDA_HOOK_POLICY=query-only-external-loaded
IOS_RUSTFRIDA_HOOK_POLICY=query-only
```

行为：

| 策略 | 行为 |
|---|---|
| `warn` | 命中外部 backend 时继续，但提示风险 |
| `deny-external-loaded` | 命中外部 backend 时进入 `cleanup-only`，允许注入会话和 `status/stop`，拒绝查询和安装 |
| `query-only-external-loaded` / `query-only` | 允许注入、查询、`status/stop`，禁止 `trace/stalker/jhook/shook/hfl` 安装路径 |

如果同一进程同时命中多个已加载外部 backend，即使 `hook_policy=warn`，也会自动降级到 query-only，避免在未实现多 backend 共存层时做 inline install。

### `native.hookenv` / `Native.detectHookEnvironment()`

返回内容包括：

- backend / warning
- 当前 `hook_policy` 建议动作
- `allowed` 与 `inlineHooksAllowed`
- `conflictState / riskLevel`
- `baseCommandMode / effectiveCommandMode / commandMode`
- `preferredPath`
- `autoDowngradedToQueryOnly / autoDowngradeReason`
- `loadedBackendCount / loadedExternalBackendCount / filesystemOnlyBackendCount`
- `loadedImageCount / filesystemPathCount`
- `coexistenceLayerAvailable`
- `singleExternalBackendLoaded / multipleExternalBackendsLoaded`
- 能力位：`bootstrapInjectionAllowed / queryCommandsAllowed / hookInstallCommandsAllowed / hookStatusCommandsAllowed / hookStopCommandsAllowed`
- `recommendedActions`
- `nextAction / nextStep / activeStep`
- `commandTemplates / commandJsonTemplates`
- `backendMatrix`
- `automation`
- `coexistence`
- `backendAdaptation`

自动化脚本可直接读取 `nextActionKey / nextActionCommand / nextActionCommandJsonTemplate` 等字段，而不必遍历整个 action 数组。

---

## 注入、Preflight 与 Spawn

### Mach 注入

现状：

- 注入链路会回读远程 bootstrap 状态。
- `IOS_RUSTFRIDA_BOOTSTRAP_WAIT_MS` 控制轮询等待时长，`0` 表示关闭等待。
- Mach bootstrap 远程内存拆成代码段和参数/状态段，分别走 `RX` / `RW`，不再依赖单块 `RWX`。
- 远程 Mach 内存按页对齐申请，`mach_vm_protect` 带降级处理。
- controller / dry-run 输出区分“实际使用字节数”和“页对齐后的实际分配字节数”。
- 注入 trace / dry-run 输出带目标进程是否 `arm64e`。
- 如果目标进程是 `arm64e` 且线程 bootstrap 只能退化到 `pthread_create`，默认拒绝；强制 fallback 需：

```bash
IOS_RUSTFRIDA_ALLOW_ARM64E_PTHREAD_FALLBACK=1
```

- 注入 trace / bootstrap summary 打印 `thread_bootstrap_kind`。
- controller 在打印 loader symbols 时，对 `thread-bootstrap` 符号补 `kind=...`。
- 正式远程写入前会执行目标 preflight。

### Preflight

`--preflight-only` 输出 plan + preflight 后退出。

`--preflight-only --preflight-json` 输出结构化 JSON，包含：

```text
environment
doctor
plan
preflight
```

目标 preflight 包含：

- 目标是否 `arm64e`
- thread bootstrap 模式
- thread bootstrap 地址是否 canonical
- 目标 dyld 镜像摘要
- 主镜像路径 / 基址
- 当前镜像总数
- `targetImages`
- `loaderSymbolChecks`
- rebased loader symbol 是否在目标镜像列表中找到模块
- `address == image.base + offset` 是否成立

`doctor` 单独收集常见本地/配置问题：

- agent 路径布局
- 是否还在用旧 `agent.dylib`
- socket path 是否接近 Darwin 长度限制
- bootstrap script 是否可读
- 本地/目标 hook strategy 是否挡住注入

### `--inject-json`

输出：

```text
environment
plan
preflight
trace
handshake
doctor
diagnostics
```

失败时尽量保留 `environment / plan / preflight`，并补：

```text
diagnostics.phase
diagnostics.code
diagnostics.hints
diagnostics.failedStep
diagnostics.hook
```

`handshake.stage` 会标出：

```text
awaiting-hello
awaiting-ping
awaiting-hook-environment
awaiting-jsinit
awaiting-loadjs
completed
```

`handshake.steps` 标记：

```text
hello
ping
hookEnvironment
jsInit
loadJs
```

状态：

```text
pending / succeeded / skipped / failed
```

### Spawn

spawn 模式通过 `controller/src/suspended_spawn.rs` 持有生命周期：

```text
Suspending
Suspended
Running
Terminating
Terminated
```

规则：

- 未恢复时任一步失败都会终止目标。
- 注入、agent handshake、`JsInit/LoadJs` 完成后才恢复。
- Apple executable 后端使用 `POSIX_SPAWN_START_SUSPENDED`。
- Linux host 用 fork-stop-exec 覆盖状态机测试。
- Simulator bundle-id 启动只使用 `xcrun simctl launch --wait-for-debugger`，并校验进程确实处于暂停状态。
- 物理设备要求 v2 `runtime-dynamic` FrontBoard/scene provider 在 `before-first-user-instruction` 阶段交付 gate。
- 状态严格校验 `held/released/terminated`。
- bundle suspended 协议绑定 bundle、PID、provider 和 gate ID。
- resume 后必须收到 provider 的 `released` 确认。
- 失败、超时或未交付状态会终止目标。
- controller 已移除启动后 `SIGSTOP` 伪装和旧 helper 兼容回退。

---

## JSON 输出与诊断

### `--command-json`

输出单个 JSON：

```text
ok
command
kind
payload
payloadJson
items
error
logs
```

会静默完成握手和可选 bootstrap script，不再把 plan / trace / hello/ping 文本混到命令结果前。

如果命令前阶段失败，也会返回结构化错误 JSON，并附带：

```text
hook
environment
doctor
plan
preflight
trace
diagnostics
handshake
```

### Hook policy 拦截错误

command 前置 hook policy 拦截错误带稳定标记：

```text
hook-effective-blocked actionKey=<...> commandGroup=<...> blockedBy=<none|controller|target|both> commandMode=<...> baseCommandMode=<...> effectiveCommandMode=<...> autoDowngradedToQueryOnly=<true|false> autoDowngradeReason=<...> coexistenceMode=<...> backendPressure=<...> fallbackActionKey=<...> fallbackStepId=<...> fallbackCommand=<...> fallbackPhase=<...>
```

`diagnostics.code` 映射：

```text
controller-hook-policy-blocked
target-hook-policy-blocked
both-hook-policies-blocked
```

### `payloadJson`

对以下 runtime 查询命令，`--command-json` 会尽量回传稳定 `payloadJson`：

```text
objc.*
native.*
pac.*
swift.*
```

里面通常带：

```text
count
classes
methods
images
symbols
types
report
text
```

列表和嵌套集合通常补：

```text
has*
first*
last*
resolved*
```

单值查询通常补：

```text
resolved*
has*
```

### 控制命令 JSON

对以下命令，`--command-json` 也会尽量回传结构化 `payloadJson`：

```text
hfl
jhook
shook
trace
stalker
```

常见字段：

```text
action
kind
target
count
key
moduleName
selectorName
resolvedLabel
targetAddress
filter
replacedCount
```

`*.status` 会补当前 active state 和 target 元数据。`*.stop` 会带回被回收的 key / target。`trace.stop / stalker.stop` 会带实际 detach 计数。

---

## CI 与发布

GitHub Actions 需要放在仓库根目录：

```text
.github/workflows/
```

`ios-rustfrida/.github/workflows/` 里的文件仅作子 workspace 镜像参考，真正触发以根目录 workflow 为准。

### 手动打包 workflow

GitHub Actions 里可手动运行：

```text
ios-rustfrida-package
```

它会在 macOS runner 上构建 agent/controller，并上传：

```text
ios-rustfrida-package-bundles
```

默认产物包括：

```text
ios-rustfrida-agent-aarch64-apple-ios.tar.gz
ios-rustfrida-controller-<host-triple>.tar.gz
ios-rustfrida-agent_<version>_iphoneos-arm64_rootless.deb
ios-rustfrida-agent_<version>_iphoneos-arm64e_rootless.deb
ios-rustfrida-agent_<version>_iphoneos-arm_rootful.deb
```

根目录 release workflow 会在 macOS runner 上补装 `dpkg`，并把 tarball 和 `.deb` 一起作为 GitHub Release asset 输出。

### 已知 CI 验证

- CI run `30764666695`：
  - ARM64 macOS host 测试通过当前进程生产 `find_image_*` 解析链。
  - QuickJS fixture 断言 `cmdHex / cmdBaseHex / isReqDyld / reqDyldCommandCount`。
- CI run `30805082247`：
  - Linux `576 passed`
  - ARM64 macOS `518 passed`
  - Simulator hosted XCTest `1 passed`
  - 通过 `dlopen/dlsym` 调用 `ios_agent_entry`
  - 验证 `HELLO / Ping / JsInit / LoadJs / RPC / structured RPC / structured JsEval / CModule / Exit`
  - 嵌套 object/array 作为 JSON 结构跨 agent frame 保真
  - CModule 与标量 RPC 均返回 `42`
  - entry 最终返回 `0`

---

## 已知边界与未完成项

iOS 功能仍处于持续迁移状态，不应视为与 Android 版完全对齐。

当前已完成或基本完成：

- ObjC 类 / selector / IMP / 方法枚举
- 协议继承 / 属性查询
- Swift 符号查找
- PAC 查询
- dyld 镜像枚举
- 基础 hook 环境探测
- File / RPC / Process 只读 API
- Module enumerate / load
- NativeFunction 标量调用
- Interceptor.attach / hookNative / attachNative
- CModule macOS host 与 iOS Simulator 路径
- Stalker bounded static transform / event generation
- ObjC typed property accessor、retain/copy/weak 生命周期、exception containment、动态类注册、有界 heap enumeration 核心
- Module 本地/非导出 nlist 与 import slot/address 解析
- Swift thin ABI 子集
- Simulator agent/CModule runtime
- `simctl --wait-for-debugger` gate
- controller remote lease adoption/release/uninstall/cleanup API 源码/静态接线
- agent-owned external-hook command/receipt 状态源码/静态接线

仍需 Apple host / 真机验收：

- 完整越狱注入
- arm64e / PAC
- ObjC zeroing weak
- ObjC automatic/manual KVO notification 与 super forwarding
- hook callback / detach
- 第三方 backend 真实运行
- 物理设备 bundle/scene 的 v2 runtime-dynamic FrontBoard/scene provider 与真机 gate
- Swift full object ABI 与泛型 / 隐藏 ABI
- 真正的 target-thread 指令级 Stalker backend
- 物理设备上的 CModule `MAP_JIT` / W^X 运行验收
- controller remote lease 的 Apple runtime / 真机验收和生产 token 回收时序

明确保持的边界：

- 四种已确认 external backend ABI 没有公开 native uninstall。
- 当前保持明确的 `NativeUninstallUnavailable` 边界，不把它写成已实现能力。
- `Java` / `Jni` / `QBDI` 在 iOS 上是兼容探测层，不是实际 Android 运行时。
- `Hook.RECOMP` / `recompHook()` / `writest` 在 iOS 上明确 unsupported。
- Swift 泛型、async、throws、隐藏上下文、间接返回和 full object ABI 仍会明确拒绝。
- Stalker `BL/BLR` LR preservation、生产 transformer/callout、自动 instruction event backend 仍待完成。
- CModule Linux 普通构建继续按平台报告 `unavailable`。

---

## 文档维护建议

原 README 中大量“最近补上的字段 / alias / 摘要”内容更适合放在：

```text
CHANGELOG.md
docs/API_REFERENCE.md
docs/JSON_SCHEMA.md
```

README 建议只保留：

- 快速开始
- 平台支持
- 核心命令
- 稳定 API 概览
- Hook 策略
- 注入流程
- 已知边界

这样后续新增字段时，不必让 README 继续膨胀。
