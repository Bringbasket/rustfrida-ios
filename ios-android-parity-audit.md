# iOS / Android 功能对齐可执行审计

## 1. 结论

本审计直接搜索两端代码、API 注册点和 host/agent 调用链，不以 README 声明作为完成依据。结论如下：

1. iOS 已具备静态闭合的 PID Attach 主链：Mach bootstrap、远程内存写入、远程线程启动、目标内 `dlopen`/entry 调用、Unix socket 握手、QuickJS 初始化、脚本/命令/RPC 分发。该结论是 `complete（静态）`，不是 Apple 真机运行证明。
2. `File`、`Process`、`rpc.exports` 的 iOS API 表面已达到 Android 基线，并已通过 Linux workspace 测试和 Apple target 交叉检查；结构化直接求值与嵌套 RPC 还通过了 ARM64 iOS Simulator agent runtime 验收，物理设备行为仍需单独验收。
3. `Memory`、`Module`、`Interceptor`、按进程名 Attach、`NativeFunction` 标量 ABI、native pointer hook、suspended spawn 生命周期、multi-session/server/断线回收均已静态接线。Simulator `simctl --wait-for-debugger` bundle gate、Stalker bounded static transform/event generation、ObjC typed/custom/atomic/KVO property 与有界 heap choose、Swift ABI 分类及 object ownership/dispose/metadata identity 验证边界、CModule Apple TinyCC/Mach-O backend 和外部 adapter FFI execution boundary 也已接线；其中 CModule JIT 已在 ARM64 macOS host 和 ARM64 iOS Simulator 完成真实运行验收。agent-owned external-hook command/receipt 路径以及 controller remote lease 的远程 command/receipt 转移与产品级调用链已完成源码/静态接线，待 Apple runtime/真机验收。剩余边界是物理设备 FrontBoard/scene provider、真正的 target-thread 指令级 Stalker、Swift full object ABI、物理设备的 CModule `MAP_JIT`/W^X 行为和 controller remote lease 的 Apple runtime/真机行为。
4. Java/ART、JNI、zygote/USAP、SELinux/property profile、eBPF `watch-so`、Android RECOMP 和当前 iOS QBDI 决策属于平台限定或明确的 `unsupported-by-design`，不应伪装成已完成，也不应默认列入 iOS 必做 backlog。
5. Android 同名 `--rpc-port` HTTP RPC 已接到有界 `SessionRegistry`：稳定 ID、并发门控、detach 生命周期、Unix frame、HTTP parser/router 和测试均已闭合；单 session HTTP 入口通过 agent `Ping` 做 liveness，transport failure 进入 reconcile/detach，cleanup 失败保留可重试 session/transport，并以有界重试后确定性退出避免永久盲 park。另有 `--server [--max-sessions N]` 持续 stdio 前端，已提供动态 `attach/spawn/list|sessions/use/detach/detachall` 管理入口、真实 launcher 接线和后台 `ping` 健康探针自动回收；`exit` 只有在 detach 报告全部 clean 且 registry 为空时才关闭，运行摘要累计 health/exit 阶段的 clean detach 数量。

整体判定：**核心 Attach/QuickJS/Apple 元数据能力已经形成，但 iOS 尚未达到 Android 全功能 parity。CModule JIT 已在 ARM64 macOS host 与 ARM64 iOS Simulator 完成真实 executable mapping、导出执行与释放验收；物理设备 runtime 仍需单独验收。本轮 Stalker 静态 transform/event generation、Swift object ownership/dispose/metadata identity、agent-owned external-hook command/receipt 状态和 controller remote lease 管理 API、远程 command/receipt 转移与产品级调用链已完成源码/静态接线，待 Apple runtime/真机验收。生产执行路径仍需物理设备 v2 runtime-dynamic bundle gate、真正的 target-thread Stalker、Swift full object ABI；external adapter 继续标记为 integration boundary，而非生产运行验收完成。**

## 2. 审计范围与状态定义

审计日期：2026-08-03。

```bash
export R=/home/xd/main/rustFrida-git
export I=/home/xd/main/rustFrida-git/ios-rustfrida
export A=/home/xd/main/rustFrida-master
```

- iOS 功能基线：`$I`，Git commit `7112f8bfec3313e70e49b2dfe7faef53fca594b9`，文档更新按该提交及 CI run `30805082247` 审计。
- Android 基线：`$A`，Git HEAD `d0bc03737e593a6d899e4ed4872c5ffd3b6d7221`，审计时工作区干净；相对上一基线仅有 README 修订，无功能代码变化。
- iOS 工作区处于并发开发状态。本审计按实际可见代码和最终接线结果判定，并以 Linux workspace test、controller transport test 和 Apple target cross-check 作为静态门禁。
- `complete`：源码实现和注册/调用链已闭合，接口达到该行定义的基线；不代表真机已验证。
- `partial`：已有可用子集，但 API、语义、接线或交付状态不完整。
- `unsupported-by-design`：代码明确声明平台不支持，并提供稳定的不可用契约或替代路径。
- `missing`：Android 有实际实现，而 iOS 对应注册面不存在、仅有名称占位，或没有可执行接线。

本轮新增能力统一采用以下口径：源码、注册点和 host 内部调用链闭合时记为“源码/静态接线已完成”；未经过 Apple host/device 生产路径的项目仍标为“待验收”。agent-owned external-hook command/receipt 路径已闭合到 agent registry；controller 的 `adopt/release/uninstall/cleanup` lease 管理 API、`Session::execute_external_hook`、`RemoteExternalHookLease`、`SessionRegistry::execute_external_hook`、injection entry 和 controller tests 已完成源码/静态接线，待 Apple runtime/真机验收，整体 external-hook 功能继续保留 `integration boundary` 标记。

复现快照：

```bash
git -C "$I" rev-parse HEAD
git -C "$I" status --short
git -C "$A" rev-parse HEAD
git -C "$A" status --short
```

## 3. Android 对标目录与关键文件

| 能力 | Android 准确路径 | 关键文件/用途 |
|---|---|---|
| Host CLI、Attach、REPL | `$A/rust_frida/src/` | `args.rs`、`main.rs`、`injection.rs`、`process.rs`、`repl.rs` |
| Spawn gate | `$A/rust_frida/src/spawn.rs`、`$A/zymbiote/` | `spawn.rs`、`zymbiote/zymbiote.c`，zygote/USAP gate、ACK、SIGSTOP/SIGCONT |
| Server、多 session、HTTP RPC | `$A/rust_frida/src/` | `server.rs`、`session.rs`、`http_rpc.rs`、`communication.rs`、`remote_agent.rs` |
| 注入 loader | `$A/loader/helpers/` | `bootstrapper.c`、`rustfrida-loader.c`、`elf-parser.c`、`syscall.c` |
| Agent | `$A/agent/src/` | `lib.rs`、`communication.rs`、`quickjs_loader.rs`、`stalker.rs`、`recompiler.rs`、`trace/` |
| QuickJS runtime/API 总入口 | `$A/quickjs-hook/src/` | `runtime.rs`、`lib.rs`、`jsapi/mod.rs` |
| Module/Process | `$A/quickjs-hook/src/jsapi/module/` | `api.rs`、`process_api.rs`、`elf.rs`、`enumerate.rs`、`resolve.rs` |
| Memory/NativePointer | `$A/quickjs-hook/src/jsapi/memory/` | `mod.rs`、`alloc.rs`、`read.rs`、`write.rs`、`writest.rs`；另见 `jsapi/ptr.rs` |
| Hook/Interceptor/NativeFunction/CModule | `$A/quickjs-hook/src/jsapi/hook_api/` | `mod.rs`、`functions.rs`、`registry.rs`、`native_boot.js`、`interceptor_boot.js`、`cmodule.rs` |
| Java/JNI | `$A/quickjs-hook/src/jsapi/java/`、`$A/quickjs-hook/src/jsapi/jni/` | ART/JVMTI、heap choose、class/method/field、JNIEnv 表和 helper |
| File/RPC | `$A/quickjs-hook/src/jsapi/file.rs`、`$A/quickjs-hook/src/jsapi/rpc.rs` | QuickJS `File`、`rpc.exports` 和 `__rpc_dispatch` |
| QBDI | `$A/qbdi/`、`$A/qbdi-helper/`、`$A/quickjs-hook/src/jsapi/hook_api/qbdi.rs` | VM、range、call、GPR/FPR、trace callback 桥接 |
| Frida Gum Stalker | `$A/frida-gum/`、`$A/frida-gum-sys/` | `frida-gum/src/stalker.rs` 及 FFI |
| `watch-so` | `$A/ldmonitor/`、`$A/ldmonitor-common/`、`$A/ldmonitor-ebpf/` | eBPF 动态库加载监控 |

iOS 主要对应目录：host 在 `$I/controller/src/`，Mach/Mach-O/Swift 在 `$I/native-api/src/`，agent 在 `$I/agent/src/lib.rs`，QuickJS API 在 `$I/quickjs-runtime/src/`，ObjC runtime 底层在 `$I/objc-api/src/lib.rs`。

## 4. 状态矩阵

### 4.1 CLI / 注入

| 功能项 | 状态 | Android 代码证据 | iOS 代码证据 | 判定 |
|---|---|---|---|---|
| PID Attach 与注入主链 | `complete` | `$A/rust_frida/src/injection.rs`；`$A/loader/helpers/bootstrapper.c`；`$A/loader/helpers/rustfrida-loader.c` | `$I/native-api/src/injection.rs`；`$I/native-api/src/mach.rs`；`$I/native-api/src/lib.rs`；`$I/controller/src/injection.rs` | iOS 已调用 `task_for_pid`、`mach_vm_allocate/write/protect`、`thread_create_running`，再完成 socket `Hello/Ping/JsInit/LoadJs`；仅静态完成。 |
| CLI/REPL/脚本/单命令/JSON 诊断 | `complete` | `$A/rust_frida/src/args.rs`；`main.rs`；`repl.rs` | `$I/controller/src/args.rs`；`main.rs`；`injection.rs` | iOS 有交互 REPL、`--script`、`--command`、`--command-json`、`--preflight-only/json`、`--inject-json`。 |
| Spawn 语义 | `partial` | `$A/rust_frida/src/spawn.rs`；`$A/zymbiote/zymbiote.c` | `$I/controller/src/launch.rs`；`suspended_spawn.rs`；`injection.rs` | 已有显式状态机、Apple executable `POSIX_SPAWN_START_SUSPENDED`、未恢复失败清理，以及“暂停 -> 注入/握手/`JsInit/LoadJs` -> 恢复”接线。Simulator bundle 启动只使用 `simctl --wait-for-debugger` 并校验进程暂停；物理设备要求 v2 `runtime-dynamic` FrontBoard/scene provider 在 `before-first-user-instruction` 交付 gate，并严格校验 bundle/PID/provider/gate ID 与 `held/released/terminated` 状态。真实 provider 和 Apple runtime 仍待验收，启动后 `SIGSTOP` 兼容路径已移除。 |
| 按进程名 Attach | `complete` | `$A/rust_frida/src/process.rs`；`$A/rust_frida/src/main.rs` 的 `find_pid_by_name` | `$I/controller/src/process_lookup.rs`；`args.rs`；`main.rs` | 已支持 `--name/-n`，Apple 用 libproc 精确匹配 name/path/basename，唯一命中后重验 PID identity；多命中和退出竞态显式失败。静态完成。 |
| `watch-so` 自动注入 | `unsupported-by-design` | `$A/rust_frida/src/injection.rs`；`$A/ldmonitor-ebpf/` | `$I/controller/src/args.rs`；`$I/controller/src/injection.rs` | Android eBPF/procfs 方案不可直接对标 Darwin；若需要，应另做 dyld/EndpointSecurity 设计，不应复制 Android 后端。 |
| Server daemon / 多 session | `partial` | `$A/rust_frida/src/server.rs`；`session.rs`；`main.rs` | `$I/controller/src/{session.rs,server.rs,server_frontend.rs,server_runtime.rs,http_rpc.rs,injection.rs,main.rs}` | 有界 registry、稳定 ID、并发 command gate、attach/detach/failed 生命周期、HTTP session 路由、`--server` stdio 前端和后台健康探针自动回收已完成静态接线；server `exit` 以“detach 报告全部 clean 且 registry 为空”为关闭 gate，并累计 health/exit 阶段 clean detach 摘要；HTTP 入口仍面向单目标 RPC，Apple runtime 断线时序待验收。 |
| Agent 载荷交付与隐藏 | `partial` | `$A/rust_frida/src/injection.rs` 的 `include_bytes!`/memfd；`$A/loader/helpers/rustfrida-loader.c` | `$I/native-api/src/injection.rs`；`$I/controller/src/injection.rs` | Android 内嵌 agent、memfd 和自解析 ELF；iOS 依赖目标可见且签名/权限兼容的 dylib 路径后 `dlopen`。 |
| property profile、SELinux、zygote/USAP | `unsupported-by-design` | `$A/rust_frida/src/props.rs`；`selinux.rs`；`spawn.rs` | `$I/controller/src/args.rs`；`$I/native-api/src/jailbreak.rs` | 这些是 Android 平台能力；iOS 对应工作应围绕 entitlement、codesign、PAC、rootful/rootless，而非逐 API 搬运。 |

### 4.2 QuickJS 全局 API

| 功能项 | 状态 | Android 代码证据 | iOS 代码证据 | 判定 |
|---|---|---|---|---|
| Runtime init/eval/cleanup/completion | `complete` | `$A/quickjs-hook/src/lib.rs`；`runtime.rs`；`$A/agent/src/quickjs_loader.rs` | `$I/quickjs-runtime/src/runtime.rs`；`lib.rs`；`$I/agent/src/lib.rs` | 真后端具备 runtime/context、限制、pending job、日志、补全和清理链。直接 `JsEval/LoadJs` 对数组和普通对象输出 JSON，并保留字符串、标量、`undefined` 与原生 wrapper 的既有表示；循环引用和复合 `BigInt` 作为求值错误返回。host runtime 与 agent 命令测试已覆盖成功、JSON 特殊值和失败路径；CI run `30805082247` 的 ARM64 iOS Simulator agent frame 也验证了嵌套 object/array。 |
| 全局注册总表 | `partial` | `$A/quickjs-hook/src/jsapi/mod.rs`；`hook_api/mod.rs` | `$I/quickjs-runtime/src/runtime.rs` 的 `initialize` | iOS 注册 `console/File/rpc/ptr/Hook/Java/Jni/DebugSymbol/Memory/Native/NativeFunction/ObjC/Module/Process/PAC/qbdi/Swift`，但多个对象仅兼容占位或缺少方法。 |
| `console`、`ptr` 基础能力 | `complete` | `$A/quickjs-hook/src/jsapi/console.rs`；`ptr.rs` | `$I/quickjs-runtime/src/console.rs`；`ptr.rs` | `ptr` 构造、加减、字符串/数值转换已对齐；内存 prototype 方法另见 Memory 组。 |
| Apple 扩展 `Native/ObjC/Swift/PAC/DebugSymbol` | `complete` | `$A/quickjs-hook/src/jsapi/module/`；`$A/frida-gum/src/debug_symbol.rs` | `$I/quickjs-runtime/src/native.rs`；`objc.rs`；`swift.rs`；`pac.rs`；`debug_symbol.rs` | 属于 iOS 正向扩展，不要求 Android 同名实现。 |
| 非 Apple host 上 Apple target 的 QuickJS | `unsupported-by-design` | Android 构建使用 `$A/quickjs-hook/build.rs` 真后端 | `$I/quickjs-runtime/build.rs` 的 `should_use_stub`/`emit_stub` | Linux 到 Apple target 的 `cargo check` 故意使用 stub，只验证 Rust 表面，不能证明 QuickJS/hook 真后端。 |

### 4.3 Native / Module

| 功能项 | 状态 | Android 代码证据 | iOS 代码证据 | 判定 |
|---|---|---|---|---|
| Module 基础定位 | `complete` | `$A/quickjs-hook/src/jsapi/module/api.rs` | `$I/quickjs-runtime/src/module.rs` | 两端都有 `enumerateModules/findBaseAddress/findByAddress/findExportByName`。 |
| Module 高级枚举 | `complete` | `$A/quickjs-hook/src/jsapi/module/api.rs` | `$I/quickjs-runtime/src/module.rs`；`$I/native-api/src/{imports,symbols}.rs` | 已注册 `enumerateExports/enumerateImports/enumerateSymbols/enumerateRanges`。Mach-O `N_SECT` 本地/非导出符号会应用 dyld slide，`N_ABS` 保持绝对地址，未定义项按 `isDefined=false` 处理；按 instruction section flags 区分 function/variable，只移除一个 ABI 下划线并按规范化名称去重。imports 已从 indirect symbol table 解析 GOT `slot/address`、pointer 类型与 dylib ordinal；load-command、segment、section、`__LINKEDIT`、nlist 和字符串表边界均有校验。静态完成，Apple runtime 行为待验收。 |
| `Module.load` | `complete` | `$A/quickjs-hook/src/jsapi/module/api.rs` 的 `js_module_load` | `$I/quickjs-runtime/src/module.rs`；`runtime.rs` | Apple 使用 `dlopen(RTLD_NOW|RTLD_LOCAL)`，handle 按 QuickJS runtime 隔离并在 context/runtime 销毁后逆序 `dlclose`；静态完成，待 Apple runtime 验证。 |
| Mach-O 原生查询 | `complete` | `$A/quickjs-hook/src/jsapi/module/elf.rs`；`enumerate.rs` | `$I/quickjs-runtime/src/native.rs`；`$I/native-api/src/{macho_load_commands,exports,imports,symbols,segments,sections,loadcmds,chained_fixups,code_signature}.rs` | iOS 已覆盖 image、symbol、export/import、依赖、加密、入口、dyld/linkedit、function starts、签名、trie/fixups、版本、UUID、rpath、segment/section/load command 等。load command 使用单一 canonical raw 表、保留 `LC_REQ_DYLD` 高位并 exact 匹配；CI run `30764666695` 已通过 ARM64 macOS 当前镜像的生产解析联动测试。 |
| `callNative` | `partial` | `$A/quickjs-hook/src/jsapi/hook_api/functions.rs`；`native_boot.js` | `$I/quickjs-runtime/src/hook.rs` | iOS 只支持最多 6 个整数参数和整数返回；无 AAPCS64 FPR、栈溢出参数和类型封送。 |
| `NativeFunction` | `complete` | `$A/quickjs-hook/src/jsapi/hook_api/native_boot.js`；`functions.rs::__nativeCall`；`$A/quickjs-hook/src/native_call.S` | `$I/quickjs-runtime/src/native_function.rs`；`native_call_aarch64.S`；`runtime.rs` | 已对齐 Android 标量类型，独立分配 `x0..x7`/`v0..v7`，支持 float/double 参数与返回、最多 256 个栈参数、64 位 BigInt 返回、PAC 规范化和 executable-page 检查；iOS 溢出参数使用 Apple arm64 自然大小/对齐栈布局。结构体/数组按值和 variadic 两端均未实现。静态完成，待 Apple runtime 验证。 |
| `CModule` | `complete` | `$A/quickjs-hook/src/jsapi/hook_api/cmodule.rs` | `$I/quickjs-runtime/src/cmodule.rs`；`runtime.rs`；`cmodule-src/`；`$I/simulator-harness/` | Apple backend 已接入 TinyCC compiler、Mach-O linker、`MAP_JIT` executable mapping、imports/exports、`findSymbol`、finalizer 和 `dropMetadata`，并保留源码/import 的真实校验。CI run `30764666695` 的 ARM64 macOS host tests 完成 TinyCC 编译、映射、导出执行与释放验收；同一 run 的 ARM64 iOS Simulator XCTest 通过 CModule + `NativeFunction` 调用返回 `42`。物理设备 runtime 仍待验收；Linux 普通构建按平台返回 `unavailable`。 |
| `hookNative/attachNative` | `complete` | `$A/quickjs-hook/src/jsapi/hook_api/functions.rs`；`callback.rs`；`mod.rs` | `$I/quickjs-runtime/src/hook.rs`；`hook-engine-src/{hook_engine.h,hook_engine_inline.c,hook_engine_mem.c,hook_engine_redir.c}` | iOS 已接收 native callback pointer/userData：replace 返回 trampoline，attach 支持指针和 options 两种形态；生成 thunk 在 C 入口维护原子活跃计数，最终 decrement + return/branch 位于 dylib 常驻文本 helper，计数归零后不再执行可回收池代码；redirect 尾调用保留原始 LR。JS callback 使用每次安装独立 dispatch storage，runtime cleanup 按 owner context 过滤；卸载 thunk 先退休，完整 thunk 与 callback quiescent 后才复用。RECOMP 继续明确 unsupported；静态完成，待 Apple ARM64/arm64e 并发 detach 真机验证。Android 也没有独立公开的 `NativeCallback` global。 |

### 4.4 Memory

| 功能项 | 状态 | Android 代码证据 | iOS 代码证据 | 判定 |
|---|---|---|---|---|
| 基础读写 | `complete` | `$A/quickjs-hook/src/jsapi/memory/{mod,read,write}.rs` | `$I/quickjs-runtime/src/memory.rs` | 对齐 `readU8/U16/U32/U64/readPointer/readCString/readUtf8String/readByteArray` 与 `writeU8/U16/U32/U64/writePointer`。 |
| 分配与字符串分配 | `complete` | `$A/quickjs-hook/src/jsapi/memory/alloc.rs` | `$I/quickjs-runtime/src/memory.rs`；`runtime.rs` | 已实现 `Memory.alloc`、`Memory.allocUtf8String`，带单次/per-runtime 上限，并按 QuickJS runtime 清理所有权。 |
| 保护与代码缓存 | `complete` | `$A/quickjs-hook/src/jsapi/memory/mod.rs` | `$I/quickjs-runtime/src/memory.rs` | 已实现严格三字符 `Memory.protect` 和平台化 `flushCodeCache`；Apple 使用 `sys_icache_invalidate`，实际权限行为待真机。 |
| 批量写/结构写 | `partial` | `$A/quickjs-hook/src/jsapi/memory/write.rs`；`writest.rs` | `$I/quickjs-runtime/src/memory.rs` | `writeBytes` 已支持 ArrayBuffer/TypedArray/number array；`writest` 依赖 Android RECOMP stealth-2，iOS 提供明确 unsupported 契约。 |
| `NativePointer.read*/write*` | `complete` | `$A/quickjs-hook/src/jsapi/memory/mod.rs`；`$A/quickjs-hook/src/jsapi/ptr.rs` | `$I/quickjs-runtime/src/memory.rs`；`ptr.rs` | prototype 已复用 Memory 的 read/write/writeBytes/protect/flushCodeCache handler。 |
| Apple 写保护恢复 | `complete` | `$A/quickjs-hook/src/jsapi/memory/helpers.rs` 从 `/proc/self/maps` 恢复权限 | `$I/quickjs-runtime/src/memory.rs` | Apple 使用 Mach VM region 查询原始/最大权限，跨 region 改权失败会回滚，写后恢复；静态完成，待真机验证。 |

### 4.5 Interceptor / hook

| 功能项 | 状态 | Android 代码证据 | iOS 代码证据 | 判定 |
|---|---|---|---|---|
| ARM64 inline hook 基础引擎 | `complete` | `$A/quickjs-hook/src/hook_engine*.c`；`jsapi/hook_api/functions.rs` | `$I/quickjs-runtime/src/hook.rs`；`$I/quickjs-runtime/hook-engine-src/` | iOS 已接 `hook/unhook`、`Interceptor.attach/replace/revert/detachAll` 和 callback registry；只能算静态完成。 |
| Frida 风格 attach 回调语义 | `complete` | `$A/quickjs-hook/src/jsapi/hook_api/interceptor_boot.js`；`functions.rs` | `$I/quickjs-runtime/src/hook.rs` | 已实现 `onEnter(args[0..7])`、`onLeave(retval)`、`retval.replace/toInt32/toUInt32/toString`、共享 `this` 和 thread-local 递归栈；当前 retval 与 Android 参考实现一样以整数/指针 `x0` 为核心，FPR/向量/结构体回调上下文不属于本轮 NativeFunction 调用桥。静态完成。 |
| `Interceptor.flush` | `complete` | `$A/quickjs-hook/src/jsapi/hook_api/mod.rs`；`functions.rs` | `$I/quickjs-runtime/src/hook.rs` | 与 Android 兼容为同步 hook backend 的 no-op，返回 `undefined`。 |
| `Hook.RECOMP/recompHook` | `unsupported-by-design` | `$A/quickjs-hook/src/recomp/`；`jsapi/hook_api/functions.rs` | `$I/quickjs-runtime/src/hook.rs` | iOS 明确抛出 Android-only；保留常量用于 feature detect。 |
| 外部 hook backend 共存 | `partial` | Android 内部 engine 与 ART/OAT/recomp 文件：`$A/quickjs-hook/src/hook_engine_art.c`、`hook_engine_oat_patch.c` | `$I/native-api/src/jailbreak.rs`；`hook_backend_adapter.rs`；`hook_backend_ffi.rs`；`$I/controller/src/{session.rs,server.rs,injection.rs}`；`$I/agent/src/lib.rs`；`$I/common/src/command.rs` | iOS 已有探测、严格解析、topology 校验，以及覆盖 query/install/attach/uninstall/cleanup/replace 的 policy/command-mode/execution-boundary 决策。agent-owned command path 已实际执行 `ExternalHookExecute/Status/Release/Uninstall`，用 `request_id/owner_id` 去重、owner 过滤并返回 receipt；receipt 保留 `owned/released/orphaned` ownership 与 `installed/restored/uncertain` target 状态，目标状态不确定时保留 orphan record。controller 已提供 `adopt_external_hook`、`release_external_hook`、`uninstall_external_hook`、`cleanup_external_hooks`、registry 转发和 attach/failure/health/detach/Drop 清理；`Session::execute_external_hook`、`RemoteExternalHookLease`、`SessionRegistry::execute_external_hook`、injection entry 和 controller tests 已完成源码/静态接线，待 Apple runtime/真机验收，故整体仍是 integration boundary。四种已确认 ABI 没有公开 native uninstall。 |

### 4.6 Stalker / QBDI

| 功能项 | 状态 | Android 代码证据 | iOS 代码证据 | 判定 |
|---|---|---|---|---|
| 函数级 `trace/stalker` 命令 | `partial` | `$A/agent/src/stalker.rs`；`$A/frida-gum/src/stalker.rs` | `$I/quickjs-runtime/src/native_hooks.rs`；`$I/controller/src/injection.rs` | iOS 可 hook 指定函数或 `objc_msgSend`，记录 enter/leave、深度和寄存器；有实用价值，但不是指令级 DBI。 |
| Frida Gum 指令级 Stalker | `partial` | `$A/agent/src/stalker.rs`；`$A/frida-gum/src/stalker.rs`；`$A/agent/src/recompiler.rs` | `$I/native-api/src/stalker.rs`；`$I/quickjs-runtime/src/{arm64_relocator.rs,native.rs,native_hooks.rs,stalker.rs}` | iOS 已有事件/mask、排除区间、生命周期、有限队列和全局 `Stalker.capabilities/status` API；本轮新增 bounded basic-block static transform、caller-supplied execution trace 的 `Compile/Block/Exec/Call/Ret` event generation、QuickJS `transform/transformBasicBlock/generateEvents/recordBlock` 接线，以及复用现有 ARM64 writer/relocator 的 `Stalker.relocate` direct-only 静态 relocation plan。能力报告明确 `directRelocationPlan=true`、`directRelocationMode=direct-only`、`transformMode=static-only`、`eventGenerationMode=caller-supplied-execution-trace`，`targetThreadInstrumentation/targetThreadInstructionRewrite/instrumented=false`。该范围只分析 caller-supplied ARM64 bytes/trace，不分配或执行 code cache，不修改目标代码，也不执行 target-thread instrumentation；真实 target-thread follow/unfollow、code cache、指令重写、transformer/callout、生产 event sink 和 instruction event backend 仍未接入。 |
| ptrace 指令 trace | `missing` | `$A/agent/src/trace/` | `$I/quickjs-runtime/src/native_hooks.rs` | iOS `trace` 是函数 hook 日志，不等价 Android ptrace instruction trace。 |
| QBDI VM | `unsupported-by-design` | `$A/qbdi/`；`$A/qbdi-helper/`；`$A/quickjs-hook/src/jsapi/hook_api/qbdi.rs` | `$I/quickjs-runtime/src/qbdi.rs` | iOS 明确 `available:false`，VM/range/call/GPR/FPR/trace 方法抛稳定错误，仅保留 status/info/methods/constants。该状态是当前项目决策，不代表技术上永远不可移植。 |

### 4.7 Java/JNI 对应 ObjC/Swift

| 功能项 | 状态 | Android 代码证据 | iOS 代码证据 | 判定 |
|---|---|---|---|---|
| Java/ART API | `unsupported-by-design` | `$A/quickjs-hook/src/jsapi/java/` | `$I/quickjs-runtime/src/java.rs` | iOS `Java.available=false`，为 `use/hook/choose/field/method/classloader/deopt/JVMTI` 提供稳定错误或空查询契约。 |
| JNI/JNIEnv API | `unsupported-by-design` | `$A/quickjs-hook/src/jsapi/jni/` | `$I/quickjs-runtime/src/jni.rs` | iOS 暴露 status/metadata/函数表名称，但调用统一不可用；替代路径是 ObjC/Swift/Native。 |
| ObjC 元数据查询 | `complete` | Android 对标 Java class/method/field inspect：`$A/quickjs-hook/src/jsapi/java/` | `$I/quickjs-runtime/src/objc.rs`；`$I/objc-api/src/lib.rs` | classes、protocols、继承/遵循、methods/properties/ivars、selector/IMP/image、object class name 已接线；静态完成。 |
| Swift 元数据查询 | `complete` | Android 对标 Java metadata：`$A/quickjs-hook/src/jsapi/java/` | `$I/quickjs-runtime/src/swift.rs`；`$I/native-api/src/swift.rs` | demangle、symbols、protocols、conformances、metadata、vtable、witness table、type layout、methods/types 已接线；新增 scalar/pointer/metatype/existential/function/tuple/nominal 的类型、对象表示和 ABI 参数分类，`Swift.metadataOf()`/`Swift.object()` 已加入对齐、可读 VM 区域、显式 metadata 必须匹配对象首字的 identity 校验，并记录 `metadataInferred/metadataVerified` 与 `borrowed/adopt/retain` ownership；wrapper 的 `status()`、`isDisposed()`、幂等 `dispose()`、finalizer 释放路径已接线。上述是源码/静态边界，不代表完整 metadata 图或生产对象 ABI；full object ABI call、泛型/隐藏参数仍关闭。 |
| `jhook/shook` 命令链 | `complete` | `$A/quickjs-hook/src/jsapi/java/java_hook_api/` | `$I/controller/src/injection.rs`；`$I/quickjs-runtime/src/controller_api.rs`；`native_hooks.rs` | iOS 命令解析、runtime dispatch、ObjC/Swift 符号解析和 inline hook 已闭合；实际稳定性待真机。 |
| 对象操作层 | `partial` | `$A/quickjs-hook/src/jsapi/java/{java_choose_api,java_field_api,callback}.rs`；`java_boot.js` | `$I/objc-api/src/{object_bridge.rs,instance_enumeration.m}`；`$I/objc-api/src/exception_shim.m`；`$I/quickjs-runtime/src/{objc.rs,objc_object.rs,swift.rs}` | ObjC wrapper、ownership、typed send、ivar/property 操作、Apple exception containment、`ObjC.registerClass` 动态 subclass/ivar/method 和 `ObjC.chooseSync/choose` 有界 heap enumeration 已接线；动态属性 accessor 已按 encoding 精确读写 1/2/4/8 字节标量和指针，retain/copy/weak 赋值与析构路径也已接入。`ObjC.registerClass` property 支持显式 `getter` / `setter`、`atomic: true`、`kvo: 'automatic' | 'manual'`，KVO 默认 `automatic`，并生成 `G` / `S` / `V` metadata，`N` 仅在 nonatomic 时写入；resolver 从动态类开始逐层使用 `class_copyPropertyList`，可处理继承和 KVO 动态子类，同时修复默认 setter 的大小写反推问题，`setTitle:` 现在会正确定位 `_title`。getter 0 冒号、setter 单末尾冒号、readonly/setter 冲突、manual KVO/readonly 冲突、selector 逗号和当前类/继承方法 selector collision 均在 mutation 前校验。manual KVO 使用 declaring-property instance marker、幂等 metaclass `+automaticallyNotifiesObserversForKey:` override、declaring-metaclass TLS super 转发，以及每层嵌套 `will/did` TLS frame 复用的同一枚 `+1 NSString` key；custom/atomic/weak 均复用同一 setter wrapper。KVO capability 和 255-byte key 上限会前置校验，runtime property/KVO mutation 失败会 poison pending class 并阻止 registration。atomic retain/copy object 使用 `objc_getProperty` / `objc_setProperty`，scalar 与 assign pointer 的 1/2/4/8 字节 atomic 访问使用 `objc_copyStruct`，weak 保持 zeroing weak runtime。KVO shim 已通过 arm64 iOS 与 x86_64 macOS 的 `-Werror` 编译，Apple Cargo cross 也已通过；ObjC property synthesis 已完成静态实现，atomic/KVO 真机 runtime 尚待验收。Swift 仍缺 full object ABI、泛型/隐藏 ABI。 |

### 4.8 File

| 功能项 | 状态 | Android 代码证据 | iOS 代码证据 | 判定 |
|---|---|---|---|---|
| `File` constructor/实例方法 | `complete` | `$A/quickjs-hook/src/jsapi/file.rs` | `$I/quickjs-runtime/src/file.rs`；`runtime.rs` | 两端都有 constructor、`tell/seek/readBytes/readText/readLine/write/flush/close`。 |
| `File` 静态方法 | `complete` | `$A/quickjs-hook/src/jsapi/file.rs` | `$I/quickjs-runtime/src/file.rs` | 对齐 `readAllBytes/readAllText/writeAllBytes/writeAllText` 和 seek constants；沙箱/权限待 Apple 运行测试。 |

### 4.9 Process

| 功能项 | 状态 | Android 代码证据 | iOS 代码证据 | 判定 |
|---|---|---|---|---|
| Process 属性和模块/range 方法 | `complete` | `$A/quickjs-hook/src/jsapi/module/process_api.rs` | `$I/quickjs-runtime/src/process.rs`；`runtime.rs` | `id/arch/platform/pointerSize/pageSize/codeSigningPolicy/mainModule` 及 module/range find/get/enumerate 表面一致。 |
| 目录、线程、调试器状态 | `complete` | `$A/quickjs-hook/src/jsapi/module/process_api.rs` | `$I/quickjs-runtime/src/process.rs` | `getCurrentDir/getHomeDir/getTmpDir/getCurrentThreadId/isDebuggerAttached/enumerateThreads` 已对齐；iOS 用 dyld、Mach thread、`csops/sysctl`。 |
| `enumerateMallocRanges` | `complete` | `$A/quickjs-hook/src/jsapi/module/process_api.rs` | `$I/quickjs-runtime/src/process.rs` | 两端当前都返回空数组，因此不是 iOS 相对缺口；若升级为真实枚举，应双端共同定义语义。 |

### 4.10 RPC

| 功能项 | 状态 | Android 代码证据 | iOS 代码证据 | 判定 |
|---|---|---|---|---|
| `rpc.exports`/`rpc.export`/`__rpc_dispatch` | `complete` | `$A/quickjs-hook/src/jsapi/rpc.rs` | `$I/quickjs-runtime/src/rpc.rs`；`runtime.rs` | QuickJS 注册和 JSON 参数派发一致；nested array/object 返回值只做一次 `JSON.stringify`，`undefined` 返回 `null`。 |
| Agent 与单次 CLI `rpccall` | `complete` | `$A/agent/src/communication.rs`；`$A/rust_frida/src/session.rs` | `$I/common/src/command.rs`；`$I/agent/src/lib.rs`；`$I/controller/src/injection.rs` | `RpcCall` 已从 controller 编码到 agent，再进入 `QuickJsRuntime::dispatch_rpc`；agent 测试同时覆盖结构化 `LoadJs/JsEval` 和 RPC 标量结果。 |
| 单目标 HTTP RPC | `complete` | `$A/rust_frida/src/http_rpc.rs`；`session.rs` | `$I/controller/src/http_rpc.rs`；`session.rs`；`server.rs`；`injection.rs`；`args.rs`；`main.rs` | `--rpc-port`、stable session ID、stream mutex、timeout、HTTP parser/router 和 Unix frame transport test 已闭合；HTTP route 测试覆盖 string/null/bool/number、嵌套 object/array 参数及类型化响应，未发生 JSON 二次编码。单 session 通过 agent `Ping` 做 liveness，transport failure 进入 registry reconcile/detach，cleanup 失败保留 session/transport 重试入口，并在有界重试后确定性退出。 |
| 多 session HTTP/daemon | `partial` | `$A/rust_frida/src/server.rs`；`session.rs`；`http_rpc.rs` | `$I/controller/src/{session.rs,server.rs,server_frontend.rs,server_runtime.rs,http_rpc.rs,injection.rs}` | registry 和 `/sessions`、`/rpc/<session>/<method>` 路由可承载多 session；`--server` stdio 前端已持续创建和管理多个 attach/spawn session，并有后台 `ping` 健康探针自动回收断线 session；`exit` 受 clean-detach + empty-registry gate 约束，摘要累计 health/exit 清理数量；HTTP 入口仍提供单目标 RPC 路由。 |

## 5. 真正剩余的可开发项

### 5.1 代码缺口

按优先级排序：

本轮已完成 Memory/Module/Interceptor/NativeFunction、`hookNative/attachNative`、spawn 生命周期核心、multi-session/断线回收、ObjC typed/custom/atomic/KVO property accessor/exception containment/dynamic-class/有界 heap choose 核心、Swift thin ABI 子集与 live-object validation/wrapper、Swift object ownership/dispose/metadata identity 静态边界、Stalker bounded static transform/event generation/direct-only relocation plan、CModule Apple backend、ARM64 macOS host 与 ARM64 iOS Simulator runtime 验收、Mach-O canonical load command 修复与 macOS 生产解析联动、Mach-O 本地/非导出 nlist 和 import slot/address 解析、agent-owned external-hook command/receipt 状态，以及带 token/lease/release 语义并已接入 controller session/registry API 的 controller remote lease 源码/静态接线；其余 Apple runtime/真机边界按下列优先级继续处理：

1. **P1：完成物理设备 bundle 原生 suspended provider。** Simulator 已使用 `xcrun simctl launch --wait-for-debugger` 并复用、校验 suspended 状态；还要实现外部 v2 `runtime-dynamic` FrontBoard/scene provider，在 `before-first-user-instruction` 交付并确认 gate，完成真实设备验收。controller 的状态绑定和失败终止逻辑已完成，启动后 `SIGSTOP` 窗口不再作为实现路径。
2. **P2：实现真正指令级 Stalker backend。** bounded basic-block transform plan、caller-supplied execution event generation、direct-only ARM64 relocation plan 和 QuickJS 接口已完成源码/静态接线；还需要真实 target-thread follow/unfollow、ARM64 instruction rewrite/code cache、生产 transformer/callout、event sink 和 flush/GC backend。
3. **P2：扩展 ObjC/Swift 对象层。** ObjC 动态类注册、异常 containment、有界 heap enumeration、typed scalar/pointer property accessor、custom getter/setter、atomic/KVO property、retain/copy/weak 生命周期，以及 Swift object ownership/dispose/metadata identity 校验已完成源码/静态实现；源码剩余项为 Swift full object ABI、泛型/隐藏 ABI，生产对象生命周期仍待 Apple runtime。
4. **P2：完成 CModule 物理设备与 external adapter 的产品运行验证。** CModule 的 Apple compiler/linker、imports/exports、`findSymbol`、finalizer 和 `dropMetadata` 已实现，并由 CI run `30764666695` 完成 ARM64 macOS host 与 ARM64 iOS Simulator runtime 验收；物理设备仍需真实 runtime 验收，Linux 普通构建的 `unavailable` 属于平台边界。agent-owned external-hook command/receipt path、controller install/replace remote lease、receipt 转移和产品级调用链已完成源码/静态接线，待 Apple runtime/真机验收；生产 token 回收时序仍需 Apple runtime 验证。四种 backend 未公开 native uninstall 的边界继续保持明确。QBDI 保持独立产品决策。

不应列为通用 iOS 代码缺口：Android property profile、SELinux patch、zygote/USAP、eBPF `watch-so`、ART/OAT/JVMTI、JNI 和 RECOMP。对应平台需求应单独立项，不能用同名空 API 追求表面数量。

CI run `30805082247` 的完整 host 测试结果为 Linux `576 passed`、ARM64 macOS `518 passed`。ARM64 macOS host 结果包含真实 CModule 编译、executable mapping、导出执行和释放测试，以及当前镜像的 canonical Mach-O production parser 测试。ARM64 iOS Simulator hosted XCTest `1 passed`，通过 `dlopen/dlsym` 驱动 `HELLO / Ping / JsInit / LoadJs / RPC / structured RPC / structured JsEval / CModule / Exit`；嵌套 object/array 作为 JSON 结构跨 agent frame 保真，CModule 与标量 RPC 均返回 `42`，`ios_agent_entry` 返回 `0`。device agent dylib 与 macOS controller 也成功构建并上传；真实 provider、物理设备注入、hook、KVO、Swift ownership、controller remote lease 和 agent adapter 生产调用时序仍按下一节验收。

### 5.2 只能 Apple host / 真机验证

以下项目不能由 Linux host 静态搜索、stub test 或 cross `cargo check` 关闭：

1. `task_for_pid` entitlement/越狱权限、目标保护级别和 remote task 获取。
2. `mach_vm_allocate/write/protect`、remote stack/thread bootstrap、目标内 `dlopen/dlsym`、entry 调用和超时清理。
3. rootful/rootless dylib 路径、代码签名、trust cache、sandbox 和 Unix socket 可达性。
4. arm64e/PAC 指针规范化、`pthread_create_from_mach_thread` fallback，以及物理设备上的 CModule `MAP_JIT`/W^X 行为和真实 executable mapping。
5. inline hook 在普通 arm64/arm64e 上的 relocation、onEnter/onLeave、并发/递归、detach/cleanup，以及与 ElleKit/Substrate/Substitute/libhooker 共存。
6. dyld image、Mach-O export/import/local-symbol/range、ObjC runtime、Swift metadata/vtable/witness table 在真实 App 和 stripped binary 上的覆盖，包括 ObjC automatic/manual KVO notification、嵌套 setter 与 superclass forwarding 的 runtime 行为。
7. `Process.enumerateRanges/enumerateThreads/isDebuggerAttached` 的 Mach 权限和结果准确性。
8. `File` 在 App sandbox、rootful/rootless 路径和不同 data protection 状态下的读写。
9. spawn 的 simulator、前台/后台 App、scene lifecycle、冷启动/热启动、v2 FrontBoard/scene provider 和真机暂停时序。
10. HTTP RPC 在真实 agent 日志交错、长调用、断线、超时和 controller 退出时的行为。
11. `NativeFunction` 的 float/double、混合 GPR/FPR、Apple 紧凑栈溢出和 arm64e code pointer 调用；Swift object ownership/dispose 在真实 runtime 的行为；agent-owned external-hook command/receipt、`request_id`/`owner_id`、ownership/target-state/orphan 状态、install/replace 执行路径和 controller remote lease 已完成源码/静态接线，待 Apple runtime/真机验收；生产 token 回收时序仍需 Apple runtime 验证。controller tests 已通过。

仓库 CI `$R/.github/workflows/ios-rustfrida-ci.yml` 当前覆盖 Linux host test、macOS host test、iOS Simulator `cargo check`、ARM64 Simulator agent/CModule runtime XCTest、device agent build 和 macOS controller build；仍没有物理设备 CModule runtime 或越狱设备注入/hook test。因此 CI 绿色关闭 macOS host 与 iOS Simulator CModule 路径，但不关闭上述物理设备项目。

## 6. 可并行执行且文件不重叠的任务清单

以下为同一并行波次。每个窗口只能修改列出的文件；共享注册点留到最后串行收口。

| 优先级/窗口 | 任务 | 独占文件范围 | 独立验收 |
|---|---|---|---|
| P1-B（已完成） | `hookNative/attachNative` | `$I/quickjs-runtime/src/hook.rs`、`hook-engine-src/` | 参数校验、registry、独立 dispatch storage、C thunk 活跃计数、常驻最终退出 helper、runtime owner cleanup、retired thunk 与 callback-in-flight 生命周期；待 Apple 真机验收 |
| P1-C（核心已完成） | suspended spawn 后端 | `$I/controller/src/launch.rs`、`suspended_spawn.rs`、`injection.rs` | 状态机、fake/host backend、预恢复脚本接线和失败终止已完成；Simulator `simctl --wait-for-debugger` gate 已接入并校验暂停状态，物理设备 v2 runtime-dynamic FrontBoard/scene provider 待实现和真机验收 |
| P1-D（核心已完成） | multi-session 核心 | `$I/controller/src/session.rs`、`server.rs`、`server_frontend.rs`、`server_runtime.rs`、`http_rpc.rs`、`injection.rs` | 并发 session、RPC serialization、stable id、HTTP registry 路由、stdio server 前端和断线健康自动回收已完成静态接线；Apple runtime 时序待验收 |
| P2-H（静态 transform/relocation plan 已完成） | 指令级 Stalker 核心 | `$I/native-api/src/stalker.rs`、`$I/quickjs-runtime/src/{arm64_relocator.rs,native.rs,stalker.rs}` | bounded basic-block transform、caller-supplied execution event generation、direct-only ARM64 relocation plan 和 QuickJS 接口已完成；真实 target-thread transformer、instruction rewrite/code cache、event sink backend 待实现 |
| P2-I（核心已完成） | ObjC 对象桥 | `$I/objc-api/src/{object_bridge.rs,instance_enumeration.m}`、`$I/objc-api/src/exception_shim.m`、`$I/quickjs-runtime/src/{objc.rs,objc_object.rs}` | wrapper 生命周期、retain/release、typed send、ivar 读写/地址、按 encoding 精确宽度的 typed property、custom getter/setter、atomic/KVO property、retain/copy/weak 赋值与析构、exception containment、动态 class/ivar/method 和有界 choose 核心已完成静态实现；atomic/KVO Apple 真机 runtime 待验收 |
| P2-J（核心子集已完成） | Swift object/ABI | `$I/native-api/src/swift.rs`、`$I/quickjs-runtime/src/swift.rs`、`$I/quickjs-runtime/src/native_function.rs` | 类型/对象表示、live-object metadata/ownership validation、`status/isDisposed/dispose` 生命周期 API、ABI 参数分类和 verified C-compatible thin scalar/pointer/float call 已完成源码/静态接线；full object ABI、泛型/隐藏 ABI 和 Apple runtime 验收待实现 |
| P2-K（CModule macOS/Simulator 已验收；物理设备待验收；adapter 能力边界已完成） | CModule / 外部 adapter | `$I/quickjs-runtime/src/cmodule.rs`、`$I/quickjs-runtime/cmodule-src/`、`$I/simulator-harness/`、`$I/native-api/src/hook_backend_adapter.rs`、`$I/native-api/src/hook_backend_ffi.rs`、`$I/controller/src/{session.rs,server.rs,injection.rs}` | CModule Apple compiler/linker backend、imports/exports/findSymbol/finalizer/dropMetadata 已由 CI run `30764666695` 的 ARM64 macOS host 与 ARM64 iOS Simulator runtime 测试验收；物理设备仍需 runtime 验收。adapter decision boundary、token/lease/release、agent-owned external-hook command/receipt、controller adopt/release/uninstall/cleanup API、`Session::execute_external_hook`、`RemoteExternalHookLease`、`SessionRegistry::execute_external_hook` 和 Apple external install/replace FFI 已完成源码/静态接线；controller remote lease、产品级调用链和 controller tests 已完成源码/静态接线，待 Apple runtime/真机验收，生产 token 回收时序仍需 Apple runtime 验证；四种已确认 ABI 的 native uninstall 保持明确 unavailable |
| V-Apple | Apple 环境验证 | 不修改源文件；只产出外部测试记录 | 按下一节矩阵保留设备、OS、jailbreak、arch、命令、输出和 crash log |

**串行收口窗口（不得与上表并行）**：统一修改 `$I/quickjs-runtime/src/lib.rs`、`runtime.rs`、`build.rs`、`$I/controller/src/args.rs`、`injection.rs`、`$I/common/src/config.rs`、各 crate `Cargo.toml` 和必要 module declarations。它只做注册、feature、CLI/transport 接线和全量回归，不重新实现各窗口逻辑。这样可避免多个窗口同时争用 `runtime.rs`、`lib.rs`、`args.rs`、`injection.rs`。

## 7. 可执行验收

### 7.1 静态/API 差异复核

```bash
rg -n 'add_cfunction_to_object|set_property' \
  "$A/quickjs-hook/src/jsapi/memory" \
  "$I/quickjs-runtime/src/memory.rs" \
  "$I/quickjs-runtime/src/ptr.rs"

rg -n 'enumerateExports|enumerateImports|enumerateSymbols|enumerateRanges|"load"' \
  "$A/quickjs-hook/src/jsapi/module/api.rs" \
  "$I/quickjs-runtime/src/module.rs"

rg -n 'NativeFunction|CModule|hookNative|attachNative|Interceptor' \
  "$A/quickjs-hook/src/jsapi/hook_api" \
  "$I/quickjs-runtime/src"

rg -n 'mod http_rpc|crate::http_rpc|rpc_bind|rpc_port' \
  "$I/controller/src/main.rs" \
  "$I/controller/src/injection.rs" \
  "$I/controller/src/args.rs"
```

### 7.2 Apple host 构建门禁

```bash
cd "$I"
cargo test -p native-api
cargo test -p quickjs-runtime -- --test-threads=1
cargo test -p controller
cargo check --target aarch64-apple-ios-sim
cargo build -p agent --release --target aarch64-apple-ios
cargo build -p controller --release --bin ios-rustfrida
```

这些命令验证编译、host 逻辑和 Apple toolchain，不验证真机注入。

### 7.3 越狱设备/Apple runtime 门禁

```bash
cd "$I"
scripts/package-artifacts.sh
scripts/deploy-agent-jailbreak.sh root@iphone.local /var/jb/usr/lib/libios_rustfrida_agent.dylib
scripts/doctor-jailbreak.sh --json root@iphone.local /var/jb/usr/lib/libios_rustfrida_agent.dylib

HOST_TRIPLE="$(rustc -vV | sed -n 's/^host: //p')"
CTL="./target/$HOST_TRIPLE/release/ios-rustfrida"

"$CTL" --pid "$PID" --agent-path "$AGENT_PATH" --preflight-only --preflight-json
"$CTL" --pid "$PID" --agent-path "$AGENT_PATH" --inject-json
"$CTL" --pid "$PID" --agent-path "$AGENT_PATH" --script rpc-smoke.js \
  --command 'rpccall ping []' --command-json
"$CTL" --pid "$PID" --agent-path "$AGENT_PATH" --script rpc-smoke.js \
  --rpc-port 127.0.0.1:9191
curl -fsS http://127.0.0.1:9191/sessions
curl -fsS -X POST http://127.0.0.1:9191/rpc/1/ping -d '[]'
```

真机验收必须记录：controller 与 agent commit、设备/OS/arch、jailbreak/rootful-rootless、codesign/trust 状态、目标 App、完整命令、JSON 输出、syslog/crash log。每个 `complete（静态）` 项至少需要一条成功和一条失败/清理路径后，才能升级为“真机已验证”。

## 8. 关闭标准

1. P0 编译阻断消失，所有新文件被版本控制追踪，Apple CI 构建通过。
2. 每个 `missing`/`partial` 项必须以注册表测试和行为测试关闭，不能只新增 status/info 占位。
3. `unsupported-by-design` 必须保持稳定 feature detection、明确错误和替代路径；若设计决策改变，再转换为开发任务。
4. Apple 专属项必须附真机/Apple runtime 证据，Linux stub 或 simulator `cargo check` 不得作为替代。
5. 多窗口实现先保持文件独占，最后由单一集成窗口修改共享注册和 CLI 文件并跑全量门禁。
