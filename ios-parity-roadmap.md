# iOS 对标 Android 剩余开发流程

## 目的

这份文档用于在 `rustFrida-git` 的 iOS 分支上继续补功能时，固定一套明确的对标基线、剩余差距和开发顺序。

当前约束：

- 当前仓库：`/home/xd/main/rustFrida-git`
- iOS 代码目录：`/home/xd/main/rustFrida-git/ios-rustfrida`
- Android 对标基线：`/home/xd/main/rustFrida-master`
- 本轮先产出流程文档，不实现 `native.dyldInfo <module>`

## 对标基线

当前分支已经移除了 Android 目录，所以后续“对标安卓版”统一以工作区里的旧仓库为基线：

- Android 基线仓库：`/home/xd/main/rustFrida-master`

这个基线里需要重点参考的目录和文件如下。

### 1. Android 主机侧 CLI / REPL

- `rustFrida-master/rust_frida/src/main.rs`
- `rustFrida-master/rust_frida/src/repl.rs`
- `rustFrida-master/rust_frida/src/injection.rs`
- `rustFrida-master/rust_frida/src/spawn.rs`
- `rustFrida-master/rust_frida/src/communication.rs`

这部分对应 iOS 当前的：

- `rustFrida-git/ios-rustfrida/controller/src/injection.rs`
- `rustFrida-git/ios-rustfrida/common/src/command.rs`

### 2. Android agent 侧

- `rustFrida-master/agent/src/lib.rs`
- `rustFrida-master/agent/src/quickjs_loader.rs`
- `rustFrida-master/agent/src/stalker.rs`
- `rustFrida-master/agent/src/trace/mod.rs`
- `rustFrida-master/agent/src/trace/arm64_analysis.rs`
- `rustFrida-master/agent/src/trace/arm64_codegen.rs`
- `rustFrida-master/agent/src/trace/transformer.rs`

这部分对应 iOS 当前的：

- `rustFrida-git/ios-rustfrida/agent/src/lib.rs`
- `rustFrida-git/ios-rustfrida/quickjs-runtime/src/runtime.rs`
- `rustFrida-git/ios-rustfrida/quickjs-runtime/src/native_hooks.rs`

### 3. Android JS API / 运行时能力面

- `rustFrida-master/quickjs-hook/src/jsapi/module/api.rs`
- `rustFrida-master/quickjs-hook/src/jsapi/module/elf.rs`
- `rustFrida-master/quickjs-hook/src/jsapi/module/linker.rs`
- `rustFrida-master/quickjs-hook/src/jsapi/memory/read.rs`
- `rustFrida-master/quickjs-hook/src/jsapi/memory/write.rs`
- `rustFrida-master/quickjs-hook/src/jsapi/hook_api/functions.rs`
- `rustFrida-master/quickjs-hook/src/jsapi/hook_api/qbdi.rs`
- `rustFrida-master/quickjs-hook/src/jsapi/java/mod.rs`
- `rustFrida-master/quickjs-hook/src/jsapi/java/java_hook_api.rs`
- `rustFrida-master/quickjs-hook/src/jsapi/java/java_inspect_api.rs`
- `rustFrida-master/quickjs-hook/src/jsapi/java/java_method_list_api.rs`
- `rustFrida-master/quickjs-hook/src/jsapi/java/java_field_api.rs`
- `rustFrida-master/quickjs-hook/src/jsapi/jni/api.rs`

这部分对应 iOS 当前的：

- `rustFrida-git/ios-rustfrida/quickjs-runtime/src/native.rs`
- `rustFrida-git/ios-rustfrida/quickjs-runtime/src/agent_api.rs`
- `rustFrida-git/ios-rustfrida/quickjs-runtime/src/native_hooks.rs`
- `rustFrida-git/ios-rustfrida/native-api/src/*.rs`
- `rustFrida-git/ios-rustfrida/objc-api/src/lib.rs`

## 当前 iOS 已有能力

按现有代码和 README，iOS 版已经具备这几块：

- 注入链路：`plan / preflight / inject / --inject-json / --command-json`
- ObjC 查询：`objc.classes / objc.protocols / objc.classProtocols / objc.protocolMethods / objc.superclass / objc.classChain / objc.properties / objc.ivars / objc.methods / objc.methodOwners / objc.classImage / objc.methodImage / objc.methodImp / objc.selectorName / objc.objectClassName`
- Native 查询：`native.images / native.mainImage / native.image / native.symbol / native.symbols / native.exports / native.dependencies / native.encryptionInfo / native.entryPoint / native.sourceVersion / native.buildVersion / native.dylinker / native.installName / native.uuid / native.rpaths / native.imports / native.loadcmds / native.sections / native.segments`
- Swift 查询：`swift.demangle / swift.symbols / swift.protocols / swift.conformances / swift.metadata / swift.types / swift.typeKinds / swift.methodOwners / swift.typeMethods / swift.methods / swift.typesOfKind`
- PAC 查询：`pac.available / pac.arm64e / pac.image / pac.images / pac.strip / pac.stripdata`
- 控制命令：`hfl / jhook / shook / trace / stalker`
- 自动化：legacy command + structured spec + `payloadJson`
- 部署打包：doctor / deploy / package deb / install deb / CI workflows

结论不是“iOS 还没成型”，而是已经完成了主体框架，剩余工作主要集中在深度元数据、兼容性和真机稳定性。

## 剩余差距

### A. Mach-O 深层查询还没拆成独立命令

目前已经有：

- `native.loadcmds`
- `native.segments`
- `native.sections`
- `native.symbols`
- `native.exports`
- `native.imports`
- `native.dependencies`
- `native.encryptionInfo`
- `native.entryPoint`
- `native.sourceVersion`
- `native.buildVersion`
- `native.dylinker`
- `native.installName`
- `native.uuid`
- `native.rpaths`

但从 `native-api/src/loadcmds.rs` 的解析面看，后面还可以继续拆：

- `native.dyldInfo <module>`
- `native.linkedit <module>`
- `native.functionStarts <module>`
- `native.dataInCode <module>`
- `native.codeSignature <module>`
- `native.exportsTrie <module>`
- `native.chainedFixups <module>`

这些能力的价值在于：

- 让 `native.loadcmds` 从“原始总表”升级成“细分查询 API”
- 方便脚本消费，不必自己再解析 load command 文本
- 更贴近 Android 版 `module/elf/linker` 那种按语义查询的体验

### B. ObjC 元数据面还偏薄

当前 `objc-api` 主要覆盖类、方法、selector、IMP 和 image 归属。

目前 ObjC 这一层已经补到协议方法枚举；后续如果继续扩，就应该优先补“协议关联的更深结构信息”，而不是再回头补基础枚举命令。

### C. Swift 元数据仍可继续补

当前 Swift 查询已经比早期完整很多，但还可以继续增强：

- `swift.typeLayout <type>`
- `swift.vtable <type>`
- `swift.witnessTable <type | protocol>`

这里不要求一步到位，但至少要先明确哪些是“稳定可读的公开元数据”，哪些已经会掉进 runtime ABI 细节。

### D. 外部 hook backend 还只有探测和拦截，没有适配

当前已经有：

- 外部 backend 探测
- hook policy
- query-only / deny-external-loaded
- 目标进程 hook 环境 preflight

还没有：

- 和 ElleKit / Substrate / Substitute / libhooker 的共存适配层
- 冲突态下的降级安装策略
- 对不同 backend 的细粒度兼容矩阵

这块不补完，iOS 版在“真实越狱环境”的稳定性就还不能说完全对标 Android。

### E. arm64e / PAC 兼容性还没收口

当前已经有：

- PAC 查询
- canonical code pointer
- arm64e 风险探测
- pthread fallback 拦截

还缺：

- 真机上不同机型和系统版本的完整验证
- hook / symbol rebasing / thread bootstrap 的最终兼容结论
- 明确哪些命令在 arm64e 上只读安全、哪些有风险、哪些默认拒绝

### F. 真机注入闭环还没收尾

README 已明确写了还没完成：

- 完整越狱注入链路真机验证
- 外部 hook backend 适配层
- 完整 arm64e/PAC 真机兼容性收尾

因此当前 iOS 版的代码结构已经基本够用，但最终稳定性结论还不能直接等同 Android 版。

## 后续开发顺序

### Phase 0: 固定对标基线和命令规范

目标：

- 不再口头说“对标安卓版”，而是固定引用 `rustFrida-master` 的具体目录和文件
- 每新增一个 iOS 命令，都写清楚它在 Android 对标面里属于哪一类能力

验收：

- 以后所有新增命令的提交说明里都要写明“对标 Android 哪个目录/文件”

### Phase 1: 先补 Mach-O 深层查询

原因：

- 这一块最适合当前阶段继续推进
- 不依赖真机稳定性验证
- 主要是 host 可测、结构清晰、增量安全

建议顺序：

1. `native.dyldInfo <module>`
2. `native.linkedit <module>`
3. `native.functionStarts <module>`
4. `native.dataInCode <module>`
5. `native.codeSignature <module>`
6. `native.exportsTrie <module>`
7. `native.chainedFixups <module>`

每个命令统一走这条开发链：

1. `native-api/src/<feature>.rs` 增加底层结构和解析
2. `native-api/src/lib.rs` 导出
3. `quickjs-runtime/src/native.rs` 注册 JS Native API
4. `quickjs-runtime/src/agent_api.rs` 增加文本格式和结构化格式
5. `common/src/command.rs` 增加 legacy parser
6. `agent/src/lib.rs` 增加 parser 测试
7. `controller/src/injection.rs` 增加 help、inline-hook 判断和测试
8. `quickjs-runtime/src/runtime.rs` 增加 structured/text 两套测试
9. `README.md` 更新命令清单和说明

验收标准：

- Linux host 单测全绿
- `--command-json` 有稳定字段
- 普通 REPL 文本输出可读
- 对空模块名、模块不存在、平台不支持都能稳定返回

### Phase 2: 补 ObjC 元数据查询

建议顺序：

1. `objc.protocols`
2. `objc.classProtocols`
3. `objc.protocolMethods`
4. `objc.properties`
5. `objc.ivars`
6. `objc.superclass`
7. `objc.classChain`

原因：

- 这一块最能直接提升 iOS 对标 Android `Java.inspect` 体验
- 对逆向使用者价值很高
- 依赖的 runtime API 较清晰

### Phase 3: 补 Swift 更深元数据

建议顺序：

1. `swift.vtable`
2. `swift.witnessTable`

原因：

- 当前 Swift 能查“符号和方法”，但查“类型内部结构”的能力还不够
- 这部分越往后越容易碰 ABI 细节，需要在 ObjC 元数据之后做

### Phase 4: 做 hook 生态兼容与降级策略

内容：

- 外部 backend 共存策略
- query-only 之外的细粒度能力矩阵
- 安装型命令的按 backend 降级
- 冲突环境下更精确的提示与拒绝条件

原因：

- 这块不属于“多写几个命令”能解决的问题
- 需要在查询能力补得差不多后再处理

### Phase 5: 真机兼容性和回归

内容：

- rootless / rootful
- arm64 / arm64e
- iOS 版本跨度
- 典型系统进程与普通 App
- 外部 backend 已加载与未加载两种环境

说明：

- 这一步你已经明确说现在先不做
- 所以前四个 phase 应该尽量都按 host 可验证方式先写完

## 建议维护的待办列表

### 第一优先级

- `native.dyldInfo <module>`
- `native.linkedit <module>`

### 第二优先级

- `native.functionStarts <module>`
- `native.dataInCode <module>`
- `native.codeSignature <module>`

### 第三优先级

- 外部 hook backend 适配层
- arm64e / PAC 真机收尾

## 每个新功能的固定开发模板

后面每次加新命令，统一按下面模板执行，不再临时发挥。

### 1. 先写目标

- 命令名
- 对应底层结构
- 文本输出字段
- JSON 输出字段
- 平台支持范围

### 2. 先写失败语义

- 空参数
- 模块不存在
- load command 缺失
- 非 Apple target
- 当前模块类型不适用

### 3. 再写代码链

- `native-api`
- `quickjs-runtime/native.rs`
- `quickjs-runtime/agent_api.rs`
- `common/command.rs`
- `agent`
- `controller`
- `runtime tests`
- `README`

### 4. 最后统一验证

- `cargo test -p native-api --target x86_64-unknown-linux-gnu`
- `cargo test -p common --target x86_64-unknown-linux-gnu`
- `cargo test -p quickjs-runtime --target x86_64-unknown-linux-gnu`
- `cargo test -p agent --target x86_64-unknown-linux-gnu`
- `cargo test -p controller --target x86_64-unknown-linux-gnu`

## 待查资料

下面这些是后续继续做时必须查的资料，不要靠印象写。

### 1. Mach-O / dyld 相关

要查什么：

- `LC_DYLD_INFO` / `LC_DYLD_INFO_ONLY` 的字段语义
- `LC_DYLD_CHAINED_FIXUPS`
- `LC_DYLD_EXPORTS_TRIE`
- `LC_FUNCTION_STARTS`
- `LC_DATA_IN_CODE`
- `LC_CODE_SIGNATURE`
- `__LINKEDIT` 地址换算规则

为什么要查：

- `native.dyldInfo`、`native.linkedit`、`native.functionStarts`、`native.codeSignature` 都依赖这些定义
- 这部分如果只按经验写，很容易把 file offset / vmaddr / linkedit base 搞混

建议资料：

- Apple OSS XNU：`mach-o/loader.h`
- Apple OSS dyld：`include/mach-o/fixup-chains.h`
- Apple OSS dyld 仓库本身的 `mach_o/` 目录

参考链接：

- https://github.com/apple-oss-distributions/xnu
- https://github.com/apple-oss-distributions/dyld
- https://developer.apple.com/documentation/xcode-release-notes/xcode-13-release-notes

### 2. Objective-C runtime 元数据

要查什么：

- `class_copyIvarList`
- `class_copyPropertyList`
- `objc_copyProtocolList`
- `class_copyProtocolList`
- `protocol_copyMethodDescriptionList`
- `property_getAttributes`
- `ivar_getTypeEncoding`
- `ivar_getOffset`

为什么要查：

- `objc.ivars` / `objc.properties` / `objc.protocols` 都直接依赖 runtime API
- 需要确认 class / metaclass 上的属性和协议该怎么区分

参考链接：

- https://developer.apple.com/documentation/objectivec/objective-c-runtime
- https://developer.apple.com/documentation/objectivec/class_copyivarlist%28_%3A_%3A%29
- https://developer.apple.com/library/archive/documentation/General/Conceptual/CocoaEncyclopedia/Introspection/Introspection.html

### 3. Swift metadata

要查什么：

- 哪些 Swift 元数据能稳定从运行中镜像直接拿
- nominal type descriptor / protocol conformance / witness table 的边界
- arm64e/PAC 下 Swift 符号地址是否需要额外规范化

为什么要查：

- Swift 这块 ABI 细节多，不能像 ObjC 一样完全凭 runtime C API

建议资料方向：

- Apple Swift runtime / ABI 文档
- Swift 官方仓库里的 ABI 文档和 metadata 定义

## 当前结论

接下来的主线应该是：

1. 先补 Mach-O 深层查询
2. 再补 ObjC 元数据
3. 再补 Swift 深元数据
4. 最后做 hook 生态适配和真机回归

具体到下一步，文档完成后，第一个要开写的仍然是：

- `native.dyldInfo <module>`

但本轮先不写实现，只以这份文档作为后续开发的统一基线。
