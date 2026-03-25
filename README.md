# rustFrida iOS Branch

这个分支只保留 iOS 越狱版实现。

代码位于 `ios-rustfrida/`：

- `common`
- `controller`
- `agent`
- `quickjs-runtime`
- `objc-api`
- `native-api`

常用命令：

```bash
cd ios-rustfrida

# Linux / 通用主机：单测、打包、doctor、部署
cargo test -p native-api --target x86_64-unknown-linux-gnu
cargo test -p objc-api --target x86_64-unknown-linux-gnu
cargo test -p quickjs-runtime --target x86_64-unknown-linux-gnu
cargo test -p agent --target x86_64-unknown-linux-gnu
cargo test -p controller --target x86_64-unknown-linux-gnu
scripts/doctor-jailbreak.sh root@iphone.local
scripts/doctor-jailbreak.sh --json root@iphone.local
scripts/deploy-agent-jailbreak.sh root@iphone.local
RUN_DOCTOR=json scripts/deploy-agent-jailbreak.sh root@iphone.local
scripts/package-agent-deb.sh rootless
scripts/package-agent-deb.sh rootful
scripts/install-agent-deb-jailbreak.sh root@iphone.local
BUILD_DEB=1 scripts/package-artifacts.sh

# Apple host 才能跑：controller dyld / preflight / inject / command
cargo run -p controller -- --pid 1234 --preflight-only
cargo run -p controller -- --pid 1234 --preflight-only --preflight-json
cargo run -p controller -- --list-images --list-images-json
cargo run -p controller -- --pid 1234 --inject-json
cargo run -p controller -- --pid 1234 --command "objc.classes UIView"
cargo run -p controller -- --pid 1234 --command "native.images UIKit" --command-json
```

主机平台要求：

- Linux 主机目前可做：`cargo test`、agent 打包、`.deb` 安装包生成、`doctor-jailbreak.sh`、`deploy-agent-jailbreak.sh`、`install-agent-deb-jailbreak.sh`。
- Linux 主机目前不能做：controller 的 `--list-images`、`--preflight-only`、`--inject-json`、`--command-json`。这些路径底层依赖 dyld / Mach 注入实现，当前代码只在 Apple targets 上启用。
- 也就是说，真机注入前体检、真正注入、一次性执行 runtime 命令这三类 controller 能力，目前都需要 Apple host。
- 上面命令块里凡是 controller 直接对 iOS 目标做事的命令，都应在 macOS / Apple host 上运行；Linux 上即使能把 CLI 编出来，也会返回 `unsupported`。

最近补上的 iOS 运行时能力：

- `ObjC.methods(className[, isClassMethod])`
- `ObjC.findMethods(className, query[, isClassMethod])`
- `ObjC.findMethodOwners(query[, isClassMethod])`
- `ObjC.classImage(className)`
- `ObjC.methodImage(className, selectorName[, isClassMethod])`
- `Swift.findMethods(typeName, methodQuery[, moduleName])`
- agent / controller CLI:
  - `hfl <module> <offset>`
  - `hfl status`
  - `hfl stop`
  - `hfl stop <module> <offset>`
  - `jhook <class> <selector> [meta]`
  - `jhook status`
  - `jhook stop`
  - `jhook stop <class> <selector> [meta]`
  - `objc.methodImp <class> <selector> [meta]`
  - `objc.classImage <class>`
  - `objc.methodImage <class> <selector> [meta]`
  - `objc.methodOwners <selector> [meta]`
  - `objc.methods <class> [meta] [filter]`
  - `objc.classes [filter]`
  - `objc.selectorName <selector>`
  - `objc.objectClassName <object>`
  - `native.base <module>`
  - `native.export <symbol>`
  - `native.export <module> -- <symbol>`
  - `native.exports <module>`
  - `native.exports <module> -- <query>`
  - `native.dependencies <module>`
  - `native.dependencies <module> -- <query>`
  - `native.encryptionInfo <module>`
  - `native.entryPoint <module>`
  - `native.sourceVersion <module>`
  - `native.buildVersion <module>`
  - `native.dylinker <module>`
  - `native.installName <module>`
  - `native.uuid <module>`
  - `native.rpaths <module>`
  - `native.rpaths <module> -- <query>`
  - `native.imports <module>`
  - `native.imports <module> -- <query>`
  - `native.loadcmds <module>`
  - `native.sections <module>`
  - `native.segments <module>`
  - `native.symbols <query>`
  - `native.symbols <module> -- <query>`
  - `native.images [filter]`
  - `native.mainImage`
  - `native.image <address>`
  - `native.symbol <address>`
  - `pac.available`
  - `pac.arm64e`
  - `pac.image <module>`
  - `pac.images [filter]`
  - `pac.strip <address>`
  - `pac.stripdata <address>`
  - `shook <type> <method>`
  - `shook <module> -- <type> <method>`
  - `shook status`
  - `shook stop`
  - `shook stop <type> <method>`
  - `shook stop <module> -- <type> <method>`
  - `trace [filter]`
  - `trace native [module] <symbol> [-- template]`
  - `trace addr <address> [-- template]`
  - `trace status`
  - `trace stop`
  - `trace stop [filter]`
  - `trace stop native [module] <symbol>`
  - `trace stop addr <address>`
  - `stalker [filter]`
  - `stalker native [module] <symbol> [-- template]`
  - `stalker addr <address> [-- template]`
  - `stalker status`
  - `stalker stop`
  - `stalker stop [filter]`
  - `stalker stop native [module] <symbol>`
  - `stalker stop addr <address>`
  - `swift.types <query>`
  - `swift.types <module> -- <query>`
  - `swift.typeKinds`
  - `swift.methodOwners <method>`
  - `swift.methodOwners <module> -- <method>`
  - `swift.typesOfKind <kind> <query>`
  - `swift.typesOfKind <module> -- <kind> <query>`
  - `swift.typeMethods <type>`
  - `swift.typeMethods <module> -- <type>`
  - `swift.methods <type> <method>`
  - `swift.methods <module> -- <type> <method>`

说明：

- Android 版目录和根 workspace 已从这个分支移除。
- controller 默认 agent 路径现在按越狱 rootless 场景优先使用 `/var/jb/usr/lib/libagent.dylib`；rootful 默认对应 `/usr/lib/libagent.dylib`。旧路径 `/usr/lib/agent.dylib` 已废弃，如果设备是 rootful 或 agent 放在别处，启动时显式传 `--agent-path <path>` 即可。
- `scripts/doctor-jailbreak.sh <user@device> [remote-agent-path]` 现在既支持文本输出，也支持 `--json` 结构化输出，便于直接接 CI 或自动化部署脚本。
- 这份远端 doctor 除了 rootless/rootful 布局、agent 目录/文件、legacy 文件名、socket path 长度、常见 hook backend 文件之外，现在还会尽量检查 agent 是否像 Mach-O 动态库、以及远端二进制检查工具能否看见 `ios_agent_entry`。
- `scripts/deploy-agent-jailbreak.sh` 现在默认会在推送 `libagent.dylib` 后自动跑一次 `doctor-jailbreak.sh`；如果只想推送不体检，可设 `RUN_DOCTOR=0`；如果想让部署阶段直接吐结构化结果，可设 `RUN_DOCTOR=json`，此时会输出单个 deploy+doctor JSON，而不是文本日志和 JSON 混杂。
- `scripts/package-agent-deb.sh [rootless|rootful]` 现在可以直接把 `libagent.dylib` 打成越狱设备可安装的 `.deb`；默认 `rootless`，会安装到 `/var/jb/usr/lib/libagent.dylib`，`rootful` 则安装到 `/usr/lib/libagent.dylib`。
- `scripts/install-agent-deb-jailbreak.sh <user@device> [deb-path]` 可以把本地 `.deb` 推到越狱设备并执行 `dpkg -i`；如果不手动给包路径，会按设备的 rootless/rootful 布局从 `dist/` 自动挑最新的匹配包。
- `scripts/package-artifacts.sh` 现在在 `dpkg-deb` 可用时会顺手产出 `rootless/rootful` 两份 `.deb`；如果要显式控制，可用 `BUILD_DEB=1` 或 `BUILD_DEB=0`。
- 根目录 release workflow 现在也会在 macOS runner 上补装 `dpkg`，把 tarball 和 `.deb` 一起作为 GitHub Release asset 输出。
- `.deb` 产物拿到手后，rootless 设备装 `..._iphoneos-arm64_rootless.deb`，rootful 设备装 `..._iphoneos-arm_rootful.deb`；常见安装方式就是设备上执行 `dpkg -i <package>.deb`，装完后 controller 默认会去对应路径找 `libagent.dylib`。
- 对 `dpkg --print-architecture` 是 `iphoneos-arm64e` 的 rootless 设备，现在也会额外产出并优先选择 `..._iphoneos-arm64e_rootless.deb`；如果不手动给包路径，`scripts/install-agent-deb-jailbreak.sh` 会先探测远端架构，再从 `dist/` 自动挑最匹配的 rootless/rootful 包。
- 如果不想打 tag，GitHub Actions 里现在可以直接手动运行 `ios-rustfrida-package` workflow；它会在 macOS runner 上构建 agent/controller，并把 tarball 和 `.deb` 作为 `ios-rustfrida-package-bundles` artifact 上传。
- 手动包工作流的默认产物里会包含：
  - `ios-rustfrida-agent-aarch64-apple-ios.tar.gz`
  - `ios-rustfrida-controller-<host-triple>.tar.gz`
  - `ios-rustfrida-agent_<version>_iphoneos-arm64_rootless.deb`
  - `ios-rustfrida-agent_<version>_iphoneos-arm64e_rootless.deb`
  - `ios-rustfrida-agent_<version>_iphoneos-arm_rootful.deb`
- GitHub Actions 需要放在仓库根目录 `.github/workflows/`；`ios-rustfrida/.github/workflows/` 里的文件仅作子 workspace 镜像参考，真正触发以根目录 workflow 为准。
- `quickjs-runtime` 需要的 ARM64 hook engine 已 vendored 到 `ios-rustfrida/quickjs-runtime/hook-engine-src/`。
- iOS 功能目前仍是持续迁移状态，不应视为和 Android 版完全对齐。
- 当前已经补到可做 ObjC 类/selector/IMP/方法枚举、Swift 符号查找、PAC 查询、dyld 镜像枚举、基础 hook 环境探测。
- hook backend filesystem 探测现在同时覆盖 rootful 和 rootless 常见路径前缀；像 ElleKit / Substrate / Substitute / libhooker 这类生态，不再只认 `/usr/lib`，也会扫描 `/var/jb/...`。
- `native.hookenv` / `Native.detectHookEnvironment()` 现在除了 backend / warning，还会补出面向当前 `hook_policy` 的建议动作，便于真机上快速判断该走 query-only、fail-fast 还是继续冒险装 inline hook；返回里也会区分 `allowed` 和 `inlineHooksAllowed`，不再把“允许注入做查询”和“允许安装 inline hook”混成一个布尔值。
- `PAC.isImageArm64e(moduleName)` / `pac.image <module>` 现在可以直接判断单个镜像是否是 `arm64e`，比只看当前进程主镜像更适合排查某个目标 dylib 是否已经进入 PAC 风险面。
- `PAC.arm64eImages([query])` / `pac.images [filter]` 现在可以直接列出当前进程里的 `arm64e` 镜像，适合先收敛 PAC 风险面，再决定具体看哪个模块。
- `quickjs-runtime` 里的 `callNative()` 现在明确沿用 canonical code pointer 路径，避免 PAC 场景下把已规范化的入口又当成 raw 指针处理。
- Mach 注入链路现在会回读远程 bootstrap 状态；可用 `IOS_RUSTFRIDA_BOOTSTRAP_WAIT_MS` 控制轮询等待时长，设为 `0` 表示关闭等待。
- Mach bootstrap 远程内存现已拆成代码段和参数/状态段，分别走 `RX` / `RW` 权限，不再依赖单块 `RWX` payload。
- 远程 Mach 内存分配现在按页对齐申请，并在 `mach_vm_protect` 上带降级处理，减少真机上因页粒度或 `set_maximum` 差异导致的失败。
- controller / dry-run 输出里的远程 bootstrap 大小现在区分“实际使用字节数”和“页对齐后的实际分配字节数”，便于排查权限与页粒度问题。
- 注入 trace / dry-run 输出现在会带上目标进程是否 `arm64e` 的探测结果，便于快速判断是否已经进入 PAC 风险区。
- 如果目标进程是 `arm64e` 且线程 bootstrap 只能退化到 `pthread_create`，注入现在默认拒绝；确实要强制走 fallback 时需显式设置 `IOS_RUSTFRIDA_ALLOW_ARM64E_PTHREAD_FALLBACK=1`。
- 注入 trace / bootstrap summary 现在会显式打印 `thread_bootstrap_kind`，直接区分 `pthread_create_from_mach_thread` 和 `pthread_create` fallback。
- controller 在打印注入计划里的 loader symbols 时，也会对 `thread-bootstrap` 符号补出 `kind=...`，便于在真正开始远程写入前先看出是否会走 fallback。
- controller 现在会在正式远程写入前先执行一次目标 preflight，提前打印目标是否 `arm64e`、thread bootstrap 模式、以及 thread bootstrap 地址是否经过 canonical 化。
- 这份目标 preflight 现在还会带出目标进程 dyld 镜像摘要，包括主镜像路径/基址和当前镜像总数，方便先判断注入对象是否就是预期目标，以及后续 Swift / dyld / hook 冲突排查时的上下文是否一致。
- 这份 preflight 现在还会直接带出目标进程的 dyld 镜像列表；文本模式默认预览前几条，`--preflight-json` 会给全量 `targetImages`。
- `preflight-json` / `inject-json` 现在还会补 `loaderSymbolChecks`，直接检查 rebased loader symbol 是否在目标镜像列表里找到对应模块，以及 `address == image.base + offset` 是否成立。
- controller 现在会把这次 preflight 结果直接复用到正式注入，减少一次重复的远端 loader symbol / arm64e 探测。
- 如果只想先看目标 `arm64e / hook backend / loader symbol / dyld` 状态而不真的写远端内存，现在可以直接加 `--preflight-only`；controller 会输出完整 plan + preflight 后退出。
- 如果后面要接自动化脚本，`--preflight-only --preflight-json` 会直接输出结构化 JSON，里面包含 `environment / doctor / plan / preflight` 四块。
- 其中 `doctor` 会把注入前最常见的本地/配置问题单独收出来，例如 agent 路径布局、是否还在用旧的 `agent.dylib` 文件名、socket path 是否逼近 Darwin 长度限制、bootstrap script 是否可读、以及本地/目标 hook strategy 是否已经把注入挡住。
- `--list-images --list-images-json` 会输出当前控制器进程可见的 dyld 镜像列表，字段和 `preflight.targetImages` 对齐。
- `--inject-json` 会把正式注入链路的 `environment / plan / preflight / trace / handshake` 汇总成单个 JSON；如果当前平台不支持，也会返回结构化错误 JSON。
- `--inject-json` 现在也会把同一份 `doctor` 结果一起带上，便于在注入失败时先分辨是“路径/脚本/socket 配置问题”，还是后面的 Mach/bootstrap/handshake 问题。
- `--inject-json` 在注入或握手失败时，现在也会尽量保留 `environment / plan / preflight`，并额外补 `diagnostics.phase / diagnostics.code / diagnostics.hints`，方便脚本或真机联调时直接分辨是 `task_for_pid`、remote bootstrap、controller socket，还是后续 handshake/script 阶段出错。
- Mach 侧常见失败现在也会细分出更明确的阶段码，例如 `mach-vm-allocate / mach-vm-write / mach-vm-protect / mach-vm-read / task-dyld-info / thread-create-running`，并在底层错误文本里附带更具体的 kernel hint，减少真机上看到一串 `state error` 却不知道该先查哪一步的情况。
- `--inject-json` 里的 `handshake.stage` 现在也会直接标出当前卡在 `awaiting-hello / awaiting-ping / awaiting-hook-environment / awaiting-jsinit / awaiting-loadjs / completed` 哪一步；`hookEnvironmentChecked` 用来区分“这一步已经成功执行但没有 notice”与“这一步还没跑到”。
- `--inject-json` 里的 `handshake.steps` 现在会把 `hello / ping / hookEnvironment / jsInit / loadJs` 分别标成 `pending / succeeded / skipped / failed` 之一；实际失败点也会同步体现在 `diagnostics.failedStep`，便于脚本直接定位。
- `--inject-json` 里的 `handshake.errors` 现在会把 `hello / ping / hookEnvironment / jsInit / loadJs` 对应阶段的失败消息单独拆出来；如果某一步没有失败则该字段为 `null`。
- `--inject-json` 现在连注入前的 `controller script read failed`、`controller socket bind failed` 这类错误也会尽量保留 `environment / plan / preflight` 并给出结构化 `diagnostics`，不再直接退化成只有顶层错误文本。
- 现在也可以在一次性注入后直接跑单条命令：`--command "<cmd>"`。适合自动化里做单发查询或 hook 控制，不必先进 REPL。
- 如果要给脚本消费结果，可以在 `--command` 基础上加 `--command-json`；输出单个 JSON，包含 `ok / command / kind / payload / payloadJson / items / error / logs`。
- `--command-json` 会静默完成握手和可选 bootstrap script，不再把 plan / trace / hello/ping 文本混到命令结果前面；如果命令前阶段失败，也会返回结构化错误 JSON。
- `--command-json` 在命令真正执行前就失败时，现在也会附带 `environment / doctor / plan / preflight / trace / diagnostics / handshake` 上下文，方便脚本直接区分是注入前配置问题、bootstrap 问题，还是命令本身失败。
- 对 `objc.* / native.* / pac.* / swift.*` 这类 runtime 查询命令，`--command-json` 现在也会尽量回传稳定的 `payloadJson` 字段，里面直接带 `count / classes / methods / images / symbols / types / report / text` 等结构化内容，不再只能从换行文本里二次解析。
- 其中 `native.symbols / native.exports / native.segments / native.sections / native.loadcmds / swift.symbols / swift.types / swift.methodOwners / swift.typeMethods / swift.methods` 这批结果现在也会补出更稳定的定位字段，例如 `moduleBase / offsetHex / sourceSymbolName / sourceOffsetHex`；`native.images / native.mainImage / pac.images` 里的镜像项也会顺手带 `name`，脚本侧不必再自己拆 basename。
- `native.dependencies <module> [-- <query>]` 现在也已接到 CLI / REPL / `--command-json`；结构化结果会带 `dependencies / ordinal / kind / path / currentVersion / compatibilityVersion / timestamp`，适合先看一个镜像依赖树，再结合 `native.imports` 缩小目标符号来源。
- `native.encryptionInfo <module>` 现在也已接到 CLI / REPL / `--command-json`；结构化结果会带 `encryptionInfo / cryptoff / cryptsize / cryptid`，适合快速确认目标 Mach-O 是否声明了加密区以及范围。
- `native.entryPoint <module>` 现在也已接到 CLI / REPL / `--command-json`；结构化结果会带 `entryPoint / entryoff / stacksize`，适合快速确认 `LC_MAIN` 指向的主入口偏移。
- `native.sourceVersion <module>` 现在也已接到 CLI / REPL / `--command-json`；结构化结果会带 `sourceVersion / version`，适合快速对齐 Mach-O 自带的 source version 字段。
- `native.buildVersion <module>` 现在也已接到 CLI / REPL / `--command-json`；结构化结果会带 `buildVersion / platform / minOs / sdk / tools`，适合直接确认目标镜像的 build platform 和工具链版本。
- `native.dylinker <module>` 现在也已接到 CLI / REPL / `--command-json`；结构化结果会带 `dylinker / path / kind`，适合直接确认某个 Mach-O 记录的 dyld linker 路径。
- `native.installName <module>` 现在也已接到 CLI / REPL / `--command-json`；结构化结果会带 `installName / path / currentVersion / compatibilityVersion / timestamp`，适合快速确认某个 dylib 自身声明的 install name 和版本信息。
- `native.uuid <module>` 现在也已接到 CLI / REPL / `--command-json`；结构化结果会带 `imageUuid / uuid`，适合把运行中镜像和 dSYM / 本地 Mach-O 做快速 UUID 对齐。
- `native.rpaths <module> [-- <query>]` 现在也已接到 CLI / REPL / `--command-json`；结构化结果会带 `rpaths / path`，适合和 `native.dependencies` 一起排查运行时 dylib 查找路径。
- `native.imports <module> [-- <query>]` 现在也已接到 CLI / REPL / `--command-json`；当前实现基于 Mach-O undefined symbol 表，结构化结果会带 `imports / dylibOrdinal / dylibName / weakImport`，适合先看一个镜像依赖了哪些外部符号，再决定后续 trace/hook 目标。
- 对 `hfl / jhook / shook / trace / stalker` 这类 controller dispatch 命令，`--command-json` 现在也会尽量回传结构化 `payloadJson`，包含 `action / kind / target / count / key / moduleName / selectorName / resolvedLabel / targetAddress / filter / replacedCount` 等字段；对应的 `*.status` 结果也会补出当前 active state 和 target 元数据，像 `hfl/jhook/shook` 不再只有 key/count；`*.stop` 结果现在也会把被回收的 key/target 一并带回，`trace.stop / stalker.stop` 也会继续带上实际 detach 计数。
- 对同一批 `*.status` 控制命令，普通文本模式的 `--command` / REPL 输出现在也不再只回一行 `active: N`；会附带当前 target / filter / symbol / Swift 命中项摘要，真机交互排查时不必每次都切到 `--command-json`。
- `hfl/jhook/shook` 现在除了 `stop` 全停，也支持按目标定向停止；对应的普通文本模式 `*.stop` 输出也会和 `*.status` 一样附带命中的 target 摘要，适合 REPL 下快速确认到底停掉了哪一个 hook。
- `hfl/jhook/shook` 的 `install/status` 结构化结果现在也会补 `currentKey / currentTarget`；其中 install 结果还会补 `replacedCount / replacedTarget`，便于脚本直接知道“当前焦点 hook 是谁”和“这次是不是覆盖了旧 key”。
- `hfl/jhook/shook stop` 的结构化结果现在也会补 `targetMatched / matchedTargetCount / matchedTargets / detachedTargetCount / detachedTargets`，脚本可以直接判断“这次 stop 是否命中了目标”和“实际拆掉了哪几个 hook”。
- `trace/stalker` 现在也支持“带选择器”的 `stop`：可以按 objc filter、native export、native address 定向尝试停止；如果当前活动 hook 和选择器不匹配，会保留现有 hook 并返回 `selector mismatch` 提示。对应结构化结果现在也会补 `selectorMatched / matchedSessionCount / matchedSessions / detachedSessionCount / detachedSessions`，脚本不必再解析文本提示判断到底有没有命中。
- `trace/stalker` 现在按目标 key 维护多会话 registry，不再只有单个活动槽位；`install/status` 的 `--command-json` 都会带回当前 `sessionCount / sessions / currentKey / currentSession`，其中 install 结果还会补 `replacedSession / replacedSessions`，方便脚本直接判断这次是否覆盖了旧会话；重复安装同一个 key 只替换该 key，本体不相关的会话会保留，裸 `stop` 则会一次回收当前全部会话。
- loader symbol 解析现在会优先使用 canonical code pointer 计算模块偏移，减少 arm64e/PAC 场景下本地 `dlsym` 地址高位污染远端 rebasing 的风险。
- 如果某个 loader symbol 的 raw 地址与 canonical 地址不同，controller 会在注入计划里同时打印两者，便于直接判断 PAC 是否介入了本地符号解析结果。
- controller 里的 `hfl/jhook/shook/trace/stalker` 指令现在统一下沉到 `quickjs-runtime` 的 `__iosRustFridaControllerApi.dispatch(...)`，controller 只负责构造结构化 spec，后续继续迁移 runtime 能力时改动面会小很多。
- 对应地，runtime 侧现在也补了 `__iosRustFridaControllerApi.dispatchResult(...)`；文本模式继续走 `dispatch(...)`，自动化模式则可以拿到结构化结果对象。
- controller 侧这些 dispatch spec 现在改成标准 JSON 生成，不再继续手写 JS object 字符串，后续字段扩展和转义会更稳。
- controller 里先前只供测试使用的遗留 `build_*_script` 包装路径也已经去掉，运行面和测试面现在都直接围绕结构化 spec 工作，不再保留第二套“拼 JS 再 dispatch”的兼容层。
- agent 里的 `objc.*` / `native.images` / `native.hookenv` / `pac.*` / `swift.*` 查询现在也开始走 `quickjs-runtime` 的 `__iosRustFridaAgentApi.handle(...)`，agent 侧重复的 Rust 格式化逻辑又收掉了一段。
- host-agent 协议现在开始补结构化命令帧：在原有字符串 `CMD` 之外新增了兼容保留的 `CMD_JSON`，controller 已经把 `ping/jsinit/loadjs/jseval/jscomplete/exit/runtime-handle` 这批自有路径切到 typed command。
- agent 侧这批 runtime 查询命令现在也开始优先走 `RuntimeDispatch` 结构化 spec，对应 `__iosRustFridaAgentApi.handleSpec(...)`；只有解析失败或旧兼容路径才会回落到原先的字符串 `handle(...)`。
- `quickjs-runtime` 里的 legacy `__iosRustFridaAgentApi.handle(...)` 现在也已经先转 spec 再复用 `handleSpec(...)`，ObjC / Native / PAC / Swift 查询不再维护两套独立执行逻辑，后续补字段时更不容易出现“structured 路径有，legacy 路径没补”的分叉。
- 在这之上，runtime 侧现在也补了 `__iosRustFridaAgentApi.handleSpecResult(...)`；文本模式继续走 `handleSpec(...)`，自动化模式则可以直接拿结构化对象。
- 在这之上，`trace/stalker/hfl/jhook/shook` 这批 controller 控制命令也已经开始走 `ControllerDispatch` 结构化 spec，不再通过 `JsEval` 把整段 dispatch JS 字符串塞给 agent。
- 旧文本命令的兼容解析现在也集中到了 `common::AgentCommand::from_legacy(...)`，controller / agent 不再各自维护一份 `ping/jsinit/runtime-handle` 的识别分支。
- controller / bootstrap 失败摘要现在会补齐代码段/数据段保护模式、线程 bootstrap 符号来源，以及失败/提前返回时远程线程是否已尝试终止。
- controller 在注入前会打印注入环境摘要：`IOS_RUSTFRIDA_DRY_RUN`、bootstrap 等待时间、hook policy / strategy、已探测到的越狱 hook backend。
- `IOS_RUSTFRIDA_HOOK_POLICY` 现在除了 `warn` / `deny-external-loaded`，还支持 `query-only-external-loaded`（可简写 `query-only`）；命中外部 backend 时，这个策略会继续允许注入、查询命令和 `status/stop` 这类非安装控制命令，但会显式禁止 `trace/stalker/jhook/shook/hfl` 的安装路径。
- 如果当前 `IOS_RUSTFRIDA_HOOK_POLICY=deny-external-loaded` 且进程里已加载 ElleKit/Substrate/Substitute/libhooker 一类外部 backend，注入会在启动前直接拒绝并给出原因。
- preflight 现在也会探测“目标进程”自身已加载的 hook backend，并打印 target hook strategy / backend 摘要；`deny-external-loaded` 不再只看 controller 当前进程，也会对目标进程生效。
- hook strategy 被本地或目标进程的外部 backend 阻断时，错误信息现在会直接附带 hook environment 摘要：active backend、各 backend 的 loaded image / filesystem path 计数、warning 数量，减少真机上只看到 `blocked` 但不知道是谁在挡路的情况。
- bootstrap 失败摘要现在会附带按状态映射的诊断提示，例如 `dlopen/dlsym/socket/connect/entry-returned/pending` 各自对应的优先排查方向，便于真机联调时快速定位是 dylib、导出符号、还是 controller socket 回连问题。
- `task_for_pid` 失败时现在会追加常见排查方向：越狱/root 上下文、`task_for_pid` 相关 entitlement/exception、目标进程平台保护限制。
- 还没完成的仍包括：完整越狱注入链路真机验证、外部 hook backend 适配层、完整 arm64e/PAC 真机兼容性收尾。
