use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    println!("cargo:rustc-check-cfg=cfg(quickjs_runtime_stub)");
    println!("cargo:rustc-check-cfg=cfg(quickjs_hook_engine)");
    println!("cargo:rerun-if-env-changed=QUICKJS_SRC_DIR");
    println!("cargo:rerun-if-env-changed=QUICKJS_RUNTIME_FORCE_STUB");
    println!("cargo:rerun-if-env-changed=SDKROOT");
    println!("cargo:rerun-if-env-changed=IPHONEOS_DEPLOYMENT_TARGET");
    println!("cargo:rerun-if-env-changed=MACOSX_DEPLOYMENT_TARGET");
    println!("cargo:rerun-if-changed=src/quickjs_wrapper.c");
    println!("cargo:rerun-if-changed=src/quickjs_wrapper.h");
    println!("cargo:rerun-if-changed=build.rs");

    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("missing CARGO_MANIFEST_DIR"));
    let target = env::var("TARGET").unwrap_or_default();
    let host = env::var("HOST").unwrap_or_default();

    if let Some(reason) = should_use_stub(&target, &host) {
        emit_stub(&manifest_dir, &reason);
        return;
    }

    let Some(quickjs_src) = resolve_quickjs_src(&manifest_dir) else {
        emit_stub(
            &manifest_dir,
            "QuickJS source not found; populate quickjs-runtime/quickjs-src or set QUICKJS_SRC_DIR",
        );
        return;
    };

    build_quickjs(&manifest_dir, &quickjs_src, &target);
    build_hook_engine(&manifest_dir, &target);
}

fn build_quickjs(manifest_dir: &Path, quickjs_src: &Path, target: &str) {
    for file in [
        "VERSION",
        "quickjs.c",
        "quickjs.h",
        "dtoa.c",
        "dtoa.h",
        "libregexp.c",
        "libregexp.h",
        "libunicode.c",
        "libunicode.h",
        "cutils.c",
        "cutils.h",
        "libbf.c",
        "libbf.h",
        "list.h",
    ] {
        println!("cargo:rerun-if-changed={}", quickjs_src.join(file).display());
    }

    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("missing OUT_DIR"));
    let src_dir = manifest_dir.join("src");
    let quickjs_version = std::fs::read_to_string(quickjs_src.join("VERSION"))
        .ok()
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".to_owned());
    let has_libbf = quickjs_src.join("libbf.c").exists();

    let mut build = cc::Build::new();
    build
        .file(quickjs_src.join("quickjs.c"))
        .file(quickjs_src.join("dtoa.c"))
        .file(quickjs_src.join("libregexp.c"))
        .file(quickjs_src.join("libunicode.c"))
        .file(quickjs_src.join("cutils.c"))
        .file(src_dir.join("quickjs_wrapper.c"))
        .include(quickjs_src)
        .include(&src_dir)
        .opt_level(2)
        .flag("-fPIC")
        .flag("-fno-exceptions")
        .flag(&format!("-DCONFIG_VERSION=\"{}\"", quickjs_version))
        .flag("-D_GNU_SOURCE")
        .flag_if_supported("-Wno-implicit-const-int-float-conversion")
        .warnings(false);

    if has_libbf {
        build.file(quickjs_src.join("libbf.c"));
        build.flag("-DCONFIG_BIGNUM");
    }

    if target.contains("android") {
        build.flag("-DANDROID");
    }

    if let Some(flag) = apple_min_version_flag(target) {
        build.flag(&flag);
    }

    build.compile("quickjs_runtime_native");

    let mut bindings = bindgen::Builder::default()
        .header(quickjs_src.join("quickjs.h").to_string_lossy().to_string())
        .header(src_dir.join("quickjs_wrapper.h").to_string_lossy().to_string())
        .clang_arg(format!("-I{}", quickjs_src.display()))
        .clang_arg(format!("-I{}", src_dir.display()))
        .clang_arg("-xc")
        .allowlist_function("JS_.*")
        .allowlist_function("js_.*")
        .allowlist_function("__JS_.*")
        .allowlist_function("qjs_.*")
        .allowlist_type("JS.*")
        .allowlist_var("JS_.*")
        .derive_debug(true)
        .derive_default(true)
        .generate_comments(true)
        .layout_tests(false);

    if let Some(args) = apple_bindgen_clang_args(target) {
        for arg in args {
            bindings = bindings.clang_arg(arg);
        }
    }

    let bindings = bindings.generate().expect("Unable to generate QuickJS bindings");

    bindings
        .write_to_file(out_dir.join("quickjs_bindings.rs"))
        .expect("Couldn't write QuickJS bindings");
}

fn build_hook_engine(manifest_dir: &Path, target: &str) {
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("missing OUT_DIR"));

    if !supports_hook_engine(target) {
        std::fs::write(
            out_dir.join("hook_bindings.rs"),
            "// hook engine unavailable for this target\n",
        )
        .expect("failed to write placeholder hook bindings");
        return;
    }

    let Some(hook_src) = resolve_hook_engine_src(manifest_dir) else {
        std::fs::write(out_dir.join("hook_bindings.rs"), "// hook engine sources not found\n")
            .expect("failed to write placeholder hook bindings");
        println!(
            "cargo:warning=ARM64 hook engine sources not found under quickjs-runtime/hook-engine-src; hook/unhook will stay unavailable"
        );
        return;
    };

    for file in [
        "hook_engine.c",
        "hook_engine.h",
        "hook_engine_internal.h",
        "hook_engine_mem.c",
        "hook_engine_inline.c",
        "hook_engine_redir.c",
        "arm64_writer.c",
        "arm64_writer.h",
        "arm64_relocator.c",
        "arm64_relocator.h",
        "arm64_common.h",
    ] {
        println!("cargo:rerun-if-changed={}", hook_src.join(file).display());
    }

    let include_dir = manifest_dir.join("include");
    let mut build = cc::Build::new();
    build
        .file(hook_src.join("hook_engine.c"))
        .file(hook_src.join("hook_engine_mem.c"))
        .file(hook_src.join("hook_engine_inline.c"))
        .file(hook_src.join("hook_engine_redir.c"))
        .file(hook_src.join("arm64_writer.c"))
        .file(hook_src.join("arm64_relocator.c"))
        .include(&hook_src)
        .opt_level(2)
        .flag("-fPIC")
        .flag("-fno-exceptions")
        .warnings(false);

    if target.contains("apple") {
        println!("cargo:rerun-if-changed={}", include_dir.join("sys/prctl.h").display());
        build.include(&include_dir);
    }

    if let Some(flag) = apple_min_version_flag(target) {
        build.flag(&flag);
    }

    build.compile("quickjs_runtime_hook_engine");

    let mut bindings = bindgen::Builder::default()
        .header(hook_src.join("hook_engine.h").to_string_lossy().to_string())
        .header(hook_src.join("arm64_writer.h").to_string_lossy().to_string())
        .header(hook_src.join("arm64_relocator.h").to_string_lossy().to_string())
        .clang_arg(format!("-I{}", hook_src.display()))
        .clang_arg("-xc")
        .allowlist_function("hook_.*")
        .allowlist_function("arm64_writer_.*")
        .allowlist_function("arm64_relocator_.*")
        .allowlist_type("Hook.*")
        .allowlist_type("Arm64.*")
        .allowlist_var("ARM64_.*")
        .derive_debug(true)
        .derive_default(true)
        .generate_comments(true)
        .layout_tests(false);

    if target.contains("apple") {
        bindings = bindings.clang_arg(format!("-I{}", include_dir.display()));
    }

    if let Some(args) = apple_bindgen_clang_args(target) {
        for arg in args {
            bindings = bindings.clang_arg(arg);
        }
    }

    bindings
        .generate()
        .expect("Unable to generate hook engine bindings")
        .write_to_file(out_dir.join("hook_bindings.rs"))
        .expect("Couldn't write hook engine bindings");

    println!("cargo:rustc-cfg=quickjs_hook_engine");
}

fn resolve_quickjs_src(manifest_dir: &Path) -> Option<PathBuf> {
    if let Some(path) = env::var_os("QUICKJS_SRC_DIR") {
        let path = PathBuf::from(path);
        if has_quickjs_sources(&path) {
            return Some(path);
        }
    }

    let local = manifest_dir.join("quickjs-src");
    if has_quickjs_sources(&local) {
        return Some(local);
    }

    None
}

fn resolve_hook_engine_src(manifest_dir: &Path) -> Option<PathBuf> {
    let local = manifest_dir.join("hook-engine-src");
    if has_hook_engine_sources(&local) {
        return Some(local);
    }

    None
}

fn has_quickjs_sources(path: &Path) -> bool {
    path.join("quickjs.c").exists() && path.join("quickjs.h").exists()
}

fn has_hook_engine_sources(path: &Path) -> bool {
    path.join("hook_engine.c").exists()
        && path.join("hook_engine.h").exists()
        && path.join("hook_engine_mem.c").exists()
        && path.join("hook_engine_inline.c").exists()
        && path.join("hook_engine_redir.c").exists()
        && path.join("arm64_writer.c").exists()
        && path.join("arm64_relocator.c").exists()
}

fn supports_hook_engine(target: &str) -> bool {
    target.contains("aarch64")
}

fn should_use_stub(target: &str, host: &str) -> Option<String> {
    if env::var_os("QUICKJS_RUNTIME_FORCE_STUB").is_some() {
        return Some("QUICKJS_RUNTIME_FORCE_STUB is set".into());
    }

    if target.contains("apple") && !host.contains("apple") {
        return Some(
            "cross-compiling QuickJS for Apple targets from a non-Apple host requires an Apple SDK and target C toolchain; using the stub backend for cargo check".into(),
        );
    }

    None
}

fn apple_bindgen_clang_args(target: &str) -> Option<Vec<String>> {
    let (sdk, clang_target) = match target {
        "aarch64-apple-ios" => ("iphoneos", format!("arm64-apple-ios{}", ios_deployment_target())),
        "aarch64-apple-ios-sim" => (
            "iphonesimulator",
            format!("arm64-apple-ios{}-simulator", ios_deployment_target()),
        ),
        "x86_64-apple-ios" => (
            "iphonesimulator",
            format!("x86_64-apple-ios{}-simulator", ios_deployment_target()),
        ),
        "aarch64-apple-darwin" => ("macosx", format!("arm64-apple-macos{}", macos_deployment_target())),
        "x86_64-apple-darwin" => ("macosx", format!("x86_64-apple-macos{}", macos_deployment_target())),
        _ => return None,
    };

    let sdk_path = env::var("SDKROOT")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| xcrun_sdk_path(sdk));

    Some(vec![format!("--target={clang_target}"), "-isysroot".into(), sdk_path])
}

fn apple_min_version_flag(target: &str) -> Option<String> {
    match target {
        "aarch64-apple-ios" => Some(format!("-miphoneos-version-min={}", ios_deployment_target())),
        "aarch64-apple-ios-sim" | "x86_64-apple-ios" => {
            Some(format!("-mios-simulator-version-min={}", ios_deployment_target()))
        }
        "aarch64-apple-darwin" | "x86_64-apple-darwin" => {
            Some(format!("-mmacosx-version-min={}", macos_deployment_target()))
        }
        _ => None,
    }
}

fn ios_deployment_target() -> String {
    env::var("IPHONEOS_DEPLOYMENT_TARGET")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| "13.0".into())
}

fn macos_deployment_target() -> String {
    env::var("MACOSX_DEPLOYMENT_TARGET")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| "11.0".into())
}

fn xcrun_sdk_path(sdk: &str) -> String {
    let output = Command::new("xcrun")
        .args(["--sdk", sdk, "--show-sdk-path"])
        .output()
        .unwrap_or_else(|err| panic!("failed to run xcrun for sdk `{sdk}`: {err}"));
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        panic!("xcrun --sdk {sdk} --show-sdk-path failed: {stderr}");
    }

    let path = String::from_utf8(output.stdout).expect("xcrun sdk path is not valid UTF-8");
    let path = path.trim();
    if path.is_empty() {
        panic!("xcrun returned an empty SDK path for `{sdk}`");
    }
    path.to_owned()
}

fn emit_stub(manifest_dir: &Path, reason: &str) {
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("missing OUT_DIR"));
    std::fs::write(out_dir.join("quickjs_bindings.rs"), "// quickjs-runtime stub backend\n")
        .expect("failed to write stub bindings");
    std::fs::write(
        out_dir.join("hook_bindings.rs"),
        "// hook engine unavailable in stub build\n",
    )
    .expect("failed to write stub hook bindings");
    println!("cargo:rustc-cfg=quickjs_runtime_stub");
    println!("cargo:warning={reason}");

    let local = manifest_dir.join("quickjs-src");
    println!("cargo:rerun-if-changed={}", local.display());
}
