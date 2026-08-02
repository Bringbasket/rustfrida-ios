use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=src/exception_shim.m");
    println!("cargo:rerun-if-changed=src/instance_enumeration.m");
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=IPHONEOS_DEPLOYMENT_TARGET");
    println!("cargo:rerun-if-env-changed=MACOSX_DEPLOYMENT_TARGET");

    let target = env::var("TARGET").unwrap_or_default();
    if !(target.contains("apple-ios") || target.contains("apple-darwin")) {
        return;
    }

    let host = env::var("HOST").unwrap_or_default();
    if !host.contains("apple") {
        build_without_sdk(&target);
        return;
    }

    let mut build = cc::Build::new();
    build
        .file("src/exception_shim.m")
        .file("src/instance_enumeration.m")
        .flag("-fobjc-exceptions")
        .flag("-fno-objc-arc")
        .warnings(true);

    build.compile("objc_api_exception_shim");
    println!("cargo:rustc-link-lib=objc");
}

fn build_without_sdk(target: &str) {
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("missing OUT_DIR"));
    let object = out_dir.join("exception_shim.o");
    let enumeration_object = out_dir.join("instance_enumeration.o");
    let archive = out_dir.join("libobjc_api_exception_shim.a");
    let clang_target = clang_target(target);

    run(
        Command::new("clang")
            .arg(format!("--target={clang_target}"))
            .args(["-x", "objective-c", "-fobjc-exceptions", "-fno-objc-arc", "-c"])
            .arg("src/exception_shim.m")
            .arg("-o")
            .arg(&object),
        "compile Objective-C exception shim",
    );
    run(
        Command::new("clang")
            .arg(format!("--target={clang_target}"))
            .args(["-x", "objective-c", "-fobjc-exceptions", "-fno-objc-arc", "-c"])
            .arg("src/instance_enumeration.m")
            .arg("-o")
            .arg(&enumeration_object),
        "compile Objective-C instance enumeration shim",
    );
    run(
        Command::new("llvm-ar")
            .arg("crs")
            .arg(&archive)
            .arg(&object)
            .arg(&enumeration_object),
        "archive Objective-C exception shim",
    );

    println!("cargo:rustc-link-search=native={}", out_dir.display());
    println!("cargo:rustc-link-lib=static=objc_api_exception_shim");
    println!("cargo:rustc-link-lib=objc");
}

fn clang_target(target: &str) -> String {
    let ios_version = env::var("IPHONEOS_DEPLOYMENT_TARGET").unwrap_or_else(|_| "13.0".into());
    let macos_version = env::var("MACOSX_DEPLOYMENT_TARGET").unwrap_or_else(|_| "11.0".into());
    match target {
        "aarch64-apple-ios" => format!("arm64-apple-ios{ios_version}"),
        "aarch64-apple-ios-sim" => format!("arm64-apple-ios{ios_version}-simulator"),
        "x86_64-apple-ios" => format!("x86_64-apple-ios{ios_version}-simulator"),
        "aarch64-apple-darwin" => format!("arm64-apple-macos{macos_version}"),
        "x86_64-apple-darwin" => format!("x86_64-apple-macos{macos_version}"),
        other => panic!("unsupported Apple target for Objective-C shim: {other}"),
    }
}

fn run(command: &mut Command, operation: &str) {
    let status = command
        .status()
        .unwrap_or_else(|error| panic!("failed to {operation}: {error}"));
    assert!(status.success(), "failed to {operation}: exit status {status}");
}
