use std::env;

fn main() {
    println!("cargo:rustc-check-cfg=cfg(native_api_apple_hook_backend)");
    println!("cargo:rerun-if-changed=build.rs");

    if env::var("CARGO_CFG_TARGET_VENDOR").as_deref() == Ok("apple") {
        println!("cargo:rustc-cfg=native_api_apple_hook_backend");
    }
}
