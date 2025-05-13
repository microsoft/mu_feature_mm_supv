use std::path::PathBuf;

const ENV_KEY: &str = "TEST_AUX_PECOFF_VALIDATION_LIB_DIR";

fn main() {
    println!("cargo::rerun-if-env-changed={}", ENV_KEY);
    println!("cargo::rerun-if-changed=build.rs");

    let path = std::env::var(ENV_KEY).unwrap_or_default();
    let path_buf = PathBuf::from(&path);
    if path_buf.exists() {
        println!(
            "cargo::rerun-if-changed={}",
            path_buf.join("BasePeCoffValidationLib.obj").display()
        );
    }
    println!("cargo:rustc-link-search={path}");
    println!("cargo:rustc-link-lib=static=BasePeCoffValidationLib");
}
