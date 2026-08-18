use std::path::PathBuf;

const ENV_KEY: &str = "TEST_AUX_PECOFF_VALIDATION_LIB_DIR";
const MAP_ENV_KEY: &str = "TEST_AUX_MM_SUPERVISOR_CORE_MAP_PATH";

fn main() {
    println!("cargo::rerun-if-env-changed={}", ENV_KEY);
    println!("cargo::rerun-if-changed=build.rs");

    let path = std::env::var(ENV_KEY).unwrap_or_default();
    if path.is_empty() {
        panic!(
            "{ENV_KEY} is not set. Set it to the directory containing BasePeCoffValidationLib.lib, \
             e.g. Build/<PKG>/<TARGET>_<TOOLCHAIN>/X64/SeaPkg/Library/BasePeCoffValidationLib/\
             BasePeCoffValidationLib/OUTPUT"
        );
    }

    let path_buf = PathBuf::from(&path);
    if !path_buf.join("BasePeCoffValidationLib.lib").exists() {
        panic!(
            "{ENV_KEY} is set to `{path}`, but BasePeCoffValidationLib.lib was not found there. \
             Build SeaPkg before building test-aux."
        );
    }

    println!(
        "cargo::rerun-if-changed={}",
        path_buf.join("BasePeCoffValidationLib.obj").display()
    );
    println!("cargo:rustc-link-search={path}");
    println!("cargo:rustc-link-lib=static=BasePeCoffValidationLib");

    resolve_linker_map();
}

/// Resolves the supervisor's linker map into a path that always exists.
///
/// The map is embedded rather than passed at run time so that test-aux always builds its auxiliary
/// file from the same inputs create-aux used, the same way the PDB and EFI are embedded. The map
/// keeps whatever name the caller gave it; only its location is passed on, so nothing here has to
/// assume what the supervisor is called. Not every toolchain emits a map, so an empty file stands
/// in for its absence and the embedding always compiles.
fn resolve_linker_map() {
    println!("cargo::rerun-if-env-changed={}", MAP_ENV_KEY);

    let map = std::env::var(MAP_ENV_KEY).unwrap_or_default();

    let resolved = if map.is_empty() {
        let placeholder = PathBuf::from(
            std::env::var_os("OUT_DIR").expect("OUT_DIR is always set by cargo for build scripts."),
        )
        .join("no_linker_map");

        std::fs::write(&placeholder, "").unwrap_or_else(|e| {
            panic!(
                "Failed to write the placeholder map to `{}`: {e}",
                placeholder.display()
            )
        });
        placeholder
    } else {
        let map = PathBuf::from(&map);
        if !map.is_file() {
            panic!(
                "{MAP_ENV_KEY} is set to `{}`, but no file exists there. Leave it unset if the \
                 supervisor build does not produce a linker map.",
                map.display()
            );
        }
        println!("cargo::rerun-if-changed={}", map.display());
        map
    };

    println!("cargo::rustc-env={MAP_ENV_KEY}={}", resolved.display());
}
