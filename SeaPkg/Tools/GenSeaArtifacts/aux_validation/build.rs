fn main() {
    println!("cargo:rustc-link-search=C:/src/sea_release/Build/DEBUG_VS2022/X64/SeaPkg/Library/BasePeCoffValidationLib/BasePeCoffValidationLib/OUTPUT");
    println!("cargo:rustc-link-lib=static=BasePeCoffValidationLib");
}