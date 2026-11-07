fn main() {
    // Without this, cargo keeps using the previously compiled icons after they change.
    println!("cargo:rerun-if-changed=icons");

    // Load the DLLs the exe imports from System32 only. Otherwise Windows looks in the
    // exe's own folder first, so a DLL planted beside a downloaded exe would run.
    if std::env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("msvc") {
        println!("cargo:rustc-link-arg-bins=/DEPENDENTLOADFLAG:0x800");
    }

    tauri_build::build()
}
