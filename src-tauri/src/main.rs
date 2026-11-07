// Prevents an additional console window on Windows in release mode.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    restrict_dll_search();
    scan_insights_for_nessus_lib::run();
}

// The linker flag in build.rs covers DLLs the exe imports. This covers those loaded while
// running, so neither is picked up from the exe's folder, such as a Downloads folder.
#[cfg(windows)]
fn restrict_dll_search() {
    const LOAD_LIBRARY_SEARCH_SYSTEM32: u32 = 0x800;

    #[link(name = "kernel32")]
    extern "system" {
        fn SetDefaultDllDirectories(flags: u32) -> i32;
    }

    // SAFETY: takes only a flag value and is called before any other threads exist.
    unsafe {
        SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32);
    }
}

#[cfg(not(windows))]
fn restrict_dll_search() {}
