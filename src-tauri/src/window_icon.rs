// Windows only: Tauri gives a window a fixed-size copy of its icon, so Windows has to stretch
// or shrink it for the title bar, the taskbar and Task Manager. This hands the window the icon
// straight from the exe's resources (LR_SHARED), this was Windows can take the matching size
// from the icon file for each place.

use tauri::{App, Manager};
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::UI::HiDpi::{GetDpiForWindow, GetSystemMetricsForDpi};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    LoadImageW, SendMessageW, ICON_BIG, ICON_SMALL, IMAGE_ICON, LR_SHARED, SM_CXICON, SM_CXSMICON,
    SM_CYICON, SM_CYSMICON, WM_SETICON,
};

// the id tauri-build gives the app icon in the exe's resources
const APP_ICON_ID: u16 = tauri::utils::platform::WINDOWS_APP_ICON_RESOURCE_ID;

pub fn use_resource_icons(app: &App) {
    for window in app.webview_windows().values() {
        let Ok(hwnd) = window.hwnd() else { continue };
        let hwnd = hwnd.0;
        unsafe {
            // sizes for the window's screen scaling: 16 and 32 px at 100%
            let dpi = match GetDpiForWindow(hwnd) {
                0 => 96,
                dpi => dpi,
            };
            let module = GetModuleHandleW(std::ptr::null());
            for (kind, cx, cy) in [(ICON_SMALL, SM_CXSMICON, SM_CYSMICON), (ICON_BIG, SM_CXICON, SM_CYICON)] {
                // MAKEINTRESOURCE: the resource id passed as a pointer value
                let icon = LoadImageW(
                    module,
                    APP_ICON_ID as usize as *const u16,
                    IMAGE_ICON,
                    GetSystemMetricsForDpi(cx, dpi),
                    GetSystemMetricsForDpi(cy, dpi),
                    LR_SHARED, // stays linked to the resource; owned by the system, never freed
                );
                if !icon.is_null() {
                    SendMessageW(hwnd, WM_SETICON, kind as usize, icon as isize);
                }
            }
        }
    }
}// use_resource_icons
