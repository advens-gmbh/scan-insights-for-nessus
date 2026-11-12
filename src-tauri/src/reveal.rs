// Shows a file in the system's file manager, selected where the platform allows it.

use std::io;
use std::path::Path;
use std::process::Command;

#[cfg(windows)]
pub fn show_in_folder(path: &Path) -> io::Result<()> {
    use std::os::windows::process::CommandExt;
    // explorer reads "/select,<path>" itself, so the quoting is done here instead of by Command
    Command::new("explorer").raw_arg(format!("/select,\"{}\"", path.display())).spawn()?;
    Ok(())
}// show_in_folder

#[cfg(target_os = "macos")]
pub fn show_in_folder(path: &Path) -> io::Result<()> {
    Command::new("open").arg("-R").arg(path).spawn()?;
    Ok(())
}// show_in_folder

// The freedesktop FileManager1 call selects the file in Nautilus, Dolphin, Nemo and most others. Without it (or without dbus-send), the folder is opened instead.
#[cfg(all(unix, not(target_os = "macos")))]
pub fn show_in_folder(path: &Path) -> io::Result<()> {
    let shown = Command::new("dbus-send")
        .args([
            "--session",
            "--print-reply",
            "--dest=org.freedesktop.FileManager1",
            "--type=method_call",
            "/org/freedesktop/FileManager1",
            "org.freedesktop.FileManager1.ShowItems",
        ])
        .arg(format!("array:string:{}", file_uri(path)))
        .arg("string:")
        .output()
        .map(|out| out.status.success())
        .unwrap_or(false);
    if shown {
        return Ok(());
    }
    let folder = path.parent().unwrap_or(path);
    open::that_detached(folder)
}// show_in_folder

// file:///… with everything but unreserved characters and "/" percent-encoded
#[cfg_attr(any(windows, target_os = "macos"), allow(dead_code))]
pub fn file_uri(path: &Path) -> String {
    let mut uri = String::from("file://");
    for b in path.to_string_lossy().bytes() {
        if b.is_ascii_alphanumeric() || b"-._~/".contains(&b) {
            uri.push(b as char);
        } else {
            uri.push_str(&format!("%{b:02X}"));
        }
    }
    uri
}// file_uri

#[cfg(test)]
mod tests {
    use super::file_uri;
    use std::path::Path;

    #[test]
    fn file_uri_encodes_spaces_and_commas() {
        assert_eq!(file_uri(Path::new("/home/me/My Reports/a,b.xlsx")), "file:///home/me/My%20Reports/a%2Cb.xlsx");
    }

    #[test]
    fn file_uri_encodes_non_ascii_as_utf8() {
        assert_eq!(file_uri(Path::new("/tmp/jelentés.csv")), "file:///tmp/jelent%C3%A9s.csv");
    }
}
