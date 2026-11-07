use std::fs::{DirBuilder, File, OpenOptions};
use std::io::{self, Write};
use std::path::Path;

pub fn create(path: impl AsRef<Path>) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)
}// create

pub fn write(path: impl AsRef<Path>, contents: impl AsRef<[u8]>) -> io::Result<()> {
    create(path)?.write_all(contents.as_ref())
}// write

pub fn create_dir_all(dir: impl AsRef<Path>) -> io::Result<()> {
    let mut builder = DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(dir)
}// create_dir_all

#[cfg(test)]
pub(crate) mod testing {
    use std::path::{Path, PathBuf};

    // Removes its folder when the test ends, including when an assert fails.
    pub struct TempDir(PathBuf);

    impl TempDir {
        pub fn new() -> Self {
            let dir = std::env::temp_dir().join(format!("scan-insights-{}", uuid::Uuid::new_v4()));
            std::fs::create_dir(&dir).unwrap();
            Self(dir)
        }

        pub fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[cfg(unix)]
    pub fn mode(path: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777
    }
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use super::testing::mode;
    use super::testing::TempDir;
    use super::*;

    #[test]
    fn write_replaces_longer_existing_contents() {
        let temp = TempDir::new();
        let path = temp.path().join("file.txt");

        write(&path, "a longer first version").unwrap();
        write(&path, "short").unwrap();

        assert_eq!(std::fs::read_to_string(&path).unwrap(), "short");
    }

    #[test]
    fn create_dir_all_makes_nested_folders_and_accepts_existing_ones() {
        let temp = TempDir::new();
        let nested = temp.path().join("a").join("b");

        create_dir_all(&nested).unwrap();
        create_dir_all(&nested).unwrap();

        assert!(nested.is_dir());
    }

    #[cfg(unix)]
    #[test]
    fn new_files_are_only_accessible_to_their_owner() {
        let temp = TempDir::new();

        let written = temp.path().join("written.txt");
        write(&written, "secret").unwrap();
        assert_eq!(mode(&written), 0o600);

        let created = temp.path().join("created.txt");
        create(&created).unwrap();
        assert_eq!(mode(&created), 0o600);
    }

    #[cfg(unix)]
    #[test]
    fn new_folders_are_only_accessible_to_their_owner() {
        let temp = TempDir::new();
        let parent = temp.path().join("a");
        let nested = parent.join("b");

        create_dir_all(&nested).unwrap();

        assert_eq!(mode(&parent), 0o700);
        assert_eq!(mode(&nested), 0o700);
    }
}
