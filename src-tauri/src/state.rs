use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use crate::models::NessusFile;

#[derive(Default)]
pub struct AppState {
    pub files: Mutex<Vec<Arc<NessusFile>>>,
    pub exported: Mutex<HashSet<PathBuf>>,
}
