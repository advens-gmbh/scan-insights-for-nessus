use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use crate::intern::Interner;
use crate::models::NessusFile;
use crate::views::{FileInfo, View};

#[derive(Default)]
pub struct AppState {
    pub files: Mutex<Vec<Arc<NessusFile>>>,
    pub exported: Mutex<HashSet<PathBuf>>,
    pub interner: Mutex<Interner>,
    pub infos: Mutex<HashMap<String, FileInfo>>,
    pub views: Mutex<HashMap<String, Arc<View>>>, // the lists, by file filter; cleared when the files change
    pub memo: Mutex<HashMap<String, Arc<String>>>, // answers of Compare and Trends, cleared with them
}
