use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use crate::models::{NessusFile, PluginDetails};

// hands out one shared copy of every plugin's details and of every short word (protocol, service name)
#[derive(Default)]
pub struct Interner {
    plugins: HashSet<Arc<PluginDetails>>,
    words: HashSet<Arc<str>>,
}// Interner

impl Interner {
    pub fn details(&mut self, details: PluginDetails) -> Arc<PluginDetails> {
        if let Some(same) = self.plugins.get(&details) {
            return Arc::clone(same);
        }
        let shared = Arc::new(details);
        self.plugins.insert(Arc::clone(&shared));
        shared
    }

    pub fn word(&mut self, word: &str) -> Arc<str> {
        if let Some(same) = self.words.get(word) {
            return Arc::clone(same);
        }
        let shared: Arc<str> = Arc::from(word);
        self.words.insert(Arc::clone(&shared));
        shared
    }

    // Points a file parsed on its own at the copies other open files already use
    pub fn adopt(&mut self, file: &mut NessusFile) {
        // each of the file's own copies is looked up once
        let mut done: HashMap<*const PluginDetails, Arc<PluginDetails>> = HashMap::new();
        for host in &mut file.hosts {
            for item in &mut host.items {
                let shared = done.entry(Arc::as_ptr(&item.details)).or_insert_with(|| {
                    match self.plugins.get(&*item.details) {
                        Some(same) => Arc::clone(same),
                        None => {
                            self.plugins.insert(Arc::clone(&item.details));
                            Arc::clone(&item.details)
                        }
                    }
                });
                item.details = Arc::clone(shared);
                item.protocol = self.word(&item.protocol);
                item.svc_name = self.word(&item.svc_name);
            }
        }
    }

    // Forgets what no open file uses any more
    pub fn prune(&mut self) {
        self.plugins.retain(|d| Arc::strong_count(d) > 1);
        self.words.retain(|w| Arc::strong_count(w) > 1);
    }

    #[cfg(test)]
    pub fn sizes(&self) -> (usize, usize) {
        (self.plugins.len(), self.words.len())
    }
}// Interner

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::parse_str;

    fn scan(host: &str, description: &str) -> String {
        format!(
            r#"<NessusClientData_v2><Report name="r"><ReportHost name="{host}"><ReportItem port="80" svc_name="www" protocol="tcp" severity="2" pluginID="7" pluginName="p" pluginFamily="f"><description>{description}</description><plugin_output>{host}</plugin_output></ReportItem><ReportItem port="443" svc_name="www" protocol="tcp" severity="2" pluginID="7" pluginName="p" pluginFamily="f"><description>{description}</description></ReportItem></ReportHost></Report></NessusClientData_v2>"#
        )
    }

    #[test]
    fn findings_of_one_plugin_share_its_details() {
        let f = parse_str(&scan("10.0.0.1", "same text")).unwrap();
        let items = &f.hosts[0].items;
        assert!(Arc::ptr_eq(&items[0].details, &items[1].details));
        assert!(Arc::ptr_eq(&items[0].svc_name, &items[1].svc_name));
        assert_eq!(items[0].plugin_output.as_deref(), Some("10.0.0.1"));
        assert_eq!(items[1].plugin_output, None);
    }

    #[test]
    fn files_share_details_until_they_are_closed() {
        let mut interner = Interner::default();
        let mut a = parse_str(&scan("10.0.0.1", "same text")).unwrap();
        let mut b = parse_str(&scan("10.0.0.2", "same text")).unwrap();
        let mut c = parse_str(&scan("10.0.0.3", "a newer plugin version")).unwrap();
        interner.adopt(&mut a);
        interner.adopt(&mut b);
        interner.adopt(&mut c);
        assert!(Arc::ptr_eq(&a.hosts[0].items[0].details, &b.hosts[0].items[0].details));
        assert!(!Arc::ptr_eq(&a.hosts[0].items[0].details, &c.hosts[0].items[0].details));
        assert_eq!(c.hosts[0].items[0].description, "a newer plugin version");
        assert_eq!(interner.sizes().0, 2);

        drop(c);
        interner.prune();
        assert_eq!(interner.sizes().0, 1);
        drop(a);
        drop(b);
        interner.prune();
        assert_eq!(interner.sizes(), (0, 0));
    }
}
