//! C#-compatible file-backed allowlist (BasisAllowList.txt).

use std::collections::HashSet;
use std::path::Path;

#[derive(Debug, Clone, Default)]
pub struct AllowList {
    entries: HashSet<String>,
}

impl AllowList {
    pub fn load(path: &Path) -> Self {
        let Ok(text) = std::fs::read_to_string(path) else {
            return Self::default();
        };
        let entries = text
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .map(str::to_string)
            .collect();
        Self { entries }
    }

    pub fn is_allowed(&self, uuid: &str) -> bool {
        self.entries.contains(uuid)
    }

    pub fn add(&mut self, uuid: &str) -> bool {
        self.entries.insert(uuid.to_string())
    }

    pub fn remove(&mut self, uuid: &str) -> bool {
        self.entries.remove(uuid)
    }

    pub fn save(&self, path: &Path) {
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let mut text = String::new();
        for entry in &self.entries {
            text.push_str(entry);
            text.push('\n');
        }
        let _ = std::fs::write(path, text);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allowlist_adds_removes_and_persists() {
        let path = std::env::current_dir()
            .unwrap()
            .join(format!("basis-allowlist-test-{}.txt", std::process::id()));
        let mut list = AllowList::default();
        assert!(list.add("did:key:a"));
        assert!(!list.add("did:key:a"));
        assert!(list.is_allowed("did:key:a"));
        list.save(&path);
        let mut loaded = AllowList::load(&path);
        assert!(loaded.is_allowed("did:key:a"));
        assert!(loaded.remove("did:key:a"));
        assert!(!loaded.is_allowed("did:key:a"));
        let _ = std::fs::remove_file(path);
    }
}
