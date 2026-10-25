//! C#-compatible permissions.xml store and effective permission resolution.

use std::collections::{HashMap, HashSet};
use std::path::Path;

pub const NODE_ALL: &str = "*";
pub const NODE_HELP: &str = "basis.command.help";
pub const NODE_CHAT_LOCK_BYPASS: &str = "basis.chat.lockbypass";
pub const NODE_VOICE_LOCK_BYPASS: &str = "basis.voice.lockbypass";
pub const NODE_RESOURCE_LOCK_BYPASS_AVATAR: &str = "basis.resource.lockbypass.avatar";
pub const NODE_RESOURCE_LOCK_BYPASS_PROP: &str = "basis.resource.lockbypass.prop";
pub const NODE_RESOURCE_LOCK_BYPASS_WORLD: &str = "basis.resource.lockbypass.world";
pub const NODE_RESOURCE_LOCK_BYPASS_SERVER: &str = "basis.resource.lockbypass.server";

const DEFAULT_NODES: &[&str] = &[
    NODE_HELP,
    "basis.resource.load.prop",
    "basis.resource.unload.prop",
    "basis.resource.load.avatar",
    "basis.resource.unload.avatar",
    "basis.resource.load.world",
    "basis.resource.unload.world",
    "basis.ownership.transfer",
    "basis.ownership.remove",
    "basis.ownership.get",
    "basis.contentshare.delete",
    "basis.contentshare.create",
];

const MODERATOR_NODES: &[&str] = &[
    "basis.moderation",
    "basis.moderation.ban",
    "basis.moderation.kick",
    "basis.moderation.ipban",
    "basis.moderation.unban",
    "basis.moderation.unbanip",
    "basis.moderation.message",
    "basis.moderation.messageall",
    "basis.moderation.teleport",
    "basis.moderation.announce",
    "basis.moderation.globallock",
    "basis.moderation.headlessaudio",
    "basis.moderation.opusbitrate",
    "basis.moderation.fullqualitybroadcast",
    "basis.moderation.forceavatar",
    "basis.moderation.locomotion",
    "basis.moderation.mute",
    "basis.moderation.rename",
    "basis.permissions.view",
    NODE_RESOURCE_LOCK_BYPASS_AVATAR,
    NODE_RESOURCE_LOCK_BYPASS_PROP,
    NODE_RESOURCE_LOCK_BYPASS_WORLD,
    NODE_RESOURCE_LOCK_BYPASS_SERVER,
    NODE_CHAT_LOCK_BYPASS,
    NODE_VOICE_LOCK_BYPASS,
];

#[derive(Default, Debug, Clone)]
pub struct PermissionUser {
    pub uuid: String,
    pub nodes: HashSet<String>,
    pub groups: HashSet<String>,
}

#[derive(Default, Debug, Clone)]
pub struct PermissionGroup {
    pub name: String,
    pub nodes: HashSet<String>,
    pub parents: HashSet<String>,
}

#[derive(Default, Debug, Clone)]
pub struct PermissionStore {
    pub users: HashMap<String, PermissionUser>,
    pub groups: HashMap<String, PermissionGroup>,
    pub seeded: HashMap<String, HashSet<String>>,
}

impl PermissionStore {
    pub fn with_defaults() -> Self {
        let mut store = Self::default();
        store.ensure_defaults();
        store
    }

    /// C# `PermissionManager.EnsureDefaults`: seed the built-in groups and nodes into a
    /// store loaded from disk. Nodes already recorded in `<SeededDefaults>` are not added
    /// again, so an operator who removed one from the group keeps that removal across
    /// restarts. A group that already exists keeps its configured parents.
    pub fn ensure_defaults(&mut self) {
        self.seed_group("default", None, DEFAULT_NODES);
        self.seed_group("moderator", Some("default"), MODERATOR_NODES);
        self.seed_group("admin", Some("moderator"), &[NODE_ALL]);
    }

    fn seed_group(&mut self, name: &str, parent: Option<&str>, nodes: &[&str]) {
        let seeded = self.seeded.entry(name.to_string()).or_default();
        let group = match self.groups.entry(name.to_string()) {
            std::collections::hash_map::Entry::Occupied(entry) => entry.into_mut(),
            std::collections::hash_map::Entry::Vacant(entry) => {
                let mut group = PermissionGroup {
                    name: name.to_string(),
                    ..Default::default()
                };
                if let Some(parent) = parent {
                    group.parents.insert(parent.to_string());
                }
                entry.insert(group)
            }
        };
        for node in nodes {
            if seeded.insert(node.to_string()) && !group.nodes.contains(&format!("-{node}")) {
                group.nodes.insert(node.to_string());
            }
        }
    }

    pub fn load(path: &Path) -> std::io::Result<Self> {
        let text = std::fs::read_to_string(path)?;
        Ok(Self::parse(&text))
    }

    pub fn parse(text: &str) -> Self {
        let mut store = Self::default();
        let mut section = Section::None;
        let mut group: Option<String> = None;
        let mut user: Option<String> = None;
        let mut seeded: Option<String> = None;

        let mut rest = text;
        while let Some(start) = rest.find('<') {
            let Some(end) = rest[start..].find('>').map(|offset| start + offset) else {
                break;
            };
            let raw_tag = &rest[start + 1..end];
            rest = &rest[end + 1..];
            let closing = raw_tag.starts_with('/');
            let body = raw_tag.trim_start_matches('/').trim_end_matches('/').trim();
            let name = body.split_whitespace().next().unwrap_or("");
            match (closing, name) {
                (false, "Groups") => section = Section::Groups,
                (false, "Users") => section = Section::Users,
                (false, "SeededDefaults") => section = Section::Seeded,
                (false, "Group") => {
                    let value = attr(body, "name");
                    match section {
                        Section::Groups => {
                            if !value.is_empty() {
                                store.groups.entry(value.clone()).or_insert_with(|| {
                                    PermissionGroup {
                                        name: value.clone(),
                                        ..Default::default()
                                    }
                                });
                                group = Some(value);
                            }
                        }
                        Section::Users => {
                            if let (Some(uuid), false) = (user.clone(), value.is_empty()) {
                                if let Some(existing) = store.users.get_mut(&uuid) {
                                    existing.groups.insert(value);
                                }
                            }
                        }
                        Section::Seeded => {
                            if !value.is_empty() {
                                store.seeded.entry(value.clone()).or_default();
                                seeded = Some(value);
                            }
                        }
                        Section::None => {}
                    }
                }
                (false, "User") => {
                    let uuid = attr(body, "uuid");
                    if !uuid.is_empty() {
                        store
                            .users
                            .entry(uuid.clone())
                            .or_insert_with(|| PermissionUser {
                                uuid: uuid.clone(),
                                ..Default::default()
                            });
                        user = Some(uuid);
                    }
                }
                (false, "Parent") => {
                    if let Some(group_name) = group.as_ref() {
                        let parent = attr(body, "name");
                        if !parent.is_empty() {
                            if let Some(existing) = store.groups.get_mut(group_name) {
                                existing.parents.insert(parent);
                            }
                        }
                    }
                }
                (false, "Node") => {
                    let mut value = attr(body, "value");
                    if value.is_empty() {
                        continue;
                    }
                    value = migrate_legacy_node(value.trim());
                    match section {
                        Section::Groups => {
                            if let Some(group_name) = group.as_ref() {
                                if let Some(existing) = store.groups.get_mut(group_name) {
                                    existing.nodes.insert(value);
                                }
                            }
                        }
                        Section::Users => {
                            if let Some(uuid) = user.as_ref() {
                                if let Some(existing) = store.users.get_mut(uuid) {
                                    existing.nodes.insert(value);
                                }
                            }
                        }
                        Section::Seeded => {
                            if let Some(name) = seeded.as_ref() {
                                store.seeded.entry(name.clone()).or_default().insert(value);
                            }
                        }
                        Section::None => {}
                    }
                }
                (true, "Group") => {
                    if section == Section::Groups {
                        group = None;
                    } else if section == Section::Seeded {
                        seeded = None;
                    }
                }
                (true, "User") => user = None,
                (true, "Groups") => {
                    section = Section::None;
                    group = None;
                }
                (true, "Users") => {
                    section = Section::None;
                    user = None;
                }
                (true, "SeededDefaults") => {
                    section = Section::None;
                    seeded = None;
                }
                _ => {}
            }
            // Self-closing elements have no EndElement event.
            if raw_tag.ends_with('/') {
                match name {
                    "Group" if section == Section::Groups => group = None,
                    "Group" if section == Section::Seeded => seeded = None,
                    "User" => user = None,
                    _ => {}
                }
            }
        }
        store
    }

    pub fn effective(&self, uuid: &str) -> EffectivePermissions {
        let mut user = self.users.get(uuid).cloned().unwrap_or_default();
        if user.groups.is_empty() {
            user.groups.insert("default".to_string());
        }
        let mut decisions = HashMap::<String, bool>::new();
        let mut visited = HashSet::new();
        for group in &user.groups {
            self.apply_group(group, &mut visited, &mut decisions);
        }
        apply_nodes(&user.nodes, &mut decisions);
        EffectivePermissions { decisions }
    }

    fn apply_group(
        &self,
        name: &str,
        visited: &mut HashSet<String>,
        decisions: &mut HashMap<String, bool>,
    ) {
        if !visited.insert(name.to_string()) {
            return;
        }
        let Some(group) = self.groups.get(name) else {
            return;
        };
        for parent in &group.parents {
            self.apply_group(parent, visited, decisions);
        }
        apply_nodes(&group.nodes, decisions);
    }

    pub fn add_user_to_group(&mut self, uuid: &str, group: &str) {
        let user = self
            .users
            .entry(uuid.to_string())
            .or_insert_with(|| PermissionUser {
                uuid: uuid.to_string(),
                ..Default::default()
            });
        user.groups.insert(group.to_string());
    }

    pub fn remove_user_from_group(&mut self, uuid: &str, group: &str) {
        if let Some(user) = self.users.get_mut(uuid) {
            user.groups.remove(group);
        }
    }

    pub fn add_user_node(&mut self, uuid: &str, node: &str) {
        let user = self
            .users
            .entry(uuid.to_string())
            .or_insert_with(|| PermissionUser {
                uuid: uuid.to_string(),
                ..Default::default()
            });
        user.nodes.insert(node.to_string());
    }

    pub fn remove_user_node(&mut self, uuid: &str, node: &str) {
        if let Some(user) = self.users.get_mut(uuid) {
            user.nodes.remove(node);
        }
    }

    pub fn add_group_node(&mut self, group: &str, node: &str) {
        let group = self
            .groups
            .entry(group.to_string())
            .or_insert_with(|| PermissionGroup {
                name: group.to_string(),
                ..Default::default()
            });
        group.nodes.insert(node.to_string());
    }

    pub fn remove_group_node(&mut self, group: &str, node: &str) {
        if let Some(group) = self.groups.get_mut(group) {
            group.nodes.remove(node);
        }
    }

    pub fn create_group(&mut self, group: &str) {
        self.groups
            .entry(group.to_string())
            .or_insert_with(|| PermissionGroup {
                name: group.to_string(),
                ..Default::default()
            });
    }

    pub fn delete_group(&mut self, group: &str) -> bool {
        if self.groups.remove(group).is_none() {
            return false;
        }
        for user in self.users.values_mut() {
            user.groups.remove(group);
        }
        for existing in self.groups.values_mut() {
            existing.parents.remove(group);
        }
        true
    }

    pub fn add_group_parent(&mut self, group: &str, parent: &str) {
        if let Some(group) = self.groups.get_mut(group) {
            group.parents.insert(parent.to_string());
        }
    }

    pub fn remove_group_parent(&mut self, group: &str, parent: &str) {
        if let Some(group) = self.groups.get_mut(group) {
            group.parents.remove(parent);
        }
    }

    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        let mut xml =
            String::from("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<Permissions>\n  <Groups>\n");
        for group in self.groups.values() {
            xml.push_str(&format!("    <Group name=\"{}\">\n", escape(&group.name)));
            for parent in &group.parents {
                xml.push_str(&format!("      <Parent name=\"{}\" />\n", escape(parent)));
            }
            for node in &group.nodes {
                xml.push_str(&format!("      <Node value=\"{}\" />\n", escape(node)));
            }
            xml.push_str("    </Group>\n");
        }
        xml.push_str("  </Groups>\n  <Users>\n");
        for user in self.users.values() {
            xml.push_str(&format!("    <User uuid=\"{}\">\n", escape(&user.uuid)));
            for group in &user.groups {
                xml.push_str(&format!("      <Group name=\"{}\" />\n", escape(group)));
            }
            for node in &user.nodes {
                xml.push_str(&format!("      <Node value=\"{}\" />\n", escape(node)));
            }
            xml.push_str("    </User>\n");
        }
        xml.push_str("  </Users>\n  <SeededDefaults>\n");
        for (group, nodes) in &self.seeded {
            xml.push_str(&format!("    <Group name=\"{}\">\n", escape(group)));
            for node in nodes {
                xml.push_str(&format!("      <Node value=\"{}\" />\n", escape(node)));
            }
            xml.push_str("    </Group>\n");
        }
        xml.push_str("  </SeededDefaults>\n</Permissions>\n");
        std::fs::write(path, xml)
    }

    pub fn groups(&self) -> impl Iterator<Item = &PermissionGroup> {
        self.groups.values()
    }

    pub fn users(&self) -> impl Iterator<Item = &PermissionUser> {
        self.users.values()
    }

    pub fn is_in_group(&self, uuid: &str, target: &str) -> bool {
        let groups = self
            .users
            .get(uuid)
            .map(|user| user.groups.clone())
            .unwrap_or_else(|| ["default".to_string()].into_iter().collect());
        let mut visited = HashSet::new();
        for group in groups {
            if self.group_inherits(&group, target, &mut visited) {
                return true;
            }
        }
        false
    }

    fn group_inherits(&self, name: &str, target: &str, visited: &mut HashSet<String>) -> bool {
        if !visited.insert(name.to_string()) {
            return false;
        }
        if name.eq_ignore_ascii_case(target) {
            return true;
        }
        let Some(group) = self.groups.get(name) else {
            return false;
        };
        group
            .parents
            .iter()
            .any(|parent| self.group_inherits(parent, target, visited))
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Section {
    None,
    Groups,
    Users,
    Seeded,
}

fn apply_nodes(nodes: &HashSet<String>, decisions: &mut HashMap<String, bool>) {
    for raw in nodes {
        let mut node = raw.trim();
        if node.is_empty() {
            continue;
        }
        let mut allow = true;
        if let Some(stripped) = node.strip_prefix('-') {
            allow = false;
            node = stripped.trim();
            if node.is_empty() {
                continue;
            }
        }
        match decisions.get(node).copied() {
            Some(false) => {}
            Some(true) if !allow => {
                decisions.insert(node.to_string(), false);
            }
            Some(_) => {}
            None => {
                decisions.insert(node.to_string(), allow);
            }
        }
    }
}

fn escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn attr(tag: &str, key: &str) -> String {
    let needle = format!("{key}=");
    let Some(start) = tag.find(&needle) else {
        return String::new();
    };
    let rest = &tag[start + needle.len()..];
    let Some(quote) = rest.chars().next() else {
        return String::new();
    };
    if quote != '"' && quote != '\'' {
        return String::new();
    }
    let rest = &rest[quote.len_utf8()..];
    rest.find(quote)
        .map(|end| rest[..end].to_string())
        .unwrap_or_default()
}

fn migrate_legacy_node(node: &str) -> String {
    // C# PermissionXml.MigrateLegacyNode: retired spellings are rewritten on load so an
    // existing grant/deny keeps working. The negated form must migrate too, or the deny
    // silently stops denying.
    const LEGACY: &str = "basis.moderation.shout";
    const CURRENT: &str = "basis.moderation.announce";
    match node.strip_prefix('-') {
        Some(value) if value.eq_ignore_ascii_case(LEGACY) => format!("-{CURRENT}"),
        Some(_) => node.to_string(),
        None if node.eq_ignore_ascii_case(LEGACY) => CURRENT.to_string(),
        None => node.to_string(),
    }
}

#[derive(Debug, Clone)]
pub struct EffectivePermissions {
    decisions: HashMap<String, bool>,
}

impl EffectivePermissions {
    pub fn has(&self, node: &str) -> bool {
        if node.trim().is_empty() {
            return false;
        }
        let mut current = node.trim();
        if let Some(value) = self.decisions.get(current) {
            return *value;
        }
        while let Some(index) = current.rfind('.') {
            current = &current[..index];
            let wildcard = format!("{current}.*");
            if let Some(value) = self.decisions.get(&wildcard) {
                return *value;
            }
        }
        self.decisions.get(NODE_ALL).copied().unwrap_or(false)
    }

    pub fn allowed_rules(&self) -> Vec<String> {
        self.decisions
            .iter()
            .filter(|(_, allow)| **allow)
            .map(|(node, _)| node.clone())
            .collect()
    }

    pub fn denied_rules(&self) -> Vec<String> {
        self.decisions
            .iter()
            .filter(|(_, allow)| !**allow)
            .map(|(node, _)| node.clone())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const XML: &str = r#"<Permissions>
  <Groups>
    <Group name="default"><Node value="basis.command.help"/></Group>
    <Group name="moderator"><Parent name="default"/><Node value="basis.moderation.ban"/></Group>
    <Group name="admin"><Parent name="moderator"/><Node value="*"/></Group>
  </Groups>
  <Users>
    <User uuid="did:key:mod"><Group name="moderator"/></User>
    <User uuid="did:key:admin"><Group name="admin"/></User>
    <User uuid="did:key:banned"><Group name="default"/><Node value="-basis.command.help"/></User>
  </Users>
  <SeededDefaults/>
</Permissions>"#;

    #[test]
    fn resolves_groups_parents_and_denies() {
        let store = PermissionStore::parse(XML);
        let moderator = store.effective("did:key:mod");
        assert!(moderator.has("basis.moderation.ban"));
        assert!(moderator.has("basis.command.help"));
        let banned = store.effective("did:key:banned");
        assert!(!banned.has("basis.command.help"));
        let unknown = store.effective("did:key:new");
        assert!(unknown.has("basis.command.help"));
    }

    #[test]
    fn wildcard_admin_has_everything() {
        let store = PermissionStore::parse(XML);
        let admin = store.effective("did:key:admin");
        assert!(admin.has("basis.anything.at.all"));
    }

    #[test]
    fn legacy_shout_nodes_migrate_to_announce_on_load() {
        let text = r#"<Permissions>
  <Groups>
    <Group name="default">
      <Node value="basis.moderation.shout" />
      <Node value="-basis.moderation.shout" />
    </Group>
  </Groups>
  <Users />
</Permissions>"#;
        let store = PermissionStore::parse(text);
        let nodes = &store.groups.get("default").unwrap().nodes;
        assert!(nodes.contains("basis.moderation.announce"));
        assert!(nodes.contains("-basis.moderation.announce"));
        assert!(!nodes.contains("basis.moderation.shout"));
    }

    #[test]
    fn permission_edits_round_trip_through_xml() {
        let mut store = PermissionStore::parse(XML);
        assert!(store.delete_group("moderator"));
        store.create_group("helpers");
        store.add_group_node("helpers", "basis.command.help");
        store.add_user_to_group("did:key:new", "helpers");
        store.add_user_node("did:key:new", "basis.custom");
        store.remove_user_node("did:key:banned", "-basis.command.help");
        let path = std::env::current_dir()
            .unwrap()
            .join(format!("basis-permissions-edit-{}.xml", std::process::id()));
        store.save(&path).unwrap();
        let loaded = PermissionStore::load(&path).unwrap();
        assert!(loaded.is_in_group("did:key:new", "helpers"));
        assert!(loaded.effective("did:key:new").has("basis.custom"));
        assert!(loaded.effective("did:key:banned").has("basis.command.help"));
        assert!(!loaded.groups.contains_key("moderator"));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn loaded_file_gets_csharp_default_groups_and_admin_wildcard() {
        // What the first-boot wizard writes: an admin group with only a parent, no nodes.
        let text = r#"<Permissions>
  <Groups>
    <Group name="admin"><Parent name="default" /></Group>
  </Groups>
  <Users>
    <User uuid="did:key:admin"><Group name="admin" /></User>
  </Users>
</Permissions>"#;
        let mut store = PermissionStore::parse(text);
        store.ensure_defaults();

        let admin = store.effective("did:key:admin");
        assert!(admin.has(NODE_ALL));
        assert!(admin.has("basis.resource.load.world"));
        assert!(admin.has("basis.resource.load.prop"));
        assert!(admin.has(NODE_RESOURCE_LOCK_BYPASS_WORLD));

        let default = store.effective("did:key:anyone");
        assert!(default.has("basis.resource.load.world"));
        assert!(default.has("basis.resource.load.prop"));
        assert!(!default.has(NODE_ALL));
    }

    #[test]
    fn seeded_defaults_are_not_reapplied_after_operator_removal() {
        let text = r#"<Permissions>
  <Groups>
    <Group name="default"><Node value="basis.command.help" /></Group>
  </Groups>
  <Users>
    <User uuid="did:key:any" />
  </Users>
  <SeededDefaults>
    <Group name="default">
      <Node value="basis.command.help" />
      <Node value="basis.resource.load.prop" />
    </Group>
  </SeededDefaults>
</Permissions>"#;
        let mut store = PermissionStore::parse(text);
        store.ensure_defaults();
        assert!(!store
            .effective("did:key:any")
            .has("basis.resource.load.prop"));
    }

    #[test]
    fn saved_seeded_defaults_survive_a_round_trip() {
        let mut store = PermissionStore::parse(XML);
        store.ensure_defaults();
        store.remove_group_node("default", "basis.resource.load.prop");
        let path = std::env::current_dir().unwrap().join(format!(
            "basis-permissions-seeded-{}.xml",
            std::process::id()
        ));
        store.save(&path).unwrap();

        let mut loaded = PermissionStore::load(&path).unwrap();
        loaded.ensure_defaults();
        assert!(!loaded
            .effective("did:key:mod")
            .has("basis.resource.load.prop"));
        assert!(loaded.effective("did:key:mod").has("basis.command.help"));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn default_store_seeds_three_groups() {
        let store = PermissionStore::with_defaults();
        assert!(store.groups.contains_key("default"));
        assert!(store.groups.contains_key("moderator"));
        assert!(store.groups.contains_key("admin"));
        assert!(store.effective("did:key:any").has(NODE_HELP));
    }
}
