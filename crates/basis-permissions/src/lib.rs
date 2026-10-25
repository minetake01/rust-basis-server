//! C#-compatible permissions.xml model and first-boot admin seeding.

pub mod store;

pub use store::{
    EffectivePermissions, PermissionGroup, PermissionStore, PermissionUser, NODE_ALL,
    NODE_CHAT_LOCK_BYPASS, NODE_HELP, NODE_RESOURCE_LOCK_BYPASS_AVATAR,
    NODE_RESOURCE_LOCK_BYPASS_PROP, NODE_RESOURCE_LOCK_BYPASS_SERVER,
    NODE_RESOURCE_LOCK_BYPASS_WORLD, NODE_VOICE_LOCK_BYPASS,
};

use std::path::Path;

/// Adds every non-empty UUID in `raw` to the `admin` group and writes a
/// permissions.xml C# `PermissionXml.Load` can read. The file contains the
/// built-in default/moderator/admin groups and their `SeededDefaults`, exactly
/// like the C# setup wizard's `EnsureDefaults` + save. Returns the number added.
pub fn seed_first_admins(path: &Path, raw: &str) -> std::io::Result<usize> {
    if path.exists() {
        return Ok(0);
    }
    let mut uuids: Vec<String> = raw
        .split([',', ';', ' ', '\t', '\r', '\n'])
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .collect();
    uuids.sort();
    uuids.dedup();
    if uuids.is_empty() {
        return Ok(0);
    }
    let mut store = PermissionStore::with_defaults();
    for uuid in &uuids {
        store.add_user_to_group(uuid, "admin");
    }
    store.save(path)?;
    Ok(uuids.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seeds_admins_once() {
        let path = std::env::current_dir()
            .unwrap()
            .join(format!("basis-permissions-test-{}.xml", std::process::id()));
        let _ = std::fs::remove_file(&path);
        assert_eq!(
            seed_first_admins(&path, "did:key:a, did:key:b did:key:a").unwrap(),
            2
        );
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("uuid=\"did:key:a\""));
        assert!(text.contains("uuid=\"did:key:b\""));
        assert!(text.contains("<Node value=\"*\" />"));
        assert!(text.contains("<SeededDefaults>"));
        let store = PermissionStore::load(&path).unwrap();
        let admin = store.effective("did:key:a");
        assert!(admin.has(NODE_ALL));
        assert!(admin.has("basis.resource.load.world"));
        assert!(admin.has("basis.resource.load.prop"));
        assert_eq!(seed_first_admins(&path, "did:key:c").unwrap(), 0);
        let _ = std::fs::remove_file(path);
    }
}
