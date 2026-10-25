//! C#-compatible banned_players.xml persistence.

use std::collections::HashMap;
use std::path::Path;

#[derive(Debug, Clone, Default)]
pub struct BannedPlayer {
    pub uuid: String,
    pub banned_ip: String,
    pub reason: String,
    pub has_banned_ip: bool,
    pub time_of_ban: String,
}

#[derive(Debug, Clone, Default)]
pub struct BanStore {
    players: HashMap<String, BannedPlayer>,
}

impl BanStore {
    pub fn load(path: &Path) -> Self {
        let Ok(text) = std::fs::read_to_string(path) else {
            return Self::default();
        };
        Self::parse(&text)
    }

    pub fn parse(text: &str) -> Self {
        let mut players = HashMap::new();
        for block in text.split("<BannedPlayer>").skip(1) {
            let Some(end) = block.find("</BannedPlayer>") else {
                continue;
            };
            let block = &block[..end];
            let uuid = tag(block, "UUID");
            if uuid.is_empty() {
                continue;
            }
            players.insert(
                uuid.clone(),
                BannedPlayer {
                    uuid: uuid.clone(),
                    banned_ip: tag(block, "BannedIp"),
                    reason: tag(block, "Reason"),
                    has_banned_ip: tag(block, "HasBannedIp").eq_ignore_ascii_case("true"),
                    time_of_ban: tag(block, "TimeOfBan"),
                },
            );
        }
        Self { players }
    }

    pub fn is_banned(&self, uuid: &str) -> bool {
        self.players.contains_key(uuid)
    }

    pub fn reason(&self, uuid: &str) -> Option<&str> {
        self.players.get(uuid).map(|player| player.reason.as_str())
    }

    pub fn ban(&mut self, uuid: &str, reason: &str) {
        self.players.insert(
            uuid.to_string(),
            BannedPlayer {
                uuid: uuid.to_string(),
                reason: reason.to_string(),
                has_banned_ip: false,
                banned_ip: String::new(),
                time_of_ban: chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string(),
            },
        );
    }

    pub fn unban(&mut self, uuid: &str) -> bool {
        self.players.remove(uuid).is_some()
    }

    pub fn save(&self, path: &Path) {
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let mut xml = String::from("<?xml version=\"1.0\"?>\n<ArrayOfBannedPlayer>\n");
        for player in self.players.values() {
            xml.push_str("  <BannedPlayer>\n");
            xml.push_str(&format!("    <UUID>{}</UUID>\n", escape(&player.uuid)));
            xml.push_str(&format!(
                "    <BannedIp>{}</BannedIp>\n",
                escape(&player.banned_ip)
            ));
            xml.push_str(&format!(
                "    <Reason>{}</Reason>\n",
                escape(&player.reason)
            ));
            xml.push_str(&format!(
                "    <HasBannedIp>{}</HasBannedIp>\n",
                if player.has_banned_ip {
                    "true"
                } else {
                    "false"
                }
            ));
            xml.push_str(&format!(
                "    <TimeOfBan>{}</TimeOfBan>\n",
                escape(&player.time_of_ban)
            ));
            xml.push_str("  </BannedPlayer>\n");
        }
        xml.push_str("</ArrayOfBannedPlayer>\n");
        let _ = std::fs::write(path, xml);
    }
}

fn tag(block: &str, name: &str) -> String {
    let open = format!("<{name}>");
    let close = format!("</{name}>");
    let Some(start) = block.find(&open) else {
        return String::new();
    };
    let rest = &block[start + open.len()..];
    let Some(end) = rest.find(&close) else {
        return String::new();
    };
    unescape(rest[..end].trim())
}

fn escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn unescape(value: &str) -> String {
    value
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_round_trips_ban_records() {
        let xml = "<ArrayOfBannedPlayer><BannedPlayer><UUID>did:key:a</UUID><BannedIp></BannedIp><Reason>spam</Reason><HasBannedIp>false</HasBannedIp><TimeOfBan>2026-01-01 00:00:00</TimeOfBan></BannedPlayer></ArrayOfBannedPlayer>";
        let mut store = BanStore::parse(xml);
        assert!(store.is_banned("did:key:a"));
        assert_eq!(store.reason("did:key:a"), Some("spam"));
        store.ban("did:key:b", "harassment");
        assert!(store.unban("did:key:a"));
        let path = std::env::current_dir()
            .unwrap()
            .join(format!("basis-ban-test-{}.xml", std::process::id()));
        store.save(&path);
        let loaded = BanStore::load(&path);
        assert!(loaded.is_banned("did:key:b"));
        assert_eq!(loaded.reason("did:key:b"), Some("harassment"));
        let _ = std::fs::remove_file(path);
    }
}
