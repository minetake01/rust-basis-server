//! C#-compatible muted_players.xml persistence.

use std::collections::HashMap;
use std::path::Path;

#[derive(Debug, Clone, Default)]
pub struct MutedPlayer {
    pub uuid: String,
    pub voice_muted: bool,
    pub text_muted: bool,
    pub time_of_mute: String,
}

#[derive(Debug, Clone, Default)]
pub struct MuteStore {
    players: HashMap<String, MutedPlayer>,
}

impl MuteStore {
    pub fn load(path: &Path) -> Self {
        let Ok(text) = std::fs::read_to_string(path) else {
            return Self::default();
        };
        Self::parse(&text)
    }

    pub fn parse(text: &str) -> Self {
        let mut players = HashMap::new();
        for block in text.split("<MutedPlayer>").skip(1) {
            let Some(end) = block.find("</MutedPlayer>") else {
                continue;
            };
            let block = &block[..end];
            let uuid = tag(block, "UUID");
            if uuid.is_empty() {
                continue;
            }
            players.insert(
                uuid.clone(),
                MutedPlayer {
                    uuid: uuid.clone(),
                    voice_muted: tag(block, "VoiceMuted").eq_ignore_ascii_case("true"),
                    text_muted: tag(block, "TextMuted").eq_ignore_ascii_case("true"),
                    time_of_mute: tag(block, "TimeOfMute"),
                },
            );
        }
        Self { players }
    }

    pub fn state(&self, uuid: &str) -> (bool, bool) {
        self.players
            .get(uuid)
            .map(|player| (player.voice_muted, player.text_muted))
            .unwrap_or((false, false))
    }

    pub fn is_voice_muted(&self, uuid: &str) -> bool {
        self.players
            .get(uuid)
            .is_some_and(|player| player.voice_muted)
    }

    pub fn is_text_muted(&self, uuid: &str) -> bool {
        self.players
            .get(uuid)
            .is_some_and(|player| player.text_muted)
    }

    pub fn apply(&mut self, uuid: &str, voice: bool, muted: bool) {
        let player = self
            .players
            .entry(uuid.to_string())
            .or_insert_with(|| MutedPlayer {
                uuid: uuid.to_string(),
                time_of_mute: chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string(),
                ..Default::default()
            });
        if voice {
            player.voice_muted = muted;
        } else {
            player.text_muted = muted;
        }
        if !player.voice_muted && !player.text_muted {
            self.players.remove(uuid);
        }
    }

    pub fn save(&self, path: &Path) {
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let mut xml = String::from("<?xml version=\"1.0\"?>\n<ArrayOfMutedPlayer>\n");
        for player in self.players.values() {
            xml.push_str("  <MutedPlayer>\n");
            xml.push_str(&format!("    <UUID>{}</UUID>\n", escape(&player.uuid)));
            xml.push_str(&format!(
                "    <VoiceMuted>{}</VoiceMuted>\n",
                if player.voice_muted { "true" } else { "false" }
            ));
            xml.push_str(&format!(
                "    <TextMuted>{}</TextMuted>\n",
                if player.text_muted { "true" } else { "false" }
            ));
            xml.push_str(&format!(
                "    <TimeOfMute>{}</TimeOfMute>\n",
                escape(&player.time_of_mute)
            ));
            xml.push_str("  </MutedPlayer>\n");
        }
        xml.push_str("</ArrayOfMutedPlayer>\n");
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
    fn mutes_are_independent_and_persisted() {
        let xml = "<ArrayOfMutedPlayer><MutedPlayer><UUID>did:key:a</UUID><VoiceMuted>true</VoiceMuted><TextMuted>false</TextMuted><TimeOfMute>2026-01-01</TimeOfMute></MutedPlayer></ArrayOfMutedPlayer>";
        let mut store = MuteStore::parse(xml);
        assert!(store.is_voice_muted("did:key:a"));
        assert!(!store.is_text_muted("did:key:a"));
        store.apply("did:key:a", false, true);
        assert!(store.is_text_muted("did:key:a"));
        store.apply("did:key:a", true, false);
        assert_eq!(store.state("did:key:a"), (false, true));
        let path = std::env::current_dir()
            .unwrap()
            .join(format!("basis-mute-test-{}.xml", std::process::id()));
        store.save(&path);
        let loaded = MuteStore::load(&path);
        assert_eq!(loaded.state("did:key:a"), (false, true));
        let _ = std::fs::remove_file(path);
    }
}
