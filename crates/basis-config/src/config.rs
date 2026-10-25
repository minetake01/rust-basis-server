/// Runtime configuration. Field names mirror the C# `BasisServerConfiguration` where the
/// Rust implementation already consumes them, so one `config.xml` can drive either server.
#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub bind: String,
    pub port: u16,
    pub peer_limit: usize,
    pub password: String,
    pub use_auth: bool,
    pub use_auth_identity: bool,
    pub company_name: String,
    pub product_name: String,
    pub server_uuid: String,
    pub server_name: String,
    pub server_motd: String,
    pub health_host: String,
    pub health_port: u16,
    pub health_path: String,
    pub avatar_reduction: bool,
    pub has_file_support: bool,
    pub enable_statistics: bool,
    pub log_connection_handshake: bool,
    pub crash_reporting_enabled: bool,
    pub auth_validation_timeout_ms: u64,
    pub how_many_duplicate_auth_can_exist: usize,
    pub disallow_headless: bool,
    pub control_socket: bool,
    pub high_quality_distance: f32,
    pub medium_quality_distance: f32,
    pub low_quality_distance: f32,
    pub log_dir: String,
    pub initial_world_url: String,
    pub initial_world_password: String,
    pub config_path: String,
    pub restriction_mode: u8,
    pub enable_avatar_bundle_compression: bool,
    pub max_microphone_range_meters: f32,
    pub max_hearing_range_meters: f32,
    pub min_avatar_eye_height_meters: f32,
    pub max_avatar_eye_height_meters: f32,
    pub max_content_spheres_per_player: i32,
    pub content_sphere_leave_timeout_seconds: i32,
    pub content_sphere_deletion_timer_seconds: i32,
    pub locomotion_policy_fields: u8,
    pub locomotion_policy_jump_height: f32,
    pub locomotion_policy_walk_speed: f32,
    pub locomotion_policy_run_speed: f32,
    pub locomotion_policy_gravity: f32,
    pub locomotion_policy_mode: u8,
    pub image_share_egress_mbps: i32,
    pub image_share_download_mbps: i32,
    pub image_share_enforcement_percent: i32,
    pub avatar_bundle_min_messages: i32,
    pub avatar_bundle_min_bytes: i32,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind: "0.0.0.0".into(),
            port: 4296,
            peer_limit: 65535,
            password: "default_password".into(),
            use_auth: true,
            use_auth_identity: true,
            company_name: "Basis Unity".into(),
            product_name: "Basis Unity".into(),
            server_uuid: "rust-server".into(),
            server_name: "Basis Server".into(),
            server_motd: String::new(),
            health_host: "localhost".into(),
            health_port: 10666,
            health_path: "/health".into(),
            avatar_reduction: true,
            has_file_support: true,
            enable_statistics: true,
            log_connection_handshake: false,
            crash_reporting_enabled: true,
            auth_validation_timeout_ms: 9000,
            how_many_duplicate_auth_can_exist: 2,
            disallow_headless: false,
            control_socket: true,
            high_quality_distance: 10.0,
            medium_quality_distance: 20.0,
            low_quality_distance: 40.0,
            log_dir: "Logs".into(),
            initial_world_url: String::new(),
            initial_world_password: String::new(),
            config_path: "config/config.xml".into(),
            restriction_mode: 0,
            enable_avatar_bundle_compression: true,
            max_microphone_range_meters: 25.0,
            max_hearing_range_meters: 25.0,
            min_avatar_eye_height_meters: 0.1,
            max_avatar_eye_height_meters: 100.0,
            max_content_spheres_per_player: 32,
            content_sphere_leave_timeout_seconds: 60,
            content_sphere_deletion_timer_seconds: 0,
            locomotion_policy_fields: 0,
            locomotion_policy_jump_height: 1.0,
            locomotion_policy_walk_speed: 2.5,
            locomotion_policy_run_speed: 4.0,
            locomotion_policy_gravity: -9.81,
            locomotion_policy_mode: 0,
            image_share_egress_mbps: 200,
            image_share_download_mbps: 200,
            image_share_enforcement_percent: 150,
            avatar_bundle_min_messages: 2,
            avatar_bundle_min_bytes: 128,
        }
    }
}
use std::path::Path;

/// C# first-boot behaviour: write the shipped default configuration before loading it.
/// Returns true when the file was created.
pub fn ensure_default_file(path: &Path) -> std::io::Result<bool> {
    if path.exists() {
        return Ok(false);
    }
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    let mut template = include_str!("../default-config.xml").to_string();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let uuid = format!("{nanos:016x}{:016x}", std::process::id());
    template = template.replace(
        "<ServerUUID>f12d7031c1a34d129273472645ad3c55</ServerUUID>",
        &format!("<ServerUUID>{uuid}</ServerUUID>"),
    );
    std::fs::write(path, template)?;
    Ok(true)
}

/// Loads the subset of the C# `config.xml` schema the Rust data plane currently uses.
/// Unknown fields are ignored, which keeps an existing server config usable while the
/// implementation grows. Environment variables with the same names override the file,
/// matching `Configuration.ProcessEnvironmentalOverrides`.
pub fn apply_file(config: &mut ServerConfig, path: &Path) -> anyhow::Result<()> {
    if !path.exists() {
        return Ok(());
    }
    let xml = std::fs::read_to_string(path)?;
    let doc = roxmltree::Document::parse(&xml)?;
    let root = doc.root_element();

    for node in root.children().filter(|n| n.is_element()) {
        let name = node.tag_name().name();
        let text = node.text().unwrap_or("").trim();
        match name {
            "SetPort" => config.port = parse(text, name)?,
            "PeerLimit" => config.peer_limit = parse(text, name)?,
            "Password" => config.password = text.to_string(),
            "UseAuth" => config.use_auth = parse(text, name)?,
            "UseAuthIdentity" => config.use_auth_identity = parse(text, name)?,
            "CompanyName" => config.company_name = text.to_string(),
            "ProductName" => config.product_name = text.to_string(),
            "ServerUUID" => config.server_uuid = text.to_string(),
            "ServerName" => config.server_name = text.to_string(),
            "HealthCheckHost" => config.health_host = text.to_string(),
            "HealthCheckPort" => config.health_port = parse(text, name)?,
            "HealthPath" => config.health_path = normalize_path(text),
            "ServerMotd" => config.server_motd = text.to_string(),
            "HasFileSupport" => config.has_file_support = parse(text, name)?,
            "EnableStatistics" => config.enable_statistics = parse(text, name)?,
            "LogConnectionHandshake" => config.log_connection_handshake = parse(text, name)?,
            "CrashReportingEnabled" => config.crash_reporting_enabled = parse(text, name)?,
            "MaxMicrophoneRangeMeters" => config.max_microphone_range_meters = parse(text, name)?,
            "MaxHearingRangeMeters" => config.max_hearing_range_meters = parse(text, name)?,
            "MinAvatarEyeHeightMeters" => config.min_avatar_eye_height_meters = parse(text, name)?,
            "MaxAvatarEyeHeightMeters" => config.max_avatar_eye_height_meters = parse(text, name)?,
            "MaxContentSpheresPerPlayer" => {
                config.max_content_spheres_per_player = parse(text, name)?
            }
            "ContentSphereLeaveTimeoutSeconds" => {
                config.content_sphere_leave_timeout_seconds = parse(text, name)?
            }
            "ContentSphereDeletionTimerSeconds" => {
                config.content_sphere_deletion_timer_seconds = parse(text, name)?
            }
            "LocomotionPolicyFields" => config.locomotion_policy_fields = parse(text, name)?,
            "LocomotionPolicyJumpHeight" => {
                config.locomotion_policy_jump_height = parse(text, name)?
            }
            "LocomotionPolicyWalkSpeed" => config.locomotion_policy_walk_speed = parse(text, name)?,
            "LocomotionPolicyRunSpeed" => config.locomotion_policy_run_speed = parse(text, name)?,
            "LocomotionPolicyGravity" => config.locomotion_policy_gravity = parse(text, name)?,
            "LocomotionPolicyMode" => config.locomotion_policy_mode = parse(text, name)?,
            "ImageShareEgressMegabitsPerSecond" => {
                config.image_share_egress_mbps = parse(text, name)?
            }
            "ImageShareDownloadMegabitsPerSecond" => {
                config.image_share_download_mbps = parse(text, name)?
            }
            "ImageShareEgressEnforcementPercent" => {
                config.image_share_enforcement_percent = parse(text, name)?
            }
            "AvatarBundleMinMessages" => config.avatar_bundle_min_messages = parse(text, name)?,
            "AvatarBundleMinBytes" => config.avatar_bundle_min_bytes = parse(text, name)?,
            "EnableAvatarBundleCompression" => {
                config.enable_avatar_bundle_compression = parse(text, name)?
            }
            "BasisUserRestrictionMode" => {
                config.restriction_mode = match text.trim() {
                    "Normal" => 0,
                    "BanList" => 1,
                    "AllowList" => 2,
                    "RejoinOnly" => 3,
                    other => parse(other, name)?,
                }
            }
            "AuthValidationTimeOutMiliseconds" => {
                config.auth_validation_timeout_ms = parse(text, name)?
            }
            "HighQualityDistance" => config.high_quality_distance = parse(text, name)?,
            "MediumQualityDistance" => config.medium_quality_distance = parse(text, name)?,
            "LowQualityDistance" => config.low_quality_distance = parse(text, name)?,
            "EnableAvatarReduction" => config.avatar_reduction = parse(text, name)?,
            _ => {}
        }
    }
    apply_env(config);
    Ok(())
}

pub fn apply_env(config: &mut ServerConfig) {
    fn report(field: &str, value: &str, secret: bool) {
        let shown = if secret { "<redacted>" } else { value };
        println!("Applying Environmental Override with Field:{field} Value:{shown}");
    }

    if let Ok(v) = std::env::var("SetPort") {
        if let Ok(v) = v.parse() {
            config.port = v;
            report("SetPort", &v.to_string(), false);
        }
    }
    if let Ok(v) = std::env::var("PeerLimit") {
        if let Ok(v) = v.parse() {
            config.peer_limit = v;
            report("PeerLimit", &v.to_string(), false);
        }
    }
    if let Ok(v) = std::env::var("Password") {
        config.password = v;
        report("Password", &config.password, true);
    }
    if let Ok(v) = std::env::var("UseAuth") {
        if let Ok(v) = v.parse() {
            config.use_auth = v;
            report("UseAuth", &v.to_string(), false);
        }
    }
    if let Ok(v) = std::env::var("UseAuthIdentity") {
        if let Ok(v) = v.parse() {
            config.use_auth_identity = v;
            report("UseAuthIdentity", &v.to_string(), false);
        }
    }
    if let Ok(v) = std::env::var("CompanyName") {
        config.company_name = v;
    }
    if let Ok(v) = std::env::var("ProductName") {
        config.product_name = v;
    }
    if let Ok(v) = std::env::var("ServerUUID") {
        config.server_uuid = v;
    }
    if let Ok(v) = std::env::var("HealthCheckHost") {
        config.health_host = v;
    }
    if let Ok(v) = std::env::var("HealthCheckPort") {
        if let Ok(v) = v.parse() {
            config.health_port = v;
        }
    }
    if let Ok(v) = std::env::var("EnableAvatarReduction") {
        if let Ok(v) = v.parse() {
            config.avatar_reduction = v;
        }
    }
    if let Ok(v) = std::env::var("ServerMotd") {
        config.server_motd = v;
    }
    if let Ok(v) = std::env::var("HasFileSupport") {
        if let Ok(v) = v.parse() {
            config.has_file_support = v;
            report("HasFileSupport", &v.to_string(), false);
        }
    }
    if let Ok(v) = std::env::var("EnableStatistics") {
        if let Ok(v) = v.parse() {
            config.enable_statistics = v;
            report("EnableStatistics", &v.to_string(), false);
        }
    }
    if let Ok(v) = std::env::var("AuthValidationTimeOutMiliseconds") {
        if let Ok(v) = v.parse() {
            config.auth_validation_timeout_ms = v;
            report("AuthValidationTimeOutMiliseconds", &v.to_string(), false);
        }
    }
    if let Ok(v) = std::env::var("LogConnectionHandshake") {
        if let Ok(v) = v.parse() {
            config.log_connection_handshake = v;
            report("LogConnectionHandshake", &v.to_string(), false);
        }
    }
    if let Ok(v) = std::env::var("CrashReportingEnabled") {
        if let Ok(v) = v.parse() {
            config.crash_reporting_enabled = v;
            report("CrashReportingEnabled", &v.to_string(), false);
        }
    }
    if let Ok(v) = std::env::var("HighQualityDistance") {
        if let Ok(v) = v.parse() {
            config.high_quality_distance = v;
        }
    }
    if let Ok(v) = std::env::var("MediumQualityDistance") {
        if let Ok(v) = v.parse() {
            config.medium_quality_distance = v;
        }
    }
    if let Ok(v) = std::env::var("LowQualityDistance") {
        if let Ok(v) = v.parse() {
            config.low_quality_distance = v;
        }
    }
    if let Ok(v) = std::env::var("HealthPath") {
        config.health_path = normalize_path(&v);
    }
}

fn parse<T: std::str::FromStr>(text: &str, field: &str) -> anyhow::Result<T> {
    text.parse()
        .map_err(|_| anyhow::anyhow!("invalid <{field}> value: {text:?}"))
}

fn normalize_path(path: &str) -> String {
    if path.is_empty() {
        "/health".to_string()
    } else if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{path}")
    }
}

const SCHEMA_TAGS: &[&str] = &[
    "ConfigVersion",
    "PeerLimit",
    "SetPort",
    "ServerName",
    "ServerMotd",
    "ServerUUID",
    "CompanyName",
    "ProductName",
    "EnableStatistics",
    "HasFileSupport",
    "HealthCheckHost",
    "HealthCheckPort",
    "HealthPath",
    "EnableAvatarReduction",
    "Password",
    "UseAuth",
    "UseAuthIdentity",
    "LogConnectionHandshake",
    "CrashReportingEnabled",
    "AuthValidationTimeOutMiliseconds",
    "HighQualityDistance",
    "MediumQualityDistance",
    "LowQualityDistance",
];

fn extract_element(template: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}");
    let start = template.find(&open)?;
    let after_open = template[start..].find('>')? + start;
    if template[start..=after_open].ends_with("/>") {
        return Some(template[start..=after_open].to_string());
    }
    let close = format!("</{tag}>");
    let end = template[after_open..].find(&close)? + after_open + close.len();
    Some(template[start..end].to_string())
}

/// C# `BasisConfigXmlDocs.NeedsUpgrade` equivalent for the fields this server uses:
/// an existing config missing a known element is rewritten with the missing settings
/// and the current schema version. Returns true when the file was upgraded.
pub fn ensure_schema(path: &Path) -> std::io::Result<bool> {
    let Ok(text) = std::fs::read_to_string(path) else {
        return Ok(false);
    };
    let template = include_str!("../default-config.xml");
    let mut missing = Vec::new();
    for tag in SCHEMA_TAGS {
        if !text.contains(&format!("<{tag}")) {
            if let Some(block) = extract_element(template, tag) {
                missing.push(block);
            }
        }
    }
    let version_current = text.contains("<ConfigVersion>15</ConfigVersion>");
    if missing.is_empty() && version_current {
        return Ok(false);
    }
    let Some(close) = text.rfind("</Configuration>") else {
        return Ok(false);
    };
    let mut updated = text[..close].to_string();
    updated.push('\n');
    for block in &missing {
        updated.push_str("  ");
        updated.push_str(block);
        updated.push('\n');
    }
    updated.push_str(&text[close..]);
    if !version_current {
        let current = extract_element(template, "ConfigVersion").unwrap_or_default();
        if updated.contains("<ConfigVersion>") {
            let start = updated.find("<ConfigVersion>").unwrap();
            if let Some(end) = updated[start..].find("</ConfigVersion>") {
                updated.replace_range(start..start + end + "</ConfigVersion>".len(), &current);
            }
        }
    }
    std::fs::write(path, updated)?;
    Ok(true)
}

/// Replace top-level element values in an existing config.xml, preserving
/// comments and unrelated settings. Empty string values are written self-closing.
pub fn update_values(path: &Path, values: &[(&str, &str)]) -> std::io::Result<()> {
    let mut text = std::fs::read_to_string(path)?;
    for (tag, value) in values {
        text = set_element(&text, tag, value);
    }
    std::fs::write(path, text)
}

fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn set_element(text: &str, tag: &str, value: &str) -> String {
    let open = format!("<{tag}");
    let replacement = if value.is_empty() {
        format!("<{tag} />")
    } else {
        format!("<{tag}>{}</{tag}>", xml_escape(value))
    };
    let Some(start) = text.find(&open) else {
        if let Some(close) = text.rfind("</Configuration>") {
            let mut out = text[..close].to_string();
            out.push_str("  ");
            out.push_str(&replacement);
            out.push('\n');
            out.push_str(&text[close..]);
            return out;
        }
        return text.to_string();
    };
    let Some(open_end_rel) = text[start..].find('>') else {
        return text.to_string();
    };
    let open_end = start + open_end_rel;
    if text[start..=open_end].ends_with("/>") {
        let mut out = text.to_string();
        out.replace_range(start..=open_end, &replacement);
        return out;
    }
    let close = format!("</{tag}>");
    let Some(close_rel) = text[open_end..].find(&close) else {
        return text.to_string();
    };
    let close_start = open_end + close_rel;
    let close_end = close_start + close.len();
    let mut out = text.to_string();
    out.replace_range(open_end + 1..close_start, &xml_escape(value));
    if value.is_empty() {
        out.replace_range(start..close_end, &format!("<{tag} />"));
    }
    out
}

/// Rewrites simple element values in an existing config.xml without touching other settings.
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_core_fields() {
        let dir = std::path::PathBuf::from("target")
            .join(format!("basis-rust-config-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.xml");
        std::fs::write(
            &path,
            r#"<?xml version="1.0"?>
            <Configuration>
              <SetPort>4400</SetPort>
              <PeerLimit>32</PeerLimit>
              <Password>secret</Password>
              <UseAuth>true</UseAuth>
              <UseAuthIdentity>false</UseAuthIdentity>
              <CompanyName>Acme</CompanyName>
              <ProductName>World</ProductName>
              <HealthCheckPort>10700</HealthCheckPort>
              <HealthPath>status</HealthPath>
              <EnableAvatarReduction>false</EnableAvatarReduction>
              <ServerMotd>hello</ServerMotd>
              <HasFileSupport>false</HasFileSupport>
              <EnableStatistics>false</EnableStatistics>
              <LogConnectionHandshake>true</LogConnectionHandshake>
              <CrashReportingEnabled>false</CrashReportingEnabled>
              <HighQualityDistance>7</HighQualityDistance>
              <MediumQualityDistance>17</MediumQualityDistance>
              <LowQualityDistance>37</LowQualityDistance>
            </Configuration>"#,
        )
        .unwrap();

        let mut c = ServerConfig::default();
        apply_file(&mut c, &path).unwrap();
        assert_eq!(c.port, 4400);
        assert_eq!(c.peer_limit, 32);
        assert_eq!(c.password, "secret");
        assert!(c.use_auth);
        assert!(!c.use_auth_identity);
        assert_eq!(c.company_name, "Acme");
        assert_eq!(c.product_name, "World");
        assert_eq!(c.health_port, 10700);
        assert_eq!(c.health_path, "/status");
        assert!(!c.avatar_reduction);
        assert_eq!(c.server_motd, "hello");
        assert!(!c.has_file_support);
        assert!(!c.enable_statistics);
        assert!(c.log_connection_handshake);
        assert!(!c.crash_reporting_enabled);
        assert_eq!(c.high_quality_distance, 7.0);
        assert_eq!(c.medium_quality_distance, 17.0);
        assert_eq!(c.low_quality_distance, 37.0);
    }

    #[test]
    fn ensure_default_file_writes_the_csharp_default_schema_once() {
        let path = std::env::current_dir()
            .unwrap()
            .join(format!("basis-config-test-{}.xml", std::process::id()));
        let _ = std::fs::remove_file(&path);
        assert!(ensure_default_file(&path).unwrap());
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("<ServerName>Basis Server</ServerName>"));
        assert!(text.contains("<SetPort>4296</SetPort>"));
        assert!(!text.contains("f12d7031c1a34d129273472645ad3c55"));
        assert!(!ensure_default_file(&path).unwrap());
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn ensure_schema_adds_missing_settings_and_bumps_version() {
        let path = std::env::current_dir()
            .unwrap()
            .join(format!("basis-schema-test-{}.xml", std::process::id()));
        let template = include_str!("../default-config.xml");
        let broken = template
            .replace(
                "<ConfigVersion>15</ConfigVersion>",
                "<ConfigVersion>14</ConfigVersion>",
            )
            .replace("<ServerName>Basis Server</ServerName>\n", "");
        std::fs::write(&path, broken).unwrap();
        assert!(ensure_schema(&path).unwrap());
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("<ConfigVersion>15</ConfigVersion>"));
        assert!(text.contains("<ServerName>Basis Server</ServerName>"));
        assert!(!ensure_schema(&path).unwrap());
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn update_values_preserves_comments_and_updates_self_closing() {
        let path = std::env::current_dir()
            .unwrap()
            .join(format!("basis-update-test-{}.xml", std::process::id()));
        std::fs::write(
            &path,
            "<Configuration>\n  <!-- keep -->\n  <ServerName>Old</ServerName>\n  <ServerMotd />\n</Configuration>\n",
        )
        .unwrap();
        update_values(
            &path,
            &[("ServerName", "New & Name"), ("ServerMotd", "hello")],
        )
        .unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("keep"));
        assert!(text.contains("<ServerName>New &amp; Name</ServerName>"));
        assert!(text.contains("<ServerMotd>hello</ServerMotd>"));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn defaults_match_the_csharp_server() {
        let c = ServerConfig::default();
        assert_eq!(c.peer_limit, 65535);
        assert_eq!(c.port, 4296);
        assert!(c.use_auth);
        assert!(c.use_auth_identity);
        assert!(c.has_file_support);
        assert!(c.enable_statistics);
        assert_eq!(c.health_host, "localhost");
        assert_eq!(c.health_port, 10666);
        assert_eq!(c.high_quality_distance, 10.0);
        assert_eq!(c.medium_quality_distance, 20.0);
        assert_eq!(c.low_quality_distance, 40.0);
    }
}
