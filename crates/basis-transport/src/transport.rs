use crate::allowlist::AllowList;
use crate::bundle_queue::BundleQueue;
use crate::locks::GlobalLocks;
use crate::moderation::BanStore;
use crate::mutes::MuteStore;
use basis_avatar::repack;
use basis_config::ServerConfig;
use basis_health::{HealthConfig, HealthStats};
use basis_logging::{debug, error, info, warn};
use basis_protocol::*;
use basis_wire::fast;
use basis_wire::{Reader, Writer};
use ed25519_dalek::{Signature, Verifier};
use std::collections::{HashMap, HashSet};
use std::io;
use std::io::Write as _;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const PROP_UNRELIABLE: u8 = 0;
const DISCONNECTION_CHANNEL: u8 = 2;
const PROP_CHANNELED: u8 = 1;
const PROP_COMPACT_MERGED: u8 = 18;
const PROP_ACK: u8 = 2;
const PROP_PING: u8 = 3;
const PROP_PONG: u8 = 4;
const PROP_CONNECT_REQUEST: u8 = 5;
const PROP_CONNECT_ACCEPT: u8 = 6;
const PROP_DISCONNECT: u8 = 7;
const PROP_MTU_CHECK: u8 = 9;
const PROP_MTU_OK: u8 = 10;
const PROP_MERGED: u8 = 12;
const PROP_SHUTDOWN_OK: u8 = 13;
const PROP_PEER_NOT_FOUND: u8 = 14;

const PROTOCOL_ID: i32 = 14;
const MAX_SEQUENCE: u16 = 32768;
const DEFAULT_MTU: usize = 1024;
const RX_BUFFER_BYTES: usize = 65535;
const CHANNELED_HEADER: usize = 4;
const FRAGMENT_HEADER: usize = 6;

#[derive(Debug)]
struct PendingReliable {
    seq: u16,
    channel: u8,
    packet: Vec<u8>,
    sent: Instant,
    attempts: u8,
}

fn distance(a: [f32; 3], b: [f32; 3]) -> f32 {
    let dx = a[0] - b[0];
    let dy = a[1] - b[1];
    let dz = a[2] - b[2];
    (dx * dx + dy * dy + dz * dz).sqrt()
}

fn quality_for_distance(distance: f32, high: f32, medium: f32, low: f32) -> AvatarQuality {
    if distance <= high {
        AvatarQuality::High
    } else if distance <= medium {
        AvatarQuality::Medium
    } else if distance <= low {
        AvatarQuality::Low
    } else {
        AvatarQuality::VeryLow
    }
}

fn refill_info_tokens(tokens: f64, last: Instant, now: Instant) -> f64 {
    (tokens + now.duration_since(last).as_secs_f64() * 100.0).min(200.0)
}

fn auth_timeout_ms(configured: u64, population: usize) -> u64 {
    let extra = (population as u64).saturating_mul(12).min(45_000);
    configured.max(1).saturating_add(extra)
}

fn limited_chars(value: &str, max: usize) -> String {
    value.chars().take(max).collect()
}

fn avatar_channel(quality: AvatarQuality, has_additional: bool) -> u8 {
    match (quality, has_additional) {
        (AvatarQuality::High, false) => PLAYER_AVATAR_HIGH_CHANNEL,
        (AvatarQuality::High, true) => PLAYER_AVATAR_HIGH_ADDITIONAL_CHANNEL,
        (AvatarQuality::Medium, false) => PLAYER_AVATAR_MEDIUM_CHANNEL,
        (AvatarQuality::Medium, true) => PLAYER_AVATAR_MEDIUM_ADDITIONAL_CHANNEL,
        (AvatarQuality::Low, false) => PLAYER_AVATAR_LOW_CHANNEL,
        (AvatarQuality::Low, true) => PLAYER_AVATAR_LOW_ADDITIONAL_CHANNEL,
        (AvatarQuality::VeryLow, false) => PLAYER_AVATAR_VERY_LOW_CHANNEL,
        (AvatarQuality::VeryLow, true) => PLAYER_AVATAR_VERY_LOW_ADDITIONAL_CHANNEL,
    }
}

#[derive(Debug)]
struct Fragmented {
    total: u16,
    parts: Vec<Option<Vec<u8>>>,
}

fn load_default_library() -> (Vec<ServerLibraryItem>, Vec<u8>) {
    let Ok(entries) = std::fs::read_dir("defaultlibrary") else {
        return (Vec::new(), Vec::new());
    };
    let mut items = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|value| value.to_str()) != Some("xml") {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        let url = xml_tag(&text, "Url").unwrap_or_default();
        if url.is_empty() {
            continue;
        }
        let mode = xml_tag(&text, "Mode")
            .and_then(|value| value.parse().ok())
            .unwrap_or(0);
        let password = xml_tag(&text, "Password").unwrap_or_default();
        items.push(ServerLibraryItem {
            mode,
            url,
            password,
        });
    }
    let wire = build_server_library(&items);
    (items, wire)
}

fn xml_tag(text: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = text.find(&open)? + open.len();
    let end = text[start..].find(&close)? + start;
    Some(text[start..end].trim().to_string())
}

fn save_library_item(item: &ServerLibraryItem) {
    let _ = std::fs::create_dir_all("defaultlibrary");
    let name: String = item
        .url
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.') {
                c
            } else {
                '_'
            }
        })
        .take(80)
        .collect();
    let xml = format!(
        "<BasisDefaultLibraryConfiguration><Mode>{}</Mode><Url>{}</Url><Password>{}</Password></BasisDefaultLibraryConfiguration>\n",
        item.mode,
        xml_escape(&item.url),
        xml_escape(&item.password)
    );
    let _ = std::fs::write(format!("defaultlibrary/{name}.xml"), xml);
}

fn remove_library_item(url: &str) {
    let Ok(entries) = std::fs::read_dir("defaultlibrary") else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        if xml_tag(&text, "Url").as_deref() == Some(url) {
            let _ = std::fs::remove_file(path);
        }
    }
}

fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

struct PreloadSession {
    mode: u8,
    expected: HashSet<u16>,
    ready: HashSet<u16>,
    failed: HashSet<u16>,
    started: Instant,
}

impl PreloadSession {
    fn complete(&self) -> bool {
        self.ready.len() + self.failed.len() >= self.expected.len()
    }
}

struct TokenBucket {
    tokens: f32,
    last_refill: Instant,
    rate: f32,
    burst: f32,
}

impl TokenBucket {
    fn new(rate: f32, burst: f32) -> Self {
        Self {
            tokens: burst,
            last_refill: Instant::now(),
            rate,
            burst,
        }
    }

    fn try_consume(&mut self) -> bool {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f32();
        self.last_refill = now;
        self.tokens = (self.tokens + elapsed * self.rate).min(self.burst);
        if self.tokens < 1.0 {
            return false;
        }
        self.tokens -= 1.0;
        true
    }
}

struct Peer {
    endpoint: SocketAddr,
    id: u16,
    connect_time: i64,
    connected_at: Instant,
    last_seen: Instant,
    reliable: Vec<PendingReliable>,
    connection_num: u8,
    _remote_id: i32,
    authenticated: bool,
    metadata_raw: Vec<u8>,
    ready_raw: Vec<u8>,
    avatar_change_raw: Vec<u8>,
    latest_sync_raw: Vec<u8>,
    position: Option<[f32; 3]>,
    did: String,
    display_name: String,
    platform: String,
    challenge: Option<Vec<u8>>,
    transcript: Option<Vec<u8>>,
    server_public: Option<[u8; 32]>,
    client_public: Option<[u8; 32]>,
    payload_hash: [u8; 32],
    protocol: u16,
    inbound_cipher: Option<basis_crypto::PacketCipher>,
    voice_recipients: Option<Vec<u16>>,
    chat_rate: TokenBucket,
    typing_rate: TokenBucket,
    jiggle_rate: TokenBucket,
    next_fragment_id: u16,
    out_seq: HashMap<u8, u16>,
    in_seq: HashMap<u8, u16>,
    fragments: HashMap<u16, Fragmented>,
}

impl Peer {
    fn new(
        endpoint: SocketAddr,
        id: u16,
        connect_time: i64,
        connection_num: u8,
        remote_id: i32,
    ) -> Self {
        Self {
            endpoint,
            id,
            connect_time,
            connected_at: Instant::now(),
            last_seen: Instant::now(),
            reliable: Vec::new(),
            connection_num,
            _remote_id: remote_id,
            authenticated: false,
            metadata_raw: Vec::new(),
            ready_raw: Vec::new(),
            avatar_change_raw: Vec::new(),
            latest_sync_raw: Vec::new(),
            position: None,
            did: String::new(),
            display_name: String::new(),
            platform: String::new(),
            challenge: None,
            transcript: None,
            server_public: None,
            client_public: None,
            payload_hash: [0u8; 32],
            protocol: PROTOCOL_VERSION,
            inbound_cipher: None,
            voice_recipients: None,
            chat_rate: TokenBucket::new(2.0, 6.0),
            typing_rate: TokenBucket::new(2.0, 8.0),
            jiggle_rate: TokenBucket::new(8.0, 16.0),
            next_fragment_id: 0,
            out_seq: HashMap::new(),
            in_seq: HashMap::new(),
            fragments: HashMap::new(),
        }
    }

    /// Builds a ReadyMessage from the latest stored pieces. A late joiner gets the most recent
    /// keyframe, not the pose the peer happened to have at connect time.
    fn ready_for_spawn(&self) -> Vec<u8> {
        if !self.ready_raw.is_empty() {
            return self.ready_raw.clone();
        }
        if self.avatar_change_raw.is_empty() || self.latest_sync_raw.is_empty() {
            return self.ready_raw.clone();
        }
        let mut out = Vec::with_capacity(
            self.metadata_raw.len() + self.avatar_change_raw.len() + self.latest_sync_raw.len(),
        );
        out.extend_from_slice(&self.metadata_raw);
        out.extend_from_slice(&self.avatar_change_raw);
        out.extend_from_slice(&self.latest_sync_raw);
        out
    }

    fn next_out_seq(&mut self, channel_id: u8) -> u16 {
        let slot = self.out_seq.entry(channel_id).or_insert(0);
        let seq = *slot;
        *slot = (seq + 1) % MAX_SEQUENCE;
        seq
    }
}

fn json_escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

fn parse_admins_xml(content: &str) -> HashSet<String> {
    let mut admins = HashSet::new();
    for chunk in content.split("<string>").skip(1) {
        if let Some(end) = chunk.find("</string>") {
            let value = chunk[..end].trim();
            if !value.is_empty() {
                admins.insert(value.to_string());
            }
        }
    }
    admins
}

fn config_dir(config: &ServerConfig) -> std::path::PathBuf {
    std::path::Path::new(&config.config_path)
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| std::path::Path::new("."))
        .to_path_buf()
}

fn data_file_candidates(config: &ServerConfig, name: &str) -> Vec<std::path::PathBuf> {
    let mut candidates = vec![config_dir(config).join(name)];
    for legacy in ["config", "Configuration"] {
        let path = std::path::Path::new(legacy).join(name);
        if !candidates.contains(&path) {
            candidates.push(path);
        }
    }
    candidates
}

fn admins_path(config: &ServerConfig) -> std::path::PathBuf {
    config_dir(config).join("admins.xml")
}

fn load_admins(config: &ServerConfig) -> HashSet<String> {
    if !config.has_file_support {
        return HashSet::new();
    }
    for path in data_file_candidates(config, "admins.xml") {
        if let Ok(content) = std::fs::read_to_string(&path) {
            return parse_admins_xml(&content);
        }
    }
    let path = admins_path(config);
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    info!("Creating a new admin list...");
    let _ = std::fs::write(
        &path,
        "<?xml version=\"1.0\"?>\n<ArrayOfString>\n</ArrayOfString>\n",
    );
    HashSet::new()
}

fn ban_path() -> std::path::PathBuf {
    let config = std::path::Path::new("config/banned_players.xml");
    let csharp = std::path::Path::new("Configuration/banned_players.xml");
    if !config.exists() && csharp.exists() {
        csharp.to_path_buf()
    } else {
        config.to_path_buf()
    }
}

fn allowlist_path() -> std::path::PathBuf {
    let config = std::path::Path::new("config/BasisAllowList.txt");
    let csharp = std::path::Path::new("Configuration/BasisAllowList.txt");
    if !config.exists() && csharp.exists() {
        csharp.to_path_buf()
    } else {
        config.to_path_buf()
    }
}

fn permissions_path(config: &ServerConfig) -> std::path::PathBuf {
    config_dir(config).join("permissions.xml")
}

fn mute_path() -> std::path::PathBuf {
    let config = std::path::Path::new("config/muted_players.xml");
    let csharp = std::path::Path::new("Configuration/muted_players.xml");
    if !config.exists() && csharp.exists() {
        csharp.to_path_buf()
    } else {
        config.to_path_buf()
    }
}

/// Loads permissions.xml next to config.xml (where the C# server keeps it), falling
/// back to the historical working-directory folders, then applies the C# built-in
/// defaults. The defaults are what give `admin` its `*` node and `default` the
/// resource-load nodes, so a hand-written or wizard-written file that only names the
/// admin user still resolves to a working administrator.
fn load_permissions(
    config: &ServerConfig,
) -> (basis_permissions::PermissionStore, std::path::PathBuf) {
    if config.has_file_support {
        for path in data_file_candidates(config, "permissions.xml") {
            if !path.exists() {
                continue;
            }
            match basis_permissions::PermissionStore::load(&path) {
                Ok(mut store) => {
                    store.ensure_defaults();
                    return (store, path);
                }
                Err(e) => warn!("Failed to load {}: {e}", path.display()),
            }
        }
    }
    (
        basis_permissions::PermissionStore::with_defaults(),
        permissions_path(config),
    )
}

fn load_blocked_words(config: &ServerConfig) -> Vec<String> {
    if !config.has_file_support {
        return Vec::new();
    }
    for path in [
        "config/chat_word_filter.txt",
        "Configuration/chat_word_filter.txt",
    ] {
        if let Ok(content) = std::fs::read_to_string(path) {
            let words: Vec<String> = content
                .lines()
                .map(str::trim)
                .filter(|line| !line.is_empty() && !line.starts_with('#'))
                .map(str::to_string)
                .collect();
            info!(
                "Loaded {} words into chat filter (using homoglyph + trigram detection)",
                words.len()
            );
            return words;
        }
    }
    let path = "config/chat_word_filter.txt";
    if let Some(parent) = std::path::Path::new(path).parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if std::fs::write(path, basis_protocol::wordfilter::default_file_contents()).is_ok() {
        info!("Created default chat word filter file: {path}");
        info!(
            "Loaded {} words into chat filter (using homoglyph + trigram detection)",
            basis_protocol::wordfilter::default_words_vec().len()
        );
    }
    basis_protocol::wordfilter::default_words_vec()
}

pub struct Server {
    socket: UdpSocket,
    config: ServerConfig,
    blocked_words: Vec<String>,
    permissions: basis_permissions::PermissionStore,
    permissions_file: std::path::PathBuf,
    locks: GlobalLocks,
    restriction_mode: u8,
    opus_packet_loss: u8,
    opus_frame_duration: u8,
    opus_global_bitrate: i32,
    opus_user_bitrates: HashMap<u16, i32>,
    headless_audio_enabled: bool,
    headless_disallowed: bool,
    audio_microphone_meters: f32,
    audio_hearing_meters: f32,
    avatar_scale_min: f32,
    avatar_scale_max: f32,
    max_spheres: i32,
    sphere_leave_timeout: i32,
    sphere_deletion_timer: i32,
    locomotion_policy: (u8, f32, f32, f32, f32, u8),
    reduction_interval: i32,
    reduction_base: i32,
    reduction_rate: f32,
    reduction_slowest: f32,
    bundle_min_messages: i32,
    bundle_min_bytes: i32,
    bsr_profiling: bool,
    bundle_zstd: bool,
    bundle_zstd_deltas: bool,
    bundle_zstd_level: i32,
    bundle_zstd_max_shed: i32,
    image_egress_mbps: i32,
    image_download_mbps: i32,
    image_enforcement_percent: i32,
    allowlist: AllowList,
    bans: BanStore,
    banned_ips: HashSet<IpAddr>,
    mutes: MuteStore,
    announce_mode: HashSet<u16>,
    shout_mode: HashSet<u16>,
    full_quality_bypass: HashSet<u16>,
    avatar_last_sent: HashMap<(u16, u16), (Instant, AvatarQuality)>,
    crash_reporting_enabled: bool,
    crash_seen: HashMap<String, HashSet<u64>>,
    peers: HashMap<SocketAddr, Peer>,
    next_peer_id: u16,
    stats: Arc<HealthStats>,
    telemetry: basis_telemetry::Telemetry,
    visitors: Arc<AtomicUsize>,
    info_last_seen: HashMap<IpAddr, Instant>,
    info_tokens: f64,
    info_last_refill: Instant,
    _control: Option<basis_control::ControlServer>,
    p2p: basis_p2p::Broker,
    control_players: Arc<Mutex<Vec<basis_control::ControlPlayer>>>,
    health_players: basis_health::Players,
    health_worlds: basis_health::Worlds,
    library_items: Vec<ServerLibraryItem>,
    library_wire: Vec<u8>,
    bundle_compression: bool,
    bundle_queue: BundleQueue,
    bundle_last_flush: Instant,
    world_commands: basis_health::WorldCommands,
    pending_world_unload: Option<(Instant, Vec<String>)>,
    pending_auth: Vec<(Instant, SocketAddr)>,
    net_ids: HashMap<String, u16>,
    scene_cache: HashMap<(u16, u16), Vec<u8>>,
    ownership: HashMap<String, u16>,
    resources: HashMap<String, Vec<u8>>,
    preload_sessions: HashMap<String, PreloadSession>,
    next_net_id: u16,
    network_id_counter: i32,
}

impl Server {
    pub fn bind(config: ServerConfig) -> io::Result<Self> {
        let addr = format!("{}:{}", config.bind, config.port);
        let socket = UdpSocket::bind(&addr)?;
        socket.set_read_timeout(Some(Duration::from_millis(500)))?;
        let stats = Arc::new(HealthStats::new());
        let visitors = Arc::new(AtomicUsize::new(0));
        let health_players = Arc::new(std::sync::Mutex::new(Vec::new()));
        let health_worlds = Arc::new(std::sync::Mutex::new(Vec::new()));
        let world_commands = Arc::new(std::sync::Mutex::new(Vec::new()));
        basis_health::start(
            HealthConfig {
                host: config.health_host.clone(),
                port: config.health_port,
                path: config.health_path.clone(),
                capacity: config.peer_limit,
                enable_statistics: config.enable_statistics,
                version: PROTOCOL_VERSION.to_string(),
            },
            Arc::clone(&stats),
            Arc::clone(&visitors),
            Arc::clone(&health_players),
            Arc::clone(&health_worlds),
            Arc::clone(&world_commands),
        );
        let mut telemetry = basis_telemetry::Telemetry::new();
        telemetry.log_startup(&config, std::mem::size_of::<Peer>(), RX_BUFFER_BYTES);
        let admins = load_admins(&config);
        let admin_list: Vec<&str> = admins.iter().map(String::as_str).collect();
        info!("Loaded Admins {} {}", admins.len(), admin_list.join(", "));
        if config.use_auth_identity {
            info!("DidAuthIdentity initialized.");
        }
        info!("Listening on UDP port {}", config.port);
        info!("  IPv4 bind: {}", config.bind);
        info!("[P2P] Broker initialised.");
        info!("Server Worker Threads Booted");
        let (library_items, library_wire) = load_default_library();
        info!(
            "Default library loaded with {} item(s).",
            library_items.len()
        );
        let control_players = Arc::new(Mutex::new(Vec::new()));
        let control = if config.control_socket {
            basis_control::default_path().and_then(|path| {
                basis_control::ControlServer::start(basis_control::ControlConfig {
                    path,
                    server_name: config.server_name.clone(),
                    port: config.port,
                    peer_limit: config.peer_limit,
                    players: Arc::clone(&control_players),
                    started: Instant::now(),
                })
            })
        } else {
            None
        };
        let bundle_compression = config.enable_avatar_bundle_compression;
        let (permissions, permissions_file) = load_permissions(&config);
        let mut server = Self {
            socket,
            blocked_words: load_blocked_words(&config),
            permissions,
            permissions_file,
            locks: GlobalLocks {
                user_restriction_mode: config.restriction_mode,
                ..Default::default()
            },
            restriction_mode: config.restriction_mode,
            opus_packet_loss: 0,
            opus_frame_duration: 20,
            opus_global_bitrate: 0,
            opus_user_bitrates: HashMap::new(),
            headless_audio_enabled: true,
            headless_disallowed: config.disallow_headless,
            audio_microphone_meters: config.max_microphone_range_meters,
            audio_hearing_meters: config.max_hearing_range_meters,
            avatar_scale_min: config.min_avatar_eye_height_meters,
            avatar_scale_max: config.max_avatar_eye_height_meters,
            max_spheres: config.max_content_spheres_per_player,
            sphere_leave_timeout: config.content_sphere_leave_timeout_seconds,
            sphere_deletion_timer: config.content_sphere_deletion_timer_seconds,
            locomotion_policy: (
                config.locomotion_policy_fields,
                config.locomotion_policy_jump_height,
                config.locomotion_policy_walk_speed,
                config.locomotion_policy_run_speed,
                config.locomotion_policy_gravity,
                config.locomotion_policy_mode,
            ),
            reduction_interval: 50,
            reduction_base: 1,
            reduction_rate: 0.005,
            reduction_slowest: 2.55,
            bundle_min_messages: config.avatar_bundle_min_messages,
            bundle_min_bytes: config.avatar_bundle_min_bytes,
            bsr_profiling: false,
            bundle_zstd: false,
            bundle_zstd_deltas: false,
            bundle_zstd_level: 0,
            bundle_zstd_max_shed: 0,
            image_egress_mbps: config.image_share_egress_mbps,
            image_download_mbps: config.image_share_download_mbps,
            image_enforcement_percent: config.image_share_enforcement_percent,
            allowlist: AllowList::load(&allowlist_path()),
            bans: BanStore::load(&ban_path()),
            banned_ips: HashSet::new(),
            mutes: MuteStore::load(&mute_path()),
            announce_mode: HashSet::new(),
            shout_mode: HashSet::new(),
            full_quality_bypass: HashSet::new(),
            avatar_last_sent: HashMap::new(),
            crash_reporting_enabled: config.crash_reporting_enabled,
            crash_seen: HashMap::new(),
            config,
            peers: HashMap::new(),
            next_peer_id: 0,
            stats,
            telemetry,
            visitors,
            info_last_seen: HashMap::new(),
            info_tokens: 200.0,
            info_last_refill: Instant::now(),
            _control: control,
            p2p: basis_p2p::Broker::default(),
            control_players,
            health_players,
            health_worlds,
            library_items,
            library_wire,
            bundle_compression,
            bundle_queue: BundleQueue::default(),
            bundle_last_flush: Instant::now(),
            world_commands,
            pending_world_unload: None,
            pending_auth: Vec::new(),
            net_ids: HashMap::new(),
            scene_cache: HashMap::new(),
            ownership: HashMap::new(),
            resources: HashMap::new(),
            preload_sessions: HashMap::new(),
            next_net_id: 1,
            network_id_counter: -1,
        };
        if !server.config.initial_world_url.is_empty() {
            let net_id = "world-initial".to_string();
            let resource = WorldResource {
                net_id: net_id.clone(),
                url: server.config.initial_world_url.clone(),
                password: server.config.initial_world_password.clone(),
                persistent: false,
                strategy: 0,
            };
            let payload = build_load_resource(&resource);
            server.resources.insert(net_id.clone(), payload);
            if let Ok(mut worlds) = server.health_worlds.lock() {
                worlds.push(basis_health::WorldSnapshot {
                    net_id,
                    url: resource.url,
                    persistent: false,
                    admin_locked: false,
                    strategy: 0,
                });
            }
        }
        Ok(server)
    }

    fn flush_pending_auth(&mut self) {
        let now = Instant::now();
        let due: Vec<SocketAddr> = self
            .pending_auth
            .iter()
            .filter(|(at, _)| *at <= now)
            .map(|(_, addr)| *addr)
            .collect();
        self.pending_auth.retain(|(at, _)| *at > now);
        for addr in due {
            if let Err(e) = self.start_auth(addr) {
                error!("failed to start auth for {addr}: {e}");
            }
        }
    }

    fn open_inbound(&mut self, addr: SocketAddr, datagram: &mut Vec<u8>) -> bool {
        let Some(peer) = self.peers.get_mut(&addr) else {
            return true;
        };
        match peer.inbound_cipher.as_mut() {
            Some(cipher) => cipher.open(datagram),
            None => true,
        }
    }

    fn reap_stale_peers(&mut self) {
        let now = Instant::now();
        let stale: Vec<(SocketAddr, u16)> = self
            .peers
            .values()
            .filter(|peer| {
                peer.authenticated && now.duration_since(peer.last_seen) >= Duration::from_secs(5)
            })
            .map(|peer| (peer.endpoint, peer.id))
            .collect();
        for (addr, id) in stale {
            if let Some(peer) = self.peers.remove(&addr) {
                self.crash_seen.remove(&peer.did);
                self.clear_peer_modes(id);
                self.visitors.fetch_sub(1, Ordering::Relaxed);
                info!("Peer removed: {id}");
                let actions = self.p2p.remove_peer(id);
                self.relay_p2p(actions);
                self.remove_control_player(id);
                self.broadcast_departure(id);
                self.reset_network_id_if_empty();
                info!("Player {id} removed and cleaned up.");
            }
        }
    }

    fn reap_auth_timeouts(&mut self) {
        let timeout = Duration::from_millis(auth_timeout_ms(
            self.config.auth_validation_timeout_ms,
            self.peers.len(),
        ));
        let now = Instant::now();
        let expired: Vec<(SocketAddr, u16, i64, u8, String)> = self
            .peers
            .values()
            .filter(|p| !p.authenticated && now.duration_since(p.connected_at) >= timeout)
            .map(|p| {
                (
                    p.endpoint,
                    p.id,
                    p.connect_time,
                    p.connection_num,
                    p.did.clone(),
                )
            })
            .collect();
        for (addr, id, connect_time, conn, did) in expired {
            info!("Authentication timeout for {did}.");
            info!(
                "Peer {id} was not in AuthenticatedPeers (likely rejected before auth completed)."
            );
            if self.peers.remove(&addr).is_some() {
                self.visitors.fetch_sub(1, Ordering::Relaxed);
                self.remove_control_player(id);
                self.reset_network_id_if_empty();
            }
            error!("Rejected after accept with reason: Authentication timeout");
            let _ = self.send_disconnect(addr, conn, connect_time, "Authentication timeout");
        }
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    pub fn run(&mut self) -> io::Result<()> {
        let mut buf = vec![0u8; RX_BUFFER_BYTES];
        loop {
            let iteration = Instant::now();
            if self
                ._control
                .as_ref()
                .is_some_and(basis_control::ControlServer::shutdown_requested)
            {
                return Ok(());
            }
            self.sweep_reliable();
            self.flush_bundle_queues();
            self.flush_pending_auth();
            self.reap_auth_timeouts();
            self.reap_stale_peers();
            self.flush_world_commands();
            self.flush_pending_world_unload();
            self.reap_preload_sessions();
            let before_receive = Instant::now();
            let received = self.socket.recv_from(&mut buf);
            let after_receive = Instant::now();
            match received {
                Ok((len, addr)) => {
                    self.stats.rx_packets.fetch_add(1, Ordering::Relaxed);
                    self.stats.rx_bytes.fetch_add(len as u64, Ordering::Relaxed);
                    let mut datagram = buf[..len].to_vec();
                    if self.open_inbound(addr, &mut datagram) {
                        if let Err(e) = self.handle_datagram(&datagram, addr) {
                            debug!("packet from {addr} rejected: {e}");
                        }
                    }
                }
                Err(e)
                    if e.kind() == io::ErrorKind::WouldBlock
                        || e.kind() == io::ErrorKind::TimedOut
                        || e.kind() == io::ErrorKind::ConnectionReset
                        || e.kind() == io::ErrorKind::ConnectionRefused
                        || e.raw_os_error() == Some(10054) =>
                {
                    // A UDP peer that closed can surface as ICMP port-unreachable. It must not
                    // take the server down; the peer timeout will reap the state.
                }
                Err(e) => return Err(e),
            }
            let finished = Instant::now();
            self.telemetry.record_iteration(
                (before_receive - iteration) + (finished - after_receive),
                after_receive - before_receive,
            );
            if self.telemetry.due() {
                self.report_telemetry();
            }
        }
    }

    fn report_telemetry(&mut self) {
        let online = self
            .peers
            .values()
            .filter(|peer| peer.authenticated)
            .count();
        let reliable_queue = self.peers.values().map(|peer| peer.reliable.len()).sum();
        let mut bundle_messages = 0;
        let mut bundle_bytes = 0;
        for target in self.bundle_queue.targets() {
            bundle_messages += self.bundle_queue.len(target);
            bundle_bytes += self.bundle_queue.bytes(target);
        }
        self.telemetry.report(basis_telemetry::Counters {
            online,
            peer_limit: self.config.peer_limit,
            pending_auth: self.pending_auth.len(),
            reliable_queue,
            bundle_messages,
            bundle_bytes,
            rx_packets: self.stats.rx_packets.load(Ordering::Relaxed),
            tx_packets: self.stats.tx_packets.load(Ordering::Relaxed),
            rx_bytes: self.stats.rx_bytes.load(Ordering::Relaxed),
            tx_bytes: self.stats.tx_bytes.load(Ordering::Relaxed),
        });
    }

    fn now_ticks() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as i64 / 100)
            .unwrap_or(0)
    }

    fn handle_datagram(&mut self, data: &[u8], addr: SocketAddr) -> Result<(), String> {
        if data.is_empty() {
            return Ok(());
        }
        if data.is_empty() {
            return Ok(());
        }
        let unconnected = data.len() >= 2 && (data[0] & 0x1F) == 8;
        let info_payload = if unconnected { &data[1..] } else { data };
        if info_payload.len() >= 8
            && u32::from_le_bytes([
                info_payload[0],
                info_payload[1],
                info_payload[2],
                info_payload[3],
            ]) == SERVER_INFO_QUERY_MAGIC
        {
            return self.handle_server_info(info_payload, unconnected, addr);
        }
        let property = data[0] & 0x1F;
        let conn = (data[0] >> 5) & 0x03;

        if property == PROP_CONNECT_REQUEST {
            return self.handle_connect_request(data, addr, conn);
        }

        if !self.peers.contains_key(&addr) {
            // A peer that vanished from our table can still be probed by LiteNetLib.
            if property == PROP_PING {
                self.send_peer_not_found(addr)?;
            }
            return Ok(());
        }

        if let Some(peer) = self.peers.get_mut(&addr) {
            peer.last_seen = Instant::now();
        }
        let peer_conn = self.peers[&addr].connection_num;
        if conn != peer_conn {
            debug!("connection number mismatch from {addr}: {conn} != {peer_conn}");
            return Ok(());
        }

        match property {
            PROP_UNRELIABLE => {
                if data.len() < 2 {
                    return Ok(());
                }
                let channel = data[1];
                self.dispatch_app(addr, channel, &data[2..], false)?;
            }
            PROP_CHANNELED => self.handle_channeled(addr, data)?,
            PROP_ACK => self.handle_ack(addr, data)?,
            PROP_PING => self.handle_ping(addr, data)?,
            PROP_PONG => {}
            PROP_DISCONNECT => {
                if let Some(peer) = self.peers.remove(&addr) {
                    self.crash_seen.remove(&peer.did);
                    self.clear_peer_modes(peer.id);
                    self.visitors.fetch_sub(1, Ordering::Relaxed);
                    if peer.authenticated {
                        info!("Peer removed: {}", peer.id);
                        let actions = self.p2p.remove_peer(peer.id);
                        self.relay_p2p(actions);
                        self.remove_control_player(peer.id);
                        self.broadcast_departure(peer.id);
                        self.reset_network_id_if_empty();
                        info!("Player {} removed and cleaned up.", peer.id);
                    } else {
                        info!(
                            "Peer {} was not in AuthenticatedPeers (likely rejected before auth completed).",
                            peer.id
                        );
                    }
                }
            }
            PROP_COMPACT_MERGED => self.handle_compact_merged(addr, data)?,
            PROP_MERGED => self.handle_merged(addr, data)?,
            PROP_MTU_CHECK | PROP_MTU_OK => {
                // The C# peer starts at 1024 and probes upward. Staying at 1024 keeps our
                // fragment sizing simple and is accepted by the client.
            }
            PROP_SHUTDOWN_OK | PROP_PEER_NOT_FOUND => {}
            other => debug!("unhandled property {other} from {addr}"),
        }
        Ok(())
    }

    fn handle_server_info(
        &mut self,
        data: &[u8],
        wrapped: bool,
        addr: SocketAddr,
    ) -> Result<(), String> {
        if data.len() < SERVER_INFO_MIN_REQUEST_BYTES {
            return Ok(());
        }
        let now = Instant::now();
        if let Some(previous) = self.info_last_seen.get(&addr.ip()) {
            if now.duration_since(*previous) < Duration::from_millis(500) {
                return Ok(());
            }
        }
        if self.info_last_seen.len() > 4096 {
            self.info_last_seen.clear();
        }
        self.info_last_seen.insert(addr.ip(), now);
        self.info_tokens = refill_info_tokens(self.info_tokens, self.info_last_refill, now);
        self.info_last_refill = now;
        if self.info_tokens < 1.0 {
            return Ok(());
        }
        self.info_tokens -= 1.0;

        let nonce = u16::from_le_bytes([data[6], data[7]]);
        let online = self.peers.values().filter(|p| p.authenticated).count();
        let mut w = Writer::with_capacity(385);
        if wrapped {
            w.put_u8(8);
        }
        w.put_u32(SERVER_INFO_RESPONSE_MAGIC);
        w.put_u16(SERVER_INFO_PROTOCOL_VERSION);
        w.put_u16(nonce);
        w.put_u16(online.min(u16::MAX as usize) as u16);
        w.put_u16(self.config.peer_limit.min(u16::MAX as usize) as u16);
        w.put_string(&limited_chars(
            &self.config.server_name,
            SERVER_INFO_NAME_MAX,
        ));
        w.put_string(&limited_chars(
            &self.config.server_motd,
            SERVER_INFO_MOTD_MAX,
        ));
        self.send_raw(w.as_slice(), addr)
    }

    fn handle_connect_request(
        &mut self,
        data: &[u8],
        addr: SocketAddr,
        conn: u8,
    ) -> Result<(), String> {
        if data.len() < 18 {
            return Err("short connect request".into());
        }
        let mut r = Reader::new(data);
        let _property = r.get_u8().map_err(|e| e.to_string())?;
        let protocol = r.get_i32().map_err(|e| e.to_string())?;
        if protocol != PROTOCOL_ID {
            warn!("{addr} uses LiteNetLib protocol {protocol}, expected {PROTOCOL_ID}");
            return Ok(());
        }
        let connect_time = r.get_i64().map_err(|e| e.to_string())?;
        let remote_id = r.get_i32().map_err(|e| e.to_string())?;
        let addr_size = r.get_u8().map_err(|e| e.to_string())? as usize;
        let _target = r.get_bytes(addr_size).map_err(|e| e.to_string())?;
        let payload = r.get_bytes(r.remaining()).map_err(|e| e.to_string())?;

        if let Some(existing) = self.peers.get(&addr) {
            if existing.connect_time == connect_time {
                self.send_connect_accept(addr, connect_time, conn, existing.id)?;
                return Ok(());
            }
        }

        if self.peers.len() >= self.config.peer_limit {
            let reason = format!(
                "This server is full ({}/{}). Please try again later.",
                self.peers.len(),
                self.config.peer_limit
            );
            error!("Rejected (kind 2): {reason}");
            self.send_structured_reject(addr, conn, connect_time, 2, (0, 0), &reason)?;
            return Ok(());
        }

        let connection = match parse_connection_data(payload) {
            Ok(v) => v,
            Err(e) => {
                let dump = payload
                    .iter()
                    .take(96)
                    .map(|b| format!("{b:02x}"))
                    .collect::<Vec<_>>()
                    .join(" ");
                debug!("{addr} sent malformed connection data: {e}; payload={dump}");
                error!("Rejected for reason: Invalid client data.");
                self.send_disconnect(addr, conn, connect_time, "Invalid client data.")?;
                return Ok(());
            }
        };
        if connection.version != PROTOCOL_VERSION && connection.version != LEGACY_PROTOCOL_VERSION {
            let guidance = if connection.version < PROTOCOL_VERSION {
                "Update your Basis client to match the server."
            } else {
                "This server is running an older Basis build than your client."
            };
            let reason = format!(
                "This server needs client protocol v{PROTOCOL_VERSION}; your client is v{}. {guidance}",
                connection.version
            );
            error!("Rejected (kind 1): {reason}");
            self.send_structured_reject(
                addr,
                conn,
                connect_time,
                1,
                (PROTOCOL_VERSION, connection.version),
                &reason,
            )?;
            return Ok(());
        }
        if self.headless_disallowed
            && matches!(
                connection
                    .ready
                    .metadata
                    .platform
                    .to_ascii_lowercase()
                    .as_str(),
                "headless" | "windowsserver" | "linuxserver" | "osxserver"
            )
        {
            let reason = "Headless client disallowed by server.";
            error!("Rejected for reason: {reason}");
            self.send_disconnect(addr, conn, connect_time, reason)?;
            return Ok(());
        }
        if connection.company_name != self.config.company_name
            || connection.product_name != self.config.product_name
        {
            let reason = format!(
                "This server only accepts company \"{}\" and product \"{}\"; your client reports company \"{}\" and product \"{}\".",
                self.config.company_name,
                self.config.product_name,
                connection.company_name,
                connection.product_name
            );
            error!("Rejected for reason: {reason}");
            self.send_disconnect(addr, conn, connect_time, &reason)?;
            return Ok(());
        }
        if self.config.use_auth && connection.auth != self.config.password.as_bytes() {
            if connection.auth.is_empty() {
                error!("User had an empty password, user is rejected");
            } else {
                error!("Passwords do not match, user is rejected");
            }
            error!("Rejected for reason: Authentication failed, Auth rejected");
            self.send_disconnect(
                addr,
                conn,
                connect_time,
                "Authentication failed, Auth rejected",
            )?;
            return Ok(());
        }

        let duplicate_auths = self
            .peers
            .values()
            .filter(|peer| peer.did == connection.ready.metadata.uuid)
            .count();
        if duplicate_auths >= self.config.how_many_duplicate_auth_can_exist {
            error!("Rejected for reason: To Many Auths From this DID!");
            self.send_disconnect(addr, conn, connect_time, "To Many Auths From this DID!")?;
            return Ok(());
        }

        let id = self.alloc_peer_id();
        let mut peer = Peer::new(addr, id, connect_time, conn, remote_id);
        peer.metadata_raw = connection.ready.metadata_raw.clone();
        peer.ready_raw = connection.ready.ready_raw.clone();
        peer.avatar_change_raw = connection.ready.avatar_change_raw.clone();
        peer.latest_sync_raw = connection.ready.avatar_sync_raw.clone();
        peer.position = repack::decode_position(&connection.ready.avatar_payload);
        peer.did = connection.ready.metadata.uuid.clone();
        peer.display_name = connection.ready.metadata.display_name.clone();
        peer.protocol = connection.version;
        peer.client_public = connection.client_public;
        peer.payload_hash = connection.payload_hash;
        self.peers.insert(addr, peer);
        self.visitors.fetch_add(1, Ordering::Relaxed);

        self.send_connect_accept(addr, connect_time, conn, id)?;
        if self.config.use_auth_identity {
            self.pending_auth
                .push((Instant::now() + Duration::from_millis(500), addr));
        } else {
            self.complete_auth(addr)?;
        }
        Ok(())
    }

    fn alloc_peer_id(&mut self) -> u16 {
        let id = self.next_peer_id;
        self.next_peer_id = self.next_peer_id.wrapping_add(1);
        id
    }

    fn start_auth(&mut self, addr: SocketAddr) -> Result<(), String> {
        let (protocol, client_public, payload_hash, did) = {
            let peer = self.peers.get(&addr).ok_or("peer vanished")?;
            (
                peer.protocol,
                peer.client_public,
                peer.payload_hash,
                peer.did.clone(),
            )
        };
        let payload = if protocol >= 56 {
            let client_public = client_public.ok_or("missing client connection key")?;
            let (server_private, server_public) = basis_crypto::generate_keypair();
            let key =
                basis_crypto::derive_server_key(&server_private, &client_public, &server_public)
                    .ok_or("invalid client connection key")?;
            let nonce = basis_crypto::random_nonce().to_vec();
            let transcript = basis_crypto::build_login_transcript(
                &did,
                &self.config.server_uuid,
                &nonce,
                &client_public,
                &server_public,
                &payload_hash,
            );
            let payload = build_challenge_v2(&nonce, &server_public, &self.config.server_uuid);
            {
                let peer = self.peers.get_mut(&addr).ok_or("peer vanished")?;
                peer.inbound_cipher = Some(basis_crypto::PacketCipher::new(&key));
                peer.challenge = Some(nonce);
                peer.transcript = Some(transcript);
                peer.server_public = Some(server_public);
            }
            payload
        } else {
            use rand::RngCore;
            let mut nonce = [0u8; 256];
            rand::rngs::OsRng.fill_bytes(&mut nonce);
            {
                let peer = self.peers.get_mut(&addr).ok_or("peer vanished")?;
                peer.challenge = Some(nonce.to_vec());
            }
            build_challenge(&nonce)
        };
        if self.config.log_connection_handshake {
            let id = self.peers[&addr].id;
            info!("Processing connection from peer {id}.");
        }
        self.send_reliable(addr, AUTH_IDENTITY_CHANNEL, &payload)?;
        if self.config.log_connection_handshake {
            info!("Sending out Writer with size : {}", payload.len());
        }
        Ok(())
    }
    fn complete_auth(&mut self, addr: SocketAddr) -> Result<(), String> {
        if self.banned_ips.contains(&addr.ip()) {
            return Err("IP banned".into());
        }
        let peer = self.peers.get(&addr).ok_or("peer vanished")?;
        if peer.authenticated {
            return Ok(());
        }
        let peer_id = peer.id;
        let control_uuid = peer.did.clone();
        let control_name = peer.display_name.clone();
        let metadata_raw = peer.metadata_raw.clone();
        let platform = parse_client_metadata_bytes(&metadata_raw)
            .map(|metadata| metadata.platform)
            .unwrap_or_else(|_| "Unknown".to_string());
        if let Some(reason) = self.bans.reason(&control_uuid).map(str::to_string) {
            let (connection_num, connect_time) = self
                .peers
                .get(&addr)
                .map(|peer| (peer.connection_num, peer.connect_time))
                .unwrap_or((0, 0));
            let _ = self.send_disconnect(
                addr,
                connection_num,
                connect_time,
                &format!("Banned: {reason}"),
            );
            self.peers.remove(&addr);
            self.visitors.fetch_sub(1, Ordering::Relaxed);
            return Ok(());
        }
        if self.restriction_mode == 2 && !self.allowlist.is_allowed(&control_uuid) {
            let (connection_num, connect_time) = self
                .peers
                .get(&addr)
                .map(|peer| (peer.connection_num, peer.connect_time))
                .unwrap_or((0, 0));
            let _ = self.send_disconnect(addr, connection_num, connect_time, "Not on allowlist");
            self.peers.remove(&addr);
            self.visitors.fetch_sub(1, Ordering::Relaxed);
            return Ok(());
        }

        {
            let peer = self.peers.get_mut(&addr).ok_or("peer vanished")?;
            peer.authenticated = true;
            peer.challenge = None;
            peer.platform = platform.clone();
        }

        let effective = self.permissions.effective(&control_uuid);
        let (permissions_bitset, extra_permissions) =
            permission_bitset::encode(&effective.allowed_rules(), &effective.denied_rules());
        let metadata = build_server_metadata_with_permissions(
            &metadata_raw,
            &self.config.server_uuid,
            self.config.peer_limit as u16,
            &permissions_bitset,
            &extra_permissions,
        );
        if let Ok(mut players) = self.control_players.lock() {
            players.retain(|player| player.id != peer_id);
            players.push(basis_control::ControlPlayer {
                id: peer_id,
                uuid: control_uuid.clone(),
                display_name: control_name.clone(),
            });
        }
        if let Ok(mut players) = self.health_players.lock() {
            players.retain(|player| player.net_id != peer_id);
            players.push(basis_health::PlayerSnapshot {
                net_id: peer_id,
                uuid: control_uuid.clone(),
                display_name: control_name,
                platform,
                position: [0.0, 0.0, 0.0],
            });
        }
        self.send_reliable(addr, METADATA_CHANNEL, &metadata)?;
        self.send_reliable(addr, REGISTRY_CONTROL_CHANNEL, &build_registry_supply())?;
        self.send_reliable(
            addr,
            ADMIN_CHANNEL,
            &[43, u8::from(self.crash_reporting_enabled)],
        )?;
        self.send_reliable(addr, ADMIN_CHANNEL, &self.locks.payload())?;
        self.send_reliable(addr, ADMIN_CHANNEL, &[27, self.opus_packet_loss])?;
        self.send_reliable(addr, ADMIN_CHANNEL, &[31, self.opus_frame_duration])?;
        self.send_reliable(
            addr,
            ADMIN_CHANNEL,
            &[22, u8::from(self.headless_audio_enabled)],
        )?;
        self.send_reliable(
            addr,
            ADMIN_CHANNEL,
            &[24, u8::from(self.headless_disallowed)],
        )?;
        let mut audio_range = Writer::new();
        audio_range.put_u8(45);
        audio_range.put_f32(self.audio_microphone_meters);
        audio_range.put_f32(self.audio_hearing_meters);
        self.send_reliable(addr, ADMIN_CHANNEL, &audio_range.into_vec())?;
        let mut scale_range = Writer::new();
        scale_range.put_u8(55);
        scale_range.put_f32(self.avatar_scale_min);
        scale_range.put_f32(self.avatar_scale_max);
        self.send_reliable(addr, ADMIN_CHANNEL, &scale_range.into_vec())?;
        let mut resource_limits = Writer::new();
        resource_limits.put_u8(57);
        resource_limits.put_i32(self.max_spheres);
        resource_limits.put_i32(self.sphere_leave_timeout);
        resource_limits.put_i32(self.sphere_deletion_timer);
        self.send_reliable(addr, ADMIN_CHANNEL, &resource_limits.into_vec())?;
        let (fields, jump, walk, run, gravity, movement) = self.locomotion_policy;
        let mut locomotion = Writer::new();
        locomotion.put_u8(91);
        locomotion.put_u8(fields);
        locomotion.put_f32(jump);
        locomotion.put_f32(walk);
        locomotion.put_f32(run);
        locomotion.put_f32(gravity);
        locomotion.put_u8(movement);
        self.send_reliable(addr, ADMIN_CHANNEL, &locomotion.into_vec())?;
        self.send_reliable(addr, ADMIN_CHANNEL, &self.reduction_payload())?;
        let mut image_bandwidth = Writer::new();
        image_bandwidth.put_u8(80);
        image_bandwidth.put_i32(self.image_egress_mbps);
        image_bandwidth.put_i32(self.image_download_mbps);
        image_bandwidth.put_i32(self.image_enforcement_percent);
        self.send_reliable(addr, ADMIN_CHANNEL, &image_bandwidth.into_vec())?;
        let mut opus_global = Writer::new();
        opus_global.put_u8(65);
        opus_global.put_i32(self.opus_global_bitrate);
        self.send_reliable(addr, ADMIN_CHANNEL, &opus_global.into_vec())?;
        if let Some(bitrate) = self.opus_user_bitrates.get(&peer_id).copied() {
            let mut override_writer = Writer::new();
            override_writer.put_u8(29);
            override_writer.put_i32(bitrate);
            self.send_reliable(addr, ADMIN_CHANNEL, &override_writer.into_vec())?;
        }
        let (voice_muted, text_muted) = self.mutes.state(&control_uuid);
        if voice_muted || text_muted {
            self.send_reliable(
                addr,
                ADMIN_CHANNEL,
                &[85, u8::from(voice_muted), u8::from(text_muted)],
            )?;
        }
        for id in self.announce_mode.clone() {
            let payload = [
                16,
                (id & 0xFF) as u8,
                (id >> 8) as u8,
                (id & 0xFF) as u8,
                (id >> 8) as u8,
            ];
            self.send_reliable(addr, ADMIN_CHANNEL, &payload)?;
        }
        for id in self.shout_mode.clone() {
            let payload = [
                88,
                (id & 0xFF) as u8,
                (id >> 8) as u8,
                (id & 0xFF) as u8,
                (id >> 8) as u8,
            ];
            self.send_reliable(addr, ADMIN_CHANNEL, &payload)?;
        }
        if !self.library_wire.is_empty() {
            self.send_reliable(addr, SERVER_LIBRARY_CHANNEL, &self.library_wire.clone())?;
        }

        // C# JoinBroadcast announces arrivals on the batch channel, including to peers that
        // were already connected. A single-record batch is the common case.
        let new_ready = self.peers[&addr].ready_for_spawn();
        let targets: Vec<SocketAddr> = self
            .peers
            .values()
            .filter(|peer| peer.authenticated && peer.endpoint != addr)
            .map(|peer| peer.endpoint)
            .collect();
        debug!("announcing peer {peer_id} ready_bytes={}", new_ready.len());
        let batch = build_ready_batch(&[(peer_id, new_ready.clone())]);
        debug!(
            "announcing peer {peer_id} to {} existing peer(s)",
            targets.len()
        );
        for target in targets {
            self.send_reliable(target, CREATE_REMOTE_PLAYERS_FOR_NEW_PEER_CHANNEL, &batch)?;
        }
        // Replay loaded resources so late joiners see the same props/world.
        let resources: Vec<Vec<u8>> = self.resources.values().cloned().collect();
        for resource in resources {
            self.send_reliable(addr, LOAD_RESOURCE_CHANNEL, &resource)?;
        }

        // Replay ownership state so props are usable immediately.
        let ownership: Vec<(String, u16)> = self
            .ownership
            .iter()
            .map(|(object, owner)| (object.clone(), *owner))
            .collect();
        for (object, owner) in ownership {
            self.send_reliable(
                addr,
                CHANGE_CURRENT_OWNER_CHANNEL,
                &build_ownership(owner, &object),
            )?;
        }

        // Replay the current scene state to the new peer.
        let cached_scenes: Vec<Vec<u8>> = self.scene_cache.values().cloned().collect();
        for message in cached_scenes {
            self.send_reliable(addr, SCENE_CHANNEL, &message)?;
        }

        // Tell the new peer about everyone already here.
        let existing: Vec<(u16, Vec<u8>)> = self
            .peers
            .values()
            .filter(|p| p.endpoint != addr && p.authenticated)
            .map(|p| (p.id, p.ready_for_spawn()))
            .collect();
        if !existing.is_empty() {
            self.send_reliable(
                addr,
                CREATE_REMOTE_PLAYERS_FOR_NEW_PEER_CHANNEL,
                &build_ready_batch(&existing),
            )?;
        }

        info!("Peer connected: {peer_id}");
        Ok(())
    }

    fn handle_channeled(&mut self, addr: SocketAddr, data: &[u8]) -> Result<(), String> {
        if data.len() < CHANNELED_HEADER {
            return Ok(());
        }
        // SAFETY: the 4-byte Channeled header was checked above.
        let seq = unsafe { fast::read_u16_le_unchecked(data, 1) };
        let channel_id = data[3];
        if channel_id > 63 {
            let dump = data
                .iter()
                .take(24)
                .map(|b| format!("{b:02x}"))
                .collect::<Vec<_>>()
                .join(" ");
            debug!("high channel {channel_id} from {addr} seq={seq}: {dump}");
        }
        if seq >= MAX_SEQUENCE {
            return Ok(());
        }
        self.send_ack(addr, seq, channel_id)?;

        let fragmented = data[0] & 0x80 != 0;
        if fragmented {
            if data.len() < CHANNELED_HEADER + FRAGMENT_HEADER {
                return Ok(());
            }
            // SAFETY: the fragment header is 6 bytes and was checked above.
            let frag_id = unsafe { fast::read_u16_le_unchecked(data, 4) };
            let part = unsafe { fast::read_u16_le_unchecked(data, 6) };
            let total = unsafe { fast::read_u16_le_unchecked(data, 8) };
            if total == 0 || part >= total {
                return Ok(());
            }
            let payload = data[CHANNELED_HEADER + FRAGMENT_HEADER..].to_vec();
            let entry = self
                .peers
                .get_mut(&addr)
                .ok_or("peer vanished")?
                .fragments
                .entry(frag_id)
                .or_insert_with(|| Fragmented {
                    total,
                    parts: vec![None; total as usize],
                });
            if entry.total != total || entry.parts.len() != total as usize {
                *entry = Fragmented {
                    total,
                    parts: vec![None; total as usize],
                };
            }
            entry.parts[part as usize] = Some(payload);
            if entry.parts.iter().all(|p| p.is_some()) {
                let parts = std::mem::take(&mut entry.parts);
                let mut joined = Vec::new();
                for p in parts {
                    joined.extend_from_slice(&p.unwrap_or_default());
                }
                self.peers
                    .get_mut(&addr)
                    .ok_or("peer vanished")?
                    .fragments
                    .remove(&frag_id);
                self.deliver_reliable(addr, channel_id, 0, joined)?;
            }
        } else {
            let payload = data[CHANNELED_HEADER..].to_vec();
            self.deliver_reliable(addr, channel_id, seq, payload)?;
        }
        Ok(())
    }

    fn deliver_reliable(
        &mut self,
        addr: SocketAddr,
        channel_id: u8,
        seq: u16,
        payload: Vec<u8>,
    ) -> Result<(), String> {
        let channel = channel_id / 4;
        let delivery = channel_id & 0x03;
        let mut expected = {
            let peer = self.peers.get(&addr).ok_or("peer vanished")?;
            peer.in_seq.get(&channel_id).copied().unwrap_or(0)
        };
        // ReliableOrdered starts at sequence 0. Sequenced starts at 1 (LiteNetLib increments
        // before sending) and does not need a gap check: a late voice frame is worse than a
        // dropped one, and the client's jitter buffer handles reordering.
        if delivery == 2 && seq != expected && seq != 0 {
            // Dynamic/plugin channels can begin at 1 rather than 0. Treat that as the first
            // packet on the channel; normal core channels still begin at 0.
            if expected == 0 && seq == 1 {
                expected = seq;
            } else {
                debug!(
                    "reliable gap/duplicate on channel {channel_id} from {addr}: seq={seq} expected={expected}"
                );
                return Ok(());
            }
        }
        let next = if delivery == 2 {
            if seq == 0 {
                expected
            } else {
                expected.wrapping_add(1) % MAX_SEQUENCE
            }
        } else {
            seq
        };
        let peer = self.peers.get_mut(&addr).ok_or("peer vanished")?;
        peer.in_seq.insert(channel_id, next);
        self.dispatch_app(addr, channel, &payload, delivery == 2)
    }

    fn dispatch_app(
        &mut self,
        addr: SocketAddr,
        channel: u8,
        payload: &[u8],
        _reliable: bool,
    ) -> Result<(), String> {
        if self.locks.voice_chat
            && matches!(
                channel,
                VOICE_CHANNEL
                    | AUDIO_RECIPIENTS_CHANNEL
                    | AUDIO_RECIPIENTS_LARGE_CHANNEL
                    | AUDIO_RECIPIENTS_INVERTED_CHANNEL
                    | AUDIO_RECIPIENTS_INVERTED_LARGE_CHANNEL
                    | AUDIO_RECIPIENTS_BITFIELD_CHANNEL
            )
        {
            let did = self
                .peers
                .get(&addr)
                .map(|peer| peer.did.clone())
                .unwrap_or_default();
            if self.mutes.is_voice_muted(&did) {
                return Ok(());
            }
            if !self
                .permissions
                .effective(&did)
                .has(basis_permissions::NODE_VOICE_LOCK_BYPASS)
            {
                return Ok(());
            }
        }
        match channel {
            AUTH_IDENTITY_CHANNEL => self.handle_auth_response(addr, payload),
            PLAYER_AVATAR_HIGH_CHANNEL | PLAYER_AVATAR_HIGH_ADDITIONAL_CHANNEL => {
                let has_additional = channel == PLAYER_AVATAR_HIGH_ADDITIONAL_CHANNEL;
                match parse_avatar_channel_payload(payload, has_additional) {
                    Ok((seq, avatar, additional)) => {
                        self.relay_avatar(addr, has_additional, seq, &avatar, &additional)
                    }
                    Err(e) => {
                        debug!("bad avatar from {addr}: {e}");
                        Ok(())
                    }
                }
            }
            DELTA_AVATAR_CHANNEL => self.relay_delta(addr, payload),
            AUDIO_RECIPIENTS_CHANNEL => self.handle_voice_recipients(addr, payload, false, false),
            AUDIO_RECIPIENTS_LARGE_CHANNEL => {
                self.handle_voice_recipients(addr, payload, true, false)
            }
            AUDIO_RECIPIENTS_INVERTED_CHANNEL => {
                self.handle_voice_recipients(addr, payload, false, true)
            }
            AUDIO_RECIPIENTS_INVERTED_LARGE_CHANNEL => {
                self.handle_voice_recipients(addr, payload, true, true)
            }
            AUDIO_RECIPIENTS_BITFIELD_CHANNEL => self.handle_voice_bitfield(addr, payload),
            ANNOUNCE_VOICE_CHANNEL => self.handle_announce_voice(addr, payload),
            VOICE_CHANNEL => match parse_voice(payload) {
                Ok((seq, silence, frame)) => self.relay_voice(addr, seq, silence, &frame),
                Err(e) => {
                    debug!("bad voice from {addr}: {e}");
                    Ok(())
                }
            },
            ADMIN_CHANNEL => self.handle_admin_request(addr, payload),
            EVENTS_CHANNEL => self.handle_event(addr, payload),
            LOAD_RESOURCE_CHANNEL => self.handle_load_resource(addr, payload),
            UNLOAD_RESOURCE_CHANNEL => self.handle_unload_resource(addr, payload),
            PRELOAD_READY_CHANNEL => self.handle_preload_ready(addr, payload),
            GET_CURRENT_OWNER_CHANNEL => self.handle_get_owner(addr, payload),
            CHANGE_CURRENT_OWNER_CHANNEL => self.handle_change_owner(addr, payload),
            REMOVE_CURRENT_OWNER_CHANNEL => self.handle_remove_owner(addr, payload),
            SCENE_CHANNEL => match parse_scene_data(payload) {
                Ok(scene) => self.relay_scene(addr, &scene),
                Err(e) => {
                    debug!("bad scene data from {addr}: {e}");
                    Ok(())
                }
            },
            NET_ID_ASSIGN_CHANNEL => self.handle_net_id(addr, payload),
            AVATAR_CHANNEL => match parse_avatar_data(payload) {
                Ok(avatar) => self.relay_avatar_data(addr, &avatar),
                Err(e) => {
                    debug!("bad avatar data from {addr}: {e}");
                    Ok(())
                }
            },
            CHAT_CHANNEL => {
                let allowed = self
                    .peers
                    .get_mut(&addr)
                    .map(|peer| peer.chat_rate.try_consume())
                    .unwrap_or(false);
                if !allowed {
                    debug!("chat rate limit from {addr}");
                    return Ok(());
                }
                match parse_chat(payload) {
                    Ok((text, sound)) => self.relay_chat(addr, &text, sound),
                    Err(e) => {
                        debug!("bad chat from {addr}: {e}");
                        Ok(())
                    }
                }
            }
            REGISTRY_CONTROL_CHANNEL => {
                if let Some(&sub) = payload.first() {
                    debug!("registry subtype {sub} from {addr}");
                }
                Ok(())
            }
            AVATAR_CHANGE_CHANNEL => {
                self.relay_avatar_change(addr, payload);
                Ok(())
            }
            basis_p2p::P2P_CHANNEL => {
                let Some(peer) = self.peers.get(&addr) else {
                    return Ok(());
                };
                if !peer.authenticated {
                    return Ok(());
                }
                let (peer_id, peer_did) = (peer.id, peer.did.clone());
                if self.locks.direct_connect
                    && !self
                        .permissions
                        .effective(&peer_did)
                        .has(basis_permissions::NODE_ALL)
                {
                    debug!("[P2P] direct connect locked; dropping request from {peer_id}");
                    return Ok(());
                }
                let actions = self.p2p.handle(peer_id, payload);
                self.relay_p2p(actions);
                Ok(())
            }
            _ => {
                debug!(
                    "unhandled app channel {channel} from {addr} ({} bytes)",
                    payload.len()
                );
                Ok(())
            }
        }
    }

    fn relay_p2p(&mut self, actions: Vec<basis_p2p::Outbound>) {
        let outbound: Vec<(SocketAddr, Vec<u8>)> = actions
            .into_iter()
            .filter_map(|action| {
                let peer = self
                    .peers
                    .values()
                    .find(|peer| peer.id == action.to && peer.authenticated)?;
                Some((peer.endpoint, action.to_payload()))
            })
            .collect();
        for (addr, payload) in outbound {
            let _ = self.send_reliable(addr, basis_p2p::P2P_CHANNEL, &payload);
        }
    }

    fn reduction_payload(&self) -> Vec<u8> {
        let mut writer = Writer::new();
        writer.put_u8(63);
        writer.put_i32(self.reduction_interval);
        writer.put_i32(self.reduction_base);
        writer.put_f32(self.reduction_rate);
        writer.put_f32(self.reduction_slowest);
        writer.put_f32(self.config.high_quality_distance);
        writer.put_f32(self.config.medium_quality_distance);
        writer.put_f32(self.config.low_quality_distance);
        writer.put_bool(self.bundle_compression);
        writer.put_i32(self.bundle_min_messages);
        writer.put_i32(self.bundle_min_bytes);
        writer.put_bool(self.bsr_profiling);
        writer.put_bool(self.bundle_zstd);
        writer.put_bool(self.bundle_zstd_deltas);
        writer.put_i32(self.bundle_zstd_level);
        writer.put_i32(self.bundle_zstd_max_shed);
        writer.into_vec()
    }

    fn flush_bundle_queues(&mut self) {
        if !self.bundle_compression {
            return;
        }
        if self.bundle_last_flush.elapsed() < Duration::from_millis(12) {
            return;
        }
        self.bundle_last_flush = Instant::now();
        let mut bundles = 0u64;
        let mut bundled_messages = 0u64;
        let mut raw_bytes = 0u64;
        let mut wire_bytes = 0u64;
        let mut direct_sends = 0u64;
        for target in self.bundle_queue.targets() {
            let count = self.bundle_queue.len(target);
            let bytes = self.bundle_queue.bytes(target);
            if count < self.bundle_min_messages as usize && bytes < self.bundle_min_bytes as usize {
                direct_sends = direct_sends.saturating_add(count as u64);
                for (channel, payload) in self.bundle_queue.take_entries(target) {
                    if self.send_unreliable(target, channel, &payload).is_err() {
                        self.telemetry.record_send_failure();
                    }
                }
            } else {
                bundled_messages = bundled_messages.saturating_add(count as u64);
                raw_bytes = raw_bytes.saturating_add(bytes as u64);
                for bundle in self.bundle_queue.take_chunks(target, 60_000) {
                    bundles = bundles.saturating_add(1);
                    wire_bytes = wire_bytes.saturating_add(bundle.len() as u64);
                    if self
                        .send_unreliable(target, COMPRESSED_AVATAR_BUNDLE_CHANNEL, &bundle)
                        .is_err()
                    {
                        self.telemetry.record_send_failure();
                    }
                }
            }
        }
        if bundles + direct_sends > 0 {
            self.telemetry.record_bundles(
                bundles,
                bundled_messages,
                raw_bytes,
                wire_bytes,
                direct_sends,
            );
        }
    }

    fn relay_avatar_change(&mut self, from: SocketAddr, payload: &[u8]) {
        if payload.len() < 2 || payload[0] != AVATAR_CHANGE_KIND_FULL {
            return;
        }
        let Some(peer) = self.peers.get(&from) else {
            return;
        };
        let sender = peer.id;
        let change = payload[1..].to_vec();
        if let Some(peer) = self.peers.get_mut(&from) {
            peer.avatar_change_raw = change.clone();
        }
        let mut msg = Vec::with_capacity(change.len() + 2);
        msg.extend_from_slice(&sender.to_le_bytes());
        msg.extend_from_slice(&change);
        let targets: Vec<SocketAddr> = self
            .peers
            .values()
            .filter(|p| p.endpoint != from && p.authenticated)
            .map(|p| p.endpoint)
            .collect();
        for target in targets {
            let _ = self.send_reliable(target, AVATAR_CHANGE_CHANNEL, &msg);
        }
    }

    fn handle_auth_response(&mut self, addr: SocketAddr, payload: &[u8]) -> Result<(), String> {
        let (sig, frag) = parse_auth_response(payload).map_err(|e| e.to_string())?;
        if sig.len() != 64 {
            let (id, conn, connect_time) = {
                let peer = &self.peers[&addr];
                (peer.id, peer.connection_num, peer.connect_time)
            };
            error!("Malformed auth response from peer {id}: bad signature data");
            self.send_disconnect(
                addr,
                conn,
                connect_time,
                "Malformed auth response: bad signature data",
            )?;
            self.drop_unauthenticated(addr);
            error!(
                "Rejected after accept with reason: Malformed auth response: bad signature data"
            );
            return Ok(());
        }
        let (did, challenge, transcript) = {
            let peer = self.peers.get(&addr).ok_or("peer vanished")?;
            (
                peer.did.clone(),
                peer.challenge.clone().ok_or("no challenge")?,
                peer.transcript.clone(),
            )
        };
        let signed_payload = transcript.as_deref().unwrap_or(challenge.as_slice());
        let key = match did_to_verifying_key(&did) {
            Ok(k) => k,
            Err(e) => {
                let (id, conn, connect_time) = {
                    let peer = &self.peers[&addr];
                    (peer.id, peer.connection_num, peer.connect_time)
                };
                error!("Malformed auth response from peer {id}: bad fragment data ({e})");
                self.send_disconnect(
                    addr,
                    conn,
                    connect_time,
                    "Malformed auth response: bad fragment data",
                )?;
                self.drop_unauthenticated(addr);
                error!(
                    "Rejected after accept with reason: Malformed auth response: bad fragment data"
                );
                return Ok(());
            }
        };
        let mut sig_bytes = [0u8; 64];
        sig_bytes.copy_from_slice(&sig);
        let signature = Signature::from_bytes(&sig_bytes);
        if key.verify(signed_payload, &signature).is_err() {
            let (id, conn, connect_time, did) = {
                let peer = &self.peers[&addr];
                (
                    peer.id,
                    peer.connection_num,
                    peer.connect_time,
                    peer.did.clone(),
                )
            };
            error!("Authentication failed for {did}.");
            debug!("peer {id} auth signature failed (fragment={frag:?})");
            self.send_disconnect(addr, conn, connect_time, "was unable to authenticate!")?;
            self.drop_unauthenticated(addr);
            error!("Rejected after accept with reason: was unable to authenticate!");
            return Ok(());
        }
        self.complete_auth(addr)
    }

    fn broadcast_departure(&mut self, id: u16) {
        self.scene_cache.retain(|(sender, _), _| *sender != id);
        let targets: Vec<SocketAddr> = self
            .peers
            .values()
            .filter(|peer| peer.authenticated)
            .map(|peer| peer.endpoint)
            .collect();
        debug!("broadcast departure {id} to {} peer(s)", targets.len());
        let payload = id.to_le_bytes();
        for target in targets {
            let _ = self.send_reliable(target, DISCONNECTION_CHANNEL, &payload);
        }
    }

    fn remove_preload_peer(&mut self, id: u16) {
        let completed: Vec<String> = self
            .preload_sessions
            .iter_mut()
            .filter_map(|(net_id, session)| {
                session.expected.remove(&id);
                session.ready.remove(&id);
                session.failed.remove(&id);
                if session.complete() {
                    Some(net_id.clone())
                } else {
                    None
                }
            })
            .collect();
        for net_id in completed {
            self.finish_preload(&net_id);
        }
    }

    fn remove_control_player(&mut self, id: u16) {
        self.remove_preload_peer(id);
        if let Ok(mut players) = self.control_players.lock() {
            players.retain(|player| player.id != id);
        }
        if let Ok(mut players) = self.health_players.lock() {
            players.retain(|player| player.net_id != id);
        }
    }

    fn reset_network_id_if_empty(&mut self) {
        if self.peers.is_empty() {
            info!("Resetting BasisNetworkIDDatabase...");
            self.network_id_counter = -1;
            self.net_ids.clear();
            self.scene_cache.clear();
            self.ownership.clear();
            self.resources.clear();
            if let Ok(mut worlds) = self.health_worlds.lock() {
                worlds.clear();
            }
            self.next_net_id = 1;
            info!(
                "Database reset complete. Counter set to {}.",
                self.network_id_counter
            );
        }
    }

    fn drop_unauthenticated(&mut self, addr: SocketAddr) {
        if let Some(peer) = self.peers.remove(&addr) {
            self.visitors.fetch_sub(1, Ordering::Relaxed);
            info!(
                "Peer {} was not in AuthenticatedPeers (likely rejected before auth completed).",
                peer.id
            );
            self.remove_control_player(peer.id);
            self.reset_network_id_if_empty();
        }
    }

    fn relay_avatar(
        &mut self,
        from: SocketAddr,
        has_additional: bool,
        seq: u8,
        payload: &[u8],
        additional: &[u8],
    ) -> Result<(), String> {
        let (sender, prior_position) = {
            let peer = self.peers.get(&from).ok_or("peer vanished")?;
            (peer.id, peer.position)
        };
        let position = repack::decode_position(payload).or(prior_position);

        // Keep the full ReadyMessage form for late joiners: quality byte + payload + the
        // additional section (a zero byte when there is none).
        let mut sync = Vec::with_capacity(payload.len() + additional.len() + 2);
        sync.push(3u8);
        sync.extend_from_slice(payload);
        if additional.is_empty() {
            sync.push(0);
        } else {
            sync.extend_from_slice(additional);
        }
        if let Some(peer) = self.peers.get_mut(&from) {
            peer.position = position;
            peer.latest_sync_raw = sync;
        }
        if let Some(position) = position {
            if let Ok(mut players) = self.health_players.lock() {
                if let Some(player) = players.iter_mut().find(|player| player.net_id == sender) {
                    player.position = position;
                }
            }
        }

        let reduction = self.config.avatar_reduction && payload.len() >= 159;
        let high_distance = self.config.high_quality_distance;
        let medium_distance = self.config.medium_quality_distance;
        let low_distance = self.config.low_quality_distance;
        let targets: Vec<(SocketAddr, u16, AvatarQuality, u8)> = self
            .peers
            .values()
            .filter(|p| p.endpoint != from && p.authenticated)
            .map(|p| {
                let distance_to = match (position, p.position) {
                    (Some(a), Some(b)) => Some(distance(a, b)),
                    _ => None,
                };
                let quality = if self.full_quality_bypass.contains(&p.id) {
                    AvatarQuality::High
                } else if reduction {
                    distance_to.map_or(AvatarQuality::High, |meters| {
                        quality_for_distance(meters, high_distance, medium_distance, low_distance)
                    })
                } else {
                    AvatarQuality::High
                };
                let interval = if self.full_quality_bypass.contains(&p.id) {
                    0
                } else {
                    let meters = distance_to.unwrap_or(0.0);
                    let raw = self.reduction_interval as f32
                        * (self.reduction_base as f32 + meters * meters * self.reduction_rate);
                    encode_avatar_interval(raw as i32, self.reduction_interval)
                };
                (p.endpoint, p.id, quality, interval)
            })
            .collect();

        let mut relays: HashMap<(AvatarQuality, u8), Vec<u8>> = HashMap::new();
        for (target, target_id, quality, interval) in targets {
            if interval > 0 {
                let required = decode_avatar_interval(interval, self.reduction_interval);
                if let Some((previous, previous_quality)) =
                    self.avatar_last_sent.get(&(sender, target_id))
                {
                    if *previous_quality == quality
                        && previous.elapsed() < Duration::from_millis(required as u64)
                    {
                        continue;
                    }
                }
                self.avatar_last_sent
                    .insert((sender, target_id), (Instant::now(), quality));
            }
            let relay = relays.entry((quality, interval)).or_insert_with(|| {
                if quality == AvatarQuality::High {
                    build_avatar_relay_with_interval(sender, seq, payload, additional, interval)
                } else {
                    match repack::repack_high(payload, quality) {
                        Some(repacked) => build_avatar_relay_with_interval(
                            sender, seq, &repacked, additional, interval,
                        ),
                        None => build_avatar_relay_with_interval(
                            sender, seq, payload, additional, interval,
                        ),
                    }
                }
            });
            let channel = avatar_channel(quality, has_additional);
            if self.bundle_compression {
                self.bundle_queue.push(target, channel, relay.clone());
            } else {
                self.send_unreliable(target, channel, relay)?;
            }
        }
        Ok(())
    }

    fn flush_world_commands(&mut self) {
        let commands: Vec<basis_health::WorldCommand> = self
            .world_commands
            .lock()
            .map(|mut list| std::mem::take(&mut *list))
            .unwrap_or_default();
        for command in commands {
            match command {
                basis_health::WorldCommand::Load {
                    net_id,
                    url,
                    password,
                    persistent,
                    strategy,
                } => {
                    let resource = WorldResource {
                        net_id: net_id.clone(),
                        url,
                        password,
                        persistent,
                        strategy,
                    };
                    let payload = build_load_resource(&resource);
                    if strategy != 3 {
                        self.resources.insert(net_id.clone(), payload.clone());
                        if let Ok(mut worlds) = self.health_worlds.lock() {
                            worlds.retain(|world| world.net_id != net_id);
                            worlds.push(basis_health::WorldSnapshot {
                                net_id: net_id.clone(),
                                url: resource.url,
                                persistent,
                                admin_locked: false,
                                strategy,
                            });
                        }
                    }
                    self.broadcast_reliable_all(LOAD_RESOURCE_CHANNEL, &payload);
                    if strategy == 2 {
                        self.start_preload(&net_id, 1);
                    }
                }
                basis_health::WorldCommand::Unload { net_id } => {
                    let payload = build_unload_resource(&net_id);
                    self.resources.remove(&net_id);
                    if let Ok(mut worlds) = self.health_worlds.lock() {
                        worlds.retain(|world| world.net_id != net_id);
                    }
                    self.broadcast_reliable_all(UNLOAD_RESOURCE_CHANNEL, &payload);
                }
                basis_health::WorldCommand::Announce { target, message } => {
                    if let Some(uuid) = target {
                        let endpoint = self
                            .peers
                            .values()
                            .find(|peer| peer.authenticated && peer.did == uuid)
                            .map(|peer| peer.endpoint);
                        if let Some(endpoint) = endpoint {
                            let payload = build_admin_message(ADMIN_MESSAGE_PLAYER, &message);
                            let _ = self.send_reliable(endpoint, ADMIN_CHANNEL, &payload);
                        }
                    } else {
                        let payload = build_admin_message(ADMIN_MESSAGE_ALL, &message);
                        self.broadcast_reliable_all(ADMIN_CHANNEL, &payload);
                    }
                }
                basis_health::WorldCommand::Switch {
                    net_id,
                    url,
                    password,
                    persistent,
                    strategy,
                    announce,
                    delay_seconds,
                } => {
                    let old_ids: Vec<String> = self
                        .resources
                        .iter()
                        .filter(|(id, payload)| {
                            *id != &net_id
                                && parse_resource_summary(payload)
                                    .is_ok_and(|summary| summary.mode == 1)
                        })
                        .map(|(id, _)| id.clone())
                        .collect();
                    let resource = WorldResource {
                        net_id: net_id.clone(),
                        url,
                        password,
                        persistent,
                        strategy,
                    };
                    let payload = build_load_resource(&resource);
                    self.resources.insert(net_id.clone(), payload.clone());
                    if let Ok(mut worlds) = self.health_worlds.lock() {
                        worlds.retain(|world| world.net_id != net_id);
                        worlds.push(basis_health::WorldSnapshot {
                            net_id: net_id.clone(),
                            url: resource.url,
                            persistent,
                            admin_locked: false,
                            strategy,
                        });
                    }
                    self.broadcast_reliable_all(LOAD_RESOURCE_CHANNEL, &payload);
                    self.broadcast_reliable_all(
                        ADMIN_CHANNEL,
                        &build_admin_message(ADMIN_MESSAGE_ALL, &announce),
                    );
                    if strategy == 2 {
                        self.start_preload(&net_id, 1);
                    } else if delay_seconds == 0 {
                        self.unload_worlds(&old_ids);
                    } else {
                        self.pending_world_unload = Some((
                            Instant::now() + Duration::from_secs(delay_seconds as u64),
                            old_ids,
                        ));
                    }
                }
                basis_health::WorldCommand::Clear => {
                    let ids: Vec<String> = self
                        .resources
                        .iter()
                        .filter(|(_, payload)| {
                            parse_resource_summary(payload).is_ok_and(|summary| summary.mode == 1)
                        })
                        .map(|(id, _)| id.clone())
                        .collect();
                    for id in ids {
                        self.resources.remove(&id);
                        self.broadcast_reliable_all(
                            UNLOAD_RESOURCE_CHANNEL,
                            &build_unload_resource(&id),
                        );
                    }
                    if let Ok(mut worlds) = self.health_worlds.lock() {
                        worlds.clear();
                    }
                }
            }
        }
    }

    fn broadcast_reliable_all(&mut self, channel: u8, payload: &[u8]) {
        let targets: Vec<SocketAddr> = self
            .peers
            .values()
            .filter(|peer| peer.authenticated)
            .map(|peer| peer.endpoint)
            .collect();
        for target in targets {
            let _ = self.send_reliable(target, channel, payload);
        }
    }

    fn flush_pending_world_unload(&mut self) {
        let Some((due, ids)) = self.pending_world_unload.as_ref() else {
            return;
        };
        if Instant::now() < *due {
            return;
        }
        let ids = ids.clone();
        self.pending_world_unload = None;
        self.unload_worlds(&ids);
    }

    fn unload_worlds(&mut self, ids: &[String]) {
        for id in ids {
            self.resources.remove(id);
            if let Ok(mut worlds) = self.health_worlds.lock() {
                worlds.retain(|world| world.net_id != *id);
            }
            self.broadcast_reliable_all(UNLOAD_RESOURCE_CHANNEL, &build_unload_resource(id));
        }
    }

    fn peer_has_permission(&self, from: SocketAddr, node: &str) -> bool {
        self.peers
            .get(&from)
            .map(|peer| self.permissions.effective(&peer.did).has(node))
            .unwrap_or(false)
    }

    fn handle_load_resource(&mut self, from: SocketAddr, payload: &[u8]) -> Result<(), String> {
        let Ok((mode, object)) = parse_resource_id(payload) else {
            warn!(
                "[LoadResource] header parse failed from {from}: {} bytes",
                payload.len()
            );
            return Ok(());
        };
        let allowed = match mode {
            0 => {
                (!self.locks.props
                    || self.peer_has_permission(
                        from,
                        basis_permissions::NODE_RESOURCE_LOCK_BYPASS_PROP,
                    ))
                    && self.peer_has_permission(from, "basis.resource.load.prop")
            }
            1 => {
                (!self.locks.worlds
                    || self.peer_has_permission(
                        from,
                        basis_permissions::NODE_RESOURCE_LOCK_BYPASS_WORLD,
                    ))
                    && self.peer_has_permission(from, "basis.resource.load.world")
            }
            _ => false,
        };
        if !allowed {
            if let Some(peer) = self.peers.get(&from) {
                match mode {
                    0 => error!("Invalid Request To Load Gameobject From {}", peer.did),
                    1 => error!("Invalid Request To Load Scene From {}", peer.did),
                    _ => {}
                }
            }
            return Ok(());
        }
        info!("Adding Object {object}");
        let mut synchronized = None;
        let mut active = true;
        if let Ok(summary) = parse_resource_summary(payload) {
            if summary.strategy == 3 {
                active = false;
            } else if summary.mode == 1 {
                if let Ok(mut worlds) = self.health_worlds.lock() {
                    worlds.retain(|world| world.net_id != summary.id);
                    worlds.push(basis_health::WorldSnapshot {
                        net_id: summary.id.clone(),
                        url: summary.url,
                        persistent: summary.persistent,
                        admin_locked: summary.admin_locked,
                        strategy: summary.strategy,
                    });
                }
            }
            if summary.strategy == 2 {
                synchronized = Some((summary.id, summary.mode));
            }
        } else {
            warn!("[LoadResource] summary parse failed from {from}: mode={mode} id={object}");
        }
        if active {
            self.resources.insert(object, payload.to_vec());
        }
        // C# `BasisNetworkResourceManagement.LoadResource` broadcasts to PeerSnapshot,
        // which includes the creator. The requesting client only spawns from the echoed
        // LoadResource message; excluding the sender leaves the creator with nothing.
        self.broadcast_reliable_all(LOAD_RESOURCE_CHANNEL, payload);
        if let Some((net_id, mode)) = synchronized {
            self.start_preload(&net_id, mode);
        }
        Ok(())
    }

    fn handle_unload_resource(&mut self, _from: SocketAddr, payload: &[u8]) -> Result<(), String> {
        let Ok(object) = parse_unload_resource_id(payload) else {
            return Ok(());
        };
        self.resources.remove(&object);
        self.preload_sessions.remove(&object);
        if let Ok(mut worlds) = self.health_worlds.lock() {
            worlds.retain(|world| world.net_id != object);
        }
        // C# broadcasts the unload to every peer, including the requesting client;
        // that echo is what makes the creator's own copy disappear.
        self.broadcast_reliable_all(UNLOAD_RESOURCE_CHANNEL, payload);
        Ok(())
    }

    fn start_preload(&mut self, net_id: &str, mode: u8) {
        let expected: HashSet<u16> = self
            .peers
            .values()
            .filter(|peer| peer.authenticated)
            .map(|peer| peer.id)
            .collect();
        if expected.is_empty() {
            self.broadcast_reliable_all(SPAWN_PRELOADED_CHANNEL, &build_spawn_preloaded(net_id));
            return;
        }
        self.preload_sessions.insert(
            net_id.to_string(),
            PreloadSession {
                mode,
                expected,
                ready: HashSet::new(),
                failed: HashSet::new(),
                started: Instant::now(),
            },
        );
    }

    fn handle_preload_ready(&mut self, from: SocketAddr, payload: &[u8]) -> Result<(), String> {
        let Ok((net_id, ready)) = parse_preload_ready(payload) else {
            return Ok(());
        };
        let peer_id = self.peers.get(&from).ok_or("peer vanished")?.id;
        let complete = if let Some(session) = self.preload_sessions.get_mut(&net_id) {
            if ready {
                session.ready.insert(peer_id);
            } else {
                session.failed.insert(peer_id);
            }
            session.complete()
        } else {
            false
        };
        if complete {
            self.finish_preload(&net_id);
        }
        Ok(())
    }

    fn finish_preload(&mut self, net_id: &str) {
        let Some(session) = self.preload_sessions.remove(net_id) else {
            return;
        };
        if session.mode == 1 {
            let old_ids: Vec<String> = self
                .resources
                .iter()
                .filter(|(id, payload)| {
                    *id != net_id
                        && parse_resource_summary(payload).is_ok_and(|summary| summary.mode == 1)
                })
                .map(|(id, _)| id.clone())
                .collect();
            self.unload_worlds(&old_ids);
        }
        self.broadcast_reliable_all(SPAWN_PRELOADED_CHANNEL, &build_spawn_preloaded(net_id));
    }

    fn reap_preload_sessions(&mut self) {
        let expired: Vec<String> = self
            .preload_sessions
            .iter()
            .filter(|(_, session)| session.started.elapsed() >= Duration::from_secs(300))
            .map(|(net_id, _)| net_id.clone())
            .collect();
        for net_id in expired {
            self.finish_preload(&net_id);
        }
    }

    fn broadcast_reliable_except(
        &mut self,
        from: SocketAddr,
        channel: u8,
        payload: &[u8],
    ) -> Result<(), String> {
        let targets: Vec<SocketAddr> = self
            .peers
            .values()
            .filter(|peer| peer.authenticated && peer.endpoint != from)
            .map(|peer| peer.endpoint)
            .collect();
        for target in targets {
            self.send_reliable(target, channel, payload)?;
        }
        Ok(())
    }

    fn handle_get_owner(&mut self, from: SocketAddr, payload: &[u8]) -> Result<(), String> {
        let Ok((_, object)) = parse_ownership(payload) else {
            return Ok(());
        };
        if !self.peer_has_permission(from, "basis.ownership.get") {
            return Ok(());
        }
        let sender = self.peers.get(&from).ok_or("peer vanished")?.id;
        let owner = match self.ownership.get(&object).copied() {
            Some(owner) => owner,
            None => {
                self.ownership.insert(object.clone(), sender);
                sender
            }
        };
        self.send_reliable(
            from,
            CHANGE_CURRENT_OWNER_CHANNEL,
            &build_ownership(owner, &object),
        )?;
        Ok(())
    }

    fn handle_change_owner(&mut self, from: SocketAddr, payload: &[u8]) -> Result<(), String> {
        let Ok((_, object)) = parse_ownership(payload) else {
            return Ok(());
        };
        if !self.peer_has_permission(from, "basis.ownership.transfer") {
            return Ok(());
        }
        let sender = self.peers.get(&from).ok_or("peer vanished")?.id;
        self.ownership.insert(object.clone(), sender);
        let message = build_ownership(sender, &object);
        let targets: Vec<SocketAddr> = self
            .peers
            .values()
            .filter(|peer| peer.authenticated)
            .map(|peer| peer.endpoint)
            .collect();
        for target in targets {
            self.send_reliable(target, CHANGE_CURRENT_OWNER_CHANNEL, &message)?;
        }
        Ok(())
    }

    fn handle_remove_owner(&mut self, from: SocketAddr, payload: &[u8]) -> Result<(), String> {
        let Ok((_, object)) = parse_ownership(payload) else {
            return Ok(());
        };
        if !self.peer_has_permission(from, "basis.ownership.remove") {
            return Ok(());
        }
        let sender = self.peers.get(&from).ok_or("peer vanished")?.id;
        if self.ownership.get(&object).copied() != Some(sender) {
            return Ok(());
        }
        self.ownership.remove(&object);
        let message = build_ownership(sender, &object);
        let targets: Vec<SocketAddr> = self
            .peers
            .values()
            .filter(|peer| peer.authenticated)
            .map(|peer| peer.endpoint)
            .collect();
        for target in targets {
            self.send_reliable(target, REMOVE_CURRENT_OWNER_CHANNEL, &message)?;
        }
        Ok(())
    }

    fn relay_scene(&mut self, from: SocketAddr, scene: &SceneData) -> Result<(), String> {
        let sender = self.peers.get(&from).ok_or("peer vanished")?.id;
        let relay = build_server_scene_data(sender, scene);
        self.scene_cache
            .insert((sender, scene.message_index), relay.clone());
        let targets: Vec<SocketAddr> = self
            .peers
            .values()
            .filter(|peer| peer.authenticated && peer.endpoint != from)
            .filter(|peer| scene.recipients.is_empty() || scene.recipients.contains(&peer.id))
            .map(|peer| peer.endpoint)
            .collect();
        for target in targets {
            self.send_reliable(target, SCENE_CHANNEL, &relay)?;
        }
        Ok(())
    }

    fn handle_event(&mut self, from: SocketAddr, payload: &[u8]) -> Result<(), String> {
        let Some(&event_type) = payload.first() else {
            return Ok(());
        };
        if event_type == 7 {
            self.handle_error_report(from, payload);
            return Ok(());
        }
        if event_type == 10 {
            return self.handle_jiggle_grab(from, payload);
        }
        if event_type == 0 {
            let sender = self.peers.get(&from).ok_or("peer vanished")?.id;
            let mut relay = Vec::with_capacity(3);
            relay.push(0);
            relay.extend_from_slice(&sender.to_le_bytes());
            let targets: Vec<SocketAddr> = self
                .peers
                .values()
                .filter(|peer| peer.authenticated && peer.endpoint != from)
                .map(|peer| peer.endpoint)
                .collect();
            for target in targets {
                self.send_sequenced(target, EVENTS_CHANNEL, &relay)?;
            }
            return Ok(());
        }
        if event_type == 8 || event_type == 9 {
            let has_state = event_type == 9;
            let needed = if has_state { 5 } else { 4 };
            if payload.len() < needed {
                return Ok(());
            }
            let target_id = u16::from_le_bytes([payload[1], payload[2]]);
            let (state, purpose) = if has_state {
                (Some(payload[3]), payload[4])
            } else {
                (None, payload[3])
            };
            let Some(target) = self
                .peers
                .values()
                .find(|peer| peer.id == target_id && peer.authenticated)
                .map(|peer| peer.endpoint)
            else {
                return Ok(());
            };
            let sender = self.peers.get(&from).ok_or("peer vanished")?.id;
            let mut relay = Vec::with_capacity(5);
            relay.push(event_type);
            relay.extend_from_slice(&sender.to_le_bytes());
            if let Some(state) = state {
                relay.push(state);
            }
            relay.push(purpose);
            self.send_reliable(target, EVENTS_CHANNEL, &relay)?;
            return Ok(());
        }
        if event_type == 2 {
            if payload.len() < 4 {
                return Ok(());
            }
            let target_id = u16::from_le_bytes([payload[1], payload[2]]);
            let is_blocked = payload[3] != 0;
            let Some(target) = self
                .peers
                .values()
                .find(|peer| peer.id == target_id && peer.authenticated)
                .map(|peer| peer.endpoint)
            else {
                return Ok(());
            };
            let sender = self.peers.get(&from).ok_or("peer vanished")?.id;
            let mut relay = Vec::with_capacity(5);
            relay.push(2);
            relay.extend_from_slice(&sender.to_le_bytes());
            relay.push(u8::from(is_blocked));
            self.send_reliable(target, EVENTS_CHANNEL, &relay)?;
            return Ok(());
        }
        if event_type == 1 {
            if payload.len() < 2 {
                return Ok(());
            }
            let sender = self.peers.get(&from).ok_or("peer vanished")?.id;
            let mut relay = Vec::with_capacity(4);
            relay.push(1);
            relay.extend_from_slice(&sender.to_le_bytes());
            relay.push(payload[1]);
            let targets: Vec<SocketAddr> = self
                .peers
                .values()
                .filter(|peer| peer.authenticated && peer.endpoint != from)
                .map(|peer| peer.endpoint)
                .collect();
            for target in targets {
                self.send_sequenced(target, EVENTS_CHANNEL, &relay)?;
            }
            return Ok(());
        }
        // Types 3..6 are [event][payload] inbound and [event][sender:u16][payload] outbound.
        if !(3..=6).contains(&event_type) {
            error!("Unknown EventsChannel event type: {event_type}");
            return Ok(());
        }
        if payload.len() < 2 {
            return Ok(());
        }
        let sender = self.peers.get(&from).ok_or("peer vanished")?.id;
        if event_type == 6 {
            let allowed = self
                .peers
                .get_mut(&from)
                .map(|peer| peer.typing_rate.try_consume())
                .unwrap_or(false);
            if !allowed {
                debug!("typing rate limit from {from}");
                return Ok(());
            }
        }
        let mut relay = Vec::with_capacity(payload.len() + 2);
        relay.push(event_type);
        relay.extend_from_slice(&sender.to_le_bytes());
        relay.extend_from_slice(&payload[1..]);
        let targets: Vec<SocketAddr> = self
            .peers
            .values()
            .filter(|peer| peer.authenticated && peer.endpoint != from)
            .map(|peer| peer.endpoint)
            .collect();
        for target in targets {
            if event_type == 6 {
                self.send_sequenced(target, EVENTS_CHANNEL, &relay)?;
            } else {
                self.send_reliable(target, EVENTS_CHANNEL, &relay)?;
            }
        }
        Ok(())
    }

    fn handle_force_avatar(
        &mut self,
        from: SocketAddr,
        mode: u8,
        reader: &mut Reader<'_>,
    ) -> Result<(), String> {
        let did = self.peers.get(&from).ok_or("peer vanished")?.did.clone();
        if !self
            .permissions
            .effective(&did)
            .has("basis.moderation.forceavatar")
        {
            return Ok(());
        }
        let target = if mode == 73 {
            let Ok(target) = reader.get_u16() else {
                return Ok(());
            };
            Some(target)
        } else {
            None
        };
        let (Ok(url), Ok(password), Ok(source)) =
            (reader.get_string(), reader.get_string(), reader.get_u8())
        else {
            return Ok(());
        };
        let sender = self.peers.get(&from).ok_or("peer vanished")?.id;
        let mut writer = Writer::new();
        writer.put_u8(74);
        writer.put_u16(sender);
        writer.put_string(&url);
        writer.put_string(&password);
        writer.put_u8(source);
        let payload = writer.into_vec();
        let targets: Vec<SocketAddr> = self
            .peers
            .values()
            .filter(|peer| {
                peer.authenticated
                    && peer.endpoint != from
                    && target.is_none_or(|id| peer.id == id)
                    && !self
                        .permissions
                        .effective(&peer.did)
                        .has("basis.protection")
            })
            .map(|peer| peer.endpoint)
            .collect();
        for endpoint in targets {
            self.send_reliable(endpoint, ADMIN_CHANNEL, &payload)?;
        }
        self.send_back(from, "Avatar forced.")?;
        Ok(())
    }

    fn handle_locomotion_override(
        &mut self,
        from: SocketAddr,
        mode: u8,
        reader: &mut Reader<'_>,
    ) -> Result<(), String> {
        let did = self.peers.get(&from).ok_or("peer vanished")?.did.clone();
        if !self
            .permissions
            .effective(&did)
            .has("basis.moderation.locomotion")
        {
            return Ok(());
        }
        let target = if mode == 76 {
            let Ok(target) = reader.get_u16() else {
                return Ok(());
            };
            Some(target)
        } else {
            None
        };
        let (Ok(fields), Ok(jump), Ok(walk), Ok(run), Ok(gravity), Ok(movement)) = (
            reader.get_u8(),
            reader.get_f32(),
            reader.get_f32(),
            reader.get_f32(),
            reader.get_f32(),
            reader.get_u8(),
        ) else {
            return Ok(());
        };
        let sender = self.peers.get(&from).ok_or("peer vanished")?.id;
        let mut writer = Writer::new();
        writer.put_u8(77);
        writer.put_u16(sender);
        writer.put_u8(fields);
        writer.put_f32(jump);
        writer.put_f32(walk);
        writer.put_f32(run);
        writer.put_f32(gravity);
        writer.put_u8(movement);
        let payload = writer.into_vec();
        let targets: Vec<SocketAddr> = self
            .peers
            .values()
            .filter(|peer| {
                peer.authenticated
                    && peer.endpoint != from
                    && target.is_none_or(|id| peer.id == id)
                    && !self
                        .permissions
                        .effective(&peer.did)
                        .has("basis.protection")
            })
            .map(|peer| peer.endpoint)
            .collect();
        for endpoint in targets {
            self.send_reliable(endpoint, ADMIN_CHANNEL, &payload)?;
        }
        self.send_back(from, "Locomotion override applied.")?;
        Ok(())
    }

    fn handle_rename(&mut self, from: SocketAddr, reader: &mut Reader<'_>) -> Result<(), String> {
        let did = self.peers.get(&from).ok_or("peer vanished")?.did.clone();
        if !self
            .permissions
            .effective(&did)
            .has("basis.moderation.rename")
        {
            return Ok(());
        }
        let (Ok(target), Ok(name)) = (reader.get_u16(), reader.get_string()) else {
            return Ok(());
        };
        let Some(target_peer) = self.peers.values().find(|peer| peer.id == target) else {
            self.send_back(from, "Player not found")?;
            return Ok(());
        };
        let sender = self.peers.get(&from).ok_or("peer vanished")?.id;
        if target != sender
            && self
                .permissions
                .effective(&target_peer.did)
                .has("basis.protection")
        {
            self.send_back(from, "Target is protected")?;
            return Ok(());
        }
        let mut writer = Writer::new();
        writer.put_u8(93);
        writer.put_u16(target);
        writer.put_string(&name);
        writer.put_u16(sender);
        self.broadcast_reliable_all(ADMIN_CHANNEL, &writer.into_vec());
        if let Some(peer) = self.peers.values_mut().find(|peer| peer.id == target) {
            peer.display_name = name.clone();
        }
        if let Ok(mut players) = self.health_players.lock() {
            for player in players.iter_mut().filter(|player| player.net_id == target) {
                player.display_name = name.clone();
            }
        }
        self.send_back(from, &format!("Player {target} renamed to '{name}'."))?;
        Ok(())
    }

    fn send_back(&mut self, to: SocketAddr, message: &str) -> Result<(), String> {
        let mut writer = Writer::new();
        writer.put_u8(3);
        writer.put_string(message);
        self.send_reliable(to, ADMIN_CHANNEL, &writer.into_vec())
    }

    fn handle_permission_edit(
        &mut self,
        mode: u8,
        from: SocketAddr,
        reader: &mut Reader<'_>,
    ) -> Result<(), String> {
        let mut affected: Option<String> = None;
        let result = match mode {
            10 => {
                let (Ok(uuid), Ok(group), Ok(add)) =
                    (reader.get_string(), reader.get_string(), reader.get_bool())
                else {
                    return Ok(());
                };
                affected = Some(uuid.clone());
                if add {
                    self.permissions.add_user_to_group(&uuid, &group);
                } else {
                    self.permissions.remove_user_from_group(&uuid, &group);
                }
                format!(
                    "{} {uuid} {} group '{group}'.",
                    if add { "Added" } else { "Removed" },
                    if add { "to" } else { "from" }
                )
            }
            11 => {
                let (Ok(uuid), Ok(node), Ok(add)) =
                    (reader.get_string(), reader.get_string(), reader.get_bool())
                else {
                    return Ok(());
                };
                affected = Some(uuid.clone());
                if add {
                    self.permissions.add_user_node(&uuid, &node);
                } else {
                    self.permissions.remove_user_node(&uuid, &node);
                }
                format!(
                    "{} node '{node}' {} user {uuid}.",
                    if add { "Added" } else { "Removed" },
                    if add { "to" } else { "from" }
                )
            }
            12 => {
                let (Ok(group), Ok(node), Ok(add)) =
                    (reader.get_string(), reader.get_string(), reader.get_bool())
                else {
                    return Ok(());
                };
                if add {
                    self.permissions.add_group_node(&group, &node);
                } else {
                    self.permissions.remove_group_node(&group, &node);
                }
                format!(
                    "{} node '{node}' {} group '{group}'.",
                    if add { "Added" } else { "Removed" },
                    if add { "to" } else { "from" }
                )
            }
            13 => {
                let Ok(group) = reader.get_string() else {
                    return Ok(());
                };
                self.permissions.create_group(&group);
                format!("Group '{group}' created.")
            }
            14 => {
                let Ok(group) = reader.get_string() else {
                    return Ok(());
                };
                if self.permissions.delete_group(&group) {
                    format!("Group '{group}' deleted.")
                } else {
                    format!("No group named '{group}'.")
                }
            }
            15 => {
                let (Ok(group), Ok(parent), Ok(add)) =
                    (reader.get_string(), reader.get_string(), reader.get_bool())
                else {
                    return Ok(());
                };
                if add {
                    self.permissions.add_group_parent(&group, &parent);
                } else {
                    self.permissions.remove_group_parent(&group, &parent);
                }
                format!(
                    "Group '{group}' {} '{parent}'.",
                    if add {
                        "now inherits"
                    } else {
                        "no longer inherits"
                    }
                )
            }
            _ => return Ok(()),
        };
        if let Err(e) = self.permissions.save(&self.permissions_file) {
            error!(
                "Failed to save permissions.xml to {}: {e}",
                self.permissions_file.display()
            );
            return self.send_back(from, "Failed to save permissions.xml.");
        }
        let refresh_all = mode >= 12;
        let refresh_uuid = if refresh_all {
            None
        } else {
            affected.as_deref()
        };
        self.refresh_permissions(refresh_uuid);
        self.send_back(from, &result)
    }

    fn refresh_permissions(&mut self, uuid: Option<&str>) {
        let targets: Vec<(SocketAddr, Vec<u8>, String)> = self
            .peers
            .values()
            .filter(|peer| peer.authenticated && uuid.is_none_or(|uuid| peer.did == uuid))
            .map(|peer| (peer.endpoint, peer.metadata_raw.clone(), peer.did.clone()))
            .collect();
        for (endpoint, metadata_raw, did) in targets {
            let effective = self.permissions.effective(&did);
            let (bitset, extras) =
                permission_bitset::encode(&effective.allowed_rules(), &effective.denied_rules());
            let metadata = build_server_metadata_with_permissions(
                &metadata_raw,
                &self.config.server_uuid,
                self.config.peer_limit as u16,
                &bitset,
                &extras,
            );
            let _ = self.send_reliable(endpoint, METADATA_CHANNEL, &metadata);
        }
    }

    fn send_mute_result(
        &mut self,
        to: SocketAddr,
        uuid: &str,
        voice_muted: bool,
        text_muted: bool,
    ) -> Result<(), String> {
        let mut writer = Writer::new();
        writer.put_u8(95);
        writer.put_string(uuid);
        writer.put_bool(voice_muted);
        writer.put_bool(text_muted);
        self.send_reliable(to, ADMIN_CHANNEL, &writer.into_vec())
    }

    fn clear_peer_modes(&mut self, id: u16) {
        self.announce_mode.remove(&id);
        self.shout_mode.remove(&id);
        self.full_quality_bypass.remove(&id);
        self.avatar_last_sent
            .retain(|(sender, target), _| *sender != id && *target != id);
    }

    fn kick_uuid(&mut self, uuid: &str, reason: &str) -> bool {
        let Some((endpoint, id, connection_num, connect_time)) = self
            .peers
            .values()
            .find(|peer| peer.did == uuid && peer.authenticated)
            .map(|peer| {
                (
                    peer.endpoint,
                    peer.id,
                    peer.connection_num,
                    peer.connect_time,
                )
            })
        else {
            return false;
        };
        let _ = self.send_disconnect(endpoint, connection_num, connect_time, reason);
        if let Some(peer) = self.peers.remove(&endpoint) {
            self.crash_seen.remove(&peer.did);
            self.clear_peer_modes(id);
            self.visitors.fetch_sub(1, Ordering::Relaxed);
            let actions = self.p2p.remove_peer(id);
            self.relay_p2p(actions);
            self.remove_control_player(id);
            self.broadcast_departure(id);
            self.reset_network_id_if_empty();
            info!("Player {id} removed and cleaned up.");
        }
        true
    }

    fn handle_admin_request(&mut self, from: SocketAddr, payload: &[u8]) -> Result<(), String> {
        let Some(&mode) = payload.first() else {
            return Ok(());
        };
        let did = match self.peers.get(&from) {
            Some(peer) => peer.did.clone(),
            None => return Ok(()),
        };
        if mode == 9 {
            if !self
                .permissions
                .effective(&did)
                .has("basis.permissions.view")
            {
                return Ok(());
            }
            let groups: Vec<_> = self.permissions.groups().collect();
            let users: Vec<_> = self.permissions.users().collect();
            let mut writer = Writer::new();
            writer.put_u8(9);
            writer.put_i32(groups.len() as i32);
            for group in groups {
                writer.put_string(&group.name);
                writer.put_i32(group.nodes.len() as i32);
                for node in &group.nodes {
                    writer.put_string(node);
                }
                writer.put_i32(group.parents.len() as i32);
                for parent in &group.parents {
                    writer.put_string(parent);
                }
            }
            writer.put_i32(users.len() as i32);
            for user in users {
                writer.put_string(&user.uuid);
                writer.put_i32(user.groups.len() as i32);
                for group in &user.groups {
                    writer.put_string(group);
                }
                writer.put_i32(user.nodes.len() as i32);
                for node in &user.nodes {
                    writer.put_string(node);
                }
            }
            self.send_reliable(from, ADMIN_CHANNEL, &writer.into_vec())?;
            return Ok(());
        }
        if mode == 21 {
            self.send_reliable(from, ADMIN_CHANNEL, &self.locks.payload())?;
            return Ok(());
        }
        if mode == 86 {
            let mut reader = Reader::new(&payload[1..]);
            let (Ok(target), Ok(kind), Ok(value)) =
                (reader.get_u16(), reader.get_u8(), reader.get_string())
            else {
                return Ok(());
            };
            let target_uuid = self
                .peers
                .values()
                .find(|peer| peer.id == target && peer.authenticated)
                .map(|peer| peer.did.clone());
            let (held, found) = match target_uuid {
                Some(uuid) if kind == 1 => (self.permissions.is_in_group(&uuid, &value), true),
                Some(uuid) => (self.permissions.effective(&uuid).has(&value), true),
                None => (false, false),
            };
            let mut writer = Writer::new();
            writer.put_u8(87);
            writer.put_u16(target);
            writer.put_u8(kind);
            writer.put_string(&value);
            writer.put_bool(held);
            writer.put_bool(found);
            self.send_reliable(from, ADMIN_CHANNEL, &writer.into_vec())?;
            return Ok(());
        }
        let mut reader = Reader::new(&payload[1..]);
        match mode {
            2 | 5 => {
                if !self.permissions.effective(&did).has("basis.moderation.ban") {
                    return Ok(());
                }
                let Ok(text) = reader.get_string() else {
                    return Ok(());
                };
                let Ok(ip) = text.trim().parse::<IpAddr>() else {
                    self.send_back(from, "Invalid IP address")?;
                    return Ok(());
                };
                if mode == 2 {
                    self.banned_ips.insert(ip);
                    self.send_back(from, &format!("IP banned: {ip}"))?;
                } else {
                    self.banned_ips.remove(&ip);
                    self.send_back(from, &format!("IP unbanned: {ip}"))?;
                }
            }
            0 => {
                if !self.permissions.effective(&did).has("basis.moderation.ban") {
                    return Ok(());
                }
                let (Ok(uuid), Ok(reason)) = (reader.get_string(), reader.get_string()) else {
                    return Ok(());
                };
                if self.permissions.effective(&uuid).has("basis.protection") {
                    self.send_back(from, "Target is protected")?;
                    return Ok(());
                }
                self.bans.ban(&uuid, &reason);
                self.bans.save(&ban_path());
                self.kick_uuid(&uuid, &format!("Banned: {reason}"));
                self.send_back(from, "Banned")?;
            }
            1 => {
                if !self
                    .permissions
                    .effective(&did)
                    .has("basis.moderation.kick")
                {
                    return Ok(());
                }
                let (Ok(uuid), Ok(reason)) = (reader.get_string(), reader.get_string()) else {
                    return Ok(());
                };
                if self.permissions.effective(&uuid).has("basis.protection") {
                    self.send_back(from, "Target is protected")?;
                    return Ok(());
                }
                self.kick_uuid(&uuid, &reason);
                self.send_back(from, "Kicked")?;
            }
            3 => {
                if !self
                    .permissions
                    .effective(&did)
                    .has("basis.moderation.message")
                {
                    return Ok(());
                }
                let (Ok(target), Ok(message)) = (reader.get_u16(), reader.get_string()) else {
                    return Ok(());
                };
                if let Some(endpoint) = self
                    .peers
                    .values()
                    .find(|peer| peer.id == target)
                    .map(|peer| peer.endpoint)
                {
                    let mut writer = Writer::new();
                    writer.put_u8(3);
                    writer.put_string(&message);
                    self.send_reliable(endpoint, ADMIN_CHANNEL, &writer.into_vec())?;
                }
            }
            4 => {
                if !self
                    .permissions
                    .effective(&did)
                    .has("basis.moderation.messageall")
                {
                    return Ok(());
                }
                let Ok(message) = reader.get_string() else {
                    return Ok(());
                };
                let mut writer = Writer::new();
                writer.put_u8(4);
                writer.put_string(&message);
                self.broadcast_reliable_except(from, ADMIN_CHANNEL, &writer.into_vec())?;
            }
            34 => {
                if !self.permissions.effective(&did).has("basis.configuration") {
                    return Ok(());
                }
                let Ok(mode_value) = reader.get_u8() else {
                    return Ok(());
                };
                if mode_value > 3 {
                    self.send_back(
                        from,
                        &format!("Unknown restriction mode value {mode_value}."),
                    )?;
                } else {
                    self.restriction_mode = mode_value;
                    self.locks.user_restriction_mode = mode_value;
                    let value = match mode_value {
                        1 => "BanList",
                        2 => "AllowList",
                        3 => "RejoinOnly",
                        _ => "Normal",
                    };
                    let _ = basis_config::update_values(
                        std::path::Path::new(&self.config.config_path),
                        &[("BasisUserRestrictionMode", value)],
                    );
                    self.broadcast_reliable_all(ADMIN_CHANNEL, &self.locks.payload());
                    self.send_back(from, &format!("Restriction mode set to {mode_value}."))?;
                }
            }
            35 | 36 => {
                if !self
                    .permissions
                    .effective(&did)
                    .has("basis.moderation.whitelist")
                {
                    return Ok(());
                }
                let Ok(uuid) = reader.get_string() else {
                    return Ok(());
                };
                if mode == 35 {
                    self.allowlist.add(&uuid);
                } else {
                    self.allowlist.remove(&uuid);
                }
                self.allowlist.save(&allowlist_path());
                self.send_back(
                    from,
                    &format!(
                        "{} {uuid} {} allowlist.",
                        if mode == 35 { "Added" } else { "Removed" },
                        if mode == 35 { "to" } else { "from" }
                    ),
                )?;
            }
            39 => {
                if !self.permissions.effective(&did).has("basis.configuration") {
                    return Ok(());
                }
                let (Ok(item_mode), Ok(url), Ok(password)) =
                    (reader.get_u8(), reader.get_string(), reader.get_string())
                else {
                    return Ok(());
                };
                if url.is_empty() || item_mode > 2 {
                    self.send_back(from, "Invalid library item")?;
                    return Ok(());
                }
                let item = ServerLibraryItem {
                    mode: item_mode,
                    url: url.clone(),
                    password,
                };
                self.library_items.retain(|existing| existing.url != url);
                self.library_items.push(item.clone());
                self.library_wire = build_server_library(&self.library_items);
                save_library_item(&item);
                let wire = self.library_wire.clone();
                self.broadcast_reliable_all(SERVER_LIBRARY_CHANNEL, &wire);
                self.send_back(from, &format!("Added {url} to default library."))?;
            }
            40 => {
                if !self.permissions.effective(&did).has("basis.configuration") {
                    return Ok(());
                }
                let Ok(url) = reader.get_string() else {
                    return Ok(());
                };
                self.library_items.retain(|item| item.url != url);
                self.library_wire = build_server_library(&self.library_items);
                remove_library_item(&url);
                let wire = self.library_wire.clone();
                self.broadcast_reliable_all(SERVER_LIBRARY_CHANNEL, &wire);
                self.send_back(from, &format!("Removed {url} from default library."))?;
            }
            22 | 24 => {
                let enabled = if mode == 22 {
                    self.headless_audio_enabled
                } else {
                    self.headless_disallowed
                };
                self.send_reliable(from, ADMIN_CHANNEL, &[mode, u8::from(enabled)])?;
            }
            23 | 25 => {
                let needed = if mode == 23 {
                    "basis.moderation.headlessaudio"
                } else {
                    "basis.moderation.globallock"
                };
                if !self.permissions.effective(&did).has(needed) {
                    return Ok(());
                }
                let Ok(enabled) = reader.get_bool() else {
                    return Ok(());
                };
                if mode == 23 {
                    self.headless_audio_enabled = enabled;
                } else {
                    self.headless_disallowed = enabled;
                }
                let state_mode = if mode == 23 { 22 } else { 24 };
                self.broadcast_reliable_all(ADMIN_CHANNEL, &[state_mode, u8::from(enabled)]);
                self.send_back(
                    from,
                    &format!(
                        "{} {}.",
                        if mode == 23 {
                            "Headless audio"
                        } else {
                            "Headless disallow"
                        },
                        if enabled { "enabled" } else { "disabled" }
                    ),
                )?;
            }
            26 | 28 | 30 | 64 => {
                if !self
                    .permissions
                    .effective(&did)
                    .has("basis.moderation.opusbitrate")
                {
                    return Ok(());
                }
                match mode {
                    26 => {
                        let Ok(percent) = reader.get_u8() else {
                            return Ok(());
                        };
                        self.opus_packet_loss = percent.min(100);
                        self.broadcast_reliable_all(ADMIN_CHANNEL, &[27, self.opus_packet_loss]);
                        self.send_back(
                            from,
                            &format!("Opus FEC packet-loss % is now {}.", self.opus_packet_loss),
                        )?;
                    }
                    28 => {
                        let (Ok(target), Ok(bitrate)) = (reader.get_u16(), reader.get_i32()) else {
                            return Ok(());
                        };
                        if bitrate == 0 {
                            self.opus_user_bitrates.remove(&target);
                        } else {
                            self.opus_user_bitrates.insert(target, bitrate);
                        }
                        if let Some(endpoint) = self
                            .peers
                            .values()
                            .find(|peer| peer.id == target)
                            .map(|peer| peer.endpoint)
                        {
                            let mut writer = Writer::new();
                            writer.put_u8(29);
                            writer.put_i32(bitrate);
                            self.send_reliable(endpoint, ADMIN_CHANNEL, &writer.into_vec())?;
                        }
                        self.send_back(
                            from,
                            &format!(
                                "Opus bitrate override for player {target} is now {bitrate} bps."
                            ),
                        )?;
                    }
                    30 => {
                        let Ok(duration) = reader.get_u8() else {
                            return Ok(());
                        };
                        if duration != 20 && duration != 40 {
                            self.send_back(from, "Opus frame duration must be 20 or 40 ms.")?;
                        } else {
                            self.opus_frame_duration = duration;
                            self.broadcast_reliable_all(ADMIN_CHANNEL, &[31, duration]);
                            self.send_back(
                                from,
                                &format!("Opus frame duration is now {duration} ms."),
                            )?;
                        }
                    }
                    64 => {
                        let Ok(bitrate) = reader.get_i32() else {
                            return Ok(());
                        };
                        self.opus_global_bitrate = bitrate;
                        let mut writer = Writer::new();
                        writer.put_u8(65);
                        writer.put_i32(bitrate);
                        self.broadcast_reliable_all(ADMIN_CHANNEL, &writer.into_vec());
                        self.send_back(
                            from,
                            &format!("Global Opus bitrate is now {bitrate} bps."),
                        )?;
                    }
                    _ => {}
                }
            }
            27 => {
                self.send_reliable(from, ADMIN_CHANNEL, &[27, self.opus_packet_loss])?;
            }
            31 => {
                self.send_reliable(from, ADMIN_CHANNEL, &[31, self.opus_frame_duration])?;
            }
            65 => {
                let mut writer = Writer::new();
                writer.put_u8(65);
                writer.put_i32(self.opus_global_bitrate);
                self.send_reliable(from, ADMIN_CHANNEL, &writer.into_vec())?;
            }
            90 | 91 => {
                if mode == 90 {
                    if !self
                        .permissions
                        .effective(&did)
                        .has("basis.moderation.globallock")
                    {
                        return Ok(());
                    }
                    let (Ok(fields), Ok(jump), Ok(walk), Ok(run), Ok(gravity), Ok(movement)) = (
                        reader.get_u8(),
                        reader.get_f32(),
                        reader.get_f32(),
                        reader.get_f32(),
                        reader.get_f32(),
                        reader.get_u8(),
                    ) else {
                        return Ok(());
                    };
                    self.locomotion_policy = (fields, jump, walk, run, gravity, movement);
                    let fields_text = fields.to_string();
                    let jump_text = jump.to_string();
                    let walk_text = walk.to_string();
                    let run_text = run.to_string();
                    let gravity_text = gravity.to_string();
                    let movement_text = movement.to_string();
                    let _ = basis_config::update_values(
                        std::path::Path::new(&self.config.config_path),
                        &[
                            ("LocomotionPolicyFields", fields_text.as_str()),
                            ("LocomotionPolicyJumpHeight", jump_text.as_str()),
                            ("LocomotionPolicyWalkSpeed", walk_text.as_str()),
                            ("LocomotionPolicyRunSpeed", run_text.as_str()),
                            ("LocomotionPolicyGravity", gravity_text.as_str()),
                            ("LocomotionPolicyMode", movement_text.as_str()),
                        ],
                    );
                }
                let (fields, jump, walk, run, gravity, movement) = self.locomotion_policy;
                let mut writer = Writer::new();
                writer.put_u8(91);
                writer.put_u8(fields);
                writer.put_f32(jump);
                writer.put_f32(walk);
                writer.put_f32(run);
                writer.put_f32(gravity);
                writer.put_u8(movement);
                let payload = writer.into_vec();
                if mode == 90 {
                    self.broadcast_reliable_all(ADMIN_CHANNEL, &payload);
                    self.send_back(
                        from,
                        if fields == 0 {
                            "Locomotion policy cleared; players keep their own movement values."
                        } else {
                            "Locomotion policy set for the instance."
                        },
                    )?;
                } else {
                    self.send_reliable(from, ADMIN_CHANNEL, &payload)?;
                }
            }
            79 | 80 => {
                if mode == 79 {
                    if !self
                        .permissions
                        .effective(&did)
                        .has("basis.moderation.globallock")
                    {
                        return Ok(());
                    }
                    let (Ok(egress), Ok(download), Ok(enforcement)) =
                        (reader.get_i32(), reader.get_i32(), reader.get_i32())
                    else {
                        return Ok(());
                    };
                    self.image_egress_mbps = egress.max(0);
                    self.image_download_mbps = download.max(0);
                    self.image_enforcement_percent = enforcement.clamp(100, 1000);
                    let egress_text = self.image_egress_mbps.to_string();
                    let download_text = self.image_download_mbps.to_string();
                    let enforcement_text = self.image_enforcement_percent.to_string();
                    let _ = basis_config::update_values(
                        std::path::Path::new(&self.config.config_path),
                        &[
                            ("ImageShareEgressMegabitsPerSecond", egress_text.as_str()),
                            (
                                "ImageShareDownloadMegabitsPerSecond",
                                download_text.as_str(),
                            ),
                            (
                                "ImageShareEgressEnforcementPercent",
                                enforcement_text.as_str(),
                            ),
                        ],
                    );
                }
                let mut writer = Writer::new();
                writer.put_u8(80);
                writer.put_i32(self.image_egress_mbps);
                writer.put_i32(self.image_download_mbps);
                writer.put_i32(self.image_enforcement_percent);
                let payload = writer.into_vec();
                if mode == 79 {
                    self.broadcast_reliable_all(ADMIN_CHANNEL, &payload);
                    self.send_back(from, "Image bandwidth updated.")?;
                } else {
                    self.send_reliable(from, ADMIN_CHANNEL, &payload)?;
                }
            }
            62 | 63 => {
                if mode == 62 {
                    if !self
                        .permissions
                        .effective(&did)
                        .has("basis.moderation.globallock")
                    {
                        return Ok(());
                    }
                    let (
                        Ok(interval),
                        Ok(base),
                        Ok(rate),
                        Ok(slowest),
                        Ok(high),
                        Ok(medium),
                        Ok(low),
                        Ok(bundle),
                        Ok(min_messages),
                        Ok(min_bytes),
                        Ok(profiling),
                        Ok(zstd),
                        Ok(zstd_deltas),
                        Ok(zstd_level),
                        Ok(zstd_max_shed),
                    ) = (
                        reader.get_i32(),
                        reader.get_i32(),
                        reader.get_f32(),
                        reader.get_f32(),
                        reader.get_f32(),
                        reader.get_f32(),
                        reader.get_f32(),
                        reader.get_bool(),
                        reader.get_i32(),
                        reader.get_i32(),
                        reader.get_bool(),
                        reader.get_bool(),
                        reader.get_bool(),
                        reader.get_i32(),
                        reader.get_i32(),
                    )
                    else {
                        return Ok(());
                    };
                    self.reduction_interval = interval.max(1);
                    self.reduction_base = base.max(1);
                    self.reduction_rate = rate.max(0.0);
                    self.reduction_slowest = slowest.max(0.0);
                    self.config.high_quality_distance = high.clamp(0.0, 1000.0);
                    self.config.medium_quality_distance = medium.clamp(0.0, 1000.0);
                    self.config.low_quality_distance = low.clamp(0.0, 1000.0);
                    self.bundle_compression = bundle && self.config.has_file_support;
                    self.bundle_min_messages = min_messages.max(1);
                    self.bundle_min_bytes = min_bytes.max(0);
                    self.bsr_profiling = profiling;
                    self.bundle_zstd = zstd;
                    self.bundle_zstd_deltas = zstd_deltas;
                    self.bundle_zstd_level = zstd_level;
                    self.bundle_zstd_max_shed = zstd_max_shed;
                    let interval_text = self.reduction_interval.to_string();
                    let base_text = self.reduction_base.to_string();
                    let rate_text = self.reduction_rate.to_string();
                    let slowest_text = self.reduction_slowest.to_string();
                    let high_text = self.config.high_quality_distance.to_string();
                    let medium_text = self.config.medium_quality_distance.to_string();
                    let low_text = self.config.low_quality_distance.to_string();
                    let bundle_text = self.bundle_compression.to_string();
                    let min_messages_text = self.bundle_min_messages.to_string();
                    let min_bytes_text = self.bundle_min_bytes.to_string();
                    let profiling_text = self.bsr_profiling.to_string();
                    let zstd_text = self.bundle_zstd.to_string();
                    let zstd_deltas_text = self.bundle_zstd_deltas.to_string();
                    let zstd_level_text = self.bundle_zstd_level.to_string();
                    let zstd_shed_text = self.bundle_zstd_max_shed.to_string();
                    let _ = basis_config::update_values(
                        std::path::Path::new(&self.config.config_path),
                        &[
                            ("BSRSMillisecondDefaultInterval", interval_text.as_str()),
                            ("BSRBaseMultiplier", base_text.as_str()),
                            ("BSRSIncreaseRate", rate_text.as_str()),
                            ("BSRSlowestSendRate", slowest_text.as_str()),
                            ("HighQualityDistance", high_text.as_str()),
                            ("MediumQualityDistance", medium_text.as_str()),
                            ("LowQualityDistance", low_text.as_str()),
                            ("EnableAvatarBundleCompression", bundle_text.as_str()),
                            ("AvatarBundleMinMessages", min_messages_text.as_str()),
                            ("AvatarBundleMinBytes", min_bytes_text.as_str()),
                            ("EnableBSRProfiling", profiling_text.as_str()),
                            ("EnableAvatarBundleZstd", zstd_text.as_str()),
                            ("AvatarBundleZstdDeltaBundles", zstd_deltas_text.as_str()),
                            ("AvatarBundleZstdLevel", zstd_level_text.as_str()),
                            ("AvatarBundleZstdMaxShedTier", zstd_shed_text.as_str()),
                        ],
                    );
                }
                let payload = self.reduction_payload();
                if mode == 62 {
                    self.broadcast_reliable_all(ADMIN_CHANNEL, &payload);
                    self.send_back(from, "Reduction settings updated.")?;
                } else {
                    self.send_reliable(from, ADMIN_CHANNEL, &payload)?;
                }
            }
            47 => {
                if !self.permissions.effective(&did).has("basis.admin.logs") {
                    return Ok(());
                }
                if !self.config.has_file_support {
                    self.send_back(
                        from,
                        "File support is disabled on this server; there are no logs to pull.",
                    )?;
                    return Ok(());
                }
                let (raw, files) = build_log_container();
                if files == 0 {
                    self.send_back(from, "No log files were found to send.")?;
                    return Ok(());
                }
                let total_chunks = raw.len().div_ceil(32 * 1024);
                let mut begin = Writer::new();
                begin.put_u8(48);
                begin.put_string(&self.config.server_name);
                begin.put_string("logs");
                begin.put_bool(false);
                begin.put_i32(raw.len() as i32);
                begin.put_i32(raw.len() as i32);
                begin.put_i32(total_chunks as i32);
                self.send_reliable(from, ADMIN_CHANNEL, &begin.into_vec())?;
                for (index, chunk) in raw.chunks(32 * 1024).enumerate() {
                    let mut writer = Writer::new();
                    writer.put_u8(49);
                    writer.put_i32(index as i32);
                    writer.put_bytes_with_length(chunk);
                    self.send_reliable(from, ADMIN_CHANNEL, &writer.into_vec())?;
                }
                let mut end = Writer::new();
                end.put_u8(50);
                end.put_bool(true);
                end.put_string(&format!(
                    "Sent {files} log file(s), {} KB raw.",
                    raw.len() / 1024
                ));
                self.send_reliable(from, ADMIN_CHANNEL, &end.into_vec())?;
            }
            52 => {
                if !self.permissions.effective(&did).has("basis.admin.logs") {
                    return Ok(());
                }
                if !self.config.has_file_support {
                    self.send_back(
                        from,
                        "File support is disabled on this server; there are no logs to delete.",
                    )?;
                    return Ok(());
                }
                let mut deleted = 0usize;
                for folder in ["logs", "CrashReports"] {
                    deleted += delete_directory_files(folder);
                }
                self.crash_seen.clear();
                self.send_back(
                    from,
                    &format!("Deleted {deleted} log/crash file(s) from logs/ and CrashReports/."),
                )?;
            }
            57 | 58 => {
                if mode == 58 {
                    if !self
                        .permissions
                        .effective(&did)
                        .has("basis.moderation.globallock")
                    {
                        return Ok(());
                    }
                    let Ok(spheres) = reader.get_i32() else {
                        return Ok(());
                    };
                    self.max_spheres = spheres.max(0);
                    if reader.remaining() >= 8 {
                        let (Ok(leave), Ok(deletion)) = (reader.get_i32(), reader.get_i32()) else {
                            return Ok(());
                        };
                        self.sphere_leave_timeout = leave.max(0);
                        self.sphere_deletion_timer = deletion.max(0);
                    }
                    let spheres_text = self.max_spheres.to_string();
                    let leave_text = self.sphere_leave_timeout.to_string();
                    let deletion_text = self.sphere_deletion_timer.to_string();
                    let _ = basis_config::update_values(
                        std::path::Path::new(&self.config.config_path),
                        &[
                            ("MaxContentSpheresPerPlayer", spheres_text.as_str()),
                            ("ContentSphereLeaveTimeoutSeconds", leave_text.as_str()),
                            ("ContentSphereDeletionTimerSeconds", deletion_text.as_str()),
                        ],
                    );
                }
                let mut writer = Writer::new();
                writer.put_u8(57);
                writer.put_i32(self.max_spheres);
                writer.put_i32(self.sphere_leave_timeout);
                writer.put_i32(self.sphere_deletion_timer);
                let payload = writer.into_vec();
                if mode == 58 {
                    self.broadcast_reliable_all(ADMIN_CHANNEL, &payload);
                    self.send_back(
                        from,
                        &format!(
                            "Resource limits set: spheres/player {}, leave timeout {}s, deletion timer {}s.",
                            self.max_spheres, self.sphere_leave_timeout, self.sphere_deletion_timer
                        ),
                    )?;
                } else {
                    self.send_reliable(from, ADMIN_CHANNEL, &payload)?;
                }
            }
            55 | 56 => {
                if mode == 56 {
                    if !self
                        .permissions
                        .effective(&did)
                        .has("basis.moderation.globallock")
                    {
                        return Ok(());
                    }
                    let (Ok(minimum), Ok(maximum)) = (reader.get_f32(), reader.get_f32()) else {
                        return Ok(());
                    };
                    self.avatar_scale_min = minimum.max(0.0);
                    self.avatar_scale_max = maximum.max(self.avatar_scale_min);
                    let minimum_text = self.avatar_scale_min.to_string();
                    let maximum_text = self.avatar_scale_max.to_string();
                    let _ = basis_config::update_values(
                        std::path::Path::new(&self.config.config_path),
                        &[
                            ("MinAvatarEyeHeightMeters", minimum_text.as_str()),
                            ("MaxAvatarEyeHeightMeters", maximum_text.as_str()),
                        ],
                    );
                }
                let mut writer = Writer::new();
                writer.put_u8(55);
                writer.put_f32(self.avatar_scale_min);
                writer.put_f32(self.avatar_scale_max);
                let payload = writer.into_vec();
                if mode == 56 {
                    self.broadcast_reliable_all(ADMIN_CHANNEL, &payload);
                    self.send_back(
                        from,
                        &format!(
                            "Avatar scale limits set: {} m .. {} m.",
                            self.avatar_scale_min, self.avatar_scale_max
                        ),
                    )?;
                } else {
                    self.send_reliable(from, ADMIN_CHANNEL, &payload)?;
                }
            }
            45 | 46 => {
                if mode == 46 {
                    if !self
                        .permissions
                        .effective(&did)
                        .has("basis.moderation.globallock")
                    {
                        return Ok(());
                    }
                    let (Ok(microphone), Ok(hearing)) = (reader.get_f32(), reader.get_f32()) else {
                        return Ok(());
                    };
                    self.audio_microphone_meters = microphone.max(0.0);
                    self.audio_hearing_meters = hearing.max(0.0);
                    let microphone_text = self.audio_microphone_meters.to_string();
                    let hearing_text = self.audio_hearing_meters.to_string();
                    let _ = basis_config::update_values(
                        std::path::Path::new(&self.config.config_path),
                        &[
                            ("MaxMicrophoneRangeMeters", microphone_text.as_str()),
                            ("MaxHearingRangeMeters", hearing_text.as_str()),
                        ],
                    );
                }
                let mut writer = Writer::new();
                writer.put_u8(45);
                writer.put_f32(self.audio_microphone_meters);
                writer.put_f32(self.audio_hearing_meters);
                let payload = writer.into_vec();
                if mode == 46 {
                    self.broadcast_reliable_all(ADMIN_CHANNEL, &payload);
                    self.send_back(
                        from,
                        &format!(
                            "Audio range limits set: microphone {} m, hearing {} m.",
                            self.audio_microphone_meters, self.audio_hearing_meters
                        ),
                    )?;
                } else {
                    self.send_reliable(from, ADMIN_CHANNEL, &payload)?;
                }
            }
            42 => {
                if !self
                    .permissions
                    .effective(&did)
                    .has("basis.moderation.globallock")
                {
                    return Ok(());
                }
                let Ok(mask) = reader.get_u8() else {
                    return Ok(());
                };
                self.locks.camera_metadata_mask = mask;
                self.broadcast_reliable_all(ADMIN_CHANNEL, &self.locks.payload());
                self.send_back(
                    from,
                    &format!("Camera metadata policy updated (mask {mask})."),
                )?;
            }
            32 => {
                if !self.permissions.effective(&did).has("basis.configuration") {
                    return Ok(());
                }
                let Ok(name) = reader.get_string() else {
                    return Ok(());
                };
                self.config.server_name = name.clone();
                let _ = basis_config::update_values(
                    std::path::Path::new(&self.config.config_path),
                    &[("ServerName", name.as_str())],
                );
                self.send_back(from, &format!("Server name set to '{name}'."))?;
            }
            33 => {
                if !self.permissions.effective(&did).has("basis.configuration") {
                    return Ok(());
                }
                let Ok(motd) = reader.get_string() else {
                    return Ok(());
                };
                self.config.server_motd = motd.clone();
                let _ = basis_config::update_values(
                    std::path::Path::new(&self.config.config_path),
                    &[("ServerMotd", motd.as_str())],
                );
                self.send_back(from, &format!("Server MOTD set to '{motd}'."))?;
            }
            81 => {
                if !self.permissions.effective(&did).has("basis.configuration") {
                    return Ok(());
                }
                let Ok(limit) = reader.get_i32() else {
                    return Ok(());
                };
                self.config.peer_limit = limit.max(0) as usize;
                let limit_text = self.config.peer_limit.to_string();
                let _ = basis_config::update_values(
                    std::path::Path::new(&self.config.config_path),
                    &[("PeerLimit", limit_text.as_str())],
                );
                self.send_back(from, &format!("Peer limit set to {limit}."))?;
            }
            82 => {
                let mut writer = Writer::new();
                writer.put_u8(82);
                writer.put_i32(self.config.peer_limit as i32);
                self.send_reliable(from, ADMIN_CHANNEL, &writer.into_vec())?;
            }
            61 => {
                if !self
                    .permissions
                    .effective(&did)
                    .has("basis.moderation.fullqualitybroadcast")
                {
                    return Ok(());
                }
                let (Ok(target), Ok(enable)) = (reader.get_u16(), reader.get_bool()) else {
                    return Ok(());
                };
                if enable {
                    self.full_quality_bypass.insert(target);
                } else {
                    self.full_quality_bypass.remove(&target);
                }
                self.send_back(
                    from,
                    &format!(
                        "Full-quality broadcast {} for player {target}.",
                        if enable { "ENABLED" } else { "DISABLED" }
                    ),
                )?;
            }
            73 | 75 => {
                self.handle_force_avatar(from, mode, &mut reader)?;
            }
            76 | 78 => {
                self.handle_locomotion_override(from, mode, &mut reader)?;
            }
            93 => {
                self.handle_rename(from, &mut reader)?;
            }
            10..=15 => {
                if !self
                    .permissions
                    .effective(&did)
                    .has("basis.permissions.edit")
                {
                    return Ok(());
                }
                self.handle_permission_edit(mode, from, &mut reader)?;
            }
            16 | 17 | 88 | 89 => {
                if !self
                    .permissions
                    .effective(&did)
                    .has("basis.moderation.announce")
                {
                    return Ok(());
                }
                let Ok(target) = reader.get_u16() else {
                    return Ok(());
                };
                let enable = mode == 16 || mode == 88;
                let shout = mode == 88 || mode == 89;
                let set = if shout {
                    &mut self.shout_mode
                } else {
                    &mut self.announce_mode
                };
                if enable {
                    set.insert(target);
                } else {
                    set.remove(&target);
                }
                let initiator = self.peers.get(&from).ok_or("peer vanished")?.id;
                let mut writer = Writer::new();
                writer.put_u8(mode);
                writer.put_u16(target);
                writer.put_u16(initiator);
                self.broadcast_reliable_all(ADMIN_CHANNEL, &writer.into_vec());
            }
            7 | 8 => {
                if !self
                    .permissions
                    .effective(&did)
                    .has("basis.moderation.teleport")
                {
                    return Ok(());
                }
                let Ok(value) = reader.get_u16() else {
                    return Ok(());
                };
                let mut writer = Writer::new();
                writer.put_u8(mode);
                if mode == 7 {
                    writer.put_u16(value);
                    self.broadcast_reliable_except(from, ADMIN_CHANNEL, &writer.into_vec())?;
                } else if let Some(endpoint) = self
                    .peers
                    .values()
                    .find(|peer| peer.id == value && peer.authenticated)
                    .map(|peer| peer.endpoint)
                {
                    let sender_id = self.peers.get(&from).ok_or("peer vanished")?.id;
                    writer.put_u16(sender_id);
                    self.send_reliable(endpoint, ADMIN_CHANNEL, &writer.into_vec())?;
                }
            }
            6 => {
                if !self
                    .permissions
                    .effective(&did)
                    .has("basis.moderation.unban")
                {
                    return Ok(());
                }
                let Ok(uuid) = reader.get_string() else {
                    return Ok(());
                };
                self.bans.unban(&uuid);
                self.bans.save(&ban_path());
                self.send_back(from, "Unbanned")?;
            }
            83 | 84 => {
                if !self
                    .permissions
                    .effective(&did)
                    .has("basis.moderation.mute")
                {
                    return Ok(());
                }
                let (Ok(uuid), Ok(muted)) = (reader.get_string(), reader.get_bool()) else {
                    return Ok(());
                };
                if self.permissions.effective(&uuid).has("basis.protection") {
                    self.send_back(from, "Target is protected")?;
                    return Ok(());
                }
                let voice = mode == 83;
                self.mutes.apply(&uuid, voice, muted);
                self.mutes.save(&mute_path());
                let (voice_state, text_state) = self.mutes.state(&uuid);
                if let Some(endpoint) = self
                    .peers
                    .values()
                    .find(|peer| peer.did == uuid)
                    .map(|peer| peer.endpoint)
                {
                    self.send_reliable(
                        endpoint,
                        ADMIN_CHANNEL,
                        &[85, u8::from(voice_state), u8::from(text_state)],
                    )?;
                }
                let kind = if voice { "Voice" } else { "Text chat" };
                let verb = if muted { "muted" } else { "unmuted" };
                self.send_back(from, &format!("{kind} {verb} for {uuid}."))?;
                self.send_mute_result(from, &uuid, voice_state, text_state)?;
            }
            94 => {
                if !self
                    .permissions
                    .effective(&did)
                    .has("basis.moderation.mute")
                {
                    return Ok(());
                }
                let Ok(uuid) = reader.get_string() else {
                    return Ok(());
                };
                let (voice_state, text_state) = self.mutes.state(&uuid);
                self.send_mute_result(from, &uuid, voice_state, text_state)?;
            }
            _ => {}
        }
        // AdminRequestMode.SetGlobalCrashReporting = 44.
        if mode == 44 {
            if !self
                .permissions
                .effective(&did)
                .has("basis.moderation.globallock")
                || payload.len() < 2
            {
                return Ok(());
            }
            let enabled = payload[1] != 0;
            if enabled == self.crash_reporting_enabled {
                return Ok(());
            }
            self.crash_reporting_enabled = enabled;
            self.broadcast_reliable_all(ADMIN_CHANNEL, &[43, u8::from(enabled)]);
            return Ok(());
        }
        if self
            .permissions
            .effective(&did)
            .has("basis.moderation.globallock")
            && self.locks.toggle(mode).is_some()
        {
            let state = self.locks.payload();
            self.broadcast_reliable_all(ADMIN_CHANNEL, &state);
        }
        Ok(())
    }

    fn handle_error_report(&mut self, from: SocketAddr, payload: &[u8]) {
        if !self.config.has_file_support || !self.crash_reporting_enabled || payload.len() < 4 {
            return;
        }
        let mut reader = Reader::new(&payload[1..]);
        let Ok(severity) = reader.get_u8() else {
            return;
        };
        let Ok(blob) = reader.get_bytes_with_length() else {
            return;
        };
        let parts = basis_protocol::permission_compression::decompress(blob, 3);
        let system = parts.first().cloned().unwrap_or_default();
        let message: String = parts
            .get(1)
            .map(|value| value.chars().take(2000).collect())
            .unwrap_or_default();
        let stack: String = parts
            .get(2)
            .map(|value| value.chars().take(12000).collect())
            .unwrap_or_default();
        let Some(peer) = self.peers.get(&from) else {
            return;
        };
        let uuid = peer.did.clone();
        let display_name = peer.display_name.clone();
        let platform = peer.platform.clone();
        let mut hash = 14695981039346656037u64;
        let mut mix = |value: &str| {
            for byte in value.as_bytes() {
                hash ^= *byte as u64;
                hash = hash.wrapping_mul(1099511628211);
            }
        };
        mix(&severity.to_string());
        mix(&system);
        mix(&message);
        mix(stack.lines().next().unwrap_or(""));
        if self.crash_seen.len() >= 4096 && !self.crash_seen.contains_key(&uuid) {
            self.crash_seen.clear();
        }
        let seen = self.crash_seen.entry(uuid.clone()).or_default();
        if seen.len() >= 256 || !seen.insert(hash) {
            return;
        }
        let safe_uuid: String = uuid
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.') {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        let base = std::env::current_exe()
            .ok()
            .and_then(|path| path.parent().map(std::path::Path::to_path_buf))
            .unwrap_or_else(|| std::path::PathBuf::from("."));
        let dir = base.join("CrashReports");
        if std::fs::create_dir_all(&dir).is_err() {
            return;
        }
        let severity_name = match severity {
            1 => "exception",
            2 => "crash",
            _ => "error",
        };
        let line = format!(
            "{{\"timeUtc\":\"{}\",\"uuid\":\"{}\",\"displayName\":\"{}\",\"platform\":\"{}\",\"severity\":\"{}\",\"system\":\"{}\",\"message\":\"{}\",\"stack\":\"{}\"}}\n",
            chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            json_escape(&uuid),
            json_escape(&display_name),
            json_escape(&platform),
            severity_name,
            json_escape(&system),
            json_escape(&message),
            json_escape(&stack),
        );
        let path = dir.join(format!("{safe_uuid}.jsonl"));
        if let Ok(mut file) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
        {
            let _ = file.write_all(line.as_bytes());
        }
    }

    fn handle_jiggle_grab(&mut self, from: SocketAddr, payload: &[u8]) -> Result<(), String> {
        if payload.len() < 3 {
            return Ok(());
        }
        let op = payload[1];
        let body = &payload[2..];
        if op > 2 || body.is_empty() {
            return Ok(());
        }
        let allowed = self
            .peers
            .get_mut(&from)
            .map(|peer| peer.jiggle_rate.try_consume())
            .unwrap_or(false);
        if !allowed {
            return Ok(());
        }
        let sender = self.peers.get(&from).ok_or("peer vanished")?.id;
        let target_id = if op == 0 {
            if body.len() < 2 {
                return Ok(());
            }
            Some(u16::from_le_bytes([body[0], body[1]]))
        } else {
            None
        };
        let target_position = target_id.and_then(|id| {
            self.peers
                .values()
                .find(|peer| peer.id == id)
                .and_then(|peer| peer.position)
        });
        let targets: Vec<SocketAddr> = self
            .peers
            .values()
            .filter(|peer| peer.authenticated && peer.endpoint != from)
            .filter(|peer| {
                let Some(target_id) = target_id else {
                    return true;
                };
                if peer.id == target_id {
                    return true;
                }
                let (Some(target), Some(recipient)) = (target_position, peer.position) else {
                    return true;
                };
                let dx = target[0] - recipient[0];
                let dy = target[1] - recipient[1];
                let dz = target[2] - recipient[2];
                dx * dx + dy * dy + dz * dz <= 64.0 * 64.0
            })
            .map(|peer| peer.endpoint)
            .collect();
        let mut relay = Vec::with_capacity(body.len() + 4);
        relay.push(10);
        relay.push(op);
        relay.extend_from_slice(&sender.to_le_bytes());
        relay.extend_from_slice(body);
        for target in targets {
            self.send_reliable(target, EVENTS_CHANNEL, &relay)?;
        }
        Ok(())
    }

    fn handle_net_id(&mut self, from: SocketAddr, payload: &[u8]) -> Result<(), String> {
        let Ok(id) = parse_net_id(payload) else {
            return Ok(());
        };
        if id.is_empty() {
            return Ok(());
        }
        let existing = self.net_ids.get(&id).copied();
        let value = match existing {
            Some(value) => value,
            None => {
                let value = self.next_net_id;
                self.next_net_id = self.next_net_id.wrapping_add(1);
                if value == 0 {
                    return Ok(());
                }
                self.net_ids.insert(id.clone(), value);
                value
            }
        };
        let message = build_net_id(&id, value);
        if existing.is_none() {
            let targets: Vec<SocketAddr> = self
                .peers
                .values()
                .filter(|peer| peer.authenticated)
                .map(|peer| peer.endpoint)
                .collect();
            for target in targets {
                self.send_reliable(target, NET_ID_ASSIGN_CHANNEL, &message)?;
            }
        } else {
            self.send_reliable(from, NET_ID_ASSIGN_CHANNEL, &message)?;
        }
        Ok(())
    }

    fn relay_avatar_data(&mut self, from: SocketAddr, avatar: &AvatarData) -> Result<(), String> {
        let sender = self.peers.get(&from).ok_or("peer vanished")?.id;
        let relay = build_server_avatar_data(sender, avatar);
        let targets: Vec<SocketAddr> = self
            .peers
            .values()
            .filter(|peer| peer.authenticated && peer.endpoint != from)
            .filter(|peer| avatar.recipients.is_empty() || avatar.recipients.contains(&peer.id))
            .map(|peer| peer.endpoint)
            .collect();
        for target in targets {
            self.send_reliable(target, AVATAR_CHANNEL, &relay)?;
        }
        Ok(())
    }

    fn relay_delta(&mut self, from: SocketAddr, payload: &[u8]) -> Result<(), String> {
        let sender = self.peers[&from].id;
        let sender_position = self.peers[&from].position;
        let Some(relay) = build_delta_relay(sender, payload) else {
            return Ok(());
        };
        let reduction = self.config.avatar_reduction;
        let high_distance = self.config.high_quality_distance;
        let medium_distance = self.config.medium_quality_distance;
        let low_distance = self.config.low_quality_distance;
        let targets: Vec<SocketAddr> = self
            .peers
            .values()
            .filter(|p| {
                p.endpoint != from && p.authenticated && !self.p2p.is_offloaded(sender, p.id)
            })
            .filter(|p| {
                if !reduction || self.full_quality_bypass.contains(&p.id) {
                    return true;
                }
                match (sender_position, p.position) {
                    (Some(a), Some(b)) => {
                        quality_for_distance(
                            distance(a, b),
                            high_distance,
                            medium_distance,
                            low_distance,
                        ) == AvatarQuality::High
                    }
                    _ => true,
                }
            })
            .map(|p| p.endpoint)
            .collect();
        for target in targets {
            if self.bundle_compression {
                self.bundle_queue
                    .push(target, DELTA_AVATAR_CHANNEL, relay.clone());
            } else {
                self.send_unreliable(target, DELTA_AVATAR_CHANNEL, &relay)?;
            }
        }
        Ok(())
    }

    fn handle_voice_recipients(
        &mut self,
        from: SocketAddr,
        payload: &[u8],
        large: bool,
        inverted: bool,
    ) -> Result<(), String> {
        let mut r = Reader::new(payload);
        let count = if large {
            r.get_u16().map_err(|e| e.to_string())? as usize
        } else {
            r.get_u8().map_err(|e| e.to_string())? as usize
        };
        if count > r.remaining() / 2 {
            return Ok(());
        }
        let mut listed = Vec::with_capacity(count);
        for _ in 0..count {
            listed.push(r.get_u16().map_err(|e| e.to_string())?);
        }
        let recipients = if inverted {
            let sender = self.peers.get(&from).ok_or("peer vanished")?.id;
            self.peers
                .values()
                .filter(|peer| {
                    peer.authenticated && peer.id != sender && !listed.contains(&peer.id)
                })
                .map(|peer| peer.id)
                .collect()
        } else {
            listed
        };
        if let Some(peer) = self.peers.get_mut(&from) {
            peer.voice_recipients = Some(recipients);
        }
        Ok(())
    }

    fn handle_voice_bitfield(&mut self, from: SocketAddr, payload: &[u8]) -> Result<(), String> {
        let mut r = Reader::new(payload);
        let byte_count = r.get_u16().map_err(|e| e.to_string())? as usize;
        if byte_count > r.remaining() {
            return Ok(());
        }
        let bytes = r.get_bytes(byte_count).map_err(|e| e.to_string())?;
        let mut recipients = Vec::new();
        for (byte_index, byte) in bytes.iter().enumerate() {
            for bit in 0..8 {
                if byte & (1 << bit) != 0 {
                    recipients.push((byte_index * 8 + bit) as u16);
                }
            }
        }
        if let Some(peer) = self.peers.get_mut(&from) {
            peer.voice_recipients = Some(recipients);
        }
        Ok(())
    }

    fn handle_announce_voice(&mut self, from: SocketAddr, payload: &[u8]) -> Result<(), String> {
        let (sender, did) = {
            let peer = self.peers.get(&from).ok_or("peer vanished")?;
            (peer.id, peer.did.clone())
        };
        if !self.announce_mode.contains(&sender) {
            return Ok(());
        }
        if self.locks.voice_chat
            && !self
                .permissions
                .effective(&did)
                .has(basis_permissions::NODE_VOICE_LOCK_BYPASS)
        {
            return Ok(());
        }
        if self.mutes.is_voice_muted(&did) {
            return Ok(());
        }
        let Ok((seq, silence, frame)) = parse_voice(payload) else {
            return Ok(());
        };
        let relay = build_server_voice(sender, seq, silence, &frame);
        let targets: Vec<SocketAddr> = self
            .peers
            .values()
            .filter(|peer| peer.authenticated && peer.endpoint != from)
            .map(|peer| peer.endpoint)
            .collect();
        for target in targets {
            self.send_unreliable(target, ANNOUNCE_VOICE_CHANNEL, &relay)?;
        }
        Ok(())
    }

    fn relay_voice(
        &mut self,
        from: SocketAddr,
        seq: u8,
        silence: u8,
        frame: &[u8],
    ) -> Result<(), String> {
        let sender = self.peers[&from].id;
        let recipients = self.peers[&from].voice_recipients.clone();
        let relay = build_server_voice(sender, seq, silence, frame);
        let targets: Vec<SocketAddr> = self
            .peers
            .values()
            .filter(|p| {
                p.endpoint != from
                    && p.authenticated
                    && !self.p2p.is_offloaded(sender, p.id)
                    && recipients.as_ref().is_none_or(|ids| ids.contains(&p.id))
            })
            .map(|p| p.endpoint)
            .collect();
        for target in targets {
            self.send_unreliable(target, VOICE_CHANNEL, &relay)?;
        }
        Ok(())
    }

    fn relay_chat(&mut self, from: SocketAddr, text: &str, sound: bool) -> Result<(), String> {
        let sender = self.peers[&from].id;
        let chat_did = self.peers[&from].did.clone();
        if self.mutes.is_text_muted(&chat_did) {
            debug!("dropping text chat from {chat_did}: muted");
            return Ok(());
        }
        if self.locks.text_chat {
            let did = chat_did.clone();
            if !self
                .permissions
                .effective(&did)
                .has(basis_permissions::NODE_CHAT_LOCK_BYPASS)
            {
                debug!("dropping text chat from {did}: global text chat lock");
                return Ok(());
            }
        }
        let text = if self.config.has_file_support {
            basis_protocol::wordfilter::filter(text, &self.blocked_words)
        } else {
            text.to_string()
        };
        let relay = build_server_chat(sender, &text, sound);
        let targets: Vec<SocketAddr> = self
            .peers
            .values()
            .filter(|p| p.endpoint != from && p.authenticated)
            .map(|p| p.endpoint)
            .collect();
        debug!(
            "relay chat from {sender} to {} peer(s): {text}",
            targets.len()
        );
        for target in targets {
            self.send_reliable(target, CHAT_CHANNEL, &relay)?;
        }
        Ok(())
    }

    fn handle_ping(&mut self, addr: SocketAddr, data: &[u8]) -> Result<(), String> {
        if data.len() < 3 {
            return Ok(());
        }
        // SAFETY: the Ping header is 3 bytes and was checked above.
        let seq = unsafe { fast::read_u16_le_unchecked(data, 1) };
        let conn = self.peers[&addr].connection_num;
        let mut pkt = vec![0u8; 11];
        pkt[0] = PROP_PONG | (conn << 5);
        pkt[1..3].copy_from_slice(&seq.to_le_bytes());
        let ticks = Self::now_ticks() as u64;
        pkt[3..11].copy_from_slice(&ticks.to_le_bytes());
        self.send_raw(&pkt, addr)?;
        Ok(())
    }

    fn handle_compact_merged(&mut self, addr: SocketAddr, data: &[u8]) -> Result<(), String> {
        let mut pos = 1usize;
        while pos < data.len() {
            let tag = data[pos];
            pos += 1;
            let is_raw = tag & 0x40 != 0;
            let is_long = tag & 0x80 != 0;
            let channel = tag & 0x3F;
            let len = if is_long {
                if pos + 2 > data.len() {
                    break;
                }
                let v = u16::from_le_bytes([data[pos], data[pos + 1]]) as usize;
                pos += 2;
                v
            } else {
                if pos >= data.len() {
                    break;
                }
                let v = data[pos] as usize;
                pos += 1;
                v
            };
            if pos + len > data.len() {
                break;
            }
            let payload = &data[pos..pos + len];
            pos += len;
            if is_raw {
                self.handle_inner_packet(addr, payload)?;
            } else {
                self.dispatch_app(addr, channel, payload, false)?;
            }
        }
        Ok(())
    }

    fn handle_merged(&mut self, addr: SocketAddr, data: &[u8]) -> Result<(), String> {
        let mut pos = 1usize;
        while pos + 2 <= data.len() {
            let len = u16::from_le_bytes([data[pos], data[pos + 1]]) as usize;
            pos += 2;
            if len == 0 || pos + len > data.len() {
                break;
            }
            let payload = &data[pos..pos + len];
            pos += len;
            self.handle_inner_packet(addr, payload)?;
        }
        Ok(())
    }

    fn handle_inner_packet(&mut self, addr: SocketAddr, data: &[u8]) -> Result<(), String> {
        if data.is_empty() {
            return Ok(());
        }
        let unconnected = data.len() >= 2 && (data[0] & 0x1F) == 8;
        let info_payload = if unconnected { &data[1..] } else { data };
        if info_payload.len() >= 8
            && u32::from_le_bytes([
                info_payload[0],
                info_payload[1],
                info_payload[2],
                info_payload[3],
            ]) == SERVER_INFO_QUERY_MAGIC
        {
            return self.handle_server_info(info_payload, unconnected, addr);
        }
        let property = data[0] & 0x1F;
        match property {
            PROP_CHANNELED => self.handle_channeled(addr, data),
            PROP_UNRELIABLE => {
                if data.len() < 2 {
                    return Ok(());
                }
                let channel = data[1];
                self.dispatch_app(addr, channel, &data[2..], false)
            }
            PROP_ACK => Ok(()),
            _ => Ok(()),
        }
    }

    fn send_raw(&self, data: &[u8], addr: SocketAddr) -> Result<(), String> {
        self.socket.send_to(data, addr).map_err(|e| e.to_string())?;
        self.stats.tx_packets.fetch_add(1, Ordering::Relaxed);
        self.stats
            .tx_bytes
            .fetch_add(data.len() as u64, Ordering::Relaxed);
        Ok(())
    }

    fn send_connect_accept(
        &self,
        addr: SocketAddr,
        connect_time: i64,
        conn: u8,
        peer_id: u16,
    ) -> Result<(), String> {
        let mut pkt = vec![0u8; 15];
        pkt[0] = PROP_CONNECT_ACCEPT | (conn << 5);
        pkt[1..9].copy_from_slice(&connect_time.to_le_bytes());
        pkt[9] = conn;
        pkt[10] = 0;
        pkt[11..15].copy_from_slice(&(peer_id as i32).to_le_bytes());
        self.send_raw(&pkt, addr)?;
        Ok(())
    }

    fn send_peer_not_found(&self, addr: SocketAddr) -> Result<(), String> {
        let mut pkt = vec![0u8; 15];
        pkt[0] = PROP_PEER_NOT_FOUND;
        let _ = self.send_raw(&pkt, addr);
        Ok(())
    }

    fn send_disconnect(
        &self,
        addr: SocketAddr,
        conn: u8,
        connect_time: i64,
        reason: &str,
    ) -> Result<(), String> {
        let mut payload = Writer::new();
        payload.put_string(reason);
        self.send_disconnect_payload(addr, conn, connect_time, payload.as_slice())
    }

    fn send_structured_reject(
        &self,
        addr: SocketAddr,
        conn: u8,
        connect_time: i64,
        kind: u8,
        aux: (u16, u16),
        message: &str,
    ) -> Result<(), String> {
        let mut payload = Writer::new();
        payload.put_u32(0xBA51_5CE1);
        payload.put_u8(kind);
        payload.put_u16(aux.0);
        payload.put_u16(aux.1);
        payload.put_string(message);
        self.send_disconnect_payload(addr, conn, connect_time, payload.as_slice())
    }

    fn send_disconnect_payload(
        &self,
        addr: SocketAddr,
        conn: u8,
        connect_time: i64,
        payload: &[u8],
    ) -> Result<(), String> {
        let mut w = Writer::new();
        w.put_u8(PROP_DISCONNECT | (conn << 5));
        w.put_i64(connect_time);
        w.put_bytes(payload);
        let _ = self.send_raw(w.as_slice(), addr);
        Ok(())
    }

    fn handle_ack(&mut self, addr: SocketAddr, data: &[u8]) -> Result<(), String> {
        if data.len() < 4 {
            return Ok(());
        }
        let window_start = u16::from_le_bytes([data[1], data[2]]);
        let channel = data[3];
        let bits = &data[4..];
        let Some(peer) = self.peers.get_mut(&addr) else {
            return Ok(());
        };
        peer.reliable.retain(|pending| {
            if pending.channel != channel {
                return true;
            }
            let offset = pending.seq.wrapping_sub(window_start) as usize;
            let acked = offset / 8 < bits.len() && bits[offset / 8] & (1 << (offset % 8)) != 0;
            !acked
        });
        Ok(())
    }

    fn sweep_reliable(&mut self) {
        let now = Instant::now();
        let mut resends = Vec::new();
        let mut resend_count = 0u64;
        let mut exhausted = 0u64;
        for peer in self.peers.values_mut() {
            let addr = peer.endpoint;
            peer.reliable.retain_mut(|pending| {
                if now.duration_since(pending.sent) < Duration::from_millis(100) {
                    return true;
                }
                if pending.attempts >= 5 {
                    exhausted = exhausted.saturating_add(1);
                    return false;
                }
                pending.attempts += 1;
                pending.sent = now;
                resend_count = resend_count.saturating_add(1);
                resends.push((pending.packet.clone(), addr));
                true
            });
        }
        for (packet, addr) in resends {
            if self.send_raw(&packet, addr).is_err() {
                self.telemetry.record_send_failure();
            }
        }
        if resend_count + exhausted > 0 {
            self.telemetry.record_reliable(resend_count, exhausted);
        }
    }

    fn send_ack(&self, addr: SocketAddr, seq: u16, channel_id: u8) -> Result<(), String> {
        let conn = self.peers[&addr].connection_num;
        // 4-byte header + 17-byte ack bitset, matching LiteNetLib's 128-packet window.
        let mut pkt = vec![0u8; 21];
        pkt[0] = PROP_ACK | (conn << 5);
        // Cumulative ack from the start of the window. The C# reliable channel advances its
        // window one packet at a time, so setting every bit through seq clears the run.
        pkt[1..3].copy_from_slice(&0u16.to_le_bytes());
        pkt[3] = channel_id;
        let last = seq.min(127) as usize;
        for idx in 0..=last {
            pkt[4 + idx / 8] |= 1 << (idx % 8);
        }
        self.send_raw(&pkt, addr)?;
        Ok(())
    }

    fn send_unreliable(&self, addr: SocketAddr, channel: u8, payload: &[u8]) -> Result<(), String> {
        let conn = self.peers[&addr].connection_num;
        let mut pkt = Vec::with_capacity(payload.len() + 2);
        pkt.push(PROP_UNRELIABLE | (conn << 5));
        pkt.push(channel);
        pkt.extend_from_slice(payload);
        self.send_raw(&pkt, addr)?;
        Ok(())
    }

    fn send_reliable(
        &mut self,
        addr: SocketAddr,
        channel: u8,
        payload: &[u8],
    ) -> Result<(), String> {
        self.send_ordered(addr, channel, payload, 2) // ReliableOrdered
    }

    fn send_sequenced(
        &mut self,
        addr: SocketAddr,
        channel: u8,
        payload: &[u8],
    ) -> Result<(), String> {
        self.send_ordered(addr, channel, payload, 3) // ReliableSequenced
    }

    fn send_ordered(
        &mut self,
        addr: SocketAddr,
        channel: u8,
        payload: &[u8],
        ordering: u8,
    ) -> Result<(), String> {
        let conn = self.peers[&addr].connection_num;
        let channel_id = channel * 4 + ordering;
        let mtu = DEFAULT_MTU;
        let max_payload = mtu.saturating_sub(CHANNELED_HEADER);

        if payload.len() + CHANNELED_HEADER <= mtu {
            let seq = self
                .peers
                .get_mut(&addr)
                .ok_or("peer vanished")?
                .next_out_seq(channel_id);
            let mut pkt = Vec::with_capacity(payload.len() + CHANNELED_HEADER);
            pkt.push(PROP_CHANNELED | (conn << 5));
            pkt.extend_from_slice(&seq.to_le_bytes());
            pkt.push(channel_id);
            pkt.extend_from_slice(payload);
            self.send_raw(&pkt, addr)?;
            if let Some(peer) = self.peers.get_mut(&addr) {
                peer.reliable.push(PendingReliable {
                    seq,
                    channel: channel_id,
                    packet: pkt,
                    sent: Instant::now(),
                    attempts: 0,
                });
            }
            return Ok(());
        }

        let frag_payload = max_payload.saturating_sub(FRAGMENT_HEADER);
        if frag_payload == 0 {
            return Err("mtu too small".into());
        }
        let total = payload.len().div_ceil(frag_payload) as u16;
        let frag_id = {
            let peer = self.peers.get_mut(&addr).ok_or("peer vanished")?;
            let id = peer.next_fragment_id;
            peer.next_fragment_id = peer.next_fragment_id.wrapping_add(1);
            id
        };
        for part in 0..total {
            let start = part as usize * frag_payload;
            let end = (start + frag_payload).min(payload.len());
            let seq = self
                .peers
                .get_mut(&addr)
                .ok_or("peer vanished")?
                .next_out_seq(channel_id);
            let mut pkt = Vec::with_capacity(CHANNELED_HEADER + FRAGMENT_HEADER + (end - start));
            pkt.push(PROP_CHANNELED | (conn << 5) | 0x80);
            pkt.extend_from_slice(&seq.to_le_bytes());
            pkt.push(channel_id);
            pkt.extend_from_slice(&frag_id.to_le_bytes());
            pkt.extend_from_slice(&part.to_le_bytes());
            pkt.extend_from_slice(&total.to_le_bytes());
            pkt.extend_from_slice(&payload[start..end]);
            self.send_raw(&pkt, addr)?;
            if let Some(peer) = self.peers.get_mut(&addr) {
                peer.reliable.push(PendingReliable {
                    seq,
                    channel: channel_id,
                    packet: pkt,
                    sent: Instant::now(),
                    attempts: 0,
                });
            }
        }
        Ok(())
    }
}

fn build_log_container() -> (Vec<u8>, usize) {
    let mut files = Vec::new();
    collect_log_files("logs", "logs", &mut files);
    collect_log_files("CrashReports", "CrashReports", &mut files);
    let mut raw = Vec::new();
    raw.extend_from_slice(&(files.len() as i32).to_le_bytes());
    for (name, bytes) in &files {
        write_7bit_string(&mut raw, name);
        raw.extend_from_slice(&(bytes.len() as i32).to_le_bytes());
        raw.extend_from_slice(bytes);
    }
    (raw, files.len())
}

fn collect_log_files(root: &str, prefix: &str, out: &mut Vec<(String, Vec<u8>)>) {
    collect_log_files_from(root, root, prefix, out);
}

fn collect_log_files_from(
    base: &str,
    current: &str,
    prefix: &str,
    out: &mut Vec<(String, Vec<u8>)>,
) {
    let Ok(entries) = std::fs::read_dir(current) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_log_files_from(base, &path.to_string_lossy(), prefix, out);
            continue;
        }
        let Ok(bytes) = std::fs::read(&path) else {
            continue;
        };
        let relative = path
            .strip_prefix(base)
            .unwrap_or(&path)
            .to_string_lossy()
            .replace('\\', "/");
        out.push((format!("{prefix}/{relative}"), bytes));
    }
}

fn write_7bit_string(out: &mut Vec<u8>, value: &str) {
    let mut length = value.len();
    loop {
        let mut byte = (length & 0x7F) as u8;
        length >>= 7;
        if length != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if length == 0 {
            break;
        }
    }
    out.extend_from_slice(value.as_bytes());
}

fn delete_directory_files(root: &str) -> usize {
    let mut deleted = 0;
    let Ok(entries) = std::fs::read_dir(root) else {
        return 0;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            deleted += delete_directory_files(&path.to_string_lossy());
        } else if std::fs::remove_file(&path).is_ok() {
            deleted += 1;
        }
    }
    deleted
}

pub fn run(config: ServerConfig) -> io::Result<()> {
    let mut server = Server::bind(config)?;
    server.run()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admins_xml_parses_string_array() {
        let parsed = parse_admins_xml(
            "<ArrayOfString><string>did:key:one</string><string> did:key:two </string></ArrayOfString>",
        );
        assert!(parsed.contains("did:key:one"));
        assert!(parsed.contains("did:key:two"));
        assert_eq!(parsed.len(), 2);
    }

    #[test]
    fn crash_report_json_escapes_control_and_quotes() {
        assert_eq!(
            json_escape("quote\" slash\\ newline\n"),
            "quote\\\" slash\\\\ newline\\n"
        );
        assert_eq!(json_escape("\u{1}"), "\\u0001");
    }

    #[test]
    fn server_info_query_response_matches_csharp_layout() {
        let config = ServerConfig {
            port: 0,
            health_port: 0,
            server_name: "Basis Server".into(),
            server_motd: "hello".into(),
            control_socket: false,
            ..ServerConfig::default()
        };
        let mut server = Server::bind(config).unwrap();
        let client = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let addr = client.local_addr().unwrap();
        let mut query = vec![0u8; SERVER_INFO_MIN_REQUEST_BYTES];
        query[..4].copy_from_slice(&SERVER_INFO_QUERY_MAGIC.to_le_bytes());
        query[4..6].copy_from_slice(&SERVER_INFO_PROTOCOL_VERSION.to_le_bytes());
        query[6..8].copy_from_slice(&0x1234u16.to_le_bytes());
        server.handle_datagram(&query, addr).unwrap();
        let mut buf = [0u8; 512];
        let (len, _) = client.recv_from(&mut buf).unwrap();
        assert_eq!(
            u32::from_le_bytes(buf[0..4].try_into().unwrap()),
            SERVER_INFO_RESPONSE_MAGIC
        );
        assert_eq!(u16::from_le_bytes(buf[4..6].try_into().unwrap()), 1);
        assert_eq!(u16::from_le_bytes(buf[6..8].try_into().unwrap()), 0x1234);
        assert_eq!(u16::from_le_bytes(buf[8..10].try_into().unwrap()), 0);
        assert_eq!(u16::from_le_bytes(buf[10..12].try_into().unwrap()), 65535);
        assert!(len > 12);
        std::thread::sleep(Duration::from_millis(600));

        let mut wrapped = vec![0u8; SERVER_INFO_MIN_REQUEST_BYTES + 1];
        wrapped[0] = 8;
        wrapped[1..5].copy_from_slice(&SERVER_INFO_QUERY_MAGIC.to_le_bytes());
        wrapped[5..7].copy_from_slice(&SERVER_INFO_PROTOCOL_VERSION.to_le_bytes());
        wrapped[7..9].copy_from_slice(&0x5678u16.to_le_bytes());
        server.handle_datagram(&wrapped, addr).unwrap();
        let mut buf2 = [0u8; 512];
        let (len2, _) = client.recv_from(&mut buf2).unwrap();
        assert_eq!(buf2[0] & 0x1F, 8);
        assert_eq!(
            u32::from_le_bytes(buf2[1..5].try_into().unwrap()),
            SERVER_INFO_RESPONSE_MAGIC
        );
        assert_eq!(u16::from_le_bytes(buf2[7..9].try_into().unwrap()), 0x5678);
        assert!(len2 > 13);
    }

    #[test]
    fn info_query_bucket_refills_at_csharp_rate_and_caps() {
        let now = Instant::now();
        assert_eq!(
            refill_info_tokens(0.0, now, now + Duration::from_secs(1)),
            100.0
        );
        assert_eq!(
            refill_info_tokens(150.0, now, now + Duration::from_secs(1)),
            200.0
        );
        assert_eq!(
            refill_info_tokens(10.0, now, now + Duration::from_secs(10)),
            200.0
        );
    }

    #[test]
    fn auth_timeout_scales_with_population_like_csharp() {
        assert_eq!(auth_timeout_ms(9000, 0), 9000);
        assert_eq!(auth_timeout_ms(9000, 1), 9012);
        assert_eq!(auth_timeout_ms(9000, 1000), 21_000);
        assert_eq!(auth_timeout_ms(9000, 10_000), 54_000);
        assert_eq!(auth_timeout_ms(1, 1), 13);
    }

    #[test]
    fn chat_token_bucket_allows_csharp_burst_then_drops() {
        let mut bucket = TokenBucket::new(0.0, 6.0);
        for _ in 0..6 {
            assert!(bucket.try_consume());
        }
        assert!(!bucket.try_consume());

        let mut typing = TokenBucket::new(0.0, 8.0);
        for _ in 0..8 {
            assert!(typing.try_consume());
        }
        assert!(!typing.try_consume());

        let mut jiggle = TokenBucket::new(0.0, 16.0);
        for _ in 0..16 {
            assert!(jiggle.try_consume());
        }
        assert!(!jiggle.try_consume());
    }

    #[test]
    fn connect_accept_matches_observed_header() {
        // The reference C# server's accept for connect time 0x08df31070e8b025a is
        // 06 5a028b0e0731df08 00 00 00000000.
        let connect_time = i64::from_le_bytes([0x5a, 0x02, 0x8b, 0x0e, 0x07, 0x31, 0xdf, 0x08]);
        let mut pkt = vec![0u8; 15];
        pkt[0] = PROP_CONNECT_ACCEPT;
        pkt[1..9].copy_from_slice(&connect_time.to_le_bytes());
        pkt[9] = 0;
        pkt[10] = 0;
        pkt[11..15].copy_from_slice(&0i32.to_le_bytes());
        assert_eq!(hex::encode(&pkt), "065a028b0e0731df08000000000000");
    }

    #[test]
    fn permissions_load_next_to_config_and_receive_csharp_defaults() {
        let dir = std::env::temp_dir().join(format!(
            "basis-transport-permissions-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let config_path = dir.join("config.xml");
        let permissions_path = dir.join("permissions.xml");
        std::fs::write(
            &permissions_path,
            r#"<?xml version="1.0" encoding="utf-8"?>
<Permissions>
  <Groups>
    <Group name="admin"><Parent name="default" /></Group>
  </Groups>
  <Users>
    <User uuid="did:key:admin"><Group name="admin" /></User>
  </Users>
</Permissions>"#,
        )
        .unwrap();

        let config = ServerConfig {
            config_path: config_path.display().to_string(),
            ..ServerConfig::default()
        };
        let (store, loaded_from) = load_permissions(&config);
        assert_eq!(loaded_from, permissions_path);

        let admin = store.effective("did:key:admin");
        assert!(admin.has(basis_permissions::NODE_ALL));
        assert!(admin.has("basis.resource.load.world"));
        assert!(admin.has("basis.resource.load.prop"));

        let regular = store.effective("did:key:regular");
        assert!(!regular.has(basis_permissions::NODE_ALL));
        assert!(regular.has("basis.resource.load.world"));
        assert!(regular.has("basis.resource.load.prop"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_and_unload_are_echoed_to_the_requesting_peer() {
        // C# broadcasts resource messages to PeerSnapshot, which includes the creator.
        // BasisNetworkSpawnItem only sends the request; the client spawns from the echo.
        let config = ServerConfig {
            port: 0,
            health_port: 0,
            control_socket: false,
            has_file_support: false,
            ..ServerConfig::default()
        };
        let mut server = Server::bind(config).unwrap();
        let client = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let addr = client.local_addr().unwrap();

        let mut peer = Peer::new(addr, 1, 0, 0, -1);
        peer.authenticated = true;
        peer.did = "did:key:admin".into();
        server.peers.insert(addr, peer);
        server
            .permissions
            .add_user_to_group("did:key:admin", "admin");

        let load = build_load_resource(&WorldResource {
            net_id: "echo-test".into(),
            url: "https://example.invalid/world.bee".into(),
            password: "pw".into(),
            persistent: false,
            strategy: 0,
        });
        server.handle_load_resource(addr, &load).unwrap();

        let mut buf = [0u8; 512];
        let (len, _) = client.recv_from(&mut buf).unwrap();
        assert!(len > CHANNELED_HEADER, "expected an echoed load packet");
        assert_eq!(buf[3], LOAD_RESOURCE_CHANNEL * 4 + 2);
        assert_eq!(buf[4], 1, "mode-1 world payload");

        let unload = build_unload_resource("echo-test");
        server.handle_unload_resource(addr, &unload).unwrap();
        let (len, _) = client.recv_from(&mut buf).unwrap();
        assert!(len > CHANNELED_HEADER, "expected an echoed unload packet");
        assert_eq!(buf[3], UNLOAD_RESOURCE_CHANNEL * 4 + 2);
        assert_eq!(buf[4], 1, "mode-1 world unload");
    }
}
