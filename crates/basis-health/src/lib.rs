//! Health endpoint and shared transport counters.
//!
//! The transport owns the socket; this crate owns the HTTP surface and the counters it reads.

use chrono::{DateTime, Utc};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

#[derive(Default)]
pub struct HealthStats {
    pub rx_packets: AtomicU64,
    pub tx_packets: AtomicU64,
    pub rx_bytes: AtomicU64,
    pub tx_bytes: AtomicU64,
    pub start_time: Option<DateTime<Utc>>,
}

impl HealthStats {
    pub fn new() -> Self {
        Self {
            start_time: Some(Utc::now()),
            ..Self::default()
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct PlayerSnapshot {
    pub net_id: u16,
    pub uuid: String,
    pub display_name: String,
    pub platform: String,
    pub position: [f32; 3],
}

pub type Players = Arc<Mutex<Vec<PlayerSnapshot>>>;

#[derive(Clone, Debug, Default)]
pub struct WorldSnapshot {
    pub net_id: String,
    pub url: String,
    pub persistent: bool,
    pub admin_locked: bool,
    pub strategy: u8,
}

pub type Worlds = Arc<Mutex<Vec<WorldSnapshot>>>;

#[derive(Clone, Debug)]
pub enum WorldCommand {
    Load {
        net_id: String,
        url: String,
        password: String,
        persistent: bool,
        strategy: u8,
    },
    Unload {
        net_id: String,
    },
    Clear,
    Announce {
        target: Option<String>,
        message: String,
    },
    Switch {
        net_id: String,
        url: String,
        password: String,
        persistent: bool,
        strategy: u8,
        announce: String,
        delay_seconds: u32,
    },
}

pub type WorldCommands = Arc<Mutex<Vec<WorldCommand>>>;

#[derive(Clone)]
pub struct HealthConfig {
    pub host: String,
    pub port: u16,
    pub path: String,
    pub capacity: usize,
    pub enable_statistics: bool,
    pub version: String,
}

pub fn start(
    config: HealthConfig,
    stats: Arc<HealthStats>,
    visitors: Arc<AtomicUsize>,
    players: Players,
    worlds: Worlds,
    world_commands: WorldCommands,
) {
    use std::net::TcpListener;
    if config.port == 0 {
        return;
    }
    let listener = match TcpListener::bind((config.host.as_str(), config.port)) {
        Ok(listener) => listener,
        Err(e) => {
            basis_logging::error!(
                "HTTP health check disabled: could not listen on 'http://{}:{}/' ({e})",
                config.host,
                config.port
            );
            return;
        }
    };
    basis_logging::info!(
        "HTTP health check started at 'http://{}:{}{}'",
        config.host,
        config.port,
        config.path
    );
    std::thread::spawn(move || {
        serve(
            listener,
            config,
            stats,
            visitors,
            players,
            worlds,
            world_commands,
        )
    });
}

fn json_escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}
struct ActiveGuard(Arc<AtomicUsize>);

impl Drop for ActiveGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

fn write_http(stream: &mut impl std::io::Write, status: u16, body: &str) {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        405 => "Method Not Allowed",
        413 => "Payload Too Large",
        _ => "Internal Server Error",
    };
    let _ = write!(
        stream,
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json; charset=utf-8\r\nCache-Control: no-store, max-age=0\r\nX-Content-Type-Options: nosniff\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
}

fn write_method_not_allowed(stream: &mut impl std::io::Write, allow: &str) {
    let _ = write!(
        stream,
        "HTTP/1.1 405 Method Not Allowed\r\nAllow: {allow}\r\nContent-Type: application/json; charset=utf-8\r\nCache-Control: no-store, max-age=0\r\nX-Content-Type-Options: nosniff\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    );
}

fn json_body_is_valid(body: &str) -> bool {
    let body = body.trim();
    if !body.starts_with('{') || !body.ends_with('}') {
        return false;
    }
    let mut depth = 0i32;
    let mut in_string = false;
    let mut escaped = false;
    for c in body.chars() {
        if in_string {
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                in_string = false;
            }
            continue;
        }
        match c {
            '"' => in_string = true,
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth < 0 {
                    return false;
                }
            }
            _ => {}
        }
    }
    depth == 0 && !in_string
}

fn split_url_fragment(raw: &str) -> (String, Option<String>) {
    let raw = raw.trim();
    if let Some((url, fragment)) = raw.split_once('#') {
        return (url.to_string(), non_empty(fragment).map(decode_fragment));
    }
    if let Some(idx) = raw.to_ascii_lowercase().find("%23") {
        return (
            raw[..idx].to_string(),
            non_empty(&raw[idx + 3..]).map(decode_fragment),
        );
    }
    (raw.to_string(), None)
}

fn decode_fragment(fragment: String) -> String {
    let Some(bytes) = base64_decode(&fragment) else {
        return fragment;
    };
    String::from_utf8(bytes).unwrap_or(fragment)
}

fn base64_decode(input: &str) -> Option<Vec<u8>> {
    if !input.len().is_multiple_of(4) {
        return None;
    }
    let mut out = Vec::with_capacity(input.len() / 4 * 3);
    for chunk in input.as_bytes().chunks(4) {
        let mut values = [0u8; 4];
        let mut padding = 0;
        for (index, &byte) in chunk.iter().enumerate() {
            values[index] = match byte {
                b'A'..=b'Z' => byte - b'A',
                b'a'..=b'z' => byte - b'a' + 26,
                b'0'..=b'9' => byte - b'0' + 52,
                b'+' => 62,
                b'/' => 63,
                b'=' => {
                    padding += 1;
                    0
                }
                _ => return None,
            };
        }
        out.push((values[0] << 2) | (values[1] >> 4));
        if padding < 2 {
            out.push((values[1] << 4) | (values[2] >> 2));
        }
        if padding == 0 {
            out.push((values[2] << 6) | values[3]);
        }
    }
    Some(out)
}

fn non_empty(value: &str) -> Option<String> {
    (!value.is_empty()).then(|| value.to_string())
}

fn json_key_present(body: &str, key: &str) -> bool {
    body.contains(&format!("\"{key}\""))
}

fn json_key_is_null(body: &str, key: &str) -> bool {
    let marker = format!("\"{key}\"");
    let Some(start) = body.find(&marker) else {
        return false;
    };
    let rest = body[start + marker.len()..].trim_start();
    let rest = rest.strip_prefix(':').map(str::trim_start).unwrap_or(rest);
    rest.starts_with("null")
}

fn json_string(body: &str, key: &str) -> Option<String> {
    let marker = format!("\"{key}\"");
    let start = body.find(&marker)? + marker.len();
    let rest = body[start..].trim_start();
    let rest = rest.strip_prefix(':')?.trim_start();
    let rest = rest.strip_prefix('"')?;
    let end = rest.find('"')?;
    Some(rest[..end].replace("\\\"", "\"").replace("\\\\", "\\"))
}

fn json_u32(body: &str, key: &str) -> Option<u32> {
    let marker = format!("\"{key}\"");
    let start = body.find(&marker)? + marker.len();
    let rest = body[start..].trim_start();
    let rest = rest.strip_prefix(':')?.trim_start();
    let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
    digits.parse().ok()
}

fn json_bool(body: &str, key: &str) -> Option<bool> {
    let marker = format!("\"{key}\"");
    let start = body.find(&marker)? + marker.len();
    let rest = body[start..].trim_start();
    let rest = rest.strip_prefix(':')?.trim_start();
    Some(rest.starts_with("true"))
}

fn serve(
    listener: std::net::TcpListener,
    config: HealthConfig,
    stats: Arc<HealthStats>,
    visitors: Arc<AtomicUsize>,
    players: Players,
    worlds: Worlds,
    world_commands: WorldCommands,
) {
    use std::io::{Read, Write};
    const MAX_CONCURRENT_REQUESTS: usize = 32;
    let active = Arc::new(AtomicUsize::new(0));
    let world_seq = Arc::new(AtomicU64::new(0));
    for stream in listener.incoming() {
        let Ok(mut stream) = stream else { continue };
        if active.fetch_add(1, Ordering::Relaxed) >= MAX_CONCURRENT_REQUESTS {
            active.fetch_sub(1, Ordering::Relaxed);
            let _ = write!(
                stream,
                "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            );
            continue;
        }
        let guard = ActiveGuard(Arc::clone(&active));
        let path = config.path.clone();
        let stats = Arc::clone(&stats);
        let visitors = Arc::clone(&visitors);
        let capacity = config.capacity;
        let enable_statistics = config.enable_statistics;
        let version = config.version.clone();
        let players = Arc::clone(&players);
        let worlds = Arc::clone(&worlds);
        let world_commands = Arc::clone(&world_commands);
        let world_seq = Arc::clone(&world_seq);
        std::thread::spawn(move || {
            let _guard = guard;
            const MAX_BODY_BYTES: usize = 1 << 20;
            let mut buf = [0u8; 2048];
            let mut request_bytes = Vec::new();
            loop {
                let Ok(n) = stream.read(&mut buf) else { return };
                if n == 0 {
                    break;
                }
                request_bytes.extend_from_slice(&buf[..n]);
                if let Some(header_end) = request_bytes.windows(4).position(|w| w == b"\r\n\r\n") {
                    let content_length = String::from_utf8_lossy(&request_bytes[..header_end])
                        .lines()
                        .find_map(|line| {
                            let (name, value) = line.split_once(':')?;
                            name.eq_ignore_ascii_case("content-length")
                                .then(|| value.trim().parse::<usize>().ok())
                                .flatten()
                        })
                        .unwrap_or(0);
                    if content_length > MAX_BODY_BYTES {
                        write_http(&mut stream, 413, "{\"error\":\"payload too large\"}");
                        return;
                    }
                    if request_bytes.len() >= header_end + 4 + content_length {
                        break;
                    }
                }
                if request_bytes.len() > MAX_BODY_BYTES + 8192 {
                    write_http(&mut stream, 413, "{\"error\":\"payload too large\"}");
                    return;
                }
            }
            let request = String::from_utf8_lossy(&request_bytes);
            let mut parts = request.lines().next().unwrap_or("").split_whitespace();
            let method = parts.next().unwrap_or("");
            let request_path = parts.next().unwrap_or("/");
            if request_path == "/api/players" {
                if !method.eq_ignore_ascii_case("GET") {
                    write_method_not_allowed(&mut stream, "GET");
                    return;
                }
                let entries: Vec<String> = players
                    .lock()
                    .map(|list| {
                        list.iter()
                            .map(|player| {
                                format!(
                                    "{{\"netId\":{},\"uuid\":\"{}\",\"displayName\":\"{}\",\"platform\":\"{}\",\"position\":[{},{},{}]}}",
                                    player.net_id,
                                    json_escape(&player.uuid),
                                    json_escape(&player.display_name),
                                    json_escape(&player.platform),
                                    player.position[0],
                                    player.position[1],
                                    player.position[2],
                                )
                            })
                            .collect()
                    })
                    .unwrap_or_default();
                let body = format!("{{\"players\":[{}]}}", entries.join(","));
                let _ = write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=utf-8\r\nCache-Control: no-store, max-age=0\r\nX-Content-Type-Options: nosniff\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                return;
            }
            if request_path == "/api/worlds" && method.eq_ignore_ascii_case("GET") {
                let entries: Vec<String> = worlds
                    .lock()
                    .map(|list| {
                        list.iter()
                            .map(|world| {
                                format!(
                                    "{{\"netId\":\"{}\",\"url\":\"{}\",\"persistent\":{},\"adminLocked\":{},\"strategy\":{}}}",
                                    json_escape(&world.net_id),
                                    json_escape(&world.url),
                                    world.persistent,
                                    world.admin_locked,
                                    world.strategy,
                                )
                            })
                            .collect()
                    })
                    .unwrap_or_default();
                let body = format!("{{\"worlds\":[{}]}}", entries.join(","));
                let _ = write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=utf-8\r\nCache-Control: no-store, max-age=0\r\nX-Content-Type-Options: nosniff\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                return;
            }
            if request_path == "/api/worlds/switch" && method.eq_ignore_ascii_case("POST") {
                let body_text = request
                    .split_once("\r\n\r\n")
                    .map(|(_, body)| body)
                    .unwrap_or("");
                if !body_text.trim().is_empty() && !json_body_is_valid(body_text) {
                    write_http(&mut stream, 400, "{\"error\":\"invalid JSON body\"}");
                    return;
                }
                let url = json_string(body_text, "url").unwrap_or_default();
                if url.is_empty() {
                    write_http(&mut stream, 400, "{\"error\":\"missing url\"}");
                    return;
                }
                if !url.starts_with("https://") {
                    write_http(&mut stream, 400, "{\"error\":\"url must use https://\"}");
                    return;
                }
                let (url, embedded_password) = split_url_fragment(&url);
                let password = json_string(body_text, "password")
                    .or(embedded_password)
                    .filter(|value| !value.is_empty())
                    .unwrap_or_default();
                if password.is_empty() {
                    write_http(
                        &mut stream,
                        400,
                        "{\"error\":\"password required (provide password field or embed in url as #fragment)\"}",
                    );
                    return;
                }
                let persistent = json_bool(body_text, "persistent").unwrap_or(false);
                let announce = if let Some(value) = json_string(body_text, "announceMessage") {
                    if value.encode_utf16().count() > 512 {
                        write_http(
                            &mut stream,
                            400,
                            "{\"error\":\"announceMessage exceeds 512 characters\"}",
                        );
                        return;
                    }
                    value
                } else {
                    String::new()
                };
                let delay_seconds = if json_key_present(body_text, "delay")
                    && !json_key_is_null(body_text, "delay")
                {
                    match json_u32(body_text, "delay") {
                        Some(value) if value <= 300 => value,
                        _ => {
                            write_http(
                                &mut stream,
                                400,
                                "{\"error\":\"delay must be an integer 0–300 (seconds)\"}",
                            );
                            return;
                        }
                    }
                } else {
                    0
                };
                if json_key_present(body_text, "announceMessage")
                    && json_string(body_text, "announceMessage").is_none()
                {
                    write_http(
                        &mut stream,
                        400,
                        "{\"error\":\"announceMessage must be a string\"}",
                    );
                    return;
                }
                let strategy = if let Some(raw) = json_string(body_text, "strategy") {
                    match raw.as_str() {
                        "synchronized" => 2,
                        "predownload" => 3,
                        "immediate" => 0,
                        _ => {
                            write_http(&mut stream, 400, "{\"error\":\"unknown strategy\"}");
                            return;
                        }
                    }
                } else if let Some(raw) = json_u32(body_text, "strategy") {
                    if raw > 3 {
                        write_http(&mut stream, 400, "{\"error\":\"unknown strategy\"}");
                        return;
                    }
                    raw as u8
                } else {
                    0
                };
                let net_id = format!("world-{}", world_seq.fetch_add(1, Ordering::Relaxed) + 1);
                if let Ok(mut commands) = world_commands.lock() {
                    commands.push(WorldCommand::Switch {
                        net_id: net_id.clone(),
                        url,
                        password,
                        persistent,
                        strategy,
                        announce,
                        delay_seconds,
                    });
                }
                let body = format!("{{\"ok\":true,\"netId\":\"{}\"}}", json_escape(&net_id));
                write_http(&mut stream, 200, &body);
                return;
            }
            if request_path == "/api/worlds" && method.eq_ignore_ascii_case("POST") {
                let body_text = request
                    .split_once("\r\n\r\n")
                    .map(|(_, body)| body)
                    .unwrap_or("");
                if !body_text.trim().is_empty() && !json_body_is_valid(body_text) {
                    write_http(&mut stream, 400, "{\"error\":\"invalid JSON body\"}");
                    return;
                }
                let url = json_string(body_text, "url").unwrap_or_default();
                if url.is_empty() {
                    write_http(&mut stream, 400, "{\"error\":\"missing url\"}");
                    return;
                }
                if !url.starts_with("https://") {
                    write_http(&mut stream, 400, "{\"error\":\"url must use https://\"}");
                    return;
                }
                let (url, embedded_password) = split_url_fragment(&url);
                let password = json_string(body_text, "password")
                    .or(embedded_password)
                    .filter(|value| !value.is_empty())
                    .unwrap_or_default();
                if password.is_empty() {
                    write_http(
                        &mut stream,
                        400,
                        "{\"error\":\"password required (provide password field or embed in url as #fragment)\"}",
                    );
                    return;
                }
                let persistent = json_bool(body_text, "persistent").unwrap_or(false);
                let strategy = if let Some(raw) = json_string(body_text, "strategy") {
                    match raw.as_str() {
                        "synchronized" => 2,
                        "predownload" => 3,
                        "immediate" => 0,
                        _ => {
                            write_http(&mut stream, 400, "{\"error\":\"unknown strategy\"}");
                            return;
                        }
                    }
                } else if let Some(raw) = json_u32(body_text, "strategy") {
                    if raw > 3 {
                        write_http(&mut stream, 400, "{\"error\":\"unknown strategy\"}");
                        return;
                    }
                    raw as u8
                } else {
                    0
                };
                let net_id = format!("world-{}", world_seq.fetch_add(1, Ordering::Relaxed) + 1);
                if let Ok(mut commands) = world_commands.lock() {
                    commands.push(WorldCommand::Load {
                        net_id: net_id.clone(),
                        url,
                        password,
                        persistent,
                        strategy,
                    });
                }
                let body = format!("{{\"ok\":true,\"netId\":\"{}\"}}", json_escape(&net_id));
                write_http(&mut stream, 200, &body);
                return;
            }
            if (request_path == "/api/worlds" || request_path.starts_with("/api/worlds/"))
                && method.eq_ignore_ascii_case("DELETE")
            {
                let net_id = request_path.trim_start_matches("/api/worlds/").to_string();
                let clear = net_id.is_empty() || net_id == "/api/worlds";
                if clear {
                    let unloaded = worlds.lock().map(|list| list.len()).unwrap_or(0);
                    if let Ok(mut commands) = world_commands.lock() {
                        commands.push(WorldCommand::Clear);
                    }
                    let body = format!("{{\"ok\":true,\"unloaded\":{unloaded}}}");
                    write_http(&mut stream, 200, &body);
                } else {
                    let found = worlds
                        .lock()
                        .map(|list| list.iter().any(|world| world.net_id == net_id))
                        .unwrap_or(false);
                    if !found {
                        write_http(&mut stream, 404, "{\"error\":\"world not found\"}");
                        return;
                    }
                    if let Ok(mut commands) = world_commands.lock() {
                        commands.push(WorldCommand::Unload {
                            net_id: net_id.clone(),
                        });
                    }
                    write_http(&mut stream, 200, "{\"ok\":true}");
                }
                return;
            }
            if request_path.starts_with("/api/worlds") {
                let allow = if request_path == "/api/worlds/switch" {
                    "POST"
                } else {
                    "GET, POST, DELETE"
                };
                write_method_not_allowed(&mut stream, allow);
                return;
            }
            if request_path == "/api/announce" || request_path.starts_with("/api/announce/") {
                if !method.eq_ignore_ascii_case("POST") {
                    write_method_not_allowed(&mut stream, "POST");
                    return;
                }
                let body_text = request
                    .split_once("\r\n\r\n")
                    .map(|(_, body)| body)
                    .unwrap_or("");
                if !body_text.trim().is_empty() && !json_body_is_valid(body_text) {
                    write_http(&mut stream, 400, "{\"error\":\"invalid JSON body\"}");
                    return;
                }
                if !json_key_present(body_text, "message") {
                    write_http(&mut stream, 400, "{\"error\":\"missing message\"}");
                    return;
                }
                let Some(message) = json_string(body_text, "message") else {
                    write_http(&mut stream, 400, "{\"error\":\"message must be a string\"}");
                    return;
                };
                if message.is_empty() {
                    write_http(&mut stream, 400, "{\"error\":\"message is empty\"}");
                    return;
                }
                if message.encode_utf16().count() > 512 {
                    write_http(
                        &mut stream,
                        400,
                        "{\"error\":\"message exceeds 512 characters\"}",
                    );
                    return;
                }
                let target = if request_path == "/api/announce" {
                    None
                } else {
                    Some(
                        request_path
                            .trim_start_matches("/api/announce/")
                            .to_string(),
                    )
                };
                if let Some(ref target_uuid) = target {
                    let exists = players
                        .lock()
                        .map(|list| list.iter().any(|player| player.uuid == *target_uuid))
                        .unwrap_or(false);
                    if !exists {
                        write_http(&mut stream, 404, "{\"error\":\"player not found\"}");
                        return;
                    }
                }
                if let Ok(mut commands) = world_commands.lock() {
                    commands.push(WorldCommand::Announce { target, message });
                }
                write_http(&mut stream, 200, "{\"ok\":true}");
                return;
            }
            if !method.eq_ignore_ascii_case("GET") {
                write_method_not_allowed(&mut stream, "GET");
                return;
            }
            if request_path != path {
                if request_path.starts_with("/api/") {
                    write_http(&mut stream, 404, "{\"error\":\"not found\"}");
                } else {
                    let _ = write!(
                        stream,
                        "HTTP/1.1 404 Not Found\r\nCache-Control: no-store, max-age=0\r\nX-Content-Type-Options: nosniff\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    );
                }
                return;
            }
            let now = Utc::now();
            let start = stats.start_time.unwrap_or(now);
            let gc = "{\"gen0\":0,\"gen1\":0,\"gen2\":0,\"heapMb\":0.0,\"allocatedMb\":0.0,\"committedMb\":0.0,\"fragmentedMb\":0.0,\"pauseTimePercent\":0.000,\"serverGc\":false,\"latencyMode\":\"Interactive\"}";
            let body = if enable_statistics {
                format!(
                    "{{\"listening\":true,\"ready\":true,\"visitors\":{},\"capacity\":{},\"sent\":{},\"recv\":{},\"packetsSent\":{},\"packetsRecv\":{},\"droppedUnreliable\":0,\"droppedVoice\":0,\"queuePerPeer\":0,\"voiceQueuePerPeer\":0,\"currentTime\":\"{}\",\"startTime\":\"{}\",\"version\":\"{}\",\"gc\":{}}}",
                    visitors.load(Ordering::Relaxed),
                    capacity,
                    stats.tx_bytes.load(Ordering::Relaxed),
                    stats.rx_bytes.load(Ordering::Relaxed),
                    stats.tx_packets.load(Ordering::Relaxed),
                    stats.rx_packets.load(Ordering::Relaxed),
                    now.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
                    start.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
                    version,
                    gc,
                )
            } else {
                format!(
                    "{{\"listening\":true,\"ready\":true,\"currentTime\":\"{}\",\"startTime\":\"{}\",\"version\":\"{}\",\"gc\":{}}}",
                    now.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
                    start.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
                    version,
                    gc,
                )
            };
            let _ = write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=utf-8\r\nCache-Control: no-store, max-age=0\r\nX-Content-Type-Options: nosniff\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fragment_base64_falls_back_to_raw_when_not_utf8() {
        assert_eq!(decode_fragment("aGVsbG8=".to_string()), "hello");
        assert_eq!(decode_fragment("not base64".to_string()), "not base64");
    }

    #[test]
    fn json_validation_accepts_objects_and_rejects_truncation() {
        assert!(json_body_is_valid(r#"{"url":"https://example.com/a"}"#));
        assert!(json_body_is_valid(r#"{"message":"a \"quoted\" value"}"#));
        assert!(!json_body_is_valid(r#"{"url":"https://example.com/a""#));
        assert!(!json_body_is_valid(r#"{"url":"#));
        assert!(!json_body_is_valid("not json"));
    }
}
