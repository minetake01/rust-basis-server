//! Black-box compatibility tests against the C# Basis server contract.
//!
//! The unit tests cover codec and message layout in-process. These tests instead start the
//! real `basis-server-rs` executable and talk to it the way an existing deployment does:
//!
//! - first boot creates the C# `config.xml` schema (v15) and seeds `permissions.xml`,
//! - an older `config.xml` is upgraded the way the C# server upgrades it,
//! - the log lines and `Logs/yyyy-MM-dd.log` file keep the C# shape,
//! - the health / REST endpoints keep the C# status codes, headers and payload fields,
//! - the unconnected server-info UDP query returns the C# packet layout,
//! - structured rejects (server full) and `Invalid client data` use the C# disconnect framing.
//!
//! Everything here is standard library only and runs on Linux, macOS and Windows. The suite is
//! deliberately black-box: packet constants are duplicated rather than imported so a refactor
//! inside the crates cannot silently change the external contract.
//!
//! ```text
//! cargo test -p basis-server --test compat_e2e -- --test-threads=1
//! ```

use std::fs;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

// ---------------------------------------------------------------------------------------------
// C# / LiteNetLib wire constants (duplicated on purpose: this is the compatibility contract).
// ---------------------------------------------------------------------------------------------

const SERVER_INFO_QUERY_MAGIC: u32 = 0xBA51_5101;
const SERVER_INFO_RESPONSE_MAGIC: u32 = 0xBA51_5102;
const SERVER_INFO_PROTOCOL_VERSION: u16 = 1;
const SERVER_INFO_REQUEST_BYTES: usize = 384;
const LITENETLIB_PROTOCOL_ID: i32 = 14;
const STRUCTURED_REJECT_MAGIC: u32 = 0xBA51_5CE1;
const PROP_CONNECT_REQUEST: u8 = 5;
const PROP_DISCONNECT: u8 = 7;

// ---------------------------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------------------------

/// Test scratch space. `CARGO_TARGET_TMPDIR` is inside the repository, so the server can write
/// to it even on machines where a sandbox blocks writes to the system temp directory.
fn scratch_dir(name: &str) -> PathBuf {
    let path = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("compat-e2e-{name}"));
    let _ = fs::remove_dir_all(&path);
    fs::create_dir_all(&path).expect("create scratch directory");
    path
}

fn free_udp_port() -> u16 {
    UdpSocket::bind("127.0.0.1:0")
        .expect("bind ephemeral UDP socket")
        .local_addr()
        .expect("ephemeral UDP address")
        .port()
}

fn free_tcp_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("bind ephemeral TCP socket")
        .local_addr()
        .expect("ephemeral TCP address")
        .port()
}

struct Launch {
    name: String,
    args: Vec<String>,
    first_admin: Option<String>,
    config_xml: Option<String>,
    health: bool,
}

impl Launch {
    fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            args: Vec::new(),
            first_admin: None,
            config_xml: None,
            health: true,
        }
    }

    fn arg(mut self, argument: &str) -> Self {
        self.args.push(argument.to_string());
        self
    }

    fn first_admin(mut self, admin: &str) -> Self {
        self.first_admin = Some(admin.to_string());
        self
    }

    /// Writes `config.xml` before the server starts, to exercise the upgrade path.
    fn config(mut self, xml: &str) -> Self {
        self.config_xml = Some(xml.to_string());
        self
    }

    /// UDP-only tests do not need the HTTP listener.
    fn no_health(mut self) -> Self {
        self.health = false;
        self
    }

    fn start(self) -> Server {
        let mut last_failure = String::new();
        for attempt in 0..3 {
            let dir = scratch_dir(&self.name);
            let config_path = dir.join("config").join("config.xml");
            if let Some(xml) = &self.config_xml {
                fs::create_dir_all(config_path.parent().unwrap()).unwrap();
                fs::write(&config_path, xml).unwrap();
            }

            let udp_port = free_udp_port();
            let health_port = if self.health { free_tcp_port() } else { 0 };
            let stdout_path = dir.join("server.stdout.log");
            let stderr_path = dir.join("server.stderr.log");
            let logs_dir = dir.join("Logs");

            let mut command = Command::new(env!("CARGO_BIN_EXE_basis-server-rs"));
            command
                .arg(format!("--config={}", config_path.display()))
                .arg("--bind=127.0.0.1")
                .arg(format!("--port={udp_port}"))
                .arg("--health-host=127.0.0.1")
                .arg(format!("--health-port={health_port}"))
                .arg(format!("--log-dir={}", logs_dir.display()))
                .arg("--no-control")
                .args(&self.args)
                .current_dir(&dir)
                .env_remove("BasisFirstAdmin")
                .stdin(Stdio::null())
                .stdout(Stdio::from(fs::File::create(&stdout_path).unwrap()))
                .stderr(Stdio::from(fs::File::create(&stderr_path).unwrap()));
            if let Some(admin) = &self.first_admin {
                command.env("BasisFirstAdmin", admin);
            }

            let child = command.spawn().expect("spawn basis-server-rs");
            let mut server = Server {
                child,
                config_path,
                stdout_path,
                stderr_path,
                logs_dir,
                udp_port,
                health_port,
            };

            match server.wait_for_log("Listening on UDP port", Duration::from_secs(20)) {
                Ok(()) => {
                    if self.health {
                        server.wait_for_health(Duration::from_secs(10));
                    }
                    return server;
                }
                Err(error) => {
                    last_failure = format!(
                        "attempt {}: {error}\n--- stdout ---\n{}\n--- stderr ---\n{}",
                        attempt + 1,
                        server.stdout(),
                        server.stderr()
                    );
                }
            }
        }
        panic!("server did not start:\n{last_failure}");
    }
}

struct Server {
    child: Child,
    config_path: PathBuf,
    stdout_path: PathBuf,
    stderr_path: PathBuf,
    logs_dir: PathBuf,
    udp_port: u16,
    health_port: u16,
}

impl Server {
    fn stdout(&self) -> String {
        fs::read_to_string(&self.stdout_path).unwrap_or_default()
    }

    fn stderr(&self) -> String {
        fs::read_to_string(&self.stderr_path).unwrap_or_default()
    }

    fn config(&self) -> String {
        fs::read_to_string(&self.config_path).unwrap_or_default()
    }

    fn permissions_path(&self) -> PathBuf {
        self.config_path
            .parent()
            .unwrap_or(Path::new("."))
            .join("permissions.xml")
    }

    fn wait_for_log(&mut self, needle: &str, timeout: Duration) -> Result<(), String> {
        let deadline = Instant::now() + timeout;
        loop {
            if self.stdout().contains(needle) {
                return Ok(());
            }
            if let Some(status) = self.child.try_wait().expect("poll server process") {
                return Err(format!(
                    "server exited with {status} before logging {needle:?}"
                ));
            }
            if Instant::now() >= deadline {
                return Err(format!("timed out waiting for log line {needle:?}"));
            }
            std::thread::sleep(Duration::from_millis(25));
        }
    }

    fn wait_for_health(&mut self, timeout: Duration) {
        let address = SocketAddr::from(([127, 0, 0, 1], self.health_port));
        let deadline = Instant::now() + timeout;
        loop {
            if TcpStream::connect_timeout(&address, Duration::from_millis(200)).is_ok() {
                return;
            }
            if let Some(status) = self.child.try_wait().expect("poll server process") {
                panic!(
                    "server exited with {status} before the health endpoint came up\n{}",
                    self.stderr()
                );
            }
            assert!(
                Instant::now() < deadline,
                "health endpoint did not come up\n--- stdout ---\n{}",
                self.stdout()
            );
            std::thread::sleep(Duration::from_millis(25));
        }
    }

    fn udp(&self) -> UdpSocket {
        let socket = UdpSocket::bind("127.0.0.1:0").expect("bind UDP client");
        socket
            .set_read_timeout(Some(Duration::from_secs(3)))
            .expect("set UDP read timeout");
        socket
            .connect(("127.0.0.1", self.udp_port))
            .expect("connect UDP client");
        socket
    }

    fn http(&self, method: &str, path: &str, body: Option<&str>) -> HttpResponse {
        self.http_with_content_length(method, path, body, body.map(|b| b.len()))
    }

    /// Sends a request with an explicit `Content-Length`, which lets the 413 test announce an
    /// oversized body without actually writing a megabyte over the socket.
    fn http_with_content_length(
        &self,
        method: &str,
        path: &str,
        body: Option<&str>,
        content_length: Option<usize>,
    ) -> HttpResponse {
        let mut stream = TcpStream::connect(("127.0.0.1", self.health_port))
            .unwrap_or_else(|e| panic!("connect to health endpoint: {e}\n{}", self.stdout()));
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("set HTTP read timeout");
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .expect("set HTTP write timeout");

        let mut request =
            format!("{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n");
        if let Some(length) = content_length {
            request.push_str(&format!("Content-Length: {length}\r\n"));
        }
        request.push_str("\r\n");
        if let Some(body) = body {
            request.push_str(body);
        }
        stream
            .write_all(request.as_bytes())
            .unwrap_or_else(|e| panic!("write HTTP request: {e}"));

        let mut raw = Vec::new();
        if let Err(error) = stream.read_to_end(&mut raw) {
            assert!(
                !raw.is_empty(),
                "read health response failed before any bytes: {error}"
            );
        }
        HttpResponse::parse(&raw)
    }

    fn send_connect_request(&self, payload: &[u8]) -> Vec<u8> {
        let connect_time: i64 = 0x0102_0304_0506_0708;
        let mut packet = Vec::new();
        packet.push(PROP_CONNECT_REQUEST);
        packet.extend_from_slice(&LITENETLIB_PROTOCOL_ID.to_le_bytes());
        packet.extend_from_slice(&connect_time.to_le_bytes());
        packet.extend_from_slice(&1i32.to_le_bytes()); // remote id
        packet.push(0); // address size
        packet.extend_from_slice(payload);

        let socket = self.udp();
        socket.send(&packet).expect("send connect request");
        let mut response = [0u8; 2048];
        let size = socket
            .recv(&mut response)
            .unwrap_or_else(|e| panic!("no response to connect request: {e}\n{}", self.stdout()));
        response[..size].to_vec()
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

struct HttpResponse {
    status: u16,
    headers: Vec<(String, String)>,
    body: String,
}

impl HttpResponse {
    fn parse(raw: &[u8]) -> Self {
        let split = raw
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .unwrap_or_else(|| {
                panic!(
                    "malformed HTTP response: {:?}",
                    String::from_utf8_lossy(raw)
                )
            });
        let head = String::from_utf8_lossy(&raw[..split]);
        let body = String::from_utf8_lossy(&raw[split + 4..]).into_owned();
        let mut lines = head.lines();
        let status_line = lines.next().unwrap_or_default();
        let status = status_line
            .split_whitespace()
            .nth(1)
            .and_then(|value| value.parse().ok())
            .unwrap_or_else(|| panic!("malformed HTTP status line: {status_line:?}"));
        let headers = lines
            .filter_map(|line| line.split_once(':'))
            .map(|(name, value)| (name.trim().to_ascii_lowercase(), value.trim().to_string()))
            .collect();
        Self {
            status,
            headers,
            body,
        }
    }

    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }

    #[track_caller]
    fn assert_header(&self, name: &str, expected: &str) {
        assert_eq!(
            self.header(name),
            Some(expected),
            "unexpected {name:?} header in {:?}",
            self.headers
        );
    }

    #[track_caller]
    fn assert_contains(&self, needle: &str) {
        assert!(
            self.body.contains(needle),
            "response body does not contain {needle:?}: {}",
            self.body
        );
    }
}

// ---------------------------------------------------------------------------------------------
// config.xml / permissions.xml compatibility
// ---------------------------------------------------------------------------------------------

#[test]
fn first_boot_matches_the_csharp_config_schema() {
    let server = Launch::new("first-boot")
        .first_admin("did:key:z6MkCompatAdmin")
        .arg("--no-file-support")
        .no_health()
        .start();

    let output = server.stdout();
    assert!(
        output.contains("not found, creating with default values"),
        "missing C# first-boot line: {output}"
    );
    assert!(
        output.contains("[Setup] Added admin: did:key:z6MkCompatAdmin"),
        "missing admin seeding line: {output}"
    );
    assert!(
        output.contains("[Setup] First boot: added 1 admin(s) from $BasisFirstAdmin."),
        "missing first-boot summary: {output}"
    );
    assert!(
        !output.contains("NO ADMIN CONFIGURED"),
        "an admin was supplied, so the warning block must not appear: {output}"
    );

    let config = server.config();
    assert!(
        config.starts_with("<?xml version=\"1.0\" encoding=\"utf-8\"?>"),
        "config.xml must keep the C# XML declaration"
    );
    for expected in [
        "<ConfigVersion>15</ConfigVersion>",
        "<PeerLimit>65535</PeerLimit>",
        "<SetPort>4296</SetPort>",
        "<ServerName>Basis Server</ServerName>",
        "<CompanyName>Basis Unity</CompanyName>",
        "<ProductName>Basis Unity</ProductName>",
        "<HealthCheckHost>localhost</HealthCheckHost>",
        "<HealthCheckPort>10666</HealthCheckPort>",
        "<HealthPath>/health</HealthPath>",
        "<Password>default_password</Password>",
        "<UseAuth>true</UseAuth>",
        "<UseAuthIdentity>true</UseAuthIdentity>",
        "<HighQualityDistance>10</HighQualityDistance>",
        "<MediumQualityDistance>20</MediumQualityDistance>",
        "<LowQualityDistance>40</LowQualityDistance>",
    ] {
        assert!(
            config.contains(expected),
            "config.xml is missing {expected:?}:\n{config}"
        );
    }

    let uuid = element(&config, "ServerUUID").expect("ServerUUID element");
    assert_eq!(
        uuid.len(),
        32,
        "ServerUUID must be a 32-digit hex UUID: {uuid}"
    );
    assert!(
        uuid.chars().all(|c| c.is_ascii_hexdigit()),
        "ServerUUID must be hexadecimal: {uuid}"
    );
    assert_ne!(
        uuid, "f12d7031c1a34d129273472645ad3c55",
        "the template sentinel must be replaced on first boot"
    );

    let permissions = fs::read_to_string(server.permissions_path()).expect("permissions.xml");
    assert!(
        permissions.contains("<User uuid=\"did:key:z6MkCompatAdmin\">"),
        "admin user was not seeded:\n{permissions}"
    );
    assert!(
        permissions.contains("<Group name=\"admin\">")
            && permissions.contains("<Node value=\"*\" />"),
        "admin group must contain the wildcard node:\n{permissions}"
    );
    assert!(
        permissions.contains("<SeededDefaults>"),
        "permissions.xml must record seeded defaults:\n{permissions}"
    );
}

#[test]
fn headless_first_boot_without_an_admin_matches_the_csharp_warning() {
    let server = Launch::new("first-boot-no-admin")
        .arg("--no-file-support")
        .no_health()
        .start();

    let output = server.stdout();
    for expected in [
        "Basis Server first-time setup: NO ADMIN CONFIGURED",
        "No interactive console is attached and the environment",
        "variable BasisFirstAdmin is not set, so the server is starting",
        "WITHOUT an admin - nobody can moderate or configure it.",
        "BasisFirstAdmin=did:key:z6Mk...   (comma-separate for several)",
        "then delete config/config.xml and restart, or run the server",
        "once in an interactive terminal to use the setup wizard.",
    ] {
        assert!(
            output.contains(expected),
            "warning block is missing {expected:?}:\n{output}"
        );
    }
    assert!(
        !server.permissions_path().exists(),
        "no permissions.xml should be written without an admin"
    );
}

#[test]
fn older_config_is_upgraded_the_way_the_csharp_server_upgrades_it() {
    let server = Launch::new("config-upgrade")
        .config(
            "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<Configuration>\n  <ConfigVersion>14</ConfigVersion>\n  <ServerName>Existing Name</ServerName>\n</Configuration>\n",
        )
        .arg("--no-file-support")
        .no_health()
        .start();

    assert!(
        server
            .stdout()
            .contains("is from an older version; adding missing settings."),
        "missing C# upgrade line:\n{}",
        server.stdout()
    );

    let config = server.config();
    assert!(
        config.contains("<ConfigVersion>15</ConfigVersion>"),
        "schema version was not bumped:\n{config}"
    );
    assert!(
        config.contains("<ServerName>Existing Name</ServerName>"),
        "existing values must be preserved:\n{config}"
    );
    assert!(
        config.contains("<PeerLimit>65535</PeerLimit>"),
        "missing settings were not added:\n{config}"
    );
    assert!(
        config.contains("<HealthCheckPort>10666</HealthCheckPort>"),
        "health settings were not added:\n{config}"
    );
    assert!(
        config
            .contains("<AuthValidationTimeOutMiliseconds>9000</AuthValidationTimeOutMiliseconds>"),
        "auth timeout was not added:\n{config}"
    );
}

// ---------------------------------------------------------------------------------------------
// Logging compatibility
// ---------------------------------------------------------------------------------------------

#[test]
fn log_lines_and_file_match_the_csharp_shape() {
    let server = Launch::new("logging").arg("--file-support").start();

    let output = server.stdout();
    let first_line = output.lines().next().unwrap_or_default();
    assert!(
        first_line.ends_with("not found, creating with default values"),
        "unexpected first boot line: {first_line:?}"
    );

    let saved = output
        .lines()
        .find(|line| line.contains("Logs are saved to "))
        .unwrap_or_else(|| panic!("missing 'Logs are saved to' line:\n{output}"));
    let saved_name = saved.rsplit(['\\', '/']).next().unwrap_or_default();
    assert!(
        is_utc_log_name(saved_name),
        "log file line must name a yyyy-MM-dd.log file: {saved:?}"
    );
    assert!(
        output.contains(&format!("[INFO] Listening on UDP port {}", server.udp_port)),
        "missing C# listening line:\n{output}"
    );
    assert_csharp_log_line(
        output
            .lines()
            .find(|line| line.contains("Server Booting"))
            .expect("Server Booting line"),
    );

    let log_file = fs::read_dir(&server.logs_dir)
        .expect("read Logs directory")
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .find(|path| path.extension().and_then(|e| e.to_str()) == Some("log"))
        .expect("a log file");
    let name = log_file.file_name().unwrap().to_string_lossy().into_owned();
    assert!(
        is_utc_log_name(&name),
        "log file must be named yyyy-MM-dd.log: {name:?}"
    );
    let contents = fs::read_to_string(&log_file).expect("read log file");
    assert!(
        contents.contains("Server Booting") && contents.contains("Listening on UDP port"),
        "log file is missing boot records:\n{contents}"
    );
    for line in contents.lines() {
        assert_csharp_log_line(line);
    }
}

#[test]
fn no_file_support_matches_the_csharp_message() {
    let server = Launch::new("logging-disabled")
        .arg("--no-file-support")
        .no_health()
        .start();
    assert!(
        server.stdout().contains("[INFO] no logs will be saved"),
        "missing C# no-file-support line:\n{}",
        server.stdout()
    );
    assert!(
        !server.logs_dir.exists(),
        "no Logs directory should be created when file support is off"
    );
}

#[track_caller]
fn assert_csharp_log_line(line: &str) {
    let rest = line
        .strip_prefix('[')
        .unwrap_or_else(|| panic!("log line must start with '[HH:mm]': {line:?}"));
    let (minute, rest) = rest
        .split_once("] [")
        .unwrap_or_else(|| panic!("log line must contain '] [': {line:?}"));
    assert!(
        minute.len() == 5
            && minute.as_bytes().get(2) == Some(&b':')
            && minute[..2].chars().all(|c| c.is_ascii_digit())
            && minute[3..].chars().all(|c| c.is_ascii_digit())
            && minute[..2].parse::<u8>().unwrap() < 24
            && minute[3..].parse::<u8>().unwrap() < 60,
        "log line must start with [HH:mm]: {line:?}"
    );
    let (level, message) = rest
        .split_once("] ")
        .unwrap_or_else(|| panic!("log line must contain '] ': {line:?}"));
    assert!(
        matches!(level, "INFO" | "WARNING" | "ERROR"),
        "log level must be INFO/WARNING/ERROR: {line:?}"
    );
    assert!(
        !message.is_empty(),
        "log message must not be empty: {line:?}"
    );
}

fn is_utc_log_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    bytes.len() == 14
        && name.ends_with(".log")
        && bytes[4] == b'-'
        && bytes[7] == b'-'
        && bytes[..4].iter().all(u8::is_ascii_digit)
        && bytes[5..7].iter().all(u8::is_ascii_digit)
        && bytes[8..10].iter().all(u8::is_ascii_digit)
}

// ---------------------------------------------------------------------------------------------
// Health / REST compatibility
// ---------------------------------------------------------------------------------------------

#[test]
fn health_endpoint_matches_the_csharp_contract() {
    let server = Launch::new("health").start();

    let health = server.http("GET", "/health", None);
    assert_eq!(health.status, 200);
    health.assert_header("content-type", "application/json; charset=utf-8");
    health.assert_header("cache-control", "no-store, max-age=0");
    health.assert_header("x-content-type-options", "nosniff");
    for expected in [
        "\"listening\":true",
        "\"ready\":true",
        "\"visitors\":0",
        "\"capacity\":65535",
        "\"version\":\"56\"",
        "\"currentTime\":\"",
        "\"startTime\":\"",
        "\"process\":{",
        "\"allocator\":\"system\"",
        "\"memory\":{",
        "\"totalBytes\":",
        "\"availableBytes\":",
    ] {
        health.assert_contains(expected);
    }
    assert!(
        json_number(&health.body, "rssBytes").is_some_and(|rss| rss > 0),
        "health must report the measured RSS: {}",
        health.body
    );
    assert!(
        !health.body.contains("\"gc\""),
        "the removed C# GC projection must not come back: {}",
        health.body
    );

    let players = server.http("GET", "/api/players", None);
    assert_eq!(players.status, 200);
    assert_eq!(players.body, "{\"players\":[]}");

    let worlds = server.http("GET", "/api/worlds", None);
    assert_eq!(worlds.status, 200);
    assert_eq!(worlds.body, "{\"worlds\":[]}");
}

#[test]
fn health_methods_and_errors_match_the_csharp_statuses() {
    let server = Launch::new("health-errors").start();

    let post_health = server.http("POST", "/health", None);
    assert_eq!(post_health.status, 405);
    post_health.assert_header("allow", "GET");
    assert!(post_health.body.is_empty());

    let post_players = server.http("POST", "/api/players", None);
    assert_eq!(post_players.status, 405);
    post_players.assert_header("allow", "GET");

    let missing = server.http("GET", "/nope", None);
    assert_eq!(missing.status, 404);

    let missing_api = server.http("GET", "/api/nope", None);
    assert_eq!(missing_api.status, 404);

    let invalid_json = server.http("POST", "/api/worlds", Some("{\"url\":"));
    assert_eq!(invalid_json.status, 400);
    invalid_json.assert_contains("invalid JSON body");

    let no_password = server.http(
        "POST",
        "/api/worlds",
        Some("{\"url\":\"https://example.invalid/world.bee\"}"),
    );
    assert_eq!(no_password.status, 400);
    no_password.assert_contains("password required");

    let bad_strategy = server.http(
        "POST",
        "/api/worlds",
        Some("{\"url\":\"https://example.invalid/world.bee\",\"password\":\"compat\",\"strategy\":\"bogus\"}"),
    );
    assert_eq!(bad_strategy.status, 400);
    bad_strategy.assert_contains("unknown strategy");

    let missing_world = server.http("DELETE", "/api/worlds/missing", None);
    assert_eq!(missing_world.status, 404);

    // C# rejects a request whose declared body exceeds 1 MiB before reading it.
    let oversize = server.http_with_content_length("POST", "/api/worlds", None, Some(1_048_600));
    assert_eq!(oversize.status, 413);
    oversize.assert_contains("payload too large");

    let announce_missing = server.http("POST", "/api/announce", Some("{}"));
    assert_eq!(announce_missing.status, 400);
    announce_missing.assert_contains("missing message");

    let announce_empty = server.http("POST", "/api/announce", Some("{\"message\":\"\"}"));
    assert_eq!(announce_empty.status, 400);
    announce_empty.assert_contains("message is empty");
}

#[test]
fn world_rest_round_trip_matches_the_csharp_contract() {
    let server = Launch::new("worlds").start();

    let load = server.http(
        "POST",
        "/api/worlds",
        Some("{\"url\":\"https://example.invalid/world.bee\",\"password\":\"compat\",\"persistent\":true}"),
    );
    assert_eq!(load.status, 200, "{}", load.body);
    load.assert_contains("\"ok\":true");
    let net_id = json_string(&load.body, "netId").expect("netId in load response");
    assert!(net_id.starts_with("world-"), "unexpected netId: {net_id}");

    // The transport drains the command queue asynchronously; C#'s harness waits the same way.
    let mut listed = String::new();
    for _ in 0..40 {
        listed = server.http("GET", "/api/worlds", None).body;
        if listed.contains(&net_id) {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(
        listed.contains(&net_id),
        "loaded world {net_id} never appeared in /api/worlds: {listed}"
    );

    let announce = server.http("POST", "/api/announce", Some("{\"message\":\"compat\"}"));
    assert_eq!(announce.status, 200);
    assert_eq!(announce.body, "{\"ok\":true}");

    let switch = server.http(
        "POST",
        "/api/worlds/switch",
        Some("{\"url\":\"https://example.invalid/next.bee\",\"password\":\"compat\",\"announceMessage\":\"moving\",\"delay\":10}"),
    );
    assert_eq!(switch.status, 200, "{}", switch.body);
    switch.assert_contains("\"ok\":true");

    let unload = server.http("DELETE", &format!("/api/worlds/{net_id}"), None);
    assert_eq!(unload.status, 200);
    assert_eq!(unload.body, "{\"ok\":true}");

    let mut after = String::new();
    for _ in 0..40 {
        after = server.http("GET", "/api/worlds", None).body;
        if !after.contains(&net_id) {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(
        !after.contains(&net_id),
        "unloaded world {net_id} is still listed: {after}"
    );

    let oversized_announce = format!(
        "{{\"url\":\"https://example.invalid/next.bee\",\"password\":\"compat\",\"announceMessage\":\"{}\"}}",
        "a".repeat(513)
    );
    let rejected = server.http("POST", "/api/worlds/switch", Some(&oversized_announce));
    assert_eq!(rejected.status, 400);
    rejected.assert_contains("announceMessage exceeds 512 characters");
}

#[test]
fn custom_health_path_matches_the_csharp_config_field() {
    let server = Launch::new("health-path")
        .arg("--health-path=/status")
        .start();

    let status = server.http("GET", "/status", None);
    assert_eq!(status.status, 200);
    status.assert_contains("\"version\":\"56\"");

    let old_path = server.http("GET", "/health", None);
    assert_eq!(old_path.status, 404);
}

// ---------------------------------------------------------------------------------------------
// Wire compatibility: server-info query and connection rejects
// ---------------------------------------------------------------------------------------------

#[test]
fn server_info_query_matches_the_csharp_layout() {
    let server = Launch::new("server-info")
        .config(
            "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<Configuration>\n  <ServerName>Compat Server</ServerName>\n  <ServerMotd>hello motd</ServerMotd>\n  <PeerLimit>42</PeerLimit>\n</Configuration>\n",
        )
        .no_health()
        .start();

    let socket = server.udp();
    let response = server_info_query(&socket, 0x1234, false);
    assert_eq!(
        u32::from_le_bytes(response[0..4].try_into().unwrap()),
        SERVER_INFO_RESPONSE_MAGIC
    );
    assert_eq!(
        u16::from_le_bytes(response[4..6].try_into().unwrap()),
        SERVER_INFO_PROTOCOL_VERSION
    );
    assert_eq!(
        u16::from_le_bytes(response[6..8].try_into().unwrap()),
        0x1234
    );
    assert_eq!(u16::from_le_bytes(response[8..10].try_into().unwrap()), 0);
    assert_eq!(u16::from_le_bytes(response[10..12].try_into().unwrap()), 42);
    let (name, name_len) = read_string(&response, 12);
    assert_eq!(name, "Compat Server");
    let (motd, motd_len) = read_string(&response, 12 + name_len);
    assert_eq!(motd, "hello motd");
    assert_eq!(response.len(), 12 + name_len + motd_len); // both strings include their u16 frame

    // The per-IP query throttle is 500 ms, matching C#.
    std::thread::sleep(Duration::from_millis(600));
    let wrapped = server_info_query(&socket, 0x5678, true);
    assert_eq!(
        wrapped[0] & 0x1F,
        8,
        "wrapped reply must keep the C# wrapper"
    );
    assert_eq!(
        u32::from_le_bytes(wrapped[1..5].try_into().unwrap()),
        SERVER_INFO_RESPONSE_MAGIC
    );
    assert_eq!(
        u16::from_le_bytes(wrapped[7..9].try_into().unwrap()),
        0x5678
    );
}

fn server_info_query(socket: &UdpSocket, nonce: u16, wrapped: bool) -> Vec<u8> {
    let mut query = vec![0u8; SERVER_INFO_REQUEST_BYTES + usize::from(wrapped)];
    let offset = usize::from(wrapped);
    if wrapped {
        query[0] = 8;
    }
    query[offset..offset + 4].copy_from_slice(&SERVER_INFO_QUERY_MAGIC.to_le_bytes());
    query[offset + 4..offset + 6].copy_from_slice(&SERVER_INFO_PROTOCOL_VERSION.to_le_bytes());
    query[offset + 6..offset + 8].copy_from_slice(&nonce.to_le_bytes());
    socket.send(&query).expect("send server-info query");
    let mut response = [0u8; 1024];
    let size = socket.recv(&mut response).expect("server-info response");
    response[..size].to_vec()
}

fn read_string(data: &[u8], offset: usize) -> (String, usize) {
    let framed = u16::from_le_bytes([data[offset], data[offset + 1]]) as usize;
    assert!(framed > 0, "empty NetDataWriter string at {offset}");
    let len = framed - 1;
    let text = String::from_utf8_lossy(&data[offset + 2..offset + 2 + len]).into_owned();
    (text, 2 + len)
}

#[test]
fn server_full_reject_matches_the_csharp_structured_payload() {
    let server = Launch::new("server-full")
        .arg("--peer-limit=0")
        .no_health()
        .start();

    let response = server.send_connect_request(&[]);
    assert_eq!(response[0] & 0x1F, PROP_DISCONNECT);
    let connect_time = i64::from_le_bytes(response[1..9].try_into().unwrap());
    assert_eq!(connect_time, 0x0102_0304_0506_0708);
    assert_eq!(
        u32::from_le_bytes(response[9..13].try_into().unwrap()),
        STRUCTURED_REJECT_MAGIC
    );
    assert_eq!(response[13], 2, "server-full must use reject kind 2");
    assert_eq!(u16::from_le_bytes(response[14..16].try_into().unwrap()), 0);
    assert_eq!(u16::from_le_bytes(response[16..18].try_into().unwrap()), 0);
    let framed = u16::from_le_bytes(response[18..20].try_into().unwrap()) as usize;
    let message = String::from_utf8_lossy(&response[20..20 + framed - 1]);
    assert_eq!(
        message,
        "This server is full (0/0). Please try again later."
    );
    assert!(
        server
            .stdout()
            .contains("Rejected (kind 2): This server is full (0/0)."),
        "missing C# reject log line:\n{}",
        server.stdout()
    );
}

#[test]
fn invalid_client_data_reject_matches_the_csharp_disconnect() {
    let server = Launch::new("invalid-data").no_health().start();

    let response = server.send_connect_request(b"not-a-connection-message");
    assert_eq!(response[0] & 0x1F, PROP_DISCONNECT);
    let connect_time = i64::from_le_bytes(response[1..9].try_into().unwrap());
    assert_eq!(connect_time, 0x0102_0304_0506_0708);
    let framed = u16::from_le_bytes(response[9..11].try_into().unwrap()) as usize;
    let reason = String::from_utf8_lossy(&response[11..11 + framed - 1]);
    assert_eq!(reason, "Invalid client data.");
    assert!(
        server
            .stdout()
            .contains("Rejected for reason: Invalid client data."),
        "missing C# invalid-data log line:\n{}",
        server.stdout()
    );
}

// ---------------------------------------------------------------------------------------------
// Small JSON helpers (the test binary intentionally has no serde dependency)
// ---------------------------------------------------------------------------------------------

fn json_number(body: &str, key: &str) -> Option<u64> {
    let marker = format!("\"{key}\":");
    let start = body.find(&marker)? + marker.len();
    body[start..]
        .chars()
        .take_while(char::is_ascii_digit)
        .collect::<String>()
        .parse()
        .ok()
}

fn json_string(body: &str, key: &str) -> Option<String> {
    let marker = format!("\"{key}\":\"");
    let start = body.find(&marker)? + marker.len();
    let end = body[start..].find('"')?;
    Some(body[start..start + end].to_string())
}

fn element(text: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = text.find(&open)? + open.len();
    let end = text[start..].find(&close)? + start;
    Some(text[start..end].to_string())
}
