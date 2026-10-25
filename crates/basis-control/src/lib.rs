//! C#-compatible `basisctl` control socket.
//!
//! The server listens on a Unix-domain socket (AF_UNIX on Windows via `uds_windows`).
//! The wire protocol is line based: the server greets with `basis 1`, a client sends
//! `run <command>` or `attach`, and command output is `I|W|E <text>` terminated by
//! `done <code>`, matching `BasisControlProtocol`/`BasisControlServer`.

use basis_logging::{info, warn};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

#[cfg(unix)]
use std::os::unix::net::{UnixListener, UnixStream};
#[cfg(windows)]
use uds_windows::{UnixListener, UnixStream};

/// Runtime values exposed by `run status`.
#[derive(Clone, Debug)]
pub struct ControlPlayer {
    pub id: u16,
    pub uuid: String,
    pub display_name: String,
}

pub struct ControlConfig {
    pub path: PathBuf,
    pub server_name: String,
    pub port: u16,
    pub peer_limit: usize,
    pub players: Arc<Mutex<Vec<ControlPlayer>>>,
    pub started: Instant,
}

pub struct ControlServer {
    path: PathBuf,
    shutdown: Arc<AtomicBool>,
}

impl ControlServer {
    pub fn start(config: ControlConfig) -> Option<Self> {
        if let Some(parent) = config.path.parent() {
            if !parent.as_os_str().is_empty() {
                if let Err(e) = std::fs::create_dir_all(parent) {
                    warn!(
                        "[basisctl] Control socket unavailable at {}: {e}",
                        config.path.display()
                    );
                    return None;
                }
            }
        }
        // A previous process may have left a stale socket. Binding over it fails, so
        // remove it first; an active server is detected by its greeting in `IsAnswering`
        // in the C# implementation, and a failed reconnect is harmless here.
        if config.path.exists() {
            let _ = std::fs::remove_file(&config.path);
        }
        let listener = match UnixListener::bind(&config.path) {
            Ok(listener) => listener,
            Err(e) => {
                warn!(
                    "[basisctl] Control socket unavailable at {}: {e}",
                    config.path.display()
                );
                return None;
            }
        };
        info!(
            "[basisctl] Control socket listening at {}",
            config.path.display()
        );

        let shutdown = Arc::new(AtomicBool::new(false));
        let state = Arc::new(ControlState {
            server_name: config.server_name,
            port: config.port,
            peer_limit: config.peer_limit,
            players: config.players,
            started: config.started,
            shutdown: Arc::clone(&shutdown),
        });
        let path = config.path;
        let accept_path = path.clone();
        std::thread::Builder::new()
            .name("basisctl accept".into())
            .spawn(move || accept_loop(listener, state))
            .map_err(|e| {
                warn!(
                    "[basisctl] Control socket unavailable at {}: {e}",
                    accept_path.display()
                );
            })
            .ok()?;
        Some(Self { path, shutdown })
    }

    pub fn shutdown_requested(&self) -> bool {
        self.shutdown.load(Ordering::Relaxed)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for ControlServer {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

struct ControlState {
    server_name: String,
    port: u16,
    peer_limit: usize,
    players: Arc<Mutex<Vec<ControlPlayer>>>,
    started: Instant,
    shutdown: Arc<AtomicBool>,
}

fn accept_loop(listener: UnixListener, state: Arc<ControlState>) {
    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        let state = Arc::clone(&state);
        let _ = std::thread::Builder::new()
            .name("basisctl session".into())
            .spawn(move || session(stream, state));
    }
}

fn session(stream: UnixStream, state: Arc<ControlState>) {
    let Ok(read_half) = stream.try_clone() else {
        return;
    };
    let mut reader = BufReader::new(read_half);
    let writer = Arc::new(Mutex::new(stream));
    {
        let mut writer = writer.lock().unwrap_or_else(|e| e.into_inner());
        if writeln!(writer, "basis 1").is_err() {
            return;
        }
        let _ = writer.flush();
    }

    let stop_attach = Arc::new(AtomicBool::new(false));
    let mut attached = false;
    let mut line = String::new();
    loop {
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
        let request = line.trim_end_matches(['\r', '\n']);
        if request.is_empty() {
            continue;
        }
        if request == "attach" {
            if !attached {
                attached = true;
                let receiver = basis_logging::subscribe();
                let writer = Arc::clone(&writer);
                let stop = Arc::clone(&stop_attach);
                std::thread::spawn(move || {
                    while !stop.load(Ordering::Relaxed) {
                        match receiver.recv_timeout(std::time::Duration::from_millis(100)) {
                            Ok((level, message)) => {
                                let mut writer = writer.lock().unwrap_or_else(|e| e.into_inner());
                                if writeln!(writer, "{} {}", level.tag(), message).is_err() {
                                    break;
                                }
                                let _ = writer.flush();
                            }
                            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
                            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
                        }
                    }
                });
            }
            continue;
        }
        let Some(command) = request.strip_prefix("run ") else {
            let mut writer = writer.lock().unwrap_or_else(|e| e.into_inner());
            let _ = writeln!(
                writer,
                "E Unrecognised request. Update basisctl to match this server."
            );
            let _ = writeln!(writer, "done 2");
            let _ = writer.flush();
            continue;
        };
        let command = command.trim_start_matches('/');
        let root = command.split_whitespace().next().unwrap_or("");
        info!("[basisctl] a local client ran {root}");
        let (code, lines) = execute(command.trim(), &state);
        let mut writer = writer.lock().unwrap_or_else(|e| e.into_inner());
        for line in lines {
            let _ = writeln!(writer, "{line}");
        }
        let _ = writeln!(writer, "done {code}");
        let _ = writer.flush();
        if state.shutdown.load(Ordering::Relaxed) {
            break;
        }
    }
    stop_attach.store(true, Ordering::Relaxed);
}

fn execute(command: &str, state: &ControlState) -> (i32, Vec<String>) {
    let command = command.trim_start_matches('/');
    match command.split_whitespace().next().unwrap_or("") {
        "status" => {
            let online = state.players.lock().map(|p| p.len()).unwrap_or(0);
            let uptime = state.started.elapsed().as_secs();
            let days = uptime / 86_400;
            let hours = (uptime % 86_400) / 3_600;
            let minutes = (uptime % 3_600) / 60;
            let seconds = uptime % 60;
            (
                0,
                vec![format!(
                    "I {}: {online} of {} players, UDP port {}, protocol v55, up {days}d {hours:02}:{minutes:02}:{seconds:02}",
                    state.server_name, state.peer_limit, state.port
                )],
            )
        }
        "help" => (
            0,
            vec!["I Commands: status, players, help, shutdown".to_string()],
        ),
        "players" => {
            let players = state.players.lock().map(|p| p.clone()).unwrap_or_default();
            let mut line = format!("I Connected Player count is {} ", players.len());
            for player in players {
                line.push_str(&format!(
                    "Player: {} UUID: {}, ",
                    player.display_name, player.uuid
                ));
            }
            (0, vec![line])
        }
        "shutdown" => {
            state.shutdown.store(true, Ordering::Relaxed);
            (0, vec!["I Shutting down the server...".to_string()])
        }
        "" => (2, vec!["E Missing command.".to_string()]),
        other => (2, vec![format!("E Unknown command: {other}")]),
    }
}

/// C# `BasisControlProtocol.ServerSocketPath`: explicit env, systemd runtime
/// directory, then `<exe>/basis.sock`. A disabled value (`off`, `0`, `false`,
/// `none`) suppresses the listener.
pub fn default_path() -> Option<PathBuf> {
    if let Ok(value) = std::env::var("BASIS_CONTROL_SOCKET") {
        let value = value.trim();
        if !value.is_empty() {
            if matches!(
                value.to_ascii_lowercase().as_str(),
                "off" | "0" | "false" | "none"
            ) {
                return None;
            }
            return Some(PathBuf::from(value));
        }
    }
    if let Ok(runtime) = std::env::var("RUNTIME_DIRECTORY") {
        if let Some(first) = runtime.split(':').next() {
            if !first.trim().is_empty() {
                return Some(Path::new(first).join("basis.sock"));
            }
        }
    }
    let base = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(Path::to_path_buf))
        .unwrap_or_else(|| PathBuf::from("."));
    Some(base.join("basis.sock"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Write};

    #[test]
    fn status_command_round_trips_on_control_socket() {
        let path = std::env::current_dir()
            .expect("cwd")
            .join(format!("basis-control-test-{}.sock", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let server = ControlServer::start(ControlConfig {
            path: path.clone(),
            server_name: "Basis Server".into(),
            port: 4396,
            peer_limit: 16,
            players: Arc::new(Mutex::new(Vec::new())),
            started: Instant::now(),
        })
        .expect("control socket");
        let mut stream = UnixStream::connect(&path).expect("connect");
        let mut reader = BufReader::new(stream.try_clone().expect("clone"));
        let mut greeting = String::new();
        reader.read_line(&mut greeting).expect("greeting");
        assert_eq!(greeting.trim_end(), "basis 1");
        writeln!(stream, "attach").expect("write");
        stream.flush().expect("flush");
        basis_logging::info!("attach test line");
        let mut saw_log = false;
        for _ in 0..100 {
            let mut line = String::new();
            reader.read_line(&mut line).expect("line");
            if line.contains("I attach test line") {
                saw_log = true;
                break;
            }
        }
        assert!(saw_log, "attach did not stream the log line");

        writeln!(stream, "run /status").expect("write");
        stream.flush().expect("flush");
        let mut response = String::new();
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).expect("line");
            response.push_str(&line);
            if line.starts_with("done ") {
                break;
            }
        }
        assert!(
            response.contains("Basis Server: 0 of 16 players"),
            "{response}"
        );
        assert!(response.ends_with("done 0\n"), "{response}");
        drop(server);
        let _ = std::fs::remove_file(path);
    }
}
