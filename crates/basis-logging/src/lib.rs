//! C#-compatible server logging.
//!
//! The C# server writes one record per line as `[HH:mm] [LEVEL] message`, both to the console
//! and (when `HasFileSupport` is enabled) to `Logs/yyyy-MM-dd.log`. This crate reproduces that
//! external shape, including the control-character sanitisation and the two boot lines.

use chrono::{Local, Utc};
use std::collections::VecDeque;
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::sync::mpsc::{sync_channel, Receiver, SyncSender, TrySendError};
use std::sync::{Mutex, OnceLock};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    Info,
    Warning,
    Error,
}

impl Level {
    pub fn tag(self) -> char {
        match self {
            Self::Info => 'I',
            Self::Warning => 'W',
            Self::Error => 'E',
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Info => "INFO",
            Self::Warning => "WARNING",
            Self::Error => "ERROR",
        }
    }
}

#[derive(Debug, Clone)]
pub struct LogConfig {
    pub use_logging: bool,
    pub write_to_screen: bool,
    pub log_dir: PathBuf,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            use_logging: false,
            write_to_screen: true,
            log_dir: PathBuf::from("Logs"),
        }
    }
}

struct Logger {
    use_logging: bool,
    write_to_screen: bool,
    log_dir: PathBuf,
    file_lock: Mutex<()>,
}

static LOGGER: OnceLock<Logger> = OnceLock::new();
static BACKLOG: OnceLock<Mutex<VecDeque<(Level, String)>>> = OnceLock::new();
type LogRecord = (Level, String);
type LogSender = SyncSender<LogRecord>;
static SUBSCRIBERS: OnceLock<Mutex<Vec<LogSender>>> = OnceLock::new();

const BACKLOG_LINES: usize = 200;

fn publish(level: Level, message: &str) {
    let backlog = BACKLOG.get_or_init(|| Mutex::new(VecDeque::new()));
    {
        let mut backlog = backlog.lock().unwrap_or_else(|e| e.into_inner());
        if backlog.len() == BACKLOG_LINES {
            backlog.pop_front();
        }
        backlog.push_back((level, message.to_string()));
    }
    let subscribers = SUBSCRIBERS.get_or_init(|| Mutex::new(Vec::new()));
    let mut subscribers = subscribers.lock().unwrap_or_else(|e| e.into_inner());
    subscribers.retain(
        |sender| match sender.try_send((level, message.to_string())) {
            Ok(()) | Err(TrySendError::Full(_)) => true,
            Err(TrySendError::Disconnected(_)) => false,
        },
    );
}

/// Subscribes to the control-socket log stream. The receiver first gets the current
/// 200-line backlog, then every new record.
pub fn subscribe() -> Receiver<(Level, String)> {
    let (sender, receiver) = sync_channel(1000);
    if let Some(backlog) = BACKLOG.get() {
        if let Ok(backlog) = backlog.lock() {
            for (level, message) in backlog.iter() {
                let _ = sender.send((*level, message.clone()));
            }
        }
    }
    SUBSCRIBERS
        .get_or_init(|| Mutex::new(Vec::new()))
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .push(sender);
    receiver
}

/// Installs the process-wide logger. Calling this more than once is rejected rather than
/// silently changing the destination under running threads.
pub fn init(config: LogConfig) -> Result<(), String> {
    if LOGGER.get().is_some() {
        return Err("logger already initialized".into());
    }
    if config.use_logging {
        fs::create_dir_all(&config.log_dir).map_err(|e| e.to_string())?;
    }
    LOGGER
        .set(Logger {
            use_logging: config.use_logging,
            write_to_screen: config.write_to_screen,
            log_dir: config.log_dir,
            file_lock: Mutex::new(()),
        })
        .map_err(|_| "logger already initialized".to_string())
}

pub fn is_initialized() -> bool {
    LOGGER.get().is_some()
}

pub fn current_log_file() -> Option<PathBuf> {
    let logger = LOGGER.get()?;
    if !logger.use_logging {
        return None;
    }
    Some(
        logger
            .log_dir
            .join(format!("{}.log", Utc::now().format("%Y-%m-%d"))),
    )
}

/// The exact text C# writes for one record.
pub fn format_line(level: Level, message: &str, minute: &str) -> String {
    format!("[{minute}] [{}] {}", level.label(), sanitize(message))
}

/// Mirrors `BasisServerSideLogging.Sanitize`: newlines become spaces, other control bytes
/// become `?`, tabs are preserved.
pub fn sanitize(message: &str) -> String {
    if !message.chars().any(|c| c < '\u{20}' && c != '\t') {
        return message.to_string();
    }
    let mut out = String::with_capacity(message.len());
    for c in message.chars() {
        match c {
            '\n' | '\r' => out.push(' '),
            c if c < '\u{20}' && c != '\t' => out.push('?'),
            c => out.push(c),
        }
    }
    out
}

pub fn log(level: Level, args: fmt::Arguments<'_>) {
    let message = args.to_string();
    publish(level, &message);
    let minute = Local::now().format("%H:%M").to_string();
    let line = format_line(level, &message, &minute);

    let Some(logger) = LOGGER.get() else {
        // Before init (or in a unit test), still produce the C# console shape.
        println!("{line}");
        return;
    };

    if logger.write_to_screen {
        println!("{line}");
    }

    if logger.use_logging {
        let path = logger
            .log_dir
            .join(format!("{}.log", Utc::now().format("%Y-%m-%d")));
        let _guard = logger.file_lock.lock().unwrap_or_else(|e| e.into_inner());
        if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(path) {
            let _ = writeln!(file, "{line}");
            let _ = file.flush();
        }
    }
}

pub fn info(args: fmt::Arguments<'_>) {
    log(Level::Info, args);
}

pub fn warning(args: fmt::Arguments<'_>) {
    log(Level::Warning, args);
}

pub fn error(args: fmt::Arguments<'_>) {
    log(Level::Error, args);
}

/// Debug records are not part of the C# external log surface. Enable them only for local
/// diagnosis with `BASIS_LOG_DEBUG=1`.
pub fn debug(args: fmt::Arguments<'_>) {
    if std::env::var_os("BASIS_LOG_DEBUG").is_some() {
        log(Level::Info, args);
    }
}

#[macro_export]
macro_rules! info {
    ($($arg:tt)*) => { $crate::info(format_args!($($arg)*)) };
}

#[macro_export]
macro_rules! warn {
    ($($arg:tt)*) => { $crate::warning(format_args!($($arg)*)) };
}

#[macro_export]
macro_rules! error {
    ($($arg:tt)*) => { $crate::error(format_args!($($arg)*)) };
}

#[macro_export]
macro_rules! debug {
    ($($arg:tt)*) => { $crate::debug(format_args!($($arg)*)) };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_shape_matches_csharp() {
        assert_eq!(
            format_line(Level::Info, "Server Booting", "23:20"),
            "[23:20] [INFO] Server Booting"
        );
        assert_eq!(
            format_line(Level::Warning, "w", "00:01"),
            "[00:01] [WARNING] w"
        );
        assert_eq!(format_line(Level::Error, "e", "12:59"), "[12:59] [ERROR] e");
    }

    #[test]
    fn sanitize_matches_csharp_rules() {
        assert_eq!(sanitize("a\nb\rc\td\u{1}"), "a b c\td?");
        assert_eq!(sanitize("plain"), "plain");
    }

    #[test]
    fn file_name_is_utc_date() {
        let path = PathBuf::from("Logs").join(format!("{}.log", Utc::now().format("%Y-%m-%d")));
        assert!(path.to_string_lossy().ends_with(".log"));
    }
}
