#![deny(unsafe_op_in_unsafe_fn)]

use basis_config::ServerConfig;
use basis_logging::LogConfig;
use std::io::IsTerminal;
use std::path::PathBuf;

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut config = ServerConfig::default();

    let config_path = args
        .iter()
        .find_map(|a| a.strip_prefix("--config=").map(PathBuf::from))
        .unwrap_or_else(|| {
            std::env::current_exe()
                .ok()
                .and_then(|p| p.parent().map(|p| p.join("config").join("config.xml")))
                .unwrap_or_else(|| PathBuf::from("config/config.xml"))
        });
    let config_created =
        basis_config::ensure_default_file(&config_path).map_err(anyhow::Error::from)?;
    if config_created {
        let display = config_path
            .canonicalize()
            .unwrap_or_else(|_| config_path.clone());
        let display = display.display().to_string();
        println!(
            "{} not found, creating with default values",
            display.strip_prefix(r"\\?\").unwrap_or(&display)
        );
    }
    if !config_created && basis_config::ensure_schema(&config_path).map_err(anyhow::Error::from)? {
        let display = config_path
            .canonicalize()
            .unwrap_or_else(|_| config_path.clone());
        let display = display.display().to_string();
        println!(
            "{} is from an older version; adding missing settings.",
            display.strip_prefix(r"\\?\").unwrap_or(&display)
        );
    }
    basis_config::apply_file(&mut config, &config_path)?;
    config.config_path = config_path.display().to_string();

    for arg in &args {
        if let Some(v) = arg.strip_prefix("--port=") {
            config.port = v.parse()?;
        } else if arg == "--bundle-compression" {
            config.enable_avatar_bundle_compression = true;
        } else if let Some(v) = arg.strip_prefix("--peer-limit=") {
            config.peer_limit = v.parse()?;
        } else if let Some(v) = arg.strip_prefix("--bind=") {
            config.bind = v.to_string();
        } else if let Some(v) = arg.strip_prefix("--password=") {
            config.password = v.to_string();
        } else if let Some(v) = arg.strip_prefix("--initial-world=") {
            let (url, password) = v.rsplit_once('#').unwrap_or((v, ""));
            config.initial_world_url = url.to_string();
            config.initial_world_password = password.to_string();
        } else if let Some(v) = arg.strip_prefix("--health-host=") {
            config.health_host = v.to_string();
        } else if let Some(v) = arg.strip_prefix("--health-port=") {
            config.health_port = v.parse()?;
        } else if let Some(v) = arg.strip_prefix("--health-path=") {
            config.health_path = if v.starts_with('/') {
                v.to_string()
            } else {
                format!("/{v}")
            };
        } else if let Some(v) = arg.strip_prefix("--auth-timeout-ms=") {
            config.auth_validation_timeout_ms = v.parse()?;
        } else if arg == "--log-connection-handshake" {
            config.log_connection_handshake = true;
        } else if let Some(v) = arg.strip_prefix("--log-dir=") {
            config.log_dir = v.to_string();
        } else if arg == "--no-file-support" {
            config.has_file_support = false;
        } else if arg == "--file-support" {
            config.has_file_support = true;
        } else if arg == "--no-avatar-reduction" {
            config.avatar_reduction = false;
        } else if arg == "--avatar-reduction" {
            config.avatar_reduction = true;
        } else if arg == "--no-auth-identity" {
            config.use_auth_identity = false;
        } else if arg == "--use-auth" {
            config.use_auth = true;
        } else if arg == "--disallow-headless" {
            config.disallow_headless = true;
        } else if arg == "--allow-headless" {
            config.disallow_headless = false;
        } else if arg == "--no-control" {
            config.control_socket = false;
        } else if arg == "--control" {
            config.control_socket = true;
        } else if arg == "--no-auth" {
            config.use_auth = false;
        }
    }

    let log_dir = if args.iter().any(|a| a.starts_with("--log-dir=")) {
        PathBuf::from(&config.log_dir)
    } else {
        std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|p| p.join("Logs")))
            .unwrap_or_else(|| PathBuf::from(&config.log_dir))
    };
    basis_logging::init(LogConfig {
        use_logging: config.has_file_support,
        write_to_screen: true,
        log_dir,
    })
    .map_err(anyhow::Error::msg)?;

    if config.has_file_support {
        if let Some(path) = basis_logging::current_log_file() {
            basis_logging::info!("Logs are saved to {}", path.display());
        }
    } else {
        basis_logging::info!("no logs will be saved");
    }

    let interactive = std::io::stdin().is_terminal() && std::io::stdout().is_terminal();
    let permissions = config_path
        .parent()
        .map(|dir| dir.join("permissions.xml"))
        .unwrap_or_else(|| PathBuf::from("permissions.xml"));
    let mut seeded_admins = 0;
    if config_created {
        if let Ok(admins) = std::env::var("BasisFirstAdmin") {
            match basis_permissions::seed_first_admins(&permissions, &admins) {
                Ok(0) => basis_logging::warn!(
                    "[Setup] $BasisFirstAdmin was set but contained no usable UUIDs."
                ),
                Ok(count) => {
                    seeded_admins = count;
                    for uuid in admins
                        .split([',', ';', ' ', '\t', '\r', '\n'])
                        .map(str::trim)
                        .filter(|value| !value.is_empty())
                    {
                        basis_logging::info!("[Setup] Added admin: {uuid}");
                    }
                    basis_logging::info!(
                        "[Setup] First boot: added {count} admin(s) from $BasisFirstAdmin."
                    );
                }
                Err(e) => basis_logging::warn!("[Setup] could not write permissions.xml: {e}"),
            }
        }
    }

    if config_created && interactive && seeded_admins == 0 {
        basis_setup::run(&config_path, &mut config, &permissions)?;
    }

    if config_created && !interactive && seeded_admins == 0 {
        basis_logging::warn!("============================================================");
        basis_logging::warn!(" Basis Server first-time setup: NO ADMIN CONFIGURED");
        basis_logging::warn!("------------------------------------------------------------");
        basis_logging::warn!(" No interactive console is attached and the environment");
        basis_logging::warn!(" variable BasisFirstAdmin is not set, so the server is starting");
        basis_logging::warn!(" WITHOUT an admin - nobody can moderate or configure it.");
        basis_logging::warn!(" To set one up, provide the admin's player UUID, e.g.:");
        basis_logging::warn!("   BasisFirstAdmin=did:key:z6Mk...   (comma-separate for several)");
        basis_logging::warn!(" then delete config/config.xml and restart, or run the server");
        basis_logging::warn!(" once in an interactive terminal to use the setup wizard.");
        basis_logging::warn!("============================================================");
    }

    basis_logging::info!("Server Booting");
    let port = config.port;
    if let Err(e) = basis_transport::run(config) {
        if e.kind() == std::io::ErrorKind::AddrInUse {
            basis_logging::error!(
                "Not listening: UDP port {port} could not be bound. Another process may already be using it."
            );
            std::process::exit(1);
        }
        return Err(e.into());
    }
    Ok(())
}
