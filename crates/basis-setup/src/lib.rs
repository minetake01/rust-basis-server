//! C# first-boot setup wizard. Interactive only; the headless path in the binary
//! prints the no-admin warning and seeds `BasisFirstAdmin` without this module.

use basis_config::{update_values, ServerConfig};
use basis_logging::{info, warn};
use std::io::{self, BufRead, Write};
use std::path::Path;

pub fn run(
    config_path: &Path,
    config: &mut ServerConfig,
    permissions_path: &Path,
) -> io::Result<()> {
    let stdin = io::stdin();
    let stdout = io::stdout();
    run_with_io(
        config_path,
        config,
        permissions_path,
        &mut stdin.lock(),
        &mut stdout.lock(),
    )
}

pub fn run_with_io<R: BufRead, W: Write>(
    config_path: &Path,
    config: &mut ServerConfig,
    permissions_path: &Path,
    reader: &mut R,
    writer: &mut W,
) -> io::Result<()> {
    print_intro();
    if let Some(settings) = settings_walkthrough(config, config_path, reader, writer)? {
        config.server_name = settings.name;
        config.server_motd = settings.motd;
        config.company_name = settings.company;
        config.product_name = settings.product;
        config.port = settings.port;
        config.password = settings.password;
        config.peer_limit = settings.peer_limit;
    }
    let admins = prompt_admins(reader, writer)?;
    if !admins.is_empty() {
        let _ = basis_permissions::seed_first_admins(permissions_path, &admins.join(","));
    }
    if admins.is_empty() {
        info!("[Setup] First-time setup complete - no admin configured. Starting server...");
    } else {
        info!(
            "[Setup] First-time setup complete - {} admin(s) configured. Starting server...",
            admins.len()
        );
    }
    Ok(())
}

fn print_intro() {
    info!("============================================================");
    info!(" Basis Server - First-Time Setup");
    info!("============================================================");
    info!("No config.xml was found, so this is a brand-new server.");
    info!("This quick wizard sets up the core server settings and has");
    info!("you designate an admin before the server starts.");
}

struct Settings {
    name: String,
    motd: String,
    company: String,
    product: String,
    port: u16,
    password: String,
    peer_limit: usize,
}

fn settings_walkthrough<R: BufRead, W: Write>(
    config: &ServerConfig,
    config_path: &Path,
    reader: &mut R,
    writer: &mut W,
) -> io::Result<Option<Settings>> {
    info!("");
    info!("--- Server settings ---");
    info!("Press Enter to keep the [current] value, or type a new one.");
    info!("");

    let name = prompt_string(
        reader,
        writer,
        "Server name (shown in the server list)",
        &config.server_name,
    )?;
    let motd = prompt_string(
        reader,
        writer,
        "Message of the day / MOTD",
        &config.server_motd,
    )?;
    let company = prompt_string(
        reader,
        writer,
        "Accepted client company name (Unity Player Settings > Company Name)",
        &config.company_name,
    )?;
    let product = prompt_string(
        reader,
        writer,
        "Accepted client product name (Unity Player Settings > Product Name)",
        &config.product_name,
    )?;
    let port = prompt_ushort(reader, writer, "Game port (UDP)", config.port)?;
    let password = prompt_password(reader, writer, &config.password)?;
    let peer_limit = prompt_int(reader, writer, "Max players", config.peer_limit, 1)?;

    info!("");
    info!("--- Review ---");
    info!("  Server name : {name}");
    info!(
        "  MOTD        : {}",
        if motd.is_empty() { "<none>" } else { &motd }
    );
    info!("  Company     : {company}");
    info!("  Product     : {product}");
    info!("  Game port   : {port}");
    info!(
        "  Password    : {}",
        if password == "default_password" {
            "default_password"
        } else {
            "(set)"
        }
    );
    info!("  Max players : {peer_limit}");
    info!("");

    if !confirm_default_yes(reader, writer, "Save these settings and start the server?")? {
        info!("[Setup] Settings discarded - keeping config.xml defaults.");
        return Ok(None);
    }

    let port_text = port.to_string();
    let peer_text = peer_limit.to_string();
    update_values(
        config_path,
        &[
            ("ServerName", &name),
            ("ServerMotd", &motd),
            ("CompanyName", &company),
            ("ProductName", &product),
            ("SetPort", &port_text),
            ("Password", &password),
            ("PeerLimit", &peer_text),
        ],
    )?;
    info!("[Setup] Settings saved to config.xml.");
    Ok(Some(Settings {
        name,
        motd,
        company,
        product,
        port,
        password,
        peer_limit,
    }))
}

fn print_admin_help() {
    info!("An admin is identified by their Basis player UUID (a DID), which");
    info!("looks like:  did:key:z6Mk...");
    info!("Where to find it:");
    info!("  - in the Basis client: open Settings > Developer tab, find the");
    info!("    \"Identity Key\" section, and tap the eye icon on the \"UUID\"");
    info!("    field to reveal it; or");
    info!("  - in this server's log: every time a player connects it prints");
    info!("    their UUID as \"(UUID did:key:...)\".");
    info!("The UUID you enter is added to the \"admin\" group (full access).");
    info!("You can add more than one; leave the prompt blank once done.");
    info!("Don't have it to hand? Type 'skip' to start without an admin and");
    info!("add one later with:  /perm user group add <uuid> admin");
    info!("");
}

fn warn_skipped_admin() {
    warn!("");
    warn!("============================================================");
    warn!(" Starting with NO ADMIN");
    warn!("------------------------------------------------------------");
    warn!(" Nobody can moderate or configure this server in game.");
    warn!(" Add one at any time from this console with:");
    warn!("   /perm user group add <uuid> admin");
    warn!("============================================================");
}

fn prompt_admins<R: BufRead, W: Write>(reader: &mut R, writer: &mut W) -> io::Result<Vec<String>> {
    info!("");
    info!("--- Admin setup ---");
    print_admin_help();
    let mut admins = Vec::new();
    loop {
        let prompt = if admins.is_empty() {
            "Admin player UUID ('skip' to start without one): "
        } else {
            "Add another admin UUID (leave blank to finish): "
        };
        let input = prompt_raw(reader, writer, prompt)?;
        if input.eq_ignore_ascii_case("help") || input == "?" {
            print_admin_help();
            continue;
        }
        if input.is_empty() || input.eq_ignore_ascii_case("skip") {
            if !admins.is_empty() {
                break;
            }
            if !confirm(
                reader,
                writer,
                "Start this server with no admin? Nobody will be able to moderate or configure it in game.",
            )? {
                continue;
            }
            warn_skipped_admin();
            break;
        }
        if !looks_like_did(&input)
            && !confirm(
                reader,
                writer,
                &format!("'{input}' doesn't look like a did:key UUID. Add it anyway?"),
            )?
        {
            continue;
        }
        info!("[Setup] Added admin: {input}");
        admins.push(input);
    }
    Ok(admins)
}

fn looks_like_did(value: &str) -> bool {
    value.to_ascii_lowercase().starts_with("did:") && value.len() > 4 && !value.contains(' ')
}

fn prompt_raw<R: BufRead, W: Write>(
    reader: &mut R,
    writer: &mut W,
    label: &str,
) -> io::Result<String> {
    write!(writer, "{label}")?;
    writer.flush()?;
    let mut line = String::new();
    reader.read_line(&mut line)?;
    Ok(line.trim().to_string())
}

fn prompt_password<R: BufRead, W: Write>(
    reader: &mut R,
    writer: &mut W,
    current: &str,
) -> io::Result<String> {
    let value = prompt_raw(reader, writer, "Server password [keep current]: ")?;
    Ok(if value.is_empty() {
        current.to_string()
    } else {
        value
    })
}

fn prompt_string<R: BufRead, W: Write>(
    reader: &mut R,
    writer: &mut W,
    label: &str,
    current: &str,
) -> io::Result<String> {
    let shown = if current.is_empty() {
        "<none>"
    } else {
        current
    };
    let value = prompt_raw(reader, writer, &format!("{label} [{shown}]: "))?;
    Ok(if value.is_empty() {
        current.to_string()
    } else {
        value
    })
}

fn prompt_ushort<R: BufRead, W: Write>(
    reader: &mut R,
    writer: &mut W,
    label: &str,
    current: u16,
) -> io::Result<u16> {
    loop {
        let value = prompt_raw(reader, writer, &format!("{label} [{current}]: "))?;
        if value.is_empty() {
            return Ok(current);
        }
        if let Ok(parsed) = value.parse::<u16>() {
            return Ok(parsed);
        }
        warn!("Please enter a whole number between 0 and 65535.");
    }
}

fn prompt_int<R: BufRead, W: Write>(
    reader: &mut R,
    writer: &mut W,
    label: &str,
    current: usize,
    min: usize,
) -> io::Result<usize> {
    loop {
        let value = prompt_raw(reader, writer, &format!("{label} [{current}]: "))?;
        if value.is_empty() {
            return Ok(current);
        }
        if let Ok(parsed) = value.parse::<usize>() {
            if parsed >= min {
                return Ok(parsed);
            }
        }
        warn!("Please enter a whole number of {min} or more.");
    }
}

fn confirm<R: BufRead, W: Write>(
    reader: &mut R,
    writer: &mut W,
    question: &str,
) -> io::Result<bool> {
    let answer = prompt_raw(reader, writer, &format!("{question} (y/N): "))?;
    Ok(answer.eq_ignore_ascii_case("y") || answer.eq_ignore_ascii_case("yes"))
}

fn confirm_default_yes<R: BufRead, W: Write>(
    reader: &mut R,
    writer: &mut W,
    question: &str,
) -> io::Result<bool> {
    let answer = prompt_raw(reader, writer, &format!("{question} (Y/n): "))?;
    Ok(answer.is_empty() || answer.eq_ignore_ascii_case("y") || answer.eq_ignore_ascii_case("yes"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn scripted_settings_walkthrough_saves_config_and_skips_admin() {
        let dir = std::env::current_dir()
            .unwrap()
            .join(format!("basis-setup-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let config_path = dir.join("config.xml");
        let permissions = dir.join("permissions.xml");
        basis_config::ensure_default_file(&config_path).unwrap();
        let mut config = ServerConfig::default();
        let mut input = Cursor::new(
            b"Rust Server\nhello\nAcme\nWorld\n4500\nsecret\n32\ny\nskip\ny\n".to_vec(),
        );
        let mut output = Vec::new();
        run_with_io(
            &config_path,
            &mut config,
            &permissions,
            &mut input,
            &mut output,
        )
        .unwrap();
        let text = std::fs::read_to_string(&config_path).unwrap();
        assert!(text.contains("<ServerName>Rust Server</ServerName>"));
        assert!(text.contains("<ServerMotd>hello</ServerMotd>"));
        assert!(text.contains("<SetPort>4500</SetPort>"));
        assert!(text.contains("<PeerLimit>32</PeerLimit>"));
        assert_eq!(config.server_name, "Rust Server");
        assert_eq!(config.port, 4500);
        assert_eq!(config.peer_limit, 32);
        let prompts = String::from_utf8(output).unwrap();
        assert!(prompts.contains("Server name (shown in the server list)"));
        assert!(prompts.contains("Start this server with no admin?"));
        assert!(!permissions.exists());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn scripted_admin_walkthrough_writes_permissions() {
        let dir = std::env::current_dir()
            .unwrap()
            .join(format!("basis-setup-admin-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let config_path = dir.join("config.xml");
        let permissions = dir.join("permissions.xml");
        basis_config::ensure_default_file(&config_path).unwrap();
        let mut config = ServerConfig::default();
        let mut input = Cursor::new(b"\n\n\n\n\n\n\ny\ndid:key:z6MkTest\n\n".to_vec());
        let mut output = Vec::new();
        run_with_io(
            &config_path,
            &mut config,
            &permissions,
            &mut input,
            &mut output,
        )
        .unwrap();
        let text = std::fs::read_to_string(&permissions).unwrap();
        assert!(text.contains("uuid=\"did:key:z6MkTest\""));
        assert!(text.contains("<Group name=\"admin\" />"));
        let _ = std::fs::remove_dir_all(dir);
    }
}
