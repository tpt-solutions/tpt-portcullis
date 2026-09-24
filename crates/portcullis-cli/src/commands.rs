//! CLI command implementations.

use std::path::PathBuf;

use portcullis_daemon::control::{offline_validate, send_request, Request};

use crate::Command;

/// Run a subcommand; returns the process exit code.
pub fn run(command: Command) -> u8 {
    match command {
        Command::Validate { file } => validate(file),
        Command::Apply { file, control } => apply(file, &control),
        Command::Reload { control } => reload(&control),
        Command::Status { control } => status(&control),
    }
}

fn validate(file: PathBuf) -> u8 {
    match offline_validate(&file) {
        Ok(rs) => {
            println!(
                "ok: {} (version {}, {} chain(s), {} rule(s))",
                file.display(),
                rs.version,
                rs.chains.len(),
                rs.iter_rules().count()
            );
            0
        }
        Err(e) => {
            eprintln!("error: {e}");
            1
        }
    }
}

fn apply(file: PathBuf, control: &str) -> u8 {
    let req = Request::Apply {
        path: file.display().to_string(),
    };
    match send_request(control, &req) {
        Ok(resp) if resp.ok => {
            if let Some(a) = resp.applied {
                println!(
                    "applied: version {}, {} chain(s), {} rule(s), {} planned change(s)",
                    a.version, a.chains, a.rules, a.planned_changes
                );
            } else {
                println!("applied");
            }
            0
        }
        Ok(resp) => {
            eprintln!("error: {}", resp.error.unwrap_or_else(|| "unknown".into()));
            1
        }
        Err(e) => {
            eprintln!("error: {e}");
            1
        }
    }
}

fn reload(control: &str) -> u8 {
    match send_request(control, &Request::Reload) {
        Ok(resp) if resp.ok => {
            if let Some(a) = resp.applied {
                println!(
                    "reloaded: version {}, {} rule(s), {} planned change(s)",
                    a.version, a.rules, a.planned_changes
                );
            } else {
                println!("reloaded");
            }
            0
        }
        Ok(resp) => {
            eprintln!("error: {}", resp.error.unwrap_or_else(|| "unknown".into()));
            1
        }
        Err(e) => {
            eprintln!("error: {e}");
            1
        }
    }
}

fn status(control: &str) -> u8 {
    match send_request(control, &Request::Status) {
        Ok(resp) if resp.ok => {
            if let Some(s) = resp.status {
                println!("config:  {}", s.config_path);
                println!("loaded:  {}", s.loaded);
                if let Some(v) = s.version {
                    println!("version: {v}");
                }
                if let (Some(c), Some(r)) = (s.chains, s.rules) {
                    println!("chains:  {c}");
                    println!("rules:   {r}");
                }
                if let Some(a) = s.last_apply {
                    println!(
                        "last apply: version {}, {} rule(s), {} change(s)",
                        a.version, a.rules, a.planned_changes
                    );
                }
            }
            0
        }
        Ok(resp) => {
            eprintln!("error: {}", resp.error.unwrap_or_else(|| "unknown".into()));
            1
        }
        Err(e) => {
            eprintln!("error: {e}");
            1
        }
    }
}
