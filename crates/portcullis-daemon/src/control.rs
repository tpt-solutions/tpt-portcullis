//! Control plane: localhost TCP server + mtime-based config reload.
//!
//! Protocol: one newline-delimited JSON request/response per connection
//! (simple, debuggable, works on Windows — no Unix-socket-only design).
//!
//! Requests:
//! - `{"cmd":"validate","path":"..."}` — offline parse+lint (no apply)
//! - `{"cmd":"apply","path":"..."}` — load, verify, apply
//! - `{"cmd":"reload"}` — re-read the daemon's configured file and apply
//! - `{"cmd":"status"}` — loaded version / counts / last apply
//!
//! Responses are a single JSON line: `{"ok":true,...}` or
//! `{"ok":false,"error":"..."}`.

use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::config::load_ruleset;
use crate::privd;
use crate::state::{ApplyOutcome, DaemonState};

/// Control-plane request (newline-delimited JSON).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum Request {
    /// Parse + lint a file without applying.
    Validate {
        /// Config file path (as visible to the daemon process).
        path: String,
    },
    /// Load, verify, and apply a file.
    Apply {
        /// Config file path.
        path: String,
    },
    /// Re-read the daemon's configured file and apply it.
    Reload,
    /// Query status.
    Status,
}

/// Control-plane response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Response {
    /// Whether the request succeeded.
    pub ok: bool,
    /// Human-readable error when `ok` is false.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Apply outcome when an apply/reload succeeded.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub applied: Option<ApplyOutcome>,
    /// Status payload.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<StatusPayload>,
    /// Lint/validate message when relevant.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

impl Response {
    fn ok_empty() -> Self {
        Self {
            ok: true,
            error: None,
            applied: None,
            status: None,
            message: None,
        }
    }

    fn err(msg: impl Into<String>) -> Self {
        Self {
            ok: false,
            error: Some(msg.into()),
            applied: None,
            status: None,
            message: None,
        }
    }
}

/// Status payload for `{"cmd":"status"}`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusPayload {
    /// Config path the daemon was started with.
    pub config_path: String,
    /// Whether a ruleset is currently loaded.
    pub loaded: bool,
    /// Schema version of the loaded ruleset, if any.
    pub version: Option<u64>,
    /// Number of chains loaded, if any.
    pub chains: Option<usize>,
    /// Number of rules loaded, if any.
    pub rules: Option<usize>,
    /// Last successful apply, if any.
    pub last_apply: Option<ApplyOutcome>,
}

/// Run the daemon: load config, apply, health-check privd, serve control
/// socket, poll config mtime for reload.
///
/// Blocks until the process is killed. Returns only on fatal bind errors.
///
/// # Errors
///
/// Initial config load failure or control-listener bind failure.
pub fn run(
    config_path: PathBuf,
    control_addr: String,
    privd_socket: Option<PathBuf>,
    poll_secs: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    // Initial load + apply (fail fast on bad config).
    let ruleset = load_ruleset(&config_path)?;
    let state = Arc::new(DaemonState::new(config_path.clone())?);
    let outcome = state.apply(&ruleset)?;
    tracing::info!(
        version = outcome.version,
        chains = outcome.chains,
        rules = outcome.rules,
        changes = outcome.planned_changes,
        "initial ruleset applied"
    );

    if let Some(sock) = &privd_socket {
        privd::try_health_check(sock);
    } else {
        tracing::debug!("no --privd-socket given; skipping privd health-check");
    }

    // Control listener.
    let listener = TcpListener::bind(&control_addr)
        .map_err(|e| format!("failed to bind control socket {control_addr}: {e}"))?;
    tracing::info!(addr = %control_addr, "control socket listening");

    // Mtime watcher thread.
    if poll_secs > 0 {
        let watch_state = Arc::clone(&state);
        let watch_path = config_path.clone();
        std::thread::spawn(move || watch_config(watch_path, watch_state, poll_secs));
    }

    // Accept loop (single-threaded; Phase 2 is local admin only).
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let st = Arc::clone(&state);
                if let Err(e) = handle_client(stream, &st) {
                    tracing::warn!(error = %e, "control connection error");
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "accept failed");
            }
        }
    }

    Ok(())
}

fn watch_config(path: PathBuf, state: Arc<DaemonState>, poll_secs: u64) {
    let mut last_mtime = std::fs::metadata(&path).and_then(|m| m.modified()).ok();
    let interval = Duration::from_secs(poll_secs.max(1));
    loop {
        std::thread::sleep(interval);
        let mtime = std::fs::metadata(&path).and_then(|m| m.modified()).ok();
        if mtime.is_none() {
            continue; // temporarily unreadable — keep last good state
        }
        if mtime != last_mtime {
            last_mtime = mtime;
            tracing::info!(path = %path.display(), "config mtime changed; reloading");
            match load_ruleset(&path) {
                Ok(rs) => match state.apply(&rs) {
                    Ok(outcome) => tracing::info!(
                        version = outcome.version,
                        rules = outcome.rules,
                        "reload applied"
                    ),
                    Err(e) => {
                        tracing::error!(error = %e, "reload apply failed; keeping previous state")
                    }
                },
                Err(e) => tracing::error!(error = %e, "reload load failed; keeping previous state"),
            }
        }
    }
}

fn handle_client(stream: TcpStream, state: &Arc<DaemonState>) -> std::io::Result<()> {
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut line = String::new();
    reader.read_line(&mut line)?;
    if line.trim().is_empty() {
        return Ok(());
    }

    let response = match serde_json::from_str::<Request>(&line) {
        Ok(req) => dispatch(req, state),
        Err(e) => Response::err(format!("bad request: {e}")),
    };

    let mut writer = stream;
    let mut out = serde_json::to_string(&response)
        .unwrap_or_else(|e| format!(r#"{{"ok":false,"error":"serialize: {e}"}}"#));
    out.push('\n');
    writer.write_all(out.as_bytes())?;
    writer.flush()
}

fn dispatch(req: Request, state: &Arc<DaemonState>) -> Response {
    match req {
        Request::Validate { path } => match load_ruleset(Path::new(&path)) {
            Ok(rs) => Response {
                message: Some(format!(
                    "ok: version {}, {} chain(s), {} rule(s)",
                    rs.version,
                    rs.chains.len(),
                    rs.iter_rules().count()
                )),
                ..Response::ok_empty()
            },
            Err(e) => Response::err(e.to_string()),
        },
        Request::Apply { path } => match load_ruleset(Path::new(&path)) {
            Ok(rs) => match state.apply(&rs) {
                Ok(outcome) => Response {
                    applied: Some(outcome),
                    ..Response::ok_empty()
                },
                Err(e) => Response::err(e.to_string()),
            },
            Err(e) => Response::err(e.to_string()),
        },
        Request::Reload => match load_ruleset(&state.config_path) {
            Ok(rs) => match state.apply(&rs) {
                Ok(outcome) => Response {
                    applied: Some(outcome),
                    ..Response::ok_empty()
                },
                Err(e) => Response::err(e.to_string()),
            },
            Err(e) => Response::err(e.to_string()),
        },
        Request::Status => {
            let current = state.current_ruleset();
            Response {
                status: Some(StatusPayload {
                    config_path: state.config_path.display().to_string(),
                    loaded: current.is_some(),
                    version: current.as_ref().map(|r| r.version),
                    chains: current.as_ref().map(|r| r.chains.len()),
                    rules: current.as_ref().map(|r| r.iter_rules().count()),
                    last_apply: state.last_apply(),
                }),
                ..Response::ok_empty()
            }
        }
    }
}

/// Client helper used by `portcullis-cli` (and tests): send one request
/// over TCP and decode the response.
///
/// # Errors
///
/// I/O or JSON errors.
pub fn send_request(addr: &str, req: &Request) -> Result<Response, String> {
    let mut stream = TcpStream::connect(addr).map_err(|e| format!("connect {addr}: {e}"))?;
    let mut line = serde_json::to_string(req).map_err(|e| e.to_string())?;
    line.push('\n');
    stream
        .write_all(line.as_bytes())
        .map_err(|e| e.to_string())?;
    stream.flush().map_err(|e| e.to_string())?;

    let mut reader = BufReader::new(stream);
    let mut reply = String::new();
    reader.read_line(&mut reply).map_err(|e| e.to_string())?;
    serde_json::from_str(reply.trim()).map_err(|e| format!("bad response: {e}"))
}

/// Validate without a daemon: parse + lint only (used by CLI `validate`).
///
/// # Errors
///
/// Same as [`load_ruleset`].
pub fn offline_validate(
    path: &Path,
) -> Result<portcullis_rules::Ruleset, crate::config::ConfigError> {
    load_ruleset(path)
}
