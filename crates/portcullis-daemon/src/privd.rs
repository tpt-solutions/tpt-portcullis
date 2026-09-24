//! `tpt-privd` client integration — health-check and command kinds.
//!
//! # Envelope shape (confirmed against real `tpt-privd`)
//!
//! Open `CommandKind(u32)` with built-ins `NOP`/`ECHO` and
//! `CUSTOM_START = 0x8000_0000` for consumers. One-shot CBOR over a Unix
//! domain socket via [`tpt_privd_client::call`].
//!
//! # Platform
//!
//! The client is Unix-only (`cfg(unix)`); on Windows every call returns
//! [`tpt_privd_client::ClientError::UnsupportedPlatform`]. The daemon
//! degrades gracefully: health-check becomes a no-op with a warning.

use std::path::Path;

use thiserror::Error;
use tpt_privd_envelope::{Command, CommandId, CommandKind};

/// Portcullis-specific command kinds, allocated from the consumer range.
///
/// Reserved so future privileged ops (beyond what netctl handles in-process)
/// have a stable namespace. Execution of these kinds requires a custom
/// `CommandExecutor` inside `tpt-privd` (follow-up — see todo.md).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortcullisCommandKind;

impl PortcullisCommandKind {
    /// First kind allocated to Portcullis.
    pub const BASE: u32 = CommandKind::CUSTOM_START;
    /// Reserved: apply a serialized ruleset via netctl (future — needs
    /// netctl executor inside tpt-privd).
    pub const APPLY_RULESET: CommandKind = CommandKind(CommandKind::CUSTOM_START);
    /// Reserved: read dataplane state (future).
    pub const READ_STATE: CommandKind = CommandKind(CommandKind::CUSTOM_START + 1);
}

/// Errors from privd integration (health-check path).
#[derive(Debug, Error)]
pub enum PrivdError {
    /// Transport / platform / decode failure from the client.
    #[error("privd call failed: {0}")]
    Client(#[from] tpt_privd_client::ClientError),
    /// Daemon returned a structured command error.
    #[error("privd returned error {code:?}: {message}")]
    Remote {
        /// Machine-readable code from the envelope.
        code: tpt_privd_envelope::ErrorCode,
        /// Human-readable message from the daemon.
        message: String,
    },
    /// Reply payload was not the expected shape.
    #[error("unexpected privd reply: {0}")]
    BadReply(String),
}

/// Health-check: send `NOP` (or `ECHO`) to the daemon at `socket_path`.
///
/// # Errors
///
/// Any [`PrivdError`] — including platform-unsupported on Windows.
pub fn health_check(socket_path: &Path) -> Result<(), PrivdError> {
    let cmd = Command::new(CommandId(1), CommandKind::NOP, Vec::new());
    let result = tpt_privd_client::call(socket_path, &cmd)?;
    match result.outcome {
        Ok(_) => Ok(()),
        Err(e) => Err(PrivdError::Remote {
            code: e.code,
            message: e.message,
        }),
    }
}

/// Best-effort health-check used at daemon startup: logs a warning and
/// returns `false` on failure instead of aborting (privd is optional for
/// Phase 2's in-process netctl apply path).
pub fn try_health_check(socket_path: &Path) -> bool {
    match health_check(socket_path) {
        Ok(()) => {
            tracing::info!(socket = %socket_path.display(), "tpt-privd health-check ok");
            true
        }
        Err(e) => {
            tracing::warn!(
                socket = %socket_path.display(),
                error = %e,
                "tpt-privd health-check failed (continuing; dataplane apply is in-process)"
            );
            false
        }
    }
}
