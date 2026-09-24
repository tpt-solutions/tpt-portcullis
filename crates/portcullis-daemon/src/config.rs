//! Plain-file (TOML) config loading: read → parse → verify.

use std::path::Path;

use portcullis_rules::{verify, LintIssue, Ruleset};
use thiserror::Error;

/// Errors from loading and verifying a config file.
#[derive(Debug, Error)]
pub enum ConfigError {
    /// The file could not be read.
    #[error("failed to read config {path}: {source}")]
    Io {
        /// Path that failed.
        path: String,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },
    /// The file is not valid TOML matching the config schema.
    #[error("failed to parse config {path}: {source}")]
    Parse {
        /// Path that failed.
        path: String,
        /// Underlying TOML error.
        #[source]
        source: toml::de::Error,
    },
    /// [`verify`] found one or more lint issues — refuse to hand off.
    #[error("ruleset failed verification ({} issue(s)):\n{}", .0.len(), format_issues(.0))]
    Verify(Vec<LintIssue>),
}

fn format_issues(issues: &[LintIssue]) -> String {
    issues
        .iter()
        .map(|i| format!("  - {i}"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// File-level config wrapper. The ruleset is under a `ruleset` key so
/// top-level metadata (comments, future daemon options) can live alongside
/// without colliding with `Ruleset`'s own fields.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FileConfig {
    /// The rule document.
    pub ruleset: Ruleset,
}

/// Read `path`, parse TOML into a [`Ruleset`], and run [`verify`].
///
/// Returns `Err(ConfigError::Verify)` when lint fails — callers **must
/// not** pass a failing ruleset to a dataplane (usage contract of
/// `portcullis-rules`).
pub fn load_ruleset(path: &Path) -> Result<Ruleset, ConfigError> {
    let path_str = path.display().to_string();
    let text = std::fs::read_to_string(path).map_err(|source| ConfigError::Io {
        path: path_str.clone(),
        source,
    })?;
    parse_ruleset(&text, &path_str)
}

/// Parse TOML text into a verified [`Ruleset`].
///
/// `path` is used only for error messages.
pub fn parse_ruleset(text: &str, path: &str) -> Result<Ruleset, ConfigError> {
    let file: FileConfig = toml::from_str(text).map_err(|source| ConfigError::Parse {
        path: path.to_string(),
        source,
    })?;
    verify(&file.ruleset).map_err(ConfigError::Verify)?;
    Ok(file.ruleset)
}
